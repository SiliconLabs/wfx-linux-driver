// SPDX-License-Identifier: GPL-2.0-only
/*
 * Implementation of chip-to-host event (aka indications) of WFxxx Split Mac
 * (WSM) API.
 *
 * Copyright (c) 2017-2019, Silicon Laboratories, Inc.
 * Copyright (c) 2010, ST-Ericsson
 */
#include <linux/skbuff.h>
#include <linux/etherdevice.h>

#include "wsm_rx.h"
#include "wfx.h"
#include "bh.h"
#include "data_rx.h"
#include "secure_link.h"
#include "sta.h"

static int wsm_generic_confirm(struct wfx_dev *wdev, struct hif_msg *hdr, void *buf)
{
	// All confirm messages start with status
	int status = le32_to_cpu(*((__le32 *) buf));
	int cmd = hdr->id;
	int len = hdr->len - 4; // drop header

	WARN(!mutex_is_locked(&wdev->wsm_cmd.lock), "data locking error");

	if (!wdev->wsm_cmd.buf_send) {
		dev_warn(wdev->dev, "Unexpected confirmation: 0x%.2x\n", cmd);
		return -EINVAL;
	}

	if (cmd != wdev->wsm_cmd.buf_send->id) {
		dev_warn(wdev->dev, "Chip response mismatch request: 0x%.2x vs 0x%.2x\n",
			 cmd, wdev->wsm_cmd.buf_send->id);
		return -EINVAL;
	}

	if (wdev->wsm_cmd.buf_recv) {
		if (wdev->wsm_cmd.len_recv >= len)
			memcpy(wdev->wsm_cmd.buf_recv, buf, len);
		else
			status = -ENOMEM;
	}
	wdev->wsm_cmd.ret = status;

	if (!wdev->wsm_cmd.async) {
		complete(&wdev->wsm_cmd.done);
	} else {
		wdev->wsm_cmd.buf_send = NULL;
		mutex_unlock(&wdev->wsm_cmd.lock);
		if (cmd != HI_SL_EXCHANGE_PUB_KEYS_REQ_ID)
			mutex_unlock(&wdev->wsm_cmd.key_renew_lock);
	}
	return status;
}

static int wsm_tx_confirm(struct wfx_dev *wdev, struct hif_msg *hdr, void *buf)
{
	struct hif_cnf_tx *body = buf;
	struct wfx_vif *wvif = wdev_to_wvif(wdev, hdr->interface);

	WARN_ON(!wvif);
	if (!wvif)
		return -EFAULT;

	wfx_tx_confirm_cb(wvif, body);
	return 0;
}

static int wsm_multi_tx_confirm(struct wfx_dev *wdev, struct hif_msg *hdr, void *buf)
{
	struct hif_cnf_multi_transmit *body = buf;
	struct hif_cnf_tx *buf_loc = (struct hif_cnf_tx *) &body->tx_conf_payload;
	struct wfx_vif *wvif = wdev_to_wvif(wdev, hdr->interface);
	int count = body->num_tx_confs;
	int i;

	WARN(count <= 0, "Corrupted message");
	WARN_ON(!wvif);
	if (!wvif)
		return -EFAULT;

	for (i = 0; i < count; ++i) {
		wfx_tx_confirm_cb(wvif, buf_loc);
		buf_loc++;
	}
	return 0;
}

int wfx_unmap_link(struct wfx_vif *wvif, int sta_id)
{
	u8 *mac_addr = NULL;

	if (sta_id)
		mac_addr = wvif->link_id_db[sta_id - 1].old_mac;

	return wsm_map_link(wvif->wdev, mac_addr, 1, sta_id, wvif->Id);
}

int wsm_fwd_probe_req(struct wfx_vif *wvif, bool enable)
{
	wvif->filter_probe_resp = enable;
	return wsm_set_rx_filter(wvif->wdev, wvif->filter_bssid,
				 wvif->filter_probe_resp, wvif->Id);
}


static int wsm_startup_indication(struct wfx_dev *wdev, struct hif_msg *hdr, void *buf)
{
	struct hif_ind_startup *body = buf;

	if (body->status || body->firmware_type > 4) {
		dev_err(wdev->dev, "Received invalid startup indication");
		return -EINVAL;
	}
	memcpy(&wdev->wsm_caps, body, sizeof(struct hif_ind_startup));
	le32_to_cpus(&wdev->wsm_caps.status);
	le16_to_cpus(&wdev->wsm_caps.hardware_id);
	le16_to_cpus(&wdev->wsm_caps.num_inp_ch_bufs);
	le16_to_cpus(&wdev->wsm_caps.size_inp_ch_buf);

	complete(&wdev->firmware_ready);
	return 0;
}

static int wsm_wakeup_indication(struct wfx_dev *wdev, struct hif_msg *hdr, void *buf)
{
	if (!wdev->pdata.gpio_wakeup
	    || !gpiod_get_value(wdev->pdata.gpio_wakeup)) {
		dev_warn(wdev->dev, "unexpected wake-up indication\n");
		return -EIO;
	}
	return 0;
}

static int wsm_keys_indication(struct wfx_dev *wdev, struct hif_msg *hdr, void *buf)
{
	struct hif_ind_sl_exchange_pub_keys *body = buf;

	// Compatibility with legacy secure link
	if (body->status == SL_PUB_KEY_EXCHANGE_STATUS_SUCCESS)
		body->status = 0;
	if (body->status)
		dev_warn(wdev->dev, "secure link negociation error\n");
	wfx_sl_check_pubkey(wdev, body->ncp_pub_key, body->ncp_pub_key_mac);
	return 0;
}

static int wsm_receive_indication(struct wfx_dev *wdev, struct hif_msg *hdr, void *buf, struct sk_buff *skb)
{
	struct wfx_vif *wvif = wdev_to_wvif(wdev, hdr->interface);
	struct hif_ind_rx *body = buf;

	if (!wvif) {
		dev_warn(wdev->dev, "ignore rx data for non existant vif %d\n", hdr->interface);
		return 0;
	}
	skb_pull(skb, sizeof(struct hif_msg) + sizeof(struct hif_ind_rx));
	wfx_rx_cb(wvif, body, skb);

	return 0;
}

static int wsm_event_indication(struct wfx_dev *wdev, struct hif_msg *hdr, void *buf)
{
	struct wfx_vif *wvif = wdev_to_wvif(wdev, hdr->interface);
	struct hif_ind_event *body = buf;
	struct wfx_wsm_event *event;
	int first;

	WARN_ON(!wvif);
	if (!wvif)
		return 0;

	event = kzalloc(sizeof(*event), GFP_KERNEL);
	if (!event)
		return -ENOMEM;

	memcpy(&event->evt, body, sizeof(struct hif_ind_event));
	spin_lock(&wvif->event_queue_lock);
	first = list_empty(&wvif->event_queue);
	list_add_tail(&event->link, &wvif->event_queue);
	spin_unlock(&wvif->event_queue_lock);

	if (first)
		schedule_work(&wvif->event_handler_work);

	return 0;
}

static int wsm_pm_mode_complete_indication(struct wfx_dev *wdev, struct hif_msg *hdr, void *buf)
{
	struct wfx_vif *wvif = wdev_to_wvif(wdev, hdr->interface);

	WARN_ON(!wvif);
	complete(&wvif->set_pm_mode_complete);

	return 0;
}

static int wsm_scan_complete_indication(struct wfx_dev *wdev, struct hif_msg *hdr, void *buf)
{
	struct wfx_vif *wvif = wdev_to_wvif(wdev, hdr->interface);
	struct hif_ind_scan_cmpl *body = buf;

	WARN_ON(!wvif);
	wfx_scan_complete_cb(wvif, body);

	return 0;
}

static int wsm_join_complete_indication(struct wfx_dev *wdev, struct hif_msg *hdr, void *buf)
{
	struct wfx_vif *wvif = wdev_to_wvif(wdev, hdr->interface);

	WARN_ON(!wvif);
	dev_warn(wdev->dev, "unattended JoinCompleteInd\n");

	return 0;
}

static int wsm_suspend_resume_indication(struct wfx_dev *wdev, struct hif_msg *hdr, void *buf)
{
	struct wfx_vif *wvif = wdev_to_wvif(wdev, hdr->interface);
	struct hif_ind_suspend_resume_tx *body = buf;

	WARN_ON(!wvif);
	wfx_suspend_resume(wvif, body);

	return 0;
}

static int wsm_error_indication(struct wfx_dev *wdev, struct hif_msg *hdr, void *buf)
{
	struct hif_ind_error *body = buf;
	u8 *pRollback = (u8 *) body->data;
	u32 *pStatus = (u32 *) body->data;

	switch (body->type) {
	case  WSM_HI_ERROR_FIRMWARE_ROLLBACK:
		dev_err(wdev->dev, "asynchronous error: firmware rollback error %d\n", *pRollback);
		break;
	case  WSM_HI_ERROR_FIRMWARE_DEBUG_ENABLED:
		dev_err(wdev->dev, "asynchronous error: firmware debug feature enabled\n");
		break;
	case  WSM_HI_ERROR_OUTDATED_SESSION_KEY:
		dev_err(wdev->dev, "asynchronous error: secure link outdated key: %#.8x\n", *pStatus);
		break;
	case WSM_HI_ERROR_INVALID_SESSION_KEY:
		dev_err(wdev->dev, "asynchronous error: invalid session key\n");
		break;
	case  WSM_HI_ERROR_OOR_VOLTAGE:
		dev_err(wdev->dev, "asynchronous error: out-of-range overvoltage: %#.8x\n", *pStatus);
		break;
	case  WSM_HI_ERROR_PDS_VERSION:
		dev_err(wdev->dev, "asynchronous error: wrong PDS payload or version: %#.8x\n", *pStatus);
		break;
	default:
		dev_err(wdev->dev, "asynchronous error: unknown (%d)\n", body->type);
		break;
	}
	return 0;
}

static int wsm_generic_indication(struct wfx_dev *wdev, struct hif_msg *hdr, void *buf)
{
	struct hif_ind_generic *body = buf;

	switch (body->indication_type) {
	case  HI_GENERIC_INDICATION_TYPE_RAW:
		return 0;
	case HI_GENERIC_INDICATION_TYPE_STRING:
		dev_info(wdev->dev, "firmware says: %s", (char *) body->indication_data.raw_data);
		return 0;
	case HI_GENERIC_INDICATION_TYPE_RX_STATS:
		mutex_lock(&wdev->rx_stats_lock);
		// Older firmware send a generic indication beside RxStats
		if (!wfx_api_older_than(wdev, 1, 4))
			dev_info(wdev->dev, "RX test ongoing. Temperature: %d°C\n", body->indication_data.rx_stats.current_temp);
		memcpy(&wdev->rx_stats, &body->indication_data.rx_stats, sizeof(wdev->rx_stats));
		mutex_unlock(&wdev->rx_stats_lock);
		return 0;
	default:
		dev_err(wdev->dev, "generic_indication: unknown indication type: %#.8x\n", body->indication_type);
		return -EIO;
	}
}

static int wsm_exception_indication(struct wfx_dev *wdev, struct hif_msg *hdr, void *buf)
{
	size_t len = hdr->len - 4; // drop header
	dev_err(wdev->dev, "Firmware exception.\n");
	print_hex_dump_bytes("Dump: ", DUMP_PREFIX_NONE, buf, len);
	wdev->chip_frozen = 1;

	return -1;
}

static const struct {
	int msg_id;
	int (*handler)(struct wfx_dev *, struct hif_msg *, void *);
} wsm_handlers[] = {
	/* Confirmations */
	{ WSM_HI_TX_CNF_ID,              wsm_tx_confirm },
	{ WSM_HI_MULTI_TRANSMIT_CNF_ID,  wsm_multi_tx_confirm },
	/* Indications */
	{ WSM_HI_EVENT_IND_ID,           wsm_event_indication },
	{ WSM_HI_SET_PM_MODE_CMPL_IND_ID, wsm_pm_mode_complete_indication },
	{ WSM_HI_JOIN_COMPLETE_IND_ID,   wsm_join_complete_indication },
	{ WSM_HI_SCAN_CMPL_IND_ID,       wsm_scan_complete_indication },
	{ WSM_HI_SUSPEND_RESUME_TX_IND_ID, wsm_suspend_resume_indication },
	{ HI_ERROR_IND_ID,               wsm_error_indication },
	{ HI_STARTUP_IND_ID,             wsm_startup_indication },
	{ HI_WAKEUP_IND_ID,              wsm_wakeup_indication },
	{ HI_GENERIC_IND_ID,             wsm_generic_indication },
	{ HI_EXCEPTION_IND_ID,           wsm_exception_indication },
	{ HI_SL_EXCHANGE_PUB_KEYS_IND_ID, wsm_keys_indication },
	// FIXME: allocate skb_p from wsm_receive_indication and make it generic
	//{ WSM_HI_RX_IND_ID,            wsm_receive_indication },
};

void wsm_handle_rx(struct wfx_dev *wdev, struct sk_buff *skb)
{
	int i;
	struct hif_msg *wsm = (struct hif_msg *) skb->data;
	int wsm_id = wsm->id;

	if (wsm_id == WSM_HI_RX_IND_ID) {
		// wsm_receive_indication take care of skb lifetime
		wsm_receive_indication(wdev, wsm, wsm->body, skb);
		return;
	}
	// Note: mutex_is_lock cause an implicit memory barrier that protect buf_send
	if (mutex_is_locked(&wdev->wsm_cmd.lock)
	    && wdev->wsm_cmd.buf_send && wdev->wsm_cmd.buf_send->id == wsm_id) {
		wsm_generic_confirm(wdev, wsm, wsm->body);
		goto free;
	}
	for (i = 0; i < ARRAY_SIZE(wsm_handlers); i++) {
		if (wsm_handlers[i].msg_id == wsm_id) {
			if (wsm_handlers[i].handler)
				wsm_handlers[i].handler(wdev, wsm, wsm->body);
			goto free;
		}
	}
	dev_err(wdev->dev, "Unsupported WSM ID %02x\n", wsm_id);
free:
	dev_kfree_skb(skb);
}

void wsm_tx_lock(struct wfx_dev *wdev)
{
	atomic_inc(&wdev->tx_lock);
}

void wsm_tx_unlock(struct wfx_dev *wdev)
{
	int tx_lock = atomic_dec_return(&wdev->tx_lock);

	WARN(tx_lock < 0, "inconsistent tx_lock value");
	if (!tx_lock)
		wfx_bh_request_tx(wdev);
}

void wsm_tx_flush(struct wfx_dev *wdev)
{
	int ret;

	WARN(!atomic_read(&wdev->tx_lock), "tx_lock is not locked");

	// Do not wait for any reply if chip is frozen
	if (wdev->chip_frozen)
		return;

	mutex_lock(&wdev->wsm_cmd.lock);
	ret = wait_event_timeout(wdev->hif.tx_buffers_empty,
				 !wdev->hif.tx_buffers_used,
				 msecs_to_jiffies(3000));
	if (!ret) {
		dev_warn(wdev->dev, "cannot flush tx buffers (%d still busy)\n", wdev->hif.tx_buffers_used);
		wfx_pending_dump_old_frames(wdev, 3000);
		// FIXME: drop pending frames here
		wdev->chip_frozen = 1;
	}
	mutex_unlock(&wdev->wsm_cmd.lock);
}

void wsm_tx_lock_flush(struct wfx_dev *wdev)
{
	wsm_tx_lock(wdev);
	wsm_tx_flush(wdev);
}

static bool wsm_handle_tx_data(struct wfx_vif *wvif, struct sk_buff *skb,
			       struct wfx_queue *queue)
{
	bool handled = false;
	struct wfx_tx_priv *tx_priv = wfx_skb_tx_priv(skb);
	struct hif_req_tx *wsm = wfx_skb_txreq(skb);
	struct ieee80211_hdr *frame = (struct ieee80211_hdr *) (wsm->frame + wsm->data_flags.fc_offset);

	enum {
		do_probe,
		do_drop,
		do_wep,
		do_tx,
	} action = do_tx;

	switch (wvif->vif->type) {
	case NL80211_IFTYPE_STATION:
		if (wvif->state < WFX_STATE_PRE_STA)
			action = do_drop;
		break;
	case NL80211_IFTYPE_AP:
		if (!wvif->state) {
			action = do_drop;
		} else if (!(BIT(tx_priv->raw_link_id) &
		      (BIT(0) | wvif->link_id_map))) {
			dev_warn(wvif->wdev->dev,
				   "A frame with expired link id is dropped.\n");
			action = do_drop;
		}
		break;
	case NL80211_IFTYPE_ADHOC:
		if (wvif->state != WFX_STATE_IBSS)
			action = do_drop;
		break;
	case NL80211_IFTYPE_MONITOR:
	default:
		action = do_drop;
		break;
	}

	if (action == do_tx) {
		if (ieee80211_is_nullfunc(frame->frame_control)) {
			mutex_lock(&wvif->bss_loss_lock);
			if (wvif->bss_loss_state) {
				wvif->bss_loss_confirm_id = wsm->packet_id;
				wsm->queue_id.queue_id = WSM_QUEUE_ID_VOICE;
			}
			mutex_unlock(&wvif->bss_loss_lock);
		} else if (ieee80211_has_protected(frame->frame_control) &&
			   tx_priv->hw_key &&
			   tx_priv->hw_key->keyidx != wvif->wep_default_key_id &&
			   (tx_priv->hw_key->cipher == WLAN_CIPHER_SUITE_WEP40 ||
			    tx_priv->hw_key->cipher == WLAN_CIPHER_SUITE_WEP104)) {
			action = do_wep;
		}
	}

	switch (action) {
	case do_drop:
		BUG_ON(wfx_pending_remove(wvif->wdev, skb));
		handled = true;
		break;
	case do_wep:
		wsm_tx_lock(wvif->wdev);
		wvif->wep_default_key_id = tx_priv->hw_key->keyidx;
		wvif->wep_pending_skb = skb;
		if (!schedule_work(&wvif->wep_key_work))
			wsm_tx_unlock(wvif->wdev);
		handled = true;
		break;
	case do_tx:
		break;
	default:
		/* Do nothing */
		break;
	}
	return handled;
}

static int wfx_get_prio_queue(struct wfx_vif *wvif,
				 u32 tx_allowed_mask, int *total)
{
	static const int urgent = BIT(WFX_LINK_ID_AFTER_DTIM) |
		BIT(WFX_LINK_ID_UAPSD);
	struct hif_req_edca_queue_params *edca;
	unsigned score, best = -1;
	int winner = -1;
	int i;

	/* search for a winner using edca params */
	for (i = 0; i < IEEE80211_NUM_ACS; ++i) {
		int queued;
		edca = &wvif->edca.params[i];
		queued = wfx_tx_queue_get_num_queued(&wvif->wdev->tx_queue[i],
				tx_allowed_mask);
		if (!queued)
			continue;
		*total += queued;
		score = ((edca->aifsn + edca->cw_min) << 16) +
			((edca->cw_max - edca->cw_min) *
			 (get_random_int() & 0xFFFF));
		if (score < best && (winner < 0 || i != 3)) {
			best = score;
			winner = i;
		}
	}

	/* override winner if bursting */
	if (winner >= 0 && wvif->wdev->tx_burst_idx >= 0 &&
	    winner != wvif->wdev->tx_burst_idx &&
	    !wfx_tx_queue_get_num_queued(&wvif->wdev->tx_queue[winner], tx_allowed_mask & urgent) &&
	    wfx_tx_queue_get_num_queued(&wvif->wdev->tx_queue[wvif->wdev->tx_burst_idx], tx_allowed_mask))
		winner = wvif->wdev->tx_burst_idx;

	return winner;
}

static int wsm_get_tx_queue_and_mask(struct wfx_vif *wvif,
				     struct wfx_queue **queue_p,
				     u32 *tx_allowed_mask_p,
				     bool *more)
{
	int idx;
	u32 tx_allowed_mask;
	int total = 0;

	/* Search for a queue with multicast frames buffered */
	if (wvif->tx_multicast) {
		tx_allowed_mask = BIT(WFX_LINK_ID_AFTER_DTIM);
		idx = wfx_get_prio_queue(wvif, tx_allowed_mask, &total);
		if (idx >= 0) {
			*more = total > 1;
			goto found;
		}
	}

	/* Search for unicast traffic */
	tx_allowed_mask = ~wvif->sta_asleep_mask;
	tx_allowed_mask |= BIT(WFX_LINK_ID_UAPSD);
	if (wvif->sta_asleep_mask) {
		tx_allowed_mask |= wvif->pspoll_mask;
		tx_allowed_mask &= ~BIT(WFX_LINK_ID_AFTER_DTIM);
	} else {
		tx_allowed_mask |= BIT(WFX_LINK_ID_AFTER_DTIM);
	}
	idx = wfx_get_prio_queue(wvif, tx_allowed_mask, &total);
	if (idx < 0)
		return -ENOENT;

found:
	*queue_p = &wvif->wdev->tx_queue[idx];
	*tx_allowed_mask_p = tx_allowed_mask;
	return 0;
}

/**
 * It returns 1 if Tx data are found else 0.
 * data, tx_len and burst are only set if 1 is returned.
 * burst is the number of pending messages (including the current reported one then burst>=1)
 *   that are allowed to be sent in the same TxOp than the current reported message.
 *   But it does not guaranty that we have the time to send them all in the duration of the TxOp.
 */
struct hif_msg *wsm_get_tx(struct wfx_dev *wdev)
{
	struct sk_buff *skb;
	struct hif_msg *hdr = NULL;
	struct hif_req_tx *wsm = NULL;
	struct wfx_queue *queue = NULL;
	struct wfx_queue *vif_queue = NULL;
	u32 tx_allowed_mask = 0;
	u32 vif_tx_allowed_mask = 0;
	const struct wfx_tx_priv *tx_priv = NULL;
	struct wfx_vif *wvif;
	/* More is used only for broadcasts. */
	bool more = false;
	bool vif_more = false;
	int not_found;
	int burst;

	for (;;) {
		int ret = -ENOENT;
		int queue_num;
		struct ieee80211_hdr *hdr80211;

		if (atomic_read(&wdev->tx_lock))
			return NULL;

		wvif = NULL;
		while ((wvif = wvif_iterate(wdev, wvif)) != NULL) {
			spin_lock_bh(&wvif->ps_state_lock);

			not_found = wsm_get_tx_queue_and_mask(wvif, &vif_queue, &vif_tx_allowed_mask, &vif_more);

			if (wvif->buffered_multicasts && (not_found || !vif_more) &&
					(wvif->tx_multicast || !wvif->sta_asleep_mask)) {
				wvif->buffered_multicasts = false;
				if (wvif->tx_multicast) {
					wvif->tx_multicast = false;
					schedule_work(&wvif->multicast_stop_work);
				}
			}

			spin_unlock_bh(&wvif->ps_state_lock);

			if (vif_more) {
				more = 1;
				tx_allowed_mask = vif_tx_allowed_mask;
				queue = vif_queue;
				ret = 0;
				break;
			} else if (!not_found) {
				if (queue && queue != vif_queue)
					dev_info(wdev->dev, "Vifs disagree about queue priority");
				tx_allowed_mask |= vif_tx_allowed_mask;
				queue = vif_queue;
				ret = 0;
			}
		}

		if (ret)
			return 0;

		queue_num = queue - wdev->tx_queue;

		skb = wfx_tx_queue_get(wdev, queue, tx_allowed_mask);
		if (!skb)
			continue;
		tx_priv = wfx_skb_tx_priv(skb);
		hdr = (struct hif_msg *) skb->data;
		wvif = wdev_to_wvif(wdev, hdr->interface);
		WARN_ON(!wvif);

		if (wsm_handle_tx_data(wvif, skb, queue))
			continue;  /* Handled by WSM */

		wvif->pspoll_mask &= ~BIT(tx_priv->raw_link_id);

		/* allow bursting if txop is set */
		if (wvif->edca.params[queue_num].tx_op_limit)
			burst = (int)wfx_tx_queue_get_num_queued(queue, tx_allowed_mask) + 1;
		else
			burst = 1;

		/* store index of bursting queue */
		if (burst > 1)
			wdev->tx_burst_idx = queue_num;
		else
			wdev->tx_burst_idx = -1;

		/* more buffered multicast/broadcast frames
		 *  ==> set MoreData flag in IEEE 802.11 header
		 *  to inform PS STAs
		 */
		if (more) {
			wsm = (struct hif_req_tx *) hdr->body;
			hdr80211 = (struct ieee80211_hdr *) (wsm->frame + wsm->data_flags.fc_offset);
			hdr80211->frame_control |= cpu_to_le16(IEEE80211_FCTL_MOREDATA);
		}
		return hdr;
	}
}

