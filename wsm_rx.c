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
#include "wfx_version.h"
#include "wfx.h"
#include "bh.h"
#include "debug.h"
#include "sta.h"

static int wsm_generic_confirm(struct wfx_dev *wdev, struct wmsg *hdr, void *buf)
{
	// All confirm messages start with Status
	int status = le32_to_cpu(*((__le32 *) buf));
	int cmd = hdr->id;
	int len = hdr->len - 4; // drop header

	WARN(!mutex_is_locked(&wdev->wsm_cmd.lock), "Data locking error");

	if (!wdev->wsm_cmd.buf_send) {
		dev_warn(wdev->dev, "Unexpected confirmation: 0x%.2X\n", cmd);
		return -EINVAL;
	}

	if (cmd != wdev->wsm_cmd.buf_send->id) {
		dev_warn(wdev->dev, "Chip response mismatch request: 0x%.2X vs 0x%.2X\n",
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
	}
	return status;
}

static int wsm_tx_confirm(struct wfx_dev *wdev, struct wmsg *hdr, void *buf)
{
	WsmHiTxCnfBody_t *body = buf;

	wfx_tx_confirm_cb(wdev, body);
	return 0;
}

static int wsm_multi_tx_confirm(struct wfx_dev *wdev, struct wmsg *hdr, void *buf)
{
	WsmHiMultiTransmitCnfBody_t *body = buf;
	WsmHiTxCnfBody_t *buf_loc = (WsmHiTxCnfBody_t *) &body->TxConfPayload;
	int count = body->NumTxConfs;
	int i;

	WARN(count <= 0, "Corrupted message");

	wfx_debug_txed_multi(wdev, count);
	for (i = 0; i < count; ++i) {
		wfx_tx_confirm_cb(wdev, buf_loc);
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
	wvif->rx_filter.probeResponder = enable;
	return wsm_set_rx_filter(wvif->wdev, &wvif->rx_filter, wvif->Id);
}


static int wsm_startup_indication(struct wfx_dev *wdev, struct wmsg *hdr, void *buf)
{
	HiStartupIndBody_t *body = buf;

	if (body->Status || body->FirmwareType > 4) {
		dev_err(wdev->dev, "Received invalid startup indication");
		return -EINVAL;
	}
	memcpy(&wdev->wsm_caps, body, sizeof(HiStartupIndBody_t));
	le32_to_cpus(&wdev->wsm_caps.Status);
	le16_to_cpus(&wdev->wsm_caps.HardwareId);
	le16_to_cpus(&wdev->wsm_caps.NumInpChBufs);
	le16_to_cpus(&wdev->wsm_caps.SizeInpChBuf);

	complete(&wdev->firmware_ready);
	return 0;
}

static int wsm_wakeup_indication(struct wfx_dev *wdev, struct wmsg *hdr, void *buf)
{
	if (!wdev->pdata.gpio_wakeup
	    || !gpiod_get_value(wdev->pdata.gpio_wakeup)) {
		dev_warn(wdev->dev, "unexpected wake-up indication\n");
		return -EIO;
	}
	return 0;
}

static int wsm_receive_indication(struct wfx_dev *wdev, struct wmsg *hdr, void *buf, struct sk_buff **skb_p)
{
	struct wfx_vif *wvif = wdev_to_wvif(wdev, hdr->interface);
	WsmHiRxIndBody_t *body = buf;
	struct ieee80211_hdr *frame;
	__le16 fctl;
	int sta_id;

	if (!wvif) {
		dev_warn(wdev->dev, "ignore rx data for non existant vif %d\n", hdr->interface);
		return 0;
	}
	skb_pull(*skb_p, sizeof(struct wmsg) + sizeof(WsmHiRxIndBody_t));

	frame = (struct ieee80211_hdr *)(*skb_p)->data;

	if (!body->RcpiRssi &&
	    (ieee80211_is_probe_resp(frame->frame_control) ||
	     ieee80211_is_beacon(frame->frame_control)))
		return 0;

	/* If no RSSI subscription has been made,
	 * convert RCPI to RSSI here
	 */
	if (!wvif->cqm_use_rssi)
		body->RcpiRssi = body->RcpiRssi / 2 - 110;

	fctl = frame->frame_control;
	pr_debug("[WSM] \t\t rx_flags=0x%.8X, frame_ctrl=0x%.4X\n",
		 *((u32 *)&body->RxFlags), le16_to_cpu(fctl));

	sta_id = body->RxFlags.PeerStaId;

	wfx_rx_cb(wvif, body, sta_id, skb_p);
	if (*skb_p)
		skb_push(*skb_p, sizeof(struct wmsg) + sizeof(WsmHiRxIndBody_t));

	return 0;
}

static int wsm_event_indication(struct wfx_dev *wdev, struct wmsg *hdr, void *buf)
{
	struct wfx_vif *wvif = wdev_to_wvif(wdev, hdr->interface);
	WsmHiEventIndBody_t *body = buf;
	struct wfx_wsm_event *event;
	int first;

	WARN_ON(!wvif);
	if (!wvif)
		return 0;

	event = kzalloc(sizeof(*event), GFP_KERNEL);
	if (!event)
		return -ENOMEM;

	memcpy(&event->evt, body, sizeof(WsmHiEventIndBody_t));

	pr_debug("[WSM] Event: %d(%d)\n",
		 event->evt.EventId, *((u32 *)&event->evt.EventData));

	spin_lock(&wvif->event_queue_lock);
	first = list_empty(&wvif->event_queue);
	list_add_tail(&event->link, &wvif->event_queue);
	spin_unlock(&wvif->event_queue_lock);

	if (first)
		schedule_work(&wvif->event_handler_work);

	return 0;
}

static int wsm_pm_mode_complete_indication(struct wfx_dev *wdev, struct wmsg *hdr, void *buf)
{
	struct wfx_vif *wvif = wdev_to_wvif(wdev, hdr->interface);

	WARN_ON(!wvif);
	complete(&wvif->set_pm_mode_complete);

	return 0;
}

static int wsm_scan_complete_indication(struct wfx_dev *wdev, struct wmsg *hdr, void *buf)
{
	struct wfx_vif *wvif = wdev_to_wvif(wdev, hdr->interface);
	WsmHiScanCmplIndBody_t *body = buf;

	WARN_ON(!wvif);
	wfx_scan_complete_cb(wvif, body);

	return 0;
}

static int wsm_join_complete_indication(struct wfx_dev *wdev, struct wmsg *hdr, void *buf)
{
	struct wfx_vif *wvif = wdev_to_wvif(wdev, hdr->interface);

	WARN_ON(!wvif);
	dev_warn(wdev->dev, "unattended JoinCompleteInd\n");

	return 0;
}

static int wsm_suspend_resume_indication(struct wfx_dev *wdev, struct wmsg *hdr, void *buf)
{
	struct wfx_vif *wvif = wdev_to_wvif(wdev, hdr->interface);
	WsmHiSuspendResumeTxIndBody_t *body = buf;

	WARN_ON(!wvif);
	wfx_suspend_resume(wvif, body);

	return 0;
}

static int wsm_error_indication(struct wfx_dev *wdev, struct wmsg *hdr, void *buf)
{
	HiErrorIndBody_t *body = buf;

	dev_err(wdev->dev, "asynchronous error: %d\n", body->Type);
	return 0;
}

static int wsm_generic_indication(struct wfx_dev *wdev, struct wmsg *hdr, void *buf)
{
	HiGenericIndBody_t *body = buf;

	switch (body->IndicationType) {
	case  HI_GENERIC_INDICATION_TYPE_RAW:
		return 0;
	case HI_GENERIC_INDICATION_TYPE_STRING:
		dev_info(wdev->dev, "%s", (char *) body->IndicationData.RawData);
		return 0;
	case HI_GENERIC_INDICATION_TYPE_RX_STATS:
		mutex_lock(&wdev->rx_stats_lock);
		// Older firmware send a generic indication beside RxStats
		if (!wfx_api_older_than(wdev, 1, 4))
			dev_info(wdev->dev, "RX test ongoing. Temperature: %d°C\n", body->IndicationData.RxStats.CurrentTemp);
		memcpy(&wdev->rx_stats, &body->IndicationData.RxStats, sizeof(wdev->rx_stats));
		mutex_unlock(&wdev->rx_stats_lock);
		return 0;
	default:
		dev_err(wdev->dev, "generic_indication: unknown indication type: %#.8x\n", body->IndicationType);
		return -EIO;
	}
}

static int wsm_exception_indication(struct wfx_dev *wdev, struct wmsg *hdr, void *buf)
{
	size_t len = hdr->len - 4; // drop header
	dev_err(wdev->dev, "Firmware exception.\n");
	print_hex_dump_bytes("Dump: ", DUMP_PREFIX_NONE, buf, len);
	wdev->chip_frozen = 1;

	return -1;
}

static const struct {
	int msg_id;
	int (*handler)(struct wfx_dev *, struct wmsg *, void *);
} wsm_handlers[] = {
	/* Confirmations */
	{ WSM_HI_TX_CNF_ID,              wsm_tx_confirm },
	{ WSM_HI_MULTI_TRANSMIT_CNF_ID,  wsm_multi_tx_confirm },
	{ WSM_HI_ADD_KEY_CNF_ID,         wsm_generic_confirm },
	{ WSM_HI_REMOVE_KEY_CNF_ID,      wsm_generic_confirm },
	{ WSM_HI_RESET_CNF_ID,           wsm_generic_confirm },
	{ WSM_HI_START_CNF_ID,           wsm_generic_confirm },
	{ WSM_HI_START_SCAN_CNF_ID,      wsm_generic_confirm },
	{ WSM_HI_STOP_SCAN_CNF_ID,       wsm_generic_confirm },
	{ WSM_HI_JOIN_CNF_ID,            wsm_generic_confirm },
	{ WSM_HI_READ_MIB_CNF_ID,        wsm_generic_confirm },
	{ WSM_HI_WRITE_MIB_CNF_ID,       wsm_generic_confirm },
	{ WSM_HI_MAP_LINK_CNF_ID,        wsm_generic_confirm },
	{ WSM_HI_EDCA_QUEUE_PARAMS_CNF_ID, wsm_generic_confirm },
	{ WSM_HI_BEACON_TRANSMIT_CNF_ID, wsm_generic_confirm },
	{ WSM_HI_SET_BSS_PARAMS_CNF_ID,  wsm_generic_confirm },
	{ WSM_HI_SET_PM_MODE_CNF_ID,     wsm_generic_confirm },
	{ WSM_HI_UPDATE_IE_CNF_ID,       wsm_generic_confirm },
	{ HI_CONFIGURATION_CNF_ID,       wsm_generic_confirm },
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
	// FIXME: allocate skb_p from wsm_receive_indication and make it generic
	//{ WSM_HI_RX_IND_ID,            wsm_receive_indication },
};

int wsm_handle_rx(struct wfx_dev *wdev, struct wmsg *wsm, struct sk_buff **skb_p)
{
	int i;
	int wsm_id = wsm->id;

	if (wsm_id == WSM_HI_RX_IND_ID)
		return wsm_receive_indication(wdev, &wsm[0], &wsm[1], skb_p);
	for (i = 0; i < ARRAY_SIZE(wsm_handlers); i++)
		if (wsm_handlers[i].msg_id == wsm_id) {
			if (wsm_handlers[i].handler)
				return wsm_handlers[i].handler(wdev, &wsm[0], &wsm[1]);
			else
				return 0;
		}
	dev_err(wdev->dev, "Unsupported WSM ID %02x\n", wsm_id);
	return -EIO;
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
		wfx_queue_dump_old_frames(wdev, 3000);
	}
	mutex_unlock(&wdev->wsm_cmd.lock);
}

void wsm_tx_lock_flush(struct wfx_dev *wdev)
{
	wsm_tx_lock(wdev);
	wsm_tx_flush(wdev);
}

static bool wsm_handle_tx_data(struct wfx_vif *wvif,
			       WsmHiTxReqBody_t *wsm,
			       const struct ieee80211_tx_info *tx_info,
			       const struct wfx_txpriv *txpriv,
			       struct wfx_queue *queue)
{
	bool handled = false;
	u8 *buf8 = (u8 *) wsm;
	const struct ieee80211_hdr *frame =
		(struct ieee80211_hdr *) (buf8 + txpriv->offset - sizeof(struct wmsg));
	__le16 fctl = frame->frame_control;

	enum {
		do_probe,
		do_drop,
		do_wep,
		do_tx,
	} action = do_tx;

	switch (wvif->mode) {
	case NL80211_IFTYPE_STATION:
		if (wvif->state < WFX_STATE_PRE_STA)
			action = do_drop;
		break;
	case NL80211_IFTYPE_AP:
		if (!wvif->state) {
			action = do_drop;
		} else if (!(BIT(txpriv->raw_link_id) &
		      (BIT(0) | wvif->link_id_map))) {
			dev_warn(wvif->wdev->dev,
				   "A frame with expired link id is dropped.\n");
			action = do_drop;
		}
		if (wfx_queue_get_generation(wsm->PacketId) >
				WFX_MAX_REQUEUE_ATTEMPTS) {
			dev_warn(wvif->wdev->dev,
				   "Too many attempts to requeue a frame; dropped.\n");
			action = do_drop;
		}
		break;
	case NL80211_IFTYPE_ADHOC:
		if (wvif->state != WFX_STATE_IBSS)
			action = do_drop;
		break;
	case NL80211_IFTYPE_MESH_POINT:
		action = do_tx;
		break;
	case NL80211_IFTYPE_MONITOR:
	default:
		action = do_drop;
		break;
	}

	if (action == do_tx) {
		if (ieee80211_is_nullfunc(fctl)) {
			mutex_lock(&wvif->bss_loss_lock);
			if (wvif->bss_loss_state) {
				wvif->bss_loss_confirm_id = wsm->PacketId;
				wsm->QueueId.QueueId = WSM_QUEUE_ID_VOICE;
			}
			mutex_unlock(&wvif->bss_loss_lock);
		} else if (ieee80211_is_probe_req(fctl)) {
			action = do_probe;
		} else if (ieee80211_has_protected(fctl) &&
			   tx_info->control.hw_key &&
			   tx_info->control.hw_key->keyidx != wvif->wep_default_key_id &&
			   (tx_info->control.hw_key->cipher == WLAN_CIPHER_SUITE_WEP40 ||
			    tx_info->control.hw_key->cipher == WLAN_CIPHER_SUITE_WEP104)) {
			action = do_wep;
		}
	}

	switch (action) {
	case do_probe:
		pr_debug("[WSM] Convert probe request to scan.\n");
		wsm_tx_lock(wvif->wdev);
		wvif->wdev->pending_frame_id = wsm->PacketId;
		if (!schedule_work(&wvif->scan.probe_work.work))
			wsm_tx_unlock(wvif->wdev);
		handled = true;
		break;
	case do_drop:
		pr_debug("[WSM] Drop frame (0x%.4X).\n", fctl);
		BUG_ON(wfx_queue_remove(queue, wsm->PacketId));
		handled = true;
		break;
	case do_wep:
		pr_debug("[WSM] Issue set_default_wep_key.\n");
		wsm_tx_lock(wvif->wdev);
		wvif->wep_default_key_id = tx_info->control.hw_key->keyidx;
		wvif->wdev->pending_frame_id = wsm->PacketId;
		if (!schedule_work(&wvif->wep_key_work))
			wsm_tx_unlock(wvif->wdev);
		handled = true;
		break;
	case do_tx:
		pr_debug("[WSM] Transmit frame.\n");
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
	WsmHiEdcaQueueParamsReqBody_t *edca;
	unsigned score, best = -1;
	int winner = -1;
	int i;

	for (i = 0; i < 4; ++i) {
		int queued;
		edca = &wvif->edca.params[i];
		queued = wfx_queue_get_num_queued(&wvif->wdev->tx_queue[i],
				tx_allowed_mask);
		if (!queued)
			continue;
		*total += queued;
		score = ((edca->AIFSN + edca->CwMin) << 16) +
			((edca->CwMax - edca->CwMin) *
			 (get_random_int() & 0xFFFF));
		if (score < best && (winner < 0 || i != 3)) {
			best = score;
			winner = i;
		}
	}

	/* override winner if bursting */
	if (winner >= 0 && wvif->wdev->tx_burst_idx >= 0 &&
	    winner != wvif->wdev->tx_burst_idx &&
	    !wfx_queue_get_num_queued(&wvif->wdev->tx_queue[winner], tx_allowed_mask & urgent) &&
	    wfx_queue_get_num_queued(&wvif->wdev->tx_queue[wvif->wdev->tx_burst_idx], tx_allowed_mask))
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
int wsm_get_tx(struct wfx_dev *wdev, u8 **data,
	       size_t *tx_len)
{
	struct wmsg *hdr = NULL;
	WsmHiTxReqBody_t *wsm = NULL;
	struct ieee80211_tx_info *tx_info;
	struct wfx_queue *queue = NULL;
	struct wfx_queue *vif_queue = NULL;
	u32 tx_allowed_mask = 0;
	u32 vif_tx_allowed_mask = 0;
	const struct wfx_txpriv *txpriv = NULL;
	struct wfx_vif *wvif;
	/* More is used only for broadcasts. */
	bool more = false;
	bool vif_more = false;
	int not_found;
	int burst;

	if (try_wait_for_completion(&wdev->wsm_cmd.ready)) {
		WARN(!mutex_is_locked(&wdev->wsm_cmd.lock), "Data locking error");
		*data = (u8 *) wdev->wsm_cmd.buf_send;
		*tx_len = le16_to_cpu(wdev->wsm_cmd.buf_send->len);
		return 1;
	}
	for (;;) {
		int ret = -ENOENT;
		int queue_num;
		struct ieee80211_hdr *hdr80211;

		if (atomic_read(&wdev->tx_lock))
			return 0;

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

		if (wfx_queue_get(queue, tx_allowed_mask, &hdr, &tx_info, &txpriv))
			continue;
		wsm = (WsmHiTxReqBody_t *) hdr->body;
		// Note: txpriv->vif_id is reundant with hdr->interface
		wvif = wdev_to_wvif(wdev, hdr->interface);
		WARN_ON(!wvif);

		if (wsm_handle_tx_data(wvif, wsm, tx_info, txpriv, queue))
			continue;  /* Handled by WSM */

		wvif->pspoll_mask &= ~BIT(txpriv->raw_link_id);

		*data = (u8 *) hdr;
		*tx_len = le16_to_cpu(hdr->len);

		/* allow bursting if txop is set */
		if (wvif->edca.params[queue_num].TxOpLimit)
			burst = (int)wfx_queue_get_num_queued(queue, tx_allowed_mask) + 1;
		else
			burst = 1;

		/* store index of bursting queue */
		if (burst > 1)
			wdev->tx_burst_idx = queue_num;
		else
			wdev->tx_burst_idx = -1;

		hdr80211 = (struct ieee80211_hdr *) (data + txpriv->offset);

		if (more)
			hdr80211->frame_control |= cpu_to_le16(IEEE80211_FCTL_MOREDATA);
		pr_debug("[WSM] Tx sta_id=%d >>> frame_ctrl=0x%.4x  tx_len=%zu, %p %c\n",
			txpriv->link_id, hdr80211->frame_control, *tx_len, *data,
			wsm->DataFlags.More ? 'M' : ' ');
		return 1;
	}
}

