/*
 * WSM host interface (HI) implementation for Silicon Labs WFX mac80211 drivers
 *
 * Copyright (c) 2017, Silicon Laboratories, Inc.
 * Copyright (c) 2010, ST-Ericsson
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <linux/skbuff.h>
#include <linux/etherdevice.h>

#include "wsm.h"
#include "wfx_version.h"
#include "wfx.h"
#include "bh.h"
#include "debug.h"
#include "sta.h"
#include "testmode.h"

static int wsm_generic_confirm(struct wfx_dev *wdev, HiMsgHdr_t *hdr, void *buf)
{
	struct wfx_vif *wvif = wdev_to_wvif(wdev, hdr->s.b.IntId);
	// All confirm messages start with Status
	int status = le32_to_cpu(*((__le32 *) buf));
	int cmd = hdr->s.t.MsgId;
	int len = hdr->MsgLen - 4; // drop header

	WARN(!mutex_is_locked(&wdev->wsm_cmd.lock), "Data locking error");

	if (cmd != wdev->wsm_cmd.buf_send->s.b.Id) {
		dev_warn(wdev->pdev, "Chip response mismatch request: %#.4X vs %#.4X\n",
			 cmd, wdev->wsm_cmd.buf_send->s.b.Id);
		return -EINVAL;
	}

	if (wdev->wsm_cmd.buf_recv) {
		if (wdev->wsm_cmd.len_recv >= len)
			memcpy(wdev->wsm_cmd.buf_recv, buf, len);
		else
			status = -EINVAL;
	}
	wdev->wsm_cmd.ret = status;

	// Legacy chip have a special management for this case.
	// Is it still necessary?
	WARN_ON(status && wvif->join_status >= WFX_JOIN_STATUS_JOINING);

	complete(&wdev->wsm_cmd.done);

	return status;
}

static int wsm_tx_confirm(struct wfx_dev *wdev, HiMsgHdr_t *hdr, void *buf)
{
	WsmHiTxCnfBody_t *body = buf;

	wfx_tx_confirm_cb(wdev, body);
	return 0;
}

static int wsm_multi_tx_confirm(struct wfx_dev *wdev, HiMsgHdr_t *hdr, void *buf)
{
	WsmHiMultiTransmitCnfBody_t *body = buf;
	WsmHiTxCnfBody_t *buf_loc = (WsmHiTxCnfBody_t *) &body->TxConfPayload;
	int count = body->NumTxConfs;
	int ret = 0;
	int i;

	if (count <= 0) {
		wfx_err(
			"Number of transmit confirmation message payload error %d\n",
			count);
		return -EINVAL;
	}

	if (count > 1) {
		ret = wsm_release_tx_buffer(wdev, count - 1);
		if (ret < 0) {
			wfx_err("Can not release transmit buffer");
			return ret;
		} else if (ret > 0) {
			wfx_bh_wakeup(wdev);
	}
	}

	wfx_debug_txed_multi(wdev, count);
	for (i = 0; i < count; ++i) {
		wfx_tx_confirm_cb(wdev, buf_loc);
		buf_loc++;
	}
	return ret;
}

int wfx_unmap_link(struct wfx_vif *wvif, int sta_id)
{
	u8 *mac_addr = NULL;

	if (sta_id)
		mac_addr = wvif->link_id_db[sta_id - 1].old_mac;

	return wsm_map_link(wvif->wdev, mac_addr, 1, sta_id, wvif->Id);
}

int wsm_set_probe_responder(struct wfx_vif *wvif, bool enable)
{
	wvif->rx_filter.probeResponder = enable;
	return wsm_set_rx_filter(wvif->wdev, &wvif->rx_filter, wvif->Id);
}


static int wsm_startup_indication(struct wfx_dev *wdev, HiMsgHdr_t *hdr, void *buf)
{
	HiStartupIndBody_t *body = buf;

	memcpy(&wdev->wsm_caps, body, sizeof(HiStartupIndBody_t));
	le32_to_cpus(&wdev->wsm_caps.Status);
	le16_to_cpus(&wdev->wsm_caps.HardwareId);
	le16_to_cpus(&wdev->wsm_caps.NumInpChBufs);
	le16_to_cpus(&wdev->wsm_caps.SizeInpChBuf);
	if (body->Status || body->FirmwareType > 4) {
		dev_err(wdev->pdev, "Received invalid startup indication");
		return -EINVAL;
	}

	dev_info(wdev->pdev, "Firmware \"%s\" started. API: %.2x caps: %#.8X\n",
		 body->FirmwareLabel, body->ApiVersion,
		 *((uint32_t *) &body->Capabilities));

	/* Disable unsupported frequency bands */
/*    if (!(wdev->wsm_caps.FirmwareCap & 0x1)) */
/*        wdev->hw->wiphy->bands[NL80211_BAND_2GHZ] = NULL; */
/*    if (!(wdev->wsm_caps.FirmwareCap & 0x2)) */
	wdev->hw->wiphy->bands[NL80211_BAND_5GHZ] = NULL;

	complete(&wdev->firmware_ready);
	return 0;
}

static int wsm_receive_indication(struct wfx_dev *wdev, HiMsgHdr_t *hdr, void *buf, struct sk_buff **skb_p)
{
	// FIXME: Get interface id from wsm_buf or if_id
	struct wfx_vif *wvif = wdev_to_wvif(wdev, 0);
	WsmHiRxIndBody_t *body = buf;
	struct ieee80211_hdr *frame;
	__le16 fctl;
	int sta_id;

	skb_pull(*skb_p, sizeof(WsmHiRxIndBody_t));


	frame = (struct ieee80211_hdr *)(*skb_p)->data;

	if (!body->RcpiRssi &&
	    (ieee80211_is_probe_resp(frame->frame_control) ||
	     ieee80211_is_beacon(frame->frame_control)))
		return 0;

	if (!wvif->cqm_use_rssi)
		body->RcpiRssi = body->RcpiRssi / 2 - 110;

	fctl = frame->frame_control;
	pr_debug("[WSM] \t\t rx_flags=0x%.8X, frame_ctrl=0x%.4X\n",
		 *((uint32_t *)&body->RxFlags), le16_to_cpu(fctl));


	sta_id = body->RxFlags.PeerStaId;

	wfx_rx_cb(wvif, body, sta_id, skb_p);
	if (*skb_p)
		skb_push(*skb_p, sizeof(WsmHiRxIndBody_t));

	return 0;
}

static int wsm_event_indication(struct wfx_dev *wdev, HiMsgHdr_t *hdr, void *buf)
{
	struct wfx_vif *wvif = wdev_to_wvif(wdev, hdr->s.b.IntId);
	WsmHiEventIndBody_t *body = buf;
	struct wfx_wsm_event *event;
	int first;

	if (!wvif || wvif->mode == NL80211_IFTYPE_UNSPECIFIED)
		/* STA is stopped. */
		return 0;

	event = kzalloc(sizeof(*event), GFP_KERNEL);
	if (!event)
		return -ENOMEM;

	memcpy(&event->evt, body, sizeof(WsmHiEventIndBody_t));

	pr_debug("[WSM] Event: %d(%d)\n",
		 event->evt.EventId, *((uint32_t *)&event->evt.EventData));

	spin_lock(&wvif->event_queue_lock);
	first = list_empty(&wvif->event_queue);
	list_add_tail(&event->link, &wvif->event_queue);
	spin_unlock(&wvif->event_queue_lock);

	if (first)
		queue_work(wdev->workqueue, &wvif->event_handler);

	return 0;
}

static int wsm_channel_switch_indication(struct wfx_dev *wdev, HiMsgHdr_t *hdr, void *buf)
{
	WsmHiSwitchChannelCnfBody_t *body = buf;

	if (body->Status) {
		wfx_err("Failed to receive: indication during channel switch");
		return -EINVAL;
	}
	wdev->channel_switch_in_progress = 0;
	wake_up(&wdev->channel_switch_done);
	wsm_unlock_tx(wdev);

	return 0;
}

static int wsm_set_pm_indication(struct wfx_dev *wdev, HiMsgHdr_t *hdr, void *buf)
{
	if (wdev->ps_mode_switch_in_progress) {
		wdev->ps_mode_switch_in_progress = 0;
		wake_up(&wdev->ps_mode_switch_done);
	}
	return 0;
}

static int wsm_scan_complete_indication(struct wfx_dev *wdev, HiMsgHdr_t *hdr, void *buf)
{
	WsmHiScanCmplIndBody_t *body = buf;

	wfx_scan_complete_cb(wdev, body);

	return 0;
}

static int wsm_join_complete_indication(struct wfx_dev *wdev, HiMsgHdr_t *hdr, void *buf)
{
	struct wfx_vif *wvif = wdev_to_wvif(wdev, hdr->s.b.IntId);
	WsmHiJoinCompleteIndBody_t *body = buf;

	pr_debug("[WSM] Join complete indication, status: %d\n", body->Status);
	wfx_join_complete_cb(wvif, body);

	return 0;
}

static int wsm_dbg_info_indication(struct wfx_dev *wdev, HiMsgHdr_t *hdr, void *buf)
{
	WsmHiDebugIndBody_t *body = buf;
	int msgLen = hdr->MsgLen;

	switch (body->DbgId) {
	case 6:
		wfx_err("dbg msg CPU profiling : cpu_load=%d\n",
			body->DbgData.EptaRtStats.MsgStartIdentifier);
		break;
	case 7:
		wfx_testmode_bs_buffer_add((uint8_t *) &body->DbgData, msgLen - 8);
		break;
	default:
		break;
	}

	return 0;
}

static int wsm_ba_timeout_indication(struct wfx_dev *wdev, HiMsgHdr_t *hdr, void *buf)
{
	WsmHiBaTimeoutIndBody_t *body = buf;

	wfx_info("BlockACK timeout, tid %d, addr %pM\n", body->TID, body->TransmitAddress);

	return 0;
}

static int wsm_suspend_resume_indication(struct wfx_dev *wdev, HiMsgHdr_t *hdr, void *buf)
{
	WsmHiSuspendResumeTxIndBody_t *body = buf;

	wfx_suspend_resume(wdev, body);

	return 0;
}

static int wsm_error_indication(struct wfx_dev *wdev, HiMsgHdr_t *hdr, void *buf)
{
	HiErrorIndBody_t *body = buf;

	wfx_err(" : type 0x%x\n", body->Type);
	return 0;
}

static void pr_rx_stats(HiRxStats_t *rx_stats)
{
	u32 *rx = rx_stats->NbRxByRate;
	u16 *per = rx_stats->Per;
	s16 *rssi = rx_stats->Rssi;
	s16 *snr = rx_stats->Snr;
	s16 *cfo = rx_stats->Cfo;

	pr_info("Receiving new Rx statistics t = %dus:\n", rx_stats->Date);
	pr_info("NbFrame %d, PERx10000 %d , throughput %dKbps/s\n",
			rx_stats->NbRxFrame, rx_stats->PerTotal, rx_stats->Throughput);
	pr_info("NbFrame by rate:\n");
	pr_info("\t1Mbps %d, 2Mpbs %d, 5.5Mbps %d, 11Mpbs %d\n",
		rx[0], rx[1], rx[2], rx[3]);
	pr_info("\t6Mbps %d, 9Mpbs %d, 12Mbps %d, 18Mpbs %d, 24Mbps %d, 36Mbps %d, 48Mbps %d, 54Mbps %d\n",
		rx[6], rx[7], rx[8], rx[9], rx[10], rx[11], rx[12], rx[13]);
	pr_info("\tMCS0 %d, MCS1 %d, MCS2 %d, MCS3 %d, MCS4 %d, MCS5 %d, MCS6 %d, MCS7 %d\n",
		rx[14], rx[15], rx[16], rx[17], rx[18], rx[19], rx[20], rx[21]);
	pr_info("PERx10000 by rate:\n");
	pr_info("\t1Mbps %d, 2Mpbs %d, 5.5Mbps %d, 11Mpbs %d\n",
		per[0], per[1], per[2], per[3]);
	pr_info("\t6Mbps %d, 9Mpbs %d, 12Mbps %d, 18Mpbs %d, 24Mbps %d, 36Mbps %d, 48Mbps %d, 54Mbps %d\n",
		per[6], per[7], per[8], per[9], per[10], per[11], per[12], per[13]);
	pr_info("\tMCS0 %d, MCS1 %d, MCS2 %d, MCS3 %d, MCS4 %d, MCS5 %d, MCS6 %d, MCS7 %d\n",
		per[14], per[15], per[16], per[17], per[18], per[19], per[20], per[21]);
	pr_info("RSSI(dB) by rate:\n");
	pr_info("\t1Mbps %d, 2Mpbs %d, 5.5Mbps %d, 11Mpbs %d\n",
		rssi[0] / 100, rssi[1] / 100, rssi[2] / 100, rssi[3] / 100);
	pr_info("\t6Mbps %d, 9Mpbs %d, 12Mbps %d, 18Mpbs %d, 24Mbps %d, 36Mbps %d, 48Mbps %d, 54Mbps %d\n",
		rssi[6] / 100, rssi[7] / 100, rssi[8] / 100, rssi[9] / 100,
		rssi[10] / 100, rssi[11] / 100, rssi[12] / 100, rssi[13] / 100);
	pr_info("\tMCS0 %d, MCS1 %d, MCS2 %d, MCS3 %d, MCS4 %d, MCS5 %d, MCS6 %d, MCS7 %d\n",
		rssi[14] / 100, rssi[15] / 100, rssi[16] / 100, rssi[17] / 100,
		rssi[18] / 100, rssi[19] / 100, rssi[20] / 100, rssi[21] / 100);
	pr_info("SNR (dB) by rate:\n");
	pr_info("\t1Mbps %d, 2Mpbs %d, 5.5Mbps %d, 11Mpbs %d\n",
		snr[0] / 100, snr[1] / 100, snr[2] / 100, snr[3] / 100);
	pr_info("\t6Mbps %d, 9Mpbs %d, 12Mbps %d, 18Mpbs %d, 24Mbps %d, 36Mbps %d, 48Mbps %d, 54Mbps %d\n",
		snr[6] / 100, snr[7] / 100, snr[8] / 100, snr[9] / 100,
		snr[10] / 100, snr[11] / 100, snr[12] / 100, snr[13] / 100);
	pr_info("\tMCS0 %d, MCS1 %d, MCS2 %d, MCS3 %d, MCS4 %d, MCS5 %d, MCS6 %d, MCS7 %d\n",
		snr[14] / 100, snr[15] / 100, snr[16] / 100, snr[17] / 100,
		snr[18] / 100, snr[19] / 100, snr[20] / 100, snr[21] / 100);
	pr_info("CFO by rate (in kHz):\n");
	pr_info("\t1Mbps %d, 2Mpbs %d, 5.5Mbps %d, 11Mpbs %d\n",
		cfo[0], cfo[1], cfo[2], cfo[3]);
	pr_info("\t6Mbps %d, 9Mpbs %d, 12Mbps %d, 18Mpbs %d, 24Mbps %d, 36Mbps %d, 48Mbps %d, 54Mbps %d\n",
		cfo[6], cfo[7], cfo[8], cfo[9], cfo[10], cfo[11], cfo[12], cfo[13]);
	pr_info("\tMCS0 %d, MCS1 %d, MCS2 %d, MCS3 %d, MCS4 %d, MCS5 %d, MCS6 %d, MCS7 %d\n",
		cfo[14], cfo[15], cfo[16], cfo[17], cfo[18], cfo[19], cfo[20], cfo[21]);
	pr_info("External power clock %u, frequency %u:\n",
		rx_stats->IsExtPwrClk, rx_stats->PwrClkFreq);
}

static int wsm_generic_indication(struct wfx_dev *wdev, HiMsgHdr_t *hdr, void *buf)
{
	HiGenericIndBody_t *body = buf;

	switch (body->IndicationId) {
	case  HI_GENERIC_INDICATION_ID_RAW:
		/* Not used yet */
		break;
	case HI_GENERIC_INDICATION_ID_STRING:
		/* Display received message */
		wfx_info("%s", (char *) body->IndicationData.RawData);
		break;
	case HI_GENERIC_INDICATION_ID_RX_STATS:
		pr_rx_stats(&body->IndicationData.RxStats);
		break;
	default:
		wfx_err("wrong type in generic_ind\n");
		return -1;
	}

	return 0;
}

void wsm_lock_tx(struct wfx_dev *wdev)
{
	mutex_lock(&wdev->wsm_cmd.lock);
	if (atomic_add_return(1, &wdev->tx_lock) == 1)
		if (wsm_flush_tx(wdev))
			pr_debug("[WSM] TX is locked.\n");
	mutex_unlock(&wdev->wsm_cmd.lock);
}

void wsm_lock_tx_async(struct wfx_dev *wdev)
{
	if (atomic_add_return(1, &wdev->tx_lock) == 1)
		pr_debug("[WSM] TX is locked (async).\n");
}

bool wsm_flush_tx(struct wfx_dev *wdev)
{
	unsigned long timestamp = jiffies;
	long timeout;

	/* Flush must be called with TX lock held. */
	BUG_ON(!atomic_read(&wdev->tx_lock));
	/* First check if we really need to do something.
	 * It is safe to use unprotected access, as hw_bufs_used
	 * can only decrements.
	 */
	if (!wdev->hw_bufs_used)
		return true;

	if (wdev->bh_error) {
		/* In case of failure do not wait for magic. */
		wfx_err("[WSM] Fatal error occurred, will not flush TX.\n");
		return false;
	} else {
		bool pending = false;
		int i;

		/* Get a timestamp of "oldest" frame */
		for (i = 0; i < 4; ++i)
			pending |= wfx_queue_get_xmit_timestamp(
				&wdev->tx_queue[i],
					&timestamp, 0xffffffff);
		/* If there's nothing pending, we're good */
		if (!pending)
			return true;

		timeout = timestamp + WSM_CMD_LAST_CHANCE_TIMEOUT - jiffies;
		if (timeout < 0 || wait_event_timeout(wdev->bh_evt_wq,
						      !wdev->hw_bufs_used,
						      timeout) <= 0) {
			/* Hmmm... Not good. Frame had stuck in firmware. */
			wdev->bh_error = 1;
			wiphy_err(wdev->hw->wiphy,
				  "[WSM] TX Frames (%d) stuck in firmware, killing BH\n",
				  wdev->hw_bufs_used);
			wake_up(&wdev->bh_wq);
			return false;
		}
		/* Ok, everything is flushed. */
		return true;
	}
}

void wsm_unlock_tx(struct wfx_dev *wdev)
{
	int tx_lock;

	tx_lock = atomic_sub_return(1, &wdev->tx_lock);
	BUG_ON(tx_lock < 0);

	if (tx_lock == 0) {
		if (!wdev->bh_error)
			wfx_bh_wakeup(wdev);
		pr_debug("[WSM] TX is unlocked.\n");
	}
}

static int wsm_exception_indication(struct wfx_dev *wdev, HiMsgHdr_t *hdr, void *buf)
{
	HiExceptionIndBody_t *body = buf;
	size_t len = hdr->MsgLen - 4; // drop header
	static const char * const reason_str[] = {
		"undefined instruction",
		"prefetch abort",
		"data abort",
		"unknown error",
	};

	if (len < sizeof(HiExceptionIndBody_t)) {
		dev_err(wdev->pdev, "Firmware exception.\n");
		print_hex_dump_bytes("Exception: ", DUMP_PREFIX_NONE, buf, len);
		return -EINVAL;
	}

	if (body->Reason < 4) {
		dev_err(wdev->pdev, "Firmware exception: %s\n",
			reason_str[body->Reason]);
		return -1;
	}

	dev_err(wdev->pdev, "Firmware assert: id %d, error code %X\n",
		body->Reserved_1, body->Reserved_2);

	return -1;
}

static const struct {
	int msg_id;
	int (* handler)(struct wfx_dev *, HiMsgHdr_t *, void *);
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
	{ WSM_HI_EDCA_PARAMS_CNF_ID,     wsm_generic_confirm },
	{ WSM_HI_BEACON_TRANSMIT_CNF_ID, wsm_generic_confirm },
	{ WSM_HI_TX_QUEUE_PARAMS_CNF_ID, wsm_generic_confirm },
	{ WSM_HI_SET_BSS_PARAMS_CNF_ID,  wsm_generic_confirm },
	{ WSM_HI_SET_PM_MODE_CNF_ID,     wsm_generic_confirm },
	{ WSM_HI_UPDATE_IE_CNF_ID,       wsm_generic_confirm },
	{ HI_CONFIGURATION_CNF_ID,       wsm_generic_confirm },
	/* Indications */
	{ WSM_HI_EVENT_IND_ID,           wsm_event_indication },
	{ WSM_HI_SET_PM_MODE_CMPL_IND_ID, wsm_set_pm_indication },
	{ WSM_HI_DEBUG_IND_ID,           wsm_dbg_info_indication },
	{ WSM_HI_BA_TIMEOUT_IND_ID,      wsm_ba_timeout_indication },
	{ WSM_HI_JOIN_COMPLETE_IND_ID,   wsm_join_complete_indication },
	{ WSM_HI_SCAN_CMPL_IND_ID,       wsm_scan_complete_indication },
	{ WSM_HI_SWITCH_CHANNEL_IND_ID,  wsm_channel_switch_indication },
	{ WSM_HI_SUSPEND_RESUME_TX_IND_ID, wsm_suspend_resume_indication },
	{ HI_ERROR_IND_ID,               wsm_error_indication },
	{ HI_STARTUP_IND_ID,             wsm_startup_indication },
	{ HI_GENERIC_IND_ID,             wsm_generic_indication },
	{ HI_EXCEPTION_IND_ID,           wsm_exception_indication },
	// FIXME: allocate skb_p from wsm_receive_indication and make it generic
	//{ WSM_HI_RX_IND_ID,            wsm_receive_indication },
 };

int wsm_handle_rx(struct wfx_dev *wdev, HiMsgHdr_t *wsm, struct sk_buff **skb_p)
{
	int i;
	int wsm_id = wsm->s.t.MsgId;

	if (wsm_id == WSM_HI_RX_IND_ID)
		return wsm_receive_indication(wdev, &wsm[0], &wsm[1], skb_p);
	for (i = 0; i < ARRAY_SIZE(wsm_handlers); i++)
		if (wsm_handlers[i].msg_id == wsm_id)
			return wsm_handlers[i].handler(wdev, &wsm[0], &wsm[1]);
	dev_err(wdev->pdev, "Unsupported WSM ID %02x\n", wsm_id);
	return -EIO;
}

static bool wsm_handle_tx_data(struct wfx_vif		*wvif,
			       WsmHiTxReq_t			*wsm,
			       const struct ieee80211_tx_info *tx_info,
			       const struct wfx_txpriv *txpriv,
			       struct wfx_queue *queue)
{
	bool handled = false;
	const struct ieee80211_hdr *frame =
		(struct ieee80211_hdr *)&((u8 *)wsm)[txpriv->offset];
	__le16 fctl = frame->frame_control;

	enum {
		do_probe,
		do_drop,
		do_wep,
		do_tx,
	} action = do_tx;

	switch (wvif->mode) {
	case NL80211_IFTYPE_STATION:
		if (wvif->join_status == WFX_JOIN_STATUS_MONITOR)
			action = do_tx;
		else if (wvif->join_status < WFX_JOIN_STATUS_PRE_STA)
			action = do_drop;
		break;
	case NL80211_IFTYPE_AP:
		if (!wvif->join_status) {
			action = do_drop;
		} else if (!(BIT(txpriv->raw_link_id) &
		      (BIT(0) | wvif->link_id_map))) {
			wiphy_warn(wvif->wdev->hw->wiphy,
				   "A frame with expired link id is dropped.\n");
			action = do_drop;
		}
		if (wfx_queue_get_generation(wsm->Body.PacketId) >
				WFX_MAX_REQUEUE_ATTEMPTS) {
			wiphy_warn(wvif->wdev->hw->wiphy,
				   "Too many attempts to requeue a frame; dropped.\n");
			action = do_drop;
		}
		break;
	case NL80211_IFTYPE_ADHOC:
		if (wvif->join_status != WFX_JOIN_STATUS_IBSS)
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
				wvif->bss_loss_confirm_id = wsm->Body.PacketId;
				wsm->Body.QueueId.QueueId = WSM_QUEUE_ID_VOICE;
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
		wsm_lock_tx_async(wvif->wdev);
		wvif->wdev->pending_frame_id = wsm->Body.PacketId;
		if (queue_delayed_work(wvif->wdev->workqueue,
				       &wvif->wdev->scan.probe_work, 0) <= 0)
			wsm_unlock_tx(wvif->wdev);
		handled = true;
		break;
	case do_drop:
		pr_debug("[WSM] Drop frame (0x%.4X).\n", fctl);
		BUG_ON(wfx_queue_remove(queue, wsm->Body.PacketId));
		handled = true;
		break;
	case do_wep:
		pr_debug("[WSM] Issue set_default_wep_key.\n");
		wsm_lock_tx_async(wvif->wdev);
		wvif->wep_default_key_id = tx_info->control.hw_key->keyidx;
		wvif->wdev->pending_frame_id = wsm->Body.PacketId;
		if (queue_work(wvif->wdev->workqueue, &wvif->wep_key_work) <= 0)
			wsm_unlock_tx(wvif->wdev);
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
				 u32 link_id_map, int *total)
{
	static const int urgent = BIT(WFX_LINK_ID_AFTER_DTIM) |
		BIT(WFX_LINK_ID_UAPSD);
	WsmHiEdcaParamsReqBody_t *edca;
	unsigned score, best = -1;
	int winner = -1;
	int i;

	edca = &wvif->edca.params;
	for (i = 0; i < 4; ++i) {
		int queued;
		queued = wfx_queue_get_num_queued(&wvif->wdev->tx_queue[i],
				link_id_map);
		if (!queued)
			continue;
		*total += queued;
		score = ((edca->AIFSN[i] + edca->CwMin[i]) << 16) +
			((edca->CwMax[i] - edca->CwMin[i]) *
			 (get_random_int() & 0xFFFF));
		if (score < best && (winner < 0 || i != 3)) {
			best = score;
			winner = i;
		}
	}

	/* override winner if bursting */
	if (winner >= 0 && wvif->wdev->tx_burst_idx >= 0 &&
	    winner != wvif->wdev->tx_burst_idx &&
	    !wfx_queue_get_num_queued(&wvif->wdev->tx_queue[winner], link_id_map & urgent) &&
	    wfx_queue_get_num_queued(&wvif->wdev->tx_queue[wvif->wdev->tx_burst_idx], link_id_map))
		winner = wvif->wdev->tx_burst_idx;

	return winner;
}

static int wsm_get_tx_queue_and_mask(struct wfx_dev	*wdev,
				     struct wfx_queue **queue_p,
				     u32 *tx_allowed_mask_p,
				     bool *more)
{
	int idx;
	u32 tx_allowed_mask;
	int total = 0;
	// FIXME: Get interface id from wsm_buf or if_id
	struct wfx_vif *wvif = wdev_to_wvif(wdev, 0);

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
	*queue_p = &wdev->tx_queue[idx];
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
	       size_t *tx_len, int *burst)
{
	WsmHiTxReq_t *wsm = NULL;
	struct ieee80211_tx_info *tx_info;
	struct wfx_queue *queue = NULL;
	u32 tx_allowed_mask = 0;
	const struct wfx_txpriv *txpriv = NULL;
	int count = 0;
	// FIXME: Get interface id from wsm_buf
	struct wfx_vif *wvif = wdev_to_wvif(wdev, 0);

	/* More is used only for broadcasts. */
	bool more = false;

	if (try_wait_for_completion(&wdev->wsm_cmd.ready)) {
		WARN(!mutex_is_locked(&wdev->wsm_cmd.lock), "Data locking error");
		*data = (u8 *) wdev->wsm_cmd.buf_send;
		*tx_len = le16_to_cpu(wdev->wsm_cmd.buf_send->MsgLen);
		*burst = 1;
		return 1;
	}
	if (!wvif) {
		// May happen during unregister
		dev_dbg(wdev->pdev, "%s: non-existant vif", __func__);
		return 0;
	}
	for (;;) {
		int ret;
		int queue_num;
		struct ieee80211_hdr *hdr;

		if (atomic_add_return(0, &wdev->tx_lock))
			break;

		spin_lock_bh(&wvif->ps_state_lock);

		ret = wsm_get_tx_queue_and_mask(wdev, &queue, &tx_allowed_mask, &more);
		queue_num = queue - wdev->tx_queue;

		if (wvif->buffered_multicasts && (ret || !more) &&
		    (wvif->tx_multicast || !wvif->sta_asleep_mask)) {
			wvif->buffered_multicasts = false;
			if (wvif->tx_multicast) {
				wvif->tx_multicast = false;
				queue_work(wdev->workqueue, &wvif->multicast_stop_work);
			}
		}

		spin_unlock_bh(&wvif->ps_state_lock);

		if (ret)
			break;

		if (wfx_queue_get(queue, tx_allowed_mask, &wsm, &tx_info, &txpriv))
			continue;

		if (wsm_handle_tx_data(wvif, wsm, tx_info, txpriv, queue))
			continue;  /* Handled by WSM */

		wsm->Header.s.b.IntId = 0;
		wvif->pspoll_mask &= ~BIT(txpriv->raw_link_id);

		*data = (u8 *)wsm;
		*tx_len = le16_to_cpu(wsm->Header.MsgLen);

		/* allow bursting if txop is set */
		if (wvif->edca.params.TxOpLimit[queue_num])
			*burst = (int)wfx_queue_get_num_queued(queue, tx_allowed_mask) + 1;
		else
			*burst = 1;

		/* store index of bursting queue */
		if (*burst > 1)
			wdev->tx_burst_idx = queue_num;
		else
			wdev->tx_burst_idx = -1;

		hdr = (struct ieee80211_hdr *) &((u8 *) wsm)[txpriv->offset];
		if (more)
			hdr->frame_control |= cpu_to_le16(IEEE80211_FCTL_MOREDATA);
		pr_debug("[WSM] Tx sta_id=%d >>> frame_ctrl=0x%.4x  tx_len=%zu, %p %c\n",
			txpriv->link_id, hdr->frame_control, *tx_len, *data,
			wsm->Body.More ? 'M' : ' ');
		++count;
		break;
	}

	return count;
}

