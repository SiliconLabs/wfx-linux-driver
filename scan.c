/*
 * Scan implementation for Silicon Labs WFX mac80211 drivers
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

#include <net/mac80211.h>

#include "scan.h"
#include "wfx.h"
#include "sta.h"

static void wfx_scan_restart_delayed(struct wfx_dev *wdev);

static int wfx_scan_start(struct wfx_dev *wdev, struct wsm_scan *scan)
{
	struct wfx_vif *wvif = wdev_to_wvif(wdev, 0);
	int ret;

	int tmo = 200;

	switch (wvif->join_status) {
	case WFX_JOIN_STATUS_PRE_STA:
	case WFX_JOIN_STATUS_JOINING:
		return -EBUSY;
	default:
		break;
	}

	tmo += scan->scan_req.NumOfChannels *
	       ((20 * (scan->scan_req.MaxChannelTime)) + 10);
	atomic_set(&wdev->scan.in_progress, 1);
	atomic_set(&wdev->wait_for_scan, 1);

	queue_delayed_work(wdev->workqueue, &wdev->scan.timeout,
			   msecs_to_jiffies(tmo));
	ret = wsm_scan(wdev, scan, 0);
	if (ret) {
		wfx_scan_failed_cb(wdev);
		atomic_set(&wdev->scan.in_progress, 0);
		atomic_set(&wdev->wait_for_scan, 0);
		cancel_delayed_work_sync(&wdev->scan.timeout);
		wfx_scan_restart_delayed(wdev);
	}
	return ret;
}

int wfx_hw_scan(struct ieee80211_hw *hw,
		   struct ieee80211_vif *vif,
		   struct ieee80211_scan_request *hw_req)
{
	struct wfx_dev *wdev = hw->priv;
	struct wfx_vif *wvif = wdev_to_wvif(wdev, 0);
	struct cfg80211_scan_request *req = &hw_req->req;
	struct sk_buff *skb;
	int i, ret;
	WsmHiMibTemplateFrame_t *p;

	if (!wdev->vif)
		return -EINVAL;

	/* Scan when P2P_GO corrupt firmware MiniAP mode */
	if (wvif->join_status == WFX_JOIN_STATUS_AP)
		return -EOPNOTSUPP;

	if (req->n_ssids == 1 && !req->ssids[0].ssid_len)
		req->n_ssids = 0;

	wiphy_dbg(hw->wiphy, "[SCAN] Scan request for %d SSIDs.\n",
		  req->n_ssids);

	if (req->n_ssids > WSM_API_SSID_DEF_SIZE)
		return -EINVAL;

	skb = ieee80211_probereq_get(hw, wdev->vif->addr, NULL, 0,
		req->ie_len);
	if (!skb)
		return -ENOMEM;

	if (req->ie_len)
		memcpy(skb_put(skb, req->ie_len), req->ie, req->ie_len);

	/* will be unlocked in wfx_scan_work() */
	down(&wdev->scan.lock);
	mutex_lock(&wdev->conf_mutex);

	p = (WsmHiMibTemplateFrame_t *)skb_push(skb, 4);
	p->FrameType = WSM_TMPLT_PRBREQ;
	p->FrameLength = cpu_to_le16(skb->len - 4);
	ret = wsm_set_template_frame(wdev, p, wvif->Id);
	skb_pull(skb, 4);

	if (!ret)
		/* Host want to be the probe responder. */
		ret = wsm_set_probe_responder(wvif, true);
	if (ret) {
		mutex_unlock(&wdev->conf_mutex);
		up(&wdev->scan.lock);
		dev_kfree_skb(skb);
		return ret;
	}

	wsm_lock_tx(wdev);

	BUG_ON(wdev->scan.req);
	wdev->scan.req = req;
	wdev->scan.n_ssids = 0;
	wdev->scan.status = 0;
	wdev->scan.begin = &req->channels[0];
	wdev->scan.curr = wdev->scan.begin;
	wdev->scan.end = &req->channels[req->n_channels];
	wdev->scan.output_power = wdev->output_power;

	for (i = 0; i < req->n_ssids; ++i) {
		WsmHiSsidDef_t *dst = &wdev->scan.ssids[wdev->scan.n_ssids];

		memcpy(&dst->SSID[0], req->ssids[i].ssid, sizeof(dst->SSID));
		dst->SSIDLength = req->ssids[i].ssid_len;
		++wdev->scan.n_ssids;
	}

	mutex_unlock(&wdev->conf_mutex);

	if (skb)
		dev_kfree_skb(skb);
	queue_work(wdev->workqueue, &wdev->scan.work);
	return 0;
}

static void __ieee80211_scan_completed_compat(struct ieee80211_hw *hw, bool aborted)
{
#if (KERNEL_VERSION(4, 8, 0) <= LINUX_VERSION_CODE)
	struct cfg80211_scan_info info = {
		.aborted = aborted ? 1 : 0,
	};

	ieee80211_scan_completed(hw, &info);
#else
	ieee80211_scan_completed(hw, aborted);
#endif
}

void wfx_scan_work(struct work_struct *work)
{
	struct wfx_dev *wdev = container_of(work, struct wfx_dev,
							scan.work);
	struct wfx_vif *wvif = wdev_to_wvif(wdev, 0);
	struct ieee80211_channel **it;
	struct wsm_scan scan = {
		.scan_req.ScanType.Type		= 0,    /* WSM_SCAN_TYPE_FG, */
	};
	bool first_run = (wdev->scan.begin == wdev->scan.curr &&
			  wdev->scan.begin != wdev->scan.end);
	int i;

	if (first_run) {
		if (cancel_delayed_work_sync(&wvif->join_timeout) > 0)
			wfx_join_timeout(&wvif->join_timeout.work);
	}

	mutex_lock(&wdev->conf_mutex);

	if (first_run) {
		if (wvif->join_status == WFX_JOIN_STATUS_STA &&
		    !(wvif->powersave_mode.PmMode.PmMode)) {
			WsmHiSetPmModeReqBody_t pm = wvif->powersave_mode;

			pm.PmMode.PmMode = 1;
			wfx_set_pm(wvif, &pm);
		} else if (wvif->join_status == WFX_JOIN_STATUS_MONITOR) {
			wfx_disable_listening(wvif);
		}
	}

	if (!wdev->scan.req || wdev->scan.curr == wdev->scan.end) {
		if (wdev->scan.output_power != wdev->output_power)
			wsm_set_output_power(wdev, wdev->output_power * 10, 0);

		if (wdev->scan.status < 0)
			wiphy_warn(wdev->hw->wiphy,
				   "[SCAN] Scan failed (%d).\n",
				   wdev->scan.status);
		else if (wdev->scan.req)
			wiphy_dbg(wdev->hw->wiphy,
				  "[SCAN] Scan completed.\n");
		else
			wiphy_dbg(wdev->hw->wiphy,
				  "[SCAN] Scan canceled.\n");

		wdev->scan.req = NULL;
		wfx_scan_restart_delayed(wdev);
		wsm_unlock_tx(wdev);
		mutex_unlock(&wdev->conf_mutex);
		__ieee80211_scan_completed_compat(wdev->hw, wdev->scan.status ? 1 : 0);
		up(&wdev->scan.lock);
		if (wvif->join_status == WFX_JOIN_STATUS_STA &&
		    !(wvif->powersave_mode.PmMode.PmMode))
			wfx_set_pm(wvif, &wvif->powersave_mode);
		return;
	} else {
		struct ieee80211_channel *first = *wdev->scan.curr;

		for (it = wdev->scan.curr + 1, i = 1;
		     it != wdev->scan.end && i < WSM_API_CHANNEL_LIST_SIZE;
		     ++it, ++i) {
			if ((*it)->band != first->band)
				break;
			if (((*it)->flags ^ first->flags) &
					IEEE80211_CHAN_NO_IR)
				break;
			if (!(first->flags & IEEE80211_CHAN_NO_IR) &&
			    (*it)->max_power != first->max_power)
				break;
		}
		scan.scan_req.Band = first->band;

		if (wdev->scan.req->no_cck)
			scan.scan_req.MaxTransmitRate = WSM_TRANSMIT_RATE_6;
		else
			scan.scan_req.MaxTransmitRate = WSM_TRANSMIT_RATE_1;
		scan.scan_req.NumOfProbeRequests =
			(first->flags & IEEE80211_CHAN_NO_IR) ? 0 : 2;
		scan.scan_req.NumOfSSIDs = wdev->scan.n_ssids;
		scan.ssids = &wdev->scan.ssids[0];
		scan.scan_req.NumOfChannels = it - wdev->scan.curr;
		scan.scan_req.ProbeDelay = 100;
		if (wvif->join_status == WFX_JOIN_STATUS_STA) {
			scan.scan_req.ScanType.Type = 1;        /* WSM_SCAN_TYPE_BG; */
			scan.scan_req.ScanFlags.Fbg = 1;        /* WSM_SCAN_FLAG_FORCE_BACKGROUND */
		}

		scan.ch = kcalloc(scan.scan_req.NumOfChannels,
				sizeof(u8),
			GFP_KERNEL);

		if (!scan.ch) {
			wdev->scan.status = -ENOMEM;
			goto fail;
		}
		for (i = 0; i < scan.scan_req.NumOfChannels; ++i)
			scan.ch[i] = wdev->scan.curr[i]->hw_value;

		if (wdev->scan.curr[0]->flags & IEEE80211_CHAN_NO_IR) {
			scan.scan_req.MinChannelTime = 50;
			scan.scan_req.MaxChannelTime = 150;
		} else {
			scan.scan_req.MinChannelTime = 10;
			scan.scan_req.MaxChannelTime = 50;
		}
		if (!(first->flags & IEEE80211_CHAN_NO_IR) &&
		    wdev->scan.output_power != first->max_power) {
			wdev->scan.output_power = first->max_power;
			wsm_set_output_power(wdev,
					     wdev->scan.output_power * 10, wvif->Id);
		}
		wdev->scan.status = wfx_scan_start(wdev, &scan);
		kfree(scan.ch);
		if (wdev->scan.status)
			goto fail;
		wdev->scan.curr = it;
	}
	mutex_unlock(&wdev->conf_mutex);
	return;

fail:
	wdev->scan.curr = wdev->scan.end;
	mutex_unlock(&wdev->conf_mutex);
	queue_work(wdev->workqueue, &wdev->scan.work);
}

static void wfx_scan_restart_delayed(struct wfx_dev *wdev)
{
	struct wfx_vif *wvif = wdev_to_wvif(wdev, 0);

	if (wvif->join_status == WFX_JOIN_STATUS_MONITOR) {
		wfx_enable_listening(wvif);
		wfx_update_filtering(wvif);
	}

	if (wvif->delayed_unjoin) {
		wvif->delayed_unjoin = false;
		if (queue_work(wdev->workqueue, &wvif->unjoin_work) <= 0)
			wsm_unlock_tx(wdev);
	} else if (wvif->delayed_link_loss) {
		wiphy_dbg(wdev->hw->wiphy, "[CQM] Requeue BSS loss.\n");
		wvif->delayed_link_loss = 0;
		wfx_cqm_bssloss_sm(wvif, 1, 0, 0);
	}
}

static void wfx_scan_complete(struct wfx_dev *wdev)
{
	atomic_set(&wdev->wait_for_scan, 0);

	if (wdev->scan.direct_probe) {
		wiphy_dbg(wdev->hw->wiphy, "[SCAN] Direct probe complete.\n");
		wfx_scan_restart_delayed(wdev);
		wdev->scan.direct_probe = 0;
		up(&wdev->scan.lock);
		wsm_unlock_tx(wdev);
	} else {
		wfx_scan_work(&wdev->scan.work);
	}
}

void wfx_scan_failed_cb(struct wfx_dev *wdev)
{
	struct wfx_vif *wvif = wdev_to_wvif(wdev, 0);

	if (wvif->mode == NL80211_IFTYPE_UNSPECIFIED)
		/* STA is stopped. */
		return;

	if (cancel_delayed_work_sync(&wdev->scan.timeout) > 0) {
		wdev->scan.status = -EIO;
		queue_delayed_work(wdev->workqueue, &wdev->scan.timeout, 0);
	}
}

void wfx_scan_complete_cb(struct wfx_dev		*wdev,
			  WsmHiScanCmplIndBody_t	*arg)
{
	struct wfx_vif *wvif = wdev_to_wvif(wdev, 0);

	if (wvif->mode == NL80211_IFTYPE_UNSPECIFIED)
		/* STA is stopped. */
		return;

	if (cancel_delayed_work_sync(&wdev->scan.timeout) > 0) {
		wdev->scan.status = 1;
		queue_delayed_work(wdev->workqueue, &wdev->scan.timeout, 0);
	}
}

void wfx_scan_timeout(struct work_struct *work)
{
	struct wfx_dev *wdev =
		container_of(work, struct wfx_dev, scan.timeout.work);
	struct wfx_vif *wvif = wdev_to_wvif(wdev, 0);

	if (atomic_xchg(&wdev->scan.in_progress, 0)) {
		if (wdev->scan.status > 0) {
			wdev->scan.status = 0;
		} else if (!wdev->scan.status) {
			wiphy_warn(wdev->hw->wiphy,
				   "Timeout waiting for scan complete notification.\n");
			wdev->scan.status = -ETIMEDOUT;
			wdev->scan.curr = wdev->scan.end;
			wsm_stop_scan(wdev, wvif->Id);
		}
		wfx_scan_complete(wdev);
	}
}

void wfx_probe_work(struct work_struct *work)
{
	struct wfx_dev *wdev =
		container_of(work, struct wfx_dev, scan.probe_work.work);
	struct wfx_vif *wvif = wdev_to_wvif(wdev, 0);
	u8 queue_id = wfx_queue_get_queue_id(wdev->pending_frame_id);
	struct wfx_queue *queue = &wdev->tx_queue[queue_id];
	const struct wfx_txpriv *txpriv;
	WsmHiTxReq_t *wsm;
	struct sk_buff *skb;
	WsmHiSsidDef_t ssids[1] = { {
					    .SSIDLength = 0,
	} };
	u8 ch[WSM_API_CHANNEL_LIST_SIZE] = {
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	struct wsm_scan scan = {
		.scan_req.ScanType.Type		= 0, /* WSM_SCAN_TYPE_FG, */
		.scan_req.NumOfProbeRequests	= 1,
		.scan_req.ProbeDelay		= 0,
		.scan_req.NumOfChannels		= 1,
		.scan_req.MinChannelTime	= 0,
		.scan_req.MaxChannelTime	= 10,
		.ssids = ssids,
		.ch = ch,
	};
	u8 *ies;
	size_t ies_len;
	int ret;
	WsmHiMibTemplateFrame_t *p;

	wiphy_dbg(wdev->hw->wiphy, "[SCAN] Direct probe work.\n");

	mutex_lock(&wdev->conf_mutex);
	if (down_trylock(&wdev->scan.lock)) {
		/* Scan is already in progress. Requeue self. */
		schedule();
		queue_delayed_work(wdev->workqueue, &wdev->scan.probe_work,
				   msecs_to_jiffies(100));
		mutex_unlock(&wdev->conf_mutex);
		return;
	}

	/* Make sure we still have a pending probe req */
	if (wfx_queue_get_skb(queue, wdev->pending_frame_id,
			      &skb, &txpriv)) {
		up(&wdev->scan.lock);
		mutex_unlock(&wdev->conf_mutex);
		wsm_unlock_tx(wdev);
		return;
	}
	wsm = (WsmHiTxReq_t *)skb->data;
	scan.scan_req.MaxTransmitRate = wsm->Body.MaxTxRate;
	scan.scan_req.Band = WSM_PHY_BAND_2_4G;
	if (wvif->join_status == WFX_JOIN_STATUS_STA ||
	    wvif->join_status == WFX_JOIN_STATUS_IBSS) {
		scan.scan_req.ScanType.Type = 1;        /* WSM_SCAN_TYPE_BG; */
		scan.scan_req.ScanFlags.Fbg = 1;        /* WSM_SCAN_FLAG_FORCE_BACKGROUND */
	}
	scan.scan_req.NumOfChannels = wdev->channel->hw_value;

	skb_pull(skb, txpriv->offset);

	ies = &skb->data[sizeof(struct ieee80211_hdr_3addr)];
	ies_len = skb->len - sizeof(struct ieee80211_hdr_3addr);

	if (ies_len) {
		u8 *ssidie =
			(u8 *)cfg80211_find_ie(WLAN_EID_SSID, ies, ies_len);

		if (ssidie && ssidie[1] && ssidie[1] <= sizeof(ssids[0].SSID)) {
			u8 *nextie = &ssidie[2 + ssidie[1]];

			/* Store SSID localy */
			ssids[0].SSIDLength = ssidie[1];
			memcpy(ssids[0].SSID, &ssidie[2], ssids[0].SSIDLength);
			scan.scan_req.NumOfSSIDs = 1;

			/* Remove SSID from IE list */
			ssidie[1] = 0;
			memmove(&ssidie[2], nextie, &ies[ies_len] - nextie);
			skb_trim(skb, skb->len - ssids[0].SSIDLength);
		}
	}
	if (wvif->join_status == WFX_JOIN_STATUS_MONITOR)
		wfx_disable_listening(wvif);

	p = (WsmHiMibTemplateFrame_t *)skb_push(skb, 4);
	p->FrameType = WSM_TMPLT_PRBREQ;
	p->FrameLength = cpu_to_le16(skb->len - 4);

	ret = wsm_set_template_frame(wdev, p, wvif->Id);
	skb_pull(skb, 4);
	wdev->scan.direct_probe = 1;
	if (!ret) {
		wsm_flush_tx(wdev);
		ret = wfx_scan_start(wdev, &scan);
	}
	mutex_unlock(&wdev->conf_mutex);

	skb_push(skb, txpriv->offset);
	if (!ret)
		IEEE80211_SKB_CB(skb)->flags |= IEEE80211_TX_STAT_ACK;
	BUG_ON(wfx_queue_remove(queue, wdev->pending_frame_id));

	if (ret) {
		wdev->scan.direct_probe = 0;
		up(&wdev->scan.lock);
		wsm_unlock_tx(wdev);
	}
}
