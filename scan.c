// SPDX-License-Identifier: GPL-2.0-only
/*
 * Scan related functions.
 *
 * Copyright (c) 2017-2019, Silicon Laboratories, Inc.
 * Copyright (c) 2010, ST-Ericsson
 */
#include <net/mac80211.h>

#include "scan.h"
#include "wfx.h"
#include "sta.h"
#include "wsm_rx.h"

static void wfx_scan_restart_delayed(struct wfx_vif *wvif);

static int wfx_scan_start(struct wfx_vif *wvif, struct wsm_scan *scan)
{
	int ret;

	int tmo = 500;

	switch (wvif->state) {
	case WFX_STATE_PRE_STA:
		return -EBUSY;
	default:
		break;
	}

	tmo += scan->scan_req.NumOfChannels *
	       ((20 * (scan->scan_req.MaxChannelTime)) + 10);
	atomic_set(&wvif->scan.in_progress, 1);
	atomic_set(&wvif->wdev->scan_in_progress, 1);

	schedule_delayed_work(&wvif->scan.timeout, msecs_to_jiffies(tmo));
	ret = wsm_scan(wvif->wdev, scan, wvif->Id);
	if (ret) {
		wfx_scan_failed_cb(wvif);
		atomic_set(&wvif->scan.in_progress, 0);
		atomic_set(&wvif->wdev->scan_in_progress, 0);
		cancel_delayed_work_sync(&wvif->scan.timeout);
		wfx_scan_restart_delayed(wvif);
	}
	return ret;
}

int wfx_hw_scan(struct ieee80211_hw *hw,
		   struct ieee80211_vif *vif,
		   struct ieee80211_scan_request *hw_req)
{
	struct wfx_dev *wdev = hw->priv;
	struct wfx_vif *wvif = (struct wfx_vif *) vif->drv_priv;
	struct cfg80211_scan_request *req = &hw_req->req;
	struct sk_buff *skb;
	int i, ret;
	WsmHiMibTemplateFrame_t *p;

	if (!wvif)
		return -EINVAL;

	/* Scan when P2P_GO corrupt firmware MiniAP mode */
	if (wvif->state == WFX_STATE_AP)
		return -EOPNOTSUPP;

	if (req->n_ssids == 1 && !req->ssids[0].ssid_len)
		req->n_ssids = 0;

	if (req->n_ssids > WSM_API_MAX_NB_SSIDS)
		return -EINVAL;

#if (KERNEL_VERSION(3, 19, 0) > LINUX_VERSION_CODE)
	skb = ieee80211_probereq_get(hw, wvif->vif, NULL, 0, req->ie_len);
#else
	skb = ieee80211_probereq_get(hw, wvif->vif->addr, NULL, 0, req->ie_len);
#endif
	if (!skb)
		return -ENOMEM;

	if (req->ie_len)
		memcpy(skb_put(skb, req->ie_len), req->ie, req->ie_len);

	/* will be unlocked in wfx_scan_work() */
	mutex_lock(&wdev->conf_mutex);

	p = (WsmHiMibTemplateFrame_t *)skb_push(skb, 4);
	p->FrameType = WSM_TMPLT_PRBREQ;
	p->FrameLength = cpu_to_le16(skb->len - 4);
	ret = wsm_set_template_frame(wdev, p, wvif->Id);
	skb_pull(skb, 4);

	if (!ret)
		/* Host want to be the probe responder. */
		ret = wsm_fwd_probe_req(wvif, true);
	if (ret) {
		mutex_unlock(&wdev->conf_mutex);
		dev_kfree_skb(skb);
		return ret;
	}

	wsm_tx_lock_flush(wdev);

	BUG_ON(wvif->scan.req);
	wvif->scan.req = req;
	wvif->scan.n_ssids = 0;
	wvif->scan.status = 0;
	wvif->scan.begin = &req->channels[0];
	wvif->scan.curr = wvif->scan.begin;
	wvif->scan.end = &req->channels[req->n_channels];
	wvif->scan.output_power = wdev->output_power;

	for (i = 0; i < req->n_ssids; ++i) {
		WsmHiSsidDef_t *dst = &wvif->scan.ssids[wvif->scan.n_ssids];

		memcpy(&dst->SSID[0], req->ssids[i].ssid, sizeof(dst->SSID));
		dst->SSIDLength = req->ssids[i].ssid_len;
		++wvif->scan.n_ssids;
	}

	mutex_unlock(&wdev->conf_mutex);

	if (skb)
		dev_kfree_skb(skb);
	schedule_work(&wvif->scan.work);
	return 0;
}

static void __ieee80211_scan_completed_compat(struct ieee80211_hw *hw, bool aborted)
{
#if (KERNEL_VERSION(4, 8, 0) > LINUX_VERSION_CODE)
	ieee80211_scan_completed(hw, aborted);
#else
	struct cfg80211_scan_info info = {
		.aborted = aborted ? 1 : 0,
	};

	ieee80211_scan_completed(hw, &info);
#endif
}

void wfx_scan_work(struct work_struct *work)
{
	struct wfx_vif *wvif = container_of(work, struct wfx_vif, scan.work);
	struct ieee80211_channel **it;
	struct wsm_scan scan = {
		.scan_req.ScanType.Type		= 0,    /* WSM_SCAN_TYPE_FG, */
	};
	bool first_run = (wvif->scan.begin == wvif->scan.curr &&
			  wvif->scan.begin != wvif->scan.end);
	int i;

	mutex_lock(&wvif->wdev->conf_mutex);
	down(&wvif->scan.lock);

	if (first_run) {
		if (wvif->state == WFX_STATE_STA &&
		    !(wvif->powersave_mode.PmMode.EnterPsm)) {
			WsmHiSetPmModeReqBody_t pm = wvif->powersave_mode;

			pm.PmMode.EnterPsm = 1;
			wfx_set_pm(wvif, &pm);
		}
	}

	if (!wvif->scan.req || wvif->scan.curr == wvif->scan.end) {
		if (wvif->scan.output_power != wvif->wdev->output_power)
			wsm_set_output_power(wvif->wdev, wvif->wdev->output_power * 10, wvif->Id);

		if (wvif->scan.status < 0)
			dev_warn(wvif->wdev->dev,
				   "[SCAN] Scan failed (%d).\n",
				   wvif->scan.status);
		else if (wvif->scan.req)
			dev_dbg(wvif->wdev->dev,
				  "[SCAN] Scan completed.\n");
		else
			dev_dbg(wvif->wdev->dev,
				  "[SCAN] Scan canceled.\n");

		wvif->scan.req = NULL;
		wfx_scan_restart_delayed(wvif);
		wsm_tx_unlock(wvif->wdev);
		mutex_unlock(&wvif->wdev->conf_mutex);
		__ieee80211_scan_completed_compat(wvif->wdev->hw, wvif->scan.status ? 1 : 0);
		up(&wvif->scan.lock);
		if (wvif->state == WFX_STATE_STA &&
		    !(wvif->powersave_mode.PmMode.EnterPsm))
			wfx_set_pm(wvif, &wvif->powersave_mode);
		return;
	} else {
		struct ieee80211_channel *first = *wvif->scan.curr;

		for (it = wvif->scan.curr + 1, i = 1;
		     it != wvif->scan.end && i < WSM_API_MAX_NB_CHANNELS;
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

		if (wvif->scan.req->no_cck)
			scan.scan_req.MaxTransmitRate = API_RATE_INDEX_G_6MBPS;
		else
			scan.scan_req.MaxTransmitRate = API_RATE_INDEX_B_1MBPS;
		scan.scan_req.NumOfProbeRequests =
			(first->flags & IEEE80211_CHAN_NO_IR) ? 0 : 2;
		scan.scan_req.NumOfSSIDs = wvif->scan.n_ssids;
		scan.ssids = &wvif->scan.ssids[0];
		scan.scan_req.NumOfChannels = it - wvif->scan.curr;
		scan.scan_req.ProbeDelay = 100;
		if (wvif->state == WFX_STATE_STA) {
			scan.scan_req.ScanType.Type = 1;        /* WSM_SCAN_TYPE_BG; */
			scan.scan_req.ScanFlags.Fbg = 1;        /* WSM_SCAN_FLAG_FORCE_BACKGROUND */
		}

		scan.ch = kcalloc(scan.scan_req.NumOfChannels,
				sizeof(u8),
			GFP_KERNEL);

		if (!scan.ch) {
			wvif->scan.status = -ENOMEM;
			goto fail;
		}
		for (i = 0; i < scan.scan_req.NumOfChannels; ++i)
			scan.ch[i] = wvif->scan.curr[i]->hw_value;

		if (wvif->scan.curr[0]->flags & IEEE80211_CHAN_NO_IR) {
			scan.scan_req.MinChannelTime = 50;
			scan.scan_req.MaxChannelTime = 150;
		} else {
			scan.scan_req.MinChannelTime = 10;
			scan.scan_req.MaxChannelTime = 50;
		}
		if (!(first->flags & IEEE80211_CHAN_NO_IR) &&
		    wvif->scan.output_power != first->max_power) {
			wvif->scan.output_power = first->max_power;
			wsm_set_output_power(wvif->wdev,
					     wvif->scan.output_power * 10, wvif->Id);
		}
		wvif->scan.status = wfx_scan_start(wvif, &scan);
		kfree(scan.ch);
		if (wvif->scan.status)
			goto fail;
		wvif->scan.curr = it;
	}
	mutex_unlock(&wvif->wdev->conf_mutex);
	return;

fail:
	wvif->scan.curr = wvif->scan.end;
	mutex_unlock(&wvif->wdev->conf_mutex);
	schedule_work(&wvif->scan.work);
}

static void wfx_scan_restart_delayed(struct wfx_vif *wvif)
{
	if (wvif->delayed_unjoin) {
		wvif->delayed_unjoin = false;
		if (!schedule_work(&wvif->unjoin_work))
			wsm_tx_unlock(wvif->wdev);
	} else if (wvif->delayed_link_loss) {
		dev_dbg(wvif->wdev->dev, "[CQM] Requeue BSS loss.\n");
		wvif->delayed_link_loss = 0;
		wfx_cqm_bssloss_sm(wvif, 1, 0, 0);
	}
}

static void wfx_scan_complete(struct wfx_vif *wvif)
{
	up(&wvif->scan.lock);
	atomic_set(&wvif->wdev->scan_in_progress, 0);

	if (wvif->scan.direct_probe) {
		dev_dbg(wvif->wdev->dev, "[SCAN] Direct probe complete.\n");
		wfx_scan_restart_delayed(wvif);
		wvif->scan.direct_probe = 0;
		wsm_tx_unlock(wvif->wdev);
	} else {
		wfx_scan_work(&wvif->scan.work);
	}
}

void wfx_scan_failed_cb(struct wfx_vif *wvif)
{
	if (cancel_delayed_work_sync(&wvif->scan.timeout) > 0) {
		wvif->scan.status = -EIO;
		schedule_work(&wvif->scan.timeout.work);
	}
}

void wfx_scan_complete_cb(struct wfx_vif		*wvif,
			  WsmHiScanCmplIndBody_t	*arg)
{
	if (cancel_delayed_work_sync(&wvif->scan.timeout) > 0) {
		wvif->scan.status = 1;
		schedule_work(&wvif->scan.timeout.work);
	}
}

void wfx_scan_timeout(struct work_struct *work)
{
	struct wfx_vif *wvif = container_of(work, struct wfx_vif, scan.timeout.work);

	if (atomic_xchg(&wvif->scan.in_progress, 0)) {
		if (wvif->scan.status > 0) {
			wvif->scan.status = 0;
		} else if (!wvif->scan.status) {
			dev_warn(wvif->wdev->dev,
				   "Timeout waiting for scan complete notification.\n");
			wvif->scan.status = -ETIMEDOUT;
			wvif->scan.curr = wvif->scan.end;
			wsm_stop_scan(wvif->wdev, wvif->Id);
		}
		wfx_scan_complete(wvif);
	}
}

void wfx_probe_work(struct work_struct *work)
{
	struct wfx_vif *wvif = container_of(work, struct wfx_vif, scan.probe_work.work);
	u8 queue_id = wfx_queue_get_queue_id(wvif->wdev->pending_frame_id);
	struct wfx_queue *queue = &wvif->wdev->tx_queue[queue_id];
	const struct wfx_txpriv *txpriv;
	WsmHiTxReqBody_t *wsm;
	struct sk_buff *skb;
	WsmHiSsidDef_t ssids = { };
	u8 ch[WSM_API_MAX_NB_CHANNELS] = {
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	struct wsm_scan scan = {
		.scan_req.ScanType.Type		= 0, /* WSM_SCAN_TYPE_FG, */
		.scan_req.NumOfProbeRequests	= 1,
		.scan_req.ProbeDelay		= 0,
		.scan_req.NumOfChannels		= 1,
		.scan_req.MinChannelTime	= 0,
		.scan_req.MaxChannelTime	= 10,
		.ssids = &ssids,
		.ch = ch,
	};
	u8 *ies;
	size_t ies_len;
	int ret;
	WsmHiMibTemplateFrame_t *p;

	dev_dbg(wvif->wdev->dev, "[SCAN] Direct probe work.\n");

	mutex_lock(&wvif->wdev->conf_mutex);
	if (down_trylock(&wvif->scan.lock)) {
		/* Scan is already in progress. Requeue self. */
		schedule();
		schedule_delayed_work(&wvif->scan.probe_work, msecs_to_jiffies(100));
		mutex_unlock(&wvif->wdev->conf_mutex);
		return;
	}

	/* Make sure we still have a pending probe req */
	if (wfx_queue_get_skb(queue, wvif->wdev->pending_frame_id,
			      &skb, &txpriv)) {
		up(&wvif->scan.lock);
		mutex_unlock(&wvif->wdev->conf_mutex);
		wsm_tx_unlock(wvif->wdev);
		return;
	}
	wsm = (WsmHiTxReqBody_t *) (skb->data + sizeof(struct wmsg));
	scan.scan_req.MaxTransmitRate = wsm->MaxTxRate;
	scan.scan_req.Band = WSM_PHY_BAND_2_4G;
	if (wvif->state == WFX_STATE_STA ||
	    wvif->state == WFX_STATE_IBSS) {
		scan.scan_req.ScanType.Type = 1;        /* WSM_SCAN_TYPE_BG; */
		scan.scan_req.ScanFlags.Fbg = 1;        /* WSM_SCAN_FLAG_FORCE_BACKGROUND */
	}
	scan.scan_req.NumOfChannels = wvif->channel->hw_value;

	skb_pull(skb, txpriv->offset);

	ies = &skb->data[sizeof(struct ieee80211_hdr_3addr)];
	ies_len = skb->len - sizeof(struct ieee80211_hdr_3addr);

	if (ies_len) {
		u8 *ssidie =
			(u8 *)cfg80211_find_ie(WLAN_EID_SSID, ies, ies_len);

		if (ssidie && ssidie[1] && ssidie[1] <= sizeof(ssids.SSID)) {
			u8 *nextie = &ssidie[2 + ssidie[1]];

			/* Store SSID localy */
			ssids.SSIDLength = ssidie[1];
			memcpy(ssids.SSID, &ssidie[2], ssids.SSIDLength);
			scan.scan_req.NumOfSSIDs = 1;

			/* Remove SSID from IE list */
			ssidie[1] = 0;
			memmove(&ssidie[2], nextie, &ies[ies_len] - nextie);
			skb_trim(skb, skb->len - ssids.SSIDLength);
		}
	}

	p = (WsmHiMibTemplateFrame_t *)skb_push(skb, 4);
	p->FrameType = WSM_TMPLT_PRBREQ;
	p->FrameLength = cpu_to_le16(skb->len - 4);

	ret = wsm_set_template_frame(wvif->wdev, p, wvif->Id);
	skb_pull(skb, 4);
	wvif->scan.direct_probe = 1;
	if (!ret) {
		wsm_tx_flush(wvif->wdev);
		ret = wfx_scan_start(wvif, &scan);
	}
	mutex_unlock(&wvif->wdev->conf_mutex);

	skb_push(skb, txpriv->offset);
	if (!ret)
		IEEE80211_SKB_CB(skb)->flags |= IEEE80211_TX_STAT_ACK;
	BUG_ON(wfx_queue_remove(queue, wvif->wdev->pending_frame_id));

	if (ret) {
		wvif->scan.direct_probe = 0;
		up(&wvif->scan.lock);
		wsm_tx_unlock(wvif->wdev);
	}
}
