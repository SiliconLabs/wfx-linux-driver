/*
 * Copyright (c) 2017, Silicon Laboratories, Inc.
 * based on:
 * Copyright (c) 2010, ST-Ericsson
 * Author: Dmitry Tarnyagin <dmitry.tarnyagin@lockless.no>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*========================================================================*/
/*                 Standard Linux Headers                                 */
/*========================================================================*/
#include <linux/sched.h>

/*========================================================================*/
/*                 Local Header files                                     */
/*========================================================================*/
#include "wfx.h"
#include "scan.h"
#include "sta.h"
#include "pm.h"
#include "debug.h"

/*========================================================================*/
/*                       Functions                                        */
/*========================================================================*/
static void wfx_scan_restart_delayed(struct wfx_common *priv);

static int wfx_scan_start(struct wfx_common *priv, struct wsm_scan *scan)
{
	int ret;

	int tmo = 200;

	switch (priv->join_status) {
	case WFX_JOIN_STATUS_PRE_STA:
	case WFX_JOIN_STATUS_JOINING:
		return -EBUSY;
	default:
		break;
	}
	wiphy_dbg(priv->hw->wiphy,
		  "[SCAN] hw req, type %d, %d channels, flags: Fbg %d, Split %d, Pre %d, TxMod %d.\n",
		  scan->scan_req.ScanType.Type, scan->scan_req.NumOfChannels, scan->scan_req.ScanFlags.Fbg,
		  scan->scan_req.ScanFlags.Split, scan->scan_req.ScanFlags.Pre,
		  scan->scan_req.ScanFlags.TxMod);

	tmo += scan->scan_req.NumOfChannels *
	       ((20 * (scan->scan_req.MaxChannelTime)) + 10);
	atomic_set(&priv->scan.in_progress, 1);
	atomic_set(&priv->wait_for_scan, 1);

	wfx_pm_stay_awake(&priv->pm_state, msecs_to_jiffies(tmo));
	queue_delayed_work(priv->workqueue, &priv->scan.timeout,
			   msecs_to_jiffies(tmo));
	ret = wsm_scan(priv, scan);
	if (ret) {
		atomic_set(&priv->scan.in_progress, 0);
		atomic_set(&priv->wait_for_scan, 0);
		cancel_delayed_work_sync(&priv->scan.timeout);
		wfx_scan_restart_delayed(priv);
	}
	return ret;
}

int wfx_hw_scan(struct ieee80211_hw		*hw,
		struct ieee80211_vif		*vif,
		struct ieee80211_scan_request	*hw_req)
{
	struct wfx_common *priv = hw->priv;
	struct cfg80211_scan_request *req = &hw_req->req;
	struct sk_buff *skb;
	int i, ret;
	WsmHiMibTemplateFrame_t *p;

	if (!priv->vif)
		return -EINVAL;

	/* Scan when P2P_GO corrupt firmware MiniAP mode */
	if (priv->join_status == WFX_JOIN_STATUS_AP)
		return -EOPNOTSUPP;

	if (req->n_ssids == 1 && !req->ssids[0].ssid_len)
		req->n_ssids = 0;

	wiphy_dbg(hw->wiphy, "[SCAN] Scan request for %d SSIDs.\n",
		  req->n_ssids);

	if (req->n_ssids > WSM_API_SSID_DEF_SIZE)
		return -EINVAL;

	skb = ieee80211_probereq_get(hw, priv->vif->addr, NULL, 0,
				     req->ie_len);
	if (!skb)
		return -ENOMEM;

	if (req->ie_len)
		memcpy(skb_put(skb, req->ie_len), req->ie, req->ie_len);

	/* will be unlocked in wfx_scan_work() */
	down(&priv->scan.lock);
	mutex_lock(&priv->conf_mutex);

	p = (WsmHiMibTemplateFrame_t *)skb_push(skb, 4);
	p->FrameType = WSM_TMPLT_PRBREQ;
	p->FrameLength = __cpu_to_le16(skb->len - 4);
	ret = wsm_set_template_frame(priv, p);
	skb_pull(skb, 4);

	if (!ret)
		/* Host want to be the probe responder. */
		ret = wsm_set_probe_responder(priv, true);
	if (ret) {
		mutex_unlock(&priv->conf_mutex);
		up(&priv->scan.lock);
		dev_kfree_skb(skb);
		return ret;
	}

	wsm_lock_tx(priv);

	BUG_ON(priv->scan.req);
	priv->scan.req = req;
	priv->scan.n_ssids = 0;
	priv->scan.status = 0;
	priv->scan.begin = &req->channels[0];
	priv->scan.curr = priv->scan.begin;
	priv->scan.end = &req->channels[req->n_channels];
	priv->scan.output_power = priv->output_power;

	for (i = 0; i < req->n_ssids; ++i) {
		WsmHiSsidDef_t *dst = &priv->scan.ssids[priv->scan.n_ssids];

		memcpy(&dst->SSID[0], req->ssids[i].ssid, sizeof(dst->SSID));
		dst->SSIDLength = req->ssids[i].ssid_len;
		++priv->scan.n_ssids;
	}

	mutex_unlock(&priv->conf_mutex);

	if (skb)
		dev_kfree_skb(skb);
	queue_work(priv->workqueue, &priv->scan.work);
	return 0;
}

void wfx_scan_work(struct work_struct *work)
{
	struct wfx_common *priv = container_of(work, struct wfx_common,
					       scan.work);
	struct ieee80211_channel **it;
	struct wsm_scan scan = {
		.scan_req.ScanType.Type		= 0,    /* WSM_SCAN_TYPE_FG, */
		.scan_req.ScanFlags.Split	= 1,    /* WSM_SCAN_FLAG_SPLIT_METHOD,*/
	};
	bool first_run = (priv->scan.begin == priv->scan.curr &&
			  priv->scan.begin != priv->scan.end);
	int i;

	if (first_run) {
		if (cancel_delayed_work_sync(&priv->join_timeout) > 0)
			wfx_join_timeout(&priv->join_timeout.work);
	}

	mutex_lock(&priv->conf_mutex);

	if (first_run) {
		if (priv->join_status == WFX_JOIN_STATUS_STA &&
		    !(priv->powersave_mode.PmMode.PmMode)) {
			WsmHiSetPmModeReqBody_t pm = priv->powersave_mode;

			pm.PmMode.PmMode = 1;
			wfx_set_pm(priv, &pm);
		} else
		if (priv->join_status == WFX_JOIN_STATUS_MONITOR) {
			wfx_disable_listening(priv);
		}
	}

	if (!priv->scan.req || (priv->scan.curr == priv->scan.end)) {
		if (priv->scan.output_power != priv->output_power)
			wsm_set_output_power(priv, priv->output_power * 10);

		if (priv->scan.status < 0)
			wiphy_warn(priv->hw->wiphy,
				   "[SCAN] Scan failed (%d).\n",
				   priv->scan.status);
		else
		if (priv->scan.req)
			wiphy_dbg(priv->hw->wiphy,
				  "[SCAN] Scan completed.\n");
		else
			wiphy_dbg(priv->hw->wiphy,
				  "[SCAN] Scan canceled.\n");

		priv->scan.req = NULL;
		wfx_scan_restart_delayed(priv);
		wsm_unlock_tx(priv);
		mutex_unlock(&priv->conf_mutex);
		ieee80211_scan_completed(priv->hw, priv->scan.status ? 1 : 0);
		up(&priv->scan.lock);
		if (priv->join_status == WFX_JOIN_STATUS_STA &&
		    !(priv->powersave_mode.PmMode.PmMode))
			wfx_set_pm(priv, &priv->powersave_mode);
		return;
	} else {
		struct ieee80211_channel *first = *priv->scan.curr;

		for (it = priv->scan.curr + 1, i = 1;
		     it != priv->scan.end && i < WSM_API_CHANNEL_LIST_SIZE;
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

		if (priv->scan.req->no_cck)
			scan.scan_req.MaxTransmitRate = WSM_TRANSMIT_RATE_6;
		else
			scan.scan_req.MaxTransmitRate = WSM_TRANSMIT_RATE_1;
		scan.scan_req.NumOfProbeRequests =
			(first->flags & IEEE80211_CHAN_NO_IR) ? 0 : 2;
		scan.scan_req.NumOfSSIDs = priv->scan.n_ssids;
		scan.ssids = &priv->scan.ssids[0];
		scan.scan_req.NumOfChannels = it - priv->scan.curr;
		scan.scan_req.ProbeDelay = 100;
		if (priv->join_status == WFX_JOIN_STATUS_STA) {
			scan.scan_req.ScanType.Type = 1;        /* WSM_SCAN_TYPE_BG; */
			scan.scan_req.ScanFlags.Fbg = 1;        /* WSM_SCAN_FLAG_FORCE_BACKGROUND */
		}

		scan.ch = kcalloc(scan.scan_req.NumOfChannels,
				sizeof(u8),
				GFP_KERNEL);

		if (!scan.ch) {
			priv->scan.status = -ENOMEM;
			goto fail;
		}
		for (i = 0; i < scan.scan_req.NumOfChannels; ++i)
			scan.ch[i] = priv->scan.curr[i]->hw_value;

		if (priv->scan.curr[0]->flags & IEEE80211_CHAN_NO_IR) {
			scan.scan_req.MinChannelTime = 50;
			scan.scan_req.MaxChannelTime = 100;
		} else {
			scan.scan_req.MinChannelTime = 10;
			scan.scan_req.MaxChannelTime = 25;
		}
		if (!(first->flags & IEEE80211_CHAN_NO_IR) &&
		    priv->scan.output_power != first->max_power) {
			priv->scan.output_power = first->max_power;
			wsm_set_output_power(priv,
					     priv->scan.output_power * 10);
		}
		priv->scan.status = wfx_scan_start(priv, &scan);
		kfree(scan.ch);
		if (priv->scan.status)
			goto fail;
		priv->scan.curr = it;
	}
	mutex_unlock(&priv->conf_mutex);
	return;

fail:
	priv->scan.curr = priv->scan.end;
	mutex_unlock(&priv->conf_mutex);
	queue_work(priv->workqueue, &priv->scan.work);
}

static void wfx_scan_restart_delayed(struct wfx_common *priv)
{
	if (priv->join_status == WFX_JOIN_STATUS_MONITOR) {
		wfx_enable_listening(priv);
		wfx_update_filtering(priv);
	}

	if (priv->delayed_unjoin) {
		priv->delayed_unjoin = false;
		if (queue_work(priv->workqueue, &priv->unjoin_work) <= 0)
			wsm_unlock_tx(priv);
	} else
	if (priv->delayed_link_loss) {
		wiphy_dbg(priv->hw->wiphy, "[CQM] Requeue BSS loss.\n");
		priv->delayed_link_loss = 0;
		wfx_cqm_bssloss_sm(priv, 1, 0, 0);
	}
}

static void wfx_scan_complete(struct wfx_common *priv)
{
	atomic_set(&priv->wait_for_scan, 0);

	if (priv->scan.direct_probe) {
		wiphy_dbg(priv->hw->wiphy, "[SCAN] Direct probe complete.\n");
		wfx_scan_restart_delayed(priv);
		priv->scan.direct_probe = 0;
		up(&priv->scan.lock);
		wsm_unlock_tx(priv);
	} else {
		wfx_scan_work(&priv->scan.work);
	}
}

void wfx_scan_failed_cb(struct wfx_common *priv)
{
	if (priv->mode == NL80211_IFTYPE_UNSPECIFIED)
		/* STA is stopped. */
		return;

	if (cancel_delayed_work_sync(&priv->scan.timeout) > 0) {
		priv->scan.status = -EIO;
		queue_delayed_work(priv->workqueue, &priv->scan.timeout, 0);
	}
}

void wfx_scan_complete_cb(struct wfx_common		*priv,
			  WsmHiScanCmplIndBody_t	*arg)
{
	if (priv->mode == NL80211_IFTYPE_UNSPECIFIED)
		/* STA is stopped. */
		return;

	if (cancel_delayed_work_sync(&priv->scan.timeout) > 0) {
		priv->scan.status = 1;
		queue_delayed_work(priv->workqueue, &priv->scan.timeout, 0);
	}
}

void wfx_scan_timeout(struct work_struct *work)
{
	struct wfx_common *priv =
		container_of(work, struct wfx_common, scan.timeout.work);

	if (atomic_xchg(&priv->scan.in_progress, 0)) {
		if (priv->scan.status > 0) {
			priv->scan.status = 0;
		} else if (!priv->scan.status) {
			wiphy_warn(priv->hw->wiphy,
				   "Timeout waiting for scan complete notification.\n");
			priv->scan.status = -ETIMEDOUT;
			priv->scan.curr = priv->scan.end;
			wsm_stop_scan(priv);
		}
		wfx_scan_complete(priv);
	}
}

void wfx_probe_work(struct work_struct *work)
{
	struct wfx_common *priv =
		container_of(work, struct wfx_common, scan.probe_work.work);
	u8 queue_id = wfx_queue_get_queue_id(priv->pending_frame_id);
	struct wfx_queue *queue = &priv->tx_queue[queue_id];
	const struct wfx_txpriv *txpriv;
	WsmHiTxReq_t *wsm;
	struct sk_buff *skb;
	WsmHiSsidDef_t ssids[1] = { {
					    .SSIDLength = 0,
				    } };
	uint8 ch[WSM_API_CHANNEL_LIST_SIZE] = {
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	struct wsm_scan scan = {
		.scan_req.ScanType.Type		= 0, /* WSM_SCAN_TYPE_FG, */
		.scan_req.NumOfProbeRequests	= 1,
		.scan_req.ProbeDelay		= 0,
		.scan_req.NumOfChannels		= 1,
		.scan_req.MinChannelTime	= 0,
		.scan_req.MaxChannelTime	= 10,
		.ssids				= ssids,
		.ch				= ch,
	};
	u8 *ies;
	size_t ies_len;
	int ret;
	WsmHiMibTemplateFrame_t *p;

	wiphy_dbg(priv->hw->wiphy, "[SCAN] Direct probe work.\n");

	mutex_lock(&priv->conf_mutex);
	if (down_trylock(&priv->scan.lock)) {
		/* Scan is already in progress. Requeue self. */
		schedule();
		queue_delayed_work(priv->workqueue, &priv->scan.probe_work,
				   msecs_to_jiffies(100));
		mutex_unlock(&priv->conf_mutex);
		return;
	}

	/* Make sure we still have a pending probe req */
	if (wfx_queue_get_skb(queue, priv->pending_frame_id,
			      &skb, &txpriv)) {
		up(&priv->scan.lock);
		mutex_unlock(&priv->conf_mutex);
		wsm_unlock_tx(priv);
		return;
	}
	wsm = (WsmHiTxReq_t *)skb->data;
	scan.scan_req.MaxTransmitRate = wsm->Body.MaxTxRate;
	scan.scan_req.Band = WSM_PHY_BAND_2_4G;
	if (priv->join_status == WFX_JOIN_STATUS_STA ||
	    priv->join_status == WFX_JOIN_STATUS_IBSS) {
		scan.scan_req.ScanType.Type = 1;        /* WSM_SCAN_TYPE_BG; */
		scan.scan_req.ScanFlags.Fbg = 1;        /* WSM_SCAN_FLAG_FORCE_BACKGROUND */
	}
	scan.scan_req.NumOfChannels = priv->channel->hw_value;

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
	if (priv->join_status == WFX_JOIN_STATUS_MONITOR)
		wfx_disable_listening(priv);

	p = (WsmHiMibTemplateFrame_t *)skb_push(skb, 4);
	p->FrameType = WSM_TMPLT_PRBREQ;
	p->FrameLength = __cpu_to_le16(skb->len - 4);

	ret = wsm_set_template_frame(priv, p);
	skb_pull(skb, 4);
	priv->scan.direct_probe = 1;
	if (!ret) {
		wsm_flush_tx(priv);
		ret = wfx_scan_start(priv, &scan);
	}
	mutex_unlock(&priv->conf_mutex);

	skb_push(skb, txpriv->offset);
	if (!ret)
		IEEE80211_SKB_CB(skb)->flags |= IEEE80211_TX_STAT_ACK;
	BUG_ON(wfx_queue_remove(queue, priv->pending_frame_id));

	if (ret) {
		priv->scan.direct_probe = 0;
		up(&priv->scan.lock);
		wsm_unlock_tx(priv);
	}
}
