// SPDX-License-Identifier: GPL-2.0-only
/*
 * Datapath implementation.
 *
 * Copyright (c) 2017-2019, Silicon Laboratories, Inc.
 * Copyright (c) 2010, ST-Ericsson
 */
#include <net/mac80211.h>

#include "data_rx.h"
#include "wfx.h"
#include "wsm_rx.h"
#include "bh.h"
#include "sta.h"
#include "debug.h"
#include "traces.h"

static int wfx_handle_action_rx(struct wfx_dev *wdev, struct sk_buff *skb)
{
	struct ieee80211_mgmt *mgmt = (void *)skb->data;

	/* Filter block ACK negotiation: fully controlled by firmware */
	if (mgmt->u.action.category == WLAN_CATEGORY_BACK)
		return 1;

	return 0;
}

static int wfx_handle_pspoll(struct wfx_vif *wvif, struct sk_buff *skb)
{
	struct ieee80211_sta *sta;
	struct ieee80211_pspoll *pspoll = (struct ieee80211_pspoll *)skb->data;
	int link_id = 0;
	u32 pspoll_mask = 0;
	int drop = 1;
	int i;

	if (wvif->state != WFX_STATE_AP)
		goto done;
	if (!ether_addr_equal(wvif->vif->addr, pspoll->bssid))
		goto done;

	rcu_read_lock();
	sta = ieee80211_find_sta(wvif->vif, pspoll->ta);
	if (sta) {
		struct wfx_sta_priv *sta_priv;
		sta_priv = (struct wfx_sta_priv *)&sta->drv_priv;
		link_id = sta_priv->link_id;
		pspoll_mask = BIT(sta_priv->link_id);
	}
	rcu_read_unlock();
	if (!link_id)
		goto done;

	wvif->pspoll_mask |= pspoll_mask;
	drop = 0;

	/* Do not report pspols if data for given link id is queued already. */
	for (i = 0; i < 4; ++i) {
		if (wfx_tx_queue_get_num_queued(&wvif->wdev->tx_queue[i],
						pspoll_mask)) {
			wfx_bh_request_tx(wvif->wdev);
			drop = 1;
			break;
		}
	}
	pr_debug("[RX] PSPOLL: %s\n", drop ? "local" : "fwd");
done:
	return drop;
}

void wfx_rx_cb(struct wfx_vif *wvif, WsmHiRxIndBody_t *arg,
	       int link_id, struct sk_buff **skb_p)
{
	struct sk_buff *skb = *skb_p;
	struct ieee80211_rx_status *hdr = IEEE80211_SKB_RXCB(skb);
	struct ieee80211_hdr *frame = (struct ieee80211_hdr *)skb->data;
	struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *)skb->data;
	struct wfx_link_entry *entry = NULL;

	bool early_data = false;
	bool p2p = wvif->vif && wvif->vif->p2p;
	size_t hdrlen;

	hdr->flag = 0;

	if (!wvif)
		goto drop;

	if (link_id && link_id <= WFX_MAX_STA_IN_AP_MODE) {
		entry = &wvif->link_id_db[link_id - 1];
		if (entry->status == WFX_LINK_SOFT &&
		    ieee80211_is_data(frame->frame_control))
			early_data = true;
		entry->timestamp = jiffies;
	} else if (p2p &&
		   ieee80211_is_action(frame->frame_control) &&
		   (mgmt->u.action.category == WLAN_CATEGORY_PUBLIC)) {
		pr_debug("[RX] Going to MAP&RESET link ID\n");
		WARN_ON(work_pending(&wvif->link_id_reset_work));
		ether_addr_copy(&wvif->action_frame_sa[0], ieee80211_get_SA(frame));
		wvif->action_link_id = 0;
		schedule_work(&wvif->link_id_reset_work);
	}

	if (link_id && p2p &&
	    ieee80211_is_action(frame->frame_control) &&
	    mgmt->u.action.category == WLAN_CATEGORY_PUBLIC) {
		/* Link ID already exists for the ACTION frame.
		 * Reset and Remap
		 */
		WARN_ON(work_pending(&wvif->link_id_reset_work));
		ether_addr_copy(&wvif->action_frame_sa[0], ieee80211_get_SA(frame));
		wvif->action_link_id = link_id;
		schedule_work(&wvif->link_id_reset_work);
	}
	if (arg->Status) {
		if (arg->Status == WSM_STATUS_MICFAILURE) {
			pr_debug("[RX] MIC failure.\n");
			hdr->flag |= RX_FLAG_MMIC_ERROR;
		} else if (arg->Status == WSM_STATUS_NO_KEY_FOUND) {
			pr_debug("[RX] No key found.\n");
			goto drop;
		} else {
			pr_debug("[RX] Receive failure: %d.\n",
				 arg->Status);
			goto drop;
		}
	}

	if (skb->len < sizeof(struct ieee80211_pspoll)) {
		dev_warn(wvif->wdev->dev, "Malformed SDU rx'ed. Size is lesser than IEEE header.\n");
		goto drop;
	}

	if (ieee80211_is_pspoll(frame->frame_control))
		if (wfx_handle_pspoll(wvif, skb))
			goto drop;

	hdr->band = NL80211_BAND_2GHZ;
	hdr->freq = ieee80211_channel_to_frequency(
		arg->ChannelNumber,
			hdr->band);

	if (arg->RxedRate >= 14) {
#if (KERNEL_VERSION(4, 12, 0) > LINUX_VERSION_CODE)
		hdr->flag |= RX_FLAG_HT;
#else
		hdr->encoding = RX_ENC_HT;
#endif
		hdr->rate_idx = arg->RxedRate - 14;
	} else if (arg->RxedRate >= 4) {
		hdr->rate_idx = arg->RxedRate - 2;
	} else {
		hdr->rate_idx = arg->RxedRate;
	}

	/* In 802.11n, short guard interval "Short GI" is
	 * introduced while the default value is 400ns.
	 * Name            : RX_FLAG_SHORT_GI
	 * Type         : Boolean, default : 1
	 * Default value: 400ns.
	 */
	/*hdr->flag |= RX_FLAG_SHORT_GI; */

	hdr->signal = (s8)arg->RcpiRssi;
	hdr->antenna = 0;

	hdrlen = ieee80211_hdrlen(frame->frame_control);

	if (arg->RxFlags.Encryp) {
		size_t iv_len = 0, icv_len = 0;

		hdr->flag |= RX_FLAG_DECRYPTED | RX_FLAG_IV_STRIPPED;

		/* Oops... There is no fast way to ask mac80211 about
		 * IV/ICV lengths. Even defineas are not exposed.
		 */
		switch (arg->RxFlags.Encryp) {
		case WSM_RI_FLAGS_WEP_ENCRYPTED:
			iv_len = 4 /* WEP_IV_LEN */;
			icv_len = 4 /* WEP_ICV_LEN */;
			break;
		case WSM_RI_FLAGS_TKIP_ENCRYPTED:
			iv_len = 8 /* TKIP_IV_LEN */;
			icv_len = 4 /* TKIP_ICV_LEN */
				+ 8 /*MICHAEL_MIC_LEN*/;
			hdr->flag |= RX_FLAG_MMIC_STRIPPED;
			break;
		case WSM_RI_FLAGS_AES_ENCRYPTED:
			iv_len = 8 /* CCMP_HDR_LEN */;
			icv_len = 8 /* CCMP_MIC_LEN */;
			break;
		case WSM_RI_FLAGS_WAPI_ENCRYPTED:
			iv_len = 18 /* WAPI_HDR_LEN */;
			icv_len = 16 /* WAPI_MIC_LEN */;
			break;
		default:
			dev_err(wvif->wdev->dev, "Unknown encryption type %d\n",
				 arg->RxFlags.Encryp);
			goto drop;
		}

		/* Firmware strips ICV in case of MIC failure. */
		if (arg->Status == WSM_STATUS_MICFAILURE)
			icv_len = 0;

		if (skb->len < hdrlen + iv_len + icv_len) {
			dev_warn(wvif->wdev->dev, "Malformed SDU rx'ed. Size is lesser than crypto headers.\n");
			goto drop;
		}

		/* Remove IV, ICV and MIC */
		skb_trim(skb, skb->len - icv_len);
		memmove(skb->data + iv_len, skb->data, hdrlen);
		skb_pull(skb, iv_len);
	}

	wfx_debug_rxed(wvif->wdev);
	if (arg->RxFlags.InAggr)
		wfx_debug_rxed_agg(wvif->wdev);

	if (ieee80211_is_action(frame->frame_control) && arg->RxFlags.MatchUcAddr) {
		if (wfx_handle_action_rx(wvif->wdev, skb))
			return;
	} else if (ieee80211_is_beacon(frame->frame_control) &&
		   !arg->Status && wvif->vif &&
		   ether_addr_equal(ieee80211_get_SA(frame), wvif->vif->bss_conf.bssid)) {
		const u8 *tim_ie;
		u8 *ies = ((struct ieee80211_mgmt *)
			  (skb->data))->u.beacon.variable;
		size_t ies_len = skb->len - (ies - (u8 *)(skb->data));

		tim_ie = cfg80211_find_ie(WLAN_EID_TIM, ies, ies_len);
		if (tim_ie) {
			struct ieee80211_tim_ie *tim =
				(struct ieee80211_tim_ie *)&tim_ie[2];

			if (wvif->dtim_period != tim->dtim_period) {
				wvif->dtim_period = tim->dtim_period;
				schedule_work(&wvif->set_beacon_wakeup_period_work);
			}
		}

		/* Disable beacon filter once we're associated... */
		if (wvif->disable_beacon_filter &&
		    (wvif->vif->bss_conf.assoc ||
		     wvif->vif->bss_conf.ibss_joined)) {
			wvif->disable_beacon_filter = false;
			schedule_work(&wvif->update_filtering_work);
		}
	}

	if (early_data) {
		spin_lock_bh(&wvif->ps_state_lock);
		/* Double-check status with lock held */
		if (entry->status == WFX_LINK_SOFT)
			skb_queue_tail(&entry->rx_queue, skb);
		else
			ieee80211_rx_irqsafe(wvif->wdev->hw, skb);
		spin_unlock_bh(&wvif->ps_state_lock);
	} else {
		ieee80211_rx_irqsafe(wvif->wdev->hw, skb);
	}
	*skb_p = NULL;

	return;

drop:
	/* TODO: update failure counters */
	return;
}

