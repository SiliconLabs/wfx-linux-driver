// SPDX-License-Identifier: GPL-2.0-only
/*
 * Datapath implementation.
 *
 * Copyright (c) 2017-2019, Silicon Laboratories, Inc.
 * Copyright (c) 2010, ST-Ericsson
 */
#include <net/mac80211.h>

#include "data_tx.h"
#include "wfx.h"
#include "wsm_rx.h"
#include "bh.h"
#include "sta.h"
#include "debug.h"
#include "traces.h"

#define WFX_INVALID_RATE_ID (0xFF)
#define WFX_LINK_ID_GC_TIMEOUT ((unsigned long)(10 * HZ))

static void wfx_notify_buffered_tx(struct wfx_vif *wvif, struct sk_buff *skb,
				   int link_id, int tid);

static int wfx_get_hw_rate(struct wfx_dev *wdev, const struct ieee80211_tx_rate *rate)
{
	if (rate->idx < 0)
		return -1;
	if (rate->flags & IEEE80211_TX_RC_MCS) {
		if (rate->idx > 7) {
			WARN(1, "wrong rate->idx value: %d", rate->idx);
			return -1;
		}
		return rate->idx + 14;
	} else {
		// WFx only support 2GHz, else band information should be
		// retreived from ieee80211_tx_info
		return wdev->hw->wiphy->bands[NL80211_BAND_2GHZ]->bitrates[rate->idx].hw_value;
	}
}

/* TX policy cache implementation */

static void tx_policy_build(struct wfx_vif *wvif, struct tx_policy *policy,
			    struct ieee80211_tx_rate *rates)
{
	int i, j;
	size_t count = IEEE80211_TX_MAX_RATES;
	struct wfx_dev *wdev = wvif->wdev;
	unsigned limit = wdev->short_frame_max_tx_count;
	unsigned total = 0;
	BUG_ON(rates[0].idx < 0);
	memset(policy, 0, sizeof(*policy));

	/* Sort rates in descending order. */
	for (i = 1; i < count; ++i) {
		if (rates[i].idx < 0) {
			count = i;
			break;
		}
		if (rates[i].idx > rates[i - 1].idx) {
			struct ieee80211_tx_rate tmp = rates[i - 1];
			rates[i - 1] = rates[i];
			rates[i] = tmp;
		}
	}

	/* Eliminate duplicates. */
	total = rates[0].count;
	for (i = 0, j = 1; j < count; ++j) {
		if (rates[j].idx == rates[i].idx) {
			rates[i].count += rates[j].count;
		} else if (rates[j].idx > rates[i].idx) {
			break;
		} else {
			++i;
			if (i != j)
				rates[i] = rates[j];
		}
		total += rates[j].count;
	}
	count = i + 1;

	/* Re-fill policy trying to keep every requested rate and with
	 * respect to the global max tx retransmission count.
	 */
	if (limit < count)
		limit = count;
	if (total > limit) {
		for (i = 0; i < count; ++i) {
			int left = count - i - 1;
			if (rates[i].count > limit - left)
				rates[i].count = limit - left;
			limit -= rates[i].count;
		}
	}

	/* HACK!!! Device has problems (at least) switching from
	 * 54Mbps CTS to 1Mbps. This switch takes enormous amount
	 * of time (100-200 ms), leading to valuable throughput drop.
	 * As a workaround, additional g-rates are injected to the
	 * policy.
	 */
	if (count == 2 && !(rates[0].flags & IEEE80211_TX_RC_MCS) &&
	    rates[0].idx > 4 && rates[0].count > 2 &&
	    rates[1].idx < 2) {
		int mid_rate = (rates[0].idx + 4) >> 1;

		/* Decrease number of retries for the initial rate */
		rates[0].count -= 2;

		if (mid_rate != 4) {
			/* Keep fallback rate at 1Mbps. */
			rates[3] = rates[1];

			/* Inject 1 transmission on lowest g-rate */
			rates[2].idx = 4;
			rates[2].count = 1;
			rates[2].flags = rates[1].flags;

			/* Inject 1 transmission on mid-rate */
			rates[1].idx = mid_rate;
			rates[1].count = 1;

			/* Fallback to 1 Mbps is a really bad thing,
			 * so let's try to increase probability of
			 * successful transmission on the lowest g rate
			 * even more
			 */
			if (rates[0].count >= 3) {
				--rates[0].count;
				++rates[2].count;
			}

			/* Adjust amount of rates defined */
			count += 2;
		} else {
			/* Keep fallback rate at 1Mbps. */
			rates[2] = rates[1];

			/* Inject 2 transmissions on lowest g-rate */
			rates[1].idx = 4;
			rates[1].count = 2;

			/* Adjust amount of rates defined */
			count += 1;
		}
	}

	policy->defined = wfx_get_hw_rate(wdev, &rates[0]) + 1;

	for (i = 0; i < count; ++i) {
		register unsigned rateid, off, shift, retries;

		rateid = wfx_get_hw_rate(wdev, &rates[i]);
		off = rateid >> 3;		/* eq. rateid / 8 */
		shift = (rateid & 0x07) << 2;	/* eq. (rateid % 8) * 4 */

		retries = rates[i].count;
		if (retries > 0x0F) {
			rates[i].count = 0x0f;
			retries = 0x0F;
		}
		policy->tbl[off] |= cpu_to_le32(retries << shift);
		policy->retry_count += retries;
	}

	pr_debug("[TX policy] Policy (%zu): %d:%d, %d:%d, %d:%d, %d:%d\n",
		 count,
		 rates[0].idx, rates[0].count,
		 rates[1].idx, rates[1].count,
		 rates[2].idx, rates[2].count,
		 rates[3].idx, rates[3].count);
}

static bool tx_policy_is_equal(const struct tx_policy *wanted,
				      const struct tx_policy *cached)
{
	size_t count = wanted->defined >> 1;
	if (wanted->defined > cached->defined)
		return false;
	if (count) {
		if (memcmp(wanted->raw, cached->raw, count))
			return false;
	}
	if (wanted->defined & 1) {
		if ((wanted->raw[count] & 0x0F) != (cached->raw[count] & 0x0F))
			return false;
	}
	return true;
}

static int tx_policy_find(struct tx_policy_cache *cache,
			  const struct tx_policy *wanted)
{
	/* O(n) complexity. Not so good, but there's only 8 entries in
	 * the cache.
	 * Also lru helps to reduce search time.
	 */
	struct tx_policy_cache_entry *it;
	/* First search for policy in "used" list */
	list_for_each_entry(it, &cache->used, link) {
		if (tx_policy_is_equal(wanted, &it->policy))
			return it - cache->cache;
	}
	/* Then - in "free list" */
	list_for_each_entry(it, &cache->free, link) {
		if (tx_policy_is_equal(wanted, &it->policy))
			return it - cache->cache;
	}
	return -1;
}

static void tx_policy_use(struct tx_policy_cache *cache,
				 struct tx_policy_cache_entry *entry)
{
	++entry->policy.usage_count;
	list_move(&entry->link, &cache->used);
}

static int tx_policy_release(struct tx_policy_cache *cache,
				    struct tx_policy_cache_entry *entry)
{
	int ret = --entry->policy.usage_count;
	if (!ret)
		list_move(&entry->link, &cache->free);
	return ret;
}

void tx_policy_init(struct wfx_vif *wvif)
{
	struct tx_policy_cache *cache = &wvif->tx_policy_cache;
	int i;

	memset(cache, 0, sizeof(*cache));

	spin_lock_init(&cache->lock);
	INIT_LIST_HEAD(&cache->used);
	INIT_LIST_HEAD(&cache->free);

	for (i = 0; i < WSM_MIB_NUM_TX_RATE_RETRY_POLICIES; ++i)
		list_add(&cache->cache[i].link, &cache->free);
}

static int tx_policy_get(struct wfx_vif *wvif, struct ieee80211_tx_rate *rates,
			 bool *renew)
{
	int idx;
	struct tx_policy_cache *cache = &wvif->tx_policy_cache;
	struct tx_policy wanted;

	tx_policy_build(wvif, &wanted, rates);

	spin_lock_bh(&cache->lock);
	if (WARN_ON_ONCE(list_empty(&cache->free))) {
		spin_unlock_bh(&cache->lock);
		return WFX_INVALID_RATE_ID;
	}
	idx = tx_policy_find(cache, &wanted);
	if (idx >= 0) {
		*renew = false;
	} else {
		struct tx_policy_cache_entry *entry;
		*renew = true;
		/* If policy is not found create a new one
		 * using the oldest entry in "free" list
		 */
		entry = list_entry(cache->free.prev,
			struct tx_policy_cache_entry, link);
		entry->policy = wanted;
		idx = entry - cache->cache;
	}
	tx_policy_use(cache, &cache->cache[idx]);
	if (list_empty(&cache->free)) {
		/* Lock TX queues. */
		wfx_tx_queues_lock(wvif->wdev);
	}
	spin_unlock_bh(&cache->lock);
	return idx;
}

static void tx_policy_put(struct wfx_vif *wvif, int idx)
{
	int usage, locked;
	struct tx_policy_cache *cache = &wvif->tx_policy_cache;

	spin_lock_bh(&cache->lock);
	locked = list_empty(&cache->free);
	usage = tx_policy_release(cache, &cache->cache[idx]);
	if (locked && !usage) {
		/* Unlock TX queues. */
		wfx_tx_queues_unlock(wvif->wdev);
	}
	spin_unlock_bh(&cache->lock);
}

static int tx_policy_upload(struct wfx_vif *wvif)
{
	int i;
	WsmHiMibTxRateRetryPolicy_t *dst;
	WsmHiMibSetTxRateRetryPolicy_t *arg;
	struct tx_policy_cache *cache = &wvif->tx_policy_cache;

	arg = kzalloc(sizeof(WsmHiMibSetTxRateRetryPolicy_t) +
		      sizeof(WsmHiMibTxRateRetryPolicy_t) * WSM_MIB_NUM_TX_RATE_RETRY_POLICIES,
		      GFP_KERNEL);
	spin_lock_bh(&cache->lock);

	/* Upload only modified entries. */
	for (i = 0; i < WSM_MIB_NUM_TX_RATE_RETRY_POLICIES; ++i) {
		struct tx_policy *src = &cache->cache[i].policy;

		if (src->retry_count && !src->uploaded) {
			dst = arg->TxRateRetryPolicy + arg->NumTxRatePolicies;

			dst->PolicyIndex = i;
			dst->ShortRetryCount = wvif->wdev->short_frame_max_tx_count;
			dst->LongRetryCount = wvif->wdev->long_frame_max_tx_count;

			/* dst->flags = WSM_TX_RATE_POLICY_FLAG_TERMINATE_WHEN_FINISHED |
			 *  WSM_TX_RATE_POLICY_FLAG_COUNT_INITIAL_TRANSMIT;
			 */
			dst->Terminate = 1;
			dst->CountInit = 1;
			memcpy(&dst->Rates, src->tbl, sizeof(src->tbl));
			src->uploaded = 1;
			arg->NumTxRatePolicies++;
		}
	}
	spin_unlock_bh(&cache->lock);
	wfx_debug_tx_cache_miss(wvif->wdev);
	wsm_set_tx_rate_retry_policy(wvif->wdev, arg, wvif->Id);
	kfree(arg);
	return 0;
}

void tx_policy_upload_work(struct work_struct *work)
{
	struct wfx_vif *wvif =
		container_of(work, struct wfx_vif, tx_policy_upload_work);

	tx_policy_upload(wvif);

	wsm_tx_unlock(wvif->wdev);
	wfx_tx_queues_unlock(wvif->wdev);
}

/* Link ID related functions */

static int wfx_alloc_link_id(struct wfx_vif *wvif, const u8 *mac)
{
	int i, ret = 0;
	unsigned long max_inactivity = 0;
	unsigned long now = jiffies;

	spin_lock_bh(&wvif->ps_state_lock);
	for (i = 0; i < WFX_MAX_STA_IN_AP_MODE; ++i) {
		if (!wvif->link_id_db[i].status) {
			ret = i + 1;
			break;
		} else if (wvif->link_id_db[i].status != WFX_LINK_HARD &&
			   !wvif->wdev->tx_queue_stats.link_map_cache[i + 1]) {
			unsigned long inactivity =
				now - wvif->link_id_db[i].timestamp;

			if (inactivity < max_inactivity)
				continue;
			max_inactivity = inactivity;
			ret = i + 1;
		}
	}

	if (ret) {
		struct wfx_link_entry *entry = &wvif->link_id_db[ret - 1];

		pr_debug("[AP] STA added, link_id: %d\n", ret);
		entry->status = WFX_LINK_RESERVE;
		ether_addr_copy(entry->mac, mac);
		memset(&entry->buffered, 0, WFX_MAX_TID);
		skb_queue_head_init(&entry->rx_queue);
		wsm_tx_lock(wvif->wdev);

		if (!schedule_work(&wvif->link_id_work))
			wsm_tx_unlock(wvif->wdev);
	} else {
		dev_info(wvif->wdev->dev,
			   "[AP] Early: no more link IDs available.\n");
	}
	spin_unlock_bh(&wvif->ps_state_lock);
	return ret;
}

int wfx_find_link_id(struct wfx_vif *wvif, const u8 *mac)
{
	int i, ret = 0;

	spin_lock_bh(&wvif->ps_state_lock);
	for (i = 0; i < WFX_MAX_STA_IN_AP_MODE; ++i) {
		if (ether_addr_equal(mac, wvif->link_id_db[i].mac) &&
		    wvif->link_id_db[i].status) {
			wvif->link_id_db[i].timestamp = jiffies;
			ret = i + 1;
			break;
		}
	}
	spin_unlock_bh(&wvif->ps_state_lock);
	return ret;
}

static int wfx_map_link(struct wfx_vif *wvif, struct wfx_link_entry *link_entry, int sta_id)
{
	int ret;

	ret = wsm_map_link(wvif->wdev, link_entry->mac, 0, sta_id, wvif->Id);

	if (ret == 0)
		/* Save the MAC address currently associated with the peer
		 * for future unmap request
		 */
		ether_addr_copy(link_entry->old_mac, link_entry->mac);

	return ret;
}

void wfx_link_id_reset_work(struct work_struct *work)
{
	struct wfx_vif *wvif =
		container_of(work, struct wfx_vif, link_id_reset_work);
	int temp_link_id;

	if (!wvif->action_link_id) {
		/* In GO mode we can receive ACTION frames without a linkID */
		temp_link_id = wfx_alloc_link_id(wvif,
						&wvif->action_frame_sa[0]);
		WARN_ON(!temp_link_id);
		if (temp_link_id) {
			/* Make sure we execute the WQ */
			flush_work(&wvif->link_id_work);
			/* Release the link ID */
			spin_lock_bh(&wvif->ps_state_lock);
			wvif->link_id_db[temp_link_id - 1].prev_status =
				wvif->link_id_db[temp_link_id - 1].status;
			wvif->link_id_db[temp_link_id - 1].status =
				WFX_LINK_RESET;
			spin_unlock_bh(&wvif->ps_state_lock);
			wsm_tx_lock(wvif->wdev);
			if (!schedule_work(&wvif->link_id_work))
				wsm_tx_unlock(wvif->wdev);
		}
	} else {
		spin_lock_bh(&wvif->ps_state_lock);
		wvif->link_id_db[wvif->action_link_id - 1].prev_status =
			wvif->link_id_db[wvif->action_link_id - 1].status;
		wvif->link_id_db[wvif->action_link_id - 1].status =
			WFX_LINK_RESET_REMAP;
		spin_unlock_bh(&wvif->ps_state_lock);
		wsm_tx_lock(wvif->wdev);
		if (!schedule_work(&wvif->link_id_work))
			wsm_tx_unlock(wvif->wdev);
		flush_work(&wvif->link_id_work);
	}
}

void wfx_link_id_gc_work(struct work_struct *work)
{
	struct wfx_vif *wvif =
		container_of(work, struct wfx_vif, link_id_gc_work.work);
	unsigned long now = jiffies;
	unsigned long next_gc = -1;
	long ttl;
	u32 mask;
	int i;

	if (wvif->state != WFX_STATE_AP)
		return;

	wsm_tx_lock_flush(wvif->wdev);
	spin_lock_bh(&wvif->ps_state_lock);
	for (i = 0; i < WFX_MAX_STA_IN_AP_MODE; ++i) {
		bool need_reset;
		need_reset = false;
		mask = BIT(i + 1);
		if (wvif->link_id_db[i].status == WFX_LINK_RESERVE ||
		    (wvif->link_id_db[i].status == WFX_LINK_HARD &&
		     !(wvif->link_id_map & mask))) {
			if (wvif->link_id_map & mask) {
				wvif->sta_asleep_mask &= ~mask;
				wvif->pspoll_mask &= ~mask;
				need_reset = true;
			}
			wvif->link_id_map |= mask;
			if (wvif->link_id_db[i].status != WFX_LINK_HARD)
				wvif->link_id_db[i].status = WFX_LINK_SOFT;

			spin_unlock_bh(&wvif->ps_state_lock);
			if (need_reset)
				wfx_unmap_link(wvif, i + 1);
			wfx_map_link(wvif, &wvif->link_id_db[i], i + 1);
			next_gc = min(next_gc, WFX_LINK_ID_GC_TIMEOUT);
			spin_lock_bh(&wvif->ps_state_lock);
		} else if (wvif->link_id_db[i].status == WFX_LINK_SOFT) {
			ttl = wvif->link_id_db[i].timestamp - now +
					WFX_LINK_ID_GC_TIMEOUT;
			if (ttl <= 0) {
				need_reset = true;
				wvif->link_id_db[i].status = WFX_LINK_OFF;
				wvif->link_id_map &= ~mask;
				wvif->sta_asleep_mask &= ~mask;
				wvif->pspoll_mask &= ~mask;
				spin_unlock_bh(&wvif->ps_state_lock);
				wfx_unmap_link(wvif, i + 1);
				spin_lock_bh(&wvif->ps_state_lock);
			} else {
				next_gc = min_t(unsigned long, next_gc, ttl);
			}
		} else if (wvif->link_id_db[i].status == WFX_LINK_RESET ||
			   wvif->link_id_db[i].status == WFX_LINK_RESET_REMAP) {
			int status = wvif->link_id_db[i].status;
			wvif->link_id_db[i].status =
				wvif->link_id_db[i].prev_status;
			wvif->link_id_db[i].timestamp = now;
			spin_unlock_bh(&wvif->ps_state_lock);
			wfx_unmap_link(wvif, i + 1);
			if (status == WFX_LINK_RESET_REMAP) {
				wfx_map_link(wvif, &wvif->link_id_db[i], i + 1);
				next_gc = min(next_gc,
						WFX_LINK_ID_GC_TIMEOUT);
			} else {
				need_reset = true;
				wvif->link_id_db[i].status = WFX_LINK_OFF;
			}
			spin_lock_bh(&wvif->ps_state_lock);
		}
		if (need_reset) {
			skb_queue_purge(&wvif->link_id_db[i].rx_queue);
			pr_debug("[AP] STA removed, link_id: %d\n",
				 0); /* 0 instead of reset.link_id */
		}
	}
	spin_unlock_bh(&wvif->ps_state_lock);
	if (next_gc != -1)
		schedule_delayed_work(&wvif->link_id_gc_work, next_gc);
	wsm_tx_unlock(wvif->wdev);
}

void wfx_link_id_work(struct work_struct *work)
{
	struct wfx_vif *wvif =
		container_of(work, struct wfx_vif, link_id_work);

	wsm_tx_flush(wvif->wdev);
	wfx_link_id_gc_work(&wvif->link_id_gc_work.work);
	wsm_tx_unlock(wvif->wdev);
}

/* Tx implementation */


static bool ieee80211_is_action_back(struct ieee80211_hdr *hdr)
{
	struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *) hdr;

	if (!ieee80211_is_action(mgmt->frame_control))
		return false;
	if (mgmt->u.action.category != WLAN_CATEGORY_BACK)
		return false;
	return true;
}
static uint8_t wfx_tx_get_raw_link_id(struct wfx_vif *wvif, struct ieee80211_sta *sta, struct ieee80211_hdr *hdr)
{
	struct wfx_sta_priv *sta_priv = sta ? (struct wfx_sta_priv *) &sta->drv_priv : NULL;
	const u8 *da = ieee80211_get_DA(hdr);
	int ret;

	if (sta_priv && sta_priv->link_id) {
		return sta_priv->link_id;
	} else if (wvif->mode != NL80211_IFTYPE_AP) {
		return 0;
	} else if (is_multicast_ether_addr(da)) {
		return 0;
	} else {
		ret = wfx_find_link_id(wvif, da);
		if (!ret)
			ret = wfx_alloc_link_id(wvif, da);
		if (!ret) {
			dev_err(wvif->wdev->dev, "No more link IDs available.\n");
			return -ENOENT;
		}
		return ret;
	}
}

static void wfx_mark_sta(struct wfx_vif *wvif, int link_id)
{
	u32 mask = ~BIT(link_id);

	spin_lock_bh(&wvif->ps_state_lock);
	wvif->sta_asleep_mask &= mask;
	wvif->pspoll_mask &= mask;
	spin_unlock_bh(&wvif->ps_state_lock);
}

static uint8_t wfx_tx_get_rate_id(struct wfx_vif *wvif, struct ieee80211_tx_info *tx_info)
{
	bool tx_policy_renew = false;
	uint8_t rate_id;

	rate_id = tx_policy_get(wvif, tx_info->driver_rates, &tx_policy_renew);
	WARN(rate_id == WFX_INVALID_RATE_ID, "Enable to get a valid Tx policy");

	if (tx_policy_renew) {
		/* FIXME: It's not so optimal to stop TX queues every now and
		 * then.  Better to reimplement task scheduling with a counter.
		 */
		wsm_tx_lock(wvif->wdev);
		wfx_tx_queues_lock(wvif->wdev);
		if (!schedule_work(&wvif->tx_policy_upload_work)) {
			wfx_tx_queues_unlock(wvif->wdev);
			wsm_tx_unlock(wvif->wdev);
		}
	}
	return rate_id;
}

static WsmHiHtTxParameters_t wfx_tx_get_tx_parms(struct wfx_dev *wdev, struct ieee80211_tx_info *tx_info)
{
	struct ieee80211_tx_rate *rate = &tx_info->driver_rates[0];
	WsmHiHtTxParameters_t ret = { };

	if (rate->flags & IEEE80211_TX_RC_GREEN_FIELD)
		ret.FrameFormat = WSM_FRAME_FORMAT_GF_HT_11N;
	else
		ret.FrameFormat = WSM_FRAME_FORMAT_MIXED_FORMAT_HT;
	if (rate->flags & IEEE80211_TX_RC_SHORT_GI)
		ret.ShortGi = 1;
	if (tx_info->flags & IEEE80211_TX_CTL_LDPC && wdev->pdata.support_ldpc)
		ret.FecCoding = 1;
	if (tx_info->flags & IEEE80211_TX_CTL_STBC)
		ret.Stbc = 0; // FIXME: Not yet supported by firmware?
	if (tx_info->flags & IEEE80211_TX_CTL_AMPDU)
		ret.Aggregation = 0; // FIXME: what is purpose of this field?
	return ret;
}

static bool wfx_tx_h_pm_state(struct wfx_vif *wvif, struct wfx_txpriv *txpriv)
{
	int was_buffered = 1;

	if (txpriv->link_id == WFX_LINK_ID_AFTER_DTIM &&
	    !wvif->buffered_multicasts) {
		wvif->buffered_multicasts = true;
		if (wvif->sta_asleep_mask)
			schedule_work(&wvif->multicast_start_work);
	}

	if (txpriv->raw_link_id && txpriv->tid < WFX_MAX_TID)
		was_buffered = wvif->link_id_db[txpriv->raw_link_id - 1].buffered[txpriv->tid]++;

	return !was_buffered;
}

static uint8_t wfx_tx_get_tid(struct ieee80211_hdr *hdr)
{
	// FIXME: ieee80211_get_tid(hdr) should be sufficient for all cases.
	if (!ieee80211_is_data(hdr->frame_control))
		return WFX_MAX_TID;
	if (ieee80211_is_data_qos(hdr->frame_control))
		return ieee80211_get_tid(hdr);
	else
		return 0;
}

static int wfx_tx_get_icv_len(struct ieee80211_key_conf *hw_key)
{
	int mic_space;

	if (!hw_key)
		return 0;
	mic_space = (hw_key->cipher == WLAN_CIPHER_SUITE_TKIP) ? 8 : 0;
	return hw_key->icv_len + mic_space;
}

void wfx_tx(struct ieee80211_hw *hw, struct ieee80211_tx_control *control,
	    struct sk_buff *skb)
{
	struct wfx_dev *wdev = hw->priv;
	struct wfx_vif *wvif = NULL;
	struct wmsg *wmsg;
	WsmHiTxReqBody_t *wsm;
	struct wfx_txpriv *txpriv;
	struct ieee80211_sta *sta = control ? control->sta : NULL;
	struct ieee80211_tx_info *tx_info = IEEE80211_SKB_CB(skb);
	struct ieee80211_key_conf *hw_key = tx_info->control.hw_key;
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) skb->data;
	int queue_id = skb_get_queue_mapping(skb);
	size_t offset = (size_t) skb->data & 3;
	int wmsg_len = sizeof(struct wmsg) + sizeof(WsmHiTxReqBody_t) + offset;
	bool tid_update = 0;
	int ret;

	compiletime_assert(sizeof(struct wfx_txpriv) <= FIELD_SIZEOF(struct ieee80211_tx_info, status.status_driver_data), "struct txpriv is too large");
	WARN(skb->next || skb->prev, "skb is already member of a list");
	// FIXME: why?
	if (ieee80211_is_action_back(hdr)) {
		dev_info(wdev->dev, "drop BA action\n");
		goto drop;
	}

	// control.vif can be NULL for injected frames
	if (tx_info->control.vif)
		wvif = (struct wfx_vif *) tx_info->control.vif->drv_priv;
	else
		wvif = wvif_iterate(wdev, NULL);
	if (!wvif)
		goto drop;

	WARN_ON(!wvif);

	if (WARN_ON(queue_id >= 4))
		goto drop;

	// From now tx_info->control is unusable
	memset(tx_info->status.status_driver_data, 0, sizeof(struct wfx_txpriv));
	// Fill txpriv and prepare auxilliary operations
	txpriv = (struct wfx_txpriv *) tx_info->status.status_driver_data;
	txpriv->tid = wfx_tx_get_tid(hdr);
	txpriv->rate_id = wfx_tx_get_rate_id(wvif, tx_info);
	txpriv->raw_link_id = wfx_tx_get_raw_link_id(wvif, sta, hdr);
	txpriv->link_id = txpriv->raw_link_id;
	if (ieee80211_has_protected(hdr->frame_control))
		txpriv->hw_key = hw_key;
	if (tx_info->flags & IEEE80211_TX_CTL_SEND_AFTER_DTIM)
		txpriv->link_id = WFX_LINK_ID_AFTER_DTIM;
	if (sta && (sta->uapsd_queues & BIT(queue_id)))
		txpriv->link_id = WFX_LINK_ID_UAPSD;
	if (txpriv->raw_link_id)
		wvif->link_id_db[txpriv->raw_link_id - 1].timestamp = jiffies;
	if (ieee80211_is_auth(hdr->frame_control))
		wfx_mark_sta(wvif, txpriv->raw_link_id);

	// Fill wmsg
	WARN(skb_headroom(skb) < wmsg_len, "not enough space in skb");
	WARN(offset & 1, "attempt to transmit an unaligned frame");
	skb_put(skb, wfx_tx_get_icv_len(txpriv->hw_key));
	skb_push(skb, wmsg_len);
	memset(skb->data, 0, wmsg_len);
	wmsg = (struct wmsg *) skb->data;
	wmsg->len = cpu_to_le16(skb->len);
	wmsg->id = cpu_to_le16(WSM_HI_TX_REQ_ID);
	wmsg->interface = wvif->Id;
	if (skb->len > wdev->wsm_caps.SizeInpChBuf) {
		dev_warn(wdev->dev, "Requested frame size (%d) is larger than maximum supported (%d)\n",
			 skb->len, wdev->wsm_caps.SizeInpChBuf);
		goto drop_pull;
	}

	// Fill tx request
	wsm = (WsmHiTxReqBody_t *) wmsg->body;
	wsm->DataFlags.FcOffset = offset;
	wsm->QueueId.PeerStaId = txpriv->raw_link_id;
	// Queue index are inverted between WSM and Linux
	wsm->QueueId.QueueId = 3 - queue_id;
	wsm->HtTxParameters = wfx_tx_get_tx_parms(wdev, tx_info);
	wsm->TxFlags.RetryPolicyIndex = txpriv->rate_id;
	wsm->MaxTxRate = wfx_get_hw_rate(wdev, &tx_info->driver_rates[0]);

	spin_lock_bh(&wvif->ps_state_lock);
	tid_update = wfx_tx_h_pm_state(wvif, txpriv);

	ret = wfx_tx_queue_put(wdev, &wdev->tx_queue[queue_id], skb);
	spin_unlock_bh(&wvif->ps_state_lock);
	BUG_ON(ret);

	if (tid_update && sta)
		ieee80211_sta_set_buffered(sta, txpriv->tid, true);

	wfx_bh_request_tx(wdev);

	return;

drop_pull:
	skb_pull(skb, wmsg_len);
	if (txpriv->rate_id != WFX_INVALID_RATE_ID) {
		wfx_notify_buffered_tx(wvif, skb,
					  txpriv->raw_link_id, txpriv->tid);
		tx_policy_put(wvif, txpriv->rate_id);
	}
drop:
	ieee80211_tx_status(wdev->hw, skb);
}

void wfx_tx_confirm_cb(struct wfx_vif *wvif, WsmHiTxCnfBody_t *arg)
{
	struct sk_buff *skb;
	const struct wfx_txpriv *txpriv;

	skb = wfx_pending_get(wvif->wdev, arg->PacketId);
	if (!skb) {
		dev_warn(wvif->wdev->dev, "Received unknown packet_id (%#.8x) from chip\n", arg->PacketId);
		return;
	}
	txpriv = wfx_skb_txpriv(skb);

	if (arg->Status == WSM_REQUEUE) {
		/* "Requeue" means "implicit suspend" */
		WsmHiSuspendResumeTxIndBody_t suspend = {
			.SuspendResumeFlags.Resume	= 0,
			.SuspendResumeFlags.BcMcOnly		= 1,
		};

		WARN(!arg->TxResultFlags.Requeue, "Incoherent Status and ResultFlags");

		wfx_suspend_resume(wvif, &suspend);
		dev_dbg(wvif->wdev->dev, "Requeuing for station %d. STAs asleep: 0x%.8X.\n",
			   txpriv->link_id, wvif->sta_asleep_mask);
		wfx_pending_requeue(wvif->wdev, skb);
		if (!txpriv->link_id) { // Is multicast?
			spin_lock_bh(&wvif->ps_state_lock);
			wvif->buffered_multicasts = true;
			if (wvif->sta_asleep_mask)
				schedule_work(&wvif->multicast_start_work);
			spin_unlock_bh(&wvif->ps_state_lock);
		}
	} else {
		struct ieee80211_tx_info *tx_info = IEEE80211_SKB_CB(skb);
		int tx_count;
		int i;

		mutex_lock(&wvif->bss_loss_lock);
		if (wvif->bss_loss_state &&
		    arg->PacketId == wvif->bss_loss_confirm_id) {
			if (arg->Status) {
				/* Recovery failed */
				__wfx_cqm_bssloss_sm(wvif, 0, 0, 1);
			} else {
				/* Recovery succeeded */
				__wfx_cqm_bssloss_sm(wvif, 0, 1, 0);
			}
		}
		mutex_unlock(&wvif->bss_loss_lock);
		/* Pull off any crypto trailers that we added on */
		skb_trim(skb, skb->len - wfx_tx_get_icv_len(txpriv->hw_key));

		// FIXME: use ieee80211_tx_info_clear_status()
		// Clear all tx->status but status_driver_data
		tx_info->status.ack_signal = 0;
		tx_info->status.ampdu_ack_len = 0;
		tx_info->status.ampdu_len = 0;
		tx_info->status.antenna = 0;
		tx_info->status.tx_time = 0;
#if (KERNEL_VERSION(4, 15, 0) <= LINUX_VERSION_CODE)
		tx_info->status.is_valid_ack_signal = false;
#endif
		if (!arg->Status) {
			_trace_tx_stats(arg, wfx_pending_get_pkt_us_delay(wvif->wdev, skb));
			tx_info->flags |= IEEE80211_TX_STAT_ACK;
			tx_info->status.tx_time = arg->MediaDelay - arg->TxQueueDelay;
		}
		if (arg->Status && !arg->AckFailures)
			tx_count = 0;
		else
			tx_count = arg->AckFailures + 1;

		for (i = 0; i < IEEE80211_TX_MAX_RATES; i++) {
			if (!tx_count) {
				tx_info->status.rates[i].count = 0;
				tx_info->status.rates[i].idx = -1;
			} else if (tx_count > tx_info->status.rates[i].count) {
				tx_count -= tx_info->status.rates[i].count;
			} else {
				if (arg->TxedRate != wfx_get_hw_rate(wvif->wdev, &tx_info->status.rates[i]))
					dev_warn(wvif->wdev->dev, "inconsistent tx_info rates: %d != %d\n",
						 arg->TxedRate, wfx_get_hw_rate(wvif->wdev, &tx_info->status.rates[i]));
				tx_info->status.rates[i].count = tx_count;
				tx_count = 0;
			}
		}

		wfx_pending_remove(wvif->wdev, skb);
	}
}

static void wfx_notify_buffered_tx(struct wfx_vif *wvif, struct sk_buff *skb,
				   int link_id, int tid)
{
	struct ieee80211_sta *sta;
	struct ieee80211_hdr *hdr;
	u8 still_buffered = 0;
	u8 *buffered;

	if (link_id && tid < WFX_MAX_TID) {
		buffered = wvif->link_id_db
				[link_id - 1].buffered;

		spin_lock_bh(&wvif->ps_state_lock);
		if (!buffered[tid])
			dev_err(wvif->wdev->dev, "wfx_notify_buffered_tx: inconsistent tid (%d)\n", tid);
		else
			still_buffered = --buffered[tid];
		spin_unlock_bh(&wvif->ps_state_lock);

		if (!still_buffered && tid < WFX_MAX_TID) {
			hdr = (struct ieee80211_hdr *)skb->data;
			rcu_read_lock();
			sta = ieee80211_find_sta(wvif->vif, hdr->addr1);
			if (sta)
				ieee80211_sta_set_buffered(sta, tid, false);
			rcu_read_unlock();
		}
	}
}

void wfx_skb_dtor(struct wfx_dev *wdev, struct sk_buff *skb)
{
	struct wmsg *hdr = (struct wmsg *) skb->data;
	WsmHiTxReqBody_t *tx_req = (WsmHiTxReqBody_t *) hdr->body;
	struct wfx_vif *wvif = wdev_to_wvif(wdev, hdr->interface);
	struct wfx_txpriv *txpriv = wfx_skb_txpriv(skb);
	unsigned int offset = sizeof(WsmHiTxReqBody_t) + sizeof(struct wmsg) + tx_req->DataFlags.FcOffset;

	WARN_ON(!wvif);
	skb_pull(skb, offset);
	if (txpriv->rate_id != WFX_INVALID_RATE_ID) {
		wfx_notify_buffered_tx(wvif, skb,
					  txpriv->raw_link_id, txpriv->tid);
		tx_policy_put(wvif, txpriv->rate_id);
	}
	ieee80211_tx_status(wdev->hw, skb);
}


