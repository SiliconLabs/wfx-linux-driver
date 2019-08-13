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

/* TX queue lock / unlock */

static void wfx_tx_queues_lock(struct wfx_dev *wdev)
{
	int i;
	for (i = 0; i < 4; ++i)
		wfx_queue_lock(&wdev->tx_queue[i]);
}

static void wfx_tx_queues_unlock(struct wfx_dev *wdev)
{
	int i;
	for (i = 0; i < 4; ++i)
		wfx_queue_unlock(&wdev->tx_queue[i]);
}

/* TX policy cache implementation */

static const struct ieee80211_rate *wfx_get_tx_rate(struct wfx_vif *wvif,
						    const struct ieee80211_tx_rate *rate)
{
	struct wfx_dev *wdev = wvif->wdev;
	int band = NL80211_BAND_2GHZ;

	// In some circumstances, channel is unassigned before all data was sent.
	if (wvif->channel)
		band = wvif->channel->band;
	if (rate->idx < 0)
		return NULL;
	if (rate->flags & IEEE80211_TX_RC_MCS)
		return &wdev->mcs_rates[rate->idx];
	return &wdev->hw->wiphy->bands[band]->bitrates[rate->idx];
}

static void tx_policy_build(struct wfx_vif *wvif, struct tx_policy *policy,
			    struct ieee80211_tx_rate *rates, size_t count)
{
	int i, j;
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

	policy->defined = wfx_get_tx_rate(wvif, &rates[0])->hw_value + 1;

	for (i = 0; i < count; ++i) {
		register unsigned rateid, off, shift, retries;

		rateid = wfx_get_tx_rate(wvif, &rates[i])->hw_value;
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
			 size_t count, bool *renew)
{
	int idx;
	struct tx_policy_cache *cache = &wvif->tx_policy_cache;
	struct tx_policy wanted;

	tx_policy_build(wvif, &wanted, rates, count);

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

struct wfx_txinfo {
	struct sk_buff *skb;
	unsigned queue;
	struct ieee80211_tx_info *tx_info;
	const struct ieee80211_rate *rate;
	struct ieee80211_hdr *hdr;
	const u8 *da;
	struct wfx_sta_priv *sta_priv;
	struct ieee80211_sta *sta;
	struct wfx_txpriv txpriv;
};


static int wfx_tx_h_calc_link_ids(struct wfx_vif *wvif, struct wfx_txinfo *t)
{
	if (t->sta && t->sta_priv->link_id) {
		t->txpriv.raw_link_id =
				t->txpriv.link_id =
				t->sta_priv->link_id;
	} else if (wvif->mode != NL80211_IFTYPE_AP) {
		t->txpriv.raw_link_id =
				t->txpriv.link_id = 0;
	} else if (is_multicast_ether_addr(t->da)) {
		if (wvif->enable_beacon) {
			t->txpriv.raw_link_id = 0;
			t->txpriv.link_id = WFX_LINK_ID_AFTER_DTIM;
		} else {
			t->txpriv.raw_link_id = 0;
			t->txpriv.link_id = 0;
		}
	} else {
		t->txpriv.link_id = wfx_find_link_id(wvif, t->da);
		if (!t->txpriv.link_id)
			t->txpriv.link_id = wfx_alloc_link_id(wvif, t->da);
		if (!t->txpriv.link_id) {
			dev_err(wvif->wdev->dev,
				  "No more link IDs available.\n");
			return -ENOENT;
		}
		t->txpriv.raw_link_id = t->txpriv.link_id;
	}
	if (t->txpriv.raw_link_id)
		wvif->link_id_db[t->txpriv.raw_link_id - 1].timestamp =
				jiffies;
	if (t->sta && (t->sta->uapsd_queues & BIT(t->queue)))
		t->txpriv.link_id = WFX_LINK_ID_UAPSD;
	return 0;
}

static void wfx_tx_h_pm(struct wfx_vif *wvif, struct wfx_txinfo *t)
{
	if (ieee80211_is_auth(t->hdr->frame_control)) {
		u32 mask = ~BIT(t->txpriv.raw_link_id);
		spin_lock_bh(&wvif->ps_state_lock);
		wvif->sta_asleep_mask &= mask;
		wvif->pspoll_mask &= mask;
		spin_unlock_bh(&wvif->ps_state_lock);
	}
}

static void wfx_tx_h_calc_tid(struct wfx_vif *wvif, struct wfx_txinfo *t)
{
	if (ieee80211_is_data_qos(t->hdr->frame_control)) {
		t->txpriv.tid = ieee80211_get_tid(t->hdr);
	} else if (ieee80211_is_data(t->hdr->frame_control)) {
		t->txpriv.tid = 0;
	}
}

static int wfx_tx_h_crypt(struct wfx_vif *wvif, struct wfx_txinfo *t)
{
	if (!t->tx_info->control.hw_key ||
	    !ieee80211_has_protected(t->hdr->frame_control))
		return 0;

	skb_put(t->skb, t->tx_info->control.hw_key->icv_len);

	if (t->tx_info->control.hw_key->cipher == WLAN_CIPHER_SUITE_TKIP)
		skb_put(t->skb, 8); /* MIC space */

	return 0;
}

static int wfx_tx_h_align(struct wfx_vif *wvif, struct wfx_txinfo *t, WsmHiDataFlags_t *flags)
{
	size_t offset = (size_t)t->skb->data & 3;

	if (!offset)
		return 0;

	if (offset & 1)
		dev_warn(wvif->wdev->dev, "Attempt to transmit an unaligned frame\n");

	if (skb_headroom(t->skb) < offset) {
		dev_err(wvif->wdev->dev,
			  "Bug: no space allocated for DMA alignment. headroom: %d\n",
			  skb_headroom(t->skb));
		return -ENOMEM;
	}
	skb_push(t->skb, offset);
	t->txpriv.offset += offset;
	flags->FcOffset = offset;
	wfx_debug_tx_align(wvif->wdev);
	return 0;
}

static int wfx_tx_h_action(struct wfx_vif *wvif, struct wfx_txinfo *t)
{
	struct ieee80211_mgmt *mgmt =
		(struct ieee80211_mgmt *)t->hdr;
	if (ieee80211_is_action(t->hdr->frame_control) &&
	    mgmt->u.action.category == WLAN_CATEGORY_BACK)
		return 1;
	else
		return 0;
}

static WsmHiTxReqBody_t *wfx_tx_h_wsm(struct wfx_vif *wvif, struct wfx_txinfo *t)
{
	struct wmsg *hdr;
	WsmHiTxReqBody_t *wsm;
	u32 wsm_length = sizeof(WsmHiTxReqBody_t) + sizeof(struct wmsg);

	if (WARN(skb_headroom(t->skb) < wsm_length, "Not enough space for WSM headers"))
		return NULL;
	if (t->skb->len > wvif->wdev->wsm_caps.SizeInpChBuf) {
		dev_info(wvif->wdev->dev, "Requested frame size (%d) is larger than maximum supported (%d)\n",
			 t->skb->len, wvif->wdev->wsm_caps.SizeInpChBuf);
		return NULL;
	}

	hdr = (struct wmsg *) skb_push(t->skb, wsm_length);
	wsm = (WsmHiTxReqBody_t *) hdr->body;
	t->txpriv.offset += wsm_length;
	memset(hdr, 0, wsm_length);
	hdr->len = cpu_to_le16(t->skb->len);
	hdr->id = cpu_to_le16(WSM_HI_TX_REQ_ID);
	hdr->interface = t->txpriv.vif_id;
	wsm->QueueId.PeerStaId = t->txpriv.raw_link_id;
	// Queue index are inverted between WSM and Linux
	wsm->QueueId.QueueId = 3 - t->queue;
	return wsm;
}

static int wfx_tx_h_rate_policy(struct wfx_vif *wvif, struct wfx_txinfo *t, WsmHiTxReqBody_t *wsm)
{
	bool tx_policy_renew = false;

	WARN_ON(!wvif);
	t->txpriv.rate_id = tx_policy_get(wvif,
		t->tx_info->control.rates, IEEE80211_TX_MAX_RATES,
		&tx_policy_renew);
	if (t->txpriv.rate_id == WFX_INVALID_RATE_ID)
		return -EFAULT;

	wsm->TxFlags.RetryPolicyIndex = t->txpriv.rate_id;

	t->rate = wfx_get_tx_rate(wvif,
		&t->tx_info->control.rates[0]),
	wsm->MaxTxRate = t->rate->hw_value;

	if (t->rate->flags & IEEE80211_TX_RC_GREEN_FIELD)
		wsm->HtTxParameters.FrameFormat =
			WSM_FRAME_FORMAT_GF_HT_11N;
	else
		/*HT mixed is used*/
		wsm->HtTxParameters.FrameFormat =
			WSM_FRAME_FORMAT_MIXED_FORMAT_HT;
	if (t->rate->flags & IEEE80211_TX_RC_SHORT_GI || wfx_ht_shortGi(&wvif->ht_info))
		wsm->HtTxParameters.ShortGi = 1;
	if (t->tx_info->flags & IEEE80211_TX_CTL_LDPC || wfx_ht_fecCoding(&wvif->ht_info))
		if (wvif->wdev->pdata.support_ldpc)
			wsm->HtTxParameters.FecCoding = 1;
	if (tx_policy_renew) {
		pr_debug("[TX] TX policy renew.\n");
		/* It's not so optimal to stop TX queues every now and then.
		 * Better to reimplement task scheduling with
		 * a counter. TODO.
		 */
		wsm_tx_lock(wvif->wdev);
		wfx_tx_queues_lock(wvif->wdev);
		if (!schedule_work(&wvif->tx_policy_upload_work)) {
			wfx_tx_queues_unlock(wvif->wdev);
			wsm_tx_unlock(wvif->wdev);
		}
	}
	return 0;
}

static bool wfx_tx_h_pm_state(struct wfx_vif *wvif, struct wfx_txinfo *t)
{
	int was_buffered = 1;

	if (t->txpriv.link_id == WFX_LINK_ID_AFTER_DTIM &&
	    !wvif->buffered_multicasts) {
		wvif->buffered_multicasts = true;
		if (wvif->sta_asleep_mask)
			schedule_work(&wvif->multicast_start_work);
	}

	if (t->txpriv.raw_link_id && t->txpriv.tid < WFX_MAX_TID)
		was_buffered = wvif->link_id_db[t->txpriv.raw_link_id - 1].buffered[t->txpriv.tid]++;

	return !was_buffered;
}

void wfx_tx(struct ieee80211_hw *hw, struct ieee80211_tx_control *control,
	    struct sk_buff *skb)
{
	struct wfx_dev *wdev = hw->priv;
	struct wfx_vif *wvif = NULL;
	struct wfx_txinfo t = {
		.skb = skb,
		.queue = skb_get_queue_mapping(skb),
		.tx_info = IEEE80211_SKB_CB(skb),
		.hdr = (struct ieee80211_hdr *)skb->data,
		.txpriv.tid = WFX_MAX_TID,
		.txpriv.rate_id = WFX_INVALID_RATE_ID,
	};
	struct ieee80211_sta *sta;
	WsmHiTxReqBody_t *wsm;
	bool tid_update = 0;
	WsmHiDataFlags_t flags = { };
	int ret;

	// control.vif can be NULL for injected frames
	if (IEEE80211_SKB_CB(skb)->control.vif)
		wvif = (struct wfx_vif *) IEEE80211_SKB_CB(skb)->control.vif->drv_priv;
	else
		wvif = wvif_iterate(wdev, NULL);
	if (!wvif)
		goto drop;

	WARN_ON(!wvif);
	t.txpriv.vif_id = wvif->Id;
	t.da = ieee80211_get_DA(t.hdr);
	if (control) {
		t.sta = control->sta;
		t.sta_priv = (struct wfx_sta_priv *)&t.sta->drv_priv;
	}

	if (WARN_ON(t.queue >= 4))
		goto drop;

	ret = wfx_tx_h_calc_link_ids(wvif, &t);
	if (ret)
		goto drop;

	wfx_tx_h_pm(wvif, &t);
	wfx_tx_h_calc_tid(wvif, &t);
	ret = wfx_tx_h_crypt(wvif, &t);
	if (ret)
		goto drop;
	ret = wfx_tx_h_align(wvif, &t, &flags);
	if (ret)
		goto drop;
	ret = wfx_tx_h_action(wvif, &t);
	if (ret)
		goto drop;
	wsm = wfx_tx_h_wsm(wvif, &t);
	if (!wsm) {
		ret = -ENOMEM;
		goto drop;
	}
	wsm->DataFlags.FcOffset = flags.FcOffset;
	ret = wfx_tx_h_rate_policy(wvif, &t, wsm);
	if (ret)
		goto drop;

	rcu_read_lock();
	sta = rcu_dereference(t.sta);

	spin_lock_bh(&wvif->ps_state_lock);
	tid_update = wfx_tx_h_pm_state(wvif, &t);
	ret = wfx_queue_put(&wdev->tx_queue[t.queue], t.skb, &t.txpriv);
	spin_unlock_bh(&wvif->ps_state_lock);
	BUG_ON(ret);

	if (tid_update && sta)
		ieee80211_sta_set_buffered(sta, t.txpriv.tid, true);

	rcu_read_unlock();

	wfx_bh_request_tx(wdev);

	return;

drop:
	wfx_skb_dtor(wdev, skb, &t.txpriv);
}

void wfx_tx_confirm_cb(struct wfx_dev *wdev, WsmHiTxCnfBody_t *arg)
{
	struct wfx_vif *wvif;
	u8 queue_id = wfx_queue_get_queue_id(arg->PacketId);
	struct wfx_queue *queue = &wdev->tx_queue[queue_id];
	struct sk_buff *skb;
	const struct wfx_txpriv *txpriv;
	int ret;

	ret = wfx_queue_get_skb(queue, arg->PacketId, &skb, &txpriv);
	if (ret) {
		dev_warn(wdev->dev, "Received unknown packet_id (%#.8x) from chip\n", arg->PacketId);
		return;
	}

	wvif = wdev_to_wvif(wdev, txpriv->vif_id);
	WARN_ON(!wvif);
	if (!wvif)
		return;

	if (arg->Status == WSM_REQUEUE) {
		/* "Requeue" means "implicit suspend" */
		WsmHiSuspendResumeTxIndBody_t suspend = {
			.SuspendResumeFlags.Resume	= 0,
			.SuspendResumeFlags.BcMcOnly		= 1,
		};

		WARN(!arg->TxResultFlags.Requeue, "Incoherent Status and ResultFlags");

		wfx_suspend_resume(wvif, &suspend);
		dev_dbg(wdev->dev, "Requeuing for station %d (try %d). STAs asleep: 0x%.8X.\n",
			   txpriv->link_id, wfx_queue_get_generation(arg->PacketId) + 1,
			   wvif->sta_asleep_mask);
		wfx_queue_requeue(queue, arg->PacketId);
		if (!txpriv->link_id) { // Is multicast?
			spin_lock_bh(&wvif->ps_state_lock);
			wvif->buffered_multicasts = true;
			if (wvif->sta_asleep_mask)
				schedule_work(&wvif->multicast_start_work);
			spin_unlock_bh(&wvif->ps_state_lock);
		}
	} else {
		struct ieee80211_tx_info *tx = IEEE80211_SKB_CB(skb);
		int tx_count = arg->AckFailures;
		u8 ht_flags = 0;
		int i;

		if (wfx_ht_greenfield(&wvif->ht_info))
			ht_flags |= IEEE80211_TX_RC_GREEN_FIELD;

		if (wfx_ht_fecCoding(&wvif->ht_info))
			ht_flags |= IEEE80211_TX_CTL_LDPC;

		if (wfx_ht_shortGi(&wvif->ht_info))
			ht_flags |= IEEE80211_TX_RC_SHORT_GI;

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

		if (!arg->Status) {
			_trace_tx_stats(arg, wfx_queue_get_pkt_us_delay(queue, arg->PacketId));
			tx->flags |= IEEE80211_TX_STAT_ACK;
			++tx_count;
			wfx_debug_txed(wdev);
			if (arg->TxResultFlags.Aggr)
				wfx_debug_txed_agg(wdev);
		} else {
			if (tx_count)
				++tx_count;
		}

		for (i = 0; i < IEEE80211_TX_MAX_RATES; ++i) {
			if (tx->status.rates[i].count >= tx_count) {
				tx->status.rates[i].count = tx_count;
				break;
			}
			tx_count -= tx->status.rates[i].count;
			if (tx->status.rates[i].flags & IEEE80211_TX_RC_MCS)
				tx->status.rates[i].flags |= ht_flags;
		}

		if (arg->TxedRate != wfx_get_tx_rate(wvif, &tx->status.rates[i])->hw_value)
			dev_warn(wvif->wdev->dev, "inconsistent tx_info rates: %d != %d\n",
					arg->TxedRate, wfx_get_tx_rate(wvif, &tx->status.rates[i])->hw_value);

		for (++i; i < IEEE80211_TX_MAX_RATES; ++i) {
			tx->status.rates[i].count = 0;
			tx->status.rates[i].idx = -1;
		}

		/* Pull off any crypto trailers that we added on */
		if (tx->control.hw_key) {
			skb_trim(skb, skb->len - tx->control.hw_key->icv_len);
			if (tx->control.hw_key->cipher == WLAN_CIPHER_SUITE_TKIP)
				skb_trim(skb, skb->len - 8); /* MIC space */
		}
		wfx_queue_remove(queue, arg->PacketId);
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

void wfx_skb_dtor(struct wfx_dev *wdev, struct sk_buff *skb,
		  const struct wfx_txpriv *txpriv)
{
	struct wfx_vif *wvif = wdev_to_wvif(wdev, txpriv->vif_id);

	WARN_ON(!wvif);
	skb_pull(skb, txpriv->offset);
	if (txpriv->rate_id != WFX_INVALID_RATE_ID) {
		wfx_notify_buffered_tx(wvif, skb,
					  txpriv->raw_link_id, txpriv->tid);
		tx_policy_put(wvif, txpriv->rate_id);
	}
	ieee80211_tx_status(wdev->hw, skb);
}


