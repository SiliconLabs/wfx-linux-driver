/*
 * Datapath implementation for Silicon Labs WFX mac80211 drivers
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

#include "data_txrx.h"
#include "wfx.h"
#include "wsm.h"
#include "bh.h"
#include "sta.h"
#include "debug.h"

#define WF200_INVALID_RATE_ID (0xFF)

static int wfx_handle_action_rx(struct wfx_dev *wdev,
				   struct sk_buff *skb);
static const struct ieee80211_rate *
wfx_get_tx_rate(const struct wfx_dev		*wdev,
		   const struct ieee80211_tx_rate *rate);

/* ******************************************************************** */
/* TX queue lock / unlock						*/

static inline void wfx_tx_queues_lock(struct wfx_dev *wdev)
{
	int i;
	for (i = 0; i < 4; ++i)
		wfx_queue_lock(&wdev->tx_queue[i]);
}

static inline void wfx_tx_queues_unlock(struct wfx_dev *wdev)
{
	int i;
	for (i = 0; i < 4; ++i)
		wfx_queue_unlock(&wdev->tx_queue[i]);
}

/* ******************************************************************** */
/* TX policy cache implementation					*/

static void tx_policy_dump(struct tx_policy *policy)
{
	pr_debug("[TX policy] %.1X%.1X%.1X%.1X%.1X%.1X%.1X%.1X %.1X%.1X%.1X%.1X%.1X%.1X%.1X%.1X %.1X%.1X%.1X%.1X%.1X%.1X%.1X%.1X: %d\n",
		 policy->raw[0] & 0x0F,  policy->raw[0] >> 4,
		 policy->raw[1] & 0x0F,  policy->raw[1] >> 4,
		 policy->raw[2] & 0x0F,  policy->raw[2] >> 4,
		 policy->raw[3] & 0x0F,  policy->raw[3] >> 4,
		 policy->raw[4] & 0x0F,  policy->raw[4] >> 4,
		 policy->raw[5] & 0x0F,  policy->raw[5] >> 4,
		 policy->raw[6] & 0x0F,  policy->raw[6] >> 4,
		 policy->raw[7] & 0x0F,  policy->raw[7] >> 4,
		 policy->raw[8] & 0x0F,  policy->raw[8] >> 4,
		 policy->raw[9] & 0x0F,  policy->raw[9] >> 4,
		 policy->raw[10] & 0x0F,  policy->raw[10] >> 4,
		 policy->raw[11] & 0x0F,  policy->raw[11] >> 4,
		 policy->defined);
}

static void tx_policy_build(const struct wfx_dev *wdev,
			    struct tx_policy *policy,
	struct ieee80211_tx_rate *rates, size_t count)
{
	int i, j;
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

	policy->defined = wfx_get_tx_rate(wdev, &rates[0])->hw_value + 1;

	for (i = 0; i < count; ++i) {
		register unsigned rateid, off, shift, retries;

		rateid = wfx_get_tx_rate(wdev, &rates[i])->hw_value;
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

static inline bool tx_policy_is_equal(const struct tx_policy *wanted,
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

static inline void tx_policy_use(struct tx_policy_cache *cache,
				 struct tx_policy_cache_entry *entry)
{
	++entry->policy.usage_count;
	list_move(&entry->link, &cache->used);
}

static inline int tx_policy_release(struct tx_policy_cache *cache,
				    struct tx_policy_cache_entry *entry)
{
	int ret = --entry->policy.usage_count;
	if (!ret)
		list_move(&entry->link, &cache->free);
	return ret;
}

void tx_policy_clean(struct wfx_dev *wdev)
{
	int idx, locked;
	struct tx_policy_cache *cache = &wdev->tx_policy_cache;
	struct tx_policy_cache_entry *entry;

	wfx_tx_queues_lock(wdev);
	spin_lock_bh(&cache->lock);
	locked = list_empty(&cache->free);

	for (idx = 0; idx < TX_POLICY_CACHE_SIZE; idx++) {
		entry = &cache->cache[idx];
		/* Policy usage count should be 0 at this time as all queues
		   should be empty
		 */
		if (WARN_ON(entry->policy.usage_count)) {
			entry->policy.usage_count = 0;
			list_move(&entry->link, &cache->free);
		}
		memset(&entry->policy, 0, sizeof(entry->policy));
	}
	if (locked)
		wfx_tx_queues_unlock(wdev);

	wfx_tx_queues_unlock(wdev);
	spin_unlock_bh(&cache->lock);
}

/* ******************************************************************** */
/* External TX policy cache API						*/

void tx_policy_init(struct wfx_dev *wdev)
{
	struct tx_policy_cache *cache = &wdev->tx_policy_cache;
	int i;

	memset(cache, 0, sizeof(*cache));

	spin_lock_init(&cache->lock);
	INIT_LIST_HEAD(&cache->used);
	INIT_LIST_HEAD(&cache->free);

	for (i = 0; i < TX_POLICY_CACHE_SIZE; ++i)
		list_add(&cache->cache[i].link, &cache->free);
}

static int tx_policy_get(struct wfx_dev *wdev,
		  struct ieee80211_tx_rate *rates,
		  size_t count, bool *renew)
{
	int idx;
	struct tx_policy_cache *cache = &wdev->tx_policy_cache;
	struct tx_policy wanted;

	tx_policy_build(wdev, &wanted, rates, count);

	spin_lock_bh(&cache->lock);
	if (WARN_ON_ONCE(list_empty(&cache->free))) {
		spin_unlock_bh(&cache->lock);
		return WF200_INVALID_RATE_ID;
	}
	idx = tx_policy_find(cache, &wanted);
	if (idx >= 0) {
		pr_debug("[TX policy] Used TX policy: %d\n", idx);
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
		pr_debug("[TX policy] New TX policy: %d\n", idx);
		tx_policy_dump(&entry->policy);
	}
	tx_policy_use(cache, &cache->cache[idx]);
	if (list_empty(&cache->free)) {
		/* Lock TX queues. */
		wfx_tx_queues_lock(wdev);
	}
	spin_unlock_bh(&cache->lock);
	return idx;
}

static void tx_policy_put(struct wfx_dev *wdev, int idx)
{
	int usage, locked;
	struct tx_policy_cache *cache = &wdev->tx_policy_cache;

	spin_lock_bh(&cache->lock);
	locked = list_empty(&cache->free);
	usage = tx_policy_release(cache, &cache->cache[idx]);
	if (locked && !usage) {
		/* Unlock TX queues. */
		wfx_tx_queues_unlock(wdev);
	}
	spin_unlock_bh(&cache->lock);
}

static int tx_policy_upload(struct wfx_dev *wdev)
{
	struct tx_policy_cache *cache = &wdev->tx_policy_cache;
	int i;
	WsmHiMibSetTxRateRetryPolicy_t arg = {
		.NumTxRatePolicy	= 0,
	};

	spin_lock_bh(&cache->lock);

	/* Upload only modified entries. */
	for (i = 0; i < TX_POLICY_CACHE_SIZE; ++i) {
		struct tx_policy *src = &cache->cache[i].policy;

		if (src->retry_count && !src->uploaded) {
			WsmHiMibTxRateRetryPolicy_t *dst =
				&arg.TxRateRetryPolicy + arg.NumTxRatePolicy *
				sizeof(WsmHiMibTxRateRetryPolicy_t);

			dst->PolicyIndex = i;
			dst->ShortRetryCount = wdev->short_frame_max_tx_count;
			dst->LongRetryCount = wdev->long_frame_max_tx_count;

			/* dst->flags = WSM_TX_RATE_POLICY_FLAG_TERMINATE_WHEN_FINISHED |
			 *  WSM_TX_RATE_POLICY_FLAG_COUNT_INITIAL_TRANSMIT;
			 */
			dst->Terminate = 1;
			dst->CountInit = 1;
			memcpy(&dst->RateCountIndices0700, src->tbl,
			       sizeof(src->tbl));
			src->uploaded = 1;
			++arg.NumTxRatePolicy;
		}
	}
	spin_unlock_bh(&cache->lock);
	wfx_debug_tx_cache_miss(wdev);
	pr_debug("[TX policy] Upload %d policies\n", arg.NumTxRatePolicy);
	return wsm_set_tx_rate_retry_policy(wdev, &arg, -1);
}

void tx_policy_upload_work(struct work_struct *work)
{
	struct wfx_dev *wdev =
		container_of(work, struct wfx_dev, tx_policy_upload_work);

	pr_debug("[TX] TX policy upload.\n");
	tx_policy_upload(wdev);

	wsm_unlock_tx(wdev);
	wfx_tx_queues_unlock(wdev);
}

/* ******************************************************************** */
/* wfx TX implementation						*/

struct wfx_txinfo {
	struct sk_buff *skb;
	unsigned queue;
	struct ieee80211_tx_info *tx_info;
	const struct ieee80211_rate *rate;
	struct ieee80211_hdr *hdr;
	size_t hdrlen;
	const u8 *da;
	struct wfx_sta_priv *sta_priv;
	struct ieee80211_sta *sta;
	struct wfx_txpriv txpriv;
};

/* Send map request message to firmware and save peer MAC address */
int wfx_map_link(struct wfx_vif		*wvif,
		 struct wfx_link_entry		*link_entry,
		 int sta_id)
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

u32 wfx_rate_mask_to_wsm(struct wfx_dev *wdev, u32 rates)
{
	u32 ret = 0;
	int i;

	for (i = 0; i < 32; ++i) {
		if (rates & BIT(i))
			ret |= BIT(wdev->rates[i].hw_value);
	}
	return ret;
}

static const struct ieee80211_rate *
wfx_get_tx_rate(const struct wfx_dev		*wdev,
		   const struct ieee80211_tx_rate *rate)
{
	if (rate->idx < 0)
		return NULL;
	if (rate->flags & IEEE80211_TX_RC_MCS)
		return &wdev->mcs_rates[rate->idx];
	return &wdev->hw->wiphy->bands[wdev->channel->band]->bitrates[rate->idx];
}

static int
wfx_tx_h_calc_link_ids(struct wfx_vif	*wvif,
			  struct wfx_txinfo *t)
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
			wiphy_err(wvif->wdev->hw->wiphy,
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

static void
wfx_tx_h_pm(struct wfx_vif	*wvif,
	       struct wfx_txinfo *t)
{
	if (ieee80211_is_auth(t->hdr->frame_control)) {
		u32 mask = ~BIT(t->txpriv.raw_link_id);
		spin_lock_bh(&wvif->ps_state_lock);
		wvif->sta_asleep_mask &= mask;
		wvif->pspoll_mask &= mask;
		spin_unlock_bh(&wvif->ps_state_lock);
	}
}

static void
wfx_tx_h_calc_tid(struct wfx_vif	*wvif,
		     struct wfx_txinfo *t)
{
	if (ieee80211_is_data_qos(t->hdr->frame_control)) {
		u8 *qos = ieee80211_get_qos_ctl(t->hdr);
		t->txpriv.tid = qos[0] & IEEE80211_QOS_CTL_TID_MASK;
	} else if (ieee80211_is_data(t->hdr->frame_control)) {
		t->txpriv.tid = 0;
	}
}

static int
wfx_tx_h_crypt(struct wfx_vif	*wvif,
		  struct wfx_txinfo *t)
{
	if (!t->tx_info->control.hw_key ||
	    !ieee80211_has_protected(t->hdr->frame_control))
		return 0;

	t->hdrlen += t->tx_info->control.hw_key->iv_len;
	skb_put(t->skb, t->tx_info->control.hw_key->icv_len);

	if (t->tx_info->control.hw_key->cipher == WLAN_CIPHER_SUITE_TKIP)
		skb_put(t->skb, 8); /* MIC space */

	return 0;
}

static int
wfx_tx_h_align(struct wfx_vif	*wvif,
		  struct wfx_txinfo *t,
	       WsmHiTxFlags_t		*flags)
{
	size_t offset = (size_t)t->skb->data & 3;

	if (!offset)
		return 0;

	if (offset & 1) {
		wiphy_err(wvif->wdev->hw->wiphy,
			  "Bug: attempt to transmit a frame with wrong alignment: %zu\n",
			  offset);
		return -EINVAL;
	}

	if (skb_headroom(t->skb) < offset) {
		wiphy_err(wvif->wdev->hw->wiphy,
			  "Bug: no space allocated for DMA alignment. headroom: %d\n",
			  skb_headroom(t->skb));
		return -ENOMEM;
	}
	skb_push(t->skb, offset);
	t->hdrlen += offset;
	t->txpriv.offset += offset;
	flags->Offset = 1;
	wfx_debug_tx_align(wvif->wdev);
	return 0;
}

static int
wfx_tx_h_action(struct wfx_vif	*wvif,
		   struct wfx_txinfo *t)
{
	struct ieee80211_mgmt *mgmt =
		(struct ieee80211_mgmt *)t->hdr;
	if (ieee80211_is_action(t->hdr->frame_control) &&
	    mgmt->u.action.category == WLAN_CATEGORY_BACK)
		return 1;
	else
		return 0;
}

/* Add WSM header */
static WsmHiTxReq_t *
wfx_tx_h_wsm(struct wfx_vif	*wvif,
		struct wfx_txinfo *t)
{
	WsmHiTxReq_t *wsm;
	uint32_t wsm_length = sizeof(WsmHiTxReq_t) - sizeof(uint32_t);

	if (WARN(skb_headroom(t->skb) < wsm_length, "Not enough space for WSM headers"))
		return NULL;
	if (t->skb->len > wvif->wdev->wsm_caps.SizeInpChBuf) {
		dev_info(wvif->wdev->pdev, "Requested frame size (%d) is larger than maximum supported (%d)\n",
			 t->skb->len, wvif->wdev->wsm_caps.SizeInpChBuf);
		return NULL;
	}

	wsm = (WsmHiTxReq_t *)skb_push(t->skb, wsm_length);
	t->txpriv.offset += wsm_length;
	memset(wsm, 0, wsm_length);
	wsm->Header.MsgLen = cpu_to_le16(t->skb->len);
	wsm->Header.s.t.MsgId = cpu_to_le16(WSM_HI_TX_REQ_ID);
	wsm->Header.s.b.IntId = t->txpriv.vif_id;
	wsm->Body.QueueId.PerStaId = t->txpriv.raw_link_id;
	wsm->Body.QueueId.QueueId = wsm_queue_id_to_wsm(t->queue);
	return wsm;
}

static int
wfx_tx_h_rate_policy(struct wfx_dev	*wdev,
			struct wfx_txinfo *t,
		     WsmHiTxReq_t	*wsm)
{
	bool tx_policy_renew = false;
	struct ieee80211_bss_conf *conf = &wdev->vif->bss_conf;

	t->txpriv.rate_id = tx_policy_get(wdev,
		t->tx_info->control.rates, IEEE80211_TX_MAX_RATES,
		&tx_policy_renew);
	if (t->txpriv.rate_id == WF200_INVALID_RATE_ID)
		return -EFAULT;

	wsm->Body.TxFlags.Txrate = t->txpriv.rate_id;

	t->rate = wfx_get_tx_rate(wdev,
		&t->tx_info->control.rates[0]),
	wsm->Body.MaxTxRate = t->rate->hw_value;
	// correct the max TX rate if needed when using the IBSS mode
	if ((conf->ibss_joined) && (wsm->Body.MaxTxRate == 0))
		wsm->Body.MaxTxRate = 10; // 24M

	/* HT rate
	 * mac80211_rate_control_flags: IEEE80211_TX_RC_MCS
	 */
#if 0
	/* IEEE80211_TX_RC_MCS flag is controlled by mac80211
	 * rate index is an HT MCS instead of an index
	 */
	if (t->rate->flags & IEEE80211_TX_RC_MCS) {
		if (wfx_ht_greenfield(&wvif->ht_info))
			wsm->ht_tx_parameters |=
				cpu_to_le32(WSM_FRAME_FORMAT_GF_HT_11N);
		else
			wsm->ht_tx_parameters |=
				cpu_to_le32(WSM_FRAME_FORMAT_MIXED_FORMAT_HT);
	}
#else
	/* IEEE80211_TX_RC_GREEN_FIELD flag is controlled by mac80211
	 * Indicates whether this rate should be used in Greenfield mode.
	 *
	 * Bit 3 to 0: 0(no-HT), 1(Mixed format), 2 (Greenfield format), other
	 */
	if (t->rate->flags & IEEE80211_TX_RC_GREEN_FIELD)
		wsm->Body.HtTxParameters.FrameFormat =
			WSM_FRAME_FORMAT_GF_HT_11N;
	else
		/*HT mixed is used*/
		wsm->Body.HtTxParameters.FrameFormat =
			WSM_FRAME_FORMAT_MIXED_FORMAT_HT;

#endif

	/* Short GI
	 * mac80211_rate_control_flags: IEEE80211_TX_RC_SHORT_GI
	 *
	 *
	 * IEEE80211_TX_RC_SHORT_GI flag is controlled by mac80211,
	 * Short Guard interval should be used for this rate.
	 * or set from userland CLI configuration utility.
	 *
	 * Bit 5: 0 (lgi), 1 (sgi)
	 */
	if (t->rate->flags & IEEE80211_TX_RC_SHORT_GI || wfx_ht_shortGi(&wdev->ht_info))
		wsm->Body.HtTxParameters.ShortGi = 1;

	/* LDPC (Low-Density Parity-Check code)
	 * mac80211_tx_info_flags : IEEE80211_TX_CTL_LDPC
	 *
	 * IEEE80211_TX_CTL_LDPC flag is controlled by mac80211
	 * tells the driver to use LDPC for this frame
	 *
	 * Bit 4: 0 (BCC), 1(LDPC)
	 */
	if (t->tx_info->flags & IEEE80211_TX_CTL_LDPC || wfx_ht_fecCoding(&wdev->ht_info))
		if (wdev->pdata.support_ldpc)
			wsm->Body.HtTxParameters.FecCoding = 1;

	/* Transmit STBC (Space-Time Block Coding)
	 *
	 * WFx driver supports only STBC Rx.
	 * IEEE80211_TX_CTL_STBC should not be set
	 */

	if (tx_policy_renew) {
		pr_debug("[TX] TX policy renew.\n");
		/* It's not so optimal to stop TX queues every now and then.
		 * Better to reimplement task scheduling with
		 * a counter. TODO.
		 */
		wsm_lock_tx_async(wdev);
		wfx_tx_queues_lock(wdev);
		if (queue_work(wdev->workqueue,
			       &wdev->tx_policy_upload_work) <= 0) {
			wfx_tx_queues_unlock(wdev);
			wsm_unlock_tx(wdev);
		}
	}
	return 0;
}

static bool
wfx_tx_h_pm_state(struct wfx_vif	*wvif,
		     struct wfx_txinfo *t)
{
	int was_buffered = 1;

	if (t->txpriv.link_id == WFX_LINK_ID_AFTER_DTIM &&
	    !wvif->buffered_multicasts) {
		wvif->buffered_multicasts = true;
		if (wvif->sta_asleep_mask)
			queue_work(wvif->wdev->workqueue,
				   &wvif->multicast_start_work);
	}

	if (t->txpriv.raw_link_id && t->txpriv.tid < WFX_MAX_TID)
		was_buffered = wvif->link_id_db[t->txpriv.raw_link_id - 1].buffered[t->txpriv.tid]++;

	return !was_buffered;
}

/* ******************************************************************** */

void wfx_tx(struct ieee80211_hw *dev,
	       struct ieee80211_tx_control *control,
	       struct sk_buff *skb)
{
	struct wfx_dev *wdev = dev->priv;
	struct wfx_vif *wvif;
	struct wfx_txinfo t = {
		.skb = skb,
		.queue = skb_get_queue_mapping(skb),
		.tx_info = IEEE80211_SKB_CB(skb),
		.hdr = (struct ieee80211_hdr *)skb->data,
		.txpriv.tid = WFX_MAX_TID,
		.txpriv.rate_id = WF200_INVALID_RATE_ID,
	};
	struct ieee80211_sta *sta;
	WsmHiTxReq_t *wsm;
	bool tid_update = 0;
	WsmHiTxFlags_t flags = { };
	int ret;

	if (wdev->bh_error)
		goto drop;

	// control.vif can be NULL for injected frames
	if (IEEE80211_SKB_CB(skb)->control.vif)
		wvif = (struct wfx_vif *) IEEE80211_SKB_CB(skb)->control.vif->drv_priv;
	else
		wvif = wdev_to_wvif(wdev, 0);

	t.txpriv.vif_id = wvif->Id;
	t.hdrlen = ieee80211_hdrlen(t.hdr->frame_control);
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

	pr_debug("[TX] TX %d bytes (queue: %d, link_id: %d(raw_link_id=%d)).\n",
		 skb->len, t.queue, t.txpriv.link_id,
		 t.txpriv.raw_link_id);

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
	wsm->Body.TxFlags = flags;
	ret = wfx_tx_h_rate_policy(wdev, &t, wsm);
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

	wfx_bh_wakeup(wdev);

	return;

drop:
	wfx_skb_dtor(wdev, skb, &t.txpriv);
}

/* ******************************************************************** */

static int wfx_handle_action_rx(struct wfx_dev	*wdev,
				   struct sk_buff *skb)
{
	struct ieee80211_mgmt *mgmt = (void *)skb->data;

	/* Filter block ACK negotiation: fully controlled by firmware */
	if (mgmt->u.action.category == WLAN_CATEGORY_BACK)
		return 1;

	return 0;
}

static int wfx_handle_pspoll(struct wfx_vif	*wvif,
				struct sk_buff *skb)
{
	struct ieee80211_sta *sta;
	struct ieee80211_pspoll *pspoll = (struct ieee80211_pspoll *)skb->data;
	int link_id = 0;
	u32 pspoll_mask = 0;
	int drop = 1;
	int i;

	if (wvif->join_status != WFX_JOIN_STATUS_AP)
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
		if (wfx_queue_get_num_queued(&wvif->wdev->tx_queue[i],
						pspoll_mask)) {
			wfx_bh_wakeup(wvif->wdev);
			drop = 1;
			break;
		}
	}
	pr_debug("[RX] PSPOLL: %s\n", drop ? "local" : "fwd");
done:
	return drop;
}

/* ******************************************************************** */

void wfx_tx_confirm_cb(struct wfx_dev	*wdev,
		       WsmHiTxCnfBody_t		*arg)
{
	struct wfx_vif *wvif;
	u8 queue_id = wfx_queue_get_queue_id(arg->PacketId);
	struct wfx_queue *queue = &wdev->tx_queue[queue_id];
	struct sk_buff *skb;
	const struct wfx_txpriv *txpriv;
	int ret;

	ret = wfx_queue_get_skb(queue, arg->PacketId, &skb, &txpriv);
	if (ret) {
		dev_warn(wdev->pdev, "Received unknown packet_id (%#.8x) from chip\n", arg->PacketId);
		return;
	}

	wvif = wdev_to_wvif(wdev, txpriv->vif_id);

	if (wvif->mode == NL80211_IFTYPE_UNSPECIFIED) {
		/* STA is stopped. */
		return;
	}

	if (arg->Status == WSM_REQUEUE) {
		/* "Requeue" means "implicit suspend" */
		WsmHiSuspendResumeTxIndBody_t suspend = {
			.SuspendResumeFlags.ResumeOrSuspend	= 0,
			.SuspendResumeFlags.CastType		= 1,
		};

		WARN(!arg->TxResultFlags.Requeue, "Incoherent Status and ResultFlags");

		wfx_suspend_resume(wdev, &suspend);
		dev_dbg(wdev->pdev, "Requeuing for station %d (try %d). STAs asleep: 0x%.8X.\n",
			   txpriv->link_id, wfx_queue_get_generation(arg->PacketId) + 1,
			   wvif->sta_asleep_mask);
		wfx_queue_requeue(queue, arg->PacketId);
		if (!txpriv->link_id) { // Is multicast?
			spin_lock_bh(&wvif->ps_state_lock);
			wvif->buffered_multicasts = true;
			if (wvif->sta_asleep_mask)
				queue_work(wdev->workqueue, &wvif->multicast_start_work);
			spin_unlock_bh(&wvif->ps_state_lock);
		}
	} else {
		struct ieee80211_tx_info *tx = IEEE80211_SKB_CB(skb);
		int tx_count = arg->AckFailures;
		u8 ht_flags = 0;
		int i;

		if (wfx_ht_greenfield(&wdev->ht_info))
			ht_flags |= IEEE80211_TX_RC_GREEN_FIELD;

		if (wfx_ht_fecCoding(&wdev->ht_info))
			ht_flags |= IEEE80211_TX_CTL_LDPC;

		if (wfx_ht_shortGi(&wdev->ht_info))
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
			tx->flags |= IEEE80211_TX_STAT_ACK;
			++tx_count;
			wfx_debug_txed(wdev);
			if (arg->TxResultFlags.Aggr) {
				/* Do not report aggregation to mac80211:
				 * it confuses minstrel a lot.
				 */
				/* tx->flags |= IEEE80211_TX_STAT_AMPDU; */
				wfx_debug_txed_agg(wdev);
			}
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
	/* XXX TODO:  Only wake if there are pending transmits.. */
	wfx_bh_wakeup(wdev);
}

static void wfx_notify_buffered_tx(struct wfx_vif *wvif,
			       struct sk_buff *skb, int link_id, int tid)
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
			dev_err(wvif->wdev->pdev, "wfx_notify_buffered_tx: inconsistent tid (%d)\n", tid);
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

void wfx_skb_dtor(struct wfx_dev		*wdev,
		     struct sk_buff *skb,
		     const struct wfx_txpriv *txpriv)
{
	struct wfx_vif *wvif = wdev_to_wvif(wdev, txpriv->vif_id);

	skb_pull(skb, txpriv->offset);
	if (txpriv->rate_id != WF200_INVALID_RATE_ID) {
		wfx_notify_buffered_tx(wvif, skb,
					  txpriv->raw_link_id, txpriv->tid);
		tx_policy_put(wdev, txpriv->rate_id);
	}
	ieee80211_tx_status(wdev->hw, skb);
}

void wfx_rx_cb(struct wfx_vif	*wvif,
	       WsmHiRxIndBody_t		*arg,
		  int link_id,
		  struct sk_buff **skb_p)
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

	if (wvif->mode == NL80211_IFTYPE_UNSPECIFIED)
		/* STA is stopped. */
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
		WARN_ON(work_pending(&wvif->linkid_reset_work));
		ether_addr_copy(&wvif->action_frame_sa[0], ieee80211_get_SA(frame));
		wvif->action_linkid = 0;
		schedule_work(&wvif->linkid_reset_work);
	}

	if (link_id && p2p &&
	    ieee80211_is_action(frame->frame_control) &&
	    (mgmt->u.action.category == WLAN_CATEGORY_PUBLIC)) {
		/* Link ID already exists for the ACTION frame.
		 * Reset and Remap
		 */
		WARN_ON(work_pending(&wvif->linkid_reset_work));
		ether_addr_copy(&wvif->action_frame_sa[0], ieee80211_get_SA(frame));
		wvif->action_linkid = link_id;
		schedule_work(&wvif->linkid_reset_work);
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
		wiphy_warn(wvif->wdev->hw->wiphy, "Mailformed SDU rx'ed. Size is lesser than IEEE header.\n");
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
#if (KERNEL_VERSION(4, 12, 0) <= LINUX_VERSION_CODE)
		hdr->encoding = RX_ENC_HT;
#else
		hdr->flag |= RX_FLAG_HT;
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
			dev_err(wvif->wdev->pdev, "Unknown encryption type %d\n",
				 arg->RxFlags.Encryp);
			goto drop;
		}

		/* Firmware strips ICV in case of MIC failure. */
		if (arg->Status == WSM_STATUS_MICFAILURE)
			icv_len = 0;

		if (skb->len < hdrlen + iv_len + icv_len) {
			wiphy_warn(wvif->wdev->hw->wiphy, "Malformed SDU rx'ed. Size is lesser than crypto headers.\n");
			goto drop;
		}

		/* Remove IV, ICV and MIC */
		skb_trim(skb, skb->len - icv_len);
		memmove(skb->data + iv_len, skb->data, hdrlen);
		skb_pull(skb, iv_len);
	}

	/* Remove TSF from the end of frame */
	if (arg->RxFlags.Timestamp) {
		memcpy(&hdr->mactime, skb->data + skb->len - 8, 8);
		hdr->mactime = le64_to_cpu(hdr->mactime);
		if (skb->len >= 8)
			skb_trim(skb, skb->len - 8);
	} else {
		hdr->mactime = 0;
	}

	wfx_debug_rxed(wvif->wdev);
	if (arg->RxFlags.InAggr)
		wfx_debug_rxed_agg(wvif->wdev);

	if (ieee80211_is_action(frame->frame_control) &&
	    (arg->RxFlags.MatchStationid)) {
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

			if (wvif->join_dtim_period != tim->dtim_period) {
				wvif->join_dtim_period = tim->dtim_period;
				queue_work(wvif->wdev->workqueue,
					   &wvif->set_beacon_wakeup_period_work);
			}
		}

		/* Disable beacon filter once we're associated... */
		if (wvif->disable_beacon_filter &&
		    (wvif->vif->bss_conf.assoc ||
		     wvif->vif->bss_conf.ibss_joined)) {
			wvif->disable_beacon_filter = false;
			queue_work(wvif->wdev->workqueue,
				   &wvif->update_filtering_work);
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

/* ******************************************************************** */
/* Security								*/

int wfx_alloc_key(struct wfx_dev *wdev)
{
	int idx;

	idx = ffs(~wdev->key_map) - 1;
	if (idx < 0 || idx > WSM_KEY_MAX_INDEX)
		return -1;

	wdev->key_map |= BIT(idx);
	wdev->keys[idx].EntryIndex = idx;
	return idx;
}

void wfx_free_key(struct wfx_dev *wdev, int idx)
{
	BUG_ON(!(wdev->key_map & BIT(idx)));
	memset(&wdev->keys[idx], 0, sizeof(wdev->keys[idx]));
	wdev->key_map &= ~BIT(idx);
}

void wfx_free_keys(struct wfx_dev *wdev)
{
	memset(&wdev->keys, 0, sizeof(wdev->keys));
	wdev->key_map = 0;
}

int wfx_upload_keys(struct wfx_vif *wvif)
{
	int idx, ret = 0;

	for (idx = 0; idx <= WSM_KEY_MAX_INDEX; ++idx)
		if (wvif->wdev->key_map & BIT(idx)) {
			ret = wsm_add_key(wvif->wdev, &wvif->wdev->keys[idx], wvif->Id);
			if (ret < 0)
				break;
		}
	return ret;
}

/* Workaround for WFD test case 6.1.10 */
void wfx_link_id_reset(struct work_struct *work)
{
	struct wfx_vif *wvif =
		container_of(work, struct wfx_vif, linkid_reset_work);
	int temp_linkid;

	if (!wvif->action_linkid) {
		/* In GO mode we can receive ACTION frames without a linkID */
		temp_linkid = wfx_alloc_link_id(wvif,
						&wvif->action_frame_sa[0]);
		WARN_ON(!temp_linkid);
		if (temp_linkid) {
			/* Make sure we execute the WQ */
			flush_workqueue(wvif->wdev->workqueue);
			/* Release the link ID */
			spin_lock_bh(&wvif->ps_state_lock);
			wvif->link_id_db[temp_linkid - 1].prev_status =
				wvif->link_id_db[temp_linkid - 1].status;
			wvif->link_id_db[temp_linkid - 1].status =
				WFX_LINK_RESET;
			spin_unlock_bh(&wvif->ps_state_lock);
			wsm_lock_tx_async(wvif->wdev);
			if (queue_work(wvif->wdev->workqueue,
				       &wvif->link_id_work) <= 0)
				wsm_unlock_tx(wvif->wdev);
		}
	} else {
		spin_lock_bh(&wvif->ps_state_lock);
		wvif->link_id_db[wvif->action_linkid - 1].prev_status =
			wvif->link_id_db[wvif->action_linkid - 1].status;
		wvif->link_id_db[wvif->action_linkid - 1].status =
			WFX_LINK_RESET_REMAP;
		spin_unlock_bh(&wvif->ps_state_lock);
		wsm_lock_tx_async(wvif->wdev);
		if (queue_work(wvif->wdev->workqueue, &wvif->link_id_work) <= 0)
			wsm_unlock_tx(wvif->wdev);
		flush_workqueue(wvif->wdev->workqueue);
	}
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

int wfx_alloc_link_id(struct wfx_vif *wvif, const u8 *mac)
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
		wsm_lock_tx_async(wvif->wdev);

		if (queue_work(wvif->wdev->workqueue, &wvif->link_id_work) <= 0)
			wsm_unlock_tx(wvif->wdev);
	} else {
		wiphy_info(wvif->wdev->hw->wiphy,
			   "[AP] Early: no more link IDs available.\n");
	}
	spin_unlock_bh(&wvif->ps_state_lock);
	return ret;
}

void wfx_link_id_work(struct work_struct *work)
{
	struct wfx_vif *wvif =
		container_of(work, struct wfx_vif, link_id_work);

	wsm_flush_tx(wvif->wdev);
	wfx_link_id_gc_work(&wvif->link_id_gc_work.work);
	wsm_unlock_tx(wvif->wdev);
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

	if (wvif->join_status != WFX_JOIN_STATUS_AP)
		return;

	wsm_lock_tx(wvif->wdev);
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
		queue_delayed_work(wvif->wdev->workqueue,
				   &wvif->link_id_gc_work, next_gc);
	wsm_unlock_tx(wvif->wdev);
}
