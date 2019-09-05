/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Datapath implementation.
 *
 * Copyright (c) 2017-2019, Silicon Laboratories, Inc.
 * Copyright (c) 2010, ST-Ericsson
 */
#ifndef WFX_DATA_TX_H
#define WFX_DATA_TX_H

#include <linux/list.h>

#include "api_wsm_cmd.h"

struct wfx_tx_priv;
struct wfx_dev;
struct wfx_vif;

struct wfx_tx_priv {
	ktime_t xmit_timestamp;
	struct ieee80211_key_conf *hw_key;
	uint8_t link_id;
	uint8_t raw_link_id;
	uint8_t tid;
} __packed;

struct tx_policy {
	struct list_head link;
	uint8_t rates[12];
	uint8_t usage_count;
	uint8_t uploaded;
};

struct tx_policy_cache {
	struct tx_policy cache[WSM_MIB_NUM_TX_RATE_RETRY_POLICIES];
	// FIXME: use a trees and drop hash from tx_policy
	struct list_head used;
	struct list_head free;
	spinlock_t lock;
};

struct wfx_ht_info {
	struct ieee80211_sta_ht_cap ht_cap;
	enum nl80211_channel_type channel_type;
	uint16_t operation_mode;
};

void tx_policy_init(struct wfx_vif *wvif);
void tx_policy_upload_work(struct work_struct *work);

void wfx_tx(struct ieee80211_hw *hw, struct ieee80211_tx_control *control,
	    struct sk_buff *skb);
void wfx_tx_confirm_cb(struct wfx_vif *wvif, struct hif_cnf_tx *arg);
void wfx_skb_dtor(struct wfx_dev *wdev, struct sk_buff *skb);

void wfx_link_id_work(struct work_struct *work);
void wfx_link_id_gc_work(struct work_struct *work);
int wfx_find_link_id(struct wfx_vif *wvif, const u8 *mac);

static inline struct wfx_tx_priv *wfx_skb_tx_priv(struct sk_buff *skb)
{
	struct ieee80211_tx_info *tx_info;

	if (!skb)
		return NULL;
	tx_info = IEEE80211_SKB_CB(skb);
	return (struct wfx_tx_priv *) tx_info->rate_driver_data;
}

static inline struct hif_req_tx *wfx_skb_txreq(struct sk_buff *skb)
{
	struct hif_msg *hdr = (struct hif_msg *) skb->data;
	return (struct hif_req_tx *) hdr->body;
}

static inline int wfx_is_ht(const struct wfx_ht_info *ht_info)
{
	return ht_info->channel_type != NL80211_CHAN_NO_HT;
}

static inline int wfx_ht_greenfield(const struct wfx_ht_info *ht_info)
{
	return wfx_is_ht(ht_info) &&
		(ht_info->ht_cap.cap & IEEE80211_HT_CAP_GRN_FLD) &&
		!(ht_info->operation_mode &
		  IEEE80211_HT_OP_MODE_NON_GF_STA_PRSNT);
}

static inline int wfx_ht_fecCoding(const struct wfx_ht_info *ht_info)
{
	return wfx_is_ht(ht_info) &&
	       (ht_info->ht_cap.cap & IEEE80211_HT_CAP_LDPC_CODING);
}

static inline int wfx_ht_shortGi(const struct wfx_ht_info *ht_info)
{
	return wfx_is_ht(ht_info) &&
	       (ht_info->ht_cap.cap & IEEE80211_HT_CAP_SGI_20);
}

static inline int wfx_ht_ampdu_density(const struct wfx_ht_info *ht_info)
{
	if (!wfx_is_ht(ht_info))
		return 0;
	return ht_info->ht_cap.ampdu_density;
}

#endif /* WFX_DATA_TX_H */
