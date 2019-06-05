// SPDX-License-Identifier: GPL-2.0-only
/*
 * Datapath implementation.
 *
 * Copyright (c) 2017-2019, Silicon Laboratories, Inc.
 * Copyright (c) 2010, ST-Ericsson
 */
#ifndef WFX_DATA_TXRX_H
#define WFX_DATA_TXRX_H

#include <linux/list.h>

#include "wsm_cmd_api.h"

/* extern */ struct wfx_txpriv;
/* extern */ struct wfx_dev;
/* extern */ struct wfx_vif;

struct tx_policy {
	union {
		__le32 tbl[3];
		u8 raw[12];
	};
	u8  defined;
	u8  usage_count;
	u8  retry_count;
	u8  uploaded;
};

struct tx_policy_cache_entry {
	struct tx_policy policy;
	struct list_head link;
};

struct tx_policy_cache {
	struct tx_policy_cache_entry cache[WSM_MIB_NUM_TX_RATE_RETRY_POLICIES];
	struct list_head used;
	struct list_head free;
	spinlock_t lock; /* Protect policy cache */
};

/* ******************************************************************** */
/* TX policy cache							*/
/* Intention of TX policy cache is an overcomplicated WSM API.
 * Device does not accept per-PDU tx retry sequence.
 * It uses "tx retry policy id" instead, so driver code has to sync
 * linux tx retry sequences with a retry policy table in the device.
 */
void tx_policy_init(struct wfx_vif *wvif);
void tx_policy_clean(struct wfx_vif *wvif);
void tx_policy_upload_work(struct work_struct *work);

/* ******************************************************************** */
/* TX implementation							*/

u32 wfx_rate_mask_to_wsm(struct wfx_dev *wdev,
			       u32 rates);
void wfx_tx(struct ieee80211_hw *hw,
	       struct ieee80211_tx_control *control,
	       struct sk_buff *skb);
void wfx_skb_dtor(struct wfx_dev *wdev,
		     struct sk_buff *skb,
		     const struct wfx_txpriv *txpriv);

/* ******************************************************************** */
/* WSM callbacks							*/

void wfx_tx_confirm_cb(struct wfx_dev *wdev,
			  WsmHiTxCnfBody_t *arg);
void wfx_rx_cb(struct wfx_vif *wvif,
		  WsmHiRxIndBody_t *arg,
		  int link_id,
		  struct sk_buff **skb_p);

/* ******************************************************************** */
/* Workaround for WFD test case 6.1.10					*/
#define WFX_LINK_ID_GC_TIMEOUT ((unsigned long)(10 * HZ))
void wfx_link_id_work(struct work_struct *work);
void wfx_link_id_gc_work(struct work_struct *work);
void wfx_link_id_reset_work(struct work_struct *work);
int wfx_find_link_id(struct wfx_vif *wvif, const u8 *mac);
int wfx_alloc_link_id(struct wfx_vif *wvif, const u8 *mac);

#endif /* WFX_DATA_TXRX_H */
