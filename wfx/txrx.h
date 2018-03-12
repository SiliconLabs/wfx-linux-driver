 /*
 * Copyright (c) 2017, Silicon Laboratories, Inc.
 *
 * Based on:
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
 


#ifndef TXRX_H
#define TXRX_H

#include <linux/list.h>

/* extern */ struct ieee80211_hw;
/* extern */ struct sk_buff;
/* extern */ /* struct wsm_tx; */
/* extern */ /* struct wsm_rx; */
/* extern */ /* struct wsm_tx_confirm; */
/* extern */ struct wfx_txpriv;

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

#define TX_POLICY_CACHE_SIZE    (8)
struct tx_policy_cache {
    struct tx_policy_cache_entry cache[TX_POLICY_CACHE_SIZE];
    struct list_head used;
    struct list_head free;
    spinlock_t lock; /* Protect policy cache */
};

/* ******************************************************************** */
/* TX policy cache                            */
/* Intention of TX policy cache is an overcomplicated WSM API.
 * Device does not accept per-PDU tx retry sequence.
 * It uses "tx retry policy id" instead, so driver code has to sync
 * linux tx retry sequences with a retry policy table in the device.
 */
void tx_policy_init(struct wfx_common *priv);
void tx_policy_upload_work(struct work_struct *work);
void tx_policy_clean(struct wfx_common *priv);

/* ******************************************************************** */
/* TX implementation                            */

u32 wfx_rate_mask_to_wsm(struct wfx_common *priv,
        u32 rates);
void wfx_tx(struct ieee80211_hw *dev,
        struct ieee80211_tx_control *control,
        struct sk_buff *skb);
void wfx_skb_dtor(struct wfx_common *priv,
        struct sk_buff *skb,
        const struct wfx_txpriv *txpriv);

/* ******************************************************************** */
/* WSM callbacks                            */

void wfx_tx_confirm_cb(struct wfx_common *priv,
        int link_id,
        WsmHiTxCnfBody_t *arg);
void wfx_rx_cb(struct wfx_common *priv,
        WsmHiRxIndBody_t *arg,
        int link_id,
        struct sk_buff **skb_p);

/* ******************************************************************** */
/* Timeout                                */

void wfx_tx_timeout(struct work_struct *work);

/* ******************************************************************** */
/* Security                                */
int wfx_alloc_key(struct wfx_common *priv);
void wfx_free_key(struct wfx_common *priv, int idx);
void wfx_free_keys(struct wfx_common *priv);
int wfx_upload_keys(struct wfx_common *priv);

/* ******************************************************************** */
/* Workaround for WFD test case 6.1.10                    */
void wfx_link_id_reset(struct work_struct *work);

#define WFX_LINK_ID_GC_TIMEOUT ((unsigned long)(10 * HZ))

int wfx_find_link_id(struct wfx_common *priv, const u8 *mac);
int wfx_alloc_link_id(struct wfx_common *priv, const u8 *mac);
void wfx_link_id_work(struct work_struct *work);
void wfx_link_id_gc_work(struct work_struct *work);


#endif /* txRX_H */
