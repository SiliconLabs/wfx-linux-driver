/*
 * Copyright (c) 2017, Silicon Laboratories, Inc.
 *
 * Based on:
 * Copyright (c) 2011, ST-Ericsson
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


#ifndef DEBUG_H_INCLUDED
#define DEBUG_H_INCLUDED

/*========================================================================*/
/*                  Structures definitions                                */
/*========================================================================*/
struct wfx_debug_priv {
    struct dentry *debugfs_phy;
    int tx;
    int tx_agg;
    int rx;
    int rx_agg;
    int tx_multi;
    int tx_multi_frames;
    int tx_cache_miss;
    int tx_align;
    int tx_ttl;
    int tx_burst;
    int ba_cnt;
    int ba_acc;
    int ba_cnt_rx;
    int ba_acc_rx;
};

/*========================================================================*/
/*                       Functions                                        */
/*========================================================================*/
int wfx_debug_init(struct wfx_common *priv);
void wfx_debug_release(struct wfx_common *priv);

/*========================================================================*/
/*                  Internally Static Functions                           */
/*========================================================================*/
static inline void wfx_debug_txed(struct wfx_common *priv)
{
    ++priv->debug->tx;
}

static inline void wfx_debug_txed_agg(struct wfx_common *priv)
{
    ++priv->debug->tx_agg;
}

static inline void wfx_debug_txed_multi(struct wfx_common *priv,
        int count)
{
    ++priv->debug->tx_multi;
    priv->debug->tx_multi_frames += count;
}

static inline void wfx_debug_rxed(struct wfx_common *priv)
{
    ++priv->debug->rx;
}

static inline void wfx_debug_rxed_agg(struct wfx_common *priv)
{
    ++priv->debug->rx_agg;
}

static inline void wfx_debug_tx_cache_miss(struct wfx_common *priv)
{
    ++priv->debug->tx_cache_miss;
}

static inline void wfx_debug_tx_align(struct wfx_common *priv)
{
    ++priv->debug->tx_align;
}

static inline void wfx_debug_tx_ttl(struct wfx_common *priv)
{
    ++priv->debug->tx_ttl;
}

static inline void wfx_debug_tx_burst(struct wfx_common *priv)
{
    ++priv->debug->tx_burst;
}

static inline void wfx_debug_ba(struct wfx_common *priv,
        int ba_cnt, int ba_acc,
        int ba_cnt_rx, int ba_acc_rx)
{
    priv->debug->ba_cnt = ba_cnt;
    priv->debug->ba_acc = ba_acc;
    priv->debug->ba_cnt_rx = ba_cnt_rx;
    priv->debug->ba_acc_rx = ba_acc_rx;
}

#endif /* DEBUG_H_INCLUDED */
