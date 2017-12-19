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

#ifndef wfx_queue_H_INCLUDED
#define wfx_queue_H_INCLUDED

#include "wsm_types.h"
#include "wfx_api.h"

/*========================================================================*/
/*                  Structures definitions                                */
/*========================================================================*/
struct wfx_queue_item;
struct sk_buff;
struct wfx_common;
struct ieee80211_tx_queue_stats;
struct wfx_txpriv;
struct wfx_queue_stats;

struct wfx_queue {
	struct wfx_queue_stats *stats;
	size_t			capacity;
	size_t			num_queued;
	size_t			num_pending;
	size_t			num_sent;
	struct wfx_queue_item *pool;
	struct list_head	queue;
	struct list_head	free_pool;
	struct list_head	pending;
	int			tx_locked_cnt;
	int			*link_map_cache;
	bool			overfull;
	spinlock_t		lock; /* Protect queue entry */
	u8			queue_id;
	u8			generation;
	struct timer_list	gc;
	unsigned long		ttl;
};

typedef void (*wfx_queue_skb_dtor_t)(struct wfx_common *priv,
					struct sk_buff *skb,
					const struct wfx_txpriv *txpriv);

struct wfx_queue_stats {
	spinlock_t		lock; /* Protect stats entry */
	int			*link_map_cache;
	int			num_queued;
	size_t			map_capacity;
	wait_queue_head_t	wait_link_id_empty;
	wfx_queue_skb_dtor_t	skb_dtor;
	struct wfx_common	*priv;
};

struct wfx_txpriv {
	u8 link_id;
	u8 raw_link_id;
	u8 tid;
	u8 rate_id;
	u8 offset;
};

/*========================================================================*/
/*                       Functions                                        */
/*========================================================================*/
int wfx_queue_stats_init(struct wfx_queue_stats *stats,
			    size_t map_capacity,
			   wfx_queue_skb_dtor_t skb_dtor,
			    struct wfx_common *priv);

int wfx_queue_init(struct wfx_queue *queue,
		      struct wfx_queue_stats *stats,
		      u8 queue_id,
		      size_t capacity,
		      unsigned long ttl);

int wfx_queue_clear(struct wfx_queue *queue);

int wfx_queue_put(struct wfx_queue *queue,
		     struct sk_buff *skb,
		     struct wfx_txpriv *txpriv);

int wfx_queue_get(struct wfx_queue *queue,
		     u32 link_id_map,
			 WsmHiTxReq_t **tx,
		     struct ieee80211_tx_info **tx_info,
		     const struct wfx_txpriv **txpriv);

int wfx_queue_requeue(struct wfx_queue *queue, u32 packet_id);

int wfx_queue_requeue_all(struct wfx_queue *queue);

int wfx_queue_remove(struct wfx_queue *queue,
			u32 packet_id);

int wfx_queue_get_skb(struct wfx_queue *queue, u32 packet_id,
			 struct sk_buff **skb,
			 const struct wfx_txpriv **txpriv);

void wfx_queue_stats_deinit(struct wfx_queue_stats *stats);

void wfx_queue_deinit(struct wfx_queue *queue);

void wfx_queue_lock(struct wfx_queue *queue);

void wfx_queue_unlock(struct wfx_queue *queue);

bool wfx_queue_get_xmit_timestamp(struct wfx_queue *queue,
				     unsigned long *timestamp,
				     u32 pending_frame_id);

bool wfx_queue_stats_is_empty(struct wfx_queue_stats *stats,
				 u32 link_id_map);

size_t wfx_queue_get_num_queued(struct wfx_queue *queue,
				   u32 link_id_map);

/*========================================================================*/
/*                  Internally Static Functions                           */
/*========================================================================*/
static inline u8 wfx_queue_get_queue_id(u32 packet_id)
{
	return (packet_id >> 16) & 0xFF;
}

static inline u8 wfx_queue_get_generation(u32 packet_id)
{
	return (packet_id >>  8) & 0xFF;
}

#endif /* wfx_queue_H_INCLUDED */
