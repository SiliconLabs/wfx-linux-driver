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
#include <net/mac80211.h>
#include <linux/sched.h>

/*========================================================================*/
/*                 Local Header files                                     */
/*========================================================================*/
#include "queue.h"
#include "wfx.h"
#include "debug.h"

/*========================================================================*/
/*                  Structures definitions                                */
/*========================================================================*/
struct wfx_queue_item {
	struct list_head	head;
	struct sk_buff		*skb;
	u32			packet_id;
	unsigned long		queue_timestamp;
	unsigned long		xmit_timestamp;
	struct wfx_txpriv	txpriv;
	u8			generation;
};

/*========================================================================*/
/*                  Internally Static Functions                           */
/*========================================================================*/
static inline void __wfx_queue_lock(struct wfx_queue *queue)
{
	struct wfx_queue_stats *stats = queue->stats;

	if (queue->tx_locked_cnt++ == 0) {
		pr_debug("[TX] Queue %d is locked.\n",
			 queue->queue_id);
		ieee80211_stop_queue(stats->priv->hw, queue->queue_id);
	}
}

static inline void __wfx_queue_unlock(struct wfx_queue *queue)
{
	struct wfx_queue_stats *stats = queue->stats;

	BUG_ON(!queue->tx_locked_cnt);
	if (--queue->tx_locked_cnt == 0) {
		pr_debug("[TX] Queue %d is unlocked.\n",
			 queue->queue_id);
		ieee80211_wake_queue(stats->priv->hw, queue->queue_id);
	}
}

static inline void wfx_queue_parse_id(u32 packet_id, u8 *queue_generation,
				      u8 *queue_id, u8 *item_generation,
				      u8 *item_id)
{
	*item_id = (packet_id >> 0) & 0xFF;
	*item_generation = (packet_id >> 8) & 0xFF;
	*queue_id = (packet_id >> 16) & 0xFF;
	*queue_generation = (packet_id >> 24) & 0xFF;
}

static inline u32 wfx_queue_mk_packet_id(u8 queue_generation, u8 queue_id,
					 u8 item_generation, u8 item_id)
{
	return ((u32)item_id << 0) |
	       ((u32)item_generation << 8) |
	       ((u32)queue_id << 16) |
	       ((u32)queue_generation << 24);
}

static void wfx_queue_post_gc(struct wfx_queue_stats	*stats,
			      struct list_head		*gc_list)
{
	struct wfx_queue_item *item, *tmp;

	list_for_each_entry_safe(item, tmp, gc_list, head) {
		list_del(&item->head);
		stats->skb_dtor(stats->priv, item->skb, &item->txpriv);
		kfree(item);
	}
}

static void wfx_queue_register_post_gc(struct list_head		*gc_list,
				       struct wfx_queue_item	*item)
{
	struct wfx_queue_item *gc_item;

	gc_item = kmalloc(sizeof(*gc_item),
			  GFP_ATOMIC);
	BUG_ON(!gc_item);
	memcpy(gc_item, item, sizeof(struct wfx_queue_item));
	list_add_tail(&gc_item->head, gc_list);
}

static void __wfx_queue_gc(struct wfx_queue	*queue,
			   struct list_head	*head,
			   bool			unlock)
{
	struct wfx_queue_stats *stats = queue->stats;
	struct wfx_queue_item *item = NULL, *tmp;
	bool wakeup_stats = false;

	list_for_each_entry_safe(item, tmp, &queue->queue, head) {
		if (jiffies - item->queue_timestamp < queue->ttl)
			break;
		--queue->num_queued;
		--queue->link_map_cache[item->txpriv.link_id];
		spin_lock_bh(&stats->lock);
		--stats->num_queued;
		if (!--stats->link_map_cache[item->txpriv.link_id])
			wakeup_stats = true;
		spin_unlock_bh(&stats->lock);
		wfx_debug_tx_ttl(stats->priv);
		wfx_queue_register_post_gc(head, item);
		item->skb = NULL;
		list_move_tail(&item->head, &queue->free_pool);
	}

	if (wakeup_stats)
		wake_up(&stats->wait_link_id_empty);

	if (queue->overfull) {
		if (queue->num_queued <= (queue->capacity >> 1)) {
			queue->overfull = false;
			if (unlock)
				__wfx_queue_unlock(queue);
		} else
		if (item) {
			unsigned long tmo = item->queue_timestamp + queue->ttl;

			mod_timer(&queue->gc, tmo);
			wfx_pm_stay_awake(&stats->priv->pm_state,
					  tmo - jiffies);
		}
	}
}

static void wfx_queue_gc(unsigned long arg)
{
	LIST_HEAD(list);
	struct wfx_queue *queue =
		(struct wfx_queue *)arg;

	spin_lock_bh(&queue->lock);
	__wfx_queue_gc(queue, &list, true);
	spin_unlock_bh(&queue->lock);
	wfx_queue_post_gc(queue->stats, &list);
}

/*========================================================================*/
/*                       Functions                                        */
/*========================================================================*/
int wfx_queue_stats_init(struct wfx_queue_stats *stats,
			 size_t			map_capacity,
			 wfx_queue_skb_dtor_t	skb_dtor,
			 struct wfx_common	*priv)
{
	memset(stats, 0, sizeof(*stats));
	stats->map_capacity = map_capacity;
	stats->skb_dtor = skb_dtor;
	stats->priv = priv;
	spin_lock_init(&stats->lock);
	init_waitqueue_head(&stats->wait_link_id_empty);

	stats->link_map_cache = kcalloc(map_capacity,
			sizeof(int),
			GFP_KERNEL);

	if (!stats->link_map_cache)
		return -ENOMEM;

	return 0;
}

int wfx_queue_init(struct wfx_queue		*queue,
		   struct wfx_queue_stats	*stats,
		   u8				queue_id,
		   size_t			capacity,
		   unsigned long		ttl)
{
	size_t i;

	memset(queue, 0, sizeof(*queue));
	queue->stats = stats;
	queue->capacity = capacity;
	queue->queue_id = queue_id;
	queue->ttl = ttl;
	INIT_LIST_HEAD(&queue->queue);
	INIT_LIST_HEAD(&queue->pending);
	INIT_LIST_HEAD(&queue->free_pool);
	spin_lock_init(&queue->lock);
	setup_timer(&queue->gc, wfx_queue_gc, (unsigned long)queue);

	queue->pool = kcalloc(capacity,
			sizeof(*queue->pool),
			GFP_KERNEL);

	if (!queue->pool)
		return -ENOMEM;

	queue->link_map_cache = kcalloc(stats->map_capacity,
			sizeof(int),
			GFP_KERNEL);

	if (!queue->link_map_cache) {
		kfree(queue->pool);
		queue->pool = NULL;
		return -ENOMEM;
	}

	for (i = 0; i < capacity; ++i)
		list_add_tail(&queue->pool[i].head, &queue->free_pool);

	return 0;
}

int wfx_queue_clear(struct wfx_queue *queue)
{
	int i;

	LIST_HEAD(gc_list);
	struct wfx_queue_stats *stats = queue->stats;
	struct wfx_queue_item *item, *tmp;

	spin_lock_bh(&queue->lock);
	queue->generation++;
	list_splice_tail_init(&queue->queue, &queue->pending);
	list_for_each_entry_safe(item, tmp, &queue->pending, head) {
		if (!item->skb)
			wfx_warn(" can not iterate item");
		wfx_queue_register_post_gc(&gc_list, item);
		item->skb = NULL;
		list_move_tail(&item->head, &queue->free_pool);
	}
	queue->num_queued = 0;
	queue->num_pending = 0;

	spin_lock_bh(&stats->lock);
	for (i = 0; i < stats->map_capacity; ++i) {
		stats->num_queued -= queue->link_map_cache[i];
		stats->link_map_cache[i] -= queue->link_map_cache[i];
		queue->link_map_cache[i] = 0;
	}
	spin_unlock_bh(&stats->lock);
	if (queue->overfull) {
		queue->overfull = false;
		__wfx_queue_unlock(queue);
	}
	spin_unlock_bh(&queue->lock);
	wake_up(&stats->wait_link_id_empty);
	wfx_queue_post_gc(stats, &gc_list);
	return 0;
}

void wfx_queue_stats_deinit(struct wfx_queue_stats *stats)
{
	kfree(stats->link_map_cache);
	stats->link_map_cache = NULL;
}

void wfx_queue_deinit(struct wfx_queue *queue)
{
	wfx_queue_clear(queue);
	del_timer_sync(&queue->gc);
	INIT_LIST_HEAD(&queue->free_pool);
	kfree(queue->pool);
	kfree(queue->link_map_cache);
	queue->pool = NULL;
	queue->link_map_cache = NULL;
	queue->capacity = 0;
}

size_t wfx_queue_get_num_queued(struct wfx_queue	*queue,
				u32			link_id_map)
{
	size_t ret;
	int bit;
	size_t map_capacity = queue->stats->map_capacity;

	if (!link_id_map)
		return 0;

	spin_lock_bh(&queue->lock);
	if (link_id_map == (u32)-1) {
		ret = queue->num_queued - queue->num_pending;
	} else {
		int i;

		ret = 0;
		for (i = 0, bit = 1; i < map_capacity; ++i, bit <<= 1)
			if (link_id_map & bit)
				ret += queue->link_map_cache[i];
	}
	spin_unlock_bh(&queue->lock);
	return ret;
}

int wfx_queue_put(struct wfx_queue	*queue,
		  struct sk_buff	*skb,
		  struct wfx_txpriv	*txpriv)
{
	int ret = 0;

	LIST_HEAD(gc_list);
	struct wfx_queue_stats *stats = queue->stats;

	if (txpriv->link_id >= queue->stats->map_capacity)
		return -EINVAL;

	spin_lock_bh(&queue->lock);
	if (!list_empty(&queue->free_pool)) {
		struct wfx_queue_item *item = list_first_entry(
			&queue->free_pool, struct wfx_queue_item, head);

		if (item->skb)
			wfx_warn(" can not iterate item");

		list_move_tail(&item->head, &queue->queue);
		item->skb = skb;
		item->txpriv = *txpriv;
		item->generation = 0;
		item->packet_id = wfx_queue_mk_packet_id(queue->generation,
							 queue->queue_id,
							 item->generation,
							 item - queue->pool);
		item->queue_timestamp = jiffies;

		++queue->num_queued;
		++queue->link_map_cache[txpriv->link_id];

		spin_lock_bh(&stats->lock);
		++stats->num_queued;
		++stats->link_map_cache[txpriv->link_id];
		spin_unlock_bh(&stats->lock);
		if (!queue->overfull &&
		    queue->num_queued >=
		    (queue->capacity - (num_present_cpus() - 1))) {
			queue->overfull = true;
			__wfx_queue_lock(queue);
			mod_timer(&queue->gc, jiffies);
		}
	} else {
		ret = -ENOENT;
	}
	spin_unlock_bh(&queue->lock);
	return ret;
}

int wfx_queue_get(struct wfx_queue		*queue,
		  u32				link_id_map,
		  WsmHiTxReq_t			**tx,
		  struct ieee80211_tx_info	**tx_info,
		  const struct wfx_txpriv	**txpriv)
{
	int ret = -ENOENT;
	struct wfx_queue_item *item;
	struct wfx_queue_stats *stats = queue->stats;
	bool wakeup_stats = false;

	spin_lock_bh(&queue->lock);
	list_for_each_entry(item, &queue->queue, head) {
		if (link_id_map & BIT(item->txpriv.link_id)) {
			ret = 0;
			break;
		}
	}

	if (!ret) {
		*tx = (WsmHiTxReq_t *)item->skb->data;
		*tx_info = IEEE80211_SKB_CB(item->skb);
		*txpriv = &item->txpriv;
		(*tx)->Body.PacketId = item->packet_id;
		list_move_tail(&item->head, &queue->pending);
		++queue->num_pending;
		--queue->link_map_cache[item->txpriv.link_id];
		item->xmit_timestamp = jiffies;

		spin_lock_bh(&stats->lock);
		--stats->num_queued;
		if (!--stats->link_map_cache[item->txpriv.link_id])
			wakeup_stats = true;
		spin_unlock_bh(&stats->lock);
	}
	spin_unlock_bh(&queue->lock);
	if (wakeup_stats)
		wake_up(&stats->wait_link_id_empty);
	return ret;
}

int wfx_queue_requeue(struct wfx_queue *queue, u32 packet_id)
{
	int ret = 0;
	u8 queue_generation, queue_id, item_generation, item_id;
	struct wfx_queue_item *item;
	struct wfx_queue_stats *stats = queue->stats;

	wfx_queue_parse_id(packet_id, &queue_generation, &queue_id,
			   &item_generation, &item_id);

	item = &queue->pool[item_id];

	spin_lock_bh(&queue->lock);
	BUG_ON(queue_id != queue->queue_id);
	if (queue_generation != queue->generation) {
		ret = -ENOENT;
	} else if (item_id >= (unsigned)queue->capacity) {
		wfx_warn("wfx_queue_requeue: Wrong item id 0x%.4X >= 0x%.4X\n",
			 item_id, (unsigned)queue->capacity);
		ret = -EINVAL;
	} else if (item->generation != item_generation) {
		wfx_warn(
			"wfx_queue_requeue: Wrong item generation 0x%.4X != 0x%.4X\n",
			item->generation, item_generation);
		ret = -ENOENT;
	} else {
		--queue->num_pending;
		++queue->link_map_cache[item->txpriv.link_id];

		spin_lock_bh(&stats->lock);
		++stats->num_queued;
		++stats->link_map_cache[item->txpriv.link_id];
		spin_unlock_bh(&stats->lock);

		item->generation = ++item_generation;
		item->packet_id = wfx_queue_mk_packet_id(queue_generation,
							 queue_id,
							 item_generation,
							 item_id);
		list_move(&item->head, &queue->queue);
	}
	spin_unlock_bh(&queue->lock);
	return ret;
}

int wfx_queue_requeue_all(struct wfx_queue *queue)
{
	struct wfx_queue_item *item, *tmp;
	struct wfx_queue_stats *stats = queue->stats;

	spin_lock_bh(&queue->lock);

	list_for_each_entry_safe_reverse(item, tmp, &queue->pending, head) {
		--queue->num_pending;
		++queue->link_map_cache[item->txpriv.link_id];

		spin_lock_bh(&stats->lock);
		++stats->num_queued;
		++stats->link_map_cache[item->txpriv.link_id];
		spin_unlock_bh(&stats->lock);

		++item->generation;
		item->packet_id = wfx_queue_mk_packet_id(queue->generation,
							 queue->queue_id,
							 item->generation,
							 item - queue->pool);
		list_move(&item->head, &queue->queue);
	}
	spin_unlock_bh(&queue->lock);

	return 0;
}

int wfx_queue_remove(struct wfx_queue *queue, u32 packet_id)
{
	int ret = 0;
	u8 queue_generation, queue_id, item_generation, item_id;
	struct wfx_queue_item *item;
	struct wfx_queue_stats *stats = queue->stats;
	struct sk_buff *gc_skb = NULL;
	struct wfx_txpriv gc_txpriv;

	wfx_queue_parse_id(packet_id, &queue_generation, &queue_id,
			   &item_generation, &item_id);

	item = &queue->pool[item_id];

	spin_lock_bh(&queue->lock);
	BUG_ON(queue_id != queue->queue_id);
	if (queue_generation != queue->generation) {
		ret = -ENOENT;
	} else if (item_id >= (unsigned)queue->capacity) {
		wfx_warn("wfx_queue_remove: Wrong item id 0x%.4X >= 0x%.4X\n",
			 item_id, (unsigned)queue->capacity);
		ret = -EINVAL;
	} else if (item->generation != item_generation) {
		wfx_warn(
			"wfx_queue_remove: Wrong item generation 0x%.4X != 0x%.4X\n",
			item->generation, item_generation);
		ret = -ENOENT;
	} else {
		gc_txpriv = item->txpriv;
		gc_skb = item->skb;
		item->skb = NULL;
		--queue->num_pending;
		--queue->num_queued;
		++queue->num_sent;
		++item->generation;
		list_move(&item->head, &queue->free_pool);

		if (queue->overfull &&
		    (queue->num_queued <= (queue->capacity >> 1))) {
			queue->overfull = false;
			__wfx_queue_unlock(queue);
		}
	}
	spin_unlock_bh(&queue->lock);

	if (gc_skb)
		stats->skb_dtor(stats->priv, gc_skb, &gc_txpriv);

	return ret;
}

int wfx_queue_get_skb(struct wfx_queue *queue, u32 packet_id,
		      struct sk_buff **skb,
		      const struct wfx_txpriv **txpriv)
{
	int ret = 0;
	u8 queue_generation, queue_id, item_generation, item_id;
	struct wfx_queue_item *item;

	wfx_queue_parse_id(packet_id, &queue_generation, &queue_id,
			   &item_generation, &item_id);

	item = &queue->pool[item_id];

	spin_lock_bh(&queue->lock);
	BUG_ON(queue_id != queue->queue_id);
	if (queue_generation != queue->generation) {
		ret = -ENOENT;
	} else if (item_id >= (unsigned)queue->capacity) {
		wfx_warn("wfx_queue_get_skb: Wrong item id 0x%.4X >= 0x%.4X\n",
			 item_id, (unsigned)queue->capacity);
		ret = -EINVAL;
	} else if (item->generation != item_generation) {
		wfx_warn(
			"wfx_queue_get_skb: Wrong item generation 0x%.4X != 0x%.4X\n",
			item->generation, item_generation);
		ret = -ENOENT;
	} else {
		*skb = item->skb;
		*txpriv = &item->txpriv;
	}
	spin_unlock_bh(&queue->lock);
	return ret;
}

void wfx_queue_lock(struct wfx_queue *queue)
{
	spin_lock_bh(&queue->lock);
	__wfx_queue_lock(queue);
	spin_unlock_bh(&queue->lock);
}

void wfx_queue_unlock(struct wfx_queue *queue)
{
	spin_lock_bh(&queue->lock);
	__wfx_queue_unlock(queue);
	spin_unlock_bh(&queue->lock);
}

bool wfx_queue_get_xmit_timestamp(struct wfx_queue	*queue,
				  unsigned long		*timestamp,
				  u32			pending_frame_id)
{
	struct wfx_queue_item *item;
	bool ret;

	spin_lock_bh(&queue->lock);
	ret = !list_empty(&queue->pending);
	if (ret) {
		list_for_each_entry(item, &queue->pending, head) {
			if (item->packet_id != pending_frame_id)
				if (time_before(item->xmit_timestamp,
						*timestamp))
					*timestamp = item->xmit_timestamp;
		}
	}
	spin_unlock_bh(&queue->lock);
	return ret;
}

bool wfx_queue_stats_is_empty(struct wfx_queue_stats	*stats,
			      u32			link_id_map)
{
	bool empty = true;

	spin_lock_bh(&stats->lock);
	if (link_id_map == (u32)-1) {
		empty = stats->num_queued == 0;
	} else {
		int i;

		for (i = 0; i < stats->map_capacity; ++i) {
			if (link_id_map & BIT(i)) {
				if (stats->link_map_cache[i]) {
					empty = false;
					break;
				}
			}
		}
	}
	spin_unlock_bh(&stats->lock);

	return empty;
}
