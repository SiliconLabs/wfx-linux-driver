// SPDX-License-Identifier: GPL-2.0-only
/*
 * O(1) TX queue with built-in allocator.
 *
 * Copyright (c) 2017-2019, Silicon Laboratories, Inc.
 * Copyright (c) 2010, ST-Ericsson
 */
#include <linux/sched.h>
#include <net/mac80211.h>

#include "queue.h"
#include "wfx.h"
#include "wsm_rx.h"
#include "debug.h"

static void __wfx_queue_lock(struct wfx_queue *queue)
{
	struct wfx_queue_stats *stats = queue->stats;
	if (queue->tx_locked_cnt++ == 0) {
		pr_debug("[TX] Queue %d is locked.\n",
			 queue->queue_id);
		ieee80211_stop_queue(stats->wdev->hw, queue->queue_id);
	}
}

static void __wfx_queue_unlock(struct wfx_queue *queue)
{
	struct wfx_queue_stats *stats = queue->stats;
	BUG_ON(!queue->tx_locked_cnt);
	if (--queue->tx_locked_cnt == 0) {
		pr_debug("[TX] Queue %d is unlocked.\n",
			 queue->queue_id);
		ieee80211_wake_queue(stats->wdev->hw, queue->queue_id);
	}
}

static void wfx_queue_parse_id(u32 packet_id, u8 *queue_generation,
					 u8 *queue_id,
					 u8 *item_id)
{
	*item_id		= (packet_id >>  0) & 0xFF;
	*queue_id		= (packet_id >> 16) & 0xFF;
	*queue_generation	= (packet_id >> 24) & 0xFF;
}

static u32 wfx_queue_mk_packet_id(u8 queue_generation, u8 queue_id, u8 item_id)
{
	return ((u32)item_id << 0) |
		((u32)queue_id << 16) |
		((u32)queue_generation << 24);
}

static void wfx_queue_post_gc(struct wfx_queue_stats *stats,
				 struct list_head *gc_list)
{
	struct wfx_queue_item *item, *tmp;

	list_for_each_entry_safe(item, tmp, gc_list, head) {
		list_del(&item->head);
		stats->skb_dtor(stats->wdev, item->skb);
		kfree(item);
	}
}

static void wfx_queue_register_post_gc(struct list_head *gc_list,
					  struct wfx_queue_item *item)
{
	struct wfx_queue_item *gc_item = kmalloc(sizeof(*gc_item), GFP_ATOMIC);
	BUG_ON(!gc_item);
	memcpy(gc_item, item, sizeof(struct wfx_queue_item));
	list_add_tail(&gc_item->head, gc_list);
}

int wfx_queue_stats_init(struct wfx_queue_stats *stats,
			    wfx_queue_skb_dtor_t skb_dtor,
			 struct wfx_dev	*wdev)
{
	memset(stats, 0, sizeof(*stats));
	stats->skb_dtor = skb_dtor;
	stats->wdev = wdev;
	spin_lock_init(&stats->lock);
	init_waitqueue_head(&stats->wait_link_id_empty);

	return 0;
}

int wfx_queue_init(struct wfx_queue *queue,
		      struct wfx_queue_stats *stats,
		      u8 queue_id,
		      size_t capacity)
{
	size_t i;

	memset(queue, 0, sizeof(*queue));
	queue->stats = stats;
	queue->capacity = capacity;
	queue->queue_id = queue_id;
	INIT_LIST_HEAD(&queue->queue);
	INIT_LIST_HEAD(&queue->pending);
	INIT_LIST_HEAD(&queue->free_pool);
	spin_lock_init(&queue->lock);

	queue->pool = kcalloc(capacity, sizeof(struct wfx_queue_item),
			GFP_KERNEL);
	if (!queue->pool)
		return -ENOMEM;

	for (i = 0; i < capacity; ++i)
		list_add_tail(&queue->pool[i].head, &queue->free_pool);

	return 0;
}

/* If successful, LOCKS the TX queue! */
void wfx_queue_wait_empty_vif(struct wfx_vif *wvif)
{
	int i;
	bool done;
	struct wfx_queue *queue;
	struct wfx_queue_item *item;
	struct wfx_dev *wdev = wvif->wdev;
	struct wmsg *hdr;

	if (wvif->wdev->chip_frozen) {
		for (i = 0; i < 4; ++i)
			wfx_queue_clear(&wdev->tx_queue[i]);
		wsm_tx_lock_flush(wdev);
		return;
	}

	do {
		done = true;
		wsm_tx_lock_flush(wdev);
		for (i = 0; i < 4 && done; ++i) {
			queue = &wdev->tx_queue[i];
			spin_lock_bh(&queue->lock);
			list_for_each_entry(item, &queue->queue, head) {
				hdr = (struct wmsg *) item->skb->data;
				if (hdr->interface == wvif->Id)
					done = false;
			}
			spin_unlock_bh(&queue->lock);
		}
		if (!done) {
			wsm_tx_unlock(wdev);
			msleep(1);
		}
	} while (!done);
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
		WARN_ON(!item->skb);
		wfx_queue_register_post_gc(&gc_list, item);
		item->skb = NULL;
		list_move_tail(&item->head, &queue->free_pool);
	}
	queue->num_queued = 0;
	queue->num_pending = 0;

	spin_lock_bh(&stats->lock);
	for (i = 0; i < ARRAY_SIZE(stats->link_map_cache); ++i) {
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
}

void wfx_queue_deinit(struct wfx_queue *queue)
{
	wfx_queue_clear(queue);
	INIT_LIST_HEAD(&queue->free_pool);
	kfree(queue->pool);
	queue->pool = NULL;
	queue->capacity = 0;
}

size_t wfx_queue_get_num_queued(struct wfx_queue *queue,
				   u32 link_id_map)
{
	size_t ret;
	int i, bit;

	if (!link_id_map)
		return 0;

	spin_lock_bh(&queue->lock);
	if (link_id_map == (u32)-1) {
		ret = queue->num_queued - queue->num_pending;
	} else {
		ret = 0;
		for (i = 0, bit = 1; i < ARRAY_SIZE(queue->link_map_cache); ++i, bit <<= 1) {
			if (link_id_map & bit)
				ret += queue->link_map_cache[i];
		}
	}
	spin_unlock_bh(&queue->lock);
	return ret;
}

int wfx_queue_put(struct wfx_queue *queue,
		     struct sk_buff *skb)
{
	int ret = 0;
	LIST_HEAD(gc_list);
	struct wfx_queue_stats *stats = queue->stats;
	struct wfx_txpriv *txpriv = wfx_skb_txpriv(skb);
	WsmHiTxReqBody_t *wsm = wfx_skb_txreq(skb);

	if (txpriv->link_id >= ARRAY_SIZE(stats->link_map_cache))
		return -EINVAL;

	spin_lock_bh(&queue->lock);
	if (!WARN_ON(list_empty(&queue->free_pool))) {
		struct wfx_queue_item *item = list_first_entry(
			&queue->free_pool, struct wfx_queue_item, head);
		BUG_ON(item->skb);

		list_move_tail(&item->head, &queue->queue);
		item->skb = skb;
		wsm->PacketId = wfx_queue_mk_packet_id(queue->generation,
							    queue->queue_id,
							    item - queue->pool);

		++queue->num_queued;
		++queue->link_map_cache[txpriv->link_id];

		spin_lock_bh(&stats->lock);
		++stats->num_queued;
		++stats->link_map_cache[txpriv->link_id];
		spin_unlock_bh(&stats->lock);

		/* TX may happen in parallel sometimes.
		 * Leave extra queue slots so we don't overflow.
		 */
		if (!queue->overfull &&
		    queue->num_queued >=
		    (queue->capacity - (num_present_cpus() - 1))) {
			queue->overfull = true;
			__wfx_queue_lock(queue);
		}
	} else {
		ret = -ENOENT;
	}
	spin_unlock_bh(&queue->lock);
	return ret;
}

struct sk_buff *wfx_queue_pop(struct wfx_queue *queue, u32 link_id_map)
{
	struct sk_buff *skb = NULL;
	struct wfx_queue_item *item;
	struct wfx_queue_stats *stats = queue->stats;
	const struct wfx_txpriv *txpriv;
	bool wakeup_stats = false;

	spin_lock_bh(&queue->lock);
	list_for_each_entry(item, &queue->queue, head) {
		txpriv = wfx_skb_txpriv(item->skb);
		if (link_id_map & BIT(txpriv->link_id)) {
			skb = item->skb;
			break;
		}
	}
	WARN_ON(!skb);
	if (skb) {
		txpriv = wfx_skb_txpriv(skb);
		list_move_tail(&item->head, &queue->pending);
		++queue->num_pending;
		--queue->link_map_cache[txpriv->link_id];
		item->xmit_timestamp = ktime_get();

		spin_lock_bh(&stats->lock);
		--stats->num_queued;
		if (!--stats->link_map_cache[txpriv->link_id])
			wakeup_stats = true;
		spin_unlock_bh(&stats->lock);
	}
	spin_unlock_bh(&queue->lock);
	if (wakeup_stats)
		wake_up(&stats->wait_link_id_empty);
	return skb;
}

int wfx_queue_requeue(struct wfx_queue *queue, u32 packet_id)
{
	int ret = 0;
	u8 queue_generation, queue_id, item_id;
	struct wfx_queue_item *item;
	struct wfx_queue_stats *stats = queue->stats;
	struct wfx_txpriv *txpriv;

	wfx_queue_parse_id(packet_id, &queue_generation, &queue_id, &item_id);

	item = &queue->pool[item_id];
	txpriv = wfx_skb_txpriv(item->skb);
	spin_lock_bh(&queue->lock);
	BUG_ON(queue_id != queue->queue_id);
	if (queue_generation != queue->generation) {
		ret = -ENOENT;
	} else if (item_id >= (unsigned) queue->capacity) {
		WARN_ON(1);
		ret = -EINVAL;
	} else {
		--queue->num_pending;
		++queue->link_map_cache[txpriv->link_id];

		spin_lock_bh(&stats->lock);
		++stats->num_queued;
		++stats->link_map_cache[txpriv->link_id];
		spin_unlock_bh(&stats->lock);
		list_move(&item->head, &queue->queue);
	}
	spin_unlock_bh(&queue->lock);
	return ret;
}

int wfx_queue_remove(struct wfx_queue *queue, u32 packet_id)
{
	int ret = 0;
	u8 queue_generation, queue_id, item_id;
	struct wfx_queue_item *item;
	struct wfx_queue_stats *stats = queue->stats;
	struct sk_buff *gc_skb = NULL;

	wfx_queue_parse_id(packet_id, &queue_generation, &queue_id, &item_id);

	item = &queue->pool[item_id];

	spin_lock_bh(&queue->lock);
	BUG_ON(queue_id != queue->queue_id);
	if (queue_generation != queue->generation) {
		ret = -ENOENT;
	} else if (item_id >= (unsigned) queue->capacity) {
		WARN_ON(1);
		ret = -EINVAL;
	} else {
		gc_skb = item->skb;
		item->skb = NULL;
		--queue->num_pending;
		--queue->num_queued;
		/* Do not use list_move_tail here, but list_move:
		 * try to utilize cache row.
		 */
		list_move(&item->head, &queue->free_pool);

		if (queue->overfull &&
		    (queue->num_queued <= (queue->capacity >> 1))) {
			queue->overfull = false;
			__wfx_queue_unlock(queue);
		}
	}
	spin_unlock_bh(&queue->lock);

	if (gc_skb)
		stats->skb_dtor(stats->wdev, gc_skb);

	return ret;
}

struct sk_buff *wfx_queue_get_id(struct wfx_queue *queue, u32 packet_id)
{
	struct sk_buff *skb = NULL;
	u8 queue_generation, queue_id, item_id;
	struct wfx_queue_item *item;

	wfx_queue_parse_id(packet_id, &queue_generation, &queue_id, &item_id);
	item = &queue->pool[item_id];
	spin_lock_bh(&queue->lock);
	BUG_ON(queue_id != queue->queue_id);
	if (queue_generation != queue->generation) {
		/* empty */
	} else if (item_id >= (unsigned) queue->capacity) {
		WARN_ON(1);
	} else {
		skb = item->skb;
	}
	spin_unlock_bh(&queue->lock);
	return skb;
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

void wfx_queue_dump_old_frames(struct wfx_dev *wdev, unsigned limit_ms)
{
	struct wfx_queue *queue;
	struct wfx_queue_item *item;
	ktime_t now = ktime_get();
	int i;

	dev_info(wdev->dev, "Frames stuck in firmware since %dms or more:\n", limit_ms);
	for (i = 0; i < 4; i++) {
		queue = &wdev->tx_queue[i];
		spin_lock_bh(&queue->lock);
		list_for_each_entry(item, &queue->pending, head) {
			if (ktime_after(now, ktime_add_ms(item->xmit_timestamp, limit_ms)))
				dev_info(wdev->dev, "   id %p sent %ums ago",
					 item->skb,
					 (unsigned int) ktime_ms_delta(now, item->xmit_timestamp));
		}
		spin_unlock_bh(&queue->lock);
	}
}

unsigned wfx_queue_get_pkt_us_delay(struct wfx_queue *queue, u32 pkt_id)
{
	ktime_t now = ktime_get();
	ktime_t xmit_ts = queue->pool[pkt_id & 0xFF].xmit_timestamp;

	return ktime_us_delta(now, xmit_ts);
}

bool wfx_queue_stats_is_empty(struct wfx_queue_stats *stats,
				 u32 link_id_map)
{
	bool empty = true;

	spin_lock_bh(&stats->lock);
	if (link_id_map == (u32)-1) {
		empty = stats->num_queued == 0;
	} else {
		int i;
		for (i = 0; i < ARRAY_SIZE(stats->link_map_cache); ++i) {
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
