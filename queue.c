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

static u32 wfx_queue_mk_packet_id(u8 queue_generation, u8 queue_id, u8 item_id)
{
	return ((u32)item_id << 0) |
		((u32)queue_id << 16) |
		((u32)queue_generation << 24);
}

static void wfx_queue_post_gc(struct wfx_queue_stats *stats,
				 struct sk_buff_head *gc_list)
{
	struct sk_buff *item;

	while ((item = skb_dequeue(gc_list)) != NULL)
		stats->skb_dtor(stats->wdev, item);
}

int wfx_queue_stats_init(struct wfx_queue_stats *stats,
			    wfx_queue_skb_dtor_t skb_dtor,
			 struct wfx_dev	*wdev)
{
	memset(stats, 0, sizeof(*stats));
	stats->skb_dtor = skb_dtor;
	stats->wdev = wdev;
	skb_queue_head_init(&stats->pending);
	spin_lock_init(&stats->lock);
	init_waitqueue_head(&stats->wait_link_id_empty);

	return 0;
}

int wfx_queue_init(struct wfx_queue *queue,
		      struct wfx_queue_stats *stats,
		      u8 queue_id,
		      size_t capacity)
{
	memset(queue, 0, sizeof(*queue));
	queue->stats = stats;
	queue->queue_id = queue_id;
	skb_queue_head_init(&queue->queue);
	spin_lock_init(&queue->lock);

	return 0;
}

/* If successful, LOCKS the TX queue! */
void wfx_queue_wait_empty_vif(struct wfx_vif *wvif)
{
	int i;
	bool done;
	struct wfx_queue *queue;
	struct sk_buff *item;
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
			skb_queue_walk(&queue->queue, item) {
				hdr = (struct wmsg *) item->data;
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
	struct sk_buff_head gc_list;
	struct wfx_queue_stats *stats = queue->stats;
	struct sk_buff *item;

	skb_queue_head_init(&gc_list);
	spin_lock_bh(&queue->lock);
	queue->generation++;
	while ((item = skb_dequeue(&queue->queue)) != NULL)
		skb_queue_head(&gc_list, item);
	queue->counter = 0;

	spin_lock_bh(&stats->lock);
	for (i = 0; i < ARRAY_SIZE(stats->link_map_cache); ++i) {
		stats->link_map_cache[i] -= queue->link_map_cache[i];
		queue->link_map_cache[i] = 0;
	}
	spin_unlock_bh(&stats->lock);
	spin_unlock_bh(&queue->lock);
	wake_up(&stats->wait_link_id_empty);
	wfx_queue_post_gc(stats, &gc_list);
	return 0;
}

void wfx_queue_stats_deinit(struct wfx_queue_stats *stats)
{
	WARN_ON(!skb_queue_empty(&stats->pending));
}

void wfx_queue_deinit(struct wfx_queue *queue)
{
	wfx_queue_clear(queue);
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
		ret = skb_queue_len(&queue->queue);
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
	wsm->PacketId = wfx_queue_mk_packet_id(queue->generation,
			queue->queue_id,
			queue->counter++);
	skb_queue_tail(&queue->queue, skb);

	++queue->link_map_cache[txpriv->link_id];

	spin_lock_bh(&stats->lock);
	++stats->link_map_cache[txpriv->link_id];
	spin_unlock_bh(&stats->lock);
	spin_unlock_bh(&queue->lock);
	return ret;
}

struct sk_buff *wfx_queue_pop(struct wfx_queue *queue, u32 link_id_map)
{
	struct sk_buff *skb = NULL;
	struct sk_buff *item;
	struct wfx_queue_stats *stats = queue->stats;
	struct wfx_txpriv *txpriv;
	bool wakeup_stats = false;

	spin_lock_bh(&queue->lock);
	skb_queue_walk(&queue->queue, item) {
		txpriv = wfx_skb_txpriv(item);
		if (link_id_map & BIT(txpriv->link_id)) {
			skb = item;
			break;
		}
	}
	WARN_ON(!skb);
	if (skb) {
		txpriv = wfx_skb_txpriv(skb);
		txpriv->xmit_timestamp = ktime_get();
		skb_unlink(skb, &queue->queue);
		--queue->link_map_cache[txpriv->link_id];

		spin_lock_bh(&stats->lock);
		skb_queue_tail(&stats->pending, skb);
		if (!--stats->link_map_cache[txpriv->link_id])
			wakeup_stats = true;
		spin_unlock_bh(&stats->lock);
	}
	spin_unlock_bh(&queue->lock);
	if (wakeup_stats)
		wake_up(&stats->wait_link_id_empty);
	return skb;
}

int wfx_queue_requeue(struct wfx_queue *queue, struct sk_buff *skb)
{
	struct wfx_queue_stats *stats = queue->stats;
	struct wfx_txpriv *txpriv = wfx_skb_txpriv(skb);

	spin_lock_bh(&queue->lock);
	++queue->link_map_cache[txpriv->link_id];

	spin_lock_bh(&stats->lock);
	++stats->link_map_cache[txpriv->link_id];
	skb_unlink(skb, &stats->pending);
	spin_unlock_bh(&stats->lock);
	skb_queue_tail(&queue->queue, skb);
	spin_unlock_bh(&queue->lock);
	return 0;
}

int wfx_queue_remove(struct wfx_queue *queue, struct sk_buff *skb)
{
	struct wfx_queue_stats *stats = queue->stats;

	spin_lock_bh(&stats->lock);
	skb_unlink(skb, &stats->pending);
	spin_unlock_bh(&stats->lock);
	stats->skb_dtor(stats->wdev, skb);

	return 0;
}

struct sk_buff *wfx_queue_get_id(struct wfx_queue *queue, u32 packet_id)
{
	struct sk_buff *skb;
	WsmHiTxReqBody_t *wsm;
	struct wfx_queue_stats *stats = queue->stats;

	spin_lock_bh(&stats->lock);
	skb_queue_walk(&stats->pending, skb) {
		wsm = wfx_skb_txreq(skb);
		if (wsm->PacketId == packet_id) {
			spin_unlock_bh(&stats->lock);
			return skb;
		}
	}
	WARN_ON(1);
	spin_unlock_bh(&stats->lock);
	return NULL;
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
	struct wfx_queue_stats *stats = &wdev->tx_queue_stats;
	ktime_t now = ktime_get();
	struct wfx_txpriv *txpriv;
	WsmHiTxReqBody_t *wsm;
	struct sk_buff *skb;

	dev_info(wdev->dev, "Frames stuck in firmware since %dms or more:\n", limit_ms);
	spin_lock_bh(&stats->lock);
	skb_queue_walk(&stats->pending, skb) {
		txpriv = wfx_skb_txpriv(skb);
		wsm = wfx_skb_txreq(skb);
		if (ktime_after(now, ktime_add_ms(txpriv->xmit_timestamp, limit_ms)))
			dev_info(wdev->dev, "   id %08x sent %lldms ago",
					wsm->PacketId,
					ktime_ms_delta(now, txpriv->xmit_timestamp));
	}
	spin_unlock_bh(&stats->lock);
}

unsigned wfx_queue_get_pkt_us_delay(struct wfx_queue *queue, struct sk_buff *skb)
{
	ktime_t now = ktime_get();
	struct wfx_txpriv *txpriv = wfx_skb_txpriv(skb);

	return ktime_us_delta(now, txpriv->xmit_timestamp);
}

bool wfx_queue_stats_is_empty(struct wfx_queue_stats *stats, uint32_t link_id_map)
{
	int i;

	spin_lock_bh(&stats->lock);
	for (i = 0; i < ARRAY_SIZE(stats->link_map_cache); i++) {
		if (link_id_map & BIT(i) && stats->link_map_cache[i]) {
			spin_unlock_bh(&stats->lock);
			return false;
		}
	}
	spin_unlock_bh(&stats->lock);

	return true;
}
