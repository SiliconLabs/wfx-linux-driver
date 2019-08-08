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
#include "data_tx.h"
#include "debug.h"

void wfx_tx_queues_lock(struct wfx_dev *wdev)
{
	int i;
	struct wfx_queue *queue;

	for (i = 0; i < 4; ++i) {
		queue = &wdev->tx_queue[i];
		spin_lock_bh(&queue->queue.lock);
		if (queue->tx_locked_cnt++ == 0)
			ieee80211_stop_queue(wdev->hw, queue->queue_id);
		spin_unlock_bh(&queue->queue.lock);
	}
}

void wfx_tx_queues_unlock(struct wfx_dev *wdev)
{
	int i;
	struct wfx_queue *queue;

	for (i = 0; i < 4; ++i) {
		queue = &wdev->tx_queue[i];
		spin_lock_bh(&queue->queue.lock);
		BUG_ON(!queue->tx_locked_cnt);
		if (--queue->tx_locked_cnt == 0)
			ieee80211_wake_queue(wdev->hw, queue->queue_id);
		spin_unlock_bh(&queue->queue.lock);
	}
}

/* If successful, LOCKS the TX queue! */
void wfx_tx_queues_wait_empty_vif(struct wfx_vif *wvif)
{
	int i;
	bool done;
	struct wfx_queue *queue;
	struct sk_buff *item;
	struct wfx_dev *wdev = wvif->wdev;
	struct wmsg *hdr;

	if (wvif->wdev->chip_frozen) {
		wsm_tx_lock_flush(wdev);
		for (i = 0; i < 4; ++i)
			wfx_tx_queue_clear(wdev, &wdev->tx_queue[i]);
		return;
	}

	do {
		done = true;
		wsm_tx_lock_flush(wdev);
		for (i = 0; i < 4 && done; ++i) {
			queue = &wdev->tx_queue[i];
			spin_lock_bh(&queue->queue.lock);
			skb_queue_walk(&queue->queue, item) {
				hdr = (struct wmsg *) item->data;
				if (hdr->interface == wvif->Id)
					done = false;
			}
			spin_unlock_bh(&queue->queue.lock);
		}
		if (!done) {
			wsm_tx_unlock(wdev);
			msleep(1);
		}
	} while (!done);
}

int wfx_tx_queue_clear(struct wfx_dev *wdev, struct wfx_queue *queue)
{
	int i;
	struct sk_buff_head gc_list;
	struct wfx_queue_stats *stats = &wdev->tx_queue_stats;
	struct sk_buff *item;

	skb_queue_head_init(&gc_list);
	spin_lock_bh(&queue->queue.lock);
	while ((item = __skb_dequeue(&queue->queue)) != NULL)
		skb_queue_head(&gc_list, item);

	spin_lock_bh(&stats->pending.lock);
	for (i = 0; i < ARRAY_SIZE(stats->link_map_cache); ++i) {
		stats->link_map_cache[i] -= queue->link_map_cache[i];
		queue->link_map_cache[i] = 0;
	}
	spin_unlock_bh(&stats->pending.lock);
	spin_unlock_bh(&queue->queue.lock);
	wake_up(&stats->wait_link_id_empty);
	while ((item = skb_dequeue(&gc_list)) != NULL)
		wfx_skb_dtor(wdev, item);
	return 0;
}

void wfx_tx_queues_init(struct wfx_dev *wdev)
{
	int i;

	memset(&wdev->tx_queue_stats, 0, sizeof(wdev->tx_queue_stats));
	memset(wdev->tx_queue, 0, sizeof(wdev->tx_queue));
	skb_queue_head_init(&wdev->tx_queue_stats.pending);
	init_waitqueue_head(&wdev->tx_queue_stats.wait_link_id_empty);

	for (i = 0; i < 4; ++i) {
		wdev->tx_queue[i].queue_id = i;
		skb_queue_head_init(&wdev->tx_queue[i].queue);
	}
}

void wfx_tx_queues_deinit(struct wfx_dev *wdev)
{
	int i;

	WARN_ON(!skb_queue_empty(&wdev->tx_queue_stats.pending));
	for (i = 0; i < 4; ++i)
		wfx_tx_queue_clear(wdev, &wdev->tx_queue[i]);
}

size_t wfx_tx_queue_get_num_queued(struct wfx_queue *queue,
				   u32 link_id_map)
{
	size_t ret;
	int i, bit;

	if (!link_id_map)
		return 0;

	spin_lock_bh(&queue->queue.lock);
	if (link_id_map == (u32)-1) {
		ret = skb_queue_len(&queue->queue);
	} else {
		ret = 0;
		for (i = 0, bit = 1; i < ARRAY_SIZE(queue->link_map_cache); ++i, bit <<= 1) {
			if (link_id_map & bit)
				ret += queue->link_map_cache[i];
		}
	}
	spin_unlock_bh(&queue->queue.lock);
	return ret;
}

void wfx_tx_queue_put(struct wfx_dev *wdev, struct wfx_queue *queue, struct sk_buff *skb)
{
	struct wfx_queue_stats *stats = &wdev->tx_queue_stats;
	struct wfx_txpriv *txpriv = wfx_skb_txpriv(skb);

	WARN(txpriv->link_id >= ARRAY_SIZE(stats->link_map_cache), "Invalid link_id value");
	spin_lock_bh(&queue->queue.lock);
	__skb_queue_tail(&queue->queue, skb);

	++queue->link_map_cache[txpriv->link_id];

	spin_lock_bh(&stats->pending.lock);
	++stats->link_map_cache[txpriv->link_id];
	spin_unlock_bh(&stats->pending.lock);
	spin_unlock_bh(&queue->queue.lock);
}

struct sk_buff *wfx_tx_queue_get(struct wfx_dev *wdev, struct wfx_queue *queue, u32 link_id_map)
{
	struct sk_buff *skb = NULL;
	struct sk_buff *item;
	struct wfx_queue_stats *stats = &wdev->tx_queue_stats;
	struct wfx_txpriv *txpriv;
	bool wakeup_stats = false;

	spin_lock_bh(&queue->queue.lock);
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
		__skb_unlink(skb, &queue->queue);
		--queue->link_map_cache[txpriv->link_id];

		spin_lock_bh(&stats->pending.lock);
		__skb_queue_tail(&stats->pending, skb);
		if (!--stats->link_map_cache[txpriv->link_id])
			wakeup_stats = true;
		spin_unlock_bh(&stats->pending.lock);
	}
	spin_unlock_bh(&queue->queue.lock);
	if (wakeup_stats)
		wake_up(&stats->wait_link_id_empty);
	return skb;
}

int wfx_pending_requeue(struct wfx_dev *wdev, struct sk_buff *skb)
{
	struct wfx_queue_stats *stats = &wdev->tx_queue_stats;
	struct wfx_txpriv *txpriv = wfx_skb_txpriv(skb);
	struct wfx_queue *queue = &wdev->tx_queue[skb_get_queue_mapping(skb)];

	WARN_ON(skb_get_queue_mapping(skb) > 3);
	spin_lock_bh(&queue->queue.lock);
	++queue->link_map_cache[txpriv->link_id];

	spin_lock_bh(&stats->pending.lock);
	++stats->link_map_cache[txpriv->link_id];
	__skb_unlink(skb, &stats->pending);
	spin_unlock_bh(&stats->pending.lock);
	__skb_queue_tail(&queue->queue, skb);
	spin_unlock_bh(&queue->queue.lock);
	return 0;
}

int wfx_pending_remove(struct wfx_dev *wdev, struct sk_buff *skb)
{
	struct wfx_queue_stats *stats = &wdev->tx_queue_stats;

	spin_lock_bh(&stats->pending.lock);
	__skb_unlink(skb, &stats->pending);
	spin_unlock_bh(&stats->pending.lock);
	wfx_skb_dtor(wdev, skb);

	return 0;
}

struct sk_buff *wfx_pending_get(struct wfx_dev *wdev, u32 packet_id)
{
	struct sk_buff *skb;
	WsmHiTxReqBody_t *wsm;
	struct wfx_queue_stats *stats = &wdev->tx_queue_stats;

	spin_lock_bh(&stats->pending.lock);
	skb_queue_walk(&stats->pending, skb) {
		wsm = wfx_skb_txreq(skb);
		if (wsm->PacketId == packet_id) {
			spin_unlock_bh(&stats->pending.lock);
			return skb;
		}
	}
	WARN_ON(1);
	spin_unlock_bh(&stats->pending.lock);
	return NULL;
}

void wfx_pending_dump_old_frames(struct wfx_dev *wdev, unsigned limit_ms)
{
	struct wfx_queue_stats *stats = &wdev->tx_queue_stats;
	ktime_t now = ktime_get();
	struct wfx_txpriv *txpriv;
	WsmHiTxReqBody_t *wsm;
	struct sk_buff *skb;

	dev_info(wdev->dev, "Frames stuck in firmware since %dms or more:\n", limit_ms);
	spin_lock_bh(&stats->pending.lock);
	skb_queue_walk(&stats->pending, skb) {
		txpriv = wfx_skb_txpriv(skb);
		wsm = wfx_skb_txreq(skb);
		if (ktime_after(now, ktime_add_ms(txpriv->xmit_timestamp, limit_ms)))
			dev_info(wdev->dev, "   id %08x sent %lldms ago",
					wsm->PacketId,
					ktime_ms_delta(now, txpriv->xmit_timestamp));
	}
	spin_unlock_bh(&stats->pending.lock);
}

unsigned wfx_pending_get_pkt_us_delay(struct wfx_dev *wdev, struct sk_buff *skb)
{
	ktime_t now = ktime_get();
	struct wfx_txpriv *txpriv = wfx_skb_txpriv(skb);

	return ktime_us_delta(now, txpriv->xmit_timestamp);
}

bool wfx_tx_queues_is_empty(struct wfx_dev *wdev)
{
	int i;
	struct sk_buff_head *queue;
	bool ret = true;

	for (i = 0; i < 4; i++) {
		queue = &wdev->tx_queue[i].queue;
		spin_lock_bh(&queue->lock);
		if (!skb_queue_empty(queue))
			ret = false;
		spin_unlock_bh(&queue->lock);
	}
	return ret;
}
