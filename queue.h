/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * O(1) TX queue with built-in allocator.
 *
 * Copyright (c) 2017-2018, Silicon Laboratories, Inc.
 * Copyright (c) 2010, ST-Ericsson
 */
#ifndef WFX_QUEUE_H
#define WFX_QUEUE_H

#include "wsm_cmd_api.h"

#define WFX_MAX_STA_IN_AP_MODE    (8)
#define WFX_LINK_ID_AFTER_DTIM    (WFX_MAX_STA_IN_AP_MODE + 1)
#define WFX_LINK_ID_UAPSD         (WFX_MAX_STA_IN_AP_MODE + 2)
#define WFX_LINK_ID_MAX           (WFX_MAX_STA_IN_AP_MODE + 3)


/* extern */ struct sk_buff;
/* extern */ struct wfx_dev;
/* extern */ struct wfx_vif;
/* extern */ struct ieee80211_tx_queue_stats;
/* extern */ struct wfx_txpriv;

/* forward */ struct wfx_queue_stats;

typedef void (*wfx_queue_skb_dtor_t)(struct wfx_dev *wdev,
					struct sk_buff *skb);

struct wfx_queue_item {
	struct list_head	head;
	struct sk_buff		*skb;
};

struct wfx_queue {
	struct wfx_queue_stats *stats;
	size_t			capacity;
	size_t			num_queued;
	size_t			num_pending;
	struct wfx_queue_item *pool;
	struct list_head	queue;
	struct list_head	free_pool;
	struct list_head	pending;
	int			tx_locked_cnt;
	int			link_map_cache[WFX_LINK_ID_MAX];
	spinlock_t		lock; /* Protect queue entry */
	u8			queue_id;
	u8			counter;
	u8			generation;
};

struct wfx_queue_stats {
	spinlock_t		lock; /* Protect stats entry */
	int			link_map_cache[WFX_LINK_ID_MAX];
	int			num_queued;
	wait_queue_head_t	wait_link_id_empty;
	wfx_queue_skb_dtor_t	skb_dtor;
	struct wfx_dev		*wdev;
};

int wfx_queue_stats_init(struct wfx_queue_stats *stats,
			    wfx_queue_skb_dtor_t skb_dtor,
			    struct wfx_dev *wdev);
int wfx_queue_init(struct wfx_queue *queue,
		      struct wfx_queue_stats *stats,
		      u8 queue_id,
		      size_t capacity);

void wfx_queue_wait_empty_vif(struct wfx_vif *wvif);

int wfx_queue_clear(struct wfx_queue *queue);
void wfx_queue_stats_deinit(struct wfx_queue_stats *stats);
void wfx_queue_deinit(struct wfx_queue *queue);

size_t wfx_queue_get_num_queued(struct wfx_queue *queue,
				   u32 link_id_map);
int wfx_queue_put(struct wfx_queue *queue,
		     struct sk_buff *skb);
struct sk_buff *wfx_queue_pop(struct wfx_queue *queue, u32 link_id_map);
struct sk_buff *wfx_queue_get_id(struct wfx_queue *queue, u32 packet_id);
int wfx_queue_requeue(struct wfx_queue *queue, struct sk_buff *skb);
int wfx_queue_remove(struct wfx_queue *queue, struct sk_buff *skb);

void wfx_queue_lock(struct wfx_queue *queue);
void wfx_queue_unlock(struct wfx_queue *queue);
unsigned wfx_queue_get_pkt_us_delay(struct wfx_queue *queue, struct sk_buff *skb);

bool wfx_queue_stats_is_empty(struct wfx_queue_stats *stats,
				 u32 link_id_map);

void wfx_queue_dump_old_frames(struct wfx_dev *wdev, unsigned limit_ms);

static inline u8 wfx_queue_get_queue_id(u32 packet_id)
{
	return (packet_id >> 16) & 0xFF;
}

#endif /* WFX_QUEUE_H */
