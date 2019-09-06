/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Common private data for Silicon Labs WFx chips.
 *
 * Copyright (c) 2017-2019, Silicon Laboratories, Inc.
 * Copyright (c) 2010, ST-Ericsson
 * Copyright (c) 2006, Michael Wu <flamingice@sourmilk.net>
 * Copyright 2004-2006 Jean-Baptiste Note <jbnote@gmail.com>, et al.
 */
#ifndef WFX_H
#define WFX_H

#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/version.h>
#include <net/mac80211.h>

#include "bh.h"
#include "data_tx.h"
#include "main.h"
#include "queue.h"
#include "scan.h"
#include "secure_link.h"
#include "sta.h"
#include "api_wsm_cmd.h"
#include "wsm_tx.h"
#include "api_wsm_mib.h"

#if (KERNEL_VERSION(4, 7, 0) > LINUX_VERSION_CODE)
#define nl80211_band ieee80211_band
#define NL80211_BAND_2GHZ IEEE80211_BAND_2GHZ
#define NUM_NL80211_BANDS IEEE80211_NUM_BANDS
#endif

#if (KERNEL_VERSION(4, 2, 0) > LINUX_VERSION_CODE)
static inline void _ieee80211_hw_set(struct ieee80211_hw *hw,
				     enum ieee80211_hw_flags flg)
{
	hw->flags |= flg;
}
#define ieee80211_hw_set(hw, flg)	_ieee80211_hw_set(hw, IEEE80211_HW_##flg)
#endif

#if (KERNEL_VERSION(4, 15, 0) > LINUX_VERSION_CODE)
static inline u8 ieee80211_get_tid(struct ieee80211_hdr *hdr)
{
    u8 *qc = ieee80211_get_qos_ctl(hdr);

    return qc[0] & IEEE80211_QOS_CTL_TID_MASK;
}
#endif

#if (KERNEL_VERSION(4, 17, 0) > LINUX_VERSION_CODE)
#define struct_size(p, member, n) \
	(n * sizeof(*(p)->member) + __must_be_array((p)->member) + sizeof(*(p)))
#endif

#define WSM_MAX_ARP_IP_ADDRTABLE_ENTRIES	2

/* Please keep order */
struct hwbus_ops;

struct wfx_dev {
	struct wfx_platform_data	pdata;
	struct device			*dev;
	struct ieee80211_hw		*hw;
	struct ieee80211_vif		*vif[2];
	struct mac_address		addresses[2];

	/* Statistics */
	struct ieee80211_low_level_stats stats;

	/* Hardware interface */
	const struct hwbus_ops		*hwbus_ops;
	void				*hwbus_priv;
	struct wfx_hif			hif;
	struct sl_context		sl;


	/* Mutex for device configuration */
	struct mutex			conf_mutex;

	struct wfx_queue		tx_queue[4];
	struct wfx_queue_stats	tx_queue_stats;
	int				tx_burst_idx;

	/* Radio data */
	int output_power;

	int				chip_frozen;

	/* Keep wfx200 awake (WUP = 1) 1 second after each scan to avoid
	 * FW issue with sleeping/waking up.
	 */
	atomic_t			scan_in_progress;

	/* Keys are global to chip */
	u32			key_map;
	struct hif_req_add_key	keys[MAX_KEY_ENTRIES];

	/* WSM */
	struct wsm_cmd			wsm_cmd;
	struct completion		firmware_ready;
	struct hif_ind_startup		wsm_caps;
	u8				keyset;
	atomic_t			tx_lock;

	/* For debugfs 'rx_stats' file */
	struct hif_rx_stats rx_stats;
	struct mutex rx_stats_lock;
};

struct wfx_vif {
	struct wfx_dev		*wdev;
	struct ieee80211_vif	*vif;
	struct ieee80211_channel *channel;
	int			id;
	int			dtim_period;
	int			beacon_int;
	int			bss_loss_state;
	int			delayed_link_loss;
	int			cqm_rssi_thold;
	int			join_complete_status;

	u32			link_id_map;
	u32			sta_asleep_mask;
	u32			pspoll_mask;
	u32			erp_info;
	u32			bss_loss_confirm_id;

	bool			enable_beacon;
	bool			setbssparams_done;
	bool			buffered_multicasts;
	bool			tx_multicast;
	bool			aid0_bit_set;
	bool			delayed_unjoin;
	bool			disable_beacon_filter;
	bool			cqm_use_rssi;
	bool			filter_probe_resp;
	bool			filter_bssid;

	/* TX/RX and security */
	s8			wep_default_key_id;
	struct sk_buff		*wep_pending_skb;

	enum wfx_state	state;

	struct wfx_scan		scan;
	struct wfx_ht_info	ht_info;
	struct wsm_edca_params	edca;
	struct wfx_link_entry	link_id_db[WFX_MAX_STA_IN_AP_MODE];
	struct wfx_grp_addr_table	multicast_filter;
	struct tx_policy_cache		tx_policy_cache;

	struct work_struct	tx_policy_upload_work;
	struct work_struct	unjoin_work;
	struct work_struct	bss_params_work;
	struct delayed_work	bss_loss_work;
	struct work_struct	event_handler_work;
	struct work_struct	wep_key_work;
	struct work_struct	update_filtering_work;
	struct work_struct	set_beacon_wakeup_period_work;
	struct work_struct	set_tim_work;
	struct work_struct	set_cts_work;
	struct work_struct	link_id_work;
	struct delayed_work	link_id_gc_work;
	struct work_struct	multicast_start_work;
	struct work_struct	multicast_stop_work;
	struct timer_list	mcast_timeout;

	/* API */
	struct hif_req_set_pm_mode		powersave_mode;
	struct hif_req_set_bss_params	bss_params;
	struct hif_mib_set_uapsd_information	uapsd_info;

	/* spinlock/mutex */
	struct mutex		bss_loss_lock;
	spinlock_t		ps_state_lock;
	spinlock_t		event_queue_lock;
	struct completion	set_pm_mode_complete;

	/* WSM events and CQM implementation */
	struct list_head	event_queue;
};

static inline struct wfx_vif *wdev_to_wvif(struct wfx_dev *wdev, int vif_id)
{
	if (vif_id >= ARRAY_SIZE(wdev->vif)) {
		dev_dbg(wdev->dev, "Requesting non-existent vif: %d\n", vif_id);
		return NULL;
	}
	if (!wdev->vif[vif_id]) {
		dev_dbg(wdev->dev, "Requesting non-allocated vif: %d\n", vif_id);
		return NULL;
	}
	return (struct wfx_vif *) wdev->vif[vif_id]->drv_priv;
}

static inline struct wfx_vif *wvif_iterate(struct wfx_dev *wdev, struct wfx_vif *cur)
{
	int i;
	int mark = 0;
	struct wfx_vif *tmp;

	if (!cur)
		mark = 1;
	for (i = 0; i < ARRAY_SIZE(wdev->vif); i++) {
		tmp = wdev_to_wvif(wdev, i);
		if (mark && tmp)
			return tmp;
		if (tmp == cur)
			mark = 1;
	}
	return NULL;
}

static inline int wvif_count(struct wfx_dev *wdev)
{
	int i;
	int ret = 0;
	struct wfx_vif *wvif;

	for (i = 0; i < ARRAY_SIZE(wdev->vif); i++) {
		wvif = wdev_to_wvif(wdev, i);
		if (wvif)
			ret++;
	}
	return ret;
}

static inline void memreverse(uint8_t *src, uint8_t length)
{
	uint8_t *lo = src;
	uint8_t *hi = src + length - 1;
	uint8_t swap;

	while (lo < hi) {
		swap = *lo;
		*lo++ = *hi;
		*hi-- = swap;
	}
}

static inline int memzcmp(void *src, unsigned int size)
{
	uint8_t *buf = src;

	if (!size)
		return 0;
	if (*buf)
		return 1;
	return memcmp(buf, buf + 1, size - 1);
}

#endif /* WFX_H */
