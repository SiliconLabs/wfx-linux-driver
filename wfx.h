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
#include "wsm_cmd_api.h"
#include "wsm_mib.h"
#include "wsm_tx.h"

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

#define TU_TO_USEC(x) ((x) * 1024)
#define TU_TO_MSEC(x) ((x) * 1024 / 1000)

/* WFx indication error */
#define INVALID_PDS_CONFIG_FILE    1
#define JOIN_CNF_AUTH_FAILED       2

#define WSM_DUAL_CTS_PROT_ENB		BIT(0)
#define WSM_NON_GREENFIELD_STA_PRESENT	BIT(1)

#define WSM_PHY_BAND_2_4G		(0)
#define WSM_PHY_BAND_5G			(1)

#define WSM_KEY_MAX_INDEX		(16)
#define WSM_MAX_ARP_IP_ADDRTABLE_ENTRIES	2
/* Start modes */
#define WSM_START_MODE_AP		(0)
#define WSM_START_MODE_P2P_GO		(1)
#define WSM_START_MODE_P2P_DEV		(2)

#define WSM_CMD_LAST_CHANCE_TIMEOUT	(HZ * 3 / 2)
#define WSM_TX_EXTRA_HEADROOM		(28) // sizeof(hdr) + sizeof(tx req) + sizeof(alignment)
#define WSM_RX_EXTRA_HEADROOM		(16) // sizeof(hdr) + sizeof(rx req)

/* Please keep order */
enum wfx_state {
	WFX_STATE_PASSIVE = 0,
	WFX_STATE_PRE_STA,
	WFX_STATE_STA,
	WFX_STATE_IBSS,
	WFX_STATE_AP,
};

/* Please keep order */
enum wfx_link_status {
	WFX_LINK_OFF,
	WFX_LINK_RESERVE,
	WFX_LINK_SOFT,
	WFX_LINK_HARD,
	WFX_LINK_RESET,
	WFX_LINK_RESET_REMAP,
};

#define WFX_MAX_STA_IN_AP_MODE    (8)
#define WFX_LINK_ID_AFTER_DTIM    (WFX_MAX_STA_IN_AP_MODE + 1)
#define WFX_LINK_ID_UAPSD         (WFX_MAX_STA_IN_AP_MODE + 2)
#define WFX_LINK_ID_MAX           (WFX_MAX_STA_IN_AP_MODE + 3)
#define WFX_MAX_REQUEUE_ATTEMPTS  (5)
#define WFX_MAX_TID               (8)

struct hwbus_ops;
struct wfx_debug_priv;

struct wfx_link_entry {
	unsigned long			timestamp;
	enum wfx_link_status		status;
	enum wfx_link_status		prev_status;
	u8			mac[ETH_ALEN];          /* peer MAC address in use */
	u8			old_mac[ETH_ALEN];      /* Previous peerMAC address. To use in unmap message */
	u8				buffered[WFX_MAX_TID];
	struct sk_buff_head		rx_queue;
};

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

	struct wfx_debug_priv	*debug;

	/* Mutex for device configuration */
	struct mutex			conf_mutex;

	struct wfx_queue		tx_queue[4];
	struct wfx_queue_stats	tx_queue_stats;
	int				tx_burst_idx;

	/* Radio data */
	int output_power;

	/* BBP/MAC state */
	const struct ieee80211_rate	*rates;
	const struct ieee80211_rate	*mcs_rates;
	u8				long_frame_max_tx_count;
	u8				short_frame_max_tx_count;

	int				chip_frozen;

	/* Keep wfx200 awake (WUP = 1) 1 second after each scan to avoid
	 * FW issue with sleeping/waking up.
	 */
	atomic_t			scan_in_progress;

	/* Keys are global to chip */
	u32			key_map;
	WsmHiAddKeyReqBody_t		keys[WSM_KEY_MAX_INDEX + 1];

	/* WSM */
	struct wsm_cmd			wsm_cmd;
	struct completion		firmware_ready;
	HiStartupIndBody_t		wsm_caps;
	u8				keyset;
	atomic_t			tx_lock;

	/* WSM Join */

	u32			pending_frame_id;


	/* For debugfs 'rx_stats' file */
	HiRxStats_t rx_stats;
	struct mutex rx_stats_lock;
};

struct wfx_vif {
	struct wfx_dev		*wdev;
	struct ieee80211_vif	*vif;
	struct ieee80211_channel *channel;
	int			Id;
	int			mode;
	int			dtim_period;
	int			beacon_int;
	int			bss_loss_state;
	int			delayed_link_loss;
	int			cqm_rssi_thold;
	int			join_complete_status;

	u8			action_frame_sa[ETH_ALEN];
	u8			action_link_id;

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

	/* TX/RX and security */
	s8			wep_default_key_id;

	enum wfx_state	state;

	struct wfx_scan		scan;
	struct wfx_ht_info	ht_info;
	struct wsm_rx_filter	rx_filter;
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
	struct work_struct	link_id_reset_work;
	struct delayed_work	link_id_gc_work;
	struct work_struct	multicast_start_work;
	struct work_struct	multicast_stop_work;
	struct timer_list	mcast_timeout;

	/* API */
	WsmHiSetPmModeReqBody_t		powersave_mode;
	WsmHiSetBssParamsReqBody_t	bss_params;
	WsmHiMibSetUapsdInformation_t	uapsd_info;
	WsmHiMibSetAssociationMode_t	association_mode;

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

struct wfx_sta_priv {
	int link_id;
	int vif_id;
};

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

#endif /* WFX_H */
