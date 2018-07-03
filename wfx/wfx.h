/*
 * Copyright (c) 2017, Silicon Laboratories
 *
 * Based on:
 * Copyright (c) 2010, ST Erickson
 * Author: Dmitry Tarnyagin <dmitry.tarnyagin@lockless.no>
 * Based on the mac80211 Prism54 code, which is
 * Copyright (c) 2006, Michael Wu <flamingice@sourmilk.net>
 * Based on the islsm (softmac prism54) driver, which is:
 * Copyright 2004-2006 Jean-Baptiste Note <jbnote@gmail.com>, et al.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef WFX_H
#define WFX_H

/*========================================================================*/
/*                 Standard Linux Headers                                   */
/*========================================================================*/
#include <linux/wait.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <net/mac80211.h>
#include <linux/version.h>

/*========================================================================*/
/*                 Local Header files                                       */
/*========================================================================*/
#include "queue.h"
#include "hwio.h"
#include "wsm.h"
#include "scan.h"
#include "data_txrx.h"
#include "pm.h"

/*========================================================================*/
/*                  PRIVATE  Constants/Macros/Types/Variables             */
/*========================================================================*/

/* WFx indication error */
#define INVALID_PDS_CONFIG_FILE    1
#define JOIN_CNF_AUTH_FAILED       2

/* For WFx FSM */
/* Please keep order */
enum wfx_error_cr {
	WFX_ERR_FW_CR = 0,
	WFX_ERR_CONFIG_CR,
	WFX_ERR_RUNNING_CR,
};

/* Please keep order */
enum wfx_error_maj {
	WFX_ERR_FW_MAJ = 0,
	WFX_ERR_CONFIG_MAJ,
	WFX_ERR_RUNNING_MAJ,
};

/* Please keep order */
enum wfx_warning {
	WFX_WARN_FW = 0,
	WFX_WARN_CONFIG,
	WFX_WARN_RUNNING,
};

enum do_action {
	doBoot,
	doConfig,
	doRunning,
	doStop,
};

/* Please keep order */
enum wfx_state {
	WFX_STATE_OFF = 0,
	WFX_STATE_ON,
	WFX_STATE_RESTARTING,
	WFX_STATE_RESTARTED,
	WFX_STATE_RESTARTING_CRASH,
	WFX_STATE_TESTMODE,
};

/* Please keep order */
enum wfx_join_status {
	WFX_JOIN_STATUS_PASSIVE = 0,
	WFX_JOIN_STATUS_MONITOR,
	WFX_JOIN_STATUS_JOINING,
	WFX_JOIN_STATUS_PRE_STA,
	WFX_JOIN_STATUS_STA,
	WFX_JOIN_STATUS_IBSS,
	WFX_JOIN_STATUS_AP,
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

#define WFX_MAX_CTRL_FRAME_LEN    (0x1000)
#define WFX_MAX_STA_IN_AP_MODE    (8)
#define WFX_LINK_ID_AFTER_DTIM    (WFX_MAX_STA_IN_AP_MODE + 1)
#define WFX_LINK_ID_UAPSD         (WFX_MAX_STA_IN_AP_MODE + 2)
#define WFX_LINK_ID_MAX           (WFX_MAX_STA_IN_AP_MODE + 3)
#define WFX_MAX_REQUEUE_ATTEMPTS  (5)
#define WFX_MAX_TID               (8)
#define WFX_BLOCK_ACK_CNT         (30)
#define WFX_BLOCK_ACK_THLD        (800)
#define WFX_BLOCK_ACK_HIST        (3)
#define WFX_BLOCK_ACK_INTERVAL    (1 * HZ / WFX_BLOCK_ACK_HIST)
#define WFX_JOIN_TIMEOUT          (1 * HZ)
#define WFX_AUTH_TIMEOUT          (5 * HZ)
#define RESET_GPIO_OTHER          (24)
#define FWLOAD_BLOCK_SIZE         (1024)


extern int sgi_mode;
extern int sgi_control;
extern int ldpc_mode;
extern int ldpc_control;
extern int wfx_power_mode;


/*========================================================================*/
/*                  Structures definitions                                */
/*========================================================================*/
struct hwbus_ops;
struct task_struct;
struct wfx_debug_priv;
struct firmware;
struct wfx_ht_info {
	struct ieee80211_sta_ht_cap	ht_cap;
	enum nl80211_channel_type	channel_type;
	u16				operation_mode;
};

struct wfx_link_entry {
	unsigned long		timestamp;
	enum wfx_link_status	status;
	enum wfx_link_status	prev_status;
	u8			mac[ETH_ALEN];          /* peer MAC address in use */
	u8			old_mac[ETH_ALEN];      /* Previous peerMAC address. To use in unmap message */
	u8			buffered[WFX_MAX_TID];
	struct sk_buff_head	rx_queue;
};

struct wfx_common {
	/* interfaces to the rest of the stack */
	struct ieee80211_hw			*hw;
	struct ieee80211_vif			*vif;
	struct device				*pdev;

	/* Statistics */
	struct ieee80211_low_level_stats	stats;

	/* Our macaddr */
	u8					mac_addr[ETH_ALEN];

	/* Hardware interface */
	const struct hwbus_ops			*hwbus_ops;
	struct hwbus_priv			*hwbus_priv;
	int					wup_gpio_num;

	/* Hardware information */
	hw_type_t				hw_type;
	hw_major_revision_t			hw_revision;

	bool					sdio;
	bool					hif_clkedge;

	const struct firmware			*pds;
	char					*pds_path;

	struct wfx_debug_priv			*debug;

	struct workqueue_struct			*workqueue;
	/* Mutex for device configuration */
	struct mutex				conf_mutex;

	struct wfx_queue			tx_queue[4];
	struct wfx_queue_stats			tx_queue_stats;
	int					tx_burst_idx;

	/* firmware/hardware info */
	unsigned int				tx_hdr_len;

	/* Radio data */
	int					output_power;

	/* BBP/MAC state */
	struct ieee80211_rate			*rates;
	struct ieee80211_rate			*mcs_rates;
	struct ieee80211_channel		*channel;
	struct wsm_edca_params			edca;
	struct wsm_tx_queue_params		tx_queue_params;
	WsmHiMibSetAssociationMode_t		association_mode;
	WsmHiSetBssParamsReqBody_t		bss_params;
	struct wfx_ht_info			ht_info;
	WsmHiSetPmModeReqBody_t			powersave_mode;
	WsmHiSetPmModeReqBody_t			firmware_ps_mode;
	int					cqm_rssi_thold;
	unsigned				cqm_rssi_hyst;
	bool					cqm_use_rssi;
	int					cqm_beacon_loss_count;
	int					channel_switch_in_progress;
	wait_queue_head_t			channel_switch_done;
	u8					long_frame_max_tx_count;
	u8					short_frame_max_tx_count;
	int					mode;
	bool					enable_beacon;
	int					beacon_int;
	bool					listening;
	struct wsm_rx_filter			rx_filter;
	WsmHiMibGrpAddrTable_t			multicast_filter;
	bool					has_multicast_subscription;
	bool					disable_beacon_filter;
	struct work_struct			update_filtering_work;
	struct work_struct			set_beacon_wakeup_period_work;

	u8					ba_rx_tid_mask;
	u8					ba_tx_tid_mask;

	struct wfx_pm_state			pm_state;

	WsmHiMibP2PPsModeInfo_t			p2p_ps_modeinfo;
	WsmHiMibSetUapsdInformation_t		uapsd_info;
	bool					setbssparams_done;

	u32					listen_interval;
	u32					erp_info;
	u32					rts_threshold;

	/* BH */
	atomic_t				bh_rx; /* record that the IRQ triggered */
	atomic_t				bh_tx;
	atomic_t				bh_term;
	atomic_t				bh_suspend;
	atomic_t				device_can_sleep; /* =!WUP signal */

	struct workqueue_struct			*bh_workqueue;
	struct work_struct			bh_work;

	int					bh_error;
	wait_queue_head_t			bh_wq;
	wait_queue_head_t			bh_evt_wq;
	u8					wsm_rx_seq;
	u8					wsm_tx_seq;
	int					hw_bufs_used;
	bool					powersave_enabled; /* doze or quiescent */
	bool					sleep_activated;

	/* Scan status */
	struct wfx_scan				scan;
	/* Keep wfx200 awake (WUP = 1) 1 second after each scan to avoid
	 * FW issue with sleeping/waking up.
	 */
	atomic_t				wait_for_scan;

	/* WSM */
	HiStartupIndBody_t			wsm_caps;
	/* Mutex to protect wsm message sending */
	struct mutex				wsm_cmd_mux;
	struct wsm_buf				wsm_cmd_buf;
	struct wsm_cmd				wsm_cmd;
	wait_queue_head_t			wsm_cmd_wq;
	wait_queue_head_t			wsm_startup_done;
	int					firmware_ready;
	atomic_t				tx_lock;

	/* WSM debug */
	int					wsm_enable_wsm_dumps;

	/* WSM Join */
	enum wfx_join_status			join_status;
	u32					pending_frame_id;
	bool					join_pending;
	struct delayed_work			join_timeout;
	struct work_struct			unjoin_work;
	struct work_struct			join_complete_work;
	int					join_complete_status;
	int					join_dtim_period;
	bool					delayed_unjoin;

	/* TX/RX and security */
	s8					wep_default_key_id;
	struct work_struct			wep_key_work;
	u32					key_map;
	WsmHiAddKeyReqBody_t			keys[WSM_KEY_MAX_INDEX + 1];

	/* AP powersave */
	u32					link_id_map;
	struct wfx_link_entry			link_id_db[
		WFX_MAX_STA_IN_AP_MODE];
	struct work_struct			link_id_work;
	struct delayed_work			link_id_gc_work;
	u32					sta_asleep_mask;
	u32					pspoll_mask;
	bool					aid0_bit_set;
	spinlock_t				ps_state_lock; /* Protect power save state */
	bool					buffered_multicasts;
	bool					tx_multicast;
	struct work_struct			set_tim_work;
	struct work_struct			set_cts_work;
	struct work_struct			multicast_start_work;
	struct work_struct			multicast_stop_work;
	struct timer_list			mcast_timeout;

	/* WSM events and CQM implementation */
	spinlock_t				event_queue_lock; /* Protect event queue */
	struct list_head			event_queue;
	struct work_struct			event_handler;

	struct delayed_work			bss_loss_work;
	spinlock_t				bss_loss_lock; /* Protect BSS loss state */
	int					bss_loss_state;
	u32					bss_loss_confirm_id;
	int					delayed_link_loss;
	struct work_struct			bss_params_work;

	/* TX rate policy cache */
	struct tx_policy_cache			tx_policy_cache;
	struct work_struct			tx_policy_upload_work;

	/* legacy PS mode switch in suspend */
	int					ps_mode_switch_in_progress;
	wait_queue_head_t			ps_mode_switch_done;

	/* Workaround for WFD testcase 6.1.10*/
	struct work_struct			linkid_reset_work;
	u8					action_frame_sa[ETH_ALEN];
	u8					action_linkid;

	/* For WFx FSM */
	enum wfx_state				state;
	struct work_struct			restart_work;
};

struct wfx_sta_priv {
	int link_id;
};

/*========================================================================*/
/*                       Functions                                        */
/*========================================================================*/
extern const char *const wfx_fw_types[];

/* interfaces for the drivers */
int wfx_core_probe(const struct hwbus_ops *hwbus_ops,
		   struct hwbus_priv *hwbus,
		   struct device *pdev,
		   struct wfx_common **pself,
		   const u8 *macaddr,
		   bool sdio, bool hif_clkedge);

void wfx_core_release(struct wfx_common *self);


void wfx_core_restart(struct work_struct *work);

/* ******************************************************************** */
/* mac80211 API                                */

int wfx_start(struct ieee80211_hw *dev);
void wfx_stop(struct ieee80211_hw *dev);
void wfx_reconfig_complete(struct ieee80211_hw		*hw,
			   enum ieee80211_reconfig_type reconfig_type);
#ifdef CONFIG_PM    /* CONFIg_PM */
int wfx_wow_suspend(struct ieee80211_hw *hw, struct cfg80211_wowlan *wowlan);
int wfx_wow_resume(struct ieee80211_hw *hw);
#endif    /*CONFIG_PM*/
int wfx_add_interface(struct ieee80211_hw *dev, struct ieee80211_vif *vif);
int wfx_change_interface(struct ieee80211_hw *dev, struct ieee80211_vif *vif,
			 enum nl80211_iftype new_type, bool p2p);
void wfx_remove_interface(struct ieee80211_hw *dev, struct ieee80211_vif *vif);
int wfx_config(struct ieee80211_hw *dev, u32 changed);
void wfx_tx(struct ieee80211_hw *dev, struct ieee80211_tx_control *control,
	    struct sk_buff *skb);
int wfx_conf_tx(struct ieee80211_hw *dev, struct ieee80211_vif *vif, u16 queue,
		const struct ieee80211_tx_queue_params *params);
int wfx_hw_scan(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
		struct ieee80211_scan_request *hw_req);
int wfx_sta_add(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
		struct ieee80211_sta *sta);
int wfx_sta_remove(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
		   struct ieee80211_sta *sta);
void wfx_sta_notify(struct ieee80211_hw *dev, struct ieee80211_vif *vif,
		    enum sta_notify_cmd notify_cmd, struct ieee80211_sta *sta);
int wfx_set_tim(struct ieee80211_hw *dev, struct ieee80211_sta *sta, bool set);
int wfx_set_key(struct ieee80211_hw *dev, enum set_key_cmd cmd,
		struct ieee80211_vif *vif, struct ieee80211_sta *sta,
		struct ieee80211_key_conf *key);
int wfx_set_rts_threshold(struct ieee80211_hw *hw, u32 value);
void wfx_bss_info_changed(struct ieee80211_hw *dev, struct ieee80211_vif *vif,
			  struct ieee80211_bss_conf *info, u32 changed);
u64 wfx_prepare_multicast(struct ieee80211_hw		*hw,
			  struct netdev_hw_addr_list	*mc_list);
void wfx_configure_filter(struct ieee80211_hw *dev, unsigned int changed_flags,
			  unsigned int *total_flags, u64 multicast);
int wfx_get_stats(struct ieee80211_hw			*dev,
		  struct ieee80211_low_level_stats	*stats);

#if (KERNEL_VERSION(4, 4, 69) <= LINUX_VERSION_CODE)
int wfx_ampdu_action(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
		     struct ieee80211_ampdu_params *params);
#else
int wfx_ampdu_action(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
		     enum ieee80211_ampdu_mlme_action action,
		     struct ieee80211_sta *sta, u16 tid, u16 *ssn, u8 buf_size,
		     bool amsdu);
#endif

void wfx_flush(struct ieee80211_hw *hw, struct ieee80211_vif *vif, u32 queues,
	       bool drop);

#ifdef CONFIG_WF200_TESTMODE
int wfx_testmode_command(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
			 void *data, int len);
#endif

/*========================================================================*/
/*                  Internally Static Functions                           */
/*========================================================================*/
static inline int wfx_is_ht(const struct wfx_ht_info *ht_info)
{
	return ht_info->channel_type != NL80211_CHAN_NO_HT;
}

/* 802.11n HT capability: IEEE80211_HT_CAP_GRN_FLD.
 * Device supports Greenfield preamble.
 */
static inline int wfx_ht_greenfield(const struct wfx_ht_info *ht_info)
{
	return wfx_is_ht(ht_info) &&
	       (ht_info->ht_cap.cap & IEEE80211_HT_CAP_GRN_FLD) &&
	       !(ht_info->operation_mode &
		 IEEE80211_HT_OP_MODE_NON_GF_STA_PRSNT);
}

/* 802.11n HT capability: IEEE80211_HT_CAP_LDPC_CODING.
 * Device supports LDPC coding.
 */
static inline int wfx_ht_fecCoding(const struct wfx_ht_info *ht_info)
{
	return wfx_is_ht(ht_info) &&
	       (ht_info->ht_cap.cap & IEEE80211_HT_CAP_LDPC_CODING);
}

/* 802.11n HT capability: IEEE80211_HT_CAP_SGI_20.
 * Device supports Short Guard    Interval on 20MHz channels.
 */
static inline int wfx_ht_shortGi(const struct wfx_ht_info *ht_info)
{
	return wfx_is_ht(ht_info) &&
	       (ht_info->ht_cap.cap & IEEE80211_HT_CAP_SGI_20);
}

static inline int wfx_ht_ampdu_density(const struct wfx_ht_info *ht_info)
{
	if (!wfx_is_ht(ht_info))
		return 0;
	return ht_info->ht_cap.ampdu_density;
}

#endif /* WFX_H */
