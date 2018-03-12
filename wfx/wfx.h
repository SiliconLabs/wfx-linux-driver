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

/*========================================================================*/
/*                 Local Header files                                       */
/*========================================================================*/
#include "queue.h"
#include "hwio.h"
#include "wsm.h"
#include "scan.h"
#include "txrx.h"
#include "pm.h"

/*========================================================================*/
/*                  PRIVATE  Constants/Macros/Types/Variables             */
/*========================================================================*/
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


extern int gi_mode;
extern int sgi_ctl;
extern int fec_mode;
extern int ldpc_ctl;

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

enum wfx_link_status {
    WFX_LINK_OFF,
    WFX_LINK_RESERVE,
    WFX_LINK_SOFT, /*EV used for what?*/
    WFX_LINK_HARD,
    WFX_LINK_RESET,
    WFX_LINK_RESET_REMAP,
};

/*========================================================================*/
/*                  Structures definitions                                */
/*========================================================================*/
struct hwbus_ops;
struct task_struct;
struct wfx_debug_priv;
struct firmware;
struct wfx_ht_info {
    struct ieee80211_sta_ht_cap     ht_cap;
    enum nl80211_channel_type       channel_type;
    u16                             operation_mode;
};

struct wfx_link_entry {
    unsigned long        timestamp;
    enum wfx_link_status status;
    enum wfx_link_status prev_status;
    u8                   mac[ETH_ALEN];            /* peer MAC address in use */
    u8                   old_mac[ETH_ALEN];        /* Previous peerMAC address. To use in unmap message */
    u8                   buffered[WFX_MAX_TID];
    struct sk_buff_head  rx_queue;
};

struct wfx_common {
    /* interfaces to the rest of the stack */
    struct ieee80211_hw  *hw;
    struct ieee80211_vif *vif;
    struct device        *pdev;

    /* Statistics */
    struct ieee80211_low_level_stats stats;

    /* Our macaddr */
    u8 mac_addr[ETH_ALEN];

    /* Hardware interface */
    const struct hwbus_ops      *hwbus_ops;
    struct hwbus_priv           *hwbus_priv;

    /* Hardware information */
    hw_type_t                    hw_type;
    hw_major_revision_t          hw_revision;
    bool                         sdio;
    bool                         hif_clkedge;
    const struct firmware       *pds;
    char                        *pds_path;

    struct wfx_debug_priv       *debug;

    struct workqueue_struct     *workqueue;
    struct mutex                 conf_mutex;

    struct wfx_queue             tx_queue[4];
    struct wfx_queue_stats       tx_queue_stats;
    int                          tx_burst_idx;

    /* firmware/hardware info */
    unsigned int                 tx_hdr_len;

    /* Radio data */
    int                          output_power;

    /* BBP/MAC state */
    struct ieee80211_rate       *rates;
    struct ieee80211_rate       *mcs_rates;
    struct ieee80211_channel    *channel;
    struct wsm_edca_params       edca;
    struct wsm_tx_queue_params   tx_queue_params;
    WsmHiMibSetAssociationMode_t association_mode;
    WsmHiSetBssParamsReqBody_t   bss_params;
    struct wfx_ht_info           ht_info;
    WsmHiSetPmModeReqBody_t      powersave_mode;
    WsmHiSetPmModeReqBody_t      firmware_ps_mode;
    int                          cqm_rssi_thold;
    unsigned                     cqm_rssi_hyst;
    bool                         cqm_use_rssi;
    int                          cqm_beacon_loss_count;
    int                          channel_switch_in_progress;
    wait_queue_head_t            channel_switch_done;
    u8                           long_frame_max_tx_count;
    u8                           short_frame_max_tx_count;
    int                          mode;
    bool                         enable_beacon;
    int                          beacon_int;
    bool                         listening;
    struct wsm_rx_filter         rx_filter;
    WsmHiMibGrpAddrTable_t       multicast_filter;
    bool                         has_multicast_subscription;
    bool                         disable_beacon_filter;
    struct work_struct           update_filtering_work;
    struct work_struct           set_beacon_wakeup_period_work;

    u8                           ba_rx_tid_mask;
    u8                           ba_tx_tid_mask;

    struct wfx_pm_state          pm_state;

    WsmHiMibP2PPsModeInfo_t      p2p_ps_modeinfo;
    WsmHiMibSetUapsdInformation_t uapsd_info;
    bool                         setbssparams_done;
    u32                          listen_interval;
    u32                          erp_info;
    u32                          rts_threshold;

    /* BH */
    atomic_t                     bh_rx;
    atomic_t                     bh_tx;
    atomic_t                     bh_term;
    atomic_t                     bh_suspend;

    struct workqueue_struct     *bh_workqueue;
    struct work_struct           bh_work;

    int                          bh_error;
    wait_queue_head_t            bh_wq;
    wait_queue_head_t            bh_evt_wq;
    u8                           wsm_rx_seq;
    u8                           wsm_tx_seq;
    int                          hw_bufs_used;
    bool                         powersave_enabled;
    bool                         device_can_sleep;

    /* Scan status */
    struct wfx_scan              scan;
    /* Keep wfx200 awake (WUP = 1) 1 second after each scan to avoid
     * FW issue with sleeping/waking up.
     */
    atomic_t                     recent_scan;
    struct delayed_work          clear_recent_scan_work;

    /* WSM */
    HiStartupIndBody_t           wsm_caps;
    struct mutex                 wsm_cmd_mux;
    struct wsm_buf               wsm_cmd_buf;
    struct wsm_cmd               wsm_cmd;
    wait_queue_head_t            wsm_cmd_wq;
    wait_queue_head_t            wsm_startup_done;
    int                          firmware_ready;
    atomic_t                     tx_lock;

    /* WSM debug */
    int                          wsm_enable_wsm_dumps;

    /* WSM Join */
    enum wfx_join_status         join_status;
    u32                          pending_frame_id;
    bool                         join_pending;
    struct delayed_work          join_timeout;
    struct work_struct           unjoin_work;
    struct work_struct           join_complete_work;
    int                          join_complete_status;
    int                          join_dtim_period;
    bool                         delayed_unjoin;

    /* TX/RX and security */
    s8                           wep_default_key_id;
    struct work_struct           wep_key_work;
    u32                          key_map;
    WsmHiAddKeyReqBody_t         keys[WSM_KEY_MAX_INDEX + 1];

    /* AP powersave */
    u32                          link_id_map;
    struct wfx_link_entry        link_id_db[WFX_MAX_STA_IN_AP_MODE];
    struct work_struct           link_id_work;
    struct delayed_work          link_id_gc_work;
    u32                          sta_asleep_mask;
    u32                          pspoll_mask;
    bool                         aid0_bit_set;
    spinlock_t                   ps_state_lock; /* Protect power save state */
    bool                         buffered_multicasts;
    bool                         tx_multicast;
    struct work_struct           set_tim_work;
    struct work_struct           set_cts_work;
    struct work_struct           multicast_start_work;
    struct work_struct           multicast_stop_work;
    struct timer_list            mcast_timeout;

    /* WSM events and CQM implementation */
    spinlock_t                   event_queue_lock; /* Protect event queue */
    struct list_head             event_queue;
    struct work_struct           event_handler;

    struct delayed_work          bss_loss_work;
    spinlock_t                   bss_loss_lock; /* Protect BSS loss state */
    int                          bss_loss_state;
    u32                          bss_loss_confirm_id;
    int                          delayed_link_loss;
    struct work_struct           bss_params_work;

    /* TX rate policy cache */
    struct tx_policy_cache       tx_policy_cache;
    struct work_struct           tx_policy_upload_work;

    /* legacy PS mode switch in suspend */
    int                          ps_mode_switch_in_progress;
    wait_queue_head_t            ps_mode_switch_done;

    /* Workaround for WFD testcase 6.1.10*/
    struct work_struct           linkid_reset_work;
    u8                           action_frame_sa[ETH_ALEN];
    u8                           action_linkid;
};

struct wfx_sta_priv {
    int link_id;
};

/*========================================================================*/
/*                       Functions                                        */
/*========================================================================*/
extern int wfx_power_mode;
extern const char * const wfx_fw_types[];

/* interfaces for the drivers */
int wfx_core_probe(const struct hwbus_ops *hwbus_ops,
        struct hwbus_priv *hwbus,
        struct device *pdev,
        struct wfx_common **pself,
        const u8 *macaddr,
        bool sdio,bool hif_clkedge);
void wfx_core_release(struct wfx_common *self);


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
