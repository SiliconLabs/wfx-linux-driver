/*
 * Copyright (c) 2017, Silicon Laboratories, Inc.
 *
 * Based on:
 * Copyright (c) 2010, ST-Ericsson
 * Author: Dmitry Tarnyagin <dmitry.tarnyagin@lockless.no>
 * Copyright (c) 2006, Michael Wu <flamingice@sourmilk.net>
 * Copyright (c) 2007-2009, Christian Lamparter <chunkeey@web.de>
 * Copyright 2008, Johannes Berg <johannes@sipsolutions.net>
 * - the islsm (softmac prism54) driver, which is:
 *   Copyright 2004-2006 Jean-Baptiste Note <jbnote@gmail.com>, et al.
 * - stlc45xx driver
 *   Copyright (C) 2008 Nokia Corporation and/or its subsidiary(-ies).
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
#include <linux/module.h>
#include <linux/firmware.h>
#include <linux/etherdevice.h>
#include <linux/vmalloc.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <net/mac80211.h>

/*========================================================================*/
/*                 Local Header files                                     */
/*========================================================================*/
#include "wfx.h"
#include "txrx.h"
#include "hwbus.h"
#include "fwio.h"
#include "hwio.h"
#include "bh.h"
#include "sta.h"
#include "scan.h"
#include "debug.h"
#include "pm.h"
#include "wfx_version.h"

/*========================================================================*/
/*                  wfx_core module information                           */
/*========================================================================*/
MODULE_DESCRIPTION("Softmac Silicon Laboratories WFx common code");
MODULE_LICENSE("GPL");
MODULE_ALIAS("wfx_core");
MODULE_VERSION(WFX_LABEL);

/*========================================================================*/
/*                  wfx_core Bypass Parameters                            */
/*========================================================================*/

/* Accept MAC address of the form macaddr=0x00,0x80,0xE1,0x30,0x40,0x50 */
static u8 wfx_mac_template[ETH_ALEN] = {0x02, 0x80, 0xe1, 0x00, 0x00, 0x00};
module_param_array_named(macaddr, wfx_mac_template, byte, NULL, S_IRUGO);
MODULE_PARM_DESC(macaddr, "Override platform_data MAC address");


int wfx_power_mode = WSM_OP_POWER_MODE_QUIESCENT;
module_param(wfx_power_mode, int, 0644);
MODULE_PARM_DESC(wfx_power_mode, "WSM power mode.  0 == active, 1 == doze, 2 == quiescent (default)");

int gi_mode = 1; /* default, sgi is controlled by mac80211 */
module_param(gi_mode, int, 0644);
MODULE_PARM_DESC(gi_mode,
        "Guard Interval mode. 0 == sgi controlled by wfx driver, "
        "1 ==  controlled by mac80211 (default)");

int fec_mode = 1; /* default, LDPC is controlled by mac80211 */
module_param(fec_mode, int, 0644);
MODULE_PARM_DESC(fec_mode,
        "Fec Coding mode. 0 == ldpc controlled by wfx driver, "
        "1 == ldpc controlled by mac80211 (default)");

int sgi_ctl = 1; /* default, LDPC is enabled */
module_param(sgi_ctl, int, 0644);
MODULE_PARM_DESC(sgi_ctl,
        "sgi. 0 == disabled , "
        "1 == enabled (default)");

int ldpc_ctl = 0; /* default, LDPC is disabled */

static int wfx_ba_rx_tids = -1;
static int wfx_ba_tx_tids = -1;
module_param(wfx_ba_rx_tids, int, 0644);
module_param(wfx_ba_tx_tids, int, 0644);
MODULE_PARM_DESC(wfx_ba_rx_tids, "Block ACK RX TIDs");
MODULE_PARM_DESC(wfx_ba_tx_tids, "Block ACK TX TIDs");

/*========================================================================*/
/*                  PRIVATE  Constants/Macros/Types/Variables             */
/*========================================================================*/
#define wfx_a_rates        (wfx_rates + 4)
#define wfx_a_rates_size    (ARRAY_SIZE(wfx_rates) - 4)
#define wfx_g_rates        (wfx_rates + 0)
#define wfx_g_rates_size    (ARRAY_SIZE(wfx_rates))
#define wfx_n_rates        (wfx_mcs_rates)
#define wfx_n_rates_size    (ARRAY_SIZE(wfx_mcs_rates))

#define RATETAB_ENT(_rate, _rateid, _flags)        \
    {                        \
        .bitrate    = (_rate),        \
        .hw_value    = (_rateid),        \
        .flags        = (_flags),        \
    }

#define CHAN2G(_channel, _freq, _flags) {            \
    .band            = IEEE80211_BAND_2GHZ,        \
    .center_freq        = (_freq),            \
    .hw_value        = (_channel),            \
    .flags            = (_flags),            \
    .max_antenna_gain    = 0,                \
    .max_power        = 30,                \
}


/*========================================================================*/
/*                  Internally Static Structures                          */
/*========================================================================*/
static struct ieee80211_rate wfx_rates[] = {
    RATETAB_ENT(10,  0,   0),
    RATETAB_ENT(20,  1,   0),
    RATETAB_ENT(55,  2,   0),
    RATETAB_ENT(110, 3,   0),
    RATETAB_ENT(60,  6,  0),
    RATETAB_ENT(90,  7,  0),
    RATETAB_ENT(120, 8,  0),
    RATETAB_ENT(180, 9,  0),
    RATETAB_ENT(240, 10, 0),
    RATETAB_ENT(360, 11, 0),
    RATETAB_ENT(480, 12, 0),
    RATETAB_ENT(540, 13, 0),
};

static struct ieee80211_rate wfx_mcs_rates[] = {
    RATETAB_ENT(65,  14, IEEE80211_TX_RC_MCS),
    RATETAB_ENT(130, 15, IEEE80211_TX_RC_MCS),
    RATETAB_ENT(195, 16, IEEE80211_TX_RC_MCS),
    RATETAB_ENT(260, 17, IEEE80211_TX_RC_MCS),
    RATETAB_ENT(390, 18, IEEE80211_TX_RC_MCS),
    RATETAB_ENT(520, 19, IEEE80211_TX_RC_MCS),
    RATETAB_ENT(585, 20, IEEE80211_TX_RC_MCS),
    RATETAB_ENT(650, 21, IEEE80211_TX_RC_MCS),
};

static struct ieee80211_channel wfx_2ghz_chantable[] = {
    CHAN2G(1, 2412, 0),
    CHAN2G(2, 2417, 0),
    CHAN2G(3, 2422, 0),
    CHAN2G(4, 2427, 0),
    CHAN2G(5, 2432, 0),
    CHAN2G(6, 2437, 0),
    CHAN2G(7, 2442, 0),
    CHAN2G(8, 2447, 0),
    CHAN2G(9, 2452, 0),
    CHAN2G(10, 2457, 0),
    CHAN2G(11, 2462, 0),
    CHAN2G(12, 2467, 0),
    CHAN2G(13, 2472, 0),
    CHAN2G(14, 2484, 0),
};


static struct ieee80211_supported_band wfx_band_2ghz = {
    .channels = wfx_2ghz_chantable,
    .n_channels = ARRAY_SIZE(wfx_2ghz_chantable),
    .bitrates = wfx_g_rates,
    .n_bitrates = wfx_g_rates_size,

     /*
      * LDPC: WFx driver supports only Transmit LDPC Tx.
      * IEEE80211_HT_CAP_LDPC_CODING should not be enabled
      *
      * SGI: WFx driver supports only Short GI for 20 MHZ
      * IEEE80211_HT_CAP_SGI_40 capability should not be enabled
      *
      *
      */
    .ht_cap = {
        .cap = IEEE80211_HT_CAP_GRN_FLD | /* Receive Greenfield */
               IEEE80211_HT_CAP_SGI_20  | /* Receive Short GI for 20MHZ */
            (1 << IEEE80211_HT_CAP_RX_STBC_SHIFT) | /* Receive STBC for 20MHZ */
            IEEE80211_HT_CAP_MAX_AMSDU,
        .ht_supported = 1,
        .ampdu_factor = IEEE80211_HT_MAX_AMPDU_8K,
        .ampdu_density = IEEE80211_HT_MPDU_DENSITY_NONE,
        .mcs = {
            .rx_mask[0] = 0xFF,
            .rx_highest = __cpu_to_le16(0x41),
            .tx_params = IEEE80211_HT_MCS_TX_DEFINED,
        },
    },
};


static const unsigned long wfx_ttl[] = {
    1 * HZ,    /* VO */
    2 * HZ,    /* VI */
    5 * HZ, /* BE */
    10 * HZ    /* BK */
};

static const struct ieee80211_ops wfx_ops = {
    .start              = wfx_start,
    .stop               = wfx_stop,
    .add_interface      = wfx_add_interface,
    .remove_interface   = wfx_remove_interface,
    .change_interface   = wfx_change_interface,
    .tx                 = wfx_tx,
    .hw_scan            = wfx_hw_scan,
    .set_tim            = wfx_set_tim,
    .sta_notify         = wfx_sta_notify,
    .sta_add            = wfx_sta_add,
    .sta_remove         = wfx_sta_remove,
    .set_key            = wfx_set_key,
    .set_rts_threshold  = wfx_set_rts_threshold,
    .config             = wfx_config,
    .bss_info_changed   = wfx_bss_info_changed,
    .prepare_multicast  = wfx_prepare_multicast,
    .configure_filter   = wfx_configure_filter,
    .conf_tx            = wfx_conf_tx,
    .get_stats          = wfx_get_stats,
    .ampdu_action       = wfx_ampdu_action,
    .flush              = wfx_flush,
#ifdef CONFIG_PM
    .suspend            = wfx_wow_suspend,
    .resume             = wfx_wow_resume,
#endif
#ifdef CONFIG_WF200_TESTMODE
    .testmode_cmd        = wfx_testmode_command,
#endif /* CONFIG_WF200_TESTMODE */
};

#ifdef CONFIG_PM
static const struct wiphy_wowlan_support wfx_wowlan_support = {
    /* Support only for limited wowlan functionalities */
    .flags = WIPHY_WOWLAN_ANY | WIPHY_WOWLAN_DISCONNECT,
};
#endif

static struct ieee80211_hw *wfx_init_common(const u8 *macaddr,
                        const bool sdio, const bool hif_clkedge)
{
    int i, band;
    struct ieee80211_hw *hw;
    struct wfx_common *priv;

    hw = ieee80211_alloc_hw(sizeof(struct wfx_common), &wfx_ops);
    if (!hw) {
        return NULL;
    }

    priv = hw->priv;
    priv->hw = hw;
    priv->hw_type = -1;
    priv->sdio = sdio;
    priv->hif_clkedge = hif_clkedge;
    priv->mode = NL80211_IFTYPE_UNSPECIFIED;
    priv->rates = wfx_rates;
    priv->mcs_rates = wfx_n_rates;
    if (wfx_ba_rx_tids != -1) {
        priv->ba_rx_tid_mask = wfx_ba_rx_tids;
    } else {
        priv->ba_rx_tid_mask = 0xFF; /* Enable RX BLKACK for all TIDs */
    }
    if (wfx_ba_tx_tids != -1) {
        priv->ba_tx_tid_mask = wfx_ba_tx_tids;
    } else {
        priv->ba_tx_tid_mask = 0xff; /* Enable TX BLKACK for all TIDs */
    }

    ieee80211_hw_set(hw, NEED_DTIM_BEFORE_ASSOC);
    ieee80211_hw_set(hw, TX_AMPDU_SETUP_IN_HW);
    ieee80211_hw_set(hw, AMPDU_AGGREGATION);
    ieee80211_hw_set(hw, CONNECTION_MONITOR);
    ieee80211_hw_set(hw, REPORTS_TX_ACK_STATUS);
    ieee80211_hw_set(hw, SUPPORTS_DYNAMIC_PS);
    ieee80211_hw_set(hw, SIGNAL_DBM);
    ieee80211_hw_set(hw, SUPPORTS_PS);
    ieee80211_hw_set(hw, MFP_CAPABLE);

    hw->wiphy->interface_modes = BIT(NL80211_IFTYPE_STATION) |
                                 BIT(NL80211_IFTYPE_ADHOC) |
                                 BIT(NL80211_IFTYPE_AP) |
                                 BIT(NL80211_IFTYPE_MESH_POINT) |
                                 BIT(NL80211_IFTYPE_P2P_CLIENT) |
                                 BIT(NL80211_IFTYPE_P2P_GO);

#ifdef CONFIG_PM
    hw->wiphy->wowlan = &wfx_wowlan_support;
#endif

    hw->wiphy->flags |= WIPHY_FLAG_AP_UAPSD;

    hw->queues = 4;

    priv->rts_threshold = 1000;

    hw->max_rates = 8;
    hw->max_rate_tries = 15;
    hw->extra_tx_headroom = WSM_TX_EXTRA_HEADROOM +
        8;  /* TKIP IV */

    hw->sta_data_size = sizeof(struct wfx_sta_priv);

    hw->wiphy->bands[IEEE80211_BAND_2GHZ] = &wfx_band_2ghz;

    /* Channel params have to be cleared before registering wiphy again */
    for (band = 0; band < IEEE80211_NUM_BANDS; band++) {
        struct ieee80211_supported_band *sband = hw->wiphy->bands[band];
        if (!sband) {
            continue;
        }
        for (i = 0; i < sband->n_channels; i++) {
            sband->channels[i].flags = 0;
            sband->channels[i].max_antenna_gain = 0;
            sband->channels[i].max_power = 30;
        }
    }

    hw->wiphy->max_scan_ssids = 2;
    hw->wiphy->max_scan_ie_len = IEEE80211_MAX_DATA_LEN;

    if (macaddr) {
        SET_IEEE80211_PERM_ADDR(hw, (u8 *)macaddr);
    } else {
        SET_IEEE80211_PERM_ADDR(hw, wfx_mac_template);
    }

    /* Fix up mac address if necessary */
    if (hw->wiphy->perm_addr[3] == 0 &&
        hw->wiphy->perm_addr[4] == 0 &&
        hw->wiphy->perm_addr[5] == 0) {
        get_random_bytes(&hw->wiphy->perm_addr[3], 3);
    }

    mutex_init(&priv->wsm_cmd_mux);
    mutex_init(&priv->conf_mutex);
    priv->workqueue = create_singlethread_workqueue("wfx_wq");
    sema_init(&priv->scan.lock, 1);
    INIT_WORK(&priv->scan.work, wfx_scan_work);
    INIT_DELAYED_WORK(&priv->scan.probe_work, wfx_probe_work);
    INIT_DELAYED_WORK(&priv->scan.timeout, wfx_scan_timeout);
    INIT_DELAYED_WORK(&priv->clear_recent_scan_work,
              wfx_clear_recent_scan_work);
    INIT_DELAYED_WORK(&priv->join_timeout, wfx_join_timeout);
    INIT_WORK(&priv->unjoin_work, wfx_unjoin_work);
    INIT_WORK(&priv->join_complete_work, wfx_join_complete_work);
    INIT_WORK(&priv->wep_key_work, wfx_wep_key_work);
    INIT_WORK(&priv->tx_policy_upload_work, tx_policy_upload_work);
    spin_lock_init(&priv->event_queue_lock);
    INIT_LIST_HEAD(&priv->event_queue);
    INIT_WORK(&priv->event_handler, wfx_event_handler);
    INIT_DELAYED_WORK(&priv->bss_loss_work, wfx_bss_loss_work);
    INIT_WORK(&priv->bss_params_work, wfx_bss_params_work);
    spin_lock_init(&priv->bss_loss_lock);
    spin_lock_init(&priv->ps_state_lock);
    INIT_WORK(&priv->set_cts_work, wfx_set_cts_work);
    INIT_WORK(&priv->set_tim_work, wfx_set_tim_work);
    INIT_WORK(&priv->multicast_start_work, wfx_multicast_start_work);
    INIT_WORK(&priv->multicast_stop_work, wfx_multicast_stop_work);
    INIT_WORK(&priv->link_id_work, wfx_link_id_work);
    INIT_DELAYED_WORK(&priv->link_id_gc_work, wfx_link_id_gc_work);
    INIT_WORK(&priv->linkid_reset_work, wfx_link_id_reset);
    INIT_WORK(&priv->update_filtering_work, wfx_update_filtering_work);
    INIT_WORK(&priv->set_beacon_wakeup_period_work,
          wfx_set_beacon_wakeup_period_work);
    init_timer(&priv->mcast_timeout);
    priv->mcast_timeout.data = (unsigned long)priv;
    priv->mcast_timeout.function = wfx_mcast_timeout;

    if (wfx_queue_stats_init(&priv->tx_queue_stats,
                    WFX_LINK_ID_MAX,
                    wfx_skb_dtor,
                    priv)) {
        ieee80211_free_hw(hw);
        return NULL;
    }

    for (i = 0; i < 4; ++i) {
        if (wfx_queue_init(&priv->tx_queue[i],
                      &priv->tx_queue_stats, i, 16,
                      wfx_ttl[i])) {
            for (; i > 0; i--)
                wfx_queue_deinit(&priv->tx_queue[i - 1]);
            wfx_queue_stats_deinit(&priv->tx_queue_stats);
            ieee80211_free_hw(hw);
            return NULL;
        }
    }

    init_waitqueue_head(&priv->channel_switch_done);
    init_waitqueue_head(&priv->wsm_cmd_wq);
    init_waitqueue_head(&priv->wsm_startup_done);
    init_waitqueue_head(&priv->ps_mode_switch_done);
    wsm_buf_init(&priv->wsm_cmd_buf);
    spin_lock_init(&priv->wsm_cmd.lock);
    priv->wsm_cmd.done = 1;
    tx_policy_init(priv);

    return hw;
}

/*========================================================================*/
/*                  Internally Static Functions                           */
/*========================================================================*/
static int wfx_register_common(struct ieee80211_hw *dev)
{
    struct wfx_common *priv = dev->priv;
    int err;

#ifdef CONFIG_PM
    err = wfx_pm_init(&priv->pm_state, priv);
    if (err) {
        pr_err("Cannot init PM. (%d).\n",
               err);
        return err;
    }
#endif

    err = ieee80211_register_hw(dev);
    if (err) {
        pr_err("Cannot register device (%d).\n",
               err);
#ifdef CONFIG_PM
        wfx_pm_deinit(&priv->pm_state);
#endif
        return err;
    }

    wfx_debug_init(priv);

    pr_info("Registered as '%s'\n", wiphy_name(dev->wiphy));
    return 0;
}

static void wfx_free_common(struct ieee80211_hw *dev)
{
    ieee80211_free_hw(dev);
}

static void wfx_unregister_common(struct ieee80211_hw *dev)
{
    struct wfx_common *priv = dev->priv;
    int i;

    ieee80211_unregister_hw(dev);

    del_timer_sync(&priv->mcast_timeout);
    wfx_unregister_bh(priv);

    wfx_debug_release(priv);

    mutex_destroy(&priv->conf_mutex);

    wsm_buf_deinit(&priv->wsm_cmd_buf);

    destroy_workqueue(priv->workqueue);
    priv->workqueue = NULL;


    if (priv->pds) {
        release_firmware(priv->pds);
        priv->pds = NULL;
    }


    for (i = 0; i < 4; ++i)
        wfx_queue_deinit(&priv->tx_queue[i]);

    wfx_queue_stats_deinit(&priv->tx_queue_stats);
#ifdef CONFIG_PM
    wfx_pm_deinit(&priv->pm_state);
#endif
}

/* Init Module function -> Called by insmod */
static int __init wfx_core_init(void)
{
    return 0;
}

/* Called at Driver Unloading */
static void __exit wfx_core_exit(void)
{
}

/*========================================================================*/
/*                       Functions                                        */
/*========================================================================*/
int wfx_core_probe(const struct hwbus_ops *hwbus_ops,
              struct hwbus_priv *hwbus,
              struct device *pdev,
              struct wfx_common **core,
              const u8 *macaddr,
              bool sdio , bool hif_clkedge)
{
    int err = -EINVAL;
    struct ieee80211_hw *dev;
    struct wfx_common *priv;
    struct wsm_operational_mode mode = {
        .power_mode = wfx_power_mode,
        .disable_more_flag_usage = true,
    };


    dev = wfx_init_common(macaddr, sdio , hif_clkedge);
    if (!dev)
        goto err;

    priv = dev->priv;
    priv->hwbus_ops = hwbus_ops;
    priv->hwbus_priv = hwbus;
    priv->pdev = pdev;
    SET_IEEE80211_DEV(priv->hw, pdev);

    /* Pass struct wfx_common back up */
    *core = priv;


    err = wfx_register_bh(priv);
    if (err) {
        goto err1;
    }

    err = wfx_load_firmware(priv);
    if (err) {
        goto err2;
    }

    msleep(100);

   if (wait_event_interruptible_timeout(priv->wsm_startup_done,
                         priv->firmware_ready,
                         10*HZ) <= 0) {

       HiCtrlReg_t CtrlReg;
       int ret;
       ret = control_reg_read(priv, &CtrlReg);
       if (ret < 0) {
           pr_err("set_wakeup: can't read control register.\n");
       }
       pr_err("Timeout waiting on device startup; HIF control_reg=0x%x\n", CtrlReg.U16CtrlReg);
       err = -ETIMEDOUT;
       goto err2;
    }
    /* Firmware is wake up, configure it */
    wfx_send_pds(priv);

    /* Set low-power mode. */
    wsm_set_operational_mode(priv, &mode);

    wsm_use_multi_tx_conf(priv, false);

    err = wfx_register_common(dev);
    if (err)
        goto err2;

    return err;

err2:
    wfx_unregister_bh(priv);
err1:
    wfx_free_common(dev);
err:
    *core = NULL;
    return err;
}
EXPORT_SYMBOL_GPL(wfx_core_probe);

void wfx_core_release(struct wfx_common *self)
{
    wfx_unregister_common(self->hw);

    /* Disable device interrupts */
    self->hwbus_ops->lock(self->hwbus_priv);
    __wfx_irq_enable(self, 0);
    self->hwbus_ops->unlock(self->hwbus_priv);

    wfx_free_common(self->hw);
    return;
}
EXPORT_SYMBOL_GPL(wfx_core_release);

module_init(wfx_core_init);
module_exit(wfx_core_exit);
