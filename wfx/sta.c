/*
 * Copyright (c) 2017, Silicon Laboratories, Inc.
 *
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


#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/firmware.h>
#include <linux/module.h>
#include <linux/etherdevice.h>

#include "wfx.h"
#include "sta.h"
#include "fwio.h"
#include "bh.h"
#include "debug.h"
#include "wsm.h"

#include "net/mac80211.h"

#include "pds/pds.h"

#if defined(CONFIG_WF200_STA_DEBUG)
#define sta_printk(...) printk(__VA_ARGS__)
#else
#define sta_printk(...)
#endif

#ifndef ERP_INFO_BYTE_OFFSET
#define ERP_INFO_BYTE_OFFSET 2
#endif

#define PAIRWISE_CIPHER_SUITE_COUNT_OFFSET 8u
#define PAIRWISE_CIPHER_SUITE_SIZE 4u
#define AKM_SUITE_COUNT_OFFSET(__pairwiseCount) (2 + PAIRWISE_CIPHER_SUITE_SIZE * (__pairwiseCount))
#define AKM_SUITE_SIZE 4u
#define RSN_CAPA_OFFSET(__akmCount) (2 + AKM_SUITE_SIZE * (__akmCount))

#define RSN_CAPA_MFPR_BIT (1 << 6)
#define RSN_CAPA_MFPC_BIT (1 << 7)

static void wfx_do_join(struct wfx_common *priv);
static void wfx_do_unjoin(struct wfx_common *priv);

static int wfx_upload_beacon(struct wfx_common *priv);
static int wfx_start_ap(struct wfx_common *priv);
static int wfx_update_beaconing(struct wfx_common *priv);
static int wfx_enable_beaconing(struct wfx_common *priv,
				   bool enable);
static void __wfx_sta_notify(struct ieee80211_hw *dev,
				struct ieee80211_vif *vif,
				enum sta_notify_cmd notify_cmd,
				int link_id);
static int __wfx_flush(struct wfx_common *priv, bool drop);

static inline void __wfx_free_event_queue(struct list_head *list)
{
	struct wfx_wsm_event *event, *tmp;
	list_for_each_entry_safe(event, tmp, list, link) {
		list_del(&event->link);
		kfree(event);
	}
}

/* ******************************************************************** */
/* STA API								*/

int wfx_start(struct ieee80211_hw *dev)
{
	struct wfx_common *priv = dev->priv;
	int ret = 0;

	wfx_pm_stay_awake(&priv->pm_state, HZ);
	pr_debug("[STA] wfx_start\n");
	mutex_lock(&priv->conf_mutex);

	/* default EDCA */
	WSM_EDCA_SET(&priv->edca, 0, 0x0002, 0x0003, 0x0007, 47, 0xc8, false);
	WSM_EDCA_SET(&priv->edca, 1, 0x0002, 0x0007, 0x000f, 94, 0xc8, false);
	WSM_EDCA_SET(&priv->edca, 2, 0x0003, 0x000f, 0x03ff, 0, 0xc8, false);
	WSM_EDCA_SET(&priv->edca, 3, 0x0007, 0x000f, 0x03ff, 0, 0xc8, false);
	ret = wsm_set_edca_params(priv, &priv->edca);
	if (ret)
		goto out;

	ret = wfx_set_uapsd_param(priv, &priv->edca);
	if (ret)
		goto out;

	priv->setbssparams_done = false;

	memcpy(priv->mac_addr, dev->wiphy->perm_addr, ETH_ALEN);
	priv->mode = NL80211_IFTYPE_MONITOR;
	priv->wep_default_key_id = -1;

	priv->cqm_beacon_loss_count = 10;

	ret = wfx_setup_mac(priv);
	if (ret)
		goto out;

out:
	mutex_unlock(&priv->conf_mutex);
	return ret;
}

void wfx_stop(struct ieee80211_hw *dev)
{
	struct wfx_common *priv = dev->priv;
	LIST_HEAD(list);
	int i;

	pr_debug("[STA] wfx_stop\n");

	wsm_lock_tx(priv);

	while (down_trylock(&priv->scan.lock)) {
		/* Scan is in progress. Force it to stop. */
		priv->scan.req = NULL;
		schedule();
	}
	up(&priv->scan.lock);

	cancel_delayed_work_sync(&priv->scan.probe_work);
	cancel_delayed_work_sync(&priv->scan.timeout);
	cancel_delayed_work_sync(&priv->clear_recent_scan_work);
	cancel_delayed_work_sync(&priv->join_timeout);
	wfx_cqm_bssloss_sm(priv, 0, 0, 0);
	cancel_work_sync(&priv->unjoin_work);
	cancel_delayed_work_sync(&priv->link_id_gc_work);
	flush_workqueue(priv->workqueue);
	del_timer_sync(&priv->mcast_timeout);
	mutex_lock(&priv->conf_mutex);
	priv->mode = NL80211_IFTYPE_UNSPECIFIED;
	priv->listening = false;

	spin_lock(&priv->event_queue_lock);
	list_splice_init(&priv->event_queue, &list);
	spin_unlock(&priv->event_queue_lock);
	__wfx_free_event_queue(&list);


	priv->join_status = WFX_JOIN_STATUS_PASSIVE;
	priv->join_pending = false;

	for (i = 0; i < 4; i++)
		wfx_queue_clear(&priv->tx_queue[i]);
	mutex_unlock(&priv->conf_mutex);
	tx_policy_clean(priv);

	if (atomic_xchg(&priv->tx_lock, 1) != 1)
		pr_debug("[STA] TX is force-unlocked due to stop request.\n");

	wsm_unlock_tx(priv);
	atomic_xchg(&priv->tx_lock, 0); /* for recovery to work */
}

static int wfx_bssloss_mitigation = 1;
module_param(wfx_bssloss_mitigation, int, 0644);
MODULE_PARM_DESC(wfx_bssloss_mitigation, "BSS Loss mitigation. 0 == disabled, 1 == enabled (default)");


void __wfx_cqm_bssloss_sm(struct wfx_common *priv,
			     int init, int good, int bad)
{
	int tx = 0;

	priv->delayed_link_loss = 0;
	cancel_work_sync(&priv->bss_params_work);

	pr_debug("[STA] CQM BSSLOSS_SM: state: %d init %d good %d bad: %d txlock: %d uj: %d\n",
		 priv->bss_loss_state,
		 init, good, bad,
		 atomic_read(&priv->tx_lock),
		 priv->delayed_unjoin);

	/* If we have a pending unjoin */
	if (priv->delayed_unjoin)
		return;

	if (init) {
		queue_delayed_work(priv->workqueue,
				   &priv->bss_loss_work,
				   HZ);
		priv->bss_loss_state = 0;

		/* Skip the confimration procedure in P2P case */
		if (!priv->vif->p2p && !atomic_read(&priv->tx_lock))
			tx = 1;
	} else if (good) {
		cancel_delayed_work_sync(&priv->bss_loss_work);
		priv->bss_loss_state = 0;
		queue_work(priv->workqueue, &priv->bss_params_work);
	} else if (bad) {
		if (priv->bss_loss_state < 3)
			tx = 1;
	} else {
		cancel_delayed_work_sync(&priv->bss_loss_work);
		priv->bss_loss_state = 0;
	}

	/* Bypass mitigation if it's disabled */
	if (!wfx_bssloss_mitigation)
		tx = 0;

	/* Spit out a NULL packet to our AP if necessary */
	if (tx) {
		struct sk_buff *skb;

		priv->bss_loss_state++;

		skb = ieee80211_nullfunc_get(priv->hw, priv->vif);
		WARN_ON(!skb);
		if (skb)
			wfx_tx(priv->hw, NULL, skb);
	}
}

int wfx_add_interface(struct ieee80211_hw *dev,
			 struct ieee80211_vif *vif)
{
	int ret;
	struct wfx_common *priv = dev->priv;

	vif->driver_flags |= IEEE80211_VIF_BEACON_FILTER |
			     IEEE80211_VIF_SUPPORTS_UAPSD |
			     IEEE80211_VIF_SUPPORTS_CQM_RSSI;

	pr_debug("[STA] wfx_add_interface : type= %d\n", vif->type);

	mutex_lock(&priv->conf_mutex);

	if (priv->mode != NL80211_IFTYPE_MONITOR) {
		mutex_unlock(&priv->conf_mutex);
		return -EOPNOTSUPP;
	}

	switch (vif->type) {
	case NL80211_IFTYPE_STATION:
	case NL80211_IFTYPE_ADHOC:
	case NL80211_IFTYPE_MESH_POINT:
	case NL80211_IFTYPE_AP:
		priv->mode = vif->type;
		break;
	default:
		mutex_unlock(&priv->conf_mutex);
		return -EOPNOTSUPP;
	}

	priv->vif = vif;
	memcpy(priv->mac_addr, vif->addr, ETH_ALEN);
	ret = wfx_setup_mac(priv);
	mutex_unlock(&priv->conf_mutex);
	return ret;
}

void wfx_remove_interface(struct ieee80211_hw *dev,
			     struct ieee80211_vif *vif)
{
	struct wfx_common *priv = dev->priv;
	WsmHiResetFlags_t reset = {
		.ResetStat = true,
	};
	int i;

	pr_debug("[STA] wfx_remove_interface : join_status= %d\n", priv->join_status);

	mutex_lock(&priv->conf_mutex);
	switch (priv->join_status) {
	case WFX_JOIN_STATUS_JOINING:
	case WFX_JOIN_STATUS_PRE_STA:
	case WFX_JOIN_STATUS_STA:
	case WFX_JOIN_STATUS_IBSS:
		wsm_lock_tx(priv);
		if (queue_work(priv->workqueue, &priv->unjoin_work) <= 0)
			wsm_unlock_tx(priv);
		break;
	case WFX_JOIN_STATUS_AP:
		for (i = 0; priv->link_id_map; ++i) {
			if (priv->link_id_map & BIT(i)) {
				wfx_unmap_link(priv, i);
				priv->link_id_map &= ~BIT(i);
			}
		}
		memset(priv->link_id_db, 0, sizeof(priv->link_id_db));
		priv->sta_asleep_mask = 0;
		priv->enable_beacon = false;
		priv->tx_multicast = false;
		priv->aid0_bit_set = false;
		priv->buffered_multicasts = false;
		priv->pspoll_mask = 0;
		/* reset.link_id = 0; */
		wsm_reset(priv, &reset);
		break;
	case WFX_JOIN_STATUS_MONITOR:
		wfx_update_listening(priv, false);
		break;
	default:
		break;
	}
	priv->vif = NULL;
	priv->mode = NL80211_IFTYPE_MONITOR;
	eth_zero_addr(priv->mac_addr);
	memset(&priv->p2p_ps_modeinfo, 0, sizeof(priv->p2p_ps_modeinfo));
	wfx_free_keys(priv);

	wfx_setup_mac(priv);

	priv->listening = false;
	priv->join_status = WFX_JOIN_STATUS_PASSIVE;
	if (!__wfx_flush(priv, true))
		wsm_unlock_tx(priv);

	mutex_unlock(&priv->conf_mutex);
}

int wfx_change_interface(struct ieee80211_hw *dev,
			    struct ieee80211_vif *vif,
			    enum nl80211_iftype new_type,
			    bool p2p)
{
	int ret = 0;
	pr_debug("[STA] wfx_change_interface: new: %d (%d), old: %d (%d)\n", new_type,
		 p2p, vif->type, vif->p2p);

	if (new_type != vif->type || vif->p2p != p2p) {
		wfx_remove_interface(dev, vif);
		vif->type = new_type;
		vif->p2p = p2p;
		ret = wfx_add_interface(dev, vif);
	}

	return ret;
}

int wfx_config(struct ieee80211_hw *dev, u32 changed)
{
	int ret = 0;
	struct wfx_common *priv = dev->priv;
	struct ieee80211_conf *conf = &dev->conf;

	pr_debug("[STA] wfx_config:  %08x\n", changed);

	down(&priv->scan.lock);
	mutex_lock(&priv->conf_mutex);
	if (changed & IEEE80211_CONF_CHANGE_POWER) {
		priv->output_power = conf->power_level;
		pr_debug("[STA] TX power: %d\n", priv->output_power);
		wsm_set_output_power(priv, priv->output_power * 10);
	}

	if ((changed & IEEE80211_CONF_CHANGE_CHANNEL) &&
	    (priv->channel != conf->chandef.chan)) {
		struct ieee80211_channel *ch = conf->chandef.chan;



		pr_debug("[STA] Freq %d (wsm ch: %d).\n",
			 ch->center_freq, ch->hw_value);


#ifdef INSPIRED_BY_SILABS_WF200_DRIVER
		/* __wfx_flush() implicitly locks tx, if successful */
		if (!__wfx_flush(priv, false)) {
			if (!wsm_switch_channel(priv, &channel)) {
				ret = wait_event_timeout(priv->channel_switch_done,
							 !priv->channel_switch_in_progress,
							 3 * HZ);
				if (ret) {
					/* Already unlocks if successful */
					priv->channel = ch;
					ret = 0;
				} else {
					ret = -ETIMEDOUT;
				}
			} else {
				/* Unlock if switch channel fails */
				wsm_unlock_tx(priv);
			}
		}
#else
		priv->channel = ch;
#endif
	}

	if (changed & IEEE80211_CONF_CHANGE_PS) {
		if (!(conf->flags & IEEE80211_CONF_PS))
			priv->powersave_mode.PmMode.PmMode = 0;
		else if (conf->dynamic_ps_timeout <= 0)
			priv->powersave_mode.PmMode.PmMode = 1;
		else {
			priv->powersave_mode.PmMode.PmMode = 1;
			priv->powersave_mode.PmMode.FastPsm = 1;
		}

		/* Firmware requires that value for this 1-byte field must
		 * be specified in units of 500us. Values above the 128ms
		 * threshold are not supported.
		 */
		if (conf->dynamic_ps_timeout >= 0x80)
			priv->powersave_mode.FastPsmIdlePeriod = 0xFF;
		else
			priv->powersave_mode.FastPsmIdlePeriod =
					conf->dynamic_ps_timeout << 1;

		if (priv->join_status == WFX_JOIN_STATUS_STA &&
		    priv->bss_params.AID)
			wfx_set_pm(priv, &priv->powersave_mode);
	}
	if (changed & IEEE80211_CONF_CHANGE_IDLE) {
		struct wsm_operational_mode mode = {
			.power_mode = wfx_power_mode,
			.disable_more_flag_usage = true,
		};

		wsm_lock_tx(priv);
		/* Disable p2p-dev mode forced by TX request */
		if ((priv->join_status == WFX_JOIN_STATUS_MONITOR) &&
		    (conf->flags & IEEE80211_CONF_IDLE) &&
		    !priv->listening) {
			wfx_disable_listening(priv);
			priv->join_status = WFX_JOIN_STATUS_PASSIVE;
		}
		wsm_set_operational_mode(priv, &mode);
		wsm_unlock_tx(priv);
	}

	if (changed & IEEE80211_CONF_CHANGE_RETRY_LIMITS) {
		pr_debug("[STA] Retry limits: %d (long), %d (short).\n",
			 conf->long_frame_max_tx_count,
			 conf->short_frame_max_tx_count);
		spin_lock_bh(&priv->tx_policy_cache.lock);
		priv->long_frame_max_tx_count = conf->long_frame_max_tx_count;
		priv->short_frame_max_tx_count =
			(conf->short_frame_max_tx_count < 0x0F) ?
			conf->short_frame_max_tx_count : 0x0F;
		priv->hw->max_rate_tries = priv->short_frame_max_tx_count;
		spin_unlock_bh(&priv->tx_policy_cache.lock);
	}
	mutex_unlock(&priv->conf_mutex);
	up(&priv->scan.lock);
	return ret;
}

void wfx_update_filtering(struct wfx_common *priv)
{
	int ret;
	bool bssid_filtering = !priv->rx_filter.bssid;
	bool is_p2p = priv->vif && priv->vif->p2p;
	bool is_sta = priv->vif && NL80211_IFTYPE_STATION == priv->vif->type;

	static WsmHiMibBcnFilterEnable_t bf_ctrl;
	static WsmHiMibBcnFilterTable_t bf_tbl = {
		.IeTable[0].IeId = WLAN_EID_VENDOR_SPECIFIC,
		.IeTable[0].HasChanged = 1,
		.IeTable[0].NoLonger = 1,
		.IeTable[0].HasAppeared = 1,
		.IeTable[0].Oui[0] = 0x50,
		.IeTable[0].Oui[1] = 0x6F,
		.IeTable[0].Oui[2] = 0x9A,
		.IeTable[1].IeId = WLAN_EID_HT_OPERATION,
		.IeTable[1].HasChanged = 1,
		.IeTable[1].NoLonger = 1,
		.IeTable[1].HasAppeared = 1,
		.IeTable[2].IeId = WLAN_EID_ERP_INFO,
		.IeTable[2].HasChanged = 1,
		.IeTable[2].NoLonger = 1,
		.IeTable[2].HasAppeared = 1,

	};

	if (priv->join_status == WFX_JOIN_STATUS_PASSIVE)
		return;
	else if (priv->join_status == WFX_JOIN_STATUS_MONITOR)
		bssid_filtering = false;

	if (priv->disable_beacon_filter) {
		bf_ctrl.Enable = 0;
		bf_ctrl.BcnCount = 1;
		bf_tbl.NumOfInfoElmts = __cpu_to_le32(0);
	} else if (is_p2p || !is_sta) {
		bf_ctrl.Enable = WSM_BEACON_FILTER_ENABLE |
			WSM_BEACON_FILTER_AUTO_ERP;
		bf_ctrl.BcnCount = 0;
		bf_tbl.NumOfInfoElmts = __cpu_to_le32(2);
	} else {
		bf_ctrl.Enable = WSM_BEACON_FILTER_ENABLE;
		bf_ctrl.BcnCount = 0;
		bf_tbl.NumOfInfoElmts = __cpu_to_le32(3);
	}
	if (is_p2p)
		bssid_filtering = false;

	ret = wsm_set_rx_filter(priv, &priv->rx_filter);
	if (!ret)
		ret = wsm_set_beacon_filter_table(priv, &bf_tbl);
	if (!ret)
		ret = wsm_beacon_filter_control(priv, &bf_ctrl);
	if (!ret)
		ret = wsm_set_bssid_filtering(priv, bssid_filtering);
	if (!ret)
		ret = wsm_set_multicast_filter(priv, &priv->multicast_filter);
	if (ret)
		wiphy_err(priv->hw->wiphy,
			  "Update filtering failed: %d.\n", ret);
	return;
}

void wfx_update_filtering_work(struct work_struct *work)
{
	struct wfx_common *priv =
		container_of(work, struct wfx_common,
			     update_filtering_work);

	wfx_update_filtering(priv);
}

void wfx_set_beacon_wakeup_period_work(struct work_struct *work)
{
	struct wfx_common *priv =
		container_of(work, struct wfx_common,
			     set_beacon_wakeup_period_work);

	wsm_set_beacon_wakeup_period(priv,
				     priv->beacon_int * priv->join_dtim_period >
				     MAX_BEACON_SKIP_TIME_MS ? 1 :
				     priv->join_dtim_period, 0);
}

u64 wfx_prepare_multicast(struct ieee80211_hw *hw,
			     struct netdev_hw_addr_list *mc_list)
{
	static u8 broadcast_ipv6[ETH_ALEN] = {
		0x33, 0x33, 0x00, 0x00, 0x00, 0x01
	};
	static u8 broadcast_ipv4[ETH_ALEN] = {
		0x01, 0x00, 0x5e, 0x00, 0x00, 0x01
	};
	struct wfx_common *priv = hw->priv;
	struct netdev_hw_addr *ha;
	int count = 0;

	pr_debug("[STA] wfx_prepare_multicast\n");

	/* Disable multicast filtering */
	priv->has_multicast_subscription = false;
	memset(&priv->multicast_filter, 0x00, sizeof(priv->multicast_filter));

	if (netdev_hw_addr_list_count(mc_list) > WSM_MAX_GRP_ADDRTABLE_ENTRIES)
		return 0;

	/* Enable if requested */
	netdev_hw_addr_list_for_each(ha, mc_list) {
		pr_debug("[STA] multicast: %pM\n", ha->addr);
		memcpy(&priv->multicast_filter.AddressList[count],
		       ha->addr, ETH_ALEN);
		if (!ether_addr_equal(ha->addr, broadcast_ipv4) &&
		    !ether_addr_equal(ha->addr, broadcast_ipv6))
			priv->has_multicast_subscription = true;
		count++;
	}

	if (count) {
		priv->multicast_filter.Enable = __cpu_to_le32(1);
		priv->multicast_filter.NumOfAddresses = __cpu_to_le32(count);
	}

	return netdev_hw_addr_list_count(mc_list);
}

void wfx_configure_filter(struct ieee80211_hw *dev,
			     unsigned int changed_flags,
			     unsigned int *total_flags,
			     u64 multicast)
{
	struct wfx_common *priv = dev->priv;
	bool listening = !!(*total_flags &
			    (FIF_OTHER_BSS |
			     FIF_BCN_PRBRESP_PROMISC |
			     FIF_PROBE_REQ));

	*total_flags &= FIF_OTHER_BSS |
			FIF_FCSFAIL |
			FIF_BCN_PRBRESP_PROMISC |
			FIF_PROBE_REQ;


	pr_debug("[STA] wfx_configure_filter : 0x%.8X\n", *total_flags);

	down(&priv->scan.lock);
	mutex_lock(&priv->conf_mutex);

	priv->rx_filter.promiscuous = 0;

	priv->rx_filter.bssid = (*total_flags & (FIF_OTHER_BSS |
			FIF_PROBE_REQ)) ? 1 : 0;
	priv->rx_filter.fcs = (*total_flags & FIF_FCSFAIL) ? 1 : 0;

	priv->disable_beacon_filter = !(*total_flags &
						(FIF_BCN_PRBRESP_PROMISC |
						 FIF_PROBE_REQ));

	if (priv->listening != listening) {
		priv->listening = listening;
		wsm_lock_tx(priv);
		wfx_update_listening(priv, listening);
		wsm_unlock_tx(priv);
	}
	wfx_update_filtering(priv);
	mutex_unlock(&priv->conf_mutex);
	up(&priv->scan.lock);
}

int wfx_conf_tx(struct ieee80211_hw *dev, struct ieee80211_vif *vif,
		   u16 queue, const struct ieee80211_tx_queue_params *params)
{
	struct wfx_common *priv = dev->priv;
	int ret = 0;
	/* To prevent re-applying PM request OID again and again*/
	uint16 old_uapsd_flags, new_uapsd_flags;

	pr_debug("[STA] wfx_conf_tx\n");

	mutex_lock(&priv->conf_mutex);

	if (queue < dev->queues) {
		memcpy(&old_uapsd_flags, &priv->uapsd_info, sizeof(old_uapsd_flags));

		WSM_TX_QUEUE_SET(&priv->tx_queue_params, queue, 0, 0, 0);
		ret = wsm_set_tx_queue_params(priv,
					      &priv->tx_queue_params.params[queue], queue);
		if (ret) {
			ret = -EINVAL;
			goto out;
		}

		WSM_EDCA_SET(&priv->edca, queue, params->aifs,
			     params->cw_min, params->cw_max,
			     params->txop, 0xc8,
			     params->uapsd);
		ret = wsm_set_edca_params(priv, &priv->edca);
		if (ret) {
			ret = -EINVAL;
			goto out;
		}

		if (priv->mode == NL80211_IFTYPE_STATION) {
			ret = wfx_set_uapsd_param(priv, &priv->edca);
			memcpy(&new_uapsd_flags, &priv->uapsd_info, sizeof(new_uapsd_flags));
			if (!ret && priv->setbssparams_done &&
			    (priv->join_status == WFX_JOIN_STATUS_STA) &&
				/* (old_uapsd_flags != le16_to_cpu(priv->uapsd_info.uapsd_flags))) */
			    (old_uapsd_flags != new_uapsd_flags))	
				ret = wfx_set_pm(priv, &priv->powersave_mode);
		}
	} else {
		ret = -EINVAL;
	}

out:
	mutex_unlock(&priv->conf_mutex);
	return ret;
}

int wfx_get_stats(struct ieee80211_hw *dev,
		     struct ieee80211_low_level_stats *stats)
{
	struct wfx_common *priv = dev->priv;

	memcpy(stats, &priv->stats, sizeof(*stats));
	return 0;
}

int wfx_set_pm(struct wfx_common *priv, const WsmHiSetPmModeReqBody_t *arg)
{
	WsmHiSetPmModeReqBody_t pm = *arg;
	uint16 uapsd_flags;
 	memcpy(&uapsd_flags, &priv->uapsd_info, sizeof(uapsd_flags));

	if (uapsd_flags != 0)
		pm.PmMode.FastPsm = 0;

	pm.PmMode.FastPsm = 0;
	pm.PmMode.PmMode = 0;
	if (memcmp(&pm, &priv->firmware_ps_mode,
		   sizeof(WsmHiSetPmModeReqBody_t))) {
		priv->firmware_ps_mode = pm;
		return wsm_set_pm(priv, &pm);
	} else {
		return 0;
	}
}

int wfx_set_key(struct ieee80211_hw *dev, enum set_key_cmd cmd,
		   struct ieee80211_vif *vif, struct ieee80211_sta *sta,
		   struct ieee80211_key_conf *key)
{
	int ret = -EOPNOTSUPP;
	struct wfx_common *priv = dev->priv;
	struct ieee80211_key_seq seq;

	pr_debug("[STA] wfx_set _key\n");

	mutex_lock(&priv->conf_mutex);

	if (cmd == SET_KEY) {
		u8 *peer_addr = NULL;
		int pairwise = (key->flags & IEEE80211_KEY_FLAG_PAIRWISE) ?
			1 : 0;
		int idx = wfx_alloc_key(priv);
		WsmHiAddKeyReqBody_t *wsm_key = &priv->keys[idx];

		if (idx < 0) {
			ret = -EINVAL;
			goto finally;
		}

		if (sta)
			peer_addr = sta->addr;

		key->flags |= IEEE80211_KEY_FLAG_PUT_IV_SPACE |
			      IEEE80211_KEY_FLAG_RESERVE_TAILROOM;

		switch (key->cipher) {
		case WLAN_CIPHER_SUITE_WEP40:
		case WLAN_CIPHER_SUITE_WEP104:
			if (key->keylen > 16) {
				wfx_free_key(priv, idx);
				ret = -EINVAL;
				goto finally;
			}

			if (pairwise) {
				wsm_key->Type = WSM_KEY_TYPE_WEP_PAIRWISE;
				memcpy(wsm_key->Key.WepPairwiseKey.PeerAddress,
				       peer_addr, ETH_ALEN);
				memcpy(wsm_key->Key.WepPairwiseKey.KeyData,
				       &key->key[0], key->keylen);
				wsm_key->Key.WepPairwiseKey.KeyLength = key->keylen;
			} else {
				wsm_key->Type = WSM_KEY_TYPE_WEP_DEFAULT;
				memcpy(wsm_key->Key.WepGroupKey.KeyData,
				       &key->key[0], key->keylen);
				wsm_key->Key.WepGroupKey.KeyLength = key->keylen;
				wsm_key->Key.WepGroupKey.KeyId = key->keyidx;
			}
			break;
		case WLAN_CIPHER_SUITE_TKIP:
			ieee80211_get_key_rx_seq(key, 0, &seq);
			if (pairwise) {
				wsm_key->Type = WSM_KEY_TYPE_TKIP_PAIRWISE;
				memcpy(wsm_key->Key.TkipPairwiseKey.PeerAddress,
				       peer_addr, ETH_ALEN);
				memcpy(wsm_key->Key.TkipPairwiseKey.TkipKeyData,
				       &key->key[0], 16);
				memcpy(wsm_key->Key.TkipPairwiseKey.TxMicKey,
				       &key->key[16], 8);
				memcpy(wsm_key->Key.TkipPairwiseKey.RxMicKey,
				       &key->key[24], 8);
			} else {
				size_t mic_offset =
					(priv->mode == NL80211_IFTYPE_AP) ?
					16 : 24;
				wsm_key->Type = WSM_KEY_TYPE_TKIP_GROUP;
				memcpy(wsm_key->Key.TkipGroupKey.TkipKeyData,
				       &key->key[0], 16);
				memcpy(wsm_key->Key.TkipGroupKey.RxMicKey,
				       &key->key[mic_offset], 8);

				wsm_key->Key.TkipGroupKey.RxSequenceCounter[0] = seq.tkip.iv16 & 0xff;
				wsm_key->Key.TkipGroupKey.RxSequenceCounter[1] = (seq.tkip.iv16 >> 8) & 0xff;
				wsm_key->Key.TkipGroupKey.RxSequenceCounter[2] = seq.tkip.iv32 & 0xff;
				wsm_key->Key.TkipGroupKey.RxSequenceCounter[3] = (seq.tkip.iv32 >> 8) & 0xff;
				wsm_key->Key.TkipGroupKey.RxSequenceCounter[4] = (seq.tkip.iv32 >> 16) & 0xff;
				wsm_key->Key.TkipGroupKey.RxSequenceCounter[5] = (seq.tkip.iv32 >> 24) & 0xff;
				wsm_key->Key.TkipGroupKey.RxSequenceCounter[6] = 0;
				wsm_key->Key.TkipGroupKey.RxSequenceCounter[7] = 0;

				wsm_key->Key.TkipGroupKey.KeyId = key->keyidx;
			}
			break;
		case WLAN_CIPHER_SUITE_CCMP:
			ieee80211_get_key_rx_seq(key, 0, &seq);
			if (pairwise) {
				wsm_key->Type = WSM_KEY_TYPE_AES_PAIRWISE;
				memcpy(wsm_key->Key.AesPairwiseKey.PeerAddress,
				       peer_addr, ETH_ALEN);
				memcpy(wsm_key->Key.AesPairwiseKey.AesKeyData,
				       &key->key[0], 16);
			} else {
				wsm_key->Type = WSM_KEY_TYPE_AES_GROUP;
				memcpy(wsm_key->Key.AesGroupKey.AesKeyData,
				       &key->key[0], 16);

				wsm_key->Key.AesGroupKey.RxSequenceCounter[0] = seq.ccmp.pn[5];
				wsm_key->Key.AesGroupKey.RxSequenceCounter[1] = seq.ccmp.pn[4];
				wsm_key->Key.AesGroupKey.RxSequenceCounter[2] = seq.ccmp.pn[3];
				wsm_key->Key.AesGroupKey.RxSequenceCounter[3] = seq.ccmp.pn[2];
				wsm_key->Key.AesGroupKey.RxSequenceCounter[4] = seq.ccmp.pn[1];
				wsm_key->Key.AesGroupKey.RxSequenceCounter[5] = seq.ccmp.pn[0];
				wsm_key->Key.AesGroupKey.RxSequenceCounter[6] = 0;
				wsm_key->Key.AesGroupKey.RxSequenceCounter[7] = 0;
				wsm_key->Key.AesGroupKey.KeyId = key->keyidx;
			}
			break;
		case WLAN_CIPHER_SUITE_SMS4:
			if (pairwise) {
				wsm_key->Type = WSM_KEY_TYPE_WAPI_PAIRWISE;
				memcpy(wsm_key->Key.WapiPairwiseKey.PeerAddress,
				       peer_addr, ETH_ALEN);
				memcpy(wsm_key->Key.WapiPairwiseKey.WapiKeyData,
				       &key->key[0], 16);
				memcpy(wsm_key->Key.WapiPairwiseKey.MicKeyData,
				       &key->key[16], 16);
				wsm_key->Key.WapiPairwiseKey.KeyId = key->keyidx;
			} else {
				wsm_key->Type = WSM_KEY_TYPE_WAPI_GROUP;
				memcpy(wsm_key->Key.WapiGroupKey.WapiKeyData,
				       &key->key[0],  16);
				memcpy(wsm_key->Key.WapiGroupKey.MicKeyData,
				       &key->key[16], 16);
				wsm_key->Key.WapiGroupKey.KeyId = key->keyidx;
			}
			break;
		case WLAN_CIPHER_SUITE_AES_CMAC:
                    ieee80211_get_key_rx_seq(key, 0, &seq);

		    pr_debug("set AES_CMAC, key_id %d, IPN = 0x%02x%02x%02x%02x%02x%02x\n",
		            key->keyidx,
		            seq.aes_cmac.pn[0],
		            seq.aes_cmac.pn[1],
		            seq.aes_cmac.pn[2],
		            seq.aes_cmac.pn[3],
		            seq.aes_cmac.pn[4],
		            seq.aes_cmac.pn[5]);

                    wsm_key->Type = WSM_KEY_TYPE_IGTK_GROUP;
                    // Copy key in wsm message
                    memcpy(wsm_key->Key.IgtkGroupKey.IGTKKeyData,
                           &key->key[0],
                           key->keylen);

                    // Reverse the bit order to match the IPN receive in frame
                    wsm_key->Key.IgtkGroupKey.IPN[0] = seq.aes_cmac.pn[5];
                    wsm_key->Key.IgtkGroupKey.IPN[1] = seq.aes_cmac.pn[4];
                    wsm_key->Key.IgtkGroupKey.IPN[2] = seq.aes_cmac.pn[3];
                    wsm_key->Key.IgtkGroupKey.IPN[3] = seq.aes_cmac.pn[2];
                    wsm_key->Key.IgtkGroupKey.IPN[4] = seq.aes_cmac.pn[1];
                    wsm_key->Key.IgtkGroupKey.IPN[5] = seq.aes_cmac.pn[0];

		    wsm_key->Key.IgtkGroupKey.KeyId = key->keyidx;
		    break;
		default:
			pr_warn("Unhandled key type %d\n", key->cipher);
			wfx_free_key(priv, idx);
			ret = -EOPNOTSUPP;
			goto finally;
		}
		ret = wsm_add_key(priv, wsm_key);
		if (!ret)
			key->hw_key_idx = idx;
		else
			wfx_free_key(priv, idx);
	} else if (cmd == DISABLE_KEY) {
		WsmHiRemoveKeyReqBody_t wsm_key = {
			.EntryIndex = key->hw_key_idx,
		};

		if (wsm_key.EntryIndex > WSM_KEY_MAX_INDEX) {
			ret = -EINVAL;
			goto finally;
		}

		wfx_free_key(priv, wsm_key.EntryIndex);
		ret = wsm_remove_key(priv, &wsm_key);
	} else {
		pr_warn("Unhandled key command %d\n", cmd);
	}

finally:
	mutex_unlock(&priv->conf_mutex);
	return ret;
}

void wfx_wep_key_work(struct work_struct *work)
{
	struct wfx_common *priv =
		container_of(work, struct wfx_common, wep_key_work);
	u8 queue_id = wfx_queue_get_queue_id(priv->pending_frame_id);
	struct wfx_queue *queue = &priv->tx_queue[queue_id];
	__le32 wep_default_key_id = __cpu_to_le32(
		priv->wep_default_key_id);

	pr_debug("[STA] Setting default WEP key: %d\n",
		 priv->wep_default_key_id);
	wsm_flush_tx(priv);
	wsm_write_mib(priv, WSM_MIB_ID_DOT11_WEP_DEFAULT_KEY_ID,
		      &wep_default_key_id, sizeof(wep_default_key_id));
	wfx_queue_requeue(queue, priv->pending_frame_id);
	wsm_unlock_tx(priv);
}

int wfx_set_rts_threshold(struct ieee80211_hw *hw, u32 value)
{
	int ret = 0;
	__le32 val32;
	struct wfx_common *priv = hw->priv;

	pr_debug("[STA] wfx_set_rts_threshold = %d\n", value);

	if (priv->mode == NL80211_IFTYPE_UNSPECIFIED)
		return 0;

	if (value != (u32) -1)
		val32 = __cpu_to_le32(value);
	else
		val32 = 0; /* disabled */

	if (priv->mode == NL80211_IFTYPE_UNSPECIFIED) { /*EV can be removed : exited before this line*/
		/* device is down, can _not_ set threshold */
		ret = -ENODEV;
		goto out;
	}

	if (priv->rts_threshold == value)
		goto out;

	/* mutex_lock(&priv->conf_mutex); */
	ret = wsm_write_mib(priv, WSM_MIB_ID_DOT11_RTS_THRESHOLD,
			    &val32, sizeof(val32));
	if (!ret)
		priv->rts_threshold = value;
	/* mutex_unlock(&priv->conf_mutex); */

out:
	return ret;
}

/* If successful, LOCKS the TX queue! */
static int __wfx_flush(struct wfx_common *priv, bool drop)
{
	int i, ret;

	for (;;) {
		if (drop) {
			for (i = 0; i < 4; ++i)
				wfx_queue_clear(&priv->tx_queue[i]);
		} else {
			ret = wait_event_timeout(
				priv->tx_queue_stats.wait_link_id_empty,
				wfx_queue_stats_is_empty(
					&priv->tx_queue_stats, -1),
				2 * HZ);
		}

		if (!drop && ret <= 0) {
			ret = -ETIMEDOUT;
			break;
		} else {
			ret = 0;
		}

		wsm_lock_tx(priv);
		if (!wfx_queue_stats_is_empty(&priv->tx_queue_stats, -1)) {
			/* Highly unlikely: WSM requeued frames. */
			wsm_unlock_tx(priv);
			continue;
		}
		break;
	}
	return ret;
}

void wfx_flush(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
		  u32 queues, bool drop)
{
	struct wfx_common *priv = hw->priv;

	pr_debug("[STA] wfx_flush\n");

	switch (priv->mode) {
	case NL80211_IFTYPE_MONITOR:
		drop = true;
		break;
	case NL80211_IFTYPE_AP:
		if (!priv->enable_beacon)
			drop = true;
		break;
	}

	if (!__wfx_flush(priv, drop))
		wsm_unlock_tx(priv);

	return;
}

/* ******************************************************************** */
/* WSM callbacks							*/

void wfx_free_event_queue(struct wfx_common *priv)
{
	LIST_HEAD(list);

	spin_lock(&priv->event_queue_lock);
	list_splice_init(&priv->event_queue, &list);
	spin_unlock(&priv->event_queue_lock);

	__wfx_free_event_queue(&list);
}

void wfx_event_handler(struct work_struct *work)
{
	struct wfx_common *priv =
		container_of(work, struct wfx_common, event_handler);
	struct wfx_wsm_event *event;
	LIST_HEAD(list);

	spin_lock(&priv->event_queue_lock);
	list_splice_init(&priv->event_queue, &list);
	spin_unlock(&priv->event_queue_lock);

	list_for_each_entry(event, &list, link) {
		switch (event->evt.EventId) {
		case WSM_EVENT_IND_ERROR:
			pr_err("Unhandled WSM Error from LMAC\n");
			break;
		case WSM_EVENT_IND_BSSLOST:
			pr_debug("[CQM] BSS lost.\n");
			cancel_work_sync(&priv->unjoin_work);
			if (!down_trylock(&priv->scan.lock)) {
				wfx_cqm_bssloss_sm(priv, 1, 0, 0);
				up(&priv->scan.lock);
			} else {
				/* Scan is in progress. Delay reporting.
				 * Scan complete will trigger bss_loss_work
				 */
				priv->delayed_link_loss = 1;
				/* Also start a watchdog. */
				queue_delayed_work(priv->workqueue,
						   &priv->bss_loss_work, 5*HZ);
			}
			break;
		case WSM_EVENT_IND_BSSREGAINED:
			pr_debug("[CQM] BSS regained.\n");
			wfx_cqm_bssloss_sm(priv, 0, 0, 0);
			cancel_work_sync(&priv->unjoin_work);
			break;
		case WSM_EVENT_IND_RADAR:
			wiphy_info(priv->hw->wiphy, "radar pulse detected\n");
			break;
		case WSM_EVENT_IND_RCPI_RSSI:
		{
			/* RSSI: signed Q8.0, RCPI: unsigned Q7.1
			 * RSSI = RCPI / 2 - 110
			 */
			int rcpi_rssi = (int)(event->evt.EventData.RcpiRssi);
			int cqm_evt;
			if (priv->cqm_use_rssi)
				rcpi_rssi = (s8)rcpi_rssi;
			else
				rcpi_rssi =  rcpi_rssi / 2 - 110;

			cqm_evt = (rcpi_rssi <= priv->cqm_rssi_thold) ?
				NL80211_CQM_RSSI_THRESHOLD_EVENT_LOW :
				NL80211_CQM_RSSI_THRESHOLD_EVENT_HIGH;
			pr_debug("[CQM] RSSI event: %d.\n", rcpi_rssi);
			ieee80211_cqm_rssi_notify(priv->vif, cqm_evt,
						  GFP_KERNEL);
			break;
		}
		case WSM_EVENT_IND_BT_INACTIVE:
			pr_warn("Unhandled BT INACTIVE from LMAC\n");
			break;
		case WSM_EVENT_IND_BT_ACTIVE:
			pr_warn("Unhandled BT ACTIVE from LMAC\n");
			break;
		}
	}
	__wfx_free_event_queue(&list);
}

void wfx_bss_loss_work(struct work_struct *work)
{
	struct wfx_common *priv =
		container_of(work, struct wfx_common, bss_loss_work.work);

	pr_debug("[CQM] Reporting connection loss.\n");
	ieee80211_connection_loss(priv->vif);
}

void wfx_bss_params_work(struct work_struct *work)
{
	struct wfx_common *priv =
		container_of(work, struct wfx_common, bss_params_work);
	mutex_lock(&priv->conf_mutex);

	priv->bss_params.BssFlags.LostCountOnly = 1;
	wsm_set_bss_params(priv, &priv->bss_params);
	priv->bss_params.BssFlags.LostCountOnly = 0;

	mutex_unlock(&priv->conf_mutex);
}

int wfx_send_pds(struct wfx_common *priv)
{
    int ret = 0;

    PDS_BUFFERS* ps_PDSDataBuffers;
    char* pc_PDSMsg;
    u16 ui16_pc_PDSMsgLen;
    u8 ui8_DataBufferIndex;
    WsmHiMibRcpiRssiThreshold_t threshold = {
            .Detection = 1,
            .Upperthresh = 1,
            .Lowerthresh = 1,
        .RollingAverageCount = 16,
    };

    struct wsm_configuration cfg;

    (void)memset(&cfg, 0, sizeof(struct wsm_configuration));
    memcpy(cfg.cnf_part.Dot11StationId, &priv->mac_addr[0], WSM_API_DOT11_STATION_ID_SIZE);
    if (threshold.Use)
        priv->cqm_use_rssi = true;
    if (WF200_HW_REV == priv->hw_revision)
    {
        if (!priv->pds) {
            ret = request_firmware(&priv->pds, priv->pds_path, priv->pdev);
            if (ret) {
                pr_err("WFX : Can't load PDS file %s.\n", priv->pds_path);
                return ret;
            }
        }

        ps_PDSDataBuffers = pds_compress_json(priv->pds->data);

        for (ui8_DataBufferIndex = 0; ui8_DataBufferIndex < ps_PDSDataBuffers->u8_NbBuffersUsed; ui8_DataBufferIndex++)
        {
            pc_PDSMsg = ps_PDSDataBuffers->apc_output_strings[ui8_DataBufferIndex];
            ui16_pc_PDSMsgLen = strlen(pc_PDSMsg) +1;

            if (ui16_pc_PDSMsgLen < 1500 )
            {
                cfg.req_part.DpdData.Length = ui16_pc_PDSMsgLen;
                pc_PDSMsg[cfg.req_part.DpdData.Length] = 0;

                ret = wsm_configuration(priv, &cfg, pc_PDSMsg);
            }
            else
            {
                pr_err("WFX : PDS message too long");
            }
        }

        pds_release_buffers(ps_PDSDataBuffers);
    }


    if (ret)
        return ret;

    /* Configure RSSI/SCPI reporting as RSSI. */
    wsm_set_rcpi_rssi_threshold(priv, &threshold);

    return 0;
}

int wfx_setup_mac(struct wfx_common *priv)
{
	int ret = 0;

	struct wsm_configuration cfg;

	(void)memset(&cfg, 0, sizeof(struct wsm_configuration));
	memcpy(cfg.cnf_part.Dot11StationId, &priv->mac_addr[0], WSM_API_DOT11_STATION_ID_SIZE);

	cfg.req_part.DpdData.Length = 0;
	ret = wsm_configuration(priv, &cfg, NULL);

	if (ret)
		return ret;

	return 0;
}

static void wfx_join_complete(struct wfx_common *priv)
{
	pr_debug("[STA] Join complete (%d)\n", priv->join_complete_status);

	priv->join_pending = false;
	if (priv->join_complete_status) {
		priv->join_status = WFX_JOIN_STATUS_PASSIVE;
		wfx_update_listening(priv, priv->listening);
		wfx_do_unjoin(priv);
		ieee80211_connection_loss(priv->vif);
	} else {
		if (priv->mode == NL80211_IFTYPE_ADHOC)
			priv->join_status = WFX_JOIN_STATUS_IBSS;
		else
			priv->join_status = WFX_JOIN_STATUS_PRE_STA;
	}
	wsm_unlock_tx(priv); /* Clearing the lock held before do_join() */
}

void wfx_join_complete_work(struct work_struct *work)
{
	struct wfx_common *priv =
		container_of(work, struct wfx_common, join_complete_work);

	mutex_lock(&priv->conf_mutex);
	wfx_join_complete(priv);
	mutex_unlock(&priv->conf_mutex);

}

void wfx_join_complete_cb(struct wfx_common *priv,
		WsmHiJoinCompleteIndBody_t *arg)
{
	pr_debug("[STA] wfx_join_complete_cb called, status=%d.\n",
		 arg->Status);

	if (cancel_delayed_work(&priv->join_timeout)) {
		priv->join_complete_status = arg->Status;
		queue_work(priv->workqueue, &priv->join_complete_work);
	} 
}

/* MUST be called with tx_lock held!  It will be unlocked for us. */
static void wfx_do_join(struct wfx_common *priv)
{
	const u8 *bssid;
	const u8 *rsnie;
	u16 *pairwiseCount;
	u16 *akmCount;
	u16 rsnCapabilities;
	u8 mfpc = 0;
	u8 mfpr = 0;
	struct ieee80211_bss_conf *conf = &priv->vif->bss_conf;
	struct cfg80211_bss *bss = NULL;
	struct wsm_protected_mgmt_policy mgmt_policy;
	WsmHiJoinReqBody_t join = {
		.Mode = conf->ibss_joined ?
				WSM_MODE_IBSS : WSM_MODE_BSS,
		.PreambleType = WSM_PREAMBLE_LONG,
		.ProbeForJoin = 1,
		.AtimWindow = 0,
		.BasicRateSet = wfx_rate_mask_to_wsm(priv,
							  conf->basic_rates),
	};


	if (delayed_work_pending(&priv->join_timeout)) {
		pr_warn("[STA] - Join request already pending, skipping..\n");
		wsm_unlock_tx(priv);
		return;
	}

	if (priv->join_status)
		wfx_do_unjoin(priv);

	bssid = priv->vif->bss_conf.bssid;

	bss = cfg80211_get_bss(priv->hw->wiphy, priv->channel, bssid, NULL, 0,
			       IEEE80211_BSS_TYPE_ANY, IEEE80211_PRIVACY_ANY);

	if (!bss && !conf->ibss_joined) {
		wsm_unlock_tx(priv);
		return;
	}

	mutex_lock(&priv->conf_mutex);

	/* Under the conf lock: check scan status and
	 * bail out if it is in progress.
	 */
	if (atomic_read(&priv->scan.in_progress)) {
		wsm_unlock_tx(priv);
		goto done_put;
	}

	priv->join_pending = true;

	/* Sanity check basic rates */
	if (!join.BasicRateSet)
		join.BasicRateSet = 7;

	/* Sanity check beacon interval */
	if (!priv->beacon_int)
		priv->beacon_int = 1;

	join.BeaconInterval = priv->beacon_int;


	if (priv->hw->conf.ps_dtim_period)
		priv->join_dtim_period = priv->hw->conf.ps_dtim_period;
	join.Reserved = priv->join_dtim_period;

	join.ChannelNumber = priv->channel->hw_value;
	join.Band =  WSM_PHY_BAND_2_4G;
	memcpy(join.BSSID, bssid, sizeof(join.BSSID));

	pr_debug("[STA] Join BSSID: %pM DTIM: %d, interval: %d\n",
		 join.BSSID,
		 join.Reserved, priv->beacon_int);

	if (!conf->ibss_joined) {
		const u8 *ssidie;
		rcu_read_lock();
		ssidie = ieee80211_bss_get_ie(bss, WLAN_EID_SSID);
		if (ssidie) {
			join.SSIDLength = ssidie[1];
			memcpy(join.SSID, &ssidie[2], join.SSIDLength);
		}
		rcu_read_unlock();
	}


	if (priv->vif->p2p) {
		join.JoinFlags.Owner = 1;
		join.BasicRateSet =
			wfx_rate_mask_to_wsm(priv, 0xFF0);
	}

	pr_debug("[STA] ready to flush Tx in %s(%d)\n",__func__,__LINE__);
	wsm_flush_tx(priv);
	pr_debug("[STA] flush Tx done in %s(%d)\n",__func__,__LINE__);

	/* Stay Awake for Join and Auth Timeouts and a bit more */
	wfx_pm_stay_awake(&priv->pm_state,
			     WFX_JOIN_TIMEOUT + WFX_AUTH_TIMEOUT);

	pr_debug("[STA] ready to wfx_update_listening in %s(%d)\n",__func__,__LINE__);

	wfx_update_listening(priv, false);

	pr_debug("[STA] ready to Turn on Block ACKs in %s(%d)\n",__func__,__LINE__);

	/* Turn on Block ACKs */
	wsm_set_block_ack_policy(priv, priv->ba_tx_tid_mask,
				 priv->ba_rx_tid_mask);

	/* Set up timeout */
	if (join.JoinFlags.ForceWithInd) {
		priv->join_status = WFX_JOIN_STATUS_JOINING;
		queue_delayed_work(priv->workqueue,
				   &priv->join_timeout,
				   WFX_JOIN_TIMEOUT);
	}


	/* 802.11w protected mgmt frames */

	// retrieve MFPC and MFPR flags from beacon or PBRSP

	// 1. Get the RSN IE
	rsnie = ieee80211_bss_get_ie (bss, WLAN_EID_RSN);

	if (rsnie != NULL)
	{
        // 2. Retrieve Pairwise Cipher Count
        pairwiseCount = (u16 *) (rsnie + PAIRWISE_CIPHER_SUITE_COUNT_OFFSET);

        // 3. Retrieve AKM Suite Count
        akmCount = (u16 *) (((u8*)pairwiseCount) + AKM_SUITE_COUNT_OFFSET(*pairwiseCount));

        // 4. Retrieve RSN Capabilities
        rsnCapabilities = *(u16 *) (((u8*)akmCount) + RSN_CAPA_OFFSET(*akmCount));

            // 5. Read MFPC and MFPR bits
        mfpc = ( (rsnCapabilities & RSN_CAPA_MFPC_BIT) != 0);
        mfpr = ( (rsnCapabilities & RSN_CAPA_MFPR_BIT) != 0);

        pr_debug ("PW count = %d, AKM count = %d, rsnCapa = 0x%04x, mfpc = %d; mfpr = %d\n",
                *pairwiseCount,
                *akmCount,
                rsnCapabilities,
                mfpc,
                mfpr);
	}

   // 6. Set firmware accordingly
   if (mfpc == 0)
   {
       // No PMF
       mgmt_policy.protectedMgmtEnable = 0;
       mgmt_policy.unprotectedMgmtFramesAllowed = 1; // Should be ignored by FW
       mgmt_policy.encryptionForAuthFrame = 1; // Should be ignored by FW
   }
   else if (mfpr == 0)
   {
       // PMF capable but not required
       mgmt_policy.protectedMgmtEnable = 1;
       mgmt_policy.unprotectedMgmtFramesAllowed = 1;
       mgmt_policy.encryptionForAuthFrame = 1;
   }
   else
   {
       // PMF required
       mgmt_policy.protectedMgmtEnable = 1;
       mgmt_policy.unprotectedMgmtFramesAllowed = 0;
       mgmt_policy.encryptionForAuthFrame = 1;
   }

   wsm_set_protected_mgmt_policy(priv, &mgmt_policy);

	/* Perform actual join */
	if (wsm_join(priv, &join)) {
		cancel_delayed_work_sync(&priv->join_timeout);
		wfx_update_listening(priv, priv->listening);
		/* Tx lock still held, unjoin will clear it. */
		if (queue_work(priv->workqueue, &priv->unjoin_work) <= 0)
			wsm_unlock_tx(priv);
	} else {
		if (!(join.JoinFlags.ForceWithInd))
			wfx_join_complete(priv); /* Will clear tx_lock */

		/* Upload keys */
		wfx_upload_keys(priv);

		/* Due to beacon filtering it is possible that the
		 * AP's beacon is not known for the mac80211 stack.
		 * Disable filtering temporary to make sure the stack
		 * receives at least one
		 */
		priv->disable_beacon_filter = true;
	}
	wfx_update_filtering(priv);


done_put:
	mutex_unlock(&priv->conf_mutex);
	if (bss)
		cfg80211_put_bss(priv->hw->wiphy, bss);

}

void wfx_join_timeout(struct work_struct *work)
{
	struct wfx_common *priv =
		container_of(work, struct wfx_common, join_timeout.work);
	pr_debug("[WSM] Join timed out.\n");
	wsm_lock_tx(priv);
	if (queue_work(priv->workqueue, &priv->unjoin_work) <= 0)
		wsm_unlock_tx(priv);
}

static void wfx_do_unjoin(struct wfx_common *priv)
{
	WsmHiResetFlags_t reset = {
		.ResetStat = true,
	};

	cancel_delayed_work_sync(&priv->join_timeout);

	mutex_lock(&priv->conf_mutex);
	priv->join_pending = false;

	if (atomic_read(&priv->scan.in_progress)) {
		if (priv->delayed_unjoin)
			wiphy_dbg(priv->hw->wiphy, "Delayed unjoin is already scheduled.\n");
		else
			priv->delayed_unjoin = true;
		goto done;
	}

	priv->delayed_link_loss = false;

	if (!priv->join_status)
		goto done;

	if (priv->join_status == WFX_JOIN_STATUS_AP)
		goto done;

	cancel_work_sync(&priv->update_filtering_work);
	cancel_work_sync(&priv->set_beacon_wakeup_period_work);
	priv->join_status = WFX_JOIN_STATUS_PASSIVE;

	/* Unjoin is a reset. */
	wsm_flush_tx(priv);
	wsm_keep_alive_period(priv, 0);
	wsm_reset(priv, &reset);
	wsm_set_output_power(priv, priv->output_power * 10);
	priv->join_dtim_period = 0;
	wfx_setup_mac(priv);
	wfx_free_event_queue(priv);
	cancel_work_sync(&priv->event_handler);
	wfx_update_listening(priv, priv->listening);
	wfx_cqm_bssloss_sm(priv, 0, 0, 0);

	/* Disable Block ACKs */
	wsm_set_block_ack_policy(priv, 0, 0);

	priv->disable_beacon_filter = false;
	wfx_update_filtering(priv);
	memset(&priv->association_mode, 0,
	       sizeof(priv->association_mode));
	memset(&priv->bss_params, 0, sizeof(priv->bss_params));
	priv->setbssparams_done = false;
	memset(&priv->firmware_ps_mode, 0,
	       sizeof(priv->firmware_ps_mode));

	pr_debug("[STA] Unjoin completed.\n");

done:
	mutex_unlock(&priv->conf_mutex);
}

void wfx_unjoin_work(struct work_struct *work)
{
	struct wfx_common *priv =
		container_of(work, struct wfx_common, unjoin_work);

	wfx_do_unjoin(priv);

	wsm_unlock_tx(priv);
}

int wfx_enable_listening(struct wfx_common *priv)
{
	WsmHiStartReqBody_t start = {
		.Mode = {
				.StartMode = WSM_START_MODE_P2P_DEV,
		},
		.Band = WSM_PHY_BAND_2_4G,
		.BeaconInterval = 100,
		.DTIMPeriod = 1,
		.ProbeDelay = 0,
		.BasicRateSet = 0x0F,
	};

	if (priv->channel) {
		start.Band =  WSM_PHY_BAND_2_4G;
		start.ChannelNumber = priv->channel->hw_value;
	} else {
		start.Band = WSM_PHY_BAND_2_4G;
		start.ChannelNumber = 1;
	}

	return wsm_start(priv, &start);
}

int wfx_disable_listening(struct wfx_common *priv)
{
	int ret;
	WsmHiResetFlags_t reset = {
		.ResetStat = true,
	};
	ret = wsm_reset(priv, &reset);
	return ret;
}

void wfx_update_listening(struct wfx_common *priv, bool enabled)
{
	if (enabled) {
		if (priv->join_status == WFX_JOIN_STATUS_PASSIVE) {
			if (!wfx_enable_listening(priv))
				priv->join_status = WFX_JOIN_STATUS_MONITOR;
			wsm_set_probe_responder(priv, true);
		}
	} else {
		if (priv->join_status == WFX_JOIN_STATUS_MONITOR) {
			if (!wfx_disable_listening(priv))
				priv->join_status = WFX_JOIN_STATUS_PASSIVE;
			wsm_set_probe_responder(priv, false);
		}
	}
}

int wfx_set_uapsd_param(struct wfx_common *priv,
			   const struct wsm_edca_params *arg)
{
	int ret;
	/* u16 uapsd_flags = 0; */

	/* Here's the mapping AC [queue, bit]
	 *  VO [0,3], VI [1, 2], BE [2, 1], BK [3, 0]
	 */

	if (arg->uapsd_enable[0])
		/* uapsd_flags |= 1 << 3; */
		priv->uapsd_info.TrigVoice = 1;

	if (arg->uapsd_enable[1])
		/* uapsd_flags |= 1 << 2; */
		priv->uapsd_info.TrigVideo = 1;

	if (arg->uapsd_enable[2])
		/* uapsd_flags |= 1 << 1; */
		priv->uapsd_info.TrigBe = 1;

	if (arg->uapsd_enable[3])
		/* uapsd_flags |= 1; */
		priv->uapsd_info.TrigBckgrnd = 1;

	/* Currently pseudo U-APSD operation is not supported, so setting
	 * MinAutoTriggerInterval, MaxAutoTriggerInterval and
	 * AutoTriggerStep to 0
	 */

	/* priv->uapsd_info.uapsd_flags = cpu_to_le16(uapsd_flags);*/
	priv->uapsd_info.MinAutoTriggerInterval = 0;
	priv->uapsd_info.MaxAutoTriggerInterval = 0;
	priv->uapsd_info.AutoTriggerStep = 0;

	ret = wsm_set_uapsd_info(priv, &priv->uapsd_info);
	return ret;
}

/* ******************************************************************** */
/* AP API								*/

int wfx_sta_add(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
		   struct ieee80211_sta *sta)
{
	struct wfx_common *priv = hw->priv;
	struct wfx_sta_priv *sta_priv =
			(struct wfx_sta_priv *)&sta->drv_priv;
	struct wfx_link_entry *entry;
	struct sk_buff *skb;

	if (priv->mode != NL80211_IFTYPE_AP)
		return 0;

	sta_priv->link_id = wfx_find_link_id(priv, sta->addr);
	pr_debug("[STA] wfx_sta_add : MAC=%d:%d:%d:%d:%d:%d, link_id=%d \n", sta->addr[0], sta->addr[1], sta->addr[2], sta->addr[3], sta->addr[4], sta->addr[5], sta_priv->link_id);

	if (WARN_ON(!sta_priv->link_id)) {
		wiphy_info(priv->hw->wiphy,
			   "[AP] No more link IDs available.\n");
		return -ENOENT;
	}

	entry = &priv->link_id_db[sta_priv->link_id - 1];
	spin_lock_bh(&priv->ps_state_lock);
	if ((sta->uapsd_queues & IEEE80211_WMM_IE_STA_QOSINFO_AC_MASK) ==
					IEEE80211_WMM_IE_STA_QOSINFO_AC_MASK)
		priv->sta_asleep_mask |= BIT(sta_priv->link_id);
	entry->status = WFX_LINK_HARD;
	while ((skb = skb_dequeue(&entry->rx_queue)))
		ieee80211_rx_irqsafe(priv->hw, skb);
	spin_unlock_bh(&priv->ps_state_lock);
	return 0;
}

int wfx_sta_remove(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
		      struct ieee80211_sta *sta)
{
	struct wfx_common *priv = hw->priv;
	struct wfx_sta_priv *sta_priv =
			(struct wfx_sta_priv *)&sta->drv_priv;
	struct wfx_link_entry *entry;

	pr_debug("[STA] wfx_sta_remove\n");

	if (priv->mode != NL80211_IFTYPE_AP || !sta_priv->link_id)
		return 0;

	entry = &priv->link_id_db[sta_priv->link_id - 1];
	spin_lock_bh(&priv->ps_state_lock);
	entry->status = WFX_LINK_RESERVE; /*EV _RESERVE or _RESET?*/
	entry->timestamp = jiffies;
	wsm_lock_tx_async(priv);
	if (queue_work(priv->workqueue, &priv->link_id_work) <= 0)
		wsm_unlock_tx(priv);
	spin_unlock_bh(&priv->ps_state_lock);
	flush_workqueue(priv->workqueue);
	return 0;
}

static void __wfx_sta_notify(struct ieee80211_hw *dev,
				struct ieee80211_vif *vif,
				enum sta_notify_cmd notify_cmd,
				int link_id)
{
	struct wfx_common *priv = dev->priv;
	u32 bit, prev;

	/* Zero link id means "for all link IDs" */
	if (link_id)
		bit = BIT(link_id);
	else if (WARN_ON_ONCE(notify_cmd != STA_NOTIFY_AWAKE))
		bit = 0;
	else
		bit = priv->link_id_map;
	prev = priv->sta_asleep_mask & bit;

	switch (notify_cmd) {
	case STA_NOTIFY_SLEEP:
		if (!prev) {
			if (priv->buffered_multicasts &&
			    !priv->sta_asleep_mask)
				queue_work(priv->workqueue,
					   &priv->multicast_start_work);
			priv->sta_asleep_mask |= bit;
		}
		break;
	case STA_NOTIFY_AWAKE:
		if (prev) {
			priv->sta_asleep_mask &= ~bit;
			priv->pspoll_mask &= ~bit;
			if (priv->tx_multicast && link_id &&
			    !priv->sta_asleep_mask)
				queue_work(priv->workqueue,
					   &priv->multicast_stop_work);
			wfx_bh_wakeup(priv);
		}
		break;
	}
}

void wfx_sta_notify(struct ieee80211_hw *dev,
		       struct ieee80211_vif *vif,
		       enum sta_notify_cmd notify_cmd,
		       struct ieee80211_sta *sta)
{
	struct wfx_common *priv = dev->priv;
	struct wfx_sta_priv *sta_priv =
		(struct wfx_sta_priv *)&sta->drv_priv;

	pr_debug("[STA] wfx_sta_notify: link_id=%d, status=%d\n", sta_priv->link_id, sta_priv->link_id);

	spin_lock_bh(&priv->ps_state_lock);
	__wfx_sta_notify(dev, vif, notify_cmd, sta_priv->link_id);
	spin_unlock_bh(&priv->ps_state_lock);
}

static void wfx_ps_notify(struct wfx_common *priv,
		      int link_id, bool ps)
{
	if (link_id > WFX_MAX_STA_IN_AP_MODE)
		return;

	pr_debug("%s for LinkId: %d. STAs asleep: %.8X\n",
		 ps ? "Stop" : "Start",
		 link_id, priv->sta_asleep_mask);

	__wfx_sta_notify(priv->hw, priv->vif,
			    ps ? STA_NOTIFY_SLEEP : STA_NOTIFY_AWAKE, link_id);
}

static int wfx_set_tim_impl(struct wfx_common *priv, bool aid0_bit_set)
{
	struct sk_buff *skb;
	struct wsm_update_ie update_ie = {
			.Body.IeFlags.Beacon = 1,
		/* .what = WSM_UPDATE_IE_BEACON, */
			.Body.NumIEs = 1,
	};
	u16 tim_offset, tim_length;

	pr_debug("[AP] mcast: %s.\n", aid0_bit_set ? "ena" : "dis");

	skb = ieee80211_beacon_get_tim(priv->hw, priv->vif,
			&tim_offset, &tim_length);
	if (!skb) {
		if (!__wfx_flush(priv, true))
			wsm_unlock_tx(priv);
		return -ENOENT;
	}

	if (tim_offset && tim_length >= 6) {
		/* Ignore DTIM count from mac80211:
		 * firmware handles DTIM internally.
		 */
		skb->data[tim_offset + 2] = 0;

		/* Set/reset aid0 bit */
		if (aid0_bit_set)
			skb->data[tim_offset + 4] |= 1;
		else
			skb->data[tim_offset + 4] &= ~1;
	}

	update_ie.ies = &skb->data[tim_offset];
	update_ie.length = tim_length;
	wsm_update_ie(priv, &update_ie);

	dev_kfree_skb(skb);

	return 0;
}

void wfx_set_tim_work(struct work_struct *work)
{
	struct wfx_common *priv =
		container_of(work, struct wfx_common, set_tim_work);
	(void)wfx_set_tim_impl(priv, priv->aid0_bit_set);
}

int wfx_set_tim(struct ieee80211_hw *dev, struct ieee80211_sta *sta,
		   bool set)
{
	struct wfx_common *priv = dev->priv;
	queue_work(priv->workqueue, &priv->set_tim_work);
	return 0;
}

void wfx_set_cts_work(struct work_struct *work)
{
	struct wfx_common *priv =
		container_of(work, struct wfx_common, set_cts_work);
	u8 erp_ie[3] = {WLAN_EID_ERP_INFO, 0x1, 0};
	struct wsm_update_ie update_ie = {
			.Body.IeFlags.Beacon = 1,
		/* .what = WSM_UPDATE_IE_BEACON, */
			.Body.NumIEs = 1,
			.ies = erp_ie,
			.length = 3,
	};
	u32 erp_info;
	__le32 use_cts_prot;

	pr_debug("[STA] wfx_set_cts_work\n");

	mutex_lock(&priv->conf_mutex);
	erp_info = priv->erp_info;
	mutex_unlock(&priv->conf_mutex);
	use_cts_prot =
		erp_info & WLAN_ERP_USE_PROTECTION ?
		__cpu_to_le32(1) : 0;

	erp_ie[ERP_INFO_BYTE_OFFSET] = erp_info;

	pr_debug("[STA] ERP information 0x%x\n", erp_info);

	wsm_write_mib(priv, WSM_MIB_ID_NON_ERP_PROTECTION,
		      &use_cts_prot, sizeof(use_cts_prot));

	if (priv->mode != NL80211_IFTYPE_STATION) {
			wsm_update_ie(priv, &update_ie);
	}

	return;
}


void wfx_bss_info_changed(struct ieee80211_hw *dev,
			     struct ieee80211_vif *vif,
			     struct ieee80211_bss_conf *info,
			     u32 changed)
{
	struct wfx_common *priv = dev->priv;
	bool do_join = false;

	mutex_lock(&priv->conf_mutex);

	pr_debug("[STA] wfx_bss_info_changed : %08x\n", changed);
	pr_debug("BSS CHANGED:  %08x\n", changed);


	if (changed & BSS_CHANGED_ARP_FILTER) {
		WsmHiMibArpIpAddrTable_t filter = {0};
		int i=0;

		pr_debug("[STA] BSS_CHANGED_ARP_FILTER cnt: %d\n",
			 info->arp_addr_cnt);

		/* Currently only one IP address is supported by firmware.
		 * In case of more IPs arp filtering will be disabled.
		 */
		if (info->arp_addr_cnt > 0 &&
		    info->arp_addr_cnt <= WSM_MAX_ARP_IP_ADDRTABLE_ENTRIES) {
			//for (i = 0; i < info->arp_addr_cnt; i++) {
				/* Caution: WsmHiMibArpIpAddrTable_t can store only 1 IPV4 address
				 * i.e. limited to info->arp_addr_cnt=1 */
				/* Caution: type of arp_addr_list[i] is __be32 */
				memcpy(filter.Ipv4Address, &info->arp_addr_list[i], sizeof(filter.Ipv4Address));
				/* filter.ipv4addrs[i] = info->arp_addr_list[i]; */
				pr_debug("[STA] addr[%d]: 0x%d.%d.%d.%d\n",
					 i, filter.Ipv4Address[0], filter.Ipv4Address[1], filter.Ipv4Address[2], filter.Ipv4Address[3]);
			//}
			filter.ArpFilter = 1;
		}

		pr_debug("[STA] arp ip filter enable: %d\n", filter.ArpFilter);

		wsm_set_arp_ipv4_filter(priv, &filter);
	}

	if (changed &
	    (BSS_CHANGED_BEACON |
	     BSS_CHANGED_AP_PROBE_RESP |
	     BSS_CHANGED_BSSID |
	     BSS_CHANGED_SSID |
	     BSS_CHANGED_IBSS)) {
		pr_debug("BSS_CHANGED_BEACON\n");
		priv->beacon_int = info->beacon_int;
		wfx_update_beaconing(priv);
		wfx_upload_beacon(priv);
	}

	if (changed & BSS_CHANGED_BEACON_ENABLED) {
		pr_debug("BSS_CHANGED_BEACON_ENABLED (%d)\n", info->enable_beacon);

		if (priv->enable_beacon != info->enable_beacon) {
			wfx_enable_beaconing(priv, info->enable_beacon);
			priv->enable_beacon = info->enable_beacon;
		}
	}

	/* assoc/disassoc, or maybe AID changed */
	if (changed & BSS_CHANGED_ASSOC) {
		wsm_lock_tx(priv);
		priv->wep_default_key_id = -1;
		wsm_unlock_tx(priv);
	}

	if ( (changed & BSS_CHANGED_ASSOC) && (info->assoc == 0)
	  && ((priv->join_status == WFX_JOIN_STATUS_STA) || (priv->join_status == WFX_JOIN_STATUS_IBSS)) )
	{
		/* Shedule unjoin work */
		pr_debug("[WSM] Issue unjoin command\n");
		wsm_lock_tx_async(priv);
		if (queue_work(priv->workqueue, &priv->unjoin_work) <= 0)
		{
			wsm_unlock_tx(priv);
		}
	}
	else
	{
	    if (changed & BSS_CHANGED_BEACON_INT) {
	        pr_debug("CHANGED_BEACON_INT\n");
	        if (info->ibss_joined)
	            do_join = true;
	        else if (priv->join_status == WFX_JOIN_STATUS_AP)
	            wfx_update_beaconing(priv);
	    }

	    if (changed & BSS_CHANGED_BSSID) {
	        pr_debug("BSS_CHANGED_BSSID\n");
	        do_join = true;
	    }

        if (changed &
            (BSS_CHANGED_ASSOC |
             BSS_CHANGED_BSSID |
             BSS_CHANGED_IBSS |
             BSS_CHANGED_BASIC_RATES |
             BSS_CHANGED_HT)) {
            pr_debug("BSS_CHANGED_ASSOC %d\n", info->assoc);
            if (info->assoc) {
                if (priv->join_status < WFX_JOIN_STATUS_PRE_STA) {
                    ieee80211_connection_loss(vif);
                    mutex_unlock(&priv->conf_mutex);
                    return;
                } else if (priv->join_status == WFX_JOIN_STATUS_PRE_STA) {
                    priv->join_status = WFX_JOIN_STATUS_STA;
                }
            } else {
                do_join = true;
            }

            if (info->assoc || info->ibss_joined) {
                struct ieee80211_sta *sta = NULL;
                __le32 htprot = 0;

                if (info->dtim_period)
                    priv->join_dtim_period = info->dtim_period;
                priv->beacon_int = info->beacon_int;

                rcu_read_lock();

                if (info->bssid && !info->ibss_joined)
                    sta = ieee80211_find_sta(vif, info->bssid);
                if (sta) {
                    priv->ht_info.ht_cap = sta->ht_cap;
                    priv->bss_params.OperationalRateSet =
                        wfx_rate_mask_to_wsm(priv,
                                    sta->supp_rates[priv->channel->band]);
                    priv->ht_info.channel_type = cfg80211_get_chandef_type(&dev->conf.chandef);
                    priv->ht_info.operation_mode = info->ht_operation_mode;
                } else {
                    memset(&priv->ht_info, 0,
                           sizeof(priv->ht_info));
                    priv->bss_params.OperationalRateSet = -1;
                }
                rcu_read_unlock();

                /* Non Greenfield stations present */
                if (priv->ht_info.operation_mode &
                    IEEE80211_HT_OP_MODE_NON_GF_STA_PRSNT)
                    htprot |= cpu_to_le32(WSM_NON_GREENFIELD_STA_PRESENT);

                /* Set HT protection method */
                htprot |= cpu_to_le32((priv->ht_info.operation_mode & IEEE80211_HT_OP_MODE_PROTECTION) << 2);
                wsm_write_mib(priv, WSM_MIB_ID_SET_HT_PROTECTION,
                          &htprot, sizeof(htprot));

                priv->association_mode.MixedOrGreenfieldType =
                    wfx_ht_greenfield(&priv->ht_info);
                priv->association_mode.PreambtypeUse = 1;
                priv->association_mode.Mode = 1;
                priv->association_mode.Rateset = 1;
                priv->association_mode.Spacing = 1;
                priv->association_mode.Snoop = 1;
                priv->association_mode.PreambleType =
                    info->use_short_preamble ? WSM_PREAMBLE_SHORT :	WSM_PREAMBLE_LONG;
                priv->association_mode.BasicRateSet = __cpu_to_le32(
                    wfx_rate_mask_to_wsm(priv,
                                info->basic_rates));
                priv->association_mode.MpduStartSpacing =
                    wfx_ht_ampdu_density(&priv->ht_info);

                wfx_cqm_bssloss_sm(priv, 0, 0, 0);
                cancel_work_sync(&priv->unjoin_work);

                priv->bss_params.BeaconLostCount = priv->cqm_beacon_loss_count;
                priv->bss_params.AID = info->aid;

                if (priv->join_dtim_period < 1)
                    priv->join_dtim_period = 1;

                pr_debug("[STA] DTIM %d, interval: %d\n",
                     priv->join_dtim_period, priv->beacon_int);
                pr_debug("[STA] Preamble: %d, Greenfield: %d, Aid: %d, Rates: 0x%.8X, Basic: 0x%.8X\n",
                     priv->association_mode.PreambleType,
                     priv->association_mode.MixedOrGreenfieldType,
                     priv->bss_params.AID,
                     priv->bss_params.OperationalRateSet,
                     priv->association_mode.BasicRateSet);
                wsm_set_association_mode(priv, &priv->association_mode);

                if (!info->ibss_joined) {
                    wsm_keep_alive_period(priv, 30 /* sec */);
                    wsm_set_bss_params(priv, &priv->bss_params);
                    priv->setbssparams_done = true;
                    wfx_set_beacon_wakeup_period_work(&priv->set_beacon_wakeup_period_work);
                    wfx_set_pm(priv, &priv->powersave_mode);
                }
                if (priv->vif->p2p) {
                    pr_debug("[STA] Setting p2p powersave configuration.\n");
                    wsm_set_p2p_ps_modeinfo(priv,
                                &priv->p2p_ps_modeinfo);
                }
            } else {
                memset(&priv->association_mode, 0,
                       sizeof(priv->association_mode));
                memset(&priv->bss_params, 0, sizeof(priv->bss_params));
            }
        }
	}

	/* ERP Protection */
	if (changed & (BSS_CHANGED_ASSOC |
		       BSS_CHANGED_ERP_CTS_PROT |
		       BSS_CHANGED_ERP_PREAMBLE)) {
		u32 prev_erp_info = priv->erp_info;
		if (info->use_cts_prot)
			priv->erp_info |= WLAN_ERP_USE_PROTECTION;
		else if (!(prev_erp_info & WLAN_ERP_NON_ERP_PRESENT))
			priv->erp_info &= ~WLAN_ERP_USE_PROTECTION;

		if (info->use_short_preamble)
			priv->erp_info |= WLAN_ERP_BARKER_PREAMBLE;
		else
			priv->erp_info &= ~WLAN_ERP_BARKER_PREAMBLE;

		pr_debug("[STA] ERP Protection: %x\n", priv->erp_info);

		if (prev_erp_info != priv->erp_info)
			queue_work(priv->workqueue, &priv->set_cts_work);
	}

	/* ERP Slottime */
	if (changed & (BSS_CHANGED_ASSOC | BSS_CHANGED_ERP_SLOT)) {
		__le32 slot_time = info->use_short_slot ?
			__cpu_to_le32(9) : __cpu_to_le32(20);
		pr_debug("[STA] Slot time: %d us.\n",
			 __le32_to_cpu(slot_time));
		wsm_write_mib(priv, WSM_MIB_ID_DOT11_SLOT_TIME,
			      &slot_time, sizeof(slot_time));
	}

	if (changed & (BSS_CHANGED_ASSOC | BSS_CHANGED_CQM)) {
		WsmHiMibRcpiRssiThreshold_t threshold = {
			.RollingAverageCount = 8,
		};
		pr_debug("[CQM] RSSI threshold subscribe: %d +- %d\n",
			 info->cqm_rssi_thold, info->cqm_rssi_hyst);
		priv->cqm_rssi_thold = info->cqm_rssi_thold;
		priv->cqm_rssi_hyst = info->cqm_rssi_hyst;

		if (info->cqm_rssi_thold || info->cqm_rssi_hyst) {
			/* RSSI: signed Q8.0, RCPI: unsigned Q7.1
			 * RSSI = RCPI / 2 - 110
			 */
			if (priv->cqm_use_rssi) {
				threshold.UpperThreshold =
					info->cqm_rssi_thold + info->cqm_rssi_hyst;
				threshold.LowerThreshold =
					info->cqm_rssi_thold;
				threshold.Use = 1;
			} else {
				threshold.UpperThreshold = (info->cqm_rssi_thold + info->cqm_rssi_hyst + 110) * 2;
				threshold.LowerThreshold = (info->cqm_rssi_thold + 110) * 2;
			}
			threshold.Detection = 1;
		} else {
			threshold.Detection = 1;
			threshold.Upperthresh = 1;
			threshold.Lowerthresh = 1;
			if (priv->cqm_use_rssi)
				threshold.Use = 1;
		}
		wsm_set_rcpi_rssi_threshold(priv, &threshold);
	}

	mutex_unlock(&priv->conf_mutex);

	if (do_join) {
		wsm_lock_tx(priv);
		wfx_do_join(priv); /* Will unlock it for us */
	}
}

void wfx_multicast_start_work(struct work_struct *work)
{
	struct wfx_common *priv =
		container_of(work, struct wfx_common, multicast_start_work);
	long tmo = priv->join_dtim_period *
			(priv->beacon_int + 20) * HZ / 1024;

	cancel_work_sync(&priv->multicast_stop_work);

	if (!priv->aid0_bit_set) {
		wsm_lock_tx(priv);
		wfx_set_tim_impl(priv, true);
		priv->aid0_bit_set = true;
		mod_timer(&priv->mcast_timeout, jiffies + tmo);
		wsm_unlock_tx(priv);
	}
}

void wfx_multicast_stop_work(struct work_struct *work)
{
	struct wfx_common *priv =
		container_of(work, struct wfx_common, multicast_stop_work);

	if (priv->aid0_bit_set) {
		del_timer_sync(&priv->mcast_timeout);
		wsm_lock_tx(priv);
		priv->aid0_bit_set = false;
		wfx_set_tim_impl(priv, false);
		wsm_unlock_tx(priv);
	}
}

void wfx_mcast_timeout(unsigned long arg)
{
	struct wfx_common *priv =
		(struct wfx_common *)arg;

	wiphy_warn(priv->hw->wiphy,
		   "Multicast delivery timeout.\n");
	spin_lock_bh(&priv->ps_state_lock);
	priv->tx_multicast = priv->aid0_bit_set &&
			priv->buffered_multicasts;
	if (priv->tx_multicast)
		wfx_bh_wakeup(priv);
	spin_unlock_bh(&priv->ps_state_lock);
}

int wfx_ampdu_action(struct ieee80211_hw *hw,
        struct ieee80211_vif *vif,
        enum ieee80211_ampdu_mlme_action action,
        struct ieee80211_sta *sta, u16 tid, u16 *ssn,
        u8 buf_size, bool amsdu)
{
	/* Aggregation is implemented fully in firmware,
	 * including block ack negotiation. Do not allow
	 * mac80211 stack to do anything: it interferes with
	 * the firmware.
	 */
	pr_debug("[STA] wfx_ampdu_action : empty (done by FW)\n");

	/* Note that we still need this function stubbed. */

	return -ENOTSUPP;
}

/* ******************************************************************** */
/* WSM callback								*/
void wfx_suspend_resume(struct wfx_common *priv, int link_id,
		WsmHiSuspendResumeTxIndBody_t *arg)
{
	pr_debug("[AP] %s: %s\n",
		 arg->SuspendResumeFlags.ResumeOrSuspend ? "stop" : "start",
		 arg->SuspendResumeFlags.CastType ? "broadcast" : "unicast");

	if (arg->SuspendResumeFlags.CastType) {
		bool cancel_tmo = false;
		spin_lock_bh(&priv->ps_state_lock);
		if (arg->SuspendResumeFlags.ResumeOrSuspend) {
			priv->tx_multicast = false;
		} else {
			/* Firmware sends this indication every DTIM if there
			 * is a STA in powersave connected. There is no reason
			 * to suspend, following wakeup will consume much more
			 * power than it could be saved.
			 */
			wfx_pm_stay_awake(&priv->pm_state,
					     priv->join_dtim_period *
					     (priv->beacon_int + 20) * HZ / 1024);
			priv->tx_multicast = (priv->aid0_bit_set &&
					      priv->buffered_multicasts);
			if (priv->tx_multicast) {
				cancel_tmo = true;
				wfx_bh_wakeup(priv);
			}
		}
		spin_unlock_bh(&priv->ps_state_lock);
		if (cancel_tmo)
			del_timer_sync(&priv->mcast_timeout);
	} else {
		spin_lock_bh(&priv->ps_state_lock);
		wfx_ps_notify(priv, link_id, arg->SuspendResumeFlags.ResumeOrSuspend);
		spin_unlock_bh(&priv->ps_state_lock);
		if (!arg->SuspendResumeFlags.ResumeOrSuspend)
			wfx_bh_wakeup(priv);
	}
	return;
}

/* ******************************************************************** */
/* AP privates								*/

static int wfx_upload_beacon(struct wfx_common *priv)
{
	int ret = 0;
	struct sk_buff *skb = NULL;
	struct ieee80211_mgmt *mgmt;
	u16 tim_offset;
	u16 tim_len;
	WsmHiMibTemplateFrame_t *p;

	if (priv->mode == NL80211_IFTYPE_STATION ||
	    priv->mode == NL80211_IFTYPE_MONITOR ||
	    priv->mode == NL80211_IFTYPE_UNSPECIFIED)
		goto done;

	skb = ieee80211_beacon_get_tim(priv->hw, priv->vif,
					     &tim_offset, &tim_len);

	if (!skb)
		return -ENOMEM;

	p = (WsmHiMibTemplateFrame_t *) skb_push(skb, 4);
	p->FrameType = WSM_TMPLT_BCN;
	p->InitRate = WSM_TRANSMIT_RATE_1; // 1Mbps DSSS
	if (priv->vif->p2p)
		p->InitRate = WSM_TRANSMIT_RATE_6;
	p->FrameLength = __cpu_to_le16(skb->len - 4);

	ret = wsm_set_template_frame(priv, p);

	skb_pull(skb, 4);

	if (ret)
		goto done;
	mgmt = (void *)skb->data;
	mgmt->frame_control =
		__cpu_to_le16(IEEE80211_FTYPE_MGMT |
			      IEEE80211_STYPE_PROBE_RESP);

	p->FrameType = WSM_TMPLT_PRBRES;

	if (priv->vif->p2p) {
		ret = wsm_set_probe_responder(priv, true);
	} else {
		ret = wsm_set_template_frame(priv, p);
		wsm_set_probe_responder(priv, false);
	}

done:
	if (!skb)
		dev_kfree_skb(skb);
	return ret;
}


static int wfx_enable_beaconing(struct wfx_common *priv,
				   bool enable)
{
	WsmHiBeaconTransmitReqBody_t transmit = {
		.EnableBeaconing = enable,
	};

	return wsm_beacon_transmit(priv, &transmit);
}

static int wfx_start_ap(struct wfx_common *priv)
{
	int ret;
	struct ieee80211_bss_conf *conf = &priv->vif->bss_conf;
	WsmHiStartReqBody_t start = {
			.Mode = {
					.StartMode = priv->vif->p2p ?
							WSM_START_MODE_P2P_GO : WSM_START_MODE_AP,
			},
		.Band =  WSM_PHY_BAND_2_4G,
		.ChannelNumber = priv->channel->hw_value,
		.BeaconInterval = conf->beacon_int,
		.DTIMPeriod = conf->dtim_period,
		.PreambleType = conf->use_short_preamble ?
				WSM_PREAMBLE_SHORT :
				WSM_PREAMBLE_LONG,
		.ProbeDelay = 100,
		.BasicRateSet = wfx_rate_mask_to_wsm(priv,
				conf->basic_rates),
	};
	struct wsm_operational_mode mode = {
		.power_mode = wfx_power_mode,
		.disable_more_flag_usage = true,
	};

	memset(start.Ssid, 0, sizeof(start.Ssid));
	if (!conf->hidden_ssid) {
		start.SsidLength = conf->ssid_len;
		memcpy(start.Ssid, conf->ssid, start.SsidLength);
	}

	priv->beacon_int = conf->beacon_int;
	priv->join_dtim_period = conf->dtim_period;

	memset(&priv->link_id_db, 0, sizeof(priv->link_id_db));

	pr_debug("[AP] ch: %d(%d), bcn: %d(%d), brt: 0x%.8X, ssid: %.*s.\n",
		 start.ChannelNumber, start.Band,
		 start.BeaconInterval, start.DTIMPeriod,
		 start.BasicRateSet,
		 start.SsidLength, start.Ssid);
	ret = wsm_start(priv, &start);
	if (!ret)
		ret = wfx_upload_keys(priv);
	if (!ret && priv->vif->p2p) {
		pr_debug("[AP] Setting p2p powersave configuration.\n");
		wsm_set_p2p_ps_modeinfo(priv, &priv->p2p_ps_modeinfo);
	}
	if (!ret) {
		wsm_set_block_ack_policy(priv, priv->ba_tx_tid_mask,
					 priv->ba_rx_tid_mask);
		priv->join_status = WFX_JOIN_STATUS_AP;
		wfx_update_filtering(priv);
	}
	wsm_set_operational_mode(priv, &mode);
	return ret;
}

static int wfx_update_beaconing(struct wfx_common *priv)
{
	struct ieee80211_bss_conf *conf = &priv->vif->bss_conf;
	WsmHiResetFlags_t reset = {
		.ResetStat = true,
	};

	if (priv->mode == NL80211_IFTYPE_AP) {
		if (priv->join_status != WFX_JOIN_STATUS_AP ||
		    priv->beacon_int != conf->beacon_int) {
			pr_debug("ap restarting\n");
			wsm_lock_tx(priv);
			if (priv->join_status != WFX_JOIN_STATUS_PASSIVE)
				wsm_reset(priv, &reset);
			priv->join_status = WFX_JOIN_STATUS_PASSIVE;
			wfx_start_ap(priv);
			wsm_unlock_tx(priv);
		} else
			pr_debug("ap started join_status: %d\n",
				 priv->join_status);
	}
	return 0;
}
