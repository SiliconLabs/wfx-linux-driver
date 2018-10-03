/*
 * Mac80211 STA API for Silicon Labs WFX drivers
 *
 * Copyright (c) 2017, Silicon Laboratories, Inc.
 * Copyright (c) 2010, ST-Ericsson
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <linux/firmware.h>
#include <net/mac80211.h>

#include "sta.h"
#include "wfx.h"
#include "fwio.h"
#include "bh.h"
#include "debug.h"
#include "wsm.h"

#define WFX_PDS_MAX_SIZE 1500

#define WFX_JOIN_TIMEOUT          (1 * HZ)
#define WFX_AUTH_TIMEOUT          (5 * HZ)

#ifndef ERP_INFO_BYTE_OFFSET
#define ERP_INFO_BYTE_OFFSET 2
#endif

#define PAIRWISE_CIPHER_SUITE_COUNT_OFFSET 8u
#define PAIRWISE_CIPHER_SUITE_SIZE 4u
#define AKM_SUITE_COUNT_OFFSET(__pairwiseCount) (2 + \
						 PAIRWISE_CIPHER_SUITE_SIZE * \
						 (__pairwiseCount))
#define AKM_SUITE_SIZE 4u
#define RSN_CAPA_OFFSET(__akmCount) (2 + AKM_SUITE_SIZE * (__akmCount))

#define RSN_CAPA_MFPR_BIT BIT(6)
#define RSN_CAPA_MFPC_BIT BIT(7)

static void wfx_do_join(struct wfx_vif *wvif);
static void wfx_do_unjoin(struct wfx_vif *wvif);

static int wfx_upload_beacon(struct wfx_vif *wvif);
static int wfx_vif_setup(struct wfx_vif *wvif);
static int wfx_start_ap(struct wfx_vif *wvif);
static int wfx_update_beaconing(struct wfx_vif *wvif);
static void __wfx_sta_notify(struct ieee80211_hw *dev,
				struct ieee80211_vif *vif,
			     enum sta_notify_cmd notify_cmd, int link_id);
static int __wfx_flush(struct wfx_dev *wdev, bool drop);

static void fill_edca(struct wsm_edca_params *edca, int queue, int aifs,
		      int cw_min, int cw_max, int txop, int lifetime, bool enabled)
{
	edca->params.CwMin[queue] = cw_min;
	edca->params.CwMax[queue] = cw_max;
	edca->params.AIFSN[queue] = aifs;
	edca->params.TxOpLimit[queue] = txop * TXOP_UNIT;
	edca->params.MaxReceiveLifetime[queue] = lifetime;
	edca->uapsd_enable[queue] = enabled;
}

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
	struct wfx_dev *wdev = dev->priv;
	int ret = 0;

	pr_debug("[STA] wfx_start\n");
	mutex_lock(&wdev->conf_mutex);

	ether_addr_copy(wdev->mac_addr, dev->wiphy->perm_addr);

	ret = wsm_set_macaddr(wdev, wdev->mac_addr, NULL);
	if (ret)
		goto out;

out:
	mutex_unlock(&wdev->conf_mutex);
	return ret;
}

/*This should stop WFx driver when receive a critical error.
 * It must turn off frame reception
 */
void wfx_stop(struct ieee80211_hw *dev)
{
	struct wfx_dev *wdev = dev->priv;

	int i;

	pr_debug("[STA] wfx_stop\n");

	wsm_lock_tx(wdev);

	while (down_trylock(&wdev->scan.lock)) {
		/* Scan is in progress. Force it to stop. */
		wdev->scan.req = NULL;
		schedule();
	}
	up(&wdev->scan.lock);

	cancel_delayed_work_sync(&wdev->scan.probe_work);
	cancel_delayed_work_sync(&wdev->scan.timeout);
	flush_workqueue(wdev->workqueue);
	mutex_lock(&wdev->conf_mutex);

	for (i = 0; i < 4; i++)
		wfx_queue_clear(&wdev->tx_queue[i]);
	mutex_unlock(&wdev->conf_mutex);
	tx_policy_clean(wdev);

	if (atomic_xchg(&wdev->tx_lock, 1) != 1)
		pr_debug("[STA] TX is force-unlocked due to stop request.\n");

	wsm_unlock_tx(wdev);
	atomic_xchg(&wdev->tx_lock, 0); /* for recovery to work */
}

void __wfx_cqm_bssloss_sm(struct wfx_vif *wvif,
			     int init, int good, int bad)
{
	int tx = 0;

	wvif->delayed_link_loss = 0;
	cancel_work_sync(&wvif->bss_params_work);

	pr_debug(
		"[STA] CQM BSSLOSS_SM: state: %d init %d good %d bad: %d txlock: %d uj: %d\n",
		wvif->bss_loss_state,
		 init, good, bad,
		atomic_read(&wvif->wdev->tx_lock),
		wvif->delayed_unjoin);

	/* If we have a pending unjoin */
	if (wvif->delayed_unjoin)
		return;

	if (init) {
		queue_delayed_work(wvif->wdev->workqueue,
				   &wvif->bss_loss_work,
				   HZ);
		wvif->bss_loss_state = 0;

		/* Skip the confimration procedure in P2P case */
		if (!wvif->vif->p2p && !atomic_read(&wvif->wdev->tx_lock))
			tx = 1;
	} else if (good) {
		cancel_delayed_work_sync(&wvif->bss_loss_work);
		wvif->bss_loss_state = 0;
		queue_work(wvif->wdev->workqueue, &wvif->bss_params_work);
	} else if (bad) {
		if (wvif->bss_loss_state < 3)
			tx = 1;
	} else {
		cancel_delayed_work_sync(&wvif->bss_loss_work);
		wvif->bss_loss_state = 0;
	}

	/* Spit out a NULL packet to our AP if necessary */
	if (tx) {
		struct sk_buff *skb;

		wvif->bss_loss_state++;

#if (KERNEL_VERSION(4, 14, 16) <= LINUX_VERSION_CODE)
		skb = ieee80211_nullfunc_get(wvif->wdev->hw, wvif->vif, false);
#else
		skb = ieee80211_nullfunc_get(wvif->wdev->hw, wvif->vif);
#endif
		if (!skb)
			dev_err(wvif->wdev->pdev, "failed to retrieve a nullfunc\n");
		if (skb)
			wfx_tx(wvif->wdev->hw, NULL, skb);
	}
}

int wfx_add_interface(struct ieee80211_hw *dev,
			 struct ieee80211_vif *vif)
{
	int ret;
	struct wfx_dev *wdev = dev->priv;
	struct wfx_vif *wvif = (struct wfx_vif *) vif->drv_priv;


	vif->driver_flags |= IEEE80211_VIF_BEACON_FILTER |
			     IEEE80211_VIF_SUPPORTS_UAPSD |
			     IEEE80211_VIF_SUPPORTS_CQM_RSSI;

	pr_debug("[STA] wfx_add_interface : type= %d\n", vif->type);

	mutex_lock(&wdev->conf_mutex);

	switch (vif->type) {
	case NL80211_IFTYPE_STATION:
	case NL80211_IFTYPE_ADHOC:
	case NL80211_IFTYPE_MESH_POINT:
	case NL80211_IFTYPE_AP:
		break;
	default:
		mutex_unlock(&wdev->conf_mutex);
		return -EOPNOTSUPP;
	}

	if (wdev->vif) {
		mutex_unlock(&wdev->conf_mutex);
		return -EOPNOTSUPP;
	}

	wdev->vif = vif;
	wvif->vif = vif;
	wvif->wdev = wdev;
	wvif->Id = 0;
	wvif->mode = vif->type;
	ether_addr_copy(wdev->mac_addr, vif->addr);
	ret = wsm_set_macaddr(wdev, wdev->mac_addr, NULL);
	wfx_vif_setup(wvif);
	mutex_unlock(&wdev->conf_mutex);
	wsm_set_edca_params(wdev, &wvif->edca.params, wvif->Id);
	wfx_set_uapsd_param(wvif, &wvif->edca);

	return 0;
}

void wfx_remove_interface(struct ieee80211_hw *dev,
			     struct ieee80211_vif *vif)
{
	struct wfx_dev *wdev = dev->priv;
	struct wfx_vif *wvif = (struct wfx_vif *) vif->drv_priv;
	LIST_HEAD(list);
	int i;

	pr_debug("[STA] wfx_remove_interface : join_status= %d\n",
		 wvif->join_status);

	mutex_lock(&wdev->conf_mutex);
	switch (wvif->join_status) {
	case WFX_JOIN_STATUS_JOINING:
	case WFX_JOIN_STATUS_PRE_STA:
	case WFX_JOIN_STATUS_STA:
	case WFX_JOIN_STATUS_IBSS:
		wsm_lock_tx(wdev);
		if (queue_work(wdev->workqueue, &wvif->unjoin_work) <= 0)
			wsm_unlock_tx(wdev);
		break;
	case WFX_JOIN_STATUS_AP:
		for (i = 0; wvif->link_id_map; ++i) {
			if (wvif->link_id_map & BIT(i)) {
				wfx_unmap_link(wvif, i);
				wvif->link_id_map &= ~BIT(i);
			}
		}
		memset(wvif->link_id_db, 0, sizeof(wvif->link_id_db));
		wvif->sta_asleep_mask = 0;
		wvif->enable_beacon = false;
		wvif->tx_multicast = false;
		wvif->aid0_bit_set = false;
		wvif->buffered_multicasts = false;
		wvif->pspoll_mask = 0;
		/* reset.link_id = 0; */
		wsm_reset(wdev, true, wvif->Id);
		break;
	case WFX_JOIN_STATUS_MONITOR:
		wfx_update_listening(wvif, false);
		break;
	default:
		break;
	}
	wvif->vif = NULL;
	wvif->mode = NL80211_IFTYPE_MONITOR;
	eth_zero_addr(wdev->mac_addr);
	memset(&wvif->p2p_ps_modeinfo, 0, sizeof(wvif->p2p_ps_modeinfo));
	wfx_free_keys(wvif);

	wsm_set_macaddr(wdev, wdev->mac_addr, NULL);

	wvif->listening = false;
	wvif->join_status = WFX_JOIN_STATUS_PASSIVE;
	if (!__wfx_flush(wdev, true))
		wsm_unlock_tx(wdev);
	cancel_delayed_work_sync(&wvif->join_timeout);
	wfx_cqm_bssloss_sm(wvif, 0, 0, 0);
	cancel_work_sync(&wvif->unjoin_work);
	cancel_delayed_work_sync(&wvif->link_id_gc_work);
	del_timer_sync(&wvif->mcast_timeout);

	wvif->mode = NL80211_IFTYPE_UNSPECIFIED;
	wvif->listening = false;

	spin_lock(&wvif->event_queue_lock);
	list_splice_init(&wvif->event_queue, &list);
	spin_unlock(&wvif->event_queue_lock);
	__wfx_free_event_queue(&list);

	wvif->join_status = WFX_JOIN_STATUS_PASSIVE;
	wvif->join_pending = false;

	wdev->vif = NULL;

	mutex_unlock(&wdev->conf_mutex);
}

int wfx_change_interface(struct ieee80211_hw *dev,
			    struct ieee80211_vif *vif,
			    enum nl80211_iftype new_type,
			    bool p2p)
{
	int ret = 0;

	pr_debug("[STA] wfx_change_interface: new: %d (%d), old: %d (%d)\n",
		 new_type,
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
	struct wfx_dev *wdev = dev->priv;
	struct ieee80211_conf *conf = &dev->conf;
	// FIXME: Interface id should not been hardcoded
	struct wfx_vif *wvif = wdev_to_wvif(wdev, 0);

	pr_debug("[STA] wfx_config:  %08x\n", changed);

	down(&wdev->scan.lock);
	mutex_lock(&wdev->conf_mutex);
	if (changed & IEEE80211_CONF_CHANGE_POWER) {
		wdev->output_power = conf->power_level;
		pr_debug("[STA] TX power: %d\n", wdev->output_power);
		wsm_set_output_power(wdev, wdev->output_power * 10, wvif->Id);
	}

	if ((changed & IEEE80211_CONF_CHANGE_CHANNEL) &&
	    (wdev->channel != conf->chandef.chan)) {
		struct ieee80211_channel *ch = conf->chandef.chan;

		pr_debug("[STA] Freq %d (wsm ch: %d).\n",
			 ch->center_freq, ch->hw_value);
		wdev->channel = ch;
	}

	if (changed & IEEE80211_CONF_CHANGE_PS) {
		if (!(conf->flags & IEEE80211_CONF_PS)) {
			wvif->powersave_mode.PmMode.PmMode = 0;
			wvif->powersave_mode.PmMode.FastPsm = 0;
		} else if (conf->dynamic_ps_timeout <= 0) {
			wvif->powersave_mode.PmMode.PmMode = 1;
			wvif->powersave_mode.PmMode.FastPsm = 0;
		} else {
			wvif->powersave_mode.PmMode.PmMode = 1;
			wvif->powersave_mode.PmMode.FastPsm = 1;
		}

		/* Firmware requires that value for this 1-byte field must
		 * be specified in units of 500us. Values above the 128ms
		 * threshold are not supported.
		 */
		if (conf->dynamic_ps_timeout >= 0x80)
			wvif->powersave_mode.FastPsmIdlePeriod = 0xFF;
		else
			wvif->powersave_mode.FastPsmIdlePeriod =
					conf->dynamic_ps_timeout << 1;

		if (wvif->join_status == WFX_JOIN_STATUS_STA &&
		    wvif->bss_params.AID)
			wfx_set_pm(wvif, &wvif->powersave_mode);
	}
	if (changed & IEEE80211_CONF_CHANGE_IDLE) {
		struct wsm_operational_mode mode = {
			.power_mode = wdev->pdata.power_mode,
			.disable_more_flag_usage = true,
		};

		wsm_lock_tx(wdev);
		/* Disable p2p-dev mode forced by TX request */
		if ((wvif->join_status == WFX_JOIN_STATUS_MONITOR) &&
		    (conf->flags & IEEE80211_CONF_IDLE) &&
		    !wvif->listening) {
			wfx_disable_listening(wvif);
			wvif->join_status = WFX_JOIN_STATUS_PASSIVE;
		}
		wsm_set_operational_mode(wdev, &mode, wvif->Id);
		wsm_unlock_tx(wdev);
	}

	if (changed & IEEE80211_CONF_CHANGE_RETRY_LIMITS) {
		pr_debug("[STA] Retry limits: %d (long), %d (short).\n",
			 conf->long_frame_max_tx_count,
			 conf->short_frame_max_tx_count);
		spin_lock_bh(&wdev->tx_policy_cache.lock);
		wdev->long_frame_max_tx_count = conf->long_frame_max_tx_count;
		wdev->short_frame_max_tx_count =
			(conf->short_frame_max_tx_count < 0x0F) ?
			conf->short_frame_max_tx_count : 0x0F;
		wdev->hw->max_rate_tries = wdev->short_frame_max_tx_count;
		spin_unlock_bh(&wdev->tx_policy_cache.lock);
	}
	mutex_unlock(&wdev->conf_mutex);
	up(&wdev->scan.lock);
	return ret;
}

void wfx_update_filtering(struct wfx_vif *wvif)
{
	int ret;
	bool bssid_filtering = !wvif->rx_filter.bssid;
	bool is_p2p = wvif->vif && wvif->vif->p2p;
	bool is_sta = wvif->vif && NL80211_IFTYPE_STATION == wvif->vif->type;

	static WsmHiMibBcnFilterEnable_t bf_ctrl;
	static WsmHiMibBcnFilterTable_t bf_tbl = {
		.IeTable[0].IeId	= WLAN_EID_VENDOR_SPECIFIC,
		.IeTable[0].HasChanged	= 1,
		.IeTable[0].NoLonger	= 1,
		.IeTable[0].HasAppeared = 1,
		.IeTable[0].Oui[0] = 0x50,
		.IeTable[0].Oui[1] = 0x6F,
		.IeTable[0].Oui[2] = 0x9A,
		.IeTable[1].IeId	= WLAN_EID_HT_OPERATION,
		.IeTable[1].HasChanged	= 1,
		.IeTable[1].NoLonger	= 1,
		.IeTable[1].HasAppeared = 1,
		.IeTable[2].IeId	= WLAN_EID_ERP_INFO,
		.IeTable[2].HasChanged	= 1,
		.IeTable[2].NoLonger	= 1,
		.IeTable[2].HasAppeared = 1,
	};

	if (wvif->join_status == WFX_JOIN_STATUS_PASSIVE)
		return;
	else if (wvif->join_status == WFX_JOIN_STATUS_MONITOR)
		bssid_filtering = false;

	if (wvif->disable_beacon_filter) {
		bf_ctrl.Enable = 0;
		bf_ctrl.BcnCount = 1;
		bf_tbl.NumOfInfoElmts = cpu_to_le32(0);
	} else if (is_p2p || !is_sta) {
		bf_ctrl.Enable = WSM_BEACON_FILTER_ENABLE |
			WSM_BEACON_FILTER_AUTO_ERP;
		bf_ctrl.BcnCount = 0;
		bf_tbl.NumOfInfoElmts = cpu_to_le32(2);
	} else {
		bf_ctrl.Enable = WSM_BEACON_FILTER_ENABLE;
		bf_ctrl.BcnCount = 0;
		bf_tbl.NumOfInfoElmts = cpu_to_le32(3);
	}
	if (is_p2p)
		bssid_filtering = false;

	ret = wsm_set_rx_filter(wvif->wdev, &wvif->rx_filter, wvif->Id);
	if (!ret)
		ret = wsm_set_beacon_filter_table(wvif->wdev, &bf_tbl, wvif->Id);
	if (!ret)
		ret = wsm_beacon_filter_control(wvif->wdev, bf_ctrl.Enable, bf_ctrl.BcnCount, wvif->Id);
	if (!ret)
		ret = wsm_set_bssid_filtering(wvif->wdev, bssid_filtering, wvif->Id);
	if (!ret)
		ret = wsm_set_multicast_filter(wvif->wdev, &wvif->multicast_filter, wvif->Id);
	if (ret)
		wiphy_err(wvif->wdev->hw->wiphy,
			  "Update filtering failed: %d.\n", ret);
}

void wfx_update_filtering_work(struct work_struct *work)
{
	struct wfx_vif *wvif =
		container_of(work, struct wfx_vif,
			     update_filtering_work);

	wfx_update_filtering(wvif);
}

void wfx_set_beacon_wakeup_period_work(struct work_struct *work)
{
	struct wfx_vif *wvif =
		container_of(work, struct wfx_vif,
			     set_beacon_wakeup_period_work);
	unsigned period = wvif->join_dtim_period;

	if (TU_TO_MSEC(wvif->beacon_int) * period > MAX_BEACON_SKIP_TIME_MS)
		period = 1;
	wsm_set_beacon_wakeup_period(wvif->wdev, period, period, wvif->Id);
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
	struct wfx_dev *wdev = hw->priv;
	struct netdev_hw_addr *ha;
	int count = 0;
	// FIXME: Interface id should not been hardcoded
	struct wfx_vif *wvif = wdev_to_wvif(wdev, 0);

	pr_debug("[STA] wfx_prepare_multicast\n");

	/* Disable multicast filtering */
	wvif->has_multicast_subscription = false;
	memset(&wvif->multicast_filter, 0x00, sizeof(wvif->multicast_filter));

	if (netdev_hw_addr_list_count(mc_list) > ARRAY_SIZE(wvif->multicast_filter.AddressList))
		return 0;

	/* Enable if requested */
	netdev_hw_addr_list_for_each(ha, mc_list) {
		pr_debug("[STA] multicast: %pM\n", ha->addr);
		ether_addr_copy(wvif->multicast_filter.AddressList[count].MacAddr,
				ha->addr);
		if (!ether_addr_equal(ha->addr, broadcast_ipv4) &&
		    !ether_addr_equal(ha->addr, broadcast_ipv6))
			wvif->has_multicast_subscription = true;
		count++;
	}

	if (count) {
		wvif->multicast_filter.Enable = cpu_to_le32(1);
		wvif->multicast_filter.NumOfAddresses = cpu_to_le32(count);
	}

	return netdev_hw_addr_list_count(mc_list);
}

void wfx_configure_filter(struct ieee80211_hw *dev,
			     unsigned int changed_flags,
			     unsigned int *total_flags,
			     u64 multicast)
{
	struct wfx_dev *wdev = dev->priv;
	bool listening = !!(*total_flags &
			    (FIF_OTHER_BSS |
			     FIF_BCN_PRBRESP_PROMISC |
			     FIF_PROBE_REQ));
	// FIXME: Interface id should not been hardcoded
	struct wfx_vif *wvif = wdev_to_wvif(wdev, 0);

	*total_flags &= FIF_OTHER_BSS |
			FIF_FCSFAIL |
			FIF_BCN_PRBRESP_PROMISC |
			FIF_PROBE_REQ;

	pr_debug("[STA] wfx_configure_filter : 0x%.8X\n", *total_flags);

	down(&wdev->scan.lock);
	mutex_lock(&wdev->conf_mutex);

	wvif->rx_filter.promiscuous = 0;

	wvif->rx_filter.bssid = (*total_flags & (FIF_OTHER_BSS |
			FIF_PROBE_REQ)) ? 1 : 0;
	wvif->rx_filter.fcs = (*total_flags & FIF_FCSFAIL) ? 1 : 0;

	wvif->disable_beacon_filter = !(*total_flags &
					(FIF_BCN_PRBRESP_PROMISC |
					 FIF_PROBE_REQ));

	if (wvif->listening != listening) {
		wvif->listening = listening;
		wsm_lock_tx(wdev);
		wfx_update_listening(wvif, listening);
		wsm_unlock_tx(wdev);
	}
	wfx_update_filtering(wvif);
	mutex_unlock(&wdev->conf_mutex);
	up(&wdev->scan.lock);
}

int wfx_conf_tx(struct ieee80211_hw *dev, struct ieee80211_vif *vif,
		   u16 queue, const struct ieee80211_tx_queue_params *params)
{
	struct wfx_dev *wdev = dev->priv;
	struct wfx_vif *wvif = (struct wfx_vif *) vif->drv_priv;
	int ret = 0;
	/* To prevent re-applying PM request OID again and again*/
	uint16_t old_uapsd_flags, new_uapsd_flags;

	pr_debug("[STA] wfx_conf_tx\n");

	mutex_lock(&wdev->conf_mutex);

	if (queue < dev->queues) {
		old_uapsd_flags = *((uint16_t *) &wvif->uapsd_info);

		// FIXME: currently unused
		wvif->tx_queue_params.params[queue].AckPolicy = 0;
		wvif->tx_queue_params.params[queue].AllowedMediumTime = 0;
		wvif->tx_queue_params.params[queue].MaxTransmitLifetime = 0;

		ret = wsm_set_tx_queue_params(wdev, queue, 0, 0, 0, wvif->Id);
		if (ret) {
			ret = -EINVAL;
			goto out;
		}

		fill_edca(&wvif->edca, queue, params->aifs,
			     params->cw_min, params->cw_max,
			     params->txop, 0xc8,
			     params->uapsd);
		ret = wsm_set_edca_params(wdev, &wvif->edca.params, wvif->Id);
		if (ret) {
			ret = -EINVAL;
			goto out;
		}

		if (wvif->mode == NL80211_IFTYPE_STATION) {
			ret = wfx_set_uapsd_param(wvif, &wvif->edca);
			new_uapsd_flags = *((uint16_t *) &wvif->uapsd_info);
			if (!ret && wvif->setbssparams_done &&
			    (wvif->join_status == WFX_JOIN_STATUS_STA) &&
			    /* (old_uapsd_flags != le16_to_cpu(wvif->uapsd_info.uapsd_flags))) */
			    (old_uapsd_flags != new_uapsd_flags))
				ret = wfx_set_pm(wvif, &wvif->powersave_mode);
		}
	} else {
		ret = -EINVAL;
	}

out:
	mutex_unlock(&wdev->conf_mutex);
	return ret;
}

int wfx_get_stats(struct ieee80211_hw *dev,
		     struct ieee80211_low_level_stats *stats)
{
	struct wfx_dev *wdev = dev->priv;

	memcpy(stats, &wdev->stats, sizeof(*stats));
	return 0;
}

int wfx_set_pm(struct wfx_vif *wvif, const WsmHiSetPmModeReqBody_t *arg)
{
	WsmHiSetPmModeReqBody_t pm = *arg;
	uint16_t uapsd_flags;
	int ret;

	memcpy(&uapsd_flags, &wvif->uapsd_info, sizeof(uapsd_flags));

	if (uapsd_flags != 0) {
		pm.PmMode.FastPsm = 0;
	}

	if (wvif->wdev->pdata.power_mode == WSM_OP_POWER_MODE_ACTIVE) {
		/* If the device is set active, disable power mode */
		pm.PmMode.FastPsm = 0;
		pm.PmMode.PmMode = 0;
	}

	pr_debug("Set PM %d, %d\n", pm.PmMode.FastPsm, pm.PmMode.PmMode);
	if (memcmp(&pm, &wvif->firmware_ps_mode,
		   sizeof(WsmHiSetPmModeReqBody_t))) {
		wvif->firmware_ps_mode = pm;
		wvif->wdev->ps_mode_switch_in_progress = 1;
		ret = wsm_set_pm(wvif->wdev, &pm, wvif->Id);
		if (ret)
			wvif->wdev->channel_switch_in_progress = 0;
		// FIXME: why ?
		if (-ETIMEDOUT == wvif->wdev->scan.status)
			wvif->wdev->scan.status = 1;
		return ret;
	} else {
		return 0;
	}
}

int wfx_set_key(struct ieee80211_hw *dev, enum set_key_cmd cmd,
		   struct ieee80211_vif *vif, struct ieee80211_sta *sta,
		   struct ieee80211_key_conf *key)
{
	int ret = -EOPNOTSUPP;
	struct wfx_dev *wdev = dev->priv;
	struct wfx_vif *wvif = (struct wfx_vif *) vif->drv_priv;
	struct ieee80211_key_seq seq;

	pr_debug("[STA] wfx_set _key\n");

	mutex_lock(&wdev->conf_mutex);

	if (cmd == SET_KEY) {
		u8 *peer_addr = NULL;
		int pairwise = (key->flags & IEEE80211_KEY_FLAG_PAIRWISE) ?
			1 : 0;
		int idx = wfx_alloc_key(wvif);
		WsmHiAddKeyReqBody_t *wsm_key = &wvif->keys[idx];

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
				wfx_free_key(wvif, idx);
				ret = -EINVAL;
				goto finally;
			}

			if (pairwise) {
				wsm_key->Type = WSM_KEY_TYPE_WEP_PAIRWISE;
				ether_addr_copy(wsm_key->Key.WepPairwiseKey.PeerAddress,
					peer_addr);
				memcpy(wsm_key->Key.WepPairwiseKey.KeyData,
				       &key->key[0], key->keylen);
				wsm_key->Key.WepPairwiseKey.KeyLength =
					key->keylen;
			} else {
				wsm_key->Type = WSM_KEY_TYPE_WEP_DEFAULT;
				memcpy(wsm_key->Key.WepGroupKey.KeyData,
				       &key->key[0], key->keylen);
				wsm_key->Key.WepGroupKey.KeyLength =
					key->keylen;
				wsm_key->Key.WepGroupKey.KeyId = key->keyidx;
			}
			break;
		case WLAN_CIPHER_SUITE_TKIP:
			ieee80211_get_key_rx_seq(key, 0, &seq);
			if (pairwise) {
				wsm_key->Type = WSM_KEY_TYPE_TKIP_PAIRWISE;
				ether_addr_copy(wsm_key->Key.TkipPairwiseKey.PeerAddress,
				       peer_addr);
				memcpy(wsm_key->Key.TkipPairwiseKey.TkipKeyData,
				       &key->key[0], 16);
				memcpy(wsm_key->Key.TkipPairwiseKey.TxMicKey,
				       &key->key[16], 8);
				memcpy(wsm_key->Key.TkipPairwiseKey.RxMicKey,
				       &key->key[24], 8);
			} else {
				size_t mic_offset =
					(wvif->mode == NL80211_IFTYPE_AP) ?
					16 : 24;

				wsm_key->Type = WSM_KEY_TYPE_TKIP_GROUP;
				memcpy(wsm_key->Key.TkipGroupKey.TkipKeyData,
				       &key->key[0], 16);
				memcpy(wsm_key->Key.TkipGroupKey.RxMicKey,
				       &key->key[mic_offset], 8);

				wsm_key->Key.TkipGroupKey.RxSequenceCounter[0] =
					seq.tkip.iv16 & 0xff;
				wsm_key->Key.TkipGroupKey.RxSequenceCounter[1] =
					(seq.tkip.iv16 >> 8) & 0xff;
				wsm_key->Key.TkipGroupKey.RxSequenceCounter[2] =
					seq.tkip.iv32 & 0xff;
				wsm_key->Key.TkipGroupKey.RxSequenceCounter[3] =
					(seq.tkip.iv32 >> 8) & 0xff;
				wsm_key->Key.TkipGroupKey.RxSequenceCounter[4] =
					(seq.tkip.iv32 >> 16) & 0xff;
				wsm_key->Key.TkipGroupKey.RxSequenceCounter[5] =
					(seq.tkip.iv32 >> 24) & 0xff;
				wsm_key->Key.TkipGroupKey.RxSequenceCounter[6] =
					0;
				wsm_key->Key.TkipGroupKey.RxSequenceCounter[7] =
					0;

				wsm_key->Key.TkipGroupKey.KeyId = key->keyidx;
			}
			break;
		case WLAN_CIPHER_SUITE_CCMP:
			ieee80211_get_key_rx_seq(key, 0, &seq);
			if (pairwise) {
				wsm_key->Type = WSM_KEY_TYPE_AES_PAIRWISE;
				ether_addr_copy(wsm_key->Key.AesPairwiseKey.PeerAddress,
				       peer_addr);
				memcpy(wsm_key->Key.AesPairwiseKey.AesKeyData,
				       &key->key[0], 16);
			} else {
				wsm_key->Type = WSM_KEY_TYPE_AES_GROUP;
				memcpy(wsm_key->Key.AesGroupKey.AesKeyData,
				       &key->key[0], 16);

				wsm_key->Key.AesGroupKey.RxSequenceCounter[0] =
					seq.ccmp.pn[5];
				wsm_key->Key.AesGroupKey.RxSequenceCounter[1] =
					seq.ccmp.pn[4];
				wsm_key->Key.AesGroupKey.RxSequenceCounter[2] =
					seq.ccmp.pn[3];
				wsm_key->Key.AesGroupKey.RxSequenceCounter[3] =
					seq.ccmp.pn[2];
				wsm_key->Key.AesGroupKey.RxSequenceCounter[4] =
					seq.ccmp.pn[1];
				wsm_key->Key.AesGroupKey.RxSequenceCounter[5] =
					seq.ccmp.pn[0];
				wsm_key->Key.AesGroupKey.RxSequenceCounter[6] =
					0;
				wsm_key->Key.AesGroupKey.RxSequenceCounter[7] =
					0;
				wsm_key->Key.AesGroupKey.KeyId = key->keyidx;
			}
			break;
		case WLAN_CIPHER_SUITE_SMS4:
			if (pairwise) {
				wsm_key->Type = WSM_KEY_TYPE_WAPI_PAIRWISE;
				ether_addr_copy(wsm_key->Key.WapiPairwiseKey.PeerAddress,
				       peer_addr);
				memcpy(wsm_key->Key.WapiPairwiseKey.WapiKeyData,
				       &key->key[0], 16);
				memcpy(wsm_key->Key.WapiPairwiseKey.MicKeyData,
				       &key->key[16], 16);
				wsm_key->Key.WapiPairwiseKey.KeyId =
					key->keyidx;
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

			pr_debug(
				"set AES_CMAC, key_id %d, IPN = 0x%02x%02x%02x%02x%02x%02x\n",
				key->keyidx,
				seq.aes_cmac.pn[0],
				seq.aes_cmac.pn[1],
				seq.aes_cmac.pn[2],
				seq.aes_cmac.pn[3],
				seq.aes_cmac.pn[4],
				seq.aes_cmac.pn[5]);

			wsm_key->Type = WSM_KEY_TYPE_IGTK_GROUP;
			/* Copy key in wsm message */
			memcpy(wsm_key->Key.IgtkGroupKey.IGTKKeyData,
			       &key->key[0],
			       key->keylen);

			/* Reverse the bit order to match the IPN receive in frame */
			wsm_key->Key.IgtkGroupKey.IPN[0] = seq.aes_cmac.pn[5];
			wsm_key->Key.IgtkGroupKey.IPN[1] = seq.aes_cmac.pn[4];
			wsm_key->Key.IgtkGroupKey.IPN[2] = seq.aes_cmac.pn[3];
			wsm_key->Key.IgtkGroupKey.IPN[3] = seq.aes_cmac.pn[2];
			wsm_key->Key.IgtkGroupKey.IPN[4] = seq.aes_cmac.pn[1];
			wsm_key->Key.IgtkGroupKey.IPN[5] = seq.aes_cmac.pn[0];

			wsm_key->Key.IgtkGroupKey.KeyId = key->keyidx;
			break;
		default:
			dev_warn(wdev->pdev, "unsupported key type %d\n", key->cipher);
			wfx_free_key(wvif, idx);
			ret = -EOPNOTSUPP;
			goto finally;
		}
		ret = wsm_add_key(wdev, wsm_key, wvif->Id);
		if (!ret)
			key->hw_key_idx = idx;
		else
			wfx_free_key(wvif, idx);
	} else if (cmd == DISABLE_KEY) {
		if (key->hw_key_idx > WSM_KEY_MAX_INDEX) {
			ret = -EINVAL;
			goto finally;
		}

		wfx_free_key(wvif, key->hw_key_idx);
		ret = wsm_remove_key(wdev, key->hw_key_idx, wvif->Id);
	} else {
		dev_warn(wdev->pdev, "unsupported key command %d\n", cmd);
	}

finally:
	mutex_unlock(&wdev->conf_mutex);
	return ret;
}

void wfx_wep_key_work(struct work_struct *work)
{
	struct wfx_vif *wvif =
		container_of(work, struct wfx_vif, wep_key_work);
	u8 queue_id = wfx_queue_get_queue_id(wvif->wdev->pending_frame_id);
	struct wfx_queue *queue = &wvif->wdev->tx_queue[queue_id];
	int wep_default_key_id = wvif->wep_default_key_id;

	pr_debug("[STA] Setting default WEP key: %d\n", wep_default_key_id);
	wsm_flush_tx(wvif->wdev);
	wsm_wep_default_key_id(wvif->wdev, wep_default_key_id, wvif->Id);
	wfx_queue_requeue(queue, wvif->wdev->pending_frame_id);
	wsm_unlock_tx(wvif->wdev);
}

int wfx_set_rts_threshold(struct ieee80211_hw *hw, u32 value)
{
	int ret = 0;
	struct wfx_dev *wdev = hw->priv;
	// FIXME: Interface id should not been hardcoded
	struct wfx_vif *wvif = wdev_to_wvif(wdev, 0);

	pr_debug("[STA] wfx_set_rts_threshold = %d\n", value);

	if (wvif->mode == NL80211_IFTYPE_UNSPECIFIED)
		return 0;

	if (wvif->rts_threshold == value)
		return 0;

	/* mutex_lock(&wdev->conf_mutex); */
	ret = wsm_rts_threshold(wdev, value, wvif->Id);
	if (!ret)
		wvif->rts_threshold = value;
	/* mutex_unlock(&wdev->conf_mutex); */

	return ret;
}

/* If successful, LOCKS the TX queue! */
static int __wfx_flush(struct wfx_dev *wdev, bool drop)
{
	int i, ret;

	for (;;) {
		if (drop) {
			for (i = 0; i < 4; ++i)
				wfx_queue_clear(&wdev->tx_queue[i]);
		} else {
			ret = wait_event_timeout(
				wdev->tx_queue_stats.wait_link_id_empty,
				wfx_queue_stats_is_empty(
					&wdev->tx_queue_stats, -1),
				2 * HZ);
		}

		if (!drop && ret <= 0) {
			ret = -ETIMEDOUT;
			break;
		} else {
			ret = 0;
		}

		wsm_lock_tx(wdev);
		if (!wfx_queue_stats_is_empty(&wdev->tx_queue_stats, -1)) {
			/* Highly unlikely: WSM requeued frames. */
			wsm_unlock_tx(wdev);
			continue;
		}
		break;
	}
	return ret;
}

void wfx_flush(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
		  u32 queues, bool drop)
{
	struct wfx_dev *wdev = hw->priv;
	struct wfx_vif *wvif = NULL;

	pr_debug("[STA] wfx_flush\n");

	if (vif)
		wvif = (struct wfx_vif *) vif->drv_priv;
	if (wvif) {
		if (wvif->mode == NL80211_IFTYPE_MONITOR)
			drop = true;
		if (wvif->mode == NL80211_IFTYPE_AP && !wvif->enable_beacon)
			drop = true;
	}

	// FIXME: only flush requested vif
	if (!__wfx_flush(wdev, drop))
		wsm_unlock_tx(wdev);
}

/* ******************************************************************** */
/* WSM callbacks							*/

void wfx_free_event_queue(struct wfx_vif *wvif)
{
	LIST_HEAD(list);

	spin_lock(&wvif->event_queue_lock);
	list_splice_init(&wvif->event_queue, &list);
	spin_unlock(&wvif->event_queue_lock);

	__wfx_free_event_queue(&list);
}

void wfx_event_handler(struct work_struct *work)
{
	struct wfx_vif *wvif =
		container_of(work, struct wfx_vif, event_handler);
	struct wfx_wsm_event *event;

	LIST_HEAD(list);

	spin_lock(&wvif->event_queue_lock);
	list_splice_init(&wvif->event_queue, &list);
	spin_unlock(&wvif->event_queue_lock);

	list_for_each_entry(event, &list, link) {
		switch (event->evt.EventId) {
		case WSM_EVENT_IND_BSSLOST:
			pr_debug("[CQM] BSS lost.\n");
			cancel_work_sync(&wvif->unjoin_work);
			if (!down_trylock(&wvif->wdev->scan.lock)) {
				wfx_cqm_bssloss_sm(wvif, 1, 0, 0);
				up(&wvif->wdev->scan.lock);
			} else {
				/* Scan is in progress. Delay reporting.
				 * Scan complete will trigger bss_loss_work
				 */
				wvif->delayed_link_loss = 1;
				/* Also start a watchdog. */
				queue_delayed_work(wvif->wdev->workqueue,
						   &wvif->bss_loss_work,
						   5 * HZ);
			}
			break;
		case WSM_EVENT_IND_BSSREGAINED:
			pr_debug("[CQM] BSS regained.\n");
			wfx_cqm_bssloss_sm(wvif, 0, 0, 0);
			cancel_work_sync(&wvif->unjoin_work);
			break;
		case WSM_EVENT_IND_RADAR:
			wiphy_info(wvif->wdev->hw->wiphy, "radar pulse detected\n");
			break;
		case WSM_EVENT_IND_RCPI_RSSI:
		{
			/* RSSI: signed Q8.0, RCPI: unsigned Q7.1
			 * RSSI = RCPI / 2 - 110
			 */
			int rcpi_rssi = (int)(event->evt.EventData.RcpiRssi);
			int cqm_evt;

			if (wvif->cqm_use_rssi)
				rcpi_rssi = (s8)rcpi_rssi;
			else
				rcpi_rssi =  rcpi_rssi / 2 - 110;

			cqm_evt = (rcpi_rssi <= wvif->cqm_rssi_thold) ?
				NL80211_CQM_RSSI_THRESHOLD_EVENT_LOW :
				NL80211_CQM_RSSI_THRESHOLD_EVENT_HIGH;
			pr_debug("[CQM] RSSI event: %d.\n", rcpi_rssi);
#if (KERNEL_VERSION(4, 11, 0) <= LINUX_VERSION_CODE)
			ieee80211_cqm_rssi_notify(wvif->vif, cqm_evt, rcpi_rssi,
						  GFP_KERNEL);
#else
			ieee80211_cqm_rssi_notify(wvif->vif, cqm_evt,
						  GFP_KERNEL);
#endif
			break;
		}
		default:
			dev_warn(wvif->wdev->pdev, "Unhandled indication %.2x\n", event->evt.EventId);
			break;
		}
	}
	__wfx_free_event_queue(&list);
}

void wfx_bss_loss_work(struct work_struct *work)
{
	struct wfx_vif *wvif =
		container_of(work, struct wfx_vif, bss_loss_work.work);

	pr_debug("[CQM] Reporting connection loss.\n");
	ieee80211_connection_loss(wvif->vif);
}

void wfx_bss_params_work(struct work_struct *work)
{
	struct wfx_vif *wvif =
		container_of(work, struct wfx_vif, bss_params_work);

	mutex_lock(&wvif->wdev->conf_mutex);

	wvif->bss_params.BssFlags.LostCountOnly = 1;
	wsm_set_bss_params(wvif->wdev, &wvif->bss_params, wvif->Id);
	wvif->bss_params.BssFlags.LostCountOnly = 0;

	mutex_unlock(&wvif->wdev->conf_mutex);
}

/* NOTE: wfx_send_pds() destroy buf */
int wfx_send_pds(struct wfx_dev *wdev, unsigned char *buf, size_t len)
{
	int ret;
	int start, brace_level, i;

	start = 0;
	brace_level = 0;
	if (buf[0] != '{') {
		dev_err(wdev->pdev, "Valid PDS start with '{'. Did you forget to compress it?");
		return -EINVAL;
	}
	for (i = 1; i < len - 1; i++) {
		if (buf[i] == '{')
			brace_level++;
		if (buf[i] == '}')
			brace_level--;
		if (buf[i] == '}' && !brace_level) {
			i++;
			if (i - start + 1 > WFX_PDS_MAX_SIZE)
				return -EFBIG;
			buf[start] = '{';
			buf[i] = 0;
			dev_dbg(wdev->pdev, "Send PDS '%s}'", buf + start);
			buf[i] = '}';
			ret = wsm_configuration(wdev, buf + start, i - start + 1);
			if (ret == INVALID_PDS_CONFIG_FILE) {
				dev_err(wdev->pdev, "PDS bytes %d to %d: invalid data (unsupported options?)\n", start, i);
				return -EINVAL;
			}
			if (ret == -ETIMEDOUT) {
				dev_err(wdev->pdev, "PDS bytes %d to %d: chip didn't replied (corrupted file?)\n", start, i);
				return ret;
			}
			if (ret) {
				dev_err(wdev->pdev, "PDS bytes %d to %d: chip returned an unknown error\n", start, i);
				return -EIO;
			}
			buf[i] = ',';
			start = i;
		}
	}
	return 0;
}

int wfx_send_pdata_pds(struct wfx_dev *wdev)
{
	int ret = 0;
	const struct firmware *pds;
	unsigned char *tmp_buf;

	ret = request_firmware(&pds, wdev->pdata.file_pds, wdev->pdev);
	if (ret) {
		dev_err(wdev->pdev, "Can't load PDS file %s", wdev->pdata.file_pds);
		return ret;
	}
	tmp_buf = kmemdup(pds->data, pds->size, GFP_KERNEL);
	ret = wfx_send_pds(wdev, tmp_buf, pds->size);
	kfree(tmp_buf);
	release_firmware(pds);
	return ret;
}

static void wfx_join_complete(struct wfx_vif *wvif)
{
	pr_debug("[STA] Join complete (%d)\n", wvif->join_complete_status);

	wvif->join_pending = false;
	if (wvif->join_complete_status) {
		wvif->join_status = WFX_JOIN_STATUS_PASSIVE;
		wfx_update_listening(wvif, wvif->listening);
		wfx_do_unjoin(wvif);
		ieee80211_connection_loss(wvif->vif);
	} else {
		if (wvif->mode == NL80211_IFTYPE_ADHOC)
			wvif->join_status = WFX_JOIN_STATUS_IBSS;
		else
			wvif->join_status = WFX_JOIN_STATUS_PRE_STA;
	}
	wsm_unlock_tx(wvif->wdev); /* Clearing the lock held before do_join() */
}

void wfx_join_complete_work(struct work_struct *work)
{
	struct wfx_vif *wvif =
		container_of(work, struct wfx_vif, join_complete_work);

	mutex_lock(&wvif->wdev->conf_mutex);
	wfx_join_complete(wvif);
	mutex_unlock(&wvif->wdev->conf_mutex);
}

void wfx_join_complete_cb(struct wfx_vif		*wvif,
			  WsmHiJoinCompleteIndBody_t	*arg)
{
	pr_debug("[STA] wfx_join_complete_cb called, status=%d.\n",
		 arg->Status);

	if (cancel_delayed_work(&wvif->join_timeout)) {
		wvif->join_complete_status = arg->Status;
		queue_work(wvif->wdev->workqueue, &wvif->join_complete_work);
	}
}

/* MUST be called with tx_lock held!  It will be unlocked for us. */
static void wfx_do_join(struct wfx_vif *wvif)
{
	const u8 *bssid;
	const u8 *rsnie = NULL;
	u16 *pairwiseCount;
	u16 *akmCount;
	u16 rsnCapabilities;
	u8 mfpc = 0;
	u8 mfpr = 0;
	struct ieee80211_bss_conf *conf = &wvif->vif->bss_conf;
	struct cfg80211_bss *bss = NULL;
	struct wsm_protected_mgmt_policy mgmt_policy;
	WsmHiJoinReqBody_t join = {
		.Mode		= conf->ibss_joined ?
				  WSM_MODE_IBSS : WSM_MODE_BSS,
		.JoinFlags.UseMacAddrIf = wvif->Id,
		.PreambleType	= WSM_PREAMBLE_LONG,
		.ProbeForJoin	= 1,
		.AtimWindow	= 0,
		.BasicRateSet	= wfx_rate_mask_to_wsm(wvif->wdev,
							  conf->basic_rates),
	};

	if (delayed_work_pending(&wvif->join_timeout)) {
		dev_warn(wvif->wdev->pdev, "do_join: join request already pending, skipping..\n");
		wsm_unlock_tx(wvif->wdev);
		return;
	}

	if (wvif->join_status)
		wfx_do_unjoin(wvif);

	bssid = wvif->vif->bss_conf.bssid;

	bss = cfg80211_get_bss(wvif->wdev->hw->wiphy, wvif->wdev->channel, bssid, NULL, 0,
			       IEEE80211_BSS_TYPE_ANY, IEEE80211_PRIVACY_ANY);

	if (!bss && !conf->ibss_joined) {
		wsm_unlock_tx(wvif->wdev);
		return;
	}

	mutex_lock(&wvif->wdev->conf_mutex);

	/* Under the conf lock: check scan status and
	 * bail out if it is in progress.
	 */
	if (atomic_read(&wvif->wdev->scan.in_progress)) {
		wsm_unlock_tx(wvif->wdev);
		goto done_put;
	}

	wvif->join_pending = true;

	/* Sanity check basic rates */
	if (!join.BasicRateSet)
		join.BasicRateSet = 7;

	/* Sanity check beacon interval */
	if (!wvif->beacon_int)
		wvif->beacon_int = 1;

	join.BeaconInterval = wvif->beacon_int;

	if (wvif->wdev->hw->conf.ps_dtim_period)
		wvif->join_dtim_period = wvif->wdev->hw->conf.ps_dtim_period;
	join.DTIMPeriod = wvif->join_dtim_period;

	join.ChannelNumber = wvif->wdev->channel->hw_value;
	join.Band = WSM_PHY_BAND_2_4G;
	memcpy(join.BSSID, bssid, sizeof(join.BSSID));

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

	if (wvif->vif->p2p) {
		join.JoinFlags.P2P = 1;
		join.BasicRateSet =
			wfx_rate_mask_to_wsm(wvif->wdev, 0xFF0);
	}

	wsm_flush_tx(wvif->wdev);

	wfx_update_listening(wvif, false);

	/* Turn on Block ACKs */
	wsm_set_block_ack_policy(wvif->wdev, 0xFF, 0xFF, wvif->Id);

	/* Set up timeout */
	if (join.JoinFlags.ForceWithInd) {
		wvif->join_status = WFX_JOIN_STATUS_JOINING;
		queue_delayed_work(wvif->wdev->workqueue,
				   &wvif->join_timeout,
				   WFX_JOIN_TIMEOUT);
	}

	/* 802.11w protected mgmt frames */

	/* retrieve MFPC and MFPR flags from beacon or PBRSP */

	/* 1. Get the RSN IE */
	rcu_read_lock();
	if (bss)
		rsnie = ieee80211_bss_get_ie(bss, WLAN_EID_RSN);

	if (rsnie != NULL) {
		/* 2. Retrieve Pairwise Cipher Count */
		pairwiseCount =
			(u16 *)(rsnie + PAIRWISE_CIPHER_SUITE_COUNT_OFFSET);

		/* 3. Retrieve AKM Suite Count */
		akmCount =
			(u16 *)(((u8 *)pairwiseCount) +
				AKM_SUITE_COUNT_OFFSET(*pairwiseCount));

		/* 4. Retrieve RSN Capabilities */
		rsnCapabilities =
			*(u16 *)(((u8 *)akmCount) + RSN_CAPA_OFFSET(*akmCount));

		/* 5. Read MFPC and MFPR bits */
		mfpc = ((rsnCapabilities & RSN_CAPA_MFPC_BIT) != 0);
		mfpr = ((rsnCapabilities & RSN_CAPA_MFPR_BIT) != 0);

		pr_debug(
			"PW count = %d, AKM count = %d, rsnCapa = 0x%04x, mfpc = %d; mfpr = %d\n",
			*pairwiseCount,
			*akmCount,
			rsnCapabilities,
			mfpc,
			mfpr);
	}
	rcu_read_unlock();

	/* 6. Set firmware accordingly */
	if (mfpc == 0) {
		/* No PMF */
		mgmt_policy.protectedMgmtEnable = 0;
		mgmt_policy.unprotectedMgmtFramesAllowed = 1;   /* Should be ignored by FW */
		mgmt_policy.encryptionForAuthFrame = 1;         /* Should be ignored by FW */
	} else if (mfpr == 0) {
		/* PMF capable but not required */
		mgmt_policy.protectedMgmtEnable = 1;
	mgmt_policy.unprotectedMgmtFramesAllowed = 1;
	mgmt_policy.encryptionForAuthFrame = 1;
	} else {
		/* PMF required */
		mgmt_policy.protectedMgmtEnable = 1;
		mgmt_policy.unprotectedMgmtFramesAllowed = 0;
		mgmt_policy.encryptionForAuthFrame = 1;
	}

	wsm_set_protected_mgmt_policy(wvif->wdev, &mgmt_policy, wvif->Id);

	/* Perform actual join */
	wvif->wdev->tx_burst_idx = -1;
	if (wsm_join(wvif->wdev, &join, wvif->Id)) {
		ieee80211_connection_loss(wvif->vif);
		wvif->join_complete_status = -1;
		cancel_delayed_work_sync(&wvif->join_timeout);
		wfx_update_listening(wvif, wvif->listening);
		/* Tx lock still held, unjoin will clear it. */
		if (queue_work(wvif->wdev->workqueue, &wvif->unjoin_work) <= 0)
			wsm_unlock_tx(wvif->wdev);
	} else {
		wvif->join_complete_status = 0;
		if (!(join.JoinFlags.ForceWithInd))
			wfx_join_complete(wvif); /* Will clear tx_lock */

		/* Upload keys */
		wfx_upload_keys(wvif);

		/* Due to beacon filtering it is possible that the
		 * AP's beacon is not known for the mac80211 stack.
		 * Disable filtering temporary to make sure the stack
		 * receives at least one
		 */
		wvif->disable_beacon_filter = true;
	}
	wfx_update_filtering(wvif);


done_put:
	mutex_unlock(&wvif->wdev->conf_mutex);
	if (bss)
		cfg80211_put_bss(wvif->wdev->hw->wiphy, bss);
}

void wfx_join_timeout(struct work_struct *work)
{
	struct wfx_vif *wvif =
		container_of(work, struct wfx_vif, join_timeout.work);

	pr_debug("[WSM] Join timed out.\n");
	wsm_lock_tx(wvif->wdev);
	if (queue_work(wvif->wdev->workqueue, &wvif->unjoin_work) <= 0)
		wsm_unlock_tx(wvif->wdev);
}

static void wfx_do_unjoin(struct wfx_vif *wvif)
{
	cancel_delayed_work_sync(&wvif->join_timeout);

	mutex_lock(&wvif->wdev->conf_mutex);
	wvif->join_pending = false;

	if (atomic_read(&wvif->wdev->scan.in_progress)) {
		if (wvif->delayed_unjoin)
			wiphy_dbg(wvif->wdev->hw->wiphy,
				  "Delayed unjoin is already scheduled.\n");
		else
			wvif->delayed_unjoin = true;
		goto done;
	}

	wvif->delayed_link_loss = false;

	if (!wvif->join_status)
		goto done;

	if (wvif->join_status == WFX_JOIN_STATUS_AP)
		goto done;

	cancel_work_sync(&wvif->update_filtering_work);
	cancel_work_sync(&wvif->set_beacon_wakeup_period_work);
	wvif->join_status = WFX_JOIN_STATUS_PASSIVE;

	/* Unjoin is a reset. */
	wsm_flush_tx(wvif->wdev);
	wsm_keep_alive_period(wvif->wdev, 0, wvif->Id);
	wsm_reset(wvif->wdev, true, wvif->Id);
	wsm_set_output_power(wvif->wdev, wvif->wdev->output_power * 10, wvif->Id);
	wvif->join_dtim_period = 0;
	wsm_set_macaddr(wvif->wdev, wvif->wdev->mac_addr, NULL);
	wfx_free_event_queue(wvif);
	cancel_work_sync(&wvif->event_handler);
	wfx_update_listening(wvif, wvif->listening);
	wfx_cqm_bssloss_sm(wvif, 0, 0, 0);

	/* Disable Block ACKs */
	wsm_set_block_ack_policy(wvif->wdev, 0, 0, wvif->Id);

	wvif->disable_beacon_filter = false;
	wfx_update_filtering(wvif);
	memset(&wvif->association_mode, 0,
	       sizeof(wvif->association_mode));
	memset(&wvif->bss_params, 0, sizeof(wvif->bss_params));
	wvif->setbssparams_done = false;
	memset(&wvif->firmware_ps_mode, 0,
	       sizeof(wvif->firmware_ps_mode));

	pr_debug("[STA] Unjoin completed.\n");

done:
	mutex_unlock(&wvif->wdev->conf_mutex);
}

void wfx_unjoin_work(struct work_struct *work)
{
	struct wfx_vif *wvif =
		container_of(work, struct wfx_vif, unjoin_work);

	wfx_do_unjoin(wvif);

	wsm_unlock_tx(wvif->wdev);
}

int wfx_enable_listening(struct wfx_vif *wvif)
{
	WsmHiStartReqBody_t start = {
		.Mode = {
				.StartMode	= WSM_START_MODE_P2P_DEV | (wvif->Id << 4),
			},
		.Band			= WSM_PHY_BAND_2_4G,
		.BeaconInterval		= 100,
		.DTIMPeriod		= 1,
		.ProbeDelay		= 0,
		.BasicRateSet		= 0x0F,
	};

	if (wvif->wdev->channel) {
		start.Band = WSM_PHY_BAND_2_4G;
		start.ChannelNumber = wvif->wdev->channel->hw_value;
	} else {
		start.Band = WSM_PHY_BAND_2_4G;
		start.ChannelNumber = 1;
	}

	wvif->wdev->tx_burst_idx = -1;
	return wsm_start(wvif->wdev, &start, wvif->Id);
}

int wfx_disable_listening(struct wfx_vif *wvif)
{
	return wsm_reset(wvif->wdev, true, wvif->Id);
}

void wfx_update_listening(struct wfx_vif *wvif, bool enabled)
{
	if (enabled) {
		if (wvif->join_status == WFX_JOIN_STATUS_PASSIVE) {
			if (!wfx_enable_listening(wvif))
				wvif->join_status = WFX_JOIN_STATUS_MONITOR;
			wsm_set_probe_responder(wvif, true);
		}
	} else {
		if (wvif->join_status == WFX_JOIN_STATUS_MONITOR) {
			if (!wfx_disable_listening(wvif))
				wvif->join_status = WFX_JOIN_STATUS_PASSIVE;
			wsm_set_probe_responder(wvif, false);
		}
	}
}

int wfx_set_uapsd_param(struct wfx_vif		*wvif,
			   const struct wsm_edca_params *arg)
{
	int ret;

	/* Here's the mapping AC [queue, bit]
	 *  VO [0,3], VI [1, 2], BE [2, 1], BK [3, 0]
	 */

	if (arg->uapsd_enable[IEEE80211_AC_VO])
		wvif->uapsd_info.TrigVoice = 1;
	else
		wvif->uapsd_info.TrigVoice = 0;

	if (arg->uapsd_enable[IEEE80211_AC_VI])
		wvif->uapsd_info.TrigVideo = 1;
	else
		wvif->uapsd_info.TrigVideo = 0;

	if (arg->uapsd_enable[IEEE80211_AC_BE])
		wvif->uapsd_info.TrigBe = 1;
	else
		wvif->uapsd_info.TrigBe = 0;

	if (arg->uapsd_enable[IEEE80211_AC_BK])
		wvif->uapsd_info.TrigBckgrnd = 1;
	else
		wvif->uapsd_info.TrigBckgrnd = 0;

	/* Currently pseudo U-APSD operation is not supported, so setting
	 * MinAutoTriggerInterval, MaxAutoTriggerInterval and
	 * AutoTriggerStep to 0
	 */
	wvif->uapsd_info.MinAutoTriggerInterval = 0;
	wvif->uapsd_info.MaxAutoTriggerInterval = 0;
	wvif->uapsd_info.AutoTriggerStep = 0;

	ret = wsm_set_uapsd_info(wvif->wdev, &wvif->uapsd_info, wvif->Id);
	return ret;
}

/* ******************************************************************** */
/* AP API								*/

int wfx_sta_add(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
		   struct ieee80211_sta *sta)
{
	struct wfx_dev *wdev = hw->priv;
	struct wfx_vif *wvif = (struct wfx_vif *) vif->drv_priv;
	struct wfx_sta_priv *sta_priv =
			(struct wfx_sta_priv *)&sta->drv_priv;
	struct wfx_link_entry *entry;
	struct sk_buff *skb;

	if (wvif->mode != NL80211_IFTYPE_AP)
		return 0;

	sta_priv->vif_id = wvif->Id;
	sta_priv->link_id = wfx_find_link_id(wvif, sta->addr);
	pr_debug("[STA] wfx_sta_add : MAC=%d:%d:%d:%d:%d:%d, link_id=%d\n",
		 sta->addr[0], sta->addr[1], sta->addr[2], sta->addr[3],
		 sta->addr[4], sta->addr[5], sta_priv->link_id);

	if (!sta_priv->link_id) {
		wiphy_info(wdev->hw->wiphy,
			   "[AP] No more link IDs available.\n");
		return -ENOENT;
	}

	entry = &wvif->link_id_db[sta_priv->link_id - 1];
	spin_lock_bh(&wvif->ps_state_lock);
	if ((sta->uapsd_queues & IEEE80211_WMM_IE_STA_QOSINFO_AC_MASK) ==
					IEEE80211_WMM_IE_STA_QOSINFO_AC_MASK)
		wvif->sta_asleep_mask |= BIT(sta_priv->link_id);
	entry->status = WFX_LINK_HARD;
	while ((skb = skb_dequeue(&entry->rx_queue)))
		ieee80211_rx_irqsafe(wdev->hw, skb);
	spin_unlock_bh(&wvif->ps_state_lock);
	return 0;
}

int wfx_sta_remove(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
		      struct ieee80211_sta *sta)
{
	struct wfx_dev *wdev = hw->priv;
	struct wfx_vif *wvif = (struct wfx_vif *) vif->drv_priv;
	struct wfx_sta_priv *sta_priv =
			(struct wfx_sta_priv *)&sta->drv_priv;
	struct wfx_link_entry *entry;

	pr_debug("[STA] wfx_sta_remove\n");

	if (wvif->mode != NL80211_IFTYPE_AP || !sta_priv->link_id)
		return 0;

	entry = &wvif->link_id_db[sta_priv->link_id - 1];
	spin_lock_bh(&wvif->ps_state_lock);
	entry->status = WFX_LINK_RESERVE;
	entry->timestamp = jiffies;
	wsm_lock_tx_async(wdev);
	if (queue_work(wdev->workqueue, &wvif->link_id_work) <= 0)
		wsm_unlock_tx(wdev);
	spin_unlock_bh(&wvif->ps_state_lock);
	flush_workqueue(wdev->workqueue);
	return 0;
}

static void __wfx_sta_notify(struct ieee80211_hw *dev,
				struct ieee80211_vif *vif,
				enum sta_notify_cmd notify_cmd,
				int link_id)
{
	struct wfx_dev *wdev = dev->priv;
	struct wfx_vif *wvif = (struct wfx_vif *) vif->drv_priv;
	u32 bit, prev;

	/* Zero link id means "for all link IDs" */
	if (link_id) {
		bit = BIT(link_id);
	} else if (notify_cmd != STA_NOTIFY_AWAKE) {
		dev_warn(wdev->pdev, "wfx_sta_notify: unsupported notify command");
		bit = 0;
	} else {
		bit = wvif->link_id_map;
	}
	prev = wvif->sta_asleep_mask & bit;

	switch (notify_cmd) {
	case STA_NOTIFY_SLEEP:
		if (!prev) {
			if (wvif->buffered_multicasts &&
			    !wvif->sta_asleep_mask)
				queue_work(wdev->workqueue,
					   &wvif->multicast_start_work);
			wvif->sta_asleep_mask |= bit;
		}
		break;
	case STA_NOTIFY_AWAKE:
		if (prev) {
			wvif->sta_asleep_mask &= ~bit;
			wvif->pspoll_mask &= ~bit;
			if (link_id && !wvif->sta_asleep_mask)
				queue_work(wdev->workqueue,
					   &wvif->multicast_stop_work);
			wfx_bh_wakeup(wdev);
		}
		break;
	}
}

void wfx_sta_notify(struct ieee80211_hw *dev,
		       struct ieee80211_vif *vif,
		       enum sta_notify_cmd notify_cmd,
		       struct ieee80211_sta *sta)
{
	struct wfx_vif *wvif = (struct wfx_vif *) vif->drv_priv;
	struct wfx_sta_priv *sta_priv =
		(struct wfx_sta_priv *)&sta->drv_priv;

	pr_debug("[STA] wfx_sta_notify: link_id=%d, status=%d\n",
		 sta_priv->link_id, sta_priv->link_id);

	spin_lock_bh(&wvif->ps_state_lock);
	__wfx_sta_notify(dev, vif, notify_cmd, sta_priv->link_id);
	spin_unlock_bh(&wvif->ps_state_lock);
}

// FIXME: wfx_ps_notify should change each station status independently
static void wfx_ps_notify(struct wfx_vif *wvif,
		      bool ps)
{
	dev_info(wvif->wdev->pdev, "%s: %s STAs asleep: %.8X\n", __func__,
		 ps ? "Start" : "Stop",
		 wvif->sta_asleep_mask);

	__wfx_sta_notify(wvif->wdev->hw, wvif->vif,
			    ps ? STA_NOTIFY_AWAKE : STA_NOTIFY_SLEEP, 0);
}

static int wfx_set_tim_impl(struct wfx_vif *wvif, bool aid0_bit_set)
{
	struct sk_buff *skb;
	WsmHiIeFlags_t target_frame = {
		.Beacon = 1,
	};
	u16 tim_offset, tim_length;
	u8 *tim_ptr;

	pr_debug("[AP] mcast: %s.\n", aid0_bit_set ? "ena" : "dis");

	skb = ieee80211_beacon_get_tim(wvif->wdev->hw, wvif->vif,
			&tim_offset, &tim_length);
	if (!skb) {
		if (!__wfx_flush(wvif->wdev, true))
			wsm_unlock_tx(wvif->wdev);
		return -ENOENT;
	}
	tim_ptr = skb->data + tim_offset;

	if (tim_offset && tim_length >= 6) {
		/* Ignore DTIM count from mac80211:
		 * firmware handles DTIM internally.
		 */
		tim_ptr[2] = 0;

		/* Set/reset aid0 bit */
		if (aid0_bit_set)
			tim_ptr[4] |= 1;
		else
			tim_ptr[4] &= ~1;
	}

	wsm_update_ie(wvif->wdev, &target_frame, tim_ptr, tim_length, wvif->Id);

	dev_kfree_skb(skb);

	return 0;
}

void wfx_set_tim_work(struct work_struct *work)
{
	struct wfx_vif *wvif =
		container_of(work, struct wfx_vif, set_tim_work);

	(void)wfx_set_tim_impl(wvif, wvif->aid0_bit_set);
}

int wfx_set_tim(struct ieee80211_hw *dev, struct ieee80211_sta *sta,
			   bool set)
{
	struct wfx_dev *wdev = dev->priv;
	struct wfx_sta_priv *sta_dev = (struct wfx_sta_priv *) &sta->drv_priv;
	struct wfx_vif *wvif = wdev_to_wvif(wdev, sta_dev->vif_id);

	queue_work(wdev->workqueue, &wvif->set_tim_work);
	return 0;
}

void wfx_set_cts_work(struct work_struct *work)
{
	struct wfx_vif *wvif = container_of(work, struct wfx_vif, set_cts_work);
	u8 erp_ie[3] = { WLAN_EID_ERP_INFO, 1, 0 };
	WsmHiIeFlags_t target_frame = {
		.Beacon = 1,
	};

	pr_debug("[STA] wfx_set_cts_work\n");

	mutex_lock(&wvif->wdev->conf_mutex);
	erp_ie[2] = wvif->erp_info;
	mutex_unlock(&wvif->wdev->conf_mutex);

	pr_debug("[STA] ERP information 0x%x\n", erp_ie[2]);

	wsm_erp_use_protection(wvif->wdev, erp_ie[2] & WLAN_ERP_USE_PROTECTION, wvif->Id);

	if (wvif->mode != NL80211_IFTYPE_STATION)
		wsm_update_ie(wvif->wdev, &target_frame, erp_ie, sizeof(erp_ie), wvif->Id);
}

void wfx_bss_info_changed(struct ieee80211_hw *dev,
			     struct ieee80211_vif *vif,
			     struct ieee80211_bss_conf *info,
			     u32 changed)
{
	struct wfx_dev *wdev = dev->priv;
	struct wfx_vif *wvif = (struct wfx_vif *) vif->drv_priv;
	bool do_join = false;

	mutex_lock(&wdev->conf_mutex);

	pr_debug("[STA] wfx_bss_info_changed : %08x\n", changed);
	pr_debug("BSS CHANGED:  %08x\n", changed);


	if (changed & BSS_CHANGED_ARP_FILTER) {
		WsmHiMibArpIpAddrTable_t filter = { 0 };
		pr_debug("[STA] BSS_CHANGED_ARP_FILTER cnt: %d\n",
			 info->arp_addr_cnt);

		/* Currently only one IP address is supported by firmware.
		 * In case of more IPs arp filtering will be disabled.
		 */
		if (info->arp_addr_cnt > 0 &&
		    info->arp_addr_cnt <= WSM_MAX_ARP_IP_ADDRTABLE_ENTRIES) {
			int i = 0;
			/*for (i = 0; i < info->arp_addr_cnt; i++) { */
			/* Caution: WsmHiMibArpIpAddrTable_t can store only
			 * 1 IPV4 address
			 * i.e. limited to info->arp_addr_cnt=1
			 */
			/* Caution: type of arp_addr_list[i] is __be32
			 */
			memcpy(filter.Ipv4Address, &info->arp_addr_list[i],
			       sizeof(filter.Ipv4Address));
			/* filter.ipv4addrs[i] = info->arp_addr_list[i]; */
			pr_debug("[STA] addr[%d]: %d.%d.%d.%d\n",
				 i, filter.Ipv4Address[0],
				 filter.Ipv4Address[1], filter.Ipv4Address[2],
				 filter.Ipv4Address[3]);
			/*} */
			filter.ArpFilter = 1;
		}

		pr_debug("[STA] arp ip filter enable: %d\n", filter.ArpFilter);

		wsm_set_arp_ipv4_filter(wdev, &filter, wvif->Id);
	}

	if (changed &
	    (BSS_CHANGED_BEACON |
	     BSS_CHANGED_AP_PROBE_RESP |
	     BSS_CHANGED_BSSID |
	     BSS_CHANGED_SSID |
	     BSS_CHANGED_IBSS)) {
		pr_debug("BSS_CHANGED_BEACON\n");
		wvif->beacon_int = info->beacon_int;
		wfx_update_beaconing(wvif);
		wfx_upload_beacon(wvif);
	}

	if (changed & BSS_CHANGED_BEACON_ENABLED) {
		pr_debug("BSS_CHANGED_BEACON_ENABLED (%d)\n",
			 info->enable_beacon);

		if (wvif->enable_beacon != info->enable_beacon) {
			wsm_beacon_transmit(wvif->wdev, info->enable_beacon, wvif->Id);
			wvif->enable_beacon = info->enable_beacon;
		}
	}

	/* assoc/disassoc, or maybe AID changed */
	if (changed & BSS_CHANGED_ASSOC) {
		wsm_lock_tx(wdev);
		wvif->wep_default_key_id = -1;
		wsm_unlock_tx(wdev);
	}

	if ((changed & BSS_CHANGED_ASSOC) && (info->assoc == 0)
	    && ((wvif->join_status == WFX_JOIN_STATUS_STA) || (wvif->join_status == WFX_JOIN_STATUS_IBSS))) {
		/* Shedule unjoin work */
		pr_debug("[WSM] Issue unjoin command\n");
		wsm_lock_tx_async(wdev);
		if (queue_work(wdev->workqueue, &wvif->unjoin_work) <= 0)
			wsm_unlock_tx(wdev);
	} else {
		if (changed & BSS_CHANGED_BEACON_INT) {
			pr_debug("CHANGED_BEACON_INT\n");
			if (info->ibss_joined)
				do_join = true;
			else if (wvif->join_status == WFX_JOIN_STATUS_AP)
				wfx_update_beaconing(wvif);
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
				if (wvif->join_status <
				    WFX_JOIN_STATUS_PRE_STA) {
					ieee80211_connection_loss(vif);
					mutex_unlock(&wdev->conf_mutex);
					return;
				} else if (wvif->join_status ==
				    WFX_JOIN_STATUS_PRE_STA) {
					wvif->join_status = WFX_JOIN_STATUS_STA;
				}
			} else {
				do_join = true;
			}

			if (info->assoc || info->ibss_joined) {
				struct ieee80211_sta *sta = NULL;
				int htprot = 0;

				if (info->dtim_period)
					wvif->join_dtim_period =
						info->dtim_period;
				wvif->beacon_int = info->beacon_int;

				rcu_read_lock();

				if (info->bssid && !info->ibss_joined)
					sta = ieee80211_find_sta(vif,
								 info->bssid);
				if (sta) {
					wdev->ht_info.ht_cap = sta->ht_cap;
					wvif->bss_params.OperationalRateSet =
						wfx_rate_mask_to_wsm(wdev,
								     sta->supp_rates[
									     wdev
									     ->
									     channel
									     ->
									     band]);
					wdev->ht_info.channel_type =
						cfg80211_get_chandef_type(
							&dev->conf.chandef);
					wdev->ht_info.operation_mode =
						info->ht_operation_mode;
				} else {
					memset(&wdev->ht_info, 0,
					       sizeof(wdev->ht_info));
					wvif->bss_params.OperationalRateSet =
						-1;
				}
				rcu_read_unlock();

				/* Non Greenfield stations present */
				if (wdev->ht_info.operation_mode &
				    IEEE80211_HT_OP_MODE_NON_GF_STA_PRSNT)
					htprot |= WSM_NON_GREENFIELD_STA_PRESENT;

				/* Set HT protection method */
				htprot |= (wdev->ht_info.operation_mode &
					IEEE80211_HT_OP_MODE_PROTECTION) << 2;
				wsm_ht_protection(wdev, htprot, wvif->Id);

				wvif->association_mode.MixedOrGreenfieldType =
					wfx_ht_greenfield(&wdev->ht_info);
				wvif->association_mode.PreambtypeUse = 1;
				wvif->association_mode.Mode = 1;
				wvif->association_mode.Rateset = 1;
				wvif->association_mode.Spacing = 1;
				wvif->association_mode.Snoop = 1;
				wvif->association_mode.PreambleType =
				info->use_short_preamble ?
					WSM_PREAMBLE_SHORT :
					WSM_PREAMBLE_LONG;
				wvif->association_mode.BasicRateSet =
					cpu_to_le32(wfx_rate_mask_to_wsm(wdev,
							info->basic_rates));
				wvif->association_mode.MpduStartSpacing =
					wfx_ht_ampdu_density(&wdev->ht_info);

				wfx_cqm_bssloss_sm(wvif, 0, 0, 0);
				cancel_work_sync(&wvif->unjoin_work);

				wvif->bss_params.BeaconLostCount =
					wvif->cqm_beacon_loss_count;
				wvif->bss_params.AID = info->aid;

				if (wvif->join_dtim_period < 1)
					wvif->join_dtim_period = 1;

				pr_debug("[STA] DTIM %d, interval: %d\n",
					 wvif->join_dtim_period,
					 wvif->beacon_int);
				pr_debug(
					"[STA] Preamble: %d, Greenfield: %d, Aid: %d, Rates: 0x%.8X, Basic: 0x%.8X\n",
					wvif->association_mode.PreambleType,
					wvif->association_mode.MixedOrGreenfieldType,
					wvif->bss_params.AID,
					wvif->bss_params.OperationalRateSet,
					wvif->association_mode.BasicRateSet);
				wsm_set_association_mode(wdev,
							 &wvif->association_mode, wvif->Id);

				if (!info->ibss_joined) {
					wsm_keep_alive_period(wdev,
							      30 /* sec */,
							      wvif->Id);
					wsm_set_bss_params(wdev,
							   &wvif->bss_params,
							   wvif->Id);
					wvif->setbssparams_done = true;
					wfx_set_beacon_wakeup_period_work(
						&wvif->set_beacon_wakeup_period_work);
					wfx_set_pm(wvif, &wvif->powersave_mode);
				}
				if (wvif->vif->p2p) {
					pr_debug(
						"[STA] Setting p2p powersave configuration.\n");
					wsm_set_p2p_ps_modeinfo(wdev,
								&wvif->p2p_ps_modeinfo, wvif->Id);
				}
			} else {
				memset(&wvif->association_mode, 0,
				       sizeof(wvif->association_mode));
				memset(&wvif->bss_params, 0,
				       sizeof(wvif->bss_params));
			}
		}
	}

	/* ERP Protection */
	if (changed & (BSS_CHANGED_ASSOC |
		       BSS_CHANGED_ERP_CTS_PROT |
		       BSS_CHANGED_ERP_PREAMBLE)) {
		u32 prev_erp_info = wvif->erp_info;

		if (info->use_cts_prot)
			wvif->erp_info |= WLAN_ERP_USE_PROTECTION;
		else if (!(prev_erp_info & WLAN_ERP_NON_ERP_PRESENT))
			wvif->erp_info &= ~WLAN_ERP_USE_PROTECTION;

		if (info->use_short_preamble)
			wvif->erp_info |= WLAN_ERP_BARKER_PREAMBLE;
		else
			wvif->erp_info &= ~WLAN_ERP_BARKER_PREAMBLE;

		pr_debug("[STA] ERP Protection: %x\n", wvif->erp_info);

		if (prev_erp_info != wvif->erp_info)
			queue_work(wdev->workqueue, &wvif->set_cts_work);
	}

	/* ERP Slottime */
	if (changed & (BSS_CHANGED_ASSOC | BSS_CHANGED_ERP_SLOT)) {
		uint32_t slot_time = info->use_short_slot ? 9 : 20;

		pr_debug("[STA] Slot time: %d us.\n", slot_time);
		wsm_slot_time(wdev, slot_time, wvif->Id);
	}

	if (changed & (BSS_CHANGED_ASSOC | BSS_CHANGED_CQM)) {
		WsmHiMibRcpiRssiThreshold_t threshold = {
			.RollingAverageCount	= 8,
		};

		pr_debug("[CQM] RSSI threshold subscribe: %d +- %d\n",
			 info->cqm_rssi_thold, info->cqm_rssi_hyst);
		wvif->cqm_rssi_thold = info->cqm_rssi_thold;
		wvif->cqm_rssi_hyst = info->cqm_rssi_hyst;

		if (info->cqm_rssi_thold || info->cqm_rssi_hyst) {
			/* RSSI: signed Q8.0, RCPI: unsigned Q7.1
			 * RSSI = RCPI / 2 - 110
			 */
			if (wvif->cqm_use_rssi) {
				threshold.UpperThreshold =
					info->cqm_rssi_thold +
					info->cqm_rssi_hyst;
				threshold.LowerThreshold =
					info->cqm_rssi_thold;
				threshold.Use = 1;
			} else {
				threshold.UpperThreshold =
					(info->cqm_rssi_thold +
					 info->cqm_rssi_hyst +
					 110) * 2;
				threshold.LowerThreshold =
					(info->cqm_rssi_thold + 110) * 2;
			}
			threshold.Detection = 1;
		} else {
			threshold.Detection = 1;
			threshold.Upperthresh = 1;
			threshold.Lowerthresh = 1;
			if (wvif->cqm_use_rssi)
				threshold.Use = 1;
		}
		wsm_set_rcpi_rssi_threshold(wdev, &threshold, wvif->Id);
	}

	if (changed & BSS_CHANGED_TXPOWER && info->txpower != wdev->output_power) {
		wdev->output_power = info->txpower;
		wsm_set_output_power(wvif->wdev, wdev->output_power * 10, wvif->Id);
	}
	mutex_unlock(&wdev->conf_mutex);

	if (do_join) {
		wsm_lock_tx(wdev);
		wfx_do_join(wvif); /* Will unlock it for us */
	}
}

void wfx_multicast_start_work(struct work_struct *work)
{
	struct wfx_vif *wvif =
		container_of(work, struct wfx_vif, multicast_start_work);
	long tmo = wvif->join_dtim_period * TU_TO_JIFFIES(wvif->beacon_int + 20);

	cancel_work_sync(&wvif->multicast_stop_work);

	if (!wvif->aid0_bit_set) {
		wsm_lock_tx(wvif->wdev);
		wfx_set_tim_impl(wvif, true);
		wvif->aid0_bit_set = true;
		mod_timer(&wvif->mcast_timeout, jiffies + tmo);
		wsm_unlock_tx(wvif->wdev);
	}
}

void wfx_multicast_stop_work(struct work_struct *work)
{
	struct wfx_vif *wvif =
		container_of(work, struct wfx_vif, multicast_stop_work);

	if (wvif->aid0_bit_set) {
		del_timer_sync(&wvif->mcast_timeout);
		wsm_lock_tx(wvif->wdev);
		wvif->aid0_bit_set = false;
		wfx_set_tim_impl(wvif, false);
		wsm_unlock_tx(wvif->wdev);
	}
}

#if (KERNEL_VERSION(4, 14, 0) <= LINUX_VERSION_CODE)
void wfx_mcast_timeout(struct timer_list *t)
{
	struct wfx_vif *wvif = from_timer(wvif, t, mcast_timeout);
#else
void wfx_mcast_timeout(unsigned long arg)
{
	struct wfx_vif *wvif = (struct wfx_vif *)arg;
#endif
	wiphy_warn(wvif->wdev->hw->wiphy,
		   "Multicast delivery timeout.\n");
	spin_lock_bh(&wvif->ps_state_lock);
	wvif->tx_multicast = wvif->aid0_bit_set &&
			     wvif->buffered_multicasts;
	if (wvif->tx_multicast)
		wfx_bh_wakeup(wvif->wdev);
	spin_unlock_bh(&wvif->ps_state_lock);
}

#if (KERNEL_VERSION(4, 4, 69) <= LINUX_VERSION_CODE)
int wfx_ampdu_action(struct ieee80211_hw		*hw,
		     struct ieee80211_vif		*vif,
		     struct ieee80211_ampdu_params	*params)
#else
int wfx_ampdu_action(struct ieee80211_hw *hw,
			struct ieee80211_vif *vif,
			enum ieee80211_ampdu_mlme_action action,
			struct ieee80211_sta *sta, u16 tid, u16 *ssn,
			u8 buf_size, bool amsdu)
#endif
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
void wfx_suspend_resume(struct wfx_vif *wvif,
			WsmHiSuspendResumeTxIndBody_t *arg)
{
	pr_debug("[AP] %s: %s\n",
		 arg->SuspendResumeFlags.ResumeOrSuspend ? "start" : "stop",
		 arg->SuspendResumeFlags.CastType ? "broadcast" : "unicast");

	if (arg->SuspendResumeFlags.CastType) {
		bool cancel_tmo = false;

		spin_lock_bh(&wvif->ps_state_lock);
		if (!arg->SuspendResumeFlags.ResumeOrSuspend) {
			wvif->tx_multicast = false;
		} else {
			wvif->tx_multicast = (wvif->aid0_bit_set &&
					      wvif->buffered_multicasts);
			if (wvif->tx_multicast) {
				cancel_tmo = true;
				wfx_bh_wakeup(wvif->wdev);
			}
		}
		spin_unlock_bh(&wvif->ps_state_lock);
		if (cancel_tmo)
			del_timer_sync(&wvif->mcast_timeout);
	} else {
		spin_lock_bh(&wvif->ps_state_lock);
		wfx_ps_notify(wvif,
			      arg->SuspendResumeFlags.ResumeOrSuspend);
		spin_unlock_bh(&wvif->ps_state_lock);
		if (arg->SuspendResumeFlags.ResumeOrSuspend)
			wfx_bh_wakeup(wvif->wdev);
	}
}

/* ******************************************************************** */
/* AP privates
 */

static int wfx_upload_beacon(struct wfx_vif *wvif)
{
	int ret = 0;
	struct sk_buff *skb = NULL;
	struct ieee80211_mgmt *mgmt;
	WsmHiMibTemplateFrame_t *p;

	if (wvif->mode == NL80211_IFTYPE_STATION ||
	    wvif->mode == NL80211_IFTYPE_MONITOR ||
	    wvif->mode == NL80211_IFTYPE_UNSPECIFIED)
		goto done;

	skb = ieee80211_beacon_get(wvif->wdev->hw, wvif->vif);

	if (!skb)
		return -ENOMEM;

	p = (WsmHiMibTemplateFrame_t *)skb_push(skb, 4);
	p->FrameType = WSM_TMPLT_BCN;
	p->InitRate = WSM_TRANSMIT_RATE_1; /* 1Mbps DSSS */
	if (wvif->vif->p2p)
		p->InitRate = WSM_TRANSMIT_RATE_6;
	p->FrameLength = cpu_to_le16(skb->len - 4);

	ret = wsm_set_template_frame(wvif->wdev, p, wvif->Id);

	skb_pull(skb, 4);

	if (ret)
		goto done;
	mgmt = (void *)skb->data;
	mgmt->frame_control =
		cpu_to_le16(IEEE80211_FTYPE_MGMT |
			      IEEE80211_STYPE_PROBE_RESP);

	p->FrameType = WSM_TMPLT_PRBRES;

	if (wvif->vif->p2p) {
		ret = wsm_set_probe_responder(wvif, true);
	} else {
		ret = wsm_set_template_frame(wvif->wdev, p, wvif->Id);
		wsm_set_probe_responder(wvif, false);
	}

done:
	if (!skb)
		dev_kfree_skb(skb);
	return ret;
}

static int wfx_start_ap(struct wfx_vif *wvif)
{
	int ret;
	struct ieee80211_bss_conf *conf = &wvif->vif->bss_conf;
	WsmHiStartReqBody_t start = {
		.Mode = {
			.StartMode	= wvif->vif->p2p ?
					  WSM_START_MODE_P2P_GO :
					  WSM_START_MODE_AP,
			.IndexMacUse	= wvif->Id,
		},
		.Band			= WSM_PHY_BAND_2_4G,
		.ChannelNumber		= wvif->wdev->channel->hw_value,
		.BeaconInterval		= conf->beacon_int,
		.DTIMPeriod		= conf->dtim_period,
		.PreambleType		= conf->use_short_preamble ? WSM_PREAMBLE_SHORT : WSM_PREAMBLE_LONG,
		.ProbeDelay		= 100,
		.BasicRateSet		= wfx_rate_mask_to_wsm(wvif->wdev, conf->basic_rates),
	};
	struct wsm_operational_mode mode = {
		.power_mode = wvif->wdev->pdata.power_mode,
		.disable_more_flag_usage = true,
	};

	memset(start.Ssid, 0, sizeof(start.Ssid));
	if (!conf->hidden_ssid) {
		start.SsidLength = conf->ssid_len;
		memcpy(start.Ssid, conf->ssid, start.SsidLength);
	}

	wvif->beacon_int = conf->beacon_int;
	wvif->join_dtim_period = conf->dtim_period;

	memset(&wvif->link_id_db, 0, sizeof(wvif->link_id_db));

	pr_debug("[AP] ch: %d(%d), bcn: %d(%d), brt: 0x%.8X, ssid: %.*s.\n",
		 start.ChannelNumber, start.Band,
		 start.BeaconInterval, start.DTIMPeriod,
		 start.BasicRateSet,
		 start.SsidLength, start.Ssid);
	wvif->wdev->tx_burst_idx = -1;
	ret = wsm_start(wvif->wdev, &start, wvif->Id);
	if (!ret)
		ret = wfx_upload_keys(wvif);
	if (!ret && wvif->vif->p2p) {
		pr_debug("[AP] Setting p2p powersave configuration.\n");
		wsm_set_p2p_ps_modeinfo(wvif->wdev, &wvif->p2p_ps_modeinfo, wvif->Id);
	}
	if (!ret) {
		wsm_set_block_ack_policy(wvif->wdev, 0xFF, 0xFF, wvif->Id);
		wvif->join_status = WFX_JOIN_STATUS_AP;
		wfx_update_filtering(wvif);
	}
	wsm_set_operational_mode(wvif->wdev, &mode, wvif->Id);
	return ret;
}

static int wfx_update_beaconing(struct wfx_vif *wvif)
{
	struct ieee80211_bss_conf *conf = &wvif->vif->bss_conf;

	if (wvif->mode == NL80211_IFTYPE_AP) {
		if (wvif->join_status != WFX_JOIN_STATUS_AP ||
		    wvif->beacon_int != conf->beacon_int) {
			pr_debug("ap restarting\n");
			wsm_lock_tx(wvif->wdev);
			if (wvif->join_status != WFX_JOIN_STATUS_PASSIVE)
				wsm_reset(wvif->wdev, true, wvif->Id);
			wvif->join_status = WFX_JOIN_STATUS_PASSIVE;
			wfx_start_ap(wvif);
			wsm_unlock_tx(wvif->wdev);
		} else {
			pr_debug("ap started join_status: %d\n",
				 wvif->join_status);
	}
	}
	return 0;
}

static int wfx_vif_setup(struct wfx_vif *wvif)
{
	/* Spin lock */
	spin_lock_init(&wvif->vif_lock);
	spin_lock_init(&wvif->ps_state_lock);
	spin_lock_init(&wvif->event_queue_lock);
	mutex_init(&wvif->bss_loss_lock);
	/* STA Work*/
	INIT_LIST_HEAD(&wvif->event_queue);
	INIT_WORK(&wvif->event_handler, wfx_event_handler);
	INIT_DELAYED_WORK(&wvif->join_timeout, wfx_join_timeout);
	INIT_WORK(&wvif->unjoin_work, wfx_unjoin_work);
	INIT_WORK(&wvif->join_complete_work, wfx_join_complete_work);
	INIT_WORK(&wvif->wep_key_work, wfx_wep_key_work);
	INIT_WORK(&wvif->bss_params_work, wfx_bss_params_work);
	INIT_WORK(&wvif->set_beacon_wakeup_period_work, wfx_set_beacon_wakeup_period_work);
	INIT_DELAYED_WORK(&wvif->bss_loss_work, wfx_bss_loss_work);

	/* AP Work */
	INIT_WORK(&wvif->link_id_work, wfx_link_id_work);
	INIT_DELAYED_WORK(&wvif->link_id_gc_work, wfx_link_id_gc_work);
	INIT_WORK(&wvif->linkid_reset_work, wfx_link_id_reset);
	INIT_WORK(&wvif->update_filtering_work, wfx_update_filtering_work);

	/* Optional */
	INIT_WORK(&wvif->set_tim_work, wfx_set_tim_work);
	INIT_WORK(&wvif->set_cts_work, wfx_set_cts_work);

	INIT_WORK(&wvif->multicast_start_work, wfx_multicast_start_work);
	INIT_WORK(&wvif->multicast_stop_work, wfx_multicast_stop_work);
#if (KERNEL_VERSION(4, 14, 0) <= LINUX_VERSION_CODE)
	timer_setup(&wvif->mcast_timeout, wfx_mcast_timeout, 0);
#else
	setup_timer(&wvif->mcast_timeout, wfx_mcast_timeout, (unsigned long) wvif);
#endif

	wvif->setbssparams_done = false;
	wvif->power_set_true = 0;
	wvif->user_power_set_true = 0;
	wvif->user_pm_mode = 0;
	wvif->htcap = false;
	/* default EDCA */
	fill_edca(&wvif->edca, 0, 0x0002, 0x0003, 0x0007, 47, 0xc8, false);
	fill_edca(&wvif->edca, 1, 0x0002, 0x0007, 0x000f, 94, 0xc8, false);
	fill_edca(&wvif->edca, 2, 0x0003, 0x000f, 0x03ff, 0, 0xc8, false);
	fill_edca(&wvif->edca, 3, 0x0007, 0x000f, 0x03ff, 0, 0xc8, false);

	memset(wvif->bssid, ~0, ETH_ALEN);
	wvif->wep_default_key_id = -1;
	wvif->cipherType = 0;
	wvif->cqm_link_loss_count = 40;
	wvif->cqm_beacon_loss_count = 20;
	wvif->rts_threshold = 1000;

	return 0;
}
