// SPDX-License-Identifier: GPL-2.0-only
/*
 * Implementation of mac80211 API.
 *
 * Copyright (c) 2017-2019, Silicon Laboratories, Inc.
 * Copyright (c) 2010, ST-Ericsson
 */
#include <net/mac80211.h>

#include "sta.h"
#include "wfx.h"
#include "fwio.h"
#include "bh.h"
#include "key.h"
#include "debug.h"
#include "wsm_rx.h"
#include "wsm_tx.h"
#include "wsm_mib.h"

#define TXOP_UNIT			32

static int __wfx_flush(struct wfx_dev *wdev, bool drop);

static void wfx_unjoin_work(struct work_struct *work);
static void wfx_bss_params_work(struct work_struct *work);
static void wfx_bss_loss_work(struct work_struct *work);
static void wfx_event_handler_work(struct work_struct *work);
static void wfx_update_filtering_work(struct work_struct *work);
static void wfx_set_beacon_wakeup_period_work(struct work_struct *work);
static void wfx_set_tim_work(struct work_struct *work);
static void wfx_set_cts_work(struct work_struct *work);
static void wfx_multicast_start_work(struct work_struct *work);
static void wfx_multicast_stop_work(struct work_struct *work);
#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
static void wfx_mcast_timeout(unsigned long arg);
#else
static void wfx_mcast_timeout(struct timer_list *t);
#endif

static u32 wfx_rate_mask_to_wsm(struct wfx_dev *wdev, u32 rates)
{
	int i;
	u32 ret = 0;
	// WFx only support 2GHz
	struct ieee80211_supported_band *sband = wdev->hw->wiphy->bands[NL80211_BAND_2GHZ];

	for (i = 0; i < sband->n_bitrates; i++) {
		if (rates & BIT(i)) {
			if (i >= sband->n_bitrates)
				dev_warn(wdev->dev, "unsupported basic rate\n");
			else
				ret |= BIT(sband->bitrates[i].hw_value);
		}
	}
	return ret;
}

static void __wfx_free_event_queue(struct list_head *list)
{
	struct wfx_wsm_event *event, *tmp;

	list_for_each_entry_safe(event, tmp, list, link) {
		list_del(&event->link);
		kfree(event);
	}
}

static void wfx_free_event_queue(struct wfx_vif *wvif)
{
	LIST_HEAD(list);

	spin_lock(&wvif->event_queue_lock);
	list_splice_init(&wvif->event_queue, &list);
	spin_unlock(&wvif->event_queue_lock);

	__wfx_free_event_queue(&list);
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
		schedule_delayed_work(&wvif->bss_loss_work, HZ);
		wvif->bss_loss_state = 0;

		/* Skip the confimration procedure in P2P case */
		if (!wvif->vif->p2p && !atomic_read(&wvif->wdev->tx_lock))
			tx = 1;
	} else if (good) {
		cancel_delayed_work_sync(&wvif->bss_loss_work);
		wvif->bss_loss_state = 0;
		schedule_work(&wvif->bss_params_work);
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

#if (KERNEL_VERSION(4, 14, 16) > LINUX_VERSION_CODE)
		skb = ieee80211_nullfunc_get(wvif->wdev->hw, wvif->vif);
#else
		skb = ieee80211_nullfunc_get(wvif->wdev->hw, wvif->vif, false);
#endif
		if (!skb)
			dev_err(wvif->wdev->dev, "failed to retrieve a nullfunc\n");
		if (skb)
			wfx_tx(wvif->wdev->hw, NULL, skb);
	}
}

void wfx_cqm_bssloss_sm(struct wfx_vif *wvif, int init, int good, int bad)
{
	mutex_lock(&wvif->bss_loss_lock);
	__wfx_cqm_bssloss_sm(wvif, init, good, bad);
	mutex_unlock(&wvif->bss_loss_lock);
}

int wfx_start(struct ieee80211_hw *hw)
{
	return 0;
}

/*This should stop WFx driver when receive a critical error.
 * It must turn off frame reception
 */
void wfx_stop(struct ieee80211_hw *hw)
{
	struct wfx_dev *wdev = hw->priv;

	int i;

	wsm_tx_lock_flush(wdev);

	mutex_lock(&wdev->conf_mutex);

	for (i = 0; i < 4; i++)
		wfx_queue_clear(wdev, &wdev->tx_queue[i]);
	mutex_unlock(&wdev->conf_mutex);

	if (atomic_xchg(&wdev->tx_lock, 1) != 1)
		pr_debug("[STA] TX is force-unlocked due to stop request.\n");

	wsm_tx_unlock(wdev);
	atomic_xchg(&wdev->tx_lock, 0); /* for recovery to work */
}

static int wfx_set_uapsd_param(struct wfx_vif		*wvif,
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

static int wfx_vif_setup(struct wfx_vif *wvif)
{
	int i;
	// FIXME: parameters are set by kernel juste after interface_add.
	// Keep WsmHiEdcaQueueParamsReqBody_t blank?
	WsmHiEdcaQueueParamsReqBody_t default_edca_params[] = {
		[IEEE80211_AC_VO] = {
			.QueueId = WSM_QUEUE_ID_VOICE,
			.AIFSN = 2,
			.CwMin = 3,
			.CwMax = 7,
			.TxOpLimit = TXOP_UNIT * 47,
		},
		[IEEE80211_AC_VI] = {
			.QueueId = WSM_QUEUE_ID_VIDEO,
			.AIFSN = 2,
			.CwMin = 7,
			.CwMax = 15,
			.TxOpLimit = TXOP_UNIT * 94,
		},
		[IEEE80211_AC_BE] = {
			.QueueId = WSM_QUEUE_ID_BESTEFFORT,
			.AIFSN = 3,
			.CwMin = 15,
			.CwMax = 1023,
			.TxOpLimit = TXOP_UNIT * 0,
		},
		[IEEE80211_AC_BK] = {
			.QueueId = WSM_QUEUE_ID_BACKGROUND,
			.AIFSN = 7,
			.CwMin = 15,
			.CwMax = 1023,
			.TxOpLimit = TXOP_UNIT * 0,
		},
	};

	if (wfx_api_older_than(wvif->wdev, 2, 0)) {
		default_edca_params[IEEE80211_AC_BE].QueueId = WSM_QUEUE_ID_BACKGROUND;
		default_edca_params[IEEE80211_AC_BK].QueueId = WSM_QUEUE_ID_BESTEFFORT;
	}
	/* Spin lock */
	spin_lock_init(&wvif->ps_state_lock);
	spin_lock_init(&wvif->event_queue_lock);
	mutex_init(&wvif->bss_loss_lock);
	/* STA Work*/
	INIT_LIST_HEAD(&wvif->event_queue);
	INIT_WORK(&wvif->event_handler_work, wfx_event_handler_work);
	INIT_WORK(&wvif->unjoin_work, wfx_unjoin_work);
	INIT_WORK(&wvif->wep_key_work, wfx_wep_key_work);
	INIT_WORK(&wvif->bss_params_work, wfx_bss_params_work);
	INIT_WORK(&wvif->set_beacon_wakeup_period_work, wfx_set_beacon_wakeup_period_work);
	INIT_DELAYED_WORK(&wvif->bss_loss_work, wfx_bss_loss_work);
	INIT_WORK(&wvif->tx_policy_upload_work, tx_policy_upload_work);

	/* AP Work */
	INIT_WORK(&wvif->link_id_work, wfx_link_id_work);
	INIT_WORK(&wvif->link_id_reset_work, wfx_link_id_reset_work);
	INIT_DELAYED_WORK(&wvif->link_id_gc_work, wfx_link_id_gc_work);
	INIT_WORK(&wvif->update_filtering_work, wfx_update_filtering_work);

	/* Optional */
	INIT_WORK(&wvif->set_tim_work, wfx_set_tim_work);
	INIT_WORK(&wvif->set_cts_work, wfx_set_cts_work);

	INIT_WORK(&wvif->multicast_start_work, wfx_multicast_start_work);
	INIT_WORK(&wvif->multicast_stop_work, wfx_multicast_stop_work);
#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
	setup_timer(&wvif->mcast_timeout, wfx_mcast_timeout, (unsigned long) wvif);
#else
	timer_setup(&wvif->mcast_timeout, wfx_mcast_timeout, 0);
#endif

	/* About scan */
	sema_init(&wvif->scan.lock, 1);
	INIT_WORK(&wvif->scan.work, wfx_scan_work);
	INIT_DELAYED_WORK(&wvif->scan.timeout, wfx_scan_timeout);
	init_completion(&wvif->set_pm_mode_complete);
	complete(&wvif->set_pm_mode_complete);

	BUG_ON(ARRAY_SIZE(default_edca_params) != ARRAY_SIZE(wvif->edca.params));
	for (i = 0; i < ARRAY_SIZE(default_edca_params); i++) {
		memcpy(&wvif->edca.params[i], &default_edca_params[i], sizeof(default_edca_params[i]));
		wvif->edca.uapsd_enable[i] = false;
	}
	wvif->setbssparams_done = false;
	wvif->wep_default_key_id = -1;

	return 0;
}

int wfx_add_interface(struct ieee80211_hw *hw,
			 struct ieee80211_vif *vif)
{
	int i;
	struct wfx_dev *wdev = hw->priv;
	struct wfx_vif *wvif = (struct wfx_vif *) vif->drv_priv;

	vif->driver_flags |= IEEE80211_VIF_BEACON_FILTER |
#if (KERNEL_VERSION(3, 19, 0) <= LINUX_VERSION_CODE)
			     IEEE80211_VIF_SUPPORTS_UAPSD |
#endif
			     IEEE80211_VIF_SUPPORTS_CQM_RSSI;

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

	for (i = 0; i < ARRAY_SIZE(wdev->vif); i++) {
		if (!wdev->vif[i]) {
			wdev->vif[i] = vif;
			wvif->Id = i;
			break;
		}
	}
	if (i == ARRAY_SIZE(wdev->vif)) {
		mutex_unlock(&wdev->conf_mutex);
		return -EOPNOTSUPP;
	}
	wvif->vif = vif;
	wvif->wdev = wdev;
	wvif->mode = vif->type;
	wfx_vif_setup(wvif);
	mutex_unlock(&wdev->conf_mutex);
	wsm_set_macaddr(wdev, vif->addr, wvif->Id);
	for (i = 0; i < 4; i++)
		wsm_set_edca_queue_params(wdev, &wvif->edca.params[i], wvif->Id);
	wfx_set_uapsd_param(wvif, &wvif->edca);
	tx_policy_init(wvif);
	wvif = NULL;
	while ((wvif = wvif_iterate(wdev, wvif)) != NULL) {
		// Combo mode does not support Block Acks. We can re-enable them
		if (wvif_count(wdev) == 1)
			wsm_set_block_ack_policy(wvif->wdev, 0xFF, 0xFF, wvif->Id);
		else
			wsm_set_block_ack_policy(wvif->wdev, 0x00, 0x00, wvif->Id);
		// Combo force powersave mode. We can re-enable it now
		wfx_set_pm(wvif, &wvif->powersave_mode);
	}
	return 0;
}

void wfx_remove_interface(struct ieee80211_hw *hw,
			     struct ieee80211_vif *vif)
{
	struct wfx_dev *wdev = hw->priv;
	struct wfx_vif *wvif = (struct wfx_vif *) vif->drv_priv;
	int i;

	// If scan is in progress, stop it
	while (down_trylock(&wvif->scan.lock))
		schedule();
	up(&wvif->scan.lock);
	wait_for_completion_timeout(&wvif->set_pm_mode_complete, msecs_to_jiffies(300));

	mutex_lock(&wdev->conf_mutex);
	switch (wvif->state) {
	case WFX_STATE_PRE_STA:
	case WFX_STATE_STA:
	case WFX_STATE_IBSS:
		wsm_tx_lock_flush(wdev);
		if (!schedule_work(&wvif->unjoin_work))
			wsm_tx_unlock(wdev);
		break;
	case WFX_STATE_AP:
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
		wsm_reset(wdev, false, wvif->Id);
		break;
	default:
		break;
	}
	wvif->mode = NL80211_IFTYPE_MONITOR;

	wvif->state = WFX_STATE_PASSIVE;
	wfx_queue_wait_empty_vif(wvif);
	wsm_tx_unlock(wdev);

	wsm_set_macaddr(wdev, NULL, wvif->Id);

	cancel_delayed_work_sync(&wvif->scan.timeout);

	wfx_cqm_bssloss_sm(wvif, 0, 0, 0);
	cancel_work_sync(&wvif->unjoin_work);
	cancel_delayed_work_sync(&wvif->link_id_gc_work);
	del_timer_sync(&wvif->mcast_timeout);
	wfx_free_event_queue(wvif);

	wdev->vif[wvif->Id] = NULL;
	wvif->mode = NL80211_IFTYPE_UNSPECIFIED;
	wvif->vif = NULL;

	mutex_unlock(&wdev->conf_mutex);
	wvif = NULL;
	while ((wvif = wvif_iterate(wdev, wvif)) != NULL) {
		// Combo mode does not support Block Acks. We can re-enable them
		if (wvif_count(wdev) == 1)
			wsm_set_block_ack_policy(wvif->wdev, 0xFF, 0xFF, wvif->Id);
		else
			wsm_set_block_ack_policy(wvif->wdev, 0x00, 0x00, wvif->Id);
		// Combo force powersave mode. We can re-enable it now
		wfx_set_pm(wvif, &wvif->powersave_mode);
	}
}

int wfx_change_interface(struct ieee80211_hw *hw,
			    struct ieee80211_vif *vif,
			    enum nl80211_iftype new_type,
			    bool p2p)
{
	int ret = 0;

	if (new_type != vif->type || vif->p2p != p2p) {
		wfx_remove_interface(hw, vif);
		vif->type = new_type;
		vif->p2p = p2p;
		ret = wfx_add_interface(hw, vif);
	}

	return ret;
}

int wfx_add_chanctx(struct ieee80211_hw *hw,
		    struct ieee80211_chanctx_conf *conf)
{
	return 0;
}

void wfx_remove_chanctx(struct ieee80211_hw *hw,
			struct ieee80211_chanctx_conf *conf)
{
}

void wfx_change_chanctx(struct ieee80211_hw *hw,
			struct ieee80211_chanctx_conf *conf,
			u32 changed)
{
}

int wfx_assign_vif_chanctx(struct ieee80211_hw *hw,
			   struct ieee80211_vif *vif,
			   struct ieee80211_chanctx_conf *conf)
{
	struct wfx_vif *wvif = (struct wfx_vif *) vif->drv_priv;
	struct ieee80211_channel *ch = conf->def.chan;

	WARN(wvif->channel, "Channel overwrite");
	wvif->channel = ch;
	wvif->ht_info.channel_type = cfg80211_get_chandef_type(&conf->def);

	return 0;
}

void wfx_unassign_vif_chanctx(struct ieee80211_hw *hw,
		struct ieee80211_vif *vif,
		struct ieee80211_chanctx_conf *conf)
{
	struct wfx_vif *wvif = (struct wfx_vif *) vif->drv_priv;
	struct ieee80211_channel *ch = conf->def.chan;

	WARN(wvif->channel != ch, "Channel mismatch");
	wvif->channel = NULL;
}

int wfx_config(struct ieee80211_hw *hw, u32 changed)
{
	int ret = 0;
	struct wfx_dev *wdev = hw->priv;
	struct ieee80211_conf *conf = &hw->conf;
	struct wfx_vif *wvif;

	mutex_lock(&wdev->conf_mutex);

	// FIXME: Interface id should not been hardcoded
	wvif = wdev_to_wvif(wdev, 0);
	if (!wvif) {
		WARN(1, "Interface 0 does not exist anymore");
		mutex_unlock(&wdev->conf_mutex);
		return 0;
	}

	down(&wvif->scan.lock);
	if (changed & IEEE80211_CONF_CHANGE_POWER) {
		wdev->output_power = conf->power_level;
		pr_debug("[STA] TX power: %d\n", wdev->output_power);
		wsm_set_output_power(wdev, wdev->output_power * 10, wvif->Id);
	}

	if (changed & IEEE80211_CONF_CHANGE_PS) {
		wvif = NULL;
		while ((wvif = wvif_iterate(wdev, wvif)) != NULL) {
			memset(&wvif->powersave_mode, 0, sizeof(wvif->powersave_mode));
			if (conf->flags & IEEE80211_CONF_PS) {
				wvif->powersave_mode.PmMode.EnterPsm = 1;
				if (conf->dynamic_ps_timeout > 0) {
					wvif->powersave_mode.PmMode.FastPsm = 1;
					// Firmware does not support more than 128ms
					wvif->powersave_mode.FastPsmIdlePeriod =
						min(conf->dynamic_ps_timeout * 2, 255);
				}
			}
			if (wvif->state == WFX_STATE_STA && wvif->bss_params.AID)
				wfx_set_pm(wvif, &wvif->powersave_mode);
		}
		wvif = wdev_to_wvif(wdev, 0);
	}

	if (changed & IEEE80211_CONF_CHANGE_RETRY_LIMITS) {
		pr_debug("[STA] Retry limits: %d (long), %d (short).\n",
			 conf->long_frame_max_tx_count,
			 conf->short_frame_max_tx_count);
		// FIXME: move wvif->tx_policy_cache.lock to wdev
		spin_lock_bh(&wvif->tx_policy_cache.lock);
		wdev->long_frame_max_tx_count = conf->long_frame_max_tx_count;
		wdev->short_frame_max_tx_count =
			(conf->short_frame_max_tx_count < 0x0F) ?
			conf->short_frame_max_tx_count : 0x0F;
		wdev->hw->max_rate_tries = wdev->short_frame_max_tx_count;
		spin_unlock_bh(&wvif->tx_policy_cache.lock);
	}
	mutex_unlock(&wdev->conf_mutex);
	up(&wvif->scan.lock);
	return ret;
}

static int wfx_set_multicast_filter(struct wfx_dev *wdev,
					   struct wfx_grp_addr_table *fp,
					   int Id)
{
	int i, ret;
	WsmHiMibConfigDataFilter_t FilterConfig = { };
	WsmHiMibSetDataFiltering_t DataFiltering = { };
	WsmHiMibMacAddrDataFrameCondition_t MacAddrCond = { };
	WsmHiMibUcMcBcDataFrameCondition_t UcMcBcCond = { };

	// Temporary workaround for filters
	return wsm_set_data_filtering(wdev, &DataFiltering, Id);

	if (!fp->enable) {
		DataFiltering.Enable = 0;
		return wsm_set_data_filtering(wdev, &DataFiltering, Id);
	}

	// A1 Address match on list
	for (i = 0; i < fp->num_addresses; i++) {
		MacAddrCond.ConditionIdx = i;
		MacAddrCond.AddressType = WSM_MAC_ADDR_A1;
		ether_addr_copy(MacAddrCond.MacAddress, fp->address_list[i]);
		ret = wsm_set_mac_addr_condition(wdev, &MacAddrCond, Id);
		if (ret)
			return ret;
		FilterConfig.MacCond |= 1 << i;
		pr_debug("[STA] Multicast Match addr[%d]: %pM\n", i, MacAddrCond.MacAddress);
	}

	// Accept unicast and broadcast
	UcMcBcCond.ConditionIdx = 0;
	UcMcBcCond.Param.bits.TypeUnicast = 1;
	UcMcBcCond.Param.bits.TypeBroadcast = 1;
	ret = wsm_set_uc_mc_bc_condition(wdev, &UcMcBcCond, Id);
	if (ret)
		return ret;

	FilterConfig.UcMcBcCond = 1;
	FilterConfig.FilterIdx = 0; // TODO #define MULTICAST_FILTERING 0
	FilterConfig.Enable = 1;
	ret = wsm_set_config_data_filter(wdev, &FilterConfig, Id);
	if (ret)
		return ret;

	// discard all data frames except match filter
	DataFiltering.Enable = 1;
	DataFiltering.DefaultFilter = 1; // discard all
	ret = wsm_set_data_filtering(wdev, &DataFiltering, Id);

	return ret;
}

void wfx_update_filtering(struct wfx_vif *wvif)
{
	int ret;
	bool is_p2p = wvif->vif && wvif->vif->p2p;
	bool is_sta = wvif->vif && NL80211_IFTYPE_STATION == wvif->vif->type;
	struct wsm_rx_filter l_rx_filter;
	WsmHiMibBcnFilterEnable_t bf_ctrl;
	WsmHiMibBcnFilterTable_t *bf_tbl;
	WsmHiIeTableEntry_t ie_tbl[] = {
		{
			.IeId        = WLAN_EID_VENDOR_SPECIFIC,
			.HasChanged  = 1,
			.NoLonger    = 1,
			.HasAppeared = 1,
			.Oui         = { 0x50, 0x6F, 0x9A},
		}, {
			.IeId        = WLAN_EID_HT_OPERATION,
			.HasChanged  = 1,
			.NoLonger    = 1,
			.HasAppeared = 1,
		}, {
			.IeId        = WLAN_EID_ERP_INFO,
			.HasChanged  = 1,
			.NoLonger    = 1,
			.HasAppeared = 1,
		}
	};

	memcpy(&l_rx_filter, &wvif->rx_filter, sizeof(l_rx_filter));

	if (wvif->state == WFX_STATE_PASSIVE)
		return;

	bf_tbl = kmalloc(sizeof(WsmHiMibBcnFilterTable_t) + sizeof(ie_tbl), GFP_KERNEL);
	memcpy(bf_tbl->IeTable, ie_tbl, sizeof(ie_tbl));
	if (wvif->disable_beacon_filter) {
		bf_ctrl.Enable = 0;
		bf_ctrl.BcnCount = 1;
		bf_tbl->NumOfInfoElmts = 0;
	} else if (is_p2p || !is_sta) {
		bf_ctrl.Enable = WSM_BEACON_FILTER_ENABLE |
			WSM_BEACON_FILTER_AUTO_ERP;
		bf_ctrl.BcnCount = 0;
		bf_tbl->NumOfInfoElmts = 2;
	} else {
		bf_ctrl.Enable = WSM_BEACON_FILTER_ENABLE;
		bf_ctrl.BcnCount = 0;
		bf_tbl->NumOfInfoElmts = 3;
	}
	if (is_p2p)
		l_rx_filter.bssid = false;

	ret = wsm_set_rx_filter(wvif->wdev, &l_rx_filter, wvif->Id);
	if (!ret)
		ret = wsm_set_beacon_filter_table(wvif->wdev, bf_tbl, wvif->Id);
	if (!ret)
		ret = wsm_beacon_filter_control(wvif->wdev, bf_ctrl.Enable, bf_ctrl.BcnCount, wvif->Id);
	if (!ret)
		ret = wfx_set_multicast_filter(wvif->wdev, &wvif->multicast_filter, wvif->Id);
	if (ret)
		dev_err(wvif->wdev->dev,
			  "Update filtering failed: %d.\n", ret);
	kfree(bf_tbl);
}

void wfx_update_filtering_work(struct work_struct *work)
{
	struct wfx_vif *wvif =
		container_of(work, struct wfx_vif, update_filtering_work);

	wfx_update_filtering(wvif);
}

u64 wfx_prepare_multicast(struct ieee80211_hw *hw, struct netdev_hw_addr_list *mc_list)
{
	int i;
	struct netdev_hw_addr *ha;
	struct wfx_vif *wvif = NULL;
	struct wfx_dev *wdev = hw->priv;
	int count = netdev_hw_addr_list_count(mc_list);

	while ((wvif = wvif_iterate(wdev, wvif)) != NULL) {
		memset(&wvif->multicast_filter, 0x00, sizeof(wvif->multicast_filter));
		if (!count || count > ARRAY_SIZE(wvif->multicast_filter.address_list))
			continue;

		i = 0;
		netdev_hw_addr_list_for_each(ha, mc_list) {
			ether_addr_copy(wvif->multicast_filter.address_list[i], ha->addr);
			i++;
		}
		wvif->multicast_filter.enable = 1;
		wvif->multicast_filter.num_addresses = count;
	}

	return 0;
}

void wfx_configure_filter(struct ieee80211_hw *hw,
			     unsigned int changed_flags,
			     unsigned int *total_flags,
			     u64 unused)
{
	struct wfx_vif *wvif = NULL;
	struct wfx_dev *wdev = hw->priv;

	*total_flags &= FIF_OTHER_BSS | FIF_FCSFAIL | FIF_PROBE_REQ;

	while ((wvif = wvif_iterate(wdev, wvif)) != NULL) {
		down(&wvif->scan.lock);
		wvif->rx_filter.bssid = (*total_flags & (FIF_OTHER_BSS | FIF_PROBE_REQ)) ? 0 : 1;
		wvif->disable_beacon_filter = !(*total_flags & FIF_PROBE_REQ);
		wsm_fwd_probe_req(wvif, true);
		wfx_update_filtering(wvif);
		up(&wvif->scan.lock);
	}
}

int wfx_conf_tx(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
		   u16 queue, const struct ieee80211_tx_queue_params *params)
{
	struct wfx_dev *wdev = hw->priv;
	struct wfx_vif *wvif = (struct wfx_vif *) vif->drv_priv;
	int ret = 0;
	/* To prevent re-applying PM request OID again and again*/
	u16 old_uapsd_flags, new_uapsd_flags;
	WsmHiEdcaQueueParamsReqBody_t *edca;

	mutex_lock(&wdev->conf_mutex);

	if (queue < hw->queues) {
		old_uapsd_flags = *((u16 *) &wvif->uapsd_info);
		edca = &wvif->edca.params[queue];

		wvif->edca.uapsd_enable[queue] = params->uapsd;
		edca->AIFSN = params->aifs;
		edca->CwMin = params->cw_min;
		edca->CwMax = params->cw_max;
		edca->TxOpLimit = params->txop * TXOP_UNIT;
		edca->AllowedMediumTime = 0;
		ret = wsm_set_edca_queue_params(wdev, edca, wvif->Id);
		if (ret) {
			ret = -EINVAL;
			goto out;
		}

		if (wvif->mode == NL80211_IFTYPE_STATION) {
			ret = wfx_set_uapsd_param(wvif, &wvif->edca);
			new_uapsd_flags = *((u16 *) &wvif->uapsd_info);
			if (!ret && wvif->setbssparams_done &&
			    wvif->state == WFX_STATE_STA &&
			    /* (old_uapsd_flags != le16_to_cpu(wvif->uapsd_info.uapsd_flags))) */
			    old_uapsd_flags != new_uapsd_flags)
				ret = wfx_set_pm(wvif, &wvif->powersave_mode);
		}
	} else {
		ret = -EINVAL;
	}

out:
	mutex_unlock(&wdev->conf_mutex);
	return ret;
}

int wfx_get_stats(struct ieee80211_hw *hw,
		     struct ieee80211_low_level_stats *stats)
{
	struct wfx_dev *wdev = hw->priv;

	memcpy(stats, &wdev->stats, sizeof(*stats));
	return 0;
}

int wfx_set_pm(struct wfx_vif *wvif, const WsmHiSetPmModeReqBody_t *arg)
{
	WsmHiSetPmModeReqBody_t pm = *arg;
	u16 uapsd_flags;
	int ret;

	if (wvif->state != WFX_STATE_STA || !wvif->bss_params.AID)
		return 0;

	memcpy(&uapsd_flags, &wvif->uapsd_info, sizeof(uapsd_flags));

	if (uapsd_flags != 0) {
		pm.PmMode.FastPsm = 0;
	}
	// Kernel disable PowerSave when multiple vifs are in use. In contrary,
	// it is absolutly necessary to enable PowerSave for WF200
	if (wvif_count(wvif->wdev) > 1) {
		pm.PmMode.EnterPsm = 1;
		pm.PmMode.FastPsm = 0;
	}

	if (!wait_for_completion_timeout(&wvif->set_pm_mode_complete, msecs_to_jiffies(300)))
		dev_warn(wvif->wdev->dev, "timeout while waiting of set_pm_mode_complete\n");
	ret = wsm_set_pm(wvif->wdev, &pm, wvif->Id);
	// FIXME: why ?
	if (-ETIMEDOUT == wvif->scan.status)
		wvif->scan.status = 1;
	return ret;
}

int wfx_set_rts_threshold(struct ieee80211_hw *hw, u32 value)
{
	struct wfx_dev *wdev = hw->priv;
	struct wfx_vif *wvif = NULL;

	while ((wvif = wvif_iterate(wdev, wvif)) != NULL)
		wsm_rts_threshold(wdev, value, wvif->Id);
	return 0;
}

/* If successful, LOCKS the TX queue! */
static int __wfx_flush(struct wfx_dev *wdev, bool drop)
{
	int i, ret;

	for (;;) {
		if (drop) {
			for (i = 0; i < 4; ++i)
				wfx_queue_clear(wdev, &wdev->tx_queue[i]);
		} else {
			ret = wait_event_timeout(
				wdev->tx_queue_stats.wait_link_id_empty,
				wfx_queue_stats_is_empty(wdev),
				2 * HZ);
		}

		if (!drop && ret <= 0) {
			ret = -ETIMEDOUT;
			break;
		} else {
			ret = 0;
		}

		wsm_tx_lock_flush(wdev);
		if (!wfx_queue_stats_is_empty(wdev)) {
			/* Highly unlikely: WSM requeued frames. */
			wsm_tx_unlock(wdev);
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
	struct wfx_vif *wvif;

	if (vif) {
		wvif = (struct wfx_vif *) vif->drv_priv;
		if (wvif->mode == NL80211_IFTYPE_MONITOR)
			drop = true;
		if (wvif->mode == NL80211_IFTYPE_AP && !wvif->enable_beacon)
			drop = true;
	}

	// FIXME: only flush requested vif
	if (!__wfx_flush(wdev, drop))
		wsm_tx_unlock(wdev);
}

/* ******************************************************************** */
/* WSM callbacks							*/

void wfx_event_handler_work(struct work_struct *work)
{
	struct wfx_vif *wvif =
		container_of(work, struct wfx_vif, event_handler_work);
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
			if (!down_trylock(&wvif->scan.lock)) {
				wfx_cqm_bssloss_sm(wvif, 1, 0, 0);
				up(&wvif->scan.lock);
			} else {
				/* Scan is in progress. Delay reporting.
				 * Scan complete will trigger bss_loss_work
				 */
				wvif->delayed_link_loss = 1;
				/* Also start a watchdog. */
				schedule_delayed_work(&wvif->bss_loss_work, 5 * HZ);
			}
			break;
		case WSM_EVENT_IND_BSSREGAINED:
			pr_debug("[CQM] BSS regained.\n");
			wfx_cqm_bssloss_sm(wvif, 0, 0, 0);
			cancel_work_sync(&wvif->unjoin_work);
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
#if (KERNEL_VERSION(4, 11, 0) > LINUX_VERSION_CODE)
			ieee80211_cqm_rssi_notify(wvif->vif, cqm_evt,
						  GFP_KERNEL);
#else
			ieee80211_cqm_rssi_notify(wvif->vif, cqm_evt, rcpi_rssi,
						  GFP_KERNEL);
#endif
			break;
		}
		case WSM_EVENT_IND_PS_MODE_ERROR:
			dev_warn(wvif->wdev->dev, "error while processing power save request\n");
			break;
		default:
			dev_warn(wvif->wdev->dev, "Unhandled event indication: %.2x\n", event->evt.EventId);
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

void wfx_set_beacon_wakeup_period_work(struct work_struct *work)
{
	struct wfx_vif *wvif =
		container_of(work, struct wfx_vif, set_beacon_wakeup_period_work);
	unsigned period = wvif->dtim_period;

	wsm_set_beacon_wakeup_period(wvif->wdev, period, period, wvif->Id);
}

static void wfx_do_unjoin(struct wfx_vif *wvif)
{
	mutex_lock(&wvif->wdev->conf_mutex);

	if (atomic_read(&wvif->scan.in_progress)) {
		if (wvif->delayed_unjoin)
			dev_dbg(wvif->wdev->dev,
				  "Delayed unjoin is already scheduled.\n");
		else
			wvif->delayed_unjoin = true;
		goto done;
	}

	wvif->delayed_link_loss = false;

	if (!wvif->state)
		goto done;

	if (wvif->state == WFX_STATE_AP)
		goto done;

	cancel_work_sync(&wvif->update_filtering_work);
	cancel_work_sync(&wvif->set_beacon_wakeup_period_work);
	wvif->state = WFX_STATE_PASSIVE;

	/* Unjoin is a reset. */
	wsm_tx_flush(wvif->wdev);
	wsm_keep_alive_period(wvif->wdev, 0, wvif->Id);
	wsm_reset(wvif->wdev, false, wvif->Id);
	wsm_set_output_power(wvif->wdev, wvif->wdev->output_power * 10, wvif->Id);
	wvif->dtim_period = 0;
	wsm_set_macaddr(wvif->wdev, wvif->vif->addr, wvif->Id);
	wfx_free_event_queue(wvif);
	cancel_work_sync(&wvif->event_handler_work);
	wfx_cqm_bssloss_sm(wvif, 0, 0, 0);

	/* Disable Block ACKs */
	wsm_set_block_ack_policy(wvif->wdev, 0, 0, wvif->Id);

	wvif->disable_beacon_filter = false;
	wfx_update_filtering(wvif);
	memset(&wvif->bss_params, 0, sizeof(wvif->bss_params));
	wvif->setbssparams_done = false;
	memset(&wvif->ht_info, 0, sizeof(wvif->ht_info));

	pr_debug("[STA] Unjoin completed.\n");

done:
	mutex_unlock(&wvif->wdev->conf_mutex);
}

static void wfx_set_mfp(struct wfx_vif *wvif, struct cfg80211_bss *bss)
{
	const int pairwise_cipher_suite_count_offset = 8 / sizeof(uint16_t);
	const int pairwise_cipher_suite_size = 4 / sizeof(uint16_t);
	const int akm_suite_size = 4 / sizeof(uint16_t);
	const uint16_t *ptr = NULL;
	bool mfpc = false;
	bool mfpr = false;

	/* 802.11w protected mgmt frames */

	/* retrieve MFPC and MFPR flags from beacon or PBRSP */

	rcu_read_lock();
	if (bss)
		ptr = (const uint16_t *) ieee80211_bss_get_ie(bss, WLAN_EID_RSN);

	if (ptr) {
		ptr += pairwise_cipher_suite_count_offset;
		ptr += 1 + pairwise_cipher_suite_size * *ptr;
		ptr += 1 + akm_suite_size * *ptr;
		mfpc = *ptr & BIT(6);
		mfpr = *ptr & BIT(7);
	}
	rcu_read_unlock();

	wsm_set_mfp(wvif->wdev, mfpc, mfpr, wvif->Id);
}

/* MUST be called with tx_lock held!  It will be unlocked for us. */
static void wfx_do_join(struct wfx_vif *wvif)
{
	const u8 *bssid;
	struct ieee80211_bss_conf *conf = &wvif->vif->bss_conf;
	struct cfg80211_bss *bss = NULL;
	WsmHiJoinReqBody_t join = {
		.Mode		= conf->ibss_joined ? WSM_MODE_IBSS : WSM_MODE_BSS,
		.PreambleType	= WSM_PREAMBLE_LONG,
		.ProbeForJoin	= 1,
		.AtimWindow	= 0,
		.BasicRateSet	= wfx_rate_mask_to_wsm(wvif->wdev, conf->basic_rates),
	};

	if (wvif->channel->flags & IEEE80211_CHAN_NO_IR)
		join.ProbeForJoin = 0;

	if (wvif->state)
		wfx_do_unjoin(wvif);

	bssid = wvif->vif->bss_conf.bssid;

#if (KERNEL_VERSION(4, 1, 0) > LINUX_VERSION_CODE)
	bss = cfg80211_get_bss(wvif->wdev->hw->wiphy, wvif->channel, bssid, NULL, 0,
			       0, 0);
#else
	bss = cfg80211_get_bss(wvif->wdev->hw->wiphy, wvif->channel, bssid, NULL, 0,
			       IEEE80211_BSS_TYPE_ANY, IEEE80211_PRIVACY_ANY);
#endif

	if (!bss && !conf->ibss_joined) {
		wsm_tx_unlock(wvif->wdev);
		return;
	}

	mutex_lock(&wvif->wdev->conf_mutex);

	/* Under the conf lock: check scan status and
	 * bail out if it is in progress.
	 */
	if (atomic_read(&wvif->scan.in_progress)) {
		wsm_tx_unlock(wvif->wdev);
		goto done_put;
	}

	/* Sanity check basic rates */
	if (!join.BasicRateSet)
		join.BasicRateSet = 7;

	/* Sanity check beacon interval */
	if (!wvif->beacon_int)
		wvif->beacon_int = 1;

	join.BeaconInterval = wvif->beacon_int;

	// DTIM period will be set on first Beacon
	wvif->dtim_period = 0;

	join.ChannelNumber = wvif->channel->hw_value;
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

	wsm_tx_flush(wvif->wdev);

	if (wvif_count(wvif->wdev) <= 1)
		wsm_set_block_ack_policy(wvif->wdev, 0xFF, 0xFF, wvif->Id);

	wfx_set_mfp(wvif, bss);

	/* Perform actual join */
	wvif->wdev->tx_burst_idx = -1;
	if (wsm_join(wvif->wdev, &join, wvif->Id)) {
		ieee80211_connection_loss(wvif->vif);
		wvif->join_complete_status = -1;
		/* Tx lock still held, unjoin will clear it. */
		if (!schedule_work(&wvif->unjoin_work))
			wsm_tx_unlock(wvif->wdev);
	} else {
		wvif->join_complete_status = 0;
		if (wvif->mode == NL80211_IFTYPE_ADHOC)
			wvif->state = WFX_STATE_IBSS;
		else
			wvif->state = WFX_STATE_PRE_STA;
		wsm_tx_unlock(wvif->wdev);

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

void wfx_unjoin_work(struct work_struct *work)
{
	struct wfx_vif *wvif =
		container_of(work, struct wfx_vif, unjoin_work);

	wfx_do_unjoin(wvif);

	wsm_tx_unlock(wvif->wdev);
}

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
	if (!sta_priv->link_id) {
		dev_info(wdev->dev,
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

	if (wvif->mode != NL80211_IFTYPE_AP || !sta_priv->link_id)
		return 0;

	entry = &wvif->link_id_db[sta_priv->link_id - 1];
	spin_lock_bh(&wvif->ps_state_lock);
	entry->status = WFX_LINK_RESERVE;
	entry->timestamp = jiffies;
	wsm_tx_lock(wdev);
	if (!schedule_work(&wvif->link_id_work))
		wsm_tx_unlock(wdev);
	spin_unlock_bh(&wvif->ps_state_lock);
	flush_work(&wvif->link_id_work);
	return 0;
}

static void __wfx_sta_notify(struct wfx_vif *wvif,
				enum sta_notify_cmd notify_cmd,
				int link_id)
{
	u32 bit, prev;

	/* Zero link id means "for all link IDs" */
	if (link_id) {
		bit = BIT(link_id);
	} else if (notify_cmd != STA_NOTIFY_AWAKE) {
		dev_warn(wvif->wdev->dev, "wfx_sta_notify: unsupported notify command");
		bit = 0;
	} else {
		bit = wvif->link_id_map;
	}
	prev = wvif->sta_asleep_mask & bit;

	switch (notify_cmd) {
	case STA_NOTIFY_SLEEP:
		if (!prev) {
			if (wvif->buffered_multicasts && !wvif->sta_asleep_mask)
				schedule_work(&wvif->multicast_start_work);
			wvif->sta_asleep_mask |= bit;
		}
		break;
	case STA_NOTIFY_AWAKE:
		if (prev) {
			wvif->sta_asleep_mask &= ~bit;
			wvif->pspoll_mask &= ~bit;
			if (link_id && !wvif->sta_asleep_mask)
				schedule_work(&wvif->multicast_stop_work);
			wfx_bh_request_tx(wvif->wdev);
		}
		break;
	}
}

void wfx_sta_notify(struct ieee80211_hw *hw,
		       struct ieee80211_vif *vif,
		       enum sta_notify_cmd notify_cmd,
		       struct ieee80211_sta *sta)
{
	struct wfx_vif *wvif = (struct wfx_vif *) vif->drv_priv;
	struct wfx_sta_priv *sta_priv =
		(struct wfx_sta_priv *)&sta->drv_priv;

	spin_lock_bh(&wvif->ps_state_lock);
	__wfx_sta_notify(wvif, notify_cmd, sta_priv->link_id);
	spin_unlock_bh(&wvif->ps_state_lock);
}

// FIXME: wfx_ps_notify should change each station status independently
static void wfx_ps_notify(struct wfx_vif *wvif, bool ps)
{
	dev_info(wvif->wdev->dev, "%s: %s STAs asleep: %.8X\n", __func__,
		 ps ? "Start" : "Stop",
		 wvif->sta_asleep_mask);

	__wfx_sta_notify(wvif, ps ? STA_NOTIFY_AWAKE : STA_NOTIFY_SLEEP, 0);
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
			wsm_tx_unlock(wvif->wdev);
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

int wfx_set_tim(struct ieee80211_hw *hw, struct ieee80211_sta *sta,
			   bool set)
{
	struct wfx_dev *wdev = hw->priv;
	struct wfx_sta_priv *sta_dev = (struct wfx_sta_priv *) &sta->drv_priv;
	struct wfx_vif *wvif = wdev_to_wvif(wdev, sta_dev->vif_id);

	schedule_work(&wvif->set_tim_work);
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

	wsm_erp_use_protection(wvif->wdev, erp_ie[2] & WLAN_ERP_USE_PROTECTION, wvif->Id);

	if (wvif->mode != NL80211_IFTYPE_STATION)
		wsm_update_ie(wvif->wdev, &target_frame, erp_ie, sizeof(erp_ie), wvif->Id);
}

static int wfx_start_ap(struct wfx_vif *wvif)
{
	int ret;
	struct ieee80211_bss_conf *conf = &wvif->vif->bss_conf;
	WsmHiStartReqBody_t start = {
		.ChannelNumber		= wvif->channel->hw_value,
		.BeaconInterval		= conf->beacon_int,
		.DTIMPeriod		= conf->dtim_period,
		.PreambleType		= conf->use_short_preamble ? WSM_PREAMBLE_SHORT : WSM_PREAMBLE_LONG,
		.BasicRateSet		= wfx_rate_mask_to_wsm(wvif->wdev, conf->basic_rates),
	};


	memset(start.Ssid, 0, sizeof(start.Ssid));
	if (!conf->hidden_ssid) {
		start.SsidLength = conf->ssid_len;
		memcpy(start.Ssid, conf->ssid, start.SsidLength);
	}

	wvif->beacon_int = conf->beacon_int;
	wvif->dtim_period = conf->dtim_period;

	memset(&wvif->link_id_db, 0, sizeof(wvif->link_id_db));

	wvif->wdev->tx_burst_idx = -1;
	ret = wsm_start(wvif->wdev, &start, wvif->Id);
	if (!ret)
		ret = wfx_upload_keys(wvif);
	if (!ret) {
		if (wvif_count(wvif->wdev) <= 1)
			wsm_set_block_ack_policy(wvif->wdev, 0xFF, 0xFF, wvif->Id);
		wvif->state = WFX_STATE_AP;
		wfx_update_filtering(wvif);
	}
	return ret;
}

static int wfx_update_beaconing(struct wfx_vif *wvif)
{
	struct ieee80211_bss_conf *conf = &wvif->vif->bss_conf;

	if (wvif->mode == NL80211_IFTYPE_AP) {
		if (wvif->state != WFX_STATE_AP ||
		    wvif->beacon_int != conf->beacon_int) {
			pr_debug("ap restarting\n");
			wsm_tx_lock_flush(wvif->wdev);
			if (wvif->state != WFX_STATE_PASSIVE)
				wsm_reset(wvif->wdev, false, wvif->Id);
			wvif->state = WFX_STATE_PASSIVE;
			wfx_start_ap(wvif);
			wsm_tx_unlock(wvif->wdev);
		} else {
			pr_debug("ap started state: %d\n",
				 wvif->state);
		}
	}
	return 0;
}

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
	p->InitRate = API_RATE_INDEX_B_1MBPS; /* 1Mbps DSSS */
	if (wvif->vif->p2p)
		p->InitRate = API_RATE_INDEX_G_6MBPS;
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
		ret = wsm_fwd_probe_req(wvif, true);
	} else {
		ret = wsm_set_template_frame(wvif->wdev, p, wvif->Id);
		wsm_fwd_probe_req(wvif, false);
	}

done:
	if (!skb)
		dev_kfree_skb(skb);
	return ret;
}

void wfx_bss_info_changed(struct ieee80211_hw *hw,
			     struct ieee80211_vif *vif,
			     struct ieee80211_bss_conf *info,
			     u32 changed)
{
	struct wfx_dev *wdev = hw->priv;
	struct wfx_vif *wvif = (struct wfx_vif *) vif->drv_priv;
	bool do_join = false;
	int i;
	int nb_arp_addr;

	mutex_lock(&wdev->conf_mutex);


	if (changed & BSS_CHANGED_ARP_FILTER) {
		WsmHiMibArpIpAddrTable_t filter = { };
		nb_arp_addr = info->arp_addr_cnt;

		if (nb_arp_addr <= 0 || nb_arp_addr > WSM_MAX_ARP_IP_ADDRTABLE_ENTRIES)
			nb_arp_addr = 0;

		for (i = 0; i < WSM_MAX_ARP_IP_ADDRTABLE_ENTRIES; i++) {
			filter.ConditionIdx = i;
			if (i < nb_arp_addr) {
				/* Caution: type of arp_addr_list[i] is __be32 */
				memcpy(filter.Ipv4Address, &info->arp_addr_list[i], sizeof(filter.Ipv4Address));
				filter.ArpEnable = WSM_ARP_NS_FILTERING_ENABLE;
			} else {
				filter.ArpEnable = WSM_ARP_NS_FILTERING_DISABLE;
			}
			wsm_set_arp_ipv4_filter(wdev, &filter, wvif->Id);
		}
	}

	if (changed &
	    (BSS_CHANGED_BEACON | BSS_CHANGED_AP_PROBE_RESP |
	     BSS_CHANGED_BSSID | BSS_CHANGED_SSID | BSS_CHANGED_IBSS)) {
		wvif->beacon_int = info->beacon_int;
		wfx_update_beaconing(wvif);
		wfx_upload_beacon(wvif);
	}

	if (changed & BSS_CHANGED_BEACON_ENABLED && wvif->state != WFX_STATE_IBSS) {
		if (wvif->enable_beacon != info->enable_beacon) {
			wsm_beacon_transmit(wvif->wdev, info->enable_beacon, wvif->Id);
			wvif->enable_beacon = info->enable_beacon;
		}
	}

	/* assoc/disassoc, or maybe AID changed */
	if (changed & BSS_CHANGED_ASSOC) {
		wsm_tx_lock_flush(wdev);
		wvif->wep_default_key_id = -1;
		wsm_tx_unlock(wdev);
	}

	if (changed & BSS_CHANGED_ASSOC && !info->assoc &&
	    (wvif->state == WFX_STATE_STA || wvif->state == WFX_STATE_IBSS)) {
		/* Shedule unjoin work */
		pr_debug("[WSM] Issue unjoin command\n");
		wsm_tx_lock(wdev);
		if (!schedule_work(&wvif->unjoin_work))
			wsm_tx_unlock(wdev);
	} else {
		if (changed & BSS_CHANGED_BEACON_INT) {
			if (info->ibss_joined)
				do_join = true;
			else if (wvif->state == WFX_STATE_AP)
				wfx_update_beaconing(wvif);
		}

		if (changed & BSS_CHANGED_BSSID)
			do_join = true;

		if (changed &
		    (BSS_CHANGED_ASSOC | BSS_CHANGED_BSSID |
		     BSS_CHANGED_IBSS | BSS_CHANGED_BASIC_RATES | BSS_CHANGED_HT)) {
			if (info->assoc) {
				if (wvif->state <
				    WFX_STATE_PRE_STA) {
					ieee80211_connection_loss(vif);
					mutex_unlock(&wdev->conf_mutex);
					return;
				} else if (wvif->state ==
				    WFX_STATE_PRE_STA) {
					wvif->state = WFX_STATE_STA;
				}
			} else {
				do_join = true;
			}

			if (info->assoc || info->ibss_joined) {
				struct ieee80211_sta *sta = NULL;
				 WsmHiMibSetAssociationMode_t association_mode = { };

				if (info->dtim_period)
					wvif->dtim_period =
						info->dtim_period;
				wvif->beacon_int = info->beacon_int;

				rcu_read_lock();

				if (info->bssid && !info->ibss_joined)
					sta = ieee80211_find_sta(vif,
								 info->bssid);
				if (sta) {
					wvif->ht_info.ht_cap = sta->ht_cap;
					wvif->bss_params.OperationalRateSet =
						wfx_rate_mask_to_wsm(wdev, sta->supp_rates[wvif->channel->band]);
					wvif->ht_info.operation_mode =
						info->ht_operation_mode;
				} else {
					memset(&wvif->ht_info, 0,
					       sizeof(wvif->ht_info));
					wvif->bss_params.OperationalRateSet =
						-1;
				}
				rcu_read_unlock();

				/* Non Greenfield stations present */
				if (wvif->ht_info.operation_mode & IEEE80211_HT_OP_MODE_NON_GF_STA_PRSNT)
					wsm_dual_cts_protection(wdev, true, wvif->Id);
				else
					wsm_dual_cts_protection(wdev, false, wvif->Id);

				association_mode.MixedOrGreenfieldType =
					wfx_ht_greenfield(&wvif->ht_info);
				association_mode.PreambtypeUse = 1;
				association_mode.Mode = 1;
				association_mode.Rateset = 1;
				association_mode.Spacing = 1;
				association_mode.PreambleType =
				info->use_short_preamble ?
					WSM_PREAMBLE_SHORT :
					WSM_PREAMBLE_LONG;
				association_mode.BasicRateSet =
					cpu_to_le32(wfx_rate_mask_to_wsm(wdev,
							info->basic_rates));
				association_mode.MpduStartSpacing =
					wfx_ht_ampdu_density(&wvif->ht_info);

				wfx_cqm_bssloss_sm(wvif, 0, 0, 0);
				cancel_work_sync(&wvif->unjoin_work);

				wvif->bss_params.BeaconLostCount = 20;
				wvif->bss_params.AID = info->aid;

				if (wvif->dtim_period < 1)
					wvif->dtim_period = 1;

				pr_debug("[STA] DTIM %d, interval: %d\n",
					 wvif->dtim_period,
					 wvif->beacon_int);
				wsm_set_association_mode(wdev,
							 &association_mode, wvif->Id);

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
			} else {
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
			schedule_work(&wvif->set_cts_work);
	}

	/* ERP Slottime */
	if (changed & (BSS_CHANGED_ASSOC | BSS_CHANGED_ERP_SLOT)) {
		u32 slot_time = info->use_short_slot ? 9 : 20;

		wsm_slot_time(wdev, slot_time, wvif->Id);
	}

	if (changed & (BSS_CHANGED_ASSOC | BSS_CHANGED_CQM)) {
		WsmHiMibRcpiRssiThreshold_t threshold = {
			.RollingAverageCount	= 8,
		};

		pr_debug("[CQM] RSSI threshold subscribe: %d +- %d\n",
			 info->cqm_rssi_thold, info->cqm_rssi_hyst);
		wvif->cqm_rssi_thold = info->cqm_rssi_thold;

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
				threshold.RcpiRssi = 1;
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
				threshold.RcpiRssi = 1;
		}
		wsm_set_rcpi_rssi_threshold(wdev, &threshold, wvif->Id);
	}

	if (changed & BSS_CHANGED_TXPOWER && info->txpower != wdev->output_power) {
		wdev->output_power = info->txpower;
		wsm_set_output_power(wvif->wdev, wdev->output_power * 10, wvif->Id);
	}
	mutex_unlock(&wdev->conf_mutex);

	if (do_join) {
		wsm_tx_lock_flush(wdev);
		wfx_do_join(wvif); /* Will unlock it for us */
	}
}

void wfx_multicast_start_work(struct work_struct *work)
{
	struct wfx_vif *wvif =
		container_of(work, struct wfx_vif, multicast_start_work);
	long tmo = wvif->dtim_period * TU_TO_JIFFIES(wvif->beacon_int + 20);

	cancel_work_sync(&wvif->multicast_stop_work);

	if (!wvif->aid0_bit_set) {
		wsm_tx_lock_flush(wvif->wdev);
		wfx_set_tim_impl(wvif, true);
		wvif->aid0_bit_set = true;
		mod_timer(&wvif->mcast_timeout, jiffies + tmo);
		wsm_tx_unlock(wvif->wdev);
	}
}

void wfx_multicast_stop_work(struct work_struct *work)
{
	struct wfx_vif *wvif =
		container_of(work, struct wfx_vif, multicast_stop_work);

	if (wvif->aid0_bit_set) {
		del_timer_sync(&wvif->mcast_timeout);
		wsm_tx_lock_flush(wvif->wdev);
		wvif->aid0_bit_set = false;
		wfx_set_tim_impl(wvif, false);
		wsm_tx_unlock(wvif->wdev);
	}
}

#if (KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE)
void wfx_mcast_timeout(unsigned long arg)
{
	struct wfx_vif *wvif = (struct wfx_vif *)arg;
#else
void wfx_mcast_timeout(struct timer_list *t)
{
	struct wfx_vif *wvif = from_timer(wvif, t, mcast_timeout);
#endif
	dev_warn(wvif->wdev->dev,
		   "Multicast delivery timeout.\n");
	spin_lock_bh(&wvif->ps_state_lock);
	wvif->tx_multicast = wvif->aid0_bit_set &&
			     wvif->buffered_multicasts;
	if (wvif->tx_multicast)
		wfx_bh_request_tx(wvif->wdev);
	spin_unlock_bh(&wvif->ps_state_lock);
}

#if (KERNEL_VERSION(4, 4, 0) > LINUX_VERSION_CODE)
int wfx_ampdu_action(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
		     enum ieee80211_ampdu_mlme_action action,
		     struct ieee80211_sta *sta, u16 tid,
		     u16 *ssn, u8 buf_size)
#else
#if (KERNEL_VERSION(4, 4, 69) > LINUX_VERSION_CODE)
int wfx_ampdu_action(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
		     enum ieee80211_ampdu_mlme_action action,
		     struct ieee80211_sta *sta, u16 tid, u16 *ssn,
		     u8 buf_size, bool amsdu)
#else
int wfx_ampdu_action(struct ieee80211_hw *hw,
		     struct ieee80211_vif *vif,
		     struct ieee80211_ampdu_params *params)
#endif
#endif
{
	/* Aggregation is implemented fully in firmware,
	 * including block ack negotiation. Do not allow
	 * mac80211 stack to do anything: it interferes with
	 * the firmware.
	 */

	/* Note that we still need this function stubbed. */

	return -ENOTSUPP;
}

void wfx_suspend_resume(struct wfx_vif *wvif,
			WsmHiSuspendResumeTxIndBody_t *arg)
{
	pr_debug("[AP] %s: %s\n",
		 arg->SuspendResumeFlags.Resume ? "start" : "stop",
		 arg->SuspendResumeFlags.BcMcOnly ? "broadcast" : "unicast");

	if (arg->SuspendResumeFlags.BcMcOnly) {
		bool cancel_tmo = false;

		spin_lock_bh(&wvif->ps_state_lock);
		if (!arg->SuspendResumeFlags.Resume) {
			wvif->tx_multicast = false;
		} else {
			wvif->tx_multicast = (wvif->aid0_bit_set &&
					      wvif->buffered_multicasts);
			if (wvif->tx_multicast) {
				cancel_tmo = true;
				wfx_bh_request_tx(wvif->wdev);
			}
		}
		spin_unlock_bh(&wvif->ps_state_lock);
		if (cancel_tmo)
			del_timer_sync(&wvif->mcast_timeout);
	} else {
		spin_lock_bh(&wvif->ps_state_lock);
		wfx_ps_notify(wvif,
			      arg->SuspendResumeFlags.Resume);
		spin_unlock_bh(&wvif->ps_state_lock);
		if (arg->SuspendResumeFlags.Resume)
			wfx_bh_request_tx(wvif->wdev);
	}
}

