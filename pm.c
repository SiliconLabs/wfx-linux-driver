/*
 * Mac80211 power management API for Silicon Labs WFX drivers
 *
 * Copyright (c) 2017, Silicon Laboratories, Inc.
 * Copyright (c) 2011, ST-Ericsson
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

#include <net/mac80211.h>

#include "pm.h"
#include "wfx_api.h"
#include "wfx.h"
#include "sta.h"
#include "bh.h"
#include "hwbus.h"

#define WF200_BEACON_SKIPPING_MULTIPLIER 3

#ifndef ETH_P_WAPI
#define ETH_P_WAPI     0x88B4
#endif

struct wfx_suspend_state {
	unsigned long	bss_loss_tmo;
	unsigned long	join_tmo;
	unsigned long	direct_probe;
	unsigned long	link_id_gc;
	bool		beacon_skipping;
	WsmHiPmMode_t	prev_ps_mode;
};

static WsmHiMibUdpPortDataFrameFilterSet_t wfx_udp_port_filter_on = {
	.NrFilters			= 2,
	.UdpPortsFilter			= {
		[0] = {
			.FilterMode	= WSM_FILTER_MODE_OUT,
			.IsSrcPort	= WSM_FILTER_PORT_TYPE_DST,
			.UDPPort	= cpu_to_le16(67), /* DHCP Bootps */
		},
		[1] = {
			.FilterMode	= WSM_FILTER_MODE_OUT,
			.IsSrcPort	= WSM_FILTER_PORT_TYPE_DST,
			.UDPPort	= cpu_to_le16(68), /* DHCP Bootpc */
		},
	}
};

static WsmHiMibUdpPortDataFrameFilterSet_t wfx_udp_port_filter_off = {
	.NrFilters	= 0,
};

static WsmHiMibEtherTypeDataFrameFilterSet_t wfx_ether_type_filter_on = {
	.NrFilters			= 4,
	.EtherTypeFilter		= {
		[0] = {
			.FilterMode	= WSM_FILTER_MODE_IN,
			.EtherType	= cpu_to_le16(ETH_P_IP),
		},
		[1] = {
			.FilterMode	= WSM_FILTER_MODE_IN,
			.EtherType	= cpu_to_le16(ETH_P_PAE),
		},
		[2] = {
			.FilterMode	= WSM_FILTER_MODE_IN,
			.EtherType	= cpu_to_le16(ETH_P_WAPI),
		},
		[3] = {
			.FilterMode	= WSM_FILTER_MODE_IN,
			.EtherType	= cpu_to_le16(ETH_P_ARP),
		},
	},
};

static WsmHiMibEtherTypeDataFrameFilterSet_t wfx_ether_type_filter_off = {
	.NrFilters	= 0,
};

#if (KERNEL_VERSION(4, 14, 0) <= LINUX_VERSION_CODE)
static void wfx_pm_stay_awake_tmo(struct timer_list *t)
#else
static void wfx_pm_stay_awake_tmo(unsigned long arg)
#endif
{
}

static long wfx_suspend_work(struct delayed_work *work)
{
	int ret = cancel_delayed_work(work);
	long tmo;

	if (ret > 0) {
		/* Timer is pending */
		tmo = work->timer.expires - jiffies;
		if (tmo < 0)
			tmo = 0;
	} else {
		tmo = -1;
	}
	return tmo;
}

static int wfx_resume_work(struct wfx_dev	*wdev,
			   struct delayed_work	*work,
			   unsigned long	tmo)
{
	if ((long)tmo < 0)
		return 1;

	return queue_delayed_work(wdev->workqueue, work, tmo);
}

void wfx_pm_deinit(struct wfx_pm_state *pm)
{
	del_timer_sync(&pm->stay_awake);
}

void wfx_pm_stay_awake(struct wfx_pm_state *pm,
			  unsigned long tmo)
{
	long cur_tmo;

	spin_lock_bh(&pm->lock);
	cur_tmo = pm->stay_awake.expires - jiffies;
	if (!timer_pending(&pm->stay_awake) || cur_tmo < (long)tmo)
		mod_timer(&pm->stay_awake, jiffies + tmo);
	spin_unlock_bh(&pm->lock);
}

int wfx_pm_init(struct wfx_pm_state	*pm,
		struct wfx_dev	*wdev)
{
	spin_lock_init(&pm->lock);

#if (KERNEL_VERSION(4, 14, 0) <= LINUX_VERSION_CODE)
	timer_setup(&pm->stay_awake, wfx_pm_stay_awake_tmo, 0);
#else
	setup_timer(&pm->stay_awake, wfx_pm_stay_awake_tmo, 0);
#endif

	return 0;
}

int wfx_can_suspend(struct wfx_dev *wdev)
{
	if (atomic_read(&wdev->bh_rx)) {
		wiphy_dbg(wdev->hw->wiphy, "Suspend interrupted.\n");
		return 0;
	}
	return 1;
}

/* Suspend WFx driver. mac80211 itself will suspend before and stop
 * transmitting and doing any other configuration and then ask WFx
 * to suspend
 */
int wfx_wow_suspend(struct ieee80211_hw *hw, struct cfg80211_wowlan *wowlan)
{
	struct wfx_dev *wdev = hw->priv;
	// FIXME: this function should work with multiple vif
	struct wfx_vif *wvif = wdev_to_wvif(wdev, 0);
	struct wfx_pm_state *pm_state = &wdev->pm_state;
	struct wfx_suspend_state *state;
	int ret;

	spin_lock_bh(&pm_state->lock);
	ret = timer_pending(&pm_state->stay_awake);
	spin_unlock_bh(&pm_state->lock);
	if (ret)
		return -EAGAIN;

	/* Do not suspend when datapath is not idle */
	if (wdev->tx_queue_stats.num_queued)
		return -EBUSY;

	/* Make sure there is no configuration requests in progress. */
	if (!mutex_trylock(&wdev->conf_mutex))
		return -EBUSY;

	if (wdev->channel_switch_in_progress)
		goto revert1;

	/* Do not suspend when join is pending */
	if (wvif->join_pending)
		goto revert1;

	/* Do not suspend when scanning */
	if (down_trylock(&wdev->scan.lock))
		goto revert1;

	/* Lock TX. */
	wsm_lock_tx_async(wdev);
	if (wait_event_timeout(wdev->bh_evt_wq,
			       !wdev->hw_bufs_used, HZ / 10) <= 0)
		goto revert2;

	/* Set UDP filter */
	wsm_set_udp_port_filter(wdev, &wfx_udp_port_filter_on, wvif->Id);

	/* Set ethernet frame type filter */
	wsm_set_ether_type_filter(wdev, &wfx_ether_type_filter_on, wvif->Id);

	/* Allocate state */
	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		goto revert3;

	/* Change to legacy PS while going to suspend */
	if (!wdev->vif->p2p &&
	    wvif->join_status == WFX_JOIN_STATUS_STA &&
	    (!wvif->powersave_mode.PmMode.PmMode ||
	     wvif->powersave_mode.PmMode.FastPsm)) {
		state->prev_ps_mode = wvif->powersave_mode.PmMode;
		wvif->powersave_mode.PmMode.PmMode = 1;
		wfx_set_pm(wvif, &wvif->powersave_mode);
		if (wait_event_interruptible_timeout(wdev->ps_mode_switch_done,
						     !wdev->ps_mode_switch_in_progress,
						     1 * HZ) <= 0)
			goto revert4;
		}

	/* Store delayed work states. */
	state->bss_loss_tmo =
		wfx_suspend_work(&wvif->bss_loss_work);
	state->join_tmo =
		wfx_suspend_work(&wvif->join_timeout);
	state->direct_probe =
		wfx_suspend_work(&wdev->scan.probe_work);
	state->link_id_gc =
		wfx_suspend_work(&wvif->link_id_gc_work);

	atomic_set(&wdev->wait_for_scan, 0);

	/* Enable beacon skipping */
	if (wvif->join_status == WFX_JOIN_STATUS_STA &&
	    wvif->join_dtim_period &&
	    !wvif->has_multicast_subscription) {
		state->beacon_skipping = true;
		wsm_set_beacon_wakeup_period(wdev,
					     wvif->join_dtim_period,
					     WF200_BEACON_SKIPPING_MULTIPLIER *
					     wvif->join_dtim_period, wvif->Id);
	}

	/* Stop serving thread */
	if (wfx_bh_suspend(wdev))
		goto revert5;

	ret = timer_pending(&wvif->mcast_timeout);
	if (ret)
		goto revert6;

	/* Store suspend state */
	pm_state->suspend_state = state;

	/* Enable IRQ wake */
	ret = wdev->hwbus_ops->power_mgmt(wdev->hwbus_priv, true);
	if (ret) {
		wiphy_err(wdev->hw->wiphy,
			  "PM request failed: %d. WoW is disabled.\n", ret);
		wfx_wow_resume(hw);
		return -EBUSY;
	}

	/* Force resume if event is coming from the device. */
	if (atomic_read(&wdev->bh_rx)) {
		wfx_wow_resume(hw);
		return -EAGAIN;
	}

	return 0;

revert6:
	WARN_ON(wfx_bh_resume(wdev));
revert5:
	wfx_resume_work(wdev, &wvif->bss_loss_work,
			   state->bss_loss_tmo);
	wfx_resume_work(wdev, &wvif->join_timeout,
			   state->join_tmo);
	wfx_resume_work(wdev, &wdev->scan.probe_work,
			   state->direct_probe);
	wfx_resume_work(wdev, &wvif->link_id_gc_work,
			   state->link_id_gc);
revert4:
	kfree(state);
revert3:
	wsm_set_udp_port_filter(wdev, &wfx_udp_port_filter_off, wvif->Id);
	wsm_set_ether_type_filter(wdev, &wfx_ether_type_filter_off, wvif->Id);
revert2:
	wsm_unlock_tx(wdev);
	up(&wdev->scan.lock);
revert1:
	mutex_unlock(&wdev->conf_mutex);
	return -EBUSY;
}

/* If WFx driver was configured, this indicates that mac80211 is now
 * resuming its operation, after this WFx must be fully functional again.
 *
 * If this returns an error, the only way out is to unregister WFx driver.
 * If this returns 1, mac80211 will resume.
 */
int wfx_wow_resume(struct ieee80211_hw *hw)
{
	struct wfx_dev *wdev = hw->priv;
	// FIXME: this function should work with multiple vif
	struct wfx_vif *wvif = wdev_to_wvif(wdev, 0);
	struct wfx_pm_state *pm_state = &wdev->pm_state;
	struct wfx_suspend_state *state;

	state = pm_state->suspend_state;
	pm_state->suspend_state = NULL;

	/* Disable IRQ wake */
	wdev->hwbus_ops->power_mgmt(wdev->hwbus_priv, false);
	up(&wdev->scan.lock);

	/* Resume BH thread */
	if (wfx_bh_resume(wdev))
		dev_dbg(wdev->pdev, "wfx_wow_resume: resume bottom half");

	/* Restores previous PS mode */
	if (!wdev->vif->p2p && wvif->join_status == WFX_JOIN_STATUS_STA) {
		wvif->powersave_mode.PmMode = state->prev_ps_mode;
		wfx_set_pm(wvif, &wvif->powersave_mode);
	}

	if (state->beacon_skipping) {
		unsigned period = wvif->beacon_int * wvif->join_dtim_period > MAX_BEACON_SKIP_TIME_MS ? 1 : wvif->join_dtim_period;

		wsm_set_beacon_wakeup_period(wdev, period, period, wvif->Id);
		state->beacon_skipping = false;
	}

	/* Resume delayed work */
	wfx_resume_work(wdev, &wvif->bss_loss_work,
			   state->bss_loss_tmo);
	wfx_resume_work(wdev, &wvif->join_timeout,
			   state->join_tmo);
	wfx_resume_work(wdev, &wdev->scan.probe_work,
			   state->direct_probe);
	wfx_resume_work(wdev, &wvif->link_id_gc_work,
			   state->link_id_gc);

	/* Remove UDP port filter */
	wsm_set_udp_port_filter(wdev, &wfx_udp_port_filter_off, wvif->Id);

	/* Remove ethernet frame type filter */
	wsm_set_ether_type_filter(wdev, &wfx_ether_type_filter_off, wvif->Id);

	/* Unlock datapath */
	wsm_unlock_tx(wdev);

	/* Unlock configuration mutex */
	mutex_unlock(&wdev->conf_mutex);

	/* Free memory */
	kfree(state);

	return 0;
}
