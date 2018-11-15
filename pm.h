/*
 * Mac80211 power management interface for Silicon Labs WFX mac80211 drivers
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

#ifndef WFX_PM_H
#define WFX_PM_H

/* ******************************************************************** */
/* mac80211 API								*/

/* extern */  struct wfx_dev;
/* private */ struct wfx_suspend_state;

struct wfx_pm_state {
	struct wfx_suspend_state *suspend_state;
	struct timer_list stay_awake;
	struct platform_device *pm_dev;
	spinlock_t lock; /* Protect access */
};

#ifdef CONFIG_PM
// mac80211 interface
int wfx_wow_suspend(struct ieee80211_hw *hw, struct cfg80211_wowlan *wowlan);
int wfx_wow_resume(struct ieee80211_hw *hw);

int wfx_pm_init(struct wfx_pm_state *pm, struct wfx_dev *wdev);
void wfx_pm_deinit(struct wfx_pm_state *pm);
int wfx_can_suspend(struct wfx_dev *wdev);
void wfx_pm_stay_awake(struct wfx_pm_state *pm, unsigned long tmo);
#else
static inline void wfx_pm_stay_awake(struct wfx_pm_state *pm, unsigned long tmo) { }
#endif

#endif /* WFX_PM_H */
