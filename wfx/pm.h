/*
 * Copyright (c) 2017, Silicon Laboratories, Inc.
 *
 * Based on:
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


#ifndef PM_H_INCLUDED
#define PM_H_INCLUDED

/*========================================================================*/
/*                  Structures definitions                                */
/*========================================================================*/
struct wfx_common;

struct wfx_suspend_state;

struct wfx_pm_state {
    struct wfx_suspend_state *suspend_state;
    struct timer_list stay_awake;
    struct platform_device *pm_dev;
    spinlock_t lock; /* Protect access */
};

/*========================================================================*/
/*                       Functions                                        */
/*========================================================================*/
#ifdef CONFIG_PM
int wfx_pm_init(struct wfx_pm_state *pm,
        struct wfx_common *priv);
void wfx_pm_deinit(struct wfx_pm_state *pm);
int wfx_wow_suspend(struct ieee80211_hw *hw,
        struct cfg80211_wowlan *wowlan);
int wfx_wow_resume(struct ieee80211_hw *hw);
int wfx_can_suspend(struct wfx_common *priv);
void wfx_pm_stay_awake(struct wfx_pm_state *pm,
        unsigned long tmo);
#else
static inline void wfx_pm_stay_awake(struct wfx_pm_state *pm,
        unsigned long tmo) {
}
#endif
#endif
