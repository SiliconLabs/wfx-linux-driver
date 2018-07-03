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

#ifndef STA_H_INCLUDED
#define STA_H_INCLUDED

int wfx_set_pm(struct wfx_common *priv, const WsmHiSetPmModeReqBody_t *arg);

/* ******************************************************************** */
/* WSM callbacks                            */

void wfx_join_complete_cb(struct wfx_common		*priv,
			  WsmHiJoinCompleteIndBody_t	*arg);

/* ******************************************************************** */
/* WSM events                                */

void wfx_free_event_queue(struct wfx_common *priv);
void wfx_event_handler(struct work_struct *work);
void wfx_bss_loss_work(struct work_struct *work);
void wfx_bss_params_work(struct work_struct *work);
void wfx_keep_alive_work(struct work_struct *work);
void wfx_tx_failure_work(struct work_struct *work);

void __wfx_cqm_bssloss_sm(struct wfx_common *priv, int init, int good, int bad);
static inline void wfx_cqm_bssloss_sm(struct wfx_common *priv,
				      int init, int good, int bad)
{
	spin_lock(&priv->bss_loss_lock);
	__wfx_cqm_bssloss_sm(priv, init, good, bad);
	spin_unlock(&priv->bss_loss_lock);
}

/* ******************************************************************** */
/* Internal API                                */

int wfx_setup_mac(struct wfx_common *priv);

int wfx_send_pds(struct wfx_common *priv);
void wfx_join_timeout(struct work_struct *work);
void wfx_unjoin_work(struct work_struct *work);
void wfx_join_complete_work(struct work_struct *work);
void wfx_wep_key_work(struct work_struct *work);
void wfx_update_listening(struct wfx_common *priv, bool enabled);
void wfx_update_filtering(struct wfx_common *priv);
void wfx_update_filtering_work(struct work_struct *work);
void wfx_set_beacon_wakeup_period_work(struct work_struct *work);
int wfx_enable_listening(struct wfx_common *priv);
int wfx_disable_listening(struct wfx_common *priv);
int wfx_set_uapsd_param(struct wfx_common		*priv,
			const struct wsm_edca_params	*arg);
void wfx_ba_work(struct work_struct *work);
void wfx_ba_timer(unsigned long arg);

/* AP stuffs */
void wfx_suspend_resume(struct wfx_common *priv, int link_id,
			WsmHiSuspendResumeTxIndBody_t *arg);
void wfx_set_tim_work(struct work_struct *work);
void wfx_set_cts_work(struct work_struct *work);
void wfx_multicast_start_work(struct work_struct *work);
void wfx_multicast_stop_work(struct work_struct *work);
void wfx_mcast_timeout(unsigned long arg);

#ifndef CONFIG_NL80211_TESTMODE
#undef CONFIG_WF200_TESTMODE
#endif /* CONFIG_NL80211_TESTMODE */

#ifdef CONFIG_WF200_TESTMODE
#include "testmode/include/prv_testmode.h"
#endif /* CONFIG_WF200_TESTMODE */

#endif
