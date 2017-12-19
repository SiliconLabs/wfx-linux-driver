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

#ifndef SCAN_H_INCLUDED
#define SCAN_H_INCLUDED

/*========================================================================*/
/*                 Standard Linux Headers             		              */
/*========================================================================*/
#include <linux/semaphore.h>

/*========================================================================*/
/*                 Local Header files             			              */
/*========================================================================*/
#include "wsm.h"

/*========================================================================*/
/*                  Structures definitions                                */
/*========================================================================*/
struct sk_buff;
struct cfg80211_scan_request;
struct ieee80211_channel;
struct ieee80211_hw;
struct work_struct;

struct wfx_scan {
	struct semaphore lock;
	struct work_struct work;
	struct delayed_work timeout;
	struct cfg80211_scan_request *req;
	struct ieee80211_channel **begin;
	struct ieee80211_channel **curr;
	struct ieee80211_channel **end;
	WsmHiSsidDef_t ssids[WSM_API_SSID_DEF_SIZE];
	int output_power;
	int n_ssids;
	int status;
	atomic_t in_progress;
	/* Direct probe requests workaround */
	struct delayed_work probe_work;
	int direct_probe;
};

/*========================================================================*/
/*                       Functions                                        */
/*========================================================================*/
int wfx_hw_scan(struct ieee80211_hw *hw,
		   struct ieee80211_vif *vif,
		   struct ieee80211_scan_request *hw_req);
void wfx_scan_work(struct work_struct *work);
void wfx_scan_timeout(struct work_struct *work);
void wfx_clear_recent_scan_work(struct work_struct *work);
void wfx_scan_complete_cb(struct wfx_common *priv,
		WsmHiScanCmplIndBody_t *arg);
void wfx_scan_failed_cb(struct wfx_common *priv);

void wfx_probe_work(struct work_struct *work);

#endif
