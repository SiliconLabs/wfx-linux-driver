/*
 * Scan interface for Silicon Labs WFX mac80211 drivers
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

#ifndef WFX_SCAN_H
#define WFX_SCAN_H

#include <linux/semaphore.h>
#include <linux/workqueue.h>
#include <net/mac80211.h>

#include "wsm_cmd_api.h"

struct wfx_dev;
struct wfx_vif;

struct wfx_scan {
	struct semaphore lock;
	struct work_struct work;
	struct delayed_work timeout;
	struct cfg80211_scan_request *req;
	struct ieee80211_channel **begin;
	struct ieee80211_channel **curr;
	struct ieee80211_channel **end;
	WsmHiSsidDef_t			ssids[WSM_API_SSID_DEF_SIZE];
	int output_power;
	int n_ssids;
	int status;
	atomic_t in_progress;
	/* Direct probe requests workaround */
	struct delayed_work probe_work;
	int direct_probe;
};

void wfx_scan_work(struct work_struct *work);
void wfx_scan_timeout(struct work_struct *work);
void wfx_scan_complete_cb(struct wfx_vif *wvif, WsmHiScanCmplIndBody_t *arg);
void wfx_scan_failed_cb(struct wfx_vif *wvif);
void wfx_probe_work(struct work_struct *work);

#endif /* WFX_SCAN_H */
