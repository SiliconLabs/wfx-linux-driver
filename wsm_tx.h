/*
 * WSM host interface (HI) interface for Silicon Labs WFX mac80211 drivers
 *
 * Copyright (c) 2017, Silicon Laboratories, Inc.
 * Copyright (c) 2010, ST-Ericsson
 * Copyright (C) 2010, ST-Ericsson SA
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

#ifndef WFX_WSM_TX_H
#define WFX_WSM_TX_H

#include "wsm_cmd_api.h"

struct wfx_dev;
struct wfx_vif;

struct wsm_scan {
	WsmHiStartScanReqBody_t scan_req;
	WsmHiSsidDef_t		*ssids;
	u8			*ch;
};

struct wsm_cmd {
	struct mutex      lock;
	struct completion ready;
	struct completion done;
	bool              async;
	HiMsgHdr_t        *buf_send;
	void              *buf_recv;
	size_t            len_recv;
	int               ret;
};

void init_wsm_cmd(struct wsm_cmd *wsm_cmd);
int wsm_configuration(struct wfx_dev *wdev, const u8 *conf, size_t len);
int wsm_reset(struct wfx_dev *wdev, bool reset_stat, int Id);
int wsm_read_mib(struct wfx_dev *wdev, u16 mib_id, void *buf, size_t buf_size);
int wsm_write_mib(struct wfx_dev *wdev, u16 mib_id, void *buf, size_t buf_size, int Id);
int wsm_scan(struct wfx_dev *wdev, const struct wsm_scan *arg, int Id);
int wsm_stop_scan(struct wfx_dev *wdev, int Id);
int wsm_join(struct wfx_dev *wdev, const WsmHiJoinReqBody_t *arg, int Id);
int wsm_set_pm(struct wfx_dev *wdev, const WsmHiSetPmModeReqBody_t *arg, int Id);
int wsm_set_bss_params(struct wfx_dev *wdev, const WsmHiSetBssParamsReqBody_t *arg, int Id);
int wsm_add_key(struct wfx_dev *wdev, const WsmHiAddKeyReqBody_t *arg, int Id);
int wsm_remove_key(struct wfx_dev *wdev, int idx, int Id);
int wsm_set_edca_queue_params(struct wfx_dev *wdev, const WsmHiEdcaQueueParamsReqBody_t *arg, int Id);
int wsm_start(struct wfx_dev *wdev, const WsmHiStartReqBody_t *arg, int Id);
int wsm_beacon_transmit(struct wfx_dev *wdev, bool enable, int Id);
int wsm_map_link(struct wfx_dev *wdev, u8 *mac_addr, int flags, int sta_id, int Id);
int wsm_update_ie(struct wfx_dev *wdev, const WsmHiIeFlags_t *target_frame, const u8 *ies, size_t ies_len, int Id);
int wsm_fwd_probe_req(struct wfx_vif *wvif, bool enable);

#endif /* WFX_WSM_TX_H */
