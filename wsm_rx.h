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

#ifndef WFX_WSM_RX_H
#define WFX_WSM_RX_H

#include "wsm_cmd_api.h"

struct wfx_dev;
struct wfx_vif;

int wfx_unmap_link(struct wfx_vif *wvif, int link_id);

int wsm_handle_rx(struct wfx_dev *wdev, HiMsgHdr_t *wsm, struct sk_buff **skb_p);
int wsm_get_tx(struct wfx_dev *wdev, u8 **data, size_t *tx_len, int *burst);

void wsm_lock_tx(struct wfx_dev *wdev);
void wsm_lock_tx_async(struct wfx_dev *wdev);
void wsm_unlock_tx(struct wfx_dev *wdev);

bool wsm_flush_tx(struct wfx_dev *wdev);

#endif /* WFX_WSM_RX_H */
