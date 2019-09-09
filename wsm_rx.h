/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Implementation of chip-to-host event (aka indications) of WFxxx Split Mac
 * (WSM) API.
 *
 * Copyright (c) 2017-2019, Silicon Laboratories, Inc.
 * Copyright (c) 2010, ST-Ericsson
 * Copyright (C) 2010, ST-Ericsson SA
 */
#ifndef WFX_WSM_RX_H
#define WFX_WSM_RX_H

#include "api_wsm_cmd.h"

struct wfx_dev;
struct wfx_vif;

int wfx_unmap_link(struct wfx_vif *wvif, int link_id);

void wsm_handle_rx(struct wfx_dev *wdev, struct sk_buff *skb);
struct hif_msg *wsm_get_tx(struct wfx_dev *wdev);

#endif /* WFX_WSM_RX_H */
