// SPDX-License-Identifier: GPL-2.0-only
/*
 * Device handling thread interface for mac80211 Silicon Labs WFX drivers
 *
 * Copyright (c) 2017-2019, Silicon Laboratories, Inc.
 * Copyright (c) 2010, ST-Ericsson
 */
#ifndef WFX_BH_H
#define WFX_BH_H

/* extern */ struct wfx_dev;

int wfx_register_bh(struct wfx_dev *wdev);
void wfx_unregister_bh(struct wfx_dev *wdev);
void wfx_irq_handler(struct wfx_dev *wdev);
void wfx_bh_wakeup(struct wfx_dev *wdev);
int wsm_release_tx_buffer(struct wfx_dev *wdev, int count);

#endif /* WFX_BH_H */
