// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2019, Silicon Laboratories, Inc.
 */
#ifndef SECURE_LINK_H
#define SECURE_LINK_H

int wfx_sl_init(struct wfx_dev *wdev);
void wfx_sl_deinit(struct wfx_dev *wdev);
int wfx_sl_check_ncp_keys(struct wfx_dev *wdev, uint8_t *ncp_pubkey, uint8_t *ncp_pubmac);

#endif /* SECURE_LINK_H */
