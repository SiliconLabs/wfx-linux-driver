// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2019, Silicon Laboratories, Inc.
 */
#ifndef SECURE_LINK_H
#define SECURE_LINK_H

#define SECURE_LINK_CCM_TAG_LENGTH              16
#define SECURE_LINK_NONCE_COUNTER_MAX           0x3FFFFFFFUL

struct sl_wmsg {
	uint32_t    seqnum:30;
	uint32_t    encrypted:2;
	uint16_t    len;
	uint8_t     payload[];
} __packed;

int wfx_sl_init(struct wfx_dev *wdev);
void wfx_sl_deinit(struct wfx_dev *wdev);
int wfx_sl_check_ncp_keys(struct wfx_dev *wdev, uint8_t *ncp_pubkey, uint8_t *ncp_pubmac);
int wfx_sl_decode(struct wfx_dev *wdev, struct sl_wmsg *m);
int wfx_sl_encode(struct wfx_dev *wdev, struct wmsg *input, struct sl_wmsg *output);
int wfx_is_secure_command(struct wfx_dev *wdev, int cmd_id);

#endif /* SECURE_LINK_H */
