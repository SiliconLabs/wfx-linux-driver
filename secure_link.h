// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2019, Silicon Laboratories, Inc.
 */
#ifndef SECURE_LINK_H
#define SECURE_LINK_H

#include "general_api.h"

struct wfx_dev;

struct sl_tag {
	uint8_t tag[16];
};

struct sl_wmsg {
	uint32_t    seqnum:30;
	uint32_t    encrypted:2;
	uint16_t    len;
	uint8_t     payload[];
} __packed;

#ifdef CONFIG_WFX_SECURE_LINK

#include <linux/bitmap.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ccm.h>

struct sl_context {
	unsigned int         rx_seqnum;
	unsigned int         tx_seqnum;
	struct completion    key_renew_done;
	struct work_struct   key_renew_work;
	DECLARE_BITMAP(commands, 256);
	mbedtls_ecdh_context edch_ctxt; // Only valid druing key negociation
	mbedtls_ccm_context  ccm_ctxt;
};

int wfx_is_secure_command(struct wfx_dev *wdev, int cmd_id);
int wfx_sl_decode(struct wfx_dev *wdev, struct sl_wmsg *m);
int wfx_sl_encode(struct wfx_dev *wdev, struct wmsg *input, struct sl_wmsg *output);
int wfx_sl_check_pubkey(struct wfx_dev *wdev, uint8_t *ncp_pubkey, uint8_t *ncp_pubmac);
int wfx_sl_init(struct wfx_dev *wdev);
void wfx_sl_deinit(struct wfx_dev *wdev);

#else /* CONFIG_WFX_SECURE_LINK */

struct sl_context {
};

static inline bool wfx_is_secure_command(struct wfx_dev *wdev, int cmd_id)
{
	return false;
}

static inline int wfx_sl_decode(struct wfx_dev *wdev, struct sl_wmsg *m)
{
	return -EIO;
}

static inline int wfx_sl_encode(struct wfx_dev *wdev, struct wmsg *input, struct sl_wmsg *output)
{
	return -EIO;
}

static inline int wfx_sl_check_pubkey(struct wfx_dev *wdev, uint8_t *ncp_pubkey, uint8_t *ncp_pubmac)
{
	return -EIO;
}

static inline int wfx_sl_init(struct wfx_dev *wdev)
{
	return -EIO;
}

static inline void wfx_sl_deinit(struct wfx_dev *wdev)
{
	return;
}

#endif /* CONFIG_WFX_SECURE_LINK */

#endif /* SECURE_LINK_H */
