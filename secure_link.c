// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2019, Silicon Laboratories, Inc.
 */

#include <linux/random.h>
#include <crypto/sha.h>
#include <mbedtls/md.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>

#include "wfx.h"
#include "secure_link.h"

/*
 * Used by MBEDTLS_ENTROPY_HARDWARE_ALT
 */
int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen)
{
	get_random_bytes(output, len);
	*olen = len;

	return 0;
}

static int mbedtls_get_random_bytes(void *data, unsigned char *output, size_t len)
{
	get_random_bytes(output, len);

	return 0;
}

static void reverse_bytes(uint8_t *src, uint8_t length)
{
	uint8_t *lo = src;
	uint8_t *hi = src + length - 1;
	uint8_t swap;

	while (lo < hi) {
		swap = *lo;
		*lo++ = *hi;
		*hi-- = swap;
	}
}

static int wfx_sl_key_exchange(struct wfx_dev *wdev)
{
	int ret;
	size_t olen;
	uint8_t host_pubmac[SHA512_DIGEST_SIZE];
	uint8_t host_pubkey[API_HOST_PUB_KEY_SIZE + 2];

	ret = mbedtls_ecdh_setup(&wdev->edch_ctxt, MBEDTLS_ECP_DP_CURVE25519);
	if (ret)
		return -EIO;
	wdev->edch_ctxt.point_format = MBEDTLS_ECP_PF_COMPRESSED;
	ret = mbedtls_ecdh_make_public(&wdev->edch_ctxt, &olen, host_pubkey,
			sizeof(host_pubkey), mbedtls_get_random_bytes, NULL);
	if (ret || olen != sizeof(host_pubkey))
		return -EIO;
	reverse_bytes(host_pubkey + 2, sizeof(host_pubkey) - 2);
	ret = mbedtls_md_hmac(
			mbedtls_md_info_from_type(MBEDTLS_MD_SHA512),
			wdev->pdata.sl_key, sizeof(wdev->pdata.sl_key),
			host_pubkey + 2, sizeof(host_pubkey) - 2,
			host_pubmac);
	if (ret)
		return -EIO;
	ret = wsm_send_pub_keys(wdev, host_pubkey + 2, host_pubmac);
	if (ret)
		return -EIO;
	if (!wait_for_completion_timeout(&wdev->sl_key_renew_done, msecs_to_jiffies(500)))
		return -EIO;
	if (!memzcmp(wdev->session_key, sizeof(wdev->session_key)))
		return -EIO;
	return 0;
}

int wfx_sl_init(struct wfx_dev *wdev)
{
	int link_mode = wdev->wsm_caps.Capabilities.LinkMode;

	init_completion(&wdev->sl_key_renew_done);
	if (!memzcmp(wdev->pdata.sl_key, sizeof(wdev->pdata.sl_key)))
		goto err;
	if (link_mode == SECURE_LINK_TRUSTED_ACTIVE_ENFORCED) {
		dev_err(wdev->dev, "TRUSTED_ACTIVE_ENFORCED is not yet supported\n");
		goto err;
	} else if (link_mode == SECURE_LINK_TRUSTED_MODE) {
		if (wsm_set_mac_key(wdev, wdev->pdata.sl_key, SL_MAC_KEY_DEST_RAM))
			goto err;
		if (wfx_sl_key_exchange(wdev))
			goto err;
	} else {
		dev_info(wdev->dev, "ignoring provided secure link key since chip does not support it\n");
	}
	return 0;

err:
	if (link_mode == SECURE_LINK_TRUSTED_ACTIVE_ENFORCED) {
		dev_err(wdev->dev, "chip require secure_link, but can't negociate it\n");
		return -EIO;
	}
	return 0;
}

void wfx_sl_deinit(struct wfx_dev *wdev)
{
	mbedtls_ecdh_free(&wdev->edch_ctxt);
}

int wfx_sl_check_ncp_keys(struct wfx_dev *wdev, uint8_t *ncp_pubkey, uint8_t *ncp_pubmac)
{
	int ret;
	size_t olen;
	uint8_t shared_secret[API_HOST_PUB_KEY_SIZE];
	uint8_t shared_secret_digest[SHA256_DIGEST_SIZE];
	uint8_t ncp_pubmac_computed[SHA512_DIGEST_SIZE];

	ret = mbedtls_md_hmac(
			mbedtls_md_info_from_type(MBEDTLS_MD_SHA512),
			wdev->pdata.sl_key, sizeof(wdev->pdata.sl_key),
			ncp_pubkey, API_NCP_PUB_KEY_SIZE,
			ncp_pubmac_computed);
	if (ret)
		goto end;
	ret = memcmp(ncp_pubmac_computed, ncp_pubmac, sizeof(ncp_pubmac_computed));
	if (ret)
		goto end;

	// FIXME: save Y or (reset it), concat it with ncp_public_key and use mbedtls_ecdh_read_public.
	reverse_bytes(ncp_pubkey, API_NCP_PUB_KEY_SIZE);
	ret = mbedtls_mpi_read_binary(&wdev->edch_ctxt.Qp.X, ncp_pubkey, API_NCP_PUB_KEY_SIZE);
	if (ret)
		goto end;
	ret = mbedtls_mpi_lset(&wdev->edch_ctxt.Qp.Z, 1);
	if (ret)
		goto end;

	ret = mbedtls_ecdh_calc_secret(&wdev->edch_ctxt, &olen,
			shared_secret, sizeof(shared_secret),
			mbedtls_get_random_bytes, NULL);
	if (ret)
		goto end;

	reverse_bytes(shared_secret, sizeof(shared_secret));
	ret = mbedtls_sha256_ret(shared_secret, sizeof(shared_secret), shared_secret_digest, 0);
	if (ret)
		goto end;

	// Use the lower 16 bytes of the sha256
	memcpy(wdev->session_key, shared_secret_digest, sizeof(wdev->session_key));

end:
	if (ret)
		dev_err(wdev->dev, "cannot get session_key\n");
	return 0;
}


