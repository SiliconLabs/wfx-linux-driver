// SPDX-License-Identifier: GPL-2.0-only
/*
 * Implementation of host-to-chip commands (aka request/confirmation) of WFxxx
 * Split Mac (WSM) API.
 *
 * Copyright (c) 2017-2019, Silicon Laboratories, Inc.
 * Copyright (c) 2010, ST-Ericsson
 */
#include <linux/skbuff.h>
#include <linux/etherdevice.h>

#include "wsm_tx.h"
#include "wfx.h"
#include "bh.h"
#include "debug.h"
#include "sta.h"

void init_wsm_cmd(struct wsm_cmd *wsm_cmd)
{
	init_completion(&wsm_cmd->ready);
	init_completion(&wsm_cmd->done);
	mutex_init(&wsm_cmd->lock);
	mutex_init(&wsm_cmd->key_renew_lock);
}

static void wfx_fill_header(struct hif_msg *hdr, int if_id, unsigned int cmd, size_t size)
{
	if (if_id == -1)
		if_id = 2;

	WARN(cmd > 0x3f, "Invalid WSM command %#.2x", cmd);
	WARN(size > 0xFFF, "Requested buffer is too large: %zu bytes", size);
	WARN(if_id > 0x3, "Invalid interface ID %d", if_id);

	hdr->len = cpu_to_le16(size + 4);
	hdr->id = cmd;
	hdr->interface = if_id;
}

static void *wfx_alloc_wsm(size_t body_len, struct hif_msg **hdr)
{
	*hdr = kzalloc(sizeof(struct hif_msg) + body_len, GFP_KERNEL);
	if (*hdr)
		return (*hdr)->body;
	else
		return NULL;
}

int wfx_cmd_send(struct wfx_dev *wdev, struct hif_msg *request, void *reply, size_t reply_len, bool async)
{
	const char *mib_name = "";
	const char *mib_sep = "";
	int cmd = request->id;
	int vif = request->interface;
	int ret;

	WARN(wdev->wsm_cmd.buf_recv && wdev->wsm_cmd.async, "API usage error");

	// Do not wait for any reply if chip is frozen
	if (wdev->chip_frozen)
		return -ETIMEDOUT;

	if (cmd != HI_SL_EXCHANGE_PUB_KEYS_REQ_ID)
		mutex_lock(&wdev->wsm_cmd.key_renew_lock);

	mutex_lock(&wdev->wsm_cmd.lock);
	WARN(wdev->wsm_cmd.buf_send, "data locking error");

	// Note: call to complete() below has an implicit memory barrier that
	// hopefully protect buf_send
	wdev->wsm_cmd.buf_send = request;
	wdev->wsm_cmd.buf_recv = reply;
	wdev->wsm_cmd.len_recv = reply_len;
	wdev->wsm_cmd.async = async;
	complete(&wdev->wsm_cmd.ready);

	wfx_bh_request_tx(wdev);

	// NOTE: no timeout is catched async is enabled
	if (async)
		return 0;

	ret = wait_for_completion_timeout(&wdev->wsm_cmd.done, 1 * HZ);
	if (!ret) {
		dev_err(wdev->dev, "chip is abnormally long to answer");
		reinit_completion(&wdev->wsm_cmd.ready);
		ret = wait_for_completion_timeout(&wdev->wsm_cmd.done, 3 * HZ);
	}
	if (!ret) {
		dev_err(wdev->dev, "chip did not answer");
		dev_info(wdev->dev, "list of stuck frames:\n");
		wfx_pending_dump_old_frames(wdev, 3000);
		wdev->chip_frozen = 1;
		reinit_completion(&wdev->wsm_cmd.done);
		ret = -ETIMEDOUT;
	} else {
		ret = wdev->wsm_cmd.ret;
	}

	wdev->wsm_cmd.buf_send = NULL;
	mutex_unlock(&wdev->wsm_cmd.lock);

	if (ret && (cmd == WSM_HI_READ_MIB_REQ_ID || cmd == WSM_HI_WRITE_MIB_REQ_ID)) {
		mib_name = get_mib_name(((u16 *) request)[2]);
		mib_sep = "/";
	}
	if (ret < 0)
		dev_err(wdev->dev,
			"WSM request %s%s%s (%#.2x) on vif %d returned error %d\n",
			get_wsm_name(cmd), mib_sep, mib_name, cmd, vif, ret);
	if (ret > 0)
		dev_warn(wdev->dev,
			 "WSM request %s%s%s (%#.2x) on vif %d returned status %d\n",
			 get_wsm_name(cmd), mib_sep, mib_name, cmd, vif, ret);

	if (cmd != HI_SL_EXCHANGE_PUB_KEYS_REQ_ID)
		mutex_unlock(&wdev->wsm_cmd.key_renew_lock);
	return ret;
}

// This function is special. After HI_SHUT_DOWN_REQ_ID, chip won't reply to any
// request anymore. We need to slightly hack struct wsm_cmd for that job. Be
// carefull to only call this funcion during device unregister.
int wsm_shutdown(struct wfx_dev *wdev)
{
	int ret;
	struct hif_msg *hdr;

	wfx_alloc_wsm(0, &hdr);
	wfx_fill_header(hdr, -1, HI_SHUT_DOWN_REQ_ID, 0);
	ret = wfx_cmd_send(wdev, hdr, NULL, 0, true);
	// After this command, chip won't reply. Be sure to give enough time to
	// bh to send buffer:
	msleep(100);
	wdev->wsm_cmd.buf_send = NULL;
	if (wdev->pdata.gpio_wakeup)
		gpiod_set_value(wdev->pdata.gpio_wakeup, 0);
	mutex_unlock(&wdev->wsm_cmd.lock);
	kfree(hdr);
	return ret;
}

int wsm_configuration(struct wfx_dev *wdev, const u8 *conf, size_t len)
{
	int ret;
	size_t buf_len = sizeof(struct hif_req_configuration) + len;
	struct hif_msg *hdr;
	struct hif_req_configuration *body = wfx_alloc_wsm(buf_len, &hdr);

	body->length = cpu_to_le16(len);
	memcpy(body->pds_data, conf, len);
	wfx_fill_header(hdr, -1, HI_CONFIGURATION_REQ_ID, buf_len);
	ret = wfx_cmd_send(wdev, hdr, NULL, 0, false);
	kfree(hdr);
	return ret;
}

int wsm_reset(struct wfx_vif *wvif, bool reset_stat)
{
	int ret;
	struct hif_msg *hdr;
	struct hif_req_reset *body = wfx_alloc_wsm(sizeof(*body), &hdr);

	body->reset_flags.reset_stat = reset_stat;
	wfx_fill_header(hdr, wvif->id, WSM_HI_RESET_REQ_ID, sizeof(*body));
	ret = wfx_cmd_send(wvif->wdev, hdr, NULL, 0, false);
	kfree(hdr);
	return ret;
}

int wsm_read_mib(struct wfx_dev *wdev, int vif_id, u16 mib_id, void *val, size_t val_len)
{
	int ret;
	struct hif_msg *hdr;
	int buf_len = sizeof(struct hif_cnf_read_mib) + val_len;
	struct hif_req_read_mib *body = wfx_alloc_wsm(sizeof(*body), &hdr);
	struct hif_cnf_read_mib *reply = kmalloc(buf_len, GFP_KERNEL);

	body->mib_id = cpu_to_le16(mib_id);
	wfx_fill_header(hdr, vif_id, WSM_HI_READ_MIB_REQ_ID, sizeof(*body));
	ret = wfx_cmd_send(wdev, hdr, reply, buf_len, false);

	if (!ret && mib_id != reply->mib_id) {
		dev_warn(wdev->dev, "%s: confirmation mismatch request\n", __func__);
		ret = -EIO;
	}
	if (ret == -ENOMEM)
		dev_err(wdev->dev, "Buffer is too small to receive %s (%zu < %d)\n",
			get_mib_name(mib_id), val_len, reply->length);
	if (!ret)
		memcpy(val, &reply->mib_data, reply->length);
	else
		memset(val, 0xFF, val_len);
	kfree(hdr);
	kfree(reply);
	return ret;
}

int wsm_write_mib(struct wfx_dev *wdev, int vif_id, u16 mib_id, void *val, size_t val_len)
{
	int ret;
	struct hif_msg *hdr;
	int buf_len = sizeof(struct hif_req_write_mib) + val_len;
	struct hif_req_write_mib *body = wfx_alloc_wsm(buf_len, &hdr);

	body->mib_id = cpu_to_le16(mib_id);
	body->length = cpu_to_le16(val_len);
	memcpy(&body->mib_data, val, val_len);
	wfx_fill_header(hdr, vif_id, WSM_HI_WRITE_MIB_REQ_ID, buf_len);
	ret = wfx_cmd_send(wdev, hdr, NULL, 0, false);
	kfree(hdr);
	return ret;
}

int wsm_scan(struct wfx_vif *wvif, const struct wsm_scan *arg)
{
	int ret, i;
	struct hif_msg *hdr;
	struct hif_ssid_def *ssids;
	size_t buf_len = sizeof(struct hif_req_start_scan) +
		arg->scan_req.num_of_channels * sizeof(u8) +
		arg->scan_req.num_of_ssi_ds * sizeof(struct hif_ssid_def);
	struct hif_req_start_scan *body = wfx_alloc_wsm(buf_len, &hdr);
	u8 *ptr = (u8 *) body + sizeof(*body);

	WARN(arg->scan_req.num_of_channels > WSM_API_MAX_NB_CHANNELS, "Invalid params");
	WARN(arg->scan_req.num_of_ssi_ds > 2, "Invalid params");
	WARN(arg->scan_req.band > 1, "Invalid params");

	// FIXME: This API is unnecessary complex, fixing NumOfChannels and
	// adding a member SsidDef at end of struct hif_req_start_scan would
	// simplify that a lot.
	memcpy(body, &arg->scan_req, sizeof(*body));
	cpu_to_le32s(&body->min_channel_time);
	cpu_to_le32s(&body->max_channel_time);
	cpu_to_le32s(&body->tx_power_level);
	memcpy(ptr, arg->ssids, arg->scan_req.num_of_ssi_ds * sizeof(struct hif_ssid_def));
	ssids = (struct hif_ssid_def *) ptr;
	for (i = 0; i < body->num_of_ssi_ds; ++i)
		cpu_to_le32s(&ssids[i].ssid_length);
	ptr += arg->scan_req.num_of_ssi_ds * sizeof(struct hif_ssid_def);
	memcpy(ptr, arg->ch, arg->scan_req.num_of_channels * sizeof(u8));
	ptr += arg->scan_req.num_of_channels * sizeof(u8);
	WARN(buf_len != ptr - (u8 *) body, "Allocation size mismatch");
	wfx_fill_header(hdr, wvif->id, WSM_HI_START_SCAN_REQ_ID, buf_len);
	ret = wfx_cmd_send(wvif->wdev, hdr, NULL, 0, false);
	kfree(hdr);
	return ret;
}

int wsm_stop_scan(struct wfx_vif *wvif)
{
	int ret;
	struct hif_msg *hdr;
	// body associated to WSM_HI_STOP_SCAN_REQ_ID is empty
	wfx_alloc_wsm(0, &hdr);

	wfx_fill_header(hdr, wvif->id, WSM_HI_STOP_SCAN_REQ_ID, 0);
	ret = wfx_cmd_send(wvif->wdev, hdr, NULL, 0, false);
	kfree(hdr);
	return ret;
}

int wsm_join(struct wfx_vif *wvif, const struct hif_req_join *arg)
{
	int ret;
	struct hif_msg *hdr;
	struct hif_req_join *body = wfx_alloc_wsm(sizeof(*body), &hdr);

	memcpy(body, arg, sizeof(struct hif_req_join));
	cpu_to_le16s(&body->channel_number);
	cpu_to_le16s(&body->atim_window);
	cpu_to_le32s(&body->ssid_length);
	cpu_to_le32s(&body->beacon_interval);
	cpu_to_le32s(&body->basic_rate_set);
	wfx_fill_header(hdr, wvif->id, WSM_HI_JOIN_REQ_ID, sizeof(*body));
	ret = wfx_cmd_send(wvif->wdev, hdr, NULL, 0, false);
	kfree(hdr);
	return ret;
}

int wsm_set_bss_params(struct wfx_vif *wvif, const struct hif_req_set_bss_params *arg)
{
	int ret;
	struct hif_msg *hdr;
	struct hif_req_set_bss_params *body = wfx_alloc_wsm(sizeof(*body), &hdr);

	memcpy(body, arg, sizeof(*body));
	cpu_to_le16s(&body->aid);
	cpu_to_le32s(&body->operational_rate_set);
	wfx_fill_header(hdr, wvif->id, WSM_HI_SET_BSS_PARAMS_REQ_ID, sizeof(*body));
	ret = wfx_cmd_send(wvif->wdev, hdr, NULL, 0, false);
	kfree(hdr);
	return ret;
}

int wsm_add_key(struct wfx_dev *wdev, const struct hif_req_add_key *arg)
{
	int ret;
	struct hif_msg *hdr;
	// FIXME: only send necessary bits
	struct hif_req_add_key *body = wfx_alloc_wsm(sizeof(*body), &hdr);

	// FIXME: swap bytes as necessary in body
	memcpy(body, arg, sizeof(*body));
	if (wfx_api_older_than(wdev, 1, 5))
		// Legacy firmwares expect that add_key to be sent on right
		// interface.
		wfx_fill_header(hdr, arg->int_id, WSM_HI_ADD_KEY_REQ_ID, sizeof(*body));
	else
		wfx_fill_header(hdr, -1, WSM_HI_ADD_KEY_REQ_ID, sizeof(*body));
	ret = wfx_cmd_send(wdev, hdr, NULL, 0, false);
	kfree(hdr);
	return ret;
}

int wsm_remove_key(struct wfx_dev *wdev, int idx)
{
	int ret;
	struct hif_msg *hdr;
	struct hif_req_remove_key *body = wfx_alloc_wsm(sizeof(*body), &hdr);

	body->entry_index = idx;
	wfx_fill_header(hdr, -1, WSM_HI_REMOVE_KEY_REQ_ID, sizeof(*body));
	ret = wfx_cmd_send(wdev, hdr, NULL, 0, false);
	kfree(hdr);
	return ret;
}

int wsm_set_edca_queue_params(struct wfx_vif *wvif, const struct hif_req_edca_queue_params *arg)
{
	int ret;
	struct hif_msg *hdr;
	struct hif_req_edca_queue_params *body = wfx_alloc_wsm(sizeof(*body), &hdr);

	// NOTE: queues numerotation are not the same between WFx and Linux
	memcpy(body, arg, sizeof(*body));
	cpu_to_le16s(&body->cw_min);
	cpu_to_le16s(&body->cw_max);
	cpu_to_le16s(&body->tx_op_limit);
	wfx_fill_header(hdr, wvif->id, WSM_HI_EDCA_QUEUE_PARAMS_REQ_ID, sizeof(*body));
	ret = wfx_cmd_send(wvif->wdev, hdr, NULL, 0, false);
	kfree(hdr);
	return ret;
}

int wsm_set_pm(struct wfx_vif *wvif, const struct hif_req_set_pm_mode *arg)
{
	int ret;
	struct hif_msg *hdr;
	struct hif_req_set_pm_mode *body = wfx_alloc_wsm(sizeof(*body), &hdr);

	memcpy(body, arg, sizeof(*body));
	wfx_fill_header(hdr, wvif->id, WSM_HI_SET_PM_MODE_REQ_ID, sizeof(*body));
	ret = wfx_cmd_send(wvif->wdev, hdr, NULL, 0, false);
	kfree(hdr);
	return ret;
}

int wsm_start(struct wfx_vif *wvif, const struct hif_req_start *arg)
{
	int ret;
	struct hif_msg *hdr;
	struct hif_req_start *body = wfx_alloc_wsm(sizeof(*body), &hdr);

	memcpy(body, arg, sizeof(*body));
	cpu_to_le16s(&body->channel_number);
	cpu_to_le32s(&body->beacon_interval);
	cpu_to_le32s(&body->basic_rate_set);
	wfx_fill_header(hdr, wvif->id, WSM_HI_START_REQ_ID, sizeof(*body));
	ret = wfx_cmd_send(wvif->wdev, hdr, NULL, 0, false);
	kfree(hdr);
	return ret;
}

int wsm_beacon_transmit(struct wfx_vif *wvif, bool enable_beaconing)
{
	int ret;
	struct hif_msg *hdr;
	struct hif_req_beacon_transmit *body = wfx_alloc_wsm(sizeof(*body), &hdr);

	body->enable_beaconing = enable_beaconing ? 1 : 0;
	wfx_fill_header(hdr, wvif->id, WSM_HI_BEACON_TRANSMIT_REQ_ID, sizeof(*body));
	ret = wfx_cmd_send(wvif->wdev, hdr, NULL, 0, false);
	kfree(hdr);
	return ret;
}

int wsm_map_link(struct wfx_vif *wvif, u8 *mac_addr, int flags, int sta_id)
{
	int ret;
	struct hif_msg *hdr;
	struct hif_req_map_link *body = wfx_alloc_wsm(sizeof(*body), &hdr);

	if (mac_addr)
		ether_addr_copy(body->mac_addr, mac_addr);
	body->map_link_flags = *(struct hif_map_link_flags *) &flags;
	body->peer_sta_id = sta_id;
	wfx_fill_header(hdr, wvif->id, WSM_HI_MAP_LINK_REQ_ID, sizeof(*body));
	ret = wfx_cmd_send(wvif->wdev, hdr, NULL, 0, false);
	kfree(hdr);
	return ret;
}

int wsm_update_ie(struct wfx_vif *wvif, const struct hif_ie_flags *target_frame,
		  const u8 *ies, size_t ies_len)
{
	int ret;
	struct hif_msg *hdr;
	int buf_len = sizeof(struct hif_req_update_ie) + ies_len;
	struct hif_req_update_ie *body = wfx_alloc_wsm(buf_len, &hdr);

	memcpy(&body->ie_flags, target_frame, sizeof(struct hif_ie_flags));
	body->num_i_es = cpu_to_le16(1);
	memcpy(body->ie, ies, ies_len);
	wfx_fill_header(hdr, wvif->id, WSM_HI_UPDATE_IE_REQ_ID, buf_len);
	ret = wfx_cmd_send(wvif->wdev, hdr, NULL, 0, false);
	kfree(hdr);
	return ret;
}

int wsm_sl_send_pub_keys(struct wfx_dev *wdev, const uint8_t *pubkey, const uint8_t *pubkey_hmac)
{
	int ret;
	struct hif_msg *hdr;
	struct hif_req_sl_exchange_pub_keys *body = wfx_alloc_wsm(sizeof(*body), &hdr);

	body->algorithm = HI_SL_CURVE25519;
	memcpy(body->host_pub_key, pubkey, sizeof(body->host_pub_key));
	memcpy(body->host_pub_key_mac, pubkey_hmac, sizeof(body->host_pub_key_mac));
	wfx_fill_header(hdr, -1, HI_SL_EXCHANGE_PUB_KEYS_REQ_ID, sizeof(*body));
	ret = wfx_cmd_send(wdev, hdr, NULL, 0, false);
	kfree(hdr);
	// Compatibility with legacy secure link
	if (ret == SL_PUB_KEY_EXCHANGE_STATUS_SUCCESS)
		ret = 0;
	return ret;
}

int wsm_sl_config(struct wfx_dev *wdev, const unsigned long *bitmap)
{
	int ret;
	struct hif_msg *hdr;
	struct hif_req_sl_configure *body = wfx_alloc_wsm(sizeof(*body), &hdr);

	memcpy(body->encr_bmp, bitmap, sizeof(body->encr_bmp));
	wfx_fill_header(hdr, -1, HI_SL_CONFIGURE_REQ_ID, sizeof(*body));
	ret = wfx_cmd_send(wdev, hdr, NULL, 0, false);
	kfree(hdr);
	return ret;
}

int wsm_sl_set_mac_key(struct wfx_dev *wdev, const uint8_t *slk_key, int destination)
{
	int ret;
	struct hif_msg *hdr;
	struct hif_req_set_sl_mac_key *body = wfx_alloc_wsm(sizeof(*body), &hdr);

	memcpy(body->key_value, slk_key, sizeof(body->key_value));
	body->otp_or_ram = destination;
	wfx_fill_header(hdr, -1, HI_SET_SL_MAC_KEY_REQ_ID, sizeof(*body));
	ret = wfx_cmd_send(wdev, hdr, NULL, 0, false);
	kfree(hdr);
	// Compatibility with legacy secure link
	if (ret == SL_MAC_KEY_STATUS_SUCCESS)
		ret = 0;
	return ret;
}

