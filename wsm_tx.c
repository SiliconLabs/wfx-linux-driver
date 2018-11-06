/*
 * WSM host interface (HI) implementation for Silicon Labs WFX mac80211 drivers
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

#include <linux/skbuff.h>
#include <linux/etherdevice.h>

#include "wsm.h"
#include "wfx.h"
#include "bh.h"
#include "debug.h"
#include "sta.h"
#include "testmode.h"

static void wfx_fill_header(HiMsgHdr_t *hdr, int if_id, unsigned cmd, size_t size)
{
	if (if_id == -1)
		if_id = 0;

	WARN(cmd > 0x3f, "Invalid WSM command %02x", cmd);
	WARN(size > 0xFFF, "Requested buffer is too large: %zu bytes", size);
	WARN(if_id > 0x3, "Invalid interface ID %d", if_id);

	hdr->MsgLen = cpu_to_le16(size + 4);
	hdr->s.b.Id = cmd;
	hdr->s.b.IntId = if_id;
}

static void *wfx_alloc_wsm(size_t body_len, HiMsgHdr_t **hdr)
{
	*hdr = kzalloc(sizeof(HiMsgHdr_t) + body_len, GFP_KERNEL);
	if (*hdr)
		return *hdr + 1;
	else
		return NULL;
}

static int wfx_cmd_send(struct wfx_dev *wdev, HiMsgHdr_t *hdr, void *arg, long tmo);

int wsm_configuration(struct wfx_dev *wdev, const u8 *conf, size_t len)
{
	int ret;
	// sizeof(HiConfigurationReqBody_t) is wider than necessary
	size_t buf_len = sizeof(u16) + len;
	HiMsgHdr_t *hdr;
	HiConfigurationReqBody_t *body = wfx_alloc_wsm(buf_len, &hdr);

	body->Length = cpu_to_le16(len);
	memcpy(body->PdsData, conf, len);
	wfx_fill_header(hdr, -1, HI_CONFIGURATION_REQ_ID, buf_len);
	ret = wfx_cmd_send(wdev, hdr, NULL, WSM_CMD_TIMEOUT);
	kfree(hdr);
	return ret;
}

int wsm_reset(struct wfx_dev *wdev, bool reset_stat, int Id)
{
	int ret;
	HiMsgHdr_t *hdr;
	WsmHiResetReqBody_t *body = wfx_alloc_wsm(sizeof(*body), &hdr);

	// FIXME: API logic is inverted
	body->ResetFlags.ResetStat = reset_stat ? 0 : 1;
	wfx_fill_header(hdr, Id, WSM_HI_RESET_REQ_ID, sizeof(*body));
	ret = wfx_cmd_send(wdev, hdr, NULL, WSM_CMD_RESET_TIMEOUT);
	kfree(hdr);
	return ret;
}

int wsm_read_mib(struct wfx_dev *wdev, u16 id, void *val, size_t val_len)
{
	int ret;
	HiMsgHdr_t *hdr;
	WsmHiReadMibReqBody_t *body = wfx_alloc_wsm(sizeof(*body), &hdr);
	WsmHiReadMibCnfBody_t *reply = kmalloc(sizeof(*reply), GFP_KERNEL);

	body->MibId = cpu_to_le16(id);
	wfx_fill_header(hdr, -1, WSM_HI_READ_MIB_REQ_ID, sizeof(*body));
	ret = wfx_cmd_send(wdev, hdr, reply, WSM_CMD_TIMEOUT);

	reply->Length -= 4; // Drop header
	if (val_len < reply->Length) {
		dev_err(wdev->pdev, "Buffer is too small to receive %s (%zu < %d)\n",
			get_mib_name(id), val_len, reply->Length);
		ret = -ENOMEM;
	}
	if (id != reply->MibId) {
		dev_warn(wdev->pdev, "%s: confirmation mismatch request\n", __func__);
		ret = -EIO;
	}
	if (!ret)
		memcpy(val, &reply->MibData, reply->Length);
	else
		memset(val, 0xFF, val_len);
	kfree(hdr);
	kfree(reply);
	return ret;
}

int wsm_write_mib(struct wfx_dev *wdev, u16 id, void *val, size_t val_len, int Id)
{
	int ret;
	// sizeof(WsmHiWriteMibReqBody_t) is wider than necessary
	int buf_len = 2 * sizeof(u16) + val_len;
	HiMsgHdr_t *hdr;
	WsmHiWriteMibReqBody_t *body = wfx_alloc_wsm(buf_len, &hdr);

	body->MibId = cpu_to_le16(id);
	body->Length = cpu_to_le16(val_len);
	memcpy(&body->MibData, val, val_len);
	wfx_fill_header(hdr, Id, WSM_HI_WRITE_MIB_REQ_ID, buf_len);
	ret = wfx_cmd_send(wdev, hdr, NULL, WSM_CMD_TIMEOUT);
	kfree(hdr);
	return ret;
}

int wsm_scan(struct wfx_dev *wdev, const struct wsm_scan *arg, int Id)
{
	int ret, i;
	HiMsgHdr_t *hdr;
	WsmHiSsidDef_t *ssids;
	size_t buf_len = sizeof(WsmHiStartScanReqBody_t) +
		arg->scan_req.NumOfChannels * sizeof(u8) +
		arg->scan_req.NumOfSSIDs * sizeof(WsmHiSsidDef_t);
	WsmHiStartScanReqBody_t *body = wfx_alloc_wsm(buf_len, &hdr);
	u8 *ptr = (u8 *) body + sizeof(*body);

	WARN(arg->scan_req.NumOfChannels > WSM_API_CHANNEL_LIST_SIZE, "Invalid params");
	WARN(arg->scan_req.NumOfSSIDs > 2, "Invalid params");
	WARN(arg->scan_req.Band > 1, "Invalid params");

	// FIXME: This API is unecessary complex, fixing NumOfChannels and
	// adding a member SsidDef at end of WsmHiStartScanReqBody_t would
	// simplify that a lot.
	memcpy(body, &arg->scan_req, sizeof(*body));
	cpu_to_le32s(&body->MinChannelTime);
	cpu_to_le32s(&body->MaxChannelTime);
	cpu_to_le32s(&body->TxPowerLevel);
	memcpy(ptr, arg->ssids, arg->scan_req.NumOfSSIDs * sizeof(WsmHiSsidDef_t));
	ssids = (WsmHiSsidDef_t *) ptr;
	for (i = 0; i < body->NumOfSSIDs; ++i)
		cpu_to_le32s(&ssids[i].SSIDLength);
	ptr += arg->scan_req.NumOfSSIDs * sizeof(WsmHiSsidDef_t);
	memcpy(ptr, arg->ch, arg->scan_req.NumOfChannels * sizeof(u8));
	ptr += arg->scan_req.NumOfChannels * sizeof(u8);
	WARN(buf_len != ptr - (u8 *) body, "Allocation size mismatch");
	wfx_fill_header(hdr, Id, WSM_HI_START_SCAN_REQ_ID, buf_len);
	ret = wfx_cmd_send(wdev, hdr, NULL, WSM_CMD_TIMEOUT);
	kfree(hdr);
	return ret;
}

int wsm_stop_scan(struct wfx_dev *wdev, int Id)
{
	int ret;
	HiMsgHdr_t *hdr;
	// body associated to WSM_HI_STOP_SCAN_REQ_ID is empty
	wfx_alloc_wsm(0, &hdr);

	wfx_fill_header(hdr, Id, WSM_HI_STOP_SCAN_REQ_ID, 0);
	ret = wfx_cmd_send(wdev, hdr, NULL, WSM_CMD_TIMEOUT);
	kfree(hdr);
	return ret;
}

int wsm_join(struct wfx_dev *wdev, const WsmHiJoinReqBody_t *arg, int Id)
{
	int ret;
	HiMsgHdr_t *hdr;
	WsmHiJoinReqBody_t *body = wfx_alloc_wsm(sizeof(*body), &hdr);

	memcpy(body, arg, sizeof(WsmHiJoinReqBody_t));
	cpu_to_le16s(&body->ChannelNumber);
	cpu_to_le16s(&body->AtimWindow);
	cpu_to_le32s(&body->SSIDLength);
	cpu_to_le32s(&body->BeaconInterval);
	cpu_to_le32s(&body->BasicRateSet);
	wfx_fill_header(hdr, Id, WSM_HI_JOIN_REQ_ID, sizeof(*body));
	ret = wfx_cmd_send(wdev, hdr, NULL, WSM_CMD_JOIN_TIMEOUT);
	kfree(hdr);
	return ret;
}

int wsm_set_bss_params(struct wfx_dev *wdev, const WsmHiSetBssParamsReqBody_t *arg, int Id)
{
	int ret;
	HiMsgHdr_t *hdr;
	WsmHiSetBssParamsReqBody_t *body = wfx_alloc_wsm(sizeof(*body), &hdr);

	memcpy(body, arg, sizeof(*body));
	cpu_to_le16s(&body->AID);
	cpu_to_le32s(&body->OperationalRateSet);
	wfx_fill_header(hdr, Id, WSM_HI_SET_BSS_PARAMS_REQ_ID, sizeof(*body));
	ret = wfx_cmd_send(wdev, hdr, NULL, WSM_CMD_TIMEOUT);
	kfree(hdr);
	return ret;
}

int wsm_add_key(struct wfx_dev *wdev, const WsmHiAddKeyReqBody_t *arg, int Id)
{
	int ret;
	HiMsgHdr_t *hdr;
	// FIXME: only send necessary bits
	WsmHiAddKeyReqBody_t *body = wfx_alloc_wsm(sizeof(*body), &hdr);

	// FIXME: swap bytes as necessary in body
	memcpy(body, arg, sizeof(*body));
	wfx_fill_header(hdr, Id, WSM_HI_ADD_KEY_REQ_ID, sizeof(*body));
	ret = wfx_cmd_send(wdev, hdr, NULL, WSM_CMD_TIMEOUT);
	kfree(hdr);
	return ret;
}

int wsm_remove_key(struct wfx_dev *wdev, int idx, int Id)
{
	int ret;
	HiMsgHdr_t *hdr;
	WsmHiRemoveKeyReqBody_t *body = wfx_alloc_wsm(sizeof(*body), &hdr);

	body->EntryIndex = idx;
	wfx_fill_header(hdr, Id, WSM_HI_REMOVE_KEY_REQ_ID, sizeof(*body));
	ret = wfx_cmd_send(wdev, hdr, NULL, WSM_CMD_TIMEOUT);
	kfree(hdr);
	return ret;
}

int wsm_set_tx_queue_params(struct wfx_dev *wdev, int queue_id, int ack_policy,
			    int max_lifetime, int medium_time, int Id)
{
	int ret;
	HiMsgHdr_t *hdr;
	WsmHiTxQueueParamsReqBody_t *body = wfx_alloc_wsm(sizeof(*body), &hdr);

	body->QueueId = wsm_queue_id_to_wsm(queue_id);
	body->AckPolicy = ack_policy;
	body->MaxTransmitLifetime = cpu_to_le32(max_lifetime);
	body->AllowedMediumTime = cpu_to_le16(medium_time);
	wfx_fill_header(hdr, Id, WSM_HI_TX_QUEUE_PARAMS_REQ_ID, sizeof(*body));
	ret = wfx_cmd_send(wdev, hdr, NULL, WSM_CMD_TIMEOUT);
	kfree(hdr);
	return ret;
}

int wsm_set_edca_params(struct wfx_dev *wdev, const WsmHiEdcaParamsReqBody_t *arg, int Id)
{
	int ret, i, j;
	HiMsgHdr_t *hdr;
	WsmHiEdcaParamsReqBody_t *body = wfx_alloc_wsm(sizeof(*body), &hdr);

	// NOTE: queues numerotation is inverted between WFx and Linux
	for (i = 0; i < IEEE80211_NUM_ACS; i++) {
		j = IEEE80211_NUM_ACS - 1 - i;
		body->AIFSN[i] = arg->AIFSN[j];
		body->CwMin[i] = cpu_to_le16(arg->CwMin[j]);
		body->CwMax[i] = cpu_to_le16(arg->CwMax[j]);
		body->TxOpLimit[i] = cpu_to_le16(arg->TxOpLimit[j]);
		body->MaxReceiveLifetime[i] = cpu_to_le32(arg->MaxReceiveLifetime[j]);
	}
	wfx_fill_header(hdr, Id, WSM_HI_EDCA_PARAMS_REQ_ID, sizeof(*body));
	ret = wfx_cmd_send(wdev, hdr, NULL, WSM_CMD_TIMEOUT);
	kfree(hdr);
	return ret;
}

int wsm_set_pm(struct wfx_dev *wdev, const WsmHiSetPmModeReqBody_t *arg, int Id)
{
	int ret;
	HiMsgHdr_t *hdr;
	WsmHiSetPmModeReqBody_t *body = wfx_alloc_wsm(sizeof(*body), &hdr);

	memcpy(body, arg, sizeof(*body));
	wfx_fill_header(hdr, Id, WSM_HI_SET_PM_MODE_REQ_ID, sizeof(*body));
	ret = wfx_cmd_send(wdev, hdr, NULL, WSM_CMD_TIMEOUT);
	kfree(hdr);
	return ret;
}

int wsm_start(struct wfx_dev *wdev, const WsmHiStartReqBody_t *arg, int Id)
{
	int ret;
	HiMsgHdr_t *hdr;
	WsmHiStartReqBody_t *body = wfx_alloc_wsm(sizeof(*body), &hdr);

	memcpy(body, arg, sizeof(*body));
	cpu_to_le16s(&body->ChannelNumber);
	cpu_to_le32s(&body->CTWindow);
	cpu_to_le32s(&body->BeaconInterval);
	cpu_to_le32s(&body->BasicRateSet);
	wfx_fill_header(hdr, Id, WSM_HI_START_REQ_ID, sizeof(*body));
	ret = wfx_cmd_send(wdev, hdr, NULL, WSM_CMD_TIMEOUT);
	kfree(hdr);
	return ret;
}

int wsm_beacon_transmit(struct wfx_dev *wdev, bool enable_beaconing, int Id)
{
	int ret;
	HiMsgHdr_t *hdr;
	WsmHiBeaconTransmitReqBody_t *body = wfx_alloc_wsm(sizeof(*body), &hdr);

	body->EnableBeaconing = enable_beaconing ? 1 : 0;
	wfx_fill_header(hdr, Id, WSM_HI_BEACON_TRANSMIT_REQ_ID, sizeof(*body));
	ret = wfx_cmd_send(wdev, hdr, NULL, WSM_CMD_TIMEOUT);
	kfree(hdr);
	return ret;
}

int wsm_map_link(struct wfx_dev *wdev, u8 *mac_addr, int flags, int sta_id, int Id)
{
	int ret;
	HiMsgHdr_t *hdr;
	WsmHiMapLinkReqBody_t *body = wfx_alloc_wsm(sizeof(*body), &hdr);

	if (mac_addr)
		ether_addr_copy(body->MacAddr, mac_addr);
	body->Flags = flags;
	body->PeerStaId = sta_id;
	wfx_fill_header(hdr, Id, WSM_HI_MAP_LINK_REQ_ID, sizeof(*body));
	ret = wfx_cmd_send(wdev, hdr, NULL, WSM_CMD_TIMEOUT);
	kfree(hdr);
	return ret;
}

int wsm_update_ie(struct wfx_dev *wdev, const WsmHiIeFlags_t *target_frame,
		  const u8 *ies, size_t ies_len, int Id)
{
	int ret;
	HiMsgHdr_t *hdr;
	WsmHiUpdateIeReqBody_t *body = wfx_alloc_wsm(sizeof(*body) + ies_len, &hdr);
	u8 *ptr = (u8 *) body + sizeof(*body);

	memcpy(&body->IeFlags, target_frame, sizeof(WsmHiIeFlags_t));
	body->NumIEs = cpu_to_le16(1);
	memcpy(ptr, ies, ies_len);
	wfx_fill_header(hdr, Id, WSM_HI_UPDATE_IE_REQ_ID, sizeof(*body) + ies_len);
	ret = wfx_cmd_send(wdev, hdr, NULL, WSM_CMD_TIMEOUT);
	kfree(hdr);
	return ret;
}

static int wfx_cmd_send(struct wfx_dev *wdev, HiMsgHdr_t *hdr, void *arg, long tmo)
{
	size_t buf_len = le16_to_cpu(hdr->MsgLen);
	int cmd = hdr->s.b.Id;
	int ret;

	if (wdev->bh_error) {
		return 0;
	}

	mutex_lock(&wdev->wsm_cmd_mux);
	WARN(wdev->wsm_cmd.ptr, "Data locking error");

	spin_lock(&wdev->wsm_cmd.lock);
	wdev->wsm_cmd.done = 0;
	wdev->wsm_cmd.ptr = (u8 *) hdr;
	wdev->wsm_cmd.len = buf_len;
	wdev->wsm_cmd.arg = arg;
	wdev->wsm_cmd.cmd = cmd;
	spin_unlock(&wdev->wsm_cmd.lock);

	wfx_bh_wakeup(wdev);

	if (-ETIMEDOUT == wdev->scan.status) {
		(void)wait_event_timeout(wdev->wsm_cmd_wq,
					 wdev->wsm_cmd.done, HZ);
		spin_lock(&wdev->wsm_cmd.lock);
		wdev->wsm_cmd.done = 1;
		wdev->wsm_cmd.ptr = NULL;
		spin_unlock(&wdev->wsm_cmd.lock);
	}

	/* Wait for command completion */
	ret = wait_event_timeout(wdev->wsm_cmd_wq,
				 wdev->wsm_cmd.done, tmo);

	if (!ret && !wdev->wsm_cmd.done) {
		spin_lock(&wdev->wsm_cmd.lock);
		wdev->wsm_cmd.done = 1;
		wdev->wsm_cmd.ptr = NULL;
		spin_unlock(&wdev->wsm_cmd.lock);
		if (wdev->bh_error) {
			/* Return ok to help system cleanup */
			ret = 0;
		} else {
			wake_up(&wdev->bh_wq);
			ret = -ETIMEDOUT;
		}
	} else {
		spin_lock(&wdev->wsm_cmd.lock);
		BUG_ON(!wdev->wsm_cmd.done);
		ret = wdev->wsm_cmd.ret;
		spin_unlock(&wdev->wsm_cmd.lock);
	}

	// Should not be necessary but just in case
	spin_lock(&wdev->wsm_cmd.lock);
	wdev->wsm_cmd.arg = NULL;
	wdev->wsm_cmd.cmd = 0xFF;
	spin_unlock(&wdev->wsm_cmd.lock);
	mutex_unlock(&wdev->wsm_cmd_mux);

	if (ret < 0)
		dev_err(wdev->pdev, "WSM request %s (%#02x) returned error %d\n",
				get_wsm_name(cmd), cmd, ret);
	if (ret > 0)
		dev_warn(wdev->pdev, "WSM request %s (%#02x) returned status %d\n",
				get_wsm_name(cmd), cmd, ret);

	return ret;
}

