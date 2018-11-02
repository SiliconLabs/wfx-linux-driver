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

#define FWLOAD_BLOCK_SIZE         (1024)

#define wfx_cmd(wfx_arg, ptr, size) \
	do { \
		if ((wfx_arg)->data + size > (wfx_arg)->end) { \
			ret = wsm_buf_reserve((wfx_arg), size); \
			if (ret < 0) \
				goto nomem; \
		} \
		memcpy((wfx_arg)->data, ptr, size); \
		(wfx_arg)->data += size; \
	} while (0)

#define __wfx_cmd(wfx_arg, val, type, type2, cvt) \
	do { \
		if ((wfx_arg)->data + sizeof(type) > (wfx_arg)->end) { \
			ret = wsm_buf_reserve((wfx_arg), sizeof(type)); \
			if (ret < 0) \
				goto nomem; \
		} \
		*(type2 *)(wfx_arg)->data = cvt(val); \
		(wfx_arg)->data += sizeof(type); \
	} while (0)

#define wfx_cmd_fl(wfx_arg, val) __wfx_cmd(wfx_arg, val, u8, u8, (u8))
#define wfx_cmd_len(wfx_arg, val) __wfx_cmd(wfx_arg, val, u16, __le16, \
					cpu_to_le16)
#define wfx_cmd_data(wfx_arg, val) __wfx_cmd(wfx_arg, val, u32, __le32, \
					cpu_to_le32)

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
	wsm_cmd_lock(wdev);
	ret = wfx_cmd_send(wdev, hdr, NULL, WSM_CMD_TIMEOUT);
	wsm_cmd_unlock(wdev);
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
	wsm_cmd_lock(wdev);
	ret = wfx_cmd_send(wdev, hdr, NULL, WSM_CMD_RESET_TIMEOUT);
	wsm_cmd_unlock(wdev);
	kfree(hdr);
	return ret;
}

int wsm_read_mib(struct wfx_dev *wdev, u16 mib_id, void *_buf,
			size_t buf_size)
{
	int ret;
	struct wsm_buf *wfx_arg = &wdev->wsm_cmd_buf;
	HiMsgHdr_t *hdr;
	// WsmHiReadMibCnfBody_t is too big to be placed on stack
	WsmHiReadMibCnfBody_t *reply = kmalloc(sizeof(WsmHiReadMibCnfBody_t), GFP_KERNEL);

	wsm_cmd_lock(wdev);
	wsm_buf_reset(wfx_arg);
	wfx_cmd_len(wfx_arg, mib_id);
	wfx_cmd_len(wfx_arg, 0);

	hdr = (HiMsgHdr_t *) wfx_arg->begin;
	wfx_fill_header(hdr, -1, WSM_HI_READ_MIB_REQ_ID, sizeof(WsmHiReadMibReqBody_t));
	ret = wfx_cmd_send(wdev, hdr, reply, WSM_CMD_TIMEOUT);

	reply->Length -= 4; // Drop header
	if (buf_size < reply->Length) {
		dev_err(wdev->pdev, "Bad buffer size to receive %s (%zu < %d)\n",
			get_mib_name(mib_id), buf_size, reply->Length);
		ret = -ENOMEM;
	}
	if (mib_id != reply->MibId) {
		dev_warn(wdev->pdev, "%s: confirmation mismatch request\n", __func__);
		ret = -EIO;
	}

nomem:
	if (!ret)
		memcpy(_buf, &reply->MibData, reply->Length);
	else
		memset(_buf, 0xFF, buf_size);
	wsm_cmd_unlock(wdev);
	kfree(reply);
	return ret;
}

int wsm_write_mib(struct wfx_dev *wdev, u16 mib_id, void *_buf,
		  size_t buf_size, int Id)
{
	int ret;
	struct wsm_buf *wfx_arg = &wdev->wsm_cmd_buf;
	HiMsgHdr_t *hdr;

	wsm_cmd_lock(wdev);
	wsm_buf_reset(wfx_arg);
	wfx_cmd_len(wfx_arg, mib_id);
	wfx_cmd_len(wfx_arg, buf_size);
	wfx_cmd(wfx_arg, _buf, buf_size);

	hdr = (HiMsgHdr_t *) wfx_arg->begin;
	wfx_fill_header(hdr, Id, WSM_HI_WRITE_MIB_REQ_ID, 2 * sizeof(u16) + buf_size);
	ret = wfx_cmd_send(wdev, hdr, NULL, WSM_CMD_TIMEOUT);

nomem:
	wsm_cmd_unlock(wdev);
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

	wsm_cmd_lock(wdev);
	ret = wfx_cmd_send(wdev, hdr, NULL, WSM_CMD_TIMEOUT);
	wsm_cmd_unlock(wdev);
	kfree(hdr);
	return ret;
}

int wsm_stop_scan(struct wfx_dev *wdev, int Id)
{
	int ret;
	HiMsgHdr_t *hdr;
	// body associated to WSM_HI_STOP_SCAN_REQ_ID is empty
	wfx_alloc_wsm(0, &hdr);

	wsm_cmd_lock(wdev);
	wfx_fill_header(hdr, Id, WSM_HI_STOP_SCAN_REQ_ID, 0);
	ret = wfx_cmd_send(wdev, hdr, NULL, WSM_CMD_TIMEOUT);
	wsm_cmd_unlock(wdev);
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
	wsm_cmd_lock(wdev);
	ret = wfx_cmd_send(wdev, hdr, NULL, WSM_CMD_JOIN_TIMEOUT);
	wsm_cmd_unlock(wdev);
	kfree(hdr);
	return ret;
}

int wsm_set_bss_params(struct wfx_dev		*wdev,
		       const WsmHiSetBssParamsReqBody_t *arg, int Id)
{
	int ret;
	struct wsm_buf *wfx_arg = &wdev->wsm_cmd_buf;
	HiMsgHdr_t *hdr;

	wsm_cmd_lock(wdev);
	wsm_buf_reset(wfx_arg);
	wfx_cmd_fl(wfx_arg, arg->BssFlags.LostCountOnly ? 1 : 0);
	wfx_cmd_fl(wfx_arg, arg->BeaconLostCount);
	wfx_cmd_len(wfx_arg, arg->AID);
	wfx_cmd_data(wfx_arg, arg->OperationalRateSet);

	hdr = (HiMsgHdr_t *) wfx_arg->begin;
	wfx_fill_header(hdr, Id, WSM_HI_SET_BSS_PARAMS_REQ_ID, sizeof(WsmHiSetBssParamsReqBody_t));
	ret = wfx_cmd_send(wdev, hdr, NULL, WSM_CMD_TIMEOUT);

nomem:
	wsm_cmd_unlock(wdev);
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
	wsm_cmd_lock(wdev);
	ret = wfx_cmd_send(wdev, hdr, NULL, WSM_CMD_TIMEOUT);
	wsm_cmd_unlock(wdev);
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
	wsm_cmd_lock(wdev);
	ret = wfx_cmd_send(wdev, hdr, NULL, WSM_CMD_TIMEOUT);
	wsm_cmd_unlock(wdev);
	kfree(hdr);
	return ret;
}

int wsm_set_tx_queue_params(struct wfx_dev *wdev,
			    const WsmHiTxQueueParamsReqBody_t *arg, u8 id, int Id)
{
	int ret;
	struct wsm_buf *wfx_arg = &wdev->wsm_cmd_buf;
	HiMsgHdr_t *hdr;

	wsm_cmd_lock(wdev);
	wsm_buf_reset(wfx_arg);
	wfx_cmd_fl(wfx_arg, wsm_queue_id_to_wsm(id));
	wfx_cmd_fl(wfx_arg, 0);
	wfx_cmd_fl(wfx_arg, arg->AckPolicy);
	wfx_cmd_fl(wfx_arg, 0);
	wfx_cmd_data(wfx_arg, arg->MaxTransmitLifetime);
	wfx_cmd_len(wfx_arg, arg->AllowedMediumTime);
	wfx_cmd_len(wfx_arg, 0);

	hdr = (HiMsgHdr_t *) wfx_arg->begin;
	wfx_fill_header(hdr, Id, WSM_HI_TX_QUEUE_PARAMS_REQ_ID, sizeof(WsmHiTxQueueParamsReqBody_t));
	ret = wfx_cmd_send(wdev, hdr, NULL, WSM_CMD_TIMEOUT);

nomem:
	wsm_cmd_unlock(wdev);
	return ret;
}

int wsm_set_edca_params(struct wfx_dev *wdev,
			const struct wsm_edca_params *arg, int Id)
{
	int ret;
	struct wsm_buf *wfx_arg = &wdev->wsm_cmd_buf;
	HiMsgHdr_t *hdr;

	wsm_cmd_lock(wdev);
	wsm_buf_reset(wfx_arg);

	wfx_cmd_len(wfx_arg, arg->params.CwMin[3]);
	wfx_cmd_len(wfx_arg, arg->params.CwMin[2]);
	wfx_cmd_len(wfx_arg, arg->params.CwMin[1]);
	wfx_cmd_len(wfx_arg, arg->params.CwMin[0]);

	wfx_cmd_len(wfx_arg, arg->params.CwMax[3]);
	wfx_cmd_len(wfx_arg, arg->params.CwMax[2]);
	wfx_cmd_len(wfx_arg, arg->params.CwMax[1]);
	wfx_cmd_len(wfx_arg, arg->params.CwMax[0]);

	wfx_cmd_fl(wfx_arg, arg->params.AIFSN[3]);
	wfx_cmd_fl(wfx_arg, arg->params.AIFSN[2]);
	wfx_cmd_fl(wfx_arg, arg->params.AIFSN[1]);
	wfx_cmd_fl(wfx_arg, arg->params.AIFSN[0]);

	wfx_cmd_len(wfx_arg, arg->params.TxOpLimit[3]);
	wfx_cmd_len(wfx_arg, arg->params.TxOpLimit[2]);
	wfx_cmd_len(wfx_arg, arg->params.TxOpLimit[1]);
	wfx_cmd_len(wfx_arg, arg->params.TxOpLimit[0]);

	wfx_cmd_data(wfx_arg, arg->params.MaxReceiveLifetime[3]);
	wfx_cmd_data(wfx_arg, arg->params.MaxReceiveLifetime[2]);
	wfx_cmd_data(wfx_arg, arg->params.MaxReceiveLifetime[1]);
	wfx_cmd_data(wfx_arg, arg->params.MaxReceiveLifetime[0]);

	hdr = (HiMsgHdr_t *) wfx_arg->begin;
	wfx_fill_header(hdr, Id, WSM_HI_EDCA_PARAMS_REQ_ID, sizeof(WsmHiEdcaParamsReqBody_t));
	ret = wfx_cmd_send(wdev, hdr, NULL, WSM_CMD_TIMEOUT);

nomem:
	wsm_cmd_unlock(wdev);
	return ret;
}

int wsm_set_pm(struct wfx_dev *wdev, const WsmHiSetPmModeReqBody_t *arg, int Id)
{
	int ret;
	struct wsm_buf *wfx_arg = &wdev->wsm_cmd_buf;
	HiMsgHdr_t *hdr;

	wsm_cmd_lock(wdev);
	wsm_buf_reset(wfx_arg);
	wfx_cmd(wfx_arg, &arg->PmMode, sizeof(arg->PmMode));
	wfx_cmd_fl(wfx_arg, arg->FastPsmIdlePeriod);
	wfx_cmd_fl(wfx_arg, arg->ApPsmChangePeriod);
	wfx_cmd_fl(wfx_arg, arg->MinAutoPsPollPeriod);

	hdr = (HiMsgHdr_t *) wfx_arg->begin;
	wfx_fill_header(hdr, Id, WSM_HI_SET_PM_MODE_REQ_ID, sizeof(WsmHiSetPmModeReqBody_t));
	ret = wfx_cmd_send(wdev, hdr, NULL, WSM_CMD_TIMEOUT);

nomem:
	wsm_cmd_unlock(wdev);
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
	wsm_cmd_lock(wdev);
	ret = wfx_cmd_send(wdev, hdr, NULL, WSM_CMD_TIMEOUT);
	wsm_cmd_unlock(wdev);
	kfree(hdr);
	return ret;
}

int wsm_beacon_transmit(struct wfx_dev *wdev,
			const WsmHiBeaconTransmitReqBody_t *arg, int Id)
{
	int ret;
	struct wsm_buf *wfx_arg = &wdev->wsm_cmd_buf;
	HiMsgHdr_t *hdr;

	wsm_cmd_lock(wdev);
	wsm_buf_reset(wfx_arg);
	wfx_cmd_data(wfx_arg, arg->EnableBeaconing ? 1 : 0);

	hdr = (HiMsgHdr_t *) wfx_arg->begin;
	wfx_fill_header(hdr, Id, WSM_HI_BEACON_TRANSMIT_REQ_ID, sizeof(WsmHiBeaconTransmitReqBody_t));
	ret = wfx_cmd_send(wdev, hdr, NULL, WSM_CMD_TIMEOUT);

nomem:
	wsm_cmd_unlock(wdev);
	return ret;
}

int wsm_map_link(struct wfx_dev *wdev, const WsmHiMapLinkReqBody_t *arg, int Id)
{
	int ret;
	struct wsm_buf *wfx_arg = &wdev->wsm_cmd_buf;
	HiMsgHdr_t *hdr;

	wsm_cmd_lock(wdev);
	wsm_buf_reset(wfx_arg);
	wfx_cmd(wfx_arg, arg->MacAddr, sizeof(arg->MacAddr));
	wfx_cmd_fl(wfx_arg, arg->Flags);
	wfx_cmd_fl(wfx_arg, arg->PeerStaId);

	hdr = (HiMsgHdr_t *) wfx_arg->begin;
	wfx_fill_header(hdr, Id, WSM_HI_MAP_LINK_REQ_ID, sizeof(WsmHiMapLinkReqBody_t));
	ret = wfx_cmd_send(wdev, hdr, NULL, WSM_CMD_TIMEOUT);

nomem:
	wsm_cmd_unlock(wdev);
	return ret;
}

int wsm_update_ie(struct wfx_dev *wdev,
		  const struct wsm_update_ie *arg, int Id)
{
	int ret;
	struct wsm_buf *wfx_arg = &wdev->wsm_cmd_buf;
	HiMsgHdr_t *hdr;

	wsm_cmd_lock(wdev);
	wsm_buf_reset(wfx_arg);
	wfx_cmd(wfx_arg, &arg->Body.IeFlags, sizeof(arg->Body.IeFlags));
	wfx_cmd_len(wfx_arg, arg->Body.NumIEs);
	wfx_cmd(wfx_arg, arg->ies, arg->length);

	hdr = (HiMsgHdr_t *) wfx_arg->begin;
	wfx_fill_header(hdr, Id, WSM_HI_UPDATE_IE_REQ_ID, sizeof(WsmHiUpdateIeReqBody_t) + arg->length);
	ret = wfx_cmd_send(wdev, hdr, NULL, WSM_CMD_TIMEOUT);

nomem:
	wsm_cmd_unlock(wdev);
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

	if (ret < 0)
		dev_err(wdev->pdev, "WSM request %s (%#02x) returned error %d\n",
				get_wsm_name(cmd), cmd, ret);
	if (ret > 0)
		dev_warn(wdev->pdev, "WSM request %s (%#02x) returned status %d\n",
				get_wsm_name(cmd), cmd, ret);

	return ret;
}

void wsm_buf_init(struct wsm_buf *buf)
{
	BUG_ON(buf->begin);
	buf->begin = kmalloc(FWLOAD_BLOCK_SIZE, GFP_KERNEL | GFP_DMA);
	buf->end = buf->begin ? &buf->begin[FWLOAD_BLOCK_SIZE] : buf->begin;
	wsm_buf_reset(buf);
}

void wsm_buf_deinit(struct wsm_buf *buf)
{
	kfree(buf->begin);
	buf->begin = buf->data = buf->end = NULL;
}

void wsm_buf_reset(struct wsm_buf *buf)
{
	if (buf->begin) {
		buf->data = &buf->begin[4];
		*(u32 *)buf->begin = 0;
	} else {
		buf->data = buf->begin;
	}
}

int wsm_buf_reserve(struct wsm_buf *buf, size_t extra_size)
{
	u8 *oldBlock = buf->begin;
	size_t pos = buf->data - buf->begin;
	size_t size = pos + extra_size;

	size = round_up(size, FWLOAD_BLOCK_SIZE);
	buf->begin = krealloc(oldBlock, size, GFP_KERNEL | GFP_DMA);
	if (buf->begin) {
		buf->data = &buf->begin[pos];
		buf->end = &buf->begin[size];
		return 0;
	} else {
		buf->end = buf->begin;
		buf->data = buf->begin;
		return -ENOMEM;
	}
}

