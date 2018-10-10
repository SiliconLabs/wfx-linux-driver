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

struct wsm_mib {
	u16	mib_id;
	void	*buf;
	size_t	buf_size;
};

static int wfx_cmd_send(struct wfx_dev *wdev, struct wsm_buf *buf, void *arg,
			u8 cmd, long tmo);

int wsm_configuration(struct wfx_dev *wdev, const u8 *conf, size_t len)
{
	int ret;
	struct wsm_buf *wfx_arg = &wdev->wsm_cmd_buf;
	HiConfigurationCnf_t reply;

	wsm_cmd_lock(wdev);
	wfx_cmd_len(wfx_arg, len);
	wfx_cmd(wfx_arg, conf, len);

	ret = wfx_cmd_send(wdev,
			   wfx_arg,
			   &reply,
			   HI_CONFIGURATION_REQ_ID,
			   WSM_CMD_TIMEOUT);
	wsm_cmd_unlock(wdev);
	if (ret < 0)
		return ret;

	WARN_ON(le32_to_cpu(reply.Header.MsgLen) != sizeof(reply));
	WARN_ON(le32_to_cpu(reply.Header.s.t.MsgId) != HI_CONFIGURATION_CNF_ID);
	return le32_to_cpu(reply.Body.Status);

nomem:
	wsm_cmd_unlock(wdev);
	return -ENOMEM;
}

int wsm_reset(struct wfx_dev *wdev, const WsmHiResetFlags_t *arg)
{
	int ret;
	struct wsm_buf *wfx_arg = &wdev->wsm_cmd_buf;

	wsm_cmd_lock(wdev);
	wfx_cmd_data(wfx_arg, arg->ResetStat ? 0 : 1);

	ret = wfx_cmd_send(wdev,
			   wfx_arg,
			   NULL,
			   WSM_HI_RESET_REQ_ID,
			   WSM_CMD_RESET_TIMEOUT);

nomem:
	wsm_cmd_unlock(wdev);
	return ret;
}

int wsm_read_mib(struct wfx_dev *wdev, u16 mib_id, void *_buf,
			size_t buf_size)
{
	int ret;
	struct wsm_buf *wfx_arg = &wdev->wsm_cmd_buf;
	struct wsm_mib mib_buf = {
		.mib_id = mib_id,
		.buf = _buf,
		.buf_size = buf_size,
	};

	wsm_cmd_lock(wdev);
	wfx_cmd_len(wfx_arg, mib_id);
	wfx_cmd_len(wfx_arg, 0);

	ret = wfx_cmd_send(wdev,
			   wfx_arg,
			   &mib_buf,
			   WSM_HI_READ_MIB_REQ_ID,
			   WSM_CMD_TIMEOUT);

nomem:
	wsm_cmd_unlock(wdev);
	return ret;
}

int wsm_write_mib(struct wfx_dev *wdev, u16 mib_id, void *_buf,
			size_t buf_size)
{
	int ret;
	struct wsm_buf *wfx_arg = &wdev->wsm_cmd_buf;
	struct wsm_mib mib_buf = {
		.mib_id = mib_id,
		.buf = _buf,
		.buf_size = buf_size,
	};

	wsm_cmd_lock(wdev);
	wfx_cmd_len(wfx_arg, mib_id);
	wfx_cmd_len(wfx_arg, buf_size);
	wfx_cmd(wfx_arg, _buf, buf_size);

	ret = wfx_cmd_send(wdev,
			   wfx_arg,
			   &mib_buf,
			   WSM_HI_WRITE_MIB_REQ_ID,
			   WSM_CMD_TIMEOUT);

nomem:
	wsm_cmd_unlock(wdev);
	return ret;
}

int wsm_scan(struct wfx_dev *wdev, const struct wsm_scan *arg)
{
	int i;
	int ret;
	struct wsm_buf *wfx_arg = &wdev->wsm_cmd_buf;

	if (arg->scan_req.NumOfChannels > WSM_API_CHANNEL_LIST_SIZE)
		return -EINVAL;

	if (arg->scan_req.NumOfSSIDs > 2)
		return -EINVAL;

	if (arg->scan_req.Band > 1)
		return -EINVAL;

	wsm_cmd_lock(wdev);
	wfx_cmd_fl(wfx_arg, arg->scan_req.Band);
	wfx_cmd(wfx_arg, &arg->scan_req.ScanType, sizeof(WsmHiScanType_t));
	wfx_cmd(wfx_arg, &arg->scan_req.ScanFlags, sizeof(WsmHiScanFlags_t));
	wfx_cmd_fl(wfx_arg, arg->scan_req.MaxTransmitRate);
	wfx_cmd(wfx_arg, &arg->scan_req.AutoScanParam, sizeof(WsmHiAutoScanParam_t));
	wfx_cmd_fl(wfx_arg, arg->scan_req.NumOfProbeRequests);
	wfx_cmd_fl(wfx_arg, arg->scan_req.ProbeDelay);
	wfx_cmd_fl(wfx_arg, arg->scan_req.NumOfSSIDs);
	wfx_cmd_fl(wfx_arg, arg->scan_req.NumOfChannels);
	wfx_cmd_data(wfx_arg, arg->scan_req.MinChannelTime);
	wfx_cmd_data(wfx_arg, arg->scan_req.MaxChannelTime);
	wfx_cmd_data(wfx_arg, arg->scan_req.TxPowerLevel);

	for (i = 0; i < arg->scan_req.NumOfSSIDs; ++i) {
		wfx_cmd_data(wfx_arg, arg->ssids[i].SSIDLength);
		wfx_cmd(wfx_arg, arg->ssids[i].SSID, sizeof(arg->ssids[i].SSID));
	}

	for (i = 0; i < arg->scan_req.NumOfChannels; ++i)
		wfx_cmd_fl(wfx_arg, arg->ch[i]);

	ret = wfx_cmd_send(wdev,
			   wfx_arg,
			   NULL,
			   WSM_HI_START_SCAN_REQ_ID,
			   WSM_CMD_TIMEOUT);

nomem:
	wsm_cmd_unlock(wdev);
	return ret;
}

int wsm_stop_scan(struct wfx_dev *wdev)
{
	int ret;
	struct wsm_buf *wfx_arg = &wdev->wsm_cmd_buf;

	wsm_cmd_lock(wdev);
	ret = wfx_cmd_send(wdev,
			   wfx_arg,
			   NULL,
			   WSM_HI_STOP_SCAN_REQ_ID,
			   WSM_CMD_TIMEOUT);

	wsm_cmd_unlock(wdev);
	return ret;
}

int wsm_join(struct wfx_dev *wdev, WsmHiJoinReqBody_t *arg)
{
	int ret;
	struct wsm_buf *wfx_arg = &wdev->wsm_cmd_buf;
	WsmHiJoinCnfBody_t resp;

	wsm_cmd_lock(wdev);
	wfx_cmd_fl(wfx_arg, arg->Mode);
	wfx_cmd_fl(wfx_arg, arg->Band);
	wfx_cmd_len(wfx_arg, arg->ChannelNumber);
	wfx_cmd(wfx_arg, arg->BSSID, sizeof(arg->BSSID));
	wfx_cmd_len(wfx_arg, arg->AtimWindow);
	wfx_cmd_fl(wfx_arg, arg->PreambleType);
	wfx_cmd_fl(wfx_arg, arg->ProbeForJoin);
	wfx_cmd_fl(wfx_arg, arg->DTIMPeriod);
	wfx_cmd(wfx_arg, &arg->JoinFlags, sizeof(arg->JoinFlags));
	wfx_cmd_data(wfx_arg, arg->SSIDLength);
	wfx_cmd(wfx_arg, arg->SSID, sizeof(arg->SSID));
	wfx_cmd_data(wfx_arg, arg->BeaconInterval);
	wfx_cmd_data(wfx_arg, arg->BasicRateSet);

	ret = wfx_cmd_send(wdev,
			   wfx_arg,
			   &resp,
			   WSM_HI_JOIN_REQ_ID,
			   WSM_CMD_JOIN_TIMEOUT);
	if (!ret)
		ret = resp.Status;

nomem:
	wsm_cmd_unlock(wdev);
	return ret;
}

int wsm_set_bss_params(struct wfx_dev		*wdev,
		       const WsmHiSetBssParamsReqBody_t *arg)
{
	int ret;
	struct wsm_buf *wfx_arg = &wdev->wsm_cmd_buf;

	wsm_cmd_lock(wdev);
	wfx_cmd_fl(wfx_arg, arg->BssFlags.LostCountOnly ? 1 : 0);
	wfx_cmd_fl(wfx_arg, arg->BeaconLostCount);
	wfx_cmd_len(wfx_arg, arg->AID);
	wfx_cmd_data(wfx_arg, arg->OperationalRateSet);

	ret = wfx_cmd_send(wdev,
			   wfx_arg,
			   NULL,
			   WSM_HI_SET_BSS_PARAMS_REQ_ID,
			   WSM_CMD_TIMEOUT);

nomem:
	wsm_cmd_unlock(wdev);
	return ret;
}

int wsm_add_key(struct wfx_dev *wdev, const WsmHiAddKeyReqBody_t *arg)
{
	int ret;
	struct wsm_buf *wfx_arg = &wdev->wsm_cmd_buf;

	wsm_cmd_lock(wdev);
	wfx_cmd(wfx_arg, arg, sizeof(*arg));

	ret = wfx_cmd_send(wdev,
			   wfx_arg,
			   NULL,
			   WSM_HI_ADD_KEY_REQ_ID,
			   WSM_CMD_TIMEOUT);

nomem:
	wsm_cmd_unlock(wdev);
	return ret;
}

int wsm_remove_key(struct wfx_dev *wdev, const WsmHiRemoveKeyReqBody_t *arg)
{
	int ret;
	struct wsm_buf *wfx_arg = &wdev->wsm_cmd_buf;

	wsm_cmd_lock(wdev);
	wfx_cmd_fl(wfx_arg, arg->EntryIndex);
	wfx_cmd_fl(wfx_arg, 0);
	wfx_cmd_len(wfx_arg, 0);

	ret = wfx_cmd_send(wdev,
			   wfx_arg,
			   NULL,
			   WSM_HI_REMOVE_KEY_REQ_ID,
			   WSM_CMD_TIMEOUT);

nomem:
	wsm_cmd_unlock(wdev);
	return ret;
}

int wsm_set_tx_queue_params(struct wfx_dev *wdev,
			    const WsmHiTxQueueParamsReqBody_t *arg, u8 id)
{
	int ret;
	struct wsm_buf *wfx_arg = &wdev->wsm_cmd_buf;

	wsm_cmd_lock(wdev);
	wfx_cmd_fl(wfx_arg, wsm_queue_id_to_wsm(id));
	wfx_cmd_fl(wfx_arg, 0);
	wfx_cmd_fl(wfx_arg, arg->AckPolicy);
	wfx_cmd_fl(wfx_arg, 0);
	wfx_cmd_data(wfx_arg, arg->MaxTransmitLifetime);
	wfx_cmd_len(wfx_arg, arg->AllowedMediumTime);
	wfx_cmd_len(wfx_arg, 0);

	ret = wfx_cmd_send(wdev,
			   wfx_arg,
			   NULL,
			   WSM_HI_TX_QUEUE_PARAMS_REQ_ID,
			   WSM_CMD_TIMEOUT);

nomem:
	wsm_cmd_unlock(wdev);
	return ret;
}

int wsm_set_edca_params(struct wfx_dev *wdev, const struct wsm_edca_params *arg)
{
	int ret;
	struct wsm_buf *wfx_arg = &wdev->wsm_cmd_buf;

	wsm_cmd_lock(wdev);

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

	ret = wfx_cmd_send(wdev,
			   wfx_arg,
			   NULL,
			   WSM_HI_EDCA_PARAMS_REQ_ID,
			   WSM_CMD_TIMEOUT);

nomem:
	wsm_cmd_unlock(wdev);
	return ret;
}

int wsm_set_pm(struct wfx_dev *wdev, const WsmHiSetPmModeReqBody_t *arg)
{
	int ret;
	struct wsm_buf *wfx_arg = &wdev->wsm_cmd_buf;

	wsm_cmd_lock(wdev);
	wfx_cmd(wfx_arg, &arg->PmMode, sizeof(arg->PmMode));
	wfx_cmd_fl(wfx_arg, arg->FastPsmIdlePeriod);
	wfx_cmd_fl(wfx_arg, arg->ApPsmChangePeriod);
	wfx_cmd_fl(wfx_arg, arg->MinAutoPsPollPeriod);

	ret = wfx_cmd_send(wdev,
			   wfx_arg,
			   NULL,
			   WSM_HI_SET_PM_MODE_REQ_ID,
			   WSM_CMD_TIMEOUT);

	if (ret)
		wdev->channel_switch_in_progress = 0;

nomem:
	wsm_cmd_unlock(wdev);
	return ret;
}

int wsm_start(struct wfx_dev *wdev, const WsmHiStartReqBody_t *arg)
{
	int ret;
	struct wsm_buf *wfx_arg = &wdev->wsm_cmd_buf;

	wsm_cmd_lock(wdev);
	wfx_cmd(wfx_arg, &arg->Mode, sizeof(arg->Mode));
	wfx_cmd_fl(wfx_arg, arg->Band);
	wfx_cmd_len(wfx_arg, arg->ChannelNumber);
	wfx_cmd_data(wfx_arg, arg->CTWindow);
	wfx_cmd_data(wfx_arg, arg->BeaconInterval);
	wfx_cmd_fl(wfx_arg, arg->DTIMPeriod);
	wfx_cmd_fl(wfx_arg, arg->PreambleType);
	wfx_cmd_fl(wfx_arg, arg->ProbeDelay);
	wfx_cmd_fl(wfx_arg, arg->SsidLength);
	wfx_cmd(wfx_arg, arg->Ssid, sizeof(arg->Ssid));
	wfx_cmd_data(wfx_arg, arg->BasicRateSet);

	ret = wfx_cmd_send(wdev,
			   wfx_arg,
			   NULL,
			   WSM_HI_START_REQ_ID,
			   WSM_CMD_START_TIMEOUT);

nomem:
	wsm_cmd_unlock(wdev);
	return ret;
}

int wsm_beacon_transmit(struct wfx_dev *wdev, const WsmHiBeaconTransmitReqBody_t *arg)
{
	int ret;
	struct wsm_buf *wfx_arg = &wdev->wsm_cmd_buf;

	wsm_cmd_lock(wdev);
	wfx_cmd_data(wfx_arg, arg->EnableBeaconing ? 1 : 0);

	ret = wfx_cmd_send(wdev,
			   wfx_arg,
			   NULL,
			   WSM_HI_BEACON_TRANSMIT_REQ_ID,
			   WSM_CMD_TIMEOUT);

nomem:
	wsm_cmd_unlock(wdev);
	return ret;
}

int wsm_map_link(struct wfx_dev *wdev, const WsmHiMapLinkReqBody_t *arg)
{
	int ret;
	struct wsm_buf *wfx_arg = &wdev->wsm_cmd_buf;

	wsm_cmd_lock(wdev);
	wfx_cmd(wfx_arg, arg->MacAddr, sizeof(arg->MacAddr));
	wfx_cmd_fl(wfx_arg, arg->Flags);
	wfx_cmd_fl(wfx_arg, arg->PeerStaId);

	ret = wfx_cmd_send(wdev,
			   wfx_arg,
			   NULL,
			   WSM_HI_MAP_LINK_REQ_ID,
			   WSM_CMD_TIMEOUT);

nomem:
	wsm_cmd_unlock(wdev);
	return ret;
}

int wsm_update_ie(struct wfx_dev *wdev, const struct wsm_update_ie *arg)
{
	int ret;
	struct wsm_buf *wfx_arg = &wdev->wsm_cmd_buf;

	wsm_cmd_lock(wdev);
	wfx_cmd(wfx_arg, &arg->Body.IeFlags, sizeof(arg->Body.IeFlags));
	wfx_cmd_len(wfx_arg, arg->Body.NumIEs);
	wfx_cmd(wfx_arg, arg->ies, arg->length);

	ret = wfx_cmd_send(wdev,
			   wfx_arg,
			   NULL,
			   WSM_HI_UPDATE_IE_REQ_ID,
			   WSM_CMD_TIMEOUT);

nomem:
	wsm_cmd_unlock(wdev);
	return ret;
}

static int wfx_cmd_send(struct wfx_dev *wdev, struct wsm_buf *buf,
			void *arg, u8 cmd, long tmo)
{
	size_t buf_len = buf->data - buf->begin;
	int ret;

	WARN(cmd > NB_REQ_MSG, "Invalid WSM command %02x", cmd);

	/* Don't bother if we're dead. */
	if (wdev->bh_error) {
		ret = 0;
		goto done;
	}

	spin_lock(&wdev->wsm_cmd.lock);
	while (!wdev->wsm_cmd.done) {
		spin_unlock(&wdev->wsm_cmd.lock);
		spin_lock(&wdev->wsm_cmd.lock);
	}
	wdev->wsm_cmd.done = 0;
	spin_unlock(&wdev->wsm_cmd.lock);

	((__le16 *)buf->begin)[0] = cpu_to_le16(buf_len);
	((__le16 *)buf->begin)[1] = cpu_to_le16(cmd);

	spin_lock(&wdev->wsm_cmd.lock);
	BUG_ON(wdev->wsm_cmd.ptr);
	wdev->wsm_cmd.ptr = buf->begin;
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
done:
	if (ret < 0)
		dev_err(wdev->pdev, "WSM request %s %08x returned error %d\n",
				get_wsm_name(cmd), cmd, ret);

	wsm_buf_reset(buf);
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

