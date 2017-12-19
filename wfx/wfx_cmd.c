/*
 * Copyright (c) 2017, Silicon Laboratories, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
 

/*========================================================================*/
/*                 Standard Linux Headers             					  */
/*========================================================================*/
#include <linux/skbuff.h>
#include <linux/wait.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/random.h>

/*========================================================================*/
/*                 Local Header files             					      */
/*========================================================================*/
#include "wfx.h"
#include "wsm.h"
#include "bh.h"
#include "debug.h"
#include "sta.h"

/*========================================================================*/
/*                  PRIVATE  Constants/Macros/Types/Variables             */
/*========================================================================*/


/*========================================================================*/
/*                  Structures definitions                                */
/*========================================================================*/
struct wsm_mib {
	u16 mib_id;
	void *buf;
	size_t buf_size;
};

/*========================================================================*/
/*                       Functions                                        */
/*========================================================================*/
static int wfx_cmd_send(struct wfx_common *priv,
			struct wsm_buf *buf,
			void *arg, u8 cmd, long tmo);
/*-----------------------------------------------------------------------
 *
 * wsm configuration
 *
 */
int wsm_configuration(struct wfx_common *priv, struct wsm_configuration *arg, const u8 *conf_file_data)
{
	int ret;
	struct wsm_configuration *wf200_cmd;

	struct wsm_buf *wfx_arg = &priv->wsm_cmd_buf;

    wf200_cmd = kzalloc(sizeof(*wf200_cmd), GFP_KERNEL);
    if (!wf200_cmd) {
            ret = -ENOMEM;
            goto out;
    }

	wsm_cmd_lock(priv);

	wfx_cmd_data(wfx_arg, arg->req_part.Dot11MaxTransmitMsduLifeTime);
	wfx_cmd_data(wfx_arg, arg->req_part.Dot11MaxReceiveLifeTime);
	wfx_cmd_data(wfx_arg, arg->req_part.Dot11RtsThreshold);

	/* DPD block. */
	wfx_cmd_len(wfx_arg, arg->req_part.DpdData.Length + 12);
	wfx_cmd_len(wfx_arg, 1); /* DPD version */
	wfx_cmd(wfx_arg, arg->cnf_part.Dot11StationId, ETH_ALEN);
	wfx_cmd_len(wfx_arg, 5); /* DPD flags */
	wfx_cmd(wfx_arg, (void *)(conf_file_data), arg->req_part.DpdData.Length);

	ret = wfx_cmd_send(priv,
			wfx_arg,
			arg,
			WSM_HI_CONFIGURATION_REQ_ID,
			WSM_CMD_TIMEOUT);
    if (ret < 0) {
            pr_debug("failed to send HI configuration request ID command");
            goto nomem;
    }

out:
	wsm_cmd_unlock(priv);
	return ret;

nomem:
	wsm_cmd_unlock(priv);
    kfree(wf200_cmd);
	return -ENOMEM;
}

/*-----------------------------------------------------------------------
 *
 * wsm reset
 *
 */
int wsm_reset(struct wfx_common *priv, const WsmHiResetFlags_t *arg)
{
	int ret;

	const WsmHiResetFlags_t *wf200_cmd;

	struct wsm_buf *wfx_arg = &priv->wsm_cmd_buf;
	u16 cmd = WSM_HI_RESET_REQ_ID;

    wf200_cmd = kzalloc(sizeof(*wf200_cmd), GFP_KERNEL);
    if (!wf200_cmd) {
            ret = -ENOMEM;
            goto out;
    }

	wsm_cmd_lock(priv);

	wfx_cmd_data(wfx_arg, arg->ResetStat ? 0 : 1);
	ret = wfx_cmd_send(priv,
			wfx_arg,
			NULL,
			cmd,
			WSM_CMD_RESET_TIMEOUT);

    if (ret < 0) {
        pr_debug("failed to send reset command");
            goto nomem;
    }

out:
	wsm_cmd_unlock(priv);
	return ret;

nomem:
	wsm_cmd_unlock(priv);
	kfree(wf200_cmd);
	return -ENOMEM;
}

/*-----------------------------------------------------------------------
 *
 * wsm read MIB
 *
 */
int wsm_read_mib(struct wfx_common *priv, u16 mib_id, void *_buf,
			size_t buf_size)
{
	int ret;

	struct wfx_common *wf200_cmd;

	struct wsm_buf *wfx_arg = &priv->wsm_cmd_buf;
	struct wsm_mib mib_buf = {
		.mib_id = mib_id,
		.buf = _buf,
		.buf_size = buf_size,
	};

    wf200_cmd = kzalloc(sizeof(*wf200_cmd), GFP_KERNEL);
    if (!wf200_cmd) {
            ret = -ENOMEM;
            goto out;
    }

	wsm_cmd_lock(priv);

	wfx_cmd_len(wfx_arg, mib_id);
	wfx_cmd_len(wfx_arg, 0);

	ret = wfx_cmd_send(priv,
			wfx_arg,
			&mib_buf,
			WSM_HI_READ_MIB_REQ_ID,
			WSM_CMD_TIMEOUT);

    if (ret < 0) {
        pr_debug("failed to send HI read mib request ID");
    	goto nomem;
    }

out:
	wsm_cmd_unlock(priv);
	return ret;

nomem:
	wsm_cmd_unlock(priv);
	kfree(wf200_cmd);
	return -ENOMEM;
}

/*-----------------------------------------------------------------------
 *
 * wsm write mib
 *
 */
int wsm_write_mib(struct wfx_common *priv, u16 mib_id, void *_buf,
			size_t buf_size)
{
	int ret;

	struct wfx_common *wf200_cmd;

	struct wsm_buf *wfx_arg = &priv->wsm_cmd_buf;
	struct wsm_mib mib_buf = {
		.mib_id = mib_id,
		.buf = _buf,
		.buf_size = buf_size,
	};

    wf200_cmd = kzalloc(sizeof(*wf200_cmd), GFP_KERNEL);
    if (!wf200_cmd) {
            ret = -ENOMEM;
            goto out;
    }

	wsm_cmd_lock(priv);

	wfx_cmd_len(wfx_arg, mib_id);
	wfx_cmd_len(wfx_arg, buf_size);
	wfx_cmd(wfx_arg, _buf, buf_size);

	ret = wfx_cmd_send(priv,
			wfx_arg,
			&mib_buf,
			WSM_HI_WRITE_MIB_REQ_ID,
			WSM_CMD_TIMEOUT);

    if (ret < 0) {
    	pr_debug("failed to send HI write mib request ID");
    	goto nomem;
    }

out:
	wsm_cmd_unlock(priv);
	return ret;

nomem:
	wsm_cmd_unlock(priv);
	kfree(wf200_cmd);
	return -ENOMEM;
}

/*-----------------------------------------------------------------------
 *
 * wsm scan
 *
 */
int wsm_scan(struct wfx_common *priv, const struct wsm_scan *arg)
{
	int i;
	int ret;

	const struct wsm_scan *wf200_cmd;
	struct wsm_buf *wfx_arg = &priv->wsm_cmd_buf;

	if (arg->scan_req.NumOfChannels > 48)
		return -EINVAL;

	if (arg->scan_req.NumOfSSIDs > 2)
		return -EINVAL;

	if (arg->scan_req.Band > 1)
		return -EINVAL;

    wf200_cmd = kzalloc(sizeof(*wf200_cmd), GFP_KERNEL);
    if (!wf200_cmd) {
            ret = -ENOMEM;
            goto out;
    }

	wsm_cmd_lock(priv);

	wfx_cmd_fl(wfx_arg, arg->scan_req.Band);
	wfx_cmd_fl(wfx_arg, arg->scan_req.ScanType);
	wfx_cmd(wfx_arg, &arg->scan_req.ScanFlags, sizeof(arg->scan_req.ScanFlags));
	wfx_cmd_fl(wfx_arg, arg->scan_req.MaxTransmitRate);
	wfx_cmd(wfx_arg, &arg->scan_req.AutoScanInterval, sizeof(arg->scan_req.AutoScanInterval));
	wfx_cmd_fl(wfx_arg, arg->scan_req.NumOfProbeRequests);
	wfx_cmd_fl(wfx_arg, arg->scan_req.NumOfChannels);
	wfx_cmd_fl(wfx_arg, arg->scan_req.NumOfSSIDs);
	wfx_cmd_fl(wfx_arg, arg->scan_req.ProbeDelay);

	for (i = 0; i < arg->scan_req.NumOfChannels; ++i) {
		wfx_cmd_len(wfx_arg, arg->ch[i].ChannelNumber);
		wfx_cmd_len(wfx_arg, 0);
		wfx_cmd_data(wfx_arg, arg->ch[i].MinChannelTime);
		wfx_cmd_data(wfx_arg, arg->ch[i].MaxChannelTime);
		wfx_cmd_data(wfx_arg, 0);
	}

	for (i = 0; i < arg->scan_req.NumOfSSIDs; ++i) {
		wfx_cmd_data(wfx_arg, arg->ssids[i].SSIDLength);
		wfx_cmd(wfx_arg, arg->ssids[i].SSID,
			sizeof(arg->ssids[i].SSID));
	}

	ret = wfx_cmd_send(priv,
			wfx_arg,
			NULL,
			WSM_HI_START_SCAN_REQ_ID,
			WSM_CMD_TIMEOUT);

    if (ret < 0) {
    	pr_debug("failed to send HI start scan request ID");
    	goto nomem;
    }

out:
	wsm_cmd_unlock(priv);
	return ret;

nomem:
	wsm_cmd_unlock(priv);
	kfree(wf200_cmd);
	return -ENOMEM;
}

/*-----------------------------------------------------------------------
 *
 * wsm stop scan
 *
 */
int wsm_stop_scan(struct wfx_common *priv)
{
	int ret;

	struct wfx_common *wf200_cmd;

	struct wsm_buf *wfx_arg = &priv->wsm_cmd_buf;

    wf200_cmd = kzalloc(sizeof(*wf200_cmd), GFP_KERNEL);

    if (!wf200_cmd) {
            ret = -ENOMEM;
            goto out;
    }

	wsm_cmd_lock(priv);
	ret = wfx_cmd_send(priv,
			wfx_arg,
			NULL,
			WSM_HI_STOP_SCAN_REQ_ID,
			WSM_CMD_TIMEOUT);

    if (ret < 0) {
    	pr_debug("failed to send HI stop scan request ID");
    	goto nomem;
    }

out:
	wsm_cmd_unlock(priv);
	return ret;

nomem:
	wsm_cmd_unlock(priv);
	kfree(wf200_cmd);
	return -ENOMEM;
}

/*-----------------------------------------------------------------------
 *
 * wsm join
 *
 */
int wsm_join(struct wfx_common *priv, WsmHiJoinReqBody_t *arg)
{
	int ret;

	WsmHiJoinReqBody_t *wf200_cmd;

	struct wsm_buf *wfx_arg = &priv->wsm_cmd_buf;
	WsmHiJoinCnfBody_t resp;

    wf200_cmd = kzalloc(sizeof(*wf200_cmd), GFP_KERNEL);

    if (!wf200_cmd) {
            ret = -ENOMEM;
            goto out;
    }

	wsm_cmd_lock(priv);

	wfx_cmd_fl(wfx_arg, arg->Mode);
	wfx_cmd_fl(wfx_arg, arg->Band);
	wfx_cmd_len(wfx_arg, arg->ChannelNumber);
	wfx_cmd(wfx_arg, arg->BSSID, sizeof(arg->BSSID));
	wfx_cmd_len(wfx_arg, arg->AtimWindow);
	wfx_cmd_fl(wfx_arg, arg->PreambleType);
	wfx_cmd_fl(wfx_arg, arg->ProbeForJoin);
	wfx_cmd_fl(wfx_arg, arg->Reserved);	/* dtim_period */
	wfx_cmd(wfx_arg, &arg->JoinFlags, sizeof(arg->JoinFlags));
	wfx_cmd_data(wfx_arg, arg->SSIDLength);
	wfx_cmd(wfx_arg, arg->SSID, sizeof(arg->SSID));
	wfx_cmd_data(wfx_arg, arg->BeaconInterval);
	wfx_cmd_data(wfx_arg, arg->BasicRateSet);

	priv->tx_burst_idx = -1;

	ret = wfx_cmd_send(priv,
			wfx_arg,
			&resp,
			WSM_HI_JOIN_REQ_ID,
			WSM_CMD_JOIN_TIMEOUT);

    if (ret < 0) {
    	pr_debug("failed to send HI join request ID");
    	goto nomem;
    }

	priv->join_complete_status = resp.Status;

out:
	wsm_cmd_unlock(priv);
	return ret;

nomem:
	wsm_cmd_unlock(priv);
	kfree(wf200_cmd);
	return -ENOMEM;
}

/*-----------------------------------------------------------------------
 *
 * wsm set bss params
 *
 */
int wsm_set_bss_params(struct wfx_common *priv,
		       const WsmHiSetBssParamsReqBody_t *arg)
{
	int ret;
	const WsmHiSetBssParamsReqBody_t *wf200_cmd;

	struct wsm_buf *wfx_arg = &priv->wsm_cmd_buf;

    wf200_cmd = kzalloc(sizeof(*wf200_cmd), GFP_KERNEL);

    if (!wf200_cmd) {
            ret = -ENOMEM;
            goto out;
    }

	wsm_cmd_lock(priv);

	wfx_cmd_fl(wfx_arg, (arg->BssFlags.LostCountOnly ?  0x1 : 0));
	wfx_cmd_fl(wfx_arg, arg->BeaconLostCount);
	wfx_cmd_len(wfx_arg, arg->AID);
	wfx_cmd_data(wfx_arg, arg->OperationalRateSet);

	ret = wfx_cmd_send(priv,
			wfx_arg,
			NULL,
			WSM_HI_SET_BSS_PARAMS_REQ_ID, WSM_CMD_TIMEOUT);

    if (ret < 0) {
    	pr_debug("failed to sent: set bss params request ID");
    	goto nomem;
    }

out:
	wsm_cmd_unlock(priv);
	return ret;

nomem:
	wsm_cmd_unlock(priv);
	kfree(wf200_cmd);
	return -ENOMEM;
}

/*-----------------------------------------------------------------------
 *
 * wsm add key
 *
 */
int wsm_add_key(struct wfx_common *priv, const WsmHiAddKeyReqBody_t *arg)
{
	int ret;
	const WsmHiAddKeyReqBody_t *wf200_cmd;
	struct wsm_buf *wfx_arg = &priv->wsm_cmd_buf;

    wf200_cmd = kzalloc(sizeof(*wf200_cmd), GFP_KERNEL);

    if (!wf200_cmd) {
            ret = -ENOMEM;
            goto out;
    }

	wsm_cmd_lock(priv);

	wfx_cmd(wfx_arg, arg, sizeof(*arg));

	ret = wfx_cmd_send(priv,
			wfx_arg,
			NULL,
			WSM_HI_ADD_KEY_REQ_ID,
			WSM_CMD_TIMEOUT);

    if (ret < 0) {
    	pr_debug("failed to sent: add key request ID");
    	goto nomem;
    }

out:
	wsm_cmd_unlock(priv);
	return ret;

nomem:
	wsm_cmd_unlock(priv);
	kfree(wf200_cmd);
	return -ENOMEM;
}

/*-----------------------------------------------------------------------
 *
 * wsm remove key
 *
 */
int wsm_remove_key(struct wfx_common *priv, const WsmHiRemoveKeyReqBody_t *arg)
{
	int ret;
	const WsmHiRemoveKeyReqBody_t *wf200_cmd;
	struct wsm_buf *wfx_arg = &priv->wsm_cmd_buf;

    wf200_cmd = kzalloc(sizeof(*wf200_cmd), GFP_KERNEL);

    if (!wf200_cmd) {
            ret = -ENOMEM;
            goto out;
    }

	wsm_cmd_lock(priv);

	wfx_cmd_fl(wfx_arg, arg->EntryIndex);
	wfx_cmd_fl(wfx_arg, 0);
	wfx_cmd_len(wfx_arg, 0);

	ret = wfx_cmd_send(priv,
			wfx_arg,
			NULL,
			WSM_HI_REMOVE_KEY_REQ_ID,
			WSM_CMD_TIMEOUT);

	if (ret < 0) {
		pr_debug("failed to sent: remove key request ID");
		goto nomem;
	}

out:
	wsm_cmd_unlock(priv);
	return ret;

nomem:
	wsm_cmd_unlock(priv);
	kfree(wf200_cmd);
	return -ENOMEM;
}

/*-----------------------------------------------------------------------
 *
 * wsm set tx queue params
 *
 */
int wsm_set_tx_queue_params(struct wfx_common *priv,
		const WsmHiTxQueueParamsReqBody_t *arg, u8 id)
{
	int ret;
	const WsmHiTxQueueParamsReqBody_t *wf200_cmd;
	struct wsm_buf *wfx_arg = &priv->wsm_cmd_buf;
	u8 queue_id_to_wmm_aci[] = {3, 2, 0, 1};

    wf200_cmd = kzalloc(sizeof(*wf200_cmd), GFP_KERNEL);

    if (!wf200_cmd) {
            ret = -ENOMEM;
            goto out;
    }

	wsm_cmd_lock(priv);

	wfx_cmd_fl(wfx_arg, queue_id_to_wmm_aci[id]);
	wfx_cmd_fl(wfx_arg, 0);
	wfx_cmd_fl(wfx_arg, arg->AckPolicy);
	wfx_cmd_fl(wfx_arg, 0);
	wfx_cmd_data(wfx_arg, arg->MaxTransmitLifetime);
	wfx_cmd_len(wfx_arg, arg->AllowedMediumTime);
	wfx_cmd_len(wfx_arg, 0);

	ret = wfx_cmd_send(priv,
			wfx_arg,
			NULL,
			WSM_HI_TX_QUEUE_PARAMS_REQ_ID,
			WSM_CMD_TIMEOUT);

	if (ret < 0) {
		pr_debug("failed to sent: tx queue params request ID");
		goto nomem;
	}

out:
	wsm_cmd_unlock(priv);
	return ret;

nomem:
	wsm_cmd_unlock(priv);
	kfree(wf200_cmd);
	return -ENOMEM;
}

/*-----------------------------------------------------------------------
 *
 * wsm set edca params
 */
int wsm_set_edca_params(struct wfx_common *priv,
				const struct wsm_edca_params *arg)
{
	int ret;
	const struct wsm_edca_params *wf200_cmd;
	struct wsm_buf *wfx_arg = &priv->wsm_cmd_buf;

    wf200_cmd = kzalloc(sizeof(*wf200_cmd), GFP_KERNEL);

    if (!wf200_cmd) {
            ret = -ENOMEM;
            goto out;
    }

	wsm_cmd_lock(priv);

	/* Implemented according to specification. */

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

	ret = wfx_cmd_send(priv,
			wfx_arg,
			NULL,
			WSM_HI_EDCA_PARAMS_REQ_ID,
			WSM_CMD_TIMEOUT);

	if (ret < 0) {
		pr_debug("failed to sent: edca params request ID");
		goto nomem;
	}

out:
	wsm_cmd_unlock(priv);
	return ret;

nomem:
	wsm_cmd_unlock(priv);
	kfree(wf200_cmd);
	return -ENOMEM;
}

/*-----------------------------------------------------------------------
 *
 * wsm switch channel
 *
 */
int wsm_switch_channel(struct wfx_common *priv,
			const WsmHiSwitchChannelReqBody_t *arg)
{
	int ret;
	const WsmHiSwitchChannelReqBody_t *wf200_cmd;
	struct wsm_buf *wfx_arg = &priv->wsm_cmd_buf;

    wf200_cmd = kzalloc(sizeof(*wf200_cmd), GFP_KERNEL);

    if (!wf200_cmd) {
            ret = -ENOMEM;
            goto out;
    }

	wsm_cmd_lock(priv);

	wfx_cmd(wfx_arg, &arg->ChannelMode, sizeof(arg->ChannelMode));
	wfx_cmd_fl(wfx_arg, arg->ChannelSwitchCount);
	wfx_cmd_len(wfx_arg, arg->NewChannelNumber);

	priv->channel_switch_in_progress = 1;

	ret = wfx_cmd_send(priv,
			wfx_arg,
			NULL,
			WSM_HI_SWITCH_CHANNEL_REQ_ID,
			WSM_CMD_TIMEOUT);

	if (ret)
		priv->channel_switch_in_progress = 0;

	if (ret < 0) {
		pr_debug("failed to sent: switch channel request ID");
		goto nomem;
	}

out:
	wsm_cmd_unlock(priv);
	return ret;

nomem:
	wsm_cmd_unlock(priv);
	kfree(wf200_cmd);
	return -ENOMEM;
}

/*-----------------------------------------------------------------------
 *
 * wsm set pm
 *
 */
int wsm_set_pm(struct wfx_common *priv, const WsmHiSetPmModeReqBody_t *arg)
{
	int ret;
	const WsmHiSetPmModeReqBody_t *wf200_cmd;
	struct wsm_buf *wfx_arg = &priv->wsm_cmd_buf;
	priv->ps_mode_switch_in_progress = 1;

    wf200_cmd = kzalloc(sizeof(*wf200_cmd), GFP_KERNEL);

    if (!wf200_cmd) {
            ret = -ENOMEM;
            goto out;
    }

	wsm_cmd_lock(priv);

	wfx_cmd(wfx_arg, &arg->PmMode, sizeof(arg->PmMode));
	wfx_cmd_fl(wfx_arg, arg->FastPsmIdlePeriod);
	wfx_cmd_fl(wfx_arg, arg->ApPsmChangePeriod);
	wfx_cmd_fl(wfx_arg, arg->MinAutoPsPollPeriod);

	ret = wfx_cmd_send(priv,
			wfx_arg,
			NULL,
			WSM_HI_SET_PM_MODE_REQ_ID,
			WSM_CMD_TIMEOUT);

	if (ret)
		priv->channel_switch_in_progress = 0;

	if (ret < 0) {
		pr_debug("failed to sent: set PM mode request ID");
		goto nomem;
	}

out:
	wsm_cmd_unlock(priv);
	return ret;

nomem:
	wsm_cmd_unlock(priv);
	kfree(wf200_cmd);
	return -ENOMEM;
}

/*-----------------------------------------------------------------------
 *
 * wsm start
 *
 */
int wsm_start(struct wfx_common *priv, const WsmHiStartReqBody_t *arg)
{
	int ret;
	const WsmHiStartReqBody_t *wf200_cmd;
	struct wsm_buf *wfx_arg = &priv->wsm_cmd_buf;

	pr_debug("[WSM] start_request : mode=%d\n", *((uint8 *)&arg->Mode));

    wf200_cmd = kzalloc(sizeof(*wf200_cmd), GFP_KERNEL);

    if (!wf200_cmd) {
            ret = -ENOMEM;
            goto out;
    }

	wsm_cmd_lock(priv);

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

	priv->tx_burst_idx = -1;
	ret = wfx_cmd_send(priv,
			wfx_arg,
			NULL,
			WSM_HI_START_REQ_ID,
			WSM_CMD_START_TIMEOUT);

	if (ret < 0) {
		pr_debug("failed to sent: start request ID");
		goto nomem;
	}

out:
	wsm_cmd_unlock(priv);
	return ret;

nomem:
	wsm_cmd_unlock(priv);
	kfree(wf200_cmd);
	return -ENOMEM;
}

/*-----------------------------------------------------------------------
 *
 * wsm beacon transmit
 *
 */
int wsm_beacon_transmit(struct wfx_common *priv,
			const WsmHiBeaconTransmitReqBody_t *arg)
{
	int ret;
	const WsmHiBeaconTransmitReqBody_t *wf200_cmd;
	struct wsm_buf *wfx_arg = &priv->wsm_cmd_buf;

    wf200_cmd = kzalloc(sizeof(*wf200_cmd), GFP_KERNEL);

    if (!wf200_cmd) {
            ret = -ENOMEM;
            goto out;
    }

	wsm_cmd_lock(priv);

	wfx_cmd_data(wfx_arg, arg->EnableBeaconing ? 1 : 0);

	ret = wfx_cmd_send(priv,
			wfx_arg,
			NULL,
			WSM_HI_BEACON_TRANSMIT_REQ_ID,
			WSM_CMD_TIMEOUT);

	if (ret < 0) {
		pr_debug("failed to sent: beacon transmit request ID");
		goto nomem;
	}

out:
	wsm_cmd_unlock(priv);
	return ret;

nomem:
	wsm_cmd_unlock(priv);
	kfree(wf200_cmd);
	return -ENOMEM;
}

/*-----------------------------------------------------------------------
 *
 * wsm map link
 *
 */
int wsm_map_link(struct wfx_common *priv, const WsmHiMapLinkReqBody_t *arg)
{
	int ret;
	const WsmHiMapLinkReqBody_t *wf200_cmd;
	struct wsm_buf *wfx_arg = &priv->wsm_cmd_buf;
	u16 cmd = WSM_HI_MAP_LINK_REQ_ID | 0;

	pr_debug("[WSM] map_link id=%d, unmap=%d\n", arg->PeerStaId, arg->Flags);

    wf200_cmd = kzalloc(sizeof(*wf200_cmd), GFP_KERNEL);

    if (!wf200_cmd) {
            ret = -ENOMEM;
            goto out;
    }

	wsm_cmd_lock(priv);


	wfx_cmd(wfx_arg, arg->MacAddr, sizeof(arg->MacAddr));
	wfx_cmd_fl(wfx_arg, arg->Flags);
	wfx_cmd_fl(wfx_arg, arg->PeerStaId);

	ret = wfx_cmd_send(priv,
			wfx_arg,
			NULL,
			cmd,
			WSM_CMD_TIMEOUT);

	if (ret < 0) {
		pr_debug("failed to sent map link");
		goto nomem;
	}

out:
	wsm_cmd_unlock(priv);
	return ret;

nomem:
	wsm_cmd_unlock(priv);
	kfree(wf200_cmd);
	return -ENOMEM;
}

/*-----------------------------------------------------------------------
 *
 * wsm update ie
 *
 */
int wsm_update_ie(struct wfx_common *priv,
		  const struct wsm_update_ie *arg)
{
	int ret;
	const struct wsm_update_ie *wf200_cmd;
	struct wsm_buf *wfx_arg = &priv->wsm_cmd_buf;

    wf200_cmd = kzalloc(sizeof(*wf200_cmd), GFP_KERNEL);

    if (!wf200_cmd) {
            ret = -ENOMEM;
            goto out;
    }

	wsm_cmd_lock(priv);

	wfx_cmd(wfx_arg, &arg->Body.IeFlags, sizeof(arg->Body.IeFlags));
	wfx_cmd_len(wfx_arg, arg->Body.NumIEs);
	wfx_cmd(wfx_arg, arg->ies, arg->length);

	ret = wfx_cmd_send(priv,
			wfx_arg,
			NULL,
			WSM_HI_UPDATE_IE_REQ_ID,
			WSM_CMD_TIMEOUT);

	if (ret < 0) {
		pr_debug("failed to sent: uapdate ie request ID");
		goto nomem;
	}

out:
	wsm_cmd_unlock(priv);
	return ret;

nomem:
	wsm_cmd_unlock(priv);
	kfree(wf200_cmd);
	return -ENOMEM;
}

/*-----------------------------------------------------------------------
 *
 * wsm command send
 *
 * command send from wf200 wlan driver to firmware
 *
 */
static int wfx_cmd_send(struct wfx_common *priv,
			struct wsm_buf *buf,
			void *arg, u8 cmd, long tmo)
{
	size_t buf_len = buf->data - buf->begin;
	int ret;

#ifdef CONFIG_WF200_TESTMODE
	/* Add ID to testmode's buffer */
	wfx_tm_hif_buffer_add(cmd);
#endif /* CONFIG_WF200_TESTMODE */
	/* Don't bother if we're dead. */
	if (priv->bh_error) {
		ret = 0;
		goto done;
	}

	spin_lock(&priv->wsm_cmd.lock);
	while (!priv->wsm_cmd.done) {
		spin_unlock(&priv->wsm_cmd.lock);
		spin_lock(&priv->wsm_cmd.lock);
	}
	priv->wsm_cmd.done = 0;
	spin_unlock(&priv->wsm_cmd.lock);

	{
		int msg_id = cmd&0x3F;
		int msg_type = (cmd>>7)&0x1;

	    if (msg_id>=NB_REQ_MSG || msg_type!=0) {
	    	pr_debug("[WSM] >>> ERROR : wrong cmd id 0x%.4X\n", cmd);
	    }
	}

	buf_len += 4;

	((__le16 *)buf->begin)[0] = __cpu_to_le16(buf_len);
	((__le16 *)buf->begin)[1] = __cpu_to_le16(cmd);

	spin_lock(&priv->wsm_cmd.lock);
	BUG_ON(priv->wsm_cmd.ptr);
	priv->wsm_cmd.ptr = buf->begin;
	priv->wsm_cmd.len = buf_len;
	priv->wsm_cmd.arg = arg;
	priv->wsm_cmd.cmd = cmd;
	spin_unlock(&priv->wsm_cmd.lock);

	wfx_bh_wakeup(priv);

	if (-ETIMEDOUT == priv->scan.status){
		(void)wait_event_timeout(priv->wsm_cmd_wq,
						 priv->wsm_cmd.done, HZ);
		spin_lock(&priv->wsm_cmd.lock);
		priv->wsm_cmd.done = 1;
		priv->wsm_cmd.ptr = NULL;
		spin_unlock(&priv->wsm_cmd.lock);
	}

	/* Wait for command completion */
	ret = wait_event_timeout(priv->wsm_cmd_wq,
				 priv->wsm_cmd.done, tmo);

	if (!ret && !priv->wsm_cmd.done) {
		spin_lock(&priv->wsm_cmd.lock);
		priv->wsm_cmd.done = 1;
		priv->wsm_cmd.ptr = NULL;
		spin_unlock(&priv->wsm_cmd.lock);
		if (priv->bh_error) {
			/* Return ok to help system cleanup */
			ret = 0;
		} else {
			pr_err("CMD req (0x%02x) stuck in firmware, killing BH\n", priv->wsm_cmd.cmd);
			print_hex_dump_bytes("REQDUMP: ", DUMP_PREFIX_NONE,
					     buf->begin, buf_len);
			pr_err("Outstanding outgoing frames:  %d\n", priv->hw_bufs_used);
			atomic_add(1, &priv->bh_term);
			wake_up(&priv->bh_wq);
			ret = -ETIMEDOUT;
		}
	} else {
		spin_lock(&priv->wsm_cmd.lock);
		BUG_ON(!priv->wsm_cmd.done);
		ret = priv->wsm_cmd.ret;
		spin_unlock(&priv->wsm_cmd.lock);
	}
done:
	wsm_buf_reset(buf);
	return ret;
}

/*----------------------------WSM buffer---------------------------------*/
void wsm_buf_init(struct wsm_buf *buf)
{
	BUG_ON(buf->begin);
	buf->begin = kmalloc(FWLOAD_BLOCK_SIZE, GFP_KERNEL | GFP_DMA);
	buf->end = buf->begin ? &buf->begin[FWLOAD_BLOCK_SIZE] : buf->begin;
	wsm_buf_reset(buf);
}

/*-----------------------------------------------------------------------*/
void wsm_buf_deinit(struct wsm_buf *buf)
{
	kfree(buf->begin);
	buf->begin = buf->data = buf->end = NULL;
}

/*-----------------------------------------------------------------------*/
void wsm_buf_reset(struct wsm_buf *buf)
{
	if (buf->begin) {
		buf->data = &buf->begin[4];
		*(u32 *)buf->begin = 0;
	} else {
		buf->data = buf->begin;
	}
}

/*-----------------------------------------------------------------------*/
int wsm_buf_reserve(struct wsm_buf *buf, size_t extra_size)
{
	size_t pos = buf->data - buf->begin;
	size_t size = pos + extra_size;

	pr_debug("[WSM] wsm_buf_reserve\n");

	size = round_up(size, FWLOAD_BLOCK_SIZE);

	pr_debug("[WSM] size\n");

	buf->begin = krealloc(buf->begin, size, GFP_KERNEL | GFP_DMA);
	if (buf->begin) {
		pr_debug("[WSM] bug begin\n");
		buf->data = &buf->begin[pos];
		pr_debug("[WSM] bug data\n");
		buf->end = &buf->begin[size];
		pr_debug("[WSM] bug end\n");
		return 0;
	} else {
		buf->end = buf->data = buf->begin;
		return -ENOMEM;
	}
}


