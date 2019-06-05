// SPDX-License-Identifier: GPL-2.0-only
/*
 * Implementation of host-to-chip MIBs of WFxxx Split Mac (WSM) API.
 *
 * Copyright (c) 2017-2019, Silicon Laboratories, Inc.
 * Copyright (c) 2010, ST-Ericsson
 * Copyright (C) 2010, ST-Ericsson SA
 */
#ifndef WFX_WSM_MIB_H
#define WFX_WSM_MIB_H

#include <linux/etherdevice.h>

#include "wsm_tx.h"
#include "wsm_cmd_api.h"

struct wsm_rx_filter {
	bool	bssid;
	bool	probeResponder;
};

struct wsm_protected_mgmt_policy {
	bool	protectedMgmtEnable;
	bool	unprotectedMgmtFramesAllowed;
	bool	encryptionForAuthFrame;
};

static inline int wsm_set_output_power(struct wfx_dev *wdev,
				       int power_level,
				       int Id)
{
	__le32 val = cpu_to_le32(power_level);

	return wsm_write_mib(wdev, WSM_MIB_ID_CURRENT_TX_POWER_LEVEL,
			     &val, sizeof(val), Id);
}

static inline int wsm_set_beacon_wakeup_period(struct wfx_dev *wdev,
					       unsigned dtim_interval,
					       unsigned listen_interval,
					       int Id)
{
	WsmHiMibBeaconWakeUpPeriod_t val = {
		.WakeupPeriodMin = dtim_interval,
		.ReceiveDTIM = 0,
		.WakeupPeriodMax = cpu_to_le16(listen_interval) ,
	};

	if (dtim_interval > 0xFF || listen_interval > 0xFFFF)
		return -EINVAL;
	return wsm_write_mib(wdev, WSM_MIB_ID_BEACON_WAKEUP_PERIOD,
			     &val, sizeof(val), Id);
}

static inline int wsm_set_rcpi_rssi_threshold(struct wfx_dev *wdev,
					      WsmHiMibRcpiRssiThreshold_t *arg,
					      int Id)
{
	return wsm_write_mib(wdev, WSM_MIB_ID_RCPI_RSSI_THRESHOLD, arg,
			     sizeof(*arg), Id);
}

static inline int wsm_get_counters_table(struct wfx_dev *wdev,
					 WsmHiMibExtendedCountTable_t *arg,
					 int Id)
{
	if (wfx_api_older_than(wdev, 1, 3)) {
		// WsmHiMibExtendedCountTable_t is wider than WsmHiMibCountTable_t
		memset(arg, 0xFF, sizeof(*arg));
		return wsm_read_mib(wdev, WSM_MIB_ID_COUNTERS_TABLE,
				    arg, sizeof(WsmHiMibCountTable_t), Id);
	} else {
		return wsm_read_mib(wdev, WSM_MIB_ID_EXTENDED_COUNTERS_TABLE,
				    arg, sizeof(WsmHiMibExtendedCountTable_t), Id);
	}
}

static inline int wsm_set_macaddr(struct wfx_dev *wdev, u8 *mac, int Id)
{
	WsmHiMibMacAddress_t msg = { };

	if (mac)
		ether_addr_copy(msg.MacAddr, mac);
	return wsm_write_mib(wdev, WSM_MIB_ID_DOT11_MAC_ADDRESS, &msg, sizeof(msg), Id);
}

static inline int wsm_set_rx_filter(struct wfx_dev *wdev,
				    const struct wsm_rx_filter *arg,
				    int Id)
{
	__le32 val = 0;

	if (arg->bssid)
		val |= cpu_to_le32(BIT(1));
	if (arg->probeResponder)
		val |= cpu_to_le32(BIT(3));
	return wsm_write_mib(wdev, WSM_MIB_ID_RX_FILTER, &val, sizeof(val), Id);
}

static inline int wsm_set_beacon_filter_table(struct wfx_dev *wdev,
					      WsmHiMibBcnFilterTable_t *ft,
					      int Id)
{
	size_t buf_len = sizeof(WsmHiMibBcnFilterTable_t)
		         + ft->NumOfInfoElmts * sizeof(WsmHiIeTableEntry_t);

	cpu_to_le32s(&ft->NumOfInfoElmts);
	return wsm_write_mib(wdev, WSM_MIB_ID_BEACON_FILTER_TABLE, ft,
			     buf_len, Id);
}

static inline int wsm_beacon_filter_control(struct wfx_dev *wdev, int enable,
					    int beacon_count, int Id)
{
	WsmHiMibBcnFilterEnable_t arg = {
	    .Enable = cpu_to_le32(enable),
	    .BcnCount = cpu_to_le32(beacon_count),
	};
	return wsm_write_mib(wdev, WSM_MIB_ID_BEACON_FILTER_ENABLE, &arg,
			     sizeof(arg), Id);
}

static inline int wsm_set_operational_mode(struct wfx_dev *wdev, enum WsmOpPowerMode_e mode)
{
	WsmHiMibGlOperationalPowerMode_t val = {
		.PowerMode = mode,
		.WupIndActivation = 1,
	};

	return wsm_write_mib(wdev, WSM_MIB_ID_GL_OPERATIONAL_POWER_MODE,
			     &val, sizeof(val), -1);
}

static inline int wsm_set_template_frame(struct wfx_dev *wdev,
					 WsmHiMibTemplateFrame_t *arg,
					 int Id)
{
	return wsm_write_mib(wdev, WSM_MIB_ID_TEMPLATE_FRAME, arg,
			     sizeof(*arg), Id);
}

static inline int wsm_set_protected_mgmt_policy(struct wfx_dev *wdev,
						struct wsm_protected_mgmt_policy *arg,
						int Id)
{
	__le32 val = 0;

	if (arg->protectedMgmtEnable)
		val |= cpu_to_le32(BIT(0));
	if (arg->unprotectedMgmtFramesAllowed)
		val |= cpu_to_le32(BIT(1));
	if (arg->encryptionForAuthFrame)
		val |= cpu_to_le32(BIT(2));
	return wsm_write_mib(wdev, WSM_MIB_ID_PROTECTED_MGMT_POLICY, &val,
			     sizeof(val), Id);
}

static inline int wsm_set_block_ack_policy(struct wfx_dev *wdev,
					   u8 tx_tid_policy, u8 rx_tid_policy,
					   int Id)
{
	WsmHiMibBlockAckPolicy_t val = {
		.BlockAckTxTidPolicy = tx_tid_policy,
		.BlockAckRxTidPolicy = rx_tid_policy,
	};

	return wsm_write_mib(wdev, WSM_MIB_ID_BLOCK_ACK_POLICY, &val,
			     sizeof(val), Id);
}

static inline int wsm_set_association_mode(struct wfx_dev *wdev,
					   WsmHiMibSetAssociationMode_t *arg,
					   int Id)
{
	return wsm_write_mib(wdev, WSM_MIB_ID_SET_ASSOCIATION_MODE, arg,
			     sizeof(*arg), Id);
}

static inline int wsm_set_tx_rate_retry_policy(struct wfx_dev *wdev,
					       WsmHiMibSetTxRateRetryPolicy_t *arg,
					       int Id)
{
	size_t size = sizeof(WsmHiMibSetTxRateRetryPolicy_t) +
		      sizeof(WsmHiMibTxRateRetryPolicy_t) * arg->NumTxRatePolicies;

	return wsm_write_mib(wdev, WSM_MIB_ID_SET_TX_RATE_RETRY_POLICY, arg,
			     size, Id);
}

static inline int wsm_set_mac_addr_condition(struct wfx_dev *wdev,
                        WsmHiMibMacAddrDataFrameCondition_t *arg,
                        int Id)
{
    return wsm_write_mib(wdev, WSM_MIB_ID_MAC_ADDR_DATAFRAME_CONDITION,
                 arg, sizeof(*arg), Id);
}

static inline int wsm_set_uc_mc_bc_condition(struct wfx_dev *wdev,
                      WsmHiMibUcMcBcDataFrameCondition_t *arg,
                      int Id)
{
    return wsm_write_mib(wdev, WSM_MIB_ID_UC_MC_BC_DATAFRAME_CONDITION,
                 arg, sizeof(*arg), Id);
}

static inline int wsm_set_config_data_filter(struct wfx_dev *wdev,
                      WsmHiMibConfigDataFilter_t *arg,
                      int Id)
{
    return wsm_write_mib(wdev, WSM_MIB_ID_CONFIG_DATA_FILTER,
                 arg, sizeof(*arg), Id);
}

static inline int wsm_set_data_filtering(struct wfx_dev *wdev,
                      WsmHiMibSetDataFiltering_t *arg,
                      int Id)
{
    return wsm_write_mib(wdev, WSM_MIB_ID_SET_DATA_FILTERING,
                 arg, sizeof(*arg), Id);
}

static inline int wsm_keep_alive_period(struct wfx_dev *wdev,
					int period,
					int Id)
{
	WsmHiMibKeepAlivePeriod_t arg = {
		.KeepAlivePeriod = cpu_to_le16(period),
	};

	return wsm_write_mib(wdev, WSM_MIB_ID_KEEP_ALIVE_PERIOD,
			     &arg, sizeof(arg), Id);
};

static inline int wsm_set_arp_ipv4_filter(struct wfx_dev *wdev,
					  WsmHiMibArpIpAddrTable_t *fp,
					  int Id)
{
	return wsm_write_mib(wdev, WSM_MIB_ID_ARP_IP_ADDRESSES_TABLE,
			     fp, sizeof(*fp), Id);
}

static inline int wsm_use_multi_tx_conf(struct wfx_dev *wdev,
					bool enabled)
{
	__le32 arg = enabled ? cpu_to_le32(1) : 0;

	return wsm_write_mib(wdev, WSM_MIB_ID_GL_SET_MULTI_MSG,
			     &arg, sizeof(arg), -1);
}

static inline int wsm_set_uapsd_info(struct wfx_dev *wdev,
				     WsmHiMibSetUapsdInformation_t *arg,
				     int Id)
{
	return wsm_write_mib(wdev, WSM_MIB_ID_SET_UAPSD_INFORMATION,
			     arg, sizeof(*arg), Id);
}

static inline int wsm_erp_use_protection(struct wfx_dev *wdev, bool enable, int Id)
{
	__le32 arg = enable ? cpu_to_le32(1) : 0;

	return wsm_write_mib(wdev, WSM_MIB_ID_NON_ERP_PROTECTION,
			     &arg, sizeof(arg), Id);
}

static inline int wsm_slot_time(struct wfx_dev *wdev, int val, int Id)
{
	__le32 arg = cpu_to_le32(val);

	return wsm_write_mib(wdev, WSM_MIB_ID_SLOT_TIME,
			     &arg, sizeof(arg), Id);
}

static inline int wsm_ht_protection(struct wfx_dev *wdev, int val, int Id)
{
	__le32 arg = cpu_to_le32(val);

	return wsm_write_mib(wdev, WSM_MIB_ID_SET_HT_PROTECTION,
			     &arg, sizeof(arg), Id);
}

static inline int wsm_wep_default_key_id(struct wfx_dev *wdev, int val, int Id)
{
	__le32 arg = cpu_to_le32(val);

	return wsm_write_mib(wdev, WSM_MIB_ID_DOT11_WEP_DEFAULT_KEY_ID,
			     &arg, sizeof(arg), Id);
}

static inline int wsm_rts_threshold(struct wfx_dev *wdev, int val, int Id)
{
	__le32 arg = cpu_to_le32(val > 0 ? val : 0);

	return wsm_write_mib(wdev, WSM_MIB_ID_DOT11_RTS_THRESHOLD,
			     &arg, sizeof(arg), Id);
}

#endif /* WFX_WSM_MIB_H */
