/* SPDX-License-Identifier: GPL-2.0-only */
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

#include "wfx.h"
#include "wsm_tx.h"
#include "api_wsm_cmd.h"

static inline int wsm_set_output_power(struct wfx_dev *wdev,
				       int power_level,
				       int id)
{
	__le32 val = cpu_to_le32(power_level);

	return wsm_write_mib(wdev, WSM_MIB_ID_CURRENT_TX_POWER_LEVEL,
			     &val, sizeof(val), id);
}

static inline int wsm_set_beacon_wakeup_period(struct wfx_dev *wdev,
					       unsigned dtim_interval,
					       unsigned listen_interval,
					       int id)
{
	struct hif_mib_beacon_wake_up_period val = {
		.wakeup_period_min = dtim_interval,
		.receive_dtim = 0,
		.wakeup_period_max = cpu_to_le16(listen_interval),
	};

	if (dtim_interval > 0xFF || listen_interval > 0xFFFF)
		return -EINVAL;
	return wsm_write_mib(wdev, WSM_MIB_ID_BEACON_WAKEUP_PERIOD,
			     &val, sizeof(val), id);
}

static inline int wsm_set_rcpi_rssi_threshold(struct wfx_dev *wdev,
					      struct hif_mib_rcpi_rssi_threshold *arg,
					      int id)
{
	return wsm_write_mib(wdev, WSM_MIB_ID_RCPI_RSSI_THRESHOLD, arg,
			     sizeof(*arg), id);
}

static inline int wsm_get_counters_table(struct wfx_dev *wdev,
					 struct hif_mib_extended_count_table *arg,
					 int id)
{
	if (wfx_api_older_than(wdev, 1, 3)) {
		// struct hif_mib_extended_count_table is wider than struct hif_mib_count_table
		memset(arg, 0xFF, sizeof(*arg));
		return wsm_read_mib(wdev, WSM_MIB_ID_COUNTERS_TABLE,
				    arg, sizeof(struct hif_mib_count_table), id);
	} else {
		return wsm_read_mib(wdev, WSM_MIB_ID_EXTENDED_COUNTERS_TABLE,
				    arg, sizeof(struct hif_mib_extended_count_table), id);
	}
}

static inline int wsm_set_macaddr(struct wfx_dev *wdev, u8 *mac, int id)
{
	struct hif_mib_mac_address msg = { };

	if (mac)
		ether_addr_copy(msg.mac_addr, mac);
	return wsm_write_mib(wdev, WSM_MIB_ID_DOT11_MAC_ADDRESS, &msg, sizeof(msg), id);
}

static inline int wsm_set_rx_filter(struct wfx_dev *wdev, bool filter_bssid,
				    bool filter_probe_resp, int id)
{
	__le32 val = 0;

	if (filter_bssid)
		val |= cpu_to_le32(BIT(1));
	if (filter_probe_resp)
		val |= cpu_to_le32(BIT(3));
	return wsm_write_mib(wdev, WSM_MIB_ID_RX_FILTER, &val, sizeof(val), id);
}

static inline int wsm_set_beacon_filter_table(struct wfx_dev *wdev,
					      struct hif_mib_bcn_filter_table *ft,
					      int id)
{
	size_t buf_len = struct_size(ft, ie_table, ft->num_of_info_elmts);

	cpu_to_le32s(&ft->num_of_info_elmts);
	return wsm_write_mib(wdev, WSM_MIB_ID_BEACON_FILTER_TABLE, ft,
			     buf_len, id);
}

static inline int wsm_beacon_filter_control(struct wfx_dev *wdev, int enable,
					    int beacon_count, int id)
{
	struct hif_mib_bcn_filter_enable arg = {
	    .enable = cpu_to_le32(enable),
	    .bcn_count = cpu_to_le32(beacon_count),
	};
	return wsm_write_mib(wdev, WSM_MIB_ID_BEACON_FILTER_ENABLE, &arg,
			     sizeof(arg), id);
}

static inline int wsm_set_operational_mode(struct wfx_dev *wdev, enum hif_op_power_mode mode)
{
	struct hif_mib_gl_operational_power_mode val = {
		.power_mode = mode,
		.wup_ind_activation = 1,
	};

	return wsm_write_mib(wdev, WSM_MIB_ID_GL_OPERATIONAL_POWER_MODE,
			     &val, sizeof(val), -1);
}

static inline int wsm_set_template_frame(struct wfx_dev *wdev,
					 struct hif_mib_template_frame *arg,
					 int id)
{
	return wsm_write_mib(wdev, WSM_MIB_ID_TEMPLATE_FRAME, arg,
			     sizeof(*arg), id);
}

static inline int wsm_set_mfp(struct wfx_dev *wdev, bool capable, bool required,
			      int id)
{
	int val = 0;

	WARN_ON(required && !capable);
	if (capable)
		val = BIT(0) | BIT(2);
	if (!required)
		val |= BIT(1);
	cpu_to_le32s(&val);
	return wsm_write_mib(wdev, WSM_MIB_ID_PROTECTED_MGMT_POLICY, &val,
			     sizeof(val), id);
}

static inline int wsm_set_block_ack_policy(struct wfx_dev *wdev,
					   u8 tx_tid_policy, u8 rx_tid_policy,
					   int id)
{
	struct hif_mib_block_ack_policy val = {
		.block_ack_tx_tid_policy = tx_tid_policy,
		.block_ack_rx_tid_policy = rx_tid_policy,
	};

	return wsm_write_mib(wdev, WSM_MIB_ID_BLOCK_ACK_POLICY, &val,
			     sizeof(val), id);
}

static inline int wsm_set_association_mode(struct wfx_dev *wdev,
					   struct hif_mib_set_association_mode *arg,
					   int id)
{
	return wsm_write_mib(wdev, WSM_MIB_ID_SET_ASSOCIATION_MODE, arg,
			     sizeof(*arg), id);
}

static inline int wsm_set_tx_rate_retry_policy(struct wfx_dev *wdev,
					       struct hif_mib_set_tx_rate_retry_policy *arg,
					       int id)
{
	size_t size = struct_size(arg, tx_rate_retry_policy, arg->num_tx_rate_policies);

	return wsm_write_mib(wdev, WSM_MIB_ID_SET_TX_RATE_RETRY_POLICY, arg,
			     size, id);
}

static inline int wsm_set_mac_addr_condition(struct wfx_dev *wdev,
					     struct hif_mib_mac_addr_data_frame_condition *arg,
					     int id)
{
	return wsm_write_mib(wdev, WSM_MIB_ID_MAC_ADDR_DATAFRAME_CONDITION, arg,
			     sizeof(*arg), id);
}

static inline int wsm_set_uc_mc_bc_condition(struct wfx_dev *wdev,
					     struct hif_mib_uc_mc_bc_data_frame_condition *arg,
					     int id)
{
	return wsm_write_mib(wdev, WSM_MIB_ID_UC_MC_BC_DATAFRAME_CONDITION, arg,
			     sizeof(*arg), id);
}

static inline int wsm_set_config_data_filter(struct wfx_dev *wdev,
					     struct hif_mib_config_data_filter *arg,
					     int id)
{
	return wsm_write_mib(wdev, WSM_MIB_ID_CONFIG_DATA_FILTER, arg,
			     sizeof(*arg), id);
}

static inline int wsm_set_data_filtering(struct wfx_dev *wdev,
					 struct hif_mib_set_data_filtering *arg,
					 int id)
{
	return wsm_write_mib(wdev, WSM_MIB_ID_SET_DATA_FILTERING, arg,
			     sizeof(*arg), id);
}

static inline int wsm_keep_alive_period(struct wfx_dev *wdev,
					int period,
					int id)
{
	struct hif_mib_keep_alive_period arg = {
		.keep_alive_period = cpu_to_le16(period),
	};

	return wsm_write_mib(wdev, WSM_MIB_ID_KEEP_ALIVE_PERIOD,
			     &arg, sizeof(arg), id);
};

static inline int wsm_set_arp_ipv4_filter(struct wfx_dev *wdev,
					  struct hif_mib_arp_ip_addr_table *fp,
					  int id)
{
	return wsm_write_mib(wdev, WSM_MIB_ID_ARP_IP_ADDRESSES_TABLE,
			     fp, sizeof(*fp), id);
}

static inline int wsm_use_multi_tx_conf(struct wfx_dev *wdev,
					bool enabled)
{
	__le32 arg = enabled ? cpu_to_le32(1) : 0;

	return wsm_write_mib(wdev, WSM_MIB_ID_GL_SET_MULTI_MSG,
			     &arg, sizeof(arg), -1);
}

static inline int wsm_set_uapsd_info(struct wfx_dev *wdev,
				     struct hif_mib_set_uapsd_information *arg,
				     int id)
{
	return wsm_write_mib(wdev, WSM_MIB_ID_SET_UAPSD_INFORMATION,
			     arg, sizeof(*arg), id);
}

static inline int wsm_erp_use_protection(struct wfx_dev *wdev, bool enable, int id)
{
	__le32 arg = enable ? cpu_to_le32(1) : 0;

	return wsm_write_mib(wdev, WSM_MIB_ID_NON_ERP_PROTECTION,
			     &arg, sizeof(arg), id);
}

static inline int wsm_slot_time(struct wfx_dev *wdev, int val, int id)
{
	__le32 arg = cpu_to_le32(val);

	return wsm_write_mib(wdev, WSM_MIB_ID_SLOT_TIME,
			     &arg, sizeof(arg), id);
}

static inline int wsm_dual_cts_protection(struct wfx_dev *wdev, bool val, int id)
{
	struct hif_mib_set_ht_protection arg = {
		.dual_cts_prot = val,
	};

	return wsm_write_mib(wdev, WSM_MIB_ID_SET_HT_PROTECTION,
			     &arg, sizeof(arg), id);
}

static inline int wsm_wep_default_key_id(struct wfx_dev *wdev, int val, int id)
{
	__le32 arg = cpu_to_le32(val);

	return wsm_write_mib(wdev, WSM_MIB_ID_DOT11_WEP_DEFAULT_KEY_ID,
			     &arg, sizeof(arg), id);
}

static inline int wsm_rts_threshold(struct wfx_dev *wdev, int val, int id)
{
	__le32 arg = cpu_to_le32(val > 0 ? val : 0xFFFF);

	return wsm_write_mib(wdev, WSM_MIB_ID_DOT11_RTS_THRESHOLD,
			     &arg, sizeof(arg), id);
}

#endif /* WFX_WSM_MIB_H */
