/*
 * WSM host interface (HI) interface for Silicon Labs WFX mac80211 drivers
 *
 * Copyright (c) 2017, Silicon Laboratories, Inc.
 * Copyright (c) 2010, ST-Ericsson
 * Copyright (C) 2010, ST-Ericsson SA
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

#ifndef WFX_WSM_H
#define WFX_WSM_H

#include <linux/spinlock.h>
#include <linux/etherdevice.h>

#include "wfx_api.h"

#define WSM_DUAL_CTS_PROT_ENB		BIT(0)
#define WSM_NON_GREENFIELD_STA_PRESENT	BIT(1)

#define WSM_PHY_BAND_2_4G		(0)
#define WSM_PHY_BAND_5G			(1)

#define WSM_KEY_MAX_INDEX		(16)
#define WSM_MAX_ARP_IP_ADDRTABLE_ENTRIES	2
/* Start modes */
#define WSM_START_MODE_AP		(0)
#define WSM_START_MODE_P2P_GO		(1)
#define WSM_START_MODE_P2P_DEV		(2)

#define WSM_TX_SEQ(seq)			((seq & HI_MSG_SEQ_RANGE) << 3)
#define WSM_CMD_LAST_CHANCE_TIMEOUT	(HZ * 3 / 2)
#define WSM_TX_EXTRA_HEADROOM		(28) // sizeof(hdr) + sizeof(tx req) + sizeof(alignment)
#define WSM_RX_EXTRA_HEADROOM		(16) // sizeof(hdr) + sizeof(rx req)
#define TXOP_UNIT			32

struct wfx_dev;
struct wfx_vif;

struct wsm_scan {
	WsmHiStartScanReqBody_t scan_req;
	WsmHiSsidDef_t		*ssids;
	u8			*ch;
};

struct wfx_wsm_event {
	struct list_head link;
	WsmHiEventIndBody_t	evt;
};

struct wsm_edca_params {
	/* NOTE: index is a linux queue id. */
	WsmHiEdcaQueueParamsReqBody_t	params[4];
	bool				uapsd_enable[4];
};

struct wsm_rx_filter {
	bool	bssid;
	bool	probeResponder;
	bool    keepAlive;
};

struct wsm_protected_mgmt_policy {
	bool	protectedMgmtEnable;
	bool	unprotectedMgmtFramesAllowed;
	bool	encryptionForAuthFrame;
};

struct wfx_grp_addr_table {
	bool enable;
	int num_addresses;
	u8 address_list[8][ETH_ALEN];
};

struct wsm_cmd {
	struct mutex      lock;
	struct completion ready;
	struct completion done;
	bool              async;
	HiMsgHdr_t        *buf_send;
	void              *buf_recv;
	size_t            len_recv;
	int               ret;
};

void init_wsm_cmd(struct wsm_cmd *wsm_cmd);
int wsm_configuration(struct wfx_dev *wdev, const u8 *conf, size_t len);
int wsm_reset(struct wfx_dev *wdev, bool reset_stat, int Id);
int wsm_read_mib(struct wfx_dev *wdev, u16 mib_id, void *buf, size_t buf_size);
int wsm_write_mib(struct wfx_dev *wdev, u16 mib_id, void *buf, size_t buf_size, int Id);
int wsm_scan(struct wfx_dev *wdev, const struct wsm_scan *arg, int Id);
int wsm_stop_scan(struct wfx_dev *wdev, int Id);
int wsm_join(struct wfx_dev *wdev, const WsmHiJoinReqBody_t *arg, int Id);
int wsm_set_pm(struct wfx_dev *wdev, const WsmHiSetPmModeReqBody_t *arg, int Id);
int wsm_set_bss_params(struct wfx_dev *wdev, const WsmHiSetBssParamsReqBody_t *arg, int Id);
int wsm_add_key(struct wfx_dev *wdev, const WsmHiAddKeyReqBody_t *arg, int Id);
int wsm_remove_key(struct wfx_dev *wdev, int idx, int Id);
int wsm_set_edca_queue_params(struct wfx_dev *wdev, const WsmHiEdcaQueueParamsReqBody_t *arg, int Id);
int wsm_start(struct wfx_dev *wdev, const WsmHiStartReqBody_t *arg, int Id);
int wsm_beacon_transmit(struct wfx_dev *wdev, bool enable, int Id);
int wsm_update_ie(struct wfx_dev *wdev, const WsmHiIeFlags_t *target_frame, const u8 *ies, size_t ies_len, int Id);

int wsm_map_link(struct wfx_dev *wdev, u8 *mac_addr, int flags, int sta_id, int Id);
int wfx_unmap_link(struct wfx_vif *wvif, int link_id);
int wsm_set_probe_responder(struct wfx_vif *wvif, bool enable);

int wsm_handle_rx(struct wfx_dev *wdev, HiMsgHdr_t *wsm, struct sk_buff **skb_p);
int wsm_get_tx(struct wfx_dev *wdev, u8 **data, size_t *tx_len, int *burst);

void wsm_lock_tx(struct wfx_dev *wdev);
void wsm_lock_tx_async(struct wfx_dev *wdev);
void wsm_unlock_tx(struct wfx_dev *wdev);

bool wsm_flush_tx(struct wfx_dev *wdev);

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
		dtim_interval, 0, cpu_to_le16(listen_interval)
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
					 WsmHiMibCountTable_t *arg)
{
	return wsm_read_mib(wdev, WSM_MIB_ID_COUNTERS_TABLE,
			    arg, sizeof(*arg));
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
	if (arg->keepAlive)
		val |= cpu_to_le32(BIT(4));
	return wsm_write_mib(wdev, WSM_MIB_ID_RX_FILTER, &val, sizeof(val), Id);
}

static inline int wsm_set_beacon_filter_table(struct wfx_dev *wdev,
					      WsmHiMibBcnFilterTable_t *ft,
					      int Id)
{
	return wsm_write_mib(wdev, WSM_MIB_ID_BEACON_FILTER_TABLE, ft,
			     sizeof(*ft), Id);
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
	uint32_t val = mode;

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
	size_t size = 4 + arg->NumTxRatePolicy *
		      sizeof(WsmHiMibTxRateRetryPolicy_t);

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

#endif /* WFX_HWIO_H */
