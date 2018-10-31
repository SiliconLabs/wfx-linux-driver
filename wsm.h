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

#define WSM_DUAL_CTS_PROT_ENB           BIT(0)
#define WSM_NON_GREENFIELD_STA_PRESENT  BIT(1)
#define WSM_HT_PROT_MODE__NO_PROT       (0 << 2)
#define WSM_HT_PROT_MODE__NON_MEMBER    (1 << 2)
#define WSM_HT_PROT_MODE__20_MHZ        (2 << 2)
#define WSM_HT_PROT_MODE__NON_HT_MIXED  (3 << 2)
#define WSM_LSIG_TXOP_PROT_FULL         BIT4
#define WSM_LARGE_L_LENGTH_PROT         BIT5

/*FOR WFX COMMANDS SEND/RECEIVE/CONFIRM*/
#define WSM_CMD_TIMEOUT         (2 * HZ)        /* With respect to interrupt loss */
#define WSM_CMD_JOIN_TIMEOUT    (7 * HZ)        /* Join timeout is 5 sec. in FW   */
#define WSM_CMD_START_TIMEOUT   (7 * HZ)
#define WSM_CMD_RESET_TIMEOUT   (3 * HZ)        /* 2 sec. timeout was observed.   */
#define WSM_CMD_MAX_TIMEOUT     (3 * HZ)
#define NB_REQ_MSG   33
#define NB_INDIC_MSG 16

#define wsm_cmd_lock(__priv)   mutex_lock(&((__priv)->wsm_cmd_mux))
#define wsm_cmd_unlock(__priv) mutex_unlock(&((__priv)->wsm_cmd_mux))

/* Bands */
/* Radio band 2.412 -2.484 GHz. */
#define WSM_PHY_BAND_2_4G		(0)
/* Radio band 4.9375-5.8250 GHz. */
#define WSM_PHY_BAND_5G			(1)
/* Transmit rates */
/* 1   Mbps            ERP-DSSS */
#define WSM_TRANSMIT_RATE_1		(0)
/* 2   Mbps            ERP-DSSS */
#define WSM_TRANSMIT_RATE_2		(1)
/* 5.5 Mbps            ERP-CCK */
#define WSM_TRANSMIT_RATE_5		(2)
/* 11  Mbps            ERP-CCK */
#define WSM_TRANSMIT_RATE_11		(3)
/* 6   Mbps   (3 Mbps) ERP-OFDM, BPSK coding rate 1/2 */
#define WSM_TRANSMIT_RATE_6		(6)
/* 9   Mbps (4.5 Mbps) ERP-OFDM, BPSK coding rate 3/4 */
#define WSM_TRANSMIT_RATE_9		(7)
/* 12  Mbps  (6 Mbps)  ERP-OFDM, QPSK coding rate 1/2 */
#define WSM_TRANSMIT_RATE_12		(8)
/* 18  Mbps  (9 Mbps)  ERP-OFDM, QPSK coding rate 3/4 */
#define WSM_TRANSMIT_RATE_18		(9)
/* 24  Mbps (12 Mbps)  ERP-OFDM, 16QAM coding rate 1/2 */
#define WSM_TRANSMIT_RATE_24		(10)
/* 36  Mbps (18 Mbps)  ERP-OFDM, 16QAM coding rate 3/4 */
#define WSM_TRANSMIT_RATE_36		(11)
/* 48  Mbps (24 Mbps)  ERP-OFDM, 64QAM coding rate 1/2 */
#define WSM_TRANSMIT_RATE_48		(12)
/* 54  Mbps (27 Mbps)  ERP-OFDM, 64QAM coding rate 3/4 */
#define WSM_TRANSMIT_RATE_54		(13)
/* 6.5 Mbps            HT-OFDM, BPSK coding rate 1/2 */
#define WSM_TRANSMIT_RATE_HT_6		(14)
/* 13  Mbps            HT-OFDM, QPSK coding rate 1/2 */
#define WSM_TRANSMIT_RATE_HT_13		(15)
/* 19.5 Mbps           HT-OFDM, QPSK coding rate 3/4 */
#define WSM_TRANSMIT_RATE_HT_19		(16)
/* 26  Mbps            HT-OFDM, 16QAM coding rate 1/2 */
#define WSM_TRANSMIT_RATE_HT_26		(17)
/* 39  Mbps            HT-OFDM, 16QAM coding rate 3/4 */
#define WSM_TRANSMIT_RATE_HT_39		(18)
/* 52  Mbps            HT-OFDM, 64QAM coding rate 2/3 */
#define WSM_TRANSMIT_RATE_HT_52		(19)
/* 58.5 Mbps           HT-OFDM, 64QAM coding rate 3/4 */
#define WSM_TRANSMIT_RATE_HT_58		(20)
/* 65  Mbps            HT-OFDM, 64QAM coding rate 5/6 */
#define WSM_TRANSMIT_RATE_HT_65		(21)
/* Scan constraints */
/* Maximum number of channels to be scanned. */
#define WSM_SCAN_MAX_NUM_OF_CHANNELS	(48)
/* The maximum number of SSIDs that the device can scan for. */
#define WSM_SCAN_MAX_NUM_OF_SSIDS	(2)
/* EPTA prioirty flags for BT Coex */
/* default epta priority */
#define WSM_EPTA_PRIORITY_DEFAULT	4
/* use for normal data */
#define WSM_EPTA_PRIORITY_DATA		4
/* use for connect/disconnect/roaming*/
#define WSM_EPTA_PRIORITY_MGT		5
/* use for action frames */
#define WSM_EPTA_PRIORITY_ACTION	5
/* use for AC_VI data */
#define WSM_EPTA_PRIORITY_VIDEO		5
/* use for AC_VO data */
#define WSM_EPTA_PRIORITY_VOICE		6
/* use for EAPOL exchange */
#define WSM_EPTA_PRIORITY_EAPOL		7
/* Key indexes */
#define WSM_KEY_MAX_INDEX             (16)
/* ACK policy */
#define WSM_ACK_POLICY_NORMAL		(0)
#define WSM_ACK_POLICY_NO_ACK		(1)
/* Start modes */
#define WSM_START_MODE_AP		(0)	/* Mini AP */
#define WSM_START_MODE_P2P_GO		(1)	/* P2P GO */
#define WSM_START_MODE_P2P_DEV		(2)	/* P2P device */
#define WSM_MAX_ARP_IP_ADDRTABLE_ENTRIES	1
#define WSM_FILTER_PORT_TYPE_DST	(0)
#define WSM_FILTER_PORT_TYPE_SRC	(1)
/* #define WSM_TX_SEQ_MAX               (7) equivalent to HI_MSG_SEQ_RANGE */
#define WSM_TX_SEQ(seq)			\
	((seq & HI_MSG_SEQ_RANGE) << 3)         /* seq location in uint8_t MsgInfo */
/* Replaced with interface_id in new msg header*/
#define WSM_TX_LINK_ID_MAX        (0x03)        /*max value but used as a MASK*/
#define WSM_TX_LINK_ID(link_id)		\
	((link_id & WSM_TX_LINK_ID_MAX) << 1)
#define MAX_BEACON_SKIP_TIME_MS 1000
#define WSM_CMD_LAST_CHANCE_TIMEOUT (HZ * 3 / 2)
/* = sizeof(generic hi hdr) + sizeof(wsm hdr) + sizeof(alignment) */
#define WSM_TX_EXTRA_HEADROOM (28)
/* = sizeof(generic hi hdr) + sizeof(wsm hdr) */
#define WSM_RX_EXTRA_HEADROOM (16)
#define TXOP_UNIT 32

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

struct wsm_tx_queue_params {
	/* NOTE: index is a linux queue id. */
	WsmHiTxQueueParamsReqBody_t params[4];
};

struct wsm_edca_params {
	/* NOTE: index is a linux queue id. */
	WsmHiEdcaParamsReqBody_t	params;
	bool				uapsd_enable[4];
};

struct wsm_update_ie {
	WsmHiUpdateIeReqBody_t	Body;
	u8			*ies;
	size_t			length;
};

struct wsm_mib_counters_table {
	__le32	plcp_errors;
	__le32	fcs_errors;
	__le32	tx_packets;
	__le32	rx_packets;
	__le32	rx_packet_errors;
	__le32	rx_decryption_failures;
	__le32	rx_mic_failures;
	__le32	rx_no_key_failures;
	__le32	tx_multicast_frames;
	__le32	tx_frames_success;
	__le32	tx_frame_failures;
	__le32	tx_frames_retried;
	__le32	tx_frames_multi_retried;
	__le32	rx_frame_duplicates;
	__le32	rts_success;
	__le32	rts_failures;
	__le32	ack_failures;
	__le32	rx_multicast_frames;
	__le32	rx_frames_success;
	__le32	rx_cmac_icv_errors;
	__le32	rx_cmac_replays;
	__le32	rx_mgmt_ccmp_replays;
} __packed;

struct wsm_rx_filter {
	bool	promiscuous;
	bool	bssid;
	bool	fcs;
	bool	probeResponder;
};

struct wsm_operational_mode {
	WsmOpPowerMode_t	power_mode;
	int			disable_more_flag_usage;
	int			perform_ant_diversity;
};

struct wsm_protected_mgmt_policy {
	bool	protectedMgmtEnable;
	bool	unprotectedMgmtFramesAllowed;
	bool	encryptionForAuthFrame;
};

struct wsm_cmd {
	spinlock_t	lock; /* Protect structure from multiple access */
	int		done;
	u8		*ptr;
	size_t		len;
	void		*arg;
	int		ret;
	u8		cmd;
};

struct wsm_buf {
	u8	*begin;
	u8	*data;
	u8	*end;
};


int wsm_buf_reserve(struct wsm_buf *buf, size_t extra_size);

void wsm_buf_reset(struct wsm_buf *buf);

int wsm_configuration(struct wfx_dev *wdev, const u8 *conf, size_t len);
int wsm_reset(struct wfx_dev *wdev, const WsmHiResetFlags_t *arg);
int wsm_read_mib(struct wfx_dev *wdev, u16 mib_id, void *buf, size_t buf_size);
int wsm_write_mib(struct wfx_dev *wdev, u16 mib_id, void *buf, size_t buf_size);
int wsm_scan(struct wfx_dev *wdev, const struct wsm_scan *arg);
int wsm_stop_scan(struct wfx_dev *wdev);
int wsm_join(struct wfx_dev *wdev, WsmHiJoinReqBody_t *arg);
int wsm_set_pm(struct wfx_dev *wdev, const WsmHiSetPmModeReqBody_t *arg);
int wsm_set_bss_params(struct wfx_dev *wdev, const WsmHiSetBssParamsReqBody_t *arg);
int wsm_add_key(struct wfx_dev *wdev, const WsmHiAddKeyReqBody_t *arg);
int wsm_remove_key(struct wfx_dev *wdev, const WsmHiRemoveKeyReqBody_t *arg);
int wsm_set_tx_queue_params(struct wfx_dev *wdev, const WsmHiTxQueueParamsReqBody_t *arg, u8 id);
int wsm_set_edca_params(struct wfx_dev *wdev, const struct wsm_edca_params *arg);
int wsm_start(struct wfx_dev *wdev, const WsmHiStartReqBody_t *arg);
int wsm_beacon_transmit(struct wfx_dev *wdev, const WsmHiBeaconTransmitReqBody_t *arg);
int wsm_update_ie(struct wfx_dev *wdev, const struct wsm_update_ie *arg);

int wsm_map_link(struct wfx_dev *wdev, const WsmHiMapLinkReqBody_t *arg);
int wfx_unmap_link(struct wfx_vif *wvif, int link_id);
int wsm_set_probe_responder(struct wfx_vif *wvif, bool enable);

int wsm_handle_exception(struct wfx_dev *wdev, u8 *data, size_t len);
int wsm_handle_rx(struct wfx_dev *wdev, HiMsgHdr_t *wsm, struct sk_buff **skb_p);
int wsm_get_tx(struct wfx_dev *wdev, u8 **data, size_t *tx_len, int *burst);

void wsm_lock_tx(struct wfx_dev *wdev);
void wsm_lock_tx_async(struct wfx_dev *wdev);
void wsm_unlock_tx(struct wfx_dev *wdev);
void wsm_buf_init(struct wsm_buf *buf);
void wsm_buf_deinit(struct wsm_buf *buf);
void wsm_txed(struct wfx_dev *wdev, u8 *data);

bool wsm_flush_tx(struct wfx_dev *wdev);

static inline int wsm_set_output_power(struct wfx_dev *wdev,
				       int power_level)
{
	__le32 val = cpu_to_le32(power_level);

	return wsm_write_mib(wdev, WSM_MIB_ID_DOT11_CURRENT_TX_POWER_LEVEL,
			     &val, sizeof(val));
}

static inline int wsm_set_beacon_wakeup_period(struct wfx_dev *wdev,
					       unsigned dtim_interval,
					       unsigned listen_interval)
{
	WsmHiMibBeaconWakeUpPeriod_t val = {
		dtim_interval, 0, cpu_to_le16(listen_interval)
	};

	if (dtim_interval > 0xFF || listen_interval > 0xFFFF)
		return -EINVAL;
	else
		return wsm_write_mib(wdev, WSM_MIB_ID_BEACON_WAKEUP_PERIOD,
				     &val, sizeof(val));
}

static inline int wsm_set_rcpi_rssi_threshold(struct wfx_dev *wdev,
					      WsmHiMibRcpiRssiThreshold_t *arg)
{
	return wsm_write_mib(wdev, WSM_MIB_ID_RCPI_RSSI_THRESHOLD, arg,
			     sizeof(*arg));
}

static inline int wsm_get_counters_table(struct wfx_dev *wdev,
					 struct wsm_mib_counters_table *arg)
{
	return wsm_read_mib(wdev, WSM_MIB_ID_COUNTERS_TABLE,
			    arg, sizeof(*arg));
}

static inline int wsm_get_station_id(struct wfx_dev *wdev, u8 *mac1, u8 *mac2)
{
	int ret;
	WsmHiMibMacAddresses_t msg;

	ret = wsm_read_mib(wdev, WSM_MIB_ID_DOT11_MAC_ADDRESSES, &msg, sizeof(msg));
	if (mac1)
		ether_addr_copy(mac1, msg.MacAddr0);
	if (mac2)
		ether_addr_copy(mac2, msg.MacAddr1);
	return ret;
}

static inline int wsm_set_station_id(struct wfx_dev *wdev, u8 *mac1, u8 *mac2)
{
	WsmHiMibMacAddresses_t msg = { };

	if (mac1)
		ether_addr_copy(msg.MacAddr0, mac1);
	if (mac2)
		ether_addr_copy(msg.MacAddr1, mac2);
	return wsm_write_mib(wdev, WSM_MIB_ID_DOT11_MAC_ADDRESSES, &msg, sizeof(msg));
}

static inline int wsm_set_rx_filter(struct wfx_dev *wdev,
				    const struct wsm_rx_filter *arg)
{
	__le32 val = 0;

	if (arg->promiscuous)
		val |= cpu_to_le32(BIT(0));
	if (arg->bssid)
		val |= cpu_to_le32(BIT(1));
	if (arg->fcs)
		val |= cpu_to_le32(BIT(2));
	if (arg->probeResponder)
		val |= cpu_to_le32(BIT(3));
	return wsm_write_mib(wdev, WSM_MIB_ID_RX_FILTER, &val, sizeof(val));
}

static inline int wsm_set_beacon_filter_table(struct wfx_dev *wdev,
					      WsmHiMibBcnFilterTable_t *ft)
{
	return wsm_write_mib(wdev, WSM_MIB_ID_BEACON_FILTER_TABLE, ft,
			     sizeof(*ft));
}

static inline int wsm_beacon_filter_control(struct wfx_dev *wdev,
					    WsmHiMibBcnFilterEnable_t *arg)
{
	struct {
		__le32 Enable;
		__le32 BcnCount;
	} val;
	val.Enable = cpu_to_le32(arg->Enable);
	val.BcnCount = cpu_to_le32(arg->BcnCount);
	return wsm_write_mib(wdev, WSM_MIB_ID_BEACON_FILTER_ENABLE, &val,
			     sizeof(val));
}

static inline int wsm_set_operational_mode(struct wfx_dev *wdev,
					   const struct wsm_operational_mode *arg)
{
	u8 val = arg->power_mode;

	if (arg->disable_more_flag_usage)
		val |= BIT(4);
	if (arg->perform_ant_diversity)
		val |= BIT(5);
	return wsm_write_mib(wdev, WSM_MIB_ID_OPERATIONAL_POWER_MODE, &val,
			     sizeof(val));
}

static inline int wsm_set_template_frame(struct wfx_dev *wdev,
					 WsmHiMibTemplateFrame_t *arg)
{
	return wsm_write_mib(wdev, WSM_MIB_ID_TEMPLATE_FRAME, arg,
			     sizeof(*arg));
}

static inline int wsm_set_protected_mgmt_policy(struct wfx_dev *wdev,
						struct wsm_protected_mgmt_policy *arg)
{
	__le32 val = 0;
	int ret;

	if (arg->protectedMgmtEnable)
		val |= cpu_to_le32(BIT(0));
	if (arg->unprotectedMgmtFramesAllowed)
		val |= cpu_to_le32(BIT(1));
	if (arg->encryptionForAuthFrame)
		val |= cpu_to_le32(BIT(2));
	ret = wsm_write_mib(wdev, WSM_MIB_ID_PROTECTED_MGMT_POLICY,
			&val, sizeof(val));
	return ret;
}

static inline int wsm_set_block_ack_policy(struct wfx_dev *wdev,
					   u8 tx_tid_policy, u8 rx_tid_policy)
{
	WsmHiMibBlockAckPolicy_t val = {
		.BlockAckTxTidPolicy = tx_tid_policy,
		.BlockAckRxTidPolicy = rx_tid_policy,
	};

	return wsm_write_mib(wdev, WSM_MIB_ID_BLOCK_ACK_POLICY, &val,
			     sizeof(val));
}

static inline int wsm_set_association_mode(struct wfx_dev *wdev,
					   WsmHiMibSetAssociationMode_t *arg)
{
	return wsm_write_mib(wdev, WSM_MIB_ID_SET_ASSOCIATION_MODE, arg,
			     sizeof(*arg));
}

static inline int wsm_set_tx_rate_retry_policy(struct wfx_dev *wdev,
					       WsmHiMibSetTxRateRetryPolicy_t *arg)
{
	size_t size = 4 + arg->NumTxRatePolicy *
		      sizeof(WsmHiMibTxRateRetryPolicy_t);

	return wsm_write_mib(wdev, WSM_MIB_ID_SET_TX_RATE_RETRY_POLICY, arg,
			     size);
}

static inline int wsm_set_ether_type_filter(struct wfx_dev *wdev,
					    WsmHiMibEtherTypeDataFrameFilterSet_t *arg)
{
	return wsm_write_mib(wdev, WSM_MIB_ID_SET_ETHERTYPE_DATAFRAME_FILTER,
			     arg, sizeof(*arg));
}

static inline int wsm_set_udp_port_filter(struct wfx_dev *wdev,
					  WsmHiMibUdpPortDataFrameFilterSet_t *arg)
{
	return wsm_write_mib(wdev, WSM_MIB_ID_SET_UDPPORT_DATAFRAME_FILTER,
			     arg, sizeof(*arg));
}

static inline int wsm_keep_alive_period(struct wfx_dev *wdev,
					int period)
{
	WsmHiMibKeepAlivePeriod_t arg = {
		.KeepAlivePeriod = cpu_to_le16(period),
	};

	return wsm_write_mib(wdev, WSM_MIB_ID_KEEP_ALIVE_PERIOD,
			     &arg, sizeof(arg));
};

static inline int wsm_set_bssid_filtering(struct wfx_dev *wdev,
					  bool enabled)
{
	WsmHiMibDisableBssidFilter_t arg = {
		.Filter = !enabled,
	};

	return wsm_write_mib(wdev, WSM_MIB_ID_DISABLE_BSSID_FILTER,
			     &arg, sizeof(arg));
}

static inline int wsm_set_multicast_filter(struct wfx_dev *wdev,
					   WsmHiMibGrpAddrTable_t *fp)
{
	return wsm_write_mib(wdev, WSM_MIB_ID_DOT11_GROUP_ADDRESSES_TABLE,
			     fp, sizeof(*fp));
}

static inline int wsm_set_arp_ipv4_filter(struct wfx_dev *wdev,
					  WsmHiMibArpIpAddrTable_t *fp)
{
	return wsm_write_mib(wdev, WSM_MIB_ID_ARP_IP_ADDRESSES_TABLE,
			    fp, sizeof(*fp));
}

static inline int wsm_set_p2p_ps_modeinfo(struct wfx_dev *wdev,
					  WsmHiMibP2PPsModeInfo_t *mi)
{
	return wsm_write_mib(wdev, WSM_MIB_ID_P2P_PS_MODE_INFO,
			     mi, sizeof(*mi));
}

static inline int wsm_get_p2p_ps_modeinfo(struct wfx_dev *wdev,
					  WsmHiMibP2PPsModeInfo_t *mi)
{
	return wsm_read_mib(wdev, WSM_MIB_ID_P2P_PS_MODE_INFO,
			    mi, sizeof(*mi));
}

static inline int wsm_use_multi_tx_conf(struct wfx_dev *wdev,
					bool enabled)
{
	__le32 arg = enabled ? cpu_to_le32(1) : 0;

	return wsm_write_mib(wdev, WSM_MIB_ID_SET_MULTI_MSG,
			&arg, sizeof(arg));
}

static inline int wsm_set_uapsd_info(struct wfx_dev *wdev,
				     WsmHiMibSetUapsdInformation_t *arg)
{
	return wsm_write_mib(wdev, WSM_MIB_ID_SET_UAPSD_INFORMATION,
				arg, sizeof(*arg));
}

/* Queue mapping: WSM <---> linux					*/
/* Linux: VO VI BE BK							*/
/* WSM:   BE BK VI VO							*/
static inline u8 wsm_queue_id_to_linux(u8 queue_id)
{
	static const u8 queue_mapping[] = {
		2, 3, 1, 0
	};

	return queue_mapping[queue_id];
}

static inline u8 wsm_queue_id_to_wsm(u8 queue_id)
{
	static const u8 queue_mapping[] = {
		3, 2, 0, 1
	};

	return queue_mapping[queue_id];
}


#endif /* WFX_HWIO_H */
