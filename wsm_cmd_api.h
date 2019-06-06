// SPDX-License-Identifier: Apache-2.0
/*
 * WFx hardware interface definitions
 *
 * Copyright (c) 2018-2019, Silicon Laboratories Inc.
 */

#ifndef _WSM_CMD_API_H_
#define _WSM_CMD_API_H_

#include "general_api.h"
#include "wsm_mib_api.h"

#define WSM_NUM_AC                             4

#define WSM_API_SSID_SIZE                      32

typedef enum HiWsmRequestsIds_e {
	WSM_HI_RESET_REQ_ID                             = 0x0a,
	WSM_HI_READ_MIB_REQ_ID                          = 0x05,
	WSM_HI_WRITE_MIB_REQ_ID                         = 0x06,
	WSM_HI_START_SCAN_REQ_ID                        = 0x07,
	WSM_HI_STOP_SCAN_REQ_ID                         = 0x08,
	WSM_HI_TX_REQ_ID                                = 0x04,
	WSM_HI_JOIN_REQ_ID                              = 0x0b,
	WSM_HI_SET_PM_MODE_REQ_ID                       = 0x10,
	WSM_HI_SET_BSS_PARAMS_REQ_ID                    = 0x11,
	WSM_HI_ADD_KEY_REQ_ID                           = 0x0c,
	WSM_HI_REMOVE_KEY_REQ_ID                        = 0x0d,
	WSM_HI_EDCA_QUEUE_PARAMS_REQ_ID                 = 0x13,
	WSM_HI_START_REQ_ID                             = 0x17,
	WSM_HI_BEACON_TRANSMIT_REQ_ID                   = 0x18,
	WSM_HI_UPDATE_IE_REQ_ID                         = 0x1b,
	WSM_HI_MAP_LINK_REQ_ID                          = 0x1c,
} HiWsmRequestsIds;

typedef enum HiWsmConfirmationsIds_e {
	WSM_HI_RESET_CNF_ID                             = 0x0a,
	WSM_HI_READ_MIB_CNF_ID                          = 0x05,
	WSM_HI_WRITE_MIB_CNF_ID                         = 0x06,
	WSM_HI_START_SCAN_CNF_ID                        = 0x07,
	WSM_HI_STOP_SCAN_CNF_ID                         = 0x08,
	WSM_HI_TX_CNF_ID                                = 0x04,
	WSM_HI_MULTI_TRANSMIT_CNF_ID                    = 0x1e,
	WSM_HI_JOIN_CNF_ID                              = 0x0b,
	WSM_HI_SET_PM_MODE_CNF_ID                       = 0x10,
	WSM_HI_SET_BSS_PARAMS_CNF_ID                    = 0x11,
	WSM_HI_ADD_KEY_CNF_ID                           = 0x0c,
	WSM_HI_REMOVE_KEY_CNF_ID                        = 0x0d,
	WSM_HI_EDCA_QUEUE_PARAMS_CNF_ID                 = 0x13,
	WSM_HI_START_CNF_ID                             = 0x17,
	WSM_HI_BEACON_TRANSMIT_CNF_ID                   = 0x18,
	WSM_HI_UPDATE_IE_CNF_ID                         = 0x1b,
	WSM_HI_MAP_LINK_CNF_ID                          = 0x1c,
} HiWsmConfirmationsIds;

typedef enum HiWsmIndicationsIds_e {
	WSM_HI_RX_IND_ID                                = 0x84,
	WSM_HI_SCAN_CMPL_IND_ID                         = 0x86,
	WSM_HI_JOIN_COMPLETE_IND_ID                     = 0x8f,
	WSM_HI_SET_PM_MODE_CMPL_IND_ID                  = 0x89,
	WSM_HI_SUSPEND_RESUME_TX_IND_ID                 = 0x8c,
	WSM_HI_EVENT_IND_ID                             = 0x85
} HiWsmIndicationsIds;

typedef union HiWsmCommandsIds_u {
	HiWsmRequestsIds request;
	HiWsmConfirmationsIds confirmation;
	HiWsmIndicationsIds indication;
} HiWsmCommandsIds_t;

typedef enum WsmStatus_e {
	WSM_STATUS_SUCCESS                         = 0x0,
	WSM_STATUS_FAILURE                         = 0x1,
	WSM_INVALID_PARAMETER                      = 0x2,
	WSM_STATUS_WARNING                         = 0x3,
	WSM_ERROR_UNSUPPORTED_MSG_ID               = 0x4,
	WSM_STATUS_DECRYPTFAILURE                  = 0x10,
	WSM_STATUS_MICFAILURE                      = 0x11,
	WSM_STATUS_NO_KEY_FOUND                    = 0x12,
	WSM_STATUS_RETRY_EXCEEDED                  = 0x13,
	WSM_STATUS_TX_LIFETIME_EXCEEDED            = 0x14,
	WSM_REQUEUE                                = 0x15,
	WSM_STATUS_REFUSED                         = 0x16,
	WSM_STATUS_BUSY                            = 0x17
} WsmStatus;

typedef struct WsmHiResetFlags_s {
	uint8_t    ResetStat:1;
	uint8_t    ResetAllInt:1;
	uint8_t    Reserved1:6;
	uint8_t    Reserved2[3];
} __packed WsmHiResetFlags_t;

typedef struct WsmHiResetReqBody_s {
	WsmHiResetFlags_t ResetFlags;
} __packed WsmHiResetReqBody_t;

typedef struct WsmHiResetCnfBody_s {
	uint32_t   Status;
} __packed WsmHiResetCnfBody_t;

typedef struct WsmHiReadMibReqBody_s {
	uint16_t   MibId;
	uint16_t   Reserved;
} __packed WsmHiReadMibReqBody_t;

typedef struct WsmHiReadMibCnfBody_s {
	uint32_t   Status;
	uint16_t   MibId;
	uint16_t   Length;
	uint8_t    MibData[];
} __packed WsmHiReadMibCnfBody_t;

typedef struct WsmHiWriteMibReqBody_s {
	uint16_t   MibId;
	uint16_t   Length;
	uint8_t    MibData[];
} __packed WsmHiWriteMibReqBody_t;

typedef struct WsmHiWriteMibCnfBody_s {
	uint32_t   Status;
} __packed WsmHiWriteMibCnfBody_t;

typedef struct WsmHiIeFlags_s {
	uint8_t    Beacon:1;
	uint8_t    ProbeResp:1;
	uint8_t    ProbeReq:1;
	uint8_t    Reserved1:5;
	uint8_t    Reserved2;
} __packed WsmHiIeFlags_t;

typedef struct WsmHiIeTlv_s {
	uint8_t    Type;
	uint8_t    Length;
	uint8_t    Data[];
} __packed WsmHiIeTlv_t;

typedef struct WsmHiUpdateIeReqBody_s {
	WsmHiIeFlags_t IeFlags;
	uint16_t   NumIEs;
	WsmHiIeTlv_t IE[];
} __packed WsmHiUpdateIeReqBody_t;

typedef struct WsmHiUpdateIeCnfBody_s {
	uint32_t   Status;
} __packed WsmHiUpdateIeCnfBody_t;

typedef struct WsmHiScanType_s {
	uint8_t    Type:1;
	uint8_t    Mode:1;
	uint8_t    Reserved:6;
} __packed WsmHiScanType_t;

typedef struct WsmHiScanFlags_s {
	uint8_t    Fbg:1;
	uint8_t    Reserved1:1;
	uint8_t    Pre:1;
	uint8_t    Reserved2:5;
} __packed WsmHiScanFlags_t;

typedef struct WsmHiAutoScanParam_s {
	uint16_t   Interval;
	uint8_t    Reserved;
	int8_t     RssiThr;
} __packed WsmHiAutoScanParam_t;

typedef struct WsmHiSsidDef_s {
	uint32_t   SSIDLength;
	uint8_t    SSID[WSM_API_SSID_SIZE];
} __packed WsmHiSsidDef_t;

#define WSM_API_MAX_NB_SSIDS                           2
#define WSM_API_MAX_NB_CHANNELS                       14

typedef struct WsmHiStartScanReqBody_s {
	uint8_t    Band;
	WsmHiScanType_t ScanType;
	WsmHiScanFlags_t ScanFlags;
	uint8_t    MaxTransmitRate;
	WsmHiAutoScanParam_t AutoScanParam;
	uint8_t    NumOfProbeRequests;
	uint8_t    ProbeDelay;
	uint8_t    NumOfSSIDs;
	uint8_t    NumOfChannels;
	uint32_t   MinChannelTime;
	uint32_t   MaxChannelTime;
	int32_t    TxPowerLevel;
	uint8_t    SsidAndChannelLists[];
} __packed WsmHiStartScanReqBody_t;

typedef struct WsmHiStartScanReqCstnbssidBody_s {
	uint8_t    Band;
	WsmHiScanType_t ScanType;
	WsmHiScanFlags_t ScanFlags;
	uint8_t    MaxTransmitRate;
	WsmHiAutoScanParam_t AutoScanParam;
	uint8_t    NumOfProbeRequests;
	uint8_t    ProbeDelay;
	uint8_t    NumOfSSIDs;
	uint8_t    NumOfChannels;
	uint32_t   MinChannelTime;
	uint32_t   MaxChannelTime;
	int32_t    TxPowerLevel;
	WsmHiSsidDef_t SsidDef[WSM_API_MAX_NB_SSIDS];
	uint8_t    ChannelList[];
} __packed WsmHiStartScanReqCstnbssidBody_t;

typedef struct WsmHiStartScanCnfBody_s {
	uint32_t   Status;
} __packed WsmHiStartScanCnfBody_t;

typedef struct WsmHiStopScanCnfBody_s {
	uint32_t   Status;
} __packed WsmHiStopScanCnfBody_t;

typedef enum WsmPmModeStatus_e {
	WSM_PM_MODE_ACTIVE                         = 0x0,
	WSM_PM_MODE_PS                             = 0x1,
	WSM_PM_MODE_UNDETERMINED                   = 0x2
} WsmPmModeStatus;

typedef struct WsmHiScanCmplIndBody_s {
	uint32_t   Status;
	uint8_t    PmMode;
	uint8_t    NumChannelsCompleted;
	uint16_t   Reserved;
} __packed WsmHiScanCmplIndBody_t;

typedef enum WsmQueueId_e {
	WSM_QUEUE_ID_BACKGROUND                    = 0x0,
	WSM_QUEUE_ID_BESTEFFORT                    = 0x1,
	WSM_QUEUE_ID_VIDEO                         = 0x2,
	WSM_QUEUE_ID_VOICE                         = 0x3
} WsmQueueId;

typedef enum WsmFrameFormat_e {
	WSM_FRAME_FORMAT_NON_HT                    = 0x0,
	WSM_FRAME_FORMAT_MIXED_FORMAT_HT           = 0x1,
	WSM_FRAME_FORMAT_GF_HT_11N                 = 0x2
} WsmFrameFormat;

typedef enum WsmStbc_e {
	WSM_STBC_NOT_ALLOWED                       = 0x0,
	WSM_STBC_ALLOWED                           = 0x1
} WsmStbc;

typedef struct WsmHiQueueId_s {
	uint8_t    QueueId:2;
	uint8_t    PeerStaId:4;
	uint8_t    Reserved:2;
} __packed WsmHiQueueId_t;

typedef struct WsmHiDataFlags_s {
	uint8_t    More:1;
	uint8_t    FcOffset:3;
	uint8_t    Reserved:4;
} __packed WsmHiDataFlags_t;

typedef struct WsmHiTxFlags_s {
	uint8_t    StartExp:1;
	uint8_t    Reserved:3;
	uint8_t    RetryPolicyIndex:4;
} __packed WsmHiTxFlags_t;

typedef struct WsmHiHtTxParameters_s {
	uint8_t    FrameFormat:4;
	uint8_t    FecCoding:1;
	uint8_t    ShortGi:1;
	uint8_t    Reserved1:1;
	uint8_t    Stbc:1;
	uint8_t    Reserved2;
	uint8_t    Aggregation:1;
	uint8_t    Reserved3:7;
	uint8_t    Reserved4;
} __packed WsmHiHtTxParameters_t;

typedef struct WsmHiTxReqBody_s {
	uint32_t   PacketId;
	uint8_t    MaxTxRate;
	WsmHiQueueId_t QueueId;
	WsmHiDataFlags_t DataFlags;
	WsmHiTxFlags_t TxFlags;
	uint32_t   Reserved;
	uint32_t   ExpireTime;
	WsmHiHtTxParameters_t HtTxParameters;
	uint32_t   Frame[];
} __packed WsmHiTxReqBody_t;

typedef enum WsmQosAckplcy_e {
	WSM_QOS_ACKPLCY_NORMAL                         = 0x0,
	WSM_QOS_ACKPLCY_TXNOACK                        = 0x1,
	WSM_QOS_ACKPLCY_NOEXPACK                       = 0x2,
	WSM_QOS_ACKPLCY_BLCKACK                        = 0x3
} WsmQosAckplcy;

typedef struct WsmHiTxResultFlags_s {
	uint8_t    Aggr:1;
	uint8_t    Requeue:1;
	uint8_t    AckPolicy:2;
	uint8_t    TxopLimit:1;
	uint8_t    Reserved1:3;
	uint8_t    Reserved2;
} __packed WsmHiTxResultFlags_t;

typedef struct WsmHiTxCnfBody_s {
	uint32_t   Status;
	uint32_t   PacketId;
	uint8_t    TxedRate;
	uint8_t    AckFailures;
	WsmHiTxResultFlags_t TxResultFlags;
	uint32_t   MediaDelay;
	uint32_t   TxQueueDelay;
} __packed WsmHiTxCnfBody_t;

typedef struct WsmHiMultiTransmitCnfBody_s {
	uint32_t   NumTxConfs;
	WsmHiTxCnfBody_t   TxConfPayload[];
} __packed WsmHiMultiTransmitCnfBody_t;

typedef enum WsmRiFlagsEncrypt_e {
	WSM_RI_FLAGS_UNENCRYPTED                   = 0x0,
	WSM_RI_FLAGS_WEP_ENCRYPTED                 = 0x1,
	WSM_RI_FLAGS_TKIP_ENCRYPTED                = 0x2,
	WSM_RI_FLAGS_AES_ENCRYPTED                 = 0x3,
	WSM_RI_FLAGS_WAPI_ENCRYPTED                = 0x4
} WsmRiFlagsEncrypt;

typedef struct WsmHiRxFlags_s {
	uint8_t    Encryp:3;
	uint8_t    InAggr:1;
	uint8_t    FirstAggr:1;
	uint8_t    LastAggr:1;
	uint8_t    Defrag:1;
	uint8_t    Beacon:1;
	uint8_t    Tim:1;
	uint8_t    Bitmap:1;
	uint8_t    MatchSsid:1;
	uint8_t    MatchBssid:1;
	uint8_t    More:1;
	uint8_t    Reserved1:1;
	uint8_t    Ht:1;
	uint8_t    Stbc:1;
	uint8_t    MatchUcAddr:1;
	uint8_t    MatchMcAddr:1;
	uint8_t    MatchBcAddr:1;
	uint8_t    KeyType:1;
	uint8_t    KeyIndex:4;
	uint8_t    Reserved2:1;
	uint8_t    PeerStaId:4;
	uint8_t    Reserved3:2;
	uint8_t    Reserved4:1;
} __packed WsmHiRxFlags_t;

typedef struct WsmHiRxIndBody_s {
	uint32_t   Status;
	uint16_t   ChannelNumber;
	uint8_t    RxedRate;
	uint8_t    RcpiRssi;
	WsmHiRxFlags_t RxFlags;
	uint32_t   Frame[];
} __packed WsmHiRxIndBody_t;


typedef struct WsmHiEdcaQueueParamsReqBody_s {
	uint8_t    QueueId;
	uint8_t    Reserved1;
	uint8_t    AIFSN;
	uint8_t    Reserved2;
	uint16_t   CwMin;
	uint16_t   CwMax;
	uint16_t   TxOpLimit;
	uint16_t   AllowedMediumTime;
	uint32_t   Reserved3;
} __packed WsmHiEdcaQueueParamsReqBody_t;

typedef struct WsmHiEdcaQueueParamsCnfBody_s {
	uint32_t   Status;
} __packed WsmHiEdcaQueueParamsCnfBody_t;

typedef enum WsmMode_e {
	WSM_MODE_IBSS                              = 0x0,
	WSM_MODE_BSS                               = 0x1
} WsmMode;

typedef enum WsmPreamble_e {
	WSM_PREAMBLE_LONG                          = 0x0,
	WSM_PREAMBLE_SHORT                         = 0x1,
	WSM_PREAMBLE_SHORT_LONG12                  = 0x2
} WsmPreamble;

typedef struct WsmHiJoinFlags_s {
	uint8_t    Reserved1:2;
	uint8_t    ForceNoBeacon:1;
	uint8_t    ForceWithInd:1;
	uint8_t    Reserved2:4;
} __packed WsmHiJoinFlags_t;

typedef struct WsmHiJoinReqBody_s {
	uint8_t    Mode;
	uint8_t    Band;
	uint16_t   ChannelNumber;
	uint8_t    BSSID[ETH_ALEN];
	uint16_t   AtimWindow;
	uint8_t    PreambleType;
	uint8_t    ProbeForJoin;
	uint8_t    Reserved;
	WsmHiJoinFlags_t JoinFlags;
	uint32_t   SSIDLength;
	uint8_t    SSID[WSM_API_SSID_SIZE];
	uint32_t   BeaconInterval;
	uint32_t   BasicRateSet;
} __packed WsmHiJoinReqBody_t;

typedef struct WsmHiJoinCnfBody_s {
	uint32_t   Status;
} __packed WsmHiJoinCnfBody_t;

typedef struct WsmHiJoinCompleteIndBody_s {
	uint32_t   Status;
} __packed WsmHiJoinCompleteIndBody_t;

typedef struct WsmHiBssFlags_s {
	uint8_t    LostCountOnly:1;
	uint8_t    Reserved:7;
} __packed WsmHiBssFlags_t;

typedef struct WsmHiSetBssParamsReqBody_s {
	WsmHiBssFlags_t BssFlags;
	uint8_t    BeaconLostCount;
	uint16_t   AID;
	uint32_t   OperationalRateSet;
} __packed WsmHiSetBssParamsReqBody_t;

typedef struct WsmHiSetBssParamsCnfBody_s {
	uint32_t   Status;
} __packed WsmHiSetBssParamsCnfBody_t;

typedef struct WsmHiPmMode_s {
	uint8_t    EnterPsm:1;
	uint8_t    Reserved:6;
	uint8_t    FastPsm:1;
} __packed WsmHiPmMode_t;

typedef struct WsmHiSetPmModeReqBody_s {
	WsmHiPmMode_t PmMode;
	uint8_t    FastPsmIdlePeriod;
	uint8_t    ApPsmChangePeriod;
	uint8_t    MinAutoPsPollPeriod;
} __packed WsmHiSetPmModeReqBody_t;

typedef struct WsmHiSetPmModeCnfBody_s {
	uint32_t   Status;
} __packed WsmHiSetPmModeCnfBody_t;

typedef struct WsmHiSetPmModeCmplIndBody_s {
	uint32_t   Status;
	uint8_t    PmMode;
	uint8_t    Reserved[3];
} __packed WsmHiSetPmModeCmplIndBody_t;


typedef struct WsmHiStartReqBody_s {
	uint8_t    Mode;
	uint8_t    Band;
	uint16_t   ChannelNumber;
	uint32_t   Reserved1;
	uint32_t   BeaconInterval;
	uint8_t    DTIMPeriod;
	uint8_t    PreambleType;
	uint8_t    Reserved2;
	uint8_t    SsidLength;
	uint8_t    Ssid[WSM_API_SSID_SIZE];
	uint32_t   BasicRateSet;
} __packed WsmHiStartReqBody_t;

typedef struct WsmHiStartCnfBody_s {
	uint32_t   Status;
} __packed WsmHiStartCnfBody_t;

typedef enum WsmBeacon_e {
	WSM_BEACON_STOP                       = 0x0,
	WSM_BEACON_START                      = 0x1
} WsmBeacon;

typedef struct WsmHiBeaconTransmitReqBody_s {
	uint8_t    EnableBeaconing;
	uint8_t    Reserved[3];
} __packed WsmHiBeaconTransmitReqBody_t;

typedef struct WsmHiBeaconTransmitCnfBody_s {
	uint32_t   Status;
} __packed WsmHiBeaconTransmitCnfBody_t;

typedef enum WsmStaMapDirection_e {
	WSM_STA_MAP                       = 0x0,
	WSM_STA_UNMAP                     = 0x1
} WsmStaMapDirection;

typedef struct WsmHiMapLinkFlags_s {
	uint8_t    MapDirection:1;
	uint8_t    Mfpc:1;
	uint8_t    Reserved:6;
} __packed WsmHiMapLinkFlags_t;

typedef struct WsmHiMapLinkReqBody_s {
	uint8_t    MacAddr[ETH_ALEN];
	WsmHiMapLinkFlags_t MapLinkFlags;
	uint8_t    PeerStaId;
} __packed WsmHiMapLinkReqBody_t;

typedef struct WsmHiMapLinkCnfBody_s {
	uint32_t   Status;
} __packed WsmHiMapLinkCnfBody_t;

typedef struct WsmHiSuspendResumeFlags_s {
	uint8_t    Resume:1;
	uint8_t    Reserved1:2;
	uint8_t    BcMcOnly:1;
	uint8_t    Reserved2:4;
	uint8_t    Reserved3;
} __packed WsmHiSuspendResumeFlags_t;

typedef struct WsmHiSuspendResumeTxIndBody_s {
	WsmHiSuspendResumeFlags_t SuspendResumeFlags;
	uint16_t   PeerStaSet;
} __packed WsmHiSuspendResumeTxIndBody_t;


#define MAX_KEY_ENTRIES         24
#define WSM_API_WEP_KEY_DATA_SIZE                       16
#define WSM_API_TKIP_KEY_DATA_SIZE                      16
#define WSM_API_RX_MIC_KEY_SIZE                         8
#define WSM_API_TX_MIC_KEY_SIZE                         8
#define WSM_API_AES_KEY_DATA_SIZE                       16
#define WSM_API_WAPI_KEY_DATA_SIZE                      16
#define WSM_API_MIC_KEY_DATA_SIZE                       16
#define WSM_API_IGTK_KEY_DATA_SIZE                      16
#define WSM_API_RX_SEQUENCE_COUNTER_SIZE                8
#define WSM_API_IPN_SIZE                                8

typedef enum WsmKeyType_e {
	WSM_KEY_TYPE_WEP_DEFAULT                   = 0x0,
	WSM_KEY_TYPE_WEP_PAIRWISE                  = 0x1,
	WSM_KEY_TYPE_TKIP_GROUP                    = 0x2,
	WSM_KEY_TYPE_TKIP_PAIRWISE                 = 0x3,
	WSM_KEY_TYPE_AES_GROUP                     = 0x4,
	WSM_KEY_TYPE_AES_PAIRWISE                  = 0x5,
	WSM_KEY_TYPE_WAPI_GROUP                    = 0x6,
	WSM_KEY_TYPE_WAPI_PAIRWISE                 = 0x7,
	WSM_KEY_TYPE_IGTK_GROUP                    = 0x8,
	WSM_KEY_TYPE_NONE                          = 0x9
} WsmKeyType;

typedef struct WsmHiWepPairwiseKey_s {
	uint8_t    PeerAddress[ETH_ALEN];
	uint8_t    Reserved;
	uint8_t    KeyLength;
	uint8_t    KeyData[WSM_API_WEP_KEY_DATA_SIZE];
} __packed WsmHiWepPairwiseKey_t;

typedef struct WsmHiWepGroupKey_s {
	uint8_t    KeyId;
	uint8_t    KeyLength;
	uint8_t    Reserved[2];
	uint8_t    KeyData[WSM_API_WEP_KEY_DATA_SIZE];
} __packed WsmHiWepGroupKey_t;

typedef struct WsmHiTkipPairwiseKey_s {
	uint8_t    PeerAddress[ETH_ALEN];
	uint8_t    Reserved[2];
	uint8_t    TkipKeyData[WSM_API_TKIP_KEY_DATA_SIZE];
	uint8_t    RxMicKey[WSM_API_RX_MIC_KEY_SIZE];
	uint8_t    TxMicKey[WSM_API_TX_MIC_KEY_SIZE];
} __packed WsmHiTkipPairwiseKey_t;

typedef struct WsmHiTkipGroupKey_s {
	uint8_t    TkipKeyData[WSM_API_TKIP_KEY_DATA_SIZE];
	uint8_t    RxMicKey[WSM_API_RX_MIC_KEY_SIZE];
	uint8_t    KeyId;
	uint8_t    Reserved[3];
	uint8_t    RxSequenceCounter[WSM_API_RX_SEQUENCE_COUNTER_SIZE];
} __packed WsmHiTkipGroupKey_t;

typedef struct WsmHiAesPairwiseKey_s {
	uint8_t    PeerAddress[ETH_ALEN];
	uint8_t    Reserved[2];
	uint8_t    AesKeyData[WSM_API_AES_KEY_DATA_SIZE];
} __packed WsmHiAesPairwiseKey_t;

typedef struct WsmHiAesGroupKey_s {
	uint8_t    AesKeyData[WSM_API_AES_KEY_DATA_SIZE];
	uint8_t    KeyId;
	uint8_t    Reserved[3];
	uint8_t    RxSequenceCounter[WSM_API_RX_SEQUENCE_COUNTER_SIZE];
} __packed WsmHiAesGroupKey_t;

typedef struct WsmHiWapiPairwiseKey_s {
	uint8_t    PeerAddress[ETH_ALEN];
	uint8_t    KeyId;
	uint8_t    Reserved;
	uint8_t    WapiKeyData[WSM_API_WAPI_KEY_DATA_SIZE];
	uint8_t    MicKeyData[WSM_API_MIC_KEY_DATA_SIZE];
} __packed WsmHiWapiPairwiseKey_t;

typedef struct WsmHiWapiGroupKey_s {
	uint8_t    WapiKeyData[WSM_API_WAPI_KEY_DATA_SIZE];
	uint8_t    MicKeyData[WSM_API_MIC_KEY_DATA_SIZE];
	uint8_t    KeyId;
	uint8_t    Reserved[3];
} __packed WsmHiWapiGroupKey_t;

typedef struct WsmHiIgtkGroupKey_s {
	uint8_t    IGTKKeyData[WSM_API_IGTK_KEY_DATA_SIZE];
	uint8_t    KeyId;
	uint8_t    Reserved[3];
	uint8_t    IPN[WSM_API_IPN_SIZE];
} __packed WsmHiIgtkGroupKey_t;

typedef union WsmPrivacyKeyData_u {
	WsmHiWepPairwiseKey_t                       WepPairwiseKey;
	WsmHiWepGroupKey_t                          WepGroupKey;
	WsmHiTkipPairwiseKey_t                      TkipPairwiseKey;
	WsmHiTkipGroupKey_t                         TkipGroupKey;
	WsmHiAesPairwiseKey_t                       AesPairwiseKey;
	WsmHiAesGroupKey_t                          AesGroupKey;
	WsmHiWapiPairwiseKey_t                      WapiPairwiseKey;
	WsmHiWapiGroupKey_t                         WapiGroupKey;
	WsmHiIgtkGroupKey_t                         IgtkGroupKey;
} WsmPrivacyKeyData_t;

typedef struct WsmHiAddKeyReqBody_s {
	uint8_t    Type;
	uint8_t    EntryIndex;
	uint8_t    IntId:2;
	uint8_t    Reserved1:6;
	uint8_t    Reserved2;
	WsmPrivacyKeyData_t Key;
} __packed WsmHiAddKeyReqBody_t;

typedef struct WsmHiAddKeyCnfBody_s {
	uint32_t   Status;
} __packed WsmHiAddKeyCnfBody_t;

typedef struct WsmHiRemoveKeyReqBody_s {
	uint8_t    EntryIndex;
	uint8_t    Reserved[3];
} __packed WsmHiRemoveKeyReqBody_t;

typedef struct WsmHiRemoveKeyCnfBody_s {
	uint32_t   Status;
} __packed WsmHiRemoveKeyCnfBody_t;

typedef enum WsmEventInd_e {
	WSM_EVENT_IND_BSSLOST                      = 0x1,
	WSM_EVENT_IND_BSSREGAINED                  = 0x2,
	WSM_EVENT_IND_RCPI_RSSI                    = 0x3,
	WSM_EVENT_IND_PS_MODE_ERROR                = 0x4,
	WSM_EVENT_IND_INACTIVITY                   = 0x5
} WsmEventInd;

typedef enum WsmPsModeError_e {
	WSM_PS_ERROR_NO_ERROR                      = 0,
	WSM_PS_ERROR_AP_NOT_RESP_TO_POLL           = 1,
	WSM_PS_ERROR_AP_NOT_RESP_TO_UAPSD_TRIGGER  = 2,
	WSM_PS_ERROR_AP_SENT_UNICAST_IN_DOZE       = 3,
	WSM_PS_ERROR_AP_NO_DATA_AFTER_TIM          = 4
} WsmPsModeError;

typedef union WsmEventData_u {
	uint8_t    RcpiRssi;
	uint32_t   PsModeError;
	uint32_t   PeerStaSet;
} WsmEventData_t;

typedef struct WsmHiEventIndBody_s {
	uint32_t   EventId;
	WsmEventData_t EventData;
} __packed WsmHiEventIndBody_t;


#endif
