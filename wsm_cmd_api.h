/*
 * Copyright (c) 2018, Silicon Laboratories Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _WSM_CMD_API_H_
#define _WSM_CMD_API_H_

#include "general_api.h"
#include "wsm_mib_api.h"

#define WSM_NUM_AC                             4

typedef enum HiWsmRequestsIds_e {
WSM_HI_RESET_REQ_ID                             =0x0a,
WSM_HI_READ_MIB_REQ_ID                          =0x05,
WSM_HI_WRITE_MIB_REQ_ID                         =0x06,
WSM_HI_START_SCAN_REQ_ID                        =0x07,
WSM_HI_STOP_SCAN_REQ_ID                         =0x08,
WSM_HI_TX_REQ_ID                                =0x04,
WSM_HI_JOIN_REQ_ID                              =0x0b,
WSM_HI_SET_PM_MODE_REQ_ID                       =0x10,
WSM_HI_SET_BSS_PARAMS_REQ_ID                    =0x11,
WSM_HI_ADD_KEY_REQ_ID                           =0x0c,
WSM_HI_REMOVE_KEY_REQ_ID                        =0x0d,
WSM_HI_EDCA_QUEUE_PARAMS_REQ_ID                 =0x13,
WSM_HI_START_REQ_ID                             =0x17,
WSM_HI_BEACON_TRANSMIT_REQ_ID                   =0x18,
WSM_HI_UPDATE_IE_REQ_ID                         =0x1b,
WSM_HI_MAP_LINK_REQ_ID                          =0x1c,
} HiWsmRequestsIds;

typedef enum HiWsmConfirmationsIds_e {
WSM_HI_RESET_CNF_ID                             =0x0a,
WSM_HI_READ_MIB_CNF_ID                          =0x05,
WSM_HI_WRITE_MIB_CNF_ID                         =0x06,
WSM_HI_START_SCAN_CNF_ID                        =0x07,
WSM_HI_STOP_SCAN_CNF_ID                         =0x08,
WSM_HI_TX_CNF_ID                                =0x04,
WSM_HI_MULTI_TRANSMIT_CNF_ID                    =0x1e,
WSM_HI_JOIN_CNF_ID                              =0x0b,
WSM_HI_SET_PM_MODE_CNF_ID                       =0x10,
WSM_HI_SET_BSS_PARAMS_CNF_ID                    =0x11,
WSM_HI_ADD_KEY_CNF_ID                           =0x0c,
WSM_HI_REMOVE_KEY_CNF_ID                        =0x0d,
WSM_HI_EDCA_QUEUE_PARAMS_CNF_ID                 =0x13,
WSM_HI_START_CNF_ID                             =0x17,
WSM_HI_BEACON_TRANSMIT_CNF_ID                   =0x18,
WSM_HI_UPDATE_IE_CNF_ID                         =0x1b,
WSM_HI_MAP_LINK_CNF_ID                          =0x1c,
} HiWsmConfirmationsIds;

typedef enum HiWsmIndicationsIds_e {
WSM_HI_RX_IND_ID								=0x84,
WSM_HI_SCAN_CMPL_IND_ID                         =0x86,
WSM_HI_JOIN_COMPLETE_IND_ID                     =0x8f,
WSM_HI_SET_PM_MODE_CMPL_IND_ID                  =0x89,
WSM_HI_SUSPEND_RESUME_TX_IND_ID                 =0x8c,
WSM_HI_EVENT_IND_ID                             =0x85
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
		WSM_ERROR_UNSUPPORTED_MSG_ID			   = 0x4,
		WSM_STATUS_DECRYPTFAILURE                  = 0x10,
        WSM_STATUS_MICFAILURE                      = 0x11,
		WSM_STATUS_NO_KEY_FOUND                    = 0x12,
        WSM_STATUS_RETRY_EXCEEDED                  = 0x13,
        WSM_STATUS_TX_LIFETIME_EXCEEDED            = 0x14,
        WSM_REQUEUE                                = 0x15,
        WSM_STATUS_REFUSED                         = 0x16
} WsmStatus;

#define WSM_API_SSID_SIZE                               32

typedef struct __attribute__((__packed__)) WsmHiResetFlags_s {
        uint8_t    ResetStat : 1;
        uint8_t    ResetAllInt : 1;
        uint8_t    Reserved1 : 6;
        uint8_t    Reserved2[3];
} WsmHiResetFlags_t;

typedef struct __attribute__((__packed__)) WsmHiResetReqBody_s {
        WsmHiResetFlags_t ResetFlags;
} WsmHiResetReqBody_t;

typedef struct __attribute__((__packed__)) WsmHiResetCnfBody_s {
        uint32_t   Status;
} WsmHiResetCnfBody_t;

typedef union WsmMibData_u {

        uint32_t                                        OperationalPowerMode;
        WsmHiMibGlBlockAckInfo_t                  MibBlockAckInfo;
        uint32_t                                        UseMultiTxConfMsg;

        WsmHiMibEthertypeDataFrameCondition_t     EtherTypeDataFrameCondition;
        WsmHiMibPortsDataFrameCondition_t         PortsDataFrameCondition;
        WsmHiMibMagicDataFrameCondition_t         MagicDataFrameCondition;
        WsmHiMibMacAddrDataFrameCondition_t      MacAddrDataFrameCondition;
        WsmHiMibIpv4AddrDataFrameCondition_t     IPv4AddrDataFrameCondition;
        WsmHiMibIpv6AddrDataFrameCondition_t     IPv6AddrDataFrameCondition;
        WsmHiMibUcMcBcDataFrameCondition_t      UcMcBcDataFrameCondition;
        WsmHiMibConfigDataFilter_t                 ConfigDataFilter;
        WsmHiMibSetDataFiltering_t                 SetDataFiltering;
        WsmHiMibArpIpAddrTable_t                  ArpIpAddressesTable;
        WsmHiMibNsIpAddrTable_t                   NsIpAddressesTable;
        uint32_t                                      RxFilter;
        WsmHiMibBcnFilterTable_t                   BeaconFilterTable;
        WsmHiMibBcnFilterEnable_t                  BeaconFilterEnable;

        WsmHiMibGroupSeqCounter_t                  GroupSeqCounter;
        WsmHiMibTsfCounter_t                        TSFCounter;
        WsmHiMibStatsTable_t                        StatisticsTable;
        WsmHiMibCountTable_t                        CountTable;

        WsmHiMibMacAddress_t                        dot11MacAdress;
        uint32_t                                        dot11MaxTransmitMsduLifeTime;
        uint32_t                                        dot11MaxReceiveLifeTime;
        WsmHiMibWepDefaultKeyId_t                 dot11WepdefaultKeyId;
        uint32_t                                        dot11RtsThreshold;
        uint32_t                                        SlotTime;
        int32_t                                        CurrentTxPowerLevel;
        uint32_t                                        useCtsToSelf;
        WsmHiMibTemplateFrame_t                     TemplateFrame;
        WsmHiMibBeaconWakeUpPeriod_t              BeaconWakeUpPeriod;
        WsmHiMibRcpiRssiThreshold_t                RcpiRssiThreshold;
        WsmHiMibBlockAckPolicy_t                   BlockAckPolicy;
        WsmHiMibOverrideIntRate_t                  MibOverrideInternalTxRate;
        WsmHiMibSetAssociationMode_t               SetAssociationMode;
        WsmHiMibSetUapsdInformation_t              SetUapsdInformation;
        WsmHiMibSetTxRateRetryPolicy_t           SetTxRateRetryPolicy;
        uint32_t                                        ProtectedMgmtFramesPolicy;
        uint32_t                                        SetHtProtection;
        WsmHiMibKeepAlivePeriod_t                  KeepAlivePeriod;
        WsmHiMibArpKeepAlivePeriod_t              ArpKeepAlivePeriod;
        WsmHiMibInactivityTimer_t                   InactivityTimer;
        uint32_t                                        InterfaceProtection;
} WsmMibData_t;

typedef struct __attribute__((__packed__)) WsmHiReadMibReqBody_s {
        uint16_t   MibId;
        uint16_t   Reserved;
} WsmHiReadMibReqBody_t;

typedef struct __attribute__((__packed__)) WsmHiReadMibCnfBody_s {
        uint32_t   Status;
        uint16_t   MibId;
        uint16_t   Length;
        uint8_t    MibData[0];
} WsmHiReadMibCnfBody_t;

typedef struct __attribute__((__packed__)) WsmHiWriteMibReqBody_s {
        uint16_t   MibId;
        uint16_t   Length;
        uint8_t    MibData[0];
} WsmHiWriteMibReqBody_t;

typedef struct __attribute__((__packed__)) WsmHiWriteMibCnfBody_s {
        uint32_t   Status;
} WsmHiWriteMibCnfBody_t;

typedef struct __attribute__((__packed__)) WsmHiIeFlags_s {
        uint8_t    Beacon : 1;
        uint8_t    ProbeResp : 1;
        uint8_t    ProbeReq : 1;
        uint8_t    Reserved1 : 5;
        uint8_t    Reserved2;
} WsmHiIeFlags_t;

typedef struct __attribute__((__packed__)) WsmHiIeTlv_s {
        uint8_t    Type;
        uint8_t    Length;
        uint8_t    Data[API_VARIABLE_SIZE_ARRAY_DUMMY_SIZE];
} WsmHiIeTlv_t;

typedef struct __attribute__((__packed__)) WsmHiUpdateIeReqBody_s {
        WsmHiIeFlags_t IeFlags;
        uint16_t          NumIEs;
        WsmHiIeTlv_t   IE[0];
} WsmHiUpdateIeReqBody_t;

typedef struct __attribute__((__packed__)) WsmHiUpdateIeCnfBody_s {
        uint32_t   Status;
} WsmHiUpdateIeCnfBody_t;

typedef struct __attribute__((__packed__)) WsmHiScanType_s {
        uint8_t    Type : 1;
        uint8_t    Mode : 1;
        uint8_t    Reserved : 6;
} WsmHiScanType_t;

typedef struct __attribute__((__packed__)) WsmHiScanFlags_s {
        uint8_t    Fbg : 1;
        uint8_t    Reserved1 : 1;
        uint8_t    Pre : 1;
        uint8_t    Reserved2 : 5;
} WsmHiScanFlags_t;

typedef struct __attribute__((__packed__)) WsmHiAutoScanParam_s {
        uint16_t   Interval;
        uint8_t    Reserved;
        int8_t    RssiThr;
} WsmHiAutoScanParam_t;

typedef struct __attribute__((__packed__)) WsmHiSsidDef_s {
        uint32_t   SSIDLength;
        uint8_t    SSID[WSM_API_SSID_SIZE];
} WsmHiSsidDef_t;

#define WSM_API_MAX_NB_SSIDS                           2
#define WSM_API_MAX_NB_CHANNELS                       14
typedef struct __attribute__((__packed__)) WsmHiStartScanReqBody_s {
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
        int32_t   TxPowerLevel;

} WsmHiStartScanReqBody_t;

typedef struct __attribute__((__packed__)) WsmHiStartScanCnfBody_s {
        uint32_t   Status;
} WsmHiStartScanCnfBody_t;

typedef struct __attribute__((__packed__)) WsmHiStopScanCnfBody_s {
        uint32_t   Status;
} WsmHiStopScanCnfBody_t;

typedef enum WsmPmModeStatus_e {
        WSM_PM_MODE_ACTIVE                         = 0x0,
        WSM_PM_MODE_PS                             = 0x1,
        WSM_PM_MODE_UNDETERMINED                   = 0x2
} WsmPmModeStatus;

typedef struct __attribute__((__packed__)) WsmHiScanCmplIndBody_s {
        uint32_t   Status;
        uint8_t    PmMode;
        uint8_t    NumChannelsCompleted;
        uint16_t   Reserved;
} WsmHiScanCmplIndBody_t;

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

typedef struct __attribute__((__packed__)) WsmHiQueueId_s {
        uint8_t    QueueId : 2;
        uint8_t    PeerStaId : 4;
        uint8_t    Reserved : 2;
} WsmHiQueueId_t;

typedef struct __attribute__((__packed__)) WsmHiDataFlags_s {
        uint8_t    More     : 1;
        uint8_t    FcOffset : 3;
        uint8_t    Reserved : 4;
} WsmHiDataFlags_t;

typedef struct __attribute__((__packed__)) WsmHiTxFlags_s {
        uint8_t    StartExp : 1;
        uint8_t    Reserved : 3;
        uint8_t    Txrate   : 4;
} WsmHiTxFlags_t;

typedef struct __attribute__((__packed__)) WsmHiHtTxParameters_s {
        uint8_t    FrameFormat : 4;
        uint8_t    FecCoding : 1;
        uint8_t    ShortGi : 1;
        uint8_t    Reserved1 : 1;
        uint8_t    Stbc : 1;
        uint8_t    Reserved2;
        uint8_t    Aggregation : 1;
        uint8_t	   Reserved3 : 7;
        uint8_t    Reserved4;
} WsmHiHtTxParameters_t;

typedef struct __attribute__((__packed__)) WsmHiTxReqBody_s {
        uint32_t   PacketId;
        uint8_t    MaxTxRate;
        WsmHiQueueId_t QueueId;
        WsmHiDataFlags_t DataFlags;
        WsmHiTxFlags_t TxFlags;
        uint32_t   Reserved;
        uint32_t   ExpireTime;
        WsmHiHtTxParameters_t HtTxParameters;
        uint32_t   Frame[0];
} WsmHiTxReqBody_t;

typedef enum WsmQosAckplcy_e {
        WSM_QOS_ACKPLCY_NORMAL                         = 0x0,
        WSM_QOS_ACKPLCY_TXNOACK                        = 0x1,
        WSM_QOS_ACKPLCY_NOEXPACK                       = 0x2,
        WSM_QOS_ACKPLCY_BLCKACK                        = 0x3
} WsmQosAckplcy;

typedef struct __attribute__((__packed__)) WsmHiTxResultFlags_s {
        uint8_t    Aggr : 1;
        uint8_t    Requeue : 1;
        uint8_t    AckPolicy : 2;
        uint8_t    TxopLimit : 1;
        uint8_t    Reserved1 : 3;
        uint8_t    Reserved2;
} WsmHiTxResultFlags_t;

typedef struct __attribute__((__packed__)) WsmHiTxCnfBody_s {
    	uint32_t   Status;
        uint32_t   PacketId;
        uint8_t    TxedRate;
        uint8_t    AckFailures;
        WsmHiTxResultFlags_t TxResultFlags;
        uint32_t   MediaDelay;
        uint32_t   TxQueueDelay;
} WsmHiTxCnfBody_t;

typedef struct __attribute__((__packed__)) WsmHiMultiTransmitCnfBody_s {
        uint32_t   NumTxConfs;
        WsmHiTxCnfBody_t   TxConfPayload[API_VARIABLE_SIZE_ARRAY_DUMMY_SIZE];
} WsmHiMultiTransmitCnfBody_t;

typedef enum WsmRiFlagsEncrypt_e {
        WSM_RI_FLAGS_UNENCRYPTED                   = 0x0,
        WSM_RI_FLAGS_WEP_ENCRYPTED                 = 0x1,
        WSM_RI_FLAGS_TKIP_ENCRYPTED                = 0x2,
        WSM_RI_FLAGS_AES_ENCRYPTED                 = 0x3,
        WSM_RI_FLAGS_WAPI_ENCRYPTED                = 0x4
} WsmRiFlagsEncrypt;

typedef struct __attribute__((__packed__)) WsmHiRxFlags_s {
        uint8_t    Encryp : 3;
        uint8_t    InAggr : 1;
        uint8_t    FirstAggr : 1;
        uint8_t    LastAggr : 1;
        uint8_t    Defrag : 1;
        uint8_t    Beacon : 1;
        uint8_t    Tim : 1;
        uint8_t    Bitmap : 1;
        uint8_t    MatchSsid : 1;
        uint8_t    MatchBssid : 1;
        uint8_t    More : 1;
        uint8_t    Reserved1 : 1;
        uint8_t    Ht : 1;
        uint8_t    Stbc : 1;
        uint8_t    MatchUcAddr : 1;
        uint8_t    MatchMcAddr : 1;
        uint8_t    MatchBcAddr : 1;
        uint8_t    KeyType : 1;
        uint8_t    KeyIndex : 4;
        uint8_t    Reserved2 : 1;
        uint8_t    PeerStaId : 4;
        uint8_t    Reserved3 : 2;
        uint8_t    Reserved4 : 1;
} WsmHiRxFlags_t;

typedef struct __attribute__((__packed__)) WsmHiRxIndBody_s {
        uint32_t   Status;
        uint16_t   ChannelNumber;
        uint8_t    RxedRate;
        uint8_t    RcpiRssi;
        WsmHiRxFlags_t RxFlags;
        uint32_t   Frame[0];
} WsmHiRxIndBody_t;

typedef enum WsmAckplcy_e {
        WSM_ACKPLCY_NORMAL                         = 0x0,
        WSM_ACKPLCY_TXNOACK                        = 0x1
} WsmAckplcy;

typedef struct __attribute__((__packed__)) WsmHiEdcaQueueParamsReqBody_s {
        uint8_t    QueueId;
    uint8_t    Reserved1;
    uint8_t    AIFSN;
    uint8_t    Reserved2;
    uint16_t   CwMin;
    uint16_t   CwMax;
    uint16_t   TxOpLimit;
    uint16_t   AllowedMediumTime;
    uint32_t    Reserved3;
} WsmHiEdcaQueueParamsReqBody_t;

typedef struct __attribute__((__packed__)) WsmHiEdcaQueueParamsCnfBody_s {
        uint32_t   Status;
} WsmHiEdcaQueueParamsCnfBody_t;

typedef enum WsmMode_e {
        WSM_MODE_IBSS                              = 0x0,
        WSM_MODE_BSS                               = 0x1
} WsmMode;

typedef enum WsmPreamble_e {
        WSM_PREAMBLE_LONG                          = 0x0,
        WSM_PREAMBLE_SHORT                         = 0x1,
        WSM_PREAMBLE_SHORT_LONG12                  = 0x2
} WsmPreamble;

typedef struct __attribute__((__packed__)) WsmHiJoinFlags_s {
        uint8_t    Reserved1 : 2;
        uint8_t    ForceNoBeacon : 1;
        uint8_t    ForceWithInd  : 1;
        uint8_t    Reserved2 : 4;

} WsmHiJoinFlags_t;

#define WSM_API_BSSID_SIZE                              6

typedef struct __attribute__((__packed__)) WsmHiJoinReqBody_s {
        uint8_t    Mode;
        uint8_t    Band;
        uint16_t   ChannelNumber;
        uint8_t    BSSID[WSM_API_BSSID_SIZE];
        uint16_t   AtimWindow;
        uint8_t    PreambleType;
        uint8_t    ProbeForJoin;
        uint8_t    Reserved;
        WsmHiJoinFlags_t JoinFlags;
        uint32_t   SSIDLength;
        uint8_t    SSID[WSM_API_SSID_SIZE];
        uint32_t   BeaconInterval;
        uint32_t   BasicRateSet;
} WsmHiJoinReqBody_t;

typedef struct __attribute__((__packed__)) WsmHiJoinCnfBody_s {
        uint32_t   Status;
} WsmHiJoinCnfBody_t;

typedef struct __attribute__((__packed__)) WsmHiJoinCompleteIndBody_s {
        uint32_t   Status;
} WsmHiJoinCompleteIndBody_t;

typedef struct __attribute__((__packed__)) WsmHiBssFlags_s {
        uint8_t    LostCountOnly : 1;
        uint8_t    Reserved : 7;
} WsmHiBssFlags_t;

typedef struct __attribute__((__packed__)) WsmHiSetBssParamsReqBody_s {
        WsmHiBssFlags_t BssFlags;
        uint8_t    BeaconLostCount;
        uint16_t   AID;
        uint32_t   OperationalRateSet;
} WsmHiSetBssParamsReqBody_t;

typedef struct __attribute__((__packed__)) WsmHiSetBssParamsCnfBody_s {
        uint32_t   Status;
} WsmHiSetBssParamsCnfBody_t;

typedef struct __attribute__((__packed__)) WsmHiPmMode_s {
        uint8_t    EnterPsm : 1;
        uint8_t    Reserved : 6;
        uint8_t    FastPsm : 1;
} WsmHiPmMode_t;

typedef struct __attribute__((__packed__)) WsmHiSetPmModeReqBody_s {
        WsmHiPmMode_t PmMode;
        uint8_t    FastPsmIdlePeriod;
        uint8_t    ApPsmChangePeriod;
        uint8_t    MinAutoPsPollPeriod;
} WsmHiSetPmModeReqBody_t;

typedef struct __attribute__((__packed__)) WsmHiSetPmModeCnfBody_s {
        uint32_t   Status;
} WsmHiSetPmModeCnfBody_t;

typedef struct __attribute__((__packed__)) WsmHiSetPmModeCmplIndBody_s {
        uint32_t   Status;
        uint8_t    PmMode;
        uint8_t    Reserved[3];
} WsmHiSetPmModeCmplIndBody_t;


typedef struct __attribute__((__packed__)) WsmHiStartReqBody_s {
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
} WsmHiStartReqBody_t;

typedef struct __attribute__((__packed__)) WsmHiStartCnfBody_s {
        uint32_t   Status;
} WsmHiStartCnfBody_t;

typedef enum WsmBeacon_e {
        WSM_BEACON_STOP                       = 0x0,
        WSM_BEACON_START                      = 0x1
} WsmBeacon;

typedef struct __attribute__((__packed__)) WsmHiBeaconTransmitReqBody_s {
        uint8_t    EnableBeaconing;
        uint8_t    Reserved[3];
} WsmHiBeaconTransmitReqBody_t;

typedef struct __attribute__((__packed__)) WsmHiBeaconTransmitCnfBody_s {
        uint32_t   Status;
} WsmHiBeaconTransmitCnfBody_t;

typedef enum WsmStaMapDirection_e {
        WSM_STA_MAP                       = 0x0,
        WSM_STA_UNMAP                     = 0x1
} WsmStaMapDirection;

typedef struct __attribute__((__packed__)) WsmHiMapLinkFlags_s {
        uint8_t    MapDirection : 1;
        uint8_t    Mfpc : 1;
        uint8_t    Reserved : 6;
} WsmHiMapLinkFlags_t;

typedef struct __attribute__((__packed__)) WsmHiMapLinkReqBody_s {
        uint8_t    MacAddr[WSM_API_MAC_ADDR_SIZE];
        WsmHiMapLinkFlags_t MapLinkFlags;
        uint8_t    PeerStaId;
} WsmHiMapLinkReqBody_t;

typedef struct __attribute__((__packed__)) WsmHiMapLinkCnfBody_s {
        uint32_t   Status;
} WsmHiMapLinkCnfBody_t;

typedef struct __attribute__((__packed__)) WsmHiSuspendResumeFlags_s {
        uint8_t    Resume : 1;
        uint8_t    Ac : 2;
        uint8_t    BcMcOnly : 1;
        uint8_t    Reserved1 : 4;
        uint8_t    Reserved2;
} WsmHiSuspendResumeFlags_t;

#define WSM_API_TX_RESUME_FLAGS_PER_IF_SIZE             3

typedef struct __attribute__((__packed__)) WsmHiSuspendResumeTxIndBody_s {
        WsmHiSuspendResumeFlags_t SuspendResumeFlags;
        uint16_t   					TxResumeFlagsPerIf;
} WsmHiSuspendResumeTxIndBody_t;


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

typedef struct __attribute__((__packed__)) WsmHiWepPairwiseKey_s {
        uint8_t    PeerAddress[WSM_API_MAC_ADDR_SIZE];
        uint8_t    Reserved;
        uint8_t    KeyLength;
        uint8_t    KeyData[WSM_API_WEP_KEY_DATA_SIZE];
} WsmHiWepPairwiseKey_t;

typedef struct __attribute__((__packed__)) WsmHiWepGroupKey_s {
        uint8_t    KeyId;
        uint8_t    KeyLength;
        uint8_t    Reserved[2];
        uint8_t    KeyData[WSM_API_WEP_KEY_DATA_SIZE];
} WsmHiWepGroupKey_t;

typedef struct __attribute__((__packed__)) WsmHiTkipPairwiseKey_s {
        uint8_t    PeerAddress[WSM_API_MAC_ADDR_SIZE];
        uint8_t    Reserved[2];
        uint8_t    TkipKeyData[WSM_API_TKIP_KEY_DATA_SIZE];
        uint8_t    RxMicKey[WSM_API_RX_MIC_KEY_SIZE];
        uint8_t    TxMicKey[WSM_API_TX_MIC_KEY_SIZE];
} WsmHiTkipPairwiseKey_t;

typedef struct __attribute__((__packed__)) WsmHiTkipGroupKey_s {
        uint8_t    TkipKeyData[WSM_API_TKIP_KEY_DATA_SIZE];
        uint8_t    RxMicKey[WSM_API_RX_MIC_KEY_SIZE];
        uint8_t    KeyId;
        uint8_t    Reserved[3];
        uint8_t    RxSequenceCounter[WSM_API_RX_SEQUENCE_COUNTER_SIZE];
} WsmHiTkipGroupKey_t;

typedef struct __attribute__((__packed__)) WsmHiAesPairwiseKey_s {
        uint8_t    PeerAddress[WSM_API_MAC_ADDR_SIZE];
        uint8_t    Reserved[2];
        uint8_t    AesKeyData[WSM_API_AES_KEY_DATA_SIZE];
} WsmHiAesPairwiseKey_t;

typedef struct __attribute__((__packed__)) WsmHiAesGroupKey_s {
        uint8_t    AesKeyData[WSM_API_AES_KEY_DATA_SIZE];
        uint8_t    KeyId;
        uint8_t    Reserved[3];
        uint8_t    RxSequenceCounter[WSM_API_RX_SEQUENCE_COUNTER_SIZE];
} WsmHiAesGroupKey_t;

typedef struct __attribute__((__packed__)) WsmHiWapiPairwiseKey_s {
        uint8_t    PeerAddress[WSM_API_MAC_ADDR_SIZE];
        uint8_t    KeyId;
        uint8_t    Reserved;
        uint8_t    WapiKeyData[WSM_API_WAPI_KEY_DATA_SIZE];
        uint8_t    MicKeyData[WSM_API_MIC_KEY_DATA_SIZE];
} WsmHiWapiPairwiseKey_t;

typedef struct __attribute__((__packed__)) WsmHiWapiGroupKey_s {
        uint8_t    WapiKeyData[WSM_API_WAPI_KEY_DATA_SIZE];
        uint8_t    MicKeyData[WSM_API_MIC_KEY_DATA_SIZE];
        uint8_t    KeyId;
        uint8_t    Reserved[3];
} WsmHiWapiGroupKey_t;

typedef struct __attribute__((__packed__)) WsmHiIgtkGroupKey_s {
        uint8_t    IGTKKeyData[WSM_API_IGTK_KEY_DATA_SIZE];
        uint8_t    KeyId;
        uint8_t    Reserved[3];
        uint8_t    IPN[WSM_API_IPN_SIZE];
} WsmHiIgtkGroupKey_t;

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

typedef struct __attribute__((__packed__)) WsmHiAddKeyReqBody_s {
        uint8_t    Type;
        uint8_t    EntryIndex;
        uint16_t   Reserved;
        WsmPrivacyKeyData_t Key;
} WsmHiAddKeyReqBody_t;

typedef struct __attribute__((__packed__)) WsmHiAddKeyCnfBody_s {
        uint32_t   Status;
} WsmHiAddKeyCnfBody_t;

typedef struct __attribute__((__packed__)) WsmHiRemoveKeyReqBody_s {
        uint8_t    EntryIndex;
        uint8_t    Reserved[3];
} WsmHiRemoveKeyReqBody_t;

typedef struct __attribute__((__packed__)) WsmHiRemoveKeyCnfBody_s {
        uint32_t   Status;
} WsmHiRemoveKeyCnfBody_t;

typedef enum WsmEventInd_e {
        WSM_EVENT_IND_BSSLOST                      = 0x1,
        WSM_EVENT_IND_BSSREGAINED                  = 0x2,
        WSM_EVENT_IND_RCPI_RSSI                    = 0x3,
        WSM_EVENT_IND_PS_MODE_ERROR                = 0x4,
		WSM_EVENT_IND_INACTIVITY                   = 0x5
} WsmEventInd;

typedef enum WsmPsModeError_e {
		WSM_PS_ERROR_NO_ERROR	                   = 0,
		WSM_PS_ERROR_AP_NOT_RESP_TO_POLL	       = 1,
		WSM_PS_ERROR_AP_NOT_RESP_TO_UAPSD_TRIGGER  = 2,
		WSM_PS_ERROR_AP_SENT_UNICAST_IN_DOZE       = 3,
		WSM_PS_ERROR_AP_NO_DATA_AFTER_TIM          = 4
} WsmPsModeError;

typedef union WsmEventData_u {
        uint8_t 					RcpiRssi;
        uint32_t 					P_S_Mode_Error;
        uint32_t					PeerStaId;
} WsmEventData_t;

typedef struct __attribute__((__packed__)) WsmHiEventIndBody_s {
        uint32_t   EventId;
        WsmEventData_t EventData;
} WsmHiEventIndBody_t;


#endif
