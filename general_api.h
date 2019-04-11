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

#ifndef _GENERAL_API_H_
#define _GENERAL_API_H_

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#define HI_API_VERSION_MINOR                0x00
#define HI_API_VERSION_MAJOR                0x01

#define API_VARIABLE_SIZE_ARRAY_DUMMY_SIZE  1
#define API_MAC_ADDR_SIZE                   6

#define GENERAL_INTERFACE_ID                2

#define HI_MSG_ID_MASK                      0x00FF
#define HI_MSG_TYPE_MASK                    0x0080
#define HI_MSG_SEQ_RANGE                    0x0007

#define HI_REQ_BASE                         0x00
#define HI_CNF_BASE                         0x00
#define HI_IND_BASE                         HI_MSG_TYPE_MASK

typedef enum ApiRateIndex_e {
	API_RATE_INDEX_B_1MBPS                   = 0,
	API_RATE_INDEX_B_2MBPS                   = 1,
	API_RATE_INDEX_B_5P5MBPS                 = 2,
	API_RATE_INDEX_B_11MBPS                  = 3,
	API_RATE_INDEX_PBCC_22MBPS               = 4,
	API_RATE_INDEX_PBCC_33MBPS               = 5,
	API_RATE_INDEX_G_6MBPS                   = 6,
	API_RATE_INDEX_G_9MBPS                   = 7,
	API_RATE_INDEX_G_12MBPS                  = 8,
	API_RATE_INDEX_G_18MBPS                  = 9,
	API_RATE_INDEX_G_24MBPS                  = 10,
	API_RATE_INDEX_G_36MBPS                  = 11,
	API_RATE_INDEX_G_48MBPS                  = 12,
	API_RATE_INDEX_G_54MBPS                  = 13,
	API_RATE_INDEX_N_6P5MBPS                 = 14,
	API_RATE_INDEX_N_13MBPS                  = 15,
	API_RATE_INDEX_N_19P5MBPS                = 16,
	API_RATE_INDEX_N_26MBPS                  = 17,
	API_RATE_INDEX_N_39MBPS                  = 18,
	API_RATE_INDEX_N_52MBPS                  = 19,
	API_RATE_INDEX_N_58P5MBPS                = 20,
	API_RATE_INDEX_N_65MBPS                  = 21,
	API_RATE_NUM_ENTRIES                     = 22
} ApiRateIndex;

typedef struct U16msginfo_s {
	uint8_t Id :7;
	uint8_t MsgType :1;
	uint8_t Reserved :1;
	uint8_t IntId :2;
	uint8_t HostCount :3;
	uint8_t SecLink :2;
} __packed U16msginfo_t;

typedef struct MsginfoBytes_s {
	uint8_t MsgId;
	uint8_t MsgInfo;
} MsginfoBytes_t;

typedef union  MsginfoUnion_u {
	uint16_t U16MsgInfo;
	MsginfoBytes_t t;
	U16msginfo_t b;
} MsginfoUnion_t;

typedef struct HiMsgHdr_s {
	uint16_t    MsgLen;
	MsginfoUnion_t s;
} __packed HiMsgHdr_t ;

typedef enum HiGeneralRequestsIds_e {
	HI_CONFIGURATION_REQ_ID                         = 0x09,
	HI_CONTROL_GPIO_REQ_ID                          = 0x26,
	HI_SET_SL_MAC_KEY_REQ_ID                        = 0x27,
	HI_SL_EXCHANGE_PUB_KEYS_REQ_ID                  = 0x28,
	HI_SL_CONFIGURE_REQ_ID                          = 0x29,
	HI_PREVENT_ROLLBACK_REQ_ID                      = 0x2a,
	HI_SHUT_DOWN_REQ_ID                             = 0x32,
} HiGeneralRequestsIds;

typedef enum HiGeneralConfirmationsIds_e {
	HI_CONFIGURATION_CNF_ID                         = 0x09,
	HI_CONTROL_GPIO_CNF_ID                          = 0x26,
	HI_SET_SL_MAC_KEY_CNF_ID                        = 0x27,
	HI_SL_EXCHANGE_PUB_KEYS_CNF_ID                  = 0x28,
	HI_SL_CONFIGURE_CNF_ID                          = 0x29,
	HI_PREVENT_ROLLBACK_CNF_ID                      = 0xe7,
} HiGeneralConfirmationsIds;

typedef enum HiGeneralIndicationsIds_e {
	HI_EXCEPTION_IND_ID                             = 0xe0,
	HI_STARTUP_IND_ID                               = 0xe1,
	HI_GENERIC_IND_ID                               = 0xe3,
	HI_ERROR_IND_ID                                 = 0xe4
} HiGeneralIndicationsIds;

typedef union HiGeneralCommandsIds_u {
	HiGeneralRequestsIds request;
	HiGeneralConfirmationsIds confirmation;
	HiGeneralIndicationsIds indication;
} HiGeneralCommandsIds_t;

typedef enum HiStatus_e {
	HI_STATUS_SUCCESS                         = 0x0,
	HI_STATUS_FAILURE                         = 0x1,
	HI_INVALID_PARAMETER                      = 0x2,
	HI_STATUS_GPIO_WARNING                    = 0x3,
	HI_ERROR_UNSUPPORTED_MSG_ID               = 0x4,

	SL_MAC_KEY_STATUS_SUCCESS                     = 0x5A,
	SL_MAC_KEY_STATUS_FAILED_KEY_ALREADY_BURNED   = 0x6B,
	SL_MAC_KEY_STATUS_FAILED_RAM_MODE_NOT_ALLOWED = 0x7C,
	SL_MAC_KEY_STATUS_FAILED_UNKNOWN_MODE         = 0x8D,
	SL_PUB_KEY_EXCHANGE_STATUS_SUCCESS            = 0x9E,
	SL_PUB_KEY_EXCHANGE_STATUS_FAILED             = 0xAF,

	PREVENT_ROLLBACK_CNF_SUCCESS                = 0x1234,
	PREVENT_ROLLBACK_CNF_WRONG_MAGIC_WORD       = 0x1256
} HiStatus;


typedef enum HiFwType_e {
	HI_FW_TYPE_ETF                             = 0x0,
	HI_FW_TYPE_WFM                             = 0x1,
	HI_FW_TYPE_WSM                             = 0x2
} HiFwType;

typedef struct HiCapabilities_s {
	uint8_t    LinkMode : 2;
	uint8_t    Reserved1: 6;
	uint8_t    Reserved2;
	uint8_t    Reserved3;
	uint8_t    Reserved4;
} __packed HiCapabilities_t;

typedef struct HiOtpRegulSelModeInfo_s {
	uint8_t    RegionSelMode:4;
	uint8_t    Reserved:4;
} __packed HiOtpRegulSelModeInfo_t;

typedef struct HiOtpPhyInfo_s {
	uint8_t    Phy1Region:3;
	uint8_t    Phy0Region:3;
	uint8_t    OtpPhyVer:2;
} __packed HiOtpPhyInfo_t;

#define API_OPN_SIZE                                    14
#define API_UID_SIZE                                    8
#define API_DISABLED_CHANNEL_LIST_SIZE                  2
#define API_FIRMWARE_LABEL_SIZE                         128

typedef struct HiStartupIndBody_s {
	uint32_t   Status;
	uint16_t   HardwareId;
	uint8_t    OPN[API_OPN_SIZE];
	uint8_t    UID[API_UID_SIZE];
	uint16_t   NumInpChBufs;
	uint16_t   SizeInpChBuf;
	uint8_t    NumLinksAP;
	uint8_t    NumInterfaces;
	uint8_t    MacAddr[2][API_MAC_ADDR_SIZE];
	uint8_t    ApiVersionMinor;
	uint8_t    ApiVersionMajor;
	HiCapabilities_t Capabilities;
	uint8_t    FirmwareBuild;
	uint8_t    FirmwareMinor;
	uint8_t    FirmwareMajor;
	uint8_t    FirmwareType;
	uint8_t    DisabledChannelList[API_DISABLED_CHANNEL_LIST_SIZE];
	HiOtpRegulSelModeInfo_t RegulSelModeInfo;
	HiOtpPhyInfo_t OtpPhyInfo;
	uint32_t   SupportedRateMask;
	uint8_t    FirmwareLabel[API_FIRMWARE_LABEL_SIZE];
} __packed HiStartupIndBody_t;

typedef struct HiConfigurationReqBody_s {
	uint16_t   Length;
	uint8_t    PdsData[0];
} __packed HiConfigurationReqBody_t;

typedef struct HiConfigurationCnfBody_s {
	uint32_t   Status;
} __packed HiConfigurationCnfBody_t;

typedef enum HiGpioMode_e {
	HI_GPIO_MODE_D0                            = 0x0,
	HI_GPIO_MODE_D1                            = 0x1,
	HI_GPIO_MODE_OD0                           = 0x2,
	HI_GPIO_MODE_OD1                           = 0x3,
	HI_GPIO_MODE_TRISTATE                      = 0x4,
	HI_GPIO_MODE_TOGGLE                        = 0x5,
	HI_GPIO_MODE_READ                          = 0x6
} HiGpioMode;

typedef struct HiControlGpioReqBody_s {
	uint8_t GpioLabel;
	uint8_t GpioMode;
} __packed HiControlGpioReqBody_t;

typedef enum HiGpioError_e {
	HI_GPIO_ERROR_0                            = 0x0,
	HI_GPIO_ERROR_1                            = 0x1,
	HI_GPIO_ERROR_2                            = 0x2
} HiGpioError;

typedef struct HiControlGpioCnfBody_s {
	uint32_t Status;
	uint32_t Value;
} __packed HiControlGpioCnfBody_t;

typedef enum HiGenericIndicationType_e {
	HI_GENERIC_INDICATION_TYPE_RAW               = 0x0,
	HI_GENERIC_INDICATION_TYPE_STRING            = 0x1,
	HI_GENERIC_INDICATION_TYPE_RX_STATS          = 0x2
} HiGenericIndicationType;

#define API_NB_RX_BY_RATE_SIZE                          22
#define API_PER_SIZE                                    22
#define API_SNR_SIZE                                    22
#define API_RSSI_SIZE                                   22
#define API_CFO_SIZE                                    22

typedef struct HiRxStats_s {
	uint32_t   NbRxFrame;
	uint32_t   NbCrcFrame;
	uint32_t   PerTotal;
	uint32_t   Throughput;
	uint32_t   NbRxByRate[API_NB_RX_BY_RATE_SIZE];
	uint16_t   Per[API_PER_SIZE];
	int16_t    Snr[API_SNR_SIZE];
	int16_t    Rssi[API_RSSI_SIZE];
	int16_t    Cfo[API_CFO_SIZE];
	uint32_t   Date;
	uint32_t   PwrClkFreq;
	uint8_t    IsExtPwrClk;
} __packed HiRxStats_t;

#define MAX_GENERIC_INDICATION_DATA_SIZE              376
typedef union HiIndicationData_u {
	HiRxStats_t                                   RxStats;
	uint8_t                                       RawData[MAX_GENERIC_INDICATION_DATA_SIZE];
} HiIndicationData_t;

typedef struct HiGenericIndBody_s {
	uint32_t IndicationType;
	HiIndicationData_t IndicationData;
} __packed HiGenericIndBody_t;

typedef enum WsmHiDbg_e {
	WSM_HI_DBG_UNDEF_INST                      = 0x0,
	WSM_HI_DBG_PREFETCH_ABORT                  = 0x1,
	WSM_HI_DBG_DATA_ABORT                      = 0x2,
	WSM_HI_DBG_UNKNOWN_ERROR                   = 0x3,
	WSM_HI_DBG_ASSERT                          = 0x4
} WsmHiDbg;

#define HI_EXCEPTION_DATA_SIZE            80
typedef struct HiExceptionIndBody_s {
	uint8_t    Data[HI_EXCEPTION_DATA_SIZE];
} __packed HiExceptionIndBody_t;

typedef enum WsmHiError_e {
	WSM_HI_ERROR_FIRMWARE_ROLLBACK             = 0x0,
	WSM_HI_ERROR_FIRMWARE_DEBUG_ENABLED        = 0x1,
	WSM_HI_ERROR_OUTDATED_SESSION_KEY          = 0x2,
	WSM_HI_ERROR_INVALID_SESSION_KEY           = 0x3,
	WSM_HI_ERROR_OOR_VOLTAGE                   = 0x4,
	WSM_HI_ERROR_PDS_VERSION                   = 0x5
} WsmHiError;

#define API_DATA_SIZE_124                               124
typedef struct HiErrorIndBody_s {
	uint32_t   Type;
	uint8_t    Data[API_DATA_SIZE_124];
} __packed HiErrorIndBody_t;

typedef enum SecureLinkState_e {
	SECURE_LINK_NA_MODE                        = 0x0,
	SECURE_LINK_UNTRUSTED_MODE                 = 0x1,
	SECURE_LINK_TRUSTED_MODE                   = 0x2,
	SECURE_LINK_TRUSTED_ACTIVE_ENFORCED        = 0x3
} SecureLinkState;

typedef enum SlMacKeyDest_e {
	SL_MAC_KEY_DEST_OTP                        = 0x78,
	SL_MAC_KEY_DEST_RAM                        = 0x87
} SlMacKeyDest;

#define API_KEY_VALUE_SIZE      32

typedef struct HiSetSlMacKeyReqBody_s {
	uint8_t    OtpOrRam;
	uint8_t    KeyValue[API_KEY_VALUE_SIZE];
} __packed HiSetSlMacKeyReqBody_t;

typedef struct HiSetSlMacKeyCnfBody_s {
	uint32_t   Status;
} __packed HiSetSlMacKeyCnfBody_t;

#define API_HOST_PUB_KEY_SIZE                           32
#define API_HOST_PUB_KEY_MAC_SIZE                       64

typedef struct HiSlExchangePubKeysReqBody_s {
	uint8_t    HostPubKey[API_HOST_PUB_KEY_SIZE];
	uint8_t    HostPubKeyMac[API_HOST_PUB_KEY_MAC_SIZE];
} __packed HiSlExchangePubKeysReqBody_t;

#define API_NCP_PUB_KEY_SIZE                            32
#define API_NCP_PUB_KEY_MAC_SIZE                        64

typedef struct HiSlExchangePubKeysCnfBody_s {
	uint32_t   Status;
	uint8_t    NcpPubKey[API_NCP_PUB_KEY_SIZE];
	uint8_t    NcpPubKeyMac[API_NCP_PUB_KEY_MAC_SIZE];
} __packed HiSlExchangePubKeysCnfBody_t;

typedef enum SlConfigureSkeyInvld_e {
	SL_CONFIGURE_SKEY_INVLD_INVALIDATE         = 0x87,
	SL_CONFIGURE_SKEY_INVLD_NOP                = 0x00
} SlConfigureSkeyInvld;

#define API_ENCR_BMP_SIZE        32

typedef struct HiSlConfigureReqBody_s {
	uint8_t    EncrBmp[API_ENCR_BMP_SIZE];
	uint8_t    SkeyInvld;
} __packed HiSlConfigureReqBody_t;

#define API_NCP_ENCR_BMP_SIZE      32

typedef struct HiSlConfigureCnfBody_s {
	uint32_t Status;
} __packed HiSlConfigureCnfBody_t;

typedef struct HiPreventRollbackReqBody_s {
	uint32_t   MagicWord;
} __packed HiPreventRollbackReqBody_t;

typedef struct HiPreventRollbackCnfBody_s {
	uint32_t    Status;
} __packed HiPreventRollbackCnfBody_t;

#endif
