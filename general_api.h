/* SPDX-License-Identifier: Apache-2.0 */
/*
 * WFx hardware interface definitions
 *
 * Copyright (c) 2018-2019, Silicon Laboratories Inc.
 */

#ifndef _GENERAL_API_H_
#define _GENERAL_API_H_

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <net/ethernet.h>
#include <stdint.h>
#define __packed __attribute__((__packed__))
#endif

#define HI_API_VERSION_MINOR                0x00
#define HI_API_VERSION_MAJOR                0x01

#define GENERAL_INTERFACE_ID                2

#define HI_MSG_ID_MASK                      0x00FF
#define HI_MSG_SEQ_RANGE                    0x0007

#define HI_REQ_BASE                         0x00
#define HI_CNF_BASE                         0x00
#define HI_IND_BASE                         0x80

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

#define WMSG_ID_IS_INDICATION               0x80
#define WMSG_COUNTER_MAX                    7
#define WMSG_ENCRYPTED_ENABLE               3
struct wmsg {
	uint16_t    len;
	uint8_t     id;
	uint8_t     reserved:1;
	uint8_t     interface:2;
	uint8_t     seqnum:3;
	uint8_t     encrypted:2;
	uint8_t     body[];
} __packed;

typedef enum HiGeneralRequestsIds_e {
	HI_CONFIGURATION_REQ_ID                         = 0x09,
	HI_CONTROL_GPIO_REQ_ID                          = 0x26,
	HI_SET_SL_MAC_KEY_REQ_ID                        = 0x27,
	HI_SL_EXCHANGE_PUB_KEYS_REQ_ID                  = 0x28,
	HI_SL_CONFIGURE_REQ_ID                          = 0x29,
	HI_PREVENT_ROLLBACK_REQ_ID                      = 0x2a,
	HI_PTA_SETTINGS_REQ_ID                          = 0x2b,
	HI_PTA_PRIORITY_REQ_ID                          = 0x2c,
	HI_PTA_STATE_REQ_ID                             = 0x2d,
	HI_SHUT_DOWN_REQ_ID                             = 0x32,
} HiGeneralRequestsIds;

typedef enum HiGeneralConfirmationsIds_e {
	HI_CONFIGURATION_CNF_ID                         = 0x09,
	HI_CONTROL_GPIO_CNF_ID                          = 0x26,
	HI_SET_SL_MAC_KEY_CNF_ID                        = 0x27,
	HI_SL_EXCHANGE_PUB_KEYS_CNF_ID                  = 0x28,
	HI_SL_CONFIGURE_CNF_ID                          = 0x29,
	HI_PREVENT_ROLLBACK_CNF_ID                      = 0x2a,
	HI_PTA_SETTINGS_CNF_ID                          = 0x2b,
	HI_PTA_PRIORITY_CNF_ID                          = 0x2c,
	HI_PTA_STATE_CNF_ID                             = 0x2d,
	HI_SHUT_DOWN_CNF_ID                             = 0x32,
} HiGeneralConfirmationsIds;

typedef enum HiGeneralIndicationsIds_e {
	HI_EXCEPTION_IND_ID                             = 0xe0,
	HI_STARTUP_IND_ID                               = 0xe1,
	HI_WAKEUP_IND_ID                                = 0xe2,
	HI_GENERIC_IND_ID                               = 0xe3,
	HI_ERROR_IND_ID                                 = 0xe4,
	HI_SL_EXCHANGE_PUB_KEYS_IND_ID                  = 0xe5
} HiGeneralIndicationsIds;

typedef union HiGeneralCommandsIds_u {
	HiGeneralRequestsIds request;
	HiGeneralConfirmationsIds confirmation;
	HiGeneralIndicationsIds indication;
} HiGeneralCommandsIds_t;

typedef enum HiStatus_e {
	HI_STATUS_SUCCESS                             = 0x0000,
	HI_STATUS_FAILURE                             = 0x0001,
	HI_INVALID_PARAMETER                          = 0x0002,
	HI_STATUS_GPIO_WARNING                        = 0x0003,
	HI_ERROR_UNSUPPORTED_MSG_ID                   = 0x0004,
	SL_MAC_KEY_STATUS_SUCCESS                     = 0x005A,
	SL_MAC_KEY_STATUS_FAILED_KEY_ALREADY_BURNED   = 0x006B,
	SL_MAC_KEY_STATUS_FAILED_RAM_MODE_NOT_ALLOWED = 0x007C,
	SL_MAC_KEY_STATUS_FAILED_UNKNOWN_MODE         = 0x008D,
	SL_PUB_KEY_EXCHANGE_STATUS_SUCCESS            = 0x009E,
	SL_PUB_KEY_EXCHANGE_STATUS_FAILED             = 0x00AF,
	PREVENT_ROLLBACK_CNF_SUCCESS                  = 0x1234,
	PREVENT_ROLLBACK_CNF_WRONG_MAGIC_WORD         = 0x1256
} HiStatus;


typedef enum HiFwType_e {
	HI_FW_TYPE_ETF                             = 0x0,
	HI_FW_TYPE_WFM                             = 0x1,
	HI_FW_TYPE_WSM                             = 0x2
} HiFwType;

typedef struct HiCapabilities_s {
	uint8_t    LinkMode:2;
	uint8_t    Reserved1:6;
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
	uint8_t    MacAddr[2][ETH_ALEN];
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

typedef struct HiWakeupIndBody_s {
} __packed HiWakeupIndBody_t;

typedef struct HiConfigurationReqBody_s {
	uint16_t   Length;
	uint8_t    PdsData[];
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

typedef struct HiRxStats_s {
	uint32_t   NbRxFrame;
	uint32_t   NbCrcFrame;
	uint32_t   PerTotal;
	uint32_t   Throughput;
	uint32_t   NbRxByRate[API_RATE_NUM_ENTRIES];
	uint16_t   Per[API_RATE_NUM_ENTRIES];
	int16_t    Snr[API_RATE_NUM_ENTRIES];
	int16_t    Rssi[API_RATE_NUM_ENTRIES];
	int16_t    Cfo[API_RATE_NUM_ENTRIES];
	uint32_t   Date;
	uint32_t   PwrClkFreq;
	uint8_t    IsExtPwrClk;
	int8_t     CurrentTemp;
} __packed HiRxStats_t;

typedef union HiIndicationData_u {
	HiRxStats_t                                   RxStats;
	uint8_t                                       RawData[1];
} HiIndicationData_t;

typedef struct HiGenericIndBody_s {
	uint32_t IndicationType;
	HiIndicationData_t IndicationData;
} __packed HiGenericIndBody_t;


#define HI_EXCEPTION_DATA_SIZE            124

typedef struct HiExceptionIndBody_s {
	uint8_t    Data[HI_EXCEPTION_DATA_SIZE];
} __packed HiExceptionIndBody_t;


typedef enum WsmHiError_e {
	WSM_HI_ERROR_FIRMWARE_ROLLBACK             = 0x0,
	WSM_HI_ERROR_FIRMWARE_DEBUG_ENABLED        = 0x1,
	WSM_HI_ERROR_OUTDATED_SESSION_KEY          = 0x2,
	WSM_HI_ERROR_INVALID_SESSION_KEY           = 0x3,
	WSM_HI_ERROR_OOR_VOLTAGE                   = 0x4,
	WSM_HI_ERROR_PDS_VERSION                   = 0x5,
	WSM_HI_ERROR_OOR_TEMPERATURE               = 0x6,
	WSM_HI_ERROR_REQ_DURING_KEY_EXCHANGE       = 0x7,
	WSM_HI_ERROR_MULTI_TX_CNF_SECURELINK       = 0x8,
	WSM_HI_ERROR_SECURELINK_OVERFLOW           = 0x9,
	WSM_HI_ERROR_SECURELINK_DECRYPTION         = 0xa
} WsmHiError;

typedef struct HiErrorIndBody_s {
	uint32_t   Type;
	uint8_t    Data[];
} __packed HiErrorIndBody_t;

typedef enum SecureLinkState_e {
	SEC_LINK_UNAVAILABLE                    = 0x0,
	SEC_LINK_RESERVED                       = 0x1,
	SEC_LINK_EVAL                           = 0x2,
	SEC_LINK_ENFORCED                       = 0x3
} SecureLinkState;

typedef enum HiSlEncryptionType_e {
	NO_ENCRYPTION = 0,
	TX_ENCRYPTION = 1,
	RX_ENCRYPTION = 2,
	HP_ENCRYPTION = 3
} HiSlEncryptionType;

typedef struct HiSlMsgHdr_s {
	uint32_t    nonce:30;
	uint32_t    encrypted:2;
} __packed HiSlMsgHdr_t ;

typedef struct HiSlMsg_s {
	HiSlMsgHdr_t   Header;
	uint16_t        MsgLen;
	uint8_t         Payload[];
} __packed HiSlMsg_t ;

#define AES_CCM_TAG_SIZE     16

typedef struct HiSlTag_s {
	uint8_t tag[16];
} __packed HiSlTag_t;

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

typedef enum HiSlSessionKeyAlg_e {
	HI_SL_CURVE25519                                = 0x01,
	HI_SL_KDF                                       = 0x02
} HiSlSessionKeyAlg;

typedef struct HiSlExchangePubKeysReqBody_s {
	uint8_t    Algorithm:2;
	uint8_t    Reserved1:6;
	uint8_t    Reserved2[3];
	uint8_t    HostPubKey[API_HOST_PUB_KEY_SIZE];
	uint8_t    HostPubKeyMac[API_HOST_PUB_KEY_MAC_SIZE];
} __packed HiSlExchangePubKeysReqBody_t;

typedef struct HiSlExchangePubKeysCnfBody_s {
	uint32_t   Status;
} __packed HiSlExchangePubKeysCnfBody_t;

#define API_NCP_PUB_KEY_SIZE                            32
#define API_NCP_PUB_KEY_MAC_SIZE                        64

typedef struct HiSlExchangePubKeysIndBody_s {
	uint32_t   Status;
	uint8_t    NcpPubKey[API_NCP_PUB_KEY_SIZE];
	uint8_t    NcpPubKeyMac[API_NCP_PUB_KEY_MAC_SIZE];
} __packed HiSlExchangePubKeysIndBody_t;

#define API_ENCR_BMP_SIZE        32

typedef struct HiSlConfigureReqBody_s {
	uint8_t    EncrBmp[API_ENCR_BMP_SIZE];
	uint8_t    DisableSessionKeyProtection:1;
	uint8_t    Reserved1:7;
	uint8_t    Reserved2[3];
} __packed HiSlConfigureReqBody_t;

typedef struct HiSlConfigureCnfBody_s {
	uint32_t Status;
} __packed HiSlConfigureCnfBody_t;

typedef struct HiPreventRollbackReqBody_s {
	uint32_t   MagicWord;
} __packed HiPreventRollbackReqBody_t;

typedef struct HiPreventRollbackCnfBody_s {
	uint32_t    Status;
} __packed HiPreventRollbackCnfBody_t;

typedef enum HI_PTA_MODES_E {
	PTA_1W_WLAN_MASTER = 0,
	PTA_1W_COEX_MASTER = 1,
	PTA_2W             = 2,
	PTA_3W             = 3,
	PTA_4W             = 4
} HiPtaModeT;

typedef enum HI_SIGNAL_LEVELS_E {
	SIGNAL_LOW  = 0,
	SIGNAL_HIGH = 1
} HiSignalLevelT;

typedef enum HI_COEX_TYPES_E {
	COEX_TYPE_GENERIC = 0,
	COEX_TYPE_BLE     = 1
} HiCoexTypeT;

typedef enum HI_GRANT_STATES_E {
	NO_GRANT = 0,
	GRANT    = 1
} HiGrantStateT;

typedef struct HiPtaSettingsReqBody_s {
	uint8_t PtaMode;
	uint8_t RequestSignalActiveLevel;
	uint8_t PrioritySignalActiveLevel;
	uint8_t FreqSignalActiveLevel;
	uint8_t GrantSignalActiveLevel;
	uint8_t CoexType;
	uint8_t DefaultGrantState;
	uint8_t SimultaneousRxAccesses;
	uint8_t PrioritySamplingTime;
	uint8_t TxRxSamplingTime;
	uint8_t FreqSamplingTime;
	uint8_t GrantValidTime;
	uint8_t FemControlTime;
	uint8_t FirstSlotTime;
	uint16_t PeriodicTxRxSamplingTime;
	uint16_t CoexQuota;
	uint16_t WlanQuota;
} __packed HiPtaSettingsReqBody_t;

typedef struct HiPtaSettingsCnfBody_s {
	uint32_t Status;
} __packed HiPtaSettingsCnfBody_t;

typedef enum HI_PTA_PRIORITY_E {
	HI_PTA_PRIORITY_COEX_MAXIMIZED = 0x00000562,
	HI_PTA_PRIORITY_COEX_HIGH      = 0x00000462,
	HI_PTA_PRIORITY_BALANCED       = 0x00001461,
	HI_PTA_PRIORITY_WLAN_HIGH      = 0x00001851,
	HI_PTA_PRIORITY_WLAN_MAXIMIZED = 0x00001A51
} HiPtaPriorityT;

typedef struct HiPtaPriorityReqBody_s {
	uint32_t Priority;
} __packed HiPtaPriorityReqBody_t;

typedef struct HiPtaPriorityCnfBody_s {
	uint32_t Status;
} __packed HiPtaPriorityCnfBody_t;

typedef enum HI_PTA_STATES_E {
	PTA_OFF = 0,
	PTA_ON  = 1
} HiPtaStateT;

typedef struct HiPtaStateReqBody_s {
	uint32_t PtaState;
} __packed HiPtaStateReqBody_t;

typedef struct HiPtaStateCnfBody_s {
	uint32_t Status;
} __packed HiPtaStateCnfBody_t;

#endif
