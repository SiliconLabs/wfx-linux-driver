

#ifndef _GENERAL_API_H_
#define _GENERAL_API_H_

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#define HI_API_VERSION_MINOR							0x00
#define HI_API_VERSION_MAJOR							0x01

#define API_VARIABLE_SIZE_ARRAY_DUMMY_SIZE  1
#define API_MAC_ADDR_SIZE                   6

#define GENERAL_INTERFACE_ID                2

#define HI_MSG_ID_MASK	      				0x00FF
#define HI_MSG_TYPE_MASK					0x80
#define HI_MSG_SEQ_RANGE	    			0x0007

#define HI_REQ_BASE		 					0x00
#define HI_CNF_BASE		 					0x00
#define HI_IND_BASE		 					HI_MSG_TYPE_MASK

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

typedef struct __attribute__((__packed__)) U16msginfo_s {
	uint8_t Id :7;
	uint8_t MsgType :1;
	uint8_t Reserved :1;
	uint8_t IntId :2;
	uint8_t HostCount :3;
	uint8_t SecLink :2;
} U16msginfo_t;

typedef struct MsginfoBytes_s {
	uint8_t MsgId;
	uint8_t MsgInfo;
} MsginfoBytes_t;

typedef union  MsginfoUnion_u {
    uint16_t U16MsgInfo;
    MsginfoBytes_t t;
    U16msginfo_t b;
} MsginfoUnion_t;

typedef struct __attribute__((__packed__)) HiMsgHdr_s {
        uint16_t    MsgLen;
        MsginfoUnion_t s;
} HiMsgHdr_t ;

typedef struct __attribute__((__packed__)) HiGenericMsg_s {
        HiMsgHdr_t Header;
        uint8_t Body[API_VARIABLE_SIZE_ARRAY_DUMMY_SIZE];
} HiGenericMsg_t;

typedef struct __attribute__((__packed__)) HiGenericCnf_s {
        HiMsgHdr_t  Header;
        uint32_t    Status;
} HiGenericCnf_t;

typedef enum HiGeneralRequestsIds_e {
 HI_CONFIGURATION_REQ_ID                         =0x09,
 HI_CONTROL_GPIO_REQ_ID                          =0x26,
 HI_SET_SL_MAC_KEY_REQ_ID                        =0x27,
 HI_SL_EXCHANGE_PUB_KEYS_REQ_ID                  =0x28,
 HI_SL_CONFIGURE_REQ_ID                          =0x29,
 HI_PREVENT_ROLLBACK_REQ_ID                      =0x2a,
 HI_SHUT_DOWN_REQ_ID                             =0x32,
} HiGeneralRequestsIds;

typedef enum HiGeneralConfirmationsIds_e {
 HI_CONFIGURATION_CNF_ID                         =0x09,
 HI_CONTROL_GPIO_CNF_ID                          =0x26,
 HI_SET_SL_MAC_KEY_CNF_ID                        =0x27,
 HI_SL_EXCHANGE_PUB_KEYS_CNF_ID                  =0x28,
 HI_SL_CONFIGURE_CNF_ID                          =0x29,
 HI_PREVENT_ROLLBACK_CNF_ID                      =0xe7,
} HiGeneralConfirmationsIds;

typedef enum HiGeneralIndicationsIds_e {
 HI_EXCEPTION_IND_ID                             =0xe0,
 HI_STARTUP_IND_ID                               =0xe1,
 HI_GENERIC_IND_ID                               =0xe3,
 HI_ERROR_IND_ID                                 =0xe4
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

        SL_MAC_KEY_STATUS_SUCCESS                     	= 0x5A,
        SL_MAC_KEY_STATUS_FAILED_KEY_ALREADY_BURNED   	= 0x6B,
        SL_MAC_KEY_STATUS_FAILED_RAM_MODE_NOT_ALLOWED 	= 0x7C,
        SL_MAC_KEY_STATUS_FAILED_UNKNOWN_MODE         	= 0x8D,
        SL_PUB_KEY_EXCHANGE_STATUS_SUCCESS        		= 0x9E,
        SL_PUB_KEY_EXCHANGE_STATUS_FAILED         		= 0xAF,

        PREVENT_ROLLBACK_CNF_SUCCESS           			= 0x1234,
        PREVENT_ROLLBACK_CNF_WRONG_MAGIC_WORD 	 		= 0x1256
} HiStatus;


typedef enum HiFwType_e {
        HI_FW_TYPE_ETF                             = 0x0,
        HI_FW_TYPE_WFM                             = 0x1,
        HI_FW_TYPE_WSM                             = 0x2
} HiFwType;

typedef struct __attribute__((__packed__)) HiCapabilities_s {
        uint8_t    LinkMode : 2;
        uint8_t    Reserved1: 6;
        uint8_t    Reserved2;
        uint8_t    Reserved3;
        uint8_t    Reserved4;
} HiCapabilities_t;

typedef struct __attribute__((__packed__)) HiOtpRegulSelModeInfo_s {
        uint8_t    RegionSelMode:4;
        uint8_t    Reserved:4;
} HiOtpRegulSelModeInfo_t;

typedef struct __attribute__((__packed__)) HiOtpPhyInfo_s {
        uint8_t    Phy1Region:3;
        uint8_t    Phy0Region:3;
        uint8_t    OtpPhyVer:2;
} HiOtpPhyInfo_t;

#define API_OPN_SIZE                                    14
#define API_UID_SIZE                                    8
#define API_DISABLED_CHANNEL_LIST_SIZE                  2
#define API_FIRMWARE_LABEL_SIZE                         128

typedef struct __attribute__((__packed__)) HiStartupIndBody_s {
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
} HiStartupIndBody_t;

typedef struct __attribute__((__packed__)) HiStartupInd_s {
        HiMsgHdr_t Header;
        HiStartupIndBody_t Body;
} HiStartupInd_t;

typedef struct __attribute__((__packed__)) HiConfigurationReqBody_s {
        uint16_t   Length;
        uint8_t    PdsData[0];
} HiConfigurationReqBody_t;

typedef struct __attribute__((__packed__)) HiConfigurationReq_s {
        HiMsgHdr_t Header;
        HiConfigurationReqBody_t Body;
} HiConfigurationReq_t;

typedef struct __attribute__((__packed__)) HiConfigurationCnfBody_s {
        uint32_t   Status;
} HiConfigurationCnfBody_t;

typedef struct __attribute__((__packed__)) HiConfigurationCnf_s {
        HiMsgHdr_t Header;
        HiConfigurationCnfBody_t Body;
} HiConfigurationCnf_t;

typedef enum HiGpioMode_e {
        HI_GPIO_MODE_D0                            = 0x0,
        HI_GPIO_MODE_D1                            = 0x1,
        HI_GPIO_MODE_OD0                           = 0x2,
        HI_GPIO_MODE_OD1                           = 0x3,
        HI_GPIO_MODE_TRISTATE                      = 0x4,
        HI_GPIO_MODE_TOGGLE                        = 0x5,
        HI_GPIO_MODE_READ                          = 0x6
} HiGpioMode;

typedef struct __attribute__((__packed__)) HiControlGpioReqBody_s {
	uint8_t GpioLabel;
	uint8_t GpioMode;
} HiControlGpioReqBody_t;

typedef struct __attribute__((__packed__)) HiControlGpioReq_s {
        HiMsgHdr_t Header;
        HiControlGpioReqBody_t Body;
} HiControlGpioReq_t;

typedef enum HiGpioError_e {
        HI_GPIO_ERROR_0                            = 0x0,
        HI_GPIO_ERROR_1                            = 0x1,
        HI_GPIO_ERROR_2                            = 0x2
} HiGpioError;

typedef struct __attribute__((__packed__)) HiControlGpioCnfBody_s {
	uint32_t Status;
	uint32_t Value;
} HiControlGpioCnfBody_t;

typedef struct __attribute__((__packed__)) HiControlGpioCnf_s {
        HiMsgHdr_t Header;
        HiControlGpioCnfBody_t Body;
} HiControlGpioCnf_t;

typedef HiMsgHdr_t HI_SHUT_DOWN_REQ;

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

typedef struct __attribute__((__packed__)) HiRxStats_s {
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
} HiRxStats_t;

#define MAX_GENERIC_INDICATION_DATA_SIZE              376
typedef union HiIndicationData_u {
        HiRxStats_t                                   RxStats;
        uint8_t                                       RawData[MAX_GENERIC_INDICATION_DATA_SIZE];
} HiIndicationData_t;

typedef struct __attribute__((__packed__)) HiGenericIndBody_s {
        uint32_t IndicationType;
        HiIndicationData_t IndicationData;
} HiGenericIndBody_t;

typedef struct __attribute__((__packed__)) HiGenericInd_s {
        HiMsgHdr_t Header;
        HiGenericIndBody_t Body;
} HiGenericInd_t;

typedef enum WsmHiDbg_e {
        WSM_HI_DBG_UNDEF_INST                      = 0x0,
        WSM_HI_DBG_PREFETCH_ABORT                  = 0x1,
        WSM_HI_DBG_DATA_ABORT                      = 0x2,
        WSM_HI_DBG_UNKNOWN_ERROR                   = 0x3,
        WSM_HI_DBG_ASSERT                          = 0x4
} WsmHiDbg;

#define HI_EXCEPTION_DATA_SIZE            80
typedef struct __attribute__((__packed__)) HiExceptionIndBody_s {
        uint8_t    Data[HI_EXCEPTION_DATA_SIZE];
} HiExceptionIndBody_t;

typedef struct __attribute__((__packed__)) HiExceptionInd_s {
        HiMsgHdr_t Header;
        HiExceptionIndBody_t Body;
} HiExceptionInd_t;

typedef enum WsmHiError_e {
        WSM_HI_ERROR_FIRMWARE_ROLLBACK             = 0x0,
        WSM_HI_ERROR_FIRMWARE_DEBUG_ENABLED        = 0x1,
        WSM_HI_ERROR_OUTDATED_SESSION_KEY          = 0x2,
        WSM_HI_ERROR_INVALID_SESSION_KEY           = 0x3,
		WSM_HI_ERROR_OOR_VOLTAGE                   = 0x4,
		WSM_HI_ERROR_PDS_VERSION                   = 0x5
} WsmHiError;

#define API_DATA_SIZE_124                               124
typedef struct __attribute__((__packed__)) HiErrorIndBody_s {
        uint32_t   Type;
        uint8_t    Data[API_DATA_SIZE_124];
} HiErrorIndBody_t;

typedef struct __attribute__((__packed__)) HiErrorInd_s {
        HiMsgHdr_t Header;
        HiErrorIndBody_t Body;
} HiErrorInd_t;

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

typedef struct __attribute__((__packed__)) HiSetSlMacKeyReqBody_s {
        uint8_t    OtpOrRam;
        uint8_t    KeyValue[API_KEY_VALUE_SIZE];
} HiSetSlMacKeyReqBody_t;

typedef struct __attribute__((__packed__)) HiSetSlMacKeyReq_s {
        HiMsgHdr_t Header;
        HiSetSlMacKeyReqBody_t Body;
} HiSetSlMacKeyReq_t;

typedef struct __attribute__((__packed__)) HiSetSlMacKeyCnfBody_s {
        uint32_t   Status;
} HiSetSlMacKeyCnfBody_t;

typedef struct __attribute__((__packed__)) HiSetSlMacKeyCnf_s {
        HiMsgHdr_t Header;
        HiSetSlMacKeyCnfBody_t Body;
} HiSetSlMacKeyCnf_t;

#define API_HOST_PUB_KEY_SIZE                           32
#define API_HOST_PUB_KEY_MAC_SIZE                       64

typedef struct __attribute__((__packed__)) HiSlExchangePubKeysReqBody_s {
        uint8_t    HostPubKey[API_HOST_PUB_KEY_SIZE];
        uint8_t    HostPubKeyMac[API_HOST_PUB_KEY_MAC_SIZE];
} HiSlExchangePubKeysReqBody_t;

typedef struct __attribute__((__packed__)) HiSlExchangePubKeysReq_s {
        HiMsgHdr_t Header;
        HiSlExchangePubKeysReqBody_t Body;
} HiSlExchangePubKeysReq_t;

#define API_NCP_PUB_KEY_SIZE                            32
#define API_NCP_PUB_KEY_MAC_SIZE                        64

typedef struct __attribute__((__packed__)) HiSlExchangePubKeysCnfBody_s {
        uint32_t   Status;
        uint8_t    NcpPubKey[API_NCP_PUB_KEY_SIZE];
        uint8_t    NcpPubKeyMac[API_NCP_PUB_KEY_MAC_SIZE];
} HiSlExchangePubKeysCnfBody_t;

typedef struct __attribute__((__packed__)) HiSlExchangePubKeysCnf_s {
        HiMsgHdr_t Header;
        HiSlExchangePubKeysCnfBody_t Body;
} HiSlExchangePubKeysCnf_t;

typedef enum SlConfigureSkeyInvld_e {
        SL_CONFIGURE_SKEY_INVLD_INVALIDATE         = 0x87,
        SL_CONFIGURE_SKEY_INVLD_NOP                = 0x00
} SlConfigureSkeyInvld;

#define API_ENCR_BMP_SIZE        32

typedef struct __attribute__((__packed__)) HiSlConfigureReqBody_s {
        uint8_t    EncrBmp[API_ENCR_BMP_SIZE];
        uint8_t    SkeyInvld;
} HiSlConfigureReqBody_t;

typedef struct __attribute__((__packed__)) HiSlConfigureReq_s {
        HiMsgHdr_t Header;
        HiSlConfigureReqBody_t Body;
} HiSlConfigureReq_t;

#define API_NCP_ENCR_BMP_SIZE      32

typedef struct __attribute__((__packed__)) HiSlConfigureCnfBody_s {
        uint32_t Status;
} HiSlConfigureCnfBody_t;

typedef struct __attribute__((__packed__)) HiSlConfigureCnf_s {
        HiMsgHdr_t Header;
        HiSlConfigureCnfBody_t Body;
} HiSlConfigureCnf_t;

typedef struct __attribute__((__packed__)) HiPreventRollbackReqBody_s {
        uint32_t   MagicWord;
} HiPreventRollbackReqBody_t;

typedef struct __attribute__((__packed__)) HiPreventRollbackReq_s {
        HiMsgHdr_t Header;
        HiPreventRollbackReqBody_t Body;
} HiPreventRollbackReq_t;

typedef struct __attribute__((__packed__)) HiPreventRollbackCnfBody_s {
        uint32_t    Status;
} HiPreventRollbackCnfBody_t;

typedef struct __attribute__((__packed__)) HiPreventRollbackCnf_s {
        HiMsgHdr_t Header;
        HiPreventRollbackCnfBody_t Body;
} HiPreventRollbackCnf_t;

#endif
