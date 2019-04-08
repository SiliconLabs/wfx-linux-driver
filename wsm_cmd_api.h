/***************************************************************************//**
 * @file wsm_cmd_api.h
 * @brief This file contains the type definitions for LMAC API command structures,
 *  enums, and other types.
 *
 * @copyright Copyright 2015 Silicon Laboratories, Inc. http://www.silabs.com
 ******************************************************************************/

#ifndef _WSM_CMD_API_H_
#define _WSM_CMD_API_H_

#include "general_api.h"
#include "wsm_mib_api.h"

/**
 * @addtogroup SPLIT_MAC_API
 * @brief Split MAC API to be used with external UMAC and supplicant like a Linux platform.
 *
 * Commands are formated with the header and body structure as described in \ref MESSAGE_CONSTRUCTION
 *
 *@n
 * \arg Split MAC \b requests are ::HiWsmRequestsIds @n
 * \arg Split MAC \b indications are ::HiWsmIndicationsIds@n
 * \arg Split MAC \b MIB elements are ::WsmMibIds@n
 * @n
 * @{
 */

///Number of Access Categories handled by firmware
#define WSM_NUM_AC                             4

/**
 * @brief Split MAC (LMAC) request message IDs
 *
 * API split mac (LMAC) request message IDs available.
 * These are messages from the host towards the WLAN.
 *
 */
typedef enum HiWsmRequestsIds_e {
WSM_HI_RESET_REQ_ID                             =0x0a,  ///< \b RESET request Id use body ::HI_RESET_REQ_BODY and returns ::HI_RESET_CNF_BODY
WSM_HI_READ_MIB_REQ_ID                          =0x05,  ///< \b READ_MIB request ID use body ::HI_READ_MIB_REQ_BODY and returns ::HI_READ_MIB_CNF_BODY
WSM_HI_WRITE_MIB_REQ_ID                         =0x06,  ///< \b WRITE_MIB request ID use body ::HI_WRITE_MIB_REQ_BODY and returns ::HI_WRITE_MIB_CNF_BODY
WSM_HI_START_SCAN_REQ_ID                        =0x07,  ///< \b START_SCAN request ID use body ::HI_START_SCAN_REQ_BODY and returns ::HI_START_SCAN_CNF_BODY
WSM_HI_STOP_SCAN_REQ_ID                         =0x08,  ///< \b STOP_SCAN request ID use body ::HI_STOP_SCAN_REQ_BODY and returns ::HI_STOP_SCAN_CNF_BODY
WSM_HI_TX_REQ_ID                                =0x04,  ///< \b TX request ID use body ::HI_TX_REQ_BODY and returns ::HI_TX_CNF_BODY
WSM_HI_JOIN_REQ_ID                              =0x0b,  ///< \b JOIN request ID use body ::HI_JOIN_REQ_BODY and returns ::HI_JOIN_CNF_BODY
WSM_HI_SET_PM_MODE_REQ_ID                       =0x10,  ///< \b SET_PM_MODE request ID use body ::HI_SET_PM_MODE_REQ_BODY and returns ::HI_SET_PM_MODE_CNF_BODY
WSM_HI_SET_BSS_PARAMS_REQ_ID                    =0x11,  ///< \b SET_BSS_PARAMS request ID use body ::HI_SET_BSS_PARAMS_REQ_BODY and returns ::HI_SET_BSS_PARAMS_CNF_BODY
WSM_HI_ADD_KEY_REQ_ID                           =0x0c,  ///< \b ADD_KEY request ID use body ::HI_ADD_KEY_REQ_BODY and returns ::HI_ADD_KEY_CNF_BODY
WSM_HI_REMOVE_KEY_REQ_ID                        =0x0d,  ///< \b REMOVE_KEY request ID use body ::HI_REMOVE_KEY_REQ_BODY and returns ::HI_REMOVE_KEY_CNF_BODY
WSM_HI_EDCA_QUEUE_PARAMS_REQ_ID                 =0x13,  ///< \b EDCA_QUEUE_PARAMS request ID use body ::HI_EDCA_QUEUE_PARAMS_REQ_BODY and returns ::HI_EDCA_QUEUE_PARAMS_CNF_BODY
WSM_HI_START_REQ_ID                             =0x17,  ///< \b START request ID use body ::HI_START_REQ_BODY and returns ::HI_START_CNF_BODY
WSM_HI_BEACON_TRANSMIT_REQ_ID                   =0x18,  ///< \b BEACON_TRANSMIT request ID use body ::HI_BEACON_TRANSMIT_REQ_BODY and returns ::HI_BEACON_TRANSMIT_CNF_BODY
WSM_HI_UPDATE_IE_REQ_ID                         =0x1b,  ///< \b UPDATE_IE request ID use body ::HI_UPDATE_IE_REQ_BODY and returns ::HI_UPDATE_IE_CNF_BODY
WSM_HI_MAP_LINK_REQ_ID                          =0x1c,  ///< \b MAP_LINK request ID use body ::HI_MAP_LINK_REQ_BODY and returns ::HI_MAP_LINK_CNF_BODY
} HiWsmRequestsIds;

/**
 * @brief Split MAC (LMAC) confirmation message IDs
 *
 * API split mac (LMAC) confirmation message IDs returned by requests described in ::HiWsmRequestsIds.
 * These are messages from the WLAN towards the host.
 *
 */
typedef enum HiWsmConfirmationsIds_e {
WSM_HI_RESET_CNF_ID                             =0x0a,  ///< \b RESET confirmation Id returns body  ::HI_RESET_CNF_BODY
WSM_HI_READ_MIB_CNF_ID                          =0x05,  ///< \b READ_MIB confirmation Id returns body  ::HI_READ_MIB_CNF_BODY
WSM_HI_WRITE_MIB_CNF_ID                         =0x06,  ///< \b WRITE_MIB confirmation Id returns body  ::HI_WRITE_MIB_CNF_BODY
WSM_HI_START_SCAN_CNF_ID                        =0x07,  ///< \b START_SCAN confirmation Id returns body  ::HI_START_SCAN_CNF_BODY
WSM_HI_STOP_SCAN_CNF_ID                         =0x08,  ///< \b STOP_SCAN confirmation Id returns body  ::HI_STOP_SCAN_CNF_BODY
WSM_HI_TX_CNF_ID                                =0x04,  ///< \b TX confirmation Id returns body  ::HI_TX_CNF_BODY
WSM_HI_MULTI_TRANSMIT_CNF_ID                    =0x1e,  ///< \b MULTI_TRANSMIT confirmation Id returns body  ::HI_MULTI_TRANSMIT_CNF_BODY
WSM_HI_JOIN_CNF_ID                              =0x0b,  ///< \b JOIN confirmation Id returns body  ::HI_JOIN_CNF_BODY
WSM_HI_SET_PM_MODE_CNF_ID                       =0x10,  ///< \b SET_PM_MODE confirmation Id returns body  ::HI_SET_PM_MODE_CNF_BODY
WSM_HI_SET_BSS_PARAMS_CNF_ID                    =0x11,  ///< \b SET_BSS_PARAMS confirmation Id returns body  ::HI_SET_BSS_PARAMS_CNF_BODY
WSM_HI_ADD_KEY_CNF_ID                           =0x0c,  ///< \b ADD_KEY confirmation Id returns body  ::HI_ADD_KEY_CNF_BODY
WSM_HI_REMOVE_KEY_CNF_ID                        =0x0d,  ///< \b REMOVE_KEY confirmation Id returns body  ::HI_REMOVE_KEY_CNF_BODY
WSM_HI_EDCA_QUEUE_PARAMS_CNF_ID                 =0x13,  ///< \b EDCA_QUEUE_PARAMS confirmation Id returns body  ::HI_EDCA_QUEUE_PARAMS_CNF_BODY
WSM_HI_START_CNF_ID                             =0x17,  ///< \b START confirmation Id returns body  ::HI_START_CNF_BODY
WSM_HI_BEACON_TRANSMIT_CNF_ID                   =0x18,  ///< \b BEACON_TRANSMIT confirmation Id returns body  ::HI_BEACON_TRANSMIT_CNF_BODY
WSM_HI_UPDATE_IE_CNF_ID                         =0x1b,  ///< \b UPDATE_IE confirmation Id returns body  ::HI_UPDATE_IE_CNF_BODY
WSM_HI_MAP_LINK_CNF_ID                          =0x1c,  ///< \b MAP_LINK confirmation Id returns body  ::HI_MAP_LINK_CNF_BODY
} HiWsmConfirmationsIds;

/**
 * @brief Split MAC (LMAC) indication message IDs
 *
 * API split mac (LMAC) indication message IDs available.
 * Indication messages are flowing from WLAN device to the host.
 *
 */
typedef enum HiWsmIndicationsIds_e {
WSM_HI_RX_IND_ID								=0x84,
WSM_HI_SCAN_CMPL_IND_ID                         =0x86,  ///< \b SCAN_CMPL indication id. Content is ::HI_SCAN_CMPL_IND_BODY
WSM_HI_JOIN_COMPLETE_IND_ID                     =0x8f,  ///< \b JOIN_COMPLETE indication id. Content is ::HI_JOIN_COMPLETE_IND_BODY
WSM_HI_SET_PM_MODE_CMPL_IND_ID                  =0x89,  ///< \b SET_PM_MODE_CMPL indication id. Content is ::HI_SET_PM_MODE_CMPL_IND_BODY
WSM_HI_SUSPEND_RESUME_TX_IND_ID                 =0x8c,  ///< \b SUSPEND_RESUME_TX indication id. Content is ::HI_SUSPEND_RESUME_TX_IND_BODY
WSM_HI_EVENT_IND_ID                             =0x85   ///< \b EVENT indication id. Content is ::HI_EVENT_IND_BODY
} HiWsmIndicationsIds;

/**
 * @brief Split MAC command message IDs
 *
 * All Split MAC message ids.
 */
typedef union HiWsmCommandsIds_u {
	HiWsmRequestsIds request; ///< Request from the host to the wlan device
	HiWsmConfirmationsIds confirmation; ///< Confirmation of a request from the wlan device to the host
	HiWsmIndicationsIds indication; ///< Indication from the wlan device to the host
} HiWsmCommandsIds_t;


/**************************************************/

/**
 * @brief Split MAC (LMAC) confirmation possible values for returned 'Status' field
 *
 * All Split MAC (LMAC) confirmation messages have a field 'Status' just after the message header.@n
 * A value of zero indicates the request is completed successfully.
 *
 */
typedef enum WsmStatus_e {
        WSM_STATUS_SUCCESS                         = 0x0,         ///<The firmware has successfully completed the request.
        WSM_STATUS_FAILURE                         = 0x1,         ///<This is a generic failure code : other error codes do not apply.
        WSM_INVALID_PARAMETER                      = 0x2,         ///<The request contains one or more invalid parameters.
		WSM_STATUS_WARNING                         = 0x3,         ///<The command is successful but impacted all interfaces. To avoid this warning you should use the GENERAL_INTERFACE_ID.
		WSM_ERROR_UNSUPPORTED_MSG_ID			   = 0x4,         ///<Unkown request ID or wrong interface ID used
		WSM_STATUS_DECRYPTFAILURE                  = 0x10,        ///<The frame received includes a decryption error (only in ::WsmHiRxInd_t).
        WSM_STATUS_MICFAILURE                      = 0x11,        ///<A MIC failure was detected in the received packet (only in ::WsmHiRxInd_t).
		WSM_STATUS_NO_KEY_FOUND                    = 0x12,        ///<No key was found for the encrypted frame (in ::WsmHiRxInd_t or ::HI_TX_CNF).
        WSM_STATUS_RETRY_EXCEEDED                  = 0x13,        ///<The transmit request failed because the retry limit was exceeded (only in ::HI_TX_CNF).
        WSM_STATUS_TX_LIFETIME_EXCEEDED            = 0x14,        ///<The transmit request failed because the MSDU life time was exceeded (only in ::HI_TX_CNF).
        WSM_REQUEUE                                = 0x15,        ///<The message should be re-queued later (in ::HI_TX_CNF or HI_START_CNF).
        WSM_STATUS_REFUSED                         = 0x16         ///<Current device state conflicts with the request (in ::HI_SET_PM_MODE_CNF, ::HI_BEACON_TRANSMIT_CNF, ::HI_START_SCAN_CNF, ::HI_START_CNF or ::HI_JOIN_CNF)
} WsmStatus;

/**
 * @brief Split MAC (LMAC) list of possible transmission rates.
 *
 * Note that ERP-PBCC is not supported by the hardware. The rate indices for 22 Mbit/s and 33 Mbit/s are only provided for standard compatibility.@n
 * Data rates (in the names) are for 20 MHz channel operation. Corresponding data rates for 10 MHz channel operation are half of them.
 *
 * In this API, some parameters such as 'BasicRateSet' encode a list of rates in a bitstream format.@n
 *     for instance SUPPORTED_B_RATES_MASK = 0x0000000F @n
 *                  SUPPORTED_A_RATES_MASK = 0x00003FC0 @n
 *                  SUPPORTED_N_RATES_MASK = 0x003FC000
 */
typedef enum WsmTransmitRate_e {
	RATE_INDEX_B_1M           = 0, ///<ERP-DSSS
	RATE_INDEX_B_2M           = 1, ///<ERP-DSSS
	RATE_INDEX_B_5_5M         = 2, ///<ERP-CCK
	RATE_INDEX_B_11M          = 3, ///<ERP-CCK
	RATE_INDEX_PBCC_22M       = 4, ///<ERP-PBCC, not supported
	RATE_INDEX_PBCC_33M       = 5, ///<ERP-PBCC, not supported
	RATE_INDEX_A_6M           = 6, ///<ERP-OFDM, BPSK coding rate 1/2
	RATE_INDEX_A_9M           = 7, ///<ERP-OFDM, BPSK coding rate 3/4
	RATE_INDEX_A_12M          = 8, ///<ERP-OFDM, QPSK coding rate 1/2
	RATE_INDEX_A_18M          = 9, ///<ERP-OFDM, QPSK coding rate 3/4
	RATE_INDEX_A_24M          = 10, ///<ERP-OFDM, 16QAM coding rate 1/2
	RATE_INDEX_A_36M          = 11, ///<ERP-OFDM, 16QAM coding rate 3/4
	RATE_INDEX_A_48M          = 12, ///<ERP-OFDM, 64QAM coding rate 1/2
	RATE_INDEX_A_54M          = 13, ///<ERP-OFDM, 64QAM coding rate 3/4
	RATE_INDEX_N_6_5M         = 14, ///<HT-OFDM, BPSK coding rate 1/2
	RATE_INDEX_N_13M          = 15, ///<HT-OFDM, QPSK coding rate 1/2
	RATE_INDEX_N_19_5M        = 16, ///<HT-OFDM, QPSK coding rate 3/4
	RATE_INDEX_N_26M          = 17, ///<HT-OFDM, 16QAM coding rate 1/2
	RATE_INDEX_N_39M          = 18, ///<HT-OFDM, 16QAM coding rate 3/4
	RATE_INDEX_N_52M          = 19, ///<HT-OFDM, 64QAM coding rate 2/3
	RATE_INDEX_N_58_5M        = 20, ///<HT-OFDM, 64QAM coding rate 3/4
	RATE_INDEX_N_65M          = 21 ///<HT-OFDM, 64QAM coding rate 5/6
} WsmTransmitRate;

#define WSM_API_SSID_SIZE                               32



/**************************************************/


/**
 * @brief Reset flags used in command ::WsmHiResetReqBody_t
 */
typedef struct __attribute__((__packed__)) WsmHiResetFlags_s {
        uint8_t    ResetStat : 1;                    ///< 0=Reset statistics - 1=Do not reset statistics
        uint8_t    ResetAllInt : 1;                  ///< Set high to reset all interfaces, not only the one indicated by header.IntId
        uint8_t    Reserved : 6;                     ///< reserved for future use, set to 0
        uint8_t    Reserved2[3];                     ///< reserved for future use, set to 0
} WsmHiResetFlags_t;

/**
 * @brief Reset a Wlan interface
 *
 * This host-to-device message requests the device to tear down a WLAN interface.@n
 * If this is the last active interface, the device will be set to its initial state (the state after configure command), clearing all internal variables to their default values and the radio is turned off if it supports the low-power mode.
 */
typedef struct __attribute__((__packed__)) WsmHiResetReqBody_s {
        WsmHiResetFlags_t ResetFlags;         
} WsmHiResetReqBody_t;

typedef struct __attribute__((__packed__)) WsmHiResetReq_s {
        HiMsgHdr_t Header;             
        WsmHiResetReqBody_t Body;               
} WsmHiResetReq_t;

/**
 * @brief Confirmation message of RESET command ::WsmHiResetReqBody_t */
typedef struct __attribute__((__packed__)) WsmHiResetCnfBody_s {
        uint32_t   Status;                           ///< see ::WsmStatus.
} WsmHiResetCnfBody_t;

typedef struct __attribute__((__packed__)) WsmHiResetCnf_s {
        HiMsgHdr_t Header;             
        WsmHiResetCnfBody_t Body;               
} WsmHiResetCnf_t;


/**
 * @brief Union of all MIB body elements
 *
 * @todo update list and comments
 */
typedef union WsmMibData_u {
        /* General MIB */
        uint32_t                                        OperationalPowerMode;         /* Element :0x2000*/
        WsmHiMibGlBlockAckInfo_t                  MibBlockAckInfo;                /* Element :0x2001*/
        uint32_t                                        UseMultiTxConfMsg;            /* Element :0x2002*/
        /* Filtering MIB */
        WsmHiMibEthertypeDataFrameCondition_t     EtherTypeDataFrameCondition;    /* Element :0x2010*/
        WsmHiMibPortsDataFrameCondition_t         PortsDataFrameCondition;        /* Element :0x2011*/
        WsmHiMibMagicDataFrameCondition_t         MagicDataFrameCondition;        /* Element :0x2012*/
        WsmHiMibMacAddrDataFrameCondition_t      MacAddrDataFrameCondition;      /* Element :0x2013*/
        WsmHiMibIpv4AddrDataFrameCondition_t     IPv4AddrDataFrameCondition;     /* Element :0x2014*/
        WsmHiMibIpv6AddrDataFrameCondition_t     IPv6AddrDataFrameCondition;     /* Element :0x2015*/
        WsmHiMibUcMcBcDataFrameCondition_t      UcMcBcDataFrameCondition;       /* Element :0x2016*/
        WsmHiMibConfigDataFilter_t                 ConfigDataFilter;               /* Element :0x2017*/
        WsmHiMibSetDataFiltering_t                 SetDataFiltering;               /* Element :0x2018*/
        WsmHiMibArpIpAddrTable_t                  ArpIpAddressesTable;            /* Element :0x2019*/
        WsmHiMibNsIpAddrTable_t                   NsIpAddressesTable;             /* Element :0x201A*/
        uint32_t                                      RxFilter;                       /* Element :0x201B*/
        WsmHiMibBcnFilterTable_t                   BeaconFilterTable;              /* Element :0x201C*/
        WsmHiMibBcnFilterEnable_t                  BeaconFilterEnable;             /* Element :0x201D*/
        /* Others Read-only MIB */
        WsmHiMibGroupSeqCounter_t                  GroupSeqCounter;                /* Element :0x2030*/
        WsmHiMibTsfCounter_t                        TSFCounter;                     /* Element :0x2031*/
        WsmHiMibStatsTable_t                        StatisticsTable;                /* Element :0x2032*/
        WsmHiMibCountTable_t                        CountTable;                     /* Element :0x2033*/
        /* Others R/W or RO MIB */
        WsmHiMibMacAddress_t                        dot11MacAdress;                 /* Element :0x2040*/
        uint32_t                                        dot11MaxTransmitMsduLifeTime;   /* Element :0x2041*/
        uint32_t                                        dot11MaxReceiveLifeTime;        /* Element :0x2042*/
        WsmHiMibWepDefaultKeyId_t                 dot11WepdefaultKeyId;           /* Element :0x2043*/
        uint32_t                                        dot11RtsThreshold;              /* Element :0x2044*/
        uint32_t                                        SlotTime;                       /* Element :0x2045*/
        int32_t                                        CurrentTxPowerLevel;            /* Element :0x2046*/
        uint32_t                                        useCtsToSelf;                   /* Element :0x2047*/
        WsmHiMibTemplateFrame_t                     TemplateFrame;                  /* Element :0x2048*/
        WsmHiMibBeaconWakeUpPeriod_t              BeaconWakeUpPeriod;             /* Element :0x2049*/
        WsmHiMibRcpiRssiThreshold_t                RcpiRssiThreshold;              /* Element :0x204A*/
        WsmHiMibBlockAckPolicy_t                   BlockAckPolicy;                 /* Element :0x204B*/
        WsmHiMibOverrideIntRate_t                  MibOverrideInternalTxRate;      /* Element :0x204C*/
        WsmHiMibSetAssociationMode_t               SetAssociationMode;             /* Element :0x204D*/
        WsmHiMibSetUapsdInformation_t              SetUapsdInformation;            /* Element :0x204E*/
        WsmHiMibSetTxRateRetryPolicy_t           SetTxRateRetryPolicy;           /* Element :0x204F*/
        uint32_t                                        ProtectedMgmtFramesPolicy;      /* Element :0x2050*/
        uint32_t                                        SetHtProtection;                /* Element :0x2051*/
        WsmHiMibKeepAlivePeriod_t                  KeepAlivePeriod;                /* Element :0x2052*/
        WsmHiMibArpKeepAlivePeriod_t              ArpKeepAlivePeriod;             /* Element :0x2053*/
        WsmHiMibInactivityTimer_t                   InactivityTimer;                /* Element :0x2054*/
        uint32_t                                        InterfaceProtection;            /* Element :0x2055. 1: send CTS to self to protect the interface before leaving if PS is disabled. 0: no CTS to self even if PS is disabled*/
} WsmMibData_t;

/**
 * @brief Read a Configuration Information (MIB element)
 *
 * This host-to-device message requests to read configuration information and statistics from the WLAN device.
 */
typedef struct __attribute__((__packed__)) WsmHiReadMibReqBody_s {
        uint16_t   MibId;                            ///< ID of the MIB to be read (see MIB elements list ::WsmMibIds)
        uint16_t   Reserved;                         ///< reserved for future use, set to 0
} WsmHiReadMibReqBody_t;

typedef struct __attribute__((__packed__)) WsmHiReadMibReq_s {
        HiMsgHdr_t Header;             
        WsmHiReadMibReqBody_t Body;               
} WsmHiReadMibReq_t;

/**
 * @brief Confirmation message of MIB READ command ::WsmHiReadMibReq_t */
typedef struct __attribute__((__packed__)) WsmHiReadMibCnfBody_s {
        uint32_t   Status;                           ///< See ::WsmStatus. If WSM_STATUS_SUCCESS is returned, MIB data will follow.
        uint16_t   MibId;                            ///< ID of the MIB to be read (see MIB elements list ::WsmMibIds)
        uint16_t   Length;                           ///< Length of the MIB data in bytes.
        WsmMibData_t MibData;                      ///< The MIB data.
} WsmHiReadMibCnfBody_t;

typedef struct __attribute__((__packed__)) WsmHiReadMibCnf_s {
        HiMsgHdr_t Header;             
        WsmHiReadMibCnfBody_t Body;               
} WsmHiReadMibCnf_t;



/**
 * @brief Write a Configuration Information (MIB element)
 *
 * This host-to-device message requests to set configuration information in the WLAN device.
 */
typedef struct __attribute__((__packed__)) WsmHiWriteMibReqBody_s {
        uint16_t   MibId;                            ///<ID of the MIB to be written.
        uint16_t   Length;                           ///<Length of the MIB data in bytes.
        WsmMibData_t MibData;                      ///<The MIB data.
} WsmHiWriteMibReqBody_t;

typedef struct __attribute__((__packed__)) WsmHiWriteMibReq_s {
        HiMsgHdr_t Header;             
        WsmHiWriteMibReqBody_t Body;               
} WsmHiWriteMibReq_t;

/**
 * @brief Confirmation message of MIB WRITE command ::WsmHiWriteMibReqBody_t */
typedef struct __attribute__((__packed__)) WsmHiWriteMibCnfBody_s {
        uint32_t   Status;                           ///< See ::WsmStatus.
} WsmHiWriteMibCnfBody_t;

typedef struct __attribute__((__packed__)) WsmHiWriteMibCnf_s {
        HiMsgHdr_t Header;             
        WsmHiWriteMibCnfBody_t Body;               
} WsmHiWriteMibCnf_t;



/**
 * @brief Select the template to update used in command ::WsmHiUpdateIeReqBody_t
 */
typedef struct __attribute__((__packed__)) WsmHiIeFlags_s {
        uint8_t    Beacon : 1;                       ///<Update IE in beacon template
        uint8_t    ProbeResp : 1;                    ///<Update IE in probe response template
        uint8_t    ProbeReq : 1;                     ///<Update IE in probe request template
        uint8_t    Reserved1 : 5;                    ///< reserved for future use, set to 0
        uint8_t    Reserved2;                        ///< reserved for future use, set to 0
} WsmHiIeFlags_t;

/**
 * @brief Information Element structure used in command ::WsmHiUpdateIeReqBody_t.
 *
 * It is coded TLV : Type, Length, Value@
 * The size of the IE_TLV is (Length+2) bytes
 */
typedef struct __attribute__((__packed__)) WsmHiIeTlv_s {
        uint8_t    Type;                      ///<ID of the IE
        uint8_t    Length;                    ///<Length of Data field below
        uint8_t    Data[API_VARIABLE_SIZE_ARRAY_DUMMY_SIZE]; ///<variable length value of the IE
} WsmHiIeTlv_t;

/**
 * @brief Update one or more IE in a template.
 *
 * The template must have been configured before using the :: WsmHiWriteMibReqBody_t command to set the MIB element ::WsmHiMibTemplateFrame_t.@n
 * It is only possible to update an IE already present in the template.@n
 * It can't be used to add or delete IE in the template. For that the whole template must be sent again.
 */
typedef struct __attribute__((__packed__)) WsmHiUpdateIeReqBody_s {
        WsmHiIeFlags_t IeFlags;             ///<Select the template to update.
        uint16_t          NumIEs;              ///<Number of information elements present in this request
        WsmHiIeTlv_t   IE[0]; //Variable length list of IEs to update
} WsmHiUpdateIeReqBody_t;

typedef struct __attribute__((__packed__)) WsmHiUpdateIeReq_s {
        HiMsgHdr_t Header;
        WsmHiUpdateIeReqBody_t Body;
} WsmHiUpdateIeReq_t;

/**
 * @brief Confirmation message of update-template-IE command ::WsmHiUpdateIeReqBody_t */
typedef struct __attribute__((__packed__)) WsmHiUpdateIeCnfBody_s {
        uint32_t   Status;                           ///< See ::WsmStatus.
} WsmHiUpdateIeCnfBody_t;

typedef struct __attribute__((__packed__)) WsmHiUpdateIeCnf_s {
        HiMsgHdr_t Header;
        WsmHiUpdateIeCnfBody_t Body;
} WsmHiUpdateIeCnf_t;



/**
 * @addtogroup WSM_Scanning
 * @brief Split MAC scanning commands
 *
 *  * It is possible to do passive scan or active scan: @n
 * - during a passive scan the device only listens to beacon @n
 * - during active scan the device transmits probe-request and listens to probe-response and beacon
 *
 * The information elements filled into the probe-request are specified using the MIB template (see ::WsmHiMibTemplateFrame_t). This MIB excludes the SSID IE.@n
 * Configuring the probe-request template is mandatory before any active scan.
 * To start a scan the host sends the start-scan request (::WsmHiStartScanReqBody_t).
 * The scan results (probe-response frame and beacon frame) will be sent back to the host using receive indication messages (::WsmHiRxIndBody_t).@n
 * When the scan process completes, a scan-complete indication message (::WsmHiScanCmplIndBody_t) will be sent to the host.@n
 * It is possible to abort a scan at any time by sending the stop-scan request (::WSM_HI_STOP_SCAN_REQ).
 *
 * When a station is active (previously configured with ::WsmHiJoinReq_t) the scan process move the station to doze state, even if it wasn't configured to do so by :: WsmHiSetPmModeReq_t.
 * When the scan is complete the initial power state is restored.
 * @{
 */

/**
 * @brief scan configuration used in ::WsmHiStartScanReqBody_t */
typedef struct __attribute__((__packed__)) WsmHiScanType_s {
        uint8_t    Type : 1;                         ///<bit0 : 0=foreground, 1=in background of an existing wifi connection trying to minimize the disruptions
        uint8_t    Mode : 1;                         ///<bit1 : 0=single scan, 1=auto periodic scan
        uint8_t    Reserved : 6;                     ///<reserved for future use, set to 0
} WsmHiScanType_t;

/**
 * @brief scan configuration used in ::WsmHiStartScanReqBody_t */
typedef struct __attribute__((__packed__)) WsmHiScanFlags_s {
        uint8_t    Fbg : 1;                          ///<Forced background scan : even if the station failed to set power-save mode, the station will perform a background scan. Only valid when ScanType is background scan.
        uint8_t    Reserved1 : 1;                     ///<reserved for future use, set to 0
        uint8_t    Pre : 1;                          ///<Preamble type to use: 0=Long, 1=Short
        uint8_t    Reserved2 : 5;                     ///<reserved for future use, set to 0
} WsmHiScanFlags_t;

/**
 * @brief auto-scan configuration used in ::WsmHiStartScanReqBody_t */
typedef struct __attribute__((__packed__)) WsmHiAutoScanParam_s {
        uint16_t   Interval;                         ///<Interval period between scans in 4TUs=4096microseconds. Maximum value supported by the device is 256s. Applicable to auto-scan ScanType only.
        uint8_t    Reserved;                         ///<reserved for future use, set to 0
        int8_t    RssiThr;                          ///<signed RSSI threshold in dBm below which received beacons and probe responses are discarded and not transmitted to the host. A value of 0 (default) disables this filtering.
} WsmHiAutoScanParam_t;

/**
 * @brief SSID structure used in ::WsmHiStartScanReqBody_t */
typedef struct __attribute__((__packed__)) WsmHiSsidDef_s {
        uint32_t   SSIDLength;                       ///<Length of the SSID in bytes (maxi 32)
        uint8_t    SSID[WSM_API_SSID_SIZE];          ///<SSID string
} WsmHiSsidDef_t;

/**
 * @brief Start a scanning process
 *
 * This host-to-device message configures and requests the device to start a scanning process.
 *
 * Parameter value constraints:@n
 * - MinChannelTime =< MaxChannelTime@n
 * - ProbeDelay > MinChannelTime@n
 * - MaxChannelTime != 0
 * Invalid parameter value combinations may result in a WSM_INVALID_PARAMETER returned Status in the start scan confirmation message.@n
 *
 * If some channels are not supported by the device (see ::HiStartupIndBody_t::DisabledChannelList), during a scan request these channels will be ignored.
 * Some channels can also be ignored to enforce compliance with regulation requirements such as FCC or CE.@n
 * It is then advice to do an active scan on channel 1 to 10, followed by a passive scan on channel 11 to 14.@n
 *
 * Note that only 1 scanning process can be active at a time.
 */
#define WSM_API_SSID_DEF_SIZE                           2
#define WSM_API_CHANNEL_LIST_SIZE                       14
typedef struct __attribute__((__packed__)) WsmHiStartScanReqBody_s {
        uint8_t    Band;                             ///<Selects the radio band. Must be set to 0 (=2.4 GHz band).
        WsmHiScanType_t ScanType;           
        WsmHiScanFlags_t ScanFlags;          
        uint8_t    MaxTransmitRate;                  ///<Max transmission rate used to send probe requests. For rate definition see enum ::WsmTransmitRate.
        WsmHiAutoScanParam_t AutoScanParam;      
        uint8_t    NumOfProbeRequests;               //<Number of probe requests (per SSID) sent on each channel. (0) means that a passive scan is done. Value greater than zero means that an active scan is done.
        uint8_t    ProbeDelay;                       ///<Delay (in microseconds) between the Probe Requests sent on the same channel
        uint8_t    NumOfSSIDs;                       ///<Number of SSIDs provided in the scan command below (set it to 0 for broadcast scan). Maximum supported value is 2.
        uint8_t    NumOfChannels;                    ///<Number of channels to be scanned and listed below. Maximum number is 14.
        uint32_t   MinChannelTime;                   ///<Time in TUs : reserved for future use, must be set to 0
        uint32_t   MaxChannelTime;                   ///<Time in TUs : max time to wait on each channel
        int32_t   TxPowerLevel;                     ///<Transmission power level in 0.1dBm unit (it can of course be limited by the device capacity!)
        /* WsmHiSsidDef_t SsidDef[WSM_API_SSID_DEF_SIZE]; */    ///<Optionnel list of SSIDs to look for explicitly during the scan
        /* uint8_t    ChannelList[WSM_API_CHANNEL_LIST_SIZE]; */   ///<Variable size array of all WIFI channels number to scan (value between 1 and 14)
} WsmHiStartScanReqBody_t;

typedef struct __attribute__((__packed__)) WsmHiStartScanReq_s {
        HiMsgHdr_t Header;             
        WsmHiStartScanReqBody_t Body;               
} WsmHiStartScanReq_t;

/**
 * @brief Confirmation message of START_SCAN command ::WsmHiStartScanReqBody_t */
typedef struct __attribute__((__packed__)) WsmHiStartScanCnfBody_s {
        uint32_t   Status;                           ///<See ::WsmStatus. If WSM_STATUS_SUCCESS is not returned, the scan process will not start. No scan-completion indication will be sent to the host.
} WsmHiStartScanCnfBody_t;

typedef struct __attribute__((__packed__)) WsmHiStartScanCnf_s {
        HiMsgHdr_t Header;             
        WsmHiStartScanCnfBody_t Body;               
} WsmHiStartScanCnf_t;


/**
 * @brief Stop a pending scanning process
 *
 * This host-to-device message requests to abort the scanning process.
 *
 * It will be followed by a stop-scan confirmation (::WsmHiStopScanCnfBody_t) and a scan-complete indication.
 */
typedef HiMsgHdr_t WSM_HI_STOP_SCAN_REQ; 

/**
 * @brief Confirmation message of STOP_SCAN command ::WSM_HI_STOP_SCAN_REQ */
typedef struct __attribute__((__packed__)) WsmHiStopScanCnfBody_s {
        uint32_t   Status;                           ///<See ::WsmStatus. The stop-scan request acceptance has no impact on whether the scan completion is sent or not.
} WsmHiStopScanCnfBody_t;

typedef struct __attribute__((__packed__)) WsmHiStopScanCnf_s {
        HiMsgHdr_t Header;             
        WsmHiStopScanCnfBody_t Body;               
} WsmHiStopScanCnf_t;


/**
 * @brief 802.11 Power Mode status reported in ::WsmHiScanCmplIndBody_t or ::WsmHiSetPmModeCmplIndBody_t.
 */
typedef enum WsmPmModeStatus_e {
        WSM_PM_MODE_ACTIVE                         = 0x0,         ///<802.11 active mode
        WSM_PM_MODE_PS                             = 0x1,         ///<802.11 PS mode
        WSM_PM_MODE_UNDETERMINED                   = 0x2          ///<Undetermined = the NULL data frame used to advertise the PM mode to the AP at pre- or post-background scan is not acknowledged.
} WsmPmModeStatus;

/**
 * @brief Scan-complete device-to-host message indicating that the scanning process is finished */
typedef struct __attribute__((__packed__)) WsmHiScanCmplIndBody_s {
        uint32_t   Status;                           ///<Result of the scanning process. See ::WsmStatus.
        uint8_t    PmMode;                           ///<Current 802.11 power management mode of the WLAN device. See enum ::WsmPmModeStatus
        uint8_t    NumChannelsCompleted;             ///<Number of channels that the scan operation completed.
        uint16_t   Reserved;                         ///<reserved for future use, set to 0
} WsmHiScanCmplIndBody_t;

typedef struct __attribute__((__packed__)) WsmHiScanCmplInd_s {
        HiMsgHdr_t Header;             
        WsmHiScanCmplIndBody_t Body;               
} WsmHiScanCmplInd_t;

/**
 * @}
 */
/* end of WSM_Scanning */


/**
 * @brief The different Access Category Index (ACI) of a message queue.
 *
 * Used in message ::WsmHiEdcaQueueParamsReqBody_t and in ::WsmHiTxReqBody_t::QueueId
 * */
typedef enum WsmQueueId_e {
        WSM_QUEUE_ID_BACKGROUND                    = 0x0,         ///<Background
        WSM_QUEUE_ID_BESTEFFORT                    = 0x1,         ///<Best effort or legacy
        WSM_QUEUE_ID_VIDEO                         = 0x2,         ///<Video
        WSM_QUEUE_ID_VOICE                         = 0x3          ///<Voice
} WsmQueueId;

/**
 * @brief Frame format of a Tx packet used in message ::WsmHiTxReqBody_t.
 * */
typedef enum WsmFrameFormat_e {
        WSM_FRAME_FORMAT_NON_HT                    = 0x0,         ///< non-HT Format
        WSM_FRAME_FORMAT_MIXED_FORMAT_HT           = 0x1,         ///< HT Mixed format
        WSM_FRAME_FORMAT_GF_HT_11N                 = 0x2          ///< HT Greenfield format
} WsmFrameFormat;

/**
 * @brief Enum for STBC activation used in message ::WsmHiTxReqBody_t.
 *
 * STBC = space-time block coding
 * */
typedef enum WsmStbc_e {
        WSM_STBC_NOT_ALLOWED                       = 0x0,         ///<STBC not allowed
        WSM_STBC_ALLOWED                           = 0x1          ///<STBC allowed
} WsmStbc;

/**
 * @brief Specify the destination queue of the Tx frame used in message ::WsmHiTxReqBody_t.
 *  */
typedef struct __attribute__((__packed__)) WsmHiQueueId_s {
        uint8_t    QueueId : 2;                      ///<Transmit queue ID : specifies the Access Category Index (ACI) of the queue (see enum ::WsmQueueId)
        uint8_t    PeerStaId : 4;                    ///<Identify the destination STA (from 1 to ::HiStartupIndBody_t::NumLinksAP) or indicate a broadcast (or multicast) packet when set to 0. It corresponds to ::WsmHiMapLinkReqBody_t::PerStaId . It is mainly used when the device is an AP. Must be set to 0 when unused.
        uint8_t    Reserved : 2;                     ///<reserved for future use, set to 0
} WsmHiQueueId_t;


/**
 * @brief Some parameters about the data payload used in message ::WsmHiTxReqBody_t.
 *  */
typedef struct __attribute__((__packed__)) WsmHiDataFlags_s {
        uint8_t    More     : 1;                     ///<Set it high to indicate that another packet is pending in the host for transmission with the same QueueId (=same destination and same QoS).
        uint8_t    FcOffset : 3;                     ///<Packet's FrameControl field offset. Packet's FrameControl field starts at Frame field below + FcOffset bytes
        uint8_t    Reserved : 4;                     ///<reserved for future use, set to 0
} WsmHiDataFlags_t;

/**
 * @brief Some parameters configuring the Tx management used in message ::WsmHiTxReqBody_t.
 *  */
typedef struct __attribute__((__packed__)) WsmHiTxFlags_s {
        uint8_t    StartExp : 1;                     ///<Start Expire time from : 0 - the first Tx attempt (default) / 1 - the receipt of the Tx request
        uint8_t    Reserved : 3;                     ///<reserved for future use, set to 0
        uint8_t    Txrate   : 4;                     ///<Tx rate retry policy @todo add details
} WsmHiTxFlags_t;

/**
 * @brief Specify High Throughput transmit parameters used in message ::WsmHiTxReqBody_t.
 *  */
typedef struct __attribute__((__packed__)) WsmHiHtTxParameters_s {
        uint8_t    FrameFormat : 4;                  ///<Transmission frame format. See enum ::WsmFrameFormat
        uint8_t    FecCoding : 1;                    ///<FEC coding selection. 0: legacy, BCC. 1: LDPC
        uint8_t    ShortGi : 1;                      ///<Guard Interval size. 0: legacy, long GI. 1: short GI
        uint8_t    Reserved : 1;                     ///<reserved for future use, set to 0
        uint8_t    Stbc : 1;                         ///<STBC requirement for this frame. See enum ::WsmStbc
        uint8_t    Reserved1;                        ///<reserved for future use, set to 0
        uint8_t    Aggregation : 1;                  ///<Set high to use A-MPDU aggregation
        uint8_t	   Reserved2 : 7;					 ///<reserved for future use, set to 0
        uint8_t    Reserved3;                        ///<reserved for future use, set to 0
} WsmHiHtTxParameters_t;

/**
 * @brief Transmit a frame
 *
 * This host-to-device message provides a 802.11 frame to transmit and configures some transmission parameters.
 * Frames are in the 802.11 format, that is, the WLAN host driver adds the WLAN MAC header.@n
 * The WLAN host driver adds all the necessary fields in transmit direction (WEP IV/ICV, TKIP Michael, QoS, and so on) excluding trailing FCS.@n
 * The content of following fields (or bits) is controlled by the WLAN device:
 *   - Timestamp field of the beacon and probe response frame@n
 *   - Frame Control@n
 *   - More fragments, retransmission, power management, and more data@n
 *   - Duration or ID@n
 *   - Sequence control@n
 *   - WEP IV/ICV@n
 *   - TKIP Michael@n
 *   - FCS@n
 * The WLAN host driver is responsible for managing the QoS control field.
 *
 */
typedef struct __attribute__((__packed__)) WsmHiTxReqBody_s {
        uint32_t   PacketId;                         ///<Packet identifier to be used in the confirmation to link the Tx_conf with this request.
        uint8_t    MaxTxRate;                        ///<Maximum transmit rate (see enum ::WsmTransmitRate)
        WsmHiQueueId_t QueueId;                     ///<destination queue (STA + Access Category)
        WsmHiDataFlags_t DataFlags;                 ///<Some info about the data
        WsmHiTxFlags_t TxFlags;                     ///<Some Tx parameters
        uint32_t   Reserved;                         ///<reserved for future use, set to 0
        uint32_t   ExpireTime;                       ///<The elapsed time in TUs, after the initial transmission of an MSDU, after which further attempts to transmit the MSDU will be terminated. Overrides the global dot11MaxTransmitMsduLifeTime setting when different from 0.
        WsmHiHtTxParameters_t HtTxParameters;      ///<High throughput transmit parameters. Set to 0 for non-HT transmissions.
        uint32_t   Frame;                            ///<A 802.11 frame. See TxFlags Bit 7 above.
} WsmHiTxReqBody_t;

typedef struct __attribute__((__packed__)) WsmHiTxReq_s {
        HiMsgHdr_t Header;             
        WsmHiTxReqBody_t Body;               
} WsmHiTxReq_t;


/**
 * @brief Ack policy values in QoS control field.
 *
 * Used in message ::WsmHiTxCnfBody_t::WsmHiTxResultFlags_t
 * As specified in 802.11-2012 table 8-6.
 * */
typedef enum WsmQosAckplcy_e {
        WSM_QOS_ACKPLCY_NORMAL                         = 0x0,         ///<Normal Acknowledge or implicit Block Ack Request
        WSM_QOS_ACKPLCY_TXNOACK                        = 0x1,         ///<No Acknowledge
        WSM_QOS_ACKPLCY_NOEXPACK                       = 0x2,         ///<No explicit acknowledge
        WSM_QOS_ACKPLCY_BLCKACK                        = 0x3          ///<Block ACK
} WsmQosAckplcy;

typedef struct __attribute__((__packed__)) WsmHiTxResultFlags_s {
        uint8_t    Aggr : 1;                         ///<Only valid when Status=WSM_SUCCESS. 0: Frame was not sent aggregated. 1: Frame was sent aggregated.
        uint8_t    Requeue : 1;                      ///<Only valid when Status=WSM_REQUEUE. 1: Host should re-queue this frame later. 0:Host should not re-queue this frame.
        uint8_t    AckPolicy : 2;                    ///<Only valid when Status=WSM_SUCCESS. See enum ::WsmQosAckplcy.
        uint8_t    TxopLimit : 1;                    ///<When high : The TXOP limit for the ACI was temporarily increased to allow this frame to transmit.
        uint8_t    Reserved  : 3;                    ///<reserved for future use
        uint8_t    Reserved1;                        ///<reserved for future use
} WsmHiTxResultFlags_t;

/**
 * @brief Confirmation of a previous ::WsmHiTxReqBody_t Tx request message.
 *
 * This confirmation is not sent just after the request but after a while when the packet is effectively sent successfully (or if it can not be transmitted).@n
 * It uses field 'PacketId' to identify which Tx request is acknowledged.
 * Note that it is possible that the transmit starts with an HT rate (MCS index) and ends up in a legacy rate.
 */
typedef struct __attribute__((__packed__)) WsmHiTxCnfBody_s {
    	uint32_t   Status;                           ///<See ::WsmStatus.
        uint32_t   PacketId;                         ///<This field uniquely defines the request that this confirmation message is replied to. It is taken from the corresponding request message.
        uint8_t    TxedRate;                         ///<The data rate at which the frame was successfully transmitted. See enum ::WsmTransmitRate.
        uint8_t    AckFailures;                      ///<The number of times the frame was transmitted without receiving an acknowledge.
        WsmHiTxResultFlags_t TxResultFlags;        ///<HT transmit result.
        uint32_t   MediaDelay;                       ///<The total time in microseconds that the frame spent in the WLAN device before transmission is completed. Value is only valid if status is STATUS_SUCCESS.
        uint32_t   TxQueueDelay;                     ///<The total time in microseconds that the frame spent in the WLAN device before transmission was started. Value is only valid if status is STATUS_SUCCESS.
} WsmHiTxCnfBody_t;

typedef struct __attribute__((__packed__)) WsmHiTxCnf_s {
        HiMsgHdr_t Header;             
        WsmHiTxCnfBody_t Body;               
} WsmHiTxCnf_t;


/**
 * @brief Confirmation of one or more previous ::WsmHiTxReqBody_t Tx request messages.
 *
 * To save some bandwidth on the device-to-host interface (SDIO or SPI), it is possible to acknowledge many Tx-requests at once.@n
 * In that case this indication is sent instead of multiple ::WsmHiTxCnfBody_t.@n
 * This feature is activated setting MIB ::WSM_MIB_ID_GL_SET_MULTI_MSG.
 *
 * Note that this indication is really special because it is not the answer to a WSM_HI_MULTI_TRANSMIT_REQ (that does not exist!).
 */
typedef struct __attribute__((__packed__)) WsmHiMultiTransmitCnfBody_s {
        uint32_t   NumTxConfs;                       ///<Number of transmit confirmation message payload structures contained in this message
        WsmHiTxCnfBody_t   TxConfPayload[API_VARIABLE_SIZE_ARRAY_DUMMY_SIZE];      ///<Variable number of transmit confirmation message payloads
} WsmHiMultiTransmitCnfBody_t;

typedef struct __attribute__((__packed__)) WsmHiMultiTransmitCnf_s {
        HiMsgHdr_t Header;
        WsmHiMultiTransmitCnfBody_t Body;
} WsmHiMultiTransmitCnf_t;


/**
 * @brief Received frame encryption type
 *
 * Used in message ::WsmHiRxIndBody_t::RxFlags
 * */
typedef enum WsmRiFlagsEncrypt_e {
        WSM_RI_FLAGS_UNENCRYPTED                   = 0x0,         ///<No encryption
        WSM_RI_FLAGS_WEP_ENCRYPTED                 = 0x1,         ///<WEP encrypted
        WSM_RI_FLAGS_TKIP_ENCRYPTED                = 0x2,         ///<TKIP encrypted
        WSM_RI_FLAGS_AES_ENCRYPTED                 = 0x3,         ///<AES encrypted
        WSM_RI_FLAGS_WAPI_ENCRYPTED                = 0x4          ///<WAPI encrypted
} WsmRiFlagsEncrypt;

/**
 * @brief Received frame flags
 *
 * Used in message ::WsmHiRxIndBody_t
 * */
typedef struct __attribute__((__packed__)) WsmHiRxFlags_s {
        uint8_t    Encryp : 3;                       ///<Bit 2 to 0 - Frame encryption type. See enum ::WsmRiFlagsEncrypt
        uint8_t    InAggr : 1;                       ///<Bit 3 : 1 - Frame was part of an aggregation
        uint8_t    FirstAggr : 1;                    ///<Bit 4 : 1 - Frame was first in an aggregation (Only valid if bit 3 = 1)
        uint8_t    LastAggr : 1;                     ///<Bit 5 : 1 - Frame was last in an aggregation (Only valid if bit 3 = 1)
        uint8_t    Defrag : 1;                       ///<Bit 6 : 1 - Indicates a defragmented frame
        uint8_t    Beacon : 1;                       ///<Bit 7 : 1 - Indicates the received frame is a beacon frame
        uint8_t    Tim : 1;                          ///<Bit 8 : 1 - Indicates the received frame contain a beacon with the station bit set within the TIM element
        uint8_t    Bitmap : 1;                       ///<Bit 9 : 1 - Indicates the received frame contain a beacon with the multicast bit set within the TIM element
        uint8_t    MatchSsid : 1;                    ///<Bit 10 : 1 - Indicates the frame contains a matching SSID
        uint8_t    MatchBssid : 1;                   ///<Bit 11 : 1 - Indicates the frame contains a matching BSSID
        uint8_t    More : 1;                         ///<Bit 12 : 1 - Indicates the More bit is set in the Framectl field
        uint8_t    Reserved2 : 1;                    ///<Bit 13 : 1 - Reserved for future used, set to 0
        uint8_t    Ht : 1;                           ///<Bit 14 : 1 - Indicates the frame received is an HT packet
        uint8_t    Stbc : 1;                         ///<Bit 15 : 1 - Indicates the frame received used STBC
        uint8_t    MatchUcAddr : 1;                  ///<Bit 16 : 1 - Indicates the address 1 field matches the station unicast MAC Address
        uint8_t    MatchMcAddr : 1;                  ///<Bit 17 : 1 - Indicates the address 1 field matches a multicast address (not broadcast)
        uint8_t    MatchBcAddr : 1;                  ///<Bit 18 : 1 - Indicates the address 1 field matches a broadcast address
        uint8_t    KeyType : 1;                      ///<Bit 19 : Reports the key type used with encrypted frames; 0 - Indicates the pairwise key used; 1 - Indicates the group key used
        uint8_t    KeyIndex : 4;                     ///<Bits 23 to 20 - Index of the key used for decryption
        uint8_t    Reserved3 : 1;                    ///<Bit 24 - Reserved for future use
        uint8_t    PeerStaId : 4;                    ///<Bits 28 to 25 - Peer STA id (from 1 to 14)
        uint8_t    Reserved4 : 2;                    ///<Bits 30 to 29 - Reserved for future use, set to 0
        uint8_t    Reserved5 : 1;                    ///<Bit 31 - Reserved for future use
} WsmHiRxFlags_t;

/**
 *  @brief Indicate a frame has been received by the firmware
 *
 *  This message contains information about the frame received followed by the frame itself
 */
typedef struct __attribute__((__packed__)) WsmHiRxIndBody_s {
        uint32_t   Status;                          ///<Status of the received frame. See enum ::WsmStatus.
        uint16_t   ChannelNumber;                   ///<Specifies the channel of the received packet.
        uint8_t    RxedRate;                        ///<The data rate at which the frame was successfully received. See enum ::WsmTransmitRate.
        uint8_t    RcpiRssi;                        ///<Bit 1 in MIB ::WsmHiMibRcpiRssiThreshold_t determined if this value represents RCPI or RSSI. The default is RCPI type. This value is expressed in dBm as signed Q8.0 format for RSSI and unsigned Q7.1 format for RCPI.
        WsmHiRxFlags_t RxFlags;                    ///<Additional information about the frame received. See structure ::WsmHiRxFlags_t.
        uint32_t   Frame[0];  ///<Content of the received frame
} WsmHiRxIndBody_t;

typedef struct __attribute__((__packed__)) WsmHiRxInd_s {
        HiMsgHdr_t Header;             
        WsmHiRxIndBody_t Body;               
} WsmHiRxInd_t;



/**
 * @brief Specifies the acknowledge type.
 *
 * Used in message ::WsmHiEdcaQueueParamsReqBody_t
 * */
typedef enum WsmAckplcy_e {
        WSM_ACKPLCY_NORMAL                         = 0x0,         ///<Normal Acknowledge
        WSM_ACKPLCY_TXNOACK                        = 0x1          ///<Tx is not Acknowledged
} WsmAckplcy;

/**
 * @brief Configure EDCA queues
 *
 * Configure the 4 EDCA queues used for QoS.
 * The queues indexes are: 0 - AC_BK (background), 1 - AC_BE (best effort), 2 - AC_VI (video), 3 - AC_VO (voice)
 */
typedef struct __attribute__((__packed__)) WsmHiEdcaQueueParamsReqBody_s {
        uint8_t    QueueId;                          ///< Specifies the Access Category Index (ACI) of the queue. See enum ::WsmQueueId
    uint8_t    Reserved0;           ///<Reserved for future used. Set to 0.
    uint8_t    AIFSN;               ///<AIFS (in slots) for the access category.
    uint8_t    Reserved1;           ///<Reserved for future use
    uint16_t   CwMin;               ///<CwMin (in slots) for the access category. Must be 2^n-1.
    uint16_t   CwMax;               ///<CwMax (in slots) for the access category. Must be 2^n-1.
    uint16_t   TxOpLimit;           ///<TX OP limit (in microseconds) for the access category.
    uint16_t   AllowedMediumTime;   ///< Medium time of TSPEC (in 32 us units) allowed per one second averaging period for this queue.
    uint32_t    Reserved2;           ///<Reserved for future used. Set to 0.
} WsmHiEdcaQueueParamsReqBody_t;

typedef struct __attribute__((__packed__)) WsmHiEdcaQueueParamsReq_s {
        HiMsgHdr_t Header;
        WsmHiEdcaQueueParamsReqBody_t Body;
} WsmHiEdcaQueueParamsReq_t;

/**
 * @brief Confirmation message for WSM_HI_EDCA_PARAMS_REQ
 */
typedef struct __attribute__((__packed__)) WsmHiEdcaQueueParamsCnfBody_s {
        uint32_t   Status;                           /*Error codes for the Set-EdcaParams request.*/
} WsmHiEdcaQueueParamsCnfBody_t;

typedef struct __attribute__((__packed__)) WsmHiEdcaQueueParamsCnf_s {
        HiMsgHdr_t Header;
        WsmHiEdcaQueueParamsCnfBody_t Body;
} WsmHiEdcaQueueParamsCnf_t;




/**
 * @addtogroup WSM_STA_specific
 * @brief Split MAC commands only used for Station setup or control
 *
 * @{
 */

/**
 * @brief Enum type of network to connect to, used in message ::WsmHiJoinReqBody_t.
 *
 * */
typedef enum WsmMode_e {
        WSM_MODE_IBSS                              = 0x0,         ///<IBSS
        WSM_MODE_BSS                               = 0x1          ///<BSS
} WsmMode;

/**
 * @brief Enum for the PLCP preamble type, used in different messages.
 *
 * */
typedef enum WsmPreamble_e {
        WSM_PREAMBLE_LONG                          = 0x0,         ///<for long preamble
        WSM_PREAMBLE_SHORT                         = 0x1,         ///<for short preamble (Long for 1 Mbit/s)
        WSM_PREAMBLE_SHORT_LONG12                  = 0x2          ///<for short preamble (Long for 1 Mbit/s and 2 Mbit/s)
} WsmPreamble;

/**
* @struct WsmHiJoinFlags_t
* @brief Configuration flags used in command ::WsmHiJoinReqBody_t
*/
typedef struct __attribute__((__packed__)) WsmHiJoinFlags_s {
        uint8_t    Reserved1 : 2;                    ///< reserved for future use, set to 0
        uint8_t    ForceNoBeacon : 1;                ///<Bit 2 = 1 - Force to join BSS with the BSSID and the SSID specified without waiting for beacons. The ::WsmHiJoinReqBody_t::ProbeForJoin parameter is ignored.
        uint8_t    ForceWithInd  : 1;                ///<Bit 3 = 1 - Force using Join Complete Indication (only valid if 'ForceNoBeacon' is also set high)
        uint8_t    Reserved2 : 4;                    ///< reserved for future use, set to 0

} WsmHiJoinFlags_t;

#define WSM_API_BSSID_SIZE                              6
/**
* @struct WsmHiJoinReqBody_t
* @brief Join/connect to a Wlan network
*
* This host-to-device message requests the device to join a network as a STAtion.
*
* If JoinFlags.ForceWithInd=0 then ::WsmHiJoinCnfBody_t is sent when the join process is completed.
* If JoinFlags.ForceWithInd=1 then ::WsmHiJoinCnfBody_t is sent immediately after the Join request @n
*                     and ::WsmHiJoinCompleteIndBody_t is sent when the join process is completed.
*
* Please note that the host can send data frames after the Join_Confirm and before the Join_Complete Indication. @n
* After the Join_Confirm and before the Join_Complete Indication the host must not send a SCAN command (neither BG scan, nor FG scan) nor a Set_PM_Mode_Req.
*
 */
typedef struct __attribute__((__packed__)) WsmHiJoinReqBody_s {
        uint8_t    Mode;                             ///<Specifies the operation mode of the station. See enum ::WsmMode .For the P2P group negotiation, the BSS mode should be used.
        uint8_t    Band;                             ///<Selects the radio band. Must be set to 0 (=2.4 GHz band).
        uint16_t   ChannelNumber;                    ///<Specifies the channel number to join. The channel number will be mapped to an actual frequency according to the band.
        uint8_t    BSSID[WSM_API_BSSID_SIZE];        ///<Specifies the BSSID of the BSS or IBSS to be joined, or the IBSS to be started. When joining for the P2P group negotiation, this field should be filled with the MAC address of the peer P2P device.
        uint16_t   AtimWindow;                       ///<ATIM window of IBSS. When the ATIM window is zero, the initiated IBSS does not support power saving.
        uint8_t    PreambleType;                     ///<Specifies the PLCP preamble type used. See enum : WsmPreamble
        uint8_t    ProbeForJoin;                     ///<Specifies if a probe request should be send with the specified SSID when joining the network. This option is to acquire the TSF time of the BSS or IBSS that is to be joined as fast as possible. The TSF time is obtained from the probe response or from beacon, whichever is received first.
        uint8_t    Reserved;                         ///< reserved for future use, set to 0
        WsmHiJoinFlags_t JoinFlags;                 ///<configuration flags
        uint32_t   SSIDLength;                       ///<Length of the SSID below
        uint8_t    SSID[WSM_API_SSID_SIZE];          ///<Specifies the SSID of the IBSS to join or start
        uint32_t   BeaconInterval;                   ///<Specifies the time between TBTTs in TUs
        uint32_t   BasicRateSet;                     ///<A bit mask that defines the BSS basic rate set. See enum ::WsmTransmitRate.
} WsmHiJoinReqBody_t;

typedef struct __attribute__((__packed__)) WsmHiJoinReq_s {
        HiMsgHdr_t Header;             
        WsmHiJoinReqBody_t Body;               
} WsmHiJoinReq_t;

/**
* @struct WsmHiJoinCnfBody_t
* @brief Confirmation message of the Join network command ::WsmHiJoinReqBody_t.
*
* It confirms that the join process is completed (or that the process is started if the Join_Complete Indication has been requested).
*/
typedef struct __attribute__((__packed__)) WsmHiJoinCnfBody_s {
        uint32_t   Status;                          ///< See ::WsmStatus.
} WsmHiJoinCnfBody_t;

typedef struct __attribute__((__packed__)) WsmHiJoinCnf_s {
        HiMsgHdr_t Header;             
        WsmHiJoinCnfBody_t Body;               
} WsmHiJoinCnf_t;


/**
* @struct WsmHiJoinCompleteIndBody_t
* @brief Indicates that the join requested with previous ::WsmHiJoinReqBody_t has completed
*/
typedef struct __attribute__((__packed__)) WsmHiJoinCompleteIndBody_s {
        uint32_t   Status;                            ///< See ::WsmStatus.
} WsmHiJoinCompleteIndBody_t;

typedef struct __attribute__((__packed__)) WsmHiJoinCompleteInd_s {
        HiMsgHdr_t Header;             
        WsmHiJoinCompleteIndBody_t Body;               
} WsmHiJoinCompleteInd_t;



/**
* @brief BSS configuration control flag, used in command ::WsmHiSetBssParamsReqBody_t
*/
typedef struct __attribute__((__packed__)) WsmHiBssFlags_s {
        uint8_t    LostCountOnly : 1;                ///<Bit 0 = 1: Only update the beacon lost count limit and reset the internal beacon lost counter.
        uint8_t    Reserved : 7;                     ///< reserved for future use, set to 0
} WsmHiBssFlags_t;


/**
* @brief Connection configuration after association to a BSS
*
* This host-to-device message set some connection parameters after the initial connection setup (after association response in infrastructure mode).@n
* The WLAN host driver must call this function before turning the WLAN device into power save as the AID field is needed to enter power save.@n
* In case of background scan or Bluetooth coexistence, the device may need to automatically enter the PS mode.@n
* Therefore, once associated with the AP, the host should always issue a Set-Bss-Params request.
*
* Note:	This command is only used when operating in the infrastructure mode.
 */
typedef struct __attribute__((__packed__)) WsmHiSetBssParamsReqBody_s {
        WsmHiBssFlags_t BssFlags;                   ///<configuration control flag
        uint8_t    BeaconLostCount;                  ///<The number of consecutive lost beacons after which the WLAN device should indicate the BSS-Lost event to the WLAN host driver. Value of 0 disables the BSS-Lost event indications, thereby also disabling the BSS-regained event indications (see ::WsmHiEventIndBody_t).
        uint16_t   AID;                              ///<Specifies the AID received during the association process.
        uint32_t   OperationalRateSet;               ///<A bit mask that defines the operational rates. Used for modem enabling purposes. See enum ::WsmTransmitRate.
} WsmHiSetBssParamsReqBody_t;

typedef struct __attribute__((__packed__)) WsmHiSetBssParamsReq_s {
        HiMsgHdr_t Header;
        WsmHiSetBssParamsReqBody_t Body;
} WsmHiSetBssParamsReq_t;


/**
* @brief Confirmation message of configuration command ::WsmHiSetBssParamsReqBody_t
*/
typedef struct __attribute__((__packed__)) WsmHiSetBssParamsCnfBody_s {
        uint32_t   Status;                           ///< See ::WsmStatus.
} WsmHiSetBssParamsCnfBody_t;

typedef struct __attribute__((__packed__)) WsmHiSetBssParamsCnf_s {
        HiMsgHdr_t Header;
        WsmHiSetBssParamsCnfBody_t Body;
} WsmHiSetBssParamsCnf_t;




typedef struct __attribute__((__packed__)) WsmHiPmMode_s {
        uint8_t    PmMode : 1;                       /*Bit 0 = 0 - Active mode, when this mode is entered, the device automatically transmits a frame with the power management bit cleared to inform the AP that the STA is in the active mode            Bit 0 = 1 - PS mode, when this mode is entered, the device automatically transmits a frame with the power management bit set to inform the AP that the STA has entered the PS mode.            Bit 7 = 1 - Fast power-saving mode is enabled. This bit is only valid with bit 0 is set to 1. */
        uint8_t    Reserved : 6;                     ///< reserved for future use, set to 0
        uint8_t    FastPsm : 1;                      /*Bit 7 = 1 - Fast power-saving mode is enabled. This bit is only valid with bit 0 is set to 1.*/
} WsmHiPmMode_t;

/* request WSM_HI_SET_PM_MODE */
/* Sets Pm Mode */
typedef struct __attribute__((__packed__)) WsmHiSetPmModeReqBody_s {
        WsmHiPmMode_t PmMode;
        uint8_t    FastPsmIdlePeriod;                /*This field, specified in units of 500 us, defines the time that the device determines the link is idle in the fast power-saving mode.             If this parameter is set to 0, a default value is taken by the device. See below for details.*/
        uint8_t    ApPsmChangePeriod;                /*This field, specified in units of 500 us, defines the time that the device determines the AP has stopped its transmit pipeline after a null frame is             received. If this parameter is set to 0, a default value is taken by the device.*/
        uint8_t    MinAutoPsPollPeriod;              /*This field, specified in units of 500 us, defines the minimum time that the device will send a PS-Poll if it guesses that there is a data frame             pending in the AP without receiving a beacon. If this parameter is set to 0, the auto PS-Poll feature is disabled.*/
} WsmHiSetPmModeReqBody_t;

typedef struct __attribute__((__packed__)) WsmHiSetPmModeReq_s {
        HiMsgHdr_t Header;             
        WsmHiSetPmModeReqBody_t Body;               
} WsmHiSetPmModeReq_t;

/* confirmation WSM_HI_SET_PM_MODE */
/* Sets Pm Mode */
typedef struct __attribute__((__packed__)) WsmHiSetPmModeCnfBody_s {
        uint32_t   Status;                           /*Error code for the set-PM-mode request.     The set-PM-mode completion message will only be sent if the status sent back to the host by the set-PM-mode confirmation message was WSM_STATUS_SUCCESS.*/
} WsmHiSetPmModeCnfBody_t;

typedef struct __attribute__((__packed__)) WsmHiSetPmModeCnf_s {
        HiMsgHdr_t Header;             
        WsmHiSetPmModeCnfBody_t Body;               
} WsmHiSetPmModeCnf_t;

/* indication WSM_HI_SET_PM_MODE_CMPL */
/* Indicates that Set-Ps-Mode has been completed */
typedef struct __attribute__((__packed__)) WsmHiSetPmModeCmplIndBody_s {
        uint32_t   Status;                           /*Error codes for the set-PM-mode operation*/
        uint8_t    PmMode;                           /*Current WLAN device PM mode state : see enum ::WsmPmModeStatus*/
        uint8_t    Reserved[3];               ///< reserved for future use, set to 0
} WsmHiSetPmModeCmplIndBody_t;

typedef struct __attribute__((__packed__)) WsmHiSetPmModeCmplInd_s {
        HiMsgHdr_t Header;             
        WsmHiSetPmModeCmplIndBody_t Body;               
} WsmHiSetPmModeCmplInd_t;


/**
 * @}
 */
/* end of WSM_STA_specific */



/**
 * @addtogroup WSM_AP_specific
 * @brief Split MAC commands only used for Access Point setup or control
 *
 * This is the mode in which the WLAN firmware can act as a WLAN Access Point with limited capabilities.@n
 * In the MiniAP mode, the firmware can support up to 14 associated STAs simultaneously.@n
 * It is the responsibility of the host to map the MAC address of a STA to a PeerStaId (from 1 to 14).@n
 * Note that PeerStaId = 0 is reserved for the broadcast and multicast traffic.@n
 * And PeerStaId = 15 is reserved for the WLAN firmware to flag for instance the traffic coming from a station that is not yet associated.
 *
 * The host must set-up the beacon and probe response templates with appropriate values as part of the initialization procedure before starting the beaconing activity.
 * @{
 */

/**
* @brief Start in AP like mode.
*
* This host-to-device message requests the device to start in Access Point mode.
* It does not start beaconing. For that ::WsmHiBeaconTransmitReqBody_t must be sent.
*
*/
typedef struct __attribute__((__packed__)) WsmHiStartReqBody_s {
        uint8_t    Mode;                             ///<reserved for future use, set to 0
        uint8_t    Band;                             ///<Selects the radio band. Must be set to 0 (=2.4 GHz band).
        uint16_t   ChannelNumber;                    ///<Specifies the channel number to use. The channel number will be mapped to an actual frequency according to the band.
        uint32_t   Reserved1;                        ///<reserved for future use, set to 0
        uint32_t   BeaconInterval;                   ///<Interval between two consecutive beacon transmissions in TU.
        uint8_t    DTIMPeriod;                       ///<DTIM period in terms of beacon intervals.
        uint8_t    PreambleType;                     ///<Specifies the PLCP preamble type used. See enum : WsmPreamble
        uint8_t    Reserved2;                        ///<reserved for future use, set to 0
        uint8_t    SsidLength;                       ///<Length of the SSID below.
        uint8_t    Ssid[WSM_API_SSID_SIZE];          ///<SSID of the BSS or P2P_GO to be started.
        uint32_t   BasicRateSet;                     ///<A bit mask that defines the BSS basic rate set. See enum ::WsmTransmitRate.
} WsmHiStartReqBody_t;

typedef struct __attribute__((__packed__)) WsmHiStartReq_s {
        HiMsgHdr_t Header;             
        WsmHiStartReqBody_t Body;               
} WsmHiStartReq_t;


/**
* @brief Confirmation message of start AP command ::WsmHiStartReqBody_t
*/
typedef struct __attribute__((__packed__)) WsmHiStartCnfBody_s {
        uint32_t   Status;                           ///< See ::WsmStatus.
} WsmHiStartCnfBody_t;

typedef struct __attribute__((__packed__)) WsmHiStartCnf_s {
        HiMsgHdr_t Header;             
        WsmHiStartCnfBody_t Body;               
} WsmHiStartCnf_t;



/**
 * @brief Enum to control the beacon transmission in ::WsmHiBeaconTransmitReqBody_t.
 *
 * */
typedef enum WsmBeacon_e {
        WSM_BEACON_STOP                       = 0x0,         ///<Stop beacon transmission
        WSM_BEACON_START                      = 0x1          ///<Start beacon transmission
} WsmBeacon;

/**
* @struct WsmHiBeaconTransmitReqBody_t
* @brief Start/stop transmitting beacons
*
* This host-to-device message requests the MiniAP to start beacon transmission
* Beacon and probe_response template frame should be downloaded before issuing this request (see ::WsmHiMibTemplateFrame_t).
*/
typedef struct __attribute__((__packed__)) WsmHiBeaconTransmitReqBody_s {
        uint8_t    EnableBeaconing;          ///<see enum ::WsmBeacon.
        uint8_t    Reserved[3];              ///< reserved for future use, set to 0
} WsmHiBeaconTransmitReqBody_t;

typedef struct __attribute__((__packed__)) WsmHiBeaconTransmitReq_s {
        HiMsgHdr_t Header;             
        WsmHiBeaconTransmitReqBody_t Body;               
} WsmHiBeaconTransmitReq_t;


/**
* @struct WsmHiBeaconTransmitCnfBody_t
* @brief Confirmation message of beacon transmission management command ::WsmHiBeaconTransmitReqBody_t
*/
typedef struct __attribute__((__packed__)) WsmHiBeaconTransmitCnfBody_s {
        uint32_t   Status;                           ///< See ::WsmStatus.
} WsmHiBeaconTransmitCnfBody_t;

typedef struct __attribute__((__packed__)) WsmHiBeaconTransmitCnf_s {
        HiMsgHdr_t Header;             
        WsmHiBeaconTransmitCnfBody_t Body;               
} WsmHiBeaconTransmitCnf_t;


/**
 * @brief Enum for STA mapping used in ::WsmHiMapLinkReqBody_t::MapLinkFlags.
 *
 * */
typedef enum WsmStaMapDirection_e {
        WSM_STA_MAP                       = 0x0,         ///<map=connect a station
        WSM_STA_UNMAP                     = 0x1          ///<unmap=disconnect a station
} WsmStaMapDirection;

/**
* @struct WsmHiMapLinkFlags_t
* @brief Configuration flags used in command ::WsmHiMapLinkReqBody_t
*/
typedef struct __attribute__((__packed__)) WsmHiMapLinkFlags_s {
        uint8_t    MapDirection : 1;                 ///<see enum ::WsmStaMapDirection
        uint8_t    Mfpc : 1;                         ///<Set to 1 if STA advertised MFPC bit (management frame protection capable)
        uint8_t    Reserved : 6;                     ///<reserved for future use, set to 0
} WsmHiMapLinkFlags_t;

/**
* @struct WsmHiMapLinkReqBody_t
* @brief Map a given mac_address to a PeerStaId
*
* This host-to-device message requests the device to add or remove a connection with a remote STAtion.
*/
typedef struct __attribute__((__packed__)) WsmHiMapLinkReqBody_s {
        uint8_t    MacAddr[WSM_API_MAC_ADDR_SIZE];   ///<MAC address of the remote device
        WsmHiMapLinkFlags_t MapLinkFlags;          ///<Configuration parameters (including add or remove info)
        uint8_t    PeerStaId;                        ///<In the range 1 to 14. ID used in other commands to identify this connection.
} WsmHiMapLinkReqBody_t;

typedef struct __attribute__((__packed__)) WsmHiMapLinkReq_s {
        HiMsgHdr_t Header;
        WsmHiMapLinkReqBody_t Body;
} WsmHiMapLinkReq_t;


/**
* @struct WsmHiMapLinkCnfBody_t
* @brief Confirmation message of peer addition/removal command ::WsmHiMapLinkReqBody_t
*/
typedef struct __attribute__((__packed__)) WsmHiMapLinkCnfBody_s {
        uint32_t   Status;                           ///<See ::WsmStatus.
} WsmHiMapLinkCnfBody_t;

typedef struct __attribute__((__packed__)) WsmHiMapLinkCnf_s {
        HiMsgHdr_t Header;
        WsmHiMapLinkCnfBody_t Body;
} WsmHiMapLinkCnf_t;



typedef struct __attribute__((__packed__)) WsmHiSuspendResumeFlags_s {
        uint8_t    ResumeOrSuspend : 1;              /*0 - Stop sending further Tx requests to the device for this link. 1 -Resume Tx. type: WSM*/
        uint8_t    Ac : 2;                           /*The AC on which Tx must be suspended or resumed. This is applicable only for UAPSD.*/
        uint8_t    CastType : 1;                     /*1 - Transmit broadcast or multicast frames. This is to instruct the host to transmit broadcast or multicast traffic, if buffered in the host after the DTIM beacon.            0 - Transmit unicast frames.*/
        uint8_t    Reserved1 : 4;                    ///< reserved for future use, set to 0
        uint8_t    Reserved2;                        ///< reserved for future use, set to 0
} WsmHiSuspendResumeFlags_t;

#define WSM_API_TX_RESUME_FLAGS_PER_IF_SIZE             3
/* indication WSM_HI_SUSPEND_RESUME_TX */
/* Send no more Tx requests */
typedef struct __attribute__((__packed__)) WsmHiSuspendResumeTxIndBody_s {
        WsmHiSuspendResumeFlags_t SuspendResumeFlags; 
        uint16_t   					TxResumeFlagsPerIf;   /*Set to 0*/
} WsmHiSuspendResumeTxIndBody_t;

typedef struct __attribute__((__packed__)) WsmHiSuspendResumeTxInd_s {
        HiMsgHdr_t Header;             
        WsmHiSuspendResumeTxIndBody_t Body;               
} WsmHiSuspendResumeTxInd_t;

/**
 * @}
 */
/* end of WSM_AP_specific */





/**
 * @addtogroup WSM_Key_Management
 * @brief Split MAC Radio Encryption Key Management commands
 *
 *@todo add details
 *
 * @{
 */
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
        WSM_KEY_TYPE_WEP_DEFAULT                   = 0x0,         /*WEP default (group) key*/
        WSM_KEY_TYPE_WEP_PAIRWISE                  = 0x1,         /*WEP pairwise key*/
        WSM_KEY_TYPE_TKIP_GROUP                    = 0x2,         /*TKIP group key*/
        WSM_KEY_TYPE_TKIP_PAIRWISE                 = 0x3,         /*TKIP pairwise key*/
        WSM_KEY_TYPE_AES_GROUP                     = 0x4,         /*AES group key*/
        WSM_KEY_TYPE_AES_PAIRWISE                  = 0x5,         /*AES pairwise key*/
        WSM_KEY_TYPE_WAPI_GROUP                    = 0x6,         /*WAPI group key*/
        WSM_KEY_TYPE_WAPI_PAIRWISE                 = 0x7,         /*WAPI pairwise key*/
        WSM_KEY_TYPE_IGTK_GROUP                    = 0x8,         /*IGTK group key*/
        WSM_KEY_TYPE_NONE                          = 0x9          /*No key*/
} WsmKeyType;

typedef struct __attribute__((__packed__)) WsmHiWepPairwiseKey_s {
        uint8_t    PeerAddress[WSM_API_MAC_ADDR_SIZE];   /*MAC address of the peer station type: SL_CONFIGURE_IND_STATUS*/
        uint8_t    Reserved;                         /*Reserved type: SlConfigureSkeyInvld*/
        uint8_t    KeyLength;                        /*Key Length in bytes*/
        uint8_t    KeyData[WSM_API_WEP_KEY_DATA_SIZE];   /*Key data*/
} WsmHiWepPairwiseKey_t;

typedef struct __attribute__((__packed__)) WsmHiWepGroupKey_s {
        uint8_t    KeyId;                            /*Unique per key identifier. Standard only allows up to four WEP group keys.*/
        uint8_t    KeyLength;                        /*Key length in bytes*/
        uint8_t    Reserved[2];   ///< reserved for future use, set to 0
        uint8_t    KeyData[WSM_API_WEP_KEY_DATA_SIZE];   /*Key data*/
} WsmHiWepGroupKey_t;

typedef struct __attribute__((__packed__)) WsmHiTkipPairwiseKey_s {
        uint8_t    PeerAddress[WSM_API_MAC_ADDR_SIZE];   /*MAC address of the peer station*/
        uint8_t    Reserved[2];   ///< reserved for future use, set to 0
        uint8_t    TkipKeyData[WSM_API_TKIP_KEY_DATA_SIZE];   /*TKIP Key data*/
        uint8_t    RxMicKey[WSM_API_RX_MIC_KEY_SIZE];   /*Rx MIC key*/
        uint8_t    TxMicKey[WSM_API_TX_MIC_KEY_SIZE];   /*Tx MIC key*/
} WsmHiTkipPairwiseKey_t;

typedef struct __attribute__((__packed__)) WsmHiTkipGroupKey_s {
        uint8_t    TkipKeyData[WSM_API_TKIP_KEY_DATA_SIZE];   /*TKIP key data*/
        uint8_t    RxMicKey[WSM_API_RX_MIC_KEY_SIZE];   /*Rx MIC key*/
        uint8_t    KeyId;                            /*Key Id*/
        uint8_t    Reserved[3];   ///< reserved for future use, set to 0
        uint8_t    RxSequenceCounter[WSM_API_RX_SEQUENCE_COUNTER_SIZE];   /*Receive sequence counter*/
} WsmHiTkipGroupKey_t;

typedef struct __attribute__((__packed__)) WsmHiAesPairwiseKey_s {
        uint8_t    PeerAddress[WSM_API_MAC_ADDR_SIZE];   /*MAC address of the peer station*/
        uint8_t    Reserved[2];   ///< reserved for future use, set to 0
        uint8_t    AesKeyData[WSM_API_AES_KEY_DATA_SIZE];   /*AES key data*/
} WsmHiAesPairwiseKey_t;

typedef struct __attribute__((__packed__)) WsmHiAesGroupKey_s {
        uint8_t    AesKeyData[WSM_API_AES_KEY_DATA_SIZE];   /*AES key data*/
        uint8_t    KeyId;                            /*Key Id*/
        uint8_t    Reserved[3];   ///< reserved for future use, set to 0
        uint8_t    RxSequenceCounter[WSM_API_RX_SEQUENCE_COUNTER_SIZE];   /*Receive sequence counter*/
} WsmHiAesGroupKey_t;

typedef struct __attribute__((__packed__)) WsmHiWapiPairwiseKey_s {
        uint8_t    PeerAddress[WSM_API_MAC_ADDR_SIZE];   /*MAC address of the peer station*/
        uint8_t    KeyId;                            /*Key Id*/
        uint8_t    Reserved;                         ///< reserved for future use, set to 0
        uint8_t    WapiKeyData[WSM_API_WAPI_KEY_DATA_SIZE];   /*WAPI key data*/
        uint8_t    MicKeyData[WSM_API_MIC_KEY_DATA_SIZE];   /*MIC key data*/
} WsmHiWapiPairwiseKey_t;

typedef struct __attribute__((__packed__)) WsmHiWapiGroupKey_s {
        uint8_t    WapiKeyData[WSM_API_WAPI_KEY_DATA_SIZE];   /*WAPI key data*/
        uint8_t    MicKeyData[WSM_API_MIC_KEY_DATA_SIZE];   /*MIC key data*/
        uint8_t    KeyId;                            /*Key Id*/
        uint8_t    Reserved[3];   ///< reserved for future use, set to 0
} WsmHiWapiGroupKey_t;

typedef struct __attribute__((__packed__)) WsmHiIgtkGroupKey_s {
        uint8_t    IGTKKeyData[WSM_API_IGTK_KEY_DATA_SIZE];   /*IGTK key data*/
        uint8_t    KeyId;                            /*Key Id*/
        uint8_t    Reserved[3];   ///< reserved for future use, set to 0
        uint8_t    IPN[WSM_API_IPN_SIZE];            /*IGTK packet number*/
} WsmHiIgtkGroupKey_t;

typedef union WsmPrivacyKeyData_u {
        WsmHiWepPairwiseKey_t                       WepPairwiseKey;                 /* Element :0*/
        WsmHiWepGroupKey_t                          WepGroupKey;                    /* Element :1*/
        WsmHiTkipPairwiseKey_t                      TkipPairwiseKey;                /* Element :2*/
        WsmHiTkipGroupKey_t                         TkipGroupKey;                   /* Element :3*/
        WsmHiAesPairwiseKey_t                       AesPairwiseKey;                 /* Element :4*/
        WsmHiAesGroupKey_t                          AesGroupKey;                    /* Element :5*/
        WsmHiWapiPairwiseKey_t                      WapiPairwiseKey;                /* Element :6*/
        WsmHiWapiGroupKey_t                         WapiGroupKey;                   /* Element :7*/
        WsmHiIgtkGroupKey_t                         IgtkGroupKey;                   /* Element :8*/
} WsmPrivacyKeyData_t;

/* request WSM_HI_ADD_KEY */
/* Requests to add a new key */
typedef struct __attribute__((__packed__)) WsmHiAddKeyReqBody_s {
        uint8_t    Type;                             /*Type of the key to be added: see enum ::WsmKeyType*/
        uint8_t    EntryIndex;                       /*Key entry index: 0 to MAX_KEY_ENTRIES-1*/
        uint16_t   Reserved;                         ///< reserved for future use, set to 0
        WsmPrivacyKeyData_t Key;
} WsmHiAddKeyReqBody_t;

typedef struct __attribute__((__packed__)) WsmHiAddKeyReq_s {
        HiMsgHdr_t Header;
        WsmHiAddKeyReqBody_t Body;
} WsmHiAddKeyReq_t;

/* confirmation WSM_HI_ADD_KEY */
/* Requests to add a new key */
typedef struct __attribute__((__packed__)) WsmHiAddKeyCnfBody_s {
        uint32_t   Status;                           /*Error codes for the Add-Key request.*/
} WsmHiAddKeyCnfBody_t;

typedef struct __attribute__((__packed__)) WsmHiAddKeyCnf_s {
        HiMsgHdr_t Header;
        WsmHiAddKeyCnfBody_t Body;
} WsmHiAddKeyCnf_t;

/* request WSM_HI_REMOVE_KEY */
/* Requests to remove a key */
typedef struct __attribute__((__packed__)) WsmHiRemoveKeyReqBody_s {
        uint8_t    EntryIndex;                       /*Key entry index: 0 to MAX_KEY_ENTRIES-1*/
        uint8_t    Reserved[3];            ///< reserved for future use, set to 0
} WsmHiRemoveKeyReqBody_t;

typedef struct __attribute__((__packed__)) WsmHiRemoveKeyReq_s {
        HiMsgHdr_t Header;
        WsmHiRemoveKeyReqBody_t Body;
} WsmHiRemoveKeyReq_t;

/* confirmation WSM_HI_REMOVE_KEY */
/* Requests to remove a key */
typedef struct __attribute__((__packed__)) WsmHiRemoveKeyCnfBody_s {
        uint32_t   Status;                           /*Error codes for the Remove-Key request.*/
} WsmHiRemoveKeyCnfBody_t;

typedef struct __attribute__((__packed__)) WsmHiRemoveKeyCnf_s {
        HiMsgHdr_t Header;
        WsmHiRemoveKeyCnfBody_t Body;
} WsmHiRemoveKeyCnf_t;


/**
 * @}
 */
/* end of WSM_Key_Management */


typedef enum WsmEventInd_e {
        WSM_EVENT_IND_BSSLOST                      = 0x1,         /*BSS lost*/
        WSM_EVENT_IND_BSSREGAINED                  = 0x2,         /*BSS regained*/
        WSM_EVENT_IND_RCPI_RSSI                    = 0x3,         /*RCPI or RSSI threshold triggered*/
        WSM_EVENT_IND_PS_MODE_ERROR                = 0x4,         /*PS-Mode error, indicating that the WLAN device had detected problems in the Power Save mode operation of the AP*/
		WSM_EVENT_IND_INACTIVITY                   = 0x5          /*Inactive*/
} WsmEventInd;

typedef enum WsmPsModeError_e {
		WSM_PS_ERROR_NO_ERROR	                   = 0,
		WSM_PS_ERROR_AP_NOT_RESP_TO_POLL	       = 1,
		WSM_PS_ERROR_AP_NOT_RESP_TO_UAPSD_TRIGGER  = 2,
		WSM_PS_ERROR_AP_SENT_UNICAST_IN_DOZE       = 3,
		WSM_PS_ERROR_AP_NO_DATA_AFTER_TIM          = 4
} WsmPsModeError;

typedef union WsmEventData_u {
        uint8_t 					RcpiRssi;                       /* Element :3*/
        uint32_t 					P_S_Mode_Error;                 /* Element :4*/
        uint32_t					PeerStaId;						/* Element :5*/
} WsmEventData_t;

/* indication WSM_HI_EVENT */
/* Event indication */
typedef struct __attribute__((__packed__)) WsmHiEventIndBody_s {
        uint32_t   EventId;                          /*Identifies the indication*/
        WsmEventData_t EventData;                  /*Indication parameters. For error indication, this will be a 32-bit WSM status.For RCPI or RSSI indication, this should be an 8-bit RCPI or RSSI value*/
} WsmHiEventIndBody_t;

typedef struct __attribute__((__packed__)) WsmHiEventInd_s {
        HiMsgHdr_t Header;
        WsmHiEventIndBody_t Body;
} WsmHiEventInd_t;




/**************************************************/

/**
 * @}
 * end of SPLIT_MAC_API
 */

#endif  /* _WSM_CMD_API_H_ */
