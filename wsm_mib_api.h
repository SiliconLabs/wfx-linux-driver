/***************************************************************************//**
 * @file wsm_mib_api.h
 * @brief This file contains the type definitions for LMAC API MIB structures,
 *  enums, and other types.
 *
 * @copyright Copyright 2015 Silicon Laboratories, Inc. http://www.silabs.com
 ******************************************************************************/

#ifndef _WSM_MIB_API_H_
#define _WSM_MIB_API_H_

#include "general_api.h"

//standard address sizes in bytes
#define WSM_API_MAC_ADDR_SIZE                           API_MAC_ADDR_SIZE
#define WSM_API_IPV4_ADDRESS_SIZE                       4
#define WSM_API_IPV6_ADDRESS_SIZE                       16


/**
 * @addtogroup SPLIT_MAC_API
 *
 * @{
 */
/**
 * @addtogroup MIB
 * @brief Split MAC MIB used for rather static configuration.
 *
 * MIB elements are written/read using the requests ::WsmHiWriteMibReqBody_t and ::WsmHiReadMibReqBody_t.
 * @{
 */


/**
 * @brief list of all MIB elements indirectly configured (or read) using commands ::WsmHiWriteMibReqBody_t (or ::WsmHiReadMibReqBody_t).
 * */
typedef enum WsmMibIds_e {
		/* General MIB */
		WSM_MIB_ID_GL_OPERATIONAL_POWER_MODE       = 0x2000,      /* OperationalPowerMode */
		WSM_MIB_ID_GL_BLOCK_ACK_INFO               = 0x2001,      /* Test Purposes Only */
        WSM_MIB_ID_GL_SET_MULTI_MSG                = 0x2002,      ///<UseMultiTxConfMessage : enables the use of the multi-transmit confirmation message (::WsmHiMultiTransmitCnfBody_t). 0: Disable. 1: enable.
		/* Filtering MIB */
        WSM_MIB_ID_ETHERTYPE_DATAFRAME_CONDITION   = 0x2010,      /* EtherTypeDataFrameCondition */
        WSM_MIB_ID_PORT_DATAFRAME_CONDITION        = 0x2011,      /* PortDataFrameCondition */
        WSM_MIB_ID_MAGIC_DATAFRAME_CONDITION       = 0x2012,      /* MagicDataFrameCondition */
        WSM_MIB_ID_MAC_ADDR_DATAFRAME_CONDITION    = 0x2013,      /* MAC Address Data Frame Condition */
        WSM_MIB_ID_IPV4_ADDR_DATAFRAME_CONDITION   = 0x2014,      /* IPv4 Address Data Frame Condition */
        WSM_MIB_ID_IPV6_ADDR_DATAFRAME_CONDITION   = 0x2015,      /* IPv6 Address Data Frame Condition */
        WSM_MIB_ID_UC_MC_BC_DATAFRAME_CONDITION    = 0x2016,      /* Unicast, multicast broadcast Condition */
        WSM_MIB_ID_CONFIG_DATA_FILTER              = 0x2017,      /* ConfigureDataFilter */
        WSM_MIB_ID_SET_DATA_FILTERING              = 0x2018,      /* SetDataFiltering */
		WSM_MIB_ID_ARP_IP_ADDRESSES_TABLE          = 0x2019,      /* ArpIpAddressesTable */
        WSM_MIB_ID_NS_IP_ADDRESSES_TABLE           = 0x201A,      /* Set IPv6 Address for Neighbor solicitation reply */
        WSM_MIB_ID_RX_FILTER                       = 0x201B,      /* RxFilter */
        WSM_MIB_ID_BEACON_FILTER_TABLE             = 0x201C,      /* BeaconFilterTable */
        WSM_MIB_ID_BEACON_FILTER_ENABLE            = 0x201D,      /* BeaconFilterEnable */
		/* Others Read-only MIB */
		WSM_MIB_ID_GRP_SEQ_COUNTER                 = 0x2030,      /* GroupTxSequenceCounter */
		WSM_MIB_ID_TSF_COUNTER                     = 0x2031,      /* TSF Counter Value */
		WSM_MIB_ID_STATISTICS_TABLE                = 0x2032,      /* StatisticsTable */
		WSM_MIB_ID_COUNTERS_TABLE                  = 0x2033,      /* CountersTable */
		/* Others R/W or RO MIB */
        WSM_MIB_ID_DOT11_MAC_ADDRESS               = 0x2040,      /* dot11MacAdress */
        WSM_MIB_ID_DOT11_MAX_TRANSMIT_MSDU_LIFETIME = 0x2041,     ///< This is a standard 802.11 MIB variable (dot11MaxtransmitMsduLifeTime). It is the elapsed time in TUs, after the initial transmission of an MSDU, after which further attempts to transmit the MSDU will be terminated.
        WSM_MIB_ID_DOT11_MAX_RECEIVE_LIFETIME      = 0x2042,      /* dot11MaxReceiveLifeTime */
        WSM_MIB_ID_DOT11_WEP_DEFAULT_KEY_ID        = 0x2043,      /* dot11WepDefaultKeyId */
        WSM_MIB_ID_DOT11_RTS_THRESHOLD             = 0x2044,      /* dot11RTSThreshold */
		WSM_MIB_ID_SLOT_TIME                 	   = 0x2045,      /* SlotTime */
		WSM_MIB_ID_CURRENT_TX_POWER_LEVEL   	   = 0x2046,      /* CurrentTxPowerLevel */
        WSM_MIB_ID_NON_ERP_PROTECTION              = 0x2047,      /* NonErpProtection */
        WSM_MIB_ID_TEMPLATE_FRAME                  = 0x2048,      /* TemplateFrame */
        WSM_MIB_ID_BEACON_WAKEUP_PERIOD            = 0x2049,      /* BeaconWakeUpPeriod */
        WSM_MIB_ID_RCPI_RSSI_THRESHOLD             = 0x204A,      /* RcpiRssiThreshold */
        WSM_MIB_ID_BLOCK_ACK_POLICY                = 0x204B,      /* BlockAckPolicy */
        WSM_MIB_ID_OVERRIDE_INTERNAL_TX_RATE       = 0x204C,      /* OverrideInternalTxRate */
        WSM_MIB_ID_SET_ASSOCIATION_MODE            = 0x204D,      /* SetAssociationMode */
        WSM_MIB_ID_SET_UAPSD_INFORMATION           = 0x204E,      /* SetUpasdInformation */
        WSM_MIB_ID_SET_TX_RATE_RETRY_POLICY        = 0x204F,      /* SetTxRateRetryPolicy */
        WSM_MIB_ID_PROTECTED_MGMT_POLICY           = 0x2050,      /* Protected Management Frame policy */
        WSM_MIB_ID_SET_HT_PROTECTION               = 0x2051,      /* SetHtProtection */
        WSM_MIB_ID_KEEP_ALIVE_PERIOD               = 0x2052,      /* Keep-alive period */
        WSM_MIB_ID_ARP_KEEP_ALIVE_PERIOD           = 0x2053,      /* Keep-alive period */
        WSM_MIB_ID_INACTIVITY_TIMER                = 0x2054,      /* Mib to Enable Inactivity Timer */
		WSM_MIB_ID_INTERFACE_PROTECTION            = 0x2055,     /* Mib to Enable Cts to self protection when leaving the interface */
} WsmMibIds;

/**
 * @addtogroup WSM_General_Mibs
 * @brief General MIB elements
 *
 * @{
 */

/* used in WSM_MIB_ID_GL_OPERATIONAL_POWER_MODE */
#define WSM_OP_POWER_MODE_MASK                     0xf
typedef enum WsmOpPowerMode_e {
        WSM_OP_POWER_MODE_ACTIVE                   = 0x0,
        WSM_OP_POWER_MODE_DOZE                     = 0x1,
        WSM_OP_POWER_MODE_QUIESCENT                = 0x2
} WsmOpPowerMode;

typedef struct __attribute__((__packed__)) WsmHiMibGlBlockAckInfo_s {
        uint8_t    BufferSize;
        uint8_t    MaxNumAgreements;
        uint8_t    Reserved[2];   /*Reserved 0*/
} WsmHiMibGlBlockAckInfo_t;

/**
 * @}
 */
/* end of WSM_General_Mibs */

/**
 * @addtogroup WSM_filtering
 * @brief MIB elements used to define the filtering done on data packets
 *
 * The global data filtering enable/disable all the filtering defined by the WsmHiMibConfigDataFilter_t MIBs.
 * When disabled, all data frames are send to the HOST.
 * When enabled, if DefaultFilter is set to 0, all data frames are send to the host except frames that match at least one filter.
 * When enabled, if DefaultFilter is set to 1, all data frames are discarded except frames that match at least one filter.
 *
 * MAX_NUMBER_DATA_FILTERS filters can be configured by the WsmHiMibConfigDataFilter_t MIB. A filter can be a combination of conditions.
 * For example, MIB to configure filter 2 with conditions EthTypeCon0 and MacCond1: {2,1,0,1,0,0,2,0,0,0,0}.
 *
 *
 * Arp and NS filtering do not depend of "global filtering". Action depends on the "ArpEnable or NsEnable" field value:
 *
 * - WSM_ARP_NS_FILTERING_DISABLE: All frames are send to host.
 * - WSM_ARP_NS_FILTERING_ENABLE: All frames with not matches address are dropped. The others are send to host.
 * - WSM_ARP_NS_REPLY_ENABLE: A reply is automatically sent without the host notification to the frames with matches address.
 *                            The others are dropped.
 * @{
 */

// Nb max of data filters
#define MAX_NUMBER_DATA_FILTERS             0xA

// Nb of conditions for filtering
#define MAX_NUMBER_IPV4_ADDR_CONDITIONS     0x4
#define MAX_NUMBER_IPV6_ADDR_CONDITIONS     0x4
#define MAX_NUMBER_MAC_ADDR_CONDITIONS      0x4
#define MAX_NUMBER_UC_MC_BC_CONDITIONS      0x4
#define MAX_NUMBER_ETHER_TYPE_CONDITIONS    0x4
#define MAX_NUMBER_PORT_CONDITIONS          0x4
#define MAX_NUMBER_MAGIC_CONDITIONS         0x4
#define MAX_NUMBER_ARP_CONDITIONS           0x2
#define MAX_NUMBER_NS_CONDITIONS            0x2

/**
 * @structure WsmHiMibEthertypeDataFrameCondition_t
 * @brief Ethernet type data filtering
 * */
typedef struct __attribute__((__packed__)) WsmHiMibEthertypeDataFrameCondition_s {
        uint8_t    ConditionIdx;                     ///< Condition index (0 to 3)
        uint8_t    reserved;                         ///< Padding
        uint16_t   EtherType;                        ///< EtherType to match
} WsmHiMibEthertypeDataFrameCondition_t;

/**
 * @brief Protocol UDP, TCP or both
 * */
typedef enum WsmUdpTcpProtocol_e {
        WSM_PROTOCOL_UDP                       = 0x0,
        WSM_PROTOCOL_TCP                       = 0x1,
        WSM_PROTOCOL_BOTH_UDP_TCP              = 0x2
} WsmUdpTcpProtocol;

/**
 * @brief Port destination, source, source or destination
 * */
typedef enum WsmWhichPort_e {
        WSM_PORT_DST                           = 0x0,
        WSM_PORT_SRC                           = 0x1,
        WSM_PORT_SRC_OR_DST                    = 0x2
} WsmWhichPort;

/**
 * @structure WsmHiMibPortsDataFrameCondition_t
 * @brief Port data filtering
 * */
typedef struct __attribute__((__packed__)) WsmHiMibPortsDataFrameCondition_s {
        uint8_t    ConditionIdx;              ///< Index of the port condition (0 to 3)
        uint8_t    Protocol;                  ///< see WsmUdpTcpProtocol
        uint8_t    WhichPort;                 ///< see WsmWhichPort
        uint8_t    reserved;                  ///< Padding
        uint16_t   PortNumber;                ///< The UDP port number to filter on
        uint8_t    reserved2[2];              ///< Padding
} WsmHiMibPortsDataFrameCondition_t;

/**
 * @structure WsmHiMibMagicDataFrameCondition_t
 * @brief Pattern data filtering
 * */
#define WSM_API_MAGIC_PATTERN_SIZE                 32
typedef struct __attribute__((__packed__)) WsmHiMibMagicDataFrameCondition_s {
        uint8_t    ConditionIdx;                              ///< Condition index (0 to 3)
        uint8_t    Offset;                                    ///< Offset in bytes from the end of the 802.11 header
        uint8_t    MagicPatternLength;                        ///< The length of the magic pattern. A maximum length of 32 bytes (WSM_MAX_MAGIC_PATTERN_LENGTH) is supported
        uint8_t    reserved;                                  ///< Padding
        uint8_t    MagicPattern[WSM_API_MAGIC_PATTERN_SIZE];  ///< The magic byte pattern to match
} WsmHiMibMagicDataFrameCondition_t;

/**
 * @brief MAC Address list.
 * */
typedef enum WsmMacAddrType_e {
        WSM_MAC_ADDR_A1                            = 0x0,
        WSM_MAC_ADDR_A2                            = 0x1,
        WSM_MAC_ADDR_A3                            = 0x2
} WsmMacAddrType;

/**
 * @structure WsmHiMibMacAddrDataFrameCondition_t
 * @brief MAC address data filtering
 * */
typedef struct __attribute__((__packed__)) WsmHiMibMacAddrDataFrameCondition_s {
        uint8_t    ConditionIdx;                       ///< Condition index (0 to 3)
        uint8_t    AddressType;                        ///< MAC address to be compared - see WsmMacAddrType
        uint8_t    MacAddress[WSM_API_MAC_ADDR_SIZE];  ///< The MAC Address to filter on
} WsmHiMibMacAddrDataFrameCondition_t;

/**
 * @brief Address IP mode: Source Address or Destination Address?
 * */
typedef enum WsmIpAddrMode_e {
        WSM_IP_ADDR_SRC                            = 0x0,
        WSM_IP_ADDR_DST                            = 0x1
} WsmIpAddrMode;

/**
 * @structure WsmHiMibIpv4AddrDataFrameCondition_t
 * @brief IPV4 address data filtering
 * */
typedef struct __attribute__((__packed__)) WsmHiMibIpv4AddrDataFrameCondition_s {
        uint8_t    ConditionIdx;                           ///< Condition index (0 to 3)
        uint8_t    AddressMode;                            ///< Source or destination address - see WsmIpAddrMode
        uint8_t    reserved[2];                            ///< Padding
        uint8_t    IPv4Address[WSM_API_IPV4_ADDRESS_SIZE]; ///< The IPv4 address to filter on
} WsmHiMibIpv4AddrDataFrameCondition_t;

/**
 * @structure WsmHiMibIpv6AddrDataFrameCondition_t
 * @brief IPV6 address data filtering
 * */
typedef struct __attribute__((__packed__)) WsmHiMibIpv6AddrDataFrameCondition_s {
        uint8_t    ConditionIdx;                           ///< Condition index (0 to 3)
        uint8_t    AddressMode;                            ///< Source or destination address - see WsmIpAddrMode
        uint8_t    reserved[2];                            ///< Padding
        uint8_t    IPv6Address[WSM_API_IPV6_ADDRESS_SIZE]; ///< The IPv6 address to filter on
} WsmHiMibIpv6AddrDataFrameCondition_t;

/**
 * @brief Type unicast, multicast and broadcast address
 * These three bits field define a condition.
 * */
typedef union __attribute__((__packed__)) WsmHiAddrType_u
{
    uint8_t value;
    struct {
        uint8_t    TypeUnicast   : 1;                      ///< bit0
        uint8_t    TypeMulticast : 1;                      ///< bit1
        uint8_t    TypeBroadcast : 1;                      ///< bit2
        uint8_t    reserved      : 5;                      ///< reserved
    }bits;
}WsmHiAddrType_t;

/**
 * @structure WsmHiMibUcMcBcDataFrameCondition_t
 * @brief Unicast, multicast and broadcast data filtering
 * The condition defined above matches if one of the defined bits field matches.
 * */
typedef struct __attribute__((__packed__)) WsmHiMibUcMcBcDataFrameCondition_s {
        uint8_t            ConditionIdx;                   ///< Condition index (0 to 3)
        WsmHiAddrType_t Param;                          ///< See WsmHiAddrType_t
        uint8_t            reserved[2];                    ///< Padding
} WsmHiMibUcMcBcDataFrameCondition_t;

/**
 * @structure WsmHiMibConfigDataFilter_t
 * @brief Data filters configuration
 * */
typedef struct __attribute__((__packed__)) WsmHiMibConfigDataFilter_s {
        uint8_t    FilterIdx;                        ///< Filter index
        uint8_t    Enable;                           ///< 0 - Disable filtering. 1 - Enable filtering
        uint8_t    reserved[2];                      ///< Padding
        uint8_t    EthTypeCond;                      ///< Ethernet type condition 0 (bit0) to 3 (bit3)
        uint8_t    PortCond;                         ///< Port condition 0 (bit0) to 3 (bit3)
        uint8_t    MagicCond;                        ///< Magic pattern condition 0 (bit0) to 3 (bit3)
        uint8_t    MacCond;                          ///< Mac address condition 0 (bit0) to 3 (bit3)
        uint8_t    Ipv4Cond;                         ///< Ipv4 address condition 0 (bit0) to 3 (bit3)
        uint8_t    Ipv6Cond;                         ///< Ipv6 address condition 0 (bit0) to 3 (bit3)
        uint8_t    UcMcBcCond;                       ///< Unicast Multicast Broadcast condition 0 (bit0) to 3 (bit3)
        uint8_t    reserved2;                        ///< Padding
} WsmHiMibConfigDataFilter_t;

/**
 * @structure WsmHiMibSetDataFiltering_t
 * @brief Global data filtering
 * */
typedef struct __attribute__((__packed__)) WsmHiMibSetDataFiltering_s {
        uint8_t    DefaultFilter;                    ///< 0: Accept all frames, 1: Discard all frames
        uint8_t    Enable;                           ///< 0: Disable the filtering feature, 1: Enable the filtering feature
        uint8_t    reserved[2];                      ///< Padding
} WsmHiMibSetDataFiltering_t;

/**
 * @brief ARP/NS frame treatment
 * */
typedef enum WsmArpNsFrameTreatment_e {
        WSM_ARP_NS_FILTERING_DISABLE                  = 0x0,
        WSM_ARP_NS_FILTERING_ENABLE                   = 0x1,
        WSM_ARP_NS_REPLY_ENABLE                       = 0x2
} WsmArpNsFrameTreatment;

/**
 * @structure WsmHiMibArpIpAddrTable_t
 * @brief Address Resolution Protocol (ARP) request IP address data filtering
 * */
typedef struct __attribute__((__packed__)) WsmHiMibArpIpAddrTable_s {
        uint8_t    ConditionIdx;                             ///< Condition index (0 to 1)
        uint8_t    ArpEnable;                                ///< see WsmArpNsFrameTreatment
        uint8_t    reserved[2];                              ///< Padding
        uint8_t    Ipv4Address[WSM_API_IPV4_ADDRESS_SIZE];   ///< The IP V4 address
} WsmHiMibArpIpAddrTable_t;

/**
 * @structure WsmHiMibNsIpAddrTable_t
 * @brief Neighbor Solicitation (NS) IP address data filtering
 * */
typedef struct __attribute__((__packed__)) WsmHiMibNsIpAddrTable_s {
        uint8_t    ConditionIdx;                             ///< Condition index (0 to 1)
        uint8_t    NsEnable;                                 ///< see WsmArpNsFrameTreatment
        uint8_t    reserved[2];                              ///< Padding
        uint8_t    Ipv6Address[WSM_API_IPV6_ADDRESS_SIZE];   ///< The IP V6 address
} WsmHiMibNsIpAddrTable_t;

#define WSM_API_OUI_SIZE                                3
#define WSM_API_MATCH_DATA_SIZE                         3
typedef struct __attribute__((__packed__)) WsmHiIeTableEntry_s {
        uint8_t    IeId;                             /*Information element number*/
        uint8_t    HasChanged : 1;                   /*Bit 0 = 1 - If IE has changed*/
        uint8_t    NoLonger : 1;                     /*Bit 1 = 1 - If IE is no longer present.*/
        uint8_t    HasAppeared : 1;                  /*Bit 2 = 1 - If IE has appeared.*/
        uint8_t    Reserved : 1;                     ///< reserved for future use, set to 0
        uint8_t    NumMatchData : 4;                 /*Bits 7 to 4 - Number of valid MatchData bytes. Applicable to IE 221 only.*/
        uint8_t    Oui[WSM_API_OUI_SIZE];            /*OUI of the information element 221. This field is only present for IE 221. 0*/
        uint8_t    MatchData[WSM_API_MATCH_DATA_SIZE];   /*OUI type of IE 221. This field is only present for IE 221. 0*/
} WsmHiIeTableEntry_t;

#define WSM_API_IE_TABLE_SIZE                           4
typedef struct __attribute__((__packed__)) WsmHiMibBcnFilterTable_s {
        uint32_t   NumOfInfoElmts;                   /*Number of information elements. Value of 0 clears the table.*/
        WsmHiIeTableEntry_t IeTable[WSM_API_IE_TABLE_SIZE];   /*IE-Table details. type: WsmHiIeTableEntry_t*/
} WsmHiMibBcnFilterTable_t;

typedef enum WsmBeaconFilter_e {
        WSM_BEACON_FILTER_DISABLE                  = 0x0,         /*Beacon filtering is disabled (default).*/
        WSM_BEACON_FILTER_ENABLE                   = 0x1,         /*Beacon filtering is enabled.*/
        WSM_BEACON_FILTER_AUTO_ERP                 = 0x2          /*Auto ERP filtering is enabled (bit 1 has to be 1as well).*/
} WsmBeaconFilter;

typedef struct __attribute__((__packed__)) WsmHiMibBcnFilterEnable_s {
        uint32_t   Enable;                           /* type: WsmBeaconFilter*/
        uint32_t   BcnCount;                         /*The value of received beacons for which the device wakes up the host.*/
} WsmHiMibBcnFilterEnable_t;

/**
 * @}
 */
/* end of WSM_filtering */

/**
 * @addtogroup WSM_Read_only
 * @brief MIB elements that are read-only
 *
 * @{
 */

typedef struct __attribute__((__packed__)) WsmHiMibGroupSeqCounter_s {
        uint32_t   Bits4716;                         /*Bits 16 to 47*/
        uint16_t   Bits1500;                         /*Bits 0 to 15*/
        uint16_t   Reserved;                         /*Padding*/
} WsmHiMibGroupSeqCounter_t;

typedef struct __attribute__((__packed__)) WsmHiMibTsfCounter_s {
        uint32_t   TSFCounterlo;                     /*TSF counter value (low)*/
        uint32_t   TSFCounterhi;                     /*TSF counter value (high)*/
} WsmHiMibTsfCounter_t;

typedef struct __attribute__((__packed__)) WsmHiMibStatsTable_s {
        uint16_t   LatestSnr;                        /*The latest SNR value.*/
        uint8_t    LatestRcpi;                       /*The latest RCPI value.*/
        int8_t    LatestRssi;                       /*The latest RSSI value.*/
} WsmHiMibStatsTable_t;

typedef struct __attribute__((__packed__)) WsmHiMibCountTable_s {
        uint32_t   CountPlcpErrors;                  /*Frames received with PLCP header errors detected.*/
        uint32_t   CountFcsErrors;                   /*Frames received with FCS errors.*/
        uint32_t   CountTxPackets;                   /*Frames transmitted, including automatic responses.*/
        uint32_t   CountRxPackets;                   /*Frames received with good FCS in the Rx buffer.*/
        uint32_t   CountRxPacketErrors;              /*Frames received with incorrect FCS or PLCP error.*/
        uint32_t   CountRxDecryptionFailures;        /*Frames received that failed decryption (AES MIC).*/
        uint32_t   CountRxMicFailures;               /*Frames received that failed the TKIP MIC check.*/
        uint32_t   CountRxNoKeyFailures;             /*Frames received encrypted but with no matching key in the key table.*/
        uint32_t   CountTxMulticastFrames;           /*Frames transmitted to multi-cast address.*/
        uint32_t   CountTxFramesSuccess;             /*Frames from host successfully transmitted.*/
        uint32_t   CountTxFrameFailures;             /*Frames from host that failed to transmit.*/
        uint32_t   CountTxFramesRetried;             /*Frames transmitted after retry attempts.*/
        uint32_t   CountTxFramesMultiRetried;        /*Frames transmitted after multiple retry attempts.*/
        uint32_t   CountRxFrameDuplicates;           /*Frames received but discarded as a duplicate.*/
        uint32_t   CountRtsSuccess;                  /*RTS frames transmitted successfully.*/
        uint32_t   CountRtsFailures;                 /*RTS frames transmitted that did not receive a CTS.*/
        uint32_t   CountAckFailures;                 /*Frame transmit attempts not receiving ACK.*/
        uint32_t   CountRxMulticastFrames;           /*Frames received with multicast receive address.*/
        uint32_t   CountRxFramesSuccess;             /*Frames received by device without error.*/
        uint32_t   CountRxCMACICVErrors;             /*MMPDUs discarded by CMAC integrity check algorithm.*/
        uint32_t   CountRxCMACReplays;               /*MMPDUs discarded by CMAC replay detector.*/
        uint32_t   CountRxMgmtCCMPReplays;           /*Robust MMPDUs discarded by CCMP replay detector.*/
        uint32_t   CountRxBIPMICErrors;              /*Robust MMPDUs discarded by CCMP replay detector.*/
} WsmHiMibCountTable_t;

/**
 * @}
 */
/* end of WSM_Read_only */

/**
 * @addtogroup WSM_Read_write
 * @brief MIB elements that are read-write
 *
 * @{
 */

typedef struct __attribute__((__packed__)) WsmHiMibMacAddress_s {
        uint8_t    MacAddr[WSM_API_MAC_ADDR_SIZE];   /*mac address to set for the interface*/
        uint16_t   Reserved;                         /*Reserved 0*/
} WsmHiMibMacAddress_t;

typedef struct __attribute__((__packed__)) WsmHiMibWepDefaultKeyId_s {
        uint8_t    WepDefaultKeyId;                  /*Range of 0 to 3.*/
        uint8_t    Reserved[3];                      /*Reserved 0*/
} WsmHiMibWepDefaultKeyId_t;


/**
 * @brief 802.11n High Throughput (HT) transmission mode. Used in MIB ::WsmHiMibTemplateFrame_t.
 */
typedef enum WsmTxMode_e {
        WSM_TX_MODE_MIXED                        = 0x0,
        WSM_TX_MODE_GREENFIELD                   = 0x1
} WsmTxMode;

/**
 * @brief Possible Template types. Used in MIB ::WsmHiMibTemplateFrame_t.
 */
typedef enum WsmTmplt_e {
        WSM_TMPLT_PRBREQ                           = 0x0,         ///<Probe request frame
        WSM_TMPLT_BCN                              = 0x1,         ///<Beacon frame
        WSM_TMPLT_NULL                             = 0x2,         ///<NULL data frame
        WSM_TMPLT_QOSNUL                           = 0x3,         ///<QoS NULL data frame
        WSM_TMPLT_PSPOLL                           = 0x4,         ///<PS-Poll frame
        WSM_TMPLT_PRBRES                           = 0x5,         ///<Probe response frame
        WSM_TMPLT_ARP                              = 0x6,         ///<ARP frame
        WSM_TMPLT_NA                               = 0x7          ///<Neighbor acknowledgment frame
} WsmTmplt;

#define WSM_API_MAX_TEMPLATE_FRAME_SIZE                              1024
/**
 * @brief Define a template for the automatically generated frames (WO MIB).
 *
 * It should be noted that the WLAN device is responsible for setting frame-control field to its right value or modify any other field when needed to carry out its operation.@n
 * For example, when entering into or exiting from power-save mode, the WLAN device is responsible for toggling the PS bit from the 802.11 header.@n
 * But all fields of the frame (modified or not afterwards by the WLAN FW) must be present in the template.
 *
 * Note1: For the frame types NULL data, QoS NULL data, and PS-Poll, the byte (Mode & InitRate) can be set to 0xFF to inform the device to use the MIB OverrideInternalTxRate for rate adaptation.
 * Note2 : The MIB structure must be padded to 4-byte length
 * Note3 : 1024 bytes of storage is reserved for the beacon and probe response templates.@n
 *         256 bytes of storage is reserved for probe request templates.@n
 *         32 bytes is reserved for NULL data frames.@n
 *         @todo check the max size for each template and complete the list above
 *  */
typedef struct __attribute__((__packed__)) WsmHiMibTemplateFrame_s {
        uint8_t    FrameType;                        ///< Template Frame type (see ::WsmTmplt)
        uint8_t    InitRate : 7;                     ///< Bits 6 to 0 - Defines the initial transmission rate. Note: This field is not valid for the probe_request template because the rate is specified by the scan command.
        uint8_t    Mode : 1;                         ///< Bit 7 - Indicates the mode to use for 11n frames. See enum ::WsmTxMode
        uint16_t   FrameLength;                      ///< Length of the frame in bytes. Measured from the first byte of the frame header to the last byte of the frame body but excluding any padding.
        uint8_t    Frame[WSM_API_MAX_TEMPLATE_FRAME_SIZE];        ///<Frame (maximum of 1024 bytes)
} WsmHiMibTemplateFrame_t;

typedef struct __attribute__((__packed__)) WsmHiMibBeaconWakeUpPeriod_s {
        uint8_t    WakeupPeriodMin;                  /*0 - Reserved. 1 to 255 - The minimum number of beacon periods the device will doze before waking up to receive a beacon. Recommended value : DTIM Period.*/
        uint8_t    ReceiveDTIM;                      /*0 - Device will wake up according to NumBeaconPeriods and ListenInterval values.            1 - Device will wake up for every DTIM frame. NumBeaconPeriods is ignored.*/
        uint16_t   WakeupPeriodMax;                  /*0 - Reserved. 1 to 255 - The maximum number of beacon periods the device will doze before waking up to receive a beacon. Recommended value : Listen Interval.*/
} WsmHiMibBeaconWakeUpPeriod_t;

/**
 * @structure WsmHiMibRcpiRssiThreshold_t
 * @brief Specifies threshold value for RCPI or RSSI
 *
 * This MIB specifies the threshold value for the RCPI or RSSI event indication to the WLAN host driver.
 * The RCPI or RSSI event is triggered when the RCPI or RSSI value goes below or over the threshold.
 * */
typedef struct __attribute__((__packed__)) WsmHiMibRcpiRssiThreshold_s {
        uint8_t    Detection : 1;                    ///<Bit 0 = 0 - Disable threshold detection (default). 1 - Enable threshold detection
        uint8_t    RcpiRssi : 1;                     ///<Bit 1 = 0 - Use RCPI (default). 1 - Use RSSI
        uint8_t    Upperthresh : 1;                  ///<Bit 2 = 0 - Use UpperThreshold (default). 1 - Do not use UpperThreshold
        uint8_t    Lowerthresh : 1;                  ///<Bit 3 = 0 - Use LowerThreshold (default). 1 - Do not use LowerThreshold
        uint8_t    Reserved : 4;                     ///<Bit 4 - Reserved, set to 0
        uint8_t    LowerThreshold;                   ///<The lower RCPI or RSSI threshold value.
        uint8_t    UpperThreshold;                   ///<The upper RCPI or RSSI threshold value.
        uint8_t    RollingAverageCount;              ///<Number of samples to use in a rolling average valid values 1 to 16.
} WsmHiMibRcpiRssiThreshold_t;

typedef struct __attribute__((__packed__)) WsmHiMibBlockAckPolicy_s {
        uint8_t    BlockAckTxTidPolicy;              /*When enabled, the WLAN device firmware can attempt to establish a block ACK agreement for that TID in the transmit direction.            Bits 7 to 0 correspond to TIDs 7 to 0, respectively. Bit value = 0 - Block ACK disabled ; = 1 - Block ACK enabled*/
        uint8_t    Reserved1;                        ///< reserved for future use, set to 0
        uint8_t    BlockAckRxTidPolicy;              /*When enabled, the WLAN device firmware will, where possible, accept requests to establish a block ACK agreement for that TID in the receive direction.            Bits 7 to 0 correspond to TIDs 7 to 0, respectively. Bit value = 0 - Block ACK requests disable ; = 1 - Block ACK requests accepted subject to availability.*/
        uint8_t    Reserved2;                        ///< reserved for future use, set to 0
} WsmHiMibBlockAckPolicy_t;

typedef struct __attribute__((__packed__)) WsmHiMibOverrideIntRate_s {
        uint8_t    InternalTxRate;                   /*Value = 0xFF (default). The device uses the lowest basic rate.             If NonErpProtection (see Section 4.9) is enabled, then the device will instead use the lowest mandatory rate of 1 Mbit/s (long preamble).             Value = 0 to 21. This value will override the default value of the device as specified above. (See Section 2.8.)*/
        uint8_t    NonErpInternalTxRate;             /*If the InternalTxRate field is not set to 0xFF, this field specifies the higher internal Tx rate when non-ERP-protection (see Section 4.9) is applied.            The rate adaptation mechanism described above will also be applied.*/
        uint8_t    Reserved[2];   /*Reserved 0*/
} WsmHiMibOverrideIntRate_t;


typedef enum WsmMpduStartSpacing_e {
        WSM_MPDU_START_SPACING_NO_RESTRIC          = 0x0,         /*No restriction*/
        WSM_MPDU_START_SPACING_QUARTER             = 0x1,         /*1/4 us*/
        WSM_MPDU_START_SPACING_HALF                = 0x2,         /*1/2 us*/
        WSM_MPDU_START_SPACING_ONE                 = 0x3,         /*1 us*/
        WSM_MPDU_START_SPACING_TWO                 = 0x4,         /*2 us*/
        WSM_MPDU_START_SPACING_FOUR                = 0x5,         /*4 us*/
        WSM_MPDU_START_SPACING_EIGHT               = 0x6,         /*8 us*/
        WSM_MPDU_START_SPACING_SIXTEEN             = 0x7          /*16 us*/
} WsmMpduStartSpacing;

typedef struct __attribute__((__packed__)) WsmHiMibSetAssociationMode_s {
        uint8_t    PreambtypeUse : 1;                /*Bit 0 = 1 use PreambleType*/
        uint8_t    Mode : 1;                         /*Bit 1 = 1 use MixedOrGreenfieldMode*/
        uint8_t    Rateset : 1;                      /*Bit 2 = 1 use BasicRateSet*/
        uint8_t    Spacing : 1;                      /*Bit 3 = 1 use MPDU start spacing*/
        uint8_t    Snoop : 1;                        /*Bit 4 = 1 snoop (re)association frames for AID and U-APSD information*/
        uint8_t    Reserved : 3;                     /*Reserved, set to 0*/
        uint8_t    PreambleType;                     ///<Specifies the PLCP preamble type used. See enum : WsmPreamble
        uint8_t    MixedOrGreenfieldType;            /*Specifies the 11n mode to be used by template frames (where applicable). Values are defined as follows: 0 - Mixed mode ; 1 - Greenfield mode*/
        uint8_t    MpduStartSpacing;                 /*Defined according to IEEE 802.11-2012 standard Table 8-125. The minimum MPDU start spacing subfield of A-MPDU parameters is as follows : type: WsmMpduStartSpacing*/
        uint32_t   BasicRateSet;                     /*Contains the BasicRateSet to be used.*/
} WsmHiMibSetAssociationMode_t;

typedef struct __attribute__((__packed__)) WsmHiMibSetUapsdInformation_s {
        uint8_t    TrigBckgrnd : 1;                  /*Bit 0 = 1 Trigger enable for background AC*/
        uint8_t    TrigBe : 1;                       /*Bit 1 = 1 Trigger enable for best effort AC*/
        uint8_t    TrigVideo : 1;                    /*Bit 2 = 1 Trigger enable for video AC*/
        uint8_t    TrigVoice : 1;                    /*Bit 3 = 1 Trigger enable for voice AC*/
        uint8_t    PseudoUapsd : 1;                  /*Bit 4 = 0 - Disable pseudo U-APSD operation; = 1 - Enable pseudo U-APSD operation*/
        uint8_t    NotAppendPspoll : 1;              /*Bit 5 = 1 - Do not append PS-Poll to a host queued data frame in the pseudo U-APSD operation.*/
        uint8_t    Reserved : 2;                     /*Reserved, set to 0.*/
        uint8_t    DelivBckgrnd : 1;                 /*Bit 8 = 1 Delivery enable for background AC*/
        uint8_t    DelivBe : 1;                      /*Bit 9 = 1 Delivery enable for best effort AC*/
        uint8_t    DelivVideo : 1;                   /*Bit 10 = 1 Delivery enable for video AC*/
        uint8_t    DelivVoice : 1;                   /*Bit 11 = 1 Delivery enable for voice AC*/
        uint8_t    Reserved2 : 4;                    /*Reserved2, set to 0*/
        uint16_t   MinAutoTriggerInterval;           /*The minimum auto-trigger interval in milliseconds. If the interval is specified as 0, then the auto-trigger feature is disabled. */
        uint16_t   MaxAutoTriggerInterval;           /*The maximum auto-trigger interval in milliseconds.*/
        uint16_t   AutoTriggerStep;                  /*The stepping in milliseconds to adjust the auto-trigger interval from minimum to maximum or from maximum to minimum.*/
} WsmHiMibSetUapsdInformation_t;


#define WSM_API_RESERVED2_SIZE      3
typedef struct __attribute__((__packed__)) WsmHiMibTxRateRetryPolicy_s {
        uint8_t    PolicyIndex;                      /*The rate retry policy index of this policy. Valid values are 0 to 7.*/
        uint8_t    ShortRetryCount;                  /*ShortRetryCount to be used with this policy*/
        uint8_t    LongRetryCount;                   /*LongRetryCount to be used with this policy*/
        uint8_t    IndexUse : 2;
        uint8_t    Terminate : 1;                    /*Bit 02 - 0 : Do not terminate retries when the Tx rate retry policy finishes.            1: Terminate retries when the Tx rate retry policy finishes.*/
        uint8_t    CountInit : 1;                    /*Bit 03 - 0: Do not count initial frame transmission as part of the rate retry counting.            1:  Count initial frame transmission as part of the rate retry counting but not as a retry attempt.*/
        uint8_t    Reserved : 4;                     ///< reserved for future use, set to 0
        uint8_t    RateRecoveryCount;                /*The number of successful first time transmissions before the device will attempt to move to a higher data rate within TxRateRetryPolicy.            Only valid for policies with PolicyFlags  bits 01 to 00 = 10b*/
        uint8_t    Reserved2[WSM_API_RESERVED2_SIZE];   ///< reserved for future use, set to 0
        uint32_t   RateCountIndices0700;             /*Counts for rate index 7 to 0*/
        uint32_t   RateCountIndices1508;             /*Counts for rate index 15 to 8*/
        uint32_t   RateCountIndices2316;             /*Counts for rate index 23 to 16*/
} WsmHiMibTxRateRetryPolicy_t;

#define WSM_MIB_NUM_TX_RATE_RETRY_POLICIES	16
typedef struct __attribute__((__packed__)) WsmHiMibSetTxRateRetryPolicy_s {
        uint8_t    NumTxRatePolicies;                  /*The number of transmit rate policies being sent in this message.*/
        uint8_t    Reserved[3];             ///< reserved for future use, set to 0
        WsmHiMibTxRateRetryPolicy_t TxRateRetryPolicy[0];     /*The number of transmit rate policies being sent in this message.*/
} WsmHiMibSetTxRateRetryPolicy_t;


typedef struct __attribute__((__packed__)) WsmHiMibKeepAlivePeriod_s {
        uint16_t   KeepAlivePeriod;                  /*The period in seconds to send keep-alive frames to the AP if the device is idle.            The default keep-alive period is 150 seconds. Set this field to zero to disable the keep-alive feature.            The keep-alive frames may be synchronized to beacon receiving depending on the mode that the device is operating.*/
        uint8_t    Reserved[2];                  ///< reserved for future use, set to 0
} WsmHiMibKeepAlivePeriod_t;

typedef struct __attribute__((__packed__)) WsmHiMibArpKeepAlivePeriod_s {
        uint16_t   ArpKeepAlivePeriod;               /*In seconds. 0 - no ARP keep alive*/
        uint8_t    EncrType;                         /* type: WsmKeyType*/
        uint8_t    Reserved;                         /*To ensure consistent byte padding.*/
        uint8_t    SenderIpv4Address[WSM_API_IPV4_ADDRESS_SIZE];   /*IP address of sender 0*/
        uint8_t    TargetIpv4Address[WSM_API_IPV4_ADDRESS_SIZE];   /*IP address of target 0*/
} WsmHiMibArpKeepAlivePeriod_t;

typedef struct __attribute__((__packed__)) WsmHiMibInactivityTimer_s {
        uint8_t    MinActiveTime;                    /*number of seconds of inactivity allowed until TIM polling is started*/
        uint8_t    MaxActiveTime;                    /*number of seconds until WSM_EVENT_IND_INACTIVITY event if the AP STA does not react to TIM polling*/
        uint16_t   Reserved;                         ///< reserved for future use, set to 0
} WsmHiMibInactivityTimer_t;

/**
 * @}
 */
/* end of WSM_Read_write */



/**
 * @}
 * end of MIB
 */
/**
 * @}
 * end of SPLIT_MAC_API
 */
#endif /* _WSM_MIB_API_H_ */
