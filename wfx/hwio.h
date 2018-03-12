/*
 * Copyright (c) 2017, Silicon Laboratories, Inc.
 *
 * Based on:
 * Copyright (c) 2010, ST-Ericsson
 * Author: Dmitry Tarnyagin <dmitry.tarnyagin@lockless.no>
 * ST-Ericsson UMAC CW1200 driver which is
 * Copyright (c) 2010, ST-Ericsson
 * Author: Ajitpal Singh <ajitpal.singh@stericsson.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef HWIO_H_INCLUDED
#define HWIO_H_INCLUDED

/*========================================================================*/
/*                  PRIVATE  Constants/Macros/Types/Variables             */
/*========================================================================*/
#define SYS_BASE_ADDR_SILICON        (0)
#define PAC_BASE_ADDRESS_SILICON     (SYS_BASE_ADDR_SILICON + 0x09000000)
#define PAC_SHARED_MEMORY_SILICON    (PAC_BASE_ADDRESS_SILICON)

#define WF200_SRAM(addr)             (PAC_SHARED_MEMORY_SILICON + (addr))


/*========================================================================*/
/*              HARDWARE HIF SPI ADDRESS REGISTER DEFINITION              */
/*                      for SDIO address must be *4                       */
/*========================================================================*/
#define WF200_ADDR_ID_BASE         (0x0000)
/* 32 bits */
#define WF200_CONFIG_REG_ID        (0x0000)
/* 16 bits */
#define WF200_CONTROL_REG_ID       (0x0001)
/* 16/32 bits, Queue mode message W/R */
#define WF200_IN_OUT_QUEUE_REG_ID  (0x0002)
/* 32 bits, AHB bus direct R/W */
#define WF200_AHB_DPORT_REG_ID     (0x0003)
/* 16 bits SRAM address offset, 32 bits absolute AHB address*/
#define WF200_BASE_ADDR_REG_ID     (0x0004)
/* 32 bits, SRAM direct R/W */
#define WF200_SRAM_DPORT_REG_ID    (0x0005)
/* 32 bits, indirect general purpose registers access*/
#define WF200_SET_GEN_R_W_REG_ID   (0x0006)
/* 16/32 bits, SPI only, Q mode read, no length */
#define WF200_FRAME_OUT_REG_ID     (0x0007)

#define WF200_ADDR_ID_MAX          (WF200_FRAME_OUT_REG_ID)


/*========================================================================*/
/*                  HARDWARE HIF CONTROL REGISTER DEFINITION               */
/*========================================================================*/
typedef enum {WLAN_NOT_READY=0,
          WLAN_READY=1
} WlanRdy_t;

typedef enum {WLAN_WAKEDOWN=0,
          WLAN_WAKEUP=1
} WlanWup_t;


#define WF200_CTRL_WUP_BIT        (BIT(12))
#define WF200_CTRL_RDY_BIT        (BIT(13))

/* next available message length, bit 11 to 0 */
#define WF200_CTRL_NEXT_LEN_MASK    (0x0FFF)

/* Configuration register fields may have different meaning when in SPI or SDIO*/
typedef union HiCtrlReg_t_s
{
  u16 U16CtrlReg;
  struct __attribute__((__packed__))  {
    u8 next_lenght_7_0;      /*[11:0]  READ ONLY Use Mask WF200_CTRL_NEXT_LEN_MASK*/
    u8 next_lenght_11_8:4;   /* Next output queue item length */
    WlanWup_t WlanWup:1;     /*[12] Frame type information */
    WlanRdy_t WlanRdy:1;     /*[13]  READ ONLY Frame type information */
    u8 reserved:2;            /*[15:14] RESERVED */
  } b;
} HiCtrlReg_t;

//This is a sanity check of the struct packing as seen by the compiler
typedef char p__LINE__[ (sizeof(HiCtrlReg_t) == 2 ) ? 1 : -1];
//The previous line generates an error during compilation if the structure is not of the expected size.

/*========================================================================*/
/*                  HARDWARE HIF CONFIG REGISTER DEFINITION               */
/*========================================================================*/
typedef    enum {
        HW_SILICON= 0,
} hw_type_t;

typedef    enum {
        WF200_HW_REV = 1,
    } hw_major_revision_t;

typedef  struct __attribute__((__packed__)) DeviceId_s {
    hw_major_revision_t hw_major:3; /*[0:2] HW major id */
    u8 reserved:4;                  /*[3:6]*/
    hw_type_t hw_type:1;            /*[7] type of HW */
} DeviceId_t;
//This is a sanity check of the struct packing as seen by the compiler
typedef char p__LINE__[ (sizeof(DeviceId_t) == 1 ) ? 1 : -1];
//The previous line generates an error during compilation if the structure is not of the expected size.

typedef enum {
    SDIO_CRC_CHECK=0,   /* Normal CRC check on data */
    SDIO_NO_CRC_CHECK=1 /*Disable SDIO CRC check on data transfers
                         (CRC result assumed always correct). */
} SDIODisCRC_t;

typedef enum {
    DOUT_NEG_EDGE=0,
    DOUT_POS_EDGE=1
} ClkPosedge_t;

typedef enum {
    IRQS_DISABLED  =0, /* Both Irq's disabled */
    DATA_IRQ_ENABLED=1,/*Data Irq enabled */
    WLAN_RDY_ENABLED=2,/*Wlan_rd enabled */
    IRQS_ENABLED   =3, /*Both Irq's enabled */
} IrqEnable_t;

typedef enum {
    DAT1_IRQ_ENABLE=0, /* Interrupt on SDIO DAT1 */
    DAT1_IRQ_DISABLE=1
} SDIODat1Irq_t;


typedef enum {
    CPU_RUN=0,
    CPU_RESET=1
} CpuRst_t;

typedef enum {
    CHANNEL_NOT_BUSY=0,
    CHANNEL_BUSY=1
} PreFetch_t;

typedef enum {
    CPU_CLK_ENABLE=0,
    CPU_CLK_DISABLE=1
} CpuClkDis_t;

typedef enum {
    QUEUE_MODE=0, /* Queue mode for HIF messages */
    DIRECT_MODE=1 /* Direct mode for internal memory access */
} AccessMode_t;

typedef enum {
    MODE0_B1B0B3B2=0,   /*Mode0 (“00”) : 4 bytes are sent : B1,B0,B3,B2
                          SPI mode after chip reset */
    MODE1_B3B2B1B0=1,   /*Mode1 (“01”) : 4 bytes are sent : B3,B2,B1,B0.  */
    MODE2_B0B1B2B3=2    /*Mode2 (“10”) : 4 bytes are sent : B0,B1,B2,B3
                          SDIO mode after chip reset */
} WordMode_t;

typedef enum {
    ERR7_NO_ERROR=0,
    ERR7_HOST_CRC_MISS=1   /*Host misses CRC error */
} CfgErr7_t;

typedef enum {
    CHECK_CS_ENABLED=0,   /*SPI CS is checked */
    CHECK_CS_DISABLED=1   /*SPI CS is not checked */
} CfgCSSPI_t;

typedef enum {
    ERR6_NO_ERROR=0,
    ERR6_HOST_NO_IN_QUEUE=1   /*host tries to send data with no hif input queue entry
                  programmed */
} CfgErr6_t;

typedef enum {
    ERR5_NO_ERROR=0,
    ERR5_DATA_OUT_TOO_LARGE=1   /*host tries to send data larger than hif input buffer */
} CfgErr5_t;

typedef enum {
    ERR4_NO_ERROR=0,
    ERR4_BUFFER_OVERRUN=1   /*host tries to send data when hif buffers overrun */
} CfgErr4_t;

typedef enum {
    ERR3_NO_ERROR=0,
    ERR3_HOST_NO_OUT_QUEUE=1   /*host tries to read data with no hif output queue entry
                                 programmed */
} CfgErr3_t;

typedef enum {
    ERR2_NO_ERROR=0,
    ERR2_DATA_IN_TOO_LARGE=1   /*host tries to read data less than output message length */
} CfgErr2_t;

typedef enum {
    ERR1_NO_ERROR=0,
    ERR1_BUFFER_UNDERRUN=1   /*host tries to read data when hif buffers underrun*/
} CfgErr1_t;

typedef enum {
    ERR0_SDIO_NO_ERROR=0,
    ERR0_BUFFER_MISMATCH=1   /*Buffer number mismatch */
} CfgErr0SDIO_t;

typedef enum {
    ERR0_SPI_NO_ERROR=0,
    ERR0_CSN_FRAMING_ERROR=1   /*SPI CS ERROR */
} CfgErr0SPI_t;

typedef struct __attribute__((__packed__)) HiCfgRegSDIO_s
{
    CfgErr0SDIO_t CfgErr0 :1;     /*[0] READ ONLY Err0 */
    CfgErr1_t CfgErr1 :1;         /*[1] READ ONLY Err1 */
    CfgErr2_t CfgErr2 :1;         /*[2] READ ONLY Err2 */
    CfgErr3_t CfgErr3 :1;         /*[3] READ ONLY Err3 */
    CfgErr4_t CfgErr4 :1;         /*[4] READ ONLY Err4 */
    CfgErr5_t CfgErr5 :1;         /*[5] READ ONLY Err5 */
    CfgErr6_t CfgErr6 :1;         /*[6] READ ONLY Err6 */
    CfgErr7_t CfgErr7 :1;         /*[7] Err7 */
    WordMode_t WordMode :2;       /*[9:8] Word mode only effective in SPI*/
    AccessMode_t AccessMode :1;   /*[10] AccessMode */
    PreFetch_t PreFetchAHB :1;    /*[11] AHB channel busy */
    CpuClkDis_t CpuClkDis :1;     /*[12] CPU clock */
    PreFetch_t PreFetchSRAM :1;   /*[13] SRAM channel busy */
    CpuRst_t CpuRst :1;           /*[14] CPU reset */
    SDIODat1Irq_t SDIODat1Irq :1; /*[15] SDIO IRQ mode. Unused in SPI mode*/
    IrqEnable_t IrqEnable :2;     /*[17:16] Irq Enable */
    ClkPosedge_t ClkPosedge :1;   /*[18] Serial bus Data out clock edge */
    SDIODisCRC_t SDIODisCRC :1;   /*[19]*/
    u8 Reserved :4;               /*[23:20]*/
    DeviceId_t DeviceId;          /*[31:24] READ ONLY Device identification information*/
} HiCfgRegSDIO_t;

typedef struct __attribute__((__packed__))  HiCfgRegSPI_s
{
    CfgErr0SPI_t CfgErr0 :1;      /*[0] READ ONLY Err0 */
    CfgErr1_t CfgErr1 :1;         /*[1] READ ONLY Err1 */
    CfgErr2_t CfgErr2 :1;         /*[2] READ ONLY Err2 */
    CfgErr3_t CfgErr3 :1;         /*[3] READ ONLY Err3 */
    CfgErr4_t CfgErr4 :1;         /*[4] READ ONLY Err4 */
    CfgErr5_t CfgErr5 :1;         /*[5] READ ONLY Err5 */
    CfgErr6_t CfgErr6 :1;         /*[6] READ ONLY Err6 */
    CfgCSSPI_t CfCSSPI :1;        /*[7] SPI CS check */
    WordMode_t WordMode :2;       /*[9:8] Word mode only effective in SPI*/
    AccessMode_t AccessMode :1;   /*[10] AccessMode */
    PreFetch_t PreFetchAHB :1;    /*[11] AHB channel busy */
    CpuClkDis_t CpuClkDis :1;     /*[12] CPU clock */
    PreFetch_t PreFetchSRAM :1;   /*[13] SRAM channel busy */
    CpuRst_t CpuRst :1;           /*[14] CPU reset */
    u8 SDIOReserved1 :1;          /*[15]*/
    IrqEnable_t IrqEnable :2;     /*[17:16] Irq Enable */
    ClkPosedge_t ClkPosedge :1;   /*[18] Serial bus Data out clock edge */
    u8 SDIOReserved0 :1;          /*[19]*/
    u8 Reserved :4;               /*[23:20]*/
    DeviceId_t DeviceId;          /*[31:24] READ ONLY Device identification information*/
} HiCfgRegSPI_t;

/* Bus access prefetch bits */
#define WF200_CONF_AHB_PREFETCH_BIT    (BIT(11))
#define WF200_CONF_SRAM_PREFETCH_BIT   (BIT(13))

/* Configuration register fields may have different meaning when in SPI or SDIO*/
typedef union HiCfgReg_s
{
    u32 U32ConfigReg;
    HiCfgRegSDIO_t hif; /* default is SDIO */
    HiCfgRegSPI_t  spi;
} HiCfgReg_t;

//This is a sanity check of the struct packing as seen by the compiler
typedef char p__LINE__[ (sizeof(HiCfgReg_t) == 4 ) ? 1 : -1];
//The previous line generates an error during compilation if the structure is not of the expected size.


/*========================================================================*/
/*                  Structures definitions                                */
/*========================================================================*/
struct wfx_common;


/*========================================================================*/
/*                       Functions                                        */
/*========================================================================*/
/*
 * Read and write HIF messages
 */
int wfx_data_read(struct wfx_common *priv, void *buf, size_t buf_len);
int wfx_data_write(struct wfx_common *priv, const void *buf, size_t buf_len);

/*
 * read and write in SRAM and AHB bus for any number of bytes
 */
int wfx_sram_read(struct wfx_common *priv, u32 addr, void *buf, size_t buf_len);
int wfx_ahb_read(struct wfx_common *priv, u32 addr, void *buf, size_t buf_len);
int wfx_sram_write(struct wfx_common *priv, u32 addr, const void *buf, size_t buf_len);
int wfx_ahb_write(struct wfx_common *priv, u32 addr, const void *buf, size_t buf_len);

/*
 * read and write in SRAM and AHB bus for a 32bits data.
 * It includes the conversion from Little Endian to the CPU endianess
 */
int wfx_sram_read_32(struct wfx_common *priv, u32 addr, u32 *val);
int wfx_ahb_read_32(struct wfx_common *priv, u32 addr, u32 *val);
int wfx_sram_write_32(struct wfx_common *priv, u32 addr, u32 val);
int wfx_ahb_write_32(struct wfx_common *priv, u32 addr, u32 val);

/*
 * read and write registers for a 32bits or 16bits data.
 * It includes the conversion from Little Endian to the CPU endianess
 */
int wfx_reg_read_16(struct wfx_common *priv, u16 addr, u16 *val);
int wfx_reg_write_16(struct wfx_common *priv, u16 addr, u16 val);
int wfx_reg_read_32(struct wfx_common *priv, u16 addr, u32 *val);
int wfx_reg_write_32(struct wfx_common *priv, u16 addr, u32 val);

/*
 * read and write WF200_CONFIG registe
 * It includes the conversion from Little Endian to the CPU endianess
 */
int config_reg_read(struct wfx_common *priv, HiCfgReg_t *val);
int config_reg_write(struct wfx_common *priv, HiCfgReg_t val);

/*
 * read and write WF200_CONTROL register
 * It includes the conversion from Little Endian to the CPU endianess
 */
int control_reg_read(struct wfx_common *priv, HiCtrlReg_t *val);
int control_reg_write(struct wfx_common *priv, HiCtrlReg_t val);

#endif /* HWIO_H_INCLUDED */
