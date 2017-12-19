/*
 * Copyright (c) 2017, Silicon Laboratories, Inc.
 *
 * based on:
 * Copyright (c) 2010, ST-Ericsson
 * Author: Dmitry Tarnyagin <dmitry.tarnyagin@lockless.no>
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
 

#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/firmware.h>

#include "wfx.h"
#include "fwio.h"
#include "hwio.h"
#include "hwbus.h"
#include "bh.h"


/* Download Fifo size */
#define SB_DOWNLOAD_FIFO_SIZE      (32*1024)

/* Download Block size */
#define SB_DOWNLOAD_BLOCK_SIZE     (1024)

/*--------------------------------------------------------------------------*
 * Constants - WF200 specific                                               *
 *--------------------------------------------------------------------------*/
// Download Control Area Base address
#define WF200_DCA_BASE_ADDRESS           0x0900C000
#define WF200_DOWNLOAD_FIFO_BASE_ADDRESS 0x09004000

// SecureBoot label 
#define WF200_SB_LABEL           0x0900C084

// PTE Info
#define WF200_PTE_INFO           0x0900C0C0

// Error report addresses
#define WF200_MSG_ID             0x0900C080
#define WF200_ERROR_ID           0x0900C0D0


///@{
/// HOST Upload State machine
#define    HOST_READY            0x87654321
#define    HOST_INFO_READ        0xA753BD99
#define    HOST_UPLOAD_PENDING   0xABCDDCBA
#define    HOST_UPLOAD_COMPLETE  0xD4C64A99
#define    HOST_OK_TO_JUMP       0x174FC882
///@}

///@{
/// NCP Upload State machine
#define    NCP_READY            0x87654321
#define    NCP_INFO_READY       0xBD53EF99
#define    NCP_DOWNLOAD_PENDING   0xABCDDCBA
#define    NCP_AUTH_OK            0xD4C64A99
#define    NCP_PUB_KEY_RDY        0x7AB41D19
///@}

//! Encrypted Firmware hash, size in bytes
#define FW_HASH_SIZE           (64/8)

//! Firmware version, size in bytes
#define FW_VERSION_SIZE           (32/8)

//! FW signature size
#define FW_SIGNATURE_SIZE (512/8)

//! Bootloader label max size
#define BOOTLOADER_LABEL_MAX_SIZE      60

//! PTE INFO size in bytes (14), rounded to the upper dword boundary = 16
#define PTE_INFO_SIZE 16

//! KeySet index in PTE info
#define KEYSET_IDX 13

// Timeout values (in millesonds)
#define INFO_READY_TIMEOUT              50
#define READY_TIMEOUT                   50
#define AUTH_TIMEOUT                    50
#define FIFO_READY_TIMEOUT              50

/**
 * Download Control Area structure
 */
typedef struct sb_download_cntl_s
{
    uint32_t    ImageSize;                            /*! size of whole firmware file (including Cheksum), host init */
    uint32_t    Put;                                  /*! No. of bytes put into the download, init & updated by host */
    uint32_t    Get;                                  /*! No. of bytes read from the download, host init, device updates */
    uint32_t    HostStatus;                           /*! Status of the Host (NOT_RDY, RDY, UPLOAD_PENDING, UPLOAD_COMPLETE) 2*/
    uint32_t    NcpStatus;                            /*! Status of the NCP  (NOT_RDY, RDY, DOWNLOAD_PENDING, DOWNLOAD_COMPLETE, FAILURE) 6*/
    uint8_t     Signature[FW_SIGNATURE_SIZE];         /*! signature of the firmware*/
    uint8_t     fw_hash[FW_HASH_SIZE];                /*! Encrypted Firmware hash , used in SecureBoot*/
    uint8_t     fw_ver[FW_VERSION_SIZE];              /*! Encrypted Firmware version , used in SecureBoot*/
} sb_download_cntl_t;


/* Local macros */
#define APB_WRITE(reg, val) \
    ret = wfx_sram_write_32(priv, (reg), (val)); \
    if (ret < 0) \
        goto error;
#define APB_READ(reg, val) \
    ret = wfx_sram_read_32(priv, (reg), &(val)); \
    if (ret < 0) \
        goto error;
#define REG_WRITE(reg, val) \
    ret = wfx_reg_write_32(priv, (reg), (val)); \
    if (ret < 0) \
        goto error;
#define REG_READ(reg, val) \
    ret = wfx_reg_read_32(priv, (reg), &(val)); \
    if (ret < 0) \
        goto error;
#define GET_ADDR(expr) (uint32_t)(&(expr))


/*--------------------------------------------------------------------------*
 * Main function
 *--------------------------------------------------------------------------*/

/**
 * @brief Firmware loading using ROM Secure Boot
 *
 * @param priv
 * @param firmware  firmware file data pointer
 * @param fw_length firmware lenght in bytes
 *
 * @return 0 if success, else negative error code 
 */
int wfx_secure_load_firmware_file(struct wfx_common *priv,
            uint8_t *firmware, uint32_t fw_length)
{
    int ret = -EIO;
    u32 val32 = 0;
    HiCfgReg_t Config_reg;
    u32 put = 0, get = 0;
    u8 *buf = NULL;              // 'Allocated' pointer - used for kmalloc/kfree operations
    uint8_t* firmware_cur_block = NULL; // Pointer on current 1k byte block to be uploaded
    uint32_t  firmware_upload_count = 0; // Number of bytes already uploaded
    sb_download_cntl_t* const dca = (sb_download_cntl_t*)(WF200_DCA_BASE_ADDRESS);
    uint32_t                  fifo = (uint32_t)(WF200_DOWNLOAD_FIFO_BASE_ADDRESS);
    const uint8_t fw_version[FW_VERSION_SIZE] = {0x01, 0x00, 0x00, 0x00};
    uint32_t firmware_blocks_size = fw_length - FW_SIGNATURE_SIZE - FW_HASH_SIZE;
    unsigned long stats_wait_states = 0;
    unsigned long stats_wait_states_1 = 0;
    unsigned long stats_wait_states_2 = 0;
    unsigned long stats_wait_states_3 = 0;
    u32 fw_sign_ofs = 0, fw_hash_ofs = 0, fw_blocks_ofs = 0;
    u8 keyset = 0x00;

    /* Init Timer */
    setup_timer(&fwio_timer, timer_expiration_cb, 0);

    /* HOST status = NOT READY */
    APB_WRITE(GET_ADDR(dca->HostStatus), HOST_READY);

    /* Release CPU from RESET */
    ret = config_reg_read(priv, &Config_reg);
    if (ret) goto error;
    Config_reg.hif.CpuRst = CPU_RUN;
    ret = config_reg_write(priv, Config_reg);
    if (ret) goto error;

    /* Enable Clock */
    Config_reg.hif.CpuClkDis = CPU_CLK_ENABLE;
    ret = config_reg_write(priv, Config_reg);
    if (ret) goto error;

    /* Wait for 'INFO-READY' state from NCP */
    start_timer(INFO_READY_TIMEOUT);
    do {
        APB_READ(GET_ADDR(dca->NcpStatus), val32);
        if(!timer_pending(&fwio_timer)) {
            pr_err("Timeout detected while waiting for NCP 'INFO_RDY' - %x\n",val32);
            ret = -ETIMEDOUT;
            goto error;
        }
        stats_wait_states++;
    } while(val32 != NCP_INFO_READY);
    stop_timer();

    /*
     *  Dump Secure Boot label
     */

    buf = kmalloc(BOOTLOADER_LABEL_MAX_SIZE, GFP_KERNEL | GFP_DMA);
    if (!buf) {
        printk(KERN_ERR "In: %s:%i can't allocate secureboot label buffer.\n", __func__, __LINE__);
        ret = -ENOMEM;
        goto error;
    }
    buf[BOOTLOADER_LABEL_MAX_SIZE-1] = 0;   // Force 'null-terminating' character
    // Read label from Shared RAM
    wfx_sram_read(priv, WF200_SB_LABEL, buf, BOOTLOADER_LABEL_MAX_SIZE); 

    kfree(buf);
    buf = NULL; // To avoid unnecessary 'kfree' in case of error

    /*
     * Dump Key Set ID
    */
    buf = kmalloc(PTE_INFO_SIZE, GFP_KERNEL | GFP_DMA);
    if (!buf) {
        printk(KERN_ERR "In: %s:%i can't allocate pte info buffer.\n", __func__, __LINE__);
        ret = -ENOMEM;
        goto error;
    }
    // Read info from Shared RAM
    wfx_sram_read(priv, WF200_PTE_INFO, buf, PTE_INFO_SIZE);
    keyset = buf[KEYSET_IDX];

    kfree(buf);
    buf = NULL; // To avoid unnecessary 'kfree' in case of error

    /* HOST status = INFO READ */
    APB_WRITE(GET_ADDR(dca->HostStatus), HOST_INFO_READ);

    /* Wait for 'READY' state from NCP */
    start_timer(READY_TIMEOUT);
    do {
        APB_READ(GET_ADDR(dca->NcpStatus), val32);
        if(!timer_pending(&fwio_timer)) {
            pr_err("Timeout detected while waiting for NCP 'RDY' - %x\n",val32);
            ret = -ETIMEDOUT;
            goto error;
        }
        stats_wait_states_1++;
    } while(val32 != NCP_READY);
    stop_timer();

    /*
     * SB misc initialization - DO NOT REMOVE
     *
     * It should always be completed at this step before signature copy
     */
    APB_WRITE(fifo, 0xFFFFFFFF);


    // Compute Firmware file information offsets, depending on key type
    if(keyset == 0xA0)
    {
        fw_sign_ofs = 8;
        firmware_blocks_size -= 8;

        // Check that encrypted file starts with KeySet indication string
        if(memcmp(firmware, "KEYSETA0", 8) != 0) {
            pr_err("Encrypted FW file is invalid (Wrong Key Set)\n");
            goto error;
        }
    } else {
        fw_sign_ofs = 0;
    }
    fw_hash_ofs = fw_sign_ofs + FW_SIGNATURE_SIZE;
    fw_blocks_ofs = fw_hash_ofs + FW_HASH_SIZE;

    /*
     * Upload Firmware Signature
     */
    ret = wfx_sram_write(priv, GET_ADDR(dca->Signature), &(firmware[fw_sign_ofs]), FW_SIGNATURE_SIZE);
    if (ret < 0) {
        pr_err("Can't write firmware signature !\n");
        goto error;
    }

    /*
     * Upload Firmware Hash
     */
    ret = wfx_sram_write(priv, GET_ADDR(dca->fw_hash), &(firmware[fw_hash_ofs]), FW_HASH_SIZE);
    if (ret < 0) {
        pr_err("Can't write firmware hash !\n");
        goto error;
    }

    /*
     * Upload Firmware Version (fixed to '0x01000000' for now)
     */
    ret = wfx_sram_write(priv, GET_ADDR(dca->fw_ver), fw_version, FW_VERSION_SIZE);
    if (ret < 0) {
        pr_err("Can't write firmware hash !\n");
        goto error;
    }

    /*
     * Give the firmware size
     */
    APB_WRITE(GET_ADDR(dca->ImageSize), firmware_blocks_size);


    /* HOST status = UPLOAD PENDING */
    APB_WRITE(GET_ADDR(dca->HostStatus), HOST_UPLOAD_PENDING);


    /* Initialize block pointer and counter */
    firmware_cur_block    = &firmware[fw_blocks_ofs];
    firmware_upload_count = 0;



    /*
     *Firmware Block Upload loop
     */

    for(firmware_upload_count = 0; firmware_upload_count < firmware_blocks_size; firmware_upload_count += SB_DOWNLOAD_BLOCK_SIZE)
    {
        /* Wait until at least 1k is available  */
        start_timer(FIFO_READY_TIMEOUT);
        do {
            APB_READ(GET_ADDR(dca->Get), get);
            if(!timer_pending(&fwio_timer)) {
                pr_err("Timeout detected while waiting for room in download fifo' - %x\n",get);
                ret = -ETIMEDOUT;
                goto error;
            }
            stats_wait_states_2++;
        } while((put - get) > (SB_DOWNLOAD_FIFO_SIZE - SB_DOWNLOAD_BLOCK_SIZE));
        stop_timer();

        /* Check NCP status is in [READY or DOWNLOAD_PENDING] */
        APB_READ(GET_ADDR(dca->NcpStatus), val32);
        if(!((val32 == NCP_READY) || (val32 == NCP_DOWNLOAD_PENDING) ))
        {
            printk(KERN_ERR "In: %s:%i Unexpected NCP status = %x.\n", __func__, __LINE__, val32);
            ret = -ETIMEDOUT;
            goto error;
        }

        /* Send the 1 kbyte block to Shared Ram fifo */
        ret = wfx_sram_write(priv,
            fifo + (put & (SB_DOWNLOAD_FIFO_SIZE - 1)),
            firmware_cur_block, SB_DOWNLOAD_BLOCK_SIZE);
        if (ret < 0) {
            pr_err("Can't write firmware block @ %d!\n",
                   put & (SB_DOWNLOAD_FIFO_SIZE - 1));
            goto error;
        }

        /* Update the put register */
        put += SB_DOWNLOAD_BLOCK_SIZE;
        APB_WRITE(GET_ADDR(dca->Put), put);

        /* Update block pointer */
        firmware_cur_block += SB_DOWNLOAD_BLOCK_SIZE;

    } /* End of firmware download loop */

    /* HOST status = UPLOAD COMPLETE */
    APB_WRITE(GET_ADDR(dca->HostStatus), HOST_UPLOAD_COMPLETE);


    /* Wait for 'AUTH' state from NCP */
    start_timer(AUTH_TIMEOUT);
    do {
        APB_READ(GET_ADDR(dca->NcpStatus), val32);
        if(!timer_pending(&fwio_timer)) {
            pr_err("Timeout detected while waiting for NCP 'AUTH' - %x\n",val32);
            ret = -ETIMEDOUT;
            goto error;
        }
        stats_wait_states_3++;
    } while(!((val32 == NCP_AUTH_OK) || (val32 == NCP_PUB_KEY_RDY)));
    stop_timer();

    /* HOST status = OK TO JUMP */
    APB_WRITE(GET_ADDR(dca->HostStatus), HOST_OK_TO_JUMP);

    return 0;

error:
    pr_err("Error detected during secure firmware upload ...\n");

    kfree(buf);

    /*
     * Dump Error information
     */
    pr_info("[SecureBoot] state : %x\n",val32);
    wfx_sram_read_32(priv, WF200_MSG_ID, &val32);
    pr_info("[SecureBoot] reported msg id = %x\n",val32);
    wfx_sram_read_32(priv, WF200_ERROR_ID, &val32);
    switch (val32) {
		case 5:
			pr_info("[SecureBoot] reported error id (%x) = Invalid Section Type (may be caused by a wrong encryption)\n",val32);
			break;
		default:
			pr_info("[SecureBoot] reported error id = %x\n",val32);
			break;
	}


    return ret;
}

#undef APB_WRITE
#undef APB_READ
#undef REG_WRITE
#undef REG_READ

