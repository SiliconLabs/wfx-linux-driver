/*
 * Copyright (c) 2017, Silicon Laboratories, Inc.
 *
 * Based on:
 * Copyright (c) 2010, ST-Ericsson
 * Author: Dmitry Tarnyagin <dmitry.tarnyagin@lockless.no>
 * ST-Ericsson UMAC CW1200 driver, which is
 * Copyright (c) 2010, ST-Ericsson
 * Author: Ajitpal Singh <ajitpal.singh@lockless.no>
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


/*========================================================================*/
/*                 Standard Linux Headers                                 */
/*========================================================================*/
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/firmware.h>

/*========================================================================*/
/*                 Local Header files                                     */
/*========================================================================*/
#include "wfx.h"
#include "fwio.h"
#include "hwio.h"
#include "hwbus.h"
#include "bh.h"

/*========================================================================*/
/*                  PRIVATE  Constants/Macros/Types/Variables             */
/*========================================================================*/

/* Wakeup timeout value (in milliseconds) */
#define WAKEUP_TIMEOUT 200


/*========================================================================*/
/*                  Structures definitions                                */
/*========================================================================*/
/* A timer object*/
struct timer_list fwio_timer;

/*========================================================================*/
/*                       Functions                                        */
/*========================================================================*/
int wfx_secure_load_firmware_file(struct wfx_common *priv, uint8_t *firmware, uint32_t fw_length);


/**
 * @brief Dummy Expiration callback - do nothing
 */
void timer_expiration_cb(unsigned long data) {
    pr_err("Timeout detected %lx\n", data);
}

/**
 * @brief Start Timer 
 *
 * @param timeout timeout value (milliseconds)
 */
void start_timer(uint32_t timeout)
{
    fwio_timer.expires = jiffies + msecs_to_jiffies(timeout);
    add_timer(&fwio_timer);
}

/**
 * @brief Stop Timer
 */
void stop_timer(void)
{
    del_timer_sync( &fwio_timer );
}


/*========================================================================*/
/*                  Internally Static Functions                           */
/*========================================================================*/



static int wfx_load_firmware_core(struct wfx_common *priv)
{
    int ret;
    const char *fw_path;
    const struct firmware *firmware = NULL;
    const struct firmware *bootloader = NULL;

    switch (priv->hw_revision) {
    case WF200_HW_REV:
        fw_path =  FIRMWARE_WF200_SEC;

        if (!priv->pds_path)
            priv->pds_path = PDS_FILE_WF200;
        break;
    default:
        pr_err("Invalid silicon revision %d.\n", priv->hw_revision);
        return -EINVAL;
    }

    /* Load a firmware file */
    ret = request_firmware(&firmware, fw_path, priv->pdev);
    if (ret) {
        pr_err("Can't load firmware file %s.\n", fw_path);
        goto error;
    }
    if (priv->hw_revision==WF200_HW_REV){

        ret = wfx_secure_load_firmware_file(priv,(uint8_t *)firmware->data,firmware->size);
        goto end;
    }

error:
end:
    if (firmware)
        release_firmware(firmware);
    if (bootloader)
        release_firmware(bootloader);
    return ret;
}

#undef APB_WRITE
#undef APB_READ
#undef REG_WRITE
#undef REG_READ

int wfx_load_firmware(struct wfx_common *priv)
{
    int ret;
    HiCtrlReg_t Control_reg;
    HiCfgReg_t Config_reg;

    /* Init before HW detection */
    priv->hw_revision = -1; /*No HW detected yet*/

    /* define default Config_register */
    /* this setting matches the chip reset values */
    /* It could be interesting to start with a write */
    /* to change parameters affecting the 1st read */
    Config_reg.U32ConfigReg=0;
    Config_reg.hif.AccessMode = DIRECT_MODE;
    Config_reg.hif.CpuClkDis = CPU_CLK_DISABLE;
    Config_reg.hif.CpuRst = CPU_RESET;
    Config_reg.hif.ClkPosedge = DOUT_NEG_EDGE;

    /* we must start with a write of the clock polarity.
     * Read can be compromised if clock is too fast. */
    if (priv->hif_clkedge) {
        /* Enable posedge on Dout  intended to be used  in 50Mhz SDIO */
        Config_reg.hif.ClkPosedge = DOUT_POS_EDGE;
    }

    ret = config_reg_write(priv, Config_reg);
    if (ret < 0) {
        pr_err("Can't write config register.\n");
        ret = -EIO;
        goto out;
    }

    /* Read back HIF config register */
    /* Note that it is normal it may be different from the written value */
    ret = config_reg_read(priv, &Config_reg);
    if (ret < 0) {
        pr_err("ERROR READING CONFIG number error=%i , value = %x \n", ret,
               Config_reg.U32ConfigReg);
        ret = -EIO;
        goto out;
    }

    if (Config_reg.U32ConfigReg == 0 || Config_reg.U32ConfigReg == 0xffffffff) {
        pr_err("Bad config register value (0x%08x)\n", Config_reg.U32ConfigReg);
        ret = -EIO;
        goto out;
    }


    priv->hw_type = Config_reg.hif.DeviceId.hw_type;
    priv->hw_revision = Config_reg.hif.DeviceId.hw_major;

    switch (priv->hw_revision) {
    case WF200_HW_REV:
        pr_info("WF200 silicon detected.\n");
        break;
    default:
        pr_err("Unsupported silicon major revision %d.\n",
               priv->hw_revision);
        ret = -ENOTSUPP;
        goto out;
    }

    switch (priv->hw_revision) {
    case WF200_HW_REV:

        /* XO tuning prior boot */
        ret = wfx_reg_write_32(priv, WF200_SET_GEN_R_W_REG_ID, 0x07138775);
        ret = wfx_reg_write_32(priv, WF200_SET_GEN_R_W_REG_ID, 0x08330013);
        ret = wfx_reg_write_32(priv, WF200_SET_GEN_R_W_REG_ID, 0x098c8c14);
        ret = wfx_reg_write_32(priv, WF200_SET_GEN_R_W_REG_ID, 0x0B42AC44);
        break;
    }

    /* Set wakeup bit in device
     * (no need to read it first because only the wakeup bit can be written) */
    Control_reg.U16CtrlReg = 0;
    Control_reg.b.WlanWup = WLAN_WAKEUP;
    ret = control_reg_write(priv, Control_reg);
    if (ret < 0) {
        pr_err("set_wakeup: can't write control register.\n");
        goto out;
    }

    /* Wait for wakeup, Init Timer */
    setup_timer(&fwio_timer, timer_expiration_cb, 0);

    start_timer(WAKEUP_TIMEOUT);
    do {
        ret = control_reg_read(priv, &Control_reg);
        if (ret < 0) {
            pr_err("wait_for_wakeup: can't read control register.\n");
            goto out;
        }
        if(!timer_pending(&fwio_timer)) {
            pr_err("Timeout detected while device wakeup (waiting for %d ms)\n",WAKEUP_TIMEOUT);
            goto out;
        }
    } while(!(Control_reg.b.WlanRdy));
    pr_info("WLAN device is ready.\n");
    stop_timer();


    /* Checking for direct access mode */
    ret = config_reg_read(priv, &Config_reg);
    if (ret < 0) {
        pr_err("Can't read config register.\n");
        goto out;
    }
    if ( Config_reg.hif.AccessMode == QUEUE_MODE ) {
        pr_err("Device is already in QUEUE mode!\n");
            ret = -EINVAL;
            goto out;
    }

    /* Load firmware */
    ret = wfx_load_firmware_core(priv);

    if (ret < 0) {
        pr_err("Firmware load error.\n");
        goto out;
    }

    /* Enable interrupt signaling */
    priv->hwbus_ops->lock(priv->hwbus_priv);
    ret = __wfx_irq_enable(priv, 1);
    priv->hwbus_ops->unlock(priv->hwbus_priv);
    if (ret < 0) {
        goto unsubscribe;
    }

    /* Configure device for MESSAGE MODE */
    ret = config_reg_read(priv, &Config_reg);
    if (ret < 0) {
        pr_err("Can't read config register.\n");
        goto unsubscribe;
    }
    Config_reg.hif.AccessMode = QUEUE_MODE;
    ret = config_reg_write(priv, Config_reg);
    if (ret < 0) {
        pr_err("Can't write config register.\n");
        goto unsubscribe;
    }

    mdelay(10);

out:
    return ret;

unsubscribe:
    /* Disable interrupt signaling */
    priv->hwbus_ops->lock(priv->hwbus_priv);
    ret = __wfx_irq_enable(priv, 0);
    priv->hwbus_ops->unlock(priv->hwbus_priv);
    return ret;
}
