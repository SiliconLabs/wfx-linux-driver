/*
 * Copyright (c) 2017, Silicon Laboratories, Inc.
 *
 * based on:
 * Copyright (c) 2010, ST-Ericsson
 * Author: Dmitry Tarnyagin <dmitry.tarnyagin@lockless.no>
 *
 * Author: Dmitry Tarnyagin <dmitry.tarnyagin@lockless.no>
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
#include <linux/module.h>
#include <linux/gpio.h>
#include <linux/delay.h>
#include <linux/mmc/host.h>
#include <linux/mmc/sdio_func.h>
#include <linux/mmc/card.h>
#include <linux/mmc/sdio.h>
#include <net/mac80211.h>
#include <linux/notifier.h>
#include <linux/reboot.h>

/*========================================================================*/
/*                 Local Header files                                     */
/*========================================================================*/
#include "wfx.h"
#include "hwbus.h"
#include "hwio.h"
#include "wfx_version.h"
#include "debug.h"

/*========================================================================*/
/*                  wfx_wlan_sdio module information                      */
/*========================================================================*/
MODULE_DESCRIPTION("Silicon labs 802.11 Wireless LAN sdio driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("sdio:wfx_wlan_sdio");
MODULE_VERSION(WFX_LABEL);

/*========================================================================*/
/*                  wfx_wlan_sdio Bypass Parameters                       */
/*========================================================================*/

/*========================================================================*/
/*                  PRIVATE  Constants/Macros/Types/Variables             */
/*========================================================================*/
#define SDIO_BLOCK_SIZE (512)

/* SDIO ADDR DEFINITION */
#define SDIO_ADDR12BIT(buf_id, reg_id) \
	((((buf_id) & 0x1F) << 7) \
	 | ((((reg_id) << 2) & 0x1F) << 0))

#undef HW_RESET_WFX_AT_DRIVER_LOAD

#ifndef SDIO_VENDOR_ID_SILABS
#define SDIO_VENDOR_ID_SILABS        0x0000
#endif

#ifndef SDIO_DEVICE_ID_SILABS_WFX200
#define SDIO_DEVICE_ID_SILABS_WFX200    0x1000
#endif

/*========================================================================*/
/*                  Structures definitions                                */
/*========================================================================*/

struct wfx_platform_data_sdio {
	bool		no_nptb;        /* SDIO hardware does not support non-power-of-2-blocksizes */
	int		reset;          /* GPIO to RSTn signal (0 disables) */
	const u8	*macaddr;       /* if NULL, use wfx_mac_template module parameter */

	bool		hif_clkedge;    /* if true Hif Dout is sampled on the rising edge of the clock */
};

/* Default platform data */
static struct wfx_platform_data_sdio wfx_pi_hat_platform_data = {
	.no_nptb	= false,
	.hif_clkedge	= false,
	.reset		= 13,
};

/* Allow platform data to be overridden */
static struct wfx_platform_data_sdio *global_plat_data =
	&wfx_pi_hat_platform_data;

struct hwbus_priv {
	struct sdio_func			*func;
	struct wfx_common			*core;
	const struct wfx_platform_data_sdio	*pdata;
	u8					buf_id_tx;
	u8					buf_id_rx;
};

static const struct sdio_device_id wfx_sdio_ids[] = {
	{ SDIO_DEVICE(SDIO_VENDOR_ID_SILABS, SDIO_DEVICE_ID_SILABS_WFX200) },
	{ /* end: all zeroes */ },
};

/*========================================================================*/
/*                       Functions                                        */
/*========================================================================*/

void __init wfx_sdio_set_platform_data(struct wfx_platform_data_sdio *pdata)
{
	global_plat_data = pdata;
}

/*========================================================================*/
/*                  Internally Static Functions                           */
/*========================================================================*/
static int wfx_sdio_memcpy_fromio(struct hwbus_priv *self,
				  unsigned int addr,
				  void *dst, int count)
{
	int ret;

	/* Queue mode buffers must be handled */
	if (addr == WF200_IN_OUT_QUEUE_REG_ID) {
		addr = SDIO_ADDR12BIT(self->buf_id_rx + 1, addr);
		ret = sdio_memcpy_fromio(self->func, dst, addr, count);
		if (!ret) {
			/* Switch to next buffer when successful */
			/* loop over 1 to 4 */
			self->buf_id_rx = (self->buf_id_rx + 1) & 3;
		}
	} else {
		addr = SDIO_ADDR12BIT(0, addr);
		ret = sdio_memcpy_fromio(self->func, dst, addr, count);
	}
	return ret;
}

static int wfx_sdio_memcpy_toio(struct hwbus_priv *self,
				unsigned int addr,
				const void *src, int count)
{
	int ret;

	/* Queue mode buffers must be handled */
	if (addr == WF200_IN_OUT_QUEUE_REG_ID) {
		addr = SDIO_ADDR12BIT(self->buf_id_tx, addr);
		ret = sdio_memcpy_toio(self->func, addr, (void *)src, count);
		if (!ret) {
			/* Switch to next buffer when successful */
			/* loop over 0 to 31 */
			self->buf_id_tx = (self->buf_id_tx + 1) & 31;
		}
	} else {
		addr = SDIO_ADDR12BIT(0, addr);
		ret = sdio_memcpy_toio(self->func, addr, (void *)src, count);
	}

	return ret;
}

static void wfx_sdio_lock(struct hwbus_priv *self)
{
	sdio_claim_host(self->func);
}

static void wfx_sdio_unlock(struct hwbus_priv *self)
{
	sdio_release_host(self->func);
}

static void wfx_sdio_irq_handler(struct sdio_func *func)
{
	struct hwbus_priv *self = sdio_get_drvdata(func);

	/* note:  sdio_host already claimed here. */
	if (self->core)
		wfx_irq_handler(self->core);
}

static int wfx_sdio_irq_subscribe(struct hwbus_priv *self)
{
	int ret = 0;

	pr_debug("SW IRQ subscribe\n");
	sdio_claim_host(self->func);
	ret = sdio_claim_irq(self->func, wfx_sdio_irq_handler);
	sdio_release_host(self->func);
	return ret;
}

static int wfx_sdio_irq_unsubscribe(struct hwbus_priv *self)
{
	int ret = 0;

	pr_debug("SW IRQ unsubscribe\n");
	sdio_claim_host(self->func);
	ret = sdio_release_irq(self->func);
	sdio_release_host(self->func);
	return ret;
}

static int wfx_sdio_off(const struct wfx_platform_data_sdio *pdata)
{
	if (pdata->reset) {
		gpio_set_value(pdata->reset, 0);
		msleep(30); /* In accordance with Reset line behavior */
		gpio_free(pdata->reset);
	}
	return 0;
}

static int wfx_sdio_on(const struct wfx_platform_data_sdio *pdata)
{
	if (pdata->reset) {
		gpio_request(pdata->reset, "wfx_wlan_reset");
#ifdef HW_RESET_WFX_AT_DRIVER_LOAD
		gpio_direction_output(pdata->reset, 0);
		msleep(10);     /* In accordance with Reset line behavior */
		gpio_set_value(pdata->reset, 1);
		msleep(200);    /* In accordance with Reset line behavior */
#else
		/* No Reset at insmod,
		 *  mmc driver should have detected the chip already
		 */
		gpio_direction_output(pdata->reset, 1);
#endif
	}
	return 0;
}

static size_t wfx_sdio_align_size(struct hwbus_priv *self, size_t size)
{
	if (self->pdata->no_nptb)
		size = round_up(size, SDIO_BLOCK_SIZE);
	else
		size = sdio_align_size(self->func, size);

	/* the limit between send a variable length frame and send a block size frame */
	/* is problematic... it must be handled as two blocks */
	if (size == SDIO_BLOCK_SIZE)
		size = 2 * SDIO_BLOCK_SIZE;
	return size;
}

static int wfx_sdio_pm(struct hwbus_priv *self, bool suspend)
{
	int ret = 0;

	return ret;
}

static struct hwbus_ops wfx_sdio_hwbus_ops = {
	.hwbus_memcpy_fromio	= wfx_sdio_memcpy_fromio,
	.hwbus_memcpy_toio	= wfx_sdio_memcpy_toio,
	.lock			= wfx_sdio_lock,
	.unlock			= wfx_sdio_unlock,
	.align_size		= wfx_sdio_align_size,
	.power_mgmt		= wfx_sdio_pm,
};

/* Probe Function to be called by SDIO stack when device is discovered */
static int wfx_sdio_probe(struct sdio_func		*func,
			  const struct sdio_device_id	*id)
{
	struct hwbus_priv *self;
	int status;

	/* We are only able to handle the wlan function */
	if (func->num != 0x01)
		return -ENODEV;

	self = kzalloc(sizeof(*self), GFP_KERNEL);
	if (!self) {
		wfx_err("Can't allocate SDIO hwbus_priv.\n");
		return -ENOMEM;
	}

	func->card->quirks |= MMC_QUIRK_LENIENT_FN0;

	self->pdata = global_plat_data;
	self->func = func;
	self->buf_id_rx = 0;
	self->buf_id_tx = 0;
	sdio_set_drvdata(func, self);
	sdio_claim_host(func);
	sdio_enable_func(func);
	sdio_release_host(func);

	status = wfx_sdio_irq_subscribe(self);

	status = wfx_core_probe(&wfx_sdio_hwbus_ops,
				self, &func->dev, &self->core,
				self->pdata->macaddr,
				true, /* SDIO is used */
				self->pdata->hif_clkedge
				);
	if (status) {
		wfx_sdio_irq_unsubscribe(self);
		sdio_claim_host(func);
		sdio_disable_func(func);
		sdio_release_host(func);
		sdio_set_drvdata(func, NULL);
		kfree(self);
	}

	return status;
}

/* Disconnect Function to be called by SDIO stack when
 * device is disconnected
 */
static void wfx_sdio_disconnect(struct sdio_func *func)
{
	struct hwbus_priv *self = sdio_get_drvdata(func);

	if (self) {
		wfx_sdio_irq_unsubscribe(self);
		if (self->core) {
			wfx_core_release(self->core);
			self->core = NULL;
		}
		sdio_claim_host(func);
		sdio_disable_func(func);
		sdio_release_host(func);
		sdio_set_drvdata(func, NULL);
		kfree(self);
	}
}

#ifdef CONFIG_PM
static int wfx_sdio_suspend(struct device *dev)
{
	int ret;
	struct sdio_func *func = dev_to_sdio_func(dev);
	struct hwbus_priv *self = sdio_get_drvdata(func);

	if (!wfx_can_suspend(self->core))
		return -EAGAIN;

	/* Notify SDIO that wfx will remain powered during suspend */
	ret = sdio_set_host_pm_flags(func, MMC_PM_KEEP_POWER);
	if (ret)
		wfx_err("Error setting SDIO pm flags: %i\n", ret);

	return ret;
}

static int wfx_sdio_resume(struct device *dev)
{
	return 0;
}

static const struct dev_pm_ops wfx_pm_ops = {
	.suspend	= wfx_sdio_suspend,
	.resume		= wfx_sdio_resume,
};

#endif

static struct sdio_driver sdio_driver = {
	.name		= "wfx_wlan_sdio",
	.id_table	= wfx_sdio_ids,
	.probe		= wfx_sdio_probe,
	.remove		= wfx_sdio_disconnect,
#ifdef CONFIG_PM
	.drv		= {
		.pm	= &wfx_pm_ops,
	}
#endif
};

static int sys_reboot_callback(struct notifier_block *self, unsigned long val,
			       void *data);

static struct notifier_block wfx_reboot_notifier = {
	.notifier_call	= sys_reboot_callback,
};

/* Init Module function -> Called by insmod */
static int __init wfx_sdio_init(void)
{
	const struct wfx_platform_data_sdio *pdata;
	int ret;

	wfx_info(
		"wfx_sdio_init\n  - SDIO_VENDOR_ID_SILABS        0x%04x\n  - SDIO_DEVICE_ID_SILABS_WFX200 0x%04x",
		SDIO_VENDOR_ID_SILABS,
		SDIO_DEVICE_ID_SILABS_WFX200);
	register_reboot_notifier(&wfx_reboot_notifier);
	pdata = global_plat_data;

	if (wfx_sdio_on(pdata)) {
		wfx_err("wfx_sdio_on returned 1");
		ret = -1;
		goto err;
	}

	ret = sdio_register_driver(&sdio_driver);
	if (ret) {
		wfx_err("wfx_wlan_sdio: can't register sdio driver %i\n", ret);
		goto err;
	}

	return 0;

err:
	wfx_sdio_off(pdata);
	return ret;
}

/* Called at Driver Unloading */
static void __exit wfx_sdio_exit(void)
{
	const struct wfx_platform_data_sdio *pdata;

	wfx_info("wfx_wlan_sdio exit\n");

	pdata = global_plat_data;
	sdio_unregister_driver(&sdio_driver);
	wfx_sdio_off(pdata);
	unregister_reboot_notifier(&wfx_reboot_notifier);
}

static int sys_reboot_callback(struct notifier_block	*self,
			       unsigned long		val,
			       void			*data)
{
	wfx_info("notifier system called with %lu.\n", val);
	if (val == SYS_RESTART) {
		pr_debug(
			"System is rebooting wfx_wlan_sdio will be unloaded.\n");
		wfx_sdio_off(global_plat_data);
	}
	return NOTIFY_DONE;
}

module_init(wfx_sdio_init);

module_exit(wfx_sdio_exit);
