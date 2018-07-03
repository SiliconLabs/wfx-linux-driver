/*
 * Copyright (c) 2017, Silicon Laboratories, Inc.
 *
 * based on:
 * Copyright (c) 2011, Sagrad Inc.
 * Author:  Solomon Peachy <speachy@sagrad.com>
 * Based on cw1200_sdio.c
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

/*========================================================================*/
/*                 Standard Linux Headers                                 */
/*========================================================================*/
#include <linux/module.h>
#include <linux/gpio.h>
#include <linux/delay.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <net/mac80211.h>
#include <linux/spi/spi.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/of_irq.h>

/*========================================================================*/
/*                 Local Header files                                     */
/*========================================================================*/
#include "wfx.h"
#include "hwbus.h"
#include "hwio.h"
#include "wfx_version.h"
#include "debug.h"

/*========================================================================*/
/*                 wfx_wlan_spi module information                        */
/*========================================================================*/
MODULE_DESCRIPTION("Silicon labs 802.11 Wireless LAN spi driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("spi:wfx_wlan_spi");
MODULE_VERSION(WFX_LABEL);

/*========================================================================*/
/*                 wfx_wlan_spi Bypass Parameters                         */
/*========================================================================*/

/*========================================================================*/
/*                  PRIVATE  Constants/Macros/Types/Variables             */
/*========================================================================*/
#define SET_WRITE 0x7FFF        /* usage: and operation */
#define SET_READ 0x8000         /* usage: or operation */

/*========================================================================*/
/*                  Structures definitions                                */
/*========================================================================*/
struct wfx_platform_data_spi {
	u8		spi_bits_per_word;      /* REQUIRED */

	int		reset;          /* GPIO to RSTn signal (0 disables) */
	const u8	*macaddr;       /* if NULL, use wfx_mac_template module parameter */

	bool		hif_clkedge;    /* if true Hif Dout is sampled on the rising edge of the clock */
};

struct hwbus_priv {
	struct spi_device		*func;
	struct wfx_common		*core;
	struct wfx_platform_data_spi	*pdata;
};

/* Default platform data */
static struct wfx_platform_data_spi silabs_platform_data = {
	.spi_bits_per_word	= 8,
	.reset			= 13,
	.hif_clkedge		= true,
};

/*========================================================================*/
/*                  Internally Static Functions                           */
/*========================================================================*/
/* Notes on byte ordering:
 * LE:  B0 B1 B2 B3
 * BE:  B3 B2 B1 B0
 *
 * Hardware expects 32-bit data to be written as 16-bit BE words:
 *
 * B1 B0 B3 B2
 */
static int wfx_spi_memcpy_fromio(struct hwbus_priv *self,
				 unsigned int addr,
				 void *dst, int count)
{
	int ret;
	u16 regaddr;
	struct spi_message m;

	struct spi_transfer t_addr = {
		.tx_buf = &regaddr,
		.len	= sizeof(regaddr),
	};
	struct spi_transfer t_msg = {
		.rx_buf = dst,
		.len	= count,
	};

	regaddr = (addr) << 12;
	regaddr |= SET_READ;
	regaddr |= (count >> 1);


	/* Header is LE16 */
	regaddr = cpu_to_le16(regaddr);

	/* We have to byteswap if the SPI bus is limited to 8b operation
	 * or we are running on a Big Endian system
	 */
#if defined(__LITTLE_ENDIAN)
	if (self->func->bits_per_word == 8)
#endif
	regaddr = swab16(regaddr);

	spi_message_init(&m);
	spi_message_add_tail(&t_addr, &m);
	spi_message_add_tail(&t_msg, &m);
	ret = spi_sync(self->func, &m);


	/* We have to byteswap if the SPI bus is limited to 8b operation
	 * or we are running on a Big Endian system
	 */
#if defined(__LITTLE_ENDIAN)
	if (self->func->bits_per_word == 8)
#endif
	{
		int i;

		u16 *buf = (u16 *)dst;

		for (i = 0; i < ((count + 1) >> 1); i++)
			buf[i] = swab16(buf[i]);
	}

	return ret;
}

static int wfx_spi_memcpy_toio(struct hwbus_priv *self,
			       unsigned int addr,
			       const void *src, int count)
{
	int rval, i;
	u16 regaddr;
	struct spi_transfer t_addr = {
		.tx_buf = &regaddr,
		.len	= sizeof(regaddr),
	};
	struct spi_transfer t_msg = {
		.tx_buf = src,
		.len	= count,
	};
	struct spi_message m;

	regaddr = (addr) << 12;
	regaddr &= SET_WRITE;
	regaddr |= (count >> 1);

	/* Header is LE16 */
	regaddr = cpu_to_le16(regaddr);

	/* We have to byteswap if the SPI bus is limited to 8b operation
	 * or we are running on a Big Endian system
	 */
#if defined(__LITTLE_ENDIAN)
	if (self->func->bits_per_word == 8)
#endif

	{
		u16 *buf = (u16 *)src;

		regaddr = swab16(regaddr);
		for (i = 0; i < ((count + 1) >> 1); i++)
			buf[i] = swab16(buf[i]);
	}

	spi_message_init(&m);
	spi_message_add_tail(&t_addr, &m);
	spi_message_add_tail(&t_msg, &m);
	rval = spi_sync(self->func, &m);


#if defined(__LITTLE_ENDIAN)
	/* We have to byteswap if the SPI bus is limited to 8b operation */
	if (self->func->bits_per_word == 8)
#endif
	{
		u16 *buf = (u16 *)src;

		for (i = 0; i < ((count + 1) >> 1); i++)
			buf[i] = swab16(buf[i]);
	}
	return rval;
}

static void wfx_spi_lock(struct hwbus_priv *self)
{
}

static void wfx_spi_unlock(struct hwbus_priv *self)
{
}

static irqreturn_t wfx_spi_irq_handler(int irq, void *dev_id)
{
	struct hwbus_priv *self = dev_id;

	if (self->core) {
		wfx_irq_handler(self->core);

		return IRQ_HANDLED;
	} else {
		return IRQ_NONE;
	}
}

static int wfx_spi_irq_subscribe(struct hwbus_priv *self)
{
	int ret;

	ret = request_irq(self->func->irq,
			  wfx_spi_irq_handler,
			  IRQF_TRIGGER_RISING,
			  "wfx_wlan_irq", self);
	if (ret < 0) {
		wfx_err("wfx spi irq subscribe");
		goto exit;
	}

	return 0;
exit:
	return ret;
}

static int wfx_spi_irq_unsubscribe(struct hwbus_priv *self)
{
	int ret = 0;

	pr_debug("SW IRQ unsubscribe\n");
	free_irq(self->func->irq, self);

	return ret;
}

static int wfx_spi_off(const struct wfx_platform_data_spi *pdata)
{
	if (pdata->reset) {
		gpio_set_value(pdata->reset, 0);
		msleep(30); /* Min is 2 * CLK32K cycles */
		gpio_free(pdata->reset);
	}
	return 0;
}

static int wfx_spi_on(const struct wfx_platform_data_spi *pdata)
{
	if (pdata->reset) {
		gpio_request(pdata->reset, "wfx_wlan_reset");
		gpio_direction_output(pdata->reset, 0);
		msleep(10); /* In accordance with Reset line behavior */
		gpio_set_value(pdata->reset, 1);
		msleep(200); /* In accordance with Reset line behavior */
	}
	return 0;
}

static size_t wfx_spi_align_size(struct hwbus_priv *self, size_t size)
{
	return (size & 1) ? size + 1 : size;
}

static int wfx_spi_pm(struct hwbus_priv *self, bool suspend)
{
	return irq_set_irq_wake(self->func->irq, suspend);
}

static struct hwbus_ops wfx_spi_hwbus_ops = {
	.hwbus_memcpy_fromio	= wfx_spi_memcpy_fromio,
	.hwbus_memcpy_toio	= wfx_spi_memcpy_toio,
	.lock			= wfx_spi_lock,
	.unlock			= wfx_spi_unlock,
	.align_size		= wfx_spi_align_size,
	.power_mgmt		= wfx_spi_pm,
};

/* Probe Function to be called by SPI stack when device is discovered */
static int wfx_spi_probe(struct spi_device *func)
{
	struct wfx_platform_data_spi *plat_data = devm_kzalloc(&func->dev,
							       sizeof(struct
								      wfx_platform_data_spi),
							       GFP_KERNEL);

	struct hwbus_priv *self;
	int status;

	plat_data->spi_bits_per_word = silabs_platform_data.spi_bits_per_word;
	wfx_info("SPI BUS\n");
	plat_data->reset = silabs_platform_data.reset;

	plat_data->hif_clkedge = silabs_platform_data.hif_clkedge;

	status = irq_of_parse_and_map(func->dev.of_node, 0);

	/* Sanity check speed */
	if (func->max_speed_hz > 52000000)
		func->max_speed_hz = 52000000;
	if (func->max_speed_hz < 1000000)
		func->max_speed_hz = 1000000;

	/* Fix up transfer size */
	if (plat_data->spi_bits_per_word)
		func->bits_per_word = plat_data->spi_bits_per_word;
	if (!func->bits_per_word)
		func->bits_per_word = 16;

	/* And finally.. */
	func->mode = SPI_MODE_0;

	wfx_info("Probe called (CS %d M %d BPW %d CLK %d)\n",
		 func->chip_select, func->mode, func->bits_per_word,
		 func->max_speed_hz); /* max_speed_hz retrieved from DT */

	if (wfx_spi_on(plat_data)) {
		wfx_err("spi_on() failed!\n");
		return -1;
	}

	if (spi_setup(func)) {
		wfx_err("spi_setup() failed!\n");
		return -1;
	}

	self = devm_kzalloc(&func->dev, sizeof(*self), GFP_KERNEL);
	if (!self) {
		wfx_err("Can't allocate SPI hwbus_priv.");
		return -ENOMEM;
	}

	self->pdata = plat_data;
	self->func = func;

	spi_set_drvdata(func, self);

	status = wfx_spi_irq_subscribe(self);
	status = wfx_core_probe(&wfx_spi_hwbus_ops,
				self, &func->dev, &self->core,
				self->pdata->macaddr,
				false, /* SPI is used */
				self->pdata->hif_clkedge
				);

	if (status) {
		wfx_spi_irq_unsubscribe(self);
		wfx_spi_off(plat_data);
	}

	return status;
}

/* Disconnect Function to be called by SPI stack when device is disconnected */
static int wfx_spi_disconnect(struct spi_device *func)
{
	struct hwbus_priv *self = spi_get_drvdata(func);

	if (self) {
		if (self->core) {
			wfx_core_release(self->core);
			self->core = NULL;
		}
		wfx_spi_irq_unsubscribe(self);

		wfx_spi_off(self->pdata);
	}
	wfx_info("All wfx wlan modules are disconnected\n");

	return 0;
}

#ifdef CONFIG_PM
static int wfx_spi_suspend(struct device *dev)
{
	struct hwbus_priv *self = spi_get_drvdata(to_spi_device(dev));

	if (!wfx_can_suspend(self->core))
		return -EAGAIN;
	return 0;
}

static const struct dev_pm_ops wfx_pm_ops = {
	.suspend	= wfx_spi_suspend,
	.resume		= NULL,
};

#endif

#if 1
static const struct spi_device_id wfx_spi_id[] = {
	{ "wfx_spi", 0 },
	{ }
};

MODULE_DEVICE_TABLE(spi, wfx_spi_id);

#ifdef CONFIG_OF
static const struct of_device_id wfx_of_match[] = {
	{ .compatible = "siliconlabs,wfx-wlan-spi" },
	{  },
};

MODULE_DEVICE_TABLE(of, wfx_of_match);
#endif
#endif
static struct spi_driver wfx_spi_driver = {
	.probe			= wfx_spi_probe,
	.remove			= wfx_spi_disconnect,
	.id_table		= wfx_spi_id,
	.driver			= {
		.name		= "wfx_wlan_spi",
		.bus		= &spi_bus_type,
		.owner		= THIS_MODULE,
#ifdef CONFIG_PM
		.pm		= &wfx_pm_ops,
#endif
#ifdef CONFIG_OF
		.of_match_table = of_match_ptr(wfx_of_match),
#endif
	},
};

module_spi_driver(wfx_spi_driver);
