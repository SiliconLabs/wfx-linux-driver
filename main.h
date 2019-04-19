/*
 * Common private data for Silicon Labs WFX drivers
 *
 * Copyright (c) 2017-2019, Silicon Laboratories, Inc.
 * Copyright (c) 2010, ST-Ericsson
 * Copyright (c) 2006, Michael Wu <flamingice@sourmilk.net>
 * Copyright 2004-2006 Jean-Baptiste Note <jbnote@gmail.com>, et al.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef MAIN_H
#define MAIN_H

#include <linux/device.h>
#include <linux/gpio/consumer.h>

#include "hwbus.h"

struct wfx_dev;

struct wfx_platform_data {
	/* Keyset and ".sec" extention will appended to this string */
	const char *file_fw;
	const char *file_pds;
	struct gpio_desc *gpio_wakeup;
	bool support_ldpc;
	/*
	 * if true HIF D_out is sampled on the rising edge of the clock
	 * (intended to be used in 50Mhz SDIO)
	 */
	bool use_rising_clk;
	bool sdio;
};

struct wfx_dev *wfx_init_common(struct device *dev,
			        const struct wfx_platform_data *pdata,
			        const struct hwbus_ops *hwbus_ops,
			        void *hwbus_priv);
void wfx_free_common(struct wfx_dev *wdev);

int wfx_probe(struct wfx_dev *wdev);
void wfx_release(struct wfx_dev *wdev);

struct gpio_desc *wfx_get_gpio(struct device *dev, int override,
			       const char *label);

#endif /* MAIN_H */
