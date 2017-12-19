/*
 * Copyright (c) 2017, Silicon Laboratories, Inc.
 *
 * Based on:
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


#ifndef HWBUS_H
#define HWBUS_H

/*========================================================================*/
/*                  Structures definitions                                */
/*========================================================================*/
struct hwbus_priv;

struct hwbus_ops {
	int (*hwbus_memcpy_fromio)(struct hwbus_priv *self, unsigned int addr,
					void *dst, int count);
	int (*hwbus_memcpy_toio)(struct hwbus_priv *self, unsigned int addr,
					const void *src, int count);
	void (*lock)(struct hwbus_priv *self);
	void (*unlock)(struct hwbus_priv *self);
	size_t (*align_size)(struct hwbus_priv *self, size_t size);
	int (*power_mgmt)(struct hwbus_priv *self, bool suspend);
};

/*========================================================================*/
/*                       Functions                                        */
/*========================================================================*/
void wfx_irq_handler(struct wfx_common *priv);

int __wfx_irq_enable(struct wfx_common *priv, int enable);

#endif /* HWBUS_H */
