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

#ifndef BH_H
#define BH_H

/*========================================================================*/
/*                  Structures definitions                                */
/*========================================================================*/
struct wfx_common;

/*========================================================================*/
/*                       Functions                                        */
/*========================================================================*/
int wfx_register_bh(struct wfx_common *priv);
int wsm_release_tx_buffer(struct wfx_common *priv, int count);
int wfx_bh_suspend(struct wfx_common *priv);
int wfx_bh_resume(struct wfx_common *priv);

/* Must be called from BH thread. */
void wfx_enable_powersave(struct wfx_common *priv,
			     bool enable);
void wfx_unregister_bh(struct wfx_common *priv);
void wfx_irq_handler(struct wfx_common *priv);
void wfx_bh_wakeup(struct wfx_common *priv);

#endif /* BH_H */
