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

#ifndef FWIO_H_INCLUDED
#define FWIO_H_INCLUDED

/*========================================================================*/
/*                  PRIVATE  Constants/Macros/Types/Variables             */
/*========================================================================*/

/* WF200 boot files */
#define FIRMWARE_WF200_SEC      "wfm_wf200.sec"
#define PDS_FILE_WF200          "pds_wf200.json"

/*========================================================================*/
/*                  Structures definitions                                */
/*========================================================================*/

extern struct timer_list fwio_timer;

/*========================================================================*/
/*                       Functions                                        */
/*========================================================================*/
int wfx_load_firmware(struct wfx_common *priv);
int wfx_secure_load_firmware_file(struct wfx_common *priv, u8 *firmware,
				  u32 fw_length);
/* Timer helper functions */
void timer_expiration_cb(unsigned long data);
void start_timer(u32 timeout);
void stop_timer(void);

#endif
