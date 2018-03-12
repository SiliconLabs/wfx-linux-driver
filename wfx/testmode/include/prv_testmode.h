/*
 * Copyright (c) 2017, Silicon Laboratories, Inc.
 *
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef PRV_TESTMODE_H_
#define PRV_TESTMODE_H_

/*========================================================================*/
/*                 Standard Linux Headers                                 */
/*========================================================================*/
#include "net/mac80211.h"

/*************************/
/* For driver's use only */
/*************************/

int wfx_testmode_command(struct ieee80211_hw *hw,
        struct ieee80211_vif *vif,
                void *data, int len);
int wfx_testmode_reply(struct wiphy *wiphy,
                const void *data, int len);

int wfx_testmode_hif(struct ieee80211_hw *hw,struct nlattr **p_tb);
int wfx_testmode_bs(struct ieee80211_hw *hw,struct nlattr **p_tb);

/* DO NOT USE DIRECTLY */
/* It is safer to call through the macro */

#ifdef CONFIG_WF200_TESTMODE
void hif_buffer_add(u16 id);
void bs_buffer_add(uint8_t *pui8_Array, size_t s_Length);
#define wfx_tm_hif_buffer_add(wsm_id) hif_buffer_add(wsm_id)
#endif

#endif /* PRV_TESTMODE_H_ */
