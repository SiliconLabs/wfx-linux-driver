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

/*========================================================================*/
/*                 Standard Linux Headers                                 */
/*========================================================================*/
#include <net/netlink.h>
#include <net/genetlink.h>
#include <linux/time.h>
#include "net/mac80211.h"

/*========================================================================*/
/*                 Local Header files                                     */
/*========================================================================*/
#include "include/wfx_testmode.h"
#include "include/prv_testmode.h"

/*========================================================================*/
/*                  PRIVATE  Constants/Macros/Types/Variables             */
/*========================================================================*/
#define TM_BS_BUFFER_LEN (1024)

/*========================================================================*/
/*                  Internally Static Functions                           */
/*========================================================================*/
static void bs_buffer_flush(struct sk_buff *skb);

static u8 l_aui8_bs_buffer[TM_BS_BUFFER_LEN];
static u16 l_ui16_bs_buffer_set;
static u16 l_ui16_bs_buffer_get;

static bool l_b_bs_pm_enable = true;

/*========================================================================*/
/*                       Functions                                        */
/*========================================================================*/
int wfx_testmode_bs(struct ieee80211_hw *hw, struct nlattr **p_tb)
{
	switch (nla_get_u32(p_tb[WFX_TM_ATTR_CMD])) {
	case WFX_TM_CMD_BS_ENABLE:
	{
		/* Should not be called. */
		l_b_bs_pm_enable = !l_b_bs_pm_enable;
	}

	case WFX_TM_CMD_BS_FLUSH:
	{
		int ret;
		struct sk_buff *skb = cfg80211_testmode_alloc_reply_skb(
			hw->wiphy,
			sizeof(
				u8) * l_ui16_bs_buffer_set);

		if (!skb)
			return -ENOMEM;

		bs_buffer_flush(skb);

		ret = cfg80211_testmode_reply(skb);

		if (ret != 0)
			pr_err("ret = %d\n", ret);
		break;
	}
	default:
		pr_info("BS testmode unknown\n");
		break;
	}
	return 0;
};

#ifdef CONFIG_WF200_TESTMODE
void bs_buffer_add(u8 *pui8_Array, size_t s_Length)
{
	size_t s_LengthCopy;

	if (!l_b_bs_pm_enable ||
	    l_ui16_bs_buffer_set == TM_BS_BUFFER_LEN)
		return;

	s_LengthCopy =
		min(s_Length,
		    (size_t)(TM_BS_BUFFER_LEN - l_ui16_bs_buffer_set));

	pr_warn("cpy %d\n", s_LengthCopy);
	memcpy(&l_aui8_bs_buffer[l_ui16_bs_buffer_set], pui8_Array,
	       s_LengthCopy);

	l_ui16_bs_buffer_set += s_LengthCopy;
}
#endif

void bs_buffer_flush(struct sk_buff *skb)
{
	u16 ui16_nbDataToFlush = l_ui16_bs_buffer_set -
				      l_ui16_bs_buffer_get;

	pr_warn("cui16_nbDataToFlush %d\n", ui16_nbDataToFlush);
	nla_put_u32(skb, WFX_TM_ATTR_BS_BUFF_LEN, ui16_nbDataToFlush);
	nla_put(skb, WFX_TM_ATTR_BS_BUFF,
		ui16_nbDataToFlush * sizeof(u8),
		&l_aui8_bs_buffer[l_ui16_bs_buffer_get]);

	l_ui16_bs_buffer_set = 0;
	l_ui16_bs_buffer_get = l_ui16_bs_buffer_set;
}
