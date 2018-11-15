/*
 * Copyright (c) 2017, Silicon Laboratories, Inc.
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

#include <net/mac80211.h>
#include <net/netlink.h>

#include "testmode.h"
#include "wfx_testmode.h"
#include "wfx.h"
#include "hwio.h"
#include "fwio.h"
#include "sta.h"
#include "debug.h"

#define TM_BS_BUFFER_LEN (1024)

static u8 l_aui8_bs_buffer[TM_BS_BUFFER_LEN];
static u16 l_ui16_bs_buffer_set;
static u16 l_ui16_bs_buffer_get;

static bool l_b_bs_pm_enable = true;

void wfx_testmode_bs_buffer_add(u8 *pui8_Array, size_t s_Length)
{
	size_t s_LengthCopy;

	if (!l_b_bs_pm_enable ||
	    l_ui16_bs_buffer_set == TM_BS_BUFFER_LEN)
		return;

	s_LengthCopy =
		min(s_Length,
		    (size_t)(TM_BS_BUFFER_LEN - l_ui16_bs_buffer_set));

	pr_warn("cpy %zu\n", s_LengthCopy);
	memcpy(&l_aui8_bs_buffer[l_ui16_bs_buffer_set], pui8_Array,
	       s_LengthCopy);

	l_ui16_bs_buffer_set += s_LengthCopy;
}

static void wfx_testmode_bs_buffer_flush(struct sk_buff *skb)
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

static int wfx_testmode_bs(struct ieee80211_hw *hw, struct nlattr **p_tb)
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

		wfx_testmode_bs_buffer_flush(skb);

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


/**
 * wfx_testmode_cmd -called when testmode command
 * reaches wfx_
 *
 * @hw: the hardware
 * @data: incoming data
 * @len: incoming data length
 *
 * Returns: 0 on success or non zero value on failure
 */
int wfx_testmode_command(struct ieee80211_hw *hw,
			 struct ieee80211_vif *vif,
			 void *data, int len)
{
	int ret = 0;
	int err;
	struct nlattr *tb[NLA_MAX_TYPE];
	struct wfx_dev *wdev;


	wdev = (struct wfx_dev *)hw->priv;

#if (KERNEL_VERSION(4, 14, 0) <= LINUX_VERSION_CODE)
	err = nla_parse(tb, NLA_MAX_TYPE, data, len, NULL, NULL);
#else
	err = nla_parse(tb, NLA_MAX_TYPE, data, len, NULL);
#endif
	if (err)
		return err;

	dev_dbg(wdev->pdev, "testmode: received command %08x\n", nla_get_u32(tb[WFX_TM_ATTR_TYPE]));
	switch (nla_get_u32(tb[WFX_TM_ATTR_TYPE])) {
	case WFX_TM_ATTR_TYPE_BITSTEAM:
		ret = wfx_testmode_bs(hw, tb);
		break;

	case WFX_TM_ATTR_TYPE_FW_TEST:
		dev_warn(wdev->pdev, "reloading PDS from testmode is deprecated, prefer /sys/kernel/debug/ieee80211/phy0/wfx/send_pds\n");
		/* FW tests are activated and configured by PDS. */
		/* Just force reloading of the file */
		ret = wfx_send_pdata_pds(wdev);
		break;
	default:
		break;
	}
	return ret;
}
