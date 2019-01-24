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
