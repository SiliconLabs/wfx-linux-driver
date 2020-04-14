/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Extra commands for nl80211 interface.
 *
 * Copyright (c) 2020, Silicon Laboratories, Inc.
 */
#ifndef WFX_NL80211_VENDOR_H
#define WFX_NL80211_VENDOR_H

#include <net/netlink.h>
#include <net/cfg80211.h>

#include "hif_api_general.h"


#define WFX_NL80211_ID 0x90fd9f

int wfx_nl_ps_timeout(struct wiphy *wiphy, struct wireless_dev *widev,
		      const void *data, int data_len);

enum {
	WFX_NL80211_SUBCMD_PS_TIMEOUT                   = 0x10,
};

enum {
	WFX_NL80211_ATTR_PS_TIMEOUT     = 1,
	WFX_NL80211_ATTR_MAX
};

static const struct nla_policy wfx_nl_policy[WFX_NL80211_ATTR_MAX] = {
	[WFX_NL80211_ATTR_PS_TIMEOUT]     = NLA_POLICY_RANGE(NLA_S32, -1, 127),
};

static const struct wiphy_vendor_command wfx_nl80211_vendor_commands[] = {
	{
		.info.vendor_id = WFX_NL80211_ID,
		.info.subcmd = WFX_NL80211_SUBCMD_PS_TIMEOUT,
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV,
		.policy = wfx_nl_policy,
		.doit = wfx_nl_ps_timeout,
		.maxattr = WFX_NL80211_ATTR_MAX - 1,
	},
};

#endif /* WFX_NL80211_VENDOR_H */
