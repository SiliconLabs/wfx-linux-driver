// SPDX-License-Identifier: GPL-2.0-only
/*
 * Extra commands for nl80211 interface.
 *
 * Copyright (c) 2020, Silicon Laboratories, Inc.
 */
#include "nl80211_vendor.h"
#include "wfx.h"
#include "sta.h"

int wfx_nl_ps_timeout(struct wiphy *wiphy, struct wireless_dev *widev,
		      const void *data, int data_len)
{
	int reply_size = nla_total_size(sizeof(u32));
	struct nlattr *tb[WFX_NL80211_ATTR_MAX];
	struct ieee80211_vif *vif;
	struct wfx_vif *wvif;
	struct sk_buff *msg;
	int rc, ps_timeout;

	rc = nla_parse(tb, WFX_NL80211_ATTR_MAX - 1, data, data_len,
		       wfx_nl_policy, NULL);
	if (rc)
		return rc;
	vif = wdev_to_ieee80211_vif(widev);
	if (!vif)
		return -ENODEV;
	wvif = (struct wfx_vif *)vif->drv_priv;

	if (tb[WFX_NL80211_ATTR_PS_TIMEOUT]) {
		wvif->force_ps_timeout =
			nla_get_s32(tb[WFX_NL80211_ATTR_PS_TIMEOUT]);
		wfx_update_pm(wvif);
	}

	msg = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, reply_size);
	if (!msg)
		return -ENOMEM;
	ps_timeout = wfx_get_ps_timeout(wvif, NULL);
	rc = nla_put_s32(msg, WFX_NL80211_ATTR_PS_TIMEOUT, ps_timeout);
	if (rc)
		goto error;
	return cfg80211_vendor_cmd_reply(msg);

error:
	kfree_skb(msg);
	return rc;
}

