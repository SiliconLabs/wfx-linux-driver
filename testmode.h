/*
 * Copyright (c) 2018, Silicon Laboratories, Inc.
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
#ifndef WFX_TESTMODE_H
# define WFX_TESTMODE_H

#include <net/mac80211.h>

#ifdef CONFIG_NL80211_TESTMODE
int wfx_testmode_command(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
			 void *data, int len);
#endif

#endif /* WFX_TESTMODE_H */

