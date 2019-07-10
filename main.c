// SPDX-License-Identifier: GPL-2.0-only
/*
 * Device probe and register.
 *
 * Copyright (c) 2017-2019, Silicon Laboratories, Inc.
 * Copyright (c) 2010, ST-Ericsson
 * Copyright (c) 2008, Johannes Berg <johannes@sipsolutions.net>
 * Copyright (c) 2008 Nokia Corporation and/or its subsidiary(-ies).
 * Copyright (c) 2007-2009, Christian Lamparter <chunkeey@web.de>
 * Copyright (c) 2006, Michael Wu <flamingice@sourmilk.net>
 * Copyright (c) 2004-2006 Jean-Baptiste Note <jbnote@gmail.com>, et al.
 */
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_net.h>
#include <linux/gpio.h>
#include <linux/gpio/consumer.h>
#include <linux/mmc/sdio_func.h>
#include <linux/spi/spi.h>
#include <linux/etherdevice.h>

#include "wfx_version.h"
#include "wsm_cmd_api.h"
#include "wfx.h"
#include "fwio.h"
#include "hwio.h"
#include "bh.h"
#include "sta.h"
#include "key.h"
#include "debug.h"
#include "wsm_mib.h"
#include "secure_link.h"

MODULE_DESCRIPTION("Silicon Labs 802.11 Wireless LAN driver for WFx");
MODULE_AUTHOR("Jérôme Pouiller <jerome.pouiller@silabs.com>");
MODULE_LICENSE("GPL");
MODULE_VERSION(WFX_LABEL);
// Legacy
MODULE_ALIAS("wfx-core");
MODULE_ALIAS("wfx-wlan-spi");
MODULE_ALIAS("wfx-wlan-sdio");

static int gpio_wakeup = -2;
module_param(gpio_wakeup, int, 0644);
MODULE_PARM_DESC(gpio_wakeup, "gpio number for wakeup. -1 for none.");

static char *slk_key = NULL;
module_param(slk_key, charp, 0600);
MODULE_PARM_DESC(slk_key, "Secret key for secure link (expect 64 hexdecimal digits)");

#define RATETAB_ENT(_rate, _rateid, _flags) { \
	.bitrate	= (_rate),   \
	.hw_value	= (_rateid), \
	.flags		= (_flags),  \
}

static struct ieee80211_rate wfx_rates[] = {
	RATETAB_ENT( 10,  0, 0),
	RATETAB_ENT( 20,  1, 0),
	RATETAB_ENT( 55,  2, 0),
	RATETAB_ENT(110,  3, 0),
	RATETAB_ENT( 60,  6, 0),
	RATETAB_ENT( 90,  7, 0),
	RATETAB_ENT(120,  8, 0),
	RATETAB_ENT(180,  9, 0),
	RATETAB_ENT(240, 10, 0),
	RATETAB_ENT(360, 11, 0),
	RATETAB_ENT(480, 12, 0),
	RATETAB_ENT(540, 13, 0),
};

static const struct ieee80211_rate wfx_mcs_rates[] = {
	RATETAB_ENT( 65, 14, IEEE80211_TX_RC_MCS),
	RATETAB_ENT(130, 15, IEEE80211_TX_RC_MCS),
	RATETAB_ENT(195, 16, IEEE80211_TX_RC_MCS),
	RATETAB_ENT(260, 17, IEEE80211_TX_RC_MCS),
	RATETAB_ENT(390, 18, IEEE80211_TX_RC_MCS),
	RATETAB_ENT(520, 19, IEEE80211_TX_RC_MCS),
	RATETAB_ENT(585, 20, IEEE80211_TX_RC_MCS),
	RATETAB_ENT(650, 21, IEEE80211_TX_RC_MCS),
};

#define CHAN2G(_channel, _freq, _flags) { \
	.band = NL80211_BAND_2GHZ, \
	.center_freq = (_freq),    \
	.hw_value = (_channel),    \
	.flags = (_flags),         \
	.max_antenna_gain = 0,     \
	.max_power = 30,           \
}

static struct ieee80211_channel wfx_2ghz_chantable[] = {
	CHAN2G( 1, 2412, 0),
	CHAN2G( 2, 2417, 0),
	CHAN2G( 3, 2422, 0),
	CHAN2G( 4, 2427, 0),
	CHAN2G( 5, 2432, 0),
	CHAN2G( 6, 2437, 0),
	CHAN2G( 7, 2442, 0),
	CHAN2G( 8, 2447, 0),
	CHAN2G( 9, 2452, 0),
	CHAN2G(10, 2457, 0),
	CHAN2G(11, 2462, 0),
	CHAN2G(12, 2467, 0),
	CHAN2G(13, 2472, 0),
	CHAN2G(14, 2484, 0),
};

static const struct ieee80211_supported_band wfx_band_2ghz = {
	.channels = wfx_2ghz_chantable,
	.n_channels = ARRAY_SIZE(wfx_2ghz_chantable),
	.bitrates = wfx_rates,
	.n_bitrates = ARRAY_SIZE(wfx_rates),
	.ht_cap = {
		// Receive caps
		.cap = IEEE80211_HT_CAP_GRN_FLD | IEEE80211_HT_CAP_SGI_20 |
		       IEEE80211_HT_CAP_MAX_AMSDU | (1 << IEEE80211_HT_CAP_RX_STBC_SHIFT),
		.ht_supported = 1,
		.ampdu_factor = IEEE80211_HT_MAX_AMPDU_16K,
		.ampdu_density = IEEE80211_HT_MPDU_DENSITY_NONE,
		.mcs = {
			.rx_mask = { 0xFF }, // MCS0 to MCS7
			.rx_highest = 65,
			.tx_params = IEEE80211_HT_MCS_TX_DEFINED,
		},
	},
};

static const struct ieee80211_iface_limit wdev_iface_limits[] = {
	{ .max = 1, .types = BIT(NL80211_IFTYPE_STATION) },
	{ .max = 1, .types = BIT(NL80211_IFTYPE_AP) },
	{ .max = 1, .types = BIT(NL80211_IFTYPE_P2P_CLIENT) | BIT(NL80211_IFTYPE_P2P_GO) },
};

static const struct ieee80211_iface_combination wfx_iface_combinations[] = {
	{
		.num_different_channels = 2,
		.max_interfaces = 2,
		.limits = wdev_iface_limits,
		.n_limits = ARRAY_SIZE(wdev_iface_limits),
	}
};

static const unsigned long wfx_ttl[] = {
	1 * HZ,	/* VO */
	2 * HZ,	/* VI */
	5 * HZ, /* BE */
	10 * HZ	/* BK */
};

static const struct ieee80211_ops wfx_ops = {
	.start			= wfx_start,
	.stop			= wfx_stop,
	.add_interface		= wfx_add_interface,
	.change_interface	= wfx_change_interface,
	.remove_interface	= wfx_remove_interface,
	.config			= wfx_config,
	.tx			= wfx_tx,
	.conf_tx		= wfx_conf_tx,
	.hw_scan		= wfx_hw_scan,
	.sta_add		= wfx_sta_add,
	.sta_remove		= wfx_sta_remove,
	.sta_notify		= wfx_sta_notify,
	.set_tim		= wfx_set_tim,
	.set_key		= wfx_set_key,
	.set_rts_threshold	= wfx_set_rts_threshold,
	.bss_info_changed	= wfx_bss_info_changed,
	.prepare_multicast	= wfx_prepare_multicast,
	.configure_filter	= wfx_configure_filter,
	.get_stats		= wfx_get_stats,
	.ampdu_action		= wfx_ampdu_action,
	.flush			= wfx_flush,
	.add_chanctx		= wfx_add_chanctx,
	.remove_chanctx		= wfx_remove_chanctx,
	.change_chanctx		= wfx_change_chanctx,
	.assign_vif_chanctx	= wfx_assign_vif_chanctx,
	.unassign_vif_chanctx	= wfx_unassign_vif_chanctx,
};

bool wfx_api_older_than(struct wfx_dev *wdev, int major, int minor)
{
	if (wdev->wsm_caps.ApiVersionMajor < major)
		return true;
	if (wdev->wsm_caps.ApiVersionMajor > major)
		return false;
	if (wdev->wsm_caps.ApiVersionMinor < minor)
		return true;
	return false;
}

struct gpio_desc *wfx_get_gpio(struct device *dev, int override, const char *label)
{
	struct gpio_desc *ret;
	char label_buf[256];

	if (override >= 0) {
		snprintf(label_buf, sizeof(label_buf), "wfx_%s", label);
		ret = ERR_PTR(devm_gpio_request_one(dev, override, GPIOF_OUT_INIT_LOW, label_buf));
		if (!ret)
			ret = gpio_to_desc(override);
	} else if (override == -1) {
		ret = NULL;
	} else {
		ret = devm_gpiod_get(dev, label, GPIOD_OUT_LOW);
	}
	if (IS_ERR(ret) || !ret) {
		if (!ret || PTR_ERR(ret) == -ENOENT)
			dev_warn(dev, "gpio %s is not defined", label);
		else
			dev_warn(dev, "error while requesting gpio %s", label);
		ret = NULL;
	} else {
		dev_dbg(dev, "using gpio %d for %s", desc_to_gpio(ret), label);
	}
	return ret;
}

static void wfx_fill_sl_key(struct device *dev, struct wfx_platform_data *pdata)
{
	const char *ascii_key = NULL;
	int ret = 0;

	if (slk_key)
		ascii_key = slk_key;
	if (!ascii_key)
		ret = of_property_read_string(dev->of_node, "slk_key", &ascii_key);
	if (ret == -EILSEQ || ret == -ENODATA)
		dev_err(dev, "ignoring malformatted key from DT\n");
	if (!ascii_key)
		return;

	ret = hex2bin(pdata->slk_key, ascii_key, sizeof(pdata->slk_key));
	if (ret) {
		dev_err(dev, "ignoring malformatted key: %s\n", ascii_key);
		memset(pdata->slk_key, 0, sizeof(pdata->slk_key));
		return;
	}
#ifndef CONFIG_WFX_SECURE_LINK
	dev_err(dev, "secure link is not supported by this driver, ignoring provided key\n");
#endif
}

struct wfx_dev *wfx_init_common(struct device *dev,
				const struct wfx_platform_data *pdata,
				const struct hwbus_ops *hwbus_ops,
				void *hwbus_priv)
{
	int i;
	struct ieee80211_hw *hw;
	struct wfx_dev *wdev;

	hw = ieee80211_alloc_hw(sizeof(struct wfx_dev), &wfx_ops);
	if (!hw)
		return NULL;

	SET_IEEE80211_DEV(hw, dev);

	ieee80211_hw_set(hw, NEED_DTIM_BEFORE_ASSOC);
	ieee80211_hw_set(hw, TX_AMPDU_SETUP_IN_HW);
	ieee80211_hw_set(hw, AMPDU_AGGREGATION);
	ieee80211_hw_set(hw, CONNECTION_MONITOR);
	ieee80211_hw_set(hw, REPORTS_TX_ACK_STATUS);
	ieee80211_hw_set(hw, SUPPORTS_DYNAMIC_PS);
	ieee80211_hw_set(hw, SIGNAL_DBM);
	ieee80211_hw_set(hw, SUPPORTS_PS);
	ieee80211_hw_set(hw, MFP_CAPABLE);
#if (KERNEL_VERSION(3, 19, 0) > LINUX_VERSION_CODE)
	ieee80211_hw_set(hw, SUPPORTS_UAPSD);
#endif

	hw->vif_data_size = sizeof(struct wfx_vif);
	hw->sta_data_size = sizeof(struct wfx_sta_priv);
	hw->queues = 4;
	hw->max_rates = 8;
	hw->max_rate_tries = 15;
	hw->extra_tx_headroom = WSM_TX_EXTRA_HEADROOM + 8;  /* TKIP IV */

	hw->wiphy->interface_modes = BIT(NL80211_IFTYPE_STATION) |
				     BIT(NL80211_IFTYPE_ADHOC) |
				     BIT(NL80211_IFTYPE_AP) |
				     BIT(NL80211_IFTYPE_MESH_POINT) |
				     BIT(NL80211_IFTYPE_P2P_CLIENT) |
				     BIT(NL80211_IFTYPE_P2P_GO);
	hw->wiphy->flags |= WIPHY_FLAG_AP_UAPSD;
	hw->wiphy->flags &= ~WIPHY_FLAG_PS_ON_BY_DEFAULT;
	hw->wiphy->max_scan_ssids = 2;
	hw->wiphy->max_scan_ie_len = IEEE80211_MAX_DATA_LEN;
	hw->wiphy->n_iface_combinations = ARRAY_SIZE(wfx_iface_combinations);
	hw->wiphy->iface_combinations = wfx_iface_combinations;
	hw->wiphy->bands[NL80211_BAND_2GHZ] = devm_kmalloc(dev, sizeof(wfx_band_2ghz), GFP_KERNEL);
	// FIXME: report OTP restriction here
	// FIXME: also copy wfx_rates and wfx_2ghz_chantable
	memcpy(hw->wiphy->bands[NL80211_BAND_2GHZ], &wfx_band_2ghz, sizeof(wfx_band_2ghz));

	wdev = hw->priv;
	wdev->hw = hw;
	wdev->dev = dev;
	wdev->hwbus_ops = hwbus_ops;
	wdev->hwbus_priv = hwbus_priv;
	wdev->rates = wfx_rates;
	wdev->mcs_rates = wfx_mcs_rates;
	memcpy(&wdev->pdata, pdata, sizeof(*pdata));
	of_property_read_string(dev->of_node, "config-file", &wdev->pdata.file_pds);
	wdev->pdata.gpio_wakeup = wfx_get_gpio(dev, gpio_wakeup, "wakeup");
	wfx_fill_sl_key(dev, &wdev->pdata);
	// LDPC support was not yet tested
	wdev->pdata.support_ldpc = false;

	init_completion(&wdev->firmware_ready);
	init_wsm_cmd(&wdev->wsm_cmd);
	mutex_init(&wdev->conf_mutex);
	mutex_init(&wdev->rx_stats_lock);

	if (wfx_queue_stats_init(&wdev->tx_queue_stats, WFX_LINK_ID_MAX,
				 wfx_skb_dtor, wdev)) {
		goto err1;
	}

	for (i = 0; i < 4; ++i)
		if (wfx_queue_init(&wdev->tx_queue[i], &wdev->tx_queue_stats,
				   i, 48, wfx_ttl[i]))
			goto err2;

	return wdev;
err2:
	for (i = 0; i < 4; ++i)
		wfx_queue_deinit(&wdev->tx_queue[i]);
	wfx_queue_stats_deinit(&wdev->tx_queue_stats);
err1:
	ieee80211_free_hw(hw);
	return NULL;
}

void wfx_free_common(struct wfx_dev *wdev)
{
	int i;

	mutex_destroy(&wdev->rx_stats_lock);
	mutex_destroy(&wdev->conf_mutex);
	for (i = 0; i < 4; ++i)
		wfx_queue_deinit(&wdev->tx_queue[i]);
	wfx_queue_stats_deinit(&wdev->tx_queue_stats);
	ieee80211_free_hw(wdev->hw);
}

int wfx_probe(struct wfx_dev *wdev)
{
	int i;
	int err;
	const void *macaddr;
	struct gpio_desc *gpio_saved = wdev->pdata.gpio_wakeup;

	// During first part of boot, gpio_wakeup cannot yet been used. So
	// prevent bh() to touch it.
	gpio_saved = wdev->pdata.gpio_wakeup;
	wdev->pdata.gpio_wakeup = NULL;

	wfx_bh_register(wdev);

	err = wfx_init_device(wdev);
	if (err)
		goto err2;

	err = wait_for_completion_interruptible_timeout(&wdev->firmware_ready, 10 * HZ);
	if (err <= 0) {
		if (err == 0) {
			dev_err(wdev->dev, "timeout while waiting for startup indication. IRQ configuration error?\n");
			err = -ETIMEDOUT;
		} else if (err == -ERESTARTSYS) {
			dev_info(wdev->dev, "probe interrupted by user\n");
		}
		goto err2;
	}

	// FIXME: fill wiphy::fw_version and wiphy::hw_version
	dev_info(wdev->dev, "Firmware \"%s\" started. Version: %d.%d.%d API: %d.%d Keyset: %02X caps: 0x%.8X\n",
		 wdev->wsm_caps.FirmwareLabel, wdev->wsm_caps.FirmwareMajor,
		 wdev->wsm_caps.FirmwareMinor, wdev->wsm_caps.FirmwareBuild,
		 wdev->wsm_caps.ApiVersionMajor, wdev->wsm_caps.ApiVersionMinor,
		 wdev->keyset, *((u32 *) &wdev->wsm_caps.Capabilities));
	strncpy(wdev->hw->wiphy->fw_version, wdev->wsm_caps.FirmwareLabel, sizeof(wdev->hw->wiphy->fw_version));

	if (wfx_api_older_than(wdev, 1, 0)) {
		dev_err(wdev->dev, "Unsupported firmware API version (expect 1 while firmware returns %d)\n",
			wdev->wsm_caps.ApiVersionMajor);
		goto err2;
	}

	err = wfx_sl_init(wdev);
	if (err && wdev->wsm_caps.Capabilities.LinkMode == SEC_LINK_ENFORCED) {
		dev_err(wdev->dev, "chip require secure_link, but can't negociate it\n");
		goto err2;
	}

	// Current firmware does not support high throughput TX encrypted buffers
	if (wfx_is_secure_command(wdev, WSM_HI_TX_REQ_ID))
		wdev->wsm_caps.NumInpChBufs = 2;

	if (wdev->wsm_caps.RegulSelModeInfo.RegionSelMode) {
		wdev->hw->wiphy->bands[NL80211_BAND_2GHZ]->channels[11].flags |= IEEE80211_CHAN_NO_IR;
		wdev->hw->wiphy->bands[NL80211_BAND_2GHZ]->channels[12].flags |= IEEE80211_CHAN_NO_IR;
		wdev->hw->wiphy->bands[NL80211_BAND_2GHZ]->channels[13].flags |= IEEE80211_CHAN_DISABLED;
	}

	dev_dbg(wdev->dev, "sending configuration file %s", wdev->pdata.file_pds);
	err = wfx_send_pdata_pds(wdev);
	if (err < 0)
		goto err2;

	wdev->pdata.gpio_wakeup = gpio_saved;
	if (wdev->pdata.gpio_wakeup) {
		dev_dbg(wdev->dev, "enable 'quiescent' power mode with gpio %d and PDS file %s\n",
			desc_to_gpio(wdev->pdata.gpio_wakeup), wdev->pdata.file_pds);
		gpiod_set_value(wdev->pdata.gpio_wakeup, 1);
		control_reg_write(wdev, 0);
		wsm_set_operational_mode(wdev, WSM_OP_POWER_MODE_QUIESCENT);
	} else {
		wsm_set_operational_mode(wdev, WSM_OP_POWER_MODE_DOZE);
	}

	wsm_use_multi_tx_conf(wdev, true);

	for (i = 0; i < ARRAY_SIZE(wdev->addresses); i++) {
		eth_zero_addr(wdev->addresses[i].addr);
		macaddr = of_get_mac_address(wdev->dev->of_node);
		if (macaddr) {
			ether_addr_copy(wdev->addresses[i].addr, macaddr);
			wdev->addresses[i].addr[ETH_ALEN - 1] += i;
		}
		ether_addr_copy(wdev->addresses[i].addr, wdev->wsm_caps.MacAddr[i]);
		if (!is_valid_ether_addr(wdev->addresses[i].addr)) {
			dev_warn(wdev->dev, "using random MAC address\n");
			eth_random_addr(wdev->addresses[i].addr);
		}
		dev_info(wdev->dev, "MAC address %d: %pM\n", i, wdev->addresses[i].addr);
	}
	wdev->hw->wiphy->n_addresses = ARRAY_SIZE(wdev->addresses);
	wdev->hw->wiphy->addresses = wdev->addresses;

	err = ieee80211_register_hw(wdev->hw);
	if (err)
		goto err2;

	err = wfx_debug_init(wdev);
	if (err)
		goto err3;

	return 0;

err3:
	ieee80211_unregister_hw(wdev->hw);
err2:
	wfx_bh_unregister(wdev);
	return err;
}

void wfx_release(struct wfx_dev *wdev)
{
	ieee80211_unregister_hw(wdev->hw);
	wsm_shutdown(wdev);
	wfx_bh_unregister(wdev);
	wfx_sl_deinit(wdev);
}

extern struct sdio_driver wfx_sdio_driver;
extern struct spi_driver wfx_spi_driver;
static int __init wfx_core_init(void)
{
	int ret = 0;

	pr_info("wfx: Silicon Labs " WFX_LABEL "\n");

	if (IS_ENABLED(CONFIG_SPI))
		ret = spi_register_driver(&wfx_spi_driver);
	if (IS_ENABLED(CONFIG_MMC) && !ret)
		ret = sdio_register_driver(&wfx_sdio_driver);
	return ret;
}
module_init(wfx_core_init);

static void __exit wfx_core_exit(void)
{
	if (IS_ENABLED(CONFIG_MMC))
		sdio_unregister_driver(&wfx_sdio_driver);
	if (IS_ENABLED(CONFIG_SPI))
		spi_unregister_driver(&wfx_spi_driver);
}
module_exit(wfx_core_exit);
