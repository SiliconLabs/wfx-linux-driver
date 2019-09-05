// SPDX-License-Identifier: GPL-2.0-only
/*
 * Debugfs interface.
 *
 * Copyright (c) 2017-2019, Silicon Laboratories, Inc.
 * Copyright (c) 2010, ST-Ericsson
 */
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/version.h>
#include <linux/crc32.h>

#if (KERNEL_VERSION(4, 17, 0) > LINUX_VERSION_CODE)
#define DEFINE_SHOW_ATTRIBUTE(__name)					\
static int __name ## _open(struct inode *inode, struct file *file)	\
{									\
	return single_open(file, __name ## _show, inode->i_private);	\
}									\
									\
static const struct file_operations __name ## _fops = {			\
	.owner		= THIS_MODULE,					\
	.open		= __name ## _open,				\
	.read		= seq_read,					\
	.llseek		= seq_lseek,					\
	.release	= single_release,				\
}
#endif

#include "debug.h"
#include "wfx.h"
#include "wsm_tx.h"
#include "sta.h"

#define CREATE_TRACE_POINTS
#include "traces.h"

static const struct trace_print_flags wsm_msg_print_map[] = {
	wsm_msg_list,
};

static const struct trace_print_flags wsm_mib_print_map[] = {
	wsm_mib_list,
};

static const struct trace_print_flags wfx_reg_print_map[] = {
	wfx_reg_list,
};

static const struct trace_print_flags wfx_fw_types_print_map[] = {
	{  0, "ETF" },
	{  1, "WFM" },
	{  2, "WSM" },
	{  3, "HI test" },
	{  4, "Platform test" },
	{ -1, NULL }
};

static const char *get_symbol(unsigned long val,
		const struct trace_print_flags *symbol_array)
{
	int i;

	for (i = 0; symbol_array[i].mask != -1; i++) {
		if (val == symbol_array[i].mask)
			return symbol_array[i].name;
	}

	return "unknown";
}

const char *get_wsm_name(unsigned long id)
{
	return get_symbol(id, wsm_msg_print_map);
}

const char *get_mib_name(unsigned long id)
{
	return get_symbol(id, wsm_mib_print_map);
}

const char *get_reg_name(unsigned long id)
{
	return get_symbol(id, wfx_reg_print_map);
}

const char *get_fw_type(unsigned long id)
{
	return get_symbol(id, wfx_fw_types_print_map);
}

/* state */
static const char * const wfx_debug_state[] = {
	"passive",
	"monitor",
	"station (joining)",
	"station (not authenticated yet)",
	"station",
	"adhoc",
	"access point",
};

static const char * const wfx_debug_preamble[] = {
	"long",
	"short",
	"long on 1 and 2 Mbps",
};

static const char * const wfx_debug_link_id[] = {
	"OFF",
	"REQ",
	"SOFT",
	"HARD",
	"RESET",
	"RESET_REMAP",
};

static const char *wfx_debug_mode(int mode)
{
	switch (mode) {
	case NL80211_IFTYPE_UNSPECIFIED:
		return "unspecified";
	case NL80211_IFTYPE_MONITOR:
		return "monitor";
	case NL80211_IFTYPE_STATION:
		return "station";
	case NL80211_IFTYPE_ADHOC:
		return "adhoc";
	case NL80211_IFTYPE_AP:
		return "access point";
	default:
		return "unsupported";
	}
}

static void wfx_queue_status_show(struct seq_file *seq,
				     struct wfx_queue *q)
{
	int i;

	seq_printf(seq, "Queue       %d:\n", q->queue_id);
	seq_printf(seq, "  queued:   %u\n", skb_queue_len(&q->queue));
	seq_printf(seq, "  locked:   %s\n", q->tx_locked_cnt ? "yes" : "no");
	seq_puts(seq,   "  link map: 0-> ");
	for (i = 0; i < ARRAY_SIZE(q->link_map_cache); ++i)
		seq_printf(seq, "%.2d ", q->link_map_cache[i]);
	seq_printf(seq, "<-%zu\n", ARRAY_SIZE(q->link_map_cache));
}

static void wfx_debug_print_map(struct seq_file *seq,
				struct wfx_dev	*wdev,
				   const char *label,
				   u32 map)
{
	int i;

	seq_printf(seq, "%s0-> ", label);
	for (i = 0; i < ARRAY_SIZE(wdev->tx_queue_stats.link_map_cache); ++i)
		seq_printf(seq, "%s ", (map & BIT(i)) ? "**" : "..");
	seq_printf(seq, "<-%zu\n", ARRAY_SIZE(wdev->tx_queue_stats.link_map_cache) - 1);
}

static int wfx_status_show(struct seq_file *seq, void *v)
{
	int i;
	struct list_head *item;
	struct wfx_dev *wdev = seq->private;
	// FIXME: wfx_status_show should be local to one interface
	struct wfx_vif *wvif = wdev_to_wvif(wdev, 0);
	struct wfx_debug_priv *d = wdev->debug;
	u32 *p_Capa = (u32 *)&wdev->wsm_caps.capabilities;

	WARN_ON(!wvif);
	seq_puts(seq,
		 "status of Linux Wireless network device drivers for Siliconlabs WFx unit\n");
	seq_printf(seq, "Firmware:   %s %d %d.%d\n",
		   get_fw_type(wdev->wsm_caps.firmware_type),
		   wdev->wsm_caps.firmware_major,
		   wdev->wsm_caps.firmware_minor,
		   wdev->wsm_caps.firmware_build);
	seq_printf(seq, "FW caps:    0x%.8X\n",
		   *p_Capa);
	seq_printf(seq, "FW label:  '%s'\n",
		   wdev->wsm_caps.firmware_label);
	seq_printf(seq, "Keyset:     0x%02X\n",
		   wdev->keyset);
	seq_printf(seq, "Power mode: %d\n",
		   wdev->pdata.gpio_wakeup ? 2 : 1);
	if (!wvif)
		return 0;

	seq_printf(seq, "Mode:       %s\n",
		   wfx_debug_mode(wvif->vif->type));
	seq_printf(seq, "Join state: %s\n",
		   wfx_debug_state[wvif->state]);
	seq_printf(seq, "Channel:    %d\n",
		   wvif->channel ? wvif->channel->hw_value : -1);

	if (wvif->filter_bssid)
		seq_puts(seq, "Filter:     bssid\n");
	if (wvif->filter_probe_resp)
		seq_puts(seq, "Filter:     probeResponder\n");

	if (!wvif->disable_beacon_filter)
		seq_puts(seq, "Filter:     beacons\n");

	if (wvif->enable_beacon ||
	    wvif->vif->type == NL80211_IFTYPE_AP ||
	    wvif->vif->type == NL80211_IFTYPE_ADHOC)
		seq_printf(seq, "Beaconing:  %s\n",
			   wvif->enable_beacon ? "enabled" : "disabled");

	for (i = 0; i < IEEE80211_NUM_ACS; ++i)
		seq_printf(seq, "EDCA(%d):    %d, %d, %d, %d\n", i,
			   wvif->edca.params[i].cw_min,
			   wvif->edca.params[i].cw_max,
			   wvif->edca.params[i].aifsn,
			   wvif->edca.params[i].tx_op_limit);

	if (wvif->state == WFX_STATE_STA) {
		seq_printf(seq, "Preamble:   %s\n",
			   wvif->vif->bss_conf.use_short_preamble ? "short" : "long");
		seq_printf(seq, "AMPDU spcn: %d\n",
			   wfx_ht_ampdu_density(&wvif->ht_info));
		seq_printf(seq, "Bss lost:   %d beacons\n",
			   wvif->bss_params.bss_flags.lost_count_only);
		seq_printf(seq, "AID:        %d\n",
			   wvif->bss_params.aid);
		seq_printf(seq, "Rates:      0x%.8X\n",
			   wvif->bss_params.operational_rate_set);
		seq_printf(seq, "Powersave WiFi:  ");
		if (wvif->powersave_mode.pm_mode.enter_psm)
			if (wvif->powersave_mode.pm_mode.fast_psm)
				seq_puts(seq, "dynamic\n");
			else
				seq_puts(seq, "on\n");
		else
			seq_puts(seq, "off\n");
	}

	seq_printf(seq, "HT:         %s\n",
		   wfx_is_ht(&wvif->ht_info) ? "on" : "off");

	if (wfx_is_ht(&wvif->ht_info)) {
		seq_printf(seq, "Greenfield: %s\n",
			   wfx_ht_greenfield(&wvif->ht_info) ? "yes" : "no");
		seq_printf(seq, "LDPC: %s\n",
			   wfx_ht_fecCoding(&wvif->ht_info) ? "yes" : "no");
		seq_printf(seq, "SGI: %s\n",
			   wfx_ht_shortGi(&wvif->ht_info) ? "yes" : "no");
		seq_printf(seq, "AMPDU dens: %d\n",
			   wfx_ht_ampdu_density(&wvif->ht_info));
	}

	seq_printf(seq, "RSSI thold: %d\n",
		   wvif->cqm_rssi_thold);
	spin_lock_bh(&wvif->tx_policy_cache.lock);
	i = 0;
	list_for_each(item, &wvif->tx_policy_cache.used)
		++i;
	spin_unlock_bh(&wvif->tx_policy_cache.lock);
	seq_printf(seq, "RC in use:  %d\n", i);

	seq_puts(seq, "\n");
	seq_printf(seq, "TX bufs:    %d x %d bytes\n",
		   wdev->wsm_caps.num_inp_ch_bufs,
		   wdev->wsm_caps.size_inp_ch_buf);
	seq_printf(seq, "Used bufs:  %d\n",
		   wdev->hif.tx_buffers_used);
	seq_printf(seq, "Device:     %s\n",
		   gpiod_get_value(wdev->pdata.gpio_wakeup) ? "awake" : "asleep");

	seq_printf(seq, "Datapath:   %s\n",
		   atomic_read(&wdev->tx_lock) ? "locked" : "unlocked");
	if (atomic_read(&wdev->tx_lock))
		seq_printf(seq, "TXlock cnt: %d\n",
			   atomic_read(&wdev->tx_lock));

	seq_printf(seq, "TXed:       %d\n",
		   d->tx);
	seq_printf(seq, "AGG TXed:   %d\n",
		   d->tx_agg);
	seq_printf(seq, "MULTI TXed: %d (%d)\n",
		   d->tx_multi, d->tx_multi_frames);
	seq_printf(seq, "RXed:       %d\n",
		   d->rx);
	seq_printf(seq, "AGG RXed:   %d\n",
		   d->rx_agg);
	seq_printf(seq, "TX miss:    %d\n",
		   d->tx_cache_miss);
	seq_printf(seq, "TX align:   %d\n",
		   d->tx_align);
	seq_printf(seq, "TX burst:   %d\n",
		   d->tx_burst);
	seq_printf(seq, "Scan:       %s\n",
		   atomic_read(&wvif->scan.in_progress) ? "active" : "idle");

	seq_puts(seq, "\n");
	for (i = 0; i < IEEE80211_NUM_ACS; ++i) {
		wfx_queue_status_show(seq, &wdev->tx_queue[i]);
		seq_puts(seq, "\n");
	}

	wfx_debug_print_map(seq, wdev, "Link map:   ",
			    wvif->link_id_map);
	wfx_debug_print_map(seq, wdev, "Asleep map: ",
			    wvif->sta_asleep_mask);
	wfx_debug_print_map(seq, wdev, "PSPOLL map: ",
			    wvif->pspoll_mask);

	seq_puts(seq, "\n");

	for (i = 0; i < WFX_MAX_STA_IN_AP_MODE; ++i) {
		if (wvif->link_id_db[i].status) {
			seq_printf(seq, "Link %d:     %s, %pM\n",
				   i + 1,
				   wfx_debug_link_id[wvif->link_id_db[i].status],
				   wvif->link_id_db[i].mac);
		}
	}

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(wfx_status);

static int wfx_counters_show(struct seq_file *seq, void *v)
{
	int ret;
	struct wfx_dev *wdev = seq->private;
	WsmHiMibExtendedCountTable_t counters;

	ret = wsm_get_counters_table(wdev, &counters, 0);
	if (ret < 0)
		return ret;
	if (ret > 0)
		return -EIO;

#define PUT_COUNTER(name) \
	seq_printf(seq, "%24s %d\n", #name ":", le32_to_cpu(counters.count_##name))

	PUT_COUNTER(tx_packets);
	PUT_COUNTER(tx_multicast_frames);
	PUT_COUNTER(tx_frames_success);
	PUT_COUNTER(tx_frame_failures);
	PUT_COUNTER(tx_frames_retried);
	PUT_COUNTER(tx_frames_multi_retried);

	PUT_COUNTER(rts_success);
	PUT_COUNTER(rts_failures);
	PUT_COUNTER(ack_failures);

	PUT_COUNTER(rx_packets);
	PUT_COUNTER(rx_frames_success);
	PUT_COUNTER(rx_packet_errors);
	PUT_COUNTER(plcp_errors);
	PUT_COUNTER(fcs_errors);
	PUT_COUNTER(rx_decryption_failures);
	PUT_COUNTER(rx_mic_failures);
	PUT_COUNTER(rx_no_key_failures);
	PUT_COUNTER(rx_frame_duplicates);
	PUT_COUNTER(rx_multicast_frames);
	PUT_COUNTER(rx_cmacicv_errors);
	PUT_COUNTER(rx_cmac_replays);
	PUT_COUNTER(rx_mgmt_ccmp_replays);

	PUT_COUNTER(rx_beacon);
	PUT_COUNTER(miss_beacon);

#undef PUT_COUNTER

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(wfx_counters);

static const char *channel_names[] = {
	[0] = "1M",
	[1] = "2M",
	[2] = "5.5M",
	[3] = "11M",
	/* Entries 4 and 5 does not exist */
	[6] = "6M",
	[7] = "9M",
	[8] = "12M",
	[9] = "18M",
	[10] = "24M",
	[11] = "36M",
	[12] = "48M",
	[13] = "54M",
	[14] = "MCS0",
	[15] = "MCS1",
	[16] = "MCS2",
	[17] = "MCS3",
	[18] = "MCS4",
	[19] = "MCS5",
	[20] = "MCS6",
	[21] = "MCS7",
};

static int wfx_rx_stats_show(struct seq_file *seq, void *v)
{
	struct wfx_dev *wdev = seq->private;
	HiRxStats_t *st = &wdev->rx_stats;
	int i;

	mutex_lock(&wdev->rx_stats_lock);
	seq_printf(seq, "Timestamp: %dus\n", st->date);
	seq_printf(seq, "Low power clock: frequency %uHz, external %s\n",
		st->pwr_clk_freq,
		st->is_ext_pwr_clk ? "yes" : "no");
	seq_printf(seq, "Num. of frames: %d, PER (x10e4): %d, Throughput: %dKbps/s\n",
		st->nb_rx_frame, st->per_total, st->throughput);
	seq_printf(seq, "       Num. of      PER     RSSI      SNR      CFO\n");
	seq_printf(seq, "        frames  (x10e4)    (dBm)     (dB)    (kHz)\n");
	for (i = 0; i < ARRAY_SIZE(channel_names); i++) {
		if (channel_names[i])
			seq_printf(seq, "%5s %8d %8d %8d %8d %8d\n",
				   channel_names[i], st->nb_rx_by_rate[i],
				   st->per[i], st->rssi[i] / 100,
				   st->snr[i] / 100, st->cfo[i]);
	}
	mutex_unlock(&wdev->rx_stats_lock);

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(wfx_rx_stats);

static ssize_t wfx_send_pds_write(struct file *file, const char __user *user_buf,
			     size_t count, loff_t *ppos)
{
	struct wfx_dev *wdev = file->private_data;
	char *buf;
	int ret;

	if (*ppos != 0) {
		dev_dbg(wdev->dev, "PDS data must be written in one transaction");
		return -EBUSY;
	}
	buf = memdup_user(user_buf, count);
	if (IS_ERR(buf))
		return PTR_ERR(buf);
	*ppos = *ppos + count;
	ret = wfx_send_pds(wdev, buf, count);
	kfree(buf);
	if (ret < 0)
		return ret;
	return count;
}

static const struct file_operations wfx_send_pds_fops = {
	.open = simple_open,
	.write = wfx_send_pds_write,
};

static ssize_t wfx_burn_slk_key_write(struct file *file, const char __user *user_buf,
			     size_t count, loff_t *ppos)
{
	struct wfx_dev *wdev = file->private_data;
	char bin_buf[API_KEY_VALUE_SIZE + 4];
	uint32_t *user_crc32 = (uint32_t *) (bin_buf + API_KEY_VALUE_SIZE);
	char ascii_buf[(API_KEY_VALUE_SIZE + 4) * 2];
	uint32_t crc32;
	int ret;

#ifndef CONFIG_WFX_SECURE_LINK
	dev_info(wdev->dev, "this driver does not support secure link\n");
	return -EINVAL;
#endif
	if (wdev->wsm_caps.capabilities.link_mode == SEC_LINK_ENFORCED) {
		dev_err(wdev->dev, "key was already burned on this device\n");
		return -EINVAL;
	}
	if (wdev->wsm_caps.capabilities.link_mode != SEC_LINK_EVAL) {
		dev_err(wdev->dev, "this device does not support secure link\n");
		return -EINVAL;
	}
	if (*ppos != 0) {
		dev_dbg(wdev->dev, "secret data must be written in one transaction\n");
		return -EBUSY;
	}
	*ppos = *ppos + count;

	ret = copy_from_user(ascii_buf, user_buf, min(count, sizeof(ascii_buf)));
	if (ret)
		return ret;
	ret = hex2bin(bin_buf, ascii_buf, sizeof(bin_buf));
	if (ret) {
		dev_info(wdev->dev, "ignoring malformatted key: %s\n", ascii_buf);
		return -EINVAL;
	}
	crc32 = crc32(0xffffffff, bin_buf, API_KEY_VALUE_SIZE) ^ 0xffffffff;
	if (crc32 != *user_crc32) {
		dev_err(wdev->dev, "incorrect crc32: %08x != %08x\n", crc32, *user_crc32);
		return -EINVAL;
	}
	ret = wsm_set_mac_key(wdev, bin_buf, SL_MAC_KEY_DEST_OTP);
	if (ret) {
		dev_err(wdev->dev, "chip returned error %d\n", ret);
		return -EIO;
	}
	return count;
}

static const struct file_operations wfx_burn_slk_key_fops = {
	.open = simple_open,
	.write = wfx_burn_slk_key_write,
};

struct dbgfs_hif_msg {
	struct wfx_dev *wdev;
	struct completion complete;
	u8 reply[1024];
	int ret;
};

static ssize_t wfx_send_hif_msg_write(struct file *file, const char __user *user_buf,
				      size_t count, loff_t *ppos)
{
	struct dbgfs_hif_msg *context = file->private_data;
	struct wfx_dev *wdev = context->wdev;
	struct wmsg *request;

	if (completion_done(&context->complete)) {
		dev_dbg(wdev->dev, "read previous result before start a new one\n");
		return -EBUSY;
	}
	if (count < sizeof(struct wmsg))
		return -EINVAL;

	// wfx_cmd_send() chekc that reply buffer is wide enough, but do not
	// return precise length read. User have to know how many bytes should
	// be read. Filling reply buffer with a memory pattern may help user.
	memset(context->reply, sizeof(context->reply), 0xFF);
	request = memdup_user(user_buf, count);
	if (IS_ERR(request))
		return PTR_ERR(request);
	if (request->len != count) {
		kfree(request);
		return -EINVAL;
	}
	context->ret = wfx_cmd_send(wdev, request, context->reply, sizeof(context->reply), false);

	kfree(request);
	complete(&context->complete);
	return count;
}

static ssize_t wfx_send_hif_msg_read(struct file *file, char __user *user_buf,
				     size_t count, loff_t *ppos)
{
	struct dbgfs_hif_msg *context = file->private_data;
	int ret;

	if (count > sizeof(context->reply))
		return -EINVAL;
	ret = wait_for_completion_interruptible(&context->complete);
	if (ret)
		return ret;
	if (context->ret < 0)
		return context->ret;
	// Be carefull, write() is waiting for a full message while read()
	// only return a payload
	ret = copy_to_user(user_buf, context->reply, count);
	if (ret)
		return ret;

	return count;
}

static int wfx_send_hif_msg_open(struct inode *inode, struct file *file)
{
	struct dbgfs_hif_msg *context = kzalloc(sizeof(*context), GFP_KERNEL);

	if (!context)
		return -ENOMEM;
	context->wdev = inode->i_private;
	init_completion(&context->complete);
	file->private_data = context;
	return 0;
}

static int wfx_send_hif_msg_release(struct inode *inode, struct file *file)
{
	struct dbgfs_hif_msg *context = file->private_data;

	kfree(context);
	return 0;
}

static const struct file_operations wfx_send_hif_msg_fops = {
	.open = wfx_send_hif_msg_open,
	.release = wfx_send_hif_msg_release,
	.write = wfx_send_hif_msg_write,
	.read = wfx_send_hif_msg_read,
};

int wfx_debug_init(struct wfx_dev *wdev)
{
	struct dentry *d;

	wdev->debug = devm_kzalloc(wdev->dev, sizeof(*wdev->debug), GFP_KERNEL);
	if (!wdev->debug)
		return -ENOMEM;

	d = debugfs_create_dir("wfx", wdev->hw->wiphy->debugfsdir);
	debugfs_create_file("status", 0444, d, wdev, &wfx_status_fops);
	debugfs_create_file("counters", 0444, d, wdev, &wfx_counters_fops);
	debugfs_create_file("rx_stats", 0444, d, wdev, &wfx_rx_stats_fops);
	debugfs_create_file("send_pds", 0200, d, wdev, &wfx_send_pds_fops);
	debugfs_create_file("burn_slk_key", 0200, d, wdev, &wfx_burn_slk_key_fops);
	debugfs_create_file("send_hif_msg", 0600, d, wdev, &wfx_send_hif_msg_fops);

	return 0;
}

