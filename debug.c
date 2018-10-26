/*
 * mac80211 glue code for mac80211 Silicon Labs WFX drivers DebugFS code
 *
 * Copyright (c) 2017, Silicon Laboratories, Inc.
 * Copyright (c) 2010, ST-Ericsson
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

#include <linux/debugfs.h>
#include <linux/seq_file.h>

#include "debug.h"
#include "wfx.h"
#include "sta.h"

#define CREATE_TRACE_POINTS
#include "traces.h"

static const struct trace_print_flags wsm_msg_print_map[] = {
	wsm_msg_list,
	{ -1, NULL }
};

static const struct trace_print_flags wsm_mib_print_map[] = {
	wsm_mib_list,
	{ -1, NULL }
};

static const struct trace_print_flags wfx_reg_print_map[] = {
	wfx_reg_list,
	{ -1, NULL }
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

	for (i = 0;  symbol_array[i].name; i++) {
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

/* join_status */
static const char * const wfx_debug_join_status[] = {
	"passive",
	"monitor",
	"station (joining)",
	"station (not authenticated yet)",
	"station",
	"adhoc",
	"access point",
};

/* WSM_JOIN_PREAMBLE */
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
	case NL80211_IFTYPE_MESH_POINT:
		return "mesh point";
	case NL80211_IFTYPE_AP:
		return "access point";
	case NL80211_IFTYPE_P2P_CLIENT:
		return "p2p client";
	case NL80211_IFTYPE_P2P_GO:
		return "p2p go";
	default:
		return "unsupported";
	}
}

static void wfx_queue_status_show(struct seq_file *seq,
				     struct wfx_queue *q)
{
	int i;

	seq_printf(seq, "Queue       %d:\n", q->queue_id);
	seq_printf(seq, "  capacity: %zu\n", q->capacity);
	seq_printf(seq, "  queued:   %zu\n", q->num_queued);
	seq_printf(seq, "  pending:  %zu\n", q->num_pending);
	seq_printf(seq, "  sent:     %zu\n", q->num_sent);
	seq_printf(seq, "  locked:   %s\n", q->tx_locked_cnt ? "yes" : "no");
	seq_printf(seq, "  overfull: %s\n", q->overfull ? "yes" : "no");
	seq_puts(seq,   "  link map: 0-> ");
	for (i = 0; i < q->stats->map_capacity; ++i)
		seq_printf(seq, "%.2d ", q->link_map_cache[i]);
	seq_printf(seq, "<-%zu\n", q->stats->map_capacity);
}

static void wfx_debug_print_map(struct seq_file *seq,
				struct wfx_dev	*wdev,
				   const char *label,
				   u32 map)
{
	int i;

	seq_printf(seq, "%s0-> ", label);
	for (i = 0; i < wdev->tx_queue_stats.map_capacity; ++i)
		seq_printf(seq, "%s ", (map & BIT(i)) ? "**" : "..");
	seq_printf(seq, "<-%zu\n", wdev->tx_queue_stats.map_capacity - 1);
}

static int wfx_status_show(struct seq_file *seq, void *v)
{
	int i;
	struct list_head *item;
	struct wfx_dev *wdev = seq->private;
	// FIXME: wfx_status_show should be local to one interface
	struct wfx_vif *wvif = wdev_to_wvif(wdev, 0);
	struct wfx_debug_priv *d = wdev->debug;
	uint32_t *p_Capa = (uint32_t *)&wdev->wsm_caps.Capabilities;

	seq_puts(seq,
		 "Status of Linux Wireless network device drivers for Siliconlabs WFx unit\n");
	seq_printf(seq, "Firmware:   %s %d %d.%d\n",
		   get_fw_type(wdev->wsm_caps.FirmwareType),
		   wdev->wsm_caps.FirmwareMajor,
		   wdev->wsm_caps.FirmwareMinor,
		   wdev->wsm_caps.FirmwareBuild);
	seq_printf(seq, "FW caps:    0x%.8X\n",
		   *p_Capa);
	seq_printf(seq, "FW label:  '%s'\n",
		   wdev->wsm_caps.FirmwareLabel);
	seq_printf(seq, "Mode:       %s%s\n",
		   wfx_debug_mode(wvif->mode),
		   wvif->listening ? " (listening)" : "");
	seq_printf(seq, "Join state: %s\n",
		   wfx_debug_join_status[wvif->join_status]);

	if (wdev->channel) {
		seq_printf(seq, "Channel:    %d%s\n",
			   wdev->channel->hw_value,
			   wdev->channel_switch_in_progress ?
			   " (switching)" : "");
	}

	if (wvif->rx_filter.promiscuous)
		seq_puts(seq,   "Filter:     promisc\n");
	else if (wvif->rx_filter.fcs)
		seq_puts(seq,   "Filter:     fcs\n");

	if (wvif->rx_filter.bssid)
		seq_puts(seq,   "Filter:     bssid\n");

	if (!wvif->disable_beacon_filter)
		seq_puts(seq,   "Filter:     beacons\n");

	if (wvif->enable_beacon ||
	    wvif->mode == NL80211_IFTYPE_AP ||
	    wvif->mode == NL80211_IFTYPE_ADHOC ||
	    wvif->mode == NL80211_IFTYPE_MESH_POINT ||
	    wvif->mode == NL80211_IFTYPE_P2P_GO)
		seq_printf(seq, "Beaconing:  %s\n",
			   wvif->enable_beacon ?
			   "enabled" : "disabled");

	for (i = 0; i < 4; ++i)
		seq_printf(seq, "EDCA(%d):    %d, %d, %d, %d, %d\n", i,
			   wvif->edca.params.CwMin[i],
			   wvif->edca.params.CwMax[i],
			   wvif->edca.params.AIFSN[i],
			   wvif->edca.params.TxOpLimit[i],
			   wvif->edca.params.MaxReceiveLifetime[i]);

	if (wvif->join_status == WFX_JOIN_STATUS_STA) {
		static const char *pm_mode = "unknown";

		switch (wvif->powersave_mode.PmMode.PmMode) {
		case 0:
			pm_mode = "off";
			break;
		case 1:
			if (wvif->powersave_mode.PmMode.FastPsm)
				pm_mode = "dynamic";
			else
				pm_mode = "on";
			break;
		}
		seq_printf(seq, "Preamble:   %s\n",
			   wfx_debug_preamble[wvif->association_mode.PreambleType]);
		seq_printf(seq, "AMPDU spcn: %d\n",
			   wvif->association_mode.MpduStartSpacing);
		seq_printf(seq, "Basic rate: 0x%.8X\n",
			   le32_to_cpu(wvif->association_mode.BasicRateSet));
		seq_printf(seq, "Bss lost:   %d beacons\n",
			   wvif->bss_params.BssFlags.LostCountOnly);
		seq_printf(seq, "AID:        %d\n",
			   wvif->bss_params.AID);
		seq_printf(seq, "Rates:      0x%.8X\n",
			   wvif->bss_params.OperationalRateSet);
		seq_printf(seq, "Powersave WiFi:  %s\n", pm_mode);
	}

	seq_printf(seq, "HT:         %s\n",
		   wfx_is_ht(&wdev->ht_info) ? "on" : "off");

	if (wfx_is_ht(&wdev->ht_info)) {
		seq_printf(seq, "Greenfield: %s\n",
			   wfx_ht_greenfield(&wdev->ht_info) ? "yes" : "no");
		seq_printf(seq, "LDPC: %s\n",
			   wfx_ht_fecCoding(&wdev->ht_info) ? "yes" : "no");
		seq_printf(seq, "SGI: %s\n",
			   wfx_ht_shortGi(&wdev->ht_info) ? "yes" : "no");
		seq_printf(seq, "AMPDU dens: %d\n",
			   wfx_ht_ampdu_density(&wdev->ht_info));
	}

	seq_printf(seq, "RSSI thold: %d\n",
		   wvif->cqm_rssi_thold);
	seq_printf(seq, "RSSI hyst:  %d\n",
		   wvif->cqm_rssi_hyst);
	seq_printf(seq, "Long retr:  %d\n",
		   wdev->long_frame_max_tx_count);
	seq_printf(seq, "Short retr: %d\n",
		   wdev->short_frame_max_tx_count);
	spin_lock_bh(&wdev->tx_policy_cache.lock);
	i = 0;
	list_for_each(item, &wdev->tx_policy_cache.used)
		++i;
	spin_unlock_bh(&wdev->tx_policy_cache.lock);
	seq_printf(seq, "RC in use:  %d\n", i);

	seq_puts(seq, "\n");
	seq_printf(seq, "Bus Handler (BH) status:  %s\n",
		   atomic_read(&wdev->bh_term) ? "terminated" : "alive");
	seq_printf(seq, "Pending IRQ: %d\n",
		   atomic_read(&wdev->bh_rx));
	seq_printf(seq, "Pending TX: %d\n",
		   atomic_read(&wdev->bh_tx));
	if (wdev->bh_error)
		seq_printf(seq, "BH errcode: %d\n",
			   wdev->bh_error);
	seq_printf(seq, "TX bufs:    %d x %d bytes\n",
		   wdev->wsm_caps.NumInpChBufs,
		   wdev->wsm_caps.SizeInpChBuf);
	seq_printf(seq, "Used bufs:  %d\n",
		   wdev->hw_bufs_used);
	seq_printf(seq, "Device:     %s\n",
		   atomic_read(&wdev->device_can_sleep) ? "asleep" : "awake");

	spin_lock(&wdev->wsm_cmd.lock);
	seq_printf(seq, "WSM status: %s\n",
		   wdev->wsm_cmd.done ? "idle" : "active");
	seq_printf(seq, "WSM cmd:    0x%.4X (%td bytes)\n",
		   wdev->wsm_cmd.cmd, wdev->wsm_cmd.len);
	seq_printf(seq, "WSM retval: %d\n",
		   wdev->wsm_cmd.ret);
	spin_unlock(&wdev->wsm_cmd.lock);

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
	seq_printf(seq, "TX TTL:     %d\n",
		   d->tx_ttl);
	seq_printf(seq, "Scan:       %s\n",
		   atomic_read(&wdev->scan.in_progress) ? "active" : "idle");

	seq_puts(seq, "\n");
	for (i = 0; i < 4; ++i) {
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

static int wfx_status_open(struct inode *inode, struct file *file)
{
	return single_open(file, &wfx_status_show,
		inode->i_private);
}

static const struct file_operations fops_status = {
	.open = wfx_status_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.owner = THIS_MODULE,
};

static int wfx_counters_show(struct seq_file *seq, void *v)
{
	int ret;
	struct wfx_dev *wdev = seq->private;
	struct wsm_mib_counters_table counters;

	ret = wsm_get_counters_table(wdev, &counters);
	if (ret)
		return ret;

#define PUT_COUNTER(name) \
	seq_printf(seq, "%24s %d\n", #name ":", le32_to_cpu(counters.name))

	PUT_COUNTER(plcp_errors);
	PUT_COUNTER(fcs_errors);
	PUT_COUNTER(tx_packets);
	PUT_COUNTER(rx_packets);
	PUT_COUNTER(rx_packet_errors);
	PUT_COUNTER(rx_decryption_failures);
	PUT_COUNTER(rx_mic_failures);
	PUT_COUNTER(rx_no_key_failures);
	PUT_COUNTER(tx_multicast_frames);
	PUT_COUNTER(tx_frames_success);
	PUT_COUNTER(tx_frame_failures);
	PUT_COUNTER(tx_frames_retried);
	PUT_COUNTER(tx_frames_multi_retried);
	PUT_COUNTER(rx_frame_duplicates);
	PUT_COUNTER(rts_success);
	PUT_COUNTER(rts_failures);
	PUT_COUNTER(ack_failures);
	PUT_COUNTER(rx_multicast_frames);
	PUT_COUNTER(rx_frames_success);
	PUT_COUNTER(rx_cmac_icv_errors);
	PUT_COUNTER(rx_cmac_replays);
	PUT_COUNTER(rx_mgmt_ccmp_replays);

#undef PUT_COUNTER

	return 0;
}

static int wfx_counters_open(struct inode *inode, struct file *file)
{
	return single_open(file, &wfx_counters_show,
		inode->i_private);
}

static const struct file_operations fops_counters = {
	.open = wfx_counters_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.owner = THIS_MODULE,
};

struct wfx_dbg_param {
	u16 filter_val;
	u8 data_size;
	u8 data_offset;
	u8 data_shift;
	const char *fs_name;
	u8 is_mib;
	u32 data_val;
	struct wfx_dev *wdev;
	struct list_head active_list;
};

const struct wfx_dbg_param wfx_dbg_params[] = {
	{ WSM_MIB_ID_BEACON_WAKEUP_PERIOD,  8,  8,  0, "wake_up_period_min", true },
	{ WSM_MIB_ID_BEACON_WAKEUP_PERIOD,  1,  9,  0, "receive_all_dtim",   true },
	{ WSM_MIB_ID_BEACON_WAKEUP_PERIOD, 16, 10,  0, "wake_up_period_max", true },
	{ WSM_MIB_ID_BLOCK_ACK_POLICY,      8,  8,  0, "ba_tx_tid_policy",   true },
	{ WSM_MIB_ID_BLOCK_ACK_POLICY,      8, 10,  0, "ba_rx_tid_policy",   true },
	{ WSM_HI_TX_REQ_ID,                 1, 20,  5, "sgi" },
	{ WSM_HI_TX_REQ_ID,                 1, 20,  4, "ldpc" },
};

static int wfx_dbg_param_set(void *data, u64 val)
{
	struct wfx_dbg_param *param = data;
	struct wfx_dev *wdev = param->wdev;
	int max_value = ((1 << param->data_size) - 1) << param->data_shift;

	if ((int) val == -1) {
		if (!list_empty(&param->active_list))
			list_del_init(&param->active_list);
	} else {
		if (val > max_value)
			return -ERANGE;
		param->data_val = (u32) val;
		if (list_empty(&param->active_list))
			list_add(&param->active_list, &wdev->debug->dbg_params_active);
	}
	return 0;
}

static int wfx_dbg_param_get(void *data, u64 *val)
{
	struct wfx_dbg_param *param = data;

	if (list_empty(&param->active_list))
		*val = (u64) -1;
	else
		*val = param->data_val;
	return 0;
}
#if (KERNEL_VERSION(4, 6, 0) <= LINUX_VERSION_CODE)
DEFINE_DEBUGFS_ATTRIBUTE(wfx_dbg_param_fops, wfx_dbg_param_get, wfx_dbg_param_set, "%lld\n");
#else
DEFINE_SIMPLE_ATTRIBUTE(wfx_dbg_param_fops, wfx_dbg_param_get, wfx_dbg_param_set, "%lld\n");
#endif

void wfx_dbg_filter_wsm(struct wfx_dev *wdev, void *buf)
{
	struct wfx_dbg_param *p;
	u32 data_mask, old_val;
	u32 *buf32 = buf;
	u16 *buf16 = buf;
	u8 *buf8 = buf;
	int match;

	// debugfs is created long time after device start to send data to chip
	if (!wdev->debug)
		return;
	list_for_each_entry(p, &wdev->debug->dbg_params_active, active_list) {
		match = 0;
		if (p->is_mib) {
			if ((buf16[1] & 0xFF) == WSM_HI_WRITE_MIB_REQ_ID && buf16[2] == p->filter_val)
				match = 1;
		} else {
			if ((buf16[1] & 0xFF) == p->filter_val)
				match = 1;
		}
		if (match) {
			if (p->data_size == 32) {
				old_val = buf32[p->data_offset / 4];
				buf32[p->data_offset / 4] = cpu_to_le32(p->data_val);
			} else if (p->data_size == 16) {
				old_val = buf16[p->data_offset / 2];
				buf16[p->data_offset / 2] = cpu_to_le16(p->data_val);
			} else {
				data_mask = ((1 << p->data_size) - 1) << p->data_shift;
				old_val = (buf8[p->data_offset] & data_mask) >> p->data_shift;
				buf8[p->data_offset] &= ~data_mask;
				buf8[p->data_offset] |= p->data_val << p->data_shift;
			}
			dev_dbg(wdev->pdev, "force parameter %s: %d -> %d\n", p->fs_name, old_val, p->data_val);
		}
	}
}

static ssize_t wfx_pds_write(struct file *file, const char __user *user_buf,
			     size_t count, loff_t *ppos)
{
	struct wfx_dev *wdev = file->private_data;
	char *buf;
	int ret;

	if (*ppos != 0) {
		dev_dbg(wdev->pdev, "PDS data must be written in one transaction");
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

static const struct file_operations fops_pds = {
	.open = simple_open,
	.write = wfx_pds_write,
};

int wfx_debug_init(struct wfx_dev *wdev)
{
	struct wfx_dbg_param *p;
	struct dentry *d;
	int i;

	wdev->debug = devm_kzalloc(wdev->pdev, sizeof(*wdev->debug), GFP_KERNEL);
	if (!wdev->debug)
		return -ENOMEM;

	d = debugfs_create_dir("wfx", wdev->hw->wiphy->debugfsdir);
	debugfs_create_file("status", 0400, d, wdev, &fops_status);
	debugfs_create_file("counters", 0400, d, wdev, &fops_counters);
	debugfs_create_file("send_pds", 0200, d, wdev, &fops_pds);

	d = debugfs_create_dir("wsm_params", d);
	INIT_LIST_HEAD(&wdev->debug->dbg_params_active);
	wdev->debug->dbg_params = devm_kmemdup(wdev->pdev, wfx_dbg_params, sizeof(wfx_dbg_params), GFP_KERNEL);
	for (i = 0; i < ARRAY_SIZE(wfx_dbg_params); i++) {
		p = &wdev->debug->dbg_params[i];
		if (p->is_mib)
			WARN(p->data_offset < 8, "Data overlap header");
		else
			WARN(p->data_offset < 4, "Data overlap header");
		if (p->data_size == 32)
			WARN(p->data_offset & 3, "Unaligned 32bit parameter");
		else if (p->data_size == 16)
			WARN(p->data_offset & 1, "Unaligned 16bit parameter");
		else if (p->data_size <= 8)
			;
		else
			WARN(1, "Invalid parameter size");
		WARN(p->data_shift && p->data_shift + p->data_size > 8, "Shift + size cannot yet > 8");
		WARN(!p->data_size, "Parameter size can't be 0");

		INIT_LIST_HEAD(&p->active_list);
		p->wdev = wdev;
#if (KERNEL_VERSION(4, 6, 0) <= LINUX_VERSION_CODE)
		debugfs_create_file_unsafe(p->fs_name, 0600, d, p, &wfx_dbg_param_fops);
#else
		debugfs_create_file(p->fs_name, 0600, d, p, &wfx_dbg_param_fops);
#endif
	}

	return 0;
}

