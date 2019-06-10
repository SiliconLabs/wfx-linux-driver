// SPDX-License-Identifier: GPL-2.0-only
/*
 * Interrupt bottom half (BH).
 *
 * Copyright (c) 2017-2019, Silicon Laboratories, Inc.
 * Copyright (c) 2010, ST-Ericsson
 */
#include <linux/gpio/consumer.h>
#include <net/mac80211.h>

#include "bh.h"
#include "wfx.h"
#include "hwio.h"
#include "debug.h"
#include "wsm_rx.h"
#include "traces.h"

static void device_wakeup(struct wfx_dev *wdev)
{
	if (!wdev->pdata.gpio_wakeup)
		return;
	if (gpiod_get_value(wdev->pdata.gpio_wakeup))
		return;

	gpiod_set_value(wdev->pdata.gpio_wakeup, 1);
	if (wfx_api_older_than(wdev, 1, 4)) {
		if (!try_wait_for_completion(&wdev->hif.wakeup_done))
			udelay(2000);
	} else {
		// TODO: measure latency for wakeup and add a trace
		if (!wait_for_completion_timeout(&wdev->hif.wakeup_done, msecs_to_jiffies(2) + 1))
			dev_dbg(wdev->dev, "timeout while wake up chip\n");
	}
}

static void device_release(struct wfx_dev *wdev)
{
	if (!wdev->pdata.gpio_wakeup)
		return;

	reinit_completion(&wdev->hif.wakeup_done);
	gpiod_set_value(wdev->pdata.gpio_wakeup, 0);
}

static int rx_helper(struct wfx_dev *wdev, size_t read_len, int *is_cnf)
{
	struct sk_buff *skb;
	struct wmsg *wsm;
	size_t alloc_len;
	int release_count;
	int piggyback = 0;

	WARN_ON(read_len < 4);

	// piggyback is not accounted
	read_len += 2;
	alloc_len = wdev->hwbus_ops->align_size(wdev->hwbus_priv, read_len);
	skb = dev_alloc_skb(alloc_len);
	if (!skb)
		return -ENOMEM;

	if (wfx_data_read(wdev, skb->data, alloc_len))
		goto err;

	piggyback = le16_to_cpup((u16 *) (skb->data + alloc_len - 2));
	_trace_piggyback(piggyback, false);

	wsm = (struct wmsg *) skb->data;
	le16_to_cpus(wsm->len);
	skb_put(skb, wsm->len);
	if (round_up(wsm->len, 2) != read_len - 2) {
		dev_err(wdev->dev, "inconsistent message length: %d != %zu\n",
			wsm->len, read_len - 2);
		print_hex_dump(KERN_INFO, "wsm: ", DUMP_PREFIX_OFFSET, 16, 1,
			       wsm, read_len, true);
		goto err;
	}
	_trace_wsm_recv(wsm);

	if (wsm->id != HI_EXCEPTION_IND_ID && wsm->id != HI_ERROR_IND_ID) {
		if (wsm->seqnum != wdev->hif.rx_seqnum)
			dev_warn(wdev->dev, "wrong message sequence: %d != %d\n",
				 wsm->seqnum, wdev->hif.rx_seqnum);
		wdev->hif.rx_seqnum = (wsm->seqnum + 1) % (WMSG_COUNTER_MAX + 1);
	}

	if (!(wsm->id & WMSG_ID_IS_INDICATION)) {
		(*is_cnf)++;
		if (wsm->id == WSM_HI_MULTI_TRANSMIT_CNF_ID)
			release_count = le32_to_cpu(((WsmHiMultiTransmitCnfBody_t *) wsm->body)->NumTxConfs);
		else
			release_count = 1;
		WARN(wdev->hif.tx_buffers_used < release_count, "corrupted buffer counter");
		wdev->hif.tx_buffers_used -= release_count;
		if (!wdev->hif.tx_buffers_used)
			wake_up(&wdev->hif.tx_buffers_empty);
	}

	// wfx_wsm_rx takes care on SKB livetime
	wsm_handle_rx(wdev, wsm, &skb);

	if (skb)
		dev_kfree_skb(skb);

	return piggyback;

err:
	if (skb)
		dev_kfree_skb(skb);
	return -EIO;
}

static int bh_work_rx(struct wfx_dev *wdev, int max_msg, int *num_cnf)
{
	size_t len;
	int i;
	int ctrl_reg, piggyback;

	piggyback = 0;
	for (i = 0; i < max_msg; i++) {
		if (piggyback & CTRL_NEXT_LEN_MASK)
			ctrl_reg = piggyback;
		else
			ctrl_reg = atomic_xchg(&wdev->hif.ctrl_reg, 0);
		if (!(ctrl_reg & CTRL_NEXT_LEN_MASK))
			return i;
		// ctrl_reg units are 16bits words
		len = (ctrl_reg & CTRL_NEXT_LEN_MASK) * 2;
		piggyback = rx_helper(wdev, len, num_cnf);
		if (piggyback < 0)
			return i;
		if (!(piggyback & CTRL_WLAN_READY))
			dev_err(wdev->dev, "unexpected piggyback value: ready bit not set: %04x", piggyback);
	}
	if (piggyback & CTRL_NEXT_LEN_MASK) {
		ctrl_reg = atomic_xchg(&wdev->hif.ctrl_reg, piggyback);
		if (ctrl_reg)
			dev_err(wdev->dev, "unexpected IRQ happened: %04x/%04x", ctrl_reg, piggyback);
	}
	return i;
}

static void tx_helper(struct wfx_dev *wdev, u8 *data, size_t len)
{
	int ret;
	struct wmsg *wsm;

	wsm = (struct wmsg *) data;
	BUG_ON(len < sizeof(*wsm));
	BUG_ON(wsm->len != len);

	wsm->seqnum = wdev->hif.tx_seqnum;
	wdev->hif.tx_seqnum = (wdev->hif.tx_seqnum + 1) % (WMSG_COUNTER_MAX + 1);

	len = wdev->hwbus_ops->align_size(wdev->hwbus_priv, len);
	ret = wfx_data_write(wdev, data, len);
	if (ret)
		return;

	_trace_wsm_send(wsm);
	wdev->hif.tx_buffers_used++;
}

static int bh_work_tx(struct wfx_dev *wdev, int max_msg)
{
	u8 *data;
	size_t len;
	int i;

	for (i = 0; i < max_msg; i++) {
		data = NULL;
		if (wdev->hif.tx_buffers_used < wdev->wsm_caps.NumInpChBufs)
			wsm_get_tx(wdev, &data, &len);
		if (!data)
			return i;
		tx_helper(wdev, data, len);
	}
	return i;
}

static void bh_work(struct work_struct *work)
{
	struct wfx_dev *wdev = container_of(work, struct wfx_dev, hif.bh);
	int stats_req = 0, stats_cnf = 0, stats_ind = 0;
	bool release_chip;
	int num_tx, num_rx;

	device_wakeup(wdev);
	do {
		num_tx = bh_work_tx(wdev, 32);
		stats_req += num_tx;
		num_rx = bh_work_rx(wdev, 32, &stats_cnf);
		stats_ind += num_rx;
	} while (num_rx || num_tx);
	stats_ind -= stats_cnf;

	if (!wdev->hif.tx_buffers_used && !work_pending(work) && !atomic_read(&wdev->scan_in_progress)) {
		device_release(wdev);
		release_chip = true;
	} else {
		release_chip = false;
	}
	_trace_bh_stats(stats_ind, stats_req, stats_cnf, wdev->hif.tx_buffers_used, release_chip);
}

void wfx_bh_request_rx(struct wfx_dev *wdev)
{
	u32 cur, prev;

	control_reg_read(wdev, &cur);
	prev = atomic_xchg(&wdev->hif.ctrl_reg, cur);
	queue_work(system_highpri_wq, &wdev->hif.bh);
	complete(&wdev->hif.wakeup_done);

	if (!(cur & CTRL_NEXT_LEN_MASK))
		dev_err(wdev->dev, "unexpected control register value: length field is 0: %04x", cur);
	if (prev != 0)
		dev_err(wdev->dev, "received IRQ but previous data was not (yet) read: %04x/%04x", prev, cur);
}

void wfx_bh_request_tx(struct wfx_dev *wdev)
{
	queue_work(system_highpri_wq, &wdev->hif.bh);
}

void wfx_bh_register(struct wfx_dev *wdev)
{
	INIT_WORK(&wdev->hif.bh, bh_work);
	init_completion(&wdev->hif.wakeup_done);
	init_waitqueue_head(&wdev->hif.tx_buffers_empty);
}

void wfx_bh_unregister(struct wfx_dev *wdev)
{
	flush_work(&wdev->hif.bh);
}

