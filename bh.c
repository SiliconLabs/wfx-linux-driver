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

#define WFX_WAKEUP_WAIT_STEP_MIN 250  /*in us */
#define WFX_WAKEUP_WAIT_STEP_MAX 300  /*in us */
#define WFX_WAKEUP_WAIT_MAX 2000      /*in us */

static int wfx_bh(void *arg);
static int wfx_prevent_device_to_sleep(struct wfx_dev *wdev);

static void wfx_bh_work(struct work_struct *work)
{
	struct wfx_dev *wdev =
		container_of(work, struct wfx_dev, bh_work);

	wfx_bh(wdev);
}

static inline void wsm_alloc_tx_buffer(struct wfx_dev *wdev)
{
	++wdev->hw_bufs_used;
}

int wfx_register_bh(struct wfx_dev *wdev)
{
	int err = 0;

	/* Realtime workqueue */
	wdev->bh_workqueue = alloc_workqueue("wfx_bh",
					     WQ_MEM_RECLAIM | WQ_HIGHPRI | WQ_CPU_INTENSIVE, 1);

	if (!wdev->bh_workqueue)
		return -ENOMEM;

	INIT_WORK(&wdev->bh_work, wfx_bh_work);

	pr_debug("[BH] register.\n");

	atomic_set(&wdev->bh_rx, 0);
	atomic_set(&wdev->bh_tx, 0);
	atomic_set(&wdev->bh_term, 0);
	wdev->bh_error = 0;
	wdev->hw_bufs_used = 0;
	atomic_set(&wdev->device_awake, 1);
	init_waitqueue_head(&wdev->bh_wq);
	init_waitqueue_head(&wdev->bh_evt_wq);

	return err;
}

void wfx_unregister_bh(struct wfx_dev *wdev)
{
	atomic_add(1, &wdev->bh_term);
	wake_up(&wdev->bh_wq);

	flush_workqueue(wdev->bh_workqueue);

	destroy_workqueue(wdev->bh_workqueue);
	wdev->bh_workqueue = NULL;

	pr_debug("[BH] unregistered.\n");
}

/* SDIO card uses level sensitive interrupts then if they are not clear fast enough
 * we can see the same IT multiple times.
 * In SPI we use an edge interrupt then we do not have the issue.
 *
 * clear the interrupt by reading control register.
 * we can do it even if WUP_pin=0 because when we have an interrupt
 * it means that INEO has data to transfer and then it is not sleeping
 *
 * when sleep is activated we have an interrupt for each wlan_ready (and not only for Rx data).
 * Thus in both SPI and SDIO we should read control_reg to differentiate both IT sources.
 *
 * But reading the ctrl_reg is SPI is not possible in an IT because spi_sync() schedule an event.
 *
 * Then in the IRQ handler, for SPI case, we just force the device to stay awake and we record it.
 * And we read the ctrl_reg as fast as possible in wfx_bh().
 * In SDIO case we must read ctrl_reg in the IRQ else we see many times the same IT
 */
void wfx_irq_handler(struct wfx_dev *wdev)
{
	u32 ctrl_reg;

	if (wdev->bh_error) {
		pr_debug("[BH] error.\n");
		return;
	}
	if (!atomic_read(&wdev->device_awake))
		wfx_prevent_device_to_sleep(wdev);

	if (wdev->pdata.sdio)
		control_reg_read(wdev, &ctrl_reg);

	atomic_set(&wdev->bh_rx, 1);
	pr_debug("[BH] %s IRQ wake_up work queue.\n", __func__);
	wake_up(&wdev->bh_wq);
}

void wfx_bh_wakeup(struct wfx_dev *wdev)
{
	pr_debug("[BH] %s wakeup.\n", __func__);
	if (wdev->bh_error) {
		dev_err(wdev->dev, "bh: wakeup failed\n");
		return;
	}

	if (atomic_add_return(1, &wdev->bh_tx) == 1)
		wake_up(&wdev->bh_wq);
}

/*
 * it returns -EINVAL in case of error
 * and 1 if we must try to Tx because we have just released buffers whereas all were used.
 */
int wsm_release_tx_buffer(struct wfx_dev *wdev, int count)
{
	int ret = wdev->hw_bufs_used >= wdev->wsm_caps.NumInpChBufs ? 1 : 0;

	wdev->hw_bufs_used -= count;
	if (wdev->hw_bufs_used < 0) {
		dev_warn(wdev->dev, "wrong buffers use %d\n", wdev->hw_bufs_used);
		ret = -EINVAL;
	}
	if (!wdev->hw_bufs_used)
		wake_up(&wdev->bh_evt_wq);
	return ret;
}

/*
 * wakeup the device : it must wait the device is ready before continuing
 * it returns 0 if the device is awake, else < 0
 */
static int wfx_device_wakeup(struct wfx_dev *wdev)
{
	int ret = 0;
	u32 Control_reg;
	int rdy_timeout = 0;

	if (wdev->pdata.gpio_wakeup) {
		gpiod_set_value(wdev->pdata.gpio_wakeup, 1);
		dev_dbg(wdev->dev, "bh: wake up device\n");
	}

	/* wait the IRQ indicating the device is ready*/
#if 0
	wait_event_interruptible_timeout(wdev->bh_wq,
					atomic_read(&wdev->device_awake),
					HZ / 50);
	/* typically HZ=100, then here wait 2 jiffies
	 * indeed waiting 1 jiffie is dangerous because if n jiffies is
	 * requested, effective wait is ]n+1, n-1[ */
#else
	do {
		usleep_range(WFX_WAKEUP_WAIT_STEP_MIN, WFX_WAKEUP_WAIT_STEP_MAX);
		rdy_timeout += WFX_WAKEUP_WAIT_STEP_MIN;
	} while (!atomic_read(&wdev->device_awake) &&
		 (rdy_timeout < WFX_WAKEUP_WAIT_MAX));
#endif
	if (!atomic_read(&wdev->device_awake)) { /* timeout */
		/* no IRQ then maybe the device was not sleeping
		 * try to read the control register */
		int error = control_reg_read(wdev, &Control_reg);

		if (error || !Control_reg || Control_reg == ~0) {
			ret = -EIO;
		} else if (!(Control_reg & CTRL_WLAN_READY)) {
			dev_err(wdev->dev, "bh: cannot wakeup device\n");
			ret = -EIO;
		} else {
			dev_dbg(wdev->dev, "bh: device correctly wake up\n");
			atomic_set(&wdev->device_awake, 1);
			ret = 0;
		}
	} else {
		dev_dbg(wdev->dev, "bh: already awake\n");
		ret = 0;
	}

	/* device is awake, remove the IRQ on data available */
	if (wdev->pdata.sdio && !ret)
		config_reg_write_bits(wdev, CFG_IRQ_ENABLE_DATA | CFG_IRQ_ENABLE_WRDY, CFG_IRQ_ENABLE_WRDY);

	return ret;
}

/*
 * allow the device to go in sleep mode
 */
static int wfx_device_wakedown(struct wfx_dev *wdev)
{
	int ret = 0;

	gpiod_set_value(wdev->pdata.gpio_wakeup, 0);
	atomic_set(&wdev->device_awake, 0);

	return ret;
}

/*
 * we know that the device is awake (for instance we know we have Rx data to read)
 * but we want to be sure the device stays awake after the last Rx data has been read.
 * Then we just set the WUP signal here
 */
static int wfx_prevent_device_to_sleep(struct wfx_dev *wdev)
{
	int ret = 0;

	if (wdev->pdata.gpio_wakeup) {
		gpiod_set_value(wdev->pdata.gpio_wakeup, 1);
		dev_dbg(wdev->dev, "%s: wake up chip", __func__);
		atomic_set(&wdev->device_awake, 1);
	}
	return ret;
}

/*
 * read the control register to check if there are Rx messages to read
 * It updates the ctrl_reg value and returns 1 when there's a message to read
 * it returns negative values in case of errors
 */
static int wfx_check_pending_rx(struct wfx_dev *wdev, u32 *ctrl_reg)
{
	int i;
	/* before reading the ctrl_reg we must be sure the device is awake */
	if (!atomic_read(&wdev->device_awake))
		if (wfx_device_wakeup(wdev))
			return -1; /* wake-up error */

	for (i = 0; i < 4; i++) {
		if (control_reg_read(wdev, ctrl_reg))
			return -EIO;
		if (*ctrl_reg & CTRL_WLAN_READY)
			break;
		dev_err(wdev->dev, "Chip is not ready! (ctrl: %08x) %d/4\n", *ctrl_reg, i + 1);
		udelay(1000);
	}
	if (!(*ctrl_reg & CTRL_WLAN_READY))
		*ctrl_reg = 0;

	return *ctrl_reg & CTRL_NEXT_LEN_MASK;
}

static int wfx_bh_rx_helper(struct wfx_dev *wdev, u32 *ctrl_reg)
{
	size_t read_len = 0;
	struct sk_buff *skb_rx = NULL;
	struct wmsg *wsm;
	int rx_resync = 1;

	size_t alloc_len;
	u8 *data;

	pr_debug("[BH] %s\n", __func__);

	read_len = (*ctrl_reg & CTRL_NEXT_LEN_MASK) * 2;
	if (!read_len)
		return 0;

	read_len = read_len + 2;

	alloc_len = wdev->hwbus_ops->align_size(wdev->hwbus_priv, read_len);

	skb_rx = dev_alloc_skb(alloc_len);
	if (!skb_rx)
		goto err;

	skb_trim(skb_rx, 0);
	skb_put(skb_rx, read_len);
	data = skb_rx->data;

	if (wfx_data_read(wdev, data, alloc_len)) {
		dev_err(wdev->dev, "bh: rx blew up, len %zu\n", alloc_len);
		goto err;
	}

	// Get piggyback value
	*ctrl_reg = le16_to_cpup((u16 *) (data + alloc_len - 2));

	wsm = (struct wmsg *) data;
	le16_to_cpus(wsm->len);

	if (round_up(wsm->len, 2) != read_len - 2) {
		dev_err(wdev->dev, "inconsistent message length: %d != %zu\n",
			wsm->len, read_len - 2);
		print_hex_dump(KERN_INFO, "wsm: ", DUMP_PREFIX_OFFSET, 16, 1,
			       data, read_len, true);
		goto err;
	}
	_trace_wsm_recv(wsm);

	skb_trim(skb_rx, wsm->len);

	if (wsm->id != HI_EXCEPTION_IND_ID) {
		if (wsm->seqnum != wdev->wsm_rx_seq &&  !rx_resync) {
			dev_warn(wdev->dev, "wrong message sequence: %d != %d\n",
					wsm->seqnum, wdev->wsm_rx_seq);
			goto err;
		}
		wdev->wsm_rx_seq = (wsm->seqnum + 1) % (WMSG_COUNTER_MAX + 1);
		rx_resync = 0;
	}

	/* is it a confirmation message? */
	if ((wsm->id & WMSG_ID_IS_INDICATION) == 0) {
		if (wsm_release_tx_buffer(wdev, 1) < 0)
			goto err;
	}

	/* wfx_wsm_rx takes care on SKB livetime */
	wsm_handle_rx(wdev, wsm, &skb_rx);

	if (skb_rx) {
		dev_kfree_skb(skb_rx);
		skb_rx = NULL;
	}

	_trace_piggyback(*ctrl_reg, false);
	return 0;

err:
	if (skb_rx) {
		dev_kfree_skb(skb_rx);
		skb_rx = NULL;
	}
	_trace_piggyback(*ctrl_reg, true);
	return -1;
}

/*
 * it returns : 0  when nothing has been sent
 *              <0 in case of error
 *              else the number of messages that could be sent in the same TxOp than
 *                 the message just sent (and including this message).
 *
 * Note that returning 1 means that a msg has been sent but we don't know if there is
 * pending data to send. Then you must try again calling this fct.
 */
static int wfx_bh_tx_helper(struct wfx_dev *wdev)
{
	size_t tx_len;
	u8 *data;
	int ret, tx_burst;
	struct wmsg *wsm;

	if (!atomic_read(&wdev->device_awake)) {
		if (wfx_device_wakeup(wdev))
			return -1;
	}

	wsm_alloc_tx_buffer(wdev);

	ret = wsm_get_tx(wdev, &data, &tx_len, &tx_burst); /* returns 1 if it founds some data to Tx */
	if (ret <= 0) {
		wsm_release_tx_buffer(wdev, 1);
		WARN_ON(ret < 0);
		return ret;
	}

	wsm = (struct wmsg *)data;
	BUG_ON(tx_len < sizeof(*wsm));
	BUG_ON(le16_to_cpu(wsm->len) != tx_len);

	tx_len = wdev->hwbus_ops->align_size(wdev->hwbus_priv, tx_len);

	wsm->seqnum = wdev->wsm_tx_seq;
	if (wfx_data_write(wdev, data, tx_len)) {
		dev_err(wdev->dev, "bh: tx blew up, len %zu\n", tx_len);
		wsm_release_tx_buffer(wdev, 1);
		return -1;
	}

	_trace_wsm_send(wsm);

	wdev->wsm_tx_seq = (wdev->wsm_tx_seq + 1) % (WMSG_COUNTER_MAX + 1);

	if (tx_burst > 1)
		wfx_debug_tx_burst(wdev);

	return tx_burst;
}

/*
 * main state machine of the Bus handler
 */
static int wfx_bh(void *arg)
{
	int term, irq_seen;
	int tx_allowed;
	long status;
	int ret, done;
	int pending_tx = 0;
	int pending_rx = 0;
	u32 ctrl_reg = 0;
	struct wfx_dev *wdev = arg;

	for (;;) {
		if (!pending_rx && (!pending_tx || wdev->hw_bufs_used >= wdev->wsm_caps.NumInpChBufs)) {
			/* enable IRQ on Rx data available to wake us up */
			config_reg_write_bits(wdev, CFG_IRQ_ENABLE_DATA | CFG_IRQ_ENABLE_WRDY, CFG_IRQ_ENABLE_DATA | CFG_IRQ_ENABLE_WRDY);

			if (!wdev->hw_bufs_used && /* !pending_rx && !pending_tx && */ wdev->pdata.gpio_wakeup &&
			    atomic_read(&wdev->device_awake) && !atomic_read(&wdev->scan_in_progress)) {
				/* no data to process and allowed to go to sleep */
				status = 10 * HZ; /* wakeup at least every 10s */
				pr_debug("[BH] Device wakedown. No data.\n");
				wfx_device_wakedown(wdev);
			} else if (wdev->hw_bufs_used) {
				/* we are waiting for confirmation msg */
				status = 1 * HZ; /*only sleep for 1s*/
				pr_debug("[BH] no wakedown : hw_bufs_used=%d  rx=%d  tx=%d\n",
					wdev->hw_bufs_used, pending_rx, pending_tx);
			} else {
				status = MAX_SCHEDULE_TIMEOUT;
			}

			status = wait_event_interruptible_timeout(wdev->bh_wq, ({
				irq_seen = atomic_xchg(&wdev->bh_rx, 0);
				pending_tx += atomic_xchg(&wdev->bh_tx, 0);
				term = atomic_xchg(&wdev->bh_term, 0);
				(irq_seen || pending_tx || term || wdev->bh_error);
			}), status);

			/* bh_rx=1 means an IRQ triggered but it can be for Rx data to read or for the device coming out of sleep
			 * then read ctrl reg to be sure a Rx msg is pending */
			if (irq_seen) {
				pending_rx = wfx_check_pending_rx(wdev, &ctrl_reg);
				if (pending_rx < 0) {
					break; /* error */
				}
			}
			/* because of the ctrl_reg read in SDIO IRQ we want to disable the IRQ when possible
			 * if device is already awake then we can update the IRQ enable now
			 * else we do it when we wake-up the device*/
			if (wdev->pdata.sdio && atomic_read(&wdev->device_awake))
				config_reg_write_bits(wdev, CFG_IRQ_ENABLE_DATA | CFG_IRQ_ENABLE_WRDY, CFG_IRQ_ENABLE_WRDY);

			pr_debug("[BH] - rx: %d, tx: %d, term: %d, bh_err: %d, status: %ld , conf_mutex: %d\n",
				pending_rx, pending_tx, term, wdev->bh_error, status,
				mutex_is_locked(&wdev->conf_mutex));

			/* Did an error occur? */
			if ((status < 0 && status != -ERESTARTSYS) || term || wdev->bh_error)
				break;

			/* wait_event timed out */
			if (!status) {
				unsigned long timestamp = jiffies;
				long timeout;
				int pending = 0;
				int i;

				/* Check to see if we have any outstanding frames */
				if (wdev->hw_bufs_used && !pending_rx) {
					pending_rx = wfx_check_pending_rx(wdev, &ctrl_reg);
					dev_warn(wdev->dev, "Missed interrupt? (%d frames outstanding) pending_rx=%d\n",
						   wdev->hw_bufs_used, pending_rx);

					if (pending_rx < 0) {
						break; /* error */
					}

					/* Get a timestamp of "oldest" frame */
					for (i = 0; i < 4; ++i)
						pending += wfx_queue_get_xmit_timestamp(&wdev->tx_queue[i], &timestamp, wdev->pending_frame_id);
					timeout = timestamp + WSM_CMD_LAST_CHANCE_TIMEOUT + 1 * HZ  - jiffies;

					/* And terminate BH thread if the frame is "stuck" */
					if (pending && timeout < 0) {
						dev_warn(wdev->dev, "Timeout waiting for TX confirm (%d/%d pending, %ld vs %lu).\n",
							wdev->hw_bufs_used, pending, timestamp, jiffies);
					}
				} /* end of timeout event */
			}
		} /* end of the wait_event global processing */
		dev_dbg(wdev->dev, "bh: wait event\n");

		/*
		 * process Rx then Tx because Rx processing can release some buffers for the Tx
		 */
rx:
		done = 0;
		while (pending_rx && (done < 32)) {
			/* ctrl_reg is updated in wfx_bh_rx_helper() using the piggy backing */
			ret = wfx_bh_rx_helper(wdev, (u32 *) &ctrl_reg);
			if (ret < 0) // Ignore piggyback on error
				ctrl_reg = 0;
			pending_rx = ctrl_reg & CTRL_NEXT_LEN_MASK;
			done++;
		}

tx:
		pending_tx += atomic_xchg(&wdev->bh_tx, 0);
		BUG_ON(wdev->hw_bufs_used > wdev->wsm_caps.NumInpChBufs);
		/* do not send more messages than buffers available in the device */
		tx_allowed = wdev->wsm_caps.NumInpChBufs - wdev->hw_bufs_used;
		tx_allowed = min(tx_allowed, 4);

		while (pending_tx && (tx_allowed > 0)) {
			done = wfx_bh_tx_helper(wdev);
			if (done < 0)
				break; /* error */
			tx_allowed--;
			if (done == 0) { /* nothing sent */
				pending_tx = 0;
			} else {
				pending_tx--;
			}
		}

		/* check_rx */
		/* clear bh_rx that is set during the IRQ (when number of Rx msg in the queue
		 * toggles from 0 to 1)
		 * because it is possible that we already read this msg */
		atomic_set(&wdev->bh_rx, 0);
		/* then Re-read ctrl reg to be sure that no Rx msg is pending */
		/* this read is also used as Dummy Read for SDIO retry mechanism to ack last Rx or Tx access */
		if (!pending_rx) {
			int memo_device_awake = atomic_read(&wdev->device_awake);

			pending_rx = wfx_check_pending_rx(wdev, &ctrl_reg);
			if (pending_rx < 0) {
				break; /* error */
			}

			if (pending_rx == 0 && memo_device_awake == 0) {
				/* device has been waked-up by wfx_check_pending_rx() just above
				 * that has generated an IRQ and thus set wdev->bh_rx to 1.
				 * to avoid going to sleep and wake-up immediately
				 * we do here what is done (when an IRQ is seen) at the beginning of this fct*/
				if (atomic_xchg(&wdev->bh_rx, 0)) {
					pending_rx = wfx_check_pending_rx(wdev, &ctrl_reg);
					if (pending_rx < 0) {
						break; /* error */
					}
				}
			}
		}

		if (pending_rx)
			goto rx;

		/* read bh_tx to avoid going to sleep while we just get a bh_wakeup */
		pending_tx += atomic_xchg(&wdev->bh_tx, 0);
		if (pending_tx)
			goto tx;
	}

	if (!term) {
		dev_dbg(wdev->dev, "bh: main exited on error\n");
		wdev->bh_error = 1;
	}
	return 0;
}
