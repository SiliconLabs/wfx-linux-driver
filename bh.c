/*
 * Device handling thread implementation for mac80211 Silicon Labs WFX drivers
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

#include <linux/gpio/consumer.h>
#include <net/mac80211.h>

#include "bh.h"
#include "wfx.h"
#include "hwio.h"
#include "debug.h"
#include "traces.h"

#define WF200_WAKEUP_WAIT_STEP_MIN 250  /*in us */
#define WF200_WAKEUP_WAIT_STEP_MAX 300  /*in us */
#define WF200_WAKEUP_WAIT_MAX 2000      /*in us */

/* an SPI message cannot be bigger than (2"12-1)*2 bytes "*2" to cvt to bytes*/
#define MAX_CTRL_FRAME_LEN      (0x1000)
#define DOWNLOAD_BLOCK_SIZE_WR  (MAX_CTRL_FRAME_LEN - 4)
#define MAX_SZ_RD_WR_BUFFERS	(DOWNLOAD_BLOCK_SIZE_WR * 2)
#define PIGGYBACK_CTRL_REG	(2)
#define EFFECTIVE_BUF_SIZE	(MAX_SZ_RD_WR_BUFFERS - PIGGYBACK_CTRL_REG)

#ifdef RASPBERRY_PI
#define HIF_ERROR_DETECTION_8   0x55
#define HIF_ERROR_DETECTION_16  0x5555
#endif
/* Suspend state privates */
enum wfx_bh_pm_state {
	WFX_BH_RESUMED = 0, WFX_BH_SUSPEND, WFX_BH_SUSPENDED, WFX_BH_RESUME,
};

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

static int wfx_bh_read_ctrl_reg(struct wfx_dev *wdev, u32 *ctrl_reg,
				uint8_t caller_id)
{
	int ret;

	ret = control_reg_read(wdev, ctrl_reg);
	if (ret) {
		udelay(WF200_WAKEUP_WAIT_MAX);
		pr_debug("[BH] *** 2d try ctrl_reg read ***\n");
		ret = control_reg_read(wdev, ctrl_reg);
		if (ret)
			wfx_err("[BH] id=%d Failed to read control register\n",
				caller_id);
	}

	return ret;
}

typedef int (*wfx_wsm_handler)(struct wfx_dev *wdev, u8 *data, size_t size);

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
	atomic_set(&wdev->bh_suspend, WFX_BH_RESUMED);
	wdev->bh_error = 0;
	wdev->hw_bufs_used = 0;
	atomic_set(&wdev->device_can_sleep, 0);
	wdev->sleep_activated = false;
	init_waitqueue_head(&wdev->bh_wq);
	init_waitqueue_head(&wdev->bh_evt_wq);

	err = !queue_work(wdev->bh_workqueue, &wdev->bh_work);
	WARN_ON(err);
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
	if (atomic_read(&wdev->device_can_sleep))
		wfx_prevent_device_to_sleep(wdev);

	if (wdev->pdata.sdio == true)
		wfx_bh_read_ctrl_reg(wdev, &ctrl_reg, 3);

	atomic_set(&wdev->bh_rx, 1);
	pr_debug("[BH] %s IRQ wake_up work queue.\n", __func__);
	wake_up(&wdev->bh_wq);
}

void wfx_bh_wakeup(struct wfx_dev *wdev)
{
	pr_debug("[BH] %s wakeup.\n", __func__);
	if (wdev->bh_error) {
		wfx_err("[BH] wakeup failed (BH error)\n");
		return;
	}

	if (atomic_add_return(1, &wdev->bh_tx) == 1)
		wake_up(&wdev->bh_wq);
}

int wfx_bh_suspend(struct wfx_dev *wdev)
{
	pr_debug("[BH] suspend.\n");
	if (wdev->bh_error) {
		wiphy_warn(wdev->hw->wiphy, "BH error -- can't suspend\n");
		return -EINVAL;
	}

	atomic_set(&wdev->bh_suspend, WFX_BH_SUSPEND);
	wake_up(&wdev->bh_wq);
	return wait_event_timeout(wdev->bh_evt_wq, wdev->bh_error ||
				  (WFX_BH_SUSPENDED ==
				   atomic_read(&wdev->bh_suspend)),
		 1 * HZ) ? 0 : -ETIMEDOUT;
}

int wfx_bh_resume(struct wfx_dev *wdev)
{
	pr_debug("[BH] resume.\n");
	if (wdev->bh_error) {
		wiphy_warn(wdev->hw->wiphy, "BH error -- can't resume\n");
		return -EINVAL;
	}

	atomic_set(&wdev->bh_suspend, WFX_BH_RESUME);
	wake_up(&wdev->bh_wq);
	return wait_event_timeout(wdev->bh_evt_wq, wdev->bh_error ||
				  (WFX_BH_RESUMED ==
				   atomic_read(&wdev->bh_suspend)),
		1 * HZ) ? 0 : -ETIMEDOUT;
}

/*
 * it returns -1 in case of error
 * and 1 if we must try to Tx because we have just released buffers whereas all were used.
 */
int wsm_release_tx_buffer(struct wfx_dev *wdev, int count)
{
	int ret = 0;
	int hw_bufs_used = wdev->hw_bufs_used;

	wdev->hw_bufs_used -= count;
	if (wdev->hw_bufs_used < 0) {
		wfx_warn("wrong buffer use %d\n", wdev->hw_bufs_used);
		ret = -1;
	} else if (hw_bufs_used >= wdev->wsm_caps.NumInpChBufs) {
		ret = 1;
	}
	if (!wdev->hw_bufs_used)
		wake_up(&wdev->bh_evt_wq);
	return ret;
}

/*
 * wakeup the device : it must wait the device is ready before continuing
 * it returns 1 if the device is awake, else 0
 */
static int wfx_device_wakeup(struct wfx_dev *wdev)
{
	int ret = 1;
	u32 Control_reg;
	int rdy_timeout = 0;

	if (wdev->sleep_activated) {
		gpiod_set_value(wdev->pdata.gpio_wakeup, 1);
		dev_dbg(wdev->pdev, "%s: wake up chip", __func__);
	}

	/* wait the IRQ indicating the device is ready*/
#if 0
	wait_event_interruptible_timeout(wdev->bh_wq,
					!atomic_read(&wdev->device_can_sleep),
					HZ / 50);
	/* typically HZ=100, then here wait 2 jiffies
	 * indeed waiting 1 jiffie is dangerous because if n jiffies is
	 * requested, effective wait is ]n+1, n-1[ */
#else
	do {
		usleep_range(WF200_WAKEUP_WAIT_STEP_MIN, WF200_WAKEUP_WAIT_STEP_MAX);
		rdy_timeout += WF200_WAKEUP_WAIT_STEP_MIN;
	} while (atomic_read(&wdev->device_can_sleep) &&
		 (rdy_timeout < WF200_WAKEUP_WAIT_MAX));
#endif
	if (atomic_read(&wdev->device_can_sleep) == 1) { /* timeout */
		/* no IRQ then maybe the device was not sleeping
		 * try to read the control register */
		int error = wfx_bh_read_ctrl_reg(wdev, &Control_reg, 2);

		if (error) {
			wfx_info("[BH] ##### %s ctrl_reg read error.\n", __func__);
			ret = 0;
		} else if (!(Control_reg & CTRL_WLAN_READY)) {
			wfx_info("[BH] ##### %s can't wakeup.\n", __func__);
			ret = 0;
		} else {
			atomic_set(&wdev->device_can_sleep, 0);
			pr_debug("[BH] %s Device was already awake.\n", __func__);
			ret = 1;
		}
	} else {
		pr_debug("[BH] %s Device awake.\n", __func__);
		ret = 1;
	}

	/* device is awake, remove the IRQ on data available */
	if (wdev->pdata.sdio == true && ret == 1)
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
	atomic_set(&wdev->device_can_sleep, 1);

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

	if (wdev->sleep_activated) {
		gpiod_set_value(wdev->pdata.gpio_wakeup, 1);
		dev_dbg(wdev->pdev, "%s: wake up chip", __func__);
		atomic_set(&wdev->device_can_sleep, 0);
	}
		return ret;
}

/*
 * read the control register to check if there are Rx messages to read
 * It updates the ctrl_reg value and returns 1 when there's a message to read
 * it returns negative values in case of errors
	 */
static int wfx_check_pending_rx(struct wfx_dev	*wdev,
				u32		*ctrl_reg_ptr)
{
	/* before reading the ctrl_reg we must be sure the device is awake */
	if (atomic_read(&wdev->device_can_sleep))
		if (wfx_device_wakeup(wdev) <= 0)
			return -1; /* wake-up error */

	if (wfx_bh_read_ctrl_reg(wdev, ctrl_reg_ptr, 1))
		return -2; /* read error */

	return *ctrl_reg_ptr & CTRL_NEXT_LEN_MASK;
}

static int wfx_bh_rx_helper(struct wfx_dev *wdev, uint32_t *ctrl_reg)
{
	size_t read_len = 0;
	struct sk_buff *skb_rx = NULL;
	HiMsgHdr_t *wsm;
	size_t wsm_len;
	u8 wsm_id, wsm_info;
	u8 wsm_seq;
	int rx_resync = 1;

	size_t alloc_len;
	u8 *data;

	pr_debug("[BH] %s\n", __func__);

	read_len = (*ctrl_reg & CTRL_NEXT_LEN_MASK) * 2;
	if (!read_len)
		return 0;

	if ((read_len < sizeof(HiMsgHdr_t)) ||
	    (read_len > EFFECTIVE_BUF_SIZE)) {
		wfx_err("Invalid read len: %zu (%08x)", read_len, *ctrl_reg);
		goto err;
	}

	read_len = read_len + 2;

	alloc_len = wdev->hwbus_ops->align_size(wdev->hwbus_priv, read_len);

	/* Check if not exceeding wfx capabilities */
	if (alloc_len > EFFECTIVE_BUF_SIZE)
		wfx_err("Allocation exceeds wfx capabilities%zu\n", alloc_len);

	skb_rx = dev_alloc_skb(alloc_len);
	if (!skb_rx)
		goto err;

	skb_trim(skb_rx, 0);
	skb_put(skb_rx, read_len);
	data = skb_rx->data;
	if (!data) {
		wfx_err("Wrong data area. Its exceed the total buffer size");
		goto err;
	}
#ifdef RASPBERRY_PI
	/* Error detection mechanism to detect the issue
	 * https://github.com/raspberrypi/linux/issues/2200
	 * The last bytes are set to a defined impair value
	 * Most of the HIF messages have a pair length
	 */
	if (wdev->pdata.sdio == false)
		((uint16_t *)data)[alloc_len / 2 - 1] = HIF_ERROR_DETECTION_16;
#endif
	if (wfx_data_read(wdev, data, alloc_len)) {
		wfx_err("rx blew up, len %zu\n", alloc_len);
		goto err;
	}

	/* update ctrl_reg with the u16 piggybacked value */
	*ctrl_reg =
		(uint32_t)le16_to_cpu(((__le16 *)data)[alloc_len / 2 - 1]);

#ifdef RASPBERRY_PI
	if (wdev->pdata.sdio == false && data[alloc_len - 2] == HIF_ERROR_DETECTION_8) {
		/* If the last byte has not been overwritten,
		 * the control register is set to 0 to cause
		 * a new read of this register in the bh loop*/
		*ctrl_reg = 0;
		wfx_warn("ctrl_reg piggyback error");
	}
#endif

	wsm = (HiMsgHdr_t *)data;
	wsm_len = le16_to_cpu(wsm->MsgLen);
	if (wsm_len > read_len) {
		wfx_err("inconsistent HIF message length %lu != %lu\n",
			(unsigned long) wsm_len,
			(unsigned long) read_len);
		goto err;
	}
	_trace_wsm_recv((u16 *) data);

	wsm_id = wsm->s.t.MsgId;
	wsm_info = wsm->s.t.MsgInfo;
	wsm_seq = (wsm_info >> 3) & HI_MSG_SEQ_RANGE;

	skb_trim(skb_rx, wsm_len);

	if (wsm_id == HI_EXCEPTION_IND_ID) {
		wsm_handle_exception(wdev,
				     &data[sizeof(*wsm)],
				     wsm_len - sizeof(*wsm));
		goto err;
	} else if (!rx_resync) {
		if (wsm_seq != wdev->wsm_rx_seq) {
			wfx_warn("Wrong message sequence %d != %d\n", wsm_seq,
				 wdev->wsm_rx_seq);
			goto err;
	}
	}
	wdev->wsm_rx_seq = (wsm_seq + 1) & 7;
	rx_resync = 0;

	/* is it a confirmation message? */
	if ((wsm_id & HI_MSG_TYPE_MASK) == 0) {
		int rc = wsm_release_tx_buffer(wdev, 1);

		if (rc < 0)
			return rc;
	}

	/* wfx_wsm_rx takes care on SKB livetime */
	if (wsm_handle_rx(wdev, wsm, &skb_rx)) {
		wfx_err("wsm_handle_rx id=0x02%x\n", wsm_id);
		goto err;
	}

	if (skb_rx) {
		dev_kfree_skb(skb_rx);
		skb_rx = NULL;
	}

	return 0;

err:
	if (skb_rx) {
		dev_kfree_skb(skb_rx);
		skb_rx = NULL;
	}
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
	HiMsgHdr_t *wsm;

	pr_debug("[BH] %s\n", __func__);

	if (atomic_read(&wdev->device_can_sleep)) {
		ret = wfx_device_wakeup(wdev);
		if (ret <= 0)           /* Did not awake */
			return -1;      /* error */
	}

	wsm_alloc_tx_buffer(wdev);

	ret = wsm_get_tx(wdev, &data, &tx_len, &tx_burst); /* returns 1 if it founds some data to Tx */
	if (ret <= 0) {
		wsm_release_tx_buffer(wdev, 1);
		if (WARN_ON(ret < 0))
			return ret; /* Error */
		return 0; /* No work */
	}
	wfx_dbg_filter_wsm(wdev, data);

	wsm = (HiMsgHdr_t *)data;
	BUG_ON(tx_len < sizeof(*wsm));
	BUG_ON(le16_to_cpu(wsm->MsgLen) != tx_len);

	tx_len = wdev->hwbus_ops->align_size(wdev->hwbus_priv, tx_len);

	/* Check if not exceeding wfx capabilities */
	if (tx_len > EFFECTIVE_BUF_SIZE)
		wfx_warn("Write aligned len: %zu\n", tx_len);

	wsm->s.t.MsgInfo &= 0xff ^ WSM_TX_SEQ(HI_MSG_SEQ_RANGE);
	wsm->s.t.MsgInfo |= WSM_TX_SEQ(wdev->wsm_tx_seq);
	if (wfx_data_write(wdev, data, tx_len)) {
		wfx_warn("tx blew up, len %zu\n", tx_len);
		wsm_release_tx_buffer(wdev, 1);
		return -1; /* Error */
	}

	_trace_wsm_send((u16 *) data);

	wsm_txed(wdev, data);
	wdev->wsm_tx_seq = (wdev->wsm_tx_seq + 1) & HI_MSG_SEQ_RANGE;

	if (tx_burst > 1)
		wfx_debug_tx_burst(wdev);

	return tx_burst;
}

/*
 * main state machine of the Bus handler
 */
static int wfx_bh(void *arg)
{
	int term, suspend, irq_seen;
	int tx_burst, tx_allowed;
	long status;
	int ret, done;
	int pending_tx = 0;
	int pending_rx = 0;
	u32 ctrl_reg = 0;
	struct wfx_dev *wdev = arg;

	for (;;) {
		if ((!pending_rx) && ((!pending_tx) || (wdev->hw_bufs_used >= wdev->wsm_caps.NumInpChBufs))) {
			/* enable IRQ on Rx data available to wake us up */
			config_reg_write_bits(wdev, CFG_IRQ_ENABLE_DATA | CFG_IRQ_ENABLE_WRDY, CFG_IRQ_ENABLE_DATA | CFG_IRQ_ENABLE_WRDY);

			if (!wdev->hw_bufs_used && /* !pending_rx && !pending_tx && */ wdev->sleep_activated &&
			    !atomic_read(&wdev->device_can_sleep) && !atomic_read(&wdev->wait_for_scan)) {
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
				suspend = pending_tx ? 0 : atomic_read(&wdev->bh_suspend);
				irq_seen = atomic_xchg(&wdev->bh_rx, 0);
				pending_tx += atomic_xchg(&wdev->bh_tx, 0);
				term = atomic_xchg(&wdev->bh_term, 0);
				(irq_seen || pending_tx || term || suspend || wdev->bh_error);
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
			if (wdev->pdata.sdio == true && !atomic_read(&wdev->device_can_sleep))
				config_reg_write_bits(wdev, CFG_IRQ_ENABLE_DATA | CFG_IRQ_ENABLE_WRDY, CFG_IRQ_ENABLE_WRDY);

			pr_debug("[BH] - rx: %d, tx: %d, term: %d, bh_err: %d, suspend: %d, status: %ld , conf_mutex: %d\n",
				pending_rx, pending_tx, term, wdev->bh_error, suspend, status,
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
					wiphy_warn(wdev->hw->wiphy, "Missed interrupt? (%d frames outstanding) pending_rx=%d\n",
						   wdev->hw_bufs_used, pending_rx);

					if (pending_rx < 0) {
						break; /* error */
					}

					/* Get a timestamp of "oldest" frame */
					for (i = 0; i < 4; ++i)
						pending += wfx_queue_get_xmit_timestamp(&wdev->tx_queue[i], &timestamp, wdev->pending_frame_id);
					timeout = timestamp + WSM_CMD_LAST_CHANCE_TIMEOUT + 1 * HZ  - jiffies;

					/* And terminate BH thread if the frame is "stuck" */
					if (pending && (timeout < 0)) {
						wiphy_warn(wdev->hw->wiphy, "Timeout waiting for TX confirm (%d/%d pending, %ld vs %lu).\n",
							wdev->hw_bufs_used, pending, timestamp, jiffies);
					}
				} /* end of timeout event */
			} else if (suspend) {
				pr_debug("[BH] Device suspend.\n");
				if (wdev->sleep_activated) {
					pr_debug("[BH] Device wakedown. Suspend.\n");
					wfx_device_wakedown(wdev);
				}

				atomic_set(&wdev->bh_suspend, WFX_BH_SUSPENDED);
				wake_up(&wdev->bh_evt_wq);
				status = wait_event_interruptible(wdev->bh_wq, atomic_read(&wdev->bh_suspend) == WFX_BH_RESUME);
				if (status < 0) {
					wiphy_err(wdev->hw->wiphy, "Failed to wait for resume: %ld.\n",
							status);
					break;
				}
				pr_debug("[BH] Device resume.\n");
				atomic_set(&wdev->bh_suspend, WFX_BH_RESUMED);
				wake_up(&wdev->bh_evt_wq);
			}
		} /* end of the wait_event global processing */

		/*
		 * process Rx then Tx because Rx processing can release some buffers for the Tx
		 */
rx:
		done = 0;
		while (pending_rx && (done < 32)) {
			/* ctrl_reg is updated in wfx_bh_rx_helper() using the piggy backing */
			ret = wfx_bh_rx_helper(wdev, (uint32_t *) &ctrl_reg);
			if (ret < 0)
				break;
			pending_rx = ctrl_reg & CTRL_NEXT_LEN_MASK;
			done++;
		}

tx:
		pending_tx += atomic_xchg(&wdev->bh_tx, 0);
		BUG_ON(wdev->hw_bufs_used > wdev->wsm_caps.NumInpChBufs);
		/* do not send more messages than buffers available in the device */
		tx_burst = wdev->wsm_caps.NumInpChBufs - wdev->hw_bufs_used;
		tx_allowed = min(tx_burst, 4);

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
			int memo_device_can_sleep = atomic_read(&wdev->device_can_sleep);

			pending_rx = wfx_check_pending_rx(wdev, &ctrl_reg);
			if (pending_rx < 0) {
				break; /* error */
			}

			if (pending_rx == 0 && memo_device_can_sleep == 1) {
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

		pr_debug("[BH] loop done.\n");
	}

	if (!term) {
		wfx_err("[BH] Fatal error, exiting.\n");
		wdev->bh_error = 1;
	}
	return 0;
}
