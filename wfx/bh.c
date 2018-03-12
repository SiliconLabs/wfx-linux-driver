/*
 * Copyright (c) 2017, Silicon Laboratories, Inc.
 *
 * Based on:
 * Copyright (c) 2010, ST-Ericsson
 * Author: Dmitry Tarnyagin <dmitry.tarnyagin@lockless.no>
 * ST-Ericsson UMAC CW1200 driver, which is
 * Copyright (c) 2010, ST-Ericsson
 * Author: Ajitpal Singh <ajitpal.singh@lockless.no>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */


/*========================================================================*/
/*                 Standard Linux Headers                                 */
/*========================================================================*/
#include <linux/module.h>
#include <net/mac80211.h>
#include <linux/kthread.h>
#include <linux/timer.h>

/*========================================================================*/
/*                 Local Header files                                     */
/*========================================================================*/
#include "wfx.h"
#include "bh.h"
#include "hwio.h"
#include "wsm.h"
#include "hwbus.h"
#include "debug.h"
#include "fwio.h"
#include "testmode/include/prv_testmode.h"

/*========================================================================*/
/*                  PRIVATE  Constants/Macros/Types/Variables             */
/*========================================================================*/
/* an SPI message cannot be bigger than (2"12-1)*2 bytes "*2" to cvt to bytes*/
#define MAX_SZ_RD_WR_BUFFERS    (DOWNLOAD_BLOCK_SIZE_WR*2)
#define PIGGYBACK_CTRL_REG      (2)
#define EFFECTIVE_BUF_SIZE      (MAX_SZ_RD_WR_BUFFERS - PIGGYBACK_CTRL_REG)
#define DOWNLOAD_BLOCK_SIZE_WR  (0x1000 - 4)


/*Suspend state privates*/
enum wfx_bh_pm_state {
    WFX_BH_RESUMED = 0,
    WFX_BH_SUSPEND,
    WFX_BH_SUSPENDED,
    WFX_BH_RESUME,
};

/*========================================================================*/
/*                  Internally Static Structures                          */
/*========================================================================*/
static int wfx_bh(void *arg);

static void wfx_bh_work(struct work_struct *work)
{
    struct wfx_common *priv =
    container_of(work, struct wfx_common, bh_work);
    wfx_bh(priv);
}

static inline void wsm_alloc_tx_buffer(struct wfx_common *priv)
{
    ++priv->hw_bufs_used;
}

static int wfx_bh_read_ctrl_reg(struct wfx_common *priv, HiCtrlReg_t *ctrl_reg)
{
    int ret;
    ret = control_reg_read(priv, ctrl_reg);
    if (ret) {
        ret = control_reg_read(priv, ctrl_reg);
        if (ret)
            pr_err("[BH] Failed to read control register.\n");
    }

    return ret;
}

/*========================================================================*/
/*                       Functions                                        */
/*========================================================================*/
typedef int (*wfx_wsm_handler)(struct wfx_common *priv,
    u8 *data, size_t size);

int wfx_register_bh(struct wfx_common *priv)
{
    int err = 0;
    // Realtime workqueue
    priv->bh_workqueue = alloc_workqueue("wfx_bh",
                WQ_MEM_RECLAIM | WQ_HIGHPRI
                | WQ_CPU_INTENSIVE, 1);

    if (!priv->bh_workqueue)
        return -ENOMEM;

    INIT_WORK(&priv->bh_work, wfx_bh_work);

    pr_debug("[BH] register.\n");

    atomic_set(&priv->bh_rx, 0);
    atomic_set(&priv->bh_tx, 0);
    atomic_set(&priv->bh_term, 0);
    atomic_set(&priv->bh_suspend, WFX_BH_RESUMED);
    priv->bh_error = 0;
    priv->hw_bufs_used = 0;
    init_waitqueue_head(&priv->bh_wq);
    init_waitqueue_head(&priv->bh_evt_wq);

    err = !queue_work(priv->bh_workqueue, &priv->bh_work);
    WARN_ON(err);
    return err;
}

void wfx_unregister_bh(struct wfx_common *priv)
{
    atomic_add(1, &priv->bh_term);
    wake_up(&priv->bh_wq);

    flush_workqueue(priv->bh_workqueue);

    destroy_workqueue(priv->bh_workqueue);
    priv->bh_workqueue = NULL;

    pr_debug("[BH] unregistered.\n");
}

void wfx_irq_handler(struct wfx_common *priv)
{

    pr_debug("[BH] %s irq.\n",__func__);

    if (priv->bh_error) {
        pr_debug("[BH] error.\n");
        return;
    }

    if (atomic_add_return(1, &priv->bh_rx) == 1) {
        pr_debug("[BH] %s wake_up work queue.\n",__func__);
        wake_up(&priv->bh_wq);
    }
}
EXPORT_SYMBOL_GPL(wfx_irq_handler);

void wfx_bh_wakeup(struct wfx_common *priv)
{
    pr_debug("[BH] %s wakeup.\n",__func__);
    if (priv->bh_error) {
        pr_err("[BH] wakeup failed (BH error)\n");
        return;
    }

    if (atomic_add_return(1, &priv->bh_tx) == 1)
        wake_up(&priv->bh_wq);
}

int wfx_bh_suspend(struct wfx_common *priv)
{
    pr_debug("[BH] suspend.\n");
    if (priv->bh_error) {
        wiphy_warn(priv->hw->wiphy, "BH error -- can't suspend\n");
        return -EINVAL;
    }

    atomic_set(&priv->bh_suspend, WFX_BH_SUSPEND);
    wake_up(&priv->bh_wq);
    return wait_event_timeout(priv->bh_evt_wq, priv->bh_error ||
        (WFX_BH_SUSPENDED == atomic_read(&priv->bh_suspend)),
         1 * HZ) ? 0 : -ETIMEDOUT;
}

int wfx_bh_resume(struct wfx_common *priv)
{
    pr_debug("[BH] resume.\n");
    if (priv->bh_error) {
        wiphy_warn(priv->hw->wiphy, "BH error -- can't resume\n");
        return -EINVAL;
    }

    atomic_set(&priv->bh_suspend, WFX_BH_RESUME);
    wake_up(&priv->bh_wq);
    return wait_event_timeout(priv->bh_evt_wq, priv->bh_error ||
        (WFX_BH_RESUMED == atomic_read(&priv->bh_suspend)),
        1 * HZ) ? 0 : -ETIMEDOUT;
}

int wsm_release_tx_buffer(struct wfx_common *priv, int count)
{
    int ret = 0;
    int hw_bufs_used = priv->hw_bufs_used;

    priv->hw_bufs_used -= count;
    if (WARN_ON(priv->hw_bufs_used < 0))
        ret = -1;
    else if (hw_bufs_used >= priv->wsm_caps.NumInpChBufs)
        ret = 1;
    if (!priv->hw_bufs_used)
        wake_up(&priv->bh_evt_wq);
    return ret;
}

static int wfx_device_wakeup(struct wfx_common *priv)
{
    HiCtrlReg_t Control_reg;
    int ret;

    pr_debug("[BH] %s  Device wakeup.\n",__func__);

    /* To force the device to be always-on, the host sets WLAN_UP to 1 */
    Control_reg.U16CtrlReg = 0;
    Control_reg.b.WlanWup = WLAN_WAKEUP;
    ret = control_reg_write(priv, Control_reg);
    if (WARN_ON(ret))
        return ret;

    ret = wfx_bh_read_ctrl_reg(priv, &Control_reg);
    if (WARN_ON(ret)) {
        return ret;
    }

    /* If the device returns WLAN_RDY as 1, the device is active and will
     * remain active.*/
    if (Control_reg.b.WlanRdy) {
        pr_debug("[BH] %s Device awake.\n",__func__);
        return 1;
    }

    return 0;
}

/* Must be called from BH thraed */
void wfx_enable_powersave(struct wfx_common *priv,
                 bool enable)
{
    pr_debug("[BH] Powerave is %s.\n",
         enable ? "enabled" : "disabled");
    priv->powersave_enabled = enable;
}

static int wfx_bh_rx_helper(struct wfx_common *priv,
                   uint16_t *ctrl_reg,
                   int *tx)
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


    read_len = (*ctrl_reg & WF200_CTRL_NEXT_LEN_MASK) * 2;
    if (!read_len) {
        return 0;
    }

    if (WARN_ON((read_len < sizeof(HiMsgHdr_t)) ||
            (read_len > EFFECTIVE_BUF_SIZE))) {
        pr_debug("Invalid read len: %zu (%04x)",
             read_len, *ctrl_reg);
        goto err;
    }

    read_len = read_len + 2;

    alloc_len = priv->hwbus_ops->align_size(
        priv->hwbus_priv, read_len);

    /* Check if not exceeding wfx capabilities */
    if (WARN_ON_ONCE(alloc_len > EFFECTIVE_BUF_SIZE)) {
        pr_debug("Read aligned len: %zu\n",
             alloc_len);
    }

    skb_rx = dev_alloc_skb(alloc_len);
    if (WARN_ON(!skb_rx))
        goto err;

    skb_trim(skb_rx, 0);
    skb_put(skb_rx, read_len);
    data = skb_rx->data;
    if (WARN_ON(!data))
        goto err;

    if (WARN_ON(wfx_data_read(priv, data, alloc_len))) {
        pr_err("rx blew up, len %zu\n", alloc_len);
        goto err;
    }

    *ctrl_reg = __le16_to_cpu(
        ((__le16 *)data)[alloc_len / 2 - 1]);

    wsm = (HiMsgHdr_t *)data;
    wsm_len = __le16_to_cpu(wsm->MsgLen);
    if (WARN_ON(wsm_len > read_len))
        goto err;

    if (priv->wsm_enable_wsm_dumps)
        print_hex_dump_bytes("<-- ",
                     DUMP_PREFIX_NONE,
                     data, wsm_len);

    wsm_id  = wsm->s.t.MsgId;
    wsm_info  = wsm->s.t.MsgInfo;
    wsm_seq = (wsm_info >> 3) & HI_MSG_SEQ_RANGE;

    skb_trim(skb_rx, wsm_len);

    if (wsm_id == HI_IND_BASE) {
        wsm_handle_exception(priv,
                     &data[sizeof(*wsm)],
                     wsm_len - sizeof(*wsm));
        goto err;
    } else if (!rx_resync) {
        if (WARN_ON(wsm_seq != priv->wsm_rx_seq))
            goto err;
    }
    priv->wsm_rx_seq = (wsm_seq + 1) & 7;
    rx_resync = 0;

    if ((wsm_id & HI_MSG_TYPE_MASK) == 0) {
        int rc = wsm_release_tx_buffer(priv, 1);
        if (WARN_ON(rc < 0))
            return rc;
        else if (rc > 0)
            *tx = 1;
    }

    /* wfx_wsm_rx takes care on SKB livetime */
    if (WARN_ON(wsm_handle_rx(priv, wsm, &skb_rx))){
        pr_err("wsm_handle_rx id=0x02%x\n",wsm_id);
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

static int wfx_bh_tx_helper(struct wfx_common *priv,
                   int *pending_tx,
                   int *tx_burst)
{
    size_t tx_len;
    u8 *data;
    int ret;
    HiMsgHdr_t *wsm;

    if (priv->device_can_sleep) {
        ret = wfx_device_wakeup(priv);
        if (WARN_ON(ret < 0)) { /* Error in wakeup */
            *pending_tx = 1;
            return 0;
        } else if (ret) { /* Woke up */
            priv->device_can_sleep = false;
        } else { /* Did not awake */
            *pending_tx = 1;
            return 0;
        }
    }

    wsm_alloc_tx_buffer(priv);
    ret = wsm_get_tx(priv, &data, &tx_len, tx_burst);
    if (ret <= 0) {
        wsm_release_tx_buffer(priv, 1);
        if (WARN_ON(ret < 0)) {
            return ret; /* Error */
        }
        return 0; /* No work */
    }

    wsm = (HiMsgHdr_t *)data;
    BUG_ON(tx_len < sizeof(*wsm));
    BUG_ON(__le16_to_cpu(wsm->MsgLen) != tx_len);

    atomic_add(1, &priv->bh_tx);

    tx_len = priv->hwbus_ops->align_size(
        priv->hwbus_priv, tx_len);

    /* Check if not exceeding wfx capabilities */
    if (WARN_ON_ONCE(tx_len > EFFECTIVE_BUF_SIZE))
        pr_debug("Write aligned len: %zu\n", tx_len);

    wsm->s.t.MsgInfo &= 0xff ^ WSM_TX_SEQ(HI_MSG_SEQ_RANGE);
    wsm->s.t.MsgInfo |= WSM_TX_SEQ(priv->wsm_tx_seq);

    if (WARN_ON(wfx_data_write(priv, data, tx_len))) {
        pr_err("tx blew up, len %zu\n", tx_len);
        wsm_release_tx_buffer(priv, 1);
        return -1; /* Error */
    }

    if (priv->wsm_enable_wsm_dumps)
        print_hex_dump_bytes("--> ",
                     DUMP_PREFIX_NONE,
                     data,
                     __le16_to_cpu(wsm->MsgLen));

    wsm_txed(priv, data);
    priv->wsm_tx_seq = (priv->wsm_tx_seq + 1) & HI_MSG_SEQ_RANGE;

    if (*tx_burst > 1) {
        wfx_debug_tx_burst(priv);
        return 1; /* Work remains */
    }

    return 0;
}

static int wfx_bh(void *arg)
{
    struct wfx_common *priv = arg;
    int rx, tx, term, suspend;
    HiCtrlReg_t ctrl_reg = { .U16CtrlReg = 0 };
    int tx_allowed;
    int pending_tx = 0;
    int tx_burst;
    long status;
    int ret;

    for (;;) {
        if (!priv->hw_bufs_used &&
            priv->powersave_enabled &&
            !priv->device_can_sleep &&
            !atomic_read(&priv->recent_scan)) {
            status = 1 * HZ;
            pr_debug("[BH] Device wakedown. No data.\n");
            ctrl_reg.b.WlanWup = WLAN_WAKEDOWN;
            control_reg_write(priv, ctrl_reg);
            priv->device_can_sleep = true;
        } else if (priv->hw_bufs_used) {
            status = 1 * HZ;
        } else {
            status = MAX_SCHEDULE_TIMEOUT;
        }

        if ((priv->hw_type != -1) &&
            (atomic_read(&priv->bh_rx) == 0) &&
            (atomic_read(&priv->bh_tx) == 0)) {
            HiCfgReg_t config_reg_dummy;
            pr_debug("[BH] Dummy Read for SDIO retry mechanism.\n");
            config_reg_read(priv, &config_reg_dummy);
        }

        pr_debug("[BH] waiting ..., conf_mutex: %d\n",mutex_is_locked(&priv->conf_mutex));

        status = wait_event_interruptible_timeout(priv->bh_wq, ({
                rx = atomic_xchg(&priv->bh_rx, 0);
                tx = atomic_xchg(&priv->bh_tx, 0);
                term = atomic_xchg(&priv->bh_term, 0);
                suspend = pending_tx ?
                    0 : atomic_read(&priv->bh_suspend);
                (rx || tx || term || suspend || priv->bh_error);
            }), status);

        pr_debug("[BH] - rx: %d, tx: %d, term: %d, bh_err: %d, suspend: %d, status: %ld , conf_mutex: %d\n",
             rx, tx, term, suspend, priv->bh_error, status , mutex_is_locked(&priv->conf_mutex) );

        /* Did an error occur? */
        if ((status < 0 && status != -ERESTARTSYS) ||
            term || priv->bh_error) {
            break;
        }

        /* wait_event timed out */
        if (!status) {
            unsigned long timestamp = jiffies;
            long timeout;
            int pending = 0;
            int i;

            /* Check to see if we have any outstanding frames */
            if (priv->hw_bufs_used && (!rx || !tx)) {
                wiphy_warn(priv->hw->wiphy,
                       "Missed interrupt? (%d frames outstanding)\n",
                       priv->hw_bufs_used);
                rx = 1;

                /* Get a timestamp of "oldest" frame */
                for (i = 0; i < 4; ++i)
                    pending += wfx_queue_get_xmit_timestamp(
                        &priv->tx_queue[i],
                        &timestamp,
                        priv->pending_frame_id);
                timeout = timestamp +
                    WSM_CMD_LAST_CHANCE_TIMEOUT +
                    1 * HZ  -
                    jiffies;

                /* And terminate BH thread if the frame is "stuck" */
                if (pending && timeout < 0) {
                    wiphy_warn(priv->hw->wiphy,
                           "Timeout waiting for TX confirm (%d/%d pending, %ld vs %lu).\n",
                           priv->hw_bufs_used, pending,
                           timestamp, jiffies);
                }
            } else if (!priv->device_can_sleep &&
                   !atomic_read(&priv->recent_scan)) {
                pr_debug("[BH] Device wakedown. Timeout.\n");
                ctrl_reg.b.WlanWup = WLAN_WAKEDOWN;
                control_reg_write(priv, ctrl_reg);
                priv->device_can_sleep = true;
            }
            goto done;
        } else if (suspend) {
            pr_debug("[BH] Device suspend.\n");
            if (priv->powersave_enabled) {
                pr_debug("[BH] Device wakedown. Suspend.\n");
                ctrl_reg.b.WlanWup = WLAN_WAKEDOWN;
                control_reg_write(priv, ctrl_reg);
                priv->device_can_sleep = true;
            }

            atomic_set(&priv->bh_suspend, WFX_BH_SUSPENDED);
            wake_up(&priv->bh_evt_wq);
            status = wait_event_interruptible(priv->bh_wq,
                              WFX_BH_RESUME == atomic_read(&priv->bh_suspend));
            if (status < 0) {
                wiphy_err(priv->hw->wiphy,
                      "Failed to wait for resume: %ld.\n",
                      status);
                break;
            }
            pr_debug("[BH] Device resume.\n");
            atomic_set(&priv->bh_suspend, WFX_BH_RESUMED);
            wake_up(&priv->bh_evt_wq);
            atomic_add(1, &priv->bh_rx);
            goto done;
        }

    rx:
        tx += pending_tx;
        pending_tx = 0;

        if (wfx_bh_read_ctrl_reg(priv, &ctrl_reg))
            break;

        {
            int exit = 0;
            while ((ctrl_reg.U16CtrlReg & WF200_CTRL_NEXT_LEN_MASK)
                        && (exit < 32 ))
            {
                ret = wfx_bh_rx_helper(priv, (uint16_t *)&ctrl_reg, &tx);
                if (ret < 0) {
                    break;
                }
                exit ++;
            }
        }

    tx:
        tx += atomic_xchg(&priv->bh_tx, 0);
        if (tx) {

            BUG_ON(priv->hw_bufs_used > priv->wsm_caps.NumInpChBufs);
            tx_burst = priv->wsm_caps.NumInpChBufs - priv->hw_bufs_used;
            tx_allowed = tx_burst > 0;
            if (!tx_allowed) {
                pending_tx = tx;
                goto done_rx;
            }

            {
                int exit = 0;
                do
                {
                    ret = wfx_bh_tx_helper(priv, &pending_tx, &tx_burst);
                    tx--;
                    exit++;
                }
                while((exit < 4)&&(tx > 0));
            }
            tx = 0;

            if (ret < 0) {
                break;
            }
            /* More to transmit */
            if (ret > 0) {
                tx = ret;
            }

            /* Re-read ctrl reg */
            if (wfx_bh_read_ctrl_reg(priv, &ctrl_reg)) {
                break;
            }
        }

    done_rx:
        if (priv->bh_error)
            break;
        if (ctrl_reg.U16CtrlReg & WF200_CTRL_NEXT_LEN_MASK)
            goto rx;
        if (tx)
            goto tx;

    done:
        pr_debug("[BH] loop done.\n");
    }

    if (!term) {
        pr_err("[BH] Fatal error, exiting.\n");
        priv->bh_error = 1;
    }
    return 0;
}
