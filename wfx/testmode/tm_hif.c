/*
 * Copyright (c) 2017, Silicon Laboratories, Inc.
 *
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
/*                 Standard Linux Headers             					  */
/*========================================================================*/
#include <net/netlink.h>
#include <net/genetlink.h>
#include <linux/time.h>
#include "net/mac80211.h"

/*========================================================================*/
/*                 Local Header files             					      */
/*========================================================================*/
#include "include/wfx_testmode.h"
#include "include/prv_testmode.h"

/*========================================================================*/
/*                  PRIVATE  Constants/Macros/Types/Variables             */
/*========================================================================*/
#define TM_HIF_BUFFER_LEN (1024)

/*========================================================================*/
/*                  Structures definitions                                */
/*========================================================================*/

/** Time  **/
typedef struct  {
    time_t tv_sec;                /* Seconds */
    long   tv_nsec;               /* Nanoseconds */
} timespec;

typedef struct {
       time_t tv_sec;
    long   tv_nsec;               /* Nanoseconds */
       u16 cmdid;
} hif_log;

/*========================================================================*/
/*                  Internally Static Functions                           */
/*========================================================================*/
static void hif_buffer_flush(struct sk_buff *skb);
static hif_log l_as_hif_buffer[TM_HIF_BUFFER_LEN] ;
static uint16_t l_ui16_hif_buffer_set = 0;
static uint16_t l_ui16_hif_buffer_get = 0;

/* Unused : we want to see what's the startup sequence */
/* A configuration flag could be used to set the default value */
static bool l_b_hif_pm_enable = true;

/*========================================================================*/
/*                       Functions                                        */
/*========================================================================*/
int wfx_testmode_hif(struct ieee80211_hw *hw,struct nlattr **p_tb)
{
	switch (nla_get_u32(p_tb[WFX_TM_ATTR_CMD])) {

	case WFX_TM_CMD_HIF_ENABLE:
	{
		// Should not be called.
		l_b_hif_pm_enable = !l_b_hif_pm_enable;
	}

	case WFX_TM_CMD_HIF_FLUSH:
	{
		int ret;
		struct sk_buff *skb = cfg80211_testmode_alloc_reply_skb(hw->wiphy,
				sizeof(hif_log)*l_ui16_hif_buffer_set);

		if (!skb)
			return -ENOMEM;

		hif_buffer_flush(skb);

		ret = cfg80211_testmode_reply(skb);

        if(ret != 0)
        	pr_err("ret = %d\n",ret);
		break;
	}
	default:
		printk("Spi testmode\n");
		break;
	}
	return 0;
};

void hif_buffer_add(u16 id)
{
	struct timespec now  ;

	getnstimeofday(&now);

	if(false == l_b_hif_pm_enable ||
		TM_HIF_BUFFER_LEN == l_ui16_hif_buffer_set)
	{
		return;
	}

	l_as_hif_buffer[l_ui16_hif_buffer_set].cmdid = id;
	l_as_hif_buffer[l_ui16_hif_buffer_set].tv_sec= now.tv_sec;
	l_as_hif_buffer[l_ui16_hif_buffer_set].tv_nsec= now.tv_nsec;
	l_ui16_hif_buffer_set++;
}

void hif_buffer_flush(struct sk_buff *skb)
{
	uint16_t ui16_nbDataToFlush = l_ui16_hif_buffer_set - l_ui16_hif_buffer_get;


	nla_put_u32(skb, WFX_TM_ATTR_HIF_NB_LOGS, ui16_nbDataToFlush);
	nla_put(skb, WFX_TM_ATTR_HIF_DATA,
			ui16_nbDataToFlush * sizeof(hif_log),
			&(l_as_hif_buffer[l_ui16_hif_buffer_get]));

	l_ui16_hif_buffer_set = 0;
	l_ui16_hif_buffer_get = l_ui16_hif_buffer_set;
}
