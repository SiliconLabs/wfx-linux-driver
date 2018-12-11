#undef TRACE_SYSTEM
#define TRACE_SYSTEM wfx

#if !defined(_WFX_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _WFX_TRACE_H

#include <linux/tracepoint.h>
#include "wfx_api.h"
#include "hwbus.h"

#define wsm_msg_cnf_name(msg) { WSM_HI_##msg##_CNF_ID, #msg }
#define wsm_msg_ind_name(msg) { WSM_HI_##msg##_IND_ID, #msg }
#define low_msg_cnf_name(msg) { HI_##msg##_CNF_ID, #msg }
#define low_msg_ind_name(msg) { HI_##msg##_IND_ID, #msg }
#define _wsm_msg_list                           \
	wsm_msg_cnf_name(ADD_KEY),              \
	wsm_msg_cnf_name(BEACON_TRANSMIT),      \
	wsm_msg_cnf_name(EDCA_QUEUE_PARAMS),    \
	wsm_msg_cnf_name(JOIN),                 \
	wsm_msg_cnf_name(MAP_LINK),             \
	wsm_msg_cnf_name(READ_MIB),             \
	wsm_msg_cnf_name(REMOVE_KEY),           \
	wsm_msg_cnf_name(RESET),                \
	wsm_msg_cnf_name(SET_BSS_PARAMS),       \
	wsm_msg_cnf_name(SET_PM_MODE),          \
	wsm_msg_cnf_name(START),                \
	wsm_msg_cnf_name(START_SCAN),           \
	wsm_msg_cnf_name(STOP_SCAN),            \
	wsm_msg_cnf_name(TX),                   \
	wsm_msg_cnf_name(MULTI_TRANSMIT),       \
	wsm_msg_cnf_name(UPDATE_IE),            \
	wsm_msg_cnf_name(WRITE_MIB),            \
	wsm_msg_ind_name(EVENT),                \
	wsm_msg_ind_name(JOIN_COMPLETE),        \
	wsm_msg_ind_name(RX),                   \
	wsm_msg_ind_name(SCAN_CMPL),            \
	wsm_msg_ind_name(SET_PM_MODE_CMPL),     \
	wsm_msg_ind_name(SUSPEND_RESUME_TX),    \
	low_msg_cnf_name(CONFIGURATION),        \
	low_msg_cnf_name(CONTROL_GPIO),         \
	low_msg_cnf_name(PREVENT_ROLLBACK),     \
	low_msg_cnf_name(SET_SL_MAC_KEY),       \
	low_msg_cnf_name(SL_CONFIGURE),         \
	low_msg_cnf_name(SL_EXCHANGE_PUB_KEYS), \
	low_msg_ind_name(ERROR),                \
	low_msg_ind_name(EXCEPTION),            \
	low_msg_ind_name(GENERIC),              \
	low_msg_ind_name(STARTUP)

#define wsm_msg_list _wsm_msg_list

#define wsm_mib_name(mib) { WSM_MIB_ID_##mib, "/" #mib }
#define _wsm_mib_list                                 \
	wsm_mib_name(ARP_IP_ADDRESSES_TABLE),         \
	wsm_mib_name(ARP_KEEP_ALIVE_PERIOD),          \
	wsm_mib_name(BEACON_FILTER_ENABLE),           \
	wsm_mib_name(BEACON_FILTER_TABLE),            \
	wsm_mib_name(BEACON_WAKEUP_PERIOD),           \
	wsm_mib_name(BLOCK_ACK_POLICY),               \
	wsm_mib_name(CONFIG_DATA_FILTER),             \
	wsm_mib_name(COUNTERS_TABLE),                 \
	wsm_mib_name(CURRENT_TX_POWER_LEVEL),         \
	wsm_mib_name(DOT11_MAC_ADDRESS),              \
	wsm_mib_name(DOT11_MAX_RECEIVE_LIFETIME),     \
	wsm_mib_name(DOT11_MAX_TRANSMIT_MSDU_LIFETIME), \
	wsm_mib_name(DOT11_RTS_THRESHOLD),            \
	wsm_mib_name(DOT11_WEP_DEFAULT_KEY_ID),       \
	wsm_mib_name(GL_BLOCK_ACK_INFO),              \
	wsm_mib_name(GL_OPERATIONAL_POWER_MODE),      \
	wsm_mib_name(GL_SET_MULTI_MSG),               \
	wsm_mib_name(INACTIVITY_TIMER),               \
	wsm_mib_name(INTERFACE_PROTECTION),           \
	wsm_mib_name(IPV4_ADDR_DATAFRAME_CONDITION),  \
	wsm_mib_name(IPV6_ADDR_DATAFRAME_CONDITION),  \
	wsm_mib_name(KEEP_ALIVE_PERIOD),              \
	wsm_mib_name(MAC_ADDR_DATAFRAME_CONDITION),   \
	wsm_mib_name(NON_ERP_PROTECTION),             \
	wsm_mib_name(NS_IP_ADDRESSES_TABLE),          \
	wsm_mib_name(OVERRIDE_INTERNAL_TX_RATE),      \
	wsm_mib_name(PROTECTED_MGMT_POLICY),          \
	wsm_mib_name(RX_FILTER),                      \
	wsm_mib_name(RCPI_RSSI_THRESHOLD),            \
	wsm_mib_name(SET_ASSOCIATION_MODE),           \
	wsm_mib_name(SET_DATA_FILTERING),             \
	wsm_mib_name(ETHERTYPE_DATAFRAME_CONDITION),  \
	wsm_mib_name(SET_HT_PROTECTION),              \
	wsm_mib_name(MAGIC_DATAFRAME_CONDITION),      \
	wsm_mib_name(SET_TX_RATE_RETRY_POLICY),       \
	wsm_mib_name(SET_UAPSD_INFORMATION),          \
	wsm_mib_name(PORT_DATAFRAME_CONDITION),       \
	wsm_mib_name(SLOT_TIME),                      \
	wsm_mib_name(STATISTICS_TABLE),               \
	wsm_mib_name(TEMPLATE_FRAME),                 \
	wsm_mib_name(TSF_COUNTER),                    \
	wsm_mib_name(UC_MC_BC_DATAFRAME_CONDITION)

#define wsm_mib_list _wsm_mib_list

DECLARE_EVENT_CLASS(wsm_data,
	TP_PROTO(u16 *wsm_buf, bool is_recv),
	TP_ARGS(wsm_buf, is_recv),
	TP_STRUCT__entry(
		__field(int, msg_id)
		__field(const char *, msg_type)
		__field(int, msg_len)
		__field(int, buf_len)
		__field(int, if_id)
		__field(int, mib)
		__field(bool, is_longer)
		__array(u8, buf, 32)
	),
	TP_fast_assign(
		int header_len;
		__entry->msg_len = le16_to_cpu(wsm_buf[0]);
		__entry->msg_id = le16_to_cpu(wsm_buf[1]) & 0xFF;
		__entry->if_id = (le16_to_cpu(wsm_buf[1]) >> 9) & 3;
		if (is_recv)
			__entry->msg_type = __entry->msg_id & 0x80 ? "IND" : "CNF";
		else
			__entry->msg_type = "REQ";
		if (!is_recv &&
		    (__entry->msg_id == WSM_HI_READ_MIB_REQ_ID || __entry->msg_id == WSM_HI_WRITE_MIB_REQ_ID)) {
			__entry->mib = le16_to_cpu(wsm_buf[2]);
			header_len = 8;
		} else {
			__entry->mib = -1;
			header_len = 4;
		}
		__entry->is_longer =  __entry->msg_len - header_len > 32 ? true : false;
		__entry->buf_len = min(32, __entry->msg_len - header_len);
		memcpy(__entry->buf, ((char *) wsm_buf) + header_len, __entry->buf_len);
	),
	TP_printk("%d:%s_%s%s: %s%s (%d bytes)",
		__entry->if_id,
		__print_symbolic(__entry->msg_id, wsm_msg_list),
		__entry->msg_type,
		__entry->mib != -1 ? __print_symbolic(__entry->mib, wsm_mib_list) : "",
		__print_hex(__entry->buf, __entry->buf_len),
		__entry->is_longer ? " ..." : "",
		__entry->msg_len
	)
);
DEFINE_EVENT(wsm_data, wsm_send,
	TP_PROTO(u16 *wsm_buf, bool is_recv),
	TP_ARGS(wsm_buf, is_recv));
#define _trace_wsm_send(wsm_buf) trace_wsm_send(wsm_buf, false)
DEFINE_EVENT(wsm_data, wsm_recv,
	TP_PROTO(u16 *wsm_buf, bool is_recv),
	TP_ARGS(wsm_buf, is_recv));
#define _trace_wsm_recv(wsm_buf) trace_wsm_recv(wsm_buf, true)

#define wfx_reg_list                             \
	{ WFX_REG_CONTROL,      "CONTROL"     }, \
	{ WFX_REG_CONFIG,       "CONFIG"      }, \
	{ WFX_REG_CONTROL,      "CONTROL"     }, \
	{ WFX_REG_IN_OUT_QUEUE, "QUEUE"       }, \
	{ WFX_REG_AHB_DPORT,    "AHB"         }, \
	{ WFX_REG_BASE_ADDR,    "BASE_ADDR"   }, \
	{ WFX_REG_SRAM_DPORT,   "SRAM"        }, \
	{ WFX_REG_SET_GEN_R_W,  "SET_GEN_R_W" }, \
	{ WFX_REG_FRAME_OUT,    "FRAME_OUT"   }

DECLARE_EVENT_CLASS(io_data32,
	TP_PROTO(int reg, int addr, u32 val),
	TP_ARGS(reg, addr, val),
	TP_STRUCT__entry(
		__field(int, reg)
		__field(int, addr)
		__field(int, val)
		__array(u8, addr_str, 10)
	),
	TP_fast_assign(
		__entry->reg = reg;
		__entry->addr = addr;
		__entry->val = val;
		if (addr >= 0)
			snprintf(__entry->addr_str, 10, "/%08x", addr);
		else
			__entry->addr_str[0] = 0;
	),
	TP_printk("%s%s: %08x",
		__print_symbolic(__entry->reg, wfx_reg_list),
		__entry->addr_str,
		__entry->val
	)
);
DEFINE_EVENT(io_data32, io_write32,
	TP_PROTO(int reg, int addr, u32 val),
	TP_ARGS(reg, addr, val));
#define _trace_io_ind_write32(reg, addr, val) trace_io_write32(reg, addr, val)
#define _trace_io_write32(reg, val) trace_io_write32(reg, -1, val)
DEFINE_EVENT(io_data32, io_read32,
	TP_PROTO(int reg, int addr, u32 val),
	TP_ARGS(reg, addr, val));
#define _trace_io_ind_read32(reg, addr, val) trace_io_read32(reg, addr, val)
#define _trace_io_read32(reg, val) trace_io_read32(reg, -1, val)

DECLARE_EVENT_CLASS(io_data,
	TP_PROTO(int reg, int addr, const void *io_buf, size_t len),
	TP_ARGS(reg, addr, io_buf, len),
	TP_STRUCT__entry(
		__field(int, reg)
		__field(int, addr)
		__field(int, msg_len)
		__field(int, buf_len)
		__array(u8, buf, 32)
		__array(u8, addr_str, 10)
	),
	TP_fast_assign(
		__entry->reg = reg;
		__entry->addr = addr;
		__entry->msg_len = len;
		__entry->buf_len = min(32, __entry->msg_len);
		memcpy(__entry->buf, io_buf, __entry->buf_len);
		if (addr >= 0)
			snprintf(__entry->addr_str, 10, "/%08x", addr);
		else
			__entry->addr_str[0] = 0;
	),
	TP_printk("%s%s: %s%s (%d bytes)",
		__print_symbolic(__entry->reg, wfx_reg_list),
		__entry->addr_str,
		__print_hex(__entry->buf, __entry->buf_len),
		__entry->buf_len != __entry->msg_len ? " ..." : "",
		__entry->msg_len
	)
);
DEFINE_EVENT(io_data, io_write,
	TP_PROTO(int reg, int addr, const void *io_buf, size_t len),
	TP_ARGS(reg, addr, io_buf, len));
#define _trace_io_ind_write(reg, addr, io_buf, len) trace_io_write(reg, addr, io_buf, len)
#define _trace_io_write(reg, io_buf, len) trace_io_write(reg, -1, io_buf, len)
DEFINE_EVENT(io_data, io_read,
	TP_PROTO(int reg, int addr, const void *io_buf, size_t len),
	TP_ARGS(reg, addr, io_buf, len));
#define _trace_io_ind_read(reg, addr, io_buf, len) trace_io_read(reg, addr, io_buf, len)
#define _trace_io_read(reg, io_buf, len) trace_io_read(reg, -1, io_buf, len)

#endif

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE traces

#include <trace/define_trace.h>
