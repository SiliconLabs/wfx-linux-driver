/*
 * Copyright (c) 2017, Silicon Laboratories, Inc.
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

#ifndef WFX_TESTMODE_UAPI_H
#define WFX_TESTMODE_UAPI_H

#define WFX_MAX_DATA_LENGTH 1024
#define LEN_MSG_PL          0x0004
#define MSG_PL              0x0000
#define RESET_MEM_VALUE     0x00000000
#define UAPSD_ENABLE_TM     0x0001
#define UAPSD_DISABLE_TM    0x0000

#define NLA_MAX_TYPE        7

/* PLEASE KEEP ORDER */

enum wfx_testmode_attr {
	__WFX_TM_ATTR_INVALID	= 0,
	WFX_TM_ATTR_TYPE	= 1,
	WFX_TM_ATTR_CMD		= 2,

	__WFX_TM_ATTR_AFTER_LAST,
	WFX_TM_ATTR_MAX		= __WFX_TM_ATTR_AFTER_LAST - 1
};

enum wfx_testmode_type {
	__WFX_TM_ATTR_TYPE_INVALD	= 0,
	WFX_TM_ATTR_TYPE_REGISTER	= 1,
	WFX_TM_ATTR_TYPE_UAPSD		= 2,
	WFX_TM_ATTR_TYPE_BITSTEAM	= 4,
	WFX_TM_ATTR_TYPE_ACCESSMODE	= 5,
	WFX_TM_ATTR_TYPE_FW_TEST	= 6,
	WFX_TM_ATTR_TYPE_READ_REG	= 7,
	WFX_TM_ATTR_TYPE_WRITE_REG	= 8
};

enum wfx_testmode_attr_reg {
	__WFX_TM_ATTR_REG_INVALID_0	= 0,    /* Used for common attributes */
	__WFX_TM_ATTR_REG_INVALID_1	= 1,    /* Used for common attributes */
	__WFX_TM_ATTR_REG_INVALID_2	= 2,    /* Used for common attributes */
	WFX_TM_ATTR_REG_MEM		= 3,
	WFX_TM_ATTR_REG_DATA		= 4,
	WFX_TM_ATTR_REG_VALUE		= 5,
	__WFX_TM_ATTR_AFTER_LAST_REG,
	WFX_TM_ATTR_MAX_REG		= __WFX_TM_ATTR_AFTER_LAST_REG - 1
};

enum wfx_testmode_cmd_reg {
	WFX_TM_CMD_REG_INVALID		= 0,
	WFX_TM_CMD_REG_MSG_SET		= 1,
	WFX_TM_CMD_REG_MSG_GET		= 2,
	WFX_TM_CMD_REG_DIRECT_SET	= 3,
	WFX_TM_CMD_REG_DIRECT_GET	= 4,
};

enum wfx_testmode_attr_accessmode {
	__WFX_TM_ATTR_ACCESSMODE_INVALID_0	= 0,    /* Used for common attributes */
	__WFX_TM_ATTR_ACCESSMODE_INVALID_1	= 1,    /* Used for common attributes */
	__WFX_TM_ATTR_ACCESSMODE_INVALID_2	= 2,    /* Used for common attributes */
	WFX_TM_ATTR_ACCESSMODE_VALUE		= 3,
	__WFX_TM_ATTR_AFTER_LAST_ACCESSMODE,
	WFX_TM_ATTR_MAX_ACCESSMODE		=
		__WFX_TM_ATTR_AFTER_LAST_ACCESSMODE - 1
};

enum wfx_testmode_cmd_accessmode {
	WFX_TM_CMD_ACCESSMODE_INVALID	= 0,
	WFX_TM_CMD_ACCESSMODE_SET	= 1,
	WFX_TM_CMD_ACCESSMODE_GET	= 2,
};

enum wfx_testmode_attr_uapsd {
	__WFX_TM_ATTR_UAPSD_INVALID_0	= 0,    /* Used for common attributes */
	WFX_TM_ATTR_UAPSD_AC		= 1,    /* like WFX_TM_ATTR_REG_MEM */
	WFX_TM_ATTR_UAPSD_AC_VALUE	= 2,    /* like WFX_TM_ATTR_REG_VALUE */
	WFX_TM_ATTR_UAPSD_VO_VALUE	= 3,
	WFX_TM_ATTR_UAPSD_VI_VALUE	= 4,
	WFX_TM_ATTR_UAPSD_BE_VALUE	= 5,
	WFX_TM_ATTR_UAPSD_BK_VALUE	= 6,
	__WFX_TM_ATTR_AFTER_LAST_UAPSD,
	WFX_TM_ATTR_MAX_UAPSD		= __WFX_TM_ATTR_AFTER_LAST_UAPSD - 1
};

enum wfx_testmode_cmd_uapsd {
	__WFX_TM_CMD_UAPSD_INVALID	= 0,
	WFX_TM_CMD_UAPSD_SET		= 1,
	WFX_TM_CMD_UAPSD_GET		= 2,
};

enum wfx_testmode_attr_bitstream {
	__WFX_TM_ATTR_BS_INVALID_0	= 0,    /* Used for common attributes */
	__WFX_TM_ATTR_BS_INVALID_1	= 1,    /* Used for common attributes */
	__WFX_TM_ATTR_BS_INVALID_2	= 2,    /* Used for common attributes */
	WFX_TM_ATTR_BS_BUFF_LEN		= 3,
	WFX_TM_ATTR_BS_BUFF		= 4,
	__WFX_TM_ATTR_AFTER_LAST_BS,
	WFX_TM_ATTR_MAX_BS		= __WFX_TM_ATTR_AFTER_LAST_BS - 1
};

enum wfx_testmode_cmd_bitstream {
	__WFX_TM_CMD_BS_INVALID = 0,
	WFX_TM_CMD_BS_ENABLE	= 1,
	WFX_TM_CMD_BS_FLUSH	= 2,
};

enum wfx_testmode_attr_readreg {
	__WFX_TM_ATTR_READ_REG_INVALID_0	= 0,    /* Used for common attributes */
	__WFX_TM_ATTR_READ_REG_INVALID_1	= 1,    /* Used for common attributes */
	__WFX_TM_ATTR_READ_REG_INVALID_2	= 2,    /* Used for common attributes */
	WFX_TM_ATTR_READ_REG_ADDR		= 3,
	WFX_TM_ATTR_READ_REG_LEN		= 4,
	WFX_TM_ATTR_READ_REG_VALUE		= 5,
	__WFX_TM_ATTR_AFTER_LAST_READ_REG,
	WFX_TM_ATTR_MAX_READ_REG		=
		__WFX_TM_ATTR_AFTER_LAST_READ_REG - 1
};

enum wfx_testmode_cmd_readreg {
	WFX_TM_CMD_READ_REG_INVALID	= 0,
	WFX_TM_CMD_READ_REG_GET		= 1,
};

enum wfx_testmode_attr_writereg {
	__WFX_TM_ATTR_WRITE_REG_INVALID_0	= 0,    /* Used for common attributes */
	__WFX_TM_ATTR_WRITE_REG_INVALID_1	= 1,    /* Used for common attributes */
	__WFX_TM_ATTR_WRITE_REG_INVALID_2	= 2,    /* Used for common attributes */
	WFX_TM_ATTR_WRITE_REG_ADDR		= 3,
	WFX_TM_ATTR_WRITE_REG_DATA		= 4,
	WFX_TM_ATTR_WRITE_REG_LEN		= 5,
	__WFX_TM_ATTR_AFTER_LAST_WRITE_REG,
	WFX_TM_ATTR_MAX_WRITE_REG		=
		__WFX_TM_ATTR_AFTER_LAST_WRITE_REG - 1
};

enum wfx_testmode_cmd_writereg {
	WFX_TM_CMD_WRITE_REG_INVALID	= 0,
	WFX_TM_CMD_WRITE_REG_SET	= 1,
};

#endif /* WFX_TESTMODE_UAPI_H */
