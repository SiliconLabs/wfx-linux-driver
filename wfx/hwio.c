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
/*                 Standard Linux Headers             		              */
/*========================================================================*/
#include <linux/types.h>

/*========================================================================*/
/*                 Local Header files             			              */
/*========================================================================*/
#include "wfx.h"
#include "hwio.h"
#include "hwbus.h"

/*========================================================================*/
/*                  PRIVATE  Constants/Macros/Types/Variables             */
/*========================================================================*/
#define MAX_RETRY		3


/*========================================================================*/
/*                  Internally Static Functions                           */
/*========================================================================*/
/*
 * read/write registers 16 and 32 bits
 * with endianess conversion but no bus lock
 */
static inline int __wfx_reg_read_32(struct wfx_common *priv,
					u16 addr, u32 *val)
{
	__le32 tmp;
	int i = priv->hwbus_ops->hwbus_memcpy_fromio(priv->hwbus_priv, addr, &tmp, sizeof(tmp));
	*val = le32_to_cpu(tmp);
	return i;
}

static inline int __wfx_reg_write_32(struct wfx_common *priv,
					u16 addr, u32 val)
{
	__le32 tmp = cpu_to_le32(val);
	return priv->hwbus_ops->hwbus_memcpy_toio(priv->hwbus_priv, addr, &tmp, sizeof(tmp));
}

static inline int __wfx_reg_read_16(struct wfx_common *priv,
					u16 addr, u16 *val)
{
	__le16 tmp;
	int i = priv->hwbus_ops->hwbus_memcpy_fromio(priv->hwbus_priv, addr, &tmp, sizeof(tmp));
	*val = le16_to_cpu(tmp);
	return i;
}

static inline int __wfx_reg_write_16(struct wfx_common *priv,
					u16 addr, u16 val)
{
	__le16 tmp = cpu_to_le16(val);
	return priv->hwbus_ops->hwbus_memcpy_toio(priv->hwbus_priv, addr, &tmp, sizeof(tmp));
}


/*
 * read/write registers of any size
 * without endianess conversion but with bus lock
 */
static inline int wfx_reg_read(struct wfx_common *priv, u16 addr, void *buf, size_t buf_len)
{
	int ret;
	priv->hwbus_ops->lock(priv->hwbus_priv);
	ret = priv->hwbus_ops->hwbus_memcpy_fromio(priv->hwbus_priv, addr, buf, buf_len);
	priv->hwbus_ops->unlock(priv->hwbus_priv);
	return ret;
}

static inline int wfx_reg_write(struct wfx_common *priv, u16 addr, const void *buf, size_t buf_len)
{
	int ret;
	priv->hwbus_ops->lock(priv->hwbus_priv);
	ret = priv->hwbus_ops->hwbus_memcpy_toio(priv->hwbus_priv, addr, buf, buf_len);
	priv->hwbus_ops->unlock(priv->hwbus_priv);
	return ret;
}


/*
 * read data in sharedRAM or AHB
 */
static int wfx_indirect_read(struct wfx_common *priv, u32 addr, void *buf,
			 size_t buf_len, u32 prefetch, u16 port_addr)
{
	u32 val32 = 0;
	int i, ret;

	if ((buf_len / 2) >= 0x1000) {
		pr_err("Can't read more than 0xfff words.\n");
		return -EINVAL;
	}

	priv->hwbus_ops->lock(priv->hwbus_priv);
	/* Write address */
	ret = __wfx_reg_write_32(priv, WF200_BASE_ADDR_REG_ID, addr);
	if (ret < 0) {
		pr_err("Can't write address register.\n");
		goto out;
	}

	/* Read CONFIG Register Value - We will read 32 bits */
	ret = __wfx_reg_read_32(priv, WF200_CONFIG_REG_ID, &val32);
	if (ret < 0) {
		pr_err("Can't read config register.\n");
		goto out;
	}

	/* Set PREFETCH bit */
	ret = __wfx_reg_write_32(priv, WF200_CONFIG_REG_ID,
					val32 | prefetch);
	if (ret < 0) {
		pr_err("Can't write prefetch bit.\n");
		goto out;
	}

	/* Check for PRE-FETCH bit to be cleared */
	for (i = 0; i < 20; i++) {
		ret = __wfx_reg_read_32(priv, WF200_CONFIG_REG_ID, &val32);
		if (ret < 0) {
			pr_err("Can't check prefetch bit.\n");
			goto out;
		}
		if (!(val32 & prefetch))
			break;

		mdelay(i);
	}

	if (val32 & prefetch) {
		pr_err("Prefetch bit is not cleared.\n");
		goto out;
	}

	/* Read data port */
	ret = priv->hwbus_ops->hwbus_memcpy_fromio(priv->hwbus_priv, port_addr, buf, buf_len);
	if (ret < 0) {
		pr_err("Can't read data port.\n");
		goto out;
	}

out:
	priv->hwbus_ops->unlock(priv->hwbus_priv);
	return ret;
}


/*
 * write data in sharedRAM or AHB
 */
static int wfx_indirect_write(struct wfx_common *priv, u32 addr, const void *buf,
			 size_t buf_len, u16 port_addr)
{
	int ret;

	if ((buf_len / 2) >= 0x1000) {
		pr_err("Can't write more than 0xfff words.\n");
		return -EINVAL;
	}

	priv->hwbus_ops->lock(priv->hwbus_priv);

	/* Write address */
	ret = __wfx_reg_write_32(priv, WF200_BASE_ADDR_REG_ID, addr);
	if (ret < 0) {
		pr_err("Can't write address register.\n");
		goto out;
	}

	/* Write data port */
	ret = priv->hwbus_ops->hwbus_memcpy_toio(priv->hwbus_priv, port_addr, buf, buf_len);
	if (ret < 0) {
		pr_err("Can't write data port.\n");
		goto out;
	}

out:
	priv->hwbus_ops->unlock(priv->hwbus_priv);
	return ret;
}



/*========================================================================*/
/*                       Functions                                        */
/*========================================================================*/

/*
 * read and write registers for a 32bits or 16bits data.
 * It includes the conversion from Little Endian to the CPU endianess
 */
int wfx_reg_read_16(struct wfx_common *priv, u16 addr, u16 *val)
{
	__le16 tmp;
	int i;
	i = wfx_reg_read(priv, addr, &tmp, sizeof(tmp));
	*val = le16_to_cpu(tmp);
	return i;
}

int wfx_reg_write_16(struct wfx_common *priv, u16 addr, u16 val)
{
	__le16 tmp = cpu_to_le16(val);
	return wfx_reg_write(priv, addr, &tmp, sizeof(tmp));
}

int wfx_reg_read_32(struct wfx_common *priv, u16 addr, u32 *val)
{
	__le32 tmp;
	int i = wfx_reg_read(priv, addr, &tmp, sizeof(tmp));
	*val = le32_to_cpu(tmp);
	return i;
}

int wfx_reg_write_32(struct wfx_common *priv, u16 addr, u32 val)
{
	__le32 tmp = cpu_to_le32(val);
	return wfx_reg_write(priv, addr, &tmp, sizeof(val));
}


/*
 * read/write HIF messages
 */
int wfx_data_read(struct wfx_common *priv, void *buf, size_t buf_len)
{
	int ret, retry = 1;

	/* Check if buffer is aligned to 4 byte boundary */
	if (WARN_ON(((unsigned long)buf & 3) && (buf_len > 4))) {
		pr_err("buffer is not aligned.\n");
		return -EINVAL;
	}

	priv->hwbus_ops->lock(priv->hwbus_priv);

	while (retry <= MAX_RETRY) {
		ret = priv->hwbus_ops->hwbus_memcpy_fromio(priv->hwbus_priv,
				WF200_IN_OUT_QUEUE_REG_ID, buf, buf_len);
		if (!ret) {
			break;
		} else {
			retry++;
			mdelay(1);
			pr_err("read error :[%d]\n", ret);
		}
	}

	priv->hwbus_ops->unlock(priv->hwbus_priv);
	return ret;
}

int wfx_data_write(struct wfx_common *priv, const void *buf, size_t buf_len)
{
	int ret, retry = 1;

	priv->hwbus_ops->lock(priv->hwbus_priv);

	while (retry <= MAX_RETRY) {
		ret = priv->hwbus_ops->hwbus_memcpy_toio(priv->hwbus_priv,
				WF200_IN_OUT_QUEUE_REG_ID, buf, buf_len);
		if (!ret) {
			break;
		} else {
			retry++;
			mdelay(1);
			pr_err("write error :[%d]\n", ret);
		}
	}

	priv->hwbus_ops->unlock(priv->hwbus_priv);
	return ret;
}


/*
 * read and write in SRAM and AHB bus for any number of bytes
 */
int wfx_sram_read(struct wfx_common *priv, u32 addr, void *buf, size_t buf_len)
{
	return wfx_indirect_read(priv, addr, buf, buf_len,
		WF200_CONF_SRAM_PREFETCH_BIT, WF200_SRAM_DPORT_REG_ID);
}

int wfx_ahb_read(struct wfx_common *priv, u32 addr, void *buf, size_t buf_len)
{
	return wfx_indirect_read(priv, addr, buf, buf_len,
		WF200_CONF_AHB_PREFETCH_BIT, WF200_AHB_DPORT_REG_ID);
}

int wfx_sram_write(struct wfx_common *priv, u32 addr, const void *buf, size_t buf_len)
{
	return wfx_indirect_write(priv, addr, buf, buf_len, WF200_SRAM_DPORT_REG_ID);
}

int wfx_ahb_write(struct wfx_common *priv, u32 addr, const void *buf, size_t buf_len)
{
	return wfx_indirect_write(priv, addr, buf, buf_len, WF200_AHB_DPORT_REG_ID);
}


/*
 * read and write in SRAM and AHB bus for a 32bits data.
 * It includes the conversion from Little Endian to the CPU endianess
 */
inline int wfx_sram_read_32(struct wfx_common *priv, u32 addr, u32 *val)
{
	__le32 tmp;
	int i = wfx_sram_read(priv, addr, &tmp, sizeof(tmp));
	*val = le32_to_cpu(tmp);
	return i;
}

int wfx_ahb_read_32(struct wfx_common *priv, u32 addr, u32 *val)
{
	__le32 tmp;
	int i = wfx_ahb_read(priv, addr, &tmp, sizeof(tmp));
	*val = le32_to_cpu(tmp);
	return i;
}

int wfx_sram_write_32(struct wfx_common *priv, u32 addr, u32 val)
{
	__le32 tmp = cpu_to_le32(val);
	return wfx_sram_write(priv, addr, &tmp, sizeof(val));
}

int wfx_ahb_write_32(struct wfx_common *priv, u32 addr, u32 val)
{
	__le32 tmp = cpu_to_le32(val);
	return wfx_ahb_write(priv, addr, &tmp, sizeof(val));
}


/*
 *  read and write WF200_CONFIG register
 */
int config_reg_read(struct wfx_common *priv, HiCfgReg_t *val)
{
	return wfx_reg_read_32(priv, WF200_CONFIG_REG_ID, &val->U32ConfigReg);
}

int config_reg_write(struct wfx_common *priv, HiCfgReg_t val)
{
	return wfx_reg_write_32(priv, WF200_CONFIG_REG_ID, val.U32ConfigReg);
}


/*
 * read and write WF200_CONTROL register
 */
int control_reg_read(struct wfx_common *priv, HiCtrlReg_t *val)
{
	return wfx_reg_read_16(priv, WF200_CONTROL_REG_ID, &val->U16CtrlReg);
}

int control_reg_write(struct wfx_common *priv, HiCtrlReg_t val)
{
	return wfx_reg_write_16(priv, WF200_CONTROL_REG_ID, val.U16CtrlReg);
}


/*
 *
 */
int __wfx_irq_enable(struct wfx_common *priv, int enable)
{
	HiCfgReg_t Config_reg;
	int ret;

	ret = config_reg_read(priv, &Config_reg);
	if (ret < 0) {
			return ret;
		}

	if (enable)
		Config_reg.hif.IrqEnable = IRQS_ENABLED;
	else
		Config_reg.hif.IrqEnable = IRQS_DISABLED;

    ret = config_reg_write(priv, Config_reg);
	if (ret < 0) {
		return ret;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(__wfx_irq_enable);
