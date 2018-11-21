/*
 * Firmware I/O code for mac80211 Silicon Labs WFX drivers
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

#include <linux/version.h>
#include <linux/firmware.h>

#if (KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE)
#include <linux/bitfield.h>
#else
#define FIELD_GET(_mask, _reg) (typeof(_mask))(((_reg) & (_mask)) >> (__builtin_ffsll(_mask) - 1))
#endif

#include "fwio.h"
#include "wfx.h"
#include "hwio.h"

// Addresses below are in SRAM area
#define WFX_DNLD_FIFO             0x09004000
#define     DNLD_BLOCK_SIZE           0x0400
#define     DNLD_FIFO_SIZE            0x8000 // (32 * DNLD_BLOCK_SIZE)
// Download Control Area (DCA)
#define WFX_DCA_IMAGE_SIZE        0x0900C000
#define WFX_DCA_PUT               0x0900C004
#define WFX_DCA_GET               0x0900C008
#define WFX_DCA_HOST_STATUS       0x0900C00C
#define     HOST_READY                0x87654321
#define     HOST_INFO_READ            0xA753BD99
#define     HOST_UPLOAD_PENDING       0xABCDDCBA
#define     HOST_UPLOAD_COMPLETE      0xD4C64A99
#define     HOST_OK_TO_JUMP           0x174FC882
#define WFX_DCA_NCP_STATUS        0x0900C010
#define     NCP_NOT_READY             0x12345678
#define     NCP_READY                 0x87654321
#define     NCP_INFO_READY            0xBD53EF99
#define     NCP_DOWNLOAD_PENDING      0xABCDDCBA
#define     NCP_DOWNLOAD_COMPLETE     0xCAFEFECA
#define     NCP_AUTH_OK               0xD4C64A99
#define     NCP_AUTH_FAIL             0x174FC882
#define     NCP_PUB_KEY_RDY           0x7AB41D19
#define WFX_DCA_FW_SIGNATURE      0x0900C014
#define     FW_SIGNATURE_SIZE         0x40
#define WFX_DCA_FW_HASH           0x0900C054
#define     FW_HASH_SIZE              0x08
#define WFX_DCA_FW_VERSION        0x0900C05C
#define     FW_VERSION_SIZE           0x04
#define WFX_DCA_RESERVED          0x0900C060
#define     DCA_RESERVED_SIZE         0x20
#define WFX_STATUS_INFO           0x0900C080
#define WFX_BOOTLOADER_LABEL      0x0900C084
#define     BOOTLOADER_LABEL_SIZE     0x3C
#define WFX_PTE_INFO              0x0900C0C0
#define     PTE_INFO_KEYSET_IDX       0x0D
#define     PTE_INFO_SIZE             0x10
#define WFX_ERR_INFO              0x0900C0D0
#define     ERR_INVALID_SEC_TYPE      0x05
#define     ERR_SIG_VERIF_FAILED      0x0F
#define     ERR_AES_CTRL_KEY          0x10
#define     ERR_ECC_PUB_KEY           0x11
#define     ERR_MAC_KEY               0x18

#define DCA_TIMEOUT  50 // milliseconds
#define WAKEUP_TIMEOUT 200 // milliseconds

static const char * const fwio_error_strings[] = {
	[ERR_INVALID_SEC_TYPE] = "Invalid section type (may be caused by a wrong encryption)",
	[ERR_SIG_VERIF_FAILED] = "Signature verification failed",
	[ERR_AES_CTRL_KEY] = "AES control key not initialized",
	[ERR_ECC_PUB_KEY] = "ECC public key not initialized",
	[ERR_MAC_KEY] = "MAC key not initialized",
};

/*
 * request_firmware() allocate data using vmalloc(). It is not compatible with
 * underlying hardware that use DMA. Function below detect this case and
 * allocate a bounce buffer if necessary.
 *
 * Notice that, in doubt, you can enable CONFIG_DEBUG_SG to ask kernel to
 * detect this problem at runtime  (else, kernel silently fail).
 *
 * NOTE: it may also be possible to use 'pages' from struct firmware and avoid
 * bounce buffer
 */
int sram_write_dma_safe(struct wfx_dev *wdev, u32 addr, const u8 *buf, size_t len)
{
	int ret;
	const u8 *tmp;

	if (!virt_addr_valid(buf)) {
		tmp = kmemdup(buf, len, GFP_KERNEL);
		if (!tmp)
			return -ENOMEM;
	} else {
		tmp = buf;
	}
	ret = sram_buf_write(wdev, addr, tmp, len);
	if (!virt_addr_valid(buf))
		kfree(tmp);
	return ret;
}

/*
 * Decode keyset from firmware buffer and read accepted key from chip. Return
 * an error if keyset are incompatible else offset to use in file (0 or 8).
 */
static int get_keyset_offset(struct wfx_dev *wdev, const u8 *firmware)
{
	/* SDIO hosts does not all correctly support unaligned buffers */
	u8 buf[PTE_INFO_SIZE] __aligned(sizeof(void *));
	u32 keyset_chip;
	int keyset_file;
	int start_offset;

	sram_buf_read(wdev, WFX_PTE_INFO, buf, PTE_INFO_SIZE);
	keyset_chip = buf[PTE_INFO_KEYSET_IDX];
	if (memcmp(firmware, "KEYSET", 6) != 0) {
		// Legacy firmware format
		start_offset = 0;
		keyset_file = 0x90;
	} else {
		start_offset = 8;
		keyset_file = (hex_to_bin(firmware[6]) * 16) | hex_to_bin(firmware[7]);
		if (keyset_file < 0)
			return -EINVAL;
	}
	if (keyset_file != keyset_chip) {
		dev_err(wdev->pdev, "firmware keyset is incompatible with chip (file: 0x%02X, chip: 0x%02X)\n",
			keyset_file, keyset_chip);
		return -ENODEV;
	}
	return start_offset;
}

static int wait_ncp_status(struct wfx_dev *wdev, u32 status)
{
	ktime_t time_zero, now, start;
	u32 reg;
	int ret;

	now = time_zero = ns_to_ktime(0);
	start = ktime_get();
	for (;;) {
		ret = sram_reg_read(wdev, WFX_DCA_NCP_STATUS, &reg);
		if (ret < 0)
			return -EIO;
		if (reg == status)
			break;
		now = ktime_get();
		if (ktime_after(now, ktime_add_ms(start, DCA_TIMEOUT)))
			return -ETIMEDOUT;
	}
	if (ktime_compare(time_zero, now))
		dev_dbg(wdev->pdev, "chip answer after %lldus\n", ktime_us_delta(now, start));
	else
		dev_dbg(wdev->pdev, "chip answer immediatly\n");
	return 0;
}

static int upload_firmware(struct wfx_dev *wdev, const u8 *data, size_t len)
{
	int ret;
	u32 offs, bytes_done;
	ktime_t time_zero, now, start;

	time_zero = ns_to_ktime(0);
	if (len % DNLD_BLOCK_SIZE) {
		dev_err(wdev->pdev, "firmware size is not aligned. Buffer overrun will occur\n");
		return -EIO;
	}
	offs = 0;
	while (offs < len) {
		start = ktime_get();
		now = time_zero;
		for (;;) {
			ret = sram_reg_read(wdev, WFX_DCA_GET, &bytes_done);
			if (ret < 0)
				return ret;
			if (offs + DNLD_BLOCK_SIZE - bytes_done < DNLD_FIFO_SIZE)
				break;
			now = ktime_get();
			if (ktime_after(now, ktime_add_ms(start, DCA_TIMEOUT)))
				return -ETIMEDOUT;
		}
		if (ktime_compare(now, time_zero))
			dev_dbg(wdev->pdev, "answer after %lldus\n", ktime_us_delta(now, start));

		ret = sram_write_dma_safe(wdev, WFX_DNLD_FIFO + (offs % DNLD_FIFO_SIZE),
					  data + offs, DNLD_BLOCK_SIZE);
		if (ret < 0)
			return ret;

		// WFx seems to not support writing 0 in this register during
		// first loop
		offs += DNLD_BLOCK_SIZE;
		ret = sram_reg_write(wdev, WFX_DCA_PUT, offs);
		if (ret < 0)
			return ret;
	}
	return 0;
}

#define CHECK(function) \
	do { \
		ret = function; \
		if (ret < 0) \
			goto error;\
	} while (0)

int load_firmware_secure(struct wfx_dev *wdev, const u8 *fw_file, u32 fw_len)
{
	const int header_size = FW_SIGNATURE_SIZE + FW_HASH_SIZE;
	/* SDIO hosts does not all correctly support unaligned buffers */
	u8 buf[BOOTLOADER_LABEL_SIZE + 1] __aligned(sizeof(void *));
	ktime_t start;
	u32 val32;
	int ret;

	CHECK(sram_reg_write(wdev, WFX_DCA_HOST_STATUS, HOST_READY));
	CHECK(config_reg_write_bits(wdev, CFG_CPU_RESET | CFG_DISABLE_CPU_CLK, 0));
	CHECK(wait_ncp_status(wdev, NCP_INFO_READY));

	CHECK(sram_buf_read(wdev, WFX_BOOTLOADER_LABEL, buf, BOOTLOADER_LABEL_SIZE));
	buf[BOOTLOADER_LABEL_SIZE] = 0;
	dev_dbg(wdev->pdev, "bootloader: \"%s\"\n", buf);

	ret = get_keyset_offset(wdev, fw_file);
	if (ret < 0)
		goto error;
	fw_file += ret;
	fw_len -= ret;

	CHECK(sram_reg_write(wdev, WFX_DCA_HOST_STATUS, HOST_INFO_READ));
	CHECK(wait_ncp_status(wdev, NCP_READY));

	CHECK(sram_reg_write(wdev, WFX_DNLD_FIFO, 0xFFFFFFFF)); // Fifo init
	CHECK(sram_write_dma_safe(wdev, WFX_DCA_FW_VERSION, "\x01\x00\x00\x00", FW_VERSION_SIZE));
	CHECK(sram_write_dma_safe(wdev, WFX_DCA_FW_SIGNATURE, fw_file, FW_SIGNATURE_SIZE));
	CHECK(sram_write_dma_safe(wdev, WFX_DCA_FW_HASH, fw_file + FW_SIGNATURE_SIZE, FW_HASH_SIZE));
	CHECK(sram_reg_write(wdev, WFX_DCA_IMAGE_SIZE, fw_len - header_size));
	CHECK(sram_reg_write(wdev, WFX_DCA_HOST_STATUS, HOST_UPLOAD_PENDING));
	CHECK(wait_ncp_status(wdev, NCP_DOWNLOAD_PENDING));

	start = ktime_get();
	CHECK(upload_firmware(wdev, fw_file + header_size, fw_len - header_size));
	dev_dbg(wdev->pdev, "firmware load after %lldus\n", ktime_us_delta(ktime_get(), start));

	CHECK(sram_reg_write(wdev, WFX_DCA_HOST_STATUS, HOST_UPLOAD_COMPLETE));
	ret = wait_ncp_status(wdev, NCP_AUTH_OK);
	// Legacy ROM support
	if (ret < 0)
		ret = wait_ncp_status(wdev, NCP_PUB_KEY_RDY);
	if (ret < 0)
		goto error;
	CHECK(sram_reg_write(wdev, WFX_DCA_HOST_STATUS, HOST_OK_TO_JUMP));

	return 0;

error:
	sram_reg_read(wdev, WFX_STATUS_INFO, &val32);
	if (val32 == 0x12345678) {
		dev_info(wdev->pdev, "no error reported by secure boot\n");
	} else {
		sram_reg_read(wdev, WFX_ERR_INFO, &val32);
		if (val32 < ARRAY_SIZE(fwio_error_strings) && fwio_error_strings[val32])
			dev_info(wdev->pdev, "secure boot error: %s\n", fwio_error_strings[val32]);
		else
			dev_info(wdev->pdev, "secure boot error: Unknown (0x%02x)\n", val32);
	}
	return ret;
}
#undef CHECK

static int load_firmware(struct wfx_dev *wdev)
{
	const struct firmware *fw;
	int ret;

	ret = request_firmware(&fw, wdev->pdata.file_fw, wdev->pdev);
	if (ret) {
		dev_err(wdev->pdev, "can't load file %s\n", wdev->pdata.file_fw);
		return ret;
	}
	ret = load_firmware_secure(wdev, fw->data, fw->size);
	release_firmware(fw);
	if (ret)
		dev_err(wdev->pdev, "can't load firmware to device: %s\n", wdev->pdata.file_fw);
	return ret;
}

static int init_otp(struct wfx_dev *wdev)
{
	return 0;
}

int wfx_init_device(struct wfx_dev *wdev)
{
	static const u32 igpr_init_sequence[] = {
		0x07208775, 0x082EC020, 0x093C3C3C, 0x0B322C44, 0x0CA06496,
	};
	int ret, i;
	ktime_t now, start;
	u32 reg;

	wdev->hw_revision = -1;

	reg = CFG_DIRECT_ACCESS_MODE | CFG_DISABLE_CPU_CLK | CFG_CPU_RESET;
	if (wdev->pdata.hif_clkedge)
		reg |= CFG_CLK_RISE_EDGE;
	ret = config_reg_write(wdev, reg);
	if (ret < 0) {
		dev_err(wdev->pdev, "%s bus returned error during first write access. Host configuration error?\n",
			wdev->pdata.sdio ? "SDIO" : "SPI");
		return -EIO;
	}

	ret = config_reg_read(wdev, &reg);
	if (ret < 0) {
		dev_err(wdev->pdev, "%s bus returned error during first read access. Bus configuration error?\n",
				wdev->pdata.sdio ? "SDIO" : "SPI");
		return -EIO;
	}
	if (reg == 0 || reg == ~0) {
		dev_err(wdev->pdev, "chip mute. Bus configuration error or chip wasn't reset?\n");
		return -EIO;
	}
	dev_dbg(wdev->pdev, "initial config register value: %08x\n", reg);

	wdev->hw_type = FIELD_GET(CFG_DEVICE_ID_TYPE, reg);
	wdev->hw_revision = FIELD_GET(CFG_DEVICE_ID_MAJOR, reg);

	if (wdev->hw_revision == 0 || wdev->hw_revision > 2) {
		dev_err(wdev->pdev, "bad hardware revision number: %d\n", wdev->hw_revision);
		return -ENODEV;
	}
	if (wdev->hw_type == 1)
		dev_notice(wdev->pdev, "development hardware detected\n");

	ret = init_otp(wdev);
	if (ret < 0)
		return ret;
	for (i = 0; i < ARRAY_SIZE(igpr_init_sequence); i++) {
		ret = igpr_reg_write(wdev, igpr_init_sequence[i]);
		if (ret < 0)
			return ret;
		ret = igpr_reg_read(wdev, &reg);
		if (ret < 0)
			return ret;
		dev_dbg(wdev->pdev, "  index %02x: %08x\n", igpr_init_sequence[i] >> 24, reg);
	}

	ret = control_reg_write(wdev, CTRL_WLAN_WAKEUP);
	if (ret < 0)
		return -EIO;
	start = ktime_get();
	for (;;) {
		ret = control_reg_read(wdev, &reg);
		now = ktime_get();
		if (reg & CTRL_WLAN_READY)
			break;
		if (ktime_after(now, ktime_add_ms(start, WAKEUP_TIMEOUT))) {
			dev_err(wdev->pdev, "chip didn't wake up. Chip wasn't reset?\n");
			return -ETIMEDOUT;
		}
	}
	dev_dbg(wdev->pdev, "chip wake up after %lldus\n", ktime_us_delta(now, start));

	ret = load_firmware(wdev);
	if (ret < 0)
		return ret;

	ret = config_reg_write_bits(wdev, CFG_IRQ_ENABLE_DATA | CFG_IRQ_ENABLE_WRDY, CFG_IRQ_ENABLE_DATA);
	if (ret < 0)
		return ret;
	ret = config_reg_write_bits(wdev, CFG_DIRECT_ACCESS_MODE, 0);
	if (ret < 0)
		goto error;
	ret = config_reg_read(wdev, &reg);
	if (ret < 0)
		goto error;
	dev_dbg(wdev->pdev, "final config register value: %08x\n", reg);
	return ret;
error:
	config_reg_write_bits(wdev, CFG_IRQ_ENABLE_DATA | CFG_IRQ_ENABLE_WRDY, 0);
	return ret;
}
