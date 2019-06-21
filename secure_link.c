// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2019, Silicon Laboratories, Inc.
 */

#include <linux/random.h>

/*
 * Used by MBEDTLS_ENTROPY_HARDWARE_ALT
 */
int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen)
{
	get_random_bytes(output, len);
	*olen = len;

	return 0;
}
