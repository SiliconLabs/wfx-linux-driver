// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2019, Silicon Laboratories, Inc.
 */
#ifndef MBED_STDLIB_H
#define MBED_STDLIB_H

#include <linux/vmalloc.h>
#include <linux/random.h>

static inline int rand(void)
{
	return get_random_int();
}

static inline void *calloc(size_t n, size_t size)
{
	return vzalloc(n * size);
}

static inline void free(void *ptr)
{
	vfree(ptr);
}

#endif
