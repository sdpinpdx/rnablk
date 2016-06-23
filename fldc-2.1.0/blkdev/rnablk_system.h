/**
 * <rnablk_system.h> - Dell Fluid Cache block driver
 *
 * Copyright (c) 2013 Dell  Inc
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */


/*
 * here you will find declaration for OS-specific functions used to perform
 * such actions as loading module and creating/loading virtual devices.
 *
 * the definitions can be found in rnablk_system_linux.c and
 * rnablk_system_windows.c
 */
#pragma once
#include "rb.h"
#include "rna_log.h"

#ifdef WINDOWS_KERNEL
#include "comAPIPublic.h"
#endif
//
// Used to turn inlining on and off for better stack traces
#define rna_inline inline
//#define rna_inline

// Used here in case the noinline macro is missing in some kernels, and to easily disable it.
#define rna_noinline noinline
//#define rna_noinline

struct rnablk_cache_info;

void rnablk_mempool_free(void                     * item,
                         struct rnablk_cache_info * cache_info);
/**
 * Register a block device with the Operating System.
 *
 * This is done when we recieve a masterblock reference,
 * at which point we know the cache block size.
 *
 */
void rnablk_deferred_register_block_device(struct rnablk_device *dev);

/**
 * Unregister device with Operating System.
 */
int rnablk_unregister_block_device(struct rnablk_device *dev);


void * rnablk_mempool_alloc(struct rnablk_cache_info * cache_info);

#ifndef WINDOWS_KERNEL
int
rnablk_rq_map_sg(struct rnablk_device *dev, struct request_queue *q,
                 struct request *req, struct io_state **pp_ios);
#endif /*WINDOWS_KERNEL*/

void rnablk_set_max_io(struct rnablk_device *dev,
                       int                   max_bytes);

