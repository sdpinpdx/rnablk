/**
 * <rna_com_linux_impl.h> - Dell Fluid Cache block driver
 *
 * Copyright (c) 2012-13 Dell  Inc
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
 * Platform specific header file that defines structures specific to
 * the linux implementation.
 *
 * Note: This file should *never* be included anywhere other than rna_com_kernel.h
 */
#pragma once

#ident "$URL$ $Id$"

#include <linux/timer.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/mutex.h>

typedef struct scatterlist rna_scatterlist_t;
typedef struct sockaddr rna_sockaddr_t;
typedef dma_addr_t rna_dma_addr_t;
typedef struct kvec rna_kvec_t;
typedef struct work_struct rna_work_struct_t;
typedef struct list_head rna_list_head_t;
typedef struct rb_node rna_rb_node_t;

#define RNA_BUG_ON BUG_ON
