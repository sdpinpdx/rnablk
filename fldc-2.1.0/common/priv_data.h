/**
 * <priv_data.h> - Dell Fluid Cache block driver
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


#ifndef INCLUDED_PRIV_DATA_H
#define INCLUDED_PRIV_DATA_H

#include "platform.h"

#ifdef LINUX_KERNEL
#include <linux/in.h>
#endif

DECLARE_PACKED_STRUCT(req_priv_data) {
    uint32_t       version;
    uint32_t       user_type;
    uint32_t       num_send; /* Number of send buffers on initiating side */
    uint32_t       num_recv; /* Number of recv buffers on initiating side */
    uint32_t       buf_size; /* Send/Recv buffer size */
    uint8_t        cpu_be;   /* Indicates that the CPU is big_endian (provides capability of optimizing byteswapping) */
    uint8_t        private_threads;     /* Allocate # of threads specifically for this EP. */
    uint32_t       min_proto_version;
    uint32_t       max_proto_version;
    uint32_t       bounce_buf_size; /* Requested bounce buffer size if supported. */
    uint8_t        sync_flag;     /* Require syncronization for recv processing of this ep. (private threads should be 0. */
} END_PACKED_STRUCT(req_priv_data);

#endif
