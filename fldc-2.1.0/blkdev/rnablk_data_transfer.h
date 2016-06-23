/**
 * <rnablk_data_transfer.h> - Dell Fluid Cache block driver
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
#include "rnablk_callbacks.h"

int rnablk_data_op_complete(struct io_state *ios, int err);
int rnablk_initiate_dma(struct io_state *ios);
int rnablk_initiate_rdma(struct io_state *ios, struct buf_entry *buf_entry);
void rnablk_dispatch_dma_io(struct io_state *ios, lockstate_t *irqflags);
void rnablk_get_local_dev(struct cache_blk          *blk,
                          struct rnablk_server_conn *conn);
void rnablk_free_local_devs(void);
