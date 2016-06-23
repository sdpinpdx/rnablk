/*
 * <rnablk_queue_dispatch.h> - Dell Fluid Cache block driver
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
#pragma once
#include "rb.h"
#pragma once

#include "rb.h"
#include "rnablk_globals.h"
#include "rnablk_system.h"

#define FORCE_QUEUED_IO TRUE
#define NO_FORCE_QUEUED_IO FALSE

typedef enum {
    QUEUE_TAIL,
    QUEUE_HEAD,
} queue_where_t;

void rnablk_queue_blk_io_nolock(struct cache_blk   *blk,
                                struct io_state    *ios,
                                queue_where_t      where);

NOINLINE void
rnablk_this_or_next_request(struct rnablk_server_conn *conn,
                            struct io_state           *new_ios);

// runs in kthread context
INLINE void rnablk_next_request(struct rnablk_server_conn *conn)
{
    rnablk_this_or_next_request(conn, NULL);
}

void rnablk_dequeue_blk_io_nolock(struct cache_blk *blk, struct io_state  *ios);
int queue_command(struct io_state *ios);

void
rnablk_requeue(struct com_ep *ep,struct io_state *ios,
               struct scatterlist *sgl,
               enum dma_data_direction dir);

void
rnablk_start_blk_io(struct cache_blk * blk, boolean devconn_too);

void
rnablk_queue_delayed_request(struct io_state *ios, int msecs);

#ifdef WINDOWS_KERNEL
void rnablk_schedule_conn_dispatch_on(struct rnablk_server_conn *conn,
                                      rna_service_work_queue_t *wq);
#else
void rnablk_schedule_conn_dispatch_on(struct rnablk_server_conn *conn, 
                                      struct workqueue_struct *wq);
#endif /*WINDOWS_KERNEL*/

/*
 * runs at softirq level
 *
 * Schedule dispatch on mt workq (normal for deferring from softirq)
 */
INLINE void rnablk_schedule_conn_dispatch(struct rnablk_server_conn *conn)
{
    rnablk_schedule_conn_dispatch_on(conn, mt_workq);
}

void rnablk_queue_conn_io(struct rnablk_server_conn *conn,
                          struct io_state           *ios,
                          queue_where_t             where);

void rnablk_dequeue_conn_io(struct io_state *ios);

void rnablk_queue_blk_io(struct cache_blk   *blk,
                         struct io_state    *ios,
                         queue_where_t      where);

void rnablk_ios_skip_query(struct io_state *ios);

void rnablk_wake_up_all(boolean devconns_too);

void rnablk_schedule_wake_up_all(void);

void
rnablk_queue_or_dispatch(struct rnablk_server_conn *conn,
                         struct io_state *ios,
                         int force_queue);

int queue_io_request(struct io_state *ios,
                     struct cache_blk *blk,
                     int force_queue);

void rnablk_queue_request(int               type,
                          struct com_ep    *ep,
                          struct io_state  *ios,
                          struct cache_blk *blk,
                          int               force_queue,
                          boolean           have_blk_lock);
