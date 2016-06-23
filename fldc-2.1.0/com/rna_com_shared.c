/**
 * <rna_com_shared.c> - Dell Fluid Cache com layer code shared by
 *                      TCP & IB com modules.
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
 */

#include <linux/delay.h>        // for msleep_interruptible

#include "../include/rna_common.h"
#include "../include/rna_atomic64.h"

#include "rna_com_linux_kernel.h"
#include "rna_proc_ep.h"
#include "priv_data.h"

static void
_com_finish_rdma_op(struct com_ep *ep, struct buf_entry *buf, int status,
                    boolean do_put)
{
    if (0 != status) {
        rna_printk(KERN_DEBUG, "ep [%p] buf [%p] optype [%d] context [%p] "
                   "ctx [%p] status [%d]\n",
                   ep, buf, buf->op_type, ep->context, buf->context,
                   status);
    }
    if ((buf->op_type == RDMA_READ) || (buf->op_type == RDMA_READ_SGL)) {
        repost_read_credit(buf);
        if (NULL != ep->com_attr.rdma_read_cmp_cb){
            ep->com_attr.rdma_read_cmp_cb(ep, ep->context, buf->context,
                                          status);
        }
    } else if ((buf->op_type == RDMA_WRITE)
                || (buf->op_type == RDMA_WRITE_SGL)) {
        if (NULL != ep->com_attr.rdma_write_cmp_cb){
            ep->com_attr.rdma_write_cmp_cb(ep, ep->context, buf->context,
                                           status);
        }
    }
    if (do_put) {
        com_put_rdma_buf(ep, buf);
    }
}

void
com_finish_rdma_op(struct com_ep *ep, struct buf_entry *buf, int status)
{
    _com_finish_rdma_op(ep, buf, status, TRUE);
}

void
com_complete_rdma_op(struct com_ep *ep, struct buf_entry *buf, int status)
{
    BUG_ON(BUF_USE_FREE == atomic_read(&buf->buf_use_state));

    /*
     * Since buf_use_state can legitimately change from ALLOCATED to
     * INFLIGHT (and in fact normally does), but not vice versa,
     * be sure to check for ALLOCATED first, then INFLIGHT to avoid
     * a race.
     */
    if (atomic_cmpxchg(&buf->buf_use_state, BUF_USE_ALLOCATED,
                       BUF_USE_COMPLETING) == BUF_USE_ALLOCATED) {
        _com_finish_rdma_op(ep, buf, status, FALSE);
    } else if (atomic_cmpxchg(&buf->buf_use_state, BUF_USE_INFLIGHT,
                              BUF_USE_COMPLETING) == BUF_USE_INFLIGHT) {
        com_finish_rdma_op(ep, buf, status);
    } else {
        rna_printk(KERN_WARNING, "ep [%p] buf [%p] optype [%d] context [%p] "
                   "ctx [%p] status [%d]: not in-flight (state [%d])\n",
                   ep, buf, buf->op_type, ep->context, buf->context,
                   status, atomic_read(&buf->buf_use_state));
    }
    return;
}

/* 
 * All outstanding RDMA requests need to report back to the application so that 
 * it may safely unpin resources.
 */
void
repost_uncompleted_ops( struct com_ep *ep)
{
	struct buf_entry *rdma_buf = NULL;
    boolean need_another_pass = TRUE;
    int npasses = 0;
    int use_state;
	int i;
	
	if (unlikely (NULL == ep->rdma_pool)) {
		rna_trace("rdma_pool was never initialized\n");
        return;
    }

    while (need_another_pass) {
        need_another_pass = FALSE;
        if (npasses++ == 2) {
            /*
             * After the first pass, we're more or less just spinning 
             * waiting for bufs in the COMPLETING state to finish up.
             * Add in a short sleep so it's not a hard spin.
             */
            msleep_interruptible(20);
        }
        for (i = 0; i < ep->num_rdma; i++) {
			rdma_buf = ep->rdma_pool[i];	
            use_state = atomic_read(&rdma_buf->buf_use_state);
            switch (use_state) {
            case BUF_USE_INFLIGHT:
                if (atomic_cmpxchg(&rdma_buf->buf_use_state,
                                   use_state, BUF_USE_REPOSTED) == use_state) {
                    com_finish_rdma_op(ep, rdma_buf, -1);
                } else {
                    need_another_pass = TRUE;
                }
                break;

            case BUF_USE_ALLOCATED:
                if (atomic_cmpxchg(&rdma_buf->buf_use_state,
                                   use_state, BUF_USE_REPOSTED) != use_state) {
                    need_another_pass = TRUE;
                }
                break;

            case BUF_USE_COMPLETING:
                need_another_pass = TRUE;
                break;

            default:
                break;
            }
        }
	}

	/* 
     * TODO: When moving to using send pools for async send ops, repost all 
     * queued sends 
     */
	
	return;
}
