/**
 * <rnablk_queue_dispatch.c> - Dell Fluid Cache block driver
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
#include "rb.h"
#include "rnablk_queue_dispatch.h"
#include "rnablk_block_state.h"
#include "rnablk_io_state.h"
#include "rnablk_cache.h"
#include "rnablk_util.h"
#include "rnablk_data_transfer.h"
#include "rnablk_protocol.h"
#include "rnablk_comatose.h" // for rnablk_command_is_ordered
#include "trace.h"

/*
 * used for SRB tracing in the storport miniport for performance
 * analysis.
 */
#ifdef WINDOWS_KERNEL
#include <storport.h>  
#include "rna_vsmp.h"
#pragma warning(push)
#pragma warning(disable : 4204)                        /* Prevent C4204 messages from stortrce.h. */
#pragma warning(disable : 6387)
#include <stortrce.h>
#pragma warning(pop)
#include "rna_vsmp_trace.h"
#include "rnablk_queue_dispatch.tmh"
#endif
    

/* private globals */

/* max number of milliseconds we spend dispatching on a workq */
#ifdef WINDOWS_KERNEL
// Windows is currently using tick count which has a
// granularity of 15.6 ms.  Make timeout a little more.
#define RNABLK_DISPATCH_LIMIT_MSECS 20
#else
#define RNABLK_DISPATCH_LIMIT_MSECS 10
#endif

atomic_t wakeup_needed = {0};
atomic_t wakeup_scheduled = {0};

#ifdef WINDOWS_KERNEL
extern uint64_t msecs_to_jiffies(const unsigned int m);
#endif /*WINDOWS_KERNEL*/

/* private prototypes */

// Add a request to the queue of submitted io requests,
// then initiate the next RDMA operation(s)
// caller MUST hold block's bl_lock
int
queue_io_request(struct io_state *ios, struct cache_blk *blk, int force_queue)
{
    struct rnablk_device *dev;
    struct rnablk_server_conn *conn;
    ENTER;

    RNABLK_BUG_ON(unlikely(NULL == blk || blk != ios->blk),
                   "ios [%p] type [%s] tag ["TAGFMT"] ios->blk [%p]\n",
                   ios,
                   rnablk_op_type_string(ios->type),
                   TAGFMTARGS(ios->tag),
                   ios->blk);

    RNABLK_BUG_ON(unlikely(!IOS_HAS_IOREQ(ios)),
                   "ios [%p] tag ["TAGFMT"] type [%s] for dev [%s] block "
                   "[%"PRIu64"] NULL request\n",
                   ios, TAGFMTARGS(ios->tag),
                   rnablk_op_type_string(ios->type),
                   ios->dev->name,
                   blk->block_number);

    dev       = ios->dev;

    rnablk_trace_ios(ios);

    // this request is now an IO operation
    rnablk_set_ios_io_type(ios);

    rnablk_set_ios_blk_ep(ios);
    conn = rnablk_get_ios_conn(ios);

    /* Don't queue IO for the MD or any disconnected CS */
    if (unlikely((g_md_conn == conn) || NULL == conn)) {
        rna_printk(KERN_ERR,
                   "ios [%p] tag ["TAGFMT"] type [%s] I/O error ios->blk [%p] "
                   "conn ["CONNFMT"] blk->ep [%p], connection not available\n",
                   ios,
                   TAGFMTARGS(ios->tag),
                   rnablk_op_type_string(ios->type),
                   ios->blk,
                   CONNFMTARGS(conn),
                   blk->ep);
        rnablk_unset_ios_ep(ios);
        GOTO( err, -EINVAL);
    }
    atomic_inc(&blk->inflight_ios);
    rnablk_queue_or_dispatch(conn, ios, force_queue);

out:
    EXIT;
err:
    rnablk_end_request(ios, ret);
    goto out;
}

/**
 * Initiate a DMA or RDMA operation
 *
 * If this is RDMA, buf_entry must be an rdma_buf.  If this is a DMA operation, 
 * buf_entry must be NULL.
 */
static void
dispatch_io_request(struct io_state *ios, struct buf_entry *buf_entry)
{
    struct rnablk_server_conn *conn;
    lockstate_t flags;
    boolean do_dispatch;
    ENTER;

    RNABLK_BUG_ON(unlikely(!ios || !ios->ep || !ios->blk || !ios->blk->ep),
                  "blk [%p] ios [%p] tag ["TAGFMT"] type [%s] blk->ep [%p] "
                  "ios->ep [%p]\n", ios ? ios->blk : NULL, ios,
                  ios ? TAGFMTARGS(ios->tag) : 0,
                  ios ? rnablk_op_type_string(ios->type) : "",
                  (ios && ios->blk) ? ios->blk->ep : NULL,
                  ios ? ios->ep : NULL);

    RNABLK_BUG_ON(!IOS_HAS_IOREQ(ios), "ios [%p] tag ["TAGFMT"] has no "
                  "request\n", ios, TAGFMTARGS(ios->tag));

    conn = rnablk_get_ios_conn(ios);

    rnablk_lock_blk_irqsave(ios->blk, flags);
    rnablk_io_dispatched_nolock(ios, ios->blk);
    if (likely(rnablk_conn_connected(conn))) {
        do_dispatch = TRUE;
    } else {
        rnablk_undo_conn_io(ios, TRUE);
        RNABLK_BUG_ON(!ios_queuestate_test_and_set(ios, IOS_QS_DISPATCH,
                      IOS_QS_DISPATCH_FAILED_REDO),
                      "ios=%p unexpected qstate=%d\n", ios,
                      ios_queuestate_get(ios));
        do_dispatch = FALSE;
    }
    rnablk_unlock_blk_irqrestore(ios->blk, flags);
    TRACE(DBG_FLAG_VERBOSE, "ios [%p] tag ["TAGFMT"]\n", ios,
          TAGFMTARGS(ios->tag));

    rnablk_trace_ios(ios);

    if (unlikely(!do_dispatch)) {
        /*
         * leave it on the dispatch queue; disconnect processing for the
         * conn should take care of cleanup and/or re-issue of the ios
         * as appropriate.
         */
        GOTO(out, -EINVAL);
    }

    rnablk_update_io_stats(ios);

    if (rnablk_ios_uses_local_dma(ios)) {
        /* local device, perform DMA */
        /* Caller should not have allocated an rdma_buf */
        BUG_ON(NULL != buf_entry);
        if(unlikely(rnablk_initiate_dma(ios))) {
            GOTO(err, -EIO);
        }
    } else {
        BUG_ON(NULL == buf_entry);
        if (unlikely(rnablk_initiate_rdma(ios, buf_entry))) {
            // initiate the RDMA operations
            GOTO(err, -EIO);
        }
    }

 out:
    EXITV;

 err:

    if (buf_entry) {
        com_put_rdma_buf(ios->ep, buf_entry);
    }
    rnablk_io_completed(ios);
    rnablk_end_request(ios, ret);
    goto out;

}

/**
 * Takes an IOS that's being dispatched as a query to satisfy the
 * requirements of its block request, and resubmits it as if the query
 * response was received.  Used when the needed ref type is already
 * held.
 *
 * The ios must be on the dispatch list.
 */
void
rnablk_ios_skip_query(struct io_state *ios)
{
    struct cache_blk          *blk = NULL;
    lockstate_t                flags;

    BUG_ON(NULL == ios);
    blk = ios->blk;
    BUG_ON(NULL == blk);

    rnablk_cache_blk_ref(blk);
    BUG_ON(IOS_QS_DISPATCH != ios_queuestate_get(ios));
    rnablk_lock_blk_irqsave(blk, flags);
    rnablk_io_completed_nolock(ios, blk);
    rnablk_retrack_ios(ios);
    BUG_ON(!rnablk_state_ok_for_req(blk, ios));
    queue_io_request(ios, blk, FORCE_QUEUED_IO);
    rnablk_unlock_blk_irqrestore(blk, flags);
    rnablk_start_blk_io(blk, TRUE);
    rnablk_cache_blk_release(blk);
}

static void
dispatch_command(struct io_state *ios, struct buf_entry *send_buf)
{
    struct rnablk_device *dev;
    struct rnablk_server_conn *conn;
    struct sockaddr_in dst_in;
    ENTER;

    rnablk_trace_ios(ios);
    dst_in = get_dest_sockaddr_from_ep(ios->ep);
    rna_printk(KERN_DEBUG,
               "[%s] CS ["NIPQUAD_FMT"]\n",
               rnablk_op_type_string(ios->type),
               NIPQUAD(dst_in.sin_addr.s_addr));

    dev  = ios->dev;
    conn = rnablk_get_ios_conn(ios);
    if (unlikely(!rnablk_conn_connected(conn))) {
        rna_printk(KERN_ERR,
                   "ios [%p] tag ["TAGFMT"] type [%s] block [%llu] conn "
                   "["CONNFMT"]\n",
                   ios,
                   TAGFMTARGS(ios->tag),
                   rnablk_op_type_string(ios->type),
                   ios->blk->block_number,
                   CONNFMTARGS(conn));
        GOTO( out,-EINVAL );
    }

    BUG_ON(NULL == send_buf);
    /* need to leave write_same cmd in place */
    if (ios->cmd && !((RNABLK_CHANGE_REF == ios->type) &&
                      ((IOS_IOTYPE_COMP_WR == ios->ios_iotype) ||
                       (IOS_IOTYPE_WRITE_SAME == ios->ios_iotype)))) {
        memcpy(com_get_send_buf_mem(send_buf), ios->cmd, cache_cmd_length(ios->cmd));
    } else {
        cache_lock_t desired_ref;
        
        /* 
         * The ios for I/O alone does not allocate an ios->cmd, and
         * if we need to change a reference, we'll need to create
         * that command in the send buffer.
         */
        BUG_ON(NULL == ios->blk);
        if (dev_is_persistent(dev)) {
            BUG_ON(!IOS_HAS_IOREQ(ios));
            if (!rnablk_needed_lock(ios, &desired_ref)) {
                /* IOS was requeued, do not send */
                goto not_sent;
            }
        } else {
            desired_ref = CACHE_READ_SHARED;
        }
        /* 
         * change_ref should never request a write only reference.  Those
         * can only be granted via new references.
         */
        BUG_ON(CACHE_WRITE_ONLY_SHARED == desired_ref);
        BUG_ON(RNABLK_CHANGE_REF != ios->type);
        rnablk_create_change_ref_cmd((struct cache_cmd *)(com_get_send_buf_mem(send_buf)), 
                                     ios, ios->blk->rid, ios->blk,
                                     ios->blk->ref_type, desired_ref,  0);
    }

    ios->issue_time_ns = getrawmonotonic_ns();
    inc_in_flight(dev, ios);

    com_set_send_buf_context(send_buf, (void *)ios->tag);
    ret = com_send(ios->ep, send_buf, 
                   (int)cache_cmd_length((struct cache_cmd *)com_get_send_buf_mem(send_buf)));

    if (unlikely(ret)) {
        dec_in_flight(dev, ios);
    
        if (-EAGAIN == ret) {
            rna_printk(KERN_ERR,
                       "REQUEUED %s on dev [%s] ios [%p] tag ["TAGFMT"] "
                       "because of send error [%d]\n",
                       rnablk_op_type_string( ios->type ),
                       dev->name,
                       ios, TAGFMTARGS(ios->tag),
                       ret);

            ios->issue_time_ns = 0;

            // put this request at the head of the list
            rnablk_requeue( ios->ep,ios,NULL,DMA_TO_DEVICE );

            // don't want caller freeing IOS...
            ret = 0;

        } else {
            rna_printk(KERN_ERR,
                       "failed to dispatch %s on dev [%s] ios [%p] tag "
                       "["TAGFMT"] because of send error [%d]\n",
                       rnablk_op_type_string(ios->type), dev->name,
                       ios, TAGFMTARGS(ios->tag), ret);
            rnablk_queue_conn_disconnect(conn);
            goto not_sent;
        }
    }

 out:
    EXITV;

 not_sent:
    if (NULL != send_buf) {
        struct com_ep   *ep;
        ep = rnablk_get_ios_ep(ios);
        if (NULL != ep) {
            struct rnablk_server_conn *conn;
            com_put_send_buf(ep, send_buf);
            conn = rnablk_get_ios_conn(ios);
            if (NULL != conn) {
                atomic_dec(&conn->send_bufs_in_use);
            }
        }
    }
    goto out;
}


static int
dispatch_query_request(struct io_state *ios, struct buf_entry *buf_entry)
{
    struct rnablk_device *dev;
    lockstate_t flags;

    ENTER;

    BUG_ON(NULL == ios);
    BUG_ON(NULL == ios->dev);

    TRACE(DBG_FLAG_VERBOSE, "ios [%p] tag ["TAGFMT"]\n", ios,
          TAGFMTARGS(ios->tag));
    rnablk_trace_ios(ios);

    rnablk_lock_blk_irqsave(ios->blk, flags);
    if (unlikely(!rnablk_cache_blk_state_is_queryable(ios->blk->state))) {
        rna_printk(KERN_ERR, "ios [%p] tag ["TAGFMT"] type [%s] for [%s] "
                   "block [%"PRIu64"] in non-queryable state [%s]\n",
                   ios, TAGFMTARGS(ios->tag),
                   rnablk_op_type_string(ios->type),
                   ios->blk->dev->name,
                   ios->blk->block_number,
                   rnablk_cache_blk_state_string(ios->blk->state));
        BUG_ON(TRUE);
    }
    rnablk_io_dispatched_nolock(ios, ios->blk);
    rnablk_unlock_blk_irqrestore(ios->blk, flags);

    dev = ios->dev;
    dev->stats.queries++;

    // Removed in rnablk_process_metadata_query_response() or rnablk_process_recv_cmp()
    inc_in_flight(dev, ios);

   // initiate query operation
    if (unlikely((RNABLK_MD_QUERY == ios->type))) {
        /* MD query (then cache query) */
        BUG_ON(NULL != buf_entry);

        if (unlikely(rnablk_metadata_query(ios))) {
            GOTO( err1,-EIO );
        }
    } else {
        BUG_ON(NULL == buf_entry);
        if (unlikely(rnablk_cache_block_query(ios, buf_entry))) {
            GOTO( err1,-EIO );
        }
    }
 
out:
    EXIT;
err1:
    dec_in_flight(dev, ios);

    rnablk_io_completed(ios);
    rnablk_end_request(ios, ret);
    goto out;
}

/*
 * Runs in kthread context
 *
 * If new_ios is not NULL (and nothing else is waiting), dispatch it
 * immediateliy if possible, otherwise queue it.  In all cases,
 * attempt to dispatch what's in the queue.  Stop dispatching when we
 * cannot get the buffer (send or rdma) we need to dispatch the next
 * ios, or after a certain amount of time
 * (RNABLK_DISPATCH_LIMIT_MSECS) has been spent here.
 */
void
rnablk_this_or_next_request(struct rnablk_server_conn *conn,
                            struct io_state *ios)
{
    struct io_state *ios_to_process;
    struct list_head *ent, *next;
    struct buf_entry *buf_entry = NULL; // used for RDMA buf or send buf
    lockstate_t flags;
    int num_commands_dispatched = 0;
    int num_ios_dispatched = 0;
    int alloc_rdma_failed = 0;
    int alloc_send_failed = 0;
    int len;
    uint64_t start_jiffies;
    unsigned long msecs = 0;
    int result;
    ENTERV;

    start_jiffies = get_jiffies();

#ifdef IOS_TIMEOUT_TEST
    if (unlikely((TRUE == ios_timeout_test)
                 && (NULL != ios) && (NULL != ios->ep)
                 && (MD_CONN_EP_METAVALUE != ios->ep))) {
#ifdef WINDOWS_KERNEL
        printk("ios_timeout_test active %p\n", ios->ep);
#else
        printk(KERN_ERR "ios_timeout_test active %p\n", ios->ep);
#endif

        EXITV;
    }

#endif /* IOS_TIMEOUT_TEST */

    if (unlikely(!rnablk_conn_connected(conn))) {
        if (conn) {
            rna_printk(KERN_ERR, "new_ios=%p CS ["rna_service_id_format"] in "
                       "unexpected state [%s]\n", ios,
                       rna_service_id_get_string(&conn->id),
                       rnablk_conn_state_string(atomic_read(&conn->state)));
        } else {
            rna_printk(KERN_ERR,
                       "new_ios=%p CS in unexpected state [NULL]\n", ios);
        }
        if (NULL != ios) {
            /* leave this to be processed by disconnect callback */
            rnablk_queue_blk_io(ios->blk, ios, QUEUE_TAIL);
        }
        EXITV;
    }

    rnablk_trace_ios(ios);

    rna_spin_in_stack_lock_irqsave(conn->sc_lock, flags);
    if (NULL != ios) {
        rnablk_queue_conn_io(conn, ios, QUEUE_TAIL);
    }

    if (list_empty(&conn->io_queue)
        || atomic_read(&rna_service_detached)
        || !atomic_bit_test_and_set(&conn->rsc_flags, RSC_F_DISPATCHING)) {

        rna_spin_in_stack_unlock_irqrestore(conn->sc_lock, flags);
        EXITV;
    }
        

    do {

        ios_to_process = NULL;

        list_for_each_safe(ent, next, &conn->io_queue) {
            ios = list_entry(ent, struct io_state, l);
        
            if (unlikely(atomic_bit_is_clear(&ios->blk->blk_cachedev->rcd_state,
                                             RCD_STATE_ONLINE))) {
                rna_printk(KERN_DEBUG, "cachedev [%#"PRIx64"] offline conn "
                           "["CONNFMT"], queuing ios [%p] tag ["TAGFMT"] "
                           "type [%s] is_io=%d block [%"PRIu64"] state [%s]\n",
                           ios->blk->blk_cachedev->rcd_id, CONNFMTARGS(conn),
                           ios, TAGFMTARGS(ios->tag),
                           rnablk_op_type_string(ios->type),
                           rnablk_is_ios_io_type(ios),
                           ios->blk->block_number,
                           rnablk_cache_blk_state_string(ios->blk->state));
                /*
                 * If this ios is associated with a cachedevice that
                 * has been marked as offline, need to defer it until
                 * the EXPEL_CACHE_DEVICE processing is complete.
                 */
                rnablk_dequeue_conn_io(ios);
                /* need to drop conn lock before acquiring blk lock... */
                rna_spin_in_stack_unlock_irqrestore(conn->sc_lock, flags);
                rnablk_undo_conn_io(ios, FALSE);  // gets blk lock
                rnablk_queue_blk_io(ios->blk, ios, QUEUE_TAIL);
                /*
                 * since we dropped the conn->sc_lock, need to start at
                 * the beginning of the list again.
                 */
                goto restart_loop;
            } else if (ios->ep != conn->ep) {
                /*
                 * If this ios doesn't point to the current conn->ep,
                 * clean it up!  (We've seen this happen with anonymous
                 * deref or write_ref_block_limit enforcer racing with a
                 * CS disconnect.).
                 */
                if (!IOS_HAS_IOREQ(ios)) {
                    rnablk_dequeue_conn_io(ios);
                    /* need to drop conn lock before acquiring blk lock... */
                    rna_spin_in_stack_unlock_irqrestore(conn->sc_lock, flags);
                    rna_printk(KERN_WARNING, "Dropping obsolete ios [%p] "
                               "type [%s] device [%s] block [%llu] "
                               "state [%s]\n", ios,
                               rnablk_op_type_string(ios->type), ios->dev->name,
                               ios->blk->block_number,
                               rnablk_cache_blk_state_string(ios->blk->state));
                    rnablk_undo_conn_io(ios, FALSE);  // gets blk lock
                    rnablk_ios_finish(ios);
                    goto restart_loop;
                } else {
                    /* this 'releases' the current ios->ep, too */
                    rna_printk(KERN_WARNING, "Resetting stale ep for ios [%p] "
                               "type [%s] device [%s] block [%llu] "
                               "state [%s] ios->ep [%p] ep [%p]\n", ios,
                               rnablk_op_type_string(ios->type), ios->dev->name,
                               ios->blk->block_number,
                               rnablk_cache_blk_state_string(ios->blk->state),
                               ios->ep, conn->ep);
                    rnablk_set_ios_ep(ios, conn->ep);
                }
            }
            rnablk_trc_discon(0,
                       "dispatch ios [%p] tag ["TAGFMT"] block [%"PRIu64"] "
                       "conn ["CONNFMT"] type [%s] state [%s] ref [%s]\n",
                       ios, TAGFMTARGS(ios->tag), ios->blk->block_number,
                       CONNFMTARGS(conn), rnablk_op_type_string(ios->type),
                       rnablk_cache_blk_state_string(ios->blk->state),
                       get_lock_type_string(ios->blk->ref_type));

            ios_to_process = ios;

            /* Get the buffer we'll need to dispatch this ios */
            switch(ios->type) {
            case RNABLK_MD_QUERY:
                /* No send or rdma buffer needed */
                break;
                
            case RNABLK_RDMA_READ:
            case RNABLK_RDMA_WRITE:
                if (rnablk_ios_uses_local_dma(ios)) {
                    /* Do not allocate an RDMA buffer for local DMA */
                } else if (alloc_rdma_failed) {
                    // already failed trying to get rdma_buf, don't try again
                    ios_to_process = NULL; 
                } else {
                    /* RDMA buffer needed */
                    len = (ios->nr_sectors * RNABLK_SECTOR_SIZE);
                    /* 
                     * This call is transport-specific, and TCP will always
                     * treat len as being 1.  RDMA will check the length and
                     * determine if a bounce buffer is needed.
                     */
                    result = com_get_rdma_buf(ios->ep, &buf_entry, &len);
                    if (unlikely((0 != result) || (NULL == buf_entry))) {
                        alloc_rdma_failed = TRUE;
                        atomic_inc(&conn->rdma_buf_alloc_failures);
                        /*
                         * rna_printk(KERN_ERR,"Failed to get RDMA buf for "
                         *         "ios [%p] tag ["TAGFMT"] res [%d] buf [%p] "
                         *         ep [%p]\n", ios, TAGFMTARGS(ios->tag),
                         *         result, buf_entry, ios->ep); 
                         */
                        ios_to_process = NULL;
                        if (alloc_send_failed) {
                            /*
                             * If both rdma & send buf allocations failed,
                             * give up altogether!
                             */
                            next = &conn->io_queue; // break out of ios loop
                        }
                    } else {
                        atomic_inc(&conn->rdma_bufs_allocated);
                        atomic_inc(&conn->rdma_bufs_in_use);
                    }
                }
                break;
                
            case RNABLK_LOCK_MASTER_BLK:
            case RNABLK_CACHE_QUERY:
            case RNABLK_CHANGE_REF:
            case RNABLK_CHANGE_REF_NORESP:
            case RNABLK_MASTER_DEREF:
            case RNABLK_MASTER_DEREF_NORESP:
            case RNABLK_MASTER_INVD:
            case RNABLK_RSV_ACCESS_RESP:
            case RNABLK_WRITE_SAME:
            case RNABLK_COMP_AND_WRITE:
            case RNABLK_DEREF_REQUEST_RESP:
            case RNABLK_SCSI_PASSTHRU:
                /* Send buffer needed */
                if (alloc_send_failed) {
                    // already failed trying to get send_buf, don't try again
                    ios_to_process = NULL;
                } else  {
                    result = com_get_send_buf(ios->ep, &buf_entry, FALSE);
                    if (unlikely((0 != result) || (NULL == buf_entry))) {
                        alloc_send_failed = TRUE;
                        atomic_inc(&conn->send_buf_alloc_failures);
                        /* 
                         * rna_printk(KERN_ERR,"Failed to get send buf for "
                         *            "ios [%p] tag ["TAGFMT"] res [%d] "
                         *            "buf [%p]\n", ios, TAGFMTARGS(ios->tag),
                         *            result, buf_entry); 
                         */
                        ios_to_process = NULL;
                        if (alloc_rdma_failed) {
                            /*
                             * If both rdma & send buf allocations failed,
                             * give up altogether!
                             */
                            next = &conn->io_queue; // break out of ios loop
                        }
                    } else {
                        atomic_inc(&conn->send_bufs_allocated);
                        atomic_inc(&conn->send_bufs_in_use);
                    }
                }
                break;
                
            case RNABLK_INIT:
            case RNABLK_BOGUS_OP_TYPE:
                rna_printk(KERN_ERR,
                           "unexpected io type [%s] (0x%x)\n",
                           rnablk_op_type_string(ios->type),
                           ios->type);
                BUG_ON(TRUE);
            }

            if (NULL != ios_to_process) {
                break;
            }
        }

        if (NULL == ios_to_process) {
            break;
        }

        rnablk_dequeue_conn_io(ios_to_process);
        rna_spin_in_stack_unlock_irqrestore(conn->sc_lock, flags);

#ifdef RNA_USE_IOS_TIMERS
        /*
         * This specifically addresses the rnablk_process_detach()
         * "frozen" state, which can leave ios's in the conn->io_queue
         * with expired timers after rejoin.  Reset the timer else we'll
         * end up discarding the response, causing hung I/O's!
         */
        if (atomic_read(&ios->ios_timer_fired)) {
            rnablk_retrack_ios(ios);    // really just need to set timer...
        }
#endif /* RNA_USE_IOS_TIMERS */

        /* reset these since we found something to process */
        alloc_rdma_failed = alloc_send_failed = FALSE;
        ios = ios_to_process;

        rnablk_trace_ios(ios);
        switch( ios->type ) {
        case RNABLK_RDMA_READ:
        case RNABLK_RDMA_WRITE:
            if (likely(rnablk_ios_uses_local_dma(ios))) {
                BUG_ON(NULL != buf_entry);
            } else {
                BUG_ON(NULL == buf_entry);
            }
            dispatch_io_request(ios, buf_entry);
            num_ios_dispatched++;
            break;
        case RNABLK_LOCK_MASTER_BLK:
        case RNABLK_CACHE_QUERY:
            BUG_ON(NULL == buf_entry);
            dispatch_query_request(ios, buf_entry);
            num_commands_dispatched++;
            break;
        case RNABLK_MD_QUERY:
            BUG_ON(NULL != buf_entry);
            dispatch_query_request(ios, NULL);
            num_commands_dispatched++;
            break;
        case RNABLK_CHANGE_REF:
        case RNABLK_CHANGE_REF_NORESP:
        case RNABLK_MASTER_DEREF:
        case RNABLK_MASTER_DEREF_NORESP:
        case RNABLK_MASTER_INVD:
        case RNABLK_DEREF_REQUEST_RESP:
            BUG_ON(NULL == buf_entry);
            rnablk_io_dispatched(ios);
            dispatch_command(ios, buf_entry);
            num_commands_dispatched++;
            break;
        case RNABLK_WRITE_SAME:
        case RNABLK_COMP_AND_WRITE:
        case RNABLK_RSV_ACCESS_RESP:
            BUG_ON(NULL == buf_entry);
            rnablk_io_dispatched(ios);
            dispatch_generic_cmd(ios, buf_entry);
            num_commands_dispatched++;
            break;
        case RNABLK_SCSI_PASSTHRU:
            BUG_ON(NULL == buf_entry);
            rnablk_io_dispatched(ios);
            dispatch_scsi_passthru(ios, buf_entry);
            num_commands_dispatched++;
            break;
        
        case RNABLK_INIT:
        case RNABLK_BOGUS_OP_TYPE:
            rna_printk(KERN_ERR,
                       "unexpected io type [%s] (0x%x)\n",
                       rnablk_op_type_string(ios->type),
                       ios->type);
            BUG_ON(TRUE);
        }

        buf_entry = NULL;   /* Consumed (if there was one) */

        msecs = jiffies_to_msecs(get_jiffies() - start_jiffies);

        if (unlikely(msecs > RNABLK_DISPATCH_LIMIT_MSECS)) {
            rna_printk(KERN_INFO, "took [%lu] msecs to dispatch [%d] "
                       "commands and [%d] IOs.  io_queue_length [%d].\n",
                       msecs,
                       num_commands_dispatched,
                       num_ios_dispatched,
                       atomic_read(&conn->io_queue_length));
        }

 restart_loop:
        rna_spin_in_stack_lock_irqsave(conn->sc_lock, flags);

    } while (!list_empty(&conn->io_queue)
             && msecs <= RNABLK_DISPATCH_LIMIT_MSECS
             && !atomic_read(&rna_service_detached));

    atomic_bit_clear(&conn->rsc_flags, RSC_F_DISPATCHING);

    /* If we stopped with items in the queue for some reason, retry later */
    if (unlikely(0 != atomic_read(&conn->io_queue_length))) {
        /*
         * If we ran out of buffers and dispatch_on_completion is already
         * set, then don't reschedule.  For all other cases, do reschedule.
         */
        if ((alloc_rdma_failed || alloc_send_failed)
            && !atomic_bit_test_and_set(&conn->rsc_flags,
                                        RSC_F_DISPATCH_ON_COMPLETION)) {
            ;
        } else {
            rnablk_schedule_conn_dispatch_on(conn, mt_workq);
            atomic_inc(&conn->dispatching_rescheduled);
        }
    }
    rna_spin_in_stack_unlock_irqrestore(conn->sc_lock, flags);

    EXITV;
}

// runs in kthread context
//
// Safe for softirq when force_queue is TRUE
void
rnablk_queue_or_dispatch(struct rnablk_server_conn *conn, 
                         struct io_state *ios, 
                         int force_queue)
{
    lockstate_t flags;

    BUG_ON(NULL==ios);

    if (unlikely(rnablk_command_is_ordered(ios))) {
        rna_spin_lock_irqsave(ios->dev->ordered_cmd_lock, flags);
        if (ios != list_first_entry(&ios->dev->ordered_commands,
                                    struct io_state,
                                    ordered_l)) {
            force_queue = 1;
            rna_printk(KERN_INFO, "Forcing queue of %s command\n", 
                       rnablk_op_type_string(ios->type));
            BUG_ON(list_empty(&ios->dev->ordered_commands));
        }
        rna_spin_unlock_irqrestore(ios->dev->ordered_cmd_lock, flags);
    }

    if (likely(force_queue)) {
        if (unlikely(NULL == conn)) {
            rna_printk(KERN_ERR, "ios [%p] tag ["TAGFMT"] type [%s] [%s] "
                       "block [%"PRIu64"] state [%s] ep [%p] has NULL conn "
                       "or disconnected conn\n", ios, TAGFMTARGS(ios->tag),
                       rnablk_op_type_string(ios->type), ios->dev->name,
                       ios->blk->block_number,
                       rnablk_cache_blk_state_string(ios->blk->state), ios->ep);
            rnablk_end_request(ios, -EINVAL);
            return;
        }

        rnablk_trace_ios(ios);

        /* Queue the request */
        rna_spin_in_stack_lock_irqsave(conn->sc_lock, flags);
        rnablk_queue_conn_io(conn, ios, QUEUE_TAIL);
        rna_spin_in_stack_unlock_irqrestore(conn->sc_lock, flags);
    } else {
        rnablk_this_or_next_request(conn, ios);
    }
}

// runs in kthread context
static void
rnablk_conn_dispatch_wf(rnablk_workq_cb_arg_t arg)
{
    struct work_struct *work = (struct work_struct *)arg;
    struct rnablk_work *w = container_of( work,struct rnablk_work,work );
    struct rnablk_conn_dispatch_wf_data *wd = &w->data.rwd_rnablk_conn_dispatch_wf;
    struct rnablk_server_conn *conn = wd->conn;
    int max_passes = 2;
    uint64_t start_seconds = get_seconds();
    ENTER;

	UNREFERENCED_PARAMETER(ret);

    if (likely(rnablk_conn_connected(conn))) {
        do {
            /* All dispatches need up to now will be handled completely below */
            atomic_set(&conn->dispatch_needed, 0);

            rnablk_next_request(conn);

        } while (likely(rnablk_conn_connected(conn)) &&
                 likely(--max_passes > 0) &&
                 unlikely(0 != atomic_read(&conn->dispatch_needed)));

        /* Scheduled dispatch completed */
        atomic_bit_clear(&conn->rsc_flags, RSC_F_DISPATCH_SCHEDULED);

        /* If a dispatch became needed after we thought we were done, schedule another */
        if (unlikely(0 != atomic_read(&conn->dispatch_needed))) {
            rnablk_schedule_conn_dispatch(conn);
        }
    } else if (NULL != conn) {
        rna_printk(KERN_ERR,
                   "CS ["rna_service_id_format"] in unexpected state [%s]\n",
                   rna_service_id_get_string(&conn->id),
                   rnablk_conn_state_string(atomic_read(&conn->state)));
    }

    rnablk_server_conn_put(conn);

    rnablk_mempool_free( w, work_cache_info );
    rnablk_finish_workq_work(start_seconds);
    EXITV;
}

/* 
 * runs at softirq level
 *
 * Schedule dispatching on a specific workq (e.g. the ordered workq
 * when deferring after other completions).
 * 
 * Take some steps here to prevent the next request from running on >1
 * workq thread at a time.
 */
#ifdef WINDOWS_KERNEL
void rnablk_schedule_conn_dispatch_on(struct rnablk_server_conn *conn, 
                                      rna_service_work_queue_t *wq)
#else
void rnablk_schedule_conn_dispatch_on(struct rnablk_server_conn *conn, 
                                      struct workqueue_struct *wq)
#endif /*WINDOWS_KERNEL*/
{
    struct rnablk_work *w = NULL;
    struct rnablk_conn_dispatch_wf_data *wd = NULL;
    ENTER;

    BUG_ON(NULL==conn);
    if (unlikely(!atomic_read(&shutdown) &&
                 !atomic_read(&rna_service_detached) &&
                 (0 != atomic_read(&conn->io_queue_length)))) {

        /* Indicate additional dispatch needed */
        atomic_inc(&conn->dispatch_needed);

        /* Do nothing if dispatch already scheduled to run somewhere */
        if (likely(!atomic_bit_test_and_set(&conn->rsc_flags,
                                            RSC_F_DISPATCH_SCHEDULED))) {
            goto out;
        }

        if (unlikely(NULL == (w = rnablk_mempool_alloc( work_cache_info )))) {
            atomic_bit_clear(&conn->rsc_flags, RSC_F_DISPATCH_SCHEDULED);
            GOTO( err,-ENOMEM );
        }

        // kick start request processing
        RNABLK_INIT_RNABLK_WORK(w, wd, rnablk_conn_dispatch_wf);
        atomic_inc(&conn->rsc_refcount);
        wd->conn = conn;
        rna_queue_work( wq,&w->work );
    }

out:
    EXITV;
err:
    printk( "%s: failed to allocate memory for work queue item\n",__FUNCTION__ );
    goto out;
}

static int
rnablk_wake_up_cb(struct rnablk_server_conn *conn,
                  void                      *context)
{
    boolean devconns_too = (boolean)((uintptr_t)context);
    struct rnablk_server_conn *devconn;
    rnablk_cachedev_t *cdp;
    struct list_head *ent;
    lockstate_t irqflags;
    int i;

    if (rnablk_conn_connected(conn)) {
        rnablk_schedule_conn_dispatch(conn);

        if (devconns_too && is_parent_conn(conn)
            && atomic_read(&conn->rsc_connected_conns) > 1) {
            /*
             * rsc_connected_conns shows there may be other live child
             * connections.  we've been asked to schedule them too.
             */
            rna_spin_in_stack_lock_irqsave(conn->sc_lock, irqflags);
            list_for_each(ent, &conn->rsc_cachedevs) {
                cdp = list_entry(ent, rnablk_cachedev_t, rcd_link);
                for (i = 0; i < RNABLK_MAX_DEV_CONNS; i++) {
                    devconn = cdp->rcd_conns[i];
                    if (NULL != devconn && rnablk_conn_connected(devconn)) {
                        rnablk_schedule_conn_dispatch(devconn);
                    }
                }
            }
            rna_spin_in_stack_unlock_irqrestore(conn->sc_lock, irqflags);
        } 
    }
    return 0;
}

// runs in kthread context
void
rnablk_wake_up_all(boolean devconns_too)
{
    unsigned char oldirql = 0;
    ENTER;

    UNREFERENCED_PARAMETER(ret);

    rna_down_read(&svr_conn_lock, &oldirql);
    rnablk_cache_foreach(&cache_conn_root, rnablk_wake_up_cb,
                         (void *)((uint64_t)devconns_too));
    rna_up_read(&svr_conn_lock, oldirql);

    EXITV;
}

// runs in kthread context
static void
rnablk_wake_up_wf(rnablk_workq_cb_arg_t arg)
{
    struct work_struct *work = (struct work_struct *)arg;
    struct rnablk_work *w = container_of( work,struct rnablk_work,work );
    uint64_t start_seconds = get_seconds();
    ENTER;

	UNREFERENCED_PARAMETER(ret);

    /* All wakeups need up to now will be handled completely below */
    atomic_set(&wakeup_needed, 0);

    rnablk_wake_up_all(TRUE);

    /* Scheduled wakeup completed */
    atomic_set(&wakeup_scheduled, 0);

    /* If more wakeups were needed since this one was begun, ensure
     * that another one is scheduled
     */
    if (unlikely(0 != atomic_read(&wakeup_needed))) {
        rna_printk(KERN_DEBUG, "Another wakeup was needed immediately\n");
        rnablk_schedule_wake_up_all();
    }

    rnablk_mempool_free( w, work_cache_info );
    rnablk_finish_workq_work(start_seconds);
    EXITV;
}

/* 
 * runs at softirq level
 *
 * Since mt_workq is multithreaded, we take some steps here to 
 * prevent the wakeup from running on >1 mt_workq thread at a time.
 * One wakeup sweep at a time is good enough.
 */
void
rnablk_schedule_wake_up_all(void)
{
    struct rnablk_work *w = NULL;
    struct rnablk_wake_up_wf_data *wd = NULL;
    ENTER;

    if (likely(!atomic_read(&shutdown)) &&
        likely(!atomic_read(&rna_service_detached))) {
        /* Indicate additional wakeup needed */
        atomic_inc(&wakeup_needed);
        /* Do nothing if wakeup already scheduled to run somewhere */
        if (likely(FALSE != atomic_cmpxchg(&wakeup_scheduled, FALSE, TRUE)))
            goto out;

        if (unlikely(NULL == (w = rnablk_mempool_alloc( work_cache_info )))) {
            atomic_set(&wakeup_scheduled, FALSE);
            GOTO( err,-ENOMEM );
        }

        // kick start request processing
        RNABLK_INIT_RNABLK_WORK(w, wd, rnablk_wake_up_wf);
        rna_queue_work( mt_workq,&w->work );
    }

out:
    EXITV;
err:
    printk( "%s: failed to allocate memory for work queue item\n",__FUNCTION__ );
    goto out;
}

static void
rnablk_queued_request(rnablk_workq_cb_arg_t arg)
{
    rnablk_dwork_t w = RNABLK_ARG_DWORK(arg);
    struct cache_blk *blk = w->data.rwd_rnablk_queued_deref_wf.blk;

    if (likely(!atomic_read(&shutdown))) {
        if (rnablk_svcctl_is_frozen()) {
            /*
             * If we're in a frozen state, don't restart the I/O.
             * Just try again later.
             */
            if (likely(!atomic_read(&shutdown))) {
                rna_printk(KERN_INFO,
                           "Requeueing [%s] block [%"PRIu64"] for [%lu] msecs\n",
                           blk->dev->name,
                           blk->block_number,
                           RNABLK_FREEZE_DELAY_MS);
                rna_queue_delayed_work(mt_workq, RNABLK_DWORK_OBJECT(w),
                                      msecs_to_jiffies(RNABLK_FREEZE_DELAY_MS));
                return;
            }
        } else {
            atomic_bit_clear(&blk->cb_flags, BLK_F_QUEUED_DRAIN);
            rna_printk(KERN_INFO,
                       "Draining [%s] block [%"PRIu64"]\n",
                       blk->dev->name,
                       blk->block_number);
            rnablk_cache_blk_drain(blk);
        }
    }
    rnablk_cache_blk_release(blk);
    if (w->delayed) {
        atomic_dec(&delayed_work);
    }
    RNABLK_FREE_DWORK(w);
}

/* caller is responsible for making sure blk is in correct state */
/* delay time is in milliseconds */
void
rnablk_queue_delayed_request(struct io_state *ios, int msecs)
{
    rnablk_dwork_t w;
    struct cache_blk *blk = ios->blk;

    if (likely(!atomic_read(&shutdown))) {
        w = RNABLK_ALLOC_DWORK();
        if (NULL == w) {
            rna_printk(KERN_ERR, "Failed to allocate workq item for ios [%p] "
                       "tag ["TAGFMT"] block [%llu]\n", ios,
                       TAGFMTARGS(ios->tag), blk->block_number);
        } else {
            rnablk_queue_blk_io(blk, ios, QUEUE_TAIL);
            if (atomic_bit_test_and_set(&blk->cb_flags, BLK_F_QUEUED_DRAIN)) {
                rnablk_cache_blk_ref(blk);
                RNABLK_INIT_DWORK(w, rnablk_queued_request);
                w->data.rwd_rnablk_queued_deref_wf.blk = blk;
                rna_queue_delayed_work(mt_workq, RNABLK_DWORK_OBJECT(w),
                                       msecs_to_jiffies(msecs));
            } else {
                RNABLK_FREE_DWORK(w);
            }
        }
    }
}

// caller must not hold block's lock
void
rnablk_start_blk_io(struct cache_blk * blk, boolean devconn_too)
{
    struct rnablk_server_conn *conn = NULL;

    // TODO: non-atomic read of state
    if (likely(RNABLK_CACHE_BLK_INVALID != blk->state)) {
        if (likely(NULL != blk->ep)) {
            conn = rnablk_get_ep_conn(blk->ep);
            if (likely(rnablk_conn_connected(conn))) {
                rnablk_next_request(conn);
            } else {
                rna_printk(KERN_INFO, "block [%llu] conn ["CONNFMT"] not "
                           "connected\n", blk->block_number, CONNFMTARGS(conn));
            }
        }
        if (devconn_too && rnablk_conn_connected(blk->cb_dev_conn)) {
            rnablk_next_request(blk->cb_dev_conn);
        }
    } else {
        rna_printk(KERN_INFO,
                   "dev [%s] block [%"PRIu64"] unexpected state [%s]\n",
                   blk->dev->name,
                   blk->block_number,
                   rnablk_cache_blk_state_string(blk->state));
    }
}

// inlining discouraged because it increases the caller's stack size more than we'd like
void
rnablk_requeue(struct com_ep *ep,struct io_state *ios,
               struct scatterlist *sgl,
               enum dma_data_direction dir)
{
    struct rnablk_device *dev = ios->dev;
    struct rnablk_server_conn *conn;
    lockstate_t flags;

    ENTER;

#if (defined(WINDOWS) && !defined(_DEBUG))
    UNREFERENCED_PARAMETER(dev);
#endif
    UNREFERENCED_PARAMETER(ret);

    conn = (struct rnablk_server_conn *)(com_get_ep_context(ep));
    BUG_ON(NULL==dev);
    BUG_ON(NULL==conn);
    rnablk_trace_ios(ios);

#ifndef WINDOWS_KERNEL
    // cleanup and get ready for the retry attempt
    if (ios->sgl) {
        com_dereg_sgl(ep, ios->sgl, ios->nsgl, dir);
    }

    if (NULL != sgl) {
        // replace the scatter list
        memcpy( ios->sgl,sgl,ios->nsgl * sizeof( struct scatterlist ) );
    }
#endif /*WINDOWS_KERNEL*/

    // re-queue at the head of the list
    rna_spin_in_stack_lock_irqsave(conn->sc_lock, flags);
    rnablk_queue_conn_io(conn, ios, QUEUE_HEAD);
    rna_spin_in_stack_unlock_irqrestore(conn->sc_lock, flags);

    EXITV;
}

// Caller must hold blk's bl_lock
void
rnablk_queue_blk_io_nolock(struct cache_blk   *blk,
                           struct io_state    *ios,
                           queue_where_t      where)
{
    rnablk_queue_ios_generic(ios, IOS_QS_BLOCK, &blk->bl, where);
}

void
rnablk_queue_blk_io(struct cache_blk   *blk,
                    struct io_state    *ios,
                    queue_where_t      where)
{
    lockstate_t flags;

    rnablk_lock_blk_irqsave(blk, flags);
    rnablk_queue_blk_io_nolock(blk, ios, where);
    rnablk_unlock_blk_irqrestore(blk, flags);
}

// Caller must hold blk's bl_lock
void rnablk_dequeue_blk_io_nolock(struct cache_blk *blk, struct io_state  *ios)
{
    rnablk_trace_ios(ios);

    rnablk_dequeue_ios_generic(ios, IOS_QS_BLOCK);
    if (unlikely(rnablk_command_is_ordered(ios))) {
        rnablk_dequeue_ordered_command(ios);
    }
}

/*
 * rnablk_queue_conn_io()
 *  Add an ios to the conn 'io_queue'.
 *  Caller must hold conn->sc_lock.
 */
void
rnablk_queue_conn_io(struct rnablk_server_conn *conn,
                     struct io_state           *ios,
                     queue_where_t             where)
{
    BUG_ON((QUEUE_TAIL != where) && (QUEUE_HEAD != where));

    rnablk_queue_ios_generic(ios, IOS_QS_CONN, &conn->io_queue, where);
    ios->conn = conn;
    atomic_inc(&conn->io_queue_length);
    if (likely(NULL != ios->dev)) {
        atomic_inc(&ios->dev->stats.in_queue);
    }
}

/* caller must hold conn->sc_lock */
void
rnablk_dequeue_conn_io(struct io_state *ios)
{
    rnablk_dequeue_ios_generic(ios, IOS_QS_CONN);
    atomic_dec(&ios->conn->io_queue_length);
    ios->conn = NULL;         /* Conn only valid while in conn queue */
    if (NULL != ios->dev) {
        atomic_dec(&ios->dev->stats.in_queue);
    }
}

// Caller must call rnablk_next_request() if they want query to be dispatched
int queue_command(struct io_state *ios)
{
    struct rnablk_device *dev;
    struct rnablk_server_conn *conn;
    ENTER;

    rnablk_trace_ios(ios);

    dev  = ios->dev;

    conn = rnablk_get_ios_conn(ios);
    if (unlikely(NULL == conn)) {
        rna_printk(KERN_ERR,
                   "Not queuing ios [%p] tag ["TAGFMT"] type [%s] block [%llu] "
                   "conn ["CONNFMT"] because disconnected.\n",
                   ios,
                   TAGFMTARGS(ios->tag),
                   rnablk_op_type_string(ios->type),
                   ios->blk ? ios->blk->block_number : 0,
                   CONNFMTARGS(conn));
        GOTO( out,-EINVAL );
    }

    rnablk_queue_or_dispatch(conn, ios, FORCE_QUEUED_IO);

out:
    EXIT;
}

// Caller must hold reference on block
void
rnablk_queue_request(int               type,
                     struct com_ep    *ep,
                     struct io_state  *ios,
                     struct cache_blk *blk,
                     int               force_queue,
                     boolean           have_blk_lock)
{
    struct rnablk_device *dev;
    struct rnablk_server_conn *conn = NULL;
    //int start_now = 0;
    //unsigned long flags;
    ENTER;

#ifdef WINDOWS_KERNEL
	UNREFERENCED_PARAMETER(ret);
#endif //WINDOWS_KERNEL

    BUG_ON(NULL == ios || NULL == ios->blk);
    BUG_ON(NULL == ios->dev);
    BUG_ON(NULL == ep);
    RNABLK_BUG_ON(blk != ios->blk, "ios=%p unexpected blk=%p ios->blk=%p\n",
                  ios, blk, ios->blk); 

    dev       = ios->dev;
    ios->type = type;

    rnablk_set_ios_ep(ios, ep);

    conn = rnablk_get_ios_conn(ios);
    if (unlikely(!rnablk_conn_connected(conn))) {
        // blk->state read below without lock, may be incorrect
        rna_printk(KERN_ERR,
                   "ios [%p] tag ["TAGFMT"] type [%s] [%s] block [%"PRIu64"] "
                   "state [%s] ep [%p] has NULL conn or disconnected conn\n",
                   ios,
                   TAGFMTARGS(ios->tag),
                   rnablk_op_type_string(ios->type),
                   dev->name,
                   ((NULL != blk) ? blk->block_number : 0),
                   ((NULL != blk) ? rnablk_cache_blk_state_string(blk->state) : "NULL"),
                   ep);

        /* leave this to be processed by disconnect callback */
        if (likely(have_blk_lock)) {
            rnablk_queue_blk_io_nolock(blk, ios, QUEUE_TAIL);
        } else {
            rnablk_queue_blk_io(blk, ios, QUEUE_TAIL);
        }
    } else {
        if (unlikely(dev->magic != RNABLK_DEVICE_MAGIC)) {
            printk( "%s: WARNING: request for deleted device object %p\n",
                    __FUNCTION__,dev );
            BUG_ON(TRUE);
        }

        TRACE(DBG_FLAG_VERBOSE,"device [%s] ios [%p] tag ["TAGFMT"] ios "
              "type [%s]\n",
               ios->dev->name,
               ios, TAGFMTARGS(ios->tag),
               rnablk_op_type_string(ios->type));

        rnablk_queue_or_dispatch(conn, ios, force_queue);
    }

    EXITV;
}
