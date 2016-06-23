/**
 * <rnablk_callbacks.c> - Dell Fluid Cache block driver
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

/* Here you will find callbacks for underlying RNA modules (COM/RNA Service) */

#include "rb.h"
#include "trace.h"
#include "rnablk_util.h"
#include "rnablk_cache.h"
#include "rnablk_block_state.h"
#include "rnablk_io_state.h"
#include "rnablk_protocol.h"
#include "rnablk_globals.h"
#include "rnablk_data_transfer.h"
#include "rnablk_queue_dispatch.h"
#include "rnablk_device.h"

#ifdef WINDOWS_KERNEL
#include "rna_com_status.h"
#include "rnablk_win_com.h"
#include "rnablk_win_util.h"
#endif /*WINDOWS_KERNEL*/

#ifdef WINDOWS_KERNEL
// Force RDMA disabled for Windows if not already disabled
#ifndef _DISABLE_IB_
#define _DISABLE_IB_ 1
#endif /* _DISABLE_IB_ */
#endif /*WINDOWS_KERNEL*/

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
#include "rnablk_callbacks.tmh"
#endif


/* runs in passive context */
#ifndef WINDOWS_KERNEL
static 
#endif /*WINDOWS_KERNEL*/
int
rnablk_connect_cb(struct com_ep *ep, void *ep_ctx)
{
    struct rnablk_server_conn *conn;
    ENTER;

    conn = (struct rnablk_server_conn *)(com_get_ep_context(ep));
    switch(com_get_ep_user_type(ep)) {
        case USR_TYPE_CACHE:
            ret = rnablk_cache_connected( ep );
            break;
        default:
            break;
    }

    if (0 == ret) {
        rna_printk(KERN_NOTICE,
                   "connection from server ["rna_service_id_format"] ep [%p] "
                   "conn ["CONNFMT"]\n",
                   rna_service_id_get_string(&conn->id), ep,
                   CONNFMTARGS(conn));
    } else {
        rna_printk(KERN_ERR,
                   "eps raced for server ["rna_service_id_format"] tossing "
                   "ep [%p] conn ["CONNFMT"]\n",
                   rna_service_id_get_string(&conn->id), ep,
                   CONNFMTARGS(conn));
    }
    EXIT;
}

/* runs in passive context */
#ifndef WINDOWS_KERNEL
static
#endif /*WINDOWS_KERNEL*/
int
rnablk_disconn_cb(struct com_ep *ep, void *ctxt)
{
    struct rnablk_server_conn *conn = NULL;
    struct sockaddr_in dst_in;
    unsigned long flags;
    ENTER;

    if( atomic_read( &shutdown ) ){
	    goto out;
    }

    switch(com_get_ep_user_type(ep)) {
        case USR_TYPE_CACHE:
            conn = (struct rnablk_server_conn *)(com_get_ep_context(ep));

            BUG_ON(NULL == conn);
            BUG_ON(IS_ERR(conn));
            if (FALSE == rnablk_verify_conn(conn)) {
                /*
                 * We currently can free the rnablk_server_conn structure
                 * while a connect is in progress.  This rnablk_verify_conn()
                 * check is to try to catch this situation.  It is not a
                 * complete resolution to this issue, though.  HRM-5363 is
                 * to address this situation more completely.
                 */
                dst_in = get_dest_sockaddr_from_ep(ep);
                rna_printk(KERN_ERR, 
                           "disconnect for EP type [%s] to ["NIPQUAD_FMT"]. "
                           "Invalid conn [%p]\n",
                           get_user_type_string(com_get_ep_user_type(ep)),
                           NIPQUAD(dst_in.sin_addr.s_addr),
                           conn);
            } else {
                rna_spin_lock_irqsave(conn->sc_lock, flags);
                if ((ep == conn->ep) || (NULL == conn->ep)) {
                    rna_printk(KERN_ERR,
                               "Disconnect from CS ["rna_service_id_format"] "
                               "cachedev [0x%"PRIx64"] ep [%p] conn ["CONNFMT"] "
                               "p_conn [%p] conn_count [%d] iface [%s] "
                               "active_if [%d] if_attempts [%d]\n",
                               rna_service_id_get_string(&conn->id),
                               is_parent_conn(conn) ?  0
                               : conn->rsc_cachedev->rcd_id,
                               ep, CONNFMTARGS(conn), conn->rsc_parent_conn,
                               atomic_read(&conn->conn_count),
                               com_get_transport_type_string(
                                   conn->if_table.ifs[conn->rsc_active_if].type),
                               conn->rsc_active_if, conn->if_attempts);

                    rna_printk(KERN_INFO,
                               "conn ["CONNFMT"] ep [%p] state [%s]->[%s]\n",
                               CONNFMTARGS(conn), conn->ep,
                               rnablk_conn_state_string(atomic_read(&conn->state)),
                               rnablk_conn_state_string
                               (RNABLK_CONN_DISCONNECT_INPROG));
                    rna_spin_unlock_irqrestore(conn->sc_lock, flags);
                    rnablk_process_conn_disconnect(conn);
                } else {
                    rna_spin_unlock_irqrestore(conn->sc_lock, flags);
                    rna_printk(KERN_DEBUG, "ep [%p] not disconnecting conn ["
                               CONNFMT"]--not conn's ep [%p]\n", 
                               ep, CONNFMTARGS(conn), conn->ep);
                }
            }
            break;
        default:
            dst_in = get_dest_sockaddr_from_ep(ep);
            rna_printk(KERN_ERR, "unexpected disconnect for EP type [%s] "
                       "to ["NIPQUAD_FMT"]\n",
                       get_user_type_string(com_get_ep_user_type(ep)),
                       NIPQUAD(dst_in.sin_addr.s_addr));
            break;
    }

out:
	com_release_ep(ep);
    EXIT;
}

void
rnablk_destructor_cb(const struct com_ep *ep,
                     void                *ep_ctx)
{
    struct rnablk_server_conn *conn = (struct rnablk_server_conn *)ep_ctx;

    BUG_ON(NULL == conn);

    /*
     * Note on Windows the ep may have already been freed by
     * comAPI.c->apiEPDestructor (if it ended up calling us via proxy).
     * So be careful not to dereference 'ep'.
     */
    rna_printk(KERN_INFO,
               "CS ["rna_service_id_format"] conn ["CONNFMT"] ep [%p]\n",
               rna_service_id_get_string(&conn->id), CONNFMTARGS(conn), ep);

    /* Drop ep's reference on conn */
    rnablk_server_conn_put(conn);
}

// runs at softirq level
#ifndef WINDOWS_KERNEL
static 
#endif /*WINDOWS_KERNEL*/
int
rnablk_recv_cb(struct com_ep *ep, void *ep_ctx, void *data, int len, int status)
{
	struct cache_cmd *cmd;
    struct sockaddr_in dst_in;
    int ret = 0;

    cmd = (struct cache_cmd *)data;

    // ignore flush errors when using IB
    if (unlikely(5 == status)) {
        TRACE(DBG_FLAG_VERBOSE,
              "Ignoring flush error on ep [%p] user_type [%s] status [%d] "
              "context [%p]\n", ep,
              get_user_type_string(com_get_ep_user_type(ep)), status,
              (void*)(uint64_t) com_get_ep_context(ep));
        goto out;
    } else if (unlikely(0 != status)) {
        dst_in = get_dest_sockaddr_from_ep(ep);
        rna_printk(KERN_ERR, "Error [%d] for EP type [%s] to ["NIPQUAD_FMT"], "
                   "disconnecting\n", status,
                   get_user_type_string(com_get_ep_user_type(ep)),
                   NIPQUAD(dst_in.sin_addr.s_addr));
    }

    TRACE(DBG_FLAG_VERBOSE,
          "type [%s] cookie [0x%"PRIx64"] ep [%p] user_type [%s] status [%d] "
          "context [%p]\n", get_cmd_type_string(cmd->h.h_type),
          cmd->h.h_cookie, ep, get_user_type_string(com_get_ep_user_type(ep)),
          status, (void*)(uint64_t) com_get_ep_context(ep));

    if (likely(!atomic_read(&shutdown))) {
        if (unlikely(com_get_ep_user_type(ep) == USR_TYPE_CACHE &&
                     cmd->h.h_type == CACHE_DEREF_REQUEST)) {
            rnablk_queue_deref_req(ep, &cmd->u.cache_deref_req, TRUE);
        } else {
            rnablk_process_recv_cmp(cmd, ep, status);
        }
    }

 out:
    return ret;
}

/*
 * rnablk_data_op_complete_common()
 *  Common to linux and Windows.
 *
 * Returns TRUE if ios should be completed, FALSE otherwise.
 */
int
rnablk_data_op_complete_common(struct io_state *ios, int err)
{
    int ret = TRUE;
    lockstate_t flags;
    struct rnablk_server_conn *conn;
    mutexstate_t mutex_handle;
    boolean need_unlock = TRUE;

    /* 
     * This function locks the cache block, so call it outside
     * of this function's lock.
     */
    rnablk_dec_inflight_ios(ios->blk);
    rnablk_lock_blk_irqsave(ios->blk, flags);
    if (unlikely(!rnablk_cache_blk_state_is_connected(ios->blk->state))) {
        rna_printk(KERN_INFO, "ios [%p] tag ["TAGFMT"] type [%s] "
                   "[%s] block [%"PRIu64"] state [%s] refcnt ["BLKCNTFMT"] "
                   "inflight_ios [%d] dispatch queue [%s] - not connected\n",
                   ios, TAGFMTARGS(ios->tag), rnablk_op_type_string(ios->type), 
                   ios->blk->dev->name,
                   ios->blk->block_number,
                   rnablk_cache_blk_state_string(ios->blk->state),
                   BLKCNTFMTARGS(ios->blk),
                   atomic_read(&ios->blk->inflight_ios),
                   list_empty(&ios->blk->dispatch_queue)?"empty":"nonempty");
        /* last I/O for block complete */
        if (rnablk_cache_blk_state_is_invalidate_pending(ios->blk->state)) {
            /*
             * If this ios is the only entry left in the dispatch queue, then
             * we can queue a deref to satisfy the pending invalidate.
             */
            if (is_only_entry_in_list(&ios->blk->dispatch_queue, ios, l)) {
                if (0 != atomic_read(&ios->blk->inflight_ios)) {
                    rna_printk(KERN_INFO,
                               "[%s] block [%"PRIu64"] state [%s] refcnt "
                               "["BLKCNTFMT"] inflight_ios [%d] dispatch "
                               "queue [%s]\n",
                               ios->blk->dev->name,
                               ios->blk->block_number,
                               rnablk_cache_blk_state_string(ios->blk->state),
                               BLKCNTFMTARGS(ios->blk),
                               atomic_read(&ios->blk->inflight_ios),
                               list_empty(&ios->blk->dispatch_queue)
                               ?"empty":"nonempty");
                } else {
                    rnablk_queue_deref(ios->blk, FALSE);
                }
            }
        } else if (RNABLK_CACHE_BLK_DISCONN_PENDING == ios->blk->state
                   && 0 == atomic_read(&ios->blk->inflight_ios)) {
            conn = rnablk_get_ep_conn(ios->blk->ep);
            if (g_md_conn == conn) {
                conn = NULL;
            }
            if (NULL != conn) {
                rnablk_unlock_blk_irqrestore(ios->blk, flags);
                rna_block_mutex_lock(&conn->block_list_lock, &mutex_handle);
                rnablk_lock_blk_irqsave(ios->blk, flags);

                if (RNABLK_CACHE_BLK_DISCONN_PENDING == ios->blk->state
                    && 0 == atomic_read(&ios->blk->inflight_ios)
                    && conn == rnablk_get_ep_conn(ios->blk->ep)) {

                    (void)rnablk_cache_blk_state_transition(ios->blk,
                                        RNABLK_CACHE_BLK_DISCONN_PENDING,
                                        RNABLK_CACHE_BLK_DISCONNECTED);
                    if (!atomic_bit_is_set(&ios->blk->cb_flags,
                                           BLK_F_DISCONN_FROZEN)) {
                        /*
                         * If the block is in hands of conn disconnect
                         * processing or cache-device failure processing,
                         * don't unset_blk_ep(), as that would also
                         * disassociate the block from its cache-device,
                         * which would interfere with the processing and
                         * potentially leave I/O for this block wedged.
                         */
                        rnablk_unset_blk_ep(ios->blk);
                    }
                    rnablk_queue_blk_restart(ios->blk);
                }

                rnablk_unlock_blk_irqrestore(ios->blk, flags);
                rna_block_mutex_unlock(&conn->block_list_lock, &mutex_handle);
                need_unlock = FALSE;
            } else {
                (void)rnablk_cache_blk_state_transition(ios->blk,
                                    RNABLK_CACHE_BLK_DISCONN_PENDING,
                                    RNABLK_CACHE_BLK_DISCONNECTED);
                rnablk_unset_blk_ep(ios->blk);
                rnablk_queue_blk_restart(ios->blk);
            }
        }
    }
    
    if (need_unlock) {
        rnablk_unlock_blk_irqrestore(ios->blk, flags);
    }

    return ret;
}

/*
 * Runs at softirq level
 * caller is expected to have reference on ios
 */
static int
rnablk_generic_completion( struct com_ep *ep,struct io_state *ios,int status )
{
    struct rnablk_server_conn *conn = NULL;
    struct rnablk_device *dev = NULL;
    lockstate_t irqflags;            
    struct sockaddr_in dst_in;
    mutexstate_t mutex_lock_handle;
    ENTER;

    BUG_ON(NULL == ios);

    rnablk_trace_ios(ios);

#ifdef TEST_OFFLINE_CACHE_DEVICE
    if (test_cachedev_fail_rdma
        && test_cachedev_fail_rdma == ios->blk->blk_cachedev->rcd_id
        && atomic_bit_is_set(&ios->blk->blk_cachedev->rcd_state,
                             RCD_STATE_ONLINE)) {
        rna_printk(KERN_ERR, "Injecting rdma CACHE_FAIL error for "
                   "ios [%p] tag ["TAGFMT"] block [%"PRIu64"]\n",
                   ios, TAGFMTARGS(ios->tag), ios->blk->block_number);
        test_cachedev_fail_rdma = 0;
        status = CB_RESP_CACHE_FAIL;
    }
    if (test_dev_conn_disconnect
        && test_dev_conn_disconnect == rnablk_get_ep_conn(ios->ep)->rsc_idx) {
        rna_printk(KERN_ERR, "Injecting rdma cachedev DISCON error for "
                   "ios [%p] tag ["TAGFMT"] block [%"PRIu64"]\n",
                   ios, TAGFMTARGS(ios->tag), ios->blk->block_number);
        rnablk_queue_conn_disconnect(rnablk_get_ep_conn(ios->ep));
        test_dev_conn_disconnect = 0;
        status = CB_RESP_FAIL;
    }
#endif /* TEST_OFFLINE_CACHE_DEVICE */
#ifdef TEST_STORAGE_ERROR
    if (0 == status
        && atomic_add_unless(&ios->blk->dev->rbd_test_err_inject, -1, 0)) {
        rna_printk(KERN_ERR, "Injecting STORAGE_ERROR for ios [%p] tag "
                   "["TAGFMT"] block [%llu]\n", ios, TAGFMTARGS(ios->tag),
                   ios->blk->block_number);
        status = CB_RESP_STORAGE_FAIL;
    }
#endif /* TEST_STORAGE_ERROR */

    rnablk_trc_discon(0, "ios [%p] tag ["TAGFMT"] block [%"PRIu64"] "
                      " err=%d state [%s] ref [%s] type [%s]\n", ios,
                      TAGFMTARGS(ios->tag),
                      ios->blk->block_number, status,
                      rnablk_cache_blk_state_string(ios->blk->state),
                      get_lock_type_string(ios->blk->ref_type),
                      rnablk_op_type_string(ios->type));

    //
    // scream about any IB layer errors encountered
    // ignore flush errors as those happen as a consequence of other errors
    if( unlikely(status) ) {
        if (!dev_is_persistent(ios->dev)) {
            rnablk_mark_cache_blk_bad_and_drain(ios->blk, TRUE);
        }
        BUG_ON(MD_CONN_EP_METAVALUE == ep);

        dst_in = get_dest_sockaddr_from_ep(ep);

        if (CB_RESP_EAGAIN == status) {
            // ratelimit EAGAIN errors as they can flood the logs
#ifndef WINDOWS_KERNEL
            if (printk_ratelimit()) {
#endif /*WINDOWS_KERNEL*/
                rna_printk(KERN_ERR,
                           "ios [%p] tag ["TAGFMT"] type [%s] "
                           "completion error [%d] [%s] "
                           "dev [%s] block [%"PRIu64"] state [%s] on server "
                           "["NIPQUAD_FMT"] ep [%p]\n",
                           ios,
                           TAGFMTARGS(ios->tag),
                           rnablk_op_type_string( ios->type ),
                           status,
                           get_rna_com_cb_resp_status_string(status),
                           ios->dev->name,
                           ios->blk->block_number,
                           rnablk_cache_blk_state_string(ios->blk->state),
                           NIPQUAD(dst_in.sin_addr.s_addr),
                           ep);
#ifndef WINDOWS_KERNEL
            }
#endif /*WINDOWS_KERNEL*/
        } else {
            rna_printk(KERN_ERR,
                       "ios [%p] tag ["TAGFMT"] type [%s] completion error [%d] "
                       "dev [%s] block [%"PRIu64"] state [%s] on server "
                       "["NIPQUAD_FMT"] ep [%p]\n",
                       ios,
                       TAGFMTARGS(ios->tag),
                       rnablk_op_type_string( ios->type ),
                       status,
                       ios->dev->name,
                       ios->blk->block_number,
                       rnablk_cache_blk_state_string(ios->blk->state),
                       NIPQUAD(dst_in.sin_addr.s_addr),
                       ep);
        }
    }

    dev = ios->dev;
    // we can't get conn_lock here as we are in soft IRQ context...
    conn = (struct rnablk_server_conn *)(com_get_ep_context(ep));

    if (unlikely((dev->magic != RNABLK_DEVICE_MAGIC) || (conn == NULL))) {
        rna_printk(KERN_WARNING, "WARNING: %s completion for deleted device "
                   "object %p\n", rnablk_op_type_string(ios->type), dev);
        rnablk_end_request(ios, -EIO);
        GOTO( out,-EINVAL );
    }

    TRACE(DBG_FLAG_VERBOSE,"ios [%p] tag ["TAGFMT"] conn [%p]\n",
          ios, TAGFMTARGS(ios->tag), conn);

    dec_in_flight(dev, ios);

    (void)rnablk_detect_cache_failure(ios, status, CB_RESP_CACHE_FAIL, FALSE);

    // end this request with the block layer
    rnablk_trc_master(IS_MASTER_BLK(ios->blk),
                      "MASTER op=%s st=%s l=%s\n",
                      rnablk_op_type_string(ios->type),
                      rnablk_cache_blk_state_string(ios->blk->state),
                      get_lock_type_string(ios->blk->ref_type));
    switch( ios->type ) {
    case RNABLK_RDMA_WRITE:
        /* Fallthru */
    case RNABLK_RDMA_READ:
        ret = rnablk_data_op_complete(ios, status);
        if (unlikely(0 != status)) {
            /*
             * if we failed, then leave IO on dispatch queue, put it back
             * in the tree, and disconnect
             */
            rnablk_retrack_ios(ios);
            rna_printk(KERN_INFO,
                       "status [%s] ios [%p] tag ["TAGFMT"] type [%s] "
                       "queue_state [%d]\n",
                       get_rna_com_cb_resp_status_string(status),
                       ios,
                       TAGFMTARGS(ios->tag),
                       rnablk_op_type_string(ios->type),
                       ios_queuestate_get(ios));
            switch (status) {
            case CB_RESP_FAIL:          // indicates a disconnect
            case CB_RESP_CACHE_FAIL:    // a cache-device failure
                /*
                 * Leave on the dispatch_queue for cleanup/resubmit
                 * during disconnect or offline_cachedev processing.
                 */
                RNABLK_BUG_ON(!ios_queuestate_test_and_set(ios,
                              IOS_QS_DISPATCH_COMPLETING,
                              IOS_QS_DISPATCH_FAILED_REDO),
                              "ios=%p unexpected qstate=%d status=%d\n", ios,
                              ios_queuestate_get(ios), status);
                break;
            case CB_RESP_OFFLINE:       // a path failure
                /*
                 * requeue I/O. delay awhile to give things a chance to
                 * recover.
                 */
                rnablk_io_completed(ios);
                rnablk_queue_delayed_request(ios, RNABLK_OFFLINE_DELAY_MS);
                break;
            case CB_RESP_EAGAIN:        // a replicated write failure
                BUG_ON(!ios_writes_data(ios));
                /*
                 * requeue I/O. delay is to avoid tight loop until
                 * resilver completes
                 */
                rnablk_io_completed(ios);
                rnablk_queue_delayed_request(ios, RNABLK_EAGAIN_DELAY_MS);
                break;
            default:
                rnablk_io_completed(ios);
                rnablk_end_request(ios, -EIO);
                break;
            }
            ret = status;
        } else if (ret) {
            /*
             * Update read/write timer counters
             */
            if (RNABLK_RDMA_READ == ios->type) {
                rna_atomic64_add((getrawmonotonic_ns() - ios->issue_time_ns),
                             &ios->dev->stats.bs_read_time);
            } else if (RNABLK_RDMA_WRITE == ios->type) {
                rna_atomic64_add((getrawmonotonic_ns() - ios->issue_time_ns),
                             &ios->dev->stats.bs_write_time);
            }
            /* Complete the request now */
            rnablk_io_completed(ios);
            rnablk_end_request(ios, 0);
            ret = 0;
        }
        break;
    case RNABLK_CHANGE_REF_NORESP:
        RNABLK_BUG_ON(NULL == ios->cmd
                      || CACHE_NO_REFERENCE !=
                      ios->cmd->u.cache_change_ref.desired_reference,
                      "ios [%p] tag ["TAGFMT"] cmd=%p desired_ref [%s] "
                      "unexpected state\n", ios, TAGFMTARGS(ios->tag),
                      ios->cmd, 
                      (ios->cmd 
                       ? get_lock_type_string(ios->cmd->u.cache_change_ref.desired_reference)
                       : "(none)"));
        if (unlikely(0 != status)) {
            /* this will drop the conn reference on the blk */
            rnablk_mark_cache_blk_bad_and_drain(ios->blk, TRUE);
        } else {                
            rna_block_mutex_lock(&conn->block_list_lock, &mutex_lock_handle);
            rnablk_lock_blk_irqsave(ios->blk, irqflags);
            
            if (!rnablk_cs_change_req_blk_transition(
                   conn, 
                   ios->blk,
                   ios->cmd->u.cache_change_ref.desired_reference)) {
                rna_printk(KERN_ERR,
                           "[%s] block [%"PRIu64"] in state [%s] ref type [%s] "
                           "transition [%s] -> [%s] failed.\n",
                           ios->blk->dev->name, ios->blk->block_number,
                           rnablk_cache_blk_state_string(ios->blk->state),
                           get_lock_type_string(ios->blk->ref_type),
                           get_lock_type_string(
                               ios->cmd->u.cache_change_ref.orig_reference),
                           get_lock_type_string(
                               ios->cmd->u.cache_change_ref.desired_reference));
            } else if (CACHE_NO_REFERENCE ==
                       ios->cmd->u.cache_change_ref.desired_reference) {
                if (!list_empty(&ios->blk->bl)) {
                    /*
                     * restart activity to ensure cleanup happens if this
                     * DEREF raced with some other CHANGE_REF
                     */
                    rnablk_queue_blk_restart(ios->blk);
                }
            }
            rnablk_cache_blk_update_dev_counts(ios->blk);
            rnablk_unlock_blk_irqrestore(ios->blk, irqflags);
            rna_block_mutex_unlock(&conn->block_list_lock, &mutex_lock_handle);
        }
        /* fallthru */
    case RNABLK_MASTER_DEREF_NORESP:
    case RNABLK_DEREF_REQUEST_RESP:
    case RNABLK_RSV_ACCESS_RESP:
        rnablk_io_completed(ios);
        rnablk_ios_finish(ios);
        break;
    case RNABLK_COMP_AND_WRITE:
        BUG();
        break;
        
    case RNABLK_CHANGE_REF:
    case RNABLK_MASTER_DEREF:
        // Change ref / deref ios not freed until response is processed
    default:
        rna_printk(KERN_ERR,
                   "unexpected io type [%s] (0x%x) completion\n",
                   rnablk_op_type_string(ios->type),
                   ios->type);
        BUG_ON(TRUE);
    }
    
    rnablk_schedule_conn_dispatch(conn);
out:
    EXIT;
}

// runs at softirq level
#ifndef WINDOWS_KERNEL
static 
#endif /*WINDOWS_KERNEL*/
int
rnablk_rdma_send_completion(struct com_ep *ep, void *ep_ctx, void *data,
                            int status)
{
    struct io_state *ios = NULL;
    struct rnablk_server_conn *conn;
    ios_tag_t ios_tag = (ios_tag_t)data;
    ENTER;

    conn = (struct rnablk_server_conn *)(com_get_ep_context(ep));

    if (likely(NULL != conn)) {
        atomic_dec(&conn->send_bufs_in_use);
    }

    if (NULL != data) {
        /* don't invalidate tag by setting response bit */
        ios = rnablk_cookie_to_ios_get_no_response(ios_tag);
    }

    if( likely(ios != NULL) ) {
        RNABLK_BUG_ON(NULL == ios->blk, "ios=%p type=%s\n", ios,
                      rnablk_op_type_string(ios->type));
        rnablk_trace_ios(ios);
        rnablk_trc_master(IS_MASTER_BLK(ios->blk),
                          "MASTER op=%s st=%s l=%s\n",
                          rnablk_op_type_string(ios->type),
                          rnablk_cache_blk_state_string(ios->blk->state),
                          get_lock_type_string(ios->blk->ref_type));

#ifdef WINDOWS_KERNEL    
        DoStorageTraceEtw(DbgLvlPerf, 
                          FldcVsmpSRBPerf, 
                          "rnablk_rdma_send_completion: SRB=0x%0I64X\n",
                          ios->SRBNumber); 
#endif
        switch( ios->type ) {
            case RNABLK_CHANGE_REF_NORESP:
            case RNABLK_MASTER_DEREF_NORESP:
            case RNABLK_DEREF_REQUEST_RESP:
            case RNABLK_RSV_ACCESS_RESP:
                if (ios_queuestate_test_and_set(ios, IOS_QS_DISPATCH,
                                                IOS_QS_DISPATCH_COMPLETING)) {
                    ret = rnablk_generic_completion(ep, ios, status);
                }
                break;
            case RNABLK_CHANGE_REF:
            case RNABLK_MASTER_DEREF:
                // De/Change-ref not complete until response arrives
                break;
            case RNABLK_RDMA_READ:
            case RNABLK_RDMA_WRITE:
                /*
                 * The response to change ref (to go from read->read/write or
                 * write-only->read/write) for an RDMA write or
                 * read may arrive before the send completion for
                 * that query is delivered here.  If that happens, and
                 * the ios tag is still found, the ios type may have
                 * already been changed to one of the RDMA types
                 * by the time we read it here.
                 */
                break;
            default:
                rna_printk(KERN_ERR,
                           "send completion for ios [%p] tag ["TAGFMT"] for "
                           "device [%s] block [%"PRIu64"] state [%s] of "
                           "unexpected type [%s] (0x%x)\n",
                           ios,
                           TAGFMTARGS(ios->tag),
                           ios->blk->dev->name,
                           ios->blk->block_number,
                           rnablk_cache_blk_state_string(ios->blk->state),
                           rnablk_op_type_string(ios->type),
                           ios->type);
                ret = -EINVAL;
                BUG();
        }
        /* release ref taken in rnablk_cookie_to_ios_get() */
        rnablk_ios_release(ios);
    } else if (likely(NULL != data)) {
        if (unlikely(NULL == conn)) {
            rna_printk(KERN_INFO,
                       "ios [%p] not found - status [%d] ep [%p]\n",
                       ios, status, ep);
        } else {
            rna_printk(KERN_INFO,
                       "ios [%p] not found - status [%d] conn ["rna_service_id_format"]\n",
                       ios, status, rna_service_id_get_string(&conn->id));
        }
    }

    if (likely(NULL != conn)) {
        if (unlikely(atomic_bit_test_and_clear(&conn->rsc_flags,
                                               RSC_F_DISPATCH_ON_COMPLETION))) {
            rnablk_schedule_conn_dispatch(conn);
        }
    }

    EXIT;
}

//
// runs at softirq level
#ifndef WINDOWS_KERNEL
static 
#endif /*WINDOWS_KERNEL*/
int
rnablk_io_completion(struct com_ep *ep, void *ep_ctx, void *data, int status)
{
    struct io_state *ios;
    struct rnablk_server_conn *conn;
    ENTER;

    conn = (struct rnablk_server_conn *)(com_get_ep_context(ep));
    if (likely(NULL != conn)) {
        atomic_dec(&conn->rdma_bufs_in_use);
    }
    ios = (struct io_state *)data;
    if (unlikely(0 == data)) {
        if (likely(NULL != conn)) {
            atomic_inc(&conn->zero_completion_tags);
        }
    }

    if( likely(ios != NULL) ) {

#ifdef WINDOWS_KERNEL    
        DoStorageTraceEtw(DbgLvlPerf, 
                          FldcVsmpSRBPerf, 
                          "rnablk_io_completion: SRB=0x%0I64X\n",
                          ios->SRBNumber); 
#endif

#ifdef RNA_USE_IOS_TIMERS
        if (unlikely(atomic_read(&ios->ios_timer_fired))) {
            rna_printk(KERN_WARNING,
                       "received completion for expired ios [%p] tag "
                       "["TAGFMT"] type [%s] from conn "
                       "["rna_service_id_format"]\n",
                       ios, TAGFMTARGS(ios->tag),
                       rnablk_op_type_string(ios->type),
                       rna_service_id_get_string(&conn->id));
        }
#endif /* RNA_USE_IOS_TIMERS */
        switch( ios->type ) {
            case RNABLK_RDMA_READ:
            case RNABLK_RDMA_WRITE:
                if (ios_queuestate_test_and_set(ios,
                                                IOS_QS_DISPATCH,
                                                IOS_QS_DISPATCH_COMPLETING)) {
                    ret = rnablk_generic_completion( ep,ios,status );
                }
                break;
            default:
                rna_printk(KERN_ERR,
                           "unexpected io type [%s] (0x%x) completion\n",
                           rnablk_op_type_string(ios->type),
                           ios->type);
                BUG_ON(TRUE);
        }
        /* release ref taken in rnablk_initiate_rdma() */
        rnablk_ios_release(ios);
    } else {
        if (0 != data) {
            if (unlikely((NULL == conn) ||
                         (IS_ERR(conn)))) {
                rna_printk(KERN_ERR,
                           "ios [%p] not found - status [%d] ep [%p]\n",
                           ios, status, ep);
            } else {
                rna_printk(KERN_ERR,
                           "ios [%p] not found - status [%d] conn ["rna_service_id_format"]\n",
                           ios, status, rna_service_id_get_string(&conn->id));
            }
        }
    }

    if (likely(NULL != conn)) {
        if (unlikely(atomic_bit_test_and_clear(&conn->rsc_flags,
                                               RSC_F_DISPATCH_ON_COMPLETION))) {
            rnablk_schedule_conn_dispatch(conn);
        }
    }

    EXIT;
}

#ifndef WINDOWS_KERNEL
void
rnablk_com_init(struct rna_com **com_ctx_p,
                struct com_attr *com_attr)
{
    struct rna_com_attrs com_attrs;

    memset(com_attr, 0, sizeof(*com_attr));

    com_attr->connect_cb        = rnablk_connect_cb;
    com_attr->disconnect_cb     = rnablk_disconn_cb;
    com_attr->destructor_cmp_cb = rnablk_destructor_cb;
    com_attr->recv_cmp_cb       = rnablk_recv_cb;

    com_attr->send_cmp_cb       = rnablk_rdma_send_completion;
    com_attr->rdma_read_cmp_cb  = rnablk_io_completion;
    com_attr->rdma_write_cmp_cb = rnablk_io_completion;

    /* Indicate to com we want the default values. */
    com_attrs.retry_count = rna_com_retry_count;
    com_attrs.rnr_retry_count = rna_com_rnr_retry_count;

    /* 
     * handle completions in interrupt context, although receive and
     * send completions will still be handled in a work queue.
     */
    com_attrs.comp_mode = COM_COMP_MODE_IRQ;
    *com_ctx_p = com_init_all((IB_TRANSPORT | TCP_TRANSPORT), &com_attrs,
                               RNA_PROTOCOL_MIN_VERSION, RNA_PROTOCOL_VERSION);

}
#endif /*WINDOWS_KERNEL*/
