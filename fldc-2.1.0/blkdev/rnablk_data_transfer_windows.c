/**
 * <rnablk_data_transfer.c> - Dell Fluid Cache block driver
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
#include "trace.h"
#include "rnablk_system.h"
#include "rnablk_io_state.h"
#include "rnablk_data_transfer.h"
#include "rnablk_queue_dispatch.h"
#include "rnablk_cache.h"
#include "rnablk_util.h"
#include "rnablk_comatose.h" // for rnablk_(inc/dec)_req_refcount
#include "rnablk_win_com.h"
#include "rnablk_win_util.h"
#include <storport.h>  
#include "rna_vsmp.h"
#include "rnablk_win_localssd.h"
#include "rnablk_scsi.h"

/*
 * used for SRB tracing in the storport miniport for performance
 * analysis.
 */
#pragma warning(push)
#pragma warning(disable : 4204)                        /* Prevent C4204 messages from stortrce.h. */
#pragma warning(disable : 6387)
#include <stortrce.h>
#pragma warning(pop)
#include "rna_vsmp_trace.h"
#include "rnablk_data_transfer_windows.tmh"

typedef struct _SCSI_REQUEST_BLOCK SCSI_REQUEST_BLOCK, *PSCSI_REQUEST_BLOCK;
extern void FreeTestSRB(PSCSI_REQUEST_BLOCK pSrb);

IO_COMPLETION_ROUTINE rnablk_local_read_done;

void
    rnablk_dispatch_dma_io(struct io_state *ios, lockstate_t * irqflags)
{
    rnablk_trace_ios(ios);

    rnablk_set_ios_io_type(ios);
    rnablk_set_ios_blk_ep(ios);

    atomic_inc(&ios->blk->inflight_ios);
    rnablk_io_dispatched_nolock(ios, ios->blk);
    rnablk_update_io_stats(ios);

    rnablk_unlock_blk_irqrestore(ios->blk, *irqflags);

    if(unlikely(rnablk_initiate_dma(ios))) {
        rnablk_end_request(ios, -EIO);
    }
}

/*
 * This uses more stack than we'd like for an inlined function, but inlining
 * it seems to have a significant performance benefit
 *
 * (XXX is the sgl copy (i.e. osgl_cache_info) still needed?  I suspect
 * not, but looks like it was originally added for ib, so no way to test
 * whether needed or not until we run on ib again...)
 */
int
rnablk_initiate_rdma(struct io_state *ios, struct buf_entry *buf_entry)
{
    rna_addr_t raddr;
    enum dma_data_direction dir = DMA_FROM_DEVICE;
    struct rnablk_device   *dev = ios->dev;
    struct rnablk_server_conn *conn;
	PVOID pBuff = NULL;

	ENTER;

    BUG_ON(MD_CONN_EP_METAVALUE == ios->ep);
    BUG_ON(NULL == ios->blk);
    BUG_ON(NULL == buf_entry);
    BUG_ON(NULL == ios->pOS_Srb);

    rnablk_trace_ios(ios);

	// calculate where in the cache block to operate on
	raddr.device_id = ios->blk->raddr.device_id;
    raddr.base_addr = ios->blk->raddr.base_addr +
                      ((ios->start_sector - ios->blk->start_sector)
                      * RNABLK_SECTOR_SIZE);

	// update the requests in flight stat
    inc_in_flight(dev, ios);

	ios->issue_time_ns = getrawmonotonic_ns();

	rnablk_ios_ref(ios);

    // To reduce overhead, we told StorPort to not map read/write buffers so we have to
    // do it ourselves when we need to access the data buffer.
    // Eventually, we might change COM so we can pass it the MDL and not have to map
    // the buffer at all.
    pBuff = MmGetSystemAddressForMdlSafe(ios->ios_mdl, NormalPagePriority);

    if (pBuff) {
        // Send IO through connection
        if (ios->ios_iotype == IOS_IOTYPE_READ) {
		    ret = com_rdma_read(ios->ep, 
                buf_entry, 
                raddr,
                pBuff, 
                ios->blk->rkey, 
                (int)ios->transfer_length, 
                (PVOID)ios,
                FALSE, 
                RDMA_OP_SERVER_ACK);

            dir = DMA_FROM_DEVICE;
        }
	    else if(ios->ios_iotype == IOS_IOTYPE_WRITE){
            ret = com_rdma_write(ios->ep, 
                buf_entry, 
                raddr,
                pBuff, 
                ios->blk->rkey, 
                (int)ios->transfer_length, 
                (PVOID)ios,
                FALSE, 
                RDMA_OP_SERVER_ACK);

            dir = DMA_TO_DEVICE;
        }
    }
    else {
        ret = -EIO;
    }

    /*
     * on success, ios and/or request may be completed by this point,
     * so don't touch them
     */
    if( unlikely(ret) ) {

        if (ios->ep) {
            // need to free buf_entry, since we're going to return success..
            com_put_rdma_buf(ios->ep, buf_entry);
        }

        if (-EAGAIN == ret) {
            rna_printk(KERN_ERR,
                       "requeued ios [%p] tag ["TAGFMT"] type [%s] on dev "
                       "[%s] block [%llu] @ sector [%llu] "
                       "nr_sectors [%u] nsgl [%d] ret [%d]\n",
                       ios, TAGFMTARGS(ios->tag),
                       rnablk_op_type_string(ios->type),
                       dev->name, ios->blk->block_number,
                       ios->start_sector,
                       ios->nr_sectors,
                       ios->nsgl,
                       ret);
            ios->issue_time_ns = 0;

            // this request is not in flight so keep our stats straight
            dec_in_flight(dev, ios);

            // remove from dispatch list
            rnablk_io_completed(ios);

            // put this request at the head of the conn list
            rnablk_requeue( ios->ep,ios,NULL,dir );
        } else {
            rna_printk(KERN_ERR,
                       "failed ios [%p] tag ["TAGFMT"] type [%s] on dev [%s] "
                       "block [%llu] @ sector %llu nr_sectors %u "
                       "nsgl %d ret [%d], disconnecting\n", ios,
                       TAGFMTARGS(ios->tag), rnablk_op_type_string(ios->type),
                       dev->name, ios->blk->block_number,
                       ios->start_sector,
                       ios->nr_sectors,
                       ios->nsgl,
                       ret);

            /*
             * leave on dispatch queue for cleanup/resubmit during
             * disconnect processing.
             */
            dec_in_flight(dev, ios);
            rnablk_io_completed(ios);
            rnablk_queue_blk_io(ios->blk, ios, QUEUE_HEAD);
            rnablk_dec_inflight_ios(ios->blk);
            conn = rnablk_get_ios_conn(ios);
            /*
             * Disconnect the parent conn.  Otherwise this i/o may get
             * stuck forever.
             */
            rnablk_queue_conn_disconnect(conn->rsc_parent_conn);
        }

        // don't want caller freeing IOS...
        ret = 0;
    }

    EXIT;
}

int rnablk_data_op_complete_win(__inout struct io_state *  ios, int err)
{
    int result = 0;
    PCache_Block pBlk;
    PHW_SRB_EXTENSION   pSrbExtension;
    LONG numOfIOsOutstanding;

    ASSERT(ios);
    pBlk = ios->blk;
    ASSERT(pBlk);

    pSrbExtension = (PHW_SRB_EXTENSION) SrbGetMiniportContext(ios->pOS_Srb);
    ASSERT(pSrbExtension);
    numOfIOsOutstanding = InterlockedDecrement(&pSrbExtension->numOutstandingIO);
    if (numOfIOsOutstanding == 0) {
        rnablk_io_scsi_sense(ios->dev, ios->pOS_Srb, err);

        VsmpDbgPrint((pSrbExtension->isWrite?DBG_VSMP_WRITE:DBG_VSMP_READ), 
            (">===CacheBlock_CompleteSRB===< SRB  %s  start sec %I64u  err %d  SrbStatus 0x%x  ScsiStatus 0x%x\n", 
            (ios->ios_iotype == IOS_IOTYPE_READ) ? "READ ":"WRITE", GetStartSectorFromSRB(ios->pOS_Srb), err,
            ios->pOS_Srb->SrbStatus, SrbGetScsiStatus(ios->pOS_Srb)));

        StorPortNotification(RequestComplete, pSrbExtension->pHBAExt, ios->pOS_Srb);
    }

    DoStorageTraceEtw(DbgLvlPerf, FldcVsmpSRBPerf, "rnablk_data_op_complete_win: SRB=0x%0I64X  ios=%p\n",pSrbExtension->SRBNumber, ios); 

	ios->pOS_Srb = NULL;
    ios->SRBNumber = 0;
    
    return result;
}


/**
 * Looks up local device pointer by ID.
 * NOOP if connection is not local or device is not a block
 * device (devnum will be zero for RAM and other non-block bstores)
 * Opens device if not already opened.
 */
void rnablk_get_local_dev(struct cache_blk          *blk,
                          struct rnablk_server_conn *conn)
{
    struct rnablk_local_dev *ldev = NULL;
    struct rnablk_local_dev *tmpdev = NULL;
    struct list_head *pos;
    KLOCK_QUEUE_HANDLE lockHandle;

    BUG_ON(NULL == blk);

    if (conn->local &&
        (0 != blk->direct_raddr.device_id.info.dev_num) &&
        (0 != blk->direct_rkey)) {

        KeAcquireInStackQueuedSpinLock(&local_dev_lock, &lockHandle);

        list_for_each(pos, &local_dev_list) {
            tmpdev = list_entry(pos, struct rnablk_local_dev, entry);
            if (CacheDevIdEqual(tmpdev->id, blk->cb_cachedev_id)) {
                ldev = tmpdev;
                break;
            }
        }

        KeReleaseInStackQueuedSpinLock(&lockHandle);

        if (NULL == ldev) {
            ldev = OpenCacheDeviceById(blk->cb_cachedev_id);
        }
    }

    VsmpDbgPrint(DBG_VSMP_LOCAL_IO, ("%s: block %I64x  conn %p  local %d  dev_num %d  rkey %I64x  cacheDevId %I64x  ldev %p\n", 
        __FUNCTION__, blk->block_number, conn, conn->local, blk->direct_raddr.device_id.info.dev_num, blk->direct_rkey, blk->cb_cachedev_id, ldev));

    blk->ldev = ldev;

}

/*
 * shared code used when either an RDMA or BIO completes
 * returns TRUE if IOS should be completed, FALSE otherwise
 */
int
rnablk_data_op_complete(struct io_state *ios, int err)
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
	rnablk_data_op_complete_win(ios, err);
    rnablk_lock_blk_irqsave(ios->blk, flags);
    if (unlikely(!rnablk_cache_blk_state_is_connected(ios->blk->state))) {
        rna_printk(KERN_INFO, "ios [%p] tag ["TAGFMT"] type [%s] "
                   "[%s] block [%"PRIu64"] state [%s] refcnt ["BLKCNTFMT"] "
                   "inflight_ios [%d] dispatch queue [%s]\n",
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
			if (ios->blk->dispatch_queue.Flink == &ios->l
				&& ios->blk->dispatch_queue.Blink == &ios->l) {
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
                    rnablk_unset_blk_ep(ios->blk);
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


_Use_decl_annotations_
NTSTATUS rnablk_local_read_done(
  _In_  PDEVICE_OBJECT pDevObj,
  _In_  PIRP pIrp,
  _In_  PVOID Context)
{
    struct io_state* ios;
    int err;
    int ret;
    IRP_ALLOC_TYPE irpAllocType;

    ios = (struct io_state*) Context;
    irpAllocType = ios->irpAllocType;

    DoStorageTraceEtw(DbgLvlPerf, FldcVsmpSRBPerf, "rnablk_local_read_done: SRB=0x%0I64X  ios=%p\n",
        ios->SRBNumber, ios); 

    VsmpDbgPrint(DBG_VSMP_LOCAL_IO, ("%s: pIrp %p  status %x  info %I64x\n", 
        __FUNCTION__, pIrp, pIrp->IoStatus.Status, pIrp->IoStatus.Information));

    if (!NT_SUCCESS(pIrp->IoStatus.Status))  {
        (void)atomic_cmpxchg(&ios->ios_err, 0, pIrp->IoStatus.Status);
    }

    rnablk_ios_release(ios);

    if (atomic_dec_and_test(&ios->pending_bios)) {
        /* last BIO complete, so IOS is done */
        err = atomic_read(&ios->ios_err);
        (void)rnablk_detect_cache_failure(ios, err != STATUS_SUCCESS, TRUE, TRUE);
        ret = rnablk_data_op_complete(ios, err);
        if (ret) {
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
            rnablk_end_request(ios, err);
        }
    }
    
    FreeDiskIrp(pIrp, irpAllocType);

    return STATUS_MORE_PROCESSING_REQUIRED;
}


/* Performs DMA on local block */
int
rnablk_initiate_dma(struct io_state *ios)
{
    struct cache_blk   *blk;
    uint64_t            base_addr;
    int                 ret = 0;
    NTSTATUS            status;

    BUG_ON(NULL == ios);

    DoStorageTraceEtw(DbgLvlPerf, FldcVsmpSRBPerf, "rnablk_initiate_dma: SRB=0x%0I64X  ios=%p\n",
        ios->SRBNumber, ios); 

    blk = ios->blk;
    BUG_ON(NULL == blk);
    BUG_ON(NULL == blk->ldev);

    base_addr = blk->direct_raddr.base_addr +
        ((ios->start_sector - blk->start_sector) * RNABLK_SECTOR_SIZE);

    if (RNABLK_RDMA_READ != ios->type) {
        rna_printk(KERN_ERR,
                   "ios [%p] tag ["TAGFMT"] unexpected type [%s]\n",
                   ios, TAGFMTARGS(ios->tag),
                   rnablk_op_type_string(ios->type));
        ret = -EINVAL;
        goto err;
    }

    // For Windows we are only going to have one IRP per ios, so we just
    // set pending_bios to 1 to represent this.
    atomic_set(&ios->pending_bios, 1);
    atomic_set(&ios->ios_err, 0);

    // Reference the ios for this request.  Will get released on I/O completion.
    rnablk_ios_ref(ios);

    // record time when this request was issued
    ios->issue_time_ns = getrawmonotonic_ns();

    status = ReadDiskDev(GetDevObjForLocalDev(blk->ldev), base_addr, ios->ios_mdl, rnablk_local_read_done, ios, &ios->irpAllocType);
    if (!NT_SUCCESS(status)) {
        rna_printk(KERN_ERR,
                   "ios [%p] tag ["TAGFMT"] failed to create %s req\n",
                   ios, TAGFMTARGS(ios->tag),
                   rnablk_op_type_string(ios->type));
        ret = -ENOMEM;
        goto err;
    }

    return 0;

err:
    return ret;
}

void rnablk_free_local_devs(void)
{
    struct rnablk_local_dev *ldev = NULL;
    struct list_head *pos;
    struct list_head *tmp;
    KLOCK_QUEUE_HANDLE lockHandle;

    KeAcquireInStackQueuedSpinLock(&local_dev_lock, &lockHandle);
    list_for_each_safe(pos, tmp, &local_dev_list) {
        ldev = list_entry(pos, struct rnablk_local_dev, entry);
        FreeLocalDevice(ldev);
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);
}

