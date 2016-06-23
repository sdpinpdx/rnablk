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



/**
 * Undo the DMA mapping for a single ios.
 *
 * Used by various completion handlers.
 */
INLINE void rnablk_unmap_ios_sgl( struct io_state *ios )
{
    enum dma_data_direction dir;
    ENTER;

    BUG_ON( ios == NULL );
    BUG_ON( ios->ep == NULL );
    BUG_ON( MD_CONN_EP_METAVALUE == ios->ep );    
    dir = DMA_FROM_DEVICE;
    if (ios_writes_data(ios)) {
        dir = DMA_TO_DEVICE;
    }

    com_dereg_sgl( ios->ep,ios->sgl,ios->nsgl,dir );

out:
    EXITV;
}

void
rnablk_dispatch_dma_io(struct io_state *ios,
                       lockstate_t    * irqflags)
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
    struct scatterlist *sgl = NULL;
    rna_addr_t raddr;
    enum dma_data_direction dir;
    struct rnablk_device   *dev = ios->dev;
    struct rnablk_server_conn *conn;
    int write;
    int nents;

    ENTER;

    BUG_ON(MD_CONN_EP_METAVALUE == ios->ep);
    BUG_ON(NULL == ios->blk);
    BUG_ON(NULL == buf_entry);

    rnablk_trace_ios(ios);

    dir = ios_writes_data(ios) ? DMA_TO_DEVICE : DMA_FROM_DEVICE;

    // calculate where in the cache block to operate on
	raddr.device_id = ios->blk->raddr.device_id;
    raddr.base_addr = ios->blk->raddr.base_addr +
                      ((ios->start_sector - ios->blk->start_sector)
                      * RNABLK_SECTOR_SIZE);
    TRACE(DBG_FLAG_TRACE_IO,"%s on dev %s @ sector %llu nr_sectors %u nsgl %d "
          "ios [%p] tag ["TAGFMT"]\n",
           rnablk_op_type_string(ios->type ), dev->name,
           ios->start_sector, ios->nr_sectors, ios->nsgl, ios,
           TAGFMTARGS(ios->tag));

    write = (dir == DMA_TO_DEVICE && ios->type == RNABLK_RDMA_WRITE) ? 1 : 0;

    // make a backup copy of the scatter list
    sgl = rnablk_mempool_alloc(osgl_cache_info);

    if(NULL == sgl) {
        /* This shouldn't happen, but if it does we can make the
         * mempool larger. */
        rna_printk(KERN_ERR,
                   "Failure of ios [%p] tag ["TAGFMT"] for device [%s] blk "
                   "[%"PRIu64"]: out of sgl bufs \n",
                   ios, TAGFMTARGS(ios->tag),
                   ios->blk->dev->name,
                   ios->blk->block_number);
        rna_printk(KERN_ERR, "ran out of osgl objects\n");
        GOTO(out, -ENOMEM);
    } 

    memcpy( sgl,ios->sgl,ios->nsgl * sizeof( struct scatterlist ) );

    // map the scatterlist for dma
    nents = com_reg_sgl( ios->ep,ios->sgl,ios->nsgl,dir );
    
    if (com_mapping_error(ios->ep, ios->sgl)) {
        GOTO(out, -EFAULT);
    }

    // record time when this request was issued
    ios->issue_time_ns = getrawmonotonic_ns();

    inc_in_flight(dev, ios);

    /* add ref so we can safely access IOS in rnablk_io_completion() */
    rnablk_ios_ref(ios);

    ret = com_rdma_sgl(ios->ep,
                       (void*)ios,
                       buf_entry,
                       raddr,
                       ios->sgl,
                       nents,
                       ios->blk->rkey,
                       write, 
                       RDMA_OP_SERVER_ACK);

    /*
     * on success, ios and/or request may be completed by this point,
     * so don't touch them
     */
    if (unlikely(ret)) {
        if (ios->ep) {
            // need to free buf_entry, since we're going to return success..
            com_put_rdma_buf(ios->ep, buf_entry);
        }
        rnablk_ios_release(ios);    // drop the extra ref we grabbed above
        dec_in_flight(dev, ios);

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

            // remove from dispatch list
            rnablk_io_completed(ios);

            // put this request at the head of the conn list
            rnablk_requeue( ios->ep,ios,sgl,dir );
        } else {
            rna_printk(KERN_ERR, "error initiating ios [%p] tag ["TAGFMT"] "
                       "type [%s] on dev [%s] block [%llu] @ sector %llu "
                       "nr_sectors %u nsgl %d ret [%d], disconnecting\n", ios,
                       TAGFMTARGS(ios->tag), rnablk_op_type_string(ios->type),
                       dev->name, ios->blk->block_number, ios->start_sector,
                       ios->nr_sectors, ios->nsgl, ret);
            if (ios->sgl) {
                com_dereg_sgl(ios->ep, ios->sgl, ios->nsgl, dir);
            }
            /*
             * leave on dispatch queue for cleanup/resubmit during
             * disconnect processing.
             */
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

 out:
    if (NULL != sgl) {
        rnablk_mempool_free(sgl, osgl_cache_info);
    }
    EXIT;
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
    static char *_rnablk_claim_ptr = "I belong to rnablk";
#endif
    struct rnablk_local_dev *ldev = NULL;
    struct list_head *pos;
    dev_t device;

    BUG_ON(NULL == blk);
    device = new_decode_dev(blk->direct_raddr.device_id.info.dev_num);

    if (conn->local &&
        (0 != blk->direct_raddr.device_id.info.dev_num) &&
        (0 != blk->direct_rkey)) {
        rna_service_mutex_lock(&local_dev_mutex);
        list_for_each(pos, &local_dev_list) {
            ldev = list_entry(pos, struct rnablk_local_dev, entry);
            if (ldev->blk_dev->bd_dev == device) {
                break;
            } else {
                ldev = NULL;
            }
        }
        if (NULL == ldev) {
            ldev = kmalloc(sizeof(*ldev), GFP_KERNEL);
            BUG_ON(NULL == ldev);
            INIT_LIST_HEAD(&ldev->entry);
            atomic_set(&ldev->run_scheduled, FALSE);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
            ldev->blk_dev = open_by_devnum(device,
                                           (FMODE_READ|FMODE_WRITE));
#else
            ldev->blk_dev = blkdev_get_by_dev(device,
                                              (FMODE_READ|FMODE_WRITE),
                                               _rnablk_claim_ptr);
#endif
            if (NULL == ldev->blk_dev || IS_ERR(ldev->blk_dev)) {
                rna_printk(KERN_ERR,
                           "Failed to open device [%d:%d] (%li)\n",
                           MAJOR(device),
                           MINOR(device),
                           PTR_ERR(ldev->blk_dev));
                kfree(ldev);
                ldev = NULL;
            } else {
                ldev->bio_set = rna_bioset_create(RNABLK_BIO_POOL_SIZE,
                                                  RNABLK_BVEC_POOL_SIZE);
                if (NULL == ldev->bio_set) {
                    rna_printk(KERN_ERR,
                               "Failed to create block IO set for device [%d]\n",
                               device);
                    kfree(ldev);
                    ldev = NULL;
                } else {
                    rna_printk(KERN_ERR,
                               "Successfully opened local device [%d:%d]\n",
                               MAJOR(device),
                               MINOR(device));
                    list_add_tail(&ldev->entry ,&local_dev_list);
                }
            }
        }
        rna_service_mutex_unlock(&local_dev_mutex);
    }
    blk->ldev = ldev;
}

static void rnablk_bio_destructor(struct bio *bio)
{
    struct rnablk_local_dev *ldev = bio->bi_private;

    bio_free(bio, ldev->bio_set);
}

/*
 * rnablk_data_op_complete()
 *  Code used when either an RDMA or BIO completes
 *
 * returns TRUE if IOS should be completed, FALSE otherwise
 */
int
rnablk_data_op_complete(struct io_state *ios, int err)
{
    /* TBD: can we unmap after end_request */
    rnablk_unmap_ios_sgl(ios);
    return rnablk_data_op_complete_common(ios, err);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
static int
rnablk_bio_done(struct bio *bio, unsigned int bytes_done, int err)
#else
static void
rnablk_bio_done(struct bio *bio, int err)
#endif
{
    struct io_state *ios = bio->bi_private;
    struct rnablk_local_dev *ldev = ios->blk->ldev;
    int ret;

#ifdef TEST_OFFLINE_CACHE_DEVICE
    if (test_cachedev_fail_ldma
        && test_cachedev_fail_ldma == ios->blk->blk_cachedev->rcd_id
        && atomic_bit_is_set(&ios->blk->blk_cachedev->rcd_state,
                             RCD_STATE_ONLINE)) {
        rna_printk(KERN_ERR, "Injecting ERROR for ios [%p] tag ["TAGFMT"] "
                   "block [%"PRIu64"]\n", ios, TAGFMTARGS(ios->tag),
                   ios->blk->block_number);
        test_cachedev_fail_ldma = 0;
        err = -EIO;
    }
#endif /* TEST_OFFLINE_CACHE_DEVICE */
    rnablk_trc_discon(0, "ios [%p] tag ["TAGFMT"] block [%"PRIu64"] "
                      "err=%d state [%s] ref [%s] type [%s]\n", ios,
                      TAGFMTARGS(ios->tag), ios->blk->block_number, err,
                      rnablk_cache_blk_state_string(ios->blk->state),
                      get_lock_type_string(ios->blk->ref_type),
                      rnablk_op_type_string(ios->type));

    /*
     * Set -EIO if !BIO_UPTODATE
     */
    if ((0 == err) &&
        !test_bit(BIO_UPTODATE, &bio->bi_flags)) {
        err = -EIO;
    }

    if (unlikely(net_link_mask & RNABLK_NL_BIO)) {
        printnl_atomic("[%d] [%s] Completed BIO [%p] for ios [%p] tag "
                       "["TAGFMT"] type [%s] to [%s] block [%"PRIu64"] err "
                       "[%d] pending BIOs [%d]\n",
                       current->pid,
                       __FUNCTION__,
                       bio,
                       ios,
                       TAGFMTARGS(ios->tag),
                       rnablk_op_type_string(ios->type),
                       ios->blk->dev->name,
                       ios->blk->block_number,
                       err,
                       atomic_read(&ios->pending_bios));
    }

    /* release reference on incoming request and IOS taken in rnablk_get_bio() */
    if (IOS_HAS_BIO(ios)) {
        rnablk_dec_bio_refcount(ios->bio);
    } else {
        RNABLK_BUG_ON(!IOS_HAS_REQ(ios), "ios=%p has no ioreq?\n", ios);
        rnablk_dec_req_refcount(ios->req);
    }

    if (0 != err)  {
        /* record the error if it's the first error seen for this ios */
        (void)atomic_cmpxchg(&ios->ios_err, 0, err);
    }

    if (atomic_dec_and_test(&ios->pending_bios)) {
        /* last BIO complete, so IOS is done */
        err = atomic_read(&ios->ios_err);
        (void)rnablk_detect_cache_failure(ios, err != 0, TRUE, TRUE);
        if (ios_queuestate_test_and_set(ios, IOS_QS_DISPATCH,
                                        IOS_QS_DISPATCH_COMPLETING)) {
            ret = rnablk_data_op_complete(ios, err);
            if (unlikely(err != 0)) {
                RNABLK_BUG_ON(!ios_queuestate_test_and_set(ios,
                       IOS_QS_DISPATCH_COMPLETING, IOS_QS_DISPATCH_FAILED_REDO),
                       "ios=%p unexpected qstate=%d err=%d\n", ios,
                       ios_queuestate_get(ios), err);
            } else if (ret) {
                /*
                 * Update read/write timer counters
                 */
                if (RNABLK_RDMA_READ == ios->type) {
                    atomic64_add((getrawmonotonic_ns() - ios->issue_time_ns),
                                 &ios->dev->stats.bs_read_time);
                } else if (RNABLK_RDMA_WRITE == ios->type) {
                    atomic64_add((getrawmonotonic_ns() - ios->issue_time_ns),
                                 &ios->dev->stats.bs_write_time);
                }
                /* Complete the request now */
                rnablk_io_completed(ios);
                rnablk_end_request(ios, err);
            }
        }
    }

    rnablk_ios_release(ios);    // release the bio reference on ios

    /*
     * XXX: hacky.  IOS probably freed when BIO destructor called.  need
     * pointer to BIO buffer pool to free it, so recycling private pointer.
     */
    bio->bi_private = ldev;
    bio_put(bio);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
    return 0;
#endif
}

static struct bio * rnablk_get_bio(struct io_state *ios,
                                   uint64_t         base_addr,
                                   uint32_t         sge_count)
{
    struct bio       *bio;
    struct cache_blk *blk;

    BUG_ON(NULL == ios);
    blk = ios->blk;
    BUG_ON(NULL == blk);
    BUG_ON(NULL == blk->ldev);

    bio = bio_alloc_bioset(GFP_NOIO, sge_count, blk->ldev->bio_set);
    if ((NULL == bio) || IS_ERR(bio)) {
        rna_printk(KERN_ERR,
                   "Unable to allocate memory for bio (%li)\n",
                   PTR_ERR(bio));
        bio = NULL;
    } else {
        bio->bi_bdev = blk->ldev->blk_dev;
        bio->bi_private = (void *) ios;
        bio->bi_destructor = rnablk_bio_destructor;
        bio->bi_end_io = &rnablk_bio_done;
        bio->bi_sector = base_addr / rna_bdev_logical_block_size(blk->ldev->blk_dev);

        /* need reference on incoming request, as we use it's buffers in BIO */
        if (IOS_HAS_BIO(ios)) {
            rnablk_inc_bio_refcount(ios->bio);
        } else {
            RNABLK_BUG_ON(!IOS_HAS_REQ(ios), "ios=%p has no ioreq?\n", ios);
            rnablk_inc_req_refcount(ios->req);
        }
        /*
         * also need refernece on IOS, as we store a pointer in our priv data
         * released in rnablk_bio_done()
         */
        rnablk_ios_ref(ios);

        atomic_inc(&ios->pending_bios);
    }

    return bio;
}

// runs in kthread context
static void rnablk_run_ldev_queue_wf(rnablk_workq_cb_arg_t arg)
{
    struct work_struct *work = (struct work_struct *)arg;
    struct rnablk_work *w = container_of( work,struct rnablk_work,work );
    struct rnablk_run_ldev_queue_wf_data *wd = &w->data.rwd_rnablk_run_ldev_queue_wf;
    struct rnablk_local_dev *ldev = wd->ldev;
    uint64_t start_seconds = get_seconds();
    ENTER;

    if (likely(TRUE == atomic_cmpxchg(&ldev->run_scheduled, TRUE, FALSE))) {
        blk_run_queue(bdev_get_queue(ldev->blk_dev));
    } else {
        rna_printk(KERN_ERR,
                   "local disk [%s] is not queued to run?!\n",
                   ldev->blk_dev->bd_disk->disk_name);
        BUG();
    }

    rnablk_mempool_free( w, work_cache_info );
    rnablk_finish_workq_work(start_seconds);

    EXITV;
}

/*
 * may run at softirq level
 *
 */
static void rnablk_schedule_run_ldev_queue(struct rnablk_local_dev *ldev)
{
    struct rnablk_work *w = NULL;
    struct rnablk_run_ldev_queue_wf_data *wd = NULL;
    struct request_queue *q = bdev_get_queue(ldev->blk_dev);
    ENTER;

    if ((NULL != q) && (NULL != q->request_fn) &&
        (FALSE == atomic_cmpxchg(&ldev->run_scheduled, FALSE, TRUE))) {
        if (unlikely(NULL == (w = rnablk_mempool_alloc(work_cache_info)))) {
            GOTO( err,-ENOMEM );
        }

        // kick start request processing
        RNABLK_INIT_RNABLK_WORK(w, wd, rnablk_run_ldev_queue_wf);
        wd->ldev = ldev;
        rna_queue_work( mt_workq,&w->work );
    }

out:
    EXITV;
err:
    printk( "%s: failed to allocate memory for work queue item\n",__FUNCTION__ );
    goto out;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
/* For RHEL5.8 (2.6.18) */
static inline unsigned short
queue_max_segments(struct request_queue *q)
{
    return q->max_phys_segments;
}
#endif

#if (!defined(RHEL_RELEASE_VERSION) && \
      (LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)))
/* For OEL6.1 and OEL6.2 (2.6.32) */
static inline unsigned short
queue_max_segments(struct request_queue *q)
{
    return queue_max_phys_segments(q);
}
#endif

/* Performs DMA on local block */
int
rnablk_initiate_dma(struct io_state *ios)
{
    struct bio         *bio;
    struct bio         *bio_head = NULL;
    struct bio         *bio_tail;
    struct scatterlist *sg;
    struct cache_blk   *blk;
    int                 i,j;
    int                 rw;
    int                 ret = 0;
    uint64_t            base_addr;
    unsigned int        bio_len, rem_len;
    struct page         *page;
    int                 max_downstream_segs;    // maximum phys segments
                                                // supported by downstream
                                                // driver
    int                 rem_pages;
    unsigned int        off;

    BUG_ON(NULL == ios);

    blk = ios->blk;
    BUG_ON(NULL == blk);
    BUG_ON(NULL == blk->ldev);

    base_addr = blk->direct_raddr.base_addr +
        ((ios->start_sector - blk->start_sector) * RNABLK_SECTOR_SIZE);


    if (RNABLK_RDMA_READ == ios->type) {
        rw = READ;
    } else if (RNABLK_RDMA_WRITE == ios->type) {
        rw = WRITE;
    } else {
        rna_printk(KERN_ERR,
                   "ios [%p] tag ["TAGFMT"] unexpected type [%s]\n",
                   ios, TAGFMTARGS(ios->tag),
                   rnablk_op_type_string(ios->type));
        ret = -EINVAL;
        goto err;
    }

    atomic_set(&ios->pending_bios, 0);
    atomic_set(&ios->ios_err, 0);

    /*
     * Calculate the maximum number of bvecs we're going to need.
     */
    max_downstream_segs = queue_max_segments(
                                    bdev_get_queue(ios->blk->ldev->blk_dev));
    rem_pages = 0;
    rna_for_each_sg(ios->sgl, sg, ios->nsgl, i) {
        rem_pages += (sg->offset + sg->length + PAGE_SIZE - 1) >> PAGE_SHIFT;
    }

    bio = rnablk_get_bio(ios, base_addr, min(rem_pages, max_downstream_segs));
    if (NULL == bio) {
        ret = -ENOMEM;
        goto err;
    }
    bio_head = bio_tail = bio;

    rna_for_each_sg(ios->sgl, sg, ios->nsgl, i) {
        rna_printk(KERN_INFO,
                   "ios [%p] Adding pages for sgl [%p] entry [%p] (index [%ld]"
                   " offset [%d] len [%d]) to BIO for tag ["TAGFMT"] %s [%p] "
                   "ss [%lu] to [%s] block [%"PRIu64"]\n",
                   ios,
                   ios->sgl,
                   sg,
                   (NULL != rna_sg_page(sg)) ? rna_sg_page(sg)->index : -1,
                   sg->offset,
                   sg->length,
                   TAGFMTARGS(ios->tag),
                   IOS_HAS_REQ(ios) ? "req" : "bio",
                   ios->ios_gen_ioreq,
                   (unsigned long)bio->bi_sector,
                   blk->dev->name,
                   blk->block_number);
        rem_len = sg->length;
        page = rna_sg_page(sg);
        off = sg->offset;
        while (rem_len) {
            bio_len = min((unsigned int)PAGE_SIZE - off, rem_len);
            ret = bio_add_page(bio, page, bio_len, off);
            if (ret == bio_len) {
                rem_pages--;
                page++;
                off = 0;
                rem_len -= bio_len;
                base_addr += bio_len;
            } else {
                /* ran out of space, so we need another bio... */
                BUG_ON(rem_pages <= 0);
                bio = rnablk_get_bio(ios, base_addr,
                                     min(rem_pages, max_downstream_segs));
                if (NULL == bio) {
                    ret = -ENOMEM;
                    goto err;
                }
                rna_printk(KERN_DEBUG,
                           "Allocating additional BIO for ios [%p] tag "
                           "["TAGFMT"] ss [%lu] to [%s] block [%"PRIu64"]\n",
                           ios, TAGFMTARGS(ios->tag),
                           (unsigned long)bio->bi_sector,
                           blk->dev->name,
                           blk->block_number);
                bio_tail = bio_tail->bi_next = bio;
            }                
        }
    }

    rna_printk(KERN_DEBUG,
               "Submitting [%d] BIOs for ios [%p] tag ["TAGFMT"] to [%s] "
               "block [%"PRIu64"]\n",
               atomic_read(&ios->pending_bios),
               ios, TAGFMTARGS(ios->tag),
               blk->dev->name,
               blk->block_number);

    // record time when this request was issued
    ios->issue_time_ns = getrawmonotonic_ns();

    /*
     * Keep a reference on the ios until we're done with everything
     * (including the blk), since we could race with the ios completing
     * as a result of the submit_bio(s).
     */
    rnablk_ios_ref(ios);
    while (bio_head) {
        bio = bio_head;
        bio_head = bio_head->bi_next;
        bio->bi_next = NULL;
        BUG_ON(irqs_disabled());
        submit_bio(rw, bio);
        if (unlikely(net_link_mask & RNABLK_NL_BIO)) {
            printnl_atomic("[%d] [%s] submitted BIO [%p] for ios [%p] tag "
                           "["TAGFMT"] type [%s] "
                           "to [%s] block [%"PRIu64"] pending BIOs [%d]\n",
                           current->pid,
                           __FUNCTION__,
                           bio,
                           ios,
                           TAGFMTARGS(ios->tag),
                           rnablk_op_type_string(ios->type),
                           ios->blk->dev->name,
                           ios->blk->block_number,
                           atomic_read(&ios->pending_bios));
        }
    }

    rnablk_schedule_run_ldev_queue(blk->ldev);
    rnablk_ios_release(ios);

    return 0;
err:
    /* release BIOs */
    while (bio_head) {
        bio = bio_head;
        bio_head = bio_head->bi_next;
        bio->bi_next = NULL;
        bio_put(bio);
        /* release reference on incoming request and IOS taken in rnablk_get_bio() */
        if (IOS_HAS_BIO(ios)) {
            rnablk_dec_bio_refcount(ios->bio);
        } else {
            RNABLK_BUG_ON(!IOS_HAS_REQ(ios), "ios=%p has no ioreq?\n", ios);
            rnablk_dec_req_refcount(ios->req);
        }
        rnablk_ios_release(ios);
    }
    return ret;
}

void rnablk_free_local_devs(void)
{
    struct rnablk_local_dev *ldev = NULL;
    struct list_head *pos;
    struct list_head *tmp;

    rna_service_mutex_lock(&local_dev_mutex);
    list_for_each_safe(pos, tmp, &local_dev_list) {
        ldev = list_entry(pos, struct rnablk_local_dev, entry);
        rna_bioset_free(ldev->bio_set);
        rna_blkdev_put(ldev->blk_dev, (FMODE_READ|FMODE_WRITE));
        list_del_init(&ldev->entry);
        kfree(ldev);
    }
    rna_service_mutex_unlock(&local_dev_mutex);
}

