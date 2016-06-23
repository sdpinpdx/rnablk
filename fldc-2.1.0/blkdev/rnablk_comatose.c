/**
 * <rnablk_comatose.c> - Dell Fluid Cache block driver
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

/* Here you will find code that is not quite dead.
 * Should be ignored by pretty much everyone until further notice.
 */

#include "rb.h"
#include "rnablk_system.h"
#include "rnablk_globals.h"
#include "rnablk_util.h"
#include "rnablk_comatose.h"
#include "rnablk_device.h"
#include "rnablk_scsi.h"
#include "rnablk_queue_dispatch.h"
#include "rnablk_cache.h"
#include "rnablk_io_state.h"
#include "rnablk_protocol.h"
#include "trace.h"

#ifdef blk_fs_request
#define RNA_FS_REQ(x) blk_fs_request(x)
#else
#define RNA_FS_REQ(x) ((x)->cmd_type == REQ_TYPE_FS)
#endif

#ifdef blk_discard_rq
#define RNA_DISC_REQ(x) blk_discard_rq(x)
#else
#define RNA_DISC_REQ(x) (RNA_REQ_FLAGS(req) & REQ_DISCARD)
#endif

#ifdef blk_pc_request
#define RNA_PC_REQ(x) blk_pc_request(x)
#else
#define RNA_PC_REQ(x) ((x)->cmd_type == REQ_TYPE_BLOCK_PC)
#endif


#ifdef blk_rq_quiet
#define RNA_QUITE_REQ(x) blk_rq_quiet(x)
#else
#define RNA_QUITE_REQ(x) (RNA_REQ_FLAGS(x) & REQ_QUIET)
#endif

atomic_t rnablk_enforcer_running;

#define RNABLK_MIN_STRATEGY_STACK (1024 * 6)

#ifdef WINDOWS_KERNEL
extern uint64_t msecs_to_jiffies(const unsigned int m);
#endif /*WINDOWS_KERNEL*/

#ifndef WINDOWS_KERNEL
/** Reads the specified stop flag
 * Caller must hold queue lock. */
static rna_inline int rnablk_get_dev_queue_stop_flag_nolock(struct rnablk_device *dev, 
                                                            enum rnablk_queue_stop_flags stop_flag)
{
    int                   stop_flag_mask = (1 << stop_flag);
    int                   prev_q_stop_flags;

    BUG_ON(NULL==dev);

    prev_q_stop_flags = atomic_read(&dev->q_stop_flags);
    return (prev_q_stop_flags & stop_flag_mask);
}

/** Sets the specified stop flag, and stops the queue if flags was zero
 * Caller must hold queue lock (if there is a queue).
 * Do not call in softirq */
static  void rnablk_set_dev_queue_stop_flag_nolock(struct rnablk_device *dev, 
                                                               enum rnablk_queue_stop_flags stop_flag)
{
    int                   stop_flag_mask = (1 << stop_flag);

    BUG_ON(NULL==dev);

    if (atomic_bit_test_and_set(&dev->q_stop_flags, stop_flag_mask)
        && dev_use_req_queue(dev)) {
        /* Transitioned from not stopped to stopped */
        BUG_ON(NULL==dev->q);
        blk_stop_queue(dev->q);
    }
}

// runs in kthread context
static void rnablk_clear_dev_queue_stop_flag_wf(rnablk_workq_cb_arg_t arg)
{
    struct work_struct *work = (struct work_struct *)arg;
    struct rnablk_work *w = container_of( work,struct rnablk_work,work );
    struct rnablk_clear_dev_queue_stop_flag_wf_data *wd = &w->data.rwd_rnablk_clear_dev_queue_stop_flag_wf;
    struct rnablk_device *dev = wd->dev;
    enum rnablk_queue_stop_flags stop_flag = wd->stop_flag;
    unsigned long       flags;
    uint64_t  start_seconds = get_seconds();
    ENTER;

    rnablk_clear_dev_queue_stop_flag(dev, stop_flag);
    rnablk_dev_release(dev);
    rnablk_mempool_free( w, work_cache_info );
    rnablk_finish_workq_work(start_seconds);

    EXITV;
}

/* 
 * may run at softirq level
 *
 */
static  void rnablk_schedule_clear_dev_queue_stop_flag(struct rnablk_device *dev, 
                                                                   enum rnablk_queue_stop_flags stop_flag)
{
    struct rnablk_work *w = NULL;
    struct rnablk_clear_dev_queue_stop_flag_wf_data *wd = NULL;
    ENTER;
    
    BUG_ON(NULL==dev);

    if (rnablk_dev_acquire(dev)) {
        if (unlikely(NULL == (w = rnablk_mempool_alloc(work_cache_info)))) {
            GOTO(err, -ENOMEM);
        }
        
        // kick start request processing
        RNABLK_INIT_RNABLK_WORK(w, wd, rnablk_clear_dev_queue_stop_flag_wf);
        wd->dev = dev;
        wd->stop_flag = stop_flag;
        rna_queue_work(mt_workq, &w->work);
    }

out:
    EXITV;
err:
    rnablk_dev_release(dev);
    printk("%s: failed to allocate memory for work queue item\n", __FUNCTION__);
    goto out;
}



/** Sets the specified stop flag, and stops the queue if flags was zero
 * Caller must *not* hold queue lock */
static void rnablk_set_dev_queue_stop_flag(struct rnablk_device *dev,
                                           enum rnablk_queue_stop_flags stop_flag)
{
    unsigned long         flags;

    BUG_ON(NULL==dev);

    if (NULL != dev->q) {
        spin_lock_irqsave(dev->q->queue_lock, flags);
    }
    rnablk_set_dev_queue_stop_flag_nolock(dev, stop_flag);
    if (NULL != dev->q) {
        spin_unlock_irqrestore(dev->q->queue_lock, flags);
    }
}

/** Clears the specified stop flag, and starts the queue if flags become zero
 * Caller must hold queue lock (if there is a queue).
 * Do not call in softirq */
static void rnablk_clear_dev_queue_stop_flag_nolock(struct rnablk_device *dev, 
                                                    enum rnablk_queue_stop_flags stop_flag)
{
    int                   stop_flag_mask = (1 << stop_flag);

    BUG_ON(NULL==dev);

    if (atomic_bit_test_and_clear(&dev->q_stop_flags, stop_flag_mask) &&
        dev_use_req_queue(dev) &&
        (0 == atomic_read(&dev->q_stop_flags))) {
        /* Transitioned from stopped to not stopped */
        BUG_ON(NULL==dev->q);
        blk_start_queue(dev->q);
    }
}

/** Clears the specified stop flag, and starts the queue if flags become zero
 * Caller must *not* hold queue lock.
 * Do not call in softirq */
void rnablk_clear_dev_queue_stop_flag(struct rnablk_device *dev,
                                      enum rnablk_queue_stop_flags stop_flag)
{
    unsigned long         flags = 0;

    BUG_ON(NULL==dev);

    if (NULL != dev->q) {
        spin_lock_irqsave(dev->q->queue_lock, flags);
    }
    rnablk_clear_dev_queue_stop_flag_nolock(dev, stop_flag);
    if (NULL != dev->q) {
        spin_unlock_irqrestore(dev->q->queue_lock, flags);
    }
}

// runs in kthread context
static void rnablk_run_queue_wf(rnablk_workq_cb_arg_t arg)
{
    struct work_struct *work = (struct work_struct *)arg;
    struct rnablk_work *w = container_of( work,struct rnablk_work,work );
    struct rnablk_run_queue_wf_data *wd = &w->data.rwd_rnablk_run_queue_wf;
    struct request_queue *q = wd->q;
    uint64_t start_seconds = get_seconds();
    ENTER;

    blk_run_queue(q);

    rnablk_mempool_free( w, work_cache_info );
    rnablk_finish_workq_work(start_seconds);

    EXITV;
}

/* 
 * may run at softirq level
 *
 */
static void rnablk_schedule_run_queue(struct request_queue *q)
{
    struct rnablk_work *w = NULL;
    struct rnablk_run_queue_wf_data *wd = NULL;
    ENTER;
    
    if (unlikely(NULL == (w = rnablk_mempool_alloc(work_cache_info)))) {
        GOTO( err,-ENOMEM );
    }
    
    // kick start request processing
    RNABLK_INIT_RNABLK_WORK(w, wd, rnablk_run_queue_wf);
    wd->q = q;
    rna_queue_work( mt_workq,&w->work );

out:
    EXITV;
err:
    printk( "%s: failed to allocate memory for work queue item\n",__FUNCTION__ );
    goto out;
}


/*
 * Special requests have a field in the rnablk_special_hdr_t to use as the
 * refcount.  If the request is not flagged as special, then req->special should
 * start as NULL, and we can use that field directly for our reference counting.
 * Alternatively, we could allocate a special type of rnablk_special_hdr_t just
 * to use to reference count, but non-special requests are the common case and
 * it's nice to avoid the kmalloc overhead for all of those.
 */
void rnablk_set_req_refcount(struct request *req, int value)
{
    rnablk_special_hdr_t *hdr;

    if (RNA_SPECIAL_REQ(req)) {
        BUG_ON(NULL == req->special);
        atomic_set(&((rnablk_special_hdr_t *)req->special)->sh_refcount, value);
    } else {
        /* We better not overwrite anything here. */
        BUG_ON(NULL != req->special);
        atomic_set((atomic_t *)&req->special, value);
    }
}

void rnablk_inc_req_refcount(struct request *req)
{
    if (RNA_SPECIAL_REQ(req)) {
        BUG_ON(NULL == req->special);
        atomic_inc(&((rnablk_special_hdr_t *)req->special)->sh_refcount);
    } else {
        atomic_inc((atomic_t *)&req->special);
    }
}

void rnablk_dec_req_refcount(struct request *req)
{
    if (RNA_SPECIAL_REQ(req)) {
        BUG_ON(NULL == req->special);
        atomic_dec(&((rnablk_special_hdr_t *)req->special)->sh_refcount);
    } else {
        atomic_dec((atomic_t *)&req->special);
    }
}

static int rnablk_read_req_refcount(struct request *req)
{
    if (RNA_SPECIAL_REQ(req)) {
        BUG_ON(NULL == req->special);
        return atomic_read(&((rnablk_special_hdr_t *)req->special)->sh_refcount);
    } else {
        return atomic_read((atomic_t *)&req->special);
    }
}

static int rnablk_atomic_dec_and_test_req_refcount(struct request *req)
{
    if (RNA_SPECIAL_REQ(req)) {
        BUG_ON(NULL == req->special);
        return atomic_dec_and_test(&((rnablk_special_hdr_t *)req->special)->sh_refcount);
    } else {
        return atomic_dec_and_test((atomic_t *)&req->special);
    }
}


static rna_inline void rnablk_release_req_special(struct request *req)
{
    if (unlikely(RNA_SPECIAL_REQ(req))) {
        BUG_ON(NULL == req->special);
        /* Other req->special structures are managed outside of the block queue handling */
        req->special = NULL;
    }
}

void rnablk_softirq_done( struct request *req )
{
    struct request_queue *q = req->q;
    struct bio *bio,*next_bio;
    unsigned long flags;
    int nr_sectors = 0;
    ENTER;

// XXX again, when did blk_end_request_all() appear?
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
    // for some reason rq_for_each_bio kept exiting the loop early
    // so I had to replace it with this hand written loop
    // so much for code reuse...
    bio = req->bio;
    while( bio != NULL ) {
        nr_sectors += bio_sectors( bio );
        next_bio = bio->bi_next;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
        bio_endio( bio,bio_sectors( bio ) << RNABLK_SECTOR_SHIFT,req->errors );
#else
        bio_endio( bio, req->errors );
#endif
        bio = next_bio;
    }
    BUG_ON(req->nr_sectors != nr_sectors);

    spin_lock_irqsave( q->queue_lock,flags );
    end_that_request_last( req,req->errors ? -EIO : 1 );
    spin_unlock_irqrestore( q->queue_lock,flags );
#else
    if (req->errors && !RNA_QUITE_REQ(req)) {
        rna_printk(KERN_INFO,
                   "ending request with error [%d]\n",
                   req->errors);
    }
    blk_end_request_all(req, req->errors);
#endif

    EXITV;
}

#endif /*WINDOWS_KERNEL*/

void rnablk_end_req(struct io_state *ios, int error)
{
#ifndef WINDOWS_KERNEL

   struct request *req;

    BUG_ON(NULL == ios);
    RNABLK_BUG_ON(!IOS_HAS_REQ(ios), "ios=%p has no req\n", ios);

    req = ios->req;

    TRACE(DBG_FLAG_TRACE_IO, "end ios [%p] tag ["TAGFMT"] sector [%llu] "
          "nr_sectors [%u] err [%d]\n",
          ios, TAGFMTARGS(ios->tag), ios->start_sector, ios->nr_sectors,error);

    if (error < 0 ) {
        req->errors = error;
    }

    // Decrement ref count on request
    if (likely(rnablk_atomic_dec_and_test_req_refcount(req))) {
        BUG_ON(atomic_read(&ios->pending_bios) > 0);

        /* avoid access to req after it is completed */
        ios->req = NULL;
        ios->ios_req_type = IOREQ_TYPE_NOREQ;
        if (atomic_bit_is_set(&ios->ios_atomic_flags, IOS_AF_DEVIOCNT)) {
            rnablk_dec_device_iocnt(ios->dev, ios_writes_data(ios));
        }
        /* This can free req->special, so don't reference after this. */
        rnablk_release_req_special(req);
        blk_complete_request(req);
    }
#endif /*WINDOWS_KERNEL*/
}

/* caller must hold conn->block_list_lock */
static void
rnablk_apply_ref_block_limit_cachedev(struct rnablk_server_conn *conn,
                                      rnablk_cachedev_t *cachedev,
                                      void *unused)
{
    uint64_t target_time;
    struct blk_lru_list *pos, *tmp;
    struct cache_blk *blk;
    struct cache_blk marker;
    int is_wref;
    mutexstate_t mutex_lock_handle;

#ifdef DEBUG_ENFORCER
    int dbg_nskipped = 0;
    int dbg_ncantdrop = 0;
    int dbg_ndropped = 0;
#endif /* DEBUG_ENFORCER */

    RNABLK_DBG_BUG_ON(!rna_service_mutex_is_locked(
                      &conn->rsc_parent_conn->block_list_lock),
                      "conn ["CONNFMT"] cachedev=%p - mutex not locked\n",
                      CONNFMTARGS(conn), cachedev);

    if (0 == rnablk_reference_target_age) {
        return;
    }

    target_time = get_jiffies() - msecs_to_jiffies(rnablk_reference_target_age);

    marker.cb_identity_flags = BLK_F_MARKER_BLK;
    blk_lru_list_init(&marker.cb_conn_lru, 0);

    blk_lru_list_for_each_safe(pos, tmp, &cachedev->rcd_block_list) {
        if (unlikely(RNABLK_CONN_CONNECTED != atomic_read(&conn->state)
                     || atomic_read(&rna_service_detached)
                     || atomic_read(&shutdown))) {
            break;
        }
        blk = blk_lru_entry(pos, &is_wref);

        if (unlikely(IS_MARKER_BLK(blk))) {
            continue;
        }

        if (!dev_is_persistent(blk->dev) || IS_MASTER_BLK(blk)) {
            continue;
        }

        if (blk->cb_ref_time >= target_time) {
            if (is_wref) {
                /*
                 * If this is the wref link to this block, then 'cb_ref_time'
                 * is out of sequence, so don't use it to end our loop!
                 */
                continue;
            }
            break;
        }

        if (rnablk_can_deref_cache_blk(blk)) {
            rnablk_cache_blk_ref(blk);
            blk_lru_list_add(&marker.cb_conn_lru, pos);
            rna_block_mutex_unlock(&conn->block_list_lock, &mutex_lock_handle);
            if (rnablk_try_deref_cache_blk(blk)) {
                rna_printk(KERN_DEBUG, "derefed block [%llu] wref=%d\n",
                           blk->block_number, is_wref);
#ifdef DEBUG_ENFORCER
                dbg_ndropped++;
#endif /* DEBUG_ENFORCER */
                atomic64_inc(&blk->dev->stats.enforcer_ref_dropped_blocks);
                rnablk_start_blk_io(blk, FALSE);
            } else {
                rna_printk(KERN_DEBUG, "FAILED to deref block [%llu] wref=%d\n",
                           blk->block_number, is_wref);
#ifdef DEBUG_ENFORCER
                dbg_ncantdrop++;
#endif /* DEBUG_ENFORCER */
            }
            rnablk_cache_blk_release(blk);
            rna_block_mutex_lock(&conn->block_list_lock, &mutex_lock_handle);
            tmp = _LRU_GET_ENT_PTR(marker.cb_conn_lru.blru_next);
            blk_lru_del_init(&marker.cb_conn_lru);
        }
#ifdef DEBUG_ENFORCER
        else {
            dbg_nskipped++;
        }
#endif /* DEBUG_ENFORCER */
    }
#ifdef DEBUG_ENFORCER
    if (dbg_ndropped || dbg_nskipped || dbg_ncantdrop) {
        rna_printk(KERN_ERR, "ndrop=%d nskip=%d ncant=%d\n",
                   dbg_ndropped, dbg_nskipped, dbg_ncantdrop);
    }
#endif /* DEBUG_ENFORCER */
    return;
}

static void
rnablk_apply_ref_block_limit(struct rnablk_server_conn *conn)
{
    mutexstate_t mutex_lock_handle;

    RNABLK_BUG_ON(!is_parent_conn(conn), "conn ["CONNFMT"] is not parent "
                  "conn\n", CONNFMTARGS(conn));

    rna_block_mutex_lock(&conn->block_list_lock, &mutex_lock_handle);
    rnablk_operate_on_conn_cachedevs(conn, NULL, NULL,
                                     rnablk_apply_ref_block_limit_cachedev);
    rna_block_mutex_unlock(&conn->block_list_lock, &mutex_lock_handle);
}                                     

static void
rnablk_apply_write_ref_block_limit(struct rnablk_server_conn *conn)
{
    uint64_t target_time;
    struct list_head *pos, *tmp;
    struct cache_blk *blk;
    struct cache_blk marker;
    mutexstate_t mutex_lock_handle;

#ifdef DEBUG_ENFORCER
    int dbg_nskipped = 0;
    int dbg_ncantdrop = 0;
    int dbg_ndropped = 0;
    unsigned long start_seconds = get_seconds();
#endif /* DEBUG_ENFORCER */

    if (0 == rnablk_write_reference_target_age) {
        /* feature disabled */
        return;
    } else if (atomic_read(&conn->rsc_outstanding_write_releases) >=
               (int32_t)rnablk_write_reference_release_max_outstanding) {
        /* don't swamp the CS with write reference drops/downgrades */
        return;
    }

    target_time = get_jiffies() - msecs_to_jiffies(rnablk_write_reference_target_age);

    marker.cb_identity_flags = BLK_F_MARKER_BLK;
    INIT_LIST_HEAD(&marker.cb_conn_wlru);

    rna_block_mutex_lock(&conn->block_list_lock, &mutex_lock_handle);
    list_for_each_safe(pos, tmp, &conn->rsc_wlru_list) {
        if (unlikely(RNABLK_CONN_CONNECTED != atomic_read(&conn->state)
                     || atomic_read(&rna_service_detached)
                     || atomic_read(&shutdown))) {
            break;
        }
        blk = list_entry(pos, struct cache_blk, cb_conn_wlru);

        if (unlikely(IS_MARKER_BLK(blk))) {
            continue;
        }

        if (!dev_is_persistent(blk->dev)) {
            continue;
        }

        if (blk->cb_write_time >= target_time) {
            break;
        }

        if (atomic_read(&conn->rsc_outstanding_write_releases) >=
                         (int32_t)rnablk_write_reference_release_max_outstanding) {
            /* don't swamp the CS with write reference drops/downgrades */
            break;
        }

        if (rnablk_can_downgrade_cache_blk(blk)) {
            rnablk_cache_blk_ref(blk);
            list_add(&marker.cb_conn_wlru, pos);
            BUG_ON(FALSE !=
                    atomic_cmpxchg(&blk->cb_write_reference_pending, FALSE, TRUE));
            rna_block_mutex_unlock(&conn->block_list_lock, &mutex_lock_handle);
            if (rnablk_try_downgrade_cache_blk(blk)) {
                atomic_inc(&conn->rsc_outstanding_write_releases);
                rna_printk(KERN_DEBUG, "downgrading block [%llu] [%d/%u]\n",
                           blk->block_number,
                           atomic_read(&conn->rsc_outstanding_write_releases),
                           rnablk_write_reference_release_max_outstanding);
#ifdef DEBUG_ENFORCER
                dbg_ndropped++;
#endif /* DEBUG_ENFORCER */
                atomic64_inc(&blk->dev->stats.enforcer_downgraded_blocks);
                rnablk_start_blk_io(blk, FALSE);
            } else {
                /*
                 * if this block has been cleaned up by
                 * rnablk_conn_blks_sort_list_cachedev(), leave it alone.
                 */
                if (conn == rnablk_get_blk_conn(blk)) {
                    BUG_ON(TRUE !=
                            atomic_cmpxchg(&blk->cb_write_reference_pending, TRUE, FALSE));
                }
                rna_printk(KERN_DEBUG, "FAILED to downgrade block [%llu]\n",
                           blk->block_number);
#ifdef DEBUG_ENFORCER
                dbg_ncantdrop++;
#endif /* DEBUG_ENFORCER */
            }
            rnablk_cache_blk_release(blk);
            rna_block_mutex_lock(&conn->block_list_lock, &mutex_lock_handle);

#ifdef WINDOWS_KERNEL
            tmp = marker.cb_conn_wlru.Flink;
#else
            tmp = marker.cb_conn_wlru.next;
#endif /*WINDOWS_KERNEL*/

            list_del_init(&marker.cb_conn_wlru);
        }
#ifdef DEBUG_ENFORCER
        else {
            dbg_nskipped++;
        }
#endif /* DEBUG_ENFORCER */
    }
    rna_block_mutex_unlock(&conn->block_list_lock, &mutex_lock_handle);
#ifdef DEBUG_ENFORCER
    if ((get_seconds() - start_seconds) >= 10) {
        rna_printk(KERN_ERR, "took [%lu] seconds: ndrop=%d nskip=%d ncant=%d\n",
                   get_seconds() - start_seconds, dbg_ndropped, dbg_nskipped,
                   dbg_ncantdrop);
    }
#endif /* DEBUG_ENFORCER */
    return;
}

static void
rnablk_enforce_limits(struct rnablk_server_conn *conn)
{
    rnablk_apply_ref_block_limit(conn);
    rnablk_apply_write_ref_block_limit(conn);
}

/*
 * Returns TRUE if the enforcement criteria indicates action is needed.
 * Otherwise returns FALSE (including for the case where enforcement isn't
 * enabled because target_ages are all 0).
 */
INLINE boolean
rnablk_enforce_criteria(struct rnablk_server_conn *conn)
{
    if (rnablk_reference_target_age
        && conn->rsc_lru_oldest_ts < (get_jiffies() - msecs_to_jiffies(
                                     rnablk_reference_target_age))) {
        return TRUE;
    }

    if (rnablk_write_reference_target_age
        && conn->rsc_wlru_oldest_ts < (get_jiffies() - msecs_to_jiffies(
                                rnablk_write_reference_target_age))) {
        return TRUE;
    }

    return FALSE;
}

/*
 * Enforce limits on read/write references.
 *
 * Begin corrective action if any criteria are above the enforcement
 * thresholds.  Start the device queue if all the criteria are below the
 * admit limit for new block requests.  The decision to stop the
 * device queue is made in the block request prep function.
 *
 * runs in kthread context
 */
static void
rnablk_enforcer_wf(rnablk_workq_cb_arg_t arg)
{
    struct work_struct *work = (struct work_struct *)arg;
    struct rnablk_work *w = container_of( work,struct rnablk_work,work );
    struct rnablk_enforcer_wf_data *wd = &w->data.rwd_rnablk_enforcer_wf;
    struct rnablk_server_conn *conn = wd->conn;
    uint64_t start_seconds = get_seconds();
    ENTER;

    UNREFERENCED_PARAMETER(ret);

    BUG_ON(NULL==conn);

    if (likely(rnablk_conn_connected(conn))) {
        if (unlikely(rnablk_enforce_criteria(conn))) {
            rnablk_enforce_limits(conn);
        }
    }
    atomic_bit_clear(&conn->rsc_flags, RSC_F_ENFORCER_SCHEDULED);
    rnablk_server_conn_put(conn);
    rnablk_mempool_free( w, work_cache_info );
    rnablk_finish_workq_work(start_seconds);
    EXITV;
}

/* 
 * Schedule limit enforcement for this device if it isn't already
 * scheduled.
 *
 * Should be called after any action that may cause any of the
 * enforced limits to change, especially if they cross the enforcement
 * or block request admission criteria.
 *
 * may run at softirq level
 */
static int
rnablk_schedule_enforcer(struct rnablk_server_conn *conn, void *unused)
{
    struct rnablk_work *w = NULL;
    struct rnablk_enforcer_wf_data *wd = NULL;
    ENTER;

    if (g_md_conn == conn) {
        return 0;
    }

    RNABLK_BUG_ON(NULL == conn, "NULL conn argument!");
    RNABLK_BUG_ON(!is_parent_conn(conn), "not a parent conn! conn ["CONNFMT"] "
                  "p_conn=%p\n", CONNFMTARGS(conn), conn->rsc_parent_conn);

    /* Do nothing if enforcer already scheduled or not needed */
    if (!rnablk_conn_connected(conn)
        || atomic_bit_is_set(&conn->rsc_flags, RSC_F_ENFORCER_SCHEDULED)
        || (!rnablk_enforce_criteria(conn))) {
        goto out;
    }

    if (likely(!atomic_bit_test_and_set(&conn->rsc_flags,
                                        RSC_F_ENFORCER_SCHEDULED))) {
        goto out;
    }

    if (unlikely((w = rnablk_mempool_alloc( work_cache_info )) == NULL)) {
        atomic_bit_clear(&conn->rsc_flags, RSC_F_ENFORCER_SCHEDULED);
        GOTO( err,-ENOMEM );
    }
    RNABLK_INIT_RNABLK_WORK(w, wd, rnablk_enforcer_wf);
    atomic_inc(&conn->rsc_refcount);
    wd->conn = conn;
    rna_queue_work(enforcer_workq, &w->work);

out:
    return 0;
err:
    rna_printk(KERN_ERR, "failed to allocate memory for work queue item\n");
    goto out;
}

static void
rnablk_run_enforcer_wf(rnablk_workq_cb_arg_t arg)
{
    rnablk_dwork_t w = RNABLK_ARG_DWORK(arg);

    if (likely(!atomic_read(&shutdown))
        && (rnablk_reference_target_age || rnablk_write_reference_target_age)) {
        rnablk_cache_conn_foreach(rnablk_schedule_enforcer, NULL);
        rna_queue_delayed_work(mt_workq, RNABLK_DWORK_OBJECT(w),
                               msecs_to_jiffies(1000));
        return;
    }
    atomic_set(&rnablk_enforcer_running, FALSE);
    if (w->delayed) {
        atomic_dec(&delayed_work);
    }
    RNABLK_FREE_DWORK(w);
}

void
rnablk_enable_enforcer()
{
    rnablk_dwork_t w;

    if (!atomic_read(&shutdown)
        && FALSE == atomic_cmpxchg(&rnablk_enforcer_running, FALSE, TRUE)) {
        w = RNABLK_ALLOC_DWORK();
        if (NULL == w) {
            rna_printk(KERN_ERR, "Failed to allocate workq item to enable "
                       "enforcer\n");
            atomic_set(&rnablk_enforcer_running, FALSE);
        } else {
            RNABLK_INIT_DWORK(w, rnablk_run_enforcer_wf);
            rna_queue_delayed_work(mt_workq, RNABLK_DWORK_OBJECT(w),
                                   msecs_to_jiffies(1000));
        }
    }
}

#ifndef WINDOWS_KERNEL

int rnablk_prep_fn( struct request_queue *q,struct request *req )
{
    struct rnablk_device *dev = q->queuedata;
    ENTER;

    RNA_REQ_FLAGS(req) |= REQ_DONTPREP;
    ret = BLKPREP_OK;
    EXIT;
}


static int rnablk_reserve_special_request(struct request *req)
{
    return (!RNA_FS_REQ(req) &&
            req->special &&
            (RNABLK_RESERVE_SPECIAL == 
             ((rnablk_special_hdr_t *)req->special)->sh_type));
}

static  int 
rnablk_handle_special_request(struct rnablk_device *dev, 
                              struct request_queue *q, 
                              struct request *req)
{
    rnablk_special_req_t type;
    int err = 0;

    BUG_ON(!req->special);
    type = ((rnablk_special_hdr_t *)req->special)->sh_type;
    switch (type) {
    case RNABLK_EXTENDED_COPY_SPECIAL:
        err = rnablk_send_extended_copy_request(dev, req);
        break;
    case RNABLK_RECEIVE_COPY_RESULTS_SPECIAL:
        err = rnablk_send_receive_copy_results_request(dev, req);
        break;
    default:
        err = -EINVAL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
        rna_printk(KERN_ERR,
                   "[%s] unsupported request [%p] type [%d] ignored\n",
                   dev->name, req, req->cmd_type);
#endif
    }
    return err;
}

/*
 * Perform strategy work.  Called only by rnablk_strategy(), which has
 * validated that it's safe to do this in the current context.
 */
static  void
rnablk_strategy_consume_requests(struct request_queue *q)
{
    struct gendisk *disk;
    struct rnablk_device *dev = NULL;
    struct request *req;
    struct io_state *ios[RNABLK_MAX_SUB_IO];
#if defined(PARANOID_BOUNDS_CHECK)
    sector_t last_sector;
#endif
    int n_io;
    int rw;
    int i;
    int err = 0;
    rnablk_cache_status status;
    ENTER;

    // retrieve pointer to our per-device data structure
    dev  = (struct rnablk_device *)q->queuedata;
    disk = dev->disk;
    status = atomic_read(&dev->stats.status);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
    req = elv_next_request(q);
#else
    req = blk_fetch_request(q);
#endif

    while (req != NULL) {
        atomic_inc( &dev->strategy_threads );

        err = 0;

        // if this device is not online refuse the request
        if (unlikely((status != RNABLK_CACHE_ONLINE) ||
                            rnablk_dev_is_shutdown(dev) ||
                            atomic_read(&shutdown))) {
            rna_printk(KERN_ERR,"[%s] req [%p] ignored while not online\n", dev->name, req);
            err = -ENODEV;
            goto done;
        }

        if (unlikely(atomic_read(&dev->failed))) {
            if (unlikely(!RNA_FS_REQ(req))) {
                rna_printk(KERN_ERR,
                           "rejecting special request type [%s] "
                           "for failed device [%s]\n",
                           rnablk_special_req_string(req),
                           dev->name);
            } else {
                rna_printk(KERN_INFO,
                           "rejecting IO for failed device [%s]\n",
                           dev->name);
            }
            err = -EIO;
            goto done;
        }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
        if (unlikely(RNA_DISC_REQ(req))) {
            rna_printk(KERN_ERR,"[%s] req [%p] is discard\n", dev->name, req);
        }
#endif

        if (unlikely(RNA_PC_REQ(req))) {
            rna_printk(KERN_ERR,"[%s] req [%p] is a SCSI command\n", dev->name, req);
        }

        if (unlikely(!RNA_FS_REQ(req))) {
            if (req->special) {
                err = rnablk_handle_special_request(dev, q, req);
            }
            goto done;
        }

        BUG_ON(NULL != req->special);
        rnablk_set_req_refcount(req, 0);

#if defined(PARANOID_BOUNDS_CHECK)
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
        last_sector = req->sector + req->nr_sectors;
#else
        last_sector = blk_rq_pos(req) + blk_rq_sectors(req);
#endif
        // Request in range of device size?
        if (unlikely(((last_sector << RNABLK_SECTOR_SHIFT)) > dev->device_cap)) {
            rna_printk(KERN_ERR,
                       "[%s] sector [%"PRIu64"] beyond end of device [%"PRIu64"]\n",
                       dev->name,
                       (uint64_t)last_sector,
                       (dev->device_cap >> RNABLK_SECTOR_SHIFT));
            err = -EIO;
            goto done;
        }
#endif //PARANOID_BOUNDS_CHECK

        // coalesce the scatter list and divide into valid sub-requests
        //
        // TBD: Seems like we should be able to do this without holding the 
        // block spinlock, and get more benefit from multiple strategy
        // threads.
        if (unlikely((n_io = rnablk_rq_map_sg(dev, q, req, &ios[0])) < 0)) {
            err = -EIO;
            goto done;
        }

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
        // remove current request from queue
        blkdev_dequeue_request( req );

        // account for this request in gendisk->disk_stats
        rw = RNA_REQ_FLAGS(req) & REQ_WRITE;
        disk_stat_inc( disk,ios[rw] );
        disk_stat_add( disk,sectors[rw],req->nr_sectors );
#endif

        // submit sub-requests
        if (likely(!rnablk_reservation_access_check(dev,
                                        (RNA_REQ_FLAGS(req) & REQ_WRITE)
                                        ? RSV_ACC_READWRITE
                                        : RSV_ACC_READONLY))) {
            rnablk_svcctl_register();
            spin_unlock_irq( q->queue_lock );
            for (i=0; i < n_io; i++) {
                rnablk_process_request( ios[i] );
            }
            spin_lock_irq( q->queue_lock );
            rnablk_svcctl_deregister();
        } else {                // access_check failed...
            RNA_REQ_FLAGS(req) |= REQ_QUIET;
            for (i = 0; i < n_io; i++) {
                /*
                 * Clear IOPATH flag so we don't try to decrement device
                 * iocnt during end_request.  (Can't decrement it since
                 * we didn't increment it up above!)
                 */
                atomic_bit_clear(&ios[i]->ios_atomic_flags, IOS_AF_DEVIOCNT);
                rnablk_end_request(ios[i], -EBUSY);
            }
        }
    done:
        atomic_dec( &dev->strategy_threads );

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
        if (unlikely(err)) {
            end_request(req, 0);
        }
        req = elv_next_request(q);
#else
        if (unlikely(err)) {
            req->errors = err;
            blk_complete_request( req );
        }
        req = blk_fetch_request(q);
#endif
    }

    EXITV;
}

/*
 * Decide whether we can perform strategy work now, or whether it 
 * must be deferred to another thread.
 */
void rnablk_strategy( struct request_queue *q )
{
    struct gendisk *disk;
    struct rnablk_device *dev = NULL;
    int remaining_stack = rnablk_remaining_stack();
    ENTER;

    // retrieve pointer to our per-device data structure
    dev  = (struct rnablk_device *)q->queuedata;
    disk = dev->disk;

    if (unlikely(!in_interrupt() && (remaining_stack < atomic_read(&dev->min_stack)))) {
        atomic_set(&dev->min_stack, remaining_stack);
    }

    /* 
     * We must be able to sleep to process any requests, so move 
     * to a work thread if we're in a softirq here.
     *
     * We also defer to a workq thread if we don't have enough stack
     * remaining here.
     */
    if (unlikely(in_interrupt() || (remaining_stack < RNABLK_MIN_STRATEGY_STACK))) {
        if (in_interrupt()) {
            atomic_inc(&dev->deferred_softirq);
        } else {
            atomic_inc(&dev->deferred_stack);
        }

        /*
         * If rnablk_strategy is already running for this queue in
         * some other thread(s), there's no need to stop and
         * reschedule (that thread will pick up these requests), and
         * in fact that will probably slow things down.
         */
        if (!atomic_read(&dev->strategy_threads) &&
            !rnablk_get_dev_queue_stop_flag_nolock(dev, RNABLK_Q_STOP_DEFER_TO_WORKQ)) {

            rnablk_set_dev_queue_stop_flag_nolock(dev, RNABLK_Q_STOP_DEFER_TO_WORKQ);
            rnablk_schedule_clear_dev_queue_stop_flag(dev, RNABLK_Q_STOP_DEFER_TO_WORKQ);
        }
        EXITV;
    }

    rnablk_strategy_consume_requests(q);

    EXITV;
}


void rnablk_stop_devs (void)
{
    struct list_head     *pos = NULL;
    struct rnablk_device *dev = NULL;
    unsigned char oldirql = 0;

    rna_down_read(&rnablk_dev_list_lock, &oldirql);
    list_for_each(pos, &rnablk_dev_list) {
        dev = list_entry(pos, struct rnablk_device, l);
        if (NULL != dev->q) {
            rna_printk(KERN_ERR,
                       "Stopping queue for dev [%s]\n",
                       dev->name);
            rnablk_set_dev_queue_stop_flag(dev, RNABLK_Q_STOP_DISCONN);
        }
    }
    rna_up_read(&rnablk_dev_list_lock, oldirql);
}

void
rnablk_start_devs(struct rnablk_server_conn *conn, boolean do_all_devs)
{
    struct list_head     *pos = NULL;
    struct rnablk_device *dev = NULL;
    unsigned char oldirql = 0;

    rna_down_read(&rnablk_dev_list_lock, &oldirql);
    list_for_each(pos, &rnablk_dev_list) {

        dev = list_entry(pos, struct rnablk_device, l);

        if (!MASTER_BLK_IS_CONNECTED(dev)
            && (do_all_devs
                || (NULL != conn && MASTER_BLK_CONN(dev) == conn))
            // we are not getting master blocks for failed devices.
            && FALSE == atomic_read(&dev->failed)) {
            rna_printk(KERN_NOTICE, "Queue MASTER_BLOCK lock for dev [%s] "
                       "conn ["CONNFMT"]\n",
                       dev->name, CONNFMTARGS(MASTER_BLK_CONN(dev)));
            /* XXXgus - MVP-6198: give MD time to realize CS is gone */
            rnablk_queue_delayed_master_blk_lock(dev);

        } else if (NULL != dev->q) {
            rna_printk(KERN_NOTICE,
                       "Starting queue for dev [%s] conn ["CONNFMT"]\n",
                       dev->name, CONNFMTARGS(MASTER_BLK_CONN(dev)));
            // avoid locking issues, as starting the queue will ultimately
            // call the strategy function
            rnablk_schedule_clear_dev_queue_stop_flag(dev, RNABLK_Q_STOP_DISCONN);
            // this may be needed if enforcer was in affect before failure
            // rnablk_schedule_enforcer(dev);
        }
    }
    rna_up_read(&rnablk_dev_list_lock, oldirql);
}
#endif /*WINDOWS_KERNEL*/

