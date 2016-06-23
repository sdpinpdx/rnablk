/**
 * <rnablk_block_state.c> - Dell Fluid Cache block driver
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

#include "rnablk_block_state.h"
#include "rnablk_cache.h"
#include "rnablk_util.h"
#include "rnablk_globals.h"
#include "rnablk_system.h"
#include "rnablk_queue_dispatch.h"
#include "rnablk_io_state.h"
#include "rnablk_device.h"
#include "rnablk_protocol.h"
#include "trace.h"

#include "rnablk_rwsemaphore.h"

#ifdef WINDOWS_KERNEL
#if defined(_MSC_VER) || defined(_MSC_EXTENSIONS)
  #define DELTA_EPOCH_IN_MICROSECS  11644473600000000Ui64
#else
  #define DELTA_EPOCH_IN_MICROSECS  11644473600000000ULL
#endif

uint64_t get_seconds(){
	LARGE_INTEGER curTime;
	unsigned __int64 tmpres = 0;

	KeQuerySystemTime (&curTime);
	tmpres |= curTime.HighPart;
	tmpres <<= 32;
	tmpres |= curTime.LowPart;
        /*converting file time to unix epoch*/
    tmpres -= DELTA_EPOCH_IN_MICROSECS; 
    tmpres /= 10;  /*convert into microseconds*/
    return (uint64_t)(tmpres / 1000000UL);
}

unsigned int jiffies_to_msecs(const uint64_t j)
{
	return (unsigned int)( KeQueryTimeIncrement() * j / 10000);
}

uint64_t msecs_to_jiffies(const unsigned int m)
{
	return (m * (uint64_t)10000) / KeQueryTimeIncrement();
}

#endif

typedef void (*RNABLK_QUEUE_DEREF_CB) (rnablk_workq_cb_arg_t);


/*
 * __rnablk_needed_lock()
 *  Internal common code for rnablk_needed_lock().
 *
 * Return value:
 *   return TRUE if the caller should process the ios, or FALSE if the ios is
 *   requeued here (in which case the caller must not touch the ios).
 */  
static int
__rnablk_needed_lock(struct io_state *ios,
                     state_property_mask_t state_mask,
                     cache_lock_t connect_lock_type,
                     cache_lock_t change_lock_type,
                     cache_lock_t *needed_lock_type)
{
    lockstate_t flags;

    if (_rnablk_cache_blk_state_is(ios->blk->state, state_mask)
        && !rnablk_cache_blk_state_is_transitional(ios->blk->state)) {
        rna_printk(KERN_ERR,
                   "device [%s] block [%llu] state [%s] op type [%s] "
                   "ios [%p] tag ["TAGFMT"] requesting reference which we "
                   "already have\n",
                   ios->dev->name,
                   ios->blk->block_number,
                   rnablk_cache_blk_state_string(ios->blk->state),
                   rnablk_op_type_string(ios->type),
                   ios, TAGFMTARGS(ios->tag));
        // queue this request for i/o, since we already have the ref we need
        rnablk_ios_skip_query(ios);
        return FALSE;   // ios requeued, caller must not dispatch or modify it
    } 

    switch (ios->blk->state) {
    case RNABLK_CACHE_BLK_CONNECT_PENDING:
        *needed_lock_type = connect_lock_type;
        break;

    case RNABLK_CACHE_BLK_CHANGE_PENDING:
        *needed_lock_type = change_lock_type;
        break;

    case RNABLK_CACHE_BLK_DISCONN_PENDING:
    case RNABLK_CACHE_BLK_INVALIDATE_PENDING:
        rna_printk(KERN_INFO, "Queuing ios [%p] tag ["TAGFMT"] block "
                   "[%"PRIu64"] state [%s]\n", ios, TAGFMTARGS(ios->tag),
                   ios->blk->block_number,
                   rnablk_cache_blk_state_string(ios->blk->state));
        rnablk_cache_blk_ref(ios->blk);
        rnablk_lock_blk_irqsave(ios->blk, flags);
        rnablk_io_completed_nolock(ios, ios->blk);
        rnablk_queue_blk_io_nolock(ios->blk, ios, QUEUE_TAIL);
        rnablk_unlock_blk_irqrestore(ios->blk, flags);
        rnablk_cache_blk_release(ios->blk);
        return FALSE;

    default:
        RNABLK_BUG_ON(TRUE, "device [%s] block [%llu] op type [%s] ios [%p] "
                      "tag ["TAGFMT"] in unexpected state [%s]\n",
                       ios->dev->name,
                       ios->blk->block_number,
                       rnablk_op_type_string(ios->type),
                       ios, TAGFMTARGS(ios->tag),
                       rnablk_cache_blk_state_string(ios->blk->state));
        break;
    }
    return TRUE;
}

/**
 * Computes needed lock type for ios.  May requeue the IOS if a query
 * is needed, or if the desired reference type for an IO is already
 * held.
 *
 * @return TRUE if the caller should process the ios, or FALSE if the ios is
 * requeued here (in which case the caller must not touch the ios).
 */
int
rnablk_needed_lock(struct io_state *ios,
                   cache_lock_t *lock_type)
{
    ENTER;

    switch (ios->ios_iotype) {
    case IOS_IOTYPE_WRITE:
    case IOS_IOTYPE_WRITE_SAME:
        // TODO: non-atomic reads (multiple) of block state
        ret = __rnablk_needed_lock(ios, RNABLK_CACHE_BLK_STATE_WRITABLE,
                                   rnablk_use_write_only ?
                                   CACHE_WRITE_ONLY_SHARED : CACHE_WRITE_SHARED,
                                   CACHE_WRITE_SHARED, lock_type);
        break;

    case IOS_IOTYPE_READ:
        ret = __rnablk_needed_lock(ios, RNABLK_CACHE_BLK_STATE_READABLE,
                                   CACHE_READ_SHARED, CACHE_WRITE_SHARED,
                                   lock_type);
        break;

    case IOS_IOTYPE_COMP_WR:
        ret = __rnablk_needed_lock(ios,
                                   RNABLK_CACHE_BLK_STATE_WRITABLE |
                                   RNABLK_CACHE_BLK_STATE_READABLE ,
                                   CACHE_WRITE_SHARED,
                                   CACHE_WRITE_SHARED, lock_type);
        break;

    default:
        RNABLK_BUG_ON(TRUE, "unexpected iotype [%d] ios [%p] "
                      "block [%llu]\n", ios->ios_iotype, ios,
                      ios->blk->block_number);
        break;
    }
    EXIT;
}


/*
 * rnablk_cs_query_blk_transition
 *  Transition cache_blk state after a successful CACHE_QUERY response
 *  from the Cache-Server.
 *
 * Notes:
 *  1) Caller must have reference on 'blk' and hold bl_lock
 */
void
rnablk_cs_query_blk_transition(struct cache_blk *blk, cache_lock_t ref_type,
                               cache_lock_t orig_ref_type)
{
    rnablk_cache_blk_state_t cur_state, new_state;
    boolean warn_usage = FALSE;

	cur_state = RNABLK_CACHE_BLK_UNINITIALIZED;
	new_state = RNABLK_CACHE_BLK_UNINITIALIZED;

    switch (ref_type) {
    case CACHE_READ_SHARED:
        cur_state = RNABLK_CACHE_BLK_CONNECT_PENDING;
        new_state = RNABLK_CACHE_BLK_CONNECTED_READ;
        break;

    case CACHE_WRITE_SHARED:
        if (orig_ref_type == CACHE_NO_REFERENCE) {
            cur_state = RNABLK_CACHE_BLK_CONNECT_PENDING;
        } else {
            cur_state = RNABLK_CACHE_BLK_CHANGE_PENDING;
            warn_usage = TRUE;
        }
        new_state = RNABLK_CACHE_BLK_CONNECTED_WRITE;
        break;

    case CACHE_WRITE_EXCLUSIVE:
        RNABLK_BUG_ON(CACHE_WRITE_SHARED == orig_ref_type,
                      "Unexpected orig_ref_type=%d blk=%p [%"PRIu64"]\n",
                      orig_ref_type, blk, blk->block_number);
        /*
         * Note we use CHANGE_PENDING here even though this request is
         * issued as a QUERY.  That's because at heart it really is
         * a change request since we already hold a reference to the
         * master block...
         */
        cur_state = RNABLK_CACHE_BLK_CHANGE_PENDING;
        new_state = RNABLK_CACHE_BLK_CONNECTED_WRITE_EXCLUSIVE;
        break;

    case CACHE_WRITE_ONLY_SHARED:
        if (CACHE_NO_REFERENCE != orig_ref_type) {
            rna_printk(KERN_ERR,
                       "[%s] block [%"PRIu64"] in state [%s] unexpected "
                       "original reference [%s] for new ref [%s]\n",
                       blk->dev->name,
                       blk->block_number,
                       rnablk_cache_blk_state_string(blk->state),
                       get_lock_type_string(orig_ref_type),
                       get_lock_type_string(ref_type));
            BUG();
        }
        cur_state = RNABLK_CACHE_BLK_CONNECT_PENDING;
        new_state = RNABLK_CACHE_BLK_CONNECTED_WRITE_ONLY;
        break;

    case CACHE_ATOMIC_SHARED:
        if (orig_ref_type == CACHE_NO_REFERENCE) {
            cur_state = RNABLK_CACHE_BLK_CONNECT_PENDING;
        } else {
            cur_state = RNABLK_CACHE_BLK_CHANGE_PENDING;
            warn_usage = TRUE;
        }
        new_state = RNABLK_CACHE_BLK_CONNECTED_ATOMIC;
        break;

    default:
        rna_printk(KERN_ERR,
                   "[%s] block [%"PRIu64"] in unexpected new ref type [%s]\n",
                   blk->dev->name, blk->block_number,
                   get_lock_type_string(ref_type));
        BUG_ON(TRUE);
    }
        
    if (warn_usage) {
        rna_printk(KERN_WARNING,
                   "[%s] block [%"PRIu64"] state [%s] using query to "
                   "transition from ref type [%s] to type [%s]\n",
                   blk->dev->name,
                   blk->block_number,
                   rnablk_cache_blk_state_string(blk->state),
                   get_lock_type_string(orig_ref_type),
                   get_lock_type_string(ref_type));
    }

    if (unlikely(!rnablk_cache_blk_state_transition(blk, cur_state,
                                                    new_state))) {
        rna_printk(KERN_ERR,
                   "[%s] block [%"PRIu64"] in unexpected state "
                   "[%s] transition from ref type [%s] to type "
                   "[%s]\n",
                   blk->dev->name,
                   blk->block_number,
                   rnablk_cache_blk_state_string(blk->state),
                   get_lock_type_string(orig_ref_type),
                   get_lock_type_string(ref_type));
        BUG_ON(TRUE);
    }
}

void
rnablk_dec_inflight_ios(struct cache_blk *blk)
{
    lockstate_t flags;
    struct io_state *ios;
    boolean start_io = FALSE;
    
    RNABLK_BUG_ON(0 == atomic_read(&blk->inflight_ios),
                  "blk @ %p device [%s] block [%llu] state [%s] inflight_ios "
                  "going negative\n", blk, blk->dev->name, blk->block_number,
                  rnablk_cache_blk_state_string(blk->state));
    rnablk_lock_blk_irqsave(blk, flags);
    if (atomic_dec_and_test(&blk->inflight_ios) &&
        unlikely(atomic_bit_is_set(&blk->cb_flags, BLK_F_WAIT_ON_IO))) {

        switch (blk->state) {
        case RNABLK_CACHE_BLK_CHANGE_PENDING:
            if (!list_empty(&blk->bl)) {
                ios = list_first_entry(&blk->bl, struct io_state, l);
                rna_printk(KERN_DEBUG, "Queuing deferred CHANGE_REF for "
                           "dev [%s] block [%"PRIu64"] state [%s] ref [%s] "
                           "ios [%p] type [%s] has_cmd=%d\n",
                           blk->dev->name, blk->block_number,
                           rnablk_cache_blk_state_string(blk->state),
                           get_lock_type_string(blk->ref_type), ios,
                           rnablk_op_type_string(ios->type), ios->cmd != NULL);
                rnablk_dequeue_blk_io_nolock(blk, ios);
                rnablk_queue_request(RNABLK_CHANGE_REF_NORESP != ios->type
                                     ? RNABLK_CHANGE_REF : ios->type,
                                     blk->ep,
                                     ios,
                                     blk,
                                     FORCE_QUEUED_IO,
                                     TRUE);
                start_io = TRUE;
            } else {
                rna_printk(KERN_WARNING,
                      "No deferred CHANGE_REF ios for device [%s] "
                      "block [%llu] state [%s] ref [%s]\n", blk->dev->name,
                      blk->block_number,
                      rnablk_cache_blk_state_string(blk->state),
                      get_lock_type_string(blk->ref_type));
            }
            break;

        case RNABLK_CACHE_BLK_INVALIDATE_PENDING:
        case RNABLK_CACHE_BLK_DISCONN_PENDING:
        case RNABLK_CACHE_BLK_DISCONNECTED:
            rna_printk(KERN_DEBUG,
                      "deferred CHANGE_REF for device [%s] "
                      "block [%llu] state [%s] ref [%s] ignored due to "
                      "blk state\n", blk->dev->name,
                      blk->block_number,
                      rnablk_cache_blk_state_string(blk->state),
                      get_lock_type_string(blk->ref_type));
            break;

        default:
            rna_printk(KERN_WARNING,
                      "deferred CHANGE_REF for device [%s] "
                      "block [%llu] state [%s] ref [%s] but unexpected "
                      "state\n", blk->dev->name,
                      blk->block_number,
                      rnablk_cache_blk_state_string(blk->state),
                      get_lock_type_string(blk->ref_type));
            break;
        }
        atomic_bit_clear(&blk->cb_flags, BLK_F_WAIT_ON_IO);
    }
    rnablk_unlock_blk_irqrestore(blk, flags);
    if (start_io) {
        rnablk_start_blk_io(blk, FALSE);
    }
}

/*
 * caller must hold conn block_list_lock
 */
void
rnablk_cache_blk_unlink_lru_locked(struct rnablk_server_conn *conn,
                                   struct cache_blk *blk,
                                   boolean write_only)
{
    rnablk_cachedev_t *cdp = blk->blk_cachedev;
    //int wref;

	RNABLK_DBG_BUG_ON(NULL == cdp || is_null_cachedev(cdp),
                  "blk [%p] block [%llu] bad cachedev %p\n", blk,
                  blk->block_number, cdp);

    if (!list_empty(&blk->cb_conn_wlru)) {
        list_del_init(&blk->cb_conn_wlru);
        blk_lru_del_init(&blk->cb_conn_wref);
        if (!list_empty(&conn->rsc_wlru_list)) {
            conn->rsc_wlru_oldest_ts = list_first_entry(&conn->rsc_wlru_list,
                                        struct cache_blk, cb_conn_wlru)->
                                        cb_write_time;
        } else {
            conn->rsc_wlru_oldest_ts = 0xffffffffffffffff;
        }
    }
    if (!write_only) {
        RNABLK_BUG_ON(blk_lru_list_empty(&blk->cb_conn_lru),
                      "blk=%p [%llu] not in conn list! conn ["CONNFMT"]\n",
                      blk, blk->block_number, CONNFMTARGS(conn));
        conn->block_list_length--;
        blk_lru_del_init(&blk->cb_conn_lru);
        if (!blk_lru_list_empty(&cdp->rcd_block_list)) {
			/* For linux code, this was okay with define. But in order to be compatible with windows, 
				change this to an inline function.
            conn->rsc_lru_oldest_ts = blk_lru_first_entry(&cdp->rcd_block_list,
                                        wref, cb_conn_lru, cb_conn_wref)->
                                        cb_ref_time;
			*/
            conn->rsc_lru_oldest_ts = blk_lru_first_entry(&cdp->rcd_block_list)->cb_ref_time;
        } else {
            conn->rsc_lru_oldest_ts = 0xffffffffffffffff;
        }
        /*
         * we're taking it completely out of all lists, so drop the
         * blk reference added in rnablk_cache_blk_insert_lru().
         */
        rnablk_cache_blk_release(blk);
    }
}

/*
 * rnablk_cs_change_req_blk_transition
 *  Transition cache_blk state after a successful CACHE_CHANGE_REF_RESP
 *  from the Cache-Server.
 *
 * Notes:
 *  1) Caller must have reference on 'blk' and hold the block lock, and also
 *     must hold conn block_list_lock (the latter is actually only needed
 *     if 'ref_type' is CACHE_NO_REFERENCE or CACHE_READ_SHARED).
 *
 * Return Value:
 *  Returns TRUE if the blk state was successfully transitioned, otherwise
 *  returns FALSE.
 */
boolean
rnablk_cs_change_req_blk_transition(struct rnablk_server_conn *conn,
                                    struct cache_blk *blk,
                                    cache_lock_t ref_type)
{
    rnablk_cache_blk_state_t cur_state, new_state;
    struct sockaddr_in dst_in;
    boolean transition;

	cur_state = RNABLK_CACHE_BLK_UNINITIALIZED;
	new_state = RNABLK_CACHE_BLK_UNINITIALIZED;

    switch (ref_type) {
    case CACHE_NO_REFERENCE:
        if (unlikely(net_link_mask & RNABLK_NL_BLK_STATE)) {
            dst_in = get_dest_sockaddr_from_ep(blk->ep);
            printnl_atomic("[%d] [%s] "
                           "block [%"PRIu64"] of dev [%s] [%s] "
                           "from cache ["NIPQUAD_FMT"] NOT deletable "
                           "bl [%s] dispatch_queue [%s] blk->ep [%p]\n",
                           current->pid,
                           __FUNCTION__,
                           blk->block_number,
                           blk->dev->name,
                           rnablk_cache_blk_state_string(blk->state),
                           NIPQUAD(dst_in.sin_addr.s_addr),
                           list_empty(&blk->bl)?"empty":"nonempty",
                           list_empty(&blk->dispatch_queue)?"empty":"nonempty",
                           blk->ep);
        }
        cur_state = RNABLK_CACHE_BLK_DISCONN_PENDING;
        new_state = RNABLK_CACHE_BLK_DISCONNECTED;
        break;

    case CACHE_READ_SHARED:
        cur_state = RNABLK_CACHE_BLK_CHANGE_PENDING;
        new_state = RNABLK_CACHE_BLK_CONNECTED_READ;
        break;

    case CACHE_WRITE_SHARED:
        cur_state = RNABLK_CACHE_BLK_CHANGE_PENDING;
        new_state = RNABLK_CACHE_BLK_CONNECTED_WRITE;
        break;

    case CACHE_ATOMIC_SHARED:
        cur_state = RNABLK_CACHE_BLK_CHANGE_PENDING;
        new_state = RNABLK_CACHE_BLK_CONNECTED_ATOMIC;
        break;


    case CACHE_WRITE_ONLY_SHARED:
        cur_state = RNABLK_CACHE_BLK_CHANGE_PENDING;
        new_state = RNABLK_CACHE_BLK_CONNECTED_WRITE_ONLY;
        break;

    default:
        rna_printk(KERN_ERR,
                   "[%s] block [%"PRIu64"] in unexpected new ref type [%s]\n",
                   blk->dev->name, blk->block_number,
                   get_lock_type_string(ref_type));
        BUG_ON(TRUE);
    }

    if (RNABLK_CACHE_BLK_CHANGE_PENDING == cur_state
        && RNABLK_CACHE_BLK_DISCONN_PENDING == blk->state) {
        cur_state = RNABLK_CACHE_BLK_DISCONN_PENDING;
    }

    transition = (boolean)rnablk_cache_blk_state_transition(blk, cur_state,
                                                            new_state);
    if (transition) {
        if (CACHE_NO_REFERENCE == ref_type) {
            rnablk_unset_blk_ep(blk);
        } else if (CACHE_READ_SHARED == ref_type) {
            rnablk_cache_blk_unlink_lru_locked(conn, blk, TRUE);
        }
    }
    return transition;
}

/**
 * Retrieves certain interesting cache block properties for display in
 * debug output
 *
 * Important note:
 * Callers who desire access to the blk's ep in any way should set the
 * 'need_ep' flag (in addition to passing in a non-null 'dbg_info', of course).
 * If they do so and a non-NULL ep is present in the blk_snapshot info,
 * then the caller is responsible for doing a com_release_ep() on that
 * ep pointer.
 *
 * @return 0 on success, !0 if block doesn't exist
 */
int
rnablk_get_cache_blk_debug_info(struct rnablk_device *dev, 
                                int blk_num,
                                struct rnablk_cache_blk_debug_info *dbg_info,
                                boolean need_ep)
{
    uint64_t start_sector = (dev->cache_blk_size / RNABLK_SECTOR_SIZE) 
                            * blk_num;
    int                 ret=0;
    lockstate_t         flags;
    struct cache_blk    *blk;

    blk = rnablk_cache_blk_get(dev, start_sector);
    if (NULL == blk) {
        ret = -1;
    } else {
        if (NULL != dbg_info) {
            rnablk_lock_blk_irqsave(blk, flags);
            memcpy(&dbg_info->blk_snapshot, blk, sizeof(dbg_info->blk_snapshot));
            dbg_info->bl_empty = list_empty(&blk->bl);
            dbg_info->connl_empty = blk_lru_list_empty(&blk->cb_conn_lru);
            dbg_info->dispatch_queue_empty = list_empty(&blk->dispatch_queue);
            dbg_info->cbd_dev_empty = list_empty(&blk->cb_dev_link);
            if (need_ep && blk->ep != NULL) {
                com_inc_ref_ep(blk->ep);
            }
            rnablk_unlock_blk_irqrestore(blk, flags);
            //TBD: Consider zeroing out hazardous info like list entries and tree nodes
        }
        rnablk_cache_blk_release(blk);        
    }
    return ret;
}

/**
 * This routine searches for the next cache_blk associated with the
 * indicated device that has a block_number >= 'next_blk_num'.
 * If found, it collects cache block properties for the block for display
 * in debug output.  If the caller passes in a non-null 'pp_blk',
 * then this routine returns a pointer to the cache_blk it returns, with
 * a reference held on that cache_blk.  In that case, the caller is
 * responsible for releasing the reference.
 * If 'busy_blks_only' is specified, this routine searches for the
 * next cache_blk that has active I/O.
 *
 * Important note:
 * This routine increments the reference on the 'ep' for the found blk
 * if there is one.  The caller is responsible for releasing that reference
 * (via com_release_ep()) if a non-NULL ep is present in the blk_snapshot
 * info.
 *
 * Return Value:
 *  On success (i.e. a matching cache_blk is found), the dbg_info is
 *  filled out with the pertinent cache_blk data.  If no matching block
 *  is found, then blk_snapshot.block_num field is set to -1 to indicate
 *  no valid data is being returned.
 *
 *  The actual return value is the block_num of the "next" block, i.e. the
 *  next block associated with this device that follows the one we
 *  looked up/reported in this call.  (If no subsequent blocks are found
 *  at all, this may be the original 'next_blk_num' value).
 */
uint64_t
rnablk_get_next_cache_blk_debug_info(
                                struct rnablk_device *dev, 
                                int next_blk_num,
                                struct rnablk_cache_blk_debug_info *dbg_info,
                                struct cache_blk **pp_blk,
                                gboolean busy_blks_only)
{
    uint64_t start_sector = (dev->cache_blk_size / RNABLK_SECTOR_SIZE) 
                            * next_blk_num;
    struct cache_blk *blk;
    lockstate_t   irqflags;
    unsigned char oldirql;

    dbg_info->blk_snapshot.block_number = INVALID_BLOCK_NUM;

    do {
        rna_down_read(&dev->cache_blk_lock, &oldirql);
        blk = rnablk_cache_blk_search_next(&dev->cache_blk_root, start_sector,
                                           &start_sector);
        if (likely(NULL != blk)) {
            rnablk_cache_blk_ref(blk);
        }
        rna_up_read(&dev->cache_blk_lock, oldirql);

        if (NULL == blk) {
            break;
        }
        
        if (!busy_blks_only || atomic_read(&blk->cb_ioref_cnt) > 0) {
            rnablk_lock_blk_irqsave(blk, irqflags);
            memcpy(&dbg_info->blk_snapshot, blk,
                   sizeof(dbg_info->blk_snapshot));
            dbg_info->bl_empty = list_empty(&blk->bl);
            dbg_info->connl_empty = blk_lru_list_empty(&blk->cb_conn_lru);
            dbg_info->dispatch_queue_empty = list_empty(&blk->dispatch_queue);
            dbg_info->cbd_dev_empty = list_empty(&blk->cb_dev_link);
            if (NULL != blk->ep && MD_CONN_EP_METAVALUE != blk->ep) {
                com_inc_ref_ep(blk->ep);
            } else {
                /* make sure this is NULL if we didn't get a ref on ep */
                dbg_info->blk_snapshot.ep = NULL; 
            }
            rnablk_unlock_blk_irqrestore(blk, irqflags);
            if (NULL == pp_blk) {
                rnablk_cache_blk_release(blk);        
            } else {
                *pp_blk = blk;  // hold onto the reference & return a ptr
            }
            break;
        }
        rnablk_cache_blk_release(blk);
    } while (1);

    return start_sector / (dev->cache_blk_size / RNABLK_SECTOR_SIZE);
}

struct rnablk_server_conn *rnablk_get_blk_conn(struct cache_blk *blk)
{
    BUG_ON(NULL==blk);

	return rnablk_get_ep_conn(blk->ep);
}
/*
 * rnablk_cache_blk_make_read_shared
 *  Calling semantics are that block's bl_lock must be held on entry,
 *  but will be unlocked by this return prior to return...
 *
 * Returns 0 on success, non-zero on failure.
 */
static int
rnablk_cache_blk_make_read_shared(struct cache_blk *blk, lockstate_t *irqflags)
{
    int                        ret  = 0;
    rnablk_cache_blk_state_t   save_state = RNABLK_CACHE_BLK_INVALID;
    struct rnablk_server_conn *conn = NULL;

    BUG_ON(NULL == blk);
    BUG_ON(NULL == blk->ep);

#ifndef WINDOWS_KERNEL
    RNABLK_BUG_ON_BLK(!spin_is_locked(&blk->bl_lock.lock), blk);
#endif /*WINDOWS_KERNEL*/

    save_state = blk->state;
    conn = rnablk_get_blk_conn(blk);

    if (unlikely(!rnablk_conn_connected(conn))) {
        rna_printk(KERN_ERR,
                   "downgrade not sent to disconnect CS ["rna_service_id_format"] for [%s] block [%"PRIu64"]\n",
                   rna_service_id_get_string(&conn->id),
                   blk->dev->name,
                   blk->block_number);
        ret = -EINVAL;
    } else if (likely((rnablk_cache_blk_state_can_become_read_shared(blk->state)))) {

        rnablk_cache_blk_state_set(blk, RNABLK_CACHE_BLK_CHANGE_PENDING);
        // temporarily inc within lock; send_change_ref will do real inc
        rnablk_cache_blk_ioref(blk, NULL);
        rnablk_unlock_blk_irqrestore(blk, *irqflags);

        ret = rnablk_cache_blk_send_change_ref(blk, CACHE_READ_SHARED, 0);

        rnablk_cache_blk_iorel(blk, NULL)   // undo temp ref
        rnablk_lock_blk_irqsave(blk, *irqflags);

        if (unlikely(ret)) {
            /* revert state */
            rna_printk(KERN_ERR,
                       "failed to send deref for [%s] block [%"PRIu64"]\n",
                       blk->dev->cache_file_name,
                       blk->block_number);
            /*
             * Restore blk state only if it hasn't changed out from under
             * us (which could have happened due to a CS disconnect or
             * a cache-device failure).
             */
            if (rnablk_cache_blk_state_transition(blk,
                                            RNABLK_CACHE_BLK_CHANGE_PENDING,
                                            save_state)) {
                /*
                 * we just left a transitional state, so need to
                 * check to see if I/Os got queued in the interim.
                 */
                rnablk_cache_blk_drain_nolock(blk, irqflags);
            }
        } else {
            rnablk_cache_blk_update_dev_counts(blk);
            rna_printk(KERN_DEBUG,
                       "[%s] block [%"PRIu64"] state [%s] transition [%s -> %s]\n",
                       blk->dev->cache_file_name,
                       blk->block_number,
                       rnablk_cache_blk_state_string(blk->state),
                       get_lock_type_string(blk->ref_type),
                       get_lock_type_string(CACHE_READ_SHARED));
        }
    } else {
        rna_printk(KERN_ERR,
                   "deref not sent for [%s] block [%"PRIu64"] in unexpected state [%s]\n",
                   blk->dev->cache_file_name,
                   blk->block_number,
                   rnablk_cache_blk_state_string(blk->state));

    }

    rnablk_unlock_blk_irqrestore(blk, *irqflags);
    return ret;
}


static void
rnablk_queued_delete(rnablk_workq_cb_arg_t arg)
{
    struct work_struct *work = (struct work_struct *)arg;
    struct rnablk_work *w = container_of( work,struct rnablk_work,work );
    struct rnablk_queued_delete_data *wd = &w->data.rwd_rnablk_queued_delete;
    lockstate_t      flags;
    struct cache_blk   *blk = wd->blk;
    uint64_t       start_seconds = get_seconds();
    boolean             did_unlink;
    unsigned char       oldirql = 0;

    /* take a peek w/o the lock; avoid the overhead if there's no point! */
    if (RNABLK_CACHE_BLK_DISCONNECTED == blk->state) {
        rna_down_write(&blk->dev->cache_blk_lock, &oldirql);
        rnablk_lock_blk_irqsave(blk, flags);
        /* ref_count of 2 means we (and the rbtree) are the only reference... */
        if ((2 == atomic_read(&blk->ref_count) &&
            rnablk_cache_blk_state_transition(blk,
                                            RNABLK_CACHE_BLK_DISCONNECTED,
                                            RNABLK_CACHE_BLK_DELETE_PENDING))) {
            RNABLK_BUG_ON_BLK(!list_empty(&blk->bl), blk);
            RNABLK_BUG_ON_BLK(!list_empty(&blk->dispatch_queue), blk);
            rnablk_cache_blk_unlink_nolock(blk);
            did_unlink = TRUE;
        } else {
            did_unlink = FALSE;
        }
        rnablk_unlock_blk_irqrestore(blk, flags);
        rna_up_write(&blk->dev->cache_blk_lock, oldirql);

        if (did_unlink) {
            /* drop the reference for being in the lru/rb tree */
            rnablk_cache_blk_release(blk);
        }
    }

    /*
     * release reference grabbed when we queued this function.
     * this may also delete block (if refcnt goes to 0).
     */
    rnablk_cache_blk_release(blk);

    rnablk_mempool_free( w, work_cache_info );
    rnablk_finish_workq_work(start_seconds);
}


static void
rnablk_queue_delete(struct cache_blk *blk)
{
    struct rnablk_work *w = NULL;
    struct rnablk_queued_delete_data *wd = NULL;

    BUG_ON(NULL == blk);
    BUG_ON(NULL == blk->dev);

    if (likely(!atomic_read(&shutdown))) {
        if (unlikely(NULL == (w = rnablk_mempool_alloc( work_cache_info )))) {
            rna_printk(KERN_ERR, "Failed to allocate workq item\n");
        } else {
            RNABLK_INIT_RNABLK_WORK(w, wd, rnablk_queued_delete);
            // released in work fn
            rnablk_cache_blk_ref(blk);
            wd->blk  = blk;
            rna_queue_work(mt_workq, &w->work);
        }
    }

}

// Allocate/init a cache block and add it to the device's list
//
// caller must hold write lock on dev->cache_blk_lock
struct cache_blk *
alloc_cache_blk(struct rnablk_device *dev, sector_t start_sector,
                boolean is_master_blk) 
{
    struct cache_blk *blk = NULL;
    uint64_t sectors_per_block;
	uint64_t seconds;

    ENTER;

#ifdef WINDOWS_KERNEL
	UNREFERENCED_PARAMETER(ret);
#endif

    if (!rnablk_dev_acquire(dev)) {     // add a reference to dev for this blk
        return NULL;
    }

	blk = (struct cache_blk *)rnablk_mempool_alloc( blk_cache_info );

    if (NULL != blk) {
        seconds = get_seconds();

        memset(blk, 0, sizeof(*blk));
        INIT_LIST_HEAD(&blk->bl);
        INIT_LIST_HEAD(&blk->dispatch_queue);
        INIT_LIST_HEAD(&blk->cb_conn_wlru);
        blk_lru_list_init(&blk->cb_conn_lru, 0);
        blk_lru_list_init(&blk->cb_conn_wref, 1);
        INIT_LIST_HEAD(&blk->cb_dev_link);
        rna_spin_lock_init(blk->bl_lock);
        blk->dev          = dev;
        blk->block_number = (start_sector * RNABLK_SECTOR_SIZE) / dev->cache_blk_size;
        sectors_per_block = dev->cache_blk_size / RNABLK_SECTOR_SIZE;
        blk->start_sector = blk->block_number * sectors_per_block;

#ifdef WINDOWS_KERNEL
		blk->state = RNABLK_CACHE_BLK_DISCONNECTED;
		blk->ref_type = CACHE_NO_REFERENCE;
		blk->required_ref_type = CACHE_NO_REFERENCE;
		blk->isMasterBlock = FALSE;

#endif //WINDOWS_KERNEL

        /* TODO: If this is the last cache block in the device,
         *       end_sector may ned to be reduced. */
        if (unlikely(is_master_blk)) {
            /* note master_blk doesn't go in lru list */
            blk->cb_identity_flags = BLK_F_MASTER_BLK;
        } else {
            blk->end_sector = blk->start_sector + (sectors_per_block - 1);
            rnablk_cache_blk_insert(&dev->cache_blk_root, blk);
            list_add_tail(&blk->cb_dev_link, &dev->rbd_blk_list);
            atomic_set(&blk->ref_count, 1);     // a ref for being in rbtree
            atomic_inc(&dev->cache_blk_count);
            atomic_inc(&dev->cumulative_cache_blk_count);
        }
        blk->last_write_secs = seconds;
        blk->last_read_secs  = seconds;
        blk->state = RNABLK_CACHE_BLK_DISCONNECTED;
        blk->ref_type = CACHE_NO_REFERENCE;
        blk->dev_counts_state = RNABLK_CACHE_BLK_DISCONNECTED;
        blk->blk_cachedev = &null_cachedev;
        blk->cb_cachedev_id = NULL_CACHEDEV_ID;
    } else {
        rnablk_dev_release(dev);
    }

    EXITPTR(blk);
}

// Caller must hold block's lock
boolean
rnablk_state_ok_for_req(struct cache_blk *blk,
                        struct io_state  *ios)
{
    int ret = FALSE;
    
    if (likely(!rnablk_cache_blk_state_is_transitional(blk->state))) {
        if (dev_is_persistent(ios->dev)) {
            switch (ios->ios_iotype) {
            case IOS_IOTYPE_READ:
                ret = rnablk_cache_blk_state_is_readable(blk->state);
                break;

            case IOS_IOTYPE_WRITE:
            case IOS_IOTYPE_WRITE_SAME:
                ret = rnablk_cache_blk_state_is_writable(blk->state);
                break;

            case IOS_IOTYPE_COMP_WR:
                ret = RNABLK_CACHE_BLK_CONNECTED_WRITE == blk->state;
                break;

            default:
                RNABLK_BUG_ON(TRUE, "unexpected iotype [%d] ios [%p] "
                              "block [%llu]\n", ios->ios_iotype, ios,
                              blk->block_number);
				break;
            }
        } else {
            ret = rnablk_cache_blk_state_is_readable(blk->state);
        }
    }

    return (boolean)ret;
}

/*
 * Returns 1 if block state changed, 0 otherwise
 * Caller MUST hold hold block's bl_lock
 */
int
rnablk_get_blk_state_for_io(struct cache_blk *blk,
                            struct io_state *ios)
{
    ENTER;

    if (atomic_bit_is_set(&blk->cb_flags, BLK_F_DISCONN_FROZEN)) {
        /*
         * Don't kick off any I/O while blk is in the "FROZEN" state;
         * it will be taken care by the code path responsible for the freeze.
         */
        rnablk_queue_blk_io_nolock(blk, ios, QUEUE_TAIL);
    } else if (rnablk_cache_blk_state_transition(blk,
                                          RNABLK_CACHE_BLK_DISCONNECTED,
                                          RNABLK_CACHE_BLK_CONNECT_PENDING)) {

        /* need to connect to cache block */
        rnablk_set_blk_ep(blk, MD_CONN_EP_METAVALUE);
        if (unlikely(net_link_mask & RNABLK_NL_BLK_STATE)) {
            printnl_atomic("[%d] [%s:%d] device [%s] block [%"PRIu64"] [%p] "
                       "transition state [%s -> %s] state [%s] refcnt "
                       "["BLKCNTFMT"] ref [%s] dev [%p] ret [%d]\n",
                       current->pid, __FUNCTION__, __LINE__,
                       blk->dev->name, blk->block_number, blk,
                       rnablk_cache_blk_state_string(
                       RNABLK_CACHE_BLK_DISCONNECTED),
                       rnablk_cache_blk_state_string(
                       RNABLK_CACHE_BLK_CONNECT_PENDING),
                       rnablk_cache_blk_state_string(blk->state),
                       BLKCNTFMTARGS(blk),
                       get_lock_type_string(blk->ref_type),
                       blk->dev, ret);
        }
        rnablk_queue_request(RNABLK_MD_QUERY,
                             MD_CONN_EP_METAVALUE,
                             ios,
                             blk,
                             FORCE_QUEUED_IO,
                             TRUE);
        ret = 1;
    } else {
        if (dev_is_persistent(ios->dev)) {
            /* 
             * This request is checked first because it both reads and
             * writes data and requires special handling.
             */
            switch (ios->ios_iotype) {
            case IOS_IOTYPE_WRITE:
            case IOS_IOTYPE_WRITE_SAME:
                ret = rnablk_cache_blk_state_transition(blk,
                                        RNABLK_CACHE_BLK_CONNECTED_READ,
                                        RNABLK_CACHE_BLK_CHANGE_PENDING);
                break;

            case IOS_IOTYPE_READ:
                ret = rnablk_cache_blk_state_transition(blk,
                                        RNABLK_CACHE_BLK_CONNECTED_WRITE_ONLY,
                                        RNABLK_CACHE_BLK_CHANGE_PENDING);
                break;

            case IOS_IOTYPE_COMP_WR:
                ret = rnablk_cache_blk_state_transition(blk,
                                        RNABLK_CACHE_BLK_CONNECTED_WRITE_ONLY,
                                        RNABLK_CACHE_BLK_CHANGE_PENDING)
                      || rnablk_cache_blk_state_transition(blk,
                                        RNABLK_CACHE_BLK_CONNECTED_READ,
                                        RNABLK_CACHE_BLK_CHANGE_PENDING);
                break;

            default:
                RNABLK_BUG_ON(TRUE, "unexpected iotype [%d] ios [%p] block "
                              "[%llu]\n", ios->ios_iotype, ios,
                              blk->block_number);
            }
        }
        if (1 == ret) {
            if ((CACHE_WRITE_ONLY_SHARED == blk->ref_type) &&
                (0 != atomic_read(&blk->inflight_ios))) {
                /* 
                 * Hold off on queuing this request because
                 * we need to wait for RDMA to complete before
                 * changing our reference type.
                 */
                rna_printk(KERN_DEBUG, "Deferring change_ref of dev [%s] "
                           "block [%"PRIu64"] until RDMA completion ios [%p] "
                           "tag ["TAGFMT"]\n",
                           blk->dev->name, blk->block_number, ios,
                           TAGFMTARGS(ios->tag));
                rnablk_trace_ios(ios);
                atomic_bit_set(&blk->cb_flags, BLK_F_WAIT_ON_IO);

                rnablk_queue_blk_io_nolock(blk, ios, QUEUE_HEAD);
            } else {
                /* 
                 * We moved to a transitional state and need to get a different 
                 * lock reference.  Use change_ref for transitioning from existing
                 * reference to another type.
                 */
                rnablk_queue_request(RNABLK_CHANGE_REF,
                                     blk->ep,
                                     ios,
                                     blk,
                                     FORCE_QUEUED_IO,
                                     TRUE);
            }
        } else if(rnablk_cache_blk_state_is_transitional(blk->state)) {
            // if the cache blk is in transition, wait for it
            rnablk_queue_blk_io_nolock(blk, ios, QUEUE_TAIL);
        } else if (RNABLK_CACHE_BLK_INVALID == blk->state) {

            // Can't do IO to cache blks that are marked as bad.
            // Fail this IO
            TRACE(DBG_FLAG_VERBOSE, "Failing io on bad block ios [%p] tag "
                  "["TAGFMT"]\n", ios, TAGFMTARGS(ios->tag));
            rnablk_end_request(ios, -EIO);

        } else {
            RNABLK_BUG_ON(TRUE,
                       "dev [%s] blk=%p [%"PRIu64"] unexpected state [%s]\n",
                       blk->dev->name, blk,
                       blk->block_number,
                       rnablk_cache_blk_state_string(blk->state));
        }
    }
    
    EXIT;
}

static cache_lock_t
rnablk_new_state_reference(struct cache_blk *blk, int new_state) 
{
    switch (new_state) {
    case RNABLK_CACHE_BLK_CONNECTED_READ:
        return CACHE_READ_SHARED;
        break;
    case RNABLK_CACHE_BLK_CONNECTED_WRITE:
        return CACHE_WRITE_SHARED;
        break;
    case RNABLK_CACHE_BLK_CONNECTED_WRITE_ONLY:
        return CACHE_WRITE_ONLY_SHARED;
        break;
    case RNABLK_CACHE_BLK_CONNECTED_ATOMIC:
        return CACHE_ATOMIC_SHARED;
        break;
    case RNABLK_CACHE_BLK_CONNECTED_WRITE_EXCLUSIVE:
        return CACHE_WRITE_EXCLUSIVE;
        break;
    case RNABLK_CACHE_BLK_DISCONNECTED:
    case RNABLK_CACHE_BLK_INVALID:
        return CACHE_NO_REFERENCE;
        break;
    case RNABLK_CACHE_BLK_FREE:
        BUG_ON(CACHE_NO_REFERENCE != blk->ref_type);
        /* drop through */
    case RNABLK_CACHE_BLK_CHANGE_PENDING:
    case RNABLK_CACHE_BLK_CONNECT_PENDING:
    case RNABLK_CACHE_BLK_DELETE_PENDING:
    case RNABLK_CACHE_BLK_DISCONN_PENDING:
    case RNABLK_CACHE_BLK_INVALIDATE_PENDING:
        return blk->ref_type;
        break;
    default:
        rna_printk(KERN_ERR, "State [%s] has no associated ref type\n",
                   rnablk_cache_blk_state_string(new_state));
		BUG();
    }
    return CACHE_NO_REFERENCE;  /* Dummy value for compiler happiness. */
}

void rnablk_cache_blk_state_set_debug (const char       *function_string,
                                       const char       *location_string,
                                       struct cache_blk *blk,
                                       int               new_state)
{
    BUG_ON(NULL == blk);

    if (unlikely(net_link_mask & RNABLK_NL_BLK_STATE)) {
        printnl_atomic("[%d] [%s] [%s] device [%s] blk [%p] block [%"PRIu64"] "
                       "set state [%s -> %s] refcnt ["BLKCNTFMT"] dev [%p]\n",
                       current->pid, function_string, location_string,
                       blk->dev->name, blk, blk->block_number,
                       rnablk_cache_blk_state_string(blk->state),
                       rnablk_cache_blk_state_string(new_state),
                       BLKCNTFMTARGS(blk), blk->dev);

    }
    blk->state = (rnablk_cache_blk_state_t) new_state;
    blk->ref_type = rnablk_new_state_reference(blk, new_state);
}


/* caller must hold blk bl lock */
int
rnablk_cache_blk_state_transition_debug(const char       *function_string,
                                        const char       *location_string,
                                        struct cache_blk *blk,
                                        int               old_state,
                                        int               new_state)
{
    int ret = FALSE;
    unsigned long flags;

    BUG_ON(NULL == blk);

	UNREFERENCED_PARAMETER(flags);

    if (old_state == blk->state) {
        ret = 1;
        blk->state = (rnablk_cache_blk_state_t) new_state;
        blk->ref_type = rnablk_new_state_reference(blk, new_state);
    }

    if (unlikely(net_link_mask & RNABLK_NL_BLK_STATE)) {
        printnl_atomic("[%d] [%s] [%s] device [%s] blk [%p] block [%"PRIu64"] "
                       "transition state [%s -> %s] state [%s] refcnt "
                       "["BLKCNTFMT"] ref [%s] dev [%p] ret [%d]\n",
                       current->pid,
                       function_string,
                       location_string,
                       ((blk->dev != NULL) ? blk->dev->name : NULL),
                       blk, blk->block_number,
                       rnablk_cache_blk_state_string(old_state),
                       rnablk_cache_blk_state_string(new_state),
                       rnablk_cache_blk_state_string(blk->state),
                       BLKCNTFMTARGS(blk),
                       get_lock_type_string(blk->ref_type),
                       blk->dev,
                       ret);

    }
    return ret;
}

static void
rnablk_queued_deref_wf(rnablk_workq_cb_arg_t arg)
{
    struct work_struct *work = (struct work_struct *)arg;
    struct rnablk_work *w = container_of( work,struct rnablk_work,work );
    struct rnablk_queued_deref_wf_data *wd =
                                        &w->data.rwd_rnablk_queued_deref_wf;
    lockstate_t       flags;
    struct cache_blk   *blk = wd->blk;
    uint32_t            hipri = wd->hipri;
    uint64_t            start_seconds = get_seconds();

    rnablk_mempool_free(w, work_cache_info);

    rnablk_lock_blk_irqsave(blk, flags);
    atomic_bit_clear(&blk->cb_flags, BLK_F_DEREF_QUEUED);

    if (rnablk_cache_blk_unused(blk)
        || (rnablk_cache_blk_state_is_invalidate_pending(blk->state)
         && !rnablk_blk_has_dispatched_io(blk))) {
        /* block is unlocked on return */
        rnablk_cache_blk_drop_ref(blk, &flags, hipri);
        rnablk_start_blk_io(blk, FALSE);
    } else {
        rnablk_unlock_blk_irqrestore(blk, flags);
    }

    // drop blk reference acquired in rnablk_queue_deref
    rnablk_cache_blk_release(blk);
    rnablk_finish_workq_work(start_seconds);
}

void
rnablk_queue_deref(struct cache_blk *blk, boolean hipri)
{
    struct rnablk_work *w = NULL;
    struct rnablk_queued_deref_wf_data *wd = NULL;

    BUG_ON(NULL == blk);

    if (!atomic_bit_test_and_set(&blk->cb_flags, BLK_F_DEREF_QUEUED)) {
        return;
    }

    if (likely(!rnablk_dev_is_shutdown(blk->dev)) &&
        likely(!atomic_read(&shutdown))) {

        if (unlikely(NULL == (w = rnablk_mempool_alloc( work_cache_info )))) {
            rna_printk(KERN_ERR, "Failed to allocate workq item\n");
            atomic_bit_clear(&blk->cb_flags, BLK_F_DEREF_QUEUED);
        } else {
            RNABLK_INIT_RNABLK_WORK(w, wd, rnablk_queued_deref_wf);
            // released in work fn
            rnablk_cache_blk_ref(blk);
            wd->blk = blk;
            wd->hipri = hipri ? DEREF_HIPRI : 0;
            /* this task allocates an ios, so use ios_workq */
            rna_queue_work(ios_workq, &w->work);
        }

    } else {
        atomic_bit_clear(&blk->cb_flags, BLK_F_DEREF_QUEUED);
    }
}

/* Mark block as bad and drain all IOs waiting on said block */
void
rnablk_mark_cache_blk_bad_and_drain(struct cache_blk *blk,
                                    boolean mark_invalid)
{
    mutexstate_t mutex_lock_handle;

    struct rnablk_server_conn *conn = rnablk_get_ep_conn(blk->ep);
    lockstate_t flags;

    rnablk_cache_blk_ref(blk);
    if (NULL != conn && g_md_conn != conn) {
		rna_block_mutex_lock(&conn->block_list_lock, &mutex_lock_handle);
    }
    rnablk_lock_blk_irqsave(blk, flags);
    rnablk_mark_cache_blk_bad_nolock(blk, mark_invalid);
    if (NULL != conn && g_md_conn != conn) {
        rna_block_mutex_unlock(&conn->block_list_lock, &mutex_lock_handle);
    }
    rnablk_cache_blk_drain_nolock(blk, &flags);
    rnablk_unlock_blk_irqrestore(blk, flags);
    rnablk_cache_blk_release(blk);
}

INLINE void
rnablk_cache_blk_update_lru(struct cache_blk *blk, boolean is_write)
{
    struct rnablk_server_conn *conn;
    rnablk_cachedev_t *cdp;
    mutexstate_t mutex_lock_handle;

    if (NULL == blk->ep
        || MD_CONN_EP_METAVALUE == blk->ep
        || NULL == (conn = rnablk_get_blk_conn(blk))) {
        return;
    }

    rna_block_mutex_lock(&conn->block_list_lock, &mutex_lock_handle);

    if (conn == rnablk_get_blk_conn(blk)) {
        cdp = blk->blk_cachedev;
        if (!blk_lru_list_empty(&blk->cb_conn_lru)) {
            /* don't add it to the list if wasn't there to begin with! */

            blk->cb_ref_time = get_jiffies();

            blk_lru_list_move_tail(&blk->cb_conn_lru, &cdp->rcd_block_list);

			/* For linux code, this was okay with define. But in order to be compatible with windows, 
				change this to an inline function.
			conn->rsc_lru_oldest_ts = blk_lru_first_entry(&cdp->rcd_block_list,
                                       wref, cb_conn_lru, cb_conn_wref)->
                                       cb_ref_time;
			*/

			conn->rsc_lru_oldest_ts = blk_lru_first_entry(&cdp->rcd_block_list)->cb_ref_time;
			
            if (is_write) {
                blk_lru_list_move_tail(&blk->cb_conn_wref,
                                       &cdp->rcd_block_list);
                list_move_tail(&blk->cb_conn_wlru, &conn->rsc_wlru_list);
                blk->cb_write_time = blk->cb_ref_time;
                conn->rsc_wlru_oldest_ts = list_first_entry(
                                            &conn->rsc_wlru_list,
                                            struct cache_blk, cb_conn_wlru)->
                                            cb_write_time;
            }
        }
    }

    rna_block_mutex_unlock(&conn->block_list_lock, &mutex_lock_handle);
}

/* Caller holds write lock on blk->dev->cache_blk_lock */
INLINE void
rnablk_cache_blk_remove_lru_nolock(struct cache_blk *blk)
{
    //int wref;

    BUG_ON(NULL == blk);
    list_del_init(&blk->cb_dev_link);
}

struct cache_blk *
rnablk_cache_blk_find_or_create(struct rnablk_device *dev,
                                sector_t              start_sector,
                                boolean               is_write)
{
    struct cache_blk *blk = NULL;
    boolean created = FALSE;
    unsigned char oldirql = 0;

    BUG_ON(NULL == dev);

    rna_down_read(&dev->cache_blk_lock, &oldirql);

    blk = rnablk_cache_blk_search(&dev->cache_blk_root, start_sector);
    if (NULL == blk) {
        /* didn't find it, may have to create it (but recheck under lock) */
        rna_up_read(&dev->cache_blk_lock, oldirql);
        rna_down_write(&dev->cache_blk_lock, &oldirql);

        blk = rnablk_cache_blk_search(&dev->cache_blk_root, start_sector);
        if (NULL == blk) {
            blk = alloc_cache_blk(dev, start_sector, FALSE);
            created = TRUE;
        }

        if (NULL != blk) {

            rnablk_cache_blk_ref(blk);
        }
        rna_up_write(&dev->cache_blk_lock, oldirql);

    } else {
        
        rnablk_cache_blk_ref(blk);
		rna_up_read(&dev->cache_blk_lock, oldirql);
    }

    if (NULL != blk && !created) {
        rnablk_cache_blk_update_lru(blk, is_write);
    }

    return blk;
}

/* Caller must hold a read or write lock on cache_blk_lock */
static struct cache_blk *
rnablk_cache_blk_get_nolock_debug(const char           *function,
                                  const char           *location,
                                  struct rnablk_device *dev,
                                  sector_t              start_sector)
{
    struct cache_blk *blk = NULL;

    BUG_ON(NULL == dev);

    blk = rnablk_cache_blk_search(&dev->cache_blk_root, start_sector);
    if (NULL != blk) {
        rnablk_cache_blk_ref_debug(function,location,blk,NULL);
    }

    return blk;
}

struct cache_blk *
rnablk_cache_blk_get_debug(const char           *function,
                           const char           *location,
                           struct rnablk_device *dev,
                           sector_t              start_sector)
{
    struct cache_blk *blk = NULL;
    unsigned char oldirql = 0;

    BUG_ON(NULL == dev);

    rna_down_read(&dev->cache_blk_lock, &oldirql);
    blk = rnablk_cache_blk_get_nolock_debug(function, location, dev, start_sector);
    rna_up_read(&dev->cache_blk_lock, oldirql);

    return blk;
}

/*
 * Removes cache_blk from both the device rbtree, and lru lists.
 *
 * The caller must also unset the block ep (which removes the block
 * from the connection block list), and release the block.
 *
 * Caller holds write lock on dev->cache_blk_lock, a reference on the
 * block, and may hold block's spinlock
 *
 * Block must be in DELETE_PENDING state.
 */
void rnablk_cache_blk_unlink_nolock(struct cache_blk *blk)
{
    BUG_ON(NULL == blk);
    BUG_ON(NULL == blk->dev);
    BUG_ON(!list_empty( &blk->bl ));
    BUG_ON(!list_empty( &blk->dispatch_queue ));

    if (unlikely(net_link_mask & RNABLK_NL_BLK_STATE)) {
        printnl_atomic("unlinking device [%s] blk [%p] block [%"PRIu64"] "
                       "refcnt ["BLKCNTFMT"]\n", blk->dev->name,
                       blk, blk->block_number,
                       BLKCNTFMTARGS(blk));
    }
    if (unlikely(RNABLK_CACHE_BLK_DELETE_PENDING != blk->state)) {
        rna_printk(KERN_ERR,
                   "[%s] block [%"PRIu64"] unlinked in state [%s]\n",
                   blk->dev->name,
                   blk->block_number,
                   rnablk_cache_blk_state_string(blk->state));
        dump_stack();
    }
    rnablk_cache_blk_remove_lru_nolock(blk);
    rnablk_cache_blk_remove(&blk->dev->cache_blk_root, blk);
}

// Call rnablk_cache_blk_unlink_nolock first to remove from tree and lru list
void
rnablk_cache_blk_free (struct cache_blk *blk)
{
    BUG_ON(NULL == blk);
    BUG_ON(NULL == blk->dev);

#ifndef WINDOWS_KERNEL
    /* can't hold lock inside object we are freeing */
    RNABLK_BUG_ON_BLK(spin_is_locked(&blk->bl_lock.lock), blk);
#endif /*WINDOWS_KERNEL*/

    if (unlikely(net_link_mask & RNABLK_NL_BLK_STATE)) {
        printnl_atomic("freeing device [%s] blk [%p] block [%"PRIu64"] "
                       "refcnt ["BLKCNTFMT"]\n", blk->dev->name,
                       blk, blk->block_number,
                       BLKCNTFMTARGS(blk));
    }
    RNABLK_BUG_ON(unlikely(0 != atomic_read(&blk->ref_count)
                           || 0 != atomic_read(&blk->cb_ioref_cnt)),
                  "[%s] blk [%p] block [%"PRIu64"] freed with outstanding "
                  "references refcnt ["BLKCNTFMT"]\n", blk->dev->name, blk,
                  blk->block_number, BLKCNTFMTARGS(blk));
    if (unlikely(RNABLK_CACHE_BLK_FREE != blk->state)) {
        rna_printk(KERN_ERR,
                   "not freeing [%s] block [%"PRIu64"] in state [%s]\n",
                   blk->dev->name,
                   blk->block_number,
                   rnablk_cache_blk_state_string(blk->state));
    } else {
        if (!rnablk_dev_is_shutdown(blk->dev)) {
            RNABLK_BUG_ON_BLK(!list_empty(&blk->bl), blk);
            RNABLK_BUG_ON_BLK(!blk_lru_list_empty(&blk->cb_conn_lru), blk);
            RNABLK_BUG_ON_BLK(!list_empty(&blk->dispatch_queue), blk);
            RNABLK_BUG_ON_BLK(0 != atomic_read(&blk->inflight_ios), blk);
            RNABLK_BUG_ON_BLK(0 != atomic_read(&blk->cb_ioref_cnt), blk);
        }

        if (!IS_MASTER_BLK(blk)) {
            atomic_dec(&blk->dev->cache_blk_count);
        }
        rnablk_dev_release(blk->dev);
        rnablk_mempool_free(blk, blk_cache_info);
    }
}

void
rnablk_cache_blk_ref_debug(const char       *function,
                           const char       *location,
                           struct cache_blk *blk,
                           struct io_state  *ios)
{
    atomic_inc(&blk->ref_count);
    if (unlikely(net_link_mask & RNABLK_NL_BLK_STATE)) {
            printnl_atomic("blk_ref [%d] [%s] [%s] [%p] [%s] block [%llu] "
                           "state [%s] refcnt ["BLKCNTFMT"] ios [%p] tag "
                           "["TAGFMT"]\n",
                           current->pid, function, location,
                           blk, blk->dev->name, blk->block_number,
                           rnablk_cache_blk_state_string(blk->state),
                           BLKCNTFMTARGS(blk), ios,
                           ((NULL != ios) ? TAGFMTARGS(ios->tag) : 0));
    }
}

void
rnablk_cache_blk_ioref_debug(const char       *function,
                             const char       *location,
                             struct cache_blk *blk,
                             struct io_state  *ios)
{
    /* bump both refcnts */
    rnablk_cache_blk_ref_debug(function, location, blk, ios);
    atomic_inc(&blk->cb_ioref_cnt);
}

/**
 * Releases a reference on a cache_blk, and frees it if this is the last
 * reference.
 *
 * Caller may hold block's bl_lock as long as it can guarantee it isn't
 * releasing the last reference to the block.  Normally callers do not hold
 * the block's bl_lock here.
 *
 * The release done when unsetting the block's ep has to be done while the
 * block's bl_lock is held.  In that case a reference on the block is also held.
 */
void
rnablk_cache_blk_release_debug(const char       *function,
                               const char       *location,
                               struct cache_blk *blk,
                               struct io_state  *ios)
{
    lockstate_t flags;

    BUG_ON(NULL == blk);
    BUG_ON(NULL == blk->dev);

    RNABLK_BUG_ON((boolean)rnablk_cache_blk_state_is_bogus(blk->state),
                  "blk_release of block in bogus state [%d] [%s] [%s] [%p] "
                  "[%s] block [%llu] state [%s] refcnt ["BLKCNTFMT"] ios [%p] "
                  "tag ["TAGFMT"]\n",
                   PROCESS_ID, function, location, blk, blk->dev->name,
                   blk->block_number, rnablk_cache_blk_state_string(blk->state),
                   BLKCNTFMTARGS(blk), ios,
                   ((NULL != ios) ? TAGFMTARGS(ios->tag) : 0));

    RNABLK_BUG_ON(atomic_read(&blk->ref_count) <= 0,
                  "[%s] block [%"PRIu64"] invalid refcnt ["BLKCNTFMT"]\n",
                  blk->dev->name, blk->block_number,
                  BLKCNTFMTARGS(blk));

    if (unlikely(net_link_mask & RNABLK_NL_BLK_STATE)) {
            printnl_atomic("blk_release [%d] [%s] [%s] [%p] [%s] block [%llu] "
                           "state [%s] refcnt ["BLKCNTFMT"] ios [%p] tag "
                           "["TAGFMT"]\n", current->pid, function, location,
                           blk, blk->dev->name, blk->block_number,
                           rnablk_cache_blk_state_string(blk->state),
                           BLKCNTFMTARGS(blk),
                           ios, ((NULL != ios) ? TAGFMTARGS(ios->tag) : 0));
    }

    /*
     * The following tests are done without the blk lock, so they aren't
     * "safe" tests.  However, the queued function will acquire the lock
     * and do all the necessary checks before taking any action, so worst
     * case is we queue unnecessarily.
     */
    if (RNABLK_CACHE_BLK_DISCONNECTED == blk->state
        && 2 == atomic_read(&blk->ref_count) && !IS_MASTER_BLK(blk)) {
        /*
         * At this moment, the only reference remaining besides this one is
         * the rbtree reference.  Queue for deletion.
         */
        rnablk_queue_delete(blk);
    } else if (rnablk_cache_blk_state_is_invalidate_pending(blk->state)
               && !rnablk_blk_has_dispatched_io(blk)) {
        rna_printk(KERN_INFO,
                   "[%s] block [%"PRIu64"] state [%s] refcnt ["BLKCNTFMT"] "
                   "inflight_ios [%d] dispatch queue [%s]\n",
                   blk->dev->name,
                   blk->block_number,
                   rnablk_cache_blk_state_string(blk->state),
                   BLKCNTFMTARGS(blk),
                   atomic_read(&blk->inflight_ios),
                   list_empty(&blk->dispatch_queue)?"empty":"nonempty");
        rnablk_queue_deref(blk, FALSE);
    }

    if (unlikely(0 == atomic_dec_return(&blk->ref_count))) {
        /* See locking notes above */
        RNABLK_BUG_ON(0 != atomic_read(&blk->cb_ioref_cnt), "blk [%p] "
                      "block [%llu] refcnt ["BLKCNTFMT"] refcnts out of sync\n",
                      blk, blk->block_number, BLKCNTFMTARGS(blk));

        rnablk_lock_blk_irqsave(blk, flags);
        if (rnablk_cache_blk_state_transition(blk,
                                            RNABLK_CACHE_BLK_DELETE_PENDING,
                                            RNABLK_CACHE_BLK_FREE)) {
            /* need to unlock block before deleting it. */
            rnablk_unlock_blk_irqrestore(blk, flags);
            if (!rnablk_dev_is_shutdown(blk->dev)) {
                RNABLK_BUG_ON(!blk_lru_list_empty(&blk->cb_conn_lru)
                              || !blk_lru_list_empty(&blk->cb_conn_wref),
                              "blk_release [%d] [%s] [%s] blk [%p] "
                              "[%s] block [%llu] state [%s] refcnt "
                              "["BLKCNTFMT"] ios [%p] tag ["TAGFMT"]\n",
                              PROCESS_ID,
                              function, location, blk, blk->dev->name,
                              blk->block_number,
                              rnablk_cache_blk_state_string(blk->state),
                              BLKCNTFMTARGS(blk), ios,
                              ((NULL != ios) ? TAGFMTARGS(ios->tag) : 0));
            }
            rnablk_cache_blk_free(blk);
        } else if (IS_MASTER_BLK(blk)
                   && rnablk_cache_blk_state_transition(blk,
                                            RNABLK_CACHE_BLK_DISCONNECTED,
                                            RNABLK_CACHE_BLK_FREE)) {
            /* need to unlock block before deleting it. */
            rnablk_unlock_blk_irqrestore(blk, flags);
            rnablk_cache_blk_free(blk);
        } else {
            rna_printk(KERN_ERR, "unexpected blk state blk [%p] [%s] "
                       "block [%llu] state [%s] refcnt ["BLKCNTFMT"] "
                       "ios [%p] tag ["TAGFMT"]\n",
                       blk, blk->dev->name, blk->block_number,
                       rnablk_cache_blk_state_string(blk->state),
                       BLKCNTFMTARGS(blk), ios,
                       ((NULL != ios) ? TAGFMTARGS(ios->tag) : 0));
            rnablk_unlock_blk_irqrestore(blk, flags);
        }
    }
}

/**
 * Releases an io reference on a cache_blk.
 * (This could potentially free the block if this is the last reference).
 */
void
rnablk_cache_blk_iorel_debug(const char       *function,
                             const char       *location,
                             struct cache_blk *blk,
                             struct io_state  *ios)
{
    RNABLK_BUG_ON(atomic_dec_return(&blk->cb_ioref_cnt) < 0,
                  "[%s] block [%"PRIu64"] invalid refcnt ["BLKCNTFMT"]\n",
                   blk->dev->name, blk->block_number,
                   BLKCNTFMTARGS(blk));
    rnablk_cache_blk_release_debug(function, location, blk, ios);
}

/*
 * rnablk_mark_cache_blk_bad_nolock
 *    Note 'mark_invalid' should be FALSE in the case where the client
 *    holds a valid reference on the block.  We need to keep our state
 *    in sync with the cache server, since it knows about our reference.
 *    That way, if the device gets reactivated after the failure, we're
 *    still in sync and can carry on as normal for this block.
 *    (Since we mark the device as failed here, all I/O to the blk will still
 *    be failed, which is what we want).
 *
 * Caller must hold blk's bl_lock & corresponding conn block_list_lock
 */
void
rnablk_mark_cache_blk_bad_nolock(struct cache_blk *blk, boolean mark_invalid)
{
#ifdef RNA_DEBUG
    struct rnablk_server_conn *conn = rnablk_get_ep_conn(blk->ep);
#endif

#ifndef WINDOWS_KERNEL
    RNABLK_BUG_ON_BLK(!spin_is_locked(&blk->bl_lock.lock), blk);
#endif /*WINDOWS_KERNEL*/
    RNABLK_DBG_BUG_ON(NULL != conn && g_md_conn != conn
                      && !rna_block_mutex_is_locked(&conn->block_list_lock),
                      "blk [%p] block [%llu] conn ["CONNFMT"] block_list_lock "
                      "not held!\n", blk, blk->block_number, CONNFMTARGS(conn));

    if (mark_invalid && RNABLK_CACHE_BLK_INVALID != blk->state) {
        blk->dev->stats.failed_blocks++;
        rnablk_unset_blk_ep(blk);
        rnablk_cache_blk_state_set(blk, RNABLK_CACHE_BLK_INVALID);
    }
    rnablk_cache_blk_update_dev_counts(blk);
    (void)rnablk_device_fail(blk->dev);
}

int
rnablk_submit_change_ref(struct io_state *ios,
                         cache_lock_t orig_ref,
                         cache_lock_t desired_ref,
                         uint32_t flags)
{
    struct com_ep *ep;
    struct cache_blk *blk = ios->blk;
    lockstate_t irqflags;
    int ret = 0;
    struct sockaddr_in dst_in;

    rnablk_lock_blk_irqsave(blk, irqflags);
    ep = blk->ep;

    if (likely((NULL != ep) && (MD_CONN_EP_METAVALUE != ep))) {
        rnablk_set_ios_ep(ios, ep);
        
        dst_in = get_dest_sockaddr_from_ep(ep);

        TRACE(DBG_FLAG_VERBOSE,
              "changing ref on dev [%s] block [%llu] on server "NIPQUAD_FMT
              " tag ["TAGFMT"] cookie [0x%"PRIx64"]\n",
              blk->dev->cache_file_name,
              blk->block_number, NIPQUAD(dst_in.sin_addr.s_addr ),
              TAGFMTARGS(ios->tag), blk->rid);
        rnablk_create_change_ref_cmd(ios->cmd, ios, blk->rid, blk,
                                     orig_ref, desired_ref, flags);
        if (unlikely(0 != atomic_read(&blk->inflight_ios)
                     && (blk->ref_type == CACHE_WRITE_ONLY_SHARED
                         || desired_ref == CACHE_ATOMIC_SHARED))) {
            rna_printk(KERN_DEBUG, "Deferring change_ref of dev [%s] block "
                       "[%"PRId64"] ref [%s] desired ref [%s] until "
                       "I/O completion\n",
                       blk->dev->name, blk->block_number,
                       get_lock_type_string(blk->ref_type),
                       get_lock_type_string(desired_ref));
            atomic_bit_set(&blk->cb_flags, BLK_F_WAIT_ON_IO);
            rnablk_queue_blk_io_nolock(blk, ios, QUEUE_HEAD);
        } else {
            ret = queue_command(ios);
            if (unlikely(ret)) {
                dst_in = get_dest_sockaddr_from_ep(ep);
                rna_printk(KERN_ERR,
                           "unable to change_ref cache block [%s:%"PRIu64
                           "] on server ["NIPQUAD_FMT"]\n",
                           blk->dev->cache_file_name, blk->block_number,
                           NIPQUAD(dst_in.sin_addr.s_addr ) );
            }
        }
    } else {
        ret = 1;
    }
    rnablk_unlock_blk_irqrestore(blk, irqflags);
    return ret;
}

int
rnablk_send_master_change_ref(struct rnablk_device *dev,
                              struct request *req,
                              enum rnablk_op_type type,
                              cache_lock_t desired_ref)
{
    struct cache_blk *blk;
    struct io_state *ios;
    rnablk_cache_blk_state_t orig_state;
    lockstate_t flags;
    struct rnablk_server_conn *conn;
    cache_lock_t orig_ref;
    int ret = 0;
    mutexstate_t mutex_lock_handle;

    BUG_ON(NULL == dev);

    blk = MASTER_BLK(dev);
    rnablk_trc_master(1, "start: blk [%p] type [%s] ref [%s] refcnt "
                      "["BLKCNTFMT"]\n", blk,
                      rnablk_op_type_string(type),
                      get_lock_type_string(blk->ref_type),
                      BLKCNTFMTARGS(blk));

    ret = rnablk_alloc_ios(dev, req, req ? IOREQ_TYPE_REQ : IOREQ_TYPE_NOREQ,
                           RSV_ACC_NONE, FALSE, TRUE, 1, &ios);

	if (unlikely(0 != ret)) {
        return ret;
    }

    ios->start_sector = -1;
    ios->type = type;

	rnablk_lock_blk_irqsave(blk, flags);
    orig_state = blk->state;
    /*
     * Note our 'ref_type' says WRITE_SHARED, but it may not match the
     * cache server's view of it (if there's an active SCSI reservation
     * in place).  Currently the cache server complains but otherwise handles
     * it...this path is dependent on that behavior!
     */
    orig_ref = blk->ref_type;

    rnablk_set_ios_blk(ios, blk);

    switch (type) {
    case RNABLK_MASTER_DEREF_NORESP:
        rnablk_cache_blk_state_set(blk, RNABLK_CACHE_BLK_DISCONNECTED);
        break;

    default:
        RNABLK_BUG_ON(TRUE, "Unsupported master block command: %d\n", type);
        break;
    }

    rnablk_unlock_blk_irqrestore(blk, flags);

    ret = rnablk_submit_change_ref(ios, orig_ref, desired_ref,  DEREF_NO_RESP);

    rnablk_trc_master(ret != 0, "submit error=%d\n", ret);

    if (0 == ret && RNABLK_MASTER_DEREF_NORESP == type) {
        conn = rnablk_get_ep_conn(blk->ep);
        if (NULL != conn) {
            rna_block_mutex_lock(&conn->block_list_lock, &mutex_lock_handle);
        }
        rnablk_lock_blk_irqsave(blk, flags);
        rnablk_unset_blk_ep(blk);
        rnablk_unlock_blk_irqrestore(blk, flags);
        if (NULL != conn) {
            rna_block_mutex_unlock(&conn->block_list_lock, &mutex_lock_handle);
        }
    }

    if (unlikely(0 != ret)) {
        rnablk_lock_blk_irqsave(blk, flags);
        rnablk_cache_blk_state_set(blk, orig_state);
        rnablk_ios_finish(ios);
        rnablk_unlock_blk_irqrestore(blk, flags);
    }

    rnablk_trc_master(ret != 0, "error=%d\n", ret);
    return ret;
}

// Caller must already have dereferenced all cache blocks
int
rnablk_master_blk_send_deref(struct rnablk_device *dev)
{
    ENTER;

    rnablk_trc_master(1, "start\n");

    ret = rnablk_send_master_change_ref(dev, NULL, RNABLK_MASTER_DEREF_NORESP,
                                        CACHE_NO_REFERENCE);

    if (unlikely(0 != ret)) {
        rna_printk(KERN_ERR, "rnablk_send_deref for [%s] master block failed "
                   "[%d]\n", dev->cache_file_name, ret);
    }
    rnablk_trc_master(1, "done - ret=%d\n", ret);
    EXIT;
}



/*
 * rnablk_cache_blk_drop_ref
 *  Calling semantics are that block's bl_lock must be held on entry,
 *  but will be unlocked by this return prior to return...
 *
 * Caller must call rnablk_next_request() if they want query to be dispatched
 *
 * Returns 0 if we successfully send a CHANGE_REF for this block,
 * otherwise returns non-zero.
 */
int
rnablk_cache_blk_drop_ref(struct cache_blk *blk, lockstate_t * irqflags,
                          uint32_t flags)
{
    int                        ret  = 0;
    rnablk_cache_blk_state_t   save_state = RNABLK_CACHE_BLK_INVALID;
    struct rnablk_server_conn *conn = NULL;
    mutexstate_t               mutex_lock_handle;

    BUG_ON(NULL == blk);
#ifndef WINDOWS_KERNEL
    RNABLK_BUG_ON_BLK(!spin_is_locked(&blk->bl_lock.lock), blk);
#endif /*WINDOWS_KERNEL*/
    save_state = blk->state;

    if (unlikely((NULL == blk->ep) || (MD_CONN_EP_METAVALUE == blk->ep))) {
        rna_printk(KERN_ERR,
                   "deref not sent for [%s] block [%"PRIu64"] in state [%s] with [%s] EP\n",
                   blk->dev?blk->dev->cache_file_name:"<unknown>",
                   blk->block_number,
                   rnablk_cache_blk_state_string(blk->state),
                   (MD_CONN_EP_METAVALUE == blk->ep) ? "MD" : "NULL");
    } else {
        conn = rnablk_get_blk_conn(blk);

        if (unlikely(NULL == conn)) {
            rna_printk(KERN_ERR,
                       "deref not sent ep null context for [%s] block [%"PRIu64"]\n",
                       blk->dev ? blk->dev->name : "NULL",
                       blk->block_number);
            dump_stack();
        } else if (unlikely(!rnablk_conn_connected(conn))) {
            rna_printk(KERN_INFO,
                       "deref not sent to disconnected CS ["rna_service_id_format"] for [%s] block [%"PRIu64"] conn ["CONNFMT"] blk=%p\n",
                       rna_service_id_get_string(&conn->id),
                       blk->dev ? blk->dev->name : "NULL",
                       blk->block_number,
                       CONNFMTARGS(conn), blk);
            //dump_stack();
            rnablk_unlock_blk_irqrestore(blk, *irqflags);
            rna_block_mutex_lock(&conn->block_list_lock, &mutex_lock_handle);
            rnablk_lock_blk_irqsave(blk, *irqflags);
            rnablk_cache_blk_state_set(blk, RNABLK_CACHE_BLK_DISCONNECTED);
            rnablk_unset_blk_ep(blk);
            rnablk_cache_blk_update_dev_counts(blk);
            rna_block_mutex_unlock(&conn->block_list_lock, &mutex_lock_handle);
            ret = -1;
        } else if (likely(rnablk_cache_blk_state_is_droppable(blk->state))) {
            rnablk_cache_blk_state_set(blk, RNABLK_CACHE_BLK_DISCONN_PENDING);
            // temporarily inc within lock; send_change_ref will do real inc
            rnablk_cache_blk_ioref(blk, NULL);
            rnablk_unlock_blk_irqrestore(blk, *irqflags);

            ret = rnablk_cache_blk_send_change_ref(blk, CACHE_NO_REFERENCE,
                                                   flags);
            rnablk_lock_blk_irqsave(blk, *irqflags);
            rnablk_cache_blk_iorel(blk, NULL);

            if (unlikely(ret)) {
                /* revert state */
                rna_printk(KERN_ERR,
                           "failed to send deref for [%s] block [%"PRIu64"]\n",
                           blk->dev ? blk->dev->cache_file_name : "<unknown>",
                           blk->block_number);
                /*
                 * Restore blk state only if it hasn't changed out from under
                 * us (which could have happened due to a CS disconnect or
                 * a cache-device failure).
                 */
                if (rnablk_cache_blk_state_transition(blk,
                                            RNABLK_CACHE_BLK_DISCONN_PENDING,
                                            save_state)) {
                    /*
                     * we just left a transitional state, so need to
                     * check to see if I/Os got queued in the interim.
                     */
                    rnablk_cache_blk_drain_nolock(blk, irqflags);
                }
            } else {
                rnablk_cache_blk_update_dev_counts(blk);
                rna_printk(KERN_DEBUG,
                           "[%s] block [%"PRIu64"] state [%s]\n",
                           blk->dev ? blk->dev->cache_file_name : "<unknown>",
                           blk->block_number,
                           rnablk_cache_blk_state_string(blk->state));
            }
        } else if (!rnablk_cache_blk_state_is_disconnected(blk->state)) {
            rna_printk(KERN_ERR,
                       "deref not sent for [%s] block [%"PRIu64"] in unexpected state [%s]\n",
                       blk->dev ? blk->dev->cache_file_name : "<unknown>",
                       blk->block_number,
                       rnablk_cache_blk_state_string(blk->state));
            ret = -1;
        }
    }

    rnablk_unlock_blk_irqrestore(blk, *irqflags);
    return ret;
}

void
rnablk_deref_cache_blks( struct rnablk_device *dev )
{
    struct list_head *pos, *tmp;
    struct cache_blk *blk;
    lockstate_t flags;
    struct cache_blk marker_blk;
    unsigned char oldirql = 0;
    int ret;

    marker_blk.cb_identity_flags = BLK_F_MARKER_BLK;

    rna_down_write(&dev->cache_blk_lock, &oldirql);
    list_for_each_safe(pos, tmp, &dev->rbd_blk_list) {
        blk = list_entry(pos, struct cache_blk, cb_dev_link);
        if (unlikely(IS_MARKER_BLK(blk))) {
            continue;
        }
        
        rnablk_cache_blk_ref(blk);

        list_add(&marker_blk.cb_dev_link, pos);
        rna_up_write(&dev->cache_blk_lock, oldirql);

        rnablk_lock_blk_irqsave(blk, flags);
        if (!rnablk_cache_blk_state_is_disconnected(blk->state) &&
            !rnablk_cache_blk_state_is_unreferenced(blk->state)) {

            /* block is unlocked on return... */
            ret = rnablk_cache_blk_drop_ref(blk, &flags, DEREF_NO_RESP);
            if (0 == ret) {
                rnablk_start_blk_io(blk, FALSE);
            }

        } else {
            rnablk_unlock_blk_irqrestore(blk, flags);
        }

        rna_down_write(&dev->cache_blk_lock, &oldirql);
        rnablk_cache_blk_release(blk);
#ifdef WINDOWS_KERNEL
        tmp = marker_blk.cb_dev_link.Flink;
#else
        tmp = marker_blk.cb_dev_link.next;
#endif /*WINDOWS_KERNEL*/
        list_del(&marker_blk.cb_dev_link);
    }
    rna_up_write( &dev->cache_blk_lock, oldirql );

    return;
}

/*
 * XXX: All these call-backs seem a bit overwrought.  Should
 *      come back to this later...
 */

/* 
 * Returns TRUE if block is successfully dereferenced.
 */
boolean
rnablk_try_deref_cache_blk(struct cache_blk *blk)
{
    lockstate_t irqflags;
    int ret = -1;
    struct sockaddr_in dst_in;

    rnablk_cache_blk_ref(blk);
    rnablk_lock_blk_irqsave(blk, irqflags);

    if (rnablk_can_deref_cache_blk(blk)) {
        dst_in = get_dest_sockaddr_from_ep(blk->ep);

        TRACE(DBG_FLAG_VERBOSE,
              "derefing dev [%s] block [%"PRIu64"] [%s] last read [%"PRIu64"] "
              "from cache ["NIPQUAD_FMT"]\n",
              blk->dev->name,
              blk->block_number,
              rnablk_cache_blk_state_string(blk->state),
              blk->last_read_secs,
              NIPQUAD(dst_in.sin_addr.s_addr));

        /* block is unlocked on return... */
        ret = rnablk_cache_blk_drop_ref(blk, &irqflags, 0);
    } else {
        rnablk_trc_master(1, "can't deref: blk [%p] block [%"PRIu64"] state "
                          "[%s] infl=%d blempty=%d dispempty=%d "
                          "refcnt ["BLKCNTFMT"] ep=%p (master=%d)\n",
                          blk, blk->block_number,
                          rnablk_cache_blk_state_string(blk->state),
                          atomic_read(&blk->inflight_ios),
                          list_empty(&blk->bl),
                          list_empty(&blk->dispatch_queue),
                          BLKCNTFMTARGS(blk),
                          blk->ep, IS_MASTER_BLK(blk));
        rnablk_unlock_blk_irqrestore(blk, irqflags);
    }
    
    rnablk_cache_blk_release(blk);
    return (ret == 0);
}

/* 
 * Returns 1 if block either:
 * - Transitions from WRITE_SHARED -> READ_SHARED
 * - Transitions from WRITE_ONLY_SHARED -> NO_REFERENCE (dropped)
 * - Is in WRITE_ONLY_SHARED or ATOMIC
 *
 * Caller must call rnablk_start_blk_io() or the equivalent on this block to 
 * ensure commands queued here are dispatched.
 *
 * Returns TRUE if we successfully instigate a downgrade or deref, otherwise
 * FALSE.
 */
boolean
rnablk_try_downgrade_cache_blk(struct cache_blk *blk)
{
    lockstate_t irqflags;
    int ret = -1;
    struct sockaddr_in dst_in;

    rnablk_lock_blk_irqsave(blk, irqflags);

    if ((RNABLK_CACHE_BLK_CONNECTED_WRITE == blk->state) &&
        (0 == atomic_read(&blk->cb_ioref_cnt))) {

        // TODO: check dispatched IO list?

        dst_in = get_dest_sockaddr_from_ep(blk->ep);

        TRACE(DBG_FLAG_VERBOSE,
              "downgrading dev [%s] block [%llu] [%s] from cache ["NIPQUAD_FMT"]\n",
              blk->dev->name,
              blk->block_number,
              rnablk_cache_blk_state_string(blk->state),
              NIPQUAD(dst_in.sin_addr.s_addr));

        /* block is unlocked on return... */
        ret = rnablk_cache_blk_make_read_shared(blk, &irqflags);
    } else if ((RNABLK_CACHE_BLK_CONNECTED_WRITE_ONLY == blk->state) &&
               (0 == atomic_read(&blk->cb_ioref_cnt))) {

        /* block is unlocked on return... */
        ret = rnablk_cache_blk_drop_ref(blk, &irqflags, 0);
    } else if ((RNABLK_CACHE_BLK_CONNECTED_ATOMIC == blk->state) &&
               (0 == atomic_read(&blk->cb_ioref_cnt))) {

        /* block is unlocked on return... */
        ret = rnablk_cache_blk_drop_ref(blk, &irqflags, 0);
    } else {
        rnablk_unlock_blk_irqrestore(blk, irqflags);
    }

    return (ret == 0);
}

#define RNABLK_DEREF_TRAVERSAL_LIMIT_NS (1 * NSEC_PER_MSEC)
static void
rnablk_deref_conn_blks(struct com_ep     *cache_ep,
                       cachedev_id_t      cachedev_id,
                       uint64_t           mem_count,
                       boolean            is_from_cs)
{
    struct rnablk_server_conn *conn;
    rnablk_cachedev_t         *cachedev;
    struct cache_blk          *blk;
    struct blk_lru_list       *pos, *tmp;
    uint64_t                   released_bytes = 0;
    int                        released_blocks = 0;
    int                        viewed_blocks = 0;
    uint64_t                   traversal_start_ns;
    uint64_t                   old_list_lock_ns;
    uint64_t                   new_list_lock_ns;
    struct cache_blk           marker;
    int                        is_wref;
    boolean                    ok;
    mutexstate_t               mutex_lock_handle;

    conn = (struct rnablk_server_conn *)(com_get_ep_context(cache_ep));
    BUG_ON(NULL == conn);
    rnablk_trc_master(1, "start: conn ["CONNFMT"] cachedev [%#"PRIx64"] "
                   "memcnt=%llu\n", CONNFMTARGS(conn), cachedev_id, mem_count);

    marker.cb_identity_flags = BLK_F_MARKER_BLK;
    blk_lru_list_init(&marker.cb_conn_lru, 0);

    /*
     * The cache-server currently doesn't distinguish between device
     * connections and the primary parent connection.  Thus it will
     * send DEREF requests for each, and more importantly, will divide
     * the amount of space it needs by the number of connections.
     * The problem with this is, block associations are essentially based only
     * on the primary connection (well, actually they're per-cachedev,
     * but still managed/locked via the primary conn).
     * So the solution for now is to simply always do the DEREF
     * on the parent connection.  (This should all balance out in the end
     * if each deref request is for a fraction of the total desired, since
     * after they all get processed, we will have deref'ed the total
     * desired amount from the parent).
     */
    conn = conn->rsc_parent_conn;
    
    cachedev = rnablk_get_conn_cachedev(conn, cachedev_id, FALSE);
    if (NULL == cachedev) {
        rna_printk(KERN_INFO, "conn ["CONNFMT"]: no cachedev [%#"PRIx64"] "
                   "found, no deref done\n", CONNFMTARGS(conn), cachedev_id);
        goto done;
    }

    traversal_start_ns = getrawmonotonic_ns();

    rna_block_mutex_lock(&conn->block_list_lock, &mutex_lock_handle);

    old_list_lock_ns = rna_atomic64_read(&conn->max_block_list_lock_ns);
    new_list_lock_ns = getrawmonotonic_ns() - traversal_start_ns;
    if (new_list_lock_ns > old_list_lock_ns) {
        rna_atomic64_set(&conn->max_block_list_lock_ns, new_list_lock_ns);
        rna_printk(KERN_NOTICE, "Acquiring conn->block_list_lock during deref "
                   "took [%"PRIu64"nS]\n", new_list_lock_ns);
    }
    traversal_start_ns = getrawmonotonic_ns();
    blk_lru_list_for_each_safe(pos, tmp, &cachedev->rcd_block_list) {
        if (unlikely(!com_connected(cache_ep)
                     || atomic_read(&rna_service_detached)
                     || atomic_read(&shutdown))) {
            break;
        }

        if ((getrawmonotonic_ns() - traversal_start_ns) 
             > RNABLK_DEREF_TRAVERSAL_LIMIT_NS) {
            if (1 == rna_atomic64_inc_return(&conn->deref_walk_timeouts)) {
                rna_printk(KERN_NOTICE, "List walk during deref exceeded "
                           "[%"PRIu64"mS] at least once\n",
                           (uint64_t)RNABLK_DEREF_TRAVERSAL_LIMIT_NS
                           / (uint64_t)NSEC_PER_MSEC);
            }
        }
        /* Skip this deref request if there's an IOS timeout queued (probably behind this) */
        if (atomic_bit_is_set(&conn->rsc_flags, RSC_F_IOS_TMO_DEFERRED)) {
            break;
        }
        if (released_blocks >= max_wr) {
            break;
        }

        blk = blk_lru_entry(pos, &is_wref);
        if (unlikely(IS_MARKER_BLK(blk) || IS_MASTER_BLK(blk))) {
            continue;
        }
        viewed_blocks++;
        ok = is_wref ? rnablk_can_downgrade_cache_blk(blk)
                     : rnablk_can_deref_cache_blk(blk);

        if (ok) {
            rnablk_cache_blk_ref(blk);
            blk_lru_list_add(&marker.cb_conn_lru, pos);
            rna_block_mutex_unlock(&conn->block_list_lock, &mutex_lock_handle);

            ok = is_wref ? rnablk_try_downgrade_cache_blk(blk)
                         : rnablk_try_deref_cache_blk(blk);

            if (ok) {
                rnablk_trc_master(1, "successful %s of blk=%p [%"PRIu64"] "
                                  "state [%s]\n",
                                  is_wref ? "downgrade" : "deref",
                                  blk, blk->block_number,
                                  rnablk_cache_blk_state_string(blk->state));
                released_bytes += blk->dev->cache_blk_size;
                if (is_wref) {
                    blk->dev->stats.anon_downgraded_blocks++;
                } else {
                    blk->dev->stats.anon_ref_dropped_blocks++;
                }
                released_blocks++;

                rnablk_next_request(conn);
            } else {
                rnablk_trc_master(1, "1 couldn't %s blk=%p [%"PRIu64"] "
                              "state [%s] ioref=%d ep [%p]\n",
                              is_wref ? "downgrade" : "deref", blk,
                              blk->block_number,
                              rnablk_cache_blk_state_string(blk->state),
                              atomic_read(&blk->cb_ioref_cnt), blk->ep);
            }
            rnablk_cache_blk_release(blk);
            rna_block_mutex_lock(&conn->block_list_lock, &mutex_lock_handle);
            tmp = _LRU_GET_ENT_PTR(marker.cb_conn_lru.blru_next);
            blk_lru_del_init(&marker.cb_conn_lru);

            if (released_bytes >= mem_count) {
                break;
            }
        } else {
            rnablk_trc_master(1, "2 couldn't %s blk=%p [%"PRIu64"] state [%s] "
                              "ioref=%d ep [%p]\n",
                              is_wref ? "downgrade" : "deref", blk,
                              blk->block_number,
                              rnablk_cache_blk_state_string(blk->state),
                              atomic_read(&blk->cb_ioref_cnt), blk->ep);
        }
    }
    rna_block_mutex_unlock(&conn->block_list_lock, &mutex_lock_handle);
    rnablk_put_cachedev(cachedev);
    rna_printk(KERN_INFO,
               "released [%d/%d] blocks [%llu/%llu] bytes for cachedev "
               "[%"PRIx64"]\n",
               released_blocks,
               viewed_blocks,
               released_bytes,
               mem_count,
               cachedev_id);

 done:
    /*
     * Note if 'is_from_cs' is FALSE, then this DEREF request was injected
     * for testing purposes via sysfs.  In which case, the CS knows nothing
     * about it and isn't expecting a DEREF response.
     */
    if (is_from_cs && com_connected(cache_ep)) {
        rnablk_send_deref_complete(cache_ep, (uint32_t)mem_count,
                                   (uint32_t)released_bytes);
    }

    if (0 == released_bytes) {
        rna_printk(KERN_INFO,
                   "Failed to release any of [%llu] bytes requested\n",
                   mem_count);
    }
    rnablk_trc_master(1, "done\n");
}

INLINE void
rnablk_drop_references(rnablk_workq_cb_arg_t arg)
{
    struct work_struct *work = (struct work_struct *)arg;
    struct rnablk_work *w = container_of( work,struct rnablk_work,work );
    struct rnablk_queued_deref_data *wd = &w->data.rwd_queued_deref;
    struct rnablk_server_conn *conn;
    uint64_t start_seconds = get_seconds();

    conn = com_get_ep_context(wd->cache_ep);
    if (likely(rnablk_verify_conn(conn))) {
        if (rnablk_conn_connected(conn) &&
            !atomic_read(&shutdown)) {
            rnablk_deref_conn_blks(wd->cache_ep, wd->cachedev_id, wd->bytes,
                                   wd->is_from_cs);
        }
    } else {
        rna_printk(KERN_ERR,
                   "conn [%p] not valid, dropping anonymous deref\n",
                   conn);
    }
    com_release_ep(wd->cache_ep);   // drop the ref taken when work was queued
    rnablk_mempool_free( w, work_cache_info );
    rnablk_finish_workq_work(start_seconds);
}


/*
 * Process an anonymous deref request from the Cache Server.
 *
 * May run at softirq level
 */
void
rnablk_queue_deref_req(struct com_ep          *ep,
                       struct cache_deref_req *request,
                       boolean is_from_cs)
{
    struct rnablk_server_conn *conn = rnablk_get_ep_conn(ep);
    struct rnablk_work *w;
    struct sockaddr_in dst_in;

    ENTERV;

    rnablk_trc_master(1, "start deref_bytes=[%"PRIu64"]\n", request->deref_bytes);
    if (request->deref_bytes > 0 &&
        likely(NULL != conn) &&
        likely(rnablk_conn_connected(conn)) &&
        likely(!atomic_read(&shutdown))) {

        dst_in = get_dest_sockaddr_from_ep(ep);

        rna_printk(KERN_INFO, "deref request from cache ["NIPQUAD_FMT"] "
                  "byte count [%"PRIu64"]\n",
                  NIPQUAD(dst_in.sin_addr.s_addr),
                  request->deref_bytes);

        w = rnablk_mempool_alloc(work_cache_info);
        if (likely(NULL != w)) {
            com_inc_ref_ep(ep);
            w->data.rwd_queued_deref.cache_ep = ep;
            w->data.rwd_queued_deref.cachedev_id = request->cachedev_id;
            w->data.rwd_queued_deref.bytes = request->deref_bytes;
            w->data.rwd_queued_deref.is_from_cs = is_from_cs;
            RNA_INIT_WORK(&w->work, rnablk_drop_references, w);
            rna_queue_work(slow_workq, &w->work);
        } else {
            rna_printk(KERN_ERR, "failed to allocate work item\n");
        }
        atomic_inc(&anon_drop_ref_requests);
    } else {
        rna_printk(KERN_WARNING,
                   "Ignoring deref request deref_bytes [%"PRIu64"] "
                   "conn [%p] shutdown [%d] rna_service_detached [%d]\n",
                   request->deref_bytes,
                   conn,
                   atomic_read(&shutdown),
                   atomic_read(&rna_service_detached));
    }
    rnablk_trc_master(1, "done\n");
    EXITV;
}

// Caller must hold block's bl_lock
void
rnablk_set_blk_ep(struct cache_blk * blk,
                  struct com_ep    * ep)
{
    struct rnablk_server_conn *conn = NULL;
    //unsigned long flags;

    RNABLK_DBG_BUG_ON(NULL == blk, "Huh?  NULL blk? ep=%p\n", ep);
    RNABLK_DBG_BUG_ON(NULL == ep, "Huh?  NULL ep? blk=%p\n", blk);
    RNABLK_DBG_BUG_ON(NULL != blk->ep,
                      "blk [%p] block [%llu] state [%s] ref [%s] already "
                      "has ep [%p], now setting to ep [%p]\n",
                      blk, blk->block_number,
                      rnablk_cache_blk_state_string(blk->state),
                      get_lock_type_string(blk->ref_type), blk->ep, ep);
    conn = rnablk_get_ep_conn(ep);
    if (g_md_conn == conn) {
        blk->ep = ep;
    } else if (NULL != conn) {
        RNABLK_BUG_ON_BLK((boolean)rnablk_cache_blk_state_is_bogus(blk->state), blk);
        RNABLK_BUG_ON_BLK((RNABLK_CACHE_BLK_DELETE_PENDING == blk->state), blk);
        RNABLK_BUG_ON_BLK((RNABLK_CACHE_BLK_DISCONNECTED == blk->state), blk);
        blk->ep = ep;
        com_inc_ref_ep(ep);
    } else {
        rna_printk(KERN_ERR,
                   "attempt to set device [%s] block [%"PRIu64"] to "
                   "conn list for ep [%p] with bad conn ["CONNFMT"]\n",
                   blk->dev->name,
                   blk->block_number,
                   ep,
                   CONNFMTARGS(conn));
        dump_stack();
    }
}

/*
 * rnablk_unset_blk_ep()
 *    Remove the blk's association with its ep, and at the same time,
 *    do the same for its cachedev association.
 *
 *   Caller must hold block's bl_lock. If blk->ep is non-NULL and doesn't
 *   reference the MD ep, then caller must also hold the conn's block_list_lock.
 *   Caller must hold a reference on the block.
 */
void
rnablk_unset_blk_ep(struct cache_blk *blk)
{
    struct com_ep *ep = blk->ep;
    struct rnablk_server_conn *conn;

    if (NULL != ep) {
        conn = rnablk_get_ep_conn(ep);
        if (g_md_conn == conn) {
            blk->ep = NULL;
        } else if (NULL != conn) {
            RNABLK_DBG_BUG_ON(!rna_block_mutex_is_locked(
                              &conn->block_list_lock), "conn ["CONNFMT"] "
                              "block_list_lock not held! blk=%p block [%llu]\n",
                              CONNFMTARGS(conn), blk, blk->block_number);
            rnablk_blk_put_cachedev(blk, conn);
            com_release_ep(blk->ep);
            blk->ep = NULL;
            blk->cb_dev_conn = NULL;
        } else {
            rna_printk(KERN_ERR,
                       "attempt to unset device [%s] block [%"PRIu64"] to "
                       "conn list for ep [%p] with bad conn ["CONNFMT"]\n",
                       blk->dev->name,
                       blk->block_number,
                       ep,
                       CONNFMTARGS(conn));
        }
    }
}


// Caller must hold read semaphore on block_list_lock
int
rnablk_cache_blk_restart(struct cache_blk *blk, boolean do_all)
{
    struct io_state *ios = NULL;
    struct list_head *ios_pos;

    rna_printk(KERN_INFO,
               "[%s] block [%"PRIu64"] in state [%s]\n",
               blk->dev->name,
               blk->block_number,
               rnablk_cache_blk_state_string(blk->state));

    if (unlikely(net_link_mask & RNABLK_NL_BLK_STATE)) {
        printnl_atomic("[%d] [%s] device [%s] block [%"PRIu64"]"
                       "set state [%s] refcnt ["BLKCNTFMT"]\n",
                       current->pid,
                       __FUNCTION__,
                       ((blk->dev != NULL) ? blk->dev->name : NULL),
                       blk->block_number,
                       rnablk_cache_blk_state_string(blk->state),
                       BLKCNTFMTARGS(blk));
    }
    if (rnablk_cache_blk_state_is_unreferenced(blk->state)) {
        /* make sure we release EP references */
        list_for_each(ios_pos, &blk->bl) {
            ios = list_entry(ios_pos, struct io_state, l);
            rnablk_trace_ios(ios);
            rnablk_unset_ios_ep(ios);
        }
        do_all = TRUE;     // overload this variable so we call drain below
    } else if (!do_all) {
        rna_printk(KERN_ERR,
                   "[%s] block [%"PRIu64"] in unexpected state [%s]\n",
                   blk->dev->name,
                   blk->block_number,
                   rnablk_cache_blk_state_string(blk->state));
    }

    if (do_all) {
        rnablk_cache_blk_drain(blk);
    }        
    return 0;
}

/*
 * rnablk_cache_blk_restart_cb()
 *
 * Notes:
 *  1) Note that this routine is currently only called from
 *     rnablk_restart_dev_blks().  For that case, we want 'do_all'
 *     (the 2nd argument passed to rnablk_cache_blk_restart()) to be
 *     TRUE.  Since this is the only code path for this routine currently,
 *     the argument is simply hard-coded to TRUE.  If that changes, then
 *     the desired value should be passed in via the 'context' argument.
 */
int
rnablk_cache_blk_restart_cb(struct cache_blk *blk,
                            void             *context)
{
    BUG_ON(NULL == blk);

    rna_printk(KERN_DEBUG, "device [%s] block [%"PRIu64"]\n",
               blk->dev->name, blk->block_number);

    return rnablk_cache_blk_restart(blk, TRUE);
}

static void rnablk_blk_restart_wf(rnablk_workq_cb_arg_t arg)
{
    struct work_struct *work = (struct work_struct *)arg;
    struct rnablk_work *w = container_of( work,struct rnablk_work,work );
    struct rnablk_blk_restart_wf_data *wd = &w->data.rwd_rnablk_blk_restart_wf;
    struct cache_blk *blk = wd->blk;

    rnablk_cache_blk_restart(blk, FALSE);
    rnablk_mempool_free(w, work_cache_info);
}



int
rnablk_queue_blk_restart(struct cache_blk *blk)
{
    int ret = 0;
    struct rnablk_work *w = NULL;
    struct rnablk_blk_restart_wf_data *wd = NULL;

    w = rnablk_mempool_alloc(work_cache_info);
    if (NULL == w) {
        rna_printk(KERN_ERR,
                   "failed to alloc work queue object");
        ret = -ENOMEM;
    } else {
        RNABLK_INIT_RNABLK_WORK(w, wd, rnablk_blk_restart_wf);
        wd->blk = blk;
        rna_queue_work(mt_workq, &w->work);
    }
    return ret;
}

