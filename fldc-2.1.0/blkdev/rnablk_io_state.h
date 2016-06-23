/**
 * <rnablk_io_state.h> - Dell Fluid Cache block driver
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
#include "rnablk_system.h"
#include "rnablk_globals.h"
#include "rnablk_block_state.h"
#include "rnablk_queue_dispatch.h"
#include "rnablk_device.h"

#ifdef WINDOWS_KERNEL
#include "rnablk_win_localssd.h"
#endif

#define rnablk_trace_ios(__rti_ios)\
    if (unlikely((NULL != __rti_ios) && (net_link_mask & RNABLK_NL_IOS_STATE))) {\
        printnl_atomic("[%d] [%s] [%s] ios [%p] tag ["TAGFMT"] type [%s] ref_count [%d] for device [%s] block [%"PRIu64"] state [%s]\n",\
                       current->pid,\
                       __FUNCTION__,\
                       __location__,\
                       __rti_ios,\
                       TAGFMTARGS(__rti_ios->tag),\
                       rnablk_op_type_string(__rti_ios->type),\
                       atomic_read(&__rti_ios->ref_count),\
                       ((NULL != __rti_ios->blk) ? __rti_ios->blk->dev->name : NULL),\
                       ((NULL != __rti_ios->blk) ?  __rti_ios->blk->block_number : 0),\
                       ((NULL != __rti_ios->blk) ?\
                        rnablk_cache_blk_state_string(__rti_ios->blk->state) :\
                        "NULL")); \
    }

INLINE void
rnablk_ios_ref_debug(const char      *function,
                     const char      *location,
                     struct io_state *ios)
{
    int count;

    if (NULL != ios) {
        count = atomic_inc_return(&ios->ref_count);
        if (unlikely((net_link_mask & RNABLK_NL_IOS_STATE) ||
                     (net_link_mask & RNABLK_NL_IOS_REF))) {
            printnl_atomic("ios_ref [%d] [%s] [%s] ios [%p] tag ["TAGFMT"] "
                           "type [%s] ref count [%d]\n",
                           current->pid,
                           function,
                           location,
                           ios,
                           TAGFMTARGS(ios->tag),
                           rnablk_op_type_string(ios->type),
                           count);
        }
    }
}
#define rnablk_ios_ref(__rir_ios)\
    rnablk_ios_ref_debug(__FUNCTION__,__location__,__rir_ios);

void rnablk_ios_release_debug (const char      *function,
                               const char      *location,
                               struct io_state *ios);
#define rnablk_ios_release(__rir_ios) \
    rnablk_ios_release_debug(__FUNCTION__,__location__,__rir_ios)

void rnablk_ios_finish_debug(const char      *function,
                             const char      *location,
                             struct io_state *ios);
#define rnablk_ios_finish(__rir_ios) \
    rnablk_ios_finish_debug(__FUNCTION__, __location__, __rir_ios)
							 
void
rnablk_end_request(struct io_state *ios, int error);

void
rnablk_cache_blk_drain_nolock(struct cache_blk * blk,
                              lockstate_t * irqflags);

void
rnablk_cache_blk_drain(struct cache_blk * blk);

void
rnablk_svcctl_register(void);

void rnablk_svcctl_freeze(void);

void rnablk_svcctl_unfreeze(void);

void
rnablk_svcctl_deregister(void);

void
rnablk_svcctl_init(void);

INLINE void rnablk_set_ios_ep( struct io_state *ios,struct com_ep *ep )
{
    BUG_ON(NULL == ios);

    if (ep == ios->ep) return;

    if (likely(ep && (MD_CONN_EP_METAVALUE != ep))) {
        com_inc_ref_ep( ep );
    }

    if (unlikely(ios->ep && (MD_CONN_EP_METAVALUE != ios->ep))) {
        com_release_ep( ios->ep );
    }

    ios->ep = ep;
}

INLINE void rnablk_unset_ios_ep(struct io_state *ios)
{
    if (likely(ios->ep && (MD_CONN_EP_METAVALUE != ios->ep))) {
        com_release_ep(ios->ep);
    }
    ios->ep = NULL;
}

void rnablk_set_ios_timer_debug(const char      *function,
                           const char      *location,
                           struct io_state *ios);

#define rnablk_set_ios_timer(__rsit_ios) \
    rnablk_set_ios_timer_debug(__FUNCTION__,__location__, \
                               (__rsit_ios))

void rnablk_retrack_ios_debug(const char      *function,
                              const char      *location,
                              struct io_state *ios);

#define rnablk_retrack_ios(__rri_ios)\
    rnablk_retrack_ios_debug(__FUNCTION__,__location__,__rri_ios)

void rnablk_io_completed_nolock(struct io_state  *ios, struct cache_blk *blk);
void rnablk_io_completed (struct io_state *ios);


int rnablk_alloc_ios(struct rnablk_device *dev,
                     void *ioreq,
                     int type,
                     rsv_access_t min_access,
                     boolean is_io,
                     boolean start_timer,
                     int n_ios,
                     struct io_state **pp_ios);

#define rnablk_alloc_ios_admin(__dev, __ios)                            \
    rnablk_alloc_ios((__dev), NULL, IOREQ_TYPE_NOREQ, RSV_ACC_NONE,     \
                     FALSE, TRUE, 1, &(__ios))

#define rnablk_alloc_ios_io(__dev, nios, ppios, ioreq, type, acc)       \
    rnablk_alloc_ios((__dev), (ioreq), (type), (acc), TRUE, FALSE,      \
                     (nios), &(ppios)[0])

void
rnablk_set_ios_blk_debug(const char       *function,
                         const char       *location,
                         struct io_state  *ios,
                         struct cache_blk *blk);
#define rnablk_set_ios_blk(__rsii,__rsib) \
    rnablk_set_ios_blk_debug(__FUNCTION__,__location__,__rsii,__rsib)

INLINE boolean
rnablk_is_ios_io_type(struct io_state *ios)
{
    return ios->type == RNABLK_RDMA_READ
            || ios->type == RNABLK_RDMA_WRITE
            || ios->type == RNABLK_COMP_AND_WRITE
            || ios->type == RNABLK_WRITE_SAME;
}

INLINE int
rnablk_ios_rsv_access_check(struct io_state *ios)
{
    if (rnablk_enforce_access(ios->dev)
        && rsv_access_is_less(ios->dev->rbd_rsv.rrs_client_access,
                              ios->ios_rsv_access)) {
        return -EBUSY;
    }
    return 0;
}

boolean rnablk_svcctl_is_frozen(void);

void
rnablk_dequeue_ordered_command(struct io_state *ios);

void rnablk_io_dispatched(struct io_state *ios);
void rnablk_io_dispatched_nolock(struct io_state  *ios,
                                 struct cache_blk *blk);

// Caller must hold ios->blk bl_lock
INLINE void
rnablk_reset_ios_dispatch(struct io_state *ios)
{
    dec_in_flight(ios->blk->dev, ios);
}

void rnablk_set_ios_io_type(struct io_state *ios);

void rnablk_set_ios_blk_ep(struct io_state *ios);

void rnablk_update_io_stats(struct io_state *ios);

void rnablk_process_request(struct io_state *ios);

#ifndef WINDOWS_KERNEL

static rna_inline void rnablk_set_bio_refcount(struct bio *bio, int value)
{
    /* We better not overwrite anything here. */
    BUG_ON(NULL != bio->bi_private);
    atomic_set((atomic_t *)&bio->bi_private, value);
}

static rna_inline void rnablk_inc_bio_refcount(struct bio *bio)
{
    atomic_inc((atomic_t *)&bio->bi_private);
}

static rna_inline void rnablk_dec_bio_refcount(struct bio *bio)
{
    atomic_dec((atomic_t *)&bio->bi_private);
}

static rna_inline int rnablk_read_bio_refcount(struct bio *bio)
{
    return atomic_read((atomic_t *)&bio->bi_private);
}

INLINE int rnablk_atomic_dec_and_test_bio_refcount(struct bio *bio)
{
    return atomic_dec_and_test((atomic_t *)&bio->bi_private);
}

#endif /*WINDOWS_KERNEL*/

struct io_state *
rnablk_cookie_to_ios_get_debug(const char *function, const char *location,
                               ios_tag_t tag, boolean is_response);

#define rnablk_cookie_to_ios_get(__rig_tag) \
    rnablk_cookie_to_ios_get_debug(__FUNCTION__,__location__,__rig_tag,TRUE)

#define rnablk_cookie_to_ios_get_no_response(__rig_tag) \
    rnablk_cookie_to_ios_get_debug(__FUNCTION__,__location__,__rig_tag,FALSE)


INLINE int
rnablk_ios_uses_local_dma(struct io_state *ios)
{
#ifdef WINDOWS_KERNEL
    return ((NULL != ios->blk->ldev) 
             && (!(ios->blk->ldev->flags & LOCDEV_FLAG_REMOVED))
             && (IOS_IOTYPE_READ == ios->ios_iotype));
#else
    return (NULL != ios->blk->ldev
            && ((!dev_dma_writes_disabled(ios->blk->dev)
                 && IOS_IOTYPE_WRITE == ios->ios_iotype)
               || (!dev_dma_reads_disabled(ios->blk->dev)
                   && IOS_IOTYPE_READ == ios->ios_iotype)));
#endif
}

INLINE boolean
rnablk_clear_ios_timer(struct io_state *ios)
{
    boolean did_delete = TRUE;
#ifdef RNA_USE_IOS_TIMERS
    if (del_timer(&ios->tl)) {
        /* release the timer's reference on ios */
        rnablk_ios_release(ios);
    } else {
        did_delete = FALSE;
    }
#endif /* RNA_USE_IOS_TIMERS */
    return did_delete;
}

void rnablk_ordered_command_completed(struct io_state *ios);
void rnablk_track_ordered_command(struct io_state *ios);


void rnablk_queue_ios_generic(struct io_state *ios, int ios_queue,
                              struct list_head *list, queue_where_t where);

void rnablk_dequeue_ios_generic(struct io_state *ios, int ios_queue);

boolean rnablk_remove_ios_from_wfc(struct io_state *ios);

int rnablk_create_ios_mempools(void);
void rnablk_destroy_ios_mempools(void);

