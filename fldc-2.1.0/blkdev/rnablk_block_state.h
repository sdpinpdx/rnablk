/**
 * <rnablk_block_state.h> - Dell Fluid Cache block driver
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
#ident "$URL$ $Id$"
#pragma once


#include "rb.h"
#include "rnablk_cache.h"
#include "rnablk_system.h"
#include "rnablk_globals.h"

#include "tree.h"

void rnablk_cache_blk_state_set_debug (const char       *function_string,
                                       const char       *location_string,
                                       struct cache_blk *blk,
                                       int               state);

#define rnablk_cache_blk_state_set(__rcbss_blk,__rcbss_state)\
    rnablk_cache_blk_state_set_debug(__FUNCTION__,__location__,__rcbss_blk,__rcbss_state)

enum state_property_bits {
    __RNABLK_CACHE_BLK_STATE_READABLE,      /**< (RDMA) reads allowed on blocks in these states */
    __RNABLK_CACHE_BLK_STATE_WRITABLE,      /**< (RDMA) writes allowed on blocks in these states */
    __RNABLK_CACHE_BLK_STATE_ATOMIC_ACCESS, /**< Atomic references held on blocks in thsese states,
                                             *   implying special I/O requirements.
                                             */
    __RNABLK_CACHE_BLK_STATE_QUERYABLE,     /**< Query request allowed on blocks in these states */
    __RNABLK_CACHE_BLK_STATE_DROPPABLE,     /**< We can (potentially) drop references on blocks 
                                             *   in these states 
                                             */
    __RNABLK_CACHE_BLK_STATE_TO_READ,       /**< We can (potentially) go to READ_SHARED from these states */
    __RNABLK_CACHE_BLK_STATE_TRANSITIONAL,  /**< States expected to change to some non-transitional 
                                             *   state soon */
    __RNABLK_CACHE_BLK_STATE_INVALIDATE_PENDING,  /**< Blocks in these states are being invalidated */
    __RNABLK_CACHE_BLK_STATE_UNREFERENCED,  /**< We have no reference on blocks in these states */
    __RNABLK_CACHE_BLK_STATE_CONNECTED,     /**< Blocks in these states are considered connected */
    __RNABLK_CACHE_BLK_STATE_DISCONNECTED,  /**< Blocks in these states are considered disconnected */
    __RNABLK_CACHE_BLK_STATE_BOGUS,         /**< Blocks in these states are probably bugs */
};

#define RNABLK_CACHE_BLK_STATE_READABLE       (1 << __RNABLK_CACHE_BLK_STATE_READABLE)
#define RNABLK_CACHE_BLK_STATE_WRITABLE       (1 << __RNABLK_CACHE_BLK_STATE_WRITABLE)
#define RNABLK_CACHE_BLK_STATE_ATOMIC_ACCESS  (1 << __RNABLK_CACHE_BLK_STATE_ATOMIC_ACCESS)
#define RNABLK_CACHE_BLK_STATE_QUERYABLE      (1 << __RNABLK_CACHE_BLK_STATE_QUERYABLE)
#define RNABLK_CACHE_BLK_STATE_DROPPABLE      (1 << __RNABLK_CACHE_BLK_STATE_DROPPABLE)
#define RNABLK_CACHE_BLK_STATE_TO_READ        (1 << __RNABLK_CACHE_BLK_STATE_TO_READ)
#define RNABLK_CACHE_BLK_STATE_TRANSITIONAL   (1 << __RNABLK_CACHE_BLK_STATE_TRANSITIONAL)
#define RNABLK_CACHE_BLK_STATE_INVALIDATE_PENDING (1 << __RNABLK_CACHE_BLK_STATE_INVALIDATE_PENDING)
#define RNABLK_CACHE_BLK_STATE_UNREFERENCED   (1 << __RNABLK_CACHE_BLK_STATE_UNREFERENCED)
#define RNABLK_CACHE_BLK_STATE_CONNECTED      (1 << __RNABLK_CACHE_BLK_STATE_CONNECTED)
#define RNABLK_CACHE_BLK_STATE_DISCONNECTED   (1 << __RNABLK_CACHE_BLK_STATE_DISCONNECTED)
#define RNABLK_CACHE_BLK_STATE_BOGUS          (1 << __RNABLK_CACHE_BLK_STATE_BOGUS)

/* Macros for entries in rnablk_cache_blk_state_properties */
#define _READ     RNABLK_CACHE_BLK_STATE_READABLE |
#define _WRITE    RNABLK_CACHE_BLK_STATE_WRITABLE |
#define _ATOMIC   RNABLK_CACHE_BLK_STATE_ATOMIC_ACCESS |
#define _QUERY    RNABLK_CACHE_BLK_STATE_QUERYABLE |
#define _DROP     RNABLK_CACHE_BLK_STATE_DROPPABLE |
#define _TO_READ  RNABLK_CACHE_BLK_STATE_TO_READ |
#define _TRANS    RNABLK_CACHE_BLK_STATE_TRANSITIONAL |
#define _INVDP    RNABLK_CACHE_BLK_STATE_INVALIDATE_PENDING |
#define _UNREF    RNABLK_CACHE_BLK_STATE_UNREFERENCED |
#define _CONN     RNABLK_CACHE_BLK_STATE_CONNECTED |
#define _DISC     RNABLK_CACHE_BLK_STATE_DISCONNECTED |
#define _BOGUS    RNABLK_CACHE_BLK_STATE_BOGUS |

typedef uint32_t state_property_mask_t;

/* Only define this table when the including file asks for it */
#if defined(RNABLK_DEFINE_CACHE_BLK_STATE_PROPERTIES)
/*
 * Table of state group membership. Array is indexed by an
 * rnablk_cache_blk_state_t.  Value is a mask of
 * RNABLK_CACHE_BLK_STATE_* values, which are bit masks for the values
 * in the enum state_property_bits.  The values in this array have
 * bits set for each state group that the indexing state is a member
 * of.
 *
 * This is formatted as a table with one column for each state group.
 * To see it as a table, you'll have to use a wide window.
 *
 * Windows require initialize rnablk_cache_blk_state_properties Array in a
 * rnablk_cache_blk_state_t order and all members need to be initialized.
 */
const state_property_mask_t rnablk_cache_blk_state_properties[RNABLK_CACHE_BLK_STATE_COUNT] = {
    /*                                                                                                                                        *
     * _BOGUS   RNABLK_CACHE_BLK_STATE_BOGUS ------------------------------------------------------------------------------------------+      *
     * _DISC    RNABLK_CACHE_BLK_STATE_DISCONNECTED ----------------------------------------------------------------------------+      |      *
     * _CONN    RNABLK_CACHE_BLK_STATE_CONNECTED -------------------------------------------------------------------------+     |      |      *
     * _UNREF   RNABLK_CACHE_BLK_STATE_UNREFERENCED ----------------------------------------------------------------+     |     |      |      *
     * _INVDP   RNABLK_CACHE_BLK_STATE_INVALIDATE_PENDING ---------------------------------------------------+      |     |     |      |      *
     * _TRANS   RNABLK_CACHE_BLK_STATE_TRANSITIONAL --------------------------------------------------+      |      |     |     |      |      *
     * _DROP    RNABLK_CACHE_BLK_STATE_DROPPABLE ----------------------------------------------+      |      |      |     |     |      |      *
     * _TO_READ RNABLK_CACHE_BLK_STATE_TO_READ -----------------------------------------+      |      |      |      |     |     |      |      *
     * _QUERY   RNABLK_CACHE_BLK_STATE_QUERYABLE -------------------------------+       |      |      |      |      |     |     |      |      *
     * _ATOMIC  RNABLK_CACHE_BLK_STATE_ATOMIC_ACCESS --------------------+      |       |      |      |      |      |     |     |      |      *
     * _WRITE   RNABLK_CACHE_BLK_STATE_WRITABLE ------------------+      |      |       |      |      |      |      |     |     |      |      *
     * _READ    RNABLK_CACHE_BLK_STATE_READABLE ------------+     |      |      |       |      |      |      |      |     |     |      |      *
     *                                                      |     |      |      |       |      |      |      |      |     |     |      |      */
    /*[RNABLK_CACHE_BLK_UNINITIALIZED]              = */(                                                                            _BOGUS 0),
    /*[RNABLK_CACHE_BLK_DISCONNECTED]               = */(                                                         _UNREF       _DISC        0),
    /*[RNABLK_CACHE_BLK_CONNECT_PENDING]            = */(                     _QUERY                _TRANS                                  0),
    /*[RNABLK_CACHE_BLK_CONNECTED_READ]             = */(_READ                                _DROP                      _CONN              0),
    /*[RNABLK_CACHE_BLK_CONNECTED_WRITE]            = */(_READ _WRITE                _TO_READ _DROP                      _CONN              0),
    /*[RNABLK_CACHE_BLK_CONNECTED_WRITE_ONLY]       = */(      _WRITE                _TO_READ _DROP                      _CONN              0),
	/*[RNABLK_CACHE_BLK_CONNECTED_WRITE_EXCLUSIVE]  = */(      _WRITE                _TO_READ _DROP                      _CONN              0),
    /*[RNABLK_CACHE_BLK_CONNECTED_ATOMIC]           = */(_READ _WRITE _ATOMIC                 _DROP                      _CONN              0),
    /*[RNABLK_CACHE_BLK_DISCONN_PENDING]            = */(                                           _TRANS                     _DISC        0),
    /*[RNABLK_CACHE_BLK_CHANGE_PENDING]             = */(                                     _DROP _TRANS               _CONN              0),
    /*[RNABLK_CACHE_BLK_DELETE_PENDING]             = */(                                                         _UNREF       _DISC        0),
    /*[RNABLK_CACHE_BLK_INVALIDATE_PENDING]         = */(                                     _DROP _TRANS _INVDP                           0),
    /* TODO: Should the INVALID state (below) be in the "disconnected" group? */
    /*[RNABLK_CACHE_BLK_INVALID]                    = */(                                                         _UNREF                    0),
    /*[RNABLK_CACHE_BLK_FREE]                       = */(                                                                            _BOGUS 0),
};
#else
const extern state_property_mask_t rnablk_cache_blk_state_properties[RNABLK_CACHE_BLK_STATE_COUNT];
#endif

INLINE int rnablk_cache_blk_state_is_out_of_range(rnablk_cache_blk_state_t state)
{
    if (unlikely(state < 0)) return 1;
    if (unlikely(state >= RNABLK_CACHE_BLK_STATE_COUNT)) return 1;
    return 0;
}

INLINE int _rnablk_cache_blk_state_is(rnablk_cache_blk_state_t state, 
                                             state_property_mask_t state_mask)
{
    BUG_ON(rnablk_cache_blk_state_is_out_of_range(state));
    return ((rnablk_cache_blk_state_properties[state] & state_mask) ==
             state_mask);
}

INLINE int rnablk_cache_blk_state_is_readable(rnablk_cache_blk_state_t state)
{ return _rnablk_cache_blk_state_is(state, RNABLK_CACHE_BLK_STATE_READABLE); }

INLINE int rnablk_cache_blk_state_is_writable(rnablk_cache_blk_state_t state)
{ return _rnablk_cache_blk_state_is(state, RNABLK_CACHE_BLK_STATE_WRITABLE); }

INLINE int rnablk_cache_blk_state_is_atomic(rnablk_cache_blk_state_t state)
{ return _rnablk_cache_blk_state_is(state, RNABLK_CACHE_BLK_STATE_ATOMIC_ACCESS); }

INLINE int rnablk_cache_blk_state_is_queryable(rnablk_cache_blk_state_t state)
{ return _rnablk_cache_blk_state_is(state, RNABLK_CACHE_BLK_STATE_QUERYABLE); }

INLINE int rnablk_cache_blk_state_can_become_read_shared(rnablk_cache_blk_state_t state)
{ return _rnablk_cache_blk_state_is(state, RNABLK_CACHE_BLK_STATE_TO_READ); }

INLINE int rnablk_cache_blk_state_is_droppable(rnablk_cache_blk_state_t state)
{ return _rnablk_cache_blk_state_is(state, RNABLK_CACHE_BLK_STATE_DROPPABLE); }

INLINE int rnablk_cache_blk_state_is_transitional(rnablk_cache_blk_state_t state)
{ return _rnablk_cache_blk_state_is(state, RNABLK_CACHE_BLK_STATE_TRANSITIONAL); }

INLINE int rnablk_cache_blk_state_is_invalidate_pending(rnablk_cache_blk_state_t state)
{ return _rnablk_cache_blk_state_is(state, RNABLK_CACHE_BLK_STATE_INVALIDATE_PENDING); }

INLINE int rnablk_cache_blk_state_is_unreferenced(rnablk_cache_blk_state_t state)
{ return _rnablk_cache_blk_state_is(state, RNABLK_CACHE_BLK_STATE_UNREFERENCED); }

INLINE int rnablk_cache_blk_state_is_connected(rnablk_cache_blk_state_t state)
{ return _rnablk_cache_blk_state_is(state, RNABLK_CACHE_BLK_STATE_CONNECTED); }

INLINE int rnablk_cache_blk_state_is_disconnected(rnablk_cache_blk_state_t state)
{ return _rnablk_cache_blk_state_is(state, RNABLK_CACHE_BLK_STATE_DISCONNECTED); }

INLINE int rnablk_cache_blk_state_is_bogus(rnablk_cache_blk_state_t state)
{
    if (unlikely(rnablk_cache_blk_state_is_out_of_range(state))) return 1;
    return _rnablk_cache_blk_state_is(state, RNABLK_CACHE_BLK_STATE_BOGUS);
}

INLINE const char * rnablk_cache_blk_state_string(rnablk_cache_blk_state_t state)
{
    static const char * ret = "Invalid State";
    switch (state) {
        case RNABLK_CACHE_BLK_UNINITIALIZED: ret = "RNABLK_CACHE_BLK_UNINITIALIZED"; break;
        case RNABLK_CACHE_BLK_DISCONNECTED: ret = "RNABLK_CACHE_BLK_DISCONNECTED"; break;
        case RNABLK_CACHE_BLK_CONNECT_PENDING: ret = "RNABLK_CACHE_BLK_CONNECT_PENDING"; break;
        case RNABLK_CACHE_BLK_CONNECTED_READ: ret = "RNABLK_CACHE_BLK_CONNECTED_READ"; break;
        case RNABLK_CACHE_BLK_CONNECTED_WRITE: ret = "RNABLK_CACHE_BLK_CONNECTED_WRITE"; break;
        case RNABLK_CACHE_BLK_CONNECTED_WRITE_ONLY: ret = "RNABLK_CACHE_BLK_CONNECTED_WRITE_ONLY"; break;
        case RNABLK_CACHE_BLK_CONNECTED_WRITE_EXCLUSIVE: ret = "RNABLK_CACHE_BLK_CONNECTED_WRITE_EXCLUSIVE"; break;
        case RNABLK_CACHE_BLK_CONNECTED_ATOMIC: ret = "RNABLK_CACHE_BLK_CONNECTED_ATOMIC"; break;
        case RNABLK_CACHE_BLK_DISCONN_PENDING: ret = "RNABLK_CACHE_BLK_DISCONN_PENDING"; break;
        case RNABLK_CACHE_BLK_CHANGE_PENDING: ret = "RNABLK_CACHE_BLK_CHANGE_PENDING"; break;
        case RNABLK_CACHE_BLK_DELETE_PENDING: ret = "RNABLK_CACHE_BLK_DELETE_PENDING"; break;
        case RNABLK_CACHE_BLK_INVALIDATE_PENDING: ret = "RNABLK_CACHE_BLK_INVALIDATE_PENDING"; break;
        case RNABLK_CACHE_BLK_INVALID: ret = "RNABLK_CACHE_BLK_INVALID"; break;
        case RNABLK_CACHE_BLK_FREE: ret = "RNABLK_CACHE_BLK_FREE"; break;
        case RNABLK_CACHE_BLK_STATE_COUNT: ret = "RNABLK_CACHE_BLK_STATE_COUNT (invalid state)"; break;
    }
    return ret;
}

void rnablk_cache_blk_unlink_nolock (struct cache_blk *blk);
void rnablk_cache_blk_free (struct cache_blk *blk);
void rnablk_cache_blk_ref_debug (const char       *function,
                                 const char       *location,
                                 struct cache_blk *blk,
                                 struct io_state  *ios);
void rnablk_cache_blk_ioref_debug(const char *function,
                                  const char *location,
                                  struct cache_blk *blk,
                                  struct io_state *ios);

#define rnablk_cache_blk_ref(__rcbr_blk)\
    rnablk_cache_blk_ref_debug(__FUNCTION__,__location__,__rcbr_blk,NULL);


#define rnablk_cache_blk_ioref(__rcbr_blk, __rcbr_ios)\
    rnablk_cache_blk_ioref_debug(__FUNCTION__,__location__,__rcbr_blk, \
                                 __rcbr_ios);

void rnablk_cache_blk_release_debug(const char *function,
                                    const char *location,
                                    struct cache_blk *blk,
                                    struct io_state *ios);
void rnablk_cache_blk_iorel_debug(const char *function,
                                  const char *location,
                                  struct cache_blk *blk,
                                  struct io_state *ios);

#define rnablk_cache_blk_release(__rcbr_blk)\
    rnablk_cache_blk_release_debug(__FUNCTION__,__location__,__rcbr_blk,NULL);

#define rnablk_cache_blk_iorel(__rcbr_blk,__rcbr_ios) \
    rnablk_cache_blk_iorel_debug(__FUNCTION__, __location__, __rcbr_blk, \
                                 __rcbr_ios);
#ifdef WINDOWS_KERNEL 
#define PROCESS_ID  PsGetCurrentProcessId()
#else
#define PROCESS_ID  current->pid
#endif

#define RNABLK_BUG_ON_BLK(expr, blk)                                          \
    if (unlikely(expr)) {                                                     \
        rna_printk(KERN_ERR,                                                  \
                "RNABLK_BUG_ON_BLK: [%d] [%s] [%s] blk [%p] block [%"PRIu64"]"\
                   " dev [%s] state [%s] refcnt ["BLKCNTFMT"]\n",             \
                   PROCESS_ID, __FUNCTION__, __location__,                  \
                   blk, blk->block_number, blk->dev->name,                    \
                   rnablk_cache_blk_state_string(blk->state),                 \
                   BLKCNTFMTARGS(blk));                                       \
        BUG();                                                                \
    }

int rnablk_cache_blk_state_transition_debug (const char       *function_string,
                                             const char       *location_string,
                                             struct cache_blk *blk,
                                             int               old_state,
                                             int               new_state);

#define rnablk_cache_blk_state_transition(__rcbst_blk,__rcbst_old_state,__rcbst_new_state)\
    rnablk_cache_blk_state_transition_debug(__FUNCTION__,__location__,__rcbst_blk,__rcbst_old_state,__rcbst_new_state)

struct cache_blk *rnablk_cache_blk_find_or_create(
                                struct rnablk_device *dev,
                                sector_t              start_sector,
                                boolean               is_write);

struct cache_blk * rnablk_cache_blk_get_debug (const char           *function,
                                               const char           *location,
                                               struct rnablk_device *dev,
                                               sector_t              start_sector);

#define rnablk_cache_blk_get(__rcbg_dev,__rcbg_sector) \
    rnablk_cache_blk_get_debug(__FUNCTION__,__location__,__rcbg_dev,__rcbg_sector)

void rnablk_queue_deref_req(struct com_ep *ep, struct cache_deref_req *request,
                            boolean is_from_cs);

void
rnablk_set_blk_ep(struct cache_blk * blk,
                  struct com_ep    * ep);

void
rnablk_unset_blk_ep(struct cache_blk *blk);

INLINE int
rnablk_cache_blk_unused(struct cache_blk *blk)
{
    return ((0 == atomic_read(&blk->cb_ioref_cnt))
            && (NULL != blk->ep)
            && (MD_CONN_EP_METAVALUE != blk->ep));
}

#define     DEREF_NO_RESP       0x01    // deref request needs no response
#define     DEREF_HIPRI         0x02    // deref request is high priority

int
rnablk_cache_blk_drop_ref(struct cache_blk *blk, lockstate_t * irqflags,
                          uint32_t flags);

void
rnablk_mark_cache_blk_bad_nolock(struct cache_blk *blk, boolean mark_invalid);

void
rnablk_mark_cache_blk_bad_and_drain(struct cache_blk *blk,
                                    boolean mark_invalid);

boolean
rnablk_cs_change_req_blk_transition(struct rnablk_server_conn *conn,
                                    struct cache_blk *blk,
                                    cache_lock_t ref_type);

int
rnablk_queue_blk_restart(struct cache_blk *blk);

/*
 * rnablk_can_downgrade_cache_blk()
 *  This routine looks at the current snapshot of the blk state
 *  to determine whether we can downgrade its reference.
 *
 *  Note the blk lock need not be held by the caller, as long as
 *  the caller can tolerate a change to the "downgradeable" state
 *  and doesn't take any consequent action on the blk without holding the
 *  appropriate locks and rechecking the state under lock, etc.
 */
INLINE boolean
rnablk_can_downgrade_cache_blk(struct cache_blk *blk)
{
    if ((RNABLK_CACHE_BLK_CONNECTED_WRITE == blk->state
         || RNABLK_CACHE_BLK_CONNECTED_WRITE_ONLY == blk->state
         || RNABLK_CACHE_BLK_CONNECTED_ATOMIC == blk->state)
        && rnablk_cache_blk_unused(blk)) {
        return TRUE;
    }
    return FALSE;
}

INLINE int rnablk_blk_recoverable (struct cache_blk *blk)
{
    return ((NULL != blk) &&
            (NULL != blk->dev) &&
            dev_is_persistent(blk->dev) &&
            !dev_is_das(blk->dev) &&
            !atomic_read(&shutdown) &&
            !rnablk_dev_is_shutdown(blk->dev) &&
            !atomic_read(&blk->dev->failed));
}

INLINE void
rnablk_assert_blk_quiesced(struct cache_blk *blk)
{
    RNABLK_BUG_ON(0 != atomic_read(&blk->inflight_ios),
                  "blk=%p [%"PRIu64"] ioref=%d infl_io=%d\n",
                  blk, blk->block_number, atomic_read(&blk->cb_ioref_cnt),
                  atomic_read(&blk->inflight_ios));
}


// returns TRUE if block is in any of the various connected states
// caller must hold block's spin lock
INLINE int rnablk_blk_connected(struct cache_blk *blk) {
    return (rnablk_cache_blk_state_is_connected(blk->state));
}

int rnablk_cache_blk_restart(struct cache_blk *blk, boolean do_all);

/*
 * rnablk_can_deref_cache_blk()
 *  This routine looks at the current snapshot of the blk state
 *  to determine whether we can drop its reference.
 *
 *  Note the blk lock need not be held by the caller, as long as
 *  the caller can tolerate a change to the "droppable" state
 *  and doesn't take any consequent action on the blk without holding the
 *  appropriate locks and rechecking the state under lock, etc.
 */
INLINE boolean
rnablk_can_deref_cache_blk(struct cache_blk *blk)
{
    return rnablk_cache_blk_state_is_droppable(blk->state) 
           && rnablk_cache_blk_unused(blk);
}

boolean
rnablk_state_ok_for_req(struct cache_blk *blk,
                        struct io_state  *ios);

boolean rnablk_try_deref_cache_blk(struct cache_blk *blk);
boolean rnablk_try_downgrade_cache_blk(struct cache_blk *blk);

void rnablk_dec_inflight_ios(struct cache_blk *blk);
void rnablk_queue_deref(struct cache_blk *blk, boolean hipri);

struct cache_blk * alloc_cache_blk(struct rnablk_device *dev,
                                   sector_t start_sector,
                                   boolean is_master_blk);

int rnablk_master_blk_send_deref(struct rnablk_device *dev);

int rnablk_cache_blk_restart_cb(struct cache_blk *blk,
                                void             *context);

int rnablk_needed_lock(struct io_state *ios, cache_lock_t *lock_type);

int rnablk_get_blk_state_for_io(struct cache_blk *blk, struct io_state *ios);

void rnablk_cs_query_blk_transition(struct cache_blk *blk,
                                    cache_lock_t      ref_type,
                                    cache_lock_t      orig_ref_type);

INLINE int
rnablk_blk_has_dispatched_io(struct cache_blk *blk)
{
    return(!list_empty(&blk->dispatch_queue)
           || (0 != atomic_read(&blk->inflight_ios)));
}

// returns TRUE if block is in any of the various dosconnected states
// caller must hold block's spin lock
INLINE int rnablk_blk_disconnected(struct cache_blk *blk) {
    return (rnablk_cache_blk_state_is_disconnected(blk->state));
}

INLINE int
rnablk_cache_blk_start_atomic_state_transition(struct cache_blk *blk)
{
    /* These are the valid states from which we can transition to atomic. */
    if (rnablk_cache_blk_state_transition(blk,
                                          RNABLK_CACHE_BLK_CONNECTED_READ,
                                          RNABLK_CACHE_BLK_CHANGE_PENDING) ||
        rnablk_cache_blk_state_transition(blk,
                                          RNABLK_CACHE_BLK_CONNECTED_WRITE,
                                          RNABLK_CACHE_BLK_CHANGE_PENDING) ||
        rnablk_cache_blk_state_transition(blk,
                                          RNABLK_CACHE_BLK_CONNECTED_WRITE_ONLY,
                                          RNABLK_CACHE_BLK_CHANGE_PENDING)) {
        return 1;
    }
    return 0;
}

#define INVALID_BLOCK_NUM           ((uint64_t)-1)

int
rnablk_send_master_change_ref(struct rnablk_device *dev,
                              struct request *req,
                              enum rnablk_op_type type,
                              cache_lock_t desired_ref);

int
rnablk_submit_change_ref(struct io_state *ios,
                         cache_lock_t orig_ref,
                         cache_lock_t desired_ref,
                         uint32_t flags);

int
rnablk_get_cache_blk_debug_info(struct rnablk_device *dev,
                                int blk_num,
                                struct rnablk_cache_blk_debug_info *dbg_info,
                                boolean need_ep);

uint64_t
rnablk_get_next_cache_blk_debug_info(
                                struct rnablk_device *dev, 
                                int next_blk_num,
                                struct rnablk_cache_blk_debug_info *dbg_info,
                                struct cache_blk **pp_blk,
                                gboolean busy_blks_only);

void
rnablk_cache_blk_unlink_lru_locked(struct rnablk_server_conn *conn,
                                   struct cache_blk *blk,
                                   boolean write_only);


struct rnablk_server_conn *rnablk_get_blk_conn(struct cache_blk *blk);
