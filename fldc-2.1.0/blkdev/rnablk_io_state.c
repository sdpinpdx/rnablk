/**
 * <rnablk_io_stat.c> - Dell Fluid Cache block driver
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
#define RNABLK_DEFINE_CACHE_BLK_STATE_PROPERTIES
#include "rnablk_io_state.h"
#include "rnablk_util.h"
#include "rnablk_cache.h"
#include "rnablk_queue_dispatch.h"
#include "rnablk_scsi.h"
#include "rnablk_data_transfer.h"
#include "rnablk_device.h"
#include "rnablk_protocol.h"
#include "rnablk_comatose.h" // for rnablk_end_req
#include "trace.h"
#include <stddef.h>

/*
 * Specific tracing support for Windows Storport Miniport...
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
#include "rnablk_io_state.tmh"
#endif

/*
 * IOS tags
 *
 * The following set of definitions of variables are used for generating/
 * managing the ios tag field.  We want the speed of being able to
 * map from a tag to the ios pretty directly, but we also need a generation
 * number to ensure we aren't using a stale tag to do the map.
 * To achieve this, we want ios address information as well as a generation
 * number in the tag.  But the problem with this is, we want the tag to
 * fit into 64 bits -- which is the 'cookie' size passed around between
 * fluidcache components.  (I spent some time looking at expanding this
 * size, btw, but it looked to be a pretty painful change!  Which is why
 * I chose the approach used here instead!).
 *
 * So, here's the scoop.  The current ios_tag_t consists of the following:
 *             +-----------------------------------+
 *             |  LLLLLLLLL      | XX  GGGGGGG  [R]|
 *             +-----------------------------------+
 *              -----32 bits-----|-----32 bits ----
 *
 *                      where LLLLLLLL  - equates to the low-order 32 bits
 *                                        of the ios address.
 *                            XX        - equates to an index that indexes
 *                                        into the ios_hiaddrs[] array where
 *                                        we have stashed the high-order 32
 *                                        bits of all ios' in the mempools.
 *                            GGGGGG    - is the current generation number for
 *                                        this ios
 *                            R         - is a special 1-bit field that
 *                                        tracks whether a 'response' has
 *                                        been received for this tag
 *
 *  Some important notes about how this works:
 *      1. First of all, note that any method that incorporates the ios
 *         address in any way depends on all ios' being pre-reserved and
 *         held onto (by this module) throughout its lifetime, i.e.
 *         the addresses need to be "valid" ios addresses even if the ios
 *         is not currently in use.
 *         Given this requirement, this current implementation optimizes
 *         by initializing the LLLLLLLLXX portion of the tag field up front
 *         at module initialization time.
 *      2. The number of bits used for the XX portion of the tag (the
 *         index field) depends on the MAX_IOS_HIADDRS definition (which must
 *         be a power of 2).  Thirty two bits in total are available for the
 *         index and generation number combined.  The defines are set up
 *         so that both fields are adjusted automagically when MAX_IOS_HIADDRS
 *         is changed.  If MAX_IOS_HIADDRS is 256, then the index field is
 *         8 bits and generation field is 24 bits, etc.  Well actually,
 *         1 bit is needed for the 'R' bit, so that gets subtracted from
 *         the generation field, so in this example, the generation field
 *         will actually be 23 bits.
 *      3. So note that the ability to strip off the high-order 32 bits of
 *         the address and be able to track it with a smale index field
 *         relies on the assumption that the ios's won't be scattered
 *         willy-nilly throughout memory, but will tend to come from a
 *         more localized memory region.
 *         Given that our normal allocation method is to reserve them
 *         up front via the rna_service_mempool facility, which will allocate
 *         them all in a single contiguous allocation if possible, this
 *         assumption should be valid.
 *         Note however that rna_service_mempool_alloc() will fall back on
 *         doing individual allocations if it can't get a contiguous memory
 *         region.  It's possible we could run into trouble in that case!
 *         (This module will fail to load if we can't fit all the different
 *         ios high-order address fields in the ios_hiaddrs array).
 *      4. The generation number in the tag is updated when the ios is
 *         allocated for use, when it is "finished" (i.e. completed via
 *         rnablk_ios_finish), and whenever it is getting 'sent' abroad
 *         (i.e. to the CS or MD).  In addition, the 'R' bit is set whenever
 *         an rnablk_cookie_to_ios_get() is performed on the ios.  This latter
 *         guards against duplicate responses for the same request.
 */
#define MAX_IOS_HIADDRS         64          // must be multiple of 2
static uint64_t ios_hiaddrs[MAX_IOS_HIADDRS];
static int n_ios_hiaddrs;

#ifdef WINDOWS_KERNEL
char ffs(ULONGLONG val)
{
    return (RtlFindLeastSignificantBit(val) + 1);
}
#endif



#define HIADDR_MASK             0xffffffff00000000L
#define LOWADDR_MASK            0xffffffff
#define LOWADDR_SHIFT           32
#define GEN_SHIFT               1

/* The following fields adjust automatically based on MAX_IOS_HIADDRS */
#define HIADDR_IDX_MASK         (MAX_IOS_HIADDRS - 1)
#define HIADDR_IDX_SHIFT        (32 - (ffs(MAX_IOS_HIADDRS) - 1))
#define GEN_MASK    (LOWADDR_MASK & \
        ~((HIADDR_IDX_MASK << HIADDR_IDX_SHIFT)|(1 << (HIADDR_IDX_SHIFT-1))))

#define IOS_GET_HIADDR(ios)    ((uint64_t)(ios) & HIADDR_MASK)
#define IOS_INITIALIZE_TAG(ios, hi_idx) \
    ((((uint64_t)(ios) & LOWADDR_MASK) << LOWADDR_SHIFT) | \
    (((hi_idx) & HIADDR_IDX_MASK) << HIADDR_IDX_SHIFT))

#define IOS_TAG_TO_IOS(tag)    \
    ((struct io_state *)(ios_hiaddrs[((tag) >> HIADDR_IDX_SHIFT) \
    & HIADDR_IDX_MASK] | (((tag) >> LOWADDR_SHIFT) & LOWADDR_MASK)))

#define IOS_TAG_TO_GEN(tag)      ((uint32_t)(((tag) >> GEN_SHIFT) & GEN_MASK))

#define IOS_UPDATE_TAG_GEN(ios, gen) \
    (((ios)->tag & (HIADDR_MASK|(HIADDR_IDX_MASK << HIADDR_IDX_SHIFT))) \
    | (((gen) & GEN_MASK) << GEN_SHIFT))


#define RNABLK_IO_EXPIRES (get_jiffies() + (rnablk_io_timeout * HZ))

rna_service_mempool_t   rnablk_ios_io_mempool;
int                     rnablk_ios_io_mempool_size = RNABLK_IOS_POOL_SIZE;
rna_service_throttle_t  rnablk_ios_admin_throttle;
rna_service_mempool_t   rnablk_ios_admin_mempool;
int                     rnablk_ios_admin_mempool_size = 512;

static rnablk_svcctl_t rnablk_svcctl;  // service control data

atomic_t ios_rb_id = {100};

/* private prototypes */
static int
rnablk_process_blk_io(struct io_state  *ios,
                      lockstate_t   *  irqflags);

static void rnablk_handle_ios_leak(void *void_ios);

/*
 * rnablk_initialize_ios_tag()
 *  This routine needs to be called during module load for every 'ios'
 *  the module will use throughout it's lifetime.  It ensures that the
 *  high-order 32 bits of the ios address are accounted for in our
 *  ios_hiaddrs[] array which is required to enable our ios 'tag' scheme
 *  to work.  (See detailed comments located with the MAX_IOS_HIADDRS 
 *  definition).
 *  This routine also initializes the ios->tag field for each ios with
 *  the fixed portion of the tag data.
 */
static int
rnablk_initialize_ios_tag(struct io_state *ios)
{
    int i;

    for (i = 0; i < n_ios_hiaddrs; i++) {
        if (IOS_GET_HIADDR(ios) == ios_hiaddrs[i]) {
            ios->tag = IOS_INITIALIZE_TAG(ios, i);
            break;
        }
    }
    if (i >= n_ios_hiaddrs) {
        if (i == n_ios_hiaddrs && n_ios_hiaddrs < MAX_IOS_HIADDRS) {
            ios_hiaddrs[n_ios_hiaddrs++] = IOS_GET_HIADDR(ios);
            ios->tag = IOS_INITIALIZE_TAG(ios, i);
        } else {
            rna_printk(KERN_ERR, "Unable to allocate ios pool in usable "
                       "configuration, fatal error!\n");
            return -EINVAL;
        }
    }
    return 0;
}

/*
 * rnablk_create_ios_mempools()
 *  Create the two ios mempools used by this module, and perform
 *  initialization on all ios structures in the pools.
 *
 * Notes:
 *   1) Important!  It is a requirement of the current ios->tag scheme
 *      that all ios structures used by the driver be pre-allocated
 *      (i.e. "reserved") up front and have their tag field initialized.
 *      (This is necessary both so we can initialize the tag field, but
 *      more importantly, to ensure that each ios address can be (and is!)
 *      represented in the ios_hiaddrs array).  See detailed comments about
 *      this located with the MAX_IOS_HIADDRS definition.
 *      So, point being, if you want to make changes that break this
 *      assumption, then be prepared to also revise the current tag mechanism!
 */
int
rnablk_create_ios_mempools(void)
{
    list_element_t *ele;
    struct io_state *ios;
    ENTER;

    if (0 != rna_service_mempool_init(&rnablk_ios_io_mempool,
                                      sizeof(struct io_state)
                                      + sizeof(struct scatterlist)
                                      * RNA_MAX_SGE, 0,
                                      rnablk_ios_io_mempool_size, 0, 1)) {
        GOTO(out, -ENOMEM);
    }
    if (0 != rna_service_throttle_init(&rnablk_ios_io_throttle,
                                       rnablk_io_queue_depth,
                                       rnablk_io_queue_depth,
                                       rnablk_ios_io_mempool_size)) {
        rna_service_mempool_destroy(&rnablk_ios_io_mempool, NULL);
        GOTO(out, -ENOMEM);
    }


    if (0 != rna_service_mempool_init(&rnablk_ios_admin_mempool,
                                      sizeof(struct io_state)
                                      + sizeof(struct cache_cmd), 0,
                                      rnablk_ios_admin_mempool_size, 0, 1)) {
        GOTO(cleanup1, -ENOMEM);
    }
    if (0 != rna_service_throttle_init(&rnablk_ios_admin_throttle,
                                       rnablk_ios_admin_mempool_size,
                                       rnablk_ios_admin_mempool_size,
                                       rnablk_ios_admin_mempool_size)) {
        rna_service_mempool_destroy(&rnablk_ios_admin_mempool, NULL);
        GOTO(cleanup1, -ENOMEM);
    }

    /*
     * Walk both ios lists and initialize the base tag info for each,
     * including saving/calculating the high-order address bucket it
     * falls into.  Also initialize the ios_lock field for the one and
     * only time.  (This needs to initialized up front exactly once due to
     * rnablk_validate_tag(), which may lock an ios without holding any
     * reference on it!.  UPDATE: rnablk_validate_tag() has gone away;
     * thus we no longer really need to init the lock up front.  Oh well,
     * no good reason to move it for now...)
     */
    for (ele = rnablk_ios_io_mempool.mp_avail; ele; ele = ele->le_next) {
        ios = (struct io_state *)ele;
        ret = rnablk_initialize_ios_tag(ios);
        if (0 != ret) {
            goto cleanup2;
        }
        rna_spin_lock_init(ios->ios_lock);
        ios->ios_magic = RNABLK_IOS_MAGIC;
    }

    for (ele = rnablk_ios_admin_mempool.mp_avail; ele; ele = ele->le_next) {
        ios = (struct io_state *)ele;
        ret = rnablk_initialize_ios_tag(ios);
        if (0 != ret) {
            goto cleanup2;
        }
        rna_spin_lock_init(ios->ios_lock);
        ios->ios_magic = RNABLK_IOS_MAGIC;
    }
    
 out:
    EXIT;

 cleanup2:
    rna_service_throttle_destroy(&rnablk_ios_admin_throttle);
    rna_service_mempool_destroy(&rnablk_ios_admin_mempool, NULL);
 cleanup1:
    rna_service_throttle_destroy(&rnablk_ios_io_throttle);
    rna_service_mempool_destroy(&rnablk_ios_io_mempool, NULL);
    goto out;
}

void
rnablk_destroy_ios_mempools(void)
{
    rna_service_throttle_destroy(&rnablk_ios_admin_throttle);
    rna_service_mempool_destroy(&rnablk_ios_admin_mempool, rnablk_handle_ios_leak);
    rna_service_throttle_destroy(&rnablk_ios_io_throttle);
    rna_service_mempool_destroy(&rnablk_ios_io_mempool, rnablk_handle_ios_leak);
}

void
rnablk_svcctl_init(void)
{
    rnablk_svcctl_t *scp = &rnablk_svcctl;
#ifdef WINDOWS_KERNEL
	KeInitializeEvent(&scp->svc_wait, NotificationEvent, FALSE);
#else
    init_waitqueue_head(&scp->svc_wait);
#endif /*WINDOWS_KERNEL*/
    rna_spin_lock_init(scp->svc_lock);
}

/*
 * rnablk_svcctl_freeze
 *  "Freeze" the driver to block all I/O activity while special
 *  processing takes place.  This is used currently for com disconnect
 *  processing (i.e. disconnect from cache server), and during
 *  cache device failure/offline processing.
 *  This function is intended to be used in conjunction with
 *  rnablk_svcctl_unfreeze(), and depends on the initiation of I/O
 *  activity to be sandwiched between calls to rnablk_svcctl_register()/
 *  rnablk_svcctl_unregister().
 *
 * Notes:
 *  1) The need for this special 'semaphore" primitive is due to
 *     the requirement during cachedev offline processing to potentially
 *     block I/O across multiple thread contexts, i.e. one thread
 *     performs the freeze, and then we can't do the unfreeze
 *     until a second independent event takes places. (See notes
 *     for rnablk_do_offline_cache_device() for more info.)
 *  2) Multiple freezers are allowed to run in parallel, as are
 *     multiple io_users.
 *  3) This implementation favors "freezers", by blocking new
 *     io_users if there is a freezer waiting.
 */
void
rnablk_svcctl_freeze()
{
    rnablk_svcctl_t *scp = &rnablk_svcctl;
    unsigned long irqflags;

    rna_spin_lock_irqsave(scp->svc_lock, irqflags);
    while (scp->svc_io_users) {
        scp->svc_freeze_waiters++;
        rna_spin_unlock_irqrestore(scp->svc_lock, irqflags);
        wait_event(scp->svc_wait, (0 == scp->svc_io_users));
        rna_spin_lock_irqsave(scp->svc_lock, irqflags);
        scp->svc_freeze_waiters--;
    }
    scp->svc_frozen++;
    rna_spin_unlock_irqrestore(scp->svc_lock, irqflags);
}
    

/*
 * rnablk_svcctl_unfreeze
 *  "Unfreeze" the driver to reenable I/O processing in the driver.
 *  This function is used to undo the effects of a previous call to
 *  rnablk_svcctl_freeze()l
 *
 * Notes:
 *  1) See general comments about this pair of functions in the
 *     header for rnablk_svcctl_freeze().
 */
void
rnablk_svcctl_unfreeze()
{
    rnablk_svcctl_t *scp = &rnablk_svcctl;
    unsigned long irqflags;

    rna_spin_lock_irqsave(scp->svc_lock, irqflags);
    RNABLK_BUG_ON(scp->svc_frozen < 1, "Unfreeze called without "
                  "a prior call to freeze?");
    if (--scp->svc_frozen == 0) {
        wake_up_all(&scp->svc_wait);
    }
    rna_spin_unlock_irqrestore(scp->svc_lock, irqflags);
}    

/*
 * rnablk_svcctl_is_frozen()
 *  Returns TRUE if the system is currently in the frozen state.
 *  Since this is just a snapshot in time anyway, we don't bother
 *  getting the lock.  Callers must be able to tolerate that the
 *  state can change (between frozen/unfrozen) at any time!
 */
boolean
rnablk_svcctl_is_frozen(void)
{
    rnablk_svcctl_t *scp = &rnablk_svcctl;

    return (scp->svc_frozen || scp->svc_freeze_waiters);
}

/*
 * rnablk_svcctl_register
 *  Used together with rnablk_svcctl_unregister() to register that
 *  new I/O activity is about to be initiated.  All code paths in the
 *  driver that initiate new I/O activity must sandwich that code
 *  between calls to this pair of routines in order for the driver
 *  to properly support freeze/unfreeze functionality.
 *
 * Notes:
 *  1) See general comments about this pair of functions in the
 *     header for rnablk_svcctl_freeze().
 */
void
rnablk_svcctl_register()
{
    rnablk_svcctl_t *scp = &rnablk_svcctl;
    unsigned long irqflags;

    rna_spin_lock_irqsave(scp->svc_lock, irqflags);
    while (scp->svc_frozen || scp->svc_freeze_waiters) {
        rna_spin_unlock_irqrestore(scp->svc_lock, irqflags);
        wait_event(scp->svc_wait,
                   (0 == scp->svc_frozen && 0 == scp->svc_freeze_waiters));
        rna_spin_lock_irqsave(scp->svc_lock, irqflags);
    }
    scp->svc_io_users++;
    rna_spin_unlock_irqrestore(scp->svc_lock, irqflags);
}
        
/*
 * rnablk_svcctl_deregister
 *  Used to indicate that I/O initiation has finished.  This function
 *  must always be preceeded by a call to rnablk_svcctl_register().
 *
 * Notes:
 *  1) See general comments about this pair of functions in the
 *     header for rnablk_svcctl_freeze().
 */
void
rnablk_svcctl_deregister()
{
    rnablk_svcctl_t *scp = &rnablk_svcctl;
    unsigned long irqflags;

    rna_spin_lock_irqsave(scp->svc_lock, irqflags);
    if (--scp->svc_io_users == 0) {
        wake_up_all(&scp->svc_wait);
    }
    rna_spin_unlock_irqrestore(scp->svc_lock, irqflags);
}

void
rnablk_ordered_command_completed(struct io_state *ios)
{
    struct rnablk_server_conn *conn = NULL;
    struct io_state *next_ios = NULL;
    unsigned long flags;
    
    rna_spin_lock_irqsave(ios->dev->ordered_cmd_lock, flags);
    if (list_first_entry(&ios->dev->ordered_commands, struct io_state, 
                         ordered_l) != ios) {
        struct io_state *head_ios = 
            list_first_entry(&ios->dev->ordered_commands, 
                             struct io_state, 
                             ordered_l);
        rna_printk(KERN_ERR,
                   "Response to ordered command %p [%s] not at head of "
                   "ordered queue %p [%s]\n", ios, 
                   rnablk_op_type_string(ios->type), head_ios,
                   rnablk_op_type_string(head_ios->type));
        BUG();
    }
    list_del_init(&ios->ordered_l);
    if (!list_empty(&ios->dev->ordered_commands)) {
        next_ios = list_first_entry(&ios->dev->ordered_commands, struct io_state, 
                                    ordered_l);
        conn = rnablk_get_ios_conn(next_ios);
    }
    rna_spin_unlock_irqrestore(ios->dev->ordered_cmd_lock, flags);
    if (NULL != conn) {
        /* Kickstart the next ordered command's queue. */
        rnablk_schedule_conn_dispatch(conn);
    }
}

void
rnablk_track_ordered_command(struct io_state *ios)
{
    unsigned long flags;

    rnablk_trace_ios(ios);
    rna_spin_lock_irqsave(ios->dev->ordered_cmd_lock, flags);
    list_add_tail(&ios->ordered_l, &ios->dev->ordered_commands);
    rna_spin_unlock_irqrestore(ios->dev->ordered_cmd_lock, flags);
}

void
rnablk_dequeue_ordered_command(struct io_state *ios)
{
    unsigned long flags;

    /* 
     * This function is called for disconnect handling.  The ios does NOT
     * need to be at the head of the dev->ordered_commands queue for
     * this to be called.
     */
    rna_spin_lock_irqsave(ios->dev->ordered_cmd_lock, flags);
    BUG_ON(list_empty(&ios->ordered_l));
    list_del_init(&ios->ordered_l);
    rna_spin_unlock_irqrestore(ios->dev->ordered_cmd_lock, flags);
}


/*
 * rnablk_track_ios_debug()
 *  Insert the ios in the global ios_rb_root tree.
 *
 * Notes:
 *  1) See notes in header of rnablk_track_ios_debug() for info regarding
 *     refcnt requirements associated with this operation.
 */
static void
rnablk_track_ios_debug(const char      *function,
                       const char      *location,
                       struct io_state *ios)
{

    unsigned long flags;

    /*
     * Modify tag within lock to synchronize with
     * rnablk_cookie_to_ios_get_debug()
     */
    rna_spin_lock_irqsave(ios->ios_lock, flags);

	UNREFERENCED_PARAMETER(function);
	UNREFERENCED_PARAMETER(location);

    ios->tag = IOS_UPDATE_TAG_GEN(ios, atomic_inc_return(&ios_rb_id));
    rna_spin_unlock_irqrestore(ios->ios_lock, flags);
}

#define rnablk_track_ios(__rti_ios)\
    rnablk_track_ios_debug(__FUNCTION__,__location__,__rti_ios)

/*
 * rnablk_remove_ios_debug()
 *  Remove the ios in the global ios_rb_root tree.
 *
 * Notes:
 *  1) See notes in header of rnablk_remove_ios_debug() for info regarding
 *     refcnt requirements associated with this operation.
 */
static void
rnablk_remove_ios_debug(const char      *function,
                        const char      *location,
                        struct io_state *ios )
{
    unsigned long flags;

	UNREFERENCED_PARAMETER(function);
	UNREFERENCED_PARAMETER(location);

    /* Update tag to ensure a late CS response won't use this ios */
    rna_spin_lock_irqsave(ios->ios_lock, flags);

    ios->tag = IOS_UPDATE_TAG_GEN(ios, atomic_inc_return(&ios_rb_id));

    rna_spin_unlock_irqrestore(ios->ios_lock, flags);
}

#ifdef RNA_USE_IOS_TIMERS
// runs at soft irq level
static void
rnablk_cache_timeout(unsigned long arg)
{
    struct io_state *ios = (struct io_state *)arg;
    struct com_ep *ep;
    boolean can_drop;

    RNABLK_BUG_ON(NULL == ios || NULL == ios->blk,
                  "Bad ios [%p] ios->blk [%p]\n", ios, ios ? ios->blk : NULL);
    ep = (NULL == ios->ep || MD_CONN_EP_METAVALUE == ios->ep)
            ? (MD_CONN_EP_METAVALUE == ios->blk->ep) ? NULL : ios->blk->ep
            : ios->ep;

    can_drop = !IOS_HAS_IOREQ(ios) && (NULL == ep || !com_connected(ep));

    rnablk_trace_ios(ios);
    if (unlikely((net_link_mask & RNABLK_NL_IOS_TIMER))) {
        printnl_atomic("[%d] timeout for ios [%p] tag ["TAGFMT"] "
                       "type [%s] for device [%s] block [%"PRIu64"] "
                       "nr_sectors [%d]\n",
                       current->pid, ios, TAGFMTARGS(ios->tag),
                       rnablk_op_type_string(ios->type),
                       ios->blk->dev->name, ios->blk->block_number, 
                       ios->nr_sectors);
    }

    if (FALSE != atomic_cmpxchg(&ios->ios_timer_fired, FALSE, TRUE)) {
        rna_printk(KERN_WARNING, "Timer fired twice!! for "
                   "ios [%p] type [%s] tag ["TAGFMT"] %s [%p] ep "
                   "[%p] queue_state [%s] for device [%s] block [%"PRIu64"] "
                   "state [%s] ep [%p] ref [%d] pending bios [%d]\n",
                   ios,
                   rnablk_op_type_string(ios->type),
                   TAGFMTARGS(ios->tag),
                   IOS_HAS_REQ(ios) ? "req" : "bio",
                   ios->ios_gen_ioreq,
                   ios->ep,
                   rnablk_ios_q_string(ios_queuestate_get(ios)),
                   ios->blk->dev->name, ios->blk->block_number,
                   rnablk_cache_blk_state_string(ios->blk->state),
                   ios->blk->ep,
                   atomic_read(&ios->ref_count),
                   atomic_read(&ios->pending_bios));
    } else if (rnablk_svcctl_is_frozen() && !can_drop) {
        rna_printk(KERN_NOTICE, "Ignoring timeout during freeze for ios "
                   "[%p] type [%s] tag ["TAGFMT"] %s [%p] ep [%p] "
                   "queue_state [%s] for device [%s] block [%"PRIu64"] "
                   "state [%s] ep [%p] ref [%d] pending bios [%d]\n",
                   ios,
                   rnablk_op_type_string(ios->type),
                   TAGFMTARGS(ios->tag),
                   IOS_HAS_REQ(ios) ? "req" : "bio",
                   ios->ios_gen_ioreq,
                   ios->ep,
                   rnablk_ios_q_string(ios_queuestate_get(ios)),
                   ios->blk->dev->name, ios->blk->block_number,
                   rnablk_cache_blk_state_string(ios->blk->state),
                   ios->blk->ep,
                   atomic_read(&ios->ref_count),
                   atomic_read(&ios->pending_bios));
    } else if (NULL == ep || can_drop) {
        unsigned long irqflags;
        struct cache_blk *blk;
        int qstate;

        rna_printk(KERN_ERR,
                   "timeout for ios [%p] type [%s] tag ["TAGFMT"] %s [%p] "
                   "ios->ep [%p] qstate [%s] for device [%s] block [%"PRIu64"] "
                   "state [%s] blk->ep [%p] ref [%d], not connected, "
                   "dropping\n",
                   ios,
                   rnablk_op_type_string(ios->type),
                   TAGFMTARGS(ios->tag),
                   IOS_HAS_REQ(ios) ? "req" : "bio",
                   ios->ios_gen_ioreq,
                   ios->ep,
                   rnablk_ios_q_string(ios_queuestate_get(ios)),
                   ios->blk->dev->name, ios->blk->block_number,
                   rnablk_cache_blk_state_string(ios->blk->state),
                   ios->blk->ep,
                   atomic_read(&ios->ref_count));
        blk = ios->blk;
        /* save queuestate before the call to rnablk_end_request */
        qstate = ios_queuestate_get(ios);
        rnablk_end_request(ios, -EIO);
        /*
         * If this is an active QUERY to the MD (either for a
         * regular block or the master block), then we need to transition
         * it back to DISCONNECTED state.  Otherwise all future I/O to
         * this blk will end up timing out waiting for it to finish
         * "transitioning".  (Note that we use qstate to decide
         * that this is the "active" QUERY for the block).
         */
        if (RNABLK_MD_QUERY == ios->type
            || RNABLK_LOCK_MASTER_BLK == ios->type) {
            rnablk_lock_blk_irqsave(blk, irqflags);
            if (IOS_QS_DISPATCH == qstate
                && MD_CONN_EP_METAVALUE == blk->ep
                && rnablk_cache_blk_state_transition(blk,
                           RNABLK_CACHE_BLK_CONNECT_PENDING,
                           RNABLK_CACHE_BLK_DISCONNECTED)) {
                /* can call without conn block_list_lock cuz it's the MD */
                rnablk_unset_blk_ep(blk);
            } else {
                rna_printk(KERN_WARNING, "timed out ios [%p] type [%s]"
                           "tag ["TAGFMT"] device [%s] block [%"PRIu64"] "
                           "in unexpected state [%s] ep [%p] qstate [%s]\n",
                           ios, rnablk_op_type_string(ios->type),
                           TAGFMTARGS(ios->tag), ios->blk->dev->name,
                           ios->blk->block_number,
                           rnablk_cache_blk_state_string(ios->blk->state),
                           ios->blk->ep,
                           rnablk_ios_q_string(ios_queuestate_get(ios)));
            }
            rnablk_unlock_blk_irqrestore(blk, irqflags);
        }
    } else {
        rna_printk(KERN_ERR,
                   "timeout for ios [%p] type [%s] tag ["TAGFMT"] %s [%p] "
                   "ios->ep [%p] queue_state [%s] for device [%s] "
                   "block [%"PRIu64"] state [%s] blk->ep [%p] ref [%d]\n",
                   ios,
                   rnablk_op_type_string(ios->type),
                   TAGFMTARGS(ios->tag),
                   IOS_HAS_REQ(ios) ? "req" : "bio",
                   ios->ios_gen_ioreq,
                   ios->ep,
                   rnablk_ios_q_string(ios_queuestate_get(ios)),
                   ios->blk->dev->name, ios->blk->block_number,
                   rnablk_cache_blk_state_string(ios->blk->state),
                   ios->blk->ep,
                   atomic_read(&ios->ref_count));
        print_ep(ep);

        if (com_connected(ep)) {
            rnablk_queue_ios_timeout_conn_disconnect(ios);
        }
    }
    rnablk_ios_release(ios);    // drop the timer reference on ios
}
#endif

void
rnablk_set_ios_timer_debug(const char      *function,
                           const char      *location,
                           struct io_state *ios)
{
#ifdef RNA_USE_IOS_TIMERS
    atomic_set(&ios->ios_timer_fired, 0);
    if (!mod_timer(&ios->tl, RNABLK_IO_EXPIRES)) {
        rnablk_ios_ref_debug(function, location, ios);

        if (unlikely((net_link_mask & RNABLK_NL_IOS_STATE) ||
                     (net_link_mask & RNABLK_NL_IOS_TIMER))) {
            printnl_atomic("[%d] [%s] [%s] setting timer for ios [%p] tag "
                           "["TAGFMT"] type [%s] for device [%s] blk "
                           "[%"PRIu64"]\n",
                           current->pid,
                           function,
                           location,
                           ios,
                           TAGFMTARGS(ios->tag),
                           rnablk_op_type_string(ios->type),
                           ((NULL != ios->blk) ? ios->blk->dev->name : NULL),
                           ((NULL != ios->blk) ? ios->blk->block_number : 0));
        }
    }
#else
	UNREFERENCED_PARAMETER(function);
	UNREFERENCED_PARAMETER(location);
	UNREFERENCED_PARAMETER(ios);
#endif
}

void
rnablk_retrack_ios_debug(const char      *function,
                         const char      *location,
                         struct io_state *ios)
{
    rnablk_track_ios_debug(function, location, ios);
    rnablk_set_ios_timer_debug(function, location, ios);
}

/*
 * rnablk_alloc_ios
 *  Allocate one or more ios structures, along with the associated scatterlists
 *  or cache_cmds as needed.
 *
 * Notes:
 *  1) All ios' need to have a timer started for them, so for most
 *     cases it happens directly in this routine.  However, for the
 *     case where multiple ios' are being allocated to service a single
 *     request (i.e. a bio or a req), we don't want to start the timer
 *     until all the ios' are safely allocated.  Thus we let the higher-level
 *     allocation routine take care of starting the timer for that scenario.
 *
 * Return Value:
 *  Returns 0 on success or a -errno on failure.
 */
int
rnablk_alloc_ios(struct rnablk_device *dev, void *ioreq,
                 int ioreq_type, rsv_access_t min_access,
                 boolean is_io, boolean start_timer,
                 int n_ios, struct io_state **pp_ios)
{
    struct io_state *ios = NULL;
    boolean need_throttle;
    rna_service_mempool_t *mempool;
    rna_service_throttle_t *throttle;
    int n_alloced = 0;
    ENTER;

    if (is_io) {
        BUG_ON(NULL == dev);
        /* we do our own throttling if not using request_queues */
        need_throttle = (!dev_use_req_queue(dev));
        throttle = &rnablk_ios_io_throttle;
        mempool = &rnablk_ios_io_mempool;
    } else {
        need_throttle = TRUE;
        throttle = &rnablk_ios_admin_throttle;
        mempool = &rnablk_ios_admin_mempool;
    }

    if (need_throttle) {
        ret = rna_service_throttle_register(throttle, n_ios,
                                            rnablk_io_timeout * HZ);
        if (0 != ret) {
            if (-EBUSY == ret) {
                rna_printk(KERN_ERR, "failed to allocate I/O state (is_io=%d): "
                           "timed out waiting for memory\n", is_io);
            } else {
                rna_printk(KERN_ERR, "failed to allocate I/O state (is_io=%d): "
                           "err=%d\n", is_io, -ret);
            }
            need_throttle = FALSE;  // turn off so we don't try to "undo"
            GOTO(err, ret);
        }
    }

    for (n_alloced = 0; n_alloced < n_ios; n_alloced++) {
        pp_ios[n_alloced] = ios =
                    (struct io_state *)rna_service_mempool_alloc(mempool, 0);
        if (NULL == ios) {
            rna_printk(KERN_ERR, "failed to allocate I/O state (is_io=%d): "
                       "no memory available\n", is_io);
            GOTO(err, -ENOMEM);
        }

        /*
         * The tag, ios_lock, and magic fields were initialized at module init
         * time when the ios pool was allocated.  Be careful to avoid
         * zero-ing them here!
         * (The tag field was pre-initialized with some fixed data that
         * we don't want to recalculate on each use, and the ios_lock
         * field gets initialized up front because it may be used by
         * callers who have no reference on the ios).
         */
        memset(&ios->blk, 0, sizeof(*ios) - offsetof(struct io_state, blk));
        ios->dev = dev;
        ios->ios_req_type = (uint8_t)ioreq_type;
        ios->ios_gen_ioreq = (void *)ioreq;
        ios->ios_rsv_access = min_access;
        atomic_inc(&ios_count);
        INIT_LIST_HEAD(&ios->l);
        INIT_LIST_HEAD(&ios->ordered_l);

#ifdef RNA_USE_IOS_TIMERS
        init_timer(&ios->tl);
        ios->tl.function = rnablk_cache_timeout;
        ios->tl.data     = (uintptr_t)ios;
        atomic_set(&ios->ios_timer_fired, 0);
#endif
        /* one for request lifetime */
        atomic_set(&ios->ref_count, 1);
        atomic_bit_set(&ios->ios_atomic_flags, IOS_AF_ALLOCATED);
        atomic_set(&ios->ios_connection_failures, 0);

        rnablk_track_ios(ios);

        if (is_io) {
#ifdef WINDOWS_KERNEL
			ios->pOS_Srb = NULL;
            ios->ios_mdl = NULL;
            ios->built_partial_mdl = FALSE;
#else
            ios->sgl = (struct scatterlist *)((char *)ios + sizeof(*ios));
            rna_sg_init_table(ios->sgl, RNA_MAX_SGE);
#endif
            atomic_bit_set(&ios->ios_atomic_flags, IOS_AF_DEVIOCNT);
        } else {
            ios->cmd = (struct cache_cmd *)((char *)ios + sizeof(*ios));
        }
    }

    if (start_timer) {
        /*
         * Wait to set timers until we've got them all allocated...
         */
        for (n_alloced = 0; n_alloced < n_ios; n_alloced++) {
            rnablk_set_ios_timer(ios);
        }
    }

    return 0;

 err:
    for (; n_alloced > 0; n_alloced--) {
        ios = pp_ios[n_alloced-1];
        rna_service_mempool_free(mempool, ios);
    }
    if (need_throttle) {
        rna_service_throttle_deregister(throttle, n_ios);
    }
    EXIT;
}

INLINE void
rnablk_unset_ios_blk_debug(const char      *function,
                           const char      *location,
                           struct io_state *ios)
{
    BUG_ON(NULL==ios);

    if (likely(NULL != ios->blk)) {
        rnablk_cache_blk_iorel_debug(function, location, ios->blk, ios);
        ios->blk = NULL;
    }
}

#define rnablk_unset_ios_blk(__ruib) \
    rnablk_unset_ios_blk_debug(__FUNCTION__,__location__,__ruib)

void
rnablk_set_ios_blk_debug(const char       *function,
                         const char       *location,
                         struct io_state  *ios,
                         struct cache_blk *blk)
{
    struct cache_blk *old_blk = NULL;

    BUG_ON(NULL==ios);

    old_blk = ios->blk;

    if (old_blk == blk) return;

    if (NULL != blk) {
        RNABLK_BUG_ON_BLK((boolean)rnablk_cache_blk_state_is_bogus(blk->state), blk);
        rnablk_cache_blk_ioref_debug(function, location, blk, ios);
        ios->blk = blk;
    }

    if (NULL != old_blk) {
        RNABLK_BUG_ON_BLK((boolean)rnablk_cache_blk_state_is_bogus(old_blk->state), blk);
        rnablk_cache_blk_iorel_debug(function, location, old_blk, ios);
    }
}

#define rnablk_set_ios_blk(__rsii,__rsib) \
    rnablk_set_ios_blk_debug(__FUNCTION__,__location__,__rsii,__rsib)

/*
 * rnablk_remove_ios_from_queue()
 *  Remove the given ios from any queue it may happen to be on.
 */
static void
rnablk_remove_ios_from_queue(struct io_state *ios)
{
    unsigned char oldirql = 0;
    lockstate_t irqflags;
    struct cache_blk *blk = ios->blk;
    struct rnablk_server_conn *conn;
    uint32_t ios_qstate;

    if (blk == NULL) {
        return;
    }

    ios_qstate = ios_queuestate_get(ios);
    if (unlikely(ios_qstate != IOS_QS_NONE)) {
        rna_printk(KERN_WARNING, "forcibly removing ios [%p] tag ["TAGFMT"] "
                   "type [%s] from %s queue\n", ios, TAGFMTARGS(ios->tag),
                   rnablk_op_type_string(ios->type),
                   rnablk_ios_q_string(ios_qstate));
        switch (ios_qstate) {
        case IOS_QS_BLOCK:
            rnablk_lock_blk_irqsave(blk, irqflags);
            /* need to recheck queue_state inside lock */
            if (IOS_QS_BLOCK == ios_queuestate_get(ios)) {
                rnablk_dequeue_blk_io_nolock(blk, ios);
            }
            rnablk_unlock_blk_irqrestore(blk, irqflags);
            break;
        case IOS_QS_DISPATCH:
        case IOS_QS_DISPATCH_FAILED_REDO:
        case IOS_QS_DISPATCH_COMPLETING:
        case IOS_QS_DISPATCH_QUIESCED:
            rnablk_lock_blk_irqsave(blk, irqflags);
            /* need to recheck queue_state inside lock */
            if (ios_qstate == ios_queuestate_get(ios)) {
                rnablk_io_completed_nolock(ios, blk);
            }
            rnablk_unlock_blk_irqrestore(blk, irqflags);
            break;
        case IOS_QS_CONN:
            conn = ios->conn;
            if (NULL != conn) {
                rna_spin_in_stack_lock_irqsave(conn->sc_lock, irqflags);
                /* need to recheck queue_state inside lock */
                if (IOS_QS_CONN == ios_queuestate_get(ios)) {
                    rnablk_dequeue_conn_io(ios);
                }
                rna_spin_in_stack_unlock_irqrestore(conn->sc_lock, irqflags);
            } else {
                rna_printk(KERN_ERR, "unable to remove ios [%p] tag ["TAGFMT"] "
                           "type [%s] from %s queue; no conn\n", ios,
                           TAGFMTARGS(ios->tag),
                           rnablk_op_type_string(ios->type),
                           rnablk_ios_q_string(ios_qstate));
            }
            break;
        case IOS_QS_WFC:
            rna_down_write(&wfc_queue_lock, &oldirql);
            if (IOS_QS_WFC == ios_queuestate_get(ios)) {
                list_del_init(&ios->l);
                RNABLK_BUG_ON(!ios_queuestate_test_and_set(ios,
                                            IOS_QS_WFC, IOS_QS_NONE),
                          "ios [%p] tag ["TAGFMT"] qstate [%d] inconsistent\n",
                          ios, TAGFMTARGS(ios->tag), ios_queuestate_get(ios));
            }
            rna_up_write(&wfc_queue_lock, oldirql);
            break;

        default:
            BUG_ON(TRUE);
            break;
        }
    }
}

static void
rnablk_destroy_io_state_debug(const char      *function,
                              const char      *location,
                              struct io_state *ios)
{
    int has_sgl = FALSE;
    struct rnablk_device *dev = NULL;
    struct cache_blk *blk;

    ENTER;

	UNREFERENCED_PARAMETER(ret);

    rna_printk(KERN_DEBUG,
               "ios [%p] tag ["TAGFMT"] type [%s]\n",
               ios,
               TAGFMTARGS(ios->tag),
               rnablk_op_type_string(ios->type));

    blk = ios->blk;

    RNABLK_BUG_ON(!atomic_bit_test_and_clear(&ios->ios_atomic_flags,
                                             IOS_AF_ALLOCATED),
                  "attempt to destroy ios [%p] tag ["TAGFMT"] type [%s] that's "
                  "already been freed\n", ios, TAGFMTARGS(ios->tag),
                   rnablk_op_type_string(ios->type));

    rnablk_remove_ios_from_queue(ios);

    RNABLK_BUG_ON(unlikely(!list_empty(&ios->l)),
                  "failed attempt to remove ios [%p] tag ["TAGFMT"] type [%s] "
                  "in list\n", ios, TAGFMTARGS(ios->tag),
                   rnablk_op_type_string(ios->type));

    RNABLK_BUG_ON(unlikely(!list_empty(&ios->ordered_l)),
                  "attempt to remove ios [%p] tag ["TAGFMT"] type [%s] in "
                  "ordered list\n",
                   ios,
                   TAGFMTARGS(ios->tag),
                   rnablk_op_type_string(ios->type));

    if (unlikely(net_link_mask & RNABLK_NL_IOS_STATE)) {
        printnl_atomic("[%d] [%s] [%s] freeing ios [%p] tag ["TAGFMT"] type [%s] for device [%s] block [%"PRIu64"] state [%s]\n",
                       current->pid,
                       function,
                       location,
                       ios,
                       TAGFMTARGS(ios->tag),
                       rnablk_op_type_string(ios->type),
                       ((NULL != blk) ? blk->dev->name : NULL),
                       ((NULL != blk) ?  blk->block_number : 0),
                       ((NULL != blk) ?
                       rnablk_cache_blk_state_string(blk->state) : "NO BLOCK"));
    }

    if (unlikely(atomic_bit_is_set(&ios->ios_atomic_flags, IOS_AF_INFLIGHT))) {
        rna_printk(KERN_ERR, "Destroying ios [%p] type [%s] tag ["TAGFMT"] "
                   "device [%s] block [%"PRIu64"] state [%s] that's still "
                   "marked in_flight.\n", ios,
                   rnablk_op_type_string(ios->type), TAGFMTARGS(ios->tag),
                   NULL != blk ? blk->dev->name : NULL,
                   NULL != blk ? blk->block_number : 0,
                   NULL != blk ? rnablk_cache_blk_state_string(blk->state)
                               : "NO BLOCK");
        dec_in_flight(ios->dev, ios);
        // dump_stack();
    }

#ifdef WINDOWS_KERNEL
	if(IOS_HAS_IOREQ(ios)){
		has_sgl = TRUE;
	}
#else
    if(ios->sgl) {
        has_sgl = TRUE;
    }
#endif /*WINDOWS_KERNEL*/

    rnablk_unset_ios_ep(ios);

    /* this has to happen before rnablk_unset_ios_blk */
    if (NULL == blk) {
        dev = ios->dev;
    } else {
        dev = blk->dev;
    }

    rnablk_unset_ios_blk(ios);

#ifdef WINDOWS_KERNEL
    if (ios->built_partial_mdl) {
        IoFreeMdl(ios->ios_mdl);
        ios->ios_mdl = NULL;
        ios->built_partial_mdl = FALSE;
    }
#endif /*WINDOWS_KERNEL*/

    /* this seems like overkill,
     * especialy now that it is in the completion path
     */
#if 0
    memset( ios, 0, sizeof( *ios ) ); // make use-after-free easier to spot
#endif
    if (has_sgl) {
        BUG_ON(NULL == dev);
        rna_service_mempool_free(&rnablk_ios_io_mempool, ios);
        if (!dev_use_req_queue(dev)) {
            rna_service_throttle_deregister(&rnablk_ios_io_throttle, 1);
        }
    } else {
        rna_service_mempool_free(&rnablk_ios_admin_mempool, ios);
        rna_service_throttle_deregister(&rnablk_ios_admin_throttle, 1);
    }

    atomic_dec(&ios_count);

    EXITV;
}

#define rnablk_destroy_io_state(__rdi_ios)\
    rnablk_destroy_io_state_debug(__FUNCTION__,__location__,__rdi_ios)

static void
rnablk_end_bio(struct io_state *ios, int error)
{
#ifdef WINDOWS_KERNEL
    UNREFERENCED_PARAMETER(ios);
    UNREFERENCED_PARAMETER(error);
#else
    struct bio *bio;

    BUG_ON(NULL == ios);
    RNABLK_BUG_ON(!IOS_HAS_BIO(ios), "ios=%p no bio?\n", ios);

    bio = ios->bio;

    rna_printk (KERN_INFO,
                "ios [%p] tag ["TAGFMT"] bio [%p] ref_count [%d]\n",
                ios,
                TAGFMTARGS(ios->tag),
                bio,
                atomic_read(&ios->ref_count));

    // Decrement ref count on BIO
    if (likely(rnablk_atomic_dec_and_test_bio_refcount(bio))) {
        BUG_ON(atomic_read(&ios->pending_bios) > 0);

        /* avoid access to BIO after it is completed */
        ios->bio = NULL;
        ios->ios_req_type = IOREQ_TYPE_NOREQ;
        bio->bi_private = ios->bio_private;
        if (atomic_bit_is_set(&ios->ios_atomic_flags, IOS_AF_DEVIOCNT)) {
            rnablk_dec_device_iocnt(ios->dev, ios_writes_data(ios));
        }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
        bio_endio(bio, error);
#else
        bio_endio(bio, 0, error);
#endif
    } else if (error < 0) {
        /* retain the error status even though we can't complete it yet! */
        clear_bit(BIO_UPTODATE, &bio->bi_flags);
    }
#endif /*WINDOWS_KERNEL*/
}

// runs in both kthread and softirq context
void
rnablk_end_request(struct io_state *ios, int error)
{
    ENTER;

	UNREFERENCED_PARAMETER(ret);

    rnablk_trace_ios(ios);

    if (unlikely(!IOS_HAS_IOREQ(ios))) {
        if (error) {
            rna_printk(KERN_ERR, "end ios [%p] tag ["TAGFMT"] (no block "
                       "request) err [%d]\n",
                       ios, TAGFMTARGS(ios->tag), error );
        }
    } else if (IOS_HAS_BIO(ios)) {
        rnablk_end_bio(ios, error);
    } else if (IOS_HAS_SPC(ios)) {
        rnablk_end_special(ios, error);
    } else {
        rnablk_end_req(ios, error);
    }
    /* and we are done with this ios! */
    rnablk_ios_finish(ios);

    EXITV;
}

void
rnablk_set_ios_io_type(struct io_state *ios)
{
    switch (ios->ios_iotype) {
    case IOS_IOTYPE_READ:
        ios->type = RNABLK_RDMA_READ;
        break;

    case IOS_IOTYPE_WRITE:
        ios->type = RNABLK_RDMA_WRITE;
        break;

    case IOS_IOTYPE_COMP_WR:
        ios->type = RNABLK_COMP_AND_WRITE;
        break;

    case IOS_IOTYPE_WRITE_SAME:
        ios->type = RNABLK_WRITE_SAME;
        break;

    default:
        RNABLK_BUG_ON(TRUE, "unexpected iotype [%d] ios [%p] block [%llu]\n",
                      ios->ios_iotype, ios, ios->blk->block_number);
    }
}

void
rnablk_set_ios_blk_ep(struct io_state *ios)
{
    BUG_ON(NULL == ios);
    BUG_ON(NULL == ios->blk);

    if ((NULL != ios->blk->cb_dev_conn) && rnablk_conn_connected(ios->blk->cb_dev_conn)) {
        rna_printk(KERN_INFO, "ios [%p] type [%s] tag ["TAGFMT"] block [%llu]: "
                   "using device conn ["CONNFMT"] EP [%p]\n",
                   ios,
                   rnablk_op_type_string(ios->type),
                   TAGFMTARGS(ios->tag),
                   ios->blk->block_number,
                   CONNFMTARGS(ios->blk->cb_dev_conn),
                   ios->blk->cb_dev_conn->ep);
        rnablk_set_ios_ep(ios, ios->blk->cb_dev_conn->ep);
    } else {
        rna_printk(KERN_INFO, "ios [%p] type [%s] tag ["TAGFMT"] block [%llu]: "
                   "not using device conn ["CONNFMT"]\n",
                   ios,
                   rnablk_op_type_string(ios->type),
                   TAGFMTARGS(ios->tag),
                   ios->blk->block_number,
                   CONNFMTARGS(ios->blk->cb_dev_conn));
        rnablk_set_ios_ep(ios, ios->blk->ep);
    }
}

/*
 * Process all requests you can in current block state, initiating
 * transition, if needed.
 *
 * Caller holds block's lock
 */
void
rnablk_cache_blk_drain_nolock(struct cache_blk * blk, lockstate_t * irqflags)
{
    struct io_state * ios;
    int rc = 0;

    if (atomic_bit_is_set(&blk->cb_flags, BLK_F_DISCONN_FROZEN)) {
        /*
         * Don't kick off any I/O while blk is in the "FROZEN" state;
         * it will be taken care by the code path responsible for the freeze.
         */
        return;
    }

    /* protect block with ref, as we may drop lock */
    rnablk_cache_blk_ref(blk);
    while (dev_io_allowed(blk->dev) && !list_empty(&blk->bl)) {
        if (unlikely(rnablk_cache_blk_state_is_transitional(blk->state))) {
            // if the cache blk is in transition, wait for it to drain later
            break;
        }
        ios = list_first_entry( &blk->bl,struct io_state,l );
        rnablk_trace_ios(ios);
        rnablk_dequeue_blk_io_nolock(blk, ios);
        if (IOS_HAS_IOREQ(ios)) {
            // Reprocess request, triggering ref change if necessary
            if (IOS_IOTYPE_NONE != ios->ios_iotype) {
                /* normal I/O */
                rc = rnablk_process_blk_io(ios, irqflags);
                if (-ENOLCK == rc) {
                    /* lock was dropped to dispatch i/o to flash */
                    rnablk_lock_blk_irqsave(blk, *irqflags);
                    /*
                     * since we start at the head of the list at each iteration
                     * it's OK to just continue here.
                     */
                } else if (unlikely(rc)) {
                    /*
                     * had to reconnect/upgrade block reference, will drain
                     * rest of queue when done
                     */
                    break;
                }
            } else {
                rnablk_set_ios_ep(ios, ios->blk->ep);
                rnablk_queue_or_dispatch(rnablk_get_ios_conn(ios), ios,
                                         FORCE_QUEUED_IO);
            }
        } else {
            rnablk_ios_finish(ios);
        }
    }
    rnablk_cache_blk_release(blk);
}

void
rnablk_cache_blk_drain(struct cache_blk * blk)
{
    lockstate_t flags;
    
    rnablk_cache_blk_ref(blk);
    rnablk_lock_blk_irqsave(blk, flags);
    rnablk_cache_blk_drain_nolock(blk, &flags);
    rnablk_unlock_blk_irqrestore(blk, flags);
    rnablk_start_blk_io(blk, TRUE);
    rnablk_cache_blk_release(blk);
}

/*
 * Returns 1 if block state changed, 0 otherwise
 * Caller MUST hold block's bl_lock
 * Caller MUST call rnablk_start_blk_io() if they want IO to be dispatched
 */
static int
rnablk_process_blk_io(struct io_state  *ios, lockstate_t *irqflags)
{
	struct cache_blk *blk = ios->blk;
    int ret = 0;

    RNABLK_BUG_ON(NULL == blk, "ios=%p NULL blk\n", ios);
    rnablk_trace_ios(ios);

    /*
     * Retrack here to a) set the timer, and b) in case this I/O is being
     * reissued, may need to clear the 'response' bit.
     */
    rnablk_retrack_ios(ios);

    if (!dev_io_allowed(ios->dev)) {
        rnablk_queue_blk_io_nolock(blk, ios, QUEUE_TAIL);
    } else if (0 != rnablk_ios_rsv_access_check(ios)) {
        rna_printk(KERN_RSV, "ios access check failed: ios [%p] "
                   "block [%"PRIu64"] need access [%s] client access [%s]\n",
                   ios, ios->blk->block_number,
                   rsv_access_string(ios->ios_rsv_access),
                   rsv_access_string(ios->dev->rbd_rsv.rrs_client_access));
        rnablk_end_request(ios, -EBUSY);
    } else if (rnablk_state_ok_for_req(blk, ios)) {
        if (rnablk_ios_uses_local_dma(ios)) {
            rnablk_cache_blk_ref(blk);
            /* drops block lock */
            rnablk_dispatch_dma_io(ios, irqflags);

            rnablk_cache_blk_release(blk);
            /* indicate that lock was dropped */
            ret = -ENOLCK;

        } else {
            /* we have the block state we need.  queue this request */
            queue_io_request(ios,
                             blk,
                             FORCE_QUEUED_IO);
        }
    } else if (unlikely(atomic_read(&blk->dev->failed))) {
        // we won't be able to get new blocks, so just fail the IO
        rna_printk(KERN_INFO,
                   "Failing io on bad device [%s] ios [%p] tag ["TAGFMT"] "
                   "block [%llu]\n", blk->dev->name, ios,
                   TAGFMTARGS(ios->tag), blk->block_number);
        rnablk_end_request(ios, -EIO);
    } else {
        ret = rnablk_get_blk_state_for_io(blk, ios);
    }

    return ret;
}

void
rnablk_process_request(struct io_state *ios)
{
    lockstate_t flags;
    struct cache_blk *blk;
    int rc;

    BUG_ON(NULL == ios);

    rna_printk(KERN_INFO, "IOS [%p]\n", ios);
    rnablk_trace_ios(ios);

#ifdef WINDOWS_KERNEL
    DoStorageTraceEtw(DbgLvlPerf, 
                      FldcVsmpSRBPerf, 
                      "rnablk_process_request: SRB=0x%I64X  ios=%p\n",
                      ios->SRBNumber, ios); 
#endif

    blk = rnablk_cache_blk_find_or_create(ios->dev, ios->start_sector,
                                          ios_writes_data(ios));

#ifdef WINDOWS_KERNEL
    DoStorageTraceEtw(DbgLvlPerf, FldcVsmpSRBPerf, "rnablk_process_request: SRB=0x%0I64X  ios=%p  blk=%p\n",
        ios->SRBNumber, ios, blk); 
#endif


    if (likely(NULL != blk)) {
        rnablk_ios_ref(ios);
        rnablk_lock_blk_irqsave(blk, flags);
        rnablk_set_ios_blk(ios, blk);

        rc = rnablk_process_blk_io(ios, &flags);
        if (-ENOLCK != rc) {
            rnablk_unlock_blk_irqrestore(blk, flags);
        }
        rnablk_start_blk_io(blk, (NULL != ios->ep));

        if (ios_writes_data(ios)) {
            (void)rna_atomic64_inc_return(&ios->dev->stats.bs_write_hits);
        } else {
            (void)rna_atomic64_inc_return(&ios->dev->stats.bs_read_hits);
        }

        rnablk_ios_release(ios);
        /* Drop the ref from rnablk_cache_blk_find_or_create() */
        rnablk_cache_blk_release(blk);
    } else {
        rnablk_end_request(ios, -ENOMEM);
    }
}

struct io_state *
rnablk_cookie_to_ios_get_debug(const char *function, const char *location,
                               ios_tag_t tag, boolean is_response)
{
    struct io_state *ios = NULL, *ret_ios = NULL;
    unsigned long flags;

    ios = IOS_TAG_TO_IOS(tag);
    RNABLK_BUG_ON(tag & 1, "Bad ios tag cookie has bit 0 set! ios [%p] tag "
                  "["TAGFMT"] cookie ["TAGFMT"]\n", ios,
                  ios ? TAGFMTARGS(ios->tag) : 0, TAGFMTARGS(tag));
    if (!rna_os_validate_kvaddr(ios)) {
        rna_printk(KERN_ERR, "Bad ios tag translates to bogus ios [%p] "
                  "cookie ["TAGFMT"]: bad virtual address, ignoring\n", ios,
                  tag);
        ios = NULL;
    } else if (ios->ios_magic != RNABLK_IOS_MAGIC) {
        rna_printk(KERN_ERR, "Bad ios tag translates to bogus ios [%p] "
                  "cookie ["TAGFMT"]: bad magic, ignoring\n", ios, tag);
        ios = NULL;
    }
    if (NULL != ios) {
        rna_spin_lock_irqsave(ios->ios_lock, flags);
        if (ios->tag == tag) {
            ret_ios = ios;
            if (is_response) {
                /*
                 * Set the response bit in the tag to protect against duplicate
                 * responses from CS
                 */
                ios->tag |= 1;
            }
            rnablk_ios_ref_debug(function, location, ios);
        } else if (is_response) {
            rna_printk(KERN_WARNING, "Received response with stale generation "
                       "for ios [%p] tag ["TAGFMT"] cookie ["TAGFMT"]\n",
                       ios, TAGFMTARGS(ios->tag), TAGFMTARGS(tag));
        }
        rna_spin_unlock_irqrestore(ios->ios_lock, flags);
    }
    return ret_ios;
}

//
// runs in kthread context
static void rnablk_schedule_destroy_ios_wf(rnablk_workq_cb_arg_t arg)
{
    struct work_struct *work = (struct work_struct *)arg;
    struct rnablk_work *w = container_of( work,struct rnablk_work,work );
    struct rnablk_schedule_destroy_ios_wf_data *wd = &w->data.rwd_rnablk_schedule_destroy_ios_wf;
    struct io_state *ios = wd->ios;
    uint64_t start_seconds = get_seconds();
    ENTER;

	UNREFERENCED_PARAMETER(ret);

    BUG_ON(NULL==ios);

    rnablk_mempool_free(w, work_cache_info);
    rnablk_destroy_io_state(ios);
    rnablk_finish_workq_work(start_seconds);

    EXITV;
}

INLINE void rnablk_schedule_destroy_ios(struct io_state *ios)
{
    struct rnablk_work *w = NULL;
    struct rnablk_schedule_destroy_ios_wf_data *wd = NULL;
    ENTER;

	UNREFERENCED_PARAMETER(ret);

    BUG_ON(NULL==ios);

    if (likely(NULL != (w = rnablk_mempool_alloc(work_cache_info)))) {
        RNABLK_INIT_RNABLK_WORK(w, wd, rnablk_schedule_destroy_ios_wf);
        wd->ios = ios;
        rna_queue_work(mt_workq, &w->work);
    } else {
        rna_printk(KERN_WARNING,
                   "Failed to alloc work object to destroy "
                   "ios [%p] tag ["TAGFMT"] will do son inline\n",
                   ios,
                   TAGFMTARGS(ios->tag));
        rnablk_destroy_io_state(ios);
    }
}

/*
 * rnablk_ios_release_debug
 *  Decrement the refcount of an ios, freeing it if refcount goes to zero.
 *  (Note that rnablk_ios_finish() should be used to 'complete' an ios;
 *  see the header for rnablk_ios_finish() for more information!).
 */
void
rnablk_ios_release_debug(const char      *function,
                         const char      *location,
                         struct io_state *ios)
{
    //unsigned long flags;
    //int           ref_count;

    BUG_ON(NULL == ios);

    rnablk_trace_ios(ios);
    RNABLK_BUG_ON(atomic_read(&ios->ref_count) <= 0,
                  "ios [%p] tag ["TAGFMT"] type [%s]\n", ios,
                  TAGFMTARGS(ios->tag),
                  rnablk_op_type_string(ios->type));

    if (unlikely((net_link_mask & RNABLK_NL_IOS_STATE) ||
                 (net_link_mask & RNABLK_NL_IOS_REF))) {
        printnl_atomic("ios_release [%d] [%s] [%s] ios [%p] tag ["TAGFMT"] "
                       "type [%s] ref count [%d]\n",
                       current->pid,
                       function,
                       location,
                       ios,
                       TAGFMTARGS(ios->tag),
                       rnablk_op_type_string(ios->type),
                       atomic_read(&ios->ref_count));
    }
    if (0 == atomic_dec_return(&ios->ref_count)) {
        /* last reference gone, delete IOS */
#ifdef RNA_USE_IOS_TIMERS
        RNABLK_BUG_ON(timer_pending(&ios->tl),
                      "ios_finish not called for ios=%p type [%s] blk "
                      "[%llu] state [%s]\n", ios,
                      rnablk_op_type_string(ios->type),
                      ios->blk->block_number,
                      rnablk_cache_blk_state_string(ios->blk->state));
#endif /* RNA_USE_IOS_TIMERS */

        rnablk_destroy_io_state(ios);

    }
}

/*
 * rnablk_remove_ios_from_wfc()
 *  Remove the given ios from the wfc_queue if it's in the queue,
 *  setting the blk state of the block it's associated with back to
 *  DISCONNECTED.
 *
 * Notes:
 *  1) The reason we need to do this is because of the functionality
 *     related to rnablk_queue_ios_conn_check().  Since this queued 
 *     work item holds a reference on the ios, the ios will not get
 *     destroyed if we end up "finishing" the ios (i.e. due to a timeout
 *     for example).  Thus it will remain in the wfc_queue and be
 *     inappropriately processed when it is no longer in the correct
 *     state for said processing.
 *
 * Return Value;
 *      Returns TRUE if the ios was removed from the wfc_queue and the
 *      device associated with the ios is still valid, otherwise FALSE.
 */
boolean
rnablk_remove_ios_from_wfc(struct io_state *ios)
{
    struct rnablk_server_conn *conn;
    unsigned char oldirql = 0;
    mutexstate_t mutex_handle;
    lockstate_t irqflags;
    boolean in_wfc = FALSE;

    if (IOS_QS_WFC == ios_queuestate_get(ios)) {
        rna_down_write(&wfc_queue_lock, &oldirql);
        if (IOS_QS_WFC == ios_queuestate_get(ios)) {
            list_del_init(&ios->l);
            in_wfc = TRUE;
            RNABLK_BUG_ON(!ios_queuestate_test_and_set(ios,
                          IOS_QS_WFC, IOS_QS_NONE),
                      "ios [%p] tag ["TAGFMT"] qstate [%d] inconsistent\n",
                      ios, TAGFMTARGS(ios->tag), ios_queuestate_get(ios));
        }
        rna_up_write(&wfc_queue_lock, oldirql);
    }

    if (in_wfc) {
        conn = ios->blk->cb_conn;
        RNABLK_BUG_ON(NULL == conn, "ios [%p] device [%s] block [%llu] has "
                      "NULL conn when in wfc queue\n", ios, ios->dev->name,
                      ios->blk->block_number);

        /*
         * Drop this block's reference to the cache device.  Since the blk is
         * not connected, and we'll be starting over with an MD query,
         * the blk shouldn't be affiliated with a cachedev.
         */
        rna_block_mutex_lock(&conn->block_list_lock, &mutex_handle);
        rnablk_lock_blk_irqsave(ios->blk, irqflags);
        rnablk_blk_put_cachedev(ios->blk, conn);
        if (unlikely(atomic_read(&ios->blk->dev->failed))) {
            /* we don't want the calling function to attempt reconnect */
            in_wfc = FALSE;

            rna_printk(KERN_NOTICE, "ending ios [%p] tag ["TAGFMT"] type [%s] "
                       "for failed device [%s] block [%"PRIu64"] state [%s]\n",
                       ios,
                       TAGFMTARGS(ios->tag),
                       rnablk_op_type_string(ios->type),
                       ios->blk->dev->name,
                       ios->blk->block_number,
                       rnablk_cache_blk_state_string(ios->blk->state));
            (void)rnablk_cache_blk_state_transition(ios->blk,
                                  RNABLK_CACHE_BLK_CONNECT_PENDING,
                                  RNABLK_CACHE_BLK_DISCONNECTED);
            rnablk_unlock_blk_irqrestore(ios->blk, irqflags);
            rna_block_mutex_unlock(&conn->block_list_lock, &mutex_handle);
            rnablk_end_request(ios, -EIO);
        } else {
            RNABLK_BUG_ON(!rnablk_cache_blk_state_transition(ios->blk,
                          RNABLK_CACHE_BLK_CONNECT_PENDING,
                          RNABLK_CACHE_BLK_DISCONNECTED)
                          && ios->blk->state != RNABLK_CACHE_BLK_DISCONNECTED,
                          "device [%s] ios [%p] type [%s] block [%llu] "
                          "unexpected state [%s]\n", ios->blk->dev->name,
                          ios, rnablk_op_type_string(ios->type),
                          ios->blk->block_number,
                          rnablk_cache_blk_state_string(ios->blk->state));
            rna_printk(KERN_INFO, "ios [%p] tag ["TAGFMT"] type [%s] "
                       "device [%s] block [%"PRIu64"] state [%s] timed out"
                       "from wfc_queue\n",
                       ios,
                       TAGFMTARGS(ios->tag),
                       rnablk_op_type_string(ios->type),
                       ios->blk->dev->name,
                       ios->blk->block_number,
                       rnablk_cache_blk_state_string(ios->blk->state));
            rnablk_unlock_blk_irqrestore(ios->blk, irqflags);
            rna_block_mutex_unlock(&conn->block_list_lock, &mutex_handle);
        }
    }

    return in_wfc;
}

/*
 * rnablk_ios_finish_debug
 *  This routine should be called when an ios "finishes".  Meaning, the
 *  i/o operation associated with it is completely done, i.e. there is
 *  no more processing to be done for the ios wrt to its associated
 *  i/o operation.
 *  Note however that it may not end up being the last current reference
 *  on the ios, in which case, the ios won't be freed here.  However, it
 *  will still always do "cleanup" on the ios. (Currently cleanup
 *  simply entails canceling the ios timer and removing the ios from the
 *  ios rbtree).
 */
void
rnablk_ios_finish_debug(const char *function,
                        const char *location,
                        struct io_state *ios)
{
    /*
     * Normal case, ios won't be in any queue at this point.
     * However, sometimes when it times out, it could be...
     * Do this before doing the clear of the timer, to accomodate
     * code paths that walk an ios list resetting the timer (when they
     * don't actually hold a reference on the ios's in the list!).
     * This will make sure we unset the newly reset timer if they beat us
     * and find the ios in the list just before we get here...
     */
    rnablk_remove_ios_from_queue(ios);

#ifdef RNA_USE_IOS_TIMERS
    (void)rnablk_clear_ios_timer(ios);
#endif /* RNA_USE_IOS_TIMERS */

    rnablk_remove_ios_debug(function, location, ios);   // remove from tree

    if (unlikely(atomic_bit_is_set(&ios->ios_atomic_flags,
                                   IOS_AF_MASTER_LOCK))) {
        /*
         * If this ios was used to do a LOCK_MASTER_BLK, unregister
         * it now so new LOCK_MASTER_BLK's can be issued...
         */
        rnablk_master_lock_unregister(ios->blk);
        atomic_bit_clear(&ios->ios_atomic_flags, IOS_AF_MASTER_LOCK);
    }

    /* release the reference from creation of ios */
    rnablk_ios_release_debug(function, location, ios);
}

void
rnablk_dequeue_ios_generic(struct io_state *ios, int ios_queue)
{
    BUG_ON(NULL == ios);
    rnablk_trace_ios(ios);

    if (likely(ios_queuestate_test_and_set(ios, ios_queue, IOS_QS_NONE))) {
        rna_printk(KERN_DEBUG,
                   "ios [%p] tag ["TAGFMT"] type [%s] dequeued from %s queue\n",
                   ios,
                   TAGFMTARGS(ios->tag),
                   rnablk_op_type_string(ios->type),
                   rnablk_ios_q_string(ios_queue));
        BUG_ON(list_empty(&ios->l));
        list_del_init(&ios->l);
    } else {
        RNABLK_BUG_ON(TRUE, "ios [%p] tag ["TAGFMT"] type [%s] : "
                   "unexpected queue_state=%s (expected=%s)\n",
                   ios,
                   TAGFMTARGS(ios->tag),
                   rnablk_op_type_string(ios->type),
                   rnablk_ios_q_string(ios_queuestate_get(ios)),
                   rnablk_ios_q_string(ios_queue));
    }
}

void
rnablk_queue_ios_generic(struct io_state *ios, int ios_queue,
                         struct list_head *list, queue_where_t where)
{
    BUG_ON(NULL == ios);
    RNABLK_BUG_ON(NULL == ios->blk || NULL == ios->dev,
                  "ios=%p type=%s has NULL dev [%p] or NULL blk [%p]\n",
                  ios, rnablk_op_type_string(ios->type), ios->dev, ios->blk);
    rnablk_trace_ios(ios);

    if (likely(ios_queuestate_test_and_set(ios, IOS_QS_NONE, ios_queue))) {
        rna_printk(KERN_DEBUG,
                   "ios [%p] tag ["TAGFMT"] type [%s] queued to %s queue\n",
                   ios,
                   TAGFMTARGS(ios->tag),
                   rnablk_op_type_string(ios->type),
                   rnablk_ios_q_string(ios_queue));
        BUG_ON(!list_empty(&ios->l));
        if (unlikely(QUEUE_HEAD == where)) {
            list_add(&ios->l, list);
        } else {
            list_add_tail(&ios->l, list);
        }
    } else {
        RNABLK_BUG_ON(TRUE,
                   "ios [%p] tag ["TAGFMT"] type [%s] : unexpected queue "
                   "state=%s (expected=%s)\n",
                   ios,
                   TAGFMTARGS(ios->tag),
                   rnablk_op_type_string(ios->type),
                   rnablk_ios_q_string(ios_queuestate_get(ios)),
                   rnablk_ios_q_string(IOS_QS_NONE));
    }
}

// Caller must hold ios->blk's bl_lock
//
// Takes reference on block, which is released in rnablk_io_completed_nolock()
void
rnablk_io_dispatched_nolock(struct io_state  *ios,
                            struct cache_blk *blk)
{
    BUG_ON(NULL == ios);
    BUG_ON(NULL == blk);

    rnablk_queue_ios_generic(ios, IOS_QS_DISPATCH, &blk->dispatch_queue,
                             QUEUE_TAIL);
}

void
rnablk_io_dispatched(struct io_state *ios)
{
    lockstate_t flags;

    BUG_ON(NULL == ios);

    rnablk_lock_blk_irqsave(ios->blk, flags);
    rnablk_io_dispatched_nolock(ios, ios->blk);
    RNABLK_BUG_ON(unlikely(atomic_read(&ios->blk->cb_ioref_cnt) < 1),
                  "ios [%p] tag ["TAGFMT"] type [%s] refers to block "
                  "[%"PRIu64"] of dev [%s] that may be about to become "
                  "unreferenced\n",
                  ios, TAGFMTARGS(ios->tag), rnablk_op_type_string(ios->type),
                  ios->blk->block_number, ios->dev->name);
    rnablk_unlock_blk_irqrestore(ios->blk, flags);
}

// Caller must hold ios->blk's bl_lock
//
// Releases reference on block obtained in rnablk_io_dispatched_nolock()
void
rnablk_io_completed_nolock(struct io_state  *ios,
                           struct cache_blk *blk)
{
    int qstate;

    BUG_ON(NULL == ios);
    BUG_ON(NULL == blk);

    qstate = ios_queuestate_get(ios);
    RNABLK_BUG_ON(qstate != IOS_QS_DISPATCH
                  && qstate != IOS_QS_DISPATCH_FAILED_REDO
                  && qstate != IOS_QS_DISPATCH_COMPLETING
                  && qstate != IOS_QS_DISPATCH_QUIESCED,
                  "blk=%p ios=%p unexpected qstate=%d\n", blk, ios, qstate);
    rnablk_dequeue_ios_generic(ios, qstate); 
    if (unlikely(atomic_bit_is_set(&ios->ios_atomic_flags, IOS_AF_INFLIGHT))) {
        rna_printk(KERN_INFO,
                   "removing ios [%p] tag ["TAGFMT"] type [%s] for device [%s] "
                   "block [%"PRIu64"] marked in_flight\n",
                   ios,
                   TAGFMTARGS(ios->tag),
                   rnablk_op_type_string(ios->type),
                   ((blk->dev != NULL) ? blk->dev->name : NULL),
                   blk->block_number);
    }
}

void rnablk_io_completed (struct io_state *ios)
{
    lockstate_t flags;

    BUG_ON(NULL == ios);

    rnablk_lock_blk_irqsave(ios->blk, flags);
    rnablk_io_completed_nolock(ios, ios->blk);
    RNABLK_BUG_ON(unlikely(atomic_read(&ios->blk->cb_ioref_cnt) < 1),
                   "ios [%p] tag ["TAGFMT"] type [%s] refers to block "
                   "[%"PRIu64"] of dev [%s] refcnt ["BLKCNTFMT"] that may "
                   "be about to become unreferenced\n",
                   ios, TAGFMTARGS(ios->tag), rnablk_op_type_string(ios->type),
                   ios->blk->block_number, ios->dev->name,
                   BLKCNTFMTARGS(ios->blk));
    rnablk_unlock_blk_irqrestore(ios->blk, flags);
}

void
rnablk_update_io_stats(struct io_state *ios)
{
    int sectors;
    int bytes;

    BUG_ON(NULL == ios->dev);
    BUG_ON(NULL == ios->blk);

    sectors = ios->nr_sectors;
    bytes = sectors << RNABLK_SECTOR_SHIFT;

    switch (ios->ios_iotype) {
    case IOS_IOTYPE_WRITE_SAME:
        ios->dev->stats.bytes_out += bytes;
        ios->dev->stats.writes++;
        ios->blk->last_write_secs = get_seconds();
        break;

    case IOS_IOTYPE_WRITE:
        ios->dev->stats.bytes_out += bytes;
        ios->dev->stats.writes++;
        ios->blk->last_write_secs = get_seconds();
        break;

    case IOS_IOTYPE_READ:
        ios->dev->stats.bytes_in += bytes;
        ios->dev->stats.reads++;
        ios->blk->last_read_secs = get_seconds();
        if (rnablk_ios_uses_local_dma(ios)) {
            ios->dev->stats.direct_reads++;
        }
        break;

    case IOS_IOTYPE_COMP_WR:
        /* 
         * Single command that does a read and write 
         */
        ios->dev->stats.bytes_out += bytes;
        ios->dev->stats.bytes_in += bytes;
        ios->blk->last_write_secs = get_seconds();
        ios->blk->last_read_secs = ios->blk->last_write_secs;
        ios->dev->stats.writes++;
        ios->dev->stats.reads++;
        break;

    }
    rnablk_device_update_histogram(ios->dev, sectors);
}

/*
 * rnablk_handle_ios_leak()
 *  This routine is passed as an argument to rna_service_mempool_destroy()
 *  to do cleanup when there is an ios leak (and also to report info
 *  to help track down the leak).
 */
static void
rnablk_handle_ios_leak(void *void_ios)
{
    struct io_state *ios = (struct io_state *)void_ios;

    if (atomic_bit_is_clear(&ios->ios_atomic_flags, IOS_AF_ALLOCATED)) {
        return;
    }
    rna_printk(KERN_WARNING, "Found leaked ios [%p] type [%s] refcnt [%d] "
               "flags [%#x] %s [%p] block [%llu] state [%s] ref [%s] "
               "refcnt ["BLKCNTFMT"] flags [%#x]\n", ios,
               rnablk_op_type_string(ios->type),
               atomic_read(&ios->ref_count),
               atomic_read(&ios->ios_atomic_flags),
               IOS_HAS_BIO(ios) ? "bio" : IOS_HAS_REQ(ios) ? "req" :
               IOS_HAS_SPC(ios) ? "spc" : "noreq", ios->ios_gen_ioreq,
               ios->blk->block_number,
               rnablk_cache_blk_state_string(ios->blk->state),
               get_lock_type_string(ios->blk->ref_type),
               BLKCNTFMTARGS(ios->blk), ios->blk->cb_identity_flags);
#ifdef RNA_USE_IOS_TIMERS
    /* make sure the timer doesn't fire after we've freed the memory! */
    (void)del_timer(&ios->tl);
#endif /* RNA_USE_IOS_TIMERS */
//    RNABLK_DBG_BUG_ON(TRUE, "BUGCHECK to track down ios leak: ios [%p]\n", ios);

    return;
}

