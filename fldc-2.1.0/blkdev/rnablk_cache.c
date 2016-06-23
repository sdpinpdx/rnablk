/**
 * <rnablk_cache.c> - Dell Fluid Cache block driver
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
#include "platform.h"
#include "trace.h"
#include "rnablk_util.h"
#include "rnablk_globals.h"
#include "rnablk_system.h"
#include "rnablk_queue_dispatch.h"
#include "rnablk_device.h"
#include "rnablk_cache.h"
#include "rnablk_io_state.h"
#include "rnablk_protocol.h"
#include "rnablk_comatose.h" // for rnablk_stop_devs and rnablk_start_devs

#ifdef WINDOWS_KERNEL
#include "rna_vsmp.h"
#include "rnablk_win_com.h"
#include "rnablk_win_util.h"
#include <stdio.h>
#endif /*WINDOWS_KERNEL*/

#if defined(LINUX_KERNEL) || defined(LINUX_USER)
//This is a nasty workaround to make both windows and linux happy. Copied the LIST_HEAD Define from Linux list.h
#undef LIST_HEAD
#define LIST_HEAD(name)  struct list_head name = LIST_HEAD_INIT(name)
#endif

/* private globals */
atomic_t rnablk_n_cachedevs = {0};    // # of cache-devices client is aware of

#ifdef WINDOWS_KERNEL
struct _LIST_ENTRY wfc_queue = {&(wfc_queue), &(wfc_queue)};
#else
LIST_HEAD( wfc_queue );           // wait for connection queue
#endif //WINDOWS_KERNEL

static void
rnablk_free_server_conn_struct(struct rnablk_server_conn *conn)
{
#if defined(RNABLK_VERIFY_CONN_BY_MAGIC)
    conn->front_magic = 0;
    conn->back_magic = 0;
#endif                
    conn->rsc_parent_conn = NULL;
    kfree(conn);
}

/*
 * _rnablk_server_conn_put()
 *  This routine should always be used to drop a reference on
 *  a 'conn'.  It ensures that the conn structure gets freed if the
 *  count drops to 0.
 *
 * Notes:
 *  1) There is currently no counterpart rnablk_server_conn_get() routine
 *     for adding a reference to the conn.  Rather, users may simply do
 *     an atomic_inc() on the conn->rsc_refcount field directly.
 */
void
_rnablk_server_conn_put_debug(const char *func, const int line,
                              struct rnablk_server_conn *conn)
{
    RNABLK_BUG_ON(atomic_read(&conn->rsc_refcount) <= 0,
                  "conn ["CONNFMT"] refcount going negative!\n",
                  CONNFMTARGS(conn));
    if (0 == atomic_dec_return(&conn->rsc_refcount)) {
        rna_printk(KERN_INFO, "(%s:%d) Freeing conn ["CONNFMT"]\n",
                   func, line, CONNFMTARGS(conn));
        rnablk_free_server_conn_struct(conn);
    } else {
        rna_printk(KERN_INFO, "(%s:%d) dec ref for conn ["CONNFMT"] now "
                   "refcnt=%d\n", func, line, CONNFMTARGS(conn),
                   atomic_read(&conn->rsc_refcount));
    }
}

#ifdef WINDOWS_KERNEL
extern PComLayerManagerObj GetDriverComLayerManager();
extern uint64_t msecs_to_jiffies(const unsigned int m);
#endif /*WINDOWS_KERNEL*/

rna_service_mutex_t conn_cleanup_mutex;

/*
 * This value is quite important, and was determined as such:
 * The bounding factor on the time to quiesce a failed device appears to be
 * the time it takes for the Micron driver to give up on failed I/Os.
 *
 * Our initial calculation of the maximum time to fail has not held
 * water in the real world, therefor we have updated it to account for
 * our empirical evidence, which is that I/O can take 90 seconds to fail.
 * We decided to add a little overhead for safety.
 */
#define RNABLK_CACHE_DEV_QUIESCE_TIMEOUT_SECS 120
#define RNABLK_CACHE_DEV_QUIESCE_WAIT_INTERVAL_MSECS 100
#define RNABLK_CACHE_DEV_MAX_QUIESCE_ATTEMPTS \
    ((RNABLK_CACHE_DEV_QUIESCE_TIMEOUT_SECS * MSEC_PER_SEC)/ \
     RNABLK_CACHE_DEV_QUIESCE_WAIT_INTERVAL_MSECS)

static void rnablk_queue_retry_connect(struct rnablk_server_conn *conn);

static boolean rnablk_conn_quiesce_and_disconnect(
                                   struct rnablk_server_conn *conn,
                                   rnablk_cachedev_t *cachedev,
                                   char *reason,
                                   boolean check_for_waiters,
                                   int n_quiesces);

static void rnablk_restart_conn_blks(struct rnablk_server_conn *conn,
                         rnablk_cachedev_t *cachedev,
                         boolean ok_to_restart);

static void rnablk_cleanup_conn_blks(struct rnablk_server_conn *conn,
                         rnablk_cachedev_t *cachedev);
static void rnablk_cleanup_conn_waiters(struct rnablk_server_conn * conn);

static void rnablk_cleanup_conn_ioq(struct rnablk_server_conn *conn,
                        rnablk_cachedev_t *cachedev);

static boolean rnablk_quiesce_dispatch_queue(struct rnablk_server_conn *conn,
                              rnablk_cachedev_t *cachedev, int n_quiesces);

static void rnablk_conn_blks_sort_list(struct rnablk_server_conn *conn,
                           rnablk_cachedev_t *cachedev);


INLINE int rnablk_ios_waiting_conn(struct io_state           *ios,
                                          struct rnablk_server_conn *conn)
{
    BUG_ON(NULL == ios);
    BUG_ON(NULL == conn);

    return(conn->id.u.hash == ios->cs_ep_key);
}

static void rnablk_disconnect_timeout( unsigned long arg )
{
    struct rnablk_device *dev = (struct rnablk_device *)arg;
    ENTER;

	UNREFERENCED_PARAMETER(ret);
	
    dev->disconnect_expired = 1;

    EXITV;
}

struct rna_blk_disconnect_cache_ctx {
    int                   announced;
    int                   announced_tag;
    struct rnablk_device *dev;
};

int
rnablk_disconnect_cache_cb(struct rnablk_server_conn *conn,
                           void                      *context)
{
    struct io_state *ios = NULL;
    struct list_head *pos = NULL;
    int found = FALSE;
    lockstate_t flags;

    struct rna_blk_disconnect_cache_ctx * ctx = context;
	rna_spin_in_stack_lock_irqsave(conn->sc_lock, flags);
    list_for_each( pos,&conn->io_queue ) {
        ios = list_entry( pos,struct io_state,l );
        if( ios->dev == ctx->dev ) {
            found = TRUE;
            rnablk_ios_ref(ios);
            break;
        }
    }
    rna_spin_in_stack_unlock_irqrestore(conn->sc_lock, flags);

    if( found ) {
        if (!ctx->announced || (ios->tag != ctx->announced_tag)) {
            ctx->announced = 1;
            rna_printk(KERN_ERR, "waiting for queued operations on dev [%s] "
                       "conn ["CONNFMT"] ios [%p] tag ["TAGFMT"] type [%s] "
                       "block [%llu] state [%s]\n", ctx->dev->name,
                       CONNFMTARGS(conn), ios, TAGFMTARGS(ios->tag),
                       rnablk_op_type_string(ios->type), ios->blk->block_number,
                       rnablk_cache_blk_state_string(ios->blk->state));
        }
        rnablk_next_request(conn);
        rnablk_ios_release(ios);
    }
    return found;
}

void
rnablk_disconnect_cache(struct rnablk_device *dev)
{
    int announced = 0;
    int found = FALSE;
    struct rna_blk_disconnect_cache_ctx ctx;
    unsigned char oldirql = 0;

    ENTERV;

    ctx.announced = FALSE;
    ctx.announced_tag = 0;
    ctx.dev = dev;

    if( !dev_is_persistent(dev) && dev_is_freeable(dev)) {
        /* We only invalidate blocks for freeable scratchpad devices */
        rna_printk(KERN_ERR, "invalidating blocks on dev [%s]\n", dev->name);
        rnablk_invalidate_cache_blks( dev );
        rna_printk(KERN_ERR, "done invalidating blocks on dev [%s]\n", dev->name);
    } else {
        rna_printk(KERN_ERR, "freeing blocks on dev [%s]\n", dev->name);
        rnablk_free_cache_blks(dev, FALSE);
        rna_printk(KERN_ERR, "done freeing blocks on dev [%s]\n", dev->name);
    }

    /* 
     * Search all connection objects for queued operations for this device.
     * Wait for these to complete. 
     */
    rna_down_read(&svr_conn_lock, &oldirql);
    do {
        found = rnablk_cache_foreach(&cache_conn_root,
                                      rnablk_disconnect_cache_cb,
                                     &ctx);
        msleep( 100 );
    } while (found);
    rna_up_read(&svr_conn_lock, oldirql);

    if (ctx.announced) {
        rna_printk(KERN_ERR, "done waiting for queued operations on dev [%s]\n", dev->name);
    }

    /* wait for all in-flight io to be completed */
    dev->disconnect_timer.function = rnablk_disconnect_timeout;
    dev->disconnect_timer.data     = (uint64_t)dev;

    /* Windows specific version of mod_timer in Rnablk_system_windows.c */
    mod_timer( &dev->disconnect_timer, RNABLK_DISCONN_EXPIRES );

    announced = 0;
    while( !dev->disconnect_expired && atomic_read( &dev->stats.in_flight ) > 0 ) {
        if (!announced) {
            announced = 1;
            rna_printk(KERN_ERR, "waiting for in-flight operations on dev [%s]\n", dev->name);
        }
        msleep_interruptible( 100 );
    }

    if (announced) {
        rna_printk(KERN_ERR, 
                   "done waiting for in-flight operations on dev [%s] ([%d] remain)\n", 
                   dev->name, atomic_read(&dev->stats.in_flight));
    }

    /* Windows specific version of del_timer_sync in Rnablk_system_windows.c */
    del_timer_sync( &dev->disconnect_timer );
    msleep( 100 );

    EXITV;
}

/*
 * rnablk_init_null_structs()
 *  Initialize placeholder null_cachedev, null_device, and null_blk data
 *  structures.
 *  (See comments where these structures are declared for more info about
 *  how these are used).
 */
void
rnablk_init_null_structs(void)
{
    memset(&null_cachedev, 0, sizeof(null_cachedev));
    atomic_bit_set(&null_cachedev.rcd_state, RCD_STATE_ONLINE);
    INIT_LIST_HEAD(&null_cachedev.rcd_link);
    blk_lru_list_init(&null_cachedev.rcd_block_list, 0);

    memset(&null_device, 0, sizeof(null_device));
    strncpy(null_device.name, "(null device)", sizeof(null_device.name));
    null_device.magic = RNABLK_DEVICE_MAGIC;
    INIT_LIST_HEAD(&null_device.l);
    INIT_LIST_HEAD(&null_device.rbd_blk_list);
    atomic_set(&null_device.stats.status, RNABLK_CACHE_ONLINE);
    null_device.dv_master_blk = &null_blk;
    /*
     * Need to mark as a persistent device to ensure that
     * rnablk_generic_completion() doesn't try to call
     * rnablk_mark_cache_blk_bad_and_drain() for the null_device on
     * error.
     */
    dev_set_persistent(&null_device);
    
    memset(&null_blk, 0, sizeof(null_blk));
    null_blk.blk_cachedev = &null_cachedev;
    null_blk.dev = &null_device;
    INIT_LIST_HEAD(&null_blk.bl);
    INIT_LIST_HEAD(&null_blk.dispatch_queue);
    blk_lru_list_init(&null_blk.cb_conn_lru, 0);
    blk_lru_list_init(&null_blk.cb_conn_wref, 1);
    INIT_LIST_HEAD(&null_blk.cb_conn_wlru);
    blk_lru_list_init(&null_blk.cb_conn_lru, 0);
    blk_lru_list_init(&null_blk.cb_conn_wref, 1);
    INIT_LIST_HEAD(&null_blk.cb_dev_link);
    rna_spin_lock_init(null_blk.bl_lock);
    /*
     * Give it 2 permanent references (including one from an io ref)
     * so that it never looks "unused" (by virtue of the ioref), and
     * it never gets freed (see rnablk_cache_blk_release_debug -- which
     * checks for refcnt of 2).
     */
    rnablk_cache_blk_ref(&null_blk);
    rnablk_cache_blk_ioref(&null_blk, NULL);
    null_blk.block_number = (uint64_t)-1;
    null_blk.ref_type = CACHE_NO_REFERENCE;
    null_blk.state = RNABLK_CACHE_BLK_DISCONNECTED;
    null_blk.dev_counts_state = RNABLK_CACHE_BLK_DISCONNECTED;
}

rnablk_cachedev_t *
rnablk_get_conn_cachedev(struct rnablk_server_conn *conn,
                         cachedev_id_t cachedev_id,
                         boolean do_insert) // insert new entry if not found
{
    rnablk_cachedev_t *new_cdp = NULL, *cdp;
    struct list_head *ent;
    boolean did_create = FALSE;
    lockstate_t irq_flags;
    int i;

    for(;;) {
        rna_spin_in_stack_lock_irqsave(conn->sc_lock, irq_flags);
        list_for_each(ent, &conn->rsc_cachedevs) {
            cdp = list_entry(ent, rnablk_cachedev_t, rcd_link);
            if (cachedev_id == cdp->rcd_id) {
                goto found;
            }
        }

        if (new_cdp) {
            cdp = new_cdp;
            list_add_tail(&cdp->rcd_link, &conn->rsc_cachedevs);
            atomic_inc(&rnablk_n_cachedevs);
            did_create = TRUE;
            goto found;
        }

        rna_spin_in_stack_unlock_irqrestore(conn->sc_lock, irq_flags);

        if (!do_insert) {   // not found and we aren't supposed to add it...
            break;
        }
#ifdef WINDOWS_KERNEL
		new_cdp = (rnablk_cachedev_t *)ExAllocatePoolWithTag(NonPagedPool, sizeof(rnablk_cachedev_t), RNA_ALLOC_TAG);
        if (new_cdp) {
		    RtlZeroMemory(new_cdp, sizeof(rnablk_cachedev_t));  
        }
#else
        new_cdp = kzalloc(sizeof(*new_cdp), GFP_KERNEL);
#endif

        if (!new_cdp) {
            rna_printk(KERN_ERR, "conn ["CONNFMT"] Error allocating memory "
                       "for cachedev %"PRIx64"\n",
                       CONNFMTARGS(conn), cachedev_id);
            break; 
        }
        INIT_LIST_HEAD(&new_cdp->rcd_link);
        blk_lru_list_init(&new_cdp->rcd_block_list, 0);
        new_cdp->rcd_id = cachedev_id;
        new_cdp->rcd_server_conn = conn;
        atomic_bit_set(&new_cdp->rcd_state, RCD_STATE_ONLINE);
        /* initial reference is for being in rsc_cachedevs list */
        atomic_set(&new_cdp->rcd_refcount, 1);
        /*
         * rcd_online_refs is used to determine when we can safely
         * offline the cache-device in the event of a failure.
         * It is incremented once for each per-cachedev connection, and
         * once (here) for actually being online.  It must go to zero
         * (i.e. all connections have been disconnected/cleaned-up, and
         * it has actually been marked offline before we can do the
         * offline processing.
         */
        atomic_set(&new_cdp->rcd_online_refs, 1);

        /* set up per cache-device connections */
        for (i = 0; i < rnablk_per_device_connections; i++) {
            new_cdp->rcd_conns[i] = rnablk_make_server_conn(&conn->id,
                                                            &conn->if_table,
                                                            conn,
                                                            new_cdp,
                                                            i + 1);
        }
    }

    return NULL;        // not found (or, potentially, failed to allocate)

 found:
    atomic_inc(&cdp->rcd_refcount);
    rna_spin_in_stack_unlock_irqrestore(conn->sc_lock, irq_flags);

    if (did_create) {
        /* may want to be silent for cachedev "0" (the "uncache cachedev") */
        rna_printk(KERN_NOTICE, "Instantiating cachedev [%#"PRIx64"] on "
                   "CS ["CONNADDRFMT"]\n", cachedev_id,
                   CONNADDRFMTARGS(conn));
        if (0 != cachedev_id) {
            /*
             * Don't let the "un-cachedev" affect the throttle limit.
             * Also, let's not create connections for it up front.
             * They'll be created if/when needed, but since in normal
             * cached mode we won't be doing real I/O to it, connections
             * may not be needed at all.
             */
            rna_service_throttle_change_limit(&rnablk_ios_io_throttle,
                                              atomic_read(&rnablk_n_cachedevs)
                                              * rnablk_io_queue_depth);
            for (i = 0; i < rnablk_per_device_connections; i++) {
                if (cdp->rcd_conns[i]) {
                    rnablk_queue_retry_connect(cdp->rcd_conns[i]);
                }
            }
        }
    } else if (NULL != new_cdp) {
        for (i = 0; i < rnablk_per_device_connections; i++) {
            if (new_cdp->rcd_conns[i]) {
                rnablk_server_conn_put(new_cdp->rcd_conns[i]);
            }
        }
        kfree(new_cdp);
    }
    return cdp;
}

void
rnablk_put_cachedev(rnablk_cachedev_t *cachedev)
{
    cachedev_id_t cachedev_id;
    struct rnablk_server_conn *conn;
    int i;
#ifdef WINDOWS_KERNEL
    struct rnablk_local_dev *ldev = NULL;
    struct list_head *pos;
    struct list_head *tmp;
    KLOCK_QUEUE_HANDLE lockHandle;
#endif

    if (0 == atomic_dec_return(&cachedev->rcd_refcount)) {
        /* last reference, so free the structure */
        rna_printk(KERN_INFO, "Discarding cachedev [%#"PRIx64"] cdp [%p] "
                   "conn ["CONNFMT"]\n", cachedev->rcd_id, cachedev,
                   CONNFMTARGS(cachedev->rcd_server_conn));
        RNABLK_BUG_ON(!list_empty(&cachedev->rcd_link), "cachedev=%p being "
                      "freed but still in list?\n", cachedev);
        RNABLK_BUG_ON(!blk_lru_list_empty(&cachedev->rcd_block_list),
                      "cachedev=%p being freed but has blocks in list?\n",
                      cachedev);
        for (i = 0; i < RNABLK_MAX_DEV_CONNS; i++) {
            if (NULL != cachedev->rcd_conns[i]) {
                conn = cachedev->rcd_conns[i];
                RNABLK_BUG_ON((boolean)rnablk_conn_connected(conn),
                              "Freeing cachedev=%p with connected "
                              "conns[%d]=%p\n",
                              cachedev, i, conn);
                rnablk_server_conn_put(conn);
            }
        }
        cachedev_id = cachedev->rcd_id;
        kfree(cachedev);
        atomic_dec(&rnablk_n_cachedevs);
        if (0 != cachedev_id) { // the "un-cachedev" doesn't affect throttle
            rna_service_throttle_change_limit(&rnablk_ios_io_throttle,
                                              atomic_read(&rnablk_n_cachedevs)
                                              * rnablk_io_queue_depth);
        }

#ifdef WINDOWS_KERNEL
        // Free the Windows local device object when the cache device is removed.
        KeAcquireInStackQueuedSpinLock(&local_dev_lock, &lockHandle);
        list_for_each_safe(pos, tmp, &local_dev_list) {
            ldev = list_entry(pos, struct rnablk_local_dev, entry);
            if (CacheDevIdEqual(ldev->id, cachedev_id)) {
                FreeLocalDevice(ldev);
                break;
            }
        }
        KeReleaseInStackQueuedSpinLock(&lockHandle);
#endif /* WINDOWS_KERNEL */

    }
}

/*
 * caller must hold conn block_list_lock
 */
INLINE void
rnablk_cache_blk_insert_lru_locked(struct rnablk_server_conn *conn,
                                   struct cache_blk *blk, boolean is_write)
{
    rnablk_cachedev_t *cdp;
    //int wref;

    RNABLK_BUG_ON(is_null_cachedev(blk->blk_cachedev), "conn ["CONNFMT"] "
                  "unexpected null cachedev for blk [%p] block [%llu] "
                  "state [%s]\n", CONNFMTARGS(conn), blk, blk->block_number,
                  rnablk_cache_blk_state_string(blk->state));
    RNABLK_DBG_BUG_ON(!blk_lru_list_empty(&blk->cb_conn_lru),
                      "blk [%p] block [%llu] state [%s] already in "
                      "lru list?\n", blk, blk->block_number,
                      rnablk_cache_blk_state_string(blk->state));

    cdp = blk->blk_cachedev;
    rnablk_cache_blk_ref(blk);  // add a ref to the blk for being in the list
    conn->block_list_length++;
    blk->cb_ref_time = get_jiffies();

    if (blk_lru_list_empty(&cdp->rcd_block_list)) {
        conn->rsc_lru_oldest_ts = blk->cb_ref_time;
    }
    blk_lru_list_add_tail(&blk->cb_conn_lru, &cdp->rcd_block_list);
    if (is_write) {
        blk->cb_write_time = blk->cb_ref_time;
        if (list_empty(&conn->rsc_wlru_list)) {
            conn->rsc_wlru_oldest_ts = blk->cb_write_time;
        }
        blk_lru_list_add_tail(&blk->cb_conn_wref,
                              &cdp->rcd_block_list);
        list_add_tail(&blk->cb_conn_wlru, &conn->rsc_wlru_list);
    }
}

/*
 * rnablk_blk_get_cachedev
 *
 * Return value:
 *  Returns 0 on success or a negative errno on failure.
 */
int
rnablk_blk_get_cachedev(struct cache_blk *blk,
                        cachedev_id_t cachedev_id,
                        struct rnablk_server_conn *conn,
                        boolean is_write)
{

    struct rnablk_server_conn *old_conn;
    rnablk_cachedev_t *cachedev;
    lockstate_t irq_flags;
    mutexstate_t mutex_lock_handle;
    mutexstate_t old_mutex_lock_handle;

    RNABLK_DBG_BUG_ON(NULL != blk->ep && (MD_CONN_EP_METAVALUE == blk->ep
                      || conn != rnablk_get_ep_conn(blk->ep)),
                      "conn mismatch for blk [%p] block [%llu] "
                      "ep [%p] conn ["CONNFMT"]\n", blk, blk->block_number,
                      blk->ep, CONNFMTARGS(conn));

    cachedev = rnablk_get_conn_cachedev(conn, cachedev_id, TRUE);
    if (NULL == cachedev) {
        return -ENOMEM;
    }

    rna_block_mutex_lock(&conn->block_list_lock, &mutex_lock_handle);
    rnablk_lock_blk_irqsave(blk, irq_flags);

    while (!is_null_cachedev(blk->blk_cachedev)) {
        RNABLK_DBG_BUG_ON(0 != blk->blk_cachedev->rcd_id,
                          "not expecting blk to have real cachedev yet! "
                          "blk [%p] block [%llu] state [%s] cacheid [%"PRIx64"]"
                          "\n", blk, blk->block_number,
                          rnablk_cache_blk_state_string(blk->state),
                          blk->blk_cachedev->rcd_id);
        if (blk->cb_conn != conn) {
            old_conn = blk->cb_conn;
            rnablk_unlock_blk_irqrestore(blk, irq_flags);
            rna_block_mutex_unlock(&conn->block_list_lock, &mutex_lock_handle);
            rna_block_mutex_lock(&old_conn->block_list_lock, &old_mutex_lock_handle);
            rnablk_lock_blk_irqsave(blk, irq_flags);
            if (blk->cb_conn == old_conn) {
                rnablk_blk_put_cachedev(blk, old_conn);
            }
            rnablk_unlock_blk_irqrestore(blk, irq_flags);
            rna_block_mutex_unlock(&old_conn->block_list_lock, &old_mutex_lock_handle);
            rna_block_mutex_lock(&conn->block_list_lock, &mutex_lock_handle);
            rnablk_lock_blk_irqsave(blk, irq_flags);
            if (!is_null_cachedev(blk->blk_cachedev)) {
                rna_printk(KERN_WARNING,
                           "blk still has cachedev! blk [%p] block [%llu] "
                           "state [%s] cacheid [%"PRIx64"]\n",
                           blk, blk->block_number,
                           rnablk_cache_blk_state_string(blk->state),
                           blk->blk_cachedev->rcd_id);
            }
        } else {
            rnablk_blk_put_cachedev(blk, conn);
        }
    }

    blk->cb_conn = conn;
    blk->blk_cachedev = cachedev;
    rnablk_cache_blk_insert_lru_locked(conn, blk, is_write);

    rnablk_unlock_blk_irqrestore(blk, irq_flags);
    rna_block_mutex_unlock(&conn->block_list_lock, &mutex_lock_handle);

    return 0;
}

/*
 * rnablk_blk_put_cachedev
 *  Drop blk reference on rnablk_cachedev_t (and switch block instead
 *  to reference the 'null_cachedev'.
 *
 * Notes:
 *  1. Caller must hold blk's bl_lock and its conn's block_list_lock.
 */
void
rnablk_blk_put_cachedev(struct cache_blk *blk, struct rnablk_server_conn *conn)
{
    rnablk_cachedev_t *cachedev;

#ifndef WINDOWS_KERNEL
    RNABLK_BUG_ON_BLK(!spin_is_locked(&blk->bl_lock.lock), blk);
#endif /*WINDOWS_KERNEL*/
    if (NULL != conn) {
        RNABLK_DBG_BUG_ON(!is_parent_conn(conn), "blk [%p] block [%llu] "
                          "conn ["CONNFMT"] not parent conn!\n", blk,
                          blk->block_number, CONNFMTARGS(conn))

        if (!is_null_cachedev(blk->blk_cachedev)) {
            cachedev = blk->blk_cachedev;
            RNABLK_DBG_BUG_ON(NULL != blk->ep &&
                              conn != rnablk_get_ep_conn(blk->ep),
                              "blk [%p] block [%llu] conn ["CONNFMT"] "
                              "ep [%p] - mismatched conn\n", blk,
                              blk->block_number, CONNFMTARGS(conn), blk->ep);
            RNABLK_DBG_BUG_ON(!rna_block_mutex_is_locked(
                              &conn->block_list_lock),
                              "blk [%p] block [%llu] conn ["CONNFMT"] - "
                              "mutex not locked\n", blk, blk->block_number,
                              CONNFMTARGS(conn));
            rnablk_cache_blk_unlink_lru_locked(conn, blk, FALSE);
            blk->blk_cachedev = &null_cachedev;
            rnablk_put_cachedev(cachedev);
        }
    }
    return;
}

/*
 * rnablk_drop_dev_conns()
 *  Initiate a disconnect for all the CS connections associated with the
 *  given cache-device.
 */
static void
rnablk_drop_dev_conns(rnablk_cachedev_t *cachedev)
{
    int i;

    rnablk_trc_discon(1, "Drop all conns for cachedev=%"PRIx64"\n",
                      cachedev->rcd_id);
    for (i = 0; i < RNABLK_MAX_DEV_CONNS; i++) {
        if (NULL != cachedev->rcd_conns[i]) {
            rnablk_drop_connection(cachedev->rcd_conns[i]);
        }
    }
    return;
}

/*
 * rnablk_drop_dev_conns_wf()
 *  Queued routine to initiate disconnects for all CS connections
 *  associated with a cache-device.
 *
 * runs in kthread context
 */
static void
rnablk_drop_dev_conns_wf(rnablk_workq_cb_arg_t arg)
{
    struct work_struct *work = (struct work_struct *)arg;
    struct rnablk_work *w = container_of( work,struct rnablk_work,work );
    struct rnablk_drop_dev_conns_wf_data *wd =
                                    &w->data.rwd_rnablk_drop_dev_conns_wf;
    uint64_t start_seconds = get_seconds();
    ENTERV;

    rnablk_drop_dev_conns(wd->cachedev);
    rnablk_put_cachedev(wd->cachedev);  // drop the ref added when queued
    
    rnablk_mempool_free(w, work_cache_info);
    rnablk_finish_workq_work(start_seconds);

    EXITV;
}


/*
 * rnablk_queue_drop_dev_conns()
 *  Queue a task to initiate disconnects for all CS connections
 *  associated with a cache-device.
 *
 * runs in kthread context
 */
static void
rnablk_queue_drop_dev_conns(rnablk_cachedev_t *cachedev)
{
    struct rnablk_work *w = NULL;
    struct rnablk_drop_dev_conns_wf_data *wd = NULL;

    if (!atomic_read(&shutdown)) {
        w = rnablk_mempool_alloc(work_cache_info);
        if (NULL == w) {
            rna_printk(KERN_ERR, "failed to alloc work queue object");
        } else {
            RNABLK_INIT_RNABLK_WORK(w, wd, rnablk_drop_dev_conns_wf);
            atomic_inc(&cachedev->rcd_refcount);
            wd->cachedev = cachedev;
            rna_queue_work(mt_workq, &w->work);
        }
    }
}


/*
 * rnablk_offline_conn_cachedev()
 *  Mark the specified cache-device as offline if currently online, and
 *  remove it from its conn linkage if 'is_expel' is true.
 *
 * Notes:
 *  1) This routine expects to be called only with the "parent" conn.
 *
 * Return value:
 *  Returns TRUE if the cache-device was originally online, otherwise FALSE.
 */
static boolean
rnablk_offline_conn_cachedev(struct rnablk_server_conn *conn,
                             rnablk_cachedev_t *cachedev,
                             boolean is_expel) 
{
    lockstate_t irq_flags;
    boolean was_online;

    RNABLK_BUG_ON(!is_parent_conn(conn), "Expected parent: conn ["CONNFMT"] "
                  "p_conn [%p]\n", CONNFMTARGS(conn), conn->rsc_parent_conn);

    rna_printk(KERN_ERR, "Offline conn ["CONNFMT"] cachedev [%#"PRIx64"] "
               "is_expel=%d online=%d expelled=%d\n", CONNFMTARGS(conn),
               cachedev->rcd_id, is_expel,
               atomic_bit_is_set(&cachedev->rcd_state, RCD_STATE_ONLINE),
               atomic_bit_is_set(&cachedev->rcd_state, RCD_STATE_EXPELLED));
    rna_spin_in_stack_lock_irqsave(conn->sc_lock, irq_flags);
    RNABLK_BUG_ON(cachedev->rcd_server_conn != conn, "conn=%p cachedev=%p "
                  "rcd_server_conn=%p is_expel=%d\n", conn, cachedev,
                  cachedev->rcd_server_conn, is_expel);
    RNABLK_BUG_ON(list_empty(&cachedev->rcd_link) && is_expel,
                  "conn=%p cachedev=%p expel & not in list?\n", conn,
                  cachedev);
    was_online = atomic_bit_test_and_clear(&cachedev->rcd_state,
                                           RCD_STATE_ONLINE);
    if (was_online) {
        /* make sure we kill per cache-device connections */
        rnablk_trc_discon(1, "Queue drop_dev_conns for cachedev=%"PRIx64"\n",
                          cachedev->rcd_id);
        rnablk_queue_drop_dev_conns(cachedev);
    }

    if (is_expel) {
        atomic_bit_set(&cachedev->rcd_state, RCD_STATE_EXPELLED);
        list_del_init(&cachedev->rcd_link);
        rna_spin_in_stack_unlock_irqrestore(conn->sc_lock, irq_flags);
        /* drop conn's reference on the cachedev struct */
        rnablk_put_cachedev(cachedev);
    } else {
        rna_spin_in_stack_unlock_irqrestore(conn->sc_lock, irq_flags);
    }
    return was_online;
}

/*
 * rnablk_do_offline_cache_device
 *  Offline a cache-device and do clean-up for cached blocks associated
 *  with that cache-device.
 *  IMPORTANT: This routine should only be called by the wrapper function
 *  rnablk_initiate_offline_cache_device()!
 *
 *  Notes:
 *      1) Note this routine is modeled after rnablk_process_conn_disconnect().
 *      2) This routine must only be called with the main CS conn, not
 *         with any cache-dev conns.
 *      3) This routine returns TRUE if the offline of the cache device is
 *         complete. "Complete" effectively means that all outstanding
 *         I/O associated with this cache device has been successfully
 *         'quiesced'.  If it hasn't been, then this function returns FALSE
 *         and it is the responsibility of the caller to requeue it
 *         so the work can be finished up.
 *      4) We use rnablk_svcctl_freeze() to freeze I/O activity for the
 *         duration of offline processing.  This means that if
 *         we wind up in the two-stage FAIL/EXPEL scenario (where we end up
 *         doing this work twice -- see header comments for
 *         rnablk_initiate_offline_cache_device() for more details),
 *         then we instigate the freeze at the beginning of the first call,
 *         and keep it in effect until the end of the second call.
 *
 * Return Value:
 *  Returns TRUE if the offline of the cache_device is complete, otherwise
 *  FALSE.  (See note above).
 */
static boolean
rnablk_do_offline_cache_device(struct rnablk_server_conn *conn,
                               rnablk_cachedev_t *cachedev,
                               boolean is_expel,
                               int n_quiesces)
{
    char reason_str[64];
    boolean ok_to_restart;
    boolean initial_offline;
    mutexstate_t  mutex_lock_handle;
    boolean is_quiesced;

    rna_printk(KERN_NOTICE, "Perform OFFLINE of cachedev [%#"PRIx64"] "
               "on CS ["CONNADDRFMT"] (expel=%d) n_quiesces=%d\n",
               cachedev->rcd_id, CONNADDRFMTARGS(conn), is_expel, n_quiesces);

    RNABLK_BUG_ON(!is_parent_conn(conn), "expected primary CS conn "
                  "conn ["CONNFMT"] p_conn [%p]\n", CONNFMTARGS(conn),
                  conn->rsc_parent_conn);

    snprintf(reason_str, sizeof(reason_str), " for cachedev [%#"PRIx64"]",
             cachedev->rcd_id);

    if (0 == n_quiesces) {
        rnablk_svcctl_freeze();
    }
    rna_service_mutex_lock(&conn_cleanup_mutex);
    
    if (0 == n_quiesces) {
        rna_printk(KERN_NOTICE, "stop devs\n");
        rnablk_stop_devs();
    }

    rna_block_mutex_lock(&conn->block_list_lock, &mutex_lock_handle);

    is_quiesced = rnablk_conn_quiesce_and_disconnect(conn, cachedev,
                                            reason_str, FALSE, n_quiesces);

    if (is_quiesced) {
        ok_to_restart = (!atomic_read(&shutdown)
                         && atomic_read(&rna_service_detached)
                            != RNA_SERVICE_DETACHED_SHUTDOWN);

        if (is_expel) {
            rna_printk(KERN_NOTICE, "restart conn blocks%s\n", reason_str);
            rnablk_restart_conn_blks(conn, cachedev, ok_to_restart);
        }

        rna_block_mutex_unlock(&conn->block_list_lock, &mutex_lock_handle);

        if (ok_to_restart) {
            rna_printk(KERN_NOTICE, "start devs\n");
            rnablk_start_devs(is_expel ? conn : NULL, FALSE);
        }

        /*
         * If this call resulted from CACHE_FAIL_CACHE_DEVICE processing,
         * then we need to keep frozen from now until the end of
         * EXPEL processing.  On the other hand, it could be that there
         * was no CACHE_FAIL_CACHE_DEVICE message, and we only get an EXPEL.
         * Determine which case it is and either do the freeze that will
         * be held til EXPEL, or (in the case of the EXPEL), release
         * the previously acquired freeze if needed.
         */
        initial_offline = atomic_bit_test_and_set(&cachedev->rcd_state,
                                                  RCD_STATE_IS_OFFLINED);

        if (!is_expel) {
            RNABLK_BUG_ON(!initial_offline, "cachedev=%p already FROZEN? "
                          "is_expel=%d\n", cachedev, is_expel);
            rnablk_svcctl_freeze();
            atomic_bit_set(&cachedev->rcd_state, RCD_STATE_FROZEN);
        } else if (!initial_offline) {
            atomic_bit_clear(&cachedev->rcd_state, RCD_STATE_FROZEN);
            rnablk_svcctl_unfreeze();
        }

        rnablk_svcctl_unfreeze();

        rna_printk(KERN_ERR, "OFFLINE of cachedev [%#"PRIx64"] on "
                   "CS ["CONNADDRFMT"] completed (expel=%d)\n",
                   cachedev->rcd_id, CONNADDRFMTARGS(conn), is_expel);

        if (!is_expel) {
            /*
             * Now we can send the FAIL_CACHE_DEVICE handshake response for
             * the parent connection.  This will allow the cache server to
             * proceed with its end of the offline processing.
             */
            rnablk_send_fail_cachedev(conn, cachedev->rcd_id, TRUE);
        }
    } else {
        rna_block_mutex_unlock(&conn->block_list_lock, &mutex_lock_handle);
        rna_printk(KERN_WARNING, "OFFLINE of cachedev [%#"PRIx64"] on "
                   "CS ["CONNADDRFMT"] (expel=%d) still quiescing\n",
                   cachedev->rcd_id, CONNADDRFMTARGS(conn), is_expel);
    }
    rna_service_mutex_unlock(&conn_cleanup_mutex);
    return is_quiesced;
}

static void rnablk_queue_offline_cache_device_restart(
                                          struct rnablk_server_conn *conn,
                                          rnablk_cachedev_t *cachedev,
                                          int n_quiesces);

static void
rnablk_queued_offline_cache_device(rnablk_workq_cb_arg_t arg)
{
    rnablk_dwork_t w = RNABLK_ARG_DWORK(arg);
    struct rnablk_queued_offline_cache_device_data *wd =
                        &w->data.rwd_rnablk_queued_offline_cache_device;
    boolean is_expel = atomic_bit_is_set(&wd->cachedev->rcd_state,
                                         RCD_STATE_EXPELLED);
    boolean is_quiesced;
    uint64_t start_seconds = get_seconds();

    is_quiesced = rnablk_do_offline_cache_device(wd->conn, wd->cachedev,
                                                 is_expel, wd->n_quiesces);

    if (!is_quiesced) {
        rnablk_queue_offline_cache_device_restart(wd->conn, wd->cachedev,
                                                  wd->n_quiesces + 1);
    }

    /* drop reference obtained when workitem was queued */
    rnablk_put_cachedev(wd->cachedev);
    rnablk_server_conn_put(wd->conn);

    if (w->delayed) {
        atomic_dec(&delayed_work);
    }
    RNABLK_FREE_DWORK(w);
    rnablk_finish_workq_work(start_seconds);
}

static void
rnablk_queue_offline_cache_device_restart(struct rnablk_server_conn *conn,
                                          rnablk_cachedev_t *cachedev,
                                          int n_quiesces)
{
    rnablk_dwork_t w;
    struct rnablk_queued_offline_cache_device_data *wd;

    if (rnablk_conn_connected(conn)) {
        if (unlikely(NULL == (w = RNABLK_ALLOC_DWORK()))) {
            rna_printk(KERN_ERR, "Error during offline of "
                       "cachedev [%#"PRIx64"] for conn ["CONNFMT"]: ENOMEM, "
                       "forcing disconnect\n", 
                       cachedev->rcd_id, CONNFMTARGS(conn));
            /*
             * Force a disconnect from the CS, so it won't get stuck
             * waiting for our handshake, and can proceed with the
             * offlining.  (The client end will get taken care of during
             * the conn disconnect processing and subsequent cache-device
             * EXPEL.)
             */
            rnablk_drop_connection(conn);
        } else {
            wd = &w->data.rwd_rnablk_queued_offline_cache_device;

            RNABLK_INIT_DWORK(w, rnablk_queued_offline_cache_device);
            atomic_inc(&conn->rsc_refcount);
            atomic_inc(&cachedev->rcd_refcount);
            wd->conn = conn;
            wd->cachedev = cachedev;
            wd->n_quiesces = n_quiesces;
            rna_queue_delayed_work(mt_workq, RNABLK_DWORK_OBJECT(w),
                                msecs_to_jiffies(
                                RNABLK_CACHE_DEV_QUIESCE_WAIT_INTERVAL_MSECS));
        }
    } else {
        rna_printk(KERN_ERR, "Unable to process CACHE_FAIL_CACHE_DEVICE "
                   "message for cachedev [%#"PRIx64"] for "
                   "conn ["CONNFMT"] not connected\n", 
                   cachedev->rcd_id, CONNFMTARGS(conn));
    }
}

/*
 * rnablk_initiate_offline_cache_device
 *  Initiate offline processing for a failed (or expelled) cache device.
 *
 *  Notes:
 *      1) This routine must only be called with the main CS conn, not
 *         with any cache-dev conns.
 *      2) This routine may end up being called only once, or may be called
 *         twice to implement the offline of a single cache-device.
 *         In a cache-device failure scenario, it will normally be called
 *         twice; once at the end of the CACHE_FAIL_CACHE_DEVICE/
 *         CACHE_FAIL_CACHE_DEVICE_RESP handshake processing, and then
 *         again when we receive the EXPEL message.  (In that event, the
 *         cleanup processing that happens at EXPEL time is largely
 *         redundant.).  If a cache-device is manually offlined by the
 *         user, on the other hand, then typically there will be only
 *         one call to this routine, i.e. the call that is associated
 *         with the EXPEL message.
 *         This routine must handle either scenario.
 */
static void
rnablk_initiate_offline_cache_device(struct rnablk_server_conn *conn,
                                     rnablk_cachedev_t *cachedev,
                                     int reason)
{
    boolean is_expel = atomic_bit_is_set(&cachedev->rcd_state,
                                         RCD_STATE_EXPELLED);
    boolean is_quiesced;

    is_quiesced = rnablk_do_offline_cache_device(conn, cachedev, is_expel, 0);
    if (!is_quiesced) {
        rnablk_queue_offline_cache_device_restart(conn, cachedev, 1);
    }
}

/*
 * rnablk_trigger_offline_cache_device()
 *  This routine begins the process of offlining a cache-device.
 *  It potentially completes it as well, if all the associated cachedev
 *  "conn" connections have been successfully disconnected.  Otherwise
 *  it initiates the process that will eventually result in the complete
 *  offline process.
 *
 * Notes:
 *  1) Note that current Cache-Server behavior is that we get a
 *     CACHE_FAIL_CACHE_DEVICE message for each connection, i.e. for
 *     the primary (parent) connection and all the cache-device conns.
 *     There is extra logic in this routine to support that model...
 */
void
rnablk_trigger_offline_cache_device(struct rnablk_server_conn *conn,
                                    cachedev_id_t cachedev_id,
                                    int reason)
{
    rnablk_cachedev_t *cachedev;
    struct rnablk_server_conn *p_conn;
    boolean is_expel = (CD_OFFLINE_EXPEL == reason);
    boolean can_offline;
    int online_refs;

    rna_printk(KERN_NOTICE, "OFFLINE cachedev [%#"PRIx64"] conn ["CONNFMT"] "
               "(reason=%s)\n", cachedev_id, CONNFMTARGS(conn),
               offline_reason_to_str(reason));

    p_conn = conn->rsc_parent_conn;

    if (is_parent_conn(conn)) {
        cachedev = rnablk_get_conn_cachedev(p_conn, cachedev_id, FALSE);
    } else if (conn->rsc_cachedev->rcd_id == cachedev_id) {
        cachedev = conn->rsc_cachedev;
        atomic_inc(&cachedev->rcd_refcount);
    } else {
        cachedev = NULL;
    }

    if (!cachedev) {
        /* no such cachedev affiliated with this connection, nothing to do */
        rna_printk(KERN_NOTICE, "conn ["CONNFMT"] has no cleanup to do for "
                   "cachedev [%#"PRIx64"]\n", CONNFMTARGS(conn), cachedev_id);
        if (CD_OFFLINE_FAIL == reason) {
            rnablk_send_fail_cachedev(conn, cachedev_id, TRUE);
        }
        return;
    }

    rnablk_trc_discon(1, "cachedev [%#"PRIx64"] online_refs=%d online=%d "
                    "expelled=%d\n",
                    cachedev_id,
                    atomic_read(&cachedev->rcd_online_refs),
                    atomic_bit_is_set(&cachedev->rcd_state, RCD_STATE_ONLINE),
                    atomic_bit_is_set(&cachedev->rcd_state,
                    RCD_STATE_EXPELLED));

    (void)rnablk_offline_conn_cachedev(p_conn, cachedev, is_expel);

    if ((is_parent_conn(conn) && (CD_OFFLINE_FAIL == reason))
         || !rnablk_conn_connected(p_conn)) {
        atomic_bit_set(&cachedev->rcd_state, RCD_STATE_PARENT_READY);
    }

    /* Decrement for disconnects and for expel */
    online_refs = (CD_OFFLINE_FAIL != reason)
                   ? atomic_dec_return(&cachedev->rcd_online_refs)
                   : atomic_read(&cachedev->rcd_online_refs);

    /*
     * The actual EXPEL may have occurred in an earlier call to this
     * routine, so re-set 'is_expel' to reflect the actual state of
     * the cachedevice.  (Note this needs to happen after the above call to
     * rnablk_offline_conn_cachedev(), but before the below subsequent
     * uses of 'is_expel'.)
     */
    is_expel = atomic_bit_is_set(&cachedev->rcd_state, RCD_STATE_EXPELLED);
    
    /*
     * rnablk_do_offline_cache_device() should be called once at the end
     * of the CACHE_FAIL_CACHE_DEVICE handshake (if there is one), and
     * once for EXPEL processing.
     *
     * rcd_online_refs has a reference for every connectecd cache-device conn,
     * and also a reference correlating to the (required) EXPEL processing.
     * Since we can't call rnablk_do_offline_cache_device() until all
     * cache-device connections have been safely disconnected, the below
     * checks ensure that's the case for both the FAIL_CACHE_DEVICE handshake
     * case and the EXPEL case...
     *  1.  is_expel && online_refs == 0
     *          For the EXPEL case, when online_refs goes to 0, all
     *          cachedev conn's have been successfully disconnected
     *  2.  !is_expel && online_refs == 1 && RCD_STATE_PARENT_READY
     *          For the FAIL_CACHE_DEVICE handshake case, we can do the
     *          offline when online_refs goes to 1, since that indicates
     *          that only the EXPEL reference is left (and the EXPEL always
     *          follows the handshake), but only if the parent
     *          CACHE_FAIL_CACHE_DEVICE message has been received/processed.
     *          (We are using the parent message to gate things; we don't
     *          send the CACHE_FAIL response for the parent back to the
     *          cache-server until the entire offline processing is complete
     *          for the handshake).
     *          [Note that the parent conn is not included in the
     *          rcd_online_refs count, which is why we need an explicit
     *          flag to tell us whether the parent is ready or not.]
     */
    can_offline = ((is_expel && online_refs == 0
                    && atomic_bit_test_and_set(&cachedev->rcd_state,
                                               RCD_STATE_EXPEL_OFFLINING))
                   || (!is_expel && online_refs == 1
                       && atomic_bit_is_set(&cachedev->rcd_state,
                                            RCD_STATE_PARENT_READY)
                       && atomic_bit_test_and_set(&cachedev->rcd_state,
                                                  RCD_STATE_FAIL_OFFLINING)));
                    
    if (can_offline) {
        rnablk_initiate_offline_cache_device(p_conn, cachedev, reason);
    }

    if ((CD_OFFLINE_FAIL == reason) && !is_parent_conn(conn)) {
        /*
         * If reason was FAIL and this wasn't the parent connection,
         * go ahead and send the FAIL_CACHE_DEVICE response now.
         * If it's the parent connection, we don't send back the response
         * until the client finishes all its offline processing for the
         * handshake, as we use the parent message to gate the offline
         * process.  (That is to say, the cache server won't complete it's
         * side of the offline processing until it receives responses for
         * all of the connections.  And we don't want that to happen until
         * the client is completely through with its side of the offline
         * processing.)
         */
        rnablk_send_fail_cachedev(conn, cachedev_id, TRUE);
    }

    // drop the reference we grabbed at the top
    rnablk_put_cachedev(cachedev);
}

/*
 * rnablk_queue_offline_cachedev_notify_wf
 *  Notify the cache-server about a cache-deviced failure detected here
 *  on the client.
 */
static void
rnablk_offline_cachedev_notify_wf(rnablk_workq_cb_arg_t arg)
{
    struct work_struct *work = (struct work_struct *)arg;
    struct rnablk_work *w = container_of(work, struct rnablk_work, work);
    struct rnablk_offline_cachedev_wf_data *wd =
                                    &w->data.rwd_rnablk_offline_cachedev_wf;
    uint64_t start_seconds = get_seconds();
    ENTERV;

    rna_printk(KERN_DEBUG, "cachedev [%#"PRIx64"] do offline notification\n",
               wd->ocd_cachedev_id);

    /* Send a message to the CS to inform it about the bad cache-device */
    rnablk_send_fail_cachedev(wd->ocd_conn, wd->ocd_cachedev_id, FALSE);

    rnablk_server_conn_put(wd->ocd_conn);
    
    rnablk_mempool_free(w, work_cache_info);
    rnablk_finish_workq_work(start_seconds);
    EXITV;
}

/*
 * rnablk_queue_offline_cache_device_notify
 *  Queue an operation to notify the cache-server about a cache-deviced
 *  failure detected here on the client.
 */
static void
rnablk_queue_offline_cache_device_notify(struct rnablk_server_conn *conn,
                                         cachedev_id_t cachedev_id)
{
    struct rnablk_work *w = NULL;
    struct rnablk_offline_cachedev_wf_data *wd = NULL;

    rna_printk(KERN_DEBUG, "cachedev [%#"PRIx64"] queue offline\n", cachedev_id);

    if (likely(NULL != (w = rnablk_mempool_alloc(work_cache_info)))) {
        RNABLK_INIT_RNABLK_WORK(w, wd, rnablk_offline_cachedev_notify_wf);
        atomic_inc(&conn->rsc_refcount);
        wd->ocd_conn = conn;
        wd->ocd_cachedev_id = cachedev_id;
        rna_queue_work(mt_workq, &w->work);
    }
}

/*
 * rnablk_io_cachedev_error()
 *  This routine is called to initiate an offline of the related
 *  cache-device when a cache-device failure is seen.
 *
 * Notes:
 *  1) The caller of this routine must leave 'ios' in place on the
 *     blk->dispatch_queue.  This ensures the I/O will get restarted
 *     with ordering preserved when restart is possible.
 */
static void
rnablk_io_cachedev_error(struct io_state *ios, boolean notify_cs)
{
    struct rnablk_server_conn *p_conn =
                            rnablk_get_ios_conn(ios)->rsc_parent_conn;
    rnablk_cachedev_t *cachedev;
    ENTERV;

    cachedev = ios->blk->blk_cachedev;
    rna_printk(KERN_ERR, "cachedev [%#"PRIx64"] I/O error detected ios [%p] "
               "tag ["TAGFMT"] type [%s] block [%"PRIu64"] state [%s] "
               "(notify=%d)\n",
               ios->blk->blk_cachedev->rcd_id, ios, TAGFMTARGS(ios->tag),
               rnablk_op_type_string(ios->type), ios->blk->block_number,
               rnablk_cache_blk_state_string(ios->blk->state), notify_cs);

#ifdef TEST_OFFLINE_CACHE_DEVICE
    /*
     * In test mode, we're potentially injecting fake "CS" cachedev errors
     * here on the client -- in which case, the CS doesn't know about them.
     * So to make things work _almost_ like normal, always notify it
     * about the failure.
     */
    notify_cs = TRUE;
#endif /* TEST_OFFLINE_CACHE_DEVICE */

    /*
     * Note that rnablk_offline_conn_cachedev() needs to be called in
     * all cases, whether 'notify_cs' is set or not..
     */
    if (likely(cachedev != &null_cachedev)
        && rnablk_offline_conn_cachedev(p_conn, cachedev, FALSE)
        && notify_cs) {
        rnablk_queue_offline_cache_device_notify(p_conn, cachedev->rcd_id);
    }
    EXITV;
}

int rnablk_verify_conn(struct rnablk_server_conn *conn)
{
    int ret = FALSE;
    if (likely((NULL != conn) &&
               !IS_ERR(conn))) {
#if defined(RNABLK_VERIFY_CONN_BY_MAGIC)
        ret = likely(likely(RNABLK_CONN_FRONT_MAGIC == conn->front_magic) &&
                     likely(RNABLK_CONN_BACK_MAGIC  == conn->back_magic));
#else
        rna_down_read(&svr_conn_lock);
        if (NULL != conn->rsc_parent_conn) {
            /* 
             * cachedev-specific conns point to their parents in
             * rsc_parent_conn.  The primary CS conn points to itself
             * in rsc_parent_conn.  The primary CS conn (parent) is
             * the connection that is put in cache_conn_root.
             */
            ret = rnablk_verify_conn_in_tree(&cache_conn_root, 
                                             conn->rsc_parent_conn);
        }
        rna_up_read(&svr_conn_lock);
#endif
    }
    return ret;
}

/*
 * returns referenced EP pointed to by con object
 * if return is non-NULL, caller must call com_release_ep()
 * to release reference acquired here.
 * */
struct com_ep * rnablk_conn_get_ep(struct rnablk_server_conn *conn)
{
    struct com_ep *ep = NULL;
    lockstate_t flags;

    BUG_ON(NULL == conn);

    rna_spin_in_stack_lock_irqsave(conn->sc_lock, flags);
    if ((NULL != conn->ep) &&
        (MD_CONN_EP_METAVALUE != conn->ep)) {
        ep = conn->ep;
        com_inc_ref_ep(ep);
    }

    rna_spin_in_stack_unlock_irqrestore(conn->sc_lock, flags);

    return ep;
}

/*
 * rnablk_conn_set_ep()
 *
 * Notes:
 *  1) IMPORTANT!
 *     In most places throughout the driver, conn->state is sampled
 *     and modified without the conn->sc_lock.  However, in order to
 *     safely handshake with disconnects, we need to change to the
 *     CONNECTED state while holding the lock.
 *  2) Note that this routine samples conn->state to check for
 *     CONNECT_PENDING, then sets ep, and finally sets
 *     conn->state to CONNECTED.  For this to be safe, we rely
 *     on the assumption that the specific state "RNABLK_CONN_CONNECT_PENDING"
 *     is only ever modified when protected by conn->sc_lock.
 *     (Here and in rnablk_process_conn_disconnect().
 *
 * caller must hold conn->sc_lock
 */
static int
rnablk_conn_set_ep(struct rnablk_server_conn *conn,
                   struct com_ep             *ep)
{
    int           ret = FALSE;

    BUG_ON(NULL == conn);

    if (RNABLK_CONN_CONNECT_PENDING == atomic_read(&conn->state)) {
        atomic_inc(&conn->conn_count);
        rna_printk(KERN_INFO, 
                   "CS [%p] ["rna_service_id_format"] conn ["CONNFMT"] EP "
                   "[%p]->[%p] state [%s]->[%s] conn_count [%d]\n",
                   conn,
                   rna_service_id_get_string(&conn->id),
                   CONNFMTARGS(conn), conn->ep, ep,
                   rnablk_conn_state_string(RNABLK_CONN_CONNECT_PENDING),
                   rnablk_conn_state_string(atomic_read(&conn->state)),
                   atomic_read(&conn->conn_count));
        conn->ep = ep;
        atomic_set(&conn->state, RNABLK_CONN_CONNECTED);
        ret = TRUE;
    } else {
        rna_printk(KERN_WARNING,
                   "Attempt to reset CS [%p] ["rna_service_id_format"] EP "
                   "in state [%s] currently [%p] [%s]. "
                   "Dropping ep [%p] [%s]\n",
                   conn,
                   rna_service_id_get_string(&conn->id),
                   rnablk_conn_state_string(atomic_read(&conn->state)),
                   conn->ep,
                   (NULL == conn->ep) ? "None" :
                   com_get_transport_type_string(
                       com_get_ep_transport_type(conn->ep)),
                   ep,
                   com_get_transport_type_string(com_get_ep_transport_type(ep)));
    }

    return ret;
}

static void
rnablk_conn_unset_ep(struct rnablk_server_conn *conn)
{
    lockstate_t flags;

    BUG_ON(NULL == conn);
    rna_spin_in_stack_lock_irqsave(conn->sc_lock, flags);
    if (RNABLK_CONN_DISCONNECT_INPROG ==
            atomic_cmpxchg(&conn->state,
                            RNABLK_CONN_DISCONNECT_INPROG,
                            RNABLK_CONN_DISCONNECTED)) {
        rna_printk(KERN_INFO,
                   "CS [%p] ["rna_service_id_format"] EP [%p] state [%s]->[%s]\n",
                   conn,
                   rna_service_id_get_string(&conn->id),
                   conn->ep,
                   rnablk_conn_state_string(RNABLK_CONN_DISCONNECT_INPROG),
                   rnablk_conn_state_string(atomic_read(&conn->state)));
        conn->ep = NULL;
    } else {
        rna_printk(KERN_ERR,
                   "Attempt to unset CS [%p] ["rna_service_id_format"] EP in state "
                   "[%s] currently [%p]\n",
                   conn,
                   rna_service_id_get_string(&conn->id),
                   rnablk_conn_state_string(atomic_read(&conn->state)),
                   conn->ep);
        dump_stack();
    }
    rna_spin_in_stack_unlock_irqrestore(conn->sc_lock, flags);
}

INLINE int rnablk_local_conn(struct rnablk_server_conn *conn)
{
    int ret = FALSE;
    struct sockaddr_in src_in;
    struct sockaddr_in dst_in;

#ifdef WINDOWS_KERNEL

	//TODO: Need to add code to check return code
//    com_get_ep_src_in_ex(conn->ep, &src_in, sizeof(src_in));
    com_get_ep_dst_in_ex(conn->ep, &dst_in, sizeof(dst_in) );

    // With the Linux VSA running on the Windows box, a "local" connection
    // is when the destination is the same as the address of the VM.
    src_in = conn->pHBAExt->pMPDrvInfo->clientAddr;

#else
    src_in = conn->ep->src_in;
    dst_in = conn->ep->dst_in;
#endif /*WINDOWS_KERNEL*/

    if(src_in.sin_addr.s_addr == dst_in.sin_addr.s_addr) {
        ret = TRUE;
    }
	 
	rna_printk(KERN_INFO,
        "["NIPQUAD_FMT"] is%s local\n",
        NIPQUAD(dst_in.sin_addr.s_addr),
        ret ? "" : " not");

    return ret;
}

// restart all requests which were stalled by waiting for a connection
// to the referenced cache server to be established
static void
rnablk_cache_server_connected(struct rnablk_server_conn *conn)
{
    lockstate_t     irqflags;
    struct io_state *ios;
    struct list_head *pos;
    unsigned char oldirql = 0;

    rnablk_register_cs_conn_with_cfm(conn);

restart:
    rna_down_write( &wfc_queue_lock, &oldirql );
    list_for_each(pos, &wfc_queue) {
        ios = list_entry(pos, struct io_state, l);
        if(rnablk_ios_waiting_conn(ios, conn)) {
            rnablk_trace_ios(ios);
            rna_printk(KERN_INFO, 
                       "ep connected, restarting stalled ios [%p] tag "
                       "["TAGFMT"]\n", ios, TAGFMTARGS(ios->tag));
            list_del_init(&ios->l);
            RNABLK_BUG_ON(!ios_queuestate_test_and_set(ios,
                                                       IOS_QS_WFC, IOS_QS_NONE),
                          "ios [%p] tag ["TAGFMT"] qstate [%d] inconsistent\n",
                          ios, TAGFMTARGS(ios->tag), ios_queuestate_get(ios));
            TRACE(DBG_FLAG_VERBOSE,"device [%s] ios [%p] tag ["TAGFMT"] type "
                  "[%s]\n", ios->dev->name, ios, TAGFMTARGS(ios->tag),
                   rnablk_op_type_string(ios->type));
            rnablk_set_ios_ep( ios, conn->ep );
            rna_up_write(&wfc_queue_lock, oldirql);

            rnablk_retrack_ios( ios );
            rnablk_cache_blk_ref(ios->blk);
            rnablk_lock_blk_irqsave(ios->blk, irqflags);
            if (unlikely(atomic_read(&ios->blk->dev->failed))) {
                rna_printk(KERN_NOTICE, "ending ios [%p] tag ["TAGFMT"] type [%s] for "
                           "failed device [%s] block [%"PRIu64"]\n",
                           ios,
                           TAGFMTARGS(ios->tag),
                           rnablk_op_type_string(ios->type),
                           ios->blk->dev->name,
                           ios->blk->block_number);
                if (!rnablk_cache_blk_state_transition(ios->blk,
                                        RNABLK_CACHE_BLK_CONNECT_PENDING,
                                        RNABLK_CACHE_BLK_DISCONNECTED)) {
                    rna_printk(KERN_WARNING, 
                              "device [%s] ios [%p] type [%s] block [%llu] "
                              "unexpected state [%s]\n", ios->blk->dev->name,
                              ios, rnablk_op_type_string(ios->type),
                              ios->blk->block_number,
                              rnablk_cache_blk_state_string(ios->blk->state));
                }
                rnablk_unlock_blk_irqrestore(ios->blk, irqflags);
                rnablk_end_request(ios, -EIO);
            } else {
                ios->blk->cb_conn = conn;
                rnablk_set_blk_ep(ios->blk, conn->ep);

                RNABLK_DBG_BUG_ON(conn != ios->blk->cb_conn
                                  || NULL == ios->blk->blk_cachedev
                                  || 0 != ios->blk->blk_cachedev->rcd_id,
                                  "[%s] blk [%p block [%llu] conn ["CONNFMT"] "
                                  "unexpected cachedev setting\n",
                                  ios->blk->dev->name, ios->blk,
                                  ios->blk->block_number, CONNFMTARGS(conn));

                rnablk_unlock_blk_irqrestore(ios->blk, irqflags);

                rnablk_queue_request(!IS_MASTER_BLK(ios->blk) ?
                                     RNABLK_CACHE_QUERY : RNABLK_LOCK_MASTER_BLK,
                                     conn->ep, ios, ios->blk, FORCE_QUEUED_IO,
                                     FALSE);

            }
            rnablk_cache_blk_release(ios->blk);
            goto restart;
        } else {
            rnablk_trace_ios(ios);
        }
    }
    rna_up_write( &wfc_queue_lock, oldirql );
    rnablk_next_request(conn);
}

static int
conn_set_retry_attempts(enum com_type type)
{
    if (RC == type) {
        /* Three attempts to connect via RDMA/RC */
        return 3;
    } else {
        return 1;
    }
}

/*
 * Return 0 if ep is used for conn.
 * Return -1 if another ep raced with us to get set for the conn.
 */
int
rnablk_cache_connected(struct com_ep *ep)
{
    struct rnablk_server_conn *conn;
    lockstate_t irq_flags;
    struct sockaddr_in dst_in;
    boolean allow_connect = TRUE;
    int ret = 0;

    BUG_ON( ep == NULL );
    conn = (struct rnablk_server_conn *)(com_get_ep_context(ep));

    dst_in = get_dest_sockaddr_from_ep(ep);

    rna_printk(KERN_INFO,
               "Connected to CS ["NIPQUAD_FMT":%d] conn ["CONNFMT"] "
               "cachedev [%#"PRIx64"] iface [%s] active_if [%d] attempts [%d]\n",
               NIPQUAD(dst_in.sin_addr.s_addr),
               dst_in.sin_port,
               CONNFMTARGS(conn),
               (NULL == conn) ? 0 : is_parent_conn(conn)
               ? 0 : conn->rsc_cachedev->rcd_id,
               com_get_transport_type_string(
               com_get_ep_transport_type(ep)),
               conn->rsc_active_if, conn->if_attempts);

    /*
     * In order to safely handshake with racing disconnects, we
     * need to hold conn->sc_lock until the connection state is fully
     * consistent.  This includes:
     *  - setting conn->ep
     *  - increment of parent_conn->rsc_connected_conns
     *  - increment of conn->rcd_online_refs
     *  - increment of conn->rcd_refcount
     *  - setting conn->state to RNABLK_CONN_CONNECTED
     * rnablk_process_conn_disconnect() depends on this to avoid races!
     */
    rna_spin_in_stack_lock_irqsave(conn->sc_lock, irq_flags);
    if (likely(rnablk_conn_set_ep(conn, ep))) {
        /* we've successfully connected, so reset the retry attempts */
        conn->if_attempts = conn_set_retry_attempts(
                                conn->if_table.ifs[conn->rsc_active_if].type);
        conn->local = rnablk_local_conn(conn);

        if (is_parent_conn(conn)) {
            /* server parent connection */
            atomic_inc(&conn->rsc_parent_conn->rsc_connected_conns);
            rna_spin_in_stack_unlock_irqrestore(conn->sc_lock, irq_flags);
            rnablk_cache_server_connected(conn);
        } else {
            atomic_inc(&conn->rsc_cachedev->rcd_refcount);
            if (!atomic_bit_is_set(&conn->rsc_cachedev->rcd_state,
                                   RCD_STATE_ONLINE)) {
                allow_connect = FALSE;
                rna_printk(KERN_WARNING, "conn ["CONNFMT"] ep [%p] connected "
                           "after cachedev [%#"PRIx64"] went offline, "
                           "dropping\n",
                            CONNFMTARGS(conn), ep, conn->rsc_cachedev->rcd_id);
            } else if (RNABLK_CONN_CONNECTED !=
                       atomic_read(&conn->rsc_parent_conn->state)) {
                allow_connect = FALSE;
                rna_printk(KERN_WARNING, "conn ["CONNFMT"] ep [%p] connected "
                           "before primary conn ["CONNFMT"], dropping\n",
                            CONNFMTARGS(conn), ep,
                            CONNFMTARGS(conn->rsc_parent_conn));
            }

            if (allow_connect) {
                atomic_inc(&conn->rsc_parent_conn->rsc_connected_conns);
                atomic_inc(&conn->rsc_cachedev->rcd_online_refs);
            } else {
                atomic_bit_set(&conn->rsc_flags, RSC_F_LATE_CONNECT);
            }
            rna_spin_in_stack_unlock_irqrestore(conn->sc_lock, irq_flags);
            if (!allow_connect) {
                rnablk_drop_connection(conn);
            }
        }
    } else {
        /* 
         * The com layer (ib or tcp) will disconnect the ep if we
         * return an error from this connection callback.
         */
        rna_spin_in_stack_unlock_irqrestore(conn->sc_lock, irq_flags);
        ret = -1;
    }

    if (!is_parent_conn(conn)) {
        /*
         * Drop the extra cachedev reference we added when we initiated
         * the connection attempt.
         */
        rnablk_put_cachedev(conn->rsc_cachedev);
    }
    return ret;
}

/* caller must hold conn->block_list_lock */
static void
display_conn_cachedev_status(struct rnablk_server_conn *conn,
                             rnablk_cachedev_t *cachedev,
                             void *unused)
{
    struct blk_lru_list *bpos;
    struct cache_blk *blk;
    lockstate_t     irqflags;
    int               is_wref;

    RNABLK_DBG_BUG_ON(!rna_service_mutex_is_locked(
                      &conn->rsc_parent_conn->block_list_lock),
                      "conn ["CONNFMT"] cachedev=%p - mutex not locked\n",
                      CONNFMTARGS(conn), cachedev);

    if (!blk_lru_list_empty(&cachedev->rcd_block_list)) {
        blk_lru_list_for_each(bpos, &cachedev->rcd_block_list) {
            blk = blk_lru_entry(bpos, &is_wref);
            if (unlikely(IS_MARKER_BLK(blk))) {
                continue;   // ignore markers
            }
            if (is_wref) {
                continue;   // only want each blk once, so ignore wref entry
            }
            rnablk_cache_blk_ref(blk);
            rnablk_lock_blk_irqsave(blk, irqflags);
            rna_printk(KERN_NOTICE,
                   "block [%"PRIu64"] state [%s] block IO list empty [%s] "
                   "dispatch list empty [%s]\n",
                   blk->block_number,
                   rnablk_cache_blk_state_string(blk->state),
                   list_empty(&blk->bl) ? "TRUE" : "FALSE",
                   list_empty(&blk->dispatch_queue) ? "TRUE" : "FALSE");
            rnablk_unlock_blk_irqrestore(blk, irqflags);
            rnablk_cache_blk_release(blk);
        }
    }
    rna_printk(KERN_NOTICE, "Done.\n");
}

static void
display_conn_status(struct rnablk_server_conn *conn)
{
    struct io_state *ios;
    struct list_head *pos, *tmp;
    unsigned char oldirql = 0;
    mutexstate_t mutex_lock_handle;

    rna_printk(KERN_NOTICE, "Check the wfc list\n");
    rna_down_write( &wfc_queue_lock, &oldirql );
    list_for_each_safe(pos, tmp, &wfc_queue) {
        ios = list_entry(pos, struct io_state, l);
        rna_printk(KERN_NOTICE,
                "ios [%p] tag ["TAGFMT"] hash [%"PRIu64"] key [%"PRIu64"] \n",
                ios, TAGFMTARGS(ios->tag), conn->id.u.hash, ios->cs_ep_key);
        if (rnablk_ios_waiting_conn(ios, conn)) {
            rna_printk(KERN_NOTICE,
                "ios [%p] tag ["TAGFMT"] queue_state [%s] dev [%s] "
                "block [%"PRIu64"]\n", ios, TAGFMTARGS(ios->tag),
                rnablk_ios_q_string(ios_queuestate_get(ios)),
                ios->dev->name,
                ios->blk->block_number);
            rna_printk(KERN_NOTICE,
               "block [%"PRIu64"] state [%s] block IO list empty [%s] "
               "dispatch list empty [%s]\n",
               ios->blk->block_number,
               rnablk_cache_blk_state_string(ios->blk->state),
               list_empty(&ios->blk->bl) ? "TRUE" : "FALSE",
               list_empty(&ios->blk->dispatch_queue) ? "TRUE" : "FALSE");
        }
    }
    rna_up_write(&wfc_queue_lock, oldirql);

    rna_printk(KERN_NOTICE, "Check all conn cachedev block lists\n");
    rna_block_mutex_lock(&conn->block_list_lock, &mutex_lock_handle);
    rnablk_operate_on_conn_cachedevs(conn, NULL, NULL,
                                     display_conn_cachedev_status);
    rna_block_mutex_unlock(&conn->block_list_lock, &mutex_lock_handle);
    rna_printk(KERN_NOTICE, "Done.\n");
}

/*
 * rnablk_conn_quiesce_and_connect()
 *  Quiesce blks/ios' (or a subset thereof) associated with a 'conn',
 *  and remove the association between any blks and this conn.
 *  This is used during disconnect of a cache-server connection and
 *  also during offline of a cache-device.
 *
 *  Notes:
 *      1) This routine calls rnablk_quiesce_dispatch_queue() which
 *         tries to quiesce all outstanding I/O relevant to the
 *         given 'conn' and 'cachedev'.  There may be outstanding I/O
 *         that can't be quiesced but instead must be waited for.  In
 *         that case, the return value indicates whether all I/O was
 *         successfully quiesced or not.  If not, then the expectation
 *         is that higher-level routines will take steps to ensure that
 *         this work gets requeued (with a delay to give the outstanding
 *         I/O time to complete) -- and will continue to requeue it until
 *         all I/O is quiesced.
 *         The 'n_quiesces' input argument is relevant to this.
 *         It basically indicates the number of "retries" that have been
 *         done in attempting to quiesce the I/O.  The first time this
 *         routine is called (for a given failure scenario, i.e. for the
 *         conn/cachedev), 'n_quiesces' should be 0.  A value of 0
 *         causes this routine to do additional work that only needs to
 *         be done once (i.e. on the first time through).  After that,
 *         the caller(s) of this routine should be incrementing the
 *         value of 'n_quiesces' for each retry attempt.
 *         (rnablk_quiesce_dispatch_queue() uses the value to effect a
 *         'timeout', i.e. to determine when we've waited too long for
 *         I/O to quiesce.
 *
 * Caller must hold conn->block_list_lock
 *
 * Return Value:
 *  Returns TRUE if all I/O was successfully quiesced, otherwise FALSE.
 */
static boolean
rnablk_conn_quiesce_and_disconnect(struct rnablk_server_conn *conn,
                                   rnablk_cachedev_t *cachedev,
                                   char *reason,
                                   boolean check_for_waiters,
                                   int n_quiesces)
{
    boolean is_quiesced;

    rna_printk(KERN_NOTICE, "clean up conn blocks%s (n_quiesces=%d)\n",
               reason ? reason : "", n_quiesces);

    if (0 == n_quiesces) {              // first time through
        rnablk_cleanup_conn_blks(conn, cachedev);

        if (check_for_waiters) {
            /*
             * in theory, if you have waiters, you should not have entries in
             * the conn queue, and vice versa.
             */
            rna_printk(KERN_NOTICE, "clean up conn waiters%s\n",
                       reason ? reason : "");
            rnablk_cleanup_conn_waiters(conn);
        }

        rna_printk(KERN_NOTICE, "clean up conn ioq%s\n", reason ? reason : "");
        rnablk_cleanup_conn_ioq(conn, cachedev);
    }

    rna_printk(KERN_NOTICE, "redo dispatch_queue%s\n", reason ? reason : "");
    is_quiesced = rnablk_quiesce_dispatch_queue(conn, cachedev, n_quiesces);

    if (is_quiesced) {
        rna_printk(KERN_NOTICE, "conn blocks sort list%s\n",
                   reason ? reason : "");
        rnablk_conn_blks_sort_list(conn, cachedev);
    }
    return is_quiesced;
}

/*
 * rnablk_cleanup_nulldev_io()
 *  This routine should be called as part of disconnect processing
 *  for any CS connection.
 *
 *  Its purpose, in a nutshell, is to cleanup outstanding
 *  RNABLK_DEREF_REQUEST_RESP ios's.  This is because (currently) these
 *  are the only type of ios that get associated with the 'null_device'.
 *  This means they have no association with any cache_device and thus
 *  aren't in any cache_device block list -- which means our other
 *  disconnect cleanup code won't see and take care of them.
 *
 * Caller should hold conn_cleanup_mutex.
 */
static void
rnablk_cleanup_nulldev_io(struct rnablk_server_conn *conn)
{
    struct cache_blk *blk = MASTER_BLK(&null_device);
    struct com_ep *ep;
    struct list_head *ent, *next;
    struct io_state *ios;
    lockstate_t irq_flags;
#ifdef WINDOWS_KERNEL
    struct _LIST_ENTRY discard_ioq;
    discard_ioq.Flink = &(discard_ioq);
    discard_ioq.Blink = &(discard_ioq);
#else
    LIST_HEAD(discard_ioq);
#endif /* WINDOWS_KERNEL */

    ep = rnablk_conn_get_ep(conn);
    if (NULL != ep) {
        rnablk_lock_blk_irqsave(blk, irq_flags);
        list_for_each_safe(ent, next, &blk->dispatch_queue) {
            ios = list_entry(ent, struct io_state, l);
            if (ios->ep == ep) {
                rnablk_io_completed_nolock(ios, ios->blk);
                RNABLK_DBG_BUG_ON(IOS_HAS_IOREQ(ios), "ios [%p] tag ["TAGFMT"] "
                                  "type [%s] for null device has ioreq!\n",
                                  ios, TAGFMTARGS(ios->tag),
                                  rnablk_op_type_string(ios->type));
                list_add_tail(&ios->l, &discard_ioq);
            }
        }
        rnablk_unlock_blk_irqrestore(blk, irq_flags);

        /*
         * Finish up the ios's we decided to drop.
         */
        while (!list_empty(&discard_ioq)) {
            ios = list_first_entry(&discard_ioq, struct io_state, l);
            list_del_init(&ios->l);
            rna_printk(KERN_ERR, "dropping ios [%p] tag ["TAGFMT"] type [%s] "
                       "ep [%p]\n", ios, TAGFMTARGS(ios->tag),
                       rnablk_op_type_string(ios->type), ep);
            dec_in_flight(ios->dev, ios);
            rnablk_ios_finish(ios);
        }
        com_release_ep(ep);
    }
    return;
}

/*
 * rnablk_get_conn_cachedev_list()
 *  Return a list of the cache-device id's associated with a conn.
 */
int
rnablk_get_conn_cachedev_list(struct rnablk_server_conn *conn,
                              void *opaque_arg)
{
    struct cachedev_list *cdl = (struct cachedev_list *)opaque_arg;
    rnablk_cachedev_t *cdp;
    struct list_head *ent;
    lockstate_t irqflags;

    if (g_md_conn == conn) {
        return 0;
    }

    conn = conn->rsc_parent_conn;   // should already be the parent!
    rna_spin_in_stack_lock_irqsave(conn->sc_lock, irqflags);
    list_for_each(ent, &conn->rsc_cachedevs) {
        cdp = list_entry(ent, rnablk_cachedev_t, rcd_link);
        if (NULL_CACHEDEV_ID != cdp->rcd_id) {
            cdl->cdl_ids[cdl->cdl_n_cachedevs++] = cdp->rcd_id;
        }
    }
    rna_spin_in_stack_unlock_irqrestore(conn->sc_lock, irqflags);
    return 0;
}

/*
 * rnablk_handle_offline_cachedevs()
 *  Called during disconnect processing of a primary connection.
 *  Checks if any cache-devices for this conn are in the process of
 *  being offlined, and if so makes sure the disappearance of the
 *  pconn doesn't hang up the offline of the cache-device.
 */
static void
rnablk_handle_offline_cachedevs(struct rnablk_server_conn *conn)
{
    struct cachedev_list *cdl;
    rnablk_cachedev_t *cdp;
    int i;


#ifdef WINDOWS_KERNEL
    cdl = (struct cachedev_list *)ExAllocatePoolWithTag(NonPagedPool,
                                            sizeof(*cdl), RNA_ALLOC_TAG);
#else /* !WINDOWS_KERNEL */
    cdl = kmalloc(sizeof(*cdl), GFP_KERNEL);
#endif /* !WINDOWS_KERNEL */
    if (NULL == cdl) {
        rna_printk(KERN_ERR, "Unable to check for offline cache devices for "
                   "conn ["CONNFMT"]: no memory\n", CONNFMTARGS(conn));
        return;
    }
    cdl->cdl_n_cachedevs = 0;
    (void)rnablk_get_conn_cachedev_list(conn, cdl);

    for (i = 0; i < cdl->cdl_n_cachedevs; i++) {
        cdp = rnablk_get_conn_cachedev(conn, cdl->cdl_ids[i], FALSE);
        if (NULL != cdp) {
            if (atomic_bit_is_clear(&cdp->rcd_state, RCD_STATE_ONLINE)) {
                /*
                 * use reason==FAIL here, not DISCONNECT, because the
                 * parent conn isn't included in the cachedev rcd_online_refs
                 * count
                 */
                rnablk_trigger_offline_cache_device(conn, cdp->rcd_id,
                                                    CD_OFFLINE_FAIL);
            }
            rnablk_put_cachedev(cdp);
        }
    }
    kfree(cdl);
}

/*
 * rnablk_process_cache_server_disconnect_full()
 *
 *  Notes:
 *      1) This routine calls rnablk_conn_quiesce_and_disconnect() which,
 *         among other things, tries to quiesce all outstanding I/O relevant
 *         to the given 'conn'.  There may be outstanding I/O
 *         that can't be quiesced but instead must be waited for.  In
 *         that case, the return value indicates whether all I/O was
 *         successfully quiesced or not.  If not, then the expectation
 *         is that higher-level routines will take steps to ensure that
 *         this routine gets requeued (with a delay to give the outstanding
 *         I/O time to complete) -- and will continue to requeue it until
 *         all I/O is quiesced.
 *         The 'n_quiesces' input argument is relevant to this.
 *         It basically indicates the number of "retries" that have been
 *         done in attempting to quiesce the I/O.  The first time this
 *         routine is called for a given conn disconnect, 'n_quiesces'
 *         should be 0.  A value of 0 causes this routine to do additional
 *         work that only needs to be done once (i.e. on the first time
 *         through).  After that, the caller(s) of this routine should be
 *         incrementing the value of 'n_quiesces' for each retry attempt.
 *         (rnablk_quiesce_dispatch_queue() uses the value to effect a
 *         'timeout', i.e. to determine when we've waited too long for
 *         I/O to quiesce.
 *
 * Return Value:
 *  Returns TRUE if all I/O was successfully quiesced, otherwise FALSE.
 */
static boolean
rnablk_process_cache_server_disconnect_full(struct rnablk_server_conn *conn,
                                                int n_quiesces)
{
    boolean ok_to_restart;
    mutexstate_t  mutex_lock_handle;
    boolean is_quiesced;

    rna_printk(KERN_NOTICE, "Process disconnect for cache-server "
               "["rna_service_id_format"] conn ["CONNFMT"] (n_quiesces=%d)\n",
               rna_service_id_get_string(&conn->id), CONNFMTARGS(conn),
               n_quiesces);

    if (0 == n_quiesces) {          // first time through
        rnablk_svcctl_freeze();
    }
    rna_service_mutex_lock(&conn_cleanup_mutex);

    RNABLK_BUG_ON(!conn->rsc_disconnecting, "conn ["CONNFMT"]: unexpected "
                  "state\n", CONNFMTARGS(conn));

    ok_to_restart = (!atomic_read(&shutdown)
                     && atomic_read(&rna_service_detached)
                        != RNA_SERVICE_DETACHED_SHUTDOWN);

    /*
     * ORDER MATTERS!
     */
    if (0 == n_quiesces) {
        rna_printk(KERN_NOTICE, "stop devs\n");
        rnablk_stop_devs();

        rna_block_mutex_lock(&conn->block_list_lock, &mutex_lock_handle);

        rnablk_cleanup_nulldev_io(conn);
    } else {
        rna_block_mutex_lock(&conn->block_list_lock, &mutex_lock_handle);
    }

    is_quiesced = rnablk_conn_quiesce_and_disconnect(conn, NULL, NULL,
                                                     TRUE, n_quiesces);
    if (is_quiesced) {
        rnablk_restart_conn_blks(conn, NULL, ok_to_restart);
    }
    
    rna_block_mutex_unlock(&conn->block_list_lock, &mutex_lock_handle);


    if (is_quiesced) {
        rna_printk(KERN_NOTICE, "deregister conn with cfm\n");
        rnablk_deregister_cs_conn_with_cfm(conn);

        rna_printk(KERN_NOTICE, "conn unset ep\n");
        rnablk_conn_unset_ep(conn);

        display_conn_status(conn);
        conn->rsc_disconnecting = FALSE;      // can clear now

        if (ok_to_restart) {
            rna_printk(KERN_NOTICE, "start devs\n");
            rnablk_start_devs(conn, FALSE);
        }

        rnablk_svcctl_unfreeze();
        rna_service_mutex_unlock(&conn_cleanup_mutex);

        rnablk_handle_offline_cachedevs(conn);
        rna_printk(KERN_ERR, "Disconnect complete for cache-server "
                   "["rna_service_id_format"] conn [%p]\n",
                   rna_service_id_get_string(&conn->id), conn);
    } else {
        rna_service_mutex_unlock(&conn_cleanup_mutex);
        rna_printk(KERN_ERR, "Disconnect for cache-server "
                   "["rna_service_id_format"] conn [%p] still quiescing\n",
                   rna_service_id_get_string(&conn->id), conn);
    }
    return is_quiesced;
}

static void rnablk_queue_conn_disconnect_work(struct rnablk_server_conn *conn,
                                  boolean (*work_func)(
                                  struct rnablk_server_conn *, int),
                                  int n_quiesces);

static void
rnablk_queued_conn_disconnect_work(rnablk_workq_cb_arg_t arg)
{
    rnablk_dwork_t w = RNABLK_ARG_DWORK(arg);
    struct rnablk_queued_conn_disconnect_work_data *wd =
                        &w->data.rwd_rnablk_queued_conn_disconnect_work;
    boolean is_quiesced;
    uint64_t start_seconds = get_seconds();


    is_quiesced = wd->work_func(wd->conn, wd->n_quiesces);

    if (!is_quiesced) {
        rnablk_queue_conn_disconnect_work(wd->conn, wd->work_func,
                                          wd->n_quiesces + 1);
    }
    rnablk_server_conn_put(wd->conn);

    if (w->delayed) {
        atomic_dec(&delayed_work);
    }
    RNABLK_FREE_DWORK(w);
    rnablk_finish_workq_work(start_seconds);
}

static void
rnablk_queue_conn_disconnect_work(struct rnablk_server_conn *conn,
                                  boolean (*work_func)(
                                  struct rnablk_server_conn *, int),
                                  int n_quiesces)
{
    rnablk_dwork_t w;
    struct rnablk_queued_conn_disconnect_work_data *wd;

    if (unlikely(NULL == (w = RNABLK_ALLOC_DWORK()))) {
        rna_printk(KERN_ERR, "Error during disconnect processing "
                   "for conn ["CONNFMT"]: ENOMEM\n", CONNFMTARGS(conn));
    } else {
        wd = &w->data.rwd_rnablk_queued_conn_disconnect_work;

        RNABLK_INIT_DWORK(w, rnablk_queued_conn_disconnect_work);
        atomic_inc(&conn->rsc_refcount);
        wd->conn = conn;
        wd->work_func = work_func;
        wd->n_quiesces = n_quiesces;
        rna_queue_delayed_work(mt_workq, RNABLK_DWORK_OBJECT(w),
                            msecs_to_jiffies(
                            RNABLK_CACHE_DEV_QUIESCE_WAIT_INTERVAL_MSECS));
    }
}

/*
 * rnablk_process_cache_server_disconnect
 *  Called for a disconnect of a primary CS connection.
 */
static void
rnablk_process_cache_server_disconnect(struct rnablk_server_conn *conn,
                                       boolean do_work)
{
    boolean is_quiesced;

    RNABLK_BUG_ON(!is_parent_conn(conn), "expected primary CS conn "
                  "conn ["CONNFMT"] p_conn [%p]\n", CONNFMTARGS(conn),
                  conn->rsc_parent_conn);

    if (!do_work) {
        rna_printk(KERN_NOTICE, "Preprocess disconnect for cache-server "
                   "["rna_service_id_format"] conn ["CONNFMT"]\n",
                   rna_service_id_get_string(&conn->id), CONNFMTARGS(conn));
        rna_service_mutex_lock(&conn_cleanup_mutex);
        conn->rsc_disconnecting = TRUE;   // protected by conn_cleanup_mutex
        rna_service_mutex_unlock(&conn_cleanup_mutex);
        rna_printk(KERN_ERR, "Prelim disconnect complete for cache-server "
                   "["rna_service_id_format"] conn [%p]\n",
                   rna_service_id_get_string(&conn->id), conn);
        return;
    }

    is_quiesced = rnablk_process_cache_server_disconnect_full(conn, 0);
    if (!is_quiesced) {
        rnablk_queue_conn_disconnect_work(conn,
                            rnablk_process_cache_server_disconnect_full, 1);
    }
}

/*
 * rnablk_undo_conn_io()
 *  "Undo" any accounting settings done for the given ios when it
 *  was queued to the conn io_queue.
 *  (For use during disconnect or cache-device offline processing when
 *  we move ios' around willy nilly, to make sure accounting stays
 *  in sync).
 *
 * 'lock_held' indicates whether or not the caller already holds the
 * the blk lock.  If not, this routine acquires it.
 */
void
rnablk_undo_conn_io(struct io_state *ios, boolean lock_held)
{
    struct cache_blk *blk;
    lockstate_t irqflags;

    if (rnablk_is_ios_io_type(ios)) {
        blk = ios->blk;

        /*
         * 'inflight_ios' & BLK_F_WAIT_ON_IO need to be checked/accessed
         * together atomically, so blk lock is needed for that.
         * (Note, the replication of code in the following if/else clause,
         * is to solve an annoying (and erroneous) compiler warning about
         * irqflags not being initialized).
         */
        if (lock_held) {
            if (atomic_dec_and_test(&blk->inflight_ios)) {
                (void)rnablk_cache_blk_state_transition(blk,
                                        RNABLK_CACHE_BLK_DISCONN_PENDING,
                                        RNABLK_CACHE_BLK_DISCONNECTED);
                atomic_bit_clear(&blk->cb_flags, BLK_F_WAIT_ON_IO);
            }
        } else {
            rnablk_lock_blk_irqsave(blk, irqflags);
            if (atomic_dec_and_test(&blk->inflight_ios)) {
                (void)rnablk_cache_blk_state_transition(blk,
                                        RNABLK_CACHE_BLK_DISCONN_PENDING,
                                        RNABLK_CACHE_BLK_DISCONNECTED);
                atomic_bit_clear(&blk->cb_flags, BLK_F_WAIT_ON_IO);
            }
            rnablk_unlock_blk_irqrestore(blk, irqflags);
        }
    }
    return;
}

/*
 * rnablk_setup_conn_io()
 *  Re-establish appropriate accounting settings for the given ios before
 *  we (forcibly, so to speak) move it to a conn io_queue.
 *  (For use during disconnect or cache-device offline processing when
 *  we move ios' around willy nilly, to make sure accounting stays
 *  in sync).
 */
INLINE void
rnablk_setup_conn_io(struct io_state *ios)
{
    struct cache_blk *blk;
    lockstate_t irqflags;

    if (rnablk_is_ios_io_type(ios)) {
        blk = ios->blk;
        /*
         * Must acquire the blk lock to increment inflight_ios, in order
         * to sync with BLK_F_WAIT_ON_IO usage.
         */
        rnablk_lock_blk_irqsave(blk, irqflags);
        atomic_inc(&blk->inflight_ios);
        rnablk_unlock_blk_irqrestore(blk, irqflags);
    }
}

/*
 * rnablk_process_dev_con_disconnect_phase2()
 *  Perform 'phase2' per-cachedev conn disconnect processing.
 *  Phase2 includes ensuring that all outstanding I/O for the 'conn'
 *  has been quiesced, and, once that is the case, finishing up other
 *  cleanup for the 'conn'.
 *
 *  Notes:
 *      1) This routine calls rnablk_quiesce_dispatch_queue() which,
 *         tries to quiesce all outstanding I/O relevant
 *         to the given 'conn'.  There may be outstanding I/O
 *         that can't be quiesced but instead must be waited for.  In
 *         that case, the return value indicates whether all I/O was
 *         successfully quiesced or not.  If not, then the expectation
 *         is that higher-level routines will take steps to ensure that
 *         this routine gets requeued (with a delay to give the outstanding
 *         I/O time to complete) -- and will continue to requeue it until
 *         all I/O is quiesced.
 *         The 'n_quiesces' input argument is relevant to this.
 *         It basically indicates the number of "retries" that have been
 *         done in attempting to quiesce the I/O.  The first time this
 *         routine is called for a given conn disconnect, 'n_quiesces'
 *         should be 0.  A value of 0 causes this routine to do additional
 *         work that only needs to be done once (i.e. on the first time
 *         through).  After that, the caller(s) of this routine should be
 *         incrementing the value of 'n_quiesces' for each retry attempt.
 *         (rnablk_quiesce_dispatch_queue() uses the value to effect a
 *         'timeout', i.e. to determine when we've waited too long for
 *         I/O to quiesce.
 *
 * Return Value:
 *  Returns TRUE if all I/O was successfully quiesced, otherwise FALSE.
 */
static boolean
rnablk_process_dev_conn_disconnect_phase2(struct rnablk_server_conn *conn,
                                          int n_quiesces)
{
    struct rnablk_server_conn *p_conn = conn->rsc_parent_conn;
    rnablk_cachedev_t *conn_cachedev = conn->rsc_cachedev;
    lockstate_t irq_flags;
    struct cache_blk *blk;
    struct com_ep *p_ep;
    struct io_state *ios;
    struct blk_lru_list *ent;
    boolean offline_cachedev;
    int is_wref;
    mutexstate_t mutex_lock_handle;
    boolean is_quiesced;

#ifdef WINDOWS_KERNEL
    struct _LIST_ENTRY dispatch_ioq;
    dispatch_ioq.Flink = &(dispatch_ioq);
    dispatch_ioq.Blink = &(dispatch_ioq);
#else
    LIST_HEAD(dispatch_ioq);
#endif //WINDOWS_KERNEL

    RNABLK_DBG_BUG_ON(is_parent_conn(conn), "expected cache-device conn "
                      "["CONNFMT"]\n", CONNFMTARGS(conn));
    rna_service_mutex_lock(&conn_cleanup_mutex);

    rna_printk(KERN_NOTICE, "Process disconnect phase2 for cache-server conn "
               "["CONNFMT"] ["rna_service_id_format"] p_conn [%p] "
               "(n_quiesces=%d)\n",
               CONNFMTARGS(conn),
               rna_service_id_get_string(&conn->id), p_conn, n_quiesces);

    rna_block_mutex_lock(&p_conn->block_list_lock, &mutex_lock_handle);

    rna_printk(KERN_NOTICE, "quiesce dispatch_queue\n");
    is_quiesced = rnablk_quiesce_dispatch_queue(conn, conn_cachedev,
                                                n_quiesces);

    if (!is_quiesced) {
        rna_block_mutex_unlock(&p_conn->block_list_lock,
                               &mutex_lock_handle);
        rna_service_mutex_unlock(&conn_cleanup_mutex);
        rna_printk(KERN_ERR, "Disconnect for cache-server "
                   "["rna_service_id_format"] conn ["CONNFMT"] "
                   "still quiescing\n",
                   rna_service_id_get_string(&conn->id), CONNFMTARGS(conn));
        return is_quiesced;
    }

    /* bits and pieces of rnablk_conn_blks_sort_list() */
    blk_lru_list_for_each(ent, &conn_cachedev->rcd_block_list) {
        blk = blk_lru_entry(ent, &is_wref);

        if (unlikely(IS_MARKER_BLK(blk))) {
            continue;       // skip marker blocks
        }

        if (is_wref) {
            continue;   // process each blk only once, so skip wref entry!
        }

        RNABLK_DBG_BUG_ON(blk->blk_cachedev != conn_cachedev,
                          "blk [%p] block [%llu] expected cachedev %p got "
                          "cachedev %p\n", blk, blk->block_number,
                          conn_cachedev, blk->blk_cachedev);

        if (conn != blk->cb_dev_conn) {
            rnablk_trc_discon(0, "skipping blk=%p [%"PRIu64"] conn "
                              "["CONNFMT"]\n", blk, blk->block_number,
                              CONNFMTARGS(blk->cb_dev_conn));
            continue;
        }

        rna_printk(KERN_DEBUG,
                   "device [%s] block [%"PRIu64"] state [%s]\n",
                   blk->dev->name,
                   blk->block_number,
                   rnablk_cache_blk_state_string(blk->state));

        rnablk_cache_blk_ref(blk);
        rnablk_lock_blk_irqsave(blk, irq_flags);

        atomic_bit_clear(&blk->cb_flags, BLK_F_QUIESCE_COMPLETE);
        blk->cb_dev_conn = NULL;
        rnablk_trc_discon(1, "reassign blk=%"PRIu64" to p_conn ["CONNFMT"]\n",
                          blk->block_number, CONNFMTARGS(p_conn));

        if (RNABLK_CACHE_BLK_INVALID != blk->state) {
            struct list_head *l_ent, *l_next;
            /*
             * move all IOs out of the dispatch_queue, so they can be
             * moved into the new io_queue.
             */
            list_for_each_safe(l_ent, l_next, &blk->dispatch_queue) {
                ios = list_entry(l_ent, struct io_state, l);
                if (rnablk_get_ep_conn(ios->ep) != conn) {
                    rnablk_trc_discon(1,
                           "ios [%p] tag ["TAGFMT"] block [%"PRIu64"] "
                           "state [%s] type [%s] "
                           "rcnt=%d io_conn=%p ep=%p conn ["CONNFMT"] - "
                           "not using conn, ignoring.\n",
                           ios, TAGFMTARGS(ios->tag), blk->block_number,
                           rnablk_cache_blk_state_string(blk->state),
                           rnablk_op_type_string(ios->type),
                           atomic_read(&ios->ref_count),
                           rnablk_get_ep_conn(ios->ep),
                           ios->ep,
                           CONNFMTARGS(conn));
                    continue;
                }
                rnablk_trc_discon(1, "move ios [%p] tag ["TAGFMT"] blk "
                           "[%"PRIu64"] state [%s] type [%s] qstate [%s] "
                           "from dispatch to %s queue\n", ios,
                           TAGFMTARGS(ios->tag), blk->block_number,
                           rnablk_cache_blk_state_string(blk->state),
                           rnablk_op_type_string(ios->type),
                           rnablk_ios_q_string(ios_queuestate_get(ios)),
                           p_conn->rsc_disconnecting ? "bl" : "pconn-ioqueue");
                rnablk_io_completed_nolock(ios, blk);
                if (p_conn->rsc_disconnecting) {
                    rnablk_queue_blk_io_nolock(blk, ios, QUEUE_HEAD);
                } else {
                    list_add_tail(&ios->l, &dispatch_ioq);
                }
                /*
                 * Clear ios->ep so it doesn't get erroneously used,
                 * i.e. for instance in the rnablk_cache_timeout path()
                 */
                rnablk_unset_ios_ep(ios);
            }
        }
        rnablk_unlock_blk_irqrestore(blk, irq_flags);
        rnablk_cache_blk_release(blk);
    }

    rna_block_mutex_unlock(&p_conn->block_list_lock, &mutex_lock_handle);

    /*
     * Move the ios's we removed from this conn's dispatch_queue
     * over to the primary conn queue.
     */
    rna_spin_in_stack_lock_irqsave(p_conn->sc_lock, irq_flags);
    if (!p_conn->rsc_disconnecting) {
        while (!list_empty(&dispatch_ioq)) {
            ios = list_first_entry(&dispatch_ioq, struct io_state, l);
            list_del_init(&ios->l);
            rnablk_setup_conn_io(ios);
            rnablk_set_ios_ep(ios, p_conn->ep);
            rnablk_queue_conn_io(p_conn, ios, QUEUE_TAIL);
        }
    }

    /*
     * Check cachedev state (& decrement rcd_online_refs while still
     * holding p_conn->sc_lock, to serialize with calls to
     * rnablk_offline_conn_cachedev()
     */
    if (atomic_bit_is_set(&conn->rsc_flags, RSC_F_LATE_CONNECT)) {
        /*
         * This conn connected after the cachedev had already been offlined,
         * so it didn't get counted as one of the cachedev's online refs.
         */
        offline_cachedev = FALSE;
    } else if (atomic_bit_is_clear(&conn_cachedev->rcd_state,
                                   RCD_STATE_ONLINE)) {
        offline_cachedev = TRUE;
    } else {
        offline_cachedev = FALSE;
        atomic_dec(&conn_cachedev->rcd_online_refs);
    }

    rna_spin_in_stack_unlock_irqrestore(p_conn->sc_lock, irq_flags);

    rnablk_conn_unset_ep(conn);

    if (!atomic_read(&shutdown) && !atomic_read(&rna_service_detached)) {
        rna_printk(KERN_NOTICE, "start devs\n");
        rnablk_start_devs(NULL, FALSE);
    }

    rnablk_svcctl_unfreeze();
    rna_service_mutex_unlock(&conn_cleanup_mutex);

    if (offline_cachedev) {
        /*
         * Looks like our associated cache-device has gone offline, so
         * this connection needs to register that it's gone and if
         * appropriate, finish up the offline processing for it.
         */
        rnablk_trc_discon(1, "cachedev=%"PRIx64" is offline, do checks\n",
                          conn_cachedev->rcd_id);
        rnablk_trigger_offline_cache_device(conn, conn_cachedev->rcd_id,
                                            CD_OFFLINE_DISCONNECT);
    }

    /* Kickstart things on the primary conn if needed */
    rnablk_schedule_conn_dispatch(p_conn);

    rna_printk(KERN_ERR, "Disconnect complete for cache-server "
               "["rna_service_id_format"] conn ["CONNFMT"]\n",
               rna_service_id_get_string(&conn->id), CONNFMTARGS(conn));

    /*
     * Finish up primary conn disconnect processing if we're the last
     * man out.  (If RSC_F_LATE_CONNECT is set, this conn was never
     * fully associated with the primary conn, so mustn't do this work!).
     */
    if (!atomic_bit_is_set(&conn->rsc_flags, RSC_F_LATE_CONNECT)
        && 0 == atomic_dec_return(&p_conn->rsc_connected_conns)) {
        rnablk_trc_discon(1, "Now process discon for p_conn=%p\n", p_conn);
        p_ep = p_conn->ep;      // save a copy as it will get cleared in call
        rnablk_process_cache_server_disconnect(p_conn, TRUE);
        /* release the ep ref added in rnablk_process_conn_disconnect */
        com_release_ep(p_ep);
    }

    /*
     * Last thing on our way out, drop this conn's reference to the cachedev
     * (Note the above rna_printk uses it in CONNFMTARGS, so must do this
     * put after that!).  This may free 'conn' as well as 'conn_cachedev'.
     */
    rnablk_put_cachedev(conn_cachedev);

    return TRUE;
}

/*
 * rnablk_process_dev_conn_disconnect()
 *  Called for a disconnect of a per-cache-device CS connection.
 */
static void
rnablk_process_dev_conn_disconnect(struct rnablk_server_conn *conn)
{
    struct rnablk_server_conn *p_conn = conn->rsc_parent_conn;
    lockstate_t irq_flags;
    struct io_state *ios;
    mutexstate_t mutex_lock_handle;
    boolean is_quiesced;

#ifdef WINDOWS_KERNEL
    struct _LIST_ENTRY conn_ioq;
    struct _LIST_ENTRY discard_ioq;
    conn_ioq.Flink = &(conn_ioq);
    conn_ioq.Blink = &(conn_ioq);
    discard_ioq.Flink = &(discard_ioq);
    discard_ioq.Blink = &(discard_ioq);
#else
    LIST_HEAD(conn_ioq);            // wait for connection queue
    LIST_HEAD(discard_ioq);
#endif //WINDOWS_KERNEL

    RNABLK_BUG_ON(is_parent_conn(conn), "expected cache-device conn "
                  "["CONNFMT"]\n", CONNFMTARGS(conn));

    rna_printk(KERN_NOTICE, "Process disconnect for cache-server conn "
               "["CONNFMT"] ["rna_service_id_format"] p_conn [%p]\n",
               CONNFMTARGS(conn),
               rna_service_id_get_string(&conn->id), p_conn);

    rnablk_svcctl_freeze();
    rna_service_mutex_lock(&conn_cleanup_mutex);

    rna_printk(KERN_NOTICE, "stop devs\n");
    rnablk_stop_devs();

    rna_block_mutex_lock(&conn->block_list_lock, &mutex_lock_handle);

    rnablk_cleanup_nulldev_io(conn);

    RNABLK_BUG_ON(0 != conn->block_list_length,
                  "conn ["CONNFMT"] has block_list_length=%d\n",
                  CONNFMTARGS(conn), conn->block_list_length);

    /* bits and pieces of rnablk_cleanup_conn_ioq()... */
    rna_printk(KERN_NOTICE, "rebase conn ioq (is_empty=%d)\n",
               list_empty(&conn->io_queue));
    rna_spin_in_stack_lock_irqsave(conn->sc_lock, irq_flags);
    while (!list_empty(&conn->io_queue)) {
        ios = list_first_entry(&conn->io_queue, struct io_state, l);
        rnablk_trc_discon(1, "ios [%p] tag ["TAGFMT"] on conn ioqueue, move "
                          "to %s queue\n", ios, TAGFMTARGS(ios->tag),
                          p_conn->rsc_disconnecting ? "bl" : "pconn-ioqueue");
        rnablk_unset_ios_ep(ios);
        rnablk_dequeue_conn_io(ios);
        if (unlikely(!IOS_HAS_IOREQ(ios))) {
            /* IOS isn't associated with any incoming I/O, safe to drop it. */
            list_add_tail(&ios->l, &discard_ioq);
        } else if (p_conn->rsc_disconnecting) {
            rnablk_undo_conn_io(ios, FALSE);
            rnablk_queue_blk_io(ios->blk, ios, QUEUE_HEAD);
        } else {
            list_add_tail(&ios->l, &conn_ioq);
        }
    }
    rna_spin_in_stack_unlock_irqrestore(conn->sc_lock, irq_flags);

    /*
     * Finish up the ios's we decided to drop.
     */
    while (!list_empty(&discard_ioq)) {
        ios = list_first_entry(&discard_ioq, struct io_state, l);
        list_del_init(&ios->l);
        rna_printk(KERN_NOTICE, "dropping ios [%p] tag ["TAGFMT"] type [%s] "
                   "device [%s] block [%"PRIu64"] state [%s]\n",
                   ios, TAGFMTARGS(ios->tag),
                   rnablk_op_type_string(ios->type),
                   ios->blk->dev->name, ios->blk->block_number,
                   rnablk_cache_blk_state_string(ios->blk->state));
        rnablk_ios_finish(ios);
    }

    rna_block_mutex_unlock(&conn->block_list_lock, &mutex_lock_handle);

    if (!list_empty(&conn_ioq)) {
        rna_spin_in_stack_lock_irqsave(p_conn->sc_lock, irq_flags);
        while (!list_empty(&conn_ioq)) {
            /*
             * (no need to call rnablk_setup_conn_io() for these,
             * because they came straight from another io_queue, so are
             * already good to go.)
             */
            ios = list_first_entry(&conn_ioq, struct io_state, l);
            list_del_init(&ios->l);
            rnablk_set_ios_ep(ios, p_conn->ep);
            rnablk_queue_conn_io(p_conn, ios, QUEUE_TAIL);
        }
        rna_spin_in_stack_unlock_irqrestore(p_conn->sc_lock, irq_flags);
    }

    rna_service_mutex_unlock(&conn_cleanup_mutex);

    is_quiesced = rnablk_process_dev_conn_disconnect_phase2(conn, 0);

    if (!is_quiesced) {
        rnablk_queue_conn_disconnect_work(conn,
                                  rnablk_process_dev_conn_disconnect_phase2, 1);
    }
}

/*
 * rnablk_process_conn_disconnect()
 *  Common disconnect processing function for any CS connection.
 *
 * Called by rnablk_disconn_cb() for a com disconnect
 * and by rnablk_retry_connection() for a failed connection attempt.
 */
void
rnablk_process_conn_disconnect(struct rnablk_server_conn *conn)
{
    struct rnablk_server_conn *p_conn = conn->rsc_parent_conn;
    lockstate_t irq_flags;
    struct list_head *ent;
    rnablk_cachedev_t *cdp;
    struct com_ep *p_ep;
    int state, save_state;

    /*
     * If this disconnect callback is due to a failed connection attempt
     * (as opposed to an actual disconnect), then the conn may be in
     * RNABLK_CONN_CONNECT_PENDING state.  It is a requirement that the
     * conn->sc_lock be held when transitioning out of that state, so
     * acquire the lock here, for that (possible) case.
     * (This is a requirement so we handshake correctly with
     * rnablk_cache_connected(); see comments there and header comments
     * for rnablk_conn_set_ep()).
     */
    rna_spin_in_stack_lock_irqsave(conn->sc_lock, irq_flags);
    state = atomic_cmpxchg(&conn->state, RNABLK_CONN_CONNECT_PENDING,
                           RNABLK_CONN_DISCONNECTED);
    rna_spin_in_stack_unlock_irqrestore(conn->sc_lock, irq_flags);

    do {
        save_state = state;
        switch (state) {
        case RNABLK_CONN_CONNECT_PENDING:
            if (!is_parent_conn(conn)) {
                /*
                 * Drop the cachedev reference added when we initiated
                 * the connection attempt.
                 */
                rnablk_put_cachedev(conn->rsc_cachedev);
            }
            // fallthru
        case RNABLK_CONN_DISCONNECTED:
        case RNABLK_CONN_DISCONNECT_INPROG:
            /* nothing (more) to do */
            return;

        case RNABLK_CONN_CONNECTED:
        case RNABLK_CONN_DISCONNECT_PENDING:
            /* disconnect processing is needed */
            state = atomic_cmpxchg(&conn->state, save_state,
                                   RNABLK_CONN_DISCONNECT_INPROG);
            break;
        }
    } while (state != save_state);

    /* It's a true disconnect, so do the processing */

    rnablk_trc_discon(1, "Disconnect of conn ["CONNFMT"] p_conn=%p n_conn=%d\n",
                      CONNFMTARGS(conn), p_conn,
                      atomic_read(&p_conn->rsc_connected_conns));

    if (is_parent_conn(conn)) {
        /*
         * We're the primary.  Can't complete processing of this disconnect
         * unless all our cache-device connections are also disconnected, so
         * see to that now.  The last man out will perform the final
         * processing for this primary connection disconnect.
         * (So add a reference to the 'ep' to make sure it sticks around
         * until that final processing).
         */
        com_inc_ref_ep(conn->ep);
        rna_spin_in_stack_lock_irqsave(conn->sc_lock, irq_flags);
        if (atomic_read(&p_conn->rsc_connected_conns) > 1) {
            /*
             * rsc_connected_conns shows there may be other live child
             * connections, so force them to disconnect..
             */
            list_for_each(ent, &conn->rsc_cachedevs) {
                cdp = list_entry(ent, rnablk_cachedev_t, rcd_link);
                rnablk_queue_drop_dev_conns(cdp);
            }
        }
        rna_spin_in_stack_unlock_irqrestore(conn->sc_lock, irq_flags);
        rnablk_process_cache_server_disconnect(p_conn, FALSE);
        if (0 == atomic_dec_return(&conn->rsc_connected_conns)) {
            /*
             * No cache-device connections are (still) present, so go
             * ahead with final processing for this disconnect, including
             * dropping the reference we put on the primary EP (see above).
             */
            rnablk_trc_discon(1, "Now process discon for p_conn=%p\n", p_conn);
            p_ep = conn->ep;  // save a copy as it will get cleared in call
            rnablk_process_cache_server_disconnect(conn, TRUE);
            com_release_ep(p_ep);
        }
    } else {
        /*
         * This is a cache-device connection.  Perform the disconnect for it.
         */
        rnablk_process_dev_conn_disconnect(conn);
    }
}

/*
 * rnablk_detect_cache_failure_debug()
 *  This routine is used to determine if an ios has completed with
 *  an error status that indicates a cache-device failure, and if so,
 *  instigates cache-device failure processing.
 *
 * Return Value;
 *  Returns TRUE if the ios status indicated a cache-device failure.
 *  Otherwise returns FALSE.
 */
boolean
rnablk_detect_cache_failure_debug(const char *function, const int line,
                                  struct io_state *ios, int ios_status,
                                  int cachedev_fail_status, boolean notify_cs)
{
    if (unlikely(ios_status == cachedev_fail_status)) {
        /*
         * This ios operation failed due to a cache-device failure.
         * Instigate our client-side cachedevice failure
         * procedure.  Leave the ios on the dispatch queue so it can
         * be reissued later,
         */
        rnablk_trc_discon(1, "[%s:%d] CACHEFAIL[%"PRIx64"] ios [%p] tag "
                          "["TAGFMT"] block [%"PRIu64"] state [%s] ref [%s] "
                          "type [%s] conn ["CONNFMT"]\n",
                          function, line, ios->blk->blk_cachedev->rcd_id,
                          ios, TAGFMTARGS(ios->tag), ios->blk->block_number,
                          rnablk_cache_blk_state_string(ios->blk->state),
                          get_lock_type_string(ios->blk->ref_type),
                          rnablk_op_type_string(ios->type),
                          CONNFMTARGS(rnablk_get_ep_conn(ios->ep)));
        rnablk_io_cachedev_error(ios, notify_cs);
        return TRUE;
    }
    return FALSE;
}

static int
rnablk_connect_server(struct rnablk_server_conn *conn,
                      uint32_t                   ip_addr,
                      uint32_t                   port,
                      enum com_type              transport,
                      int                        type,
                      int                        size)
{
    struct com_ep *ep;
    struct sockaddr_in in;
    int local_max_wr;
    int local_size;
    struct rna_dev_attr attr;

    ENTER;

    BUG_ON(NULL == conn);

    if (0 != com_get_device_attributes(g_com, transport, &attr)) {
        rna_printk(KERN_ERR, "transport not supported, "
                   "not connecting to cache server\n");
        GOTO (out, -EINVAL);
    }

    if (RC == transport) {
        local_max_wr = min(attr.max_wr, RNA_MAX_RDMA_WR);
    } else {
        local_max_wr = min (attr.max_wr, max_wr);
    }
    conn->send_bufs = local_max_wr;
    conn->rdma_bufs = local_max_wr;
    /* clear dispatch_scheduled to ensure scheduling gets reenabled */
    atomic_bit_clear(&conn->rsc_flags, RSC_F_DISPATCH_SCHEDULED);
    local_size   = PAGE_SIZE;

    /*
     * XXX: In the long run, we should probably have a per-connection max sge
     * but we currently don't have access to connection info when we map the
     * io into an sge (rnablk_rq_map_sg() called from rnablk_strategy()).
     *
     * For now, just use the lowest common denominator of our connections'
     * limits.
     */
    max_sge = min(RNA_MAX_SGE, min(max_sge, attr.max_sge));

    /*
     * Set the 'sync_recv_flag' argument to true for primary connections.
     * This is to deal with the strict ordering requirement we have that
     * we receive/process the CACHE_RSV_ACCESS message before the
     * CACHE_RESPONSE for the LOCK_MASTER_BLK.  The cache server always
     * sends them in the correct order, but without the 'sync_recv_flag',
     * it is possible for them to be processed out-of-order.
     */
    ret = com_alloc_ep(g_com,
                      &g_com_attr,
                       transport,
                       NULL,
                       NULL,
                       local_max_wr,
                       local_max_wr,
                       size,
                       min(RNA_MAX_RDMA_WR,local_max_wr),
                       local_size,
                       type,
                       is_parent_conn(conn) ? 1 : 0,
                       rb_bounce_buffer_bytes, 
                       rb_bounce_segment_bytes,
                       &ep);

    if (0 != ret) {
        rna_printk(KERN_WARNING, "could not allocate ep\n");
    } else {
        com_set_ep_context(ep, conn);
        /*
         * Increment conn's refcount to reflect that 'ep' now references it.
         * This reference won't be dropped until our rnablk_destructor_cb()
         * callback gets called, which happens when the ep gets freed.
         */
        atomic_inc(&conn->rsc_refcount);

        in.sin_family      = AF_INET;
#ifdef WINDOWS_KERNEL
        in.sin_port        = RtlUshortByteSwap((USHORT)port);
#else
        in.sin_port        = port;
#endif /*WINDOWS_KERNEL*/
        in.sin_addr.s_addr = ip_addr;

        if( (ret = com_connect( ep,(rna_sockaddr_t *)(struct sockaddr *)&in )) ){
            rna_printk(KERN_WARNING, "could not connect to remote server\n");
            com_release_ep(ep);
        }
    }

out:

    EXIT;
}

// runs in kthread context
static void
rnablk_retry_connection(rnablk_workq_cb_arg_t arg)
{
    struct work_struct *work = (struct work_struct *)arg;
    struct rnablk_work *w = container_of( work,struct rnablk_work,work );
    struct rnablk_retry_connection_data *wd =
                            &w->data.rwd_rnablk_retry_connection;
    struct rnablk_server_conn *conn = wd->conn;
    lockstate_t irqflags;
    int start, limit;
    int save_active_if;
    int i, j;
    struct rna_if_info *iface = NULL;
    int connected = FALSE;
    uint64_t start_seconds = get_seconds();
    ENTER;

#ifdef WINDOWS_KERNEL
	if(g_com == NULL)
	{
		PComLayerManagerObj pComManager = GetDriverComLayerManager();
		g_com = pComManager->pCom;
		g_com_attr = pComManager->com_attr;
	}
#endif /*WINDOWS_KERNEL*/

    if (unlikely(NULL == conn)) {
        rna_printk (KERN_ERR, "shouldn't happen: conn is NULL\n");
        dump_stack();
    } else if (unlikely(RNABLK_CONN_CONNECT_PENDING
                        != atomic_read(&conn->state))) {
        rna_printk(KERN_ERR, "conn ["CONNFMT"] CS ["rna_service_id_format"] in "
                   "unexpected state [%s]\n", CONNFMTARGS(conn),
                   rna_service_id_get_string(&conn->id),
                   rnablk_conn_state_string(atomic_read(&conn->state)));
    } else {
        rna_printk(KERN_DEBUG,
                   "conn ["CONNFMT"] CS ["rna_service_id_format"]\n",
                   CONNFMTARGS(conn),
                   rna_service_id_get_string(&conn->id));

        if (!atomic_read(&shutdown) &&
            !atomic_read(&rna_service_detached)) {

            if (0 == conn->if_attempts) {
                if (++conn->rsc_active_if >= 
                    (int)conn->if_table.table_entries) {
                    conn->rsc_active_if = 0;
                }
                conn->if_attempts = conn_set_retry_attempts(
                                            conn->if_table.ifs[
                                            conn->rsc_active_if].type) - 1;
            } else {
                conn->if_attempts--;
            }

            save_active_if = conn->rsc_active_if;

            start = save_active_if;
            limit = conn->if_table.table_entries;
            for (i = 0; !connected && i < 2;
                 i++, start = 0, limit = save_active_if) {
                for (j = start; j < limit; j++) {
                    iface = &conn->if_table.ifs[j];
                    if (j != save_active_if) {
                        conn->rsc_active_if = j;
                        conn->if_attempts = conn_set_retry_attempts(
                                                            iface->type) - 1;
                    }

                    if (com_transport_enabled(g_com, iface->type)) {
                        rna_printk(KERN_NOTICE,
                                   "Connecting to CS ["NIPQUAD_FMT"/%d] "
                                   "via [%s] conn ["CONNFMT"] active_if [%d] "
                                   "remaining attempts [%d]\n",
                                   NIPQUAD(iface->addr),
                                   iface->port,
                                   com_get_transport_type_string(iface->type),
                                   CONNFMTARGS(conn),
                                   conn->rsc_active_if,
                                   conn->if_attempts);

                        ret = rnablk_connect_server(conn,
                                                iface->addr,
                                                iface->port,
                                                iface->type,
                                                USR_TYPE_CACHE,
                                                max(sizeof(struct cache_cmd),
                                                DEFAULT_RDMA_SENDBUF_SIZE));
                        if (0 == ret) {
                            connected = TRUE;
                            break;
                        } else {
                            rna_printk(KERN_ERR,
                                       "Failed Connecting to "
                                       "CS ["NIPQUAD_FMT"/%d] via [%s] "
                                       "conn ["CONNFMT"] ret = %d.%s\n",
                                       NIPQUAD(iface->addr),
                                       iface->port,
                                       com_get_transport_type_string(
                                       iface->type),
                                       CONNFMTARGS(conn),
                                       ret,
                                       (RC == iface->type) ? 
                                       " Performance may be degraded." : "");
                        }
                    } else {
                        rna_printk(KERN_ERR,
                                   "Failed to connect to CS ["NIPQUAD_FMT"/%d] "
                                   "via [%s] conn ["CONNFMT"] active_if [%d] "
                                   "attempts [%d]\n",
                                   NIPQUAD(iface->addr),
                                   iface->port,
                                   com_get_transport_type_string(iface->type),
                                   CONNFMTARGS(conn),
                                   conn->rsc_active_if, conn->if_attempts);
                    }
                }
            }
            if (!connected) {
                rna_printk(KERN_ERR, "Failed to connect to "
                           "CS ["rna_service_id_format"] conn ["CONNFMT"] "
                           "active_if [%d] attempts [%d]\n",
                           rna_service_id_get_string(&conn->id),
                           CONNFMTARGS(conn),
                           conn->rsc_active_if, conn->if_attempts);
                rna_spin_in_stack_lock_irqsave(conn->sc_lock, irqflags);
                if (RNABLK_CONN_CONNECT_PENDING !=
                    atomic_cmpxchg(&conn->state, RNABLK_CONN_CONNECT_PENDING,
                                   RNABLK_CONN_DISCONNECTED)) {
                    rna_printk(KERN_ERR,
                               "conn ["CONNFMT"] CS ["rna_service_id_format"] "
                               "in unexpected state [%s]\n",
                               CONNFMTARGS(conn),
                               rna_service_id_get_string(&conn->id),
                               rnablk_conn_state_string(atomic_read(
                               &conn->state)));
                }
                rna_spin_in_stack_unlock_irqrestore(conn->sc_lock, irqflags);
            }
        }
    }

    atomic_bit_test_and_clear(&conn->rsc_flags, RSC_F_QUEUING_CONN_RETRY);
    if (!connected && !is_parent_conn(conn)) {
        rnablk_put_cachedev(conn->rsc_cachedev);
    }

    rnablk_mempool_free( w, work_cache_info );
    rnablk_finish_workq_work(start_seconds);

    EXITV;
}

/*
 * rnablk_drop_connection()
 *  Inline function to drop a connection.
 *  (Not to be confused with rnablk_drop_connection_wf() which is a queued
 *  functon; the semantics are very slightly different).
 */
void
rnablk_drop_connection(struct rnablk_server_conn *conn)
{
    struct com_ep *ep = NULL;

    if (RNABLK_CONN_CONNECTED == atomic_cmpxchg(&conn->state,
                                            RNABLK_CONN_CONNECTED,
                                            RNABLK_CONN_DISCONNECT_PENDING)) {
        ep = rnablk_conn_get_ep(conn);
        rnablk_trc_discon(1, "Drop conn ["CONNFMT"] ep=%p\n",
                          CONNFMTARGS(conn), ep);
        if (NULL != ep) {
            rna_printk(KERN_INFO,
                       "Dropping connection to CS ["rna_service_id_format"] conn ["CONNFMT"] ep [%p]\n",
                       rna_service_id_get_string(&conn->id),
                       CONNFMTARGS(conn),
                       ep);
            com_disconnect(ep);
            com_release_ep(ep);
        } else {
            rna_printk(KERN_ERR,
                       "CS ["rna_service_id_format"] has NULL EP\n",
                       rna_service_id_get_string(&conn->id));
        }
    } else {
        rnablk_trc_discon(1, "Not connected conn ["CONNFMT"]\n",
                          CONNFMTARGS(conn));
    }
}

// runs in kthread context
static void
rnablk_drop_connection_wf(rnablk_workq_cb_arg_t arg)
{
    struct work_struct *work = (struct work_struct *)arg;
    struct rnablk_work *w = container_of( work,struct rnablk_work,work );
    struct rnablk_drop_connection_wf_data *wd = 
                                    &w->data.rwd_rnablk_drop_connection_wf;
    struct rnablk_server_conn *conn = wd->conn;
    struct com_ep *ep = NULL;
    uint64_t start_seconds = get_seconds();
    ENTER;

	UNREFERENCED_PARAMETER(ret);

    if (RNABLK_CONN_DISCONNECT_PENDING == atomic_read(&conn->state) &&
	    (NULL != conn->ep)) {
        ep = rnablk_conn_get_ep(conn);
        rnablk_trc_discon(1, "Drop conn ["CONNFMT"] ep=%p\n", CONNFMTARGS(conn),
                          ep);
        if (NULL != ep) {
            rna_printk(KERN_INFO,
                       "Dropping connection to CS ["rna_service_id_format"] conn ["CONNFMT"] ep [%p]\n",
                       rna_service_id_get_string(&conn->id),
                       CONNFMTARGS(conn),
                       ep);
            com_disconnect(ep);
            com_release_ep(ep);
        } else {
            rna_printk(KERN_ERR,
                       "CS ["rna_service_id_format"] has NULL EP\n",
                       rna_service_id_get_string(&conn->id));
        }
    } else {
        rnablk_trc_discon(1, "wrong state [%d] conn ["CONNFMT"]\n",
                          atomic_read(&conn->state), CONNFMTARGS(conn));
    }
    rnablk_server_conn_put(conn);

    rnablk_mempool_free( w, work_cache_info );
    rnablk_finish_workq_work(start_seconds);

    EXITV;
}

void
rnablk_queue_conn_disconnect(struct rnablk_server_conn *conn)
{
    struct rnablk_work *w = NULL;
    struct rnablk_drop_connection_wf_data *wd = NULL;

    if (!atomic_read(&shutdown)) {
        if((NULL != conn) &&
           (RNABLK_CONN_CONNECTED ==
            atomic_cmpxchg(&conn->state,
                            RNABLK_CONN_CONNECTED,
                            RNABLK_CONN_DISCONNECT_PENDING))) {
            rna_printk(KERN_INFO,
                       "CS conn ["CONNFMT"] ["rna_service_id_format"] EP [%p] "
                       "state [%s]->[%s]\n", CONNFMTARGS(conn),
                       rna_service_id_get_string(&conn->id), conn->ep,
                       rnablk_conn_state_string(RNABLK_CONN_CONNECTED),
                       rnablk_conn_state_string(atomic_read(&conn->state)));

            w = rnablk_mempool_alloc(work_cache_info);
            if (NULL == w) {
                rna_printk(KERN_ERR,
                           "failed to alloc work queue object");
            } else {
                RNABLK_INIT_RNABLK_WORK(w, wd, rnablk_drop_connection_wf);
                atomic_inc(&conn->rsc_refcount);
                wd->conn = conn;
                rna_queue_work(mt_workq, &w->work);
            }
        } else if (NULL != conn) {
            rna_printk(KERN_ERR,
                       "Attempt to disconn CS conn ["CONNFMT"] "
                       "["rna_service_id_format"] EP in state [%s]\n",
                       CONNFMTARGS(conn),
                       rna_service_id_get_string(&conn->id),
                       rnablk_conn_state_string(atomic_read(&conn->state)));
        }
    }
}

/*
 * At least for now, for all uses of this routine we want to do a complete
 * disconnect with the cache server -- so do the disconnect on the
 * primary connection...
 */
void
rnablk_queue_ios_timeout_conn_disconnect(struct io_state *ios)
{
    struct com_ep *ep = NULL;
    struct rnablk_server_conn *conn;

    if (!atomic_read(&shutdown)) {
        if (NULL != ios->ep) {
            ep = ios->ep;
        } else if (NULL != ios->blk) {
            ep = ios->blk->ep;
        }
        if (NULL != ep) {
            if (MD_CONN_EP_METAVALUE == ep) {
                rna_printk(KERN_ERR,
                           "ios [%p] tag ["TAGFMT"] can't disconnect MD ep\n",
                           ios,
                           TAGFMTARGS(ios->tag));
            } else {
                conn = ((struct rnablk_server_conn *)
                        com_get_ep_context(ep))->rsc_parent_conn;
                if (unlikely(TRUE == ios_timeout_script_active)) {
                    int ret;
                    ret = rnablk_deferred_process_ios_timeout_helper(ios,
                                                                     conn,
                                                                     FALSE);
                    if (ret == -1) {
                        rnablk_queue_conn_disconnect(conn);
                    }
                } else  {
                    rnablk_queue_conn_disconnect(conn);
                }
            }
        }
    }
}

/* 
 * Return index in if_table that matches the current active_if_info.
 * -1 is returned if a match is not found.
 */
static int
rnablk_active_if_index(struct rna_if_info *active_if_info,
                       struct rna_if_table *if_table)
{
    int i;

    for (i = 0; i < (int)if_table->table_entries; i++) {
        if ((active_if_info->addr == if_table->ifs[i].addr) &&
            (active_if_info->port == if_table->ifs[i].port) &&
            (active_if_info->type == if_table->ifs[i].type)) {
            return i;
        }
    }
    return -1;
}

static void
rnablk_update_conn_iftable(struct rnablk_server_conn *conn,
                           struct rna_if_table *if_table,
                           boolean is_new_conn)
{
    int i;
    int active_if = is_new_conn ? -1 : conn->rsc_active_if;
    int j = 0;
    struct rna_if_info active_info;

    if (-1 != active_if) {
        memcpy(&active_info, &conn->if_table.ifs[active_if], 
               sizeof(active_info));
    } else {
        memset(&active_info, 0, sizeof(active_info));
    }
    if (rnablk_only_use_rdma_for_cs) {
        for (i = 0; i < (int)if_table->table_entries; i++) {
            if (RC == if_table->ifs[i].type) {
                memcpy(&conn->if_table.ifs[j++], &if_table->ifs[i],
                       sizeof(if_table->ifs[0]));
            } else {
                rna_printk(KERN_DEBUG, 
                           "Ignoring interface type [%s] to CS ["NIPQUAD_FMT"]\n",
                           com_get_transport_type_string(if_table->ifs[i].type),
                           NIPQUAD(if_table->ifs[i].addr));
            }
        }
        if (j > 0) {
            /* we found at least one RC entry */
            if ((-1 != active_if) && (RC != active_info.type)) {
                /* don't use non-RC iface! */
                active_if = -1;
            }
            conn->if_table.table_entries = j;
        }
    }
    if (0 == j) {
        /* We didn't find any RC interfaces (or didn't even look). */
        memcpy(&conn->if_table, if_table, sizeof(conn->if_table));
    }
    /* 
     * If there was an active interface, it may have moved in the table,
     * set its index correctly here.
     */
    conn->rsc_active_if = (-1 == active_if) ? -1
                            : rnablk_active_if_index(&active_info, &conn->if_table);
    if (-1 == conn->rsc_active_if) {
        conn->if_attempts = 0; /* reset attempts as well */
    }

}

struct rnablk_server_conn *
rnablk_make_server_conn(struct rna_service_id *service_id,
                        struct rna_if_table *if_table,
                        struct rnablk_server_conn *p_conn,
                        rnablk_cachedev_t *cachedev,
                        int rsc_idx)
{
    struct rnablk_server_conn *conn;
    int i;
    ENTER;
#ifdef WINDOWS_KERNEL
	UNREFERENCED_PARAMETER(i);
	conn = (struct rnablk_server_conn *)ExAllocatePoolWithTag(NonPagedPool, sizeof(struct rnablk_server_conn), 'NOCR');
#else
    conn = kzalloc(sizeof(struct rnablk_server_conn), GFP_NOIO);
#endif /*WINDOWS_KERNEL*/

	if(conn == NULL){
        GOTO( out,-ENOMEM );
    }

#ifdef WINDOWS_KERNEL
	RtlZeroMemory(conn, sizeof(struct rnablk_server_conn));
#endif /*WINDOWS_KERNEL*/
    INIT_LIST_HEAD( &conn->io_queue );
    INIT_LIST_HEAD(&conn->rsc_wlru_list);
    INIT_LIST_HEAD(&conn->rsc_cachedevs);
    atomic_set(&conn->rsc_connected_conns, 0);
    atomic_set(&conn->rsc_refcount, 1);     // create it with a reference
    rna_spin_lock_init( conn->sc_lock );
    rna_block_mutex_init( &conn->block_list_lock );

#ifdef WINDOWS_KERNEL
    if (p_conn) {
        conn->pHBAExt = p_conn->pHBAExt;
    }
#endif /*WINDOWS_KERNEL*/

    atomic_set(&conn->state, RNABLK_CONN_DISCONNECTED);
    conn->rsc_parent_conn = p_conn ? p_conn : conn;
    conn->rsc_idx = rsc_idx;
    conn->rsc_cachedev = cachedev;
    if (if_table) {
        rnablk_update_conn_iftable(conn, if_table, TRUE);
    }
    if (service_id) {
        memcpy(&conn->id, service_id, sizeof(conn->id));
    }
#if defined(RNABLK_VERIFY_CONN_BY_MAGIC)
    conn->front_magic = RNABLK_CONN_FRONT_MAGIC;
    conn->back_magic = RNABLK_CONN_BACK_MAGIC;
#endif

 out:
    EXITPTR(conn);
}

static int
rnablk_get_next_conn(struct rnablk_server_conn *conn,
                     void *opaque_ret_conn)
{
    struct rnablk_server_conn **ret_conn = (struct rnablk_server_conn **)
                                            opaque_ret_conn;

    *ret_conn = conn;
    return 1;
}

void
rnablk_free_server_conns(void)
{
    struct rnablk_server_conn *conn;
    rnablk_cachedev_t *cdp;
    lockstate_t flags;
    struct io_state *ios;
    int found_conn;
    int i;
    unsigned char oldirql = 0;

    rna_down_read(&svr_conn_lock, &oldirql);
    found_conn = rnablk_cache_foreach(&cache_conn_root,
                                      rnablk_get_next_conn, &conn);
    while (found_conn) {
        rnablk_cache_remove(&cache_conn_root, conn);
        rna_spin_in_stack_lock_irqsave(conn->sc_lock, flags);
        while (!list_empty(&conn->io_queue)) {
            ios = list_first_entry(&conn->io_queue, struct io_state, l);
            rnablk_dequeue_conn_io(ios);
            rna_spin_in_stack_unlock_irqrestore(conn->sc_lock, flags);
            rna_printk(KERN_WARNING, "Finishing stranded ios [%p] tag ["TAGFMT
               "] type [%s] refcnt [%d] flags [%#x] %s [%p] block [%llu] "
               "state [%s] ref [%s] refcnt ["BLKCNTFMT"] flags [%#x]\n", ios,
               TAGFMTARGS(ios->tag),
               rnablk_op_type_string(ios->type),
               atomic_read(&ios->ref_count),
               atomic_read(&ios->ios_atomic_flags),
               IOS_HAS_BIO(ios) ? "bio" : IOS_HAS_REQ(ios) ? "req" :
               IOS_HAS_SPC(ios) ? "spc" : "noreq", ios->ios_gen_ioreq,
               ios->blk->block_number,
               rnablk_cache_blk_state_string(ios->blk->state),
               get_lock_type_string(ios->blk->ref_type),
               BLKCNTFMTARGS(ios->blk), ios->blk->cb_identity_flags);
            rnablk_end_request(ios, -EIO);
            rna_spin_in_stack_lock_irqsave(conn->sc_lock, flags);
        }
        while (!list_empty(&conn->rsc_cachedevs)) {
            cdp = list_first_entry(&conn->rsc_cachedevs, rnablk_cachedev_t,
                                   rcd_link);
            list_del_init(&cdp->rcd_link);
            rna_spin_in_stack_unlock_irqrestore(conn->sc_lock, flags);
            for (i = 0; i < RNABLK_MAX_DEV_CONNS; i++) {
                if (NULL != cdp->rcd_conns[i]) {
                    if (atomic_read(&cdp->rcd_conns[i]->rsc_refcount) != 1) {
                        rna_printk(KERN_WARNING, "Freeing conn ["CONNFMT"] "
                               "with refcnt=%d\n",
                               CONNFMTARGS(cdp->rcd_conns[i]),
                               atomic_read(&cdp->rcd_conns[i]->rsc_refcount));
                    }
                    rnablk_free_server_conn_struct(cdp->rcd_conns[i]);
                }
            }
            kfree(cdp);
            rna_spin_in_stack_lock_irqsave(conn->sc_lock, flags);
        }
        rna_spin_in_stack_unlock_irqrestore(conn->sc_lock, flags);
        if (atomic_read(&conn->rsc_refcount) != 1) {
            rna_printk(KERN_WARNING, "Freeing conn ["CONNFMT"] with "
                       "refcnt=%d\n", CONNFMTARGS(conn),
                       atomic_read(&conn->rsc_refcount));
        }
        rnablk_free_server_conn_struct(conn);
        found_conn = rnablk_cache_foreach(&cache_conn_root,
                                          rnablk_get_next_conn, &conn);
    }
    rna_up_read(&svr_conn_lock, oldirql);
}

INLINE void rnablk_ios_set_cache_id(struct io_state       *ios,
                                           struct rna_service_id *service_id)
{
    BUG_ON(NULL == ios);
    BUG_ON(NULL == service_id);

    ios->cs_ep_key = service_id->u.hash;
}

static void
rnablk_queue_retry_connect(struct rnablk_server_conn *conn)
{
    struct rnablk_work                  *w = NULL;
    struct rnablk_retry_connection_data *wd = NULL;
    int state;

    BUG_ON(NULL == conn);

    if (!atomic_read(&shutdown) &&
        !atomic_read(&rna_service_detached)) {

        state = atomic_cmpxchg(&conn->state,
                                RNABLK_CONN_DISCONNECTED,
                                RNABLK_CONN_CONNECT_PENDING);

        if (RNABLK_CONN_DISCONNECTED == state
            || ((RNABLK_CONN_CONNECT_PENDING == state) &&
                ((get_jiffies() - conn->rsc_last_queued_conn_ts) >
               msecs_to_jiffies(RNABLK_IOS_CONN_CHECK_MS)))) {

            if (atomic_bit_test_and_set(&conn->rsc_flags,
                                        RSC_F_QUEUING_CONN_RETRY)) {
                conn->rsc_last_queued_conn_ts = get_jiffies();
                if (RNABLK_CONN_DISCONNECTED == state) {
                    rna_printk(KERN_INFO,
                           "conn [%p] CS ["rna_service_id_format"] EP [%p] "
                           "state [%s]-> [%s]\n",
                           conn, rna_service_id_get_string(&conn->id),
                           conn->ep,
                           rnablk_conn_state_string(RNABLK_CONN_DISCONNECTED),
                           rnablk_conn_state_string(
                           RNABLK_CONN_CONNECT_PENDING));
                } else {
                    rna_printk(KERN_INFO,
                           "conn [%p] CS ["rna_service_id_format"] EP [%p] "
                           "state already [%s]. Trying again [%d] ms after "
                           "previous try.\n",
                           conn,
                           rna_service_id_get_string(&conn->id),
                           conn->ep,
                           rnablk_conn_state_string(
                           RNABLK_CONN_CONNECT_PENDING),
                           jiffies_to_msecs(get_jiffies()
                           - conn->rsc_last_queued_conn_ts));
                }
                    
                if( (w = rnablk_mempool_alloc( work_cache_info )) == NULL ) {
                    rna_printk(KERN_WARNING, "mempool_alloc failed\n");
                    atomic_bit_test_and_clear(&conn->rsc_flags,
                                              RSC_F_QUEUING_CONN_RETRY);
                } else {
                    /* Queue connection work to the referenced cache sever */
                    RNABLK_INIT_RNABLK_WORK(w, wd, rnablk_retry_connection);
                    wd->conn = conn;
                    if (!is_parent_conn(conn)) {
                        atomic_inc(&conn->rsc_cachedev->rcd_refcount);
                    }
                    rna_queue_work( mt_workq,&w->work );
                }
            }
        } else {
            rna_printk(KERN_DEBUG,
                       "conn [%p] CS ["rna_service_id_format"] in unexpected "
                       "state [%s] ep [%p]\n",
                       conn,
                       rna_service_id_get_string(&conn->id),
                       rnablk_conn_state_string(atomic_read(&conn->state)),
                       conn->ep);
        }
    }
}

static void
rnablk_queued_ios_conn_check(rnablk_workq_cb_arg_t arg)
{
    rnablk_dwork_t w = RNABLK_ARG_DWORK(arg);
    struct io_state *ios = w->data.rwd_rnablk_ios_requeue_wf_data.ios;
    boolean redo = FALSE;

    if (likely(!atomic_read(&shutdown))) {
        if (rnablk_svcctl_is_frozen() && !IS_MASTER_BLK(ios->blk)) {
            /*
             * Don't restart the I/O if we're in a frozen state.
             * Instead, set up to retry again later.
             */
            rna_queue_delayed_work(mt_workq, RNABLK_DWORK_OBJECT(w),
                                   msecs_to_jiffies(RNABLK_FREEZE_DELAY_MS));
            return;
        }

        redo = rnablk_remove_ios_from_wfc(ios);

        if (redo) {
            /*
             * This ios has waited long enough for the cache server to connect!
             * Maybe that cache server has died, in which case we want to
             * restart this ios from scratch, in hopes the MD has reassigned
             * the blk to a different CS.
             */
            if (IS_MASTER_BLK(ios->blk)) {
                /*
                 * This was a lock_master_blk request.
                 * Be sure to 'finish' this ios before we try to issue
                 * the next one, as the finish will clear the serialization
                 * that will allow a new MASTER_BLK_LOCK to be issued.
                 */
                RNABLK_BUG_ON(!atomic_bit_is_set(&ios->ios_atomic_flags,
                                                 IOS_AF_MASTER_LOCK),
                              "Not a MASTER_BLK_LOCK?  dev [%s] ios [%p] "
                              "type [%s]\n", ios->dev->name, ios,
                              rnablk_op_type_string(ios->type));
                rnablk_ios_ref(ios);   // ref ios til we're done with it...
                rnablk_ios_finish(ios);
                rnablk_lock_master_blk(ios->dev);
                rnablk_ios_release(ios);
            } else {
                rnablk_queue_blk_io(ios->blk, ios, QUEUE_TAIL);
                rnablk_cache_blk_drain(ios->blk);
            }
        }
    }

    /* release ref taken in rnablk_queue_ios_conn_check */
    rnablk_ios_release(ios);
    if (w->delayed) {
        atomic_dec(&delayed_work);
    }
    RNABLK_FREE_DWORK(w);
}

static void
rnablk_queue_ios_conn_check(struct io_state *ios)
{
    rnablk_dwork_t w;

    if (likely(!atomic_read(&shutdown))) {
        w = RNABLK_ALLOC_DWORK();
        if (NULL == w) {
            rna_printk(KERN_ERR, "Failed to allocate workq item for ios [%p] "
                       "tag ["TAGFMT"] block [%llu]\n", ios,
                       TAGFMTARGS(ios->tag), ios->blk->block_number);
        } else {
            /* released in rnablk_queued_ios_conn_check */
            rnablk_ios_ref(ios);
            RNABLK_INIT_DWORK(w, rnablk_queued_ios_conn_check);
            w->data.rwd_rnablk_ios_requeue_wf_data.ios = ios;
            rna_queue_delayed_work(mt_workq, RNABLK_DWORK_OBJECT(w),
                                   msecs_to_jiffies(RNABLK_IOS_CONN_CHECK_MS));

        }
    }
}

struct rnablk_server_conn *
rnablk_next_cachedev_conn(rnablk_cachedev_t *cachedev)
{
    struct rnablk_server_conn *p_conn = cachedev->rcd_server_conn;
    struct rnablk_server_conn *conn = NULL;
    int start, index;

    if (&null_cachedev == cachedev
        || !atomic_bit_is_set(&cachedev->rcd_state, RCD_STATE_ONLINE)) {
        return NULL;
    } 

    if (rnablk_per_device_connections) {
        start = index = atomic_inc_return(&cachedev->rcd_next_conn)
                                          % rnablk_per_device_connections;
        do {
            conn = cachedev->rcd_conns[index];
            if (likely(rnablk_conn_connected(conn))) {
                break;
            } else if (NULL == conn) {
                /*
                 * This connection never got set up -- maybe because
                 * 'rnablk_per_device_connections' got modified at run time.
                 * In that case, go ahead and try to establish it now for
                 * future use.
                 */
                conn = cachedev->rcd_conns[index] =
                                rnablk_make_server_conn(&p_conn->id,
                                                        &p_conn->if_table,
                                                        p_conn, cachedev,
                                                        index + 1);
                rnablk_trc_discon(1, "post-create of rcd_conns[%d]=%p for "
                                  "cachedev=%"PRIx64"\n", index,
                                  cachedev->rcd_conns[index],
                                  cachedev->rcd_id);
            } else {
                rnablk_update_conn_iftable(conn, &p_conn->if_table, FALSE);
            }

            /*
             * In case there's some kind of problem with connecting,
             * prevent too tight of a retry loop by injecting a time lapse
             * between re-attempts.
             */
            if (NULL != conn
                && ((get_jiffies() - conn->rsc_last_queued_conn_ts)
                     > msecs_to_jiffies(RNABLK_CACHEDEV_CONN_CHECK_MS))) {
                rnablk_queue_retry_connect(conn);
            }
        } while ((index = atomic_inc_return(&cachedev->rcd_next_conn) %
                 rnablk_per_device_connections) != start);
    }
    return conn;
}

// Caller may hold svr_conn_lock
int
rnablk_server_conn_debug_dump(struct rnablk_server_conn *conn)
{
    rna_printk(KERN_ERR, 
               "conn ["CONNFMT"] server ["rna_service_id_format"]%s dev "
               "[%"PRIx64"] state [%s]\n"
               "\tio_queue_len [%d] next_request_scheduled [%d] "
               "next_request_needed [%d] dispatching [%d]\n",
               CONNFMTARGS(conn),
               rna_service_id_get_string(&conn->id),
               (conn==g_md_conn)?" (MD pseudo-conn)":"",
               is_parent_conn(conn) ? 0 : conn->rsc_cachedev->rcd_id,
               rnablk_conn_state_string(atomic_read(&conn->state)),
               atomic_read(&conn->io_queue_length),
               atomic_bit_is_set(&conn->rsc_flags, RSC_F_DISPATCH_SCHEDULED),
               atomic_read(&conn->dispatch_needed),
               atomic_bit_is_set(&conn->rsc_flags, RSC_F_DISPATCHING));
    return 0;
}

// Do something (that doesn't change the conn tree) with each connection
int rnablk_cache_conn_foreach(RNABLK_CACHE_FOREACH_CB cb,
                              void                   *ctx)
{
    int ret = 0;
    unsigned char oldirql = 0;

    rna_down_read(&svr_conn_lock, &oldirql);
    ret = rnablk_cache_foreach(&cache_conn_root, cb, ctx);
    rna_up_read(&svr_conn_lock, oldirql);
    return ret;
}

/* needed to track total length printed for CFS */
typedef struct {
    char * buf;
    int    written;
    int    remaining;
} rnablk_print_conn_stats;


static int
rnablk_print_conn_cb(struct rnablk_server_conn *conn,
                     void                      *context)
{
    rnablk_print_conn_stats *cb_stats = context;
    int len = 0;
    mutexstate_t mutex_lock_handle;

    BUG_ON(NULL == conn);
    BUG_ON(NULL == cb_stats);
    BUG_ON(NULL == cb_stats->buf);

    if (g_md_conn == conn) {
        return 0;  /* MD conn uninteresting */
    }

    rna_block_mutex_lock(&conn->block_list_lock, &mutex_lock_handle);

    if (is_parent_conn(conn)) {
        len = snprintf(cb_stats->buf, cb_stats->remaining,
                       "CS %s["NIPQUAD_FMT":%d] PRIMARY : ",
                       conn->local ? "local " : "",
                       NIPQUAD(conn->id.u.data.address),
                       conn->id.u.data.number);
    } else {
        len = snprintf(cb_stats->buf, cb_stats->remaining,
                       "   CS CACHEDEV %s[%#"PRIx64":%d] : ",
                       conn->local ? "local " : "",
                       conn->rsc_cachedev->rcd_id,
                       conn->rsc_idx);
    }

    if (len > cb_stats->remaining) {
        len = cb_stats->remaining;
    }
    cb_stats->written += len;
    cb_stats->remaining -= len;
    cb_stats->buf += len;

    len = snprintf(cb_stats->buf, cb_stats->remaining,
                  "state [%s] "
                  "IOQ len [%3d] "
                  "blk_list_len [%d] "
                  "\n\t"
                  "dispatching [%d] "
                  "resched [%4d] "
                  "(to compl [%d]) "
                  "EAGAINs [%d] "
                  "\n\t"
                  "rdma_buf alloc [%7d] fails [%4d] in use [%3d/%d] "
                  "send_buf alloc [%7d] fails [%4d] in use [%3d/%d]\n",
                  rnablk_conn_state_string(atomic_read(&conn->state)),
                  atomic_read(&conn->io_queue_length),
                  conn->block_list_length,
                  atomic_bit_is_set(&conn->rsc_flags, RSC_F_DISPATCHING),
                  atomic_read(&conn->dispatching_rescheduled),
                  atomic_bit_is_set(&conn->rsc_flags,
                                    RSC_F_DISPATCH_ON_COMPLETION),
                  atomic_read(&conn->eagains),
                  atomic_read(&conn->rdma_bufs_allocated),
                  atomic_read(&conn->rdma_buf_alloc_failures),
                  atomic_read(&conn->rdma_bufs_in_use),
                  conn->rdma_bufs,
                  atomic_read(&conn->send_bufs_allocated),
                  atomic_read(&conn->send_buf_alloc_failures),
                  atomic_read(&conn->send_bufs_in_use),
                  conn->send_bufs
                  );

    rna_block_mutex_unlock(&conn->block_list_lock, &mutex_lock_handle);

    /*
     * snprintf returns the number of bytes that would have been written
     * if not truncated, rather than what we really want, which is the 
     * number of bytes actually written.
     */
    if (len > cb_stats->remaining) {
        len = cb_stats->remaining;
    }

    cb_stats->written += len;
    cb_stats->remaining -= len;
    cb_stats->buf += len;

    if (is_parent_conn(conn)) {
#define MAX_CACHEDEVS_PER_CONN   16
        rnablk_cachedev_t *cdp_array[MAX_CACHEDEVS_PER_CONN];
        rnablk_cachedev_t *cdp;
        struct list_head *ent;
        lockstate_t irq_flags;
        int n_cds = 0;
        int i, j;

        rna_spin_in_stack_lock_irqsave(conn->sc_lock, irq_flags);
        list_for_each(ent, &conn->rsc_cachedevs) {
            if (n_cds >= MAX_CACHEDEVS_PER_CONN) {
                rna_printk(KERN_WARNING, "Not displaying connections for one "
                           "or more cache devices\n");
                break;
            }
            cdp = list_entry(ent, rnablk_cachedev_t, rcd_link);
            atomic_inc(&cdp->rcd_refcount);
            cdp_array[n_cds++] = cdp;
        }
        rna_spin_in_stack_unlock_irqrestore(conn->sc_lock, irq_flags);

        for (i = 0; i < n_cds; i++) {
            for (j = 0; j < RNABLK_MAX_DEV_CONNS; j++) {
                if (NULL != cdp_array[i]->rcd_conns[j]) {
                    (void)rnablk_print_conn_cb(cdp_array[i]->rcd_conns[j],
                                               context);
                }
            }
            rnablk_put_cachedev(cdp_array[i]);
        }
    }

    return 0;
}

int rnablk_print_conns(char *buf, int buflen)
{
    rnablk_print_conn_stats cb_stats;
    unsigned char oldirql = 0;

	cb_stats.buf = buf;
	cb_stats.written = 0;
	cb_stats.remaining = buflen;

    rna_down_read(&svr_conn_lock, &oldirql);
    rnablk_cache_foreach(&cache_conn_root,
                          rnablk_print_conn_cb,
                          &cb_stats);
    rna_up_read(&svr_conn_lock, oldirql);
    buf[buflen - 1] = '\0';

    return cb_stats.written;
}

/*
 * rnablk_cleanup_conn_ioq()
 *
 * Notes:
 *  1) Note that rnablk_process_dev_conn_disconnect() duplicates some
 *     of the logic done here.  If this routine changes, check whether changes
 *     are needed there as well.
 *
 * caller must hold conn->block_list_lock
 */ 
static void
rnablk_cleanup_conn_ioq(struct rnablk_server_conn *conn,
                        rnablk_cachedev_t *cachedev)
{
    struct list_head *ent;
    struct io_state *ios;
    lockstate_t flags;
    boolean dropped_lock;

    ENTERV;

    // end all queued io requests (or all for this cache-device)
    do {
        dropped_lock = FALSE;
        rna_spin_in_stack_lock_irqsave(conn->sc_lock, flags);
        list_for_each(ent, &conn->io_queue) {
            ios = list_entry(ent, struct io_state, l);

            if (cachedev && (ios->blk->blk_cachedev != cachedev)) {
                /* this ios is not for the cachedev we care about */
                rnablk_trc_discon(0, "ios=%p skip: wrong cachedev exp=%"PRIx64
                                  " act=%"PRIx64"\n", ios, cachedev->rcd_id,
                                  ios->blk->blk_cachedev->rcd_id);
                continue;
            }

            rnablk_trace_ios(ios);
            rnablk_unset_ios_ep(ios);
            rnablk_dequeue_conn_io(ios);
            rna_spin_in_stack_unlock_irqrestore(conn->sc_lock, flags);
            dropped_lock = TRUE;
            if (unlikely(!IOS_HAS_IOREQ(ios))) {
                /*
                 * this IOS in not associated with any incoming I/O,
                 * we can drop it
                 */
                rna_printk(KERN_NOTICE, "dropping ios [%p] tag ["TAGFMT"] "
                           "type [%s] device [%s] block [%llu] state [%s]\n",
                           ios, TAGFMTARGS(ios->tag),
                           rnablk_op_type_string(ios->type),
                           ios->blk->dev->name, ios->blk->block_number,
                           rnablk_cache_blk_state_string(ios->blk->state));
                rnablk_ios_finish(ios);
            } else if (cachedev || rnablk_blk_recoverable(ios->blk)) {
                rna_printk(KERN_NOTICE, "redispatching ios [%p] tag ["TAGFMT"] "
                           "type [%s] device [%s] block [%llu] state [%s]\n",
                           ios, TAGFMTARGS(ios->tag),
                           rnablk_op_type_string(ios->type),
                           ios->blk->dev->name, ios->blk->block_number,
                           rnablk_cache_blk_state_string(ios->blk->state));
                /*
                 * This does not actually dispatch the ios.  The
                 * dispatch list is used here to track all the ios's
                 * that will be re-dispatched if/when this connection
                 * is re-established
                 */
                rnablk_lock_blk_irqsave(ios->blk, flags);
                rnablk_undo_conn_io(ios, TRUE);
                rnablk_queue_blk_io_nolock(ios->blk, ios, QUEUE_HEAD);
                rnablk_unlock_blk_irqrestore(ios->blk, flags);
            } else {
                if (unlikely(rnablk_command_is_ordered(ios))) {
                    /* We don't need to block things behind this anymore. */
                    rnablk_dequeue_ordered_command(ios);
                }
                rna_printk(KERN_ERR, "failing ios [%p] tag ["TAGFMT"] "
                           "type [%s] device [%s] block [%llu] state [%s]\n",
                           ios, TAGFMTARGS(ios->tag),
                           rnablk_op_type_string(ios->type),
                           ios->blk->dev->name, ios->blk->block_number,
                           rnablk_cache_blk_state_string(ios->blk->state));
                rnablk_undo_conn_io(ios, FALSE);
                rnablk_end_request(ios, -EIO);
            }
            break;
        }
    } while (dropped_lock);

    rna_spin_in_stack_unlock_irqrestore(conn->sc_lock, flags);

    EXITV;
}

/*
 * rnablk_cleanup_blk
 *  Do 'cleanup' of the specified block due to either a CS disconnect
 *  or to a cache-device going offline.
 *
 * Notes:
 *  1) Caller must hold blk->bl_lock & the blk's conn->block_list_lock
 */
void
rnablk_cleanup_blk(struct cache_blk *blk)
{
    struct list_head *ent, *n_ent;
    struct io_state *ios;
    int qstate;

#ifndef WINDOWS_KERNEL
    RNABLK_BUG_ON_BLK(!spin_is_locked(&blk->bl_lock.lock), blk);
#endif /*WINDOWS_KERNEL*/
    rnablk_mark_cache_blk_bad_nolock(blk, TRUE);
    while (!list_empty(&blk->bl)) {
        ios = list_first_entry(&blk->bl, struct io_state, l);
        rnablk_trace_ios(ios);
        rnablk_unset_ios_ep(ios);
        rnablk_dequeue_blk_io_nolock(blk, ios);
        rna_printk(KERN_NOTICE, "ending ios [%p] tag ["TAGFMT"] type [%s] for "
                   "device [%s] block [%"PRIu64"] on bl queue\n",
                   ios,
                   TAGFMTARGS(ios->tag),
                   rnablk_op_type_string(ios->type),
                   blk->dev->name,
                   blk->block_number);
        rnablk_end_request(ios, -EIO);
    }
    list_for_each_safe(ent, n_ent, &blk->dispatch_queue) {
        ios = list_entry(ent, struct io_state, l);
        qstate = ios_queuestate_get(ios);

        switch (qstate) {
        case IOS_QS_DISPATCH:
            rnablk_undo_conn_io(ios, TRUE);
            // fallthru

        case IOS_QS_DISPATCH_FAILED_REDO:
        case IOS_QS_DISPATCH_QUIESCED:
            rnablk_unset_ios_ep(ios);
            dec_in_flight(ios->dev, ios);
            rnablk_io_completed_nolock(ios, blk);
            if (unlikely(rnablk_command_is_ordered(ios))) {
                rnablk_dequeue_ordered_command(ios);
            }
            rna_printk(KERN_NOTICE, "ending ios [%p] tag ["TAGFMT"] type [%s] "
                       "for device [%s] block [%"PRIu64"] qstate [%s]\n",
                       ios,
                       TAGFMTARGS(ios->tag),
                       rnablk_op_type_string(ios->type),
                       blk->dev->name,
                       blk->block_number,
                       rnablk_ios_q_string(qstate));
            rnablk_end_request(ios, -EIO);
            break;

        case IOS_QS_DISPATCH_COMPLETING:
            rna_printk(KERN_NOTICE, "ignoring ios [%p] tag ["TAGFMT"] "
                       "type [%s] device [%s] block [%"PRIu64"] in COMPLETING "
                       "state\n",
                       ios,
                       TAGFMTARGS(ios->tag),
                       rnablk_op_type_string(ios->type),
                       blk->dev->name,
                       blk->block_number);
            break;

        default:
            RNABLK_BUG_ON(TRUE, "ios [%p] type [%s] device [%s] block [%llu] "
                          "unexpected qstate [%d]\n",
                          ios, rnablk_op_type_string(ios->type),
                          blk->dev->name, blk->block_number, qstate);
            break;
        }
    }
}

/* Caller must hold conn->block_list_lock */
static void
rnablk_cleanup_conn_waiters(struct rnablk_server_conn * conn)
{
    struct io_state *ios;
    struct list_head *pos,*tmp;
    struct cache_blk *blk;
    lockstate_t flags;
    unsigned char oldirql = 0;

    ENTER;

	UNREFERENCED_PARAMETER(ret);

    BUG_ON(IS_ERR(conn));
    // Fail all requests waiting for this connection
    rna_down_write( &wfc_queue_lock, &oldirql );
    list_for_each_safe( pos,tmp,&wfc_queue ) {
        ios = list_entry(pos, struct io_state, l);
        rna_printk(KERN_NOTICE, "ios [%p] tag ["TAGFMT"] type [%s] "
                   "device [%s] block [%llu] state [%s] - %s waiting for "
                   "conn ["CONNFMT"]\n",
                   ios, TAGFMTARGS(ios->tag), rnablk_op_type_string(ios->type),
                   ios->blk->dev->name, ios->blk->block_number,
                   rnablk_cache_blk_state_string(ios->blk->state),
                   rnablk_ios_waiting_conn(ios, conn) ? "is" : "isn't",
                   CONNFMTARGS(conn));
        if(rnablk_ios_waiting_conn(ios, conn)) {
            rnablk_unset_ios_ep(ios);
            list_del_init(&ios->l);
            RNABLK_BUG_ON(!ios_queuestate_test_and_set(ios,
                                                       IOS_QS_WFC, IOS_QS_NONE),
                          "ios [%p] tag ["TAGFMT"] qstate [%d] inconsistent\n",
                          ios, TAGFMTARGS(ios->tag), ios_queuestate_get(ios));
            blk = ios->blk;
            rnablk_cache_blk_ref(blk);
            rnablk_lock_blk_irqsave(blk, flags);
            if (rnablk_blk_recoverable(blk)) {
                rnablk_trc_discon(1, "ios=%p put on blk=%p [%"PRIu64"] "
                                  "dispatch\n", ios, blk,
                                  blk->block_number);
                rnablk_queue_blk_io_nolock(blk, ios, QUEUE_HEAD);
            } else {
                rnablk_trc_discon(1, "ios=%p blk=%p [%"PRIu64"] mark block "
                                  "bad\n", ios, blk,
                                  blk->block_number);
                if (RNABLK_CACHE_BLK_INVALID != blk->state) {
                    rnablk_cleanup_blk(blk);
                }
                if (unlikely(rnablk_command_is_ordered(ios))) {
                    rnablk_dequeue_ordered_command(ios);
                }
                rnablk_blk_put_cachedev(blk, conn);
                rnablk_end_request(ios, -EIO);
            }
            rnablk_unlock_blk_irqrestore(blk, flags);
            rnablk_cache_blk_release(blk);
        }
    }
    rna_up_write( &wfc_queue_lock, oldirql );

    EXITV;
}

void
rnablk_operate_on_conn_cachedevs(struct rnablk_server_conn *conn,
                                 rnablk_cachedev_t *cachedev,
                                 void *func_arg,
                                 void  per_cachedev_func(
                                       struct rnablk_server_conn *,
                                       rnablk_cachedev_t *,
                                       void *))
{
    rnablk_cachedev_t *cachedev_array[MAX_CACHEDEVS_PER_CONN];
    struct rnablk_server_conn *p_conn = conn->rsc_parent_conn;
    lockstate_t irqflags;
    struct list_head *ent;
    int n_cds = 0;
    int i;

    if (NULL != cachedev) {
        per_cachedev_func(conn, cachedev, func_arg);
        return;
    }

    /* Need to do operation on all cachedevs associated with conn */
    rna_spin_in_stack_lock_irqsave(p_conn->sc_lock, irqflags);
    list_for_each(ent, &p_conn->rsc_cachedevs) {
        RNABLK_BUG_ON(n_cds >= MAX_CACHEDEVS_PER_CONN,
                      "Ack, too many cachedevs per conn ["CONNFMT"]\n",
                      CONNFMTARGS(conn));
        cachedev = list_entry(ent, rnablk_cachedev_t, rcd_link);
        atomic_inc(&cachedev->rcd_refcount);
        cachedev_array[n_cds++] = cachedev;
    }

    rna_spin_in_stack_unlock_irqrestore(p_conn->sc_lock, irqflags);

    for (i = 0; i < n_cds; i++) {
        cachedev = cachedev_array[i]; 
        per_cachedev_func(conn, cachedev, func_arg);
        rnablk_put_cachedev(cachedev);
    }
}

/* Caller holds conn->block_list_lock */
static void
rnablk_cleanup_conn_blks_cachedev(struct rnablk_server_conn *conn,
                                  rnablk_cachedev_t *cachedev,
                                  void *opaque_cleanup_all)
{
    uint32_t cleanup_all = (uint32_t)((uintptr_t)opaque_cleanup_all);
    struct blk_lru_list *pos, *npos;
    struct cache_blk *blk;
    lockstate_t     irqflags;
    int is_wref;

    ENTER;

	UNREFERENCED_PARAMETER(ret);

    RNABLK_DBG_BUG_ON(NULL == cachedev, "conn ["CONNFMT"] -- null cachedev!\n",
                      CONNFMTARGS(conn));
    RNABLK_DBG_BUG_ON(!rna_service_mutex_is_locked(
                      &conn->rsc_parent_conn->block_list_lock),
                      "conn ["CONNFMT"] cachedev=%p - mutex not locked\n",
                      CONNFMTARGS(conn), cachedev);
 restart_loop:
    blk_lru_list_for_each_safe(pos, npos, &cachedev->rcd_block_list) {
        blk = blk_lru_entry(pos, &is_wref);

        if (unlikely(IS_MARKER_BLK(blk))) {
            continue;       // skip marker blocks
        }

        if (is_wref) {
            continue;   // only need to process each blk once, so skip wref
        }

        /*
         * In case we end up removing blk from the block_list below (for
         * instance, in rnablk_cleanup_blk()), need to double-check that
         * 'npos' isn't also pointing to blk, and if so, fix up 'npos'.
         * (This is due to the unusual characteristic of the blru list,
         * that the blk may be in the list twice).
         */
        if (blk_lru_entry(npos, &is_wref) == blk) {
            npos = _LRU_GET_ENT_PTR(npos->blru_next);
        }

        rnablk_cache_blk_ref(blk);
        rnablk_lock_blk_irqsave(blk, irqflags);

        rna_printk(KERN_INFO,
                   "dev [%s] block [%"PRIu64"] state [%s] block IO list empty "
                   "[%s] dispatch list empty [%s] cachedev [%#"PRIx64"]\n",
                   blk->dev->name,
                   blk->block_number,
                   rnablk_cache_blk_state_string(blk->state),
                   list_empty(&blk->bl) ? "TRUE" : "FALSE",
                   list_empty(&blk->dispatch_queue) ? "TRUE" : "FALSE",
                   cachedev->rcd_id);

        BUG_ON(NULL == blk->dev);

        if (RNABLK_CACHE_BLK_INVALID == blk->state) {
            ;               /* ignore bad blocks at this point.... */
        } else if (atomic_read(&blk->dev->failed)) {
            rna_printk(KERN_INFO,
                       "dev [%s] block [%"PRIu64"] cleanup due to failed dev\n",
                       blk->dev->name,
                       blk->block_number);
            rnablk_cleanup_blk(blk);
        } else if (!cleanup_all || rnablk_blk_recoverable(blk)) {
            if (0 == atomic_read(&blk->inflight_ios)) {
                rnablk_cache_blk_state_set(blk, RNABLK_CACHE_BLK_DISCONNECTED);
            } else {
                rnablk_cache_blk_state_set(blk, RNABLK_CACHE_BLK_DISCONN_PENDING);
            }
            atomic_bit_set(&blk->cb_flags, BLK_F_DISCONN_FROZEN);
            if (IS_MASTER_BLK(blk)) {
                rna_printk(KERN_NOTICE, "disabling block queue for device [%s] "
                           "until masterblock lock reacquired\n",
                           blk->dev->name);
                atomic_bit_clear(&blk->dev->rbd_io_allowed,
                                 RBD_FIO_MASTER_LOCKED);
            }
            rna_printk(KERN_INFO,
                       "dev [%s] block [%"PRIu64"] set to state [%s]\n",
                       blk->dev->name,
                       blk->block_number,
                       rnablk_cache_blk_state_string(blk->state));
            /*
             * leave on the block list so we can find it in
             * rnablk_restart_conn_blks()
             */
        } else {
            /*
             * Found a non-recoverable blk, which means we have to
             * fail the device itself (and then go back through
             * and reprocess all the blocks in the list, now that
             * none of them will be recoverable anymore).
             */
            (void)rnablk_device_fail(blk->dev);
            rnablk_unlock_blk_irqrestore(blk, irqflags);
            rnablk_cache_blk_release(blk);
            rna_printk(KERN_ERR, "dev [%s] block [%"PRIu64"] state [%s] ios "
                       "count [%d] triggers device failure\n",
                       blk->dev->name,
                       blk->block_number,
                       rnablk_cache_blk_state_string(blk->state),
                       atomic_read(&ios_count));
            goto restart_loop;
        }

        rnablk_unlock_blk_irqrestore(blk, irqflags);
        rnablk_cache_blk_release(blk);
    }

    EXITV;
}

/* Caller holds conn->block_list_lock */
static void
rnablk_cleanup_conn_blks(struct rnablk_server_conn *conn,
                         rnablk_cachedev_t *cachedev)
{
    rnablk_operate_on_conn_cachedevs(conn, cachedev,
                                     NULL == cachedev ? (void *)1 : (void *)0,
                                     rnablk_cleanup_conn_blks_cachedev);
}                                     

struct quiesce_dispatch_args {
    int     n_quiesces;
    boolean quiesced;
};

/*
 * rnablk_quiesce_dispatch_queue_cachedev()
 *  Quiesce outstanding I/O for the specified 'conn' and 'cachedev'.
 *
 *  Notes:
 *      The input argument 'struct quiesce_dispatch_args' fields are used
 *      as follows:
 *          'n_quiesces':       - input value, indicating how many times
 *                                this routine has already been called for
 *                                this conn/cachedev pair.  The value is
 *                                used here to determine when it's time to
 *                                give up, i.e. we've waited long enough.
 *          'quiesced':         - this is an output value.  If this routine
 *                                is unable to quiesce all the I/O, then
 *                                it sets this value to FALSE.  Note,
 *                                however, that this routine should not
 *                                modify it otherwise, since it is initialized
 *                                to TRUE by rnablk_quiesce_dispatch_queue()
 *                                and may contain cumulative results for the
 *                                case where we cycle through multiple
 *                                cachedevs.
 *
 * caller must hold conn->block_list_lock
 */
static void
rnablk_quiesce_dispatch_queue_cachedev(struct rnablk_server_conn *conn,
                                       rnablk_cachedev_t *cachedev,
                                       void *void_args)
{
    struct quiesce_dispatch_args *p_args = (struct quiesce_dispatch_args *)
                                            void_args;
    struct blk_lru_list *bpos;
    struct list_head *ios_ent;
    struct io_state  *ios;
    struct cache_blk *blk;
    lockstate_t       irq_flags;
    boolean           has_outstanding_ios;
    boolean           need_to_wait;
    boolean           is_dma;
    int               qstate;
    int               n_quiesces = p_args->n_quiesces;
    boolean           be_verbose = FALSE;
    int is_wref;

    ENTERV;

    RNABLK_DBG_BUG_ON(NULL == cachedev, "conn ["CONNFMT"] -- null cachedev!\n",
                      CONNFMTARGS(conn));
    RNABLK_DBG_BUG_ON(!rna_service_mutex_is_locked(
                      &conn->rsc_parent_conn->block_list_lock),
                      "conn ["CONNFMT"] cachedev=%p - mutex not locked\n",
                      CONNFMTARGS(conn), cachedev);
    rnablk_trc_discon(1, "conn ["CONNFMT"] cachedev [%#"PRIx64"]\n",
                       CONNFMTARGS(conn), cachedev->rcd_id);

    RNABLK_BUG_ON(be_verbose, "Waited too long for quiesce!  conn "
                  "["CONNFMT"] cachedev=%p [0x%"PRIx64"]\n",
                  CONNFMTARGS(conn), cachedev, cachedev->rcd_id);

    if (n_quiesces > RNABLK_CACHE_DEV_MAX_QUIESCE_ATTEMPTS) {
        rna_printk(KERN_ERR, "quiesce appears stalled, do last (verbose) "
                   "pass, conn ["CONNFMT"] cachedev [%#"PRIx64"]\n",
                   CONNFMTARGS(conn), cachedev ? cachedev->rcd_id : 0);
        be_verbose = TRUE;
    }

    need_to_wait = FALSE;
    blk_lru_list_for_each(bpos, &cachedev->rcd_block_list) {
        blk = blk_lru_entry(bpos, &is_wref);

        if (unlikely(IS_MARKER_BLK(blk))) {
            continue;       // skip marker blocks
        }

        RNABLK_DBG_BUG_ON(blk->blk_cachedev != cachedev,
                          "blk [%p] block [%llu] expected cachedev %p "
                          "got cachedev %p\n", blk, blk->block_number,
                          cachedev, blk->blk_cachedev);

        if (is_wref) {
            continue;
        }

        if (conn != blk->cb_dev_conn && !is_parent_conn(conn)) {
            rnablk_trc_discon(0, "skipping blk=%p [%"PRIu64"] conn "
                              "["CONNFMT"]\n", blk, blk->block_number,
                              CONNFMTARGS(blk->cb_dev_conn));
            continue;
        }

        rna_printk(KERN_DEBUG,
                   "device [%s] block [%"PRIu64"] state [%s]\n",
                   blk->dev->name,
                   blk->block_number,
                   rnablk_cache_blk_state_string(blk->state));

        has_outstanding_ios = FALSE;

        rnablk_cache_blk_ref(blk);
        rnablk_lock_blk_irqsave(blk, irq_flags);

        if (!is_blk_quiesce_complete(blk)) {
            list_for_each(ios_ent, &blk->dispatch_queue) {
                ios = list_entry(ios_ent, struct io_state, l);
                /*
                 * DMA requests, whether local or remote, are
                 * guaranteed to "complete" (one way or another, i.e.
                 * rna service library may forcibly complete them).
                 * So we wait for those.  Others we forcibly "quiesce".
                 */
                is_dma = (ios->type == RNABLK_RDMA_READ
                          || ios->type == RNABLK_RDMA_WRITE);

                qstate = ios_queuestate_get(ios);

                if (rnablk_get_ep_conn(ios->ep) != conn) {
                    /*
                     * Ignore i/o that wasn't issued on the conn we're
                     * currently processing.
                     */
                    if (be_verbose) {
                        rna_printk(KERN_NOTICE,
                           "ios [%p] tag ["TAGFMT"] block [%"PRIu64"] "
                           "state [%s] type [%s] "
                           "rcnt=%d io_conn=%p ep=%p conn ["CONNFMT"] "
                           "qs=%d - not using conn, ignoring\n",
                           ios, TAGFMTARGS(ios->tag), blk->block_number,
                           rnablk_cache_blk_state_string(blk->state),
                           rnablk_op_type_string(ios->type),
                           atomic_read(&ios->ref_count),
                           rnablk_get_ep_conn(ios->ep),
                           ios->ep,
                           CONNFMTARGS(conn), qstate);
                    }
                    continue;
                }

                if (!is_dma && ios_queuestate_test_and_set(ios,
                                    IOS_QS_DISPATCH,
                                    IOS_QS_DISPATCH_QUIESCED)) {
                    qstate = IOS_QS_DISPATCH;
                }

                if (be_verbose) {
                    rna_printk(KERN_NOTICE,
                           "ios [%p] tag ["TAGFMT"] block [%"PRIu64"] "
                           "state [%s] type [%s] "
                           "rcnt=%d io_conn=%p conn ["CONNFMT"] qs=%d\n",
                           ios, TAGFMTARGS(ios->tag), blk->block_number,
                           rnablk_cache_blk_state_string(blk->state),
                           rnablk_op_type_string(ios->type),
                           atomic_read(&ios->ref_count),
                           rnablk_get_ep_conn(ios->ep),
                           CONNFMTARGS(conn), qstate);
                }

                switch (qstate) {
                case IOS_QS_DISPATCH_COMPLETING:
                    if (be_verbose) {
                        rna_printk(KERN_NOTICE,
                           "COMPLETING ios [%p] tag ["TAGFMT"] blk "
                           "[%"PRIu64"] state [%s] type [%s]\n", ios,
                           TAGFMTARGS(ios->tag),
                           blk->block_number,
                           rnablk_cache_blk_state_string(blk->state),
                           rnablk_op_type_string(ios->type));
                    }
                    has_outstanding_ios = TRUE;
                    break;

                case IOS_QS_DISPATCH_FAILED_REDO:
                    if (be_verbose) {
                        rna_printk(KERN_NOTICE,
                           "COMPLETED ios [%p] tag ["TAGFMT"] blk "
                           "[%"PRIu64"] state [%s] type [%s]\n", ios,
                           TAGFMTARGS(ios->tag),
                           blk->block_number,
                           rnablk_cache_blk_state_string(blk->state),
                           rnablk_op_type_string(ios->type));
                    }
                    break;

                case IOS_QS_DISPATCH_QUIESCED:
                    break;

                case IOS_QS_DISPATCH:
                    if (is_dma) {
                        if (be_verbose) {
                            rna_printk(KERN_ERR,
                               "OUTSTANDING ios [%p] tag ["TAGFMT"] "
                               "block [%"PRIu64"] state [%s] type [%s]\n",
                               ios, TAGFMTARGS(ios->tag),
                               blk->block_number,
                               rnablk_cache_blk_state_string(blk->state),
                               rnablk_op_type_string(ios->type));
                        }
                        has_outstanding_ios = TRUE;
                    } else {
                        if (be_verbose) {
                            rna_printk(KERN_ERR, "INCOMPLETE-QUIESCED "
                                "ios [%p] tag ["TAGFMT"] block [%"PRIu64"] "
                                "state [%s] type [%s]\n",
                                ios, TAGFMTARGS(ios->tag),
                                blk->block_number,
                                rnablk_cache_blk_state_string(blk->state),
                                rnablk_op_type_string(ios->type));
                        }
                        /*
                         * rnablk_undo_conn_io() will take care of
                         * I/O accounting cleanup for WRITE_SAME and
                         * COMP_AND_WRITE (for which 'is_dma' is FALSE).
                         */
                        rnablk_undo_conn_io(ios, TRUE);
                        dec_in_flight(ios->dev, ios);
                    }
                    break;

                default:
                    RNABLK_BUG_ON(TRUE, "blk=%p qstate=%d\n", blk, qstate);
                }
            }
            if (likely(!has_outstanding_ios)) {
                atomic_bit_set(&blk->cb_flags, BLK_F_QUIESCE_COMPLETE);
                if (is_parent_conn(conn)) {
                    rnablk_assert_blk_quiesced(blk);
                }
            } else {
                if (be_verbose) {
                    rna_printk(KERN_NOTICE, "blk=%"PRIu64" outstanding "
                               "ios, needtowait\n", blk->block_number);
                }
                need_to_wait = TRUE;
            }
        }
        rnablk_unlock_blk_irqrestore(blk, irq_flags);
        rnablk_cache_blk_release(blk);
    }

    if (need_to_wait) {
        p_args->quiesced = FALSE;
        RNABLK_BUG_ON(be_verbose, "Waited too long for quiesce!  conn "
                      "["CONNFMT"] cachedev=%p [0x%"PRIx64"]\n",
                      CONNFMTARGS(conn), cachedev, cachedev->rcd_id);
    }

    EXITV;
}

/*
 * rnablk_quiesce_dispatch_queue()
 *
 *  Notes:
 *      1) This routine tries to quiesce all outstanding I/O relevant to the
 *         given 'conn' and (potentially) 'cachedev'.  There may be
 *         outstanding I/O that can't be quiesced but instead must be
 *         waited for.  In that case, the return value indicates whether
 *         all I/O was successfully quiesced or not.  If not, then the
 *         expectation is that higher-level routines will take steps to
 *         ensure that this work gets requeued (with a delay to give the
 *         outstanding I/O time to complete) -- and will continue to requeue
 *         it until all I/O is quiesced.
 *         The 'n_quiesces' argument indicates the number of "retries" that
 *         have been done in attempting to quiesce the I/O. The caller(s)
 *         of this routine are responsible for incrementing its value for
 *         each retry attempt.  The value is used (in
 *         rnablk_quiesce_dispatch_queue_cachedev() to effect a
 *         'timeout', i.e. to determine when we've waited too long for
 *         I/O to quiesce.
 *
 * caller must hold conn->block_list_lock
 *
 * Return value:
 *  Returns TRUE if all I/O was successfully quiesced, otherwise FALSE.
 */
static boolean
rnablk_quiesce_dispatch_queue(struct rnablk_server_conn *conn,
                              rnablk_cachedev_t *cachedev,
                              int n_quiesces)
{
    struct quiesce_dispatch_args args;

    args.n_quiesces = n_quiesces;
    args.quiesced = TRUE;

    rnablk_operate_on_conn_cachedevs(conn, cachedev, &args,
                                     rnablk_quiesce_dispatch_queue_cachedev);
    return args.quiesced;
}                                     

/*
 * rnablk_conn_blks_sort_list_cachedev()
 *
 * Notes:
 *  1) Note that rnablk_process_dev_conn_disconnect() duplicates some
 *     of the logic done here.  If this routine changes, check whether changes
 *     are needed there as well.
 *
 * caller must hold conn->block_list_lock
 */
static void
rnablk_conn_blks_sort_list_cachedev(struct rnablk_server_conn *conn,
                                    rnablk_cachedev_t *cachedev,
                                    void *unused)
{
    struct blk_lru_list *bpos;
    struct list_head *ent, *nent;
    struct io_state  *ios;
    struct cache_blk *blk;
    lockstate_t       irqflags;
    int is_wref;
    
    ENTERV;

    RNABLK_DBG_BUG_ON(NULL == cachedev, "conn ["CONNFMT"] -- null cachedev!\n",
                      CONNFMTARGS(conn));
    RNABLK_DBG_BUG_ON(!rna_service_mutex_is_locked(
                      &conn->rsc_parent_conn->block_list_lock),
                      "conn ["CONNFMT"] cachedev=%p - mutex not locked\n",
                      CONNFMTARGS(conn), cachedev);

    blk_lru_list_for_each(bpos, &cachedev->rcd_block_list) {
        blk = blk_lru_entry(bpos, &is_wref);

        if (unlikely(IS_MARKER_BLK(blk))) {
            continue;       // skip marker blocks
        }

        RNABLK_DBG_BUG_ON(blk->blk_cachedev != cachedev,
                          "blk [%p] block [%llu] expected cachedev %p got "
                          "cachedev %p\n", blk, blk->block_number, cachedev,
                          blk->blk_cachedev);

        if (is_wref) {
            continue;
        }

        rna_printk(KERN_DEBUG,
                   "device [%s] block [%"PRIu64"] state [%s]\n",
                   blk->dev->name,
                   blk->block_number,
                   rnablk_cache_blk_state_string(blk->state));

        if (RNABLK_CACHE_BLK_INVALID == blk->state) {
            /* device has failed, remove block */
            continue;
        }

        rnablk_cache_blk_ref(blk);
        rnablk_lock_blk_irqsave(blk, irqflags);

        blk->cb_dev_conn = NULL;

        atomic_bit_clear(&blk->cb_flags, BLK_F_QUIESCE_COMPLETE);
        /* Clean up the blk cb_write_reference_pending state if needed... */
        if (TRUE == atomic_cmpxchg(&blk->cb_write_reference_pending, TRUE,
                                   FALSE)) {
            atomic_dec(&conn->rsc_outstanding_write_releases);
        }

        if (!list_empty(&blk->bl)) {
            list_for_each_safe(ent, nent, &blk->bl) {
                ios = list_entry(ent, struct io_state, l);
                if (unlikely(!IOS_HAS_IOREQ(ios))) {
                    /*
                     * this IOS in not associated with any incoming I/O,
                     * we can drop it
                     */
                    rna_printk(KERN_NOTICE, "dropping ios [%p] tag ["TAGFMT"] "
                           "type [%s] device [%s] block [%llu] state [%s] "
                           "from bl\n",
                           ios, TAGFMTARGS(ios->tag),
                           rnablk_op_type_string(ios->type),
                           ios->blk->dev->name, ios->blk->block_number,
                           rnablk_cache_blk_state_string(ios->blk->state));
                    rnablk_dequeue_blk_io_nolock(blk, ios);
                    rnablk_ios_finish(ios);
                }
            }
        }

        /*
         * move all IOs that were in dispatch queue (which now also
         * includes IOs that were on the conn queue) and prepend them
         * on the block queue.
         */
        if (!list_empty(&blk->dispatch_queue)) {
            list_for_each_safe(ent, nent, &blk->dispatch_queue) {
                ios = list_entry(ent, struct io_state, l);
                rnablk_reset_ios_dispatch(ios);
                if (unlikely(!IOS_HAS_IOREQ(ios))) {
                    /*
                     * this IOS in not associated with any incoming I/O,
                     * we can drop it
                     */
                    rna_printk(KERN_NOTICE, "dropping ios [%p] tag ["TAGFMT"] "
                           "type [%s] device [%s] block [%llu] state [%s] "
                           "from dispatch\n",
                           ios, TAGFMTARGS(ios->tag),
                           rnablk_op_type_string(ios->type),
                           ios->blk->dev->name, ios->blk->block_number,
                           rnablk_cache_blk_state_string(ios->blk->state));
                    rnablk_io_completed_nolock(ios, blk);
                    rnablk_ios_finish(ios);
                } else {
                    rna_printk(KERN_NOTICE,
                               "ios [%p] tag ["TAGFMT"] type [%s] device [%s] "
                               "block [%"PRIu64"] state [%s] qstate [%s]\n",
                               ios, TAGFMTARGS(ios->tag),
                               rnablk_op_type_string(ios->type),
                               blk->dev->name, blk->block_number,
                               rnablk_cache_blk_state_string(blk->state),
                               rnablk_ios_q_string(
                               ios_queuestate_get(ios)));

                    RNABLK_BUG_ON(!ios_queuestate_test_and_set(ios,
                           IOS_QS_DISPATCH_FAILED_REDO, IOS_QS_BLOCK)
                           && !ios_queuestate_test_and_set(ios,
                           IOS_QS_DISPATCH_QUIESCED, IOS_QS_BLOCK),
                           "ios=%p in unexpected qstate=%d\n", ios,
                           ios_queuestate_get(ios));
                    /*
                     * Clear ios->ep so it doesn't get erroneously used,
                     * i.e. for instance in the rnablk_cache_timeout path()
                     */
                    rnablk_unset_ios_ep(ios);
                }
            }
            if (!list_empty(&blk->dispatch_queue)) {
                list_splice_init(&blk->dispatch_queue, &blk->bl);
            }
        }
        rnablk_unlock_blk_irqrestore(blk, irqflags);
        rnablk_cache_blk_release(blk);
    }
    EXITV;
}

/* caller must hold conn->block_list_lock */
static void
rnablk_conn_blks_sort_list(struct rnablk_server_conn *conn,
                           rnablk_cachedev_t *cachedev)
{
    rnablk_operate_on_conn_cachedevs(conn, cachedev, NULL,
                                     rnablk_conn_blks_sort_list_cachedev);
}                                     


#define RESTART_OK_TO_RESTART   0x1
#define RESTART_IS_DISCONNECT   0x2

// Caller holds conn->block_list_lock
static void
rnablk_restart_conn_blks_cachedev(struct rnablk_server_conn *conn,
                                  rnablk_cachedev_t *cachedev,
                                  void *opaque_flags)
{
    uint32_t flags = (uint32_t)((uintptr_t)opaque_flags);
    struct blk_lru_list *pos, *next;
    struct cache_blk *blk;
    lockstate_t       irqflags;
    int is_wref;

    ENTERV;

    RNABLK_DBG_BUG_ON(NULL == cachedev, "conn ["CONNFMT"] -- null cachedev!\n",
                      CONNFMTARGS(conn));
    RNABLK_DBG_BUG_ON(!rna_service_mutex_is_locked(
                      &conn->rsc_parent_conn->block_list_lock),
                      "conn ["CONNFMT"] cachedev=%p - mutex not locked\n",
                      CONNFMTARGS(conn), cachedev);
    blk_lru_list_for_each_safe(pos, next, &cachedev->rcd_block_list) {
        blk = blk_lru_entry(pos, &is_wref);

        if (unlikely(IS_MARKER_BLK(blk))) {
            continue;       // skip marker blocks
        }

        RNABLK_DBG_BUG_ON(blk->blk_cachedev != cachedev,
                          "blk [%p] block [%llu] expected cachedev %p got "
                          "cachedev %p\n", blk, blk->block_number, cachedev,
                          blk->blk_cachedev);
        if (is_wref) {
            continue;
        }

        /*
         * Below in rnablk_unset_blk_ep() (indirectly), we'll be removing
         * blk from the block_list.  And if it's in the list twice (once for
         * reference lru and once for write reference lru), it will be
         * removed in both places.  Due to this unusual characteristic of the
         * blru list (i.e. the blk may be in the list twice), we have to do an
         * extra check here to ensure that our 'next' pointer isn't
         * pointing to this same blk.  If it is, advance it, so our
         * next pointer will still be valid after we remove blk from the list!
         */
        if (blk_lru_entry(next , &is_wref) == blk) {
            next = _LRU_GET_ENT_PTR(next->blru_next);
        }

        rna_printk(KERN_DEBUG, "dev [%s] block [%"PRIu64"] state [%s] "
                   "blk->conn [%p] conn [%p] cachedev [%#"PRIx64"]\n",
                   blk->dev->name,
                   blk->block_number,
                   rnablk_cache_blk_state_string(blk->state),
                   MASTER_BLK_CONN(blk->dev),
                   conn, cachedev->rcd_id);

        rnablk_cache_blk_ref(blk);
        rnablk_lock_blk_irqsave(blk, irqflags);
        rnablk_unset_blk_ep(blk);

        /*
         * For the normal case, the above call to rnablk_unset_blk_ep() did
         * the rnablk_blk_put_cachedev for us.  However, for blks that had
         * an ios sitting in the wfc_queue waiting for the CS to connect,
         * that won't have happened, because blk->ep pointed to the MD.
         * However, blk_cachedev is still set for these blk's and needs to
         * be unset here!  (If not needed, the following call will do
         * nothing).
         */
        rnablk_blk_put_cachedev(blk, conn);

        /* clear DISCONN_FROZEN _after_ we "put" the cachedev */
        atomic_bit_clear(&blk->cb_flags, BLK_F_DISCONN_FROZEN);

        if (RNABLK_CACHE_BLK_DISCONNECTED == blk->state) {
            rnablk_unlock_blk_irqrestore(blk, irqflags);
            /*
             * If the block is stopped because the cachedev went
             * offline, we can restart now.
             * Otherwise (i.e. if connection went away) don't restart blocks
             * that are missing master due to this disconnect; they'll get
             * restarted when we get the new master block by
             * rnablk_restart_dev_blks()
             */
            if ((flags & RESTART_OK_TO_RESTART)
                 && MASTER_BLK_IS_CONNECTED(blk->dev)
                && (!(flags & RESTART_IS_DISCONNECT)
                    || MASTER_BLK_CONN(blk->dev) != conn)) {
                rnablk_cache_blk_restart(blk, FALSE);
            }
        } else {
            rnablk_unlock_blk_irqrestore(blk, irqflags);
        }
        rnablk_cache_blk_release(blk);
    }

    EXITV;
}

/* caller must hold conn->block_list_lock */
static void
rnablk_restart_conn_blks(struct rnablk_server_conn *conn,
                         rnablk_cachedev_t *cachedev,
                         boolean ok_to_restart)
{
    uint32_t flags = 0;

    if (ok_to_restart) {
        flags |= RESTART_OK_TO_RESTART;
    }
    if (NULL == cachedev) {
        flags |= RESTART_IS_DISCONNECT;
    }
    rnablk_operate_on_conn_cachedevs(conn, cachedev, (void *)((uintptr_t)flags),
                                     rnablk_restart_conn_blks_cachedev);
}                                     

void
rnablk_md_send_cache_query_from_md_response(
                            rna_service_metadata_query_response_t *resp,
                            struct io_state                       *ios)
{
    struct rna_if_table *if_table = NULL;
    struct com_ep       *cache_ep = NULL;
	//int                  ret      = 0;
    //int                  i;
    //uint32_t             cache_addr;
    //uint16_t             cache_port;
    //enum com_type        transport;
    struct rnablk_server_conn *conn = NULL;
    lockstate_t          irqflags;
    boolean              is_connected;
	int64_t              master_block_no;
    unsigned char        oldirql = 0;

    BUG_ON(NULL == resp);
    BUG_ON(NULL == ios);

    rnablk_trc_master(IS_MASTER_BLK(ios->blk),
                      "%sblock [%"PRIu64"] ios [%p] tag ["TAGFMT"]\n",
                      IS_MASTER_BLK(ios->blk) ? "MASTER" : "",
                      ios->blk->block_number, ios, TAGFMTARGS(ios->tag));

    if_table = &resp->mqr_if_table;

    memcpy(&ios->hash_key, &resp->mqr_path_key, sizeof(ios->hash_key));
    ios->c = resp->c;

#ifdef PLATFORM_WINDOWS
	master_block_no = 0xFFFFFFFFFFFFFFFF;
#else
	master_block_no = -1ULL;
#endif

    if (unlikely(ios->blk->block_number != resp->c.co_block_num)) {
        /* if MD specifies -1 as Master blkno, ignore the mismatch... */
        if (!(IS_MASTER_BLK(ios->blk)
              && resp->c.co_block_num == (uint64_t)(master_block_no))) {
            rna_printk(KERN_ERR,
                       "[%s] MD response block number [%"PRIu64"] does not "
                       "match local block number [%"PRIu64"] cookie "
                       "[0x%"PRIx64"]\n",
                       ios->dev->name,
                       resp->c.co_block_num,
                       ios->blk->block_number,
                       resp->mqr_cookie);
            BUG();
        }
    }

    memcpy(&ios->blk->hash_key, &resp->mqr_path_key,
           sizeof(ios->blk->hash_key));
    rnablk_ios_set_cache_id(ios, &resp->mqr_service_id);

    rna_down_read(&svr_conn_lock, &oldirql);
    conn = rnablk_cache_search(&cache_conn_root, &resp->mqr_service_id);
    rna_up_read(&svr_conn_lock, oldirql);

    /*
     * To resolve connection race when no conn is found or a conn is
     * found but is disconnected, repeat search while holding write
     * lock on svr_conn_lock and wfc_queue_lock
     */
    if (rnablk_conn_connected(conn)
        && (cache_ep = rnablk_conn_get_ep(conn)) != NULL) {
        is_connected = TRUE;
    } else {
        is_connected = FALSE;
        rna_printk(KERN_DEBUG, "ios [%p] attempt to connect\n", ios);
        rna_down_write(&svr_conn_lock, &oldirql);
        conn = rnablk_cache_search(&cache_conn_root, &resp->mqr_service_id);
        if (rnablk_conn_connected(conn)
            && (cache_ep = rnablk_conn_get_ep(conn)) != NULL) {
            is_connected = TRUE;
        } else if (NULL == conn) {
            /*
             * No existing connection with the cache server.  We will attempt to
             * connect on the first interface in the interface table that we
             * support.  If that fails, we will try next interface.
             */
            conn = rnablk_make_server_conn(&resp->mqr_service_id, if_table,
                                           NULL, NULL, 0);
            if (NULL != conn) {
                rnablk_cache_insert(&cache_conn_root, conn);

#ifdef WINDOWS_KERNEL
                if (NULL == conn->pHBAExt) {
                    conn->pHBAExt = ios->dev->pHBAExt;
                }
#endif
            }
        } else {
            rna_printk(KERN_DEBUG,
                       "Attempting connect to CS ["rna_service_id_format"]\n",
                       rna_service_id_get_string(&conn->id));
            // update interface table (may have changed due to failed interface)
            rnablk_update_conn_iftable(conn, if_table, FALSE);
        }
        rna_up_write(&svr_conn_lock, oldirql);
    }

    if (NULL == conn) {
        rna_printk(KERN_WARNING, "Unable to create CS conn\n");
        rnablk_end_request(ios, -ENOMEM);
        goto out;
    }

    if (unlikely(0 != rnablk_blk_get_cachedev(ios->blk, NULL_CACHEDEV_ID, conn,
                                              ios_writes_data(ios)))) {
        rna_printk(KERN_ERR, "[%s] block [%"PRIu64"] memory not available, "
                   "failing ios [%p] tag ["TAGFMT"] type [%s]\n",
                   ios->blk->dev->name, ios->blk->block_number,
                   ios, TAGFMTARGS(ios->tag), rnablk_op_type_string(ios->type));
        rnablk_end_request(ios, -ENOMEM);
        rnablk_mark_cache_blk_bad_and_drain(ios->blk, TRUE);
        goto out;
    }

    if (is_connected) {

        rnablk_trc_master(IS_MASTER_BLK(ios->blk),
                          "%sblk=%p [%"PRIu64"] already connected\n",
                          IS_MASTER_BLK(ios->blk) ? "MASTER " : "",
                          ios->blk, ios->blk->block_number);
        rnablk_trace_ios(ios);

        rna_printk(KERN_INFO, "cache server found, queueing request ios [%p] "
                   "tag ["TAGFMT"]\n", ios, TAGFMTARGS(ios->tag));

        /*
         * We're reusing the ios struct from the MD query for the cache
         * query.  Alloc a new tag for the cache query since the previous
         * one used by the md query has been removed
         */ 
        rnablk_retrack_ios(ios);

		rnablk_lock_blk_irqsave(ios->blk, irqflags);
        rnablk_set_blk_ep(ios->blk, cache_ep);
        rnablk_unlock_blk_irqrestore(ios->blk, irqflags);

        rnablk_queue_request(!IS_MASTER_BLK(ios->blk)
                             ? RNABLK_CACHE_QUERY : RNABLK_LOCK_MASTER_BLK,
                             cache_ep, ios, ios->blk, NO_FORCE_QUEUED_IO,
                             FALSE);

        com_release_ep(cache_ep);

    } else {
        rnablk_trc_master(IS_MASTER_BLK(ios->blk),
                          "%sblk=%p [%"PRIu64"] not connected yet ios [%p]"
                          "(conn=%p)\n",
                          IS_MASTER_BLK(ios->blk) ? "MASTER " : "",
                          ios->blk, ios->blk->block_number, ios, conn);
        rnablk_trace_ios(ios);

        /*
         * Queue this request on wfc_queue until the connection to the
         * CS is established.  This ios will then be reused (in
         * rnablk_cache_connected) for the cache query.
         */
        rna_down_write(&wfc_queue_lock, &oldirql);
        list_add_tail(&ios->l, &wfc_queue);
        RNABLK_BUG_ON(!ios_queuestate_test_and_set(ios, IOS_QS_NONE,
                                                   IOS_QS_WFC),
                      "ios [%p] tag ["TAGFMT"] qstate [%d] inconsistent\n",
                      ios, TAGFMTARGS(ios->tag), ios_queuestate_get(ios));
        rna_up_write(&wfc_queue_lock, oldirql);
        rna_printk(KERN_INFO,
                   "queued ios [%p] tag ["TAGFMT"] waiting for cache "
                   "[%"PRIu64"]\n", ios, TAGFMTARGS(ios->tag),
                   ios->cs_ep_key);

        rnablk_queue_retry_connect(conn);
        rnablk_queue_ios_conn_check(ios);
    }
    rnablk_trc_master(IS_MASTER_BLK(ios->blk),
                      "%sblk=%p [%"PRIu64"] done\n",
                      IS_MASTER_BLK(ios->blk) ? "MASTER " : "",
                      ios->blk, ios->blk->block_number);

 out:
    return;
}

/* caller must hold conn->block_list_lock */
static void
rnablk_detached_shutdown_dev_conn_cleanup(struct rnablk_server_conn *p_conn,
                                          rnablk_cachedev_t *cachedev,
                                          void *unused)
{
    struct rnablk_server_conn *conn;
    int i;

    RNABLK_DBG_BUG_ON(!rna_service_mutex_is_locked(
                      &p_conn->block_list_lock),
                      "conn ["CONNFMT"] cachedev=%p - mutex not locked\n",
                      CONNFMTARGS(p_conn), cachedev);

    for (i = 0; i < RNABLK_MAX_DEV_CONNS; i++) {
        if (NULL != (conn = cachedev->rcd_conns[i])) {
            rnablk_cleanup_conn_ioq(conn, NULL);
        }
    }
    return;
}

static int
rnablk_detached_shutdown_server_conn_cleanup(struct rnablk_server_conn *conn,
                                             void *unused)
{
    mutexstate_t mutex_lock_handle;

    rna_printk(KERN_NOTICE, "Cleaning up server conn ["CONNFMT"]\n",
               CONNFMTARGS(conn));
    rna_block_mutex_lock(&conn->block_list_lock, &mutex_lock_handle);
    rnablk_operate_on_conn_cachedevs(conn, NULL, NULL,
                                     rnablk_detached_shutdown_dev_conn_cleanup);
    rnablk_cleanup_conn_ioq(conn, NULL);
    rna_block_mutex_unlock(&conn->block_list_lock, &mutex_lock_handle);
    return 0;
}

void
rnablk_detached_shutdown_cleanup_conns()
{
    if (!atomic_read(&rna_service_detached)) {
        return;
    }

    rnablk_cache_conn_foreach(rnablk_detached_shutdown_server_conn_cleanup,
                              NULL);
}

static void
rnablk_expel_cache_device_wf(rnablk_workq_cb_arg_t arg)
{
    struct work_struct *work = (struct work_struct *)arg;
    struct rnablk_work *w = container_of(work, struct rnablk_work, work);
    struct rnablk_offline_cachedev_wf_data *wd =
                                    &w->data.rwd_rnablk_offline_cachedev_wf;
    uint64_t start_seconds = get_seconds();
    ENTERV;

    rnablk_trigger_offline_cache_device(wd->ocd_conn, wd->ocd_cachedev_id,
                                        CD_OFFLINE_EXPEL);
    rnablk_server_conn_put(wd->ocd_conn);

    rnablk_mempool_free(w, work_cache_info);
    rnablk_finish_workq_work(start_seconds);
    EXITV;
}

static void
rnablk_queue_expel_cache_device(rnablk_cachedev_t *cdp)
{
    struct rnablk_work *w = NULL;
    struct rnablk_offline_cachedev_wf_data *wd = NULL;

    if (likely(NULL != (w = rnablk_mempool_alloc(work_cache_info)))) {
        RNABLK_INIT_RNABLK_WORK(w, wd, rnablk_expel_cache_device_wf);
        wd->ocd_conn = cdp->rcd_server_conn->rsc_parent_conn;
        atomic_inc(&wd->ocd_conn->rsc_refcount);
        wd->ocd_cachedev_id = cdp->rcd_id;
        rna_queue_work(mt_workq, &w->work);
    }
}

static void
rnablk_check_cachedev_for_expel(struct rnablk_server_conn *conn,
                                rnablk_cachedev_t *cdp,
                                void *opaque_uc)
{
    rna_service_unexpelled_cachedevs_t *uc =
                        (rna_service_unexpelled_cachedevs_t *)opaque_uc;
    int i;

    if (NULL_CACHEDEV_ID == cdp->rcd_id) {
        return;     // nothing to do for a "null" cachedev
    }

    for (i = 0; i < MAX_CACHE_DEVICES_PER_CLUSTER
                && NULL_CACHEDEV_ID != uc->cuc_unexpelled_cachedevs[i]; i++) {
        if (cdp->rcd_id == uc->cuc_unexpelled_cachedevs[i]) {
            /* this cachedev is golden, nothing to do */
            return;
        }
    }

    /*
     * If we got here, this cachedev wasn't in the list.  If its id is
     * below the specified 'max', then it has been expelled.
     */
    if (cdp->rcd_id < uc->cuc_unexpelled_cachedevs_max) {
        rnablk_queue_expel_cache_device(cdp);
    }
    return;
}

static int
rnablk_check_conn_for_expelled_cachedevs(struct rnablk_server_conn *conn,
                                         void *opaque_uc)
{
    rnablk_operate_on_conn_cachedevs(conn, NULL, opaque_uc,
                                     rnablk_check_cachedev_for_expel);
    return 0;
}

void
rnablk_check_for_expelled_cachedevs(rna_service_unexpelled_cachedevs_t *uc)
{
    (void)rnablk_cache_conn_foreach(rnablk_check_conn_for_expelled_cachedevs,
                                    uc);
}
                              

#ifndef WINDOWS_KERNEL
/*
 * rnablk_ping_cs()
 *  Issue a ping to the Cache Server connected to us via 'ep', in order
 *  to proactively detect disconnects.
 */
static int
rnablk_ping_cs(struct com_ep *ep)
{
    struct rnablk_server_conn *conn;
    struct buf_entry *buf_entry;
    struct cache_cmd *cmd;
    int ret;

    conn = (struct rnablk_server_conn *)com_get_ep_context(ep);
    if (!rnablk_conn_connected(conn)) {
        /* nothing to do */
        return 0;
    }

    ret = com_get_send_buf(ep, &buf_entry, FALSE);
    if (0 != ret || NULL == buf_entry) {
        return -ENOMEM;
    }

    atomic_inc(&conn->send_bufs_in_use);

    cmd = com_get_send_buf_mem(buf_entry);
    memset(&cmd->h, 0, sizeof(cmd->h));
    cmd->h.h_type = CS_TO_CLIENT_PING;

    ret = com_send(ep, buf_entry, (int)cache_cmd_length(cmd));
    if (unlikely(ret)) {
        atomic_dec(&conn->send_bufs_in_use);
    } 

    return 0;
}


/*
 * rnablk_cs_ping_devconns
 *  Ping all the per-cachedev connections for the given cache device
 */
static void
rnablk_cs_ping_devconns(struct rnablk_server_conn *conn,
                        rnablk_cachedev_t *cdp,
                        void *unused)
{
    struct rnablk_server_conn *devconn;
    struct com_ep *ep;
    int i;

    RNABLK_DBG_BUG_ON(!is_parent_conn(conn),
                      "Expected parent conn here, got conn ["CONNFMT"] "
                      "cdp [%p]\n", CONNFMTARGS(conn), cdp);
    
    for (i = 0; i < RNABLK_MAX_DEV_CONNS; i++) {
        devconn = cdp->rcd_conns[i];
        if (NULL != devconn && rnablk_conn_connected(devconn)) {
            ep = rnablk_conn_get_ep(devconn);
            if (NULL != ep) {
                rnablk_ping_cs(ep);
                com_release_ep(ep);
            }
        }
    }
    return;
}

/*
 * rnablk_cs_ping_worker()
 *  Runs as a kthread. Loops forever checking for active Cache Server
 *  connections and issuing a ping on them at the configured interval,
 *  in order to proactively detect when a CS becomes disconnected.
 *
 * NOTES:
 *  1) In order to keep com credits in balance, the client-to-CS ping
 *     should happen at the same approximate interval as the CS-to-client
 *     pings. (See HRM-4127).  Currently they are both using a default
 *     interval of 5 seconds, but there is no actual coordination between
 *     the two to ensure they're in sync.  This is a TODO!
 */
int
rnablk_cs_ping_worker(void *unused)
{
    struct rnablk_server_conn *conn;
    uint64_t conn_id_key;
    struct com_ep *ep;
    unsigned char oldirql;

    rna_printk(KERN_INFO, "Running...\n");

    while (!atomic_read(&shutdown)) {
        conn_id_key = 0;

        do {
            ep = NULL;
            rna_down_read(&svr_conn_lock, &oldirql);
            conn = rnablk_cache_search_next(&cache_conn_root, conn_id_key);
            if (NULL != conn) {
                conn_id_key = conn->id.u.hash + 1;  // set for next search
                ep = rnablk_conn_get_ep(conn);
            }
            rna_up_read(&svr_conn_lock, oldirql);

            if (NULL != ep) {
                if (rnablk_conn_connected(conn)) {
                    rnablk_ping_cs(ep);
                }
                /* our logic above ensures that if ep is non-null, so is conn */
                if (atomic_read(&conn->rsc_connected_conns) > 1) {
                    /*
                     * Looks like it may have other live child connections,
                     * so try to ping those as well.
                     */
                    rnablk_operate_on_conn_cachedevs(conn, NULL, NULL,
                                                     rnablk_cs_ping_devconns);
                }
                com_release_ep(ep);
            }
        } while (NULL != conn);

        (void)wait_event_interruptible_timeout(rnablk_cs_ping_wq,
                                               (0 != atomic_read(&shutdown)),
                                               rnablk_cs_ping_interval);
    }
    rna_printk(KERN_INFO, "exiting\n");
    return 0;
}
#endif /* !WINDOWS_KERNEL */
