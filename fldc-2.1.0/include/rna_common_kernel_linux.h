/**
 * <rna_common_kernel_linux.h> - Dell Fluid Cache block driver
 *
 * Copyright (c) 2012-13 Dell  Inc 
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

#include "platform.h"

#include "rna_common_kernel_types.h"

#include <linux/seq_file.h>
#include <linux/rwsem.h>
#include <linux/netlink.h>
#include "config.h"

#ifndef NO_KERNEL_MUTEX
#include <linux/mutex.h>
#endif
#include <linux/rbtree.h>
#include <linux/version.h>
#include <linux/wait.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
#include <linux/smp_lock.h> // for lock_kernel and unlock_kernel
#endif
#include <linux/module.h> // for THIS_MODULE
#include <linux/workqueue.h>
#include <linux/gfp.h>
#include <linux/scatterlist.h> // sg_init_table definition needs this

#include "rna_common_logging.h"


#ifdef __powerpc64__
#define __PRI64_PREFIX  "l"
#else
#if defined(__GNUC__) && !defined(__STRICT_ANSI__)
#define  __PRI64_PREFIX  "ll"
#endif
#endif /* __powerpc64__ */

#define PRId64         __PRI64_PREFIX "d"
#define PRIx64         __PRI64_PREFIX "x"
#define PRIu64         __PRI64_PREFIX "u"

#ifndef atomic_cmpxchg
#define atomic_cmpxchg(v, old, new) ((int)cmpxchg(&((v)->counter), old, new))
#endif /* ifndef atomic_cmpxchg */

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
#define READ_UPDATE_ATIME_BUF
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18) && !defined(RNA_OFED_BUILD)
#define RNA_INIT_WORK(work, func, ctx)  INIT_WORK(work, func, ctx)
#else
#define RNA_INIT_WORK(work, func, ctx)  INIT_WORK(work, func)
#endif

#ifdef NO_KZALLOC

static inline
void *kzalloc(size_t size, int flags)
{
        void *ret = kmalloc(size, flags);
        if (ret)
                memset(ret, 0, size);
        return ret;
}

#endif /* NO_KZALLOC */

/* function attribute to warn if the return value is ignored */
#define WARN_UNUSED __attribute__((warn_unused_result))

#define debug_assert_locked(lock) \
        if (mutex_trylock(lock)) { \
                mutex_unlock(lock); \
                printk(KERN_ERR "%s: debug_assert_locked failed!", __FUNCTION__); \
                dump_stack(); \
        }



/* Malloc wrappers that make it more difficult to allocate a
 * region who's size doesn't correspond to the pointer type.
 * Typical use: struct foo* x = rna_kmalloc(x, GFP_KERNEL) */

#define rna_kmalloc(ptr, flags) (typeof(ptr)) kmalloc(sizeof(*ptr), flags)
#define rna_kzalloc(ptr, flags) (typeof(ptr)) kzalloc(sizeof(*ptr), flags)

 
/* kzalloc has a size limit of 128k, and vmalloc does some
 * page table and vma setup that isn't appropriate for
 * kernel use, so we create our own allocation routines on
 * top of __get_free_pages. */
static inline void *gfp_alloc(size_t size, int flags)
{
	int order = get_order(size);
	void *addr;

	if (unlikely(order < 0)) {
		rna_printk(KERN_ERR, "size %zd not supported\n", size);
		addr = NULL;
	} else {
		addr = (void*) __get_free_pages(flags, order);
		if (unlikely(NULL == addr))
			rna_printk(KERN_ERR, "__get_free_pages "
			           "failed, size %zd\n", size);
	}
	return addr;
}

/* Zero out the part of the memory region we plan to use. */
static inline void *gfp_zalloc(size_t size, int flags)
{
	void *addr = gfp_alloc(size, flags);
	if (likely(NULL != addr))
		memset(addr, 0, size);

	return addr;
}

/* Unfortunately, we have to remember how big our allocation was,
 * and free the same amount.  This is error prone, so we really 
 * shouldn't use gfp_alloc unless we have to. */
static inline void gfp_free(void *addr, size_t size) 
{
	if (size)
		free_pages((unsigned long)addr, get_order(size));
}


/******** Work Queue ***********/



#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
int rna_queue_delayed_work(struct workqueue_struct *wq, struct work_struct *work, unsigned long delay);
#else
int rna_queue_delayed_work(struct workqueue_struct *wq, struct delayed_work *work, unsigned long delay);
#endif


/***** Timer items ****/




/* 
 * When this returns, any timers that were pending are canceled, and
 * any timers that were running have finished.  If you don't plan to
 * use this timer again, use rna_final_cancel_timer instead.
 */
#define rna_stop_timer(t) _rna_cancel_timer(t, TIMER_IDLE)

/* 
 * When this returns, any timers that were pending are canceled,
 * any timers that were running have finished, and this timer has
 * not and cannot be re-armed, except by calling rna_timer_init.
 */
#define rna_final_cancel_timer(t) _rna_cancel_timer(t, TIMER_NO_REARM)


/* 
 * We don't actually transition the state to TIMER_IDLE when a timer
 * expires, so this will return TRUE even for expired timers.
 */
INLINE int rna_timer_running (struct rna_timer *timer)
{
    if (TIMER_ACTIVE == atomic_read(&timer->timer_state)) {
        return (TRUE);
    } else {
        return (FALSE);
    }
}


/***** Timer Functionality ****/

/**
 * Initialize a timer.
 *
 * @param timer - the timer struct that wraps a struct timer_list
 */
INLINE void rna_init_timer ( struct rna_timer *timer )
{
    init_timer ( &timer->timer );
    atomic_set(&timer->timer_state, TIMER_IDLE);
}

/* 
 * Stop a timer, and set it to newstate.  If it's in the ARMING state,
 * we spin.
 */
INLINE void _rna_cancel_timer (struct rna_timer *timer,
                                      enum timer_state newstate)
{
    int oldstate;
    int done = FALSE;

    while (!done) {
        oldstate = atomic_read(&timer->timer_state);

        switch (oldstate) {
            case TIMER_ACTIVE:
                del_timer_sync(&timer->timer);
                if (oldstate == atomic_cmpxchg(&timer->timer_state,
                                               oldstate, newstate)) {
                    done = TRUE;
#ifdef RNA_TIMER_DEBUG
                    atomic_inc(&timers_stopped);
#endif
                } /* otherwise retry */
                break;
            case TIMER_ARMING:
                /* rna_set_timeout is running in another thread,
                 * spin until it's done */
                break;
            default:
                done = TRUE;
                break;
        }
    }
}


/**
 * Set up a timer which will call a callback function when the timer expires.
 * Inlining this may be expensive.
 *
 * @param timer - the timer struct that wraps a struct timer_list
 */
INLINE int rna_set_timeout (struct rna_timer *timer,
                                   int timeout_msec,
                                   void *callback, void *ctx)
{
    int state;
    int done = FALSE;
    int ret;
    int error_printed = FALSE;

    while (!done) {

        state = atomic_read(&timer->timer_state);

        switch (state) {
            case TIMER_NO_REARM:
                rna_printk(KERN_WARNING, "Attempt to re-arm timer [%p] in NO_REARM state.\n", timer);
                done = TRUE;
                ret = TIMER_NO_REARM;
                break;
            case TIMER_ACTIVE:
                rna_stop_timer(timer);
                /* retry */
                break;
            case TIMER_ARMING:
                if (!error_printed) {
                    rna_printk(KERN_WARNING, "Timer [%p] being armed "
                               "from two contexts at once.\n", timer);
                    error_printed = TRUE;
                }
                /* spin until state progresses */
                break;
            case TIMER_IDLE:
            case TIMER_EXPIRED:
                /* While we're ARMING, _rna_cancel_timer will spin.
                 * If state has changed, we just bail out and retry. */
                if (state == atomic_cmpxchg(&timer->timer_state,
                                            state, TIMER_ARMING))
                {
                    timer->timer.expires = msecs_to_jiffies(timeout_msec)+jiffies;
                    if (!time_after (timer->timer.expires, jiffies)) {
                        rna_printk(KERN_INFO, "timer expired\n");
                        ret = TIMER_EXPIRED;
                    } else {
                        init_timer (&timer->timer);
                        timer->timer.data = (unsigned long) ctx;
                        timer->timer.function = callback;

                        add_timer (&timer->timer);
                        ret = TIMER_ACTIVE;
                    }

                    if (TIMER_ARMING != atomic_cmpxchg(&timer->timer_state,
                                                       TIMER_ARMING, ret))
                    {
                        /* This shouldn't ever happen. */
                        rna_printk(KERN_ERR, "unexpected timer state "
                                   "transition while arming\n");
                        del_timer_sync(&timer->timer);
                        atomic_set(&timer->timer_state, TIMER_NO_REARM);
                    } else {
#ifdef RNA_TIMER_DEBUG
                        atomic_inc(&timers_started);
#endif
                    }

                    done = TRUE;
                }
                break;
            default:
                rna_printk(KERN_ERR, "Unexpected timer state [%d].", state);
                break;
        }
    }
    return ret;
}




#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
#ifndef RNA_OFED_BUILD
#define rna_sg_init_table rna_sg_init_table_dummy
#else
#define rna_sg_init_table sg_init_table
#endif
#else
#define rna_sg_init_table sg_init_table
#endif

/* No idea what the scale parameter does, but a couple of drivers use 4. */
#define BIOSET_SCALE 4
#define BIOSET_FRONTPAD 0

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
#define rna_bioset_create(bio_pool_size, bvec_pool_size) bioset_create(bio_pool_size, bvec_pool_size, BIOSET_SCALE)
#define rna_bioset_free(bioset)
#else
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
#define rna_bioset_create(bio_pool_size, bvec_pool_size) bioset_create(bio_pool_size, bvec_pool_size)
#define rna_bioset_free(bioset)
#else
#define rna_bioset_create(bio_pool_size, bvec_pool_size) bioset_create(bio_pool_size, BIOSET_FRONTPAD)
#define rna_bioset_free(bioset) bioset_free(bioset)
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
#define rna_bdev_logical_block_size(bdev) 512
#else
#define rna_bdev_logical_block_size bdev_logical_block_size
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
#define rna_queue_max_sectors(q) (q->max_sectors)
#else
#define rna_queue_max_sectors(q) queue_max_sectors(q)
#endif

//#define rna_blk_queue_max_sectors(q, 

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
#define rna_blkdev_put(bdev, mode) blkdev_put(bdev)
#else
#define rna_blkdev_put(bdev, mode) blkdev_put(bdev, mode)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
#define rna_for_each_sg(sgl, sg, nsgl, i) \
  for (i=0, sg=&(sgl[0]); i<nsgl; sg = &(sgl[i]), i++)
#else
#define rna_for_each_sg for_each_sg
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
#define rna_sg_page(sg) (sg->page)
#else
#define rna_sg_page sg_page
#endif

