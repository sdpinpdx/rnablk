/**
 * <rna_common.h> - Dell Fluid Cache block driver
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

#ifdef PLATFORM_WINDOWS
#include "rna_common_kernel_windows.h"

#else
#include "rna_common_kernel_linux.h"
#endif

#include "rna_common_logging.h"

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif


#ifdef NO_KERNEL_MUTEX
#define mutex_init(lock)                        sema_init(lock, 1)
#define mutex_destroy(lock)                     sema_init(lock, -99)
#define mutex_lock(lock)                        down(lock)
#define mutex_trylock(lock)                     (down_trylock(lock) ? 0 : 1)
#define mutex_unlock(lock)                      up(lock)
#endif


/* Zero out the contents of a structure pointed to by the pointer p.*/
#define clear(p) memset(p, 0, sizeof(*p))


/* Common workqueue definitions */
#ifdef WINDOWS_KERNEL
#include "rna_service_win_workqueue.h"

rna_service_work_queue_t *rna_create_workqueue(const char *name);
rna_service_work_queue_t *rna_create_singlethread_workqueue(const char *name);
void rna_flush_workqueue(rna_service_work_queue_t *wq);
void rna_destroy_workqueue(rna_service_work_queue_t *wq);
int rna_queue_work(rna_service_work_queue_t *wq, rna_work_struct_t *work);

#else

workqueue_t *rna_create_workqueue(const char *name);
workqueue_t *rna_create_singlethread_workqueue(const char *name);
void rna_flush_workqueue(workqueue_t *wq);
void rna_destroy_workqueue(workqueue_t *wq);
int rna_queue_work(workqueue_t *wq, workstruct_t *work);

#endif /*WINDOWS_KERNEL */


#define rna_assert_timer_cancelled(timer) \
    BUG_ON(rna_timer_running(timer));

INLINE void print_timer_debug (void)
{
#ifdef RNA_TIMER_DEBUG
    int started = atomic_read(&timers_started);
    int stopped = atomic_read(&timers_stopped);

    if (started == stopped) {
        rna_printk(KERN_INFO, "Timers OK: [%d] started and stopped.\n", started);
    } else {
        rna_printk(KERN_ERR, "Timer mismatch: [%d] started, [%d] stopped.\n", started, stopped);
    }
#endif
}

#ifndef WINDOWS_KERNEL

/* If were're doing a non-OFED build against a pre-2.6.24 kernel,
 * we need to define our own "sg_init_table" function. */
INLINE void rna_sg_init_table_dummy(struct scatterlist *sgl, unsigned int nents)
{
    memset(sgl, 0, sizeof(*sgl) * nents);
}

#endif /*WINDOWS_KERNEL*/

/* Add to an atomic_t, but only if its previous value was >= 0.
 * Return TRUE on success, FALSE on failure.
 * May livelock, but that's unlikely. */
INLINE int
atomic_add_nonnegative(int value, atomic_t *a)
{
    int ret = 1;
    int prev;
    
    /* Windows kernel complier throws error C4127 for while loops
     * that evaluate to a constant.  MSFT recommends for loops
     */
    for ( ; ; )
    {
        prev = atomic_read(a);
        if (prev < 0) {       
            ret = 0;
            break;
        }
    
        if (atomic_cmpxchg(a, prev, prev+value) == prev) {
            ret = 1;
            break;
        }
    }
    
    return ret;
}

/* 
 * Given two integer ranges, find the largest value contained by both.
 * If one is found, return 0 and set best_match to that value.
 * If the ranges do not overlap, find the closest value from the first
 * range to any of the values in the second range, and set best_match to
 * that.
 */
INLINE int max_overlap(int mina, int maxa, int minb, int maxb, int* best_match)
{                               
    int overlap_max = maxa > maxb ? maxb : maxa;
    int overlap_min = mina > minb ? mina : minb;
    int ret = 0;
                          
    if (likely(overlap_min <= overlap_max)) {
        *best_match = overlap_max;
    } else {              
        ret = -1;
        if (maxa < minb) {
            *best_match = maxa;
        } else if (mina > maxb) {
            *best_match = mina;
        } else {    
            BUG();
        }
    }
    
    return ret;
}
 
