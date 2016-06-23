/**
 * <rna_common_kernel_types.h>
 *
 * Copyright (c) 2012-13 Dell  Inc 
 *
 */
#pragma once

#include "platform.h"
#include "platform_atomic.h" /*needed for atomic_t */

/* Although the implementation of the inline functions are in a different .h, given
 * the interdependency between typedefs, structs, etc. putting both OSes in here
 * is the best solution to centralize knowledge.
 */


#if defined (WINDOWS_KERNEL)

typedef PIO_WORKITEM workstruct_t;
typedef HANDLE workqueue_t;
typedef PIO_WORKITEM delayedwork_t;

typedef PKTIMER timerlist_t;

typedef KEVENT rna_service_wait_obj;

#else
/* LINUX KERNEL */

#include <linux/timer.h>

typedef struct work_struct workstruct_t;
typedef struct work_struct rna_service_work_t;
typedef struct workqueue_struct workqueue_t;
typedef struct delayed_work delayedwork_t;

typedef struct timer_list timerlist_t;

#endif


/***** Timer items ****/

#define RNA_TIMER_DEBUG 1

#ifdef RNA_TIMER_DEBUG
extern atomic_t timers_started;
extern atomic_t timers_stopped;
#endif


enum timer_state
{
    TIMER_IDLE  = 0,
    TIMER_ARMING,
    TIMER_ACTIVE,
    TIMER_EXPIRED,
    TIMER_NO_REARM
};

struct rna_timer
{
    atomic_t          timer_state;
    timerlist_t		  timer;
#ifdef WINDOWS_KERNEL
    /* Store the KTIMER here so we don't have to do a separate
     * allocation.  Still use 'timer' as a pointer to this to
     * maintain code compatibility.
     */
    KTIMER            ktimer;
	/* WinKern needs a DPC object for custom callbacks. */
	KDPC			  timerDpc;
#endif
}; 

/* Malloc wrappers that make it more difficult to allocate a
 * region who's size doesn't correspond to the pointer type.
 * Typical use: struct foo* x = rna_kmalloc(x, GFP_KERNEL) 
 */

#define RNA_ALLOC_TAG 'RNAK'
