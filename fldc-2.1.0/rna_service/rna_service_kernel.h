/**
 * <rna_service_kernel.h> - Dell Fluid Cache block driver
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

/*
 * === THIS FILE IS TO BE INCLUDED BY rna_service.c ONLY ===
 *
 * Kernel-level compatability for the rna_service component.
 *
 * These defines, typedefs, and inline functions allow rna_service to build at
 * the kernel level.  NOTE that any changes to this file must be reflected in
 * rna_service_user.h.
 */

#ifndef _RNA_SERVICE_KERNEL_H_
#define _RNA_SERVICE_KERNEL_H_

#include "platform.h"

CODE_IDENT("$URL: https://svn.rnanetworks.com/full/tags/HERMES_2_1_0_RC1/linux-kernel/rna_service/rna_service_kernel.h $ $Id: rna_service_kernel.h 48531 2016-01-27 03:53:25Z jroy $")

#undef LIST_HEAD

/* First system includes */

#include "../include/rna_common_kernel_types.h"

#ifdef LINUX_KERNEL
#include <linux/utsname.h>
#include <linux/time.h>
#include <linux/module.h>
#include <linux/hardirq.h>
#include <linux/workqueue.h>
#include <linux/ctype.h>
#include <linux/string.h>

#else  /* WINDOWS KERNEL */

#define NTSTRSAFE_LIB
#include <ntstrsafe.h>

#include <wsk.h>
#include <Wdmguid.h>

#pragma warning(push)
#pragma warning(disable:4100)   /* "unreferenced formal parameter" */
#pragma message("'Unreferenced formal parameter' warning disabled")

#endif /*LINUX_KERNEL*/

/* Now local includes */
#ifdef LINUX_KERNEL
#include "../com/rna_com_linux_kernel.h"
#include "protocol.h"

#else  /* WINDOWS KERNEL */

#include "rna_status_codes.h"
#include "../../windows/kernel/RNA_Service\rna_service_win_workqueue.h"
#include "../../common/protocol.h"
#include "../../windows/kernel/include/comAPIPublic.h"
#include "../../windows/kernel/RNA_RNASvcTest/RNA_RNASvcTest/ComInitFns.h"

#endif /*LINUX_KERNEL*/

#include <stdarg.h>

#include "../include/rna_common.h"
#include "rna_common_logging.h"

#include "../com/rna_com_ib.h"
#include "rna_locks.h"
#include "rna_mutex.h"
#include "rna_service_id.h"
#include "rna_dskattrs_common.h"

struct cache_cmd;
struct cfm_cmd;


/* ------------------------------- General -------------------------------- */

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#undef  __location__
#define __location__ "rna_service.c:" TOSTRING(__LINE__)

#define rna_service_assert(expr)    \
    BUG_ON(!(expr))

#define rna_service_debug_assert(expr)    \
    BUG_ON(!(expr))

#if defined(LINUX_KERNEL)
#define rna_service_gettimeofday            do_gettimeofday
#elif defined(WINDOWS_KERNEL)

/* Windows doesn't have a 'do_gettimeofday' so have to create */
/* Found part of this snippet @ stackoverflow */

/* number of microseconds between Jan 1st 1601 and Jan 1st 1970 */
#if defined(_MSC_VER) || defined(_MSC_EXTENSIONS)
  #define DELTA_EPOCH_IN_MICROSECS  11644473600000000Ui64
#else
  #define DELTA_EPOCH_IN_MICROSECS  11644473600000000ULL
#endif


// TODO: This shouldn't be in a .h file.  Move to appropriate .c file.
static void rna_service_gettimeofday( struct timeval *tv)
{
  LARGE_INTEGER curTime;
  unsigned __int64 tmpres = 0;
  //ULONG secs;

  if (NULL != tv)
  {
    KeQuerySystemTime (&curTime);
    tmpres |= curTime.HighPart;
    tmpres <<= 32;
    tmpres |= curTime.LowPart;
        /*converting file time to unix epoch*/
    tmpres -= DELTA_EPOCH_IN_MICROSECS; 
    tmpres /= 10;  /*convert into microseconds*/
    tv->tv_sec = (long)(tmpres / 1000000UL);
    tv->tv_usec = (long)(tmpres % 1000000UL);
  }

}


#endif /* LINUX_KERNEL, WINDOWS_KERNEL */


#define rna_service_atomic_read             atomic_read

INLINE uint32_t
rna_service_gettime_seconds(void)
{
        struct timeval tv;

        rna_service_gettimeofday(&tv);
	/* WARNING: Questionalble cast to 32 bits! --MAZ */
	return (uint32_t) tv.tv_sec;
}


/*
 * Returns:
 *  TRUE  if the _old value at _addr has been replaced with the _new value
 *  FALSE if the value found at _addr was not _old, so was not replaced
 *        with _new
 *
 * (Note in the following that atomic_cmpxchg() returns the initial value
 * found at the specified address).
 */
#define rna_service_atomic_test_and_set(_addr, _old, _new)  \
    ((_old) == atomic_cmpxchg((_addr), (_old), (_new)))

#define rna_service_atomic_add_return(_addr, _val)  \
        atomic_add_return((_val), (_addr))


/* ------------------------------- Logging -------------------------------- */




/* ----------------------------- ep handling ------------------------------ */

typedef struct com_ep_handle_s {
    struct com_ep       *eph_ep;
    uint32_t             eph_gen;
    uint8_t              eph_user_type;
    uint8_t              eph_pad[3];  // for future use and 64-bit alignment
    struct sockaddr_in   eph_dst_in;
} com_ep_handle_t;

INLINE void
com_init_eph(com_ep_handle_t *eph)
{
    memset(eph, 0, sizeof(*eph));
}

static void
create_eph(struct com_ep *ep, com_ep_handle_t *eph)
{
    com_init_eph(eph);
    eph->eph_ep = ep;
    eph->eph_user_type = com_get_ep_user_type(ep);
    eph->eph_dst_in = com_get_ep_dst_in(ep);
}

INLINE boolean
com_eph_isempty(com_ep_handle_t *eph)
{
    return (NULL == eph->eph_ep);
}

INLINE  boolean
com_eph_equal(com_ep_handle_t *eph1, com_ep_handle_t *eph2)
{
    return ((NULL != eph1->eph_ep) && (eph1->eph_ep == eph2->eph_ep));
}

INLINE struct com_ep *
com_get_ep_ptr(com_ep_handle_t *eph)
{
    return ((eph != NULL) ? eph->eph_ep : NULL);
}

INLINE int
com_get_ep_src_in(com_ep_handle_t *eph, struct sockaddr_in *src_in)
{
    if ((NULL == eph)
      || (NULL == eph->eph_ep)) {
        memset(src_in, 0, sizeof(*src_in));
        return (1);
    } else {
#ifdef WINDOWS_KERNEL
        //TODO:  Check return value!!!!
        com_get_ep_src_in_ex(eph->eph_ep, src_in, sizeof(*src_in) );
        
#else
        *src_in = eph->eph_ep->src_in;
#endif /* WINDOWS_KERNEL */
        return (0);
    }
}

INLINE int
com_get_ep_is_local_connection(com_ep_handle_t *eph)
{
#ifdef WINDOWS_KERNEL
    struct sockaddr_in src_in;
    struct sockaddr_in dst_in;
#endif /* WINDOWS_KERNEL */

    if ((NULL == eph)
      || (NULL == eph->eph_ep)) {
        return 0;
    }
#ifdef WINDOWS_KERNEL
    //TODO:  Check return value!!!!
     com_get_ep_src_in_ex(eph->eph_ep, &src_in, sizeof(src_in) );
     com_get_ep_dst_in_ex(eph->eph_ep, &dst_in, sizeof(dst_in) );
     if(src_in.sin_addr.s_addr == dst_in.sin_addr.s_addr)
         return 1;
     else
         return 0;
#else
    return (eph->eph_ep->src_in.sin_addr.s_addr == 
            eph->eph_ep->dst_in.sin_addr.s_addr);
#endif /* WINDOWS_KERNEL */
}



#ifdef DEBUG_EP_REFCOUNT

#define com_inc_ref_eph(_eph)                                                 \
(                                                                             \
    rna_dbg_log(RNA_DBG_VERBOSE,                                              \
                "com_inc_ref_eph [%p]\n", (_eph)->eph_ep),                    \
    com_inc_ref_ep((_eph)->eph_ep)                                            \
) 

#define com_release_eph(_eph)                                                 \
    if (NULL == (_eph)->eph_ep) {                                             \
        rna_dbg_log(RNA_DBG_ERR,                                              \
                    "com_release_eph called with NULL eph_ep\n");             \
    } else {                                                                  \
        rna_dbg_log(RNA_DBG_VERBOSE,                                          \
                    "com_release_eph [%p]\n",                                 \
                    (_eph)->eph_ep);                                          \
        com_release_ep((_eph)->eph_ep);                                       \
    }

#else

#define com_inc_ref_eph(_eph)                                                 \
    com_inc_ref_ep((_eph)->eph_ep)

#define com_release_eph(_eph)                                                 \
    if (NULL == (_eph)->eph_ep) {                                             \
        rna_dbg_log(RNA_DBG_ERR,                                              \
                    "%s: com_release_eph called with NULL eph_ep\n",          \
                    __location__);                                            \
    } else {                                                                  \
        com_release_ep((_eph)->eph_ep);                                       \
    }

#endif  // DEBUG_EP_REFCOUNT


INLINE void *
com_get_eph_context(com_ep_handle_t *eph)
{
    if (NULL != eph) {
        return com_get_ep_context(eph->eph_ep);
    }
    return NULL;
}

INLINE void
com_set_eph_context(com_ep_handle_t *eph, void *context)
{
    rna_service_assert(NULL != eph && NULL != eph->eph_ep);

    com_set_ep_context(eph->eph_ep, context);
}

/* ------------------------------- Locking -------------------------------- */

/* ---------- Mutex stuff was here. Moving to rna_locks.h ----------------- */

#ifdef WINDOWS_KERNEL
#define rna_service_might_sleep()  /* Empty */
#else
#define rna_service_might_sleep    might_sleep
#endif /* WINDOWS_KERNEL */

/*------------ Spinlock stuff was here -----*/

/* ------------------------ Memory Allocation ----------------------------- */

INLINE void *
rna_service_alloc(uint32_t size)
{
    /* allocation with GFP_KERNEL can sleep */
#ifdef LINUX_KERNEL
    BUG_ON(in_atomic());
#endif

    /* GFP_ATOMIC or GFP_NOIO are safe choices here.  If we're sure
     * the block driver won't call directly into us from the same
     * thread while servicing a disk flush that was triggered by
     * malloc, then we can use GFP_KERNEL.  Otherwise, we're likely
     * to see RECLAIM_FS-unsafe warnings from lockdep. */
#ifdef WINDOWS_KERNEL
    /* Not using rna_kmalloc because that #define assumes the ptr isn't void and 
     * has a size (so sizeof returns a value.  So as to not create yet more
     * #defines, just stuffing in ExAllocate directly here
     */
    return (ExAllocatePoolWithTag(NonPagedPoolNx, size, RNA_ALLOC_TAG));
#else
    return (kmalloc(size, GFP_ATOMIC));
#endif /* WINDOWS_KERNEL */

}


INLINE void *
rna_service_alloc0(uint32_t size)
{
#ifdef WINDOWS_KERNEL
    void * ptr;
#endif /* WINDOWS_KERNEL */

    /* allocation with GFP_KERNEL can sleep */
#ifdef LINUX_KERNEL
    BUG_ON(in_atomic());
#endif

#ifdef WINDOWS_KERNEL
    /* Not using rna_kmalloc because that #define assumes the ptr isn't void and 
     * has a size (so sizeof returns a value.  So as to not create yet more
     * #defines, just stuffing in ExAllocate and zeroing directly here
     */
    ptr = ExAllocatePoolWithTag(NonPagedPoolNx, size, RNA_ALLOC_TAG);
    if (NULL != ptr) {
        RtlZeroMemory(ptr,size);  
    }
    return(ptr);

#else
    return (kzalloc(size, GFP_ATOMIC));
#endif /* WINDOWS_KERNEL */


}


#define rna_service_simple_alloc rna_service_alloc
#define rna_service_simple_free  kfree

#ifndef WINDOWS_KERNEL
#define rna_kfree       kfree   /* ?? */
#endif /*WINDOWS_KERNEL */

INLINE void
rna_service_free(uint32_t size DECLARE_UNUSED, void *mem_block)
{
    UNREFERENCED_PARAMETER(size);
    rna_kfree(mem_block);
}

/*-----------------WORKQUEUE----------------------*/

#ifdef LINUX_KERNEL

typedef struct workqueue_struct rna_service_work_queue_t;

INLINE int
rna_service_workq_create(int      num_threads,
                         int      priority DECLARE_UNUSED,
                         int      min_size DECLARE_UNUSED,
                         rna_service_work_queue_t
                                **new_wq)
{
    if (1 == num_threads) {
        /* Using GPL-only workqueue constructor. */
        *new_wq = create_singlethread_workqueue("fldc_serv.");
    } else {
        /* using GPL-only workqueue function */
        *new_wq = create_workqueue("fldc_serv.");
    }

    if (NULL == *new_wq) {
        return (-1);
    }
    return (0);
}

/*
 * Returns:
 *     0 on success
 *    -1 on failure
 */
INLINE int
rna_service_workq_add(struct workqueue_struct *wq, struct work_struct *work)
{
    /*
     * rna_queue_work() returns non-zero on success, and 0 if the work queue
     * structure was already waiting in the queue and was not aded a second
     * time.
     */
	if (0 != rna_queue_work(wq, work)) {
        /* non-zero return indicates success */
        return (0);
    } else {
        /*
         * zero return indicates that the work queue structure was already
         * waiting in the queue and was not aded a second time
         */
        return (-1);
    }
}

#define rna_service_workq_flush     rna_flush_workqueue
/* XXX ignore thread cancelation arg for now */
#define rna_service_workq_destroy(__rswd_queue, __rswd_cancel_threads) rna_destroy_workqueue(__rswd_queue)

/*
 * Deal with the differences between workq callback functions at the user and
 * kernel levels.
 */
typedef void rna_service_workq_cb_ret_t;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
typedef void * rna_service_workq_cb_arg_t;
#else
typedef struct work_struct * rna_service_workq_cb_arg_t;
#endif


typedef void (*rna_service_work_cb) (rna_service_workq_cb_arg_t ctx);

#define RNA_SERVICE_WORKQ_CB_RETURN(retval) \
    return;

#define RNA_SERVICE_WORK_INIT RNA_INIT_WORK

// This value doesn't matter since the argument is ignored by
// rna_fifo_workq_create
#define RNA_UTIL_THREAD_PRIORITY_HIGH    2

#endif /*LINUX_KERNEL*/

/* ---------------------------- Timers -------------------------------- */

typedef struct rna_timer rna_service_timer_t;

typedef void (*rna_service_timer_callback)(uint64_t timer_context);

/*
 * No initialization is needed for the kernel-level timer subsystem.
 */
#define rna_service_timer_subsystem_init()

#define rna_service_timer_init rna_init_timer
#define rna_service_assert_timer_canceled rna_assert_timer_cancelled

typedef struct {
     rna_service_work_queue_t *kcx_timer_workq;
    boolean                  kcx_shutting_down;
} rna_service_kernel_context_t;

typedef struct {
    rna_service_timer_t           sto_timer;
    rna_service_timer_callback    sto_timer_callback;
    uint64_t                      sto_timer_callback_parameter;    
     rna_service_work_t     sto_timer_work;
    rna_service_kernel_context_t *sto_timer_ctx;
} rna_service_timer_object_t;

#ifdef LINUX_KERNEL
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
INLINE void rna_service_timer_workq_callback(void *work)
#else
INLINE void rna_service_timer_workq_callback(struct work_struct *work)
#endif /*Linux kernel rev */
#else
/* WINDOWS KERNEL */
INLINE void rna_service_timer_workq_callback( rna_service_work_t *work)
#endif
{
    rna_service_timer_object_t * object = NULL;

    BUG_ON(NULL == work);
#ifdef WINDOWS_KERNEL
    object = CONTAINING_RECORD(work, rna_service_timer_object_t, sto_timer_work);
#else
    object = container_of(work, rna_service_timer_object_t, sto_timer_work);
#endif /* WINDOWS_KERNEL */

    if (!object->sto_timer_ctx->kcx_shutting_down) {
        BUG_ON(NULL == object->sto_timer_callback);
        object->sto_timer_callback(object->sto_timer_callback_parameter);
    }
}

INLINE void
rna_service_timer_callback_wrapper (uint64_t timer_callback_parameter)
{
    rna_service_timer_object_t * object =
        (rna_service_timer_object_t *)timer_callback_parameter;

    BUG_ON(NULL == object);

    if (!object->sto_timer_ctx->kcx_shutting_down) {
#ifdef LINUX_KERNEL
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
        INIT_WORK(&object->sto_timer_work,
                   rna_service_timer_workq_callback,
                  &object->sto_timer_work);
#else
        INIT_WORK(&object->sto_timer_work,
                   rna_service_timer_workq_callback);
#endif
#else 
		/* WINDOWS KERNEL*/
        RNA_INIT_WORK(&object->sto_timer_work,
                   rna_service_timer_workq_callback,
                  &object->sto_timer_work);


#endif 
        rna_queue_work(object->sto_timer_ctx->kcx_timer_workq,
                  &object->sto_timer_work);
    }
}

INLINE void
rna_service_timer_cancel(rna_service_timer_object_t *timer_object)
{
    rna_stop_timer(&timer_object->sto_timer);
}

INLINE void
rna_service_timer_final_cancel(rna_service_timer_object_t *timer_object)
{
    rna_final_cancel_timer(&timer_object->sto_timer);
}

/**
 * Set a timer.  The callback function 'timer_callback' will be called with the
 * parameter 'timer_callback_parameter' in 'timeout_sec' seconds.
 *
 * @param ctx    Service context of timer object
 * @param timer_object    The timer object to be used
 * @param  timer_callback    Callback to be invoked after timeout_sec seconds
 * @param timer_callback_param    Parameter that will be passed to timer_callback
 * @param timeout_sec    Number of seconds until the timeout elapses
 */
#if defined(WINDOWS_KERNEL)
#pragma warning(push)
#pragma warning(disable:4054)   /* "type cast from function to data" */
#endif  /* WINDOWS_KERNEL */
INLINE void
rna_service_timer_set(void                       *timer_ctx,
                      rna_service_timer_object_t *timer_object,
                      rna_service_timer_callback  timer_callback,
                      uint64_t                    timer_callback_parameter,
                      int                         timeout_sec)
{
    rna_service_kernel_context_t * ctx =
        (rna_service_kernel_context_t *)timer_ctx;

    BUG_ON(NULL == ctx);
    BUG_ON(NULL == timer_object);

    timer_object->sto_timer_callback = timer_callback;
    timer_object->sto_timer_callback_parameter = timer_callback_parameter;
    timer_object->sto_timer_ctx = ctx;

    if (ctx->kcx_shutting_down) {
        return;
    } else if (0 == timeout_sec) {
        /*
         * rna_set_timeout() doesn't deal well with a zero timeout.  Cut to
         * the chase and invoke the timer callback directly.
         */
        rna_service_timer_callback_wrapper((uint64_t)timer_object);
    } else {
        rna_set_timeout(&timer_object->sto_timer,
                        timeout_sec * 1000,  // timeout in msec
                        (void *)&rna_service_timer_callback_wrapper,
                        (void *)timer_object);
    }
}
#if defined(WINDOWS_KERNEL)
#pragma warning(pop)
#endif  /* WINDOWS_KERNEL */

#define rna_service_print_timer_debug print_timer_debug

/* --------------------------------- Com ---------------------------------- */

#define rna_service_com_set_priv_data       com_set_priv_data
#define rna_service_com_disconnect_all_eps  com_disconnect_all_eps
#define rna_service_com_exit                com_exit

typedef struct buf_entry rna_service_send_buf_entry_t;

#ifdef WINDOWS_KERNEL
INLINE uint32_t htonl(uint32_t v)
{
    /* MSDN points to this as a kernel-friendly alternative to htonl() */
    return RtlUlongByteSwap(v);
}
INLINE uint16_t htons(uint16_t v)
{
    /* MSDN points to this as a kernel-friendly alternative to htons() */
    return RtlUshortByteSwap(v);
}
#endif  /* WINDOWS_KERNEL */


INLINE void *
rna_service_com_ep_get_priv_data(com_ep_handle_t *eph)
{
    return ((eph != NULL) ? com_ep_get_priv_data(eph->eph_ep) : NULL);
}

/*
 * The infinite_timeouts attribute doesn't currently exist at the kernel level.
 */
INLINE int
rna_service_com_set_infinite_timeouts_attr(int ignored DECLARE_UNUSED)
{
    UNREFERENCED_PARAMETER(ignored);
    return (0);
}

INLINE int
rna_service_com_disconnect(com_ep_handle_t *eph)
{
    struct com_ep *ep;

    if (NULL == eph) {
        return (0); // not connected
    }

    ep = eph->eph_ep;
    if (NULL == ep) {
        return (0); // already disconnected
    }

    return (com_disconnect(ep));
}

INLINE int
rna_service_com_connected(com_ep_handle_t *eph)
{
    struct com_ep *ep;

    if (NULL == eph) {
        return (0); // not connected
    }

    ep = eph->eph_ep;
    if (NULL == ep) {
        return (0); // not connected
    } else {
        return (com_connected(ep));
    }
}

INLINE int
rna_service_com_get_send_buf(com_ep_handle_t *eph,
                             rna_service_send_buf_entry_t **buf,
                             int blocking,
                             void *context)
{
    int countdown = 100;
    int ret;
    struct com_ep *ep;

    if (NULL == eph) {
        *buf = NULL;
        return (1);
    }

    ep = eph->eph_ep;
    if (NULL == ep) {
        *buf = NULL;
        return (1);
    }

    if (0 == blocking) {
        ret = com_get_send_buf(ep, buf, blocking);
    } else {
        /*
         * Continue trying to get a sendbuf until we either succeed or lose
         * the connection.
         */
        do {
            ret = com_get_send_buf(ep, buf, blocking);
            if ((ret != 0) && (rna_service_com_connected(eph))) {
                rna_dbg_log(RNA_DBG_WARN,
                            "Failed com_get_send_buf: "
                            "ret %d buf %p connected %d countdown %d\n",
                            ret, *buf,
                            rna_service_com_connected(eph), countdown);
            }
        } while (((ret != 0) || (NULL == *buf))
          && (rna_service_com_connected(eph))
          && (--countdown > 0));  // don't loop forever
        /*
         * If repeated blocking attempts to get a sendbuf failed, disconnect
         * this obviously ill ep.
         */
        if (((ret != 0) || (NULL == *buf))
          && (rna_service_com_connected(eph))) {
            rna_service_com_disconnect(eph);
            rna_dbg_log(RNA_DBG_WARN,
                        "Disconnecting ep after repeated blocking failures "
                        "to get a sendbuf\n");
        }
    }
    if (unlikely((NULL == *buf) &&
                 (0 == ret))) {
        ret = -EAGAIN;
    } else if (0 == ret) {
        com_set_send_buf_context(*buf, context);
    }
    return (ret);
}

INLINE int
rna_service_com_put_send_buf (com_ep_handle_t *eph,
                              rna_service_send_buf_entry_t *buf)
{
    struct com_ep *ep;

    if (NULL == eph) {
        return (0);
    }

    ep = eph->eph_ep;
    if (NULL == ep) {
        return (0);
    }

    return (com_put_send_buf(ep, buf));
}


INLINE int
rna_service_com_send(com_ep_handle_t *eph, 
                     rna_service_send_buf_entry_t *buf,
                     int size)
{
    return (com_send(eph->eph_ep, buf, size));
}


/* TODO: transports is presently ignored */
INLINE struct rna_com *
rna_service_com_init(int transports, void * priv_data)
{
    struct rna_com      *com_handle = NULL;
    struct rna_com_attrs com_attrs;
#ifdef WINDOWS_KERNEL
#ifdef WINDOWS_RNA_SERVICE_TEST_DRIVER_ONLY
    NTSTATUS dwStatus;
#endif /*#ifdef WINDOWS_RNA_SERVICE_TEST_DRIVER_ONLY */
#endif /*WINDOWS_KERNEL */

    /* These are currently only defined in kernel space,
     * otherwise, we'd move this out to the caller. */
    transports = IB_TRANSPORT | TCP_TRANSPORT;

    // XXX: these need to be configurable
    com_attrs.comp_mode = COM_COMP_MODE_WORKQ_CB;
    com_attrs.retry_count = 6;
    com_attrs.rnr_retry_count = 6;
#ifdef LINUX_KERNEL
    com_handle = com_init_all(transports, &com_attrs, RNA_PROTOCOL_MIN_VERSION, RNA_PROTOCOL_VERSION); 
#else

#ifdef WINDOWS_RNA_SERVICE_TEST_DRIVER_ONLY
    dwStatus = RnaTest_Service_Init_Com();

    com_attrs.comp_mode = COM_COMP_MODE_IRQ;
#endif /* WINDOWS_RNA_SERVICE_TEST_DRIVER_ONLY */

    com_handle = RnaTest_Service_Com_Init_Ex( &com_attrs, RNA_PROTOCOL_MIN_VERSION, RNA_PROTOCOL_VERSION );
     
    
#endif /*LINUX vs WINDOWS KERNEL */

    if (NULL != com_handle) {
        com_set_priv_data(com_handle, priv_data);
    }

    return (com_handle);
}


/*
 * Note that this function may have to change in the future, since
 * system_utsname may be removed in newer kernels.  If so, replace with
 * init_utsname()->nodename.
 */
#ifdef LINUX_KERNEL

INLINE int
rna_service_gethostname(char *name, size_t len)
{
    struct new_utsname *uts_name;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,20)
    uts_name = &system_utsname;
#else
    uts_name = utsname();
#endif

    strncpy(name, uts_name->nodename, len);
    return (0);
}

#else

#define DEFAULT_NODE_DESC	"Fluidcache junk hostname"


INLINE int
rna_service_gethostname(char *name, size_t len)
{
    NTSTATUS status = STATUS_SUCCESS;
    /* Remember the terminating entry in the table below. */
    RTL_QUERY_REGISTRY_TABLE table[2] = {0};
    UNICODE_STRING hostNamePath;        /* argument */
    UNICODE_STRING hostNameW;           /* returned string */

    /* Get the host name. */
    RtlInitUnicodeString(&hostNamePath, L"ComputerName\\ComputerName");
    RtlInitUnicodeString(&hostNameW, NULL);


    /* Setup the table entries. */
    table[0].Flags = RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_REQUIRED;
    table[0].Name = L"ComputerName";
    table[0].EntryContext = &hostNameW;
    table[0].DefaultType = REG_SZ;
    table[0].DefaultData = &hostNameW;
    table[0].DefaultLength = 0;
    /* Have at it! */
    status = RtlQueryRegistryValues(RTL_REGISTRY_CONTROL,
                                    hostNamePath.Buffer, table, NULL, NULL);
    if (NT_SUCCESS(status)) {       /* if we got the value from the registry */
        /* Convert the UNICODE host name to UTF-8 (ASCII). */
        ANSI_STRING hostNameA;

        hostNameA.Length = 0;
        hostNameA.MaximumLength = (USHORT) len;
        hostNameA.Buffer = name;
        memset((void *) name, 0, len);  /* paranoia */
        status = RtlUnicodeStringToAnsiString(&hostNameA, &hostNameW, FALSE);
        RtlFreeUnicodeString(&hostNameW);
    } 
    if ( !NT_SUCCESS(status) ) {    /* failed registry read or failed copy */
        rna_dbg_log(RNA_DBG_ERR, "Failed to get host name.\n");
        (void) RtlStringCbCopyA(name, len, DEFAULT_NODE_DESC);  /* copy default */
    }

    return(0);    
}

#endif /* Linux_Kernel */

/**
 * rna_service_com_get_transport_type() is currently a no-op at the kernel
 * level, since com_get_transport_type isn't implemented in the kernel com.
 * Instead, we rely on the interface type in interface tables and we specify
 * the CFM's transport type when we create the service instance.
 */
INLINE int
rna_service_com_get_transport_type(
                        struct rna_com     *com_handle DECLARE_UNUSED,
                        struct sockaddr_in *dst_addr   DECLARE_UNUSED)
{
    UNREFERENCED_PARAMETER(com_handle);
    UNREFERENCED_PARAMETER(dst_addr);
    return (-1);
}

/**
 * rna_service_com_set_keep_alive_attributes() is a no-op at the kernel
 * level.  The keep alive attributes are handled in the rna_com_tcp module.
 */
INLINE void
rna_service_com_set_keep_alive_attributes(struct com_attr *attr DECLARE_UNUSED,
                    int keep_alive_count DECLARE_UNUSED,
                    int keep_alive_wait DECLARE_UNUSED,
                    int keep_alive_interval DECLARE_UNUSED)
{
    UNREFERENCED_PARAMETER(attr);
    UNREFERENCED_PARAMETER(keep_alive_count);
    UNREFERENCED_PARAMETER(keep_alive_wait);
    UNREFERENCED_PARAMETER(keep_alive_interval);
    return;
}

/**
 * rna_service_com_set_tcp_nodelay_attr() is a no-op at the kernel
 * level.  The tcp_nodelay attribute is handled in the rna_com_tcp module.
 */
INLINE void
rna_service_com_set_tcp_nodelay_attr(struct com_attr *attr DECLARE_UNUSED,
                    int ignored DECLARE_UNUSED)
{
    UNREFERENCED_PARAMETER(attr);
    UNREFERENCED_PARAMETER(ignored);
    return;
}

INLINE uint64_t
rna_service_getpid(void)
{
#ifdef WINDOWS_KERNEL    
    /* PsGetCurrentProcessId returns a handle, just cast to a 
     * 64-bit val since used in debugging */
    return ((uint64_t) PsGetCurrentProcessId() );

#else
    return ((uint64_t)current->pid);
#endif
}


INLINE int
rna_service_com_alloc_ep(struct rna_com  *com_handle,
                         struct com_attr *com_attr,
                         enum com_type    type,
                         int              num_send,
                         int              num_recv,
                         int              buf_size,
                         int              num_rdma,
                         int              rdma_size,
                         char             user_type,
                         uint8_t          sync_recvq_flag,
                         int              bounce_buffer_bytes,
                         int              bounce_segment_bytes,
                         com_ep_handle_t *new_eph)
{
    struct com_ep *new_ep = NULL;
    int ret;

    com_init_eph(new_eph);
    ret = com_alloc_ep(com_handle,
                       com_attr,
                       type,
                        NULL,
                       NULL,
                       num_send,
                       num_recv,
                       buf_size,
                       num_rdma,
                       rdma_size,
                       user_type,
					   sync_recvq_flag,
                       bounce_buffer_bytes,
                       bounce_segment_bytes,
                       &new_ep);
    if (0 == ret) {
        /* successfully allocated an ep; translate it into an ep handle */
        create_eph(new_ep, new_eph);
    }
    return (ret);
}



typedef struct rdma_buf rna_service_rdma_info_t;


/*
 * If the specified buffer isn't yet registered for RDMA, register it.
 * In any case, get its RDMA information, returning its rkey and filling
 * in its rna_service_rdma_info_t.
 */
INLINE int
rna_service_com_get_rdma_info(/* INPUT PARAMETERS: */
                              struct rna_com *com_handle,
                              com_ep_handle_t *eph,
                              void *buffer,
                              uint32_t buflen,
                              /* OUTPUT PARAMETERS: */
                              rna_rkey_t *rkey,
                              rna_service_rdma_info_t *rdma_info)
{
    int ret = 0;

    UNREFERENCED_PARAMETER(com_handle);

    rdma_info->rdma_mem = buffer;
    rdma_info->size = buflen;
    if (!com_isreg(eph->eph_ep, rdma_info)) {
        rdma_info->mr = NULL;
        rdma_info->rdma_mem_dma = 0;
        rdma_info->ib_device = NULL;
#ifdef LINUX_KERNEL
        ret = com_reg_single(eph->eph_ep, rdma_info, DMA_FROM_DEVICE);
#else
        #pragma message(" Need to hook up com_reg_single and define DMA_FROM_DEVICE")
#endif
        if (0 != ret) {
            return (ret);
        }
    }
    *rkey = com_get_rkey(eph->eph_ep, rdma_info);
    return (0);
}


/*
 * If the specified buffer is registered for DMA, de-register it.
 */
INLINE int
rna_service_com_deregister_rdma_buffer(struct rna_com *com_handle
                                                       DECLARE_UNUSED,
                                       com_ep_handle_t *eph,
                                       rna_service_rdma_info_t *rdma_info)
{
    UNREFERENCED_PARAMETER(com_handle);
    if ((NULL != eph)
      && (NULL != eph->eph_ep)
      && (com_isreg(eph->eph_ep, rdma_info))) {
        com_dereg_single(eph->eph_ep, rdma_info);
    }
    return (0);
}

typedef int RNA_SERVICE_CONNECT_CB_T (com_ep_handle_t *eph, void *ep_ctx);
typedef RNA_SERVICE_CONNECT_CB_T *RNA_SERVICE_CONNECT_CB;
typedef int RNA_SERVICE_DISCONNECT_CB_T (com_ep_handle_t *eph, void *ep_ctx);
typedef RNA_SERVICE_DISCONNECT_CB_T *RNA_SERVICE_DISCONNECT_CB;
typedef int RNA_SERVICE_RECV_CMP_CB_T (com_ep_handle_t *eph, void *ep_ctx,
                                           void *data, int len, int status);
typedef RNA_SERVICE_RECV_CMP_CB_T *RNA_SERVICE_RECV_CMP_CB;
typedef int RNA_SERVICE_ACCEPT_CB_T (com_ep_handle_t *eph,
                                           int private_data);
typedef RNA_SERVICE_ACCEPT_CB_T *RNA_SERVICE_ACCEPT_CB;
typedef int RNA_SERVICE_RDMA_READ_CMP_CB_T (com_ep_handle_t *eph,
                                           struct buf_entry *rdma_buf, int status);
typedef RNA_SERVICE_RDMA_READ_CMP_CB_T *RNA_SERVICE_RDMA_READ_CMP_CB;


typedef struct {
    RNA_SERVICE_CONNECT_CB       ca_connect_cb;
    RNA_SERVICE_DISCONNECT_CB    ca_disconnect_cb;
    RNA_SERVICE_RECV_CMP_CB      ca_recv_completion_cb;
    RNA_SERVICE_RDMA_READ_CMP_CB ca_rdma_read_completion_cb;
} rna_service_com_attr_t ;

extern rna_service_com_attr_t rna_service_com_attr;


static int
connect_cb_wrapper(struct com_ep *ep, void *ep_ctx)
{
    com_ep_handle_t eph;

    create_eph(ep, &eph);
    return (rna_service_com_attr.ca_connect_cb(&eph, ep_ctx));
}

static int
disconnect_cb_wrapper(struct com_ep *ep, void *ep_ctx)
{
    com_ep_handle_t eph;

    create_eph(ep, &eph);
    return (rna_service_com_attr.ca_disconnect_cb(&eph, ep_ctx));
}

static int
recv_completion_cb_wrapper(struct com_ep *ep,
                           void *ep_ctx,
                           void *data,
                           int len,
                           int status)
{
    com_ep_handle_t eph;

    create_eph(ep, &eph);
    return (rna_service_com_attr.ca_recv_completion_cb(&eph,
                                                        ep_ctx,
                                                        data,
                                                        len,
                                                        status));
}

static int
rdma_read_completion_cb_wrapper(struct com_ep *ep,
                                void          *ep_ctx,
                                void          *app_ctx,
                                int            status)
{
    com_ep_handle_t eph;

    UNREFERENCED_PARAMETER(ep_ctx);
    create_eph(ep, &eph);
    return (rna_service_com_attr.ca_rdma_read_completion_cb(&eph, app_ctx, status));
}


INLINE void
rna_service_com_attr_init(struct com_attr *attr,
                          RNA_SERVICE_ACCEPT_CB accept_cb
                                DECLARE_UNUSED,  // user-level only
                          RNA_SERVICE_CONNECT_CB connect_cb,
                          RNA_SERVICE_DISCONNECT_CB disconnect_cb,
                          RNA_SERVICE_RECV_CMP_CB recv_completion_cb,
                          RNA_SERVICE_RDMA_READ_CMP_CB rdma_read_completion_cb)
{
    UNREFERENCED_PARAMETER(accept_cb);
    memset(&rna_service_com_attr, 0, sizeof(rna_service_com_attr_t));
    rna_service_com_attr.ca_connect_cb = connect_cb;
    rna_service_com_attr.ca_disconnect_cb = disconnect_cb;
    rna_service_com_attr.ca_recv_completion_cb = recv_completion_cb;
    rna_service_com_attr.ca_rdma_read_completion_cb = rdma_read_completion_cb;

    memset(attr, 0, sizeof(*attr));
    attr->connect_cb = connect_cb_wrapper;
    attr->disconnect_cb = disconnect_cb_wrapper;
    attr->recv_cmp_cb = recv_completion_cb_wrapper;
    attr->rdma_read_cmp_cb = rdma_read_completion_cb_wrapper;
}

INLINE int
rna_service_com_connect_sync(com_ep_handle_t *eph,
                             struct sockaddr *dst_addr,
                             int timeout)
{
    int ret;

    com_inc_ref_ep(eph->eph_ep);
    ret = com_connect_sync(eph->eph_ep, (rna_sockaddr_t *)dst_addr, timeout);
    if (0 == ret) {
#ifdef WINDOWS_KERNEL
        com_get_ep_dst_in_ex(eph->eph_ep, &eph->eph_dst_in, sizeof(*dst_addr) );           
#else
        eph->eph_dst_in = eph->eph_ep->dst_in;
#endif /* WINDOWS_KERNEL */
    }
    com_release_ep(eph->eph_ep);
    return (ret);
}

/*
 * This function isn't yet implemented at the kernel level.
 */
INLINE void
rna_service_com_dump_md_ep_info_xml(void *eph DECLARE_UNUSED,
                                    void *service_id_p DECLARE_UNUSED,
                                    void *info_file  DECLARE_UNUSED)
{
    UNREFERENCED_PARAMETER(eph);
    UNREFERENCED_PARAMETER(service_id_p);
    UNREFERENCED_PARAMETER(info_file);
}

/*
 * This function isn't yet implemented at the kernel level.
 */
INLINE int
rna_service_com_dump_all_ep_info_xml(void *com_handle DECLARE_UNUSED,
                                     void *com_context DECLARE_UNUSED,
                                     void *info_file  DECLARE_UNUSED)
{
    UNREFERENCED_PARAMETER(com_handle);
    UNREFERENCED_PARAMETER(com_context);
    UNREFERENCED_PARAMETER(info_file);
    return (0);
}

/*
 * This function isn't yet implemented at the kernel level.
 */
INLINE int
rna_service_com_dump_all_ep_info(void *com_handle DECLARE_UNUSED,
                                 void *info_file  DECLARE_UNUSED)
{
    UNREFERENCED_PARAMETER(com_handle);
    UNREFERENCED_PARAMETER(info_file);
    return (0);
}

/* --------------------------- Private Data ------------------------------- */

INLINE void
rna_service_ctx_private_data_init (void ** cx_private)
{
    rna_service_kernel_context_t * kernel_context = NULL;

#ifdef LINUX_KERNEL
    BUG_ON(in_atomic());
#endif

    BUG_ON(NULL == cx_private);

    kernel_context = rna_service_alloc(sizeof(*kernel_context));
    BUG_ON(NULL == kernel_context);

    kernel_context->kcx_shutting_down = FALSE;

    /* using GPL-only workqueue function */
    kernel_context->kcx_timer_workq = rna_create_workqueue("fldc_serv_timers");

    BUG_ON(NULL == kernel_context->kcx_timer_workq);

    *cx_private = kernel_context;

}

#define CACHE_CONNECT_TIMEOUT   5000 /* in msec */

INLINE void
rna_service_ctx_private_data_free (void * cx_private)
{
    rna_service_kernel_context_t * kernel_context =
        (rna_service_kernel_context_t *)cx_private;

    BUG_ON(NULL == kernel_context);

    BUG_ON(NULL == kernel_context->kcx_timer_workq);

    kernel_context->kcx_shutting_down = TRUE;

    rna_flush_workqueue(kernel_context->kcx_timer_workq);
    rna_destroy_workqueue(kernel_context->kcx_timer_workq);
}

INLINE void
rna_service_ctx_private_data_shutting_down (void * cx_private)
{
    rna_service_kernel_context_t * kernel_context =
        (rna_service_kernel_context_t *)cx_private;

    BUG_ON(NULL == kernel_context);

    kernel_context->kcx_shutting_down = TRUE;
}

/* ------------------------- Exported Symbols ----------------------------- */
#ifdef LINUX_KERNEL

EXPORT_SYMBOL(rna_service_ctx_create);
EXPORT_SYMBOL(rna_service_ctx_destroy);
EXPORT_SYMBOL(rna_service_alloc_message_buffer);
EXPORT_SYMBOL(rna_service_free_message_buffer);
EXPORT_SYMBOL(rna_service_send_md);
EXPORT_SYMBOL(rna_service_send_mount_registration);
EXPORT_SYMBOL(rna_service_send_mount_deregistration);
EXPORT_SYMBOL(rna_service_get_error_string);
EXPORT_SYMBOL(get_cache_req_type_string);
EXPORT_SYMBOL(get_lock_type_string);
EXPORT_SYMBOL(get_write_mode_string);
EXPORT_SYMBOL(get_cache_commit_mode_string);
EXPORT_SYMBOL(get_cache_invd_mode_string);
EXPORT_SYMBOL(get_cache_error_persistence_string);
EXPORT_SYMBOL(get_cache_evict_policy_string);
EXPORT_SYMBOL(rna_service_get_message_type_string);
EXPORT_SYMBOL(rna_service_send_client_event);
EXPORT_SYMBOL(rna_service_convert_md_rep_to_cache_query);
EXPORT_SYMBOL(rna_service_sprintf_connection_status);
EXPORT_SYMBOL(rna_service_get_event_type_string);
EXPORT_SYMBOL(rna_service_send_block_device_registration);
EXPORT_SYMBOL(rna_service_send_block_device_stats);
EXPORT_SYMBOL(rna_service_parse_ip_addr);
EXPORT_SYMBOL(rna_service_send_block_device_deregistration);
EXPORT_SYMBOL(rna_service_send_notification_event);
EXPORT_SYMBOL(rna_service_send_block_device_control_response);
EXPORT_SYMBOL(rna_service_send_svc_conn_registration);
EXPORT_SYMBOL(rna_service_send_svc_conn_deregistration);
EXPORT_SYMBOL(rna_service_send_oms_event_to_cfm);
EXPORT_SYMBOL(rna_service_mempool_init);
EXPORT_SYMBOL(rna_service_mempool_destroy);
EXPORT_SYMBOL(rna_service_mempool_alloc);
EXPORT_SYMBOL(rna_service_mempool_alloc_timed);
EXPORT_SYMBOL(rna_service_mempool_free);
EXPORT_SYMBOL(rna_service_throttle_init);
EXPORT_SYMBOL(rna_service_throttle_destroy);
EXPORT_SYMBOL(rna_service_throttle_register);
EXPORT_SYMBOL(rna_service_throttle_deregister);
EXPORT_SYMBOL(rna_service_throttle_change_limit);
EXPORT_SYMBOL(rna_service_cfms_update);

/* ------------------------ Module Registration ---------------------------- */

MODULE_AUTHOR("Dell Inc");
MODULE_LICENSE("GPL");

#endif /* LINUX_KERNEL */


/* ------------------------- Cache Server Support ------------------------- 
 * (NOTE that these are all no-ops, since cache servers aren't supported
 * at the kernel level)
 */

INLINE int
RNA_SERVICE_METADATA_RID_TO_PARTITION(uint64_t rid)
{
    UNREFERENCED_PARAMETER(rid);
    rna_dbg_log(RNA_DBG_ERR,
                "METADATA_RID_TO_PARTITION is not yet supported at kernel "
                "level!\n");
    return (0);
}


INLINE int
rna_service_send_service_connection_info(
                    com_ep_handle_t       *primary_cfm DECLARE_UNUSED,
                    struct rna_service_id *service_id  DECLARE_UNUSED,
                    com_ep_handle_t       *service_eph DECLARE_UNUSED,
                    int                    ordinal     DECLARE_UNUSED)
{
    UNREFERENCED_PARAMETER(primary_cfm);
    UNREFERENCED_PARAMETER(service_id);
    UNREFERENCED_PARAMETER(service_eph);
    UNREFERENCED_PARAMETER(ordinal);
    rna_dbg_log(RNA_DBG_ERR,
                "not yet supported at kernel level!\n");
    return (0);
}

INLINE int
rna_service_send_service_disconnection_info(
                    com_ep_handle_t       *eph        DECLARE_UNUSED,
                    struct rna_service_id *service_id DECLARE_UNUSED,
                    unsigned int           ordinal    DECLARE_UNUSED,
                    uint64_t               cs_memb_gen_num
                                                      DECLARE_UNUSED)
{
    UNREFERENCED_PARAMETER(eph);
    UNREFERENCED_PARAMETER(service_id);
    UNREFERENCED_PARAMETER(ordinal);
    UNREFERENCED_PARAMETER(cs_memb_gen_num);
    rna_dbg_log(RNA_DBG_ERR,
                "not yet supported at kernel level!\n");
    return (0);
}


typedef int rna_service_ping_context_t;
typedef int rna_service_ping_data_t;


INLINE int
rna_service_ping_local_ctx_init(
            com_ep_handle_t            *eph            DECLARE_UNUSED,
            rna_service_ping_context_t *ping_ctx       DECLARE_UNUSED,
            void                       *ping_data      DECLARE_UNUSED,
            size_t                      ping_data_size DECLARE_UNUSED,
            rna_addr_t                 *ping_buf       DECLARE_UNUSED,
            rna_rkey_t                 *ping_rkey      DECLARE_UNUSED)
{
    rna_dbg_log(RNA_DBG_ERR,
                "rdma ping is not yet supported at kernel level!\n");
    return (0);
}


INLINE void
rna_service_ping_remote_ctx_init(
            com_ep_handle_t            *eph            DECLARE_UNUSED,
            rna_service_ping_context_t *ping_ctx       DECLARE_UNUSED,
            void                       *ping_data      DECLARE_UNUSED,
            size_t                      ping_data_size DECLARE_UNUSED,
            struct cache_cmd           *cmd            DECLARE_UNUSED)
{
    rna_dbg_log(RNA_DBG_ERR,
                "rdma ping is not yet supported at kernel level!\n");
}


INLINE int
rna_service_ping_local_context_deregister(
                rna_service_ping_context_t *ping_ctx DECLARE_UNUSED)
{
    rna_dbg_log(RNA_DBG_ERR,
                "rdma ping is not yet supported at kernel level!\n");
    return (0);
}

INLINE int
rna_service_ping_remote_context_deregister(
                rna_service_ping_context_t *ping_ctx DECLARE_UNUSED)
{
    rna_dbg_log(RNA_DBG_ERR,
                "rdma ping is not yet supported at kernel level!\n");
    return (0);
}


INLINE int
rna_service_ping_rdma(
                rna_service_ping_context_t *ping_ctx DECLARE_UNUSED)
{
    rna_dbg_log(RNA_DBG_ERR,
                "rna_service_ping_rdma is not yet supported at kernel "
                "level!\n" );
    return (0);
}


INLINE boolean
rna_service_md_has_remote_ping_rkey(
                rna_service_ping_context_t *ping_ctx DECLARE_UNUSED)
{
    rna_dbg_log(RNA_DBG_ERR,
                "rdma ping is not yet supported at kernel level!\n");
    return (FALSE);
}

INLINE int
rna_service_conf_lib_process_recv(com_ep_handle_t *eph  DECLARE_UNUSED,
                                  struct cfm_cmd  *cmd DECLARE_UNUSED)
{
    rna_dbg_log(RNA_DBG_ERR,
                "not yet supported at kernel level!\n");
    return (0);
}


#define rna_service_thread_t    void *


INLINE rna_service_thread_t
rna_service_fifo_thread_create(int  priority         DECLARE_UNUSED,
                               void (*func) (void *) DECLARE_UNUSED,
                               void *context         DECLARE_UNUSED)
{
    rna_dbg_log(RNA_DBG_ERR,
                "rna_service_fifo_thread_create is not yet supported at "
                "kernel level!\n");
    return (NULL);
}


INLINE void
rna_service_util_thread_cancel(
                          rna_service_thread_t thread DECLARE_UNUSED)
{
    rna_dbg_log(RNA_DBG_ERR,
                "rna_service_util_thread_cancel is not yet supported at "
                "kernel level!\n");
}


INLINE size_t
histogram_copy_and_truncate(void *dest,
                            size_t dest_bufsize,
                            int dest_buckets,
                            void *src)
{
    rna_dbg_log(RNA_DBG_ERR,
                "histogram_copy_and_truncate is not yet supported at "
                "kernel level!\n");
    return (0);
}


INLINE uint32_t
rna_service_time(void *ignored DECLARE_UNUSED)
{
    rna_dbg_log(RNA_DBG_ERR,
                "rna_service_time is not yet supported at kernel level!\n");
    return (0);
}


INLINE int
agent_announce_mount_action(com_ep_handle_t *eph DECLARE_UNUSED,
                            int              action DECLARE_UNUSED)
{
    rna_dbg_log(RNA_DBG_ERR,
                "is not yet supported at kernel level!\n");
    return (1);
}


/*
 * Process a ping of this cache server by a metadata server.
 */
INLINE void
rna_service_process_md_ping_read(
        rna_service_ping_context_t *remote_ping_ctx   DECLARE_UNUSED)
{
    rna_dbg_log(RNA_DBG_ERR,
                "is not yet supported at kernel level!\n");
}


INLINE int
rna_service_com_put_rdma_buf(com_ep_handle_t *eph       DECLARE_UNUSED,
                             void            *rdma_buf DECLARE_UNUSED)
{
    rna_dbg_log(RNA_DBG_ERR,
                "is not yet supported at kernel level!\n");
    return (1);
}

/*
 * Code called by process_cfm_cmd for a command only sent
 * to cache servers.
 */
INLINE int
rna_create_wwn_strings(const rna_store_wwn_t *rna_wwn,
                       char **id_str_p,
                       char **id_type_str_p,
                       char **id_code_set_str_p,
                       char **err_str_p)
{
    if (id_str_p) {
        *id_str_p = NULL;
    }
    if (id_type_str_p) {
        *id_type_str_p = NULL;
    }
    if (id_code_set_str_p) {
        *id_code_set_str_p = NULL;
    }
    if (id_code_set_str_p) {
        *id_code_set_str_p = NULL;
    }
    if (err_str_p) {
        *err_str_p = NULL;
    }
    return 0;
}

/* ------------------------- Wait Objects  ------------------------- */


INLINE void 
rna_service_init_wait_obj(rna_service_wait_obj *obj) 
{
#ifdef WINDOWS_KERNEL
    /* Create event in a non-signaled state */
    KeInitializeEvent(obj, NotificationEvent, FALSE);
#else
    init_waitqueue_head(obj);
#endif /* WINDOWS_KERNEL */
}


/*
 * Note caller is assumed to have already checked conditions that
 * indicate this thread needs to block.  Thus here we always block
 * unconditionally up front.  We'll check 'condition' before
 * possible subsequent sleeps.
 * (The reason for this approach is to support the case where the
 * initial condition the caller checked for may be different than the
 * one passed in here).
 */
#ifdef WINDOWS_KERNEL

#define __rna_wait_event_timeout(wq, slock, flags_p, condition, ret)        \
{                                                                           \
    LARGE_INTEGER v;                                                        \
    LARGE_INTEGER tickStart;                                                \
    LARGE_INTEGER tickNow;                                                  \
    int64_t timeoutTicks;                                                   \
    /* Ensure we will wait, since we already decided we need to. */         \
    KeClearEvent(&wq);                                                      \
    rna_service_spinlock_release(slock, flags_p);                           \
                                                                            \
    /* Granularity of MSFT timer is 100ns per unit.                         \
     * One millisecond is equivalent to 10000 system units.                 \
     *                                                                      \
     * Interval needs be negative to indicate relative to current           \
     * system time else you get absolute time since Jan 1, 1601...          \
     * not what we want.                                                    \
     *		                                                                \
     * Timeout value (ret) gets passed in as jiffies.                       \
     * For Windows we are equating one jiffy to a clock tick,               \
     * which on current hardware is ~15.6 ms.                               \
     */                                                                     \
                                                                            \
    /* Delay thread execution */                                            \
    /* Remember total max time (in ticks) we want to wait. */               \
    timeoutTicks = ret;                                                     \
    v.QuadPart = jiffies_to_msecs(ret) * (LONGLONG)(-10000);                \
    KeQueryTickCount(&tickStart);                                           \
    KeWaitForSingleObject(&wq, Executive, KernelMode, FALSE, &v);           \
    KeQueryTickCount(&tickNow);                                             \
    /* Adjust wait timeout for next time. */                                \
    ret = timeoutTicks - (tickNow.QuadPart - tickStart.QuadPart);           \
    /* Elapsed ticks could be slightly more than timeout we set. */         \
    /* Negative value of ret is treated as error by caller so set to 0. */  \
    if (ret < 0) {                                                          \
        ret = 0;                                                            \
    }                                                                       \
                                                                            \
    if (!rna_service_spinlock_acquire(slock, flags_p)) {                    \
        ret = -EPERM;                                                       \
    }                                                                       \
                                                                            \
    while (ret > 0) {                                                       \
        if (condition) {                                                    \
            break;                                                          \
        }                                                                   \
        /* If the condition is NOT met then pause execution */              \
        KeClearEvent(&wq);                                                  \
        rna_service_spinlock_release(slock, flags_p);                       \
        /* Compute new timeout */                                           \
        v.QuadPart = jiffies_to_msecs(ret) * (LONGLONG)(-10000);            \
        KeWaitForSingleObject(&wq, Executive, KernelMode, FALSE, &v);       \
        KeQueryTickCount(&tickNow);                                         \
        ret = timeoutTicks - (tickNow.QuadPart - tickStart.QuadPart);       \
        if (ret < 0) {                                                      \
            ret = 0;                                                        \
        }                                                                   \
        if (!rna_service_spinlock_acquire(slock, flags_p)) {                \
            ret = -EPERM;                                                   \
        }                                                                   \
    }                                                                       \
}

#else

#define __rna_wait_event_timeout(wq, slock, flags_p, condition, ret)        \
do {                                                                        \
    DEFINE_WAIT(__wait);                                                    \
                                                                            \
    prepare_to_wait_exclusive(&wq, &__wait, TASK_UNINTERRUPTIBLE);          \
    rna_service_spinlock_release(slock, flags_p);                           \
    ret = schedule_timeout(ret);                                            \
                                                                            \
    if (!rna_service_spinlock_acquire(slock, flags_p)) {                    \
        ret = -EPERM;                                                       \
    }                                                                       \
                                                                            \
    while (ret > 0) {                                                       \
        prepare_to_wait_exclusive(&wq, &__wait, TASK_UNINTERRUPTIBLE);      \
        if (condition) {                                                    \
            break;                                                          \
        }                                                                   \
        rna_service_spinlock_release(slock, flags_p);                       \
        ret = schedule_timeout(ret);                                        \
        if (!rna_service_spinlock_acquire(slock, flags_p)) {                \
            ret = -EPERM;                                                   \
        }                                                                   \
    }                                                                       \
    finish_wait(&wq, &__wait);                                              \
} while (0)

#endif /* WINDOWS_KERNEL */


/*
 * rna_service_wait_obj_timed_wait
 *
 * NOTES:
 *  1) This needs to be a macro to avoid computation of conditional's value.
 */
#ifdef NOTDEF   /* can't do portable because of defered condition */
#define rna_service_wait_obj_timed_wait(wq_p, slock, flags_p, condition,    \
                                        timeout)                            \
{                                                                          \
    long __ret = (timeout);                                                 \
                                                                            \
    __rna_wait_event_timeout(*(wq_p), (slock), (flags_p), (condition), __ret);\
    __ret;                                                                  \
}
#endif  /* NOTDEF */


/* Windows kernel notes:  Orignally thought had to add 'SetEvent' to each'
 * place the conditional variables were touched.  But to replicate linux
 * behavior, not necessary.  Since Linux code sets "TASK_UNINTERRUPTIBLE"
 * then task won't be woken up until time expires.  As such, you can just 
 * keep waiting.  The below obj_wake_up is called where the variables used
 * in the conditions are actually touched, so this *should take care of 
 * waking up the Windows wait if it gets set early 
 */
INLINE void
rna_service_wait_obj_wake_up(rna_service_wait_obj *obj)
{
#ifdef WINDOWS_KERNEL
    KeSetEvent(obj, 0, FALSE);
#else
    wake_up(obj);
#endif /* WINDOWS_KERNEL */
}

#define rna_service_max(__rsm_a,__rsm_b) max(__rsm_a,__rsm_b)

#ifdef WINDOWS_KERNEL
#pragma warning(pop)    /* restore 4100: "unreferenced formal parameter" */
#endif  /* WINDOWS_KERNEL */

#endif  // _RNA_SERVICE_KERNEL_H_

/* vi: set expandtab sw=4 sts=4 tw=80: */
/* Emacs settings */
/*
 * Local Variables:
 * c-basic-offset: 4
 * c-file-offsets: ((substatement-open . 0))
 * tab-width: 4
 * End:
 */
