/**
 * <util.h> - Dell Fluid Cache block driver
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

#ifndef _UTIL_H_
#define _UTIL_H_

#include "platform.h"
#include "platform_threads.h"
#include "platform_network.h"
#include "platform_atomic.h"

#include "rna_common_logging.h"

#ifdef WINDOWS_KERNEL
#include <stdlib.h>
#include "queue.h"
#include "rna_types.h"
//#include "rna_service_kernel.h"
#endif

#if defined(LINUX_USER) || defined(WINDOWS_USER)

#include <glib.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include "queue.h"
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "rna_types.h"


#include <fcntl.h>


#ifdef _SYS_EVENTFD_H
#include <sys/eventfd.h>
#else
#define EFD_SEMAPHORE 1
#define EFD_CLOEXEC 02000000
#define EFD_NONBLOCK 04000
#endif

#if defined(LINUX_USER)
# include <netdb.h>
# include <sys/shm.h>
# include <sys/msg.h>
# include <sys/sem.h>
# include <sys/syscall.h>
# include <unistd.h>
# include <syslog.h>
# include <sys/resource.h>
#endif  /* LINUX_USER */


#define BITS_PER_BYTE                   (8)
#define BITS_PER_GULONG                 (sizeof(gulong) * BITS_PER_BYTE)
#define DIV_ROUND_UP(N, B)              (((N) + (B) - 1) / (B))
#define ROUND_UP(N, B)                  ((B) * DIV_ROUND_UP(N, B))

#define STRINGIZE(int) #int
#define RNA_VERSION_STR(rev_str, build_int) rev_str "." STRINGIZE(build_int)

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define __location__ __FILE__ ":" TOSTRING(__LINE__)

#ifndef FALSE
	// glib takes care of these
/* Moved to platform.h  	typedef unsigned char gboolean; */
	#define FALSE 0
	#define TRUE 1
#endif

#endif /* __KERNEL__ */

#if defined (WINDOWS_KERNEL)

#define DIV_ROUND_UP(N, B)              (((N) + (B) - 1) / (B))
#define ROUND_UP(N, B)                  ((B) * DIV_ROUND_UP(N, B))

#define STRINGIZE(int) #int
#define RNA_VERSION_STR(rev_str, build_int) rev_str "." STRINGIZE(build_int)

#endif /* WINDOWS_KERNEL */


 #if defined(LINUX_USER) || defined(WINDOWS_USER)

extern void rna_write_sockaddr_in_xml(FILE *fd, char *name, struct sockaddr_in *addr);

 /****  Queue items ****/

/* Not defined in redhat linux sys/queue.h */
#ifndef TAILQ_INSERT_BEFORE
#define TAILQ_INSERT_BEFORE(listelm, elm, field) do {			\
	(elm)->field.tqe_prev = (listelm)->field.tqe_prev;		\
	(elm)->field.tqe_next = (listelm);				\
	*(listelm)->field.tqe_prev = (elm);				\
	(listelm)->field.tqe_prev = &(elm)->field.tqe_next;		\
} while (0)
#endif

#ifndef TAILQ_FOREACH
#define TAILQ_FOREACH(var, head, field)                                 \
        for ((var) = ((head)->tqh_first);                               \
                (var);                                                  \
                (var) = ((var)->field.tqe_next))
#endif

#ifndef TAILQ_FOREACH_REVERSE
#define TAILQ_FOREACH_REVERSE(var, head, headname, field)               \
        for ((var) = (*(((struct headname *)((head)->tqh_last))->tqh_last));    \
                (var);                                                  \
                (var) = (*(((struct headname *)((var)->field.tqe_prev))->tqh_last)))
#endif

#ifndef TAILQ_EMPTY
#define TAILQ_EMPTY(head)               ((head)->tqh_first == NULL)
#endif

#ifndef TAILQ_FIRST
#define TAILQ_FIRST(head)               ((head)->tqh_first)
#endif

#ifndef TAILQ_NEXT
#define TAILQ_NEXT(elm, field)          ((elm)->field.tqe_next)
#endif

#ifndef TAILQ_LAST
#define	TAILQ_LAST(head, headname) \
	(*(((struct headname *)((head)->tqh_last))->tqh_last))
#endif

#ifndef TAILQ_PREV
#define TAILQ_PREV(elm, headname, field) \
	(*(((struct headname *)((elm)->field.tqe_prev))->tqh_last))
#endif

//#ifdef __powerpc__
//typedef struct { volatile int counter; } atomic_t;
//#else



//#endif
enum {
    WO_MAGIC_INITIALIZED = 0xDAD,
    WO_MAGIC_DESTROYED   = 0xADA
};

struct wait_obj {
    volatile unsigned char	wo_signaled;
    uint8_t                 wo_latch;
    int16_t  wo_cookie;     // for optional use between signaler and signalee
#ifdef _USE_WAIT_OBJ_MAGIC_NUMBER_
    atomic_t wo_magic;
#endif
};

#ifdef _USE_WAIT_OBJ_MAGIC_NUMBER_
#define rna_wait_obj_assert_initialized(WO)                             \
    rna_log_assert(WO_MAGIC_INITIALIZED == atomic_get(&(WO)->wo_magic))
#else
/* Nothing if we aren't using wo_magic */
#define rna_wait_obj_assert_initialized(WO)
#endif

/**
 * Statically initialize an RNA wait_obj.
 */
#ifdef _USE_WAIT_OBJ_MAGIC_NUMBER_
#define RNA_WAIT_OBJ_INITIALIZER {              \
    FALSE,                      /* signaled */  \
    FALSE,                      /* latch */     \
    0,                          /* wo_cookie */ \
    {WO_MAGIC_INITIALIZED}                      \
}
#else
#define RNA_WAIT_OBJ_INITIALIZER {              \
    FALSE,                      /* signaled */  \
    FALSE,                      /* latch */     \
    0                           /* wo_cookie */ \
}
#endif

/******** Work Queue ***********/
typedef int ( *rna_work_cb) (uint64_t ctx);
typedef gboolean (*rna_work_iter_cb)(uint64_t ctx, void *data);

struct rna_work_obj {
	TAILQ_ENTRY(rna_work_obj) entry;
	uint64_t			ctx;
	rna_work_cb			callback;
    uint64_t            queued_time;
};

struct rna_thread {
    pthread_t pthread_id;
    atomic_t  started;
};

typedef struct rna_thread * rna_thread_t;

struct rna_wq_thread {
    rna_thread_t                wqt_thread;
    struct rna_work_queue       *wqt_queue;
};

typedef struct rna_wq_thread * rna_wq_thread_t;

/*
 * A flag to indicate that work objects belonging to this queue shouldn't be
 * freed by the rna_workq_thread.
 */
#define RNA_WORK_QUEUE_FLAG_NO_FREE   0x1

struct rna_work_queue {
	
	int				num_threads;
	rna_wq_thread_t *threads;
	pthread_mutex_t	lock;
	int				num_pending;
	TAILQ_HEAD(pending_list, rna_work_obj) pending;
    int             destroying;
	
    int     flags;
	int		min_free;
	int		num_free;
	struct wait_obj wait_obj;
	TAILQ_HEAD(free_list, rna_work_obj) free;
    struct histogram *item_wait_histogram;       // time spent queued
    struct histogram *item_completed_histogram;  // time to completion
} ;

#define RNA_WORK_INIT( wr, cb, context) \
	do { \
		(wr)->callback = cb; \
		(wr)->ctx = context; \
	} while (0)
	
/* #ifdef __powerpc__ */

/* #define EIEIO_ON_SMP   "eieio\n" */
/* #define ISYNC_ON_SMP   "\n\tisync" */

/* #define ATOMIC_INIT(i)	{ (i) } */

/* #define atomic_read(v)		((v)->counter) */
/* #define atomic_set(v,i)		(((v)->counter) = (i)) */

/* extern void atomic_clear_mask(unsigned long mask, unsigned long *addr); */
/* extern void atomic_set_mask(unsigned long mask, unsigned long *addr); */

/* #define SMP_ISYNC	"\n\tisync" */
/* #define LWSYNC_ON_SMP	"lwsync" */
/* //#define PPC405_ERR77(ra,rb)     "dcbt     ra, rb;" */

 
/* /\* Note: This expects that the var length is 32 bits *\/ */
/* INLINE int test_and_set_bit(unsigned long nr, volatile unsigned long *addr) */
/* { */
/* 	unsigned long old, t; */
/* 	unsigned long mask = 1UL << (nr & 0x1f); */
/* 	unsigned long *p = ((unsigned long *)addr) + (nr >> 6); */

/* 	__asm__ __volatile__( */
/* 		EIEIO_ON_SMP */
/* "1:     lwarx   %0,0,%3         # test_and_set_bit\n\ */
/* 		or      %1,%0,%2 \n\ */
/* 		stwcx.  %1,0,%3 \n\ */
/* 		bne-    1b" */
/* 		ISYNC_ON_SMP */
/* 		: "=&r" (old), "=&r" (t) */
/* 		: "r" (mask), "r" (p) */
/* 		: "cc", "memory"); */

/* 	return (old & mask) != 0; */
/* } */

/* /\* Note: This expects that the var length is 32 bits *\/ */
/* INLINE int test_and_clear_bit(unsigned long nr, volatile unsigned long *addr) */
/* { */
/* 	unsigned long old, t; */
/* 	unsigned long mask = 1UL << (nr & 0x1f); */
/* 	unsigned long *p = ((unsigned long *)addr) + (nr >> 6); */

/* 	__asm__ __volatile__( */
/* 		EIEIO_ON_SMP */
/* "1:     lwarx   %0,0,%3         # test_and_clear_bit\n\ */
/* 		andc    %1,%0,%2\n\ */
/* 		stwcx.  %1,0,%3\n\ */
/* 		bne-    1b" */
/* 		ISYNC_ON_SMP */
/* 		: "=&r" (old), "=&r" (t) */
/* 		: "r" (mask), "r" (p) */
/* 		: "cc", "memory"); */

/* 	return (old & mask) != 0; */
/* } */

/* INLINE gboolean */
/* atomic_test_and_set(volatile unsigned int *p, unsigned long old, */
/*                         unsigned long new) */
/* { */
/*         unsigned int prev; */

/*         __asm__ __volatile__ ( */
/* "1:     lwarx   %0,0,%2         # __cmpxchg_u32\n\ */
/*         cmpw    0,%0,%3\n\ */
/*         bne-    2f\n" */
/* "       stwcx.  %4,0,%2\n\ */
/*         bne-    1b" */
/*         "\n\ */
/* 2:" */
/*         : "=&r" (prev), "+m" (*p) */
/*         : "r" (p), "r" (old), "r" (new) */
/*         : "cc", "memory"); */

/*         return prev == old; */
/* } */



/* //INLINE unsigned long */
/* //__cmpxchg_u32(volatile unsigned int *p, unsigned long old, unsigned long new) */
/* /\* */
/* INLINE int */
/* atomic_test_and_set ( atomic_t *a, int match, int new ) */
/* { */
/*         unsigned int prev; */

/*         __asm__ __volatile__ ( */
/*         LWSYNC_ON_SMP */
/* "1:     lwarx   %0,0,%2         # __cmpxchg_u32\n\ */
/*         cmpw    0,%0,%3\n\ */
/*         bne-    2f\n" */
/* "       stwcx.  %4,0,%2\n\ */
/*         bne-    1b" */
/*         ISYNC_ON_SMP */
/*         "\n\ */
/* 2:" */
/*         : "=&r" (prev), "+m" (*p) */
/*         : "r" (p), "r" (old), "r" (new) */
/*         : "cc", "memory"); */

/*         return prev; */
/* } */
/* *\/ */
/* /\* */
/* INLINE int */
/* atomic_test_and_set ( atomic_t *a, int match, int new ) */
/* { */
/* 	unsigned int cur = 0; */
	
/* 	while(test_and_set_bit(31,(unsigned long*)a)) { } */

/* 	cur = (*a & 0x7FFF);	 */

/* 	if((*a & 0x7FFF) == match){ */
/* 		*a = (0x80000000 |  new); */
/* 	} */
	
/* 	assert(test_and_clear_bit(31,(unsigned long*)a)); */
	
/* 	return cur; */
/* } */
/* *\/ */
/* // ***** */

/* INLINE void atomic_inc(atomic_t *v) */
/* { */
/* 	int t; */

/* 	__asm__ __volatile__( */
/* "1:	lwarx	%0,0,%2		# atomic_inc\n\ */
/* 	addic	%0,%0,1\n\ */
/* 	stwcx.	%0,0,%2\n\ */
/* 	bne-	1b" */
/* 	: "=&r" (t), "=m" (*v) */
/* 	: "r" (v), "m" (*v) */
/* 	: "cc"); */
/* } */

/* INLINE gboolean atomic_dec(atomic_t *v) */
/* { */
/* 	int t; */

/* 	__asm__ __volatile__( */
/* "1:	lwarx	%0,0,%2		# atomic_dec\n\ */
/* 	addic	%0,%0,-1\n\ */
/* 	stwcx.	%0,0,%2\n\ */
/* 	bne-	1b" */
/* 	: "=&r" (t), "=m" (*v) */
/* 	: "r" (v), "m" (*v) */
/* 	: "cc"); */

/* 	return (0 == *v); */
/* } */

/* /\* Note: the input parameters are reversed for the non-powerpc version of this. Depending on how the  */
/* 	     inputs are referenced in the assembly the ordering may matter. This needs to be investigated */
/* 		 and fixed if necessary in the assembly to avoid having the second funct call. *\/ */
/* INLINE int atomic_add_return2(int a, atomic_t *v) */
/* { */
/* 	int t; */

/* 	__asm__ __volatile__( */
/* "1:	lwarx	%0,0,%2		# atomic_add_return\n\ */
/* 	add	%0,%1,%0\n\ */
/* 	stwcx.	%0,0,%2\n\ */
/* 	bne-	1b" */
/* 	SMP_ISYNC */
/* 	: "=&r" (t) */
/* 	: "r" (a), "r" (v) */
/* 	: "cc", "memory"); */

/* 	return t; */
/* } */

/* INLINE int atomic_add_return(atomic_t *v, int a) */
/* { */
/* 	return atomic_add_return2(a,v); */
/* } */

/* // ***** */


/* typedef unsigned long long cycles_t; */
/* INLINE cycles_t get_cycles() */
/* { */
/* 	unsigned low, high; */
/* 	unsigned long long val; */
/* 	asm volatile ("rdtsc" : "=a" (low), "=d" (high)); */
/* 	val = high; */
/* 	val = (val << 32) | low; */
/* 	return val; */
/* } */


/* //================================================================================================================= */

/* INLINE void atomic_add(int a, atomic_t *v) */
/* { */
/* 	int t; */

/* 	__asm__ __volatile__( */
/* "1:	lwarx	%0,0,%3		# atomic_add\n\ */
/* 	add	%0,%2,%0\n\ */
/* 	stwcx.	%0,0,%3\n\ */
/* 	bne-	1b" */
/* 	: "=&r" (t), "=m" (*v) */
/* 	: "r" (a), "r" (v), "m" (*v) */
/* 	: "cc"); */
/* } */



/* INLINE void atomic_sub(int a, atomic_t *v) */
/* { */
/* 	int t; */

/* 	__asm__ __volatile__( */
/* "1:	lwarx	%0,0,%3		# atomic_sub\n\ */
/* 	subf	%0,%2,%0\n\ */
/* 	stwcx.	%0,0,%3\n\ */
/* 	bne-	1b" */
/* 	: "=&r" (t), "=m" (*v) */
/* 	: "r" (a), "r" (v), "m" (*v) */
/* 	: "cc"); */
/* } */

/* INLINE int atomic_sub_return(int a, atomic_t *v) */
/* { */
/* 	int t; */

/* 	__asm__ __volatile__( */
/* "1:	lwarx	%0,0,%2		# atomic_sub_return\n\ */
/* 	subf	%0,%1,%0\n\ */
/* 	stwcx.	%0,0,%2\n\ */
/* 	bne-	1b" */
/* 	SMP_ISYNC */
/* 	: "=&r" (t) */
/* 	: "r" (a), "r" (v) */
/* 	: "cc", "memory"); */

/* 	return t; */
/* } */



/* INLINE int atomic_dec_return(atomic_t *v) */
/* { */
/* 	int t; */

/* 	__asm__ __volatile__( */
/* "1:	lwarx	%0,0,%1		# atomic_dec_return\n\ */
/* 	addic	%0,%0,-1\n\ */
/* 	stwcx.	%0,0,%1\n\ */
/* 	bne-	1b" */
/* 	SMP_ISYNC */
/* 	: "=&r" (t) */
/* 	: "r" (v) */
/* 	: "cc", "memory"); */

/* 	return t; */
/* } */

/* #define atomic_sub_and_test(a, v)	(atomic_sub_return((a), (v)) == 0) */
/* #define atomic_dec_and_test(v)		(atomic_dec_return((v)) == 0) */

/* /\* */
/*  * Atomically test *v and decrement if it is greater than 0. */
/*  * The function returns the old value of *v minus 1. */
/*  *\/ */
/* INLINE int atomic_dec_if_positive(atomic_t *v) */
/* { */
/* 	int t; */

/* 	__asm__ __volatile__( */
/* "1:	lwarx	%0,0,%1		# atomic_dec_if_positive\n\ */
/* 	addic.	%0,%0,-1\n\ */
/* 	blt-	2f\n\ */
/* 	stwcx.	%0,0,%1\n\ */
/* 	bne-	1b" */
/* 	SMP_ISYNC */
/* 	"\n\ */
/* 2:"	: "=&r" (t) */
/* 	: "r" (v) */
/* 	: "cc", "memory"); */

/* 	return t; */
/* } */

/* /\* */
/*  * Memory barrier. */
/*  * The sync instruction guarantees that all memory accesses initiated */
/*  * by this processor have been performed (with respect to all other */
/*  * mechanisms that access memory).  The eieio instruction is a barrier */
/*  * providing an ordering (separately) for (a) cacheable stores and (b) */
/*  * loads and stores to non-cacheable memory (e.g. I/O devices). */
/*  * */
/*  * mb() prevents loads and stores being reordered across this point. */
/*  * rmb() prevents loads being reordered across this point. */
/*  * wmb() prevents stores being reordered across this point. */
/*  * */
/*  * We can use the eieio instruction for wmb, but since it doesn't */
/*  * give any ordering guarantees about loads, we have to use the */
/*  * stronger but slower sync instruction for mb and rmb. */
/*  *\/ */
/* #define mb()  __asm__ __volatile__ ("sync" : : : "memory") */
/* #define rmb()  __asm__ __volatile__ ("sync" : : : "memory") */
/* #define wmb()  __asm__ __volatile__ ("eieio" : : : "memory") */

/* #define IATOMIC_DEFINED		1 */

/* #else /\* __powerpc__ *\/ */





/* #endif */

/**
 * Current time in nanoseconds for the specified clock
 *
 * @return nanoseconds
 */
INLINE 
uint64_t get_timestamp(clockid_t clock)
{
#ifdef WINDOWS_USER
	return gettime_nsec();
#elif defined(LINUX_USER)
	struct timespec tp;	
	int ret;
	
	ret = clock_gettime(clock, &tp);
	if (unlikely(ret)) {
		printf("Error in getting monotonic time stamp counter\n");
		return 0;
	}
	/* convert the nsec timestamp into nanoseconds */
	return ((uint64_t)(tp.tv_sec) * NSEC_PER_SEC + (uint64_t)tp.tv_nsec);
#endif	/* Windows/Linux */
}

INLINE 
uint64_t get_monotonic_timestamp(void)
{
#if defined(CLOCK_MONOTONIC_RAW)
	return get_timestamp(CLOCK_MONOTONIC_RAW);
#else
	return get_timestamp(CLOCK_MONOTONIC);
#endif
}

INLINE 
uint64_t get_realtime_timestamp(void)
{
	return get_timestamp(CLOCK_REALTIME);
}

INLINE 
uint64_t get_cpu_timestamp(void)
{
#ifdef WINDOWS_USER
	return (((uint64_t)clock()) * (NSEC_PER_SEC / CLOCKS_PER_SEC));
#elif defined(LINUX_USER)
	return get_timestamp(CLOCK_PROCESS_CPUTIME_ID);
#endif
}

struct aging_conf{
	int decay;
	int bump;
	int constant;
	int escaler;
};

void init_age_conf(struct aging_conf *conf, int decay, int bump, int constant, int escaler);

int get_env_val ( char *env_str, int default_val );

typedef enum {
    RNA_UTIL_THREAD_PRIORITY_LOW,
    RNA_UTIL_THREAD_PRIORITY_MID,
    RNA_UTIL_THREAD_PRIORITY_HIGH,
    RNA_UTIL_THREAD_PRIORITY_INVALID
} rna_util_thread_priority;


enum {
    CANCEL_WORKQ_THREADS = 0,
    NOCANCEL_WORKQ_THREADS,
            /*
             * This option is used if the workq threads aren't safe for
             * cancelation, and the process is about to exit so thread
             * cancelation is unnecessary.
             */
    JOIN_WORKQ_THREADS,
            /*
             * This option is used if we want to wait for rna_workq_thread() to 
             * exit before tearing down the queue.
             */
};


rna_thread_t rna_thread_create (void (*func) (void *),
                                void  *context);

rna_thread_t rna_fifo_thread_create (rna_util_thread_priority priority,
                                     void                     (*func) (void *),
                                     void                    *context);

int wait_obj_init(struct wait_obj *obj);
int wait_obj_init_latch (struct wait_obj *obj);
int wait_obj_timed_wait_generic(struct wait_obj *obj, int64_t seconds,
                                int64_t nsecs);
INLINE int
wait_obj_wait(struct wait_obj *obj)
{
    return wait_obj_timed_wait_generic(obj, -1, 0);
}
INLINE int
wait_obj_timed_wait (struct wait_obj *obj, int seconds)
{
    return wait_obj_timed_wait_generic(obj, seconds, 0);
}
INLINE int
wait_obj_timed_wait_nsecs (struct wait_obj *obj, int64_t nsecs)
{
    return wait_obj_timed_wait_generic(obj, 0, nsecs);
}
int wait_obj_wakeup(struct wait_obj *obj);
int wait_obj_try_wakeup(struct wait_obj *obj);
int wait_obj_wakeup_all(struct wait_obj *obj);
void wait_obj_destroy(struct wait_obj *obj);
int wait_obj_reset_latch(struct wait_obj *obj);

int get_addr(char *dst, struct sockaddr_in *addr);
int get_host(struct sockaddr *addr, char *host, int host_len);
double get_time( void );

int
rna_fifo_workq_create_debug(const char              *func_string,
                            const char              *location_string,
                            const char              *queue_string,
                            int                      num_threads,
                            rna_util_thread_priority priority,
                            int                      min_size,
                            struct rna_work_queue  **new_wq);
#define rna_fifo_workq_create(rwc_num_threads, rwc_priority, rwc_min_size, rwc_new_wq) \
    rna_fifo_workq_create_debug(__FUNCTION__, __location__, #rwc_new_wq, \
                                rwc_num_threads, rwc_priority, rwc_min_size, rwc_new_wq)

int
rna_workq_create_debug(const char             *func_string,
                       const char             *location_string,
                       const char             *queue_string,
                       int                     num_threads,
                       int                     min_size,
                       struct rna_work_queue **new_wq);
#define rna_workq_create(rwc_num_threads, rwc_min_size, rwc_new_wq) \
    rna_workq_create_debug(__FUNCTION__, __location__, #rwc_new_wq, \
                           rwc_num_threads, rwc_min_size, rwc_new_wq)

int
rna_work_obj_remove(struct rna_work_queue  *wq, struct rna_work_obj *wr);
void
rna_workq_destroy_debug(const char             *func_string,
                        const char             *location_string,
                        const char             *queue_string,
                        struct rna_work_queue  *wq,
                        int                     thread_cancel_flag);
#define rna_workq_destroy(rwd_wq, rwd_thread_cancel_flag) \
    rna_workq_destroy_debug(__FUNCTION__, __location__, #rwd_wq, rwd_wq, rwd_thread_cancel_flag)

int rna_workq_get_obj(struct rna_work_queue	*wq, struct rna_work_obj	**new_wr);
int rna_workq_add(struct rna_work_queue	*wq, struct rna_work_obj	*wr);
int rna_workq_add_if_not_pending(struct rna_work_queue *wq,
                                 struct rna_work_obj *wr);
gboolean rna_workq_iterate(struct rna_work_queue *wq, rna_work_iter_cb cb, void *cb_data);
int msg_q_create(int key);
int msg_q_open(int key);
int sem_create(int key, int num);
int rna_sem_open(int key, int num);
int shm_create(int key, int size);
int	rna_shm_open(int key);

struct sem_rwlock {
//	atomic_t wr_lock_taken;
//	atomic_t rd_lock_taken;
	int write_mutex;
	int count_sem;
};

int sem_rwlock_alloc(int key, struct sem_rwlock *lock);
int sem_rwlock_open(int key, struct sem_rwlock *lock);
int sem_rwlock_read_lock(struct sem_rwlock *lock, int tryit);
int sem_rwlock_read_unlock(struct sem_rwlock *lock);
int sem_rwlock_write_lock(struct sem_rwlock *lock);
int sem_rwlock_write_unlock(struct sem_rwlock *lock);
int sem_rwlock_close(struct sem_rwlock *lock);
void sem_rwlock_free(struct sem_rwlock *lock);

struct shm_rwlock {
	atomic_t	mutex;
	atomic_t	count;
};

/* pthread_rwlock_t not yet defined for Windows */
#if !defined(WINDOWS_USER)
#define USE_PTHREAD_RWLOCKS
#endif

/**
 * Pthread rwlocks are not enabled. We'll use this implementation for
 * now.  We can move over to a standard implementation when available.
 */
typedef struct _rna_rwlock_t {
#if defined(USE_PTHREAD_RWLOCKS)
	pthread_mutex_t  rwlock_guard;
    pthread_rwlock_t rwlock;
#else //!defined(USE_PTHREAD_RWLOCKS)
	atomic_t         count;             /* Current read locks. */
	pthread_mutex_t  lock;
    struct wait_obj  write_locker;
#endif //defined(USE_PTHREAD_RWLOCKS)
#if defined(_LATENCY_DEBUG_)
    uint64_t         lock_acquire_time;
#endif
} rna_rw_lock_t;

#if defined(_LATENCY_DEBUG_)
#define RNA_LOCK_ACQUIRE_TIME_INITIALIZER ((uint64_t) 0),  /* Note the comma */
#else //!defined(_LATENCY_DEBUG_)
#define RNA_LOCK_ACQUIRE_TIME_INITIALIZER
#endif //defined(_LATENCY_DEBUG_)

/**
 * Statically initialize an RNA rwlock.
 */
#if defined(USE_PTHREAD_RWLOCKS)
#define RNA_RW_LOCK_INITIALIZER {                               \
    PTHREAD_MUTEX_INITIALIZER,   /* rwlock_guard */             \
    PTHREAD_RWLOCK_INITIALIZER,  /* rwlock */                   \
    RNA_LOCK_ACQUIRE_TIME_INITIALIZER  /* NO COMMA! */          \
}
#else //!defined(USE_PTHREAD_RWLOCKS)
#define RNA_RW_LOCK_INITIALIZER {                               \
    ATOMIC_T_INITIALIZER(0),    /* count */                     \
    PTHREAD_MUTEX_INITIALIZER,  /* lock */                      \
    RNA_WAIT_OBJ_INITIALIZER,   /* write_locker */              \
    RNA_LOCK_ACQUIRE_TIME_INITIALIZER /* NO COMMA! */           \
}
#endif //defined(USE_PTHREAD_RWLOCKS)

INLINE void debug_assert_write_locked (rna_rw_lock_t *rw_lock);
INLINE void debug_assert_not_write_locker (rna_rw_lock_t *rw_lock);

int rna_rwlock_init(rna_rw_lock_t *lock);
int rna_rwlock_destroy(rna_rw_lock_t *lock);

/**
 * Acquire, or try to acquire, a read lock.
 *
 * This should only be called with the rna_rwlock_read_lock() macro.
 *
 * @return 1 for success, 0 for failure
 */
INLINE int rna_rwlock_read_lock_debug(const char      *function,
                                      const char      *info_string,
                                      const char      *lock_string,
                                      rna_rw_lock_t   *lock, 
                                      const int        tryit)
{
    int ret         = 1;  
    int pthread_ret = 0;
#if defined(_LATENCY_DEBUG_)
	uint64_t start_time = get_monotonic_timestamp();
	uint64_t stop_time  = 0;
	uint64_t latency    = 0;
#endif

    debug_assert_not_write_locker(lock);

    if(tryit) {
#if defined(USE_PTHREAD_RWLOCKS)
        pthread_ret = pthread_mutex_trylock(&lock->rwlock_guard);
        if (0 == pthread_ret) {
            pthread_ret = pthread_rwlock_tryrdlock(&lock->rwlock);
            pthread_mutex_unlock(&lock->rwlock_guard);
        }
#else //!defined(USE_PTHREAD_RWLOCKS)
        pthread_ret = pthread_mutex_trylock(&lock->lock);
#endif //defined(USE_PTHREAD_RWLOCKS)
    } else {
#if defined(USE_PTHREAD_RWLOCKS)
        pthread_ret = pthread_mutex_lock(&lock->rwlock_guard);
        if (0 == pthread_ret) {
            pthread_ret = pthread_rwlock_rdlock(&lock->rwlock);
            pthread_mutex_unlock(&lock->rwlock_guard);
        }
#else //!defined(USE_PTHREAD_RWLOCKS)
        pthread_ret = pthread_mutex_lock(&lock->lock);
#endif //defined(USE_PTHREAD_RWLOCKS)
    }
    if (unlikely(0 != pthread_ret)) {
        ret = 0;
    } else {
#if !defined(USE_PTHREAD_RWLOCKS)
        atomic_inc(&lock->count);
        pthread_mutex_unlock(&lock->lock);
#endif //!defined(USE_PTHREAD_RWLOCKS)
#if defined(_RNA_DBG_RW_LOCKS_)
        rna_dbg_log(RNA_DBG_WARN,
                    "tid [%d] %s: %s, lock [%s] count [%d]\n",
                    gettid(),
                    function,
                    info_string,
                    lock_string,
                    atomic_get(&lock->count));
#endif
#if defined(_LATENCY_DEBUG_)
        stop_time = get_monotonic_timestamp();
        if (likely(stop_time > start_time)) { // avoid clock skew issues
            latency = (stop_time - start_time);
            if (unlikely(latency > NSEC_PER_SEC)) {
                rna_dbg_log(RNA_DBG_WARN,
                            "%s: %s, read lock [%s] took [%lu] secs\n",
                            function,
                            info_string,
                            lock_string,
                            latency/NSEC_PER_SEC);
            }
        }
#endif
    }

    return ret;
}

int _rna_rwlock_lock_generic(gboolean write, rna_rw_lock_t *lock, int tryit, long seconds, long nsecs);

#define rna_rwlock_read_lock(__lock, __tryit)\
    rna_rwlock_read_lock_debug(__FUNCTION__, __location__, #__lock, __lock, __tryit)

INLINE int 
rna_rwlock_read_lock_timed(rna_rw_lock_t *lock, long seconds, long nsecs) {
    return _rna_rwlock_lock_generic(FALSE, lock, 1, seconds, nsecs);
}

INLINE int 
rna_rwlock_write_lock_debug(const char    *function,
                            const char    *info_string,
                            const char    *lock_string,
                            rna_rw_lock_t *lock,
                            int            tryit) {
    int ret;
#if defined(_LATENCY_DEBUG_)
	uint64_t start_time = get_monotonic_timestamp();
	uint64_t stop_time  = 0;
	uint64_t latency    = 0;
#endif

    ret = _rna_rwlock_lock_generic(TRUE, lock, tryit, 0, 0);

#if defined(_LATENCY_DEBUG_)
    stop_time = get_monotonic_timestamp();
    if (likely(stop_time > start_time)) { // avoid clock skew issues
        latency = (stop_time - start_time);
        if (unlikely(latency > NSEC_PER_SEC)) {
            rna_dbg_log(RNA_DBG_WARN,
                        "%s: %s, write lock [%s] took [%lu] secs\n",
                        function,
                        info_string,
                        lock_string,
                        latency/NSEC_PER_SEC);
        }
    }
    if (ret) {
        /* We are the write locker */
        lock->lock_acquire_time = stop_time;
    }
#endif
    return ret;
}

#define rna_rwlock_write_lock(__lock,__tryit) \
   rna_rwlock_write_lock_debug(__FUNCTION__, __location__, #__lock, __lock, __tryit) 

INLINE int 
rna_rwlock_write_lock_timed(rna_rw_lock_t *lock, long seconds, long nsecs) {
    return _rna_rwlock_lock_generic(TRUE, lock, 1, seconds, nsecs);
}

int rna_rwlock_write_unlock_debug(const char    *function,
                                  const char    *info_string,
                                  const char    *lock_string,
                                  rna_rw_lock_t *lock);
#define rna_rwlock_write_unlock(__lock) \
   rna_rwlock_write_unlock_debug(__FUNCTION__, __location__, #__lock, __lock)


extern int rna_rwlock_read_unlock_generic_debug(const char *function,
                                         const char      *info_string,
                                         const char      *lock_string,
                                         rna_rw_lock_t   *lock,
                                         const gboolean  tryit);

#define rna_rwlock_read_unlock_generic(__lock, tryit)\
    rna_rwlock_read_unlock_generic_debug(__FUNCTION__, __location__, #__lock, __lock, tryit) 

/**
 * Release a read lock.  Never blocks.
 *
 * This should only be called with the
 * rna_rwlock_nonblocking_read_unlock() macro.
 */
INLINE int 
rna_rwlock_nonblocking_read_unlock_debug(const char      *function,
                                         const char      *info_string,
                                         const char      *lock_string,
                                         rna_rw_lock_t    *lock) {
    return rna_rwlock_read_unlock_generic_debug(function, info_string, lock_string, lock, 1);
}

#define rna_rwlock_nonblocking_read_unlock(__lock)\
    rna_rwlock_nonblocking_read_unlock_debug(__FUNCTION__, __location__, #__lock, __lock) 

/**
 * Release a read lock.  May block briefly to signal write lockers,
 * which is only really a problem in signal handlers.
 *
 * This should only be called with the
 * rna_rwlock_blocking_read_unlock() macro.
 */
INLINE int 
rna_rwlock_blocking_read_unlock_debug(const char      *function,
                                      const char      *info_string,
                                      const char      *lock_string,
                                      rna_rw_lock_t   *lock) {
    return rna_rwlock_read_unlock_generic_debug(function, info_string, lock_string, lock, 0);
}

#define rna_rwlock_blocking_read_unlock(__lock)\
    rna_rwlock_blocking_read_unlock_debug(__FUNCTION__, __location__, #__lock, __lock, 0) 

/**
 * Release a read lock with the default blocking behavior.
 *
 * The default is to allow blocking, because we don't seem to be doing
 * this from any signal handlers.
 *
 * This should only be called wirth the rna_rwlock_read_unlock()
 * macro.
 */
INLINE int 
rna_rwlock_read_unlock_debug(const char      *function,
                             const char      *info_string,
                             const char      *lock_string,
                             rna_rw_lock_t   *lock) {
    return rna_rwlock_blocking_read_unlock_debug(function, info_string, lock_string, lock);
}

#define rna_rwlock_read_unlock(__lock)\
    rna_rwlock_read_unlock_debug(__FUNCTION__, __location__, #__lock, __lock) 


/* Decrement given atomic_t but only if atomic is positive.
 * Return TRUE on success, FALSE if atomic would have gone negative. */
INLINE gboolean
atomic_dec_if_positive(atomic_t *a)
{
    int ret = TRUE;
    int prev;

    while (TRUE) {
       prev = atomic_get(a);

       if (prev <= 0) {
            ret = FALSE;
            break;
        }

        if (atomic_test_and_set(a, prev, prev-1)) {
            ret = TRUE;
            break;
        }
    }

    return ret;
}

/*
 * The number of vlock modes is limited to 8 to keep the size of an rna_vlock_t
 * small.  This value can be increased to up 16 with a fairly minimal increase
 * in memory usage by an rna_vlock_t, and can be further increased up to 64 by
 * increasing the size of the vl_modes_held bitmap.
 */
#define RNA_VLOCK_MAX_MODES 8

/* A vlock preempt generation number */
typedef int16_t  vlock_gen_t;

/**
 * An RNA vector lock.
 *
 * A vector lock is a generalized lock, in the sense that it can support any
 * locking protocol whose conflicts can be represented by a conflict matrix.
 * A vector lock can be used as an ordinary mutex (see the RNA_VLOCK_MUTEX_*
 * defines), a reader/writer lock (see the RNA_VLOCK_RW_* defines), a
 * multi-mode Gray-style hierarchical lock, a reader/reader/writer lock (see
 * the RNA_VLOCK_RRW_* defines) or practically any other lock imaginable.
 * An example of a lock protocol that a vector lock can not support is one
 * in which, say, 3 threads are allowed to co-execute in mode X but no more,
 * since this conflict rule can't be described by a conflict matrix.
 *
 * Vector locks support the following features:
 *   1. Nested lock acquisition and release: For non-exclusive lock modes
 *      (a lock mode is exclusive if its conflict vector does includes itself),
 *      a thread is allowed to acquire a vlock it already holds in the mode it
 *      already holds it in.  The thread must release the vlock once for each
 *      acquisition.  NOTE that nested lock acquisition is not allowed for
 *      exclusive lock modes, as self-deadlock will result.
 *   2. Optional timeout for lock acquisition: The caller is allowed to specify
 *      the maximum amount of time it is willing to wait for the vlock.
 *   3. Optional preemption on timeout: If the acquisition times out, all
 *      holders of the vlock in the specified conflicting modes are preempted
 *      and the vlock is granted to the caller.
 */
typedef struct rna_vlock_s {
    pthread_mutex_t vl_mutex;   /* A mutex to guard the following fields */
    uint16_t        vl_count[RNA_VLOCK_MAX_MODES];
                                   /* Number of threads that hold the vlock in
                                    * each mode.
                                    */
    uint16_t        vl_modes_held; /* A bitmap containing the modes in which
                                    * this vlock is currently held.
                                    */
    vlock_gen_t     vl_gen[RNA_VLOCK_MAX_MODES];
                                   /* The preemption generation of each mode.
                                    * This value is used to indicate when a
                                    * the holders of a vlock in a given mode
                                    * have been preempted.
                                    */
    pthread_cond_t  vl_cv;         /* Threads that can't immediately acquire
                                    * the vlock wait here.
                                    */
} rna_vlock_t;


/*
 * Vlock support for mutex locking.
 */
#define RNA_VLOCK_MUTEX_MODE        0
/* Each request conflicts with every other request (hence the name) */
#define RNA_VLOCK_MUTEX_CONFLICTS   0x1

/*
 * Vlock support for reader/writer locks
 */
#define RNA_VLOCK_RW_READER_MODE    0
#define RNA_VLOCK_RW_WRITER_MODE    1
/* Readers conflict with writers, but not with other readers */
#define RNA_VLOCK_RW_READER_CONFLICTS \
    (1 << RNA_VLOCK_RW_WRITER_MODE)
/* Writers conflict with both readers and writers */
#define RNA_VLOCK_RW_WRITER_CONFLICTS  \
    ((1 << RNA_VLOCK_RW_READER_MODE) | (1 << RNA_VLOCK_RW_WRITER_MODE))


/*
 * Vlock support for reader/reader/writer locks
 *
 * Under a reader/reader/writer lock, multiple readers in class A are allowed
 * to co-execute, as are multiple readers in class B, but multiple writers are
 * not allowed to co-execute.  Holders of a lock in any mode preclude holders
 * in every other mode, so readers in class A are not allowed to co-execute
 * with readers in class B, or vice-versa, or with writers, etc.  The conflict
 * matrix is as follows (X indicates a conflict):
 *
 *           readerA  readerB  writer
 *  readerA              X       X
 *  readerB     X                X
 *  writer      X        X       X
 */
#define RNA_VLOCK_RRW_READER_A_MODE  0
#define RNA_VLOCK_RRW_READER_B_MODE  1
#define RNA_VLOCK_RRW_WRITER_MODE    2
/*
 * Readers from class A conflict with readers from class B and with writers,
 * but not with other readers from class A
 */
#define RNA_VLOCK_RRW_READER_A_CONFLICTS  \
    (1 << RNA_VLOCK_RRW_READER_B_MODE) | (1 << RNA_VLOCK_RRW_WRITER_MODE)
/*
 * Readers from class B conflict with readers from class A and with writers,
 * but not with other readers from class B
 */
#define RNA_VLOCK_RRW_READER_B_CONFLICTS  \
    ((1 << RNA_VLOCK_RRW_READER_A_MODE) | (1 << RNA_VLOCK_RRW_WRITER_MODE))
/*
 * Writers conflict with readers of either class and with other writers.
 */
#define RNA_VLOCK_RRW_WRITER_CONFLICTS      \
    ((1 << RNA_VLOCK_RRW_READER_A_MODE) |   \
     (1 << RNA_VLOCK_RRW_READER_B_MODE) |   \
     (1 << RNA_VLOCK_RRW_WRITER_MODE))

/* The vlock request timed out */
#define VLOCK_TIMEOUT   -1

/**
 * Initialize a vector lock.
 *
 * A vector lock is generalized, in the sense that it can support any locking
 * protocol whose conflicts can be represented by a conflict matrix.  A vector
 * lock can be used as an ordinary mutex, a reader/writer lock, a multi-mode
 * Gray-style hierarchical lock, or practically any other lock imaginable.
 * An example of a lock protocol that a vector lock can not support is one in
 * which, say, 3 threads are allowed to co-execute in mode X, but no more
 * (this can't be described by a conflict matrix).
 *
 * Returns:
 *      1 for success
 *      0 for failure
 */
extern int
rna_vlock_init(rna_vlock_t *vlock);

/** 
 * Destroy a vector lock.
 *
 * Returns:
 *      0 for success
 *      Non-zero on failure.
 */
extern int
rna_vlock_destroy(rna_vlock_t *vlock);

/**
 * The rna_vlock_lock, rna_vlock_try, and rna_vlock_timed_lock macros are
 * wrappers for this function, and should be used to call it.
 */
extern vlock_gen_t
rna_vlock_timed_lock_debug(const char   *function,
                           const char   *info_string,
                           const char   *lock_string,
                           rna_vlock_t  *vlock,
                           int           mode,
                           int           conflict_vector,
                           int           timeout_seconds,
                           int           preempt_vector);


/**
 * Acquire a vector lock in the specified mode.
 *
 * A vector lock is generalized, in the sense that it can support any locking
 * protocol whose conflicts can be represented by a conflict matrix.  A vector
 * lock can be used as an ordinary mutex, a reader/writer lock, a multi-mode
 * Gray-style hierarchical lock, or practically any other lock imaginable.
 * An example of a lock protocol that a vector lock can not support is one in
 * which, say, 3 threads are allowed to co-execute in mode X, but no more
 * (this can't be described by a conflict matrix).
 *
 * Because of meta_data.c requirements, vlocks support a lot of features,
 * making them more complex than one might like.  The following features are
 * supported:
 *   1. Nested lock acquisition and release: A thread is allowed to acquire
 *      a vlock it already holds in the mode it already holds it in without
 *      self-deadlocking.  The thread must release the vlock once for each
 *      acquisition.
 *   2. Optional timeout for lock acquisition: The caller is allowed to specify
 *      the maximum amount of time it is willing to wait for the vlock.
 *   3. Optional preemption on timeout: If the acquisition times out, all
 *      holders of the vlock are preempted and the vlock is granted to the
 *      caller.
 *
 * Arguments:
 *   lock              The vlock to be acquired
 *   mode              The mode the lock is to be acquired in
 *   conflict_vector   A bitmap of the modes that conflict with the mode
 *                     specified above
 *
 * Returns:
 *      The lock generation number on success.  This value can be passed to
 *          rna_vlock_unlock, to deal correctly with the case where the lock
 *          has been preempted before being unlocked.
 *      0 on failure
 *      VLOCK_TIMEOUT (-1) on timeout, unless the VLOCK_PREEMPT_ON_TIMEOUT flag
 *          is specified, in which case one of the above values will be
 *          returned.
 */
#define rna_vlock_lock(__lock, __mode, __conflict_vector)                   \
    rna_vlock_timed_lock_debug(__FUNCTION__, __location__, #__lock, __lock, \
                                __mode, __conflict_vector, -1, 0) 

/**
 * Try to acquire a vector lock in the specified mode.
 *
 * A vector lock is generalized, in the sense that it can support any locking
 * protocol whose conflicts can be represented by a conflict matrix.  A vector
 * lock can be used as an ordinary mutex, a reader/writer lock, a multi-mode
 * Gray-style hierarchical lock, or practically any other lock imaginable.
 * An example of a lock protocol that a vector lock can not support is one in
 * which, say, 3 threads are allowed to co-execute in mode X, but no more
 * (this can't be described by a conflict matrix).
 *
 * Because of meta_data.c requirements, vlocks support a lot of features,
 * making them more complex than one would like.  The following features are
 * supported:
 *   1. Nested lock acquisition and release: A thread is allowed to acquire
 *      a vlock it already holds in the mode it already holds it in without
 *      self-deadlocking.  The thread must release the vlock once for each
 *      acquisition.
 *   2. Optional timeout for lock acquisition: The caller is allowed to specify
 *      the maximum amount of time it is willing to wait for the vlock.
 *   3. Optional preemption on timeout: If the acquisition times out, all
 *      holders of the vlock are preempted and the vlock is granted to the
 *      caller.
 *
 * Arguments:
 *   lock              The vlock to be acquired
 *   mode              The mode the lock is to be acquired in
 *   conflict_vector   A bitmap of the modes that conflict with the mode
 *                     specified above
 *
 * Returns:
 *      The lock generation number on success.  This value can be passed to
 *          rna_vlock_unlock, to deal correctly with the case where the lock
 *          has been preempted before being unlocked.
 *      0 on failure
 */
#define rna_vlock_try(__lock, __mode, __conflict_vector)                    \
    rna_vlock_timed_lock_debug(__FUNCTION__, __location__, #__lock, __lock, \
                                __mode, __conflict_vector, 0, 0) 

/**
 * Acquire a vector lock in the specified mode, with a timeout specified.
 *
 * A vector lock is generalized, in the sense that it can support any locking
 * protocol whose conflicts can be represented by a conflict matrix.  A vector
 * lock can be used as an ordinary mutex, a reader/writer lock, a multi-mode
 * Gray-style hierarchical lock, or practically any other lock imaginable.
 * An example of a lock protocol that a vector lock can not support is one in
 * which, say, 3 threads are allowed to co-execute in mode X, but no more
 * (this can't be described by a conflict matrix).
 *
 * vlocks have too many features for their own good.  The following features
 * are supported:
 *   1. Nested lock acquisition and release: A thread is allowed to acquire
 *      a lock it already holds in the mode it already holds it in without
 *      self-deadlocking.  The thread must release the lock once for each
 *      acquisition.
 *   2. Optional timeout for lock acquisition: The caller is allowed to specify
 *      the maximum amount of time it is willing to wait for the lock.
 *   3. Optional preemption on timeout: If the acquisition times out, all
 *      holders of the lock are preempted and the lock us granted to the
 *      caller.
 *
 * Arguments:
 *   lock              The vlock to be acquired
 *   mode              The mode the lock is to be acquired in
 *   conflict_vector   A bitmap of the modes that conflict with the mode
 *                     specified above
 *   timeout_seconds   The maximum amount of time the caller is willing to wait
 *                     for the lock, in seconds.  The following timeouts are
 *                     supported:
 *                         > 0  The maximum number of seconds to wait
 *                           0  Return immediately if the lock is not
 *                              available (try lock)
 *                          -1  Infinite timeout; wait until the lock is
 *                              available, no matter how long it takes
 *   preempt_vector    A bitmap of the lock modes to be preempted if the above
 *                     timeout expires.  If this bitmap is not empty (non-zero),
 *                     and lock holders in the specified modes block this
 *                     request, they will be preempted and the lock will be
 *                     granted to the caller.  If empty (zero), -1 will be
 *                     returned to indicate a timeout.
 *
 * Returns:
 *      The lock generation number on success.  This value can be passed to
 *          rna_vlock_unlock, to deal correctly with the case where the lock
 *          has been preempted before being unlocked.
 *      0 on failure
 *      VLOCK_TIMEOUT (-1) on timeout, unless a non-zero preempt_vector was
 *          specified and preemption allowed the request to be granted, in
 *          which case one of the above values will be returned.
 */
#define rna_vlock_timed_lock(__lock, __mode, __conflict_vector,               \
                               __timeout_seconds, __flags)                    \
    rna_vlock_timed_lock_debug(__FUNCTION__, __location__, #__lock, __lock,   \
                                 __mode, __conflict_vector, __timeout_seconds,\
                                 __flags) 

/**
 * The rna_vlock_unlock macro is a wrapper for this function, and should be
 * used to call it.
 */
extern int
rna_vlock_unlock_debug(const char   *function,
                       const char   *info_string,
                       const char   *lock_string,
                       rna_vlock_t  *lock,
                       int           mode,
                       vlock_gen_t   gen);

/**
 * Release a vector lock for the specified mode.  Nested lock releases are
 * allowed.
 *
 * A vector lock is generalized, in the sense that it can support any locking
 * protocol whose conflicts can be represented by a conflict matrix.  A vector
 * lock can be used as an ordinary mutex, a reader/writer lock, a multi-mode
 * Gray-style hierarchical lock, or practically any other lock imaginable.
 * An example of a lock protocol that a vector lock can not support is one in
 * which, say, 3 threads are allowed to co-execute in mode X, but no more
 * (this can't be described by a conflict matrix).
 *
 * Arguments:
 *   lock     Pointer to the lock to be released
 *   mode     The mode the lock is held in
 *   gen      The lock acquisition generation number, which was returned by
 *            rna_vlock_lock when the lock was acquired, or 0.  If non-zero,
 *            this value is used to deal correctly with the case where the
 *            caller's hold on the lock has already been preempted by another
 *            thread.  If the caller is unable to determine the acquisition
 *            generation number or if the caller knows the lock can not have
 *            been preempted, 0 can be used to circumvent the preemption check.
 *            If the caller does not know that the lock can not have been
 *            preempted, a generation number should be specified to prevent
 *            incorrect operation (double unlock).
 *
 * @return 1 for success, 0 for failure
 */
#define rna_vlock_unlock(__lock, __mode, __gen)                            \
    rna_vlock_unlock_debug(__FUNCTION__, __location__, #__lock, __lock,    \
                           __mode, __gen)

/**
 * The rna_vlock_preempt macro is a wrapper for this function, and should be
 * used to call it.
 */
extern int
rna_vlock_preempt_debug(const char     *function,
                          const char   *info_string,
                          const char   *lock_string,
                          rna_vlock_t  *lock,
                          int           mode,
                          int           conflict_vector,
                          int           preempt_vector);

/**
 * Preempt a vector lock and acquire it in the specified mode.
 *
 * A vector lock is generalized, in the sense that it can support any locking
 * protocol whose conflicts can be represented by a conflict matrix.  A vector
 * lock can be used as an ordinary mutex, a reader/writer lock, a multi-mode
 * Gray-style hierarchical lock, or practically any other lock imaginable.
 * An example of a lock protocol that a vector lock can not support is one in
 * which, say, 3 threads are allowed to co-execute in mode X, but no more
 * (this can't be described by a conflict matrix).
 *
 * Arguments:
 *   lock              Pointer to the vlock to be acquired
 *   mode              The mode the lock is to be acquired in
 *   conflict_vector   A bitmap of the modes that conflict with the mode
 *                     specified above
 *   preempt_vector    A bitmap of the lock modes to be preempted.
 *
 * Returns:
 *      The lock generation number on success.  This value can be passed to
 *          rna_vlock_unlock, to deal correctly with the case where the lock
 *          has been preempted before being unlocked.
 *      0 on failure
 */
#define rna_vlock_preempt(__lock, __mode, __conflict_vector,__preempt_vector) \
    rna_vlock_preempt_debug(__FUNCTION__, __location__, #__lock, __lock,      \
                            __mode, __conflict_vector, __preempt_vector) 

/**
 * Check if a vector lock has been preempted.
 *
 * A vector lock is generalized, in the sense that it can support any locking
 * protocol whose conflicts can be represented by a conflict matrix.  A vector
 * lock can be used as an ordinary mutex, a reader/writer lock, a multi-mode
 * Gray-style hierarchical lock, or practically any other lock imaginable.
 * An example of a lock protocol that a vector lock can not support is one in
 * which, say, 3 threads are allowed to co-execute in mode X, but no more
 * (this can't be described by a conflict matrix).
 *
 * Arguments:
 *   vlock     Pointer to the vlock to check for preemption
 *   mode      The mode the lock was held in
 *   lock_gen  The lock generation when the lock was acquired in the above mode
 *
 * @return TRUE if the lock in the mode has been preempted; FALSE otherwise
 */
extern gboolean
rna_vlock_preempted(rna_vlock_t *lock, int mode, vlock_gen_t lock_gen);


void init_age_conf(struct aging_conf *conf, int decay, int bump, int constant, int escaler);
uint32_t get_time_ms();
uint32_t cmp_delay(uint32_t prev_time, uint32_t curr_time);
int32_t  age_calculate_decay(struct aging_conf *conf, int32_t val, uint32_t elapsed);
int32_t  age_calculate_weight(struct aging_conf *conf, int32_t val, uint32_t elapsed);
int32_t  age_calculate_weight_diff(struct aging_conf *conf, int32_t val, uint32_t elapsed);

/* Function to combine 2 strings and alloc new space for them. Returns NULL if space cannot be allocated. */
char *rna_strcat_alloc(const char *str1, int len1, const char *str2, int len2, char* buf, int buf_len);

int rna_is_full_path(char *file);

char *rna_path_convert(char *current, const char *file, char *buf, int buf_len);

#define DEF_SHARED_KEY 0x93316002

#define RNA_QUEUE_KEY_INC   1
#define RNA_STAT_KEY_INC    2
#define RNA_SHM_KEY_INC     3
#define RNA_SEARCH_KEY_INC  4
#define RNA_UPDATE_KEY_INC  5

struct shm_key_info {
	uint32_t key_base; /* Base key value. Top 8 bits are masked to each type */
	uint32_t queue_key;
	uint32_t stat_key;
	uint32_t shm_key;
	uint32_t search_lock_key;
	uint32_t update_lock_key;
};

void rna_fill_shm_key_info_data(uint32_t base, struct shm_key_info *data);

char *rna_get_proc_name(pid_t pid, char *buf, int buf_len);
void registerHandler(int signalType, void (*func)(int));

int create_data_dir(char *path, uint32_t mode);

/* Returns the physical and available memory of the sytem */
int rna_get_phys_mem_limit(uint64_t *total_mem, uint64_t  *avail_mem);

struct rt_time_stats{
	pthread_mutex_t	rt_stat_lock;
	uint64_t count;
	uint64_t total;
	uint64_t max;
	uint64_t min;
	uint64_t thresh;
	uint64_t thresh_above;
	uint64_t print_thresh;
        const char *name;
};

void rt_log_time(struct rt_time_stats *pstat, uint64_t t);
void rt_log_value(struct rt_time_stats *pstat, uint64_t t);
void rt_clear_stats(struct rt_time_stats *pstat);
void rt_init_stats(struct rt_time_stats *pstat, int t,const char *name, uint64_t print_thresh);
void rt_print_stats(struct rt_time_stats *pstat);

/* Compare hostnames normalizing fqdn to just the hostname */
int rna_comp_hostnames(const char *h1, const char *h2);

typedef atomic_t rna_spnlck_t;

/* #include "rna_common_logging.h" */

INLINE void rna_spinlock_init(rna_spnlck_t *lck){
	atomic_set(lck,0);
}

INLINE void rna_spinlock_acquire(rna_spnlck_t *lck){
	while (unlikely(!atomic_test_and_set(lck,0,1))) {
		sched_yield();
	} 
}

INLINE void rna_spinlock_release(rna_spnlck_t *lck){
	if (unlikely(!atomic_test_and_set(lck,1,0))) {
		rna_debug_log_assert(0);	
	}
}


INLINE void rna_dbg_init (int log_level)
{
    if (0 == log_level) { // may be set in config
        log_level = (RNA_DBG_ERR | RNA_DBG_WARN | RNA_DBG_INFO);
    } 
    // allow env to override config
	g_rna_dbg_type = get_env_val("RNA_DBG_TYPE", log_level);
	g_rna_dbg_dest = get_env_val("RNA_DBG_DEST", RNA_DBG_DEST_FILE);
}

void rna_dbg_backtrace (void);

/* This shouls not be defined here in util.h */
struct bstore_tls {
    struct wait_obj wait_obj;
    int             status;
};


typedef struct _rna_mutex_wait_obj_s {
    TAILQ_ENTRY(_rna_mutex_wait_obj_s)      rmwo_link;
    void                                    *rmwo_data;
    gboolean                                rmwo_signaled;
    pthread_cond_t                          rmwo_cv;
} _rna_mutex_wait_obj_t;

/** Thread specific data for util.c */
struct util_tls {
    gboolean            rna_dbg_log_event_func_entered;
    gboolean            rna_dbg_log_file_func_entered;
    pid_t               tid;
    struct bstore_tls   bstore;
    _rna_mutex_wait_obj_t  tls_rmwo;
};

/*
 * Do per-thread tls data structure allocation/initialization.
 * (Note that threads created via our rna thread creation utilities
 * don't need to call this, as it is done for them).
 */
int util_tls_setup(void);

/*
 * Free/destroy this thread's util_tls struct, if necessary.  
 * (Note that threads created via our rna thread creation utilities
 * don't need to call this, as it is done for them).
 */
void util_tls_cleanup(void);

/*
 * Get this thread's util_tls struct, creating it if necessary.  
 *
 * Triggers per-process util module initilaization if that hasn't
 * happened already.
 */
struct util_tls *get_util_tls(void);

/*
 * get tid from our create-once-thread-specific struct
 * saves a lot of system calls.
 */

INLINE pid_t gettid(void)
{
    struct util_tls *tls = get_util_tls();
    return tls->tid;
}

INLINE _rna_mutex_wait_obj_t *get_mutex_tls(void)
{
    struct util_tls *tls = get_util_tls();
    return &tls->tls_rmwo;
}

/*
 * RNA wrapper to daemon() this should always be used instead of
 * daemon since we have a thread specific structure that requires
 * re-initialization once daemonized
 */
int rna_daemonize(int nochdir, int noclose);

INLINE gboolean
pthread_mutex_held (pthread_mutex_t *lock)
{
    return ((NULL != lock) && (pthread_mutex_owner(lock) == gettid()));
}

#if defined(_RNA_LOCK_ASSERT_) && !defined(USE_PTHREAD_RWLOCKS)
#define rna_rw_lock_assert_not_locker(__lock) \
    rna_debug_log_assert((NULL != __lock) && \
                         !pthread_mutex_held(&(__lock)->lock))
#else
#define rna_rw_lock_assert_not_locker(__lock)
#endif

INLINE void debug_assert_locked (pthread_mutex_t *lock)
{
#if defined(_RNA_LOCK_ASSERT_)
    rna_debug_log_assert(pthread_mutex_held(lock));
#endif
}

/** This mutex is not locked by this thread */
INLINE void debug_assert_not_locker (pthread_mutex_t *lock)
{
#if defined(_RNA_LOCK_ASSERT_)
    rna_debug_log_assert((NULL != lock) &&
                         !pthread_mutex_held(lock));
#endif
}


INLINE void debug_assert_write_locked (rna_rw_lock_t *rw_lock)
{
#if !defined(USE_PTHREAD_RWLOCKS)
    debug_assert_locked(&rw_lock->lock);
#endif
}

/** This rw_lock is not write locked by this thread */
INLINE void debug_assert_not_write_locker (rna_rw_lock_t *rw_lock)
{
#if !defined(USE_PTHREAD_RWLOCKS)
    debug_assert_not_locker(&rw_lock->lock);
#endif
}


/* =========================== rna mutex support ============================ */
/*
 * RNA mutex support, including support for two types of mutexes,
 * the rna_mutex and the rna_hc_mutex:
 *
 * IMPORTANT:
 *      Please note the trade-offs in the usage model for rna_hc_mutex
 *      versus rna_mutex (described below), and be careful to choose the
 *      appropriate type of mutex for a given usage.
 *
 *   rna_hc_mutex   -- (high contention mutexes)
 *      The rna_hc_mutex implementation is basically a simple wrapper
 *      around pthread mutexes that enables us to add some extra debug
 *      capabilities.
 *        
 *   rna_mutex      -- 
 *      The rna_mutex implementation supports mutex functionality while
 *      using fewer system resources per mutex (less memory and no object
 *      handle).
 *
 *
 *    When to use each type:
 *    ---------------------
 *      Use an
 *        rna_mutex    - when there can potentially be a large number of
 *                       concurrent instances of the mutex
 *                       [Example: a mutex embedded in a data structure,
 *                       where there may be hundreds or thousands of those
 *                       data structures in existence at the same time].
 *
 *        rna_hc_mutex - when the mutex may be highly contended and there
 *                       will be a limited number of instances of it.
 *                       [Example: global mutexes (i.e. only 1 instance) are
 *                       always safe candidates for using an rna_hc_mutex,
 *                       as is any other mutex that may be highly contended
 *                       and has a limited number of instances].
 *      
 *
 *    High-level summary of trade-offs:
 *    ---------------------------------
 *      rna_mutex
 *        - uses less memory
 *        - doesn't use an object handle
 *        - when contended, may impact or be impacted by other unrelated
 *          mutexes (in terms of performance)
 *
 *      rna_hc_mutex
 *        - uses more memory
 *        - uses an object handle
 *        - when contended, neither impacts nor is impacted by other
 *          unrelated mutexes (in terms of performance)
 *
 *    High-level design details:
 *    --------------------------
 *      An rna_hc_mutex has an embedded pthread_mutex_t in it, whereas
 *      an rna_mutex does not, but instead maps to a set of globally shared
 *      waiter queues.  The purpose of the rna_mutex model is to reduce
 *      both the memory footprint of the rna_mutex, and the number of
 *      object handles needed by a process.  [* The "object handle" is a
 *      Windows concern; on Windows, there is a limit to the number of
 *      active object handles a process can have, and thus it is important
 *      to conserve these resources.) On Windows, every pthread_mutex_t
 *      requires its own handle, so the rna_mutex implementation provides
 *      a means to support a variable (large!) number of rna_mutexes using
 *      a fixed number of pthread_mutex_t's.
 *       
 *    Practical explanation of how the above trade-offs direct usage:
 *    ---------------------------------------------------------------
 *      The impetus behind the rna_mutex design was specifically to reduce
 *      memory and object handle usage.  This was to address concerns about
 *      the Cache Server regarding its memory size and the number of object
 *      handles it needs as we increase the size of our flash devices (and
 *      so want to have increasing numbers of cache_entry structures resident
 *      in memory).
 *
 *      The trade-off of this design is that it uses a waiter queue (which
 *      includes a pthread_mutex) that is shared with other unrelated
 *      rna_mutex's.  This makes it possible for one (or more!) highly
 *      contended rna_mutex(es) to have an adverse effect on the performance
 *      of other unrelated mutexes.
 *
 *      The rna_hc_mutex facility is provided to address this potential
 *      performance problem.  Since high-contention is seen most often with
 *      global (or other minimally distributed) locks, an rna_hc_mutex
 *      can be used for such locks.  Doing so ensures that the lock won't
 *      affect performance for other unrelated locks, while, since there are
 *      few instances of the lock, we don't need to worry about it consuming
 *      exorbitant memory or object handles.
 */

/* ------------------------------ rna_hc_mutex ------------------------------ */

/*
 * rna_hc_mutex support
 *      Facility used to support high-contention/low-occurence mutexes.
 *      This implementation is basically a simple wrapper around pthread
 *      mutexes that enables us to add some extra debug capabilities.
 *      
 */

typedef struct {
    pthread_mutex_t rm_mutex;
#if defined(_LATENCY_DEBUG_)
    uint64_t        rm_lock_acquire_time;
#endif
} rna_hc_mutex_t;

#if defined(_LATENCY_DEBUG_)
#define RNA_HC_MUTEX_INITIALIZER                \
    {                                           \
        .rm_mutex = PTHREAD_MUTEX_INITIALIZER,  \
        .rm_lock_acquire_time = 0               \
    }
#else
#define RNA_HC_MUTEX_INITIALIZER                \
    {                                           \
        .rm_mutex = PTHREAD_MUTEX_INITIALIZER,  \
    }
#endif

INLINE gboolean
rna_hc_mutex_held (rna_hc_mutex_t *lock)
{
    return pthread_mutex_held(&lock->rm_mutex);
}

#if defined(_RNA_LOCK_ASSERT_)
#define rna_hc_mutex_assert_locked(__mutex) \
    rna_debug_log_assert(pthread_mutex_held(&(__mutex)->rm_mutex))
#else
#define rna_hc_mutex_assert_locked(__mutex)
#endif

#if defined(_RNA_LOCK_ASSERT_)
#define rna_hc_mutex_assert_not_locker(__mutex) \
    rna_debug_log_assert((NULL != __mutex) && \
                         !pthread_mutex_held(&(__mutex)->rm_mutex))
#else
#define rna_hc_mutex_assert_not_locker(__mutex)
#endif

INLINE int rna_hc_mutex_lock_debug(const char      *function,
                                const char      *info_string,
                                const char      *mutex_string,
                                rna_hc_mutex_t     *mutex,
                                struct timespec *timeout,
                                int              tryit)
{
    int ret = 0;

#if defined(_LATENCY_DEBUG_)
	uint64_t start_time = get_monotonic_timestamp();
	uint64_t stop_time  = 0;
	uint64_t latency    = 0;
#endif

#if defined(_RNA_DBG_LOCKS_)
    rna_dbg_log(RNA_DBG_INFO,
                "%s: %s, getting mutex [%s]\n",
                function,
                info_string,
                mutex_string);
#endif

    debug_assert_not_locker(&mutex->rm_mutex);

    if (0 != timeout) {
        rna_log_assert(!tryit);
        ret = pthread_mutex_timedlock (&mutex->rm_mutex, timeout);
    } else if (tryit){
        ret = pthread_mutex_trylock (&mutex->rm_mutex);
    } else {
        ret = pthread_mutex_lock (&mutex->rm_mutex);
    }

#if defined(_LATENCY_DEBUG_)
    stop_time = get_monotonic_timestamp();
    if (likely(stop_time > start_time)) { // avoid clock skew issues
        latency = (stop_time - start_time);
        if (unlikely(latency > NSEC_PER_SEC)) {
            rna_dbg_log(RNA_DBG_WARN,
                        "%s: %s, mutex [%s] [%p] took [%lu] secs\n",
                        function,
                        info_string,
                        mutex_string,
                        mutex,
                        latency/NSEC_PER_SEC);
        }
    }
    if (!tryit || (0 == ret)) {
        mutex->rm_lock_acquire_time = stop_time;
    }
#endif

#if defined(_RNA_DBG_LOCKS_)
    if (likely(0 == ret)) {
        rna_dbg_log(RNA_DBG_INFO,
                    "%s: %s, got mutex [%s]\n",
                    function,
                    info_string,
                    mutex_string);
    } else {
        rna_dbg_log(RNA_DBG_INFO,
                    "%s: %s, failed to get mutex [%s] error [%d]\n",
                    function,
                    info_string,
                    mutex_string,
                    ret);
    }
#endif

    return ret;
}
#define rna_hc_mutex_lock(__mutex) \
    rna_hc_mutex_lock_debug(__FUNCTION__, __location__, #__mutex, __mutex, \
                            0, FALSE)

#define rna_hc_mutex_timedlock(__mutex, timeout) \
    rna_hc_mutex_lock_debug(__FUNCTION__, __location__, #__mutex, __mutex, \
                            timeout, FALSE)

#define rna_hc_mutex_trylock(__mutex) \
    rna_hc_mutex_lock_debug(__FUNCTION__, __location__, #__mutex, __mutex, \
                            0, TRUE)

#define rna_hc_mutex_init(__mutex) \
    pthread_mutex_init(&(__mutex)->rm_mutex, NULL)

#define rna_hc_mutex_destroy(__mutex) \
    pthread_mutex_destroy(&(__mutex)->rm_mutex)

INLINE int rna_hc_mutex_unlock_debug(const char  *function,
                                     const char  *info_string,
                                     const char  *mutex_string,
                                     rna_hc_mutex_t *mutex)
{
    int ret;
#if defined(_LATENCY_DEBUG_)
	uint64_t held_time = (get_monotonic_timestamp() - mutex->rm_lock_acquire_time);

    if (held_time > NSEC_PER_SEC) {
        rna_dbg_log(RNA_DBG_WARN,
                    "%s: %s, mutex [%s] [%p]  held for [%lu] secs\n",
                    function,
                    info_string,
                    mutex_string,
                    mutex,
                    held_time/NSEC_PER_SEC);
    }
#endif

#if defined(_RNA_LOCK_ASSERT_)
    rna_debug_log_assert ((NULL != mutex) &&
                        (pthread_mutex_owner(&mutex->rm_mutex) == gettid()));
#endif

    ret = pthread_mutex_unlock(&mutex->rm_mutex);

#if defined(_RNA_DBG_LOCKS_)
    rna_dbg_log(RNA_DBG_INFO,
                "%s: %s, mutex [%s]\n",
                function,
                info_string,
                mutex_string);
#endif

    return ret;
}

#define rna_hc_mutex_unlock(__mutex)\
    rna_hc_mutex_unlock_debug(__FUNCTION__, __location__, #__mutex, __mutex) 

/* ---------------------------- end rna_hc_mutex ---------------------------- */
/* ------------------------------- rna_mutex -------------------------------- */

/*
 * rna_mutex support
 *      The rna_mutex implementation supports mutex functionality while
 *      using fewer system resources per mutex (less memory and no object
 *      handle).
 */

#define RNA_MUTEX_DEBUG    1
//#define RNA_MUTEX_LOG      1

typedef struct rna_mutex_s {
    atomic_t        rmx_state;
#define     RMX_STATE_UNLOCKED      0        // mutex is unlocked
#define     RMX_STATE_LOCKED        (1 << 0) // mutex is locked
#define     RMX_STATE_WAITERS       (1 << 1) // at least one waiter for mutex
    pid_t           rmx_owner;
#if defined(_LATENCY_DEBUG_)
    uint64_t        rmx_lock_acquire_time;
#endif
} rna_mutex_t;

#if defined(_LATENCY_DEBUG_)
#define RNA_MUTEX_INITIALIZER       \
    {                               \
        .rmx_state.value = 0,       \
        .rmx_owner       = 0,       \
        .rmx_lock_acquire_time = 0  \
    }
#else /* !_LATENCY_DEBUG_ */
#define RNA_MUTEX_INITIALIZER       \
    {                               \
        .rmx_state.value = 0,       \
        .rmx_owner       = 0        \
    }
#endif /* !_LATENCY_DEBUG_ */


void rna_mutex_init(rna_mutex_t *rmxp);
void rna_mutex_destroy(rna_mutex_t *rmxp);
#ifdef RNA_MUTEX_DEBUG
void rna_mutex_dump_stats(void);
#endif /* RNA_MUTEX_DEBUG */

#define rna_mutex_lock(rmxp) \
        rna_mutex_lock_debug(__FUNCTION__, __location__, #rmxp, (rmxp), -1)

#define rna_mutex_trylock(rmxp) \
        rna_mutex_lock_debug(__FUNCTION__, __location__, #rmxp, (rmxp), 0)

#define rna_mutex_timedlock(rmxp, secs) \
        rna_mutex_lock_debug(__FUNCTION__, __location__, #rmxp, (rmxp), (secs))

#define rna_mutex_unlock(rmxp) \
        rna_mutex_unlock_debug(__FUNCTION__, __location__, #rmxp, (rmxp))


INLINE gboolean
rna_mutex_held(rna_mutex_t *rmxp)
{
    return atomic_bit_is_set(&rmxp->rmx_state, RMX_STATE_LOCKED)
           && rmxp->rmx_owner == gettid();
}

#if defined(_RNA_LOCK_ASSERT_)
#define rna_mutex_assert_locked(rmxp) \
    rna_debug_log_assert(rna_mutex_held(rmxp))
#else
#define rna_mutex_assert_locked(rmxp)
#endif


#if defined(_RNA_LOCK_ASSERT_)
#define rna_mutex_assert_not_locker(rmxp) \
    rna_debug_log_assert(!rna_mutex_held(rmxp))
#else
#define rna_mutex_assert_not_locker(rmxp)
#endif


/*
 * The following definitions and variables are "internal" to the
 * fast_mutex utility, but need to defined here in the header to
 * support INLINE of the acquire/release routines.
 */

#ifdef RNA_MUTEX_LOG
#define RNA_RMX_LOG(rm, fmt, ...) \
        rna_dbg_log(RNA_DBG_MSG, "RMX: " fmt, __VA_ARGS__);
#else /* !RNA_MUTEX_LOG*/
#define RNA_RMX_LOG(rm, fmt, ...)
#endif /* !RNA_MUTEX_LOG */


typedef struct rna_mutex_obj_s {
    TAILQ_HEAD(rmo_waiter_list, _rna_mutex_wait_obj_s) rmo_waiters;
    pthread_mutex_t rmo_mutex;
#ifdef RNA_MUTEX_DEBUG
    atomic64_t rmo_active_users;    // current active users
    atomic64_t rmo_max_users;       // max simultaneous active users
    uint32_t   rmo_n_waiters;       // how many current waiters
    uint32_t   rmo_max_waiters;     // max concurrent waiters ever seen
#endif /* RNA_MUTEX_DEBUG */
} rna_mutex_obj_t;

extern rna_mutex_obj_t rna_mutex_objs[];

/*
 * NUM_GBL_MUTEX_OBJS is the size of the rna_mutex_objs[] global array.
 * This value must be a power-of-2 to work correctly with the GBL_MUTEX_MAP
 * macro.
 */
#define NUM_GBL_MUTEX_OBJS   4096               // must be a power-of-2
#define GBL_MUTEX_MAP(p) \
        (((unsigned long)(p) >> 4) & (NUM_GBL_MUTEX_OBJS - 1))

/*
 * rna_mutex_lock
 *      Acquire (or attempt to acquire) the specified mutex.
 *      A 'timeout_secs' value < then 0 means wait indefinitely,
 *      a value == 0 means don't wait, and a value > 0 indicates
 *      maximum time to wait (in seconds) for the mutex to become
 *      available.
 *
 * Return value: returns 0 on success or a positive errno on failure.
 */
INLINE int
rna_mutex_lock_debug(const char *function, const char *info_string,
                     const char *mutex_string, rna_mutex_t *rmxp,
                     int timeout_secs)
{
    _rna_mutex_wait_obj_t *rmwo, *t_rmwo;
    rna_mutex_obj_t  *rmo;
    struct timespec ts;
    gboolean more_waiters;
    uint32_t state, newstate;
    int ret;
#if defined(_LATENCY_DEBUG_)
	uint64_t start_time;
	uint64_t stop_time;
	uint64_t latency;
#endif
#ifdef PLATFORM_WINDOWS
    UNREFERENCED_PARAMETER(function);
    UNREFERENCED_PARAMETER(info_string);
    UNREFERENCED_PARAMETER(mutex_string);
#endif

    if (atomic_test_and_set(&rmxp->rmx_state, RMX_STATE_UNLOCKED,
                            RMX_STATE_LOCKED)) {
        // got it, we're good to go!
        RNA_RMX_LOG(rmxp, "%s: %s, mutex [%s] [%p] nowait\n", function,
                    info_string, mutex_string, rmxp);
        rmxp->rmx_owner = gettid();
#if defined(_LATENCY_DEBUG_)
        rmxp->rmx_lock_acquire_time = get_monotonic_timestamp();
#endif
        return 0;
    }

    if (0 == timeout_secs) {
        return EBUSY;
    }

    rmo = &rna_mutex_objs[GBL_MUTEX_MAP(rmxp)];

    if (timeout_secs >= 0) {
        clock_gettime(CLOCK_MONOTONIC, &ts);
        ts.tv_sec += timeout_secs;
    }

#if defined(_LATENCY_DEBUG_)
	start_time = get_monotonic_timestamp();
#endif

    ret = pthread_mutex_lock(&rmo->rmo_mutex);
    if (0 != ret) {
        rna_dbg_log(RNA_DBG_ERR, "%s: %s, mutex [%s] [%p] mutex lock failure"
                    ": ret=%d\n", function, info_string, mutex_string,
                    rmxp, ret);
        return ret;
    }

    do {
        state = atomic_get(&rmxp->rmx_state);
        if (RMX_STATE_UNLOCKED == state) {
            newstate = RMX_STATE_LOCKED;
        } else {
            newstate = RMX_STATE_LOCKED | RMX_STATE_WAITERS;
        }
    } while (state != newstate
             && !atomic_test_and_set(&rmxp->rmx_state, state, newstate));

    if (RMX_STATE_LOCKED != newstate) {

        rmwo = get_mutex_tls();

        rmwo->rmwo_data = rmxp;
        rmwo->rmwo_signaled = FALSE;

#ifdef RNA_MUTEX_DEBUG
        rmo->rmo_n_waiters++;
        if (rmo->rmo_n_waiters > rmo->rmo_max_waiters) {
            rmo->rmo_max_waiters = rmo->rmo_n_waiters;
        }
#endif /* RNA_MUTEX_DEBUG */
        TAILQ_INSERT_TAIL(&rmo->rmo_waiters, rmwo, rmwo_link);

        do {
            RNA_RMX_LOG(rmxp, "%s: %s, mutex [%s] [%p] rmwo [%p] waiting...\n",
                        function, info_string, mutex_string, rmxp, rmwo);
            ret = timeout_secs >= 0
                    ? pthread_cond_timedwait(&rmwo->rmwo_cv, &rmo->rmo_mutex,
                                             &ts)
                    : pthread_cond_wait(&rmwo->rmwo_cv, &rmo->rmo_mutex);
        } while (0 == ret && !rmwo->rmwo_signaled);

        if (rmwo->rmwo_signaled) {
            RNA_RMX_LOG(rmxp, "%s: %s, mutex [%s] [%p] signaled\n",
                        function, info_string, mutex_string, rmxp);
            ret = 0;        // just in case of race between timeout & granted...
        } else {
            RNA_RMX_LOG(rmxp, "%s: %s, mutex [%s] [%p] timeout? ret=%d\n",
                        function, info_string, mutex_string, rmxp, ret);
            /*
             * Need to reevaluate ce_mutex_wait_state status here, since we
             * are removing self out of the set of waiters.
             */
            t_rmwo = TAILQ_NEXT(rmwo, rmwo_link);
            TAILQ_REMOVE(&rmo->rmo_waiters, rmwo, rmwo_link);
#ifdef RNA_MUTEX_DEBUG
            rmo->rmo_n_waiters--;
#endif /* RNA_MUTEX_DEBUG */

            /* see if there are any more waiters associated with this lock */
            more_waiters = FALSE;
            for (; NULL != t_rmwo; t_rmwo = TAILQ_NEXT(t_rmwo, rmwo_link)) {
                if (t_rmwo->rmwo_data == rmxp) {
                    more_waiters = TRUE;
                    break;
                }
            }
            if (!more_waiters) {
                atomic_bit_clear(&rmxp->rmx_state, RMX_STATE_WAITERS);
            }
        }
    } else {
        RNA_RMX_LOG(rmxp, "%s: %s, mutex [%s] [%p] got mutex but nowait\n",
                    function, info_string, mutex_string, rmxp);
    }

    pthread_mutex_unlock(&rmo->rmo_mutex);

#if defined(_LATENCY_DEBUG_)
    stop_time = get_monotonic_timestamp();
    if (likely(stop_time > start_time)) { // avoid clock skew issues
        latency = stop_time - start_time;
        if (unlikely(latency > NSEC_PER_SEC)) {
            rna_dbg_log(RNA_DBG_WARN, "%s: %s, mutex [%s] [%p] took [%lu] "
                        "secs (timeout=%d): ret=%d\n",
                        function, info_string, mutex_string,
                        rmxp, latency/NSEC_PER_SEC, timeout_secs, ret);
        }
    }
#endif

    if (0 == ret) {
        rmxp->rmx_owner = gettid();
#if defined(_LATENCY_DEBUG_)
        rmxp->rmx_lock_acquire_time = stop_time;
#endif
    } else if (timeout_secs < 0) {
        rna_dbg_log(RNA_DBG_ERR, "%s: %s, mutex [%s] [%p] pthread_cond_wait "
                    "error: ret=%d\n", function, info_string, mutex_string,
                    rmxp, ret);
    }
    return ret;
}

INLINE void
rna_mutex_unlock_debug(const char *function, const char *info_string,
                       const char *mutex_string, rna_mutex_t *rmxp)
{
    _rna_mutex_wait_obj_t *rmwo, *next;
    rna_mutex_obj_t *rmo;
    gboolean found_waiter;
    gboolean more_waiters;
    int ret;
#if defined(_LATENCY_DEBUG_)
	uint64_t held_time = get_monotonic_timestamp() -
                         rmxp->rmx_lock_acquire_time;

    if (held_time > NSEC_PER_SEC) {
        rna_dbg_log(RNA_DBG_WARN,
                    "%s: %s, mutex [%s] [%p]  held for [%lu] secs\n",
                    function, info_string, mutex_string, rmxp,
                    held_time/NSEC_PER_SEC);
    }
#endif
#ifdef PLATFORM_WINDOWS
    UNREFERENCED_PARAMETER(function);
    UNREFERENCED_PARAMETER(info_string);
    UNREFERENCED_PARAMETER(mutex_string);
#endif

    rmxp->rmx_owner = 0;

    if (atomic_test_and_set(&rmxp->rmx_state, RMX_STATE_LOCKED,
                            RMX_STATE_UNLOCKED)) {
        /* no waiters, we're done! */
        RNA_RMX_LOG(rmxp, "%s: %s, mutex [%s] [%p] atomic release\n",
                    function, info_string, mutex_string, rmxp);
        return;
    }

    rmo = &rna_mutex_objs[GBL_MUTEX_MAP(rmxp)];
    ret = pthread_mutex_lock(&rmo->rmo_mutex);
    rna_debug_log_assert(0 == ret);

    /*
     * Normally if we get here there will be waiters. But it's not
     * guaranteed, because they could have timed out, so still need
     * to check!
     */
    if (atomic_bit_is_set(&rmxp->rmx_state, RMX_STATE_WAITERS)) {
        RNA_RMX_LOG(rmxp, "%s: %s, mutex [%s] [%p] releasing to waiters\n",
                    function, info_string, mutex_string, rmxp);

        found_waiter = FALSE;
        more_waiters = FALSE;

        TAILQ_FOREACH_SAFE(rmwo, next, &rmo->rmo_waiters, rmwo_link) {
            if (rmwo->rmwo_data == rmxp) {
                if (found_waiter) {
                    RNA_RMX_LOG(rmxp, "mutex [%s] [%p] has more waiters\n",
                                mutex_string, rmxp);
                    more_waiters = TRUE;
                    break;
                }
                RNA_RMX_LOG(rmxp, "%s: %s, mutex [%s] [%p] releasing to "
                            "rmwo [%p]\n", function, info_string,
                            mutex_string, rmxp, rmwo);
                TAILQ_REMOVE(&rmo->rmo_waiters, rmwo, rmwo_link);
#ifdef RNA_MUTEX_DEBUG
                rmo->rmo_n_waiters--;
#endif /* RNA_MUTEX_DEBUG */
                rmwo->rmwo_signaled = TRUE;
                pthread_cond_signal(&rmwo->rmwo_cv);
                found_waiter = TRUE;
            }
        }

        rna_log_assert(TRUE == found_waiter);
        if (!more_waiters) {
            atomic_bit_clear(&rmxp->rmx_state, RMX_STATE_WAITERS);
        }
    } else {
        /*
         * Only clear state bit if there are no waiters.
         * Otherwise, leave it set, to be inherited by the new owner.
         */
        RNA_RMX_LOG(rmxp, "%s: %s, mutex [%s] [%p] releasing (nowaiters)\n",
                    function, info_string, mutex_string, rmxp);
        rna_log_assert(atomic_bit_test_and_clear(&rmxp->rmx_state,
                                                 RMX_STATE_LOCKED));
    }

    ret = pthread_mutex_unlock(&rmo->rmo_mutex);
    rna_debug_log_assert(0 == ret);
}

/* ----------------------------- end rna_mutex ------------------------------ */
/* ========================= end rna mutex support ========================== */

void rna_strncpy(char* dest, const char* src, int n);
gboolean rna_file_rotate (const char* path, int *rotate_errno);

gboolean rna_verify_pid (const char * path,
						 uint64_t     pid,
                         gboolean     report_error);

#define MAX_DEBUG_TRIGGERS 100
gboolean dbg_set_trigger(void *item);
gboolean dbg_clear_trigger(void *item);
gboolean dbg_has_trigger(void *item);

gboolean check_mount (const char* path,
                      const char* fstype,
                      const char* opts,
                      gboolean exact_match);
 

#if defined(LINUX_USER)
INLINE char * rna_file_flag_string (int flags, char * string)
{
    int str_len = 0;

    str_len += sprintf (string, "(");

    if (O_ACCMODE == (flags & O_ACCMODE)) {
        str_len += sprintf ((string+str_len), " O_ACCMODE");
    }
    if (O_RDONLY == (flags & O_RDONLY)) {
        str_len += sprintf ((string+str_len), " O_RDONLY");
    }
    if (O_WRONLY == (flags & O_WRONLY)) {
        str_len += sprintf ((string+str_len), " O_WRONLY");
    }
    if (O_RDWR == (flags & O_RDWR)) {
        str_len += sprintf ((string+str_len), " O_RDWR");
    }
    if (O_CREAT == (flags & O_CREAT)) {
        str_len += sprintf ((string+str_len), " O_CREAT");
    }
    if (O_EXCL == (flags & O_EXCL)) {
        str_len += sprintf ((string+str_len), " O_EXCL");
    }
    if (O_NOCTTY == (flags & O_NOCTTY)) {
        str_len += sprintf ((string+str_len), " O_NOCTTY");
    }
    if (O_TRUNC == (flags & O_TRUNC)) {
        str_len += sprintf ((string+str_len), " O_TRUNC");
    }
    if (O_APPEND == (flags & O_APPEND)) {
        str_len += sprintf ((string+str_len), " O_APPEND");
    }
    if (O_NONBLOCK == (flags & O_NONBLOCK)) {
        str_len += sprintf ((string+str_len), " O_NONBLOCK");
    }
    if (O_SYNC == (flags & O_SYNC)) {
        str_len += sprintf ((string+str_len), " O_SYNC");
    }
    if (O_NDELAY == (flags & O_NDELAY)) {
        str_len += sprintf ((string+str_len), " O_NDELAY");
    }

    sprintf (string+str_len, ")");

    return string;
}
#endif	/* LINUX_USER */

int set_limit(unsigned resource, uint64_t value);

INLINE const char * rlimit_resource_string (int resource)
{
    const char * ret = "Unknown";

#ifdef LINUX_USER       /* xxx Not clear what to do on other systems */
    switch (resource) {
        case RLIMIT_AS: ret = "RLIMIT_AS"; break;
        case RLIMIT_CORE: ret = "RLIMIT_CORE"; break;
        case RLIMIT_CPU: ret = "RLIMIT_CPU"; break;
        case RLIMIT_DATA: ret = "RLIMIT_DATA"; break;
        case RLIMIT_FSIZE: ret = "RLIMIT_FSIZE"; break;
        case RLIMIT_LOCKS: ret = "RLIMIT_LOCKS"; break;
        case RLIMIT_MEMLOCK: ret = "RLIMIT_MEMLOCK"; break;
        case RLIMIT_MSGQUEUE: ret = "RLIMIT_MSGQUEUE"; break;
        case RLIMIT_NOFILE: ret = "RLIMIT_NOFILE"; break;
        case RLIMIT_NPROC: ret = "RLIMIT_NPROC"; break;
        case RLIMIT_RSS: ret = "RLIMIT_RSS"; break;
        case RLIMIT_SIGPENDING: ret = "RLIMIT_SIGPENDING"; break;
        case RLIMIT_STACK: ret = "RLIMIT_STACK"; break;
    }
#endif	/* LINUX_USER */
    return ret;
}

int rna_util_thread_join (rna_thread_t thread);
void rna_util_thread_cancel (rna_thread_t thread);
int rna_util_thread_cancel_join (rna_thread_t thread);

int get_cpu_core_count(void);

INLINE void rebuild_iov(struct msghdr *msg, int bytes_sent)
{
	struct iovec *iov = msg->msg_iov;
	int i;
	size_t iov_len = 0;
	
	for(i=0;i<msg->msg_iovlen;i++){
		if((iov_len + iov[i].iov_len) > bytes_sent){
			/* we are at the element */
			iov[i].iov_base += bytes_sent - iov_len;
			iov[i].iov_len -= bytes_sent - iov_len;
			msg->msg_iov = &iov[i];
			msg->msg_iovlen -= i;			
			break;
		}
		iov_len += iov[i].iov_len;
	}
	
	return;	
}

int rna_aligned_read(int fd, off_t offset, int len, void *addr);
int rna_aligned_write(int fd, off_t offset, int len, void *addr);

int rna_eventfd(unsigned int initval, int flags);

INLINE void print_rna_addr_xml(rna_addr_t   rna_addr, 
                                      char         *name,
                                      FILE         *info_file)
{
    fprintf(info_file, "<rna_addr ");
    if (NULL != name) {
        fprintf(info_file, "name=\"%s\" ", name);
    }
    fprintf(info_file, "dev_num=\"%u\" ", rna_addr.device_id.info.dev_num);
    fprintf(info_file, "fd=\"%u\" ", rna_addr.device_id.info.fd);
    fprintf(info_file, "base_addr=\"0x%"PRIx64"\" ", rna_addr.base_addr);    
    fprintf(info_file, "/>\n");
}

#define OOM_CMD_STRLEN 128
int set_oom_adj(int level);
int set_oom_unkillable(void);

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
            assert(FALSE);
        }
    }

    return ret;
}


/* 
 * What follows is a collection of allocation routines that follow a
 * particular naming convention:
 *
 * *_malloc:
 *    Given a pointer, allocate an object sized according to
 *    the sizeof the thing pointed to.  Using this for arrays
 *    is not recommended.
 *
 * *_zalloc:
 *    Same as rna_*_malloc, but zero out the object.
 *
 * *_sized_*
 *    Allocation routine that takes a size parameter, like ordinary malloc.
 *    Intended for variable-sized allocations and arrays.  Otherwise, use
 *    the non-sized version.
 *
 * *_datapath_*:
 *    (Documentation) This allocation is happening in a performance-critical
 *    code path, and should be replaced by a mempool of some sort
 *
 * *_unclassified_*
 *    (Documentation) I'm not sure if this allocation is happening in the
 *    datapath.  Please investigate and promote to *_datapath_* if necessary. 
 *
 * rna_free
 *    Wrapper for free.
 */
#define rna_datapath_malloc rna_malloc
#define rna_unclassified_malloc rna_malloc
#define rna_malloc(ptr) (TYPEOF(ptr)) _rna_malloc(sizeof(*(ptr)), __location__)

#define rna_datapath_zalloc rna_zalloc
#define rna_unclassified_zalloc rna_zalloc
#define rna_zalloc(ptr) (TYPEOF(ptr)) _rna_zalloc(sizeof(*(ptr)), __location__)

#define rna_datapath_sized_malloc rna_sized_malloc
#define rna_sized_malloc(size) _rna_malloc(size, __location__)

#define rna_datapath_sized_zalloc rna_sized_zalloc
#define rna_sized_zalloc(size) _rna_zalloc(size, __location__)

#define rna_datapath_array_malloc rna_array_malloc
#define rna_datapath_array_zalloc rna_array_zalloc
#define rna_array_malloc(count, ptr) (TYPEOF(ptr)) _rna_malloc((sizeof(ptr[0]) * count), __location__)
#define rna_array_zalloc(count, ptr) (TYPEOF(ptr)) _rna_zalloc((sizeof(ptr[0]) * count), __location__)

void * _rna_malloc(size_t size, const char *location);
void * _rna_zalloc(size_t size, const char *location);
int _rna_memalign(void **data, size_t alignment, size_t size, const char *location);

INLINE void _rna_free(void *data, const char *location)
{
    free(data);
}

#define rna_free(data) _rna_free(data, __location__)

#define rna_datapath_memalign rna_memalign
#define rna_memalign(ptr, align, size) _rna_memalign(ptr, align, size, __location__)

/* get statistics counters */
int get_malloc_fail(void);
int get_malloc_success(void);
int get_malloc_slow(void);

/* wrappers for glib slice functions */
#define rna_slice_sized_zalloc(size) _rna_slice_zalloc(size, __location__)
#define rna_slice_sized_malloc(size) _rna_slice_malloc(size, __location__)
#define rna_slice_sized_free _rna_slice_free

#define rna_slice_malloc(ptr) (TYPEOF(ptr)) _rna_slice_malloc(sizeof(*(ptr)), __location__)
#define rna_slice_zalloc(ptr) (TYPEOF(ptr)) _rna_slice_zalloc(sizeof(*(ptr)), __location__)
#define rna_slice_free(ptr) _rna_slice_free(sizeof(*(ptr)), ptr)

void * _rna_slice_zalloc(size_t size, const char *location);
void * _rna_slice_malloc(size_t size, const char *location);
void _rna_slice_free(size_t size, void *ptr);

extern int get_device_size(int fd, size_t *size, struct stat *stats);

typedef enum node_personality_e {
    NC_UNKNOWN = 0,
    NC_DAS,
    NC_SAN,
    NC_VSA,
    NC_WINVSA,
    NC_WINDOWS,
} node_personality_t;

extern node_personality_t get_node_personality(gboolean silent);
extern const char *get_node_personality_string(gboolean silent);

extern int get_if_paddr_by_name(char *ifname, char *buf, int buflen, gboolean silent);
extern int get_if_paddr_by_addr(uint32_t addr, uint32_t mask, char *buf, int buflen,
    gboolean silent);

#endif /* __KERNEL__ */

/*
 * ===========================================================================
 * The atomic_bit_XX functions operate atomically on a single bit in an atomic
 * variable.
 * ===========================================================================
 */
#ifdef __KERNEL__
/* #define free                kfree */
#endif /* __KERNEL__ */
/*
 * ===========================================================================
 * The atomic_bits_XX functions operate atomically on a set of bits in a 
 * uint32_t which need not be adjacent.
 * ===========================================================================
 */

/*
 * In case this file is compiled without optimization, which could otherwise
 * disable inlining...
 */


/*
 * Atomically set the specified bits in the specified atomic variable to
 * contain the specified new value.
 *
 * Arguments
 *     a          Pointer to the atomic variable containing the bits
 *     bitmask    Mask of the set of bits to set
 *     new_val    The new values of all the bits in bitmask.
 *
 */

INLINE void atomic_bits_set(atomic_t *a,
                                   uint32_t bitmask,
                                   uint32_t new_val)
                                   ALWAYS_INLINE;
INLINE void
atomic_bits_set(atomic_t *a, uint32_t bitmask, uint32_t new_val)
{
    uint32_t old_val;

    rna_debug_log_assert(0 == (new_val & ~bitmask));

    do {
        old_val = atomic_get(a);
    } while (unlikely(!atomic_test_and_set(a,
                                           old_val,
                                           (old_val & ~bitmask) | new_val)));
}


/*
 * Atomically check whether the value in the specified bits in the
 * specified atomic variable matches the specified match value, and if so,
 * store the specified new value in the bits.
 *
 * Arguments
 *     a          Pointer to the atomic variable containing the bitfield
 *     bitmask    Mask of the bits to test and change
 *     match      The old value to be checked in the bits.
 *     next       The new value to be stored in the bits.
 *
 * Returns:
 *     TRUE   The old value stored in the bits matched 'match' and the
 *            new value has been stored in the bits
 *     FALSE  The old value stored in the bits did not match 'match'.
 *
 */
#if defined(LINUX_USER) || defined(WINDOWS_USER)
INLINE gboolean atomic_bits_test_and_set(atomic_t *a,
                                                uint32_t bitmask,
                                                uint32_t match,
                                                uint32_t next)
                                                ALWAYS_INLINE;
INLINE gboolean
atomic_bits_test_and_set(atomic_t *a,
                         uint32_t bitmask,
                         uint32_t match,
                         uint32_t next)
{
    uint32_t old_val;

    rna_debug_log_assert(0 == (next & ~bitmask));
    rna_debug_log_assert(0 == (match & ~bitmask));

    do {
        old_val = atomic_get(a);
        if ((old_val & bitmask) != match) {
            return (FALSE);
        }
    } while (unlikely(!atomic_test_and_set(a,
                                           old_val,
                                           (old_val & ~bitmask) | next)));
    return (TRUE);
}
#endif  /* defined(LINUX_USER) || defined(WINDOWS_USER) */


/*
 * Atomically read the specified bits in the specified atomic variable and
 * return its content.
 *
 * Arguments
 *     a          Pointer to the atomic variable containing the bitfield
 *     bitmask    Mask of the bits to read
 *
 */
INLINE uint32_t atomic_bits_get(atomic_t *a,
                                       uint32_t bitmask)
                                       ALWAYS_INLINE;
INLINE uint32_t
atomic_bits_get(atomic_t *a, uint32_t bitmask)
{
    return (atomic_get(a) & bitmask);
}

#define atomic_bits_read atomic_bits_get


/*
 * ===========================================================================
 * The atomic_bitfield_XX functions operate atomically on a bitfield, which is
 * a series of adjacent bits in a uint32_t.
 * ===========================================================================
 */

/*
 * In case this file is compiled without optimization, which could otherwise
 * disable inlining...
 */



/*
 * Atomically set the specified bitfield in the specified atomic variable to
 * contain the specified new value.
 *
 * Arguments
 *     a          Pointer to the atomic variable containing the bitfield
 *     start_bit  The beginning position of the bitfield in the atomic variable
 *     numbits    The number of bits in the bitfield
 *     next       The new value to be stored in the bitfield.
 *
 * Example:
 * If a 'state' value is stored in bits 3 through 7 of atomic variable x,
 * and one wishes to atomically set the state to new_state, one would do
 * the following:
 *
 *     #define STATE_STARTBIT   3
 *     #define STATE_NUMBITS    5
 *
 *     atomic_bitfield_set(&x, STATE_STARTBIT, STATE_NUMBITS, new_state);
 */

INLINE void atomic_bitfield_set(atomic_t *a,
                                       int start_bit,
                                       int numbits,
                                       uint32_t next_val)
                                                ALWAYS_INLINE;

INLINE void
atomic_bitfield_set(atomic_t *a, int start_bit, int numbits, uint32_t new_val)
{
    uint32_t bitmask;
    uint32_t old_val;

    bitmask = ((1 << numbits) - 1) << start_bit;
    /* TODO: atomic_bits_set(a, bitmask, new_val) */
    do {
        old_val = atomic_get(a);
    } while (unlikely(!atomic_test_and_set(a,
                                           old_val,
                                           (old_val & ~bitmask) | 
                                           (new_val << start_bit))));
}

/*
 * Atomically check whether the value in the specified bitfield in the
 * specified atomic variable matches the specified match value, and if so,
 * store the specified new value in the bitfield.
 *
 * Arguments
 *     a          Pointer to the atomic variable containing the bitfield
 *     start_bit  The beginning position of the bitfield in the atomic variable
 *     numbits    The number of bits in the bitfield
 *     match      The old value to be checked in the bitfield.
 *     next       The new value to be stored in the bitfield.
 *
 * Returns:
 *     TRUE   The old value stored in the bitfield matched 'match' and the
 *            new value has been stored in the bitfield
 *     FALSE  The old value stored in the bitfield did not match 'match'.
 *
 * Example:
 * If a 'state' value is stored in bits 3 through 7 of atomic variable x,
 * and one wishes to atomically transition the state from old_state to
 * new_state, one would do the following:
 *
 *     #define STATE_STARTBIT   3
 *     #define STATE_NUMBITS    5
 *
 *     ret = atomic_bitfield_test_and_set(&x,
 *                                        STATE_STARTBIT,
 *                                        STATE_NUMBITS,
 *                                        old_state,
 *                                        new_state);
 */
INLINE gboolean atomic_bitfield_test_and_set(atomic_t *a,
                                                    int start_bit,
                                                    int numbits,
                                                    uint32_t match,
                                                    uint32_t next)
                                                ALWAYS_INLINE;

INLINE gboolean
atomic_bitfield_test_and_set(atomic_t *a,
                             int start_bit,
                             int numbits,
                             uint32_t match,
                             uint32_t next)
{
    uint32_t bitmask;
    uint32_t old_val;

    bitmask = ((1 << numbits) - 1) << start_bit;
    /* TODO: return(atomic_bits_test_and_set(a, bitmask, match, next)) */
    do {
        old_val = atomic_get(a);
        if (((old_val & bitmask) >> start_bit) != match) {
            return (FALSE);
        }
    } while (unlikely(!atomic_test_and_set(a,
                                           old_val,
                                           (old_val & ~bitmask) | (next << start_bit))));
    return (TRUE);
}

/*
 * Atomically read the specified bitfield in the specified atomic variable and
 * return its content.
 *
 * Arguments
 *     a          Pointer to the atomic variable containing the bitfield
 *     start_bit  The beginning position of the bitfield in the atomic variable
 *     numbits    The number of bits in the bitfield
 *
 * Example:
 * If a 'state' value is stored in bits 3 through 7 of atomic variable x,
 * and one wishes to atomically read the state, one would do the following:
 *
 *     #define STATE_STARTBIT   3
 *     #define STATE_NUMBITS    5
 *
 *     state = atomic_bitfield_get(&x, STATE_STARTBIT, STATE_NUMBITS);
 */
INLINE uint32_t atomic_bitfield_get(atomic_t *a,
                                           int start_bit,
                                           int numbits)
                                                ALWAYS_INLINE;
INLINE uint32_t
atomic_bitfield_get(atomic_t *a, int start_bit, int numbits)
{
    return ((atomic_get(a) >> start_bit) & ((1 << numbits) - 1));
}

#define atomic_bitfield_read atomic_bitfield_get

/*
 * Atomically increment the specified bitfield in the specified atomic
 * variable and return the incremented value.
 *
 * Arguments
 *     a          Pointer to the atomic variable containing the bitfield to be
 *                incremented
 *     start_bit  The beginning position of the bitfield in the atomic variable
 *     numbits    The number of bits in the bitfield
 *
 * Example:
 * If a 'count' value is stored in bits 8 through 15 of atomic variable x,
 * and one wishes to atomically increment the count, one would do the following:
 *
 *     #define COUNT_STARTBIT   8
 *     #define COUNT_NUMBITS    8
 *
 *     atomic_bitfield_inc(&x, COUNT_STARTBIT, COUNT_NUMBITS);
 */

INLINE uint32_t atomic_bitfield_inc(atomic_t *a,
                                           int start_bit,
                                           int numbits)
                                                ALWAYS_INLINE;
INLINE uint32_t
atomic_bitfield_inc(atomic_t *a, int start_bit, int numbits)
{
    uint32_t old_val;

    do {
        old_val = atomic_bitfield_get(a, start_bit, numbits);
    } while (unlikely(!atomic_bitfield_test_and_set(a,
                                                    start_bit,
                                                    numbits,
                                                    old_val,
                                                    old_val + 1)));
    /* Watch for overflow */
    rna_debug_log_assert(atomic_bitfield_get(a, start_bit, numbits) > old_val);

    return (old_val + 1);
}


/*
 * Atomically decrement the specified bitfield in the specified atomic
 * variable and return the decremented value.
 *
 * Arguments
 *     a          Pointer to the atomic variable containing the bitfield to be
 *                decremented
 *     start_bit  The beginning position of the bitfield in the atomic variable
 *     numbits    The number of bits in the bitfield
 *
 * Example:
 * If a 'count' value is stored in bits 8 through 15 of atomic variable x,
 * and one wishes to atomically decrement the count, one would do the following:
 *
 *     #define COUNT_STARTBIT   8
 *     #define COUNT_NUMBITS    8
 *
 *     atomic_bitfield_dec(&x, COUNT_STARTBIT, COUNT_NUMBITS);
 */

INLINE uint32_t atomic_bitfield_dec(atomic_t *a,
                                           int start_bit,
                                           int numbits)
                                                ALWAYS_INLINE;
INLINE uint32_t
atomic_bitfield_dec(atomic_t *a, int start_bit, int numbits)
{
    uint32_t old_val;

    do {
        old_val = atomic_bitfield_get(a, start_bit, numbits);
        /* Watch for underflow */
        rna_debug_log_assert(old_val > 0);
    } while (unlikely(!atomic_bitfield_test_and_set(a,
                                                    start_bit,
                                                    numbits,
                                                    old_val,
                                                    old_val - 1)));
    return (old_val - 1);
}

/*
 * ===========================================================================
 * The atomic_refcnt_XX functions provide a general-purpose ref-count facility.
 *
 * There are a couple of possible approaches for reference counting:
 *
 *     Primordial reference: A reference is taken when an object is created
 *     and released when the object is removed.  The object is freed when its
 *     reference count reaches zero.
 *
 *     Deleted bit: A bit in the reference count is designated as a mark for
 *     deletion.  Because this flag is in the same atomic_t as the reference
 *     count, it can be manipulated atomically w.r.t. the reference count.
 *     The ojject is freed only if its deleted bit is set AND its reference
 *     count reaches zero.  Since its perfectly OK for the reference count
 *     to be zero as long as the deleted bit isn't set, no reference needs
 *     to be acquired when the object is created or released when the object
 *     is removed.
 *
 * The 'deleted bit' approach has a couple of advantages over the 'primordial
 * reference' approach, including the following:
 *
 * 1. Using the 'deleted bit' approach, underflow errors that occur before a
 *    ref count is marked for deletion can be logged.  In the 'primordial
 *    reference' approach, the object is freed as soon as its ref count reaches
 *    zero, so an underflow error causes a reference to freed memory, which can
 *    corrupt the heap or cause a segfault.
 *
 * 2. The 'deleted bit' approach assures that the reference count reaches a
 *    state that causes the struct to be freed exactly once ('bounce' isn't
 *    possible).  In some 'primordial reference' approaches, a reference count
 *    can reach zero and be freed, but before/while being freed, another
 *    reference can be potentially taken (unless the implementation doesn't
 *    allow the reference count to be incremented from 0 to 1, and has a
 *    special case for setting the primordial reference when the object is
 *    created), which when released (assuming it doesn't segfault on the
 *    release) can result in a second free.
 *
 * These functions use a 'deleted bit' approach (see ATOMIC_REF_DELETED_FLAG).
 * ===========================================================================
 */

typedef void (*atomic_refcnt_free_fn) (atomic_t *refcnt_p, void *struct_p);

/*
 * In case this file is compiled without optimization, which could otherwise
 * disable inlining...
 */
#if defined(LINUX_USER) || defined(WINDOWS_USER)
INLINE gboolean atomic_refcnt_acquire(atomic_t *refcnt_p)
                                                ALWAYS_INLINE;
#endif  /* defined(LINUX_USER) || defined(WINDOWS_USER) */

#define atomic_refcnt_release(__arl_refcnt_p,__arl_struct_p,__arl_free_fn)          \
    atomic_refcnt_release_debug(__FUNCTION__,__location__,__arl_refcnt_p,__arl_struct_p,__arl_free_fn)

#if defined(LINUX_USER) || defined(WINDOWS_USER)
INLINE gboolean atomic_refcnt_is_deleted(atomic_t *refcnt_p)
                                                ALWAYS_INLINE;
#endif  /* defined(LINUX_USER) || defined(WINDOWS_USER) */


/*
 * Used to indicate when a re-counted structure has been marked for deletion.
 * Once this flag is set, the struct is freed when its ref count reaches zero.
 */
#define ATOMIC_REF_DELETED_FLAG     (1 << 31)

/*
 * Acquire a reference, unless the object has been marked for deletion.
 *
 * Returns:
 *     TRUE  if a reference has been acquired
 *     FALSE if a reference can not be acquired, because the object has been
 *           marked for deletion
 */



INLINE gboolean
atomic_refcnt_acquire(atomic_t *refcnt_p)
{
    int32_t refcnt;

    do {
        refcnt = atomic_get(refcnt_p);
        if (unlikely(refcnt & ATOMIC_REF_DELETED_FLAG)) {
            return (FALSE);
        }
        if (unlikely(ATOMIC_REF_DELETED_FLAG == (refcnt + 1))) {
            rna_dbg_log(RNA_DBG_ERR,
                        "Overflow error for refcnt_p [%p]\n", refcnt_p);
            return (FALSE);
        }
    } while (unlikely(!atomic_test_and_set(refcnt_p, refcnt, refcnt+1)));

    return (TRUE);
}

/*
 * Release a reference (and free the object, if it's marked for deletion and
 * this was its last reference).
 *
 * Arguments:
 *     refcnt_p     Pointer to the atomic_t reference counter
 *     struct_p     Pointer to the struct that contains the reference counter
 *     free_fn      Optional function to free the struct, after it's been
 *                  marked for deletion and its last reference has been dropped.
 *                  If NULL, free() is called to free the struct.
 */

INLINE void atomic_refcnt_release_debug(const char *function,
                                               const char *location,
                                               atomic_t *refcnt_p,
                                               void *struct_p,
                                               atomic_refcnt_free_fn free_fn)
                                                ALWAYS_INLINE;
INLINE void
atomic_refcnt_release_debug(const char         *function,
                            const char         *location,
                            atomic_t *refcnt_p,
                            void *struct_p,
                            atomic_refcnt_free_fn free_fn)
{
    int32_t refcnt;

#ifdef WINDOWS_KERNEL
	UNREFERENCED_PARAMETER(function);
	UNREFERENCED_PARAMETER(location);
#endif

    do {
        refcnt = atomic_get(refcnt_p);
        if (unlikely(0 == (refcnt & ~ATOMIC_REF_DELETED_FLAG))) {
            rna_dbg_log(RNA_DBG_ERR,
                        "[%s] [%s] Underflow error refcnt_p [%p] struct_p [%p]\n",
                        function, location, refcnt_p, struct_p);
            return;
        }
    } while (unlikely(!atomic_test_and_set(refcnt_p, refcnt, refcnt-1)));

    /*
     * If the ref count is marked for deletion and this was its last reference,
     * free its containing struct.
     */
    if (unlikely((ATOMIC_REF_DELETED_FLAG | 1) == refcnt)) {
        if (free_fn != NULL) {
            /* use the caller-supplied free function */
            (free_fn)(refcnt_p, struct_p);
        } else {
#ifdef WINDOWS_KERNEL
            /* How was struct_p allocated?  Difficult to track through linux
             * code so if ever hit in Windows kernel we can backtrack and fill
             * in appropriately.
             */
            NT_ASSERT(TRUE);
#else
            free(struct_p);
#endif /*WINDOWS_KERNEL */
        }
    }
}

/*
 * Mark a ref count for deletion (and free the object, if it has no references)
 *
 * Arguments:
 *     refcnt_p     Pointer to the atomic_t reference counter
 *     struct_p     Pointer to the struct that contains the reference counter
 *     free_fn      Optional function to free the struct, after it's been
 *                  marked for deletion and its last reference has been dropped.
 *                  If NULL, free() is called to free the struct.
 */

INLINE void atomic_refcnt_delete(atomic_t *refcnt_p,
                                        void *struct_p,
                                        atomic_refcnt_free_fn free_fn)
                                                ALWAYS_INLINE;
INLINE void
atomic_refcnt_delete(atomic_t *refcnt_p,
                     void *struct_p,
                     atomic_refcnt_free_fn free_fn)
{
    int32_t refcnt;

    do {
        refcnt = atomic_get(refcnt_p);
        if (unlikely(refcnt & ATOMIC_REF_DELETED_FLAG)) {
            /* don't double-delete, as that could cause a 'bounce' */
            return;
        }
    } while (unlikely(!atomic_test_and_set(refcnt_p,
                                           refcnt,
                                           refcnt | ATOMIC_REF_DELETED_FLAG)));

    /*
     * If the ref count was zero before being marked for deletion, free its
     * containing struct.
     */
    if (unlikely(0 == refcnt)) {
        if (free_fn != NULL) {
            /* use the caller-supplied free function */
            (free_fn)(refcnt_p, struct_p);
        } else {
#ifdef WINDOWS_KERNEL
            /* How was struct_p allocated?  Difficult to track through linux
             * code so if ever hit in Windows kernel we can backtrack and fill
             * in appropriately.
             */
            NT_ASSERT(TRUE);
#else
            free(struct_p);
#endif /* WINDOWS_KERNEL */
        }
    }
}

/*
 * Return a boolean indicating whether the object has been marked for
 * deletion.
 *
 * Returns:
 *     TRUE  if a object has been marked for deletion
 *     FALSE flase if the object has not been marked for deletion.
 *
 *     (Note that while a return value of TRUE is a stable condition,
 *     a return value of FALSE is just a point-in-time snapsot of the state).
 */
INLINE gboolean
atomic_refcnt_is_deleted(atomic_t *refcnt_p)
{
    return (atomic_get(refcnt_p) & ATOMIC_REF_DELETED_FLAG) != 0;
}

/*
 * Free resources allocated for queued logging.
 */
void rna_dbg_queued_logging_destroy (void);

#ifdef __KERNEL__



#endif /* __KERNEL__ */


#endif /* defined(LINUX_KERNEL) || defined(WINDOWS_KERNEL) */

