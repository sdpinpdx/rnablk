/**
 * <rna_locks.h> - Dell Fluid Cache block driver
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

#if defined(WINDOWS_KERNEL)
#include <wdm.h>
#elif defined(LINUX_KERNEL)
#include <linux/spinlock.h>
#include <linux/mutex.h>
#endif

// spinlocks stuff
#if defined(WINDOWS_KERNEL) || defined(LINUX_KERNEL)
typedef struct {
    int pid; // thread ID of owner
#ifdef WINDOWS_KERNEL
    KSPIN_LOCK    lock;
    KIRQL        oldirql;
#else
    spinlock_t    lock; // lock
#endif
} rna_spinlock_t;
#endif  /* WINDOWS_KERNEL || LINUX_KERNEL */


#if defined(LINUX_KERNEL) || defined(WINDOWS_KERNEL)
typedef struct {
    boolean         sp_shutting_down_flag;
    rna_spinlock_t  sp_spinlock;
} rna_service_spinlock_t;

#else
typedef struct {
    gboolean       sp_shutting_down_flag;
    rna_spnlck_t  sp_spinlock;
} rna_service_spinlock_t;
#endif

#if defined(LINUX_KERNEL) || defined(LINUX_USER)
typedef long unsigned int irq_flag_t;   /* uint64_t is equiv, but fails typecheck */
#define PRIxIRQ         "lx"
#else   /* LINUX_KERNEL || LINUX_USER */
typedef uint64_t irq_flag_t;
#define PRIxIRQ         PRIx64
#endif  /* LINUX_KERNEL || LINUX_USER */

// these have to be a macro for instruction pointer to work
#ifdef CHECK_STATE_LOCKS
#ifdef NETLINK_LOGGING
#define rna_spin_lock(rna_lock)\
	if (unlikely (log_nl & LOG_SLOCK)) {\
        printnl_atomic("[%s] [%s] getting spin_lock lock [%s] [%p] owner pid[%"RNA_PID_T_FMT"] current pid[%"RNA_PID_T_FMT"]\n",\
                       __FUNCTION__,\
                       __location__,\
                       #rna_lock,\
                       &rna_lock,\
                       rna_lock.pid,\
                       current->pid);\
    }\
    spin_lock(&rna_lock.lock);\
    rna_lock.pid = current->pid;\
	if (unlikely (log_nl & LOG_SLOCK)) {\
        printnl_atomic("[%s] [%s] got spin_lock lock [%s] [%p] owner pid[%"RNA_PID_T_FMT"] current pid[%"RNA_PID_T_FMT"]\n",\
                       __FUNCTION__,\
                       __location__,\
                       #rna_lock,\
                       &rna_lock,\
                       rna_lock.pid,\
                       current->pid);\
    }
#else
#define rna_spin_lock(rna_lock)\
    spin_lock(&rna_lock.lock);\
    rna_lock.pid = current->pid;
#endif // NETLINK_LOGGING
#else
#ifdef WINDOWS_KERNEL
#define rna_spin_lock(rna_lock)\
    KeAcquireSpinLock(&rna_lock.lock, &rna_lock.oldirql);    
#else
#define rna_spin_lock(rna_lock)\
    spin_lock(&rna_lock.lock);
#endif /* WINDOWS_KERNEL */
#endif // CHECK_STATE_LOCKS


#ifdef CHECK_STATE_LOCKS
#ifdef NETLINK_LOGGING
#define rna_spin_unlock(rna_lock)\
    if (unlikely (current->pid != rna_lock.pid)) {\
        rna_printk(KERN_ERR,\
                   "[%s] [%s] bad spin_unlock lock [%s] [%p] owner pid[%"RNA_PID_T_FMT"] current pid[%"RNA_PID_T_FMT"]\n",\
                   __FUNCTION__,\
                   __location__,\
                   #rna_lock,\
                   &rna_lock,\
                   rna_lock.pid, \
                   current->pid);\
    } else {\
        if (unlikely (log_nl & LOG_SLOCK)) {\
            printnl_atomic("[%s] [%s] spin_unlock lock [%s] [%p] owner pid[%"RNA_PID_T_FMT"] current pid[%"RNA_PID_T_FMT"]\n",\
                           __FUNCTION__,\
                           __location__,\
                           #rna_lock,\
                           &rna_lock,\
                           rna_lock.pid, \
                           current->pid);\
        }\
        rna_lock.pid = 0;\
        spin_unlock(&rna_lock.lock);\
        BUG_ON(preempt_count() < 0);\
    }
#else
#define rna_spin_unlock(rna_lock)\
    if (unlikely (current->pid != rna_lock.pid)) {\
        rna_printk(KERN_ERR,\
                   "[%s] [%s] bad spin_unlock lock [%p] owner pid[%"RNA_PID_T_FMT"] current pid[%"RNA_PID_T_FMT"]\n",\
                   __FUNCTION__,\
                   __location__,\
                   &rna_lock,\
                   rna_lock.pid, \
                   current->pid);\
    } else {\
        rna_lock.pid = 0;\
        spin_unlock(&rna_lock.lock);\
        BUG_ON(preempt_count() < 0);\
    }
#endif // NETLINK_LOGGING
#else
#ifdef WINDOWS_KERNEL
#define rna_spin_unlock(rna_lock)\
    KeReleaseSpinLock(&rna_lock.lock, rna_lock.oldirql);    
#else
#define rna_spin_unlock(rna_lock)\
    spin_unlock(&rna_lock.lock);
#endif /* WINDOWS_KERNEL */
#endif // CHECK_STATE_LOCKS

#ifdef WINDOWS_KERNEL
#define rna_spin_lock_init(rna_lock)\
    KeInitializeSpinLock(&rna_lock.lock);\
    rna_lock.pid = 0;
#else
#define rna_spin_lock_init(rna_lock)\
    spin_lock_init(&rna_lock.lock);\
    rna_lock.pid = 0;
#endif /* WINDOWS_KERNEL */

#ifdef WINDOWS_KERNEL
#define rna_bug_on_unlocked(rna_lock)  \
    BUG_ON(KeTestSpinLock(&rna_lock.lock));
#else
#define rna_bug_on_unlocked(rna_lock) \
    BUG_ON(!spin_is_locked(&rna_lock.lock));
#endif /* WINDOWS_KERNEL */

#ifdef CHECK_STATE_LOCKS
#ifdef NETLINK_LOGGING
#define rna_spin_lock_irqsave(rna_lock, flags)\
	if (unlikely (log_nl & LOG_SLOCK)) {\
        printnl_atomic("[%s] [%s] getting rna_spin_lock_irqsave lock [%s] [%p] owner pid[%"RNA_PID_T_FMT"] current pid[%"RNA_PID_T_FMT"]\n",\
                       __FUNCTION__,\
                       __location__,\
                       #rna_lock,\
                       &rna_lock,\
                       rna_lock.pid, \
                       current->pid);\
    }\
    spin_lock_irqsave(&rna_lock.lock, flags);\
    rna_lock.pid = current->pid;\
	if (unlikely (log_nl & LOG_SLOCK)) {\
        printnl_atomic("[%s] [%s] got rna_spin_lock_irqsave lock [%s] [%p] flags [0x%lx] owner pid[%"RNA_PID_T_FMT"] current pid[%"RNA_PID_T_FMT"]\n",\
                       __FUNCTION__,\
                       __location__,\
                       #rna_lock,\
                       &rna_lock,\
                       ((long)(flags)),         \
                       rna_lock.pid, \
                       current->pid);           \
    }
#else
#define rna_spin_lock_irqsave(rna_lock, flags)\
    spin_lock_irqsave(&rna_lock.lock, flags);\
    rna_lock.pid = current->pid;
#endif // NETLINK_LOGGING
#else
#ifdef WINDOWS_KERNEL
/* Note, Windows doesn't have the concept of disabling interrupts to block.
 * the normal KeAcquireSpinLock does raise the IRQL to Dispatch which should 
 * have the desired behavior like Linux, but we may need to rework this */
#define rna_spin_lock_irqsave(rna_lock, flags)\
	UNREFERENCED_PARAMETER(flags);\
    KeAcquireSpinLock(&rna_lock.lock, &rna_lock.oldirql);    
#else
#define rna_spin_lock_irqsave(rna_lock, flags)\
    spin_lock_irqsave(&rna_lock.lock, flags);
#endif /* WINDOWS_KERNEL */
#endif // CHECK_STATE_LOCKS

#ifdef CHECK_STATE_LOCKS
#ifdef NETLINK_LOGGING
#define rna_spin_unlock_irqrestore(rna_lock, flags)\
    if (unlikely ((0 != rna_lock.pid) && (current->pid != rna_lock.pid))) {\
        rna_printk(KERN_ERR,\
                   "[%s] [%s] bad spin_unlock_irqrestore lock [%s] [%p] flags [0x%lx] owner pid[%"RNA_PID_T_FMT"] current pid[%"RNA_PID_T_FMT"]\n",\
                   __FUNCTION__,\
                   __location__,\
                   #rna_lock,\
                   &rna_lock,\
                   ((long)(flags)),       \
                   rna_lock.pid, \
                   current->pid);               \
    } else {\
        if (unlikely (log_nl & LOG_SLOCK)) {\
            printnl_atomic("[%s] [%s] spin_unlock_irqrestore lock [%s] [%p] flags [0x%lx] owner pid[%"RNA_PID_T_FMT"] current pid[%"RNA_PID_T_FMT"]\n",\
                           __FUNCTION__,\
                           __location__,\
                           #rna_lock,\
                           &rna_lock,\
                           ((long)(flags)),     \
                           rna_lock.pid, \
                           current->pid);\
        }\
        rna_lock.pid = 0;\
        spin_unlock_irqrestore(&rna_lock.lock, flags);\
    }
#else
#define rna_spin_unlock_irqrestore(rna_lock, flags)\
    if (unlikely ((0 != rna_lock.pid) && (current->pid != rna_lock.pid))) {\
        rna_printk(KERN_ERR,\
                   "[%s] [%s] bad spin_unlock_irqrestore lock [%p] flags [0x%lx] owner pid[%"RNA_PID_T_FMT"] current pid[%"RNA_PID_T_FMT"]\n",\
                   __FUNCTION__,\
                   __location__,\
                   &rna_lock,\
                   ((long)(flags)),             \
                   rna_lock.pid, \
                   current->pid);\
    } else {\
        rna_lock.pid = 0;\
        spin_unlock_irqrestore(&rna_lock.lock, flags);\
    }
#endif // NETLINK_LOGGING
#else
#ifdef WINDOWS_KERNEL
#define rna_spin_unlock_irqrestore(rna_lock, flags)\
    KeReleaseSpinLock(&(rna_lock).lock, (rna_lock).oldirql);    
#else
#define rna_spin_unlock_irqrestore(rna_lock, flags)\
    spin_unlock_irqrestore(&(rna_lock).lock, flags);
#endif /* WINDOWS_KERNEL */
#endif // CHECK_STATE_LOCKS

#ifdef WINDOWS_KERNEL
#define rna_spin_trylock(rna_lock)\
    KeAcquireSpinLock(&(rna_lock).lock, &(rna_lock).oldirql);    

#else
#define rna_spin_trylock(rna_lock)\
    spin_trylock(&(rna_lock).lock);
#endif /* WINDOWS_KERNEL */

#ifdef WINDOWS_KERNEL
#define rna_spin_in_stack_lock_irqsave(rna_lock, flags)\
    KeAcquireInStackQueuedSpinLock(&(rna_lock.lock), &flags);
#else
#define rna_spin_in_stack_lock_irqsave(rna_lock, flags)\
    rna_spin_lock_irqsave(rna_lock, flags);
#endif /* WINDOWS_KERNEL */

#ifdef WINDOWS_KERNEL
#define rna_spin_in_stack_unlock_irqrestore(rna_lock, flags)\
    UNREFERENCED_PARAMETER(rna_lock);\
    KeReleaseInStackQueuedSpinLock(&flags);   
#else
#define rna_spin_in_stack_unlock_irqrestore(rna_lock, flags)\
    rna_spin_unlock_irqrestore(rna_lock, flags);
#endif /* WINDOWS_KERNEL */


/* ----------------  Spinlock functions  -------------- */
#if defined(LINUX_KERNEL)  || defined (WINDOWS_KERNEL)

INLINE void
rna_service_spinlock_init(rna_service_spinlock_t *spinlock_ptr)
{
    spinlock_ptr->sp_shutting_down_flag = FALSE;
    rna_spin_lock_init(spinlock_ptr->sp_spinlock);
}

/*
 * Returns:
 *  TRUE if the spinlock is locked
 *  FALSE if the spinlock is shutting down
 */
INLINE gboolean
rna_service_spinlock_acquire(rna_service_spinlock_t *spinlock_ptr,
                             irq_flag_t          *flags_ptr)
{
    rna_spin_lock_irqsave(spinlock_ptr->sp_spinlock, *flags_ptr);

    UNREFERENCED_PARAMETER(flags_ptr);

    if (spinlock_ptr->sp_shutting_down_flag) {
        rna_spin_unlock_irqrestore(spinlock_ptr->sp_spinlock, *flags_ptr);
        return (FALSE);
    } else {
        return (TRUE);
    }
}


INLINE void
rna_service_spinlock_release(rna_service_spinlock_t *spinlock_ptr,
                             irq_flag_t          *flags_ptr)
{
    UNREFERENCED_PARAMETER(flags_ptr); // MSFT flags this as unused, but look... it's right there... stupid compiler....
    rna_spin_unlock_irqrestore(spinlock_ptr->sp_spinlock, *flags_ptr);
}


#ifdef WINDOWS_KERNEL
/* Windows kernel drives have a feature called In-Stack Queued spinlocks.  These are 
 * preferred over regular spinlocks.  They are acquired slightly differnently and therefore
 * created basic acquire/release functions to support.
 *
 *  Note:  These are Windows Kernel only features.
 */

/*
 * Returns:
 *  TRUE if the spinlock is locked
 *  FALSE if the spinlock is shutting down
 */
INLINE gboolean
rna_service_instkqd_spinlock_acquire(rna_service_spinlock_t *spinlock_ptr,
                                     KLOCK_QUEUE_HANDLE *lockHandle
                                     )
{
    KeAcquireInStackQueuedSpinLock(&(spinlock_ptr->sp_spinlock).lock,lockHandle);

    if (spinlock_ptr->sp_shutting_down_flag) {
        KeReleaseInStackQueuedSpinLock (lockHandle);
        return (FALSE);
    } else {
        return (TRUE);
    }
}


INLINE void
rna_service_instkqd_spinlock_release(KLOCK_QUEUE_HANDLE *lockHandle )
{
    KeReleaseInStackQueuedSpinLock (lockHandle);
}

#endif /* WINDOWS_KERNEL */

/*
 * Acquire the specified spinlock and mark it as shutting down.  This routine
 * is called before beginning to tear down the objects guarded by the spinlock.
 */
INLINE void
rna_service_spinlock_acquire_shutdown(rna_service_spinlock_t *spinlock_ptr,
                                      irq_flag_t          *flags_ptr)
{
    rna_service_spinlock_acquire(spinlock_ptr, flags_ptr);
    spinlock_ptr->sp_shutting_down_flag = TRUE;
}

#endif /* ifdef LINUX_KERNEL or WINDOWS_KERNEL  */

#if defined (LINUX_USER) || defined (WINDOWS_USER )

INLINE void
rna_service_spinlock_init(rna_service_spinlock_t *spinlock_ptr)
{
    spinlock_ptr->sp_shutting_down_flag = FALSE;
    rna_spinlock_init(&spinlock_ptr->sp_spinlock);
}

/*
 * Returns:
 *  TRUE if the spinlock is locked
 *  FALSE if the spinlock is shutting down
 */
INLINE gboolean
rna_service_spinlock_acquire(rna_service_spinlock_t *spinlock_ptr,
                             irq_flag_t          *flags)
{
    (void)flags;
    rna_spinlock_acquire(&spinlock_ptr->sp_spinlock);

    if (spinlock_ptr->sp_shutting_down_flag) {
        rna_spinlock_release(&spinlock_ptr->sp_spinlock);
        rna_dbg_log(RNA_DBG_VERBOSE, "shutting down\n");
        return (FALSE);
    } else {
        return (TRUE);
    }
}


INLINE void
rna_service_spinlock_release(rna_service_spinlock_t *spinlock_ptr,
                             irq_flag_t          *flags)
{
    (void)flags;
    rna_spinlock_release(&spinlock_ptr->sp_spinlock);
}


/*
 * Acquire the specified spinlock and mark it as shutting down.  This routine
 * is called before starting to tear down the objects guarded by the spinlock.
 */
INLINE void
rna_service_spinlock_acquire_shutdown(rna_service_spinlock_t *spinlock_ptr,
                                      irq_flag_t          *flags)
{
    rna_service_spinlock_acquire(spinlock_ptr, flags);
    spinlock_ptr->sp_shutting_down_flag = TRUE;
}

#endif /* ifdef LINUX_USER or WINDOWS_USER */
