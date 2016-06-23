/**
 * <rna_mutex.h> - Dell Fluid Cache block driver
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
#include <linux/mutex.h>
#endif

// Mutex stuff
#ifdef NO_KERNEL_MUTEX

typedef struct {
    gboolean          mu_shutting_down_flag;
    struct semaphore mu_mutex;
} rna_service_mutex_t;

INLINE void
rna_service_mutex_destroy(rna_service_mutex_t *mutex)
{
    mutex_destroy(&mutex->mu_mutex);
}
#define rna_service_mutex_destroy    mutex_destroy

#else

typedef struct {
    boolean          mu_shutting_down_flag;
#ifdef WINDOWS_KERNEL
    KMUTEX  mu_mutex;
#else
    struct mutex     mu_mutex;
#endif /* WINDOWS_KERNEL */
} rna_service_mutex_t;

#define rna_service_mutex_destroy(lock)

#endif  // !NO_KERNEL_MUTEX

/*
 * The following is a macro rather than an inline function to try to avoid
 * lockdep 'possible recursive lock' false positives (see MVP-5368).
 */
#ifdef WINDOWS_KERNEL
#define rna_service_mutex_init(mutex)          \
    (mutex)->mu_shutting_down_flag = FALSE;    \
    KeInitializeMutex (&(mutex)->mu_mutex, 0);

#else
#define rna_service_mutex_init(mutex)          \
    (mutex)->mu_shutting_down_flag = FALSE;    \
    mutex_init(&(mutex)->mu_mutex);
#endif /* WINDOWS_KERNEL*/

/*
 * Returns:
 *  TRUE if the mutex is locked
 *  FALSE if the mutex is shutting down
 */
INLINE boolean
rna_service_mutex_lock(rna_service_mutex_t *mutex)
{
#ifdef WINDOWS_KERNEL
    KeWaitForMutexObject(&mutex->mu_mutex,
                         Executive,
                         KernelMode,
                         FALSE,
                         NULL);
#else
    mutex_lock(&mutex->mu_mutex);
#endif /* WINDOWS_KERNEL */

    if (mutex->mu_shutting_down_flag) {
#ifdef WINDOWS_KERNEL
        KeReleaseMutex(&mutex->mu_mutex, FALSE);
#else
        mutex_unlock(&mutex->mu_mutex);
#endif /* WINDOWS_KERNEL */
        return (FALSE);
    } else {
        return (TRUE);
    }
}


/*
 * Returns:
 *  TRUE if the mutex is locked
 *  FALSE if the mutex is not locked or is shutting down
 */
INLINE boolean
rna_service_mutex_trylock(rna_service_mutex_t *mutex)
{
    /* Windows doesn't have a 'trylock' mutex, so using the basic waitforsingleobject */
#ifdef WINDOWS_KERNEL
    NTSTATUS status = STATUS_SUCCESS;

    status = KeWaitForMutexObject(&mutex->mu_mutex,
                         Executive,
                         KernelMode,
                         FALSE,
                         NULL);
    if(NT_SUCCESS(status) ) {
#else
    if (mutex_trylock(&mutex->mu_mutex)) {
#endif /* WINDOWS_KERNEL */
        /* mutex_trylock succeeded, make sure we're not shutting down */
        if (mutex->mu_shutting_down_flag) {
#ifdef WINDOWS_KERNEL
            KeReleaseMutex(&mutex->mu_mutex, FALSE);
#else
            mutex_unlock(&mutex->mu_mutex);
#endif /* WINDOWS_KERNEL */
            return (FALSE);
        } else {
            return (TRUE);
        }
    } else {
        return (FALSE);
    }
}


INLINE void
rna_service_mutex_unlock(rna_service_mutex_t *mutex)
{
#ifdef WINDOWS_KERNEL
    KeReleaseMutex(&mutex->mu_mutex, FALSE);
#else
    mutex_unlock(&mutex->mu_mutex);
#endif /* WINDOWS_KERNEL */
}


/*
 * Lock the specified mutex and mark it as shutting down.  This routine is
 * called before beginning to tear down the objects guarded by the mutex.
 */
INLINE void
rna_service_mutex_lock_shutdown(rna_service_mutex_t *mutex)
{
#ifdef WINDOWS_KERNEL
    NTSTATUS status = STATUS_SUCCESS;

    status = KeWaitForMutexObject(&mutex->mu_mutex,
                         Executive,
                         KernelMode,
                         FALSE,
                         NULL);
#else
    mutex_lock(&mutex->mu_mutex);
#endif /* WINDOWS_KERNEL */
    mutex->mu_shutting_down_flag = TRUE;
}


INLINE void
rna_service_assert_locked(rna_service_mutex_t *mutex)
{
#if defined (LINUX_USER) || defined (WINDOWS_USER )
    BUG_ON(mutex->mu_mutex.count > 0);
#else
#ifdef WINDOWS_KERNEL
#ifdef DBG
    ASSERT(!KeReadStateMutex(&mutex->mu_mutex));
#else
    DECLARE_UNUSED(mutex);
#endif
#else
    BUG_ON(!mutex_is_locked(&mutex->mu_mutex));
#endif /* WINDOWS_KERNEL */
#endif
}

INLINE int rna_service_mutex_is_locked(rna_service_mutex_t *mutex)
{
#if defined (LINUX_USER) || defined (WINDOWS_USER )
    BUG_ON(mutex->mu_mutex.count > 0);
#else
#ifdef WINDOWS_KERNEL
    return (!KeReadStateMutex(&mutex->mu_mutex));
#else
    return mutex_is_locked(&mutex->mu_mutex);
#endif /* WINDOWS_KERNEL */
#endif
}