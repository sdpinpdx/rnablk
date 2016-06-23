/**
 * <rna_block_mutex.h> - Dell Fluid Cache block driver
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
#include "rna_mutex.h"
#endif

#ifdef WINDOWS_KERNEL
typedef struct {
    boolean          mu_shutting_down_flag;
    KSPIN_LOCK mu_mutex;
} rna_block_mutex_t;
#else
#define rna_block_mutex_t rna_service_mutex_t
#endif /*WINDOWS_KERNEL*/

#ifdef WINDOWS_KERNEL
typedef KLOCK_QUEUE_HANDLE lockstate_t;
#else
typedef unsigned long lockstate_t;
#endif /*WINDOWS_KERNEL*/

#ifdef WINDOWS_KERNEL
typedef KLOCK_QUEUE_HANDLE mutexstate_t;
#else
typedef struct empty_struct{
} empty_struct_t;
typedef empty_struct_t mutexstate_t;
#endif /*WINDOWS_KERNEL*/

#define rna_block_mutex_destroy(lock)

#ifdef WINDOWS_KERNEL
#define rna_block_mutex_init(mutex)          \
    (mutex)->mu_shutting_down_flag = FALSE;    \
    KeInitializeSpinLock(&(mutex)->mu_mutex);

#else
#define rna_block_mutex_init(mutex)          \
    rna_service_mutex_init(mutex);
#endif /* WINDOWS_KERNEL*/

/*
 * Returns:
 *  TRUE if the mutex is locked
 *  FALSE if the mutex is shutting down
 */
#ifdef WINDOWS_KERNEL
INLINE boolean
rna_block_mutex_lock(rna_block_mutex_t *mutex, mutexstate_t * pLockHandle)
{
    KeAcquireInStackQueuedSpinLock(&(mutex->mu_mutex), pLockHandle);
    if (mutex->mu_shutting_down_flag) {
        KeReleaseInStackQueuedSpinLock(pLockHandle);
        return (FALSE);
    } else {
        return (TRUE);
    }
}
#else
#define rna_block_mutex_lock(mutex, lockHandle) \
    rna_service_mutex_lock(mutex);
#endif

/*
 * Returns:
 *  TRUE if the mutex is locked
 *  FALSE if the mutex is not locked or is shutting down
 */
#ifdef WINDOWS_KERNEL
INLINE boolean
rna_block_mutex_trylock(rna_block_mutex_t *mutex, mutexstate_t * pLockHandle)
{
    /* Windows doesn't have a 'trylock' mutex, so using the basic waitforsingleobject */
    NTSTATUS status = STATUS_SUCCESS;

    KeAcquireInStackQueuedSpinLock(&(mutex->mu_mutex), pLockHandle);

    if(NT_SUCCESS(status) ) {
        if (mutex->mu_shutting_down_flag) {
            KeReleaseInStackQueuedSpinLock(pLockHandle);
            return (FALSE);
        } else {
            return (TRUE);
        }
    } else {
        return (FALSE);
    }
}
#else
#define rna_block_mutex_trylock(mutex, pLockHandle)\
    return rna_service_mutex_trylock(mutex);
#endif /* WINDOWS_KERNEL */       

#ifdef WINDOWS_KERNEL
INLINE void
rna_block_mutex_unlock(rna_block_mutex_t *mutex, mutexstate_t * pLockHandle)
{

    UNREFERENCED_PARAMETER(mutex);
    KeReleaseInStackQueuedSpinLock(pLockHandle);

}
#else
#define rna_block_mutex_unlock(mutex, pLockHandle)\
        rna_service_mutex_unlock(mutex);
#endif /* WINDOWS_KERNEL */

/*
 * Lock the specified mutex and mark it as shutting down.  This routine is
 * called before beginning to tear down the objects guarded by the mutex.
 */
#ifdef WINDOWS_KERNEL
INLINE void
rna_block_mutex_lock_shutdown(rna_block_mutex_t *mutex, mutexstate_t * pLockHandle)
{
    KeAcquireInStackQueuedSpinLock(&(mutex->mu_mutex), pLockHandle);
    mutex->mu_shutting_down_flag = TRUE;
}
#else
#define rna_block_mutex_lock_shutdown(mutex, pLockHandle)\
    rna_service_mutex_lock_shutdown(mutex);
#endif /* WINDOWS_KERNEL */


INLINE void
rna_block_mutex_assert_locked(rna_block_mutex_t *mutex)
{
#ifdef WINDOWS_KERNEL
    UNREFERENCED_PARAMETER(mutex);
    ASSERT(!KeTestSpinLock(&(mutex->mu_mutex)));
#else
    rna_service_assert_locked(mutex);
#endif /* WINDOWS_KERNEL */
}

INLINE int rna_block_mutex_is_locked(rna_block_mutex_t *mutex)
{
#ifdef WINDOWS_KERNEL
    if(KeTestSpinLock(&(mutex->mu_mutex)))
        return 0;

    return 1;
#else
    return rna_service_mutex_is_locked(mutex);
#endif /* WINDOWS_KERNEL */
}