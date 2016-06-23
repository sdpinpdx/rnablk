/**
 * <rnablk_rwsemaphore_windows.h> - Dell Fluid Cache block driver
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

#ifndef RNABLK_RWSEMAPHORE_H
#define RNABLK_RWSEMAPHORE_H

#include "platform.h"

#if defined(WINDOWS_KERNEL) || defined(LINUX_KERNEL)

//#ifdef LINUX_KERNEL
#define DECLARE_RNA_RWSEM(name) \
struct rna_rw_semaphore
//#endif 

struct rna_rw_semaphore {
#ifdef WINDOWS_KERNEL
	EX_SPIN_LOCK  rwlock;
#else
    struct rw_semaphore lock;
#endif /*WINDOWS_KERNEL*/
};

INLINE void rna_init_rwsem(struct rna_rw_semaphore * sem)
{
#ifdef WINDOWS_KERNEL
	sem->rwlock = 0;
#else
    init_rwsem(&(sem->lock));
#endif /*WINDOWS_KERNEL*/
}

INLINE void rna_destroy_rwsem(struct rna_rw_semaphore *sem)
{
#ifdef WINDOWS_KERNEL
    UNREFERENCED_PARAMETER(sem);
#else
#endif /*WINDOWS_KERNEL*/
}

INLINE void rna_down_read(struct rna_rw_semaphore * sem, unsigned char * poldirql)
{
#ifdef WINDOWS_KERNEL
	*poldirql = ExAcquireSpinLockShared(&sem->rwlock);
#else
    down_read(&(sem->lock));
#endif /*WINDOWS_KERNEL*/
}

INLINE void rna_up_read(struct rna_rw_semaphore * sem, unsigned char oldirql)
{
#ifdef WINDOWS_KERNEL
	ExReleaseSpinLockShared(&sem->rwlock, oldirql);
#else
    up_read(&(sem->lock));
#endif /*WINDOWS_KERNEL*/
}

INLINE void rna_down_write(struct rna_rw_semaphore * sem, unsigned char *poldirql)
{
#ifdef WINDOWS_KERNEL
	*poldirql = ExAcquireSpinLockExclusive(&sem->rwlock);
#else
    down_write(&(sem->lock));
#endif /*WINDOWS_KERNEL*/
}

INLINE void rna_up_write(struct rna_rw_semaphore * sem, unsigned char oldirql)
{
#ifdef WINDOWS_KERNEL
	ExReleaseSpinLockExclusive(&sem->rwlock, oldirql);
#else
    up_write(&(sem->lock));
#endif /*WINDOWS_KERNEL*/
}

#endif /*defined(WINDOWS_KERNEL) || defined(LINUX_KERNEL)*/

#endif //RNABLK_RWSEMAPHORE_H