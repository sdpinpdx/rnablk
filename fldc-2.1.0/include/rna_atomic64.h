/**
 * <rna_common_kernel_windows.h>
 *
 * Copyright (c) 2012-13 Dell  Inc 
 *
 */

#pragma once

#include "platform.h"

#if defined(WINDOWS_KERNEL) || defined(WINDOWS_USER)

INLINE int rna_atomic_test_and_set(atomic64_t *a, LONGLONG match, LONGLONG next)
{
    return InterlockedCompareExchange64(&(a->value), next, match) == match;
}

INLINE long long rna_atomic64_read(const atomic64_t *v)
{
	return v->value;
}

INLINE void rna_atomic64_set(atomic64_t *v, long long i)
{
	v->value = i;
}

INLINE long long rna_atomic64_add_return(long long i, atomic64_t *v)
{
	return InterlockedAddNoFence64(&(v->value), i);
}

INLINE long long rna_atomic64_inc_return(atomic64_t *v)
{
	return InterlockedAddNoFence64(&(v->value), 1);
}

INLINE void rna_atomic64_add(LONGLONG i, atomic64_t *v)
{
	InterlockedAddNoFence64(&(v->value), i);
}

/* 
 * Return TRUE on a successful add.  If the atomic is found to equal u,
 * we bail out and return  FALSE.  There is a version of this function
 * in Linux 2.6.32 that has the opposite return value behavior, but it appears
 * to have been fixed in RHEL6.
 */
INLINE int rna_atomic64_add_unless(atomic64_t *v, 
                                          long long a, 
                                          long long u)
{
    long long cur;

	UNREFERENCED_PARAMETER(a);

    while ((cur = rna_atomic64_read(v)) != u) {
        if ( atomic64_test_and_set(v, cur, cur + u) ) {
            return 1;                   /* success! */
        }
    }
    return 0;                           /* failure */
}

#else   /* Linux version */

#include <linux/version.h>
#include <linux/spinlock.h>


/* 
 * atomic64_add_unless isn't available in 2.6.18 kernels, therefore we
 * must implement our own version using a spinlock.  In order to maintain
 * atomic behavior with respect to the other atomic functions, we must 
 * re-implement those as well.
 * 
 * The kernel also implements 64 bit atomics in terms of spinlocks, but it
 * maintains a hash table of locks indexed by the the address of the 
 * atomic_t.  Using a single spinlock may be a little slower in some cases,
 * as there is higher chance of contention.
 *
 * To make things a little more complicated, the kernel isn't consistent
 * across versions or architectures about whether an atomic64_t is a
 * "long" or a "long long", which really only matters for printk.  We go
 * with the "long long" interpretation.
 *
 * This code was not included in rna_common.h because of the atomic_lock.
 * Modules which include this file must declare the atomic_lock, else
 * they won't compile.  It seemed undesirable to require all source files
 * to declare a lock that only a few will actually make use of.
 */ 

static DEFINE_SPINLOCK(atomic_lock);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
INLINE long long rna_atomic64_read(const atomic64_t *v)
{
    long long ret;
    unsigned long flags;

    spin_lock_irqsave(&atomic_lock, flags);
    ret = v->counter;
    spin_unlock_irqrestore(&atomic_lock, flags);

    return ret;
}


INLINE void rna_atomic64_set(atomic64_t *v, long long i)
{
    unsigned long flags;

    spin_lock_irqsave(&atomic_lock, flags);
    v->counter = i;
    spin_unlock_irqrestore(&atomic_lock, flags);
}

INLINE long long rna_atomic64_add_return(long long i, atomic64_t *v)
{
    unsigned long flags;
    long ret;

    spin_lock_irqsave(&atomic_lock, flags);
    ret = v->counter + i;
    v->counter = ret;
    spin_unlock_irqrestore(&atomic_lock, flags);

    return ret;
}

#define rna_atomic64_inc_return(v) \
    rna_atomic64_add_return(1, v)

INLINE void rna_atomic64_add(long long i, atomic64_t *v)
{
    unsigned long flags;

    spin_lock_irqsave(&atomic_lock, flags);
    v->counter += i;
    spin_unlock_irqrestore(&atomic_lock, flags);
}

/* 
 * Return TRUE on a successful add.  If the atomic is found to equal u,
 * we bail out and return  FALSE.  There is a version of this function
 * in 2.6.32 that has the opposite return value behavior, but it appears
 * to have been fixed in RHEL6.
 */
INLINE int rna_atomic64_add_unless(atomic64_t *v, 
                                          long long a, 
                                          long long u)
{
    unsigned long flags;
    int ret = 0;

    spin_lock_irqsave(&atomic_lock, flags);
    if (v->counter != u) {
        v->counter += u;
        ret = 1;
    }

    spin_unlock_irqrestore(&atomic_lock, flags);

    return ret;
}

#else   /* OLD Linux kernel */

#define rna_atomic64_read        (long long) atomic64_read
#define rna_atomic64_set         atomic64_set
#define rna_atomic64_add_return  (long long) atomic64_add_return
#define rna_atomic64_inc_return  (long long) atomic64_inc_return
#define rna_atomic64_add         atomic64_add
#define rna_atomic64_add_unless  atomic64_add_unless

#endif  /* not OLD Linux kernel */
#endif  /* Linux */

