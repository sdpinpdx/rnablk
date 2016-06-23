/*
 * Platform-specific atomic operations
 */

#ifndef _PLATFORM_ATOMIC_H_
#define _PLATFORM_ATOMIC_H_

#include "platform.h"

#if defined(LINUX_USER)
# include <glib.h>
#elif defined(WINDOWS_USER)
# include "glib.h"
# include <intrin.h>
#endif  /* LINUX_USER */

#if defined(LINUX_KERNEL)
# include <asm/atomic.h>
/*# define gboolean            boolean */
/* Moved to platform.h   #define gboolean bool */

#elif defined (WINDOWS_KERNEL)
# include <Wdm.h>  /* pulls in WinBase and other atomic fns */
/* Moved to platform.h   # define gboolean   BOOLEAN  */

#endif  /* defined(LINUX_KERNEL) */

#if defined(LINUX_USER) || defined(PLATFORM_WINDOWS)
typedef struct {
    volatile int32_t value;
} atomic_t;

# define ATOMIC_T_INITIALIZER(val)  { (int32_t) val }

typedef struct {
    volatile int64_t value;
} atomic64_t;

# define ATOMIC64_T_INITIALIZER(val)  { (int64_t) val }
#endif  /* defined(LINUX_USER) || defined(PLATFORM_WINDOWS) */


/****************************************************************************
 *
 *      32-bit Atomics Operations
 */

/**
 *  atomic_inc  --  Atomic increment 32 bits
 */

#ifdef LINUX_USER
INLINE void
atomic_inc(atomic_t *a)
{
    g_atomic_int_inc ((gint *)&a->value);
}
#elif defined(PLATFORM_WINDOWS)

INLINE void
atomic_inc(atomic_t *a)
{
    (void) _InterlockedIncrement((LONG *)&a->value);
}
#endif  /* defined(PLATFORM_WINDOWS) */


/**
 *  atomic_dec  --  Returns TRUE if value goes to zero
 */

#ifdef LINUX_USER
INLINE gboolean
atomic_dec( atomic_t *a)
{
    return g_atomic_int_dec_and_test((gint *)&a->value);
}
#elif defined(PLATFORM_WINDOWS)

INLINE gboolean
atomic_dec( atomic_t *a)
{
    return 0 == _InterlockedDecrement((LONG *)&a->value);
}
#endif  /* defined(PLATFORM_WINDOWS) */


/**
 *  atomic_test_and_set -- Returns TRUE if set was successful
 */

#ifdef LINUX_USER
INLINE gboolean
atomic_test_and_set(atomic_t *a, int32_t match, int32_t next)
{
    return g_atomic_int_compare_and_exchange((gint *)&a->value, match, next);
}

#elif defined(PLATFORM_WINDOWS)
INLINE gboolean
atomic_test_and_set(atomic_t *a, int32_t match, int32_t next)
{
    return _InterlockedCompareExchange((LONG *)&a->value, next, match) == match;
}
#elif defined(LINUX_KERNEL)
/* Why is this a macro instead of INLINE? -- MAZ */
# define atomic_test_and_set(_addr, _old, _new)          \
    ((_old) == (int32_t)atomic_cmpxchg((_addr), (_old), (_new)))
#endif  /* defined(PLATFORM_WINDOWS) */


/**
 *  atomic_add_return -- Returns value after add
 */

#ifdef LINUX_USER
INLINE int32_t
atomic_add_return(atomic_t *a, int32_t i)
{
    return i + g_atomic_int_exchange_and_add((gint *)&a->value, i);
}
#elif defined(PLATFORM_WINDOWS)

INLINE int32_t
atomic_add_return(atomic_t *a, int32_t i)
{
    return _InterlockedAdd((LONG *)&a->value, i);
}
#endif  /* defined(PLATFORM_WINDOWS) */


/**
 *  atomic_add -- No return value
 */

#if defined(LINUX_USER) || defined(PLATFORM_WINDOWS)
INLINE void
atomic_add(atomic_t *a, int32_t i)
{
    (void) atomic_add_return(a, i);
}
#endif  /* defined(LINUX_USER) || defined(PLATFORM_WINDOWS) */


/**
 *  atomic_inc_return  --  Return value after increment
 */

#if defined(LINUX_USER) || defined(PLATFORM_WINDOWS)
INLINE int32_t 
atomic_inc_return(atomic_t *a)
{
    return atomic_add_return(a, 1);
}
#endif  /* defined(LINUX_USER) || defined(PLATFORM_WINDOWS) */


/**
 *  atomic_dec_return  --  Return value after decrement
 */

#if defined(LINUX_USER) || defined(PLATFORM_WINDOWS)
INLINE int32_t
atomic_dec_return(atomic_t *a)
{
    return atomic_add_return(a, -1);
}
#endif  /* defined(LINUX_USER) || defined(PLATFORM_WINDOWS) */

#if defined(PLATFORM_WINDOWS)
INLINE int32_t
atomic_dec_and_test(atomic_t *a)
{
    return atomic_add_return(a, -1) == 0;
}
#endif  /* defined(LINUX_USER) || defined(PLATFORM_WINDOWS) */


/**
 *  atomic_read  --  Return unblurred value
 */

#ifdef LINUX_USER
INLINE int32_t
atomic_read (atomic_t *a)
{
    return g_atomic_int_get(&a->value);
}
#elif defined(PLATFORM_WINDOWS)
INLINE int32_t
atomic_read (atomic_t *a)
{
    _ReadWriteBarrier();
    return a->value;
}
#endif  /* defined(PLATFORM_WINDOWS) */

/* Linux kernel calls atomic_get() atomic_read() */

# define atomic_get atomic_read


/**
 *  atomic_set --  Set value
 */

#if defined(LINUX_USER) || defined(PLATFORM_WINDOWS)
INLINE void 
atomic_set(atomic_t *a, int32_t value)
{
    /* g_atomic_int_set is not available on glib-2.0 version on RH 4.6.
     * 
     * We believe this is unnecessary because writes are not reordered on 
     * x86 machines.
     */
    //g_atomic_int_set(a, value);
    a->value = value; 
}
#endif  /* defined(LINUX_USER) || defined(PLATFORM_WINDOWS) */

/**
 *  atomic_xchg -- Atomic swap
 *
 * Glib doesn't provide this, so we implement it ourselves.
 * May livelock, but that's unlikely.  Return previous value of atomic_t.
 */

#if defined(LINUX_USER) || defined(PLATFORM_WINDOWS)
INLINE int32_t
atomic_xchg(atomic_t *a, int32_t value)
{
    int32_t prev;

    /* Windows kernel complier throws error C4127 for while loops
     * that evaluate to a constant.  MSFT recommends for loops
     */
    for ( ; ; )
    {
        prev = atomic_get(a);
        if (atomic_test_and_set(a, prev, value)) {
            break;
        }
    }

    return prev;
}
#endif  /* defined(LINUX_USER) || defined(PLATFORM_WINDOWS) */


/**
 *  atomic_add_nonnegative  --  Conditional add
 *
 * Add to an atomic_t, but only if its previous value was >= 0.
 * Return TRUE on success, FALSE on failure.
 * May livelock, but that's unlikely.
 */

#if defined(LINUX_USER) || defined(WINDOWS_USER)  /*defined(PLATFORM_WINDOWS) */
INLINE gboolean
atomic_add_nonnegative(atomic_t *a, int32_t value)
{
    gboolean ret = TRUE;
    int32_t prev;

    /* Windows kernel complier throws error C4127 for while loops
     * that evaluate to a constant.  MSFT recommends for loops
     */
    for ( ; ; )
    {
        prev = atomic_get(a);
        if (prev < 0) {
            ret = FALSE;
            break;
        }

        if (atomic_test_and_set(a, prev, prev+value)) {
            ret = TRUE;
            break;
        }
    }

    return ret;
}
#endif  /* defined(LINUX_USER) || defined(PLATFORM_WINDOWS) */


#if defined(LINUX_USER) || defined(PLATFORM_WINDOWS)
/*
 * Generic form of atomic_add_if_positive() and
 * atomic_add_return_if_positive().  Use one of those instead
 * of calling this directly.
 *
 * Produces both a success flag and the new value.
 */
INLINE void
_atomic_add_if_positive(atomic_t *a,
                        int32_t value,
                        gboolean * const success,
                        int32_t *new_val)
{
    int32_t prev;

    /* Windows kernel complier throws error C4127 for while loops
     * that evaluate to a constant.  MSFT recommends for loops
     */
    for (;;)
    {
        prev = atomic_get(a);
        if (prev + value < 0) {
            *success = FALSE;
            *new_val = prev;
            break;
        }

        if (atomic_test_and_set(a, prev, prev + value)) {
            *success = TRUE;
            *new_val = prev + value;
            break;
        }
    }

    return;
}

/**
 *  atomic_add_if_positive  --  Conditional add
 *
 * Add to an atomic_t, but only if the new value is >= 0.
 * Return TRUE on success, FALSE on failure.
 * May livelock, but that's unlikely.
 */
INLINE gboolean
atomic_add_if_positive(atomic_t *a, int32_t value)
{
    gboolean success;
    int32_t  new_value;

    _atomic_add_if_positive(a, value, &success, &new_value);
    return(success);
}

/**
 *  atomic_add_return_if_positive  --  Conditional add
 *
 * Add to an atomic_t, but only if the new value is >= 0.
 *
 * Return the value of a after the operation, whether
 * it changed or not
 *
 * May livelock, but that's unlikely.
 */
INLINE int32_t
atomic_add_return_if_positive(atomic_t *a, int32_t value)
{
    gboolean success;
    int32_t  new_value;

    _atomic_add_if_positive(a, value, &success, &new_value);
    return(new_value);
}
#endif  /* defined(LINUX_USER) || defined(PLATFORM_WINDOWS) */


#if defined(PLATFORM_WINDOWS)
INLINE gboolean
atomic_add_unless(atomic_t *a, int32_t value, int32_t comparevalue)
{
    gboolean ret = TRUE;
    int32_t prev;

    /* Windows kernel complier throws error C4127 for while loops
     * that evaluate to a constant.  MSFT recommends for loops
     */
    for ( ; ; )
    {
        prev = atomic_get(a);
		if (prev == comparevalue) {
            ret = FALSE;
            break;
        }

        if (atomic_test_and_set(a, prev, prev + value)) {
            ret = TRUE;
            break;
        }
    }

    return ret;
}
#endif  /* defined(PLATFORM_WINDOWS) */



/**
 *  atomic_add_if_true  --  Conditional add
 *
 * Add value to given atomic_t but only if user-supplied predicate
 * p is TRUE when tested against the previous value.  Return TRUE
 * on success, FALSE if predicate fails. */
#if defined(LINUX_USER) || defined(PLATFORM_WINDOWS)
INLINE gboolean
atomic_add_if_true(atomic_t *a, int (*p)(int), int32_t value)
{
    gboolean ret = TRUE;
    int32_t prev;

    /* Windows kernel complier throws error C4127 for while loops
     * that evaluate to a constant.  MSFT recommends for loops
     */
    for ( ; ; )
    {
       prev = atomic_get(a);

       if (!p(prev)) {
            ret = FALSE;
            break;
        }

        if (atomic_test_and_set(a, prev, prev + value)) {
            ret = TRUE;
            break;
        }
    }

    return ret;
}
#endif  /* defined(LINUX_USER) || defined(PLATFORM_WINDOWS) */


/**
 * Get cycle count on the current CPU.  Comparison to values obtained
 * on other CPUs is meaningless, since these clocks are not
 * (necessarily) synchronized, or even running at the same rate.
 *
 * Comparison of consecutive values returned by this funct in the
 * same thread are not necessarily meaningful, unless steps have been
 * taken to ensure that the thread did not migrate (and the CPU clock
 * frequency hasn't changed, or your CPUs TSC register counts ticks on
 * a clock that doesn't change).
 *
 * Consider get_monotonic_timestamp() instead.
 */

#if defined(LINUX_USER) || defined(PLATFORM_WINDOWS)
typedef uint64_t cycles_t;
#endif  /* defined(LINUX_USER) || defined(PLATFORM_WINDOWS) */


#if defined(LINUX_USER)
INLINE cycles_t get_cycles()
{
    uint32_t low, high;
    uint64_t val;
    asm volatile ("rdtsc" : "=a" (low), "=d" (high));
    val = high;
    val = (val << 32) | low;
    return val;
}
#elif defined(PLATFORM_WINDOWS)
INLINE cycles_t get_cycles()
{
    return __rdtsc();
}
#endif  /* defined(PLATFORM_WINDOWS) */


/****************************************************************************
 *
 *      64-bit Atomic Operations
 */


/**
 *  atomic64_get  --  Get unblurred value
 */

#if defined(LINUX_USER) || defined(PLATFORM_WINDOWS)
INLINE int64_t 
atomic64_get(atomic64_t *a)
{
    return a->value;
}
#endif  /* defined(LINUX_USER) || defined(PLATFORM_WINDOWS) */

/* Linux kernel calls atomic_get() atomic_read() */
#if !defined(LINUX_KERNEL)
# define atomic64_read atomic64_get
#endif  /* !defined(LINUX_KERNEL) */


/**
 *  atomic64_set  --  Set value
 */

#if defined(LINUX_USER) || defined(PLATFORM_WINDOWS)
INLINE void 
atomic64_set(atomic64_t *a, int64_t value)
{
    a->value = value;
}
#endif  /* defined(LINUX_USER) || defined(PLATFORM_WINDOWS) */


/**
 *  atomic64_add_return  --  Return result
 */

#if defined(LINUX_USER)
INLINE int64_t 
atomic64_add_return(atomic64_t *a, int64_t i)
{
    return __sync_add_and_fetch(&a->value, i);
}
#elif defined(PLATFORM_WINDOWS)
INLINE int64_t 
atomic64_add_return(atomic64_t *a, int64_t i)
{
    return _InterlockedAdd64(&a->value, i);
}
#endif  /* defined(PLATFORM_WINDOWS) */


/**
 *  atomic64_add  --  Atomic add, no result
 */

#if defined(LINUX_USER) || defined(PLATFORM_WINDOWS)
INLINE void 
atomic64_add(atomic64_t *a, int64_t i)
{
    (void) atomic64_add_return(a, i);
}
#endif  /* defined(LINUX_USER) || defined(PLATFORM_WINDOWS) */


/**
 *  atomic64_inc  --  Returns TRUE if a goes to zero
 */

#if defined(LINUX_USER) || defined(PLATFORM_WINDOWS)
INLINE gboolean
atomic64_dec(atomic64_t *a)
{
    return (0 == atomic64_add_return(a, -1));
}
#endif  /* defined(LINUX_USER) || defined(PLATFORM_WINDOWS) */


/**
 *  atomic64_inc  --  Atomic increment, no result
 */

#if defined(LINUX_USER) || defined(PLATFORM_WINDOWS)
INLINE void
atomic64_inc(atomic64_t *a)
{
    (void) atomic64_add_return(a, 1);
}
#endif  /* defined(LINUX_USER) || defined(PLATFORM_WINDOWS) */


/**
 *  atomic64_inc_return  --  Atomic decrement and return result
 */

#if defined(LINUX_USER) || defined(PLATFORM_WINDOWS)
INLINE int64_t
atomic64_inc_return(atomic64_t *a)
{
    return atomic64_add_return(a, 1);
}
#endif  /* defined(LINUX_USER) || defined(PLATFORM_WINDOWS) */


/**
 *  atomic64_test_and_set  --  Returns TRUE if set was successful
 */

#if defined(LINUX_USER)
INLINE gboolean
atomic64_test_and_set(atomic64_t *a, int64_t match, int64_t next)
{
    return __sync_bool_compare_and_swap(&a->value, match, next);
}
#elif defined(PLATFORM_WINDOWS)

INLINE gboolean
atomic64_test_and_set(atomic64_t *a, int64_t match, int64_t next)
{
    return (_InterlockedCompareExchange64(&a->value, next, match) == match);
}
#endif  /* defined(PLATFORM_WINDOWS) */

/*
 * Add to an atomic64_t, but only if the new value is >= 0.
 * If the new value is < 0, set the atomic64_t to 0.
 * May livelock, but that's unlikely.
 *
 * NOTE: This is a slight variation from the 32-bit version of
 * the same funct -- that funct never sets the value
 * of the atomic to 0 if the new value is < 0. This funct, on
 * the other hand, does.
 */
#if defined(LINUX_USER) || defined(PLATFORM_WINDOWS)
INLINE int64_t
atomic64_add_if_positive(atomic64_t *a, int64_t value)
{
    int64_t next;
    int64_t prev;

    /* Windows kernel complier throws error C4127 for while loops
     * that evaluate to a constant.  MSFT recommends for loops
     */
    for ( ; ; )
    {
        prev = atomic64_get(a);
        if (prev + value < 0) {
            /*
             * If the new value is going to be zero, set it
             * to zero.
             */
            next = 0;
            if (atomic64_test_and_set(a, prev, next)) {
                break;
            }
        } else {
            next = prev + value;
            if (atomic64_test_and_set(a, prev, next)) {
                break;
            }
        }
    }

    return next;
}
#endif  /* defined(LINUX_USER) || defined(PLATFORM_WINDOWS) */

/*
 * Atomically set the specified bit in the specified atomic variable.
 *
 * Arguments
 *     a          Pointer to the atomic variable containing the bit to be set
 *     bitmask    A bitmask for the bit to be set
 *
 * Example:
 * If a 'flag' boolean value is stored in bit 3 of atomic variable x,
 * and one wishes to atomically set the flag, one would do the following:
 *
 *     #define FLAG_BITMASK  (1 << 3)
 *
 *     atomic_bit_set(&x, FLAG_BITMASK);
 */

INLINE void atomic_bit_set(atomic_t *a, uint32_t bitmask)
                                                ALWAYS_INLINE;
INLINE void
atomic_bit_set(atomic_t *a, uint32_t bitmask)
{
    uint32_t old_val;

    do {
        old_val = atomic_get(a);
    } while (unlikely(!atomic_test_and_set(a, old_val, old_val | bitmask)));
}



/*
 * Atomically clear the specified bit in the specified atomic variable.
 *
 * Arguments
 *     a          Pointer to the atomic variable containing the bit to be
 *                cleared
 *     bitmask    A bitmask for the bit to be cleared
 *
 * Example:
 * If a 'flag' boolean value is stored in bit 3 of atomic variable x,
 * and one wishes to atomically clear the flag, one would do the following:
 *
 *     #define FLAG_BITMASK  (1 << 3)
 *
 *     atomic_bit_clear(&x, FLAG_BITMASK);
 */

INLINE void atomic_bit_clear(atomic_t *a, uint32_t bitmask)
                                                ALWAYS_INLINE;
INLINE void
atomic_bit_clear(atomic_t *a, uint32_t bitmask)
{
    uint32_t old_val;

    do {
        old_val = atomic_get(a);
    } while (unlikely(!atomic_test_and_set(a, old_val, old_val & ~bitmask)));
}



/*
 * Atomically check whether the specified bit in the specified atomic variable
 * is clear, and if so, set it.
 *
 * Arguments
 *     a          Pointer to the atomic variable containing the bit to be
 *                conditionally set
 *     bitmask    A bitmask for the bit to be conditionaly set
 *
 * Returns TRUE if set was successful
 *
 * Example:
 * If a 'flag' boolean value is stored in bit 3 of atomic variable x,
 * and one wishes to atomically transition the flag from FALSE to TRUE,
 * one would do the following:
 *
 *     #define FLAG_BITMASK  (1 << 3)
 *
 *     ret = atomic_bit_test_and_set(&x, FLAG_BITMASK);
 */

INLINE gboolean atomic_bit_test_and_set(atomic_t *a, uint32_t bitmask)  
                                                ALWAYS_INLINE; 
INLINE gboolean
atomic_bit_test_and_set(atomic_t *a, uint32_t bitmask)
{
    uint32_t old_val;

    do {
        old_val = atomic_get(a);
        if ((old_val & bitmask) != 0) {
            return (FALSE);
        }
    } while (unlikely(!atomic_test_and_set(a, old_val, (old_val | bitmask))));
    return (TRUE);
}



/*
 * Atomically check whether the specified bit in the specified atomic variable
 * is set, and if so, clear it.
 *
 * Arguments
 *     a          Pointer to the atomic variable containing the bit to be
 *                conditionally cleared
 *     bitmask    A bitmask for the bit to be conditionally cleared
 *
 * Returns TRUE if clear was successful
 *
 * Example:
 * If a 'flag' boolean value is stored in bit 3 of atomic variable x,
 * and one wishes to atomically transition the flag from TRUE to FALSE,
 * one would do the following:
 *
 *     #define FLAG_BITMASK  (1 << 3)
 *
 *     ret = atomic_bit_test_and_clear(&x, FLAG_BITMASK);
 */

INLINE gboolean atomic_bit_test_and_clear(atomic_t *a, uint32_t bitmask)
                                                ALWAYS_INLINE;
INLINE gboolean
atomic_bit_test_and_clear(atomic_t *a, uint32_t bitmask)
{
    uint32_t old_val;

    do {
        old_val = atomic_get(a);
        if ((old_val & bitmask) == 0) {
            return (FALSE);
        }
    } while (unlikely(!atomic_test_and_set(a, old_val, old_val & ~bitmask)));
   return (TRUE);
}



/*
 * Atomically read the specified bit in the specified atomic variable and
 * return TRUE if it's set, or FALSE if it's not.
 *
 * Arguments
 *     a          Pointer to the atomic variable containing the bit to be
 *                checked
 *     bitmask    A bitmask for the bit to be checked
 *
 * Return:
 *     TRUE       If the specified bit is set
 *     FALSE      If the specified bit is not set
 *
 * Example:
 * If a 'flag' boolean value is stored in bit 3 of atomic variable x,
 * and one wishes to atomically check the flag, one would do the following:
 *
 *     #define FLAG_BITMASK  (1 << 3)
 *
 *     if (atomic_bit_is_set(&x, FLAG_BITMASK)) {
 *         whatever;
 *     }
 *
 * If bitmask contains >1 bit, returns TRUE if any of them are set
 */

INLINE gboolean atomic_bit_is_set(atomic_t *a, uint32_t bitmask)
                                                ALWAYS_INLINE;
INLINE gboolean
atomic_bit_is_set(atomic_t *a, uint32_t bitmask)
{
    return ((atomic_get(a) & bitmask) != 0);
}



/*
 * Atomically read the specified bit in the specified atomic variable and
 * return TRUE if it's clear, or FALSE if it's not.
 *
 * Arguments
 *     a          Pointer to the atomic variable containing the bit to be
 *                checked
 *     bitmask    A bitmask for the bit to be checked
 *
 * Return:
 *     TRUE       If the specified bit is clear
 *     FALSE      If the specified bit is not clear
 *
 * Example:
 * If a 'flag' boolean value is stored in bit 3 of atomic variable x,
 * and one wishes to atomically check the flag, one would do the following:
 *
 *     #define FLAG_BITMASK  (1 << 3)
 *
 *     if (atomic_bit_is_clear(&x, FLAG_BITMASK)) {
 *         whatever;
 *     }
 *
 * If bitmask contains >1 bit, returns TRUE only when ALL of them are clear
 */

INLINE gboolean atomic_bit_is_clear(atomic_t *a, uint32_t bitmask)
                                                ALWAYS_INLINE;
INLINE gboolean
atomic_bit_is_clear(atomic_t *a, uint32_t bitmask)
{
    return ((atomic_get(a) & bitmask) == 0);
}



/*
 * Return the string "TRUE" if the specified atomic bit is set, and the string
 * "FALSE' if it is not.
 */

INLINE char * get_atomic_bit_is_set_string(atomic_t *a, uint32_t bitmask)
                                                ALWAYS_INLINE;
INLINE char *
get_atomic_bit_is_set_string(atomic_t *a, uint32_t bitmask)
{
    return ((atomic_get(a) & bitmask) ? "TRUE" : "FALSE");
}


/****************************************************************************
 *
 * rna_service_wait_obj
 */


#if defined(WINDOWS_KERNEL)
    typedef KEVENT rna_service_wait_obj;
#elif defined(LINUX_KERNEL)
    #include <linux/wait.h>
    typedef wait_queue_head_t rna_service_wait_obj;
#else /* WINDOWS_USER or LINUX_USER */
    typedef struct wait_obj rna_service_wait_obj;
#endif 


#endif  /* _PLATFORM_ATOMIC_H_ */


/* vi: set sw=4 sts=4 tw=80: */
/* Emacs settings */
/* 
 * Local Variables:
 * c-basic-offset: 4
 * c-file-offsets: ((substatement-open . 0))
 * tab-width: 4
 * End:
 */
