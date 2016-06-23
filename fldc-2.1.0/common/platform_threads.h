/*
 * Platform-specific threading
 */

#ifndef _PLATFORM_THREADS_H_
#define _PLATFORM_THREADS_H_

#include "platform.h"

#if defined(WINDOWS)

/***********************************************************************
 *
 * Windows platform dependencies
 */

#if defined(WINDOWS_USER)
# include <WinBase.h>
# include <process.h>
#else /*WINDOWS_KERNEL*/
#endif /* WINDOWS_USER */

INLINE DWORD
timespec_to_dwMilliseconds(const struct timespec *ts)
{
    if (((struct timespec *) 0L) == ts) {
        return INFINITE;
    }
    return (DWORD)((ts->tv_sec * MSEC_PER_SEC) +
        (ts->tv_nsec / NSEC_PER_MSEC));
}

/*
 * Threads
 */

typedef struct {
    HANDLE      pt_handle;  /* thread handle */
    uint32_t    pt_tid;     /* thread id (?) */
} pthread_t;
typedef int pthread_attr_t;     // placeholder

typedef int pid_t;          /* placeholder -- may be some better type */

/**
 *  pthread_create  --  Create and launch a thread
 */

#if defined(WINDOWS_USER)
INLINE int
pthread_create(pthread_t *thread, const pthread_attr_t *attr,
               void *(*start_routine)(void *), void *arg)
{
    typedef unsigned int (__stdcall *TMain)(void *);
    uintptr_t h;

    /*
     * _beginthreadex() takes the address of a __stdcall function, while
     * this code is compiled using __cdecl calling convention.  This is a
     * major mismatch with ia32, but with x86_64 it appears that __stdcall
     * and __cdecl us the same calling convention.
     */

    h = _beginthreadex(NULL, 0, (TMain) start_routine, arg, 0,
                       &thread->pt_tid);
    if (((intptr_t) h) <= 0) {          /* error */
        return -1;              /* should return some meaningful error code */
    }
    thread->pt_handle = (HANDLE) h;
    return 0;
}
#else /* Windows Kernel */

INLINE int
pthread_create(pthread_t *thread, const pthread_attr_t *attr,
               void* (*start_routine)(void *), void *arg)
{
    /* Thread items aren't used in the kernel driver though 
       WinKernel threads are much different than user-mode
       thus returning a failure inside the stub to catch
       anything trying to use them 
    */
	UNREFERENCED_PARAMETER(arg);
	UNREFERENCED_PARAMETER(thread);
	UNREFERENCED_PARAMETER(attr);
	UNREFERENCED_PARAMETER(start_routine);
    return (-1);              /* should return some meaningful error code */
}

#endif /* WINDOWS_USER */

/*
 * Mutexes
 */

typedef struct {
    HANDLE ptm_handle;
} pthread_mutex_t;

# define PTHREAD_MUTEX_INITIALIZER  {((HANDLE)0)}

typedef int pthread_mutexattr_t;    // placeholder

/**
 *  pthread_mutex_init  --  Initialize a mutex
 */

#if defined(WINDOWS_USER)

INLINE int
pthread_mutex_init(pthread_mutex_t *mutex, 
    const pthread_mutexattr_t *attr)
{
    mutex->ptm_handle = CreateMutex(NULL, FALSE, NULL);
    if (((pthread_mutex_t *) 0L) == mutex->ptm_handle) {
        return (99);    /* unspecified error */
    }
    return (0);         /* success */
}
#else /* WINDOWS_KERNEL */

INLINE int
pthread_mutex_init(pthread_mutex_t *mutex,
                   const pthread_mutexattr_t *attr)
{
    /* Thread items aren't used in the kernel driver though 
       WinKernel threads are much different than user-mode
       thus returning a failure inside the stub to catch
       anything trying to use them 
    */
	UNREFERENCED_PARAMETER(mutex);
	UNREFERENCED_PARAMETER(attr);
    return (99);    /* unspecified error */
}

#endif /*WINDOWS_USER */


/**
 *  pthread_mutex_destroy  --  Destroy and clean up mutex
 */
#if defined(WINDOWS_USER)

INLINE int
pthread_mutex_destroy(pthread_mutex_t *mutex)
{
    CloseHandle(mutex->ptm_handle);
    return (0);
}

#else /* WINDOWS_KERNEL */

INLINE int
pthread_mutex_destroy(pthread_mutex_t *mutex)
{
	UNREFERENCED_PARAMETER(mutex);
    return (99);  /* Unspecified error */
}
#endif /* WINDOWS_USER */



/**
 *  pthread_mutex_lock  --  Unconditionally acquire lock
 */
#if defined(WINDOWS_USER)

INLINE int
pthread_mutex_lock(pthread_mutex_t *mutex)
{
    return WaitForSingleObject(mutex->ptm_handle, INFINITE);
}

#else /* WINDOWS KERNEL */

INLINE int
pthread_mutex_lock(pthread_mutex_t *mutex)
{
	UNREFERENCED_PARAMETER(mutex);
    return (99); /* Unspecified error */
}

#endif /* WINDOWS_USER */

/**
 *  pthread_mutex_timedlock  --  Attempt to acquire lock with timeout
 */

#if defined(WINDOWS_USER)

INLINE int
pthread_mutex_timedlock(pthread_mutex_t *mutex,
              const struct timespec *timeout)
{
    return WaitForSingleObject(mutex->ptm_handle,
        timespec_to_dwMilliseconds(timeout));
}

#else /* WINDOWS KERNEL */
INLINE int
pthread_mutex_timedlock(pthread_mutex_t *mutex,
                        const struct timespec *timeout)
{
	UNREFERENCED_PARAMETER(mutex);
	UNREFERENCED_PARAMETER(timeout);

    return (99);  /* Unspecified error */
}
#endif /* WINDOWS_USER */

/**
 *  pthread_mutex_trylock  --  One-shot attempt to acquire lock
 */
#if defined(WINDOWS_USER)

INLINE int
pthread_mutex_trylock(pthread_mutex_t *mutex)
{
    return WaitForSingleObject(mutex->ptm_handle, 0);
}
#else /* WINDOWS_KERNEL*/
INLINE int
pthread_mutex_trylock(pthread_mutex_t *mutex)
{
	UNREFERENCED_PARAMETER(mutex);
    return (99); /* Unspecified error */
}
#endif /* WINDOWS_USER */

/**
 *  pthread_mutex_unlock  --  Release lock
 */
#if defined(WINDOWS_USER)

INLINE int
pthread_mutex_unlock(pthread_mutex_t *mutex)
{
    (void) ReleaseMutex(mutex->ptm_handle);
    return (0);
}
#else /* WINDOWS KERNEL */
INLINE int
pthread_mutex_unlock(pthread_mutex_t *mutex)
{
	UNREFERENCED_PARAMETER(mutex);
    return (99); /* Unspecified error */
}
#endif /* WINDOWS_USER */


/**
 *  pthread_mutex_owner  --  NON-FUNCTIONAL IN WINDOWS
 */

INLINE pid_t
pthread_mutex_owner(pthread_mutex_t *mutex)
{
    UNREFERENCED_PARAMETER(mutex);
    return (pid_t) 0L;      // placeholder
}


/*
 * Conditions (Events)
 */

typedef HANDLE pthread_cond_t;
typedef int pthread_condattr_t;     // placeholder


/**
 *  pthread_cond_init  --  Set up condition, return TRUE on success
 */
#if defined(WINDOWS_USER)

INLINE int
pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr)
{
    *cond = CreateEvent(NULL, FALSE, FALSE, NULL);
    return ((pthread_cond_t *) 0L) != *cond;
}
#else /* WINDOWS KERNEL */
INLINE int
pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr)
{
    UNREFERENCED_PARAMETER(cond);
    UNREFERENCED_PARAMETER(attr);
    return (99);    /* unspecified error */
}
#endif /* WINDOWS_USER */

/**
 *  pthread_cond_signal  --  Signal condition, return TRUE on success
 */
#if defined(WINDOWS_USER)

INLINE int
pthread_cond_signal(pthread_cond_t *cond)
{
    return SetEvent(*cond) != 0L;

}
#else /* Windows Kernel */
INLINE int
pthread_cond_signal(pthread_cond_t *cond)
{
	UNREFERENCED_PARAMETER(cond);
    return (99);  /* Unspecified error */
}
#endif /* WINDOWS_USER */


/**
 *  pthread_cond_wait  --  Atomically release lock, wait for condition,
 *                          then acquire lock
 */
#if defined(WINDOWS_USER)

INLINE int
pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex)
{
    DWORD retval;

    retval = SignalObjectAndWait(mutex->ptm_handle, *cond, INFINITE, FALSE);
    if (retval == 0L) {
        (void) WaitForSingleObject(mutex->ptm_handle, INFINITE);
        return (0);
    }
    return retval;
}
#else /* Windows Kernel */
INLINE int
pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex)
{
	UNREFERENCED_PARAMETER(cond);
	UNREFERENCED_PARAMETER(mutex);
    return (99); /* unspecified error */
}
#endif /* WINDOWS_USER */

/**
 *  sched_yield  --  Release CPU for the nonce
 */

INLINE void
sched_yield(void)
{
    //YieldProcessor();
}



#elif defined(LINUX_USER)

/***********************************************************************
 *
 * Linux user mode platform dependencies
 */

# include <pthread.h>


/**
 *  pthread_mutex_owner  --  Return mutex owner task id (?)
 */

INLINE pid_t
pthread_mutex_owner(pthread_mutex_t *mutex)
{
    return (mutex->__data.__owner);
}

#elif defined(LINUX_KERNEL)

/***********************************************************************
 *
 * Linux user kernel platform dependencies
 */

/* empty */


#endif  /* __linux__ */


#endif  /* _PLATFORM_THREADS_H_ */


/* vi: set sw=4 sts=4 tw=80: */
/* Emacs settings */
/* 
 * Local Variables:
 * c-basic-offset: 4
 * c-file-offsets: ((substatement-open . 0))
 * tab-width: 4
 * End:
 */
