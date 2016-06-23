/*--------------------------------------------------------------------
**
**          DELL INC. PROPRIETARY INFORMATION
**
** This software is supplied under the terms of a license agreement or
** nondisclosure agreement with Dell Inc. and may not be copied or
** disclosed except in accordance with the terms of that agreement.
**
** Copyright (c) 2014 - 2016 Dell Inc. All rights reserved.
**
**--------------------------------------------------------------------*/

#ifndef __PLATFORM_TIME_H__
#define __PLATFORM_TIME_H__

#include "platform.h"

#if ( PLATFORM_TYPE != PLATFORM_TYPE_LINUX_KERNEL )

#include <time.h>

#endif /* ! PLATFORM_TYPE_LINUX_KERNEL */

#if ( PLATFORM_TYPE == PLATFORM_TYPE_WINDOWS_USER )

#include <WinSock2.h>    /* Required for definition of struct timeval. */
#include "pthread.h"

#endif  /* PLATFORM_TYPE_WINDOWS_USER */

#define BAD_TIME    (0)

#if ( PLATFORM_TYPE != PLATFORM_TYPE_LINUX_KERNEL )

#   define NSEC_PER_SEC   1000000000
#   define NSEC_PER_MSEC     1000000
#   define NSEC_PER_USEC        1000
#   define USEC_PER_TSEC      100000
#   define USEC_PER_SEC      1000000
#   define USEC_PER_MSEC        1000
#   define MSEC_PER_TSEC         100
#   define MSEC_PER_SEC         1000
#   define TSEC_PER_SEC           10
#   define SEC_PER_MIN            60
#   define TSEC_PER_MIN          600
#   define MIN_PER_HOUR           60
#   define SEC_PER_HOUR         3600
#   define TSEC_PER_HOUR       36000
#   define SEC_PER_DAY         86400
#   define SEC_PER_YEAR     31557600
#   define DAY_PER_YEAR          365

#endif /* ! PLATFORM_TYPE_LINUX_KERNEL */

#if ( PLATFORM_OS == PLATFORM_OS_WINDOWS)

/* Borrowed a few macros from OSR for time computation for thread delay: */
#   define DELAY_ABSOLUTE_TIME(wait)   (wait)
#   define DELAY_RELATIVE_TIME(wait)   (-(wait))
#   define NANOSECONDS(nanos)          (((signed __int64)(nanos)) / 100L)
#   define MICROSECONDS(micros)        (((signed __int64)(micros)) * NANOSECONDS(1000L))
#   define MILLISECONDS(milli)         (((signed __int64)(milli)) * MICROSECONDS(1000L))
#   define SECONDS(seconds)            (((signed __int64)(seconds)) * MILLISECONDS(1000L))

struct timezone 
{
    int  tz_minuteswest; /* minutes W of Greenwich */
    int  tz_dsttime;     /* type of dst correction */
};

#if ( PLATFORM_TYPE == PLATFORM_TYPE_WINDOWS_KERNEL )

/* Windows kernel doesn't have an equivalent
* timeval struct.  Just copy from Linux  */
struct timeval {
    long tv_sec;
    long tv_usec;
};

typedef enum _clockid_t {
    CLOCK_REALTIME,
    CLOCK_MONOTONIC,
} clockid_t;
#define HAVE_CLOCKID_T

struct timespec {
    int64_t tv_sec;    // seconds
    int64_t tv_nsec;   // nanoseconds
};

#endif /* PLATFORM_TYPE_WINDOWS_KERNEL */

#define gettimeofday(tv,tz) _gettimeofday_windows((tv),(tz))
int     _gettimeofday_windows(struct timeval *tv, struct timezone *tz);

extern char * ctime_r(const time_t *t, char *buf);
extern char * asctime_r(const struct tm *tm, char *buf);
extern struct tm * gmtime_r(const time_t *t, struct tm *tm);

#endif  /* PLATFORM_OS_WINDOWS */

/**
*  gettime_nsec  --  Return clock time in nanoseconds
*/

#if ( PLATFORM_TYPE == PLATFORM_TYPE_WINDOWS_USER )
INLINE uint64_t
gettime_nsec(void)
{
    struct __timeb64 tp;

    if (0 != _ftime64_s(&tp)) {
        return BAD_TIME;
    }
    return (((uint64_t)(tp.time) * NSEC_PER_SEC)
        + (((uint64_t)tp.millitm) * NSEC_PER_MSEC));
}
#elif ( PLATFORM_TYPE == PLATFORM_TYPE_LINUX_USER )
INLINE uint64_t
gettime_nsec(void)
{
    struct timeval tv;

    if (!gettimeofday(&tv, (struct timezone *)(0L))) {
        return BAD_TIME;
    }
    /* convert the nsec timestamp into nanoseconds */
    return ((uint64_t)(tv.tv_sec) * NSEC_PER_SEC +
        (uint64_t)tv.tv_usec * NSEC_PER_USEC);
}
#endif  /* PLATFORM_TYPE_*_USER */

/**
*  gettime_sec  --  Return clock time in seconds
*/

#if ( PLATFORM_TYPE == PLATFORM_TYPE_WINDOWS_USER )
INLINE uint64_t
gettime_sec(void)
{
    struct __timeb64 tp;

    if (0 != _ftime64_s(&tp)) {
        return BAD_TIME;
    }
    return ((uint64_t)tp.time);
}
#elif ( PLATFORM_TYPE == PLATFORM_TYPE_LINUX_USER )
INLINE uint64_t
gettime_sec(void)
{
    struct timeval tv;

    if (!gettimeofday(&tv, (struct timezone *)(0L))) {
        return BAD_TIME;
    }
    return ((uint64_t)tv.tv_sec);
}
#endif  /* PLATFORM_TYPE_*_USER */

/*
*  localtime_r  --  Work-alike for Linux localtime_r
*/

#if ( PLATFORM_TYPE == PLATFORM_TYPE_WINDOWS_USER )
INLINE struct tm*
localtime_r(const time_t *timep, struct tm *result)
{
    *result = *localtime(timep);
    return result;
}
#endif  /* PLATFORM_TYPE_WINDOWS_USER */

#if ( PLATFORM_OS == PLATFORM_OS_WINDOWS )

INLINE DWORD
timespec_to_dwMilliseconds(const struct timespec *ts)
{
    DWORD ms_time = INFINITE;

    if (ts) {
        ms_time = (DWORD)((ts->tv_sec * MSEC_PER_SEC) + (ts->tv_nsec / NSEC_PER_MSEC));
    }

    return ms_time;
}

#endif /* PLATFORM_OS_WINDOWS */

#endif  /* __PLATFORM_TIME_H__ */
