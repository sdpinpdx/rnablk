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

/**
 * Platform customization
 */
#pragma once

#ifndef _PATHFORM_H_
#define _PATHFORM_H_

#include "platform_detection.h"

# define UNREFERENCED_FORMAL_PARAMETER(x) (void)(x)

/*************************************************************
 *
 * Includes
 */

#ifdef WINDOWS
# pragma warning(disable: 4996)     /* disable "strncpy" warnings */
# define CODE_IDENT(A)  __pragma(comment(user,A))

#if defined (WINDOWS_USER)
# include <WinDef.h>
# include <stdint.h>
# include <stdlib.h>
# include <sys/types.h>
# include <time.h>
# include <sys/timeb.h>
# include <stddef.h>

#else /* WINDOWS KERNEL */

#define RTL_USE_AVL_TABLES 0

# include <ntddk.h>
# include <ntintsafe.h>  /* Safe way to pull in datatypes needed */
//# include <errno.h>

#endif /* WINDOWS_USER */
#elif defined(LINUX_USER)
# define CODE_IDENT(A)  asm(".ident \"" A "\"");
# include <inttypes.h>
# include <sys/types.h>
# include <sys/time.h>
# include <uuid/uuid.h>
#elif defined(LINUX_KERNEL)
# define CODE_IDENT(A)  asm(".ident \"" A "\"");
#endif

#define PATHNAME_LEN                    4096

#ifndef PATH_MAX
# define PATH_MAX   4096    /* try to get it defined once */
#endif  /* PATH_MAX */

#include "platform_types.h"

#ifdef PLATFORM_WINDOWS
# define TYPEOF(X)  void *          /* may be dangerous */
#else
# define TYPEOF(X)  typeof(X)       /* not dangerous at all */
#endif  /* WINDOWS */

#ifdef LINUX

/* Define RNA_FILE to be the correct 'FILE' (see Windows kernel note above for details) */ 
#define RNA_FILE FILE

#endif  /* LINUX */


#ifdef LINUX
# ifndef TRUE
#  define TRUE  (1)
# endif /* TRUE */
# ifndef FALSE
#  define FALSE  (0)
# endif /* FALSE */
#endif  /* LINUX */


/*************************************************************
 *
 * Attributes
 *
 */

#ifdef WINDOWS

# define INLINE __inline
# define NOINLINE __declspec(noinline)
# define FORMAT(A)  /* empty */
# define ALWAYS_INLINE  /* empty */
# define UNUSED_ARG /* empty */
# define PACKED     /* empty */
#define DECLARE_UNUSED   /*empty */

//#define BUG_ON   NT_ASSERT
#define BUG_ON(expr) NT_ASSERT(!(expr))
#define BUG() ASSERT(0)
#elif defined(LINUX)

# define INLINE static inline
# define NOINLINE noinline
# define FORMAT(A)  __attribute__((format A))
# define ALWAYS_INLINE  __attribute__((always_inline))
# define UNUSED_ARG __attribute__((unused))
# define UNREFERENCED_PARAMETER(x)  /* empty */
# define PACKED __attribute__((packed))
# define DECLARE_UNUSED __attribute__((unused))
#endif  /* LINUX */

/*************************************************************
 *
 * Inter-OS Data Structures
 *
 * These are packed for historical reasons.
 * Post-processing tools verify the data layout is identical
 * on different OSs.
 */

#ifdef WINDOWS

# define DECLARE_PACKED_STRUCT(tag) __pragma(pack(push,1)); \
    struct tag
# define END_PACKED_STRUCT(tag) ; \
    typedef struct tag tag##_t; \
    __pragma(pack(pop))



#elif defined(LINUX)

# define DECLARE_PACKED_STRUCT(tag) \
    struct tag
# define END_PACKED_STRUCT(tag)   __attribute__((packed)); \
    typedef struct tag tag##_t, tag##_p;



#endif  /* LINUX */

#ifdef WINDOWS_KERNEL
/* Linux has a "request" structure for making requests to block devices.
 * Fill in this structure for Windows to use if we need it.
 */
struct request {
    int dummy;             // Placeholder since we don't currently use the structure contents in Windows.
};

/* Linux has a "scatterlist" structure.
 * Fill in this structure for Windows to use if we need it.
 */
struct scatterlist {
    unsigned long dummy_value;
};

#endif

/*
 * Data alignment
 */

#if defined(LINUX_USER) || defined(LINUX_KERNEL)
# define BEGIN_ALIGNED(N)  /* empty */
# define END_ALIGNED(N)     __attribute ((__aligned__ (N)))
#else   /* WINDOWS_USER or WINDOWS_KERNEL */
# define BEGIN_ALIGNED(N)  __declspec(align(N))
# define END_ALIGNED(N)    /* empty */
#endif  /* LINUX/WINDOWS */


/*************************************************************
 *
 * Compiler hints.  Here at the top in case INLINE stuff below
 * want to use it.
 */

#if defined(LINUX_USER)
# define likely(expr) __builtin_expect((expr),1)
# define unlikely(expr) __builtin_expect((expr),0)
#elif defined(LINUX_KERNEL)
    /* don't define! */
#elif defined(WINDOWS_USER) || defined(WINDOWS_KERNEL)
# define likely(expr) (expr)
# define unlikely(expr) (expr)
#endif


/*************************************************************
 *
 * Formatting flavors
 */

#ifdef WINDOWS
# define PRIx64 "I64x"
# define PRIu64 "I64u"
# define PRId64 "I64d"
#endif  /* WINDOWS */

#include "platform_time.h"

/*************************************************************
 *
 * Random [sic] operations
 */

#ifdef WINDOWS
INLINE const char *
strerror_r(int errnum, char *buf, size_t buflen)
{
    strerror_s(buf, buflen, errnum);
    return buf;
}

# define snprintf   sprintf_s

INLINE void
syslog(int flag, const char *fmt, ...)
{
    /* empty */
	UNREFERENCED_PARAMETER(flag);
	UNREFERENCED_PARAMETER(fmt);
}
#endif  /* WINDOWS */


#ifdef WINDOWS
/*
 * This is a kludge to keep fcache/util.h from failing.
 * It's here to minimize the impact on util.h.
 */

struct iovec {  // placeholder
    uint8_t     *iov_base;
    size_t      iov_len;
};

struct msghdr { // placeholder
    void *msg_name;
    uintptr_t msg_namelen;
    struct iovec *msg_iov;
    uintptr_t msg_iovlen;
    void *msg_control;
    uintptr_t msg_controllen;
    int msg_flags;
};

/*
 * End of fcache/util.h kludge
 */
#endif  /* WINDOWS */


#endif  /* _PATHFORM_H_ */


/* vi: set sw=4 sts=4 tw=80: */
/* Emacs settings */
/* 
 * Local Variables:
 * c-basic-offset: 4
 * c-file-offsets: ((substatement-open . 0))
 * tab-width: 4
 * End:
 */
