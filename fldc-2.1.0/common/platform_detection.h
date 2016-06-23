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

#ifndef __PLATFORM_DETECTION_H__
#define __PLATFORM_DETECTION_H__

// setup PLATFORM_OS symbols
#if ( ! defined ( PLATFORM_OS ) )
#   define PLATFORM_OS_UNKNOWN	(0x00)
#   define PLATFORM_OS_WINDOWS	(0x01)
#   define PLATFORM_OS_LINUX	(0x02)
#   define PLATFORM_OS_MASK     (0x0F)

#   if ( defined ( _WIN32 ) || defined ( __WIN32__ ) || defined ( WIN32 ) || defined ( _WIN64 ) )
#       define PLATFORM_OS	PLATFORM_OS_WINDOWS
#   elif ( defined ( linux ) || defined ( __linux ) || defined ( __linux__ ) || defined ( __GNU__ ) || defined ( __GLIBC__ ) )
#       define PLATFORM_OS PLATFORM_OS_LINUX
#   else
#       define PLATFORM_OS PLATFORM_OS_UNKNOWN
#       error Undefined OS
#   endif   /* OS type */
#endif  /* ! PLATFORM_OS */

// setup the PLATFORM_MODE symbols
#if ( ! defined ( PLATFORM_MODE ) )
#   define PLATFORM_MODE_UNKNOWN	(0x00)
#   define PLATFORM_MODE_USER	    (0x10)
#   define PLATFORM_MODE_KERNEL	    (0x20)
#   define PLATFORM_MODE_MASK       (0xF0)

#   if ( PLATFORM_OS == PLATFORM_OS_WINDOWS )
#       if ( defined ( _KERNEL ) )
#           define PLATFORM_MODE PLATFORM_MODE_KERNEL
#       else   /* _KERNEL */
#           define PLATFORM_MODE PLATFORM_MODE_USER
#       endif   /* _KERNEL */
#   elif ( PLATFORM_OS == PLATFORM_OS_LINUX )
#       if ( defined ( __KERNEL__ ) )
#           define PLATFORM_MODE PLATFORM_MODE_KERNEL
#       else
#           define PLATFORM_MODE PLATFORM_MODE_USER
#       endif   /* __KERNEL__ */
#   else
#       define PLATFORM_MODE PLATFORM_MODE_UNKNOWN
#       error Undefined platform
#   endif   /* OS type */
#endif  /* ! PLATFORM_MODE */

// setup the specific combinations
#if ( ! defined ( PLATFORM_TYPE ) )
#   define PLATFORM_TYPE_UNKNOWN	    (PLATFORM_OS_UNKNOWN | PLATFORM_MODE_UNKNOWN)
#   define PLATFORM_TYPE_LINUX_USER	    (PLATFORM_OS_LINUX   | PLATFORM_MODE_USER)
#   define PLATFORM_TYPE_LINUX_KERNEL	(PLATFORM_OS_LINUX   | PLATFORM_MODE_KERNEL)
#   define PLATFORM_TYPE_WINDOWS_USER	(PLATFORM_OS_WINDOWS | PLATFORM_MODE_USER)
#   define PLATFORM_TYPE_WINDOWS_KERNEL	(PLATFORM_OS_WINDOWS | PLATFORM_MODE_KERNEL)
#   define PLATFORM_TYPE_MASK           (PLATFORM_OS_MASK    | PLATFORM_MODE_MASK)

#   define PLATFORM_TYPE                (PLATFORM_OS | PLATFORM_MODE)
#endif  /* ! PLATFORM_TYPE */

/* Clean off definitions */
#ifdef WINDOWS_USER
# undef WINDOWS_USER
#endif  /* WINDOWS_USER */
#ifdef WINDOWS_KERNEL
# undef WINDOWS_KERNEL
#endif  /* WINDOWS_KERNEL */
#ifdef LINUX_USER
# undef LINUX_USER
#endif  /* LINUX_USER */
#ifdef LINUX_KERNEL
# undef LINUX_KERNEL
#endif  /* LINUX_KERNEL */

/*
* Define flavors
*/

#if defined(_WINDOWS) || defined(_WIN64) || defined(_WIN32)
# ifndef WINDOWS
#  define WINDOWS           /* all Windows flavors */
#  define PLATFORM_WINDOWS
# endif /* WINDOWS */

# if defined(_KERNEL)
#  define WINDOWS_KERNEL
# else
# define WINDOWS_USER
# endif /*_KERNEL */


#elif defined(__linux__)
#  ifndef LINUX
#   define LINUX            /* all linux flavors */
#  endif    /* LINUX */
#  ifdef __KERNEL__
#   define LINUX_KERNEL
#  else
#   define LINUX_USER
#  endif    /* __KERNEL__ */
#else
# error "Unrecognized platform"
#endif  /* _WINDOWS, __linux__ */


/* Cross-check build */
#if defined(WINDOWS)
# ifndef _M_X64
#  error "Not a 64-bit compile!"
# endif /* _M_X64 */
# ifndef _AMD64_
#  define _AMD64_
# endif /* _AMD64_ */ 
#endif  /* WINDOWS */

#endif   /* __PLATFORM_DETECTION_H__ */
