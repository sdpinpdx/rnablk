/*--------------------------------------------------------------------
**
**          DELL INC. PROPRIETARY INFORMATION
**
** This software is supplied under the terms of a license agreement or
** nondisclosure agreement with Dell Inc. and may not be copied or
** disclosed except in accordance with the terms of that agreement.
**
** Copyright (c) 2015 Dell Inc. All rights reserved.
**
**--------------------------------------------------------------------*/

#pragma once

#ifndef __PLATFORM_TYPES_H__
#define __PLATFORM_TYPES_H__

#if ( PLATFORM_TYPE == PLATFORM_TYPE_WINDOWS_USER )

#include <stdio.h>
#include <stdint.h>

typedef int64_t     ssize_t;
typedef int64_t     off64_t;
typedef int64_t     loff_t;
typedef uint32_t    mode_t;

typedef BOOLEAN     boolean; /*yes... Windows redefines boolean as all caps*/

typedef FILE        RNA_FILE;

#elif ( PLATFORM_TYPE == PLATFORM_TYPE_WINDOWS_KERNEL )

typedef unsigned char uint8_t;
typedef unsigned char u8;
typedef char int8_t;

typedef __int16 int16_t;

typedef unsigned __int16 uint16_t;
typedef unsigned __int16 u16;

typedef int int32_t;
typedef unsigned int uint32_t;
typedef unsigned int u32;
typedef u32 __be32;  /* MSFT doesn't have a __bitwise operator in its compiler */

typedef long off_t;
typedef __int64  int64_t;
typedef __int64  ssize_t;
typedef __int64 off64_t;
typedef unsigned __int64 uint64_t;
typedef unsigned __int64 size_t;

typedef unsigned __int64 u64;
typedef u64 dma_addr_t;


typedef BOOLEAN boolean; /*yes... Windows redefines boolean as all caps*/

#define gboolean BOOLEAN /*gbool is typedef'ed or #defined everywhere , centeralize here */

#define INFINITE 0xFFFFFFFF  // Infinite timeout

/* Note this is ONLY used in rna_common_logging.h !
* This is due to the MSFT ntstrsafe pulling stdio.h
* which already has a definition for FILE.  As we had redefined FILE here
* to be HANDLE, it was stomping on the stdio.h definition of FILE and
* causing chaos.  To avoid that, use RNA_FILE -> HANDLE to fix
* compile errors.
*/
typedef HANDLE  RNA_FILE;

#elif ( PLATFORM_TYPE == PLATFORM_TYPE_LINUX_USER )

typedef unsigned char BOOLEAN;

#elif ( PLATFORM_TYPE == PLATFORM_TYPE_LINUX_KERNEL )

typedef unsigned char gboolean;
typedef unsigned char boolean;
typedef unsigned char BOOLEAN;
typedef long long     off64_t;

#define free(p)       kfree(p)

#else
#   error "Unknown platform type"
#endif /* PLATFORM_TYPE */

#endif  /* __PLATFORM_TYPES_H__ */
