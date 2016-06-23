/**
 * <rna_byteswap.h> - Dell Fluid Cache block driver
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

#ifdef PLATFORM_WINDOWS

#define CPU_BE 0
#else

#ifndef __KERNEL__

//#if __BYTE_ORDER == __BIG_ENDIAN

#ifdef __powerpc64__

#ifndef CPU_BE
#define CPU_BE 1
#endif /* #ifndef CPU_BE */

#else

#ifndef CPU_BE
//#define CPU_BE 0 
#define CPU_BE 0
//#warning CPU_BE is being forced to 1 to test byteswapping!!!! THIS IS NOT STANDARD. IF YOU SEE THIS MESSAGE FIND THIS LINE AND FIX THE CPU_BE FLAG
#endif /* #ifndef CPU_BE */

#endif /* #else */


#else /* __KERNEL__ */
#ifndef WINDOWS_KERNEL
#include <linux/version.h>

#include <asm/byteorder.h>
// XXX again, no idea when this changed, sigh
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
#include <linux/byteorder/swab.h>
#else
#include <linux/swab.h>
#endif

#endif

#define bswap_16 swab16
#define bswap_32 swab32
#define bswap_64 swab64

#ifdef __powerpc64__

#ifndef CPU_BE
#define CPU_BE 1
#endif

#else

#ifndef CPU_BE
#define CPU_BE 0
//#warning CPU_BE is being forced to 1 to test byteswapping!!!! THIS IS NOT STANDARD. IF YOU SEE THIS MESSAGE FIND THIS LINE AND FIX THE CPU_BE FLAG
#endif /* #ifndef CPU_BE */

#endif /* else #ifndef CPU_BE */

#endif /* #else __KERNEL__ */ 

#endif

