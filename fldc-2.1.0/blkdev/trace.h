/**
 * <trace.h> - Dell Fluid Cache block driver
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

#ident "$URL$ $Id$"

#ifndef INCLUDED_TRACE_H
#define INCLUDED_TRACE_H

#include "rna_byteswap.h"
#include "rna_types.h"
#if defined(LINUX_KERNEL)
#include <linux/kernel.h>
#endif

#define DBG_FLAG_EXEC_FLOW      0x00000001
#define DBG_FLAG_ERROR          0x00000002
#define DBG_FLAG_TRACE_IO       0x00000004
#define DBG_FLAG_TRACE_TIMEOUT  0x00000008
#define DBG_FLAG_VERBOSE        0x00000010

extern uint32_t dbg_flags;

// trace log markers
#define ENTER int ret = 0; \
    if (unlikely(dbg_flags & DBG_FLAG_EXEC_FLOW))            \
        printk( "%s: entered\n",__FUNCTION__ )

#define ENTERV \
    if (unlikely(dbg_flags & DBG_FLAG_EXEC_FLOW))   \
        printk( "%s: entered\n",__FUNCTION__ )

#define EXIT \
    if (unlikely(dbg_flags & DBG_FLAG_EXEC_FLOW))                   \
        printk( "%s: exited rc = %d\n",__FUNCTION__,ret );          \
    return ret

#define EXITVAL( x ) \
    if (unlikely(dbg_flags & DBG_FLAG_EXEC_FLOW))                       \
        printk( "%s: exited with %d\n",__FUNCTION__,(x) );              \
    return (x)

#define EXITPTR( x ) \
    if (unlikely(dbg_flags & DBG_FLAG_EXEC_FLOW))                       \
        printk( "%s: exited with %p\n",__FUNCTION__,x );                \
    return (x)

#define EXITV \
    if (unlikely(dbg_flags & DBG_FLAG_EXEC_FLOW))        \
        printk( "%s: exited\n",__FUNCTION__ );           \
    return

#define GOTO( x,y ) {                                                   \
        if (unlikely(dbg_flags & DBG_FLAG_ERROR))                       \
            printk( "%s: goto taken @ line %d rc = %d\n",               \
                    __FUNCTION__,__LINE__,(y) );                        \
        ret = (y); goto x;                                              \
    }

#define GOTOV( x ) {                                           \
        if (unlikely(dbg_flags & DBG_FLAG_ERROR))              \
            printk( "%s: goto taken @ line %d\n",              \
                    __FUNCTION__,__LINE__ );                   \
        goto x;                                                \
    }

#define BREAK {                                            \
        if (unlikely(dbg_flags & DBG_FLAG_ERROR))          \
            printk( "%s: break taken @ line %d\n",         \
                    __FUNCTION__,__LINE__ );               \
        break;                                             \
    }

#define TRACE( x,format,... ) {                         \
        if (unlikely(dbg_flags & (x))) {                \
            printk( "%s:%d: ",__FUNCTION__,__LINE__ );  \
            printk( format,__VA_ARGS__ );               \
        }                                               \
    }

#define TRACESTR( x ) { \
        if (unlikely(dbg_flags & DBG_FLAG_TRACE)) { \
            printk( "%s: %s\n",__FUNCTION__,x );    \
        }                                           \
    }

#endif
