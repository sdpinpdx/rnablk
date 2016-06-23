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


#ifndef INCLUDED_TRACE_H
#define INCLUDED_TRACE_H

#define DBG_FLAG_EXEC_FLOW    0x00000001
#define DBG_FLAG_ERROR        0x00000002
#define DBG_FLAG_TRACE        0x00000004

// trace log markers
#define ENTER int ret = 0; \
              if( dbg_flags & DBG_FLAG_EXEC_FLOW ) \
                  printk( "%s/%d: entered\n",__FUNCTION__,current->pid )

#define EXIT if( dbg_flags & DBG_FLAG_EXEC_FLOW ) \
                 printk( "%s/%d: exited rc = %d\n",__FUNCTION__,current->pid,ret ); \
             return ret

#define EXITVAL( x ) if( dbg_flags & DBG_FLAG_EXEC_FLOW ) \
                         printk( "%s: exited with %d\n",__FUNCTION__,x ); \
                     return (x)

#define EXITPTR( x ) if( dbg_flags & DBG_FLAG_EXEC_FLOW ) \
                         printk( "%s: exited with %p\n",__FUNCTION__,x ); \
                     return (x)

#define EXITV if( dbg_flags & DBG_FLAG_EXEC_FLOW ) \
                  printk( "%s/%d: exited\n",__FUNCTION__,current->pid ); \
              return

#define GOTO( x,y ) { if( dbg_flags & DBG_FLAG_ERROR ) \
                          printk( "%s/%d: goto taken @ line %d rc = %d\n", \
                                  __FUNCTION__,current->pid,__LINE__,(y) ); \
                      ret = (y); goto x; }

#define GOTOV( x ) { if( dbg_flags & DBG_FLAG_ERROR ) \
                         printk( "%s/%d: goto taken @ line %d\n", \
                                 __FUNCTION__,current->pid,__LINE__ ); \
                     goto x; }

#define BREAK { if( dbg_flags & DBG_FLAG_ERROR ) \
                    printk( "%s: break taken @ line %d\n", \
                            __FUNCTION__,__LINE__ ); \
                break; }

#define TRACE( format,... ) { \
    if( dbg_flags & DBG_FLAG_TRACE ) { \
        printk( "%s/%d: ",__FUNCTION__,current->pid ); \
        printk( format,__VA_ARGS__ ); \
    } \
}

#define TRACESTR( x ) { \
    if( dbg_flags & DBG_FLAG_TRACE ) { \
        printk( "%s: %s\n",__FUNCTION__,x ); \
    } \
}

#endif
