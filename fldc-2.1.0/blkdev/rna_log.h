/**
 * <rna_log.h> - Dell Fluid Cache block driver
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

#ifndef _RNA_LOG_H_
#define _RNA_LOG_H_

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif 

#ifdef RNABLK_ENABLE_NETLINK
#define init_log() __init_log()
#define log_string(buf) __log_string(buf)
#define log_string_atomic(buf) __log_string_atomic(buf)
#define printnl(fmt, arg...) \
    __printnl(fmt, ## arg);
#define printnl_atomic(fmt, arg...) \
    __printnl(fmt, ## arg);
#define cleanup_log() __cleanup_log()
#else
#define init_log()
#define log_string(buf)
#define log_string_atomic(buf)

#ifdef WINDOWS_KERNEL
#define printnl(fmt, ...)
#define printnl_atomic(fmt, ...)
#else
#define printnl(fmt, arg...)
#define printnl_atomic(fmt, arg...)
#endif

#define cleanup_log()
#endif
void __init_log(void);
int __log_string(char* buf);
int __log_string_atomic(char* buf);

#ifndef WINDOWS_KERNEL
void __printnl(const char * fmt, ...) __attribute__((format(printf,1,2)));
void __printnl_atomic(const char * fmt, ...) __attribute__((format(printf,1,2)));
#endif /*WINDOWS_KERNEL*/

void __cleanup_log(void);

#endif /* _RNA_LOG_H_ */
