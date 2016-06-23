/**
 * <rna_duplicated_code.c> - Dell Fluid Cache block driver
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

#ifdef NOTDEF

#include <stdarg.h>
#include "../include/rna_common.h"

// By setting rna_printk_level, we can control which printks are
// printed independently of the kernel's /proc/sys/kernel/printk setting.

extern int rna_verbosity;
extern int rna_printk_level;

void __rna_printk(const char * type, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    rna_vprintk(type, fmt, args);

    va_end(args);
}

#endif  /* NOTDEF */

