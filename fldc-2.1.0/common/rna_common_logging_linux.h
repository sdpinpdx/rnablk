/**
 * <rna_log_linux.h> - Dell Fluid Cache logging mechanism
 *
 * Copyright (c) 2012-13 Dell  Inc 
 *
 */
/**
 *  Linux-specific implmentation for logging
 */

#ifndef _RNA_LOG_LINUX_H_
#define _RNA_LOG_LINUX_H_

#include "platform.h"

#include <stdarg.h>

#ifdef LINUX_USER

#include <string.h>
#include <stdio.h>
#include <assert.h>

#endif  /* LINUX_USER */

#ifdef LINUX_KERNEL

#include <linux/slab.h>
#include <linux/version.h>  /* need for KERNEL_VERSION */

/*
 * Define set of temporary macros to enable atomic_bit_XX & atomic_refcnt_XX
 * to compile for both user-level and kernel.
 */



#define RNA_DBG_VERBOSE		KERN_DEBUG
#define RNA_DBG_INFO		KERN_INFO
#define RNA_DBG_INFO_REM	KERN_INFO
#define RNA_DBG_MSG         KERN_WARNING
#define RNA_DBG_WARN		KERN_WARNING
#define RNA_DBG_WARN_REM	KERN_WARNING
#define RNA_DBG_ERR         KERN_ERR

/*
 * The following are never used at kernel level, and are here just for
 * compilation compatability.
 */

#define RNA_DBG_REMOTE         0x2000
#define RNA_DBG_HISTOGRAM      0x4000
#define RNA_DBG_EVENT          0x10000


// By setting rna_printk_level, we can control which printks are
// printed independently of the kernel's /proc/sys/kernel/printk setting.


/* MODULE LOAD OPTIONS */
/**
 * rna_printk_level is one of the things that controls the verbosity
 * of log messages.  See the comment at the top of rna_com_eth.c for
 * how-to info on controlling log levels.  Set to 4 normally, or 7
 * for max debugging. (KERN_INFO => 6, KERN_DEBUG => 7)
 */
extern int rna_printk_level;



/**
 * Module parameter that defines the rna_verbosity level.
 */
extern int rna_verbosity;

// XXX guessing the number here
#if ( LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,20) )
    #define DBG_LOG_CURRENT_PID current->pid
#else   /* LINUX_VERSION_CODE */
    #include <linux/sched.h>
    #define DBG_LOG_CURRENT_PID task_pid_nr(current)
#endif   /* LINUX_VERSION_CODE */

#define DBG_LOG_VERBOSE_FORMAT      " %s:%d: "
#define DBG_LOG_VERBOSE_ARGUMENTS   , __FUNCTION__, __LINE__

#define rna_printk(type, fmt, arg...) \
            __rna_printk( type \
                        , "fldc: pid [%"RNA_PID_T_FMT"]:" DBG_LOG_VERBOSE_FORMAT fmt \
                        , DBG_LOG_CURRENT_PID \
                          DBG_LOG_VERBOSE_ARGUMENTS \
                        , ## arg )

INLINE void rna_vprintk(const char *type, const char *fmt, va_list args)
{
    /* use kernel defaults when rna_printk_level == -1 */
    if (rna_printk_level == -1) {
        char *buf = kmalloc(strlen(type) + strlen(fmt) + 1, GFP_ATOMIC);
        if (buf) {
            strcpy(buf, type);
            strcat(buf, fmt);
            vprintk(buf, args);
            kfree(buf);
        } else {
            vprintk(fmt, args);
        }
    } else {
        /* default to highest priority (KERN_EMERG) */
        int priority = 0;
        if (strlen(type) == 3) { /* "<N>" */
            priority = type[1] - '0';
            if (priority < 1 || priority > 7) priority = 0;
        }

        if (priority <= rna_printk_level)  {
            vprintk(fmt, args);
        }
    }
}

static void __rna_printk(const char *type, const char *fmt, ...) __attribute__((format(printf,2,3)));


static void __rna_printk(const char * type, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    rna_vprintk(type, fmt, args);

    va_end(args);
}


#define rna_debug_log_assert(x)     BUG_ON(!(x))

#define rna_dbg_log         	rna_printk


#ifdef VERBOSE_LOGS
#define rna_trace(...) \
        if (unlikely(rna_verbosity)) { \
            rna_printk(KERN_ERR, ##__VA_ARGS__); \
        }
#else
#define rna_trace(...)
#endif


#else /* LINUX_KERNEL */
/* Linux User */




#endif /* Linux kernel vs Linux User */
#endif  /* _RNA_LOG_LINUX_H_ */
