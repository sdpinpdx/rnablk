/**
 * <rna_com_module.c> - Dell Fluid Cache block driver
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

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/workqueue.h>

#include "../include/rna_common.h"
#include "rna_locks.h"
#include "rna_common_logging.h"
#include "rna_com_linux_kernel.h"
#include "rna_proc_ep.h"

#define PROC_DIR_NAME "rna_com"

/* This file contains boilerplate code specific to loading *
 * the com core as a module. */


/* REDEFINITIONS */

/* Only GPL modules are allowed to manage their own workqueues,
 * but proprietary modules may use a shared multithreaded workqueue
 * managed by the kernel.
 *
 * If MANUAL_WORKQUEUE is defined, we manage all of our own workqueues
 * through the GPL-only workqueue interface.  We must also use 
 * MODULE_LICENSE(GPL) in all modules that depend on the com.
 * This is not enforced by the linker, thus enabling MANUAL_WORKQUEUE
 * is not recommended except for testing. */

#define MANUAL_WORKQUEUE 1

#ifdef MANUAL_WORKQUEUE
struct workqueue_struct *rna_create_workqueue(const char *name)
{
	/* create a multithreaded workqueue */
	return create_workqueue(name);
}

struct workqueue_struct *rna_create_singlethread_workqueue(const char *name)
{
    /* create a multithreaded workqueue */
    return create_singlethread_workqueue(name);
}


void rna_flush_workqueue(struct workqueue_struct *wq)
{
	flush_workqueue(wq);
}

void rna_destroy_workqueue(struct workqueue_struct *wq)
{
	destroy_workqueue(wq);
}

int rna_queue_work(struct workqueue_struct *wq, struct work_struct *work)
{
	return queue_work(wq, work);
}

/*
 * rna_queue_delayed_work
 *  The 'delay' argument is in jiffies.
 */
int
rna_queue_delayed_work(struct workqueue_struct *wq,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
                       struct work_struct *work,
#else
                       struct delayed_work *work,
#endif
                       unsigned long delay)
{
	return queue_delayed_work(wq, work, delay);
}
#else /* MANUAL_WORKQUEUE */


/* The linux kernel provides a shared multi-threaded workqueue which
 * non-GPL modules may use.  We can wrap all of our workqueue functions 
 * to use these.
 *
 * In place of a workqueue_struct pointer, we use nonzero number
 * that tell us if the workqueue is supposed to have single-threaded
 * or multi-threaded semantics.  Testing the wq pointer for NULL
 * works as expected, as far as the calling application is concerned. 
 *
 * Single-threaded semantics are, unfortunately, difficult to support,
 * so, when possible, we want to convert all of our workqueue code not 
 * to expect strict ordering or non-concurrent execution.
 *
 * On newer kernels, we may be able to simulate single-threaded semantics
 * by using schedule_work_on CPU 0.  This is not implemented.
 *
 * When using shared workqueues, we must be careful not to call flush 
 * from a workqueue context or sleeping on a workqueue while waiting for
 * work that must also run from workqueue context.  Sleeping in general is
 * a bad idea.
 *
 * Workqueues created with plain "create_workqueue" and 
 * "create_singlethread_workqueue" are compatible with these functions,
 * so migrating code to use shared or dedicated workqueues is quite easy. 
 * 
 * If we're using a shared workqueue,  we use the constants 1 or 2 instead 
 * of a workqueue pointer.  This is unambigous, as a pointer cannot have 
 * either of those values. */

#define SINGLETHREADED_GLOBAL_WQ 1
#define MULTITHREADED_GLOBAL_WQ 2 

/* Wrapper to use the shared workqueue.  For a real, dedicated
 * workqueue, use plain old "create_workqueue" and set your
 * module license to GPL. */
struct workqueue_struct *rna_create_workqueue(const char *name)
{
        return (struct workqueue_struct *) MULTITHREADED_GLOBAL_WQ;
}

/* This is essentially the same as rna_create_workqueue.  For true
 * single-threaded semantics on a dedicated workqueue, use 
 * "create_singlethread_workqueue" and set your module license to
 * GPL. */
struct workqueue_struct *rna_create_singlethread_workqueue(const char *name)
{
        return (struct workqueue_struct *) SINGLETHREADED_GLOBAL_WQ;
}


void rna_flush_workqueue(struct workqueue_struct *wq)
{
	switch ((unsigned long)wq) {
		case MULTITHREADED_GLOBAL_WQ:
		case SINGLETHREADED_GLOBAL_WQ:
			flush_scheduled_work();
			break;
		default:
			flush_workqueue(wq);
	}
}

void rna_destroy_workqueue(struct workqueue_struct *wq)
{
	switch ((unsigned long)wq) {
		case MULTITHREADED_GLOBAL_WQ:
		case SINGLETHREADED_GLOBAL_WQ:
			/* do nothing */
			break;
		default:
			destroy_workqueue(wq);
			break;
	}
}

int rna_queue_work(struct workqueue_struct *wq, struct work_struct *work)
{
	int ret=0;

	switch ((unsigned long)wq) {
		case MULTITHREADED_GLOBAL_WQ : 
		case SINGLETHREADED_GLOBAL_WQ :
			/* We'd like to do something like schedule_work_on
			 * CPU 0 in the singlethreaded case, but that isn't 
			 * available on older kernels. */
			ret = schedule_work(work);
			break;
		case (unsigned long) NULL:
			BUG();
			break;
		default:
			ret = queue_work(wq, work);
			break;
	}

	return ret;
}

/*
 * rna_queue_delayed_work
 *  The 'delay' argument is in jiffies.
 */
int
rna_queue_delayed_work(struct workqueue_struct *wq,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
                       struct work_struct *work,
#else
                       struct delayed_work *work,
#endif
                       unsigned long delay)
{
        return schedule_delayed_work(work, delay);
}

#endif /* MANUAL_WORKQUEUE */

/* MODULE LOAD OPTIONS */

/**
 * rna_printk_level is one of the things that controls the verbosity
 * of log messages.  See the comment at the top of rna_com_eth.c for
 * how-to info on controlling log levels.  Set to 4 normally, or 7
 * for max debugging. (KERN_INFO => 6, KERN_DEBUG => 7)
 */

int rna_printk_level = 4;

module_param(rna_printk_level, int, 0444);
MODULE_PARM_DESC(rna_printk_level,
                 "Printk level for rnacache; set to 7 for everything or "         
                 "0 for only KERN_EMERG.  Default is 4, which prints "  
                 "only (KERN_WARNING) or higher.  Set to -1 to use the "
                 "kernel's standard printk settings.");


#ifdef RDMA_READ_OVERRIDE
int rdma_read_override = -1;
module_param(rdma_read_override, int, 0444);
MODULE_PARM_DESC(rdma_read_override, "rdma read size override (debug only)");
#endif

/**
 * Module parameter that defines the rna_verbosity level.
 */
int rna_verbosity = 0;

module_param(rna_verbosity, int, 0);
MODULE_PARM_DESC(rna_verbosity,
                 "Initial verbosity level (0 or 1; defaults to "
                 "0, which is Quiet)");


/* INIT / EXIT */

static int com_core_init(void)
{
    rna_printk(KERN_INFO, "rna_com_core module init starting\n");

    rna_spin_lock_init(transport_list_lock);

#ifdef ENABLE_PROC_EP
    /* ep proc files are the only current user of this directory */ 
    proc_dir = proc_mkdir(PROC_DIR_NAME, NULL);
    proc_ep_init();
#endif

    rna_printk(KERN_INFO, "rna_com_core module init complete\n");
    return 0;
}


static void com_core_exit(void)
{
    proc_ep_cleanup();

#ifdef ENABLE_PROC_EP
    if (proc_dir)
        remove_proc_entry(PROC_DIR_NAME, NULL);
#endif

    rna_printk(KERN_INFO, "rna_com exit\n");
}

/* MODULE REGISTRATION */

module_init(com_core_init);
module_exit(com_core_exit);

MODULE_AUTHOR("Dell Inc");

/* We use GPL-only workqueue functions.*/
MODULE_LICENSE("GPL");

/* EXPORTED SYMBOLS */

