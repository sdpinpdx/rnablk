/**
 * <rna_log.c> - Dell Fluid Cache block driver
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

/* 
	This file includes infrastructure necessary to log file 
	accesses rather than perform any actual caching.

	This uses netlink to send logs to user space.  Presumably,
	we would send a version of the rna client with logging
	enabled and cacheing disabled to customers, and they would
	send us back the logs so we could examine the sorts of I/O
	access patterns their apps use.

	For information on netlink, see:
 		http://lwn.net/Articles/131802/
		http://www.ietf.org/rfc/rfc3549.txt
		http://www.linuxjournal.com/article/7356
		http://en.wikipedia.org/wiki/Netlink

	For documentation on how to use the logging functionality
	provided herein, see:
	https://clearspace.rnanetworks.com/clearspace/docs/DOC-1048

*/
#ident "$URL$ $Id$"

#include "rna_log.h"
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/mempool.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/version.h>
#include "rna_com_linux_kernel.h"

#define NETLINK_RNA 22  /* probably unused for now, check netlink.h */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
typedef void * rna_log_workq_cb_arg_t;
#else
typedef struct work_struct * rna_log_workq_cb_arg_t;
#endif

struct rna_log_work {
    struct work_struct      work;
    char                    print_buffer[512];    
};

struct sock *nls; // netlink socket

/* Recieve callback.
 * We don't expect any messages, so just log the event. */

void rcv (struct sock* sk, int len) 
{
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&(sk->sk_receive_queue))) != NULL) {
		printk(KERN_INFO "received netlink message\n");
		kfree_skb(skb);
	}
}

#define RNA_LOG_POOL_SIZE   256
struct kmem_cache *rna_log_cache = NULL;
mempool_t *rna_log_pool = NULL;
static struct workqueue_struct *rna_log_workq;
int cleanup_log_needed = FALSE;

/* This should be called once at startup. */
void __init_log (void)
{	
#ifdef RNABLK_ENABLE_NETLINK
	printk(KERN_INFO "Initializing FLDC cache netlink socket\n");

    rna_log_cache = kmem_cache_create("rnablk_log_cache", 
                                      sizeof(struct rna_log_work), 
                                      8, 
                                      0, 
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
                                      NULL, 
#endif
                                      NULL);
    if (NULL == rna_log_cache) {
		printk(KERN_ERR "unable to allocate rna_log kmem cache\n");
        goto fail;             /* <---------- FAIL */
    }

    rna_log_pool = mempool_create_slab_pool(RNA_LOG_POOL_SIZE, rna_log_cache);

    if (NULL == rna_log_pool) {
        printk(KERN_ERR "failed to create rna_log mempool\n");
        goto fail;             /* <---------- FAIL */
    }

    rna_log_workq = rna_create_singlethread_workqueue("fldcblk_log_wq");
    if (NULL == rna_log_workq) {
		printk(KERN_ERR "unable to initialize netlink workqueue\n");
        goto fail;             /* <---------- FAIL */
    }

	/* the second argument, groups, gets overridden as 32 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
    nls = netlink_kernel_create(&init_net,
                                 NETLINK_RNA,
                                 0,
                                 NULL,
                                 NULL,
                                 THIS_MODULE);
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2,6,9)
	nls = netlink_kernel_create(NETLINK_RNA, 0, rcv, THIS_MODULE);
#else
	nls = netlink_kernel_create(NETLINK_RNA, rcv);
#endif

	if (nls == NULL) {
		printk(KERN_WARNING "unable to initialize netlink socket\n");
        goto fail;             /* <---------- FAIL */
	} else {
		log_string("started rna netlink connection\n");
        cleanup_log_needed = TRUE;
    }

 out:
    return;

 fail:
    if (NULL != rna_log_workq) {
        rna_destroy_workqueue(rna_log_workq);
        rna_log_workq = NULL;
    }

    if (NULL != rna_log_pool) {
        mempool_destroy(rna_log_pool);
        rna_log_pool = NULL;
    }

    if (NULL != rna_log_cache) {
        kmem_cache_destroy(rna_log_cache);
        rna_log_cache = NULL;
    }

    goto out;
#endif
}

/* Take a string and dump it to the netlink socket.
 * Gfp_mask could be GFP_KERNEL or GFP_ATOMIC depending on
 * context.
 * Return value of 0 denotes success. */
static void _log_string_wf(rna_log_workq_cb_arg_t arg)
{
#ifdef RNABLK_ENABLE_NETLINK
    struct work_struct *work = (struct work_struct *)arg;
    struct rna_log_work *w = container_of(work, struct rna_log_work, work);
	struct sk_buff *skb;
	char *pos; /* not really needed at present */
	int len;

	if (nls) {
		len = strlen(w->print_buffer) + 1;
		skb = alloc_skb(len, GFP_KERNEL);
		strncpy (skb->data, w->print_buffer, len);
		pos = skb_put(skb, len);

		/* sock, sk_buff, from pid, group, flags */
		netlink_broadcast(nls, skb, 0, 1, GFP_KERNEL);
	}

    mempool_free(w, rna_log_pool);
#endif
}

/* Take a string and dump it to the netlink socket.
 * Gfp_mask could be GFP_KERNEL or GFP_ATOMIC depending on
 * context.
 * Return value of 0 denotes success. */
int _log_string(char* buf, gfp_t gfp_mask)
{
#ifdef RNABLK_ENABLE_NETLINK
    struct rna_log_work *w;

    w = (struct rna_log_work*) mempool_alloc(rna_log_pool, GFP_ATOMIC);
    if (NULL == w) {
        return 0;   /* <------------------- FAIL */
    }

    RNA_INIT_WORK(&w->work, _log_string_wf, w);
    strncpy(w->print_buffer, buf, sizeof(w->print_buffer));
    rna_queue_work(rna_log_workq, &w->work);

#endif
    return 0;
}

int __log_string(char* buf) {
        return _log_string (buf, GFP_KERNEL);
}

int __log_string_atomic(char* buf) {
        return _log_string (buf, GFP_ATOMIC);
}

/* Like printk, but we print to the netlink socket.  Most users
 * of this api will want to use this function or the next one. */
void __printnl(const char * fmt, ...)
{
#ifdef RNABLK_ENABLE_NETLINK
	va_list args;

	/* This eats into our limited stack space, but
           its faster than malloc and a global buffer
           would need locking. */
	char print_buffer[512];
	
	va_start (args, fmt);
	vsnprintf(print_buffer, sizeof(print_buffer), fmt, args);
	va_end(args);

	_log_string (print_buffer, GFP_KERNEL);
#endif
}

void __printnl_atomic(const char * fmt, ...)
{
#ifdef RNABLK_ENABLE_NETLINK
        va_list args;
        char print_buffer[512];

        va_start (args, fmt);
        vsnprintf(print_buffer, sizeof(print_buffer), fmt, args);
        va_end(args);

        _log_string (print_buffer, GFP_ATOMIC);
#endif
}

/* This should be called once at shutdown. */
void __cleanup_log (void)
{
#ifdef RNABLK_ENABLE_NETLINK
    if (cleanup_log_needed) {
        // what do we need to do to clean up after ourselves?
        rna_flush_workqueue(rna_log_workq);
        rna_destroy_workqueue(rna_log_workq);

        mempool_destroy(rna_log_pool);
        kmem_cache_destroy(rna_log_cache);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
        netlink_kernel_release(nls);
        //netlink_unregister_notifier(?);
#else
        sock_release(nls->sk_socket);
#endif
        nls = NULL;
    }
#endif
}
