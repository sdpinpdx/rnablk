/**
 * <rna_com_core.c> - Dell Fluid Cache block driver
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

#include "platform.h"

CODE_IDENT("$URL: https://svn.rnanetworks.com/full/tags/HERMES_2_1_0_RC1/linux-kernel/com/rna_com_core.c $ $Id: rna_com_core.c 34857 2014-06-27 20:43:21Z greivel $")

#include <linux/net.h>
#include <linux/socket.h>
#include <linux/hardirq.h> /* for in_atomic */

#include "../include/rna_common.h"
#include "rna_com_linux_kernel.h"
#include "rna_proc_ep.h"
#include "priv_data.h"

/* Internal function prototypes */
int com_send_internal (struct com_ep *ep,
                       struct buf_entry *buf,
                       int size,
                       int nocredit,
                       enum env_type env_type);

/* Globals */

/* List of transports that have registered with rna_com_core */
LIST_HEAD(transport_list);

/* Protects application against insertion or removal of a 
 * transport while we're iterating over transport list, which
 * is something we probably aren't going to do very often. */
rna_spinlock_t transport_list_lock;

struct proc_dir_entry *proc_dir=NULL;

/* Common Functions */

/* Applications create a com context with com_init. 
 * Unlike user space and previous versions of the kernel com layer,
 * com_init now creates an empty context that isn't associated with
 * any transport.  Transports must be added manually with 
 * com_add_transport.
 *
 * Todo: Add locking.
 *       It isn't strictly needed, assuming that all initialization happens 
 *       in a single thread before the first EP is created, and tear-down 
 *       is left until all EPs are free. */
struct rna_com* com_init(int min_proto_version, int max_proto_version)
{
    struct rna_com *com = rna_kzalloc(com, GFP_KERNEL);

    if (NULL != com) {
        com->min_proto_version = min_proto_version;
        com->max_proto_version = max_proto_version;
    }

    return com;
}

/* Add a transport to an existing com instance.  Usually, we will
 * want to call this once for RC and once for IP_TCP.  Order may
 * affect performance and behavior of a few functions, 
 * such as com_find_ep.  The transport loaded first has highest
 * priority. */
int com_add_transport(struct rna_com *com, struct rna_com_attrs *attrs) 
{
    int ret = 0;
    struct rna_transport_handle* transport_handle;
    int transport_idx = com->avail_coms;
    int i;

    for (i=0; i < com->avail_coms; i++) {
        if (com->transport_types[i] == attrs->com_type) {
            rna_printk(KERN_ERR, "A transport with type [%d] already "
                        "exists.\n", attrs->com_type);
            ret = -EINVAL;
        }
    }

    if (0==ret) {
        if (com->avail_coms >= MAX_TRANSPORTS) {
            rna_printk(KERN_ERR, "Com instance unable to support more than "
                        "%d transports.", MAX_TRANSPORTS);
            ret = -EINVAL;
        } else {
            if (0 == attrs->comp_mode) {
                /* We ought to be explicitly setting the completion mode.*/
                rna_printk(KERN_ERR, 
                           "completion mode unspecified, setting to %d\n",
                           RNA_DEFAULT_COM_COMP_MODE);
                attrs->comp_mode = RNA_DEFAULT_COM_COMP_MODE;
            }

            transport_handle = transport_init(attrs);

            if (transport_handle) {
                BUG_ON(transport_handle->transport->transport_type 
                       != attrs->com_type);

                com->transports[transport_idx] = transport_handle;
                com->transport_types[transport_idx] = attrs->com_type;
                com->avail_coms++;
            } else {
                ret = -EINVAL;
            }
        }
    }

    return ret;
}

/* Create a com instance, add all known transports.  Fail if no 
 * transports are available.  This is for convenience, 
 * "com_add_transport" provides a more flexible interface, which
 * allows the application to use separate rna_com_attrs structures
 * for each transport. */

struct rna_com *com_init_all(int transports, 
                             const struct rna_com_attrs *attrs_ptr,
                             int min_proto_version,
                             int max_proto_version)
{
    struct rna_com *com = com_init(min_proto_version, max_proto_version);
    struct rna_com_attrs attrs = *attrs_ptr;

    if (com) {
        if (transports & IB_TRANSPORT) {
            attrs.com_type = RC;
            if (0 == com_add_transport(com, &attrs)) {
                rna_printk(KERN_ERR, "Using RDMA transport\n");
            } else {
                rna_printk(KERN_ERR, "RDMA transport unavailable\n");
            }
        }

        if (transports & TCP_TRANSPORT) {
            attrs.com_type = IP_TCP;
            if (0 == com_add_transport(com, &attrs)) {
                rna_printk(KERN_ERR, "Using TCP transport\n");
            } else {
                rna_printk(KERN_ERR, "TCP transport unavailable\n");
            }
        }

        if (com->avail_coms == 0) {
            rna_printk(KERN_ERR, "No transports available.\n");
            com_exit(com);
            com = NULL;
        }
    } else {
        rna_printk(KERN_ERR, "Unable to allocate com instance.\n");
    }
    return com;
}

/* Return TRUE if a transport of the given type has been added to the com. */
int com_transport_enabled(struct rna_com *com, enum com_type type) 
{
    int ret = FALSE;
    int i;
	
    for (i=0; i < com->avail_coms; i++) {
        if (com->transport_types[i] == type) {
            ret = TRUE;
            break;
        }
    }

    return ret;
}

/* Delete a transport.  Not likely to be used often -- usually we'll
 * just want to call com_exit(). */
int com_del_transport(struct rna_com *com, enum com_type type) 
{
    int ret = -EINVAL;
    int i;

    for (i=0; i < com->avail_coms; i++) {
        if (com->transport_types[i] == type) {
            ret = transport_exit(com->transports[i]);
            BUG_ON(ret);

            com->avail_coms--;
            break;
        }
    }

    /* shift the remainder of the array */
    if (ret == 0) {
        for(; i<com->avail_coms; i++) {
            com->transports[i] = com->transports[i+1];
            com->transport_types[i] = com->transport_types[i + 1];
        }

        com->transports[i] = NULL;
        com->transport_types[i] = 0;
    }

    return ret;
}

/* Tear down all transport instances associated with this com,
 * and free the com. */
int com_exit(struct rna_com *com) 
{
    int i, ret = 0;

    for (i=0; i < com->avail_coms; i++) {
        rna_printk(KERN_ERR, "exiting transport type %d\n", com->transport_types[i]);
        ret = transport_exit(com->transports[i]);
        BUG_ON(ret);
    }

    kfree(com);

    return ret;
}

/* 
 * Determine the highest protocol version supported by both
 * the com and an incoming connection request.  Return 0 if
 * there is a common version, otherwise return negative.
 * Best_match is set to the largest common version if there is
 * one, otherwise it's the closest match within the com handle's
 * range. 
 */
int common_proto_version(struct rna_com *com_handle,
                         struct req_priv_data *priv_data,
                         int *best_match)
{
    int ret = max_overlap(com_handle->min_proto_version,
                          com_handle->max_proto_version,
                          priv_data->min_proto_version,
                          priv_data->max_proto_version,
                          best_match);
    if (unlikely(ret < 0)) {
        rna_printk(KERN_ERR, "protocol version mismatch: "
                   "we support [%d-%d], but peer supports [%d-%d]\n",
                   com_handle->min_proto_version,
                   com_handle->max_proto_version,
                   priv_data->min_proto_version,
                   priv_data->max_proto_version);
    }   
            
    return ret;
}           


/* Figure out how many EPs we have active, for statistics. */
int com_get_connection_count(struct rna_com *com) 
{
    int i;
    int ret = 0;
    for (i=0; i < com->avail_coms; i++) {
        ret += atomic_read(&(com->transports[i]->connection_count));
    }

    return ret;
}

/**
 * Returns whether the ep is connected. This can be used by the application to determine
 * if it should wait on the connect or if the ep is functional. Getting an EP reference will
 * return success even if the ep is not yet connected. So the application can use that in
 * conjunction with this call to get a valid and persistent state of the EP.
 *
 * The application should have a local reference on the ep before checking the connected state
 * @param ep - the endpoint
 * @return 0 if not connected, 1 if connected
 */
int com_connected ( struct com_ep *ep )
{
    return ( atomic_read ( &ep->ep_state ) == EP_CONNECTED );
}

/**
 * Connect with the specified destination, returning when the connect succeeds,
 * fails, or times out.
 *
 * Arguments:
 *  ep          The ep to connect
 *  dst_addr    The destination address
 *  timeout     Number of SECONDS to wait for the connection to be established.
 *
 * Returns:
 *   0 on success.  If a connect_cb is defined, it has been/is being/is about
 *     to be invoked.
 *   1 on timeout.  A connect_cb, disconnect_cb, or reject_cb will not be
 *     invoked.
 *  -1 on connect failure.
 */
int com_connect_sync(struct com_ep *ep, struct sockaddr *dst_addr, int timeout)
{

    int ret;

    /*
     * Make sure the ep doesn't disappear out from under us, due to an
     * asynnchronous disconnect after the following connect.  We don't want
     * to access freed memory.
     */
    com_inc_ref_ep(ep);
    
    ret = com_connect(ep, dst_addr);
    if (0 != ret) {
        rna_spin_lock(ep->transport_handle->ep_dsc_lock);
        ep->callback_state = CB_FAILED;
        ret = -1;
        goto done;
    }

    (void) wait_event_interruptible_timeout(
                              ep->conn_wait,
                              ((atomic_read( &ep->ep_state ) == EP_CONNECTED) ||
                               (atomic_read( &ep->ep_state ) == EP_DISCONNECTED)),
                              msecs_to_jiffies( timeout * 1000 ) );

    rna_spin_lock(ep->transport_handle->ep_dsc_lock);
    if (CB_INIT == ep->callback_state) {
        /*
         * The connect timed out and is still unfinished.  Mark it as failed
         * to assure that if the connect eventually succeeds, we don't get an
         * unexpected connect_cb and disconnect_cb if the connect eventually
         * succeeds and is disconnected.
         */
        ep->callback_state = CB_FAILED;
        ret = 1;
    } else {
        /*
         * The connect succeeded.  Note that it may have since disconnected;
         * nothing is guaranteed, since an asynchronous disconnect can happen
         * at any moment.
         */
        ret = 0;
    }

done:
    rna_spin_unlock(ep->transport_handle->ep_dsc_lock);
    com_release_ep(ep);
    return ret;
}

/* 
 * Allocate a pool of buf_entries, using the transport-specific
 * com_alloc_buf_pool_elem function.  This is generally used internally
 * by the com transports, but it could be used by an application
 * directly if the need were to arise.
 *
 * Note: only IB needs to set aside extra space for the envelope.
 */
int com_alloc_buf_pool(struct com_ep *ep, 
                       struct buf_pool *buf_pool,
                       int count,
                       int buf_size)
{
    int ret=0;
    int i;

    struct buf_pool_ctx ctx;

    BUG_ON(NULL == ep);
    BUG_ON(NULL == buf_pool);

    if (count <= 0 || buf_size < 0)
        return -EINVAL;

    ctx.ep       = ep;
    ctx.pool     = buf_pool;
    ctx.buf_size = buf_size + sizeof(struct rna_com_envelope);

    buf_pool->count = count;
    buf_pool->buf_size = buf_size + sizeof(struct rna_com_envelope);

    buf_pool->entries =
        (struct buf_entry **)
            rna_alloc_boxed_array(count,
                                  sizeof(**buf_pool->entries),
                                  com_alloc_buf_pool_elem,
                                  com_free_buf_pool_elem,
                                  (unsigned long) &ctx);

    if (NULL != buf_pool->entries) {
        atomic_set(&buf_pool->num_avail, count);
        buf_pool->next_avail = 0;
    } else {
        rna_printk(KERN_ERR, "buf pool allocation failed\n");
        ret = -ENOMEM;
    }

    return ret;
}

/* 
 * Free a pool of buf_entries using the transport-specific function
 * com_free_buf_pool_elem.
 */
int com_free_buf_pool (struct com_ep *ep, struct buf_pool *buf_pool)
{
    int i;
    struct buf_pool_ctx ctx;

    rna_trace("ep=0x%p, buf_pool=0x%p\n", ep, buf_pool);

    ctx.ep       = ep;
    ctx.pool     = buf_pool;
    ctx.buf_size = buf_pool->buf_size;

    if (!ep) {
        rna_printk (KERN_INFO, "ep is NULL, returning -1\n");
        return -1;
    }

    if (!buf_pool->count || !buf_pool->buf_size) {
        rna_printk (KERN_INFO, "count or buf_size is 0, returning -EINVAL\n");
        return -EINVAL;
    }

    if (buf_pool->entries) {
        rna_free_boxed_array((void**)buf_pool->entries, buf_pool->count,
                             com_free_buf_pool_elem, (unsigned long) &ctx);
    }

    buf_pool->next_avail = 0;
    buf_pool->entries = NULL;
    atomic_set(&buf_pool->num_avail, 0);

    return 0;
}


/* Debugging aid -- figure out which buffer pool we're dealing with. */
const char* pool_name(struct com_ep *ep, struct buf_pool *bp)
{
    char *pool = "unknown";
    if (bp == &ep->recv_pool) {
        pool = "recv";
    } else if (bp == &ep->send_pool) {
        pool = "send";
    } else if (bp == &ep->credits_pool) {
        pool = "credits";
    }

    return pool;
}

/*
 * Find the next free buffer from a buffer pool.
 * Caller is responsible to make sure EP is connected 
 * and we hold a reference. 
 * Returns 0 and sets *buf on success,
 * If there are no free buffers right now, returns -EAGAIN.
 *
 * Contrary to the name, this can be used for recieve buffers
 * as well.
 */
int com_get_send_buf_from_pool(struct com_ep *ep,
                               struct buf_entry **buf,
                               struct buf_pool *bp)
{
    int ret = 0;
    unsigned int index = bp->next_avail % bp->count;
    struct buf_entry *tmpbuf;
    int avail;
    int retries = 0;

    if (unlikely(*buf != NULL)) {
        rna_printk(KERN_ERR, "*buf not NULL\n");
        *buf = NULL;
    }

    avail = atomic_read(&bp->num_avail);
    if (unlikely(avail < 0 || avail > bp->count)) {
        rna_printk(KERN_ERR, "%s buffer pool available count is bogus.  "
                   "%d of %d available.\n",
                   pool_name(ep, bp), avail, bp->count);
        print_ep(ep);
    }

    while(atomic_read(&bp->num_avail) > 0 && 
          EP_CONNECTED == atomic_read(&ep->ep_state))
    {
        retries++;
        tmpbuf = (bp->entries[index]);
        if(atomic_cmpxchg(&tmpbuf->buf_use_state, BUF_USE_FREE,
                          BUF_USE_ALLOCATED) == BUF_USE_FREE) {
            *buf = tmpbuf;
            (*buf)->context = NULL;
            (*buf)->send_cmp_cb = NULL;
            atomic_dec(&bp->num_avail);
            bp->next_avail = (index + 1) % bp->count;
            break;
        }
        index = (index + 1) % bp->count;

        if (unlikely(retries == (2 * bp->count))) {
           rna_printk(KERN_ERR,
                      "No available bufs in %s pool %p (%d/%d), state [%s].\n",
                      pool_name(ep, bp), bp,
                      atomic_read(&bp->num_avail), bp->count,
                      ep_to_state_string(ep));
            print_ep(ep);
            ret = -EAGAIN;
            break;
        }
    }

    if (NULL == *buf) {
        rna_printk(KERN_ERR,
                   "No available sendbufs in %s pool %p (%d/%d), state [%s].\n",
                   pool_name(ep, bp), bp,
                   atomic_read(&bp->num_avail), bp->count,
                   ep_to_state_string(ep));
        print_ep(ep);
        ret = -EAGAIN;
    }
    return ret;
}

/**
 * Iterate over the global list of endpoints, and disconnect each.
 * @return 0 if all disconnected, otherwise return current connect count.
 *
 * Usually, we will call this from the transport modules during
 * transport_exit.  Applications will usually want to call 
 * com_disconnect_all_eps. */

int transport_disconnect_all_eps (struct rna_transport_handle* g_com)
{
    int timeout = 0;
    struct com_ep *ep = NULL;
    int ret = 0;
    int con_count;
    int dangling_ep_count = 0;

    BUG_ON(NULL == g_com);

    con_count = atomic_read ( &g_com->connection_count );
    rna_printk ( KERN_INFO, "start: connect count %d\n", con_count );
    mutex_lock ( &g_com->ep_lst_lock );
    list_for_each_entry ( ep, &g_com->ep_lst_head, entries ) {
        queue_disconnect_work ( ep );
    }
    mutex_unlock ( &g_com->ep_lst_lock );

    /* The conn workq does all the disconnect work, so block on that first */
    if (NULL != g_com->rna_conn_workq) {
        rna_flush_workqueue ( g_com->rna_conn_workq );
    }

    if ( con_count > 0 ) {
        timeout = 60000; /* 1 minute */

        ret = wait_event_interruptible_timeout ( g_com->all_disconnected_wait,
                ( atomic_read ( &g_com->connection_count ) == 0 ),
                msecs_to_jiffies ( timeout ) );

        if (unlikely(ret <= 0)) {
            rna_printk(KERN_ERR, "wait to disconnect all eps returned %d%s; "
                       "connection count %d\n", ret, 0 == ret ?
                       " (timed out)" : "",
                       atomic_read(&g_com->connection_count));
            mutex_lock ( &g_com->ep_lst_lock );
            list_for_each_entry ( ep, &g_com->ep_lst_head, entries ) {
                rna_printk(KERN_ERR, "dangling EP: " NIPQUAD_FMT
                           " pointer [%p] type [%d] state [%d] ref_count [%d]\n",
                           NIPQUAD(ep->dst_in.sin_addr), ep, ep->user_type,
                           atomic_read(&ep->ep_state), atomic_read(&ep->ref_count));
                dangling_ep_count++;
            }
            if (unlikely (0 == dangling_ep_count)) {
                rna_printk(KERN_ERR, "all_disconnect_wait didn't wait but no "
                           "dangling EPs\n");
            }

            mutex_unlock ( &g_com->ep_lst_lock );
        }
    }

    rna_printk(KERN_INFO, "end: connect count %d\n", atomic_read(&g_com->connection_count));
    return dangling_ep_count;
}

/* Attempt to disconnect all eps.  Returns remaining connection count. */
int com_disconnect_all_eps(struct rna_com* com) 
{
    int i;
    int ret = 0;
    for (i=0; i < com->avail_coms; i++) {
        set_disconnecting(com->transports[i]);
        ret += transport_disconnect_all_eps(com->transports[i]);
    }

    return ret;
}

int com_disable(struct rna_com* com)
{
    int i;
    int ret = 0;

    for (i=0; i < com->avail_coms; i++) {
        ret |= transport_disable(com->transports[i]);
    }

    return ret;
}

/**
 * Get the state of the endpoint see - enum ep_state in rna_com_common.h
 * @param ep - the endpoint
 * @return the state
 */
int com_ep_state (struct com_ep *ep)
{
    return atomic_read (&ep->ep_state);
}

/**
 * Set the "context" of an ep - current either the ep itself or NULL
 * @param ep - the endpoint
 * @param context - the context
 */
inline void com_set_ep_context ( struct com_ep *ep, void *context )
{
    if ( ep )
        ep->context = context;
}

/**
 * Set the user_type of an ep -- see user_type enum in ../../fcache/protocol.h
 * @param ep - the endpoint
 * @param user_type - the user type
 */
inline void com_set_ep_user_type ( struct com_ep *ep, user_type_t user_type )
{
    if ( ep )
        ep->user_type = user_type;
}

/**
 * Return the user_type of an ep -- see user_type enum in ../../fcache/protocol.h
 * @param ep - the endpoint
 */
inline char com_get_ep_user_type( struct com_ep *ep )
{
    return ep->user_type;
}

inline struct sockaddr_in com_get_ep_dst_in( struct com_ep *ep )
{
    return ep->dst_in;
}

/**
 * Construct a name for debugging purposes, based on the ep address
 * and the process ID of the caller (there is no way to get the hostname
 * from a kernel module).
 * @param ep - the ep we're associated with
 * @param uniquename - the buffer to put the name into
 * @param rlen - the length of uniquename
 * @return 0 on success, otherwise -1
 */
int com_get_unique_client_name ( void *ctx, char *uniquename, int rlen )
{
    snprintf ( uniquename, rlen, "%p.%d", ctx, current->pid );
    return 0;
}

/**
 * Decrement the connection count, warning if the count goes below zero.
 * @param calling_fn - the name of the calling function
 * @return TRUE if the reference count is zero, FALSE otherwise
 */
int
_connection_count_dec_and_test ( struct rna_transport_handle* g_com, const char *calling_fn )
{
    int ret = 0;
    ret = atomic_add_return ( -1, &g_com->connection_count );

    if ( ret < 0 ) {
        rna_printk ( KERN_ERR,
                     "%s -- connection count decremented below zero. Count[%d]\n", calling_fn, ret );
    }

    else  {
        rna_trace ( "%s -- connection_count_dec_and_test: new count %d\n", calling_fn, ret );
    }

    return ( ret <= 0 ); // still act like 0 even if an error make it go negative
}

/**
 * Increment the global connection count
 * @param calling_fn - the name of the calling function
 */
void
_connection_count_inc ( struct rna_transport_handle* g_com, const char *calling_fn )
{
    atomic_inc ( &g_com->connection_count );
    rna_trace ( "%s new count %d\n",
                calling_fn,
                atomic_read ( &g_com->connection_count ) );
}

/**
 * Increment reference count and check state. Spinlock guarantees that a derefence hasn't
 * advanced the state between the increment and state check.
 * @param ep - the ep we're associated with
 * @param calling_fn - the name of the function calling this (for debugging)
 * @return 0 on success, otherwise -1
 */
int _com_inc_ref_ep ( struct com_ep *ep, const char *calling_fn )
{
    int state;
    int ret = 0;
    int ref_count_after;
    int ref_count_before;

    if ( !ep )
        return -1;

    ref_count_before = atomic_read ( &ep->ref_count );
    atomic_inc ( &ep->ref_count );
    ref_count_after = atomic_read ( &ep->ref_count );
    rna_trace ( "Caller: %s, ep: %p, ref_count before: %d, after: %d, returning: %d\n",
                calling_fn, ep, ref_count_before, ref_count_after, ret );
    return ret;
}

/* Used by com_find_next_ep to iterate through transports associated
 * with a particular com.  This would have been easier, had I used a
 * list rather than an array. */
static struct rna_transport_handle* 
	find_next_transport(struct rna_com *com, 
	                    struct rna_transport_handle * prev)
{
	int i;
	int found_idx = -1;
	struct rna_transport_handle *next = NULL;

	for (i=0; i<com->avail_coms; i++) {
		if (com->transports[i] == prev) {
			found_idx = i;
			break;
		}
	}

	if (found_idx != -1 && (found_idx+1 < com->avail_coms)) {
		/* "prev" was found in the list and wasn't the last one */
		next = com->transports[found_idx+1];
	}

	return next;
}

/**
 * Find EP based on user_type
 * @param prev - the ep before the one we want in the list or
 *               NULL to start at the beginning
 * @return a pointer to the ep we're after, or NULL
 *
 * We take a reference on the ep we return, and we drop a reference
 * on the ep we're given.  The application need not do any
 * explicit reference counting, so long as it doesn't abort an
 * iteration in the middle.
 *
 * It is unsafe to unload a transport instance while this is running.
 *
 * The logic of this function is confusing because we are essentially 
 * jumping into the middle of a nested loop with hardly any context.
 *
 * A full iteration over all EPs is O(num_eps + num_transports). */

struct com_ep* com_find_next_ep ( struct rna_com *com_handle, 
                                  struct com_ep *original_prev, 
                                  user_type_t user_type)
{
	struct rna_transport_handle* transport = NULL;
	struct com_ep *next = NULL;
	struct com_ep *prev = original_prev;
	struct com_ep *found_ep = NULL;
	struct list_head cur;
	int i = 0;

	if (NULL == prev) {
		/* start at the beginning */
		if (com_handle->avail_coms > 0) {
			transport = com_handle->transports[0];
		}
	} else {
		transport = prev->transport_handle;
	}

	while (transport && NULL == found_ep) {
		mutex_lock (&transport->ep_lst_lock);

		do {
			if (++i % 1000 == 0) {
				rna_printk(KERN_ERR, "i %d, probably stuck in loop\n", i);
			}
			/* Find the next EP in the list. */
			if (NULL == prev) {
				/* We don't have a previous EP, so
				 * start at the beginning. */
				if (!list_empty(&transport->ep_lst_head)) {
					next = list_entry(transport->ep_lst_head.next, 
					                  struct com_ep, entries);
				} else {
					break;
				}
			} else {
				if (list_is_last(&prev->entries, &transport->ep_lst_head)) {
					break;
				} else {
					next = list_entry(prev->entries.next, 
					                  struct com_ep, entries);
				}
			}

			if (next->user_type == user_type) {
				/* We found an EP that matches */
		 		found_ep = next;
				com_inc_ref_ep(found_ep);
			} else {
				/* Not the EP we're looking for, 
				 * continue looking. */
				prev = next;
			}

		} while (NULL != next && NULL == found_ep);

		mutex_unlock (&transport->ep_lst_lock);

		transport = find_next_transport(com_handle, transport);
		prev = next = NULL;
	}

	if (original_prev)
		com_release_ep(original_prev);

	return found_ep;
}

/**
 * Get a printable string for an ep's state
 *
 * @param state - the ep state
 * @return a string describing the ep state
 */
const char * get_ep_state_string ( enum ep_state state )
{
    char * ret;

    switch ( state ) {
        case EP_INIT:
            ret = "EP_INIT";
            break;
        case EP_CONNECT_PENDING:
            ret = "EP_CONNECT_PENDING";
            break;
        case EP_SEND_PRIV_DATA:
            ret = "EP_SEND_PRIV_DATA";
            break;
        case EP_PRIV_DATA_SENT:
            ret = "EP_PRIV_DATA_SENT";
            break;
/*      case EP_ETH_RDMA_CONNECT_PENDING:
            ret = "EP_ETH_RDMA_CONNECT_PENDING";
            break;
        case EP_ETH_RDMA_SEND_PRIV_DATA:
            ret = "EP_ETH_RDMA_SEND_PRIV_DATA";
            break;
        case EP_ETH_RDMA_PRIV_DATA_SENT:
            ret = "EP_ETH_RDMA_PRIV_DATA_SENT";
            break; */
        case EP_CONNECTED:
            ret = "EP_CONNECTED";
            break;
        case EP_DISCONNECT_PENDING:
            ret = "EP_DISCONNECT_PENDING";
            break;
        case EP_DISCONNECTED:
            ret = "EP_DISCONNECTED";
            break;
        case EP_FREE:
            ret = "EP_FREE";
            break;
        default:
            ret = "unknown ep_state";
            break;
    }

    return ret;
}

enum com_type com_get_transport_type(struct rna_transport_handle * com_handle) {
        return com_handle->transport->transport_type;
}

void * com_ep_get_priv_data (struct com_ep *ep)
{
    BUG_ON(NULL == ep->com_handle);
    return ep->com_handle->priv_data;
}

void com_set_priv_data (struct rna_com *com_handle, void *val)
{
    BUG_ON(NULL == com_handle);
    com_handle->priv_data = val;
}

/* Transport modules don't export any symbols of their own,
 * rather they register sets of callbacks with the core com
 * module, via register_transport.  Typically this is done
 * at module load time.
 *
 * We don't allow any of the methods to be NULL; this way,
 * we don't have to check them for NULL every time we use
 * them. */

int register_transport(struct rna_transport* transport)
{
    BUG_ON(NULL == transport ||
           NULL == transport->transport_init_fn ||
           NULL == transport->transport_disable_fn ||
           NULL == transport->transport_exit_fn ||
           NULL == transport->transport_alloc_ep_fn ||
           NULL == transport->com_connect_fn ||
           NULL == transport->com_disconnect_fn ||
           NULL == transport->queue_disconnect_work_fn ||
           NULL == transport->com_get_send_buf_fn ||
           NULL == transport->com_put_send_buf_fn ||
           NULL == transport->com_wait_send_avail_fn ||
           NULL == transport->com_send_fn ||
           NULL == transport->com_get_rdma_buf_fn ||
           NULL == transport->com_put_rdma_buf_fn ||
           NULL == transport->com_get_rkey_fn ||
           NULL == transport->com_rdma_read_fn ||
           NULL == transport->com_wait_rdma_avail_fn ||
           NULL == transport->com_rdma_write_fn ||
           NULL == transport->com_reg_single_fn ||
           NULL == transport->com_dereg_single_fn ||
           NULL == transport->com_isreg_fn ||
           NULL == transport->com_wait_connected_fn ||
           NULL == transport->_com_release_ep_fn ||
           NULL == transport->transport_find_ep_fn ||
           NULL == transport->com_get_guid_fn ||
           NULL == transport->com_rdma_sgl_fn ||
           NULL == transport->com_reg_sgl_fn ||
           NULL == transport->com_mapping_error_fn ||
           NULL == transport->com_dereg_sgl_fn ||
           NULL == transport->transport_get_device_attributes_fn ||
           NULL == transport->transport_ep_send_order_fn ||
           NULL == transport->transport_alloc_buf_pool_elem_fn ||
           NULL == transport->transport_free_buf_pool_elem_fn);

    rna_spin_lock(transport_list_lock);
    list_add_tail(&transport->transport_list, &transport_list);
    rna_spin_unlock(transport_list_lock);

    rna_printk(KERN_INFO, "registered transport type %d\n", transport->transport_type);

    return 0;
}

/* Remove a transport from the transport_list, typically 
 * called when the transport module is unloaded. */

int unregister_transport(struct rna_transport* transport) 
{
    int ret = 0;
    int ref_count;

    BUG_ON(NULL == transport);

    rna_spin_lock(transport_list_lock);

    ref_count = module_refcount(transport->module);
    if (0 == ref_count)
        list_del(&transport->transport_list);
    else {
        rna_printk(KERN_ERR, "Failed to unregister a transport "
                   "with a non-zero ref_count of %d\n", ref_count);
        ret = -EBUSY;
    }
    rna_spin_unlock(transport_list_lock);

    return ret;
}

/* 
 * Send completion for unsolicited ack.
 * We must override the standard send completion, as the application
 * may not be prepared for a copmletion for a send it knows nothing
 * about.
 */
int 
com_notify_ack_done (struct com_ep *ep, void* ep_ctx, void* send_ctx, int status)
{
    if (status) {
        rna_printk(KERN_ERR, "Unsolicited ack send failed.\n");
    }
    BUG_ON(1 != atomic_cmpxchg(&ep->ack_in_progress, 1, 0));
    return 0;
}

/* 
 * Send an unsolicited ack if we have an ack backlog and our extra
 * buffer is available.  The locking requirements of the TCP receive 
 * path don't allow us to call this inline, so we use a workqueue.
 * Set force to nonzero to always send ack regardless of whether
 * our peer is low on credits.
 */
static int _com_unsolicited_ack(struct com_ep *ep, int force)
{
    int ret=0;
    struct buf_entry *buf = NULL;

    if (force
     || atomic_read(&ep->need_ack_ack)
     || (atomic_read(&ep->unacked_recvs) > ep->num_recv/2)) {
        if (0 == atomic_cmpxchg(&ep->ack_in_progress, 0, 1)) {
            ret = com_get_send_buf_from_pool(ep, &buf, &ep->credits_pool);
            if (NULL == buf || ret) {
                /* This should be a rare occurance. */
                rna_printk(KERN_ERR, 
                           "Couldn't get sendbuf for unsolicited ack on EP [%p]\n", ep);
                print_ep(ep);
                BUG_ON(1 != atomic_cmpxchg(&ep->ack_in_progress, 1, 0));
            } else {
                /* Bypass credit accounting. */
                buf->send_cmp_cb = com_notify_ack_done;
                ret = com_send_internal(ep, buf, 0, TRUE, ENV_TYPE_ACK);
                if (ret) {
                    rna_printk(KERN_ERR, "sending unsolicited ack failed\n");
                    BUG_ON(1 != atomic_cmpxchg(&ep->ack_in_progress, 1, 0));
                }
            }
        } else {
            /* Our peer is rather slow in acknowledging our previous ack. */
            rna_printk(KERN_DEBUG, "Can't send unsolicited ack, previous ack outstanding.\n");
        }
    }

    return ret;
}

int com_unsolicited_ack(struct com_ep *ep)
{
    return  _com_unsolicited_ack(ep, FALSE);
}

int com_force_unsolicited_ack(struct com_ep *ep)
{
    return  _com_unsolicited_ack(ep, TRUE);
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
void com_send_unsolicited_ack(void *arg)
#else
void com_send_unsolicited_ack(struct work_struct *arg)
#endif
{   
    struct com_ep *ep = container_of(arg, struct com_ep, unsolicited_ack_work);
    com_unsolicited_ack(ep);
}

/* 
 * We use a workqueue to deal with the TCP receive path's locking
 * constraints.
 */
int com_maybe_queue_unsolicited_ack(struct com_ep *ep)
{
    int ret = 0;
    struct work_struct *w = &ep->unsolicited_ack_work;

    if (atomic_read(&ep->need_ack_ack)
     || (atomic_read(&ep->unacked_recvs) > ep->num_recv/2)) {
        /* Note: queue_work doesn't do anything if the work is already
         * queued, which is what we want here.  In that case, rna_queue_work
         * returns 0. */
        ret = rna_queue_work(ep->transport_handle->rna_delayed_send_workq, w);
    }

    return 0;
} 

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
void com_process_credits_available(void *arg)
#else
void com_process_credits_available(struct work_struct *arg)
#endif
{
    struct com_ep *ep = container_of(arg, struct com_ep, 
                                     credits_available_work);
    int new_credits;
    int used_credits = 0;
    struct buf_entry *buf;
    int cur_credits;

    new_credits = atomic_xchg(&ep->send_window_queued, 0);

    while (new_credits > 0 && !list_empty(&ep->delayed_send_list)) {
        int ret;
        new_credits--;
        used_credits++;

        buf = list_first_entry(&ep->delayed_send_list, 
                               struct buf_entry, 
                               queued_send_entry);
        BUG_ON(buf == NULL);
        list_del_init(&buf->queued_send_entry);

        ret = com_send_internal(ep, buf, buf->send_size, TRUE, buf->env_type);

        if (ret != 0) {
            rna_printk(KERN_ERR,
                       "unable to send buf [%p] on ep [%p] ret [%d]\n",
                       buf, ep, ret);
            com_disconnect(ep);
        }
    }

    /* Used credits get recycled to the send_window. */
    if (used_credits > 0) {
        BUG_ON(atomic_add_return(used_credits, &ep->send_window) > 0);
    }

    /* Unused credits can go into the send window if it's not negative,
     * otherwise new sends are about to be queued.  We don't need to
     * retry because the sender will queue the necessary work. */
    if (new_credits > 0) {
        if (!atomic_add_nonnegative(new_credits, &ep->send_window)) {
            atomic_add(new_credits, &ep->send_window_queued);
        }
    }

    /* Accounting paranoia */
    cur_credits = atomic_read(&ep->send_window);
    if (unlikely(cur_credits > ep->num_send)) {
        rna_printk(KERN_ERR, "We have more credits than send buffers (shouldn't happen).\n");
        print_ep(ep);
    }
}


int com_notify_credits_available(struct com_ep *ep)
{
    int ret = 0;
    struct work_struct *w = &ep->credits_available_work;

    /* Note: queue_work doesn't do anything if the work is already
     * queued, which is what we want here.  In that case, rna_queue_work
     * returns 0. */
    ret = rna_queue_work(ep->transport_handle->rna_delayed_send_workq, w);

    return 0;
}

/* We can prevent outgoing traffic on an EP by plugging it.
 * Internally, we use the credit system -- a plugged EP has all its 
 * credits transfered into a "plugged_credits" counter. */
void unplug_ep(struct com_ep *ep)
{
    int prev = ep->plugged;
    int credits = 0;
    ep->plugged = FALSE;
    if (unlikely(prev)) {
        /* It's okay to race -- this is idempotent. */
        rna_trace("unplugging [%p]\n", ep);

        credits = atomic_xchg(&ep->plugged_credits, 0);
        atomic_add(credits, &ep->send_window_queued);

        com_notify_credits_available(ep);
    }
}


/* Workqueue function to add a send_buf onto the queued send list. */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
void com_process_send_queued(void *arg)
#else
void com_process_send_queued(struct work_struct *arg)
#endif
{
    struct buf_entry* buf = container_of(arg, struct buf_entry, 
                                         queued_send_work);
    struct com_ep *ep = buf->ep;
    BUG_ON(NULL == ep);

    /* If this sendbuf is already in the list, something went wrong. */
    if (!list_empty(&buf->queued_send_entry)) {
        rna_printk(KERN_ERR, "bad list: %p %p %p\n", 
                   &buf->queued_send_entry,
                   buf->queued_send_entry.prev, 
                   buf->queued_send_entry.next);
    }

    list_add_tail(&buf->queued_send_entry, &ep->delayed_send_list);

    if (!ep->plugged && atomic_read(&ep->send_window_queued) > 0)
        com_notify_credits_available(ep);
}

/* 
 * Queue work to add a particular send to the delayed_send_queue.
 * Delayed sends are effectively queued twice, once on the workqueue,
 * and then the workqueue puts the send on the delayed_send_queue.
 * The reason for this redundancy is that the workqueue provides 
 * implicit synchronization and a convenient wakeup mechanism; 
 * however, the workqueue can't just re-queue on itself sends that 
 * can't complete yet, as that would cause sends to be re-ordered.
 * Therefore, we add queued sends to a separate internal list that
 * requires no locking, so long as our workqueue is single-threaded.
 */

int com_notify_send_queued(struct com_ep *ep,
                            struct buf_entry *buf,
                            enum env_type env_type)
{
    int ret = 0;
    struct work_struct *w = &buf->queued_send_work;

    /* This is safe because
     * a) the buf_entry should not already be queued at this point 
     * b) this initialization is idempotent */
    RNA_INIT_WORK(w, com_process_send_queued, w);

    buf->env_type = env_type;

    ret = rna_queue_work(ep->transport_handle->rna_delayed_send_workq, w);

    /* zero return means it was already queued */
    BUG_ON(0==ret);

    return 0;
}


/* Return the number of receive buffers we've freed which we
 * haven't acked yet.  Set unsolicited ack bit if it's needed.
 * See com_envelope.h for details. */
uint16_t
com_get_reset_unacked_recvs(struct com_ep *ep)
{
    uint16_t unacked = atomic_xchg(&ep->unacked_recvs, 0);
    return unacked;
}

/* Return unsent acks if we decide not to send a message. */
void
com_restore_unacked_recvs(struct com_ep *ep, struct rna_com_envelope* env)
{
    if (env->recv_acks != 0) {
        atomic_add(env->recv_acks, &ep->unacked_recvs);
        env->recv_acks = 0;
    }
}

/* 
 * Increment our counter of unsent credits.
 * We run this after we've re-posted a recive buffer.
 * We may send an unsolicited ack if there is a backlog.
 */
void
inc_unacked_recvs(struct com_ep *ep)
{
    atomic_inc(&ep->unacked_recvs);
    com_maybe_queue_unsolicited_ack(ep);
}

/* Read credits from an envelope. */
void
com_process_acks(struct com_ep *ep, struct rna_com_envelope* env)
{
    if (ENV_TYPE_ACK == env->msg_type) {
        /* Got unsolicited ack.  We need to send an ack back. */
        unplug_ep(ep);

        rna_printk(KERN_DEBUG, "ep [%p] got unsolicited ack\n", ep);

        /* Send an ack back if required by first_send_order logic. */
        if (!ep->sent_second_ack) {
            ep->sent_second_ack = TRUE;
            do_second_ack(ep);
        }
    }

    if (0x7fff == env->recv_acks) {
        rna_printk(KERN_ERR, "fixme: double-processing envelope\n");
        dump_stack();
    } else if (env->recv_acks > 0) {
        /* Increment send window if positive, otherwise increment
         * send_window_queued and queue necessary work. */
        if (!atomic_add_nonnegative(env->recv_acks, &ep->send_window)) {
            atomic_add(env->recv_acks, &ep->send_window_queued);
            com_notify_credits_available(ep);
        }
        env->recv_acks = 0x7fff;
    }

    /* Send an unsolicited ack if we have a backlog. */
    com_maybe_queue_unsolicited_ack(ep);
}

/* Todo: update transport modules to call this to reduce code duplication. */
int send_callback(struct com_ep *ep, struct buf_entry *buf, int status) 
{
    int ret = 0;
    SEND_CMP_CB cb = (NULL != buf->send_cmp_cb) ? buf->send_cmp_cb 
                                                : ep->com_attr.send_cmp_cb;
    if (cb) {
        ret = (cb) (ep, ep->context, (void*) buf->context, status);
    }

    return ret;
}

/* During EP disconnect we must cancel delayed sends, as they hold 
 * references on the EP. */
void
com_cancel_delayed_sends(struct com_ep *ep)
{
    struct buf_entry *buf;
    struct list_head *pos;

    list_for_each(pos, &(ep->delayed_send_list)) {
        buf = list_entry(pos, struct buf_entry, queued_send_entry);
        rna_printk(KERN_INFO, "canceling delayed send ep [%p] buf[%p]\n", ep, buf);
        /* Kernel-space has a way to indicate send failure, so we use it. */
        send_callback(ep, buf, -1);
        com_put_send_buf(ep, buf);
    }
}


/* Useful for debugging. */
void print_ep(struct com_ep *ep) {
    rna_printk(KERN_ERR,
               "ep [%p] user_type [%d] state[%s] connected[%d] cb_state[%d] "
               "refcount[%d] rem_addr["NIPQUAD_FMT":%d] recved [%d/%d] avail [%d] "
               "sent [%d/%d] avail [%d] send_window[%d] send_window_queued[%d] "
               "unacked[%d]\n",
               ep, 
               ep->user_type, 
               get_ep_state_string(com_ep_state(ep)),
               ep->connected,
               ep->callback_state,
               atomic_read(&ep->ref_count),
               NIPQUAD(ep->dst_in.sin_addr.s_addr),
               ep->dst_in.sin_port,
               atomic_read(&ep->recv_posted), ep->num_recv,
               atomic_read(&ep->recv_pool.num_avail),
               atomic_read(&ep->send_posted), ep->num_send,
               atomic_read(&ep->send_pool.num_avail),
               atomic_read(&ep->send_window),
               atomic_read(&ep->send_window_queued),
               atomic_read(&ep->unacked_recvs));
}

/* We frequently need to allocate arrays of pointers to items of
 * fixed size (such as buffer pools), so to make this easier we 
 * have generic functions to allocate, free, and iterate over 
 * pointer arrays. */

/* Simple iterator function that calls a callback function for all 
 * elements.   We pass the address of the element pointer to the 
 * callback function - this allows the callback to manipulate the 
 * pointer as well as the element.  Bail out if the callback fails. */
int rna_boxed_array_iter(void **array, 
                         int func(void **elem, unsigned long arg, int idx), 
                         int count, unsigned long arg)
{
	int ret = 0;
	int i;

	if (NULL != func) {
		for (i=0; i<count && 0==ret; i++) {
			ret = func(&array[i], arg, i);
		}
	}

	return ret;
} 

/* allocate a single element */
static int rna_boxed_elem_alloc(void **data, unsigned long size, int idx)
{
	int ret = 0;

	BUG_ON(NULL != *data);

	*data = kzalloc(size, GFP_KERNEL);

	if (NULL == *data)
		ret = -ENOMEM;

	return ret;
}

/* free a single element */
static int rna_boxed_elem_free(void **data, unsigned long size, int idx) 
{
	if (NULL != *data) {
		kfree(*data);
		*data = NULL;
	}
	return 0;
}

/* Free an array, with an optional per-item free function (typically 
 * used for memory deregistration, if necessary).  The free function
 * should not fail. */
void rna_free_boxed_array(void** array, int count,
                          int freefunc(void**, unsigned long, int),
                          unsigned long arg)
{
	if (NULL != freefunc)
		BUG_ON(0 != rna_boxed_array_iter(array, freefunc, count, arg));

	rna_boxed_array_iter(array, rna_boxed_elem_free,
	                     count, arg);
	kfree(array);
}

/* Allocate an array of pointers, and allocate memory for each of those
 * pointers individually.  Apply the initialization function to each element
 * after it has been allocated (ypically used for memory registration).
 * We bail out with freefunc if one of the initializations fail.
 * Freefunc may be called on a NULL element, but initfunc will not. 
 *  count    : size of array
 *  size     : size of individual elements
 *  arg      : parameter to pass to init and free functions - often the same as size
 *  initfunc : element initialization function (optional)
 *  freefunc : element free function in case initfunc fails (optional) */

void** rna_alloc_boxed_array(int count, int size,
                             int initfunc(void** elem, unsigned long arg, int idx), 
                             int freefunc(void** elem, unsigned long arg, int idx),
                             unsigned long arg)
{
	int ret=0;
	void** array;

	BUG_ON(in_atomic());

	/* allocate an array of pointers */
        array = kzalloc (count * sizeof(void*), GFP_KERNEL);
	if (array) {
		/* allocate memory for each of those pointers */
		ret = rna_boxed_array_iter(array, rna_boxed_elem_alloc, count, size);
	
		if (ret)
			rna_printk(KERN_ERR, "allocation failed, cleaning up\n");
	
		/* initialize each new memory region */
		if (0==ret && NULL != initfunc) {
			ret = rna_boxed_array_iter(array, initfunc, count, arg);
			if (ret)
				rna_printk(KERN_ERR, "initfunc failed, cleaning up\n");
		}

		/* free everything if anything failed */
		if (ret)
		{   
			rna_free_boxed_array(array, count, freefunc, arg);
			array = NULL;
		}
	}

	return array;
}

/* EXPORTED SYMBOLS */

/* Symbols that probably shouldn't be exported, but
 * are needed by omnicache are marked with ??? */

/* Symbols from this file */
EXPORT_SYMBOL(com_set_ep_context);
EXPORT_SYMBOL(get_ep_state_string); // ???
EXPORT_SYMBOL(com_ep_state);        // ???
EXPORT_SYMBOL(com_get_ep_dst_in);
EXPORT_SYMBOL(com_get_ep_user_type);
EXPORT_SYMBOL(com_set_ep_user_type);
EXPORT_SYMBOL(com_get_ep_context);
EXPORT_SYMBOL(com_get_ep_transport_type);
EXPORT_SYMBOL(com_connected);
EXPORT_SYMBOL(com_connect_sync);
EXPORT_SYMBOL(com_disconnect_all_eps);
EXPORT_SYMBOL(_com_inc_ref_ep);
EXPORT_SYMBOL(com_find_next_ep);
EXPORT_SYMBOL(com_ep_get_priv_data);
EXPORT_SYMBOL(com_set_priv_data);
EXPORT_SYMBOL(com_get_transport_type);
EXPORT_SYMBOL(rna_alloc_boxed_array);
EXPORT_SYMBOL(rna_free_boxed_array);
EXPORT_SYMBOL(rna_boxed_array_iter);
EXPORT_SYMBOL(com_transport_enabled);
EXPORT_SYMBOL(com_get_connection_count);

/* Symbols from the transport-specific module or rna_com_core_wrappers.c*/
EXPORT_SYMBOL(transport_init);
EXPORT_SYMBOL(com_alloc_ep);
EXPORT_SYMBOL(com_get_rkey);
EXPORT_SYMBOL(com_wait_connected);
EXPORT_SYMBOL(transport_exit);
EXPORT_SYMBOL(com_connect);
EXPORT_SYMBOL(com_disconnect);
EXPORT_SYMBOL(com_send);
EXPORT_SYMBOL(com_send_internal);
EXPORT_SYMBOL(com_get_send_buf);
EXPORT_SYMBOL(com_put_send_buf);
EXPORT_SYMBOL(com_get_rdma_buf);
EXPORT_SYMBOL(com_put_rdma_buf);
EXPORT_SYMBOL(com_set_send_buf_context);
EXPORT_SYMBOL(com_get_send_buf_mem);
EXPORT_SYMBOL(_com_release_ep);
EXPORT_SYMBOL(com_reg_single);
EXPORT_SYMBOL(com_wait_send_avail);
EXPORT_SYMBOL(com_isreg);
EXPORT_SYMBOL(com_rdma_read);
EXPORT_SYMBOL(com_wait_rdma_avail);
EXPORT_SYMBOL(com_find_ep);
EXPORT_SYMBOL(com_get_guid);
EXPORT_SYMBOL(com_rdma_write);
EXPORT_SYMBOL(com_dereg_single);
EXPORT_SYMBOL(com_rdma_sgl);
EXPORT_SYMBOL(com_reg_sgl);
EXPORT_SYMBOL(com_mapping_error);
EXPORT_SYMBOL(com_dereg_sgl);
EXPORT_SYMBOL(com_get_device_attributes);
EXPORT_SYMBOL(com_init);
EXPORT_SYMBOL(com_init_all);
EXPORT_SYMBOL(com_add_transport);
EXPORT_SYMBOL(com_del_transport);
EXPORT_SYMBOL(com_disable);
EXPORT_SYMBOL(com_exit);

/* Other misc symbols needed by the transport modules, but which
 * shouldn't be used by the application.  */
EXPORT_SYMBOL(register_transport);
EXPORT_SYMBOL(unregister_transport);
EXPORT_SYMBOL(rna_verbosity);
EXPORT_SYMBOL(rdma_read_override);
EXPORT_SYMBOL(_connection_count_dec_and_test);
EXPORT_SYMBOL(_connection_count_inc);
EXPORT_SYMBOL(rna_queue_work);
EXPORT_SYMBOL(rna_queue_delayed_work);
EXPORT_SYMBOL(rna_create_singlethread_workqueue);
EXPORT_SYMBOL(rna_create_workqueue);
EXPORT_SYMBOL(rna_destroy_workqueue);
EXPORT_SYMBOL(rna_flush_workqueue);
EXPORT_SYMBOL(com_get_unique_client_name);
EXPORT_SYMBOL(__rna_printk);
EXPORT_SYMBOL(ep_create_proc);
EXPORT_SYMBOL(ep_delete_proc);
EXPORT_SYMBOL(transport_disconnect_all_eps);
EXPORT_SYMBOL(com_get_reset_unacked_recvs);
EXPORT_SYMBOL(com_restore_unacked_recvs);
EXPORT_SYMBOL(com_process_acks);
EXPORT_SYMBOL(inc_unacked_recvs);
EXPORT_SYMBOL(print_ep);
EXPORT_SYMBOL(com_force_unsolicited_ack);
EXPORT_SYMBOL(unplug_ep);
EXPORT_SYMBOL(ep_send_order);
EXPORT_SYMBOL(com_get_send_buf_from_pool);
EXPORT_SYMBOL(com_alloc_buf_pool);
EXPORT_SYMBOL(com_free_buf_pool);
EXPORT_SYMBOL(pool_name);
EXPORT_SYMBOL(common_proto_version);
