/**
 * <rna_com_core_wrappers.c> - Dell Fluid Cache block driver
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

CODE_IDENT("$URL: https://svn.rnanetworks.com/full/tags/HERMES_2_1_0_RC1/linux-kernel/com/rna_com_core_wrappers.c $ $Id: rna_com_core_wrappers.c 25417 2013-09-26 18:12:55Z greivel $")

#include "../include/rna_common.h"
#include "rna_com_linux_kernel.h"
#include "rna_proc_ep.h"

/* Transport callback invocations are defined here. 
 * This would be a good place to put calls to rna_trace,
 * so we don't duplicate code.
 *
 * Functions which do not need to call transport callbacks
 * can go in rna_com_core.c.
 *
 * We check when we register the transport that none
 * of the functions are null, so we don't have to 
 * do the checks here. 
 *
 * Note that transport_init increments a reference count on
 * the transport, while transport_exit decrements.  If we
 * try to call any of the com callbacks after shutting
 * down the com with transport_exit, bad things are likely
 * to happen, either because the com handle points to
 * freed memory, or the transport may have unloaded,
 * leaving its method pointer pointing at garbage. */

/* Monotonically increasing id, to give each transport instance
 * a unique name.  Protected by transport_list_lock. */
int com_number = 1;

/* Create a transport instance, which we can store inside a com instance. */
struct rna_transport_handle* transport_init(struct rna_com_attrs *attrs)
{
    struct rna_transport_handle *com_handle = NULL;
    struct rna_transport *transport = NULL;
    struct rna_transport *cur;
    int retry;

    BUG_ON(NULL == attrs);

    do {
        retry = FALSE;
        rna_spin_lock(transport_list_lock);

        list_for_each_entry(cur, &transport_list, transport_list) {
            if (attrs->com_type == cur->transport_type) {
                transport = cur;
                break;
            }
        }

        if(transport && transport->module) {
            /* 1 is success, in this case. */
            if (0 == try_module_get(transport->module)) {
                /* The module is being unloaded, but hasn't been removed
                 * from the list yet. */
                rna_printk(KERN_ERR, "Could not get reference on module\n");
                retry = TRUE;
            }
        }

        rna_spin_unlock(transport_list_lock);
    } while (retry);

    if (transport) {
        com_handle = transport->transport_init_fn(attrs);
        if (com_handle != NULL) {
            com_handle->transport = transport;

            rna_spin_lock(transport_list_lock);
            com_handle->id = com_number++;
            rna_spin_unlock(transport_list_lock);

            proc_ep_init_instance(com_handle, proc_dir);
        } else {
            rna_printk(KERN_ERR, "Unable to initialize transport instance\n");
            module_put(transport->module);
        }
    }

    return com_handle;
}

int transport_disable (struct rna_transport_handle* transport_handle)
{
    return transport_handle->transport->transport_disable_fn(transport_handle);
}

int transport_exit (struct rna_transport_handle* com_handle) 
{
    struct rna_transport* transport = com_handle->transport;
    int ret;

    /* 
     * Call proc_ep_cleanup_instance before calling transport_exit_fn(), 
     * because com_handle will be freed in transport_exit_fn().
     */
    proc_ep_cleanup_instance(com_handle, proc_dir);
    ret = transport->transport_exit_fn(com_handle);
    if (0 == ret) {
        module_put(transport->module);
    }

    return ret;
}

int com_alloc_ep (struct rna_com *com_handle,
                  struct com_attr *com_attr,
                  enum com_type type,
                  void *context,
                  void *cma_id,
                  int num_send, int num_recv, int buf_size,
                  int num_rdma, int rdma_size,
                  user_type_t user_type,
                  uint8_t sync_recvq_flag,
                  int bounce_buffer_bytes,
                  int bb_segment_bytes,
                  struct com_ep** new_ep)
{
    struct rna_transport_handle *transport_handle = NULL;
    int i;
    int ret = 0;
    struct com_ep *ep;

    *new_ep = NULL;

    for (i=0; i<com_handle->avail_coms; i++) {
        if (type == com_handle->transport_types[i]) {
            transport_handle = com_handle->transports[i];
            break;
        }
    }

    if (unlikely(NULL == transport_handle)) {
        rna_printk(KERN_ERR, "No transport is available for type [%d]. "
                   "Perhaps the necessary module isn't loaded.\n", type);
        ret = -ENODEV;
    } else {
        ep = rna_kzalloc(ep, RNA_NOIO);

        if (NULL == ep) {
            rna_printk(KERN_ERR, "No memory to allocate EP\n");
            ret = -ENOMEM;
        } else {
            /* We need to set up the transport_ops early on, so we can
             * call into these wrapped functions during initialization.
             * While we're at it, we get some common setup work out of
             * the way.*/
            BUG_ON(NULL == com_handle);
            BUG_ON(NULL == com_attr);

            ep->com_handle = com_handle;
            ep->transport_handle = transport_handle;
            ep->transport_ops = transport_handle->transport;
            INIT_LIST_HEAD(&ep->delayed_send_list);
            INIT_LIST_HEAD(&ep->completed_list);
            RNA_INIT_WORK(&ep->credits_available_work,
                          com_process_credits_available,
                          &ep->credits_available_work);
            RNA_INIT_WORK(&ep->unsolicited_ack_work,
                          com_send_unsolicited_ack,
                          &ep->unsolicited_ack_work);

            ep->com_attr      = *com_attr;
            ep->context       = context;
            ep->cma_id        = cma_id;
            ep->num_recv      = num_recv;
            ep->num_send      = num_send;
            ep->buf_size      = buf_size;
            ep->user_type     = user_type;
            ep->passive       = FALSE;
            ep->num_rdma      = num_rdma;
            ep->rdma_buf_size = rdma_size;
            ep->sync_recvq    = sync_recvq_flag;
            ep->dst_addr      = (struct sockaddr *)&ep->dst_in;
            ep->src_addr      = (struct sockaddr *)&ep->src_in;

            /* Keep one spare sendbuf for unsolicited ack. */
            atomic_set(&ep->send_window, num_send-1);
            ep->plugged = TRUE;
            ret = transport_handle->transport->transport_alloc_ep_fn(ep,
                                                                     bounce_buffer_bytes,
                                                                     bb_segment_bytes);
            if (0 == ret) {
                *new_ep = ep;
            } else {
                rna_printk(KERN_ERR, 
                           "EP initialization failed (ret=[%d]).\n", ret);
                kfree(ep);
            }
        }
    }

    return ret;
}

int com_connect (struct com_ep *ep, struct sockaddr *dst_addr)
{
    return ep->transport_ops->com_connect_fn(ep, dst_addr);
}

int com_disconnect (struct com_ep *ep)
{
    return ep->transport_ops->com_disconnect_fn(ep);
}

void queue_disconnect_work(struct com_ep *ep)
{
    ep->transport_ops->queue_disconnect_work_fn(ep);
}

int com_get_send_buf (struct com_ep *ep, struct buf_entry **buf, 
                      int poll_ep)
{
    return ep->transport_ops->com_get_send_buf_fn(ep, buf, poll_ep);
}

int com_put_send_buf (struct com_ep *ep, struct buf_entry *buf)
{
    return ep->transport_ops->com_put_send_buf_fn(ep, buf);
}

int com_wait_send_avail (struct  com_ep *ep)
{
    return ep->transport_ops->com_wait_send_avail_fn(ep);
}

/* This bypasses credits.  It should only be used internal to the com. */
int com_send_internal (struct com_ep *ep,
                       struct buf_entry *buf,
                       int size,
                       int nocredit,
                       enum env_type env_type)
{
    if (nocredit || (0 <= atomic_dec_return(&ep->send_window))) {
        return ep->transport_ops->com_send_fn(ep, buf, size, env_type);
    } else {
        buf->send_size = size;
        return com_notify_send_queued(ep, buf, env_type);
    }
}

int com_send (struct com_ep *ep, struct buf_entry *buf, int size)
{
    return com_send_internal(ep, buf, size, FALSE, ENV_TYPE_PROTO);
}

int com_get_rdma_buf(struct com_ep *ep, struct buf_entry **buf,
                            int *length)
{
    return ep->transport_ops->com_get_rdma_buf_fn(ep, buf, length);
}

void com_put_rdma_buf(struct com_ep *ep, struct buf_entry *buf)
{
    ep->transport_ops->com_put_rdma_buf_fn(ep, buf);
}

rna_rkey_t com_get_rkey (struct com_ep *ep, const struct rdma_buf *buf)
{
    return ep->transport_ops->com_get_rkey_fn(ep, buf);
}

int com_rdma_read (struct com_ep *ep, struct buf_entry *rdma_buf,
                   rna_addr_t remote_addr,
                   void *buf, rna_rkey_t remote_rkey,
                   int size, void *context, char signaled,
                   uint32_t flags)
{
    return ep->transport_ops->com_rdma_read_fn(ep, rdma_buf, remote_addr,
                                               buf, remote_rkey, size,
                                               context, signaled, flags);
}

int com_wait_rdma_avail (struct com_ep *ep)
{
    return ep->transport_ops->com_wait_rdma_avail_fn(ep);
}

int com_rdma_write (struct com_ep *ep, struct buf_entry *rdma_buf,
                    rna_addr_t remote_addr,
                    void *buf,
                    rna_rkey_t remote_rkey,
                    int size, void *context, char signaled, uint32_t flags)
{
    return ep->transport_ops->com_rdma_write_fn(ep, rdma_buf, remote_addr,
                                                buf, remote_rkey, size,
                                                context, signaled, flags);
}

int com_reg_single (struct com_ep *ep, struct rdma_buf *rdma_buf,
                    enum dma_data_direction direction)
{
    return ep->transport_ops->com_reg_single_fn(ep, rdma_buf, direction);
}

void com_dereg_single (struct com_ep *ep, struct rdma_buf *rdma_buf) 
{
    if (NULL == ep) {
        rna_printk(KERN_ERR, "com_dereg_single called with NULL ep\n!");
    } else {
        ep->transport_ops->com_dereg_single_fn(ep, rdma_buf);
    }
}

int com_isreg (struct com_ep *ep, struct rdma_buf *rdma_buf) 
{
    return ep->transport_ops->com_isreg_fn(ep, rdma_buf);
}

int com_wait_connected (struct com_ep *ep, int timeout)
{
    return ep->transport_ops->com_wait_connected_fn(ep, timeout);
}

void _com_release_ep (struct com_ep *ep, const char *fn)
{
    ep->transport_ops->_com_release_ep_fn (ep, fn);
}

/* When we have multiple active transports, search order is 
 * determined by the order in which transports were added. */
int com_find_ep (struct rna_com *com_handle,
                 struct sockaddr *dst_addr,
                 struct com_ep **ep, uint8_t sync_flag)
{
    int i;
    int ret = -1;
    struct rna_transport_handle *transport_handle;

    for (i=0; i<com_handle->avail_coms; i++) {
        transport_handle = com_handle->transports[i];
        ret = transport_handle->transport->
                  transport_find_ep_fn(transport_handle, dst_addr,
                                       ep, sync_flag);
        if (0 == ret)
            break;
    }
    
    return ret;
}

uint64_t com_get_guid (struct com_ep* ep) 
{            
    return ep->transport_ops->com_get_guid_fn(ep);
}

int com_rdma_sgl( struct com_ep *ep, void *ctxt, struct buf_entry *buf,
				  rna_addr_t raddr, struct scatterlist *sgl,int num_sgl,
                  rna_rkey_t rkey, int write, uint32_t flags )
{
    return ep->transport_ops->com_rdma_sgl_fn(ep, ctxt, buf, raddr, sgl,
                                              num_sgl, rkey, write, flags);
}

void com_dereg_sgl(struct com_ep *ep, struct scatterlist *sgl, 
                   int nents, enum dma_data_direction dir)
{
    ep->transport_ops->com_dereg_sgl_fn(ep, sgl, nents, dir);
}

int com_reg_sgl(struct com_ep *ep, struct scatterlist *sgl, 
                int nents, enum dma_data_direction dir)
{
    return ep->transport_ops->com_reg_sgl_fn(ep, sgl, nents, dir);
}

int com_mapping_error(struct com_ep *ep, struct scatterlist *sgl)
{
    return ep->transport_ops->com_mapping_error_fn(ep, sgl);
}

int com_get_device_attributes(struct rna_com *com_handle,
                              enum com_type type, 
                              struct rna_dev_attr *attr)
{
    int i;
    int ret = -EINVAL;
    struct rna_transport_handle *transport_handle;

    for (i=0; i<com_handle->avail_coms; i++) {
        if (type == com_handle->transport_types[i]) {
            transport_handle = com_handle->transports[i];
            ret = transport_handle->transport->
                      transport_get_device_attributes_fn(transport_handle,
                                                         type, attr);
            break;
        }
    }

    return ret;
}

/* listen isn't supported yet in kernel space */
int com_listen(struct rna_com *com_handle, unsigned short int port)
{
    return -EINVAL;
}

enum rna_first_send_order ep_send_order(struct com_ep *ep)
{
    return ep->transport_ops->transport_ep_send_order_fn(ep);
}

/* Callbacks to allocate or free a single buf_entry, used by generic
 * com_alloc_buf_pool and com_free_buf_pool functions. */
int com_alloc_buf_pool_elem(void **elem, unsigned long arg, int idx)
{
    struct buf_pool_ctx *ctx = (typeof(ctx)) arg;
    struct com_ep *ep = ctx->ep;
    return ep->transport_ops->transport_alloc_buf_pool_elem_fn(elem, arg, idx);
}

int com_free_buf_pool_elem(void **elem, unsigned long arg, int idx)
{
    struct buf_pool_ctx *ctx = (typeof(ctx)) arg;
    struct com_ep *ep = ctx->ep;
    return ep->transport_ops->transport_free_buf_pool_elem_fn(elem, arg, idx);
}

char *com_print_bb_stats(struct com_ep *ep, char *p)
{
    return ep->transport_ops->transport_ep_proc_stats_fn(ep, p);
}
