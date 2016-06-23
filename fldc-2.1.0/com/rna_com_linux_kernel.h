/**
 * <rna_com_linux_kernel.h> - Dell Fluid Cache block driver
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
 * Platform specific header file that defines functions, etc. specific
 * to the Linux implementation of fluid cache.
 *
 * NOTE: This file should *never* be included on a platform other than
 * Linux.
 */
#pragma once

#include "platform.h"

#ident "$URL$ $Id$"

#include "../include/rna_common.h"
#include "rna_byteswap.h"
#include "../include/config.h"
#include "rna_locks.h"
#include "rna_common_logging.h"

#include "rna_types.h"
#include "rna_com_ib.h"
#include "rna_com_tcp.h"
#include "rna_com_status.h"
#include "rna_com_kernel.h"

#ifdef RDMA_READ_OVERRIDE
extern int rdma_read_override;
#endif

#define CONNECT_TIMEOUT	2000

#define RNA_COM_RETRY_COUNT 7     // default to infinite retries
#define RNA_COM_RNR_RETRY_COUNT 7 // default to infinite retries

/* Number of send buffers reserved for sending unsolicited ack. */
#define CREDIT_BUFS 4

/* In theory, the filesystem client can get away with GFP_NOFS,
 * but the block driver requires the stricter GFP_NOIO.
 * This is to prevent the allocation routines from recursing. */
#define RNA_NOIO GFP_NOIO

#ifndef NIPQUAD
#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
#endif
#ifndef NIPQUAD_FMT
    #define NIPQUAD_FMT "%u.%u.%u.%u"
#endif

extern struct proc_dir_entry *proc_dir;

struct req_priv_data; // defined in priv_data.h

extern rna_spinlock_t transport_list_lock;
extern struct list_head transport_list;

/* The following send order logic is duplicated from user-space. */

/*
 * Enum for specifying first-send logic for one end of an EP.  We use
 * unsolicited acks as a harmless protocol message.
 * NOACK_NOWAIT: don't do anything special, rely on application logic.
 * NOACK_WAIT: plug the EP until unsolicited ack arrives.
 * ACK_NOWAIT: send unsolicited ack, don't plug the EP
 * ACK_WAIT: plug the EP, send an ACK, wait for return ack.
 * DELAYEDACK_WAIT: wait for ACK before unplugging and sending ack.
 */

enum rna_first_send_order {
    SO_NOACK_NOWAIT = 0,
    SO_NOACK_WAIT,
    SO_ACK_NOWAIT,
    SO_ACK_WAIT,
    SO_DELAYEDACK_WAIT
};

/*
 * On Mellanox IB, we want to control the first passive-side
 * send to prevent stuck EPs (see MVP-5191 and MVP-4846 for example).
 * On iWARP, the active side must send first.
 *
 * These settings must match those in linux_kernel/com/rna_com_kernel.h.
 * We don't check at connect time that both ends of a connection
 * have compatible expectations about who sends what when.
 */

/* For IB, passive sends first. */
#define DEFAULT_ACTIVE_IB_SEND_ORDER  SO_NOACK_WAIT
#define DEFAULT_PASSIVE_IB_SEND_ORDER SO_ACK_NOWAIT

/* For iWarp, active sends first. */
#define DEFAULT_ACTIVE_IWARP_SEND_ORDER SO_ACK_NOWAIT
#define DEFAULT_PASSIVE_IWARP_SEND_ORDER SO_NOACK_WAIT

/* We don't need to do anything special for TCP */
#define DEFAULT_ACTIVE_TCP_SEND_ORDER SO_NOACK_NOWAIT
#define DEFAULT_PASSIVE_TCP_SEND_ORDER SO_NOACK_NOWAIT

/* We pass in a pointer to a wr_ctx as the wr_id field of
 * a work request.  Usually, this will point to a buf_entry,
 * but it might also be a context pointer that we want to just
 * pass back to the application.
 *
 * Possible values for the wr_ctx type field.
 * We aren't defining this as an enumeration, so that we can
 * leave open the possibility that the user defines more than
 * one kind of app pointer.  IS_APP_POINTER is just one possible
 * value, so we should test for inequality with IS_BUF_ENTRY,
 * rather than equality with IS_APP_POINTER. */

#define IS_BUF_ENTRY  -1
#define IS_APP_POINTER 1

struct wr_ctx {
    int type;
    void * data;
};

#define COM_NUM_WC 50

/**
 * RDMA State transitions:
 *   Note: These transitions occur in this order and this order only:
 *   EP_INIT->EP_CONNECT_PENDING->EP_CONNECTED->EP_DISCONNECT_PENDING->EP_DISCONNECTED->EP_FREE
 *
 */

enum ep_state {
    EP_INIT,
    EP_CONNECT_PENDING,
    EP_SEND_PRIV_DATA,
    EP_PRIV_DATA_SENT,
    EP_CONNECTED,
    EP_DISCONNECT_PENDING,
    EP_DISCONNECTED,
    EP_FREE,
    EP_STATE_ILLEGAL    /* Must be last */
};

struct buf_pool {
	struct buf_entry   **entries;
	struct buf_entry   *in_flight_list; /* List of RDMA entries that have been posted. Used in sockets based transport */
	int                count;
	atomic_t           num_avail;
	unsigned int       next_avail;
	int                buf_size;
	dma_addr_t         mem_dma;
};

/*
 * Used by com_alloc_buf_pool routines to embed multiple values
 * into the context argument passed into the boxed array allocation
 * routines.
 */
struct buf_pool_ctx
{
        struct com_ep *ep;
        struct buf_pool *pool;
        size_t buf_size;
};

enum {
    KERNEL_TRANSPORT_STATE_OK = 0,
    KERNEL_TRANSPORT_STATE_DISCONNECTING,
    KERNEL_TRANSPORT_STATE_SHUTTING_DOWN,
};

/* Context state for a particular transport instance.
 * Formerly known as "struct rna_com". */
struct rna_transport_handle {
    /* CM */
    char                     initialized;
    struct rdma_cm_id       *listen_cma_id;
    struct workqueue_struct *workqueue; /* not initialized, never used */
    struct mutex             ep_lst_lock;
    rna_spinlock_t           ep_ref_lock;
    rna_spinlock_t           ep_dsc_lock;
    struct list_head         ep_lst_head;
    atomic_t                 connection_count;
    wait_queue_head_t        all_disconnected_wait;
    /* Used to signal the clean thread that there is work to do */
    struct work_struct       clean_work; 
    /* To protect against connecting eps while tearing down the transport */
    struct mutex             transport_state_lock; 
    atomic_t                 transport_state;
    struct workqueue_struct *rna_workq;
    struct workqueue_struct *rna_conn_workq;
    struct workqueue_struct *rna_clean_workq;
    struct workqueue_struct *rna_delayed_send_workq;
    //struct rna_ib_client     rna_ib_client;
    struct rna_transport    *transport;
    struct proc_dir_entry   *proc_connections;
    int                      id; /* used to generate a unique name for the proc dir */
	enum com_comp_mode       comp_mode;

    /* ethernet-specific fields */
    rna_spinlock_t           work_envelope_lock;  // initialized in transport_init, used in rna_new_work and rna_free_work
    atomic_t                 work_envelopes_in_use;
    struct list_head         work_lst_head;// this is initialized(TCP), but never used
    struct mutex             work_lst_lock;// this is inttialized(TCP), but never used
    wait_queue_head_t        work_wait;    // this is initialized(TCP), but never used

   /**
    * We keep a pool of work "envelopes" - just a holder for work structs
    * with an in_use flag - so we can queue more than one event for a
    * socket.  (It doesn't work to use the work struct in the ep, since
    * you can get messages faster than they are processed, and you can't
    * queue the same work struct twice.)
    */
    struct com_work_envelope rna_com_work_envelopes[MAX_WORK_ENVELOPES]; // never used

    /* RDMA-only values */
    int           retry_count;
    int           rnr_retry_count;
};

typedef enum ep_callback_state_e {
	CB_INIT         = 0,
	CB_CONNECTED    = 1,
	CB_DISCONNECTED = 2,
	CB_FAILED       = -1,
} ep_callback_state_t;

/* Communication End Point */
struct com_ep {
	/* These three should never be NULL outside of com_alloc_ep */
	struct rna_com *com_handle;
    struct rna_transport_handle *transport_handle;
	struct rna_transport *transport_ops;

	int                 id;
    rwlock_t            ep_state_lock;             /* used by TCP */
    atomic_t            ep_state_ref;              /* used by IB */
    atomic_t            ep_state_disconnect_latch; /* used by IB */

	/* distinguish different users
	 * e.g. client, cache_mgr, meta_data etc
	 * the types are defined in protocol.h
	 */
	user_type_t user_type;
	int proto_version;

	atomic_t            ep_state;
	atomic_t            ref_count;
	char                passive;
	struct rdma_cm_id   *cma_id;

	/* addressing */
	struct sockaddr_in  dst_in;
	struct sockaddr     *dst_addr;
	struct sockaddr_in  src_in;
	struct sockaddr     *src_addr;
	int                 connected;
	ep_callback_state_t callback_state;
                            /*
                             *  CB_INIT: no callbacks have been invoked for
                             *      this ep
                             *  CB_CONNECTED: a connect_cb, if defined, has
                             *      been invoked for this ep
                             *  CB_DISCONNECTED: a disconnect_cb, if defined,
                             *      has been invoked for this ep
                             * CB_FAILED: a com_connect_sync() call for this
                             *      ep has timed out; no callbacks should be
                             *      invoked
                             */

	/* application callbacks */
	struct com_attr     com_attr;
	void                *context;

	/* IB handles */
	struct ib_pd        *pd;
	struct ib_mr        *mr;
	struct ib_ah        *ah;
	uint32_t            remote_qpn;
	uint32_t            remote_qkey;

	struct cq_ctx       send_cq;
	struct cq_ctx       recv_cq;
    struct workqueue_struct *ep_comp_wq;

	/* Ethernet-specific data */
	struct com_socket   com_sock;
	struct com_socket   rdma_sock;
	struct mutex        recv_mutex;
	struct mutex        send_mutex;
	atomic_t            rdma_is_writeable;
	atomic_t            com_is_writeable;
	atomic_t            callback_queued; /* items on recv_wq or comp_wq */
	spinlock_t          recv_serialization_lock; /* to serialize com_socket_recv_softirq */

	/* workqueues, work structures, etc */
	wait_queue_head_t   conn_wait; /* wait queue for connection */
	wait_queue_head_t   com_wait; /* wait queue for send buffer */
	struct list_head    work_list;
	struct work_struct  work;
	struct work_struct  rdma_work;

	/* send/recv */
	int                 num_recv;
	int                 num_send;
	int                 buf_size;
	atomic_t            send_posted;
	atomic_t            recv_posted;
	atomic_t            unacked_recvs;
	atomic_t            send_window;
	atomic_t            send_window_queued;
    rna_service_wait_obj    buf_pool_wait_obj;
    /* Workq for posting data write operations */
    struct workqueue_struct *send_wq;

	/* send/recv pools */
	struct buf_pool     send_pool;
	struct buf_pool     recv_pool;

	/* rdma */

	int                 num_rdma;
	int                 rdma_buf_size;
	void                *rdma_mem;
	dma_addr_t          rdma_mem_dma;
	struct buf_entry    **rdma_pool;
	wait_queue_head_t   rdma_wait;

	struct buf_entry    *last_zcopy_buf;
	/* TODO: only temporary for testing poll */
	volatile int        rdma_read_completed;

	rna_spinlock_t      rdma_lock;
	volatile int        next_rdma;
	atomic_t            rdma_avail;
	atomic_t            rdma_posted;
	uint8_t             cpu_be;
	uint8_t             sync_recvq; /* Set if we should syncronize the recvq. (Used for pub/sub messages) */
	atomic_t            in_progress;
	struct list_head    entries;
	struct list_head    free_entry;
	struct device_context *dev;

	struct proc_dir_entry * procfile;

	atomic_t            trans_id; /* Packet number used for debugging. MVP-3754 */
	uint64_t            remote_trans_id; /* Remote packet number for debugging. MVP-3754 */
	int                 max_sge; /* Max number of scatter gather elements this ep supports */
	struct kvec         iov[2 + RNA_COM_MAX_SGL]; // IO vector, protected by send mutex

	/* credits */
	struct work_struct  credits_available_work;
	struct work_struct  unsolicited_ack_work;
	struct list_head    delayed_send_list; /* Delayed sends waiting for credits. */
	spinlock_t          completed_list_lock;
	struct list_head    completed_list; /* List of completed requests that still need callbacks */
	atomic_t            ack_in_progress; /* Do we have an outstanding unsolicited ack? */
	atomic_t            need_ack_ack;  /* We got an unsolicited ack, which we must ack. */
	int                 plugged;
	atomic_t            plugged_credits; /* Credits we can't use until we unplug the EP. */
	int                 sent_second_ack;
	struct buf_pool     credits_pool; /* Send buffer pool for unsolicited ack. */

    /* if we are using bounce buffers, this pointer will be non-NULL
     * The structure may be transport specific.
     */
    void                *bounce_buf_ctxt;

    /* mmu vars go here */
    uint64_t            remote_pid; /* PID of remote connection. Relevant only when colocated */
    struct mm_struct    *remote_mm; /* Memory Map Struct of remote PID */

    atomic_t            min_rdma_avail;
    atomic_t            min_send_avail;
    atomic64_t          ep_num_sends;
    atomic64_t          ep_num_recvs;
    atomic_t            ep_recv_queued;
};

static __inline__ void bswap_in_addr(struct in_addr *data)
{
#if CPU_BE
		//data->s_addr = bswap_32(data->s_addr);
#endif
}


static __inline__ void bswap_req_priv_data(struct req_priv_data *data)
{
#if CPU_BE
        data->version = bswap_32(data->version);
		bswap_in_addr(&data->dst_addr);
		bswap_in_addr(&data->src_addr);
        data->user_type = bswap_32(data->user_type);
        data->num_send = bswap_32(data->num_send);
        data->num_recv = bswap_32(data->num_recv);
        data->buf_size = bswap_32(data->buf_size);
#endif
}

static inline void set_disconnecting(struct rna_transport_handle *transport_handle)
{
    mutex_lock(&transport_handle->transport_state_lock);
    atomic_set(&transport_handle->transport_state, 
               KERNEL_TRANSPORT_STATE_DISCONNECTING);
    mutex_unlock(&transport_handle->transport_state_lock);
}

static inline void set_shutting_down(struct rna_transport_handle *transport_handle)
{
    atomic_set(&transport_handle->transport_state, 
               KERNEL_TRANSPORT_STATE_SHUTTING_DOWN);
}

static inline int is_disconnecting(struct rna_transport_handle *transport_handle)
{
    return (KERNEL_TRANSPORT_STATE_DISCONNECTING ==
            atomic_read(&transport_handle->transport_state));
}

static inline int is_shutting_down(struct rna_transport_handle *transport_handle)
{
    return (KERNEL_TRANSPORT_STATE_SHUTTING_DOWN == 
            atomic_read(&transport_handle->transport_state));
}

static inline int is_transport_handle_ok(struct rna_transport_handle *transport_handle)
{
    return (KERNEL_TRANSPORT_STATE_OK == atomic_read(&transport_handle->transport_state));
}

/* end-point related functions */
void com_set_ep_timewait(struct com_ep *ep);
int com_find_ep(struct rna_com *com_handle, struct sockaddr *dst_addr, struct com_ep **ep,                 uint8_t sync_flag);
int com_listen(struct rna_com *com_handle, unsigned short int port);
const char *get_ep_state_string(enum ep_state);
int com_ep_state(struct com_ep *ep);
void com_set_ep_user_type(struct com_ep *ep, user_type_t user_type);
char com_get_ep_user_type(struct com_ep *ep);
struct sockaddr_in com_get_ep_dst_in(struct com_ep *ep);
void unplug_ep(struct com_ep *ep);

/*
 * internal buffer pool initialization/teardown functions - can be made public
 * if needed.
 */
int com_alloc_buf_pool(struct com_ep *ep, struct buf_pool *buf_pool, int count, int buf_size);
int com_free_buf_pool(struct com_ep *ep, struct buf_pool *buf_pool);
int com_alloc_rdma_pool(struct com_ep *ep, int num_rdma, int buf_size);
int com_free_rdma_pool(struct com_ep *ep);
int com_alloc_rdma_buffer(int size, struct rdma_buf *rdma_buf);
int com_free_rdma_buffer(struct rdma_buf *rdma_buf);
int com_get_send_buf_from_pool(struct com_ep *ep,
                               struct buf_entry **buf,
                               struct buf_pool *bp);
int rna_boxed_array_iter(void **array,
                         int func(void **elem, unsigned long arg, int idx),
                         int count, unsigned long arg);
void rna_free_boxed_array(void** array, int count,
                          int freefunc(void** elem, unsigned long arg, int idx),
                          unsigned long arg);
void** rna_alloc_boxed_array(int count, int size,
                             int initfunc(void** elem, unsigned long arg, int idx),
                             int freefunc(void** elem, unsigned long arg, int idx),
                             unsigned long arg);
int com_alloc_buf_pool_elem(void **elem, unsigned long arg, int idx);
int com_free_buf_pool_elem(void **elem, unsigned long arg, int idx);
char *com_print_bb_stats(struct com_ep *ep, char *p);
const char* pool_name(struct com_ep *ep, struct buf_pool *bp);


int com_poll_send_completion(struct com_ep *ep);
int com_poll_recv_completion(struct com_ep *ep);
int transport_disconnect_all_eps(struct rna_transport_handle *g_com);

int com_wait_rdma_completion(struct buf_entry *rdma_buf);
int    _connection_count_dec_and_test ( struct rna_transport_handle *com_handle, const char *fn );
void   _connection_count_inc ( struct rna_transport_handle *com_handle, const char *fn );
struct com_ep* com_find_next_ep ( struct rna_com *com_handle, struct com_ep *prev, 
                                  user_type_t user_type );
/* Helper function for debugging */
int com_get_unique_client_name ( void *ctx, char *uniquename, int rlen );
enum com_type com_get_transport_type(struct rna_transport_handle * com_handle);
int com_notify_send_queued(struct com_ep *ep,
                           struct buf_entry *buf,
                           enum env_type env_type);
int com_notify_credits_available(struct com_ep *ep);
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
void com_process_credits_available(void *arg);
void com_send_unsolicited_ack(void *arg);
#else
void com_process_credits_available(struct work_struct *arg);
void com_send_unsolicited_ack(struct work_struct *arg);
#endif
int com_unsolicited_ack(struct com_ep *ep);
int com_force_unsolicited_ack(struct com_ep *ep);
void inc_unacked_recvs(struct com_ep *ep);

int common_proto_version(struct rna_com *com_handle,
                         struct req_priv_data *priv_data,
                         int *best_match);
int com_reg_usr_buf(struct com_ep *ep, void *user_buf, size_t size, struct buf_entry **buf_entry);
int com_dereg_usr_buf(struct com_ep *ep, struct buf_entry *rdma_buf);
int com_get_device_attributes(struct rna_com *com_handle,
                              enum com_type type, struct rna_dev_attr *attr);

int    _com_inc_ref_ep ( struct com_ep *ep, const char *fn );
void   _com_release_ep ( struct com_ep *ep, const char *fn );

/* Thes are used by transport modules to register themselves
 * with the core com module.  get_transport_type is implemented
 * by the particular transport; it is not called by the core
 * com code.*/
int register_transport(struct rna_transport* transport);
int unregister_transport(struct rna_transport* transport);

enum com_type get_transport_type(void);
int com_add_transport(struct rna_com *com, struct rna_com_attrs *attrs);
int com_del_transport(struct rna_com *com, enum com_type);
int com_get_connection_count(struct rna_com *com);

struct rna_transport_handle* transport_init(struct rna_com_attrs *attrs);
int transport_disable(struct rna_transport_handle *g_com);
int transport_exit(struct rna_transport_handle *g_com);
int transport_alloc_ep(struct com_ep *ep, int bounce_buffer_bytes,
                       int bb_segment_bytes);
void queue_disconnect_work(struct com_ep *ep);

int com_wait_send_avail(struct  com_ep *ep);
int com_wait_connected(struct com_ep *ep, int timeout);
int transport_find_ep(struct rna_transport_handle *com_handle,
                      struct sockaddr *dst_addr, struct com_ep **ep,
                      uint8_t sync_flag);
uint64_t com_get_guid (struct com_ep *ep);
int transport_get_device_attributes(struct rna_transport_handle *com_handle,
                                    enum com_type type, struct rna_dev_attr *attr);
int transport_listen(struct rna_transport_handle *com_handle, unsigned short int port);
enum rna_first_send_order transport_ep_send_order(struct com_ep *ep);
int transport_alloc_buf_pool_elem(void **elem, unsigned long arg, int idx);
int transport_free_buf_pool_elem(void **elem, unsigned long arg, int idx);
char *transport_ep_proc_stats(struct com_ep *ep, char *p);

/*
 * An rna_transport is a structure used by a transport module to
 * register itself with the com layer.  There should be at most one
 * transport per interface, though there may be many rna_com com
 * instances associated with a transport.
 *
 * Note: Do not confuse transport methods such as com_connect_fn
 *       with ep application callbacks such as connect_cb.
 *       Also, do not confuse an rna_transport with
 *       rna_transport_handle, which is a particular instance of
 *       a transport, as used by an application.
 */

struct rna_transport {
    struct list_head transport_list;
    enum com_type transport_type;
    struct module* module; /* protected by transport_list_lock */

    typeof(transport_init) (*transport_init_fn);
    typeof(transport_disable) (*transport_disable_fn);
    typeof(transport_exit) (*transport_exit_fn);
    typeof(transport_alloc_ep) (*transport_alloc_ep_fn);
    typeof(com_connect) (*com_connect_fn);
    typeof(com_disconnect) (*com_disconnect_fn);
    typeof(queue_disconnect_work) (*queue_disconnect_work_fn);
    typeof(com_get_send_buf) (*com_get_send_buf_fn);
    typeof(com_put_send_buf) (*com_put_send_buf_fn);
    typeof(com_wait_send_avail)(*com_wait_send_avail_fn);
    typeof(_com_send) (*com_send_fn);
    typeof(com_get_rdma_buf) (*com_get_rdma_buf_fn);
    typeof(com_put_rdma_buf) (*com_put_rdma_buf_fn);
    typeof(com_get_rkey) (*com_get_rkey_fn);
    typeof(com_rdma_read) (*com_rdma_read_fn);
    typeof(com_wait_rdma_avail) (*com_wait_rdma_avail_fn);
    typeof(com_rdma_write) (*com_rdma_write_fn);
    typeof(com_reg_single) (*com_reg_single_fn);
    typeof(com_dereg_single) (*com_dereg_single_fn);
    typeof(com_isreg) (*com_isreg_fn);
    typeof(com_wait_connected) (*com_wait_connected_fn);
    typeof(_com_release_ep) (*_com_release_ep_fn);
    typeof(transport_find_ep) (*transport_find_ep_fn);
    typeof(com_get_guid) (*com_get_guid_fn);
    typeof(com_rdma_sgl) (*com_rdma_sgl_fn);
    typeof(com_reg_sgl)  (*com_reg_sgl_fn);
    typeof(com_dereg_sgl) (*com_dereg_sgl_fn);
    typeof(com_mapping_error)  (*com_mapping_error_fn);
    typeof(transport_get_device_attributes) (*transport_get_device_attributes_fn);
    typeof(transport_listen) (*transport_listen_fn);
    typeof(transport_ep_send_order) (*transport_ep_send_order_fn);
    typeof(transport_alloc_buf_pool_elem) (*transport_alloc_buf_pool_elem_fn);
    typeof(transport_free_buf_pool_elem) (*transport_free_buf_pool_elem_fn);
    typeof(transport_ep_proc_stats) (*transport_ep_proc_stats_fn);
};

/* Pass caller through so we can debug more easily */
#define connection_count_dec_and_test(com_handle) _connection_count_dec_and_test(com_handle, __FUNCTION__)
#define connection_count_inc(com_handle) _connection_count_inc(com_handle, __FUNCTION__)

/* Given an rna_first_send_order enum, decide if we need to
 * unplug immediately, send an ack immediately, or send an
 * ack after we receive one.  We always unplug the interface
 * when we get an ack, so we don't need to test for that case. */
#define _do_immediate_unplug(so) (SO_NOACK_NOWAIT == so || SO_ACK_NOWAIT == so)
#define _do_first_ack(so)        (SO_ACK_WAIT == so || SO_ACK_NOWAIT == so)
#define _do_second_ack(so)       (SO_DELAYEDACK_WAIT == so)

/* Determine the send order for a particular EP. */
enum rna_first_send_order ep_send_order(struct com_ep *ep);

/* Use ep_to_so to lift the above checks to operate on eps
 * rather than send_orders, and do the action if needed. */
#define do_immediate_unplug(ep) \
    if (_do_immediate_unplug(ep_send_order(ep))) unplug_ep(ep);

#define do_first_ack(ep) \
    if (_do_first_ack(ep_send_order(ep))) com_force_unsolicited_ack(ep);

#define do_second_ack(ep) \
    if (_do_second_ack(ep_send_order(ep))) {com_force_unsolicited_ack(ep); unplug_ep(ep);}

#define ep_to_state_string(ep) get_ep_state_string (atomic_read(&ep->ep_state))

/* Pass caller through so we can debug more easily */
#define com_inc_ref_ep(ep) _com_inc_ref_ep(ep, __FUNCTION__)
#define com_release_ep(ep) _com_release_ep(ep, __FUNCTION__)

static inline void *com_get_ep_context(struct com_ep *ep)
{
    RNA_BUG_ON(NULL == ep);
    return ep->context;
}

static inline enum com_type com_get_ep_transport_type(struct com_ep *ep)
{
    RNA_BUG_ON(NULL == ep);
    return ep->transport_ops->transport_type;
}

static inline void com_set_send_buf_context(struct buf_entry *buf_entry, void *context)
{
    RNA_BUG_ON(NULL == buf_entry);
    buf_entry->context = context;
}

static inline void *com_get_send_buf_mem(struct buf_entry *buf_entry)
{
    RNA_BUG_ON(NULL == buf_entry);
    return buf_entry->mem;
}

static inline void
com_mark_rdma_buf_inflight(struct com_ep *ep, struct buf_entry *buf)
{
    int use_state;

    use_state = atomic_cmpxchg(&buf->buf_use_state, BUF_USE_ALLOCATED,
                               BUF_USE_INFLIGHT);
    switch (use_state) {
    case BUF_USE_ALLOCATED:     // expected case; business as usual
        break;

    case BUF_USE_COMPLETING:    // completion beat us out, just do the put
        com_put_rdma_buf(ep, buf);
        break;

    case BUF_USE_REPOSTED:      // repost got to it!
        com_finish_rdma_op(ep, buf, -1);
        break;

    default:
        BUG();
    }
}


static inline void
com_mark_rdma_buf_done(struct com_ep *ep, struct buf_entry *buf, int status)
{
    int use_state;

    use_state = atomic_cmpxchg(&buf->buf_use_state, BUF_USE_ALLOCATED,
                               BUF_USE_COMPLETING);
    switch (use_state) {
    case BUF_USE_ALLOCATED:
    case BUF_USE_REPOSTED:
        com_finish_rdma_op(ep, buf, status);
        break;

    case BUF_USE_COMPLETING:
        rna_printk(KERN_WARNING, "ep [%p] buf [%p] optype [%d] context [%p] "
                   "ctx [%p] status [%d] unexpected buf use_state [%d]\n",
                   ep, buf, buf->op_type, ep->context, buf->context,
                   status, atomic_read(&buf->buf_use_state));
        com_put_rdma_buf(ep, buf);
        break;

    default:
        BUG();
    }
}

static inline void
com_mark_rdma_buf_free(struct buf_entry *buf)
{
    int use_state;
	
    do {
        use_state = atomic_read(&buf->buf_use_state);
        if (unlikely(BUF_USE_FREE == use_state)) {
            rna_printk(KERN_ERR, "rdma buf=%p already completed!\n", buf);
            break;
        }
    } while (atomic_cmpxchg(&buf->buf_use_state, use_state, BUF_USE_FREE)
             != use_state);
}
