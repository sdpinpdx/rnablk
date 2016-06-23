/**
 * <rna_com_kernel.h> - Dell Fluid Cache block driver
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
 * Platform independant header file that defines the communication protocol
 * for kernel components of fluid cache.
 */
#pragma once

#include "platform.h"

CODE_IDENT("$URL: https://svn.rnanetworks.com/full/tags/HERMES_2_1_0_RC1/linux-kernel/com/rna_com_kernel.h $ $Id: rna_com_kernel.h 38017 2014-11-04 02:10:21Z dolien $")

#if defined(LINUX_KERNEL)
#include "rna_com_linux_impl.h"
#endif

#define VERSION 0003

#define MAX_TRANSPORTS 3
#define RNA_COM_MAX_SGL 32

/* Bitmask values for "transports" module param for fldc cache */
typedef int transport_type_bitmap_t;
#define IB_TRANSPORT 1
#define TCP_TRANSPORT 2

/*
 * Forward declarations, defined in rna_com_linux_impl.h for
 * the Linux implementation. Windows will need to define it's
 * own.
 */
struct rna_com;
struct com_ep;
struct rna_com_envelope;
struct rna_transport_handle;
struct com_rdma_msg;
struct rdma_buf;
struct buf_pool;
struct rna_transport;
struct wr_ctx;

/* Communication Types */
enum com_type {
	MULTICAST=0,
	UD,
	RC,
	IP_TCP,
	IP_RDMA,
	COM_TYPE_UNKNOWN,
};

INLINE const char * com_get_transport_type_string (int trans)
{
	const char * ret = NULL;
	switch (trans) {
		case MULTICAST: ret = "MULTICAST"; break;
		case UD: ret = "RDMA/UD"; break;
		case RC: ret = "RDMA/RC"; break;
		case IP_TCP: ret = "TCP"; break;
		case IP_RDMA: ret = "IP/RDMA"; break;
		case COM_TYPE_UNKNOWN:
		default: ret = "UNKNOWN"; break;
	}
	return ret;
}

enum op_type {
	POST_RECV=0,
	POST_SEND,
	RDMA_READ,
	RDMA_WRITE,
	RDMA_READ_SGL, // only used by TCP
	RDMA_WRITE_SGL, // only used by TCP
	TCP_HS  // only used by TCP
};

enum rdma_op_flag {
	RDMA_OP_SERVER_ACK = 0x01
};

/* per-ep application callbacks */
typedef int ( *CONNECT_CB)    (struct com_ep *ep, void *ep_ctx);
typedef int ( *ACCEPT_CB)     (void *ctx);
typedef int ( *DISCONNECT_CB) (struct com_ep *ep, void *ep_ctx);
typedef int ( *SEND_CMP_CB)   (struct com_ep *ep, void *ep_ctx, void *app_ctx, int status);
typedef int ( *RECV_CMP_CB)   (struct com_ep *ep, void *ep_ctx, void *data, int len, int status);
typedef int ( *RDMA_CMP_CB)   (struct com_ep *ep, void *ep_ctx, void *app_ctx, int status);
typedef void ( *DESTRUCTOR_CB) (const struct com_ep *ep, void *ep_ctx);

struct com_attr {
    int                 rdma_disabled;
    int                 eth_disabled;
    int                 request_bounce_buffer_bytes;
    int                 bb_segment_bytes;
    CONNECT_CB          connect_cb;
    DISCONNECT_CB       disconnect_cb;
    SEND_CMP_CB         send_cmp_cb;
    RECV_CMP_CB         recv_cmp_cb;
    RDMA_CMP_CB         rdma_read_cmp_cb;
    RDMA_CMP_CB         rdma_write_cmp_cb;
    DESTRUCTOR_CB       destructor_cmp_cb;
};

#define RNA_DEFAULT_COM_COMP_MODE COM_COMP_MODE_WORKQ
/* Default mode for the cache client */
#define RNA_COM_CACHE_COMPLETION_MODE COM_COMP_MODE_WORKQ_CB

/*
 * ideally the completion mode would be defined in the platform independant code
 * but before that can be done, it needs to be abstracted out from
 * the rna_com_atts structure
 */
enum com_comp_mode{
	COM_COMP_MODE_IRQ = 1,  /* Do everything at soft IRQ level */
	COM_COMP_MODE_WORKQ_CB, /* Do data processing at soft IRQ, Callbacks in workqs */
	COM_COMP_MODE_WORKQ,    /* Do everything in workq's */
};

/* Attributes passed in to com_init_all */
struct rna_com_attrs {
    enum com_type com_type;
	enum com_comp_mode comp_mode;
    /* RDMA-only values */
    int           retry_count;
    int           rnr_retry_count;
};

struct rna_dev_attr {
    int max_sge;
    int max_wr;
};

// TODO: See which of these are unused and delete them

#define INVALID_BOUNCE_BIT  (-1)

struct buf_entry {
#ifndef WINDOWS_KERNEL
    struct buf_entry *next;
    struct buf_entry *rdma_send_buf;
    /* TODO: op_type should probably be an enum of type op_type (above) */
    int               op_type;
    void             *context;
    struct rna_com_envelope *env;
    void             *mem;
    rna_dma_addr_t    mem_dma;
    int               mem_size;
    struct com_ep    *ep;
    struct buf_pool  *pool;

    /* TCP-specific fields */
    rna_scatterlist_t sgl[RNA_COM_MAX_SGL]; /* Used to save the SGL list for TCP RDMA ops
                                                to copy data from socket buffers to the app buffers */
    int                sgl_nents;            /* Number of entries in the sgl table */

    /* RDMA-specific fields */
    struct ib_mr     *mr;  /* only used by ib */
    rna_dma_addr_t    zcopy_dma;
    struct ib_mr     *zcopy_mr;
    int               dma_size;
    enum              dma_data_direction direction;
    atomic_t          buf_use_state;
    atomic_t          extra_completions;
    int               comp_status; /* Status of rdma operation saved for async completions */
    void             *ctx;
    rna_addr_t        rem_addr; /* Saved remote address for an rdma read/write op */
    int               length;   /* Saved remote data len for an rdma read/write op */
    rna_rkey_t        rkey;     /* Saved remote rkey for an rdma read/write op */
    int               rdma_data_size;  /* May be smaller than mem_size. */
    int               rdma_flags;      /* Track flags if we have to re-queue. */
    int               is_rdma_buf;     /* Used to distinguish rdmabuf from sendbuf. */

    /* filesystem-specific fields */
    rna_rb_node_t     rb_node; /* only used by ethernet */
    uint64_t          tid;     /* only used by ethernet */

    /* IB specific, used to identify which pool this buffer belongs to. */
    int               index; /* our index into buf_pool array */
    uint32_t          op_flags; /* Optional flags for rdma/send operations */
    rna_work_struct_t queued_send_work;
    rna_list_head_t   queued_send_entry;
    rna_list_head_t   completed_list_entry;
    struct ib_work    ibw;
    int               send_size; /* used by deferred send logic */
    int               env_type;  /* used by deferred send logic */
    SEND_CMP_CB       send_cmp_cb; /* overrides ep's default send completion */
    void              *buf_transport_data;

    /* bounce buffer specific information */
    int               bounce_start_bit; /* first bit of bounce vector */
    int               bounce_bits;       /* bits needed in bounce vector */
    uint64_t          bounce_address;  /* address of bounce buffer */
    uint64_t          bounce_send_start; /* nanoseconds phase start time */
    uint64_t          bounce_rdma_start; /* nanoseconds phase start time */
    
    /* TCP specific thread-local state, placed here to save stack space.
     * Todo: find a better place for this so we don't bloat the sendbuf */
    struct rna_com_envelope tl_env;
    struct com_rdma_msg     tl_rdma_msg;
    struct et_work          etw; /* Used to post to the send workq */
    rna_kvec_t              tl_iov[2 + RNA_COM_MAX_SGL];
#else
	/* only expose the actual public members, keeping the implementation private
	   if we find code that references members, add them in here or make accessor functions that keep
	   the private implementation private */
    void             *mem;
#endif
};

/* buf_use_state values */
#define BUF_USE_FREE        0       // buf_entry is unallocated
#define BUF_USE_ALLOCATED   1       // buf_entry allocated, not yet issued
#define BUF_USE_INFLIGHT    2       // buf_entry allocated and issued
#define BUF_USE_COMPLETING  3       // buf_entry in process by normal
                                    //  completion path
#define BUF_USE_REPOSTED    4       // buf_entry processed by
                                    //  repost_uncompleted_ops()

/* end-point related functions */
int com_alloc_ep(struct rna_com *com_handle,
                 struct com_attr *com_attr,
                 enum com_type type,
                 void *context,
                 void *cma_id,
                 int num_send,
                 int num_recv,
                 int buf_size,
                 int num_rdma, int rdma_size,
                 user_type_t user_type,
                 uint8_t sync_recvq_flag,
                 int bounce_buffer_bytes,
                 int bb_segment_bytes,
                 struct com_ep** new_ep);
void com_set_ep_context(struct com_ep *ep, void *context);
void com_set_ep_user_type (struct com_ep *ep, user_type_t user_type);
void com_release_ep(struct com_ep *ep);
int com_disconnect_all_eps(struct rna_com *g_com);
void * com_ep_get_priv_data(struct com_ep *ep);
void com_set_priv_data(struct rna_com *com_handle, void *val);
void print_ep(struct com_ep *ep);

/* rdma get/put buffer functions as well as rdma I/O related functions */
int com_get_send_buf(struct com_ep *ep, struct buf_entry **buf, int poll_ep);
int com_put_send_buf(struct com_ep *ep, struct buf_entry *buf);
int com_send(struct com_ep *ep, struct buf_entry *buf, int size);
int com_get_rdma_buf(struct com_ep *ep, struct buf_entry **buf, int *length);
void com_put_rdma_buf(struct com_ep *ep, struct buf_entry *buf);
rna_rkey_t com_get_rkey(struct com_ep *ep, const struct rdma_buf *buf);
int com_rdma_read(struct com_ep *ep, struct buf_entry *rdma_buf,
                  rna_addr_t remote_addr,
                  void *buf, rna_rkey_t remote_rkey,
                  int size, void *context, char signaled, uint32_t flags);
int com_wait_rdma_avail(struct com_ep *ep);
int com_rdma_write(struct com_ep *ep, struct buf_entry *rdma_buf,
                   rna_addr_t remote_addr,
                   void *buf,
                   rna_rkey_t remote_rkey,
                   int size, void *context, char signaled, uint32_t flags);
int com_reg_single(struct com_ep *ep, struct rdma_buf *rdma_buf,
                   enum dma_data_direction direction);
void com_dereg_single(struct com_ep *ep, struct rdma_buf *rdma_buf);
int com_isreg(struct com_ep *ep, struct rdma_buf *rdma_buf);

/*
 * Creation/destruction of com handles, and routines to
 * associate a transport with a particular com handle.
 */

/* com create functions are platform specific */
int com_transport_enabled(struct rna_com *com, enum com_type type);
int com_exit(struct rna_com* com);

int com_connect(struct com_ep *ep, rna_sockaddr_t *dst_addr);
int com_connect_sync(struct com_ep *ep, rna_sockaddr_t *dst_addr, int timeout);
int com_connected(struct com_ep *ep);
int com_disconnect(struct com_ep *ep);


/* group platform specific APIs here */
#if defined(LINUX_KERNEL)

/* this is an opaque handle on other platforms */
struct rna_com {
    int avail_coms;
    struct rna_transport_handle *transports[MAX_TRANSPORTS];
    enum com_type transport_types[MAX_TRANSPORTS];
    void *priv_data;
    int min_proto_version;
    int max_proto_version;
};

struct rna_com *com_init(int min_proto_version, int max_proto_version);
struct rna_com *com_init_all(int transports,
                             const struct rna_com_attrs *attrs_ptr,
                             int min_proto_version,
                             int max_proto_version);

/* these are used internally on the Linux implemention */
int _com_send(struct com_ep *ep, struct buf_entry *buf, int size, enum env_type env_type);
int com_send_internal (struct com_ep *ep,
                       struct buf_entry *buf,
                       int size,
                       int nocredit,
                       enum env_type env_type);

/* scatterlists are a Linux construct, Windows will have versions that use MDLs */
int com_rdma_sgl( struct com_ep *ep, void *context, struct buf_entry *buf_entry,
                  rna_addr_t raddr, rna_scatterlist_t *sgl,int num_sgl,
                  rna_rkey_t rkey, int write, uint32_t flags );
int com_reg_sgl(struct com_ep *ep, rna_scatterlist_t *sgl, int nents, enum dma_data_direction direction);
void com_dereg_sgl(struct com_ep *ep, rna_scatterlist_t *sgl, int nents, enum dma_data_direction direction);
int com_mapping_error(struct com_ep *ep, rna_scatterlist_t *sgl);
void com_finish_rdma_op(struct com_ep *ep, struct buf_entry *buf, int status);
void com_complete_rdma_op(struct com_ep *ep, struct buf_entry *buf, int status);
void repost_uncompleted_ops( struct com_ep *ep);
void repost_read_credit(struct buf_entry *buf);

#elif defined(WINDOWS_KERNEL)
/* Windows drivers may have multiple instances (globals are mostly evil), 
   so we need some context information stored */
struct rna_com *com_init_ex(PVOID comAPIContextPublic,
							int transports,
                            const struct rna_com_attrs *attrs_ptr,
                            int min_proto_version,
                            int max_proto_version);

#else
# error "Unrecognized platform"
#endif
