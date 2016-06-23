/**
 * <rna_com_tcp.h> - Dell Fluid Cache block driver
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

#pragma once

#ifdef WINDOWS_KERNEL

#else
#include <linux/version.h>
#include <linux/in.h>
#endif /* WINDOWS_KERNEL */

#include "rna_byteswap.h"
#include "rna_locks.h"
#include "eth_rdma.h"
#include "com_envelope.h"

#define VERSION 0003

#define RNA_MAX_TCP_WR  4096

/* forward definition */
struct rna_com;
struct com_ep;
struct buf_entry;

enum eth_env_type{
	ETH_ENV_TYPE_UNSET,
	ETH_ENV_TYPE_HANDSHAKE,
	ETH_ENV_TYPE_PROTO,
	ETH_ENV_TYPE_RDMA,
	ETH_ENV_TYPE_ACK
};

INLINE void bswap_eth_envelope(struct rna_com_envelope *e)
{
#if CPU_BE
	e->envelope_boundary = bswap_16(e->envelope_boundary);
	e->envelope_version = bswap_16(e->envelope_version);
	e->rna_connection_type = bswap_16(e->rna_connection_type);
	e->msg_type = bswap_16(e->msg_type);
	e->msg_body_check = bswap_32(e->msg_body_check);
	e->msg_body_size = bswap_32(e->msg_body_size);
#endif
}

/* Used to store the envelope in progress */
struct com_inp_envelope{
	struct rna_com_envelope  env;
	int                      env_data_offset;
	struct rna_com_envelope *env_p;	
	int                      env_zcpy;
};

//#define CONNECT_TIMEOUT 2000  /* defined elsewhere as 5000 */
#define RNA_MAX_ETH_SEND_RETRIES 25

/***** These two defines must be the same as in ../../fcache/eth_envelope.h *****/
#define ETH_ENVELOPE_MAGIC_COOKIE 0x171E
#define ETH_ENVELOPE_VERSION      0x0001

// define this to check message body consistency
// #define ETH_ENVELOPE_CHECK_DATA        1

/******** Start of Stuff Copied from ../../fcache/com.h *********/


typedef enum {
	ETH_CONX_DISC,      /* Disconnected */
	ETH_CONX_CONX_EST,  /* TCP Established */
	ETH_CONX_PRIV_SENT, /* Sent private data (awaiting response) */
	ETH_CONX_CONNECTED, /* Connection is now usable for data traffic */
} eth_conx_status;

struct foo {
	struct com_conx_reply rep;
};

// types
struct et_work {
    struct work_struct w;
    struct com_ep *ep;
    struct rna_transport_handle *transport_handle;
    union {
        struct cfm_cmd   *cfm_cmd;
        struct cache_cmd *cache_cmd;
        struct buf_entry *buf;
        struct com_conx_reply csd;
        struct sockaddr dst_addr;
    } u;
    int type;
    int env_type;
    int status;
    int size;
    int resched;
    uint64_t msg_tid;
};

enum sock_recv_state{
	SOCK_RECV_STATE_READY,
	SOCK_RECV_STATE_ENV_IN_PROGRESS,
	SOCK_RECV_STATE_DATA_IN_PROGRESS
};

struct com_inp_recv{
	struct buf_entry *recv_buf;
	int               recv_data_offset;
};

struct com_inp_rdma{
	struct com_rdma_msg  rdma_msg;
	int                  rdma_msg_offset;
	struct buf_entry    *rdma_buf;
	int                  rdma_data_offset;
};

struct com_inp_handshake{
	struct com_conx_reply csd;
	int                         handshake_data_offset;
};


struct com_socket {
    struct socket               *com;
	atomic_t                     com_sock_state;
    void (*com_old_data_ready)   (struct sock *, int);
    void (*com_old_state_change) (struct sock *);
    void (*com_old_write_space)  (struct sock *);
	atomic_t                     recv_in_progress;
	enum sock_recv_state         recv_state;
	spinlock_t                   sock_lock;
    atomic_t                     com_rd_bytes_available;
    atomic_t                     com_bytes_writeable;
	struct work_struct           sock_recv_work; /* Used in sockets mode to queue (com) work requests */
	atomic_t                     connected;
    int64_t                      last_time;
	struct com_inp_envelope      inp_env;       /* In progress envelope */
	struct com_inp_recv          inp_recv;      /* In progress receive */
	struct com_inp_rdma          inp_rdma;      /* In progress rdma */
	struct com_inp_handshake     inp_handshake; /* In progress handshake */
};



/**
 * A work "envelope" is just a holder of a work struct with
 * an in_use flag.  Since messages can come in on a socket
 * faster than they are processed by the work queue, and
 * since you can't queue the same struct twice, we need a
 * pool of them.
 */ 
#define MAX_WORK_ENVELOPES 128
struct com_work_envelope {
    struct work_struct work;
    struct com_ep      *ep; 
    int                 is_rdma;
    int                 in_use;
};


/******** End of Stuff Copied from ../../fcache/com.h *********/

/**
 ***************************************
 * Function Declarations
 ***************************************
 */

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
void com_event( void *work);
#else
void com_event( struct work_struct *work);
#endif




/**
 * rna_countbits - an inexpensive (and crummy) alternative to crc32 that doesn't care about endian stuff - just counts 1 bits
 *                 I tried to find a reasonable crc32 algorithm with a license we don't have to care about, but couldn't find anything
 *                 reasonable.  (The best is linux source code src/crc32.c, but that has an initialization function and is GPL, so
 *                 we *must not touch* it.  I didn't want to take the time right now to find or write our own.)
 * @buffer - the bytes to count bits in
 * @buffer_len - the number of bytes in buffer
 */
uint32_t rna_countbits(void *buffer, uint32_t buffer_len);

/**
 * If an ep has disconnected, we need to go through all the outstanding requests and
 * call the appropriate completion callback with an error code.  TODO: find out if recursive
 * functions are a no-no in kernel code.  Since this is depth-first tree walk, it shouldn't
 * recurse more than log2(n) times...
 *
 * @param tree - the red-black tree
 */
void rb_clear_on_disconnect(struct com_ep *ep, struct rb_root * tree, struct rb_node *node);

/**
 * Make sure we have only one thread at a time trying to clean up the same outstanding
 * requests for an ep.
 * @param ep - the endpoint that has disconnected
 */
void ep_clear_pending(struct com_ep *ep);

void check_data_avail( struct socket *sock, atomic_t *remaining_available);

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
struct work_struct * rna_new_work(struct rna_com *com_handle, void (*func) (void *), void *data, int rdma);
#else
struct work_struct * rna_new_work(struct rna_com *com_handle, void (*func) (struct work_struct *), void *data, int rdma);
#endif

void check_data_writeable( struct socket *sock, atomic_t *remaining_available);
void reschedule_work(struct com_ep *ep);

/**
 * Debugging functions, for helping to figure out mismatches between client
 * and server.  Comment or ifdef these out when things start working.
 */
void rna_dbg_print_com_rdma_hdr(const char * dbg_level, const char *caller, struct com_rdma_hdr * hdr, int printchars, int numcalls);
char * rna_dbg_get_eth_msg_type(uint8_t type);
char * rna_dbg_get_eth_status_type(uint8_t type);
void rna_dbg_log_status(struct socket *sock, int success, int rval);

int com_get_recv_buf(struct com_ep *ep,
    struct buf_entry **buf);

int com_release_recv_buf(struct com_ep *ep,
    struct buf_entry *recv_buf);

