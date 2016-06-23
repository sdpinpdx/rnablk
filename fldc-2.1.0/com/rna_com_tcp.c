/**
 * <rna_com_tcp.c> - Dell Fluid Cache block driver
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

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/socket.h>
#include <linux/uio.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/net.h>
#include <linux/sockios.h>
#include <linux/sched.h>
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
#include <asm/mmsegment.h>
#endif
#include <asm/uaccess.h>
#include <asm/ioctls.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/tcp_states.h>
//#include "protocol.h"
#include "../include/rna_common.h"
#include "com_envelope.h"
#include "rna_com_linux_kernel.h"

#include "priv_data.h"
#include "trace.h"
#include "rna_proc_ep.h"
#include <linux/sockios.h>
#include <net/tcp.h>


// definitions
#define DEBUG_ETH_COM 0
#define MAX_READ_ITERATIONS 32768 /* Do 8 consective reads before yielding the workq to another socket */
#define RNA_COM_TCP_RDMA_BUF_WAIT 30000 /* Max wait time for an RDMA buf. Purposely set high since callers don't handle this case very well */

#define RNA_SOCK_OPT_SO_KEEPALIVE 1

/* Number of keepalives that fail before disconnecting. */
#define RNA_SOCK_OPT_TCP_KEEPCNT        5
/* Time (in seconds) for connection to be idle before sending keepalives. */
#define RNA_SOCK_OPT_TCP_KEEPIDLE       60
/* Time (in seconds) between keepalives. */
#define RNA_SOCK_OPT_TCP_KEEPINTVL      12

#define RNA_SOCK_OPT_TCP_NODELAY 1 /* 1=Enable, 0=Disable WARNING Disabling this has some drastic performance implications */
#define RNA_SOCK_OPT_SO_SNDTIMEO 10 

#define STRINGIZE(int) #int

#define RNA_ETH_COM_CREDITS_DEFAULT 256
#define RNA_ETH_COM_CREDITS_WAIT 50 /* Milliseconds to wait for credits */

// prototypes
int com_free_ep(struct rna_transport_handle *transport_handle,
                struct com_ep               *ep);
int com_schedule_free_ep( struct com_ep *ep );


// globals
static uint32_t dbg_flags = DBG_FLAG_ERROR;
static atomic_t next_tid = ATOMIC_INIT( 0 );
static struct workqueue_struct *conn_wq;
static struct workqueue_struct *comp_wq;
static struct workqueue_struct *send_wq;
static struct workqueue_struct *recv_wq;
static struct workqueue_struct *delayed_send_wq;
struct mutex             dev_lst_lock;
struct list_head         dev_lst_head;

static spinlock_t eth_com_credit_lock; /* Synchronize on the credits variable */
static int com_recv_credits = RNA_ETH_COM_CREDITS_DEFAULT;
module_param(com_recv_credits, int, 0444);
MODULE_PARM_DESC(com_recv_credits,
        "Receive credits.  0 = use system limit (default).  "
        "Number of outstanding page requests which may affect performance "
        "by limiting network congestion. Default=8"
        );
/* Note: We translate the credits to bytes. We may change this to outstanding requests in the future though */
static int64_t eth_com_credits = (RNA_ETH_COM_CREDITS_DEFAULT * 4096);

static 	wait_queue_head_t eth_com_credit_wait; /* wait queue for send buffer */


// save a pointer to the default state change routine
static void (*sock_def_wakeup)( struct sock * ) = NULL;
static void (*sock_def_data_ready) (struct sock *, int) = NULL;
static void sock_def_readable(struct sock *sk, int len);

void com_put_rdma_buf( struct com_ep *ep, struct buf_entry *buf);
int com_queue_completion( struct com_ep *ep,
						 int type,
						 struct buf_entry *entry,
						 int status);

int com_queue_csd( struct com_ep *ep, struct com_conx_reply *csd, uint64_t tid);

int
com_socket_recv_soft_irq(read_descriptor_t *d, struct sk_buff *skb,
						 unsigned int offset, size_t len);

int com_queue_recv_work( struct com_ep *ep);
int com_put_recv_buf( struct com_ep *ep,struct buf_entry *buf );
static int rna_com_socket_read( struct com_ep *ep);
static void et_disconnect_part2 (struct com_ep *ep);
void com_sock_run_completion_cbs(struct com_ep *ep);

// module parameters

int sndbuf_kb = 0;
module_param(sndbuf_kb, int, 0444);
MODULE_PARM_DESC(sndbuf_kb, 
	"Size of sndbuf in KB.  0 = use system limit (default).  "
	"Set smaller if you see allocation failures from "
	"__alloc_skb in dmesg.  Smaller values may degrade performance.  "
	"128 is a reasonable starting place.");

int tcp_keepcnt = RNA_SOCK_OPT_TCP_KEEPCNT;
module_param(tcp_keepcnt, int, 0444);
MODULE_PARM_DESC(tcp_keepcnt, 
    "The maximum number of missed probes before a TCP "
     "connection will be dropped.  Default: " STRINGIZE(RNA_SOCK_OPT_TCP_KEEPCNT));

int tcp_keepidle = RNA_SOCK_OPT_TCP_KEEPIDLE;
module_param(tcp_keepidle, int, 0444);
MODULE_PARM_DESC(tcp_keepidle, 
    "The number of seconds to wait on an idle TCP connection "
    "before sending a probe.  Default: " STRINGIZE(RNA_SOCK_OPT_TCP_KEEPIDLE));

int tcp_keepintvl = RNA_SOCK_OPT_TCP_KEEPINTVL;
module_param(tcp_keepintvl, int, 0444);
MODULE_PARM_DESC(tcp_keepintvl, 
    "The number of seconds between probes on a TCP connection. "
    "Default: " STRINGIZE(RNA_SOCK_OPT_TCP_KEEPINTVL));

int tcp_nodelay = RNA_SOCK_OPT_TCP_NODELAY;
module_param(tcp_nodelay, int, 0444);
MODULE_PARM_DESC(tcp_nodelay, 
    "Determines whether to disable the Nagle algorithm on TCP connections. "
    "Default: " STRINGIZE(RNA_SOCK_OPT_TCP_NODELAY));



void
repost_read_credit(struct buf_entry *buf)
{
	spin_lock_bh(&eth_com_credit_lock);
	eth_com_credits += buf->length;
	spin_unlock_bh(&eth_com_credit_lock);
	
	wake_up_all(&eth_com_credit_wait);
	
}

/* Helper functions to keep a reference count on workqueue
 * items that may invoke a user callback.  We use it to let
 * us know if it's safe to call the disconnect callback. */
static void inc_callback_queued(struct com_ep *ep)
{
        atomic_inc(&ep->callback_queued);
}

/* Must be run in kthread context, as it may invoke the 
 * disconnect callback, which in turn may sleep. */
static void dec_callback_queued(struct com_ep *ep) 
{
	might_sleep();
	if (atomic_dec_and_test(&ep->callback_queued)) {
		et_disconnect_part2(ep);
	}
}

/* Wait on the credits variable. Note that it is possible for credits to go 
 negative since we'll only wait so long and this counter keeps track of
 all outstanding RDMA read operations. Failed connections will eventually
 refill their outstanding credits. */
static void eth_wait_on_credits(int size){
	int retry = TRUE;
	int ret;
	
do_retry:
	
	/* Check the global counter */
	spin_lock_bh(&eth_com_credit_lock);
	if((eth_com_credits > size) || (retry == FALSE)){
		eth_com_credits -= size;
		retry = FALSE;
	}	
	spin_unlock_bh(&eth_com_credit_lock);
	
	if(retry){
		/* Wait on credits to go up */
		rna_printk(KERN_DEBUG,"Waiting on credits [%d] Current credits [%"PRId64"]\n", size,eth_com_credits);
		ret = wait_event_interruptible_timeout (eth_com_credit_wait,
												(eth_com_credits > size),
												msecs_to_jiffies ( RNA_ETH_COM_CREDITS_WAIT ) );												
		if(ret <= 0){
			rna_printk(KERN_INFO,"Timed out waiting on credits [%d] Current credits [%"PRId64"]\n",size,eth_com_credits);
			retry = FALSE;
		}
		goto do_retry;		
	}
	
	return;
}


/* How many bytes can we read without blocking?
 * The get_fs/set_fs trick is to prevent the kernel
 * from checking if arg is really a user pointer.
 * I'm not sure if this is really necessary. */
static size_t bytes_avail(struct sock *sk)
{
    int arg = 0;
    mm_segment_t oldfs = get_fs();
    set_fs(KERNEL_DS);
	
    tcp_ioctl (sk, SIOCINQ, (unsigned long)&arg);
	
    set_fs(oldfs);
    return arg;
}


/* Used by rna_com_transport_module.c to fill in
 * the rna_transport structure. */
enum com_type get_transport_type( void )
{
    return IP_TCP;
}

enum rna_first_send_order transport_ep_send_order(struct com_ep *ep)
{
    return ep->passive ? DEFAULT_PASSIVE_TCP_SEND_ORDER :
                         DEFAULT_ACTIVE_TCP_SEND_ORDER;
}

int WARN_UNUSED set_com_sock_state(struct com_ep *ep, int prev_state, int new_state)
{
	BUG_ON (NULL == ep);

	if(atomic_cmpxchg(&ep->com_sock.com_sock_state,prev_state,new_state) != prev_state){
		return -1;
	}
	
	return 0;
}

/* The kernel send and recieve methods are awkward,
 * so we use our own wrappers. */

/* This is only ever called from com_socket_recv_soft_irq, 
 * which is a socket callback. */
int rna_recvmsg(struct com_ep *ep, struct kvec *iov, size_t nsgl, 
                size_t size, int flags)
{
	struct msghdr msg;

	msg.msg_name       = NULL;
	msg.msg_namelen    = 0;
	msg.msg_iov        = (struct iovec *)&iov;
	msg.msg_iovlen     = nsgl;
	msg.msg_control    = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags      = 0;

	return kernel_recvmsg(ep->com_sock.com, &msg, iov, nsgl, size, flags);
}

/* Should be called with the send_mutex held, both to prevent multiple
 * writers from jumbling a message and to keep the socket from 
 * disappearing on us. */
int rna_sendmsg(struct com_ep *ep, struct kvec *iov, size_t nsgl, 
                size_t size)
{
	struct msghdr msg;

	msg.msg_name       = NULL;
	msg.msg_namelen    = 0;
	msg.msg_iov        = (struct iovec *)&iov;
	msg.msg_iovlen     = nsgl;
	msg.msg_control    = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags      = 0;

	if(atomic_read(&ep->ep_state) != EP_CONNECTED){
		return -1;
	}

	return kernel_sendmsg(ep->com_sock.com, &msg, iov, nsgl, size);
}

/* Append the second kvec array onto the first.  The caller is expected
 * to verify that the first kvec array is large enough. 
 * Return length of resulting vector in bytes. */
unsigned long kvec_append (struct kvec *iov1, int nsgl1, 
                           struct kvec *iov2, int nsgl2)
{
	int i;
	unsigned long len = 0;

	for (i = 0; i < nsgl1; i++) {
		len += iov1[i].iov_len;
	}

	for (i = 0; i < nsgl2; i++) {
		iov1[i+nsgl1] = iov2[i];
		len += iov2[i].iov_len;
	}

	return len;
}


/* Append a scatterlist to a list of kvecs, doing the appropriate
 * conversions.  Caller is expected to verify that iov1 is large enough.
 * Return length of resulting vector in bytes. */
unsigned long kvec_append_sgl (struct kvec *iov1, int nsgl1, 
                               struct scatterlist *sgl2, int nsgl2)
{
	int i;
	unsigned long len = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
	struct scatterlist *sg;
#endif

	for (i = 0; i < nsgl1; i++) {
		len += iov1[i].iov_len;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
	for (i = 0; i < nsgl2; i++) {
		iov1[i+nsgl1].iov_base = page_address(sgl2[i].page) + sgl2[i].offset;
		iov1[i+nsgl1].iov_len  = sgl2[i].length;
		len += sgl2[i].length;
	}
#else
	for_each_sg(sgl2, sg, nsgl2, i) {
		iov1[i+nsgl1].iov_base = page_address(sg_page(sg)) + sg->offset;
		iov1[i+nsgl1].iov_len  = sg->length;
		len += sg->length;
	}
#endif

	return len;
}

static int _com_send_internal (struct com_ep *ep, struct scatterlist *sgl,
                              int nsgl, int msg_type)
{
    struct socket *sock;
    struct rna_com_envelope env;
    int total_len;
    int i;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
    struct scatterlist *sg;
#endif
    ENTER;

    mutex_lock (&ep->send_mutex);
    sock = ep->com_sock.com;

    if (NULL == sock) { 
        ret = -EINVAL;
    } else { 
        ep = (struct com_ep *)sock->sk->sk_user_data;

        ep->iov[0].iov_base = &env;
        ep->iov[0].iov_len  = sizeof( struct rna_com_envelope );
        total_len       = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
        for( i=0; i < nsgl; i++ ) {
            ep->iov[i+1].iov_base = page_address( sgl[i].page ) + sgl[i].offset;
            ep->iov[i+1].iov_len  = sgl[i].length;
            total_len         += sgl[i].length;
        }
#else
        for_each_sg(sgl, sg, nsgl, i) {
            ep->iov[i+1].iov_base = page_address(sg_page(sg)) + sg->offset;
            ep->iov[i+1].iov_len  = sg->length;
            total_len            += sg->length;
        }
#endif
        /* Empty message is an unsolicited ack. */
        if (0 == total_len) {
            msg_type = ENV_TYPE_ACK;
        }

        com_envelope_init(&env, ep->user_type, total_len, msg_type, 
                          atomic_inc_return(&ep->trans_id) - 1, 
                          com_get_reset_unacked_recvs(ep));
        ret = rna_sendmsg(ep, &ep->iov[0],nsgl + 1, total_len + sizeof( env ) );
        rna_trace("ep[%p] Sent %d bytes\n",ep,(int)ret);
    }

    mutex_unlock( &ep->send_mutex );
    EXIT;
}


static struct buf_entry *
com_locate_rdma_buf_entry(struct com_ep *ep, uint64_t tid)
{
	int i;
	struct buf_entry* tmp = (struct buf_entry*)tid;
	
	/* Search the rdma_buffer list */
	for(i=0;i<ep->num_rdma;i++){
		if(tmp == ep->rdma_pool[i]){
			BUG_ON(atomic_read(&ep->rdma_pool[i]->buf_use_state) ==
                               BUF_USE_FREE);
			return ep->rdma_pool[i];
		}
	}
	
	return NULL;
}

// This currently runs ONLY on comp_wq context.
static void com_socket_handshake_complete(struct com_ep *ep,
                                          struct com_conx_reply *csd,
                                          uint64_t tid )
{
    int addr_len;
    int ret = 0;
    int bytes_read;
#ifdef REMOTE_PID_ENABLED
    struct task_struct *task = NULL;
#endif
    ep->remote_trans_id = tid;
#ifdef REMOVE_PID_ENABLED
    ep->remote_pid = csd->src_pid;

    rcu_read_lock();
    ep->remote_mm = get_task_mm(pid_task(find_get_pid((pid_t)ep->remote_pid),
                                         PIDTYPE_PID));
    rcu_read_unlock();

    rna_printk(KERN_ERR, "Remote PID of con[%p] is [%"PRIu64"] mm[%p]\n",
               ep, ep->remote_pid, ep->remote_mm);
#endif
    /* Debugging state check */
    if(0 == set_com_sock_state(ep,ETH_CONX_PRIV_SENT,ETH_CONX_CONNECTED)) {

        /* TODO: Get ETH_CONX_OK defined in kernel land */
        if(csd->status == 0){
            // retrieve peer address
            addr_len = sizeof( struct sockaddr_in );
            ep->com_sock.com->ops->getname(ep->com_sock.com,
                                           ep->dst_addr,&addr_len, 1 );
            ep->com_sock.com->ops->getname(ep->com_sock.com,
                                           ep->src_addr,&addr_len, 0 );

            // connection established
            if(atomic_cmpxchg(&ep->ep_state, EP_CONNECT_PENDING, EP_CONNECTED) ==
               EP_CONNECT_PENDING){
                ep->proto_version = csd->proto_version;
                rna_spin_lock(ep->transport_handle->ep_dsc_lock);
                if(CB_FAILED == ep->callback_state) {
                    /*
                     * A com_connect_sync() on this ep has timed out.  Don't
                     * invoke an unexpected callback.
                     */
                    rna_spin_unlock(ep->transport_handle->ep_dsc_lock);
                }else{
                    /*
                     * A com_connect_sync() on this ep hasn't timed out.
                     * Indicate that the connect_cb, if defined, is about to
                     * be invoked.
                     */
                    ep->callback_state = CB_CONNECTED;
                    rna_spin_unlock(ep->transport_handle->ep_dsc_lock);
                    if(ep->com_attr.connect_cb){
                        ret = ep->com_attr.connect_cb( ep,ep->context );
                    }
                    if (0 != ret) {
                        com_disconnect(ep);
                    }
                }

                if ((0 == ret) && (!ep->passive)) {
                    do_first_ack(ep);
                    do_immediate_unplug(ep);
                }

                /*
                 * Let com_connect_sync() and com_wait_connected know about the
                 * state change.
                 */
                wake_up_all( &ep->conn_wait );

                /*
                 * if any new messages arrived on the kernel socket while
                 * the handshake completion was queued, then processes
                 * those right now. (see HRM-6003)
                 */
                bytes_read = rna_com_socket_read(ep);
                rna_printk(KERN_INFO,
                           "ep [%p] Read [%d] bytes\n",
                           ep,
                           bytes_read);
                com_sock_run_completion_cbs(ep);
            }else{
                /* EP has probably been disconnected */
                rna_printk(KERN_ERR,
                           "Got handshake but EP %p no longer in CONNECT_PENDING\n",
                           ep);
            }
            rna_trace("EP[%p] Successfully Connected\n",ep);

        }else{
            rna_printk(KERN_ERR,"Connection failed. Private data rejected with "
                       "status[%d]\n",csd->status);
            com_disconnect(ep);
        }
    } else {
        rna_printk(KERN_ERR, "Got handshake but sock state for EP %p "
                   "no longer in ETH_CONX_PRIV_SENT\n", ep);
    }
}

static inline void
rna_com_post_completed_op(struct com_ep *ep)
{
    struct buf_entry *buf = ep->com_sock.inp_rdma.rdma_buf;

    /* clear to make sure we don't erroneously re-use this rdma_buf! */
    ep->com_sock.inp_rdma.rdma_buf = NULL;

    spin_lock_bh(&ep->completed_list_lock);
    list_add_tail(&buf->completed_list_entry, &ep->completed_list);
    spin_unlock_bh(&ep->completed_list_lock);
}

// runs in kthread context
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
void com_socket_recv( void *arg)
#else
void com_socket_recv( struct work_struct *arg)
#endif
{
    struct com_ep *ep;
    int bytes;
	int consumed;
	struct sock *sk = (struct sock*)arg;
	int max_iterations = MAX_READ_ITERATIONS;
	read_descriptor_t rd;
	
    ENTER;

	ep = (struct com_ep *)sk->sk_user_data;
	
	/* Shutting down stops all communication even if things were in flight. */
	if(is_shutting_down(ep->transport_handle)){
		atomic_set(&ep->com_sock.recv_in_progress,0);
		goto out;
	}

	/* We might be better off moving this lock inside 
	 * com_socket_recv_soft_irq, but it looks like this function
	 * can't gracefully handle the case where someone else pulls
	 * data off the socket.  See also the comment in 
	 * rna_com_socket_read. */
	spin_lock_bh(&ep->recv_serialization_lock);
	
	bytes = bytes_avail(sk);
	
	rd.count = 1;
	rd.arg.data = ep;
	
	/* Note: This is to limit the number of times we go through this loop in the event
	 lots of little messages arrived since we started processing them */	
	atomic_set(&ep->com_sock.recv_in_progress,1);	

	while(1){
#if 0		
		/* To avoid starving other sockets put this one in the back of the queue. */
		if(--max_iterations == 0){
			/* Requeue work */
			
			/* Note: This is necessary on newer kernels to clear the pending bit in the workq structure. 
			         Otherwise the queue work will fail. */
			//work_release( &ep->com_sock.sock_recv_work );
			
			RNA_INIT_WORK( &ep->com_sock.sock_recv_work, com_socket_recv, sk );
			rna_queue_work( recv_wq, &ep->com_sock.sock_recv_work);
			break;
		}
		
#endif			
		consumed = com_socket_recv_soft_irq(&rd, NULL,0,bytes);		
		if(0 == rd.count){
			/* We had an error and should stop trying. */
			goto err;
		}
		
		/* Don't mess with the recv_in_progress counter since we didn't get all
		   the bytes on the last pass */
		if(consumed < bytes){
			continue;
		}
		
		/* No data. We exit syncronized on the in progress flag */
		if(atomic_dec_return(&ep->com_sock.recv_in_progress) == 0){
			break;
		}
		/* Reset how many bytes are available to drain */
		bytes = bytes_avail(sk);
	}

out:
	spin_unlock_bh(&ep->recv_serialization_lock);
	dec_callback_queued(ep);
	EXITV;

err:
	com_disconnect(ep);
	atomic_set(&ep->com_sock.recv_in_progress,0);
	goto out;
}

struct com_buf* find_rdma_buf(uint64_t ctx)
{
	/* FIXME: Do a lookup on the context for the buffer. For now the context is the pointer. */
	struct com_buf* buf = (struct com_buf*)ctx;
	
	return buf;
}


// runs in kthread context
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
void et_send_priv_data( void *arg)
#else
void et_send_priv_data( struct work_struct *arg)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
    struct work_struct *w = (struct work_struct *)arg;
    struct et_work *etw = w->data;
#else
    struct et_work *etw = container_of(arg, struct et_work, w);
#endif
    struct com_ep *ep;
    struct rna_com_envelope env;
    struct req_priv_data pd;
    struct msghdr msg;
    struct kvec iov[2];
    int flag = 1;
    struct socket *sock;
		
    ENTER;
	
    TRACE("sending private data arg %p\n", arg);

    ep = (struct com_ep *)etw->ep;

    if (is_shutting_down(ep->transport_handle)) {
        return;
    }
	
    mutex_lock( &ep->send_mutex );

    sock = ep->com_sock.com;
    BUG_ON(NULL == sock);

    com_envelope_init(&env, ep->user_type, sizeof(struct req_priv_data),
                      ENV_TYPE_HANDSHAKE, 
                      atomic_inc_return(&ep->trans_id) - 1,
                      com_get_reset_unacked_recvs(ep));

    // turn off the nagle algorithm on this socket
    sock->ops->setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag));

    pd = (struct req_priv_data) {
        .version           = VERSION,
        .num_send          = ep->num_send,
        .num_recv          = ep->num_recv,
        .buf_size          = ep->buf_size,
        .user_type         = ep->user_type,
        .cpu_be            = CPU_BE,
        .min_proto_version = ep->com_handle->min_proto_version,
        .max_proto_version = ep->com_handle->max_proto_version,
        .bounce_buf_size   = 0,
    };

    iov[0].iov_base = &env;
    iov[0].iov_len  = sizeof( struct rna_com_envelope );
    iov[1].iov_base = &pd;
    iov[1].iov_len  = sizeof( struct req_priv_data );

    msg.msg_name       = NULL;
    msg.msg_namelen    = 0;
    msg.msg_iov        = (struct iovec *)&iov;
    msg.msg_iovlen     = 2;
    msg.msg_control    = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags      = 0;
	
	/* Debugging state check */
	if(set_com_sock_state(ep, ETH_CONX_CONX_EST, ETH_CONX_PRIV_SENT)){
		ret = -EIO;
		GOTO( out,ret );
	}

    if( (ret = kernel_sendmsg(sock, &msg, &iov[0], 2, iov[0].iov_len + iov[1].iov_len)) <= 0 )
        GOTO( out,ret );

out:
	
	mutex_unlock( &ep->send_mutex );
	
    EXITV;
}

// runs in kthread context
static void et_close( void *arg )
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
    struct work_struct *w = (struct work_struct *)arg;
    struct et_work *etw = w->data;
#else
    struct et_work *etw = container_of(arg, struct et_work, w);
#endif
    struct com_ep *ep = etw->ep;
	
    ENTER;
	
    if (!is_shutting_down(ep->transport_handle))
        com_disconnect(ep);
	
    kfree( etw );
	
    EXITV;
}


#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
void et_call_disconnect( void *arg)
#else
void et_call_disconnect( struct work_struct *arg)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
    struct work_struct *w = (struct work_struct *)arg;
    struct et_work *etw = w->data;
#else
    struct et_work *etw = container_of(arg, struct et_work, w);
#endif
    struct com_ep *ep;
	
    ENTER;
	
	ep = etw->ep;
	
	BUG_ON(ep == NULL);
		
	com_disconnect(ep);
	
	com_release_ep(ep);
	
	kfree( etw );
	
    EXITV;
}

// runs in kthread context
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
static void et_disconnect(void *arg)
#else
static void et_disconnect(struct work_struct *arg)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
    struct work_struct *w = (struct work_struct *)arg;
    struct et_work *etw = w->data;
#else
    struct et_work *etw = container_of(arg, struct et_work, w);
#endif
    struct com_ep *ep = etw->ep;
    struct sock *sk = ep->com_sock.com->sk;
    int bytes_read;
		
    ENTER;

    BUG_ON(NULL == sk);

    BUG_ON(NULL == sk);

    if (!is_shutting_down(ep->transport_handle)) {
        if (atomic_cmpxchg(&ep->ep_state,
                           EP_DISCONNECT_PENDING,EP_DISCONNECTED) == 
            EP_DISCONNECT_PENDING){

            /* We don't want to lose any data received prior to the 4-way teardown,
             * so drain before sock_release discards all pending data. */
            if (ep->transport_handle->comp_mode != COM_COMP_MODE_WORKQ){
                bytes_read = rna_com_socket_read(ep);
                com_sock_run_completion_cbs(ep);
                rna_trace("EP[%p] Read %d bytes\n",ep,bytes_read);
            }

            /* Reset the callback pointers to prevent new 
             * socket callback invocations. */        
            write_lock_bh(&sk->sk_callback_lock);
            sk->sk_state_change = ep->com_sock.com_old_state_change;
            sk->sk_data_ready   = ep->com_sock.com_old_data_ready;
            write_unlock_bh(&sk->sk_callback_lock);

            /* Force all the cores to schedule, so we know there
             * aren't any lingering socket callbacks that are
             * running concurrently.
             * rcu_barrier may work, but this is not ideal since we're
             * relying on the rcu implementation not to change. */
            rcu_barrier();

            /* Return all uncompleted rdma operations.
             * Runs synchronously and does not queue any work. */
            repost_uncompleted_ops(ep);

            rna_trace("ep[%p] usr_type[%d] disconnected\n", 
                      ep, ep->user_type);

            if (NULL != ep->remote_mm) {
                mmput(ep->remote_mm);
            }
            /* Drop long-held reference.  We can't access the ep
             * from here on out. */
            dec_callback_queued(ep);
            ep = NULL;

        }else{
            rna_printk(KERN_ERR, "EP[%p] is in an invalid state %d\n",
                       ep, atomic_read(&ep->ep_state));
        }
    }
	
    kfree( etw );

    EXITV;
}

/* Called from dec_callback_queued when the ep no longer has
 * any callbacks queued, thus it is safe to run the disconnect
 * callback.  */
static void et_disconnect_part2 (struct com_ep *ep)
{
    ENTER;

    BUG_ON (ep == NULL);
    BUG_ON (0 != atomic_read(&ep->callback_queued));

    rna_trace("ep[%p] usr_type[%d] disconnected\n", 
              ep, ep->user_type );

    /* If the connect_callback has been invoked for the ep, invoke the
     * disconnect callback. */
    rna_spin_lock(ep->transport_handle->ep_dsc_lock);
        /*
         * Either the ep has connected (CB_CONNECTED)
         * or an asynchronous connection attempt has failed (CB_INIT).
         * NOTE: in the second case, we will be calling the disconnect
         * call-back for and EP which never got a connect call-back.
         * This is sub-optimal, but we don't currently have a better
         * machanism available.
         */
    if ((CB_CONNECTED == ep->callback_state) ||
        (CB_INIT == ep->callback_state)) {
        // Indicate that the disconnect_cb, if defined, is about to be invoked.
        ep->callback_state = CB_DISCONNECTED;
        rna_spin_unlock(ep->transport_handle->ep_dsc_lock);
        if (ep->com_attr.disconnect_cb) {
            (*ep->com_attr.disconnect_cb)(ep, ep->context);
        }
    } else {
        rna_printk(KERN_ERR, "ep [%p] state [%d]\n", ep, ep->callback_state);

        /*
         * A com_connect_sync() on this ep has timed out (CB_FAILED), or the
         * disconnect callback has already been invoked (CB_DISCONNECTED,
         * shouldn't happen).  Don't invoke an unexpected callback.
         */
        rna_spin_unlock(ep->transport_handle->ep_dsc_lock);
    }
  
    /* Let com_connect_sync() and com_wait_connected know about the
     * state change. */
    wake_up_all(&ep->conn_wait);

    /* Generally this will end up calling com_free_ep().
     * We can't access the ep pointer from here on out. */
    com_release_ep(ep);
    ep = NULL;

    EXITV;
}

// runs at soft irq level
static void com_state_change( struct sock *sk )
{
    struct com_ep *ep;
    struct et_work *etw;
	
    ENTER;
	
    TRACE( "sk %p state %d\n",sk,sk->sk_state );

    ep = (struct com_ep *)sk->sk_user_data;

    if (NULL==ep) {
        rna_printk(KERN_ERR, "ep is NULL\n");
        EXITV;
    }

    if(NULL != ep->com_sock.com_old_state_change) {
        (*ep->com_sock.com_old_state_change)( sk );
    }

    if (is_shutting_down(ep->transport_handle))
        return;

    switch( sk->sk_state ) {
        case TCP_SYN_SENT:
            TRACE ("TCP_SYN_SENT sk %p\n", sk);
            break;
        case TCP_SYN_RECV:
            TRACE ("TCP_SYN_RECV sk %p\n", sk);
            break;
        case TCP_ESTABLISHED:
            TRACE ("TCP_SYN_ESTABLISHED sk %p\n", sk);
            /* Debugging state check */
            if(set_com_sock_state(ep,ETH_CONX_DISC,ETH_CONX_CONX_EST)){
                BUG();
            }
            /* This could race with com_disconnect_all_eps, 
             * resulting in a dangling EP.*/
            atomic_set(&ep->com_sock.connected, 1);
            if( (etw = rna_kmalloc(etw ,GFP_ATOMIC )) != NULL ) {
                etw->ep = ep;
                RNA_INIT_WORK(&etw->w, et_send_priv_data, etw);
                rna_queue_work( conn_wq,&etw->w );
                TRACE( "queued et_send_priv_data to the conn_wq... sk=%p\n", sk);
            } else {
                rna_printk(KERN_ERR, "can't allocate et_work\n");
            }
            break;
        case TCP_CLOSE:
		case TCP_CLOSE_WAIT:
		case TCP_FIN_WAIT1:
		case TCP_FIN_WAIT2:
		case TCP_TIME_WAIT:
            TRACE ("Closing connection ep[%p] sk=%p\n",ep , sk);					
			
            if (!(set_com_sock_state(ep, ETH_CONX_CONX_EST,  ETH_CONX_DISC) ||
                  set_com_sock_state(ep, ETH_CONX_PRIV_SENT, ETH_CONX_DISC) ||
                  set_com_sock_state(ep, ETH_CONX_CONNECTED, ETH_CONX_DISC)) )
            {
                rna_printk(KERN_WARNING, "Unexpected socket close, ignoring.\n");
            } else {

                /* Guard against this being called multiple times. We may get multiple events. All events 
                   lead to closing the ep. We should notify the application in a timely manner. */
                if( (atomic_cmpxchg( &ep->ep_state, EP_CONNECT_PENDING, EP_DISCONNECT_PENDING ) == EP_CONNECT_PENDING) ||
                    (atomic_cmpxchg( &ep->ep_state, EP_CONNECTED, EP_DISCONNECT_PENDING ) == EP_CONNECTED) ) {
                    if( (etw = rna_kmalloc(etw, GFP_ATOMIC )) != NULL ) {
                        etw->ep = ep;
                        RNA_INIT_WORK(&etw->w, et_disconnect, etw);
                        rna_queue_work( conn_wq,&etw->w );
                    } else {
                        rna_printk(KERN_ERR, "No memory to queue disconnect, "
                                   "leaking resources. ep=%p\n", ep);
                    }
                    rna_printk(KERN_INFO,
                                "EP [%p] state [%s] socket state [%d]\n",
                                ep,
                                get_ep_state_string(atomic_read(&ep->ep_state)),
                                sk->sk_state);
                } else {
                    rna_printk(KERN_INFO, "Got close on EP %p in state %s, ignoring\n", 
                               ep, get_ep_state_string(atomic_read(&ep->ep_state)));
                }

            }
			break;
        default:
            TRACE ("some other state sk=%p\n", sk);
            break;
    }

    EXITV;
}

// runs in either kthread or softirq context
static int com_socket_recv_data(struct com_ep *ep, void *mem, int msg_len)
{
    struct kvec iov[1];
    int total_len;
    int ret = 0;

    if (msg_len > 0) {
        iov[0].iov_base = mem;
        iov[0].iov_len  = msg_len;
        total_len = iov[0].iov_len; 
	
	ret = rna_recvmsg( ep,&iov[0],1,total_len,MSG_DONTWAIT );
    }

    return ret;
}

static inline int
rna_copy_socket_bits(struct com_ep *ep, struct sk_buff *skb, unsigned int offset, void *env_ptr, size_t to_read)
{
	int bytes_read;
	
	if(to_read == 0)
		return 0;
	
	if(skb){
		bytes_read = skb_copy_bits(skb, offset, env_ptr, to_read);
		if(bytes_read != 0){
			rna_printk(KERN_ERR,"Failed to read bytes expected on socket. Socket will be put in error state ret[%d] copy size attempted[%zd]\n",bytes_read,to_read);
		}		
		return bytes_read;
	}
	
	bytes_read = com_socket_recv_data(ep, env_ptr, to_read);
	if(bytes_read != to_read){
		rna_printk(KERN_ERR,"Failed to read bytes expected on socket. Socket will be put in error state read[%d] expected[%zd]\n",bytes_read,to_read);
		return -EFAULT;
	}
	
	return 0;
}


static inline int
com_socket_envelope_get(struct com_ep *ep, struct sk_buff *skb,
						unsigned int offset, size_t len, int *bytes_read)
{
	int env_size = sizeof(struct rna_com_envelope);
	int to_read;
	char *env_ptr;
	
	to_read = env_size - ep->com_sock.inp_env.env_data_offset;
	
	/* This is OK. We already have the envelope */
	if(0 == to_read){
		return 0;
	}
	
	if(len < to_read){
		to_read = len;
	}
	
	env_ptr = (char*)&ep->com_sock.inp_env.env + ep->com_sock.inp_env.env_data_offset;
	
	if(rna_copy_socket_bits(ep, skb, offset, env_ptr, to_read) != 0){
		return -EFAULT;
	}
	ep->com_sock.inp_env.env_data_offset += to_read;
	
	*bytes_read = to_read;

	if(ep->com_sock.inp_env.env_data_offset == env_size){
		/* We have a whole envelope*/
		return 0;
	}

	/* More to go */
    return -EAGAIN;
}

static inline int
com_socket_proto_get(struct com_ep *ep, struct sk_buff *skb,
                     unsigned int offset, size_t len, int *bytes_read)
{
	int msg_size;
	int to_read;
	char *env_ptr;
	
	BUG_ON(NULL == ep);
	BUG_ON(NULL == ep->com_sock.inp_recv.recv_buf);
	
	msg_size = ep->com_sock.inp_env.env.msg_body_size;
	to_read = msg_size - ep->com_sock.inp_recv.recv_data_offset;
	
	if(len < to_read){
		to_read = len;
	}
		
	env_ptr = (char*)ep->com_sock.inp_recv.recv_buf->mem + ep->com_sock.inp_recv.recv_data_offset;
	
	rna_trace("EP[%p] msg size[%d] to_read[%d] buf[%p] current_bytes[%d]\n", 
	          ep, msg_size, to_read, env_ptr, ep->com_sock.inp_recv.recv_data_offset);
	
	if(rna_copy_socket_bits(ep, skb, offset, env_ptr, to_read) != 0){
		return -EFAULT;
	}
	
	ep->com_sock.inp_recv.recv_data_offset += to_read;
	
	
	*bytes_read = to_read;
	
	if(ep->com_sock.inp_recv.recv_data_offset == msg_size){
		/* We have a whole envelope*/
		ep->com_sock.inp_recv.recv_buf->length = msg_size;
		/* If we can do the callback at the softirq level or if we're already in a workq then instantiate the callback, else queue it up. */
#if 0
        /* MVP-6980 We always queue the recv completions so that the handler can process messages inline without having to reallocate the 
         * the message structure. Code is left in, in case the block client code changes that makes this even unecessary. There is a performance
         * penalty for the queue, but lock dependancies. */
		if((ep->transport_handle->comp_mode == COM_COMP_MODE_IRQ) || 
		   (ep->transport_handle->comp_mode == COM_COMP_MODE_WORKQ )){
			if (NULL != ep->com_attr.recv_cmp_cb){
				ep->com_attr.recv_cmp_cb( ep, ep->context, ep->com_sock.inp_recv.recv_buf->mem, ep->com_sock.inp_recv.recv_buf->length, 0);
			}
			com_put_recv_buf(ep, ep->com_sock.inp_recv.recv_buf);
		}else{
			/* Queue the work */
			com_queue_completion(ep, POST_RECV, ep->com_sock.inp_recv.recv_buf, 0);
		}
#else
        com_queue_completion(ep, POST_RECV, ep->com_sock.inp_recv.recv_buf, 0);
#endif
		ep->com_sock.inp_recv.recv_buf = NULL;

		return 0;
	}
	
	/* More to go */
	return -EAGAIN;
}

static inline int
com_socket_handshake_get(struct com_ep *ep, struct sk_buff *skb,
					 unsigned int offset, size_t len, int *bytes_read)
{
	int msg_size = ep->com_sock.inp_env.env.msg_body_size;
	int to_read;
	char *env_ptr;
	
	to_read = msg_size - ep->com_sock.inp_handshake.handshake_data_offset;
	
	if(len < to_read){
		to_read = len;
	}
	
	env_ptr = (char*)&ep->com_sock.inp_handshake.csd + ep->com_sock.inp_handshake.handshake_data_offset;
	
	if(rna_copy_socket_bits(ep, skb, offset, env_ptr, to_read) != 0){
		return -EFAULT;
	}
	ep->com_sock.inp_handshake.handshake_data_offset += to_read;
	
	*bytes_read = to_read;
	
	if(ep->com_sock.inp_handshake.handshake_data_offset == msg_size){
		/* We have a whole message*/
		com_queue_csd(ep,&ep->com_sock.inp_handshake.csd,ep->com_sock.inp_env.env.tid);
		return 0;
	}
	
	/* More to go */
    return -EAGAIN;
}

/* Returns index in which offset is located */
int com_socket_rdma_locate_segment(struct buf_entry *rdma_buf, int offset, int *seg_offset, int *seg_remain){
	int i;
	int bytes = 0;
	
	for(i=0;i<rdma_buf->sgl_nents;i++){
		if(rdma_buf->sgl[i].length + bytes > offset){
			*seg_offset = offset - bytes;
			*seg_remain = rdma_buf->sgl[i].length - *seg_offset;
			return i;
		}
		bytes += rdma_buf->sgl[i].length;
	}

	return -1;
}

static inline int
com_socket_rdma_payload_get(struct com_ep *ep, struct sk_buff *skb,
							unsigned int offset, size_t len, int *bytes_read)
{
	int msg_size;
	int to_read;
	char *env_ptr;
	int i;
	struct buf_entry *rdma_buf = ep->com_sock.inp_rdma.rdma_buf;

	/* Set status in the rdma_buf since the buf is eventually posted to a list without the response message */
	ep->com_sock.inp_rdma.rdma_buf->comp_status = ep->com_sock.inp_rdma.rdma_msg.hdr.status; 
	
	if(ep->com_sock.inp_rdma.rdma_buf->op_type == RDMA_READ_SGL){
		int seg_offset = 0;
		int seg_remain = 0;
		int seg_index;
		
		msg_size = ep->com_sock.inp_rdma.rdma_msg.hdr.payload_len;
		
		while(1){
			seg_index = com_socket_rdma_locate_segment(rdma_buf,ep->com_sock.inp_rdma.rdma_data_offset,&seg_offset, &seg_remain);
			if(seg_index < 0){
				rna_printk(KERN_ERR,"EP[%p] Segment could not be located for rdma_buf[%p]\n", ep, rdma_buf);
				return -EIO;
			}			
			
			to_read = seg_remain;
			if(len < to_read){
				to_read = len;
			}
			
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
			env_ptr = (char*)(page_address(rdma_buf->sgl[seg_index].page) + rdma_buf->sgl[seg_index].offset) + seg_offset;
#else
// XXX This will NOT work for chained scatterlists - code needs rework
			env_ptr = (char*)(page_address(sg_page(&rdma_buf->sgl[seg_index])) + rdma_buf->sgl[seg_index].offset) + seg_offset;
#endif
			
			rna_trace("EP[%p] msg size[%d] to_read[%d] read[%d] ptr[%p] offset[%d] segment[%d]\n", ep, msg_size, to_read, seg_offset, env_ptr, offset, seg_index);
			
			if(rna_copy_socket_bits(ep, skb, offset, env_ptr, to_read) != 0){
				return -EFAULT;
			}
			
			ep->com_sock.inp_rdma.rdma_data_offset += to_read;
			
			*bytes_read += to_read;

			offset += to_read;
			len -= to_read;			
			
			if(ep->com_sock.inp_rdma.rdma_data_offset == msg_size){
				break;
			}
			
			if(len == 0){
				return -EAGAIN;
			}
		}

		rna_com_post_completed_op(ep);
			
	}else if(ep->com_sock.inp_rdma.rdma_buf->op_type == RDMA_READ){
		
		/* Just read into the single buffer */
		msg_size = ep->com_sock.inp_rdma.rdma_msg.hdr.payload_len;
		to_read = msg_size - ep->com_sock.inp_rdma.rdma_data_offset;
		if(len < to_read){
			to_read = len;
		}
		
		env_ptr = ((char*)ep->com_sock.inp_rdma.rdma_buf->mem) + ep->com_sock.inp_rdma.rdma_data_offset;
		
		rna_trace("EP[%p] msg size[%d] to_read[%d] read[%d] ptr[%p] offset[%d]\n", ep, msg_size, to_read, ep->com_sock.inp_rdma.rdma_data_offset, env_ptr, offset);
		
		if(rna_copy_socket_bits(ep, skb, offset, env_ptr, to_read) != 0){
			return -EFAULT;
		}
		
		ep->com_sock.inp_rdma.rdma_data_offset += to_read;
		
		/* Note this adds since we may have read some bytes in getting the header */
		*bytes_read += to_read;
		
		if(ep->com_sock.inp_rdma.rdma_data_offset != msg_size){
			/* We require more bytes so just return. */
			return -EAGAIN;
		}

		rna_com_post_completed_op(ep);
		
	}else if((ep->com_sock.inp_rdma.rdma_buf->op_type == RDMA_WRITE) ||
             (ep->com_sock.inp_rdma.rdma_buf->op_type == RDMA_WRITE_SGL)){

		rna_com_post_completed_op(ep);

	}else{
		/* Invalid optype */
		rna_printk(KERN_ERR,"EP[%p] Invalid op_type[%d]\n",
				   ep,
				   ep->com_sock.inp_rdma.rdma_buf->op_type);		
	}
	
	
	return 0;
}


static inline int
com_socket_rdma_header_get(struct com_ep *ep, struct sk_buff *skb,
                         unsigned int offset, size_t len, int *bytes_read)
{
    int msg_size = sizeof(ep->com_sock.inp_rdma.rdma_msg);
    int to_read;
    char *env_ptr;
    int payload_read = 0;
    int l_offset = offset;
    int l_len = len;
    boolean do_disconnect = FALSE;
    int ret;

    if(ep->com_sock.inp_rdma.rdma_msg_offset < msg_size){
        /* We need to read in the rdma request first to lookup the entry */
        to_read = msg_size - ep->com_sock.inp_rdma.rdma_msg_offset;
        if(len < to_read){
            to_read = len;
        }

        env_ptr = (char*)&ep->com_sock.inp_rdma.rdma_msg +
                        ep->com_sock.inp_rdma.rdma_msg_offset;

        if(rna_copy_socket_bits(ep, skb, offset, env_ptr, to_read) != 0){
            return -EFAULT;
        }

        ep->com_sock.inp_rdma.rdma_msg_offset += to_read;

        *bytes_read = to_read;

        l_offset += to_read;
        l_len -= to_read;

        if(ep->com_sock.inp_rdma.rdma_msg_offset != msg_size){
            /* We require more bytes so just return. */
            return -EAGAIN;
        }

        /* Validate header */
        if(ep->com_sock.inp_rdma.rdma_msg.hdr.status){
            rna_printk(KERN_ERR,
                       "EP[%p] RDMA Operation Failed with status[%s]\n",
                       ep, get_rna_com_cb_resp_status_string(
                       ep->com_sock.inp_rdma.rdma_msg.hdr.status));
            if (CB_RESP_FAIL == ep->com_sock.inp_rdma.rdma_msg.hdr.status) {
                /*
                 * A CB_RESP_FAIL is an indication that the connection
                 * is going away.  Be pro-active about it!
                 * (But finish processing the message first).
                 */
                do_disconnect = TRUE;
            }
            /* drop down so we call completion and clean up socket */
        }

        ep->com_sock.inp_rdma.rdma_buf = com_locate_rdma_buf_entry(ep,
                                    ep->com_sock.inp_rdma.rdma_msg.hdr.cookie);

        if (ep->com_sock.inp_rdma.rdma_buf){
            rna_trace("Got RDMA buffer[%p] mem[%p]\n",
                      ep->com_sock.inp_rdma.rdma_buf,
                      ep->com_sock.inp_rdma.rdma_buf->mem);
            ep->com_sock.inp_rdma.rdma_data_offset = 0;
        }
    }
    if (NULL == ep->com_sock.inp_rdma.rdma_buf) {
        rna_printk(KERN_ERR,
                   "EP[%p] Failed to locate the rdma buf entry[%"PRIx64"]! "
                   "len[%"PRId64"]\n", ep,
                   ep->com_sock.inp_rdma.rdma_msg.hdr.cookie,
                   ep->com_sock.inp_rdma.rdma_msg.hdr.payload_len);
        return -EIO;
    } else {
        ret = com_socket_rdma_payload_get(ep,skb,l_offset,l_len,bytes_read);
        if (0 == ret && do_disconnect) {
            queue_disconnect_work(ep);
        }
        return ret;    
    }
}

static inline void reset_envelope(struct com_ep *ep){
	ep->com_sock.inp_env.env_data_offset = 0;
}

static inline void reset_handshake(struct com_ep *ep){
	ep->com_sock.inp_handshake.handshake_data_offset = 0;
}

static inline void reset_proto_msg(struct com_ep *ep){
	ep->com_sock.inp_recv.recv_data_offset = 0;
}

static inline void reset_rdma_msg(struct com_ep *ep){
	ep->com_sock.inp_rdma.rdma_msg_offset = 0;
	ep->com_sock.inp_rdma.rdma_data_offset = 0;
}




/* Must not run concurrently with itself. 
 * (Enforced by acquiring ep->recv_serialization_lock) */
int
com_socket_recv_soft_irq(read_descriptor_t *d, struct sk_buff *skb,
				unsigned int offset, size_t len)
{
	int l_offset = offset;
	struct com_ep *ep = d->arg.data;
	size_t l_len = len;
	int bytes_read = 0;
	int ret = 0;
	
	rna_trace("ep[%p] offset[%d] len[%zd]!\n",ep, l_offset, l_len);
	
	if(len == 0){
		return 0;
	}
	
again:
	/* Switch on state */	
	if(ep->com_sock.recv_state == SOCK_RECV_STATE_READY){
		ret = com_socket_envelope_get(ep, skb, l_offset, l_len, &bytes_read);
		
		rna_trace("ep[%p] got env bytes read[%d] offset[%d] len[%zd]!\n",ep, bytes_read, l_offset, l_len);
		
		l_offset += bytes_read;
		l_len -= bytes_read;		

		if(ret == -EAGAIN){
			/* We didn't have enough bytes so just return */
			goto done;
		}else if(ret){
            rna_printk(KERN_ERR, "failed to get env, error [%d]\n", ret);
			goto err;
		}

        com_process_acks(ep, &ep->com_sock.inp_env.env);

		/* Setup the next stage */
		switch(ep->com_sock.inp_env.env.msg_type){
			case ENV_TYPE_RDMA:
				reset_rdma_msg(ep);
				break;
			case ENV_TYPE_PROTO:
				/* Attmept to allocate a recv buffer */
				ret = com_get_recv_buf(ep, &ep->com_sock.inp_recv.recv_buf);
				if(ret){
					/* Recv buffer logic will requeue a socket read in this event */
					/* Tell caller to back off by resetting the count field */
					rna_printk(KERN_ERR, "EP[%p] Failed to get recv buffer resetting d->count\n",ep);
                    print_ep(ep);
					d->count = 0;
					goto done;
				}
				reset_proto_msg(ep);
				break;
			case ENV_TYPE_HANDSHAKE:
				reset_handshake(ep);
				break;
			case ENV_TYPE_ACK:
				break;
			default:
				rna_printk(KERN_ERR,"EP[%p] Bad envelope! type value[%d] len[%d]\n",ep, 
				ep->com_sock.inp_env.env.msg_type,
				ep->com_sock.inp_env.env.msg_body_size);
                ret = -EIO;
				goto err;
		}

		/* We're all set up for the next stage */
		ep->com_sock.recv_state = SOCK_RECV_STATE_DATA_IN_PROGRESS;
	}
	
	rna_trace("ep[%p] type[%d]\n",ep, ep->com_sock.inp_env.env.msg_type);
	
	if(ep->com_sock.recv_state == SOCK_RECV_STATE_DATA_IN_PROGRESS){
		switch(ep->com_sock.inp_env.env.msg_type){
			case ENV_TYPE_RDMA:
				ret = com_socket_rdma_header_get(ep,skb,l_offset,l_len,&bytes_read);
				break;
			case ENV_TYPE_PROTO:
				ret = com_socket_proto_get(ep,skb,l_offset,l_len,&bytes_read);
				break;
			case ENV_TYPE_HANDSHAKE:
				ret = com_socket_handshake_get(ep,skb,l_offset,l_len,&bytes_read);				
				break;
			case ENV_TYPE_ACK:
				bytes_read = 0;
				ret = 0;
				break;
			default:
				rna_printk(KERN_ERR,"EP[%p] Bad envelope! Type[%d]\n",ep,ep->com_sock.inp_env.env.msg_type);
				goto err;
		}
	
		l_offset += bytes_read;
		l_len -= bytes_read;		

		if(0 == ret){
			ep->com_sock.recv_state = SOCK_RECV_STATE_READY;
			reset_envelope(ep);
			goto again;
		}else if(ret != -EAGAIN){
			goto err;
		}
	}
	
done:
	return (len - l_len);
	
err:
	rna_printk(KERN_ERR,
               "ep[%p] ERROR[%s]: returning [%dd]\n",
               ep,
               get_rna_com_cb_resp_status_string(ret),
               ret);
	/* Tell caller to back off by resetting the count field */
	d->count = 0;
    queue_disconnect_work(ep);
	return (ret);
}


// Normally runs at soft irq level. May run in kthread context if
// requeued.
static int rna_com_socket_read(struct com_ep *ep)
{
	read_descriptor_t rd;
	int bytes = 0;
	
	BUG_ON(NULL == ep->com_sock.com);

	if (NULL == ep->com_sock.com->sk) {
		rna_printk(KERN_ERR, "sk NULL (shouldn't happen)\n");
	} else {
		/* Locking constraints:
		 * we must disable softirqs if we take a write lock
		 * com_socket_recv_soft_irq cannot run concurrently with
		 *     itself, so we need a write lock.
		 * tcp_read_sock expects at least a read lock on 
		 *     sk_callback_lock  
		 * lockdep complains if we take a write lock on 
		 *     sk_callback_lock due to a conflict with sunrpc
		 *     (see MVP-4753) 
		 * solution: take a read lock on sk_callback_lock, and
		 *     a write lock on a per-ep lock we use only to
		 *     guarantee serialized access to 
		 *     com_socket_recv_soft_irq */
		read_lock_bh(&ep->com_sock.com->sk->sk_callback_lock);
		spin_lock_bh(&ep->recv_serialization_lock);
		rd.arg.data = ep;
		rd.count = 1;
		bytes = tcp_read_sock(ep->com_sock.com->sk, &rd, 
		                      com_socket_recv_soft_irq);
		spin_unlock_bh(&ep->recv_serialization_lock);
		read_unlock_bh(&ep->com_sock.com->sk->sk_callback_lock);
	}

	return bytes;
}

void
com_sock_run_completion_cbs(struct com_ep *ep)
{
    struct buf_entry *buf;
    struct list_head *pos;

    while (1) {
        spin_lock_bh(&ep->completed_list_lock);
		if(list_empty(&ep->completed_list)){
            spin_unlock_bh(&ep->completed_list_lock);
			break;
		}

        buf = list_first_entry(&ep->completed_list,
                               struct buf_entry,
                               completed_list_entry);

		BUG_ON(NULL == buf);

        list_del_init(&buf->completed_list_entry);
        spin_unlock_bh(&ep->completed_list_lock);

        BUG_ON(!(buf->op_type == RDMA_WRITE
                || buf->op_type == RDMA_WRITE_SGL
                || buf->op_type == RDMA_READ
                || buf->op_type == RDMA_READ_SGL));

        if ((ep->transport_handle->comp_mode == COM_COMP_MODE_IRQ) ||
            (ep->transport_handle->comp_mode == COM_COMP_MODE_WORKQ)) {
            com_complete_rdma_op(ep, buf, buf->comp_status);
        } else {
            /* Queue the work */
            com_queue_completion(ep, buf->op_type, buf, buf->comp_status);
        }

	}
}


// runs at soft irq level
static void com_sock_data_ready( struct sock *sk, int bytes )
{
    struct com_ep *ep = NULL;
    struct et_work *etw;
    int bytes_read;

    if (! sk) {
        rna_printk(KERN_ERR,
                   "socket pointer is NULL. Ignoring data available\n");
                   
        return;
    }
    
    ep = (struct com_ep *)sk->sk_user_data;

    if (NULL == ep) {
        rna_printk( KERN_ERR, "Context for socket[%p] is NULL. "
                    "Ignoring data available\n", sk);
        return;
    }

    /* stopgap dubious partial fix for MVP-4494 */
    if (unlikely((atomic_read(&ep->ep_state)) > EP_CONNECTED))
        return;

    /* invoke the original callback */
    if (NULL != ep->com_sock.com_old_data_ready) {
        (*ep->com_sock.com_old_data_ready)(sk, bytes);
    }

    /* 
     * TODO: Optimize scheduling work on the number of data bytes received. 
     * When bytes_avail is greater then the size of the envelope, we can 
     * schedule work assuming not all bytes have arrived, we can use a hint 
     * on when to schedule more work 
     */

	/* ignore callbacks if shutdown flag is set */	
	if(likely(!is_shutting_down(ep->transport_handle))) {
		if(ep->transport_handle->comp_mode != COM_COMP_MODE_WORKQ){
			bytes_read = rna_com_socket_read(ep);
			rna_trace("EP[%p] Read %d bytes\n",ep,bytes_read);
			/* 
             * TODO: Fix up this logic. the comp mode workq is obsolete with 
             * this change to drain and put all the completions on a list. We 
             * can consolidate down to inline or workq completions but we'll 
             * always drain inline. 
             */
			com_sock_run_completion_cbs(ep);
		}else{
			if(((atomic_read(&ep->ep_state) == EP_CONNECTED) || 
                (atomic_read(&ep->ep_state) == EP_CONNECT_PENDING)) && 
               (atomic_inc_return(&ep->com_sock.recv_in_progress) == 1)){
				/* 
                 * TODO: Move INIT_WORK to the com_alloc_ep routine since its 
                 * part of the structure. 
                 */
				RNA_INIT_WORK(&ep->com_sock.sock_recv_work, com_socket_recv, sk);
				inc_callback_queued(ep);
				rna_queue_work( recv_wq, &ep->com_sock.sock_recv_work);
			}
		}
	}
	
	return;
}

static int
send_completion(struct com_ep *ep, struct buf_entry *send_buf, int ret)
{
    SEND_CMP_CB cb = ep->com_attr.send_cmp_cb;

    if (NULL != send_buf->send_cmp_cb) {
        cb = send_buf->send_cmp_cb;
    }

    if (DEBUG_ETH_COM)
        rna_printk ( KERN_DEBUG, "ep=0x%p, send_buf=0x%p\n", ep, send_buf );

    if (NULL != cb) {
        (cb) (ep, ep->context, (void*) send_buf->context, ret);
    }

    com_put_send_buf(ep, send_buf);
    return 0;
}

static int free_ep( struct com_ep *ep )
{
    int ret = 0;
    int state;
	
    BUG_ON(atomic_read(&ep->com_sock.recv_in_progress) > 0);
    BUG_ON(!list_empty(&ep->entries));

    com_free_buf_pool(ep, &ep->send_pool);
    com_free_buf_pool(ep, &ep->recv_pool);
    com_free_buf_pool(ep, &ep->credits_pool);
    com_free_rdma_pool(ep);

    sock_release( ep->com_sock.com );
    ep->com_sock.com = NULL;

    rna_destroy_workqueue( ep->send_wq );

    memset(ep, 1, sizeof(*ep));

    kfree ( ep );
    return 0;
}

static int init_ep( struct com_ep *ep )
{
    int ret = -1;

    /* TODO: Make this common across transports */
    rna_spin_lock_init(ep->rdma_lock);
    spin_lock_init(&ep->completed_list_lock);

    if (ep->num_recv) {
        ret = com_alloc_buf_pool(ep, &ep->recv_pool,
                                 ep->num_recv, ep->buf_size);

        if (ret) {
            printk("rna_com: unable to allocate recv pool <ep=0x%p> %d\n", ep,
                   ret);
            goto err;
        }
    }

    if (ep->num_send) {
        ret = com_alloc_buf_pool(ep, &ep->send_pool,
                                 ep->num_send, ep->buf_size);

        if (ret) {
            printk("rna_com: unable to allocate send pool <ep=0x%p> %d\n", ep,
                   ret);
            goto err;
        }
        atomic_set(&ep->min_send_avail, atomic_read(&ep->send_pool.num_avail));
    }

    ret = com_alloc_buf_pool(ep, &ep->credits_pool, CREDIT_BUFS, 0);
    if (ret) {
        rna_printk(KERN_ERR, "unable to allocate credit pool ep [%p]\n", ep);
        goto err;
    }

    if (ep->num_rdma) {
        ret = com_alloc_rdma_pool(ep, ep->num_rdma, ep->rdma_buf_size);

        if (ret) {
            printk("rna_com: unable to allocate rdma pool <ep=0x%p> %d\n", ep,
                   ret);
            goto err;
        }
    }

    return ret;

err:
    com_free_buf_pool(ep, &ep->recv_pool);
    com_free_buf_pool(ep, &ep->recv_pool);
    com_free_buf_pool(ep, &ep->credits_pool);
    com_free_rdma_pool(ep);
    return ret;
}

static void init_rdma_buf ( struct buf_entry *rdma_buf )
{
    if ( DEBUG_ETH_COM )
        rna_printk ( KERN_DEBUG, "rdma_buf=0x%p\n", rdma_buf );

    rdma_buf->rem_addr.device_id.data  = 0;
    rdma_buf->rem_addr.base_addr  = 0;
    rdma_buf->zcopy_dma = 0;
    rdma_buf->op_type   = -1;
    rdma_buf->dma_size  = 0;
}

rna_rkey_t com_get_rkey( struct com_ep *ep, const struct rdma_buf* buf )
{
    return 0;
}

void _com_release_ep ( struct com_ep *ep, const char *fn )
{
    int ret;
    int do_free = 0;

    rna_trace ( "Caller: %s, ep: %p\n", fn, ep );

    if ( !ep ) {
        rna_printk ( KERN_ERR, "ERROR: EP is NULL, caller: %s\n", fn );
        return;
    }

    ret = atomic_add_return ( -1, &ep->ref_count );

    if ( ret < 0 ) {
        /* HACK. This should be for debugging only to detect refence counting issues */
        rna_printk ( KERN_ERR, "WARNING: Caller [%s] dereferencing ep[%p] state[%s] "
                     "but ep has no references count[%d] (tcp)\n",
                     fn,
                     ep,
                     get_ep_state_string(atomic_read ( &ep->ep_state )),
                     atomic_read ( &ep->ref_count ) );
        print_ep(ep);
        dump_stack();
        atomic_inc ( &ep->ref_count );
    }

    /* Note: for fully debugged code, reference count should *NEVER* be less then 0 */
    if ( ret == 0 ) {
		/* It would be a bug to free something that is connected or in some transient state */
		if ((atomic_read(&ep->ep_state) != EP_INIT) && (atomic_read(&ep->ep_state) != EP_DISCONNECTED)) {
			rna_printk ( KERN_ERR, "Caller [%s] dereferencing ep [%p] state [%s] reference count went to 0 but state is not what we expect.\n",
                         fn,
                         ep,
                         get_ep_state_string(atomic_read ( &ep->ep_state )));
			dump_stack();
            BUG_ON (TRUE);
        }
		ret = com_schedule_free_ep ( ep );    
		if(ret){
			rna_printk(KERN_WARNING,
                       "WARNING: Failed to schedule free work for EP[%p]. "
                       "Memory will not be free'd until the module is "
                       "unloaded\n", ep);
		}
	}

	return;
}

int
com_get_rdma_buf(struct com_ep *ep, struct buf_entry **buf, int *len)
{
    int num_buf;
    int buf_size = 0;
    struct buf_entry *rdma_buf = NULL;
	int count = 0;
    int remaining;

    /* 
     * rnablk_queue_dispatch.c was sending in a fixed value of 1 for *len,
     * but that needed to be updated for bounce buffer allocation in the
     * RDMA transport.  Here we set *len to 1 for TCP, because it should
     * always be allocating a single rdma_buf.
     *
     * XXX--CMG.  This is ugly.
     */
    if (*len > ep->rdma_buf_size) {
        rna_printk(KERN_DEBUG, "Passed in *len [%d] forcing to [1]\n", *len);
    }
    *len = 1;

    if ( DEBUG_ETH_COM )
        rna_printk ( KERN_DEBUG, "ep=0x%p, buf=0x%p, len=%d\n", ep, buf, *len );

    BUG_ON ( !ep );

    if ( atomic_read ( &ep->ep_state ) != EP_CONNECTED ) {
        rna_trace("ep[%p] send on ep->ep_state not connected state %d\n", ep , atomic_read ( &ep->ep_state ) );
        *buf = NULL;
        return 0;
    }

    if ( !ep->rdma_pool )
        return -1;

    *buf = NULL;

    if ( *len <= ep->rdma_buf_size )
        num_buf = 1;
    else {
        num_buf = ( *len / ep->rdma_buf_size );

        if ( *len % ep->rdma_buf_size )
            num_buf++;
    }

    if ( num_buf > 1 ) {
        printk ( "com_get_rdma_buf: NUM BUF %d, len %d, buf_size %d\n",
                 num_buf, *len, ep->rdma_buf_size );
    }

    rna_spin_lock( ep->rdma_lock );

    while ( num_buf ) {
        if ( atomic_read(&ep->rdma_avail) ) {
            if ( !rdma_buf ) {
                rdma_buf = ep->rdma_pool[ep->next_rdma];
                BUG_ON ( !rdma_buf );

				if (atomic_cmpxchg(&rdma_buf->buf_use_state, BUF_USE_FREE,
                                   BUF_USE_ALLOCATED) == BUF_USE_FREE) {
                    init_rdma_buf ( rdma_buf );
					remaining = atomic_dec_return(&ep->rdma_avail);
                    if (remaining < atomic_read(&ep->min_rdma_avail)) {
                        atomic_set(&ep->min_rdma_avail, remaining);
                    }
                } else {
                    /* Note: sometimes the next_rdma buf shows up as incompleted
                     * continue to next buffer
                     */
                    rdma_buf = NULL;
                    ep->next_rdma++;
                    
					if ( ep->next_rdma >= ep->num_rdma ) {
                        ep->next_rdma = 0;
                    }
					
					/* If we've examined the entire list then just bail */
					if(++count == ep->num_rdma){
						break;
					}
					
                    continue;
                }
            }

            buf_size += ep->rdma_buf_size;

			ep->next_rdma++;
            if ( ep->next_rdma >= ep->num_rdma ) {
                ep->next_rdma = 0;
            }
            num_buf--;
        }
        else {
            rdma_buf = NULL;
            break;
        }
    }

    /* return the actual number of bytes available */
    if ( buf_size < *len )
        *len = buf_size;

    //printf("com returning rdma length %d\n", *len);

    *buf = rdma_buf;

    rna_spin_unlock( ep->rdma_lock );
	
	if(!rdma_buf){
		return -1;
	}
	
    return 0;
}

int com_alloc_rdma_pool ( struct com_ep *ep, int num_rdma, int buf_size )
{
    int ret = 0;
    int i;

    /* size in bytes of array of "buf_entry->mem" buffers */
    int size;

    /* size in bytes of buf_entry array */
    int be_array_size = sizeof ( *ep->rdma_pool ) * num_rdma;

    if ( DEBUG_ETH_COM )
        rna_printk ( KERN_DEBUG, "ep=0x%p, num_rdma=%d, buf_size=%d\n", ep, num_rdma, buf_size );

    ep->num_rdma = num_rdma;
    ep->rdma_buf_size = buf_size;

    size = num_rdma * buf_size;
    ep->rdma_mem = NULL;

    /* allocate array of buf_entry pointers */
    ep->rdma_pool = kmalloc (sizeof (struct buf_entry*) * num_rdma,
                             RNA_NOIO);
    if (!ep->rdma_pool) {
        ret = -ENOMEM;
        goto err;
    }

    for (i=0; i<num_rdma; i++) {
        ep->rdma_pool[i] = kmalloc (sizeof (struct buf_entry),
                                    RNA_NOIO);

        if (!ep->rdma_pool[i]) {
            ret = -ENOMEM;
            goto err;
        }
    }
  

    if ( DEBUG_ETH_COM )
        printk ( "rna: page_size = %ld, rdma_alloc total size %d, rdma_buf size %d \n",
                 PAGE_SIZE, size, buf_size );

    atomic_set(&ep->rdma_avail, ep->num_rdma);
    atomic_set ( &ep->rdma_posted, 0 );
    ep->next_rdma = 0;

    /* init rdma pool */

    for ( i = 0; i < num_rdma; i++ ) {
        ep->rdma_pool[i]->mem = NULL;
        //init_waitqueue_head(&(ep->rdma_pool[i].wait));
        atomic_set(&ep->rdma_pool[i]->buf_use_state, BUF_USE_FREE);
    }
    atomic_set(&ep->min_rdma_avail, ep->num_rdma);
    return 0;

err:
    com_free_rdma_pool ( ep );
    return ret;
}

int com_free_rdma_pool ( struct com_ep *ep )
{
    int i;
    struct buf_entry *be;

    if ( DEBUG_ETH_COM )
        rna_printk ( KERN_DEBUG, "ep=0x%p\n", ep );

    if ( !ep )
        return -1;

    if ( ep->rdma_pool ) {
       for (i = 0; i < ep->num_rdma; i++) {
           be = ep->rdma_pool[i];
           kfree(be);
           ep->rdma_pool[i] = NULL;
       }
       kfree (ep->rdma_pool);
    }

    atomic_set(&ep->rdma_avail, 0);
    ep->rdma_mem = ep->rdma_pool = NULL;

    return 0;
}


int transport_alloc_buf_pool_elem(void **elem, unsigned long arg, int idx) 
{
	int ret = 0;
	struct buf_entry* buf = (typeof(buf)) *elem;
	struct buf_pool_ctx *ctx = (typeof(ctx)) arg;
	void *mem = kzalloc (ctx->buf_size, RNA_NOIO);
 
	if (mem) {
		buf->mem = mem;
		buf->env = NULL; /* We allocate the envelope on the stack. */
		atomic_set(&buf->buf_use_state, BUF_USE_FREE);
		INIT_LIST_HEAD(&buf->queued_send_entry);
		buf->ep = ctx->ep;
		buf->pool = ctx->pool;
	} else {
		ret = -ENOMEM;
	}

	return ret;
}

int transport_free_buf_pool_elem(void **elem, unsigned long arg, int idx)
{
	struct buf_entry* buf = (typeof(buf)) *elem;
	kfree(buf->mem);
	buf->mem = NULL;
	
	return 0;
}

int com_wait_send_avail ( struct  com_ep *ep )
{
    int ret = 0;

    if ( DEBUG_ETH_COM )
        rna_printk ( KERN_DEBUG, "ep=0x%p\n", ep );

    // wait for enough space to be available to write to the socket
    rna_printk ( KERN_DEBUG, "posted %d \n", atomic_read ( &ep->send_posted ) );
    ret = wait_event_interruptible_timeout ( ep->com_wait,
            ( ( atomic_read ( &ep->com_is_writeable ) > 0 ) ||
              ( atomic_read ( &ep->ep_state ) != EP_CONNECTED ) ),
            msecs_to_jiffies ( 10 ) );

    if ( ret ) {
        rna_printk ( KERN_ERR, "wait for send got interrupted\n" );
        goto err;
    }

    if ( atomic_read ( &ep->ep_state ) != EP_CONNECTED )
        goto err;

    return 0;
err:
    return -1;
}

int com_get_send_buf (struct com_ep *ep, struct buf_entry **buf, int poll_ep)
{
    int i;
    int state;
    int ret = 0;
    int avail;
    static const unsigned int timeout = 100; // msec

    *buf = NULL;

    if (DEBUG_ETH_COM)
        rna_printk (KERN_DEBUG, "ep=0x%p, buf=0x%p\n", ep, buf);

restart:
    if ((state = atomic_read (&ep->ep_state)) != EP_CONNECTED) {
        rna_trace("ep[%p] not connected state %d\n",
                  ep, state);
        if (state == EP_CONNECT_PENDING) {
            ret = -ENOTCONN;
        } else {
            ret = -1;
        }
    } else {
        /* If a blocking call then wait for buf pool to be available */
        if (poll_ep && !atomic_read(&ep->send_pool.num_avail)) {
            wait_event_interruptible_timeout(ep->buf_pool_wait_obj,
                                         (0 < atomic_read(&ep->send_pool.num_avail)),
                                         msecs_to_jiffies(timeout));
            /* Check state of ep again before continuing through */
            goto restart;
        }
        ret = com_get_send_buf_from_pool(ep, buf, &ep->send_pool);
        avail = atomic_read(&ep->send_pool.num_avail);
        if (avail < atomic_read(&ep->min_send_avail)) {
            atomic_set(&ep->min_send_avail, avail);
        }
    }

    return ret;;
}

int com_put_send_buf(struct com_ep *ep, struct buf_entry *buf)
{
    int ret = 0;

    if (atomic_cmpxchg(&buf->buf_use_state, BUF_USE_ALLOCATED, BUF_USE_FREE)
                       == BUF_USE_ALLOCATED) {
        /* wake up anyone waiting for a send buf */
        atomic_inc(&buf->pool->num_avail);
        wake_up( &ep->buf_pool_wait_obj );
    } else {
        rna_printk(KERN_ERR, "%s buffer already completed, buf [%p]\n",
                   pool_name(ep, buf->pool), buf);
        dump_stack();
        ret = -EINVAL;
    }	
    return ret;
}

int com_get_recv_buf ( struct com_ep *ep, struct buf_entry **buf)
{
    int i;
    int state;
	
    if (DEBUG_ETH_COM) {
        rna_printk (KERN_DEBUG, "ep=0x%p, buf=0x%p\n", ep, buf);
    }
	
    *buf = NULL;
    return com_get_send_buf_from_pool(ep, buf, &ep->recv_pool);
}

void
com_put_rdma_buf( struct com_ep *ep, struct buf_entry *buf)
{
	if(buf->zcopy_dma){
		buf->mem = NULL;
	}

    com_mark_rdma_buf_free(buf);

	atomic_inc(&ep->rdma_avail);
	/* Only wake up one waiter to avoid alot of unnecessary attempts to get a buffer */
	wake_up(&ep->rdma_wait); 
	
}

int com_put_recv_buf( struct com_ep *ep,struct buf_entry *buf )
{
	int num_avail;
    int ret = 0;

    if (atomic_cmpxchg(&buf->buf_use_state, BUF_USE_ALLOCATED, BUF_USE_FREE)
                       == BUF_USE_ALLOCATED) {
        num_avail = atomic_inc_return( &ep->recv_pool.num_avail );
        inc_unacked_recvs(ep);

        /* Due to this case, COM_COMP_MODE_WORKQ_CB 
         * mode may sometimes use recv_wq. */
        if(num_avail == 1){
            com_queue_recv_work(ep);
        }
    } else {
        rna_printk(KERN_ERR, "%s buffer already completed, buf [%p]\n",
                   pool_name(ep, buf->pool), buf);
        dump_stack();
        ret = -EINVAL;
    }        
	return ret;
}

int com_reg_single ( struct com_ep *ep,
                     struct rdma_buf *rdma_buf,
                     enum dma_data_direction direction )
{
    if ( DEBUG_ETH_COM )
        rna_printk ( KERN_DEBUG, "ep=0x%p, rdma_buf=0x%p, direction=%d\n",
                     ep, rdma_buf, direction );

    rdma_buf->ib_device = NULL;
    rdma_buf->mr = NULL;
    rdma_buf->direction = direction;

    return 0;
}

void com_dereg_single( struct com_ep *ep,struct rdma_buf *rdma_buf )
{
    if ( DEBUG_ETH_COM )
        rna_printk ( KERN_DEBUG, "rdma_buf=0x%p\n", rdma_buf );
}

int com_isreg( struct com_ep *ep,struct rdma_buf *rdma_buf )
{
	return FALSE;
}

void
com_rdma_send_write(struct com_ep *ep, struct buf_entry *buf, int buf_len)
{
    struct rna_com_envelope *env = &buf->tl_env;
    struct com_rdma_msg *rdma_msg = &buf->tl_rdma_msg;
    int len, nents;
    int ret;
    struct kvec *iov = buf->tl_iov;

    nents = 0;
    len   = 0;

    com_envelope_init(env, ep->user_type,buf_len + sizeof(*rdma_msg), 
                      ENV_TYPE_RDMA, 0,
                      com_get_reset_unacked_recvs(ep));

    *rdma_msg = (typeof(*rdma_msg)) {
        .hdr.flags = 0,
        .msg_type = RDMA_MSG_TYPE_WRITE,
        .hdr.cookie = (uint64_t)buf,
        .u.com_rdma_req = {
            .addr = buf->rem_addr,
            .rkey = buf->rkey,
            .len = buf_len
        }
    };

    if(buf->op_flags & RDMA_OP_SERVER_ACK){
        rdma_msg->hdr.flags |= RDMA_MSG_FLAG_RESP_REQ;
    }
	
    rna_trace("com_rdma_send ep[%p] cookie[%"PRIx64"] op_flags[%x] flags[%x]\n",
              ep, rdma_msg->hdr.cookie, buf->op_flags, rdma_msg->hdr.flags);

    iov[0].iov_base = env;
    iov[0].iov_len  = sizeof( struct rna_com_envelope );
    iov[1].iov_base = rdma_msg;
    iov[1].iov_len  = sizeof( struct com_rdma_msg );

    if (buf->op_type == RDMA_WRITE) {
        iov[2].iov_base = buf->mem;
        iov[2].iov_len  = buf_len;
        len = iov[0].iov_len + iov[1].iov_len + iov[2].iov_len;
        nents = 3;
    } else if (buf->op_type == RDMA_WRITE_SGL) {
        len = kvec_append_sgl(&iov[0], 2, &buf->sgl[0], buf->sgl_nents);
        rna_trace("%d = kvec_append_sgl(%p, %d, %p, %d);\n",len,&iov[0], 2, &buf->sgl[0], buf->sgl_nents);
        nents = 2 + buf->sgl_nents;
        rna_trace("nents = %d\n",nents);
    } else {
        BUG();
    }

    mutex_lock( &ep->send_mutex );

    env->tid = atomic_inc_return(&ep->trans_id) - 1;

    ret = rna_sendmsg(ep, &iov[0], nents, len );
		
    rna_trace("ep[%p] Sent %d bytes\n",ep,(int)ret);

    mutex_unlock( &ep->send_mutex );

    // signal completion of write
    ret = ret > 0 ? 0 : -1;

	/*
     * If we're not waiting on the server to ACK (or it will never ACK due to
     * failure here) then we call the completion callback and repost the buffer
     */
    if((-1 == ret) || !(buf->op_flags & RDMA_OP_SERVER_ACK)){
        com_mark_rdma_buf_done(ep, buf, ret);
    } else {
        com_mark_rdma_buf_inflight(ep, buf);
    }
}

/* note: context is not used */
static int eth_send_rdma_read( struct com_ep *ep,struct buf_entry *buf,
                               rna_addr_t remote_addr,rna_rkey_t remote_rkey,
                               int size,void *context )
{
    struct scatterlist sgl;
    struct com_rdma_msg msg;
    uint64_t baddr,daddr;
    ENTER;
	
	memset(&msg,0,sizeof(msg));

    msg.msg_type = RDMA_MSG_TYPE_READ;
	msg.hdr.cookie = (uint64_t)buf;

    msg.u.com_rdma_req.addr = remote_addr;
    msg.u.com_rdma_req.rkey = remote_rkey;
	msg.u.com_rdma_req.len = size;

    bswap_com_rdma_msg( &msg );

    daddr      = (uint64_t)&msg;
    baddr      = daddr & PAGE_MASK;
    rna_sg_init_table(&sgl, 1);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
    sgl.page   = virt_to_page( &msg );
#else
    sgl.page_link = 0;
    sg_assign_page(&sgl, virt_to_page(&msg));
#endif
    sgl.offset = (unsigned int)(daddr - baddr);
    sgl.length = sizeof( struct com_rdma_msg );

    ret = _com_send_internal( ep, &sgl, 1, ENV_TYPE_RDMA );

    EXIT;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
void com_rdma_send( void *arg)
#else
void com_rdma_send( struct work_struct *arg)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
    struct work_struct *w = (struct work_struct *)arg;
    struct et_work *etw = w->data;
#else
    struct et_work *etw = container_of(arg, struct et_work, w);
#endif
    struct com_ep *ep = etw->ep;

    /*
     * etw is embedded in 'buf', which may be freed in these calls, so
     * don't access etw afterwards.
     */
    if (RDMA_WRITE_SGL == etw->u.buf->op_type) {
	    com_rdma_send_write(ep, etw->u.buf, etw->size);
    } else {
        int ret;

        ret = eth_send_rdma_read(ep,
                                 etw->u.buf,
                                 etw->u.buf->rem_addr,
                                 etw->u.buf->rkey,
                                 etw->size,
                                 etw->u.buf->context);

        /*
         * XXX
         * Since this is in a work queue context, if the eth_send_rdma_read()
         * call fails, we can not propogate that failure up the call stack
         * to the originator of this work item.  So we must do some additional
         * cleanup here
         *
         * Since the eth_send_rdma_read() call has failed, we can assert
         * that the completion callback for this request will never be invoked
         * through that code path.  So we can safely invoke it here without
         * risk that callback being redundant.
         *
         * We are really relying on there always BEING a callback handler.
         *
         * If the above call failed, then buf will not have been freed,
         * and etw will still be valid.
         */
        if (ret < 0) {
            com_mark_rdma_buf_done(ep, etw->u.buf, -1);
        } else {
            com_mark_rdma_buf_inflight(ep, etw->u.buf);
        }
    }

    com_release_ep(ep);
}

/**
 * This is called by rna_cache_read in rna_client.c to get a hunk of data from a cache server.
 *
 * @param ep - the com endpoint
 * @param rdma_buf - the buffer to fill in
 * @param remote_addr - the remote address
 * @param buf - not sure what this is??
 * @param remote_rkey - the remote key of the data we want
 * @param size - how much data we want
 * @param context - not sure what this is for - currently it's always the same as rdma_buf
 * @param signaled - no idea what this is - it's always set to 1
 * @param fence - this is how you keep the cows from wandering off
 * @return 0 on success, non-zero on failure
 */
int
com_rdma_read(struct com_ep *ep,
              struct buf_entry *rdma_buf,
              rna_addr_t remote_addr,
              void *buf,
              rna_rkey_t remote_rkey,
              int size,
              void *context,
              char signaled,
              uint32_t flags )
{
    ENTER;

	rna_trace("Posted RDMA Buf[%p] mem[%p]\n",rdma_buf, buf);
	
    if ( DEBUG_ETH_COM )
        rna_printk( KERN_DEBUG, "ep=0x%p, rdma_buf=0x%p, remote_addr=%"PRId64":%"PRId64", buf=0x%p, "
                    "remote_rkey=%"PRIu64", size=%d, context=0x%p, signaled=%d, flags=%x\n",
                     ep, rdma_buf, remote_addr.device_id.data, remote_addr.base_addr, buf, remote_rkey, size, context,
                     (int)signaled,flags );

    if ( atomic_read ( &ep->ep_state ) != EP_CONNECTED ) {
        GOTO( out,-1 );
    }

    /*
     * Wait up to 1ms for work envelopes to free up - not because *we* need one, but because
     * this is one of the only places we can throttle things - we can't wait in the interrupt handler
     * side of things.  This is woken up by process_eth_rdma_read_response.  We wait for less than
     * 75% to be busy so there is room for com events as well as rdma read and write events.
     * TODO: This wait may no longer be needed since we now just increment a counter rather than
     *       adding events indefinitely to the work queue - figure that out.
     */

	 if ( size == 0 ) {
        printk ( "com_rdma_read: ERROR read size 0; dst %u.%u.%u.%u: rdma_buf %p, rem_addr 0x%"PRIx64":%"PRIx64","
                 " rkey 0x%"PRIx64", rdma_length %d\n",
                 NIPQUAD ( ep->dst_in.sin_addr.s_addr ),
                 rdma_buf, rdma_buf->rem_addr.device_id.data, rdma_buf->rem_addr.base_addr, rdma_buf->rkey,
                 rdma_buf->length );
        GOTO( out,-1 );
    }

	if(buf){
		rdma_buf->zcopy_dma = 1;	
		rdma_buf->mem = buf;
		rdma_buf->length = size;
	}else{
		rdma_buf->zcopy_dma = 0;
	}
	
    rdma_buf->op_type = RDMA_READ;
    rdma_buf->rem_addr = remote_addr;
    rdma_buf->rkey = remote_rkey;
    rdma_buf->dma_size = size;
    rdma_buf->tid = atomic_inc_return ( &next_tid );

    /* Since com_rdma_read() never appeared in any of the deadlock report
     * stacks (see MVP-8405), and in fact this appears to NOT used in the rb
     * kernel driver, we won't submit this to a work queue.
     *
     * But, since we removed the eth_wait_on_credits() call
     * from eth_send_rdma_read(), we insert here.
     */
	eth_wait_on_credits(size);

    ret = eth_send_rdma_read( ep,rdma_buf,remote_addr,remote_rkey,size,context );
    if ( ret <= 0 ) {
        rna_printk ( KERN_ERR, "failed to post rdma read: %d\n", ret );
    } else {
		ret = 0;
        atomic_inc ( &ep->rdma_posted );
    }

out:
    EXIT;
}

int com_rdma_write( struct com_ep *ep,
                    struct buf_entry *rdma_buf,
                    rna_addr_t remote_addr,
                    void *buf,
                    rna_rkey_t remote_rkey,
                    int size,
                    void *context,
                    char signaled,
					uint32_t flags )
{
    ENTER;
	
	rna_trace("com_rdma_write ep[%p] flags[%x]\n",ep ,flags);

    rdma_buf->zcopy_dma = 0;
    rdma_buf->op_type   = RDMA_WRITE;
	rdma_buf->op_flags  = flags;
    rdma_buf->rem_addr  = remote_addr;
    rdma_buf->rkey      = remote_rkey;
    rdma_buf->dma_size  = size;
    rdma_buf->tid       = atomic_inc_return( &next_tid );
    rdma_buf->mem       = buf;

    RNA_INIT_WORK(&rdma_buf->etw.w, com_rdma_send, &rdma_buf->etw);
    rdma_buf->etw.ep  = ep;
    rdma_buf->etw.u.buf = rdma_buf;
    rdma_buf->etw.size  = size;
	
	com_inc_ref_ep(ep);
	
    rna_queue_work( ep->send_wq,&rdma_buf->etw.w );

out:
    EXIT;
}
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
void com_run_completion( void *arg)
#else
void com_run_completion( struct work_struct *arg)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
    struct work_struct *w = (struct work_struct *)arg;
    struct et_work *etw = w->data;
#else
    struct et_work *etw = container_of(arg, struct et_work, w);
#endif
	struct com_ep *ep = etw->ep;
    boolean etw_is_malloced = FALSE;

	BUG_ON(ep == NULL);
	
	rna_trace("Running completion EP[%p] type[%d]\n",ep,etw->type);

	switch(etw->type){
		case RDMA_READ:
		case RDMA_READ_SGL:
		case RDMA_WRITE:
		case RDMA_WRITE_SGL:
			rna_trace("RDMA completion EP[%p] status[%d]\n",ep,etw->status);
			if (etw->status != CB_RESP_INVALID_RKEY) {
				com_complete_rdma_op(ep, etw->u.buf, etw->status);
			} else {
				//Error state. Call disconnect
				rna_printk(KERN_ERR,"ep[%p] Invalid Rkey response message\n",ep);
				com_disconnect(ep);
			}
			break;

		case POST_RECV:
			rna_trace("Recv completion EP[%p]\n",ep);
			if (NULL != ep->com_attr.recv_cmp_cb){
				ep->com_attr.recv_cmp_cb( ep, ep->context, etw->u.buf->mem, etw->u.buf->length, etw->status);
			}
			com_put_recv_buf(ep, etw->u.buf);
			break;
		case POST_SEND:
			/* Not currently used */
			break;
		case TCP_HS:
			com_socket_handshake_complete( ep, &etw->u.csd, etw->msg_tid );
            etw_is_malloced = TRUE;
			break;
	}
	
	/* TODO: Revisit this. We may need to convert all the spin locks to the _bh variety. */
	//com_release_ep(ep);	

	dec_callback_queued(ep);

    if (etw_is_malloced) {
        /*
         * etw is kmalloc'ed rather than being a buf_entry embedded
         * structure, so need to free it.
         */
        kfree(etw);
    }

	return;	
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
void com_run_recv( void *arg)
#else
void com_run_recv( struct work_struct *arg)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
    struct work_struct *w = (struct work_struct *)arg;
    struct et_work *etw = w->data;
#else
    struct et_work *etw = container_of(arg, struct et_work, w);
#endif
	struct com_ep *ep = etw->ep;
	int bytes_read;
	
	BUG_ON(ep == NULL);
	
	rna_trace("Running recv EP[%p]\n",ep);
	/* TODO: Create a counter to track how many times this runs. This could indicate
	         that the recv buffer size is too small */
	bytes_read = rna_com_socket_read(ep);
	com_sock_run_completion_cbs(ep);
	
	rna_trace("Read[%d] bytes for EP[%p]\n",bytes_read,ep);
		
	com_release_ep(ep);	
	kfree(etw);
	
	return;	
}	

int com_queue_completion( struct com_ep *ep,
						  int type,
						  struct buf_entry *buf,
						  int status)
{
    struct et_work *etw;
	
	BUG_ON(NULL == ep);
	
    RNA_INIT_WORK(&buf->etw.w, com_run_completion, &buf->etw);
	
    buf->etw.ep = ep;
	buf->etw.type = type;
	buf->etw.u.buf = buf;
	buf->etw.status = status;
					
	/* TODO: Revisit this. We may need to convert all the spin locks to the _bh variety. */
    //com_inc_ref_ep(ep);
					
    inc_callback_queued (ep);
    rna_queue_work(comp_wq,&buf->etw.w);

    return 0;
}

int com_queue_recv_work( struct com_ep *ep)
{
    struct et_work *etw;
    ENTER;
	
	BUG_ON(NULL == ep);
	
    if( (etw = rna_kmalloc(etw, GFP_ATOMIC )) == NULL )
        GOTO( out,-ENOMEM );
	
    RNA_INIT_WORK(&etw->w, com_run_recv, etw);
	
	com_inc_ref_ep(ep);
	
	etw->ep = ep;
	
    rna_queue_work( recv_wq, &etw->w );
	
out:
    EXIT;
}


int com_queue_csd( struct com_ep *ep, struct com_conx_reply *csd, uint64_t tid)
{
    struct et_work *etw;
    ENTER;
	
	BUG_ON(NULL == ep);
	
    if( (etw = rna_kmalloc(etw, GFP_ATOMIC )) == NULL )
        GOTO( out,-ENOMEM );
	
    RNA_INIT_WORK(&etw->w, com_run_completion, etw);
	
	//com_inc_ref_ep(ep);
	
	etw->ep = ep;
	etw->type = TCP_HS;
	memcpy(&etw->u.csd,csd,sizeof(*csd));
	etw->msg_tid = tid;

    inc_callback_queued (ep);
    rna_queue_work( comp_wq, &etw->w );
	
out:
    EXIT;	
	
}


int
com_rdma_sgl(struct com_ep *ep, void *ctxt, struct buf_entry *buf,
             rna_addr_t raddr, struct scatterlist *sgl, int nents,
             rna_rkey_t rkey, int write, uint32_t flags)
{
    int use_state;
	int ret=0;
	int len=0;
	int i;

	BUG_ON(NULL == buf);

	if (unlikely(nents > RNA_COM_MAX_SGL)) {
		rna_printk(KERN_ERR, "sgl list too long\n");
		ret = -EINVAL;
	} else {
		buf->zcopy_dma = 1;

		for (i=0; i<nents; i++) {
			len += sgl[i].length;
			buf->sgl[i] = sgl[i];
			rna_trace("i[%d] len[%d] sgl[%p]\n",i,len,&sgl[i]);
		}

		buf->sgl_nents = nents;
		buf->length    = len;
		buf->rem_addr  = raddr;
		buf->rkey      = rkey;
		buf->dma_size  = len;
		buf->op_flags = flags;
		buf->tid = atomic_inc_return (&next_tid);
		buf->context = (void *) (unsigned long)ctxt;

        RNA_INIT_WORK(&buf->etw.w, com_rdma_send, &buf->etw);

        buf->etw.ep  = ep;
        buf->etw.u.buf = buf;
        buf->etw.size  = len;

		com_inc_ref_ep(ep);

        if (write) {
            buf->op_type = RDMA_WRITE_SGL;
        } else {
            buf->op_type = RDMA_READ_SGL;
	        eth_wait_on_credits(len);
        }

		rna_queue_work(ep->send_wq, &buf->etw.w);
    }
	return ret;
}

int com_wait_rdma_avail( struct  com_ep *ep )
{
    int ret = 0;

    // wait for enough space to be available to write to the socket
    rna_trace ( "PRE: ep[%p] avail %d \n",ep, atomic_read ( &ep->rdma_avail ) );
    ret = wait_event_interruptible_timeout ( ep->rdma_wait,
            ( atomic_read ( &ep->rdma_avail ) > 0 ),
            msecs_to_jiffies ( RNA_COM_TCP_RDMA_BUF_WAIT ) );
    if ( ret <= 0 ) {
		return -1;
    }
	rna_trace ( "POST: ret[%d] ep[%p] avail %d \n",ret, ep, atomic_read ( &ep->rdma_avail ) );

    return 0;
err:
    return -1;
}

void com_set_socket_options(struct com_ep *ep)
{
	int optval = 0;

	if((tcp_keepcnt > 0) && (tcp_keepidle > 0) && (tcp_keepintvl > 0)){

		/* Enable the keep alive */
		optval = RNA_SOCK_OPT_SO_KEEPALIVE;	
		kernel_setsockopt(ep->com_sock.com, SOL_SOCKET, SO_KEEPALIVE, (char*)&optval, sizeof(optval));
	
		/* TODO: Make this configurable. These are tight because we need to detect failed connections
	         quickly */
		/* TCP_KEEPCNT: overrides tcp_keepalive_probes */
		optval = tcp_keepcnt;	/* Number of missed probes before disconnecting */
		kernel_setsockopt(ep->com_sock.com, IPPROTO_TCP, TCP_KEEPCNT, (char*)&optval, sizeof(optval));
	
		/* TCP_KEEPIDLE: overrides tcp_keepalive_time */
		optval = tcp_keepidle; /* Seconds to wait on an idle socket before sending the probe */	
		kernel_setsockopt(ep->com_sock.com, IPPROTO_TCP, TCP_KEEPIDLE, (char*)&optval, sizeof(optval));

		/* TCP_KEEPINTVL: overrides tcp_keepalive_intvl */
		optval = tcp_keepintvl; /* Seconds between probes */
		kernel_setsockopt(ep->com_sock.com, IPPROTO_TCP, TCP_KEEPINTVL, (char*)&optval, sizeof(optval));

	}else{
		rna_trace("Keepalives disabled\n");
	}
	
	/* Disable the Nagle (TCP No Delay) algorithm */
	if (RNA_SOCK_OPT_TCP_NODELAY == tcp_nodelay) {
		optval = RNA_SOCK_OPT_TCP_NODELAY;
		kernel_setsockopt(ep->com_sock.com, IPPROTO_TCP, TCP_NODELAY, (char *)&optval, sizeof(optval) );
	}

	/* Maximum time to block when calling sendmsg */
	optval = RNA_SOCK_OPT_SO_SNDTIMEO;
	kernel_setsockopt(ep->com_sock.com, SOL_SOCKET, SO_SNDTIMEO, (char *)&optval, sizeof(optval) );
	
	optval = 0;
	kernel_setsockopt(ep->com_sock.com, SOL_SOCKET, SO_DONTROUTE, (char *)&optval, sizeof(optval) );

  /* Setting a limit on the sendbuf size can be used to prevent allocation 
	 * errors in __alloc_skb, but it reduces throughput as well. */
	if(sndbuf_kb) {
		optval = sndbuf_kb * 1024;
		kernel_setsockopt(ep->com_sock.com, SOL_SOCKET, SO_SNDBUF, (char*)&optval, sizeof(optval));
	}

	return;
}

int transport_alloc_ep(struct com_ep *ep, int bounce_buffer_bytes,
                       int bb_segment_bytes)
{
    struct sock *sk;
    struct rna_transport_handle *com = ep->transport_handle;
    ENTER;

    /* bounce_buffer_bytes and bb_segment_bytes are not used by TCP */

    BUG_ON(ep->transport_ops->transport_type != IP_TCP);
    if (!com->initialized) {
        GOTO(out, -EINVAL);
    }

    ep->callback_state = CB_INIT;
    ep->max_sge       = RNA_COM_MAX_SGL;

    atomic_set( &ep->ep_state,EP_INIT );
    atomic_set( &ep->ref_count,1 );

    rwlock_init(&ep->ep_state_lock);
    spin_lock_init(&ep->recv_serialization_lock);
    mutex_init( &ep->recv_mutex );
    mutex_init( &ep->send_mutex );

    init_waitqueue_head( &ep->conn_wait );
    init_waitqueue_head( &ep->rdma_wait );
    init_waitqueue_head( &ep->com_wait );
    init_waitqueue_head(&ep->buf_pool_wait_obj);

    ep->send_wq = create_singlethread_workqueue("fldc_com");
    if (!ep->send_wq){
        rna_printk(KERN_ERR, "Failed to allocate ep send_wq\n");
        GOTO( err,-ENOMEM );
    }

    if( (ret = sock_create_kern( PF_INET,SOCK_STREAM,IPPROTO_TCP,&ep->com_sock.com )) )
        GOTO( err,-ENOMEM );

    // back-link to the ep
    sk = ep->com_sock.com->sk;
    sk->sk_user_data = ep;

    /* Use GFP_ATOMIC to prevent block device from hanging when we run out
     * of memory.  GFP_ATOMIC implies GFP_NOFS.  __GFP_NOWARN may also be
     * necessary, but we'll leave it off unless we know we need it. */
    ep->com_sock.com->sk->sk_allocation = GFP_ATOMIC;
	
    com_set_socket_options(ep);

    ret = init_ep(ep);

    if (ret) {
        rna_printk(KERN_ERR, "unable to initialize ep, bailing out\n");
        GOTO (err1, -ENOMEM);
    }
	
    write_lock_bh( &sk->sk_callback_lock );

    /* Store off the old one routines to call in addition to our own. */
    ep->com_sock.com_old_state_change = sk->sk_state_change;
    sk->sk_state_change = com_state_change;

    ep->com_sock.com_old_data_ready = sk->sk_data_ready;
    sk->sk_data_ready = com_sock_data_ready;

    write_unlock_bh( &sk->sk_callback_lock );

    atomic_set (&ep->rdma_is_writeable, 0);
    atomic_set (&ep->com_is_writeable,  0);

    /* Long-held ref is dropped in et_disconnect.  Otherwise, we
     * hold a reference whenever something is queued that could 
     * invoke a callback.  (Affects users of comp_wq and recv_wq.) */
    atomic_set (&ep->callback_queued,   1);

    atomic_inc(&com->connection_count);

    mutex_lock( &com->ep_lst_lock );
    list_add_tail( &ep->entries,&com->ep_lst_head );
    mutex_unlock( &com->ep_lst_lock );

    ep_create_proc(ep, NULL);

out:
    EXIT;
err1:
    sock_release( ep->com_sock.com );
err:
    goto out;
}

/* Note: The caller must own the com_handle->ep_lst_lock */
int com_validate_ep ( struct rna_transport_handle* com_handle, struct com_ep *ep )
{
    struct com_ep *ent;

    list_for_each_entry ( ent, &com_handle->ep_lst_head, entries ) {
		if(ep == ent){
			return TRUE;
		}
    }
	
    return FALSE;
}

int transport_find_ep ( struct rna_transport_handle* com_handle, struct sockaddr *dst_addr, struct com_ep **ep, uint8_t sync_flag )
{
    struct com_ep *ent;
    unsigned long flags;
	int ep_state;
	
    *ep = NULL;	
    mutex_lock ( &com_handle->ep_lst_lock );


    list_for_each_entry ( ent, &com_handle->ep_lst_head, entries ) {
        /* explicitly check for s_addr and port */

        rna_trace("dst_addr = %d, ent->dst_addr = %d, dst_addr->sin_port = %d, ent->dst_addr->sin_port = %d\n",
            ((struct sockaddr_in*)dst_addr)->sin_addr.s_addr,
            ((struct sockaddr_in*)ent->dst_addr)->sin_addr.s_addr,
            ntohs(((struct sockaddr_in*)ent->dst_addr)->sin_port),
            ((struct sockaddr_in*)dst_addr)->sin_port); 

        if ( ( ( ( struct sockaddr_in* ) ent->dst_addr )->sin_addr.s_addr ==
                ( ( struct sockaddr_in* ) dst_addr )->sin_addr.s_addr ) &&
                ( ntohs ( ( ( struct sockaddr_in* ) ent->dst_addr )->sin_port ) ==
                  ( ( struct sockaddr_in* ) dst_addr )->sin_port ) ) {
			
			ep_state = atomic_read(&ent->ep_state);
			if((ep_state == EP_CONNECTED) || (ep_state == EP_CONNECT_PENDING)){
				if ( com_inc_ref_ep ( ent ) == 0 ) {
					ep_state = atomic_read(&ent->ep_state);
					
					if((ep_state != EP_CONNECTED) && (ep_state != EP_CONNECT_PENDING)){
						/* Double check the state to avoid a tight race here since we don't hold 
						   a long standing reference on the ep while its in the list. We decerement
						   the reference directly to avoid a BUG_ON(). This is safe here *only* because we
						   hold the ep_lst_lock and as such the ep cannot be free'd while we own the lock. */
						rna_printk(KERN_WARNING,"Detected and avoided MVP-3972. EP[%p]\n",ent); 
						atomic_dec(&ent->ref_count);
						continue;
					}
					*ep = ent;
					break;
				}
			}
        }
    }
    mutex_unlock ( &com_handle->ep_lst_lock );

    if ( *ep )
        return 0;

    return -1;
}

int com_free_ep(struct rna_transport_handle *transport_handle,
                struct com_ep               *ep)
{
    ENTER;

    mutex_lock(&transport_handle->ep_lst_lock);

    if(!com_validate_ep(transport_handle, ep)) {
        ret = -EINVAL;
        /* Note: This is for MVP-4411 to detect a double free.
         * The root cause is still unknown but this resolves the crash */
        rna_printk(KERN_ERR, "Failed to validate TCP ep [%p] com_handle [%p] "
                   "perhaps it is already deleted? (Please file a bug.)\n",
                   ep,
                   transport_handle);
        print_ep(ep);
        mutex_unlock(&transport_handle->ep_lst_lock);
    } else {
        list_del_init(&ep->entries);
        ret = 0;
        mutex_unlock(&transport_handle->ep_lst_lock);

        if (ep->com_attr.destructor_cmp_cb) {
            ep->com_attr.destructor_cmp_cb (ep, ep->context);
        }
        ep->context = NULL;
        ep_delete_proc(ep);

        ret = free_ep(ep);

        if(atomic_dec_and_test(&transport_handle->connection_count)) {
            wake_up_all (&transport_handle->all_disconnected_wait);
        }
    }

    EXIT;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
void com_do_free_ep( void *arg)
#else
void com_do_free_ep( struct work_struct *arg)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
    struct work_struct *w = (struct work_struct *)arg;
    struct et_work *etw = w->data;
#else
    struct et_work *etw = container_of(arg, struct et_work, w);
#endif
	
    ENTER;
	
	com_free_ep(etw->transport_handle, etw->ep);
	
	kfree( etw );
	
    EXITV;
}

int com_schedule_free_ep( struct com_ep *ep )
{
	struct et_work *etw;
	
	if( (etw = kmalloc( sizeof( struct et_work ),GFP_ATOMIC )) != NULL ) {
		etw->ep = ep;
		etw->transport_handle = ep->transport_handle;
		RNA_INIT_WORK(&etw->w, com_do_free_ep, etw);
		/* rna_queue_work returns 1 on success */
		return !rna_queue_work( conn_wq,&etw->w );	
	}
	return -ENOMEM;
}

/** 
 * We use the MAC address as a GUID.  This might not work if we're using
 * some kind of non-ethernet device that doesn't use MAC addresses, but
 * that's unlikely.  We could use the IP address, but if several clients
 * are connected via NAT, they might have the same address.
 * We could also use the CPUID, but it might not be available on all 
 * architectures.
 *
 * The GUID is used by the block device as a unique key to prepend to 
 * block numbers.  If the GUID isn't truly unique, we may cause unintential
 * block sharing.
 *
 * TODO: we may want to cache this value, as dev_get_by_index takes a
 * spinlock. */

uint64_t com_get_guid (struct com_ep* ep)
{
	uint64_t guid = 0;
	struct net_device* dev;
	int count, i;
	unsigned char* mac;

	BUG_ON(NULL == ep->com_sock.com);

	/* find the MAC by looking up the device associated with 
	 * the socket, then read its mac into guid. */

// XXX -  Don't know when this changed
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
	dev = dev_get_by_index(ep->com_sock.com->sk->sk_bound_dev_if);
#else
	dev = dev_get_by_index(&init_net, ep->com_sock.com->sk->sk_bound_dev_if);
#endif

	if (NULL == dev) {
		rna_printk(KERN_ERR, "Can't find device associated with EP's socket.\n");
	} else {
		mac = &dev->dev_addr[0];
		count = min(8, MAX_ADDR_LEN);

		for (i=0; i<count; i++)
			guid += (1ULL << (i*8)) * mac[i];
	}

	if (0 == guid)
		rna_printk(KERN_ERR, "Unable to read mac address associated with EP, "
		           "using 0 as GUID. (May cause unintentional sharing.)\n");

	return guid;
}

void queue_disconnect_work( struct com_ep *ep )
{
	struct et_work *etw;
	
	ENTER;
	
	if( (etw = rna_kmalloc(etw, GFP_ATOMIC )) != NULL ) {
		etw->ep = ep;
		RNA_INIT_WORK(&etw->w, et_call_disconnect, etw);
		
		com_inc_ref_ep(ep);
		
		rna_queue_work( conn_wq,&etw->w );
	} else {
		rna_printk(KERN_ERR, "No memory to queue disconnect, "
				   "leaking resources. ep=%p\n", ep);
	}

    EXITV;
}


void com_dereg_sgl(struct com_ep *ep, struct scatterlist *sgl,
                   int nents, enum dma_data_direction dir)
{
    return;
}

/* We don't have to do anything, but we're expected to return
 * the number of entries sucessfully registered. */
int com_reg_sgl(struct com_ep *ep, struct scatterlist *sgl,
                int nents, enum dma_data_direction dir)
{
     return nents;
}

/* Since com_reg_sgl() does nothing for this transport, there is never
 * a mapping error */
int com_mapping_error(struct com_ep *ep, struct scatterlist *sgl)
{
    return 0;
}

int transport_get_device_attributes(struct rna_transport_handle *com_handle,
                                    enum com_type type,
                                    struct rna_dev_attr *attr )
{
    int ret = 0;
    BUG_ON(IP_TCP != type);

    attr->max_sge = RNA_COM_MAX_SGL;
    attr->max_wr  = RNA_MAX_TCP_WR; /* What's a sensible number?  Does it matter? */
    
    return ret;
}

/* This is called by the real module init function in 
 * rna_com_transport_module.c.  We currently share our
 * workqueues amongst all com instances rather than
 * allocate them separately. */
int transport_module_init (void)
{
    int ret = 0;

    if (0 != sndbuf_kb) {
        printk( "sndbuf_kb=%d\n", sndbuf_kb );
    }
	
	spin_lock_init(&eth_com_credit_lock);
    init_waitqueue_head(&eth_com_credit_wait);

    if (RNA_SOCK_OPT_TCP_KEEPCNT != tcp_keepcnt) {
        printk( "tcp_keepcnt=%d\n", tcp_keepcnt );
    }

    if (RNA_SOCK_OPT_TCP_KEEPIDLE != tcp_keepidle) {
        printk( "tcp_keepidle=%d\n", tcp_keepidle );
    }

    if (RNA_SOCK_OPT_TCP_KEEPINTVL != tcp_keepintvl) {
        printk( "tcp_keepintvl=%d\n", tcp_keepintvl );
    }

    if (RNA_SOCK_OPT_TCP_NODELAY != tcp_nodelay) {
        printk( "tcp_nodelay=%d\n", tcp_nodelay );
    }

    if (RNA_ETH_COM_CREDITS_DEFAULT != com_recv_credits){
        printk( "com_recv_credits=%d\n", com_recv_credits );
    }
	eth_com_credits = (com_recv_credits * 4096);

    INIT_LIST_HEAD(&dev_lst_head);
    mutex_init(&dev_lst_lock);

    /* Using GPL-only workqueue constructors. */
    conn_wq = create_singlethread_workqueue("fldc_conn_wq");
    if (!conn_wq)
        goto err1;

    send_wq = create_singlethread_workqueue("fldc_send_wq");
    if (!send_wq)
        goto err2;

    recv_wq = create_workqueue("fldc_recv_wq");
    if (!recv_wq)
        goto err3;
	
    comp_wq = create_workqueue("fldc_comp_wq");
    if (!comp_wq)
        goto err4;

    delayed_send_wq = create_singlethread_workqueue("fldc_dsend_wq");
    if (!delayed_send_wq)
        goto err5;

    return ret;
err5:
    rna_destroy_workqueue( delayed_send_wq );
err4:
    rna_destroy_workqueue( recv_wq );
err3:
    rna_destroy_workqueue( send_wq );
err2:
    rna_destroy_workqueue( conn_wq );
err1:
    rna_printk(KERN_ERR, "Unable to create workqueues\n");
    ret = -ENOMEM;
    return ret;
}

/* This is called by the real module_exit function in
 * rna_com_transport_module.c. */
void transport_module_exit (void)
{
    rna_printk(KERN_ERR, "module exit, destroying workqueues\n");

    rna_flush_workqueue( recv_wq );
    rna_flush_workqueue( delayed_send_wq );
    rna_flush_workqueue( send_wq );
    rna_flush_workqueue( conn_wq );
    rna_flush_workqueue( comp_wq );

    rna_destroy_workqueue( recv_wq );
    rna_destroy_workqueue( send_wq );
    rna_destroy_workqueue( conn_wq );
    rna_destroy_workqueue( comp_wq );
    rna_destroy_workqueue( delayed_send_wq );
	
    recv_wq = NULL;
    send_wq = NULL;
    conn_wq = NULL;
	comp_wq = NULL;

    return;
}

static void
_com_send_wq(struct work_struct *arg)
{
    struct et_work *etw = container_of(arg, struct et_work, w);
    struct com_ep *ep = etw->ep;
    struct buf_entry *buf = etw->u.buf;
    int size = etw->size;
    struct scatterlist sgl[4];
    uint64_t baddr, daddr, eaddr;
    enum env_type env_type = etw->env_type;
    int nsgl;
    ENTER;

    // build a scatter list
    daddr = (uint64_t)buf->mem;
    baddr = daddr & PAGE_MASK;
    eaddr = baddr + (PAGE_SIZE - 1);
    nsgl  = 0;
    rna_sg_init_table(sgl, 4);
    while( nsgl < 4 && size > 0 ) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
        sgl[nsgl].page   = virt_to_page( daddr );
#else
        sgl[nsgl].page_link = 0;
        sg_assign_page(&sgl[nsgl], virt_to_page(daddr));
#endif
        sgl[nsgl].offset = (unsigned int)(daddr - baddr);
        sgl[nsgl].length = (eaddr - daddr) < size ? (eaddr - daddr) + 1 : size;

        daddr += sgl[nsgl].length;
        baddr = daddr & PAGE_MASK;
        eaddr = baddr + (PAGE_SIZE - 1);

        size -= sgl[nsgl].length;
        nsgl++;
    }

    // if the scatter list isn't big enough to describe the entire buffer
    // then we bail
    if( size > 0 ) {
        printk( "%s: residual size %d\n",__FUNCTION__,size );
        GOTO( out,-EINVAL );
    }

    ret = _com_send_internal( ep, &sgl[0], nsgl, env_type);
    if (ret > 0) {
        ret = 0;
    }
    
out:
    /*
     * etw is embedded in 'buf', which may be freed in this call, so
     * don't access etw afterwards.
     */
    send_completion(ep, buf, ret);
    com_release_ep(ep);
    EXITV;
}

int _com_send( struct com_ep *ep, struct buf_entry *buf, 
               int size, enum env_type env_type)
{
    ENTER;

    RNA_INIT_WORK(&buf->etw.w, _com_send_wq, &buf->etw);
    buf->etw.ep = ep;
    buf->etw.u.buf = buf;
    buf->etw.size = size;
    buf->etw.env_type = env_type;
    com_inc_ref_ep(ep);
    /* returns 1 on success */
    ret = !rna_queue_work(ep->send_wq, &buf->etw.w);
    if (ret) {
	    rna_printk(KERN_ERR,
                   "ep [%p] failed to queue send work (ret [%d])\n", ep, ret);
    }

    EXIT;
}

int com_wait_connected( struct com_ep *ep,int timeout )
{
    ENTER;

    if( !com_inc_ref_ep( ep ) ) {
        if( atomic_read( &ep->ep_state ) != EP_CONNECTED ) {
            ret = wait_event_interruptible_timeout( ep->conn_wait,
                                      (atomic_read( &ep->ep_state ) == EP_CONNECTED),
                                      msecs_to_jiffies( timeout ) );
            if( !ret ){
                rna_trace("EP[%p] timed out waiting for connection\n",ep);
            }
        }
        com_release_ep( ep );
        ret = com_connected( ep );
    }

    EXIT;
}

// runs in kthread context
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
void et_com_connect( void *arg)
#else
void et_com_connect( struct work_struct *arg)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
    struct work_struct *w = (struct work_struct *)arg;
    struct et_work *etw = w->data;
#else
    struct et_work *etw = container_of(arg, struct et_work, w);
#endif
    struct com_ep *ep;
    struct sockaddr_in *addr;
	int ret = -1;
	
	ep = etw->ep;
	
	com_inc_ref_ep(ep);
    // the caller passes in the port number in LE order so
    // we have to byte-swap it into BE order before calling
    // into the network stack
    addr = (struct sockaddr_in *)&etw->u.dst_addr;
    addr->sin_port = htons( addr->sin_port );
	addr->sin_family = AF_INET;
	
	ep->dst_in = *addr;
	
	/* Take an additional reference on the ep. A connection failure
	   may instantiate the disconnect_cb. */
	
	/* Initialize the socket states */
	atomic_set(&ep->com_sock.com_sock_state,ETH_CONX_DISC);
	
	/* Guarantee that we only call this once on the ep */
	if(atomic_cmpxchg(&ep->ep_state, EP_INIT,EP_CONNECT_PENDING) == EP_INIT){
		ret = kernel_connect( ep->com_sock.com,&etw->u.dst_addr,sizeof( struct sockaddr_in ),0 );
	} else {
		rna_printk(KERN_ERR, "EP %p not in EP_INIT state, but rather %s\n", 
		           ep, get_ep_state_string(atomic_read(&ep->ep_state)));
	}
	
	if(ret){
		/* On error reset the state and the reference. Caller may choose to retry connection */
		rna_trace("kernel_connect failed for ep %p, ret=%d\n", ep, ret);
		if(atomic_cmpxchg(&ep->ep_state, EP_CONNECT_PENDING, EP_DISCONNECT_PENDING) == EP_CONNECT_PENDING){
			struct et_work *etn = NULL;

			if (printk_ratelimit()) {
				rna_printk(KERN_ERR,
				           "EP[%p] user_type [%d]: Success resetting the EP state to [%s]. "
			                   "Releasing extra reference\n",
				           ep, ep->user_type,
				           get_ep_state_string(atomic_read(&ep->ep_state)));
			}

			/* queue an et_disconnect so we instantiate a disconnect callback. */
			if( (etn = rna_kmalloc(etn, GFP_ATOMIC )) != NULL ) {
				etn->ep = ep;
				RNA_INIT_WORK(&etn->w, et_disconnect, etn);
				rna_queue_work( conn_wq,&etn->w );
			} else {
				rna_printk(KERN_ERR, 
				           "couldn't allocate memory to disconnect\n");
			}
		}else{
            /* this can happen legitimately when we fail to connect */
            rna_printk(KERN_INFO,
                       "Failed to reset EP [%p] in unexpected state [%s].\n",
                       ep,
                       get_ep_state_string(atomic_read(&ep->ep_state)));
			/* We return success since the application layer will get a disconnect callback in this case. Possibly before the
			   connect returns */
			ret = 0;
		}
	}

    rna_printk(KERN_INFO,
               "EP[%p] Returning[%d] Ref count[%d]\n",ep, ret, atomic_read(&ep->ref_count));

	/* Taken when queueing this work */
	com_release_ep(ep);
	kfree(etw);
	
	return;
}

/* Queue a com connect request */
int com_connect(struct com_ep *ep, struct sockaddr *dst_addr)
{
	
	struct et_work *etw;
	
	ENTER;

	if (is_shutting_down(ep->transport_handle)) {
		rna_printk(KERN_ERR, "tried to connect new EP after "
                           "the shutting down flag is set\n");
		ret = -EINVAL;
	} else {
		if( (etw = rna_kmalloc(etw, GFP_ATOMIC )) != NULL ) {
			etw->ep = ep;
			memcpy(&etw->u.dst_addr,dst_addr,sizeof(*dst_addr));
			RNA_INIT_WORK(&etw->w, et_com_connect, etw);
		
			com_inc_ref_ep(ep);
		
			rna_queue_work( conn_wq,&etw->w );
		} else {
			rna_printk(KERN_ERR, "No memory to queue disconnect, "
					   "leaking resources. ep=%p\n", ep);
		}
	}
	EXIT;	
}


int com_disconnect( struct com_ep *ep )
{
	int ret=0;
	BUG_ON(NULL==ep);

	/* We only want to call shutdown on the socket once */
	if(atomic_cmpxchg(&ep->com_sock.connected,1,-1) == 1){		

        rna_printk(KERN_ERR,
                   "disconnecting EP [%p] type [%d] ["NIPQUAD_FMT"]\n",
                   ep,
                   ep->user_type,
                   NIPQUAD(ep->dst_in.sin_addr.s_addr));

                BUG_ON(NULL == ep->com_sock.com);

		// shutdown causes a state change that triggers com_state_change
		// to schedule the et_disconnect routine
		if(ep->com_sock.com->ops && 
		   ep->com_sock.com->ops->shutdown)
		{
			ret = ep->com_sock.com->ops->shutdown( ep->com_sock.com, 2 );
			if (ret) {
				rna_printk(KERN_ERR,
                           "EP [%p] shutdown failed ret [%d]\n", ep, ret);
			}

		} else {
			rna_printk(KERN_ERR, "no shutdown operation\n");
		}
	}

	return ret;
}

int transport_listen(struct rna_transport_handle *com_handle, unsigned short int port)
{
	return -EINVAL;
}

/** Note: This is a stop-gap in the event the caller did not release all the references on EPs as it 
 *        should have. 
 */
/**
 * Iterate over the global list of endpoints, and free's each.
 * @return 0 if all freed, otherwise return current connect count.
 */
static int com_free_all_eps (struct rna_transport_handle* g_com)
{
    int timeout = 0;
    struct com_ep *ep = NULL;
    struct com_ep *ep_tmp = NULL;
    int ret = 0;
    int con_count;
	
    BUG_ON(NULL == g_com);
	
	if(atomic_read ( &g_com->connection_count ) > 0){	
		/* Note: the workq threads *MUST* be stopped here. We assume that
	         we're shutting down and we can just free up the items on
	         the list without anyone calling into us. */
		rna_printk ( KERN_ERR, "start: connect count %d\n", atomic_read ( &g_com->connection_count ) );

		list_for_each_entry_safe ( ep, ep_tmp, &g_com->ep_lst_head, entries ) {
			com_free_ep(g_com, ep);		
		}
	
		rna_printk ( KERN_ERR, "end: connect count %d\n", atomic_read ( &g_com->connection_count ) );
	}
	
    return atomic_read ( &g_com->connection_count );
}


struct rna_transport_handle* transport_init(struct rna_com_attrs *attrs)
{
    struct rna_transport_handle *com;
    ENTER;

    if ((com = rna_kzalloc(com, GFP_KERNEL)) == NULL)
        GOTO( out,-ENOMEM );
	
    com->comp_mode = attrs->comp_mode;

    atomic_set( &com->transport_state, KERNEL_TRANSPORT_STATE_OK );
    atomic_set( &com->connection_count,0 );

    INIT_LIST_HEAD( &com->work_lst_head );
    INIT_LIST_HEAD( &com->ep_lst_head );

    mutex_init( &com->work_lst_lock );

    init_waitqueue_head( &com->work_wait );
    init_waitqueue_head( &com->all_disconnected_wait );

    mutex_init(&com->ep_lst_lock);
    mutex_init(&com->transport_state_lock);
    rna_spin_lock_init(com->ep_ref_lock);
    rna_spin_lock_init(com->ep_dsc_lock);

    /* We set this so rna_com_core:transport_disconnect_all_eps
     * flushes the workqueue properly. */

    com->rna_conn_workq = conn_wq;
    com->rna_delayed_send_workq = delayed_send_wq;

    com->initialized = TRUE;

out:
    EXITPTR( com );
err:
    kfree( com );
    com = NULL;
    goto out;
}

int transport_disable(struct rna_transport_handle *com)
{
    int dangling_eps;
    int retry_limit = 5;

    if(com->initialized){
        do {
            set_disconnecting(com);
            dangling_eps = transport_disconnect_all_eps(com);

            if(dangling_eps){
                rna_printk(KERN_ERR,"Notice. All eps were not cleaned up on exit. Will force cleanup.\n");
            }

            /* Flush out remaining work */
            rna_flush_workqueue(recv_wq);
            rna_flush_workqueue(delayed_send_wq);
            rna_flush_workqueue(send_wq);
            rna_flush_workqueue(conn_wq);
            rna_flush_workqueue(comp_wq);

            /* Prohibit any more work from being queued */
            set_shutting_down(com);

            rna_flush_workqueue(recv_wq);
            rna_flush_workqueue(delayed_send_wq);
            rna_flush_workqueue(send_wq);
            rna_flush_workqueue(conn_wq);
            rna_flush_workqueue(comp_wq);
        } while (atomic_read(&com->connection_count) > dangling_eps && 
                 --retry_limit > 0);
    }
    return atomic_read(&com->connection_count);
}

int transport_exit( struct rna_transport_handle *com )
{
    ENTER;

    if(com->initialized){
        transport_disable(com);
	
        /* Clean up any remaining eps */
        /* TODO: This *shouldn't* be necessary if the caller did all the right things.
         * since this is not always the case we force the cleanup here and 
         * assume the caller won't try and dereference any EPs from here on out */
        com_free_all_eps(com);
        com->initialized = FALSE;
    }

    kfree(com);

    EXIT;
}

/* XXX 
 * The following code was in rna_com_transport_module.c, but makefile changes
 * to support OFED didn't like rna_com_transport_module.o to be shared
 * between two .ko files built by a single make.  I opted to 'unshare'
 * the code.  Maybe someone smarter can figure out a better way.
 */
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

/*
 * Routine used by ep_proc to print out transport specific information
 */
char *
print_bb_stats(struct com_ep *ep, char *p)
{
    return p;
}

int _com_send(struct com_ep *ep, struct buf_entry *buf, int size, enum env_type env_type);

/* This file contains boilerplate code related to
 * loading a transport as a module.  It is linked
 * with both the IB and TCP transport modules.
 * The transport itself need only implement the
 * "get_transport_type" function.  */

struct rna_transport transport = {
    .transport_list           = {NULL,NULL},
    .transport_type           = 0,
    .module                   = NULL,
    .transport_init_fn        = transport_init,
    .transport_disable_fn     = transport_disable,
    .transport_exit_fn        = transport_exit,
    .transport_alloc_ep_fn    = transport_alloc_ep,
    .com_connect_fn           = com_connect,
    .com_disconnect_fn        = com_disconnect,
    .queue_disconnect_work_fn = queue_disconnect_work,
    .com_get_send_buf_fn      = com_get_send_buf,
    .com_put_send_buf_fn      = com_put_send_buf,
    .com_wait_send_avail_fn   = com_wait_send_avail,
    .com_send_fn              = _com_send,
    .com_get_rdma_buf_fn      = com_get_rdma_buf,
    .com_put_rdma_buf_fn      = com_put_rdma_buf,
    .com_get_rkey_fn          = com_get_rkey,
    .com_rdma_read_fn         = com_rdma_read,
    .com_wait_rdma_avail_fn   = com_wait_rdma_avail,
    .com_rdma_write_fn        = com_rdma_write,
    .com_reg_single_fn        = com_reg_single,
    .com_dereg_single_fn      = com_dereg_single,
    .com_isreg_fn             = com_isreg,
    .com_wait_connected_fn    = com_wait_connected,
    ._com_release_ep_fn       = _com_release_ep,
    .transport_find_ep_fn     = transport_find_ep,
    .com_get_guid_fn          = com_get_guid,
    .com_rdma_sgl_fn          = com_rdma_sgl,
    .com_reg_sgl_fn           = com_reg_sgl,
    .com_mapping_error_fn     = com_mapping_error,
    .com_dereg_sgl_fn         = com_dereg_sgl,
    .transport_get_device_attributes_fn = transport_get_device_attributes,
    .transport_listen_fn      = transport_listen,
    .transport_ep_send_order_fn = transport_ep_send_order,
    .transport_alloc_buf_pool_elem_fn = transport_alloc_buf_pool_elem,
    .transport_free_buf_pool_elem_fn  = transport_free_buf_pool_elem,
    .transport_ep_proc_stats_fn = print_bb_stats,
};

int transport_module_init (void);
void transport_module_exit (void);


/* INIT / EXIT */

static int com_generic_transport_module_init(void)
{
    int ret = 0;
    char* modname = THIS_MODULE->name;

    rna_printk(KERN_INFO, "%s init starting\n", modname);  

    /* Do transport-specific initialization. */
    ret = transport_module_init();

    if (ret) {
        rna_printk(KERN_ERR, "%s transport initialization failed\n", modname);
    } else {
        transport.transport_type = get_transport_type();
        transport.module = THIS_MODULE;
        ret = register_transport(&transport);
        if (ret) {
            rna_printk(KERN_ERR, 
                       "%s init failed, register_transport returned %d\n",
                       modname, ret);
        } else {
            rna_printk(KERN_INFO, "%s init complete\n", modname);
        }
    }
    return ret;
}

/* We shouldn't be called if we have an active com instance, due to reference
 * counting.  However, an application may call transport_init right when we're 
 * shutting down.  In that case, we may crash. */

static void com_generic_transport_module_exit(void)
{
    char* modname = THIS_MODULE->name;

    rna_printk(KERN_INFO, "%s exit starting\n", modname);

    /* Unhook ourselves from our application, so we can't
     * get a new transport_init call. */
    unregister_transport(&transport);

    /* Call transport-specific shutdown. */
    transport_module_exit();

    rna_printk(KERN_INFO, "%s exit complete\n", modname);
}

/* MODULE REGISTRATION */

module_init(com_generic_transport_module_init);
module_exit(com_generic_transport_module_exit);

MODULE_AUTHOR("Dell Inc");
/* We use GPL-only workqueue functions. */
MODULE_LICENSE("GPL");
