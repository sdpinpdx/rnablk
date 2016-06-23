/**
 * <rna_com_ib.c> - Dell Fluid Cache block driver
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
 */

#include <linux/workqueue.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/mutex.h>
#include <linux/timer.h>
#include <linux/proc_fs.h>
#include <linux/cpumask.h>
#include <linux/mempool.h>

#include "../include/rna_common.h"
#include "../include/rna_atomic64.h"

#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>

#include "rna_com_linux_kernel.h"
#include "rna_proc_ep.h"
#include "priv_data.h"

#define RNA_IB_COM_READ_CREDITS_DEFAULT 0
#define RNA_IB_COM_READ_CREDITS_WAIT 50 /* Milliseconds to wait for credits */
static spinlock_t ib_com_read_credit_lock; /* Synchronize on the credits variable */
static long ib_read_credits = RNA_IB_COM_READ_CREDITS_DEFAULT;
module_param(ib_read_credits, long, 0444);
MODULE_PARM_DESC(ib_read_credits,
                 "Read credits. Number of outstanding bounce buffer read "
                 "requests which may affect performance by limiting network "
                 "congestion. Default=0");
static wait_queue_head_t ib_com_read_credit_wait; /* wait queue for send buffer */
static int ib_com_use_read_credits;
static int64_t ib_com_read_credits;

/* 
 * All IB-level errors are mapped to CB_RESP_FAIL.  The completion handler will 
 * trigger disconnect processing (process_single_completion sets *do_disconnect 
 * to TRUE and __cq_work_handler will queue the disconnect work), and then block 
 * client will retry the ios.  Some of the fake RDMA paths might already be 
 * indicating a CB_RESP_ code, which is always < 0 for an error.  Don't change 
 * those.
 */
static inline int
com_ib_status_to_cb_resp(int wc_status) 
{
    if (wc_status <= 0) {
        return wc_status;
    }
    return CB_RESP_FAIL;
}

void 
repost_read_credit(struct buf_entry *buf_entry)
{
    unsigned long credit_lock_flags;

    if ((TRUE == ib_com_use_read_credits) &&
        (0 != buf_entry->bounce_address)) {
        spin_lock_irqsave(&ib_com_read_credit_lock, credit_lock_flags);
        ib_com_read_credits++;
        spin_unlock_irqrestore(&ib_com_read_credit_lock, credit_lock_flags);
        wake_up_all(&ib_com_read_credit_wait);
    }
}

/* 
 * Wait on the credits variable. Note that it is possible for credits to go 
 * negative since we'll only wait so long and this counter keeps track of
 * all outstanding RDMA read operations. Failed connections will eventually
 * refill their outstanding credits. 
 */
static void 
ib_wait_on_read_credit(struct buf_entry *buf_entry) {
	int retry = TRUE;
	int ret;
    unsigned long credit_lock_flags;
	
    if ((FALSE == ib_com_use_read_credits) ||
        (0 == buf_entry->bounce_address)) {
        /* Only use read credits when the bounce buffer is being used. */
        return;
    }
    
do_retry:
	/* Check the global counter */
	spin_lock_irqsave(&ib_com_read_credit_lock, credit_lock_flags);
	if ((ib_com_read_credits > 0) || (retry == FALSE)) {
		ib_com_read_credits--;
		retry = FALSE;
	}	
	spin_unlock_irqrestore(&ib_com_read_credit_lock, credit_lock_flags);
	
	if (retry) {
		/* Wait on credits to go up */
		rna_printk(KERN_DEBUG, "Waiting on credit. Current credits [%"
                   PRId64"]\n", ib_com_read_credits);
		ret = wait_event_interruptible_timeout(
            ib_com_read_credit_wait,
            (ib_com_read_credits > 0),
            msecs_to_jiffies(RNA_IB_COM_READ_CREDITS_WAIT));
		if (ret <= 0) {
			rna_printk(KERN_INFO, "Timed out waiting on read credit. "
                       "Current credits [%"PRId64"]\n", ib_com_read_credits);
			retry = FALSE;
		}
		goto do_retry;		
	}
	return;
}

/* XXX */
static inline uint64_t getrawmonotonic_ns(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
    return get_jiffies_64() * NS_PER_HZ;
#else    
    struct timespec tspec;

    getrawmonotonic(&tspec);
    return (tspec.tv_sec*1000*1000*1000) + tspec.tv_nsec;
#endif
}

#define EP_CLEANUP_WAIT_TIMEOUT 60000

#ifdef RHEL_RELEASE_VERSION
#if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(6,2)
#define RDMA_CREATE_ID_FOUR_ARGS
#endif
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
#define RDMA_CREATE_ID_FOUR_ARGS
#endif
#endif

/* 
 * Print out a warning when we spend more then this amount of time processing 
 * completion event set 
 */
#define POLL_WARN_LAT 10000

static struct kmem_cache *ibsgl_cache;
static mempool_t *ibsgl_pool;

/* rna_add_device is easier to implement if these are shared globals,
 * rather than stored in the per-instance rna_com structure. */

struct mutex             dev_lst_lock;
struct list_head         dev_lst_head;
struct ib_client         rna_ib_client;

typedef struct ib_com_buf_data_s {
    struct ib_send_wr   icb_send_wr;
    struct ib_sge       icb_sge;
    struct ib_sge       *icb_sglp;
} ib_com_buf_data_t;

struct device_context {
    struct ib_device *ib_device;

    /* Device attributes */
    struct ib_device_attr attr;

    /* One Protection Domain per device
     * That way Cache Blocks can be registered once per channel/device
     */
    struct ib_pd     *pd;
    struct ib_mr     *mr;
    /* 
     * mr_registered acts as a guard for the global
     *    memory region, ensuring that it is only registered once.
     *    see rna_com_device_reg_mr()
     */
    atomic_t          mr_registered;
    struct list_head  entries;
};

/* context for bounce buffer management in the infiniband transport */
struct com_ib_bb_ctxt {
    /* larger buffer for RDMA transfers */
    uint32_t            bbc_buf_req_size; /* Requested bounce pool bytes. */
    uint32_t            bbc_buf_alloc_size; /* bytes in a bounce bufflet */
    uint64_t            bbc_buf_addr; /* Address of remote bounce pool */
    uint32_t            bbc_buf_size; /* Actual bytes in bounce pool */
    rna_rkey_t          bbc_buf_rkey; /* rkey to use for bounce pool */
    /*
     * bitvector for allocating segments of bounce buffer.  This MUST
     * be padded by sizeof(uint64_t) because of the test_and_set_mask()
     * function.  See comments there for more details.
     */
    int                 bbc_bitvec_size; /* actual bitvec size in bits */
    int                 bbc_bitvec_first; /* next bit in bitvec to allocate */
    int                 bbc_bits_allocated; /* count of allocated bits */
    int                 bbc_bits_pending;   /* count of pending alloc bits */
    int                 bbc_bits_max_allocated;
    int                 bbc_bits_max_pending;
    int                 bbc_bitvec_first_resets;
    atomic_t            bbc_bb_used;
    atomic_t            bbc_bb_rejected;
    atomic_t            bbc_read_allocation_waiters;
    atomic_t            bbc_write_allocation_waiters;
    atomic64_t          bbc_allocation_wait;
    atomic64_t          bbc_read_send_wait;
    atomic64_t          bbc_read_rdma_wait;
    atomic64_t          bbc_write_send_wait;
    atomic64_t          bbc_write_rdma_wait;
    atomic_t            bbc_read_count;
    atomic_t            bbc_write_count;

    /* list of buf_entry structures that HAVE a bounce buffer */
    spinlock_t          bbc_state_lock; /* lock for bbuffer state */
    uint8_t             bbc_bitvec[0];
};

#define MAX_BB_BITVEC_BYTES     (1024)
#define BB_CTXTP(ep)    ((struct com_ib_bb_ctxt *)((ep)->bounce_buf_ctxt))

char *
print_bb_stats(struct com_ep *ep, char *p)
{
    struct com_ib_bb_ctxt *bb_ctxt = BB_CTXTP(ep);

    if (NULL == bb_ctxt) {
        return p;
    }
    p += sprintf(p, "Bounce Buffer Stats:\n");
    p += sprintf(p, "max_allocated %d\n", bb_ctxt->bbc_bits_max_allocated);
    p += sprintf(p, "max_pending %d\n", bb_ctxt->bbc_bits_max_pending);
    p += sprintf(p, "first_resets %d\n", bb_ctxt->bbc_bitvec_first_resets);
    p += sprintf(p, "bounce used %d\n", atomic_read(&bb_ctxt->bbc_bb_used));
    p += sprintf(p, "bounce rej %d\n", atomic_read(&bb_ctxt->bbc_bb_rejected));
    p += sprintf(p, "total alloc wait %"PRId64"\n",
                 rna_atomic64_read(&bb_ctxt->bbc_allocation_wait));
    /* Average alloc wait */
    if ((atomic_read(&bb_ctxt->bbc_read_count) +
         atomic_read(&bb_ctxt->bbc_write_count)) != 0) {
        p += sprintf(p, "alloc wait avg %"PRId64"\n",
                     rna_atomic64_read(&bb_ctxt->bbc_allocation_wait) /
                     (atomic_read(&bb_ctxt->bbc_read_count) +
                      atomic_read(&bb_ctxt->bbc_write_count)));
    }
    
    /* read statistics */
    p += sprintf(p, "read count %d\n", atomic_read(&bb_ctxt->bbc_read_count));
    p += sprintf(p,
                 "read send wait %"PRId64"\n",
                 rna_atomic64_read(&bb_ctxt->bbc_read_send_wait));
    p += sprintf(p,
                 "read rdma wait %"PRId64"\n",
                 rna_atomic64_read(&bb_ctxt->bbc_read_rdma_wait));
    /* read averages */
    if (atomic_read(&bb_ctxt->bbc_read_count) != 0) {
        p += sprintf(p,
                     "read send wait avg %"PRId64"\n",
                     rna_atomic64_read(&bb_ctxt->bbc_read_send_wait)/
                     atomic_read(&bb_ctxt->bbc_read_count));
        p += sprintf(p,
                     "read rdma wait avg %"PRId64"\n",
                     rna_atomic64_read(&bb_ctxt->bbc_read_rdma_wait)/
                     atomic_read(&bb_ctxt->bbc_read_count));
    }
    /* write statistics */
    p += sprintf(p, "write count %d\n", atomic_read(&bb_ctxt->bbc_write_count));
    p += sprintf(p,
                 "write send wait %"PRId64"\n",
                 rna_atomic64_read(&bb_ctxt->bbc_write_send_wait));
    p += sprintf(p,
                 "write rdma wait %"PRId64"\n",
                 rna_atomic64_read(&bb_ctxt->bbc_write_rdma_wait));
    /* write averages */
    if (atomic_read(&bb_ctxt->bbc_write_count) != 0) {
        p += sprintf(p,
                     "write send wait avg %"PRId64"\n",
                     rna_atomic64_read(&bb_ctxt->bbc_write_send_wait)/
                     atomic_read(&bb_ctxt->bbc_write_count));
        p += sprintf(p,
                     "write rdma wait avg %"PRId64"\n",
                     rna_atomic64_read(&bb_ctxt->bbc_write_rdma_wait)/
                     atomic_read(&bb_ctxt->bbc_write_count));
    }
    return p;
}

/*
 * Allocate a bounce buffer context structure with a big enough
 * bbc_bitvec array to hold the allocation state for the segments
 * This array size must be padded with sizeof(uint64_t) bytes due to
 * the algorithm used to allocate/free bits in the bitvec array.
 * That algorithm DOES read/write to bits in the pad space.
 */
static struct com_ib_bb_ctxt *
kernel_allocate_ib_bb_ctxt(int bounce_buf_size, int bounce_buf_seg_size)
{
    struct com_ib_bb_ctxt *bb_ctxt;
    int bitvec_size;
    int bitvec_bytes;

    if ((0 >= bounce_buf_size) ||
        (0 >= bounce_buf_seg_size) ||
        (bounce_buf_size < bounce_buf_seg_size)) {
        if (!((0 == bounce_buf_size) || (0 == bounce_buf_seg_size))) {
            rna_printk(KERN_ERR,
                       "kernel_alloc_ib_bb_ctxt: "
                       "bad bounce buffer arguments buf_size %d seg_size %d\n",
                       bounce_buf_size,
                       bounce_buf_seg_size);
        }
        return NULL;
    }

    /* rounds down, ignore any remainder */
    bitvec_size = bounce_buf_size / bounce_buf_seg_size;
    if (0 == bitvec_size) {
        rna_printk(KERN_ERR,
                   "kernel_alloc_ib_bb_ctxt: "
                   "bad bounce buffer arguments, no bitvec buf_size %d seg_size %d\n",
                   bounce_buf_size,
            bounce_buf_seg_size);
        return NULL;
    }

    bitvec_bytes = DIV_ROUND_UP(bitvec_size, sizeof(uint8_t)) +
                                sizeof(uint64_t);

    rna_printk(KERN_DEBUG,
               "allocate_ib_bb_ctxt bb_size %d bb_seg_size %d bitvec size %d "
               "bitvec bytes %d\n",
               bounce_buf_size,
               bounce_buf_seg_size,
               bitvec_size,
               bitvec_bytes);
    
    bb_ctxt = kzalloc(sizeof(struct com_ib_bb_ctxt) + bitvec_bytes,
                      GFP_KERNEL);

    if (NULL != bb_ctxt) {
        bb_ctxt->bbc_buf_req_size = bounce_buf_size;
        bb_ctxt->bbc_buf_alloc_size = bounce_buf_seg_size;
    } else {
        rna_printk(KERN_ERR,
                  "failed to allocate ib_bb_ctxt bb size %d bb seg size %d\n",
                  bounce_buf_size, bounce_buf_seg_size);
    }

    rna_printk(KERN_INFO, "return bb_ctxt %p\n", bb_ctxt);

    return bb_ctxt;
}

static void
kernel_free_ib_bb_ctxt(struct com_ib_bb_ctxt *bb_ctxt)
{
    rna_printk(KERN_DEBUG, "Free bounce buffer context %p\n", bb_ctxt);
    kfree(bb_ctxt);
}

static void
bounce_buffer_init(struct com_ep *ep, struct com_conx_reply *rep)
{
    struct com_ib_bb_ctxt *bb_ctxt = BB_CTXTP(ep);

    if (NULL == bb_ctxt) {
        return;
    }

    if (rep->bounce_buffer_size != bb_ctxt->bbc_buf_req_size) {
        rna_printk(KERN_INFO,
                   "bounce_buffer_init: "
                   "ep [%p] No bounce buffers allocated "
                   "rep [%"PRIu64"] alloc_size [%d]\n",
                   ep,
                   rep->bounce_buffer_size,
                   bb_ctxt->bbc_buf_req_size);
        kernel_free_ib_bb_ctxt(bb_ctxt);
        ep->bounce_buf_ctxt = NULL;
        return;

    }

    atomic_set(&bb_ctxt->bbc_bb_used, 0);
    atomic_set(&bb_ctxt->bbc_bb_rejected, 0);
    bb_ctxt->bbc_buf_addr = rep->bounce_buffer_addr.base_addr;
    bb_ctxt->bbc_buf_size = rep->bounce_buffer_size;
    bb_ctxt->bbc_buf_rkey = rep->bounce_buffer_rkey;

    /* this effectively rounds down to an even multiple
     * of bounce_alloc_size, then converts to a bit size.
     */
    bb_ctxt->bbc_bitvec_size = bb_ctxt->bbc_buf_size /
                                    bb_ctxt->bbc_buf_alloc_size;

    if (bb_ctxt->bbc_bitvec_size > MAX_BB_BITVEC_BYTES * BITS_PER_BYTE) {
        rna_printk(KERN_ERR,
                   "Reduced bounce buffer bit vector size "
                    "from %d to %d\n",
                    bb_ctxt->bbc_bitvec_size,
                    MAX_BB_BITVEC_BYTES * BITS_PER_BYTE);
        bb_ctxt->bbc_bitvec_size = MAX_BB_BITVEC_BYTES * BITS_PER_BYTE;
    }

    spin_lock_init(&bb_ctxt->bbc_state_lock);

    rna_printk(KERN_DEBUG,
               "bounce_buffer_init: ep [%p] "
               "bounce buf addr [0x%"PRIu64"]"
               "size [%d] "
               "allocation unit size [%d] "
               "number units [%d]\n",
               ep,
               bb_ctxt->bbc_buf_addr,
               bb_ctxt->bbc_buf_size,
               bb_ctxt->bbc_buf_alloc_size,
               bb_ctxt->bbc_bitvec_size);
}

/* This can be very simple. The bounce buffer should be able
 * to handle any request size up to the maximum permitted by the
 * block device.
 */
static int 
kernel_com_use_bounce_buffer(struct com_ep *ep, int size)
{
    struct com_ib_bb_ctxt *bb_ctxt = BB_CTXTP(ep);

    if (NULL == bb_ctxt) {
        return FALSE;
    }
    if (size <= MAX_RDMA_VIA_SEND_SIZE) {
        atomic_inc(&bb_ctxt->bbc_bb_rejected);
        return FALSE;
    }

    atomic_inc(&bb_ctxt->bbc_bb_used);
    return TRUE;
}

static uint64_t 
kernel_com_sgl_size(struct scatterlist *sgl, int nents)
{
    int i;
    uint64_t len = 0;

    for (i=0; i < nents; i++ ) {
        len += (sgl +i)->length;
    }
    return len;
}

/* array of bit masks.  Each entry has a number of bits set that corresponds
 * to that entry's index in the array.  So for example, element 3 in the array
 * has 3 bits set.
 */
static const uint64_t mask_patterns[] =
{ 0x0, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f, 0xff, 0x1ff, 0x3ff, 0x7ff, 0xfff,
  0x1fff, 0x3fff, 0x7fff, 0xffff, 0x1ffff, 0x3ffff, 0x7ffff, 0xfffff, 0x1fffff,
  0x3fffff, 0x7fffff, 0xffffff, 0x1ffffff, 0x3ffffff, 0x7ffffff, 0xfffffff,
  0x1fffffff, 0x3fffffff, 0x7fffffff, 0xffffffff, 0x1ffffffff, 0x3ffffffff,
  0x7ffffffff, 0xfffffffff, 0x1fffffffff, 0x3fffffffff, 0x7fffffffff,
  0xffffffffff, 0x1ffffffffff, 0x3ffffffffff, 0x7ffffffffff, 0xfffffffffff,
  0x1fffffffffff, 0x3fffffffffff, 0x7fffffffffff, 0xffffffffffff,
  0x1ffffffffffff, 0x3ffffffffffff, 0x7ffffffffffff, 0xfffffffffffff,
  0x1fffffffffffff, 0x3fffffffffffff, 0x7fffffffffffff, 0xffffffffffffff
};

/*
 * test and set "bits_needed" number of bits in the bit vector,
 * starting with "start_bit".
 *
 * Return value:
 *  success: 0 - The requested bits were all clear on entry. They are all set
 *               on exit.
 *  failure: -1 - One or more of the requested bits was set.  No changess
 *               were made to the bit vector.
 *
 *  This code requires one operation to test the entire bit set, and
 *  a second operation to set those bits.
 *
 *  However, this code works only on little-endian processors that
 *  allow unaligned 64-bit memory accesses.
 *
 *  It also requires that the bitvec argument be padded by an extra 64 bits,
 *  because this code WILL read and write bytes beyond the end of the
 *  vector.
 *
 *  caller must hold whatever locking is needed to assure atomicity.
 */
static int
test_and_set_mask(uint8_t *bitvec, int start_bit, int bits_needed)
{
    uint64_t test_mask = mask_patterns[bits_needed];
    uint64_t *start_byte;

    start_byte = (uint64_t *)&bitvec[start_bit/BITS_PER_BYTE];
    test_mask <<= (start_bit % BITS_PER_BYTE);

    if ((test_mask & *start_byte) == 0) {
        *start_byte |= test_mask;
        return 0;
    }

    return -1;
}

/* Clear the specified number of bits in the bit vector, starting
 * with the specified starting bit number.
 *
 * assert that all of the specified bits are indeed set to begin with.
 */
static void
clear_mask(uint8_t *bitvec, int start_bit, int bits_needed)
{
    uint64_t test_mask = mask_patterns[bits_needed];
    uint64_t *start_byte;

    start_byte = (uint64_t *)&bitvec[start_bit/BITS_PER_BYTE];
    test_mask <<= (start_bit % BITS_PER_BYTE);

    BUG_ON((test_mask & *start_byte) != test_mask);
    *start_byte &= ~test_mask;
}

/* size number of bounce bufflets needed to construct the
 * needed bounce buffer.
 *
 * size translates directly to the number of consecutive bit vector
 * bits needed.
 *
 * Return -1 on failure, if there are not enough bits available.
 *
 * Return a number zero or greater on success.  This is the bit number of
 * the first bit in the set of bits that were just allocated.
 *
 * Caller must hold ep->bounce_state_lock
 */
static int
allocate_bbufflets(struct com_ep *ep, int bbt_needed)
{
    struct com_ib_bb_ctxt *bb_ctxt = BB_CTXTP(ep);
    int bbt_bit, ret;

    BUG_ON(NULL == bb_ctxt);

    /* we must not need more bits than are in the bit vector */
    BUG_ON(bbt_needed > bb_ctxt->bbc_bitvec_size);


    /* If there are not enough bits in the bit vector following the
     * currenly first allocatable bit, the restart the allocation from
     * the beginning of the bit vector.
     */
    if ((bb_ctxt->bbc_bitvec_first + bbt_needed) > bb_ctxt->bbc_bitvec_size) {
        bb_ctxt->bbc_bitvec_first_resets++;
        bb_ctxt->bbc_bitvec_first = 0;
    }

    bbt_bit = bb_ctxt->bbc_bitvec_first;
    ret = test_and_set_mask(bb_ctxt->bbc_bitvec, bbt_bit, bbt_needed);

    /* No, there are not enough bits available */
    if (0 != ret) {
        return -1;
    }

    /* return the starting bit number of this allocation, and upate
     * the bit number for the start of the next allocation.
     */
    bb_ctxt->bbc_bitvec_first += bbt_needed;

    return bbt_bit;
}

static int
assign_bounce_buffer_to_rdma_buf(struct com_ep *ep,
                                 struct buf_entry *buf)
{
    struct com_ib_bb_ctxt *bb_ctxt = BB_CTXTP(ep);
    int bbt_bit;

    bbt_bit = allocate_bbufflets(ep, buf->bounce_bits);
    /* did we get the requested number of bit vector bits? */
    if (0 > bbt_bit) {
        return bbt_bit;
    } else {
        /* Success!
         * update statistics on pending vs allocated bits.
         * Remove this buf_entry from the pending allocation list
         * Add this buf_entry to the list of buf_entries with bits allocated.
         * translate the starting bit vector number into the starting address
         *    of the allocated bounce buffer segment.
         * wake up the thread blocked on this buf_entry.
         */
        buf->bounce_start_bit = bbt_bit;
        bb_ctxt->bbc_bits_allocated += buf->bounce_bits;
        if (bb_ctxt->bbc_bits_allocated > bb_ctxt->bbc_bits_max_allocated) {
            bb_ctxt->bbc_bits_max_allocated = bb_ctxt->bbc_bits_allocated;
        }
        bb_ctxt->bbc_bits_pending -= buf->bounce_bits;
    }
    return 0;
}

#define kernel_com_get_bounce_buffer(B, S)                  \
    _kernel_com_get_bounce_buffer(B, S, __location__)
#define kernel_com_release_bounce_buffer(B)            \
    _kernel_com_release_bounce_buffer(B, __location__)

/*
 * Release a buf_entry's bounce buffer resources to the pool.
 *
 * This may be called either after an IO request has completed, or
 * in the event of an allocation timeout or end point disconnect.
 *
 * In the event of a timeout/disconnect, there MAY or MAY NOT
 * be bits allocated to this buf_entry.
 *
 * If there are bits allocated, 
 *  Return the bit vector segment allocated to this buf_entry
 *  to the pool
 *  update the bits allocated count.
 *  Then see if bounce buffers can be assigned to another buf_entry.
 *
 * In either case, remove the buf_entry from whatever list it is on
 * (could be either the pending or allocated list).
 *
 * acquires and releases buf_entry->bounce_stat_lock.
 * Will zero bounce_start_bit, bounce_bits, bounce_address.
 */
void
_kernel_com_release_bounce_buffer(struct buf_entry *buf_entry,
                                  const char *loc)
{
    struct com_ep *ep = buf_entry->ep;
    struct com_ib_bb_ctxt *bb_ctxt = BB_CTXTP(ep);
    unsigned long bounce_lock_flags;
    int i;

    BUG_ON(NULL == bb_ctxt);

    spin_lock_irqsave(&bb_ctxt->bbc_state_lock, bounce_lock_flags);

    if (INVALID_BOUNCE_BIT != buf_entry->bounce_start_bit) {
        clear_mask(bb_ctxt->bbc_bitvec,
                   buf_entry->bounce_start_bit,
                   buf_entry->bounce_bits);
        bb_ctxt->bbc_bits_allocated -= buf_entry->bounce_bits;
    }
    spin_unlock_irqrestore(&bb_ctxt->bbc_state_lock, bounce_lock_flags);

    buf_entry->bounce_bits = 0;
    buf_entry->bounce_start_bit = INVALID_BOUNCE_BIT;
    buf_entry->bounce_address = 0;
}

/* Wait until a bounce buffer segment can be assigned to this
 * request.
 *
 * size is desired bounce buffer size in bytes.
 *
 * The address of the allocated bounce buffer is returned in
 * buf_entry->bounce_address
 *
 * Returns 0 on sucess.
 * Returns -1 on failure (timeout or lost connection)
 *
 * acquires and releases ep->bounce_state_lock
 */
int
_kernel_com_get_bounce_buffer(struct buf_entry *buf_entry,
                              int size,
                              const char *loc)
{
    struct com_ep *ep = buf_entry->ep;
    struct com_ib_bb_ctxt *bb_ctxt = BB_CTXTP(ep);
    unsigned long bounce_lock_flags;
    int ret;

    BUG_ON(NULL == bb_ctxt);
    /* size and bounce_buf_size are in bytes */
    BUG_ON(size > bb_ctxt->bbc_buf_size);

    /* convert size into bits to be allocated */
    buf_entry->bounce_bits = DIV_ROUND_UP(size, bb_ctxt->bbc_buf_alloc_size);
    buf_entry->bounce_start_bit = INVALID_BOUNCE_BIT;
    buf_entry->bounce_address = 0;

    spin_lock_irqsave(&bb_ctxt->bbc_state_lock, bounce_lock_flags);
    bb_ctxt->bbc_bits_pending += buf_entry->bounce_bits;
    assign_bounce_buffer_to_rdma_buf(ep, buf_entry);
    spin_unlock_irqrestore(&bb_ctxt->bbc_state_lock, bounce_lock_flags);
    if (INVALID_BOUNCE_BIT == buf_entry->bounce_start_bit) {
        ret = -1;
    } else {
        ret = 0;
        buf_entry->bounce_address = (bb_ctxt->bbc_buf_addr +
                                     (buf_entry->bounce_start_bit *
                                      bb_ctxt->bbc_buf_alloc_size));
    }
    return ret;
}

/* 
 * Allocate a pool of buf_entries for sending, using the transport-specific
 * com_alloc_buf_pool_elem function.  This is generally used internally
 * by the com transports, but it could be used by an application
 * directly if the need were to arise.
 *
 * I chose to do this instead of augment com_alloc_buf_pool to indicate if
 * the pool is for sends or receives.  If we choose to do that, then the 
 * IB transport_alloc_buf_pool_elem() could allocate the ib_wr if the
 * buf_pool_ctx indicated a send buffer pool.
 */
static int 
com_alloc_send_buf_pool(struct com_ep *ep, 
                        struct buf_pool *buf_pool,
                        int count,
                        int buf_size)
{
    int ret;
    int i;

    ret = com_alloc_buf_pool(ep, buf_pool, count, buf_size);
    if (0 == ret) {
        for (i = 0; i < count; i++) {
            buf_pool->entries[i]->buf_transport_data = 
                kzalloc(sizeof(ib_com_buf_data_t), GFP_NOFS);
            if (NULL == buf_pool->entries[i]->buf_transport_data) {
                ret = -ENOMEM;
                break;
            }
        }
        if (0 != ret) {
            (void)com_free_buf_pool(ep, buf_pool);
        }
    }
    return ret;
}

static int disconnect_handler(struct com_ep *ep);

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
void disconnect_work( void *work)
#else
void disconnect_work( struct work_struct *work)
#endif
{
    struct com_ep *ep = container_of((struct work_struct*)work,
                                     struct com_ep, work);
    disconnect_handler(ep);
}

/* 
 * Code paths which don't want the EP to get disconnected
 * should call this.  If it returns FALSE, then the EP is
 * already disconnected.  If it returns TRUE, then we must
 * call state_unlock when we leave the critical region.
 *
 * This used to use an actual lock (and still does in the
 * TCP transport), but reference counting turned out to be
 * a better route here, as we'd rather not hold locks 
 * across callbacks.
 */

static void state_unlock(struct com_ep *ep)
{ 
    int do_disconn = FALSE;

    BUG_ON((atomic_read(&ep->ep_state) < EP_INIT) ||
           (atomic_read(&ep->ep_state) >= EP_STATE_ILLEGAL));
    BUG_ON(atomic_read(&ep->ep_state_ref) < 0);

    if (atomic_read(&ep->ep_state_ref) == 0) {
        /* 
         * Connection rejected before it was ever fully established.  In some 
         * cases we are forcing connections to disconnect before transitioning
         * even to EP_CONNECT_PENDING.
         */
        BUG_ON((EP_CONNECT_PENDING != atomic_read(&ep->ep_state)) &&
               (EP_INIT != atomic_read(&ep->ep_state)));
        do_disconn = TRUE;

    } else if (unlikely(atomic_dec_and_test(&ep->ep_state_ref))) {
        /* 
         * TRUE if we decrement to zero, which means we need to
         * start the necessary disconnection work. 
         */
        BUG_ON(EP_CONNECTED != atomic_read(&ep->ep_state));
        do_disconn = TRUE;
    }
    if (TRUE == do_disconn) {
        if (EP_DISCONNECT_PENDING != atomic_read(&ep->ep_state)) {
            rna_printk(KERN_DEBUG, "ep [%p] going to DISCONNECT_PENDING tid "
                       "[%d] remote_tid [%"PRIu64"]\n", 
                       ep, atomic_read(&ep->trans_id), ep->remote_trans_id);
        }
        atomic_set(&ep->ep_state, EP_DISCONNECT_PENDING);
        /* 
         * This may be more efficient for those waiting on a connection
         * to be established then at the end of the disconnect callback 
         */
        wake_up_all(&ep->conn_wait);
        RNA_INIT_WORK(&ep->work, disconnect_work, &ep->work);
        rna_queue_work(ep->transport_handle->rna_conn_workq, &ep->work);
    
    }
}

static int try_state_lock(struct com_ep *ep)
{
    int ret;

    BUG_ON(atomic_read(&ep->ep_state) < 0);
    BUG_ON(atomic_read(&ep->ep_state_ref) < 0);

    if (likely(atomic_add_unless(&ep->ep_state_ref, 1, 0))) {
        BUG_ON(EP_CONNECTED != atomic_read(&ep->ep_state));
        ret = TRUE;
    } else {
        ret = FALSE;
    }

    return ret;
}

/* Drop the initial reference, but only do it once. */
static void try_state_disconnect(struct com_ep *ep)
{
    if (FALSE == atomic_cmpxchg(&ep->ep_state_disconnect_latch, FALSE, TRUE)) {
        state_unlock(ep);
    }
}

/* 
 * Stringify rdma_node_type enum found in ib_device->node_type.
 */
static char* com_get_ib_node_type_string(const enum rdma_node_type type)
{
    char *s = "Unexpected rdma_node_type";
    switch (type) {
        /* no "UNKNOWN" node type in kernel space */
        case RDMA_NODE_IB_CA:      s = "ca";      break;
        case RDMA_NODE_IB_SWITCH:  s = "switch";  break;
        case RDMA_NODE_IB_ROUTER:  s = "router";  break;
        case RDMA_NODE_RNIC:       s = "rnic";    break;
        default:                   s = "unknown"; break;
    }
    return s;
}

/* 
 * Stringify rdma_transport_type enum returned from rdma_node_get_transport.
 */
static char* com_get_ib_transport_string(const enum rdma_transport_type type)
{
    char *s = "Unexpected ibv_transport_type";
    switch (type) {
        /* no "UNKNOWN" transport type in kernel space */
        case RDMA_TRANSPORT_IB:      s = "IB";      break;
        case RDMA_TRANSPORT_IWARP:   s = "iWarp";   break;
        default:                     s = "unknown"; break;
    }
    return s;
}

/* Used by rna_com_transport_module.c to fill in
 * the rna_transport structure. */
enum com_type get_transport_type(void) {
    return RC;
}

static enum rdma_transport_type ib_transport(struct com_ep *ep)
{
    enum rdma_transport_type type = -1;

    if (NULL == ep->cma_id) {
        rna_printk(KERN_ERR, "ep doesn't have cma_id\n");
    } else {
        type = rdma_node_get_transport(ep->cma_id->device->node_type);
    }

    return type;
}

/* These are meant to be called from within the com.
 * We query the EP rather than the com handle to account for the ambiguous
 * case in which we're running on a machine with both an IB and an iWarp 
 * interface managed by the same com instance. */
int is_iwarp(struct com_ep *ep)
{
    return FALSE;
    //return (ib_transport(ep) == RDMA_TRANSPORT_IWARP);
}

int is_infiniband(struct com_ep *ep)
{
    return TRUE;
    //return (ib_transport(ep) == RDMA_TRANSPORT_IB);
}

enum rna_first_send_order transport_ep_send_order(struct com_ep *ep)
{
    enum rna_first_send_order order = -1;
    int passive = ep->passive;

    if (is_infiniband(ep)) {
        order = passive ? DEFAULT_PASSIVE_IB_SEND_ORDER :
                          DEFAULT_ACTIVE_IB_SEND_ORDER;
    } else if (is_iwarp(ep)) {
        order = passive ? DEFAULT_PASSIVE_IWARP_SEND_ORDER :
                          DEFAULT_ACTIVE_IWARP_SEND_ORDER;
    } else {
        rna_printk(KERN_ERR, "unexpected ib transport type [%d]\n",
                   ib_transport(ep));
    }

    return order;
}

int check_ep_free_state(struct com_ep *ep);
int free_ep(struct com_ep *ep);
static void com_unregister_mr(struct com_ep *ep,
                                  struct ib_mr **mr_p);
static struct ib_mr * com_register_mr (struct com_ep      *ep,
                                           struct ib_phys_buf *ipb,
                                           dma_addr_t         *rdma_mem_dma);
struct ib_mr * com_ep_get_mr (struct com_ep *ep);
static int ib_send_rdma_read_msg(struct com_ep *ep,
                                 struct buf_entry *buf_entry,
                                 rna_addr_t remote_addr,
                                 rna_rkey_t remote_rkey,
                                 int size,
                                 void *context);

static void resume_queued_rdmas(struct com_ep *ep);

/* Start a new rdma write. */
static int ib_send_rdma_write_msg(struct com_ep *ep, struct buf_entry *buf,
                                  int size, char signaled, uint32_t flags);

int ib_process_rdma_req(struct com_ep* ep,
                        struct rna_com_envelope *env,
                        struct com_rdma_msg *rdma_msg,
                        void *data_buf,
                        size_t buf_len);
static int ib_rdma_sgl(struct com_ep      *ep,
                       struct ib_send_wr  *wr,
                       rna_addr_t          remote_addr,
                       rna_rkey_t          remote_rkey,
                       struct scatterlist *sgl,
                       int                 write,
                       uint32_t            flags);


static int connect_established(struct com_ep *ep, int proto_version)
{
    int do_disconnect = 0;
    int ret = 0;

    /* synchronize with connect est event on a recv completion */
    if (atomic_cmpxchg(&ep->ep_state, EP_CONNECT_PENDING, EP_CONNECTED)
            == EP_CONNECT_PENDING) {

        /*
         * Establish long-held reference on the connected state.
         * We don't drop the reference until we want to disconnect.
         */

        /* Ensure it didn't get set anywhere else */
        BUG_ON(0 != atomic_read(&ep->ep_state_ref));
        atomic_set(&ep->ep_state_ref, 1);
        rna_trace("on local addr [" NIPQUAD_FMT "]\n.",
                  NIPQUAD (ep->cma_id->route.addr.src_addr));

        ep->src_in = *((struct sockaddr_in*)&ep->cma_id->route.addr.src_addr);
        ep->dst_in = *((struct sockaddr_in*)&ep->cma_id->route.addr.dst_addr);
        ep->proto_version = proto_version;

        /* Note: There is a potential race condition where the connect was pending
                 but the application timed out and wanted to cancel, calling com_disconnect
                 If com_disconnect occurs before the connect callback, but we get a connect
                 callback we should immediately call the com_disconnect() instead of the
                 application connect callback routine.
                 If com_disconnect() is called, the connected flag will = -1
        */

        rna_spin_lock(ep->transport_handle->ep_dsc_lock);

        connection_count_inc(ep->transport_handle);

        /* If the client called disconnect before the connect occurred we should disconnect
           immediately, otherwise the connection could be left dangling. */
        if(ep->connected == -1){
            do_disconnect = 1;
        }

        ep->connected = 1;

        if((do_disconnect)      // client already called com_disconnect()
          || (CB_FAILED == ep->callback_state)) {
                                // A com_connect_sync() on this ep has timed
                                // out.  Don't invoke an unexpected callback.
            rna_spin_unlock(ep->transport_handle->ep_dsc_lock);
            com_disconnect(ep);
            return 0;
        } else {
            // Indicate that the connect_cb, if defined, is about to be invoked
            ep->callback_state = CB_CONNECTED;
            rna_spin_unlock(ep->transport_handle->ep_dsc_lock);
            if (ep->com_attr.connect_cb) {
                ret = (*ep->com_attr.connect_cb)( ep, ep->context );
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
        wake_up_all(&ep->conn_wait);
    } else {
        rna_printk(KERN_ERR, "Connect established but EP[%p] is not in the "
                   "CONNECT_PENDING state. Current state[%d]\n",
                   ep, atomic_read(&ep->ep_state));
    }

    rna_trace("connection_count %d\n",
               atomic_read(&ep->transport_handle->connection_count));

    return 0;
}


void com_destroy_ib_conx(struct com_ep *ep)
{
	unsigned long flags;
	int ret;

	/* Normally we only call this on eps that have been disconnected,
	 * but in free_all_eps, we call this also for EPs that were never
	 * connected to begin with.
	 * Everything that this might race with should check that the
	 * state is EP_CONNECTED while holding a reference on 
	 * ep->ep_state_ref.*/
	if (!is_shutting_down(ep->transport_handle)) {
		BUG_ON(atomic_read(&ep->ep_state) <= EP_CONNECTED);
	}

	if (ep->cma_id->qp){
		rdma_destroy_qp(ep->cma_id); /* returns void */
		ep->cma_id->qp = NULL;
	}
	
	if (ep->send_cq.cq){
		ret = ib_destroy_cq(ep->send_cq.cq);
		if (0 != ret) {
			rna_printk(KERN_ERR, "ib_destroy_cq failed, "
			           "ret=%d, ep=%p\n", ret, ep);
		}
		ep->send_cq.cq = NULL;		
	}
	
	if (ep->recv_cq.cq){
		ret = ib_destroy_cq(ep->recv_cq.cq);
		if (0 != ret) {
			rna_printk(KERN_ERR, "ib_destroy_cq failed, "
			           "ret=%d, ep=%p\n", ret, ep);
		}
		ep->recv_cq.cq = NULL;		
	}

	repost_uncompleted_ops(ep);
	
	return;
}



static int disconnect_handler(struct com_ep *ep)
{
	int wakeup=0;

	if (atomic_read(&ep->ep_state) != EP_DISCONNECT_PENDING) {
		rna_printk(KERN_ERR,
                   "Error: Expected ep[%p] to be in state[%d] current state[%d] "
                   "global connection count [%d]\n", 
                   ep, 
				   EP_DISCONNECT_PENDING,
				   atomic_read(&ep->ep_state),
                   atomic_read(&ep->transport_handle->connection_count));
		return 0;
	} else {
        rna_trace("disconnect handler ep %p state %d\n", 
                   ep, 
                   EP_DISCONNECT_PENDING);
    }
	
	if (ep->connected == 1) {
		if (connection_count_dec_and_test(ep->transport_handle)){
			wakeup = 1;
		}
	}
	
    rna_spin_lock(ep->transport_handle->ep_dsc_lock);
	ep->connected = 0;
    rna_spin_unlock(ep->transport_handle->ep_dsc_lock);

	com_disconnect(ep);
	
	com_destroy_ib_conx(ep);

	rna_spin_lock(ep->transport_handle->ep_dsc_lock);
	/*
	 * Invoke the disconnect callback only if the connect callback has been
	 * invoked or our initial connection is failing here.
	 */
	if ((CB_CONNECTED == ep->callback_state) ||
        (CB_INIT == ep->callback_state)){
		/* Indicate that the disconnect_cb, if defined, is about to be invoked */
		ep->callback_state = CB_DISCONNECTED;
		rna_spin_unlock(ep->transport_handle->ep_dsc_lock);
		if (ep->com_attr.disconnect_cb) {
			(*ep->com_attr.disconnect_cb)(ep, ep->context);
		}
	} else {
		/*
		 * Either com_connect_sync() on this ep has timed out (CB_FAILED), or 
         * the disconnect callback has already been invoked (CB_DISCONNECTED,
		 * shouldn't happen).  Don't invoke an unexpected callback.
		 */
		rna_spin_unlock(ep->transport_handle->ep_dsc_lock);
	}

	if (atomic_cmpxchg(&ep->ep_state, EP_DISCONNECT_PENDING,EP_DISCONNECTED) != 
        EP_DISCONNECT_PENDING){
		rna_printk(KERN_ERR,
                   "Error: EP[%p] state changed and shouldn't have. "
                   "Expected[%d] Current State[%d]\n",
                   ep,
                   EP_DISCONNECT_PENDING,
                   atomic_read(&ep->ep_state));
	}
    rna_trace("ep [%p] connection_count %d\n", 
               ep,
               atomic_read(&ep->transport_handle->connection_count));

	/* free EP in both active/passive case 
	 * this way the application doesn't need to keep track of it
	 */

	/*
	 * Let com_connect_sync() and com_wait_connected know about the
	 * state change.
	 */
	wake_up_all(&ep->conn_wait);
	
	com_release_ep(ep);

	if (1 == wakeup) {
		wake_up_all(&ep->transport_handle->all_disconnected_wait);
    }
	return 0;
}

/* This routine scans the ep free list for entities that have had
   all the underlying resources released. 
 */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
void cleanup_work( void * data)
#else
void cleanup_work( struct work_struct *work)
#endif
{   
	struct com_ep *ep=NULL, *temp_ep=NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
	//struct rna_com *com_handle = (struct rna_com*) ((struct work_struct*) work)->data;
	struct rna_transport_handle *com_handle = (struct rna_transport_handle*) data;
#else
	struct rna_transport_handle *com_handle = container_of(work, struct rna_transport_handle, clean_work);
#endif
	struct list_head local_free_lst_head;

	INIT_LIST_HEAD(&local_free_lst_head);
	
	BUG_ON(NULL == com_handle);

	mutex_lock(&com_handle->ep_lst_lock);

	/* Scan the free list for fully disconnected EPs */
	list_for_each_entry_safe(ep, temp_ep, &com_handle->ep_lst_head, entries) {
		if(check_ep_free_state(ep)){
			/* Move entry from global free list to local free list */
			list_del(&ep->entries);
			list_add(&ep->free_entry,&local_free_lst_head);
		}
	}

	mutex_unlock(&com_handle->ep_lst_lock);
	
	/* Delete all the qualified entries from the local free list */
	list_for_each_entry_safe(ep, temp_ep, &local_free_lst_head, free_entry) {
		list_del(&ep->free_entry);
		free_ep(ep);
	}
	
	return;
}


/* Syncronizes disconnect work. Only one call to this for each ep will
   succeed. The state is advanced to DISCONNECT_PENDING and a work req
   is added to the queue.
*/

void queue_disconnect_work(struct com_ep *ep)
{
	int state;
	unsigned long flags;
	
	if (is_shutting_down(ep->transport_handle)) {
		return;
	}

	state = atomic_read(&ep->ep_state);
	
	/* Note: We syncronize on the state variable. If the state has already
	 * been advanced to any of these we don't  need to queue the work. 
	 * Double queueing of the work can be catastrophic. */
	if((state == EP_DISCONNECT_PENDING) || 
	   (state == EP_DISCONNECTED) || 
	   (state == EP_FREE)) {
		return;
	}

	/* Drop long-held reference. */
    try_state_disconnect(ep);
}

static inline
void queue_cleanup_work(struct rna_transport_handle* com_handle)
{
	struct work_struct* clean_work;

	BUG_ON(NULL == com_handle);

	if (is_shutting_down(com_handle)) {
		return;
    }

	clean_work = &com_handle->clean_work;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
	clean_work->data = com_handle;
#endif

	//ep->com_handle->clean_work.data = ep->com_handle;	
	rna_queue_work(com_handle->rna_clean_workq, clean_work);
}

static int post_all_recvs(struct com_ep *ep)
{
	struct ib_recv_wr recv_wr, *bad_wr;
	struct ib_sge		sge;
	uint64_t	recv_buf_dma;
	void	*recv_buf;
	int	len, i, ret=0;
	
	struct buf_entry *buf;
	
	recv_buf_dma = ep->recv_pool.mem_dma;
	len = ep->recv_pool.buf_size + sizeof(struct rna_com_envelope);
	
	sge.length = len;
	
	recv_wr.sg_list = &sge;
	recv_wr.num_sge = 1;
	recv_wr.next = NULL;
	
	for (i = 0; i < ep->num_recv && !ret; i++ ) {
		if(!ep->recv_pool.entries[i]->mr){
			ret = -1;
			rna_printk(KERN_ERR,"MR is for ep[%p] NULL!\n",ep);
			break;
		}
		if(!ep->recv_pool.entries[i]->mr){
			ret = -1;
			rna_printk(KERN_ERR,"MR [%d] is for ep[%p] NULL!\n", i, ep);
			break;
		}
		sge.lkey = ep->recv_pool.entries[i]->mr->lkey;
		sge.addr = ep->recv_pool.entries[i]->mem_dma;
		buf = (ep->recv_pool.entries[i]);
		buf->op_type = POST_RECV;
		recv_wr.wr_id = (uint64_t)buf;
		ret = ib_post_recv(ep->cma_id->qp, &recv_wr, &bad_wr);
		if (ret) {
			printk("failed to post receives: %d\n", ret);
			break;
		}
		atomic_inc(&ep->recv_posted);
	}
	return ret;
	
}

static int post_recv(struct com_ep *ep, struct buf_entry *buf)
{	
	struct ib_recv_wr recv_wr, *bad_wr;
	struct ib_sge		sge;
	
	int	len, ret=0;
	
	len = ep->recv_pool.buf_size + sizeof(struct rna_com_envelope);
	buf->op_type = POST_RECV;
	sge.length = len;
	sge.addr = buf->mem_dma;
	sge.lkey = buf->mr->lkey;
	
	recv_wr.sg_list = &sge;
	recv_wr.num_sge = 1;
	recv_wr.next = NULL;
	recv_wr.wr_id = (uint64_t)buf;
	
	ret = ib_post_recv(ep->cma_id->qp, &recv_wr, &bad_wr);
	if (ret) {	
		printk("fldc: failed to post receives: %d\n", ret);
	} else {
		inc_unacked_recvs(ep);
		atomic_inc(&ep->recv_posted);
	}
	return ret;
	
}
static int total_recvd=0;

static int
recv_completion(struct com_ep *ep, struct ib_wc *wc)
{
	int ret = 0;
    int saved_ret = 0;

	/* Receives are always associated with a buf_entry. */
	struct buf_entry *recv_buf = (typeof(recv_buf)) wc->wr_id;

	BUG_ON(NULL == recv_buf);

	if (!ep) {
		rna_printk(KERN_ERR, "EP=NULL wc[%p]!!\n",wc);
		goto error;
	}
    atomic64_inc(&ep->ep_num_recvs);
	// TODO: Potential race on the state? 
	//       Because the state could transition at any time we 
	//       could attempt to repost the recv buffer to a downed 
	//       connection. If this occurs this could be the cause of 
	//       MVP-965 or MVP-
	if((!wc->status) && (atomic_read(&ep->ep_state) == EP_CONNECTED)){
		atomic_dec(&ep->recv_posted);
		com_process_acks(ep, recv_buf->env);

		rna_trace("fldc_com: recv completion ep %p\n",ep);

		total_recvd++;
		rna_trace("total recvd %d\n",total_recvd);
		
		if (recv_buf->env->msg_type == ENV_TYPE_PROTO) {
			if (ep->com_attr.recv_cmp_cb) {
				ret = (*ep->com_attr.recv_cmp_cb)(ep, ep->context, 
                                                  recv_buf->mem, 
                                                  (wc->byte_len - 
                                                   sizeof(struct rna_com_envelope)), 
                                                  com_ib_status_to_cb_resp(wc->status));
			}
		} else if (recv_buf->env->msg_type == ENV_TYPE_ACK) {
			/* nothing to do */
		} else if (recv_buf->env->msg_type == ENV_TYPE_RDMA) {
            ret = ib_process_rdma_req(ep,
                                      recv_buf->env,
                                      recv_buf->mem,
                                      recv_buf->mem + sizeof(struct com_rdma_msg),
                                      wc->byte_len - sizeof(struct rna_com_envelope)
                                                   - sizeof(struct com_rdma_msg));
		} else {
			rna_printk(KERN_ERR, "rna: ep[%p] msg_type[%d] unsupported\n", 
                       ep, recv_buf->env->msg_type);
		}
        
        saved_ret = ret; /* Save so we can report this if needed. */
		ret = post_recv(ep, recv_buf);
		if (ret) {
			rna_printk(KERN_ERR, "rna: ep[%p] state[%d] post recv error[%d]\n", 
                       ep, atomic_read(&ep->ep_state), ret);
            goto error;
		} else {
            ret = saved_ret;
        }
	} else {
		if (atomic_dec_and_test(&ep->recv_posted)) {
			wake_up_all(&ep->recv_cq.wait_obj);
			queue_cleanup_work(ep->transport_handle);
		}
		
        if (!wc->status) {
            if (recv_buf->env->msg_type == ENV_TYPE_PROTO) {
                if (ep->com_attr.recv_cmp_cb) {
                    ret = (*ep->com_attr.recv_cmp_cb)(ep, ep->context,
                                    recv_buf->mem, wc->byte_len,
                                    com_ib_status_to_cb_resp(wc->status));
                }
            }
        } else {
            /*
             * Currently errors besides IB_WC_WR_FLUSH_ERR are being
             * logged in process_single_completion().  So don't log again
             * for those errors.
             */
            if (wc->status == IB_WC_WR_FLUSH_ERR) {
                rna_printk(KERN_ERR, "recv error for dest ["
                            NIPQUAD_FMT"], status [%d], vendor_err [0x%x], "
                            "ep state [%d], recv [%d], sends [%d], rdmas [%d], "
                            "wr_id = [0x%"PRIx64"]\n",
                            NIPQUAD(ep->dst_in.sin_addr.s_addr),
                            wc->status,
                            wc->vendor_err,
                            atomic_read(&ep->ep_state),
                            atomic_read(&ep->recv_posted),
                            atomic_read(&ep->send_posted),
                            atomic_read(&ep->rdma_posted),
                            wc->wr_id);
			} 
        }

		rna_trace("recv_posted %d ep:%p wc->status[%d]\n",
		          atomic_read(&ep->recv_posted), ep, wc->status);
	}
		
error:
	return ret;		
}

/* If there was a send buffer associated with this request,
 * use that as the third argument to the callback and the ep's 
 * context as the second.  Otherwise, we use the pointer
 * associated with this request as the context. */
static int send_completion(struct com_ep *ep, struct ib_wc *wc)
{
    int ret = 0;
    struct buf_entry *send_buf = (typeof(send_buf)) wc->wr_id;
    uint64_t ctx = 0;
    SEND_CMP_CB cb = ep->com_attr.send_cmp_cb;

    atomic64_inc(&ep->ep_num_sends);
    ctx = (typeof(ctx)) send_buf->context;
    if (NULL != send_buf->send_cmp_cb) {
        cb = send_buf->send_cmp_cb;
    }

    if (0 == com_put_send_buf(ep, send_buf)) {
        if (cb) {
            if (0 != wc->status) {
                rna_printk(KERN_ERR, "ep [%p] context [%p] ctx [0x%"PRIx64
                           "] status [%d->%d]\n",
                           ep, ep->context, ctx, wc->status,
                           com_ib_status_to_cb_resp(wc->status));
            }
            ret = (cb) (ep, ep->context, (void*) ctx, 
                        com_ib_status_to_cb_resp(wc->status));
        }

        if (atomic_dec_and_test(&ep->send_posted)) {
            if (wc->status) {
                queue_cleanup_work(ep->transport_handle);
            }
        }
    }
    wake_up_all(&ep->send_cq.wait_obj);

    return ret;	
}

static void
com_put_rdma_buf_internal(struct com_ep *ep, struct buf_entry *buf,
                          boolean rdma_posted)
{
    unsigned long irqflags;
    ib_com_buf_data_t *buf_data;

    BUG_ON(NULL == ep);
    BUG_ON(NULL == buf);
    BUG_ON(!buf->is_rdma_buf);

    /* test the extra_completions value only when this ep is connected */
    BUG_ON((0 != atomic_read(&buf->extra_completions)) &&
                (atomic_read(&buf->ep->ep_state) == EP_CONNECTED));
    atomic_set(&buf->extra_completions, 0);
#ifdef RNA_Z_COPY
    if (buf->zcopy_dma) {
        if (!ep->cma_id || !ep->cma_id->device){
            rna_printk(KERN_ERR,"cma_id/device is NULL for ep[%p]\n",ep);
        } else {
            ib_dma_unmap_single(ep->cma_id->device,
                                buf->zcopy_dma,
                                buf->dma_size,
                                buf->direction);
            com_unregister_mr(ep, &buf->zcopy_mr);
        }
        buf->zcopy_dma = 0;
    }
#endif

    if (NULL != buf->rdma_send_buf) {
        /* note this can happen in certain error paths */
        rna_printk(KERN_ERR, "freeing still attached rdma_send_buf for "
                   "buf [%p]\n", buf);
        com_put_send_buf(ep, buf->rdma_send_buf);
        buf->rdma_send_buf = NULL;
    }

    if (0 != buf->bounce_address) {
        kernel_com_release_bounce_buffer(buf);
    }
    rna_spin_lock_irqsave(ep->rdma_lock, irqflags);

    buf->rem_addr.device_id.data = 0;
    buf->rem_addr.base_addr = 0;

    buf_data = (ib_com_buf_data_t *)buf->buf_transport_data;
    if (NULL != buf_data->icb_sglp) {
        mempool_free(buf_data->icb_sglp, ibsgl_pool);
        buf_data->icb_sglp = NULL;
    }

    if (rdma_posted) {
        atomic_dec(&ep->rdma_posted);
    }

    com_mark_rdma_buf_free(buf);

    atomic_inc(&ep->rdma_avail);
    wake_up_all(&ep->rdma_wait);

    if (0 == atomic_read(&ep->rdma_posted)
        && (EP_FREE == atomic_read(&ep->ep_state))) {
        queue_cleanup_work(ep->transport_handle);
    }

    rna_spin_unlock_irqrestore(ep->rdma_lock, irqflags);
}

void
com_put_rdma_buf(struct com_ep *ep, struct buf_entry *buf)
{
    com_put_rdma_buf_internal(ep, buf, TRUE);
}

void
com_put_rdma_buf_external(struct com_ep *ep, struct buf_entry *buf)
{
    com_put_rdma_buf_internal(ep, buf, FALSE);
}

static int
_rdma_completion(struct com_ep *ep, struct ib_wc *wc, boolean fake)
{
    struct com_ib_bb_ctxt *bb_ctxt = BB_CTXTP(ep);
    struct rna_transport_handle *com_handle = ep->transport_handle;
    struct buf_entry *buf = (typeof(buf)) wc->wr_id;
    uint64_t ctx = 0;
    int ret=0;
    /* If wc->status is non-zero, then wc->opcode is undefined */
    int write_op = (RDMA_WRITE == buf->op_type) || 
                   (RDMA_WRITE_SGL == buf->op_type);

    BUG_ON(NULL == com_handle);
    BUG_ON(NULL == buf);	

    ctx = (typeof(ctx)) buf->context;
    /* This better be either a read or a write */
    BUG_ON(!write_op && !((RDMA_READ == buf->op_type) || 
                          (RDMA_READ_SGL == buf->op_type)));

    if (wc->status) {
        buf->comp_status = wc->status; // save status for final completion
        rna_printk(KERN_DEBUG,
                   "rdma_%s_completion: ERROR [%d] vendor_err [0x%x] "
                   "rdma_buf [0x%p] rem_addr [0x%"PRIx64":%"PRIx64"] "
                   "rkey [0x%"PRIx64"] rdma_length [%d] rdma_posted [%d]\n", 
                   write_op ? "write" : "read",
                   wc->status,
                   wc->vendor_err,
                   buf, 
                   buf->rem_addr.device_id.data, 
                   buf->rem_addr.base_addr,
                   buf->rkey, 
                   buf->length, 
                   atomic_read(&ep->rdma_posted));
        if (fake) {
            rna_printk(KERN_ERR,
                       "rdma_buf [0x%p] failed msg portion of bounce "
                       "buffer %s: status [%d]\n", buf,
                       write_op ? "write" : "read", wc->status);
        }
    }

    if (NULL != bb_ctxt) {
        /* gather timing info */
        if (write_op) {
            if (TRUE == fake) {
                if (0 != buf->bounce_rdma_start) {
                    rna_atomic64_add(
                                 getrawmonotonic_ns() - buf->bounce_rdma_start,
                                 &bb_ctxt->bbc_write_rdma_wait);
                    buf->bounce_rdma_start = 0;
                }
            } else {
                if (0 != buf->bounce_send_start) {
                    rna_atomic64_add(
                                 getrawmonotonic_ns() - buf->bounce_send_start,
                                 &bb_ctxt->bbc_write_send_wait);
                    buf->bounce_send_start = 0;
                }
            }
        } else {
            if (TRUE == fake) {
                if (0 != buf->bounce_rdma_start) {
                    atomic64_add(getrawmonotonic_ns() - buf->bounce_rdma_start,
                             &bb_ctxt->bbc_read_rdma_wait);
                    buf->bounce_rdma_start = 0;
                }
            } else {
                if (0 != buf->bounce_send_start) {
                    atomic64_add(getrawmonotonic_ns() - buf->bounce_send_start,
                                &bb_ctxt->bbc_read_send_wait);
                    buf->bounce_send_start = 0;
                }
            }
        }
    }

    if (1 == atomic_cmpxchg(&buf->extra_completions, 1, 0)) {
        /* 
         * One phase of a bounce buffer I/O finished.  Don't call completion
         * callback until both phases finish.
         */
        atomic_dec(&ep->rdma_posted);
    } else {

        buf->bounce_send_start = 0;
        buf->bounce_rdma_start = 0;
        /*
         * If bad rkey then don't complete the rdma and return
         * the non-zero status to get an early disconnect.
         */
        if (buf->comp_status != CB_RESP_INVALID_RKEY) {
            com_complete_rdma_op(ep, buf,
                                 com_ib_status_to_cb_resp(buf->comp_status));
        }
    }
    /*
     * For now, return the error even if we're still waiting for the 2nd
     * phase completion.  (Currently _fake_rdma_completion() is the only
     * one who looks at the return status, and we want it to be able to
     * initiate a disconnect even if the operation isn't fully complete.)
     */
    return buf->comp_status;		
}

/* Used by process_single_completion. We typically see a lot of bogus opcodes
 * when we disconnect an EP and all the receives get posted back to us.  We
 * filter these out so we aren't overwhelemed by printks. */
static void __check_opcode(struct com_ep *ep, enum ib_wc_opcode expected, 
                           struct ib_wc* wc, const char *loc) 
{
#ifdef VERBOSE_LOGS
	if (likely(0 == wc->status) && unlikely(expected != wc->opcode)) {
        /* 
         * opcode is not valid if status is non-zero, so only check the 
         * opcode against expected if status is 0.
         */
		if (expected != IB_WC_RECV) {
			rna_printk(KERN_ERR, "[%s] Caught bogus opcode [0x%x] on ep [%p]. "
			           "Expected [0x%x]\n", loc, wc->opcode, ep, expected);
		} else {
			rna_printk(KERN_DEBUG, 
                       "[%s] Caught bogus recv opcode [0x%x] "
                       "on ep [%p]. Expected [0x%x].\n", 
                       loc, wc->opcode, ep, expected);
		}
	}
#endif
}
#define check_opcode(EP, EXPECTED, WCP)             \
    __check_opcode(EP, EXPECTED, WCP, __location__)

void
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
ib_com_run_completion(void *arg)
#else
ib_com_run_completion(struct work_struct *arg)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
    struct work_struct *w = (struct work_struct *)arg;
    struct ib_work *ibw = w->data;
#else
    struct ib_work *ibw = container_of(arg, struct ib_work, w);
#endif
	struct com_ep *ep = ibw->ep;
	struct buf_entry *buf;

    buf = (typeof(buf)) ibw->wc.wr_id;

    if (try_state_lock(ep)) {
        BUG_ON(ep == NULL);
        rna_trace("Running completion EP[%p] type[%d]\n", ep, buf->op_type);
        switch(buf->op_type){
        case POST_RECV:
            rna_trace("Recv completion EP[%p]\n",ep);
            check_opcode(ep, IB_WC_RECV, &ibw->wc);
            recv_completion(ep, &ibw->wc);
            atomic_dec(&ep->ep_recv_queued);
            break;
        case POST_SEND:
            rna_trace("Send completion EP[%p]\n",ep);
            check_opcode(ep, IB_WC_SEND, &ibw->wc);
            send_completion(ep, &ibw->wc);
            break;
        default:
            /* WRITE completions don't get queued */
            rna_printk(KERN_ERR,
                       "Unexpected type for completion [%d]\n",
                       buf->op_type);
        }
        state_unlock(ep);
    }

    /* Release reference from ib_com_queue_completion() */
    com_release_ep(ep);
    return;
}

static int 
ib_com_queue_completion(struct com_ep *ep,
                        struct ib_wc *wc)
{
    struct ib_work *ibw;
	struct buf_entry *buf;
	
	BUG_ON(NULL == ep);

    /* 
     * Take a reference on the ep so that it is not freed while we 
     * have something queued on it.
     */
    com_inc_ref_ep(ep);
	buf = (typeof(buf)) wc->wr_id;
    RNA_INIT_WORK(&buf->ibw.w, ib_com_run_completion, &buf->ibw);
    buf->ibw.ep = ep;
    buf->ibw.wc = *wc;
    rna_queue_work(ep->ep_comp_wq, &buf->ibw.w);
    return 0;
}

/* Called by __cq_work_handler to handle 
 * a single completion off one of the ep's CQs. */
int 
process_single_completion(struct com_ep* ep, struct ib_wc* wc, 
                          int *do_disconnect)
{
	int ret = 0;
	int opcode;
	struct buf_entry *buf;

	BUG_ON(NULL == ep);
	BUG_ON(NULL == wc);

	if (wc->status) {
		if (atomic_read(&ep->ep_state) == EP_CONNECTED) {
			if (wc->status != IB_WC_WR_FLUSH_ERR) {
				rna_printk(KERN_ERR, "cq completion failed for dest ["
                           NIPQUAD_FMT"], status [%d], vendor_err [0x%x], "
                           "ep state [%d], recv [%d], sends [%d], rdmas [%d], "
                           "wr_id = [0x%"PRIx64"]\n",
                           NIPQUAD(ep->dst_in.sin_addr.s_addr),
                           wc->status,
                           wc->vendor_err,
                           atomic_read(&ep->ep_state),
                           atomic_read(&ep->recv_posted),
                           atomic_read(&ep->send_posted),
                           atomic_read(&ep->rdma_posted),
                           wc->wr_id);
			} 

			if (wc->status == IB_WC_RETRY_EXC_ERR) {
				rna_trace("IB_WC_RETRY_EXC_ERR dest %u.%u.%u.%u, "
				          "ep_state %d, rem_qpn %d rem_qkey %d\n",
				          NIPQUAD(ep->dst_in.sin_addr.s_addr),
				          atomic_read(&ep->ep_state),
				          ep->remote_qpn,
				          ep->remote_qkey);

			}

			if (NULL != do_disconnect) {
				*do_disconnect = TRUE;
			}
		}
		ret = wc->status;
	}
	
	buf = (typeof(buf)) wc->wr_id;

	switch (buf->op_type) {
		case POST_RECV:
			check_opcode(ep, IB_WC_RECV, wc);
            if (in_interrupt()
                || (ep->sync_recvq && atomic_read(&ep->ep_recv_queued) > 0)) {
                atomic_inc(&ep->ep_recv_queued);
                ib_com_queue_completion(ep, wc);
            } else {
                ret = recv_completion(ep, wc); 
                rna_trace("fldc_com_ib: recv_completion ret %d\n",ret);
            }
			break;

		case POST_SEND:
			check_opcode(ep, IB_WC_SEND, wc);
            if (in_interrupt()) {
                ib_com_queue_completion(ep, wc);
            } else {
                send_completion(ep, wc);
            }
			break;

		case RDMA_READ:
		case RDMA_READ_SGL:
			check_opcode(ep, IB_WC_RDMA_READ, wc);
            _rdma_completion(ep, wc, FALSE);
			break;

		case RDMA_WRITE:
		case RDMA_WRITE_SGL:
			check_opcode(ep, IB_WC_RDMA_WRITE, wc);
			 _rdma_completion(ep, wc, FALSE);
			break;

		default:
			rna_printk(KERN_ERR, "unknown completion type %d!\n",
			           wc->opcode);
			ret = -1;
			break;
	}
	return ret;
}


/* Processes the notifications in a completion queue.
 *
 * This will always process at least as many completions as were in
 * the wc when this was called, and if any remain, it will add itself
 * back onto rna_workq so it can finish polling them later. 
 *
 * Wc_array is just a big chunk of uninitialized data that we pass
 * to ib_poll_cq.
 *
 * Note: This routine will deref the ep associated with the cq. The caller
 *       MUST have taken a reference on the ep before calling this.
 **/

static int __cq_work_handler(
		struct ib_cq *cq, 
		struct cq_ctx *cq_ctx, 
		struct ib_wc* wc_array, 
		int wc_array_size)
{
	struct com_ep	*ep = cq_ctx->ep;
	int ret=0;
	int n=0, i;

	/* Number of completions we're willing to handle at one time.
	 * We may process more than this, though, if sync is true, and 
	 * another thread incremented in_progress. */
	int wc_max_count = 0;

	/* number of completions processed since restarting */
	int wc_count;

	/* If true, we only allow one thread to process the cq at a time */
	int sync = (ep->sync_recvq) && (&ep->recv_cq == cq_ctx);
	int do_disconnect = FALSE;

#ifdef WARN_ON_POLL_LATENCY
	int count=0;
	rna_timeoffset start_time;
	unsigned long long latency;
	char* type_string;

	start_clock(&start_time);
#endif

	/* If this lock is not available then the cq is being destroyed, so don't bother to spin 
	 * NOTE: If the write_lock(&ep->ep_state_lock) is called anywhere else then this breaks. Due to 
	 *       the fragility of the code this should be refactored. This patch is in response to 
	 *       MVP-4427. 
	 */
	if(!try_state_lock(ep)){
        rna_printk(KERN_DEBUG,
                  "__cq_work_handler can't get state lock for ep [%p]\n",
                  ep);
		com_release_ep(ep);
		return 0;		
	}
	
	/* This protects accessing a cq that has been destroyed because of a disconnect. This 
	   may occur if this routine is part of a work queue that had a backlog during the disconnect */
	if ((ep->recv_cq.cq != cq) && (ep->send_cq.cq != cq)) {
		rna_printk(KERN_INFO,"EP[%p] CQ[%p] has no association cq_ctx[%p]\n",ep,cq,cq_ctx);	
		state_unlock(ep);
		com_release_ep(ep);
		return 0;	
	}
	
	//rna_trace(KERN_INFO, "sync = %d, array_size = %d\n", sync, wc_array_size);
	
	/* Syncronizes the recv queue by allowing only one thread to 
	 * process it at a time. This keeps write_update messages in order.
	 * 
	 * If the current process doesn't get into the loop because 
	 * in_progress was nonzero, it doesn't need to decrement 
	 * in_progress because the process that _is_ in the loop
	 * will reset the counter and re-poll the cq.
	 *
	 * Note: in_progress is really just a tri-state variable
	 * pretending to be a counter.  Any value > 1 is equivalent. */

	if (sync && (atomic_inc_return(&ep->in_progress) != 1) ) {
		ret = 0;
	} else {
		/* We try to process as many requests as can be posted 
		 * to the cq at one time (as indicated by the num_[recv,send]
		 * field of the ep).  If more arrive in the mean time, we'll 
		 * just add ourself back on to the work queue.

		 * We could also use ib_peek_cq to find out what's been
		 * posted now, and only process that many. 

		 * When we shut down the EP, we get an event for all of
		 * the buffers.  By setting our quota one larger, we skip 
		 * having to re-queue in that case. */

		if (&ep->recv_cq == cq_ctx) {
			wc_max_count = ep->num_recv+1;
		} else if (&ep->send_cq == cq_ctx) {
			wc_max_count = ep->num_send+1;
		} else {
			BUG();
		}

		do {
			//rna_trace(KERN_INFO, "in outer loop, wc_max_count = %d\n", wc_max_count);

			/* 
             * If in_progress is more than 1, we can reduce
			 * it to 1 so we don't loop needlessly. 
             */
			if (sync) {
				atomic_set(&ep->in_progress, 1);
            }
			wc_count = 0;

			do {
				//rna_trace(KERN_INFO, "in inner loop wc_count = %d\n", wc_count);

				n = ib_poll_cq(cq, wc_array_size, wc_array);
				if (n < 0) {
					rna_printk(KERN_ERR, "ib_poll_cq returned error %d\n", n);
					break;
				}
				wc_count += n;
				for (i = 0; i < n; ++i) 
				{
#ifdef WARN_ON_POLL_LATENCY
					count++;
#endif
					process_single_completion(ep, &wc_array[i], &do_disconnect);
				}
		
			} while ((wc_count < wc_max_count) && (n == wc_array_size));
		} while (sync && (atomic_dec_return(&ep->in_progress) > 0));

		/* Re-queue ourselves if we've exhausted our work quota. */
		if (wc_count >= wc_max_count) {
            rna_trace("too many completions to process at one time, "
                      "re-queueing completion handler. wc_count [%d] "
                      "wc_max_count [%d] n [%d] wc_array_size [%d]\n",
                      wc_count, wc_max_count, n, wc_array_size);
			com_inc_ref_ep(ep);
			rna_queue_work(ep->transport_handle->rna_workq, &cq_ctx->work);
		}
	}

#ifdef WARN_ON_POLL_LATENCY

	latency = stop_clock(&start_time);
	
	if(latency > POLL_WARN_LAT) {
		if(&ep->recv_cq == cq_ctx) {
			type_string = "RECV";
		} else if(&ep->send_cq == cq_ctx) { 
			type_string = "SEND";
		} else {
			type_string = "UNKNOWN";
		}
		rna_printk(KERN_ERR,
		           "rna: Warning processing ep[%p] "
		           "DEST["NIPQUAD_FMT"] Type[%d] %s CQ took " 
		           "%llu us. num messages[%d]\n",
		           ep,
		           NIPQUAD(ep->dst_in.sin_addr.s_addr),
		           ep->user_type,
		           type_string,
		           latency,
		           count);
	}
#endif

	state_unlock(ep);
	
	/* We defer the disconnect because queue_disconnect_work 
	 * updates ep->ep_state, and we'd rather not do that with the
	 * state_lock held. */
	if (do_disconnect) {
		queue_disconnect_work(ep);
	}

	com_release_ep(ep);
		
	return ret;
}

/* This doesn't use a per-cpu pre-allocated memory buffer to poll with, but
 * rather allocates the array off the stack.  Each ib_wc is 60 bytes or so,
 * therefore we can't allocate a very large array without eating
 * significantly into our limited 4k stack.
 * 
 * By not using a shared buffer, we can call this from more places than
 * we would be able to otherwise. 
 *
 * Note: __cq_work_handler() will deref the ep associated with the cq. The caller
 *       MUST have taken a reference on the ep before calling this.
 */
static int cq_work_handler_safe(struct ib_cq *cq, struct cq_ctx *cq_ctx)
{
	/* About 1200 bytes, or 1/3 of our stack. */
	struct ib_wc wc_array[20];

	return __cq_work_handler(cq, cq_ctx, wc_array, 20);
}


/* If this is called from the context of rna_workq, we can poll with
 * pre-allocated buffers (though currently we don't).  
 * Everyone else should use cq_work_handler_safe,
 * which may be a little slower as we use a smaller buffer. */

static int cq_work_handler(struct ib_cq *cq, struct cq_ctx *cq_ctx)
{
    return cq_work_handler_safe( cq,cq_ctx );
}

int com_poll_send_completion(struct com_ep *ep)
{
	com_inc_ref_ep(ep);
	return cq_work_handler_safe(ep->send_cq.cq, &ep->send_cq);
}

int com_poll_recv_completion(struct com_ep *ep)
{
	com_inc_ref_ep(ep);
	return cq_work_handler_safe(ep->send_cq.cq, &ep->recv_cq);
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
void rna_cq_work( void *work)
#else
void rna_cq_work( struct work_struct *work)
#endif
{    
	struct cq_ctx *cq_ctx = container_of((struct work_struct*)work, 
                                         struct cq_ctx, work);
	struct ib_cq *cq;
	int ret;
	
	/* cq may be NULL if we've disconnected and destroyed if before this
	   had a chance to run. Don't re-arm if this is the case */
	cq = cq_ctx->cq;
	if (!cq) {
		com_release_ep( cq_ctx->ep );
		return;
	}

	ret = ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);
	if (0 != ret) {
		rna_printk(KERN_ERR, "ib_req_notify_cq failed, ret=%d\n", ret);
	}

	cq_work_handler(cq, cq_ctx);

out:
	return;
}

void rna_completion_handler(struct ib_cq *cq, void *context)
{
    struct cq_ctx *cq_ctx = context;
    struct com_ep *ep     = cq_ctx->ep;	

    /* 
     * Note: We need to disable queueing any more work if we're
     * shutting down or disconnecting all eps. 
     */
    if (is_transport_handle_ok(ep->transport_handle)) {	
        /* 
         * We take a reference on the ep to avoid it being free'd if 
         * the workq gets stalled and the disconnect handler completes 
         */
        com_inc_ref_ep(ep);

        if (ep->transport_handle->comp_mode == COM_COMP_MODE_IRQ) {
            ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);
            cq_work_handler(cq, cq_ctx);
        } else {
            rna_queue_work(ep->transport_handle->rna_workq, &cq_ctx->work);
        }
    }
}

static int __attribute__((warn_unused_result)) get_device_context(struct com_ep* ep,
                              struct rdma_cm_id *cma_id,
                              struct device_context **device)
{
	int ret=0;
	struct device_context *dev = NULL;
	int	found=0;

	mutex_lock(&dev_lst_lock);
	
	list_for_each_entry(dev, &dev_lst_head, entries) {
		if (dev->ib_device->node_guid == cma_id->device->node_guid) {
			found = 1;
			break;
		}
	}
	
	if (!found) {
		/* This shouldn't happen under ordinary conditions.
		 * Maybe a device was added or removed. */
		rna_printk(KERN_ERR, "failed to find device with guid "
		           "[%"PRIx64"] in dev_lst\n", 
		           cma_id->device->node_guid);
		ret = -ENODEV;
	}	
	
	mutex_unlock(&dev_lst_lock);	
	*device = dev;
	return ret;
}

static void free_device_context(struct device_context *dev)
{
    int ret = 0;
    ret = ib_dealloc_pd(dev->pd);

    /* This often returns -16, but it seems to be innocuous. */
    if (0 != ret) {
        rna_printk(ret == -16 ? KERN_INFO : KERN_ERR, 
                   "ib_dealloc_pd returned %d\n", ret);
    }

    if(atomic_read(&dev->mr_registered)) {
        ret = ib_dereg_mr(dev->mr);
        if (0 != ret) {
            rna_printk(KERN_ERR, "ib_dereg_mr returned %d\n", ret);
        }
    }

    kfree(dev);
}


static void rna_async_cq_event_handler(struct ib_event *event, void *data)
{
}

static void rna_async_qp_event_handler(struct ib_event *event, void *data)
{
}


static int init_ep(struct com_ep *ep)
{
	struct ib_qp_init_attr init_qp_attr;
	int ret;
	struct device_context *dev;

	/* lookup PD from device context */
	ret = get_device_context(ep, ep->cma_id, &dev);
	if (ret) {
		ret = -ENOMEM;
		printk("fldc_com: unable to get device context: %d\n", ret);
		goto out;
	}

	/* PD and MR are the same for all EPs on this device */	
	ep->pd = dev->pd;
	ep->dev = dev;
	ep->mr = dev->mr;
	
	/* Setup the max_sge for this ep */
	ep->max_sge = min(dev->attr.max_sge, RNA_MAX_SGE);
	
	ep->send_cq.ep = ep;
	ep->recv_cq.ep = ep;
	RNA_INIT_WORK(&ep->send_cq.work, rna_cq_work, &ep->send_cq.work);
	RNA_INIT_WORK(&ep->recv_cq.work, rna_cq_work, &ep->recv_cq.work);
	
#ifdef OFED_1_2_5
	/* All CQs on this device use the same completion channel */
	ep->send_cq.cq = ib_create_cq(ep->cma_id->device, 
								rna_completion_handler,
								rna_async_cq_event_handler,
								&ep->send_cq,
								ep->num_send + ep->num_rdma, 0);

#else
	/* All CQs on this device use the same completion channel */
	ep->send_cq.cq = ib_create_cq(ep->cma_id->device, 
								rna_completion_handler,
								rna_async_cq_event_handler,
								&ep->send_cq,
								ep->num_send + ep->num_rdma);
#endif
	if (IS_ERR(ep->send_cq.cq)) {
		ret = -ENOMEM;
		printk("fldc_com: unable to create send CQ\n");
		ep->send_cq.cq = NULL;
		goto out;
	}
	
#ifdef OFED_1_2_5
	/* All CQs on this device use the same completion channel */
	ep->recv_cq.cq = ib_create_cq(ep->cma_id->device, 
								rna_completion_handler,
								rna_async_cq_event_handler,
								&ep->recv_cq,
								ep->num_recv, 0);
								
#else
	ep->recv_cq.cq = ib_create_cq(ep->cma_id->device, 
								rna_completion_handler,
								rna_async_cq_event_handler,
								&ep->recv_cq,
								ep->num_recv);
#endif
	if (IS_ERR(ep->recv_cq.cq)) {
		ret = -ENOMEM;
		printk("fldc_com: unable to create recv CQ\n");
		ep->recv_cq.cq = NULL;
		goto out;
	}
	
	rna_trace("successfully created PD and CQ\n");

		
	ret = ib_req_notify_cq(ep->send_cq.cq, IB_CQ_NEXT_COMP);
	if (ret) {
		printk("ib_req_notify_cq failed\n");
		ret = -ENOMEM;
		goto out;
	}

	ret = ib_req_notify_cq(ep->recv_cq.cq, IB_CQ_NEXT_COMP);
	if (ret) {
		printk("ib_req_notify_cq failed\n");
		goto out;
	}

	memset(&init_qp_attr, 0, sizeof init_qp_attr);
	init_qp_attr.cap.max_send_wr = ep->num_send + ep->num_rdma;
	init_qp_attr.cap.max_recv_wr = ep->num_recv;
	init_qp_attr.cap.max_send_sge = min(dev->attr.max_sge, RNA_MAX_SGE);
	init_qp_attr.cap.max_recv_sge = init_qp_attr.cap.max_send_sge;
	init_qp_attr.qp_context = ep;
	init_qp_attr.sq_sig_type = IB_SIGNAL_ALL_WR;
	
	init_qp_attr.send_cq = ep->send_cq.cq;
	init_qp_attr.recv_cq = ep->recv_cq.cq;
	init_qp_attr.event_handler = rna_async_qp_event_handler;
	
	/* Create unreliable connections with IB_QPT_UD, but that's 
	 * disabled for now while we think about how best to expose
	 * that option to the application. */
	init_qp_attr.qp_type = IB_QPT_RC;
		
	ret = rdma_create_qp(ep->cma_id, ep->pd, &init_qp_attr);
	if (ret) {
		rna_printk(KERN_ERR,
                   "unable to create QP: %d\n", ret);
		goto out;
	}
	rna_trace("init_ep: successfully created QP\n");

	if (ep->num_recv) {
		ret = com_alloc_buf_pool(ep, &ep->recv_pool, ep->num_recv, ep->buf_size);
		if (ret) {
			printk("fldc_com: unable to allocate recv pool <ep=0x%p> %d\n", ep, 
					ret);
			goto out;
		}
	}

	if (ep->num_send) {
		atomic_set(&ep->send_posted, 0);
		ret = com_alloc_send_buf_pool(ep, &ep->send_pool, ep->num_send, ep->buf_size);
		if (ret) {
			printk("fldc_com: unable to allocate send pool <ep=0x%p> %d\n", ep, 
					ret);
			goto out;
		}
        atomic_set(&ep->min_send_avail, atomic_read(&ep->send_pool.num_avail));
	}

	/* With 1, we sometimes run out of unsolicited ack send buffers.
	 * With 2, this should be rare. */
	ret = com_alloc_send_buf_pool(ep, &ep->credits_pool, CREDIT_BUFS, 0);
	if (ret) {
		rna_printk(KERN_ERR, "unable to allocate credit pool ep [%p]\n", ep);
		goto out;
	}
	if (ep->num_rdma) {
        int i;

		ret = com_alloc_rdma_pool(ep, ep->num_rdma, ep->rdma_buf_size);
		if (ret) {
			printk("fldc_com: unable to allocate rdma pool <ep=0x%p> %d\n", ep, 
					ret);
			goto out;
		}
        rna_printk(KERN_DEBUG, "allocated %d rdma bufs for ep [%p]\n", 
                   ep->num_rdma, ep);
	}
	
out:
	return ret;
}

static void connect_error(struct com_ep *ep)
{
	queue_disconnect_work(ep);
}

static int addr_handler(struct com_ep *ep)
{
	int ret;

    /* Synchronize with set_disconnecting() */
    mutex_lock(&ep->transport_handle->transport_state_lock);    
    if (!is_transport_handle_ok(ep->transport_handle)) {
        rna_printk(KERN_NOTICE, 
                   "ep [%p] shutting down, failing addr_handler()\n", ep);
        connect_error(ep);
    } else {
        ret = rdma_resolve_route(ep->cma_id, CONNECT_TIMEOUT);
        if (ret) {
            printk("fldc_com: resolve route failed: %d\n", ret);
            connect_error(ep);
        }
    }
    mutex_unlock(&ep->transport_handle->transport_state_lock);
	return 0;
}

static int route_handler(struct com_ep *ep)
{
	struct rdma_conn_param conn_param;
	struct req_priv_data priv_data;
	int ret;
	
	rna_trace("route_handler ep 0x%p\n", 
               ep);

    /* Synchronize with set_disconnecting() */
    mutex_lock(&ep->transport_handle->transport_state_lock);
    if (!is_transport_handle_ok(ep->transport_handle)) {
        rna_printk(KERN_NOTICE, 
                   "ep [%p] shutting down, failing route_handler()\n", ep);
        ret = -EFAULT;
        goto err;
    }

	ret = init_ep(ep);
	if (ret) {
		goto err;
    }
	ret = post_all_recvs(ep);
	if (ret) {
		goto err;
    }

	memset(&priv_data, 0, sizeof(priv_data));

	priv_data = (struct req_priv_data) {	
		.version = VERSION,
		.num_send = ep->num_send,
		.num_recv = ep->num_recv,
		.buf_size = ep->buf_size,
		.user_type = ep->user_type,
		.cpu_be = CPU_BE,
		.private_threads = 0,
		.min_proto_version = ep->com_handle->min_proto_version,
		.max_proto_version = ep->com_handle->max_proto_version,
        .bounce_buf_size = (NULL != BB_CTXTP(ep)) ? 
                              BB_CTXTP(ep)->bbc_buf_req_size :
                              0,
        .sync_flag = (uint8_t)ep->sync_recvq,
	};

	bswap_req_priv_data(&priv_data);

	memset(&conn_param, 0, sizeof conn_param);
	
	conn_param.responder_resources = 4;
	
#ifdef RDMA_INITIATOR_DEPTH_1
	conn_param.initiator_depth = 1;
#else
	conn_param.initiator_depth = 4;
#endif
	/* Note: retry_count of 7=infinite. See IB spec for other values */
	conn_param.retry_count = ep->transport_handle->retry_count;
	conn_param.rnr_retry_count = ep->transport_handle->rnr_retry_count;
	conn_param.private_data = &priv_data;
	conn_param.private_data_len = (u8) sizeof (priv_data);
	
	ret = rdma_connect(ep->cma_id, &conn_param);
	if (ret) {
		printk("fldc_com: failure connecting: %d\n", ret);
		goto err;
	}
    mutex_unlock(&ep->transport_handle->transport_state_lock);
	return 0;

err:
	connect_error(ep);
    mutex_unlock(&ep->transport_handle->transport_state_lock);
	return ret;
}

/*
 * This is an untested code path.  We don't currently support
 * listen in the kernel com.
 * TODO: set application protocol version
 */
static int connect_handler(struct rdma_cm_id *cma_id, 
                           struct req_priv_data *priv_data)
{
	struct com_ep *ep;
	struct com_ep *listen_ep = (struct com_ep*) (cma_id->context);
	struct rdma_conn_param conn_param;
	int ret;

	rna_trace("connect_req_handler \n");
	
	bswap_req_priv_data(priv_data);
	
	if (priv_data->version != VERSION) {
		ret = -EFAULT;
		goto err1;
	}

	/* TODO: figure out a clean way to set the context, if the library
	 * is allocating the ep rather than the application.  */
	ret = com_alloc_ep(listen_ep->com_handle,
	                   &listen_ep->com_attr,
	                   RC,
	                   NULL, 
	                   cma_id, 
	                   priv_data->num_send, priv_data->num_recv,
	                   priv_data->buf_size,
	                   0, 0, 
	                   priv_data->user_type,
                       0,
                       0, /* passive side doesn't specify bounce buffers */
                       0,
	                   &ep);	

	ep->passive = TRUE;
	ep->cpu_be = priv_data->cpu_be;

	/* since this is a passive EP re-set reference count to 0
	 * the ref count is set to 1 in com_alloc_ep so that
	 * active clients get a reference on the EP on allocation
	 */
	atomic_set(&ep->ref_count, 0);
	
	ret = init_ep(ep);
	if (ret)
		goto err2;
	
	if(atomic_cmpxchg(&ep->ep_state,EP_INIT,EP_CONNECT_PENDING) != EP_INIT){
		rna_printk(KERN_ERR,"Error: EP[%p] Expected state [%d] Current state[%d]\n",
                   ep,EP_INIT,atomic_read(&ep->ep_state));
		goto err2;
	}

	ret = common_proto_version(listen_ep->com_handle, priv_data, &ep->proto_version);
	if (ret < 0) {
		goto err2;
	}
	
	memset(&conn_param, 0, sizeof conn_param);

	conn_param.responder_resources = 4;

#ifdef RDMA_INITIATOR_DEPTH_1
	conn_param.initiator_depth = 1;
#else
	conn_param.initiator_depth = 4;
#endif

	conn_param.retry_count = ep->transport_handle->retry_count;
	conn_param.rnr_retry_count = ep->transport_handle->rnr_retry_count;
		
	ret = rdma_accept(ep->cma_id, &conn_param);
	if (ret) {
		printk("fldc_com: failure accepting: %d\n", ret);
		goto err2;
	}

	if(atomic_cmpxchg(&ep->ep_state,EP_CONNECT_PENDING,EP_CONNECTED) != EP_CONNECT_PENDING){
		rna_printk( KERN_ERR,"Warning: Connect complete Expected EP[%p] state[%d] Current state[%d]\n",
                    ep,EP_CONNECT_PENDING,atomic_read(&ep->ep_state) );
	}	
	
	rna_trace("connect_req_handler success, new ep 0x%p\n",
               ep);
	return 0;

err2:
	ep->cma_id = NULL;
	connect_error(ep);
err1:
	rna_printk(KERN_ERR,
               "fldc_com: failing connection request\n");
	rdma_reject(ep->cma_id, NULL, 0);
	return ret;
}


static char* cma_event_str(int code){

	switch (code) {

	case RDMA_CM_EVENT_ADDR_RESOLVED:
		return "RDMA_CM_EVENT_ADDR_RESOLVED";
	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		return "RDMA_CM_EVENT_ROUTE_RESOLVED";
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		return "RDMA_CM_EVENT_CONNECT_REQUEST";
	case RDMA_CM_EVENT_ESTABLISHED:
		return "RDMA_CM_EVENT_ESTABLISHED";
	case RDMA_CM_EVENT_DISCONNECTED:
		return "RDMA_CM_EVENT_DISCONNECTED";
	case RDMA_CM_EVENT_ADDR_ERROR:
		return "RDMA_CM_EVENT_ADDR_ERROR";
	case RDMA_CM_EVENT_ROUTE_ERROR:
		return "RDMA_CM_EVENT_ROUTE_ERROR";

	case RDMA_CM_EVENT_CONNECT_ERROR:
		return "RDMA_CM_EVENT_CONNECT_ERROR";

	case RDMA_CM_EVENT_UNREACHABLE:
		return "RDMA_CM_EVENT_UNREACHABLE";

	case RDMA_CM_EVENT_REJECTED:
		return "RDMA_CM_EVENT_REJECTED";

	case RDMA_CM_EVENT_MULTICAST_ERROR:
		return "RDMA_CM_EVENT_MULTICAST_ERROR";
	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		return "RDMA_CM_EVENT_DEVICE_REMOVAL";
	default:
		return "UNKNOWN";
		
	}
	
	return "";

}


static int rna_cma_handler(struct rdma_cm_id *cma_id, struct rdma_cm_event *event)
{
	int ret = 0;
	struct com_ep *ep;
	struct com_conx_reply *rep;
	
	ep = (struct com_ep*) (cma_id->context);

	rna_trace("event 0x%x cma_id %p ep %p\n", event->event, cma_id, ep);

	switch (event->event) {

	case RDMA_CM_EVENT_ADDR_RESOLVED:
		ret = addr_handler(ep);
		break;
	
	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		ret = route_handler(ep);
		break;

	case RDMA_CM_EVENT_CONNECT_REQUEST:
		ret = connect_handler(cma_id, 
							(struct req_priv_data*)event->param.conn.private_data);
		break;
		
	case RDMA_CM_EVENT_ESTABLISHED:
		if (event->param.conn.private_data_len <= sizeof(*rep)) {
			rna_printk(KERN_ERR,
			           "private_data_len [%d] shorter than expected\n",
			           event->param.conn.private_data_len);
		} else {
			rep = (typeof(rep)) event->param.conn.private_data;
            bounce_buffer_init(ep, rep);
			ret = connect_established(ep, rep->proto_version);
		}
		break;

	case RDMA_CM_EVENT_DISCONNECTED:
		queue_disconnect_work(ep);
		break;

	case RDMA_CM_EVENT_ADDR_ERROR:
	case RDMA_CM_EVENT_ROUTE_ERROR:
	case RDMA_CM_EVENT_CONNECT_ERROR:
	case RDMA_CM_EVENT_UNREACHABLE:
	case RDMA_CM_EVENT_REJECTED:
	case RDMA_CM_EVENT_MULTICAST_ERROR:
		rna_printk(KERN_ERR,"fldc_com: event: %s[%d], error: %d ep %p\n", 
		                     cma_event_str(event->event),
		                     event->event,
		                     event->status, 
		                     ep);
		/* TODO */
		ret = event->status;
		
		if (ep) {
			connect_error(ep);
		}
		break;
	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		/* TODO */
		break;
	default:
		break;
	}

	return 0;
}

void com_dump_ep_state(struct com_ep *ep)
{

	rna_printk(KERN_ERR,"EP[%p] USR_TYPE[%d] Remote["NIPQUAD_FMT":%d]\n",
	           ep,
			   ep->user_type,
			   NIPQUAD(ep->dst_in.sin_addr.s_addr),
			   ep->dst_in.sin_port);

	rna_printk(KERN_ERR,"posted recv %d send %d reads %d\n",
                atomic_read(&ep->recv_posted), atomic_read(&ep->send_posted), 
               atomic_read(&ep->rdma_posted));



				


}

int
check_ep_free_state(struct com_ep *ep)
{
	if ((EP_FREE != atomic_read(&ep->ep_state)) ||
		atomic_read(&ep->send_posted) || 
		atomic_read(&ep->rdma_posted)) {
		rna_trace("EP[%p] waiting on resources to be reposted.\n",ep);
		return FALSE;
	}
	
	return TRUE;
}



int free_ep(struct com_ep *ep)
{
	int state;

    /* Clean up completion workqueues */
    if (NULL != ep->ep_comp_wq) {
        rna_flush_workqueue(ep->ep_comp_wq);
        rna_destroy_workqueue(ep->ep_comp_wq);
        ep->ep_comp_wq = NULL;
    }
	com_free_buf_pool(ep, &ep->send_pool);
	com_free_buf_pool(ep, &ep->recv_pool);
	com_free_buf_pool(ep, &ep->credits_pool);
	com_free_rdma_pool(ep);
	
	ep_delete_proc(ep);
	
	rdma_destroy_id(ep->cma_id); /* returns void */
	ep->cma_id = NULL;

	rna_trace("ep %p [" NIPQUAD_FMT "] cleaning up: send/recv "
	          "recv [%d] send [%d] reads [%d] to be flushed\n",
	          ep, NIPQUAD(ep->dst_in.sin_addr.s_addr),
	          atomic_read(&ep->recv_posted), 
	          atomic_read(&ep->send_posted), 
	          atomic_read(&ep->rdma_posted));

	/* wake up any waiters on the connection event */
	wake_up_all(&ep->conn_wait);

	rna_trace("completed freeing ep %p\n", ep);

	kfree(ep);

	return 0;
}


static void free_all_eps(struct rna_transport_handle* com_handle)
{
	struct com_ep *ep, *temp_ep;
	
	mutex_lock(&com_handle->ep_lst_lock);

	rna_trace("start freeing all EPs\n");
	
	/* Force delete all active entries */
	/* Note: Under normal circumstances this list should be empty. Log message is 
	         for diagnositics and debugging. */
	list_for_each_entry_safe(ep, temp_ep, &com_handle->ep_lst_head, entries) {
		list_del(&ep->entries);
		if(atomic_read(&ep->ref_count)){
			rna_printk(KERN_ERR,"Cleaning up EP[%p] ref_count[%d]  state[%d] "
                       "recv_posted[%d]  send_posted[%d]  rdma_posted[%d]\n",
					   ep, 
					   atomic_read(&ep->ref_count),
					   atomic_read(&ep->ep_state),
					   atomic_read(&ep->recv_posted),
					   atomic_read(&ep->send_posted),
					   atomic_read(&ep->rdma_posted));
		}

		com_destroy_ib_conx(ep);
		free_ep(ep);
	}
	
	rna_trace("done feeing all EPs\n");
	mutex_unlock(&com_handle->ep_lst_lock);
}

void free_all_devices(void)
{
	struct device_context *dev, *next_dev;
	
	mutex_lock(&dev_lst_lock);

	list_for_each_entry_safe(dev, next_dev, &dev_lst_head, entries) {
		list_del(&dev->entries);
		free_device_context(dev);
	}
	
	mutex_unlock(&dev_lst_lock);
	
}

/* 
 * Allocate a new Communication Endpoint.
 * com_handle is the com context that the ep will be associated with.
 * com_attr is a pointer to a set of callbacks.  These aren't copied,
 *   so it's important they aren't freed as long as the ep exists.
 * context is a place to store application state associated with the 
 *   callbacks.
 */

int
transport_alloc_ep(struct com_ep *ep, int bounce_buffer_bytes, 
                   int bb_segment_bytes)
{
	int ret=0;
	struct rdma_cm_id *cma_id = ep->cma_id;
    struct rna_transport_handle *com = ep->transport_handle;

	BUG_ON(ep->transport_ops->transport_type != RC);

	rna_trace( "\n");
	if (unlikely(!com->initialized) || 
        !is_transport_handle_ok(ep->transport_handle)) {
		return -EFAULT;
    }

	rna_trace ("creating EP: send bufs [%d] recv bufs [%d]\n",
	           ep->num_send,
	           ep->num_recv);

	if (ep->buf_size < DEFAULT_RDMA_SENDBUF_SIZE) {
		ep->buf_size = DEFAULT_RDMA_SENDBUF_SIZE;
	}

	ep->connected = 0;
	ep->callback_state = CB_INIT;
	ep->max_sge = 1;
	atomic_set(&ep->ref_count, 1); /* One ref from the com layer, one ref for the client layer */
	atomic_set(&ep->ep_state,EP_INIT);
	atomic_set(&ep->in_progress,0);
	
	rwlock_init(&ep->ep_state_lock);
	/* TODO: Make this common across transports */
	rna_spin_lock_init(ep->rdma_lock);
	spin_lock_init(&ep->completed_list_lock);

	/* If no cma_id provided then create one - always on the active side of
	 * the connection
	 */
	if (!cma_id) {	
		//printk("fldc_com: rdma_create_id for RC context %p\n", ep);
#ifdef RDMA_CREATE_ID_FOUR_ARGS
		ep->cma_id = rdma_create_id(rna_cma_handler,
                                    ep,
                                    RDMA_PS_TCP,
                                    IB_QPT_RC);
#else
		ep->cma_id = rdma_create_id(rna_cma_handler, ep, RDMA_PS_TCP);
#endif
		if (!ep->cma_id) {
			ret = -ENOMEM;
			printk("fldc_com: unable to create cma_id\n");
			goto err;
		}
	}
	
	init_waitqueue_head(&ep->conn_wait);

	init_waitqueue_head(&ep->send_cq.wait_obj);

	init_waitqueue_head(&ep->recv_cq.wait_obj);
	init_waitqueue_head(&ep->rdma_wait);

    ep->ep_comp_wq = (ep->sync_recvq)
                        ? rna_create_singlethread_workqueue("fldc_ib_comp_wq")
                        : rna_create_workqueue("fldc_ib_comp_wq");
    if (!ep->ep_comp_wq) {
        ret = -ENOMEM;
        printk("fldc_com: unable to create ep_comp_wq\n");
        goto err;
    }
	ep->cma_id->context = ep;
	
	mutex_lock(&com->ep_lst_lock);
	list_add(&ep->entries, &com->ep_lst_head);
	mutex_unlock(&com->ep_lst_lock);

	ep_create_proc(ep, NULL);
    ep->bounce_buf_ctxt = kernel_allocate_ib_bb_ctxt(bounce_buffer_bytes, 
                                                     bb_segment_bytes);
	
	return 0;

err:
	rdma_destroy_id(ep->cma_id); /* returns void */
	return ret;
}

/* Find EP based on destination address  */
int transport_find_ep(struct rna_transport_handle* com_handle, 
                struct sockaddr *dst_addr, 
                struct com_ep **ep, uint8_t sync_flag)
{
	struct com_ep *ent;
	int ep_state;

	*ep = NULL;
	mutex_lock(&com_handle->ep_lst_lock);
	
	list_for_each_entry(ent, &com_handle->ep_lst_head, entries) {
		/* explicitly check for s_addr and port */
		if ( (((struct sockaddr_in*)ent->dst_addr)->sin_addr.s_addr ==
		     ((struct sockaddr_in*)dst_addr)->sin_addr.s_addr ) &&
		     ( ntohs(((struct sockaddr_in*)ent->dst_addr)->sin_port) ==
		     ((struct sockaddr_in*)dst_addr)->sin_port ) &&
			 (ent->sync_recvq == sync_flag)) {
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

	mutex_unlock(&com_handle->ep_lst_lock);
	
	if(*ep)
		return 0;
	
	return -1;
}

int com_wait_connected(struct com_ep *ep, int timeout)
{
	int ret = 0;
	
	/* Check state just in case we've moved to a deleting state */
	if(com_inc_ref_ep(ep)){
        // NNOP, we are disconnected
    } else {
        if(atomic_read(&ep->ep_state) != EP_CONNECTED){
            wait_event_interruptible_timeout(ep->conn_wait,
                                             (atomic_read(&ep->ep_state) == EP_CONNECTED),
                                              msecs_to_jiffies(timeout));
        }
        com_release_ep(ep);
        ret = com_connected(ep);								   
    }
    return ret;
}

/**
 * Decrement reference count and check state. Spinlock guarantees that a reference doesn't
 * occur between ref_count decrment and the state check 
 * @param ep - the endpoint
 * @param fn - the name of the calling function (for debugging)
 */
void _com_release_ep(struct com_ep *ep, const char *fn)
{
    int ret;
    int do_free = 0;
    struct rna_transport_handle* com_handle = NULL;

    if (!ep) {
        rna_printk(KERN_ERR,"ERROR: EP is NULL, caller is %s\n", fn);
        return;
    }

    com_handle = ep->transport_handle;
    ret = atomic_add_return(-1, &ep->ref_count);
    rna_trace ("Caller: %s, ep: %p, ref_count after: %d\n", fn, ep, ret);

    if (ret < 0) {
        /* HACK. This should be for debugging only to detect refence counting issues */
        rna_printk(KERN_ERR,"WARNING: Caller: %s -- dereferencing ep[%p] state[%d] "
                   "but ep has no references count[%d] (ib)\n",
                   fn,
                   ep,
                   atomic_read(&ep->ep_state),
                   atomic_read(&ep->ref_count));
        dump_stack();
        atomic_inc(&ep->ref_count);
    }

    /* Note: for fully debugged code, reference count should *NEVER* be less then 0 */
    if (ret <= 0) {
        /* Only if we're disconnected do we free the ep. */
        if (atomic_cmpxchg(&ep->ep_state, EP_DISCONNECTED, EP_FREE)
                == EP_DISCONNECTED) {
            do_free = 1;
        }
    }

    if (do_free) {
        rna_trace("Caller: %s -- adding EP[%p] to the free list\n", fn, ep);

        if (ep->com_attr.destructor_cmp_cb) {
            ep->com_attr.destructor_cmp_cb (ep, ep->context);
        }
        ep->context = NULL;

        queue_cleanup_work(com_handle);
    }

    return;
}


int transport_listen(struct rna_transport_handle* com_handle, unsigned short int port)
{
	int ret;
	struct sockaddr_in	src_in;
	struct sockaddr *src_addr;

	/* The kernel client doesn't listen, so this is completely
	 * untested.  If you really want to do this, remove the BUG(). */
	BUG();

#ifdef RDMA_CREATE_ID_FOUR_ARGS
	com_handle->listen_cma_id = rdma_create_id(rna_cma_handler,
                                               com_handle,
                                               RDMA_PS_TCP,
                                               IB_QPT_RC);
#else
	com_handle->listen_cma_id = rdma_create_id(rna_cma_handler,
                                               com_handle,
                                               RDMA_PS_TCP);
#endif
	if (!com_handle->listen_cma_id) {
		printk("fldc_com: listen request failed\n");
		return -ENOMEM;
	}

	memset(&src_in, 0, sizeof(src_in));
	src_in.sin_family = PF_INET;
	src_in.sin_port = htons(port);
	
	src_addr = (struct sockaddr *) &src_in;
	
	ret = rdma_bind_addr(com_handle->listen_cma_id, src_addr);
	if (ret) {
		rdma_destroy_id(com_handle->listen_cma_id);
		printk("fldc_com: bind address failed: %d\n", ret);
		goto out;
	}

	ret = rdma_listen(com_handle->listen_cma_id, 0);
	if (ret) {
		printk("fldc_com: failure trying to listen: %d\n", ret);
		goto out;
	}
out:
	return ret;	

}

/*
 * 
 */

int com_connect(struct com_ep *ep, struct sockaddr *dst_addr)
{
	int ret=0;
	uint8_t	*addr;
	

	if (atomic_cmpxchg(&ep->ep_state, EP_INIT, EP_CONNECT_PENDING) == EP_INIT) {

		ep->dst_in = *((struct sockaddr_in*)dst_addr);
		
		addr = (uint8_t*) (&ep->dst_in.sin_addr.s_addr);
				
		rna_trace("dst addr %d.%d.%d.%d : %d\n", 
				addr[0], addr[1], addr[2], addr[3], 
				 ep->dst_in.sin_port);
					 
		/* Note: port is always set in host ordering, 
		 * but in connect we need it to be in network byte ordering. */
		ep->dst_in.sin_port = htons(ep->dst_in.sin_port);
	
		ep->dst_in.sin_family = PF_INET;

		com_inc_ref_ep(ep);

        rna_trace("calling resolve addr: family 0x%x, port 0x%x\n",
                   ep->dst_in.sin_family, 
                   ep->dst_in.sin_port);
					
		ret = rdma_resolve_addr(ep->cma_id, NULL, (struct sockaddr *)&ep->dst_in, 2000);
		if (ret) {
			if(atomic_cmpxchg(&ep->ep_state,EP_CONNECT_PENDING,EP_INIT) != 
               EP_CONNECT_PENDING){
				rna_printk(KERN_ERR,
                           "fldc_com: EP[%p] state[%d] is corrupted after "
                           "attempting to resolve a bad address\n",
                           ep,
                           atomic_read(&ep->ep_state));
			}else{
				/* 
                 * We need to release the reference taken since the ep is back 
                 * to init state 
                 */
				com_release_ep(ep);
			}
			rna_printk(KERN_ERR,"fldc_com: failure getting addr: %d. Check IB "
                       "network configuration\n", ret);
		} else {
			/* 
             * Get a reference to protect against the caller releasing
			 * the EP while the IB layer has a pointer to it.
			 * Released in disconnect_handler. 
             */
		}
	} else {
		rna_printk(KERN_ERR, "Com connect called on an EP[%p] that is not in "
                   "INIT state. Current state[%d]\n",
                   ep, atomic_read(&ep->ep_state)); 
	}

    rna_trace("done\n");
	return ret;	
}


int com_wait_send_avail(struct  com_ep *ep)
{	
#ifndef SPIN_ON_SEND_AVAIL
	int ret=0;
#endif

	if(NULL == ep){
		rna_printk(KERN_ERR,"EP is NULL\n");
		return -1;
	}
		
#ifndef SPIN_ON_SEND_AVAIL
	rna_trace("posted %d \n", 
               atomic_read(&ep->send_posted));
	ret = wait_event_interruptible(ep->send_cq.wait_obj,
									((atomic_read(&ep->send_pool.num_avail) > 0) ||
									(atomic_read(&ep->ep_state) != EP_CONNECTED)));
	if (ret) {
		printk("com_wait_send_avail: wait for send got interrupted\n");
		goto err;
	}
#else
	while (	0 == atomic_read(&ep->send_pool.num_avail) &&
			atomic_read(&ep->ep_state) == EP_CONNECTED) {
		schedule();
	}
#endif
		
	if (atomic_read(&ep->ep_state) != EP_CONNECTED)
		goto err;

	rna_trace("WAKEUP posted %d \n", 
               atomic_read(&ep->send_posted));
	return 0;
err:
	return -1;
}

int com_wait_rdma_avail(struct  com_ep *ep)
{
	int ret;
	rna_trace("posted %d \n", 
               atomic_read(&ep->send_posted));
	ret = wait_event_interruptible(ep->rdma_wait,
									((atomic_read(&ep->rdma_avail) > 0) ||
									(atomic_read(&ep->ep_state) != EP_CONNECTED)));
	if (ret) {
		rna_trace("wait for rdma got interrupted rna_avail %d\n",
                   atomic_read(&ep->rdma_avail));
		goto err;
	}
	
	if (atomic_read(&ep->ep_state) != EP_CONNECTED)
		goto err;

	rna_trace("WAKEUP posted %d \n", atomic_read(&ep->send_posted));
	return 0;
err:
	return -1;
}

int com_get_send_buf(struct com_ep *ep, struct buf_entry **buf, int poll_ep)
{
    int                       index   = 0;
    int                       state   = 0;
    static const unsigned int timeout = 100; // msecs    
    struct buf_entry         *tmpbuf  = NULL;
    int                       ret     = 0;
    int                       avail;

    *buf = NULL;
    if (unlikely(!ep)) {
        rna_printk(KERN_ERR,"EP is NULL\n");
        dump_stack();
        return -EIO;
    }

    state = atomic_read(&ep->ep_state);
    if (state != EP_CONNECTED) {	
        rna_trace("send on ep not connected state %d\n",
                  atomic_read(&ep->ep_state));
				  
        if (state != EP_CONNECT_PENDING)
            return -EIO;
			
        return -ENOTCONN;
    }

     /* If polling is enabled, poll until more space is available
      * XXX DMO poll-ep wait this is in a way bogus.
      * It does NOT guarantee that the caller will actually get a send buffer.
      * I have just removed the last use of this in the fluidcache kernel.
      * Leave it here for now anyway.
      */
    if (poll_ep &&
        !atomic_read(&ep->send_pool.num_avail) &&
        atomic_read(&ep->send_posted)) {

        com_poll_send_completion(ep);
        if ((state = atomic_read(&ep->ep_state)) != EP_CONNECTED) {
            rna_trace("send on ep not connected state %d\n", 
                      atomic_read(&ep->ep_state));
       	    return -ENOTCONN;
        }
        wait_event_interruptible_timeout(ep->recv_cq.wait_obj,
                                         (0 < atomic_read(&ep->send_pool.num_avail)),
                                         msecs_to_jiffies(timeout));
    }
    ret = com_get_send_buf_from_pool(ep, buf, &ep->send_pool);
    avail = atomic_read(&ep->send_pool.num_avail);
    if (avail < atomic_read(&ep->min_send_avail)) {
        atomic_set(&ep->min_send_avail, avail);
    }
    return ret;
}

int
com_put_send_buf(struct com_ep *ep, struct buf_entry *buf)
{
    int ret = 0;
    unsigned long lock_flags;
    ib_com_buf_data_t *buf_data;

    BUG_ON(buf->is_rdma_buf);
    BUG_ON(0 != atomic_read(&buf->extra_completions));

    buf_data = (ib_com_buf_data_t *)buf->buf_transport_data;
    if (NULL != buf_data->icb_sglp) {
        mempool_free(buf_data->icb_sglp, ibsgl_pool);
        buf_data->icb_sglp = NULL;
    }
    if (atomic_cmpxchg(&buf->buf_use_state, BUF_USE_ALLOCATED, BUF_USE_FREE)
                       == BUF_USE_ALLOCATED) {
        atomic_inc(&buf->pool->num_avail);
        wake_up( &ep->recv_cq.wait_obj );
    } else {
        rna_printk(KERN_ERR, "%s buffer already completed, buf [%p]\n",
                   pool_name(ep, buf->pool), buf);
        dump_stack();
        ret = -EINVAL;
    }

    return ret;
}

int
_com_send(struct com_ep *ep, struct buf_entry *buf, int size,
          enum env_type env_type)
{
    int ret = 0;
    struct ib_send_wr *send_wr, *bad_wr;
    struct ib_sge     *sge;
    ib_com_buf_data_t *buf_data = (ib_com_buf_data_t *)buf->buf_transport_data;

    rna_trace("ep[%p] buf[%p] env_type[%d]\n", ep, buf, env_type);

    /* Application may have called com_put_send_buf already. */
    if (unlikely(atomic_read(&buf->buf_use_state) == BUF_USE_FREE)) {
        rna_printk(KERN_ERR, "buf [%p] already completed\n", buf);
        dump_stack();
        ret = -EINVAL;
        goto out;
    }

    send_wr = &buf_data->icb_send_wr;
    sge = &buf_data->icb_sge;
    BUG_ON(NULL != buf_data->icb_sglp);
    
    sge->length = size + sizeof(struct rna_com_envelope);
    sge->addr = (u64)buf->mem_dma;
    sge->lkey = buf->mr->lkey;
    com_envelope_init(buf->env, ep->user_type, size, 
                      env_type, atomic_inc_return(&ep->trans_id) - 1,
                      com_get_reset_unacked_recvs(ep));

    send_wr->next = NULL;
    send_wr->opcode = IB_WR_SEND;
    send_wr->send_flags = IB_SEND_SIGNALED;
    send_wr->sg_list = sge;
    send_wr->num_sge = 1;
    send_wr->wr_id = (uint64_t) buf;	

    buf->op_type = POST_SEND;

    if (try_state_lock(ep)) {
        if(ep->cma_id->qp){
            ret = ib_post_send(ep->cma_id->qp, send_wr, &bad_wr);
            if (unlikely(ret)){ 
                /* TODO: Repost the send buffer here */
                printk("ep[%p] failed to post send. ret[%d]\n",ep , ret);
            } else {
                atomic_inc(&ep->send_posted);
            }
        } else {
            com_put_send_buf(ep, buf);
            ret = -1;
        }

        state_unlock(ep);
    } else {
        ret = -1;
        com_put_send_buf(ep, buf);
    }
out:
    return ret;
}

static inline void
init_rdma_buf(struct buf_entry *rdma_buf)
{
    int i;

    rdma_buf->op_flags = 0;
    atomic_set(&rdma_buf->extra_completions, 0);
	rdma_buf->rem_addr.device_id.data = 0;
	rdma_buf->rem_addr.base_addr = 0;
	rdma_buf->zcopy_dma = 0;
	rdma_buf->zcopy_mr = NULL;
	rdma_buf->op_type = -1;
	rdma_buf->dma_size = 0;
    rdma_buf->comp_status = 0;

    rdma_buf->bounce_start_bit = INVALID_BOUNCE_BIT;
    rdma_buf->bounce_bits = 0;
    rdma_buf->bounce_address = 0;
    rdma_buf->bounce_send_start = 0;
    rdma_buf->bounce_rdma_start = 0;
}

/* This function allocates a buf_entry for the rdma buffer, and
 * it ALSO allocates a send buffer to be used as part of the fakey rdma
 * implementation.
 *
 * if/When we eventually do support RAM as a target device for our RDMA,
 * we will not need this additional send buffer.  In order to avoid
 * this unneeded allocation, we will need an additional argument to this
 * function.  This argument can be derived from:
 *
 *      ios->blk->raddr.device_id.data == 0
 */
int
com_get_rdma_buf(struct com_ep *ep, struct buf_entry **buf, int *len)
{
    int ret = 0;
	int num_buf;
	int buf_size=0;
    unsigned long irqflags;
	struct buf_entry *rdma_buf=NULL;
    int remaining;
    uint64_t alloc_start_time;
    struct buf_entry *send_buf_entry;

	BUG_ON(!ep);
	if (atomic_read(&ep->ep_state) != EP_CONNECTED) {
		rna_trace("send on ep not connected state %d\n",
                   atomic_read(&ep->ep_state));
		*buf = NULL;
		return -ENOTCONN;
	}

	if (!ep->rdma_pool)
		return -1;

	*buf = NULL;
	num_buf = 1;
	if (num_buf > 1) {
        rna_trace("NUM BUF %d, len %d, buf_size %d\n",
                   num_buf,
                  *len,
                   ep->rdma_buf_size);
	}

    ret = com_get_send_buf(ep, &send_buf_entry, FALSE);
    if (0 != ret || NULL == send_buf_entry) {
        return -ENOMEM;
    }

	rna_spin_lock_irqsave(ep->rdma_lock, irqflags);

	while(num_buf) {
		if (atomic_read(&ep->rdma_avail)) {
			if (!rdma_buf) {
				rdma_buf = (ep->rdma_pool[ep->next_rdma]);
				BUG_ON(!rdma_buf);
				if (atomic_cmpxchg(&rdma_buf->buf_use_state, BUF_USE_FREE,
                                   BUF_USE_ALLOCATED) == BUF_USE_FREE) {
					init_rdma_buf(rdma_buf);
				} else {

					/* Note: sometimes the next_rdma buf shows up as incompleted
					 * continue to next buffer
					 */
					rdma_buf = NULL;
					ep->next_rdma++;
					if(ep->next_rdma == ep->num_rdma) {
						/* bail out, just in case we end up looping forever
						 */
						ep->next_rdma = 0;
						break;
					}
					continue;

				}
			}

			remaining = atomic_dec_return(&ep->rdma_avail);
            if (remaining < atomic_read(&ep->min_rdma_avail)) {
                atomic_set(&ep->min_rdma_avail, remaining);
            }
			ep->next_rdma++;

			buf_size += ep->rdma_buf_size;
			if(ep->next_rdma == ep->num_rdma) {
				ep->next_rdma = 0;
				/* return only contiguous buffers */
				break;
			}

			num_buf--;

		} else {
			rdma_buf = NULL;
			break;
		}
	}
	rna_spin_unlock_irqrestore(ep->rdma_lock, irqflags);

    if (likely(NULL != rdma_buf)) {

        rdma_buf->rdma_send_buf = send_buf_entry;

        if (kernel_com_use_bounce_buffer(ep, *len)) {
            struct com_ib_bb_ctxt *bb_ctxt = BB_CTXTP(ep);

            alloc_start_time = getrawmonotonic_ns();
            ret = kernel_com_get_bounce_buffer(rdma_buf, *len);
            if (0 != ret) {
                rna_printk(KERN_DEBUG,
                          "Failed to allocate bounce buffer for ep [%p]\n",
                          ep);
                com_put_send_buf(ep, send_buf_entry);
                send_buf_entry = NULL;
                rdma_buf->rdma_send_buf = NULL;
                com_put_rdma_buf_internal(ep, rdma_buf, FALSE);
                rdma_buf = NULL;
            } else if (NULL != bb_ctxt) {
                rna_atomic64_add(getrawmonotonic_ns() - alloc_start_time,
                                &bb_ctxt->bbc_allocation_wait);
            }
        }
    } else {
        com_put_send_buf(ep, send_buf_entry);
    }

	*buf = rdma_buf;
	return ret;
}


typedef struct kernel_com_bounce_read_s {
    struct com_ep       *br_ep;
    void                *br_buf;        /* com_rdma_read */
    struct scatterlist  *br_sgl;        /* com_rdma_sgl */
    int                 br_nents;       /* com_rdma_sgl */
    void                *br_context;
    char                br_signaled;
    uint32_t            br_flags;
    int                 br_size;  // XXX May be redundant?
} kernel_com_bounce_read_t;

static void init_buf_for_rdma_read(struct buf_entry *buf_entry,
                                   rna_addr_t remote_addr,
                                   rna_rkey_t remote_rkey)
{
    buf_entry->zcopy_dma = 0;
	buf_entry->zcopy_mr = NULL;
    buf_entry->op_type = RDMA_READ;
    buf_entry->rem_addr = remote_addr;
    buf_entry->rkey = remote_rkey;	
}

int 
rdma_read_post_send(struct com_ep *ep,
                    struct buf_entry *buf_entry, 
                    rna_addr_t remote_addr,
                    void *buf,
                    rna_rkey_t remote_rkey,
                    int size,
                    void *context,
                    char signaled,
                    uint32_t flags)
{
    struct ib_send_wr   *rdma_wr, *bad_wr;
    struct ib_sge		*sge;		
    struct ib_phys_buf  ipb;
    int                 ret;
    ib_com_buf_data_t   *buf_data;

    buf_data = (ib_com_buf_data_t *)buf_entry->buf_transport_data;
#ifdef RDMA_READ_OVERRIDE
    if (rdma_read_override != -1 &&
            rdma_read_override < size) {
        size = rdma_read_override;
        buf_entry->length = size;
    }
#endif

#ifdef RNA_Z_COPY
    rdma_wr = &buf_data->icb_send_wr;
    sge = &buf_data->icb_sge;
    BUG_ON(NULL != buf_data->icb_sglp);

    if (buf) {
        sge->addr = ib_dma_map_single(ep->cma_id->device,
                                      buf,
                                      size,
                                      DMA_FROM_DEVICE);

        if (ib_dma_mapping_error(ep->cma_id->device, sge->addr)) {
            printk("rna: ib_dma_mapping_error buf %p, size %d\n", buf, size);
            return -ENOMEM;
        }

        buf_entry->zcopy_dma = sge->addr;
        buf_entry->dma_size =  size;
        buf_entry->direction = DMA_FROM_DEVICE;
        ipb.addr = buf_entry->zcopy_dma;
        ipb.size = size;
        buf_entry->zcopy_mr = NULL;
        buf_entry->zcopy_mr = com_register_mr(ep, &ipb, &sge->addr);
        if(IS_ERR(buf_entry->zcopy_mr)) {
            buf_entry->zcopy_mr = NULL;
        }

    } else {
        sge->addr = buf_entry->mem_dma;
    }
#else // !RNA_Z_COPY

#warning RNA_Z_COPY must be enabled for reads from buf to work properly!  See MVP-3952.
    sge->addr = buf_entry->mem_dma;

#endif //RNA_Z_COPY

    rna_trace("buf %p, sge->addr 0x%llx\n", buf_entry->mem, sge->addr);

    if ((NULL != buf_entry->zcopy_mr) && !IS_ERR(buf_entry->zcopy_mr)) {
        sge->lkey = buf_entry->zcopy_mr->lkey;
    } else  {
        sge->lkey = buf_entry->mr->lkey;
    }

    rna_printk(KERN_DEBUG, "TRUE RDMA READ to buf_entry [%p]: remote_addr "
               "[0x%"PRIx64"], size [%d]\n", 
               buf_entry, remote_addr.base_addr, size);

	rdma_wr->next = NULL;
	rdma_wr->opcode = IB_WR_RDMA_READ;
	rdma_wr->send_flags = IB_SEND_SIGNALED;
	rdma_wr->sg_list = sge;
	rdma_wr->num_sge = 1;
	
	buf_entry->op_type = RDMA_READ;
	rdma_wr->wr_id = (uint64_t) buf_entry;
	sge->length = size;
	rdma_wr->wr.rdma.remote_addr = remote_addr.base_addr;

    rdma_wr->wr.rdma.rkey = (uint32_t)remote_rkey;

    if (try_state_lock(ep)) {
        if(ep->cma_id->qp){
            ret = ib_post_send(ep->cma_id->qp, rdma_wr, &bad_wr);
            if (ret) {
                rna_printk(KERN_ERR,
                       "failed to post send: %d\n", ret);
            } else {
                atomic_inc(&ep->rdma_posted);
            }
        }else{
            ret = -1;	
        }

        state_unlock(ep);
    } else {
        ret = -1;	
    }

    rna_trace("successful buf %p, sge->addr %llx \n", buf_entry->mem,
            sge->addr);
    return ret;
}

int 
com_rdma_read(struct com_ep *ep,
              struct buf_entry *buf_entry, 
              rna_addr_t remote_addr,
              void *buf,
              rna_rkey_t remote_rkey,
              int size,
              void *context,
              char signaled,
              uint32_t flags)
{
    int ret = 0;
    kernel_com_bounce_read_t *bounce_read_ctx;

    if (atomic_read(&ep->ep_state) != EP_CONNECTED) {
        return -1;
    }

    if (size == 0) {
        printk("com_rdma_read: ERROR read size 0; dst %u.%u.%u.%u: "
               "rdma_buf %p, rem_addr 0x%"PRIx64":%"PRIx64","
               " rkey 0x%"PRIx64", rdma_length %d\n", 
               NIPQUAD(ep->dst_in.sin_addr.s_addr),
               buf_entry, buf_entry->rem_addr.device_id.data, 
               buf_entry->rem_addr.base_addr, buf_entry->rkey, 
               buf_entry->length);
        return -1;
    }
    init_buf_for_rdma_read(buf_entry, remote_addr, remote_rkey);

    if (remote_addr.device_id.data != 0) {
        /* fake the rdma using send */
        rna_printk(KERN_DEBUG,
                   "ep=0x%p, buf_entry=0x%p, remote_addr=%"PRId64":%"PRId64
                   ", buf=0x%p, mem=0x%p remote_rkey=%"PRIu64", size=%d, "
                   "context=0x%p, signaled=%d, flags=0x%x\n",
                   ep, buf_entry, remote_addr.device_id.data, 
                   remote_addr.base_addr, buf, buf_entry->mem, remote_rkey, 
                   size, context, (int)signaled, flags);

        /* XXX: This won't work for fs client since it uses ctx */
        buf_entry->ctx = buf; /* local_addr */

        if (kernel_com_use_bounce_buffer(ep, size)) {
            rna_printk(KERN_DEBUG, 
                       "Using bounce address [0x%"PRIx64"] for buf_entry "
                       "[0x%p]\n", buf_entry->bounce_address, buf_entry);
            /* 
             * We should have gotten the bounce buffer at the same time
             * that we got the RDMA buffer.
             */
            BUG_ON(0 == buf_entry->bounce_address);
            bounce_read_ctx = kmalloc(sizeof(*bounce_read_ctx), GFP_NOFS);
            if (NULL == bounce_read_ctx) {
                rna_printk(KERN_ERR,
                           "Failed to get bounce_read_ctx for buf_entry [%p]\n", 
                           buf_entry);
                ret = -1;
            } else {
                bounce_read_ctx->br_ep = ep;
                bounce_read_ctx->br_buf = buf;
                bounce_read_ctx->br_sgl = NULL;
                bounce_read_ctx->br_nents = 0;
                bounce_read_ctx->br_context = context;
                bounce_read_ctx->br_signaled = signaled;
                bounce_read_ctx->br_flags = flags;
                bounce_read_ctx->br_size = size;
                buf_entry->ctx = bounce_read_ctx;
                atomic_set(&buf_entry->extra_completions, 1);
                ret = ib_send_rdma_read_msg(ep,
                                            buf_entry,
                                            remote_addr,
                                            remote_rkey,
                                            size,
                                            context);
                if (0 != ret) {
                    atomic_set(&buf_entry->extra_completions, 0);
                    rna_printk(KERN_ERR, 
                               "Failed to post bounce rdma read send buf [%p] "
                               "ep [%p] ["NIPQUAD_FMT"]: ret [%d]\n",
                               buf_entry, ep,
                               NIPQUAD(ep->dst_in.sin_addr.s_addr), ret);
                    kfree(bounce_read_ctx);
                }
            }
        } else {
            /* Read without bounce buffer using RDMA SEND */
            ret = ib_send_rdma_read_msg(ep,
                                        buf_entry,
                                        remote_addr,
                                        remote_rkey,
                                        size,
                                        context);
            if (ret != 0) {
                rna_printk ( KERN_ERR, "failed to post rdma read send: %d\n", ret );
            }
        }
    } else {
        /* Do a true RDMA READ operation */
        ret = rdma_read_post_send(ep, buf_entry, remote_addr, buf, remote_rkey,
                                  size, context, signaled, flags);
    }
    return ret;

}

static int
kernel_com_use_ib_send_rdma_write(struct com_ep *ep, struct buf_entry *buf_entry, 
                                  void *buf, int size, char signaled, 
                                  uint32_t flags)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
    uint64_t             ccaddr;
    uint64_t             bpaddr;
#endif
    int ret;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
    ccaddr = (uint64_t)buf;
    bpaddr = ccaddr & PAGE_MASK;
    buf_entry->sgl[0].page = virt_to_page(buf);
    buf_entry->sgl[0].offset = (unsigned int)(ccaddr - bpaddr);
    buf_entry->sgl[0].length = size;
#else
    buf_entry->sgl[0].page_link = 0;
    sg_init_one(&buf_entry->sgl[0], buf, size);
#endif

    buf_entry->sgl_nents = 1;

    ret = ib_send_rdma_write_msg(ep,
                                 buf_entry,
                                 size,
                                 signaled,
                                 flags);
    if (ret) {
        rna_printk(KERN_ERR,
                   "failed to post send: %d\n", 
                   ret);
    }
    return ret;
}

/**
 * cook up a wc that has the rdma_buf in wr_id to complete the original
 * RDMA request.
 */
static void
_fake_rdma_completion(struct com_ep *ep,
                      uint64_t wr_id,
                      int opcode,
                      int status)
{
    struct ib_wc wc;
    int ret = 0;

    wc.wr_id = wr_id;
    wc.opcode = opcode;
    wc.status = status;

    ret = _rdma_completion(ep, &wc, TRUE);
    rna_trace("rdma completion EP[%p] opcode[%d] ret[%d]\n", ep, opcode, ret);
    if (ret == CB_RESP_INVALID_RKEY) {
        queue_disconnect_work(ep);
    }

    return;
}

int 
com_rdma_write(struct com_ep *ep, struct buf_entry *buf_entry, 
               rna_addr_t remote_addr, void *buf, rna_rkey_t remote_rkey,
               int size, void *context, char signaled, uint32_t flags)
{
    struct com_ib_bb_ctxt       *bb_ctxt = BB_CTXTP(ep);
    struct ib_send_wr           *rdma_wr = NULL, *bad_wr;
    struct ib_sge               *sge;
    int                         ret = 0;
    int                         use_bounce_buffer = FALSE;
    ib_com_buf_data_t           *buf_data;

    if (atomic_read(&ep->ep_state) != EP_CONNECTED) {
        return -1;
    }

    if (remote_addr.device_id.data == 0 && remote_addr.base_addr == 0) {
        printk("com_rdma_write: bad remote address 0x%"PRIx64":%"PRIx64
               " or size %d\n", remote_addr.device_id.data, 
               remote_addr.base_addr, size);
        return -1;
    }
    buf_data = (ib_com_buf_data_t *)buf_entry->buf_transport_data;
    rdma_wr = &buf_data->icb_send_wr;
    sge = &buf_data->icb_sge;
    BUG_ON(NULL != buf_data->icb_sglp);

    buf_entry->rem_addr = remote_addr;
    buf_entry->rkey = remote_rkey;
    buf_entry->op_flags = flags;
    buf_entry->op_type = RDMA_WRITE;

    if (remote_addr.device_id.data != 0) {
        /* fake the rdma using send */
        rna_printk(KERN_DEBUG,
                   "ep=0x%p, buf_entry=0x%p, "
                   "remote_addr=%"PRId64":%"PRId64", buf=0x%p, "
                   "remote_rkey=%"PRIu64", size=%d, context=0x%p, signaled=%d, flags=0x%x\n",
                   ep, buf_entry, remote_addr.device_id.data, remote_addr.base_addr,
                   buf, remote_rkey, size, context,
                   (int)signaled,flags );

        if (kernel_com_use_bounce_buffer(ep, size)) {
            BUG_ON(NULL == bb_ctxt);
            rna_printk(KERN_DEBUG,
                       "BOUNCE ep=0x%p, buf_entry=0x%p, "
                       "remote_addr=0x%"PRIx64":%"PRId64", buf=0x%p, "
                       "remote_rkey=%"PRIu64", size=%d, context=0x%p, "
                       "signaled=%d, flags=0x%x\n",
                       ep, buf_entry, remote_addr.device_id.data, remote_addr.base_addr,
                       buf, remote_rkey, size, context,
                       (int)signaled,flags );
            /* 
             * We should have allocated the bounce buffer when we got the
             * RDMA buffer.
             */
            BUG_ON(0 == buf_entry->bounce_address);
            use_bounce_buffer = TRUE;
            atomic_set(&buf_entry->extra_completions, 1);
        } else {
            ret = kernel_com_use_ib_send_rdma_write(ep, buf_entry, buf, size, 
                                                    signaled, flags);
            return ret;
        }
    }

#ifdef RNA_Z_COPY_WRITE

    if (buf) {
        sge->addr = ib_dma_map_single(ep->cma_id->device,
                                      buf,
                                      size,
                                      DMA_TO_DEVICE);
    } else {
        sge->addr = buf_entry->mem_dma;

    }
#else // ! RNA_Z_COPY_WRITE
#warning RNA_Z_COPY_WRITE must be enabled for writes from buf to work properly!  See MVP-3952.

    sge->addr = buf_entry->mem_dma;

#endif // RNA_Z_COPY_WRITE

    sge->length = size;

    sge->lkey = buf_entry->mr->lkey;

    rdma_wr->next = NULL;
    rdma_wr->opcode = IB_WR_RDMA_WRITE;
    rdma_wr->send_flags = IB_SEND_SIGNALED;

    if (size) {
        rdma_wr->sg_list = sge;
        rdma_wr->num_sge = 1;
    } else {
        rdma_wr->sg_list = NULL;
        rdma_wr->num_sge = 0;
    }
    rdma_wr->wr_id = (uint64_t) buf_entry;
    if (TRUE == use_bounce_buffer) {
        rdma_wr->wr.rdma.rkey = (uint32_t)bb_ctxt->bbc_buf_rkey;
        rdma_wr->wr.rdma.remote_addr = buf_entry->bounce_address;
    } else {
        rdma_wr->wr.rdma.rkey = (uint32_t)remote_rkey;
        rdma_wr->wr.rdma.remote_addr = remote_addr.base_addr;
    }
    if (try_state_lock(ep)) {
        if (ep->cma_id->qp) {
            ret = ib_post_send(ep->cma_id->qp, rdma_wr, &bad_wr);
            if (ret) {
                rna_printk(KERN_ERR, "failed to post send: %d\n", ret);
            } else {
                atomic_inc(&ep->rdma_posted);
                if (TRUE == use_bounce_buffer) {
                    buf_entry->sgl_nents = 0;
                    ret = ib_send_rdma_write_msg(ep, buf_entry, size, 
                                                 signaled, 
                                                 flags | IB_SEND_FENCE);
                    if (0 != ret) {
                        rna_printk(KERN_ERR, "fail to post RDMA buf [%p]: "
                                   "ret [%d]\n", buf_entry, ret);
                        /*
                         * Since we successfully posted phase-1, we'll be
                         * getting a completion for that.  So capture the
                         * error for this bounce-buffer phase and return
                         * success for now.  (When the phase-1 completion
                         * arrives, the error will be returned.)
                         * Note that CB_RESP_INVALID_RKEY will trigger a
                         * disconnect in _fake_rdma_completion -- which
                         * seems like the best way to handle this error.
                         */
                        _fake_rdma_completion(ep, (uint64_t)buf_entry,
                                              IB_WC_RDMA_WRITE,
                                              CB_RESP_INVALID_RKEY);
                        ret = 0;
                    }
                }
            }
        } else {
            ret = -1;
        }

        state_unlock(ep);
    } else {
        ret = -1;
    }
    if (unlikely((0 != ret) && (TRUE == use_bounce_buffer))) {
        if (1 == atomic_cmpxchg(&buf_entry->extra_completions, 1, 0)) {
            rna_printk(KERN_DEBUG,
                       "Cleared extra_completions for buf_entry [0x%p]\n", 
                       buf_entry);
        } else {
            rna_printk(KERN_WARNING,
                       "extra_completions not set for buf_entry [0x%p]\n", 
                       buf_entry);
        }
    }
    rna_trace("%s buf %p, sge->addr %"PRIx64", ret %d\n", 
              (0 == ret) ? "successful" : "unsuccessful",
              buf_entry->mem, sge->addr, ret);
    return ret;

}

int 
kernel_com_sgl_post_send(struct com_ep *ep, void *ctxt, 
                         struct buf_entry *buf_entry,
                         struct scatterlist *sgl,
                         rna_rkey_t rkey, int write, uint32_t flags)
{
    struct ib_send_wr *bad_wr;
    struct ib_sge *ib_sgl;
    int i;
    int ret = 0;
    ib_com_buf_data_t *buf_data;

    buf_data = (ib_com_buf_data_t *)buf_entry->buf_transport_data;
    /* 
     * Each element in ibsgl_pool is sizeof(struct ib_sge[256])
     * (see transport_module_init()). 
     */
    ib_sgl = mempool_alloc(ibsgl_pool, GFP_ATOMIC);
    buf_data->icb_sglp = ib_sgl; /* So we can free it on completion */
    if (unlikely(NULL == ib_sgl)) {
        rna_printk(KERN_ERR, "failed to allocate sge\n");
        ret = -ENOMEM;
        goto out;
    }
    for (i = 0; i < buf_data->icb_send_wr.num_sge; i++) {
        (ib_sgl + i)->addr = 
            ib_sg_dma_address(ep->cma_id->device, (sgl + i) );
        (ib_sgl + i)->length = 
            ib_sg_dma_len(ep->cma_id->device, (sgl + i) );
        (ib_sgl + i)->lkey = ep->mr->lkey;
    }

    buf_data->icb_send_wr.sg_list = ib_sgl;
    if (try_state_lock(ep)) {
        if(ep->cma_id->qp){
            ret = ib_post_send(ep->cma_id->qp, 
                               &buf_data->icb_send_wr, 
                               &bad_wr);
            if( ret < 0 ) {
                /* 
                 * Note: this is possible if we overrun the sendq. Downgrading
                 * to a trace since the application should generate an
                 * error message if it can't handle this. We may want to
                 * revisit this and increment a counter since this is rather
                 * expensive 
                 */
                rna_printk(KERN_INFO, "ep[%p] error %d num_sge %d %s\n",
                           ep, ret, buf_data->icb_send_wr.num_sge, 
                           write ? "write" : "read" );
                /* Turn the error into one of ours. */
                ret = CB_RESP_CACHE_FAIL;
             } else {
                atomic_inc(&ep->rdma_posted);
             }
        } else {
            rna_printk(KERN_ERR, "No qp for ep [%p]\n", ep);
            ret = CB_RESP_CACHE_FAIL;
        }
        state_unlock(ep);
    } else {
        rna_printk(KERN_ERR, "try_state_lock for ep [%p] failed\n", ep);
        ret = CB_RESP_CACHE_FAIL;
    }

out:
    if (unlikely((0 != ret) && (ib_sgl != NULL))) {
        /* 
         * If we successfully submitted the wr, then we'll free the ib_sgl 
         * upon RDMA completion. 
         */
        mempool_free(ib_sgl, ibsgl_pool);
        buf_data->icb_sglp = NULL;
    }
    return ret;
}

static void
com_init_ib_send_wr_and_buf(struct ib_send_wr *wr, struct buf_entry *buf_entry,
                            void *context, rna_addr_t raddr, rna_rkey_t rkey, 
                            int nents, int opcode, uint32_t flags)
{
    memset(wr, 0, sizeof(*wr));
    wr->next                = NULL;
    wr->wr_id               = (uint64_t) buf_entry;
    wr->opcode              = opcode;
    wr->send_flags          = IB_SEND_SIGNALED;
    wr->num_sge             = nents;
    wr->wr.rdma.remote_addr = raddr.base_addr;
    wr->wr.rdma.rkey        = (uint32_t)rkey;

    buf_entry->op_type = (opcode == IB_WR_RDMA_READ) ? 
        RDMA_READ_SGL : RDMA_WRITE_SGL;
    buf_entry->context = context;
    buf_entry->rem_addr = raddr;
    buf_entry->rkey = rkey;
    buf_entry->op_flags = flags;
    
}

static int
com_rdma_bounce_buffer_sgl(struct com_ep *ep, void *ctxt, 
                           struct buf_entry *buf_entry,
                           rna_addr_t raddr, struct scatterlist *sgl, 
                           rna_rkey_t rkey, int write, 
                           uint32_t flags, uint64_t size)
{

    struct ib_send_wr *wr;
    struct com_ib_bb_ctxt *bb_ctxt = BB_CTXTP(ep);
    int ret = 0;
    kernel_com_bounce_read_t *bounce_read_ctx;
    ib_com_buf_data_t *buf_data;

    buf_data = (ib_com_buf_data_t *)buf_entry->buf_transport_data;
    wr = &buf_data->icb_send_wr;

    /* 
     * We should have allocated the bounce buffer when we allocated the
     * RDMA buffer.
     */
    BUG_ON(0 == buf_entry->bounce_address);
    /* 
     * We need two completions on the buf_entry before
     * the IO is complete (a message plus an RDMA read/write)
     */
    atomic_set(&buf_entry->extra_completions, 1);
    if (write) {
        /* Issue true RDMA WRITE with bounce buffer.
         * time how long we wait for a buffer.
         */
        if (NULL != bb_ctxt) {
            atomic_inc(&bb_ctxt->bbc_write_count);
        }
        /* Override the default remote_addr and rkey */
        wr->wr.rdma.remote_addr = buf_entry->bounce_address;
        wr->wr.rdma.rkey        = (uint32_t)bb_ctxt->bbc_buf_rkey;

        /* how long to do the rdma write */
        buf_entry->bounce_send_start = getrawmonotonic_ns();

        ret = kernel_com_sgl_post_send(ep, ctxt, buf_entry, sgl, 
                                       rkey, write, flags);
        if (0 == ret) {
            /* Use RDMA SEND with FENCE to signal where data is written */

            buf_entry->bounce_rdma_start = getrawmonotonic_ns();

            buf_entry->sgl_nents = 0;
            ret = ib_send_rdma_write_msg(ep, buf_entry, size, 
                                         IB_SEND_SIGNALED, 
                                         flags | IB_SEND_FENCE);
            if (0 != ret) {
                rna_printk(KERN_ERR,
                           "Failed to send bounce buffer write "
                           "message for buf_entry [%p]\n", 
                           buf_entry);
                /*
                 * Since we successfully posted phase-1, we'll be
                 * getting a completion for that.  So capture the
                 * error for this bounce-buffer phase and return
                 * success for now.  (When the phase-1 completion
                 * arrives, the error will be returned.)
                 * Note that CB_RESP_INVALID_RKEY will trigger a
                 * disconnect in _fake_rdma_completion -- which
                 * seems like the best way to handle this error.
                 */
                _fake_rdma_completion(ep, (uint64_t)buf_entry,
                                      IB_WC_RDMA_WRITE, CB_RESP_INVALID_RKEY);
                ret = 0;
            }
        } else {
            rna_printk(KERN_ERR, 
                       "Failed to post bounce buffer RDMA WRITE for buf_entry "
                       "[%p] ep [%p] ["NIPQUAD_FMT"]\n",
                       buf_entry, ep,
                       NIPQUAD(ep->dst_in.sin_addr.s_addr));
        }
    } else {
        /* Use RDMA SEND to signal reading data into bounce buffer */
        bounce_read_ctx = kmalloc(sizeof(*bounce_read_ctx), GFP_NOFS);
        if (NULL == bounce_read_ctx) {
            rna_printk(KERN_ERR,
                       "Failed to get bounce_read_ctx for buf_entry "
                       "[%p]\n", buf_entry);
            ret = -1;
        } else {
            bounce_read_ctx->br_ep = ep;
            bounce_read_ctx->br_buf = NULL;
            bounce_read_ctx->br_sgl = sgl;
            bounce_read_ctx->br_nents = wr->num_sge;
            bounce_read_ctx->br_context = ctxt;
            bounce_read_ctx->br_signaled = IB_SEND_SIGNALED;
            bounce_read_ctx->br_flags = flags;
            bounce_read_ctx->br_size = size;
            // FIXME:This won't work for fs client since it uses ctx */
            buf_entry->ctx = bounce_read_ctx;
            if (NULL != bb_ctxt) {
                atomic_inc(&bb_ctxt->bbc_read_count);
            }
            buf_entry->bounce_rdma_start = getrawmonotonic_ns();

            ret = ib_send_rdma_read_msg(ep,
                                        buf_entry,
                                        raddr,
                                        rkey,
                                        size,
                                        ctxt);
            /* 
             * Receive completion will release the buffer and free 
             * bounce_read_ctx. 
             */
        }
    }
    if (0 != ret) {
        if (1 == atomic_cmpxchg(&buf_entry->extra_completions, 1, 0)) {
            rna_printk(KERN_DEBUG,
                       "Cleared extra_completions for buf_entry [0x%p]\n", 
                       buf_entry);
        } else {
            rna_printk(KERN_WARNING,
                       "extra_completions not set for buf_entry [0x%p]\n", 
                       buf_entry);
        }
    }
    return ret;
}

/* raddr is the address based on the ios->start_sector that held the sgl */
int
com_rdma_sgl(struct com_ep *ep, void *ctxt, struct buf_entry *buf_entry,
             rna_addr_t raddr, struct scatterlist *sgl, int nents,
             rna_rkey_t rkey, int write, uint32_t flags)
{
    int ret = 0;
    uint64_t size;
    ib_com_buf_data_t *buf_data;
    int use_state;
    
    BUG_ON(NULL == buf_entry);
    buf_data = (ib_com_buf_data_t *)buf_entry->buf_transport_data;

    rna_trace("ep[%p] ctxt[%p] raddr[%"PRIx64":0x%"PRIx64"] rkey[0x%"PRIx64"] "
              "nents[%d] write[%d]\n",
              ep, ctxt, raddr.device_id.data, raddr.base_addr, rkey, 
              nents, write);
    com_init_ib_send_wr_and_buf(&buf_data->icb_send_wr, buf_entry, ctxt, raddr, 
                                rkey, nents, 
                                write ? IB_WR_RDMA_WRITE : IB_WR_RDMA_READ, 
                                flags);
    if (raddr.device_id.data != 0) {
        size = kernel_com_sgl_size(sgl, nents);
        if (kernel_com_use_bounce_buffer(ep, size)) {
            ret = com_rdma_bounce_buffer_sgl(ep, ctxt, buf_entry, raddr, sgl,
                                             rkey, write, flags, size);
        } else {
            /*
             * Track total of processed recv packet bytes in mem_size.
             * TODO: mem_size is an int, is 2GB large enough
             */
            buf_entry->mem_size = 0;
            ret = ib_rdma_sgl(ep,
                              &buf_data->icb_send_wr,
                              raddr,
                              rkey,
                              sgl,
                              write,
                              flags);
        }
    } else {
        ret = kernel_com_sgl_post_send(ep, ctxt, buf_entry, sgl, rkey, 
                                       write, flags);
    }

    if (0 == ret) {
        com_mark_rdma_buf_inflight(ep, buf_entry);
    }
    return ret;
}


int com_free_rdma_pool(struct com_ep *ep)
{
	int size;
	int i;
	struct buf_entry* be;
	
	if (!ep)
		return -1;
	

	size = ep->num_rdma * ep->rdma_buf_size ;

	if (ep->rdma_pool) {
		for(i=0; i< ep->num_rdma; i++) {
			be = ep->rdma_pool[i];

			if (be->mem) {
                ib_dma_unmap_single(ep->cma_id->device,
                                    be->mem_dma, 
				                    ep->rdma_buf_size, 
				                    DMA_BIDIRECTIONAL);
				kfree(be->mem);

				com_unregister_mr(ep, &be->mr);
				be->mem = NULL;
                if (be->buf_transport_data) {
                    kfree(be->buf_transport_data);
                    be->buf_transport_data = NULL;
                }
				kfree(be);
				ep->rdma_pool[i] = NULL;
			}
		}
	}
	
	if (ep->rdma_pool)
		kfree(ep->rdma_pool);
		
	atomic_set(&ep->rdma_avail,0);
	ep->rdma_mem = ep->rdma_pool = NULL;
	
	return 0;
}

int transport_free_buf_pool_elem(void **elem, unsigned long arg, int idx)
{
	struct buf_entry *entry = (typeof(entry)) *elem;
	struct buf_pool_ctx *ctx = (typeof(ctx)) arg;
	struct com_ep *ep = ctx->ep;
	struct buf_pool *buf_pool = ctx->pool;

    if (entry && entry->buf_transport_data) {
        kfree(entry->buf_transport_data);
        entry->buf_transport_data = NULL;
    }
	if(entry && entry->env) {
	
		rna_trace("buf pool entry [%d] for ep[%p] = [%p]\n", 
		          idx, ep, entry->mr);
				  
		if(NULL != entry->mr){
			com_unregister_mr(ep, &entry->mr);
			entry->mr = NULL;
		}
		
		if(0 != entry->mem_dma){
			ib_dma_unmap_single(ep->cma_id->device,
		                        entry->mem_dma,
		                        ctx->buf_size,
		                        DMA_BIDIRECTIONAL);
			entry->mem_dma = 0;
		}

		kfree(entry->env);
		entry->env = NULL;
		entry->mem = NULL;
	}

	return 0;
}

/* initialize an IB buf_entry */
int transport_alloc_buf_pool_elem(void **elem, unsigned long arg, int idx)
{
	int ret = 0;
	struct buf_entry *entry = (typeof(entry)) *elem;
	struct buf_pool_ctx *ctx = (typeof(ctx)) arg;
	struct com_ep *ep = ctx->ep;
	struct buf_pool *buf_pool = ctx->pool;
	struct ib_phys_buf ipb;
	
	entry->env = kmalloc(ctx->buf_size, GFP_NOFS);
	
	if(entry->env) {
		/* Envelope is a private header to the com layer
		 mem pointer is for the com user payload data */
		entry->mem = (void*)(entry->env) + sizeof(struct rna_com_envelope);

		/* Get a DMA mapped address for this entry */
		entry->mem_dma = ib_dma_map_single(ep->cma_id->device,
		                                   (void*)entry->env,
		                                   ctx->buf_size, 
		                                   DMA_BIDIRECTIONAL);
		if (ib_dma_mapping_error(ep->cma_id->device, entry->mem_dma)){
			rna_printk(KERN_ERR,"Failed to map DMA address to RDMA device.\n");
			ret = -EFAULT;
			entry->mem_dma = 0;
			goto error;
		}
	
		entry->ep = ep;	
		entry->index = idx;
		entry->pool = ctx->pool; 
		atomic_set(&entry->buf_use_state, BUF_USE_FREE);
		atomic_set(&entry->extra_completions, 0);
        entry->comp_status = 0;
		INIT_LIST_HEAD(&entry->queued_send_entry);
		
		ipb.addr = entry->mem_dma;
		ipb.size = ctx->buf_size;
	
		entry->mem_size = ctx->buf_size;
	
		entry->mr = com_register_mr(ep, &ipb, &entry->mem_dma);
		
		if((NULL == entry->mr) || IS_ERR(entry->mr)){
			rna_printk(KERN_ERR,"Failed to register buf pool entry\n");
			ret = -EFAULT;
			entry->mr = NULL;
			goto error;
		}
	}else{
		rna_printk(KERN_ERR,"Failed to allocate buf pool entry\n");
		ret = -ENOMEM;
	}
	
	return ret;
	
error:
	transport_free_buf_pool_elem(elem, arg, idx);
	return ret;
}

int com_alloc_rdma_pool(struct com_ep *ep, int num_rdma, int buf_size)
{
	int ret, size;
	int i;
	struct ib_phys_buf ipb;
	boolean            register_mr = TRUE;
	struct buf_entry *be;
	
	ep->num_rdma = num_rdma;
	ep->rdma_buf_size = buf_size;
		
	size = num_rdma * buf_size;
	ep->rdma_mem = NULL;
	
	/* allocate array of buf_entry pointers */
	ep->rdma_pool = kmalloc (sizeof (struct buf_entry*) * num_rdma,
	                         GFP_NOFS);
	if (!ep->rdma_pool) {
		ret = -ENOMEM;
		goto err;
	}
	
	for (i=0; i<num_rdma; i++) {
		ep->rdma_pool[i] = kmalloc (sizeof (struct buf_entry), 
		                            GFP_NOFS);
		if (!ep->rdma_pool[i]) {
			ret = -ENOMEM;
			goto err;
		}
        ep->rdma_pool[i]->buf_transport_data = 
            kzalloc(sizeof(ib_com_buf_data_t), GFP_NOFS);
        if (!ep->rdma_pool[i]->buf_transport_data) {
            ret = -ENOMEM;
            goto err;
        }
	}

	rna_trace("rna: page_size = %ld, rdma_alloc total size %d, rdma_buf size %d \n", 
					PAGE_SIZE, size, buf_size);

	atomic_set(&ep->rdma_avail, ep->num_rdma);
	atomic_set(&ep->rdma_posted, 0);
    atomic_set(&ep->min_rdma_avail, ep->num_rdma);
	ep->next_rdma = 0;
	
	/* init rdma pool */
	
	for(i=0; i< num_rdma; i++) {
		be = ep->rdma_pool[i];
		be->mem = kmalloc(buf_size, GFP_NOFS);
		be->index = i;

		if(be->mem) {
			be->mem_dma = ib_dma_map_single(ep->cma_id->device,
			                                be->mem, 
			                                buf_size, 
			                                DMA_BIDIRECTIONAL);

			ipb.addr = be->mem_dma;
			ipb.size = buf_size;

			be->mr = NULL;
			if (register_mr) {
				be->mr = com_register_mr(ep, 
				                         &ipb, 
				                         &be->mem_dma);
			}
		} else {
			rna_printk(KERN_ERR, "couldn't allocate all rdma buffers\n");
			ret = -ENOMEM;
			goto err;
		}
		atomic_set(&be->buf_use_state, BUF_USE_FREE);
		atomic_set(&be->extra_completions, 0);
		be->ep = ep;
		be->is_rdma_buf = TRUE;
	}
	
    rna_trace("success, num_rdma %d, size %d\n",
               ep->num_rdma, 
               ep->rdma_buf_size);
	return 0;
	
err:
	if (ep->rdma_pool)
		com_free_rdma_pool(ep);

	return ret;	
}

void com_dereg_single(struct com_ep *ep, struct rdma_buf *rdma_buf)
{
	if (rdma_buf->ib_device && rdma_buf->rdma_mem_dma) {
		ib_dma_unmap_single(rdma_buf->ib_device, 
							rdma_buf->rdma_mem_dma, 
							rdma_buf->size, 
							rdma_buf->direction);
		rdma_buf->ib_device = NULL;
        com_unregister_mr(ep, &rdma_buf->mr);
	}
}	

int com_reg_single(struct com_ep *ep, 
					struct rdma_buf *rdma_buf,
					enum dma_data_direction direction)
{
    int ret = 0;
	struct ib_phys_buf ipb;

    rna_trace("com_reg_single: ep [%p] rdma_buf [%p] direction [%d]\n",
            ep,
            rdma_buf,
            direction);
    if (NULL == ep) {
        printk("com_reg_single: NULL EP\n");
        ret = -1;
    } else if (NULL == rdma_buf) {
        printk("com_reg_single: NULL RDMA BUF\n");
        ret = -1;
    } else {

        rdma_buf->rdma_mem_dma = ib_dma_map_single(ep->cma_id->device,
                                                   rdma_buf->rdma_mem,
                                                   rdma_buf->size, 
                                                   direction);

        if (ib_dma_mapping_error(ep->cma_id->device, rdma_buf->rdma_mem_dma)) {
            printk("error in com_reg_single\n");
            return -1;
        }
        rdma_buf->ib_device = ep->cma_id->device;
		ipb.addr = rdma_buf->rdma_mem_dma;
    	ipb.size = rdma_buf->size;

    	rdma_buf->mr = com_register_mr(ep, 
                                       &ipb,
                                       &rdma_buf->rdma_mem_dma);

		if (IS_ERR(rdma_buf->mr)){
			rdma_buf->mr = ep->mr;
			rna_trace("Failed to register buf pool entry for ep[%p] using ep->mr[%p]\n",ep,ep->mr);
		}


        rdma_buf->direction = direction;
        
        rna_trace("com_reg_single: rdma registration success, rdma_virt_mem %p\n",
                   rdma_buf->rdma_mem);
    }

	return ret;
}

void com_dereg_sgl(struct com_ep *ep, struct scatterlist *sgl, 
                   int nents, enum dma_data_direction dir)
{
     BUG_ON(NULL == sgl);
     BUG_ON(NULL == ep);
	 
	 if(NULL == ep->cma_id){
		/* TODO: Make this return a value and an error here */
		return;
	 }
	 
     ib_dma_unmap_sg(ep->cma_id->device, sgl, nents, dir);
}

int com_reg_sgl(struct com_ep *ep, struct scatterlist *sgl, 
                int nents, enum dma_data_direction dir)
{
	BUG_ON(NULL == sgl);
	BUG_ON(NULL == ep);
	
	if(NULL == ep->cma_id){
		return -EINVAL;
	}	
	return ib_dma_map_sg(ep->cma_id->device, sgl, nents, dir);
}

int com_mapping_error(struct com_ep *ep, struct scatterlist *sgl)
{
    // the linux kernels x86_64 dma mapping code is such that if mapping
    // any entry of the scatterlist fails the whole operation fails
    // so we only need to check the first entry
    // Use the IB version of this function - cf. com_rdma_read()
    return ib_dma_mapping_error(ep->cma_id->device, ib_sg_dma_address(ep->cma_id->device,sgl));
}

/* Test if the given rdma buffer is registered with an ep. */

int com_isreg(struct com_ep *ep, struct rdma_buf *rdma_buf)
{
	int ret=FALSE;

	BUG_ON(NULL == rdma_buf);
	BUG_ON(NULL == ep);

	/* Check if the buffer matches the ep. */
	if (NULL != rdma_buf->mr && 
	    rdma_buf->mr == ep->mr &&
	    rdma_buf->ib_device == ep->cma_id->device) {
		ret = TRUE;
	}
	
	return ret;
}

/* Disconnect the EP. Note: This can only be called once. Once disconnected 
   we reset the connected flag to prevent corrupting the OFED layer. */
int com_disconnect(struct com_ep *ep)
{
	int ret = 0;
	struct rdma_cm_id *cma_id = NULL;

	rna_spin_lock(ep->transport_handle->ep_dsc_lock);
	
	/* If connected != 1, then we haven't gotten a connect_callback yet. */
	if(ep->connected == 0){
		ep->connected = -1;		
	}
    cma_id = ep->cma_id;

	
	rna_spin_unlock(ep->transport_handle->ep_dsc_lock);

	if(cma_id){
		ret = rdma_disconnect(cma_id);
		if (ret) {
			rna_printk(KERN_INFO,"fldc_com: disconnect ep %p, ret %d\n", ep, ret);
		}		
	}
	
	return ret;
}

static void rna_add_device(struct ib_device *device)
{
	struct device_context *dev;
	int ret=0;
	int     found=0;

	mutex_lock(&dev_lst_lock);

	list_for_each_entry(dev, &dev_lst_head, entries) {
		if (dev->ib_device->node_guid == device->node_guid) {
			found = 1;
			break;
		}
	}

	if (!found) {
		dev = rna_kzalloc(dev, GFP_NOFS);
		if (!dev) {
			ret = -ENOMEM;
			goto err1;
		}
		dev->ib_device = device;

		if( ib_query_device( device,&dev->attr ) == 0 ) {
			printk( "IB device %s found with %d port(s) Max WR %d Max SGE %d\n",
			        device->name,device->phys_port_cnt,
			        dev->attr.max_qp_wr,dev->attr.max_sge );
		} else {
			printk( "%s: failed to query device\n",__FUNCTION__ );
			goto err1;
		}

		dev->pd = ib_alloc_pd(dev->ib_device);
		if (!dev->pd) {
			ret = -ENOMEM;
			printk("fldc_com: unable to allocate PD\n");
			goto err1;
		}

		dev->mr = ib_get_dma_mr(dev->pd, IB_ACCESS_LOCAL_WRITE |
		                        IB_ACCESS_REMOTE_WRITE |
		                        IB_ACCESS_REMOTE_READ);

		if (IS_ERR(dev->mr)) {
			printk("err allocating dma mr\n");
			dev->mr = NULL;
			goto dma_mr_err;
		}

		printk("adding device type [%s] transport [%s] name [%s] "
		       "module [%s] guid [%"PRIx64"]\n",
		       com_get_ib_node_type_string(device->node_type),
		       com_get_ib_transport_string(rdma_node_get_transport(device->node_type)),
		       device->name,
		       device->owner->name,
		       device->node_guid);
		list_add(&dev->entries,&dev_lst_head);
		mutex_unlock(&dev_lst_lock);
	} 
	else
		mutex_unlock(&dev_lst_lock);

	goto done;

dma_mr_err:
	ib_dealloc_pd(dev->pd);
err1:
	mutex_unlock(&dev_lst_lock);

	if(dev)
		kfree(dev);
	dev=NULL;

done:
	return;

}

static void rna_remove_device(struct ib_device *device)
{
}

/*
struct ib_client rna_ib_client = {
        .name   = "rnacache",
        .add    = rna_add_device,
        .remove = rna_remove_device
};
*/

uint64_t com_get_guid (struct com_ep* ep) 
{
	return ep->cma_id->device->node_guid;
}

/* Extract an rkey from rdma_buf structure.  We need a function
 * for this because the rkey is found within structures that
 * the non-ib code shouldn't have to know about. */
rna_rkey_t com_get_rkey(struct com_ep *ep, const struct rdma_buf* buf) 
{
	rna_rkey_t rna_rkey = buf->mr->rkey;

	return rna_rkey;
}

/* Note: this gets the attributes for the first device in the list.
 * This may not be what you want. */
int transport_get_device_attributes(struct rna_transport_handle *com_handle,
                                    enum com_type type,
                                    struct rna_dev_attr *attr )
{
    struct device_context *dev = NULL;
    int ret = -EINVAL;

    BUG_ON(NULL == com_handle || NULL == attr);
    BUG_ON(RC != type);

    rna_printk(KERN_INFO,
               "getting device attributes com_handle = %p, attr = %p\n", com_handle, attr);

    mutex_lock( &dev_lst_lock );
    if (list_empty (&dev_lst_head)) {
        rna_printk(KERN_ERR, "Device list empty\n");
    } else {
        dev = container_of( dev_lst_head.next, struct device_context, entries );
    }
    mutex_unlock( &dev_lst_lock );

    if( dev != NULL ) {
        /* Mellanox Tavor cards lie about the maximum scatter list size they support */
        attr->max_sge = dev->attr.max_sge;
        attr->max_wr  = dev->attr.max_qp_wr;
        ret = 0;
    }

    return ret;
}

/*
struct rdma_sgl_io {
    struct ib_sge        rsgli_sge[256],
    struct buf_entry    *rsgli_buf_entry,
    struct com_rdma_msg  rsgli_rdma_msg,
    rna_addr_t           rsgli_remote_addr,
    rna_rkey_t           rsgli_remote_rkey,
    int                  rsgli_rdma_size,
    void                *rsgli_context,
}

struct ib_cache_info_member {
    struct list_head entry;
    char             data[0];
};

static struct ib_cache_info {
    struct kmem_cache *cache;
    mempool_t         *pool;
    char              *name;
    size_t             size;
    int                mempool_size;
    int                outstanding_mem;
    struct list_head   member_list;
    spinlock_t         member_list_lock;
} ib_cache_info[] = {
    .cache          = NULL,
    .pool           = NULL,
    .name           = "ib_pend_io",
    .size           = sizeof(struct ib_cache_info_member) +
                      sizeof(struct rdma_sgl_cache),
    .mempool_size   = NR_CPUS,
    .outstnding_mem = {0},
}

static struct ib_cache_info * sgl_cache_info = &ib_cache_info[0];
struct rdma_sgl_io * w;
if( (w = rnablk_mempool_alloc( sgl_cache_info )) == NULL ) {
w->rsgli_buf_entry = buf_entry;
w->rsgli_context = context;
} else {
RNABLK_INIT_RNABLK_WORK(w, w, ib_queued_rdam_io);
wd->buf_entry = buf_entry;
wd->context = context;
rna_queue_work(ep->transport_handle->workqueue, &w->work);
*/

/* This is called by the real module init function in 
 * rna_com_transport_module.c  */
int transport_module_init (void) 
{
    int ret = 0;

    INIT_LIST_HEAD(&dev_lst_head);
    mutex_init(&dev_lst_lock);

	spin_lock_init(&ib_com_read_credit_lock);
    init_waitqueue_head(&ib_com_read_credit_wait);
    if (0 == ib_read_credits) {
        ib_com_use_read_credits = FALSE;
        rna_printk(KERN_NOTICE, "Disabling ib_com_read_credits\n");
    } else {
        ib_com_use_read_credits = TRUE;
        rna_printk(KERN_NOTICE, "Setting ib_com_read_credits to [%ld]\n",
                   ib_read_credits);
    }
    ib_com_read_credits = ib_read_credits;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
#ifdef RNA_OFED_BUILD
    /* OFED 1.4.1 redefines this function to use the 2.6.22 version */
    ibsgl_cache = kmem_cache_create("fldc_ibsgl_cache",
                                    sizeof(struct ib_sge[256]),
                                    8, 0, NULL);
#else
    ibsgl_cache = kmem_cache_create("fldc_ibsgl_cache", 
                                    sizeof(struct ib_sge[256]), 
                                    8, 0, NULL, NULL);
#endif
#else
    ibsgl_cache = kmem_cache_create("fldc_ibsgl_cache", 
                                    sizeof(struct ib_sge[256]), 
                                    8, 0, NULL);
#endif
    if (NULL == ibsgl_cache) {
        rna_printk(KERN_ERR, "failed to create ibsgl_cache\n");
        ret = -ENOMEM;
    } else {
        ibsgl_pool = mempool_create(NR_CPUS, 
                                    mempool_alloc_slab, 
                                    mempool_free_slab, 
                                    ibsgl_cache);
        if (NULL == ibsgl_pool) {
            rna_printk(KERN_ERR, "failed to create ibsgl_pool\n");
            kmem_cache_destroy(ibsgl_cache);
            ret = -ENOMEM;
        }
    }

    if (0 == ret) {
        rna_ib_client = (struct ib_client) {
            .name   = "fldccache",
            .add    = rna_add_device,
            .remove = rna_remove_device
        };

        /* TODO: this is brittle, as we can't guarantee that ib_client
         * and rna_ib_client have the same layout. */
        ib_register_client(&rna_ib_client);
    }

    return ret;	
}

void transport_module_exit (void)
{
    free_all_devices();
    ib_unregister_client((struct ib_client*) &rna_ib_client);

    if (NULL != ibsgl_pool)
        mempool_destroy(ibsgl_pool);
    if (NULL != ibsgl_cache)
        kmem_cache_destroy(ibsgl_cache);

    ibsgl_pool = NULL;
    ibsgl_cache = NULL;
}

struct rna_transport_handle* transport_init (struct rna_com_attrs *attrs)
{
	int ret = 0;
	struct rna_transport_handle* com_handle = rna_kzalloc(com_handle, GFP_NOFS);

	if (NULL == com_handle) {
		ret = -ENOMEM;
		goto out;
	}

	/* We don't want the application to try to use an RDMA
	 * transport when there is no RDMA-capable hardware. */
	mutex_lock(&dev_lst_lock);
	if (list_empty(&dev_lst_head)) {
		mutex_unlock(&dev_lst_lock);
		rna_printk(KERN_ERR, "No IB devices found.\n");
		ret = -ENODEV;
		goto out;
	}
	mutex_unlock(&dev_lst_lock);

	com_handle->comp_mode = attrs->comp_mode;
	com_handle->retry_count = attrs->retry_count;
	com_handle->rnr_retry_count = attrs->rnr_retry_count;

	if (-1 == attrs->retry_count) {
		com_handle->retry_count = RNA_COM_RETRY_COUNT;
	} else {
		com_handle->retry_count = attrs->retry_count;
	}

	if (-1 == attrs->rnr_retry_count) {
		com_handle->rnr_retry_count = RNA_COM_RNR_RETRY_COUNT;
	} else {
        com_handle->rnr_retry_count = attrs->rnr_retry_count;
	}

	rna_printk(KERN_INFO, "transport_init \n");

	atomic_set(&com_handle->transport_state, KERNEL_TRANSPORT_STATE_OK);

	atomic_set(&com_handle->connection_count, 0);
	init_waitqueue_head(&com_handle->all_disconnected_wait);
	
	/* Need more data to determine if it's better to have multiple 
	 * threads polling the cq for each completion or single thread 
	 * polling the cq to read > 1 completion at a time
	 */
	 
	com_handle->rna_workq = rna_create_workqueue("fldc_kqp");
	if (!com_handle->rna_workq) {
		rna_printk(KERN_ERR, "failed to create fldc_workq\n");
		ret = -ENOMEM;
		goto out;
	}
	
	com_handle->rna_conn_workq = rna_create_singlethread_workqueue("fldc_kcm");
	if (!com_handle->rna_conn_workq) {
		rna_printk(KERN_ERR, "failed to create fldc_conn_workq\n");
		ret = -ENOMEM;
		goto out;
	}
	
	com_handle->rna_clean_workq = rna_create_singlethread_workqueue("fldc_kcl");
	if (!com_handle->rna_clean_workq) {
		rna_printk(KERN_ERR, "failed to create fldc_clean_workq\n");
		ret = -ENOMEM;
		goto out;
	}

	com_handle->rna_delayed_send_workq = 
		rna_create_singlethread_workqueue("fldc_dsend");
	if (!com_handle->rna_delayed_send_workq) {
		rna_printk(KERN_ERR, 
		           "failed to create fldc_delayed_send_workq\n");
		goto out;
	}
	
	INIT_LIST_HEAD(&com_handle->ep_lst_head);

	
	RNA_INIT_WORK(&com_handle->clean_work, cleanup_work, &com_handle->clean_work);
	
	mutex_init(&com_handle->ep_lst_lock);
	mutex_init(&com_handle->transport_state_lock);
	rna_spin_lock_init(com_handle->ep_ref_lock);
	rna_spin_lock_init(com_handle->ep_dsc_lock);

	com_handle->initialized = TRUE;

out:
	/* todo: shut down work queues if an error occurred*/

	if (0 == ret) {
		rna_printk(KERN_INFO, "transport_init completed\n");
		return com_handle;
	} else {
		if (com_handle) {
			if (com_handle->rna_workq)
				rna_destroy_workqueue(com_handle->rna_workq);
			if (com_handle->rna_conn_workq)
				rna_destroy_workqueue(com_handle->rna_conn_workq);
	        if (com_handle->rna_clean_workq)
				rna_destroy_workqueue(com_handle->rna_clean_workq);
			if (com_handle->rna_delayed_send_workq)
				rna_destroy_workqueue(com_handle->rna_delayed_send_workq);
			kfree(com_handle);
		}

		rna_printk(KERN_ERR, "transport_init failed\n");

		return NULL;
	}
}

int transport_disable(struct rna_transport_handle* com_handle)
{
    int ret = 0;

    BUG_ON(NULL == com_handle);

    set_disconnecting(com_handle);

    /* Disconnect first. This will likely schedule disconnect callbacks.*/
    ret = transport_disconnect_all_eps(com_handle);

    /* Disallow any more work elements from being queued. */
    set_shutting_down(com_handle);

    /* We need to flush these before freeing all the EPs, since freeing the EPs
     * could have catestrophic effects if one of the EPs */

    /* To avoid spin locking the shutting down atomic We flush twice.
       It doesn't guarantee that one of the queue threads could have
       posted something however. The likelyhood is *VERY* low. */

    /* TODO: Efficient ways of making the check and post to queue atomic.
       Maybe stop the threads? */

    rna_flush_workqueue(com_handle->rna_delayed_send_workq);
    rna_flush_workqueue(com_handle->rna_workq);
    rna_flush_workqueue(com_handle->rna_conn_workq);
    rna_flush_workqueue(com_handle->rna_clean_workq);

    rna_flush_workqueue(com_handle->rna_delayed_send_workq);
    rna_flush_workqueue(com_handle->rna_workq);
    rna_flush_workqueue(com_handle->rna_conn_workq);
    rna_flush_workqueue(com_handle->rna_clean_workq);

    return 0;
}

int transport_exit(struct rna_transport_handle *com_handle)
{
    if (com_handle->initialized) {
        transport_disable(com_handle);

        rna_destroy_workqueue(com_handle->rna_delayed_send_workq);
        rna_destroy_workqueue(com_handle->rna_workq);
        rna_destroy_workqueue(com_handle->rna_conn_workq);
        rna_destroy_workqueue(com_handle->rna_clean_workq);

        /* free any eps that did not get cleaned up in 
         * disconnect_all phase
         */
        free_all_eps(com_handle);
        com_handle->initialized = FALSE;
    }
    kfree(com_handle);

    return 0;
}

static struct ib_mr * rna_com_device_reg_mr (struct device_context *dev)
{
    BUG_ON(NULL == dev);

    if(FALSE == atomic_cmpxchg(&dev->mr_registered, FALSE, TRUE)) {
        dev->mr = ib_get_dma_mr(dev->pd, 
                                (IB_ACCESS_LOCAL_WRITE | 
                                 IB_ACCESS_REMOTE_WRITE | 
                                 IB_ACCESS_REMOTE_READ));
        if ((NULL == dev->mr) || IS_ERR(dev->mr)) {
            rna_printk(KERN_ERR, "error allocating dma mr for dev [%p]\n", dev);
        } else {
            rna_trace("success allocating dma mr for dev [%p]\n", dev);
        }
    }
    return dev->mr;
}

struct ib_mr * com_ep_get_mr (struct com_ep *ep)
{
    struct ib_mr *mr = NULL;
    if ((NULL != ep) &&
        (NULL != ep->dev)) {
        mr = ep->dev->mr;
    }
    return mr;
}

// unlike com_ep_get_mr, this will register the
// global memory region if it is not already registered
static struct ib_mr * rna_com_ep_reg_mr (struct com_ep *ep)
{
    BUG_ON(NULL == ep);
    BUG_ON(NULL == ep->dev);
    return rna_com_device_reg_mr(ep->dev);
}

static struct ib_mr * com_register_mr (struct com_ep      *ep,
                                       struct ib_phys_buf *ipb,
                                       dma_addr_t         *rdma_mem_dma)
{
    struct ib_mr *mr = NULL;

    BUG_ON(NULL == ep);
 
    // this will register the global region, if need be
    mr = rna_com_ep_reg_mr(ep);

    if ((NULL == mr) || IS_ERR(mr)) {
        /*
         * global memory registration not supported by this card/driver.
         * use individual registration instead
         */

        mr = ib_reg_phys_mr(ep->pd, 
                            ipb, 
                            1,
                            (IB_ACCESS_LOCAL_WRITE | 
                            IB_ACCESS_REMOTE_WRITE | 
                            IB_ACCESS_REMOTE_READ), 
                            rdma_mem_dma);
        if ((NULL == mr) || IS_ERR(mr)) {
            rna_trace("Failed to register buf pool entry for ep[%p]\n",
                      ep);
        }
    }

    return mr;
}

static void com_unregister_mr(struct com_ep *ep,
                                  struct ib_mr **mr_p)
{
    struct ib_mr *mr = NULL;

    if (NULL == ep) {
        /* XXX: we should not be in this state,
         * but we find that we ofter are after a lot
         * of HA testing.  need to investigate further,
         * but for now, let's not assert
         */
        rna_printk(KERN_WARNING,
                   "NULL EP\n");
    } else {
        BUG_ON(NULL == mr_p);
        BUG_ON(NULL == *mr_p);
        
        mr = * mr_p;
        
        if((NULL != mr) && !IS_ERR(mr) && (mr != com_ep_get_mr(ep))) {
            ib_dereg_mr(mr);
        }
        *mr_p = NULL;
    }
}

/*
 * POST_SEND completion routine that doesn't perform any actions.
 * Used by fake rdma operations when sending msgs.
 */
static int
ib_rdma_snd_noop_cb(struct com_ep *ep       __attribute__((unused)),
                    void          *ep_ctx   __attribute__((unused)),
                    void          *send_ctx __attribute__((unused)),
                    int            status   __attribute__((unused)))
{
    return 0;
}

/*
 * The last send for the fake rdma write has completed.
 * The send_ctx is the pointer to the rdma write buf_entry
 * which we will now complete.
 */
static int
ib_rdma_write_snd_complete(struct com_ep *ep,
                           void          *ep_ctx __attribute__((unused)),
                           void          *send_ctx,
                           int            status)
{
    struct buf_entry *rdma_buf = (typeof(rdma_buf)) send_ctx;

    BUG_ON(atomic_read(&rdma_buf->buf_use_state) == BUF_USE_FREE);
    BUG_ON(!rdma_buf->is_rdma_buf);

    if (!(rdma_buf->op_flags & RDMA_OP_SERVER_ACK)) {
//        rna_printk(KERN_ERR,
        rna_printk(KERN_DEBUG,
                "complete rdma write rdma_buf 0x%p on EP[%p] status[%d]\n",
                rdma_buf, ep, status);
        _fake_rdma_completion(ep,
                              (uint64_t)rdma_buf,
                              IB_WC_RDMA_WRITE,
                              status);
    }
    return 0;
}

/*
 * Begin fake rdma read with a send.
 * Note that buf came from rdma_pool and should not be
 * completed until the RDMA_MSG_TYPE_READ_RESP msgs
 * have been processed.
 */
static int
ib_send_rdma_read_msg(struct com_ep *ep,
                      struct buf_entry *buf_entry,
                      rna_addr_t remote_addr,
                      rna_rkey_t remote_rkey,
                      int size,
                      void *context)
{
    struct buf_entry *send_buf = NULL;
    struct com_rdma_msg *msg = NULL;
    int ret = -EAGAIN;

    /* Use the send buf associated with this rdma buffer, which was allocated
     * prior to this call. Clear the pointer to this send buffer in this
     * rdma buffer.
     */
    send_buf = buf_entry->rdma_send_buf;
    buf_entry->rdma_send_buf = NULL;
    if (unlikely(NULL == send_buf)) {
        rna_printk(KERN_ERR, "rdma buffer lacks associated send buffer\n");
        print_ep(ep);
        BUG_ON(NULL == send_buf);
    }

    BUG_ON(send_buf->mem_size < DEFAULT_RDMA_SENDBUF_SIZE);

    /*
     * Once the read is complete we can call the attribute send completion 
     * call back, but for this send do not notify the caller. 
     */
    send_buf->send_cmp_cb = ib_rdma_snd_noop_cb;

    msg = (struct com_rdma_msg *)send_buf->mem;
    memset (msg, 0, sizeof(*msg));

    msg->msg_type = RDMA_MSG_TYPE_READ;
    msg->hdr.cookie = (uint64_t)buf_entry; /* saving the rdma buf_entry */
    msg->hdr.payload_len = size;

    msg->u.com_rdma_req.addr = remote_addr;
    msg->u.com_rdma_req.rkey = remote_rkey;
    msg->u.com_rdma_req.len = size;
    msg->u.com_rdma_req.bounce_buf_addr = buf_entry->bounce_address;
    bswap_com_rdma_msg(msg);

    ib_wait_on_read_credit(buf_entry);
    rna_printk(KERN_DEBUG,
               "RDMA_MSG_TYPE_READ (via send) payload_len [%"PRIu64"] on ep[%p] "
               "Addr[%"PRIx64":%"PRIx64"] RKEY[%"PRIx64"] bb_addr [%"PRIu64"]\n",
               msg->hdr.payload_len, ep,
               msg->u.com_rdma_req.addr.device_id.data,
               msg->u.com_rdma_req.addr.base_addr,
               msg->u.com_rdma_req.rkey,
               msg->u.com_rdma_req.bounce_buf_addr);

    ret = com_send_internal(ep, send_buf, sizeof(*msg), FALSE, ENV_TYPE_RDMA);

    if (0 == ret) {
        /* TODO: consider fake rdma counters */
        atomic_inc(&ep->rdma_posted);
    }

out:
    return ret;
}

static struct buf_entry*
ib_locate_rdma_buf_entry(struct com_ep *ep, uint64_t tid)
{
    int i = 0;
    unsigned long irqflags;
    struct buf_entry *be_p = (struct buf_entry *)tid;

    /* search the rdma_pool for this specific entry */
    rna_spin_lock_irqsave(ep->rdma_lock, irqflags);

    for (i=0; i<ep->num_rdma; i++) {
        if (be_p == ep->rdma_pool[i]) {
            if (atomic_read(&ep->rdma_pool[i]->buf_use_state) == BUF_USE_FREE) {
                rna_printk(KERN_ERR, "buffer [%p] already completed\n", be_p);
                dump_stack();
            }
            rna_spin_unlock_irqrestore(ep->rdma_lock, irqflags);
            return be_p;
        }
    }

    rna_printk(KERN_ERR, "buffer [%p] not found\n", be_p);
    dump_stack();

    rna_spin_unlock_irqrestore(ep->rdma_lock, irqflags);

    return NULL;
}

static int
ib_rdma_locate_segment(struct buf_entry *rdma_buf,
                       int  offset,
                       int  *seg_offset,
                       int  *seg_remain)
{
    int i;
    int bytes = 0;

    for (i=0; i< rdma_buf->sgl_nents; i++) {
        if (rdma_buf->sgl[i].length + bytes > offset) {
            *seg_offset = offset - bytes;
            *seg_remain = rdma_buf->sgl[i].length - *seg_offset;
            return i;
        }
        bytes += rdma_buf->sgl[i].length;
    }
   
    return -1;
}

static int
process_rdma_read_response(struct com_rdma_msg *rdma_msg,
                           struct buf_entry *rdma_buf,
                           void *data_buf,
                           int buf_len)
{
    int msg_size = 0;
    int to_copy = 0;
    char *env_ptr = (typeof(env_ptr)) data_buf;
    rna_addr_t remote;
    int ret = 0;
    kernel_com_bounce_read_t *bounce_ctx;

    rna_printk(KERN_DEBUG,
               "rdma_buf 0x%p mem 0x%p payload_len [%"PRIu64"] pkt_offset "
               "[%"PRIu64"] pkt_len [%"PRIu64"] buf_len [%d] bounce_address "
               " [0x%"PRIx64"] status [%u]\n",
               rdma_buf,
               rdma_buf->mem,
               rdma_msg->hdr.payload_len,
               rdma_msg->hdr.pkt_offset,
               rdma_msg->hdr.pkt_len,
               buf_len,
               rdma_buf->bounce_address,
               rdma_msg->hdr.status);

    msg_size = rdma_msg->hdr.payload_len;
    to_copy = rdma_msg->hdr.pkt_len;
    if (buf_len < to_copy) {
        to_copy = buf_len;
    }

    if (RDMA_READ == rdma_buf->op_type) {
        /* XXX This has to change since ctx is used by file client. */
        if (0 == rdma_buf->bounce_address) {
            if (0 == rdma_msg->hdr.status) {
                env_ptr = (char *)rdma_buf->ctx + rdma_msg->hdr.pkt_offset;
                memcpy(env_ptr, data_buf, to_copy);
            } else {
                ret = rdma_msg->hdr.status;
            }
        } else {
            bounce_ctx = (kernel_com_bounce_read_t *)rdma_buf->ctx;
            rna_printk(KERN_DEBUG, 
                       "read completed to bounce buffer for buf [0x%p]\n", 
                       rdma_buf);
            /* Issue rdma read from the bounce buffer */
            rdma_buf->ctx = NULL;
            BUG_ON(NULL != bounce_ctx->br_sgl);
            if (0 == rdma_msg->hdr.status) {
                remote.device_id.data = 0;
                remote.base_addr = rdma_buf->bounce_address;

                /* Do RDMA read from bounce buffer */
                init_buf_for_rdma_read(rdma_buf, remote, 
                                    BB_CTXTP(bounce_ctx->br_ep)->bbc_buf_rkey);
                rdma_buf->bounce_send_start = getrawmonotonic_ns();
                ret = rdma_read_post_send(bounce_ctx->br_ep,
                                          rdma_buf,
                                          remote,
                                          bounce_ctx->br_buf,
                                      BB_CTXTP(bounce_ctx->br_ep)->bbc_buf_rkey,
                                          bounce_ctx->br_size,
                                          bounce_ctx->br_context,
                                          bounce_ctx->br_signaled,
                                          bounce_ctx->br_flags);
            } else {
                ret = rdma_msg->hdr.status;
            }
            if (0 != ret) {
                repost_read_credit(rdma_buf);
                rna_printk(KERN_ERR,
                           "Failed to do RDMA READ from bounce buffer for buf "
                           "[0x%p] ret [%d]\n", rdma_buf, ret);
                if (1 == atomic_cmpxchg(&rdma_buf->extra_completions, 1, 0)) {
                    rna_printk(KERN_DEBUG,
                               "Cleared extra_completions for rdma_buf [0x%p]\n",
                               rdma_buf);
                } else {
                    rna_printk(KERN_WARNING,
                               "extra_completions not set for rdma_buf [0x%p]\n",
                               rdma_buf);
                }
            }
            kfree(bounce_ctx);
        }
    } else if (RDMA_READ_SGL == rdma_buf->op_type) {
        if (0 == rdma_buf->bounce_address) {
            if (0 == rdma_msg->hdr.status) {
                int seg_offset = 0;
                int seg_remain = 0;
                int seg_index;

                while (1) {
                    seg_index = ib_rdma_locate_segment(rdma_buf,
                                                       rdma_buf->mem_size,
                                                       &seg_offset,
                                                       &seg_remain);
                    if (seg_index < 0) {
                        rna_printk(KERN_ERR,
                                   "Segment could not be located for rdma_buf[%p]\n",
                                   rdma_buf);
                        return -EIO;
                    }
                    to_copy = seg_remain;
                    if (buf_len < to_copy) {
                        to_copy = buf_len;
                    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
                    env_ptr = (char *)page_address(rdma_buf->sgl[seg_index].page) +
                        rdma_buf->sgl[seg_index].offset +
                        seg_offset;
#else
                    env_ptr = (char *)sg_virt(&rdma_buf->sgl[seg_index]) +
                        seg_offset;
#endif

                    memcpy(env_ptr, data_buf, to_copy);

                    buf_len -= to_copy;
                    rdma_buf->mem_size += to_copy;
                    data_buf += to_copy;

                    if ((0 >= buf_len) || (rdma_buf->mem_size == msg_size)) {
                        break;
                    }
                }
            } else {
                ret = rdma_msg->hdr.status;
            }
        } else {
            ib_com_buf_data_t *buf_data;
            buf_data = (ib_com_buf_data_t *)rdma_buf->buf_transport_data;

            bounce_ctx = (kernel_com_bounce_read_t *)rdma_buf->ctx;
            rdma_buf->ctx = NULL;
            if (0 == rdma_msg->hdr.status) {
                remote.device_id.data = 0;
                remote.base_addr = rdma_buf->bounce_address;
                BUG_ON(NULL != bounce_ctx->br_buf);
                /* Now do the RDMA read from the bounce buffer */
                com_init_ib_send_wr_and_buf(&buf_data->icb_send_wr,
                                            rdma_buf,
                                            bounce_ctx->br_context,
                                            remote,
                                            BB_CTXTP(bounce_ctx->br_ep)->
                                                bbc_buf_rkey,
                                            bounce_ctx->br_nents, 
                                            IB_WR_RDMA_READ,
                                            bounce_ctx->br_flags);
                
                rdma_buf->bounce_send_start = getrawmonotonic_ns();

                ret = kernel_com_sgl_post_send(bounce_ctx->br_ep,
                                      bounce_ctx->br_context,
                                      rdma_buf,
                                      bounce_ctx->br_sgl,
                                      BB_CTXTP(bounce_ctx->br_ep)->bbc_buf_rkey,
                                      FALSE,
                                      bounce_ctx->br_flags);
            } else {
                ret = rdma_msg->hdr.status;
            }
            
            if (0 != ret) {
                repost_read_credit(rdma_buf);
                rna_printk(KERN_ERR,
                           "Failed to do RDMA READ from bounce buffer for buf "
                           "[0x%p] ret [%d]\n", rdma_buf, ret);
                if (1 == atomic_cmpxchg(&rdma_buf->extra_completions, 1, 0)) {
                    rna_printk(KERN_DEBUG,
                               "Cleared extra_completions for rdma_buf [0x%p]\n",
                               rdma_buf);
                } else {
                    rna_printk(KERN_WARNING,
                               "extra_completions not set for rdma_buf [0x%p]\n",
                               rdma_buf);
                }
            }
            kfree(bounce_ctx);
        }
    }
    if (0 != rdma_buf->bounce_address) {
        return ret;
    } else if (unlikely((0 == ret) &&
                        ((rdma_msg->hdr.pkt_offset + rdma_msg->hdr.pkt_len) <
                         rdma_msg->hdr.payload_len))) {
        /* 
         * XXX: Better to have receiver track data copied since
         * final msg out of order could prematurely complete the read.
         */
        rna_printk(KERN_WARNING, 
                   "Unexpected EAGAIN for RoCE read with rdma_buf [0x%p]\n",
                   rdma_buf);
        return EAGAIN;
    } else {
        return ret;
    }
}

static int
process_rdma_write_response(struct com_ep *ep,
                            struct com_rdma_msg *rdma_msg,
                            struct buf_entry *rdma_buf,
                            void *data_buf,
                            int buf_len)
{
    int msg_size = 0;
    int to_copy = 0;
    char *env_ptr = (typeof(env_ptr)) data_buf;

    if (rdma_buf->op_flags & RDMA_OP_SERVER_ACK) {
        rna_printk(KERN_DEBUG,
                   "complete rdma write rdma_buf 0x%p on EP[%p] cookie[%"PRIx64"] status[%d]\n",
                   rdma_buf, ep, rdma_msg->hdr.cookie, rdma_msg->hdr.status);
        _fake_rdma_completion(ep,
                              (uint64_t)rdma_buf,
                              IB_WC_RDMA_WRITE,
                              rdma_msg->hdr.status);
    } else {
        rna_printk(KERN_ERR,
            "Write response was not expected, op_flags[0x%x] "
            "rdma_buf 0x%p payload_len [%"PRIu64"] pkt_offset [%"PRIx64"] "
            "pkt_len [%"PRIu64"] buf_len [%d]\n",
            rdma_buf->op_flags,
            rdma_buf,
            rdma_msg->hdr.payload_len,
            rdma_msg->hdr.pkt_offset,
            rdma_msg->hdr.pkt_len,
            buf_len);
    }
    return 0;
}

/** 
 * Processing of IB recv msg with envelope msg_type ENV_TYPE_RDMA
 *
 * @param ep - end point struct (contains state data and com handles)
 * @param env - com envelope
 * @param rdma_msg - com rdma msg
 * @param buf - data buffer
 * @param buf_len - length of data buffer;
 *                  may not be filled with payload bytes.
 * @return 0 on success, -1 on failure
 */
int
ib_process_rdma_req(struct com_ep* ep,
                    struct rna_com_envelope *env,
                    struct com_rdma_msg *rdma_msg,
                    void *data_buf,
                    size_t buf_len)
{
    int ret = -1;
    struct buf_entry *rdma_buf = NULL;

    rdma_buf = ib_locate_rdma_buf_entry(ep, rdma_msg->hdr.cookie);
    if (NULL == rdma_buf) {
        rna_printk(KERN_ERR,
                   "EP[%p] RDMA cookie [%"PRIx64"] no buf_entry match.\n",
                   ep, rdma_msg->hdr.cookie);
        return ret;
    }

    if (RDMA_MSG_TYPE_READ_RESP == rdma_msg->msg_type) {
        /*
         * functionality of com_socket_rdma_payload_get
         */
        ret = process_rdma_read_response(rdma_msg, rdma_buf, data_buf, buf_len);
        if (ret) {
            if (ret == EAGAIN) {
                /* we have more data coming in */
            } else {
                rna_printk(KERN_ERR,
                            "EP[%p] RDMA Read request failed. "
                            "Addr[%"PRIx64":%"PRIx64"] RKEY[%"PRIx64"] "
                            "Return code[%d]\n",
                            ep,
                            rdma_msg->u.com_rdma_req.addr.device_id.data,
                            rdma_msg->u.com_rdma_req.addr.base_addr,
                            rdma_msg->u.com_rdma_req.rkey,
                            ret);
                _fake_rdma_completion(ep,
                                      (uint64_t)rdma_buf,
                                      IB_WC_RDMA_READ,
                                      ret);
            }
        } else {
            /* All done. Call the RDMA completion callback and free the buf_entry */
            // The current wc is a POST_RECV and completion will be handled by caller.
            _fake_rdma_completion(ep,
                                  (uint64_t)rdma_buf,
                                  IB_WC_RDMA_READ,
                                  0);
        }
    } else if (RDMA_MSG_TYPE_WRITE == rdma_msg->msg_type) {
        rna_printk(KERN_ERR,
                            "EP[%p] RDMA Write request not supported. "
                            "Addr[%"PRIx64":%"PRIx64"] RKEY[%"PRIx64"]\n",
                            ep,
                            rdma_msg->u.com_rdma_req.addr.device_id.data,
                            rdma_msg->u.com_rdma_req.addr.base_addr,
                            rdma_msg->u.com_rdma_req.rkey);
    } else if (RDMA_MSG_TYPE_WRITE_RESP == rdma_msg->msg_type) {
        ret = process_rdma_write_response(ep,
                                          rdma_msg,
                                          rdma_buf,
                                          data_buf,
                                          buf_len);
    } else {
        rna_printk(KERN_ERR,
                            "EP[%p] RDMA request [%d] not supported. "
                            "Addr[%"PRIx64":%"PRIx64"] RKEY[%"PRIx64"]\n",
                            ep,
                            rdma_msg->msg_type,
                            rdma_msg->u.com_rdma_req.addr.device_id.data,
                            rdma_msg->u.com_rdma_req.addr.base_addr,
                            rdma_msg->u.com_rdma_req.rkey);
    }

    return ret;
}

/*
 * With the introduction of bounce buffers, we no longer need to
 * worry about splitting up an rdma into multiple sends.
 * The use of bounce buffers was designed to avoid the need for just
 * this splitting by having all rdma bigger than MAX_RDMA_VIA_SEND_SIZE
 * use the bounce buffer.
 *
 * If bounce buffers are disabled, then the maximum rdma size is limited to
 * MAX_RDMA_VIA_SEND_SIZE.
 *
 * This means we know that this routine will consume at most one send buf
 * buf_entry for this rdma operation.  This has been allocated prior to
 * calling this routine, and is attached to the rdma buf_entry that was
 * passed in.
 */
static int
ib_send_rdma_write_msg(struct com_ep *ep,
                       struct buf_entry *buf_entry,
                       int size,
                       char signaled,
                       uint32_t flags)
{
    int ret = 0;
    struct com_rdma_msg rdma_msg;
    struct buf_entry *send_buf;
    unsigned char *data_buf = NULL;
    unsigned char *sg_buf_ptr = NULL;
    struct scatterlist *sgl = NULL;
    int sgl_s = 0;
    int copysize = 0;
    int sge_c_l = 0;
    int i = 0;

    BUG_ON(!buf_entry->is_rdma_buf);
    BUG_ON(NULL == buf_entry->rdma_send_buf);

    buf_entry->rdma_data_size = size;
    buf_entry->rdma_flags = flags;

    memset(&rdma_msg, 0, sizeof(rdma_msg));

    rdma_msg.msg_type = RDMA_MSG_TYPE_WRITE;
    // cookie is buf_entry pointer, used to locate the
    // buf_entry for completion callback.
    rdma_msg.hdr.cookie = (uint64_t)buf_entry;

    rdma_msg.hdr.status = RDMA_STATUS_OK;
    rdma_msg.hdr.payload_len = size;
    rdma_msg.hdr.flags = flags;

    /*
     * Default is to always set server ack required.
     */
    buf_entry->op_flags |= RDMA_OP_SERVER_ACK;

    if (buf_entry->op_flags & RDMA_OP_SERVER_ACK) {
        rdma_msg.hdr.flags |= RDMA_MSG_FLAG_RESP_REQ;
    }

    rdma_msg.u.com_rdma_req.addr = buf_entry->rem_addr;
    rdma_msg.u.com_rdma_req.rkey = buf_entry->rkey;
    rdma_msg.u.com_rdma_req.len = size;
    rdma_msg.u.com_rdma_req.bounce_buf_addr = buf_entry->bounce_address;

    /* Use the send buf associated with this rdma buffer, which was allocated
     * prior to this call. Clear the pointer to this send buffer in this
     * rdma buffer.
     */
    send_buf = buf_entry->rdma_send_buf;
    buf_entry->rdma_send_buf = NULL;

    /* XXX DMO copied from the rdma_send_rdma_read() case */
    BUG_ON(send_buf->mem_size < DEFAULT_RDMA_SENDBUF_SIZE);

    rdma_msg.hdr.pkt_offset = 0;
    if (0 == buf_entry->bounce_address) {
        if ((ep->buf_size - sizeof(rdma_msg)) > size) {
            rdma_msg.hdr.pkt_len = size;
        } else {
            rdma_msg.hdr.pkt_len = ep->buf_size - sizeof(rdma_msg);
            rna_printk(KERN_ERR,
                       "xfer size [%d] ep buf_size [%d] sizeof rdma_msg [%u]\n",
                        size,
                        ep->buf_size,
                        (unsigned int)sizeof(rdma_msg));
            print_ep(ep);
            BUG_ON(TRUE);
        }
        /* XXX DMO optimize bstore by limiting write size??? */
        if (rdma_msg.hdr.pkt_len > (int)DEFAULT_RDMA_SENDBUF_PAYLOAD) {
            rna_printk(KERN_ERR,
                       "pkt_len [%"PRIu64"] LIMIT [%d]\n",
                       rdma_msg.hdr.pkt_len,
                       (int)DEFAULT_RDMA_SENDBUF_PAYLOAD);
            print_ep(ep);
            BUG_ON(rdma_msg.hdr.pkt_len > (int)DEFAULT_RDMA_SENDBUF_PAYLOAD);
        }
    } else {
        BUG_ON(0 != rdma_msg.hdr.pkt_offset);
        rdma_msg.hdr.pkt_len = 0;
    }

    memcpy(send_buf->mem, &rdma_msg, sizeof(rdma_msg));
    bswap_com_rdma_msg((struct com_rdma_msg *)&send_buf->mem);

    data_buf = send_buf->mem + sizeof(rdma_msg);

    if (0 == buf_entry->bounce_address) {
        copysize = rdma_msg.hdr.pkt_len;
        for (i = sgl_s; i < buf_entry->sgl_nents; i++) {
            if (buf_entry->sgl[i].length <= copysize) {
                sge_c_l = buf_entry->sgl[i].length;
            } else {
                sge_c_l = copysize;
            }
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
            sg_buf_ptr = (char *)page_address(rdma_buf->sgl[i].page) +
                rdma_buf->sgl[i].offset;
#else
            sg_buf_ptr = (char *)sg_virt(&buf_entry->sgl[i]);
#endif
            memcpy(data_buf, (void *)sg_buf_ptr, sge_c_l);
            buf_entry->sgl[i].offset += sge_c_l;
            buf_entry->sgl[i].length -= sge_c_l;
            data_buf += sge_c_l;
            copysize -= sge_c_l;
            if (0 == copysize) {
                break;
            }
        }
        sgl_s = i;

    }
    send_buf->length = rdma_msg.hdr.pkt_len + sizeof(rdma_msg);
    /*
     * Save the rdma_buf in the send_buf context.
     * The final send completion callback will then use this
     * to complete the rdma write.
     */
    send_buf->context = buf_entry;
    send_buf->send_cmp_cb = ib_rdma_snd_noop_cb;
    if (unlikely(!(rdma_msg.hdr.flags & RDMA_MSG_FLAG_RESP_REQ))) {
        /*
         * Last send, set callback for rdma write completion
         * when not expecting write resp from server side.
         */
        rna_printk(KERN_DEBUG,
                   "last rdma write send, buf_entry [%p] on EP[%p]\n",
               buf_entry, ep);
        send_buf->send_cmp_cb = ib_rdma_write_snd_complete;
    }
    /*
     * Have to check data_sent before calling com_send_internal(), because
     * buf_entry might be released by the callback at any time.
     */
    ret = com_send_internal(ep, send_buf, send_buf->length, FALSE,
                            ENV_TYPE_RDMA);
    if (ret) {
        rna_printk(KERN_ERR,
                   "Failed rdma RDMA_MSG_TYPE_WRITE (via send) "
                   "pktlen [%"PRIu64"] on ep[%p]\n",
                   rdma_msg.hdr.pkt_len, ep);
        return -EIO;
    }

    atomic_inc(&ep->rdma_posted);

    return ret;
}


static int
ib_rdma_sgl(struct com_ep      *ep,
            struct ib_send_wr  *wr,
            rna_addr_t          remote_addr,
            rna_rkey_t          remote_rkey,
            struct scatterlist *sgl,
            int                 write,
            uint32_t            flags)
{
    struct buf_entry *buf_entry = NULL;
    int i;
    int ret = 0;
    int nents = 0;
    uint64_t len = 0;

    buf_entry = (struct buf_entry *)wr->wr_id;
    if (unlikely(NULL == buf_entry)) {
        rna_printk(KERN_ERR, "buf_entry is NULL\n");
        ret = -EINVAL;
        goto out;
    }

	buf_entry->rem_addr = remote_addr;
	buf_entry->rkey = remote_rkey;	

    nents = wr->num_sge;
    if (unlikely(nents > RNA_COM_MAX_SGL)) {
        rna_printk(KERN_ERR, "sgl list too long\n");
        ret = -EINVAL;
        goto out;
    }

    /*
     * Copy rdma information into buf_entry
     */
    for (i = 0; i < nents; i++) {
        len += (sgl +i)->length;
        buf_entry->sgl[i] = sgl[i];
    }
	
    if (len < 4) {
        rna_printk(KERN_ERR,
                "RDMA Op to non-dram media over IB looks too short." \
                "buf_entry [%p] num_sge[%d] size[%"PRIu64"]\n",
                buf_entry, nents, len);
    }

    buf_entry->sgl_nents = nents;
    buf_entry->length    = len;
    buf_entry->rem_addr  = remote_addr;
    buf_entry->rkey      = remote_rkey;
    buf_entry->op_flags  = flags;
    //buf_entry->tid       = atomic_inc_return(&next_tid);

    rna_printk(KERN_DEBUG,
                "RDMA %s to non-dram media over IB. buf[%p] " \
                "num_sge[%d] size[%"PRIu64"]\n",
                (write ? "write" : "read"), buf_entry, nents, len);

    if (write) {
	    ret = ib_send_rdma_write_msg(ep,
                                     buf_entry,
                                     len,
                                     IB_SEND_SIGNALED,
                                     flags);
    } else { // read
        /* buf_entry->op_type already set to RDMA_READ_SGL */
        ret = ib_send_rdma_read_msg(ep,
                                    buf_entry,
                                    remote_addr,
                                    remote_rkey,
                                    len,
                                    buf_entry->context);
    }

    if (ret) {
        rna_printk(KERN_ERR,
                       "failed to post send: %d\n", 
                       ret);
    }
out:
    return ret;
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
 * how-to info on controlling log levels.  Set to 5 normally, or 7
 * for max debugging. (KERN_NOTICE =>5, KERN_INFO => 6, KERN_DEBUG => 7)
 */

int rna_printk_level = 5;

module_param(rna_printk_level, int, 0444);
MODULE_PARM_DESC(rna_printk_level,
                 "Printk level for rnacache; set to 7 for everything or "         
                 "0 for only KERN_EMERG.  Default is 5, which prints "  
                 "only (KERN_NOTICE) or higher.  Set to -1 to use the "
                 "kernel's standard printk settings.");



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
    .com_put_rdma_buf_fn      = com_put_rdma_buf_external,
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
MODULE_LICENSE("GPL");
