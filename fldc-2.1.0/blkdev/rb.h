/**
 * <rb.h> - Dell Fluid Cache block driver
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

#ident "$URL$ $Id$"

#ifndef INCLUDED_SB_H
#define INCLUDED_SB_H

#include "tree.h"

#ifndef WINDOWS_KERNEL

#ifndef _LINUX_RBTREE_H
#include <linux/rbtree.h>
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/timer.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/completion.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <linux/bio.h>
#include <linux/genhd.h>
#include <linux/hdreg.h>
#include <linux/fs.h>
#include <linux/scatterlist.h>
#include <linux/dma-mapping.h>
#include <linux/list.h>
#include <linux/err.h>
#include <linux/utsname.h>
#include <linux/version.h>
#include <linux/kmod.h>
#include <linux/mempool.h>
#include <linux/string.h>
#include <linux/limits.h>
#include <linux/configfs.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/configfs.h>
#include <linux/blkdev.h>
#include <linux/miscdevice.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
#include <linux/blk_types.h>
#endif

#include "rna_com_linux_kernel.h"
#include "rna_scsi.h"
#else
#include "rnablk_win_device.h"
typedef struct _HW_HBA_EXT *pHW_HBA_EXT;
#endif //WINDOWS_KERNEL

#include "rnablk_rwsemaphore.h"
#include "platform_atomic.h"

#include "../include/rna_atomic64.h"

#include "util.h"
#include "protocol.h"

#if !defined(BEGIN_ALIGNED)     /* eventually defined in platform.h */
# if defined(LINUX_USER) || defined(LINUX_KERNEL)
#  define BEGIN_ALIGNED(N)  /* empty */
#  define END_ALIGNED(N)     __attribute ((__aligned__ (N)))
# else   /* WINDOWS_USER or WINDOWS_KERNEL */
#  define BEGIN_ALIGNED(N)  __declspec(align(N))
#  define END_ALIGNED(N)    /* empty */
# endif  /* LINUX/WINDOWS */
#endif  /* BEGIN_ALIGNED */

#if !defined(REQ_WRITE)
#define REQ_WRITE REQ_RW
#endif

#if !defined(MIN)
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif


#ifdef WINDOWS_KERNEL
 /*
INLINE void RNABLK_BUG_ON(boolean expr, char * fmt, ...)
{
	UNREFERENCED_PARAMETER(fmt);
	ASSERT(!(expr));
}
*/

#define RNABLK_BUG_ON(expr, fmt, ...)                                   \
    if((expr)){                                                         \
        DbgPrint("ASSERT(%s) at %s:%d: " , fmt, #expr, __FILE__,        \
            __LINE__, ##__VA_ARGS__);                                   \
        ASSERT(0);                                                      \
    }                                                                                                                              

#else
#define RNABLK_BUG_ON(expr, fmt, ...)                                   \
    if (unlikely((expr))) {                                             \
        printk(KERN_ERR "ASSERT(%s) at %s:%d: " fmt, #expr, __FILE__,   \
               __LINE__, ##__VA_ARGS__);                                \
        BUG();                                                          \
    }
#endif /*WINDOWS_KERNEL*/

#ifdef RNA_DEBUG        // it's a non-production build
#define RNABLK_DBG_BUG_ON   RNABLK_BUG_ON
#else
#define RNABLK_DBG_BUG_ON(expr, fmt, ...)
#endif

#ifdef WINDOWS_KERNEL
INLINE boolean
rna_os_validate_kvaddr(void *addr)
{
    UNREFERENCED_PARAMETER(addr);
    /* XXX currently just a stub on Windows */
    return TRUE;
}
#else
INLINE boolean
rna_os_validate_kvaddr(void *addr)
{
    return virt_addr_valid((uintptr_t)addr);
}
#endif


/*
 * simple cfs interface for causing IO timeouts.
 *  see cfs file "ios_timeout_test".
 */
#define IOS_TIMEOUT_TEST

/* Enable to support test injection via /sys/kernel/config/fldc/... */
#define TEST_OFFLINE_CACHE_DEVICE
#define TEST_MASTER_BLOCK
#define TEST_STORAGE_ERROR

/*
 * Note: Caller needs to have a known reference on rsc_cachedev in order to
 * use CONNFMT/CONNFMTARGS!
 */
#define CONNFMT             "%p:%"PRIx64":%d"
#define CONNFMTARGS(c)      (c), (c) ? (c)->rsc_cachedev ? \
                            (c)->rsc_cachedev->rcd_id : 0 : 0, \
                            (c) ? (c)->rsc_idx : 0
#define CONNADDRFMT         RNA_ADDR_FORMAT
#define CONNADDRFMTARGS(c)  RNA_ADDR((c)->id.u.data.address)
#define TAGFMT              "%llx"
#define TAGFMTARGS(t)       (t) 
#define BLKCNTFMT           "%d:%d"
#define BLKCNTFMTARGS(b)    atomic_read(&(b)->ref_count), \
                            atomic_read(&(b)->cb_ioref_cnt)

#define RNABLK_DEVICE_ITEM_PATH     "/sys/kernel/config/fldc/devices"

#define RNABLK_DISCONN_EXPIRES      (get_jiffies() + (HZ * 60))
#define RNABLK_DISCONN_TIMEOUT      (HZ * 60)
#define RNABLK_MAX_RETRY            2
/* Largest cache block (bytes) we can create a dirty sector map for */
#define RNABLK_MAX_CACHE_BLK_SIZE   (MAX_DIRTY_LIST_BITS * RNABLK_SECTOR_SIZE)
#define RNABLK_DEFAULT_CACHE_BLK_SIZE       MIN(RNABLK_MAX_CACHE_BLK_SIZE, (16 * 1024 * 1024))
#define RNABLK_DEFAULT_PERSIST_CACHE_BLK_SIZE       MIN(RNABLK_MAX_CACHE_BLK_SIZE, (512 * 1024))    

/*
 * For persistent devices.
 *
 * For now, we assume this is smaller than the bounce buffer pool size.
 * But if we increase RNABLK_DEFAULT_PERSIST_CACHE_BLK_SIZE to 2Gigabytes or so,
 * we need to make sure this is still true.  Although in reality, the maximum
 * size bounce buffer allocated from the bounce buffer pool is probably limited
 * by scatter gather list size limitations.
 */
#define RNABLK_DEFAULT_MAX_REQUEST_SIZE     RNABLK_DEFAULT_PERSIST_CACHE_BLK_SIZE

#define RNABLK_ENFORCER_HYSTERESIS  5     /* Fraction (1/x) of enforce target enforcer will try to overshoot by */
#define RNABLK_ENFORCER_HYSTERESIS_BLOCK_LIMIT  128
/* per-device limits/targets are all off by default */
#define RNABLK_DEFAULT_REFERENCED_BLOCK_LIMIT           0
#define RNABLK_DEFAULT_WRITE_REFERENCED_BLOCK_LIMIT     0
#define RNABLK_DEFAULT_REFERENCED_BLOCK_TARGET          0
#define RNABLK_DEFAULT_WRITE_REFERENCED_BLOCK_TARGET    0

#define RNABLK_MAX_SUB_IO           10
#define RNABLK_SGL_POOL_SIZE        256 
#define RNABLK_BLK_POOL_SIZE        128
#define RNABLK_IOS_POOL_SIZE        1024
#define RNABLK_WORK_POOL_SIZE       1024
#define RNABLK_CMD_POOL_SIZE        128
#define RNABLK_SHORT_DEV_NAME       "fldc"
#define RNABLK_BIO_POOL_SIZE        1024
#define RNABLK_BVEC_POOL_SIZE       64 /* not used by recent kernels */

// unused ioctl codes, see Documentation/ioctl/ioctl-number.txt
//#define RNABLK_IOCTL_WRITE_SAME                 0xFFFd  Deprecated, use SCSI command
#define RNABLK_IOCTL_EXTENDED_COPY              0xFFFc
//#define RNABLK_IOCTL_COMPARE_AND_WRITE          0xFFFb  Deprecated, use SCSI command
#define RNABLK_IOCTL_RECEIVE_COPY_RESULTS       0xFFFa

#define SIZE_4K                     (4*1024)
#define SIZE_16K                    (16*1024)
#define SIZE_32K                    (32*1024)
#define SIZE_64K                    (64*1024)
#define SIZE_128K                   (128*1024)
#define SIZE_256K                   (256*1024)
#define SIZE_512K                   (512*1024)
#define SIZE_1024K                  (1024*1024)

#define _1M                         (1024 * 1024)

INLINE uint64_t get_jiffies(void)
{
#ifdef WINDOWS_KERNEL
    //TODO: This code might need to re-evaluate to see what the precision is for this tickcount
    uint64_t tick_count = 0; 
    KeQueryTickCount(&tick_count); 
    return tick_count;
#else
    return jiffies;
#endif /*WINDOWS_KERNEL*/
}

#ifdef WINDOWS_KERNEL
#define HZ (10000000 / KeQueryTimeIncrement())
#endif /*WINDOWS_KERNEL*/

#ifdef WINDOWS_KERNEL
#define list_first_entry(ptr, type, member) list_entry((ptr)->Flink, type, member)
#else
// this doesn't get included in the kernel until 2.6.18.128 (CentOS 5.3)
#ifndef list_first_entry
#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)
#endif //list_first_entry
#endif //WINDOWS_KERNEL

#ifdef WINDOWS_KERNEL
//TODO: Does this need to be implemented?
#define dump_stack()
#endif

/* If we have less than this amount of stack leftover when deciding
 * whether or not to queue a bio, then we automatically queue it.
 * The appropriate value may be OS-dependent.  See MVP-6690. */
#define RNA_BIO_STACK_THRESHOLD 5600



/** Flags used to stop the device.  If any are set, the
 * device queue remains stopped.
 */
enum rnablk_queue_stop_flags {
    RNABLK_Q_STOP_ENFORCER,       /**< Queue stopped because enforcer 
                                   *   admit criteria exceeded */
    RNABLK_Q_STOP_DEFER_TO_WORKQ, /**< Queue stopped because strategy function 
                                   *   is being deferred to a work thread */
    RNABLK_Q_STOP_DISCONN,        /**< Queue is stopped because disconnect 
                                   *   processing is still in progress */
};

INLINE const char *
get_queue_stop_string(enum rnablk_queue_stop_flags qsf)
{
    const char *ret = "UNKNOWN";

    switch (qsf) {
        case RNABLK_Q_STOP_ENFORCER:
            ret = "RNABLK_Q_STOP_ENFORCER";
            break;
        case RNABLK_Q_STOP_DEFER_TO_WORKQ:
            ret = "RNABLK_Q_STOP_DEFER_TO_WORKQ";
            break;
        case RNABLK_Q_STOP_DISCONN:
            ret = "RNABLK_Q_STOP_DISCONN";
            break;
    }

    return ret;
}

#define IS_MASTER_BLK(b)    (((b)->cb_identity_flags & BLK_F_MASTER_BLK) != 0)
#define IS_MARKER_BLK(b)    (((b)->cb_identity_flags & BLK_F_MARKER_BLK) != 0)

#define is_blk_quiesce_complete(b)  \
            atomic_bit_is_set(&(b)->cb_flags, BLK_F_QUIESCE_COMPLETE)

struct rnablk_cache_blk_debug_info {
    struct cache_blk            blk_snapshot;
    int                         bl_empty;
    int                         connl_empty;
    int                         dispatch_queue_empty;
    int                         cbd_dev_empty;
};

/*
 * rnablk_svcctl_t  -- service control
 *  Used to enforce freeze/unfreeze of services while disconnects
 *  or cachedevice failure processing is in progress.
 */
typedef struct rnablk_svcctl_s {
#ifdef WINDOWS_KERNEL
	KEVENT              svc_wait;
#else
    wait_queue_head_t   svc_wait;
#endif //WINDOWS_KERNEL
    rna_spinlock_t      svc_lock;
    int                 svc_io_users;
    int                 svc_frozen;
    int                 svc_freeze_waiters;
} rnablk_svcctl_t;

#ifdef WINDOWS_KERNEL
/* Macros for waiting on and setting events (svc_wait and rbd_event_wait)
 * to mimic Linux usage.
 */
#define wait_event(wevent, cond)                                                 \
do {                                                                             \
    if (!(cond)) {                                                               \
        do {                                                                     \
            KeWaitForSingleObject(&wevent, Executive, KernelMode, FALSE, NULL);  \
        } while (!(cond));                                                       \
    }                                                                            \
} while (FALSE)

#define wake_up_all(wevent_ptr)  KePulseEvent(wevent_ptr, 0, FALSE)

#endif //WINDOWS_KERNEL

/* valid values for rrs_ack_needed */
typedef enum {
    RSV_ACK_NEED_NONE,
    RSV_ACK_NEED_CS,
    RSV_ACK_NEED_CLIENT
} rsv_ack_state;

struct rnablk_device {
    uint32_t             magic;             // RNABLK_DEVICE_MAGIC
    struct list_head     l;
    struct config_item   item;
    struct gendisk       *disk;
    struct request_queue *q;
    atomic_t             rbd_ext_rsvacc_mgrs; // count of external (reservation)
                                              // access managers
    atomic_t             deferred_softirq;
    atomic_t             deferred_stack;
    atomic_t             min_stack;
    atomic_t             q_stop_flags;      /* Current reasons (bit vector) for the request queue to 
                                             * be stopped.  The queue should not be started until 
                                             * this is zero. Protected (writes) by q->queue_lock. */
    struct rb_root       cache_blk_root;
    struct list_head     rbd_blk_list;
    struct rna_rw_semaphore  cache_blk_lock;    //< Acquire svr_conn_lock first (if needed)
    uint64_t             cache_blk_size;    //< bytes
    uint64_t             rbd_large_write_sects; //< bytes
                                                // the number of sectors that
                                                // qualify an i/o as a
                                                // "large write" in determining
                                                // whether to issue an immediate
                                                // deref of the blk afterwards.
    uint64_t             rbd_cfm_cookie;


    uint32_t             max_sectors;       // max sectors / request advertised
    uint64_t             rbd_block_debug;   // Used by .block_debug cfs file
    uint64_t             device_cap;        //< bytes
    uint64_t             dv_master_block_id;
    struct cache_blk     *dv_master_blk;
    uint32_t             access_uid;
    uint32_t             access_gid;
    uint32_t             rbd_flags;
                /* bit definitions for rbd_flags -- see RBD_FLAG_DESC_FUNCS */
#define         RBD_F_persistent            0
#define         RBD_F_shareable             1
#define         RBD_F_freeable              2
#define         RBD_F_das                   3
#define         RBD_F_dma_reads_disabled    4
#define         RBD_F_dma_writes_disabled   5
#define         RBD_F_quiesce_on_release    6
#define         RBD_F_use_req_queue         7
    atomic_t             rbd_io_allowed;
#define         RBD_FIO_MASTER_LOCKED       0x0001
#define         RBD_FIO_NEED_RSV_ACK        0x0002
    int                  major;
    uint32_t             mount_status;
    atomic_t             strategy_threads;  //< Current number of threads in rnablk_strategy()
    atomic_t             cache_blk_count;   //< cache_blk objects that currently exist 
    atomic_t             cumulative_cache_blk_count;   //< cache_blk objects that ever existed 
    atomic_t             rbd_refcnt;        // (see notes below)
    atomic_t             status;
    atomic_t             registered_with_os;
#ifdef WINDOWS_KERNEL
    struct timer_win     disconnect_timer;
#else
    struct timer_list    disconnect_timer;
#endif
    int                  disconnect_expired;
    struct blkdev_stats  stats;
    atomic_t             disable_new_openers;
    atomic_t             failed;
    struct list_head     ordered_commands; /**< Used to order RESERVE and COMPARE AND WRITE */
    rna_spinlock_t       ordered_cmd_lock; /**< Lock protecting ordered_commands list */
    struct rnablk_rsv_state_s {             // protected by rbd_event_lock
        boolean             rrs_is_valid;
        uint32_t            rrs_generation;
        volatile rsv_access_t rrs_client_access;
        rsv_access_t        rrs_other_access;
        atomic_t            rrs_wait;
        rsv_ack_state       rrs_ack_needed;     // see rsv_ack_state     
        int                 rrs_n_itns;
        rsv_itn_id_t        rrs_itn_list[MAX_PER_CLIENT_INITIATORS];
    }                    rbd_rsv;
    struct rnablk_unitattn_state_s {        // protected by rbd_event_lock
        int                 rus_n_itns;
        uint32_t            rus_n_pending;
        uint32_t            rus_all_unitattn;       // for all initiators
        uint32_t            rus_ini_unitattn[32];   // per itn UNITATTN's
        rsv_initiator_t     rus_ini_list[MAX_PER_CLIENT_INITIATORS];
    }                    rbd_ua_state;
    atomic_t             rbd_n_write;     // in-progress write I/O's
    atomic_t             rbd_n_read;      // in-progress read I/O's
    atomic_t             path_md_policy;
#ifdef WINDOWS_KERNEL
	rna_spinlock_t       dev_blk_queue_lock;
    LIST_ENTRY           dev_blk_queue;       // pending cache block waiting for the connection, after connected, it should be empty
	LIST_ENTRY           dev_lru_blk_queue;   // Least used cache block queue, used for deref
    pHW_HBA_EXT          pHBAExt;
    uint32_t             ptlkey;              // Path, Target, Lun
    uint32_t             devnum;              // relative device number
    LONG                 thinState;           // tracking thin provisioning state
    KEVENT               rbd_event_wait;
#else
    wait_queue_head_t    rbd_event_wait;
#endif //WINDOWS_KERNEL
    rna_spinlock_t       rbd_event_lock;
    uint32_t             rbd_event_state;    // protected by rbd_event_lock
#define         RBD_EV_OUTOFSPACE           0
    char                 name[NAME_MAX+1];  //< The name of the block device
#ifdef TEST_STORAGE_ERROR
    atomic_t             rbd_test_err_inject;
#endif /* TEST_STORAGE_ERROR */
    char                 persist_location[PATH_MAX+1];
    char                 cache_file_name[MAX(NAME_MAX,PATH_MAX)+1];
    char                 class_name[NAME_MAX+1];
    char                 class_params[NAME_MAX+1];
};



#define dev_io_allowed(d) \
    ((atomic_read(&(d)->rbd_io_allowed) & \
     (RBD_FIO_NEED_RSV_ACK|RBD_FIO_MASTER_LOCKED)) == RBD_FIO_MASTER_LOCKED)

#ifdef WINDOWS_KERNEL
typedef struct rnablk_device Rnablk_Device, *PRnablk_Device;
#endif //WINDOWS_KERNEL
/*
 * TRUE if rnablk driver is in charge of enforcing SCSI reservation
 * access restrictions.
 */
#define rnablk_controls_access(dev)     \
            (0 == atomic_read(&(dev)->rbd_ext_rsvacc_mgrs))

/*
 * TRUE if rnablk driver should enforce SCSI reservation access
 * restrictions at this time.
 */
#define rnablk_enforce_access(d) \
        (rnablk_controls_access(d) || \
         RSV_ACK_NEED_CLIENT == (d)->rbd_rsv.rrs_ack_needed)

/* rbd_event_state macros */
#define rbd_event_is_set(d, f)  (((d)->rbd_event_state & (f)) != 0)
#define rbd_event_set(d, f)     ((d)->rbd_event_state |= (f))
#define rbd_event_clear(d, f)   ((d)->rbd_event_state &= ~(f)) 


#ifdef WINDOWS_KERNEL
INLINE void set_bit(uint64_t nr, volatile uint64_t *addr)
{
	InterlockedBitTestAndSet64((volatile __int64 *)addr, nr);
}

INLINE void clear_bit(uint64_t nr, volatile uint64_t *addr)
{
	InterlockedBitTestAndReset64((volatile __int64 *)addr, nr);
}

INLINE boolean test_bit(uint64_t nr, volatile uint64_t *addr)
{
	return 1 & (((const volatile uint32_t *) addr)[nr >> 5] >> (nr & 31));
}

#endif

/*
 * Notes about usage of rbd_refcnt.
 * We put a reference on the dev struct when it is created, plus one
 * for being in the rnablk_dev_list, plus one when the cfs item is created.
 * Each cache_blk that is created adds a reference to its corresponding 'dev'.
 * Any other users of 'dev' should use one of the "find" routines to get
 * the pointer to the dev, which will add a reference, and then must
 * explicitly release the reference via rnablk_dev_release() when
 * finished with it.
 */ 

INLINE void
_rnablk_dev_free(atomic_t *refcnt_p, void *struct_p)
{
    struct rnablk_device *dev = (struct rnablk_device *)struct_p;
    UNREFERENCED_PARAMETER(refcnt_p);

    dev->magic = RNABLK_DEVICE_NONMAGICAL;
#ifdef WINDOWS_KERNEL
    Free_Device(dev);
#else
    free(dev);
#endif /* WINDOWS_KERNEL */
}

#define rnablk_dev_shutdown(d) \
        atomic_refcnt_delete(&(d)->rbd_refcnt, (d), _rnablk_dev_free)
#define rnablk_dev_is_shutdown(d) atomic_refcnt_is_deleted(&(d)->rbd_refcnt)

#define rnablk_dev_acquire(d)   atomic_refcnt_acquire(&(d)->rbd_refcnt)
#define rnablk_dev_release(d) \
        atomic_refcnt_release(&(d)->rbd_refcnt, (d), _rnablk_dev_free)

#ifdef WINDOWS_KERNEL

#define RBD_FLAG_MODIFY_FUNCS(fl) \
INLINE void dev_set_##fl(struct rnablk_device *dev) \
{ \
    set_bit(RBD_F_##fl, (uint64_t *)&dev->rbd_flags); \
} \
INLINE void dev_clear_##fl(struct rnablk_device *dev) \
{ \
    clear_bit(RBD_F_##fl, (uint64_t*)&dev->rbd_flags); \
}

#define RBD_FLAG_DESC_FUNCS(fl) \
RBD_FLAG_MODIFY_FUNCS(fl); \
INLINE boolean dev_is_##fl(struct rnablk_device *dev) \
{ \
    return test_bit(RBD_F_##fl, (uint64_t *)&dev->rbd_flags); \
}

#define RBD_FLAG_VERB_FUNCS(fl) \
RBD_FLAG_MODIFY_FUNCS(fl); \
INLINE boolean dev_##fl(struct rnablk_device *dev) \
{ \
    return test_bit(RBD_F_##fl, (uint64_t *)&dev->rbd_flags); \
}

#else

#define RBD_FLAG_MODIFY_FUNCS(fl) \
INLINE void dev_set_##fl(struct rnablk_device *dev) \
{ \
    set_bit(RBD_F_##fl, (unsigned long *)&dev->rbd_flags); \
} \
INLINE void dev_clear_##fl(struct rnablk_device *dev) \
{ \
    clear_bit(RBD_F_##fl, (unsigned long *)&dev->rbd_flags); \
}

#define RBD_FLAG_DESC_FUNCS(fl) \
RBD_FLAG_MODIFY_FUNCS(fl); \
INLINE boolean dev_is_##fl(struct rnablk_device *dev) \
{ \
    return test_bit(RBD_F_##fl, (unsigned long *)&dev->rbd_flags); \
}

#define RBD_FLAG_VERB_FUNCS(fl) \
RBD_FLAG_MODIFY_FUNCS(fl); \
INLINE boolean dev_##fl(struct rnablk_device *dev) \
{ \
    return test_bit(RBD_F_##fl, (unsigned long *)&dev->rbd_flags); \
}
#endif //WINDOWS_KERNEL

RBD_FLAG_DESC_FUNCS(persistent)
RBD_FLAG_DESC_FUNCS(shareable)
RBD_FLAG_DESC_FUNCS(freeable)
RBD_FLAG_DESC_FUNCS(das)
RBD_FLAG_VERB_FUNCS(dma_reads_disabled)
RBD_FLAG_VERB_FUNCS(dma_writes_disabled)
RBD_FLAG_VERB_FUNCS(quiesce_on_release)
RBD_FLAG_VERB_FUNCS(use_req_queue)

#ifdef WINDOWS_KERNEL
#define LOCDEV_FLAG_REMOVED    0x001
struct rnablk_local_dev {
    struct list_head entry;
    cachedev_id_t id;
    PVOID pDiskDevice;
    uint32_t flags;
};
#else
struct rnablk_local_dev {
    struct list_head     entry; /**< antry in local_dev_list */
    struct block_device *blk_dev; /**< pointer to open device */
    struct bio_set      *bio_set; /**< pool of block IO structures */
    atomic_t             run_scheduled; /**< guard to prevent lots of
                                          *  run_ldev_queue() is work queue */
};
#endif


/* cache-device offline 'reason' for rnablk_initiate_offline_cache_device() */
enum {
    CD_OFFLINE_DISCONNECT,      // a cache-dev conn has disconnected
    CD_OFFLINE_FAIL,            // a CACHE_FAIL_CACHE_DEVICE msg received
    CD_OFFLINE_EXPEL,           // a RNA_SERVICE_MESSAGE_TYPE_EXPEL_CS
};

#define offline_reason_to_str(r)    \
    ((r) == CD_OFFLINE_DISCONNECT ? "DISCONNECT" : \
     (r) == CD_OFFLINE_FAIL ? "FAIL" : "EXPEL")

enum rnablk_op_type {
    RNABLK_BOGUS_OP_TYPE,               // 0
    RNABLK_MD_QUERY,
    RNABLK_CACHE_QUERY,
    RNABLK_RDMA_READ,
    RNABLK_RDMA_WRITE,
    RNABLK_WRITE_SAME,                  // 5
    RNABLK_MASTER_INVD,
    RNABLK_CHANGE_REF,
    RNABLK_CHANGE_REF_NORESP,           // Only used for master block ref changes
    RNABLK_DEREF_REQUEST_RESP,
    RNABLK_MASTER_DEREF,                // 10
    RNABLK_MASTER_DEREF_NORESP,
    RNABLK_LOCK_MASTER_BLK,
    RNABLK_COMP_AND_WRITE,
    RNABLK_INIT,
    RNABLK_SCSI_PASSTHRU,               // 15
    RNABLK_RSV_ACCESS_RESP,
};

typedef enum rnablk_op_type RNABLK_OP_TYPE;

INLINE const char * rnablk_op_type_string (enum rnablk_op_type type)
{
    const char * ret = NULL;

    switch (type) {
    case RNABLK_BOGUS_OP_TYPE:
        ret = "RNABLK_BOGUS_OP_TYPE";
        break;
    case RNABLK_LOCK_MASTER_BLK:
        ret = "RNABLK_LOCK_MASTER_BLK";
        break;
    case RNABLK_MD_QUERY:
        ret = "RNABLK_MD_QUERY";
        break;
    case RNABLK_CACHE_QUERY:
        ret = "RNABLK_CACHE_QUERY";
        break;
    case RNABLK_RDMA_READ:
        ret = "RNABLK_RDMA_READ";
        break;
    case RNABLK_RDMA_WRITE:
        ret = "RNABLK_RDMA_WRITE";
        break;
    case RNABLK_MASTER_INVD:
        ret = "RNABLK_MASTER_INVD";
        break;
    case RNABLK_CHANGE_REF:
        ret = "RNABLK_CHANGE_REF";
        break;
    case RNABLK_CHANGE_REF_NORESP:
        ret = "RNABLK_CHANGE_REF_NORESP";
        break;
    case RNABLK_MASTER_DEREF:
        ret = "RNABLK_MASTER_DEREF";
        break;
    case RNABLK_MASTER_DEREF_NORESP:
        ret = "RNABLK_MASTER_DEREF_NORESP";
        break;
    case RNABLK_INIT:
        ret = "RNABLK_INIT";
        break;
    case RNABLK_WRITE_SAME:
        ret = "RNABLK_WRITE_SAME";
        break;
    case RNABLK_COMP_AND_WRITE:
        ret = "RNABLK_COMP_AND_WRITE";
        break;
    case RNABLK_DEREF_REQUEST_RESP:
        ret = "RNABLK_DEREF_REQUEST_RESP";
        break;
    case RNABLK_SCSI_PASSTHRU:
        ret = "RNABLK_SCSI_PASSTHRU";
        break;
    case RNABLK_RSV_ACCESS_RESP:
        ret = "RNABLK_RSV_ACCESS_RESP";
        break;
    default:
        ret = "unknown";
    }
    return ret;
}

/*
 * (Note the "aligned" attribute is to ensure that the io_state struct
 * size is rounded up to an 8-byte boundary.  This will actually already be
 * the case, but since we allocate these from a pool where we also
 * allocate the scatterlist from the same allocation (so in other words,
 * from the memory immediately following the io_state struct), just spelling
 * out the requirement!)
 */
BEGIN_ALIGNED(8) struct io_state {
    struct list_head        l;          // this field must be first, because
                                        // we overlay this struct with a
                                        // list_element_t when "free"
    ios_tag_t               tag;
    rna_spinlock_t          ios_lock;
    uint64_t                ios_magic;
#define RNABLK_IOS_MAGIC            0x72626c6b5f696f73    /* "rblk_ios" */
    /*
     * The above three fields get initialized at module_init time and
     * must not be reinitialized.  rnablk_alloc_ios() zeros the structure
     * but carefully skips the above fields.  To do this, it knows that
     * a) they are at the beginning of the struct, and b) that the field 'blk'
     * immediately follows them.  So don't move any of these fields
     * (i.e. those above or 'blk') without fixing rnablk_alloc_ios()!
     */
    struct cache_blk        *blk;
    struct list_head        ordered_l;
#ifdef RNA_USE_IOS_TIMERS
    struct timer_list       tl;
    atomic_t                ios_timer_fired;
#endif
    struct rnablk_device    *dev;
    union {
        void                    *ios_gen_ioreq;
#ifndef WINDOWS_KERNEL
        struct request          *req;
        struct bio              *bio;
#endif /*WINDOWS_KERNEL*/
        void                    *ios_spc_req;   // rnablk_special_completion_t
    };

    void                    *bio_private;
    struct rnablk_server_conn *conn; /**< Valid only when in conn queue */
    struct com_ep           *ep;
    struct cache_cmd        *cmd;
#ifdef WINDOWS_KERNEL
	PSCSI_REQUEST_BLOCK     pOS_Srb;
#else
    struct scatterlist      *sgl;
#endif
    int                     nsgl;
    enum rnablk_op_type     type;
    rna_hash_key_t          hash_key;
    uint64_t                issue_time_ns;
    uint64_t                cs_ep_key;
    int64_t                 start_sector;
    uint32_t                nr_sectors;
    atomic_t                ios_atomic_flags;
#define     IOS_AF_QUEUESTATE_STARTBIT       0
#define     IOS_AF_QUEUESTATE_NUMBITS        3
#define       IOS_QS_NONE             0         // not in any queue
#define       IOS_QS_DISPATCH         1         // in blk->dispatch_queue
#define       IOS_QS_BLOCK            2         // in blk->bl queue
#define       IOS_QS_CONN             3         // in conn->io_queue
#define       IOS_QS_DISPATCH_FAILED_REDO 4     // completed w/err, left queued
#define       IOS_QS_DISPATCH_COMPLETING  5     // non-io ios in process of
                                                // completing
#define       IOS_QS_DISPATCH_QUIESCED    6     // non-io ios has been quiesced
#define       IOS_QS_WFC              7         // in wfc conn queue
#define     IOS_AF_INFLIGHT          0x00000008
#define     IOS_AF_IN_TREE           0x00000010 // atomicity not needed...
#define     IOS_AF_ALLOCATED         0x00000020 // atomicity not needed...
#define     IOS_AF_DEVIOCNT          0x00000040 // atomicity not needed...
#define     IOS_AF_MASTER_LOCK       0x00000080 // atomicity not needed...
    uint8_t                 ios_req_type;       // type of hi-level request
#define     IOREQ_TYPE_NOREQ         0 // ios has no I/O request
#define     IOREQ_TYPE_REQ           1 // ios->req points to a 'struct request'
#define     IOREQ_TYPE_BIO           2 // ios->bio points to a 'struct bio'
#define     IOREQ_TYPE_SPC           3 // ios->ios_spc_req points to a 
                                       //  'rnablk_special_completion_t'
    uint8_t                 ios_rsv_access;     // rsv_access_t value ==
                                                // min access required
    uint16_t                ios_iotype;         // underlying i/o type
#define     IOS_IOTYPE_NONE             0
#define     IOS_IOTYPE_READ             0x0100
#define     IOS_IOTYPE_WRITE            0x0201
#define     IOS_IOTYPE_COMP_WR          0x0301
#define     IOS_IOTYPE_WRITE_SAME       0x0401
    atomic_t                ios_err;        // stashed error status
    atomic_t                ref_count;
    atomic_t                pending_bios; /**< number of outstanding DMA BIO requests */
    /*
     * we need this in addition to the block failure count to cover the case
     * where we have multiple I/Os pending for a failued query.
     * (common when doing sequential I/O).
     */
    atomic_t                ios_connection_failures;
    common_meta_data_t      c;
#ifdef WINDOWS_KERNEL
	uint64_t                transfer_length;
    PMDL                    ios_mdl;
    uint8_t                 irpAllocType;
    BOOLEAN                 built_partial_mdl;
    uint64_t                SRBNumber;     // For quick access during perf reporting.
#endif /*WINDOWS_KERNEL*/
} END_ALIGNED(8);

#define IOS_HAS_IOREQ(ios) ((ios)->ios_req_type != IOREQ_TYPE_NOREQ)

#ifdef WINDOWS_KERNEL
#define IOS_HAS_BIO(ios)  0
#else
#define IOS_HAS_BIO(ios)  ((ios)->ios_req_type == IOREQ_TYPE_BIO)
#endif /*WINDOWS_KERNEL*/

#ifdef WINDOWS_KERNEL
#define IOS_HAS_REQ(ios)  0
#else
#define IOS_HAS_REQ(ios)  ((ios)->ios_req_type == IOREQ_TYPE_REQ)
#endif /*WINDOWS_KERNEL*/

#define IOS_HAS_SPC(ios)  ((ios)->ios_req_type == IOREQ_TYPE_SPC)

/* low-order bit of ios_iotype indicates whether I/O type does any writing */
#define     _IOS_IOTYPE_WRITE_BIT       0x01
#define     ios_writes_data(ios) \
        (((ios)->ios_iotype & _IOS_IOTYPE_WRITE_BIT) != 0)


#define ios_queuestate_set(ios, val) \
    atomic_bitfield_set(&(ios)->ios_atomic_flags, IOS_AF_QUEUESTATE_STARTBIT, \
                        IOS_AF_QUEUESTATE_NUMBITS, (val)
#define ios_queuestate_get(ios) \
    atomic_bitfield_read(&(ios)->ios_atomic_flags, IOS_AF_QUEUESTATE_STARTBIT, \
                         IOS_AF_QUEUESTATE_NUMBITS)
#define ios_queuestate_test_and_set(ios, old, new)  \
    atomic_bitfield_test_and_set(&(ios)->ios_atomic_flags, \
                            IOS_AF_QUEUESTATE_STARTBIT, \
                            IOS_AF_QUEUESTATE_NUMBITS, \
                            (old), (new))

/* debug buffer for the  .ios_debug cfs file  */
struct rnablk_cache_ios_debug_info {
    struct io_state     ios_snapshot;
    struct io_state     *iosp;
    uint64_t            ios_blk_block_number;
    struct com_ep      *ios_blk_ep;
    char                ios_blk_dev_name[NAME_MAX+1];
    /* other stuff ?? */
};

INLINE const char *
rnablk_ios_q_string(int q_state)
{
    const char *ret = NULL;

    switch (q_state) {
    case IOS_QS_NONE:
        ret = "(no)";
        break;
    case IOS_QS_DISPATCH:
        ret = "blk-dispatch";
        break;
    case IOS_QS_BLOCK:
        ret = "blk-bl";
        break;
    case IOS_QS_CONN:
        ret = "conn-ioqueue";
        break;
    case IOS_QS_DISPATCH_FAILED_REDO:
        ret = "blk-dispatch[FAILED_REDO]";
        break;
    case IOS_QS_DISPATCH_COMPLETING:
        ret = "blk-dispatch[COMPLETING]";
        break;
    case IOS_QS_DISPATCH_QUIESCED:
        ret = "blk-dispatch[QUIESCED]";
        break;
    case IOS_QS_WFC:
        ret = "wfc";
        break;
    default:
        BUG_ON(TRUE);
    }
    return ret;
}

int rnablk_get_ios_debug_info(ios_tag_t ios_debug_tag,
                              struct  rnablk_cache_ios_debug_info *info);

int rnablk_ios_timeout_script_store(const char *buf, int len);
int rnablk_ios_timeout_script_show(char *page);
int rnablk_ios_timeout_script_test_store(const char *buf, int len);
int rnablk_ios_timeout_script_finish_store(const char *buf, int len);
#ifdef IOS_TIMEOUT_TEST
int rnablk_ios_timeout_test_store(const char *buf, int len);
int rnablk_ios_timeout_test_show(char *page);
#endif /* IOS_TIMEOUT_TEST */

#define is_parent_conn(c)   ((c)->rsc_parent_conn == (c))

struct cfm_info_item {
    struct sockaddr_in ip_addr;
    enum com_type com_type;
};

struct cfm_info {
    struct cfm_info_item cfms[RNA_SERVICE_CFMS_MAX];
    uint8_t cfm_count;
    char cfm_addrs_string[4096];
};


// prototypes

int rnablk_print_conns(char *buf, int buflen);
int rnablk_print_devs(char *buf, int buf_size);
int rnablk_print_latency_stats(char *buf, int buf_size);

int rnablk_configfs_init( void );
void rnablk_configfs_cleanup( void );

#define rnablk_server_conn_put(c) \
    _rnablk_server_conn_put_debug(__FUNCTION__, __LINE__, (c))

extern void _rnablk_server_conn_put_debug(const char *func, const int line,
                                          struct rnablk_server_conn *conn);

#endif //INCLUDED_SB_H
