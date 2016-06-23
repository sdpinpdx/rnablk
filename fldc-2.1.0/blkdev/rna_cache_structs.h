/**
 * <rna_cache_structs.h> - Basic cache structures needed by Dell Fluid Cache block driver
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

#ifndef INCLUDED_RNA_CACHE_STRUCTS_H
#define INCLUDED_RNA_CACHE_STRUCTS_H

#include "platform.h"
#include "rna_types.h"
#include "rna_hash_common.h"
#include "rna_service.h"
#include "rna_block_mutex.h"
#include "rna_mutex.h"

#ifdef WINDOWS_KERNEL
#include "rnablk_win_common.h"
#include "rna_common_kernel_windows.h"
#include "rna_status_codes.h"
#endif //WINDOWS_KERNEL

//Copied this from rna_com_linux_kernel.h
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
//End of copy from rna_com_linux_kernel.h

typedef enum {
    RNABLK_CONN_DISCONNECTED,
    RNABLK_CONN_CONNECT_PENDING,
    RNABLK_CONN_CONNECTED,
    RNABLK_CONN_DISCONNECT_PENDING,
    RNABLK_CONN_DISCONNECT_INPROG,
} rnablk_conn_state;

#ifdef WINDOWS_KERNEL
typedef PRTL_GENERIC_TABLE rna_rb_node;
#else
typedef struct rb_node rna_rb_node;
#endif /*WINDOWS_KERNEL*/

#ifdef WINDOWS_KERNEL

#define DMA_FROM_DEVICE dmaDataIn 
#define DMA_TO_DEVICE   dmaDataOut

struct rb_root {
	rna_rb_node node;
};

#define container_of(ptr, type, member) CONTAINING_RECORD(ptr, type, member)
typedef rnablk_conn_state Rnablk_Connection_State;

typedef struct _HW_HBA_EXT *pHW_HBA_EXT;

/* This section is from err.h in Linux source code */
#define MAX_ERRNO	4095
#define IS_ERR_VALUE(x) ((x) >= (uint64_t)-MAX_ERRNO)

INLINE uint64_t IS_ERR(const void *ptr)
{
	return IS_ERR_VALUE((uint64_t)ptr);
}

#endif /*WINDOWS_KERNEL*/

//TODO: This section is moved from rb.h
typedef uint64_t ios_tag_t;

#if !defined(MAX)
#define MAX(l,r) (((l)<(r))?(r):(l))
#endif
//END OF section

#ifdef WINDOWS_KERNEL
#define DEFAULT_RDMA_SENDBUF_SIZE 10240     // Must be <= COM_BUF_SIZE_LIMIT 
#define RNA_MAX_TCP_WR  4096
#define RNA_MAX_RDMA_WR 1024
#define RNA_MAX_SGE     32
#endif /*WINDOWS_KERNEL*/

#ifdef WINDOWS_KERNEL
#define list_head _LIST_ENTRY
#define LIST_POISON1  ((void *) 0x00100100)
#define LIST_POISON2  ((void *) 0x00200200)
#define INIT_LIST_HEAD(ptr) InitializeListHead(ptr)
#define list_empty(ptr) IsListEmpty(ptr)
#define list_for_each(pos, head) for (pos = (head)->Flink; pos != (head); pos = pos->Flink)
#define list_for_each_safe(pos, n, head) for (pos = (head)->Flink, n = pos->Flink; pos != (head); pos = n, n = pos->Flink)

#define list_entry(ptr, type, member) container_of(ptr, type, member)

INLINE void __list_del(struct list_head * prev, struct list_head * next)
{
	next->Blink = prev;
	prev->Flink = next;
}

INLINE void __list_del_entry(struct list_head *entry)
{
	__list_del(entry->Blink, entry->Flink);
}

INLINE void __list_add(struct list_head *newitem,
					   struct list_head *prev,
					   struct list_head *next)
{
	next->Blink = newitem;
	newitem->Flink = next;
	newitem->Blink = prev;
	prev->Flink = newitem;
}

INLINE void list_add_tail(struct list_head *newitem, struct list_head *head)
{
	__list_add(newitem, head->Blink, head);
}

INLINE void list_move_tail(struct list_head *list,
                           struct list_head *head)
{
    __list_del_entry(list);
    list_add_tail(list, head);
}


INLINE void list_add(struct list_head *newitem, struct list_head *head)
{
	__list_add(newitem, head, head->Flink);
}

INLINE void list_del_init(struct list_head *entry)
{
	__list_del_entry(entry);
	INIT_LIST_HEAD(entry);
}

INLINE void list_del(struct list_head *entry)
{
    __list_del_entry(entry);
    entry->Flink = (struct list_head *)LIST_POISON1;
    entry->Blink = (struct list_head *)LIST_POISON2;
}

INLINE void __list_splice(const struct list_head *list,
                                 struct list_head *prev,
                                 struct list_head *next)
{
    struct list_head *first = list->Flink;
    struct list_head *last = list->Blink;

    first->Blink = prev;
    prev->Flink = first;

    last->Flink = next;
    next->Blink = last;
}

INLINE void list_splice_init(struct list_head *list,
                             struct list_head *head)
{
    if (!list_empty(list)) {
        __list_splice(list, head, head->Flink);
        INIT_LIST_HEAD(list);
    }
}

/* TRUE if 'ent' is the one and only entry in the list represented by 'head' */
#define is_only_entry_in_list(head, ent, member) \
    ((head)->Flink == &(ent)->member && (head)->Blink == &(ent)->member)

#else /* !WINDOWS_KERNEL -- i.e. LINUX */

/* TRUE if 'ent' is the one and only entry in the list represented by 'head' */
#define is_only_entry_in_list(head, ent, member) \
    ((head)->next == &(ent)->member && (head)->prev == &(ent)->member)

#endif /* !WINDOWS_KERNEL -- i.e. LINUX */


#ifdef WINDOWS_KERNEL
struct kmem_cache {
        BYTE * data;
};
#endif /*WINDOWS_KERNEL*/

#ifdef WINDOWS_KERNEL
typedef uint64_t sector_t;
#endif /*WINDOWS_KERNEL*/

#define RNABLK_DEVICE_MAGIC            0x72626c6b       /* "rblk" */
#define RNABLK_DEVICE_NONMAGICAL       0xdeadbeef

/* Use magic numbers instead of tree search (which requires a lock) to verify conns are good */
#define RNABLK_VERIFY_CONN_BY_MAGIC     1   
#define RNABLK_CONN_FRONT_MAGIC         0x72626c6b636f6e6eL       /* "rblkconn" */
#define RNABLK_CONN_BACK_MAGIC          0x6e6e6f636b6c6272L       /* "nnocklbr" */

/*
 * blk_lru_list & accompanying macros
 *  This is a special construct which enables us to put a cache_blk
 *  in the same list twice.  This is to improve our LRU management
 *  (for anonymous dereferences and "enforcer" management).  Basically
 *  the idea is to be able to track read and write access LRU usage
 *  of a blk, such that we can drop write references in a true LRU
 *  fashion, while still keeping the read reference if read accesses
 *  have been more recent, etc.
 *
 * Usage of this construct must be done very carefully, using the
 * provided macros.  Otherwise, CRASH and BURN, since it uses the LSB
 * of pointer fields to track which lru entry is which.  Thus the pointers
 * can't be used directly!
 *
 * Note an unpleasant downside to this construct is that it will
 * no longer be possible to dump the cachedev->rcd_block_list in crash
 * using the built-in crash "list" facility. (So instead we install a
 * crash extension "blk_lru_list").
 */
struct blk_lru_list {
    struct blk_lru_list *blru_next;
    struct blk_lru_list *blru_prev;
};

#define _LRU_GET_ENT_LSB(ent)    ((uintptr_t)(ent) & 1)
#define _LRU_GET_ENT_INT(ent)    ((uintptr_t)(ent) & ~1)

#define _LRU_GET_ENT_PTR(ent)    ((struct blk_lru_list *)_LRU_GET_ENT_INT(ent))

#define _LRU_SET_ENT_VAL(ent, lsb) \
    (struct blk_lru_list *)(_LRU_GET_ENT_INT(ent) | (lsb))

#define _LRU_SET_ENT_PTR(dst, val) \
    (struct blk_lru_list *)(_LRU_GET_ENT_LSB(dst) | _LRU_GET_ENT_INT(val))

/* This is original Linux code as a define. But in windows, in order to compile this, change this to
   an inline function call
#define blk_lru_list_init(l, lsb) \
 do { \
    (l)->blru_next = (l)->blru_prev = _LRU_SET_ENT_VAL(l, lsb); \
 } while (0);
*/

INLINE void blk_lru_list_init(struct blk_lru_list *l, int lsb)
{
	(l)->blru_next = _LRU_SET_ENT_VAL(l, lsb);
	(l)->blru_prev = _LRU_SET_ENT_VAL(l, lsb);
}

#define blk_lru_list_empty(ent) \
    (_LRU_GET_ENT_PTR((ent)->blru_next) == (ent))

INLINE void __blk_lru_list_add(struct blk_lru_list *new,
			                   struct blk_lru_list *prev,
			                   struct blk_lru_list *next)
{
    next->blru_prev = _LRU_SET_ENT_PTR(next->blru_prev, new);
    new->blru_next = _LRU_SET_ENT_PTR(new->blru_next, next);
    new->blru_prev = _LRU_SET_ENT_PTR(new->blru_prev, prev);
    prev->blru_next = _LRU_SET_ENT_PTR(prev->blru_next, new);
}

INLINE void blk_lru_list_add(struct blk_lru_list *new,
                                         struct blk_lru_list *head)
{
	__blk_lru_list_add(new, head, _LRU_GET_ENT_PTR(head->blru_next));
}

INLINE void blk_lru_list_add_tail(struct blk_lru_list *new,
                                         struct blk_lru_list *head)
{
	__blk_lru_list_add(new, _LRU_GET_ENT_PTR(head->blru_prev), head);
}

#define blk_lru_list_for_each(pos, head) \
	for (pos = _LRU_GET_ENT_PTR((head)->blru_next); pos != (head); \
         pos = _LRU_GET_ENT_PTR(pos->blru_next))

#define blk_lru_list_for_each_safe(pos, n, head) \
	for (pos = _LRU_GET_ENT_PTR((head)->blru_next), \
         n = _LRU_GET_ENT_PTR((pos)->blru_next); pos != (head); \
         pos = n, n = _LRU_GET_ENT_PTR(pos->blru_next))


INLINE void
__blk_lru_del(struct blk_lru_list *prev, struct blk_lru_list *next)
{
    next->blru_prev = _LRU_SET_ENT_PTR(next->blru_prev, prev);
    prev->blru_next = _LRU_SET_ENT_PTR(prev->blru_next, next);
}

INLINE void
blk_lru_del_init(struct blk_lru_list *ent)
{
    __blk_lru_del(_LRU_GET_ENT_PTR(ent->blru_prev),
                  _LRU_GET_ENT_PTR(ent->blru_next));
    ent->blru_prev = ent->blru_next = _LRU_SET_ENT_PTR(ent->blru_next, ent);
}

INLINE void blk_lru_list_move_tail(struct blk_lru_list *list,
				                          struct blk_lru_list *head)
{
	__blk_lru_del(_LRU_GET_ENT_PTR(list->blru_prev),
                  _LRU_GET_ENT_PTR(list->blru_next));
	blk_lru_list_add_tail(list, head);
}

/* maximum number of per-cache-device connections */
#define RNABLK_MAX_DEV_CONNS 8
/* represents the cache_device affiliated with a given cache_blk */
typedef struct rnablk_cachedev_s {
    struct list_head           rcd_link;
                                    // our link into rnablk_server_conn
                                    // rsc_cachedevs list
    cachedev_id_t              rcd_id;     // ID of cachedev
    struct rnablk_server_conn *rcd_server_conn;
                                    // cache-server this cachedev is
                                    // associated with
    atomic_t                   rcd_state;
#define     RCD_STATE_ONLINE            0x00000001
#define     RCD_STATE_EXPELLED          0x00000002
#define     RCD_STATE_FROZEN            0x00000004
#define     RCD_STATE_PARENT_READY      0x00000008
#define     RCD_STATE_IS_OFFLINED       0x00000010
#define     RCD_STATE_FAIL_OFFLINING    0x00000020
#define     RCD_STATE_EXPEL_OFFLINING   0x00000040
    atomic_t                   rcd_refcount;
    atomic_t                   rcd_online_refs;
                                    // used to track when we can safely
                                    // offline (i.e. fail!) a cachedev
    struct blk_lru_list        rcd_block_list;
                                    // LRU list of blocks associated
                                    // with this cachedev
                                    // (protected by pconn->block_list_lock)
    struct rnablk_server_conn *rcd_conns[RNABLK_MAX_DEV_CONNS];
                                    // per-device connections to CS
    atomic_t                   rcd_next_conn;
} rnablk_cachedev_t;

#define is_null_cachedev(p)     (&null_cachedev == (p))

typedef enum {
    RNABLK_CACHE_BLK_UNINITIALIZED = 0,
    RNABLK_CACHE_BLK_DISCONNECTED,
    RNABLK_CACHE_BLK_CONNECT_PENDING,
    RNABLK_CACHE_BLK_CONNECTED_READ,
    RNABLK_CACHE_BLK_CONNECTED_WRITE,
    RNABLK_CACHE_BLK_CONNECTED_WRITE_ONLY,
    RNABLK_CACHE_BLK_CONNECTED_WRITE_EXCLUSIVE,
    RNABLK_CACHE_BLK_CONNECTED_ATOMIC,
    RNABLK_CACHE_BLK_DISCONN_PENDING,
    RNABLK_CACHE_BLK_CHANGE_PENDING,
    RNABLK_CACHE_BLK_DELETE_PENDING,
    RNABLK_CACHE_BLK_INVALIDATE_PENDING,
    RNABLK_CACHE_BLK_INVALID,
    RNABLK_CACHE_BLK_FREE,
    RNABLK_CACHE_BLK_STATE_COUNT  /* Must be last */
} rnablk_cache_blk_state_t;

#ifdef WINDOWS_KERNEL
typedef struct com_ep Com_EP, *PCom_EP;
#endif //WINDOWS_KERNEL
  
struct rnablk_server_conn {
#if defined(RNABLK_VERIFY_CONN_BY_MAGIC)
    uint64_t                front_magic;
#endif
    struct rna_service_id   id;             // transport-independent ID
#ifndef WINDOWS_KERNEL
	struct rb_node          rbn;            // used in connection tree
#endif /*WINDOWS_KERNEL*/
    atomic_t                rsc_refcount;
    struct list_head        io_queue;       // io requests (logically) queued here before dispatch
    struct list_head        rsc_wlru_list;  // write LRU list of blks...
    rna_block_mutex_t       block_list_lock;// protects block list

    int                     block_list_length;// all blocks associated with conn
    atomic_t                io_queue_length;// requests in io_queue
    rna_spinlock_t          sc_lock;        // protects query_queue, io_queue
    struct list_head        rsc_cachedevs;  // list of cache-devices associated
                                            // with this cache server
                                            // (protected by rsc_lock)
    struct com_ep           *ep;            // NULL for MD connection
    atomic_t                state;          // see rnablk_conn_state
    uint64_t                rsc_last_queued_conn_ts;

    int                     send_bufs;      // send_buf count specified on ep
    int                     rdma_bufs;      // rdma_buf count specified on ep


    int                     local;          /**< TRUE if CS is running on local node */

    /* Buffer count stats for debug only */
    atomic_t                rdma_bufs_allocated;
    atomic_t                send_bufs_allocated;

    atomic_t                rdma_buf_alloc_failures;
    atomic_t                send_buf_alloc_failures;

    atomic_t                rdma_bufs_in_use;
    atomic_t                send_bufs_in_use;

    atomic_t                null_completion_bufs;
    atomic_t                zero_completion_tags;
    atomic_t                eagains;        /**< Count of cache responses with status EAGAIN */

    atomic_t                conn_count; /* connection count */

    atomic64_t              max_block_list_lock_ns;
    atomic64_t              deref_walk_timeouts;

    atomic_t                dispatching_rescheduled;
    atomic_t                dispatch_needed;

    atomic_t                rsc_flags;           // used as a bitfield
#define RSC_F_DISPATCHING            0x00000001 // TRUE when next_request
                                                // decides to consume one
                                                // until it is dispatched.
#define RSC_F_DISPATCH_SCHEDULED     0x00000002
#define RSC_F_DISPATCH_ON_COMPLETION 0x00000004
#define RSC_F_QUEUING_CONN_RETRY     0x00000008
#define RSC_F_ENFORCER_SCHEDULED     0x00000010
#define RSC_F_IOS_TMO_DEFERRED       0x00000020
#define RSC_F_EXPELLED               0x00000040
#define RSC_F_LATE_CONNECT           0x00000080  // connected after cachedev
                                                 // was expelled

    struct rnablk_server_conn *rsc_parent_conn;
                                // distinguishes primary CS conn from
                                // cache-device conns.
                                // points to self for primary CS conn
    boolean                   rsc_disconnecting;
                                // used only for primary conn, used to
                                // coordinate with per-cachedev conn
                                // disconnects.
                                // protected by conn_cleanup_mutex

    /* used for cache server cache-device connections */
    atomic_t                  rsc_connected_conns; // only used in CS conn
    rnablk_cachedev_t         *rsc_cachedev;       // only used in non-CS conn
    int                       rsc_idx;             // index in rcd_conns array
	uint64_t                  rsc_lru_oldest_ts;   // jiffies
    uint64_t                  rsc_wlru_oldest_ts;  // jiffies

    /* used to rate-limit proactive write reference drops/downgrades */
    atomic_t                  rsc_outstanding_write_releases;

    int                     rsc_active_if;  // interface we last actively
                                            // attempted to connect to
    int                     if_attempts;    // Number of attempts to retry next_if
    struct rna_if_table     if_table;       // list of available interfaces for cache server
#ifdef WINDOWS_KERNEL
    pHW_HBA_EXT                pHBAExt;
#endif //WINDOWS_KERNEL

#if defined(RNABLK_VERIFY_CONN_BY_MAGIC)
    uint64_t                back_magic;
#endif
};

#ifdef WINDOWS_KERNEL
typedef struct rnablk_server_conn Server_Conn, *PServer_Conn;

//This define is from Linux limits.h
 #define NAME_MAX         255

//The following struct is copied from Linux kref.h file
struct kref {
	atomic_t refcount;
};

//The following define and struct are copied from Linux configfs.h file
#define CONFIGFS_ITEM_NAME_LEN  20
struct config_item {
	char                    *ci_name;
	char                    ci_namebuf[CONFIGFS_ITEM_NAME_LEN];
	struct kref             ci_kref;
	struct list_head        ci_entry;
	struct config_item      *ci_parent;
	struct config_group     *ci_group;
	struct config_item_type *ci_type;
	struct dentry           *ci_dentry;
};

//TODO: This section is copied from Linux timer.h file
struct tvec_base;
 
struct timer_list {
	/*
	 * All fields that change during normal runtime grouped to the
	 * same cacheline
	 */

	struct list_head entry;
	unsigned long expires;
	struct tvec_base *base;
	
	void (*function)(unsigned long);
	uint64_t data;

	int slack;
	
#ifdef CONFIG_TIMER_STATS
	int start_pid;
	void *start_site;
	char start_comm[16];
#endif
#ifdef CONFIG_LOCKDEP
	struct lockdep_map lockdep_map;
#endif
};

/*
 * This structure and the following functions are Windows specific 
 * versions of their Linux counterparts.
 */
struct timer_win {
    /*
     * timer_list structure for windows support...
     */
    uint64_t		expires;
    void (*function)(unsigned long);
    uint64_t        data;
    KDPC            timerDpc;
    KTIMER          timer;
    boolean         bDpcQueuedBeforeCancel;
};

extern void init_timer(struct timer_win *timer);
extern int mod_timer(struct timer_win *timer, uint64_t expires);
extern int del_timer_sync(struct timer_win *timer);
extern void clean_timer(struct timer_win *timer);
extern void DisconnectTimerDpc(PKDPC Dpc,PVOID Context,PVOID Arg1,PVOID Arg2);
#endif

struct cache_blk {
#ifndef WINDOWS_KERNEL
    struct rb_node   rbn;
#endif /*WINDOWS_KERNEL*/
    struct list_head bl;
    struct list_head dispatch_queue;
    struct blk_lru_list cb_conn_lru;
    struct blk_lru_list cb_conn_wref;
    struct list_head    cb_conn_wlru;
    struct list_head    cb_dev_link;
    rna_spinlock_t       bl_lock;
    uint64_t    cb_ref_time;           // time of last i/o (jiffies)
	uint64_t    cb_write_time;         // time of last write i/o (jiffies)

    // XXX: we should really use a conn pointer instead of an EP
    struct com_ep    *ep;
    struct rnablk_server_conn *cb_conn;     // currently only used for
                                            // MASTER blk for specific
                                            // uses; still need to do
                                            // above switch for all, i.e.
                                            // use conn instead of ep
    /* one of server per-device EPs */
    struct rnablk_server_conn *cb_dev_conn;

    uint64_t         start_sector;
    uint64_t         end_sector;
    uint64_t         rid;

    // fields describing the remote buffer to the IB layer
    rna_addr_t       raddr;
    rna_rkey_t       rkey;
    uint32_t         rlen;
    /**< For direct (DMA, RDMA) (read) access to block, when allowed,
     *   which bypasses some or all software layers in the target */
    rna_addr_t       direct_raddr;  
    rna_rkey_t       direct_rkey;

    rna_hash_key_t   hash_key;
    uint64_t    last_write_secs;
    uint64_t    last_read_secs;
    uint64_t         block_number;
    atomic_t         ref_count;
    atomic_t         cb_ioref_cnt;
    int              connection_failures;
    atomic_t         retries; // number of EAGAINS

    union {
        uint32_t     cb_identity_flags;
        /* "permanent" flags so don't require atomicity to access */
#define     BLK_F_MASTER_BLK        0x00000001
#define     BLK_F_MARKER_BLK        0x00000002
        atomic_t         cb_flags;
#define     BLK_F_QUIESCE_COMPLETE  0x00000004  // cachedev fail processing
                                                //  (used with bl lock)
#define     BLK_F_QUEUED_DRAIN      0x00000008  // a drain has been queued
#define     BLK_F_DEREF_QUEUED      0x00000010
#define     BLK_F_DISCONN_FROZEN    0x00000020  // blk involved in 'freeze'
                                                // processing
                                                // (atomicity not rneeded)
#define     BLK_F_WAIT_ON_IO        0x00000040  // TRUE if a CHANGE_REF
                                                // is blocked waiting for
                                                // outstanding I/O to drain.
#define     BLK_F_MASTER_LOCK_ACTIVE 0x00000080 // LOCK_MASTER_BLK active on
                                                // this (MASTER) blk
#define     BLK_F_QUEUED_MASTER_LOCK 0x00000100 // a delayed LOCK_MASTER_BLK
                                                // has been queued
    };
    rnablk_cache_blk_state_t state;     // State as of last queued IO
    cache_lock_t     ref_type;  /**< Current reference type */
    rnablk_cache_blk_state_t dev_counts_state; /* State last used to determine reading/writing 
                                                  block count contribution */
    atomic_t         inflight_ios;     /* Number of outstanding i/o's */
    struct rnablk_device *dev;      // back-pointer to device
    struct rnablk_local_dev *ldev;/* local block store device.  NULL if remote */
    struct rnablk_cachedev_s *blk_cachedev; // cache-device where block resides
                                        // (this field always has a valid ptr)
    cachedev_id_t           cb_cachedev_id;  // Cache device ID from MD response

    /* used this to identify a block as being released/downgraded proactively */
    atomic_t                    cb_write_reference_pending;

#ifdef WINDOWS_KERNEL
    unsigned long               blkSeq;
    LIST_ENTRY                  dev_blk_list;
	LIST_ENTRY                  dev_lru_blk_list;        // device cache block least used list
    LIST_ENTRY                  wfc_list;
    cache_lock_t                required_ref_type;
    BOOLEAN                     isMasterBlock;
    pHW_HBA_EXT                 pHBAExt;
#endif //WINDOWS_KERNEL
};

typedef int (*RNABLK_CACHE_FOREACH_CB) (struct rnablk_server_conn *conn,
                                        void                      *ctx);

typedef int (*RNA_BLK_FOREACH_CB) (struct cache_blk *blk,
                                   void             *ctx);

/* This is original Linux code as a define. But in windows, in order to compile this, change this to
   an inline function call

#define blk_lru_first_entry(ent, is_wref, reflink, writelink) \
 ({ \
    struct cache_blk *_b; \
    struct blk_lru_list *_bent; \
    \
    _bent = _LRU_GET_ENT_PTR((ent)->blru_next); \
    if (_LRU_GET_ENT_LSB(_bent->blru_next)) { \
        _b = container_of(_bent, struct cache_blk, writelink); \
        (is_wref) = 1; \
    } else { \
        _b = container_of(_bent, struct cache_blk, reflink); \
        (is_wref) = 0; \
    } \
    _b; \
 })
*/
INLINE struct cache_blk * blk_lru_first_entry(struct blk_lru_list * ent)
{
    struct cache_blk *_b;
    struct blk_lru_list *_bent;
    
    _bent = _LRU_GET_ENT_PTR((ent)->blru_next);
    if (_LRU_GET_ENT_LSB(_bent->blru_next)) {
		_b = container_of(_bent, struct cache_blk, cb_conn_wref);
    } else {
        _b = container_of(_bent, struct cache_blk, cb_conn_lru);
    }
    return _b;
 }


/* This is original Linux code as a define. But in windows, in order to compile this, change this to
   an inline function call
#define blk_lru_entry(ent, is_wref, reflink, writelink) \
 ({ \
    struct cache_blk *__b; \
    if (_LRU_GET_ENT_LSB((ent)->blru_next)) { \
        __b = container_of(ent, struct cache_blk, writelink); \
        (is_wref) = 1; \
    } else { \
        __b = container_of(ent, struct cache_blk, reflink); \
        (is_wref) = 0; \
    } \
    __b; \
 })
 */

INLINE struct cache_blk * blk_lru_entry(struct blk_lru_list *ent, int * is_wref)
{
    struct cache_blk *__b;
    if (_LRU_GET_ENT_LSB((ent)->blru_next)) {
        __b = container_of(ent, struct cache_blk, cb_conn_wref);
        (*is_wref) = 1;
    } else {
        __b = container_of(ent, struct cache_blk, cb_conn_lru);
        (*is_wref) = 0;
    }
    return __b;
}

#endif //INCLUDED_RNA_CACHE_STRUCTS_H
