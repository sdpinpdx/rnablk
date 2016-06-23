/*
 * <rnablk_util.h> - Dell Fluid Cache block driver
 *
 * Copyright (c) 2013 Dell  Inc
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
#pragma once

#include "rnablk_block_state.h"
#include "../include/rna_common.h"

#ifdef WINDOWS_KERNEL
#include "rna_service_win_workqueue.h"
#endif

enum {
    RNABLK_LATENCY_QUERY = 0,
    RNABLK_LATENCY_WO_QUERY,
    RNABLK_LATENCY_WO_TO_W,
    RNABLK_LATENCY_DEREF,
    RNABLK_NUM_LATENCY_STATS    /* Must be last */
};

struct rnablk_latency_stats {
    rna_spinlock_t  ls_spinlock;
    atomic_t    ls_count[RNABLK_NUM_LATENCY_STATS];
    uint64_t    ls_time[RNABLK_NUM_LATENCY_STATS];
    uint64_t    ls_min[RNABLK_NUM_LATENCY_STATS];
    uint64_t    ls_max[RNABLK_NUM_LATENCY_STATS];
};

#ifdef WINDOWS_KERNEL
static void rnablk_latency_stats_init(struct rnablk_latency_stats *pStats)
{
    int i;
    memset(pStats, 0, sizeof(*pStats));
    rna_spin_lock_init(pStats->ls_spinlock);
    for (i = 0; i < RNABLK_NUM_LATENCY_STATS; i++) {
        pStats->ls_min[i] = (uint64_t)-1;
    }
}
#else
INLINE void
rnablk_latency_stats_init(void) 
{
    int i;
    memset(&latency_stats, 0, sizeof(latency_stats));
    rna_spin_lock_init(latency_stats.ls_spinlock);
    for (i = 0; i < RNABLK_NUM_LATENCY_STATS; i++) {
        latency_stats.ls_min[i] = (uint64_t)-1;
    }
}
#endif

INLINE struct sockaddr_in get_dest_sockaddr_from_ep(struct com_ep *ep)
{
#ifdef WINDOWS_KERNEL
    return com_get_ep_dst_in(ep);
#else
    return ep->dst_in;
#endif /*WINDOWS_KERNEL*/
}

#define NS_PER_HZ ((1000*1000*1000)/HZ)

/*
 * XXXcorene The below is temporary, to help track extra logging messages
 * added for early debug of SCSI reservation support.  Later these messages
 * can either be changed to a lower loglevel or in some cases deleted entirely.
 */
#define KERN_RSV    KERN_NOTICE

#define rnablk_nl_trace(mask, fmt, ...)                             \
    if (net_link_mask & (mask)) {                                   \
        __printnl_atomic("%s:%d:: " fmt, __FUNCTION__,              \
                           __LINE__ , ##__VA_ARGS__);               \
    }
    
#define rnablk_trace(lvl, mask, fmt, ...)                           \
    (net_link_mask & (mask))                                        \
        ? __printnl_atomic("%s:%d:: " fmt, __FUNCTION__,            \
                           __LINE__ , ##__VA_ARGS__)                \
        : rna_printk((lvl), fmt, ##__VA_ARGS__)

/* Enable the below to enable specific tracing... */
#if 0
#define RNABLK_TRC_MASTER
#define RNABLK_TRC_DISCON
#endif

#ifdef RNABLK_TRC_MASTER
#define rnablk_trc_master(cond, fmt, ...)                           \
    if (cond) {                                                     \
        rnablk_trace(KERN_NOTICE, RNABLK_NL_MASTER, fmt, ##__VA_ARGS__); \
    }
#else
#define rnablk_trc_master(cond, fmt, ...)
#endif
#ifdef RNABLK_TRC_DISCON
#define rnablk_trc_discon(cond, fmt, ...)                           \
    if (cond) {                                                     \
        rnablk_trace(KERN_NOTICE, RNABLK_NL_DISCON, fmt, ##__VA_ARGS__); \
    }
#else
#define rnablk_trc_discon(cond, fmt, ...)
#endif

#ifdef IOS_TIMEOUT_TEST
extern boolean ios_timeout_test;
#endif /* IOS_TIMEOUT_TEST */

#ifdef WINDOWS_KERNEL
extern uint64_t get_seconds();
extern unsigned int jiffies_to_msecs(const uint64_t j);
#endif

/* RNA_INIT_WORK wrapper for struct rnablk_work, which initializes a
 * local pointer to the work data union member matching the work
 * function 
 */
#define RNABLK_INIT_RNABLK_WORK(_rirw_work, _rirw_work_data, _rirw_func)  {   \
    RNA_INIT_WORK(&_rirw_work->work, _rirw_func, _rirw_work);                 \
    _rirw_work_data=&_rirw_work->data.rwd_##_rirw_func;                       \
}

struct rnablk_retry_connection_data {
    struct  rnablk_server_conn *conn;
};

struct rnablk_drop_connection_wf_data {
    struct rnablk_server_conn       *conn;
};

struct rnablk_drop_dev_conns_wf_data {
    rnablk_cachedev_t               *cachedev;
};

struct rnablk_run_queue_wf_data {
    struct request_queue            *q;
};

struct rnablk_clear_dev_queue_stop_flag_wf_data {
    struct rnablk_device            *dev;
    enum rnablk_queue_stop_flags    stop_flag;
};

struct rnablk_conn_dispatch_wf_data {
    struct rnablk_server_conn       *conn;
};

struct rnablk_wake_up_wf_data {
	//Add this member just to make the code compile. Windows requires struct has at least one member
	uint64_t foo;
};

struct rnablk_enforcer_wf_data {
    struct rnablk_server_conn       *conn;
};

struct rnablk_queued_deref_data {
    struct com_ep                   *cache_ep;
    cachedev_id_t                    cachedev_id;
    uint64_t                         bytes;
    boolean                          is_from_cs;
};

struct rnablk_restart_dev_blks_data {
    struct rnablk_device            *dev;
};

struct rnablk_queued_deref_wf_data {
    struct cache_blk                *blk;
    uint32_t                        hipri;
};

struct rnablk_queued_offline_cache_device_data {
    struct rnablk_server_conn       *conn;
    rnablk_cachedev_t               *cachedev;
    int                             n_quiesces;
};

struct rnablk_queued_conn_disconnect_work_data {
    struct rnablk_server_conn      *conn;
    boolean (*work_func)(struct rnablk_server_conn *, int);
    int                            n_quiesces;     
};

struct rnablk_trans_req_wf_data {
    struct rnablk_device *tr_dev;
    uint64_t tr_block_num;
    uint8_t tr_cur_ref;
    uint8_t tr_new_ref;
};

struct rnablk_ios_release_wf_data {
    ios_tag_t                        tag;
};

struct rnablk_queued_transition_data {
    struct cache_blk                *blk;
    cache_lock_t                     to_ref;
};

struct rnablk_queued_delete_data {
    struct cache_blk                *blk;
};

struct rnablk_delayed_master_blk_lock_data {
    struct rnablk_device            *dev;
};

struct rnablk_run_ldev_queue_wf_data {
    struct rnablk_local_dev *ldev;
};


struct rnablk_schedule_destroy_ios_wf_data {
    struct io_state *ios;
};

struct rnablk_das_mdq_response_wf_data {
    struct rna_service_ctx_s *ctx;
    rna_service_message_buffer_t *mbuf;
    rna_service_message_buffer_t *rbuf;
    rna_service_response_callback callback;
};

struct rnablk_offline_cachedev_wf_data {
    struct rnablk_server_conn       *ocd_conn;
    cachedev_id_t                   ocd_cachedev_id;
    boolean                         ocd_notify_cs;
};

struct rnablk_process_bio_wf_data {
    struct request_queue *q;
    struct bio           *bio;
};

struct rnablk_blk_restart_wf_data {
    struct cache_blk *blk;
};

struct rnablk_ios_requeue_wf_data {
    struct io_state *ios;
};

struct rnablk_rsv_access_wf_data {
    struct rnablk_device *dev;
};

struct rnablk_register_block_device_wf_data {
    struct rnablk_device *dev;
};

struct rnablk_cs_ping_resp {
    struct com_ep *cpr_ep;
};

/* Data union for work funcitons taking an rnablk_work struct. Union
 * member name must match work function name (with rwd_ prepended) for
 * RNABLK_INIT_RNABLK_WORK() macro to function. */
union rnablk_work_data {
    struct rnablk_retry_connection_data                 rwd_rnablk_retry_connection;
    struct rnablk_drop_connection_wf_data               rwd_rnablk_drop_connection_wf;
    struct rnablk_drop_dev_conns_wf_data                rwd_rnablk_drop_dev_conns_wf;
    struct rnablk_run_queue_wf_data                     rwd_rnablk_run_queue_wf;
    struct rnablk_clear_dev_queue_stop_flag_wf_data     rwd_rnablk_clear_dev_queue_stop_flag_wf;
    struct rnablk_conn_dispatch_wf_data                 rwd_rnablk_conn_dispatch_wf;
    struct rnablk_wake_up_wf_data                       rwd_rnablk_wake_up_wf;
    struct rnablk_enforcer_wf_data                      rwd_rnablk_enforcer_wf;
    struct rnablk_restart_dev_blks_data                 rwd_rnablk_restart_dev_blks;
    struct rnablk_queued_deref_wf_data                  rwd_rnablk_queued_deref_wf;
    struct rnablk_ios_release_wf_data                   rwd_rnablk_ios_release_wf;
    struct rnablk_queued_transition_data                rwd_rnablk_queued_transition;
    struct rnablk_queued_delete_data                    rwd_rnablk_queued_delete;
    struct rnablk_run_ldev_queue_wf_data                rwd_rnablk_run_ldev_queue_wf;
    struct rnablk_schedule_destroy_ios_wf_data          rwd_rnablk_schedule_destroy_ios_wf;
    struct rnablk_das_mdq_response_wf_data              rwd_rnablk_das_mdq_response_wf;
    struct rnablk_offline_cachedev_wf_data              rwd_rnablk_offline_cachedev_wf;
    struct rnablk_offline_cachedev_wf_data              rwd_rnablk_offline_cachedev_notify_wf;
    struct rnablk_offline_cachedev_wf_data              rwd_rnablk_expel_cache_device_wf;
    struct rnablk_process_bio_wf_data                   rwd_rnablk_process_bio_wf;
    struct rnablk_blk_restart_wf_data                   rwd_rnablk_blk_restart_wf;
    /*
     * Used for rnablk_drop_references, and rnablk_downgrade_writers work functions.  
     * Not initialized by RNABLK_INIT_RNABLK_WORK()
     */
    struct rnablk_queued_deref_data                     rwd_queued_deref;
    struct rnablk_rsv_access_wf_data                    rwd_rnablk_rsv_access_wf;
    struct rnablk_trans_req_wf_data                     rwd_rnablk_trans_req_wf;
    struct rnablk_register_block_device_wf_data         rwd_rnablk_register_block_device_wf;
    struct rnablk_cs_ping_resp                          rwd_rnablk_cs_ping_resp;

#ifdef WINDOWS_KERNEL   
    /*
     * Added the following because in windows, delayed workqueue is defined to regular work queue
     */
    struct rnablk_ios_requeue_wf_data                   rwd_rnablk_ios_requeue_wf_data;
    struct rnablk_delayed_master_blk_lock_data          rwd_rnablk_delayed_master_blk_lock;
    struct rnablk_queued_offline_cache_device_data      rwd_rnablk_queued_offline_cache_device;
    struct rnablk_queued_conn_disconnect_work_data      rwd_rnablk_queued_conn_disconnect_work;
#endif /*WINDOWS_KERNEL*/
};

struct rnablk_work {
    rna_work_struct_t       work;
    union rnablk_work_data  data;
    int                     delayed : 1;
};

struct rnablk_create_delete_work {
    rna_work_struct_t            work;
    struct rna_service_ctx_s     *ctx;
    rna_service_message_buffer_t *message;
};

#ifndef WINDOWS_KERNEL

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
/* The subset of the rnablk_work_data union that's actually used in dwork functions.
 *
 * Member names must be identical to the corresponding member of rnablk_work_data. */
union rnablk_dwork_data {
    struct rnablk_delayed_master_blk_lock_data          rwd_rnablk_delayed_master_blk_lock;
    struct rnablk_ios_requeue_wf_data                   rwd_rnablk_ios_requeue_wf_data;
    struct rnablk_queued_deref_wf_data                  rwd_rnablk_queued_deref_wf;
    struct rnablk_queued_offline_cache_device_data      rwd_rnablk_queued_offline_cache_device;
    struct rnablk_queued_conn_disconnect_work_data      rwd_rnablk_queued_conn_disconnect_work;
};

struct rnablk_dwork {
    struct delayed_work     dwork;
    union rnablk_dwork_data data;
    int                     delayed : 1;
};
#endif /*LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)*/
#endif /*WINDOWS_KERNEL*/

#ifdef WINDOWS_KERNEL
typedef rna_work_struct_t * rnablk_workq_cb_arg_t;
#else
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
typedef void * rnablk_workq_cb_arg_t;
#else
typedef struct work_struct * rnablk_workq_cb_arg_t;
#endif
#endif /*WINDOWS_KERNEL*/

#ifdef WINDOWS_KERNEL
#define RNABLK_DWORK_OBJECT(__rdo) &__rdo->work
#else
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
#define RNABLK_DWORK_OBJECT(__rdo) &__rdo->work
#else
#define RNABLK_DWORK_OBJECT(__rdo) &__rdo->dwork
#endif
#endif /*WINDOWS_KERNEL*/

#ifdef WINDOWS_KERNEL
#define RNABLK_ALLOC_DWORK() rnablk_mempool_alloc(work_cache_info)
#else
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
#define RNABLK_ALLOC_DWORK() rnablk_mempool_alloc(work_cache_info)
#else
#define RNABLK_ALLOC_DWORK() rnablk_mempool_alloc(dwork_cache_info)
#endif
#endif /*WINDOWS_KERNEL*/

#ifdef WINDOWS_KERNEL
#define RNABLK_FREE_DWORK(__rfdw) rnablk_mempool_free( __rfdw, work_cache_info );
#else
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
#define RNABLK_FREE_DWORK(__rfdw) rnablk_mempool_free( __rfdw, work_cache_info );
#else
#define RNABLK_FREE_DWORK(__rfdw) rnablk_mempool_free( __rfdw, dwork_cache_info );
#endif
#endif /*WINDOWS_KERNEL*/

#ifdef WINDOWS_KERNEL
#define RNABLK_INIT_DWORK(__rid_w,__rid_cb)\
{\
    memset(__rid_w,0,sizeof(*__rid_w)); \
    RNA_INIT_WORK( &__rid_w->work,__rid_cb,__rid_w);\
}
#else
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
#define RNABLK_INIT_DWORK(__rid_w,__rid_cb)\
{\
    memset(__rid_w,0,sizeof(*__rid_w)); \
    RNA_INIT_WORK( &__rid_w->work,__rid_cb,__rid_w);\
}
#else
#define RNABLK_INIT_DWORK(__rid_w,__rid_cb)\
{\
    memset(__rid_w,0,sizeof(*__rid_w)); \
    INIT_DELAYED_WORK(&__rid_w->dwork, __rid_cb);\
    atomic_inc( &delayed_work );\
    __rid_w->delayed = 1;\
}
#endif
#endif /*WINDOWS_KERNEL*/

#ifdef WINDOWS_KERNEL
typedef struct rnablk_work * rnablk_dwork_t;
#else
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
typedef struct rnablk_work * rnablk_dwork_t;
#else
typedef struct rnablk_dwork * rnablk_dwork_t;
#endif
#endif /*WINDOWS_KERNEL*/

#ifdef WINDOWS_KERNEL
#define RNABLK_ARG_DWORK(__rad_arg) container_of(__rad_arg, struct rnablk_work, work)
#else
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
#define RNABLK_ARG_DWORK(__rad_arg) container_of(__rad_arg, struct rnablk_work, work)
#else
#define RNABLK_ARG_DWORK(__rad_arg) container_of(__rad_arg, struct rnablk_dwork, dwork.work)
#endif
#endif /*WINDOWS_KERNEL*/

#define rnablk_lock_irqsave(__rli_lock,__rli_flags)\
    if(unlikely(net_link_mask & RNABLK_NL_LOCK)) {\
        printnl_atomic("[%d] [%s] [%s] locking [%s]\n",\
                       current->pid,\
                       __FUNCTION__,\
                       __location__,\
                       #__rli_lock);\
    }\
    spin_lock_irqsave(__rli_lock,__rli_flags);\
    if(unlikely(net_link_mask & RNABLK_NL_LOCK)) {\
        printnl_atomic("[%d] [%s] [%s] got lock [%s]\n",\
                       current->pid,\
                       __FUNCTION__,\
                       __location__,\
                       #__rli_lock);\
    }

#define rnablk_unlock_irqrestore(__rli_lock,__rli_flags)\
    spin_unlock_irqrestore(__rli_lock,__rli_flags);\
    if(unlikely(net_link_mask & RNABLK_NL_LOCK)) {\
        printnl_atomic("[%d] [%s] [%s] released lock [%s]\n",\
                       current->pid,\
                       __FUNCTION__,\
                       __location__,\
                       #__rli_lock);\
    }

#ifdef WINDOWS_KERNEL
#define rnablk_lock_blk_irqsave(__rlbi_blk,__rli_flags)\
    if(unlikely(net_link_mask & RNABLK_NL_LOCK)) {\
        printnl_atomic("[%d] [%s] [%s] locking [%s] block [%"PRIu64"]\n",\
                       current->pid,\
                       __FUNCTION__,\
                       __location__,\
                       __rlbi_blk->dev->name,\
                       __rlbi_blk->block_number);\
    }\
    rna_spin_in_stack_lock_irqsave(__rlbi_blk->bl_lock, __rli_flags);\
    RNABLK_BUG_ON_BLK((boolean)(rnablk_cache_blk_state_is_bogus(__rlbi_blk->state)), __rlbi_blk); \
    if(unlikely(net_link_mask & RNABLK_NL_LOCK)) {\
        printnl_atomic("[%d] [%s] [%s] got lock [%s] block [%"PRIu64"]\n",\
                       current->pid,\
                       __FUNCTION__,\
                       __location__,\
                       __rlbi_blk->dev->name,\
                       __rlbi_blk->block_number);\
    }
#else
#define rnablk_lock_blk_irqsave(__rlbi_blk,__rli_flags)\
    if(unlikely(net_link_mask & RNABLK_NL_LOCK)) {\
        printnl_atomic("[%d] [%s] [%s] locking [%s] block [%"PRIu64"]\n",\
                       current->pid,\
                       __FUNCTION__,\
                       __location__,\
                       __rlbi_blk->dev->name,\
                       __rlbi_blk->block_number);\
    }\
    rna_spin_lock_irqsave(__rlbi_blk->bl_lock,__rli_flags);\
    RNABLK_BUG_ON_BLK((boolean)(rnablk_cache_blk_state_is_bogus(__rlbi_blk->state)), __rlbi_blk); \
    if(unlikely(net_link_mask & RNABLK_NL_LOCK)) {\
        printnl_atomic("[%d] [%s] [%s] got lock [%s] block [%"PRIu64"]\n",\
                       current->pid,\
                       __FUNCTION__,\
                       __location__,\
                       __rlbi_blk->dev->name,\
                       __rlbi_blk->block_number);\
    }
#endif /*WINDOWS_KERNEL*/

#ifdef WINDOWS_KERNEL
#define rnablk_unlock_blk_irqrestore(__rubi_blk,__rli_flags)\
    rna_spin_in_stack_unlock_irqrestore(__rubi_blk->bl_lock, __rli_flags);\
    if(unlikely(net_link_mask & RNABLK_NL_LOCK)) {\
        printnl_atomic("[%d] [%s] [%s] released lock [%s] block [%"PRIu64"]\n",\
                       current->pid,\
                       __FUNCTION__,\
                       __location__,\
                       __rubi_blk->dev->name,\
                       __rubi_blk->block_number);\
    }
#else
#define rnablk_unlock_blk_irqrestore(__rubi_blk,__rli_flags)\
    rna_spin_unlock_irqrestore(__rubi_blk->bl_lock,__rli_flags);\
    if(unlikely(net_link_mask & RNABLK_NL_LOCK)) {\
        printnl_atomic("[%d] [%s] [%s] released lock [%s] block [%"PRIu64"]\n",\
                       current->pid,\
                       __FUNCTION__,\
                       __location__,\
                       __rubi_blk->dev->name,\
                       __rubi_blk->block_number);\
    }
#endif /*WINDOWS_KERNEL*/

#define rnablk_mutex_lock(__rml_mutex)\
    BUG_ON(__rml_mutex == &g_md_conn->block_list_lock);\
    if(unlikely(net_link_mask & RNABLK_NL_MUTEX)) {\
        printnl_atomic("[%d] [%s] [%s] locking mutex [%s] [%p]\n",\
                       current->pid,\
                       __FUNCTION__,\
                       __location__,\
                       #__rml_mutex,\
                       __rml_mutex);\
    }\
    mutex_lock(__rml_mutex);\
    if(unlikely(net_link_mask & RNABLK_NL_MUTEX)) {\
        printnl_atomic("[%d] [%s] [%s] got mutex [%s] [%p]\n",\
                       current->pid,\
                       __FUNCTION__,\
                       __location__,\
                       #__rml_mutex,\
                       __rml_mutex);\
    }

#define rnablk_mutex_unlock(__rmu_mutex)\
    mutex_unlock(__rmu_mutex);\
    if(unlikely(net_link_mask & RNABLK_NL_MUTEX)) {\
        printnl_atomic("[%d] [%s] [%s] released [%s] [%p]\n",\
                       current->pid,\
                       __FUNCTION__,\
                       __location__,\
                       #__rmu_mutex,\
                       __rmu_mutex);\
    }

#define RNABLK_QUEUED_FUNC_TIMEOUT_SECONDS 1
#define _rnablk_finish_workq_work(___rfww_start_seconds,___rfww_description,___rfww_seperator)    \
    if (unlikely((get_seconds() - ___rfww_start_seconds) > RNABLK_QUEUED_FUNC_TIMEOUT_SECONDS)) { \
        atomic_inc(&slow_workq_items);\
        rna_printk(KERN_ERR,\
                   "%s%stook [%"PRIu64"] seconds\n",\
                   ___rfww_description,\
                   ___rfww_seperator,\
                   (get_seconds() - ___rfww_start_seconds));\
    }\

#define rnablk_finish_workq_work(__rfww_start_seconds) _rnablk_finish_workq_work(__rfww_start_seconds,"","")
#define rnablk_finish_workq_work_with_desc(__rfwwwd_start_seconds,__rfwwwd_description)\
    _rnablk_finish_workq_work(__rfwwwd_start_seconds,__rfwwwd_description," ")

INLINE uint64_t getrawmonotonic_ns(void)
{
#ifdef WINDOWS_KERNEL
    LARGE_INTEGER perfCount;
    LARGE_INTEGER perfFreq;
    LARGE_INTEGER sec;
    LARGE_INTEGER ns;
    perfCount = KeQueryPerformanceCounter(&perfFreq);
    sec.QuadPart = (perfCount.QuadPart / perfFreq.QuadPart) * 1000000000;
    ns.QuadPart = ((perfCount.QuadPart % perfFreq.QuadPart) * 1000000000) / perfFreq.QuadPart;
    return (sec.QuadPart + ns.QuadPart);
#else
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
    return get_jiffies_64() * NS_PER_HZ;
#else    
    struct timespec tspec;

    getrawmonotonic(&tspec);
    return (tspec.tv_sec*1000*1000*1000) + tspec.tv_nsec;
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
#endif //WINDOWS_KERNEL
}

int
rnablk_deferred_process_ios_timeout_helper(struct io_state *ios,
                                           struct rnablk_server_conn *conn,
                                           boolean test);
