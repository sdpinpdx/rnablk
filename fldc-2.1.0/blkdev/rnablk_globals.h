/**
 * <rnablk_globals.h> - Dell Fluid Cache block driver
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
#include "rb.h"
#include "../include/rna_common.h"

#ifdef WINDOWS_KERNEL
#include "rna_service_win_workqueue.h"
#endif


extern int net_link_mask;
extern rsv_client_id_t rnablk_client_id;
extern rsv_itn_id_t rnablk_itn_id;
extern int rnablk_use_write_only;
extern struct rna_rw_semaphore svr_conn_lock;
#ifndef WINDOWS_KERNEL
extern struct rna_rw_semaphore rnablk_dev_list_lock;
#endif
extern struct rna_rw_semaphore wfc_queue_lock;
extern struct rb_root cache_conn_root;
extern atomic_t shutdown;
extern rnablk_cachedev_t null_cachedev;
extern atomic_t rna_service_detached;
extern struct rnablk_device null_device;
extern struct cache_blk null_blk;
extern int rnablk_io_queue_depth;
extern atomic_t slow_workq_items;
extern int rnablk_per_device_connections;

extern rna_service_throttle_t  rnablk_ios_io_throttle;

extern int rna_com_retry_count;
extern int rna_com_rnr_retry_count;
extern int max_wr;
extern int max_sge;
extern struct rna_com *g_com;
extern struct com_attr g_com_attr;
extern boolean ios_timeout_script_active;
extern atomic_t anon_drop_ref_requests;
extern atomic_t delayed_work;
extern int net_link_mask;
extern atomic_t ios_count;
extern atomic_t ios_rb_id;
extern long rnablk_io_timeout;
#ifndef WINDOWS_KERNEL
extern struct rna_service_ctx_s *rna_service_ctx;
#endif /*WINDOWS_KERNEL*/
extern int max_connection_failures;
#ifndef WINDOWS_KERNEL
extern atomic_t g_conn_status;
#endif
extern int enable_creates;
extern uint64_t max_rs;
extern int rnablk_queue_bios;
extern int read_deref_secs;
extern int write_deref_secs;

/* set to TRUE via CFS to disable SCSI UNMAP command support */
extern int rnablk_scsi_unmap_disable;

/*
 * set to TRUE via CFS to disable SCSI WRITE_SAME and WRITE_SAME_16
 * command support.
 */
extern int rnablk_scsi_write_same_disable;
/* 
 * set to TRUE via CFS to only use RDMA connections for client-CS connections if
 * RDMA is configured.
 */
extern int rnablk_only_use_rdma_for_cs;

extern int rb_bounce_buffer_bytes;
extern int rb_bounce_segment_bytes;

/* If true we will use the block elevator to manage incoming I/O */
extern int rnablk_use_req_queue;

/* XXX: These are Linux-specific and need to get hidden away behind some API */
extern struct rnablk_cache_info * blk_cache_info;
extern struct rnablk_cache_info * work_cache_info;
extern struct rnablk_cache_info * cmd_cache_info;
extern struct rnablk_cache_info * create_cache_info;
extern struct rnablk_cache_info * osgl_cache_info;

#ifdef WINDOWS_KERNEL
extern struct rnablk_cache_info * dwork_cache_info;
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
extern struct rnablk_cache_info * dwork_cache_info;
#endif
#endif /*WINDOWS_KERNEL*/

#ifdef WINDOWS_KERNEL
extern rna_service_work_queue_t *mt_workq;
extern rna_service_work_queue_t *ios_workq;
extern rna_service_work_queue_t *ordered_workq;
extern rna_service_work_queue_t *slow_workq;
extern rna_service_work_queue_t *bio_workq;
extern rna_service_work_queue_t *enforcer_workq;
#else
extern struct workqueue_struct *mt_workq;
extern struct workqueue_struct *ios_workq;
extern struct workqueue_struct *ordered_workq;
extern struct workqueue_struct *slow_workq;
extern struct workqueue_struct *bio_workq;
extern struct workqueue_struct *enforcer_workq;

#endif /*WINDOWS_KERNEL*/

#ifndef WINDOWS_KERNEL
extern struct list_head rnablk_dev_list;

extern rna_service_mutex_t local_dev_mutex;
#else
extern KSPIN_LOCK local_dev_lock;
#endif
extern struct list_head local_dev_list;

extern struct completion rna_service_connect_comp;

#ifndef WINDOWS_KERNEL
extern struct cfm_info cfm_config_info;
extern struct sockaddr_in online_cfms[RNA_SERVICE_CFMS_MAX];
#endif

extern char node_name[MAX_HOST_LEN];

#ifndef WINDOWS_KERNEL
extern struct rnablk_latency_stats latency_stats;
#endif

extern struct rnablk_server_conn *g_md_conn;

#ifdef TEST_OFFLINE_CACHE_DEVICE
extern cachedev_id_t test_cachedev_fail_ldma;
extern cachedev_id_t test_cachedev_fail_rdma;
extern cachedev_id_t test_cachedev_fail_cache_resp;
extern cachedev_id_t test_cachedev_fail_cache_ref_resp;
extern int test_dev_conn_disconnect;
#endif /* TEST_OFFLINE_CACHE_DEVICE */

#define RNABLK_NL_IOS_STATE  1
#define RNABLK_NL_BLK_STATE  2
#define RNABLK_NL_LOCK       4
#define RNABLK_NL_ENFORCER   8
#define RNABLK_NL_BIO       16
#define RNABLK_NL_IOS_REF   32
#define RNABLK_NL_IOS_TIMER 64
#define RNABLK_NL_DISCON    128     // used for disconnect & cachedev failure
#define RNABLK_NL_MASTER    256     // master_block tracing
#define RNABLK_NL_MUTEX     512

/* time values */
#define RNABLK_FREEZE_DELAY_MS      (2 * MSEC_PER_SEC)
#define RNABLK_IOS_CONN_CHECK_MS    (1 * MSEC_PER_SEC)
#define RNABLK_CACHEDEV_CONN_CHECK_MS   (30 * MSEC_PER_SEC)
#define RNABLK_BUSY_DELAY_MS        50
#define RNABLK_EAGAIN_DELAY_MS      (1 * MSEC_PER_SEC)
#define RNABLK_OFFLINE_DELAY_MS     (5 * MSEC_PER_SEC)
#define RNABLK_RELOCATE_DELAY_MS    50

/* rna_service_detached states */
#define RNA_SERVICE_JOINED              0       // must be 0
#define RNA_SERVICE_DETACHED            1
#define RNA_SERVICE_DETACHED_SHUTDOWN   2


extern unsigned long rnablk_reference_target_age;
extern unsigned long rnablk_write_reference_target_age;

/*
 * the maximum number of outstanding proactive write reference
 * drops/downgrades in flight to a given CS at any one time
 */
extern unsigned int rnablk_write_reference_release_max_outstanding;

/* CS ping definitions & declarations */
#define CS_PING_INTERVAL                (5 * MSEC_PER_SEC)  // in milliseconds

/* MD ping interval -- this one's in seconds */
#define MD_PING_INTERVAL                (10)                // in seconds


#ifndef WINDOWS_KERNEL
extern wait_queue_head_t rnablk_cs_ping_wq;
extern long rnablk_cs_ping_interval;         // in jiffies
extern int rnablk_cs_ping_worker(void *unused);
#endif


#ifdef WINDOWS_KERNEL
// Converting Linux names of globals into fields in miniport HBA extension.
#define latency_stats         pHBAExt->hba_latency_stats
#define cfm_config_info       pHBAExt->hba_cfm_config_info
#define g_conn_status         pHBAExt->hba_g_conn_status
#endif
