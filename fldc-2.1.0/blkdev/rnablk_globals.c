/**
 * <rnablk_globals.c> - Dell Fluid Cache block driver
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
#include "rnablk_util.h"

#ifdef WINDOWS_KERNEL
#include "rna_service_win_workqueue.h"
#endif

#if defined(LINUX_KERNEL) || defined(LINUX_USER)
//This is a nasty workaround to make both windows and linux happy. Copied the LIST_HEAD Define from Linux list.h
#undef LIST_HEAD
#define LIST_HEAD(name)  struct list_head name = LIST_HEAD_INIT(name)
#endif

//KERN_EMERG	"<0>"	/* system is unusable			*/
//KERN_ALERT	"<1>"	/* action must be taken immediately	*/
//KERN_CRIT	    "<2>"	/* critical conditions			*/
//KERN_ERR	    "<3>"	/* error conditions			*/
//KERN_WARNING	"<4>"	/* warning conditions			*/
//KERN_NOTICE	"<5>"	/* normal but significant condition	*/
//KERN_INFO	    "<6>"	/* informational			*/
//KERN_DEBUG	"<7>"	/* debug-level messages			*/
int rna_printk_level = 5;

#define RNABLK_MAX_WR (MAX(RNA_MAX_TCP_WR,RNA_MAX_RDMA_WR))

/* XXX--Maybe make these more configurable */
#define RNABLK_DEFAULT_MAX_BOUNCE_BUFFER_IO_SIZE        (32 * 1024)
/* Allocate space for 32 buffers of MAX_BOUNCE_BUFFER_IO_SIZE */
#define RNABLK_DEFAULT_BOUNCE_BUFFER_BYTES          \
    (RNABLK_DEFAULT_MAX_BOUNCE_BUFFER_IO_SIZE * 32)

uint32_t dbg_flags;
rsv_client_id_t rnablk_client_id;
rsv_itn_id_t rnablk_itn_id;
int rna_com_retry_count = 6; //RNA_COM_RETRY_COUNT;
int rna_com_rnr_retry_count = 6; //RNA_COM_RNR_RETRY_COUNT;

int max_wr  = RNABLK_MAX_WR;
/* Total space for bounce buffer */
int rb_bounce_buffer_bytes = RNABLK_DEFAULT_BOUNCE_BUFFER_BYTES;
/* How much of the bounce buffer can be used for one IO */
int rb_bounce_segment_bytes = RNABLK_DEFAULT_MAX_BOUNCE_BUFFER_IO_SIZE;

int max_sge = RNA_MAX_SGE;

// Max sectors per request
uint64_t max_rs  = RNABLK_DEFAULT_MAX_REQUEST_SIZE;
int read_deref_secs = 40;
int write_deref_secs = 10;
int net_link_mask = 0;
int enable_creates = 1;
/*
 * default maximum number of MD query retries.
 * we back off our retry rate linearly, and reset the IOS timer on each retry.
 * so this does not directly translate to the number of seconds before we fail
 *
 * this is also adjustable via CFS
 */
int max_connection_failures = 100;
/* If true we will use the block elevator to manage incoming I/O */
int rnablk_use_req_queue = FALSE;
/* if true all incoming BIOs will go on a work queue */
int rnablk_queue_bios = FALSE;
/* if true, we will use write-only reference if first access of block is a write */
int rnablk_use_write_only = TRUE;
/* number of connections to use for each cache device */
int rnablk_per_device_connections = RNABLK_MAX_DEV_CONNS;
/* maximum number of outstanding I/Os */
int rnablk_io_queue_depth = 128;
atomic_t slow_workq_items;
//long rnablk_io_timeout = RNABLK_IO_TIMEOUT;     // in seconds
/* XXX TEMPorarily use really long timeout; ignore "slow" I/O, only timeout if really hung! */
long rnablk_io_timeout = (15*60);

/* set to TRUE via CFS to disable SCSI UNMAP command support */
int rnablk_scsi_unmap_disable = TRUE;

/*
 * set to TRUE via CFS to disable SCSI WRITE_SAME and WRITE_SAME_16
 * command support.
 */
int rnablk_scsi_write_same_disable = TRUE;

/* 
 * set to TRUE via CFS to only use RDMA connections for client-CS connections if
 * RDMA is configured.
 */
int rnablk_only_use_rdma_for_cs = TRUE;

rna_service_throttle_t  rnablk_ios_io_throttle;

#ifndef WINDOWS_KERNEL
LIST_HEAD( rnablk_dev_list );            // all configured devices
#endif 

#ifndef WINDOWS_KERNEL
struct cfm_info cfm_config_info;

// really rnablk_cache_status 
atomic_t g_conn_status;

// configfs holding area for cfm promotion list of cfms
struct sockaddr_in online_cfms[RNA_SERVICE_CFMS_MAX];
#endif
    
#ifndef WINDOWS_KERNEL
struct hd_geometry rna_geo;
#endif /*WINDOWS_KERNEL*/

char node_name[MAX_HOST_LEN];

atomic_t shutdown;
atomic_t delayed_work;

#ifdef WINDOWS_KERNEL
rna_service_work_queue_t *mt_workq;
rna_service_work_queue_t *ios_workq;
rna_service_work_queue_t *ordered_workq;
rna_service_work_queue_t *slow_workq;
rna_service_work_queue_t *bio_workq;
rna_service_work_queue_t *enforcer_workq;
#else
struct workqueue_struct *mt_workq;
struct workqueue_struct *ios_workq;
struct workqueue_struct *ordered_workq;
struct workqueue_struct *slow_workq;
struct workqueue_struct *bio_workq;
struct workqueue_struct *enforcer_workq;
#endif /*WINDOWS_KERNEL*/

struct rb_root cache_conn_root;
atomic_t ios_count;
atomic_t anon_drop_ref_requests;
struct rna_com *g_com;
struct com_attr g_com_attr;
struct rnablk_server_conn *g_md_conn;   // For throttling MD requests to rna_service
#ifndef WINDOWS_KERNEL
struct rna_service_ctx_s *rna_service_ctx = NULL;
#endif /*WINDOWS_KERNEL*/

/*
 * 'null_cachedev' is used as a "default" cache-device for cache_blk's
 * that have not yet been assigned a cache-device.  It also represents
 * cache_blk's that are uncached.
 *
 * On creation, each cache_blk is setup to reference 'null_cachedev', until
 * a successful CACHE_QUERY response from the cache server provides the true
 * cache-device information (if the block is cached), at which point the
 * cache_blk is updated to point to the real cache-device data structure.
 */
rnablk_cachedev_t null_cachedev;

/*
 * null_device (& null_blk) are used by any 'ios' that doesn't reference
 * an actual device.  Note these exist simply to simplify/stream-line
 * the code, so that every code path that cares can safely assume that
 * ios->dev and ios->blk are non-NULL.
 * Currently these are only needed for ios type RNABLK_DEREF_REQUEST_RESP.
 * All other existing types reference an actual device.  (And note for
 * any of those that don't reference a physical block, they are set to
 * reference the master_block.  Thus they are guaranteed to have both a
 * 'dev' and a 'blk').
 */
struct rnablk_device null_device;
struct cache_blk null_blk;

// lists and there locks

struct rna_rw_semaphore wfc_queue_lock;
#ifndef WINDOWS_KERNEL
struct rna_rw_semaphore rnablk_dev_list_lock;
#endif /*WINDOWS_KERNEL*/

#ifndef WINDOWS_KERNEL
DECLARE_COMPLETION( rna_service_connect_comp );
#endif /*WINDOWS_KERNEL*/

/* 
 * Reader lock protects against an rnablk_server_conn (stored in
 * ep->context) being freed by the disconnect handler.  Also protects
 * against changes in the cache_conn_root.  Fields inside
 * rnblk_server_conn are protected by their own spinlocks.
 *
 * Acquire this before waiting on dev->cache_blk_lock
 */
struct rna_rw_semaphore svr_conn_lock;

atomic_t rna_service_detached = {RNA_SERVICE_JOINED};

#ifndef WINDOWS_KERNEL
rna_service_mutex_t local_dev_mutex;
#else
KSPIN_LOCK local_dev_lock;
#endif /* WINDOWS_KERNEL */
struct list_head local_dev_list;

/* boolean indicating whether an ios timeout debug script is present */
boolean ios_timeout_script_active;

unsigned long rnablk_reference_target_age = 0;          // in milliseconds
unsigned long rnablk_write_reference_target_age = (5 * 60 * MSEC_PER_SEC);
                                                // 5 min. default - in msecs)

/*
 * the maximum number of outstanding proactive write reference
 * drops/downgrades in flight to a given CS at any one time
 */
unsigned int rnablk_write_reference_release_max_outstanding = 16;

#ifndef WINDOWS_KERNEL
struct rnablk_latency_stats latency_stats;
#endif /*WINDOWS_KERNEL*/

#ifndef WINDOWS_KERNEL
DECLARE_WAIT_QUEUE_HEAD(rnablk_cs_ping_wq);
long rnablk_cs_ping_interval;           // in jiffies
#endif


#ifdef TEST_OFFLINE_CACHE_DEVICE
cachedev_id_t test_cachedev_fail_ldma;
cachedev_id_t test_cachedev_fail_rdma;
cachedev_id_t test_cachedev_fail_cache_resp;
cachedev_id_t test_cachedev_fail_cache_ref_resp;
int test_dev_conn_disconnect;
#endif /* TEST_OFFLINE_CACHE_DEVICE */
