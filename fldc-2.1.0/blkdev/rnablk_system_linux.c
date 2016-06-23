/**
 * <rnablk_system_linux.c> - Dell Fluid Cache block driver
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


/*
 * here you will find OS-specific functions used to perform such actions as
 * loading module and creating/loading virtual devices.
 */
#include "rb.h"
#include "build.h"
#include "rnablk_globals.h"
#include "rnablk_util.h"
#include "rnablk_io_state.h"
#include "rnablk_cache.h"
#include "rnablk_callbacks.h"
#include "rnablk_data_transfer.h"
#include "rnablk_device.h"
#include "rna_log.h"
#include "rnablk_scsi.h"
#include "rnablk_comatose.h" // for rnablk_strategy rnablk_softirq_done
#include "rnablk_protocol.h"
#include "trace.h"

extern rna_service_mutex_t conn_cleanup_mutex;

static void rnablk_cache_blk_force_free(void *void_blk);
static char *rnablk_client_id_str;

struct rnablk_cache_info_member {
    struct list_head entry;
    char             data[0];
};

static struct rnablk_cache_info {
    struct kmem_cache *cache;
    mempool_t *pool;
    const char *name;
    size_t size;
    int mempool_size;
    int mempool_highwater;
    int mempool_hits;
    atomic64_t outstanding_mem;
    struct list_head member_list;
    spinlock_t member_list_lock;
    atomic_t warned;
    void (*rci_force_free)(void *);
} rnablk_cache_info[] = {
    {
        .cache = NULL,
        .pool  = NULL,
        .name  = "rnablk_cache_blk_cache",
        .size  = sizeof(struct rnablk_cache_info_member) +
                     sizeof( struct cache_blk ),
        .mempool_size = RNABLK_BLK_POOL_SIZE,
        .outstanding_mem = {0},
        .warned = {FALSE},
        .rci_force_free = rnablk_cache_blk_force_free,
    },
    {
        .cache = NULL,
        .pool  = NULL,
        .name  = "rnablk_work_cache",
        .size  = sizeof(struct rnablk_cache_info_member) +
                     sizeof( struct rnablk_work ),
        .mempool_size = RNABLK_WORK_POOL_SIZE,
        .outstanding_mem = {0},
        .warned = {FALSE},
    },
    {
        .cache = NULL,
        .pool  = NULL,
        .name  = "rnablk_cmd_cache",
        .size  = sizeof(struct rnablk_cache_info_member) +
                     sizeof( struct cache_cmd ),
        .mempool_size = RNABLK_CMD_POOL_SIZE,
        .outstanding_mem = {0},
        .warned = {FALSE},
    },
    {
        .cache = NULL,
        .pool  = NULL,
        .name  = "rnablk_create_delete_work_cache",
        .size  = sizeof(struct rnablk_cache_info_member) +
                     sizeof( struct rnablk_create_delete_work ),
        .mempool_size = RNABLK_WORK_POOL_SIZE,
        .outstanding_mem = {0},
        .warned = {FALSE},
    },
    {
        .cache = NULL,
        .pool  = NULL,
        .name  = "rnablk_osgl_cache",
        .size  = sizeof(struct rnablk_cache_info_member) +
                     sizeof (struct scatterlist[RNA_MAX_SGE]),
        .mempool_size = NR_CPUS,
        .outstanding_mem = {0},
        .warned = {FALSE},
    },
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
    {
        .cache = NULL,
        .pool  = NULL,
        .name  = "rnablk_dwork_cache",
        .size  = sizeof(struct rnablk_cache_info_member) +
                     sizeof( struct rnablk_dwork ),
        .mempool_size = RNABLK_WORK_POOL_SIZE,
        .outstanding_mem = {0},
        .warned = {FALSE},
    },
#endif
};

// XXX: need to come up with a good way to keep these automagically in sync
struct rnablk_cache_info * blk_cache_info = &rnablk_cache_info[0];
struct rnablk_cache_info * work_cache_info = &rnablk_cache_info[1];
struct rnablk_cache_info * cmd_cache_info = &rnablk_cache_info[2];
struct rnablk_cache_info * create_cache_info = &rnablk_cache_info[3];
struct rnablk_cache_info * osgl_cache_info = &rnablk_cache_info[4];
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
struct rnablk_cache_info * dwork_cache_info = &rnablk_cache_info[5];
#endif


static struct kmem_cache *work_cache;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
static struct kmem_cache *dwork_cache;
#endif
static struct kmem_cache *sgl_cache;
static struct kmem_cache *cache_blk_cache;
static struct kmem_cache *ios_cache;
static struct kmem_cache *cmd_cache;
static struct kmem_cache *create_work_cache;

static int rnablk_init_kmem_caches(void);
static void rnablk_free_kmem_caches(void);
static int rnablk_make_request(struct request_queue *q,
                               struct bio           *bio);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
static int rnablk_ioctl( struct inode *inode,struct file *file,
                         unsigned int cmd,unsigned long arg )
#else
static int rnablk_ioctl(struct block_device *bdev, fmode_t mode,
                        unsigned int cmd, unsigned long arg );
#endif

static rna_inline void rnablk_mempool_free_nolock (struct rnablk_cache_info_member * member,
                                                   struct rnablk_cache_info        * cache_info);
static int
rnablk_bio_calculate_n_ios(struct rnablk_device *dev,
                           struct request_queue *q,
                           struct bio           *bio,
                           boolean              cluster,
                           boolean              need_extra_sg);

static void
rnablk_io_map_sg(struct rnablk_device *dev,
                  struct request_queue *q,
                  struct bio *bio,
                  void *ioreq,
                  void *ioreq_private,
                  uint16_t ioreq_type,
                  atomic_t *ioreq_refcount,
                  boolean cluster,
                  boolean need_extra_sg,
                  int n_ios,
                  struct io_state **pp_ios);

#ifdef QUEUE_FLAG_CLUSTER
#define blk_queue_cluster(q)    test_bit(QUEUE_FLAG_CLUSTER, &(q)->queue_flags);
#endif

#define RNABLK_CTL_REGISTRATION     ((void *)0xdeadbeef)

static int
rnablk_ctl_open(struct inode *inode, struct file *filp)
{
    filp->private_data = NULL;
    try_module_get(THIS_MODULE);

    return 0;
}

static int
rnablk_ctl_release(struct inode *inode, struct file *filp)
{
    struct rnablk_device *dev;

    if (NULL != filp->private_data) {
        dev = filp->private_data;
        filp->private_data = NULL;
        RNABLK_BUG_ON(RNABLK_DEVICE_MAGIC != dev->magic,
                      "%p not an rnablk_device? filp=%p\n", dev, filp);
        if (atomic_dec_and_test(&dev->rbd_ext_rsvacc_mgrs)) {
            rna_printk(KERN_NOTICE, "resuming control of RSV "
                       "access mgmt for device [%s]\n", dev->name);
        }
        rnablk_dev_release(dev);
    } 

    module_put(THIS_MODULE);
    return 0;
}

static long
rnablk_ctl_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct rnablk_device *dev;
    struct rnablk_ioc_tgt_register iocbuf;
    char *p, *path = iocbuf.ritr_path;
    long ret = 0; 

    switch (cmd) {
    case RNABLK_IOC_CTL_REGISTER:
        if (copy_from_user(&iocbuf, (void __user *)arg, sizeof(iocbuf))) {
            ret = -EFAULT;
            break;
        }
        path[sizeof(iocbuf.ritr_path) - 1] = '\0';

        for (p = &path[strlen(path)-1]; p >= path && *p != '/'; p--) {
            continue;
        }
        p++;
        if (NULL == (dev = rnablk_find_device(p))) {
            ret = -ENODEV;
            break;
        }
        filp->private_data = dev;
        if (atomic_inc_return(&dev->rbd_ext_rsvacc_mgrs) == 1) {
            rna_printk(KERN_NOTICE, "ceding control of RSV "
                       "access mgmt for device [%s]\n", dev->name);
        }
        break;

    default:
        ret = -ENOTTY;
        break;
    }

    return ret;
}

static const struct file_operations rnablk_ctl_fops = {
    .owner      = THIS_MODULE,
    .open       = rnablk_ctl_open,
    .unlocked_ioctl = rnablk_ctl_ioctl,
    .release    = rnablk_ctl_release,
};

static struct miscdevice fldc_ctl_device = {
    MISC_DYNAMIC_MINOR,
    "fldc_ctl",
    &rnablk_ctl_fops
};


/*
 * This is the function that the Linux kernel will call when the module
 * is loaded.
 */
static int __init
rnablk_init(void)
{
    struct rna_dev_attr attr;
    struct task_struct *kthread;
    int len;
    ENTER;

    rna_printk(KERN_NOTICE,
               "Fluid Cache Block Device Driver revision %d\n",
               BUILD );

    if (!rsv_str_to_client_id(&rnablk_client_id, rnablk_client_id_str)) {
        rna_printk(KERN_WARNING, "  Specified rnablk_client_id <%s> too big "
                   "or has bad format\n", rnablk_client_id_str);
    }

    rna_printk(KERN_NOTICE, "ClientID = <%s>\n",
               rsv_client_id_get_string(&rnablk_client_id));

    rsv_make_itn_id(&rnablk_itn_id, &rnablk_client_id, &NULL_RSV_INITIATOR);

    // this has to be set high enough so that it doesn't get confused
    // with the cookie values in unsolicited msgs from the cfm
    // XXX: this seems arbitrary/dangerous
    atomic_set(&ios_rb_id, 100);

    atomic_set( &shutdown,0 );
    atomic_set( &delayed_work,0 );    
    atomic_set( &ios_count,0 );
    atomic_set( &anon_drop_ref_requests,0 );
    atomic_set( &g_conn_status, RNABLK_CACHE_OFFLINE );
    atomic_set( &slow_workq_items, 0 );
    memset(&cfm_config_info, 0, sizeof(cfm_config_info));
    init_completion(&rna_service_connect_comp);
    rna_service_mutex_init(&local_dev_mutex);
    INIT_LIST_HEAD(&local_dev_list);
    rna_init_rwsem(&wfc_queue_lock);
    rna_init_rwsem(&rnablk_dev_list_lock);
    rna_init_rwsem(&svr_conn_lock);
    
    rnablk_latency_stats_init();

    rna_service_mutex_init(&conn_cleanup_mutex);
    rnablk_svcctl_init();
    rnablk_init_null_structs();

    // set up netlink socket 
    init_log();

    ret = rnablk_init_kmem_caches();
    if( ret )
        GOTO( out,-ENOMEM );

    if (0 != (ret = rnablk_create_ios_mempools())) {
        GOTOV(err);
    }

    // For low-delay work items on all devices
    if( (mt_workq = rna_create_workqueue( "fldcblk_wq" )) == NULL )
        GOTO( err1,-ENOMEM );

    // For low-delay order-sensitive work items (receives) on all devices
    if( (ordered_workq = rna_create_singlethread_workqueue( "fldcblk_ord_wq" )) == NULL )
        GOTO( err2,-ENOMEM );

    // for high-delay work items on all devices
    if( (slow_workq = rna_create_singlethread_workqueue( "fldcblk_slow_wq" )) == NULL )
        GOTO( err3,-ENOMEM );

    // For low-delay order-sensitive work items (incoming BIOS) on all devices
    if( (bio_workq = rna_create_singlethread_workqueue( "fldcblk_bio_wq" )) == NULL )
        GOTO( err4,-ENOMEM );

    // For low-delay order-sensitive work items (incoming BIOS) on all devices
    if ((enforcer_workq = rna_create_singlethread_workqueue("fldcblk_enf_wq"))
                                                            == NULL ) {
        GOTO(err5, -ENOMEM);
    }

    rnablk_com_init(&g_com, &g_com_attr);
    if (NULL == g_com) {
        GOTO (err6, -EINVAL);
    }


    if( (ret = rnablk_configfs_init()) )
        GOTO( err7,ret );

    // For work items that allocate ios's and thus may block
    if ((ios_workq = rna_create_workqueue("fldcblk_io_wq")) == NULL) {
        GOTO(err8, -ENOMEM);
    }

    if (rnablk_reference_target_age || rnablk_write_reference_target_age) {
        rnablk_enable_enforcer();
    }

    if (misc_register(&fldc_ctl_device)) {
        rna_printk(KERN_WARNING, "Unable to register fldc_ctl device\n");
    }

    rnablk_cs_ping_interval = msecs_to_jiffies(CS_PING_INTERVAL);
    kthread = kthread_run(rnablk_cs_ping_worker, NULL, "fldc_ping");
    if (IS_ERR(kthread)) {
        rna_printk(KERN_WARNING, "Unable to create CS ping thread\n");
    }

    goto out;

/*
 * If additional failure case added after initializing ios_workq, use
 * this to clean up on err.
err9:
    rna_flush_workqueue(ios_workq);
    rna_destroy_workqueue(ios_workq);
*/
err8:
    rnablk_configfs_cleanup();
err7:
    com_exit( g_com );
err6:
    rna_flush_workqueue(enforcer_workq);
    rna_destroy_workqueue(enforcer_workq);
err5:
    rna_flush_workqueue( bio_workq );
    rna_destroy_workqueue( bio_workq );
err4:
    rna_flush_workqueue( slow_workq );
    rna_destroy_workqueue( slow_workq );
err3:
    rna_flush_workqueue( ordered_workq );
    rna_destroy_workqueue( ordered_workq );
err2:
    rna_flush_workqueue( mt_workq );
    rna_destroy_workqueue( mt_workq );
err1:
    rnablk_destroy_ios_mempools();
err:
    rnablk_free_kmem_caches();
    cleanup_log();
out:
    EXIT;
}

/*
 * This is the function that the Linux kernel will call when the module
 * is unloaded.
 */
static void __exit
rnablk_exit(void)
{
    struct rnablk_server_conn *conn;
    struct list_head *pos,*tmp;
    unsigned char oldirql;

    ENTER;

    // signal driver wide shutdown
    atomic_set( &shutdown,1 );
    atomic_set( &g_conn_status, RNABLK_CACHE_OFFLINE );

    // wait for delayed work that won't be noticed
    // by flush_workqueue because its not currently queued
    if (atomic_read( &delayed_work )) {
        rna_printk(KERN_ERR, "Waiting for delayed work queue to drain\n");
        while( atomic_read( &delayed_work ) ) {
            msleep_interruptible( 100 );
        }
        rna_printk(KERN_ERR, "Delayed workqueue drained\n");
    }

    // wait for device destruction to complete
    rna_printk(KERN_ERR, "Waiting for block device destruction\n");
    rna_down_read( &rnablk_dev_list_lock, &oldirql );
    while( !list_empty( &rnablk_dev_list )) {
        rna_up_read( &rnablk_dev_list_lock, oldirql );
        //wait_for_completion_interruptible( &dev_destroy_comp );
        //init_completion( &dev_destroy_comp );
        msleep_interruptible(200);
        rna_down_read( &rnablk_dev_list_lock, &oldirql );
    }
    rna_up_read( &rnablk_dev_list_lock, oldirql );

    // relase netlink socket
    cleanup_log();

    rna_printk(KERN_INFO, "Removing configfs files\n");
    rnablk_configfs_cleanup();

    if (NULL != rna_service_ctx) {
        rna_printk(KERN_INFO, "Waiting for service context destroy\n");
        (void)rna_service_ctx_destroy(&rna_service_ctx);
    }

    if (NULL != g_com) {
        rna_printk(KERN_NOTICE, "Waiting for com instance exit\n");
        com_exit( g_com );
    }

    wake_up_interruptible(&rnablk_cs_ping_wq);

    rna_printk(KERN_ERR, "Flushing and destroying slow work queue\n");
    complete_all(&rna_service_connect_comp);
    rna_flush_workqueue( slow_workq );
    rna_destroy_workqueue( slow_workq );

    rna_printk(KERN_ERR, "Flushing and destroying work queue\n");
    rna_flush_workqueue( mt_workq );
    rna_destroy_workqueue( mt_workq );

    rna_printk(KERN_ERR, "Flushing and destroying ios work queue\n");
    rna_flush_workqueue(ios_workq);
    rna_destroy_workqueue(ios_workq);

    rna_printk(KERN_ERR, "Flushing and destroying ordered work queue\n");
    rna_flush_workqueue( ordered_workq );
    rna_destroy_workqueue( ordered_workq );

    rna_printk(KERN_ERR, "Flushing and destroying bio work queue\n");
    rna_flush_workqueue( bio_workq );
    rna_destroy_workqueue( bio_workq );

    rna_printk(KERN_ERR, "Flushing and destroying enforcer work queue\n");
    rna_flush_workqueue(enforcer_workq);
    rna_destroy_workqueue(enforcer_workq);

    rnablk_free_server_conns();

    rna_printk(KERN_ERR, "Closing local devices\n");
    rnablk_free_local_devs();

    rnablk_destroy_ios_mempools();

    rna_printk(KERN_ERR, "Freeing kmem caches\n");
    rnablk_free_kmem_caches();

    if (misc_deregister(&fldc_ctl_device) < 0) {
        rna_printk(KERN_WARNING, "Unable to deregister fldc_ctl device\n");
    }

    rna_printk(KERN_NOTICE,
               "Fluid Cache Block Device Driver exiting\n" );

    rna_destroy_rwsem(&wfc_queue_lock);
    rna_destroy_rwsem(&rnablk_dev_list_lock);
    rna_destroy_rwsem(&svr_conn_lock);

    EXITV;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
static int rnablk_open( struct inode *inode,struct file *file )
{
    struct rnablk_device *dev;
    ENTER;

    dev = (struct rnablk_device *)inode->i_bdev->bd_disk->private_data;
    if (dev_new_openers_are_enabled(dev) && dev_openers_do_open(dev)) {
        try_module_get(THIS_MODULE);
    } else {
        /* can't open if the device is being torn down */
        rna_printk(KERN_WARNING,
                  "failing open for task pid [%d], command [%s]\n",
                   current->pid,
                   current->comm);
        ret = -ENODEV;
    }

    EXIT;
}

static int rnablk_release( struct inode *inode,struct file *file )
{
    struct rnablk_device *dev;
    ENTER;

    dev = (struct rnablk_device *)inode->i_bdev->bd_disk->private_data;
    RNABLK_BUG_ON(!dev_openers_is_open(dev),
                  "device [%s] released when not open\n", dev->name);
    if (0 == dev_openers_do_close(dev)) {
        if (dev_is_persistent(dev) && dev_quiesce_on_release(dev)) {
            rna_printk(KERN_NOTICE, "Dropping references for device [%s]\n", dev->name);
            rnablk_quiesce(dev);
        }
    }

    module_put( THIS_MODULE );

    EXIT;
}
#else // New block device api
static int rnablk_open(struct block_device *bdev, fmode_t mode)
{
    struct rnablk_device *dev;
    ENTER;

    dev = (struct rnablk_device *)bdev->bd_disk->private_data;
    if (dev_new_openers_are_enabled(dev) && (dev_openers_do_open(dev))) {
        try_module_get(THIS_MODULE);
    } else {
        /* can't open if the device is being torn down */
        rna_printk(KERN_WARNING,
                   "failing open for task pid [%d], command [%s]\n",
                   current->pid,
                   current->comm);
        ret = -ENODEV;
    }

    EXIT;
}

static int rnablk_release(struct gendisk *disk, fmode_t mode)
{
    struct rnablk_device *dev;
    ENTER;

    dev = (struct rnablk_device *)disk->private_data;
    RNABLK_BUG_ON(!dev_openers_is_open(dev),
                  "device [%s] released when not open\n", dev->name);
    if (0 == dev_openers_do_close(dev)) {
        if (dev_is_persistent(dev) && dev_quiesce_on_release(dev)) {
            int saved_dbg_flags = dbg_flags;

            rna_printk(KERN_NOTICE, "Finishing IO for device [%s]\n", dev->name);
            rnablk_quiesce(dev);
            dbg_flags=saved_dbg_flags;
        }
    }

    module_put( THIS_MODULE );

    EXIT;
}
#endif

static int
rnablk_getgeo(struct block_device *bdev, struct hd_geometry *geo)
{
    struct gendisk *disk;
    ENTER;

    disk = bdev->bd_disk;
    // These values result in better page alignment
    geo->heads     = 64;
    geo->sectors   = 32;
    geo->cylinders = get_capacity(disk) / (geo->sectors * geo->heads);
    geo->start     = get_start_sect(bdev);

    EXIT;
}


static struct block_device_operations bdops = {
    .open     = rnablk_open,
    .release  = rnablk_release,
    .ioctl    = rnablk_ioctl,
    .getgeo   = rnablk_getgeo,
};

#if ((defined(RHEL_RELEASE_VERSION) && \
      (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32))) || \
     (!defined(RHEL_RELEASE_VERSION) && \
      (LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0))))
/* For RHEL5.8 and OEL6.1 and OEL6.2 */
static inline void
blk_queue_max_segments(struct request_queue *q, unsigned short max_segments)
{
    blk_queue_max_phys_segments(q, max_segments);
    blk_queue_max_hw_segments(q, max_segments);
}
#endif


/**
 * Register a block device with the Linux block layer
 *
 * This is queued to be done when the masterblock query/lock for the
 * device's cache file completes, and we know the cache block size.
 *
 * This function was initially called directly by
 * rnablk_process_cache_master_block_response().  But with the addition
 * of support for partitions, the add_disk() function call below needs to
 * read the disk to fill out the partition table.  These reads
 * could dead lock when the cache master block response
 * handler was still in progress.  By moving this to a deferred work
 * context, the master block responses handler is allowed to complete,
 * and these reads complete without deadlock.
 */
static void
rnablk_register_block_device( struct rnablk_device *dev )
{
    int namelen = sizeof(dev->disk->disk_name);
    char lbuf[namelen];
    uint64_t cap;
    ENTER;

    BUG_ON(NULL == dev);

    if (atomic_cmpxchg(&dev->registered_with_os, FALSE, TRUE) != FALSE) {
        rna_printk(KERN_ERR,
                   "[%s] already registered\n",
                   dev->name);
        goto out;
    }

    /* Make sure we have enough room for the string. */
    BUG_ON(NAME_MAX < namelen);
    snprintf(lbuf,
             namelen,
             dev->name);
    dev->name[namelen-1] = '\0';

    /* The name we pass here shows up in /proc/devices. */
    dev->major = register_blkdev( 0, RNABLK_SHORT_DEV_NAME );
    if( dev->major < 0 )
        GOTO( err,dev->major );

    if (dev_use_req_queue(dev)) {
        rna_printk(KERN_ERR,
                   "creating device [%s] with request queue\n",
                   dev->name);
        dev->q = blk_init_queue( rnablk_strategy,NULL );
    } else {
        rna_printk(KERN_ERR,
                   "creating device [%s] without request queue\n",
                   dev->name);
        dev->q = blk_init_queue(rnablk_strategy, NULL);
        if (NULL != dev->q) {
            blk_queue_make_request(dev->q, rnablk_make_request);
        }
    }
    if( dev->q == NULL )
        GOTO( err,-ENOMEM );

    blk_queue_max_segments(dev->q, max_sge);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
    blk_queue_hardsect_size( dev->q,RNABLK_SECTOR_SIZE );
#else
    blk_queue_logical_block_size(dev->q, RNABLK_SECTOR_SIZE);
    blk_queue_physical_block_size(dev->q, RNABLK_SECTOR_SIZE);
#endif

    blk_queue_softirq_done( dev->q,rnablk_softirq_done );
    blk_queue_prep_rq( dev->q,rnablk_prep_fn );

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 28)
    /* we don't have a spinning spindle, which affects elevator strategy */
    set_bit(QUEUE_FLAG_NONROT, &dev->q->queue_flags);
#endif

    dev->q->queuedata = dev;

    /* Max sectors limited by configured (global) max_rs, and max disk
     * blocks per cache block.  This allows the max_rs setting to
     * limit the max RDMA size (to avoid congestion on IB), and
     * prevents block requests from spanning many cache blocks.
     */
    rna_printk(KERN_INFO,
               "register max_io bytes max_rs %"PRIu64" "
               "cache_blk_size %"PRIu64" "
               "rb_bounce_buffer_bytes %d "
               "rb_bounce_segment_bytes %d "
               "MAX_RDMA_VIA_SEND_SIZE %d "
               "DEFAULT_RDMA_SENDBUF_PAYLOAD %d\n",
               max_rs,
               dev->cache_blk_size,
               rb_bounce_buffer_bytes,
               rb_bounce_segment_bytes,
               MAX_RDMA_VIA_SEND_SIZE,
               DEFAULT_RDMA_SENDBUF_PAYLOAD);

#ifndef _DISABLE_IB_
    if (0 == rb_bounce_buffer_bytes) {
        rnablk_set_max_io(dev, MAX_RDMA_VIA_SEND_SIZE);
    } else {
        /* The original bounce buffer implementation allowed for
         * a transfer to use multiple bounce buffer segments for
         * a transfer.  we coud use dev->cache_blk_size for the
         * max_io, and transfer size would be limmited by the
         * number of scatter/gather entries.
         *
         * But there were unexplained problems with
         * performance with large rdma tranfers.  So now we limit
         * tranfers to just one bounce buffer segment.
         */
        rnablk_set_max_io(dev, min(max_rs, (uint64_t)rb_bounce_segment_bytes));
    }
#else
    rnablk_set_max_io(dev, min(max_rs, dev->cache_blk_size));
#endif

    dev->disk = alloc_disk(256);
    if( dev->disk == NULL )
        GOTO( err,-ENOMEM );

    dev->disk->major        = dev->major;
    dev->disk->first_minor  = 0;
    dev->disk->fops         = &bdops;
    dev->disk->queue        = dev->q;
    dev->disk->private_data = dev;

    /* This name shows up in /dev and /proc/partitions. */
    strlcpy(dev->disk->disk_name, lbuf, namelen);
    cap = dev->device_cap;
    set_capacity(dev->disk, (cap / RNABLK_SECTOR_SIZE ));
    BUG_ON(0 != (dev->device_cap % RNABLK_SECTOR_SIZE));
    add_disk( dev->disk );

out:
    EXITV;

err:
    rna_printk(KERN_ERR, "error creating block device ret=%d\n", ret);
    rnablk_unregister_block_device(dev);
    goto out;
}

/*
 * rnablk_deferred_register_block_device() acquired a reference
 * on the block device structure so the structure could not go away
 * while waiting for this work function to be scheduled.  So this code
 * needs to release that reference once it's finished with the dev.
 */
static void
rnablk_register_block_device_wf(rnablk_workq_cb_arg_t arg)
{
    struct work_struct *work = (struct work_struct *)arg;
    struct rnablk_work *w = container_of(work, struct rnablk_work, work);
    struct rnablk_register_block_device_wf_data *wd =
            &w->data.rwd_rnablk_register_block_device_wf;
    ENTER;

    rnablk_register_block_device(wd->dev);
    rnablk_dev_release(wd->dev);
    rnablk_mempool_free(w, work_cache_info);

    EXITV;
}

/*
 * Register the block device in a work queue context, so it will
 * be done AFTER this function's caller is complete.
 *
 * Acquire a reference to the rnablk_device so it can't be freed while
 * waiting for the work function to be scheduled.  The work function
 * will release this reference.
 */
void
rnablk_deferred_register_block_device( struct rnablk_device *dev )
{
    struct rnablk_work *w;
    struct rnablk_register_block_device_wf_data *wd;
    ENTER;


    if((w = rnablk_mempool_alloc(work_cache_info)) == NULL ) {
        rna_printk(KERN_ERR,
                    "block device %s register ranblk_work alloc failed\n",
                     dev->name);
        GOTO (out, -ENOMEM);
    }


    RNABLK_INIT_RNABLK_WORK(w, wd, rnablk_register_block_device_wf);
    wd->dev = dev;
    rnablk_dev_acquire(dev);
    rna_queue_work(slow_workq, &w->work);

out:
    EXITV;
}

/**
 * Unregister device with Linux block layer.
 */
int rnablk_unregister_block_device( struct rnablk_device *dev )
{
    ENTER;

    if (TRUE == atomic_read(&dev->registered_with_os)) {
        if( dev->disk != NULL )
            del_gendisk( dev->disk );
        if( dev->q != NULL )
            blk_cleanup_queue( dev->q );
        if( dev->major >= 0 ) {
            unregister_blkdev(dev->major, RNABLK_SHORT_DEV_NAME);
        }
    }

    EXIT;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
static int
rnablk_ioctl(struct inode *inode, struct file *file,
             unsigned int cmd, unsigned long arg)
#else
static int
rnablk_ioctl(struct block_device *bdev, fmode_t mode,
             unsigned int cmd, unsigned long arg)
#endif
{
    struct hd_geometry rna_geo;
    struct rnablk_device *dev = NULL;
    struct rnablk_device *dev_ptr;
    struct sg_io_hdr hdr;
    union {
        struct rnablk_ioc_scsi_event event;
        struct rnablk_ioc_tgt_hdr tgt_hdr;
        struct rnablk_ioc_rsv_ack rsv_ack;
    } u;
    rsv_itn_id_t itn_id, *p_itn_id = &rnablk_itn_id;
    int reset;
    ENTER;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
    dev_ptr = (struct rnablk_device *)inode->i_bdev->bd_disk->private_data;
#else
    dev_ptr = (struct rnablk_device *)bdev->bd_disk->private_data;
#endif


    switch( cmd ) {
        case SG_SCSI_RESET:
            ret = -EFAULT;
            if (get_user(reset, (int __user*)arg))
                break;

            ret = -EINVAL;
            if (SG_SCSI_RESET_DEVICE != reset) {
                if (SG_SCSI_RESET_NOTHING == reset)
                    ret =0;
                break;
            }

            dev = rnablk_find_device_by_addr(dev_ptr);
            if (NULL == dev) {
                rna_printk(KERN_ERR,
                           "dev ptr [%p] no longer valid\n",
                           dev_ptr);
                ret = -ENOTTY;
            } else {
                rna_printk(KERN_INFO,
                           "sg_reset request for dev [%s]\n",
                           dev->name);
                ret = rnablk_sg_reset(dev);
            }
            break;

        case RNABLK_IOC_TGT_SG_IO:
            ret = -EFAULT;
            if (copy_from_user(&u.tgt_hdr, (void __user *)arg,
                               sizeof(u.tgt_hdr))) {
                break;
            }

            rsv_make_itn_id(&itn_id, &rnablk_client_id, &u.tgt_hdr.rith_ini);
            p_itn_id = &itn_id;

            arg = (unsigned long)u.tgt_hdr.rith_sg_hdr;
            /* fall-through */

        case SG_IO:
            ret = -EFAULT;
            if (copy_from_user(&hdr, (void __user *)arg, sizeof(hdr)))
                break;

            dev = rnablk_find_device_by_addr(dev_ptr);
            if (NULL == dev) {
                rna_printk(KERN_ERR,
                           "dev ptr [%p] no longer valid\n",
                           dev_ptr);
                ret = -ENOTTY;
            } else {
                rna_printk(KERN_INFO,
                           "sg_io request for dev [%s]\n",
                           dev->name);
                ret = rnablk_sg_io(dev, p_itn_id, &hdr, mode);
            }

            if (0 == ret) {
                if (copy_to_user((void __user *)arg, &hdr, sizeof(hdr))) {
                    ret = -EFAULT;
                }
            }

            break;

        case RNABLK_IOCTL_EXTENDED_COPY:
        case RNABLK_IOCTL_RECEIVE_COPY_RESULTS:
            dev = rnablk_find_device_by_addr(dev_ptr);
            if (NULL == dev) {
                rna_printk(KERN_ERR,
                           "dev ptr [%p] no longer valid\n",
                           dev_ptr);
                ret = -ENOTTY;
            } else {
                rna_printk(KERN_INFO,
                           "special request %d for dev [%s]\n", cmd,
                           dev->name);
                ret = rnablk_generic_special_request(dev, cmd);
            }
            break;

        case RNABLK_IOC_SCSI_EVENT_WAIT:
            if (copy_from_user(&u.event, (void __user *)arg, sizeof(u.event))) {
                ret = -EFAULT;
                break;
            }

            dev = rnablk_find_device_by_addr(dev_ptr);
            if (NULL == dev) {
                rna_printk(KERN_ERR,
                           "dev ptr [%p] no longer valid\n",
                           dev_ptr);
                ret = -ENOTTY;
            } else {
                rna_printk(KERN_INFO,
                           "RNABLK_IOC_SCSI_EVENT_WAIT request for dev [%s]\n",
                           dev->name);
                ret = rnablk_wait_for_scsi_event(dev, &u.event);
                if (0 == ret) {
                    if (copy_to_user((void __user *)arg, &u.event,
                                     sizeof(u.event))) {
                        ret = -EFAULT;
                    }
                }
            }
            break;

        case RNABLK_IOC_SCSI_RSV_ACCESS_ACK:
            if (copy_from_user(&u.rsv_ack, (void __user *)arg,
                               sizeof(u.rsv_ack))) {
                ret = -EFAULT;
                break;
            }
            dev = rnablk_find_device_by_addr(dev_ptr);
            if (NULL == dev) {
                rna_printk(KERN_ERR, "dev ptr [%p] no longer valid\n", dev_ptr);
                ret = -ENOTTY;
            } else {
                rna_printk(KERN_RSV, "RNABLK_IOC_SCSI_RSV_ACCESS_ACK request "
                           "for dev [%s]\n", dev->name);
                rnablk_rsv_access_process_ack(dev, u.rsv_ack.rira_phase,
                                              u.rsv_ack.rira_gen, TRUE);
            }
            break;

        default:
            rna_printk(KERN_INFO, "ignored cmd [%u/0x%x] arg [%lu/0x%lx]\n",
                       cmd, cmd, arg, arg);
            ret = -ENOTTY;
            break;


        /* Silently ignored ioctls */
        case BLKFLSBUF:
        /* CDROM_GET_CAPABILITY */
        case 0x5331:
            ret = -ENOTTY;
            break;
    }

    if (NULL != dev) {
        rnablk_dev_release(dev);
    }
    EXIT;
}

static void
rnablk_cache_info_free(struct rnablk_cache_info * cache_info)
{
    struct rnablk_cache_info_member *member = NULL;
    struct list_head                *pos, *next;
    unsigned long                    flags;

    BUG_ON(NULL == cache_info);
    BUG_ON(list_empty(&cache_info->member_list));

    spin_lock_irqsave(&cache_info->member_list_lock, flags);
    list_for_each_safe(pos, next, &cache_info->member_list) {
        member = list_entry(pos, struct rnablk_cache_info_member, entry);
        if (cache_info->rci_force_free) {
            cache_info->rci_force_free(member->data);
        }
        rnablk_mempool_free_nolock(member, cache_info);
    }
    spin_unlock_irqrestore(&cache_info->member_list_lock, flags);
    BUG_ON(0 != atomic64_read(&cache_info->outstanding_mem));
}

static void rnablk_free_kmem_caches( void )
{
    struct rnablk_cache_info *info;
    int i;
    ENTER;

    for( i=0; i < ARRAY_SIZE( rnablk_cache_info ); i++ ) {
        info = &rnablk_cache_info[i];

        while (0 != atomic64_read(&info->outstanding_mem)) {
            rna_printk(KERN_ERR,
                       "freeing [%lu] outstanding bytes [%lu] units in cache [%s]\n",
                       atomic64_read(&info->outstanding_mem),
                       (atomic64_read(&info->outstanding_mem) / info->size),
                       info->name);
            rnablk_cache_info_free(info);
        }

        if( info->pool ) {
            mempool_destroy( info->pool );
            info->pool = NULL;
        }

        if( info->cache) {
            kmem_cache_destroy( info->cache );
            info->cache = NULL;
        }
    }

    EXITV;
}

/* Wrapper callbacks for mempool allocation routines. 
 * Adds logging to the generic callbacks. */
static void *mempool_alloc_log_slab(gfp_t gfp_mask, void *pool_data)
{
    struct rnablk_cache_info *info = (typeof(info)) pool_data;
    mempool_t *pool = info->pool;
    void *elem;
    int fill;

    elem = mempool_alloc_slab(gfp_mask, (void*)info->cache);

    if (unlikely (NULL == elem)) {
        if (0 == info->mempool_hits) {
            rna_printk(KERN_WARNING, "Allocation failed for cache [%s], "
                       "falling back on mempool ([%d] reserve entries). "
                       "System memory is very low.", info->name, pool->min_nr);
        }
        info->mempool_hits++;

        /* +1 because we haven't done the allocation yet,
         * but we will. */
        fill = (pool->min_nr - pool->curr_nr) + 1;

        if (fill > info->mempool_highwater) {
            info->mempool_highwater = fill;
            if (0 == fill % 32) {
                rna_printk(KERN_INFO, "Falling back on pool [%s], [%d] of [%d] in use.\n",
                           info->name,
                           fill,
                           pool->min_nr);
            }
        }
    }

    return elem;
}

/* This isn't a very useful logging point - we get called for items that are
 * freed back to the system, but not for items that go back in the pool. */
static void mempool_free_log_slab(void *element, void *pool_data)
{
    struct rnablk_cache_info *info = (typeof(info)) pool_data;
    return mempool_free_slab(element, (void*)(info->cache));
}

/* Create kmem caches, and optionally back them up with mempools, so we can
 * keep running when there is no more free memory. */
static int rnablk_init_kmem_caches( void )
{
    struct rnablk_cache_info *info;
    int i;
    ENTER;

    for( i=0; i < ARRAY_SIZE( rnablk_cache_info ); i++ ) {
        info = &rnablk_cache_info[i];
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
        info->cache = kmem_cache_create( info->name,info->size,8,0,NULL,NULL );
#else
        info->cache = kmem_cache_create(info->name, info->size, 8, 0, NULL);
#endif
        if( info->cache == NULL ) {
            rnablk_free_kmem_caches();
            ret = -ENOMEM;
            break;
        }

        info->pool = mempool_create(info->mempool_size,
                                    mempool_alloc_log_slab,
                                    mempool_free_log_slab, info);
        if (info->pool == NULL) {
            rna_printk(KERN_ERR, "failed to create mempool\n");
            rnablk_free_kmem_caches();
            ret = -ENOMEM;
            break;
        }


        info->mempool_hits = 0;
        info->mempool_highwater = 0;

        INIT_LIST_HEAD(&info->member_list);
        spin_lock_init(&info->member_list_lock);
    }

    EXIT;
}



static rna_noinline int
rnablk_bio_map_sg(struct rnablk_device *dev,
                  struct request_queue *q,
                  struct bio           *bio,
                  void                 *bio_private,
                  struct io_state     **pp_ios)
{
    int n_ios;
    boolean is_write = (WRITE == bio_data_dir(bio));
    int ret;

    n_ios = rnablk_bio_calculate_n_ios(dev, q, bio, TRUE, FALSE);
    if (unlikely(n_ios <= 0)) {
        rna_printk(KERN_ERR, "bio [%p] is too big or zero size(?) ret=%d\n",
                   bio, n_ios);
        return n_ios;
    }

    ret = rnablk_alloc_ios_io(dev, n_ios, pp_ios, bio, IOREQ_TYPE_BIO,
                              is_write ? RSV_ACC_READWRITE : RSV_ACC_READONLY);
    if (0 != ret) {
       return ret;
    }
    
    rnablk_io_map_sg(dev, q, bio, bio, bio_private,
                     is_write ? IOS_IOTYPE_WRITE : IOS_IOTYPE_READ,
                     (atomic_t *)&bio->bi_private,
                     TRUE, FALSE, n_ios, pp_ios);
#ifdef RNABLK_DEBUG_SG
    {
    struct io_state *ios;
    struct scatterlist *sg;
    int i, j;
    for (i = 0; i < n_ios; i++) {
        ios = pp_ios[i];
        for (sg = ios->sgl, j = 0 ; j < ios->nsgl; sg++, j++) {
            RNABLK_BUG_ON(rna_sg_page(sg) == NULL, "sg_page: ppios=%p ios=%p "
                          "sg=%p i=%d j=%d\n", pp_ios, ios, sg, i, j)
            RNABLK_BUG_ON(sg->length == 0, "sg length: ppios=%p ios=%p "
                          "sg=%p i=%d j=%d\n", pp_ios, ios, sg, i, j)
            RNABLK_BUG_ON(sg_is_chain(sg), "sg chain: ppios=%p ios=%p "
                          "sg=%p i=%d j=%d\n", pp_ios, ios, sg, i, j)
            RNABLK_BUG_ON(sg_is_last(sg) && j != ios->nsgl - 1,
                          "sg shouldn't be last: ppios=%p ios=%p "
                          "sg=%p i=%d j=%d\n", pp_ios, ios, sg, i, j)
            RNABLK_BUG_ON(!sg_is_last(sg) && j == ios->nsgl - 1,
                          "sg should be last: ppios=%p ios=%p "
                          "sg=%p i=%d j=%d\n", pp_ios, ios, sg, i, j)
        }
    }
    }
#endif /* RNABLK_DEBUG_SG */
    return n_ios;
}

/*
 * XXXgus: we should split this work queue out to be per-device so we
 * can halt processing when the device stop flag is set
 */
static void
rnablk_process_bio(struct request_queue *q,
                   struct bio           *bio)
{
    void * bio_private;
    struct gendisk *disk;
    struct rnablk_device *dev;
    int n_io, i;
    struct io_state *ios[RNABLK_MAX_SUB_IO];
    int err = 0;

    // retrieve pointer to our per-device data structure
    dev  = (struct rnablk_device *)q->queuedata;
    disk = dev->disk;

    if (unlikely(atomic_read(&dev->failed))) {
        bio_endio(bio, -EIO);
    } else if (rnablk_dev_is_shutdown(dev)) {
        bio_endio(bio, -ENODEV);
    } else {
        /* save caller's private data */
        bio_private = bio->bi_private;
        bio->bi_private = NULL;
        rnablk_set_bio_refcount(bio, 0);

        n_io = rnablk_bio_map_sg(dev, q, bio, bio_private, &ios[0]);

        if (likely(n_io > 0
                   && 0 == rnablk_reservation_access_check(dev,
                                        (WRITE == bio_data_dir(bio))
                                        ? RSV_ACC_READWRITE
                                        : RSV_ACC_READONLY))) {
            rna_printk(KERN_INFO, "BIO [%p] n_io [%d]\n", bio, n_io);

            rnablk_svcctl_register();
            for (i=0; i < n_io; i++) {
                rnablk_process_request(ios[i]);
            }
            rnablk_svcctl_deregister();
        } else if (n_io <= 0) {
            err = -EIO;
            bio->bi_private = bio_private;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
            bio_endio(bio, -EIO);
#else
            bio_endio(bio, 0, -EIO);
#endif
        } else {        // reservation access check failed
            rna_printk(KERN_DEBUG, "reservation access check failed: bio=%p "
                        "need %s\n", bio, WRITE == bio_data_dir(bio)
                        ? "READWRITE" : "READONLY");
            set_bit(BIO_QUIET, &bio->bi_flags);
            for (i=0; i < n_io; i++) {
                /*
                 * Clear DEVIOCNT flag so we don't try to decrement device
                 * iocnt during end_request.  (Can't decrement it since
                 * we didn't increment it up above!)
                 */
                atomic_bit_clear(&ios[i]->ios_atomic_flags, IOS_AF_DEVIOCNT);
                rnablk_end_request(ios[i], -EBUSY);
            }
        }
    }
}

static void rnablk_process_bio_wf(rnablk_workq_cb_arg_t arg)
{
    struct work_struct *work = (struct work_struct *)arg;
    struct rnablk_work *w = container_of( work,struct rnablk_work,work );
    struct rnablk_process_bio_wf_data *wd = &w->data.rwd_rnablk_process_bio_wf;
    struct request_queue *q  = wd->q;
    struct bio *bio = wd->bio;

    rnablk_process_bio(q, bio);
    rnablk_mempool_free(w, work_cache_info);
}

static int
rnablk_queue_process_bio(struct request_queue *q,
                         struct bio           *bio)
{
    int ret = 0;
    struct rnablk_work *w = NULL;
    struct rnablk_process_bio_wf_data *wd = NULL;

    w = rnablk_mempool_alloc(work_cache_info);
    if (NULL == w) {
        rna_printk(KERN_ERR,
                   "failed to alloc work queue object");
        ret = -ENOMEM;
    } else {
        RNABLK_INIT_RNABLK_WORK(w, wd, rnablk_process_bio_wf);
        wd->q = q;
        wd->bio = bio;
        rna_queue_work(bio_workq, &w->work);
    }
    return ret;
}

/* We only want to print the warning once. */
static int bio_stack_warn = TRUE;

static int
rnablk_make_request(struct request_queue *q,
                    struct bio           *bio)
{
    int err = 0;
    int remaining_stack = rnablk_remaining_stack();

    rna_printk(KERN_INFO,
               "BIO [%p]\n",
               bio);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
    if (unlikely(!bio_has_data(bio)))
#else
    if (unlikely(NULL == bio->bi_io_vec))
#endif
    {
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
        if (bio->bi_rw & REQ_HARDBARRIER)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
        if (bio_rw_flagged(bio, BIO_RW_BARRIER))
#else
        if (bio_barrier(bio))
#endif
        {
            /* empty barrier */
        } else {
            rna_printk(KERN_ERR,
                       "Unknown null bio ignored. (rw_flags %lx)\n", bio->bi_rw);
        }
#endif
        err = -EOPNOTSUPP;
    } else if (rnablk_queue_bios || remaining_stack < RNA_BIO_STACK_THRESHOLD) {
        if (unlikely(bio_stack_warn &&
            remaining_stack < RNA_BIO_STACK_THRESHOLD))
        {
            bio_stack_warn = FALSE;
            rna_printk(KERN_WARNING,
                       "queueing bios, leftover stack [%d], "
                       "current process [%s]\n",
                       remaining_stack, current->comm);
        }
        atomic_inc(&((struct rnablk_device *)q->queuedata)->deferred_stack);
        err = rnablk_queue_process_bio(q, bio);
    } else {
        rnablk_process_bio(q, bio);
    }

    if (unlikely(err)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
        bio_endio(bio, err);
#else
        bio_endio(bio, 0, err);
#endif
    }
    return 0;
}


static void
rnablk_cache_blk_force_free(void *void_blk)
{
    struct cache_blk *blk = (struct cache_blk *)void_blk;
    rnablk_dev_release(blk->dev);
}

void * rnablk_mempool_alloc (struct rnablk_cache_info * cache_info)
{
    struct rnablk_cache_info_member * member = NULL;
    void *ret = NULL;
    unsigned long flags;

    BUG_ON(NULL == cache_info);
    BUG_ON(NULL == cache_info->pool);
    if (atomic_read(&shutdown)) {
        rna_printk(KERN_ERR,
                   "Attempt to allocate from pool [%s] while shutting down\n",
                   cache_info->name);
        dump_stack();
    } else {
        member = mempool_alloc(cache_info->pool, GFP_ATOMIC);
        if (NULL != member) {
            rna_atomic64_add(cache_info->size, &cache_info->outstanding_mem);
            INIT_LIST_HEAD(&member->entry);
            spin_lock_irqsave(&cache_info->member_list_lock, flags);
            list_add_tail(&member->entry, &cache_info->member_list);
            spin_unlock_irqrestore(&cache_info->member_list_lock, flags);
            ret = &member->data;
        } else {
            rna_printk(KERN_ERR,
                       "mempool_alloc failed for pool [%s]\n",
                       cache_info->name);
        }
    }
    return ret;
}

static rna_inline void rnablk_mempool_free_nolock (struct rnablk_cache_info_member * member,
                                                   struct rnablk_cache_info        * cache_info)
{
    BUG_ON(NULL == member);
    BUG_ON(NULL == cache_info);
    BUG_ON(NULL == cache_info->pool);

    list_del_init(&member->entry);

    mempool_free(member, cache_info->pool);
    if ((rna_atomic64_add_return(-cache_info->size, &cache_info->outstanding_mem) < 0) &&
        (FALSE == atomic_cmpxchg(&cache_info->warned, FALSE, TRUE))) {
        rna_printk(KERN_ERR,
                   "pool [%s] outstanding_mem [%lu] would drop below zero after subtracting [%lu]\n",
                   cache_info->name,
                   atomic64_read(&cache_info->outstanding_mem),
                   cache_info->size);
        WARN_ON(TRUE);
    }
}

void rnablk_mempool_free (void                     * item,
                                            struct rnablk_cache_info * cache_info)
{
    unsigned long flags;
    struct rnablk_cache_info_member * member =
        container_of(item, struct rnablk_cache_info_member, data);

    spin_lock_irqsave(&cache_info->member_list_lock, flags);
    rnablk_mempool_free_nolock(member, cache_info);
    spin_unlock_irqrestore(&cache_info->member_list_lock, flags);
}


static void rnablk_req_add_sg(struct io_state     *ios,
                              struct bio_vec      *bvec,
                              int                  nbytes,
                              int                  offset);

static void
rnablk_req_cluster_accounting(struct request_queue *q,
                              struct io_state      *ios,
                              int                   nbytes,
                              struct bio_vec       *bvec,
                              struct bio_vec       *bvprv,
                              int                   cluster)
{
    struct scatterlist *sg = &ios->sgl[ios->nsgl-1];

    RNABLK_BUG_ON(ios->nsgl <= 0, "logic error: unexpected ios [%p] nsgl "
                  "[%d]\n", ios, ios->nsgl);
            
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
    if ((sg->length + nbytes > q->max_segment_size) ||
#else
    if ((sg->length + nbytes > queue_max_segment_size(q)) ||
#endif
        !BIOVEC_PHYS_MERGEABLE(bvprv, bvec) ||
        !BIOVEC_SEG_BOUNDARY(q, bvprv, bvec)) {
        rnablk_req_add_sg(ios, bvec, nbytes, 0);
    } else {
        sg->length += nbytes;
    }
}

static boolean
rnablk_req_can_cluster(struct request_queue *q, int sg_length,
                       int nbytes, struct bio_vec *bvec,
                       struct bio_vec *bvprv, int cluster)
{
    BUG_ON (NULL == bvprv);

    return (!(!cluster ||
            (sg_length + nbytes > queue_max_segment_size(q)) ||
            !BIOVEC_PHYS_MERGEABLE(bvprv, bvec) ||
            !BIOVEC_SEG_BOUNDARY(q, bvprv, bvec)));
}

static rna_noinline int
rnablk_bio_calculate_n_ios(struct rnablk_device *dev,
                           struct request_queue *q,
                           struct bio           *bio,
                           boolean              cluster,
                           boolean              need_extra_sg)
{
    struct bio_vec *bvec, *bvprv = NULL;
    uint64_t start_sector;
    int ios_nsgl[RNABLK_MAX_SUB_IO];
    int64_t ios_start_sector[RNABLK_MAX_SUB_IO];
    unsigned int sg_length = 0;
    int bv_nsecs;
    int sectors_per_block;
    int i;
    int nbytes;
    int extra_sectors;
    int block_one_sectors;
    int block_one_bytes;
    int block_two_bytes;
    int n_bios = 0;
    int n_ios = 0;

    start_sector = bio->bi_sector;
    sectors_per_block = dev->cache_blk_size >> RNABLK_SECTOR_SHIFT;

    for (; bio; bio = bio->bi_next) {
        n_bios++;
        bio_for_each_segment( bvec,bio,i ) {
            bv_nsecs = bvec->bv_len >> RNABLK_SECTOR_SHIFT;
            nbytes   = bvec->bv_len;

            if ((bv_nsecs > (sectors_per_block -
                (start_sector % sectors_per_block)))) {
                /*
                 * This request overlaps cache block boundaries, need to
                 * split it.
                 */
                extra_sectors = bv_nsecs - (sectors_per_block -
                                (start_sector % sectors_per_block));
                block_one_sectors = bv_nsecs - extra_sectors;
                block_one_bytes = block_one_sectors * RNABLK_SECTOR_SIZE;
                block_two_bytes = (extra_sectors * RNABLK_SECTOR_SIZE);

                rna_printk(KERN_INFO, "start_sector [%"PRIu64"] nsecs [%d] "
                           "end sector [%"PRIu64"] past end of cache block "
                           "[%"PRIu64"]\n", start_sector, bv_nsecs,
                            (start_sector + bv_nsecs),
                            (start_sector - (start_sector % sectors_per_block)
                            + sectors_per_block));

                if ((0 == n_ios) || (ios_nsgl[n_ios-1] == max_sge)) {
                    // we need two new IOs
                    if (++n_ios > RNABLK_MAX_SUB_IO) {
                        rna_printk(KERN_ERR, "bio[%d]=%p needs too many ios\n",
                                   n_bios-1, bio);
                        return -EIO;
                    }
                    ios_start_sector[n_ios-1] = start_sector;
                    ios_nsgl[n_ios-1] = 1;
                    sg_length = block_one_bytes;
                } else if (rnablk_req_can_cluster(q, sg_length, block_one_bytes,
                                                  bvec, bvprv, cluster)) {
                    sg_length += block_one_bytes;
                } else {
                    ios_nsgl[n_ios-1]++;
                }

                // now for the second IO
                if (++n_ios > RNABLK_MAX_SUB_IO) {
                    rna_printk(KERN_ERR, "bio[%d]=%p needs too many ios\n",
                               n_bios-1, bio);
                    return -EIO;
                }
                ios_start_sector[n_ios-1] = start_sector + (bv_nsecs -
                                            extra_sectors);
                ios_nsgl[n_ios-1] = 1;
                sg_length = block_two_bytes;
            } else if (0 == n_ios || (start_sector % sectors_per_block) == 0
                       || ios_nsgl[n_ios-1] == max_sge ) {
                /*
                 * if we've reached the next cache block or the scatter list
                 * in the current request is full we must start a new one
                 */
                if (++n_ios > RNABLK_MAX_SUB_IO) {
                    rna_printk(KERN_ERR, "bio[%d]=%p needs too many ios\n",
                               n_bios-1, bio);
                    return -EIO;
                }
                ios_start_sector[n_ios-1] = start_sector;
                ios_nsgl[n_ios-1] = 1;
                sg_length = nbytes;
            } else if (rnablk_req_can_cluster(q, sg_length, nbytes, bvec, bvprv,
                                              cluster)) {
                sg_length += nbytes;
            } else {
                ios_nsgl[n_ios-1]++;
            }
            start_sector += bv_nsecs;
            bvprv = bvec;
        }
    }
    if (need_extra_sg && (0 == n_ios || ios_nsgl[n_ios-1] == max_sge)) {
        if (++n_ios > RNABLK_MAX_SUB_IO) {
            rna_printk(KERN_ERR, "extra_sg needs too many ios (n_bios=%d)\n",
                       n_bios);
            return -EIO;
        }
    }
        
    return n_ios;
}

static struct io_state *
rnablk_segment_init_next_ios(struct io_state *ios, void *ioreq,
                             void *ioreq_private, uint16_t ioreq_type,
                             atomic_t *ioreq_refcount, uint64_t ss,
                             int *cur_ios, int tot_ios,
                             struct io_state **pp_ios)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
    if (NULL != ios) {
        /* Terminate previous sgl */
        sg_mark_end(&ios->sgl[ios->nsgl-1]);
    }
#endif
    ios = pp_ios[*cur_ios];
    (*cur_ios)++;
    RNABLK_BUG_ON(*cur_ios > tot_ios, "Mismatch in bio n_ios "
                  "calculation: exp=%d cur=%d\n", tot_ios, *cur_ios);
    ios->bio_private  = ioreq_private;
    ios->type         = RNABLK_INIT;
    ios->start_sector = ss;
    ios->ios_iotype = ioreq_type;
    //
    // increment our ref count on the request
    atomic_inc(ioreq_refcount);
    return ios;
}

static rna_noinline void
rnablk_io_map_sg(struct rnablk_device *dev,
                  struct request_queue *q,
                  struct bio *bio,
                  void *ioreq,
                  void *ioreq_private,
                  uint16_t ioreq_type,
                  atomic_t *ioreq_refcount,
                  boolean cluster,
                  boolean need_extra_sg,
                  int n_ios,
                  struct io_state **pp_ios)
{
    struct bio_vec *bvec, *bvprv = NULL;
    struct io_state *ios = NULL;
    uint64_t start_sector;
    int bv_nsecs;
    int sectors_per_block;
    int i;
    int nbytes;
    int extra_sectors;
    int block_one_sectors;
    int block_one_bytes;
    int block_two_bytes;
    int cur_ios = 0;
    int ret = 0;

    RNABLK_BUG_ON(n_ios > RNABLK_MAX_SUB_IO, "logic error: n_ios [%d] too big; "
                  "ioreq [%p] dev [%p]\n", n_ios, ioreq, dev);

    start_sector = bio->bi_sector;
    sectors_per_block = dev->cache_blk_size >> RNABLK_SECTOR_SHIFT;

    for (; bio; bio = bio->bi_next) {
        bio_for_each_segment( bvec,bio,i ) {
            bv_nsecs = bvec->bv_len >> RNABLK_SECTOR_SHIFT;
            nbytes   = bvec->bv_len;
            if ((bv_nsecs > (sectors_per_block -
                (start_sector % sectors_per_block)))) {
                /*
                 * This request overlaps cache block boundaries, need to
                 * split it.
                 */
                extra_sectors = bv_nsecs - (sectors_per_block -
                                (start_sector % sectors_per_block));
                block_one_sectors = bv_nsecs - extra_sectors;
                block_one_bytes = block_one_sectors * RNABLK_SECTOR_SIZE;
                block_two_bytes = (extra_sectors * RNABLK_SECTOR_SIZE);
                if ((ios == NULL) || (ios->nsgl == max_sge)) {
                    ios = rnablk_segment_init_next_ios(ios, ioreq,
                                        ioreq_private, ioreq_type,
                                        ioreq_refcount, start_sector,
                                        &cur_ios, n_ios, pp_ios);
                    // truncate first IO to end of cache block
                    rnablk_req_add_sg(ios, bvec, block_one_bytes, 0);
                } else {
                    rnablk_req_cluster_accounting(q, ios, block_one_bytes,
                                                  bvec, bvprv, cluster);
                }
                ios->nr_sectors += block_one_sectors;

                // now for the second IO
                ios = rnablk_segment_init_next_ios(ios, ioreq,
                                        ioreq_private, ioreq_type,
                                        ioreq_refcount, start_sector +
                                        (bv_nsecs - extra_sectors),
                                        &cur_ios, n_ios, pp_ios);
                // truncate first IO to end of cache block
                rnablk_req_add_sg(ios, bvec, block_two_bytes, block_one_bytes);
                ios->nr_sectors += extra_sectors;

            } else if (ios == NULL || (start_sector % sectors_per_block) == 0
                       || ios->nsgl == max_sge ) {
                // if we've reached the next cache block or the scatter list in
                // the current request is full we must start a new one
                ios = rnablk_segment_init_next_ios(ios, ioreq,
                                            ioreq_private, ioreq_type,
                                            ioreq_refcount, start_sector,
                                            &cur_ios, n_ios, pp_ios);

                rnablk_req_add_sg(ios, bvec, nbytes, 0);
                ios->nr_sectors += bv_nsecs;
            } else {
                rnablk_req_cluster_accounting(q, ios, nbytes, bvec, bvprv,
                                              cluster);
                ios->nr_sectors += bv_nsecs;
            }

            start_sector += bv_nsecs;
            bvprv = bvec;
        }
    }
    if (need_extra_sg && (NULL == ios || ios->nsgl == max_sge)) {
        ios = rnablk_segment_init_next_ios(ios, ioreq, ioreq_private,
                                           ioreq_type, ioreq_refcount,
                                           start_sector, &cur_ios, n_ios,
                                           pp_ios);
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
    if (NULL != ios) {
        /* terminate final sgl */
        sg_mark_end(&ios->sgl[ios->nsgl-1]);
    }
#endif
    RNABLK_BUG_ON(cur_ios != n_ios, "Mismatch on number of ios; exp=%d "
                  "act=%d\n", n_ios, cur_ios);
    return;
}

// Probably copied from blk_rq_map_sg() in kernel-2.6/18/vanilla/block/ll_rw_blk.c
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
static void
rnablk_req_add_sg(struct io_state     *ios,
                  struct bio_vec      *bvec,
                  int                  nbytes,
                  int                  offset)
{
    struct scatterlist *sg;

    sg = &ios->sgl[ios->nsgl];
    memset(sg, 0, sizeof(*sg));
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
    sg->page = bvec->bv_page;
#else
    sg_assign_page(sg, bvec->bv_page);
#endif
    sg->length = nbytes;
    sg->offset = bvec->bv_offset + offset;

    ios->nsgl++;
}

int
rnablk_rq_map_sg(struct rnablk_device *dev, struct request_queue *q,
                 struct request *req, struct io_state **pp_ios)
{
    int cluster;
    int n_ios;
    boolean is_write = (RNA_REQ_FLAGS(req) & REQ_WRITE) != 0;
    struct io_state *ios;
    struct scatterlist *sg;
    ENTER;

    cluster = test_bit(QUEUE_FLAG_CLUSTER, &q->queue_flags);

    n_ios = rnablk_bio_calculate_n_ios(dev, q, req->bio, cluster, FALSE);
    if (n_ios <= 0) {
        rna_printk(KERN_ERR, "req [%p] is too big or zero size(?) ret=%d\n",
                   req, n_ios);
        return n_ios;
    }
    ret = rnablk_alloc_ios_io(dev, n_ios, pp_ios, req, IOREQ_TYPE_REQ,
                              is_write ? RSV_ACC_READWRITE : RSV_ACC_READONLY);
    if (0 != ret) {
       return ret;
    }

    rnablk_io_map_sg(dev, q, req->bio, req, NULL,
                     is_write ? IOS_IOTYPE_WRITE : IOS_IOTYPE_READ,
                     (atomic_t *)&req->special, cluster, FALSE, n_ios, pp_ios);

    return n_ios;
}

#else  // LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)

static void
rnablk_req_add_sg(struct io_state     *ios,
                  struct bio_vec      *bvec,
                  int                  nbytes,
                  int                  offset)
{
    struct scatterlist *sg;

    sg = &ios->sgl[ios->nsgl];
    sg->page_link = 0;
    sg_set_page(sg, bvec->bv_page, nbytes, (bvec->bv_offset + offset));
    ios->nsgl++;
}

int
rnablk_rq_map_sg(struct rnablk_device *dev, struct request_queue *q,
                 struct request *req, struct io_state **pp_ios)
{
    int cluster;
    int n_ios;
    boolean is_write = (RNA_REQ_FLAGS(req) & REQ_WRITE) != 0;
    boolean drain_needed;
    struct io_state *ios;
    struct scatterlist *sg;
    unsigned int pad_len;
    ENTER;

    cluster = blk_queue_cluster(q);
    drain_needed = q->dma_drain_size && q->dma_drain_needed(req);

    n_ios = rnablk_bio_calculate_n_ios(dev, q, req->bio, cluster,
                                       drain_needed);
    if (n_ios <= 0) {
        rna_printk(KERN_ERR, "req [%p] is too big or zero size(?) ret=%d\n",
                   req, n_ios);
        return n_ios;
    }
    ret = rnablk_alloc_ios_io(dev, n_ios, pp_ios, req, IOREQ_TYPE_REQ,
                              is_write ? RSV_ACC_READWRITE : RSV_ACC_READONLY);
    if (0 != ret) {
       return ret;
    }

    rnablk_io_map_sg(dev, q, req->bio, req, NULL,
                     is_write ? IOS_IOTYPE_WRITE : IOS_IOTYPE_READ,
                     (atomic_t *)&req->special, cluster, drain_needed,
                     n_ios, pp_ios);

    if (unlikely((req->cmd_flags & REQ_COPY_USER) &&
                 (blk_rq_bytes(req) & q->dma_pad_mask))) {

        ios = pp_ios[n_ios-1]->nsgl > 0 ? pp_ios[n_ios-1] : pp_ios[n_ios-2];
        sg = &ios->sgl[ios->nsgl-1];

        pad_len = (q->dma_pad_mask & ~blk_rq_bytes(req)) + 1;

        rna_printk(KERN_ERR, "pad_len [%u]\n", pad_len);

        sg->length += pad_len;
        req->extra_len += pad_len;
    }

    if (q->dma_drain_size && q->dma_drain_needed(req)) {
        if (req->cmd_flags & REQ_WRITE) {
            memset(q->dma_drain_buffer, 0, q->dma_drain_size);
        }

        rna_printk(KERN_ERR, "dma_drain_needed drain_size [%u] offset [%lu]\n",
                   q->dma_drain_size,
                   ((unsigned long)q->dma_drain_buffer) & (PAGE_SIZE - 1));

        ios = pp_ios[n_ios-1];
        if (ios->nsgl > 0) {
            sg = &ios->sgl[ios->nsgl-1];
            sg->page_link &= ~0x02;
            sg = sg_next(sg);
        } else {
            sg = ios->sgl;
        }
        sg_set_page(sg, virt_to_page(q->dma_drain_buffer), q->dma_drain_size,
                    ((unsigned long)q->dma_drain_buffer) & (PAGE_SIZE - 1));
        req->extra_len += q->dma_drain_size;
        ios->nsgl++;
        sg_mark_end(sg);
    }

#ifdef RNABLK_DEBUG_SG
    {
    int i, j;
    for (i = 0; i < n_ios; i++) {
        ios = pp_ios[i];
        for (sg = ios->sgl, j = 0 ; j < ios->nsgl; sg++, j++) {
            RNABLK_BUG_ON(rna_sg_page(sg) == NULL, "sg_page: ppios=%p ios=%p "
                          "sg=%p i=%d j=%d\n", pp_ios, ios, sg, i, j)
            RNABLK_BUG_ON(sg->length == 0, "sg length: ppios=%p ios=%p "
                          "sg=%p i=%d j=%d\n", pp_ios, ios, sg, i, j)
            RNABLK_BUG_ON(sg_is_chain(sg), "sg chain: ppios=%p ios=%p "
                          "sg=%p i=%d j=%d\n", pp_ios, ios, sg, i, j)
            RNABLK_BUG_ON(sg_is_last(sg) && j != ios->nsgl - 1,
                          "sg shouldn't be last: ppios=%p ios=%p "
                          "sg=%p i=%d j=%d\n", pp_ios, ios, sg, i, j)
            RNABLK_BUG_ON(!sg_is_last(sg) && j == ios->nsgl - 1,
                          "sg should be last: ppios=%p ios=%p "
                          "sg=%p i=%d j=%d\n", pp_ios, ios, sg, i, j)
        }
    }
    }
#endif /* RNABLK_DEBUG_SG */
    return n_ios;
}


#endif  // LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)

void rnablk_set_max_io(struct rnablk_device *dev,
                       int                   max_bytes)
{
    BUG_ON(NULL == dev);

    dev->max_sectors = (max_bytes / RNABLK_SECTOR_SIZE);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
    // block layers BLK_DEF_MAX_SECTORS = 1024
    if( dev->max_sectors <= BLK_DEF_MAX_SECTORS ) {
        blk_queue_max_sectors( dev->q, dev->max_sectors );
    } else {
        // TBD: Why do we set this differently in this case?  To exceed BLK_DEF_MAX_SECTORS?
        dev->q->max_hw_sectors = dev->q->max_sectors = dev->max_sectors;
    }
#else
    blk_queue_max_hw_sectors(dev->q, dev->max_sectors);
    blk_queue_io_opt(dev->q, max_bytes);
#endif
    blk_queue_max_segment_size(dev->q, max_bytes);

}


module_param_named(client_id, rnablk_client_id_str, charp, 0440);

module_init( rnablk_init );
module_exit( rnablk_exit );

MODULE_LICENSE( "GPL" );
MODULE_AUTHOR( "Dell Inc" );
