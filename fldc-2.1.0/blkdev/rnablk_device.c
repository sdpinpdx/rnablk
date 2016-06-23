/**
 * <rnablk_device.c> - Dell Fluid Cache block driver
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
#include "trace.h"
#include "rnablk_device.h"
#include "rnablk_globals.h"
#include "rnablk_cache.h"
#include "rnablk_queue_dispatch.h"
#include "rnablk_io_state.h"
#include "rnablk_util.h"
#include "rnablk_protocol.h"
#include "rnablk_comatose.h" // for rnablk_clear_dev_queue_stop_flag

#ifdef WINDOWS_KERNEL
#include "rnablk_win_device.h"
#include "rnablk_win_util.h"
#endif

#ifndef WINDOWS_KERNEL

DECLARE_COMPLETION(dev_destroy_comp);

struct rnablk_device *
rnablk_find_device_by_path_nolock(char *path)
{
    struct list_head *pos;
    struct rnablk_device *dev = NULL;
    struct rnablk_device *this_dev = NULL;
    ENTER;

    list_for_each( pos,&rnablk_dev_list ) {
        this_dev = list_entry( pos,struct rnablk_device,l );
        if (0 == strcmp(this_dev->cache_file_name, path)) {
            if (rnablk_dev_acquire(this_dev)) {
                dev = this_dev;
            }
            break;
        }
    }

    EXITPTR( dev );
}

static struct rnablk_device *
rnablk_find_device_by_rid_nolock(const uint64_t rid)
{
    struct list_head *pos;
    struct rnablk_device *dev = NULL;
    struct rnablk_device *this_dev = NULL;

    list_for_each(pos, &rnablk_dev_list) {
        this_dev = list_entry(pos, struct rnablk_device, l);
        if (rid == MASTER_BLK(this_dev)->rid) {
            dev = this_dev;
            break;
        }
    }

    return(dev);
}

struct rnablk_device *
rnablk_find_device_nolock(char *name)
{
    struct list_head *pos;
    struct rnablk_device *dev = NULL;
    struct rnablk_device *this_dev = NULL;
    ENTER;
	
    list_for_each( pos,&rnablk_dev_list ) {
        this_dev = list_entry( pos,struct rnablk_device,l );
        if( 0 == strcmp(this_dev->name, name) ) {
            if (rnablk_dev_acquire(this_dev)) {
                dev = this_dev;
            }
            break;
        }
    }

    EXITPTR( dev );
}

struct rnablk_device *rnablk_find_device( char *name )
{
    struct rnablk_device *dev;
    unsigned char oldirql = 0;
    ENTER;

    rna_down_read( &rnablk_dev_list_lock, &oldirql );
    dev = rnablk_find_device_nolock(name);
    rna_up_read( &rnablk_dev_list_lock, oldirql );

    EXITPTR( dev );
}

struct rnablk_device *
rnablk_find_device_by_addr_nolock(void *find_dev)
{
    struct list_head *pos;
    struct rnablk_device *dev = NULL;
    struct rnablk_device *this_dev = NULL;
    ENTER;

    list_for_each( pos,&rnablk_dev_list ) {
        this_dev = list_entry( pos,struct rnablk_device,l );
        if( this_dev == find_dev ) {
            if (rnablk_dev_acquire(this_dev)) {
                dev = this_dev;
            }
            break;
        }
    }

    EXITPTR( dev );
}

struct rnablk_device *rnablk_find_device_by_addr( void *find_dev )
{
    struct rnablk_device *dev;
    unsigned char oldirql = 0;
    ENTER;

    rna_down_read( &rnablk_dev_list_lock, &oldirql );
    dev = rnablk_find_device_by_addr_nolock(find_dev);
    rna_up_read( &rnablk_dev_list_lock, oldirql );

    EXITPTR( dev );
}

void
rnablk_add_device_nolock(struct rnablk_device *dev)
{
    (void)rnablk_dev_acquire(dev);      // add reference for being in list
    list_add_tail( &dev->l,&rnablk_dev_list );
}

void rnablk_add_device( struct rnablk_device *dev )
{
    unsigned char oldirql = 0;

    ENTER;

    UNREFERENCED_PARAMETER(ret);

    rna_down_write( &rnablk_dev_list_lock, &oldirql );
    rnablk_add_device_nolock( dev );
    rna_up_write( &rnablk_dev_list_lock, oldirql );

    EXITV;
}

void
rnablk_remove_device(struct rnablk_device *dev)
{
    unsigned char oldirql = 0;

    ENTER;

    rna_down_write( &rnablk_dev_list_lock, &oldirql );
    list_del_init( &dev->l );
    /*
     * release the "list" reference while holding the mutex, to ensure that
     * walkers of the list can safely access the device.
     */
    rnablk_dev_release(dev);
    rna_up_write( &rnablk_dev_list_lock, oldirql );

    EXITV;
}

static void
rnablk_detached_shutdown_device_cleanup(struct rnablk_device *dev)
{
    struct cache_blk *blk;
    struct list_head *ent, *next;
    unsigned char oldirql;
    unsigned long irqflags;
    struct rnablk_server_conn *conn;
    struct cache_blk marker_blk;
    mutexstate_t mutex_lock_handle;
    boolean do_cleanup;

    RNABLK_BUG_ON(!atomic_read(&dev->failed),
                  "Cleanup called for dev [%s] when not in failed state?\n",
                  dev->name);

    marker_blk.cb_identity_flags = BLK_F_MARKER_BLK;

    rna_down_write(&dev->cache_blk_lock, &oldirql);

    list_for_each_safe(ent, next, &dev->rbd_blk_list) {
        blk = list_entry(ent, struct cache_blk, cb_dev_link);

        if (unlikely(IS_MARKER_BLK(blk))) {
            continue;
        }

        rnablk_cache_blk_ref(blk);

        list_add(&marker_blk.cb_dev_link, ent);
        rna_up_write(&dev->cache_blk_lock, oldirql);

        do_cleanup = FALSE;

        rnablk_lock_blk_irqsave(blk, irqflags);    
        
        if (RNABLK_CACHE_BLK_INVALID != blk->state) {
            if (NULL != (conn = rnablk_get_ep_conn(blk->ep))
                && g_md_conn != conn) {
                rnablk_unlock_blk_irqrestore(blk, irqflags);
                rna_block_mutex_lock(&conn->block_list_lock, &mutex_lock_handle);
                rnablk_lock_blk_irqsave(blk, irqflags);    
                if (RNABLK_CACHE_BLK_INVALID != blk->state) {
                    do_cleanup = TRUE;
                }
            } else {
                do_cleanup = TRUE;
                conn = NULL;
            }

            if (do_cleanup) {
                rnablk_cleanup_blk(blk);
            }

            rnablk_unlock_blk_irqrestore(blk, irqflags);

            if (NULL != conn) {
                rna_block_mutex_unlock(&conn->block_list_lock, &mutex_lock_handle);
            }
        } else {
            rnablk_unlock_blk_irqrestore(blk, irqflags);
        }

        rna_down_write(&dev->cache_blk_lock, &oldirql);
        rnablk_cache_blk_release(blk);
#ifdef WINDOWS_KERNEL
        next = marker_blk.cb_dev_link.Flink;
#else
        next = marker_blk.cb_dev_link.next;
#endif /*WINDOWS_KERNEL*/
        list_del(&marker_blk.cb_dev_link);
    }
    rna_up_write( &dev->cache_blk_lock, oldirql );

    /* Cleanup outstanding commands for the MASTER blk as well */
    blk = MASTER_BLK(dev);
    do_cleanup = FALSE;
    rnablk_lock_blk_irqsave(blk, irqflags);    
    if (RNABLK_CACHE_BLK_INVALID != blk->state) {
        if (NULL != (conn = rnablk_get_ep_conn(blk->ep))
            && g_md_conn != conn) {
            rnablk_unlock_blk_irqrestore(blk, irqflags);
            rna_block_mutex_lock(&conn->block_list_lock, &mutex_lock_handle);
            rnablk_lock_blk_irqsave(blk, irqflags);    
            if (RNABLK_CACHE_BLK_INVALID != blk->state) {
                do_cleanup = TRUE;
            }
        } else {
            do_cleanup = TRUE;
            conn = NULL;
        }

        if (do_cleanup) {
            rnablk_cleanup_blk(blk);
        }

        rnablk_unlock_blk_irqrestore(blk, irqflags);

        if (NULL != conn) {
            rna_block_mutex_unlock(&conn->block_list_lock, &mutex_lock_handle);
        }
    } else {
        rnablk_unlock_blk_irqrestore(blk, irqflags);
    }

    // rnablk_cleanup_conn_waiters_for_dev(dev);    // maybe need this??
}

void
rnablk_detached_shutdown_cleanup_devices()
{
    struct rnablk_device *dev, *tdev;
    struct list_head *ent;
    unsigned char oldirql;

    if (!atomic_read(&rna_service_detached)) {
        return;
    }

    do {
        dev = NULL;

        rna_down_read(&rnablk_dev_list_lock, &oldirql);
        list_for_each(ent, &rnablk_dev_list) {
            tdev = list_entry(ent, struct rnablk_device, l);
            if (!atomic_read(&tdev->failed)) {
                if (rnablk_dev_acquire(tdev)) {
                    dev = tdev;
                    break;
                }
            }
        }
        rna_up_read(&rnablk_dev_list_lock, oldirql);

        if (NULL != dev) {
            rna_printk(KERN_NOTICE, "Clean up device [%s]\n", dev->name);
            (void)rnablk_device_fail(dev);
            rnablk_detached_shutdown_device_cleanup(dev);
            rnablk_dev_release(dev);
        }
    } while (NULL != dev);

    return;
}

#endif //WINDOWS_KERNEL

/* Call rnablk_make_device() or rnablk_find_or_make_device(), not this. */
struct rnablk_device *
rnablk_make_device_internal(const char *name, int lock_held)
{
    struct rnablk_device *dev = NULL;

#ifdef WINDOWS_KERNEL
	UNREFERENCED_PARAMETER(name);
	UNREFERENCED_PARAMETER(lock_held);
	return dev;

#else
    size_t max_dev_name = (sizeof(dev->disk->disk_name) - 1);
    ENTER;

    BUG_ON(NULL == name);

    if( strlen( name ) >= sizeof( dev->name ) ) {
        GOTO( err,-EINVAL );
    }

    dev = kmalloc( sizeof( struct rnablk_device ),GFP_KERNEL );
    if( dev == NULL )
        GOTO( err,-ENOMEM );
    memset( dev,0,sizeof( struct rnablk_device ) );

    strncpy(dev->name, name, max_dev_name);

    if ((strlen(name) > max_dev_name)) {
        rna_printk(KERN_ERR,
                   "device name [%s] too long, truncating to [%s]\n",
                   name,
                   dev->name);
    }

    dev->magic = RNABLK_DEVICE_MAGIC;
    atomic_set(&dev->rbd_refcnt, 2);    // one ref for creation, one for caller

    // init device specific variables
    INIT_LIST_HEAD( &dev->l );
    INIT_LIST_HEAD(&dev->rbd_blk_list);
    rna_init_rwsem( &dev->cache_blk_lock );
    atomic_set( &dev->stats.openers,0 );
    atomic_set( &dev->stats.status, RNABLK_CACHE_OFFLINE );
    rna_atomic64_set( &dev->stats.bs_write_query_time, 0);
    rna_atomic64_set( &dev->stats.bs_read_query_time, 0);
    rna_atomic64_set( &dev->stats.bs_read_time, 0);
    rna_atomic64_set( &dev->stats.bs_write_time, 0);
    rna_atomic64_set( &dev->stats.bs_write_hits, 0);
    rna_atomic64_set( &dev->stats.bs_read_hits, 0);
    atomic_set( &dev->failed, FALSE );
    atomic_set(&dev->min_stack, 0x7FFFFFFF);
    dev->cache_blk_size = RNABLK_DEFAULT_CACHE_BLK_SIZE;
    /*
     * By default, set the "large_write" qualifying size as 1/4 of the
     * cache_blk size.
     */
    dev->rbd_large_write_sects = (dev->cache_blk_size / 4) / RNABLK_SECTOR_SIZE;
    dev_clear_dma_reads_disabled(dev);
    dev_set_dma_writes_disabled(dev);
    dev_clear_quiesce_on_release(dev);
    init_timer( &dev->disconnect_timer );
    INIT_LIST_HEAD(&dev->ordered_commands);
    rna_spin_lock_init(dev->ordered_cmd_lock);
    init_waitqueue_head(&dev->rbd_event_wait);
    rna_spin_lock_init(dev->rbd_event_lock);
    dev->rbd_rsv.rrs_is_valid = FALSE;
    dev->rbd_rsv.rrs_client_access = RSV_ACC_NONE;  // no access at start!

    dev->dv_master_blk = alloc_cache_blk(dev, 0, TRUE);
    if (dev->dv_master_blk == NULL) {
        GOTO(err, -ENOMEM);
    }
    // keep a permanent reference on the master blk
    rnablk_cache_blk_ioref(dev->dv_master_blk, NULL);

    if (rnablk_use_req_queue) {
        dev_set_use_req_queue(dev);
    }

    if (lock_held) {
        // list locking handled by caller
        rnablk_add_device_nolock( dev );
    } else {
        rnablk_add_device( dev );
    }

    EXITPTR( dev );
err:
    if (dev) {
        if (dev->dv_master_blk) {
            rnablk_mempool_free(dev->dv_master_blk, blk_cache_info);
        }
        kfree(dev);
    }
    EXITPTR( NULL );
#endif /*WINDOWS_KERNEL*/
}

/*
 * Make an rnablk_device object, for an actual block device, or the
 * hidden control device
 */
struct rnablk_device *
rnablk_make_device(const char *name)
{
    /* we must lock the list because we're using a multi-threaded workqueue */
    return rnablk_make_device_internal(name, 0);
}

/* Destroy and clean up an rnablk_device object */
void
rnablk_disconnect_device(struct rnablk_device *dev)
{
    struct rnablk_server_conn *conn;
    struct cache_blk *master_blk;
    lockstate_t irqflags;
    mutexstate_t mutex_lock_handle;

    ENTER;

    /*
     * We disconnect only if the device isn't currently open.
     * In that event, we disallow any new opens on the device
     * by setting 'openers' to special value of -1.
     */
    dev_openers_set_disabled(dev);
    if (!dev_openers_is_disabled(dev)) {
        rna_printk(KERN_ERR,
                   "not disconnecting device [%s] with [%d] openers\n",
                   dev->name,
                   atomic_read(&dev->stats.openers));

        GOTO(out, -EBUSY);
    }

    /*
     * Disconnecting state may have already been set if triggered by
     * disconnect cfs file
     */ 
    atomic_set(&dev->stats.status, RNABLK_CACHE_DISCONNECTING);

    /* prevent automatic re-connection attempts */
    rnablk_dev_shutdown(dev);

    /* after device is marked 'shutdown', wake up any UA waiters */
    rna_spin_lock_irqsave(dev->rbd_event_lock, irqflags);
    wake_up_all(&dev->rbd_event_wait);
    rna_spin_unlock_irqrestore(dev->rbd_event_lock, irqflags);

    /* Wait for all block references to be dropped */
    rnablk_quiesce(dev);

    master_blk = MASTER_BLK(dev);
    conn = rnablk_get_ep_conn(master_blk->ep);
    if (!atomic_read(&rna_service_detached)) {
        /* Dereference master block before destruction */
        if (0 == rnablk_master_blk_send_deref(dev)
            && rnablk_conn_connected(conn)) {
            rnablk_next_request(conn);
        }
    } else {
        /* If we couldn't deref it above, then at least drop our reference */
        if (NULL != conn) {
            rna_block_mutex_lock(&conn->block_list_lock, &mutex_lock_handle);
        }
        rnablk_lock_blk_irqsave(master_blk, irqflags);
        rnablk_unset_blk_ep(master_blk);
        rnablk_unlock_blk_irqrestore(master_blk, irqflags);
        if (NULL != conn) {
            rna_block_mutex_unlock(&conn->block_list_lock, &mutex_lock_handle);
        }
    }

    /* disconnect from cache */
    rnablk_disconnect_cache( dev );

#ifdef WINDOWS_KERNEL
    /*
     * Free the Timer and DPC objects that were allocated by the 
     * Windows version of alloc device: Rnablk_win_device.c->Allocate_Device. 
     */
    clean_timer(&dev->disconnect_timer);
#endif

    atomic_set(&dev->stats.status, RNABLK_CACHE_DISCONNECTED);
    rna_printk(KERN_ERR, "Disconnected dev [%s]\n", dev->name);

out:
    EXITV;
}

/* Destroy and clean up an rnablk_device object */
void
rnablk_destroy_device(struct rnablk_device *dev)
{
    int status;
    ENTER;

    /*
     * We can destroy only if the device isn't currently open.
     * In that event, we disallow any new opens on the device
     * by setting 'openers' to special value of -1.
     */
    dev_openers_set_disabled(dev);
    if (!dev_openers_is_disabled(dev)) {
        rna_printk(KERN_ERR,
                   "not destroying device [%s] with [%d] openers\n",
                   dev->name,
                   atomic_read(&dev->stats.openers));

        GOTO(out, -EBUSY);
    }

    status = atomic_read(&dev->stats.status);

    /* Do nothing here is disconnect in progress */
    if (RNABLK_CACHE_DISCONNECTING == status) {
        rna_printk(KERN_ERR,
                   "not destroying device [%s] in state [%s]\n",
                   dev->name,
                   get_rnablk_cache_status_string(status));

        GOTO(out, -EBUSY);
    }

    if (RNABLK_CACHE_DISCONNECTED != status) {
        rnablk_disconnect_device(dev);
    }

    // remove from kernels list of block devices
    rnablk_unregister_block_device( dev );

    // remove from internal device list
    rnablk_remove_device( dev );

    if (unlikely(1 != atomic_read(&dev->dv_master_blk->ref_count))) {
        /*
         * Somebody still has a reference on the master_blk.
         * Everything should cleanup fine when that reference goes away.
         * However, if through some abnormal situation the outstanding
         * reference(s) on the master blk don't go away, then it won't be
         * freed until the driver module gets unloaded. At that time it
         * will be freed as part of tearing down the mempools (which will
         * also take care of freeing this rnablk_device structure).
         */
        rna_printk(KERN_WARNING, "device [%s]: unexpected refcnt ["BLKCNTFMT"] "
                   "on master blk, exp=1\n", dev->name,
                   BLKCNTFMTARGS(dev->dv_master_blk));
    }
    /*
     * Drop our permanent "io" reference on the master.
     * Normal case is this will be the last ref on it, which will cause it
     * to be freed, and thus will release the second-to-last ref on dev,
     * which will then get freed via the rnablk_dev_release() below.
     */
    rnablk_cache_blk_iorel(dev->dv_master_blk, NULL);

#ifdef WINDOWS_KERNEL
    rnablk_cache_blk_free_cache_blk_root(&(dev->cache_blk_root));
#endif /*WINDOWS_KERNEL*/

    rnablk_dev_release(dev);

#ifndef WINDOWS_KERNEL
    // signal destruction of this device is complete
    complete( &dev_destroy_comp );
#endif /*WINDOWS_KERNEL*/

out:
    EXITV;
}

/**
 * Removes a block device configfs item
 *
 * Runs in kthread context
 */
void rnablk_remove_device_item(char *name)
{
#ifdef WINDOWS_KERNEL
	UNREFERENCED_PARAMETER(name);
#else
    int result;
// this is too big for the stack - dynamically allocate instead
    char *dev_path;
    char *argv[3], *envp[1];
    int i;
    ENTER;

    dev_path = kmalloc(PATHNAME_LEN, GFP_ATOMIC);
    if (dev_path == NULL) {
        result = -ENOMEM;
        goto out;
    }
    snprintf(dev_path, PATHNAME_LEN, RNABLK_DEVICE_ITEM_PATH "/%s", name);

    rna_printk(KERN_INFO, "Removing directory %s\n", dev_path);

    i=0;
    argv[i++] = "/bin/rmdir";
    argv[i++] = dev_path;
    argv[i++] = NULL;

    i=0;
    envp[i++] = NULL;

    result = call_usermodehelper(argv[0], argv, envp, 1);

out:
    if( 0 != result )
        printk( "%s: Failed to remove device directory %s\n",__FUNCTION__,dev_path );

    kfree(dev_path);

    EXITV;
#endif /*WINDOWS_KERNEL*/
}
/**
 * Stops a block device
 *
 * Runs in kthread context
 */
int rnablk_stop_device_item(char *name)
{
#ifdef WINDOWS_KERNEL
	UNREFERENCED_PARAMETER(name);
	return 0;
#else
    int result = 0;
// this is too big for the stack - dynamically allocate instead
    char *dev_name = NULL;
    char *argv[3];
    static char *stop_envp[] = {
        "HOME=/",
        "TERM=linux",
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin",
        NULL };
    int i;
    ENTER;

    dev_name = kmalloc(PATHNAME_LEN, GFP_ATOMIC);
    if (dev_name == NULL) {
    	result = -ENOMEM;
    	goto out;
    }
    snprintf(dev_name, PATHNAME_LEN, "%s", name);

    rna_printk(KERN_INFO, "Stopping device: %s\n", dev_name);

    i=0;
    argv[i++] = "/opt/dell/fluidcache/bin/fldc_stop";
    argv[i++] = dev_name;
    argv[i++] = NULL;

    result = call_usermodehelper(argv[0], argv, stop_envp, 1);

out:
    if( 0 != result ) {
        printk( "%s: Failed to run class stop script for device: %s result %d\n",__FUNCTION__,dev_name,result );
        ret = result;
    }

    kfree(dev_name);

    EXIT;
#endif /*WINDOWS_KERNEL*/
}

/**
 * Makes a block device configfs item as if its directory was created by some process 
 *
 * Runs in kthread context, and may take a while
 */
void rnablk_make_device_item(char *name)
{
#ifdef WINDOWS_KERNEL
	UNREFERENCED_PARAMETER(name);
#else
    int result;
    // this is too big for the stack - dynamically allocate instead
    char *dev_path;
    char *argv[4], *envp[1];
    int i;
    ENTER;

    dev_path = kmalloc(PATHNAME_LEN, GFP_ATOMIC);
    if (dev_path == NULL) {
        result = -ENOMEM;
        goto out;
    }
    snprintf(dev_path, PATHNAME_LEN, RNABLK_DEVICE_ITEM_PATH "/%s", name);

    rna_printk(KERN_INFO, "Making directory %s\n", dev_path);

    i=0;
    argv[i++] = "/bin/mkdir";
    argv[i++] = "-p";
    argv[i++] = dev_path;
    argv[i++] = NULL;

    i=0;
    envp[i++] = NULL;

    result = call_usermodehelper(argv[0], argv, envp, 1);

out:
    if( 0 != result )
        printk( "%s: Failed to create device %s\n",__FUNCTION__,dev_path );

    kfree(dev_path);

    EXITV;
#endif /*WINDOWS_KERNEL*/
}

#ifndef WINDOWS_KERNEL

/* 0 == success */
int rnablk_apply_device_capacity(struct rnablk_device *dev, uint64_t capacity)
{
    int do_register = 0;
    ENTER;

    if (0 == atomic_read(&dev->registered_with_os)) {
        dev->device_cap = capacity;
        if(RNABLK_CACHE_ONLINE == atomic_read(&dev->stats.status)) {
            do_register = 1;
        } else {
            rna_printk(KERN_ERR,
                       "device [%s] in unexpected state [%s]\n",
                       dev->name,
                       get_rnablk_cache_status_string(atomic_read(&dev->stats.status)));
        }
    }
    else
        ret = -EINVAL;

    if( do_register )
        rnablk_deferred_register_block_device( dev );

    EXIT;
}

/* 0 == success */
int
rnablk_apply_shareable(struct rnablk_device *dev, int shareable)
{
    ENTER;

    /* shareable can't be changed if device creation has started, or set if the freeable flag is set */
    if (RNABLK_CACHE_OFFLINE != atomic_read(&dev->stats.status) &&
        shareable && !dev_is_freeable(dev)) {
        rna_printk(KERN_ERR,
                   "device [%s] in unexpected state [%s]\n",
                   dev->name,
                   get_rnablk_cache_status_string(atomic_read(&dev->stats.status)));
        ret = -EINVAL;
    } else if (shareable) {
        dev_set_shareable(dev);
    } else {
        dev_clear_shareable(dev);
    }

    EXIT;
}

/* 0 == success */
int rnablk_apply_persist_location(struct rnablk_device *dev, const char *location)
{
    ENTER;

    /* location can't be changed if device creation has started */
    if (RNABLK_CACHE_OFFLINE != atomic_read(&dev->stats.status)) {
        rna_printk(KERN_ERR,
                   "device [%s] in unexpected state [%s]\n",
                   dev->name,
                   get_rnablk_cache_status_string(atomic_read(&dev->stats.status)));
        GOTO(err, -EINVAL);
    }

    if (strlen(location) > sizeof(dev->persist_location)) {
        GOTO(err, -EINVAL);
    }

    if (strlen(location) > 0) {
        dev_set_persistent(dev);
    } else {
        dev_clear_persistent(dev);
    }
    strncpy(&dev->persist_location[0], location, sizeof(dev->persist_location));

    /* Persistent devices are always freeable */
    if (dev_is_persistent(dev)) {
        dev_set_freeable(dev);
    }

 err:
    EXIT;
}

/* 0 == success */
int rnablk_apply_access_uid(struct rnablk_device *dev, int uid)
{
    ENTER;

    /* access_uid can't be changed if device creation has started */
    if (RNABLK_CACHE_OFFLINE != atomic_read(&dev->stats.status)) {
        rna_printk(KERN_ERR,
                   "device [%s] in unexpected state [%s]\n",
                   dev->name,
                   get_rnablk_cache_status_string(atomic_read(&dev->stats.status)));
        ret = -EINVAL;
    } else {
        dev->access_uid = uid;
    }

    EXIT;
}

/* 0 == success */
int rnablk_apply_access_gid(struct rnablk_device *dev, int gid)
{
    ENTER;

    /* access_gid can't be changed if device creation has started */
    if (RNABLK_CACHE_OFFLINE != atomic_read(&dev->stats.status)) {
        rna_printk(KERN_ERR,
                   "device [%s] in unexpected state [%s]\n",
                   dev->name,
                   get_rnablk_cache_status_string(atomic_read(&dev->stats.status)));
        ret = -EINVAL;
    } else {
        dev->access_gid = gid;
    }

    EXIT;
}

/* 0 == success */
int rnablk_apply_freeable(struct rnablk_device *dev, int freeable)
{
    ENTER;

    /* freeable can't be set if the shareable flag is set */
    if (freeable && dev_is_shareable(dev)) {
        GOTO(err, -EINVAL);
    }

    /* Freeable can't be cleared if the device is persistent */
    if( !freeable && dev_is_persistent(dev)) {
        GOTO(err, -EINVAL);
    }

    if (freeable) {
        dev_set_freeable(dev);
    } else {
        dev_clear_freeable(dev);
    }

 err:
    EXIT;
}

/* 0 == success */
int rnablk_apply_cache_blk_size(struct rnablk_device *dev, uint32_t cache_blk_size)
{
    ENTER;

    /* cache_blk_size can't be changed if device creation has started */
    if (RNABLK_CACHE_OFFLINE != atomic_read(&dev->stats.status)) {
        rna_printk(KERN_ERR,
                   "device [%s] in unexpected state [%s]\n",
                   dev->name,
                   get_rnablk_cache_status_string(atomic_read(&dev->stats.status)));
        ret = -EINVAL;
    } else {
        dev->cache_blk_size = min(RNABLK_MAX_CACHE_BLK_SIZE, (int)cache_blk_size);
    }

    EXIT;
}

int rnablk_is_driver_in_use( void )
{
    struct list_head *pos;
    struct rnablk_device *dev;
    unsigned char oldirql = 0;
    ENTER;

    rna_down_read( &rnablk_dev_list_lock, &oldirql );

    list_for_each( pos,&rnablk_dev_list ) {
        dev = list_entry( pos,struct rnablk_device,l );
        if (dev_openers_is_open(dev)) {
            ret = 1;
            break;
        }
    }

    rna_up_read( &rnablk_dev_list_lock, oldirql );

    EXIT;
}
#endif /*WINDOWS_KERNEL*/

void rnablk_device_update_histogram( struct rnablk_device *dev,int nr_sectors )
{
    int bytes = nr_sectors << RNABLK_SECTOR_SHIFT;

    if ( bytes < SIZE_4K )
        dev->stats.histo[0]++;
    else if(likely( bytes == SIZE_4K ))
        dev->stats.histo[1]++;
    else if(unlikely( bytes <= SIZE_16K ))
        dev->stats.histo[2]++;
    else if(likely( bytes <= SIZE_32K ))
        dev->stats.histo[3]++;
    else if( bytes <= SIZE_64K )
        dev->stats.histo[4]++;
    else if( bytes <= SIZE_128K )
        dev->stats.histo[5]++;
    else if( bytes <= SIZE_256K )
        dev->stats.histo[6]++;
    else if( bytes <= SIZE_512K )
        dev->stats.histo[7]++;
    else
        dev->stats.histo[8]++;
}

/**
 * Update the device's writing_blocks and reading_blocks counts for
 * this block's current state, possibly removing any counts it was
 * previously contributing towards.
 *
 * A block is counted as either a writer or a reader or niether, but
 * not both.
 * 
 * Caller must hold block's bl_lock
 */
void rnablk_cache_blk_update_dev_counts(struct cache_blk *blk)
{
    rnablk_cache_blk_state_t last_state;
    int writer_delta = 0;
    int reader_delta = 0;
    
    BUG_ON(NULL==blk);
    
    last_state = blk->dev_counts_state;
    if (last_state == blk->state) return;
    blk->dev_counts_state = blk->state;

    /* If we were writable last time ... */
    if (rnablk_cache_blk_state_is_writable(last_state)) {
        /* Remove that contribution */
        writer_delta--;        
    } else {
        /* If we were not writable last time, but were readable ... */
        if (rnablk_cache_blk_state_is_readable(last_state)) {
            /* Remove previous reader count contribution */
            reader_delta--;
        }
    }

    /* If we are now writable ... */
    if (rnablk_cache_blk_state_is_writable(blk->state)) {
        /* Add that contribution */
        writer_delta++;        
    } else {
        /* If we are not writable now, but are readable ... */
        if (rnablk_cache_blk_state_is_readable(blk->state)) {
            /* Add new reader count contribution */
            reader_delta++;
        }
    }

    if (writer_delta > 0) {
        BUG_ON(reader_delta > 0);
        atomic_inc(&blk->dev->stats.writing_blocks);
    } else if (writer_delta < 0) {
        BUG_ON(reader_delta < 0);
        if (unlikely(!atomic_add_unless(&blk->dev->stats.writing_blocks, -1, 0))) {
            rna_printk(KERN_ERR, "[%s] writing_blocks would go negative\n", blk->dev->name);
        }
    }

    if (reader_delta > 0) {
        BUG_ON(writer_delta > 0);
        atomic_inc(&blk->dev->stats.reading_blocks);
    } else if (reader_delta < 0) {
        BUG_ON(writer_delta < 0);
        if (unlikely(!atomic_add_unless(&blk->dev->stats.reading_blocks, -1, 0))) {
            rna_printk(KERN_ERR, "[%s] reading_blocks would go negative\n", blk->dev->name);
        }
    }
}


/*
 * Mark a device as failed and do proper processing.
 * Returns FALSE if the device is already marked as fail
 *         TRUE otherwise
 */
int
rnablk_device_fail(struct rnablk_device *dev)
{
    lockstate_t irqflags;
    int ret = FALSE;

    if (FALSE == atomic_cmpxchg(&dev->failed, FALSE, TRUE)) {
        rna_printk(KERN_ERR, "failing dev [%s]\n", dev->name);
        /*
         * Though we may have zero blocks for this device (as when
         * starting after a CS containing this block device's
         * masterblock has failed), ensure that at least one failed
         * block is reported to the CFM so the device will be marked
         * as failed in the status display.
         */
        if (0 == dev->stats.failed_blocks) {
            dev->stats.failed_blocks++;
        }

        rna_spin_lock_irqsave(dev->rbd_event_lock, irqflags);
        wake_up_all(&dev->rbd_event_wait);
        rna_spin_unlock_irqrestore(dev->rbd_event_lock, irqflags);

        ret = TRUE;
    }
    return ret;
}

#ifndef WINDOWS_KERNEL
int rnablk_print_devs(char *buf, int buf_size)
{
    struct list_head *pos;
    struct rnablk_device *this_dev = NULL;
    int buf_remaining = buf_size;
    unsigned char oldirql = 0;
    ENTER;

    *buf = '\0';
    rna_down_read( &rnablk_dev_list_lock, &oldirql );
    list_for_each( pos,&rnablk_dev_list ) {
        this_dev = list_entry( pos,struct rnablk_device,l );
        if (buf_remaining < strlen(this_dev->name) +2) {
            break;
        }
        strcat(buf, this_dev->name);
        buf_remaining -= strlen(this_dev->name);
        strcat(buf, "\n");
        buf_remaining -= 1;
    }
    rna_up_read( &rnablk_dev_list_lock, oldirql );

    ret = strlen(buf);
    EXIT;
}

#endif  /*WINDOWS_KERNEL*/

void
rnablk_free_cache_blks(struct rnablk_device *dev,
                       boolean do_invalid_only)
{
    struct cache_blk *blk;
#ifdef WINDOWS_KERNEL
    struct cache_blk ** rbn;
    struct cache_blk **next_blk;
    PVOID restartKey;
#else
    struct rb_node *next;
#endif /*WINDOWS_KERNEL*/

    lockstate_t flags;
    int n_unfreed;
#define FREE_BLKS_MS_TIME       300
#define MAX_FREE_BLK_RETRIES    ((60*1000)/FREE_BLKS_MS_TIME)   // ~1 minute
    int n_retry = 0;
    int first_pass = TRUE;
    unsigned char oldirql = 0;

    ENTERV;

    do {
        n_unfreed = 0;
        rna_down_write(&dev->cache_blk_lock, &oldirql);
#ifdef WINDOWS_KERNEL
        rbn = rb_first(&dev->cache_blk_root, &restartKey);
        if(rbn == NULL)
            blk = NULL;
        else
            blk = *rbn;
#else
        blk = container_of(rb_first(&dev->cache_blk_root), struct cache_blk,
                           rbn );
#endif /*WINDOWS_KERNEL*/
        while (blk != NULL) {
#ifdef WINDOWS_KERNEL
            next_blk = rb_next(&dev->cache_blk_root, &restartKey);
#else
            next = rb_next(&blk->rbn);
#endif /*WINDOWS_KERNEL*/
            /* Move failed and disconnected blocks to a deletable state. */
            rnablk_lock_blk_irqsave(blk, flags);

            if (!do_invalid_only || RNABLK_CACHE_BLK_INVALID == blk->state) {
                if (1 == atomic_read(&blk->ref_count)
                    && (RNABLK_CACHE_BLK_INVALID == blk->state
                        || RNABLK_CACHE_BLK_DISCONNECTED == blk->state)) {
                    if (do_invalid_only) {
                        rna_printk(KERN_NOTICE, "Freeing invalid blk "
                                   "[%"PRIu64"]\n", blk->block_number);
                    }
                    rnablk_cache_blk_state_set(blk,
                                               RNABLK_CACHE_BLK_DELETE_PENDING);
                    rnablk_cache_blk_unlink_nolock(blk);
                    rnablk_unlock_blk_irqrestore(blk, flags);
                    rnablk_cache_blk_release(blk);
                } else {
                    if (first_pass) {
                        rna_printk(KERN_WARNING, "not freeing [%s] block "
                               "[%"PRIu64"] in state [%s] with refcnt "
                               "["BLKCNTFMT"]\n",
                               blk->dev->name, blk->block_number,
                               rnablk_cache_blk_state_string(blk->state),
                               BLKCNTFMTARGS(blk));
                    }
                    rnablk_unlock_blk_irqrestore(blk, flags);
                    n_unfreed++;
                }
            } else {
                rnablk_unlock_blk_irqrestore(blk, flags);
            }
#ifdef WINDOWS_KERNEL
            if(next_blk == NULL){
                blk = NULL;
            }
            else{
                blk = *next_blk;
            }
#else
            blk = container_of(next, struct cache_blk,rbn);
#endif /*WINDOWS_KERNEL*/
        }
        rna_up_write( &dev->cache_blk_lock, oldirql );
        first_pass = FALSE;
        if (n_unfreed) {
            msleep_interruptible(FREE_BLKS_MS_TIME);
        }
    } while (n_unfreed && n_retry++ < MAX_FREE_BLK_RETRIES);
    if (n_unfreed) {
        rna_printk(KERN_WARNING, "Unable to free %d blks\n", n_unfreed);
    }
    EXITV;
}

int
rnablk_invalidate_cache_blks(struct rnablk_device *dev)
{
    ENTER;
    // free nodes of the cache_blk tree
    rnablk_free_cache_blks(dev, FALSE);
    EXIT;
}

/* 
 * If there are no openers, dereferences all blocks and waits for that
 * and all other pending IO to complete.
 *
 * Then if there are still 0 openers, releases all references on
 * blocks in this device, then waits for all blocks to become valid
 * again (which they do when we get the change_ref response).
 * Quit waiting if the device gets opened again.
 */
void
rnablk_quiesce(struct rnablk_device *dev)
{
#define QUIESCE_MS_TIME         300
#define MAX_QUIESCE_RETRIES     ((3*60*1000)/QUIESCE_MS_TIME) // ~3 minutes
#ifdef WINDOWS_KERNEL
    struct cache_blk **rbn;
    struct cache_blk **rbn_next;
    PVOID restartKey;
#else
    struct rb_node *rbn,*rbn_next;
#endif /*WINDOWS_KERNEL*/
    struct cache_blk *blk;
    lockstate_t flags;
    int n_notready;
    int n_retry = 0;
    int verbose = 0;
    unsigned char oldirql = 0;

    if (dev_openers_is_open(dev)) {
        return;
    }

    rna_printk(KERN_INFO, "Dropping references for device [%s]\n", dev->name);
    rnablk_deref_cache_blks(dev);

    rna_printk(KERN_INFO, "Awaiting IO completion for device [%s]\n",
               dev->name);
    do {
        n_notready = 0;
        rna_down_read( &dev->cache_blk_lock, &oldirql );
#ifdef WINDOWS_KERNEL
        rbn = rb_first( &dev->cache_blk_root, &restartKey );
#else
        rbn = rb_first( &dev->cache_blk_root );
#endif /*WINDOWS_KERNEL*/
        rnablk_trc_master(1, "top-of-loop rbn=%p\n", rbn);
        while (!dev_openers_is_open(dev) && (rbn != NULL)) {

#ifdef WINDOWS_KERNEL
            rbn_next = rb_next(&dev->cache_blk_root, &restartKey);
            blk = *rbn;
#else
            rbn_next = rb_next( rbn );
            blk = container_of( rbn,struct cache_blk,rbn );
#endif /*WINDOWS_KERNEL*/

            rnablk_lock_blk_irqsave(blk, flags);
            if (!rnablk_cache_blk_state_is_disconnected(blk->state) &&
                !rnablk_cache_blk_state_is_unreferenced(blk->state)) {
                if (verbose) {
                    rna_printk(KERN_NOTICE,
                          "[%s] block [%"PRIu64"] not unreferenced, in state "
                          "[%s] refcnt ["BLKCNTFMT"]\n", blk->dev->name,
                          blk->block_number,
                          rnablk_cache_blk_state_string(blk->state),
                          BLKCNTFMTARGS(blk));
                }
                /* block is unlocked on return... */
                rnablk_cache_blk_drop_ref(blk, &flags, DEREF_NO_RESP);
                rnablk_start_blk_io(blk, FALSE);
                n_notready++;
            } else if (1 != atomic_read(&blk->ref_count)) {
                if (verbose) {
                    rna_printk(KERN_NOTICE, "[%s] block [%"PRIu64"] in state "
                          "[%s] refcnt ["BLKCNTFMT"] connl %s empty\n",
                          blk->dev->name,
                          blk->block_number,
                          rnablk_cache_blk_state_string(blk->state),
                          BLKCNTFMTARGS(blk),
                          (blk_lru_list_empty(&blk->cb_conn_lru)
                          ? "is" : "is not"));
                }
                rnablk_unlock_blk_irqrestore(blk, flags);
                n_notready++;
            } else {
                rnablk_unlock_blk_irqrestore(blk, flags);
                rnablk_trc_master(1, "[%s] block [%"PRIu64"] good to go, in "
                                  "state [%s] refcnt ["BLKCNTFMT"]\n",
                                  blk->dev->name, blk->block_number,
                                  rnablk_cache_blk_state_string(blk->state),
                                  BLKCNTFMTARGS(blk));
            }
            rbn = rbn_next;
        }
        rna_up_read( &dev->cache_blk_lock, oldirql );
        if (n_notready) {
            rnablk_trc_master(1, "unable to quiesce %d blks, retrying\n",
                              n_notready);
            msleep_interruptible(QUIESCE_MS_TIME);
            rnablk_wake_up_all(FALSE);
        }
        if (n_retry == MAX_QUIESCE_RETRIES - 1) {
            verbose = 1;
        }
    } while (n_notready && n_retry++ < MAX_QUIESCE_RETRIES);

    /* Check MASTER_BLK as well */
    verbose = 0;
    n_retry = 0;
    blk = MASTER_BLK(dev);
    do {
        rna_down_read(&dev->cache_blk_lock, &oldirql);
        if (dev_openers_is_open(dev)) {
            rna_up_read(&dev->cache_blk_lock, oldirql);
            break;
        }
        rnablk_lock_blk_irqsave(blk, flags);
        if ((2 == atomic_read(&blk->ref_count)
             && !blk_lru_list_empty(&blk->cb_conn_lru))
            || (1 == atomic_read(&blk->ref_count)
                && blk_lru_list_empty(&blk->cb_conn_lru))) {
            rnablk_unlock_blk_irqrestore(blk, flags);
            rna_up_read(&dev->cache_blk_lock, oldirql);
            rnablk_trc_master(1, "[%s] MASTER block [%"PRIu64"] good to go, in "
                              "state [%s] refcnt ["BLKCNTFMT"]\n",
                              blk->dev->name, blk->block_number,
                              rnablk_cache_blk_state_string(blk->state),
                              BLKCNTFMTARGS(blk));
            break;
        }
        if (verbose) {
            rna_printk(KERN_NOTICE, "[%s] MASTER block [%"PRIu64"] in state "
                      "[%s] refcnt ["BLKCNTFMT"] connl %s empty\n",
                      blk->dev->name, blk->block_number,
                      rnablk_cache_blk_state_string(blk->state),
                      BLKCNTFMTARGS(blk),
                      (blk_lru_list_empty(&blk->cb_conn_lru)
                      ? "is" : "is not"));
        }
        rnablk_unlock_blk_irqrestore(blk, flags);
        rna_up_read(&dev->cache_blk_lock, oldirql);
        msleep_interruptible(QUIESCE_MS_TIME);
        rnablk_wake_up_all(FALSE);
        /*
         * Note we only retry if n_notready is clear; otherwise we
         * already waited 3 minutes above, so not much use in waiting
         * longer!
         */
        if (n_retry == MAX_QUIESCE_RETRIES - 1) {
            verbose = 1;
        }
    } while (!n_notready && n_retry++ < MAX_QUIESCE_RETRIES);

    if (n_notready || n_retry >= MAX_QUIESCE_RETRIES) {
        rna_printk(KERN_ERR, "Unable to quiesce all blks for device [%s]\n",
                   dev->name);
    }
    rna_printk(KERN_NOTICE, "IO complete for device [%s]\n", dev->name);
    return;
}

#ifndef WINDOWS_KERNEL

struct rnablk_device *rnablk_find_device_by_path( char *path )
{
    struct rnablk_device *dev = NULL;
    unsigned char oldirql = 0;

    ENTER;

    rna_down_read( &rnablk_dev_list_lock, &oldirql );
    dev = rnablk_find_device_by_path_nolock(path);
    rna_up_read( &rnablk_dev_list_lock, oldirql );

    EXITPTR( dev );
}
#endif /*WINDOWS_KERNEL*/

void
rnablk_restart_dev_blks(rnablk_workq_cb_arg_t arg)
{
    struct work_struct *work = (struct work_struct *)arg;
    struct rnablk_work *w = container_of( work,struct rnablk_work,work );
    struct rnablk_restart_dev_blks_data *wd =
                                        &w->data.rwd_rnablk_restart_dev_blks;
    struct rnablk_device *dev = wd->dev;
    uint64_t       start_seconds = get_seconds();
    unsigned char oldirql = 0;

    rna_down_read(&dev->cache_blk_lock, &oldirql);
    /*
     * Take care of MASTER, then others.  Call drain directly
     * on master, since it is already in the referenced state.
     */
    rnablk_cache_blk_drain(MASTER_BLK(dev));
    rnablk_cache_blk_foreach(&dev->cache_blk_root,
                              rnablk_cache_blk_restart_cb,
                              NULL,
                              0,
                              NULL);
    rna_up_read(&dev->cache_blk_lock, oldirql);
    if (NULL == dev->q) {
        rna_printk(KERN_ERR, "Not starting queue for dev [%s], because it "
                   "hasn't been created yet\n", wd->dev->name);
    } else {
        rna_printk(KERN_ERR, "Starting queue for dev [%s]\n", dev->name);
#ifndef WINDOWS_KERNEL
        rnablk_clear_dev_queue_stop_flag(dev, RNABLK_Q_STOP_DISCONN);
#endif /*WINDOWS_KERNEL*/
        // this may be needed if enforcer was in affect before failure
        // rnablk_schedule_enforcer(dev);
    }
    rnablk_dev_release(dev);
    rnablk_mempool_free( w, work_cache_info );
    rnablk_finish_workq_work(start_seconds);
}

void rnablk_queue_restart_dev_blks(struct rnablk_device *dev)
{
    struct rnablk_work *w = NULL;
    struct rnablk_restart_dev_blks_data *wd = NULL;
    BUG_ON(NULL == dev);

    if (!atomic_read(&shutdown) &&
        !atomic_read(&rna_service_detached) &&
        rnablk_dev_acquire(dev)) {
        if( (w = rnablk_mempool_alloc( work_cache_info )) == NULL ) {
            rna_printk(KERN_ERR, "Failed to allocate workq item\n");
            rnablk_dev_release(dev);
        } else {
            RNABLK_INIT_RNABLK_WORK(w, wd, rnablk_restart_dev_blks);
            wd->dev  = dev;
            rna_queue_work(mt_workq, &w->work);
        }
    }
}

static void
rnablk_delayed_master_blk_lock(rnablk_workq_cb_arg_t arg)
{
    rnablk_dwork_t w = RNABLK_ARG_DWORK(arg);
    struct rnablk_delayed_master_blk_lock_data *wd = 
                                    &w->data.rwd_rnablk_delayed_master_blk_lock;
    uint64_t start_seconds = get_seconds();

    atomic_bit_clear(&MASTER_BLK(wd->dev)->cb_flags,
                     BLK_F_QUEUED_MASTER_LOCK);

    if (!rnablk_dev_is_shutdown(wd->dev)
        && !atomic_read(&shutdown)) {
        rnablk_lock_master_blk(wd->dev);
    }
    rnablk_dev_release(wd->dev);

    if( w->delayed )
        atomic_dec( &delayed_work );
    RNABLK_FREE_DWORK(w);
    rnablk_finish_workq_work(start_seconds);
}

void
rnablk_queue_delayed_master_blk_lock(struct rnablk_device *dev)
{
#define RNABLK_MASTER_SHORT_DELAY_RETRY_LIMIT   30
#define     RNABLK_MASTER_BLOCK_DELAY_SHORT     (5 * HZ)    // 5 seconds
#define     RNABLK_MASTER_BLOCK_DELAY_LONG      (20 * HZ)   // 20 seconds
    rnablk_dwork_t w;
    unsigned long delay;

    BUG_ON(NULL == dev);

    if (!atomic_read(&shutdown) &&
        !atomic_read(&rna_service_detached) &&
        rnablk_dev_acquire(dev)) {
        w = RNABLK_ALLOC_DWORK();
        if (NULL == w) {
            rna_printk(KERN_ERR, "Failed to allocate workq item\n");
            rnablk_dev_release(dev);
        } else if (atomic_bit_test_and_set(&MASTER_BLK(dev)->cb_flags,
                                           BLK_F_QUEUED_MASTER_LOCK)) {
            rna_printk(KERN_INFO, "queueing reconnect to dev [%p] [%s] "
                       "cache_file_nem [%s] in 5 seconds\n",
                       dev,
                       dev->name,
                       dev->cache_file_name);
            /*
             * If we've had to retry lots of times, something likely is
             * causing a problem.  Increase the delay between retry attempts,
             * just to reduce thrash. 
             */
            delay = atomic_get(&dev->dv_master_blk->retries)
                        <= RNABLK_MASTER_SHORT_DELAY_RETRY_LIMIT
                        ? RNABLK_MASTER_BLOCK_DELAY_SHORT
                        : RNABLK_MASTER_BLOCK_DELAY_LONG;
            RNABLK_INIT_DWORK(w, rnablk_delayed_master_blk_lock);
            w->data.rwd_rnablk_delayed_master_blk_lock.dev  = dev;
            /* this task allocates an ios, so use ios_workq */
            rna_queue_delayed_work(ios_workq, RNABLK_DWORK_OBJECT(w), delay);
        } else {
            RNABLK_FREE_DWORK(w);
        }
    }
}
