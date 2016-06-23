/**
 * <rnablk_device.h> - Dell Fluid Cache block driver
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

#include "rb.h"
#include "rnablk_system.h"
#include "rnablk_block_state.h"
#include "rnablk_util.h"


/*
 * MASTER_BLK   -- pointer to master_block struct for given device
 * MASTER_BLK_IS_CONNECTED -- determine whether we have a valid current
 *                         reference to the given master_block
 */
#define MASTER_BLK(dv)              ((dv)->dv_master_blk)
#define MASTER_BLK_IS_CONNECTED(dv) (rnablk_blk_connected(MASTER_BLK(dv)))
#define MASTER_BLK_CONN(dv)         (MASTER_BLK(dv)->cb_conn)

/*
 * dev_new_openers macros to manipulate whether we will allow new openers
 * in the future, even when there may currently BE openers.
 *
 * These macros closely resemble the dev_openers...() macros.  The distinction
 * is that the dev_openers.. macro operate in the openers count for the device
 * directly, will generally have an effect only if the openers count is either
 * zero or -1.
 *
 * These macros can operate on a device that currently has openers, and
 * will allow those current openers to continue, but will allow no NEW openers.
 * Then when the openers count goes to zero in the release() routine, it will
 * force use the dev_openers... macro to do the final teardown of the
 * device.
 */
#define dev_new_openers_are_disabled(d) \
    (atomic_read(&(d)->disable_new_openers) == 1)

#define dev_new_openers_are_enabled(d) \
    (atomic_read(&(d)->disable_new_openers) == 0)

#define dev_new_openers_disable(d) \
    (atomic_cmpxchg(&(d)->disable_new_openers, 0, 1))

#define dev_new_openers_enable(d) \
    (atomic_cmpxchg(&(d)->disable_new_openers, 1, 0))


/*
 * dev_openers macros to track device opens.
 * We use the special value of -1 to disable future opens (used during
 * device teardown).
 */
#define dev_openers_is_open(d)       (atomic_read(&(d)->stats.openers) > 0)
#define dev_openers_is_disabled(d)   (atomic_read(&(d)->stats.openers) < 0)

/* returns TRUE if we successfully disabled opens */
#define dev_openers_set_disabled(d) \
            (atomic_cmpxchg(&(d)->stats.openers, 0, -1) == 0)

/* returns TRUE on success, else FALSE */
#define dev_openers_do_open(d) \
            (atomic_add_nonnegative(1, &(d)->stats.openers))

/* returns current open count */
#define dev_openers_do_close(d)     atomic_dec_return(&(d)->stats.openers)




int rnablk_invalidate_cache_blks(struct rnablk_device *dev);
void rnablk_free_cache_blks(struct rnablk_device *dev,
                            boolean do_invalid_only);
void rnablk_cache_blk_update_dev_counts(struct cache_blk *blk);
int rnablk_device_fail(struct rnablk_device *dev);

void rnablk_queue_delayed_master_blk_lock(struct rnablk_device *dev);

#ifndef WINDOWS_KERNEL
struct rnablk_device * rnablk_find_device(char *name);
struct rnablk_device * rnablk_find_device_by_path( char *path );
struct rnablk_device * rnablk_find_device_by_path_nolock(char *path);


struct rnablk_device * rnablk_find_device_by_addr(void *find_dev);
struct rnablk_device * rnablk_find_device_by_addr_nolock(void *find_dev);
#endif

void rnablk_quiesce(struct rnablk_device *dev);
void rnablk_deref_cache_blks(struct rnablk_device *dev);
void rnablk_device_update_histogram(struct rnablk_device *dev, int nr_sectors);
void rnablk_restart_dev_blks(rnablk_workq_cb_arg_t arg);

void rnablk_queue_restart_dev_blks(struct rnablk_device *dev);

void rnablk_make_device_item(char *name);
void rnablk_remove_device_item(char *name);
int rnablk_stop_device_item(char *name);

void rnablk_disconnect_device(struct rnablk_device *dev);

int rnablk_apply_device_capacity(struct rnablk_device *dev, uint64_t capacity);
int rnablk_apply_persist_location(struct rnablk_device *dev, const char *location);
int rnablk_apply_access_uid(struct rnablk_device *dev, int uid);
int rnablk_apply_access_gid(struct rnablk_device *dev, int gid);
int rnablk_apply_shareable(struct rnablk_device *dev, int shareable);
int rnablk_apply_freeable(struct rnablk_device *dev, int freeable);
int rnablk_apply_cache_blk_size(struct rnablk_device *dev, uint32_t cache_blk_size);
void rnablk_notify_mount_event(struct rnablk_device *dev, int32_t value);

struct rnablk_device * rnablk_make_device(const char *name);

void rnablk_destroy_device(struct rnablk_device *dev);
int rnablk_is_driver_in_use( void );
void rnablk_detached_shutdown_cleanup_devices(void);

//
// Extremely verbose
//#define DEBUG_IN_FLIGHT 1

INLINE void inc_in_flight(struct rnablk_device *dev, struct io_state *ios)
{
    BUG_ON(NULL==ios);
    if (atomic_bit_test_and_set(&ios->ios_atomic_flags, IOS_AF_INFLIGHT)) {
        if (NULL != dev) {
            atomic_inc(&dev->stats.in_flight);
#if defined(DEBUG_IN_FLIGHT)
            rna_printk(KERN_ERR, "inc %d ios %p tag "TAGFMT" type %d\n",
                       atomic_read(&dev->stats.in_flight),
                       ios, TAGFMTARGS(ios->tag), ios->type);
#endif
        }
    } else {
        rna_printk(KERN_ERR, "ios already in flight: ios [%p] tag ["TAGFMT"] "
                   "type %d\n", ios, TAGFMTARGS(ios->tag), ios->type);
        dump_stack();
    }
}

INLINE void dec_in_flight(struct rnablk_device *dev, struct io_state *ios)
{
    BUG_ON(NULL==ios);
    if (atomic_bit_test_and_clear(&ios->ios_atomic_flags, IOS_AF_INFLIGHT)) {
        if (NULL != dev) {
            atomic_dec(&dev->stats.in_flight);
#if defined(DEBUG_IN_FLIGHT)
            rna_printk(KERN_ERR, "dnc %d ios [%p] tag ["TAGFMT"] type %d\n",
                       atomic_read(&dev->stats.in_flight),
                       ios, ios ? TAGFMTARGS(ios->tag) : 0,
                       ios ? ios->type : -1);
#endif
        }
    } else {
        rna_printk(KERN_INFO,
                   "ios [%p] tag ["TAGFMT"] type [%s] not in flight\n",
                   ios, ios ? TAGFMTARGS(ios->tag): 0,
                   rnablk_op_type_string(ios ? ios->type : -1));
        //dump_stack(); 
    }
}

/**
 * Returns the number of blocks in this device, including any final "short"
 * block if this device's size is not a multipe of its cache block size.
 */
INLINE uint64_t rnablk_get_block_count(struct rnablk_device *dev) 
{
    uint64_t block_count;

    BUG_ON(NULL == dev);

    if (unlikely((0 == dev->device_cap) || (0 == dev->cache_blk_size))) {
        return 0;
    }

    block_count = dev->device_cap / dev->cache_blk_size;
    /* Ensure block count includes the last block if its' not full sized */
    if (0 != (dev->device_cap % dev->cache_blk_size)) {
        block_count++;
    }
    return block_count;
}
