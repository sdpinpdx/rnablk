/**
 * <cfs.c> - Dell Fluid Cache block driver
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

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include <linux/completion.h>
#include <linux/version.h>
#include "trace.h"
#include "rna_com_linux_kernel.h"
#include "rb.h"
#include "rnablk_block_state.h"
#include "rnablk_io_state.h"
#include "rnablk_protocol.h"
#include "rnablk_globals.h"
#include "rnablk_cache.h"
#include "rnablk_device.h"
#include "rnablk_comatose.h" // for rnablk_enable_enforcer

static char rqs_flags_str[1024];

static inline struct rnablk_device *to_rnablk_dev( struct config_item *item )
{
	return item ? container_of( item,struct rnablk_device,item ) : NULL;
}

static struct configfs_attribute rnablk_dev_attr_class_name = {
	.ca_owner = THIS_MODULE,
	.ca_name = "class_name",
	.ca_mode = S_IRUGO,
};

static struct configfs_attribute rnablk_dev_attr_class_params = {
	.ca_owner = THIS_MODULE,
	.ca_name = "class_params",
	.ca_mode = S_IRUGO,
};

static struct configfs_attribute rnablk_dev_attr_capacity = {
	.ca_owner = THIS_MODULE,
	.ca_name = "capacity",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_dev_attr_dot_drop_ref = {
	.ca_owner = THIS_MODULE,
	.ca_name = ".drop_ref",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_dev_attr_persistent = {
	.ca_owner = THIS_MODULE,
	.ca_name = "persistent",
	.ca_mode = S_IRUGO,
};

static struct configfs_attribute rnablk_dev_attr_persist_location = {
	.ca_owner = THIS_MODULE,
	.ca_name = "persist_location",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_dev_attr_persist_access_uid = {
	.ca_owner = THIS_MODULE,
	.ca_name = "persist_access_uid",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_dev_attr_persist_access_gid = {
	.ca_owner = THIS_MODULE,
	.ca_name = "persist_access_gid",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_dev_attr_shareable = {
	.ca_owner = THIS_MODULE,
	.ca_name = "shareable",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_dev_attr_freeable = {
	.ca_owner = THIS_MODULE,
	.ca_name = "freeable",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_dev_attr_cache_blk_size = {
	.ca_owner = THIS_MODULE,
	.ca_name = "cache_blk_size",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_dev_attr_status = {
	.ca_owner = THIS_MODULE,
	.ca_name = "status",
	.ca_mode = S_IRUGO,
};

static struct configfs_attribute rnablk_dev_attr_open_count = {
	.ca_owner = THIS_MODULE,
	.ca_name = "open_count",
	.ca_mode = S_IRUGO,
};

static struct configfs_attribute rnablk_dev_attr_disable_new_openers = {
	.ca_owner = THIS_MODULE,
	.ca_name = "disable_new_openers",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_dev_attr_stats = {
	.ca_owner = THIS_MODULE,
	.ca_name = "stats",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_dev_attr_dot_debug = {
	.ca_owner = THIS_MODULE,
	.ca_name = ".debug",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_dev_attr_mount_status = {
	.ca_owner = THIS_MODULE,
	.ca_name = "mount_status",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_dev_attr_dot_block_debug = {
	.ca_owner = THIS_MODULE,
	.ca_name = ".block_debug",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_dev_attr_dot_block_debug_xml = {
	.ca_owner = THIS_MODULE,
	.ca_name = ".block_debug.xml",
	.ca_mode = S_IRUGO,
};

static struct configfs_attribute rnablk_dev_attr_dot_block_debug_next_xml = {
	.ca_owner = THIS_MODULE,
	.ca_name = ".block_debug_next.xml",
	.ca_mode = S_IRUGO,
};

static struct configfs_attribute rnablk_dev_attr_dot_block_debug_busy_xml = {
	.ca_owner = THIS_MODULE,
	.ca_name = ".block_debug_busy.xml",
	.ca_mode = S_IRUGO,
};

static struct configfs_attribute rnablk_dev_attr_dma_reads_disabled = {
	.ca_owner = THIS_MODULE,
	.ca_name = "dma_reads_disabled",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_dev_attr_dma_writes_disabled = {
	.ca_owner = THIS_MODULE,
	.ca_name = "dma_writes_disabled",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_dev_attr_large_write_minsize = {
	.ca_owner = THIS_MODULE,
	.ca_name = "large_write_minsize",
	.ca_mode = S_IRUGO | S_IWUSR,
};

#ifdef TEST_STORAGE_ERROR
static struct configfs_attribute rnablk_dev_attr_dot_inject_storage_error = {
	.ca_owner = THIS_MODULE,
	.ca_name = ".inject_storage_error",
	.ca_mode = S_IRUGO | S_IWUSR,
};
#endif /* TEST_STORAGE_ERROR */

static struct configfs_attribute rnablk_dev_attr_dot_inject_device_fail = {
	.ca_owner = THIS_MODULE,
	.ca_name = ".inject_device_fail",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_dev_attr_quiesce_on_release = {
	.ca_owner = THIS_MODULE,
	.ca_name = "quiesce_on_release",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_dev_attr_max_io_size = {
	.ca_owner = THIS_MODULE,
	.ca_name = "max_io_size",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_dev_attr_disconnect = {
	.ca_owner = THIS_MODULE,
	.ca_name = "disconnect",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute *rnablk_dev_attrs[] = {
	&rnablk_dev_attr_class_name,
	&rnablk_dev_attr_class_params,
	&rnablk_dev_attr_capacity,
	&rnablk_dev_attr_dot_drop_ref,
	&rnablk_dev_attr_persistent,
	&rnablk_dev_attr_persist_location,
	&rnablk_dev_attr_persist_access_uid,
	&rnablk_dev_attr_persist_access_gid,
	&rnablk_dev_attr_shareable,
	&rnablk_dev_attr_freeable,
	&rnablk_dev_attr_cache_blk_size,
    &rnablk_dev_attr_status,
    &rnablk_dev_attr_stats,
    &rnablk_dev_attr_open_count,
    &rnablk_dev_attr_disable_new_openers,
    &rnablk_dev_attr_dot_debug,
    &rnablk_dev_attr_mount_status,
    &rnablk_dev_attr_dot_block_debug,
    &rnablk_dev_attr_dot_block_debug_xml,
    &rnablk_dev_attr_dot_block_debug_next_xml,
    &rnablk_dev_attr_dot_block_debug_busy_xml,
    &rnablk_dev_attr_dma_reads_disabled,
    &rnablk_dev_attr_dma_writes_disabled,
    &rnablk_dev_attr_large_write_minsize,
#ifdef TEST_STORAGE_ERROR
    &rnablk_dev_attr_dot_inject_storage_error,
#endif /* TEST_STORAGE_ERROR */
    &rnablk_dev_attr_dot_inject_device_fail,
    &rnablk_dev_attr_quiesce_on_release,
    &rnablk_dev_attr_max_io_size,
    &rnablk_dev_attr_disconnect,
	NULL,
};

static int
rnablk_format_ios_debug_info(char *buf, ssize_t bufsize,
                             struct rnablk_cache_ios_debug_info  *ios_dbg)
{
    struct io_state *ios;
    uint64_t blkno = ios_dbg->ios_blk_block_number;
    struct com_ep *blk_ep = ios_dbg->ios_blk_ep;
    char *name = ios_dbg->ios_blk_dev_name;
    int qstate;
    int count;

    ios = &ios_dbg->ios_snapshot;
    qstate = ios_queuestate_get(ios);
    count = snprintf(buf, bufsize,
                    "<ios "
                    "iosp=\"%p\" "          /* the address of the io_state */
                    "blkno=\"%"PRIu64"\" "  /* block number, 0 if NONT */
                    "blkep=\"%p\" "         /* ep stored in block */
                    "devnm=\"%s\" "         /* device name */
                    "iosep=\"%p\" "         /* ep stored in ios */
                    "%s=\"%p\" "            /* pointer to struct request */
                    "sg=\"%d\" "            /* nsgl  */
                    "type=\"%s\" "          /* rnablk_op_type */
                    "it=\"%"PRIu64"\" "     /* issue time */
                    "ss=\"%"PRId64"\" "     /* start sector */
                    "ns=\"%u\" "            /* number sectors */
                    "tag=\"%llu\" "           /* tag */
                    "%s"                    /* in dispatch queue */
                    "%s"                    /* in block queue */
                    "%s"                    /* in conn queue */
                    "%s"                    /* in wfc queue */
                    "%s"                    /* in flight */
                    "rc=\"%d\" "            /* ref count */
                    "pb=\"%d\" "            /* pending bios */
                    "%s"                    /* in tree */
                    "\\>\n",
                    ios_dbg->iosp,
                    blkno, 
                    blk_ep,
                    name,
                    ios->ep,
                    IOS_HAS_REQ(ios) ? "req" : "bio",
                    ios->ios_gen_ioreq,
                    ios->nsgl,
                    rnablk_op_type_string(ios->type),
                    ios->issue_time_ns,
                    ios->start_sector,
                    ios->nr_sectors,
                    ios->tag,
                    IOS_QS_DISPATCH == qstate ? "D=\"1\" " : "",
                    IOS_QS_BLOCK == qstate ? "B=\"1\" " : "",
                    IOS_QS_CONN == qstate ? "C=\"1\" " : "",
                    IOS_QS_WFC == qstate ? "W=\"1\" " : "",
                    atomic_bit_is_set(&ios->ios_atomic_flags, IOS_AF_INFLIGHT)
                    ? "F=\"1\" " : "",
                    atomic_read(&ios->ref_count),
                    atomic_read(&ios->pending_bios),
                    atomic_bit_is_set(&ios->ios_atomic_flags, IOS_AF_IN_TREE)
                    ? "T=\"1\" " : ""
                    );
    if (count > bufsize) {
        count = bufsize;
    }
    return count;
}

static ssize_t
rnablk_format_cache_blk_debug_info(char *buf, ssize_t bufsize,
                                   struct rnablk_cache_blk_debug_info *blk_info,
                                   char *next_blk_str)
{
    unsigned long this_second = get_seconds();
    struct rnablk_server_conn *conn;
    ssize_t count;
    int val = 0;

    conn = rnablk_get_ep_conn(blk_info->blk_snapshot.ep);
    if (conn) {
        val = conn->id.u.data.address;
    }
    count = snprintf(buf, bufsize,
                    "<blk "
                    "CS=\""NIPQUAD_FMT":%d\" " /* cache_server_ip:instance */
                    "n=\"%"PRIu64"\" "     /* cache block number */
                    "%s"            /* bl="1" if bl list is !empty */
                    "%s"            /* cl="1" if connl list is !empty */
                    "%s"            /* dq="1" if dispatch_queue is !empty */
                    "%s"            /* dev="1" if cb_dev_link list is !empty */
                    "state=\"%s\" "     /* block state enum */
                    "ios=\"%d\" "       /* outstanding ios */
                    "io=\"%d\" "        /* inflight_ios */
                    "ss=\"%"PRIu64"\" " /* start sector */
                    "es=\"%"PRIu64"\" " /* end sector */
                    "lws=\"%"PRIu64"\" "  /* last write time */
                    "lrs=\"%"PRIu64"\" "  /* last read time */
                    "wa=\"%"PRIu64"\" "   /* write age (now - lws) */
                    "ra=\"%"PRIu64"\" "   /* read age (now - rws) */
                    "rc=\"%d\" "          /* ref count (minus ours) */
                    "%s"                  /* 'nxt', next block (if any) */
                    "\\>\n",
                    NIPQUAD(val),
                    (conn) ? conn->id.u.data.number : 0,
                    blk_info->blk_snapshot.block_number,
                    blk_info->bl_empty ? "" : "bl=\"1\" ",
                    blk_info->connl_empty ? "" : "cl=\"1\" ",
                    blk_info->dispatch_queue_empty ? "" : "dq=\"1\" ",
                    blk_info->cbd_dev_empty ? "" : "dev=\"1\" ",
                    rnablk_cache_blk_state_string(blk_info->blk_snapshot.state),
                    atomic_read(&blk_info->blk_snapshot.cb_ioref_cnt),
                    atomic_read(&blk_info->blk_snapshot.inflight_ios),
                    blk_info->blk_snapshot.start_sector,
                    blk_info->blk_snapshot.end_sector,
                    blk_info->blk_snapshot.last_write_secs,
                    blk_info->blk_snapshot.last_read_secs,
                    this_second - blk_info->blk_snapshot.last_write_secs,
                    this_second - blk_info->blk_snapshot.last_read_secs,
                    atomic_read(&blk_info->blk_snapshot.ref_count) - 1,
                    next_blk_str ? next_blk_str : "");
    if (count > bufsize) {
        count = bufsize;
    }
    return count;
}

static inline void
rnablk_get_ios_debug_state(struct io_state *ios,
                           struct rnablk_cache_ios_debug_info *ios_info)
{
    ios_info->ios_snapshot = *ios;
    ios_info->iosp  = ios;
    memcpy(ios_info->ios_blk_dev_name, ios->dev->name, NAME_MAX+1);
    ios_info->ios_blk_block_number= 0;
    ios_info->ios_blk_ep= NULL;
    if (NULL != ios->blk) {
        ios_info->ios_blk_block_number = ios->blk->block_number;
        ios_info->ios_blk_ep = ios->blk->ep;
    }
}

ssize_t
rnablk_report_dispatched_ios(struct cache_blk *blk, char *buf, ssize_t bufsize)
{
    struct rnablk_cache_ios_debug_info ios_info;
    struct list_head *ent;
    lockstate_t irqflags;
    struct io_state *ios_array[64];
    struct io_state *ios;
    ssize_t len;
    ssize_t count = 0;
    int n_ios = 0;
    int i;

    rnablk_lock_blk_irqsave(blk, irqflags);
    list_for_each(ent, &blk->dispatch_queue) {
        if (n_ios >= 64) {
            rna_printk(KERN_ERR, "Not reporting all dispatched ios for "
                       "device [%s] block [%llu]\n", blk->dev->name,
                       blk->block_number);
            break;
        }
        ios = list_entry(ent, struct io_state, l);
        rnablk_ios_ref(ios);
        ios_array[n_ios++] = ios;
    }
    rnablk_unlock_blk_irqrestore(blk, irqflags);

    for (i = 0; i < n_ios && bufsize > 0; i++) {
        rnablk_get_ios_debug_state(ios_array[i], &ios_info);
        len = rnablk_format_ios_debug_info(buf+count, bufsize, &ios_info);
        rnablk_ios_release(ios_array[i]);
        bufsize -= len;
        count += len;
    }
    
    return count;
}

static ssize_t
rnablk_dev_attr_show( struct config_item *item,
                                     struct configfs_attribute *attr,
                                     char *buf )
{
    struct rnablk_device *dev;
    ssize_t bufsize = 4096;     // why isn't this passed in by caller??
	ssize_t count = 0;

    dev = to_rnablk_dev( item );

    if( strcmp( attr->ca_name,"capacity" ) == 0 )
        count = sprintf( buf,"%"PRIu64"\n",dev->device_cap );
    else if( strcmp( attr->ca_name,"class_name" ) == 0 )
        count = sprintf( buf,"%s\n",dev->class_name );
    else if( strcmp( attr->ca_name,"class_params" ) == 0 )
        count = sprintf( buf,"%s\n",dev->class_params );
    else if( strcmp( attr->ca_name,"persistent" ) == 0 )
        count = sprintf(buf, "%u\n", dev_is_persistent(dev));
    else if( strcmp( attr->ca_name,"open_count" ) == 0 )
        count = sprintf(buf, "%d\n", atomic_read(&dev->stats.openers));
    else if( strcmp( attr->ca_name,"disable_new_openers" ) == 0 )
        count = sprintf(buf, "%d\n", atomic_read(&dev->disable_new_openers));
    else if( strcmp( attr->ca_name,"persist_location" ) == 0 )
        count = sprintf( buf,"%s\n",dev->persist_location );
    else if( strcmp( attr->ca_name,"persist_access_uid" ) == 0 )
        count = sprintf( buf,"%u\n",dev->access_uid );
    else if( strcmp( attr->ca_name,"persist_access_gid" ) == 0 )
        count = sprintf( buf,"%u\n",dev->access_gid );
    else if( strcmp( attr->ca_name,"shareable" ) == 0 )
        count = sprintf(buf, "%d\n", dev_is_shareable(dev));
    else if( strcmp( attr->ca_name,"freeable" ) == 0 )
        count = sprintf(buf, "%d\n", dev_is_freeable(dev));
    else if( strcmp( attr->ca_name,"cache_blk_size" ) == 0 )
        count = sprintf( buf,"%llu\n",dev->cache_blk_size );
    else if( strcmp( attr->ca_name,"mount_status" ) == 0 )
        count = sprintf( buf,"%d\n",dev->mount_status );
    else if( strcmp( attr->ca_name,"status" ) == 0 ) {
        if (atomic_read(&dev->stats.status) == RNABLK_CACHE_ONLINE
            && atomic_read(&dev->failed)) {
            count = sprintf(buf, "failed\n");
        } else {
            count = sprintf( buf,"%s\n",
                            get_rnablk_cache_status_display_string(
                            atomic_read(&dev->stats.status)));
        }
    }
    else if( strcmp( attr->ca_name,"cache_blk_size" ) == 0 )
        count = sprintf( buf,"%llu\n",dev->cache_blk_size );
    else if( strcmp( attr->ca_name,"dma_reads_disabled" ) == 0 )
        count = sprintf(buf, "%d\n", dev_dma_reads_disabled(dev));
    else if( strcmp( attr->ca_name,"dma_writes_disabled" ) == 0 )
        count = sprintf(buf, "%d\n", dev_dma_writes_disabled(dev));
    else if( strcmp( attr->ca_name,"large_write_minsize" ) == 0 )
        count = sprintf(buf, "%llu\n",
                        dev->rbd_large_write_sects * RNABLK_SECTOR_SIZE);
#ifdef TEST_STORAGE_ERROR
    else if( strcmp( attr->ca_name,".inject_storage_error" ) == 0 )
        count = sprintf( buf,"Write a number to this file to inject 'n'"
                        "block query storage errors for this device\n");
#endif /* TEST_STORAGE_ERROR */
    else if (strcmp(attr->ca_name, ".inject_storage_error") == 0)
        count = sprintf(buf, "Write here to inject a failure state for this "
                        "device\n");
    else if( strcmp( attr->ca_name,"quiesce_on_release" ) == 0 )
        count = sprintf(buf, "%d\n", dev_quiesce_on_release(dev));
    else if( strcmp( attr->ca_name,"max_io_size" ) == 0 )
        count = sprintf( buf,"%d\n", (dev->max_sectors * RNABLK_SECTOR_SIZE));
    else if( strcmp( attr->ca_name,"disconnect" ) == 0 )
        count = sprintf( buf,"Write here to trigger device disconnect\n" );
    else if( strcmp( attr->ca_name,"stats" ) == 0 ) {
        count = sprintf( buf,"General Stats\n"
                         "writes\t\t: %16llu\treads\t\t: %16llu\n"
                         "direct reads\t: %16llu\tqueries\t\t: %16llu\n"
                         "reading blocks\t: %16d\twriting blocks\t: %16d\n"
                         "bytes out\t: %16llu\tbytes in\t: %16llu\n"
                         "queue usage\t: %16d\tin flight\t: %16d\n"
                         "req retries\t: %16llu\tfailed blocks\t: %16llu\n"
                         "write hits\t: %16llu\tread hits\t: %16llu\n"
                         "write time\t: %16llu\tread time\t: %16llu\n"
                         "\nHistogram\n"
                         "<4K\t\t: %16llu\n"
                         "4K\t\t: %16llu\t16K\t\t: %16llu\n"
                         "32K\t\t: %16llu\t64K\t\t: %16llu\n"
                         "128K\t\t: %16llu\t256K\t\t: %16llu\n"
                         "512K\t\t: %16llu\t1024K\t\t: %16llu\n",
                         dev->stats.writes,dev->stats.reads,
                         dev->stats.direct_reads,dev->stats.queries,
                         atomic_read(&dev->stats.reading_blocks),
                         atomic_read(&dev->stats.writing_blocks),
                         dev->stats.bytes_out,dev->stats.bytes_in,
                         atomic_read(&dev->stats.in_queue),
                         atomic_read(&dev->stats.in_flight),
                         dev->stats.retries,
                         dev->stats.failed_blocks,
                         rna_atomic64_read(&dev->stats.bs_write_hits),
                         rna_atomic64_read(&dev->stats.bs_read_hits),
                         rna_atomic64_read(&dev->stats.bs_write_time),
                         rna_atomic64_read(&dev->stats.bs_read_time),
                         dev->stats.histo[0],dev->stats.histo[1],
                         dev->stats.histo[2],dev->stats.histo[3],
                         dev->stats.histo[4],dev->stats.histo[5],
                         dev->stats.histo[6],dev->stats.histo[7],
                         dev->stats.histo[8]);
    }
    else if( strcmp( attr->ca_name,".debug" ) == 0 ) {
        /*
         * Get a copy of the stop flags and create a
         * human readble string representing the bits
         * set in the flags
         */
        int i;
        int s_len = 0;
        char *sep = "";
        const char *p = NULL;
        int rqs_flgs = atomic_read(&dev->q_stop_flags);    // unsynchronized read, may blur
        memset(rqs_flags_str, 0 , sizeof(rqs_flags_str));

        /* Check for the maximum number of bits in the enum */
        for (i = 0; i < sizeof(enum rnablk_queue_stop_flags) * 8; i++) {
            /* If a bit is on, get it's string */
            if ((rqs_flgs >> i) & 1) {
                p = get_queue_stop_string(i);
                /* Make sure that everything fits */
                s_len += strlen(sep);
                if (s_len >= sizeof(rqs_flags_str)) {
                    strcpy(rqs_flags_str, "FLAGS ERROR");
                    break;
                }
                strcat(rqs_flags_str, sep);
                s_len += strlen(p);
                if (s_len >= sizeof(rqs_flags_str)) {
                    strcpy(rqs_flags_str, "FLAGS ERROR");
                    break;
                }
                strcat(rqs_flags_str, p);
                sep=",";
                /* 
                 * If we have extra bits the we don't know about, then
                 * exit early.
                 */
                if (strcmp(p, "UNKNOWN") == 0) {
                    break;
                }
            } else if ((rqs_flgs >> i) == 0) {
                /*  exit if there are't any more bits in the word */
                break;
            }
        }

        count = sprintf(buf,
                        "Device debug info:\n"
                        "max_sectors [%d]\n"
                        "Write referenced blocks [%d] (target age [%lu])\n"
                        "Read referenced blocks [%d]\n"
                        "Current total cache blocks [%d] (target age [%lu])\n"
                        "Cumulative total [%d]\n"
                        "Strategy threads [%d]\n"
                        "Queue stop flags [0x%x %s]\n"
                        "Deferred from softirq [%d] "
                        "Deferred for more stack [%d] "
                        "Min stack in strategy [%d]\n"
                        "Successful SCSI reservations [%"PRId64"] "
                        "Failed [%"PRId64"]\n"
                        "Failed IO due to SCSI reservation conflicts [%"PRId64"]\n"
                        "WRITE SAME requests [%"PRId64"] "
                        "UNMAP requests [%"PRId64"] "
                        "COMPARE AND WRITE requests [%"PRId64"]\n"
                        "Blocks anonymously downgraded [%"PRId64"] "
                        "Block references anonymously dropped [%"PRId64"]\n"
                        "downgraded [%ld] "
                        "references dropped [%ld]\n",
                        dev->max_sectors,
                        atomic_read(&dev->stats.writing_blocks),
                        rnablk_write_reference_target_age / 1000,
                        atomic_read(&dev->stats.reading_blocks),
                        atomic_read(&dev->cache_blk_count),
                        rnablk_reference_target_age / 1000,
                        atomic_read(&dev->cumulative_cache_blk_count),
                        atomic_read(&dev->strategy_threads),
                        rqs_flgs,
                        (rqs_flgs) ? rqs_flags_str : "NONE",
                        atomic_read(&dev->deferred_softirq),
                        atomic_read(&dev->deferred_stack),
                        atomic_read(&dev->min_stack),
                        dev->stats.reservations,
                        dev->stats.reservation_conflicts,
                        dev->stats.io_reservation_conflicts,
                        dev->stats.write_same_requests,
                        dev->stats.unmap_requests,
                        dev->stats.comp_and_write_requests,
                        dev->stats.anon_downgraded_blocks,
                        dev->stats.anon_ref_dropped_blocks,
                        atomic64_read(&dev->stats.enforcer_downgraded_blocks),
                        atomic64_read(&dev->stats.enforcer_ref_dropped_blocks));
    }
    else if( strcmp( attr->ca_name,".block_debug" ) == 0 ) {
        count = sprintf(buf,
                        "Write cache block number here and read info on "
                        "that block from .block_debug.xml\n");
    } else if( strcmp( attr->ca_name,".block_debug.xml" ) == 0 ) {
        struct rnablk_cache_blk_debug_info blk_info;
        uint64_t next_block;
        char nxt_str[48];

        count = 0;
        next_block = rnablk_get_next_cache_blk_debug_info(dev,
                                            dev->rbd_block_debug,
                                            &blk_info, NULL, FALSE);
        if (next_block != dev->rbd_block_debug) {
            sprintf(nxt_str, "nxt=\"%"PRIu64"\" ", next_block);
        } else {
            /* no next blk found */
            nxt_str[0] = '\0';
        }

        if (INVALID_BLOCK_NUM != blk_info.blk_snapshot.block_number) {
            if (blk_info.blk_snapshot.block_number == dev->rbd_block_debug) {
                /* found the block we asked for */
                count = rnablk_format_cache_blk_debug_info(buf, bufsize,
                                                           &blk_info,
                                                           nxt_str);
            } else {
                /*
                 * this blk must be a higher blkno than the one asked for,
                 * so it should be the rightful "next_block".
                 */
                next_block = blk_info.blk_snapshot.block_number;
            }
            if (NULL != blk_info.blk_snapshot.ep) {
                com_release_ep(blk_info.blk_snapshot.ep);
            }
        }

        dev->rbd_block_debug = next_block;

    } else if (strcmp(attr->ca_name, ".block_debug_next.xml") == 0) {
        struct rnablk_cache_blk_debug_info blk_info;

        dev->rbd_block_debug = rnablk_get_next_cache_blk_debug_info(dev,
                                            dev->rbd_block_debug,
                                            &blk_info, NULL, FALSE);
        if (-1 != blk_info.blk_snapshot.block_number) {
            count = rnablk_format_cache_blk_debug_info(buf, bufsize,
                                                       &blk_info, NULL);
            if (NULL != blk_info.blk_snapshot.ep) {
                com_release_ep(blk_info.blk_snapshot.ep);
            }
        } else {
            count = 0;
        }
    } else if (strcmp(attr->ca_name, ".block_debug_busy.xml") == 0) {
        struct rnablk_cache_blk_debug_info blk_info;
        struct cache_blk *blk;

        dev->rbd_block_debug = rnablk_get_next_cache_blk_debug_info(dev,
                                            dev->rbd_block_debug,
                                            &blk_info, &blk, TRUE);
        if (-1 != blk_info.blk_snapshot.block_number) {
            count = rnablk_format_cache_blk_debug_info(buf, bufsize,
                                                       &blk_info, NULL);
            count += rnablk_report_dispatched_ios(blk, buf + count,
                                                  bufsize - count);
            if (count == bufsize) {
                /* make sure buffer ends with '\n' */
                buf[bufsize-1] = '\n';
            }
            if (NULL != blk_info.blk_snapshot.ep) {
                com_release_ep(blk_info.blk_snapshot.ep);
            }
            rnablk_cache_blk_release(blk);
        } else {
            count = 0;
        }
    }
    return(count);
}

static int rnablk_disconnect_device_th( void *arg )
{
    struct rnablk_device *dev = (struct rnablk_device *)arg;
    ENTER;

    rnablk_disconnect_device( dev );

    EXIT;
}

/**
 * Perform device disconnect work on another thread, and allow this
 * cfs operation to complete.
 *
 * TBD: Consider doing this on the slow workq instead of a dedicated thread.
 */
static int
rnablk_schedule_disconnect_device(struct rnablk_device *dev)
{
    ENTER;

    rna_printk(KERN_INFO,
               "disconnect of device [%s] in state [%s] requested\n",
               dev->name,
               get_rnablk_cache_status_string(atomic_read(&dev->stats.status)));

    if (dev_openers_is_open(dev)) {
        rna_printk(KERN_ERR,
                   "not disconnecting device [%s] with [%d] openers\n",
                   dev->name,
                   atomic_read(&dev->stats.openers));

        GOTO(out, -EBUSY);
    }

    if ((RNABLK_CACHE_ONLINE != atomic_cmpxchg(&dev->stats.status,
                                               RNABLK_CACHE_ONLINE,
                                               RNABLK_CACHE_DISCONNECTING)) &&
        (RNABLK_CACHE_CONNECTING != atomic_cmpxchg(&dev->stats.status,
                                               RNABLK_CACHE_CONNECTING,
                                               RNABLK_CACHE_DISCONNECTING)) &&
        (RNABLK_CACHE_OFFLINE != atomic_cmpxchg(&dev->stats.status,
                                               RNABLK_CACHE_OFFLINE,
                                               RNABLK_CACHE_DISCONNECTING))) {
        rna_printk(KERN_ERR,
                   "device [%s] in unexpected state [%s] was not disconnected\n",
                   dev->name,
                   get_rnablk_cache_status_string(atomic_read(&dev->stats.status)));
        ret = -EBUSY;
    } else {
        kthread_run( rnablk_disconnect_device_th,dev,"rnablk_disconnect_%s",dev->name );
    }

 out:
    EXIT;
}

static void
rnablk_handle_detached_shutdown(void)
{
    if (RNA_SERVICE_DETACHED == atomic_cmpxchg(&rna_service_detached,
                                               RNA_SERVICE_DETACHED,
                                               RNA_SERVICE_DETACHED_SHUTDOWN)) {
        /*
         * Must 'cleanup' the devices before the conn's, because the conn
         * cleanup depends on all the devices being marked as failed.
         */
        rnablk_detached_shutdown_cleanup_devices();
        rnablk_detached_shutdown_cleanup_conns();
        rnablk_svcctl_unfreeze();
    }
}

static int
rna_dev_attr_dot_drop_ref(struct rnablk_device *dev, uint64_t blkno)
{
    struct cache_blk *blk;
    lockstate_t irqflags;
    int ret = -EEXIST;

    /* Need to convert blkno to sector offset for cache_blk lookup... */
    blk = rnablk_cache_blk_get(dev,
                        (blkno * dev->cache_blk_size) / RNABLK_SECTOR_SIZE);
    if (NULL != blk) {
        rnablk_lock_blk_irqsave(blk, irqflags);

        ret = rnablk_cache_blk_drop_ref(blk, &irqflags, DEREF_NO_RESP);

        /* block lock is dropped by above call */

        rnablk_cache_blk_release(blk);
        if (0 != ret) {
            ret = -EINVAL;
        }
    }
    rna_printk(KERN_NOTICE, "Requested to drop reference for device [%s] "
               "block [%llu]: %s\n",
               dev->name, blkno, ret == 0 ? "Success!" : ret == -EINVAL
               ? "Failed to drop reference" : "Block not cached");
    return ret;
}

static ssize_t rnablk_dev_attr_store( struct config_item *item,
                                      struct configfs_attribute *attr,
                                      const char *buf,size_t len )
{
    struct rnablk_device *dev;
    int tmp;
    ENTER;

    dev = to_rnablk_dev( item );

    if (strcmp(attr->ca_name, ".block_debug") == 0) {
        uint64_t blkno = simple_strtoul(buf, NULL, 0);

        if (blkno >= rnablk_get_block_count(dev)) {
            rna_printk(KERN_WARNING, "block [%s] beyond end of device [%s] "
                       "(nblocks [%"PRIu64"])\n", buf, dev->name,
                       rnablk_get_block_count(dev));
        }                
        dev->rbd_block_debug = blkno;
    }
    // disallow interaction with this device if the driver is being unloaded
    else if (rnablk_dev_is_shutdown(dev)) {
        len = -EPERM;
        GOTO( out,-EPERM );
    }

    else if( strcmp( attr->ca_name,"capacity" ) == 0 ) {
        unsigned long capacity;
        capacity = simple_strtoul( buf,NULL,10 );
        if( capacity > 0 ) {
            ret = rnablk_apply_device_capacity( dev, capacity );
            if (0 != ret)
                len = ret;
        }
        else
            len = -EINVAL;
    } else if (strcmp(attr->ca_name, ".drop_ref") == 0) {
        uint64_t blkno = simple_strtoul(buf, NULL, 0);

        ret = rna_dev_attr_dot_drop_ref(dev, blkno);
    }
    else if( strcmp( attr->ca_name,"persist_location" ) == 0 ) {
        ret = rnablk_apply_persist_location(dev, attr->ca_name);
        if (0 != ret)
            len = ret;
    }
    else if( strcmp( attr->ca_name,"persist_access_uid" ) == 0 ) {
        tmp = simple_strtoul( buf,NULL,10 );
        ret = rnablk_apply_access_uid(dev, tmp);
        if (0 != ret)
            len = ret;
    }
    else if( strcmp( attr->ca_name,"persist_access_gid" ) == 0 ) {
        tmp = simple_strtoul( buf,NULL,10 );
        ret = rnablk_apply_access_gid(dev, tmp);
        if (0 != ret)
            len = ret;
    }
    else if( strcmp( attr->ca_name,"shareable" ) == 0 ) {
        tmp = simple_strtoul( buf,NULL,10 );
        ret = rnablk_apply_shareable(dev, tmp);
        if (0 != ret)
            len = ret;
    }
    else if( strcmp( attr->ca_name,"freeable" ) == 0 ) {
        tmp = simple_strtoul( buf,NULL,10 );
        ret = rnablk_apply_freeable(dev, tmp);
        if (0 != ret)
            len = ret;
    }
    else if( strcmp( attr->ca_name,"cache_blk_size" ) == 0 ) {
        uint32_t tmp;
        tmp = simple_strtoul( buf,NULL,10 );
        ret = rnablk_apply_cache_blk_size(dev, tmp);
        if (0 != ret)
            len = ret;
    }
    else if( strcmp( attr->ca_name,"mount_status" ) == 0 ) {
        uint32_t tmp = simple_strtoul( buf,NULL,10 );
        dev->mount_status = tmp;
        rnablk_notify_mount_event( dev, tmp );
    }
    else if( strcmp( attr->ca_name,"disable_new_openers" ) == 0 ) {
        uint32_t tmp = simple_strtoul(buf, NULL, 10 );

        /* zero means enable new openers.  If new openers are
         * currently disabled, then set to allow new openers.
         *
         * 1 means enable to disable new openers.
         */
        if (0 == tmp) {
            dev_new_openers_enable(dev);
        } else if (1 == tmp) {
            dev_new_openers_disable(dev);
        } else {
            len = -EPERM;
            GOTO( out,-EPERM );
        }
    }
    else if( strcmp( attr->ca_name,"stats" ) == 0 ) {
        dev->stats.writes           = 0;
        dev->stats.reads            = 0;
        dev->stats.direct_reads     = 0;
        dev->stats.queries          = 0;
        dev->stats.retries          = 0;
        dev->stats.bytes_out        = 0;
        dev->stats.bytes_in         = 0;
        dev->stats.reservations     = 0;
        dev->stats.reservation_conflicts = 0;
        dev->stats.io_reservation_conflicts = 0;
        dev->stats.write_same_requests = 0;
        dev->stats.unmap_requests = 0;
        dev->stats.comp_and_write_requests = 0;
        rna_atomic64_set( &dev->stats.bs_write_query_time, 0);
        rna_atomic64_set( &dev->stats.bs_read_query_time, 0);
        rna_atomic64_set( &dev->stats.bs_read_time, 0);
        rna_atomic64_set( &dev->stats.bs_write_time, 0);
        rna_atomic64_set( &dev->stats.bs_write_hits, 0);
        rna_atomic64_set( &dev->stats.bs_read_hits, 0);
        memset( &dev->stats.histo[0],0,
                BLKDEV_STATS_HISTORY_COUNT * sizeof( uint64_t ) );
    }
    else if(strcmp(attr->ca_name, "dma_reads_disabled") == 0) {
        tmp = simple_strtoul(buf, NULL, 10);
        if (tmp != dev_dma_reads_disabled(dev)) {
            rna_printk(KERN_NOTICE, "Changing dma_reads_disabled from %d to "
                       "%d on dev %s\n", dev_dma_reads_disabled(dev), tmp,
                       dev->name);
        }
        if (tmp) {
            dev_set_dma_reads_disabled(dev);
        } else {
            dev_clear_dma_reads_disabled(dev);
        }
    }
    else if(strcmp(attr->ca_name, "dma_writes_disabled") == 0) {
        tmp = simple_strtoul(buf, NULL, 10);
#ifdef ALLOW_DMA_WRITES
        if (tmp != dev_dma_writes_disabled(dev)) {
            rna_printk(KERN_NOTICE, "Changing dma_writes_disabled from %d "
                       "to %d on dev %s\n", dev_dma_writes_disabled(dev),
                       tmp, dev->name);
        }
        if (tmp) {
            dev_set_dma_writes_disabled(dev);
        } else {
            dev_clear_dma_writes_disabled(dev);
        }
#endif
    } else if (strcmp(attr->ca_name, "large_write_minsize") == 0) {
        unsigned long size;
        size = simple_strtoul(buf, NULL, 0);
        if (size > dev->cache_blk_size) {
            size = dev->cache_blk_size;
            rna_printk(KERN_NOTICE, "Truncating specified large_write_minsize "
                       "to match cache_block_size of %lu\n", size);
        }
        size /= RNABLK_SECTOR_SIZE;
        if (size != dev->rbd_large_write_sects) {
            rna_printk(KERN_NOTICE, "Changing large_write_minsize for device "
                       "%s from %llu to %lu\n", dev->name,
                       dev->rbd_large_write_sects * RNABLK_SECTOR_SIZE,
                       size * RNABLK_SECTOR_SIZE);
            dev->rbd_large_write_sects = size;
        }
    }
#ifdef TEST_STORAGE_ERROR
    else if(strcmp(attr->ca_name, ".inject_storage_error") == 0) {
        tmp = simple_strtoul(buf, NULL, 0);
        atomic_set(&dev->rbd_test_err_inject, tmp);
        rna_printk(KERN_ERR, "Injecting %d I/O storage errors for dev [%s]\n",
                   tmp, dev->name);
    }
#endif /* TEST_STORAGE_ERROR */
    else if (strcmp(attr->ca_name, ".inject_device_fail") == 0) {
        rna_printk(KERN_ERR, "Injecting device failure state for device [%s]\n",
                   dev->name);
        rnablk_device_fail(dev);
    }
    else if(strcmp(attr->ca_name, "quiesce_on_release") == 0) {
        tmp = simple_strtoul(buf, NULL, 10);
        if (tmp) {
            dev_set_quiesce_on_release(dev);
        } else {
            dev_clear_quiesce_on_release(dev);
        }
    }
    else if(strcmp(attr->ca_name, "disconnect") == 0) {
        len = rnablk_schedule_disconnect_device(dev);
        if (0 == len) {
            len = strlen(buf);
        }
    }
    else if(strcmp(attr->ca_name, "max_io_size") == 0) {
        tmp = simple_strtoul(buf, NULL, 10);
        rnablk_set_max_io(dev, tmp);
    }

out:
    EXITVAL( (int)len );
}

static int rnablk_destroy_device_th( void *arg )
{
    struct rnablk_device *dev = (struct rnablk_device *)arg;
    ENTER;

    rnablk_destroy_device( dev );

    EXIT;
}

static void
rnablk_cfs_dev_release(struct config_item *item)
{
    struct rnablk_device *dev = to_rnablk_dev( item );
    ENTER;

    /*
     * We'll do this inline now, so all the device destroys will be
     * done by the time we try to unload.  Much of this has moved
     * forward to the close operation.
     */
    //kthread_run( rnablk_destroy_device_th,dev,"rnablk_rel_%s",dev->name );
    rnablk_destroy_device(dev);

    rnablk_dev_release(dev);    // drop the cfs reference on 'dev'

    EXITV;
}

static struct configfs_item_operations rnablk_dev_item_ops = {
	.release         = rnablk_cfs_dev_release,
	.show_attribute  = rnablk_dev_attr_show,
	.store_attribute = rnablk_dev_attr_store,
};

static struct config_item_type rnablk_dev_type = {
	.ct_item_ops = &rnablk_dev_item_ops,
	.ct_attrs	 = rnablk_dev_attrs,
	.ct_owner    = THIS_MODULE,
};

static struct config_item *
rnablk_devices_make_item(struct config_group *group,const char *name)
{
	struct rnablk_device *dev;
    ENTER;

    if( strlen( name ) > sizeof( dev->name ) )
        GOTO( err,-EINVAL );

    /*
     * Keep the dev reference we acquire in the find routine until
     * we do a '.release'
     */
	dev = rnablk_find_device((char *)name);
	if( dev == NULL )
        GOTO( err,-ENODEV );

	config_item_init_type_name( &dev->item,name,&rnablk_dev_type );

    EXITPTR( &dev->item );

err:
    EXITPTR( NULL );
}

static struct configfs_attribute *rnablk_devices_attrs[] = {
	NULL,
};

static struct configfs_group_operations rnablk_devices_group_ops = {
	.make_item	= rnablk_devices_make_item,
};

static struct config_item_type rnablk_devices_type = {
	.ct_group_ops = &rnablk_devices_group_ops,
	.ct_attrs	  = rnablk_devices_attrs,
	.ct_owner	  = THIS_MODULE,
};

/* It seems we only call rnablk_make_group once, so we can
 * statically allocate this. */
struct config_group grp;
int grp_in_use = 0;

static struct config_group *rnablk_make_group(struct config_group *group, 
                                              const char *name)
{
    ENTER;

    /* Verify that we don't re-use the statically_allocated struct. */
    BUG_ON(grp_in_use);
    grp_in_use++;

    memset(&grp, 0, sizeof(struct config_group));
    config_group_init_type_name(&grp, name, &rnablk_devices_type);

out:
    EXITPTR( &grp );
}

/* Freeing the group or the item will cause a crash, even if the
 * group was allocated dynamically. */
static void rnablk_release_group( struct config_group *group,struct config_item *item )
{
    ENTER;
    grp_in_use--;
    EXITV;
}

static struct configfs_attribute rnablk_driver_attr_version = {
	.ca_owner = THIS_MODULE,
	.ca_name = "version",
	.ca_mode = S_IRUGO,
};

static struct configfs_attribute rnablk_driver_attr_max_wr = {
	.ca_owner = THIS_MODULE,
	.ca_name = "max_wr",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_max_sge = {
	.ca_owner = THIS_MODULE,
	.ca_name = "max_sge",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_max_rs = {
	.ca_owner = THIS_MODULE,
	.ca_name = "max_rs",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_bounce_buffer_bytes = {
	.ca_owner = THIS_MODULE,
	.ca_name = "bounce_buffer_bytes",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_bounce_segment_bytes = {
	.ca_owner = THIS_MODULE,
	.ca_name = "bounce_segment_bytes",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_dbg_flags = {
	.ca_owner = THIS_MODULE,
	.ca_name = "dbg_flags",
	.ca_mode = S_IRUGO | S_IWUSR, 
};

static struct configfs_attribute rnablk_driver_attr_rna_printk_level = {
	.ca_owner = THIS_MODULE,
	.ca_name = "rna_printk_level",
	.ca_mode = S_IRUGO | S_IWUSR, 
};

static struct configfs_attribute rnablk_driver_attr_rna_com_retry_count = {
	.ca_owner = THIS_MODULE,
	.ca_name = "rna_com_retry_count",
	.ca_mode = S_IRUGO | S_IWUSR, 
};

static struct configfs_attribute rnablk_driver_attr_rna_com_rnr_retry_count = {
	.ca_owner = THIS_MODULE,
	.ca_name = "rna_com_rnr_retry_count",
	.ca_mode = S_IRUGO | S_IWUSR, 
};

static struct configfs_attribute rnablk_driver_attr_cfm_addrs = {
	.ca_owner = THIS_MODULE,
	.ca_name = "cfm_addrs",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_node_name = {
	.ca_owner = THIS_MODULE,
	.ca_name = "node_name",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_status = {
	.ca_owner = THIS_MODULE,
	.ca_name = "status",
	.ca_mode = S_IRUGO,
};

static struct configfs_attribute rnablk_driver_attr_in_use = {
	.ca_owner = THIS_MODULE,
	.ca_name = "in_use",
	.ca_mode = S_IRUGO,
};

static struct configfs_attribute rnablk_driver_attr_enable_creates = {
	.ca_owner = THIS_MODULE,
	.ca_name = "enable_creates",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_net_link_mask = {
	.ca_owner = THIS_MODULE,
	.ca_name = "net_link_mask",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_read_deref_secs = {
	.ca_owner = THIS_MODULE,
	.ca_name = "read_deref_secs",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_write_deref_secs = {
	.ca_owner = THIS_MODULE,
	.ca_name = "write_deref_secs",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_max_connection_failures = {
	.ca_owner = THIS_MODULE,
	.ca_name = "max_connection_failures",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_dot_debug = {
	.ca_owner = THIS_MODULE,
	.ca_name = ".debug",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_dot_show_conns = {
	.ca_owner = THIS_MODULE,
	.ca_name = ".show_conns",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_dot_inject_deref_request = {
	.ca_owner = THIS_MODULE,
	.ca_name = ".inject_deref_request",
	.ca_mode = S_IRUGO | S_IWUSR,
};

#ifdef TEST_OFFLINE_CACHE_DEVICE
static struct configfs_attribute rnablk_driver_attr_dot_expel_cd = {
	.ca_owner = THIS_MODULE,
	.ca_name = ".expel_cd",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_dot_expel_cd2 = {
	.ca_owner = THIS_MODULE,
	.ca_name = ".expel_cd2",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_dot_expel_cd3 = {
	.ca_owner = THIS_MODULE,
	.ca_name = ".expel_cd3",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_dot_fail_cd = {
	.ca_owner = THIS_MODULE,
	.ca_name = ".fail_cd",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_dot_inject_ldma_cd_fail = {
	.ca_owner = THIS_MODULE,
	.ca_name = ".inject_ldma_cd_fail",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_dot_inject_rdma_cd_fail = {
	.ca_owner = THIS_MODULE,
	.ca_name = ".inject_rdma_cd_fail",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_dot_inject_cache_resp_cd_fail = {
	.ca_owner = THIS_MODULE,
	.ca_name = ".inject_cache_resp_cd_fail",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_dot_inject_cache_ref_resp_cd_fail = {
	.ca_owner = THIS_MODULE,
	.ca_name = ".inject_cache_ref_resp_cd_fail",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_dot_inject_cs_disconnect = {
	.ca_owner = THIS_MODULE,
	.ca_name = ".inject_cs_disconnect",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_dot_inject_io_cs_disconnect = {
	.ca_owner = THIS_MODULE,
	.ca_name = ".inject_io_cs_disconnect",
	.ca_mode = S_IRUGO | S_IWUSR,
};
#endif /* TEST_OFFLINE_CACHE_DEVICE */

static struct configfs_attribute rnablk_driver_attr_dot_inject_invd = {
	.ca_owner = THIS_MODULE,
	.ca_name = ".inject_invd",
	.ca_mode = S_IRUGO | S_IWUSR,
};


static struct configfs_attribute rnablk_driver_attr_dot_ios_timeout_script= {
	.ca_owner = THIS_MODULE,
	.ca_name = ".ios_timeout_script",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute
        rnablk_driver_attr_dot_ios_timeout_script_finish = {
	.ca_owner = THIS_MODULE,
	.ca_name = ".ios_timeout_script_finish",
	.ca_mode = S_IWUSR,
};

static struct configfs_attribute
        rnablk_driver_attr_dot_ios_timeout_script_test = {
	.ca_owner = THIS_MODULE,
	.ca_name = ".ios_timeout_script_test",
	.ca_mode = S_IWUSR,
};

#ifdef IOS_TIMEOUT_TEST
static struct configfs_attribute
        rnablk_driver_attr_dot_ios_timeout_test = {
	.ca_owner = THIS_MODULE,
	.ca_name = ".ios_timeout_test",
	.ca_mode = S_IRUGO | S_IWUSR,
};
#endif /* IOS_TIMEOUT_TEST */

static struct configfs_attribute rnablk_driver_attr_io_timeout = {
	.ca_owner = THIS_MODULE,
	.ca_name = "io_timeout",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_use_req_queue = {
	.ca_owner = THIS_MODULE,
	.ca_name = "use_req_queue",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_queue_bios = {
	.ca_owner = THIS_MODULE,
	.ca_name = "queue_bios",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_use_write_only = {
	.ca_owner = THIS_MODULE,
	.ca_name = "use_write_only",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_per_device_connections = {
	.ca_owner = THIS_MODULE,
	.ca_name = "per_device_connections",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_devices_list = {
	.ca_owner = THIS_MODULE,
	.ca_name = "devices_list",
	.ca_mode = S_IRUGO,
};

static struct configfs_attribute rnablk_driver_attr_io_queue_depth = {
	.ca_owner = THIS_MODULE,
	.ca_name = "io_queue_depth",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_dot_latency_stats = {
	.ca_owner = THIS_MODULE,
	.ca_name = ".latency_stats",
	.ca_mode = S_IRUGO,
};


static struct configfs_attribute rnablk_driver_attr_reference_target_age = {
	.ca_owner = THIS_MODULE,
	.ca_name = "reference_target_age",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_write_reference_target_age = {
	.ca_owner = THIS_MODULE,
	.ca_name = "write_reference_target_age",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_write_reference_release_max_outstanding = {
	.ca_owner = THIS_MODULE,
	.ca_name = "write_reference_release_max_outstanding",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_scsi_unmap_disable = {
	.ca_owner = THIS_MODULE,
	.ca_name = "scsi_unmap_disable",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_scsi_write_same_disable = {
	.ca_owner = THIS_MODULE,
	.ca_name = "scsi_write_same_disable",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_dot_inject_detach = {
	.ca_owner = THIS_MODULE,
	.ca_name = ".inject_detach",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_dot_inject_rejoin = {
	.ca_owner = THIS_MODULE,
	.ca_name = ".inject_rejoin",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_dot_detached_shutdown = {
	.ca_owner = THIS_MODULE,
	.ca_name = ".detached_shutdown",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_detached = {
	.ca_owner = THIS_MODULE,
	.ca_name = "detached",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_attr_dot_cs_ping_interval = {
	.ca_owner = THIS_MODULE,
	.ca_name = ".cs_ping_interval",
	.ca_mode = S_IRUGO | S_IWUSR,
};

static struct configfs_attribute rnablk_driver_cs_conns_rdma_only = {
	.ca_owner = THIS_MODULE,
	.ca_name = "cs_conns_rdma_only",
	.ca_mode = S_IRUGO | S_IWUSR, 
};

static struct configfs_attribute *rnablk_driver_attrs[] = {
	&rnablk_driver_attr_version,
	&rnablk_driver_attr_dot_debug,
	&rnablk_driver_attr_dot_show_conns,
    &rnablk_driver_attr_dot_inject_deref_request,
#ifdef TEST_OFFLINE_CACHE_DEVICE
    &rnablk_driver_attr_dot_expel_cd,
    &rnablk_driver_attr_dot_expel_cd2,
    &rnablk_driver_attr_dot_expel_cd3,
    &rnablk_driver_attr_dot_fail_cd,
    &rnablk_driver_attr_dot_inject_ldma_cd_fail,
    &rnablk_driver_attr_dot_inject_rdma_cd_fail,
    &rnablk_driver_attr_dot_inject_cache_resp_cd_fail,
    &rnablk_driver_attr_dot_inject_cache_ref_resp_cd_fail,
    &rnablk_driver_attr_dot_inject_cs_disconnect,
    &rnablk_driver_attr_dot_inject_io_cs_disconnect,
#endif /* TEST_OFFLINE_CACHE_DEVICE */
    &rnablk_driver_attr_dot_ios_timeout_script,
    &rnablk_driver_attr_dot_ios_timeout_script_test,
    &rnablk_driver_attr_dot_ios_timeout_script_finish,
#ifdef IOS_TIMEOUT_TEST
    &rnablk_driver_attr_dot_ios_timeout_test,
#endif /* IOS_TIMEOUT_TEST */
	&rnablk_driver_attr_max_wr,
	&rnablk_driver_attr_max_sge,
	&rnablk_driver_attr_max_rs,
    &rnablk_driver_attr_bounce_buffer_bytes,
    &rnablk_driver_attr_bounce_segment_bytes,
	&rnablk_driver_attr_dbg_flags,
	&rnablk_driver_attr_rna_printk_level,
	&rnablk_driver_attr_cfm_addrs,
    &rnablk_driver_attr_node_name,
	&rnablk_driver_attr_status,
	&rnablk_driver_attr_rna_com_retry_count,
	&rnablk_driver_attr_rna_com_rnr_retry_count,
	&rnablk_driver_attr_in_use,
	&rnablk_driver_attr_enable_creates,
    &rnablk_driver_attr_net_link_mask,
    &rnablk_driver_attr_read_deref_secs,
    &rnablk_driver_attr_write_deref_secs,
    &rnablk_driver_attr_max_connection_failures,
    &rnablk_driver_attr_io_timeout,
    &rnablk_driver_attr_use_req_queue,
    &rnablk_driver_attr_queue_bios,
    &rnablk_driver_attr_use_write_only,
    &rnablk_driver_attr_per_device_connections,
    &rnablk_driver_attr_devices_list,
    &rnablk_driver_attr_io_queue_depth,
    &rnablk_driver_attr_dot_inject_invd,
    &rnablk_driver_attr_dot_latency_stats,
    &rnablk_driver_attr_reference_target_age,
    &rnablk_driver_attr_write_reference_target_age,
    &rnablk_driver_attr_write_reference_release_max_outstanding,
    &rnablk_driver_attr_scsi_unmap_disable,
    &rnablk_driver_attr_scsi_write_same_disable,
    &rnablk_driver_attr_dot_inject_detach,
    &rnablk_driver_attr_dot_inject_rejoin,
    &rnablk_driver_attr_dot_detached_shutdown,
    &rnablk_driver_attr_detached,
    &rnablk_driver_attr_dot_cs_ping_interval,
    &rnablk_driver_cs_conns_rdma_only,
	NULL,
};

int rnablk_conn_list_show_cb(struct rnablk_server_conn *conn,
                             void                      *context)
{
    return rnablk_server_conn_debug_dump(conn);
}

static void rnablk_conn_list_show(void)
{
    rnablk_cache_conn_foreach(rnablk_conn_list_show_cb, NULL);
}

static int
rnablk_find_cs_conn(struct rnablk_server_conn *conn,
                    void *opaque_p_conn)
{
    struct rnablk_server_conn **p_conn;

    if (APP_TYPE_CS == conn->id.u.data.type) {
        p_conn = (struct rnablk_server_conn **)opaque_p_conn;
        *p_conn = conn;
        return 1;
    }
    return 0;
}

struct _find_cs_cachedev_conn {
    cachedev_id_t f_cachedev_id;
    void (*f_func)(struct rnablk_server_conn *, cachedev_id_t, void *);
    boolean f_doall;
    void *f_arg;
    int f_nfound;
};

static int
rnablk_find_cs_cachedev_conn(struct rnablk_server_conn *conn,
                             void *arg)
{
    struct _find_cs_cachedev_conn *argp = (struct _find_cs_cachedev_conn *)arg;
    cachedev_id_t cachedev_id = argp->f_cachedev_id;
    rnablk_cachedev_t *cachedev;
    int ret = 0;

    if (APP_TYPE_CS == conn->id.u.data.type
        && NULL != (cachedev = rnablk_get_conn_cachedev(conn,
                                                        argp->f_cachedev_id,
                                                        FALSE))) {
        argp->f_nfound++;
        argp->f_func(conn, argp->f_cachedev_id, argp->f_arg);

        rnablk_put_cachedev(cachedev);

        if (!argp->f_doall) {
            /*
             * found the one and only CS conn with matching cachedev_id, so
             * we're done!
             */
            ret = 1;
        }
    }
    return ret;
}

void rnablk_queue_deref_req(struct com_ep *ep, struct cache_deref_req *request,
                            boolean is_from_cs);
struct com_ep *rnablk_conn_get_ep(struct rnablk_server_conn *conn);


static void
rnablk_cfs_inject_deref_request_for_cachedev(struct rnablk_server_conn *conn,
                                             rnablk_cachedev_t *cachedev,
                                             void *unused)
{
    struct com_ep *ep;
    struct cache_deref_req request;
    int ret;

    ep = rnablk_conn_get_ep(conn);
    if (likely(NULL != ep)) {
        request.deref_bytes = 0xffffffff;
        request.cachedev_id = cachedev->rcd_id;
        rnablk_queue_deref_req(ep, &request, FALSE);
        com_release_ep(ep);
        rna_printk(KERN_NOTICE, "Initiated DEREF for cachedev [%#"PRIx64"] on "
                   "conn ["CONNFMT"]\n", cachedev->rcd_id, CONNFMTARGS(conn));
    } else {
        rna_printk(KERN_NOTICE, "Client conn ["CONNFMT"] not connected, "
                   "not doing DEREF for cachedev [%#"PRIx64"]\n",
                   CONNFMTARGS(conn), cachedev->rcd_id);
    }
}

static void
rnablk_cfs_inject_deref_request(struct rnablk_server_conn *conn,
                                cachedev_id_t cachedev_id,
                                void *unused)
{
    rnablk_cachedev_t *cachedev;

    if (0 == cachedev_id) {
        rnablk_operate_on_conn_cachedevs(conn, NULL, NULL,
                            rnablk_cfs_inject_deref_request_for_cachedev);
    } else {
        cachedev = rnablk_get_conn_cachedev(conn, cachedev_id, FALSE);
        RNABLK_BUG_ON(NULL == cachedev,
                      "What happened to cachedev [%#"PRIx64"]\n", cachedev_id);
        rnablk_cfs_inject_deref_request_for_cachedev(conn, cachedev, NULL);
        rnablk_put_cachedev(cachedev);
    }
}

static void
rnablk_attr_store_inject_deref_request(cachedev_id_t cachedev_id)
{
    struct _find_cs_cachedev_conn arg;

    arg.f_cachedev_id = cachedev_id;
    arg.f_nfound = 0;
    arg.f_doall = (cachedev_id == 0);
    arg.f_func = rnablk_cfs_inject_deref_request;

    rnablk_cache_conn_foreach(rnablk_find_cs_cachedev_conn, &arg);
}


#ifdef TEST_OFFLINE_CACHE_DEVICE

static void
rnablk_cfs_expel_cd(struct rnablk_server_conn *conn, cachedev_id_t cachedev_id,
                    void *unused)
{
    rna_printk(KERN_ERR, "Injecting EXPEL of cachedev [%#"PRIx64"] on conn "
               "["CONNFMT"]\n", cachedev_id, CONNFMTARGS(conn));
    rnablk_trigger_offline_cache_device(conn, cachedev_id, CD_OFFLINE_EXPEL);
    rna_printk(KERN_ERR, "Injected EXPEL of cachedev [%#"PRIx64"] complete\n",
               cachedev_id);
}

static void
rnablk_attr_store_expel_cd(cachedev_id_t cachedev_id)
{
    struct _find_cs_cachedev_conn arg;

    arg.f_cachedev_id = cachedev_id;
    arg.f_nfound = 0;
    arg.f_doall = (cachedev_id == 0);
    arg.f_func = rnablk_cfs_expel_cd;

    rnablk_cache_conn_foreach(rnablk_find_cs_cachedev_conn, &arg);

    if (arg.f_nfound != 1) {
        rna_printk(KERN_NOTICE, "Expelled %d cache devices\n", arg.f_nfound);
    }
}

static void
rnablk_get_cachedev_list(struct cachedev_list *cdl)
{
    cdl->cdl_n_cachedevs = 0;
    (void)rnablk_cache_conn_foreach(rnablk_get_conn_cachedev_list, cdl);
}
                              
extern void
rnablk_process_unexpelled_cachedevs(struct rna_service_ctx_s *ctx,
                                    rna_service_message_buffer_t *message);
static void
rnablk_attr_store_expel_cd2(cachedev_id_t cachedev_id)
{
    rna_service_message_buffer_t *msg;
    struct cachedev_list *cdl;
    cachedev_id_t max_id = cachedev_id + 1;
    int i, m_idx;

    rna_printk(KERN_ERR, "Injecting UNEXPELLED_CACHEDEVS msg to expel "
               "cachedev [%#"PRIx64"]\n", cachedev_id);

    if ((msg = kmalloc(sizeof(*msg), GFP_KERNEL)) == NULL) {
        rna_printk(KERN_ERR, "Failed to inject UNEXPELLED_CACHEDEVS msg: "
                   "ENOMEM\n");
        return;
    }
    if ((cdl = kmalloc(sizeof(*cdl), GFP_KERNEL)) == NULL) {
        rna_printk(KERN_ERR, "Failed to inject UNEXPELLED_CACHEDEVS msg: "
                   "ENOMEM\n");
        kfree(msg);
        return;
    }

    rnablk_get_cachedev_list(cdl);

    for (i = 0, m_idx = 0; i < cdl->cdl_n_cachedevs; i++) {
        if (cdl->cdl_ids[i] != cachedev_id) {
            msg->u.rmb_unexpelled_cachedevs.cuc_unexpelled_cachedevs[m_idx++]
                                                    = cdl->cdl_ids[i];
            if (cdl->cdl_ids[i] > max_id) {
                max_id = cdl->cdl_ids[i];
            }
        }
    }
    msg->u.rmb_unexpelled_cachedevs.cuc_unexpelled_cachedevs[m_idx] =
                                                        NULL_CACHEDEV_ID;
    msg->u.rmb_unexpelled_cachedevs.cuc_unexpelled_cachedevs_max = max_id;

    rnablk_process_unexpelled_cachedevs(NULL, msg);

    kfree(msg);
    kfree(cdl);
}

static void
rnablk_attr_store_expel_cd3(cachedev_id_t max_cachedev_id)
{
    rna_service_message_buffer_t *msg;

    rna_printk(KERN_ERR, "Injecting UNEXPELLED_CACHEDEVS msg to expel "
               "cachedevs with ID less than cachedev [%#"PRIx64"]\n",
               max_cachedev_id);

    if ((msg = kmalloc(sizeof(*msg), GFP_KERNEL)) == NULL) {
        rna_printk(KERN_ERR, "Failed to inject UNEXPELLED_CACHEDEVS msg: "
                   "ENOMEM\n");
        return;
    }

    msg->u.rmb_unexpelled_cachedevs.cuc_unexpelled_cachedevs[0] =
                                                        NULL_CACHEDEV_ID;
    msg->u.rmb_unexpelled_cachedevs.cuc_unexpelled_cachedevs_max =
                                                        max_cachedev_id;

    rnablk_process_unexpelled_cachedevs(NULL, msg);

    kfree(msg);
}

static void
rnablk_cfs_fail_cd(struct rnablk_server_conn *conn, cachedev_id_t cachedev_id,
                   void *unused)
{
    /*
     * Send a FAIL_CACHE_DEVICE message, to kick off the whole
     * offline process.
     */
    rna_printk(KERN_ERR, "Injecting FAIL notification for cachedev [%#"PRIx64"]"
               " on conn ["CONNFMT"]\n",
               cachedev_id, CONNFMTARGS(conn));
    rnablk_send_fail_cachedev(conn, cachedev_id, FALSE);
}

static void
rnablk_attr_store_fail_cd(cachedev_id_t cachedev_id)
{
    struct _find_cs_cachedev_conn arg;

    if (0 == cachedev_id) {
        rna_printk(KERN_NOTICE, "Can't inject cd_fail for cachedev [0x0]\n");
        return;
    }

    arg.f_cachedev_id = cachedev_id;
    arg.f_nfound = 0;
    arg.f_doall = (cachedev_id == 0);
    arg.f_func = rnablk_cfs_fail_cd;

    rnablk_cache_conn_foreach(rnablk_find_cs_cachedev_conn, &arg);

    if (arg.f_nfound != 1) {
        rna_printk(KERN_NOTICE, "Failed %d cache devices\n", arg.f_nfound);
    }
}

static void
rnablk_cfs_inject_ldma_cd_fail(struct rnablk_server_conn *conn,
                               cachedev_id_t cachedev_id, void *unused)
{
    rna_printk(KERN_ERR, "Inject LDMA I/O error for cachedev [%#"PRIx64"]\n",
               cachedev_id);
    test_cachedev_fail_ldma = cachedev_id;
}


static void
rnablk_attr_store_inject_ldma_cd_fail(cachedev_id_t cachedev_id)
{
    struct _find_cs_cachedev_conn arg;

    if (0 == cachedev_id) {
        rna_printk(KERN_NOTICE, "Can't inject cd_fail for cachedev [0x0]\n");
        return;
    }

    arg.f_cachedev_id = cachedev_id;
    arg.f_nfound = 0;
    arg.f_doall = FALSE;
    arg.f_func = rnablk_cfs_inject_ldma_cd_fail;

    rnablk_cache_conn_foreach(rnablk_find_cs_cachedev_conn, &arg);

    if (arg.f_nfound != 1) {
        rna_printk(KERN_NOTICE, "Injected ldma_cd_fail on %d cache devices\n",
                   arg.f_nfound);
    }
}

static void
rnablk_cfs_inject_rdma_cd_fail(struct rnablk_server_conn *conn,
                               cachedev_id_t cachedev_id, void *unused)
{
    rna_printk(KERN_ERR, "Inject RDMA I/O error for cachedev [%#"PRIx64"]\n",
               cachedev_id);
    test_cachedev_fail_rdma = cachedev_id;
}

static void
rnablk_attr_store_inject_rdma_cd_fail(cachedev_id_t cachedev_id)
{
    struct _find_cs_cachedev_conn arg;

    if (0 == cachedev_id) {
        rna_printk(KERN_NOTICE, "Can't inject cd_fail for cachedev [0x0]\n");
        return;
    }

    arg.f_cachedev_id = cachedev_id;
    arg.f_nfound = 0;
    arg.f_doall = FALSE;
    arg.f_func = rnablk_cfs_inject_rdma_cd_fail;

    rnablk_cache_conn_foreach(rnablk_find_cs_cachedev_conn, &arg);

    if (arg.f_nfound != 1) {
        rna_printk(KERN_NOTICE, "Injected rdma_cd_fail on %d cache devices\n",
                   arg.f_nfound);
    }
}


static void
rnablk_cfs_inject_cache_resp_cd_fail(struct rnablk_server_conn *conn,
                                     cachedev_id_t cachedev_id,
                                     void *unused)
{
    rna_printk(KERN_ERR, "Inject CACHE_RESP cachedev error for cachedev "
               "[%"PRIx64"]\n", cachedev_id);
    test_cachedev_fail_cache_resp = cachedev_id;
}

static void
rnablk_attr_store_inject_cache_resp_cd_fail(cachedev_id_t cachedev_id)
{
    struct _find_cs_cachedev_conn arg;

    if (0 == cachedev_id) {
        rna_printk(KERN_NOTICE, "Can't inject cd_fail for cachedev [0x0]\n");
        return;
    }

    arg.f_cachedev_id = cachedev_id;
    arg.f_nfound = 0;
    arg.f_doall = FALSE;
    arg.f_func = rnablk_cfs_inject_cache_resp_cd_fail;

    rnablk_cache_conn_foreach(rnablk_find_cs_cachedev_conn, &arg);

    if (arg.f_nfound != 1) {
        rna_printk(KERN_NOTICE, "Injected cache_resp_cd_fail on %d "
                   "cache devices\n", arg.f_nfound);
    }
}

static void
rnablk_cfs_inject_cache_ref_resp_cd_fail(struct rnablk_server_conn *conn,
                                         cachedev_id_t cachedev_id,
                                         void *unused)
{
    rna_printk(KERN_ERR, "Inject CACHE_REF_RESP cachedev error for cachedev "
               "[%"PRIx64"]\n", cachedev_id);
    test_cachedev_fail_cache_ref_resp = cachedev_id;
}

static void
rnablk_attr_store_inject_cache_ref_resp_cd_fail(cachedev_id_t cachedev_id)
{
    struct _find_cs_cachedev_conn arg;

    if (0 == cachedev_id) {
        rna_printk(KERN_NOTICE, "Can't inject cd_fail for cachedev [0x0]\n");
        return;
    }

    arg.f_cachedev_id = cachedev_id;
    arg.f_nfound = 0;
    arg.f_doall = FALSE;
    arg.f_func = rnablk_cfs_inject_cache_ref_resp_cd_fail;

    rnablk_cache_conn_foreach(rnablk_find_cs_cachedev_conn, &arg);

    if (arg.f_nfound != 1) {
        rna_printk(KERN_NOTICE, "Injected cache_ref_resp_cd_fail on %d "
                   "cache devices\n", arg.f_nfound);
    }
}

static void
rnablk_cfs_inject_cs_disconnect(struct rnablk_server_conn *conn,
                                cachedev_id_t cachedev_id, void *void_idx)
{
    rnablk_cachedev_t *cdp;
    struct list_head *ent;
    int idx = (int)(uintptr_t)void_idx;
    int i;

    rna_printk(KERN_ERR, "Inject disconnect for cachedev=%"PRIx64" idx=%d "
               "on conn ["CONNFMT"]\n", cachedev_id, idx, CONNFMTARGS(conn));

    if (0 == idx) {
        rna_printk(KERN_ERR, "Disconnecting primary CS connection [%p]\n",
                   conn);
        rnablk_drop_connection(conn);
    } else {
        cdp = rnablk_get_conn_cachedev(conn, cachedev_id, FALSE);
        if (NULL == cdp) {
            rna_printk(KERN_ERR, "Unable to inject CS disconnect for "
                       "cachedev [%#"PRIx64"] idx=%d, cachedev not found\n",
                       cachedev_id, idx);
            return;
        }
        if (NULL != cdp->rcd_conns[idx-1]) {
            rna_printk(KERN_ERR, "Disconnecting cachedev [%#"PRIx64"] idx=%d "
                       "conn ["CONNFMT"]\n", cachedev_id, idx,
                       CONNFMTARGS(conn));
            rnablk_drop_connection(cdp->rcd_conns[idx-1]);
        } else {
            rna_printk(KERN_ERR, "Unable to inject CS disconnect for "
                       "cachedev [%#"PRIx64"] idx=%d, conn not found\n",
                       cachedev_id, idx);
        }
        rnablk_put_cachedev(cdp);
    }            
    return;
}

static int
rnablk_cfs_inject_cs_primary_disconnect(struct rnablk_server_conn *conn,
                                        void *unused)
{
    if (APP_TYPE_CS == conn->id.u.data.type) {
        rna_printk(KERN_ERR, "Injecting disconnect of primary CS conn "
                   "["CONNFMT"]\n", CONNFMTARGS(conn));
        rnablk_drop_connection(conn);
    }
    return 0;
}

static void
rnablk_attr_store_inject_cs_disconnect(cachedev_id_t cachedev_id, int idx)
{
    struct _find_cs_cachedev_conn arg;

    if (0 == cachedev_id) {
        /* Disconnect all primary CS conn's */
        rnablk_cache_conn_foreach(rnablk_cfs_inject_cs_primary_disconnect,
                                  NULL);
    } else {
        arg.f_cachedev_id = cachedev_id;
        arg.f_nfound = 0;
        arg.f_arg = (void *)((uintptr_t)idx);
        arg.f_doall = FALSE;
        arg.f_func = rnablk_cfs_inject_cs_disconnect;

        rnablk_cache_conn_foreach(rnablk_find_cs_cachedev_conn, &arg);

        if (arg.f_nfound != 1) {
            rna_printk(KERN_NOTICE, "Performed CS disconnect for %d "
                       "cache devices\n", arg.f_nfound);
        }
    }
}


static void
rnablk_attr_store_inject_io_cs_disconnect(cachedev_id_t cachedev_id, int idx)
{
    struct rnablk_server_conn *conn = NULL;
    rnablk_cachedev_t *cdp;
    struct list_head *ent;
    int i;

    rna_printk(KERN_ERR, "Inject I/O disconnect for cachedev=%"PRIx64
               " idx=%d\n", cachedev_id, idx);

    if (cachedev_id == 0 || idx == 0) {
        rna_printk(KERN_ERR, "This interface can't be used to inject "
                   "a primary CS disconnect\n");
        return;
    }

    rnablk_cache_conn_foreach(rnablk_find_cs_conn, &conn);

    if (conn == NULL) {
        rna_printk(KERN_ERR, "Unable to inject I/O CS disconnect; no "
                   "CS connection found\n");
        return;
    }

    cdp = rnablk_get_conn_cachedev(conn, cachedev_id, FALSE);
    if (NULL == cdp) {
        rna_printk(KERN_ERR, "Unable to inject CS disconnect for "
                   "cachedev=%"PRIx64" connidx=%d, cachedev not found\n",
                   cachedev_id, idx);
        return;
    }
    if (NULL != cdp->rcd_conns[idx-1]) {
        rna_printk(KERN_ERR, "Inject I/O disconnecting for conn=%p\n",
                   cdp->rcd_conns[idx-1]);
        test_dev_conn_disconnect = idx;
    }
    rnablk_put_cachedev(cdp);
    return;
}
#endif /* TEST_OFFLINE_CACHE_DEVICE */

static void
rnablk_attr_store_inject_invd(char *devname, uint64_t blkno)
{
    struct rnablk_server_conn *conn = NULL;
    struct rnablk_device *dev;
    struct cache_cmd *cmd;
    struct com_ep *ep;

    rnablk_cache_conn_foreach(rnablk_find_cs_conn, &conn);

    dev = rnablk_find_device(devname);
    if (NULL == dev) {
        rna_printk(KERN_ERR, "Unable to invalidate blkno [%"PRIu64"], device "
                   "[%s] not found\n", blkno, devname);
        return;
    }
        
    if (conn == NULL || (ep = conn->ep) == NULL) {
        rna_printk(KERN_ERR, "Unable to invalidate blkno [%"PRIu64"], no "
                   "CS connection found\n", blkno);
        return;
    }

    if ((cmd = kmalloc(sizeof(*cmd), GFP_KERNEL)) == NULL) {
        rna_printk(KERN_ERR, "Unable to invalidate blkno [%"PRIu64"], malloc "
                   "error\n", blkno);
        return;
    }

    com_inc_ref_ep(ep);
    strncpy(cmd->u.cache_invd.rnas.cis_pathname, dev->cache_file_name, 256);
    cmd->u.cache_invd.rnas.cis_block_num = blkno;
    rna_printk(KERN_ERR, "Injecting Invalidate of blkno [%"PRIu64"] on "
               "device [%s] [%s]\n", blkno, devname,
               cmd->u.cache_invd.rnas.cis_pathname);
    rnablk_process_cache_invd(ep, cmd, TRUE);
    rna_printk(KERN_ERR, "Done with Invalidate injection for blkno [%"PRIu64"] "
               "on device [%s]\n", blkno, devname);
    rnablk_dev_release(dev);
    com_release_ep(ep);
    kfree(cmd);
}

static ssize_t
rnablk_driver_attr_show(struct config_item *item,
                        struct configfs_attribute *attr,
                        char *page )
{
    int len = 0;
    int page_size = 4096;   // TODO: Get this from CFS somehow
    ENTER;

    if( strcmp( attr->ca_name,"version" ) == 0 )
        len = sprintf( page,"%s","2.5\n" );
    else if( strcmp( attr->ca_name,"max_wr" ) == 0 )
        len = sprintf( page,"%d\n",max_wr );
    else if( strcmp( attr->ca_name,"max_sge" ) == 0 )
        len = sprintf( page,"%d\n",max_sge );
    else if( strcmp( attr->ca_name,"max_rs" ) == 0 )
        len = sprintf( page,"%"PRIu64"\n",max_rs );
    else if( strcmp( attr->ca_name,"bounce_buffer_bytes" ) == 0 )
        len = sprintf( page,"%d\n",rb_bounce_buffer_bytes );
    else if( strcmp( attr->ca_name,"bounce_segment_bytes" ) == 0 )
        len = sprintf( page,"%d\n",rb_bounce_segment_bytes );
    else if( strcmp( attr->ca_name,"dbg_flags" ) == 0 )
        len = sprintf( page,"%d\n",dbg_flags );
    else if( strcmp( attr->ca_name,"rna_printk_level" ) == 0 )
        len = sprintf( page,"%d\n",rna_printk_level );
    else if( strcmp( attr->ca_name,"cfm_addrs" ) == 0 )
        len = sprintf( page,"%s\n",cfm_config_info.cfm_addrs_string );
    else if( strcmp( attr->ca_name,"node_name" ) == 0 )
        len = sprintf( page,"%s\n",node_name );
    else if( strcmp( attr->ca_name,"status" ) == 0 )
        len = sprintf( page,"%s\n", get_rnablk_cache_status_display_string(atomic_read(&g_conn_status)));
    else if( strcmp( attr->ca_name,"in_use" ) == 0 )
        len = sprintf( page,"%d\n",rnablk_is_driver_in_use() );
    else if( strcmp( attr->ca_name,"enable_creates" ) == 0 )
        len = sprintf( page,"%d\n",enable_creates );
    else if( strcmp( attr->ca_name,"rna_com_retry_count" ) == 0 )
        len = sprintf( page,"%d\n",rna_com_retry_count );
    else if( strcmp( attr->ca_name,"rna_com_rnr_retry_count" ) == 0 )
        len = sprintf( page,"%d\n",rna_com_rnr_retry_count );
    else if( strcmp( attr->ca_name,"net_link_mask" ) == 0 )
        len = sprintf( page,"%d\n",net_link_mask );
    else if( strcmp( attr->ca_name,"read_deref_secs" ) == 0 )
        len = sprintf( page,"%d\n",read_deref_secs );
    else if( strcmp( attr->ca_name,"write_deref_secs" ) == 0 )
        len = sprintf( page,"%d\n",write_deref_secs );
    else if( strcmp( attr->ca_name,"max_connection_failures" ) == 0 )
        len = sprintf( page,"%d\n",max_connection_failures );
    else if( strcmp( attr->ca_name,"io_timeout" ) == 0 )
        len = sprintf( page,"%ld\n",rnablk_io_timeout );
    else if( strcmp( attr->ca_name,"use_req_queue" ) == 0 )
        len = sprintf( page,"%d\n",rnablk_use_req_queue );
    else if( strcmp( attr->ca_name,"queue_bios" ) == 0 )
        len = sprintf( page,"%d\n",rnablk_queue_bios );
    else if( strcmp( attr->ca_name,"use_write_only" ) == 0 )
        len = sprintf( page,"%d\n",rnablk_use_write_only );
    else if( strcmp( attr->ca_name,"per_device_connections" ) == 0 )
        len = sprintf( page,"%d\n",rnablk_per_device_connections );
    else if( strcmp( attr->ca_name,"devices_list" ) == 0 )
        len = rnablk_print_devs(page, page_size);
    else if( strcmp( attr->ca_name,"io_queue_depth" ) == 0 )
        len = sprintf( page,"%d\n",rnablk_io_queue_depth );
    else if( strcmp( attr->ca_name,".debug" ) == 0 ) {
        len = sprintf(page,
                      "Driver debug info:\n"
                      "IOS count [%3d] "
                      "Anonymous drop ref requests [%d] "
                      "Slow work queue items [%d]\n",
                      atomic_read(&ios_count),
                      atomic_read(&anon_drop_ref_requests),
                      atomic_read(&slow_workq_items));
        len += rnablk_print_conns(page + len, page_size - len);
    } else if( strcmp( attr->ca_name,".show_conns" ) == 0 ) {
        len = sprintf(page, "write here to see conn info in log\n");
    } else if (strcmp( attr->ca_name, ".inject_deref_request" ) == 0) {
        len = sprintf(page, "write cachedev_id to this file to simulate a "
                      "CACHE_DEREF_REQUEST for that cache device.\n"
                      "A value of 0 will generate a DEREF for all known "
                      "cache devices\n");
#ifdef TEST_OFFLINE_CACHE_DEVICE
    } else if (strcmp( attr->ca_name, ".expel_cd" ) == 0) {
        len = sprintf(page, "write cachedev_id to this file to expel it\n");
    } else if (strcmp( attr->ca_name, ".expel_cd2" ) == 0) {
        len = sprintf(page, "write cachedev_id to this file to expel it via "
                      "UNEXPELLED_CACHEDEVS msg\n");
    } else if (strcmp( attr->ca_name, ".expel_cd3" ) == 0) {
        len = sprintf(page, "write cachedev_id to this file to expel all "
                      "cachedevs with ID below this value\n");
    } else if (strcmp( attr->ca_name, ".fail_cd" ) == 0) {
        len = sprintf(page, "write cachedev_id to this file to fail it\n");
    } else if (strcmp( attr->ca_name, ".inject_ldma_cd_fail") == 0) {
        len = sprintf(page, "write cachedev_id to this file to inject an "
                      "ldma cache-device failure for it\n");
    } else if (strcmp(attr->ca_name, ".inject_rdma_cd_fail") == 0) {
        len = sprintf(page, "write cachedev_id to this file to inject an "
                      "rdma cache-device failure for it\n");
    } else if (strcmp(attr->ca_name, ".inject_cache_resp_cd_fail") == 0) {
        len = sprintf(page, "write cachedev_id to this file to inject a "
                      "cache response cache-device failure for it\n");
    } else if (strcmp(attr->ca_name, ".inject_cache_ref_resp_cd_fail")
               == 0) {
        len = sprintf(page, "write cachedev_id to this file to inject an "
                      "cache reference response cache-device failure for it\n");
    } else if (strcmp( attr->ca_name, ".inject_cs_disconnect" ) == 0) {
        len = sprintf(page, "write cachedev_id & an index to this file to "
                      "inject a disconnect\nfor a specific per-cachedev "
                      "connection.\nA value of 0 & 0 "
                      "will disconnect the primary cache-server connection.\n");
    } else if (strcmp( attr->ca_name, ".inject_io_cs_disconnect" ) == 0) {
        len = sprintf(page, "write cachedev_id & an index to this file to "
                      "inject an I/O-based disconnect\n"
                      "for a specific cachedev connection.\n");
#endif /* TEST_OFFLINE_CACHE_DEVICE */
    } else if( strcmp( attr->ca_name,".ios_timeout_script" ) == 0 ) {
        len = rnablk_ios_timeout_script_show(page);
#ifdef IOS_TIMEOUT_TEST
    } else if( strcmp( attr->ca_name,".ios_timeout_test" ) == 0 ) {
        len = rnablk_ios_timeout_test_show(page);
#endif /* IOS_TIMEOUT_TEST */
    } else if (strcmp(attr->ca_name, ".inject_invd") == 0) {
        len = sprintf(page, "write \"blkno devname\" to this file to "
                      "inject an invalidate for that block\n");
    } else if( strcmp( attr->ca_name,".latency_stats" ) == 0 ) {
        len = rnablk_print_latency_stats(page, page_size);
    } else if (strcmp(attr->ca_name, "reference_target_age") == 0) {
        len = sprintf(page, "%lu seconds\n",
                      rnablk_reference_target_age / 1000);
    } else if (strcmp(attr->ca_name, "write_reference_target_age") == 0) {
        len = sprintf(page, "%lu seconds\n",
                      rnablk_write_reference_target_age / 1000);
    } else if (strcmp(attr->ca_name,
                      "write_reference_release_max_outstanding") == 0) {
        len = sprintf(page, "%u writer reference drops/downgrades per CS\n",
                      rnablk_write_reference_release_max_outstanding);
    } else if (strcmp(attr->ca_name,
                      "scsi_unmap_disable") == 0) {
        len = sprintf(page, "SCSI UNMAP command %ssupported\n",
                      rnablk_scsi_unmap_disable ? "not " : "");
    } else if (strcmp(attr->ca_name,
                      "scsi_write_same_disable") == 0) {
        len = sprintf(page,
                      "SCSI WRITE_SAME and WRITE_SAME_16 command %ssupported\n",
                      rnablk_scsi_write_same_disable ? "not " : "");
    } else if (strcmp(attr->ca_name, ".inject_detach") == 0) {
        len = sprintf(page, "write here to simulate client being detached "
                      "from cluster\n");
    } else if (strcmp(attr->ca_name, ".inject_rejoin") == 0) {
        len = sprintf(page, "write here to simulate client rejoining "
                      "cluster after being detached\n");
    } else if (strcmp(attr->ca_name, "detached") == 0) {
        len = sprintf(page, "%d\n", atomic_read(&rna_service_detached));
    } else if (strcmp(attr->ca_name, ".cs_ping_interval") == 0) {
        len = sprintf(page, "%dms\n",
                      jiffies_to_msecs(rnablk_cs_ping_interval));
    } else if (strcmp(attr->ca_name, "cs_conns_rdma_only") == 0) {
        len = sprintf(page, "%d\n", rnablk_only_use_rdma_for_cs);
    }

    EXITVAL( len );
}

#if 0
int parse_ip_addr(char *ip, char **remainder, uint32_t *addr, uint32_t *port)
{
	char temp;
	int	value;
    int ret = 0;
	
	int i;
	char *a, *cur;
	
	*addr = 0;
	a = (char*)addr;
	cur = ip;
	temp = *cur;
	
	for (i = 0; i < 4; i++) {
		value = 0;
        for (;;) {
                 if (isascii(temp) && isdigit(temp)) {
	                value = (value * 10) + temp - '0';
                    temp = *++cur;
                } else
					break;
        }
        if (temp == ':') {
            if (NULL != port) {
                /* 
                 * For some reason, the compiler is fine with this,
                 * but does not like it when ++cur is in the call to simple_strtol.
                 * It warns that the opperation "may not be definted".
                 */
                ++cur;
                *port = (int) simple_strtol (cur, &cur, 0);
            }
        } else if (value > 255) {
        	ret = -1;
            break;
        }
        a[i] = (char)value;
        temp = *++cur;
	}
    *remainder = cur;
	return ret;
}
#endif

static ssize_t
rnablk_driver_attr_store(struct config_item *item,
                         struct configfs_attribute *attr,
                         const char *buf,size_t len)
{
    int rc;
    uint32_t addr;
    uint16_t port;
    int com_type;
    int cfm_count;
    cachedev_id_t cachedev_id;
    char *nextstr;
    int idx;
    int tmp = 0;
    char *remaining_cfm_addrs;
    uint64_t blkno;
    char devname[64];
    boolean cache_offline = TRUE;
    ENTER;

    if( strcmp( attr->ca_name,"max_wr" ) == 0 ) {
        max_wr = simple_strtoul( buf,NULL,10 );
        rna_printk(KERN_INFO, "max_wr=%d\n", max_wr);
    }
    else if ( strcmp( attr->ca_name,"max_sge" ) == 0 ) {
        max_sge = min(RNA_MAX_SGE, (int)simple_strtoul( buf,NULL,10 ));
        rna_printk(KERN_INFO, "max_sge=%d\n", max_sge);
    }
    else if( strcmp( attr->ca_name,"max_rs" ) == 0 ) {
        max_rs = simple_strtoul( buf,NULL,10 );
    }
    else if( strcmp( attr->ca_name,"bounce_buffer_bytes" ) == 0 ) {
        rb_bounce_buffer_bytes = simple_strtol( buf,NULL,10 );
    }
    else if( strcmp( attr->ca_name,"bounce_segment_bytes" ) == 0 ) {
        rb_bounce_segment_bytes = simple_strtol( buf,NULL,10 );
    }
    else if( strcmp( attr->ca_name,"enable_creates" ) == 0 ) {
        tmp = simple_strtoul( buf,NULL,10 );
        if (tmp != enable_creates) {
            rna_printk(KERN_NOTICE, "Device create requests will now be %s\n",
                       tmp ? "processed" : "ignored");
            enable_creates = tmp;
        }
    }
    else if( strcmp( attr->ca_name,"dbg_flags" ) == 0 ) {
        dbg_flags = simple_strtoul( buf,NULL,0 );
    }
    else if( strcmp( attr->ca_name,"rna_printk_level" ) == 0 ) {
        rna_printk_level = simple_strtoul( buf,NULL,10 );
    }
    else if( strcmp( attr->ca_name,"cfm_addrs" ) == 0 ) {
        if (atomic_read(&g_conn_status) != RNABLK_CACHE_OFFLINE) {
            cache_offline = FALSE;
        }
        if (len > sizeof(cfm_config_info.cfm_addrs_string)-1) {
            len=-EINVAL;
        } else {
            remaining_cfm_addrs = (char*)buf;
            cfm_count = 0;
            rc = 0;
            while (('\0' != *remaining_cfm_addrs) &&
                   (0 == rc) &&
                   (cfm_count < RNA_SERVICE_CFMS_MAX)) {

                rna_printk(KERN_DEBUG, "Parsing first CFM addr/port from [%s]\n", remaining_cfm_addrs);
                port = 0;
                com_type = IP_TCP;
                rc = rna_service_parse_ip_addr(remaining_cfm_addrs, &addr,
                                               &port, &com_type,
                                               &remaining_cfm_addrs);
                if (0 == rc) {
                    if (0 == port) {
                        port = CONF_MGR_PORT;
                    }
                    if (cache_offline) {
                        cfm_config_info.cfms[cfm_count].ip_addr.sin_addr.s_addr = addr;
                        cfm_config_info.cfms[cfm_count].ip_addr.sin_port = port;
                        cfm_config_info.cfms[cfm_count].com_type = com_type;
                        rna_printk(KERN_INFO, "CFM #%d addr[%08x] port [%d]\n",
                                   cfm_count,
                                   cfm_config_info.cfms[cfm_count].ip_addr.sin_addr.s_addr,
                                   cfm_config_info.cfms[cfm_count].ip_addr.sin_port);
                    } else {
                        online_cfms[cfm_count].sin_port = port;
                        online_cfms[cfm_count].sin_addr.s_addr = addr;
                        rna_printk(KERN_INFO, "CFM #%d addr[%08x] port [%d]\n",
                                   cfm_count,
                                   online_cfms[cfm_count].sin_addr.s_addr,
                                   online_cfms[cfm_count].sin_port);
                    }
                    cfm_count++;
                } else {
                    len=-EINVAL;
                    goto out;
                }
            }
            if (0 == cfm_count) {
                len=-EINVAL;
                goto out;
            }
            rna_printk(KERN_INFO, "%d CFMs\n", cfm_count);
            if (cache_offline) {
                cfm_config_info.cfm_count = cfm_count;
                /* Retain entire string for display */
                strncpy(cfm_config_info.cfm_addrs_string, buf, sizeof(cfm_config_info.cfm_addrs_string));
                // strip newline from string
                if (cfm_config_info.cfm_addrs_string[
                    strlen(cfm_config_info.cfm_addrs_string) - 1] == '\n') {
                    cfm_config_info.cfm_addrs_string[
                    strlen(cfm_config_info.cfm_addrs_string) - 1] = '\0';
                }
                // change state so we won't kick off another kthread
                if (RNABLK_CACHE_OFFLINE != atomic_cmpxchg(&g_conn_status,
                                                           RNABLK_CACHE_OFFLINE,
                                                           RNABLK_CACHE_INITIALIZING)) {
                    len=-EINVAL;
                    goto out;
                }
                kthread_run( rnablk_service_init,NULL,"rnablk_control_ct");
            } else {
                if (0 == rnablk_process_cfms_update(cfm_count, online_cfms)) {
                    cfm_config_info.cfm_count = cfm_count;
                    /* Retain entire string for display */
                    strncpy(cfm_config_info.cfm_addrs_string,
                            buf, sizeof(cfm_config_info.cfm_addrs_string));
                    // strip newline from string
                    if (cfm_config_info.cfm_addrs_string[
                        strlen(cfm_config_info.cfm_addrs_string) - 1] == '\n') {
                        cfm_config_info.cfm_addrs_string[
                        strlen(cfm_config_info.cfm_addrs_string) - 1] = '\0';
                    }
                } else {
                    len = -EAGAIN;
                }
            }
        }
    }
    else if(strcmp(attr->ca_name,"node_name") == 0) {
        if (len > sizeof(node_name) - 1) {
            len=-EINVAL;
        } else {
            strncpy(node_name, buf, sizeof(node_name));
            // strip newline from string
            if (node_name[strlen(node_name) - 1] == '\n') {
                node_name[strlen(node_name) - 1] = '\0';
            }
            rna_printk(KERN_INFO, "node_name [%s]\n", node_name);
        }
    }
    else if( strcmp( attr->ca_name,"rna_com_retry_count" ) == 0 ) {
        int val = simple_strtoul( buf,NULL,10 );
        if (val < 0 || val > 7)
            len=-EINVAL;
        else
            rna_com_retry_count = val;
    }
    else if( strcmp( attr->ca_name,"rna_com_rnr_retry_count" ) == 0 ) {
        int val = simple_strtoul( buf,NULL,10 );
        if (val < 0 || val > 7)
            len=-EINVAL;
        else
            rna_com_rnr_retry_count = val;
    }
    else if( strcmp( attr->ca_name,"net_link_mask" ) == 0 ) {
        net_link_mask = simple_strtoul( buf,NULL,0 );
    }
    else if( strcmp( attr->ca_name,"read_deref_secs" ) == 0 ) {
        read_deref_secs = simple_strtoul( buf,NULL,10 );
        rna_printk(KERN_INFO, "read_deref_secs now %d\n", read_deref_secs);
    }
    else if( strcmp( attr->ca_name,"write_deref_secs" ) == 0 ) {
        write_deref_secs = simple_strtoul( buf,NULL,10 );
        rna_printk(KERN_INFO, "write_deref_secs now %d\n", write_deref_secs);
    }
    else if( strcmp( attr->ca_name,"max_connection_failures" ) == 0 ) {
        max_connection_failures = simple_strtoul( buf,NULL,10 );
        rna_printk(KERN_INFO, "max_connection_failures now %d\n",
               max_connection_failures);
    }
    else if( strcmp( attr->ca_name,"io_timeout" ) == 0 ) {
        rnablk_io_timeout = simple_strtoul( buf,NULL,10 );
        rna_printk(KERN_INFO, "io_timeout now %ld\n", rnablk_io_timeout);
    }
    else if(strcmp(attr->ca_name, "use_req_queue") == 0) {
        tmp = simple_strtoul( buf,NULL,10 );
        if (tmp != rnablk_use_req_queue) {
            rna_printk(KERN_NOTICE, "Request queue will%s be used\n",
                       tmp ? "" : " not");
            rnablk_use_req_queue = tmp;
        }
    }
    else if(strcmp(attr->ca_name, "queue_bios") == 0) {
        tmp = simple_strtoul( buf,NULL,10 );
        if (tmp != rnablk_queue_bios) {
            rna_printk(KERN_NOTICE, "BIOs will%s be queued\n",
                       tmp ? "" : " not");
            rnablk_queue_bios = tmp;
        }
    }
    else if(strcmp(attr->ca_name, "use_write_only") == 0) {
        tmp = simple_strtoul( buf,NULL,10 );
        if (tmp != rnablk_use_write_only) {
            rna_printk(KERN_NOTICE, "Write-only references will%s be used\n",
                       tmp ? "" : " not");
            rnablk_use_write_only = tmp;
        }
    }
    else if(strcmp(attr->ca_name, "per_device_connections") == 0) {
        rnablk_per_device_connections =
                      MIN(RNABLK_MAX_DEV_CONNS, simple_strtoul(buf, NULL, 10));
        rna_printk(KERN_INFO, "Setting per_device_connections to %d\n",
                   rnablk_per_device_connections);
    }
    else if(strcmp(attr->ca_name, "io_queue_depth") == 0) {
        rnablk_io_queue_depth = simple_strtoul(buf, NULL, 10);
        rna_printk(KERN_NOTICE, "IO queue depth is now %d\n", rnablk_io_queue_depth);
    }
    else if( strcmp( attr->ca_name,".show_conns" ) == 0 ) {
        rnablk_conn_list_show();
    } else if( strcmp( attr->ca_name,".inject_deref_request" ) == 0 ) {
        cachedev_id = simple_strtoul(buf, NULL, 0); 
        rnablk_attr_store_inject_deref_request(cachedev_id);
#ifdef TEST_OFFLINE_CACHE_DEVICE
    } else if (strcmp(attr->ca_name, ".expel_cd") == 0) {
        cachedev_id = simple_strtoul(buf, NULL, 0); 
        rnablk_attr_store_expel_cd(cachedev_id);
    } else if (strcmp(attr->ca_name, ".expel_cd2") == 0) {
        cachedev_id = simple_strtoul(buf, NULL, 0); 
        rnablk_attr_store_expel_cd2(cachedev_id);
    } else if (strcmp(attr->ca_name, ".expel_cd3") == 0) {
        cachedev_id = simple_strtoul(buf, NULL, 0); 
        rnablk_attr_store_expel_cd3(cachedev_id);
    } else if (strcmp(attr->ca_name, ".fail_cd") == 0) {
        cachedev_id = simple_strtoul(buf, NULL, 0); 
        rnablk_attr_store_fail_cd(cachedev_id);
    } else if (strcmp(attr->ca_name, ".inject_ldma_cd_fail") == 0) {
        cachedev_id = simple_strtoul(buf, NULL, 0); 
        rnablk_attr_store_inject_ldma_cd_fail(cachedev_id);
    } else if (strcmp(attr->ca_name, ".inject_rdma_cd_fail") == 0) {
        cachedev_id = simple_strtoul(buf, NULL, 0); 
        rnablk_attr_store_inject_rdma_cd_fail(cachedev_id);
    } else if (strcmp(attr->ca_name, ".inject_cache_resp_cd_fail") == 0) {
        cachedev_id = simple_strtoul(buf, NULL, 0); 
        rnablk_attr_store_inject_cache_resp_cd_fail(cachedev_id);
    } else if (strcmp(attr->ca_name, ".inject_cache_ref_resp_cd_fail")
               == 0) {
        cachedev_id = simple_strtoul(buf, NULL, 0); 
        rnablk_attr_store_inject_cache_ref_resp_cd_fail(cachedev_id);
    } else if (strcmp(attr->ca_name, ".inject_cs_disconnect") == 0) {
        cachedev_id = simple_strtoul(buf, &nextstr, 0); 
        while (*nextstr == ' ' || *nextstr == '\t') {
            nextstr++;
        }
        idx = simple_strtoul(nextstr, NULL, 0);
        rnablk_attr_store_inject_cs_disconnect(cachedev_id, idx);
    } else if (strcmp(attr->ca_name, ".inject_io_cs_disconnect") == 0) {
        cachedev_id = simple_strtoul(buf, &nextstr, 0); 
        while (*nextstr == ' ' || *nextstr == '\t') {
            nextstr++;
        }
        idx = simple_strtoul(nextstr, NULL, 0);
        rnablk_attr_store_inject_io_cs_disconnect(cachedev_id, idx);
#endif /* TEST_OFFLINE_CACHE_DEVICE */
    } else if (strcmp(attr->ca_name, ".inject_invd") == 0) {
        blkno = simple_strtoul(buf, &nextstr, 0); 
        while (*nextstr == ' ' || *nextstr == '\t') {
            nextstr++;
        }
        strncpy(devname, nextstr, sizeof(devname));
        rnablk_attr_store_inject_invd(devname, blkno);
    } else if( strcmp( attr->ca_name,".ios_timeout_script" ) == 0 ) {
        if (rnablk_ios_timeout_script_store(buf, len) != 0) {
            len = -EINVAL;
        }
    } else if( strcmp( attr->ca_name,".ios_timeout_script_test" ) == 0 ) {
        if (rnablk_ios_timeout_script_test_store(buf, len) != 0) {
            len = -EINVAL;
        }
    } else if( strcmp( attr->ca_name,".ios_timeout_script_finish" ) == 0 ) {
        if (rnablk_ios_timeout_script_finish_store(buf, len) != 0){
            len = -EINVAL;
        }
    } else if (strcmp(attr->ca_name, "reference_target_age") == 0) {
        unsigned long tmp = simple_strtoul(buf, NULL, 10);

        rna_printk(KERN_NOTICE, "Changing reference_target_age "
                   "from %lus to %lus\n",
                   rnablk_reference_target_age / 1000, tmp);
        rnablk_reference_target_age = tmp * 1000;
        if (0 != rnablk_reference_target_age) {
            rnablk_enable_enforcer();
        }
    } else if (strcmp(attr->ca_name, "write_reference_target_age") == 0) {
        unsigned long tmp = simple_strtoul(buf, NULL, 10);

        rna_printk(KERN_NOTICE, "Changing write_reference_target_age "
                   "from %lus to %lus\n",
                   rnablk_write_reference_target_age / 1000, tmp);
        rnablk_write_reference_target_age = tmp * 1000;
        if (0 != rnablk_write_reference_target_age) {
            rnablk_enable_enforcer();
        }
#ifdef IOS_TIMEOUT_TEST
    } else if( strcmp( attr->ca_name,".ios_timeout_test" ) == 0 ) {
        if (rnablk_ios_timeout_test_store(buf, len) != 0) {
            len = -EINVAL;
        }
#endif
    } else if (strcmp(attr->ca_name, "write_reference_release_max_outstanding") == 0) {
        tmp = simple_strtoul(buf, NULL, 10);

        rna_printk(KERN_NOTICE,
                   "Changing write_reference_release_max_outstanding "
                   "from %u to %d\n",
                   rnablk_write_reference_release_max_outstanding, tmp);
        rnablk_write_reference_release_max_outstanding = tmp;
    } else if(strcmp(attr->ca_name, "scsi_unmap_disable") == 0) {
        tmp = simple_strtoul(buf, NULL, 10);
        if (tmp != rnablk_scsi_unmap_disable) {
            rna_printk(KERN_NOTICE,
                       "SCSI UNMAP command %s\n",
                       tmp ? "disabled" : "enabled");
            rnablk_scsi_unmap_disable = tmp;
        }
    } else if(strcmp(attr->ca_name, "scsi_write_same_disable") == 0) {
        tmp = simple_strtoul(buf, NULL, 10);
        if (tmp != rnablk_scsi_write_same_disable) {
            rna_printk(KERN_NOTICE,
                       "SCSI WRITE_SAME and WRITE_SAME_16 command %s\n",
                       tmp ? "disabled" : "enabled");
            rnablk_scsi_write_same_disable = tmp;
        }
    } else if (strcmp(attr->ca_name, ".inject_detach") == 0) {
        rnablk_process_detach();
    } else if (strcmp(attr->ca_name, ".inject_rejoin") == 0) {
        rnablk_process_rejoin();
    } else if (strcmp(attr->ca_name, ".detached_shutdown") == 0) {
        rnablk_handle_detached_shutdown();
    } else if (strcmp(attr->ca_name, ".cs_ping_interval") == 0) {
        long int old_interval = rnablk_cs_ping_interval;

        rnablk_cs_ping_interval =
                        msecs_to_jiffies(simple_strtoul(buf, NULL, 0));
        if (old_interval != rnablk_cs_ping_interval) {
            rna_printk(KERN_NOTICE, "Modified CS ping interval from %ldms to "
                       "%ldms\n", old_interval, rnablk_cs_ping_interval);
            wake_up_interruptible(&rnablk_cs_ping_wq);
        }
    } else if (strcmp(attr->ca_name, "cs_conns_rdma_only") == 0) {
        rnablk_only_use_rdma_for_cs = simple_strtoul(buf, NULL, 10);
    }

 out:
    EXITVAL( (int)len );
}

static struct configfs_item_operations rnablk_driver_item_ops = {
	.show_attribute	 = rnablk_driver_attr_show,
    .store_attribute = rnablk_driver_attr_store,
};

static struct configfs_group_operations rnablk_driver_group_ops = {
	.make_group	= rnablk_make_group,
    .drop_item  = rnablk_release_group,
};

static struct config_item_type rnablk_driver_type = {
	.ct_item_ops  = &rnablk_driver_item_ops,
	.ct_group_ops = &rnablk_driver_group_ops,
	.ct_attrs	  = rnablk_driver_attrs,
	.ct_owner	  = THIS_MODULE,
};

static struct configfs_subsystem rnablk_subsys = {
	.su_group = {
		.cg_item = {
			.ci_namebuf = "fldc",
			.ci_type    = &rnablk_driver_type,
		},
	},
};

int rnablk_configfs_init( void )
{
    ENTER;

    config_group_init( &rnablk_subsys.su_group );
// XXX - where did this change?
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
    init_MUTEX( &rnablk_subsys.su_sem );
#else
    mutex_init(&rnablk_subsys.su_mutex);
#endif
    ret = configfs_register_subsystem( &rnablk_subsys );
    if( ret )
        printk( KERN_ERR "Error %d while registering subsystem %s\n",
                ret,rnablk_subsys.su_group.cg_item.ci_namebuf );

    EXIT;
}

void rnablk_configfs_cleanup( void )
{
    ENTER;

    configfs_unregister_subsystem( &rnablk_subsys );

    EXITV;
}
