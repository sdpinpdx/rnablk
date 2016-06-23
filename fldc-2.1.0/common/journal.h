/**
 * <journal.h> - Dell Fluid Cache block driver
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

#ifndef _JOURNAL_H_
#define _JOURNAL_H_

#include "platform.h"
#include "platform_network.h"

CODE_IDENT("$URL: https://svn.rnanetworks.com/full/tags/HERMES_2_1_0_RC1/common/journal.h $ $Id: journal.h 48107 2016-01-08 20:09:36Z pkrueger $")

#include "rna_service.h"    // for primary_cfm_id_t
#include "rna_service_id.h" // for struct rna_service_id, etc.
#include "cachedev.h"       // for cachedev_id_t
#include "cachedlun.h"      // for cached lun registration info
#include "meta_data.h"      // for NUM_MD_ORDINALS
#include "md5.h"            // for MD5_DIGEST_LENGTH
#if defined(LINUX_USER) || defined(WINDOWS_USER)
#include "com.h"            // for com_ep_handle_t in journal_info_t
#endif
#include "journal_defs.h"
#include "cmd_queue.h"
/*
 * The CFM journal has the following features:
 * 1. Support for transactions:  Logically, the journal is composed of a
 *    superblock, followed by a set of L1 version maps, followed by data
 *    blocks.  Each of these logical blocks is represented by two physical
 *    blocks.  The L0 version map in the superblock (block 0) together with
 *    the L1 version maps in the following blocks indicate which physical
 *    block in a block pair holds the current content of the logical block.
 *    The superblock is buffered in memory (in the superblock_buf).  A read
 *    request always reads the most recently written content for the block
 *    (i.e. the 'current' physical block of the block pair, as specified by
 *    the version map in the buffered superblock).  The first write of a block
 *    in a transaction writes to the non-current block of the block pair,
 *    making it the new current block (in the version map in the buffered
 *    superblock), and subsequent writes of the block in the transaction
 *    re-write the modified block.  A write transaction commits when the
 *    superblock_buf is written.  If the transaction doesn't commit, the
 *    modified superblock (containing the L0 version map) isn't written, so
 *    none of the changes made to the journal in the transaction are visible,
 *    since the original block contents (i.e. the content before the
 *    transaction began) continue to be 'current'.
 * 2. Three-way mirroring:  Three coherent copies of the journal are always
 *    maintained.  If access is lost to a mirror, another is created to replace
 *    it.  Each mirror contains a generation number and a record indicating
 *    where its peer mirrors are located.  This information can be used to
 *    verify that a set of journal mirrors is current (i.e. has the latest
 *    update), or to find the current set when starting from an obsolete mirror
 *    (see journal_open()).  A read requires at least one mirror to be
 *    accessible, and a write requires at least two (i.e. a write must complete
 *    on at two mirrors to commit).
 * 3. Merkle tree organization provides corruption detection and correction:
 *    The hash for each block is stored in that block's version map entry
 *    (i.e. outside the block).  As a result, all block corruptions can be
 *    detected, including lost writes, torn writes, mangled writes, etc.
 *    If a block is found to be corrupt in a journal mirror, a read is
 *    attempted from the next journal mirror.  If that read succeeds,
 *    it's used to correct the corrupted block.
 *
 * The journal is laid out as follows:
 *     First logical block (i.e. physical block pair):  Superblock
 *     Next JOURNAL_NUM_L1_BLOCKS logical blocks:  L1 version map
 *     All following logical blocks:  User data blocks:
 *         First user data block: journal block allocation bitmap
 *         Second data block: journal mirror index
 *         ...
 */


/*
 * The version number of the journal layout described in this file
 *
 * NOTES:
 * 1. When the JOURNAL_LAYOUT_VERSION needs to be incremented, it should be
 *    incremented to 15 for both VSA and non-VSA builds.  At that time, the
 *    #if (and this comment) can be removed.
 *
 * 2. The JOURNAL_LAYOUT_VERSION does not need to be incremented when adding a
 *    new block type to the journal, as long as code has been added to the CFM
 *    to create a block (or blocks) of that type if they don't yet exist.  The
 *    layout version needs, in general, to be incremented only if an existing
 *    block type is modified in an incompatible way, such as changing the
 *    format of one of its fields or adding a field in the middle of the struct
 *    (adding a field to the end of the struct may not cause compatability
 *    issues, so may not require the layout version to be incremented).
 */
#if ( defined ( BUILD_TYPE_VSA ) )
#define JOURNAL_LAYOUT_VERSION          14
#else
#define JOURNAL_LAYOUT_VERSION          13
#endif  /* build type */


/*
 * Journal errors
 */
#define RNA_JOURNAL_ERROR_IO            -1
            /* An I/O error occurred; details are in errno */
#define RNA_JOURNAL_ERROR_FULL          -2
            /* The journal is full, it's reached its maximum size */
#define RNA_JOURNAL_ERROR_INVALID       -3
            /* The request is invalid */
#define RNA_JOURNAL_ERROR_OVERRUN       -4
            /* The specified blocknum is greater than the maximum size of
             * a journal
             */
#define RNA_JOURNAL_ERROR_ID_MISMATCH   -5
            /* The js_journal_id doesn't match the cluster id */
#define RNA_JOURNAL_ERROR_VERSON_BITMAP -6
            /* The jb_type of the bitmap block is wrong */
#define RNA_JOURNAL_ERROR_INSUFFICIENT_MIRRORS -7
            /* Too few journal mirrors are accessible */
#define RNA_JOURNAL_ERROR_CORRUPT       -8
            /*
             * The requested block is corrupt in all accessible journal mirrors
             */
#define RNA_JOURNAL_ERROR_NO_TRANSACTION -9
            /* A write transaction must be in progress when this function is
             * called.
             */
#define RNA_JOURNAL_TRANSACTION_ID_MISMATCH   -10
            /* The remote response transaction ID doesn't match the request
             * or not found */
#define RNA_JOURNAL_NO_DATA -11
            /* No data was returned with the remote response */
#define RNA_JOURNAL_PRIMARY_MISMATCH -12
            /* remote message has differnt primay CFM info */
#define RNA_JOURNAL_LOC_MISMATCH -13
            /* remote message journal mirror not found on this node */
#define RNA_JOURNAL_MEM_ALLOC_FAILURE -14
            /* journal memory alloc failure */
#define RNA_JOURNAL_SEND_REQ_FAILURE -15
            /* remote request send failure*/
#define RNA_JOURNAL_REQ_PRIMARY -16
            /* remote request to primary */
#define RNA_JOURNAL_NO_CONFIG -17
            /* No configuration file record found*/
#define RNA_JOURNAL_SHUTTING_DOWN -18
            /* CFM is shutting down*/


/*
 * Journal location information (i.e. the path name of the journal or the wwn
 * of the cache device containing the journal).  Note that increasing this
 * constant may cause a journal_mirror_index_t to exceed the size of a journal
 * block (JOURNAL_BLOCK_SIZE_BYTES).
 */
#define JOURNAL_LOCATION_MAXLEN         1024


/*
 * A journal may be located either in a directory (in a filesystem) or on a
 * cache device.
 */
typedef enum {
    JOURNAL_LOCATION_UNUSED   = 0,
    JOURNAL_LOCATION_DIR      = 1,
    JOURNAL_LOCATION_CACHEDEV = 2,
} journal_location_type_t;


typedef enum {
    JOURNAL_BLOCK_TYPE_PHYSICAL,   /* The block number specifies a physical block in the journal */
    JOURNAL_BLOCK_TYPE_L1,         /* The block number species an L1 version map block in the journal */
    JOURNAL_BLOCK_TYPE_LOGICAL,    /* The block number specifies a logical block in the journal */
} journal_blocknum_t;

typedef int journal_io_status_t;

/*
 * A journal mirror is located either in a directory, in which case its
 * location is a pathname, or on a cache device, in which case its location
 * is a wwn).
 */
typedef struct journal_location_s {
    journal_location_type_t jl_type;
    char                    jl_location[JOURNAL_LOCATION_MAXLEN];
                                /* This field specifies a pathname if jl_type
                                 * is JOURNAL_LOCATION_DIR or a wwn string if
                                 * jl_type is JOURNAL_LOCATION_CACHEDEV
                                 */
    in_addr_t               jl_ipaddr;
    uint16_t                jl_cfm_port;
} journal_location_t;


/*
 * Journal block types (i.e. values for the jb_type field in a
 * journal_block_hdr_t)
 */
enum journal_block_type {
    JOURNAL_BLOCK_TYPE_AVAILABLE = 0,
                    /* a journal block that's not currently in use */
    JOURNAL_BLOCK_TYPE_SUPERBLOCK,
                    /* a journal block containing a journal_superblock_t */
    JOURNAL_BLOCK_TYPE_ALLOCATION_BITMAP,
                    /* a journal block containing the
                     * journal_allocation_bitmap_t
                     */
    JOURNAL_BLOCK_TYPE_MIRROR_INDEX,
                    /* a journal block containing a journal_mirror_index_t */
    JOURNAL_BLOCK_TYPE_GROUP,
                    /* a journal block containing a journal_group_t */
    JOURNAL_BLOCK_TYPE_CACHE_DEVICE,
                    /* a journal block containing a journal_cache_device_t */
    JOURNAL_BLOCK_TYPE_CACHED_LUN,
                    /* a journal block containing a journal_cached_lun_t */
    JOURNAL_BLOCK_TYPE_UNUSED,
                    /* for future use */
    JOURNAL_BLOCK_TYPE_DEBUG,
                    /* a journal block containing debug data*/
    JOURNAL_BLOCK_TYPE_CONFIG,
                    /* a journal block containing the current compressed configuration xml data*/
    JOURNAL_BLOCK_TYPE_LICENSE,
                    /* a journal block containing a time structure for eval license start */
    JOURNAL_BLOCK_TYPE_SAN_OBJECT,
                    /* a journal block containing information about a SAN object journal_san_object_t */
    JOURNAL_BLOCK_TYPE_VOLUME_OBJECT,
                    /* a journal block containing information about a volume object journal_vol_object_t */
    JOURNAL_BLOCK_TYPE_EVENT_HANDLERS,
                    /* a journal block containing a journal_eventhandlers_t */
    JOURNAL_BLOCK_TYPE_QUEUED_CMD,
                    /* a journal block containing a cmd_queue_data_t */
    JOURNAL_BLOCK_TYPE_LUN_REGISTRATIONS,
                    /* a journal block containing a journal_lun_registrations_t */
    JOURNAL_BLOCK_TYPE_LUN_MASK
                    /* a journal block containing a journal_lun_mask_t */
};


extern char *
journal_type_to_string(enum journal_block_type);


/*
 * A header for every journal block
 */
typedef struct journal_block_hdr_s {
    uint16_t      jb_layout_version; /* Journal layout version number (may be
                                      * valid only in the superblock)
                                      */
    uint8_t       jb_type;           /* Journal block type (see
                                      * journal_block_type)
                                      */
    uint8_t       jb_pad[5];         /* for future use */
} journal_block_hdr_t;


/*
 * An entry in a journal's bitmap of in-use blocks
 */
typedef uint64_t journal_bitmap_entry_t;


/*
 * MD5 is sufficient for the journal's purposes, since we're only looking for
 * corruption.
 */
#define JOURNAL_DIGEST_LENGTH MD5_DIGEST_LENGTH


/*
 * The hash of a journal block's content.
 */
typedef struct journal_digest_s {
    uint8_t jd_hash[JOURNAL_DIGEST_LENGTH];
} journal_digest_t;


/*
 * An entry in either the L0 or L1 version map.  This entry indicates which
 * block of the block pair is current and the hash value for its content.
 * The hash value is used to verify that the block is not corrupt.  Note that
 * since the hash is stored outside the block, it detects corruption caused
 * by lost writes, as well as all other corruption sources.
 */
typedef struct journal_version_map_entry_s {
    journal_digest_t jme_block_hash; /* Hash value calculated for the block
                                      * content
                                      */
    uint8_t          jme_current:1;  /* 0 indicates that the block 0 in the
                                      * block pair is current; 1 indicates that
                                      * block 1 in the block-pair is current.
                                      */
    uint8_t          jme_unused:7;   /* For future use */
} journal_version_map_entry_t;


/*
 * Cluster state enum.  Needed for transitional states that might need to
 * persist across lights-out failures (such as prepare for upgrade).
 */
typedef enum {
    JOURNAL_CLUSTER_STATE_INIT = 0,
    JOURNAL_CLUSTER_STATE_ACTIVE,
    JOURNAL_CLUSTER_STATE_PREPARE_MAINTENANCE,
    JOURNAL_CLUSTER_STATE_MAINTENANCE,
    JOURNAL_CLUSTER_STATE_EXIT_MAINTENANCE,
    JOURNAL_CLUSTER_STATE_INVALID,
} journal_cluster_state;

INLINE const char *
journal_cluster_state_string(journal_cluster_state state)
{
    const char * ret = "Unknown";

    switch (state) {
        case JOURNAL_CLUSTER_STATE_INIT:
            ret = "Initializing"; break;
        case JOURNAL_CLUSTER_STATE_ACTIVE:
            ret = "Active"; break;
        case JOURNAL_CLUSTER_STATE_PREPARE_MAINTENANCE:
            ret = "Preparing for Maintenance"; break;
        case JOURNAL_CLUSTER_STATE_MAINTENANCE:
            ret = "In Maintenance Mode"; break;
        case JOURNAL_CLUSTER_STATE_EXIT_MAINTENANCE:
            ret = "Exiting Maintenance Mode"; break;
        case JOURNAL_CLUSTER_STATE_INVALID:
            ret = "Invalid"; break;
    }
    return ret;
}

#define NULL_INSTANCE_ID 0

/*
 * The L0 version map (journal block 0).  This map specifies which block in
 * each of the logical blocks (i.e. block pairs) composing the L1 version map
 * is current.  A journal transaction is committed by writing this block.
 */
typedef struct journal_superblock_s {
    journal_digest_t       js_superblock_hash;
                                            /* Hash calculated over the
                                             * superblock's content
                                             */
    struct b {
        rna_cluster_id_t   js_cluster_id;   /* The ID of the cluster this
                                             * journal belongs to
                                             */
        uint64_t           js_cluster_key;  /* The authentication token of the
                                             * cluster this journal belongs to
                                             */
        uint64_t           js_transaction_gen;
                                            /* Transaction generation number,
                                             * incremented at the end of each
                                             * journal write transaction
                                             */
        time_t             js_transaction_time;
                                            /* Timestamp of latest journal
                                             * transaction
                                             */
        uint32_t           js_highwater_blocknum;
                                            /* The highest-numbered logical
                                             * block number that has been
                                             * allocated in the journal.
                                             */
        uint8_t            js_invalid;      /* Non-zero if this journal is
                                             * invalid and should not be used
                                             */
        uint8_t            js_cluster_state;/* See enum journal_cluster_state */
        uint8_t            js_pad1[2];      /* For future use */
        uint64_t           js_pad2;         /* For future use */
    } b;
#define JOURNAL_L0_VERSION_MAP_SIZE (((JOURNAL_SINGLE_SECTOR_SIZE_BYTES - sizeof(journal_block_hdr_t)) - sizeof(journal_digest_t)) - sizeof(struct b)) / sizeof(journal_version_map_entry_t)
    journal_version_map_entry_t
                           js_L0_version_map[JOURNAL_L0_VERSION_MAP_SIZE];
                                            /* This bitmap indicates which
                                             * block in each of the L1 version
                                             * map block pairs is current.
                                             * 0 indicates that the first block
                                             * in the pair is current;
                                             * 1 indicates that the second
                                             * block in the block pair is
                                             * current.
                                             */
} journal_superblock_t;


/*
 * The number of L1 version map blocks contained in the journal.
 */
#define JOURNAL_NUM_L1_BLOCKS      JOURNAL_L0_VERSION_MAP_SIZE


/*
 * The physical block location of the superblock
 */
#define SUPERBLOCK_PHYS_BLOCKNUM     0

/*
 * Logical block number of the allocation bitmap block.  The allocation bitmap
 * indicates which logical journal blocks (i.e. physical block pairs) are
 * currently in use.
 */
#define JOURNAL_ALLOCATION_BITMAP_BLOCK 0


/*
 * Logical block number of the journal mirror index block.
 */
#define JOURNAL_MIRROR_INDEX_BLOCK      1

/*
 * First journal user data block
 */
#define JOURNAL_FIRST_DATA_BLOCK        2


/*
 * The size of an L1 version map (js_L1_version_map)
 */
#define JOURNAL_L1_VERSION_MAP_SIZE                  \
            ((JOURNAL_BLOCK_SIZE_BYTES  -            \
                sizeof(journal_block_hdr_t)) /       \
              sizeof(journal_version_map_entry_t))


/*
 * The L1 version map is stored in a series of JOURNAL_NUM_L1_BLOCKS logical
 * blocks (i.e. block pairs), with each L1 logical block corresponding to an
 * entry in the js_L0_version_map.  Like the L0 version map, each entry in
 * this map indicates which block in a block pair is current.
 */
typedef struct journal_L1_version_map_s {
    journal_version_map_entry_t js_L1_version_map[JOURNAL_L1_VERSION_MAP_SIZE];
                                            /* This bitmap indicates which
                                             * block in each block pair is
                                             * current.  0 indicates that the
                                             * first block in the pair is
                                             * current; 1 indicates that the
                                             * second block in the block pair is
                                             * current.
                                             */
} journal_L1_version_map_t;


/* The number of bitmap bits contained in an allocation bitmap entry */
#define JOURNAL_NUMBITS_PER_BITMAP_ENTRY            \
                 (CHAR_BIT *sizeof(uint64_t))


/*
 * The number of entries in a journal's allocation bitmap block.
 */
#define JOURNAL_ALLOCATION_BITMAP_SIZE                    \
            ((JOURNAL_BLOCK_SIZE_BYTES  -            \
                sizeof(journal_block_hdr_t)) /       \
              sizeof(journal_bitmap_entry_t))


/*
 * The maximum number of logical journal blocks (i.e. block pairs) that the
 * journal can contain.
 */
#define JOURNAL_MAX_LOGICAL_BLOCKS                                          \
            MIN((JOURNAL_L0_VERSION_MAP_SIZE *                              \
                    JOURNAL_L1_VERSION_MAP_SIZE *                           \
                    JOURNAL_NUMBITS_PER_BITMAP_ENTRY),                      \
                (JOURNAL_ALLOCATION_BITMAP_SIZE *                           \
                    JOURNAL_NUMBITS_PER_BITMAP_ENTRY))


/*
 * A bitmap indicating which logical journal blocks (i.e. physical block pairs)
 * are in use and which are available for use.
 */
typedef struct journal_allocation_bitmap_s {
    journal_bitmap_entry_t js_allocation_bitmap[JOURNAL_ALLOCATION_BITMAP_SIZE];
                                       /* A bitmap to indicate which logical
                                        * journal blocks (i.e. block pairs)
                                        * are currently in use.  1 indicates
                                        * in use,  0 indicates not in use.
                                        */
} journal_allocation_bitmap_t;


/*
 * A CFM Journal block that contains the locations of the three journal mirrors.
 */
typedef struct journal_mirror_index_s {
    journal_location_t    jmi_index[NUM_JOURNAL_MIRRORS];
} journal_mirror_index_t;


/*
 * A CFM Journal block that contains group information that must persist across
 * CFM failures
 */
typedef struct journal_group_s {
    uint32_t         jm_group_id;          /* The group that the values in this
                                            * journal block apply to
                                            */
    uint32_t         jm_pad;               /* For future use (and 64-bit
                                            * alignment)
                                            */
    struct cfm_md_partition_map
                     jm_partition_map;     /* Metadata partition map */
    uint64_t         jm_cs_membership_gen; /* Cache server membership
                                            * generation number
                                            */
    uint8_t          jm_available_md_ordinals[NUM_MD_ORDINALS];
                                           /* List of available MD ordinals */
    cachedev_id_t    jm_next_cachedev_id;  /* The ID that will be assigned to
                                            * the new or re-initialized cache
                                            * device
                                            */
    primary_cfm_id_t jm_primary_cfm;       /* The ID of the current (or most
                                            * recent) primary CFM
                                            */
    uint64_t         jm_cmd_queue_seq;     /* The next cmd queue sequence
                                            * number to allocate
                                            */
    uint64_t         jm_next_instance_id;  /* The CFM-assigned clusterwide
                                            * instance ID that will be
                                            * assigned to the next
                                            * newly-started component to
                                            * register with the CFM.
                                            */
} journal_group_t;


/*
 * A CFM Journal block that contains information about a cached LUN device
 *      derived from path_cfg_info_t
 *
 * JOURNAL_BLOCK_TYPE_CACHED_LUN
 *
 */

#define MD_POLICY_STR_SIZE  (63)
#define OPTS_STR_SIZE       (63)
#define TYPE_STR_SIZE       (63)

typedef struct journal_cached_lun_s {
    cached_lun_journal_info_t   jcl_cached_lun_info;
} journal_cached_lun_t;

/*
 * calculate the maximum number of entries that
 * can fit in a journal block.
 */
#ifndef DEBUG_JOURNAL_RESERVATIONS
#define MAX_ITN_REGISTRATION_ENTS ((JOURNAL_BLOCK_SIZE_BYTES - \
                            sizeof(journal_block_hdr_t) - \
                            sizeof(uint32_t) - \
                            sizeof(uint32_t)) / \
                            sizeof(rsv_registration_entry_t))
#else
#define MAX_ITN_REGISTRATION_ENTS 2
#endif

/*
 * A CFM journal block that contains information about ITN
 * registrations for SCSI reservations associated with cached LUNs
 *
 * JOURNAL_BLOCK_TYPE_LUN_REGISTRATION
 *
 */
typedef struct journal_lun_registrations_s {
    uint32_t                    jlr_reg_count;  /* entries in this block */
    uint32_t                    jlr_jnl_blk;    /* location of chained entry */
    rsv_registration_entry_t
                jlr_itn_registrations[MAX_ITN_REGISTRATION_ENTS];
} journal_lun_registrations_t;

/*
 * Information about a replica store.
 */
typedef struct journal_replica_store_info_s {
    cachedev_id_t          rs_replica_store_id;
                                /* The ID of this replica store */
    cachedev_id_t          rs_host_cache_device_id;
                                /* The ID of the cache device that contains
                                 * this replica store.
                                 */
    struct rna_service_id  rs_host_cache_server;
                                /* The cache server that manages the cache
                                 * device that hosts this replica store.
                                 */
    replica_store_state_t  rs_state;
                                /* The state of this replica store */
    uint32_t               rs_pad;
                                /* For future use, and for 64-bit alignment */
} journal_replica_store_info_t;


#if defined(LINUX_USER) || defined(WINDOWS_USER)
INLINE void rna_dump_journal_replica_store_info_xml(FILE *info_file, 
                                                    char *name,
                                                    journal_replica_store_info_t *replica)
{
	fprintf(info_file, "<replica_store_info");
    if (NULL != name) {
        fprintf(info_file, " name=\"%s\"", name);
    }
    fprintf(info_file, " replica_store_id=\"0x%"PRIx64"\"", replica->rs_replica_store_id);
    fprintf(info_file, " host_cache_device_id=\"0x%"PRIx64"\"", replica->rs_host_cache_device_id);
    fprintf(info_file, " state=\"%s\"", get_replica_store_state_string(replica->rs_state));
	fprintf(info_file, ">\n");

    rna_dump_cachedev_id_internal_xml(info_file, 
                                      "replica_store_id", 
                                      (cachedev_id_internal_t *)&replica->rs_replica_store_id);

    rna_dump_cachedev_id_internal_xml(info_file, 
                                      "host_cache_device_id", 
                                      (cachedev_id_internal_t *)&replica->rs_host_cache_device_id);

    rna_write_service_id_xml(info_file, "host_cache_server", &replica->rs_host_cache_server);

	fprintf(info_file, "</replica_store_info>\n");
}
#endif 

INLINE void
bswap_journal_replica_store_info_t(journal_replica_store_info_t *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    data->rs_replica_store_id = bswap_64(data->rs_replica_store_id);
    data->uc_prev_cachedev_id = bswap_64(data->rs_host_cache_device_id);
    bswap_rna_service_id(&data->rs_host_cache_server);
    data->uc_prev_cachedev_id = bswap_32(data->rs_state);
#endif
}


/*
 * The maximum number of previous replica stores whose information can be
 * stored in a CFM Journal block (journal_cache_device_t)
 *
 * 1st line: size of a journal_cache_device_t - the size of its jcd_info header
 * 2nd line: sum of the sizes of jrs_current fields in jcd_san_replica_stores
 * and jcd_das_replica_stores entries
 * 3rd line: size of jrs_prev_replica_stores fields in jcd_san_replica_stores
 * and jcd_das_replica_stores entries
 */
#define MAX_PREV_REPLICA_STORES                                             \
    (((JOURNAL_BLOCK_SIZE_BYTES - sizeof(cachedev_info_t)) -                \
       (MAX_REPLICA_STORES_USED * 2 * sizeof(journal_replica_store_info_t))) / \
     (MAX_REPLICA_STORES_USED * 2 * sizeof(journal_replica_store_info_t)))


/*
 * Information about a cache device's replica store
 */
typedef struct journal_replica_store_s {
    journal_replica_store_info_t
                            jrs_current;
                                /* Information about the current incarnation(s)
                                 * of this cache device's replica store.
                                 */
    journal_replica_store_info_t
                            jrs_prev_replica_stores[MAX_PREV_REPLICA_STORES];
                                /* Information about any still-existing
                                 * previous incarnations of this cache device's
                                 * replica store.  On occasion, it's necessary
                                 * to move a replica store from one host cache
                                 * device to another.  This array is the set of
                                 * prior locations of this replica store whose
                                 * content is in the process of being moved to
                                 * the current replica store.
                                 */
} journal_replica_store_t;


/*
 * A block in the CFM Journal that contains information about a cache device
 */
typedef struct journal_cache_device_s {
    cachedev_info_t           jcd_info; /* info. about the cache device */
    /*
     * NOTE:  DON'T ADD NEW FIELDS HERE.  Any new fields needed for this
     * struct should be added to cachedev_info_t.  Placing a new field here
     * will break the MAX_PREV_REPLICA_STORES calculation.
     */
    journal_replica_store_t  jcd_san_replica_stores[MAX_REPLICA_STORES_USED];
                                        /*
                                         * The cache device's replica stores
                                         * for blocks backed by SAN storage.
                                         */
    journal_replica_store_t  jcd_das_replica_stores[MAX_REPLICA_STORES_USED];
                                        /*
                                         * The cache device's replica stores
                                         * for blocks backed by direct-attached
                                         * storage.
                                         */
} journal_cache_device_t;

INLINE void
bswap_journal_cache_device_t(journal_cache_device_t *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    int i;

    bswap_cachedev_info_t(&data->jcd_info);
    for (i = 0; i < MAX_REPLICA_STORES_USED; i++) {
        bswap_journal_replica_store_t(&data->jcd_san_replica_stores);
        bswap_journal_replica_store_t(&data->jcd_das_replica_stores);
    }
#endif
}

typedef struct journal_debug_s {
    int dbg_a;
    int dbg_b;
    int dbg_c;
    int dbg_d;
} journal_debug_t;


/*
 * Journal records to support saving and restoring the cluster
 * configuration.
 */
typedef struct journal_cluster_config_hdr_s {
    uint16_t            jcc_page_num;
    uint16_t            jcc_num_bytes;
} journal_cluster_config_hdr_t;

#define JOURNAL_CONFIG_PAGE_SIZE                \
        (JOURNAL_BLOCK_SIZE_BYTES -             \
         (sizeof(journal_block_hdr_t) +         \
          sizeof(journal_cluster_config_hdr_t)))

typedef struct journal_cluster_config_s {
    journal_cluster_config_hdr_t    jcc_h;
    uint8_t                         jcc_config[JOURNAL_CONFIG_PAGE_SIZE];
} journal_cluster_config_t;

#define JOURNAL_LICENSE_XML_SIZE 4070
/*
 * A block in the CFM Journal that contains information about license
 */
typedef struct journal_license_s {
    time_t              jrnl_license_firstuse;
    uint8_t             jrnl_license_xml[JOURNAL_LICENSE_XML_SIZE];
} journal_license_t;

typedef struct journal_san_object {
    char                jso_san_id[J_SAN_ID_LEN];
    char                jso_san_name[J_SAN_NAME_LEN];
    char                jso_san_type[J_SAN_TYPE_LEN];
    char                jso_san_status[J_SAN_STATUS_LEN];
    int                 jso_mgmt_ip_count;
    struct j_mgmt_ip    jso_mgmt_ips[J_MAX_BIND_INTERFACES];
} journal_san_object_t;

typedef struct journal_vol_object {
    char                jvo_cache_mode[J_CACHE_MODE_LEN];
    char                jvo_config_cache_mode[J_CACHE_MODE_LEN];
    char                jvo_cache_policy[J_CACHE_POLICY_LEN];
    time_t              jvo_create_date;
    char                jvo_san_id[J_SAN_ID_LEN];
    char                jvo_san_vol_id[J_SAN_VOL_ID_LEN];
    char                jvo_hc_vol_id[J_HC_VOL_ID_LEN];
    char                jvo_vol_name[J_VOL_NAME_LEN];
    struct j_scsi_info  jvo_orig_scsi;
    struct j_scsi_info  jvo_alias_scsi;
    char                jvo_scsi_id[J_SCSI_ID_LEN];
    uint64_t            jvo_size_in_bytes;
    int                 jvo_status;
    int                 jvo_hv_status;
    int                 jvo_hv_status_event;
    uint32_t            jvo_hv_flags;
    // TODO: are hccID, hcnIDs, and isFlushing needed here?
} journal_vol_object_t;

typedef struct journal_lun_mask {
    uuid_t                  jlm_hcnid;
    int                     jlm_count;
    struct j_lun_mask_info  jlm_info[RNA_MAX_BACKING_STORES];
} journal_lun_mask_t;

typedef struct journal_eventhandlers {
    int                        jeh_eh_count;
    struct j_eventhandler_info jeh_eh_info[J_MAX_EVENT_HANDLERS];
} journal_eventhandlers_t;

/*
 * Journal block for cmd_queue_t
 * JOURNAL_BLOCK_TYPE_QUEUED_CMD
 */
typedef struct journal_cmd_queue_block {
    cmd_queue_data_t    jcq_queue_data;
} journal_cmd_queue_block_t;

/*
 * A block in the CFM Journal
 */
typedef struct journal_block_s {
    journal_block_hdr_t    h;  /* Every journal block has this header */
    union {
        journal_superblock_t            jb_superblock;
        journal_L1_version_map_t        jb_L1_version_map;
        journal_allocation_bitmap_t     jb_allocation_bitmap;
        journal_mirror_index_t          jb_mirror_index;
        journal_group_t                 jb_group;
        journal_cache_device_t          jb_cache_device;
        journal_cached_lun_t            jb_cached_lun;
        journal_cluster_config_t        jb_cluster_config;
        journal_license_t               jb_license;
        journal_san_object_t            jb_san_obj;
        journal_vol_object_t            jb_vol_obj;
        journal_lun_mask_t              jb_lun_mask;
        journal_eventhandlers_t         jb_event_handlers;
        journal_cmd_queue_block_t       jb_queue_data;
        journal_debug_t                 jb_debug_block;
        journal_lun_registrations_t     jb_lun_registrations;
        /*
         * The following field is used to pad out a journal_block_t to its
         * proper size:
         */
        uint8_t                         jb_pad[(JOURNAL_BLOCK_SIZE_BYTES -
                                                sizeof(journal_block_hdr_t))];
    } u;
} journal_block_t;

#if defined(LINUX_USER) || defined(WINDOWS_USER)

/* Flags used in the ji_flags field below */
#define JOURNAL_INFO_FLAG_FD_INITIALIZED   (1 << 0)
                            /* Set if ji_fd has been initialized since startup.
                             * Otherwise FALSE.
                             */
#define JOURNAL_INFO_FLAG_OBSOLETE_GEN     (1 << 1)
                            /* Set if this journal mirror has an obsolete
                             * generation number.
                             */
#define JOURNAL_INFO_FLAG_FD_REMOTE     (1 << 2)
                            /* Set if this journal mirror is not
                             * on the local system.
                             */

/*
 * Information about a journal mirror.
 */
typedef struct journal_info_s {
    int                 ji_flags;
    int                 ji_fd;      /* fd for this journal mirror
                                     * -1: Closed
                                     * -2: Remote pathname
                                     */
    in_addr_t           ji_ipaddr;
    uint16_t            ji_cfm_port;
    char                ji_pathname[JOURNAL_LOCATION_MAXLEN];
                                    /* Pathname for this journal mirror.
                                     * NOTE that this field differs from
                                     * jl_location in current_journal_mirror_set
                                     * for JOURNAL_LOCATION_CACHEDEV entries:
                                     * jl_location contains the wwn for the
                                     * device, while this field contains the
                                     * pathname that corresponds to that wwn.
                                     */
    size_t              ji_offset;  /* Offset of this journal mirror within
                                     * the device/file that contains it.
                                     */
    uint64_t            ji_gen;     /* Generation number of this mirror
                                     * at the time it was opened.
                                     */
    com_ep_handle_t     ji_eph;     /* eph of connection to the remote
                                     * CFM responsible for this mirror
                                     */
    /*
     * NOTE that the following is used for temporarily buffering journal
     * mirror index records in journal_open, and shouldn't be used for other
     * purposes.
     */
    journal_block_t     ji_block;   /* mirror index block... */
} journal_info_t;



/*
 * The current set of journal mirrors.
 */
extern journal_mirror_index_t *current_journal_mirror_set;

/*
 * operating as primary CFM or not.
 */
extern gboolean journal_primary_mode;
extern journal_info_t journal_info[NUM_JOURNAL_MIRRORS];

/* A callback that's invoked when a write to a journal mirror fails. */
typedef void (*journal_mirror_replace_callback)(char *wwn_str);


/*
 * Register the journal_mirror_replace_callback.
 */
extern void
journal_register_mirror_replace_callback(
                                    journal_mirror_replace_callback callback);

/*
 * Create and initialize the journal files.
 *
 * Returns:
 *     0                        On success
 *     RNA_JOURNAL_ERROR_IO     On I/O failure, details are in errno
 */
extern int
journal_initialize(rna_cluster_id_t *cluster_id,
                   journal_mirror_index_t *mirror_index,
                   int num_journals,
                   uint64_t cluster_key);

/*
 * Open the journal file(s).  Check for existence, consistency.
 * If too few journal mirrors exist, create mirrors in the default location
 * to fill out the set.
 *
 * Returns:
 *     0                                On success
 *     RNA_JOURNAL_ERROR_IO             On I/O failure, details are in errno
 *     RNA_JOURNAL_ERROR_ID_MISMATCH    On failure due to cluster ID mismatch
 *     RNA_JOURNAL_ERROR_INSUFFICIENT_MIRRORS
 *                                      On failure due to too few journal
 *                                      mirrors being accessible
 */
extern int
journal_open(rna_cluster_id_t       *cluster_id,
             gboolean                force_flag,
             journal_mirror_index_t *mirror_index,
             in_addr_t               my_addr,
             uint16_t                my_port);


/*
 * Used for local mirror access either to supply remote journal
 * data or for other than cfm access to local journal info.
 */
extern int journal_open_local_mirrors(rna_cluster_id_t *cluster_id, journal_info_t *journal_info);

extern int
journal_read_local_logical_block(int                 block_num,
                                 journal_block_t    *buf);

extern uint64_t journal_get_generation();
extern time_t journal_get_time();
extern int journal_get_hash(journal_digest_t *);

#endif


/*
 * Close the journal file.
 */
extern void
journal_close(void);


/*
 * Move the specified journal mirror from its current location to the specified
 * location.'
 *
 * Arguments:
 *     mirror_index The ordinal of the journal mirror that's being replaced
 *     wwn_str      The wwn string for the cache device that the journal mirror
 *                  should be moved to.  If NULL, the mirror will be moved to
 *                  the default location.
 * Transaction:
 *     The caller must have a write transaction in progress on entry (due to
 *     call to journal_update_mirror_index()).
 *
 * Returns:
 *     0                               On success
 *     RNA_JOURNAL_ERROR_IO            On I/O failure, details are in errno
 *     RNA_JOURNAL_ERROR_NO_TRANSACTION
 *                                      A write transaction is not in progress.
 *     RNA_JOURNAL_ERROR_INSUFFICIENT_MIRRORS
 *                                     Too few journal mirrors are accessible
 *     RNA_JOURNAL_ERROR_INVALID       An invalid device has been specified
 */
extern int journal_mirror_replace(int mirror_index, char *wwn_str);


/*
 * Return the cluster ID that the journal belongs to.
 *
 * Arguments:
 *     cluster_id  A buffer to hold the ID read from the journal
 *
 * Returns:
 *     0                               On success
 *     RNA_JOURNAL_ERROR_IO            On I/O failure, details are in errno
 */
extern int
journal_get_id(rna_cluster_id_t *cluster_id);

 /*
  * Return the authentication token that the journal belongs to.
  *
  * Arguments:
  *     cluster_key  A pointer to cluster key read from the journal
  *
  * Returns:
  *     0                               On success
  *     RNA_JOURNAL_ERROR_IO            On I/O failure, details are in errno
  */
extern int
journal_get_key(uint64_t *cluster_key);

/*
 * manage journal write priority requests
 */
typedef enum {
    JOURNAL_WRITE_NORMAL_PRIORITY,
    JOURNAL_WRITE_HIGH_PRIORITY
} journal_priority_t;

/*
 * Begin a journal write transaction.
 *  - request priority for this write request if
 *    priority is JOURNAL_WRITE_HIGH_PRIORITY.
 *  - get the journal rw write lock
 *  - increment the begin transaction generation number
 *    and write the superblock to the journal.
 *
 * Returns:
 *     0                     On success
 *     RNA_JOURNAL_ERROR_IO  On I/O failure, details are in errno
 */
extern int
journal_begin_write_transaction(journal_priority_t priority);

/*
 * sync journal write data
 *  - write the superblock to the journal.
 *  - update bitmap
 *
 * Returns:
 *     0                     On success
 *     RNA_JOURNAL_ERROR_IO  On I/O failure, details are in errno
 */
extern int
journal_sync_mirror_data(void);

/*
 * End a journal write transaction.
 *  - write the superblock to the journal.
 *  - update bitmap
 *  - release the journal rw write lock.
 *
 * Returns:
 *     0                     On success
 *     RNA_JOURNAL_ERROR_IO  On I/O failure, details are in errno
 */
extern int
journal_end_write_transaction(void);

/*
 * Abort a journal write transaction.
 *  - release the the journal rw lock and exit.
 *  - the bitmap and superblock are not
 *    updated so any modifications to the
 *    journal are nullified.
 *
 * Returns:
 *     0                     On success
 *     RNA_JOURNAL_ERROR_IO  On I/O failure, details are in errno
 */
extern int
journal_abort_write_transaction(void);

/*
 * Begin a journal read transaction.
 *  - get the journal rw read lock
 *
 * Returns:
 *     0                                On success
 */
extern int
journal_begin_read_transaction(void);

/*
 * End a journal read transaction.
 *  - release the journal rw read lock.
 *
 * Returns:
 *     0                                On success
 */
extern int
journal_end_read_transaction(void);

/*
 * Read the content of the specified block from the specified journal file
 * into the specified buffer.
 *
 * Arguments:
 *     journal_fd  The file descriptor for the journal to be read
 *     blocknum  The block to be read
 *     buf       A buffer to read the block into
 *
 * Returns:
 *     0                               On success
 *     RNA_JOURNAL_ERROR_IO            On I/O failure, details are in errno
 *     RNA_JOURNAL_ERROR_OVERRUN       The specified blocknum is greater than
 *                                     the maximum size of a journal
 */
extern int
journal_read(int blocknum, journal_block_t *buf);

/*
 * Read the content of the next in-use block from the specified journal file
 * into the specified buffer.  This function is used to iterate through a
 * journal.
 *
 * Arguments:
 *     blocknum  On entry, the blocknum that was previously read (-1 if no
 *               block was previously read)
 *               On return, the blocknum of the block that was read (i.e. the
 *               next in-use block following the blocknum specified on entry;
 *               -1 if there are no more in-use blocks)
 *     buf       A buffer to read the block into
 *
 * Returns:
 *     0                               On success
 *     RNA_JOURNAL_ERROR_IO            On I/O failure, details are in errno
 *     RNA_JOURNAL_ERROR_OVERRUN       The specified blocknum is greater than
 *                                     the maximum size of a journal
 *     RNA_JOURNAL_ERROR_INCONSISTENT  The journal is inconsistent (i.e. a
 *                                     transaction started, but never finished,
 *                                     leaving the journal in an inconsistent
 *                                     state)
 */
extern int
journal_read_next(int *blocknum, journal_block_t *buf);

/*
 * Write the content of the specified buffer into the specified block in the
 * specified journal file.
 *
 * The write needs to be done as a journal transaction.  The caller is
 * responsible to call journal_begin_transaction() before calling this
 * function.  journal_end_transaction needs to be called when all writes
 * are finished.
 *
 * Arguments:
 *     blocknum    The block to be written
 *     buf         A buffer to write the block from
 *
 * Returns:
 *     0                               On success
 *     RNA_JOURNAL_ERROR_IO            On I/O failure, details are in errno
 *     RNA_JOURNAL_ERROR_OVERRUN       The specified blocknum is greater than
 *                                     the maximum size of a journal
 *     RNA_JOURNAL_ERROR_INCONSISTENT  The journal is inconsistent (i.e. a
 *                                     transaction started, but never finished,
 *                                     leaving the journal in an inconsistent
 *                                     state)
 *     RNA_JOURNAL_ERROR_INVALID       The specified block is unallocated
 */
extern int
journal_write(int blocknum, journal_block_t *buf);

/*
 * Delete the specified block from the specified journal.
 *
 * Arguments:
 *     blocknum         - The block to be deleted
 *     need_transaction - The function acquires the write transaction
 *                        lock if TRUE.
 *                        Otherwise the caller must have acquired it.
 *
 * Returns:
 *     0                               On success
 *     RNA_JOURNAL_ERROR_IO            On I/O failure, details are in errno
 *     RNA_JOURNAL_ERROR_OVERRUN       The specified blocknum is greater than
 *                                     the maximum size of a journal
 *     RNA_JOURNAL_ERROR_INCONSISTENT  The journal is inconsistent (i.e. a
 *                                     transaction started, but never finished,
 *                                     leaving the journal in an inconsistent
 *                                     state)
 */
extern int
journal_delete_block(int blocknum, gboolean need_transaction);

/*
 * Get the block number of an available block in the specified journal.
 *
 * Arguments:
 *     blocknum    On success return, the block number of an available block
 *
 * Returns:
 *     0                        On success
 *     RNA_JOURNAL_ERROR_IO     On I/O failure, details are in errno
 *     RNA_JOURNAL_ERROR_FULL   If the journal is full
 */
extern int
journal_allocate_block(int *blocknum);

/*
 * Programs that need remote journal access
 * define this before any include files
 */
#ifdef REMOTE_JOURNAL_ACCESS
struct cfm_cmd;

extern int
journal_handle_read_request_message(com_ep_handle_t *eph,
                                    struct cfm_cmd *cmd);
extern int
journal_handle_read_response_message(struct cfm_cmd *cmd);


extern int
journal_handle_write_request_message(com_ep_handle_t *eph,
                                     struct cfm_cmd *cmd);
extern int
journal_handle_write_response_message(struct cfm_cmd *cmd);

#endif
/*
 * Used by the CFM's journal_corruption_correction_thread() only to look for
 * and attempt to correct journal corruption.
 */
extern void
periodic_corruption_check(void);


extern char *
journal_error_to_string(int err);

/*
 * Functions to manage compressed configuration data in the
 * journal.
 */
extern int
journal_compress_config(int fd, journal_block_t *jblock, char *path);

extern int
journal_decompress_config(int fd, journal_block_t *jblock);

extern int
get_config_from_journal(uint64_t flags);

extern uint64_t journal_debug;
#define JD_LOCAL_JOURNAL            1  /* create journals in local dir for testing */
#define JD_IGNORE_CLUSTER_ID        2  /* ignore cluster ID in journal for testing */
#define JD_LOCAL_MODE               4  /* Local access to a mirror. Used for initialization, debug, cfm start up */
#define JD_IGNORE_INVALID           8  /* Ignore the js_invalid flag in the superblock for testing */

/*
 * Return a string representing the
 * journal location type.
 */
INLINE char *
journal_loc_str(int loc)
{
    char *p = "Unused";

    switch(loc) {

    case JOURNAL_LOCATION_DIR:
        p = "File Path";
        break;

    case JOURNAL_LOCATION_CACHEDEV:
        p = "Cache Device";
        break;

    default:
        break;
    }

    return p;
}

/*
 * Return the current journaled cluster state.
 * JOURNAL_CLUSTER_STATE_INVALID indicates a failure to read.
 */
journal_cluster_state journal_get_cluster_state(void);

/*
 * Set cluster state in Journal
 * returns zero on success, non-zero on failure
 */
int journal_update_cluster_state(journal_cluster_state old_state,
                                 journal_cluster_state new_state);
#endif  // _JOURNAL_H_
