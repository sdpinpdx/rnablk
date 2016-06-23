/**
 * <rna_service.h> - Dell Fluid Cache block driver
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

/**
 * @file
 *
 * @section DESCRIPTION
 * This library handles all communication between a client and the
 * Configuration Managers and Metadata Servers.  Messages are delivered to
 * the correct destination server, even if multiple server failovers change
 * the server designated to handle the message multiple times before a
 * response is received.
 */
#ifndef _RNA_SERVICE_H_
#define _RNA_SERVICE_H_

#include "platform.h"

CODE_IDENT("$URL: https://svn.rnanetworks.com/full/tags/HERMES_2_1_0_RC1/common/rna_service.h $ $Id: rna_service.h 48951 2016-02-18 19:16:42Z jroy $")

#include "cachedev.h"
#include "rna_service_id.h"
#include "platform_network.h"
#include "platform_atomic.h"
#include "rna_dskattrs_common.h"

#include "platform_atomic.h"
#include "rna_dskattrs_common.h"

#if (defined(LINUX_KERNEL))
#include <linux/time.h>        // timespec
#elif (defined(WINDOWS_KERNEL))
// timespec in platform.h
#endif  /* LINUX_KERNEL || WINDOWS_KERNEL */

#include "rna_locks.h"

#if defined(LINUX_USER) || defined(WINDOWS_USER)
#include <time.h>       // timespec

#include "rna_com.h"    // for com_ep_handle_t
#endif

#define RNA_SERVICE_MESSAGE_BUFFER_PAD  (4112)

/* supported size of unit serial number string reported in page 80 inquiry
 * If there is no serial number, then use a few (how many?) spaces.
 *
 * We are storing serial numbers in memory as NULL terminated strings.
 * However the serial number string in the page 80 inquire NEED NOT be
 * NULL terminated.
 *
 * So serial number size below does NOT include a NULL termination byte.
 */
#define UNIT_SERIALNO_SIZE  (128)
#define NULL_SERIALNO   "                "

/*
 * Maximum length of path when registering a mount with cfm
 */
#define MAX_MOUNT_PATH_LEN 128

/*
 * Maximum length of mount options when registering mount with cfm
 */
#define MAX_MOUNT_OPTS_LEN 128

/*!
 * Maximum number of Configuration managers (CFMs).
 *   Configuration allowsONLY 1 or 3 CMFs.
 */
#define RNA_SERVICE_CFMS_MAX        3

/** Maximum length of the client reference private data
 *  This value is a multiple of 8, to avoid causing alignment problems with
 *  fields following it.
*/
#define RNA_SERVICE_PVT_DATA_MAX    16

/*
 * A value placed by the CFM in a ping message's ping loc_cnt field to
 * indicate that no quiesce timeout (for split-brain handling) should 
 * NOT be set.  Used for disabling ping timeouts on DAS nodes.
 */
#define PING_NO_TIMEOUT 0xFFFFFFFFULL

/* used cs is unable to register with pcfm because stats are not ready
*/
#define RETRY_PCFM_REGISTRATION   -3

/*!
 * rna_service errors
 */
typedef enum rna_service_error_e {
    RNA_SERVICE_ERROR_NONE = 0,
    RNA_SERVICE_ERROR_WORKQ_INIT_FAILURE,
                                    /*! Unable to initialize the workq */
    RNA_SERVICE_ERROR_COM_INIT_FAILURE,
                                    /*! Failed to initialize the communication
                                     *  layer
                                     */
    RNA_SERVICE_ERROR_INVALID_CTX,  /*! Either the ctx argument is NULL, or it
                                     *  was not created by
                                     *  rna_service_ctx_create().
                                     */
    RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER,
                                    /*! The message buffer specified either was
                                     *  not allocated by
                                     *  rna_service_alloc_message_buffer() or
                                     *  has not yet been returned in a response
                                     *  callback.
                                     */
    RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE,
                                    /*! Invalid rmb_message_type field in an
                                     *  rna_service_message_buffer_t
                                     */
    RNA_SERVICE_ERROR_INVALID_RESPONSE_CALLBACK,
                                    /*! The response_callback argument is
                                     *  invalid
                                     */
    RNA_SERVICE_ERROR_INVALID_PARAMS,
                                    /*! One or more of the specified parameters
                                     *  is invalid
                                     */
    RNA_SERVICE_ERROR_NO_MEMORY,    /*! Memory allocation failed */
    RNA_SERVICE_ERROR_MAX_OUTSTANDING_EXCEEDED,
                                    /*! Sending this message would cause the
                                     *  limit on the maximum number of
                                     *  outstanding messages to be exceeded.
                                     */
} rna_service_error_t;


/*
 * Opaque rna_service context.
 */
struct rna_service_ctx_s;

/*!
 * rna_service user type
 */
typedef enum rna_service_user_type_e {
    RNA_SERVICE_USER_TYPE_GENERIC_CLIENT = 0,   /*! An RNA client */
    RNA_SERVICE_USER_TYPE_FILE_CLIENT,          /*! An RNAcache (file) client */
    RNA_SERVICE_USER_TYPE_BLOCK_CLIENT,         /*! An RNA block client */

    /* === RNAcache internal components === */
    RNA_SERVICE_USER_TYPE_AGENT,
    RNA_SERVICE_USER_TYPE_CACHE_SERVER,
    RNA_SERVICE_USER_TYPE_METADATA_SERVER,
    RNA_SERVICE_USER_TYPE_CONFIGURATION_MANAGER,

    RNA_SERVICE_USER_TYPE_UNDEFINED,            /*! must be last */
} rna_service_user_type_t;


/*!
 * Flags used for the rsp_flags rna_service parameter.
 */
typedef enum rna_service_params_flags_e {
    RNA_SERVICE_NO_FLAGS =              0,
    RNA_SERVICE_FLAG_NO_WORKQ =         (1 << 0),
                                    /*! If this flag is not set (default), a
                                     *  work queue is used to handle responses
                                     *  from the metadata servers.  If this
                                     *  flag is set, a work queue is NOT used,
                                     *  requiring more care from the user in
                                     *  the implementation of the response
                                     *  callbacks.
                                     */
    RNA_SERVICE_FLAG_PING_CFM =         (1 << 1),
                                    /*! If set, the library periodically sends
                                     *  a ping message to the primary
                                     *  configuration manager.
                                     */
    RNA_SERVICE_COM_INFINITE_TIMEOUTS = (1 << 2),
                                    /*! If set, the com infinite_timeouts
                                     *  attribute is set.  This flag is ignored
                                     *  for kernel-space clients.
                                     */
    RNA_SERVICE_FLAG_TCP_NODELAY_OFF =  (1 << 3),
                                    /*! If set, enable the TCP Nagle algorithm
                                     * (i.e. don't set TCP_NODELAY)
                                     */
} rna_service_params_flags_t;


/*!
 * Cache type
 */
typedef enum cache_req_type_e {
    CACHE_REQ_TYPE_INVALID=-1,  /**< Invalid request */
    CACHE_REQ_TYPE_FULL = 0,    /*! Full file request (cache is a full file) */
    CACHE_REQ_TYPE_BLOCK,       /*! File block request */
    CACHE_REQ_TYPE_MASTER,      /*! Master block record (maintains
                                 *  metainfo and file level lock info)
                                 */
    CACHE_REQ_TYPE_REPLICA_BLOCK,/*! File replica block request */
} cache_req_type_t;

/*!
 * Cache lock type.
 * Used when requesting a cache lock.
 */
typedef enum cache_lock_e {
    CACHE_READ_SHARED = 0,
    CACHE_WRITE_EXCLUSIVE,  /*! Used for master block only, to indicate that a
                             *  SCSI initiator has a reservation on the device
                             *  represented by this master block.
                             */
    CACHE_WRITE_SHARED,     /*! Publish/Subscribe mode. Single publisher
                             *  multiple subscribers
                             */
    CACHE_WRITE_ONLY_SHARED, /*! write-only reference, no need to read in cache block */
    CACHE_REPLICA,            /*! Block is a replica, and this ref is from the block's primary CS (TBD: Use W/O ref instead?) */
    CACHE_ATOMIC_SHARED,     /*! atomic reference, serializes COMPARE AND WRITE with
                              *  other I/O operations. (= 5)
                              */
    CACHE_NO_REFERENCE,      /*! No reference held on block. */
    CACHE_NO_ACCESS_REFERENCE, /*! Used internally to signal a master block 
                                *  reference release.
                                */
} cache_lock_t;

/**
 * Lock types on normal blocks that are client writable
 */
INLINE int
cache_lock_t_is_writable(cache_lock_t lock_type)
{
    return ((CACHE_WRITE_SHARED == lock_type)
            || (CACHE_WRITE_ONLY_SHARED == lock_type)
            || (CACHE_ATOMIC_SHARED == lock_type)
            || (CACHE_REPLICA == lock_type));
}

/**
 * Lock types on normal blocks that are client readable
 */
INLINE int
cache_lock_t_is_readable(cache_lock_t lock_type)
{
    return ((CACHE_READ_SHARED == lock_type)
            || (CACHE_WRITE_SHARED == lock_type)
            || (CACHE_ATOMIC_SHARED == lock_type));
}

INLINE int
cache_ref_is_valid_transition(cache_lock_t orig_ref,
                              cache_lock_t new_ref)
{
    int ret = 0;  /* Assume invalid */

    if (unlikely(CACHE_NO_REFERENCE == new_ref)) {
        /* 
         * If we're dealing with the FS_UNKNOWN ref, don't 
         * perform checks, and all references can switch to
         * no reference (i.e., release the reference).
         */
        ret = 1;
    } else {
        switch (orig_ref) {
        case CACHE_READ_SHARED:
            ret = (CACHE_WRITE_SHARED == new_ref) ||
                (CACHE_ATOMIC_SHARED == new_ref) ||
                (CACHE_NO_ACCESS_REFERENCE == new_ref);
            break;
        case CACHE_WRITE_EXCLUSIVE:
            /* 
             * write exclusive is only used for master block locking
             * for reservations.  No read reference is used.
             */
            ret = (CACHE_WRITE_SHARED == new_ref);
            break;
        case CACHE_WRITE_SHARED:
            ret = (CACHE_WRITE_EXCLUSIVE == new_ref) /* reservations */ ||
                (CACHE_READ_SHARED == new_ref) ||
                (CACHE_ATOMIC_SHARED == new_ref) ||
                (CACHE_NO_ACCESS_REFERENCE == new_ref); /* other client has
                                                         * reservation 
                                                         */
            break;
        case CACHE_WRITE_ONLY_SHARED:
            ret = (CACHE_WRITE_SHARED == new_ref) ||
                (CACHE_ATOMIC_SHARED == new_ref);
            break;
        case CACHE_NO_REFERENCE:
            /* 
             * CACHE_NO_ACCESS_REFERENCE is a special ref that cannot
             * just be acquired.  It keeps a hold on the master block
             * lock while another client has a reservation.  We only
             * transition to/from CACHE_WRITE_SHARED .
             */
            ret = (CACHE_NO_ACCESS_REFERENCE != new_ref);
            break;
        case CACHE_NO_ACCESS_REFERENCE:
            ret = (CACHE_WRITE_SHARED == new_ref);
            break;
        default:
            /* 
             * If it's not one of the cases we're covering above,
             * don't complain about it.
             */
            ret = 1;
        }
    }
    
    return ret;
}

/*!
 * Cache Write Mode
 * Used when requesting a cache lock.
 */
typedef enum cache_write_mode_e {
    CACHE_SCRATCHPAD = 0,   /*! Cache blocks are not persisted in any other
                             *  storage
                             */
    CACHE_WRITE_THROUGH,    /*! Cache blocks are persisted in underlying
                             *  storage.  NOTE that this mode does NOT refer
                             *  to the block device's write-through mode,
                             *  which is an alternative to replicated write-
                             *  back mode.  This instead refers to the
                             *  filesystem client's 'write-invalidate' mode,
                             *  which is an alternative to the block client's
                             *  handling of writes (which might be
                             *  write-through, replicated write-back, or
                             *  read/write around).
                             */
    CACHE_WRITE_UPDATE,     /*! Cache blocks are persisted in underlying
                             *  storage, and writes are published to subscribed
                             *  clients by cache server.
                             */
    CACHE_WRITE_BACK,        /*! Cache blocks are persisted in underlying
                             *  storage by server.  NOTE that this does NOT
                             *  refer to the block device's replicated
                             *  write-back mode, which is an alternative to
                             *  its write-through mode.  This mode is an
                             *  alternative to scratchpad mode, and simply
                             *  indicates that a backing store exists for
                             *  the block device.
                             */
} cache_write_mode_t;

/*!
 * Cache Commit Mode
 * Indicates to the Cache Server if it should persist data or if the client
 * will persist the data
 */
typedef enum cache_commit_mode_e {
    DISABLE_COMMIT = 0,
    CACHE_COMMIT,
    CLIENT_COMMIT,
} cache_commit_mode_t;

/*!
 * Cache Invalidate Mode
 * Used when requesting a cache lock.
*/
typedef enum cache_invd_mode_e {
    CACHE_INVD_FILE = 0,
    CACHE_INVD_BLOCK,
} cache_invd_mode_t;

/*!
 * Cache block error persistence (and failed block replacement).
 * Controls how long the record of a failed cache block will be retained in
 * the MD.
*/
typedef enum cache_error_persistence_e {
    CACHE_ERRS_NOT_PERSISTENT = 0,       /*! Blocks are removed on failure,
                                          *  and replaced on next reference.
                                          */
    CACHE_ERRS_PERSIST_UNTIL_BLOCK_INVD, /*! MD keeps failed block info until
                                          *  the block is explicitly
                                          *  invalidated, or a master
                                          *  invalidate for the file completes.
                                          */
    CACHE_ERRS_PERSIST_UNTIL_MASTER_INVD,/*! MD keeps failed block info until
                                          *  a master invalidate for the
                                          *  containing file completes.
                                          *  Block invalidates are ignored
                                          */
} cache_error_persistence_t;


/*!
 * Cache evict policy
 * Controls if/when cache blocks are evicted
 */
typedef enum cache_evict_policy_e {
    CACHE_SERVER_EVICT_POLICY = 0,       /*! Blocks are evicted when the CS
                                          *  decides to evict them
                                          */
    CACHE_CLIENT_EVICT_POLICY,           /*! Blocks are evicted when the client
                                          *  explicitly invalidates them
                                          */
} cache_evict_policy_t;

/*!
 * Cache registration status codes
 * Used to indicate to the MD if the cache is usable.  
 * (An unusable cache would be one that doesn't have the right mounts.)
 */
enum cache_status {
    CACHE_UNAVAILABLE = 0,  /* must be zero */
    CACHE_AVAILABLE,
};

/*!
 * Client control type 
 * Used to indicate the type of control that the CFM requests of the client.
 */
typedef enum {
    CLIENT_CONTROL_START = 1,       /**< Start */
    CLIENT_CONTROL_FLUSH,           /**< Flush */
    CLIENT_CONTROL_STOP,            /**< Stop */
    CLIENT_CONTROL_DELETE,          /**< Delete */
    CLIENT_CONTROL_REACTIVATE,      /**< Reactivate */
    CLIENT_CONTROL_ADDCLIENT,       /**< Add Client (CFM only action) */
    CLIENT_CONTROL_REMCLIENT,       /**< Remove Client */
} rna_service_client_control_t;

/** Max length of interface name.
  * Example of interface names are eth0, eth1, ib0 etc.
  */
#define RNA_IF_NAME_LEN 32

/** Abstraction for interface info
  * Used to represent any RNA supported transport
  */
struct rna_if_info{
    uint32_t addr;  /**< ipv4 address */
    uint16_t port;  /**< port number */
    uint8_t type;   /**< interface type @see rna_if_type */
    uint8_t status; /**< interface status @see rna_if_status  */
    uint32_t rank; /**< interface network rank */
    char name[RNA_IF_NAME_LEN]; /**< interface name. IE. eth0, ib0 etc. */
};

/** Maximum number of interfaces
*/
#define MAX_NET_IF 32

DECLARE_PACKED_STRUCT(rna_if_table) {
    /*
     * The following array is currently a multiple of 8 bytes in size.  If
     * anything is changed, the padding should be adjusted to account for it.
     */
    struct rna_if_info ifs[MAX_NET_IF];
    uint32_t           table_entries;
    uint32_t           pad;
} END_PACKED_STRUCT(rna_if_table);

/*!
 * Request file information from a metadata server.
 */
DECLARE_PACKED_STRUCT(rna_service_metadata_query) {
    uint64_t            mqs_cookie;         /*! A value to be returned in the
                                             *  mqr_cookie field of the response
                                             */
    uint8_t             mqs_request_type;   /*! Master or Block record.  @see
                                             *  cache_req_type_t
                                             */
    uint8_t             mqs_lock_type;      /*! Read_shared, write_exclusive.
                                             * @see rna_service_cache_lock_t
                                             */
    uint8_t             mqs_write_mode;     /*! Write through or scratchpad.
                                             *  @see cache_write_mode_t
                                             */
    uint8_t             mqs_write_commit_flag;
                                            /*! Indicates whether the cache
                                             *  server should persist dirty
                                             *  data.  @see
                                             *  rna_service_cache_commit_mode_t
                                             */
    uint8_t             mqs_invd_mode;      /*! File or block.  @see
                                             *  rna_service_cache_invalidate_mode_t
                                             */
    uint8_t             mqs_evict_policy;   /*! Controls if/when cache blocks
                                             *  are evicted.  @see
                                             *  rna_service_cache_evict_policy_t
                                             */
    uint8_t             mqs_error_persistence;
                                            /*! Controls failed block
                                             *  replacement and error retention.
                                             *  @see rna_service_cache_error_persistence_t
                                             */
    uint8_t             mqs_pad1;           /*! For future use (64-bit align) */
    uint64_t            mqs_block_size;     /*! Desired cache block size for this file.
                                             *  Considered only on master block create.
                                             *  Actual cache block size is returned by MD.
                                             */   
    uint64_t            mqs_block_num;      /*! Block number */
    uint64_t            mqs_size;
    uint64_t            mqs_offset;
    uint32_t            mqs_open_flag;      /*! Flags used in open() call */
    uint32_t            mqs_open_mode;      /*! Mode used in open() call */
    uint32_t            mqs_reader_uid;     /*! uid file block will be read
                                             *  into the cache as
                                             */
    uint32_t            mqs_reader_gid;     /*! gid file block will be read
                                             *  into the cache as
                                             */
    uint32_t            mqs_pad2;           /*! For future use (64-bit align) */
    uint32_t            mqs_pvt_data_len;   /*! # of bytes in the pvt_data
                                             *  field
                                             */
    char                mqs_pvt_data[RNA_SERVICE_PVT_DATA_MAX];
                                            /*! Used in any block update
                                             *  messages to refer to data
                                             *  returned in this query
                                             */
    uint64_t            mqs_master_block_id; /*! If this request is a re-lock of
                                              * a master block, the master_block_id
                                              * of the master block.
                                              * otherwise 0.
                                              */
    uint32_t            mqs_path_md_policy; /* md policy for clientaffinity */
    char                mqs_pathname[1];    /*! Full path name of the file as a
                                             *  variable-length string
                                             *  (declared length 1 rather than
                                             *  0 to avoid upsetting the
                                             *  windows compiler, which warns
                                             *  about fields that follow
                                             *  variable-length fields).
                                             *  MUST BE LAST.
                                             */
} END_PACKED_STRUCT(rna_service_metadata_query);

INLINE void
bswap_rna_service_metadata_query_t(rna_service_metadata_query_t *data)
{
	UNREFERENCED_PARAMETER(data);
#if CPU_BE
    data->mqs_cookie = bswap_64(data->mqs_remote_cookie);
    data->mqs_block_num = bswap_64(data->mqs_block_num);
    data->mqs_size = bswap_64(data->mqs_size);
    data->mqs_offset = bswap_64(data->mqs_offset);
    data->mqs_open_flag = bswap_32(data->mqs_open_flag);
    data->mqs_open_mode = bswap_32(data->mqs_open_mode);
    data->mqs_reader_uid = bswap_32(data->mqs_reader_uid);
    data->mqs_reader_gid = bswap_32(data->mqs_reader_gid);
    data->mqs_pvt_data_len = bswap_32(data->mqs_pvt_data_len);
    data->mqs_path_md_policy = bswap_32(data->mqs_path_md_policy);
    data->mqs_master_block_id = bswap_64(data->mqs_master_block_id);
#endif
}


/*
 * This is the opaque version of an rna_hash_key_t, and is the same size as
 * that struct.
 */
typedef struct rna_service_hash_key_s {
    char rsh_key[24];
} rna_service_hash_key_t;

/*
 * Block device states.
 */
typedef enum {
    RNABLK_CACHE_OFFLINE = 0,
    RNABLK_CACHE_ONLINE,
    RNABLK_CACHE_INITIALIZING,
    RNABLK_CACHE_CONNECTING,
    RNABLK_CACHE_DISCONNECTING,
    RNABLK_CACHE_DISCONNECTED,
    RNABLK_CACHE_RESERVED,
} rnablk_cache_status;

INLINE const char *
get_rnablk_cache_status_string(rnablk_cache_status status)
{
    const char * ret = "Unknown";
        // (Note that initializing ret allows us to leave out a default case in
        // the below switch, which allows the compiler to flag a warning if not
        // all cases are covered, if new cases get added in the future).

    switch (status) {
    case RNABLK_CACHE_ONLINE:
        ret = "RNABLK_CACHE_ONLINE";
        break;
    case RNABLK_CACHE_OFFLINE:
        ret = "RNABLK_CACHE_OFFLINE";
        break;
    case RNABLK_CACHE_CONNECTING:
        ret = "RNABLK_CACHE_CONNECTING";
        break;
    case RNABLK_CACHE_DISCONNECTING:
        ret = "RNABLK_CACHE_DISCONNECTING";
        break;
    case RNABLK_CACHE_DISCONNECTED:
        ret = "RNABLK_CACHE_DISCONNECTED";
        break;
    case RNABLK_CACHE_INITIALIZING:
        ret = "RNABLK_CACHE_INITIALIZING";
        break;
    case RNABLK_CACHE_RESERVED:
        ret = "RNABLK_CACHE_RESERVED";
        break;
    }
    return ret;
}

INLINE const char *
get_rnablk_cache_status_display_string(rnablk_cache_status status)
{
    const char * ret = "UNKNOWN";
        // (Note that initializing ret allows us to leave out a default case in
        // the below switch, which allows the compiler to flag a warning if not
        // all cases are covered, if new cases get added in the future).

    switch (status) {
    case RNABLK_CACHE_ONLINE:
        ret = "online";
        break;
    case RNABLK_CACHE_OFFLINE:
        ret = "offline";
        break;
    case RNABLK_CACHE_CONNECTING:
        ret = "connecting";
        break;
    case RNABLK_CACHE_DISCONNECTING:
        ret = "disconnecting";
        break;
    case RNABLK_CACHE_DISCONNECTED:
        ret = "disconnected";
        break;
    case RNABLK_CACHE_INITIALIZING:
        ret = "initializing";
        break;
    case RNABLK_CACHE_RESERVED:
        ret = "SCSI-2 reserved";
        break;
    }
    return ret;
}

/*
 * Block device stats.
 */
#define BLKDEV_STATS_HISTORY_COUNT     9
struct blkdev_stats {
    uint64_t  writes;           ///< IB reads
    uint64_t  reads;            ///< IB writes
    uint64_t  direct_reads;     ///< local cache reads
    uint64_t  queries;
    uint64_t  retries;
    uint64_t  failed_blocks;       ///< Lost/failed/permanently inaccessible cache blocks
    uint64_t  histo[BLKDEV_STATS_HISTORY_COUNT];
    uint64_t  bytes_out;        ///< IB bytes out
    uint64_t  bytes_in;         ///< IB bytes in
    uint64_t  flushes;   // TBD: remove
    uint64_t  barriers;  // TBD: remove
    uint64_t  fua_reqs;  // TBD: remove
    uint64_t  reservations;
    uint64_t  reservation_conflicts;
    uint64_t  io_reservation_conflicts;
    uint64_t  write_same_requests;
    uint64_t  unmap_requests;
    uint64_t  comp_and_write_requests;
    uint64_t  anon_downgraded_blocks;
    uint64_t  anon_ref_dropped_blocks;
    atomic64_t enforcer_downgraded_blocks;
    atomic64_t enforcer_ref_dropped_blocks;
    atomic64_t  bs_write_query_time;  // nanoseconds write ref type of RNABLK_CACHE_QUERY
    atomic64_t  bs_read_query_time;   // nanoseconds read ref type of RNABLK_CACHE_QUERY
    atomic64_t  bs_read_time;         // nanoseconds spent processing ios type RNABLK_RDMA_READ
    atomic64_t  bs_write_time;        // nanoseconds spent processing ios type RNABLK_RDMA_READ
    atomic64_t  bs_read_hits;         // Count of reads that didn't require an MD query
    atomic64_t  bs_write_hits;        // Count of writes that didn't require an MD query
    atomic_t  in_flight;
    atomic_t  in_queue;
    atomic_t  openers;
    atomic_t  status;            // @see rnablk_cache_status
    atomic_t  unflushed_blocks;  // Count of blocks with (any) unflushed writes (TBD: remove)
    atomic_t  pending_flushes;   // Count of outstanding flush requests (TBD: remove)
    atomic_t  writing_blocks;    // Count of blocks with write references
    atomic_t  reading_blocks;    // Count of blocks with read references
};

typedef struct blkdev_stats Device_Stats, *PDevice_Stats;

/*!
 * Invalidate a cached file (sent to a metadata server).
 */
DECLARE_PACKED_STRUCT(rna_service_cache_invalidate) {
    uint64_t            cis_cache_rid;
    uint64_t            cis_md_rid;
    uint8_t             cis_cache_type;     /*! Master or Block record.  @see
                                             *  cache_req_type_t
                                             */
    uint8_t             cis_write_mode;     /*! Write through or scratchpad.
                                             *  @see
                                             *  rna_service_cache_write_mode_t
                                             */
    uint8_t             cis_invd_mode;      /*! File or block.  @see
                                             *  rna_service_cache_invalidate_mode_t
                                             */
    uint8_t             cis_evict_cause;    /*! Used by CS to categorize the
                                             * bytes *this will evict.  @see
                                             * cache_evict_cause 
                                             */
    uint32_t            cis_pvt_data_len;
                                            /*! Length in bytes of pvt_data */
    char                cis_pvt_data[RNA_SERVICE_PVT_DATA_MAX];
                                            /*! Private data */
    uint64_t            cis_block_num;      /*! Block number */
    uint64_t            cis_truncate_offset;
    /*!
     * == The following are used only if the caller is an RS_USER_CACHE_SERVER.
     */
    uint64_t            cis_mem_locked;
    uint64_t            cis_mem_locked_gen;
    uint64_t            cis_mem_used;
    uint64_t            cis_mem_used_gen;

    /* === Variable-length pathname === */
    char                cis_pathname[1];    /*! Pathname of item being
                                             *  invalidated as a
                                             *  variable-length string
                                             *  (declared length 1 rather
                                             *  than 0 to avoid upsetting
                                             *  the windows compiler, which
                                             *  warns about fields that follow
                                             *  variable-length fields).
                                             *  MUST BE LAST.
                                             */
} END_PACKED_STRUCT(rna_service_cache_invalidate);

INLINE void
bswap_rna_service_cache_invalidate_t(
                                    rna_service_cache_invalidate_t *data)
{
	UNREFERENCED_PARAMETER(data);
#if CPU_BE
    data->cis_md_rid = bswap_64(data->cis_cache_rid);
    data->cis_md_rid = bswap_64(data->cis_md_rid);

    //uint8_t     cache_type;
    //uint8_t        ack_required;
    data->cis_block_num = bswap_64(data->cis_block_num);
    data->cis_pvt_data_len = bswap_32(data->cis_pvt_data_len);
    data->cis_truncate_offset = bswap_64(data->cis_truncate_offset);
    data->cis_mem_locked = bswap_64(data->cis_mem_locked);
    data->cis_mem_locked_gen = bswap_64(data->cis_mem_locked_gen);
    data->cis_mem_used = bswap_64(data->cis_mem_used);
    data->cis_mem_used_gen = bswap_64(data->cis_mem_used_gen);
    //char             pvt_data[MAX_PVT_DATA];
    //char    pathname[PATHNAME_LEN];
#endif
}

/*
 * Storage path registration info (sent to the cfm)
 */
DECLARE_PACKED_STRUCT(rna_service_register_path) {
    struct rna_service_id   rp_service_id;
    uint8_t                 rp_status;
    rna_rkey_t              io_stat_rkey;
    rna_addr_t              io_stat_buf;
    uint32_t                io_stat_length;
    void                    *io_stat_info;
    int                     io_stat_num_mr;
    uint8_t                 rp_active_cache_mode;
    uint8_t                 rp_flush_on_shutdown;
    uint8_t                 rp_evict_on_shutdown;
    uint8_t                 rp_das;
    rna_store_wwn_t         rp_wwn;
    uint8_t                 rp_snap_write_all_flags;
    struct rna_service_id   rp_snap_write_all_cfm_service_id;
    uint64_t                rp_snap_write_all_cfm_time;
    uint64_t                rp_master_block_id;
    char                    rp_path[MAX_MOUNT_PATH_LEN];    /* Pathname on registering CS */
} END_PACKED_STRUCT(rna_service_register_path);

INLINE void
bswap_rna_service_register_path_t(rna_service_register_path_t *data)
{
	UNREFERENCED_PARAMETER(data);
#if CPU_BE
    data->rp_service_id = bswap_rna_service_id(&data->rp_service_id);
    //data->rp_status = bswap_8(&data->rp_status);
    //rna_rkey_t io_stat_rkey;
    //rna_addr_t io_stat_buf;
    data->io_stat_length = bswap_32(&data->io_stat_length);
    //void *io_stat_info;
    data->io_stat_num_mr = bswap_32(&data->io_stat_num_mr);
    // TODO?: create byte swap routine for rna_store_wwn_t rp_wwn;
#endif
}

/*!
 * Register a filesystem mount (sent to the cfm)
 */
DECLARE_PACKED_STRUCT(rna_service_register_mount) {
    uint64_t            rms_mount_id;
                            // A local ID for the mount, which will be used
                            // to de-register the mount.
    char                rms_uppermnt_path[MAX_MOUNT_PATH_LEN];
    char                rms_lowermnt_path[MAX_MOUNT_PATH_LEN];
    char                rms_opts[MAX_MOUNT_OPTS_LEN];
} END_PACKED_STRUCT(rna_service_register_mount);


INLINE void
bswap_rna_service_register_mount_t(rna_service_register_mount_t *data)
{
	UNREFERENCED_PARAMETER(data);
#if CPU_BE
    data->rms_mount_id = bswap_64(data->rms_mount_id);
    //char uppermnt_path[MAX_MOUNT_PATH_LEN];
    //char lowermnt_path[MAX_MOUNT_PATH_LEN];
    //char opts[MAX_MOUNT_OPTS_LEN];
#endif
}


/*!
 * Deregister a filesystem mount (sent to the configuration manager).
 */
DECLARE_PACKED_STRUCT(rna_service_deregister_mount) {
    uint64_t            dms_mount_id;
                            // The local ID given to the mount when it was
                            // registered.
} END_PACKED_STRUCT(rna_service_deregister_mount);


/*!
 * Send an event from client.
 */
DECLARE_PACKED_STRUCT(rna_service_notification_event) {
                uint32_t                event;
                uint64_t                cookie;
                char                    persist_location[PATH_MAX+1];
} END_PACKED_STRUCT(rna_service_notification_event);

INLINE void
bswap_rna_service_notification_event_t(rna_service_notification_event_t *data)
{
	UNREFERENCED_PARAMETER(data);
#if CPU_BE
    data->event = bswap_32(data->event);
    data->cookie = bswap_64(data->cookie);
#endif
}

/*!
 * Report number of MD hash partitions and the CS's RNA service ID to CS
 */
DECLARE_PACKED_STRUCT(rna_service_num_md_hash_partitions) {
        rna_service_id_t        np_service_id;  /* The CS's rna service ID */
        uint16_t                np_num_partitions;
} END_PACKED_STRUCT(rna_service_num_md_hash_partitions);

INLINE void
bswap_rna_service_num_md_hash_partitions_t(rna_service_num_md_hash_partitions_t *data)
{
    UNREFERENCED_PARAMETER(data);
#if CPU_BE
    data->event = bswap_16(data->num_partitions);
#endif
}

INLINE void
bswap_rna_service_deregister_mount_t(
                                    rna_service_deregister_mount_t *data)
{
	UNREFERENCED_PARAMETER(data);
#if CPU_BE
    data->dms_mount_id = bswap_64(data->dms_mount_id);
#endif
}

/*!
 * Register a block device (sent to the configuration manager).
 */
DECLARE_PACKED_STRUCT(rna_service_register_block_device) {
    uint64_t            rbs_device;    /*! Used to match this registration in
                                         *  responses (as rbr_device) and 
                                         *  deregistration
                                         */
    uint64_t            cookie;         /* cookie for soap context */
    uint64_t            rbs_capacity;   /*! Bytes */
    uint64_t            rbs_master_block_id;
    uint32_t            rbs_cache_block_size;   /*! Actual cache block size in bytes */
    uint8_t             rbs_shared;     /*! TRUE if there will be multiple
                                         *  clients attached to this disk
                                         */
    uint8_t             rbs_existing;   /*! TRUE if the device has already been
                                         *  created (say, when reconnecting to
                                         *  a CFM)
                                         */
    uint32_t            rbs_persist_access_uid; /*! uid used to access
                                                 *  persistent storage.
                                                 */
    uint32_t            rbs_persist_access_gid; /*! gid used to access
                                                 *  persistent storage
                                                 */
    char                rbs_persist_location[MAX_MOUNT_PATH_LEN]; /*! Pathname
                                                 * to persistent storage for
                                                 * device. XXX make variable
                                                 */
    char                rbs_name[1];    /*! Full path name as a variable-length
                                         *  string (declared length 1 rather
                                         *  than 0 to avoid upsetting the
                                         *  windows compiler, which warns about
                                         *  fields that follow variable-length
                                         *  fields).  MUST BE LAST.
                                         */
} END_PACKED_STRUCT(rna_service_register_block_device);


INLINE void bswap_rna_service_register_block_device_t(
                                rna_service_register_block_device_t *data)
{
	UNREFERENCED_PARAMETER(data);
#if CPU_BE
    data->rbs_device = bswap_64(data->rbs_device);
    data->cookie = bswap_64(data->cookie);
    data->rbs_master_block_id = bswap_64(data->rbs_master_block_id);
    //char        name[PATHNAME_LEN];
    data->rbs_capacity = bswap_32(data->rbs_capacity);
    data->rbs_cache_block_size = bswap_32(data->rbs_cache_block_size);
    //uint_8      shared;
    //uint_8      existing;
    data->rbs_persist_access_uid = bswap_32(data->rbs_persist_access_uid);
    data->rbs_persist_access_gid = bswap_32(data->rbs_persist_access_gid);
    //char       rbs_persist_location[PATHNAME_LEN];
    //char       rbs_name[0];
#endif
}


/*!
 * De-register a block device (sent to the configuration manager).
 */
DECLARE_PACKED_STRUCT(rna_service_deregister_block_device) {
    uint64_t            dbs_device;     /*! Used to match this registration in
                                         *  responses and deregistration
                                         */
    uint8_t             dbs_freed;      /*! TRUE if the cache file was freed */
    char                dbs_name[1];    /*! Full path name as a variable-length
                                         *  string (declared length 1 rather
                                         *  than 0 to avoid upsetting the
                                         *  windows compiler).  MUST BE LAST.
                                         */
} END_PACKED_STRUCT(rna_service_deregister_block_device);


INLINE void bswap_rna_service_deregister_block_device_t(
                            rna_service_deregister_block_device_t *data)
{
	UNREFERENCED_PARAMETER(data);
#if CPU_BE
    data->dbs_device = bswap_64(data->dbs_device);
    //uint_8      freed;
    //char       dbs_name[0];
#endif
}


/*!
 * Register a service connection (sent to the configuration manager).
 */
DECLARE_PACKED_STRUCT(rna_service_register_svc_conn) {
    struct rna_service_id rsc_service_id;     /**< ID of service connected to by reporter */
    struct sockaddr_in    rsc_src_in;         /**< Connection reporter's address */
    struct sockaddr_in    rsc_dst_in;         /**< Connection reporter's address */
    uint64_t              rsc_conn_id;        /**< Opaque local identifier optionally used in 
                                                 deregister request if service_id is not available */
    uint16_t              rsc_ordinal;
    uint8_t               rsc_transport_type; /**< Transport type as seen by connection reporter.  See #com_type enum */
} END_PACKED_STRUCT(rna_service_register_svc_conn);


INLINE void bswap_rna_service_register_svc_conn_t(
                                rna_service_register_svc_conn_t *data)
{
	UNREFERENCED_PARAMETER(data);
#if CPU_BE
    bswap_rna_service_id(&data->rsc_service_id);
    bswap_sockaddr_in(&data->rsc_src_in);
    bswap_sockaddr_in(&data->rsc_dst_in);
    data->dbs_device = bswap_64(data->rsc_conn_id);  /** Really only used by local rna_service */
#endif
}


/*!
 * De-register a service connection (sent to the configuration manager).
 */
DECLARE_PACKED_STRUCT(rna_service_deregister_svc_conn) {
    struct rna_service_id dsc_service_id;     /**< ID of service connected to by reporter */
    uint64_t              dsc_conn_id;        /**< Opaque local identifier optionally used in 
                                                 deregister request if service_id is not available */
    uint8_t               dsc_dereg_by_conn_id; /**< Match service conn registration by local opaque
                                                   ID on deregistration.  Service_id from registration 
                                                   message will be inserted above */
} END_PACKED_STRUCT(rna_service_deregister_svc_conn);


INLINE void bswap_rna_service_deregister_svc_conn_t(
                            rna_service_deregister_svc_conn_t *data)
{
	UNREFERENCED_PARAMETER(data);
#if CPU_BE
    bswap_rna_service_id(&data->dsc_service_id);
    data->dbs_device = bswap_64(data->dsc_conn_id);  /** Really only used by local rna_service */
#endif
}


/*!
 * Used as part of an rna_service_register_cache_device_t to register a
 * replica store that's hosted by a cache device.
 */
DECLARE_PACKED_STRUCT(rna_service_register_replica_store) {
    cachedev_id_t   cdr_served_cachedev_id; /* The ID of the cache device whose
                                             * blocks are replicated in this
                                             * replica store.
                                             */
    cachedev_id_t   cdr_repstore_id;        /* The ID of this replica store */
} END_PACKED_STRUCT(rna_service_register_replica_store);

INLINE void
bswap_rna_service_register_replica_store_t(
                                    rna_service_register_replica_store_t *data)
{
	UNREFERENCED_PARAMETER(data);
#if CPU_BE
    data->rrs_served_cachedev_id = bswap_64(data->rrs_served_cachedev_id);
    data->rrs_repstore_id = bswap_64(data->rrs_repstore_id);
#endif
}

DECLARE_PACKED_STRUCT(rna_replica_store_info) {
    cachedev_id_t rbrsi_replica_dev_id;
    cachedev_id_t rbrsi_served_dev_id;
}END_PACKED_STRUCT(rna_replica_store_info);

INLINE void
bswap_rna_replica_store_info_t(rna_replica_store_info_t *data)
{
	UNREFERENCED_PARAMETER(data);
#if CPU_BE
    data->rbrsi_replica_dev_id = bswap_64(data->rbrsi_replica_dev_id);
    data->rbrsi_served_dev_id = bswap_64(data->rbrsi_served_dev_id);
#endif
}

/*!
 * Register a cache device (sent to MDs and configuration managers).
 */
DECLARE_PACKED_STRUCT(rna_service_register_cache_device) {
    /* cli support */
    uint64_t            cdr_cookie;     /*! cli session cookie */
    uint32_t            cdr_result;     /*! zero result indicates cs success */
    uint8_t             cdr_final;      /*! non-zero indicates final response */
    /* registration information */
    uint8_t             cdr_pad;        /*! for future use */
    uint16_t            cdr_num_hosted_replica_stores;
                                        /*! Number of replica stores hosted by
                                         * this cache device
                                         */
    rna_replica_store_info_t
                        cdr_hosted_replica_stores[MAX_REPLICA_STORES_HOSTED];
                                        /*! Information about the replica
                                         *  stores hosted by (i.e. contained
                                         *  in) this cache device.
                                         */
    cachedev_label_t    cdr_cachedev_label;
                                        /*! The cache device's label */
    rna_rkey_t          cdr_io_stat_rkey;
    rna_addr_t          cdr_io_stat_buf;
    uint32_t            cdr_io_stat_length;
    void               *cdr_io_stat_info; 
    int                 cdr_io_stat_num_mr;
    char                cdr_error_str[1];
                                        /*! Error string as a variable-length
                                         *  string.  (Declared length 1 rather
                                         *  than 0 to avoid upsetting the
                                         *  windows compiler).
                                         *  MUST BE LAST.
                                         */
} END_PACKED_STRUCT(rna_service_register_cache_device);

INLINE void
bswap_rna_service_register_cache_device_t(
                                    rna_service_register_cache_device_t *data)
{
	UNREFERENCED_PARAMETER(data);
#if CPU_BE
    data->cdr_cookie = bswap_64(data->cdr_cookie);
    data->cdr_result = bswap_32(data->cdr_result);
    data->cdr_final = bswap_8(data->cdr_final);
    data->cdr_num_hosted_replica_stores =
                                bswap_16(data->cdr_num_hosted_replica_stores);
    for (i = 0; i < MAX_REPLICA_STORES_HOSTED; i++) {
        bswap_rna_replica_store_info_t(&data->cdr_hosted_replica_stores[i]);
    }
    bswap_cachedev_label_t(&data->cdr_cachedev_label);
    //rna_rkey_t cdr_io_stat_rkey;
    //rna_addr_t cdr_io_stat_buf;
    data->io_stat_length = bswap_32(&data->cdr_io_stat_length);
    //void *io_stat_info;
    data->io_stat_num_mr = bswap_32(&data->cdr_io_stat_num_mr);
#endif
}


/*!
 * End of a set of cache device registrations (sent to the configuration
 * manager).
 */
DECLARE_PACKED_STRUCT(rna_service_register_cache_device_end) {
    uint8_t crde_pad;   /* for future use */
} END_PACKED_STRUCT(rna_service_register_cache_device_end);

INLINE void
bswap_rna_service_register_cache_device_end_t(
                                rna_service_register_cache_device_end_t *data)
{
	UNREFERENCED_PARAMETER(data);
#if CPU_BE
#endif
}

/*!
 * Deregister a cache device (sent to the configuration manager).
 */
DECLARE_PACKED_STRUCT(rna_service_deregister_cache_device) {
    uint64_t            cdd_cookie;            /*! cli session cookie */
    uint32_t            cdd_result;            /*! zero result indicates cs success */
    uint8_t             cdd_final;             /*! non-zero indicates final response */
    cachedev_label_t    cdd_cachedev_label;    /* The cache device label */
                                               /* NOTE: cl_state should be:
                                                * CACHEDEV_STATE_FAILING if the
                                                * cache device has failed a read
                                                * or write operation, or
                                                * CACHEDEV_STATE_REMOVED if the
                                                * cache device has been removed
                                                * from the node or has been
                                                * removed from the RNA cache.
                                                */
} END_PACKED_STRUCT(rna_service_deregister_cache_device);

INLINE void
bswap_rna_service_deregister_cache_device_t(
                                    rna_service_deregister_cache_device_t *data)
{
	UNREFERENCED_PARAMETER(data);
#if CPU_BE
    data->cdd_cookie = bswap_64(data->cdd_cookie);
    data->cdd_result = bswap_32(data->cdd_result);
    data->cdd_final = bswap_8(data->cdd_final);
    bswap_cachedev_label_t(&data->cdd_cachedev_label);
#endif
}

/*!
 * Expel a cache device (sent by the configuration manager).
 */
DECLARE_PACKED_STRUCT(rna_service_expel_cache_device) {
    cachedev_id_t          ced_cachedev_id;  /* The RNA-assigned ID of the
                                              * expelled cache device
                                              */
    cachedev_physical_id_t ced_physical_id;  /* The globally unique physical ID
                                              * of the cache device
                                              */
    struct rna_service_id  ced_cs_id;        /* The ID of the CS that manages
                                              * the expelled cache device
                                              */
    uint32_t               ced_reactivating_flag;
                                             /* TRUE if this is a 'fake' expel
                                              * message, sent when a failed
                                              * cache device is reactivated
                                              * (in which case, the cache
                                              * device ID continues to exist
                                              * and be valid).
                                              * FALSE if this is an actual
                                              * expel message, sent when the
                                              * cache device identified by the
                                              * ID ceases to exist, after being
                                              * recovered or removed.
                                              */
    uint32_t               ced_delete_flag; /* TRUE is the CS should delete the
                                             * cache device if it owns it.
                                             * Otherwise FALSE.  This flags is
                                             * TRUE only if a query will be
                                             * sent for the cache device before
                                             * it is re-used.
                                             */
} END_PACKED_STRUCT(rna_service_expel_cache_device);


INLINE void
bswap_rna_service_expel_cache_device_t(
                                    rna_service_expel_cache_device_t *data)
{
	UNREFERENCED_PARAMETER(data);
#if CPU_BE
    data->ced_cachedev_id = bswap_64(data->ced_cachedev_id);
    bswap_rna_service_id(&data->ced_cs_id);
	data->ced_reactivating_flag = bswap_32(data->ced_reactivating_flag);
#endif
}

/*!
 * Check for expelled cache devices (sent by the configuration manager).
 *  [RNA_SERVICE_MESSAGE_TYPE_UNEXPELLED_CACHEDEVS]
 */
DECLARE_PACKED_STRUCT(rna_service_unexpelled_cachedevs) {
    cachedev_id_t    cuc_unexpelled_cachedevs_max;
                                            /* The next available cache device
                                             * ID.  Any cache device ID that's
                                             * smaller than this and not
                                             * contained in the above array is
                                             * known to be expelled.
                                             */
    cachedev_id_t    cuc_unexpelled_cachedevs[MAX_CACHE_DEVICES_PER_CLUSTER];
                                            /* The current set of unexpelled
                                             * cache devices
                                             */
} END_PACKED_STRUCT(rna_service_unexpelled_cachedevs);


INLINE void
bswap_rna_service_unexpelled_cachedevs_t(
                                    rna_service_unexpelled_cachedevs_t *data)
{
	UNREFERENCED_PARAMETER(data);
#if CPU_BE
    bswap_cfm_unexpelled_cachedevs(&data->rs_uc);
#endif
}

/*!
 * Deregister a replica store (sent to the configuration manager).
 */
DECLARE_PACKED_STRUCT(rna_service_deregister_replica_store) {
    cachedev_id_t   drs_host_cachedev_id;   /* The ID of the cache device this
                                             * replica store is contained in
                                             */
    cachedev_id_t   drs_served_cachedev_id; /* The ID of the cache device whose
                                             * blocks are replicated in this
                                             * replica store.
                                             */
    cachedev_id_t   drs_repstore_id;        /* The ID of this replica store */
} END_PACKED_STRUCT(rna_service_deregister_replica_store);

INLINE void
bswap_rna_service_deregister_replica_store_t(
                                rna_service_deregister_replica_store_t *data)
{
	UNREFERENCED_PARAMETER(data);
#if CPU_BE
    data->drs_host_cachedev_id = bswap_64(data->drs_host_cachedev_id);
    data->drs_served_cachedev_id = bswap_64(data->drs_served_cachedev_id);
    data->drs_repstore_id = bswap_64(data->drs_repstore_id);
#endif
}


/*!
 * Create a block device (sent to the block client by the configuration
 * manager).
 */
DECLARE_PACKED_STRUCT(rna_service_create_block_device) {
    uint64_t            cbs_capacity;  /*! Bytes */
    uint64_t            cookie;  /*! soap cookie */
    uint64_t            cbs_target_referenced_blocks;  /*! total blocks target */
    uint64_t            cbs_target_read_referenced_blocks;  /*! read target */
    uint64_t            cbs_target_write_referenced_blocks; /*! write target */
    uint64_t            cbs_max_referenced_blocks;  /*! total limit limit */
    uint64_t            cbs_max_read_referenced_blocks;  /*! read limit */
    uint64_t            cbs_max_write_referenced_blocks; /*! write limit */
    uint64_t            cbs_master_block_id;    /* generated by CFM */
    uint32_t            cbs_cache_block_size;   /*! desired cache
                                                 *  block size in
                                                 *  bytes 
                                                 */
    uint32_t            cbs_flush_delta_size;   /*! flush change
                                                 *  detection
                                                 *  granularity in
                                                 *  bytes
                                                 */
    uint32_t            cbs_persist_access_uid; /*! uid used to access
                                                 *  persistent storage.
                                                 */
    uint32_t            cbs_persist_access_gid; /*! gid used to access
                                                 *  persistent storage
                                                 */
    uint32_t            cbs_path_md_policy;     /* holder for md policy on
                                                 *  clientaffinity
                                                 */
    uint8_t             cbs_shared;              /*! TRUE if there will be
                                                  *  multiple clients attached
                                                  *  to this disk
                                                  */
    uint8_t             cbs_ordered_writes;      /*! TRUE if the device should 
                                                  *  advertise ordered write
                                                  *  capability to the block 
                                                  *  layer.
                                                  */
    uint8_t             cbs_write_through;       /*! TRUE if the device is
                                                  *  initially in strict 
                                                  *  write-through mode.
                                                  */
    uint8_t             cbs_das;                  /*! TRUE if the device is
                                                  *  in single node mode.
                                                  */
    uint8_t             cbs_thin_status;          /*! NORMAL
                                                   *  LOWSPACE
                                                   *  OUTOFSPACE
                                                   */
    char                cbs_persist_location[MAX_MOUNT_PATH_LEN];  /*! Pathname
                                                 * to persistent storage for
                                                 * device. XXX make variable
                                                 */
    char                cbs_class_name[MAX_MOUNT_PATH_LEN];  /*! Names
                                                 * a group of
                                                 * start/stop actions.
                                                 */
    char                cbs_class_params[MAX_MOUNT_OPTS_LEN];  /*!
                                                 * Params for
                                                 * start/stop actions
                                                 * identified in
                                                 * class_name.
                                                 */
    char                cbs_name[1];            /*! Device name as a
                                                 *  variable-length string
                                                 *  (declared length 1 rather
                                                 *  than 0 to avoid upsetting
                                                 *  the windows compiler).
                                                 *  MUST BE LAST.
                                                 */
} END_PACKED_STRUCT(rna_service_create_block_device);


/*!
 * Control a block device (sent to the block client by the configuration manager).
 */
DECLARE_PACKED_STRUCT(rna_service_control_block_device) {
    uint64_t            cbs_cookie;             /*! cli session cookie */
    uint32_t            cbs_type;               /*! control type */
    char                cbs_name[1];            /*! Device name as a
                                                 *  variable-length string
                                                 *  (declared length 1 rather
                                                 *  than 0 to avoid upsetting
                                                 *  the windows compiler).
                                                 *  MUST BE LAST.
                                                 */
} END_PACKED_STRUCT(rna_service_control_block_device);

/*!
 * block control delete response (sent to the configuration manager by the block client).
 */
DECLARE_PACKED_STRUCT(rna_service_control_block_device_response) {
    uint64_t            cbr_cookie;             /*! cli session cookie */
    uint32_t            cbr_type;               /*! control type */
    uint32_t            cbr_result;             /*! zero result indicates block client success */
    uint8_t             cbr_final;              /*! non-zero indicates final response */
    char                cbr_name[1];            /*! Device name as a
                                                 *  variable-length string.
                                                 *  (declared length 1 rather
                                                 *  than 0 to avoid upsetting
                                                 *  the windows compiler).
                                                 *  MUST BE LAST.
                                                 */
} END_PACKED_STRUCT(rna_service_control_block_device_response);

/*!
 * Control a cache server (sent to the cache server by the configuration manager).
 */
DECLARE_PACKED_STRUCT(rna_service_control_cs) {
    uint64_t            ccs_cookie;             /*! cli session cookie */
    uint32_t            ccs_type;               /*! control type */
    uint32_t            ccs_pad;                /*! for future use (and 64-bit
                                                 *! alignment)
                                                 */
    union {
        uint32_t        ccs_cache_enable;
        uint32_t        ccs_cachedev_mode;      /*! CS_CONTROL_TYPE_ADD_PATH */
        uint32_t        ccs_discard_dirty;      /*! CS_CONTROL_TYPE_REMOVE_PATH */
        uint32_t        ccs_evict_after_flush;  /*! CS_CONTROL_TYPE_FLUSH_PATH */
        uint64_t        ccs_max_cache_mem;
        uint64_t        ccs_cache_evict_level;
        uint64_t        ccs_default_block_size;
        uint64_t        ccs_io_latency_threshold;
    } u;
    rna_store_wwn_t     ccs_wwn;                /*! used for ccs_type
                                                 *! CS_CONTROL_TYPE_ADD_PATH
                                                 *! CS_CONTROL_TYPE_REMOVE_PATH
                                                 *! CS_CONTROL_TYPE_FLUSH_PATH
                                                 *! CS_CONTROL_TYPE_ENABLE_PATH
                                                 *! CS_CONTROL_TYPE_MODITY_CACHE
                                                 */
    rna_store_wwn_t     ccs_orig_wwn;           /*! Used only ccs_type
                                                 *! CS_CONTROL_TYPE_ADD_PATH
                                                 */
    char                ccs_alias_serialno[UNIT_SERIALNO_SIZE];
    char                ccs_orig_serialno[UNIT_SERIALNO_SIZE];
    uint8_t             ccs_alias_serialno_len;
    uint8_t             ccs_orig_serialno_len;
    uint8_t             ccs_san_type;           /*! san vendor */
    uint8_t             ccs_write_mode;         /* path_mode_t, used for 
                                                 *  CS_CONTROL_TYPE_MODIFY_CACHE_MODE
                                                 *  only
                                                 */
    uint32_t            ccs_das;                /*! used for ccs_type
                                                 *! CS_CONTROL_TYPE_ADD_PATH
                                                 *! only
                                                 */
    uint32_t            ccs_flush_on_shutdown;  /* used for ccs_type
                                                 *! CS_CONTROL_TYPE_ADD_PATH
                                                 *! only
                                                 */
    uint32_t            ccs_evict_on_shutdown;  /* used for ccs_type
                                                 *! CS_CONTROL_TYPE_ADD_PATH
                                                 *! only
                                                 */
    uint32_t            ccs_block_size;         /* used for
                                                 * CS_CONTROL_TYPE_ADD_PATH
                                                 * only
                                                 */
    uint32_t            ccs_path_md_policy;     /* used for
                                                 * CS_CONTROL_TYPE_ADD_PATH
                                                 * only
                                                 */
    uint32_t            ccs_remove_single_cs_path;/* used for
                                                  * CS_CONTROL_TYPE_REMOVE_PATH
                                                  * only
                                                  */
    uint64_t            ccs_master_block_id;    /* master_block_id for LUN */
} END_PACKED_STRUCT(rna_service_control_cs);

INLINE void
bswap_rna_service_control_cs_t(rna_service_control_cs_t *data)
{
	UNREFERENCED_PARAMETER(data);
#if CPU_BE
    data->ccs_cookie = bswap_64(data->ccs_cookie);
	data->ccs_type = bswap_32(data->ccs_type);
    data->u = bswap_64(data->u);
#endif
}

/*!
 * control cs response (sent to the configuration manager by the cache server).
 */
DECLARE_PACKED_STRUCT(rna_service_control_cs_response) {
    uint64_t            ccr_cookie;             /*! cli session cookie */
    uint32_t            ccr_type;               /*! control type */
    uint32_t            ccr_result;             /*! zero result indicates cs success */
    uint8_t             ccr_final;              /*! non-zero indicates final response */
} END_PACKED_STRUCT(rna_service_control_cs_response);

/*!
 * Set the log level.
 */
DECLARE_PACKED_STRUCT(rna_service_set_log_level) {
    uint32_t  sll_log_level;
} END_PACKED_STRUCT(rna_service_set_log_level);


DECLARE_PACKED_STRUCT(rna_service_expel_cs) {
    struct rna_service_id  ecs_service_id;      /*! The unique ID of the cache
                                                 *  server that's being
                                                 *  expelled from the cluster
                                                 */
    uint64_t               ecs_cs_membership_generation;
                                                /*! The new cache server
                                                 *  membership generation
                                                 *  number
                                                 */
} END_PACKED_STRUCT(rna_service_expel_cs);

/*!
 * suggest cache block relocate (sent to the metadata server by the cache server).
 */
DECLARE_PACKED_STRUCT(rna_service_relocate_cache_block) {
    uint64_t            rcb_md_rid;
	struct sockaddr_in  rcb_dst_in;         /**< relocate to this address */
    uint8_t             rcb_hash_partition; /**< MD partition of cache entry */
} END_PACKED_STRUCT(rna_service_relocate_cache_block);

INLINE void
bswap_rna_service_relocate_cache_block_t(
                                    rna_service_relocate_cache_block_t *data)
{
	UNREFERENCED_PARAMETER(data);
#if CPU_BE
	data->rcb_md_rid = bswap_64(data->rcb_md_rid);
	bswap_sockaddr_in(&data->rcb_dst_in);
	//data->rcb_hash_partition = bswap_8(data->rcb_hash_partition);
#endif
}

/*
 * RNA_SERVICE_MESSAGE_TYPE_ABSORB_BLOCK message sent by a cache server to a
 * metadata server to announce that the cache server is absorbing the specified
 * block, which it previously stored in the specified replica store.
 */
DECLARE_PACKED_STRUCT(rna_service_cache_absorb_block) {
    uint64_t            cab_md_rid;         /**< md rid of absorbed block */
    uint64_t            cab_cs_rid;         /**< cs rid of absorbed block */
    cachedev_id_t       cab_repstore_id;    /**< ID of the replica store the
                                             *   block is being absorbed from
                                             */
    cachedev_id_t       cab_cachedev_id;    /**< ID of the cache device the
                                             *   block is being absorbed into
                                             */
    rna_service_hash_key_t cab_hash_key;    /* hash key used to determine
                                              * MD partition, among other things */
    rna_service_metadata_query_t cab_query_cmd;  /**< (variable-size struct) */
} END_PACKED_STRUCT(rna_service_cache_absorb_block);

INLINE void
bswap_rna_service_cache_absorb_block(rna_service_cache_absorb_block_t *data)
{
	UNREFERENCED_PARAMETER(data);
#if CPU_BE
    data->cab_md_rid = bswap_64(data->cab_md_rid);
    data->cab_cs_rid = bswap_64(data->cab_cs_rid);
    data->cab_repstore_id = bswap_64(data->cab_repstore_id);
    data->cab_cachedev_id = bswap_64(data->cab_cachedev_id);
    bswap_rna_service_metadata_query_response_t(data->cab_query_cmd);
#endif
}


/*
 * RNA_SERVICE_MESSAGE_TYPE_ABSORB_BLOCK_RESPONSE message sent by a metadata
 * server to a cache server in response to a
 * RNA_SERVICE_MESSAGE_TYPE_ABSORB_BLOCK message.
 */
DECLARE_PACKED_STRUCT(rna_service_cache_absorb_block_response) {
    uint64_t      cabr_cs_rid;         /**< cs rid of absorbed block */
    cachedev_id_t cabr_repstore_id;    /**< ID of the replica store the
                                         *   block is being absorbed from
                                         */
    int           cabr_ret;   /**< Return code.  0 indicates success;
                                *   non-zero indicates failure
                                */
} END_PACKED_STRUCT(rna_service_cache_absorb_block_response);

INLINE void
bswap_rna_service_cache_absorb_block_response(
                            rna_service_cache_absorb_block_response_t *data)
{
	UNREFERENCED_PARAMETER(data);
#if CPU_BE
    data->cabr_ret = bswap_32(data->crbr_ret);
    data->cabr_cs_rid = bswap_64(data->cabr_cs_rid);
    data->cabr_repstore_id = bswap_64(data->cabr_repstore_id);
#endif
}


/*!
 * cache server response to invalidate and hold (sent to the metadata server by the cache server).
 */
DECLARE_PACKED_STRUCT(rna_service_invd_hold_response) {
    uint64_t            ihr_md_rid;
    uint32_t            ihr_cs_policy; /**< MD cache selection policy */
    uint8_t             ihr_hash_partition; /**< MD partition of cache entry */
    uint8_t             ihr_cancel; /**< CS indicates to MD relocate is done */
} END_PACKED_STRUCT(rna_service_invd_hold_response);

INLINE void
bswap_rna_service_invd_hold_response_t(rna_service_invd_hold_response_t *data)
{
	UNREFERENCED_PARAMETER(data);
#if CPU_BE
	data->ihr_md_rid = bswap_64(data->ihr_md_rid);
	data->ihr_cs_policy = bswap_32(data->ihr_cs_policy);
	//data->ihr_hash_partition = bswap_8(data->ihr_hash_partition);
	//data->ihr_cancel = bswap_8(data->ihr_cancel);
#endif
}

/*!
 * cfm sends cache server connection data to client for DAS operation
 */
DECLARE_PACKED_STRUCT(rna_service_cache_client_reg) {
    struct rna_service_id   ccr_service_id;
    struct rna_if_table     ccr_if_table;
} END_PACKED_STRUCT(rna_service_cache_client_reg);

INLINE void
bswap_rna_service_cache_client_reg_t(rna_service_cache_client_reg_t *data)
{
	UNREFERENCED_PARAMETER(data);
#if CPU_BE
    bswap_rna_service_id(&data->ccr_service_id);
    bswap_rna_if_table(&data->ccr_if_table);
#endif
}

DECLARE_PACKED_STRUCT(rna_service_cfm_client_resp) {
    uint32_t per_device_connections;
    uint32_t default_block_size;
} END_PACKED_STRUCT(rna_service_cfm_client_resp);

INLINE void
bswap_rna_service_cfm_client_resp_t(rna_service_cfm_client_resp_t *data)
{
	UNREFERENCED_PARAMETER(data);
#if CPU_BE
    bswap_32(&data->per_device_connections);
    bswap_32(&data->default_block_size);
#endif
}

#define RNA_SERVICE_EVENT_PRINT_BUF_SIZE    512

/*!
 * A client event.
 */
DECLARE_PACKED_STRUCT(rna_service_client_event) {
    char      ces_print_buffer[RNA_SERVICE_EVENT_PRINT_BUF_SIZE];
} END_PACKED_STRUCT(rna_service_client_event);


/*!
 * Registration for client events.
 */
DECLARE_PACKED_STRUCT(rna_service_client_event_reg) {
    uint32_t  cer_event_mask;     /*! Event types to register for */
} END_PACKED_STRUCT(rna_service_client_event_reg);


/*!
 * De-registration for all client events.
 */
DECLARE_PACKED_STRUCT(rna_service_client_event_dereg) {
    uint32_t  ced_unused;         /*! For future use */
} END_PACKED_STRUCT(rna_service_client_event_dereg);


/*!
 * Request for block device stats.
 */
DECLARE_PACKED_STRUCT(rna_service_bstat_req) {
    uint32_t  br_unused;         /*! For future use */
} END_PACKED_STRUCT(rna_service_bstat_req);


/*!
 * Response to a request for block device stats.
 */
DECLARE_PACKED_STRUCT(rna_service_bstat_response) {
    uint64_t             bsr_device_id;
    struct blkdev_stats  bsr_stats;
} END_PACKED_STRUCT(rna_service_bstat_response);

/*
 * Meta data stored by both metadata servers and cache servers.
 *
 * This struct is used in the MDs' meta_data_struct, the CSs'
 * cache_entry_struct, and the md_sync_data and cache_req messages.
 */
typedef struct common_meta_data_s {
    uint8_t        co_cache_req_type;
    uint8_t        co_evict_policy;/**< Controls if/when cache blocks are
                                   *   evicted. @see cache_evict_policy
                                   */
    uint8_t        co_error_persistence;
                                  /**< Controls failed block replacement and
                                   *   error retention. @see
                                   *   cache_error_persistence
                                   */
    uint8_t        co_lock_type;  /**< @see cache_lock_t */
    uint8_t        co_write_mode; /**< @see cache_write_mode_t */
    uint8_t        co_invd_mode;  /**< @see cache_invd_mode_t */
    uint16_t       co_partition;
    uint64_t       co_md_rid;
    uint64_t       co_master_block_id;/**< Used in block mode to determine parent
                                       *   object...
                                       * and used for master blocks.
                                       */
    uint64_t       co_block_num;
    uint32_t       co_reader_uid; /**< uid that the file block will be read
                                   *   into the cache as
                                   */
    uint32_t       co_reader_gid; /**< gid that the file block will be read
                                   *   into the cache as
                                   */
    uint64_t       co_pad;        /**< For future use (pad to 64-bit boundary)*/
} common_meta_data_t;

INLINE void bswap_common_meta_data(common_meta_data_t *data)
{
	UNREFERENCED_PARAMETER(data);
#if CPU_BE
    data->co_md_rid = bswap_64(data->co_md_rid);
    data->co_master_block_id = bswap_64(data->master_block_id);
    data->co_block_num = bswap_64(data->co_block_num);
    data->co_max_block_num = bswap_64(data->co_max_block_num);
    data->co_reader_uid = bswap_32(data->co_reader_uid);
    data->co_reader_gid = bswap_32(data->co_reader_gid);
    data->co_partition = bswap_16(data->co_partition);
#endif
}

/*!
 * Response to a rna_service_metadata_query_t, from a metadata server.
 */
DECLARE_PACKED_STRUCT(rna_service_metadata_query_response) {
    uint64_t              mqr_cookie;       /*! The value from the mqs_cookie
                                             *  field of the message for which
                                             *  this message is a response
                                             */
    struct rna_service_id mqr_service_id;   /*! Cache server's unique ID */
    struct rna_if_table   mqr_if_table;     /*! Cache server's available
                                             *  interfaces
                                             */
    uint64_t              mqr_block_size;   /*! Informs client of block size
                                             *  that is being used.
                                             */
    uint64_t              mqr_new_offset;   /*! New offset for truncation */
    int32_t               mqr_error;
    uint64_t              mqr_master_block_id;
                                            /*! If this response is for a master
                                             * block, the master block ID of the
                                             * master block.  Otherwise 0.
                                             */
    cachedev_id_t         mqr_cachedev_id;  /**< MD-assigned cache device */
    common_meta_data_t    c;                /*! Common metadata stored by both
                                             *  the MDs and the CSs.
                                             */
    rna_service_hash_key_t
                          mqr_path_key;     /*! 24 bytes */
} END_PACKED_STRUCT(rna_service_metadata_query_response);

INLINE void
bswap_rna_service_metadata_query_response_t(
                                   rna_service_metadata_query_response_t *data)
{
	UNREFERENCED_PARAMETER(data);
#if CPU_BE
    bswap_rna_service_id(&data->mqr_service_id);
    bswap_rna_if_table(&data->mqr_if_table);
    data->mqr_block_size = bswap_64(data->mqr_block_size);
    data->mqr_new_offset = bswap_64(data->mqr_new_offset);
    data->mqr_master_block_id = bswap_64(data->mqr_master_block_id);
    bswap_common_meta_data(&data->c);
    bswap_rna_hash_key_t(&data->mqr_path_key);
#endif
}


/*!
 * Response to a rna_service_cache_invalidate_t, from a metadata server.
 */
DECLARE_PACKED_STRUCT(rna_service_cache_invalidate_response) {
    char                cir_pad;            /*! Currently unused */
} END_PACKED_STRUCT(rna_service_cache_invalidate_response);


/*!
 * Response to a rna_service_mount_register_t, from the configuration
 * manager.
 */
DECLARE_PACKED_STRUCT(rna_service_register_mount_response) {
    uint32_t            rmr_pad;            /*! Currently unused */
} END_PACKED_STRUCT(rna_service_register_mount_response);


/*!
 * Response to a rna_service_mount_deregister_t, from the configuration
 * manager.
 */
DECLARE_PACKED_STRUCT(rna_service_deregister_mount_response) {
    uint32_t            dmr_pad;            /*! Currently unused */
} END_PACKED_STRUCT(rna_service_deregister_mount_response);


/*!
 * Response to an rna_service_register_block_device_t, from the
 * configuration manager.
 */
DECLARE_PACKED_STRUCT(rna_service_register_block_device_response) {
    uint64_t            rbr_device;     /*! device supplied in rbs_device in
                                         *  rna_service_register_block_device_t
                                         */
    uint64_t            rbr_capacity;   /*! Bytes.  Must be used unless device
                                         *  already exists
                                         */
    uint8_t             rbr_shared;     /*! TRUE if the device is shared */
    uint8_t             rbr_available;  /*! TRUE if there's space for this
                                         *  device.  If false, fail create.
                                         */
} END_PACKED_STRUCT(rna_service_register_block_device_response);


DECLARE_PACKED_STRUCT(rna_service_deregister_block_device_response) {
    uint32_t            dbr_pad;            /*! Currently unused */
} END_PACKED_STRUCT(rna_service_deregister_block_device_response);


/*!
 * Notify the CFM that resilvering of the specified cache device's replica
 * stores has completed.
 */
DECLARE_PACKED_STRUCT(rna_service_resilver_cache_device_complete) {
	uint64_t        rcdc_msg_id;                /*! Requester's message ID,
                                                 *  which is returned unchanged
                                                 *  by the cfm
                                                 */
    cachedev_id_t   rcdc_cachedev_id;           /*! The ID of the cache device
                                                 *  whose resilvering has
                                                 *  completed
                                                 */
    uint64_t        rcdc_resilver_request_number;
                                                /*! Each resilver request is
                                                 * associated with a unique
                                                 * resilver request number
                                                 */
} END_PACKED_STRUCT(rna_service_resilver_cache_device_complete);

INLINE void
bswap_rna_service_resilver_cache_device_complete(
                            rna_service_resilver_cache_device_complete_t *data)
{
	UNREFERENCED_PARAMETER(data);
#if CPU_BE
    data->rcdc_msg_id = bswap_64(data->rcdc_msg_id);
    data->rcdc_cachedev_id = bswap_64(data->rcdc_cachedev_id);
    data->rcdc_resilver_request_num = bswap_64(data->rcdc_resilver_request_num);
#endif
}

/*!
 * Request permission to shutdown from the CFM.
 */
DECLARE_PACKED_STRUCT(rna_service_cs_shutdown_request) {
	uint64_t        sr_msg_id;                  /*! Requester's message ID,
                                                 *  which is returned unchanged
                                                 *  by the cfm
                                                 */
} END_PACKED_STRUCT(rna_service_cs_shutdown_request);

INLINE void
bswap_rna_cs_shutdown_request(rna_service_cs_shutdown_request_t *data)
{
    UNREFERENCED_PARAMETER(data);
#if CPU_BE
    data->sr_msg_id = bswap_64(data->sr_msg_id);
#endif
}

/*!
 * Response from the CFM to a CS request permission to shutdown
 */
DECLARE_PACKED_STRUCT(rna_service_cs_shutdown_response) {
	uint8_t        sr_pad;
} END_PACKED_STRUCT(rna_service_cs_shutdown_response);

INLINE void
bswap_rna_cs_shutdown_response(rna_service_cs_shutdown_response_t *data)
{
    UNREFERENCED_PARAMETER(data);
#if CPU_BE
#endif
}

// Begin SCSI III journaling messages.

/* a structure for transferring scsi reservation data from the
 * response message back to the caller's context.
 */
typedef struct scsi_device_reservation_state_s {
    rsv_itn_id_t        reservation_holder_itn_id;
    uint64_t            reservation_holder_key;
    uint8_t             reservation_mode;
    uint8_t             reservation_type;
    uint8_t             reservation_aptpl;
    uint64_t            reservation_generation;
} scsi_reservation_state_t;

/* a structure for transferring scsi registration data from the
 * response mesage back to the user context.
 *
 * This supports transferring the entire registration state in segments,
 * using a sequence of messages.
 *
 * Explanation of fields:
 *
 *  registration_num_req_entries    Is the number of entries the
 *                                  caller to acquire_cfm_registration_state()
 *                                  has available.
 *  registration_num_resp_entries   The number of entries required to
 *                                  hold the registration list.
 *
 * registration data is transferred only if registration_num_resp_entries
 * is less than or equal to registration_num_req_entries.
 *
 * If registrations data is transferred, then these fields apply:
 *
 *  registration_start_entry_index   Is the index into the user's
 *                                   registration buffer array to
 *                                   begin this segment of the transfer.
 *
 *  registration_num_transfer_entries   The number of entries to transfer.
 *
 *  registration_resp_entries           Pointer to the BEGINNING of the
 *                                      user's registration buffer array.
 */
typedef struct scsi_device_itn_registration_state_s {
    int                         registration_num_req_entries;
    int                         registration_num_resp_entries;
    int                         registration_start_entry_index;
    int                         registration_num_transfer_entries;
    rsv_registration_entry_t   *registration_resp_entries;
} scsi_itn_registration_state_t;

/*!
 * update SCSI reservation in cfm journal.
 */
DECLARE_PACKED_STRUCT(rna_service_update_scsi_itn_reservation) {
    rna_store_wwn_t       scsi_res_update_lun_wwn;
    rsv_itn_id_t          scsi_res_update_holder_itn_id;
    rsv_key_t             scsi_res_update_holder_key;
    uint8_t               scsi_res_update_mode;
    uint8_t               scsi_res_update_type;
    uint8_t               scsi_res_update_preempt;
    rsv_key_t             scsi_res_update_clear_key;
    rsv_itn_id_t          scsi_res_update_itn_id_to_keep;
    uint64_t              scsi_res_update_generation;
    uint64_t              scsi_res_update_seq_no;
    uint64_t              scsi_res_update_msg_id;
} END_PACKED_STRUCT(rna_service_update_scsi_itn_reservation);

INLINE void
bswap_rna_service_update_scsi_itn_reservation_msg_t(
    rna_service_update_scsi_itn_reservation_t *data)
{
	UNREFERENCED_PARAMETER(data);
#if CPU_BE
    data->res_state.XXX = bswap_64(data->reg_state.XXX);
#endif
}

/*!
 * update SCSI itn registration in cfm journal.
 */
DECLARE_PACKED_STRUCT(rna_service_update_scsi_itn_registration) {
    rna_store_wwn_t     scsi_reg_update_lun_wwn;
    rsv_itn_id_t        scsi_reg_update_itn_id;
    rsv_key_t           scsi_reg_update_itn_key;
    uint8_t             scsi_reg_update_aptpl;
    uint64_t            scsi_reg_update_reservation_generation;
    uint64_t            scsi_reg_update_seq_no;
    uint64_t            scsi_reg_update_msg_id;
} END_PACKED_STRUCT(rna_service_update_scsi_itn_registration);

INLINE void
bswap_rna_service_scsi_itn_reservation_msg_t(
    rna_service_update_scsi_itn_reservation_t *data)
{
	UNREFERENCED_PARAMETER(data);
#if CPU_BE
    data->res_state.XXX = bswap_64(data->res_state.XXX);
#endif
}

/*!
 * Clear the scsi itn reservation and all registrations in
 * cfm journal. preserve the generation number for the reservation.
 */
DECLARE_PACKED_STRUCT(rna_service_clear_scsi_itn_reservation) {
    rna_store_wwn_t     scsi_res_clear_lun_wwn;
    rsv_key_t           scsi_res_clear_key;
    uint64_t            scsi_res_clear_reservation_generation;
    uint64_t            scsi_res_clear_seq_no;
    uint64_t            scsi_res_clear_msg_id;
} END_PACKED_STRUCT(rna_service_clear_scsi_itn_reservation);

INLINE void
bswap_rna_service_clear_scsi_itn_reservation_t(
    rna_service_clear_scsi_itn_reservation_t *data)
{
    UNREFERENCED_PARAMETER(data);
#if CPU_BE
    data->scsi_rs_clear_ = bswap_64();
#endif
}

/*!
 * Response message for update reservation, update registration,
 * and clear reservation.
 */
DECLARE_PACKED_STRUCT(rna_service_update_clear_scsi_itn_resg_resp) {
    rna_store_wwn_t     scsi_resg_resp_lun_wwn;
    int                 scsi_resg_resp_error;
    uint64_t            scsi_resg_resp_seq_no;
    uint64_t            scsi_resg_resp_msg_id;
} END_PACKED_STRUCT(rna_service_update_clear_scsi_itn_resg_resp);

INLINE void
bswap_rna_service_update_clear_scsi_itn_resg_resp_t(
    rna_service_update_clear_scsi_itn_resg_resp_t *data)
{
    UNREFERENCED_PARAMETER(data);
#if CPU_BE
    data->XXX = bswap_64();
#endif
}

/*!
 * Request to acquire the CFM journal information for a scsi reservation
 */
DECLARE_PACKED_STRUCT(rna_service_acquire_scsi_itn_res) {
    rna_store_wwn_t     scsi_res_acquire_lun_wwn;
    uint64_t            scsi_res_acquire_seq_no;
    uint64_t            scsi_res_acquire_msg_id;
} END_PACKED_STRUCT(rna_service_acquire_scsi_itn_res);

INLINE void
bswap_rna_service_acquire_scsi_itn_res_t(
    rna_service_acquire_scsi_itn_res_t *data) {
    UNREFERENCED_PARAMETER(data);
#if CPU_BE
    data->XXX = bswap_64();
#endif
}

/*!
 * Response with CFM jouranl information for a scsi reservation
 */
DECLARE_PACKED_STRUCT(rna_service_acquire_scsi_itn_res_resp) {
    rna_store_wwn_t     scsi_res_acquire_resp_lun_wwn;
    rsv_itn_id_t        scsi_res_acquire_resp_holder_itn_id;
    rsv_key_t           scsi_res_acquire_resp_holder_key;
    uint8_t             scsi_res_acquire_resp_mode;
    uint8_t             scsi_res_acquire_resp_type;
    uint8_t             scsi_res_acquire_resp_aptpl;
    uint64_t            scsi_res_acquire_resp_generation;
    int                 scsi_res_acquire_resp_error;
    uint64_t            scsi_res_acquire_resp_seq_no;
    uint64_t            scsi_res_acquire_resp_msg_id;
} END_PACKED_STRUCT(rna_service_acquire_scsi_itn_res_resp);

INLINE void
bswap_rna_service_acquire_scsi_itn_res_resp(
    rna_service_acquire_scsi_itn_res_resp_t *data)
{
    UNREFERENCED_PARAMETER(data);
#if CPU_BE
    data->XXX = bswap_64();
#endif
}

/*!
 * Request to acquire the cfm journal information for a scsi registration
 * The number of entries in the journal may be larger than what will fit
 * in a single message.
 *
 * So we need to support retrieving it all using a sequence of messages.
 *
 * Fields in this request message are:
 *
 *  scsi_reg_acquire_lun_wwn            Identifies the LUN we are operating on
 *
 *  scsi_reg_acquire_num_reg_entries    The number of registration entries in
 *                                      the user's buffer (should not change
 *                                      during the multi-message transfer
 *                                      sequence)
 *
 *  scsi_reg_acquire_start_entry_index  The index of the first entry in
 *                                      the array of registration entries
 *                                      to begin the transfer from.
 *
 *  scsi_reg_acquire_seq_no             A unique message sequence number
 *                                      returned in the response to match
 *                                      it to this request in the response
 *                                      message handler.
 *
 *  scsi_reg_acquire_msg_id             The rna message id, used by the
 *                                      rna service library to match a response
 *                                      with this request.
 *
 * The transfer_entry_index is the index into the array of registration entries
 * to start the next block transfer from.
 *
 * It is assumed that once num_reg_entries is big enough, there will
 * be space available for whatever size is transferred in this request.
 */
DECLARE_PACKED_STRUCT(rna_service_acquire_scsi_itn_reg) {
    rna_store_wwn_t     scsi_reg_acquire_lun_wwn;
    int                 scsi_reg_acquire_num_reg_entries;
    int                 scsi_reg_acquire_start_entry_index;
    uint64_t            scsi_reg_acquire_seq_no;
    uint64_t            scsi_reg_acquire_msg_id;
} END_PACKED_STRUCT(rna_service_acquire_scsi_itn_reg);

INLINE void
bswap_rna_service_acquire_scsi_itn_reg_t(
    rna_service_acquire_scsi_itn_reg_t *data)
{
    UNREFERENCED_PARAMETER(data);
#if CPU_BE
    data->XXX = bswap_64();
#endif
}

/* Use as much space as we can in the rna_service_message_buffer,
 * which is smaller than the cfm_cmd_t message buffer.
 *
 * Subtract one rsv_registration_entry_t just for
 * safety padding, in case the arithmetic doesn't quite work out.
 */
#define SCSI_REG_ACQUIRE_RESP_ENTS \
      (((RNA_SERVICE_MESSAGE_BUFFER_PAD)  - \
        sizeof(rna_store_wwn_t)           - \
        sizeof(int)                       - \
        sizeof(int)                       - \
        sizeof(uint64_t)                  - \
        sizeof(uint64_t)                  - \
        sizeof(rsv_registration_entry_t))/sizeof(rsv_registration_entry_t))

/*!
 * Response containing CFM journal information for a scsi registration
 *
 * See comment about multi-message transfers in
 * rna_service_acquire_scsi_itn_reg_t.
 *
 * Field meanings are:
 *
 *  scsi_reg_acquire_resp_lun_wwn          identifies the LUN being operated on.
 *
 *  scsi_reg_acquire_resp_num_reg_entries  The number of registration entries
 *                                         in the user's buffer.  This
 *                                         does not change during the multi-
 *                                         message transfer sequence.
 *
 *  scsi_reg_acquire_resp_start_entry_index The index into the array of
 *                                          registration entries to begin
 *                                          the transfer at.  This is
 *                                          actually redundant with
 *                                          what was sent in the request.
 *
 *  scsi_reg_acquire_resp_num_transfer_entries The number of registration
 *                                          entries included in this response.
 *
 *  scsi_reg_acquire_resp_data              Array of registation entries
 *                                          included in this response buffer.
 */
DECLARE_PACKED_STRUCT(rna_service_acquire_scsi_itn_reg_resp) {
    rna_store_wwn_t            scsi_reg_acquire_resp_lun_wwn;
    int                        scsi_reg_acquire_resp_num_reg_entries;
    int                        scsi_reg_acquire_resp_start_entry_index;
    int                        scsi_reg_acquire_resp_num_transfer_entries;
    int                        scsi_reg_acquire_resp_error;
    uint64_t                   scsi_reg_acquire_resp_seq_no;
    uint64_t                   scsi_reg_acquire_resp_msg_id;
    rsv_registration_entry_t
        scsi_reg_acquire_resp_data[SCSI_REG_ACQUIRE_RESP_ENTS];
} END_PACKED_STRUCT(rna_service_acquire_scsi_itn_reg_resp);


INLINE void
bswap_rna_service_acquire_scsi_itn_reg_resp(
    rna_service_acquire_scsi_itn_reg_resp_t *data)
{
    UNREFERENCED_PARAMETER(data);
#if CPU_BE
    data->XXX = bswap_64();
#endif
}

// END of SCSI III reservation journal messages

#define RNA_EVENT_DATA_LEN 512
#define HISTOGRAM_MAX_RNA_EVENT_BUCKETS     50
#define HISTOGRAM_MAX_NAME_LENGTH 255
struct histogram {
    char        name[HISTOGRAM_MAX_NAME_LENGTH+1];
    int         num_buckets;
    uint64_t    bucket_size;
    uint64_t    bucket_offset;  // Left edge of bucket 0
    atomic_t    bucket[1];
};

#define RNA_OMS_ARG_LEN     256
#define RNA_OMS_MAX_ARGS    4

struct oms_arg_data {
    uint32_t        oms_arg_type;
    union {
        uint64_t            oms_size;
        cache_write_mode_t  oms_write_mode;
        rna_store_wwn_t     oms_store_wwn;
        char                oms_string[RNA_OMS_ARG_LEN];
    } u;
};

struct oms_event {
    uint32_t    oms_event_id;
    uint32_t    oms_arg_count;
    struct oms_arg_data oms_data[RNA_OMS_MAX_ARGS];
};

/** RNA event data
 * Components will send event data to any entity that has registered and maintains an active ep.
 * @see rna_event_reg
 */
typedef struct rna_service_event_msg_s {
    //	uint64_t key; /**< Event key */
    //	uint64_t index; /**< monotonically increasing value used to track holes in the event log */
	uint32_t type; /**< Error, Warning, Etc. (See enum in util.h TBA later) */
	struct timespec timestamp; /**< Local timestamp */
    union {
        uint8_t data[RNA_EVENT_DATA_LEN]; /**< String or well defined event data type */
        struct oms_event oms_event;       /** When type is RNA_DBG_EVENT */
        struct {
            struct histogram histogram;  /** When type has RNA_DBG_HISTOGRAM set */
            atomic_t buckets[HISTOGRAM_MAX_RNA_EVENT_BUCKETS-1];
        } rna_dbg_histogram;
    };
} rna_service_event_msg_t;

INLINE void bswap_rna_service_event_msg_t(
    rna_service_event_msg_t *data)
{
	UNREFERENCED_PARAMETER(data);
#if CPU_BE
	data->key = bswap_64(data->key);
	data->index = bswap_32(data->index);
	data->type = bswap_32(data->type);
	data->timestamp = bswap_32(data->timestamp);
	//uint8_t data[RNA_EVENT_DATA_LEN];
#endif
}


typedef enum rna_service_message_type_e {
    RNA_SERVICE_MESSAGE_TYPE_INVALID = 0,
    /* Messages to send: */
    RNA_SERVICE_MESSAGE_TYPE_MD_QUERY,
    RNA_SERVICE_MESSAGE_TYPE_CACHE_INVD,
    RNA_SERVICE_MESSAGE_TYPE_CACHE_MASTER_INVD,
    RNA_SERVICE_MESSAGE_TYPE_REG_MNT,
    RNA_SERVICE_MESSAGE_TYPE_DEREG_MNT,
    RNA_SERVICE_MESSAGE_TYPE_REG_PATH,
    RNA_SERVICE_MESSAGE_TYPE_DEREG_PATH,
    RNA_SERVICE_MESSAGE_TYPE_REG_BLKDEV,
    RNA_SERVICE_MESSAGE_TYPE_DEREG_BLKDEV,
    RNA_SERVICE_MESSAGE_TYPE_REG_SVC_CONN,
    RNA_SERVICE_MESSAGE_TYPE_DEREG_SVC_CONN,
    RNA_SERVICE_MESSAGE_TYPE_REG_CACHE_DEVICE,
    RNA_SERVICE_MESSAGE_TYPE_REG_CACHE_DEVICE_END,
    RNA_SERVICE_MESSAGE_TYPE_DEREG_CACHE_DEVICE,
    RNA_SERVICE_MESSAGE_TYPE_EXPEL_CACHE_DEVICE,
    RNA_SERVICE_MESSAGE_TYPE_UNEXPELLED_CACHEDEVS,
    RNA_SERVICE_MESSAGE_TYPE_DEREG_REPLICA_STORE,
    RNA_SERVICE_MESSAGE_TYPE_RESILVER_CACHE_DEVICE_COMPLETE,
    RNA_SERVICE_MESSAGE_TYPE_CS_SHUTDOWN_REQUEST,
    RNA_SERVICE_MESSAGE_TYPE_EVENT,
    // begin SCSI III request message types
    RNA_SERVICE_MESSAGE_TYPE_UPDATE_SCSI_ITN_RES,
    RNA_SERVICE_MESSAGE_TYPE_UPDATE_SCSI_ITN_REG,
    RNA_SERVICE_MESSAGE_TYPE_CLEAR_SCSI_ITN_RES,
    RNA_SERVICE_MESSAGE_TYPE_ACQUIRE_SCSI_ITN_RES,
    RNA_SERVICE_MESSAGE_TYPE_ACQUIRE_SCSI_ITN_REG,
    // end SCSI III request message types

    /* Responses: */
    RNA_SERVICE_MESSAGE_TYPE_MD_QUERY_RESPONSE,
    RNA_SERVICE_MESSAGE_TYPE_CACHE_INVD_RESPONSE,
    RNA_SERVICE_MESSAGE_TYPE_REG_MNT_RESPONSE,
    RNA_SERVICE_MESSAGE_TYPE_DEREG_MNT_RESPONSE,
    RNA_SERVICE_MESSAGE_TYPE_REG_BLKDEV_RESPONSE,
    RNA_SERVICE_MESSAGE_TYPE_DEREG_BLKDEV_RESPONSE,
    RNA_SERVICE_MESSAGE_TYPE_CS_SHUTDOWN_RESPONSE,
    // begin SCSI III request message responses
    RNA_SERVICE_MESSAGE_TYPE_UPDATE_CLEAR_SCSI_ITN_RES_RESPONSE,
    RNA_SERVICE_MESSAGE_TYPE_ACQUIRE_SCSI_ITN_RES_RESPONSE,
    RNA_SERVICE_MESSAGE_TYPE_ACQUIRE_SCSI_ITN_REG_RESPONSE,

    /*
     * Asynchronous messages (messages that are sent or received with no
     * expectation of a response).
     */
    RNA_SERVICE_MESSAGE_TYPE_SET_LOG_LEVEL,
    RNA_SERVICE_MESSAGE_TYPE_CLIENT_EVENT_REG,
    RNA_SERVICE_MESSAGE_TYPE_CLIENT_EVENT_DEREG,
    RNA_SERVICE_MESSAGE_TYPE_CLIENT_EVENT,
    RNA_SERVICE_MESSAGE_TYPE_BSTAT_REQUEST,
    RNA_SERVICE_MESSAGE_TYPE_BSTAT_RESPONSE,
    RNA_SERVICE_MESSAGE_TYPE_CREATE_BLKDEV,
    RNA_SERVICE_MESSAGE_TYPE_CONTROL_BLKDEV,
    RNA_SERVICE_MESSAGE_TYPE_CONTROL_BLKDEV_RESPONSE,
    RNA_SERVICE_MESSAGE_TYPE_EXPEL_CS,
    RNA_SERVICE_MESSAGE_TYPE_CONTROL_CS,
    RNA_SERVICE_MESSAGE_TYPE_CONTROL_CS_RESPONSE,
    RNA_SERVICE_MESSAGE_TYPE_RELOCATE_BLOCK,
    RNA_SERVICE_MESSAGE_TYPE_ABSORB_BLOCK,
    RNA_SERVICE_MESSAGE_TYPE_ABSORB_BLOCK_RESPONSE,
    RNA_SERVICE_MESSAGE_TYPE_INVD_HOLD_RESPONSE,
    RNA_SERVICE_MESSAGE_TYPE_CS_CLIENT_REG,
    RNA_SERVICE_MESSAGE_TYPE_CONF_MGR_REG_RESPONSE,
    RNA_SERVICE_MESSAGE_TYPE_NOTIFICATION_EVENT,
    RNA_SERVICE_MESSAGE_TYPE_NUM_MD_HASH_PARTITIONS,
} rna_service_message_type_t;


/*!
 * A header for an rna_service_message_buffer_t.
 */
DECLARE_PACKED_STRUCT(rna_service_message_buffer_header) {
    rna_service_message_type_t rmb_message_type;
    uint32_t                   rmb_pad;  // For future use (and for
                                         // 64-bit alignment).  Add new field
                                         // here.
} END_PACKED_STRUCT(rna_service_message_buffer_header);


/*!
 * A buffer that can contain either a message to be sent or a response to a
 * message previously sent.  This buffer must either be allocated by
 * rna_service_alloc_message_buffer (rmb_metadata_query or
 * rmb_cache_invalidate) or provided as an argument to a response
 * callback (rmb_metadata_query_response or rmb_cache_invalidate_response).
 */
DECLARE_PACKED_STRUCT(rna_service_message_buffer) {
    rna_service_message_buffer_header_t     h;
    union {
        /* Messages to send: */
        rna_service_metadata_query_t        rmb_metadata_query;
        rna_service_cache_invalidate_t      rmb_cache_invalidate;
        rna_service_register_path_t         rmb_register_path;
        rna_service_register_mount_t        rmb_register_mount;
        rna_service_deregister_mount_t      rmb_deregister_mount;
        rna_service_register_block_device_t
                                            rmb_register_block_device;
        rna_service_deregister_block_device_t
                                            rmb_deregister_block_device;
        rna_service_register_svc_conn_t     rmb_register_svc_conn;
        rna_service_deregister_svc_conn_t   rmb_deregister_svc_conn;
        rna_service_register_cache_device_t rmb_register_cache_device;
        rna_service_register_cache_device_end_t
                                            rmb_register_cache_device_end;
        rna_service_deregister_cache_device_t
                                            rmb_deregister_cache_device;
        rna_service_expel_cache_device_t    rmb_expel_cache_device;
        rna_service_unexpelled_cachedevs_t  rmb_unexpelled_cachedevs;
        rna_service_register_replica_store_t
                                            rmb_register_replica_store;
        rna_service_deregister_replica_store_t
                                            rmb_deregister_replica_store;
        rna_service_resilver_cache_device_complete_t
                                            rmb_resilver_cache_device_complete;
        rna_service_cs_shutdown_request_t   rmb_cs_shutdown_request;
        rna_service_event_msg_t             rmb_event;

        /* Responses: */
        rna_service_metadata_query_response_t
                                            rmb_metadata_query_response;
        rna_service_cache_invalidate_response_t
                                            rmb_cache_invalidate_response;
        rna_service_register_mount_response_t
                                            rmb_register_mount_response;
        rna_service_deregister_mount_response_t
                                            rmb_deregister_mount_response;
        rna_service_register_block_device_response_t
                                            rmb_register_block_device_response;
        rna_service_deregister_block_device_response_t
                                           rmb_deregister_block_device_response;
        rna_service_cs_shutdown_response_t  rmb_cs_shutdown_response;

        /*
         * Asynchronous messages (messages that are sent or received with no
         * expectation of a response).
         */
        rna_service_set_log_level_t         rmb_set_log_level;
        rna_service_client_event_reg_t      rmb_client_event_reg;
        rna_service_client_event_dereg_t    rmb_client_event_dereg;
        rna_service_client_event_t          rmb_client_event;
        rna_service_bstat_req_t             rmb_bstat_req;
        rna_service_bstat_response_t        rmb_bstat_response;
        rna_service_create_block_device_t   rmb_create_block_device;
        rna_service_control_block_device_t  rmb_control_block_device;
        rna_service_control_block_device_response_t
                                            rmb_control_block_device_response;
        rna_service_expel_cs_t              rmb_expel_cs;
        rna_service_control_cs_t            rmb_control_cs;
        rna_service_control_cs_response_t   rmb_control_cs_response;
        rna_service_relocate_cache_block_t  rmb_relocate_cache_block;
        rna_service_cache_absorb_block_t    rmb_cache_absorb_block;
        rna_service_cache_absorb_block_response_t
                                            rmb_cache_absorb_block_response;
        rna_service_invd_hold_response_t    rmb_invd_hold_response;
        rna_service_cache_client_reg_t      rmb_cache_client_reg;
        rna_service_cfm_client_resp_t       rmb_cfm_client_resp;
        rna_service_notification_event_t    rmb_notification_event;

        /* SCSI III reservation messages */
        rna_service_update_scsi_itn_reservation_t
                                    rmb_cfm_update_scsi_itn_reservation;
        rna_service_update_scsi_itn_registration_t
                                    rmb_cfm_update_scsi_itn_registration;
        rna_service_clear_scsi_itn_reservation_t
                                    rmb_cfm_clear_scsi_itn_reservation;
        rna_service_update_clear_scsi_itn_resg_resp_t
                                    rmb_cfm_update_clear_scsi_itn_resg_resp;
        rna_service_acquire_scsi_itn_res_t
                                    rmb_cfm_acquire_scsi_itn_reservation;
        rna_service_acquire_scsi_itn_res_resp_t
                                    rmb_cfm_acquire_scsi_itn_res_resp;
        rna_service_acquire_scsi_itn_reg_t
                                    rmb_cfm_acquire_scsi_itn_registration;
        rna_service_acquire_scsi_itn_reg_resp_t
                                    rmb_cfm_acquire_scsi_itn_reg_resp;

        /* end SCSI III reservation messages */
        rna_service_num_md_hash_partitions_t rmb_num_partitions;
		unsigned char _pad[RNA_SERVICE_MESSAGE_BUFFER_PAD];
    } u;
} END_PACKED_STRUCT(rna_service_message_buffer);


/* ----------------------------- Callbacks --------------------------------- */

/*!
 * The message response status for an rna_service_response_callback.
 */
typedef enum rna_service_response_status_e {
    RNA_SERVICE_RESPONSE_STATUS_SUCCESS,    /*! The message was successfully
                                             *  sent and a reply successfully
                                             *  received.
                                             */
    RNA_SERVICE_RESPONSE_STATUS_SEND_TIMED_OUT,
                                            /*! The message could not be sent
                                             *  before the timeout elapsed,
                                             *  because there is no connection
                                             *  to the destination.
                                             */
    RNA_SERVICE_RESPONSE_STATUS_RESPONSE_TIMED_OUT,
                                            /*! The message was sent, but no
                                             *  response was received before
                                             *  the timeout elapsed.
                                             */
    RNA_SERVICE_RESPONSE_STATUS_CANCELED,    /*! The message send was canceled
                                             *  by the user (cancellation is
                                             *  not currently supported).
                                             */
} rna_service_response_status_t;

/*!
 * rna_service callback invoked when a response to an rna_service message
 * is received.
 *
 * Arguments:
 *    ctx           The user's rna_service context, as created by
 *                  rna_service_ctx_create.
 *
 *    message_sent  Pointer to the message that was responded to.  This
 *                  message buffer was the 'message' argument to the
 *                  rna_service_send_md() call that sent the message that
 *                  has been responded to.
 *
 *                  NOTE that the user is responsible for freeing this
 *                  message buffer, using rna_service_free_message_buffer().
 *
 *    response      If status is RNA_SERVICE_RESPONSE_STATUS_SUCCESS, this is
 *                  a pointer to the response to the above message; otherwise
 *                  NULL.
 *
 *                  NOTE that if 'response' is non-NULL, the user is
 *                  responsible for freeing this response message buffer, using
 *                  rna_service_free_message_buffer().
 *
 *    status          The status of the response:
 *    RNA_SERVICE_RESPONSE_STATUS_SUCCESS     A response has been successfully
 *                                            received.
 *    RNA_SERVICE_RESPONSE_STATUS_SEND_TIMED_OUT
 *                                            There is no connection to the
 *                                            recipient.  The message was not
 *                                            sent, because it timed out before
 *                                            a connection could be made.
 *                                            'response' is NULL.
 *    RNA_SERVICE_RESPONSE_STATUS_RESPONSE_TIMED_OUT
 *                                            The message was sent, but the
 *                                            user-specified response timeout
 *                                            elapsed before a response was
 *                                            received; 'response' is NULL.
 *    RNA_SERVICE_RESPONSE_STATUS_CANCELED    Not currently implemented.
 */
typedef void (*rna_service_response_callback)
                                    (struct rna_service_ctx_s     *ctx,
                                     rna_service_message_buffer_t *message_sent,
                                     rna_service_message_buffer_t *response,
                                     rna_service_response_status_t status);


/*!
 * Event types for an rna_service_event_callback.
 */
typedef uint64_t rna_service_event_t;
#define RNA_SERVICE_EVENT_NONE                   0
#define RNA_SERVICE_EVENT_INFO_FULLY_CONNECTED   1
                /*
                 * Connections have been established to the primary CFM and
                 * all the MDs.
                 */
#define RNA_SERVICE_EVENT_CACHE_MOUNT_BLOCKED    2
#define RNA_SERVICE_EVENT_CACHE_MOUNT_UNBLOCKED  3
#define RNA_SERVICE_EVENT_KILL_SELF_RESTART      4
#define RNA_SERVICE_EVENT_KILL_SELF_NO_RESTART   5
#define RNA_SERVICE_EVENT_DETACHED_FROM_CLUSTER  6
                /*
                 * This component may no longer be a member of the cluster,
                 * and should quiesce.  This condition may be transient;
                 * if so, an RNA_SERVICE_EVENT_REJOINED_CLUSTER event will be
                 * invoked to signal its end.
                 */
#define RNA_SERVICE_EVENT_REJOINED_CLUSTER       7
                /*
                 * After becoming detached from the cluster, this component has
                 * rejoined the cluster, so can resume activity.
                 */
#define RNA_SERVICE_EVENT_SEND_SHUTDOWN_REQUEST_TIMEOUT 8
                /*
                 * A shutdown request message failed to be sent to the primary
                 * CFM in time.  Possibly there is no primary CFM.
                 */


/*!
 * rna_service callback invoked when an rna_service event occurs.
 *
 * Arguments:
 *    ctx        The user's rna_service context, as created by
 *               rna_service_ctx_create.
 *
 *    event      The event that occurred.
 */
typedef void (*rna_service_event_callback) (struct rna_service_ctx_s *ctx,
                                            const rna_service_event_t event);


/*!
 * rna_service callback invoked if an asynchronous message (a message with
 * no response), is received.  These messages are:
 *
 *  rna_service_set_log_level_t      RNA_SERVICE_MESSAGE_TYPE_SET_LOG_LEVEL
 *  rna_service_client_event_t       RNA_SERVICE_MESSAGE_TYPE_CLIENT_EVENT
 *  rna_service_client_event_reg_t   RNA_SERVICE_MESSAGE_TYPE_CLIENT_EVENT_REG
 *  rna_service_client_event_dereg_t RNA_SERVICE_MESSAGE_TYPE_CLIENT_EVENT_DEREG
 *
 * NOTE that the callback function is responsible for freeing the message
 * using rna_service_free_message_buffer().
 *
 * Arguments:
 *    ctx        The user's rna_service context, as created by
 *               rna_service_ctx_create.
 *
 *    message   A message of type RNA_SERVICE_SET_LOG_LEVEL
 *                                          (rna_service_set_log_level_t),
 *               RNA_SERVICE_MESSAGE_TYPE_CLIENT_EVENT_REG
 *                                          (rna_service_client_event_reg_t),
 *               RNA_SERVICE_MESSAGE_TYPE_CLIENT_EVENT_DEREG
 *                                          (rna_service_client_event_dereg_t),
 *               or RNA_SERVICE_MESSAGE_TYPE_CLIENT_EVENT
 *                                          (rna_service_client_event_t).
 */
typedef void (*rna_service_async_msg_callback) (
                            struct rna_service_ctx_s     *ctx,
                            rna_service_message_buffer_t *message);

/* -------------------- Context Initialize / Destroy --------------------- */


/*!
  * Structure that contains all rna_service configuration options
  */
typedef struct rna_service_params_s {
    rna_service_user_type_t
                        rsp_user_type;    
                            /*! Type of user */
    char                rsp_node_name[128];
                            /*! Node name to use during registration */
    rna_service_params_flags_t
                        rsp_flags;
    int                 rsp_transports;
                            /*! For kernel-level clients, the preferred
                             * communication transports (IB_TRANSPORT and/or
                             * TCP_TRANSPORT) to use.  Ignored for user-level
                             * clients.
                             */
    struct rna_service_id
                        rsp_service_id;
                            /*! User's RNA service ID */
    time_t              rsp_metadata_query_response_timeout;
                            /*! The amount of time the user is willing to wait
                             *  for a response to an
                             *  RNA_SERVICE_MESSAGE_TYPE_MD_QUERY
                             *  (rna_service_metadata_query_t) message,
                             *  in seconds.
                             *
                             *  0 indicates the user is willing to wait
                             *  forever.
                             */
    time_t              rsp_cache_invalidate_response_timeout;
                            /*! The amount of time the user is willing to wait
                             *  for a response to an
                             *  RNA_SERVICE_MESSAGE_TYPE_CACHE_INVD or
                             *  RNA_SERVICE_MESSAGE_TYPE_CACHE_MASTER_INVD
                             *  (rna_service_cache_invalidate_t) message,
                             *  in seconds.
                             *
                             *  0 indicates the user is willing to wait
                             *  forever.
                             */
    time_t              rsp_mount_reg_response_timeout;
                            /*! The amount of time the user is willing to wait
                             *  for a response to an
                             *  RNA_SERVICE_MESSAGE_TYPE_REG_MNT or
                             *  RNA_SERVICE_MESSAGE_TYPE_DEREG_MNT
                             *  (rna_service_register_mount_t or
                             *  rna_service_deregister_mount_t) message,
                             *  in seconds.
                             *
                             *  0 indicates the user is willing to wait
                             *  forever.
                             *
                             *  NOTE that this parameter is currently ignored,
                             *  because mount registration messages do not yet
                             *  have responses.
                             */
    time_t              rsp_block_device_reg_response_timeout;
                            /*! The amount of time the user is willing to wait
                             *  for a response to an
                             *  RNA_SERVICE_MESSAGE_TYPE_REG_BLKDEV
                             *  (rna_service_register_block_device_t)
                             *  message, in seconds.
                             *
                             *  0 indicates the user is willing to wait forever
                             */
    rna_service_event_callback
                        rsp_event_callback;
                            /*! Callback invoked if an RNAservice event occurs
                             *  (see rna_service_event_t).  NOTE that an event
                             *  callback must be specified.
                             */
   rna_service_async_msg_callback
                        rsp_async_msg_callback;
                            /*! Callback invoked if an asynchronous message is
                             *  received (for example, an
                             *  rna_service_client_event_reg_t,
                             *  rna_service_client_event_dereg_t,
                             *  rna_service_client_event_t, or
                             *  rna_service_bstat_req_t).
                             *
                             *  May be NULL, if the user isn't interested in
                             *  these messages.
                             */
    void              * rsp_stat_buf;
                            /*! The address of the stats buffer.  May be zero
                             *  (NULL).
                             */
    uint32_t            rsp_stat_length;
                            /*! The size of the above stats buffer, in bytes.
                             *  Must be non-zero if rsp_stat_buf is non-zero,
                             *  otherwise must be zero.
                             */
    uint32_t            rsp_cfm_count;
                            /*! Number of configuration manager addresses in
                             *  the following array (NOTE that this value must
                             *  not be zero)
                             */
    struct sockaddr_in  rsp_cfm_addrs[RNA_SERVICE_CFMS_MAX];
                            /*! Addresses of the set of configuration managers
                             *  in the cluster (at least one address must be
                             *  specified)
                             */
    int                 rsp_cfm_com_types[RNA_SERVICE_CFMS_MAX];
                            /*! Com_type of cfms - more important in
                             *  kernel space, as we don't have a 
                             *  "com_get_transport_type" function */
    int                 rsp_keep_alive_count;
                            /*! overrides /proc/sys/net/ipv4/tcp_keepalive_probes */
    int                 rsp_keep_alive_wait;
                            /*! overrides /proc/sys/net/ipv4/tcp_keepalive_time */
    int                 rsp_keep_alive_interval;
                            /*! overrides /proc/sys/net/ipv4/tcp_keepalive_intvl */
    int                 rsp_md_ping_rate;
                            /*! if non-zero, interval at which to ping MD's */
} rna_service_params_t;

/*!
 * Create and initialize an rna_service context, to be used as an argument to
 * all subsequent rna_service_*() calls.
 *
 * Returns:
 *    RNA_SERVICE_ERROR_NONE  on success.  *ctxpp contains a pointer to the
 *                            allocated rna_service context.
 *    RNA_SERVICE_ERROR_NO_MEMORY
 *                            Memory allocation failed (*ctxpp is NULL)
 *    RNA_SERVICE_ERROR_INVALID_PARAMS
 *                            One or more of the specified parameters is invalid
 *    RNA_SERVICE_ERROR_WORKQ_INIT_FAILURE
 *                            Unable to initialize the workq
 *    RNA_SERVICE_ERROR_COM_INIT_FAILURE
 *                            Failed to initialize the communication layer
 */
extern rna_service_error_t
rna_service_ctx_create(rna_service_params_t      *params,
                       struct rna_service_ctx_s **ctxpp);


/*!
 * Destroy the specified rna_service context (which was created by a prior call
 * to rna_service_ctx_create).  On return, *ctxpp is NULL.
 *
 * Returns:
 *    RNA_SERVICE_ERROR_NONE  on success (*ctxpp is set to NULL)
 *    RNA_SERVICE_ERROR_INVALID_CTX
 *                            Either ctxpp is NULL, or *ctxpp is NULL, or it
 *                            was not created by rna_service_ctx_create().
 */
extern rna_service_error_t
rna_service_ctx_destroy(struct rna_service_ctx_s **ctxpp);

/* ------------------ Message Buffer Allocate / Free ----------------------- */

/*!
 * Allocate an rna_service message buffer.
 *
 * NOTE that once this message buffer has been used as an argument to  an
 * rna_service_send_XXX function, it may not be modified, freed, or re-used
 * until it is returned as the 'message_sent' argument of a response callback.
 *
 * Arguments:
 *    ctx       The caller's rna_service context, created by
 *              rna_service_ctx_create()
 *    msg_type  The type of message that will be stored in the buffer.  Note
 *              that no other message type may be stored in the buffer.
 *    pathname  Used only for messages of the following types to indicate the
 *              pathname:
 *                      RNA_SERVICE_MESSAGE_TYPE_MD_QUERY
 *                      RNA_SERVICE_MESSAGE_TYPE_CACHE_INVD
 *                      RNA_SERVICE_MESSAGE_TYPE_REG_BLKDEV
 *                      RNA_SERVICE_MESSAGE_TYPE_CREATE_BLKDEV
 *                      RNA_SERVICE_MESSAGE_TYPE_CONTROL_BLKDEV
 *                      RNA_SERVICE_MESSAGE_TYPE_CONTROL_BLKDEV_RESPONSE
 *
 * Returns:
 *    A pointer to a message buffer on success
 *    NULL on failure
 */
extern rna_service_message_buffer_t *
rna_service_alloc_message_buffer(struct rna_service_ctx_s  *ctx,
                                 rna_service_message_type_t msg_type,
                                 const char                *pathname);


/*!
 * Free an rna_service message buffer for either a message sent or a response,
 * which was returned as either as the 'message_sent' or 'response' argument
 * of a response callback.
 *
 * Returns:
 *    RNA_SERVICE_ERROR_NONE  on success
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER
 *                            The message buffer specified was not allocated by
 *                            rna_service_alloc_message_buffer() or has not yet
 *                            been returned in a response callback.
 */
extern rna_service_error_t
rna_service_free_message_buffer(struct rna_service_ctx_s     *ctx,
                                rna_service_message_buffer_t *buf);


/*!
 * The function send_md_generic() is the bottom function several call
 * stacks that the cache server uses to send messages to metadata servers.
 * Each of these messages require response messages from the MD before
 * their "send" operation is complete.  While a message is waiting
 * for a response message, it is remembered in a queue.  This is a
 * "pending" message.
 *
 * send_md_generic() enforces a quota for each metadata
 * partition on the number of messages have been sent and are waiting
 * for responses from an MD. If the submission would exceed one of
 * these quotes, the submission is failed, with the error
 * RNA_SERVICE_ERROR_MAX_OUTSTANDING_EXCEEDED error.
 *
 * The problem is that often by the time send_md_generic() fails, it
 * fails so far down the call stack that it is difficult to recover
 * cleanly from that failure.
 *
 * This function tries to "borrow" against the send_md_generic() quotas.
 * If the number of "pending" messages plus the number of "borrowed"
 * messages is less than the quota, then this function permits the
 * borrow, and marks this buffer, so that send_md_generic() is guaranteed
 * to allow this buffer to be sent.
 *
 * If there are already too many pending plus "borrowed" messages for
 * a petition, then this function will fail.
 *
 * Arguments:
 *    ctx  The caller's rna_service context, created by
 *         rna_service_ctx_create()
 *    buf  A message buffer that specifies the message to be sent.
 *         NOTES:
 *            This message buffer must have been allocated by
 *            rna_service_alloc_message_buffer().
 * Returns:
 *    RNA_SERVICE_ERROR_NONE  on success
 *    RNA_SERVICE_ERROR_INVALID_CTX
 *                            Either ctx is NULL, or it is in the process of
 *                            shutting down (rna_service_ctx_destroy() has been
 *                            called), or it was not created by
 *                            rna_service_ctx_create().
 *    RNA_SERVICE_ERROR_MAX_OUTSTANDING_EXCEEDED
 *                            if sending this message would cause the limit
 *                            on the number of outstanding to be exceeded
 */
extern rna_service_error_t
acquire_msgbuf_quota(struct rna_service_ctx_s *ctx,
                     rna_service_message_buffer_t *msg_buf);

/**
 * This function releases the "quota" acquired by acquire_msgbuf_quota()
 *
 * Arguments:
 *    ctx  The caller's rna_service context, created by
 *         rna_service_ctx_create()
 *    buf  A message buffer that specifies the message being released.
 *         NOTES:
 *            This message buffer must have been allocated by
 *            rna_service_alloc_message_buffer().
 * Returns:
 *    RNA_SERVICE_ERROR_NONE  on success
 *    RNA_SERVICE_ERROR_INVALID_CTX
 *                            Either ctx is NULL, or it is in the process of
 *                            shutting down (rna_service_ctx_destroy() has been
 *                            called), or it was not created by
 *                            rna_service_ctx_create().
 */
extern rna_service_error_t
release_msgbuf_quota(struct rna_service_ctx_s *ctx,
                     rna_service_message_buffer_t *msg_buf);

/* ----------------------------- Message Send ----------------------------- */

/**
 * CS path registration with CFM.
 *
 * Arguments:
 *    ctx     The caller's rna_service context, created by
 *            rna_service_ctx_create()
 *    buf     A message buffer that specifies the message to be sent.
 *            NOTES:
 *            1. The rmb_message_type must be
 *               RNA_SERVICE_MESSAGE_TYPE_REG_PATH
 *            2. The message buffer must have been allocated by
 *               rna_service_alloc_message_buffer().
 *
 * Returns:
 *    RNA_SERVICE_ERROR_NONE    On success
 *    RNA_SERVICE_ERROR_INVALID_CTX
 *                            Either ctx is NULL or it was not created by
 *                            rna_service_ctx_create().
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE
 *                            The rmb_message_type of 'message' is not
 *                            RNA_SERVICE_MESSAGE_TYPE_REG_PATH
 *                            or the message buffer was not allocated as an
 *                            RNA_SERVICE_MESSAGE_TYPE_REG_PATH
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER
 *                            The message buffer specified was not allocated by
 *                            rna_service_alloc_message_buffer() or has not yet
 *                            been returned in a response callback.
 */
extern rna_service_error_t
rna_service_send_paths_to_cfm(
                            struct rna_service_ctx_s     *ctx,
                            rna_service_message_buffer_t *buf);

/**
 * CS path registration with MD.
 *
 * Arguments:
 *    ctx     The caller's rna_service context, created by
 *            rna_service_ctx_create()
 *    buf     A message buffer that specifies the message to be sent.
 *            NOTES:
 *            1. The rmb_message_type must be
 *               RNA_SERVICE_MESSAGE_TYPE_REG_PATH
 *            2. The message buffer must have been allocated by
 *               rna_service_alloc_message_buffer().
 *
 * Returns:
 *    RNA_SERVICE_ERROR_NONE    On success
 *    RNA_SERVICE_ERROR_INVALID_CTX
 *                            Either ctx is NULL or it was not created by
 *                            rna_service_ctx_create().
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE
 *                            The rmb_message_type of 'message' is not
 *                            RNA_SERVICE_MESSAGE_TYPE_REG_PATH
 *                            or the message buffer was not allocated as an
 *                            RNA_SERVICE_MESSAGE_TYPE_REG_PATH
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER
 *                            The message buffer specified was not allocated by
 *                            rna_service_alloc_message_buffer() or has not yet
 *                            been returned in a response callback.
 */
extern rna_service_error_t
rna_service_send_paths_to_md(
                            struct rna_service_ctx_s     *ctx,
                            rna_service_message_buffer_t *buf);

/*!
 * A filesystem client uses this API to register a mount with rna_service.
 *
 * Arguments:
 *    ctx     The caller's rna_service context, created by
 *            rna_service_ctx_create()
 *    buf     A message buffer that specifies the message to be sent.
 *            NOTES:
 *            1. The rmb_message_type must be
 *               RNA_SERVICE_MESSAGE_TYPE_REG_MNT
 *            2. The message buffer must have been allocated by
 *               rna_service_alloc_message_buffer().
 *            3. If no response_callback is specified, the message buf must not
 *               be accessed after this call.  It will be freed by the
 *               rna_service library.
 *               If a response_callback is specified, the message buf must not be
 *               accessed (modified, freed, or re-used) until it is returned as
 *               the 'message_sent' argument of the response callback.
 *    response_callback
 *            Currently, this argument must be NULL.  A response callback is
 *            not yet supported for this function.
 *
 * Returns:
 *    RNA_SERVICE_ERROR_NONE    On success
 *    RNA_SERVICE_ERROR_INVALID_CTX
 *                            Either ctx is NULL or it was not created by
 *                            rna_service_ctx_create().
 *    RNA_SERVICE_ERROR_INVALID_RESPONSE_CALLBACK
 *                            A response callback is not yet supported for
 *                            this function
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE
 *                            The rmb_message_type of 'message' is not
 *                            RNA_SERVICE_MESSAGE_TYPE_REG_MNT
 *                            or the message buffer was not allocated as an
 *                            RNA_SERVICE_MESSAGE_TYPE_REG_MNT.
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER
 *                            The message buffer specified was not allocated by
 *                            rna_service_alloc_message_buffer() or has not yet
 *                            been returned in a response callback.
 */
extern rna_service_error_t
rna_service_send_mount_registration(
                            struct rna_service_ctx_s     *ctx,
                            rna_service_message_buffer_t *buf,
                            rna_service_response_callback response_callback);


/*!
 * A filesystem client uses this API to deregister a mount with rna_service.
 *
 * Arguments:
 *    ctx     The caller's rna_service context, created by
 *            rna_service_ctx_create()
 *    buf     A message buffer that specifies the message to be sent.
 *            NOTES:
 *            1. The rmb_message_type must be
 *               RNA_SERVICE_MESSAGE_TYPE_DEREG_MNT
 *            2. The message buffer must have been allocated by
 *               rna_service_alloc_message_buffer().
 *            3. If no response_callback is specified, the message buf must not
 *               be accessed after this call.  It will be freed by the
 *               rna_service library.
 *               If a response_callback is specified, the message buf must not be
 *               accessed (modified, freed, or re-used) until it is returned as
 *               the 'message_sent' argument of the response callback.
 *    response_callback
 *            Currently, this argument must be NULL.  A response callback is
 *            not yet supported for this function.
 *
 * Returns:
 *    RNA_SERVICE_ERROR_NONE    On success
 *    RNA_SERVICE_ERROR_INVALID_CTX
 *                            Either ctx is NULL or it was not created by
 *                            rna_service_ctx_create().
 *    RNA_SERVICE_ERROR_INVALID_RESPONSE_CALLBACK
 *                            A response callback is not yet supported for
 *                            this function
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE
 *                            The rmb_message_type of 'message' is not
 *                            RNA_SERVICE_MESSAGE_TYPE_DEREG_MNT
 *                            or the message buffer was not allocated as an
 *                            RNA_SERVICE_MESSAGE_TYPE_DEREG_MNT.
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER
 *                            The message buffer specified was not allocated by
 *                            rna_service_alloc_message_buffer() or has not yet
 *                            been returned in a response callback.
 */
extern rna_service_error_t
rna_service_send_mount_deregistration(
                            struct rna_service_ctx_s     *ctx,
                            rna_service_message_buffer_t *buf,
                            rna_service_response_callback response_callback);


/*!
 * A block device client uses this API to register a block device with
 * rna_service.
 *
 * Arguments:
 *    ctx     The caller's rna_service context, created by
 *            rna_service_ctx_create()
 *    buf     A message buffer that specifies the message to be sent.
 *            NOTES:
 *            1. The rmb_message_type must be
 *               RNA_SERVICE_MESSAGE_TYPE_REG_BLKDEV
 *            2. The message buffer must have been allocated by
 *               rna_service_alloc_message_buffer().
 *            3. If no response_callback is specified, the message buf must not
 *               be accessed after this call.  It will be freed by the
 *               rna_service library.
 *               If a response_callback is specified, the message buf must not
 *               be accessed (modified, freed, or re-used) until it is returned
 *               as the 'message_sent' argument of the response callback.
 *    response_callback
 *            If non-NULL, the callback routine that will be invoked either
 *            when a response to this message is received or when the response
 *            times out (if the user has specified a response timeout).
 *
 * Returns:
 *    RNA_SERVICE_ERROR_NONE    On success
 *    RNA_SERVICE_ERROR_INVALID_CTX
 *                            Either ctx is NULL or it was not created by
 *                            rna_service_ctx_create().
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE
 *                            The rmb_message_type of 'message' is not
 *                            RNA_SERVICE_MESSAGE_TYPE_REG_BLKDEV
 *                            or the message buffer was not allocated as an
 *                            RNA_SERVICE_MESSAGE_TYPE_REG_BLKDEV.
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER
 *                            The message buffer specified was not allocated by
 *                            rna_service_alloc_message_buffer() or has not yet
 *                            been returned in a response callback.
 */
extern rna_service_error_t
rna_service_send_block_device_registration(
                            struct rna_service_ctx_s     *ctx,
                            rna_service_message_buffer_t *buf,
                            rna_service_response_callback response_callback);

/*!
 * A block device client uses this API to deregister a block device with
 * rna_service.
 *
 * Arguments:
 *    ctx     The caller's rna_service context, created by
 *            rna_service_ctx_create()
 *    buf     A message buffer that specifies the message to be sent.
 *            NOTES:
 *            1. The rmb_message_type must be
 *               RNA_SERVICE_MESSAGE_TYPE_DEREG_BLKDEV
 *            2. The message buffer must have been allocated by
 *               rna_service_alloc_message_buffer().
 *            3. If no response_callback is specified, the message buf must not
 *               be accessed after this call.  It will be freed by the
 *               rna_service library.
 *               If a response_callback is specified, the message buf must not
 *               be accessed (modified, freed, or re-used) until it is returned
 *               as the 'message_sent' argument of the response callback.
 *
 * Returns:
 *    RNA_SERVICE_ERROR_NONE    On success
 *    RNA_SERVICE_ERROR_INVALID_CTX
 *                            Either ctx is NULL or it was not created by
 *                            rna_service_ctx_create().
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE
 *                            The rmb_message_type of 'message' is not
 *                            RNA_SERVICE_MESSAGE_TYPE_DEREG_BLKDEV
 *                            or the message buffer was not allocated as an
 *                            RNA_SERVICE_MESSAGE_TYPE_DEREG_BLKDEV.
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER
 *                            The message buffer specified was not allocated by
 *                            rna_service_alloc_message_buffer() or has not yet
 *                            been returned in a response callback.
 */
extern rna_service_error_t
rna_service_send_block_device_deregistration(
                            struct rna_service_ctx_s     *ctx,
                            rna_service_message_buffer_t *buf);

extern rna_service_error_t
rna_service_send_notification_event(
                            struct rna_service_ctx_s     *ctx,
                            rna_service_message_buffer_t *buf);

/*!
 * A block device client uses this API to send a block device control response with
 * rna_service.
 *
 * Arguments:
 *    ctx     The caller's rna_service context, created by
 *            rna_service_ctx_create()
 *    buf     A message buffer that specifies the message to be sent.
 *            NOTES:
 *            1. The rmb_message_type must be
 *               RNA_SERVICE_MESSAGE_TYPE_CONTROL_BLKDEV_RESPONSE
 *            2. The message buffer must have been allocated by
 *               rna_service_alloc_message_buffer().
 *            3. If no response_callback is specified, the message buf must not
 *               be accessed after this call.  It will be freed by the
 *               rna_service library.
 *               If a response_callback is specified, the message buf must not
 *               be accessed (modified, freed, or re-used) until it is returned
 *               as the 'message_sent' argument of the response callback.
 *
 * Returns:
 *    RNA_SERVICE_ERROR_NONE  On success
 *    RNA_SERVICE_ERROR_INVALID_CTX
 *                            Either ctx is NULL, or it is in the process of
 *                            shutting down (rna_service_ctx_destroy() has been
 *                            called), or it was not created by
 *                            rna_service_ctx_create().
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE
 *                            The rmb_message_type of 'message' is not
 *                            RNA_SERVICE_MESSAGE_TYPE_CONTROL_BLKDEV_RESPONSE
 *                            or the message buffer was not allocated as an
 *                            RNA_SERVICE_MESSAGE_TYPE_CONTROL_BLKDEV_RESPONSE.
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER
 *                            The message buffer specified was not allocated by
 *                            rna_service_alloc_message_buffer() or has not yet
 *                            been returned in a response callback.
 */
extern rna_service_error_t
rna_service_send_block_device_control_response(
                            struct rna_service_ctx_s     *ctx,
                            rna_service_message_buffer_t *buf);

/*!
 * A cache server uses this API to send a control response with
 * rna_service.
 *
 * Arguments:
 *    ctx     The caller's rna_service context, created by
 *            rna_service_ctx_create()
 *    buf     A message buffer that specifies the message to be sent.
 *            NOTES:
 *            1. The rmb_message_type must be
 *               RNA_SERVICE_MESSAGE_TYPE_CONTROL_CS_RESPONSE
 *            2. The message buffer must have been allocated by
 *               rna_service_alloc_message_buffer().
 *            3. If no response_callback is specified, the message buf must not
 *               be accessed after this call.  It will be freed by the
 *               rna_service library.
 *               If a response_callback is specified, the message buf must not
 *               be accessed (modified, freed, or re-used) until it is returned
 *               as the 'message_sent' argument of the response callback.
 *
 * Returns:
 *    RNA_SERVICE_ERROR_NONE  On success
 *    RNA_SERVICE_ERROR_INVALID_CTX
 *                            Either ctx is NULL, or it is in the process of
 *                            shutting down (rna_service_ctx_destroy() has been
 *                            called), or it was not created by
 *                            rna_service_ctx_create().
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE
 *                            The rmb_message_type of 'message' is not
 *                            RNA_SERVICE_MESSAGE_TYPE_CONTROL_CS_RESPONSE
 *                            or the message buffer was not allocated as an
 *                            RNA_SERVICE_MESSAGE_TYPE_CONTROL_CS_RESPONSE.
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER
 *                            The message buffer specified was not allocated by
 *                            rna_service_alloc_message_buffer() or has not yet
 *                            been returned in a response callback.
 */
extern rna_service_error_t
rna_service_send_control_cs_response(
                            struct rna_service_ctx_s     *ctx,
                            rna_service_message_buffer_t *buf);

/*!
 * A client uses this API to register a connection to a service with
 * rna_service.
 *
 * Arguments:
 *    ctx     The caller's rna_service context, created by
 *            rna_service_ctx_create()
 *    buf     A message buffer that specifies the message to be sent.
 *            NOTES:
 *            1. The rmb_message_type must be
 *               RNA_SERVICE_MESSAGE_TYPE_REG_SVC_CONN
 *            2. The message buffer must have been allocated by
 *               rna_service_alloc_message_buffer().
 *            3. The message buf must not be accessed after this call.
 *               It will be freed by the rna_service library.
 *
 * Returns:
 *    RNA_SERVICE_ERROR_NONE  On success
 *    RNA_SERVICE_ERROR_INVALID_CTX
 *                            Either ctx is NULL, or it is in the process of
 *                            shutting down (rna_service_ctx_destroy() has been
 *                            called), or it was not created by
 *                            rna_service_ctx_create().
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE
 *                            The rmb_message_type of 'message' is not
 *                            RNA_SERVICE_MESSAGE_TYPE_REG_SVC_CONN
 *                            or the message buffer was not allocated as an
 *                            RNA_SERVICE_MESSAGE_TYPE_REG_SVC_CONN.
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER
 *                            The message buffer specified was not allocated by
 *                            rna_service_alloc_message_buffer() or has not yet
 *                            been returned in a response callback.
 */
extern rna_service_error_t
rna_service_send_svc_conn_registration(
                                       struct rna_service_ctx_s     *ctx,
                                       rna_service_message_buffer_t *buf);


/*!
 * A client uses this API to register a connection to a service with
 * rna_service.
 *
 * Arguments:
 *    ctx     The caller's rna_service context, created by
 *            rna_service_ctx_create()
 *    buf     A message buffer that specifies the message to be sent.
 *            NOTES:
 *            1. The rmb_message_type must be
 *               RNA_SERVICE_MESSAGE_TYPE_DEREG_SVC_CONN
 *            2. The message buffer must have been allocated by
 *               rna_service_alloc_message_buffer().
 *            3. The message buf must not be accessed after this call.
 *               It will be freed by the rna_service library.
 *
 * Returns:
 *    RNA_SERVICE_ERROR_NONE  On success
 *    RNA_SERVICE_ERROR_INVALID_CTX
 *                            Either ctx is NULL, or it is in the process of
 *                            shutting down (rna_service_ctx_destroy() has been
 *                            called), or it was not created by
 *                            rna_service_ctx_create().
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE
 *                            The rmb_message_type of 'message' is not
 *                            RNA_SERVICE_MESSAGE_TYPE_DEREG_SVC_CONN
 *                            or the message buffer was not allocated as an
 *                            RNA_SERVICE_MESSAGE_TYPE_DEREG_SVC_CONN.
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER
 *                            The message buffer specified was not allocated by
 *                            rna_service_alloc_message_buffer() or has not yet
 *                            been returned in a response callback.
 */
extern rna_service_error_t
rna_service_send_svc_conn_deregistration(
                            struct rna_service_ctx_s     *ctx,
                            rna_service_message_buffer_t *buf);


/*!
 * Send a cfm client event message to the configuration manager.
 *
 * Arguments:
 *    ctx     The caller's rna_service context, created by
 *            rna_service_ctx_create()
 *    buf     A message buffer that specifies the message to be sent.
 *            NOTES:
 *            1. The rmb_message_type must be
 *               RNA_SERVICE_MESSAGE_TYPE_CLIENT_EVENT.
 *            2. The message buffer must have been allocated by
 *               rna_service_alloc_message_buffer().
 *            3. If this routine returns RNA_SERVICE_ERROR_NONE, then the
 *               message buf must not be accessed after this call, since
 *               it will be freed by the rna_service library.
 *               Otherwise, the caller is responsible for freeing the message
 *               buffer.
 *
 * Returns:
 *    RNA_SERVICE_ERROR_NONE    On success
 *    RNA_SERVICE_ERROR_INVALID_CTX
 *                            Either ctx is NULL or it was not created by
 *                            rna_service_ctx_create().  The caller must free
 *                            'buf'.
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE
 *                            The rmb_message_type of 'message' is not
 *                            RNA_SERVICE_MESSAGE_TYPE_CLIENT_EVENT
 *                            or the message buffer was not allocated as an
 *                            RNA_SERVICE_MESSAGE_TYPE_CLIENT_EVENT.
 *                            The caller must free 'buf'.
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER
 *                            The message buffer specified was not allocated by
 *                            rna_service_alloc_message_buffer() or has not yet
 *                            been returned in a response callback.  The caller
 *                            must free 'buf'.
 */
extern rna_service_error_t
rna_service_send_client_event(struct rna_service_ctx_s     *ctx,
                              rna_service_message_buffer_t *buf);


/*!
 * Send a block device stats message to the configuration manager.
 *
 * Arguments:
 *    ctx     The caller's rna_service context, created by
 *            rna_service_ctx_create()
 *    buf     A message buffer that specifies the message to be sent.
 *            NOTES:
 *            1. The rmb_message_type must be
 *               RNA_SERVICE_MESSAGE_TYPE_BSTAT_RESPONSE.
 *            2. The message buffer must have been allocated by
 *               rna_service_alloc_message_buffer().
 *            3. If this routine returns RNA_SERVICE_ERROR_NONE, then the
 *               message buf must not be accessed after this call, since
 *               it will be freed by the rna_service library.
 *               Otherwise, the caller is responsible for freeing the message
 *               buffer.
 *
 * Returns:
 *    RNA_SERVICE_ERROR_NONE    On success
 *    RNA_SERVICE_ERROR_INVALID_CTX
 *                            Either ctx is NULL or it was not created by
 *                            rna_service_ctx_create().  The caller must free
 *                            'buf'.
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE
 *                            The rmb_message_type of 'message' is not
 *                            RNA_SERVICE_MESSAGE_TYPE_BSTAT_RESPONSE
 *                            or the message buffer was not allocated as an
 *                            RNA_SERVICE_MESSAGE_TYPE_BSTAT_RESPONSE.
 *                            The caller must free 'buf'.
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER
 *                            The message buffer specified was not allocated by
 *                            rna_service_alloc_message_buffer() or has not yet
 *                            been returned in a response callback.  The caller
 *                            must free 'buf'.
 */
extern rna_service_error_t
rna_service_send_block_device_stats(struct rna_service_ctx_s     *ctx,
                                    rna_service_message_buffer_t *buf);


/**
 * Convert a metadata query message (RNA_SERVICE_MESSAGE_TYPE_MD_QUERY)
 * and its response (RNA_SERVICE_MESSAGE_TYPE_MD_QUERY_RESPONSE) into a cache
 * query (CACHE_QUERY).
 *
 * This function is temporary, and is to be used only until rna_service
 * supports client/cache-server communication.
 *
 * Arguments:
 *  message_sent    The metadata server query message that was sent
 *                  (RNA_SERVICE_MESSAGE_TYPE_MD_QUERY)
 *  response        The response to the above message that was received from a
 *                  metadata server (RNA_SERVICE_MESSAGE_TYPE_MD_QUERY_RESPONSE)
 *  buf             The struct cache_cmd buffer in which the CACHE_QUERY
 *                  message should be built.
 *
 * Returns:
 *    RNA_SERVICE_ERROR_NONE  on success
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER
 *                            Either 'message_sent' or 'response' is corrupt,
 *                            or 'message_sent', 'response', or 'cmd' is NULL,
 *                            or 'message_sent' is not of type
 *                            RNA_SERVICE_MESSAGE_TYPE_MD_QUERY,
 *                            or 'response' is not of type
 *                            RNA_SERVICE_MESSAGE_TYPE_MD_QUERY_RESPONSE.
 */    
extern rna_service_error_t
rna_service_convert_md_rep_to_cache_query(
                                rna_service_message_buffer_t *message_sent,
                                rna_service_message_buffer_t *response,
                                void *buf);

/**
 * Send the specified message to the appropriate MD and invoke the specified
 * callback when a response arrives.
 *
 * Arguments:
 *    ctx     The caller's rna_service context, created by
 *            rna_service_ctx_create()
 *    message A message buffer containing the message to be sent.
 *            NOTES:
 *
 *            1. The message buffer must have been allocated by
 *               rna_service_alloc_message_buffer(), specifying the
 *               msg_type argument with the value appropriate for the
 *               intended action.
 *
 *            2. rna_service_alloc_message_buffer() will store the msg_type
 *               argument into the message buffer (message->h.rmb_message_type).
 *               The following message types are supported by this function:
 *                   RNA_SERVICE_MESSAGE_TYPE_MD_QUERY
 *                   RNA_SERVICE_MESSAGE_TYPE_CACHE_INVD
 *                   RNA_SERVICE_MESSAGE_TYPE_CACHE_MASTER_INVD
 *                   RNA_SERVICE_MESSAGE_TYPE_CACHE_RESPONSE
 *                   RNA_SERVICE_MESSAGE_TYPE_CACHE_QUERY_REQUEST
 *                   RNA_SERVICE_MESSAGE_TYPE_RELOCATE_BLOCK
 *                   RNA_SERVICE_MESSAGE_TYPE_ABSORB_BLOCK
 *                   RNA_SERVICE_MESSAGE_TYPE_INVD_HOLD_RESPONSE
 *
 *    response_callback
 *
 *            If non-NULL, the callback routine that will be invoked either
 *            when a response to this message is received or when the response
 *            times out (if the user has specified a response timeout).
 *            The message must not be accessed until it is returned as the
 *            'message_sent' argument of the response callback.
 *
 *            If no response_callback (NULL) is specified, the message must not
 *            be accessed after this call.  It will be freed by the
 *            rna_service library.
 *
 * Returns:
 *    return value from send_md_generic()
 *    RNA_SERVICE_ERROR_INVALID_CTX
 *                            Either ctx is NULL or it was not created by
 *                            rna_service_ctx_create().
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE
 *                            The rmb_message_type of 'message' is not a type
 *                            supported by this function or the message buffer
 *                            was not allocated with the same type
 *                            (rna_service_alloc_message_buffer specified a
 *                            message type that differs from what's stored in
 *                            message->h.rmb_message_type).  The following
 *                            message types are supported:
 *                                RNA_SERVICE_MESSAGE_TYPE_MD_QUERY
 *                                RNA_SERVICE_MESSAGE_TYPE_CACHE_INVD
 *                                RNA_SERVICE_MESSAGE_TYPE_CACHE_MASTER_INVD
 *                                RNA_SERVICE_MESSAGE_TYPE_CACHE_RESPONSE
 *                                RNA_SERVICE_MESSAGE_TYPE_CACHE_QUERY_REQUEST
 *                                RNA_SERVICE_MESSAGE_TYPE_RELOCATE_BLOCK
 *                                RNA_SERVICE_MESSAGE_TYPE_ABSORB_BLOCK
 *                                RNA_SERVICE_MESSAGE_TYPE_INVD_HOLD_RESPONSE
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER
 *                            The message buffer specified was not allocated by
 *                            rna_service_alloc_message_buffer() or has not yet
 *                            been returned in a response callback.
 *
 *    RNA_SERVICE_ERROR_MAX_OUTSTANDING_EXCEEDED
 *                            Sending this message would have caused the
 *                            limit on the maximum number of outstanding
 *                            messages to be exceeded.
 */
extern rna_service_error_t
rna_service_send_md(struct rna_service_ctx_s     *ctx,
                    rna_service_message_buffer_t *message,
                    rna_service_response_callback response_callback);

extern rna_service_error_t
rna_service_send_md_nomaxcheck(struct rna_service_ctx_s     *ctx,
                               rna_service_message_buffer_t *message,
                               rna_service_response_callback response_callback);

/* -------------------- Primary CFM ID --------------------- */

/*
 * Identification information for the primary CFM.  Filled in only if the sender
 * believes it's the primary CFM.
 */
typedef struct primary_cfm_id_s {
    uint64_t       pci_generation; /**< primary cfm generation number */
    struct in_addr pci_addr;       /**< primary cfm identifying address */
} primary_cfm_id_t;

INLINE void bswap_primary_cfm_id_t(primary_cfm_id_t *data)
{
	UNREFERENCED_PARAMETER(data);
#if CPU_BE
    data->pci_generation = bswap_64(data->pci_generation);
    // data->pci_addr = bswap_64(data->pci_addr);
#endif
}

/**
 * Return the current primary CFM ID.
 *
 * Arguments:
 *    ctx     The caller's rna_service context, created by
 *            rna_service_ctx_create()
 */
extern primary_cfm_id_t *
rna_service_primary_cfm_id(struct rna_service_ctx_s *ctx);

/* ----------------------------- Strings ---------------------------------- */

/*!
 * Return the string representation for the specified rna_service_error_t,
 * for use in log messages.
 */
extern const char *
rna_service_get_error_string(rna_service_error_t error);

/*!
 * Return the string representation for the specified cache_req_type_t,
 * for use in log messages.
 */
extern const char *
get_cache_req_type_string(cache_req_type_t type);

/*!
 * Return the string representation for the specified
 * rna_service_event_t, for use in log messages.
 */
extern const char *
rna_service_get_event_type_string(rna_service_event_t event);

/*!
 * Return the string representation for the specified cache_lock_t,
 * for use in log messages.
 */
extern const char *
get_lock_type_string(cache_lock_t type);

/*!
 * Return the string representation for the specified cache_write_mode_t,
 * for use in log messages.
 */
extern const char *
get_write_mode_string(cache_write_mode_t type);

INLINE const char *
get_write_mode(cache_write_mode_t type)
{
    return(get_write_mode_string(type));
}

/*!
 * Return the string representation for the specified cache_commit_mode_t,
 * for use in log messages.
 */
extern const char *
get_cache_commit_mode_string(cache_commit_mode_t mode);


/*!
 * Return the string representation for the specified cache_invd_mode_t,
 * for use in log messages.
 */
extern const char *
get_cache_invd_mode_string(cache_invd_mode_t mode);


/*!
 * Return the string representation for the specified cache_error_persistence_t,
 * for use in log messages.
 */
extern const char *
get_cache_error_persistence_string(cache_error_persistence_t mode);


/*!
 * Return the string representation for the specified cache_evict_policy_t,
 * for use in log messages.
 */
extern const char *
get_cache_evict_policy_string(cache_evict_policy_t policy);


/*!
 * Return the string representation for the specified
 * rna_service_message_type_t, for use in log messages.
 */
extern const char *
rna_service_get_message_type_string(rna_service_message_type_t type);


/*!
 * Return the string representation for the specified
 * rna_service_client_control_t, for use in log messages.
 */
extern const char *
rna_service_get_client_control_type_string(rna_service_client_control_t type);


/*!
 * Dump information about all rna_service communication connections in XML.
 */
extern int
rna_service_dump_all_connection_info_xml(struct rna_service_ctx_s *ctx,
                                         void                     *info_file);

/*!
 * Dump information about all md communication connections in XML.
 */
extern int
rna_service_dump_md_eph_xml(struct rna_service_ctx_s *ctx,
                            void *info_file);

/*!
 * Dump information about all rna_service communication connections.
 */
extern int
rna_service_dump_all_connection_info(struct rna_service_ctx_s *ctx,
                                     void                     *info_file);


/*!
 * Add the connection status for each configuration manager and metadata
 * server to the specified sprintf buffer.  On return, the specified buffer
 * pointer is incremented to account for the information added to the buffer.
 *
 * Returns:
 *    RNA_SERVICE_ERROR_NONE    On success
 *    RNA_SERVICE_ERROR_INVALID_CTX
 *                            Either ctx is NULL or it was not created by
 *                            rna_service_ctx_create().  The caller must free
 *                            'buf'.
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER
 *                            The specified buffer is NULL.
 */
extern rna_service_error_t
rna_service_sprintf_connection_status(struct rna_service_ctx_s  *ctx,
                                      char                     **p);

/*!
 * Read a string passed in as the first argument, in the form "a.b.c.d:p:t"
 * where "a.b.c.d" is an IP address, "p" is a port number and "t" is the
 * transport type.  The port and/or transport type may be omitted, and may 
 * be specified in reverse order, though the ip address must come first.
 * Port_ptr and com_type may be NULL.  If non-NULL, the caller should 
 * set them to a reasonable default before calling parse_ip_addr.
 *
 * Returns: 0 on success, nonzero otherwise.
 *
 * If "rest" is non-NULL, we make it point to the remainder of the string
 * (In case we want to parse multiple whitespace-separated cfm addresses 
 * out of one string.)
 */
extern int
rna_service_parse_ip_addr(char *ip, uint32_t *addr, uint16_t *port_ptr, 
                          int *com_type, char **rest);

/*!
 * External routine to provide a string which represents the com_type.
 * Used only for CFM configuration IP address decoration.
 * TCP is the presumed default com_type.
 *
 * Arguments:
 *    type     Preferred transport com_type
 *
 * Returns:
 *    String to use to decorate CFM address for configuration.
 */
extern char *
rna_service_com_type_string(int type);

/*!
 * Send the specified oms event to the configuration manager.
 *
 * The variable argument list consists of pairs of
 * arg_type_t and corresponding data value.  The last
 * argument must be a ARG_TYPE_END to terminate processing
 * of the va_list.
 *
 * See arg_type_t in event_log.h for supported argument types.
 *
 * Returns:
 *    0 on success
 *    Non-zero on failure
 */
int
rna_service_send_oms_event_to_cfm(struct rna_service_ctx_s *ctx,
        uint32_t event_id, ...);

#if defined(LINUX_USER) || defined(WINDOWS_USER)
/*!
 * Output the specified oms event from the configuration manager.
 *
 * This code is intended to only be called from the CFM.
 * All others should call rna_service_send_oms_event_to_cfm.
 *
 * Once the event data has been processed, 'cmd' arg is called
 * to actually write it to the cfm event log.
 *
 * The variable argument list consists of pairs of
 * arg_type_t and corresponding data value.  The last
 * argument must be a ARG_TYPE_END to terminate processing
 * of the va_list.
 *
 * Returns:
 *    0 on success
 *    Non-zero on failure
 */
struct rna_event;
typedef int (*cfm_event_cmd) (com_ep_handle_t *eph,
                              rna_service_event_msg_t *evt);
int
rna_service_oms_event_from_cfm(cfm_event_cmd cmd,
        uint32_t event_id, ...);
#endif

/* ----------------------------- Memory pools ---------------------------------- */


/**
 * A list element, for use in a memory pool.
 */
typedef struct list_element_s {
    struct list_element_s *le_next;
} list_element_t;

typedef struct rna_service_throttle_s {
    rna_service_spinlock_t  thr_spinlock;
    int                     thr_nwaiters;
    rna_service_wait_obj    thr_wait;
    int                     thr_cur_limit;  // current ops limit
    int                     thr_min_limit;  // minimum value of cur_limit
    int                     thr_max_limit;  // maximum value of cur_limit
    int                     thr_n_active;   // ops currently active
} rna_service_throttle_t;


extern int rna_service_throttle_init(rna_service_throttle_t *throttle,
                          int                    initial_limit,
                          int                    min_limit,
                          int                    max_limit);
extern void rna_service_throttle_destroy(rna_service_throttle_t *throttle);
extern int rna_service_throttle_register(rna_service_throttle_t *throttle,
                              int        n_registrations,
                              int64_t    timeout);
extern void rna_service_throttle_deregister(rna_service_throttle_t *throttle,
                                            int n_registrations);
extern void rna_service_throttle_change_limit(rna_service_throttle_t *throttle,
                                  int new_limit);

/**
 * A pool of structs.  Allocations are first from the pre-allocated pool, then,
 * if that is empty, from dynamic allocation, and then, if that fails, from the
 * 'reserve' portion of the pre-allocated pool.
 *
 *  Note: When mp_no_dynamic is specified, and rna_service_mempool_init()
 *        is unable to allocate the entire pool as a contiguous allocation,
 *        it will fall back on allocating the elements as individual
 *        allocations.  This scenario can be identified because in that
 *        case, 'mp_begin' will be NULL but 'mp_end' will be set.
 *        (For that case, we use 'mp_end' as list head to track a linked
 *        chain of the individually allocated elements.)
 */
typedef struct rna_service_mempool_s {
    void           *mp_begin;   /*! Starting address of the memory block
                                 *  comprising this memory pool.
                                 */
    void           *mp_end;     /*! Ending address + 1 of the memory block
                                 *  comprising this memory pool.
                                 */
    int             mp_no_dynamic;
                                /*! Disallow dynamic allocation for this pool */
    int             mp_element_size;
                                /*! Size of an element in this memory pool */
    int             mp_memset_size;
                                /*! The portion of the above element size that
                                 *  should be zero'd on allocation.
                                 */
    int             mp_num_reserved;
                                /*! Number of objects from the pre-allocated
                                 *  pool that are reserved for use only when
                                 *  dynamic allocation fails.
                                 */
    int             mp_avail_count;
                                /*! Number of objects available to be allocated
                                 *  from the pre-allocated mp_avail pool.
                                 */
    int             mp_nwaiters;
                                /*! Number of waiters blocked on mp_wait */
    atomic_t        mp_alloc_count;
                                /*! Number of objects currently allocated.
                                 *  Includes both those allocated from the
                                 *  pre-allocated pool and those dynamically
                                 *  allocated.
                                 */
    rna_service_spinlock_t
                    mp_spinlock;/*! Spinlock to guard mp_avail */
    list_element_t *mp_avail;   /*! List of available structures in this
                                 *  memory pool
                                 */
    rna_service_wait_obj
                    mp_wait;    /* wait obj used for threads waiting on entry */
} rna_service_mempool_t;


/**
 * Initialize a memory pool.
 */
int
rna_service_mempool_init(rna_service_mempool_t *mempool,
                         int                    element_size,
                         int                    memset_size,
                         int                    num_elements,
                         int                    num_reserved,
                         int                    no_dynamic_allocation);

/**
 * Tear-down and free a memory pool.
 *
 * Arguments:
 *     mempool  Pointer to the mempool that should be torn down.
 */
void
rna_service_mempool_destroy(rna_service_mempool_t *mempool,
                            void (leakchk)(void *));


/**
 * Allocate an item from a memory pool.
 *
 * Arguments:
 *  mempool     Pointer to the mempool that the allocation should be done from
 *  dynamic_alloc_reduction
 *              If this routine must fall back to dynamic allocation because
 *              no items are available for allocation from the pre-allocated
 *              pool, this argument specifies the reduction in size from the
 *              mempool's element size that should be used (so, the allocate
 *              size will be this mempool's element size -
 *              dynamic_alloc_reduction).  This parameter is non-zero if the
 *              item is variable-sized, perhaps because it ends with a
 *              variable-length pathname.  While pre-allocated elements must be
 *              maximally sized to fit any pathname, a dynamically-allocated
 *              item can be smaller, since only a specific string must fit.
 */
void *
rna_service_mempool_alloc(rna_service_mempool_t *mempool,
                          size_t                 dynamic_alloc_reduction);


/**
 * Allocate an item from a fixed-size memory pool, blocking if needed
 * up to a specified timeout period.
 *
 * Arguments:
 *  mempool     Pointer to the mempool that the allocation should be done from
 *  alloc_timeout
 *              Amount of time to wait (in jiffies) for an item to be available
 *              for allocation.
 *              Any value less than 1 indicates that we will not wait at all.
 *  ret_ptr     Pointer to the allocated memory(on success)
 */
int
rna_service_mempool_alloc_timed(rna_service_mempool_t *mempool,
                                int64_t               alloc_timeout,
                                void                  **ret_ptr);


/**
 * Free an item to a memory pool.
 */
void
rna_service_mempool_free(rna_service_mempool_t *mempool,
                         void                  *item);

/**
 * Controls the decision to allow migration by blocking
 * the relocate_block request from CS to MD. It can be enable if
 * clientaffinity is not selected.
 */
#if defined(_CACHE_BLOCK_MIGRATION_)
#define CACHE_BLOCK_MIGRATION TRUE
#else
#define CACHE_BLOCK_MIGRATION FALSE
#endif

/*!
 * Update cfm addresses in rna_service context, to be used by kernel module
 * that may not have connection to primary cfm to get promotion notices.
 *
 * Returns:
 *    RNA_SERVICE_ERROR_NONE  On success
 *    RNA_SERVICE_ERROR_INVALID_PARAMS
 *                            One or more of the specified parameters is invalid
 */
extern rna_service_error_t
rna_service_cfms_update(uint32_t                   cfm_count,
                        struct sockaddr_in        *cfm_addrs,
                        struct rna_service_ctx_s  *ctxp);

#endif // _RNA_SERVICE_H_
