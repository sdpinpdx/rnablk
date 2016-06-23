/**
 * <rna_service.c> - Dell Fluid Cache block driver
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

#include "platform.h"

CODE_IDENT("$URL: https://svn.rnanetworks.com/full/tags/HERMES_2_1_0_RC1/common/rna_service.c $ $Id: rna_service.c 48951 2016-02-18 19:16:42Z jroy $")

#include "platform_network.h"

#ifdef LINUX_KERNEL
#include "../com/rna_com_linux_kernel.h"
#elif defined (LINUX_USER) || defined (WINDOWS_USER)
#include "com.h"
#elif defined (WINDOWS_KERNEL)
#include "..\RNA_StorPortVirtualMiniport\RNA_StorPortVirtualMiniport\inc\rna_vsmp.h" // needed for pHW_HBA_EXT knowledge
#include <ctype.h>
#include "rna_com_status.h"
#endif

#ifdef WINDOWS_KERNEL
#ifdef  WPP_TRACING_ENABLED
#include "wpptrace.h"
#include "rna_service.tmh"  // For WPP and ETW tracing
#endif /* WPP_TRACING_ENABLED */
#endif /* WINDOWS_KERNEL */

#include "rna_common_logging.h"

#include "protocol.h"
#include "event_log.h"
#include "rna_service.h"
#include "rna_service_cs_md.h"
#include "md5.h"


#if defined (LINUX_KERNEL) || defined (WINDOWS_KERNEL)

#include "rna_service_kernel.h"
#include "rna_hash_common.h"

#elif defined(LINUX_USER) || defined(WINDOWS_USER)
#include "rna_service_user.h"
#endif

#include "queue.h"
#include "meta_data.h"


#ifdef LINUX_KERNEL
/*
 *  Instantiate printk level here if kernel to pull into module correctly.
 *
 */
int rna_printk_level = 4;
module_param(rna_printk_level, int, 0444);
MODULE_PARM_DESC(rna_printk_level,
                 "Printk level for rnacache; set to 7 for everything or "         
                 "0 for only KERN_EMERG.  Default is 4, which prints "  
                 "only (KERN_WARNING) or higher.  Set to -1 to use the "
                 "kernel's standard printk settings.");


int rna_verbosity = 0;
module_param(rna_verbosity, int, 0);
MODULE_PARM_DESC(rna_verbosity,
                 "Initial verbosity level (0 or 1; defaults to "
                 "0, which is Quiet)");

#endif /*LINUX_KERNEL */

#ifdef WINDOWS_KERNEL
# define PF_INET    ((ADDRESS_FAMILY)AF_INET)     /* protocol family != address family, but close enough */
#endif /* WINDOWS_KERNEL */

/* =============================== Constants =============================== */
// XXX: make these configurable?

static const time_t
RNA_SERVICE_RECONNECT_INTERVAL = 10;// Retry reconnect interval (seconds) 

static const time_t
RNA_SERVICE_CFM_RESEND_INTERVAL = 2;// Interval to retry failed CFM sends
                                    // (seconds)

static const time_t
RNA_SERVICE_CFM_REGISTRATION_TIMEOUT = 60;// Primary cfm registration timeout
                                       // (seconds) 

static const time_t
RNA_SERVICE_CS_CFM_REGISTRATION_TIMEOUT = 1;// CS to Primary cfm registration timeout
                                       // (seconds) 
static const int
RNA_SERVICE_CFM_SEND_BUFS = 128;    // Number of send buffers per
                                    // configuration manager connection
static const int
RNA_SERVICE_CFM_RECV_BUFS = 128;    // Number of receive buffers
                                    // per configuration manager connection

/* 
 * Since RNABLK_IOS_POOL_SIZE maxes out at 1024, we should only need that many
 * client-MD buffers.
 */
static const int
RNA_SERVICE_CLIENT_MD_SEND_BUFS = 1024;
                                    // For client users, the number of send
                                    // buffers per metadata server connection
static const int
RNA_SERVICE_CLIENT_MD_RECV_BUFS = 1024;
                                    // For client users, the number of receive
                                    // buffers per metadata server connection
static const int
RNA_SERVICE_CS_MD_SEND_BUFS = 1024;
                                    // For cache server users, number of send
                                    // buffers per metadata server connection
static const int
RNA_SERVICE_CS_MD_RECV_BUFS = 1024;
                                    // For cache server users, number of receive
                                    // buffers per metadata server connection
static const int
RNA_SERVICE_CFM_CONNECT_WORK_QUEUE_THREADS = 1;
                                    // Number of threads for establishing CFM
                                    // connections
static const int
RNA_SERVICE_CFM_WORK_QUEUE_THREADS = 1;
                                    // Number of threads servicing response
                                    // messages from the configuration manager
static const int
RNA_SERVICE_CONTROL_CS_WORK_QUEUE_THREADS = 1;
                                    // Number of threads servicing
                                    // RNA_SERVICE_MESSAGE_TYPE_CONTROL_CS
                                    // messages from the configuration manager
static const int
RNA_SERVICE_MD_WORK_QUEUE_THREADS = 3;
                                    // Number of threads servicing MD work
static const int
RNA_SERVICE_CALLBACK_WORK_QUEUE_THREADS = 1;
                                    // Number of threads servicing invocations
                                    // of callback functions
static const int
RNA_SERVICE_WORK_QUEUE_SIZE = 1;    // Starting/minimum work queue depth

/*
 * Per-struct memory pool sizes
 */
/* Number of invoke_callback_work_ctx_t */
static const int
MEMPOOL_NUM_ELEMENTS_MD_RESPONSE_WORK_CTX = 20;
static const int
MEMPOOL_NUM_ELEMENTS_MD_RESPONSE_WORK_CTX_RESERVE = 4;
/* Number of cfm_work_ctx_t */
static const int
MEMPOOL_NUM_ELEMENTS_CFM_WORK_CTX = 5;
static const int
MEMPOOL_NUM_ELEMENTS_CFM_WORK_CTX_RESERVE = 1;
/* Number of md_info_t */
static const int
MEMPOOL_NUM_ELEMENTS_MD_INFO = 10;
static const int
MEMPOOL_NUM_ELEMENTS_MD_INFO_RESERVE = 2;
/* message buffer memory pool sizes */
static const int
MEMPOOL_NUM_ELEMENTS_METADATA_QUERY_SEND = 16;
static const int
MEMPOOL_NUM_ELEMENTS_METADATA_QUERY_SEND_RESERVE = 4;
static const int
MEMPOOL_NUM_ELEMENTS_METADATA_QUERY_RESPONSE = 16;
static const int
MEMPOOL_NUM_ELEMENTS_METADATA_QUERY_RESPONSE_RESERVE = 4;
static const int
MEMPOOL_NUM_ELEMENTS_CACHE_INVALIDATE_SEND = 16;
static const int
MEMPOOL_NUM_ELEMENTS_CACHE_INVALIDATE_SEND_RESERVE = 4;
static const int
MEMPOOL_NUM_ELEMENTS_CACHE_INVALIDATE_RESPONSE = 16;
static const int
MEMPOOL_NUM_ELEMENTS_CACHE_INVALIDATE_RESPONSE_RESERVE = 4;
static const int
MEMPOOL_NUM_ELEMENTS_CACHE_RESPONSE = 16;
static const int
MEMPOOL_NUM_ELEMENTS_CACHE_RESPONSE_RESERVE = 4;

static const int
RNA_SERVICE_MSGS_OUTSTANDING_MAX = 4096;
                                    // Maximum number of messages we're willing
                                    // to queue waiting for a response, per
                                    // partition.
static const int
RNA_SERVICE_PREMATURE_MSGS_OUTSTANDING_MAX = 1024;
                                    // Maximum number of messages we're willing
                                    // to queue before the first partition map
                                    // has arrived.
static const int
MD_CONNECT_WAIT_SEC = 5;            // Number of seconds we're willing to wait
                                    // for a connection to be established with
                                    // an MD
static const int
CFM_CONNECT_WAIT_SEC = 5;           // Number of seconds we're willing to wait
                                    // for a connection to be established with
                                    // a CFM

static const int
SEND_WAITING_CFM_MSGS_DELAY_SEC = 1;// Number of seconds to delay before
                                    // running send_waiting_cfm_msgs after a
                                    // failure to get a send buf, etc.

static const int
SEND_WAITING_MD_MSGS_DELAY_SEC = 1; // Number of seconds to delay before
// running send_waiting_md_msgs after a
// failure to get a send buf, etc.

/* counters referenced by linux-kernel/include/rna_common.h */
atomic_t timers_started;
atomic_t timers_stopped;

/* ========================== Private Data Types =========================== */

/*
 * A mark to identify an rna_service_ctx_t that was allocated by
 * rna_service_ctx_create()
 */
#define RNA_SERVICE_CTX_WATERMARK                   0x8406b1d2284b2beULL
/*
 * A mark to identify an rna_service message buffer that was allocated by
 * rna_service_alloc_message_buffer() and is not currently queued.
 */
#define MESSAGE_BUFFER_INTERNAL_WATERMARK_ALLOCATED 0x6519e5caf69e4cd3ULL
/*
 * A mark to identify an rna_service message buffer that was allocated by
 * rna_service_alloc_message_buffer() and is currently queued.
 */
#define MESSAGE_BUFFER_INTERNAL_WATERMARK_QUEUED    0x5f8885010e16f485ULL

/* Number of pre-allocated rna_service message buffers */
#define NUM_PREALLOCATED_MESSAGE_BUFFERS            50


/*
 * Flags used in the cx_partition_flags array in an rnx_service_ctx_t.
 */
typedef enum partition_flags_e {
    PARTITION_FLAG_SEND_TO_NEW_MD           = 0x1,
                            /* Either the MD assigned to this partition
                             * disconnected or this partition was reassigned
                             * to a new MD.  In either case, any messages for
                             * this partition must be (re-)sent to the new MD
                             * when it becomes connected.
                             */
} partition_flags_t;


/**
 * Information about a hash partition.  (As background, the global metadata
 * hash space is divided into equal-sized hash partitions, each of which is
 * assigned to a metadata server.  A given MD is assigned one or more
 * partitions to service).
 */
typedef struct partition_info_s {
    partition_flags_t    pi_partition_flags;
                                    /*! Per-hash-partition flags */
    YAQ_HEAD             pi_waiting_to_send;
                                    /*! Messages for this hash partition that
                                     *  have not yet been sent.
                                     */
    YAQ_HEAD             pi_waiting_for_reply;
                                    /*! Messages for this hash partition that
                                     *  have been sent and are awaiting replies.
                                     */
    int                  pi_msgs_outstanding_cnt;
                                    /*! The number of messages queued in the
                                     *  above two lists.
                                     */
    int                  pi_msgs_preallocated_cnt;
                                    /* ! The number of messages that have
                                     * been given pre-approval to get
                                     * through the OUTSTANDING_MAX test
                                     */
} partition_info_t;


/*
 * Flags used in the cx_md_flags field in an rna_service_ctx_t.
 */
typedef enum ctx_md_flags_e {
    CTX_MD_FLAG_MSGS_OUTSTANDING_OVERFLOWED     = (1 << 0),
                            /* A message queue has overflowed */
    CTX_MD_FLAG_RECONNECT_SCHEDULED             = (1 << 1),
                            /* reconnect_mds has been scheduled on a workq */
    CTX_MD_FLAG_RECONNECT_RESTART               = (1 << 2),
                            /* reconnect_mds needs to restart */
    CTX_MD_FLAG_MUST_SEND_MD_CONNECTION_INFO    = (1 << 3),
                            /* The user is a cache server that's failed to send
                             * at least one MD connect or disconnect info
                             * message to the CFM.
                             */
} ctx_md_flags_t;


/*
 * Flags used in the cx_cfm_flags field in an rna_service_ctx_t.
 */
typedef enum ctx_cfm_flags_e {
    CTX_CFM_FLAG_RECONNECT_SCHEDULED            = (1 << 0),
                            /* reconnect_cfms() has been scheduled on a workq */
    CTX_CFM_FLAG_RECONNECT_RESTART              = (1 << 1),
                            /* reconnect_cfms() needs to restart */
    CTX_CFM_FLAG_RESEND_SCHEDULED               = (1 << 2),
                            /* send_waiting_cfm_msgs() has been scheduled */
    CTX_CFM_FLAG_MUST_REGISTER                  = (1 << 3),
                            /* we're not yet registered with the primary CFM */
    CTX_CFM_FLAG_AWAIT_REGISTRATION_RESPONSE    = (1 << 4),
                            /*
                             * We're waiting for a successful response to our
                             * registration before sending any other messages.
                             * The goal of this is to avoid sending stale
                             * messages if the CS has been expelled.
                             */
    CTX_CFM_FLAG_DETACHED_FROM_CLUSTER          = (1 << 5),
                            /* an RNA_SERVICE_EVENT_DETACHED_FROM_CLUSTER
                             * event has been invoked
                             */
    CTX_CFM_FLAG_DISABLED_HEARTBEAT_TIMER       = (1 << 6),
                            /* there is only one CFM, and it is the primary
                             * and it is local. There is no need for heartbeat
                             */
    CTX_CFM_FLAG_INITIAL_REGISTRATIONS_COMPLETE = (1 << 7),
                            /* The cache server has finished registering cache
                             * devices and replica stores, at least for the
                             * time being.
                             */
    CTX_CFM_FLAG_MUST_SEND_CACHEDEV_REGISTRATION_END
                                                = (1 << 8),
                             /* This flag indicates that a
                              * CONF_MGR_REG_CACHE_DEVICE_END message must be
                              * sent.  This flag is turned on whenever:
                              * (a) CTX_CFM_FLAG_INITIAL_REGISTRATIONS_COMPLETE
                              *     is turned on
                              * (b) a connection is made to a primary CFM (i.e.
                              *     whenever primary_cfm_connected is called and
                              *     CTX_CFM_FLAG_MUST_REGISTER is set) and the
                              *     CTX_CFM_FLAG_INITIAL_REGISTRATIONS_COMPLETE
                              *     flag is set (to deal with (re-)registration
                              *     with a new primary CFM)
                              * (c) a CONF_MGR_REG_CACHE_DEVICE message is sent
                              *     (to deal with the case where a new cache
                              *     device is dynamically added, so a single
                              *     CONF_MGR_REG_CACHE_DEVICE message is sent
                              */
    CTX_CFM_FLAG_INITIAL_REGISTRATION_SENT      = (1 << 9),
                             /* Set if the first registration message has
                              * been sent to the CFM since startup; otherwise
                              * not set.
                              */
    CTX_CFM_FLAG_REGISTRATION_TIMER_SET         = (1 << 10),
                             /* Set when the primary CFM disconnects 
                              * or a registration is sent to the primary
                              * and cleared when registration with the primary
                              * CFM is re-established.
                              * Note that this is only used for user type
                              * RNA_SERVICE_USER_TYPE_CACHE_SERVER.
                              */
    CTX_CFM_FLAG_BLOCK_DEVICES_CREATED          = (1 << 11),
                             /* Set when the first CONF_MGR_BLOCK_DEVICE_CREATE
                              * message is received, indicating that a block
                              * device can be created.
                              */
    CTX_CFM_FLAG_ACTIVATED                      = (1 << 12),
                             /* Set if this is a cache server and it's been
                              * activated by a primary CFM.
                              */
} ctx_cfm_flags_t;

typedef enum mempool_id_e {
    MEMPOOL_ID_MD_RESPONSE_WORK_CTX = 0,
    MEMPOOL_ID_CFM_WORK_CTX,
    MEMPOOL_ID_MD_INFO,
    MEMPOOL_ID_METADATA_QUERY_SEND,
    MEMPOOL_ID_METADATA_QUERY_RESPONSE,
    MEMPOOL_ID_CACHE_INVALIDATE_SEND,
    MEMPOOL_ID_CACHE_INVALIDATE_RESPONSE,
    MEMPOOL_ID_CACHE_RESPONSE,
    MEMPOOL_ID_INVALID,                    // MUST BE LAST
} mempool_id_t;


typedef struct mempool_ele_s {
    struct rna_service_mempool_s *mpe_pool;
    struct mempool_ele_s *mpe_next;
} mempool_ele_t;


/**
 * Information about a configuration manager
 */
typedef struct cfm_info_s {
    com_ep_handle_t            ci_eph;
    rna_service_rdma_info_t    ci_stat_info;
} cfm_info_t;


/*
 * A workq context, for handing waiting messages.
 */
typedef struct send_waiting_msgs_work_ctx_s {
    rna_service_work_t         swx_work_obj;
    struct rna_service_ctx_s  *swx_ctx;
    int                        swx_ordinal;  // MD ordinal (for MD msgs only)
} send_waiting_msgs_work_ctx_t;



/*
 * A workq context, for handing register and deregister
 * mount or blkdev with CFM messages.
 */
typedef struct reg_mnt_blkdev_msg_work_ctx_s {
    rna_service_work_t           swx_work_obj;
    struct rna_service_ctx_s     *swx_ctx;
    rna_service_message_buffer_t *buf;
    boolean                       retry_flag;
} reg_mnt_blkdev_msg_work_ctx_t;



/**
 * Flags for the mdii_flags field in an md_instance_info_t.  These flags are
 * instance-specific, so apply to all connections to a particular instance of
 * an MD (i.e. all connections to an MD having a given rna_service_id).
 */
typedef enum md_instance_info_flags_e {
    MD_INFO_IFLAG_ACTIVATED                    = (1 << 0),
                            /* The MD has been activated by the primary CFM */
    MD_INFO_IFLAG_MUST_SEND_MD_CONNECTION_INFO = (1 << 1),
                            /* Either a connection or disconnection with the
                             * MD needs to be reported to the primary CFM.
                             */
    MD_INFO_IFLAG_SEND_WAITING_MSGS_SCHEDULED  = (1 << 2),
                            /* If set, send_waiting_md_msgs() is scheduled to
                             * run or is running.
                             */
    MD_INFO_IFLAG_CONNECTING                   = (1 << 3),
                            /* If set, a connection to this MD is in the
                             * process of being established.
                             */
} md_instance_info_flags_t;


/**
 * Flags for the mdic_flags field in an md_connection_info_t.  These flags are
 * connection-specific, so apply only to a specific connection (eph) with an
 * MD.
 */
typedef enum md_connection_info_flags_e {
    MD_INFO_CFLAG_CONNECTION_MARKED            = (1 << 0),
    MD_INFO_CFLAG_CONNECTED                    = (1 << 1),
                            /*
                             * This MD connection is live (i.e. it's been
                             * registered with the CFM, etc.)
                             */
    MD_INFO_CFLAG_CONNECTION_FAILED            = (1 << 2),
                            /* Either we (as a CS) failed to connect with this
                             * MD or this connection to the MD has failed.
                             */
    MD_INFO_CFLAG_MUST_REGISTER                = (1 << 3),
                            /* The user is a cache server and it's not yet
                             * registered on this MD connection. (A CS must
                             * re-register after re-connecting).
                             */
    MD_INFO_CFLAG_AWAIT_REGISTRATION_RESPONSE  = (1 << 4),
                            /*
                             * The user is a cache server, and it must wait for
                             * a successful response to its registration before
                             * sending any other messages.  The goal of this is
                             * to avoid sending stale messages if the CS has
                             * been expelled (it's notified if it has been
                             * expelled in the registration response).
                             */
    MD_INFO_CFLAG_PRELIM_DISCONN               = (1 << 5),
                            /*
                             * Early disconnect processing has been done for
                             * this MD connection (but still needs final
                             * disconnection processing).
                             */
    MD_INFO_CFLAG_FINAL_DISCONN                = (1 << 6),
                            /*
                             * Final disconnect processing has been done for
                             * this MD connection.
                             */
} md_connection_info_flags_t;


/**
 * The portion of the information about a metadata server that's specific to
 * the MD instance.  This information applies to all connections to a given
 * MD instance.  An MD instance is identified by its ordinal and/or service ID.
 */
typedef struct md_instance_info_s {
    uint16_t              mdii_ordinal; /* This MD's index in the cx_md_table[]
                                         * of an rna_service_ctx_t.
                                         */
    md_instance_info_flags_t
                          mdii_iflags;
    struct rna_service_id mdii_service_id;
    struct rna_if_table   mdii_if_tbl;  /* Network interfaces available.  */
    uint64_t              mdii_partition_map_generation_sent;
                                        /* The generation number of the last
                                         * partition map sent to this MD.
                                         */
} md_instance_info_t;

/**
 * The portion of the information about a metadata server that's specific to
 * an MD connection.
 */
typedef struct md_connection_info_s {
    com_ep_handle_t       mdic_eph;     /* This ep is valid only if the
                                         * MD_INFO_CFLAG_CONNECTED flag is set
                                         * in mdi_cflags.
                                         */
    md_connection_info_flags_t
                          mdic_cflags;
    /*
     * The following fields are used only if the user of this library is a
     * cache server (RNA_SERVICE_USER_TYPE_CACHE_SERVER).
     */
    rna_service_ping_data_t
                          mdic_ping_data;
    rna_service_ping_context_t
                          mdic_local_ping_ctx;
    rna_service_ping_context_t
                          mdic_remote_ping_ctx;
} md_connection_info_t;

/**
 * Information about a metadata server.
 */
typedef struct md_info_s {
    md_connection_info_t mdi_connection;    // connection-specific information
    md_instance_info_t   mdi_instance;      // instance-specific information
} md_info_t;

#define mdi_eph             mdi_connection.mdic_eph
#define mdi_cflags          mdi_connection.mdic_cflags
#define mdi_ping_data       mdi_connection.mdic_ping_data
#define mdi_local_ping_ctx  mdi_connection.mdic_local_ping_ctx
#define mdi_remote_ping_ctx mdi_connection.mdic_remote_ping_ctx

#define mdi_ordinal         mdi_instance.mdii_ordinal
#define mdi_iflags          mdi_instance.mdii_iflags
#define mdi_service_id      mdi_instance.mdii_service_id
#define mdi_if_tbl          mdi_instance.mdii_if_tbl
#define mdi_partition_map_generation_sent \
                            mdi_instance.mdii_partition_map_generation_sent


/*
 * A container for storing a primary_cfm_id_t.  This is the rna_service version
 * of a primary_cfm_id_container_t.  (rna_service needs it's own version, to
 * deal with the difference between user-level and kernel-level locking, both
 * of which must be handled).
 */
typedef struct rna_service_primary_cfm_id_container_s {
#ifdef WINDOWS_KERNEL
    /* Note:  Due to lock changes, this can not be a mutex in the windows 
     *        kernel version.  It must be a spinlock
     */
    rna_service_spinlock_t pcic_spinlock; /* Instack queued spinlock*/
#else
    rna_service_mutex_t pcic_mutex;    /* A mutex to allow pcic_pci to be
                                        * read/written consistently.
                                        */
#endif /* WINDOWS_KERNEL*/

    /* The following are guarded by pcic_mutex: */
    primary_cfm_id_t    pcic_pci;      /* ID of the current primary CFM */
} rna_service_primary_cfm_id_container_t;


/*
 * A fake partition, which is used as a stand-in before the first partition map
 * is received.
 */
#define PREMATURE_PARTITION MAX_MD_HASH_PARTITIONS

/*
 * Flag values for cx_flags.
 */
#define CX_FLAG_SHUTTING_DOWN   (1 << 0)
            /* A flag to indicate that the user is in the process of destroying
             * this rna_service_ctx_t, so no new work should be added to its
             * work queues (since they're being flushed/destroyed).
             */
#define CX_FLAG_SHUT_DOWN       (1 << 1)
            /* A flag to indicate that the user has completed the shutdown of
             * this rna_service context.
             */

/*
 * Used in cx_ref_count to indicate that the ep has disconnected.
 */
#define CTX_REF_COUNT_SHUTTING_DOWN_FLAG  (1 << 31)


/**
 * An rna_service user's context.
 */
typedef struct rna_service_ctx_s {
    uint64_t            cx_watermark;
                                  /*! Used to verify that this struct was
                                   *  created by rna_service_ctx_create().
                                   */
    atomic_t            cx_ref_count;
                                  /*! Keeps rna_service_ctx_destroy() from
                                   *  freeing this struct while it's in use.
                                   */
    uint32_t            cx_flags; /*! Flags for this rna_service_ctx_t.
                                   *  See CTX_FLAG_*
                                   */
    struct rna_com     *cx_com_instance;
    struct com_attr     cx_com_attributes;
    rna_service_params_t
                        cx_params;/*! The set of parameters specified by the
                                   *  user in the call to
                                   *  rna_service_ctx_create().
                                   */
    rna_service_cs_params_t
                        cx_cs_params;
                                  /*! Cache server specific parameters (set
                                   *  for a user of type
                                   *  RNA_SERVICE_USER_TYPE_CACHE_SERVER only).
                                   */
    rna_service_md_params_t
                        cx_md_params;
                                  /*! Metadata server specific parameters (set
                                   *  for a user of type
                                   *  RNA_SERVICE_USER_TYPE_METADATA_SERVER
                                   *  only).
                                   */
    rna_service_work_queue_t
                       *cx_cfm_connect_work_queue;
                                  /*! For handling connection attempts to the
                                   *  CFMs (com_connect_sync calls may have
                                   *  long delays).
                                   */
    rna_service_work_queue_t
                       *cx_cfm_work_queue;
                                  /*! Deferred handling of messages from/to
                                   *  the configuration manager, to be
                                   *  executed by the workq threads.
                                   */
    send_waiting_msgs_work_ctx_t
                        cx_cfm_wctx;
                                  /* A pre-allocated work queue context struct
                                   * for use with the above work queue.
                                   */
    rna_service_work_queue_t
                       *cx_control_cs_work_queue;
                                  /*! Deferred handling of CONF_MGR_CONTROL_CS
                                   *  messages from/to the CFM, to be executed
                                   *  by the workq threads.
                                   */
    rna_service_work_queue_t
                       *cx_md_work_queue;
                                  /*! Deferred handling of messages from/to
                                   *  the MDs.
                                   */
    rna_service_work_queue_t
                       *cx_response_callback_work_queue;
                                  /*! Deferred handling of response callbacks,
                                   *  to be invoked by the workq threads.
                                   */
    uint64_t            cx_cs_membership_generation;
                                  /*! The current cache server membership
                                   *  generation number, provided by the primary
                                   *  CFM.
                                   */
    rna_service_mutex_t cx_cfm_mutex;
                                  /*! A mutex to guard the following fields:
                                   *      cx_cfm_config_gen
                                   *      cx_cfm_next_msg_id
                                   *      cx_connected_cfms
                                   *      cx_primary_cfm_eph
                                   *      cx_cfm_flags
                                   *      cx_registrations_waiting_for_reply
                                   *      cx_cfm_waiting_for_reply
                                   *      cx_deregistrations_waiting_for_reply
                                   *      cx_registered
                                   *      cx_cfm_registrations_waiting_to_send
                                   *      cx_cfm_msgs_waiting_to_send
                                   *      cx_primary_cfm_heartbeat_timer
                                   *      cx_non_primary_cfm_ping_timer
                                   *      cx_send_waiting_cfm_msgs_timer
                                   *      cx_send_shutdown_request_timer
                                   *      cx_send_shutdown_request_timer_is_set
                                   *      cx_send_shutdown_request_in_progress
                                   *      cx_send_shutdown_request_timeout_sec
                                   *      cx_cfm_event_mask
                                   *      cx_deferred_mount_action
                                   *      cx_cfm_query_cachedev_timestamp
                                   *  If this mutex must be held concurrently
                                   *  with the cx_md_mutex, it must be acquired
                                   *  AFTER the cx_md_mutex to prevent
                                   *  deadlock.
                                   */
    uint32_t            cx_cfm_config_gen;
                                  /*!
                                   * The generation number of the CFM's
                                   * configuration.
                                   */
    uint32_t            cx_cfm_next_msg_id;
                                  /*! The ID that will be stored (in 
                                   *  req_msg_id) in the next message to be
                                   *  sent to a configuration manager.
                                   */
    cfm_info_t          cx_connected_cfms[RNA_SERVICE_CFMS_MAX];
                                  /*! The set of connected configuration
                                   *  managers.
                                   *  Note that a CFM node is placed in this
                                   *  array at the same index that it has in
                                   *  the cx_params.rsp_cfm_addrs array.
                                   *  Guarded by the cx_cfm_mutex.
                                   */
    cfm_info_t          cx_disconnecting_cfms[RNA_SERVICE_CFMS_MAX];
                                  /*! CFMs for which com_disconnect has been
                                   *  called but the disconnect callback has
                                   *  not yet been invoked.
                                   *  Note that a CFM node is placed in this
                                   *  array at the same index that it has in
                                   *  the cx_params.rsp_cfm_addrs array (and
                                   *  the cx_connected_cfms array).
                                   *  Guarded by the cx_cfm_mutex.
                                   */
    rna_service_primary_cfm_id_container_t
                        cx_primary_cfm_id;
                                  /*! The ID of the current primary CFM */
    com_ep_handle_t     cx_primary_cfm_eph;
                                  /*! A communication endpoint handle for the
                                   *  primary configuration manager.  Guarded
                                   *  by the cx_cfm_mutex.
                                   */
    ctx_cfm_flags_t     cx_cfm_flags;
                                  /*! Guarded by the cx_cfm_mutex. */
    time_t              cx_quorum_heartbeat_timeout_sec;
                                  /*! Specified by the primary CFM */
    YAQ_HEAD            cx_registrations_waiting_for_reply;
                                  /*! Mount and/or block device registration
                                   *  messages for the configuration manager
                                   *  that have been sent and are waiting for
                                   *  a reply.
                                   */
    YAQ_HEAD            cx_cfm_waiting_for_reply;
                                  /*! Messages for the CFM other than
                                   *  registrations and de-registrations that
                                   *  have been sent to the CFM and are waiting
                                   *  for a reply.
                                   */
    YAQ_HEAD            cx_registered;
                                  /*! Mounts, block devices, replica stores,
                                   *  storage paths, etc. that are registered.
                                   */
    YAQ_HEAD            cx_deregistrations_waiting_for_reply;
                                  /*! Mount, cache device, block device, etc.
                                   * de-registration messages for the
                                   * configuration manager that have been sent
                                   * and are waiting for a reply.
                                   */
    YAQ_HEAD            cx_cfm_registrations_waiting_to_send;
                                  /*! Mount, cache device, replica store, block
                                   *  device, etc. registration and/or
                                   *  de-registration messages for the
                                   *  configuration manager that are waiting
                                   *  to be sent.
                                   */
    YAQ_HEAD            cx_cfm_msgs_waiting_to_send;
                                  /*! Messages other than the above for the
                                   *  configuration manager that are waiting
                                   *  to be sent.
                                   */
    rna_service_timer_object_t
                        cx_primary_cfm_heartbeat_timer;
                                  /*! Guarded by the cx_cfm_mutex, to allow
                                   *  correct ctx reference count handling
                                   *  during shutdown
                                   */
    rna_service_timer_object_t
                        cx_non_primary_cfm_ping_timer;
                                  /*! Guarded by the cx_cfm_mutex, to allow
                                   *  correct ctx reference count handling
                                   *  during shutdown
                                   */
    rna_service_timer_object_t
                        cx_send_waiting_cfm_msgs_timer;
                                  /*! Guarded by the cx_cfm_mutex, to allow
                                   *  correct ctx reference count handling
                                   *  during shutdown
                                   */
    rna_service_timer_object_t
                        cx_send_shutdown_request_timer;
                                  /*! Guarded by the cx_cfm_mutex, to allow
                                   *  correct ctx reference count handling
                                   *  during shutdown
                                   */
    boolean             cx_send_shutdown_request_timer_is_set;
                                  /*! TRUE if the cx_send_shutdown_request_timer
                                   *  is set.  Guarded by the cx_cfm_mutex.
                                   */
    boolean             cx_send_shutdown_request_in_progress;
                                  /*! If TRUE, a shutdown request has been sent
                                   *  to the primary CFM, and has not yet been
                                   *  responded to.
                                   *  Guarded by the cx_cfm_mutex.
                                   */
    int32_t             cx_send_shutdown_request_timeout_sec;
                                  /*! A shutdown request message msut be sent to
                                   *  a primary CFM before this amount of time
                                   *  has elapsed to avoid triggering a timeout.
                                   *  Guarded by the cx_cfm_mutex.
                                   */
    uint32_t            cx_cfm_event_mask;
                                  /*! Currently used by cache servers only.
                                   *  Guarded by the cx_cfm_mutex.
                                   */
    rna_cmd_type        cx_deferred_mount_action;
                                  /*! If non-zero, and the user is a cache
                                   * server, this value indicates that at
                                   * MOUNT_BLOCKED or MOUNT_UNBLOCKED message
                                   * must be sent to the CFM.  n earlier send
                                   * attempt failed.  Guarded by the
                                   * cx_cfm_mutex.
                                   */
    struct timespec     cx_cfm_query_cachedev_timestamp;
                                  /*! The timestamp contained in the most
                                   * recent CONF_MGR_QUERY_CACHE_DEVICE message
                                   * from the primary CFM.  Guarded by the
                                   * cx_cfm_mutex.
                                   */
    rna_service_timer_object_t
                        cx_reconnect_cfms_timer_object;
    rna_service_timer_object_t
                        cx_cs_cfm_registration_timer;
    rna_service_timer_object_t
                        cx_primary_cfm_registration_timer;
                                  /*! Guarded by the cx_cfm_mutex, to allow user
                                   * type RNA_SERVICE_USER_TYPE_CACHE_SERVER to
                                   * be sent an
                                   * RNA_SERVICE_EVENT_KILL_SELF_RESTART if the
                                   * primary cfm registration can't be
                                   * re-established in
                                   * RNA_SERVICE_CFM_REGISTRATION_TIMEOUT seconds
                                   */
    rna_service_mutex_t cx_md_mutex;
                                  /*! A mutex to guard the following fields:
                                   *      cx_md_next_msg_id
                                   *      cx_md_table[]
                                   *      cx_md_table_first
                                   *      cx_md_table_last
                                   *      cx_send_waiting_md_msgs_timers
                                   *      cx_md_registered_paths
                                   *      cx_num_mds
                                   *      cx_num_configured_mds
                                   *      cx_hash_partition_bitmask
                                   *      cx_partitions
                                   *      cx_partition_map
                                   *      cx_hash_key_temp
                                   *      cx_md_flags
                                   *      cx_ping_mds_work_object
                                   *      cx_ping_mds_timer_object
                                   *  If this mutex must be held concurrently
                                   *  with the cx_cfm_mutex, it must be
                                   *  acquired BEFORE the cx_cfm_mutex to
                                   *  prevent deadlock.
                                   */
    uint32_t            cx_md_next_msg_id;
                                  /*! The ID that will be stored (in 
                                   *  req_msg_id) in the next message to be
                                   *  sent to a metadata server.
                                   */
    md_info_t          *cx_md_table[NUM_MD_ORDINALS];
                                  /*! A table containing information about
                                   *  all the metadata servers in the
                                   *  cluster.  The entry at index i is
                                   *  non-NULL if the MD with ordinal i is
                                   *  connected; otherwise the entry is NULL.
                                   *  Guarded by the cx_md_mutex.
                                   */
    md_info_t         **cx_md_table_first;
                                  /*! The first cx_md_table entry that
                                   *  cx_partition_map.pm_partition_assignments
                                   *  entries refer to.
                                   *  Guarded by the cx_md_mutex.
                                   */
    md_info_t         **cx_md_table_last;
                                  /*! The last cx_md_table entry that
                                   *  cx_partition_map.pm_partition_assignments
                                   *  entries refer to.
                                   *  Guarded by the cx_md_mutex.
                                   */
    rna_service_timer_object_t
                        cx_send_waiting_md_msgs_timers[NUM_MD_ORDINALS];
                                  /* A timer object for each ordinal to use for
                                   * scheduling delayed_send_waiting_md_msgs.
                                   */
    int                 cx_num_mds;
                                  /*! The number of MDs stored in md_table[] */
    uint32_t            cx_num_configured_mds;
                                  /*! The number of MDs configured in the group
                                   */
    uint32_t            cx_hash_partition_bitmask;
                                  /*! A bitmask for converting a hash value
                                   *  to a hash partition number.
                                   */
    partition_info_t    cx_partitions[MAX_MD_HASH_PARTITIONS + 1];
                                  /*! Information about each metadata hash
                                   *  partition.  The extra entry in this table
                                   *  is for the PREMATURE_PARTITION, which is
                                   *  used before the first partition map
                                   *  arrives.  Guarded by the cx_md_mutex.
                                   */
    struct cfm_md_partition_map
                        cx_partition_map;
                                  /*! The assignments of metadata hash
                                   *  partitions to MDs.
                                   *  Guarded by the cx_md_mutex.
                                   */
    YAQ_HEAD            cx_md_registered_paths;
                                  /*! Storage paths that are registered with
                                   *  the MD
                                   */
    rna_hash_key_t      cx_hash_key_temp;
                                  /*! A temporary spot to store a hash key.
                                   *  Guarded by the cx_md_mutex.
                                   */
    ctx_md_flags_t      cx_md_flags;
                                  /*! Guarded by the cx_md_mutex. */
    rna_service_work_t  cx_ping_mds_work_object;
                                  /*! Guarded by the cx_md_mutex. */
    rna_service_timer_object_t
                        cx_ping_mds_timer_object;
                                  /*! Guarded by the cx_md_mutex, to allow
                                   *  correct ctx reference count handling
                                   *  during shutdown.  User by cache server
                                   *  users only.
                                   */
    rna_service_timer_object_t
                        cx_reconnect_mds_timer_object;
    rna_service_mempool_t
                        cx_mempools[MEMPOOL_ID_INVALID];
                                  /*! Memory pools, to speed allocation */
    void               *cx_private;
} rna_service_ctx_t;


/*
 * A function to process an incoming message.
 */
typedef int (*process_message_function) (rna_service_ctx_t *ctx,
                                         com_ep_handle_t   *eph,
                                         struct cfm_cmd    *cmd);


/*
 * Flags used in the rmbi_flags field in an
 * rna_service_message_buffer_internal_hdr.
 */
#define RMBI_FLAG_TIMED_OUT 0x1
                        /* This message send has timed out */
#define RMBI_FLAG_SENT      0x2
                        /* This message has been sent at least once. */
#define RMBI_FLAG_PRE_ALLOC 0x4
                        /* This message has been pre-allocated */


/*
 * Header for an rna_service_message_buffer_internal_t.
 */
DECLARE_PACKED_STRUCT(rna_service_message_buffer_internal_hdr) {
    YAQ_LINK        rmbi_link;          /* Used for linking this struct into a
                                         * pi_waiting_to_send or
                                         * pi_waiting_for_reply list.
                                         */
    uint64_t        rmbi_watermark;     /* Used to verify that this struct
                                         * is indeed an
                                         * rna_service_message_buffer_internal_t
                                         */
    uint64_t        rmbi_req_msg_id;    /* The internal identifier for this
                                         * message.  Used to match this message
                                         * with its response.
                                         */
    rna_service_response_callback
                    rmbi_response_callback;
                                        /* The callback routine that will be
                                         * invoked either when a response to
                                         * this message is received or when
                                         * the response times out (if the
                                         * user has specified a response
                                         * timeout).
                                         */
    rna_service_ctx_t
                  * rmbi_ctx;           /* rna_service context of the user that
                                         * sent this message
                                         */
    rna_service_timer_object_t
                    rmbi_response_timer_object;
                                        /* Timer set to wait for a response
                                         * for this message
                                         */
    int             rmbi_partition;     /* If this is a message for the
                                         * metadata server, the metadata hash
                                         * partition this message is
                                         * associated with.
                                         */
    uint8_t         rmbi_msg_type;      /* The type of message stored in this
                                         * buffer (rna_service_message_type_t).
                                         */
    uint8_t         rmbi_mempool_id;    /* The mempool this message buffer was
                                         * allocated from (mempool_id_t), or
                                         * MEMPOOL_ID_INVALID if it wasn't
                                         * allocated from a mempool.
                                         */
    uint8_t         rmbi_flags;
    uint8_t         rmbi_pad;           /* for future use (8-byte alignment) */
} END_PACKED_STRUCT(rna_service_message_buffer_internal_hdr);


/**
 * Internal view of an rna_service message buffer.
 */
DECLARE_PACKED_STRUCT(rna_service_message_buffer_internal) {
    /* --- Internal-only portion of this struct --- */
    rna_service_message_buffer_internal_hdr_t
                    h;                          /* Header */
    /* --- User-visible portion of this struct --- */
    union {
        rna_service_message_buffer_t
                    rmbi_message_buffer;        /* User-visible message */
        rna_service_cs_md_message_buffer_t
                    rmbi_cs_md_message_buffer;  /* User-visible CS/MD message */
    } u;
} END_PACKED_STRUCT(rna_service_message_buffer_internal);
/*
 * We hope the above PACKED is a no-op, and that the size
 * of an rna_service_message_buffer_internal_hdr_t is a multiple of 8.  This
 * attribute is included out of paranoia, in case the header is modified, to
 * assure that the memory allocations in rna_service_alloc_message_buffer
 * are correct in size.
 */


/**
 * A workq context, for dealing with cfm_cmd messages.
 */
typedef struct cfm_work_ctx_s {
    rna_service_work_t  cwx_work_obj;
    rna_service_ctx_t  *cwx_ctx;
    com_ep_handle_t     cwx_eph;
    struct cfm_cmd      cwx_cmd;
} cfm_work_ctx_t;


/*
 * A workq context, for handing responses (or asynchronous messages)
 * to the user.
 */
typedef struct invoke_callback_work_ctx_s {
    rna_service_work_t             mwx_work_obj;
    rna_service_ctx_t             *mwx_ctx;
    rna_service_message_buffer_internal_t
                                  *mwx_message_sent;
    rna_service_message_buffer_t  *mwx_response_received;
    int                            mwx_event;
} invoke_callback_work_ctx_t;


/*
 * Macro to calculate the size of an rna_service message buffer, including an
 * optional pathname
 */
#define RNAS_MESSAGE_SIZE(__message_type, __pathlen)                        \
        (uint32_t)(sizeof(rna_service_message_buffer_internal_hdr_t) +      \
         sizeof(rna_service_message_buffer_header_t) +                      \
         sizeof(__message_type) +                                           \
         (__pathlen))


/*
 * Prototype for a comparator function used with find_registration().
 *
 * Returns:
 *     TRUE if the search should stop
 *     FALSE if the search should continue
 */
typedef boolean (*find_registration_compare_fn)
                                (rna_service_ctx_t                     *ctx,
                                 rna_service_message_buffer_internal_t *ibuf,
                                 void                                  *arg);

/* 
 * This section of code is moved from rna_service_kernel.h
 */
#if defined (LINUX_KERNEL) || defined (WINDOWS_KERNEL)
rna_service_com_attr_t rna_service_com_attr = {0};
#endif /*KERNEL*/
/* End of copy from rna_service_kernel.h */

/**
 * Forward declarations.
 */
static void reconnect_cfms_to(uint64_t context);
static void register_with_cfm_tc(uint64_t context);
static void reconnect_mds_to(uint64_t context);
static rna_service_workq_cb_ret_t send_waiting_md_msgs(
                                    rna_service_workq_cb_arg_t workq_context);
static rna_service_workq_cb_ret_t send_waiting_cfm_msgs(
                                    rna_service_workq_cb_arg_t workq_context);
static int process_cs_async_message(rna_service_ctx_t *ctx,
                                    com_ep_handle_t   *eph,
                                    void              *cmd);
static int process_blk_async_message(rna_service_ctx_t *ctx,
                                    com_ep_handle_t    *eph,
                                    struct cfm_cmd     *cmd);
static void rna_service_check_and_update_cfms(rna_service_ctx_t *ctx,
                                              uint32_t cfm_count,
                                              struct sockaddr_in *cfm_addr_tbl,
                                              const uint32_t max_entries);
static void queue_reconnect_cfms(rna_service_ctx_t *ctx);
static void queue_reconnect_mds(rna_service_ctx_t *ctx);
static void delayed_send_waiting_md_msgs(uint64_t context);
static void schedule_waiting_md_msgs(rna_service_ctx_t *ctx, md_info_t *mdi,
                                    int delay_sec);
static void resend_md_messages(rna_service_ctx_t *ctx);
static void md_disconnected(rna_service_ctx_t *ctx, md_info_t *mdi);

INLINE int
rna_service_hashkey_to_partition(rna_hash_key_t *key,
                              uint32_t        hash_partition_bitmask)
{
    rna_service_assert(0 != hash_partition_bitmask);
    return md_hashkey_to_partition(key, hash_partition_bitmask);
}

/*
 * Make sure the wrong hashkey-to-partition function isn't used in this module.
 * This module should use rna_service_hashkey_to_partition.
 */
#define hashkey_to_partition

/* ========================== Private Functions ============================ */

#if (defined(LINUX_KERNEL) || defined(WINDOWS_KERNEL) || defined(WINDOWS_USER))

int clock_gettime (clockid_t         clock_id,
                   struct timespec * p_timespec)
{
    int result = -1;
    
    if (clock_id != CLOCK_REALTIME) {
        // only do realtime
    } else if (! p_timespec) {
        // need a timespec
    } else {
        #if (defined(LINUX_KERNEL))
        {
            getnstimeofday(p_timespec);
        }
        #elif (defined(WINDOWS_KERNEL) || defined(WINDOWS_USER))
        {
            LARGE_INTEGER  time_100ns;
            
            #if (defined(WINDOWS_USER))
                GetSystemTimeAsFileTime((PFILETIME)&time_100ns.u);
            #else
                KeQuerySystemTimePrecise(&time_100ns);
            #endif
            
            time_100ns.QuadPart += 1164447360000000LL;   // 1601 ==> 1970 (100nS resolution)
            
            p_timespec->tv_nsec = (long)((time_100ns.QuadPart % 10000000l) * 100);
            p_timespec->tv_sec  = (long) (time_100ns.QuadPart / 10000000l);
        }
        #endif
        
        result = 0;
    }
    
    return result;
}

#endif  /* LINUX_KERNEL || WINDOWS_KERNEL || WINDOWS_USER */


/* ---------------------------- Memory Pools ------------------------------ */

/**
 * Initialize a memory pool.
 */
int
rna_service_mempool_init(rna_service_mempool_t *mempool,
                         int                    element_size,
                         int                    memset_size,
                         int                    num_elements,
                         int                    num_reserved,
                         int                    no_dynamic_allocation)
{
    mempool_ele_t *ele, *prev;
    char      *p, *end;
    int i;

    memset(mempool, 0, sizeof(*mempool));
    rna_service_spinlock_init(&mempool->mp_spinlock);

    /*
     * Round the element size up to a multiple of 8 bytes, to assure that the
     * start of each element in the allocated array is 64-bit aligned.
     */
    mempool->mp_element_size = element_size = (element_size + 7) & ~0x7;
    rna_service_assert(memset_size <= element_size);
    mempool->mp_memset_size = memset_size;
    mempool->mp_num_reserved = num_reserved;
    mempool->mp_no_dynamic = no_dynamic_allocation;
    rna_service_init_wait_obj(&mempool->mp_wait);

    if (0 == num_elements) {
        return 0;
    }

    mempool->mp_begin = rna_service_alloc0(element_size * num_elements);
    if (NULL == mempool->mp_begin) {
        if (!no_dynamic_allocation) {
            /*
             * This isn't a fatal error, it just means we'll have to do all our
             * allocations individually and dynamically.
             */
            rna_dbg_log(RNA_DBG_WARN, "mempool allocation failed, size "
                        "%d, elements will be allocated dynamically\n",
                        element_size * num_elements);
            return -ENOMEM;
        }

        /*
         * If dynamic allocation isn't permitted for this pool, attempt
         * to allocate the elements individually rather than as a
         * contiguous pool.  Sometimes memory is too fragmented to get
         * a large contiguous chunk!
         */
        rna_dbg_log(RNA_DBG_VERBOSE,
                    "Unable to allocate [%d] contiguous bytes for all "
                    "mempool elements, so elements will instead be allocated "
                    "individually.  This condition is expected if the mempool "
                    "size is large\n",
                    element_size * num_elements);
        element_size += sizeof(mempool_ele_t);
        mempool->mp_element_size = element_size;
        ele = NULL;

        for (i = 0, prev = NULL; i < num_elements; i++, prev = ele) {
            ele = rna_service_alloc0(element_size);
            if (NULL == ele) {
                rna_dbg_log(RNA_DBG_ERR, "mempool allocation failed, size "
                            "%d\n", element_size * num_elements);
                for (ele = prev; NULL != ele; ele = prev) {
                    prev = prev->mpe_next;
                    rna_service_free(element_size, ele);
                }
                return -ENOMEM;
            }
            ele->mpe_pool = mempool;
            ele->mpe_next = prev;
            p = (char *)ele + sizeof(*ele);
            ((list_element_t *)p)->le_next = (list_element_t *)(prev
                                              ? ((char *)prev + sizeof(*prev))
                                              : NULL);
        }
        mempool->mp_end = ele;
        mempool->mp_avail = (list_element_t *)((char *)ele + sizeof(*ele));
    } else {
        /* mp_end is the address of the byte following the end of this pool */
        mempool->mp_end = (char *)mempool->mp_begin +
                                  (element_size * num_elements);

        /*
         * Link the elements together to form an available list.
         * (Don't initialize the le_next pointer of the last element, since it
         * should be left NULL)
         */
        end = ((char *)mempool->mp_end) - element_size;
        for (p = (char *)mempool->mp_begin; p < end; p += element_size) {
            /*
             * Superimpose a list_element_t over the mempool object and use it to
             * link the mempool object into the available list.
             */
            ((list_element_t *)p)->le_next =
                                    (list_element_t *)(p + element_size);
        }
        ((list_element_t *)p)->le_next = NULL;
        mempool->mp_avail = mempool->mp_begin;
    }
    mempool->mp_avail_count = num_elements;

    return 0;
}


INLINE void
mempool_init(rna_service_ctx_t *ctx,
             mempool_id_t       mempool_id,
             int                element_size,
             int                memset_size,
             int                num_elements,
             int                num_reserved)
{
    rna_service_assert(mempool_id < MEMPOOL_ID_INVALID);

    (void)rna_service_mempool_init(&ctx->cx_mempools[mempool_id],
                              element_size, memset_size,
                              num_elements, num_reserved, 0);
}

static void
__rna_service_check_for_leaks(rna_service_mempool_t *mempool,
                              void (leakchk)(void *))
{
    char      *p, *end;
    int element_size = mempool->mp_element_size;

    end = ((char *)mempool->mp_end) - element_size;
    for (p = (char *)mempool->mp_begin; p < end; p += element_size) {
        leakchk((void *)p);
    }
}


/**
 * Tear-down and free a memory pool.
 *
 * Arguments:
 *     mempool  Pointer to the mempool that should be torn down.
 */
void
rna_service_mempool_destroy(rna_service_mempool_t *mempool,
                            void (leakchk)(void *))
{
    irq_flag_t    flags;
    mempool_ele_t *ele, *next;
    gboolean got_leak = FALSE;

    if (NULL == mempool) {
        rna_dbg_log(RNA_DBG_ERR,
                    "mempool is NULL\n");
    }

    if (!rna_service_spinlock_acquire(&mempool->mp_spinlock, &flags)) {
        /* This failure means we're in the process of shutting down */
        return;
    }

    if (rna_service_atomic_read(&mempool->mp_alloc_count) != 0) {
        rna_dbg_log(RNA_DBG_ERR,
                    "memory leak for mempool [%p] "
                    "remaining elements [%d]\n",
                    mempool,
                    rna_service_atomic_read(&mempool->mp_alloc_count));
        got_leak = TRUE;
    }

    if (mempool->mp_begin != NULL) {
        if (got_leak && leakchk) {
            __rna_service_check_for_leaks(mempool, leakchk);
        }
        rna_service_free((uint32_t)(((uintptr_t)mempool->mp_end) - ((uintptr_t)mempool->mp_begin)),
                         mempool->mp_begin);
    } else {
        for (ele = (mempool_ele_t *)mempool->mp_end; NULL != ele; ele = next) {
            next = ele->mpe_next;
            if (got_leak && leakchk) {
                leakchk((void *)((char *)ele + sizeof(*ele)));
            }
            rna_service_free(mempool->mp_element_size, ele);
        }
    }
    mempool->mp_begin = mempool->mp_end = mempool->mp_avail = NULL;
    mempool->mp_no_dynamic = 0;
    mempool->mp_avail_count = 0;
    mempool->mp_element_size = 0;
    atomic_set(&mempool->mp_alloc_count, 0);
    rna_service_spinlock_release(&mempool->mp_spinlock, &flags);
}


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
                          size_t dynamic_alloc_reduction)
{
    list_element_t  *ret = NULL;
    irq_flag_t    flags;

    /* Take a peek at the available list before grabbing the spinlock. */
    if (mempool->mp_avail_count > mempool->mp_num_reserved) {
        /* It looks like the list may not be empty; grab the spinlock... */
        if (!rna_service_spinlock_acquire(&mempool->mp_spinlock, &flags)) {
            /* This failure means we're in the process of shutting down */
            return (NULL);
        }
        /* Check again, now that we hold the spinlock. */
        if (mempool->mp_avail_count > mempool->mp_num_reserved) {
            rna_service_assert(NULL != mempool->mp_avail);
            ret = mempool->mp_avail;
            mempool->mp_avail = ret->le_next;
            if (0 == mempool->mp_avail_count) {
                rna_dbg_log(RNA_DBG_ERR,
                            "mp_avail_count underflow\n");
            } else {
                mempool->mp_avail_count--;
            }
        }
        rna_service_spinlock_release(&mempool->mp_spinlock, &flags);
    }

    /*
     * Fall back to dynamic allocation if we were unable to allocate from
     * the memory pool's available list.
     */
    if (NULL == ret && !mempool->mp_no_dynamic) {
        if (0 == dynamic_alloc_reduction) {
            ret = rna_service_alloc(mempool->mp_element_size);
        } else {
            ret = rna_service_simple_alloc((uint32_t)(mempool->mp_element_size -
                                                      dynamic_alloc_reduction));
        }
    }
    if (NULL == ret) {
        /*
         * Dynamic allocation failed.  As a long shot, take another look at
         * the reserve pool -- maybe something's been freed.
         *
         * Take a peek at the reserve pool before grabbing the spinlock.
         */
        if (mempool->mp_avail_count > 0) {
            /*
             * It looks like the reserve pool may not be empty; grab the
             * spinlock...
             */
            if (!rna_service_spinlock_acquire(&mempool->mp_spinlock,
                                              &flags)) {
                /* This failure means we're shutting down */
                return (NULL);
            }
            /* Check again, now that we hold the spinlock. */
            if (mempool->mp_avail_count > 0) {
                rna_service_assert(NULL != mempool->mp_avail);
                ret = mempool->mp_avail;
                mempool->mp_avail = ret->le_next;
                if (0 == mempool->mp_avail_count) {
                    rna_dbg_log(RNA_DBG_ERR,
                                "mp_avail_count underflow\n");
                } else {
                    mempool->mp_avail_count--;
                }
            }
            rna_service_spinlock_release(&mempool->mp_spinlock, &flags);
        }
    }
    if (NULL != ret) {
        atomic_inc(&mempool->mp_alloc_count);
        if (mempool->mp_memset_size > 0) {
            rna_service_assert(mempool->mp_memset_size <=
                        (mempool->mp_element_size - dynamic_alloc_reduction));
            memset(ret, 0, mempool->mp_memset_size);
        }
    }
    return ((void *)ret);
}

/**
 * Wait for up to the specified timeout period for an allocation to
 * become available.
 *
 * Arguments:
 *  mempool     Pointer to the mempool that the allocation should be done from
 *  flags_p     Pointer to previously saved interrupt flags
 *  alloc_timeout
 *              Amount of time to wait (in jiffies) for an item to be available
 *              for allocation.
 *              Any value less than 1 indicates that we will not wait at all.
 *
 * Notes:
 *  The caller must hold the mempool lock on entry to this function.
 *  The lock may be dropped within this function, but will be held again
 *  on return.
 *
 * Return value:
 *  Returns 0 on normal completion, or a negative errno value on failure.
 *  (Note that a timeout is considered a "normal" completion in this context,
 *  and thus returns 0!)
 */
static int
rna_service_mempool_alloc_timed_wait(rna_service_mempool_t *mempool,
                                     irq_flag_t *flags_p,
                                     int64_t timeout)
{

    if (mempool->mp_avail_count > mempool->mp_nwaiters) {
        return 0;
    }

    mempool->mp_nwaiters++;
#if defined(LINUX_USER) || defined(WINDOWS_USER)
    do {
        /*
         * This was the original code for USER and KERNEL, but because
         * of the deferred evaluation of the condition (arg 4,
         * "mempool->mp_avail_count > 0") it can't use the macro defined
         * for KERNEL mode.
         *
         * In USER mode ***THE CONDITION IS IGNORED***, so the original
         * code is used.  The effect is that this routine can possibly
         * a failure under heavy load conditions when it would otherwise
         * keep trying.
         */

        timeout = rna_service_wait_obj_timed_wait(&mempool->mp_wait,
                                             &mempool->mp_spinlock,
                                             flags_p,
                                             (mempool->mp_avail_count > 0), 
                                             timeout);

    } while (mempool->mp_avail_count == 0 && timeout > 0);
#else   /* not LINUX_USER || WINDOWS_USER */
    __rna_wait_event_timeout(mempool->mp_wait,
                             &mempool->mp_spinlock,
                             flags_p,
                             (mempool->mp_avail_count > 0), 
                             timeout);
#endif  /* not LINUX_USER || WINDOWS_USER */
    mempool->mp_nwaiters--;
    return (timeout < 0) ? (int)timeout : 0;
}

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
 *
 * Notes:
 *  1) Note that fairness in allocation will be fully maintained only
 *     if all users of a specific mempool are using the same "timeout"
 *     value!
 */
int
rna_service_mempool_alloc_timed(rna_service_mempool_t *mempool,
                                int64_t               alloc_timeout,
                                void                  **ret_ptr)
{
    list_element_t   *ret = NULL;
    irq_flag_t         flags;
    int              rc;

    if (!rna_service_spinlock_acquire(&mempool->mp_spinlock, &flags)) {
        /* This failure means we're in the process of shutting down */
        return -EINVAL;
    }

    /* wait if needed */
    if (0 != alloc_timeout) {
        rc = rna_service_mempool_alloc_timed_wait(mempool, &flags,
                                                  alloc_timeout);
        if (0 != rc) {
            if (rc != -EPERM) {     // we don't have the lock if EPERM...
                rna_service_spinlock_release(&mempool->mp_spinlock, &flags);
            }
            return rc;
        }
    }

    if (mempool->mp_avail_count > 0) { 
        rna_service_assert(NULL != mempool->mp_avail);
        ret = mempool->mp_avail;
        mempool->mp_avail = ret->le_next;
        mempool->mp_avail_count--;
    }
    rna_service_spinlock_release(&mempool->mp_spinlock, &flags);

    if (NULL != ret) {
        atomic_inc(&mempool->mp_alloc_count);
        if (mempool->mp_memset_size > 0) {
            memset(ret, 0, mempool->mp_memset_size);
        }
        *ret_ptr = ret;
        return 0;
    }

    return -ENOMEM;
}

static void *
mempool_alloc(rna_service_ctx_t *ctx,
              mempool_id_t mempool_id,
              size_t dynamic_alloc_reduction)
{
    rna_service_mempool_t       *mempool;

    rna_service_assert((mempool_id >= 0) && (mempool_id < MEMPOOL_ID_INVALID));
    mempool = &ctx->cx_mempools[mempool_id];

    return rna_service_mempool_alloc(&ctx->cx_mempools[mempool_id],
                                      dynamic_alloc_reduction);
}

/**
 * Free an item to a memory pool.
 */
void
rna_service_mempool_free(rna_service_mempool_t *mempool,
                         void                  *item)
{
    irq_flag_t flags;

    if (mempool->mp_no_dynamic
        || ((item >= mempool->mp_begin)
            && (item < mempool->mp_end))) {

        rna_service_assert((mempool->mp_end && mempool->mp_begin)
                           || (mempool->mp_no_dynamic
                               && ((mempool_ele_t *)((char *)item
                               - sizeof(mempool_ele_t)))->mpe_pool == mempool));

        /* This item was allocated from the mempool */

        if (!rna_service_spinlock_acquire(&mempool->mp_spinlock, &flags)) {
            /* This failure means we're in the process of shutting down */
            goto done;
        }
        /*
         * Superimpose a list_element_t over the mempool object and use it
         * to link the mempool object into the available list.
         */
        ((list_element_t *)item)->le_next = mempool->mp_avail;
        mempool->mp_avail = (list_element_t *)item;
        mempool->mp_avail_count++;
        rna_service_wait_obj_wake_up(&mempool->mp_wait);
        rna_service_spinlock_release(&mempool->mp_spinlock, &flags);
    } else {
        /* This item was dynamically allocated */
        rna_service_simple_free(item);
    }
        
done:
    if (atomic_dec_return(&mempool->mp_alloc_count) < 0) {
        /* It appears something may have been multiply freed */
        rna_dbg_log(RNA_DBG_ERR,
                    "mp_alloc_count underflow [%d] in mempool [%p]\n", 
                    rna_service_atomic_read(&mempool->mp_alloc_count),
                    mempool);
    }
}

static void
mempool_free(rna_service_ctx_t *ctx, mempool_id_t mempool_id, void *item)
{
    rna_service_assert((mempool_id >= 0) && (mempool_id < MEMPOOL_ID_INVALID));
    rna_service_mempool_free(&ctx->cx_mempools[mempool_id], item);
}

/* ------------------------------- Throttle -------------------------------- */

int
rna_service_throttle_init(rna_service_throttle_t *throttle,
                          int                    initial_limit,
                          int                    min_limit,
                          int                    max_limit)
{
    if (initial_limit < min_limit || initial_limit > max_limit
        || min_limit > max_limit) {
        rna_dbg_log(RNA_DBG_ERR, "throttle=%p initialization failed, "
                    "illegal limits specified\n", throttle);
        return -EINVAL;
    }

    memset(throttle, 0, sizeof(*throttle));

    rna_service_spinlock_init(&throttle->thr_spinlock);
    rna_service_init_wait_obj(&throttle->thr_wait);
    throttle->thr_min_limit = min_limit;
    throttle->thr_max_limit = max_limit;
    throttle->thr_cur_limit = initial_limit;
    return 0;
}

void
rna_service_throttle_destroy(rna_service_throttle_t *throttle)
{
    irq_flag_t    flags;

    if (!rna_service_spinlock_acquire(&throttle->thr_spinlock, &flags)) {
        /* This failure means we're in the process of shutting down */
        return;
    }

    if (throttle->thr_n_active != 0) {
        rna_dbg_log(RNA_DBG_ERR, "throttle leak for throttle [%p] "
                    "n_active [%d]\n",
                    throttle, throttle->thr_n_active);
    }

    throttle->thr_cur_limit = 0;
    throttle->thr_n_active = 0;
    rna_service_spinlock_release(&throttle->thr_spinlock, &flags);
}

/**
 * Wait for up to the specified timeout period for the current active
 * count to go below the 'throttle' limit.
 *
 * Arguments:
 *  throttle    Pointer to the throttle structure
 *  flags_p     Pointer to previously saved interrupt flags
 *  timeout
 *              Amount of time to wait (in jiffies) for the throttle
 *              active count to go below the limit.
 *              Any value less than 1 indicates that we will not wait at all.
 *
 * Notes:
 *  The caller must hold the throttle lock on entry to this function.
 *  The lock may be dropped within this function, but will be held again
 *  on return.
 *
 * Return value:
 *  Returns 0 on normal completion, or a negative errno value on failure.
 *  (Note that a timeout is considered a "normal" completion in this context,
 *  and thus returns 0!)
 */
static int
rna_service_throttle_timed_wait(rna_service_throttle_t *throttle,
                                irq_flag_t *flags_p,
                                int n_registrations,
                                int64_t timeout)
{
    if ((throttle->thr_cur_limit - (throttle->thr_n_active + n_registrations))
         >= throttle->thr_nwaiters) {
        return 0;
    }

    throttle->thr_nwaiters += n_registrations;
#if defined(LINUX_USER) || defined(WINDOWS_USER)
    do {
        /*
         * This was the original code for USER and KERNEL, but because
         * of the deferred evaluation of the condition (arg 4) it can't
         * use the macro defined for KERNEL mode.
         *
         * In USER mode ***THE CONDITION IS IGNORED***, so the original
         * code is used.  The effect is that this routine can possibly
         * a failure under heavy load conditions when it would otherwise
         * keep trying.
         */

        timeout = rna_service_wait_obj_timed_wait(&throttle->thr_wait,
                                             &throttle->thr_spinlock,
                                             flags_p,
                                             (throttle->thr_n_active +
                                              n_registrations <=
                                             throttle->thr_cur_limit),
                                             timeout);
    } while (throttle->thr_n_active + n_registrations
             > throttle->thr_cur_limit && timeout > 0);
#elif defined(WINDOWS_KERNEL) || defined(LINUX_KERNEL)
    __rna_wait_event_timeout(throttle->thr_wait,
                             &throttle->thr_spinlock,
                             flags_p,
                             (throttle->thr_n_active + n_registrations <=
                              throttle->thr_cur_limit),
                             timeout);
#endif  /* LINUX_KERNEL, WINDOWS_KERNEL */
    throttle->thr_nwaiters -= n_registrations;
    return (timeout < 0) ? (int)timeout : 0;
}

/*
 * rna_service_throttle_register
 *  Block up to 'timeout' jiffies waiting for the 'throttle' active
 *  count to go below the throttle limit.
 *
 * Return value:
 *  Returns 0 on success, -EBUSY if a timeout occurs, or a negative
 *  errno for other errors.
 */
int
rna_service_throttle_register(rna_service_throttle_t *throttle,
                              int                    n_registrations,
                              int64_t                timeout)
{
    irq_flag_t    flags;
    int rc = 0;

    if (!rna_service_spinlock_acquire(&throttle->thr_spinlock, &flags)) {
        /* This failure means we're in the process of shutting down */
        return -EINVAL;
    }

    /* wait if needed */
    if (0 != timeout) {
        rc = rna_service_throttle_timed_wait(throttle, &flags, n_registrations,
                                             timeout);
        if (0 != rc) {
            if (rc != -EPERM) {     // we don't have the lock if EPERM...
                rna_service_spinlock_release(&throttle->thr_spinlock, &flags);
            }
            return rc;
        }
    }

    if (throttle->thr_n_active + n_registrations <= throttle->thr_cur_limit) {
        throttle->thr_n_active += n_registrations;
    } else {
        rc = -EBUSY;
    }
    rna_service_spinlock_release(&throttle->thr_spinlock, &flags);

    return rc;
}

void
rna_service_throttle_deregister(rna_service_throttle_t *throttle,
                                int n_registrations)
{
    irq_flag_t flags;

    if (!rna_service_spinlock_acquire(&throttle->thr_spinlock, &flags)) {
        /* This failure means we're in the process of shutting down */
        return;
    }

    if (throttle->thr_n_active < n_registrations) {
        rna_dbg_log(RNA_DBG_ERR,
                    "thr_n_active underflow [%d] n_reg [%d] in throttle "
                    "[%p]\n", throttle->thr_n_active,
                    n_registrations, throttle);
    } else {
        throttle->thr_n_active -= n_registrations;
    }
    /* Check against limit before waking up waiters, in case limit has been
     * changed to a value less than currently active.                       
     */
    if (throttle->thr_n_active < throttle->thr_cur_limit) {
        rna_service_wait_obj_wake_up(&throttle->thr_wait);
    }
    rna_service_spinlock_release(&throttle->thr_spinlock, &flags);
}

void
rna_service_throttle_change_limit(rna_service_throttle_t *throttle,
                                  int new_limit)
{
    irq_flag_t    flags;

    if (!rna_service_spinlock_acquire(&throttle->thr_spinlock, &flags)) {
        /* This failure means we're in the process of shutting down */
        return;
    }

    if (new_limit < throttle->thr_min_limit) {
        rna_dbg_log(RNA_DBG_WARN, "attempt to change throttle=%p limit to "
                    "less than min_limit\n", throttle);
        new_limit = throttle->thr_min_limit;
    } else if (new_limit > throttle->thr_max_limit) {
        rna_dbg_log(RNA_DBG_WARN, "attempt to change throttle=%p limit to "
                    "greater than max_limit\n", throttle);
        new_limit = throttle->thr_max_limit;
    }
    rna_dbg_log(RNA_DBG_WARN, "Change ios throttle limit from %d to %d\n",
                throttle->thr_cur_limit, new_limit);
    throttle->thr_cur_limit = new_limit;
    
    rna_service_spinlock_release(&throttle->thr_spinlock, &flags);
    return;
}

/* reset an rna_service_primary_cfm_id_container_t */
INLINE void
rna_service_primary_cfm_id_container_reset(
                    rna_service_primary_cfm_id_container_t *pcic)
{
    pcic->pcic_pci.pci_generation = 0;
    pcic->pcic_pci.pci_addr.s_addr = INADDR_NONE;
}

/* Initialize an rna_service_primary_cfm_id_container_t */
INLINE void
rna_service_primary_cfm_id_container_init(
                    rna_service_primary_cfm_id_container_t *pcic)
{
#ifdef WINDOWS_KERNEL
    rna_spin_lock_init(pcic->pcic_spinlock.sp_spinlock);
#else
    rna_service_mutex_init(&pcic->pcic_mutex);
#endif /* WINDOWS_KERNEL */

    rna_service_primary_cfm_id_container_reset(pcic);
}


/*
 * Copy a primary cfm id from the specified primary cfm id container to the
 * specified primary cfm id.
 */
INLINE void
rna_service_copy_primary_cfm_id(rna_service_primary_cfm_id_container_t *source,
                                primary_cfm_id_t                       *dest)
{
#ifdef WINDOWS_KERNEL
    KLOCK_QUEUE_HANDLE lockHandle;
#endif /* WINDOWS_KERNEL */

    if (NULL == source) {
        memset(dest, 0, sizeof(*dest));
#ifdef WINDOWS_KERNEL
    } else if (rna_service_instkqd_spinlock_acquire(&source->pcic_spinlock, &lockHandle ) ) 
#else
    } else if (rna_service_mutex_lock(&source->pcic_mutex)) 
#endif /* WINDOWS_KERNEL */
    {
        /* Successfully acquired the lock */
        *dest = source->pcic_pci;
#ifdef WINDOWS_KERNEL
        rna_service_instkqd_spinlock_release(&lockHandle);
#else
        rna_service_mutex_unlock(&source->pcic_mutex);
#endif /* WINDOWS_KERNEL */
    } else {
        /*
         * Lock acquisition failed.  This failure return means we're in the
         * process of shutting down.  Do an unguarded store.
         */
        *dest = source->pcic_pci;
    }
}


/* --------------------------------- Com ---------------------------------- */

INLINE int
rna_service_com_send_cache_cmd(com_ep_handle_t                        *eph,
                               rna_service_send_buf_entry_t           *buf,
                               size_t                                  size,
                               rna_service_primary_cfm_id_container_t *pcic)
{
    /* Reduce the send buf length to the actual length of the message.  */
#ifdef WINDOWS_KERNEL
    
    /* Setting buf->length is confusing as the code doesn't seem to use it */

#else
    buf->length = cache_cmd_length((struct cache_cmd *)buf->mem);
#endif /* WINDOWS_KERNEL */

    rna_service_copy_primary_cfm_id(pcic,
                                    &((struct cfm_cmd *)buf->mem)->h.h_pci);
    bswap_cache_cmd((struct  cache_cmd*)buf->mem, 0);
    return ((int) rna_service_com_send(eph, buf, (int) size));
}


INLINE int
rna_service_com_send_cfm_cmd(com_ep_handle_t                        *eph,
                             rna_service_send_buf_entry_t           *buf,
                             size_t                                  size,
                             rna_service_primary_cfm_id_container_t *pcic)
{
#ifdef WINDOWS_KERNEL
    
    /* Setting buf->length is confusing as the code doesn't seem to use it */

#else
    /* Reduce the send buf length to the actual length of the message.  */
    buf->length = cfm_cmd_length((struct cfm_cmd *)buf->mem);
#endif /* WINDOWS_KERNEL */

    rna_service_copy_primary_cfm_id(pcic,
                                    &((struct cfm_cmd *)buf->mem)->h.h_pci);
    bswap_cfm_cmd((struct cfm_cmd*)buf->mem, 0);
    return ((int) rna_service_com_send(eph, buf, (int) size));
}


/* -------------------------- General Utilities --------------------------- */

#if !defined(MIN)
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

/*
 * Take a reference on the specified rna_service_ctx.
 *
 * Returns:
 *   TRUE   if a reference was added to the context
 *   FALSE  if a reference was not added to the context, because it's in the
 *          process of shutting down.
 */
static boolean
_ctx_add_reference(rna_service_ctx_t **ctxpp)
{
    int32_t refcnt;
    rna_service_ctx_t *ctx;
    static int refcount_overflow_countdown = 0;
            // report first overflow, and every 100000th overflow thereafter

    if ((NULL == ctxpp)
      || (NULL == (ctx = *ctxpp))) {
        return (FALSE);
    }

    /*
     * If the ctx isn't shutting down, take a reference on it.  In the very
     * rare case of a race, this may take a couple of tries.  Note that if a
     * race occurs, one contender successfully exits the loop on each iteration.
     *
     * NOTE that we're careful not to take a reference if the
     * CTX_REF_COUNT_SHUTTING_DOWN_FLAG is set, which is important to assure
     * that only one thread releases a reference and finds both that it was the
     * last reference and that the CTX_REF_COUNT_SHUTTING_DOWN_FLAG is set, so
     * goes on to free the ctx).  If we acquired a reference while the
     * CTX_REF_COUNT_SHUTTING_DOWN_FLAG was set, we'd have to release it, and
     * in doing so might find it was the last reference, allowing multiple
     * threads concurrently executing this routine to sequentially come to the
     * same conclusion.
     */
    do {
        refcnt = rna_service_atomic_read(&ctx->cx_ref_count);
    } while ((0 == (refcnt & CTX_REF_COUNT_SHUTTING_DOWN_FLAG))
      && (!rna_service_atomic_test_and_set(&ctx->cx_ref_count,
                                           refcnt,
                                           refcnt+1)));

    if (((refcnt & ~CTX_REF_COUNT_SHUTTING_DOWN_FLAG) > 500000)
      && (0 == refcount_overflow_countdown--)) {
        rna_dbg_log(RNA_DBG_WARN,
                    "Possible ctx reference leak: %x\n",
                    rna_service_atomic_read(&ctx->cx_ref_count));
        refcount_overflow_countdown = 100000;
    }

    /*
     * If the ctx isn't shutting down, return TRUE.
     */
    if (refcnt & CTX_REF_COUNT_SHUTTING_DOWN_FLAG) {
        // (Note that we fell out of the above loop without taking a reference
        // in this case)
        *ctxpp = NULL;
        return (FALSE);
    } else {
        return (TRUE);
    }
} 

/* Wrapper for _ctx_add_reference() */
#define ctx_add_reference(_ctxpp)                                             \
(                                                                             \
    rna_dbg_log(RNA_DBG_VERBOSE,                                              \
              "ctx_add_reference ref_count before [%x]\n",                    \
              ((NULL == (_ctxpp)) || (NULL == *(_ctxpp)))                     \
                        ? 0xdead                                              \
                        : rna_service_atomic_read(&(*_ctxpp)->cx_ref_count)), \
    _ctx_add_reference((_ctxpp))                                              \
) 


static void
free_ctx(rna_service_ctx_t **ctxpp)
{
    int i;
    rna_service_ctx_t *ctx = *ctxpp;

#if defined(WINDOWS_KERNEL) && !(defined(DBG))
    /* This symbol is used, but the MS compiler needs this...
     */
    ctx;
#endif

    rna_service_assert_timer_canceled(
        &ctx->cx_primary_cfm_heartbeat_timer.sto_timer);
    rna_service_assert_timer_canceled(
        &ctx->cx_non_primary_cfm_ping_timer.sto_timer);
    rna_service_assert_timer_canceled(
        &ctx->cx_send_waiting_cfm_msgs_timer.sto_timer);
    rna_service_assert_timer_canceled(
        &ctx->cx_send_shutdown_request_timer.sto_timer);
    rna_service_assert_timer_canceled(
        &ctx->cx_reconnect_cfms_timer_object.sto_timer);
    rna_service_assert_timer_canceled(
        &ctx->cx_primary_cfm_registration_timer.sto_timer);
    rna_service_assert_timer_canceled(
        &ctx->cx_cs_cfm_registration_timer.sto_timer);
    rna_service_assert_timer_canceled(
        &ctx->cx_ping_mds_timer_object.sto_timer);
    rna_service_assert_timer_canceled(
        &ctx->cx_reconnect_mds_timer_object.sto_timer);

    /*
     * We're about to free the ctx.  Before doing so, check if there are still
     * any outstanding allocations from any of this ctx's mempools.
     */
    for (i = 0; i < MEMPOOL_ID_INVALID; i++) {
        if (rna_service_atomic_read(&(*ctxpp)->cx_mempools[i].mp_alloc_count)
                                                                      != 0) {
            rna_dbg_log(RNA_DBG_ERR,
                        "memory leak for mempool %d: %d\n",
                        i,
                        rna_service_atomic_read(
                                &(*ctxpp)->cx_mempools[i].mp_alloc_count));
        }
    }

    rna_dbg_log(RNA_DBG_INFO, "rna_service ctx %p freed\n",
                *ctxpp);
    /* Make use-after-free easier to spot */
    memset(*ctxpp, 0, sizeof(**ctxpp));
    rna_service_free(sizeof(**ctxpp), *ctxpp);
    *ctxpp = NULL;

    rna_service_print_timer_debug();
}


/*
 * Release a reference on the specified ctx.  If the ctx is shutting down and
 * this is the last reference, the ctx is freed.
 *
 * Returns:
 *    FALSE if the reference count is already zero, so wasn't decremented
 *    TRUE  otherwise
 */
INLINE boolean
_ctx_release_reference(rna_service_ctx_t **ctxpp)
{
    int32_t refcnt;

    /*
     * Release a reference on the specified ctx, being careful not to decrement
     * it below zero.  If the ctx is shutting down and our reference was the
     * final reference, free the ctx.
     *
     * Note that multiple iterations of this loop may be necessary if multiple
     * threads are attempting to add or release references on this context
     * concurrently.  In case of such a race, one of the racers succeeds in
     * each iteration of the loop.
     */
    for (;;) {
        refcnt = rna_service_atomic_read(&(*ctxpp)->cx_ref_count);
        if (0 == (refcnt & ~CTX_REF_COUNT_SHUTTING_DOWN_FLAG)) {
            return (FALSE); // decrement would cause a ref count underflow
        } else if (rna_service_atomic_test_and_set(&(*ctxpp)->cx_ref_count,
                                                   refcnt,
                                                   refcnt-1)) {
            /*
             * Decrement was successful.  If we just removed the last reference
             * and the context is shutting down, then the ctx can now be freed.
             */
            if ((CTX_REF_COUNT_SHUTTING_DOWN_FLAG | 1) == refcnt) {
                /* This ctx can be freed. */
                rna_service_ctx_t *ctx = *ctxpp;
                free_ctx(&ctx);
            }
            break;  // reference released; we're finished
        }
    }
    return (TRUE);
}

/* Wrapper for _ctx_release_reference() */
#define ctx_release_reference(_ctxpp)                                         \
{                                                                             \
    rna_dbg_log(RNA_DBG_VERBOSE, "ctx_release_reference before [%x]\n",       \
                rna_service_atomic_read(&((*_ctxpp)->cx_ref_count)));         \
    if ((NULL != (_ctxpp))                                                    \
      && (NULL != *(_ctxpp))) {                                               \
        if (!_ctx_release_reference((_ctxpp))) {                              \
            rna_dbg_log(RNA_DBG_ERR,                                          \
                        "cx_ref_count is already 0!\n");                      \
        }                                                                     \
    }                                                                         \
}


/*
 * Set an rna_service_ctx_t's CTX_REF_COUNT_SHUTTING_DOWN_FLAG.
 * An rna_service_ctx_t can't be freed until its
 * CTX_REF_COUNT_SHUTTING_DOWN_FLAG is set.
 */
INLINE void
_set_ctx_shutting_down_flag(rna_service_ctx_t *ctx)
{
    int32_t refcnt;

    if ((NULL != ctx)) {
        /*
         * In the very rare case of a race, this may take a couple of tries.
         * Note that if a race occurs, one contender successfully exits the
         * loop on each iteration.
         */
        do {
            refcnt = rna_service_atomic_read(&ctx->cx_ref_count);
        } while (!rna_service_atomic_test_and_set(
                                          &ctx->cx_ref_count,
                                          refcnt,
                                          refcnt |
                                            CTX_REF_COUNT_SHUTTING_DOWN_FLAG));

        /*
         * If there are no references on this ep, it can now be removed.
         */
        if (CTX_REF_COUNT_SHUTTING_DOWN_FLAG ==
                                rna_service_atomic_read(&ctx->cx_ref_count)) {
            /* This ctx can be freed.  */
            free_ctx(&ctx);
        }
    }
}

/* Wrapper for _set_ctx_shutting_down_flag() */
#define set_ctx_shutting_down_flag(_ctx)                                      \
    _set_ctx_shutting_down_flag((_ctx));                                      \
    rna_trace("set_ctx_shutting_down_flag ref_count after [%x]\n",       \
              rna_service_atomic_read(&(_ctx)->cx_ref_count));


/*
 * Free all the messages in the specified message queue.
 */
static void
free_messages(rna_service_ctx_t *ctx, YAQ_HEAD *headp)
{
    rna_service_message_buffer_internal_t *ibuf;

    while (!YAQ_EMPTY(headp)) {
        ibuf = YAQ_OBJECT(rna_service_message_buffer_internal_t,
                          h.rmbi_link,
                          YAQ_FIRST(headp));
        YAQ_REMOVE(&ibuf->h.rmbi_link);
        rna_service_free_message_buffer(ctx, &ibuf->u.rmbi_message_buffer);
    }
}


/*
 * Convert a pointer to an rna_service_message_buffer_t to a pointer to the
 * rna_service_message_buffer_internal_t that contains it.
 */
INLINE rna_service_message_buffer_internal_t *
mbuf_to_ibuf(rna_service_message_buffer_t *mbuf)
{
#ifdef WINDOWS_KERNEL
    return ((rna_service_message_buffer_internal_t *)
                ((char *)mbuf - FIELD_OFFSET(rna_service_message_buffer_internal_t,
                                        u.rmbi_message_buffer)));

#else
    return ((rna_service_message_buffer_internal_t *)
                ((char *)mbuf - offsetof(rna_service_message_buffer_internal_t,
                                        u.rmbi_message_buffer)));
#endif /* WINDOWS_KERNEL */
}


/**
 * Return the ordinal of the metadata server that owns the metadata partition
 * that corresponds with the specified metadata hash key.
 *
 * The ctx->cx_md_mutex must be held on entry.
 */
INLINE uint32_t
hash_key_to_md_ordinal(rna_service_ctx_t *ctx, rna_hash_key_t *hash_key)
{
    rna_service_assert(NULL != ctx);
    rna_service_assert_locked(&ctx->cx_md_mutex);

    if (0 == ctx->cx_partition_map.pm_generation) {
        /* We haven't yet received a partition map from the CFM */
        rna_dbg_log(RNA_DBG_ERR,
                    "Called before initial partition map received\n");
        return (0);
    }

    return (ctx->cx_partition_map.pm_partition_assignments[
                                        rna_service_hashkey_to_partition(
                                                hash_key,
                                                ctx->cx_hash_partition_bitmask)
                                                          ]);
}


/**
 * Return the ordinal of the metadata server that owns the metadata partition
 * that corresponds with the specified rid (record ID).
 *
 * NOTE that RNA_SERVICE_METADATA_RID_TO_PARTITION is currently implemented for
 * user-level use only.
 *
 * The ctx->cx_md_mutex must be held on entry.
 */
INLINE uint32_t
rid_to_md_ordinal_user_space_only(rna_service_ctx_t *ctx, uint64_t rid)
{
    rna_service_assert(NULL != ctx);
    rna_service_assert_locked(&ctx->cx_md_mutex);

    if (0 == ctx->cx_partition_map.pm_generation) {
        /* We haven't yet received a partition map from the CFM */
        rna_dbg_log(RNA_DBG_ERR,
                    "Called before initial partition map received\n");
        return (0);
    }

    return (ctx->cx_partition_map.pm_partition_assignments[
                                    RNA_SERVICE_METADATA_RID_TO_PARTITION(rid)
                                                          ]);
}


/**
 * Invoked by a workq thread to invoke a response callback.
 */
static rna_service_workq_cb_ret_t
invoke_response_callback(rna_service_workq_cb_arg_t workq_context)
{
    invoke_callback_work_ctx_t *wctx =
                                (invoke_callback_work_ctx_t *) workq_context;
    rna_service_ctx_t *ctx;
    rna_service_message_buffer_internal_t *ibuf;

    rna_service_assert(NULL != wctx);

    ctx = wctx->mwx_ctx;
    ibuf = wctx->mwx_message_sent;

    rna_service_assert(NULL != ctx);
    if (NULL != ibuf) {
        rna_service_assert(MESSAGE_BUFFER_INTERNAL_WATERMARK_ALLOCATED ==
                                                    ibuf->h.rmbi_watermark);
    }
    if (wctx->mwx_response_received != NULL) {
        rna_service_assert(
            MESSAGE_BUFFER_INTERNAL_WATERMARK_ALLOCATED ==
                (mbuf_to_ibuf(wctx->mwx_response_received))->h.rmbi_watermark);
    }

    if (ctx->cx_flags & CX_FLAG_SHUTTING_DOWN) {
        /* Don't invoke any callbacks if we're shutting down. */
        if (ibuf != NULL) {
            rna_service_free_message_buffer(ctx, &ibuf->u.rmbi_message_buffer);
        }
        if (wctx->mwx_response_received != NULL) {
            rna_service_free_message_buffer(ctx, wctx->mwx_response_received);
        }
    } else if (RNA_SERVICE_EVENT_NONE != wctx->mwx_event) {
        /* This is an asynchronous event */
        if (NULL != ctx->cx_params.rsp_event_callback) {
            ctx->cx_params.rsp_event_callback(ctx, wctx->mwx_event);
        }
    } else if (NULL == ibuf) {
        /* This is an asynchronous message */
        if (NULL != ctx->cx_params.rsp_async_msg_callback) {
            ctx->cx_params.rsp_async_msg_callback(ctx,
                                                  wctx->mwx_response_received);
        } else {
            rna_service_free_message_buffer(ctx, wctx->mwx_response_received);
        }
    } else {
        /* This is a synchronous message response */
        rna_service_assert(NULL != ibuf);
        if (NULL != ibuf->h.rmbi_response_callback) {
            rna_dbg_log(RNA_DBG_VERBOSE,
                        "invoking response callback for message ID "
                        "[%"PRIx64"]\n", ibuf->h.rmbi_req_msg_id);
            ibuf->h.rmbi_response_callback(ctx,
                                          &ibuf->u.rmbi_message_buffer,
                                           wctx->mwx_response_received,
                                           RNA_SERVICE_RESPONSE_STATUS_SUCCESS);
            rna_dbg_log(RNA_DBG_VERBOSE,
                        "returned from response callback\n");
        } else {
            rna_dbg_log(RNA_DBG_VERBOSE,
                        "no response callback specified for message ID "
                        "[%"PRIx64"]\n", ibuf->h.rmbi_req_msg_id);
            rna_service_free_message_buffer(ctx, &ibuf->u.rmbi_message_buffer);
            rna_service_free_message_buffer(ctx, wctx->mwx_response_received);
        }
    }

    mempool_free(ctx, MEMPOOL_ID_MD_RESPONSE_WORK_CTX, (void *)wctx);

    /*
     * Release the ctx reference that was added in
     * work_queue_add_callback.
     */
    ctx_release_reference(&ctx);

    /*
     * NOTE that rna_service workq callbacks must use
     * RNA_SERVICE_WORKQ_CB_RETURN instead of return.
     */
    RNA_SERVICE_WORKQ_CB_RETURN(0);
}


/*
 * Queue the specified callback (either message response callback, asynchronous
 * message callback, or asynchronous event callback), to be invoked by a work
 * queue thread.
 */
static int
work_queue_add_callback(rna_service_ctx_t *ctx, 
                        rna_service_message_buffer_internal_t *message_sent,
                        rna_service_message_buffer_t *response_received,
                        int event)
{
    invoke_callback_work_ctx_t *wctx;
    int ret;

    rna_service_assert(NULL != ctx);
    if (NULL != message_sent) {
        rna_service_assert(MESSAGE_BUFFER_INTERNAL_WATERMARK_ALLOCATED ==
                                            message_sent->h.rmbi_watermark);
    }
    if (NULL != response_received) {
        rna_service_assert(NULL != response_received);
        rna_service_assert(
                MESSAGE_BUFFER_INTERNAL_WATERMARK_ALLOCATED ==
                        (mbuf_to_ibuf(response_received))->h.rmbi_watermark);
    }

    /*
     * Since *wctx will include a reference to an rna_service_ctx_t, a ctx
     * reference must be taken.  This reference must be released by
     * invoke_response_callback().
     */
    if (ctx_add_reference(&ctx)) {
        wctx = (invoke_callback_work_ctx_t *)
                        mempool_alloc(ctx, MEMPOOL_ID_MD_RESPONSE_WORK_CTX, 0);
        if (NULL == wctx) {
            rna_dbg_log(RNA_DBG_WARN,
                        "Memory allocation failed!\n");
            ctx_release_reference(&ctx);
            return (ENOMEM);
        }
        
        wctx->mwx_ctx = ctx;
        wctx->mwx_message_sent = message_sent;
        wctx->mwx_response_received = response_received;
        wctx->mwx_event = event;


        // TODO: Dummy routine
        RNA_SERVICE_WORK_INIT(&wctx->mwx_work_obj,
                              invoke_response_callback,
                              (rna_service_workq_cb_arg_t)wctx);

        /*
         * (All returns from rna_service_workq_add are considered successful
         * from the perspective of this routine).
         */
        ret = rna_service_workq_add(ctx->cx_response_callback_work_queue,
                                   &wctx->mwx_work_obj);
        if (0 != ret) {
            rna_dbg_log(RNA_DBG_WARN,
                        "Add failed for cx_response_callback_work_queue: "
                        "ret [%d] sent [%p] resp [%p] event [%d]\n",
                        ret,
                        wctx->mwx_message_sent,
                        wctx->mwx_response_received,
                        wctx->mwx_event);
        }
    }
    return (0);
}


/*
 * Search for a queued registration having the specified
 * rna_service_message_type_t, calling the specified comparator function
 * whenever one is encountered.  Stop the search when the comparator
 * function indicates to do so.
 *
 * Locking:
 *     The cx_cfm_mutex must be held on entry.
 */
static boolean
find_registration(rna_service_ctx_t           *ctx,
                  uint8_t                      msg_type,
                  find_registration_compare_fn compare_fn,
                  void                        *compare_fn_arg)
{
    YAQ_LINK                              *lnkp;
    rna_service_message_buffer_internal_t *ibuf;
    boolean                                found = FALSE;

    rna_service_assert_locked(&ctx->cx_cfm_mutex);

    YAQ_FOREACH(&ctx->cx_registered, lnkp) {
        ibuf = YAQ_OBJECT(rna_service_message_buffer_internal_t,
                          h.rmbi_link,
                          lnkp);
        if ((ibuf->h.rmbi_msg_type == msg_type)
          && ((found = compare_fn(ctx, ibuf, compare_fn_arg)) == TRUE)) {
            break;
        }
    }
    if (!found) {
        YAQ_FOREACH(&ctx->cx_registrations_waiting_for_reply, lnkp) {
            ibuf = YAQ_OBJECT(rna_service_message_buffer_internal_t,
                              h.rmbi_link,
                              lnkp);
            if ((ibuf->h.rmbi_msg_type == msg_type)
              && ((found = compare_fn(ctx, ibuf, compare_fn_arg)) == TRUE)) {
                break;
            }
        }
    }
    return (found);
}


/* ------------------------------ Timeouts ------------------------------- */

/*
 * An rna_service_timer function that's invoked when we've timed out waiting
 * for a response from a metadata server.  Invoke an rna_service callback to
 * notify the user.
 *
 * (Note that it's possible that this is a 'fake' timeout resulting from
 * an overabundance of messages queued waiting to be sent).
 */
static void
md_response_timed_out(uint64_t param)
{
    rna_service_message_buffer_internal_t
                        *ibuf = (rna_service_message_buffer_internal_t *)param;
    rna_service_ctx_t   *ctx;
    int                  md_ordinal;
    rna_service_response_status_t
                         status;

    ctx = ibuf->h.rmbi_ctx;
    rna_service_assert(NULL != ctx);
    /*
     * Note that there's no need to call ctx_add_reference, since a reference
     * already exists for h.rmbi_ctx pointer to the ctx (see
     * rna_service_alloc_message_buffer()).
     */

    rna_dbg_log(RNA_DBG_INFO,
                "timeout of response message ID [%"PRIx64"]\n",
                ibuf->h.rmbi_req_msg_id);

    if (!rna_service_mutex_lock(&ctx->cx_md_mutex)) {
        // This failure means we're in the process of shutting down; do nothing
        return;
    }

    /*
     * Check if this message timed out previously, but timeout processing was
     * deferred.
     */
    if (0 == (ibuf->h.rmbi_flags & RMBI_FLAG_TIMED_OUT)) {
        /* This message hasn't previously timed out */
        if YAQ_EMPTY(&ibuf->h.rmbi_link) {
            /*
             * Another thread (likely one running send_waiting_md_messages)
             * has a send (or a com_get_send_buf -- see send_md_generic) in
             * progress for this message buffer.  Mark it as timed out, but
             * defer timeout processing.  The timeout will be processed once
             * the operation in progress has finished.
             */
            ibuf->h.rmbi_flags |= RMBI_FLAG_TIMED_OUT;
            rna_service_mutex_unlock(&ctx->cx_md_mutex);
            return;
        } else {
            /*
             * Nothing else is operating on this message buffer, so timeout
             * processing can be done now.
             */
            YAQ_REMOVE(&ibuf->h.rmbi_link);
        }
    } else {
        /*
         * This message timed out previously.  The operation that was in
         * progress (and that deferred the timed out processing until now) has
         * now completed, so the deferred timeout processing can now be done.
         */
    }

    if (--ctx->cx_partitions[ibuf->h.rmbi_partition].pi_msgs_outstanding_cnt
                                                                        < 0) {
        rna_dbg_log(RNA_DBG_WARN,
                    "msgs_outstanding_cnt underflow for partition %d!\n",
                    ibuf->h.rmbi_partition);
        ctx->cx_partitions[ibuf->h.rmbi_partition].pi_msgs_outstanding_cnt = 0;
    }
    if (ibuf->h.rmbi_watermark != MESSAGE_BUFFER_INTERNAL_WATERMARK_QUEUED) {
        rna_dbg_log(RNA_DBG_WARN,
                    "queued message has incorrect state: %"PRIx64"\n",
                    ibuf->h.rmbi_watermark);
    }
    ibuf->h.rmbi_watermark = MESSAGE_BUFFER_INTERNAL_WATERMARK_ALLOCATED;
    /*
     * If we're not yet connected to the MD this message was to have been sent
     * to, then the send timed out.  Otherwise the receive timed out.
     *
     * Get the ordinal of the MD for this message's hash table partition.
     */
    if (PREMATURE_PARTITION != ibuf->h.rmbi_partition) {
        md_ordinal = ctx->cx_partition_map.pm_partition_assignments[
                                                        ibuf->h.rmbi_partition];
        rna_service_assert(md_ordinal < NUM_MD_ORDINALS);
        if ((NULL == ctx->cx_md_table[md_ordinal])
          || !(ctx->cx_md_table[md_ordinal]->mdi_cflags &
                                                    MD_INFO_CFLAG_CONNECTED)) {
            status = RNA_SERVICE_RESPONSE_STATUS_SEND_TIMED_OUT;
        } else {
            status = RNA_SERVICE_RESPONSE_STATUS_RESPONSE_TIMED_OUT;
        }
    } else {
        status = RNA_SERVICE_RESPONSE_STATUS_SEND_TIMED_OUT;
    }

    rna_service_mutex_unlock(&ctx->cx_md_mutex);

    if (NULL == ibuf->h.rmbi_response_callback) {
        /* The user hasn't requested a callback, so we're finished */
        rna_service_free_message_buffer(ctx, &ibuf->u.rmbi_message_buffer);
    } else {
        /* invoke the user's callback */
        ibuf->h.rmbi_response_callback(ctx,
                                     &ibuf->u.rmbi_message_buffer,
                                     NULL,
                                     status);
    }
}

/*
 * An rna_service_timer function that's invoked when we've timed out waiting
 * for a response from a configuration manager.  Invoke an rna_service callback
 * to notify the user.
 */
static void
cfm_response_timed_out(uint64_t param)
{
    rna_service_message_buffer_internal_t
                        *ibuf = (rna_service_message_buffer_internal_t *)param;
    rna_service_ctx_t   *ctx;
    rna_service_response_status_t
                         status;

    ctx = ibuf->h.rmbi_ctx;
    rna_service_assert(NULL != ctx);
    /*
     * Note that there's no need to call ctx_add_reference, since a reference
     * already exists for h.rmbi_ctx pointer to the ctx (see
     * rna_service_alloc_message_buffer()).
     */

    if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
        // This failure means we're in the process of shutting down; do nothing
        return;
    }

    /*
     * Check if this message timed out previously, but timeout processing was
     * deferred.
     */
    if (0 == (ibuf->h.rmbi_flags & RMBI_FLAG_TIMED_OUT)) {
        /* This message hasn't previously timed out */
        if YAQ_EMPTY(&ibuf->h.rmbi_link) {
            /*
             * Another thread (likely one running send_waiting_cfm_messages)
             * has a send (or a com_get_send_buf -- see send_md_generic) in
             * progress for this message buffer.  Mark it as timed out, but
             * defer timeout processing.  The timeout will be processed once
             * the operation in progress has finished.
             */
            ibuf->h.rmbi_flags |= RMBI_FLAG_TIMED_OUT;
            rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
            return;
        } else {
            /*
             * Nothing else is operating on this message buffer, so the timeout
             * processing can be done now.
             */
            YAQ_REMOVE(&ibuf->h.rmbi_link);
        }
    } else {
        /*
         * This message timed out previously.  The operation that was in
         * progress (and that deferred the timed out processing until now) has
         * now completed, so the deferred timeout processing can now be done.
         */
    }
    
    if (ibuf->h.rmbi_watermark != MESSAGE_BUFFER_INTERNAL_WATERMARK_QUEUED) {
        rna_dbg_log(RNA_DBG_WARN,
                    "queued message has incorrect state: %"PRIx64"\n",
                    ibuf->h.rmbi_watermark);
    }
    ibuf->h.rmbi_watermark = MESSAGE_BUFFER_INTERNAL_WATERMARK_ALLOCATED;

    /*
     * If we're not connected to the CFM this message was to have been sent
     * to, then the send timed out.  Otherwise the receive timed out.
     */
    if (com_eph_isempty(&ctx->cx_primary_cfm_eph)) {
        status = RNA_SERVICE_RESPONSE_STATUS_SEND_TIMED_OUT;
    } else {
        status = RNA_SERVICE_RESPONSE_STATUS_RESPONSE_TIMED_OUT;
    }

    rna_service_mutex_unlock(&ctx->cx_cfm_mutex);

    if (NULL == ibuf->h.rmbi_response_callback) {
        /* The user hasn't requested a callback, so we're finished */
        rna_service_free_message_buffer(ctx, &ibuf->u.rmbi_message_buffer);
    } else {
        /* invoke the user's callback */
        ibuf->h.rmbi_response_callback(ctx,
                                     &ibuf->u.rmbi_message_buffer,
                                     NULL,
                                     status);
    }
}


/* ---------------------- Configuration Managers  ------------------------ */
/* ----- CFM connect, registration, promotion, disconnect, reconnect ----- */

/**
 * Search the list of connected configuration managers for the CFM having the
 * specified address.
 *
 * Locking:
 *    The ctx->cx_cfm_mutex must be held on entry.
 */
static boolean
find_connected_cfm_by_address(rna_service_ctx_t *ctx,
                              struct in_addr    *addr,
                              com_ep_handle_t   *eph)
{
    cfm_info_t *ci;

    rna_service_assert(NULL != ctx);

    rna_service_assert_locked(&ctx->cx_cfm_mutex);

    if (NULL == addr) {
        goto not_found;
    }

    for (ci = ctx->cx_connected_cfms;
         ci < &ctx->cx_connected_cfms[RNA_SERVICE_CFMS_MAX];
         ci++) {

        if (ci->ci_eph.eph_dst_in.sin_addr.s_addr == addr->s_addr) {
            if (NULL != eph) {
                *eph = ci->ci_eph;
            }
            return (TRUE);
        }
    }

not_found:
    if (NULL != eph) {
        com_init_eph(eph);
    }
    return (FALSE);
}


/**
 * Find the configuration manager having the specified endpoint in the list of
 * connected configuration managers.
 *
 * Locking:
 *    The ctx->cx_cfm_mutex must be held on entry.
 */
static cfm_info_t *
find_connected_cfm_by_eph(rna_service_ctx_t *ctx, com_ep_handle_t *eph)
{
    cfm_info_t *ci;

    rna_service_assert(NULL != ctx);
    rna_service_assert_locked(&ctx->cx_cfm_mutex);

    if (NULL == eph) {
        return (NULL);
    }

    for (ci = ctx->cx_connected_cfms;
         ci < &ctx->cx_connected_cfms[RNA_SERVICE_CFMS_MAX];
         ci++) {

        if (com_eph_equal(&ci->ci_eph, eph)) {
            return (ci);
        }
    }

    return (NULL);
}


/**
 * An rna_service_timer function that's invoked to schedule
 * send_waiting_cfm_msgs on a workq.
 */
static void
delayed_send_waiting_cfm_msgs(uint64_t context)
{
    send_waiting_msgs_work_ctx_t *wctx =
                                 (send_waiting_msgs_work_ctx_t *)context;

    rna_service_assert(wctx != NULL);
    rna_service_assert(wctx->swx_ctx != NULL);

    /*
     * (All returns from rna_service_workq_add are considered
     * successful from the perspective of this routine).
     */
    (void) rna_service_workq_add(wctx->swx_ctx->cx_cfm_work_queue,
                                 &wctx->swx_work_obj);
}


/**
 * An rna_service_timer function that's invoked to trigger an
 * RNA_SERVICE_EVENT_SEND_SHUTDOWN_REQUEST_TIMEOUT event.
 */
static void
shutdown_request_send_timed_out(uint64_t context)
{
    rna_service_ctx_t   *ctx = (rna_service_ctx_t *) context;

    ctx->cx_send_shutdown_request_timer_is_set = FALSE;
    work_queue_add_callback(ctx,
                            NULL,
                            NULL,
                            RNA_SERVICE_EVENT_SEND_SHUTDOWN_REQUEST_TIMEOUT);
}


/*
 * Schedule send_waiting_cfm_msgs() to send CFM messages that couldn't be sent
 * immediately because no sendbufs were available, or because we'd lost contact
 * with the primary CFM.
 *
 * Locking:
 *    The ctx->cx_cfm_mutex must be held on entry.
 */
static void
schedule_waiting_cfm_msgs(rna_service_ctx_t *ctx, int delay_sec)
{
    send_waiting_msgs_work_ctx_t *wctx;

    rna_service_assert(NULL != ctx);
    rna_service_assert_locked(&ctx->cx_cfm_mutex);

    /*
     * If send_waiting_cfm_msgs() hasn't already been scheduled, schedule it
     * now.
     */
    if (!(ctx->cx_cfm_flags & CTX_CFM_FLAG_RESEND_SCHEDULED)) {
        rna_dbg_log(RNA_DBG_VERBOSE,
                    "scheduling send_waiting_cfm_msgs\n");
        ctx->cx_cfm_flags |= CTX_CFM_FLAG_RESEND_SCHEDULED;
        wctx = &ctx->cx_cfm_wctx;

        wctx->swx_ctx = ctx;

        RNA_SERVICE_WORK_INIT(&wctx->swx_work_obj,
                              send_waiting_cfm_msgs,
                              (rna_service_workq_cb_arg_t)wctx);

        /*
         * Since *wctx includes a reference to an rna_service_ctx_t, a ctx
         * reference must be taken.  This reference must be released by
         * send_waiting_cfm_msgs().
         */
        if (ctx_add_reference(&ctx)) {
            if (0 == delay_sec) {
                /*
                 * Schedule send_waiting_cfm_msgs to run immediately.
                 * (All returns from rna_service_workq_add are considered
                 * successful from the perspective of this routine).
                 */
                (void) rna_service_workq_add(ctx->cx_cfm_work_queue,
                                             &wctx->swx_work_obj);
            } else {
                /*
                 * Schedule send_waiting_cfm_msgs to run after the specified
                 * delay.  (All returns from rna_service_workq_add are
                 * considered successful from the perspective of this routine).
                 */
                rna_service_timer_set(
                                ctx->cx_private,
                                &ctx->cx_send_waiting_cfm_msgs_timer,
                                delayed_send_waiting_cfm_msgs,
                                (uint64_t)wctx,
                                delay_sec);
            }
        }
    }
}


/*
 * Either a connected CFM has just become the primary CFM, or a connection has
 * just been established to the primary CFM.  In either case, send the necessary
 * introductory messages to it.
 *
 * Locking:
 *     The cx_cfm_mutex must be held on entry.
 *     If this library's user is a cache server, the cx_md_mutex must be held
 *     on entry.
 */
static void
primary_cfm_connected(rna_service_ctx_t *ctx)
{
    rna_service_assert_locked(&ctx->cx_cfm_mutex);

    ctx->cx_cfm_flags |= CTX_CFM_FLAG_MUST_REGISTER;

    /*
     * Any messages that were waiting for a reply from the cfm must now
     * be re-sent, as must any mount/block device and storage path
     * registrations from non-cache servers.  If we're a cache server
     * we need to clear out CTX_CFM_FLAG_INITIAL_REGISTRATIONS_COMPLETE
     * flag so we don't get registration end messages later when were sending
     * device registration messages in response to the query causing the CFM to
     * believe the other cache devices have failed.
     */
    if (RNA_SERVICE_USER_TYPE_CACHE_SERVER == ctx->cx_params.rsp_user_type) {
        ctx->cx_cfm_flags &= ~(CTX_CFM_FLAG_INITIAL_REGISTRATIONS_COMPLETE |
                              CTX_CFM_FLAG_MUST_SEND_CACHEDEV_REGISTRATION_END) ;
    } else {
        YAQ_MERGE_HEAD(&ctx->cx_cfm_registrations_waiting_to_send,
                       &ctx->cx_registrations_waiting_for_reply);
        YAQ_MERGE_HEAD(&ctx->cx_cfm_registrations_waiting_to_send,
                       &ctx->cx_registered);
    }
    YAQ_MERGE_HEAD(&ctx->cx_cfm_msgs_waiting_to_send,
                   &ctx->cx_cfm_waiting_for_reply);

    /*
     * If the user is a cache server, all MD connection info
     * must be sent to the new CFM.
     */
    if (RNA_SERVICE_USER_TYPE_CACHE_SERVER == ctx->cx_params.rsp_user_type) {
        md_info_t **md_table_first = ctx->cx_md_table_first;
        md_info_t **md_table_last = ctx->cx_md_table_last;
        md_info_t **mdipp;

        rna_service_assert_locked(&ctx->cx_md_mutex);

        if (md_table_first != NULL) {
            for (mdipp = md_table_first;
                 mdipp <= md_table_last;
                 mdipp++) {

                if (NULL != *mdipp) {
                    (*mdipp)->mdi_iflags |=
                            MD_INFO_IFLAG_MUST_SEND_MD_CONNECTION_INFO;
                    ctx->cx_md_flags |=
                            CTX_MD_FLAG_MUST_SEND_MD_CONNECTION_INFO;
                }
            }
        }
    }

    /*
     * Schedule send_waiting_cfm_msgs() to send the above messages.
     */
    schedule_waiting_cfm_msgs(ctx, 0);
}


/*
 * Demote the old primary CFM.
 *
 * Locking:
 *     The cx_cfm_mutex must be held on entry.
 */
static void
rnas_demote_cfm(rna_service_ctx_t *ctx,
                cfm_info_t        *ci,
                primary_cfm_id_t  *demoted_pci) // primary cfm ID of the cfm
                                                // that's being demoted
{
    struct cfm_cmd               *send_cmd;
    rna_service_send_buf_entry_t *send_buf;
    size_t                       ret;

    rna_service_assert_locked(&ctx->cx_cfm_mutex);

    rna_dbg_log(RNA_DBG_INFO,
                "["RNA_ADDR_FORMAT"] is no longer the "
                "primary CFM\n",
                RNA_ADDR(ctx->cx_primary_cfm_eph.eph_dst_in.sin_addr));

    /*
     * In case the old primary isn't aware that it's no longer the primary,
     * tell it.
     */
    ret = rna_service_com_get_send_buf(&ctx->cx_primary_cfm_eph,
                                       &send_buf,
                                       TRUE,
                                       NULL);
    if ((0 == ret) && (send_buf != NULL)) {
#if defined(LINUX_KERNEL) || defined(WINDOWS_KERNEL)
        send_cmd = (struct cfm_cmd *)(com_get_send_buf_mem(send_buf));
#else
        send_cmd = (struct cfm_cmd *) send_buf->mem;
#endif
        memset(send_cmd, 0, sizeof(send_cmd->h));

        send_cmd->h.h_type = CONF_MGR_CONTROL_REJECT;
        send_cmd->u.cfm_control_reject.ccr_rejected_id = *demoted_pci;
        ret = rna_service_com_send_cfm_cmd(&ctx->cx_primary_cfm_eph,
                                           send_buf,
                                           cfm_cmd_length(send_cmd),
                                           &ctx->cx_primary_cfm_id);
        if (0 != ret) {
            /*
             * The previous primary CFM may have died, in which case this
             * message is moot.
             */
            rna_dbg_log(RNA_DBG_INFO, 
                        "Failed to send reject primary CFM message: "
                        "%ld\n", ret);
        }
    }

    /* If the caller didn't provide the demotee's ci, find it */
    if (NULL == ci) {
        ci = find_connected_cfm_by_eph(ctx, &ctx->cx_primary_cfm_eph);
    }
    /* If this CFM has a registered stats buf, de-register it.  */
    if (NULL != ci) {
        rna_service_com_deregister_rdma_buffer(ctx->cx_com_instance,
                                               &ctx->cx_primary_cfm_eph,
                                               &ci->ci_stat_info);
        memset(&ci->ci_stat_info, 0, sizeof(ci->ci_stat_info));
    }

    com_init_eph(&ctx->cx_primary_cfm_eph);
    ctx->cx_cfm_flags &= ~(CTX_CFM_FLAG_MUST_REGISTER |
                           CTX_CFM_FLAG_MUST_SEND_CACHEDEV_REGISTRATION_END);
}


/**
 * Add the specified configuration manager to the list of connected
 * configuration managers.
 *
 * Locking:
 *    The ctx->cx_cfm_mutex must be held on entry.
 *     If this library's user is a cache server, the cx_md_mutex must be held
 *     on entry.
 */
static void
add_connected_cfm(rna_service_ctx_t *ctx, com_ep_handle_t *eph)
{
    unsigned int i;
    cfm_info_t *ci;

    rna_service_assert(NULL != ctx);
    rna_service_assert(NULL != eph);

    rna_dbg_log(RNA_DBG_INFO, "adding cfm "RNA_ADDR_FORMAT"\n",
                RNA_ADDR(eph->eph_dst_in.sin_addr));

    rna_service_assert_locked(&ctx->cx_cfm_mutex);
    if (RNA_SERVICE_USER_TYPE_CACHE_SERVER ==
                                    ctx->cx_params.rsp_user_type) {
        rna_service_assert_locked(&ctx->cx_md_mutex);
    }

    if (NULL == find_connected_cfm_by_eph(ctx, eph)) {
        for (i = 0; i < ctx->cx_params.rsp_cfm_count; i++) {
            /*
             * Use the same entry in the cx_connected_cfms array as is used
             * for this CFM in the cx_params.rsp_cfm_addrs array.
             */
            if (eph->eph_dst_in.sin_addr.s_addr ==
                            ctx->cx_params.rsp_cfm_addrs[i].sin_addr.s_addr) { 
                ci = &ctx->cx_connected_cfms[i];

                ci->ci_eph = *eph;

                /*
                 * Check if this is a connection for the primary CFM.
                 */
                if (eph->eph_dst_in.sin_addr.s_addr ==
                            ctx->cx_primary_cfm_id.pcic_pci.pci_addr.s_addr) {
                    /* Store the primary CFM's new eph */
                    ctx->cx_primary_cfm_eph = *eph;
                    /* Send required introductory messages to the primary CFM */
                    primary_cfm_connected(ctx);
                }

                return;  /* <=== we're finished */
            }
        }
        
        if (i == ctx->cx_params.rsp_cfm_count) {
            rna_dbg_log(RNA_DBG_WARN, 
                        "CFM ["RNA_ADDR_FORMAT"] not found in "
                        "rsp_cfm_addrs table; cfm not added\n",
                        RNA_ADDR(eph->eph_dst_in.sin_addr));

        }
    }
}


/*
 * Called by delete_connected_cfm only to delete an entry from the
 * cx_connected_cfms or cx_disconnecting_cfms array.
 *
 * Locking:
 *    The ctx->cx_cfm_mutex must be held on entry.
 */
static void
delete_cfm_entry(rna_service_ctx_t *ctx, com_ep_handle_t *eph, cfm_info_t *ci)
{
    primary_cfm_id_t demoted_pci;
#ifdef WINDOWS_KERNEL
    KLOCK_QUEUE_HANDLE lockHandle;
#endif /* WINDOWS_KERNEL */

    rna_service_assert(NULL != ctx);
    rna_service_assert(NULL != ci);
    rna_service_assert_locked(&ctx->cx_cfm_mutex);

    if (com_eph_equal(&ctx->cx_primary_cfm_eph, eph)) {
        /*
         * It's the primary CFM -- if it has a registered stats buf,
         * de-register it.
         */
        rna_dbg_log(RNA_DBG_INFO,
                    "Primary CFM ["RNA_ADDR_FORMAT"] "
                    "disconnected\n",
                    RNA_ADDR(eph->eph_dst_in.sin_addr));
#ifdef WINDOWS_KERNEL
        if (rna_service_instkqd_spinlock_acquire(&ctx->cx_primary_cfm_id.pcic_spinlock, 
                                                 &lockHandle))
#else
        if (rna_service_mutex_lock(&ctx->cx_primary_cfm_id.pcic_mutex))
#endif /* WINDOWS_KERNEL */
        {
            demoted_pci = ctx->cx_primary_cfm_id.pcic_pci;
            rna_service_primary_cfm_id_container_reset(
                                   &ctx->cx_primary_cfm_id);
#ifdef WINDOWS_KERNEL
            rna_service_instkqd_spinlock_release( &lockHandle );
#else
            rna_service_mutex_unlock(
                                   &ctx->cx_primary_cfm_id.pcic_mutex);
#endif /* WINDOWS_KERNEL */
            rnas_demote_cfm(ctx, ci, &demoted_pci);
        }
    } else {
        rna_dbg_log(RNA_DBG_INFO,
                    "CFM ["RNA_ADDR_FORMAT"] disconnected, "
                    "primary CFM is ["RNA_ADDR_FORMAT"]\n",
                    RNA_ADDR(eph->eph_dst_in.sin_addr),
                    RNA_ADDR(ctx->cx_primary_cfm_eph.eph_dst_in.
                                                            sin_addr));
    }
    if (rna_service_com_connected(&ci->ci_eph)) {
        rna_dbg_log(RNA_DBG_INFO,
                    "Disconnecting from CFM ["RNA_ADDR_FORMAT"]\n",
                    RNA_ADDR(ci->ci_eph.eph_dst_in.sin_addr));
        rna_service_com_disconnect(&ci->ci_eph);
    }
    memset(ci, 0, sizeof(*ci));
}


/**
 * Delete the specified configuration manager from the list of connected
 * configuration managers.
 *
 * Locking:
 *    The ctx->cx_cfm_mutex must be held on entry.
 */
static void
delete_connected_cfm(rna_service_ctx_t *ctx, com_ep_handle_t *eph)
{
    cfm_info_t      *ci;

    rna_service_assert(NULL != ctx);
    rna_service_assert(NULL != eph);
    rna_service_assert_locked(&ctx->cx_cfm_mutex);

    for (ci = ctx->cx_connected_cfms;
         ci < &ctx->cx_connected_cfms[RNA_SERVICE_CFMS_MAX];
         ci++) {

        if (com_eph_equal(&ci->ci_eph, eph)) {
            /* found the cfm to be deleted */
            delete_cfm_entry(ctx, eph, ci);
            break;
        }
    }

    /*
     * If the entry wasn't found in the set of connected CFMs, look in the set
     * of CFM connections for which com_disconnect has been called.
     */
    if (&ctx->cx_connected_cfms[RNA_SERVICE_CFMS_MAX] == ci) {
        for (ci = ctx->cx_disconnecting_cfms;
             ci < &ctx->cx_disconnecting_cfms[RNA_SERVICE_CFMS_MAX];
             ci++) {

            if (com_eph_equal(&ci->ci_eph, eph)) {
                /* found the cfm to be deleted */
                delete_cfm_entry(ctx, eph, ci);
                break;
            }
        }
    }
}

static void
rna_service_primary_cfm_registration_to(uint64_t context)
{
    rna_service_ctx_t *ctx = (rna_service_ctx_t *)context;

    if (ctx->cx_params.rsp_user_type == RNA_SERVICE_USER_TYPE_CACHE_SERVER) {
        rna_dbg_log(RNA_DBG_WARN, "Cannot register with the primary CFM after"
            " [%ld] seconds, restarting...\n",
            RNA_SERVICE_CFM_REGISTRATION_TIMEOUT);
        ctx->cx_params.rsp_event_callback(ctx,
            RNA_SERVICE_EVENT_KILL_SELF_RESTART);
    }

    return;
}

/**
 * Invoked by a workq thread to connect to any CFMs we don't currently have
 * connections with.
 */
static rna_service_workq_cb_ret_t
reconnect_cfms(rna_service_workq_cb_arg_t workq_context)
{
    send_waiting_msgs_work_ctx_t
                       *wctx = (send_waiting_msgs_work_ctx_t *)workq_context;
    rna_service_ctx_t  *ctx;
    int                 ret;
    uint32_t            i;
    struct sockaddr_in *addr;
    com_ep_handle_t     eph;
    user_type_t           user_type = RNA_SERVICE_USER_TYPE_UNDEFINED;
    int                 com_type;
    boolean             reschedule = FALSE;
    uint32_t            connected_cfm_count;

    rna_service_assert(NULL != wctx);
    rna_service_assert(NULL != wctx->swx_ctx);

    ctx = wctx->swx_ctx;

    if (ctx->cx_flags & CX_FLAG_SHUTTING_DOWN) {
        /* This ctx is in the process of shutting down; don't reconnect */
        ctx->cx_cfm_flags &= ~CTX_CFM_FLAG_RECONNECT_SCHEDULED;
        goto done;
    }

    switch (ctx->cx_params.rsp_user_type) {
    case RNA_SERVICE_USER_TYPE_CACHE_SERVER:
        user_type = USR_TYPE_CFM_CACHE;
        break;

    case RNA_SERVICE_USER_TYPE_BLOCK_CLIENT:
        /* client_type field in CFM registration filled in with
           CLIENT_TYPE_BLOCK in register_with_cfm() */
    case RNA_SERVICE_USER_TYPE_GENERIC_CLIENT:
    case RNA_SERVICE_USER_TYPE_FILE_CLIENT:
        user_type = USR_TYPE_CFM_CLIENT;
        break;

    case RNA_SERVICE_USER_TYPE_METADATA_SERVER:
    case RNA_SERVICE_USER_TYPE_CONFIGURATION_MANAGER:
    case RNA_SERVICE_USER_TYPE_AGENT:
    case RNA_SERVICE_USER_TYPE_UNDEFINED:
        /* These user types aren't yet supported. */
        rna_dbg_log(RNA_DBG_ERR,
                    "Unsupported user type [%d]\n",
                    ctx->cx_params.rsp_user_type);
        goto done;
    /*
     * NOTE that there is purposely no default case here, so the compiler
     * catches a failure to list a defined message type.  Specifying an
     * illegal (undefined) type is handled below).
     */
    }

    if (RNA_SERVICE_USER_TYPE_UNDEFINED == user_type) {
        rna_dbg_log(RNA_DBG_ERR,
                    "Undefined user type %d\n",
                    ctx->cx_params.rsp_user_type);
        goto done;
    }

    rna_dbg_log(RNA_DBG_INFO, 
                "Attempting to connect to all registered CFMs as user type "
                "[%s]\n",
                get_user_type_string(user_type));

    if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
        // This failure means we're in the process of shutting down; do nothing
        ctx->cx_cfm_flags &= ~CTX_CFM_FLAG_RECONNECT_SCHEDULED;
        goto done;
    }

    do {
        ctx->cx_cfm_flags &= ~CTX_CFM_FLAG_RECONNECT_RESTART;
        connected_cfm_count = 0;

        for (i = 0; i < ctx->cx_params.rsp_cfm_count; i++) {
            /* Don't bother re-connecting if we're shutting down */
            if (ctx->cx_flags & CX_FLAG_SHUTTING_DOWN) {
                rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
                goto done;
            }

            addr = &ctx->cx_params.rsp_cfm_addrs[i]; 

            /* XXX: HRM-1768 Always use TCP for control plane */
#if 1
            com_type = IP_TCP;
#else
            com_type = rna_service_com_get_transport_type(ctx->cx_com_instance,
                                                          addr);
            /*
             * In kernel space, we can't get the com type this way,
             * so instead we look at our configuration.
             */
            if (-1 == com_type) {
                com_type = ctx->cx_params.rsp_cfm_com_types[i];
            }
#endif

            if (!find_connected_cfm_by_address(ctx, &addr->sin_addr, &eph)) {
                /* CFM i isn't connected; try to connect */
                ret = rna_service_com_alloc_ep(ctx->cx_com_instance,
                                              &ctx->cx_com_attributes,
                                               (enum com_type) com_type,
                                               RNA_SERVICE_CFM_SEND_BUFS,
                                               RNA_SERVICE_CFM_RECV_BUFS,
                                               sizeof(struct cfm_cmd),
                                               0,
                                               0,
                                               user_type,
                                               0,
                                               0,
                                               0,
                                              &eph);
                if (0 != ret) {
                    rna_dbg_log(RNA_DBG_WARN,
                                "failed to alloc EP for configuration "
                                "manager connection\n");
                    /* Retry the connect after a delay */
                    reschedule = TRUE;
                    break;
                } else {
                    /* (Don't hold the cx_cfm_mutex while we're blocked) */
                    rna_service_mutex_unlock(&ctx->cx_cfm_mutex);

                    /*
                     * Take a reference on the ep, to keep it from being freed
                     * if an asynchronous disconnect happens before the return
                     * from com_connect_sync() (or at any moment after).
                     */
                    com_inc_ref_eph(&eph);  // (no-op at user level)

                    rna_dbg_log(RNA_DBG_INFO, 
                                "Attempting to connect to CFM "
                                "["RNA_ADDR_FORMAT"] ep [%p]\n",
                                RNA_ADDR(addr->sin_addr),
                                com_get_ep_ptr(&eph));

                    /* This test races with this flag being set in
                     * rna_service_ctx_destroy().  There is no way to completely
                     * eliminate the timing window with a simple fix. Best we
                     * can do for now is to make that window narrower.
                     *
                     * See MVP-6617 about fully resolving this race.
                     */
                    if (ctx->cx_flags & CX_FLAG_SHUTTING_DOWN) {
                        /* This ctx is in the process of shutting down;
                         * don't reconnect.
                         */
                       ctx->cx_cfm_flags &= ~CTX_CFM_FLAG_RECONNECT_SCHEDULED;
                       com_release_eph(&eph); // reference acquired above
                       goto done;
                     }

                    ret = rna_service_com_connect_sync(&eph,
                                                       (struct sockaddr *)addr,
                                                       CFM_CONNECT_WAIT_SEC);
                    /* re-acquire the lock */
                    if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
                        /* This return indicates we're shutting down */
                        com_release_eph(&eph); // reference acquired above
                        if (0 != ret) {
                            /*
                             * We need to release the primary reference, too,
                             * in this case, since the disconnect_callback()
                             * wasn't invoked.
                             *
                             * The primary reference was acquired in
                             * com_alloc_ep.
                             */
                            com_release_eph(&eph); // primary reference
                        }
                        goto done;
                    }

                    /*
                     * (Note that add_connected_cfm() is called in the
                     * connect_callback() rather than here, since otherwise the
                     * cfm could send a message (such as a promotion message)
                     * before it had been added to the list of connected CFMs,
                     * causing its promotion to be ignored).
                     */

                    if (0 == ret) {
                        /*
                         * The com_connect() succeeded, though the connection
                         * may already have disconnected.
                         */
                        if (rna_service_com_connected(&eph)) {
                            rna_dbg_log(RNA_DBG_INFO, 
                                        "connected to CFM "
                                        "["RNA_ADDR_FORMAT"] ep [%p]\n",
                                        RNA_ADDR(addr->sin_addr),
                                        com_get_ep_ptr(&eph));
                            connected_cfm_count++;
                        } else {
                            /*
                             * The connection has already disconnected, we'll
                             * need to retry.  This flag is presumably already
                             * set (by the disconnect_callback()), but just in
                             *  case...
                             */
                            rna_dbg_log(RNA_DBG_INFO, 
                                        "Unable to connect to CFM "
                                        "["RNA_ADDR_FORMAT"] ep [%p]\n",
                                        RNA_ADDR(addr->sin_addr),
                                        com_get_ep_ptr(&eph));
                            /* Retry the connect after a delay */
                            reschedule = TRUE;
                            ctx->cx_cfm_flags &=
                                            ~CTX_CFM_FLAG_RECONNECT_RESTART;
                        }
                    } else {
                        /*
                         * The connect failed (either the com_connect() failed
                         * or the connect timed out); the disconnect_callback()
                         * hasn't been invoked.
                         */
                        rna_dbg_log(RNA_DBG_INFO, 
                                    "failed to connect to CFM "
                                    "["RNA_ADDR_FORMAT"] ep [%p]: [%d]\n",
                                    RNA_ADDR(addr->sin_addr),
                                    com_get_ep_ptr(&eph),
                                    ret);
                        /* Retry the connect after a delay */
                        reschedule = TRUE;
                        /*
                         * We need to release the primary reference, too,
                         * in this case, since the disconnect_callback()
                         * wasn't invoked.
                         *
                         * The primary reference was acquired in com_alloc_ep.
                         */
                        com_release_eph(&eph);  // primary reference
                    }
                    com_release_eph(&eph); // reference acquired above
                }
            } else {
                connected_cfm_count++;
            }

            /*
             * If another thread has indicated that a CFM has changed its
             * connected state, restart at the beginning.
             */
            if (ctx->cx_cfm_flags & CTX_CFM_FLAG_RECONNECT_RESTART) {
                break;
            }
        }
    } while (ctx->cx_cfm_flags & CTX_CFM_FLAG_RECONNECT_RESTART);

    // If we have at least one cfm connection, check to see if the
    // cx_primary_cfm_registration_timer needs to be set or cancelled
    if (connected_cfm_count &&
        ctx->cx_params.rsp_user_type == RNA_SERVICE_USER_TYPE_CACHE_SERVER) {
        // If we don't know who the primary cfm is, it's possible that
        // we missed a cfm reassignment, so set the cfm promotion timer
        if (!(ctx->cx_cfm_flags & CTX_CFM_FLAG_REGISTRATION_TIMER_SET) &&
            (connected_cfm_count < ctx->cx_params.rsp_cfm_count) &&
            !rna_service_com_connected(&ctx->cx_primary_cfm_eph)) {
            rna_dbg_log(RNA_DBG_INFO, "Set primary cfm registration timer\n");
            rna_service_timer_cancel(&ctx->cx_primary_cfm_registration_timer);
            rna_service_timer_set(ctx->cx_private,
                &ctx->cx_primary_cfm_registration_timer,
                rna_service_primary_cfm_registration_to, (uint64_t)ctx,
                (int)RNA_SERVICE_CFM_REGISTRATION_TIMEOUT);
            ctx->cx_cfm_flags |= CTX_CFM_FLAG_REGISTRATION_TIMER_SET;
        }
    }

    if (reschedule) {
        /*
         * Schedule an attempt to reconnect with the CFMs we've failed to
         * connect with.
         *
         * (Note that because the cx_cfm_mutex is held, we know this ctx isn't
         * being shut down (see rna_service_ctx_destroy()), so it's safe to
         * call rna_service_timer_set() -- specifically, we know the timer
         * cancellation phase of the shutdown hasn't yet been executed, so
         * we won't be leaving a set timer after shutdown).
         */
        rna_dbg_log(RNA_DBG_INFO, 
                    "will retry CFM connections in [%ld] seconds\n",
                    RNA_SERVICE_RECONNECT_INTERVAL);
        rna_service_timer_cancel(&ctx->cx_reconnect_cfms_timer_object);
        rna_service_timer_set(ctx->cx_private,
                             &ctx->cx_reconnect_cfms_timer_object,
                              reconnect_cfms_to,
                              (uint64_t)ctx,
                              (int) RNA_SERVICE_RECONNECT_INTERVAL);
    }

    ctx->cx_cfm_flags &= ~CTX_CFM_FLAG_RECONNECT_SCHEDULED;

    rna_service_mutex_unlock(&ctx->cx_cfm_mutex);

done:
    rna_service_free(sizeof(*wctx), wctx);

    /*
     * NOTE that rna_service workq callbacks must use
     * RNA_SERVICE_WORKQ_CB_RETURN instead of return.
     */
    RNA_SERVICE_WORKQ_CB_RETURN(0);
}


/*
 * Add a call to reconnect_cfms to the cx_cfm_connect_work_queue.
 *
 * The cx_cfm_mutex must be held on entry.
 */
static void
queue_reconnect_cfms(rna_service_ctx_t *ctx)
{
    send_waiting_msgs_work_ctx_t *wctx;

    rna_service_assert_locked(&ctx->cx_cfm_mutex);

    if (ctx->cx_cfm_flags & CTX_CFM_FLAG_RECONNECT_SCHEDULED) {
        /*
         * reconnect_cfms is already scheduled on a workq.  Indicate it should
         * take another turn around its loop, in case it missed a CFM state
         * change.
         */
        ctx->cx_cfm_flags |= CTX_CFM_FLAG_RECONNECT_RESTART;
    } else {
        wctx = rna_service_alloc0(sizeof(*wctx));
        if (NULL == wctx) {
            rna_dbg_log(RNA_DBG_WARN,
                        "unable to allocate memory, so unable to "
                        "connect to CFM\n");
            return;
        }

        ctx->cx_cfm_flags |= CTX_CFM_FLAG_RECONNECT_SCHEDULED;

        /*
         * If a delayed request to queue reconnect_cfms has been set, cancel it,
         * since we're queuing it now.
         */
        rna_service_timer_cancel(&ctx->cx_reconnect_cfms_timer_object);

        wctx->swx_ctx = ctx;
        RNA_SERVICE_WORK_INIT(&wctx->swx_work_obj,
                              reconnect_cfms,
                              (rna_service_workq_cb_arg_t)wctx);
        (void) rna_service_workq_add(ctx->cx_cfm_connect_work_queue,
                                     &wctx->swx_work_obj);
    }
}


/**
 * An rna_service_timer function that's invoked to attempt to connect to any
 * CFMs we don't currently have connections with.
 */
static void
reconnect_cfms_to(uint64_t context)
{
    rna_service_ctx_t  *ctx = (rna_service_ctx_t *) context;

    rna_service_assert(NULL != ctx);

    if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
        /* This failure means we're in the process of shutting down */
        return;
    }

    queue_reconnect_cfms(ctx);

    rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
}


/*
 * Invoked if we haven't gotten a heartbeat from the primary CFM for a
 * particularly long time.  Disconnect the ep, in case the primary cfm has
 * lost power and is taking a particularly long time to disconnect.  If we
 * don't disconnect and the old primary cfm reboots and becomes the primary
 * once more, we'll take a very long time to connect to the new incarnation of
 * the primary CFM  (until the disconnect happens for the old ep).
 */
static void
primary_cfm_heartbeat_long_timeout(uint64_t context)
{
    rna_service_ctx_t *ctx = (rna_service_ctx_t *) context;
    int i;

    /*
     * NOTE that this log message may not appear in the log, since this routine
     * is executed by the timer thread.
     */
    rna_dbg_log(RNA_DBG_WARN,
                "long CFM heartbeat timeout, disconnecting\n");

    if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
        // This failure means we're in the process of shutting down; do nothing
        return;
    }

    if ((ctx->cx_cfm_flags & CTX_CFM_FLAG_DETACHED_FROM_CLUSTER)
      && (rna_service_com_connected(&ctx->cx_primary_cfm_eph))) {
        rna_dbg_log(RNA_DBG_INFO,
                    "Disconnecting from CFM ["RNA_ADDR_FORMAT"]\n",
                    RNA_ADDR(ctx->cx_primary_cfm_eph.eph_dst_in.sin_addr));
        rna_service_com_disconnect(&ctx->cx_primary_cfm_eph);
        /*
         * It may take a long time for the disconnect_callback to be invoked
         * for this CFM connection, and this component will be detached from
         * the cluster during that time.  To minimize the detached time, try
         * to move the CFM entry from the cx_connected_cfms array to the
         * cx_disconnected_cfms array and if successful, immediately start
         * trying to reconnect to it.
         */
        for (i = 0; i < RNA_SERVICE_CFMS_MAX; i++) {
            if (com_eph_equal(&ctx->cx_connected_cfms[i].ci_eph,
                              &ctx->cx_primary_cfm_eph)) {
                /*
                 * This is the entry for the CFM, check the corresponding entry
                 * in the cx_disconnected_cfms array.  Note that a given CFM
                 * node's information is stored in at the same index in the
                 * cx_params.rsp_cfm_addrs array, the cx_connected_cfms array,
                 * and the cx_disconnecting_cfms array.
                 */
                if (com_eph_isempty(&ctx->cx_disconnecting_cfms[i].ci_eph)) {
                    /*
                     * There isn't already a disconnecting entry for a previous
                     * connection with this CFM, so we can store this
                     * connection there.
                     */
                    ctx->cx_disconnecting_cfms[i] = ctx->cx_connected_cfms[i];
                    /*
                     * Remove the entry from the cx_connected_cfms array and
                     * start trying to reconnect to it.
                     */
                    memset(&ctx->cx_connected_cfms[i],
                            0,
                            sizeof(ctx->cx_connected_cfms[i]));
                    queue_reconnect_cfms(ctx);
                }
            }
        }
    }

    rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
}


/**
 * An rna_service_timer function that's invoked if the
 * primary_cfm_heartbeat_timer expires, indicating that this component may
 * no longer be a member of the cluster.
 */
static void
primary_cfm_heartbeat_timed_out(uint64_t context)
{
    rna_service_ctx_t *ctx = (rna_service_ctx_t *) context;

    /*
     * NOTE that this log message may not appear in the log, since this routine
     * is executed by the timer thread.
     */
    rna_dbg_log(RNA_DBG_WARN,
                "primary CFM heartbeat has timed out\n");

    if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
        // This failure means we're in the process of shutting down; do nothing
        return;
    }

    if (!(ctx->cx_cfm_flags & CTX_CFM_FLAG_DETACHED_FROM_CLUSTER)) {
        ctx->cx_cfm_flags |= CTX_CFM_FLAG_DETACHED_FROM_CLUSTER;
        /*
         * We schedule this event on a work queue, to preserve ordering
         * between RNA_SERVICE_EVENT_DETACHED_FROM_CLUSTER events and
         * RNA_SERVICE_EVENT_REJOINED_CLUSTER events.
         */
        work_queue_add_callback(ctx,
                                NULL,
                                NULL,
                                RNA_SERVICE_EVENT_DETACHED_FROM_CLUSTER);
        rna_service_timer_set(ctx->cx_private,
                             &ctx->cx_primary_cfm_heartbeat_timer,
                              primary_cfm_heartbeat_long_timeout,
                              (uint64_t)ctx,
                              (int)ctx->cx_quorum_heartbeat_timeout_sec / 2);
    } else {
        rna_dbg_log(RNA_DBG_ERR,
                    "primary_cfm_heartbeat_timed_out invoked when "
                    "already detached\n");
    }
    rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
}


/*
 * Send empty pings to non-primary CFMs.  Empty pings are not part of the
 * quorum heartbeat protocol, but serve simply to identify connections that
 * have been dropped.  Without these junk pings, it can take a very long time
 * to get a disconnect callback for an ethernet connection to a CFM on a node
 * that has had a power failure.  As a result, if that CFM later re-started
 * and became primary, we wouldn't get its promotion message, since we
 * wouldn't have noticed the disconnect and re-connected yet (see MVP-5473).
 */
static void
ping_non_primary_cfms_to(uint64_t context)
{
    rna_service_ctx_t            *ctx = (rna_service_ctx_t *) context;
    cfm_info_t                   *ci;
    int                           ret;
    rna_service_send_buf_entry_t *send_buf;
    struct cfm_cmd               *ping;

    if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
        // This failure means we're in the process of shutting down; do nothing
        return;
    }

    for (ci = ctx->cx_connected_cfms;
         ci < &ctx->cx_connected_cfms[RNA_SERVICE_CFMS_MAX];
         ci++) {

        /*
         * NOTE in the following that it's not necessary to log failures.
         * Since the goal of this routine is to identify dead connections,
         * some failures are expected.
         */
        if ((!com_eph_isempty(&ci->ci_eph))
          && (!com_eph_equal(&ci->ci_eph, &ctx->cx_primary_cfm_eph))) {
            ret = rna_service_com_get_send_buf(&ci->ci_eph,
                                               &send_buf,
                                               TRUE,
                                               NULL);
            if ((0 == ret) && (send_buf != NULL)) {
#if defined(LINUX_KERNEL) || defined(WINDOWS_KERNEL)
                ping = (struct cfm_cmd *)(com_get_send_buf_mem(send_buf));
#else
                ping = (struct cfm_cmd *) send_buf->mem;
#endif

                memset(&ping->h, 0, sizeof(ping->h));
                ping->h.h_type = EMPTY_PING;

                (void) rna_service_com_send_cfm_cmd(&ci->ci_eph,
                                                    send_buf,
                                                    cfm_cmd_length(ping),
                                                    &ctx->cx_primary_cfm_id);
            }
        }
    }

    /* If there is only one CFM, and it is local, then we don't need
     * to ping non-primary CFMs either.  There won't BE any.
     */
    if (!(ctx->cx_cfm_flags & CTX_CFM_FLAG_DISABLED_HEARTBEAT_TIMER)) {
        rna_dbg_log(RNA_DBG_VERBOSE, "set timeout handler\n");
        rna_service_timer_set(ctx->cx_private,
                              &ctx->cx_non_primary_cfm_ping_timer,
                              ping_non_primary_cfms_to,
                              (uint64_t)ctx,
                              NON_PRIMARY_CFM_PING_SEC);
    } else {
        rna_dbg_log(RNA_DBG_VERBOSE, "timeout handler DISABLED\n");
    }

    rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
}


/**
 * Process a PING message from the configuration manager.
 */
static int 
process_ping(rna_service_ctx_t *ctx,
             com_ep_handle_t   *eph,
             struct cfm_cmd    *cmd) 
{
    size_t      ret;
    rna_service_send_buf_entry_t *send_buf;
    struct cfm_cmd *ping;

    rna_service_assert(NULL != ctx);

    if (eph->eph_dst_in.sin_addr.s_addr != cmd->h.h_pci.pci_addr.s_addr) {
        /*
         * This appears to be a ping from a CFM that realizes it's no longer
         * the primary.  Possibly there was a race, in which the CFM stopped
         * being primary as the message was being sent?  If these are seen
         * repeatedly, there's a problem.
         */
        rna_dbg_log(RNA_DBG_MSG,
                    "Received ping from a CFM that realizes it's not the "
                    "primary, possibly due to a race with a demotion. "
                    "Sender ["RNA_ADDR_FORMAT"] primary ["RNA_ADDR_FORMAT"]\n",
                    RNA_ADDR(eph->eph_dst_in.sin_addr),
                    RNA_ADDR(cmd->h.h_pci.pci_addr));
        return 0;
    } else {
        rna_dbg_log(RNA_DBG_VERBOSE,
                    "Received ping from primary CFM ["RNA_ADDR_FORMAT"]\n",
                    RNA_ADDR(eph->eph_dst_in.sin_addr));
    }

    if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
        // This failure means we're in the process of shutting down; do nothing
        return 0;
    }

    /* Since we've received a heartbeat/ping from CFM, reset the ping timout */
    rna_service_timer_cancel(&ctx->cx_primary_cfm_heartbeat_timer);

    ctx->cx_quorum_heartbeat_timeout_sec =
                        cmd->u.agent_ping.ap_quorum_heartbeat_timeout_sec;

    /*
     * If this is the first ping received after becoming detached from the
     * cluster, tell the library's user that we've rejoined the cluster.
     */
    if ((ctx->cx_cfm_flags & CTX_CFM_FLAG_DETACHED_FROM_CLUSTER) != 0) {
        ctx->cx_cfm_flags &= ~CTX_CFM_FLAG_DETACHED_FROM_CLUSTER;
        work_queue_add_callback(ctx,
                                NULL,
                                NULL,
                                RNA_SERVICE_EVENT_REJOINED_CLUSTER);
    }

    /* Send a ping in reply. */
    ret = rna_service_com_get_send_buf(eph, &send_buf, TRUE, NULL);
    if ((NULL == send_buf) || (0 != ret)) {
        rna_dbg_log(RNA_DBG_WARN,
                    "failed to allocate send buffer\n");
        rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
        return -1;
    }

#if defined(LINUX_KERNEL) || defined(WINDOWS_KERNEL)
    ping = (struct cfm_cmd *)(com_get_send_buf_mem(send_buf));
#else
    ping = (struct cfm_cmd *) send_buf->mem;
#endif
    memset(ping, 0, sizeof(cmd_hdr_t));

    if (RNA_SERVICE_USER_TYPE_CACHE_SERVER == ctx->cx_params.rsp_user_type) {
        ping->h.h_type = CS_TO_CFM_PING;
    } else if (RNA_SERVICE_USER_TYPE_FILE_CLIENT ==
                                              ctx->cx_params.rsp_user_type) {
        ping->h.h_type = FSCLIENT_TO_CFM_PING;
    } else {
        /* possibly an RNA_SERVICE_USER_TYPE_BLOCK_CLIENT */
        ping->h.h_type = PING;
    }

    ret = rna_service_com_send_cfm_cmd(eph,
                                       send_buf,
                                       cfm_cmd_length(ping),
                                       &ctx->cx_primary_cfm_id);
    if (ret != 0) {
        rna_dbg_log(RNA_DBG_WARN, "Failed to send CFM message: %ld\n", ret);
    }

    rna_dbg_log(RNA_DBG_VERBOSE,
                "Sent ping to primary CFM ["RNA_ADDR_FORMAT"]\n",
                RNA_ADDR(eph->eph_dst_in.sin_addr));

    /*
     * If heartbeats are not disabled, re-set the timeout for the next
     * expected ping
     */
    if ((!(ctx->cx_cfm_flags & CTX_CFM_FLAG_DISABLED_HEARTBEAT_TIMER))
      && (cmd->u.agent_ping.loc_cnt != PING_NO_TIMEOUT)) {

        rna_dbg_log(RNA_DBG_VERBOSE, "resetting process_ping\n");
        rna_service_timer_set(ctx->cx_private,
                             &ctx->cx_primary_cfm_heartbeat_timer,
                              primary_cfm_heartbeat_timed_out,
                              (uint64_t)ctx,
                              (int)ctx->cx_quorum_heartbeat_timeout_sec);
    } else {
        rna_dbg_log(RNA_DBG_VERBOSE, "NOT resetting process_ping - DISABLED\n");
    }

    /*
     * Note also that we wait until after we've set the timer to drop the
     * cx_cfm_mutex, to assure we don't set the timer after a shutdown has
     * started.
     */
    rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
    return 0;
}

/*
 * Function used by deregister_mount_or_blkdev_with_cfm() and
 * queue_mount_or_blkdev_registration() to check whether the queued
 * mount/block device or storage path registration message matches the
 * specified message.
 *
 * Arguments:
 *    ibuf  pointer to a queued message
 *    buf   pointer to a message to be matched against the above queued message
 */
INLINE boolean
mount_blkdev_match(rna_service_message_buffer_internal_t *ibuf,
                   rna_service_message_buffer_t          *buf)
{
    switch (buf->h.rmb_message_type) {
    case RNA_SERVICE_MESSAGE_TYPE_REG_MNT:
        if ((RNA_SERVICE_MESSAGE_TYPE_REG_MNT == ibuf->h.rmbi_msg_type)
          && (ibuf->u.rmbi_message_buffer.u.rmb_register_mount.rms_mount_id ==
                        buf->u.rmb_register_mount.rms_mount_id)) {
            return (TRUE);
        }
        break;

    case RNA_SERVICE_MESSAGE_TYPE_DEREG_MNT:
        if ((RNA_SERVICE_MESSAGE_TYPE_REG_MNT == ibuf->h.rmbi_msg_type)
          && (ibuf->u.rmbi_message_buffer.u.rmb_register_mount.rms_mount_id ==
                        buf->u.rmb_deregister_mount.dms_mount_id)) {
            return (TRUE);
        }
        break;

    case RNA_SERVICE_MESSAGE_TYPE_REG_BLKDEV:
        if ((RNA_SERVICE_MESSAGE_TYPE_REG_BLKDEV == ibuf->h.rmbi_msg_type)
            && (ibuf->u.rmbi_message_buffer.u.rmb_register_block_device.
                                                            rbs_device ==
                        buf->u.rmb_register_block_device.rbs_device)) {
            return (TRUE);
        }
        break;

    case RNA_SERVICE_MESSAGE_TYPE_DEREG_BLKDEV:
        if ((RNA_SERVICE_MESSAGE_TYPE_REG_BLKDEV == ibuf->h.rmbi_msg_type)
          && (ibuf->u.rmbi_message_buffer.u.rmb_register_block_device.
                                                            rbs_device ==
                        buf->u.rmb_deregister_block_device.dbs_device)) {
            return (TRUE);
        }
        break;

    case RNA_SERVICE_MESSAGE_TYPE_REG_CACHE_DEVICE:
        if ((RNA_SERVICE_MESSAGE_TYPE_REG_CACHE_DEVICE == ibuf->h.rmbi_msg_type)
          && (memcmp(&ibuf->u.rmbi_message_buffer.u.rmb_register_cache_device.
                                    cdr_cachedev_label.cl_physical_id,
                     &buf->u.rmb_register_cache_device.
                                    cdr_cachedev_label.cl_physical_id,
                     sizeof(buf->u.rmb_register_cache_device.
                                    cdr_cachedev_label.cl_physical_id)) == 0)) {
            return (TRUE);
        }
        break;

    case RNA_SERVICE_MESSAGE_TYPE_DEREG_CACHE_DEVICE:
        if ((RNA_SERVICE_MESSAGE_TYPE_REG_CACHE_DEVICE == ibuf->h.rmbi_msg_type)
          && (memcmp(&ibuf->u.rmbi_message_buffer.u.rmb_register_cache_device.
                                    cdr_cachedev_label.cl_physical_id,
                     &buf->u.rmb_deregister_cache_device.
                                    cdd_cachedev_label.cl_physical_id,
                     sizeof(buf->u.rmb_deregister_cache_device.
                                    cdd_cachedev_label.cl_physical_id)) == 0)) {
            return (TRUE);
        }
        break;

    case RNA_SERVICE_MESSAGE_TYPE_REG_SVC_CONN:
        if ((RNA_SERVICE_MESSAGE_TYPE_REG_SVC_CONN == ibuf->h.rmbi_msg_type)
          && (buf->u.rmb_deregister_svc_conn.dsc_dereg_by_conn_id
          ? (ibuf->u.rmbi_message_buffer.u.rmb_register_svc_conn.rsc_conn_id == 
                        buf->u.rmb_register_svc_conn.rsc_conn_id)
          : (match_rna_service_id(
                        &ibuf->u.rmbi_message_buffer.u.
                                        rmb_register_svc_conn.rsc_service_id,
                                  &buf->u.rmb_register_svc_conn.rsc_service_id,
                                  TRUE)))) {
            return (TRUE);
        }
        break;

    case RNA_SERVICE_MESSAGE_TYPE_DEREG_SVC_CONN:
        if ((RNA_SERVICE_MESSAGE_TYPE_REG_SVC_CONN == ibuf->h.rmbi_msg_type)
          && (buf->u.rmb_deregister_svc_conn.dsc_dereg_by_conn_id
          ? (ibuf->u.rmbi_message_buffer.u.rmb_register_svc_conn.rsc_conn_id == 
                         buf->u.rmb_deregister_svc_conn.dsc_conn_id)
          : (match_rna_service_id(
                        &ibuf->u.rmbi_message_buffer.u.
                                        rmb_register_svc_conn.rsc_service_id,
                        &buf->u.rmb_deregister_svc_conn.dsc_service_id,
                         TRUE)))) {
            return (TRUE);
        }
        break;

    case RNA_SERVICE_MESSAGE_TYPE_REG_PATH:
    case RNA_SERVICE_MESSAGE_TYPE_DEREG_PATH:
        if ((RNA_SERVICE_MESSAGE_TYPE_REG_PATH == ibuf->h.rmbi_msg_type)
          && (0 == memcmp(
                       &ibuf->u.rmbi_message_buffer.u.rmb_register_path.rp_wwn,
                       &buf->u.rmb_register_path.rp_wwn,
                       sizeof(buf->u.rmb_register_path.rp_wwn)))) {
            return (TRUE);
        }
        break;

    default:
        rna_dbg_log(RNA_DBG_ERR,
                    "unhandled message type [%d] [%s]\n",
                    buf->h.rmb_message_type,
                    rna_service_get_message_type_string(
                                                    buf->h.rmb_message_type));
        break;
    }

    return (FALSE);
}


/*
 * Function used by deregister_mount_or_blkdev_with_cfm() to 
 * fill in parts of dereg message from stored reg message.
 */
INLINE void
mount_blkdev_complete_dereg_msg(rna_service_message_buffer_internal_t *ibuf,
                                rna_service_message_buffer_t          *buf)
{
    if ((RNA_SERVICE_MESSAGE_TYPE_DEREG_SVC_CONN == buf->h.rmb_message_type)
        && (RNA_SERVICE_MESSAGE_TYPE_REG_SVC_CONN == ibuf->h.rmbi_msg_type)
        && buf->u.rmb_deregister_svc_conn.dsc_dereg_by_conn_id) {
        
        /* Deregistering service connection by local ID, not rna_service_id.
         * Fill in service_id in dereg message from stored reg message. */
        memcpy(&buf->u.rmb_deregister_svc_conn.dsc_service_id,
               &ibuf->u.rmbi_message_buffer.u.rmb_register_svc_conn.
                                                            rsc_service_id,
               sizeof(buf->u.rmb_deregister_svc_conn.dsc_service_id));
    }
}


/*
 * A find_registration_compare_fn used by queue_mount_or_blkdev_registration.
 * If a matching registration is queued, remove it, so the new registration
 * can be enqueued.
 *
 * Arguments:
 *     ctx   The rna_service context
 *     ibuf  The queued registration message to be checked
 *     arg   The new registration message to be added
 */
static boolean
reg_remove_matching_registration(rna_service_ctx_t                     *ctx,
                                 rna_service_message_buffer_internal_t *ibuf,
                                 void                                  *arg)
{
    rna_service_message_buffer_t *buf_being_added;

    buf_being_added = (rna_service_message_buffer_t *) arg;

    /*
     * If the buffer we're trying to enqueue is already
     * on the appropriate queue, don't bother to do anything.
     */
    if (&ibuf->u.rmbi_message_buffer == buf_being_added) {
        rna_dbg_log(RNA_DBG_INFO,
                    "registration message is already queued, "
                    "not queuing it again.\n");
        YAQ_REMOVE(&ibuf->h.rmbi_link);
        return (TRUE);
    }    

    if (mount_blkdev_match(ibuf, buf_being_added)) {
        /*
         * Found a registration for this same mount/block device or 
         * storage path. Remove the old registration, to be replaced 
         * with the new one.
         */
        YAQ_REMOVE(&ibuf->h.rmbi_link);
        rna_service_free_message_buffer(ctx, &ibuf->u.rmbi_message_buffer);
        return (TRUE);
    }

    return (FALSE);
}


/*
 * Queue the specified mount/block device/storage path registration in the 
 * cx_registered queue.
 *
 * The mount/block device/storage path will be re-registered if a cfm failover 
 * happens.
 *
 * Locking:
 *    The ctx->cx_cfm_mutex must be held on entry.
 */
static void
queue_mount_or_blkdev_registration(rna_service_ctx_t                     *ctx,
                                   rna_service_message_buffer_internal_t *ibuf)
{
    rna_service_assert_locked(&ctx->cx_cfm_mutex);

    if ((ibuf->u.rmbi_message_buffer.h.rmb_message_type !=
                                    RNA_SERVICE_MESSAGE_TYPE_REG_BLKDEV)
      && (ibuf->u.rmbi_message_buffer.h.rmb_message_type !=
                                    RNA_SERVICE_MESSAGE_TYPE_REG_CACHE_DEVICE) 
      && (ibuf->u.rmbi_message_buffer.h.rmb_message_type !=
                                    RNA_SERVICE_MESSAGE_TYPE_REG_MNT)
      && (ibuf->u.rmbi_message_buffer.h.rmb_message_type !=
                                    RNA_SERVICE_MESSAGE_TYPE_REG_SVC_CONN) 
      && (ibuf->u.rmbi_message_buffer.h.rmb_message_type !=
                                    RNA_SERVICE_MESSAGE_TYPE_REG_PATH)) {
        rna_dbg_log(RNA_DBG_ERR,
                    "Error: illegal message type [%s], ignoring\n",
                    rna_service_get_message_type_string(
                            ibuf->u.rmbi_message_buffer.h.rmb_message_type));
        return;
    }

    /*
     * If a registration for this mount / block device is already queued, toss
     * the old registration in favor of the new one.
     */
    (void) find_registration(ctx,
                             ibuf->h.rmbi_msg_type, 
                             reg_remove_matching_registration,
                             &ibuf->u.rmbi_message_buffer);

    YAQ_INSERT_TAIL(&ctx->cx_registered, &ibuf->h.rmbi_link);
}


/*
 * NOTE that this routine is meant to be called by
 * register_mount_or_blkdev_with_cfm only.  Enqueue the specified message on
 * the cx_cfm_registrations_waiting_to_send queue, unless it's an
 * RNA_SERVICE_MESSAGE_TYPE_REG_CACHE_DEVICE_END message.
 *
 * Locking:
 *     The cx_cfm_mutex must be held on entry.
 */
static void
enqueue_waiting_cfm_registration_msg(
                        rna_service_ctx_t                     *ctx,
                        rna_service_message_buffer_t          *buf,
                        rna_service_message_buffer_internal_t *ibuf)
{
    rna_service_assert_locked(&ctx->cx_cfm_mutex);

    /*
     * 'End of cache device registration' messages are never queued.  Doing
     * so would be problematic, since it would allow the possibility that
     * another cache device registration message could be queued behind it.
     */
    if (RNA_SERVICE_MESSAGE_TYPE_REG_CACHE_DEVICE_END ==
                                                buf->h.rmb_message_type) {
        /* don't queue message -- see comment above */
        rna_service_free_message_buffer(ctx, buf);
    } else {
        /*
         * (Note that if this is a re-send, inserting the message at the tail
         * of the queue may re-order the queue, since the message was removed
         * from the head.  We're not worried about re-ordering registration
         * messages, though, since these messages aren't ordered).
         */
        YAQ_INSERT_TAIL(&ctx->cx_cfm_registrations_waiting_to_send,
                        &ibuf->h.rmbi_link);
    }
}


/**
 * Register the specified mount, block device or storage path with the 
 * configuration manager.
 *
 * For mounts:
 *     Currently, mount registration is for informational purposes only.
 *     In the future, the CFM may reject mounts if a client tries to mount
 *     a directory with different options than another client.  
 *
 * A mount/block device/storage path is registered at mount time/device
 * creation time, and re-registered if the CFM disconnects and reconnects,
 * or if a secondary CFM becomes the primary CFM.
 *
 * The cookie/mount ID passed the CFM needs to be unique only for the
 * current client; other clients may use the same value without causing
 * problems.
 *
 * A client may possibly register a mount or block device more than once if
 * the CFM reconnects, so the CFM must accept redundant mount and block device
 * registrations gracefully (redundant registrations have the same cookie/mount
 * ID).  For mounts, the cookie/mount ID is currently the mount_info pointer.
 * For block devices, it's the address of the device's struct rnablk_device.
 *
 * While mounts or block devices are registered by the client, storage paths
 * are registered by the cache server.
 */
static void
register_mount_or_blkdev_with_cfm(rna_service_ctx_t            *ctx,
                                  rna_service_message_buffer_t *buf,
                                  boolean                       retry_flag)
{
    size_t ret;
    com_ep_handle_t  primary_cfm_eph;
    rna_service_message_buffer_internal_t *ibuf;
    rna_service_send_buf_entry_t *send_buf;
    struct cfm_cmd *cmd;
    char *wwn_str = NULL;

    ibuf = mbuf_to_ibuf(buf);

    if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
        /* This failure means we're in the process of shutting down */
        rna_service_free_message_buffer(ctx, buf);
        return;
    }

 rmb_restart:
    /*
     * If there's no primary CFM to send this message to or if this isn't a
     * retry and messages are queued waiting to be sent, queue this message
     * behind them.
     */
    if ((!rna_service_com_connected(&ctx->cx_primary_cfm_eph))
      || ((!retry_flag)
        && (!YAQ_EMPTY(&ctx->cx_cfm_registrations_waiting_to_send)))) {

        enqueue_waiting_cfm_registration_msg(ctx, buf, ibuf);
        schedule_waiting_cfm_msgs(ctx, 0);
        goto done_set_timer;
    }

    primary_cfm_eph = ctx->cx_primary_cfm_eph;
    if (!retry_flag) {
        /*
         * For the first try, we do a non-blocking request for a sendbuf, to
         * reduce overhead for the common case.  This request will usually
         * succeed, since sendbufs are usually available.  If it fails, we'll
         * queue a retry request.
         */
        ret = rna_service_com_get_send_buf(&primary_cfm_eph,
                                           &send_buf,
                                           FALSE,
                                           NULL);
    } else {
        /*
         * For retries, we do a blocking request for a sendbuf, since a
         * non-blocking request previously failed.  This gets a bit
         * complicated, since we don't want to hold the cx_cfm_mutex across
         * a blocking request.
         */
        com_inc_ref_eph(&primary_cfm_eph);  // (no-op at user level)
        /* Don't hold mutex across blocking operation */
        rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
        ret = rna_service_com_get_send_buf(&primary_cfm_eph,
                                           &send_buf,
                                           TRUE,
                                           NULL);
        /* Re-acquire the cx_cfm_mutex */
        if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
            /*
             * This failure means we're in the process of shutting down
             * Give back the sendbuf we allocated.
             */
            if (send_buf != NULL) {
                rna_service_com_put_send_buf(&primary_cfm_eph, send_buf);
            }
            com_release_eph(&primary_cfm_eph);  // (no-op at user level)
            return;
        }
        /* The primary CFM may have changed while we didn't hold the mutex */
        if (!com_eph_equal(&ctx->cx_primary_cfm_eph, &primary_cfm_eph)) {
            /*
             * The primary CFM changed, so we may hold a sendbuf on the wrong
             * ep.  If so, give it back.
             */
            if (send_buf != NULL) {
                rna_service_com_put_send_buf(&primary_cfm_eph, send_buf);
            }
            com_release_eph(&primary_cfm_eph);  // (no-op at user level)
            goto rmb_restart;   // try again with new primary CFM
        }
        com_release_eph(&primary_cfm_eph);  // (no-op at user level)
        /*
         * Make sure the message didn't time out while we were waiting for a
         * send buffer.
         */
        if (ibuf->h.rmbi_flags & RMBI_FLAG_TIMED_OUT) {
            rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
            cfm_response_timed_out((uint64_t)ibuf);
            return;
        }
    }

    if ((NULL == send_buf) || (0 != ret)) {
        if ((retry_flag)
          && (rna_service_com_connected(&primary_cfm_eph))) {
            /* This should never happen! */
            rna_dbg_log(RNA_DBG_ERR,
                        "Failed to get send buffer after blocking!\n");
        } else {
            rna_dbg_log(RNA_DBG_WARN,
                        "Failed to get send buffer!!\n");
        }
        /* Schedule a retry */
        enqueue_waiting_cfm_registration_msg(ctx, buf, ibuf);
        schedule_waiting_cfm_msgs(ctx, SEND_WAITING_CFM_MSGS_DELAY_SEC);
        goto done_set_timer;
    }

#if defined(LINUX_KERNEL) || defined(WINDOWS_KERNEL)
    cmd = (struct cfm_cmd *)(com_get_send_buf_mem(send_buf));
#else
    cmd = (struct cfm_cmd *) send_buf->mem;
#endif
    ibuf->h.rmbi_req_msg_id = ctx->cx_cfm_next_msg_id++;

    if (RNA_SERVICE_MESSAGE_TYPE_REG_MNT == buf->h.rmb_message_type) {
        /* Mount registration */
        memset(cmd, 0, sizeof(cmd_hdr_t) + sizeof(struct client_mount_reg));
        cmd->h.h_type = CONF_MGR_REG_CLIENT_MOUNT;
        cmd->u.client_mount_reg.rms_mount_id =
                                buf->u.rmb_register_mount.rms_mount_id;
        strncpy(cmd->u.client_mount_reg.rms_uppermnt_path, 
                buf->u.rmb_register_mount.rms_uppermnt_path,
                MAX_MOUNT_PATH_LEN);
        /* make sure the string is null terminated */
        cmd->u.client_mount_reg.rms_uppermnt_path[MAX_MOUNT_PATH_LEN-1] = '\0';
        strncpy(cmd->u.client_mount_reg.rms_lowermnt_path, 
                buf->u.rmb_register_mount.rms_lowermnt_path,
                MAX_MOUNT_PATH_LEN);
        /* make sure the string is null terminated */
        cmd->u.client_mount_reg.rms_lowermnt_path[MAX_MOUNT_PATH_LEN-1] = '\0';
        strncpy(cmd->u.client_mount_reg.rms_opts, 
                buf->u.rmb_register_mount.rms_opts,
                MAX_MOUNT_OPTS_LEN);
        /* make sure the string is null terminated */
        cmd->u.client_mount_reg.rms_opts[MAX_MOUNT_OPTS_LEN-1] = '\0';

        rna_dbg_log(RNA_DBG_INFO,
                    "registering mount with cfm: options %s lowermnt %s "
                    "uppermnt %s\n",
                    cmd->u.client_mount_reg.rms_opts,
                    cmd->u.client_mount_reg.rms_lowermnt_path,
                    cmd->u.client_mount_reg.rms_uppermnt_path);
    } else if (RNA_SERVICE_MESSAGE_TYPE_REG_BLKDEV == buf->h.rmb_message_type) {
        /* Block device registration */
        memset(cmd,
               0,
               sizeof(cmd_hdr_t) + sizeof(struct client_block_device_reg));
        cmd->h.h_type = CONF_MGR_REG_BLOCK_DEVICE;
        cmd->h.h_cookie = buf->u.rmb_register_block_device.rbs_device;
        cmd->u.client_block_device_reg.req_msg_id = ibuf->h.rmbi_req_msg_id;
        cmd->u.client_block_device_reg.rnas = buf->u.rmb_register_block_device;
        /*
         * (NOTE that it's important not to use strncpy with a PATHNAME_LEN
         * limit here, since strncpy fills the remainder of the destination
         * buffer with nulls, but the destination buffer is variable-sized,
         * and has been allocated to be only as large as the string to be
         * copied in).
         */
        strcpy(cmd->u.client_block_device_reg.rnas.rbs_name, 
               buf->u.rmb_register_block_device.rbs_name);

        rna_dbg_log(RNA_DBG_INFO,
                    "registering block device [%s] with CFM "
                    "["RNA_ADDR_FORMAT"]\n",
                    cmd->u.client_block_device_reg.rnas.rbs_name,
                    RNA_ADDR(primary_cfm_eph.eph_dst_in.sin_addr));
    } else if (RNA_SERVICE_MESSAGE_TYPE_REG_SVC_CONN ==
                                                buf->h.rmb_message_type) {
        /* Service connection registration */
        memset(cmd,
               0,
               sizeof(cmd_hdr_t) + sizeof(struct cfm_service_reg));
        cmd->h.h_type = CONF_MGR_CONN_REG;
        memcpy(&cmd->u.cfm_service_reg.service_id,
               &buf->u.rmb_register_svc_conn.rsc_service_id,
               sizeof(cmd->u.cfm_service_reg.service_id));
        cmd->u.cfm_service_reg.conn_details_valid = 1;
        cmd->u.cfm_service_reg.transport_type =
            buf->u.rmb_register_svc_conn.rsc_transport_type;
        memcpy(&cmd->u.cfm_service_reg.src_in,
               &buf->u.rmb_register_svc_conn.rsc_src_in,
               sizeof(cmd->u.cfm_service_reg.src_in));
        memcpy(&cmd->u.cfm_service_reg.dst_in,
               &buf->u.rmb_register_svc_conn.rsc_dst_in,
               sizeof(cmd->u.cfm_service_reg.dst_in));

        rna_dbg_log(RNA_DBG_INFO,
                    "registering service connection "
                    "["rna_service_id_format"] with CFM ["RNA_ADDR_FORMAT"]\n",
                    rna_service_id_get_string(
                                &buf->u.rmb_register_svc_conn.rsc_service_id),
                    RNA_ADDR(primary_cfm_eph.eph_dst_in.sin_addr));
    } else if (RNA_SERVICE_MESSAGE_TYPE_REG_PATH == buf->h.rmb_message_type) {
        /* Storage path registration */
        rna_trace("sending CONF_MGR_REG_PATH\n");

        memset(cmd, 0, 
              (sizeof(cmd_hdr_t) + sizeof(struct path_reg)));
        cmd->h.h_type = CONF_MGR_REG_PATH;
        cmd->u.path_reg.rnas = buf->u.rmb_register_path;

#if defined(LINUX_USER) || defined(WINDOWS_USER)
        if (0 != buf->u.rmb_register_path.io_stat_length) {
            cmd->u.path_reg.rnas.io_stat_rkey = 
                rna_com_get_ep_rkey(&primary_cfm_eph, 
                                buf->u.rmb_register_path.io_stat_info, 
                                buf->u.rmb_register_path.io_stat_num_mr);
        }
#endif
        rna_create_wwn_strings(&cmd->u.path_reg.rnas.rp_wwn,
                               &wwn_str, NULL, NULL, NULL);
        rna_dbg_log(RNA_DBG_INFO,
                    "registering storage path with cfm: wwn [%s] path [%s] "
                    "active_cache_mode [%d] "
                    "status [%d] stat addr [0x%"PRIx64"] stat length [%d] "
                    "rkey [0x%"PRIx64"] das [%d] flush [%d] evict [%d]\n",
                    wwn_str != NULL ? wwn_str : NULL,
                    &cmd->u.path_reg.rnas.rp_path[0],
                    (int)cmd->u.path_reg.rnas.rp_active_cache_mode,
                    cmd->u.path_reg.rnas.rp_status,
                    cmd->u.path_reg.rnas.io_stat_buf.base_addr,
                    cmd->u.path_reg.rnas.io_stat_length,
                    cmd->u.path_reg.rnas.io_stat_rkey,
                    cmd->u.path_reg.rnas.rp_das,
                    cmd->u.path_reg.rnas.rp_flush_on_shutdown,
                    cmd->u.path_reg.rnas.rp_evict_on_shutdown
                    );
        if (wwn_str) {
            rna_service_simple_free(wwn_str);
        }
    } else if (RNA_SERVICE_MESSAGE_TYPE_REG_CACHE_DEVICE ==
                                                buf->h.rmb_message_type) {
        /* Cache device registration */
        /* Make sure we eventually send an 'end of registrations' message */
        ctx->cx_cfm_flags |= CTX_CFM_FLAG_MUST_SEND_CACHEDEV_REGISTRATION_END;

        memset(cmd,
               0,
               sizeof(cmd_hdr_t) + sizeof(struct cache_cfm_reg_cachedev));
        cmd->h.h_type = CONF_MGR_REG_CACHE_DEVICE;
        cmd->h.h_cookie = buf->u.rmb_register_cache_device.cdr_cookie;
        cmd->u.cache_cfm_reg_cachedev.rnas = buf->u.rmb_register_cache_device;

        if (cmd->u.cache_cfm_reg_cachedev.rnas.cdr_result) {
            if (strlen(buf->u.rmb_register_cache_device.cdr_error_str)) {
                strcpy(cmd->u.cache_cfm_reg_cachedev.rnas.cdr_error_str,
                    buf->u.rmb_register_cache_device.cdr_error_str);
            }
#if defined(LINUX_USER) || defined (WINDOWS_USER)
        } else {
            if (0 != buf->u.rmb_register_cache_device.cdr_io_stat_length) {
                cmd->u.cache_cfm_reg_cachedev.rnas.cdr_io_stat_rkey = 
                    rna_com_get_ep_rkey(&primary_cfm_eph, 
                        buf->u.rmb_register_cache_device.cdr_io_stat_info, 
                        buf->u.rmb_register_cache_device.cdr_io_stat_num_mr);
            }
#endif
        }

        rna_dbg_log(RNA_DBG_INFO,
                    "registering cache device [%"PRIx64"] "
                    "session cookie [%"PRIx64"] "
                    "with CFM ["RNA_ADDR_FORMAT"] "
                    "stat addr [0x%"PRIx64"] "
                    "stat length [%d] "
                    "rkey [0x%"PRIx64"]\n",
                    cmd->u.cache_cfm_reg_cachedev.rnas.cdr_cachedev_label.
                                                                    cl_rna_id,
                    cmd->h.h_cookie,
                    RNA_ADDR(primary_cfm_eph.eph_dst_in.sin_addr),
                    cmd->u.cache_cfm_reg_cachedev.rnas.cdr_io_stat_buf.base_addr,
                    cmd->u.cache_cfm_reg_cachedev.rnas.cdr_io_stat_length,
                    cmd->u.cache_cfm_reg_cachedev.rnas.cdr_io_stat_rkey);
    } else if (RNA_SERVICE_MESSAGE_TYPE_REG_CACHE_DEVICE_END ==
                                                buf->h.rmb_message_type) {
        /* end of cache device registrations */
        memset(cmd,
               0,
               sizeof(cmd_hdr_t) + sizeof(struct cache_cfm_reg_cachedev_end));
        cmd->h.h_type = CONF_MGR_REG_CACHE_DEVICE_END;
        cmd->u.cache_cfm_reg_cachedev_end.rce_timestamp =
                                        ctx->cx_cfm_query_cachedev_timestamp;

        rna_dbg_log(RNA_DBG_INFO,
                    "end of cache device registrations "
                    "with CFM ["RNA_ADDR_FORMAT"]\n",
                    RNA_ADDR(primary_cfm_eph.eph_dst_in.sin_addr));
    } else {
        rna_dbg_log(RNA_DBG_ERR, "Illegal message type %d\n",
                    buf->h.rmb_message_type);
        goto done_set_timer;
    }

    ret = rna_service_com_send_cfm_cmd(&primary_cfm_eph,
                                       send_buf,
                                       cfm_cmd_length(cmd),
                                       &ctx->cx_primary_cfm_id);
    if (ret != 0) {
        rna_dbg_log(RNA_DBG_WARN, "Failed to send CFM message: %ld\n", ret);
        enqueue_waiting_cfm_registration_msg(ctx, buf, ibuf);
        schedule_waiting_cfm_msgs(ctx, SEND_WAITING_CFM_MSGS_DELAY_SEC);
        goto done_set_timer;
    } else {
        if (RNA_SERVICE_MESSAGE_TYPE_REG_BLKDEV == buf->h.rmb_message_type) {
            /* Wait for a reply for this block device registration */
            YAQ_INSERT_TAIL(&ctx->cx_registrations_waiting_for_reply,
                        &ibuf->h.rmbi_link);
        } else if (RNA_SERVICE_MESSAGE_TYPE_REG_CACHE_DEVICE_END ==
                                                    buf->h.rmb_message_type) {
            /*
             * The 'end of cache device registrations' message has been
             * successfully sent.
             */
            ctx->cx_cfm_flags &=
                            ~CTX_CFM_FLAG_MUST_SEND_CACHEDEV_REGISTRATION_END;
            rna_service_free_message_buffer(ctx, buf);
            buf = NULL;
        } else {
            /*
             * Rather than wait for a response, this registration message
             * is immediately placed in the 'registered' queue, because the
             * CFM doesn't yet reply to mount registration messages.
             */
            queue_mount_or_blkdev_registration(ctx, ibuf);
            /*
             * The cookie in a cache device registration message is the session
             * ID for the CLI command (add, reactivate, or none if the cookie
             * is zero) that triggered the registration.  A cache device
             * registration should be sent with a given non-zero cookie only
             * once.  Re-registrations of the cache device, due to disconnects
             * and reconnects, shouldn't repeat it, since the CLI command will
             * have completed and will no longer be the trigger for the
             * re-registration.
             */
            if (RNA_SERVICE_MESSAGE_TYPE_REG_CACHE_DEVICE ==
                                                    buf->h.rmb_message_type) {
                if (buf->u.rmb_register_cache_device.cdr_cookie != 0) {
                    rna_dbg_log(RNA_DBG_VERBOSE,
                                "clearing session cookie [%"PRId64"] "
                                "after successful registration of cache device "
                                "[%"PRIx64"]\n",
                                buf->u.rmb_register_cache_device.cdr_cookie,
                                buf->u.rmb_register_cache_device.
                                                cdr_cachedev_label.cl_rna_id);
                    buf->u.rmb_register_cache_device.cdr_cookie = 0;
                }
            }
        }
    }

 done_set_timer:
    /*
     * Set a response timeout if one has been requested.  (Note that only
     * block device registrations currently have responses, and that if this
     * is a retry, the timeout is already set).
     */
    if ((!retry_flag)
      && (NULL != buf)
      && (RNA_SERVICE_MESSAGE_TYPE_REG_BLKDEV == buf->h.rmb_message_type)
      && (ctx->cx_params.rsp_block_device_reg_response_timeout > 0)) {
        /*
         * (Note that because the cx_cfm_mutex is held, we know this ctx isn't
         * being shut down (see rna_service_ctx_destroy()), so it's safe to
         * call rna_service_timer_set() -- specifically, we know the timer
         * cancellation phase of the shutdown hasn't yet been executed, so
         * we won't be leaving a set timer after shutdown).
         */
        rna_service_timer_set(
                        ctx->cx_private,
                       &ibuf->h.rmbi_response_timer_object,
                        cfm_response_timed_out,
                        (uint64_t)ibuf,
                        (int) ctx->cx_params.rsp_block_device_reg_response_timeout);
    }

    /*
     * If there are no more registration messages queued to be sent to the CFM
     * and all initial cache device registrations have been sent but an 'end of
     * registrations' message has not yet been sent, send one now.
     */
    if  ((YAQ_EMPTY(&ctx->cx_cfm_registrations_waiting_to_send))
      && ((ctx->cx_cfm_flags &
                           (CTX_CFM_FLAG_INITIAL_REGISTRATIONS_COMPLETE |
                            CTX_CFM_FLAG_MUST_SEND_CACHEDEV_REGISTRATION_END))
                        == (CTX_CFM_FLAG_INITIAL_REGISTRATIONS_COMPLETE |
                            CTX_CFM_FLAG_MUST_SEND_CACHEDEV_REGISTRATION_END)))
    {
        /* Send an 'end of cache device registrations' message. */
        buf = rna_service_alloc_message_buffer(
                            ctx,
                            RNA_SERVICE_MESSAGE_TYPE_REG_CACHE_DEVICE_END,
                            NULL);
        if (NULL == buf) {
            rna_dbg_log(RNA_DBG_WARN,
                        "failed to get send buffer for "
                        "RNA_SERVICE_MESSAGE_TYPE_REG_CACHE_DEVICE_END "
                        "message\n");
        } else {
            ibuf = mbuf_to_ibuf(buf);
            /* Send the RNA_SERVICE_MESSAGE_TYPE_REG_CACHE_DEVICE_END */
            goto rmb_restart;
        }
    }

    rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
}


#ifdef WINDOWS_KERNEL

static void
dequeue_reg_mnt_or_blkdev_with_cfm(reg_mnt_blkdev_msg_work_ctx_t *workq_context)
{

    reg_mnt_blkdev_msg_work_ctx_t *wct = (reg_mnt_blkdev_msg_work_ctx_t *)workq_context;
    
    register_mount_or_blkdev_with_cfm(wct->swx_ctx, wct->buf, wct->retry_flag);

    rna_service_free(sizeof(*wct), wct);
}


/**
 * Package up a register call for a specified mount, block 
 * device or storage path to place on a lower priority work 
 * queue 
 */

static void
enqueue_reg_mnt_or_blkdev_with_cfm(rna_service_ctx_t            *ctx,
                                   rna_service_message_buffer_t *buf,
                                   boolean                       retry_flag)
{
    reg_mnt_blkdev_msg_work_ctx_t *wctx;

    wctx = rna_service_alloc0(sizeof(*wctx));
    if (NULL == wctx)
    {
        rna_dbg_log(RNA_DBG_WARN,
                    "unable to allocate memory, so unable to "
                    "enqueue register mount with CFM\n");
        return;
    }

    wctx->swx_ctx = ctx;
    wctx->retry_flag = retry_flag;
    wctx->buf = buf;
    RNA_INIT_WORK(&wctx->swx_work_obj,
                          dequeue_reg_mnt_or_blkdev_with_cfm,
                          wctx);

    (void)rna_service_workq_add(ctx->cx_cfm_connect_work_queue,
                                &wctx->swx_work_obj);
}


#endif /*WINDOWS_KERNEL*/

/*
 * A find_registration_compare_fn used by deregister_mount_or_blkdev_with_cfm.
 * Remove the registration that matches the specified de-registration.
 *
 * Arguments:
 *     ctx   The rna_service context
 *     ibuf  The queued registration message to be checked
 *     arg   The de-registration message
 */
static boolean
dereg_remove_reg(rna_service_ctx_t                     *ctx,
                 rna_service_message_buffer_internal_t *ibuf,
                 void                                  *arg)
{
    rna_service_message_buffer_t *dereg_buf;

    dereg_buf = (rna_service_message_buffer_t *) arg;

    /*
     * If the buffer we're trying to enqueue is already
     * on the appropriate queue, don't bother to do anything.
     */
    if (&ibuf->u.rmbi_message_buffer == dereg_buf) {
        rna_dbg_log(RNA_DBG_INFO,
                    "registration message is already queued, "
                    "not queuing it again.\n");
        YAQ_REMOVE(&ibuf->h.rmbi_link);
        return (TRUE);
    }    

    if (mount_blkdev_match(ibuf, dereg_buf)) {
        /*
         * Found a registration for this same mount/block device or 
         * storage path. Remove the old registration, to be replaced 
         * with the new one.
         */
        YAQ_REMOVE(&ibuf->h.rmbi_link);
        mount_blkdev_complete_dereg_msg(ibuf, dereg_buf);
        rna_service_free_message_buffer(ctx, &ibuf->u.rmbi_message_buffer);
        return (TRUE);
    }

    return (FALSE);
}


/*
 * A find_registration_compare_fn used for replica store deregistrations only,
 * by deregister_mount_or_blkdev_with_cfm.  Remove the replica store
 * registration that matches the specified de-registration from its host cache
 * device's registration.
 *
 * Arguments:
 *     ctx   The rna_service context
 *     ibuf  The queued registration message to be checked
 *     arg   The de-registration message
 */
static boolean
dereg_remove_repstore_reg(rna_service_ctx_t                     *ctx,
                          rna_service_message_buffer_internal_t *ibuf,
                          void                                  *arg)
{
    rna_service_message_buffer_t *dereg_buf;
    cachedev_id_t                 dereg_repstore_id;
    int                           num_repstores;
    rna_replica_store_info_t     *rsi;
    int                           i;

    UNREFERENCED_PARAMETER(ctx);
    
    dereg_buf = (rna_service_message_buffer_t *) arg;

    /*
     * If the buffer we're trying to enqueue is already
     * on the appropriate queue, don't bother to do anything.
     */
    if (&ibuf->u.rmbi_message_buffer == dereg_buf) {
        rna_dbg_log(RNA_DBG_INFO,
                    "registration message is already queued, "
                    "not queuing it again.\n");
        YAQ_REMOVE(&ibuf->h.rmbi_link);
        return (TRUE);
    }    

    /*
     * If the queued registration is the for the cache device that hosts this
     * replica store, then remove this replica store from the array of replica
     * stores contained in the cache device registration message.
     */
    if (dereg_buf->u.rmb_deregister_replica_store.drs_host_cachedev_id ==
            ibuf->u.rmbi_message_buffer.u.rmb_register_cache_device.
                                            cdr_cachedev_label.cl_rna_id) {
        /* get the ID of the replica store being de-registered */
        dereg_repstore_id =
                    dereg_buf->u.rmb_deregister_replica_store.drs_repstore_id;
        /* get the number of replica stores hosted by its host cache device */
        num_repstores = ibuf->u.rmbi_message_buffer.u.
                    rmb_register_cache_device.cdr_num_hosted_replica_stores;
        /*
         * initialize the replica store pointer to the first entry in the array
         * of replica stores hosted by the cache device.
         */
        rsi = ibuf->u.rmbi_message_buffer.u.
                    rmb_register_cache_device.cdr_hosted_replica_stores;
        /*
         * Find the replica store being deregistered in the array of replica
         * stores hosted by the cache device and remove the replica store
         * from the array.
         */
        for (i = 0; i < num_repstores; i++, rsi++) {
            if (rsi->rbrsi_replica_dev_id == dereg_repstore_id) {
                /*
                 * We've found the replica store being de-registered, remove it
                 * from the array of replica stores hosted by the cache device.
                 */
                for ( ; i < num_repstores-1; i++, rsi++) {
                    *rsi = *(rsi+1);
                }
                break;
            }
        }
        return (TRUE);
    }

    return (FALSE);
}


/**
 * De-register the specified mount or block device with the configuration
 * manager.
 */
static void
deregister_mount_or_blkdev_with_cfm(rna_service_ctx_t            *ctx,
                                    rna_service_message_buffer_t *buf,
                                    boolean                       retry_flag)
{
    size_t ret;
    rna_service_message_buffer_internal_t *ibuf;
    rna_service_send_buf_entry_t *send_buf;
    struct cfm_cmd *cmd;
    com_ep_handle_t primary_cfm_eph;
    uint8_t compare_msg_type;
    char *wwn_str = NULL;

    if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
        /* This failure means we're in the process of shutting down */
        rna_service_free_message_buffer(ctx, buf);
        return;
    }

    if (!retry_flag) {
        switch (buf->h.rmb_message_type) {
        case RNA_SERVICE_MESSAGE_TYPE_DEREG_MNT:
            compare_msg_type = RNA_SERVICE_MESSAGE_TYPE_REG_MNT;
            break;
        case RNA_SERVICE_MESSAGE_TYPE_DEREG_BLKDEV:
            compare_msg_type = RNA_SERVICE_MESSAGE_TYPE_REG_BLKDEV;
            break;
        case RNA_SERVICE_MESSAGE_TYPE_DEREG_SVC_CONN:
            compare_msg_type = RNA_SERVICE_MESSAGE_TYPE_REG_SVC_CONN;
            break;
        case RNA_SERVICE_MESSAGE_TYPE_DEREG_PATH:
            compare_msg_type = RNA_SERVICE_MESSAGE_TYPE_REG_PATH;
            break;
        case RNA_SERVICE_MESSAGE_TYPE_DEREG_CACHE_DEVICE:
            compare_msg_type = RNA_SERVICE_MESSAGE_TYPE_REG_CACHE_DEVICE;
            break;
        case RNA_SERVICE_MESSAGE_TYPE_DEREG_REPLICA_STORE:
            /*
             * Replica store de-registrations are handled a bit specially,
             * because there's no explicit replica store registration message.
             * Instead, the replica stores hosted by a cache device are listed
             * in an array contained in the host cache device's registration.
             * Find the host cache device's registration and remove the
             * de-registered replica store from the array of replica stores it
             * hosts.
             */
            if (!find_registration(ctx,
                                   RNA_SERVICE_MESSAGE_TYPE_REG_CACHE_DEVICE,
                                   dereg_remove_repstore_reg,
                                   buf)) {
                /*
                 * That's odd, we have no record of a registration for this
                 * replica store.  We'll send the de-registration out of
                 * paranoia.
                 */
                rna_dbg_log(RNA_DBG_WARN,"replica store "
                            "registration not found!\n");
            }
            goto dmb_restart;
        default:
            rna_dbg_log(RNA_DBG_ERR,
                        "Illegal message type [%d] [%s], ignoring\n",
                        buf->h.rmb_message_type,
                        rna_service_get_message_type_string(
                                                    buf->h.rmb_message_type));
            
            rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
            
            return;
        }

        /*
         * Remove the mount or block device from the list of registered mounts
         * or block devices.
         */
        if (!find_registration(ctx, compare_msg_type, dereg_remove_reg, buf)) {
            /*
             * That's odd, we have no record of a registration for this
             * mount being in progress.  We'll send the de-registration
             * out of paranoia.
             */
            rna_dbg_log(RNA_DBG_WARN,"mount or block device "
                        "registration not found!\n");
        }
    }

dmb_restart:
    ibuf = mbuf_to_ibuf(buf);

    if ((!rna_service_com_connected(&ctx->cx_primary_cfm_eph))
      || ((!retry_flag)
        && (!YAQ_EMPTY(&ctx->cx_cfm_registrations_waiting_to_send)))) {

        /*
         * There are messages ahead of this one waiting to be sent.  Queue this
         * message behind them.
         */
        YAQ_INSERT_TAIL(&ctx->cx_cfm_registrations_waiting_to_send,
                        &ibuf->h.rmbi_link);
        schedule_waiting_cfm_msgs(ctx, 0);
        goto done;
    }

    /*
     * Send a de-registration message to the CFM.
     */

    primary_cfm_eph = ctx->cx_primary_cfm_eph;
    if (!retry_flag) {
        /*
         * For the first try, we do a non-blocking request for a sendbuf, to
         * reduce overhead for the common case.  This request will usually
         * succeed, since sendbufs are usually available.  If it fails, we'll
         * queue a retry request.
         */
        ret = rna_service_com_get_send_buf(&primary_cfm_eph,
                                           &send_buf,
                                           FALSE,
                                           NULL);
    } else {
        /*
         * For retries, we do a blocking request for a sendbuf, since a
         * non-blocking request previously failed.  This gets a bit
         * complicated, since we don't want to hold the cx_cfm_mutex across
         * a blocking request.
         */
        com_inc_ref_eph(&primary_cfm_eph);  // (no-op at user level)
        /* Don't hold mutex across blocking operation */
        rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
        ret = rna_service_com_get_send_buf(&primary_cfm_eph,
                                           &send_buf,
                                           TRUE,
                                           NULL);
        /* Re-acquire the cx_cfm_mutex */
        if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
            /*
             * This failure means we're in the process of shutting down
             * Give back the sendbuf we allocated.
             */
            if (send_buf != NULL) {
                rna_service_com_put_send_buf(&primary_cfm_eph, send_buf);
            }
            com_release_eph(&primary_cfm_eph);  // (no-op at user level)
            rna_service_free_message_buffer(ctx, buf);
            return;
        }
        /* The primary CFM may have changed while we didn't hold the mutex */
        if (!com_eph_equal(&ctx->cx_primary_cfm_eph, &primary_cfm_eph)) {
            /*
             * The primary CFM changed, so we may hold a sendbuf on the wrong
             * ep.  If so, give it back.
             */
            if (send_buf != NULL) {
                rna_service_com_put_send_buf(&primary_cfm_eph, send_buf);
            }
            com_release_eph(&primary_cfm_eph);  // (no-op at user level)
            goto dmb_restart;   // try again with new primary CFM
        }
        com_release_eph(&primary_cfm_eph);  // (no-op at user level)
        /*
         * Make sure the message didn't time out while we were waiting for a
         * send buffer.
         */
        if (ibuf->h.rmbi_flags & RMBI_FLAG_TIMED_OUT) {
            rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
            cfm_response_timed_out((uint64_t)ibuf);
            return;
        }
    }

    if ((NULL == send_buf) || (0 != ret)) {
        /*
         * (Note that if this is a re-send, inserting the message at the tail
         * of the queue may re-order the queue, since the message was removed
         * from the head.  We're not worried about re-ordering de-registration
         * messages, though, since these messages aren't ordered).
         */
        YAQ_INSERT_TAIL(&ctx->cx_cfm_registrations_waiting_to_send,
                        &ibuf->h.rmbi_link);
        if ((retry_flag)
          && (rna_service_com_connected(&ctx->cx_primary_cfm_eph))) {
            /* This should never happen! */
            rna_dbg_log(RNA_DBG_ERR,
                        "Failed to get send buffer after blocking!\n");
        } else {
            rna_dbg_log(RNA_DBG_WARN,
                        "Failed to get send buffer!!\n");
        }
        /* schedule send_waiting_cfm_msgs() to send this message */
        schedule_waiting_cfm_msgs(ctx, SEND_WAITING_CFM_MSGS_DELAY_SEC);
        goto done;
    }

#if defined(LINUX_KERNEL) || defined(WINDOWS_KERNEL)
    cmd = (struct cfm_cmd *)(com_get_send_buf_mem(send_buf));
#else
    cmd = (struct cfm_cmd *) send_buf->mem;
#endif

    if (RNA_SERVICE_MESSAGE_TYPE_DEREG_MNT == buf->h.rmb_message_type) {
        memset(cmd, 0, sizeof(cmd_hdr_t) + sizeof(struct client_mount_dereg));
        cmd->h.h_type = CONF_MGR_DEREG_CLIENT_MOUNT;
        cmd->u.client_mount_dereg.dms_mount_id =
                                buf->u.rmb_deregister_mount.dms_mount_id;
    } else if (RNA_SERVICE_MESSAGE_TYPE_DEREG_BLKDEV ==
                                                    buf->h.rmb_message_type) {
        memset(cmd,
               0,
               sizeof(cmd_hdr_t) + sizeof(struct client_block_device_dereg));
        cmd->h.h_type = CONF_MGR_DEREG_BLOCK_DEVICE;
        cmd->h.h_cookie = buf->u.rmb_deregister_block_device.dbs_device;
        cmd->u.client_block_device_dereg = buf->u.rmb_deregister_block_device;
        strcpy(cmd->u.client_block_device_dereg.dbs_name,
                buf->u.rmb_deregister_block_device.dbs_name);
        rna_dbg_log(RNA_DBG_INFO, 
                    "Sending CONF_MGR_DEREG_BLOCK_DEVICE name [%s] [%s].\n",
                    cmd->u.client_block_device_dereg.dbs_name,
                    buf->u.rmb_deregister_block_device.dbs_name);
    } else if (RNA_SERVICE_MESSAGE_TYPE_DEREG_PATH ==
                                                    buf->h.rmb_message_type) {
        memset(cmd, 0,
            (sizeof(cmd_hdr_t) + sizeof(struct path_reg)));
        cmd->h.h_type = CONF_MGR_DEREG_PATH;
        rna_create_wwn_strings(&cmd->u.path_reg.rnas.rp_wwn,
                               &wwn_str, NULL, NULL, NULL);
        cmd->u.path_reg.rnas = buf->u.rmb_register_path;
        rna_dbg_log(RNA_DBG_INFO, 
            "Sending CONF_MGR_DEREG_PATH wwn [%s] das [%d]\n",
            wwn_str ? wwn_str : NULL,
            cmd->u.path_reg.rnas.rp_das);
        if (wwn_str) {
            rna_service_simple_free(wwn_str);
        }
    } else if (RNA_SERVICE_MESSAGE_TYPE_DEREG_SVC_CONN ==
                                                    buf->h.rmb_message_type) {
        memset(cmd,
               0,
               sizeof(cmd_hdr_t) + sizeof(struct cfm_service_reg));
        cmd->h.h_type = CONF_MGR_DISCONN_REG;
        cmd->u.cfm_service_reg.service_id =
                                buf->u.rmb_register_svc_conn.rsc_service_id;
    } else if (RNA_SERVICE_MESSAGE_TYPE_DEREG_CACHE_DEVICE ==
                                            buf->h.rmb_message_type) {
        memset(cmd,
               0,
               sizeof(cmd_hdr_t) + sizeof(struct cache_cfm_dereg_cachedev));
        cmd->h.h_type = CONF_MGR_DEREG_CACHE_DEVICE;
        cmd->h.h_cookie = buf->u.rmb_deregister_cache_device.cdd_cookie;
        cmd->u.cache_cfm_dereg_cachedev.rnas =
                                        buf->u.rmb_deregister_cache_device;
    } else if (RNA_SERVICE_MESSAGE_TYPE_DEREG_REPLICA_STORE ==
                                            buf->h.rmb_message_type) {
        memset(cmd,
               0,
               sizeof(cmd_hdr_t) + sizeof(struct cache_cfm_dereg_repstore));
        cmd->h.h_type = CONF_MGR_DEREG_REPLICA_STORE;
        cmd->u.cache_cfm_dereg_repstore.rnas =
                                        buf->u.rmb_deregister_replica_store;
    }

    ret = rna_service_com_send_cfm_cmd(&ctx->cx_primary_cfm_eph,
                                       send_buf,
                                       cfm_cmd_length(cmd),
                                       &ctx->cx_primary_cfm_id);
    rna_dbg_log(RNA_DBG_INFO, 
                    "Sending cmd length [%ld] ret %ld.\n",
                               cfm_cmd_length(cmd), ret);
    if (ret != 0) {
        rna_dbg_log(RNA_DBG_WARN, "Failed to send CFM message: %ld\n", ret);
        /*
         * (Note that if this is a re-send, inserting the message at the tail
         * of the queue may re-order the queue, since the message was removed
         * from the head.  We're not worried about re-ordering de-registration
         * messages, though, since these messages aren't ordered).
         */
        YAQ_INSERT_TAIL(&ctx->cx_cfm_registrations_waiting_to_send,
                        &ibuf->h.rmbi_link);
        schedule_waiting_cfm_msgs(ctx, SEND_WAITING_CFM_MSGS_DELAY_SEC);
        goto done;
    } else {
        /* Free the message buffer, since there's no reply for this message */
        rna_service_free_message_buffer(ctx, buf);
    }

 done:
    rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
}


/*!
 * Generic routine used by rna_service_send_mount_registration,
 * rna_service_send_mount_deregistration, rna_service_send_blkdev_registration,
 * rna_service_send_blkdev_deregistration and 
 * rna_service_send_paths_to_cfm to send a mount/block device/storage path
 * registration or deregistration message to the CFM.
 *
 * Arguments:
 *    ctx     The caller's rna_service context, created by
 *            rna_service_ctx_create()
 *    buf     A message buffer that specifies the message to be sent.
 *    response_callback
 *            If non-NULL, the callback routine that will be invoked either
 *            when a response to this message is received or when the response
 *            times out (if the user has specified a response timeout).
 *
 * Returns:
 *    RNA_SERVICE_ERROR_NONE  On success
 *    RNA_SERVICE_ERROR_INVALID_CTX
 *                            Either ctx is NULL, or it is in the process of
 *                            shutting down (rna_service_ctx_destroy() has been
 *                            called), or it was not created by
 *                            rna_service_ctx_create().
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE
 *                            The rmb_message_type of 'buf' is invalid.
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER
 *                            The message buffer specified was not allocated by
 *                            rna_service_alloc_message_buffer() or has not yet
 *                            been returned in a response callback.
 */
static rna_service_error_t
send_registration_or_deregistration(
                            rna_service_ctx_t            *ctx,
                            rna_service_message_buffer_t *buf,
                            rna_service_response_callback response_callback)
{
    rna_service_message_buffer_internal_t *ibuf;
    rna_service_error_t ret = RNA_SERVICE_ERROR_NONE;

    ibuf = mbuf_to_ibuf(buf);
    if (ibuf->h.rmbi_watermark != MESSAGE_BUFFER_INTERNAL_WATERMARK_ALLOCATED) {
        /*
         * Possibly this struct is already queued or was not allocated by
         * rna_service_alloc_message_buffer().
         */
        return (RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER);
    }
    if (ibuf->h.rmbi_msg_type != buf->h.rmb_message_type) {
        rna_dbg_log(RNA_DBG_WARN,
                    "message type mismatch (%d vs. %d)\n",
                    ibuf->h.rmbi_msg_type,
                    buf->h.rmb_message_type);
        return (RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE);
    }

    if ((NULL == ctx)
      || (ctx->cx_watermark != RNA_SERVICE_CTX_WATERMARK)
      || (!ctx_add_reference(&ctx))) {
        rna_dbg_log(RNA_DBG_WARN,
                    "called with NULL or corrupt rna_service_ctx [%p]\n", ctx);
        return (RNA_SERVICE_ERROR_INVALID_CTX);
    }

    ibuf->h.rmbi_response_callback = response_callback;
    ibuf->h.rmbi_watermark = MESSAGE_BUFFER_INTERNAL_WATERMARK_QUEUED;

    rna_service_might_sleep();  // needed at kernel-level; no-op at user level

    /*
     * (In the following cases, we don't care about a failure return from
     * *register_*_with_cfm().  If the request fails, it'll be retried later).
     */
    switch (buf->h.rmb_message_type) {
        case RNA_SERVICE_MESSAGE_TYPE_REG_MNT:
        case RNA_SERVICE_MESSAGE_TYPE_REG_BLKDEV:
        case RNA_SERVICE_MESSAGE_TYPE_REG_SVC_CONN:
        case RNA_SERVICE_MESSAGE_TYPE_REG_PATH:
        case RNA_SERVICE_MESSAGE_TYPE_REG_CACHE_DEVICE:
#ifdef WINDOWS_KERNEL
            enqueue_reg_mnt_or_blkdev_with_cfm(ctx, buf, FALSE);
#else
            register_mount_or_blkdev_with_cfm(ctx, buf, FALSE);
#endif /*WINDOWS_KERNEL*/
            break;

        case RNA_SERVICE_MESSAGE_TYPE_DEREG_MNT:
        case RNA_SERVICE_MESSAGE_TYPE_DEREG_BLKDEV:
        case RNA_SERVICE_MESSAGE_TYPE_DEREG_SVC_CONN:
        case RNA_SERVICE_MESSAGE_TYPE_DEREG_PATH:
        case RNA_SERVICE_MESSAGE_TYPE_DEREG_CACHE_DEVICE:
        case RNA_SERVICE_MESSAGE_TYPE_DEREG_REPLICA_STORE:
            deregister_mount_or_blkdev_with_cfm(ctx, buf, FALSE);
            break;

        default:
            ret = RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE;
            break;
    }

    ctx_release_reference(&ctx);
    return (ret);
}


/*!
 * Generic routine used to send a message OTHER THAN a registration or
 * de-registration to the CFM.
 *
 * Arguments:
 *    ctx     The caller's rna_service context, created by
 *            rna_service_ctx_create()
 *    buf     A message buffer that specifies the message to be sent.
 *    retry_flag
 *            FALSE if this is the first attempt to send the message
 *            (i.e. called by the user's thread).  TRUE is this is a retry
 *            (i.e. called by send_waiting_cfm_msgs).
 *
 * Returns:
 *    RNA_SERVICE_ERROR_NONE  On success
 *    RNA_SERVICE_ERROR_INVALID_CTX
 *                            Either ctx is NULL, or it is in the process of
 *                            shutting down (rna_service_ctx_destroy() has been
 *                            called), or it was not created by
 *                            rna_service_ctx_create().
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE
 *                            The rmb_message_type of 'buf' is invalid.
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER
 *                            The message buffer specified was not allocated by
 *                            rna_service_alloc_message_buffer() or has not yet
 *                            been returned in a response callback.
 */
static rna_service_error_t
send_cfm_non_reg_dereg(rna_service_ctx_t            *ctx,
                       rna_service_message_buffer_t *buf,
                       boolean                       retry_flag)
{
    rna_service_message_buffer_internal_t *ibuf;
    rna_service_error_t ret = RNA_SERVICE_ERROR_NONE;
    com_ep_handle_t primary_cfm_eph;
    rna_service_send_buf_entry_t *send_buf;
    struct cfm_cmd *cmd;

    ibuf = mbuf_to_ibuf(buf);
    if (((FALSE == retry_flag) &&
         (ibuf->h.rmbi_watermark !=
            MESSAGE_BUFFER_INTERNAL_WATERMARK_ALLOCATED)) ||
        ((TRUE == retry_flag) &&
         (ibuf->h.rmbi_watermark !=
            MESSAGE_BUFFER_INTERNAL_WATERMARK_QUEUED))) {
        /*
         * Possibly this struct is already queued or was not allocated by
         * rna_service_alloc_message_buffer().
         */
        rna_dbg_log(RNA_DBG_WARN,
                    "Message buffer has invalid watermark "
                    "retry_flag [%d] "
                    "watermark [%"PRIu64"]\n",
                    retry_flag,
                    ibuf->h.rmbi_watermark);

        return (RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER);
    }
    if (ibuf->h.rmbi_msg_type != buf->h.rmb_message_type) {
        rna_dbg_log(RNA_DBG_WARN,
                    "message type mismatch (%d vs. %d)\n",
                    ibuf->h.rmbi_msg_type,
                    buf->h.rmb_message_type);
        return (RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE);
    }

    if ((NULL == ctx)
      || (ctx->cx_watermark != RNA_SERVICE_CTX_WATERMARK)
      || (!ctx_add_reference(&ctx))) {
        rna_dbg_log(RNA_DBG_WARN,
                    "called with NULL or corrupt rna_service_ctx [%p]\n", ctx);
        return (RNA_SERVICE_ERROR_INVALID_CTX);
    }

    ibuf->h.rmbi_response_callback = NULL;
    ibuf->h.rmbi_watermark = MESSAGE_BUFFER_INTERNAL_WATERMARK_QUEUED;

    rna_service_might_sleep();  // needed at kernel-level; no-op at user level

    if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
        /* This failure means we're in the process of shutting down */
        rna_service_free_message_buffer(ctx, buf);
        return (RNA_SERVICE_ERROR_NONE);
    }

 scnrd_restart:
    /*
     * If there's no primary CFM to send this message to or if this isn't a
     * retry and messages are queued waiting to be sent, queue this message
     * behind them.
     */
    if ((!rna_service_com_connected(&ctx->cx_primary_cfm_eph))
      || ((!retry_flag)
        && (!YAQ_EMPTY(&ctx->cx_cfm_msgs_waiting_to_send)))) {

        YAQ_INSERT_TAIL(&ctx->cx_cfm_msgs_waiting_to_send, &ibuf->h.rmbi_link);
        schedule_waiting_cfm_msgs(ctx, 0);
        goto scnrd_done;
    }

    primary_cfm_eph = ctx->cx_primary_cfm_eph;
    if (!retry_flag) {
        /*
         * For the first try, we do a non-blocking request for a sendbuf, to
         * reduce overhead for the common case.  This request will usually
         * succeed, since sendbufs are usually available.  If it fails, we'll
         * queue a retry request.
         */
        ret = rna_service_com_get_send_buf(&primary_cfm_eph,
                                           &send_buf,
                                           FALSE,
                                           NULL);
    } else {
        /*
         * For retries, we do a blocking request for a sendbuf, since a
         * non-blocking request previously failed.  This gets a bit
         * complicated, since we don't want to hold the cx_cfm_mutex across
         * a blocking request.
         */
        com_inc_ref_eph(&primary_cfm_eph);  // (no-op at user level)
        /* Don't hold mutex across blocking operation */
        rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
        ret = rna_service_com_get_send_buf(&primary_cfm_eph,
                                           &send_buf,
                                           TRUE,
                                           NULL);
        /* Re-acquire the cx_cfm_mutex */
        if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
            /*
             * This failure means we're in the process of shutting down
             * Give back the sendbuf we allocated.
             */
            if (send_buf != NULL) {
                rna_service_com_put_send_buf(&primary_cfm_eph, send_buf);
            }
            com_release_eph(&primary_cfm_eph);  // (no-op at user level)
            return (RNA_SERVICE_ERROR_NONE);
        }
        /* The primary CFM may have changed while we didn't hold the mutex */
        if (!com_eph_equal(&ctx->cx_primary_cfm_eph, &primary_cfm_eph)) {
            /*
             * The primary CFM changed, so we may hold a sendbuf on the wrong
             * ep.  If so, give it back.
             */
            if (send_buf != NULL) {
                rna_service_com_put_send_buf(&primary_cfm_eph, send_buf);
            }
            com_release_eph(&primary_cfm_eph);  // (no-op at user level)
            goto scnrd_restart;   // try again with new primary CFM
        }
        com_release_eph(&primary_cfm_eph);  // (no-op at user level)
        /*
         * Make sure the message didn't time out while we were waiting for a
         * send buffer.
         */
        if (ibuf->h.rmbi_flags & RMBI_FLAG_TIMED_OUT) {
            rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
            cfm_response_timed_out((uint64_t)ibuf);
            ctx_release_reference(&ctx);
            return (RNA_SERVICE_ERROR_NONE);
        }
    }

    if ((NULL == send_buf) || (0 != ret)) {
        if ((retry_flag)
          && (rna_service_com_connected(&primary_cfm_eph))) {
            /* This should never happen! */
            rna_dbg_log(RNA_DBG_ERR,
                        "Failed to get send buffer after blocking!\n");
        } else {
            rna_dbg_log(RNA_DBG_WARN,
                        "Failed to get send buffer!!\n");
        }
        /* Schedule a retry */
        if (TRUE == retry_flag) {
            /*
             * Place this message back where it was in the 'waiting to send'
             * queue, so the queue isn't re-ordered.
             */
            YAQ_INSERT_HEAD(&ctx->cx_cfm_msgs_waiting_to_send,
                            &ibuf->h.rmbi_link);
        } else {
            /* This is a new message; place it at the end of the queue */
            YAQ_INSERT_TAIL(&ctx->cx_cfm_msgs_waiting_to_send,
                            &ibuf->h.rmbi_link);
        }
        schedule_waiting_cfm_msgs(ctx, SEND_WAITING_CFM_MSGS_DELAY_SEC);
        goto scnrd_done;
    }

#if defined(LINUX_KERNEL) || defined(WINDOWS_KERNEL)
    cmd = (struct cfm_cmd *)(com_get_send_buf_mem(send_buf));
#else
    cmd = (struct cfm_cmd *) send_buf->mem;
#endif
    memset(cmd, 0, sizeof(cmd_hdr_t));

    ibuf->h.rmbi_req_msg_id = ctx->cx_cfm_next_msg_id++;

    if (RNA_SERVICE_MESSAGE_TYPE_RESILVER_CACHE_DEVICE_COMPLETE ==
                                                    buf->h.rmb_message_type) {
        cmd->h.h_type = CONF_MGR_RESILVER_CACHE_DEVICE_COMPLETE;
        cmd->u.cache_cfm_resilver_cachedev_complete.rnas =
                                    buf->u.rmb_resilver_cache_device_complete;
        cmd->u.cache_cfm_resilver_cachedev_complete.rnas.rcdc_msg_id =
                                                    ibuf->h.rmbi_req_msg_id;
        rna_dbg_log(RNA_DBG_INFO,
                    "notifying the CFM that resilvering of cache device "
                    "[%"PRIx64"] is complete\n",
                    buf->u.rmb_resilver_cache_device_complete.rcdc_cachedev_id);
    } else if (RNA_SERVICE_MESSAGE_TYPE_CONTROL_BLKDEV_RESPONSE ==
                                                    buf->h.rmb_message_type) {
        cmd->h.h_type = CONF_MGR_BLOCK_DEVICE_CONTROL_RESP;
        cmd->h.h_cookie = buf->u.rmb_control_block_device_response.cbr_cookie;
        cmd->u.client_control_block_device_resp.type =
                        buf->u.rmb_control_block_device_response.cbr_type;
        cmd->u.client_control_block_device_resp.result =
                        buf->u.rmb_control_block_device_response.cbr_result;
        cmd->u.client_control_block_device_resp.final =
                        buf->u.rmb_control_block_device_response.cbr_final;
        strcpy(cmd->u.client_control_block_device_resp.name,
               buf->u.rmb_control_block_device_response.cbr_name);

        rna_dbg_log(RNA_DBG_INFO, 
                    "control response for type %d name [%s] result %d %s\n",
                    cmd->u.client_control_block_device_resp.type,
                    cmd->u.client_control_block_device_resp.name,
                    cmd->u.client_control_block_device_resp.result,
                    cmd->u.client_control_block_device_resp.final ? "Final"
                                                                  : "Progress");
    } else if (RNA_SERVICE_MESSAGE_TYPE_CONTROL_CS_RESPONSE ==
                                                    buf->h.rmb_message_type) {
        cmd->h.h_type = CONF_MGR_CONTROL_CS_RESP;
        cmd->h.h_cookie = buf->u.rmb_control_cs_response.ccr_cookie;
        cmd->u.control_cs_resp.type = buf->u.rmb_control_cs_response.ccr_type;
        cmd->u.control_cs_resp.result =
                                    buf->u.rmb_control_cs_response.ccr_result;
        cmd->u.control_cs_resp.final =
                                    buf->u.rmb_control_cs_response.ccr_final;
    } else if (RNA_SERVICE_MESSAGE_TYPE_NOTIFICATION_EVENT ==
                                                    buf->h.rmb_message_type) {
        cmd->h.h_type = CONF_MGR_NOTIFICATION_EVENT;
        cmd->u.client_notification_event.event =
                                        buf->u.rmb_notification_event.event;
        cmd->u.client_notification_event.cookie =
                                        buf->u.rmb_notification_event.cookie;
        strncpy(cmd->u.client_notification_event.persist_location,
                buf->u.rmb_notification_event.persist_location,
                PATH_MAX+1);
    } else if (RNA_SERVICE_MESSAGE_TYPE_EVENT == buf->h.rmb_message_type) {
        cmd->u.rna_event.rnas = buf->u.rmb_event;
        cmd->h.h_type = CONF_MGR_EVENT;
    } else if (RNA_SERVICE_MESSAGE_TYPE_CS_SHUTDOWN_REQUEST ==
                                                    buf->h.rmb_message_type) {
        cmd->h.h_type = CONF_MGR_CS_SHUTDOWN_REQ;
        cmd->u.cache_cfm_shutdown_req.rnas.sr_msg_id = ibuf->h.rmbi_req_msg_id;
        rna_dbg_log(RNA_DBG_INFO,
                    "requesting permission to shut down from the CFM\n");

    } else if (RNA_SERVICE_MESSAGE_TYPE_UPDATE_SCSI_ITN_RES ==
                buf->h.rmb_message_type) {
        cmd->h.h_type = CONF_MGR_CS_UPDATE_SCSI_ITN_RES;
        cmd->u.cache_cfm_update_scsi_itn_reservation.rnas =
                buf->u.rmb_cfm_update_scsi_itn_reservation;
        cmd->u.cache_cfm_update_scsi_itn_reservation.rnas.
                scsi_res_update_msg_id = ibuf->h.rmbi_req_msg_id;
        rna_dbg_log(RNA_DBG_INFO,
                    "requesting scsi reservation UPDATE\n");

    } else if (RNA_SERVICE_MESSAGE_TYPE_UPDATE_SCSI_ITN_REG ==
                buf->h.rmb_message_type) {
        cmd->h.h_type = CONF_MGR_CS_UPDATE_SCSI_ITN_REG;
        cmd->u.cache_cfm_update_scsi_itn_registration.rnas =
                buf->u.rmb_cfm_update_scsi_itn_registration;
        cmd->u.cache_cfm_update_scsi_itn_registration.rnas.
                scsi_reg_update_msg_id = ibuf->h.rmbi_req_msg_id;
        rna_dbg_log(RNA_DBG_INFO,
                    "requesting scsi registration UPDATE\n");

    } else if (RNA_SERVICE_MESSAGE_TYPE_CLEAR_SCSI_ITN_RES ==
                buf->h.rmb_message_type) {
        cmd->h.h_type = CONF_MGR_CS_CLEAR_SCSI_ITN_RES;
        cmd->u.cache_cfm_clear_scsi_itn_reservation.rnas =
                buf->u.rmb_cfm_clear_scsi_itn_reservation;
        cmd->u.cache_cfm_clear_scsi_itn_reservation.rnas.
                scsi_res_clear_msg_id = ibuf->h.rmbi_req_msg_id;
        rna_dbg_log(RNA_DBG_INFO,
                    "requesting scsi reservation CLEAR\n");

    } else if (RNA_SERVICE_MESSAGE_TYPE_ACQUIRE_SCSI_ITN_RES ==
                buf->h.rmb_message_type) {
        cmd->h.h_type = CONF_MGR_CS_ACQUIRE_SCSI_ITN_RES;
        cmd->u.cache_cfm_acquire_scsi_itn_reservation.rnas =
                buf->u.rmb_cfm_acquire_scsi_itn_reservation;
        cmd->u.cache_cfm_acquire_scsi_itn_reservation.rnas.
                scsi_res_acquire_msg_id = ibuf->h.rmbi_req_msg_id;
        rna_dbg_log(RNA_DBG_INFO,
                    "requesting scsi reservation ACQUIRE\n");

    } else if (RNA_SERVICE_MESSAGE_TYPE_ACQUIRE_SCSI_ITN_REG ==
                buf->h.rmb_message_type) {
        cmd->h.h_type = CONF_MGR_CS_ACQUIRE_SCSI_ITN_REG;
        cmd->u.cache_cfm_acquire_scsi_itn_registration.rnas =
                buf->u.rmb_cfm_acquire_scsi_itn_registration;
        cmd->u.cache_cfm_acquire_scsi_itn_registration.rnas.
                scsi_reg_acquire_msg_id = ibuf->h.rmbi_req_msg_id;
        rna_dbg_log(RNA_DBG_INFO,
                    "requesting scsi registration ACQUIRE\n");

    } else {
        rna_dbg_log(RNA_DBG_ERR, "Illegal message type %d\n",
                    buf->h.rmb_message_type);
        goto scnrd_done;
    }

    ret = rna_service_com_send_cfm_cmd(&primary_cfm_eph,
                                       send_buf,
                                       cfm_cmd_length(cmd),
                                       &ctx->cx_primary_cfm_id);
    if (ret != 0) {
        rna_dbg_log(RNA_DBG_WARN, "Failed to send CFM message: %d\n", ret);
        if (TRUE == retry_flag) {
            /*
             * Place this message back where it was in the 'waiting to send'
             * queue, so the queue isn't re-ordered.
             */
            YAQ_INSERT_HEAD(&ctx->cx_cfm_msgs_waiting_to_send,
                            &ibuf->h.rmbi_link);
        } else {
            /* This is a new message; place it at the end of the queue */
            YAQ_INSERT_TAIL(&ctx->cx_cfm_msgs_waiting_to_send,
                            &ibuf->h.rmbi_link);
        }
        schedule_waiting_cfm_msgs(ctx, SEND_WAITING_CFM_MSGS_DELAY_SEC);
    } else if ((RNA_SERVICE_MESSAGE_TYPE_RESILVER_CACHE_DEVICE_COMPLETE ==
                                                    buf->h.rmb_message_type) ||
               (RNA_SERVICE_MESSAGE_TYPE_CS_SHUTDOWN_REQUEST ==
                                                    buf->h.rmb_message_type) ||
               (RNA_SERVICE_MESSAGE_TYPE_UPDATE_SCSI_ITN_RES ==
                                                    buf->h.rmb_message_type) ||
               (RNA_SERVICE_MESSAGE_TYPE_UPDATE_SCSI_ITN_REG ==
                                                    buf->h.rmb_message_type) ||
               (RNA_SERVICE_MESSAGE_TYPE_CLEAR_SCSI_ITN_RES ==
                                                    buf->h.rmb_message_type) ||
               (RNA_SERVICE_MESSAGE_TYPE_ACQUIRE_SCSI_ITN_RES ==
                                                    buf->h.rmb_message_type) ||
               (RNA_SERVICE_MESSAGE_TYPE_ACQUIRE_SCSI_ITN_REG ==
                                                    buf->h.rmb_message_type)) {
        YAQ_INSERT_TAIL(&ctx->cx_cfm_waiting_for_reply, &ibuf->h.rmbi_link);

        /* Only the shutdown request has a timer? */
        if (RNA_SERVICE_MESSAGE_TYPE_CS_SHUTDOWN_REQUEST ==
                                                    buf->h.rmb_message_type) {
            rna_service_timer_cancel(&ctx->cx_send_shutdown_request_timer);
            ctx->cx_send_shutdown_request_timer_is_set = FALSE;
        }
    } else {
        rna_service_free_message_buffer(ctx, buf);
    }

 scnrd_done:
    rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
    ctx_release_reference(&ctx);
    return (ret);
}


/**
 * Process a response from the CFM to a non-registration/deregistration message
 * we sent (for example, this response might be a
 * CONF_MGR_RESILVER_CACHE_DEVICE_COMPLETE_RESP message).
 */
static int
process_cfm_non_reg_dereg_response(rna_service_ctx_t *ctx,
                                   com_ep_handle_t   *eph,
                                   struct cfm_cmd    *cmd)
{
    YAQ_LINK                     *e;
    rna_service_message_buffer_internal_t
                                 *ib, *ibuf;
    uint64_t                      msg_id;

    rna_service_assert(NULL != ctx);
    rna_service_assert(NULL != eph);
    rna_service_assert(NULL != cmd);

    /*
     * Get the message ID that was stuffed into the request's message ID field
     * and returned in the response
     */
    switch (cmd->h.h_type) {
        case CONF_MGR_RESILVER_CACHE_DEVICE_COMPLETE_RESP:
            msg_id =
                cmd->u.cache_cfm_resilver_cachedev_complete_resp.req_msg_id;
            break;

        case CONF_MGR_CS_SHUTDOWN_RESP:
            msg_id = cmd->u.cache_cfm_shutdown_resp.req_msg_id;
            ctx->cx_send_shutdown_request_in_progress = FALSE;
            break;

        case CONF_MGR_CS_UPDATE_CLEAR_SCSI_ITN_RES_RESP:
            msg_id = cmd->u.
                cache_cfm_update_clear_scsi_itn_resg_response.rnas.
                    scsi_resg_resp_msg_id;
            break;

        case CONF_MGR_CS_ACQUIRE_SCSI_ITN_RES_RESP:
            msg_id = cmd->u.
                cache_cfm_acquire_scsi_itn_reservation_response.rnas.
                    scsi_res_acquire_resp_msg_id;
            break;

        case CONF_MGR_CS_ACQUIRE_SCSI_ITN_REG_RESP:
            msg_id = cmd->u.
                cache_cfm_acquire_scsi_itn_registration_response.rnas.
                    scsi_reg_acquire_resp_msg_id;
            break;

        default:
            rna_dbg_log(RNA_DBG_ERR,
                        "Unexpected message type %s, ignoring\n",
                        get_cmd_type_string(cmd->h.h_type));
            return (-1);
    }

    if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
        // This failure means we're in the process of shutting down; do nothing
        return (0);
    }

    /*
     * Find the message this response is a reply to.
     */
    ibuf = NULL;
    YAQ_FOREACH(&ctx->cx_cfm_waiting_for_reply, e) {
        ib = YAQ_OBJECT(rna_service_message_buffer_internal_t, h.rmbi_link, e);
        if (ib->h.rmbi_req_msg_id == msg_id) {
            ibuf = ib;
            break;
        }
    }
    if (NULL == ibuf) {
        /*
         * Possibly this is a late response from a CFM that has since died or
         * been demoted?
         */
        rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
        rna_dbg_log(RNA_DBG_VERBOSE,
                    "Received a response (id [%"PRIu64"]) to a "
                    "message that we have no record of having sent\n",
                    msg_id);
    } else {
        YAQ_REMOVE(&ibuf->h.rmbi_link);
        rna_service_mutex_unlock(&ctx->cx_cfm_mutex);

        if (MESSAGE_BUFFER_INTERNAL_WATERMARK_QUEUED != ibuf->h.rmbi_watermark)
        {
            rna_dbg_log(RNA_DBG_WARN,
                        "queued message has incorrect state [%"PRIx64"]\n",
                        ibuf->h.rmbi_watermark);
        }

        ibuf->h.rmbi_watermark = MESSAGE_BUFFER_INTERNAL_WATERMARK_ALLOCATED;
        rna_service_free_message_buffer(ctx, &ibuf->u.rmbi_message_buffer);
    }

    /*
     * CONF_MGR_CS_SHUTDOWN_RESP,
     * CONF_MGR_CS_UPDATE_CLEAR_SCSI_ITN_RES_RESP,
     * CONF_MGR_CS_ACQUIRE_SCSI_ITN_RES_RESP,
     * CONF_MGR_CS_ACQUIRE_SCSI_ITN_REG_RESP,
     * get handed up to the cache server.
     */
    if ((CONF_MGR_CS_SHUTDOWN_RESP == cmd->h.h_type) ||
        (CONF_MGR_CS_UPDATE_CLEAR_SCSI_ITN_RES_RESP == cmd->h.h_type) ||
        (CONF_MGR_CS_ACQUIRE_SCSI_ITN_RES_RESP == cmd->h.h_type) ||
        (CONF_MGR_CS_ACQUIRE_SCSI_ITN_REG_RESP == cmd->h.h_type)) {
        process_cs_async_message(ctx, eph, cmd);
    }

    return (0);
}


/**
 * Register the user of this library with the configuration manager.
 */
static ssize_t
register_with_cfm(rna_service_ctx_t *ctx)
{
    com_ep_handle_t               primary_cfm_eph;
    cfm_info_t                   *cfm_info;
    size_t                        ret;
    rna_rkey_t                    stat_rkey = 0;
    rna_service_send_buf_entry_t *send_buf;
    struct cfm_cmd               *cmd;

    rna_service_assert(NULL != ctx);

    if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
        /* This failure means we're in the process of shutting down */
        return (-1);
    }

    primary_cfm_eph = ctx->cx_primary_cfm_eph;
    if (NULL == com_get_ep_ptr(&primary_cfm_eph)) {
        /*
         * We don't have a connection with the primary CFM.  Most likely,
         * it disconnected before the work queue thread got around to running
         * this routine.
         */
        rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
        return (-1);
    }
    cfm_info = find_connected_cfm_by_eph(ctx, &primary_cfm_eph);
    if (NULL == cfm_info) {
        /*
         * That's odd: we have a primary CFM, but it's not listed in the set of
         * connected CFMs.
         */
        rna_dbg_log(RNA_DBG_ERR, 
                    "Primary CFM ["RNA_ADDR_FORMAT"] has no record in "
                    "connected CFM list.  Aborting registration with CFM.\n",
                    RNA_ADDR(primary_cfm_eph.eph_dst_in.sin_addr));
        rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
        return (-2);
    }

    /*
     * If the user has specified a stats buffer, get its RDMA information or
     * register it for RDMA with the CFM if it hasn't yet been registered.
     */
    if (0 != ctx->cx_params.rsp_stat_length) {
        ret = rna_service_com_get_rdma_info(ctx->cx_com_instance,
                                           &primary_cfm_eph,
                                            ctx->cx_params.rsp_stat_buf,
                                            ctx->cx_params.rsp_stat_length,
                                           &stat_rkey,
                                           &cfm_info->ci_stat_info);
        if (0 != ret) {
            rna_dbg_log(RNA_DBG_WARN,
                        "Failed to get/register stat info: %ld\n", ret);
            /*
             * It's better to delay and retry so that stat info
             * can be available.
             */
            rna_dbg_log(RNA_DBG_WARN, 
                        "Requeing registration with Primary CFM ["RNA_ADDR_FORMAT"]\n",
                        RNA_ADDR(primary_cfm_eph.eph_dst_in.sin_addr));
            rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
            rna_service_timer_cancel(&ctx->cx_cs_cfm_registration_timer);
            rna_service_timer_set(ctx->cx_private,
                                  &ctx->cx_cs_cfm_registration_timer,
                                  register_with_cfm_tc,
                                  (uint64_t)ctx,
                                  RNA_SERVICE_CS_CFM_REGISTRATION_TIMEOUT);
            return (RETRY_PCFM_REGISTRATION);
        }
    }
    
    /* Don't hold the cx_cfm_mutex across blocking operations */
    com_inc_ref_eph(&primary_cfm_eph);  // (no-op at user level)
    rna_service_mutex_unlock(&ctx->cx_cfm_mutex);

    rna_dbg_log(RNA_DBG_INFO,
                "registering client with CFM ["RNA_ADDR_FORMAT"]\n",
                RNA_ADDR(primary_cfm_eph.eph_dst_in.sin_addr));

    ret = rna_service_com_get_send_buf(&primary_cfm_eph, &send_buf, TRUE, NULL);
    if ((NULL == send_buf) || (0 != ret)) {
        if (rna_service_com_connected(&primary_cfm_eph)) {
            /* This should never happen! */
            rna_dbg_log(RNA_DBG_ERR,
                        "Failed to get send buffer after blocking!\n");
        } else {
            rna_dbg_log(RNA_DBG_WARN,
                        "Failed to get send buffer!!\n");
            /* schedule send_waiting_cfm_msgs() to send this message */
        }
        com_release_eph(&primary_cfm_eph);  // (no-op at user level)
        return (-1);
    }

#if defined(LINUX_KERNEL) || defined(WINDOWS_KERNEL)
    cmd = (struct cfm_cmd *)(com_get_send_buf_mem(send_buf));
#else
    cmd = (struct cfm_cmd *) send_buf->mem;
#endif

    if (RNA_SERVICE_USER_TYPE_CACHE_SERVER == ctx->cx_params.rsp_user_type) {
        /* The user is a cache server. */
        memset(cmd, 0, sizeof(cmd_hdr_t) + sizeof(struct cache_cfm_reg));
        cmd->h.h_type = CONF_MGR_REG_CACHE;

        cmd->u.cache_cfm_reg.service_id = ctx->cx_params.rsp_service_id;
        strcpy(cmd->u.cache_cfm_reg.hostname, ctx->cx_params.rsp_node_name);
        cmd->u.cache_cfm_reg.ccr_cs_membership_generation =
                                            ctx->cx_cs_membership_generation;
        cmd->u.cache_cfm_reg.pid = rna_service_getpid();    // for debugging
        cmd->u.cache_cfm_reg.stat_buf.device_id.data = 0;
        cmd->u.cache_cfm_reg.stat_buf.base_addr =
                                        (uint64_t)ctx->cx_params.rsp_stat_buf;
        cmd->u.cache_cfm_reg.stat_rkey = stat_rkey;
        cmd->u.cache_cfm_reg.stat_length = ctx->cx_params.rsp_stat_length;
        cmd->u.cache_cfm_reg.byte_order = CPU_BE;
        cmd->u.cache_cfm_reg.max_mem = ctx->cx_cs_params.csp_cs_max_mem;
        cmd->u.cache_cfm_reg.host_total_mem =
                                            ctx->cx_cs_params.csp_cs_total_mem;
        cmd->u.cache_cfm_reg.host_avail_mem =
                                            ctx->cx_cs_params.csp_cs_avail_mem;

        if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
            /* This failure means we're in the process of shutting down */
            return (-1);
        }
        if (ctx->cx_cfm_flags & CTX_CFM_FLAG_INITIAL_REGISTRATION_SENT) {
            cmd->u.cache_cfm_reg.ccr_flags |= CACHE_CFM_REG_FLAG_REREGISTRATION;
        } else {
            ctx->cx_cfm_flags |= CTX_CFM_FLAG_INITIAL_REGISTRATION_SENT;
        }

        if (ctx->cx_cfm_flags & CTX_CFM_FLAG_ACTIVATED) {
            cmd->u.cache_cfm_reg.ccr_flags |= CACHE_CFM_REG_FLAG_ACTIVATED;
        }

        /*
         * Set the cfm timer so we can force a CS restart if we don't
         * get a registration response.
         */
        rna_service_timer_cancel(&ctx->cx_primary_cfm_registration_timer);
        rna_service_timer_set(ctx->cx_private,
            &ctx->cx_primary_cfm_registration_timer,
            rna_service_primary_cfm_registration_to, (uint64_t)ctx,
            (int)RNA_SERVICE_CFM_REGISTRATION_TIMEOUT);
        ctx->cx_cfm_flags |= CTX_CFM_FLAG_REGISTRATION_TIMER_SET;
        rna_dbg_log(RNA_DBG_INFO, "Set primary cfm registration timer\n");

        rna_service_mutex_unlock(&ctx->cx_cfm_mutex);


        rna_dbg_log(RNA_DBG_INFO, "global stat buf addr [0x%"PRIx64"], length [%d], "
                    "stat rkey [0x%"PRIx64"]\n",
                    (uint64_t)ctx->cx_params.rsp_stat_buf,
                    ctx->cx_params.rsp_stat_length,
                    (uint64_t)stat_rkey);
        /*
         * Give the CFM the current partition map.  This is useful if the CFM
         * is newly started and this CS has been running for a while.
         * (We need to hold the cx_md_mutex to assure we get a consistent copy
         * of the partition_map).
         */
        if (!rna_service_mutex_lock(&ctx->cx_md_mutex)) {
            // This failure means we're in the process of shutting down;
            // do nothing
            com_release_eph(&primary_cfm_eph);  // (no-op at user level)
            return (0);
        }
        cmd->u.cache_cfm_reg.ccr_partition_map = ctx->cx_partition_map;
        cmd->u.cache_cfm_reg.cs_if_tbl = ctx->cx_cs_params.csp_cs_if_tbl;
        rna_service_mutex_unlock(&ctx->cx_md_mutex);
    } else {
        /* The user is a client. */
        memset(cmd, 0, sizeof(cmd_hdr_t) + sizeof(struct client_cfm_reg));
        cmd->h.h_type = CONF_MGR_REG_CLIENT;
        if (RNA_SERVICE_USER_TYPE_BLOCK_CLIENT == ctx->cx_params.rsp_user_type)
        {
            cmd->u.client_cfm_reg.client_type = CLIENT_TYPE_BLOCK;
        }
        strcpy(cmd->u.client_cfm_reg.hostname, ctx->cx_params.rsp_node_name);
        com_get_ep_src_in(&primary_cfm_eph, &cmd->u.client_cfm_reg.client_addr);
        cmd->u.client_cfm_reg.byte_order = CPU_BE;
#ifdef LINUX_KERNEL
        cmd->u.client_cfm_reg.stat_buf.device_id.data = 0;
        cmd->u.client_cfm_reg.stat_buf.base_addr =
                                (uint64_t)cfm_info->ci_stat_info.rdma_mem_dma;
#endif
        cmd->u.client_cfm_reg.stat_length = ctx->cx_params.rsp_stat_length;
        cmd->u.client_cfm_reg.stat_rkey = stat_rkey;

        if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
            /* This failure means we're in the process of shutting down */
            return (-1);
        }
        if (ctx->cx_cfm_flags & CTX_CFM_FLAG_INITIAL_REGISTRATION_SENT) {
            /* initial registration was sent, this is a re-registration */
            cmd->u.client_cfm_reg.lcr_flags |=
                                    CLIENT_CFM_REG_FLAG_REREGISTRATION;
        } else {
            /* initial registration wasn't previously sent; it has been now */
            ctx->cx_cfm_flags |= CTX_CFM_FLAG_INITIAL_REGISTRATION_SENT;
        }
        /* Tell the CFM if this client has already had block devices created */
        if (ctx->cx_cfm_flags & CTX_CFM_FLAG_BLOCK_DEVICES_CREATED) {
            cmd->u.client_cfm_reg.lcr_flags |=
                                    CLIENT_CFM_REG_FLAG_BLOCK_DEVICES_CREATED;
        }
        rna_service_mutex_unlock(&ctx->cx_cfm_mutex);

        /*
         * Give the CFM the current partition map.  This is useful if the CFM
         * is newly started and this client has been running for a while.
         * (We need to hold the cx_md_mutex to assure we get a consistent copy
         * of the partition_map).
         */
        if (!rna_service_mutex_lock(&ctx->cx_md_mutex)) {
            // This failure means we're in the process of shutting down;
            // do nothing
            com_release_eph(&primary_cfm_eph);  // (no-op at user level)
            return (0);
        }
        cmd->u.client_cfm_reg.lcr_partition_map = ctx->cx_partition_map;
        rna_service_mutex_unlock(&ctx->cx_md_mutex);
    }

    //TODO: group support

    ret = rna_service_com_send_cfm_cmd(&primary_cfm_eph,
                                       send_buf,
                                       cfm_cmd_length(cmd),
                                       &ctx->cx_primary_cfm_id);
    com_release_eph(&primary_cfm_eph);  // (no-op at user level)
    return (ret);
}

/*
 * Timer callback to call to retry cs registration with cfm
 * when stat buf info is not available
 */

static void
register_with_cfm_tc(uint64_t context)
{
    com_ep_handle_t               primary_cfm_eph;
    rna_service_ctx_t *ctx = (rna_service_ctx_t *)context;

    rna_service_assert(NULL != ctx);
    rna_service_timer_cancel(&ctx->cx_cs_cfm_registration_timer);

    /*
     * re-queue cfm registration work if needed
     */
    if (register_with_cfm(ctx) == RETRY_PCFM_REGISTRATION) {
        primary_cfm_eph = ctx->cx_primary_cfm_eph;
        rna_dbg_log(RNA_DBG_WARN, 
                    "Requeing registration with Primary CFM ["RNA_ADDR_FORMAT"]\n",
                    RNA_ADDR(primary_cfm_eph.eph_dst_in.sin_addr));

        rna_service_timer_set(ctx->cx_private,
                              &ctx->cx_cs_cfm_registration_timer,
                              register_with_cfm_tc,
                              (uint64_t)ctx,
                              RNA_SERVICE_CS_CFM_REGISTRATION_TIMEOUT);
    }
}


/**
 * Invoked by a workq thread to send queued messages to the configuration
 * manager.  The messages were queued either because a connection to the
 * primary CFM hadn't yet been established, or because a send attempt failed
 * (either because a sendbuf allocation failed or because the send itself
 * failed).
 */
static rna_service_workq_cb_ret_t
send_waiting_cfm_msgs(rna_service_workq_cb_arg_t workq_context)
{
    send_waiting_msgs_work_ctx_t *wctx =
                                 (send_waiting_msgs_work_ctx_t *)workq_context;
    rna_service_ctx_t            *ctx;
    com_ep_handle_t               primary_cfm_eph;
    size_t                        ret;
    rna_service_message_buffer_t *buf;
    rna_service_message_buffer_internal_t *ibuf;

    rna_service_assert(NULL != wctx);
    rna_service_assert(NULL != wctx->swx_ctx);

    ctx = wctx->swx_ctx;
    com_init_eph(&primary_cfm_eph);

    if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
        /* This failure means we're in the process of shutting down */
        goto done_nolock;
    }

    do {
        rna_service_assert_locked(&ctx->cx_cfm_mutex);

        if (!com_eph_isempty(&primary_cfm_eph)) {
            /* release reference acquired in prior loop iteration */
            com_release_eph(&primary_cfm_eph);  // (no-op at user level)
            com_init_eph(&primary_cfm_eph);
        }

        if (!rna_service_com_connected(&ctx->cx_primary_cfm_eph)) {
            break;
        }

        primary_cfm_eph = ctx->cx_primary_cfm_eph;
        com_inc_ref_eph(&primary_cfm_eph);  // (no-op at user level)

        /*
         * If we haven't yet registered with the CFM, try now.
         */
        if (ctx->cx_cfm_flags & CTX_CFM_FLAG_MUST_REGISTER) {
            /* don't hold cx_cfm_mutex across blocking operation */
            rna_service_mutex_unlock(&ctx->cx_cfm_mutex);

            ret = register_with_cfm(ctx);

            if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
                /* This failure means we're in the process of shutting down */
                goto done_nolock;
            }
            if (-2 == ret) {
                /* Internal error occurred that makes registration impossible */
                break;
            }

            /* Restart the loop if the primary CFM changed */
            if (!com_eph_equal(&ctx->cx_primary_cfm_eph, &primary_cfm_eph)) {
                continue;
            }

            if (0 == ret) {
                ctx->cx_cfm_flags &= ~CTX_CFM_FLAG_MUST_REGISTER;
                /*
                 * A CS must wait for a positive registration response before
                 * sending any other messages, with the goal of avoiding
                 * sending stale messages if it's been expelled.
                 */
                if (RNA_SERVICE_USER_TYPE_CACHE_SERVER ==
                                    ctx->cx_params.rsp_user_type) {
                    ctx->cx_cfm_flags |=
                                    CTX_CFM_FLAG_AWAIT_REGISTRATION_RESPONSE;
                }
            } else {
                /*
                 * Registration failed.  We can't do any of the other
                 * operations without first registering.  Retry.
                 */
                continue;
            }

            /*
             * If the user is a cache server and it's waiting for a positive
             * registration response from the CFM, don't send any other
             * messages until it arrives.  We want to avoid sending stale
             * messages if this CS has been expelled (i.e. if the registration
             * is rejected).
             */
            if ((RNA_SERVICE_USER_TYPE_CACHE_SERVER ==
                                ctx->cx_params.rsp_user_type)
              && (ctx->cx_cfm_flags &
                                CTX_CFM_FLAG_AWAIT_REGISTRATION_RESPONSE)) {
                break;
            }
        }

        /*
         * If the user is a cache server and it failed to register some of its
         * MD connections with the CFM  send the registration messages now.  
         */
        if (RNA_SERVICE_USER_TYPE_CACHE_SERVER == ctx->cx_params.rsp_user_type)
        {
            /* Restart the loop if the primary CFM changed */
            if (!com_eph_equal(&ctx->cx_primary_cfm_eph, &primary_cfm_eph)) {
                continue;
            }

            /*
             * (note that it's OK to check the
             * CTX_MD_FLAG_MUST_SEND_MD_CONNECTION_INFO flag while holding the
             * cx_cfm_mutex only, since both the cx_md_mutex and the
             * cx_cfm mutex are held when it's set).
             */
            if (ctx->cx_md_flags & CTX_MD_FLAG_MUST_SEND_MD_CONNECTION_INFO) {
                /*
                 * We'll need the cx_md_mutex for the following.  We need to
                 * acquire it before the cx_cfm_mutex to prevent deadlock.
                 */
                rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
                if (!rna_service_mutex_lock(&ctx->cx_md_mutex)) {
                    /* We're in the process of shutting down. */
                    goto done_nolock;
                }
                if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
                    /* We're in the process of shutting down. */
                    rna_service_mutex_unlock(&ctx->cx_md_mutex);
                    goto done_nolock;
                }

                /* Restart the loop if the primary CFM changed */
                if (!com_eph_equal(&ctx->cx_primary_cfm_eph,
                                   &primary_cfm_eph)) {
                    rna_service_mutex_unlock(&ctx->cx_md_mutex);
                    continue;
                }

                /* Check again, now that locks are held */
                if (ctx->cx_md_flags &
                                    CTX_MD_FLAG_MUST_SEND_MD_CONNECTION_INFO) {
                    md_info_t **md_table_first = ctx->cx_md_table_first;
                    md_info_t **md_table_last = ctx->cx_md_table_last;
                    md_info_t **mdipp;

                    ctx->cx_md_flags &=
                        ~CTX_MD_FLAG_MUST_SEND_MD_CONNECTION_INFO; // optimism
                    if (md_table_first != NULL) {
                        for (mdipp = md_table_first;
                             mdipp <= md_table_last;
                             mdipp++) {

                            if ((NULL != *mdipp)
                              && ((*mdipp)->mdi_iflags &
                                MD_INFO_IFLAG_MUST_SEND_MD_CONNECTION_INFO)) {

                                ret = 0;
                                if (rna_service_com_connected(
                                                    &(*mdipp)->mdi_eph)) {
                                    /*
                                     * We have a connection to the MD, tell the
                                     * CFM
                                     */
                                    ret =
                                       rna_service_send_service_connection_info(
                                                    &primary_cfm_eph,
                                                    &(*mdipp)->mdi_service_id,
                                                    &(*mdipp)->mdi_eph,
                                                    (*mdipp)->mdi_ordinal);
                                } else if ((*mdipp)->mdi_cflags &
                                              MD_INFO_CFLAG_CONNECTION_FAILED) {
                                    /*
                                     * We've had a connection failure with the
                                     * MD, tell the CFM.
                                     */
                                    ret =
                                    rna_service_send_service_disconnection_info(
                                                    &primary_cfm_eph,
                                                    &(*mdipp)->mdi_service_id,
                                                    (*mdipp)->mdi_ordinal,
                                                    0);
                                }
                                if (0 == ret) {
                                    (*mdipp)->mdi_iflags &=
                                    ~MD_INFO_IFLAG_MUST_SEND_MD_CONNECTION_INFO;
                                } else {
                                    /* re-set the global flag and retry */
                                    ctx->cx_md_flags |=
                                      CTX_MD_FLAG_MUST_SEND_MD_CONNECTION_INFO;
                                    rna_service_mutex_unlock(&ctx->cx_md_mutex);
                                    break;
                                }
                            }
                        }
                    }
                }
                rna_service_mutex_unlock(&ctx->cx_md_mutex);
                /*
                 * Restart at the top of the loop if we failed to send any
                 * MD connection info.
                 */
                if (ctx->cx_md_flags &
                                    CTX_MD_FLAG_MUST_SEND_MD_CONNECTION_INFO) {
                    continue;   // restart loop at the top
                }
            }

            /*
             * If this cache server failed to send a MOUNT_BLOCKED or
             * MOUNT_UNBLOCKED message, send it now.
             */
            if (ctx->cx_deferred_mount_action != 0) {
                /* Don't hold the cx_cfm_mutex across blocking operations */
                rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
                ret = agent_announce_mount_action(
                                                &primary_cfm_eph,
                                                ctx->cx_deferred_mount_action);
                if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
                    /* We're in the process of shutting down. */
                    goto done_nolock;
                }
                /* Restart the loop if the primary CFM changed */
                if (!com_eph_equal(&ctx->cx_primary_cfm_eph,
                                   &primary_cfm_eph)) {
                    continue;
                }
                if (0 == ret) {
                    ctx->cx_deferred_mount_action = 0;
                }
            }
        }

        /*
         * Registration messages:  Try to re-send registration messages that
         * failed previously.
         */
        while (!YAQ_EMPTY(&ctx->cx_cfm_registrations_waiting_to_send)) {
            ibuf = YAQ_OBJECT(rna_service_message_buffer_internal_t,
                              h.rmbi_link,
                              YAQ_FIRST(
                                  &ctx->cx_cfm_registrations_waiting_to_send));
            YAQ_REMOVE(&ibuf->h.rmbi_link);

            /* Don't hold the cx_cfm_mutex across blocking operations */
            rna_service_mutex_unlock(&ctx->cx_cfm_mutex);

            switch (ibuf->u.rmbi_message_buffer.h.rmb_message_type) {
            case RNA_SERVICE_MESSAGE_TYPE_REG_MNT:
            case RNA_SERVICE_MESSAGE_TYPE_REG_BLKDEV:
            case RNA_SERVICE_MESSAGE_TYPE_REG_SVC_CONN:
            case RNA_SERVICE_MESSAGE_TYPE_REG_PATH:
            case RNA_SERVICE_MESSAGE_TYPE_REG_CACHE_DEVICE:
                register_mount_or_blkdev_with_cfm(ctx,
                                                 &ibuf->u.rmbi_message_buffer,
                                                  TRUE);
                break;

            case RNA_SERVICE_MESSAGE_TYPE_DEREG_MNT:
            case RNA_SERVICE_MESSAGE_TYPE_DEREG_BLKDEV:
            case RNA_SERVICE_MESSAGE_TYPE_DEREG_SVC_CONN:
            case RNA_SERVICE_MESSAGE_TYPE_DEREG_PATH:
            case RNA_SERVICE_MESSAGE_TYPE_DEREG_CACHE_DEVICE:
            case RNA_SERVICE_MESSAGE_TYPE_DEREG_REPLICA_STORE:
                deregister_mount_or_blkdev_with_cfm(ctx,
                                                   &ibuf->u.rmbi_message_buffer,
                                                    TRUE);
                break;

            default:
                rna_dbg_log(RNA_DBG_ERR,
                            "Illegal message type queued: %d, dropping\n",
                            ibuf->u.rmbi_message_buffer.h.rmb_message_type);
                rna_service_free_message_buffer(ctx,
                                               &ibuf->u.rmbi_message_buffer);
                ret = 0;
                break;
            }

            if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
                /* This failure means we're in the process of shutting down. */
                goto done_nolock;
            }

            if (!com_eph_equal(&ctx->cx_primary_cfm_eph, &primary_cfm_eph)) {
                break;
            }
        }

        /* Restart the loop if the primary CFM changed */
        if (!com_eph_equal(&ctx->cx_primary_cfm_eph, &primary_cfm_eph)) {
            continue;
        }

        /*
         * If there are no more registration messages queued to be sent to the
         * CFM, and all initial cache device registrations have been sent but
         * an 'end of registrations' message has not yet been sent, and the
         * send of an 'end of registrations' message has not yet been
         * scheduled, schedule it now.
         */
        if ((YAQ_EMPTY(&ctx->cx_cfm_registrations_waiting_to_send))
          && ((ctx->cx_cfm_flags &
                           (CTX_CFM_FLAG_INITIAL_REGISTRATIONS_COMPLETE |
                            CTX_CFM_FLAG_MUST_SEND_CACHEDEV_REGISTRATION_END))
                        == (CTX_CFM_FLAG_INITIAL_REGISTRATIONS_COMPLETE |
                            CTX_CFM_FLAG_MUST_SEND_CACHEDEV_REGISTRATION_END)))
        {
            /* Don't hold the cx_cfm_mutex across blocking operations */
            rna_service_mutex_unlock(&ctx->cx_cfm_mutex);

            /* Send an 'end of cache device registrations' message. */
            buf = rna_service_alloc_message_buffer(
                                ctx,
                                RNA_SERVICE_MESSAGE_TYPE_REG_CACHE_DEVICE_END,
                                NULL);
            if (NULL == buf) {
                rna_dbg_log(RNA_DBG_WARN,
                            "failed to get send buffer for "
                            "RNA_SERVICE_MESSAGE_TYPE_REG_CACHE_DEVICE_END "
                            "message\n");
            } else {
                ibuf = mbuf_to_ibuf(buf);
                /* Send the RNA_SERVICE_MESSAGE_TYPE_REG_CACHE_DEVICE_END */
                register_mount_or_blkdev_with_cfm(ctx,
                                                 &ibuf->u.rmbi_message_buffer,
                                                  TRUE);
            }

            if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
                /* This failure means we're in the process of shutting down. */
                goto done_nolock;
            }
        }

        /* Restart the loop if the primary CFM changed */
        if (!com_eph_equal(&ctx->cx_primary_cfm_eph, &primary_cfm_eph)) {
            continue;
        }

        /*
         * Non-registration messages:  Try to re-send non-registration
         * messages that failed previously.
         */
        while (!YAQ_EMPTY(&ctx->cx_cfm_msgs_waiting_to_send)) {
            ibuf = YAQ_OBJECT(rna_service_message_buffer_internal_t,
                              h.rmbi_link,
                              YAQ_FIRST(&ctx->cx_cfm_msgs_waiting_to_send));
            YAQ_REMOVE(&ibuf->h.rmbi_link);

            /* Don't hold the cx_cfm_mutex across blocking operations */
            rna_service_mutex_unlock(&ctx->cx_cfm_mutex);

            send_cfm_non_reg_dereg(ctx, &ibuf->u.rmbi_message_buffer, TRUE);

            if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
                /* This failure means we're in the process of shutting down. */
                goto done_nolock;
            }

            if (!com_eph_equal(&ctx->cx_primary_cfm_eph, &primary_cfm_eph)) {
                break;
            }
        }
    } while (!com_eph_equal(&ctx->cx_primary_cfm_eph, &primary_cfm_eph));

    ctx->cx_cfm_flags &= ~CTX_CFM_FLAG_RESEND_SCHEDULED;
    rna_service_mutex_unlock(&ctx->cx_cfm_mutex);

 done_nolock:
    if (!com_eph_isempty(&primary_cfm_eph)) {
        com_release_eph(&primary_cfm_eph);  // (no-op at user level)
    }

    /*
     * Release the ctx reference that was added when this workq item was queued
     */
    ctx_release_reference(&wctx->swx_ctx);

    /*
     * (Note that we don't free *wctx, since it's statically allocated as
     * ctx->cx_cfm_wctx).
     */

    /*
     * NOTE that rna_service workq callbacks must use
     * RNA_SERVICE_WORKQ_CB_RETURN instead of return.
     */
    RNA_SERVICE_WORKQ_CB_RETURN(0);
}


/* ------------------------- Metadata Servers --------------------------- */

#define NEW_MD_MSG_ID(ctx, partition)                           \
    ((((uint64_t)(partition)) << 32) | (ctx)->cx_md_next_msg_id++)

#define MD_MSG_ID_TO_PARTITION(msg_id)                          \
    ((msg_id) >> 32)


/**
 * Find the entry for the MD having the specified endpoint in the specified
 * rna_service context's MD table.
 *
 * Locking:
 *    The ctx->cx_md_mutex must be held on entry.
 */
static md_info_t *
find_md_by_eph(rna_service_ctx_t *ctx, com_ep_handle_t *eph)
{
    md_info_t **md_table_first = ctx->cx_md_table_first;
    md_info_t **md_table_last = ctx->cx_md_table_last;
    md_info_t **mdipp;

    rna_service_assert_locked(&ctx->cx_md_mutex);

    if (md_table_first != NULL) {
        for (mdipp = md_table_first; mdipp <= md_table_last; mdipp++) {
            if ((NULL != *mdipp)
               && (com_eph_equal(&((*mdipp)->mdi_eph), eph))) {
                rna_service_assert((*mdipp)->mdi_ordinal < NUM_MD_ORDINALS);
                rna_service_assert(
                            ctx->cx_md_table[(*mdipp)->mdi_ordinal] == *mdipp);
                return (*mdipp);
            }
        }
    }
    return NULL;
}

int
rna_service_dump_md_eph_xml(rna_service_ctx_t *ctx, void *info_file)
{
    md_info_t **md_table_first = NULL;
    md_info_t **md_table_last = NULL;
    md_info_t **mdipp = NULL;

    if ((NULL == ctx)
      || (ctx->cx_watermark != RNA_SERVICE_CTX_WATERMARK)
      || (!ctx_add_reference(&ctx))) {
        return 0;
    }

    rna_service_mutex_lock(&ctx->cx_md_mutex);
    md_table_first = ctx->cx_md_table_first;
    md_table_last = ctx->cx_md_table_last;
    for (mdipp = md_table_first; mdipp <= md_table_last; mdipp++) {
        if ((mdipp) &&
            (*mdipp) &&
            (*mdipp)->mdi_cflags & MD_INFO_CFLAG_CONNECTED) {
            rna_service_com_dump_md_ep_info_xml(&((*mdipp)->mdi_eph), 
                                                &((*mdipp)->mdi_service_id), 
                                                info_file);
        }
    }
    rna_service_mutex_unlock(&ctx->cx_md_mutex);
    ctx_release_reference(&ctx);
    return 0;
}


/*
 * Free an md_info_t.
 */
INLINE void
free_mdi(rna_service_ctx_t *ctx, md_info_t *mdi)
{
    rna_dbg_log(RNA_DBG_MSG,
                "Freeing mdi ent [%p] ordinal [%d]\n", mdi, mdi->mdi_ordinal);
    memset(mdi, 0, sizeof(*mdi)); // make use-after-free easier to spot
    mempool_free(ctx, MEMPOOL_ID_MD_INFO, (void *)mdi);
}


/**
 * Remove the entry at the specified ordinal from the MD table.
 *
 * Locking:
 *    The ctx->cx_md_mutex must be held on entry.
 */
static void
remove_md_table_entry(rna_service_ctx_t *ctx, int md_ordinal)
{
    md_info_t *mdi, **mdipp;

    rna_service_assert_locked(&ctx->cx_md_mutex);

    mdi = ctx->cx_md_table[md_ordinal];

    if (NULL != mdi) {
        rna_service_timer_final_cancel(
                            &ctx->cx_send_waiting_md_msgs_timers[md_ordinal]);
        ctx->cx_md_table[md_ordinal] = NULL;

        mdipp = &ctx->cx_md_table[md_ordinal];
        ctx->cx_num_mds--;

        rna_dbg_log(RNA_DBG_MSG,
                    "Removing MD ordinal [%d] ent [%p] from cx_md_table, "
                    "[%d] MDs remain\n",
                    md_ordinal,  mdi, ctx->cx_num_mds);


        /* Recalculate cx_md_table_first and cx_md_table_last, if necessary */
        if (0 == ctx->cx_num_mds) {
            ctx->cx_md_table_first = ctx->cx_md_table_last = NULL;
        } else if (mdipp == ctx->cx_md_table_first) {
            for (mdipp++; mdipp <= ctx->cx_md_table_last; mdipp++) {
                if (NULL != *mdipp) {
                    ctx->cx_md_table_first = mdipp;
                    break;
                }
            }
        } else if (mdipp == ctx->cx_md_table_last) {
            for (mdipp--; mdipp >= ctx->cx_md_table_first; mdipp--) {
                if (NULL != *mdipp) {
                    ctx->cx_md_table_last = mdipp;
                    break;
                }
            }
        }
        rna_service_assert((ctx->cx_num_mds == 0) ==
                           (ctx->cx_md_table_first == NULL));
        rna_service_assert((ctx->cx_num_mds == 0) ==
                           (ctx->cx_md_table_last == NULL));

        if ((com_eph_isempty(&mdi->mdi_eph))
          || (mdi->mdi_cflags & MD_INFO_CFLAG_FINAL_DISCONN)) {
            /*
             * Either no connect is in progress for this mdi (so the
             * disconnect callback won't be invoked) or disconnect callback
             * processing has finished, so this mdi is no longer needed.
             */
            free_mdi(ctx, mdi);
        } else {
            /*
             * We can't yet safely free this mdi, since other threads may be
             * referencing it.  Go ahead and instigate a disconnect if it's
             * connected.  The disconnect processing (or connect path, in the
             * case of CONNECTING) will take care of freeing the structure.
             */
            rna_dbg_log(RNA_DBG_INFO,
                        "Disconnecting from MD ["RNA_ADDR_FORMAT"]\n",
                        RNA_ADDR(mdi->mdi_eph.eph_dst_in.sin_addr));
            rna_service_com_disconnect(&mdi->mdi_eph);
            md_disconnected(ctx, mdi);
        }
    }

    return;
}


/**
 * Add a new entry to the MD table.
 *
 * Locking:
 *    The ctx->cx_md_mutex must be held on entry.
 */
static void
add_md_table_entry(rna_service_ctx_t *ctx, md_info_t *new_mdi)
{
    md_info_t **mdipp;

    rna_service_assert_locked(&ctx->cx_md_mutex);

    /*
     * Check if there's an earlier incarnation of this MD in the MD table
     * (i.e. an MD that died, causing this new one to be started), and if so,
     * remove it.  Specifically, search for an MD that has the same
     * rna_service_id as the new MD except for the start time.
     */
    if (ctx->cx_md_table_first != NULL) {
        for (mdipp = ctx->cx_md_table_first;
             mdipp <= ctx->cx_md_table_last;
             mdipp++) {
            if ((*mdipp != NULL)
              && (match_rna_service_id(&(*mdipp)->mdi_service_id,
                                       &new_mdi->mdi_service_id,
                                       FALSE /* disregard timestamp */))) {
                /*
                 * This entry has the same rna_service_id as the new MD except
                 * for its start time.  It's presumably an earlier (dead)
                 * incarnation of the MD.  Remove it, so we don't keep trying
                 * to re-connect to it.
                 */
                rna_dbg_log(RNA_DBG_MSG,
                            "removing earlier incarnation of MD "
                            "["RNA_ADDR_FORMAT"] ent [%p] at ordinal [%d]\n",
                            RNA_ADDR((*mdipp)->mdi_eph.eph_dst_in.sin_addr),
                            *mdipp,
                            (*mdipp)->mdi_ordinal);
                remove_md_table_entry(ctx, (*mdipp)->mdi_ordinal);
                break;
            }
        }
    }

    mdipp = &ctx->cx_md_table[new_mdi->mdi_ordinal];
    if (NULL != *mdipp) {
        /*
         * We already have an entry at this ordinal.  Free it so we can replace
         * it with a new entry for the new MD.
         */
        rna_dbg_log(RNA_DBG_MSG,
                    "removing pre-existing entry for MD ordinal [%d/%d] "
                    "ent [%p]\n",
                    new_mdi->mdi_ordinal, (*mdipp)->mdi_ordinal, *mdipp);
        remove_md_table_entry(ctx, new_mdi->mdi_ordinal);
    }

    *mdipp = new_mdi;
    ctx->cx_num_mds++;

    rna_dbg_log(RNA_DBG_MSG,
                "Added MD ordinal [%d] ent [%p] to cx_md_table, [%d] MDs\n",
                new_mdi->mdi_ordinal,  new_mdi, ctx->cx_num_mds);

    /* Recalculate cx_md_table_first and cx_md_table_last */
    if (mdipp > ctx->cx_md_table_last) {
        ctx->cx_md_table_last = mdipp;
    }
    if (NULL == ctx->cx_md_table_first || mdipp < ctx->cx_md_table_first) {
        ctx->cx_md_table_first = mdipp;
    }
}


/*
 * Verify that the specified md_info_t is still in existence.  This is a useful
 * check after dropping and reacquiring the cx_md_mutex.
 */
INLINE boolean
verify_mdi(rna_service_ctx_t *ctx,
           uint64_t           gen,
           md_info_t         *mdi,
           int                ordinal,
           com_ep_handle_t   *md_eph)
{
    if ((ctx->cx_partition_map.pm_generation != gen)
      || (ctx->cx_md_table[ordinal] != mdi)
      || (!com_eph_equal(&mdi->mdi_eph, md_eph))
      || (!rna_service_com_connected(md_eph))) {
        return (FALSE);
    } else {
        return (TRUE);
    }
}


/**
 * An rna_service_timer function that's invoked to schedule
 * send_waiting_md_msgs on a workq.
 */
static void
delayed_send_waiting_md_msgs(uint64_t context)
{
    send_waiting_msgs_work_ctx_t *wctx =
                                 (send_waiting_msgs_work_ctx_t *)context;

    rna_service_assert(wctx != NULL);
    rna_service_assert(wctx->swx_ctx != NULL);

    /*
     * (All returns from rna_service_workq_add are considered
     * successful from the perspective of this routine).
     */
    (void) rna_service_workq_add(wctx->swx_ctx->cx_md_work_queue,
                                 &wctx->swx_work_obj);
}


/*
 * Schedule send_waiting_md_msgs() to send MD messages that couldn't be
 * sent immediately because no sendbufs were available, or because we'd lost
 * contact with the MD the partition is assigned to.
 *
 * Locking:
 *    The ctx->cx_md_mutex must be held on entry.
 */
static void
schedule_waiting_md_msgs(rna_service_ctx_t *ctx, md_info_t *mdi, int delay_sec)
{
    send_waiting_msgs_work_ctx_t *wctx;

    rna_service_assert(NULL != ctx);
    rna_service_assert(NULL != mdi);
    rna_service_assert_locked(&ctx->cx_md_mutex);

    /*
     * If send_waiting_md_msgs() hasn't already been scheduled for this MD,
     * schedule it now.
     */
    if (!(mdi->mdi_iflags & MD_INFO_IFLAG_SEND_WAITING_MSGS_SCHEDULED)) {
        mdi->mdi_iflags |= MD_INFO_IFLAG_SEND_WAITING_MSGS_SCHEDULED;
        wctx = rna_service_alloc0(sizeof(*wctx));
        if (NULL == wctx) {
            rna_dbg_log(RNA_DBG_WARN,
                        "unable to allocate memory, so unable to send "
                        "waiting MD messages\n");
            return;
        }

        wctx->swx_ctx = ctx;
        wctx->swx_ordinal = mdi->mdi_ordinal;
        rna_service_assert(wctx->swx_ordinal < NUM_MD_ORDINALS);

        RNA_SERVICE_WORK_INIT(&wctx->swx_work_obj,
                              send_waiting_md_msgs,
                              (rna_service_workq_cb_arg_t)wctx);

        /*
         * Since *wctx includes a reference to an rna_service_ctx_t, a ctx
         * reference must be taken.  This reference must be released by
         * send_waiting_md_msgs().
         */
        if (ctx_add_reference(&ctx)) {
            if (0 == delay_sec) {
                /*
                 * Schedule send_waiting_md_msgs to run immediately.
                 * (All returns from rna_service_workq_add are considered
                 * successful from the perspective of this routine).
                 */
                (void) rna_service_workq_add(ctx->cx_md_work_queue,
                                             &wctx->swx_work_obj);
            } else {
                /*
                 * Schedule send_waiting_md_msgs to run after the specified
                 * delay.
                 */
                rna_service_timer_set(
                                  ctx->cx_private,
                                 &ctx->cx_send_waiting_md_msgs_timers[
                                                            mdi->mdi_ordinal],
                                  delayed_send_waiting_md_msgs,
                                  (uint64_t)wctx,
                                  delay_sec);
            }
        } else {
            /* The ctx is shutting down */
            rna_service_free(sizeof(*wctx), wctx);
        }
    }
}

/**
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
 * these quotas, the submission is failed, with the error
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
 * a petition, then this function will fail with error code
 * RNA_SERVICE_ERROR_MAX_OUTSTANDING_EXCEEDED.  In which case, the caller
 * should release msg_buf, and retry its operation again later.
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
 *                            on the number of outstanding plus preallocated
 *                            messages to be exceeded
 */
rna_service_error_t
acquire_msgbuf_quota(rna_service_ctx_t *ctx,
                     rna_service_message_buffer_t *buf)
{
    rna_service_error_t                     err = RNA_SERVICE_ERROR_NONE;
    rna_service_message_buffer_internal_t   *ibuf;
    int                                     partition = 0;
    char                                    *pathname;
    rna_service_cache_query_request_t       *cache_query_request;
    rna_hash_key_t                          hash_key;

    ibuf = mbuf_to_ibuf(buf);
    memset((void *) &hash_key, 0, sizeof(hash_key));

    if ((NULL == ctx)
      || (ctx->cx_watermark != RNA_SERVICE_CTX_WATERMARK)
      || (!ctx_add_reference(&ctx))) {
        rna_dbg_log(RNA_DBG_WARN,
                    "called with NULL or corrupt rna_service_ctx [%p]\n",
                    ctx);
        return (RNA_SERVICE_ERROR_INVALID_CTX);
    }

    if (!rna_service_mutex_lock(&ctx->cx_md_mutex)) {
        /* This failure means we're in the process of shutting down */
        rna_dbg_log(RNA_DBG_WARN,
                    "Server is shutting down\n");
        err = RNA_SERVICE_ERROR_INVALID_CTX;
        goto done;
    }

    /*
     * NOTE that if any new messages need to be added to this switch
     * statement, they must also be added to the similar switch statement
     * in process_partition_map().
     *
     * In the context of this function, we currently don't expect
     * most of these cases to be called. But keep the structure anyway,
     * may for future support.
     *
     * Maybe for trunk submission, this block of code could be pulled into
     * a function, that is called here, and from send_md_generic(), where
     * this code was cloned from.
     *
     * This section of code could probably be extracted into a separate
     * function, and called from several places, rather than duplicating
     * code.  But perhaps for another day.
     */
    switch (buf->h.rmb_message_type) {
        case RNA_SERVICE_MESSAGE_TYPE_MD_QUERY:
        {
            rna_service_metadata_query_t *user_msg = &buf->u.rmb_metadata_query;
            pathname = buf->u.rmb_metadata_query.mqs_pathname;

            /*
             * (Note that we unfortunately can't use cx_hash_key_temp, because
             * the cx_md_mutex must be dropped and re-acquired in this routine)
             */
            rna_service_assert(user_msg->mqs_master_block_id != 0);
            rna_hash_compute_key_path(pathname, strlen(pathname), &hash_key);
            switch (user_msg->mqs_request_type) {
                case CACHE_REQ_TYPE_BLOCK:
                    rna_hash_convert_key_to_block_key(&hash_key,
                                                       user_msg->mqs_block_num);
                    break;

                case CACHE_REQ_TYPE_MASTER:
                    rna_hash_convert_key_to_master_key(&hash_key);
                    break;
                case CACHE_REQ_TYPE_FULL:
                    // NOOP
                    break;
            }
            /*
             * If we haven't received an initial partition map yet, don't call
             * rna_service_hashkey_to_partition(), because it will panic.
             * In that case, partition will be set to the PREMATURE_PARTITION
             * down below and the message will be queued for later.
             */
            if (0 != ctx->cx_partition_map.pm_generation) {
                partition = rna_service_hashkey_to_partition(
                                             &hash_key,
                                             ctx->cx_hash_partition_bitmask);
            }
            break;
        }

        case RNA_SERVICE_MESSAGE_TYPE_CACHE_INVD:
        case RNA_SERVICE_MESSAGE_TYPE_CACHE_MASTER_INVD:
        {
            rna_service_cache_invalidate_t *user_msg =
                                              &buf->u.rmb_cache_invalidate;
            pathname = buf->u.rmb_cache_invalidate.cis_pathname;

            /*
             * (Note that we unfortunately can't use cx_hash_key_temp, because
             * the cx_md_mutex must be dropped and re-acquired in this routine)
             */
            rna_hash_compute_key_path(pathname, strlen(pathname), &hash_key);
            switch (user_msg->cis_cache_type) {
                case CACHE_REQ_TYPE_BLOCK:
                    rna_hash_convert_key_to_block_key(&hash_key,
                                                       user_msg->cis_block_num);
                    break;

                case CACHE_REQ_TYPE_MASTER:
                    rna_hash_convert_key_to_master_key(&hash_key);
                    break;
                case CACHE_REQ_TYPE_FULL:
                    // NOOP
                    break;
            }
            /*
             * If we haven't received an initial partition map yet, don't call
             * rna_service_hashkey_to_partition(), because it will panic.
             * In that case, partition will be set to the PREMATURE_PARTITION
             * down below and the message will be queued for later.
             */
            if (0 != ctx->cx_partition_map.pm_generation) {
                partition = rna_service_hashkey_to_partition(
                                             &hash_key,
                                              ctx->cx_hash_partition_bitmask);
            }
            break;
        }

        case RNA_SERVICE_MESSAGE_TYPE_CACHE_RESPONSE:
            /* This is a cache-server-specific message */
            partition = ((rna_service_cs_md_message_buffer_t *)buf)->
                                        u.cmb_cache_response.cr_hash_partition;
            break;

        case RNA_SERVICE_MESSAGE_TYPE_CACHE_QUERY_REQUEST:
            /* This is a cache-server-specific message */
            cache_query_request =
                    &((rna_service_cs_md_message_buffer_t *)buf)->
                                                    u.cmb_cache_query_request;
            pathname = cache_query_request->cqr_pathname;
            /*
             * (Note that we unfortunately can't use cx_hash_key_temp, because
             * the cx_md_mutex must be dropped and re-acquired in this routine)
             */
            rna_hash_compute_key_path(pathname, strlen(pathname), &hash_key);

            switch (cache_query_request->cqr_cache_type) {
                case CACHE_REQ_TYPE_BLOCK:
                    rna_hash_convert_key_to_block_key(
                                        &hash_key,
                                        cache_query_request->cqr_block_number);
                    break;
                case CACHE_REQ_TYPE_MASTER:
                    rna_hash_convert_key_to_master_key(&hash_key);
                    break;
                case CACHE_REQ_TYPE_FULL:
                    // NOOP
                    break;
            }

            /*
             * If we haven't received an initial partition map yet, don't call
             * rna_service_hashkey_to_partition(), because it will panic.
             * In that case, partition will be set to the PREMATURE_PARTITION
             * down below and the message will be queued for later.
             */
            if (0 != ctx->cx_partition_map.pm_generation) {
                partition = rna_service_hashkey_to_partition(
                                             &hash_key,
                                              ctx->cx_hash_partition_bitmask);
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_RELOCATE_BLOCK:
            /* partition passed directly from cache hash entry */
            partition = buf->u.rmb_relocate_cache_block.rcb_hash_partition;
            break;

        case RNA_SERVICE_MESSAGE_TYPE_ABSORB_BLOCK:
            partition = RNA_SERVICE_METADATA_RID_TO_PARTITION(
                                  buf->u.rmb_cache_absorb_block.cab_md_rid);
            break;

        case RNA_SERVICE_MESSAGE_TYPE_INVD_HOLD_RESPONSE:
            partition = buf->u.rmb_invd_hold_response.ihr_hash_partition;
            break;

        default:
            rna_dbg_log(RNA_DBG_ERR,
                        "illegal message type %d\n",
                        buf->h.rmb_message_type);
            err = RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE;
            rna_service_free_message_buffer(ctx, buf);
            goto done_unlock;
    }

    /*
     * If the first partition map hasn't yet arrived, we won't be able to
     * determine which hash partition it belongs to, since we won't know how
     * many partitions there are.
     */
    if (0 == ctx->cx_partition_map.pm_generation) {
        partition  = PREMATURE_PARTITION;
    }

    /*
     * This is an estimate of the maximum reasonable number of
     * pre-allocated buffers in existence at a time.  There
     * should normally be only a FEW preallocated buffers.
     *
     * The normal flow is for a buffer to be pre-allocated, and
     * then very shortly afterwards, to be either submitted for
     * send, or freed.  So this number should be limited by the
     * number of threads doing concurrent operations.
     *
     * So if this number gets large, it indicates a flaw in the logic somewhere.
     */
    rna_debug_log_assert(ctx->cx_partitions[partition].pi_msgs_preallocated_cnt
                                             < 10);

    /*
     * Check if sending this message would cause the limit on the maximum
     * number of outstanding messages to be exceeded.
     */
    if (((partition != PREMATURE_PARTITION) &&
         ((ctx->cx_partitions[partition].pi_msgs_outstanding_cnt +
             ctx->cx_partitions[partition].pi_msgs_preallocated_cnt) >=
                            RNA_SERVICE_MSGS_OUTSTANDING_MAX)) ||
        ((ctx->cx_partitions[partition].pi_msgs_outstanding_cnt +
             ctx->cx_partitions[partition].pi_msgs_preallocated_cnt) >=
                            RNA_SERVICE_PREMATURE_MSGS_OUTSTANDING_MAX)) {

        rna_dbg_log(RNA_DBG_INFO,
                    "message buffer send slot preallocation failed\n");
        err = RNA_SERVICE_ERROR_MAX_OUTSTANDING_EXCEEDED;
        goto done_unlock;
    }

    /*
     * RMBI_FLAG_PRE_ALLOC flagged ibufs are guaranteed
     * that they won't trigger the RNA_SERVICE_ERROR_MAX_OUTSTANDING_EXCEEDED
     * error from send_md_generic().
     */
    ctx->cx_partitions[partition].pi_msgs_preallocated_cnt++;
    ibuf->h.rmbi_flags |= RMBI_FLAG_PRE_ALLOC;
    ibuf->h.rmbi_partition = partition;

 done_unlock:
        rna_service_mutex_unlock(&ctx->cx_md_mutex);

 done:
        ctx_release_reference(&ctx);
        return (err);
}


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
rna_service_error_t
release_msgbuf_quota(rna_service_ctx_t *ctx,
                     rna_service_message_buffer_t *buf)
{
    rna_service_error_t                     err = RNA_SERVICE_ERROR_NONE;
    rna_service_message_buffer_internal_t   *ibuf;
    int                                     partition = 0;

    ibuf = mbuf_to_ibuf(buf);

    /* if there is no quota assigned to this buffer, than just return. */
    if (0 == (ibuf->h.rmbi_flags & RMBI_FLAG_PRE_ALLOC)) {
        return (RNA_SERVICE_ERROR_NONE);
    }

    if ((NULL == ctx)
      || (ctx->cx_watermark != RNA_SERVICE_CTX_WATERMARK)
      || (!ctx_add_reference(&ctx))) {
        rna_dbg_log(RNA_DBG_WARN,
                    "called with NULL or corrupt rna_service_ctx [%p]\n",
                    ctx);
        return (RNA_SERVICE_ERROR_INVALID_CTX);
    }

    if (!rna_service_mutex_lock(&ctx->cx_md_mutex)) {
        /* This failure means we're in the process of shutting down */
        rna_dbg_log(RNA_DBG_WARN,
                    "Server is shutting down\n");
        err = RNA_SERVICE_ERROR_INVALID_CTX;
        goto done;
    }

    partition = ibuf->h.rmbi_partition;

    if (--ctx->cx_partitions[partition].pi_msgs_preallocated_cnt < 0) {
        rna_dbg_log(RNA_DBG_MSG,
                    "preallocation count underflow, partition [%d] "
                    "gen [%"PRIu64"]\n",
                    partition,
                    ctx->cx_partition_map.pm_generation);
        ctx->cx_partitions[partition].pi_msgs_preallocated_cnt = 0;
    }
    ibuf->h.rmbi_flags &= ~RMBI_FLAG_PRE_ALLOC;

    rna_service_mutex_unlock(&ctx->cx_md_mutex);

 done:
        ctx_release_reference(&ctx);
        return (err);
}

/*
 * Flags used for the 'flags' argument to send_md_generic().
 */
#define SEND_MD_GENERIC_FLAG_RESEND                 (1 << 0)
        /*
         * If set, this is a re-send of a message that was previously queued,
         * but has either had its partition assigned to a new MD or has had
         * its MD re-connect after a period of being disconnected.
         */
#define SEND_MD_GENERIC_FLAG_BLOCKING_OK            (1 << 1)
        /*
         * If set, this routine should do a blocking request for a sendbuf.
         * Otherwise, it should do a non-blocking request.
         */
#define SEND_MD_GENERIC_FLAG_FORCE                  (1 << 2)
        /*
         * Don't generate a fail return even if accepting the message results
         * in the maximum number of messages allowed to be outstanding to be
         * exceeded.
         */


/**
 * Send a metadata query (METADATA_QUERY), cache invalidate (CACHE_INVD),
 * cache master invalidate (CACHE_MASTER_INVD), cache response
 * (CACHE_RESPONSE), cache path registration (CACHE_REG_PATH),
 * relocate cache block (CACHE_RELOCATE_REQ)
 * message to the appropriate metadata server.
 *
 * Arguments:
 *    ctx  The caller's rna_service context, created by
 *         rna_service_ctx_create()
 *    ibuf A message buffer that specifies the message to be sent.
 *         NOTES:
 *         1. This message buffer must have been allocated by
 *            rna_service_alloc_message_buffer().
 *         2. This message buffer may not be modified, freed, or re-used
 *            until it is returned as the 'message_sent' argument of the
 *            response callback.
 *    flags
 *          See SEND_MD_GENERIC_FLAG_XX definitions above.
 *
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
static rna_service_error_t
send_md_generic(rna_service_ctx_t *ctx,
                rna_service_message_buffer_internal_t *ibuf,
                int flags)
{
    rna_service_error_t                 err = RNA_SERVICE_ERROR_NONE;
    rna_service_message_buffer_t       *buf = &ibuf->u.rmbi_message_buffer;
    rna_service_cs_md_message_buffer_t *cs_buf =
                                            &ibuf->u.rmbi_cs_md_message_buffer;
    size_t                              ret;
    com_ep_handle_t                     md_eph;
    int                                 ordinal;
    uint64_t                            gen;
    rna_service_send_buf_entry_t       *send_buf;
    struct cache_cmd                   *cmd;
    int                                partition = 0;
    md_info_t                          *mdi;
    char                               *pathname;
    time_t                              timeout;
    rna_service_cache_query_request_t  *cache_query_request;
    rna_hash_key_t                      hash_key;
                                            /* Note that we unfortunately can't
                                             * use cx_hash_key_temp, because
                                             * the cx_md_mutex must be dropped
                                             * and re-acquired in this routine.
                                             */
    memset((void *) &hash_key, 0, sizeof(hash_key));
    if ((NULL == ctx)
      || (ctx->cx_watermark != RNA_SERVICE_CTX_WATERMARK)
      || (!ctx_add_reference(&ctx))) {
        rna_dbg_log(RNA_DBG_WARN,
                    "called with NULL or corrupt rna_service_ctx [%p]\n",
                    ctx);
        /* "buf" is not freed here because its integrity cannot 
         * be guaranteed */
        return (RNA_SERVICE_ERROR_INVALID_CTX);
    }

    if (!rna_service_mutex_lock(&ctx->cx_md_mutex)) {
        /* This failure means we're in the process of shutting down */
        rna_service_free_message_buffer(ctx, buf);
        goto done;
    }

    /*
     * NOTE that if any new messages need to be added to this switch
     * statement, they must also be added to the similar switch statement
     * in process_partition_map().
     */
    switch (buf->h.rmb_message_type) {
        case RNA_SERVICE_MESSAGE_TYPE_MD_QUERY:
        {
            rna_service_metadata_query_t *user_msg = &buf->u.rmb_metadata_query;

            pathname = buf->u.rmb_metadata_query.mqs_pathname;
            timeout = ctx->cx_params.rsp_metadata_query_response_timeout;

            /*
             * (Note that we unfortunately can't use cx_hash_key_temp, because
             * the cx_md_mutex must be dropped and re-acquired in this routine)
             */
            rna_hash_compute_key_path(pathname, strlen(pathname), &hash_key);
            switch (user_msg->mqs_request_type) {
                case CACHE_REQ_TYPE_BLOCK:
                    rna_hash_convert_key_to_block_key(&hash_key,
                                                       user_msg->mqs_block_num);
                    break;

                case CACHE_REQ_TYPE_MASTER:
                    rna_hash_convert_key_to_master_key(&hash_key);
                    break;
                case CACHE_REQ_TYPE_FULL:
                    // NOOP
                    break;
            }
            /*
             * If we haven't received an initial partition map yet, don't call
             * rna_service_hashkey_to_partition(), because it will panic.
             * In that case, partition will be set to the PREMATURE_PARTITION
             * down below and the message will be queued for later.
             */
            if (0 != ctx->cx_partition_map.pm_generation) {
                partition = rna_service_hashkey_to_partition(
                                             &hash_key,
                                              ctx->cx_hash_partition_bitmask);
            }
            break;
        }

        case RNA_SERVICE_MESSAGE_TYPE_CACHE_INVD:
        case RNA_SERVICE_MESSAGE_TYPE_CACHE_MASTER_INVD:
        {
            rna_service_cache_invalidate_t *user_msg =
                                                &buf->u.rmb_cache_invalidate;

            pathname = buf->u.rmb_cache_invalidate.cis_pathname;
            timeout = ctx->cx_params.rsp_cache_invalidate_response_timeout;

            /*
             * (Note that we unfortunately can't use cx_hash_key_temp, because
             * the cx_md_mutex must be dropped and re-acquired in this routine)
             */
            rna_hash_compute_key_path(pathname, strlen(pathname), &hash_key);
            switch (user_msg->cis_cache_type) {
                case CACHE_REQ_TYPE_BLOCK:
                    rna_hash_convert_key_to_block_key(&hash_key,
                                                       user_msg->cis_block_num);
                    break;

                case CACHE_REQ_TYPE_MASTER:
                    rna_hash_convert_key_to_master_key(&hash_key);
                    break;
                case CACHE_REQ_TYPE_FULL:
                    // NOOP
                    break;
            }
            /*
             * If we haven't received an initial partition map yet, don't call
             * rna_service_hashkey_to_partition(), because it will panic.
             * In that case, partition will be set to the PREMATURE_PARTITION
             * down below and the message will be queued for later.
             */
            if (0 != ctx->cx_partition_map.pm_generation) {
                partition = rna_service_hashkey_to_partition(
                                             &hash_key,
                                              ctx->cx_hash_partition_bitmask);
            }
            break;
        }

        case RNA_SERVICE_MESSAGE_TYPE_CACHE_RESPONSE:
            /* This is a cache-server-specific message */
            pathname = ((rna_service_cs_md_message_buffer_t *)buf)->
                                        u.cmb_cache_response.cr_pathname;
            timeout = ctx->cx_cs_params.csp_cache_response_timeout;
            partition = ((rna_service_cs_md_message_buffer_t *)buf)->
                                        u.cmb_cache_response.cr_hash_partition;
            break;

        case RNA_SERVICE_MESSAGE_TYPE_CACHE_QUERY_REQUEST:
            /* This is a cache-server-specific message */
            cache_query_request =
                    &((rna_service_cs_md_message_buffer_t *)buf)->
                                                    u.cmb_cache_query_request;
            pathname = cache_query_request->cqr_pathname;
            timeout = ctx->cx_cs_params.csp_cache_response_timeout;

            /*
             * (Note that we unfortunately can't use cx_hash_key_temp, because
             * the cx_md_mutex must be dropped and re-acquired in this routine)
             */
            rna_hash_compute_key_path(pathname, strlen(pathname), &hash_key);

            switch (cache_query_request->cqr_cache_type) {
                case CACHE_REQ_TYPE_BLOCK:
                    rna_hash_convert_key_to_block_key(
                                        &hash_key,
                                        cache_query_request->cqr_block_number);
                    break;
                case CACHE_REQ_TYPE_MASTER:
                    rna_hash_convert_key_to_master_key(&hash_key);
                    break;
                case CACHE_REQ_TYPE_FULL:
                    // NOOP
                    break;
            }

            /*
             * If we haven't received an initial partition map yet, don't call
             * rna_service_hashkey_to_partition(), because it will panic.
             * In that case, partition will be set to the PREMATURE_PARTITION
             * down below and the message will be queued for later.
             */
            if (0 != ctx->cx_partition_map.pm_generation) {
                partition = rna_service_hashkey_to_partition(
                                             &hash_key,
                                              ctx->cx_hash_partition_bitmask);
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_RELOCATE_BLOCK:
            /* partition passed directly from cache hash entry */
            pathname = NULL;
            partition = buf->u.rmb_relocate_cache_block.rcb_hash_partition;
            timeout = 0;
            break;

        case RNA_SERVICE_MESSAGE_TYPE_ABSORB_BLOCK:
            pathname = NULL;
            partition = RNA_SERVICE_METADATA_RID_TO_PARTITION(
                                    buf->u.rmb_cache_absorb_block.cab_md_rid);
            timeout = 0;
            break;

        case RNA_SERVICE_MESSAGE_TYPE_INVD_HOLD_RESPONSE:
            pathname = NULL;
            partition = buf->u.rmb_invd_hold_response.ihr_hash_partition;
            timeout = 0;
            break;

        default:
            rna_dbg_log(RNA_DBG_ERR,
                        "illegal message type %d\n",
                        buf->h.rmb_message_type);
            err = RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE;
            rna_service_free_message_buffer(ctx, buf);
            goto done_unlock;
    }

    ibuf->h.rmbi_watermark = MESSAGE_BUFFER_INTERNAL_WATERMARK_QUEUED;

    /*
     * If the first partition map hasn't yet arrived, we won't be able to
     * determine which hash partition it belongs to, since we won't know how
     * many partitions there are.
     */
    if (0 == ctx->cx_partition_map.pm_generation) {
        /* Queue this message in a fake partition until a map arrives */
        partition = ibuf->h.rmbi_partition = PREMATURE_PARTITION;
        ibuf->h.rmbi_partition = partition;
        /* (Note that this message can't possibly be a resend). */
        YAQ_INSERT_TAIL(&ctx->cx_partitions[partition].pi_waiting_to_send,
                        &ibuf->h.rmbi_link);
        goto done_set_timeout;
    }

    ibuf->h.rmbi_partition = partition;

    /*
     * Check if sending this message would cause the limit on the maximum
     * number of outstanding messages to be exceeded.
     *
     * RMBI_FLAG_PRE_ALLOC flagged ibufs have already been guaranteed
     * that they will pass this quota check.
     */
    if (!(flags & (SEND_MD_GENERIC_FLAG_RESEND | SEND_MD_GENERIC_FLAG_FORCE)) &&
        !(ibuf->h.rmbi_flags & RMBI_FLAG_PRE_ALLOC) &&
        (((partition != PREMATURE_PARTITION) &&
          ((ctx->cx_partitions[partition].pi_msgs_outstanding_cnt +
             ctx->cx_partitions[partition].pi_msgs_preallocated_cnt) >=
                            RNA_SERVICE_MSGS_OUTSTANDING_MAX)) ||
         ((ctx->cx_partitions[partition].pi_msgs_outstanding_cnt +
             ctx->cx_partitions[partition].pi_msgs_preallocated_cnt) >=
                            RNA_SERVICE_PREMATURE_MSGS_OUTSTANDING_MAX))) {
        ctx->cx_md_flags |= CTX_MD_FLAG_MSGS_OUTSTANDING_OVERFLOWED;
        err = RNA_SERVICE_ERROR_MAX_OUTSTANDING_EXCEEDED;
        rna_service_free_message_buffer(ctx, buf);
        goto done_unlock;
    }

 smg_restart:
    mdi = ctx->cx_md_table[
                    ctx->cx_partition_map.pm_partition_assignments[partition]];

    /*
     * If the user is a cache server that hasn't yet registered with the MD
     * we shouldn't send this message yet.  Also, if a new partition map has
     * arrived since a message was last sent to this MD, it needs to be sent
     * before this message.  Finally, if this isn't a resend and messages are
     * queued for this partition waiting to be sent, this message should be
     * sent after those messages.
     */
    if ((NULL == mdi)
      || (mdi->mdi_cflags & MD_INFO_CFLAG_MUST_REGISTER)
      || (mdi->mdi_partition_map_generation_sent <
                                        ctx->cx_partition_map.pm_generation)
      || ((!(flags & SEND_MD_GENERIC_FLAG_RESEND))
        && (!YAQ_EMPTY(&ctx->cx_partitions[partition].pi_waiting_to_send)))) {

        if (flags & SEND_MD_GENERIC_FLAG_RESEND) {
            /*
             * Place this message back where it was in the queue, so the queue
             * isn't re-ordered.
             */
            YAQ_INSERT_HEAD(&ctx->cx_partitions[partition].pi_waiting_to_send,
                            &ibuf->h.rmbi_link);
        } else {
            /* This is a new message; place it at the end of the queue */
            YAQ_INSERT_TAIL(&ctx->cx_partitions[partition].pi_waiting_to_send,
                            &ibuf->h.rmbi_link);
        }
        if (NULL != mdi) {
            schedule_waiting_md_msgs(ctx, mdi, 0);
        }
        goto done_set_timeout;
    }

    /*
     * If we have a connection to the MD, we'll send the message immediately.
     * A NULL entry in the cx_md_table indicates that we haven't yet connected
     * with the target MD, and an unset MD_INFO_CFLAG_CONNECTED flag indicates
     * either that the connect is still in progress or we've lost the
     * connection.
     */
    if ((NULL != mdi)
      && (mdi->mdi_cflags & MD_INFO_CFLAG_CONNECTED)
      && (rna_service_com_connected(&mdi->mdi_eph))) {
        /*
         * We can send the message immediately, rather than queue it for later
         * send.
         *
         * Don't hold the cx_md_mutex across the call.
         */
        md_eph = mdi->mdi_eph;    // in case changes occur while lock not held
        ordinal = mdi->mdi_ordinal;
        rna_service_assert(ordinal < NUM_MD_ORDINALS);
        gen = ctx->cx_partition_map.pm_generation;

        com_inc_ref_eph(&md_eph);   // (no-op at user level)
        rna_service_mutex_unlock(&ctx->cx_md_mutex);

        ret = rna_service_com_get_send_buf(&md_eph,
                                           &send_buf,
                                           (flags &
                                              SEND_MD_GENERIC_FLAG_BLOCKING_OK),
                                           NULL);
        if (!rna_service_mutex_lock(&ctx->cx_md_mutex)) {
            /* This failure means we're in the process of shutting down */
            rna_service_free_message_buffer(ctx, buf);
            if (send_buf != NULL) {
                rna_service_com_put_send_buf(&md_eph, send_buf);
            }
            com_release_eph(&md_eph);   // (no-op at user level)
            goto done;
        }
        /*
         * Make sure nothing happened to the mdi or MD connection while we
         * didn't hold the mutex
         */
        if (!verify_mdi(ctx, gen, mdi, ordinal, &md_eph)) {
            if (send_buf != NULL) {
                rna_service_com_put_send_buf(&md_eph, send_buf);
            }
            com_release_eph(&md_eph);   // (no-op at user level)
            goto smg_restart;
        }
        com_release_eph(&md_eph);   // (no-op at user level)
        /*
         * Make sure the message didn't time out while we were waiting for a
         * send buffer.
         */
        if (ibuf->h.rmbi_flags & RMBI_FLAG_TIMED_OUT) {
            rna_service_mutex_unlock(&ctx->cx_md_mutex);
            md_response_timed_out((uint64_t)ibuf);
            goto done;
        }

        if ((NULL == send_buf) || (0 != ret)) {
            /* No available sendbufs; queue this message to be sent later */
            if (flags & SEND_MD_GENERIC_FLAG_RESEND) {
                /*
                 * Place this message back where it was in the queue, so the
                 * queue isn't re-ordered.
                 */
                YAQ_INSERT_HEAD(&ctx->cx_partitions[partition].
                                                        pi_waiting_to_send,
                                &ibuf->h.rmbi_link);
            } else {
                /* This is a new message; place it at the end of the queue */
                YAQ_INSERT_TAIL(&ctx->cx_partitions[partition].
                                                        pi_waiting_to_send,
                                &ibuf->h.rmbi_link);
            }
            if ((flags & SEND_MD_GENERIC_FLAG_BLOCKING_OK)
              && (rna_service_com_connected(&mdi->mdi_eph))) {
                /* This should never happen! */
                rna_dbg_log(RNA_DBG_ERR,
                            "Failed to get send buffer after blocking!\n");
            } else {
                rna_dbg_log(RNA_DBG_WARN,
                            "Failed to get send buffer!!\n");
                /* schedule send_waiting_md_msgs() to send this message */
                schedule_waiting_md_msgs(ctx,
                                         mdi,
                                         SEND_WAITING_MD_MSGS_DELAY_SEC);
            }
            goto done_set_timeout;
        }

#if defined(LINUX_KERNEL) || defined(WINDOWS_KERNEL)
        cmd = (struct cache_cmd *)(com_get_send_buf_mem(send_buf));
#else
        cmd = (struct cache_cmd *) send_buf->mem;
#endif

        if (RNA_SERVICE_MESSAGE_TYPE_MD_QUERY == buf->h.rmb_message_type) {
            rna_service_metadata_query_t *user_msg;
            user_msg = &buf->u.rmb_metadata_query;

            /* initialize the pathname and type for cache_cmd_length() */
            cmd->u.md_query.rnas.mqs_pathname[0] = 0;
            cmd->h.h_type = META_DATA_QUERY;
            memset(cmd, 0, cache_cmd_length(cmd));

            cmd->h.h_type = META_DATA_QUERY;
            cmd->h.h_cookie = user_msg->mqs_cookie;

            cmd->u.md_query.req_gen = ctx->cx_partition_map.pm_generation;
            cmd->u.md_query.path_key = hash_key;
            cmd->u.md_query.path_key_valid = 1;
            cmd->u.md_query.rnas = buf->u.rmb_metadata_query;
            /*
             * (NOTE that it's important not to use strncpy with a PATHNAME_LEN
             * limit here, since strncpy fills the remainder of the destination
             * buffer with nulls, but the destination buffer is variable-sized,
             * and has been allocated to be only as large as the string to be
             * copied in).
             */
            strcpy(cmd->u.md_query.rnas.mqs_pathname,
                   buf->u.rmb_metadata_query.mqs_pathname);
            /*
             * We use the req_msg_id field to help us find this message when
             * its response arrives.  The MD assumes nothing about the content
             * of this field, and simply returns its value in its response.
             * MD message IDs include the partition number.
             */
            cmd->u.md_query.req_msg_id = NEW_MD_MSG_ID(ctx, partition);
            ibuf->h.rmbi_req_msg_id = cmd->u.md_query.req_msg_id;
        } else if ((RNA_SERVICE_MESSAGE_TYPE_CACHE_INVD ==
                                                    buf->h.rmb_message_type)
          || (RNA_SERVICE_MESSAGE_TYPE_CACHE_MASTER_INVD ==
                                                    buf->h.rmb_message_type)) {
            memset(cmd, 0, empty_cache_cmd_length(CACHE_INVD));

            if (RNA_SERVICE_MESSAGE_TYPE_CACHE_INVD == buf->h.rmb_message_type)
            {
                cmd->h.h_type = CACHE_INVD;
            } else {
                cmd->h.h_type = CACHE_MASTER_INVD;
            }
            cmd->h.h_cookie = buf->u.rmb_cache_invalidate.cis_cache_rid;

            if (ibuf->h.rmbi_flags & RMBI_FLAG_SENT) {
                cmd->u.cache_invd.ci_flags = CACHE_INVD_FLAG_RESEND;
            }
            cmd->u.cache_invd.invd_gen = ctx->cx_partition_map.pm_generation;
            cmd->u.cache_invd.hash_key = hash_key;
            cmd->u.cache_invd.ack_required = TRUE;
                                    // (Note that rna_service requires an ack
                                    //  whether or not the user requires one)
            cmd->u.cache_invd.rnas = buf->u.rmb_cache_invalidate;
            /*
             * (NOTE that it's important not to use strncpy with a PATHNAME_LEN
             * limit here, since strncpy fills the remainder of the destination
             * buffer with nulls, but the destination buffer is variable-sized,
             * and has been allocated to be only as large as the string to be
             * copied in).
             */
            strcpy(cmd->u.cache_invd.rnas.cis_pathname,
                   buf->u.rmb_cache_invalidate.cis_pathname);
            /*
             * We use the req_msg_id field to help us find this message when
             * its response arrives.  The MD assumes nothing about the content
             * of this field, and simply returns its value in its response,
             * which can then be matched against the stored ibuf.
             */
            cmd->u.cache_invd.req_msg_id = NEW_MD_MSG_ID(ctx, partition);
            ibuf->h.rmbi_req_msg_id = cmd->u.cache_invd.req_msg_id;
        } else if (RNA_SERVICE_MESSAGE_TYPE_CACHE_RESPONSE ==
                                                cs_buf->h.rmb_message_type) {
            /*
             * This is a message sent by a cache server only.
             */
            memset(cmd, 0, empty_cache_cmd_length(CACHE_RESPONSE));

            cmd->h.h_type = CACHE_RESPONSE;
            cmd->h.h_cookie = cs_buf->u.cmb_cache_response.cr_cookie;

            if (ibuf->h.rmbi_flags & RMBI_FLAG_SENT) {
                cmd->u.cache_rep.cr_flags = CACHE_REP_FLAG_RESEND;
            }
            cmd->u.cache_rep.cr_gen = ctx->cx_partition_map.pm_generation;
            cmd->u.cache_rep.rnas = cs_buf->u.cmb_cache_response;
            /*
             * (NOTE that it's important not to use strncpy with a PATHNAME_LEN
             * limit here, since strncpy fills the remainder of the destination
             * buffer with nulls, but the destination buffer is variable-sized,
             * and has been allocated to be only as large as the string to be
             * copied in).
             */
            strcpy(cmd->u.cache_rep.rnas.cr_pathname,
                   cs_buf->u.cmb_cache_response.cr_pathname);
            /*
             * We use the req_msg_id field to help us find this message when
             * its response arrives.  The MD assumes nothing about the content
             * of this field, and simply returns its value in its response,
             * which can then be matched against the stored ibuf.
             */
            cmd->u.cache_rep.cr_msg_id = NEW_MD_MSG_ID(ctx, partition);
            ibuf->h.rmbi_req_msg_id = cmd->u.cache_rep.cr_msg_id;
        } else if ((RNA_SERVICE_MESSAGE_TYPE_CACHE_QUERY_REQUEST ==
                                                buf->h.rmb_message_type)) {
            /*
             * This is a message sent by a cache server only.
             */
            memset(cmd, 0, empty_cache_cmd_length(CACHE_QUERY_REQ));

            cmd->h.h_type = CACHE_QUERY_REQ;
            cmd->u.cache_query_req.cqr_partition_map_gen =
                                        ctx->cx_partition_map.pm_generation;
            cmd->u.cache_query_req.cqr_hash_key = hash_key;
            cmd->u.cache_query_req.cqr_md_rid =
                            cs_buf->u.cmb_cache_query_request.cqr_md_rid;
            cmd->u.cache_query_req.cqr_cs_rid =
                            cs_buf->u.cmb_cache_query_request.cqr_cs_rid;
            cmd->u.cache_query_req.cqr_cachedev_id =
                            cs_buf->u.cmb_cache_query_request.cqr_cachedev_id;
            cmd->u.cache_query_req.cqr_service_id =
                                            ctx->cx_params.rsp_service_id;
            /*
             * We use the req_msg_id field to help us find this message when
             * its response arrives.  The MD assumes nothing about the content
             * of this field, and simply returns its value in its response,
             * which can then be matched against the stored ibuf.
             */
            cmd->u.cache_query_req.cqr_msg_id = NEW_MD_MSG_ID(ctx, partition);
            ibuf->h.rmbi_req_msg_id = cmd->u.cache_query_req.cqr_msg_id;
        } else if ((RNA_SERVICE_MESSAGE_TYPE_RELOCATE_BLOCK ==
                                                buf->h.rmb_message_type)) {
            memset(cmd, 0, empty_cache_cmd_length(CACHE_RELOCATE_BLOCK));
            cmd->h.h_type = CACHE_RELOCATE_BLOCK;
            cmd->u.relocate_block.crb_md_rid =
                            buf->u.rmb_relocate_cache_block.rcb_md_rid;
            cmd->u.relocate_block.crb_dst_in =
                            buf->u.rmb_relocate_cache_block.rcb_dst_in;
            cmd->u.relocate_block.crb_hash_partition =
                            buf->u.rmb_relocate_cache_block.rcb_hash_partition;
            /*
             * zero indicates that buf can be freed after transmit rather than 
             * queuing onto pi_waiting_for_reply.
             */
            ibuf->h.rmbi_req_msg_id = 0;
        } else if ((RNA_SERVICE_MESSAGE_TYPE_ABSORB_BLOCK ==
                                                buf->h.rmb_message_type)) {
            memset(cmd, 0, empty_cache_cmd_length(CACHE_ABSORB_BLOCK));
            cmd->h.h_type = CACHE_ABSORB_BLOCK;
            cmd->u.cache_absorb_block.cab_partition_map_gen =
                                        ctx->cx_partition_map.pm_generation;
            cmd->u.cache_absorb_block.rnas = buf->u.rmb_cache_absorb_block;
            strcpy(cmd->u.cache_absorb_block.rnas.cab_query_cmd.mqs_pathname,
                   buf->u.rmb_cache_absorb_block.cab_query_cmd.mqs_pathname);
            /*
             * We use the req_msg_id field to help us find this message when
             * its response arrives.  The MD assumes nothing about the content
             * of this field, and simply returns its value in its response,
             * which can then be matched against the stored ibuf.
             */
            cmd->u.cache_absorb_block.cab_msg_id =
                                            NEW_MD_MSG_ID(ctx, partition);
            ibuf->h.rmbi_req_msg_id = cmd->u.cache_absorb_block.cab_msg_id;
        } else if ((RNA_SERVICE_MESSAGE_TYPE_INVD_HOLD_RESPONSE ==
                                                buf->h.rmb_message_type)) {
            memset(cmd, 0, empty_cache_cmd_length(CACHE_INVD_HOLD_RESP));
            cmd->h.h_type = CACHE_INVD_HOLD_RESP;
            cmd->u.cache_invd_hold_resp.cihr_md_rid =
                            buf->u.rmb_invd_hold_response.ihr_md_rid;
            cmd->u.cache_invd_hold_resp.cihr_cancel =
                            buf->u.rmb_invd_hold_response.ihr_cancel;
            cmd->u.cache_invd_hold_resp.cihr_cs_policy =
                            buf->u.rmb_invd_hold_response.ihr_cs_policy;
            cmd->u.cache_invd_hold_resp.cihr_hash_partition =
                            buf->u.rmb_invd_hold_response.ihr_hash_partition;
            /*
             * zero indicates that buf can be freed after transmit rather than 
             * queuing onto pi_waiting_for_reply.
             */
            ibuf->h.rmbi_req_msg_id = 0;
        }
        /* end of if-else command setup */

        rna_dbg_log(RNA_DBG_VERBOSE, //INFO,
                    "sending [%s] message ID [%"PRIx64"] "
                    "to ["RNA_ADDR_FORMAT"] for %s\n",
                    get_cmd_type_string(cmd->h.h_type),
                    ibuf->h.rmbi_req_msg_id,
                    RNA_ADDR(mdi->mdi_eph.eph_dst_in.sin_addr),
                    pathname);

        ret = rna_service_com_send_cache_cmd(&mdi->mdi_eph,
                                             send_buf,
                                             cache_cmd_length(cmd),
                                             &ctx->cx_primary_cfm_id);
        if (0 == ret) {
            if (ibuf->h.rmbi_req_msg_id != 0) {
                ibuf->h.rmbi_flags |= RMBI_FLAG_SENT;
                YAQ_INSERT_TAIL(
                            &ctx->cx_partitions[partition].pi_waiting_for_reply,
                            &ibuf->h.rmbi_link);
            } else {
                rna_service_free_message_buffer(ctx,
                                                &ibuf->u.rmbi_message_buffer);
            }
        } else {
            rna_dbg_log(RNA_DBG_WARN, "Failed to send MD message: %ld\n",
                        ret);
            if (flags & SEND_MD_GENERIC_FLAG_RESEND) {
                /*
                 * Place this message back where it was in the queue, so the
                 * queue isn't re-ordered.
                 */
                YAQ_INSERT_HEAD(&ctx->cx_partitions[partition].
                                                        pi_waiting_to_send,
                                &ibuf->h.rmbi_link);
            } else {
                /* This is a new message; place it at the end of the queue */
                YAQ_INSERT_TAIL(&ctx->cx_partitions[partition].
                                                        pi_waiting_to_send,
                                &ibuf->h.rmbi_link);
            }
            schedule_waiting_md_msgs(ctx, mdi, SEND_WAITING_MD_MSGS_DELAY_SEC);
        }
    } else {
        if (flags & SEND_MD_GENERIC_FLAG_RESEND) {
            /*
             * Place this message back where it was in the queue, so the queue
             * isn't re-ordered.
             */
            YAQ_INSERT_HEAD(&ctx->cx_partitions[partition].pi_waiting_to_send,
                            &ibuf->h.rmbi_link);
        } else {
            /* This is a new message; place it at the end of the queue */
            YAQ_INSERT_TAIL(&ctx->cx_partitions[partition].pi_waiting_to_send,
                            &ibuf->h.rmbi_link);
        }
    }

 done_set_timeout:
    if (!(flags & SEND_MD_GENERIC_FLAG_RESEND)) {
        /*
         * If the user has specified a response timeout, set a timer.
         *
         * (Note that because the cx_md_mutex is held, we know this ctx isn't
         * being shut down (see rna_service_ctx_destroy()), so it's safe to
         * call rna_service_timer_set() -- specifically, we know the timer
         * cancellation phase of the shutdown hasn't yet been executed, so
         * we won't be leaving a set timer after shutdown).
         */
        if (timeout > 0) {
            rna_service_timer_set(ctx->cx_private,
                                  &ibuf->h.rmbi_response_timer_object,
                                  md_response_timed_out,
                                  (uint64_t)ibuf,
                                  (int) timeout);
        }

        ctx->cx_partitions[partition].pi_msgs_outstanding_cnt++;

        if (ibuf->h.rmbi_flags & RMBI_FLAG_PRE_ALLOC) {
            ibuf->h.rmbi_flags &= ~RMBI_FLAG_PRE_ALLOC;
            if (--ctx->cx_partitions[partition].pi_msgs_preallocated_cnt < 0) {
                rna_dbg_log(RNA_DBG_MSG,
                            "preallocation count underflow, partition [%d] "
                            "gen [%"PRIu64"]\n",
                            partition,
                            ctx->cx_partition_map.pm_generation);
                ctx->cx_partitions[partition].pi_msgs_preallocated_cnt = 0;
            }
        }
    }

 done_unlock:
    rna_service_mutex_unlock(&ctx->cx_md_mutex);

 done:
    ctx_release_reference(&ctx);
    return (err);
}


/**
 * If a hash partition has been assigned to a new metadata server or if the
 * metadata server assigned to it has recently (re-)connected, any messages
 * waiting in that partition's message queue need to be (re-)sent to the
 * metadata server.
 *
 * (As background, the metadata hash space is divided into equal-sized hash
 * partitions, each of which is assigned to a metadata server.  A given MD is
 * assigned one or more partitions to service).
 *
 * Locking:
 *    The ctx->cx_md_mutex must be held on entry.
 */
static void
resend_md_messages(rna_service_ctx_t *ctx)
{
    int        i;
    md_info_t *mdi;
    YAQ_HEAD   msg_queue;

    YAQ_INIT(&msg_queue);

    rna_service_assert(NULL != ctx);
    rna_service_assert_locked(&ctx->cx_md_mutex);

    /*
     * The callers of this routine should have assured that the initial
     * partition map has been received.    Without it, we can't tell which
     * partitions are assigned to this MD, so we don't know which partitions'
     * messages to send.
     */
    if (0 == ctx->cx_partition_map.pm_generation) {
        rna_dbg_log(RNA_DBG_ERR,
                    "Called before initial partition map received\n");
        return;
    }

    /*
     * (As an obsessive-compulsive optimization, the partitions are traversed
     * in reverse order, so ctx->cx_partition_map.pm_num_hash_partitions
     * doesn't need to be re-evaluated on each iteration).
     */
    for (i = ctx->cx_partition_map.pm_num_hash_partitions - 1; i >= 0; --i) {
        /*
         * Re-send the waiting messages for a hash partition if the partition
         * is marked as needing to have its messages re-sent, and we now have
         * a connection to the MD the partition is assigned to.
         */
        if ((ctx->cx_partitions[i].pi_partition_flags &
                                                PARTITION_FLAG_SEND_TO_NEW_MD)
          && (NULL != (mdi = ctx->cx_md_table[ctx->cx_partition_map.
                                                pm_partition_assignments[i]]))
          && (mdi->mdi_cflags & MD_INFO_CFLAG_CONNECTED)) {
            /*
             * Move the messages from the 'waiting from reply' queue to the
             * 'waiting to send' queue and schedule them to be re-sent.
             */
            rna_dbg_log(RNA_DBG_MSG,
                        "Re-queueing messages in partition [%d] "
                        "for re-send to MD ["RNA_ADDR_FORMAT"] "
                        "["rna_service_id_format"] "
                        "ordinal [%d] ent [%p]  ep [%p]\n",
                        i,
                        RNA_ADDR(mdi->mdi_eph.eph_dst_in.sin_addr),
                        rna_service_id_get_string(&mdi->mdi_service_id),
                        mdi->mdi_ordinal,
                        mdi,
                        com_get_ep_ptr(&mdi->mdi_eph));
            ctx->cx_partitions[i].pi_partition_flags &=
                                                ~PARTITION_FLAG_SEND_TO_NEW_MD;
            YAQ_MERGE_HEAD(&ctx->cx_partitions[i].pi_waiting_to_send,
                           &ctx->cx_partitions[i].pi_waiting_for_reply);

            /*
             * If send_waiting_md_msgs() isn't already scheduled to run,
             * schedule it now.
             */
            schedule_waiting_md_msgs(ctx, mdi, 0);
        }
    }
}


/**
 * md_disconnected()
 *   The specified metadata server either has been or is being
 *   disconnected.  This routine does some early disconnect
 *   processing that is safe to do without waiting for the
 *   underlying com layer to see/acknowledge the disconnect.
 *
 * Notes:
 *   The reason for splitting out this early processing is because
 *   occasionally it takes awhile for the com layer to fully disconnect.
 *   Doing this processing early may allow us to reconnect to a new MD
 *   sooner (i.e. before the full disconnect processing completes).
 *
 * Locking:
 *    The ctx->cx_md_mutex must be held on entry.
 */
static void
md_disconnected(rna_service_ctx_t *ctx, md_info_t *mdi)
{
    int i;
    int ret;

    rna_service_assert(NULL != ctx);
    rna_service_assert(NULL != mdi);
    rna_service_assert_locked(&ctx->cx_md_mutex);

    if (mdi->mdi_cflags & MD_INFO_CFLAG_PRELIM_DISCONN) {
        rna_dbg_log(RNA_DBG_WARN, "prelim disconnect work already done for MD "
                    "[" RNA_ADDR_FORMAT "] ent [%p] ep [%p]\n",
                    RNA_ADDR(mdi->mdi_eph.eph_dst_in.sin_addr),
                    mdi,
                    com_get_ep_ptr(&mdi->mdi_eph));
        return;
    }
    mdi->mdi_cflags |= MD_INFO_CFLAG_PRELIM_DISCONN;

    /*
     * (Note that the MD_INFO_IFLAG_MUST_SEND_MD_CONNECTION_INFO must be
     * cleared before potentially being re-set below).
     */
    mdi->mdi_iflags &= ~(MD_INFO_IFLAG_ACTIVATED |
                         MD_INFO_IFLAG_MUST_SEND_MD_CONNECTION_INFO);

    rna_dbg_log(RNA_DBG_MSG,
                "Preliminary disconnect from Meta Data server "
                "[" RNA_ADDR_FORMAT "] ent [%p] ordinal [%d] ep [%p]\n",
                RNA_ADDR(mdi->mdi_eph.eph_dst_in.sin_addr),
                mdi,
                mdi->mdi_ordinal,
                (!com_eph_isempty(&mdi->mdi_eph))
                    ? com_get_ep_ptr(&mdi->mdi_eph)
                    : NULL);

    /*
     * Indicate that, for any partitions that were assigned to this MD, any
     * messages waiting to be sent or waiting for a response will need to be
     * re-sent to whatever MD eventually gets assigned those partitions,
     * whenever such an MD becomes connected.
     */
    for (i = ctx->cx_partition_map.pm_num_hash_partitions - 1; i >= 0; --i) {
        if (ctx->cx_partition_map.pm_partition_assignments[i] ==
                                                            mdi->mdi_ordinal) {
            ctx->cx_partitions[i].pi_partition_flags |=
                                                PARTITION_FLAG_SEND_TO_NEW_MD;
        }
    }

    /*
     * If the user is a cache server and if the connection was 'live',
     * tell the CFM that the connection has been lost.
     */
    if ((RNA_SERVICE_USER_TYPE_CACHE_SERVER == ctx->cx_params.rsp_user_type)
      && (mdi->mdi_cflags & MD_INFO_CFLAG_CONNECTED)) {
        ret = rna_service_send_service_disconnection_info(
                                                    &ctx->cx_primary_cfm_eph,
                                                    &mdi->mdi_service_id,
                                                    mdi->mdi_ordinal,
                                                    0);
        if (ret != 0) {
            /* send failed, we'll need to retry later */
            mdi->mdi_cflags |= MD_INFO_CFLAG_CONNECTION_FAILED;
            mdi->mdi_iflags |= MD_INFO_IFLAG_MUST_SEND_MD_CONNECTION_INFO;
            ctx->cx_md_flags |= CTX_MD_FLAG_MUST_SEND_MD_CONNECTION_INFO;
        }
    }
    /*
     * (Note that the MD_INFO_CFLAG_CONNECTED flag must not be cleared before
     * this point, since it's needed in the above 'if').
     */
    mdi->mdi_cflags &= ~MD_INFO_CFLAG_CONNECTED;

    if (!(ctx->cx_flags & CX_FLAG_SHUTTING_DOWN)) {
        queue_reconnect_mds(ctx);
    }
}

/**
 * md_disconnected_complete()
 *   The specified metadata server has been disconnected.
 *   The com layer has seen/acknowledged the disconnect, so full
 *   disconnect processing is taken care of here.
 *
 * Locking:
 *    The ctx->cx_md_mutex must be held on entry.
 */
static void
md_disconnected_complete(rna_service_ctx_t *ctx, md_info_t *mdi)
{
    rna_service_assert(NULL != ctx);
    rna_service_assert(NULL != mdi);
    rna_service_assert_locked(&ctx->cx_md_mutex);

    if (!(mdi->mdi_cflags & MD_INFO_CFLAG_PRELIM_DISCONN)) {
        md_disconnected(ctx, mdi);
    }

    rna_dbg_log(RNA_DBG_MSG,
                "Disconnect complete from Meta Data server "
                "[" RNA_ADDR_FORMAT "] ent [%p] ordinal [%d] ep [%p]\n",
                RNA_ADDR(mdi->mdi_eph.eph_dst_in.sin_addr),
                mdi,
                mdi->mdi_ordinal,
                (!com_eph_isempty(&mdi->mdi_eph))
                    ? com_get_ep_ptr(&mdi->mdi_eph)
                    : NULL);

    mdi->mdi_cflags |= MD_INFO_CFLAG_FINAL_DISCONN;

    if (!com_eph_isempty(&mdi->mdi_eph)) {
        com_set_eph_context(&mdi->mdi_eph, NULL);
        /*
         * Release mdi_eph reference (added by connect_md() when mdi_eph
         * was set).
         */
        com_release_eph(&mdi->mdi_eph); // (no-op at user level)
        com_init_eph(&mdi->mdi_eph);
    }

    /*
     * If the user is a cache server, we have a bit more to do...
     */
    if (RNA_SERVICE_USER_TYPE_CACHE_SERVER == ctx->cx_params.rsp_user_type) {
        rna_service_ping_local_context_deregister(&mdi->mdi_local_ping_ctx);
        rna_service_ping_remote_context_deregister(&mdi->mdi_remote_ping_ctx);
    }

    if (ctx->cx_md_table[mdi->mdi_ordinal] != mdi) {
        /*
         * This mdi has been removed from the md_table (by
         * remove_md_table_entry after being expelled) or replaced
         * (by connect_md to establish a new connection), so it's
         * no longer needed.
         */
        free_mdi(ctx, mdi);
    }
}


/**
 * Process an MD connection that's been established.
 *
 * If the blocking_flag is TRUE, the caller must hold a reference on
 * mdi->mdi_ep.
 *
 * Locking:
 *    The ctx->cx_md_mutex must be held on entry.  This mutex may be dropped
 *    and re-acquired by this function.
 *
 * Returns:
 *    0    on success
 *   -1    the cx_md_mutex is no longer held, because a shutdown is in progress
 *    1    other failure
 */
static int
md_connected(rna_service_ctx_t *ctx, md_info_t *mdi, boolean blocking_flag)
{
    size_t                ret;
    int                   i;
    int                   ordinal;
    com_ep_handle_t       md_eph;
    com_ep_handle_t       cfm_eph;
    struct rna_service_id service_id;
    rna_service_send_buf_entry_t
                         *send_buf;
    struct cache_cmd     *cmd;
    rna_service_message_buffer_internal_t *ib;
    YAQ_LINK *lnkp;
    char                 *wwn_str = NULL;

    rna_service_assert(NULL != ctx);
    rna_service_assert(NULL != mdi);
    rna_service_assert_locked(&ctx->cx_md_mutex);
    ordinal = mdi->mdi_ordinal;
    rna_service_assert(ordinal < NUM_MD_ORDINALS);

    md_eph = mdi->mdi_eph;
    rna_dbg_log(RNA_DBG_INFO,
                "Connection established with MD [" RNA_ADDR_FORMAT "] "
                "ordinal [%d]\n",
                RNA_ADDR(md_eph.eph_dst_in.sin_addr), ordinal);

    if (RNA_SERVICE_USER_TYPE_CACHE_SERVER == ctx->cx_params.rsp_user_type) {
        /*
         * Since the rna_service user is a cache server, it must register
         * with the newly-connected MD.
         *
         * If we're making a blocking request for a sendbuf, don't hold the
         * cx_md_mutex across the call.
         */
        if (blocking_flag) {
            rna_service_mutex_unlock(&ctx->cx_md_mutex);
        }
        ret = rna_service_com_get_send_buf(&md_eph,
                                           &send_buf,
                                           blocking_flag,
                                           NULL);
        if (blocking_flag) {
            if (!rna_service_mutex_lock(&ctx->cx_md_mutex)) {
                /* This failure means we're in the process of shutting down */
                if (send_buf != NULL) {
                    rna_service_com_put_send_buf(&md_eph, send_buf);
                }
                return (-1);
            }
            /*
             * Make sure nothing happened to the mdi or MD connection while we
             * didn't hold the mutex
             */
            if ((ctx->cx_md_table[ordinal] != mdi)
              || (!com_eph_equal(&mdi->mdi_eph, &md_eph))) {
                /*
                 * (No need wo call schedule_waiting_md_msgs here, since it'll
                 * be scheduled when we have a new connection to the MD).
                 */
                if (send_buf != NULL) {
                    rna_service_com_put_send_buf(&md_eph, send_buf);
                }
                return (1);
            }
        }
        if ((NULL == send_buf) || (0 != ret)) {
            mdi->mdi_cflags |= MD_INFO_CFLAG_MUST_REGISTER;
            if ((blocking_flag)
              && (rna_service_com_connected(&md_eph))) {
                /* This should never happen! */
                rna_dbg_log(RNA_DBG_ERR,
                            "Failed to get send buffer after blocking!\n");
            } else {
                rna_dbg_log(RNA_DBG_WARN,
                            "Failed to get send buffer!!\n");
            }
            schedule_waiting_md_msgs(ctx, mdi, SEND_WAITING_MD_MSGS_DELAY_SEC);
            return (1);
        }

#if defined(LINUX_KERNEL) || defined(WINDOWS_KERNEL)
        cmd = (struct cache_cmd *)(com_get_send_buf_mem(send_buf));
#else
        cmd = (struct cache_cmd *) send_buf->mem;
#endif
        
        cmd->h.h_type = CACHE_REGISTER;
        cmd->u.cache_reg.service_id = ctx->cx_params.rsp_service_id;
        cmd->u.cache_reg.cr_cs_membership_generation =
                                            ctx->cx_cs_membership_generation;
        cmd->u.cache_reg.if_tbl = ctx->cx_cs_params.csp_cs_if_tbl;

        strcpy(cmd->u.cache_reg.hostname, ctx->cx_params.rsp_node_name);

        rna_dbg_log(RNA_DBG_INFO,
                    "Register cache gen [%"PRId64"] with MD "
                    "[" RNA_ADDR_FORMAT "]\n",
                    cmd->u.cache_reg.cr_cs_membership_generation,
                    RNA_ADDR(md_eph.eph_dst_in.sin_addr));
        cmd->u.cache_reg.max_mem = ctx->cx_cs_params.csp_cs_max_mem;
        rna_service_ping_local_ctx_init(
                                    &md_eph, 
                                    &mdi->mdi_local_ping_ctx,
                                    ctx->cx_cs_params.csp_cs_ping_data,
                                    ctx->cx_cs_params.csp_cs_ping_data_length,
                                    &cmd->u.cache_reg.ping_buf,
                                    &cmd->u.cache_reg.ping_rkey);
        cmd->u.cache_reg.status = ctx->cx_cs_params.csp_cs_status;

        ret = rna_service_com_send_cache_cmd(&md_eph,
                                             send_buf,
                                             cache_cmd_length(cmd),
                                             &ctx->cx_primary_cfm_id);
        if (ret != 0) {
            rna_dbg_log(RNA_DBG_WARN, "Send failed: %ld\n", ret);
            /* It's likely the connection has been lost; wait for reconnect */
            mdi->mdi_cflags |= MD_INFO_CFLAG_MUST_REGISTER;
            schedule_waiting_md_msgs(ctx, mdi, SEND_WAITING_MD_MSGS_DELAY_SEC);
            return (1);
        }

        /*
         * Tell the CFM this cache server has connected with the specified MD
         * and register this cache server with this MD.  (Note that when both
         * the cx_cfm_mutex and the cx_md_mutex must be held, the cx_cfm_mutex
         * must be acquired after the cx_md_mutex to prevent deadlock).
         *
         * Since rna_service_send_service_connection_info involves a blocking
         * operation, we do some work here to avoid holding mutexes when it's
         * called.
         */
        if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
            /* This failure means we're in the process of shutting down */
            rna_service_mutex_unlock(&ctx->cx_md_mutex);
            return (-1);
        }
        cfm_eph = ctx->cx_primary_cfm_eph;
        com_inc_ref_eph(&cfm_eph);  // (no-op at user level)
        com_inc_ref_eph(&md_eph);

        /* Don't hold mutex across blocking operation */
        rna_service_mutex_unlock(&ctx->cx_cfm_mutex);

        service_id = mdi->mdi_service_id;

        /* Don't hold mutex across blocking operation */
        rna_service_mutex_unlock(&ctx->cx_md_mutex);

        /* (NOTE that 'ret' is deal with a bit below) */
        ret = rna_service_send_service_connection_info(&cfm_eph,
                                                       &service_id,
                                                       &md_eph,
                                                       ordinal);
        com_release_eph(&md_eph);   // (no-op at user level)
        com_release_eph(&cfm_eph);

        if (!rna_service_mutex_lock(&ctx->cx_md_mutex)) {
            /* This failure means we're in the process of shutting down */
            return (-1);
        }
        /*
         * Make sure nothing happened to the mdi or MD connection while we
         * didn't hold the mutex
         */
        if ((ctx->cx_md_table[ordinal] != mdi)
          || (!com_eph_equal(&mdi->mdi_eph, &md_eph))) {
            /*
             * (No need to call schedule_waiting_md_msgs here, since it'll
             * be scheduled when we have a new connection to the MD).
             */
            return (1);
        }

        if (0 != ret) {
            mdi->mdi_cflags &= ~MD_INFO_CFLAG_CONNECTION_FAILED;
            mdi->mdi_iflags |= MD_INFO_IFLAG_MUST_SEND_MD_CONNECTION_INFO;
            ctx->cx_md_flags |= CTX_MD_FLAG_MUST_SEND_MD_CONNECTION_INFO;
            /*
             * Schedule send_waiting_cfm_msgs() to send this message.  The
             * cx_cfm_mutex must be held to call schedule_waiting_cfm_msgs.
             */
            if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
                /* This failure means we're in the process of shutting down */
                rna_service_mutex_unlock(&ctx->cx_md_mutex);
                return (-1);
            }
            schedule_waiting_cfm_msgs(ctx, SEND_WAITING_CFM_MSGS_DELAY_SEC);
            rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
        }

        /*
         * Register all the storage paths on the cx_md_registered_paths
         * list. cx_md_mutex must be dropped before calling send_md_generic()
         */
        YAQ_FOREACH(&ctx->cx_md_registered_paths, lnkp) {
            ib = YAQ_OBJECT(rna_service_message_buffer_internal_t,
                            h.rmbi_link,
                            lnkp);
            if (blocking_flag) {
                rna_service_mutex_unlock(&ctx->cx_md_mutex);
            }

            ret = rna_service_com_get_send_buf(&md_eph,
                                               &send_buf,
                                               blocking_flag,
                                               NULL);
            if (blocking_flag) {
                if (!rna_service_mutex_lock(&ctx->cx_md_mutex)) {
                    /* This means we're in the process of shutting down */
                    if (send_buf != NULL) {
                        rna_service_com_put_send_buf(&md_eph, send_buf);
                    }
                    return (-1);
                }
                /*
                 * Make sure nothing happened to the mdi or MD connection while
                 * we didn't hold the mutex
                 */
                if ((ctx->cx_md_table[ordinal] != mdi)
                  || (!com_eph_equal(&mdi->mdi_eph, &md_eph))) {
                    /*
                     * (No need wo call schedule_waiting_md_msgs here, since
                     * it'll be scheduled when we have a new connection to the
                     * MD).
                     */
                    if (send_buf != NULL) {
                        rna_service_com_put_send_buf(&md_eph, send_buf);
                    }
                    return (1);
                }
            }
            if ((NULL == send_buf) || (0 != ret)) {
                if ((blocking_flag) && (rna_service_com_connected(&md_eph))) {
                    /* This should never happen! */
                    rna_dbg_log(
                            RNA_DBG_ERR,
                            "Failed to get send buffer after blocking!\n");
                } else {
                    rna_dbg_log(RNA_DBG_WARN,
                                "Failed to get send buffer!!\n");
                    schedule_waiting_md_msgs(ctx,
                                             mdi,
                                             SEND_WAITING_MD_MSGS_DELAY_SEC);
                }
                return (1);
            }

#if defined(LINUX_KERNEL) || defined(WINDOWS_KERNEL)
            cmd = (struct cache_cmd *)(com_get_send_buf_mem(send_buf));
#else
            cmd = (struct cache_cmd *) send_buf->mem;
#endif

            cmd->h.h_type = CACHE_REG_PATH;
            cmd->u.path_reg.rnas.rp_service_id = ctx->cx_params.rsp_service_id;

            cmd->u.path_reg.rnas.rp_wwn =
                   ib->u.rmbi_message_buffer.u.rmb_register_path.rp_wwn;

            memcpy(&cmd->u.path_reg.rnas.rp_path[0],
                   &ib->u.rmbi_message_buffer.u.rmb_register_path.rp_path[0],
                   sizeof(cmd->u.path_reg.rnas.rp_path));

            rna_create_wwn_strings(&cmd->u.path_reg.rnas.rp_wwn,
                               &wwn_str, NULL, NULL, NULL);
            rna_dbg_log(RNA_DBG_INFO,
                        "Registering storage path with MD: wwn [%s]\n",
                        wwn_str ? wwn_str : NULL);
            if (wwn_str) {
                rna_service_simple_free(wwn_str);
            }

            ret = rna_service_com_send_cache_cmd(&md_eph,
                                                 send_buf,
                                                 cache_cmd_length(cmd),
                                                 &ctx->cx_primary_cfm_id);
            if (ret != 0) {
                rna_dbg_log(RNA_DBG_WARN, "Send failed: %ld\n", ret);
                // It's likely the connection has been lost; wait for reconnect
                schedule_waiting_md_msgs(ctx,
                                         mdi,
                                         SEND_WAITING_MD_MSGS_DELAY_SEC);
                return (1);
            }
        }
    }

    /*
     * If we've received an initial partition map, any messages queued for
     * this MD can now be sent.
     */
    if (ctx->cx_partition_map.pm_generation != 0) {
        for (i = ctx->cx_partition_map.pm_num_hash_partitions - 1;
             i >= 0;
             --i) {

            if (ctx->cx_partition_map.pm_partition_assignments[i] ==
                                                            mdi->mdi_ordinal) {
                ctx->cx_partitions[i].pi_partition_flags |=
                                                PARTITION_FLAG_SEND_TO_NEW_MD;
            }
        }
        resend_md_messages(ctx);
    }

    /*
     * If a message queue overflow has occurred and we've received at least
     * one partition map, check if we now have all MD connections, and if so,
     * notify the user.  If the user stopped submitting messages after the
     * overflow, this event will serve as notification that it's now OK to
     * restart.
     */
    if ((ctx->cx_md_flags & CTX_MD_FLAG_MSGS_OUTSTANDING_OVERFLOWED)
      && (ctx->cx_partition_map.pm_generation != 0)) {
        for (i = ctx->cx_partition_map.pm_num_hash_partitions - 1; i >= 0; --i)
        {
            mdi = ctx->cx_md_table[
                            ctx->cx_partition_map.pm_partition_assignments[i]];
            if ((NULL == mdi)
              || (!(mdi->mdi_cflags & MD_INFO_CFLAG_CONNECTED))
              || (!rna_service_com_connected(&mdi->mdi_eph))) {
                break;
            }
        }
        if (i < 0) {
            /*
             * We now have all MD connections.  Notify the user.
             */
            ctx->cx_md_flags &= ~CTX_MD_FLAG_MSGS_OUTSTANDING_OVERFLOWED;
            /* don't hold mutex during callback */
            rna_service_mutex_unlock(&ctx->cx_md_mutex);
            rna_dbg_log(RNA_DBG_INFO,
                        "All MD connections are now established\n");
            ctx->cx_params.rsp_event_callback(
                        ctx, RNA_SERVICE_EVENT_INFO_FULLY_CONNECTED);
            if (!rna_service_mutex_lock(&ctx->cx_md_mutex)) {
                /* This failure means we're in the process of shutting down */
                return (-1);
            }
        }
    }
    return (0);
}

/**
 * Establish a connection with a metadata server.
 *
 * Locking:
 *    The ctx->cx_md_mutex must be held on entry.  This mutex may be dropped
 *    and re-acquired by this function.
 *
 * Returns:
 *    0 if the cx_md_mutex is still held
 *   -1 if the cx_md_mutex is no longer held, because a shutdown is in progress
 */
static int
connect_md(rna_service_ctx_t *ctx, md_info_t **mdipp)
{
    int                 ret = -1;
    md_info_t          *mdi, *old_mdi;
    uint32_t            i;
    struct sockaddr_in  addr;
    struct rna_if_info *md_if;
    user_type_t         user_type;
    int                 num_send_bufs;
    int                 num_recv_bufs;
    com_ep_handle_t     eph;
    size_t              bufsize;
#if defined(_RNA_CS_MD_CONNS_RDMA_ONLY_)
    boolean             rdma_only = FALSE;
#endif

    rna_service_assert((NULL != mdipp) && (NULL != *mdipp));
    rna_service_assert_locked(&ctx->cx_md_mutex);

    mdi = *mdipp;

    if (RNA_SERVICE_USER_TYPE_CACHE_SERVER == ctx->cx_params.rsp_user_type) {
        user_type = USR_TYPE_META_CACHE;
    } else {
        user_type = USR_TYPE_META_CLIENT;
    }
    rna_trace("connecting to MD [%d] ["rna_service_id_format"] as "
              "user type [%s]\n",
              mdi->mdi_ordinal,
              rna_service_id_get_string(&mdi->mdi_service_id),
              get_user_type_string(user_type));

    /*
     * Determine the number of send and receive bufs we'll allocate for each
     * MD's ep.
     */
    rna_service_assert(ctx->cx_num_configured_mds > 0);
    if (RNA_SERVICE_USER_TYPE_CACHE_SERVER == ctx->cx_params.rsp_user_type)
    {
        num_send_bufs = RNA_SERVICE_CS_MD_SEND_BUFS /
                                                ctx->cx_num_configured_mds;
        num_recv_bufs = RNA_SERVICE_CS_MD_RECV_BUFS /
                                                ctx->cx_num_configured_mds;
        /*
         * A CS sends both cache_cmd and md_sync_cmd messages on this connection
         */
        #if defined(WINDOWS_KERNEL) || defined(WINDOWS_USER)
            #pragma warning(push)
            #pragma warning(disable:4127)   /* constant conditional expr just fine here */
        #endif /* WINDOWS */
        if (sizeof(struct cache_cmd) > sizeof(struct md_sync_cmd)) {
            bufsize = sizeof(struct cache_cmd);
        } else {
            bufsize = sizeof(struct md_sync_cmd);
        }
        #if defined(WINDOWS_KERNEL) || defined(WINDOWS_USER)
            #pragma warning(pop)
        #endif /* WINDOWS */
    } else {
        num_send_bufs = RNA_SERVICE_CLIENT_MD_SEND_BUFS /
                                                ctx->cx_num_configured_mds;
        num_recv_bufs = RNA_SERVICE_CLIENT_MD_RECV_BUFS /
                                                ctx->cx_num_configured_mds;
        bufsize = sizeof(struct cache_cmd);
    }
    /*
     * To deal with the possibility that not all configured MDs are running,
     * over-allocate per-MD buffers by 25%.
     */
    if (ctx->cx_num_configured_mds > 1) {
        num_send_bufs += (num_send_bufs >> 2);
        num_recv_bufs += (num_recv_bufs >> 2);
    }
#if defined(_RNA_CS_MD_CONNS_RDMA_ONLY_)
    for (i = 0; (i < mdi->mdi_if_tbl.table_entries); i++) {
        if (RC == mdi->mdi_if_tbl.ifs[i].type) {
            /* 
             * We're configured for RDMA-only MD connections and
             * we found one RDMA interface, so we'll only try
             * RDMA.
             */
            rdma_only = TRUE;
            break;
        }
    }
#endif
    for (i = 0;
         (i < mdi->mdi_if_tbl.table_entries) &&
                                (!(mdi->mdi_cflags & MD_INFO_CFLAG_CONNECTED));
         i++) {

        if (ctx->cx_flags & CX_FLAG_SHUTTING_DOWN) {
            /* Don't bother re-connecting if we're shutting down */
            return (0);
        }

        md_if = &mdi->mdi_if_tbl.ifs[i];
#if defined(_RNA_CS_MD_CONNS_RDMA_ONLY_)
        if ((TRUE == rdma_only) && (RC != md_if->type)) {
            rna_dbg_log(RNA_DBG_INFO, "Ignoring interface type [%s] to "
                        "MD ["RNA_ADDR_FORMAT"]\n",
                        com_get_transport_type_string(md_if->type),
                        RNA_ADDR(md_if->addr));
            continue;
        }
#endif
        addr.sin_family = PF_INET;
        addr.sin_addr.s_addr = md_if->addr;

#ifdef WINDOWS_KERNEL

        // TODO: FIXME:  This is an UGLY workaround for HRM-2493 where the linux stuff is storing the 
        // ports in host byte order not network byte order.  It causes havoc w/Windows com driver.  This is
        // a TEMPORARY hack that needs be removed once the HRM is fixed.
        addr.sin_port = htons(md_if->port);
#else
        addr.sin_port = md_if->port;
#endif /* WINDOWS_KERNEL */

        /*
         * Most messages on the ep will be struct cache_cmd, but we may also
         * possibly send a CONF_MGR_MD_PARTITION_MAP message, which is a
         * struct cfm_cmd.  Since CONF_MD_PARTITION_MAP messages are smaller
         * than cache_cmd, we size the ep buffers to cache_cmd, which is
         * considerably smaller than cfm_cmd.
         */
        ret = rna_service_com_alloc_ep(ctx->cx_com_instance,
                                      &ctx->cx_com_attributes,
                                       md_if->type,
                                       num_send_bufs,
                                       num_recv_bufs,
                                       (int)bufsize,
                                       0,
                                       0,
                                       user_type,
                                       0,
                                       0,
                                       0,
                                      &eph);
        if (0 != ret) {
            if (-ENODEV != ret) {
                rna_dbg_log(RNA_DBG_INFO,
                            "failed to alloc ep for connection to "
                            "metadata server [%d] ["rna_service_id_format"] "
                            "via ["RNA_ADDR_FORMAT"/%d] [%s]\n",
                            mdi->mdi_ordinal,
                            rna_service_id_get_string(&mdi->mdi_service_id),
                            RNA_ADDR(addr.sin_addr),
                            addr.sin_port,
                            com_get_transport_type_string(md_if->type));
            }
            continue;   // try the next entry in the mdi_if_tbl
        }

        /*
         * If 'mdi' represents a previous connection to the MD, create a new
         * mdi to represent this new connection in the md_table.
         */
        if (com_eph_isempty(&mdi->mdi_eph)) {
            /*
             * Either this mdi has never had a connection, or its previous
             * attempt's disconnect processing has completed (mdi_eph is
             * re-initialized in md_disconnected_complete).  Make sure the
             * mdi contains no residual information from a past connect
             * attempt.
             */
            memset((void *)&mdi->mdi_connection,
                   0,
                   sizeof(mdi->mdi_connection));
        } else {
            /*
             * Disconnect processing hasn't yet completed for a previous
             * connect attempt.  Create a new mdi for this new connect
             * attempt.
             */
            old_mdi = mdi;
            mdi = (md_info_t *) mempool_alloc(ctx, MEMPOOL_ID_MD_INFO, 0);
            if (NULL == mdi) {
                rna_dbg_log(RNA_DBG_WARN,
                            "Unable to allocate MD entry\n");
                continue;
            }

            /* Inherit instance-specific MD information */
            mdi->mdi_instance = old_mdi->mdi_instance;
            /*
             * Replace the old md_table entry with the new entry.
             * The old mdi will temporarily become an orphan,
             * findable only through com_get_eph_context, until
             * it is freed by md_disconnected_complete.
             */
            *mdipp = mdi;
            rna_dbg_log(RNA_DBG_MSG,
                        "Replaced old mdi [%p] ordinal [%d] "
                        "with new mdi [%p]\n",
                        old_mdi, mdi->mdi_ordinal, mdi);
        }

        /*
         * Take a reference on the ep, to keep it from being freed if an
         * asynchronous disconnect happens before the return from
         * com_connect_sync() (or at any moment after).
         *
         * We'll refer to this as the com_connect_sync reference.
         */
        com_inc_ref_eph(&eph);  // (no-op at user level)
        /* Tie this ep to this mdi */
        com_set_eph_context(&eph, mdi);
        mdi->mdi_eph = eph;
        /*
         * Take a reference for the eph stored in the mdi.  This reference
         * will be released by md_disconnected_complete().
         *
         * We'll refer to this as the mdi_eph reference.
         */
        com_inc_ref_eph(&eph);  // (no-op at user level)

        rna_dbg_log(RNA_DBG_MSG,
                    "attempting com_connect to metadata server [%d] "
                    "["rna_service_id_format"] via ["RNA_ADDR_FORMAT"/%d] "
                    "[%s]\n",
                    mdi->mdi_ordinal,
                    rna_service_id_get_string(&mdi->mdi_service_id),
                    RNA_ADDR(addr.sin_addr),
                    addr.sin_port,
                    com_get_transport_type_string(md_if->type));

        /* This test races with this flag being set in
         * rna_service_ctx_destroy().  There is no way to completely
         * eliminate the timing window with a simple fix. Best we can do
         * for now is to make that window narrower.
         *
         * See MVP-6617 about fully resolving this race.
         */
        if (ctx->cx_flags & CX_FLAG_SHUTTING_DOWN) {
            /* This ctx is in the process of shutting down; don't reconnect */
            com_release_eph(&eph);  /* com_connect_sync reference */
            com_set_eph_context(&eph, NULL);
            com_init_eph(&mdi->mdi_eph);
            com_release_eph(&eph);  /* mdi_eph reference */
            com_release_eph(&eph);  /* primary reference */
            return (-1);
        }

        /* Drop the cx_md_mutex before waiting for the connect */
        rna_service_mutex_unlock(&ctx->cx_md_mutex);

        ret = rna_service_com_connect_sync(&eph,
                                           (struct sockaddr *)&addr,
                                           MD_CONNECT_WAIT_SEC);

        /* Re-acquire the cx_md_mutex we dropped above */
        if (!rna_service_mutex_lock(&ctx->cx_md_mutex)) {
            /*
             * This failure means we're in the process of shutting down.
             */
            com_release_eph(&eph);     /* com_connect_sync reference */
            if (0 != ret) {
                /* The connect attempt failed */
                if (!com_eph_isempty(&mdi->mdi_eph)) {
                    com_set_eph_context(&mdi->mdi_eph, NULL);
                    com_release_eph(&mdi->mdi_eph);  /* mdi_eph reference */
                    com_init_eph(&mdi->mdi_eph);
                }
                /*
                 * We need to release the primary reference in this case,
                 * since the disconnect_callback() wasn't invoked.
                 *
                 * The primary reference was acquired in com_alloc_ep.
                 */
                com_release_eph(&eph); /* primary reference */
            }
            return (-1);
        }

        if (0 == ret) {
            /*
             * Connect succeeded.  Make sure, though, that the MD wasn't
             * expelled while the cx_md_mutex wasn't held
             */
            if (*mdipp != mdi) {
                /*
                 * The MD was expelled.  If it's connected, drop this now
                 * unneeded connection.
                 *
                 * NOTE that it's possible the mdi has been freed, so it's no
                 * longer safe to dereference it.
                 */
                rna_dbg_log(RNA_DBG_MSG,
                            "MD ["RNA_ADDR_FORMAT"] "
                            "expelled while reconnect was in progress. "
                            "Dropping connection.\n",
                            RNA_ADDR(addr.sin_addr));
                rna_service_com_disconnect(&eph);
                /*
                 * Since it's expelled, we're finished trying to connect to
                 * this MD.
                 */
                break;
            }

            if (rna_service_com_connected(&eph)) {
                mdi->mdi_cflags |= MD_INFO_CFLAG_CONNECTED;
                rna_dbg_log(RNA_DBG_MSG,
                            "connected to MD ["RNA_ADDR_FORMAT"] "
                            "["rna_service_id_format"] "
                            "ordinal [%d] ep [%p]\n",
                            RNA_ADDR(mdi->mdi_eph.eph_dst_in.sin_addr),
                            rna_service_id_get_string(&mdi->mdi_service_id),
                            mdi->mdi_ordinal, com_get_ep_ptr(&eph));
                /*
                 * Complete connect processing.
                 * (NOTE that the cx_md_mutex may be dropped and reacquired
                 * by md_connected()).
                 */
                if (-1 == md_connected(ctx, mdi, FALSE)) {
                    /* Shutdown in progress, cx_md_mutex no longer held */
                    com_release_eph(&eph);  /* com_connect_sync reference */
                    com_release_eph(&eph);  /* mdi_eph reference */
                    return (-1);
                }
            } else {
                /* The connection has already disconnected.  Try again. */
                rna_dbg_log(RNA_DBG_MSG,
                            "unable to com_connect to metadata server [%d]"
                            " ["rna_service_id_format"] via"
                            " ["RNA_ADDR_FORMAT"/%d] [%s] ep [%p]\n",
                            mdi->mdi_ordinal,
                            rna_service_id_get_string(&mdi->mdi_service_id),
                            RNA_ADDR(addr.sin_addr),
                            addr.sin_port,
                            com_get_transport_type_string(md_if->type),
                            com_get_ep_ptr(&eph));
            }
            com_release_eph(&eph);  /* com_connect_sync reference */
        } else {
            /* connect failed */
            rna_dbg_log(RNA_DBG_MSG,
                        "failed com_connect to metadata server [%d] "
                        "["rna_service_id_format"] via ["RNA_ADDR_FORMAT"/%d] "
                        "[%s] ep [%p]\n",
                        mdi->mdi_ordinal,
                        rna_service_id_get_string(&mdi->mdi_service_id),
                        RNA_ADDR(addr.sin_addr),
                        addr.sin_port,
                        com_get_transport_type_string(md_if->type),
                        com_get_ep_ptr(&eph));
            com_release_eph(&eph);  /* com_connect_sync reference */

            if (!com_eph_isempty(&mdi->mdi_eph)) {
                com_set_eph_context(&mdi->mdi_eph, NULL);
                com_release_eph(&mdi->mdi_eph); /* mdi_eph reference */
                com_init_eph(&mdi->mdi_eph);
                /*
                 * We need to release the primary reference in this case,
                 * since the disconnect_callback() wasn't invoked.
                 *
                 * The primary reference was acquired in com_alloc_ep.
                 */
                com_release_eph(&eph);          /* primary reference */
            }

            mdi->mdi_cflags |= MD_INFO_CFLAG_CONNECTION_FAILED;
            mdi->mdi_iflags |= MD_INFO_IFLAG_MUST_SEND_MD_CONNECTION_INFO;
            ctx->cx_md_flags |= CTX_MD_FLAG_MUST_SEND_MD_CONNECTION_INFO;

            if (*mdipp != mdi) {
                /*
                 * The MD was expelled while the cx_md_mutex wasn't held.
                 * Since the connect failed, the disconnect callback won't be
                 * invoked, and since the MD has been expelled, the mdi won't
                 * be used for a later re-connect attempt.  Since it's
                 * therefore now an orphan, free it.
                 */
                free_mdi(ctx, mdi);
                /*
                 * Since it's expelled, we're finished trying to connect to
                 * this MD.
                 */
                break;
            }
        }
    }
    return (0);
}

/**
 * Invoked by a workq thread to connect to any MDs we don't currently have
 * connections with.
 */
static rna_service_workq_cb_ret_t
reconnect_mds(rna_service_workq_cb_arg_t workq_context)
{
    send_waiting_msgs_work_ctx_t
                       *wctx = (send_waiting_msgs_work_ctx_t *)workq_context;
    rna_service_ctx_t  *ctx;
    md_info_t         **mdipp;
    int                 i;
    boolean             reschedule = FALSE;

    rna_service_assert(NULL != wctx);
    rna_service_assert(NULL != wctx->swx_ctx);

    ctx = wctx->swx_ctx;

    if (!rna_service_mutex_lock(&ctx->cx_md_mutex)) {
        // This failure means we're in the process of shutting down; do nothing
        ctx->cx_md_flags &= ~CTX_MD_FLAG_RECONNECT_SCHEDULED;
        goto rm_shutdown_in_progress;
    }

    rna_dbg_log(RNA_DBG_INFO, "Attempting to connect to all MDs\n");
    do {
        if (NULL == ctx->cx_md_table_first) {
            /* We don't have any MD information yet, try again later */
            reschedule = TRUE;
            break;
        }

        ctx->cx_md_flags &= ~CTX_MD_FLAG_RECONNECT_RESTART;
        if (RNA_SERVICE_USER_TYPE_CACHE_SERVER ==
                                            ctx->cx_params.rsp_user_type) {
            /*
             * Since this this a cache server, try to connect to all the
             * MDs.  It's necessary to do this, since the CFM will activate
             * only the MDs that have connections to all the CSs, and will
             * assign partition to only the MDs that are activated.
             *
             * Mark all the MD entries, so we try to connect to them all.
             */
            for (mdipp = ctx->cx_md_table_first;
                 mdipp <= ctx->cx_md_table_last;
                 mdipp++) {

                if (*mdipp != NULL) {
                    (*mdipp)->mdi_cflags |= MD_INFO_CFLAG_CONNECTION_MARKED;
                }
            }
        } else {
            /*
             * Since this isn't a cache server (and therefore doesn't have
             * the above chicken-and-egg issue with MD connections and
             * partition assignments), connect to only the MDs that have
             * partitions assigned to them.
             *
             * Check if there are any MDs that have hash partitions
             * assigned to them but are disconnected, and if so, attempt
             * to reconnect.
             *
             * Start by un-marking all MD entries.
             */
            for (mdipp = ctx->cx_md_table_first;
                 mdipp <= ctx->cx_md_table_last;
                 mdipp++) {

                if (*mdipp != NULL) {
                    (*mdipp)->mdi_cflags &= ~MD_INFO_CFLAG_CONNECTION_MARKED;
                }
            }
            /* Mark entries of MDs that have partitions assigned to them */
            for (i = ctx->cx_partition_map.pm_num_hash_partitions - 1;
                 i >= 0;
                 --i) {

                mdipp = &ctx->cx_md_table[
                        ctx->cx_partition_map.pm_partition_assignments[i]];
                if (*mdipp != NULL) {
                    (*mdipp)->mdi_cflags |= MD_INFO_CFLAG_CONNECTION_MARKED;
                }
            }
        }
        /*
         * Try to reconnect to any MDs that are marked but are currently
         * not connected and that don't already have a reconnect in progress.
         * (Note that another thread may be executing this function
         * concurrently, and the cx_md_mutex is dropped and re-acquired by
         * connect_md, so without this last check, concurrent connection
         * attempts to the same MD would be possible).
         */
        for (mdipp = ctx->cx_md_table_first;
             mdipp <= ctx->cx_md_table_last;
             mdipp++) {

            if ((NULL != *mdipp)
              && (!((*mdipp)->mdi_iflags & MD_INFO_IFLAG_CONNECTING))
              && (((*mdipp)->mdi_cflags &
                  (MD_INFO_CFLAG_CONNECTION_MARKED | MD_INFO_CFLAG_CONNECTED))
                                         == MD_INFO_CFLAG_CONNECTION_MARKED)) {
                /*
                 * MD is marked but not connected and not in the process of
                 * connecting -- try to reconnect.
                 *
                 * Mark the mdi as having a connect in progress, so it doesn't
                 * get freed while the cx_md_mutex isn't held in the connect_md
                 * call.
                 */
                (*mdipp)->mdi_iflags |= MD_INFO_IFLAG_CONNECTING;

                /*
                 * NOTE that the cx_md_mutex may be dropped and re-acquired
                 * by connect_md() and its callees.  During this time, a lot
                 * can potentialy happen, including replacing the mdi entry
                 * at *mdipp with a new entry (see connect_md).  To avoid being
                 * confused by such a swith, this function continues to refer
                 * to the entry of interest as *mdipp.
                 */
                if (-1 == connect_md(ctx, mdipp)) {
                    /* Shutdown in progress, cx_md_mutex no longer held */
                    goto rm_shutdown_in_progress;
                }

                /*
                 * It's possible the MD was expelled while the cx_md_mutex
                 * wasn't held in connect_md.
                 */
                if (NULL == *mdipp) {
                    /* Continue with the next MD in the md_table. */
                    continue;
                }

                (*mdipp)->mdi_iflags &= ~MD_INFO_IFLAG_CONNECTING;

                /* Check again after a bit to make sure we succeeded */
                reschedule = TRUE;
            }
            /*
             * If another thread has indicated that an MD has changed its
             * connected state, restart at the beginning.
             */
            if (ctx->cx_md_flags & CTX_MD_FLAG_RECONNECT_RESTART) {
                break;
            }
        }
    } while (ctx->cx_md_flags & CTX_MD_FLAG_RECONNECT_RESTART);

    if (reschedule) {
        /*
         * Schedule an attempt to reconnect with any MDs we've failed to
         * connect with.
         *
         * (Note that because the cx_md_mutex is held, we know this ctx isn't
         * being shut down (see rna_service_ctx_destroy()), so it's safe to
         * call rna_service_timer_set() -- specifically, we know the timer
         * cancellation phase of the shutdown hasn't yet been executed, so
         * we won't be leaving a set timer after shutdown).
         */
        rna_dbg_log(RNA_DBG_INFO, 
                    "will retry MD connections in [%ld] seconds\n",
                    RNA_SERVICE_RECONNECT_INTERVAL);
        rna_service_timer_cancel(&ctx->cx_reconnect_mds_timer_object);
        rna_service_timer_set(ctx->cx_private,
                             &ctx->cx_reconnect_mds_timer_object,
                              reconnect_mds_to,
                              (uint64_t)ctx,
                              (int)RNA_SERVICE_RECONNECT_INTERVAL);
    }

    ctx->cx_md_flags &= ~CTX_MD_FLAG_RECONNECT_SCHEDULED;
    rna_service_mutex_unlock(&ctx->cx_md_mutex);

rm_shutdown_in_progress:
    rna_service_free(sizeof(*wctx), wctx);

    /*
     * NOTE that rna_service workq callbacks must use
     * RNA_SERVICE_WORKQ_CB_RETURN instead of return.
     */
    RNA_SERVICE_WORKQ_CB_RETURN(0);
}


/*
 * Add a call to reconnect_mds to the cx_md_work_queue.
 *
 * The cx_md_mutex must be held on entry.
 */
static void
queue_reconnect_mds(rna_service_ctx_t *ctx)
{
    send_waiting_msgs_work_ctx_t *wctx;

    rna_service_assert_locked(&ctx->cx_md_mutex);

    if (ctx->cx_md_flags & CTX_MD_FLAG_RECONNECT_SCHEDULED) {
        /*
         * reconnect_mds is already scheduled on a workq.  Indicate it should
         * take another turn around its loop, in case it missed an MD state
         * change.
         */
        rna_trace("reconnect_mds already running\n");
        ctx->cx_md_flags |= CTX_MD_FLAG_RECONNECT_RESTART;
    } else {
        rna_trace("queuing reconnect_mds\n");
        ctx->cx_md_flags |= CTX_MD_FLAG_RECONNECT_RESTART;
        wctx = rna_service_alloc0(sizeof(*wctx));
        if (NULL == wctx) {
            rna_dbg_log(RNA_DBG_WARN,
                        "unable to allocate memory, so unable to "
                        "connect to CFM\n");
            return;
        }

        ctx->cx_md_flags |= CTX_MD_FLAG_RECONNECT_SCHEDULED;

        /*
         * If a delayed request to queue reconnect_mds has been set, cancel it,
         * since we're queuing it now.
         */
        rna_service_timer_cancel(&ctx->cx_reconnect_mds_timer_object);

        wctx->swx_ctx = ctx;
        RNA_SERVICE_WORK_INIT(&wctx->swx_work_obj,
                              reconnect_mds,
                              (rna_service_workq_cb_arg_t)wctx);
        (void) rna_service_workq_add(ctx->cx_md_work_queue,
                                     &wctx->swx_work_obj);
    }
}


/**
 * An rna_service_timer function that's invoked to attempt to connect to any
 * MDs we don't currently have connections with.
 */
static void
reconnect_mds_to(uint64_t context)
{
    rna_service_ctx_t  *ctx = (rna_service_ctx_t *) context;

    rna_service_assert(NULL != ctx);

    if (!rna_service_mutex_lock(&ctx->cx_md_mutex)) {
        /* This failure means we're in the process of shutting down */
        return;
    }

    queue_reconnect_mds(ctx);

    rna_service_mutex_unlock(&ctx->cx_md_mutex);
}


/*
 * Send our copy of the map of MD-to-partition assignments to an MD that has
 * an obsolete version.
 *
 * Locking:
 *    The ctx->cx_md_mutex must be held on entry.  This mutex may be dropped
 *    and re-acquired by this function.
 *
 * Returns:
 *    0    on success
 *   -1    failed, try again
 *   -2    failed, don't try again
 *   -3    shutdown is in progress, no mutexes are held
 */
static int
send_partition_map(rna_service_ctx_t *ctx, md_info_t *mdi)
{
    int                           ret;
    int                           ordinal;
    com_ep_handle_t               eph;
    rna_service_send_buf_entry_t *send_buf;
    struct cfm_cmd               *cmd;

    rna_service_assert(NULL != ctx);
    rna_service_assert(NULL != mdi);
    rna_service_assert_locked(&ctx->cx_md_mutex);

    ordinal = mdi->mdi_ordinal;
    rna_service_assert(ordinal < NUM_MD_ORDINALS);

    if (0 == ctx->cx_partition_map.pm_generation) {
        /* We haven't yet received a partition map from the CFM */
        rna_dbg_log(RNA_DBG_ERR,
                    "Called before initial partition map received\n");
        ret = -2;   /* don't retry until partition map arrives */
        goto done;
    }

    /*
     * Don't hold cx_md_mutex across a blocking operation
     */
    eph = mdi->mdi_eph; // save eph in case mdi disappears while mutex not held
    rna_service_mutex_unlock(&ctx->cx_md_mutex);

    ret = rna_service_com_get_send_buf(&eph, &send_buf, TRUE, NULL);
    if (!rna_service_mutex_lock(&ctx->cx_md_mutex)) {
        ret = -3;   /* don't retry, we're in the process of shutting down */
        goto done;
    }
    /*
     * Make sure nothing happened to the mdi or MD connection while we
     * didn't hold the mutex
     */
    if ((ctx->cx_md_table[ordinal] != mdi)
      || (!com_eph_equal(&mdi->mdi_eph, &eph))) {
        if (send_buf != NULL) {
            rna_service_com_put_send_buf(&eph, send_buf);
        }
        ret = -1;   /* try again with new mdi */
        goto done;
    }
    if ((NULL == send_buf) || (0 != ret)) {
        if (rna_service_com_connected(&eph)) {
            /* This should never happen! */
            rna_dbg_log(RNA_DBG_ERR,
                        "Failed to get send buffer after blocking!\n");
        }
        schedule_waiting_md_msgs(ctx, mdi, SEND_WAITING_MD_MSGS_DELAY_SEC);
        ret = -2;   /* don't retry immediately, rescheduled for later */
        goto done;
    }

#if defined(LINUX_KERNEL) || defined(WINDOWS_KERNEL)
    cmd = (struct cfm_cmd *)(com_get_send_buf_mem(send_buf));
#else
    cmd = (struct cfm_cmd *) send_buf->mem;
#endif
    cmd->h.h_type = CONF_MGR_MD_PARTITION_MAP;
    cmd->u.cfm_md_partition_map = ctx->cx_partition_map;

    ret = rna_service_com_send_cfm_cmd(&eph,
                                       send_buf,
                                       cfm_cmd_length(cmd),
                                       &ctx->cx_primary_cfm_id);
    if (ret != 0) {
        rna_dbg_log(RNA_DBG_WARN,"Send failed: %d\n", ret);
        schedule_waiting_md_msgs(ctx, mdi, SEND_WAITING_MD_MSGS_DELAY_SEC);
        ret = -2;    /* don't retry immediately, rescheduled for later */
        goto done;
    }

    mdi->mdi_partition_map_generation_sent = 
                                        ctx->cx_partition_map.pm_generation;

 done:
    return (ret);
}


/**
 * Invoked by a workq thread to send queued messages to a metadata server.
 * The messages were queued either because a connection to the MD hadn't yet
 * been established, or because a send attempt failed (either because a sendbuf
 * allocation failed or because the send itself failed).
 */
static rna_service_workq_cb_ret_t
send_waiting_md_msgs(rna_service_workq_cb_arg_t workq_context)
{
    send_waiting_msgs_work_ctx_t *wctx =
                                 (send_waiting_msgs_work_ctx_t *)workq_context;
    rna_service_ctx_t            *ctx;
    int                           ordinal;
    rna_service_message_buffer_internal_t *ibuf;
    md_info_t                    *mdi = NULL;
    com_ep_handle_t               md_eph;
    int                           i;
    boolean                       messages_remain;
    int                           ret;

    rna_service_assert(NULL != wctx);
    rna_service_assert(NULL != wctx->swx_ctx);

    com_init_eph(&md_eph);
    ctx = wctx->swx_ctx;

    ordinal = wctx->swx_ordinal;
    rna_service_assert(ordinal < NUM_MD_ORDINALS);

    if (!rna_service_mutex_lock(&ctx->cx_md_mutex)) {
        /* This failure means we're in the process of shutting down */
        goto done_nolock;
    }

    if (0 == ctx->cx_partition_map.pm_generation) {
        /* We haven't yet received a partition map from the CFM */
        rna_dbg_log(RNA_DBG_ERR,
                    "Called before initial partition map received!\n");
        goto done;
    }

    mdi = NULL;
    do {
        rna_service_assert_locked(&ctx->cx_md_mutex);
        messages_remain = TRUE;

        /*
         * If an ep reference was taken on the last iteration of the loop,
         * release it now.  (ep references are no-ops at user level).
         */
        if (!com_eph_isempty(&md_eph)) {
            com_release_eph(&md_eph);   // (no-op at user level)
            com_init_eph(&md_eph);
        }

        /*
         * If the previous iteration of the loop was working with a different
         * mdi than we'll be working with in this iteration, indicate that
         * send_waiting_md_msgs is no longer scheduled for that mdi.
         */
        if ((mdi != NULL)
          && (mdi != ctx->cx_md_table[ordinal])) {
            mdi->mdi_iflags &= ~MD_INFO_IFLAG_SEND_WAITING_MSGS_SCHEDULED;
        }

        mdi = ctx->cx_md_table[ordinal];
        if ((NULL == mdi)
          || (!(mdi->mdi_cflags & MD_INFO_CFLAG_CONNECTED))
          || (!rna_service_com_connected(&mdi->mdi_eph))) {
            /*
             * There's nothing to do now.  This routine will be rescheduled
             * if/when we reconnect to this md.
             */
            break;
        }

        md_eph = mdi->mdi_eph;
        com_inc_ref_eph(&md_eph);   // (no-op at user level)

        /*
         * If the user is a cache server and it hasn't yet registered with one
         * or more MDs, try to do so now.
         */
        if (RNA_SERVICE_USER_TYPE_CACHE_SERVER == ctx->cx_params.rsp_user_type)
        {
            if (mdi->mdi_cflags & MD_INFO_CFLAG_MUST_REGISTER) {
                /*
                 * Register the CS with the MD.
                 *
                 * (NOTE that the cx_md_mutex may be dropped and reacquired
                 * by md_connected).
                 */
                if (-1 == md_connected(ctx, mdi, TRUE)) {
                    /* Shutdown is in progress, cx_md_mutex is no longer held */
                    goto done_nolock;
                } else if ((ctx->cx_md_table[ordinal] != mdi)
                  || (!com_eph_equal(&mdi->mdi_eph, &md_eph))
                  || (mdi->mdi_cflags & MD_INFO_CFLAG_MUST_REGISTER)) {
                    /*
                     * The mdi changed while we didn't hold the cx_md_mutex,
                     * or the send failed in md_connected, and we still need
                     * to register.  Restart.
                     */
                    continue;
                }
                mdi->mdi_cflags &= ~MD_INFO_CFLAG_MUST_REGISTER;
                mdi->mdi_cflags |= MD_INFO_CFLAG_AWAIT_REGISTRATION_RESPONSE;
            }

            /*
             * If we're waiting for a registration response from this MD,
             * don't send any other messages until it arrives.  We want to
             * avoid sending stale messages if this CS has been expelled
             * (i.e. if the registration is rejected).
             */
            if (mdi->mdi_cflags & MD_INFO_CFLAG_AWAIT_REGISTRATION_RESPONSE) {
                goto done;
            }
        }

        /*
         * If we haven't yet sent this MD the latest partition map, do so now.
         * We want to assure the MD isn't working with a stale partition map
         * before sending it messages that may depend on the new partition
         * assignments.
         */
        if (mdi->mdi_partition_map_generation_sent < 
                                        ctx->cx_partition_map.pm_generation) {
            /*
             * Send the partition map.
             *
             * (NOTE that the cx_md_mutex may be dropped and reacquired by
             * send_partition_map).
             */
            ret = send_partition_map(ctx, mdi);
            if (-1 == ret) {
                /*
                 * The mdi changed while we didn't hold the cx_md_mutex,
                 * try again.
                 */
                continue;
            } else if (-2 == ret) {
                /* This callback has been rescheduled to try again later. */
                goto done;
            } else if (-3 == ret) {
                /*
                 * This failure means that we no longer hold the cx_md_mutex,
                 * because we're in the process of shutting down.
                 */
                goto done_nolock;
            }
        }

        rna_service_assert(mdi->mdi_partition_map_generation_sent ==
                           ctx->cx_partition_map.pm_generation);

        /*
         * If any messages for any of the hash partitions assigned to this MD
         * are waiting to be sent, try to send them.
         *
         * To avoid starving partitions, we iterate through the partitions,
         * sending one from each that has messages waiting on each iteration.
         */
        messages_remain = FALSE;
        for (i = ctx->cx_partition_map.pm_num_hash_partitions - 1; i >= 0; --i)
        {

            /* Skip this partition if it's not assigned to this MD */
            if (ctx->cx_partition_map.pm_partition_assignments[i] != ordinal) {
                continue;
            }
            /*  If this partition has messages waiting to be sent, send one */
            if (!YAQ_EMPTY(&ctx->cx_partitions[i].pi_waiting_to_send)) {
                messages_remain = TRUE;
                ibuf = YAQ_OBJECT(rna_service_message_buffer_internal_t,
                                  h.rmbi_link,
                                  YAQ_FIRST(&ctx->cx_partitions[i].
                                                        pi_waiting_to_send));
                YAQ_REMOVE(&ibuf->h.rmbi_link);

                /* must drop the cx_md_mutex before calling send_md_generic() */
                rna_service_mutex_unlock(&ctx->cx_md_mutex);

                (void) send_md_generic(ctx,
                                       ibuf,
                                       SEND_MD_GENERIC_FLAG_RESEND |
                                             SEND_MD_GENERIC_FLAG_BLOCKING_OK |
                                             SEND_MD_GENERIC_FLAG_FORCE);

                if (!rna_service_mutex_lock(&ctx->cx_md_mutex)) {
                    /*
                     * This failure means we're in the process of shutting
                     * down; bail out.
                     */
                    goto done_nolock;
                }
                /*
                 * Make sure nothing happened to the mdi or MD connection
                 * while we didn't hold the mutex
                 */
                if ((ctx->cx_md_table[ordinal] != mdi)
                  || (!com_eph_equal(&mdi->mdi_eph, &md_eph))
                  || (!(mdi->mdi_cflags & MD_INFO_CFLAG_CONNECTED))
                  || (!rna_service_com_connected(&md_eph))) {
                    /* Do another iteration of the outer loop */
                    break;
                }

                /*
                 * Quit sending if the 'must register' flag was turned on or
                 * a new partition map arrived while we didn't hold the mutex.
                 */
                if ((mdi->mdi_cflags & MD_INFO_CFLAG_MUST_REGISTER)
                  || (mdi->mdi_partition_map_generation_sent < 
                                        ctx->cx_partition_map.pm_generation)) {
                    /* Do another iteration of the outer loop */
                    break;
                }
            }
        }
    } while (messages_remain);

 done:
    if (mdi != NULL) {
        mdi->mdi_iflags &= ~MD_INFO_IFLAG_SEND_WAITING_MSGS_SCHEDULED;
    }
    rna_service_mutex_unlock(&ctx->cx_md_mutex);

 done_nolock:
    if (!com_eph_isempty(&md_eph)) {
        com_release_eph(&md_eph);   // (no-op at user level)
    }

    /*
     * Release the ctx reference that was added when this routine was scheduled
     * to run.
     */
    ctx_release_reference(&ctx);

    rna_service_free(sizeof(*wctx), wctx);

    /*
     * NOTE that rna_service workq callbacks must use
     * RNA_SERVICE_WORKQ_CB_RETURN instead of return.
     */
    RNA_SERVICE_WORKQ_CB_RETURN(0);
}


/**
 * This function is used by metadata users only
 * (RNA_SERVICE_USER_TYPE_METADATA_SERVER) to process a CONF_MGR_CONN_REG from
 * the configuration manager, which indicates that the specified cache server
 * is now activated.
 */
static int
md_process_cs_activation(rna_service_ctx_t *ctx,
                         com_ep_handle_t   *eph,
                         struct cfm_cmd    *cmd) 
{
    UNREFERENCED_PARAMETER(ctx);
    UNREFERENCED_PARAMETER(eph);
    UNREFERENCED_PARAMETER(cmd);

    // ZZZZ RNA_SERVICE_USER_TYPE_METADATA_SERVER users are not yet supported
    return (EINVAL);
}


/**
 * This function is used by metadata users only
 * (RNA_SERVICE_USER_TYPE_METADATA_SERVER) to process a CONF_MGR_CONN_REG from
 * the configuration manager, which indicates that the specified metadata
 * server is now activated.
 */
static int
md_process_md_activation(rna_service_ctx_t *ctx,
                         com_ep_handle_t   *eph,
                         struct cfm_cmd    *cmd) 
{
    UNREFERENCED_PARAMETER(ctx);
    UNREFERENCED_PARAMETER(eph);
    UNREFERENCED_PARAMETER(cmd);

    // ZZZZ RNA_SERVICE_USER_TYPE_METADATA_SERVER users are not yet supported
    return (EINVAL);
}


/* ---------------------------- Cache Servers ------------------------------ */

/**
 * This function is used by cache server users only
 * (RNA_SERVICE_USER_TYPE_CACHE_SERVER) to process a CONF_MGR_CONN_REG from
 * the configuration manager, which indicates that the specified metadata
 * server is now activated.
 */
static int
cs_process_md_activation(rna_service_ctx_t *ctx,
                         com_ep_handle_t   *eph,
                         struct cfm_cmd    *cmd) 
{
    int        ret = -1;
    md_info_t *mdi;

    UNREFERENCED_PARAMETER(eph);

    rna_service_assert(cmd->u.cfm_service_reg.csr_md_ordinal < NUM_MD_ORDINALS);
    if (!rna_service_mutex_lock(&ctx->cx_md_mutex)) {
        // This failure means we're in the process of shutting down; do nothing
        return (0);
    }
    rna_dbg_log(RNA_DBG_MSG,
                "MD ["rna_service_id_format"] activated\n",
                rna_service_id_get_string(&cmd->u.cfm_service_reg.service_id));

    mdi = ctx->cx_md_table[cmd->u.cfm_service_reg.csr_md_ordinal];
    if ((NULL != mdi)
      && (rna_service_com_connected(&mdi->mdi_eph))) {

        if (!(mdi->mdi_iflags & MD_INFO_IFLAG_ACTIVATED)) {
            /* this MD has just been activated by the CFM, set its flag */
            rna_dbg_log(RNA_DBG_MSG,
                        "MD ["rna_service_id_format"] activated\n",
                        rna_service_id_get_string(
                                            &cmd->u.cfm_service_reg.service_id));
            mdi->mdi_iflags |= MD_INFO_IFLAG_ACTIVATED;
        }
        ret = 0;
#ifdef _RNA_DBG_
        if (!match_rna_service_id(&mdi->mdi_service_id,
                                  &cmd->u.cfm_service_reg.service_id,
                                   FALSE /* disregard timestamp */)) {
            rna_dbg_log(RNA_DBG_ERR,
                        "[%d] service ID mismatch ["rna_service_id_format"] ["rna_service_id_format"]\n",
                        cmd->u.cfm_service_reg.csr_md_ordinal,
                        rna_service_id_get_string(&mdi->mdi_service_id),
                        rna_service_id_get_string(
                                            &cmd->u.cfm_service_reg.service_id));
        }
#endif
    }
    if (ret) {
        rna_dbg_log(RNA_DBG_MSG,
                    "Not yet connected to MD["rna_service_id_format"]\n",
                    rna_service_id_get_string(
                                        &cmd->u.cfm_service_reg.service_id));
    }
    rna_service_mutex_unlock(&ctx->cx_md_mutex);

    return ret;
}


/**
 * Process a CONF_MGR_DISCONN_REG message from the configuration manager,
 * which indicates that the specified metadata server has been expelled.
 */
static int
process_cfm_expel_md(rna_service_ctx_t *ctx,
                     com_ep_handle_t   *cfm_eph,
                     struct cfm_cmd    *cmd)
{
    UNREFERENCED_PARAMETER(ctx);
    UNREFERENCED_PARAMETER(cfm_eph);
    UNREFERENCED_PARAMETER(cmd);

    rna_dbg_log(RNA_DBG_MSG,
                "CFM warned that MD ["rna_service_id_format"] "
                "ordinal [%u] "
                "has been expelled from the cluster\n",
                rna_service_id_get_string(&cmd->u.cfm_service_reg.service_id),
                cmd->u.cfm_service_reg.csr_md_ordinal);
    if (!rna_service_mutex_lock(&ctx->cx_md_mutex)) {
        /* This failure means we're in the process of shutting down */
        return (RNA_SERVICE_ERROR_NONE);
    }
    remove_md_table_entry(ctx, cmd->u.cfm_service_reg.csr_md_ordinal);
    rna_service_mutex_unlock(&ctx->cx_md_mutex);
    return (0);
}


/*
 * An rna_service_timer function that's invoked periodically to ping metadata
 * servers.  This function is used by cache server users only
 * (RNA_SERVICE_USER_TYPE_CACHE_SERVER).
 */
static void
ping_mds_timer(uint64_t context)
{
    rna_service_ctx_t *ctx = (rna_service_ctx_t *) context;

    rna_service_assert(ctx != NULL);
    /*
     * (All returns from rna_service_workq_add are considered
     * successful from the perspective of this routine).
     */
    (void) rna_service_workq_add(ctx->cx_md_work_queue,
                                &ctx->cx_ping_mds_work_object);
}

/*
 * Function used for Cache Servers to ping the MD's.
 */
static void
cs_ping_mds(rna_service_ctx_t *ctx, md_info_t *mdip)
{
    int ret;

    if (rna_service_md_has_remote_ping_rkey(&mdip->mdi_remote_ping_ctx)) {
        rna_dbg_log(RNA_DBG_VERBOSE, 
                   "Pinging MD server "
                   "[" RNA_ADDR_FORMAT "].\n",
                   RNA_ADDR (mdip->mdi_eph.eph_dst_in.sin_addr));

        ret = rna_service_ping_rdma(&mdip->mdi_remote_ping_ctx);

        if (0 != ret) {
            rna_dbg_log(RNA_DBG_WARN, 
                       "Failed to send ping to MD server "
                       "[" RNA_ADDR_FORMAT "].  Disconnecting\n",
                       RNA_ADDR(mdip->mdi_eph.eph_dst_in.sin_addr));
            rna_service_com_disconnect(&mdip->mdi_eph);
            /*
             * It may take a long time for the disconnect_callback to be
             * invoked for this MD connection.  To minimize the delay for
             * MD messages, do preliminary disconnect processing now and
             * immediately start trying to reconnect to it.
             */
            md_disconnected(ctx, mdip);

             /*
              * Complain to the primary CFM immediately about the problem,
              * rather than wait for the disconnect callback to be invoked.
              * If the MD is dead, we want to trigger its expel as soon as
              * possible.
              */
            ret = rna_service_send_service_disconnection_info(
                                                 &ctx->cx_primary_cfm_eph,
                                                 &mdip->mdi_service_id,
                                                 mdip->mdi_ordinal,
                                                 0);
            if (ret != 0) {
                /* send failed, we'll need to retry later */
                mdip->mdi_cflags |= MD_INFO_CFLAG_CONNECTION_FAILED;
                mdip->mdi_iflags |= MD_INFO_IFLAG_MUST_SEND_MD_CONNECTION_INFO;
                ctx->cx_md_flags |= CTX_MD_FLAG_MUST_SEND_MD_CONNECTION_INFO;
            }
        }
    }
    return;
}

/*
 * Function used for Clients to ping the MD's.
 */
static void
client_ping_mds(rna_service_ctx_t *ctx, md_info_t *mdip)
{
    rna_service_send_buf_entry_t *buf;
    struct cache_cmd *cmd;
    int ret;

    UNREFERENCED_PARAMETER(ctx);

    ret = rna_service_com_get_send_buf(&mdip->mdi_eph, &buf, FALSE, NULL);
    if (0 != ret || NULL == buf) {
        rna_dbg_log(RNA_DBG_VERBOSE, "get buf error eph [%p] ret=%d\n",
                    &mdip->mdi_eph, ret);
        return;
    }

    cmd = (struct cache_cmd *)buf->mem;
    memset(&cmd->h, 0, sizeof(cmd->h));
    cmd->h.h_type = MD_CLIENT_PING;

    ret = rna_service_com_send(&mdip->mdi_eph, buf,
                               (int)cache_cmd_length(cmd));
    if (0 != ret) {
        rna_dbg_log(RNA_DBG_VERBOSE, "com_send eph [%p] ret=%d\n",
                    &mdip->mdi_eph, ret);
    }
    return;
}

/*
 * An work queue function that's invoked periodically to ping metadata
 * servers.  This function is used by cache servers and clients.
 */
static rna_service_workq_cb_ret_t
ping_mds(rna_service_workq_cb_arg_t workq_context)
{
#ifdef LINUX_KERNEL
    rna_service_ctx_t *ctx = container_of(workq_context, rna_service_ctx_t,
                                          cx_ping_mds_work_object);
#else /* !LINUX_KERNEL */
    rna_service_ctx_t *ctx = (rna_service_ctx_t *) workq_context;
#endif /* !LINUX_KERNEL */
    int                num_mds_to_ping;
    int                ping_interval;
    static md_info_t **mdipp = NULL;  // NOTE that this is declared static

    rna_service_assert(NULL != ctx);
    if (!rna_service_mutex_lock(&ctx->cx_md_mutex)) {
        /* This failure means we're in the process of shutting down. */
        goto pm_done;
    }

    if (ctx->cx_flags & CX_FLAG_SHUTTING_DOWN) {
        /* We're shutting down; bail out. */
        rna_service_mutex_unlock(&ctx->cx_md_mutex);
        goto pm_done;
    }

    /*
     * Figure out how many MDs to ping on this iteration, and how long to wait
     * until the next iteration.
     */
    if (ctx->cx_num_mds > 0) {
        rna_service_assert(ctx->cx_md_table_first != NULL);
        ping_interval = ctx->cx_params.rsp_md_ping_rate / ctx->cx_num_mds;
        if (0 == ping_interval) {
            ping_interval = 1;
            num_mds_to_ping = ctx->cx_num_mds /
                                          ctx->cx_params.rsp_md_ping_rate;
        } else {
            num_mds_to_ping = 1;
        }
    } else {
        ping_interval = ctx->cx_params.rsp_md_ping_rate;
        num_mds_to_ping = 0;
    }

    while (num_mds_to_ping > 0) {
        /*
         * Start with the MD following the MD we pinged last time, unless it's
         * off the end of the md_table.
         */
        if ((mdipp < ctx->cx_md_table_first)
          || (mdipp > ctx->cx_md_table_last)) {
            mdipp = ctx->cx_md_table_first;
        }

        /* Send ping */
        if ((NULL != *mdipp)
          && (rna_service_com_connected(&((*mdipp)->mdi_eph)))
          && (0 == (ctx->cx_flags & CX_FLAG_SHUTTING_DOWN))) {

            switch (ctx->cx_params.rsp_user_type) {
            case RNA_SERVICE_USER_TYPE_CACHE_SERVER:
                cs_ping_mds(ctx, *mdipp);
                break;

            case RNA_SERVICE_USER_TYPE_BLOCK_CLIENT:
                client_ping_mds(ctx, *mdipp);
                break;

            default:
                rna_service_assert(0);
            }
        }

        mdipp++;    // go on to the next MD
        --num_mds_to_ping;
    }
    /*
     * Schedule the next ping.
     *
     * (Note that because the cx_md_mutex is held, we know this ctx isn't
     * being shut down (see rna_service_ctx_destroy()), so it's safe to
     * call rna_service_timer_set() -- specifically, we know the timer
     * phase of the shutdown hasn't yet been executed, so we won't be leaving
     * a set timer after shutdown).
     */
    rna_service_timer_set(ctx->cx_private,
                         &ctx->cx_ping_mds_timer_object,
                          ping_mds_timer,
                          (uint64_t)ctx,
                          ping_interval);
    /*
     * Note that we don't need to add a ctx reference, since we already hold
     * one.  Note also that we wait until after we've set the timer to drop
     * the cx_md_mutex, to assure we don't set the timer after a shutdown has
     * started.
     */
    rna_service_mutex_unlock(&ctx->cx_md_mutex);

 pm_done:
    /*
     * NOTE that rna_service workq callbacks must use
     * RNA_SERVICE_WORKQ_CB_RETURN instead of return.
     */
    RNA_SERVICE_WORKQ_CB_RETURN(0);
}


/* ---------------------- Process Messages Received ------------------------ */

/*
 * Add the specified function to the CFM work queue.  The specified message
 * from the CFM will be handled by a work queue thread.
 */
static int
work_queue_add_cfm(rna_service_ctx_t  *ctx,
                   com_ep_handle_t    *eph,
                   struct cfm_cmd     *cmd,
                   rna_service_work_cb func)
{
    cfm_work_ctx_t *wctx;

    UNREFERENCED_PARAMETER(func);

    rna_service_assert(NULL != ctx);
    rna_service_assert(NULL != eph);

    /*
     * Since *wctx will include a reference to an rna_service_ctx_t, a ctx
     * reference must be taken.  This reference must be released by 'func'.
     */
    if (ctx_add_reference(&ctx)) {
        wctx = (cfm_work_ctx_t *) mempool_alloc(ctx,
                                                MEMPOOL_ID_CFM_WORK_CTX,
                                                0);
        if (NULL == wctx) {
            rna_dbg_log(RNA_DBG_WARN,
                        "Memory allocation failed!\n");
            ctx_release_reference(&ctx);
            return (ENOMEM);
        }

        wctx->cwx_ctx = ctx;
        wctx->cwx_eph = *eph;
        memcpy(&wctx->cwx_cmd, cmd, cfm_cmd_length(cmd));

        /*
         * Take a reference on the endpoint, to keep it from disappearing
         * before this work queue item is scheduled.
         */
        com_inc_ref_eph(&wctx->cwx_eph);    // (no-op at user level)

        RNA_SERVICE_WORK_INIT(&wctx->cwx_work_obj,
                              func,
                              (rna_service_workq_cb_arg_t)wctx);
        /*
         * (All returns from rna_service_workq_add are considered successful
         * from the perspective of this routine).
         */
        (void) rna_service_workq_add(ctx->cx_cfm_work_queue,
                                     &wctx->cwx_work_obj);
    }
    return (0);
}

/*
 * Add the specified function to the CONF_MGR_CONTROL_CS work queue.  The
 * specified message from the CFM will be handled by a work queue thread.
 */
static int
work_queue_add_control_cs(rna_service_ctx_t  *ctx,
                          com_ep_handle_t    *eph,
                          struct cfm_cmd     *cmd,
                          rna_service_work_cb func)
{
    cfm_work_ctx_t *wctx;

    UNREFERENCED_PARAMETER(func);

    rna_service_assert(NULL != ctx);
    rna_service_assert(NULL != eph);

    /*
     * Since *wctx will include a reference to an rna_service_ctx_t, a ctx
     * reference must be taken.  This reference must be released by 'func'.
     */
    if (ctx_add_reference(&ctx)) {
        wctx = (cfm_work_ctx_t *)mempool_alloc(ctx,
                                               MEMPOOL_ID_CFM_WORK_CTX,
                                               0);
        if (NULL == wctx) {
            rna_dbg_log(RNA_DBG_WARN,
                        "Memory allocation failed!\n");
            ctx_release_reference(&ctx);
            return (ENOMEM);
        }

        wctx->cwx_ctx = ctx;
        wctx->cwx_eph = *eph;
        memcpy(&wctx->cwx_cmd, cmd, cfm_cmd_length(cmd));

        /*
         * Take a reference on the endpoint, to keep it from disappearing
         * before this work queue item is scheduled.
         */
        com_inc_ref_eph(&wctx->cwx_eph);    // (no-op at user level)

        RNA_SERVICE_WORK_INIT(&wctx->cwx_work_obj,
                              func,
                              (rna_service_workq_cb_arg_t)wctx);
        /*
         * (All returns from rna_service_workq_add are considered successful
         * from the perspective of this routine).
         */
        (void)rna_service_workq_add(ctx->cx_control_cs_work_queue,
                                    &wctx->cwx_work_obj);
    }
    return (0);
}

/**
 * Invoked by a workq thread to process a CONF_MGR_MD_PARTITION_MAP message
 * (cfm_md_partition_map), which has arrived from either the CFM or an MD to
 * notify us about the current set of mappings between metadata hash partitions
 * and metadata servers.
 */
static rna_service_workq_cb_ret_t
process_partition_map(rna_service_workq_cb_arg_t workq_context)
{
    cfm_work_ctx_t    *wctx = (cfm_work_ctx_t *) workq_context;
    com_ep_handle_t   *eph;
    rna_service_ctx_t *ctx;
    struct cfm_cmd    *cmd;
    int                i;
    boolean            must_resend = FALSE;
    uint64_t           prev_gen;
    md_info_t         *mdi;
    rna_service_message_buffer_internal_t
                      *ibuf;
    rna_service_message_buffer_t
                      *buf;
    int                partition;

    rna_service_assert(NULL != wctx);

    eph = &wctx->cwx_eph;

    ctx = wctx->cwx_ctx;
    rna_service_assert(NULL != ctx);

    cmd = &wctx->cwx_cmd;

    rna_dbg_log(RNA_DBG_INFO,
                "Received MD Partition Map generation [%"PRId64"] "
                "(vs. [%"PRId64"]) from [%s] ["RNA_ADDR_FORMAT"/%d]\n",
                cmd->u.cfm_md_partition_map.pm_generation,
                ctx->cx_partition_map.pm_generation,
                get_user_type_string(eph->eph_user_type),
                RNA_ADDR(eph->eph_dst_in.sin_addr),
                eph->eph_dst_in.sin_port);

    if (!rna_service_mutex_lock(&ctx->cx_md_mutex)) {
        // This failure means we're in the process of shutting down; do nothing
        goto done_nolock;
    }

    /*
     * Ignore this partition map update if it's stale or a duplicate.
     */
    if (cmd->u.cfm_md_partition_map.pm_generation <
                                        ctx->cx_partition_map.pm_generation) {
        /*
         * An obsolete partition map can legitimately be sent if, for example,
         * we've just had our partition map updated.  Possibly if, for example,
         * the MD sent the partition map, it's response was delayed.
         */
        rna_dbg_log(RNA_DBG_INFO,
                    "Received obsolete cfm_md_partition_map "
                    "(generation [%"PRId64"] vs. [%"PRId64"]) "
                    "from [%s] ["RNA_ADDR_FORMAT"/%d], possibly due to a "
                    "race\n",
                    cmd->u.cfm_md_partition_map.pm_generation,
                    ctx->cx_partition_map.pm_generation,
                    get_user_type_string(eph->eph_user_type),
                    RNA_ADDR(eph->eph_dst_in.sin_addr),
                    eph->eph_dst_in.sin_port);
        goto done;
    } else if (cmd->u.cfm_md_partition_map.pm_generation ==
                                        ctx->cx_partition_map.pm_generation) {
        /*
         * This can legitimately happen if, for example, we sent several
         * requests, each of which triggered the send of a partition map.
         */
        rna_dbg_log(RNA_DBG_INFO,
                    "Received redundant cfm_md_partition_map "
                    "(generation [%"PRId64"])"
                    "from [%s] ["RNA_ADDR_FORMAT"/%d]\n",
                    cmd->u.cfm_md_partition_map.pm_generation,
                    get_user_type_string(eph->eph_user_type),
                    RNA_ADDR(eph->eph_dst_in.sin_addr),
                    eph->eph_dst_in.sin_port);
        goto done;
    }

    /*
     * If any partitions have been assigned to new metadata servers, indicate
     * that any messages waiting to be sent or waiting for a response will
     * need to be re-sent to the newly-assigned MDs.
     */
    for (i = cmd->u.cfm_md_partition_map.pm_num_hash_partitions - 1;
         i >= 0;
         --i) {

        if (ctx->cx_partition_map.pm_partition_assignments[i] !=
                    cmd->u.cfm_md_partition_map.pm_partition_assignments[i]) {
            ctx->cx_partitions[i].pi_partition_flags |=
                                                PARTITION_FLAG_SEND_TO_NEW_MD;
            must_resend = TRUE;
        }
    }

    /*
     * Save the new set of partition-to-MD assignments.  (As background, the
     * metadata hash space is divided into equal-sized partitions, each of
     * which is assigned to an MD to service).
     */
    prev_gen = ctx->cx_partition_map.pm_generation;
    ctx->cx_partition_map = cmd->u.cfm_md_partition_map;

    ctx->cx_hash_partition_bitmask =
            ctx->cx_partition_map.pm_num_hash_partitions - 1;

    /*
     * Check if this is the first partition map that's been received.
     */
    if (0 == prev_gen) {

        /*
         * Brute force set the pi_msgs_preallocated_cnt for the
         * PREMATURE_PARTITION to zero.  Even though the PREMATURE_PARTITION
         * should never be used again, and so its counters are really
         * irrelevant.
         *
         * The pi_msgs_preallocated_cnt fields for the other partitions
         * will be remain zero during this transition.  This is OK.
         * We don't want the cost of trying to reconstruct these count fields
         * accurately.  So letting them remain zero assures that we never get
         * into a situation where the outstanding_cnt is never bigger than it
         * should be, an so IMPROPERLY preventing us from sending messages.
         *
         * This is a satisfactory approach, since the "outstanding messages"
         * count should never be a large number, probably never more than
         * 2 or 3. Since the mechanism on pi_msgs_outstanding_cnt is not
         * really a firm limit, it's OK for this to allow it to be inaccurate
         * for a short period of time after processing a new partition.
         */
        ctx->cx_partitions[PREMATURE_PARTITION].pi_msgs_preallocated_cnt = 0;

        /*
         * The first partition map received tells us how many partitions exist.
         * Now that we know, distribute any messages that have already been
         * queued to be sent (in the PREMATURE_PARTITION queue) into their
         * proper per-partition waiting-to-send queues, so they can be sent.
         */
        while (!YAQ_EMPTY(&ctx->cx_partitions[PREMATURE_PARTITION].
                                                        pi_waiting_to_send)) {
            ibuf = YAQ_OBJECT(rna_service_message_buffer_internal_t,
                              h.rmbi_link,
                              YAQ_FIRST(&ctx->cx_partitions[
                                    PREMATURE_PARTITION].pi_waiting_to_send));
            YAQ_REMOVE(&ibuf->h.rmbi_link);
            if (--ctx->cx_partitions[PREMATURE_PARTITION].
                                                pi_msgs_outstanding_cnt < 0) {
                rna_dbg_log(RNA_DBG_WARN,
                            "msgs_outstanding_cnt underflow for premature "
                            "partition\n");
                ctx->cx_partitions[PREMATURE_PARTITION].
                                                pi_msgs_outstanding_cnt = 0;
            }

            /*
             * Determine the partition this message belongs to.
             *
             * NOTE that if any new messages need to be added to this switch
             * statement, they must also be added to the similar switch
             * statement in send_md_generic().
             */
            buf = &ibuf->u.rmbi_message_buffer;
            switch (buf->h.rmb_message_type) {
            case RNA_SERVICE_MESSAGE_TYPE_MD_QUERY:
            case RNA_SERVICE_MESSAGE_TYPE_CACHE_INVD:
            case RNA_SERVICE_MESSAGE_TYPE_CACHE_MASTER_INVD:
            case RNA_SERVICE_MESSAGE_TYPE_CACHE_QUERY_REQUEST:
            {
                char    *pathname;
                int      cache_type;
                uint64_t blocknum;

                /*
                 * Find the cache type and block number in this request, which
                 * are needed to calculate its hash key.
                 */
                switch (buf->h.rmb_message_type) {
                case RNA_SERVICE_MESSAGE_TYPE_MD_QUERY:
                {
                    rna_service_metadata_query_t *user_msg =
                                                &buf->u.rmb_metadata_query;

                    pathname = buf->u.rmb_metadata_query.mqs_pathname;
                    cache_type = user_msg->mqs_request_type;
                    blocknum = user_msg->mqs_block_num;
                    break;
                }
                case RNA_SERVICE_MESSAGE_TYPE_CACHE_INVD:
                case RNA_SERVICE_MESSAGE_TYPE_CACHE_MASTER_INVD:
                {
                    rna_service_cache_invalidate_t *user_msg =
                                                &buf->u.rmb_cache_invalidate;

                    pathname = buf->u.rmb_cache_invalidate.cis_pathname;
                    cache_type = user_msg->cis_cache_type;
                    blocknum = user_msg->cis_block_num;
                    break;
                }
                case RNA_SERVICE_MESSAGE_TYPE_CACHE_QUERY_REQUEST:
                {
                    rna_service_cache_query_request_t *user_msg =
                            &((rna_service_cs_md_message_buffer_t *)buf)->
                                                    u.cmb_cache_query_request;

                    pathname = ((rna_service_cs_md_message_buffer_t *)buf)->
                                        u.cmb_cache_response.cr_pathname;
                    cache_type = user_msg->cqr_cache_type;
                    blocknum = user_msg->cqr_block_number;
                    break;
                }
                default:
                    /* This should be impossible */
                    rna_dbg_log(RNA_DBG_ERR,
                                "apparent memory corruption: "
                                "message type [%d], dropping\n",
                                buf->h.rmb_message_type);
                    rna_service_free_message_buffer(ctx, buf);
                    continue;
                }

                /* Caclculate the hash key for this request */
                rna_hash_compute_key_path(pathname,
                                          strlen(pathname),
                                          &ctx->cx_hash_key_temp);
                switch (cache_type) {
                case CACHE_REQ_TYPE_BLOCK:
                    rna_hash_convert_key_to_block_key(&ctx->cx_hash_key_temp,
                                                       blocknum);
                    break;
                case CACHE_REQ_TYPE_MASTER:
                    rna_hash_convert_key_to_master_key(&ctx->cx_hash_key_temp);
                    break;
                case CACHE_REQ_TYPE_FULL:
                    // NOOP
                    break;
                }

                /* Calculate the partition from the hash key */
                partition = rna_service_hashkey_to_partition(
                                             &ctx->cx_hash_key_temp,
                                              ctx->cx_hash_partition_bitmask);
                break;
            }
            case RNA_SERVICE_MESSAGE_TYPE_CACHE_RESPONSE:
                /* This is a cache-server-specific message */
                partition = ((rna_service_cs_md_message_buffer_t *)buf)->
                                        u.cmb_cache_response.cr_hash_partition;
                break;
            case RNA_SERVICE_MESSAGE_TYPE_RELOCATE_BLOCK:
                /* partition passed directly from cache hash entry */
                partition = buf->u.rmb_relocate_cache_block.rcb_hash_partition;
                break;
            case RNA_SERVICE_MESSAGE_TYPE_ABSORB_BLOCK:
                partition = RNA_SERVICE_METADATA_RID_TO_PARTITION(
                                    buf->u.rmb_cache_absorb_block.cab_md_rid);
                break;
            case RNA_SERVICE_MESSAGE_TYPE_INVD_HOLD_RESPONSE:
                partition = buf->u.rmb_invd_hold_response.ihr_hash_partition;
                break;
            default:
                rna_dbg_log(RNA_DBG_ERR,
                            "illegal message type [%d], dropping\n",
                            buf->h.rmb_message_type);
                rna_service_free_message_buffer(ctx, buf);
                continue;
            }

            /*
             * Insert the message into the waiting-to-send queue for its
             * partition.
             */
            YAQ_INSERT_TAIL(&ctx->cx_partitions[partition].pi_waiting_to_send,
                            &ibuf->h.rmbi_link);
            ctx->cx_partitions[partition].pi_msgs_outstanding_cnt++;
        }

        /*
         * Check if we have all MD connections, and if so, generate a callback.
         */
        for (i = ctx->cx_partition_map.pm_num_hash_partitions - 1; i >= 0; --i)
        {
            mdi = ctx->cx_md_table[
                            ctx->cx_partition_map.pm_partition_assignments[i]];
            if ((NULL == mdi)
              || (!(mdi->mdi_cflags & MD_INFO_CFLAG_CONNECTED))) {
                break;
            }
        }
        if (i < 0) {
            /* We have all MD connections, generate a callback */
            ctx->cx_md_flags &= ~CTX_MD_FLAG_MSGS_OUTSTANDING_OVERFLOWED;
            /* don't hold mutex during callback */
            rna_service_mutex_unlock(&ctx->cx_md_mutex);
            rna_dbg_log(RNA_DBG_INFO,
                        "All MD connections are now established\n");
            ctx->cx_params.rsp_event_callback(
                        ctx, RNA_SERVICE_EVENT_INFO_FULLY_CONNECTED);
            if (!rna_service_mutex_lock(&ctx->cx_md_mutex)) {
                /* This failure means we're in the process of shutting down */
                goto done_nolock;
            }
        }
    } else {
        rna_service_assert(YAQ_EMPTY(&ctx->cx_partitions[PREMATURE_PARTITION].
                                                         pi_waiting_to_send));
    }

    /*
     * If any hash partitions have been reassigned to new metadata servers, any
     * queued messages belonging to those partitions will need to be sent to
     * their new MDs.
     */
    if (must_resend) {
        /*
         * If an MD that previously had no partitions assigned to it now has at
         * least one partition assigned to it, it's newly eligible to have a
         * connection made to it.  Check if this has happened, and if so,
         * establish a connection.
         */
        queue_reconnect_mds(ctx);

        resend_md_messages(ctx);
    }

 done:
    rna_service_mutex_unlock(&ctx->cx_md_mutex);

 done_nolock:
    /* Release the reference that was added in work_queue_add_cfm(). */
    com_release_eph(&wctx->cwx_eph);    // (no-op at user level)

    mempool_free(ctx, MEMPOOL_ID_CFM_WORK_CTX, (void *)wctx);

    /*
     * Release the ctx reference that was added in work_queue_add_cfm.
     */
    ctx_release_reference(&ctx);

    /*
     * NOTE that rna_service workq callbacks must use
     * RNA_SERVICE_WORKQ_CB_RETURN instead of return.
     */
    RNA_SERVICE_WORKQ_CB_RETURN(0);
}


/**
 * Invoked by a workq thread to process a CONF_MGR_MD_REPORT message
 * (cfm_md_host_rep) that arrived from the configuration manager (CFM) to
 * notify us about the existence of a metadata server.
 */
static rna_service_workq_cb_ret_t
process_md_report(rna_service_workq_cb_arg_t workq_context)
{
    cfm_work_ctx_t          *wctx = (cfm_work_ctx_t *) workq_context;
    rna_service_ctx_t       *ctx;
    struct cfm_cmd          *cmd;
    struct cfm_md_host_rep  *report;
    md_info_t               *mdi;
    int                      ret = 0;

    rna_service_assert(NULL != wctx);

    ctx = wctx->cwx_ctx;
    rna_service_assert(NULL != ctx);

    cmd = &wctx->cwx_cmd;
    report = &cmd->u.cfm_md_host_rep;

    if (!rna_service_mutex_lock(&ctx->cx_md_mutex)) {
        // This failure means we're in the process of shutting down; do nothing
        goto done_nolock;
    }

    rna_dbg_log(RNA_DBG_MSG, "MD Host Report [%d] ["rna_service_id_format"]\n",
                report->md_ordinal,
                rna_service_id_get_string(&report->md_service_id));

    ctx->cx_num_configured_mds = report->md_num_configured;

    mdi = ctx->cx_md_table[report->md_ordinal];
    if ((NULL == mdi)
      || (memcmp(&mdi->mdi_service_id,
                 &report->md_service_id,
                 sizeof(mdi->mdi_service_id)) != 0)) {
        /*
         * We don't yet have an entry for this MD; create one.
         */
        mdi = (md_info_t *) mempool_alloc(ctx, MEMPOOL_ID_MD_INFO, 0);
        if (NULL == mdi) {
            rna_dbg_log(RNA_DBG_WARN,
                        "Ran out of memory creating MD entity.\n");
            ret = ENOMEM;
            goto done;
        }

        rna_service_assert(report->md_ordinal < NUM_MD_ORDINALS);
        com_init_eph(&mdi->mdi_eph);
        mdi->mdi_ordinal = report->md_ordinal;
        rna_service_assert(mdi->mdi_ordinal < NUM_MD_ORDINALS);

        mdi->mdi_if_tbl = report->md_if_tbl;
        mdi->mdi_service_id = report->md_service_id;
        rna_service_timer_init(
            &ctx->cx_send_waiting_md_msgs_timers[report->md_ordinal].sto_timer);

        /*
         * Add this MD to the md_table and start trying to establish a
         * connection to the new MD.
         */
        add_md_table_entry(ctx, mdi);
        queue_reconnect_mds(ctx);
    }

done:
    rna_service_mutex_unlock(&ctx->cx_md_mutex);

done_nolock:
    /* Release the reference that was added in work_queue_add_cfm(). */
    com_release_eph(&wctx->cwx_eph);    // (no-op at user level)

    mempool_free(ctx, MEMPOOL_ID_CFM_WORK_CTX, (void *)wctx);

    /*
     * Release the ctx reference that was added in work_queue_add_cfm.
     */
    ctx_release_reference(&ctx);

    /*
     * NOTE that rna_service workq callbacks must use
     * RNA_SERVICE_WORKQ_CB_RETURN instead of return.
     */
    RNA_SERVICE_WORKQ_CB_RETURN(ret);
}


/**
 * Process a CONF_MGR_EVENT_REG message.
 */
static void
process_cfm_event_reg(rna_service_ctx_t *ctx,
                      com_ep_handle_t   *eph,
                      struct cfm_cmd    *cmd)
{
    UNREFERENCED_PARAMETER(eph);

    rna_dbg_log(RNA_DBG_INFO,
                "Got event registration message: mask: 0x%x\n",
                cmd->u.rna_event_reg.event_mask);
    /* (failure to get the following mutex indicates we're shutting down) */
    if (rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
        ctx->cx_cfm_event_mask = cmd->u.rna_event_reg.event_mask;
        rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
    }
}


/**
 * Process a CONF_MGR_EVENT_DEREG message.
 */
static void
process_cfm_event_dereg(rna_service_ctx_t *ctx,
                        com_ep_handle_t   *eph,
                        struct cfm_cmd    *cmd)
{
    UNREFERENCED_PARAMETER(cmd);
    UNREFERENCED_PARAMETER(eph);

    rna_dbg_log(RNA_DBG_INFO, "Got event deregistration message\n");
    /* (failure to get the following mutex indicates we're shutting down) */
    if (rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
        ctx->cx_cfm_event_mask = 0;
        rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
    }
}


/**
 * Invoked by a workq thread to process a CONF_MGR_CSTAT_REQ message.
 */
static rna_service_workq_cb_ret_t
process_cstat_req(rna_service_workq_cb_arg_t workq_context)
{
    cfm_work_ctx_t    *wctx = (cfm_work_ctx_t *) workq_context;
    rna_service_ctx_t *ctx;
    int                ret = 0;
    struct cfm_cmd    *cmd;
    rna_service_send_buf_entry_t
                      *send_buf;

    rna_service_assert(NULL != wctx);

    ctx = wctx->cwx_ctx;
    rna_service_assert(NULL != ctx);

    /*
     * Make sure the primary CFM hasn't disappeared since this work queue task
     * was scheduled.
     */
    if (!rna_service_com_connected(&ctx->cx_primary_cfm_eph)) {
        goto done;
    }

    ret = rna_service_com_get_send_buf(&ctx->cx_primary_cfm_eph,
                                       &send_buf,
                                       TRUE,
                                       NULL);
    if ((NULL == send_buf) || (0 != ret)) {
        rna_dbg_log(RNA_DBG_WARN,
                    "failed to allocate send buffer\n");
        goto done;
    }

#if defined(LINUX_KERNEL) || defined(WINDOWS_KERNEL)
    cmd = (struct cfm_cmd *)(com_get_send_buf_mem(send_buf));
#else
    cmd = (struct cfm_cmd *) send_buf->mem;
#endif
    memset(cmd, 0, sizeof(cmd_hdr_t));

    cmd->h.h_type = CONF_MGR_CSTAT_RESP;
    cmd->h.h_cookie = 0;

    if (NULL != ctx->cx_params.rsp_stat_buf) {
        memcpy(&cmd->u.cache_stats_rep,
                ctx->cx_params.rsp_stat_buf,
                sizeof(cmd->u.cache_stats_rep));
    } else {
        memset(&cmd->u.cache_stats_rep, 0, sizeof(cmd->u.cache_stats_rep));
    }

    ret = rna_service_com_send_cfm_cmd(&ctx->cx_primary_cfm_eph,
                                       send_buf,
                                       cfm_cmd_length(cmd),
                                       &ctx->cx_primary_cfm_id);
    if (ret != 0) {
        rna_dbg_log(RNA_DBG_WARN, "Failed to send CFM message: %d\n", ret);
    }    

 done:
    /* Release the reference that was added in work_queue_add_cfm(). */
    com_release_eph(&wctx->cwx_eph);    // (no-op at user level)

    mempool_free(ctx, MEMPOOL_ID_CFM_WORK_CTX, (void *)wctx);

    /*
     * Release the ctx reference that was added in work_queue_add_cfm.
     */
    ctx_release_reference(&ctx);

    /*
     * NOTE that rna_service workq callbacks must use
     * RNA_SERVICE_WORKQ_CB_RETURN instead of return.
     */
    RNA_SERVICE_WORKQ_CB_RETURN(ret);
}


/**
 * Invoked by a workq thread to process a CONF_MGR_BSTAT_REQ message.
 */
static int
process_bstat_request(rna_service_ctx_t *ctx,
                      com_ep_handle_t   *eph,
                      struct cfm_cmd    *cmd)
{
    rna_service_message_buffer_t *mbuf;

    UNREFERENCED_PARAMETER(cmd);
    UNREFERENCED_PARAMETER(eph);

    if ((NULL == ctx->cx_params.rsp_async_msg_callback)
      || (ctx->cx_flags & CX_FLAG_SHUTTING_DOWN)) {
        /* Bail out */
        return (0);
    }

    mbuf = rna_service_alloc_message_buffer(
                                        ctx,
                                        RNA_SERVICE_MESSAGE_TYPE_BSTAT_REQUEST,
                                        NULL);
    if (NULL == mbuf) {
        rna_dbg_log(RNA_DBG_WARN,
                    "Memory allocation failed!  Dropping "
                    "CONF_MGR_BSTAT_REQ message\n");
        return (ENOMEM);
    }

    mbuf->h.rmb_message_type = RNA_SERVICE_MESSAGE_TYPE_BSTAT_REQUEST;

    /*
     * If the user has specified that the work queue isn't to be used
     * (presumably for performance reasons), then invoke the user's
     * callback directly.  Otherwise, hand the invocation off to a
     * workq thread.
     */
    if (ctx->cx_params.rsp_flags & RNA_SERVICE_FLAG_NO_WORKQ) {
        /* Don't invoke any callbacks if we're shutting down. */
        if (ctx->cx_flags & CX_FLAG_SHUTTING_DOWN) {
            rna_service_free_message_buffer(ctx, mbuf);
        } else {
            ctx->cx_params.rsp_async_msg_callback(ctx, mbuf);
        }
    } else {
        work_queue_add_callback(ctx, NULL, mbuf, RNA_SERVICE_EVENT_NONE);
    }
    return (0);
}


/**
 * Process a CONF_MGR_CONN_REG message received from the configuration manager.
 */
static int 
process_connection_register(rna_service_ctx_t *ctx,
                            com_ep_handle_t   *eph,
                            struct cfm_cmd    *cmd) 
{
    int ret = 0;

    if (NULL == eph ||
        NULL == cmd) {
        ret = EINVAL;
    } else {
        switch (cmd->u.cfm_service_reg.service_id.u.data.type) {
            case APP_TYPE_MD:
                if (RNA_SERVICE_USER_TYPE_CACHE_SERVER ==
                                                ctx->cx_params.rsp_user_type) {
                    ret = cs_process_md_activation(ctx, eph, cmd);
                } else if (RNA_SERVICE_USER_TYPE_METADATA_SERVER ==
                                                ctx->cx_params.rsp_user_type) {
                    ret = md_process_md_activation(ctx, eph, cmd);
                } else {
                    rna_dbg_log(RNA_DBG_ERR,
                                "User type %d received CONF_MGR_CONN_REG/"
                                "APP_TYPE_MD, ignoring\n",
                                ctx->cx_params.rsp_user_type);
                    ret = EINVAL;
                }
                break;

            case APP_TYPE_CS:
                if (RNA_SERVICE_USER_TYPE_METADATA_SERVER ==
                                                ctx->cx_params.rsp_user_type) {
                    ret = md_process_cs_activation(ctx, eph, cmd);
                } else if (RNA_SERVICE_USER_TYPE_CACHE_SERVER ==
                                                ctx->cx_params.rsp_user_type) {
                    /*
                     * Check if it's this cache server that's been activated.
                     * Activation of this CS is recorded in the ctx, and is
                     * not handed upward.
                     */
                    if (match_rna_service_id(&cmd->u.cfm_service_reg.service_id,
                                             &ctx->cx_params.rsp_service_id,
                                              TRUE)) {
                        /*
                         * (Failure to acquire this lock means we're in the
                         * process of shutting down, in which case this flag
                         * doesn't matter).
                         */
                        if (rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
                            ctx->cx_cfm_flags |= CTX_CFM_FLAG_ACTIVATED;
                            rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
                        }
                    } else {
                        /* Pass this connection registration upward */
                        ret = process_cs_async_message(ctx, eph, cmd);
                    }
                } else {
                    rna_dbg_log(RNA_DBG_ERR,
                                "User type %d received CONF_MGR_CONN_REG/"
                                "APP_TYPE_CS, ignoring\n",
                                ctx->cx_params.rsp_user_type);
                    ret = EINVAL;
                }
                break;

            default:
                rna_dbg_log(RNA_DBG_WARN,
                            "CFM connection registration for unknown type "
                            "[%s]\n",
                            get_user_type_string(
                                cmd->u.cfm_service_reg.service_id.u.data.type));
                ret = EINVAL;
        }
    }

    return ret;
}


/**
 * The primary CFM has notified us that a cache server has been expelled from
 * the cluster.
 */
static int
process_cs_disconnection(rna_service_ctx_t *ctx,
                         com_ep_handle_t   *cfm_eph,
                         struct cfm_cmd    *cmd) 
{
    rna_service_message_buffer_t *mbuf;

    UNREFERENCED_PARAMETER(cfm_eph);

    /*
     * A CS expel operation comes with a new cache server membership generation
     * number, save it.  We'll need it if this is a cache server
     * (RNA_SERVICE_USER_TYPE_CACHE_SERVER) and it ever needs to re-register
     * with the CFM and MDs.
     */
    rna_dbg_log(RNA_DBG_INFO,
                "Updating CS membership generation from [%"PRId64"] "
                "to [%"PRId64"]\n",
                ctx->cx_cs_membership_generation,
                cmd->u.cfm_service_reg.csr_cs_membership_generation);
    ctx->cx_cs_membership_generation = 
                        cmd->u.cfm_service_reg.csr_cs_membership_generation;

    if ((NULL == ctx->cx_params.rsp_async_msg_callback)
      || (ctx->cx_flags & CX_FLAG_SHUTTING_DOWN)) {
        /* Bail out */
        return (0);
    }

    /*
     * Tell the user of this library about the expel.
     */
    mbuf = rna_service_alloc_message_buffer(ctx,
                                            RNA_SERVICE_MESSAGE_TYPE_EXPEL_CS,
                                            NULL);
    if (NULL == mbuf) {
        rna_dbg_log(RNA_DBG_WARN,
                    "Memory allocation failed!  Dropping "
                    "CONF_MGR_DISCONN_REG message\n");
        return (ENOMEM);
    }

    mbuf->h.rmb_message_type = RNA_SERVICE_MESSAGE_TYPE_EXPEL_CS;
    mbuf->u.rmb_expel_cs.ecs_service_id = cmd->u.cfm_service_reg.service_id;
    mbuf->u.rmb_expel_cs.ecs_cs_membership_generation =
                        cmd->u.cfm_service_reg.csr_cs_membership_generation;

    /*
     * If the user has specified that the work queue isn't to be used
     * (presumably for performance reasons), then invoke the user's
     * callback directly.  Otherwise, hand the invocation off to a
     * workq thread.
     */
    if (ctx->cx_params.rsp_flags & RNA_SERVICE_FLAG_NO_WORKQ) {
        /* Don't invoke any callbacks if we're shutting down. */
        if (ctx->cx_flags & CX_FLAG_SHUTTING_DOWN) {
            rna_service_free_message_buffer(ctx, mbuf);
        } else {
            ctx->cx_params.rsp_async_msg_callback(ctx, mbuf);
        }
    } else {
        work_queue_add_callback(ctx, NULL, mbuf, RNA_SERVICE_EVENT_NONE);
    }
    return (0);
}


/**
 * Process a CONF_MGR_DISCONN_REG message received from the configuration
 * manager.
 */
static int 
process_disconnection_register(rna_service_ctx_t *ctx,
                               com_ep_handle_t   *cfm_eph,
                               struct cfm_cmd    *cmd) 
{
    int ret = 0;

    if (NULL == cfm_eph ||
        NULL == cmd) {
        ret = EINVAL;
    } else {
        switch (cmd->u.cfm_service_reg.service_id.u.data.type) {
            case APP_TYPE_MD:
                ret = process_cfm_expel_md(ctx, cfm_eph, cmd);
                break;

            case APP_TYPE_CS:
                ret = process_cs_disconnection(ctx, cfm_eph, cmd);
                break;

            default:
                rna_dbg_log(RNA_DBG_WARN,
                            "CFM disconnection registration for unknown type "
                            "[%d] [%s]\n",
                            cmd->u.cfm_service_reg.service_id.u.data.type,
                            get_user_type_string(
                                cmd->u.cfm_service_reg.service_id.u.data.type));
                ret = EINVAL;
        }
    }

    return ret;
}


/*
 * Every cfm_cmd and cache_cmd message contains an indicator of what the sender
 * believes to be the primary CFM ID.  Check if that ID is more recent than the
 * ID we have, and if so, handle the change in primary CFM.
 */
static void
check_for_primary_cfm_change(rna_service_ctx_t *ctx, primary_cfm_id_t  *pci)
{
    boolean          promotion = FALSE;
    primary_cfm_id_t demoted_pci;
#ifdef WINDOWS_KERNEL
    KLOCK_QUEUE_HANDLE lockHandle;
#endif /* WINDOWS_KERNEL */

    memset(&demoted_pci, 0, sizeof(demoted_pci));

    /*
     * Start with a cheap unguarded comparison of this primary CFM ID with the
     * one we have.  Since cx_primary_cfm_id.pcic_pci.pci_generation increases
     * monotonically, the result of this check won't change after the
     * appropriate lock is held.
     */
    if ((pci->pci_generation < ctx->cx_primary_cfm_id.pcic_pci.pci_generation)
      || ((pci->pci_generation ==
                           ctx->cx_primary_cfm_id.pcic_pci.pci_generation)
        && (pci->pci_addr.s_addr ==
                           ctx->cx_primary_cfm_id.pcic_pci.pci_addr.s_addr))) {
        return; /* <=== cfm is unchanged; there's nothing to do */
    }

    /*
     * The primary CFM may be changing.  Lock the primary CFM ID and look
     * more closely.  We may also need the cx_cfm_mutex, so grab it here,
     * to avoid lock ordering problems.  If the user is a cache server, we'll
     * also need the cx_md_mutex.  To prevent deadlock, the md mutex must be
     * acquired first.
     */
    if (RNA_SERVICE_USER_TYPE_CACHE_SERVER == ctx->cx_params.rsp_user_type) {
        if (!rna_service_mutex_lock(&ctx->cx_md_mutex)) {
            /* This failure means we're in the process of shutting down */
            return;
        }
    }
    if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
        /* This failure means we're in the process of shutting down */
        if (RNA_SERVICE_USER_TYPE_CACHE_SERVER ==
                                                ctx->cx_params.rsp_user_type) {
            rna_service_mutex_unlock(&ctx->cx_md_mutex);
        }
        return;
    }
#ifdef WINDOWS_KERNEL
    if (!rna_service_instkqd_spinlock_acquire(&ctx->cx_primary_cfm_id.pcic_spinlock, &lockHandle))
#else
    if (!rna_service_mutex_lock(&ctx->cx_primary_cfm_id.pcic_mutex)) 
#endif /* WINDOWS_KERNEL */
    {
        /* This failure means we're in the process of shutting down */
        if (RNA_SERVICE_USER_TYPE_CACHE_SERVER ==
                                                ctx->cx_params.rsp_user_type) {
            rna_service_mutex_unlock(&ctx->cx_md_mutex);
        }
        rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
        return;
    }

    /*
     * Replace the primary CFM with this new primary CFM if:
     *   1. This primary CFM id has a higher generation than the one we have
     * or:
     *   2. This primary CFM id has the same generation as the one we have but
     *      a null address (this happens if the old primary CFM has demoted
     *      itself).
     */
    if ((pci->pci_generation >                                     // 1
                    ctx->cx_primary_cfm_id.pcic_pci.pci_generation)
      || ((pci->pci_generation ==                                  // 2
                    ctx->cx_primary_cfm_id.pcic_pci.pci_generation)
        && (INADDR_NONE == pci->pci_addr.s_addr)))                 // 2 cont'd
    {
        /*
         * Check if the primary CFM address is actually changing (this may be
         * a generation change only).
         */
        if ((ctx->cx_primary_cfm_id.pcic_pci.pci_addr.s_addr !=
                                                       pci->pci_addr.s_addr)
          && (ctx->cx_primary_cfm_id.pcic_pci.pci_addr.s_addr != INADDR_NONE)) {
            /* The old primary is no longer primary */
            demoted_pci = ctx->cx_primary_cfm_id.pcic_pci;
        }

        if (pci->pci_addr.s_addr != INADDR_NONE) {
            promotion = TRUE;
        }
        ctx->cx_primary_cfm_id.pcic_pci = *pci;

#ifdef WINDOWS_KERNEL
        rna_service_instkqd_spinlock_release( &lockHandle );
#else
        rna_service_mutex_unlock(&ctx->cx_primary_cfm_id.pcic_mutex);
#endif /* WINDOWS_KERNEL */

        rna_dbg_log(RNA_DBG_MSG,
                    "New primary CFM ID: [" RNA_ADDR_FORMAT "] "
                    "gen [%"PRId64"]\n",
                    RNA_ADDR(pci->pci_addr.s_addr),
                    pci->pci_generation);

    } else {
#ifdef WINDOWS_KERNEL
        rna_service_instkqd_spinlock_release( &lockHandle );
#else
        rna_service_mutex_unlock(&ctx->cx_primary_cfm_id.pcic_mutex);
#endif /* WINDOWS_KERNEL */
    }

    if (demoted_pci.pci_generation != 0) {
        /* Demote the old primary CFM */
        rnas_demote_cfm(ctx, NULL, &demoted_pci);
    }

    if (promotion) {
        /*
         * If we have a connection to the new primary CFM, store its connection
         * as the primary CFM connection and register with it.
         */
        if (find_connected_cfm_by_address(ctx,
                                          &pci->pci_addr,
                                          &ctx->cx_primary_cfm_eph)) {
            rna_dbg_log(RNA_DBG_INFO,
                        "Primary CFM is now ["RNA_ADDR_FORMAT"]\n",
                        RNA_ADDR(ctx->cx_primary_cfm_eph.eph_dst_in.sin_addr));

            /* Send the required introductory messages to the new primary CFM */
            primary_cfm_connected(ctx);
        }
    }

    if (RNA_SERVICE_USER_TYPE_CACHE_SERVER == ctx->cx_params.rsp_user_type) {
        rna_service_mutex_unlock(&ctx->cx_md_mutex);
    }
    rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
}

/*
 * Process updated list of cfms.
 * Replace any new cfm and queue cfm reconnect work.
 * Locking: cx_cfm_mutex must be held by caller
 */
static void
rna_service_check_and_update_cfms(rna_service_ctx_t *ctx,
                                  uint32_t cfm_count,
                                  struct sockaddr_in *cfm_addr_tbl,
                                  const uint32_t max_entries)
{
    uint32_t            i;
    uint32_t            j;
    cfm_info_t         *ci;
    gboolean removed_some = FALSE;

    /*
     * TRUE if the entry at that index in cfm_addr_tbl is already
     * in the list of configured CFMs (rsp_cfm_addr_tbl).
     * Otherwise FALSE
     */
    gboolean cfm_addr_found[RNA_SERVICE_CFMS_MAX];

    /*
     * TRUE if the entry at that index in rsp_cfm_addrs is being removed
     * (i.e. is not contained in cfm_addr_tbl).
     * Otherwise FALSE.
     */
    gboolean rsp_addr_remove[RNA_SERVICE_CFMS_MAX];


    memset(cfm_addr_found, FALSE, sizeof(cfm_addr_found));
    memset(rsp_addr_remove, FALSE, sizeof(rsp_addr_remove));

    /*
     * Look for removed CFMs
     */
    for (j = 0; (j < cfm_count) && (j < max_entries); j++) {
        for (i = 0; (i < cfm_count) && (i < max_entries); i++) {
            /*
             * skip if we've already found this in the list, or
             * if we match then set the flag saying that we found
             * this cfm in the list.
             */
            if ((FALSE == cfm_addr_found[i]) &&
                (cfm_addr_tbl[i].sin_addr.s_addr ==
                 ctx->cx_params.rsp_cfm_addrs[j].sin_addr.s_addr)) {
                /*
                 * found it, no change for this one.
                 */
                cfm_addr_found[i] = TRUE;
                break;
            }
        }
        if (i == cfm_count) {
            /*
             * This means that this cfm is being replaced
             * because we exited without finding it in the new list.
             *
             * before updating the entry, disconnect from the
             * obsolete CFM, if we're connected.
             */
            rna_dbg_log(RNA_DBG_MSG,
                        "Removing "
                        "CFM ["RNA_ADDR_FORMAT"]\n",
                        RNA_ADDR(
                            ctx->cx_params.rsp_cfm_addrs[j].sin_addr.s_addr));
            ci = &ctx->cx_connected_cfms[j];
            if (!com_eph_isempty(&ci->ci_eph)) {
                /*
                 * If this CFM has a registered stats buf,
                 * de-register it.
                 */
                rna_service_com_deregister_rdma_buffer(
                        ctx->cx_com_instance,
                        &ci->ci_eph,
                        &ci->ci_stat_info);
                memset(&ci->ci_stat_info,
                        0,
                        sizeof(ci->ci_stat_info));
                rna_dbg_log(RNA_DBG_INFO,
                            "Disconnecting from obsolete "
                            "CFM ["RNA_ADDR_FORMAT"]\n",
                            RNA_ADDR(
                                ci->ci_eph.eph_dst_in.sin_addr));
                rna_service_com_disconnect(&ci->ci_eph);
                com_init_eph(&ci->ci_eph);
            }
            removed_some = TRUE;
            rsp_addr_remove[j] = TRUE;
            memset(ci, 0, sizeof(*ci));
        }
    }

    /*
     * Look for added CFMs
     */
    if (removed_some) {
        for (j = 0; (j < cfm_count) && (j < max_entries); j++) {
            /*
             * skip if not being replaced
             */
            if (TRUE == cfm_addr_found[j]) {
                continue;
            }
            rna_dbg_log(RNA_DBG_MSG, "Adding CFM ["RNA_ADDR_FORMAT"]\n",
                    RNA_ADDR(cfm_addr_tbl[j].sin_addr));

            for (i = 0; (i < cfm_count) && (i < max_entries); i++) {
                if (TRUE == rsp_addr_remove[i]) {
                    /*
                     * found an empty spot, add it here.
                     */
                     ctx->cx_params.rsp_cfm_addrs[i] = cfm_addr_tbl[j];
                     break;

                }
            }
            if (i == cfm_count) {
                /*
                 * This should not happen.  Should not have
                 * more adds than deletes.
                 */
                rna_dbg_log(RNA_DBG_ERR, "No place to add ["RNA_ADDR_FORMAT"]\n",
                            RNA_ADDR(cfm_addr_tbl[j].sin_addr));
            }
        }
    }

    ctx->cx_params.rsp_cfm_count = cfm_count;
    /* Connect to the new CFM */
    queue_reconnect_cfms(ctx);
}

/*
 * Update cfm addresses in rna_service context, to be used by kernel module
 * that may not have connection to primary cfm to get promotion notices.
 *
 * Returns:
 *    RNA_SERVICE_ERROR_NONE  On success
 *    RNA_SERVICE_ERROR_INVALID_PARAMS
 *                            One or more of the specified parameters is invalid
 */
rna_service_error_t
rna_service_cfms_update(uint32_t            cfm_count,
                        struct sockaddr_in *cfm_addr_tbl,
                        rna_service_ctx_t  *ctx)
{
    if ((NULL == cfm_addr_tbl)
        || (NULL == ctx)
        || (RNA_SERVICE_CFMS_MAX < cfm_count)
        || (0 == cfm_count)) {
        return (RNA_SERVICE_ERROR_INVALID_PARAMS);
    }
    if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
        // This failure means we're in the process of shutting down; do nothing
    } else {
        rna_service_check_and_update_cfms(ctx,
                                          cfm_count,
                                          cfm_addr_tbl,
                                          RNA_SERVICE_CFMS_MAX);
        rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
    }
    return RNA_SERVICE_ERROR_NONE;
}

/**
 * Invoked by a workq thread to process a CONF_MGR_CONTROL message
 * (cfm_control).
 */
static rna_service_workq_cb_ret_t
process_cfm_control(rna_service_workq_cb_arg_t workq_context)
{
    cfm_work_ctx_t     *wctx = (cfm_work_ctx_t *) workq_context;
    rna_service_ctx_t  *ctx;
    com_ep_handle_t    *cfm_eph;
    com_ep_handle_t    disconn_eph;
    struct cfm_cmd     *cmd;
    struct cfm_control *control;
    rna_service_message_buffer_t
                       *mbuf;

    rna_service_assert(NULL != wctx);

    ctx = wctx->cwx_ctx;
    rna_service_assert(NULL != ctx);

    cfm_eph = &wctx->cwx_eph;

    cmd = &wctx->cwx_cmd;
    control = &cmd->u.cfm_control;

    rna_trace("incoming ["RNA_ADDR_FORMAT"] type [%s]\n",
               RNA_ADDR(cfm_eph->eph_dst_in.sin_addr),
               get_app_control_type_string(control->type));

    switch(control->type) {
        case CFM_PROMOTION:
            /*
             * This promotion has already been handled by
             * check_for_primary_cfm_change(), which was called by
             * process_cfm_cmd() before this function was scheduled to run.
             */
            rna_dbg_log(RNA_DBG_INFO,
                        "Promotion notice from CFM ["RNA_ADDR_FORMAT"] "
                        "config gen [%d]\n",
                        RNA_ADDR(cfm_eph->eph_dst_in.sin_addr),
                        cmd->u.cfm_control.arg.generation.ccg_config_gen);

            if (cmd->u.cfm_control.arg.generation.ccg_config_gen <
                                                    ctx->cx_cfm_config_gen) {
                rna_dbg_log(RNA_DBG_WARN,
                            "Out of order config gen [%d] < [%d]\n",
                            cmd->u.cfm_control.arg.generation.ccg_config_gen,
                            ctx->cx_cfm_config_gen);
            } else if (cmd->u.cfm_control.arg.generation.ccg_config_gen >
                                                    ctx->cx_cfm_config_gen) {
                /*
                 * Look for mismatches between our set of CFMs and those
                 * specified in this message, and update our set if any are
                 * found.
                 */
                if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
                    // we're in the process of shutting down; do nothing
                    break;
                }
                rna_service_check_and_update_cfms(ctx,
                        cmd->u.cfm_control.arg.generation.cfm_count,
                        cmd->u.cfm_control.arg.generation.cfm_addr_tbl,
                        MAX_NET_IF);
                rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
            }

            /* If there is only one CFM, and this end point is a
             * local connection to that CFM, then cancel the
             * heartbeat timer
             */
            if ((control->arg.generation.cfm_count == 1) &&
                    com_get_ep_is_local_connection(cfm_eph)) {
                rna_dbg_log(RNA_DBG_INFO,
                            "Cancel heartbeat timer\n");
                /* Mark the context so new heartbeat timers are NOT
                 * and cancel the heartbeat timer.
                 */
                if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
                    break;
                }
                rna_dbg_log(RNA_DBG_INFO, "Disable Heartbeat Timer\n");
                ctx->cx_cfm_flags |= CTX_CFM_FLAG_DISABLED_HEARTBEAT_TIMER;
                rna_service_timer_cancel(&ctx->cx_primary_cfm_heartbeat_timer);
                rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
            } else {
                rna_dbg_log(RNA_DBG_INFO, "Enable Heartbeat TImer\n");
            }

            break;

        case CFM_DEMOTION:
            /*
             * This demotion has already been handled by
             * check_for_primary_cfm_change(), which was called by
             * process_cfm_cmd() before this function was scheduled to run.
             */
            rna_dbg_log(RNA_DBG_INFO,
                        "Demotion notice from CFM ["RNA_ADDR_FORMAT"]\n",
                        RNA_ADDR(cfm_eph->eph_dst_in.sin_addr));
            break;

        case CACHE_MOUNT_BLOCKED:
            /* (Don't invoke any callbacks if we're shutting down) */
            if (!(ctx->cx_flags & CX_FLAG_SHUTTING_DOWN)) {
                ctx->cx_params.rsp_event_callback(
                            ctx,
                            RNA_SERVICE_EVENT_CACHE_MOUNT_BLOCKED);
            }
            break;

        case CACHE_MOUNT_UNBLOCKED:
            /* (Don't invoke any callbacks if we're shutting down) */
            if (!(ctx->cx_flags & CX_FLAG_SHUTTING_DOWN)) {
                ctx->cx_params.rsp_event_callback(
                            ctx,
                            RNA_SERVICE_EVENT_CACHE_MOUNT_UNBLOCKED);
            }
            break;

        case APP_CTL_SET_LOG_LEVEL:
            if ((NULL == ctx->cx_params.rsp_async_msg_callback)
              || (ctx->cx_flags & CX_FLAG_SHUTTING_DOWN)) {
                /* Bail out */
                break;
            }

            mbuf = rna_service_alloc_message_buffer(
                                        ctx,
                                        RNA_SERVICE_MESSAGE_TYPE_SET_LOG_LEVEL,
                                        NULL);
            if (NULL == mbuf) {
                rna_dbg_log(RNA_DBG_WARN,
                            "Memory allocation failed!  Dropping "
                            "APP_CTL_SET_LOG_LEVEL message\n");
                break;
            }

            mbuf->h.rmb_message_type = RNA_SERVICE_MESSAGE_TYPE_SET_LOG_LEVEL;
            mbuf->u.rmb_set_log_level.sll_log_level = 
                            cmd->u.cfm_control.arg.set_log_level.log_level;
            /*
             * If the user has specified that the work queue isn't to be used
             * (presumably for performance reasons), then invoke the user's
             * callback directly.  Otherwise, hand the invocation off to a
             * workq thread.
             */
            if (ctx->cx_params.rsp_flags & RNA_SERVICE_FLAG_NO_WORKQ) {
                /* Don't invoke any callbacks if we're shutting down. */
                if (ctx->cx_flags & CX_FLAG_SHUTTING_DOWN) {
                    rna_service_free_message_buffer(ctx, mbuf);
                } else {
                    ctx->cx_params.rsp_async_msg_callback(ctx, mbuf);
                }
            } else {
                work_queue_add_callback(ctx,
                                        NULL,
                                        mbuf,
                                        RNA_SERVICE_EVENT_NONE);
            }
            break;

        case APP_CTL_DROP_CONNECTION:
            /* XXX: currently no good way to validate the EPH... */
            memset(&disconn_eph,'\0',sizeof(com_ep_handle_t));
            disconn_eph.eph_gen =
                            cmd->u.cfm_control.arg.cca_drop_connection.cdc_gen;
#if defined(LINUX_USER) || defined(WINDOWS_USER)
            disconn_eph.eph_ep_hdr = (struct com_ep_hdr *)
                                     cmd->u.cfm_control.arg.
                                                cca_drop_connection.cdc_eph;
            rna_dbg_log(RNA_DBG_MSG,
                        "Got drop message for EPH/EP [%p/%p/%d].  "
                        "Disconnecting\n",
                        (void *)cmd->u.cfm_control.arg.
                                                cca_drop_connection.cdc_eph,
                        com_get_ep_ptr((com_ep_handle_t *)
                            cmd->u.cfm_control.arg.cca_drop_connection.cdc_eph),
                        cmd->u.cfm_control.arg.cca_drop_connection.cdc_gen);
            com_disconnect((com_ep_handle_t *)&disconn_eph);
#else
            rna_dbg_log(RNA_DBG_MSG,
                        "Got drop message for EP [%p].  Disconnecting\n",
                        (void*)cmd->u.cfm_control.arg.
                                                cca_drop_connection.cdc_eph);
            com_disconnect((struct com_ep *)cmd->u.cfm_control.arg.
                           cca_drop_connection.cdc_eph);

#endif
            break;

        default:
            rna_dbg_log(RNA_DBG_WARN,
                        "Received unknown control type. %d\n",
                        control->type);
            break;
    }

    /* Release the reference that was added in work_queue_add_cfm(). */
    com_release_eph(&wctx->cwx_eph);    // (no-op at user level)
    
    mempool_free(ctx, MEMPOOL_ID_CFM_WORK_CTX, (void *)wctx);

    /*
     * Release the ctx reference that was added in work_queue_add_cfm.
     */
    ctx_release_reference(&ctx);

    /*
     * NOTE that rna_service workq callbacks must use
     * RNA_SERVICE_WORKQ_CB_RETURN instead of return.
     */
    RNA_SERVICE_WORKQ_CB_RETURN(0);
}


/**
 * Process a CONF_MGR_REG_BLOCK_DEVICE_RESP message
 * (client_block_device_reg_resp), which has been received from the
 * configuration manager as a reply to our CONF_MGR_REG_BLOCK_DEVICE message.
 */

static int
process_reg_block_device_resp(rna_service_ctx_t *ctx,
                              com_ep_handle_t   *eph,
                              struct cfm_cmd    *cmd)
{
    YAQ_LINK                     *e;
    rna_service_message_buffer_internal_t
                                 *ib, *ibuf;
    rna_service_message_buffer_t *orig_mbuf, *resp_mbuf;
    uint64_t                      msg_id;

    rna_service_assert(NULL != ctx);
    rna_service_assert(NULL != eph);
    rna_service_assert(NULL != cmd);
    // Get the message ID that was stuffed into the request's req_msg_id field
    // and returned in the response
    msg_id = cmd->u.client_block_device_reg_resp.req_msg_id;

    if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
        // This failure means we're in the process of shutting down; do nothing
        return (0);
    }

    /*
     * Find the message this response is a reply to.
     */
    ibuf = NULL;
    YAQ_FOREACH(&ctx->cx_registrations_waiting_for_reply, e) {
        ib = YAQ_OBJECT(rna_service_message_buffer_internal_t, h.rmbi_link, e);
        if (ib->h.rmbi_req_msg_id == msg_id) {
            ibuf = ib;
            break;
        }
    }
    if (NULL == ibuf) {
        /*
         * Possibly this is a late response from a CFM that has since died or
         * been demoted?
         */
        rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
        rna_dbg_log(RNA_DBG_VERBOSE,
                    "Received a response (id [%"PRIu64"]) to a "
                    "CONF_MGR_REG_BLOCK_DEVICE that we have no record of "
                    "having sent\n",
                    msg_id);
    } else {
        YAQ_REMOVE(&ibuf->h.rmbi_link);
        rna_service_timer_cancel(&ibuf->h.rmbi_response_timer_object);

        rna_dbg_log(RNA_DBG_INFO,
                    "device [%s] is now registered with CFM "
                    "["RNA_ADDR_FORMAT"]\n",
                    ibuf->u.rmbi_message_buffer.u.
                                        rmb_register_block_device.rbs_name,
                    RNA_ADDR(eph->eph_dst_in.sin_addr));

        if (MESSAGE_BUFFER_INTERNAL_WATERMARK_QUEUED != ibuf->h.rmbi_watermark)
        {
            rna_dbg_log(RNA_DBG_WARN,
                        "queued message has incorrect state [%"PRIx64"]\n",
                        ibuf->h.rmbi_watermark);
        }

        if (ibuf->u.rmbi_message_buffer.h.rmb_message_type !=
                                    RNA_SERVICE_MESSAGE_TYPE_REG_BLKDEV) {
            /* We've received the wrong type of response!  Again, this
             * shouldn't happen, and probably indicates corruption.
             */
            rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
            rna_dbg_log(RNA_DBG_WARN,
                        "Received a CONF_MGR_REG_BLOCK_DEVICE_RESP "
                        "apparently in response to a message of rna_service "
                        "type %d, ignoring\n",
                        ibuf->u.rmbi_message_buffer.h.rmb_message_type);
            ibuf->h.rmbi_watermark =
                                MESSAGE_BUFFER_INTERNAL_WATERMARK_ALLOCATED;
            rna_service_free_message_buffer(ctx, &ibuf->u.rmbi_message_buffer);
        } else if (NULL == ibuf->h.rmbi_response_callback) {
            queue_mount_or_blkdev_registration(ctx, ibuf);
            rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
        } else {
            /*
             * Before queuing this registered block device, make a copy of the
             * original registration message, to be handed as an argument to
             * the response callback routine.
             */
            orig_mbuf = rna_service_alloc_message_buffer(
                                ctx,
                                RNA_SERVICE_MESSAGE_TYPE_REG_BLKDEV,
                                ibuf->u.rmbi_message_buffer.u.
                                          rmb_register_block_device.rbs_name);
            if (NULL == orig_mbuf) {
                rna_dbg_log(RNA_DBG_WARN,
                            "Memory allocation failed!  Dropping "
                            "CONF_MGR_REG_BLOCK_DEVICE_RESP message\n");
                rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
                return (ENOMEM);
            }
            /* (copy the response callback, so we can invoke it below) */
            (mbuf_to_ibuf(orig_mbuf))->h.rmbi_response_callback =
                                                ibuf->h.rmbi_response_callback;
            orig_mbuf->h = ibuf->u.rmbi_message_buffer.h;
            orig_mbuf->u.rmb_register_block_device =
                    ibuf->u.rmbi_message_buffer.u.rmb_register_block_device;
            /*
             * (NOTE that it's important not to use strncpy with a PATHNAME_LEN
             * limit here, since strncpy fills the remainder of the destination
             * buffer with nulls, but the destination buffer is variable-sized,
             * and has been allocated to be only as large as the string to be
             * copied in).
             */
            strcpy(orig_mbuf->u.rmb_register_block_device.rbs_name,
                   ibuf->u.rmbi_message_buffer.u.rmb_register_block_device.
                                                                    rbs_name);

            /*
             * Now that we've finished copying from it, queue the registered
             * device.  But before doing so, clear rmbi_response_callback, so
             * callbacks won't be invoked after re-registrations, which is
             * correct behavior.
             */
            ibuf->h.rmbi_response_callback = NULL;
            queue_mount_or_blkdev_registration(ctx, ibuf);

            /*
             * Don't hold the cx_cfm_mutex across the response callback.
             */
            rna_service_mutex_unlock(&ctx->cx_cfm_mutex);

            /*
             * Create an rna_service version of the response, to pass back to
             * the response callback.
             */
            resp_mbuf = rna_service_alloc_message_buffer(
                                ctx,
                                RNA_SERVICE_MESSAGE_TYPE_REG_BLKDEV_RESPONSE,
                                NULL);
            if (NULL == resp_mbuf) {
                rna_dbg_log(RNA_DBG_WARN,
                            "Memory allocation failed!  Dropping "
                            "CONF_MGR_REG_BLOCK_DEVICE_RESP message\n");
                return (ENOMEM);
            }

            resp_mbuf->h.rmb_message_type =
                                RNA_SERVICE_MESSAGE_TYPE_REG_BLKDEV_RESPONSE;
            /*
             * Convert the response message received to an
             * rna_service_register_block_device_response_t to be given to the
             * user.
             */
            resp_mbuf->u.rmb_register_block_device_response =
                                   cmd->u.client_block_device_reg_resp.rnas;

            /*
             * Pass the ack on to the user, using the user's response callback.
             * The user is responsible for freeing both message buffers.
             *
             * If the user has specified that the work queue isn't to be used
             * (presumably for performance reasons), then invoke the user's
             * callback directly.  Otherwise, hand the invocation off to a
             * workq thread.
             */
            if (ctx->cx_params.rsp_flags & RNA_SERVICE_FLAG_NO_WORKQ) {
                /* Don't invoke any callbacks if we're shutting down. */
                if (!(ctx->cx_flags & CX_FLAG_SHUTTING_DOWN)) {
                    (mbuf_to_ibuf(orig_mbuf))->h.rmbi_response_callback(
                                      ctx,
                                      orig_mbuf,
                                      resp_mbuf,
                                      RNA_SERVICE_RESPONSE_STATUS_SUCCESS);
                }
            } else {
                work_queue_add_callback(ctx,
                                        mbuf_to_ibuf(orig_mbuf),
                                        resp_mbuf,
                                        RNA_SERVICE_EVENT_NONE);
            }
        }
    }

    return (0);
}

/**
 * Process a CONF_MGR_REG_CLIENT_RESP message
 * (cfm_client_resp), which has been received from the
 * configuration manager in response to registration request from
 * client
 */
static int
process_conf_mgr_reg_client_resp(rna_service_ctx_t *ctx,
                            com_ep_handle_t   *eph,
                            struct cfm_cmd    *cmd)
{
    rna_service_message_buffer_t *mbuf;

#if defined(WINDOWS_KERNEL) && !(defined(DBG))
    DECLARE_UNUSED(eph);
#endif

    rna_service_assert(NULL != ctx);
    rna_service_assert(NULL != eph);
    rna_service_assert(NULL != cmd);

    if ((NULL == ctx->cx_params.rsp_async_msg_callback)
        || (ctx->cx_flags & CX_FLAG_SHUTTING_DOWN)) {
        /* Bail out */
        return (0);
    }

    mbuf = rna_service_alloc_message_buffer(
                                        ctx,
                                        RNA_SERVICE_MESSAGE_TYPE_CONF_MGR_REG_RESPONSE,
                                        NULL);
    if (NULL == mbuf) {
        rna_dbg_log(RNA_DBG_ERR,
                    "Memory allocation failed!  Dropping "
                    "CONF_MGR_REG_CLIENT_RESP message\n");
        return (ENOMEM);
    }

    mbuf->h.rmb_message_type = RNA_SERVICE_MESSAGE_TYPE_CONF_MGR_REG_RESPONSE;
    mbuf->u.rmb_cfm_client_resp.per_device_connections = 
                        cmd->u.cfm_client_resp.per_device_connections;
    mbuf->u.rmb_cfm_client_resp.default_block_size = 
                        cmd->u.cfm_client_resp.default_block_size;

    if (ctx->cx_params.rsp_flags & RNA_SERVICE_FLAG_NO_WORKQ) {
        /* Don't invoke any callbacks if we're shutting down. */
        if (ctx->cx_flags & CX_FLAG_SHUTTING_DOWN) {
            rna_service_free_message_buffer(ctx, mbuf);
        } else {
            ctx->cx_params.rsp_async_msg_callback(ctx, mbuf);
        }
    } else {
        work_queue_add_callback(ctx, NULL, mbuf, RNA_SERVICE_EVENT_NONE);
    }

    return (0);
}


/**
 * Process a CONF_MGR_BLOCK_DEVICE_CREATE message
 * (client_block_device_reg_resp), which has been received from the
 * configuration manager
 */
static int
process_create_block_device(rna_service_ctx_t *ctx,
                            com_ep_handle_t   *eph,
                            struct cfm_cmd    *cmd)
{
    rna_service_message_buffer_t *mbuf;

#if defined(WINDOWS_KERNEL) && !(defined(DBG))
    DECLARE_UNUSED(eph);
#endif

    rna_service_assert(NULL != ctx);
    rna_service_assert(NULL != eph);
    rna_service_assert(NULL != cmd);

    if ((NULL == ctx->cx_params.rsp_async_msg_callback)
        || (ctx->cx_flags & CX_FLAG_SHUTTING_DOWN)) {
        /* Bail out */
        return (0);
    }

    mbuf = rna_service_alloc_message_buffer(
                                        ctx,
                                        RNA_SERVICE_MESSAGE_TYPE_CREATE_BLKDEV,
                                        cmd->u.client_create_block_device.name);
    if (NULL == mbuf) {
        rna_dbg_log(RNA_DBG_WARN,
                    "Memory allocation failed!  Dropping "
                    "CONF_MGR_BLOCK_DEVICE_CREATE message\n");
        return (ENOMEM);
    }

    mbuf->h.rmb_message_type = RNA_SERVICE_MESSAGE_TYPE_CREATE_BLKDEV;
    mbuf->u.rmb_create_block_device.cbs_capacity =
                        cmd->u.client_create_block_device.capacity;
    mbuf->u.rmb_create_block_device.cookie =
                        cmd->h.h_cookie;
    mbuf->u.rmb_create_block_device.cbs_cache_block_size =
                                cmd->u.client_create_block_device.default_block_size;
    mbuf->u.rmb_create_block_device.cbs_das =
                        cmd->u.client_create_block_device.ccb_das;
    mbuf->u.rmb_create_block_device.cbs_master_block_id =
                        cmd->u.client_create_block_device.ccb_master_block_id;
    mbuf->u.rmb_create_block_device.cbs_thin_status =
                        cmd->u.client_create_block_device.thin_status;
    mbuf->u.rmb_create_block_device.cbs_shared =
                        cmd->u.client_create_block_device.shared;
    mbuf->u.rmb_create_block_device.cbs_persist_access_uid =
                        cmd->u.client_create_block_device.persist_access_uid;
    mbuf->u.rmb_create_block_device.cbs_persist_access_gid =
                        cmd->u.client_create_block_device.persist_access_gid;
    mbuf->u.rmb_create_block_device.cbs_target_read_referenced_blocks =
                       cmd->u.client_create_block_device.read_ref_block_target;
    mbuf->u.rmb_create_block_device.cbs_target_referenced_blocks =
                       cmd->u.client_create_block_device.ref_block_target;
    mbuf->u.rmb_create_block_device.cbs_target_write_referenced_blocks =
                       cmd->u.client_create_block_device.write_ref_block_target;
    mbuf->u.rmb_create_block_device.cbs_max_referenced_blocks =
                       cmd->u.client_create_block_device.ref_block_limit;
    mbuf->u.rmb_create_block_device.cbs_max_read_referenced_blocks =
                       cmd->u.client_create_block_device.read_ref_block_limit;
    mbuf->u.rmb_create_block_device.cbs_max_write_referenced_blocks =
                       cmd->u.client_create_block_device.write_ref_block_limit;
    mbuf->u.rmb_create_block_device.cbs_path_md_policy =
                       cmd->u.client_create_block_device.path_md_policy;
    strncpy(mbuf->u.rmb_create_block_device.cbs_persist_location,
            cmd->u.client_create_block_device.persist_location,
            MIN(sizeof(mbuf->u.rmb_create_block_device.cbs_persist_location),
                sizeof(cmd->u.client_create_block_device.persist_location)));
    strncpy(mbuf->u.rmb_create_block_device.cbs_class_name,
            cmd->u.client_create_block_device.class_name,
            MIN(sizeof(mbuf->u.rmb_create_block_device.cbs_class_name),
                sizeof(cmd->u.client_create_block_device.class_name)));
    strncpy(mbuf->u.rmb_create_block_device.cbs_class_params,
            cmd->u.client_create_block_device.class_params,
            MIN(sizeof(mbuf->u.rmb_create_block_device.cbs_class_params),
                sizeof(cmd->u.client_create_block_device.class_params)));
    strcpy(mbuf->u.rmb_create_block_device.cbs_name,
           cmd->u.client_create_block_device.name);

    /*
     * If the user has specified that the work queue isn't to be used
     * (presumably for performance reasons), then invoke the user's
     * callback directly.  Otherwise, hand the invocation off to a
     * workq thread.
     */
    if (ctx->cx_params.rsp_flags & RNA_SERVICE_FLAG_NO_WORKQ) {
        /* Don't invoke any callbacks if we're shutting down. */
        if (ctx->cx_flags & CX_FLAG_SHUTTING_DOWN) {
            rna_service_free_message_buffer(ctx, mbuf);
        } else {
            ctx->cx_params.rsp_async_msg_callback(ctx, mbuf);
        }
    } else {
        work_queue_add_callback(ctx, NULL, mbuf, RNA_SERVICE_EVENT_NONE);
    }

    /* Remember that at least one block device has been created. */
    if (rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
        ctx->cx_cfm_flags |= CTX_CFM_FLAG_BLOCK_DEVICES_CREATED;
        rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
    }

    return (0);
}

/**
 * Process a CONF_MGR_BLOCK_DEVICE_CONTROL message
 * (client_control_block_device), which has been received from the
 * configuration manager
 */
static int
process_control_block_device(rna_service_ctx_t *ctx,
                            com_ep_handle_t   *eph,
                            struct cfm_cmd    *cmd)
{
    rna_service_message_buffer_t *mbuf;

#if defined(WINDOWS_KERNEL) && !(defined(DBG))
    DECLARE_UNUSED(eph);
#endif

    rna_service_assert(NULL != ctx);
    rna_service_assert(NULL != eph);
    rna_service_assert(NULL != cmd);

    if ((NULL == ctx->cx_params.rsp_async_msg_callback)
        || (ctx->cx_flags & CX_FLAG_SHUTTING_DOWN)) {
        /* Bail out */
        return (0);
    }

    mbuf = rna_service_alloc_message_buffer(
                                    ctx,
                                    RNA_SERVICE_MESSAGE_TYPE_CONTROL_BLKDEV,
                                    cmd->u.client_control_block_device.name);
    if (NULL == mbuf) {
        rna_dbg_log(RNA_DBG_WARN,
                    "Memory allocation failed!  Dropping "
                    "CONF_MGR_BLOCK_DEVICE_CONTROL message\n");
        return (ENOMEM);
    }

    mbuf->h.rmb_message_type = RNA_SERVICE_MESSAGE_TYPE_CONTROL_BLKDEV;
    mbuf->u.rmb_control_block_device.cbs_cookie = cmd->h.h_cookie;
    mbuf->u.rmb_control_block_device.cbs_type =
                                    cmd->u.client_control_block_device.type;
    strcpy(mbuf->u.rmb_control_block_device.cbs_name,
           cmd->u.client_control_block_device.name);

    /*
     * If the user has specified that the work queue isn't to be used
     * (presumably for performance reasons), then invoke the user's
     * callback directly.  Otherwise, hand the invocation off to a
     * workq thread.
     */
    if (ctx->cx_params.rsp_flags & RNA_SERVICE_FLAG_NO_WORKQ) {
        /* Don't invoke any callbacks if we're shutting down. */
        if (ctx->cx_flags & CX_FLAG_SHUTTING_DOWN) {
            rna_service_free_message_buffer(ctx, mbuf);
        } else {
            ctx->cx_params.rsp_async_msg_callback(ctx, mbuf);
        }
    } else {
        work_queue_add_callback(ctx, NULL, mbuf, RNA_SERVICE_EVENT_NONE);
    }

    return (0);
}

/**
 * Invoked by a workq thread to process a CONF_MGR_CONTROL_CS message.
 */
static rna_service_workq_cb_ret_t
process_control_cs(rna_service_workq_cb_arg_t workq_context)
{
    cfm_work_ctx_t *wctx = (cfm_work_ctx_t *)workq_context;
    rna_service_ctx_t *ctx;
    struct cfm_cmd *cmd;
    com_ep_handle_t *cfm_eph;
    rna_service_message_buffer_t *mbuf;

    rna_service_assert(NULL != wctx);
    ctx = wctx->cwx_ctx;
    rna_service_assert(NULL != ctx);
    cmd = &wctx->cwx_cmd;
    rna_service_assert(NULL != cmd);
    cfm_eph = &wctx->cwx_eph;
    rna_service_assert(NULL != cfm_eph);

    rna_trace("incoming ["RNA_ADDR_FORMAT"] type [%s] sub-type [%d]\n",
        RNA_ADDR(cfm_eph->eph_dst_in.sin_addr), get_cmd_type_string(cmd->h.h_type),
        cmd->u.control_cs.rnas.ccs_type);

    if ((NULL == ctx->cx_params.rsp_async_msg_callback)
        || (ctx->cx_flags & CX_FLAG_SHUTTING_DOWN)) {
        /* Bail out */
        RNA_SERVICE_WORKQ_CB_RETURN(0);
    }

    mbuf = rna_service_alloc_message_buffer(
                                        ctx,
                                        RNA_SERVICE_MESSAGE_TYPE_CONTROL_CS,
                                        NULL);

    if (NULL == mbuf) {
        rna_dbg_log(RNA_DBG_WARN,
                    "Memory allocation failed!  Dropping "
                    "CONF_MGR_CONTROL_CS message\n");
        RNA_SERVICE_WORKQ_CB_RETURN(ENOMEM);
    }

    mbuf->h.rmb_message_type = RNA_SERVICE_MESSAGE_TYPE_CONTROL_CS;
    mbuf->u.rmb_control_cs = cmd->u.control_cs.rnas;
    mbuf->u.rmb_control_cs.ccs_cookie = cmd->h.h_cookie;

    /*
     * RNA_SERVICE must observe the cache_enable change.
     * If the CS is being disabled and it happens to reconnect to a MD
     * then change its status so it will register as unavailable.
     */
    if (CS_CONTROL_TYPE_ENABLE_DISABLE == cmd->u.control_cs.rnas.ccs_type) {
        if (0 == cmd->u.control_cs.rnas.u.ccs_cache_enable) {
            ctx->cx_cs_params.csp_cs_status = CACHE_UNAVAILABLE;
        } else {
            ctx->cx_cs_params.csp_cs_status = CACHE_AVAILABLE;
        }
    }

    /* Invoke callback */
    ctx->cx_params.rsp_async_msg_callback(ctx, mbuf);

    /* Release the reference that was added in work_queue_add_control_cs(). */
    com_release_eph(&wctx->cwx_eph);    // (no-op at user level)

    mempool_free(ctx, MEMPOOL_ID_CFM_WORK_CTX, (void *)wctx);

    /*
     * Release the ctx reference that was added in work_queue_add_control_cs.
     */
    ctx_release_reference(&ctx);

    /*
     * NOTE that rna_service workq callbacks must use
     * RNA_SERVICE_WORKQ_CB_RETURN instead of return.
     */
    RNA_SERVICE_WORKQ_CB_RETURN(0);
}

/**
 * Process a response message from an MD.
 */
static int
process_md_response(rna_service_ctx_t *ctx,
                    com_ep_handle_t   *eph,
                    struct cache_cmd  *cmd)
{
    int                           partition;
    YAQ_LINK                     *e;
    uint64_t                      msg_id;
    rna_service_message_buffer_t *mbuf;
    rna_service_message_buffer_internal_t
                                 *ib, *ibuf;

    rna_service_assert(NULL != ctx);
    rna_service_assert(NULL != eph);
    rna_service_assert(NULL != cmd);

    /*
     * Get the message ID that was stuffed into the request's req_msg_id field
     * and returned in the response
     */
    switch (cmd->h.h_type) {
        case CACHE_INVD_REP:
            msg_id = cmd->u.cache_invd.req_msg_id;
            break;

        case META_DATA_RESPONSE:
            msg_id = cmd->u.md_rep.req_msg_id;
            break;

        case CACHE_RESPONSE_RESPONSE:
            msg_id = cmd->u.cache_req.cq_msg_id;
            break;

        case CACHE_QUERY_REQ_RESPONSE:
            msg_id = cmd->u.cache_req.cq_msg_id;
            break;

        case CACHE_ABSORB_BLOCK_RESP:
            msg_id = cmd->u.cache_absorb_block_resp.cabr_msg_id;
            break;

        default:
            rna_dbg_log(RNA_DBG_ERR,
                        "Unexpected message type %s, ignoring\n",
                        get_cmd_type_string(cmd->h.h_type));
            return (-1);
    }

    /*
     * Find the message this response is a reply to.  For MD messages, the
     * partition number is in the high-order 32 bits of the message ID.
     */
    partition = MD_MSG_ID_TO_PARTITION(msg_id);

    if (!rna_service_mutex_lock(&ctx->cx_md_mutex)) {
        // This failure means we're in the process of shutting down; do nothing
        return (0);
    }

    ibuf = NULL;
    YAQ_FOREACH(&ctx->cx_partitions[partition].pi_waiting_for_reply, e) {
        ib = YAQ_OBJECT(rna_service_message_buffer_internal_t, h.rmbi_link, e);
        if (ib->h.rmbi_req_msg_id == msg_id) {
            ibuf = ib;
            break;
        }
    }
    if (NULL == ibuf) {
        /*
         * There's a very slight chance the message is in the 'waiting to send'
         * list, if this is a late response from the previous MD after the
         * partition has been assigned to a new MD.
         */
        YAQ_FOREACH(&ctx->cx_partitions[partition].pi_waiting_to_send, e)
        {
            ib = YAQ_OBJECT(rna_service_message_buffer_internal_t,
                            h.rmbi_link,
                            e);
            if (ib->h.rmbi_req_msg_id == msg_id) {
                ibuf = ib;
                break;
            }
        }
    }
    if (NULL == ibuf) {
        /*
         * Most likely, this happened because this partition was reassigned and
         * we've received responses from both the old and the new MD.  In more
         * detail, we hadn't yet received a response from the old MD at the
         * time the partition was reassigned, so we re-sent the query to the
         * new MD.  However, a response from the old MD may still arrive after
         * that point, giving us two responses for the same query.  It's not a
         * problem, since the responses should be identical (due to paxos
         * mirroring).
         */
        rna_service_mutex_unlock(&ctx->cx_md_mutex);
        rna_dbg_log(RNA_DBG_VERBOSE,
                    "Received a message of type [%s] message id "
                    "[%"PRIx64"] from ["RNA_ADDR_FORMAT"] as a response to a "
                    "message that we have no record of having sent -- possibly "
                    "the result of a partition reassignment\n",
                    get_cmd_type_string(cmd->h.h_type), msg_id,
                    RNA_ADDR(eph->eph_dst_in.sin_addr));
    } else {
        YAQ_REMOVE(&ibuf->h.rmbi_link);
        rna_service_timer_cancel(&ibuf->h.rmbi_response_timer_object);
        if (--ctx->cx_partitions[partition].pi_msgs_outstanding_cnt < 0) {
            rna_dbg_log(RNA_DBG_WARN,
                        "msgs_outstanding_cnt underflow for partition "
                        "%d!\n",
                        partition);
            ctx->cx_partitions[partition].pi_msgs_outstanding_cnt = 0;
        }

        rna_service_mutex_unlock(&ctx->cx_md_mutex);


        if (MESSAGE_BUFFER_INTERNAL_WATERMARK_QUEUED != ibuf->h.rmbi_watermark)
        {
            rna_dbg_log(RNA_DBG_WARN,
                        "queued message has incorrect state: %"PRIx64"\n",
                        ibuf->h.rmbi_watermark);
        }
        ibuf->h.rmbi_watermark = MESSAGE_BUFFER_INTERNAL_WATERMARK_ALLOCATED;

        rna_dbg_log(RNA_DBG_VERBOSE, //INFO,
                    "received [%s] message ID [%"PRIx64"] [%"PRIx64"] "
                    "from ["RNA_ADDR_FORMAT"]\n",
                    get_cmd_type_string(cmd->h.h_type),
                    msg_id,
                    ibuf->h.rmbi_req_msg_id,
                    RNA_ADDR(eph->eph_dst_in.sin_addr));

        if (CACHE_QUERY_REQ_RESPONSE == cmd->h.h_type) {
            /*
             * We cheat for these messages, and simply pass along a pointer to
             * the cache_cmd.
             *
             * Invoke the cache server's asynchronous message callback.
             */
            ctx->cx_cs_params.csp_cs_async_msg_callback(ctx, cmd);
            /* We're responsible for freeing the request message in this case */
            rna_service_free_message_buffer(ctx, &ibuf->u.rmbi_message_buffer);
        } else if (NULL == ibuf->h.rmbi_response_callback) {
            /*
             * The user hasn't requested a response callback, so we're finished
             * with this message.
             */
            rna_service_free_message_buffer(ctx, &ibuf->u.rmbi_message_buffer);
        } else {
            /*
             * Pass the ack on to the user, using the user's response callback.
             * The user is responsible for freeing both message buffers.
             */
            switch (cmd->h.h_type) {
            case CACHE_INVD_REP:
                mbuf = rna_service_alloc_message_buffer(
                                ctx,
                                RNA_SERVICE_MESSAGE_TYPE_CACHE_INVD_RESPONSE,
                                NULL);
                if (NULL == mbuf) {
                    rna_dbg_log(RNA_DBG_WARN,
                                "Memory allocation failed!  Dropping "
                                "CACHE_INVD_REP message\n");
                    return (ENOMEM);
                }
                mbuf->h.rmb_message_type =
                                RNA_SERVICE_MESSAGE_TYPE_CACHE_INVD_RESPONSE;
                break;

            case META_DATA_RESPONSE:
                mbuf = rna_service_alloc_message_buffer(
                                ctx,
                                RNA_SERVICE_MESSAGE_TYPE_MD_QUERY_RESPONSE,
                                NULL);
                if (NULL == mbuf) {
                    rna_dbg_log(RNA_DBG_WARN,
                                "Memory allocation failed!  Dropping "
                                "CACHE_INVD_REP message\n");
                    return (ENOMEM);
                }
                mbuf->h.rmb_message_type =
                                RNA_SERVICE_MESSAGE_TYPE_MD_QUERY_RESPONSE;
                /*
                 * Convert the response message received to an
                 * rna_service_metadata_query_response_t to be given to the
                 * user.
                 */
                mbuf->u.rmb_metadata_query_response = cmd->u.md_rep.rnas;
                mbuf->u.rmb_metadata_query_response.mqr_error = cmd->h.h_error;
                mbuf->u.rmb_metadata_query_response.mqr_cookie =
                                                               cmd->h.h_cookie;
                break;

            case CACHE_ABSORB_BLOCK_RESP:
                mbuf = rna_service_alloc_message_buffer(
                          ctx,
                          RNA_SERVICE_MESSAGE_TYPE_ABSORB_BLOCK_RESPONSE,
                          NULL);
                if (NULL == mbuf) {
                    rna_dbg_log(RNA_DBG_WARN,
                                "Memory allocation failed!  Dropping "
                                "CACHE_INVD_REP message\n");
                    return (ENOMEM);
                }
                mbuf->h.rmb_message_type =
                                RNA_SERVICE_MESSAGE_TYPE_ABSORB_BLOCK_RESPONSE;
                mbuf->u.rmb_cache_absorb_block_response =
                                cmd->u.cache_absorb_block_resp.rnas;
                break;

            default:
                rna_dbg_log(RNA_DBG_ERR,
                            "Unexpected message type %s, ignoring\n",
                            get_cmd_type_string(cmd->h.h_type));
                return (-1);
            }

            /*
             * If the user has specified that the work queue isn't to be used
             * (presumably for performance reasons), then invoke the user's
             * callback directly.  Otherwise, hand the invocation off to a
             * workq thread.
             */
            if (ctx->cx_params.rsp_flags & RNA_SERVICE_FLAG_NO_WORKQ) {
                /* Don't invoke any callbacks if we're shutting down. */
                if (!(ctx->cx_flags & CX_FLAG_SHUTTING_DOWN)) {
                    rna_dbg_log(RNA_DBG_INFO,
                                "invoking callback for [%s] "
                                "message ID [%"PRIx64"] [%"PRIx64"] "
                                "from ["RNA_ADDR_FORMAT"]\n",
                                get_cmd_type_string(cmd->h.h_type),
                                msg_id,
                                ibuf->h.rmbi_req_msg_id,
                                RNA_ADDR(eph->eph_dst_in.sin_addr));
                    ibuf->h.rmbi_response_callback(
                                        ctx,
                                        &ibuf->u.rmbi_message_buffer,
                                        mbuf,
                                        RNA_SERVICE_RESPONSE_STATUS_SUCCESS);
                }
            } else {
                work_queue_add_callback(ctx,
                                        ibuf,
                                        mbuf,
                                        RNA_SERVICE_EVENT_NONE);
            }
        }
    }

    return (0);
}


/**
 * Process a CACHE_REGISTER_RESPONSE message (cache_reg_resp), which has been
 * received from a metadata server as a reply to our CACHE_REGISTER message.
 */
static void
process_md_cache_register_response(rna_service_ctx_t *ctx,
                                   com_ep_handle_t   *eph,
                                   struct cache_cmd  *cmd)
{
    md_info_t *mdi;

    // (legacy comment from cache.c:)
    // TODO: Set data. 
    // NOTE: Verify that no slabs have yet been allocated.. It is *possible*
    // that this response message is processed out of order, and as such a
    // client *could* have connected and requested a cache block. Highly
    // improbable though.

    rna_dbg_log(RNA_DBG_INFO,
                "MD register response: status[%d] block_size[%"PRId64"] "
                "block_threshold[%"PRId64"] ep [%p] ping_rkey [0x%"PRIx64"] "
                "ping_buf [0x%"PRIx64":%"PRIx64"] current CS membership gen "
                "[%"PRId64"]\n",
                cmd->u.cache_reg_resp.status, 
                cmd->u.cache_reg_resp.block_size, 
                cmd->u.cache_reg_resp.block_threshold, 
                com_get_ep_ptr(eph),
                cmd->u.cache_reg_resp.ping_rkey, 
                cmd->u.cache_reg_resp.ping_buf.device_id.data,
                cmd->u.cache_reg_resp.ping_buf.base_addr,
                cmd->u.cache_reg_resp.crr_cs_membership_generation);

    /*
     * If this is a cache server and its MD registration request has been
     * rejected, it's because this cache server has been expelled from the
     * cluster.  Tell it that it needs to kill itself.
     */
    if ((RNA_SERVICE_USER_TYPE_CACHE_SERVER == ctx->cx_params.rsp_user_type)
      && (cmd->u.cache_reg_resp.status != 0)) {
        rna_dbg_log(RNA_DBG_INFO,
                    "MD registration refused, our generation number "
                    "[%"PRId64"] current generation number [%"PRId64"]\n",
                    ctx->cx_cs_membership_generation,
                    cmd->u.cache_reg_resp.crr_cs_membership_generation);
        ctx->cx_params.rsp_event_callback(ctx,
                                          RNA_SERVICE_EVENT_KILL_SELF_RESTART);
        return;
    }

    if (!rna_service_mutex_lock(&ctx->cx_md_mutex)) {
        // This failure means we're in the process of shutting down; do nothing
        return;
    }
    mdi = find_md_by_eph(ctx, eph);
    if (NULL == mdi) {
        rna_dbg_log(RNA_DBG_INFO, 
                    "Registration response from unknown MD EP [%p]\n", 
                    com_get_ep_ptr(eph));
    } else {
        rna_service_ping_remote_ctx_init(eph, 
                                         &mdi->mdi_remote_ping_ctx,
                                         &mdi->mdi_ping_data,
                                         sizeof(mdi->mdi_ping_data),
                                         cmd);
        /*
         * If we were waiting for the registration to be accepted before
         * sending any other messages, they can now be sent.
         */
        if (mdi->mdi_cflags & MD_INFO_CFLAG_AWAIT_REGISTRATION_RESPONSE) {
            mdi->mdi_cflags &= ~MD_INFO_CFLAG_AWAIT_REGISTRATION_RESPONSE;
            schedule_waiting_md_msgs(ctx, mdi, 0);
        }
    }
    rna_service_mutex_unlock(&ctx->cx_md_mutex);
}


/**
 * Process a CONF_MGR_REG_CACHE_RESPONSE message (cache_cfm_reg_resp), which
 * has been received from the primary CFM as a reply to our CONF_MGR_REG_CACHE
 * message.
 */
static void
process_cfm_cache_register_response(rna_service_ctx_t *ctx,
                                    com_ep_handle_t   *eph,
                                    struct cfm_cmd    *cmd)
{
    UNREFERENCED_PARAMETER(eph);

    if (cmd->h.h_type == CONF_MGR_REG_CACHE_RESPONSE_V2) {
        rna_dbg_log(RNA_DBG_INFO,
                    "CFM register response V2: status [%d] "
                    "current CS membership gen [%"PRId64"] "
                    "service ID ["rna_service_id_format"] "
                    "partitions [%d]\n",
                    cmd->u.cache_cfm_reg_resp_V2.ccrr_status, 
                    cmd->u.cache_cfm_reg_resp_V2.ccrr_cs_membership_generation,
                    rna_service_id_get_string(
                        &cmd->u.cache_cfm_reg_resp_V2.ccrr_service_id),
                    cmd->u.cache_cfm_reg_resp_V2.ccrr_num_md_hash_partitions);
    } else {
        rna_dbg_log(RNA_DBG_INFO,
                    "CFM register response: status [%d] "
                    "current CS membership gen [%"PRId64"] "
                    "partitions [%d]\n",
                    cmd->u.cache_cfm_reg_resp.ccrr_status,
                    cmd->u.cache_cfm_reg_resp.ccrr_cs_membership_generation,
                    cmd->u.cache_cfm_reg_resp.ccrr_num_md_hash_partitions);
    }

    /*
     * If this is a cache server and its registration request has been
     * rejected by the primary CFM, it's either because this cache server
     * has been expelled from the cluster or because this cache server
     * doesn't belong to the cluster (cluster ID mismatch).  Tell it that
     * it needs to kill itself.
     */
    if (RNA_SERVICE_USER_TYPE_CACHE_SERVER == ctx->cx_params.rsp_user_type) {

        /*
         * reset the cfm timer now that we've received the
         * registration response
         */
        if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
            /* This failure means we're in the process of shutting down */
            return;
        }

        rna_service_timer_cancel(&ctx->cx_primary_cfm_registration_timer);
        ctx->cx_cfm_flags &= ~CTX_CFM_FLAG_REGISTRATION_TIMER_SET;
        rna_dbg_log(RNA_DBG_INFO,
                    "Cancelled primary cfm registration timer\n");

        rna_service_mutex_unlock(&ctx->cx_cfm_mutex);

        // Handle the V2 cache sserver registration response from the cfm
        if (cmd->h.h_type == CONF_MGR_REG_CACHE_RESPONSE_V2) {
            if (CFM_REG_RESP_OK == cmd->u.cache_cfm_reg_resp_V2.ccrr_status) {
                /*
                 * If the CFM has assigned us an instance ID, accept it (this will
                 * be the case if we're newly started).
                 */
                if (cmd->u.cache_cfm_reg_resp_V2.ccrr_service_id.start_time !=
                                        ctx->cx_params.rsp_service_id.start_time) {
                    rna_service_message_buffer_t *mbuf;
    
                    ctx->cx_params.rsp_service_id.start_time =
                        cmd->u.cache_cfm_reg_resp_V2.ccrr_service_id.start_time;
                    ctx->cx_cs_membership_generation =
                        cmd->u.cache_cfm_reg_resp_V2.ccrr_cs_membership_generation;
                    rna_dbg_log(RNA_DBG_VERBOSE,
                                "updated cs membership generation number\n");
                    if ((NULL == ctx->cx_params.rsp_async_msg_callback)
                        || (ctx->cx_flags & CX_FLAG_SHUTTING_DOWN)) {
                        /* Bail out */
                        return;
                    }
                    /*
                     * Report the instance ID assigned by the CFM (embedded in the
                     * service ID) and the number of MD has partitions up to the CS
                     */
                    mbuf = rna_service_alloc_message_buffer(
                        ctx,
                        RNA_SERVICE_MESSAGE_TYPE_NUM_MD_HASH_PARTITIONS,
                        NULL);
                    if (NULL == mbuf) {
                        rna_dbg_log(RNA_DBG_WARN,
                                    "Memory allocation failed!  Dropping "
                                    "CONF_MGR_BSTAT_REQ message\n");
                        return;
                    }
                    mbuf->h.rmb_message_type = 
                        RNA_SERVICE_MESSAGE_TYPE_NUM_MD_HASH_PARTITIONS;
                    mbuf->u.rmb_num_partitions.np_service_id = 
                        cmd->u.cache_cfm_reg_resp_V2.ccrr_service_id;
                    mbuf->u.rmb_num_partitions.np_num_partitions = 
                        cmd->u.cache_cfm_reg_resp_V2.ccrr_num_md_hash_partitions;
                    if (ctx->cx_params.rsp_flags & RNA_SERVICE_FLAG_NO_WORKQ) {
                        /* Don't invoke any callbacks if we're shutting down. */
                        if (ctx->cx_flags & CX_FLAG_SHUTTING_DOWN) {
                            rna_service_free_message_buffer(ctx, mbuf);
                        } else {
                            ctx->cx_params.rsp_async_msg_callback(ctx, mbuf);
                        }
                    } else {
                        work_queue_add_callback(ctx, NULL, mbuf, RNA_SERVICE_EVENT_NONE);
                    }
                }
    
                /*
                 * If we were waiting for the registration to be accepted before
                 * sending any other messages, they can now be sent.
                 */
                if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
                    /* This failure means we're in the process of shutting down */
                    return;
                }
                if (ctx->cx_cfm_flags & CTX_CFM_FLAG_AWAIT_REGISTRATION_RESPONSE) {
                    ctx->cx_cfm_flags &= ~CTX_CFM_FLAG_AWAIT_REGISTRATION_RESPONSE;
                    schedule_waiting_cfm_msgs(ctx, 0);
                }
                rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
            } else if (CFM_REG_RESP_RESTART ==
                                        cmd->u.cache_cfm_reg_resp_V2.ccrr_status) {
                rna_dbg_log(RNA_DBG_INFO,
                           "CFM registration refused: our generation number "
                           "[%"PRId64"] current generation number [%"PRId64"]\n",
                           ctx->cx_cs_membership_generation,
                           cmd->u.cache_cfm_reg_resp_V2.ccrr_cs_membership_generation);
                ctx->cx_params.rsp_event_callback(
                                            ctx,
                                            RNA_SERVICE_EVENT_KILL_SELF_RESTART);
            } else {
                rna_dbg_log(RNA_DBG_INFO,
                           "CFM registration refused with no restart allowed "
                           "(presumably due to a cluster ID mismatch)\n");
                ctx->cx_params.rsp_event_callback(
                                            ctx,
                                            RNA_SERVICE_EVENT_KILL_SELF_NO_RESTART);
            }
        // Handle the V1 cache sserver registration response from the cfm
        } else {
            if (CFM_REG_RESP_OK == cmd->u.cache_cfm_reg_resp.ccrr_status) {
                /*
                 * If the CFM has given us a new cs_membership_generation number,
                 * accept it (this will be the case if we're newly started).
                 */
                if (cmd->u.cache_cfm_reg_resp.ccrr_cs_membership_generation >
                                                ctx->cx_cs_membership_generation) {
                    rna_service_message_buffer_t *mbuf;
    
                    ctx->cx_cs_membership_generation =
                        cmd->u.cache_cfm_reg_resp.ccrr_cs_membership_generation;
                    rna_dbg_log(RNA_DBG_VERBOSE,
                                "updated cs membership generation number\n");
                    if ((NULL == ctx->cx_params.rsp_async_msg_callback)
                        || (ctx->cx_flags & CX_FLAG_SHUTTING_DOWN)) {
                        /* Bail out */
                        return;
                    }
                    /* Report the number of MD has partitions up to the CS */
                    mbuf = rna_service_alloc_message_buffer(
                        ctx,
                        RNA_SERVICE_MESSAGE_TYPE_NUM_MD_HASH_PARTITIONS,
                        NULL);
                    if (NULL == mbuf) {
                        rna_dbg_log(RNA_DBG_WARN,
                                    "Memory allocation failed!  Dropping "
                                    "CONF_MGR_BSTAT_REQ message\n");
                        return;
                    }
                    mbuf->h.rmb_message_type = 
                        RNA_SERVICE_MESSAGE_TYPE_NUM_MD_HASH_PARTITIONS;
                    mbuf->u.rmb_num_partitions.np_num_partitions = 
                        cmd->u.cache_cfm_reg_resp.ccrr_num_md_hash_partitions;

                    if (ctx->cx_params.rsp_flags & RNA_SERVICE_FLAG_NO_WORKQ) {
                        /* Don't invoke any callbacks if we're shutting down. */
                        if (ctx->cx_flags & CX_FLAG_SHUTTING_DOWN) {
                            rna_service_free_message_buffer(ctx, mbuf);
                        } else {
                            ctx->cx_params.rsp_async_msg_callback(ctx, mbuf);
                        }
                    } else {
                        work_queue_add_callback(ctx, NULL, mbuf, RNA_SERVICE_EVENT_NONE);
                    }
                }
    
                /*
                 * If we were waiting for the registration to be accepted before
                 * sending any other messages, they can now be sent.
                 */
                if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
                    /* This failure means we're in the process of shutting down */
                    return;
                }
                if (ctx->cx_cfm_flags & CTX_CFM_FLAG_AWAIT_REGISTRATION_RESPONSE) {
                    ctx->cx_cfm_flags &= ~CTX_CFM_FLAG_AWAIT_REGISTRATION_RESPONSE;
                    schedule_waiting_cfm_msgs(ctx, 0);
                }
                rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
            } else if (CFM_REG_RESP_RESTART ==
                                        cmd->u.cache_cfm_reg_resp.ccrr_status) {
                rna_dbg_log(RNA_DBG_INFO,
                           "CFM registration refused: our generation number "
                           "[%"PRId64"] current generation number [%"PRId64"]\n",
                           ctx->cx_cs_membership_generation,
                           cmd->u.cache_cfm_reg_resp.ccrr_cs_membership_generation);
                ctx->cx_params.rsp_event_callback(
                                            ctx,
                                            RNA_SERVICE_EVENT_KILL_SELF_RESTART);
            } else {
                rna_dbg_log(RNA_DBG_INFO,
                           "CFM registration refused with no restart allowed "
                           "(presumably due to a cluster ID mismatch)\n");
                ctx->cx_params.rsp_event_callback(
                                            ctx,
                                            RNA_SERVICE_EVENT_KILL_SELF_NO_RESTART);
            }
        }
    }
}


/*
 * Process a CACHE_QUERY, CACHE_DEREF, CACHE_MASTER_INVD, or CACHE_INVD_ANY
 * message that's been received, by invoking the user's asynchronous message
 * callback.
 */
static int 
process_cs_async_message(rna_service_ctx_t *ctx,
                         com_ep_handle_t   *eph,
                         void              *cmd) 
{
    rna_service_assert(NULL != ctx);
    rna_service_assert(NULL != cmd);

    UNREFERENCED_PARAMETER(eph);

    if ((NULL == ctx->cx_cs_params.csp_cs_async_msg_callback)
      || (ctx->cx_flags & CX_FLAG_SHUTTING_DOWN)) {
        /* Bail out */
        return (0);
    }

    /*
     * We cheat for these messages, and simply pass along a pointer to the
     * message.  A cache server can receive some of these messages from either
     * clients or MDs, so it already needs to know about the internal structure
     * of the message, so hiding it in an rna_service-defined message is
     * unnecessary.
     *
     * Invoke the cache server's asynchronous message callback.
     */
    ctx->cx_cs_params.csp_cs_async_msg_callback(ctx, cmd);
    return (0);
}

/*
 * send local CS data to the client.  This is used to support
 * single node (DAS) operation.  The rna_service_id and rna_if_table
 * information for the cache server that is on the same node as the client
 * is delivered via the async call back function specified in
 * rsp_async_msg_callback.
 */
static int
process_blk_async_message(rna_service_ctx_t *ctx,
                         com_ep_handle_t    *eph,
                         struct cfm_cmd     *cmd)
{
    rna_service_message_buffer_t *mbuf;

#if defined(WINDOWS_KERNEL) && !(defined(DBG))
    DECLARE_UNUSED(eph);
#endif

    rna_service_assert(NULL != ctx);
    rna_service_assert(NULL != eph);
    rna_service_assert(NULL != cmd);

    if ((NULL == ctx->cx_params.rsp_async_msg_callback)
      || (ctx->cx_flags & CX_FLAG_SHUTTING_DOWN)) {
        /* Bail out */
        return (0);
    }

    mbuf = rna_service_alloc_message_buffer(
                                        ctx,
                                        RNA_SERVICE_MESSAGE_TYPE_CS_CLIENT_REG,
                                        NULL);
    if (NULL == mbuf) {
        rna_dbg_log(RNA_DBG_WARN,
                    "Memory allocation failed!  Dropping "
                    "RNA_SERVICE_MESSAGE_TYPE_CS_CLIENT_REG message\n");
        return (ENOMEM);
    }

    mbuf->h.rmb_message_type = RNA_SERVICE_MESSAGE_TYPE_CS_CLIENT_REG;
    /*
     * Fill in the rmb_cache_client_connect data
     */
    mbuf->u.rmb_cache_client_reg.ccr_service_id =
                                cmd->u.cfm_service_reg.service_id;
    mbuf->u.rmb_cache_client_reg.ccr_if_table =
                                cmd->u.cfm_service_reg.csr_if_tbl;

    /*
     * If the user has specified that the work queue isn't to be used
     * (presumably for performance reasons), then invoke the user's
     * callback directly.  Otherwise, hand the invocation off to a
     * workq thread.
     */
    if (ctx->cx_params.rsp_flags & RNA_SERVICE_FLAG_NO_WORKQ) {
        /* Don't invoke any callbacks if we're shutting down. */
        if (ctx->cx_flags & CX_FLAG_SHUTTING_DOWN) {
            rna_service_free_message_buffer(ctx, mbuf);
        } else {
            ctx->cx_params.rsp_async_msg_callback(ctx, mbuf);
        }
    } else {
        work_queue_add_callback(ctx, NULL, mbuf, RNA_SERVICE_EVENT_NONE);
    }
    return (0);
}


/*
 * Process a CONF_MGR_EXPEL_CACHE_DEVICE: message received from the CFM.
 */
static int
process_expel_cache_device(rna_service_ctx_t *ctx,
                           com_ep_handle_t   *eph,
                           struct cfm_cmd    *cmd)
{
    rna_service_message_buffer_t *mbuf;

#if defined(WINDOWS_KERNEL) && !(defined(DBG))
    DECLARE_UNUSED(eph);
#endif

    rna_service_assert(NULL != ctx);
    rna_service_assert(NULL != eph);
    rna_service_assert(NULL != cmd);

    if ((NULL == ctx->cx_params.rsp_async_msg_callback)
      || (ctx->cx_flags & CX_FLAG_SHUTTING_DOWN)) {
        /* Bail out */
        return (0);
    }

    mbuf = rna_service_alloc_message_buffer(
                                ctx,
                                RNA_SERVICE_MESSAGE_TYPE_EXPEL_CACHE_DEVICE,
                                NULL);
    if (NULL == mbuf) {
        rna_dbg_log(RNA_DBG_WARN,
                    "Memory allocation failed!  Dropping "
                    "CONF_MGR_EXPEL_CACHE_DEVICE message\n");
        return (ENOMEM);
    }

    mbuf->h.rmb_message_type = RNA_SERVICE_MESSAGE_TYPE_EXPEL_CACHE_DEVICE;
    mbuf->u.rmb_expel_cache_device = cmd->u.cache_cfm_expel_cachedev.rnas;

    /*
     * If the user has specified that the work queue isn't to be used
     * (presumably for performance reasons), then invoke the user's
     * callback directly.  Otherwise, hand the invocation off to a
     * workq thread.
     */
    if (ctx->cx_params.rsp_flags & RNA_SERVICE_FLAG_NO_WORKQ) {
        /* Don't invoke any callbacks if we're shutting down. */
        if (ctx->cx_flags & CX_FLAG_SHUTTING_DOWN) {
            rna_service_free_message_buffer(ctx, mbuf);
        } else {
            ctx->cx_params.rsp_async_msg_callback(ctx, mbuf);
        }
    } else {
        work_queue_add_callback(ctx, NULL, mbuf, RNA_SERVICE_EVENT_NONE);
    }

    return (0);
}

/*
 * Process a CONF_MGR_UNEXPELLED_CACHEDEVS: message received from the CFM.
 */
static int
process_unexpelled_cachedevs(rna_service_ctx_t *ctx,
                             com_ep_handle_t   *eph,
                             struct cfm_cmd    *cmd)
{
    rna_service_message_buffer_t *mbuf;

#if defined(WINDOWS_KERNEL) && !(defined(DBG))
    DECLARE_UNUSED(eph);
#endif

    rna_service_assert(NULL != ctx);
    rna_service_assert(NULL != eph);
    rna_service_assert(NULL != cmd);

    if ((NULL == ctx->cx_params.rsp_async_msg_callback)
      || (ctx->cx_flags & CX_FLAG_SHUTTING_DOWN)) {
        /* Bail out */
        return (0);
    }

    mbuf = rna_service_alloc_message_buffer(
                                ctx,
                                RNA_SERVICE_MESSAGE_TYPE_UNEXPELLED_CACHEDEVS,
                                NULL);
    if (NULL == mbuf) {
        rna_dbg_log(RNA_DBG_WARN,
                    "Memory allocation failed!  Dropping "
                    "CONF_MGR_UNEXPELLED_CACHEDEVS message\n");
        return (ENOMEM);
    }

    mbuf->h.rmb_message_type = RNA_SERVICE_MESSAGE_TYPE_UNEXPELLED_CACHEDEVS;
    mbuf->u.rmb_unexpelled_cachedevs = cmd->u.cfm_unexpelled_cachedevs.uc;

    /*
     * If the user has specified that the work queue isn't to be used
     * (presumably for performance reasons), then invoke the user's
     * callback directly.  Otherwise, hand the invocation off to a
     * workq thread.
     */
    if (ctx->cx_params.rsp_flags & RNA_SERVICE_FLAG_NO_WORKQ) {
        /* Don't invoke any callbacks if we're shutting down. */
        if (ctx->cx_flags & CX_FLAG_SHUTTING_DOWN) {
            rna_service_free_message_buffer(ctx, mbuf);
        } else {
            ctx->cx_params.rsp_async_msg_callback(ctx, mbuf);
        }
    } else {
        work_queue_add_callback(ctx, NULL, mbuf, RNA_SERVICE_EVENT_NONE);
    }

    return (0);
}

/*
 * A find_registration_compare_fn used by process_cfm_cmd.
 * Update the cache device ID stored in the matching queued cache device
 * registration.
 *
 * Arguments:
 *     ctx   The rna_service context
 *     ibuf  The queued registration message to be checked
 *     arg   The cache device update (CONF_MGR_UPDATE_CACHE_DEVICE) command
 */
static boolean
update_cachedev_reg(rna_service_ctx_t                     *ctx,
                    rna_service_message_buffer_internal_t *ibuf,
                    void                                  *arg)
{
    struct cfm_cmd *cmd = (struct cfm_cmd *) arg;

    UNREFERENCED_PARAMETER(ctx);

    rna_service_assert(RNA_SERVICE_MESSAGE_TYPE_REG_CACHE_DEVICE ==
                                                    ibuf->h.rmbi_msg_type);

    /*
     * Check whether the physical device IDs for the cache device registration
     * and update match.
     */
    if (memcmp(&cmd->u.cache_cfm_update_cachedev.uc_cachedev.
                                            jcd_info.cd_label.cl_physical_id,
               &ibuf->u.rmbi_message_buffer.u.rmb_register_cache_device.
                                            cdr_cachedev_label.cl_physical_id,
                sizeof(cachedev_physical_id_t)) == 0) {
        /*
         * Update the cache device ID for the cache device registration.
         */
        ibuf->u.rmbi_message_buffer.u.rmb_register_cache_device.
                                            cdr_cachedev_label.cl_rna_id =
            cmd->u.cache_cfm_update_cachedev.uc_cachedev.
                                            jcd_info.cd_label.cl_rna_id;
        return (TRUE);
    } else {
        return (FALSE);
    }
}


/**
 * Process the specified cfm_cmd message, which has been received on the
 * specified endpoint.
 */
static int
process_cfm_cmd(com_ep_handle_t *eph, struct cfm_cmd *cmd)
{
    rna_service_ctx_t *ctx;
    int                ret = 0;
    struct cfm_cmd    *send_cmd;
    rna_service_send_buf_entry_t
                      *send_buf;
    char *wwn_str = NULL;

    rna_service_assert(NULL != eph);

    /*
     * (Note that the user's context was stored in the endpoint's com_handle's
     * private data by the rna_service_com_init() call in
     * rna_service_ctx_create()).
     */
    ctx = (rna_service_ctx_t *) rna_service_com_ep_get_priv_data(eph);
    if (NULL == ctx) {
        if (!rna_service_com_connected(eph)) {
            rna_dbg_log(RNA_DBG_INFO,
                        "ep [" RNA_ADDR_FORMAT "] disconnected, "
                        "dropping message [%s]\n",
                        RNA_ADDR(eph->eph_dst_in.sin_addr),
                        get_cmd_type_string(cmd->h.h_type));
            return (0);
        } else {
            /* This shouldn't happen */
            rna_dbg_log(RNA_DBG_ERR,
                        "User context not stored in ep private data!\n");
            return (-1);
        }
    }

    if ((ctx->cx_watermark != RNA_SERVICE_CTX_WATERMARK)
      || (!ctx_add_reference(&ctx))) {
        rna_dbg_log(RNA_DBG_INFO,
                    "shutting down; ignoring message of type [%s]\n",
                    get_cmd_type_string(cmd->h.h_type));
        return (0);
    }

    rna_trace("incoming ["RNA_ADDR_FORMAT"] type [%s]\n",
              RNA_ADDR(eph->eph_dst_in.sin_addr),
              get_cmd_type_string(cmd->h.h_type));

    check_for_primary_cfm_change(ctx, &cmd->h.h_pci);

    /*
     * If this is a message that should be sent only by the primary CFM, and
     * the sender is no longer the primary CFM, reject the message and tell
     * it that it's no longer the primary.
     */
    if ((ctx->cx_primary_cfm_id.pcic_pci.pci_generation != 
                                            cmd->h.h_pci.pci_generation)
      || (ctx->cx_primary_cfm_id.pcic_pci.pci_addr.s_addr !=
                                            cmd->h.h_pci.pci_addr.s_addr)) {
        rna_dbg_log(RNA_DBG_WARN,
                    "[%s] received from [" RNA_ADDR_FORMAT "], "
                    "but it's no longer the primary CFM; rejecting "
                    "(gen [%"PRId64"] vs. [%"PRId64"]\n",
                    get_cmd_type_string(cmd->h.h_type),
                    RNA_ADDR(eph->eph_dst_in.sin_addr),
                    cmd->h.h_pci.pci_generation,
                    ctx->cx_primary_cfm_id.pcic_pci.pci_generation);
        /*
         * This message should have been sent by the primary CFM, but appears
         * not to have been.  Tell the CFM that it's no longer the primary.
         */
        ret = rna_service_com_get_send_buf(eph, &send_buf, TRUE, NULL);
        if ((NULL == send_buf) || (0 != ret)) {
            rna_dbg_log(RNA_DBG_WARN,
                        "failed to get send buffer!!\n");
            return (-ENOMEM);
        } else {
#if defined(LINUX_KERNEL) || defined(WINDOWS_KERNEL)
            send_cmd = (struct cfm_cmd *)(com_get_send_buf_mem(send_buf));
#else
            send_cmd = (struct cfm_cmd *) send_buf->mem;
#endif

            memset(&send_cmd->h, 0, sizeof(send_cmd->h));
            send_cmd->h.h_type = CONF_MGR_CONTROL_REJECT;
            send_cmd->u.cfm_control_reject.ccr_rejected_id = cmd->h.h_pci;
            ret = rna_service_com_send_cfm_cmd(eph,
                                               send_buf,
                                               cfm_cmd_length(cmd),
                                               &ctx->cx_primary_cfm_id);
            if (ret != 0) {
                rna_dbg_log(RNA_DBG_WARN, "failed to send message [%d]\n",
                            ret);
            }
        }
        return 0;
    }

    bswap_cfm_cmd(cmd, 1);
    switch (cmd->h.h_type) {
        case CONF_MGR_CONF_RESPONSE:
        case CONF_MGR_REG_RESPONSE:
            rna_dbg_log(RNA_DBG_WARN,
                        "Received unexpected cmd type [%s]\n",
                        get_cmd_type_string(cmd->h.h_type));
            break;

        case CONF_MGR_REG_CACHE_RESPONSE: /* response to a CONF_MGR_REG_CACHE */
        case CONF_MGR_REG_CACHE_RESPONSE_V2:
            /* Only cache servers get CONF_MGR_REG_CACHE_RESPONSE messages */
            if (RNA_SERVICE_USER_TYPE_CACHE_SERVER ==
                                                ctx->cx_params.rsp_user_type) {
                process_cfm_cache_register_response(ctx, eph, cmd);
                ret = 0;
            } else {
                rna_dbg_log(RNA_DBG_ERR, "Received unexpected %s message\n",
                            get_cmd_type_string(cmd->h.h_type));
                ret = EINVAL;
            }
            break;

        case CONF_MGR_MD_REPORT:
            ret = work_queue_add_cfm(ctx, eph, cmd, process_md_report);
            break;

        case CONF_MGR_MD_PARTITION_MAP:
            ret = work_queue_add_cfm(ctx, eph, cmd, process_partition_map);
            break;

        case CONF_MGR_EVENT_REG:
            process_cfm_event_reg(ctx, eph, cmd);
            break;

        case CONF_MGR_EVENT_DEREG:
            process_cfm_event_dereg(ctx, eph, cmd);
            break;

        case CONF_MGR_CSTAT_REQ:
            ret = work_queue_add_cfm(ctx, eph, cmd, process_cstat_req);
            break;

        case CONF_MGR_BSTAT_REQ:
            ret = process_bstat_request(ctx, eph, cmd);
            break;

        case CONF_MGR_CONTROL:
            ret = work_queue_add_cfm(ctx, eph, cmd, process_cfm_control);
            break;

        case CONF_MGR_LOCAL_CS_REG:
            ret = process_blk_async_message(ctx, eph, cmd);
            break;

        case CONF_MGR_REG_CLIENT_RESP:
            ret = process_conf_mgr_reg_client_resp(ctx, eph, cmd);
            break;

        case CONF_MGR_CONN_REG:
            if ((RNA_SERVICE_USER_TYPE_CACHE_SERVER ==
                                            ctx->cx_params.rsp_user_type)
              ||(RNA_SERVICE_USER_TYPE_METADATA_SERVER ==
                                            ctx->cx_params.rsp_user_type)) {
                ret = process_connection_register(ctx, eph, cmd);
            } else {
                rna_dbg_log(RNA_DBG_WARN,
                            "Received unexpected cmd type [%s]\n",
                            get_cmd_type_string(cmd->h.h_type));
            }
            break;

        case CONF_MGR_DISCONN_REG:
            ret = process_disconnection_register(ctx, eph, cmd);
            break;

        case CONF_MGR_REG_BLOCK_DEVICE_RESP:
            ret = process_reg_block_device_resp(ctx, eph, cmd);
            break;

        case CONF_MGR_BLOCK_DEVICE_CREATE:
            ret = process_create_block_device(ctx, eph, cmd);
            break;

        case CONF_MGR_BLOCK_DEVICE_CONTROL:
            ret = process_control_block_device(ctx, eph, cmd);
            break;

        case CONF_MGR_CONTROL_CS:
            if (RNA_SERVICE_USER_TYPE_CACHE_SERVER ==
                                            ctx->cx_params.rsp_user_type) {
                ret = work_queue_add_control_cs(ctx, eph, cmd, process_control_cs);
            } else {
                rna_dbg_log(RNA_DBG_WARN,
                            "Received unexpected cmd type [%s] sub-type [%d]\n",
                            get_cmd_type_string(cmd->h.h_type),
                            cmd->u.control_cs.rnas.ccs_type);
            }
            break;

        case CONF_MGR_CS_UPDATE_CLEAR_SCSI_ITN_RES_RESP:
        case CONF_MGR_CS_ACQUIRE_SCSI_ITN_RES_RESP:
        case CONF_MGR_CS_ACQUIRE_SCSI_ITN_REG_RESP:
        case CONF_MGR_RESILVER_CACHE_DEVICE_COMPLETE_RESP:
        case CONF_MGR_CS_SHUTDOWN_RESP:
            ret = process_cfm_non_reg_dereg_response(ctx, eph, cmd);
            break;

        case CONF_MGR_UPDATE_CACHE_DEVICE:
            /*
             * It's possible the CFM has assigned the cache device a new ID.
             * To deal with that possibility, update the ID in the cache
             * device's queued registration message, which will be sent to
             * the CFM the next time a CFM is promoted to primary.  Look for
             * a cache device entry in the registered list that has a matching
             * physical ID and update its cachedev ID.
             */
            if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
                /* This failure means we're in the process of shutting down */
                break;
            }

            if (!find_registration(ctx,
                                   RNA_SERVICE_MESSAGE_TYPE_REG_CACHE_DEVICE,
                                   update_cachedev_reg,
                                   cmd)) {
                rna_create_wwn_strings(&cmd->u.cache_cfm_update_cachedev.
                                            uc_cachedev.jcd_info.cd_label.
                                            cl_physical_id.u.cpi_wwn,
                                       &wwn_str, NULL, NULL, NULL);
                rna_dbg_log(RNA_DBG_WARN,
                            "registration not found for "
                            "cache device ID [%"PRIx64"] "
                            "physical ID [%s]\n",
                            cmd->u.cache_cfm_update_cachedev.uc_cachedev.
                                        jcd_info.cd_label.cl_rna_id,
                            wwn_str != NULL ? wwn_str : NULL);
                if (wwn_str) {
                    rna_service_simple_free(wwn_str);
                }
            }

            rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
            /*
             * Fall through to process the message.
             */
            // FALL THROUGH
        case CONF_MGR_QUERY_CACHED_LUN:
        case CONF_MGR_QUERY_CACHE_DEVICE:
        case CONF_MGR_DELETE_REPLICA_STORE:
        case CONF_MGR_ABSORB_REPLICA_STORE:
        case CONF_MGR_CACHED_LUN_WRITE_ALL_INITIATE:
        case CONF_MGR_CACHED_LUN_WRITE_ALL_CONCLUDE:
            /* Only cache servers get these messages */
            if (RNA_SERVICE_USER_TYPE_CACHE_SERVER ==
                                                ctx->cx_params.rsp_user_type) {
                process_cs_async_message(ctx, eph, cmd);
                ret = 0;
            } else {
                rna_dbg_log(RNA_DBG_WARN,
                            "Received unknown cmd type: %d %s\n",
                            cmd->h.h_type,
                            get_cmd_type_string(cmd->h.h_type));
                ret = EINVAL;
            }
            break;

        case CONF_MGR_EXPEL_CACHE_DEVICE:
            ret = process_expel_cache_device(ctx, eph, cmd);
            break;

        case CONF_MGR_UNEXPELLED_CACHEDEVS:
            ret = process_unexpelled_cachedevs(ctx, eph, cmd);
            break;

        case PING:
            ret = process_ping(ctx, eph, cmd);
            break;

        default:
            rna_dbg_log(RNA_DBG_WARN,
                        "Received unexpected cmd type [%s]\n",
                        get_cmd_type_string(cmd->h.h_type));
            break;
    }
    ctx_release_reference(&ctx);
    return ret;
}


/**
 * Process the specified cache_cmd message, which has been received on the
 * specified endpoint.
 */
static int
process_cache_cmd(com_ep_handle_t *eph, struct cache_cmd *cmd)
{
    rna_service_ctx_t *ctx;
    int                ret = 0;

    rna_service_assert(NULL != eph);

    /*
     * (Note that the user's context was stored in the endpoint's com_handle's
     * private data by the rna_service_com_init() call in
     * rna_service_ctx_create()).
     */
    ctx = (rna_service_ctx_t *) rna_service_com_ep_get_priv_data(eph);
    if (NULL == ctx) {
        if (!rna_service_com_connected(eph)) {
            rna_dbg_log(RNA_DBG_INFO,
                        "ep [" RNA_ADDR_FORMAT "] disconnected, "
                        "dropping message [%s]\n",
                        RNA_ADDR(eph->eph_dst_in.sin_addr),
                        get_cmd_type_string(cmd->h.h_type));
            return (0);
        } else {
            /* This shouldn't happen */
            rna_dbg_log(RNA_DBG_ERR,
                        "User context not stored in ep private data!\n");
            return (-1);
        }
    }

    if ((ctx->cx_watermark != RNA_SERVICE_CTX_WATERMARK)
      || (!ctx_add_reference(&ctx))) {
        rna_dbg_log(RNA_DBG_INFO,
                    "shutting down; ignoring message of type [%s]\n",
                    get_cmd_type_string(cmd->h.h_type));
        return (0);
    }

    rna_trace("incoming ["RNA_ADDR_FORMAT"] type [%s]\n",
               RNA_ADDR(eph->eph_dst_in.sin_addr),
               get_cmd_type_string(cmd->h.h_type));

    check_for_primary_cfm_change(ctx, &cmd->h.h_pci);

    bswap_cache_cmd(cmd, 1);
    /*
     * Some of the processing work for these messages may or may not be handed
     * off to the workq threads.  See process_md_response() for details.
     */
    switch (cmd->h.h_type) {
        case CACHE_REGISTER_RESP:   /* response to a CACHE_REGISTER */
            /* Only cache servers get CACHE_REGISTER_RESP messages */
            if (RNA_SERVICE_USER_TYPE_CACHE_SERVER ==
                                                ctx->cx_params.rsp_user_type) {
                process_md_cache_register_response(ctx, eph, cmd);
                ret = 0;
            } else {
                rna_dbg_log(RNA_DBG_ERR,
                            "Received unexpected CACHE_REGISTER_RESP "
                            "message\n");
                ret = EINVAL;
            }
            break;

        case META_DATA_RESPONSE:      /* Response to a META_DATA_QUERY */
        case CACHE_RESPONSE_RESPONSE: /* Response to a CACHE_RESPONSE */
        case CACHE_QUERY_REQ_RESPONSE:/* Response to a CACHE_QUERY_REQ */
        case CACHE_ABSORB_BLOCK_RESP: /* Response to a CACHE_ABSORB_BLOCK */
        case CACHE_INVD_REP:          /* Response to a CACHE_INVD or
                                       * CACHE_MASTER_INVD
                                       */
            ret = process_md_response(ctx, eph, cmd);
            break;

        case RESEND_REQ:
            /* This message is no longer supported */
            rna_dbg_log(RNA_DBG_ERR,
                        "Unexpected RESEND_REQ message received, "
                        "presumably from downrev MD, ignoring\n");
            break;

        case CACHE_QUERY:
        case CACHE_CHANGE_REF:
        case CACHE_MASTER_INVD:
        case CACHE_INVD_HOLD:
            /* Only cache servers get these messages */
            if (RNA_SERVICE_USER_TYPE_CACHE_SERVER ==
                                                ctx->cx_params.rsp_user_type) {
                process_cs_async_message(ctx, eph, cmd);
                ret = 0;
            } else {
                rna_dbg_log(RNA_DBG_WARN,
                            "Received unknown cmd type: %d %s\n",
                            cmd->h.h_type,
                            get_cmd_type_string(cmd->h.h_type));
                ret = EINVAL;
            }
            break;

        case MD_CLIENT_PING:
            ret = 0;
            break;

        default:
            rna_dbg_log(RNA_DBG_WARN, "Received unknown cmd type: %d %s\n",
                        cmd->h.h_type,
                        get_cmd_type_string(cmd->h.h_type));
            ret = 0;
            break;
    }

    ctx_release_reference(&ctx);
    return (ret);
}


INLINE int
process_md_ping_read(struct rna_service_ctx_s *ctx,
                     com_ep_handle_t          *eph, 
                     void                     *rdma_buf)
{
    int                       ret       = 0;
    struct md_info_s         *mdi;

#if defined(WINDOWS_KERNEL) && !(defined(DBG))
    DECLARE_UNUSED(rdma_buf);
#endif

    rna_service_assert (NULL != ctx);
    rna_service_assert (NULL != eph);
    rna_service_assert (NULL != rdma_buf);

    if (!rna_service_mutex_lock(&ctx->cx_md_mutex)) {
        /* This failure means we're in the process of shutting down */
        return (RNA_SERVICE_ERROR_NONE);
    }

    mdi = find_md_by_eph(ctx, eph);
    if (NULL == mdi) {
        rna_dbg_log(RNA_DBG_WARN,
                    "RDMA read completion from unknown MD ep [%p].\n",
                    com_get_ep_ptr(eph));
        ret = 1;
    } else {
        rna_service_process_md_ping_read(&mdi->mdi_remote_ping_ctx);
    }

    rna_service_mutex_unlock(&ctx->cx_md_mutex);
    return (ret);
}


/* ---------------------------- Com Callbacks ------------------------------ */

/**
 * Invoked when a message has been received on the specified endpoint.
 */
static RNA_SERVICE_RECV_CMP_CB_T recv_callback;        /* typecheck */

static int
recv_callback(com_ep_handle_t *eph,
              void *ep_ctx UNUSED_ARG,
                           // valid at kernel-level, always NULL at user-level
              void *buf,
              int len,
              int status)  // valid at kernel-level, always 0 at user-level
{
    int ret;

    UNREFERENCED_PARAMETER(ep_ctx);

    if (NULL == eph) {
        /* This shouldn't happen */
        rna_dbg_log(RNA_DBG_ERR, "Received a recv callback with no ep!\n");
        return (-1);
    }

    if (0 != status) {
        rna_dbg_log(RNA_DBG_INFO,
                    "got an error %d on ep [%p]\n",
                    status, com_get_ep_ptr(eph));
        return (0);
    }

    rna_trace("incoming ["RNA_ADDR_FORMAT"] ep [%p] type [%s]\n",
              RNA_ADDR(eph->eph_dst_in.sin_addr),
              com_get_ep_ptr(eph),
              get_user_type_string(eph->eph_user_type));

    switch (eph->eph_user_type) {
        case USR_TYPE_CFM_CLIENT:
        case USR_TYPE_CFM_CACHE:
            if (cfm_cmd_length((struct cfm_cmd *)buf) == len) {
                ret = process_cfm_cmd(eph, (struct cfm_cmd *)buf);
            } else {
                rna_dbg_log(RNA_DBG_ERR,
                    "Received wrong-sized cfm_cmd on ep [%p], ignoring: "
                    "%d/%lu\n",
                    com_get_ep_ptr(eph),
                    len, cfm_cmd_length((struct cfm_cmd *)buf));
                ret = -1;
            }
            break;

        case USR_TYPE_META_CLIENT:
        case USR_TYPE_META_CACHE:
            // The MD can send a CONF_MGR_MD_PARTITION_MAP, which is a cfm_cmd.
            if ((CONF_MGR_MD_PARTITION_MAP == ((cmd_hdr_t *)buf)->h_type)
              && (len >= cfm_cmd_length((struct cfm_cmd *)buf))) {
                ret = process_cfm_cmd(eph, (struct cfm_cmd *)buf);
            } else if (META_DATA_SYNC_REQUEST == ((cmd_hdr_t *)buf)->h_type) {
                /*
                 * (Note that the user's context was stored in the endpoint's
                 * com_handle's private data by the rna_service_com_init() call
                 * in rna_service_ctx_create()).
                 */
                rna_service_ctx_t *ctx = (rna_service_ctx_t *)
                                        rna_service_com_ep_get_priv_data(eph);
                if ((NULL == ctx) // disconnected
                  || (NULL == ctx->cx_cs_params.csp_sync_request_callback)
                  || (ctx->cx_flags & CX_FLAG_SHUTTING_DOWN)) {
                    /* Bail out */
                    return (0);
                }
                ret = ctx->cx_cs_params.csp_sync_request_callback(eph, buf);
            } else if (len >= cache_cmd_length((struct cache_cmd *)buf)) {
                ret = process_cache_cmd(eph, (struct cache_cmd *)buf);
            } else {
                rna_dbg_log(RNA_DBG_ERR,
                    "Received wrong-sized cache_cmd on ep [%p], "
                    "ignoring: %d\n",
                    com_get_ep_ptr(eph), len);
                ret = -1;
            }
            break;

        default:
            rna_dbg_log(RNA_DBG_ERR, "Unknown user type [%d] ep [%p]\n",
                        eph->eph_user_type, com_get_ep_ptr(eph));
            ret = -1;
    }
    return ret;
}


/* 
 * Completion of an RDMA read.  User and kernel modes both use this same
 * routine, but they have different prototypes: the 3rd arg is -int- in
 * the kernel and an -enum- in userland.
 *
 * Altho Linux is quite happy, Windows complains, so the code gets inlined
 * with the appropriate wrapper, below.
 */

INLINE int
__rdma_read_callback(com_ep_handle_t *eph,
                     struct buf_entry *rdma_buf,
                     int status)
{
    rna_service_ctx_t *ctx;
    int ret = 0;

    rna_service_assert (NULL != eph);
    rna_service_assert (NULL != rdma_buf);
        
    rna_trace("ep [%p], type [%s], status [%d]\n", 
              com_get_ep_ptr(eph), 
              get_user_type_string(eph->eph_user_type),
              status);

    /*
     * (Note that the user's context was stored in the endpoint's com_handle's
     * private data by the rna_service_com_init() call in
     * rna_service_ctx_create()).
     */
    ctx = (rna_service_ctx_t *) rna_service_com_ep_get_priv_data(eph);
    if (NULL == ctx) {
        if (!rna_service_com_connected(eph)) {
            rna_dbg_log(RNA_DBG_INFO,
                        "ep [" RNA_ADDR_FORMAT "] disconnected, "
                        "dropping message\n",
                        RNA_ADDR(eph->eph_dst_in.sin_addr));
            return (0);
        } else {
            /* This shouldn't happen */
            rna_dbg_log(RNA_DBG_ERR,
                        "User context not stored in ep private data!\n");
            return (-1);
        }
    }

    if (USR_TYPE_META_CACHE == eph->eph_user_type) {
        if (RNA_SERVICE_USER_TYPE_CACHE_SERVER == ctx->cx_params.rsp_user_type)
        {
            if (CB_RESP_SUCCESS == status) {
                /* This cache server's ping of an MD has completed */
                ret = process_md_ping_read(ctx, eph, rdma_buf);
            } else {
                rna_dbg_log(RNA_DBG_WARN,
                            "RDMA read failure on EP [%p] type [%s].\n",
                            com_get_ep_ptr(eph), 
                            get_user_type_string(eph->eph_user_type));
            }
        } else if (RNA_SERVICE_USER_TYPE_METADATA_SERVER ==
                                                ctx->cx_params.rsp_user_type) {
            /*
             * This metadata server's ping of a cache server has completed.
             * This is not yet handled; code needs to be added here if
             * metadata servers users are supported in the future.
             */
            rna_dbg_log(RNA_DBG_ERR, "CS ping by MD not yet supported\n");
        }
    } else {
        rna_dbg_log(RNA_DBG_WARN,
                    "RDMA read completion on unexpected EP [%p] type [%s].\n",
                    com_get_ep_ptr(eph), get_user_type_string(eph->eph_user_type));
    }

    return (ret);
}

/*
 * Wrap rdma_read_callback() with appropriate type
 */

#if defined(LINUX_USER) || defined(WINDOWS_USER)

static RDMA_READ_CMP_CB_T rdma_read_callback;      /* typecheck */
static int rdma_read_callback(com_ep_handle_t *eph,
                              struct buf_entry *rdma_buf,
                              enum rna_com_cb_resp_status status)
{
    return __rdma_read_callback(eph, rdma_buf, (int)status);
}

#elif defined(LINUX_KERNEL) || defined(WINDOWS_KERNEL)

static RNA_SERVICE_RDMA_READ_CMP_CB_T rdma_read_callback;      /* typecheck */
static int rdma_read_callback(com_ep_handle_t *eph,
                              struct buf_entry *rdma_buf,
                              int status)
{
    return __rdma_read_callback(eph, rdma_buf, status);
}

#endif  /* The Kernels */



#if defined(LINUX_USER) || defined(WINDOWS_USER)
/*
 * Invoked at user-level only.
 *
 * We grab a reference on the EP, so that active and passive EPs can be
 * treated the same way.
 */
static ACCEPT_CB_T accept_callback;        /* typecheck */

static int
accept_callback(com_ep_handle_t *eph, int private_data)
{
    UNREFERENCED_PARAMETER(private_data);

    rna_trace("incoming accept from ["RNA_ADDR_FORMAT"] type [%s]\n",
               RNA_ADDR(eph->eph_dst_in.sin_addr),
               get_user_type_string(eph->eph_user_type));

    com_inc_ref_eph(eph);   // (no-op at user level)
    return 0;
}
#elif defined(LINUX_KERNEL) || defined(WINDOWS_KERNEL)
# define accept_callback    (0)
#endif  /* The Kernels */


/*
 * NOTE that all the connections handled here are active, rather than passive,
 * and are initiated by rna_service.  Passive connections are handled by this
 * library's user's connect callback handler.  This library doesn't contain a
 * call to com_listen_addr(), com_listen_networks(), or com_listen_all(), since
 * it would get complicated if both this library and this library's user did so.
 */
static RNA_SERVICE_CONNECT_CB_T connect_callback;      /* typecheck */

static int
connect_callback(com_ep_handle_t *eph,
                 void            *ep_ctx UNUSED_ARG)
                                   // valid at kernel level, NULL at user-level
{
    int                ret    = 0;
    rna_service_ctx_t *ctx;

    UNREFERENCED_PARAMETER(ep_ctx);

    if (NULL == eph) {
        /* This shouldn't happen */
        rna_dbg_log(RNA_DBG_ERR,
                    "Received a connect callback with no ep!\n");
        return (-1);
    }

    rna_trace("incoming connection from ["RNA_ADDR_FORMAT"] ep [%p] "
              "type [%s]\n",
               RNA_ADDR(eph->eph_dst_in.sin_addr),
               com_get_ep_ptr(eph),
               get_user_type_string(eph->eph_user_type));

    /*
     * (Note that the user's context was stored in the endpoint's com_handle's
     * private data by the rna_service_com_init() call in
     * rna_service_ctx_create()).
     */
    ctx = (rna_service_ctx_t *) rna_service_com_ep_get_priv_data(eph);
    if ((NULL == ctx)
      || (ctx->cx_watermark != RNA_SERVICE_CTX_WATERMARK)
      || (0 != (ctx->cx_flags & (CX_FLAG_SHUTTING_DOWN | CX_FLAG_SHUT_DOWN)))
      || (!ctx_add_reference(&ctx))) {
        rna_dbg_log(RNA_DBG_INFO,
                    "shutting down; ignoring connect callback from "
                    "["RNA_ADDR_FORMAT"] ep [%p] type [%s]\n",
                    RNA_ADDR(eph->eph_dst_in.sin_addr),
                    com_get_ep_ptr(eph),
                    get_user_type_string(eph->eph_user_type));
        return (0);
    }

    switch (eph->eph_user_type) {
        case USR_TYPE_CFM_CLIENT: 
        case USR_TYPE_CFM_CACHE:
            /*
             * If the library's user is a cache server, then the cx_md_mutex
             * must be held to call add_connected_cfm().  To prevent deadlock,
             * the md mutex must be acquired before the cx_cfm_mutex.
             */
            if (RNA_SERVICE_USER_TYPE_CACHE_SERVER ==
                                               ctx->cx_params.rsp_user_type) {
                if (!rna_service_mutex_lock(&ctx->cx_md_mutex)) {
                    /* We're in the process of shutting down */
                    break;;
                }
            }
            if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
                /* This failure means we're in the process of shutting down */
                rna_service_mutex_unlock(&ctx->cx_md_mutex);
                break;
            }

            add_connected_cfm(ctx, eph);

            rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
            if (RNA_SERVICE_USER_TYPE_CACHE_SERVER ==
                                               ctx->cx_params.rsp_user_type) {
                rna_service_mutex_unlock(&ctx->cx_md_mutex);
            }
            break;

        case USR_TYPE_META_CLIENT:
        case USR_TYPE_META_CACHE:
            rna_dbg_log(RNA_DBG_INFO,
                        "MD ["RNA_ADDR_FORMAT"] connected\n",
                        RNA_ADDR(eph->eph_dst_in.sin_addr));
            ret = 0;
            break;

        default:
            break;
    }

    ctx_release_reference(&ctx);
    return (0);
}


/**
 * Invoked when a disconnect has occurred from the specified endpoint.
 */
static RNA_SERVICE_DISCONNECT_CB_T disconnect_callback;    /* typecheck */

static int
disconnect_callback(com_ep_handle_t *eph,
                    void            *ep_ctx UNUSED_ARG)
                                   // valid at kernel level, NULL at user-level
{
    int                ret    = 0;
    rna_service_ctx_t *ctx;
    md_info_t         *mdi;

    UNREFERENCED_PARAMETER(ep_ctx);

    if (NULL == eph) {
        /* This shouldn't happen */
        rna_dbg_log(RNA_DBG_ERR,
                    "Received a disconnect callback with no ep!\n");
        return (-1);
    }

    rna_dbg_log(RNA_DBG_INFO,
                "disconnect from ["RNA_ADDR_FORMAT"] ep [%p] type [%s]\n",
                RNA_ADDR(eph->eph_dst_in.sin_addr),
                com_get_ep_ptr(eph),
                get_user_type_string(eph->eph_user_type));

    /*
     * (Note that the user's context was stored in the endpoint's com_handle's
     * private data by the rna_service_com_init() call in
     * rna_service_ctx_create()).
     */
    ctx = (rna_service_ctx_t *) rna_service_com_ep_get_priv_data(eph);
    /*
     * NOTE that in the following, we don't check whether the ctx is in the
     * process of shutting down, since it's important that disconnects be
     * processed even during shutdown.
     */
    if ((NULL == ctx)
      || (ctx->cx_watermark != RNA_SERVICE_CTX_WATERMARK)
      || (!ctx_add_reference(&ctx))) {
        /*
         * We're in the last stage of shutting down, we shouldn't be getting
         * a disconnect callback at this point.
         */
        rna_dbg_log(RNA_DBG_WARN,
                    "shutting down; ignoring disconnect callback for "
                    "ep [%p] type [%s]\n",
                    com_get_ep_ptr(eph),
                    get_user_type_string(eph->eph_user_type));
        /*
         * We're shutting down.  Drop the last reference on the ep, so the ep
         * can be freed, so com can shut down cleanly.
         */
        com_release_eph(eph);   // (no-op at user level)
        return (0);
    }

    switch (eph->eph_user_type) {
        case USR_TYPE_CFM_CLIENT:
        case USR_TYPE_CFM_CACHE:
            if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
                /* This failure means we're in the process of shutting down */
                break;
            }
            delete_connected_cfm(ctx, eph);
            /* Schedule an attempt to re-connect with this CFM.  */
            queue_reconnect_cfms(ctx);
            /*
             * If a shutdown request is in progress and the request has already
             * been sent to the primary CFM, it'll need to be re-sent to the
             * new primary CFM.  Re-set the send timer.
             */
            if ((ctx->cx_send_shutdown_request_in_progress)
              && (!ctx->cx_send_shutdown_request_timer_is_set)) {
                rna_service_timer_cancel(&ctx->cx_send_shutdown_request_timer);
                rna_service_timer_set(
                                    ctx->cx_private,
                                   &ctx->cx_send_shutdown_request_timer,
                                    shutdown_request_send_timed_out,
                                    (uint64_t)ctx,
                                    ctx->cx_send_shutdown_request_timeout_sec);
                ctx->cx_send_shutdown_request_timer_is_set = TRUE;
            }
            rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
            break;

        case USR_TYPE_META_CLIENT:
        case USR_TYPE_META_CACHE:
            if (!rna_service_mutex_lock(&ctx->cx_md_mutex)) {
                /* This failure means we're in the process of shutting down */
                break;
            }
            mdi = com_get_eph_context(eph);
            if (NULL == mdi) {
                mdi = find_md_by_eph(ctx, eph);
            }
            if (NULL == mdi) {
                rna_service_mutex_unlock(&ctx->cx_md_mutex);
                rna_dbg_log(RNA_DBG_WARN,
                            "disconnect from EP [%p] with no associated MDI "
                            "[" RNA_ADDR_FORMAT "]\n",
                            com_get_ep_ptr(eph),
                            RNA_ADDR(eph->eph_dst_in.sin_addr));
                break;
            }

            rna_dbg_log(RNA_DBG_INFO,
                        "MD ["RNA_ADDR_FORMAT"] disconnected\n",
                        RNA_ADDR(eph->eph_dst_in.sin_addr));
            md_disconnected_complete(ctx, mdi);
            rna_service_mutex_unlock(&ctx->cx_md_mutex);
            break;

        default:
            ret = -1;
    }

    ctx_release_reference(&ctx);
    /* Release primary ep reference */
    com_release_eph(eph);   // (no-op at user level)
    return (ret);
}


/* =========================== Public Functions ============================ */

/**
 * Destroy the specified rna_service context (which was created by a prior call
 * to rna_service_ctx_create).  On return, *ctxpp is NULL.
 *
 * Returns:
 *    RNA_SERVICE_ERROR_NONE  on success (*ctxpp is set to NULL)
 *    RNA_SERVICE_ERROR_INVALID_CTX
 *                            Either ctxpp is NULL, or *ctxpp is NULL, or it
 *                            was not created by rna_service_ctx_create().
 */
rna_service_error_t
rna_service_ctx_destroy(rna_service_ctx_t **ctxpp)
{
    rna_service_ctx_t *ctx;
    int i;
    rna_service_mempool_t *mp;
    rna_service_message_buffer_internal_t *ibuf;
    YAQ_LINK *lnkp;
    irq_flag_t flags;
    md_info_t **mdipp;
    mempool_ele_t *ele, *next;

    if ((NULL == ctxpp)
      || (NULL == *ctxpp)
      || ((*ctxpp)->cx_watermark != RNA_SERVICE_CTX_WATERMARK)
      || (0 != ((*ctxpp)->cx_flags &
                            (CX_FLAG_SHUTTING_DOWN | CX_FLAG_SHUT_DOWN)))) {
        return (RNA_SERVICE_ERROR_INVALID_CTX);
    }

    ctx = *ctxpp;
    *ctxpp = NULL;  /* disable the user's context pointer */
    rna_dbg_log(RNA_DBG_INFO, "ctx %p\n", ctx);

    /*
     * Make sure nothing new gets added to the work queues, etc. while we're
     * in the process of flushing/destroying them.
     */
    ctx->cx_flags |= CX_FLAG_SHUTTING_DOWN;
    rna_service_ctx_private_data_shutting_down(ctx->cx_private);

    rna_service_com_disconnect_all_eps(ctx->cx_com_instance);

    rna_dbg_log(RNA_DBG_INFO, "all eps disconnected\n");

    /*
     * Acquire all mutexes and spinlocks and mark them as shutting down (except
     * for the mempool spinlocks, to allow us to call free_messages below), to
     * keep the state of the ctx from changing beneath us and to keep others
     * from seeing it in an inconsistent (i.e. partially torn down) state.
     *
     * Once they've been marked as shutting down, all subsequent acquisition
     * attempts will fail, so we can safely release them, which we must do
     * before calling rna_service_workq_flush(), since queued work items may
     * attempt to acquire these mutexes.
     */
    rna_service_mutex_lock_shutdown(&ctx->cx_md_mutex);
    /*
     * While we hold the cx_md_mutex, cancel the timers associated with the
     * cx_md_table entries.
     */
    for (mdipp = &ctx->cx_md_table[0];
         mdipp < &ctx->cx_md_table[NUM_MD_ORDINALS];
         mdipp++) {

        if (*mdipp != NULL) {
            rna_service_timer_final_cancel(
                &ctx->cx_send_waiting_md_msgs_timers[(*mdipp)->mdi_ordinal]);
        }
    }
    rna_service_mutex_unlock(&ctx->cx_md_mutex);

    rna_service_mutex_lock_shutdown(&ctx->cx_cfm_mutex);
    rna_service_mutex_unlock(&ctx->cx_cfm_mutex);

    rna_service_workq_flush(ctx->cx_cfm_connect_work_queue);
    rna_service_workq_destroy(ctx->cx_cfm_connect_work_queue,
                              JOIN_WORKQ_THREADS);

    rna_service_workq_flush(ctx->cx_cfm_work_queue);
    rna_service_workq_destroy(ctx->cx_cfm_work_queue,
                              JOIN_WORKQ_THREADS);

    rna_service_workq_flush(ctx->cx_control_cs_work_queue);
    rna_service_workq_destroy(ctx->cx_control_cs_work_queue,
                              JOIN_WORKQ_THREADS);

    rna_service_workq_flush(ctx->cx_md_work_queue);
    rna_service_workq_destroy(ctx->cx_md_work_queue,
                              JOIN_WORKQ_THREADS);

    rna_service_workq_flush(ctx->cx_response_callback_work_queue);
    rna_service_workq_destroy(ctx->cx_response_callback_work_queue,
                              JOIN_WORKQ_THREADS);

    /*
     * Cancel all timers.  Note that no new timers can be set, since all are
     * set while a mutex is held, and all mutexes have been acquired and marked
     * as shutting down, so all mutex acquisition attempts will fail.
     */
    ctx->cx_md_flags &= ~CTX_MD_FLAG_RECONNECT_SCHEDULED;
    rna_service_timer_final_cancel(&ctx->cx_reconnect_mds_timer_object);
    ctx->cx_md_flags &= ~CTX_MD_FLAG_RECONNECT_RESTART;

    ctx->cx_cfm_flags &= ~CTX_CFM_FLAG_RECONNECT_SCHEDULED;
    rna_service_timer_final_cancel(&ctx->cx_reconnect_cfms_timer_object);
    ctx->cx_cfm_flags &= ~CTX_CFM_FLAG_RECONNECT_RESTART;

    rna_service_timer_final_cancel(&ctx->cx_primary_cfm_registration_timer);
    ctx->cx_cfm_flags &= ~CTX_CFM_FLAG_REGISTRATION_TIMER_SET;

    rna_service_timer_final_cancel(&ctx->cx_primary_cfm_heartbeat_timer);
    rna_service_timer_final_cancel(&ctx->cx_non_primary_cfm_ping_timer);
    rna_service_timer_final_cancel(&ctx->cx_ping_mds_timer_object);
    rna_service_timer_final_cancel(
                &ctx->cx_send_waiting_cfm_msgs_timer);
    rna_service_timer_final_cancel(
                &ctx->cx_send_shutdown_request_timer);
    ctx->cx_send_shutdown_request_timer_is_set = FALSE;
    rna_service_timer_final_cancel(&ctx->cx_ping_mds_timer_object);

    YAQ_FOREACH(&ctx->cx_cfm_msgs_waiting_to_send, lnkp) {
        ibuf = YAQ_OBJECT(rna_service_message_buffer_internal_t,
                          h.rmbi_link,
                          lnkp);
        rna_service_timer_final_cancel(&ibuf->h.rmbi_response_timer_object);
    }
    YAQ_FOREACH(&ctx->cx_cfm_registrations_waiting_to_send, lnkp) {
        ibuf = YAQ_OBJECT(rna_service_message_buffer_internal_t,
                          h.rmbi_link,
                          lnkp);
        rna_service_timer_final_cancel(&ibuf->h.rmbi_response_timer_object);
    }
    YAQ_FOREACH(&ctx->cx_cfm_waiting_for_reply, lnkp) {
        ibuf = YAQ_OBJECT(rna_service_message_buffer_internal_t,
                          h.rmbi_link,
                          lnkp);
        rna_service_timer_final_cancel(&ibuf->h.rmbi_response_timer_object);
    }

    YAQ_FOREACH(&ctx->cx_registrations_waiting_for_reply, lnkp) {
        ibuf = YAQ_OBJECT(rna_service_message_buffer_internal_t,
                          h.rmbi_link,
                          lnkp);
        rna_service_timer_final_cancel(&ibuf->h.rmbi_response_timer_object);
    }
    YAQ_FOREACH(&ctx->cx_registered, lnkp) {
        ibuf = YAQ_OBJECT(rna_service_message_buffer_internal_t,
                          h.rmbi_link,
                          lnkp);
        rna_service_timer_final_cancel(&ibuf->h.rmbi_response_timer_object);
    }
    YAQ_FOREACH(&ctx->cx_md_registered_paths, lnkp) {
        ibuf = YAQ_OBJECT(rna_service_message_buffer_internal_t,
                          h.rmbi_link,
                          lnkp);
        rna_service_timer_final_cancel(&ibuf->h.rmbi_response_timer_object);
    }
    YAQ_FOREACH(&ctx->cx_deregistrations_waiting_for_reply, lnkp) {
        ibuf = YAQ_OBJECT(rna_service_message_buffer_internal_t,
                          h.rmbi_link,
                          lnkp);
        rna_service_timer_final_cancel(&ibuf->h.rmbi_response_timer_object);
    }

    /*
     * In kernel space, this flushes and frees up a work queue
     * and associated kmem cache that are used by the timers.
     * Therefore it must be called AFTER the timers are canceled.
     */
    rna_service_ctx_private_data_free(ctx->cx_private);

    /*
     * Free all queued message buffers.  Since messages contain
     * rna_service_timer_object_t structs, they must be freed after work
     * queues have been flushed by rna_service_ctx_private_data_free().
     */
    free_messages(ctx, &ctx->cx_cfm_msgs_waiting_to_send);
    free_messages(ctx, &ctx->cx_cfm_registrations_waiting_to_send);
    free_messages(ctx, &ctx->cx_cfm_waiting_for_reply);
    free_messages(ctx, &ctx->cx_registrations_waiting_for_reply);
    free_messages(ctx, &ctx->cx_registered);
    free_messages(ctx, &ctx->cx_md_registered_paths);
    free_messages(ctx, &ctx->cx_deregistrations_waiting_for_reply);
    for (i = ctx->cx_partition_map.pm_num_hash_partitions - 1; i >= 0; --i) {
        free_messages(ctx, &ctx->cx_partitions[i].pi_waiting_to_send);
        free_messages(ctx, &ctx->cx_partitions[i].pi_waiting_for_reply);
    }
    free_messages(ctx, &ctx->cx_partitions[PREMATURE_PARTITION].
                                                        pi_waiting_to_send);

    /*
     * The following will cause subsequent ctx_add_reference calls to fail.
     * Note that this flag should not be set until after
     * rna_service_com_disconnect_all_eps() has been called, or
     * disconnect_callback() will short-circuit its necessary work after
     * failing to take a ctx reference.
     */
    set_ctx_shutting_down_flag(ctx);

    /*
     * The timer callback functions depend on the COM instance.
     * Therefore it must be freed AFTER the timers are canceled.
     */

    if (NULL != ctx->cx_com_instance) {
        rna_service_com_set_priv_data(ctx->cx_com_instance, NULL);
        (void)rna_service_com_exit(ctx->cx_com_instance);
    }

    /*
     * Now that all disconnect callbacks are complete (after the
     * rna_service_com_exit call above), we can free the entries in the
     * cx_md_table.
     */
    for (mdipp = &ctx->cx_md_table[0];
         mdipp < &ctx->cx_md_table[NUM_MD_ORDINALS];
         mdipp++) {

        if (NULL != (*mdipp)) {
            free_mdi(ctx, *mdipp);
            *mdipp = NULL;
        }
    }

    /* Free the memory pools */
    for (mp = &ctx->cx_mempools[MEMPOOL_ID_INVALID - 1];
         mp >= ctx->cx_mempools;
         --mp)
    {
        if (NULL == mp->mp_end) {
            continue;
        }
        rna_service_spinlock_acquire_shutdown(&mp->mp_spinlock, &flags);
        if (mp->mp_begin) {
            rna_service_free((uint32_t)(((uintptr_t) mp->mp_end) - ((uintptr_t) mp->mp_begin)),
            mp->mp_begin);
        } else {
            for (ele = (mempool_ele_t *)mp->mp_end; NULL != ele; ele = next) {
                next = ele->mpe_next;
                rna_service_free(mp->mp_element_size, ele);
            }
        }

        mp->mp_begin = mp->mp_end = mp->mp_avail = NULL;
        mp->mp_avail_count = 0;
        mp->mp_element_size = 0;
        atomic_set(&mp->mp_alloc_count, 0);
        rna_service_spinlock_release(&mp->mp_spinlock, &flags);
    }

    /*
     * In some environments, mutexes need to be destroyed.
     */
    rna_service_mutex_destroy(&ctx->cx_cfm_mutex);
    rna_service_mutex_destroy(&ctx->cx_md_mutex);

    /*
     * Finally, release the reference that was placed on the ctx by
     * rna_service_ctx_create().
     */
    ctx->cx_flags |= CX_FLAG_SHUT_DOWN;

    rna_dbg_log(RNA_DBG_INFO, "service ctx %p shutdown complete\n", ctx);

    /* 
     * We must drop the last reference after rna_dbg_log,
     * which invokes a callback that dereferences ctx.
     */
    ctx_release_reference(&ctx);
    return (RNA_SERVICE_ERROR_NONE);
}


/*
 * This is the more general form of rna_service_ctx_create(), for use by
 * cache servers (RNA_SERVICE_USER_TYPE_CACHE_SERVER) and metadata servers
 * (RNA_SERVICE_USER_TYPE_METADATA_SERVER).
 *
 * Create and initialize an rna_service context, to be used as an argument to
 * all subsequent rna_service_*() calls.
 *
 * Arguments:
 *    params     The set of general parameters for this rna_service context.
 *    cs_params  The set of cache-server-specific parameters for this
 *               rna_service context.  Null if the caller is not
 *               RNA_SERVICE_USER_TYPE_CACHE_SERVER.
 *    md_params  The set of metadata-server-specific parameters for this
 *               rna_service context.  Null if the caller is not
 *               RNA_SERVICE_USER_TYPE_METADATA_SERVER.
 *    ctxpp      A pointer to the location where a pointer the rna_service
 *               context should be stored.
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
rna_service_error_t
rna_service_cs_md_ctx_create(rna_service_params_t     *params,
                             rna_service_cs_params_t  *cs_params,
                             rna_service_md_params_t  *md_params,
                             rna_service_ctx_t       **ctxpp)
{
    int                ret;
    rna_service_ctx_t *ctx;
    int                i;

    rna_service_assert(sizeof(rna_hash_key_t) ==
                                            sizeof(rna_service_hash_key_t));

    /*
     * Validate arguments
     *
     * An event callback must be specified, as must at least one configuration
     * manager.  If a stats buffer is specified, it must have a length.
     */
    if ( (NULL == ctxpp)
      || (NULL == params)
      || (NULL == params->rsp_event_callback)
      || (0 == params->rsp_cfm_count)
      || ((NULL != params->rsp_stat_buf)
        && (0 == params->rsp_stat_length))
      || ((RNA_SERVICE_USER_TYPE_CACHE_SERVER == params->rsp_user_type)
        && (NULL == cs_params))
      || ((RNA_SERVICE_USER_TYPE_METADATA_SERVER == params->rsp_user_type)
        && (NULL == md_params)))
    {
        *ctxpp = NULL;
        return (RNA_SERVICE_ERROR_INVALID_PARAMS);
    }

    /*
     * Allocate and initialize an rna_service_ctx_t.
     */
    ctx = (rna_service_ctx_t *) rna_service_alloc0(sizeof(rna_service_ctx_t));
    if (NULL == ctx) {
        *ctxpp = NULL;
        return (RNA_SERVICE_ERROR_NO_MEMORY);
    }
    ctx->cx_watermark = RNA_SERVICE_CTX_WATERMARK;
    (void)ctx_add_reference(&ctx); // rna_service_ctx_destroy will drop this ref

    if (!strlen(params->rsp_node_name)) {
        if (1 == params->rsp_cfm_count && 
            INADDR_LOOPBACK == htonl(params->rsp_cfm_addrs[0].sin_addr.s_addr)) {
            /* Running in DAS mode. */
            rna_dbg_log(RNA_DBG_MSG, "Running in loopback (DAS) mode, "
                        "registering with cfm as localhost.\n"); 
            strncpy(params->rsp_node_name, "localhost", sizeof(params->rsp_node_name));
        } else {
            (void)rna_service_gethostname(params->rsp_node_name,
                                          sizeof(params->rsp_node_name) -1 );
            rna_dbg_log(RNA_DBG_MSG,
                        "Running in non-loopback (SAN) mode, registering with cfm as %s\n",
                        params->rsp_node_name);
        }
    }

    rna_service_primary_cfm_id_container_init(&ctx->cx_primary_cfm_id);

    rna_service_timer_subsystem_init();

    ret = rna_service_workq_create(RNA_SERVICE_CFM_CONNECT_WORK_QUEUE_THREADS,
                                   RNA_UTIL_THREAD_PRIORITY_HIGH, 
                                   RNA_SERVICE_WORK_QUEUE_SIZE, 
                                   &ctx->cx_cfm_connect_work_queue);

    if (ret != 0 || (NULL == ctx->cx_cfm_connect_work_queue)) {
        rna_dbg_log(RNA_DBG_WARN,
                    "Could not create cfm connect work queue: %d\n", ret);
        rna_service_free(sizeof(*ctx), ctx);
        *ctxpp = NULL;
        return (RNA_SERVICE_ERROR_WORKQ_INIT_FAILURE);
    }

    ret = rna_service_workq_create((RNA_SERVICE_USER_TYPE_CACHE_SERVER ==
                                                params->rsp_user_type)
                                      ? cs_params->csp_cs_workq_threads
                                      : RNA_SERVICE_CFM_WORK_QUEUE_THREADS,
                                   RNA_UTIL_THREAD_PRIORITY_HIGH, 
                                   RNA_SERVICE_WORK_QUEUE_SIZE, 
                                   &ctx->cx_cfm_work_queue);

    if (ret != 0 || (NULL == ctx->cx_cfm_work_queue)) {
        rna_dbg_log(RNA_DBG_WARN, "Could not create cfm work queue: %d\n", ret);
        rna_service_workq_flush(ctx->cx_cfm_connect_work_queue);
        rna_service_workq_destroy(ctx->cx_cfm_connect_work_queue,
                                  JOIN_WORKQ_THREADS);
        rna_service_free(sizeof(*ctx), ctx);
        *ctxpp = NULL;
        return (RNA_SERVICE_ERROR_WORKQ_INIT_FAILURE);
    }

    ret = rna_service_workq_create(RNA_SERVICE_CONTROL_CS_WORK_QUEUE_THREADS,
                                   RNA_UTIL_THREAD_PRIORITY_HIGH, 
                                   RNA_SERVICE_WORK_QUEUE_SIZE, 
                                   &ctx->cx_control_cs_work_queue);

    if (ret != 0 || (NULL == ctx->cx_control_cs_work_queue)) {
        rna_dbg_log(RNA_DBG_WARN, "Could not create control_cs work queue: %d\n", ret);
        rna_service_workq_flush(ctx->cx_cfm_connect_work_queue);
        rna_service_workq_destroy(ctx->cx_cfm_connect_work_queue,
                                  JOIN_WORKQ_THREADS);
        rna_service_workq_flush(ctx->cx_cfm_work_queue);
        rna_service_workq_destroy(ctx->cx_cfm_work_queue,
                                  JOIN_WORKQ_THREADS);
        rna_service_free(sizeof(*ctx), ctx);
        *ctxpp = NULL;
        return (RNA_SERVICE_ERROR_WORKQ_INIT_FAILURE);
    }

    ret = rna_service_workq_create(RNA_SERVICE_MD_WORK_QUEUE_THREADS,
                                   RNA_UTIL_THREAD_PRIORITY_HIGH, 
                                   RNA_SERVICE_WORK_QUEUE_SIZE, 
                                   &ctx->cx_md_work_queue);

    if (ret != 0 || (NULL == ctx->cx_md_work_queue)) {
        rna_dbg_log(RNA_DBG_WARN, "Could not create md work queue: %d\n", ret);
        rna_service_workq_flush(ctx->cx_cfm_connect_work_queue);
        rna_service_workq_destroy(ctx->cx_cfm_connect_work_queue,
                                  JOIN_WORKQ_THREADS);
        rna_service_workq_flush(ctx->cx_cfm_work_queue);
        rna_service_workq_destroy(ctx->cx_cfm_work_queue,
                                  JOIN_WORKQ_THREADS);
        rna_service_workq_flush(ctx->cx_control_cs_work_queue);
        rna_service_workq_destroy(ctx->cx_control_cs_work_queue,
                                  JOIN_WORKQ_THREADS);
        rna_service_free(sizeof(*ctx), ctx);
        *ctxpp = NULL;
        return (RNA_SERVICE_ERROR_WORKQ_INIT_FAILURE);
    }

    /*
     * Create a work queue to invoke user callbacks  NOTE that this work queue
     * is needed even if the user has specified RNA_SERVICE_FLAG_NO_WORKQ to
     * handle events such as RNA_SERVICE_EVENT_DETACHED_FROM_CLUSTER,
     * RNA_SERVICE_EVENT_REJOINED_CLUSTER, and
     * RNA_SERVICE_EVENT_SEND_SHUTDOWN_REQUEST_TIMEOUT.
     */
    ret = rna_service_workq_create(RNA_SERVICE_CALLBACK_WORK_QUEUE_THREADS,
                                   RNA_UTIL_THREAD_PRIORITY_HIGH, 
                                   RNA_SERVICE_WORK_QUEUE_SIZE, 
                                   &ctx->cx_response_callback_work_queue);

    if (ret != 0 || (NULL == ctx->cx_response_callback_work_queue)) {
        rna_dbg_log(RNA_DBG_WARN, "Could not create work queue: %d\n", ret);
        rna_service_workq_flush(ctx->cx_cfm_connect_work_queue);
        rna_service_workq_destroy(ctx->cx_cfm_connect_work_queue,
                                  JOIN_WORKQ_THREADS);
        rna_service_workq_flush(ctx->cx_cfm_work_queue);
        rna_service_workq_destroy(ctx->cx_cfm_work_queue,
                                  JOIN_WORKQ_THREADS);
        rna_service_workq_flush(ctx->cx_control_cs_work_queue);
        rna_service_workq_destroy(ctx->cx_control_cs_work_queue,
                                  JOIN_WORKQ_THREADS);
        rna_service_workq_flush(ctx->cx_md_work_queue);
        rna_service_workq_destroy(ctx->cx_md_work_queue,
                                  JOIN_WORKQ_THREADS);
        rna_service_free(sizeof(*ctx), ctx);
        *ctxpp = NULL;
        return (RNA_SERVICE_ERROR_WORKQ_INIT_FAILURE);
    }

    YAQ_INIT(&ctx->cx_cfm_msgs_waiting_to_send);
    YAQ_INIT(&ctx->cx_cfm_registrations_waiting_to_send);
    YAQ_INIT(&ctx->cx_cfm_waiting_for_reply);
    YAQ_INIT(&ctx->cx_registrations_waiting_for_reply);
    YAQ_INIT(&ctx->cx_registered);
    YAQ_INIT(&ctx->cx_md_registered_paths);
    YAQ_INIT(&ctx->cx_deregistrations_waiting_for_reply);
    /* (The +1 in the following is for the PREMATURE_PARTITION) */
    for (i = 0; i < MAX_MD_HASH_PARTITIONS + 1; i++) {
        YAQ_INIT(&ctx->cx_partitions[i].pi_waiting_to_send);
        YAQ_INIT(&ctx->cx_partitions[i].pi_waiting_for_reply);
    }

    /*
     * The following is a fake setting of the overflow flag, to trigger an
     * initial RNA_SERVICE_EVENT_INFO_FULLY_CONNECTED event when connections
     * are established to all the MDs.
     */
    ctx->cx_md_flags |= CTX_MD_FLAG_MSGS_OUTSTANDING_OVERFLOWED;

    ctx->cx_params = *params;
    if (cs_params != NULL) {
        ctx->cx_cs_params = *cs_params;
    }
    if (md_params != NULL) {
        ctx->cx_md_params = *md_params;
    }

    rna_service_mutex_init(&ctx->cx_cfm_mutex);
    rna_service_mutex_init(&ctx->cx_md_mutex);

    rna_service_timer_init(&ctx->cx_reconnect_mds_timer_object.sto_timer);
    rna_service_timer_init(&ctx->cx_reconnect_cfms_timer_object.sto_timer);
    rna_service_timer_init(&ctx->cx_primary_cfm_registration_timer.sto_timer);
    rna_service_timer_init(&ctx->cx_cs_cfm_registration_timer.sto_timer);
    rna_service_timer_init(&ctx->cx_primary_cfm_heartbeat_timer.sto_timer);
    rna_service_timer_init(&ctx->cx_non_primary_cfm_ping_timer.sto_timer);
    rna_service_timer_init(&ctx->cx_send_waiting_cfm_msgs_timer.sto_timer);
    rna_service_timer_init(&ctx->cx_send_shutdown_request_timer.sto_timer);
    ctx->cx_send_shutdown_request_timer_is_set = FALSE;
    RNA_SERVICE_WORK_INIT(&ctx->cx_ping_mds_work_object,
                          ping_mds,
                          (rna_service_workq_cb_arg_t)ctx);
    rna_service_timer_init(&ctx->cx_ping_mds_timer_object.sto_timer);

    /*
     * NOTE that no mempool object is allowed to be smaller than a
     * list_element_t, since it must be possible to overlay a mempool object
     * with a list_element_t (see mempool_free).
     */
    mempool_init(ctx,
                 MEMPOOL_ID_MD_RESPONSE_WORK_CTX,
                 sizeof(invoke_callback_work_ctx_t),
                 sizeof(invoke_callback_work_ctx_t),
                 MEMPOOL_NUM_ELEMENTS_MD_RESPONSE_WORK_CTX,
                 MEMPOOL_NUM_ELEMENTS_MD_RESPONSE_WORK_CTX_RESERVE);
    mempool_init(ctx,
                 MEMPOOL_ID_CFM_WORK_CTX,
                 sizeof(cfm_work_ctx_t),
                 sizeof(cfm_work_ctx_t),
                 MEMPOOL_NUM_ELEMENTS_CFM_WORK_CTX,
                 MEMPOOL_NUM_ELEMENTS_CFM_WORK_CTX_RESERVE);
    mempool_init(ctx,
                 MEMPOOL_ID_MD_INFO,
                 sizeof(md_info_t),
                 sizeof(md_info_t),
                 MEMPOOL_NUM_ELEMENTS_MD_INFO,
                 MEMPOOL_NUM_ELEMENTS_MD_INFO_RESERVE);
    mempool_init(ctx,
                 MEMPOOL_ID_METADATA_QUERY_SEND,
                 RNAS_MESSAGE_SIZE(rna_service_metadata_query_t,
                                   PATHNAME_LEN), // max. size for an  md query
                 RNAS_MESSAGE_SIZE(rna_service_metadata_query_t, 1),
                                           // don't clear the entire pathname
                 MEMPOOL_NUM_ELEMENTS_METADATA_QUERY_SEND,
                 MEMPOOL_NUM_ELEMENTS_METADATA_QUERY_SEND_RESERVE);
    mempool_init(ctx,
                 MEMPOOL_ID_METADATA_QUERY_RESPONSE,
                 RNAS_MESSAGE_SIZE(rna_service_metadata_query_response_t, 0),
                 RNAS_MESSAGE_SIZE(rna_service_metadata_query_response_t, 0),
                 MEMPOOL_NUM_ELEMENTS_METADATA_QUERY_RESPONSE,
                 MEMPOOL_NUM_ELEMENTS_METADATA_QUERY_RESPONSE_RESERVE);
    mempool_init(ctx,
                 MEMPOOL_ID_CACHE_INVALIDATE_SEND,
                 RNAS_MESSAGE_SIZE(rna_service_cache_invalidate_t,
                                   PATHNAME_LEN), // max. size for a cache invd
                 RNAS_MESSAGE_SIZE(rna_service_cache_invalidate_t, 1),
                                           // don't clear the entire pathname
                 MEMPOOL_NUM_ELEMENTS_CACHE_INVALIDATE_SEND,
                 MEMPOOL_NUM_ELEMENTS_CACHE_INVALIDATE_SEND_RESERVE);
    mempool_init(ctx,
                 MEMPOOL_ID_CACHE_INVALIDATE_RESPONSE,
                 RNAS_MESSAGE_SIZE(rna_service_cache_invalidate_response_t, 0),
                 RNAS_MESSAGE_SIZE(rna_service_cache_invalidate_response_t, 0),
                 MEMPOOL_NUM_ELEMENTS_CACHE_INVALIDATE_RESPONSE,
                 MEMPOOL_NUM_ELEMENTS_CACHE_INVALIDATE_RESPONSE_RESERVE);
    mempool_init(ctx,
                 MEMPOOL_ID_CACHE_RESPONSE,
                 RNAS_MESSAGE_SIZE(rna_service_cache_response_t, PATHNAME_LEN),
                                            // max. size for a cache response
                 RNAS_MESSAGE_SIZE(rna_service_cache_response_t, 1),
                                           // don't clear the entire pathname
                 MEMPOOL_NUM_ELEMENTS_CACHE_RESPONSE,
                 MEMPOOL_NUM_ELEMENTS_CACHE_RESPONSE_RESERVE);

    rna_service_ctx_private_data_init(&ctx->cx_private);

    ctx->cx_md_next_msg_id = 1;
    ctx->cx_cfm_next_msg_id = 1;

    rna_service_com_attr_init(&ctx->cx_com_attributes,
                              accept_callback,  // invoked at user-level only
                              connect_callback,
                              disconnect_callback,
                              recv_callback,
                              rdma_read_callback);

    ctx->cx_com_instance = rna_service_com_init(params->rsp_transports,
                                                (void *)ctx);
    if (NULL == ctx->cx_com_instance) {
        rna_dbg_log(RNA_DBG_WARN, "Failed to create com instance\n");
        rna_service_ctx_destroy(&ctx);
        *ctxpp = NULL;
        return (RNA_SERVICE_ERROR_COM_INIT_FAILURE);
    }

    if (params->rsp_flags & RNA_SERVICE_COM_INFINITE_TIMEOUTS) {
        /*
         * Though the following has a return argument, it can't actually fail.
         */
        (void) rna_service_com_set_infinite_timeouts_attr(TRUE);
    }

    if (params->rsp_keep_alive_count &&
        params->rsp_keep_alive_wait &&
        params->rsp_keep_alive_interval) {
        (void) rna_service_com_set_keep_alive_attributes(
                                            &ctx->cx_com_attributes,
                                            params->rsp_keep_alive_count,
                                            params->rsp_keep_alive_wait,
                                            params->rsp_keep_alive_interval);
    }

    if (params->rsp_flags & RNA_SERVICE_FLAG_TCP_NODELAY_OFF) {
        /*
         * Though the following has a return argument, it can't actually fail.
         */
        (void) rna_service_com_set_tcp_nodelay_attr(&ctx->cx_com_attributes,
                                                    FALSE);
    } else {
        (void) rna_service_com_set_tcp_nodelay_attr(&ctx->cx_com_attributes,
                                                    TRUE);
    }

    /*
     * -----------------------------------------------------------------------
     * The newly-created context is now fully initialized, set the caller's
     * pointer to it.
     *
     * NOTE that this must be done before rna_service begins registering with
     * the CFM and MDs, since once that happens, messages may begin arriving
     * from the primary CFM or MDs (such as a CONF_MGR_QUERY_CACHE_DEVICE
     * message from the CFM).  Such messages may be processed by threads other
     * than the one that invoked this function, and will need this pointer in
     * order to service these messages (for instance, in order to call
     * rna_service_cs_register_cache_device() and
     * rna_service_cs_initial_cache_device_registrations_complete(), each of
     * which will fail (with RNA_SERVICE_ERROR_INVALID_CTX) if a NULL
     * rna_service_ctx is supplied as an argument).
     * -----------------------------------------------------------------------
     */
    *ctxpp = ctx;

    /*
     * Open connections to all the configuration managers.  We do this by
     * faking a timeout expiration.
     *
     * NOTE that it's important that the caller's pointer to the newly-created
     * context be set before this point (see above).
     */
    if (rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
        queue_reconnect_cfms(ctx);
        rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
    }

    /*
     * Begin periodically pinging the MDs, if the user has requested it
     */
    if (0 != params->rsp_md_ping_rate) {
        rna_service_timer_set(ctx->cx_private,
                             &ctx->cx_ping_mds_timer_object,
                              ping_mds_timer,
                              (uint64_t)ctx,
                              1);
    }

    /*
     * Start the cycle of sending empty pings to non-primary CFMs.
     */
    rna_service_timer_set(ctx->cx_private,
                         &ctx->cx_non_primary_cfm_ping_timer,
                          ping_non_primary_cfms_to,
                          (uint64_t)ctx,
                          NON_PRIMARY_CFM_PING_SEC);

    return (RNA_SERVICE_ERROR_NONE);
}


/*
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
rna_service_error_t
rna_service_ctx_create(rna_service_params_t *params, rna_service_ctx_t **ctxpp)
{
    return (rna_service_cs_md_ctx_create(params, NULL, NULL, ctxpp));
}


/*
 * Used by rna_service_alloc_message_buffer and
 * rna_service_alloc_cs_md_message_buffer only to initialize an ibuf.
 */
static void
init_ibuf(rna_service_ctx_t                     *ctx,
          rna_service_message_buffer_internal_t *ibuf,
          rna_service_message_type_t             msg_type,
          uint8_t                                mempool_id)
{
    ibuf->h.rmbi_watermark = MESSAGE_BUFFER_INTERNAL_WATERMARK_ALLOCATED;
    YAQ_INIT(&ibuf->h.rmbi_link);
    ibuf->h.rmbi_ctx = ctx;
    ibuf->h.rmbi_msg_type = msg_type;
    ibuf->h.rmbi_mempool_id = mempool_id;
    ibuf->u.rmbi_message_buffer.h.rmb_message_type = msg_type;
    rna_service_timer_init(&ibuf->h.rmbi_response_timer_object.sto_timer);
    ibuf->h.rmbi_flags = 0;
}


/**
 * Allocate an rna_service message buffer.
 *
 * NOTE that once this message buffer has been used as an argument to an
 * rna_service_send_XXX function, it may not be modified, freed, or re-used
 * until it is returned as the 'message_sent' argument of a response callback.
 *
 * Arguments:
 *    ctx       The caller's rna_service context, created by
 *              rna_service_ctx_create()
 *    msg_type  The type of message that will be stored in the buffer.  Note
 *              that no other message type may be stored in the buffer.
 *    msg_str   A pathname or error string:
 *                A pathname must be specified for messages of the following
 *                types:
 *                  RNA_SERVICE_MESSAGE_TYPE_MD_QUERY
 *                  RNA_SERVICE_MESSAGE_TYPE_CACHE_RESPONSE
 *                  RNA_SERVICE_MESSAGE_TYPE_CACHE_INVD
 *                  RNA_SERVICE_MESSAGE_TYPE_CACHE_MASTER_INVD
 *                  RNA_SERVICE_MESSAGE_TYPE_REG_PATH
 *                  RNA_SERVICE_MESSAGE_TYPE_REG_BLKDEV
 *                  RNA_SERVICE_MESSAGE_TYPE_DEREG_BLKDEV
 *                  RNA_SERVICE_MESSAGE_TYPE_CREATE_BLKDEV
 *                  RNA_SERVICE_MESSAGE_TYPE_DEREG_PATH
 *                An error string may be specified for messages of the
 *                following types:
 *                  RNA_SERVICE_MESSAGE_TYPE_REG_CACHE_DEVICE
 *
 * Returns:
 *    A pointer to a message buffer on success
 *    NULL on failure
 */
rna_service_message_buffer_t *
rna_service_alloc_message_buffer(rna_service_ctx_t         *ctx,
                                 rna_service_message_type_t msg_type,
                                 const char                *msg_str)
{
    rna_service_message_buffer_internal_t *ibuf = NULL;
    uint8_t mempool_id = MEMPOOL_ID_INVALID;

    if ((NULL == ctx)
      || (ctx->cx_watermark != RNA_SERVICE_CTX_WATERMARK)
      || (!ctx_add_reference(&ctx))) {
        return (NULL);
    }

    switch (msg_type) {
        case RNA_SERVICE_MESSAGE_TYPE_MD_QUERY:
            /* The caller must specify a pathname for this message type */
            if (NULL != msg_str) {
                ibuf = mempool_alloc(ctx,
                                     MEMPOOL_ID_METADATA_QUERY_SEND,
                                     (PATHNAME_LEN - strlen(msg_str)) - 1);
                if (NULL != ibuf) {
                    mempool_id = MEMPOOL_ID_METADATA_QUERY_SEND;
                }
            } else {
                rna_dbg_log(RNA_DBG_ERR,
                            "pathname must be specified for %s\n",
                            rna_service_get_message_type_string(msg_type));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_CACHE_INVD:
        case RNA_SERVICE_MESSAGE_TYPE_CACHE_MASTER_INVD:
            /* The caller must specify a pathname for this message type */
            if (NULL != msg_str) {
                ibuf = mempool_alloc(ctx,
                                     MEMPOOL_ID_CACHE_INVALIDATE_SEND,
                                     (PATHNAME_LEN - strlen(msg_str)) - 1);
                if (NULL != ibuf) {
                    mempool_id = MEMPOOL_ID_CACHE_INVALIDATE_SEND;
                }
            } else {
                rna_dbg_log(RNA_DBG_ERR,
                            "pathname must be specified for %s\n",
                            rna_service_get_message_type_string(msg_type));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_REG_PATH:
        case RNA_SERVICE_MESSAGE_TYPE_DEREG_PATH:
            /* The caller must specify a pathname for these message types */
            if (NULL == msg_str) {
                ibuf = rna_service_simple_alloc(
                                RNAS_MESSAGE_SIZE(rna_service_register_path_t, 0));
                if (NULL != ibuf) {
                    memset(ibuf, 0, RNAS_MESSAGE_SIZE(
                                          rna_service_register_path_t, 0));
                }
            } else {
                rna_dbg_log(RNA_DBG_ERR,
                            "pathname must NOT be specified for %s\n",
                            rna_service_get_message_type_string(msg_type));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_REG_MNT:
            ibuf = rna_service_simple_alloc(
                        RNAS_MESSAGE_SIZE(rna_service_register_mount_t,
                                          0));
            if (NULL != ibuf) {
                memset(ibuf, 0, RNAS_MESSAGE_SIZE(
                                          rna_service_register_mount_t,
                                          0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_NOTIFICATION_EVENT:
            ibuf = rna_service_simple_alloc(
                        RNAS_MESSAGE_SIZE(rna_service_notification_event_t,
                                          0));
            if (NULL != ibuf) {
                memset(ibuf, 0, RNAS_MESSAGE_SIZE(
                                          rna_service_notification_event_t,
                                          0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_NUM_MD_HASH_PARTITIONS:
            ibuf = rna_service_simple_alloc(
                        RNAS_MESSAGE_SIZE(rna_service_num_md_hash_partitions_t,
                                          0));
            if (NULL != ibuf) {
                memset(ibuf, 0, RNAS_MESSAGE_SIZE(
                                          rna_service_num_md_hash_partitions_t,
                                          0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_DEREG_MNT:
            ibuf = rna_service_simple_alloc(
                        RNAS_MESSAGE_SIZE(rna_service_deregister_mount_t,
                                          0));
            if (NULL != ibuf) {
                memset(ibuf, 0, RNAS_MESSAGE_SIZE(
                                          rna_service_deregister_mount_t,
                                          0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_REG_BLKDEV:
        case RNA_SERVICE_MESSAGE_TYPE_DEREG_BLKDEV:
            /* The caller must specify a pathname for this message type */
            if (NULL != msg_str) {
                rna_dbg_log(RNA_DBG_INFO,
                            "Allocating "
                            "%s path [%s]\n",
                            rna_service_get_message_type_string(msg_type),
                            (NULL==msg_str) ? "nil" : msg_str);
                ibuf = rna_service_simple_alloc(
                        RNAS_MESSAGE_SIZE(rna_service_register_block_device_t,
                                          strlen(msg_str) + 1));
                if (NULL != ibuf) {
                    /* Don't clear the entire pathname, since it may be huge */
                    memset(ibuf, 0, RNAS_MESSAGE_SIZE(
                                          rna_service_register_block_device_t,
                                          1));
                }
            } else {
                rna_dbg_log(RNA_DBG_ERR,
                            "pathname must be specified for %s\n",
                            rna_service_get_message_type_string(msg_type));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_REG_SVC_CONN:
            ibuf = rna_service_simple_alloc(
                   RNAS_MESSAGE_SIZE(rna_service_register_svc_conn_t,
                                     0));
            if (NULL != ibuf) {
                memset(ibuf, 0, RNAS_MESSAGE_SIZE(
                                     rna_service_register_svc_conn_t,
                                     0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_DEREG_SVC_CONN:
            ibuf = rna_service_simple_alloc(
                   RNAS_MESSAGE_SIZE(rna_service_deregister_svc_conn_t,
                                     0));
            if (NULL != ibuf) {
                memset(ibuf, 0, RNAS_MESSAGE_SIZE(
                                     rna_service_deregister_svc_conn_t,
                                     0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_REG_CACHE_DEVICE:
            if (NULL != msg_str) {
                ibuf = rna_service_simple_alloc(
                    RNAS_MESSAGE_SIZE(rna_service_register_cache_device_t,
                                      strlen(msg_str) + 1));
            } else {
                ibuf = rna_service_simple_alloc(
                    RNAS_MESSAGE_SIZE(rna_service_register_cache_device_t,
                                      0));
            }

            if (NULL != ibuf) {
                memset(ibuf, 0, RNAS_MESSAGE_SIZE(
                                     rna_service_register_cache_device_t,
                                     0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_REG_CACHE_DEVICE_END:
            ibuf = rna_service_simple_alloc(
                    RNAS_MESSAGE_SIZE(rna_service_register_cache_device_end_t,
                                     0));
            if (NULL != ibuf) {
                memset(ibuf, 0, RNAS_MESSAGE_SIZE(
                                     rna_service_register_cache_device_end_t,
                                     0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_DEREG_CACHE_DEVICE:
            ibuf = rna_service_simple_alloc(
                   RNAS_MESSAGE_SIZE(rna_service_deregister_cache_device_t,
                                     0));
            if (NULL != ibuf) {
                memset(ibuf, 0, RNAS_MESSAGE_SIZE(
                                     rna_service_deregister_cache_device_t,
                                     0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_EXPEL_CACHE_DEVICE:
            ibuf = rna_service_simple_alloc(
                   RNAS_MESSAGE_SIZE(rna_service_expel_cache_device_t,
                                     0));
            if (NULL != ibuf) {
                memset(ibuf, 0, RNAS_MESSAGE_SIZE(
                                     rna_service_expel_cache_device_t,
                                     0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_UNEXPELLED_CACHEDEVS:
            ibuf = rna_service_simple_alloc(
                   RNAS_MESSAGE_SIZE(rna_service_unexpelled_cachedevs_t,
                                     0));
            if (NULL != ibuf) {
                memset(ibuf, 0, RNAS_MESSAGE_SIZE(
                                     rna_service_unexpelled_cachedevs_t,
                                     0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_DEREG_REPLICA_STORE:
            ibuf = rna_service_simple_alloc(
                   RNAS_MESSAGE_SIZE(rna_service_deregister_replica_store_t,
                                     0));
            if (NULL != ibuf) {
                memset(ibuf, 0, RNAS_MESSAGE_SIZE(
                                     rna_service_deregister_replica_store_t,
                                     0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_RESILVER_CACHE_DEVICE_COMPLETE:
            ibuf = rna_service_simple_alloc(
                   RNAS_MESSAGE_SIZE(
                                rna_service_resilver_cache_device_complete_t,
                                0));
            if (NULL != ibuf) {
                memset(ibuf, 0, RNAS_MESSAGE_SIZE(
                                 rna_service_resilver_cache_device_complete_t,
                                 0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_CS_SHUTDOWN_REQUEST:
            ibuf = rna_service_simple_alloc(
                   RNAS_MESSAGE_SIZE(rna_service_cs_shutdown_request_t, 0));
            if (NULL != ibuf) {
                memset(ibuf, 0, RNAS_MESSAGE_SIZE(
                                 rna_service_cs_shutdown_request_t,
                                 0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_CS_SHUTDOWN_RESPONSE:
            ibuf = rna_service_simple_alloc(
                   RNAS_MESSAGE_SIZE(rna_service_cs_shutdown_response_t, 0));
            if (NULL != ibuf) {
                memset(ibuf, 0, RNAS_MESSAGE_SIZE(
                                 rna_service_cs_shutdown_response_t,
                                 0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_EVENT:
            ibuf = rna_service_simple_alloc(
                   RNAS_MESSAGE_SIZE(rna_service_event_msg_t, 0));
            if (NULL != ibuf) {
                memset(ibuf, 0, RNAS_MESSAGE_SIZE(rna_service_event_msg_t, 0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_MD_QUERY_RESPONSE:
            /*
             * Since this is a latency-sensitive message, try first to allocate
             * from the pre-allocated pool for this message type.
             */
            ibuf = mempool_alloc(ctx, MEMPOOL_ID_METADATA_QUERY_RESPONSE, 0);
            if (NULL != ibuf) {
                mempool_id = MEMPOOL_ID_METADATA_QUERY_RESPONSE;
            }
            break;
            
        case RNA_SERVICE_MESSAGE_TYPE_CREATE_BLKDEV:
            /* The caller must specify a pathname for this message type */
            if (NULL != msg_str) {
                rna_dbg_log(RNA_DBG_INFO,
                           "Allocating "
                           "RNA_SERVICE_MESSAGE_TYPE_CREATE_BLKDEV path [%s]\n",
                            (NULL==msg_str) ? "nil" : msg_str);
                ibuf = rna_service_simple_alloc(
                           RNAS_MESSAGE_SIZE(rna_service_create_block_device_t,
                                             strlen(msg_str) + 1));
                if (NULL != ibuf) {
                    /* Don't clear the entire pathname, since it may be huge */
                    memset(ibuf, 0, RNAS_MESSAGE_SIZE(
                                             rna_service_create_block_device_t,
                                             1));
                }
            } else {
                rna_dbg_log(RNA_DBG_ERR,
                            "pathname must be specified for %s\n",
                            rna_service_get_message_type_string(msg_type));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_CONTROL_BLKDEV:
            /* The caller must specify a pathname for this message type */
            if (NULL != msg_str) {
                rna_dbg_log(RNA_DBG_INFO,
                           "Allocating "
                           "RNA_SERVICE_MESSAGE_TYPE_CONTROL_BLKDEV "
                           "path [%s]\n",
                            (NULL==msg_str) ? "nil" : msg_str);
                ibuf = rna_service_simple_alloc(
                           RNAS_MESSAGE_SIZE(rna_service_control_block_device_t,
                                             strlen(msg_str) + 1));
                if (NULL != ibuf) {
                    /* Don't clear the entire pathname, since it may be huge */
                    memset(ibuf, 0, RNAS_MESSAGE_SIZE(
                                             rna_service_control_block_device_t,
                                             1));
                }
            } else {
                rna_dbg_log(RNA_DBG_ERR,
                            "pathname must be specified for %s\n",
                            rna_service_get_message_type_string(msg_type));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_CONTROL_BLKDEV_RESPONSE:
            /* The caller must specify a pathname for this message type */
            if (NULL != msg_str) {
                rna_dbg_log(RNA_DBG_INFO,
                           "Allocating "
                           "RNA_SERVICE_MESSAGE_TYPE_CONTROL_BLKDEV_RESPONSE "
                           "path [%s]\n",
                            (NULL==msg_str) ? "nil" : msg_str);
                ibuf = rna_service_simple_alloc(
                               RNAS_MESSAGE_SIZE(
                                   rna_service_control_block_device_response_t,
                                   strlen(msg_str) + 1));
                if (NULL != ibuf) {
                    /* Don't clear the entire pathname, since it may be huge */
                    memset(ibuf,
                           0,
                           RNAS_MESSAGE_SIZE(
                                rna_service_control_block_device_response_t,
                                1));
                }
            } else {
                rna_dbg_log(RNA_DBG_ERR,
                            "pathname must be specified for %s\n",
                            rna_service_get_message_type_string(msg_type));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_CACHE_INVD_RESPONSE:
            /*
             * Since this is a latency-sensitive message, try first to allocate
             * from the pre-allocated pool for this message type.
             */
            ibuf = mempool_alloc(ctx, MEMPOOL_ID_CACHE_INVALIDATE_RESPONSE, 0);
            if (NULL != ibuf) {
                mempool_id = MEMPOOL_ID_CACHE_INVALIDATE_RESPONSE;
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_REG_MNT_RESPONSE:
            ibuf = rna_service_simple_alloc(
                       RNAS_MESSAGE_SIZE(rna_service_register_mount_response_t,
                                         0));
            if (NULL != ibuf) {
                memset(ibuf,
                       0,
                       RNAS_MESSAGE_SIZE(rna_service_register_mount_response_t,
                                         0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_DEREG_MNT_RESPONSE:
            ibuf = rna_service_simple_alloc(
                       RNAS_MESSAGE_SIZE(
                                rna_service_deregister_mount_response_t,
                                0));
            if (NULL != ibuf) {
                memset(ibuf,
                       0,
                       RNAS_MESSAGE_SIZE(
                                rna_service_deregister_mount_response_t,
                                0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_REG_BLKDEV_RESPONSE:
            ibuf = rna_service_simple_alloc(
                       RNAS_MESSAGE_SIZE(
                                rna_service_register_block_device_response_t,
                                0));
            if (NULL != ibuf) {
                memset(ibuf,
                       0,
                       RNAS_MESSAGE_SIZE(
                                rna_service_register_block_device_response_t,
                                0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_DEREG_BLKDEV_RESPONSE:
            ibuf = rna_service_simple_alloc(
                       RNAS_MESSAGE_SIZE(
                                rna_service_deregister_block_device_response_t,
                                0));
            if (NULL != ibuf) {
                memset(ibuf,
                       0,
                       RNAS_MESSAGE_SIZE(
                                rna_service_deregister_block_device_response_t,
                                0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_SET_LOG_LEVEL:
            ibuf = rna_service_simple_alloc(
                       RNAS_MESSAGE_SIZE(rna_service_set_log_level_t, 0));
            if (NULL != ibuf) {
                memset(ibuf,
                       0,
                       RNAS_MESSAGE_SIZE(rna_service_set_log_level_t, 0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_CLIENT_EVENT_REG:
            ibuf = rna_service_simple_alloc(
                       RNAS_MESSAGE_SIZE(rna_service_client_event_reg_t, 0));
            if (NULL != ibuf) {
                memset(ibuf,
                       0,
                       RNAS_MESSAGE_SIZE(rna_service_client_event_reg_t, 0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_CLIENT_EVENT_DEREG:
            ibuf = rna_service_simple_alloc(
                       RNAS_MESSAGE_SIZE(rna_service_client_event_dereg_t, 0));
            if (NULL != ibuf) {
                memset(ibuf,
                       0,
                       RNAS_MESSAGE_SIZE(rna_service_client_event_dereg_t, 0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_CLIENT_EVENT:
            ibuf = rna_service_simple_alloc(
                       RNAS_MESSAGE_SIZE(rna_service_client_event_t, 0));
            if (NULL != ibuf) {
                memset(ibuf,
                       0,
                       RNAS_MESSAGE_SIZE(rna_service_client_event_t, 0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_CONF_MGR_REG_RESPONSE:
            ibuf = rna_service_simple_alloc(
                       RNAS_MESSAGE_SIZE(rna_service_cfm_client_resp_t, 0));
            if (NULL != ibuf) {
                memset(ibuf,
                       0,
                       RNAS_MESSAGE_SIZE(rna_service_cfm_client_resp_t, 0));
            }
            break;
        case RNA_SERVICE_MESSAGE_TYPE_BSTAT_REQUEST:
            ibuf = rna_service_simple_alloc(
                       RNAS_MESSAGE_SIZE(rna_service_bstat_req_t, 0));
            if (NULL != ibuf) {
                memset(ibuf,
                       0,
                       RNAS_MESSAGE_SIZE(rna_service_bstat_req_t, 0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_BSTAT_RESPONSE:
            ibuf = rna_service_simple_alloc(
                       RNAS_MESSAGE_SIZE(rna_service_bstat_response_t, 0));
            if (NULL != ibuf) {
                memset(ibuf,
                       0,
                       RNAS_MESSAGE_SIZE(rna_service_bstat_response_t, 0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_EXPEL_CS:
            ibuf = rna_service_simple_alloc(
                       RNAS_MESSAGE_SIZE(rna_service_expel_cs_t, 0));
            if (NULL != ibuf) {
                memset(ibuf, 0, RNAS_MESSAGE_SIZE(rna_service_expel_cs_t, 0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_CONTROL_CS:
            /* if a pathname is specified, account for it in the size */
            if (NULL == msg_str) {
                ibuf = rna_service_simple_alloc(
                           RNAS_MESSAGE_SIZE(rna_service_control_cs_t, 0));
            } else {
                rna_dbg_log(RNA_DBG_ERR,
                           "msg contains a wwn not a path "
                           "RNA_SERVICE_MESSAGE_TYPE_CONTROL_CS path [%s]\n",
                            msg_str);
                ibuf = NULL;
            }
            if (NULL != ibuf) {
                memset(ibuf, 0, RNAS_MESSAGE_SIZE(rna_service_control_cs_t, 0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_CONTROL_CS_RESPONSE:
            ibuf = rna_service_simple_alloc(
                       RNAS_MESSAGE_SIZE(rna_service_control_cs_response_t, 0));
            if (NULL != ibuf) {
                memset(ibuf,
                       0,
                       RNAS_MESSAGE_SIZE(rna_service_control_cs_response_t, 0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_RELOCATE_BLOCK:
            ibuf = rna_service_simple_alloc(
                       RNAS_MESSAGE_SIZE(rna_service_relocate_cache_block_t,
                                         0));
            if (NULL != ibuf) {
                memset(ibuf,
                       0,
                       RNAS_MESSAGE_SIZE(rna_service_relocate_cache_block_t,
                                         0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_ABSORB_BLOCK:
            /* The caller must specify a pathname for this message type */
            if (NULL != msg_str) {
                ibuf = rna_service_simple_alloc(
                           RNAS_MESSAGE_SIZE(rna_service_cache_absorb_block_t,
                                             strlen(msg_str) + 1));
                if (NULL != ibuf) {
                    memset(ibuf,
                           0,
                           RNAS_MESSAGE_SIZE(rna_service_cache_absorb_block_t,
                                             strlen(msg_str) + 1));
                }
            } else {
                rna_dbg_log(RNA_DBG_ERR,
                            "pathname must be specified for %s\n",
                            rna_service_get_message_type_string(msg_type));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_ABSORB_BLOCK_RESPONSE:
            ibuf = rna_service_simple_alloc(
                       RNAS_MESSAGE_SIZE(
                                    rna_service_cache_absorb_block_response_t,
                                    0));
            if (NULL != ibuf) {
                memset(ibuf,
                       0,
                       RNAS_MESSAGE_SIZE(
                                    rna_service_cache_absorb_block_response_t,
                                    0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_INVD_HOLD_RESPONSE:
            ibuf = rna_service_simple_alloc(
                       RNAS_MESSAGE_SIZE(rna_service_invd_hold_response_t, 0));
            if (NULL != ibuf) {
                memset(ibuf,
                       0,
                       RNAS_MESSAGE_SIZE(rna_service_invd_hold_response_t, 0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_CS_CLIENT_REG:
            ibuf = rna_service_simple_alloc(
                       RNAS_MESSAGE_SIZE(rna_service_cache_client_reg_t, 0));
            if (NULL != ibuf) {
                memset(ibuf, 0, RNAS_MESSAGE_SIZE(rna_service_cache_client_reg_t, 0));
            }
            break;

        // begin SCSI III journal message types
        case RNA_SERVICE_MESSAGE_TYPE_UPDATE_SCSI_ITN_RES:
            ibuf = rna_service_simple_alloc(
                RNAS_MESSAGE_SIZE(rna_service_update_scsi_itn_reservation_t,
                                  0));
            if (NULL != ibuf) {
                memset(ibuf, 0,
                RNAS_MESSAGE_SIZE(rna_service_update_scsi_itn_reservation_t,
                                  0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_UPDATE_SCSI_ITN_REG:
            ibuf = rna_service_simple_alloc(
                RNAS_MESSAGE_SIZE(rna_service_update_scsi_itn_registration_t,
                                  0));
            if (NULL != ibuf) {
                memset(ibuf, 0,
                RNAS_MESSAGE_SIZE(rna_service_update_scsi_itn_registration_t,
                                  0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_CLEAR_SCSI_ITN_RES:
            ibuf = rna_service_simple_alloc(
                RNAS_MESSAGE_SIZE(rna_service_clear_scsi_itn_reservation_t,
                                  0));
            if (NULL != ibuf) {
                memset(ibuf, 0,
                RNAS_MESSAGE_SIZE(rna_service_clear_scsi_itn_reservation_t,
                                  0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_ACQUIRE_SCSI_ITN_RES:
            ibuf = rna_service_simple_alloc(
                RNAS_MESSAGE_SIZE(rna_service_acquire_scsi_itn_res_t,
                                  0));
            if (NULL != ibuf) {
                memset(ibuf, 0,
                RNAS_MESSAGE_SIZE(rna_service_acquire_scsi_itn_res_t,
                                  0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_ACQUIRE_SCSI_ITN_REG:
            ibuf = rna_service_simple_alloc(
               RNAS_MESSAGE_SIZE(rna_service_acquire_scsi_itn_reg_t,
                                  0));
            if (NULL != ibuf) {
               memset(ibuf, 0,
               RNAS_MESSAGE_SIZE(rna_service_acquire_scsi_itn_reg_t,
                                  0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_UPDATE_CLEAR_SCSI_ITN_RES_RESPONSE:
            ibuf = rna_service_simple_alloc(
            RNAS_MESSAGE_SIZE(rna_service_update_clear_scsi_itn_resg_resp_t,
                                  0));
            if (NULL != ibuf) {
                memset(ibuf, 0,
             RNAS_MESSAGE_SIZE(rna_service_update_clear_scsi_itn_resg_resp_t,
                                  0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_ACQUIRE_SCSI_ITN_RES_RESPONSE:
            ibuf = rna_service_simple_alloc(
                   RNAS_MESSAGE_SIZE(rna_service_acquire_scsi_itn_res_resp_t,
                                  0));
            if (NULL != ibuf) {
                memset(ibuf, 0,
                   RNAS_MESSAGE_SIZE(rna_service_acquire_scsi_itn_res_resp_t,
                                  0));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_ACQUIRE_SCSI_ITN_REG_RESPONSE:
            ibuf = rna_service_simple_alloc(
                RNAS_MESSAGE_SIZE(rna_service_acquire_scsi_itn_reg_resp_t,
                                  0));
            if (NULL != ibuf) {
                memset(ibuf, 0,
                RNAS_MESSAGE_SIZE(rna_service_acquire_scsi_itn_reg_resp_t,
                                  0));
            }
            break;

        // end scsi III journal message types

        case RNA_SERVICE_MESSAGE_TYPE_INVALID:
            break;

        /*
         * NOTE that there is purposely no default case here, so the compiler
         * catches a failure to list a defined message type.  Specifying an
         * illegal (undefined) type is handled below).
         */
    }

    if (NULL == ibuf) {
        rna_dbg_log(RNA_DBG_WARN,
                    "unable to allocate message buffer for message type "
                    "[%d] [%s]\n",
                    msg_type,
                    rna_service_get_message_type_string(msg_type));
        ctx_release_reference(&ctx);
        return (NULL);
    }

    init_ibuf(ctx, ibuf, msg_type, mempool_id);

    /*
     * NOTE that we do not call ctx_release_reference, since we need to
     * maintain a ctx reference as long as the above pointer to the ctx exists
     * (h.rmbi_ctx).  This reference will be released when this message buffer
     * is freed.
     *
     * Return a pointer to the user-visible portion of this struct.
     */
    return (&ibuf->u.rmbi_message_buffer);
}


/**
 * Free an rna_service message buffer, which was returned either as the
 * 'message_sent' or 'response' argument of a response callback.
 *
 * Returns:
 *    RNA_SERVICE_ERROR_NONE  on success
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER
 *                            The message buffer specified was not allocated by
 *                            rna_service_alloc_message_buffer() or has not yet
 *                            been returned in a response callback.
 */
rna_service_error_t
rna_service_free_message_buffer(struct rna_service_ctx_s     *ctx,
                                rna_service_message_buffer_t *buf)
{
    rna_service_message_buffer_internal_t *ibuf;

    if ((NULL == buf)
      || (NULL == ctx)
      || (ctx->cx_watermark != RNA_SERVICE_CTX_WATERMARK)) {
        rna_dbg_log(RNA_DBG_WARN,
                    "invalid ctx, so unable to free message buffer\n");
        return (RNA_SERVICE_ERROR_NONE);
    }

    /* If this buffer has a quota allotment, then release that allotment */
    release_msgbuf_quota(ctx, buf);

    /*
     * NOTE that a reference on the ctx does not need to be acquired, since
     * one was acquired by rna_service_alloc_message_buffer when this message
     * buffer was allocated (when the rmbi_ctx pointer was set).
     */

    ibuf = mbuf_to_ibuf(buf);
    rna_service_assert((MESSAGE_BUFFER_INTERNAL_WATERMARK_QUEUED ==
                                                    ibuf->h.rmbi_watermark)
                    || (MESSAGE_BUFFER_INTERNAL_WATERMARK_ALLOCATED ==
                                                    ibuf->h.rmbi_watermark));
    /* (in case the above assert is debug only) */
    if ((ibuf->h.rmbi_watermark != MESSAGE_BUFFER_INTERNAL_WATERMARK_QUEUED) &&
        (ibuf->h.rmbi_watermark != MESSAGE_BUFFER_INTERNAL_WATERMARK_ALLOCATED))
    {
        rna_dbg_log(RNA_DBG_WARN,
                    "Attempt to free a message buffer that wasn't "
                    "allocated by rna_service_alloc_message_buffer: %p "
                    "%"PRIu64"\n",
                    buf, ibuf->h.rmbi_watermark);
        return (RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER);
    }

    ibuf->h.rmbi_watermark = 0;
    ibuf->h.rmbi_ctx = NULL;
    /*
     * NOTE that even though this message no longer has a pointer to the ctx,
     * the ctx reference can't yet be dropped, since the ctx must still exist
     * below.  The reference will be dropped at the end of this function.
     */

    if (ibuf->h.rmbi_msg_type != buf->h.rmb_message_type) {
        rna_dbg_log(RNA_DBG_WARN,
                    "message type mismatch (%d vs. %d)\n",
                    ibuf->h.rmbi_msg_type,
                    buf->h.rmb_message_type);
    }

    if (!YAQ_EMPTY(&ibuf->h.rmbi_link)) {
        rna_dbg_log(RNA_DBG_ERR,
                    "Freeing buffer that appears to still be linked into "
                    "a queue: %p\n",
                    ibuf);
        YAQ_REMOVE(&ibuf->h.rmbi_link);
    }

    /* cancel timer, in case it's set */
    rna_service_timer_final_cancel(&ibuf->h.rmbi_response_timer_object);

    if (MEMPOOL_ID_INVALID != ibuf->h.rmbi_mempool_id) {
        /* This message buffer was allocated from a memory pool */
        mempool_free(ctx, ibuf->h.rmbi_mempool_id, (void *)ibuf);
    } else {
        /* This message buffer was dynamically allocated */
        rna_service_simple_free((void *)ibuf);
    }

    /*
     * This ctx_release_reference is for the reference that was added in
     * rna_service_alloc_message_buffer when the rmbi_ctx pointer was set.
     */
    ctx_release_reference(&ctx);
    return (RNA_SERVICE_ERROR_NONE);
}


/**
 * Convert a metadata query message (RNA_SERVICE_MESSAGE_TYPE_MD_QUERY)
 * and its response (RNA_SERVICE_MESSAGE_TYPE_MD_QUERY_RESPONSE) into a cache
 * query (CACHE_QUERY).
 *
 * This function is temporary, and is to be used only until rna_service
 * supports client/cache server communication.
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
 *  RNA_SERVICE_ERROR_NONE  on success
 *  RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER
 *                          Either 'message_sent' or 'response' is corrupt,
 *                          or 'message_sent', 'response', or 'cmd' is NULL,
 *                          or 'message_sent' is not of type
 *                          RNA_SERVICE_MESSAGE_TYPE_MD_QUERY,
 *                          or 'response' is not of type
 *                          RNA_SERVICE_MESSAGE_TYPE_MD_QUERY_RESPONSE.
 */    
rna_service_error_t
rna_service_convert_md_rep_to_cache_query(
                                rna_service_message_buffer_t *message_sent,
                                rna_service_message_buffer_t *response,
                                void *buf)
{
    struct cache_cmd *cmd = (struct cache_cmd *) buf;
    rna_service_metadata_query_t *sent;
    rna_service_metadata_query_response_t *resp;

    if ((NULL == message_sent)
      || (NULL == response)
      || (NULL == cmd)
      || (message_sent->h.rmb_message_type != RNA_SERVICE_MESSAGE_TYPE_MD_QUERY)
      || (response->h.rmb_message_type !=
                                RNA_SERVICE_MESSAGE_TYPE_MD_QUERY_RESPONSE)) {
          return (RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER);
    }

    memset(cmd, 0, empty_cache_cmd_length(CACHE_QUERY));

    cmd->h.h_type = CACHE_QUERY;

    sent = &message_sent->u.rmb_metadata_query;
    resp = &response->u.rmb_metadata_query_response;
    /*
     * (The initial intent was to group the following fields together into a
     * struct and do this copy as a memcpy.  Timing measurements, however,
     * show that approach to be less than 0.4% faster than the following,
     * so the ungainliness of that approach wasn't considered worthwhile).
     */
    memcpy(&(cmd->u.cache_req.hash_key),
           &(resp->mqr_path_key),
           sizeof(cmd->u.cache_req.hash_key));
    cmd->u.cache_req.c = resp->c;
    cmd->u.cache_req.pre_cache_flag = 0;
    cmd->u.cache_req.write_commit_flag = sent->mqs_write_commit_flag;
    cmd->u.cache_req.block_size = resp->mqr_block_size;
    cmd->u.cache_req.cq_cachedev_id = resp->mqr_cachedev_id;
    if (unlikely(NULL_CACHEDEV_ID == resp->mqr_cachedev_id)) {
        rna_dbg_log(RNA_DBG_ERR,
                    "Got NULL cachedev ID in MD response\n");
    }
    strcpy(cmd->u.cache_req.cr_path, sent->mqs_pathname);
    return (RNA_SERVICE_ERROR_NONE);
}

/*!
 * CS storage path registration/deregistration with the CFM
 *
 * Arguments:
 *    ctx     The caller's rna_service context, created by
 *            rna_service_ctx_create()
 *    buf     A message buffer that specifies the message to be sent.
 *            NOTES:
 *            1. The rmb_message_type must be RNA_SERVICE_MESSAGE_TYPE_REG_PATH
 *               or RNA_SERVICE_MESSAGE_TYPE_DEREG_PATH
 *            2. The message buffer must have been allocated by
 *               rna_service_alloc_message_buffer().
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
 *                            RNA_SERVICE_MESSAGE_TYPE_REG_PATH or
 *                            RNA_SERVICE_MESSAGE_TYPE_DEREG_PATH,
 *                            or the message buffer was not allocated as an
 *                            RNA_SERVICE_MESSAGE_TYPE_REG_PATH or
 *                            RNA_SERVICE_MESSAGE_TYPE_DEREG_PATH
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER
 *                            The message buffer specified was not allocated by
 *                            rna_service_alloc_message_buffer() or has not yet
 *                            been returned in a response callback.
 */
rna_service_error_t
rna_service_send_paths_to_cfm(
                            rna_service_ctx_t            *ctx,
                            rna_service_message_buffer_t *buf)
{
    int ret;

    if (buf->h.rmb_message_type != RNA_SERVICE_MESSAGE_TYPE_REG_PATH &&
        buf->h.rmb_message_type != RNA_SERVICE_MESSAGE_TYPE_DEREG_PATH) {
        return (RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE);
    }

    /* 
     * additional checking on the message buffer happens in
     * send_registration_or_deregistration() so there's no
     * need to repeat the same thing here.
     */ 
    ret = send_registration_or_deregistration(ctx, buf, NULL);

    if (ret != RNA_SERVICE_ERROR_NONE) {
        rna_dbg_log(RNA_DBG_WARN,
                    "message %d could not be sent to the CFM\n",
                    buf->h.rmb_message_type);
    }
    return ret;
}


/*!
 * CS storage path registration/deregistration with the MD
 *
 * Arguments:
 *    ctx     The caller's rna_service context, created by
 *            rna_service_ctx_create()
 *    buf     A message buffer that specifies the message to be sent.
 *            NOTES:
 *            1. The rmb_message_type must be RNA_SERVICE_MESSAGE_TYPE_REG_PATH
 *               or RNA_SERVICE_MESSAGE_TYPE_DEREG_PATH
 *            2. The message buffer must have been allocated by
 *               rna_service_alloc_message_buffer().
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
 *                            RNA_SERVICE_MESSAGE_TYPE_REG_PATH or
 *                            RNA_SERVICE_MESSAGE_TYPE_DEREG_PATH,
 *                            or the message buffer was not allocated as an
 *                            RNA_SERVICE_MESSAGE_TYPE_REG_PATH or
 *                            RNA_SERVICE_MESSAGE_TYPE_DEREG_PATH
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER
 *                            The message buffer specified was not allocated by
 *                            rna_service_alloc_message_buffer() or has not yet
 *                            been returned in a response callback.
 */
rna_service_error_t
rna_service_send_paths_to_md(rna_service_ctx_t            *ctx,
                             rna_service_message_buffer_t *buf)
{
    rna_service_message_buffer_internal_t *ibuf, *ib;
    rna_service_send_buf_entry_t *send_buf;
    YAQ_LINK *lnkp;
    com_ep_handle_t md_eph;
    md_info_t *mdi;
    struct cache_cmd *cmd;
    int ret = RNA_SERVICE_ERROR_NONE;
    char *wwn_str = NULL;
    int i;

    if (buf->h.rmb_message_type != RNA_SERVICE_MESSAGE_TYPE_REG_PATH &&
        buf->h.rmb_message_type != RNA_SERVICE_MESSAGE_TYPE_DEREG_PATH) {
        return (RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE);
    }

    ibuf = mbuf_to_ibuf(buf);

    if ((NULL == ctx)
      || (ctx->cx_watermark != RNA_SERVICE_CTX_WATERMARK)
      || (!ctx_add_reference(&ctx))) {
        rna_dbg_log(RNA_DBG_WARN,
                    "called with NULL or corrupt rna_service_ctx [%p]\n", ctx);
        return (RNA_SERVICE_ERROR_INVALID_CTX);
    }

    if (!rna_service_mutex_lock(&ctx->cx_md_mutex)) {
        /* This failure means we're in the process of shutting down */
        rna_service_free_message_buffer(ctx, buf);
        goto done;
    }

    rna_create_wwn_strings(&buf->u.rmb_register_path.rp_wwn,
                           &wwn_str, NULL, NULL, NULL);
    /*
     * If a registration for this storage path is already queued, toss
     * the old registration in favor of the new one.
     *
     * If this is a deregistration, and the storage path is in the list,
     * just remove it.
     */
    YAQ_FOREACH(&ctx->cx_md_registered_paths, lnkp) {
        ib = YAQ_OBJECT(rna_service_message_buffer_internal_t,
                        h.rmbi_link,
                        lnkp);
        if (mount_blkdev_match(ib, buf)) {
            /*
             * Found a registration for this same storage path
             * Remove the old registration, to be replaced with the new one.
             */
            rna_dbg_log(RNA_DBG_INFO, "%s obsolete registration for %s\n",
                buf->h.rmb_message_type == RNA_SERVICE_MESSAGE_TYPE_REG_PATH ?
                "Replacing" : "Removing",
                wwn_str);
            YAQ_REMOVE(lnkp);
            rna_service_free_message_buffer(ctx,
                                            &ib->u.rmbi_message_buffer);
            break;
        }
    }

    if (buf->h.rmb_message_type == RNA_SERVICE_MESSAGE_TYPE_REG_PATH) {
        /*
         * Queue the message up first so that new MDs coming online
         * will get it
         */
        YAQ_INSERT_TAIL(&ctx->cx_md_registered_paths, &ibuf->h.rmbi_link);
    }

    for (i = 0; i < NUM_MD_ORDINALS; i ++) {
        mdi = ctx->cx_md_table[i];

        /*
         * A NULL entry in the cx_md_table indicates that we haven't yet
         * connected with the target MD
         *
         * An unset MD_INFO_CFLAG_CONNECTED flag indicates that we've lost our
         * connection.
         *
         * A set MD_INFO_CFLAG_MUST_REGISTER flag indicates that this is a
         * cache server that hasn't yet registered with the MD, so we
         * shouldn't send this message yet.
         */
        if ((NULL != mdi)
            && (mdi->mdi_cflags & MD_INFO_CFLAG_CONNECTED)
            && !(mdi->mdi_cflags & MD_INFO_CFLAG_MUST_REGISTER)
            && (rna_service_com_connected(&mdi->mdi_eph))) {
            md_eph = mdi->mdi_eph;

            ret = rna_service_com_get_send_buf(&md_eph,
                                               &send_buf,
                                               TRUE,
                                               NULL);
            if ((NULL == send_buf) || (0 != ret)) {
                /* no sendbufs available, bail out */
                goto done;
            }

#if defined(LINUX_KERNEL) || defined(WINDOWS_KERNEL)
            cmd = (struct cache_cmd *)(com_get_send_buf_mem(send_buf));
#else
            cmd = (struct cache_cmd *) send_buf->mem;
#endif

            if (buf->h.rmb_message_type == RNA_SERVICE_MESSAGE_TYPE_REG_PATH) {
                memset(cmd, 0, empty_cache_cmd_length(CACHE_REG_PATH));
                cmd->h.h_type = CACHE_REG_PATH;
            } else {
                memset(cmd, 0, empty_cache_cmd_length(CACHE_DEREG_PATH));
                cmd->h.h_type = CACHE_DEREG_PATH;
            }

            cmd->u.path_reg.rnas.rp_service_id = ctx->cx_params.rsp_service_id;
            cmd->u.path_reg.rnas.rp_wwn = buf->u.rmb_register_path.rp_wwn;
            memcpy(&cmd->u.path_reg.rnas.rp_path[0],
                   &buf->u.rmb_register_path.rp_path[0],
                   sizeof(cmd->u.path_reg.rnas.rp_path));
            cmd->u.path_reg.rnas.rp_status = buf->u.rmb_register_path.rp_status;
            rna_dbg_log(RNA_DBG_INFO, "%s storage path with MD: "
                        "wwn [%s], status [%d]\n",
                        cmd->h.h_type == CACHE_REG_PATH ?
                        "registering" : "deregistering",
                        wwn_str,
                        cmd->u.path_reg.rnas.rp_status);

            ret = rna_service_com_send_cache_cmd(&mdi->mdi_eph,
                                                 send_buf,
                                                 cache_cmd_length(cmd),
                                                 &ctx->cx_primary_cfm_id);
            if (0 != ret) {
                rna_dbg_log(RNA_DBG_WARN,
                            "Failed to send MD message: %d\n", ret);
            }
        }
    }

done:
    rna_service_mutex_unlock(&ctx->cx_md_mutex);

    if (wwn_str) {
        rna_service_simple_free(wwn_str);
    }
    return (ret);
}

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
 *               If a response_callback is specified, the message buf must not
 *               be accessed (modified, freed, or re-used) until it is returned
 *               as the 'message_sent' argument of the response callback.
 *    response_callback
 *            Currently, this argument must be NULL.  A response callback is
 *            not yet supported for this function.
 *
 * Returns:
 *    RNA_SERVICE_ERROR_NONE  On success
 *    RNA_SERVICE_ERROR_INVALID_CTX
 *                            Either ctx is NULL, or it is in the process of
 *                            shutting down (rna_service_ctx_destroy() has been
 *                            called), or it was not created by
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
rna_service_error_t
rna_service_send_mount_registration(
                            rna_service_ctx_t            *ctx,
                            rna_service_message_buffer_t *buf,
                            rna_service_response_callback response_callback)
{
    if (NULL != response_callback) {
        /*
         * Response callbacks aren't yet supported, since the CFM doesn't yet
         * send responses for mount registrations.
         */
        return (RNA_SERVICE_ERROR_INVALID_RESPONSE_CALLBACK);
    }
    if (buf->h.rmb_message_type != RNA_SERVICE_MESSAGE_TYPE_REG_MNT) {
        return (RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE);
    }
    return (send_registration_or_deregistration(ctx, buf, response_callback));
}


/*!
 * A filesystem client uses this API to deregister a mount with rna_service.
 *
 * Arguments:
 *    ctx        The caller's rna_service context, created by
 *            rna_service_ctx_create()
 *    buf        A message buffer that specifies the message to be sent.
 *            NOTES:
 *            1. The rmb_message_type must be
 *               RNA_SERVICE_MESSAGE_TYPE_DEREG_MNT
 *            2. The message buffer must have been allocated by
 *               rna_service_alloc_message_buffer().
 *            3. If no response_callback is specified, the message buf must not
 *               be accessed after this call.  It will be freed by the
 *               rna_service library.
 *               If a response_callback is specified, the message buf must not
 *               be accessed (modified, freed, or re-used) until it is returned
 *               as the 'message_sent' argument of the response callback.
 *    response_callback
 *            Currently, this argument must be NULL.  A response callback is
 *            not yet supported for this function.
 *
 * Returns:
 *    RNA_SERVICE_ERROR_NONE  On success
 *    RNA_SERVICE_ERROR_INVALID_CTX
 *                            Either ctx is NULL, or it is in the process of
 *                            shutting down (rna_service_ctx_destroy() has been
 *                            called), or it was not created by
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
rna_service_error_t
rna_service_send_mount_deregistration(
                            rna_service_ctx_t            *ctx,
                            rna_service_message_buffer_t *buf,
                            rna_service_response_callback response_callback)
{
    if (NULL != response_callback) {
        /*
         * Response callbacks aren't yet supported, since the CFM doesn't yet
         * send responses for mount registrations.
         */
        return (RNA_SERVICE_ERROR_INVALID_RESPONSE_CALLBACK);
    }
    if (buf->h.rmb_message_type != RNA_SERVICE_MESSAGE_TYPE_DEREG_MNT) {
        return (RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE);
    }
    return (send_registration_or_deregistration(ctx, buf, response_callback));
}


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
 *    RNA_SERVICE_ERROR_NONE  On success
 *    RNA_SERVICE_ERROR_INVALID_CTX
 *                            Either ctx is NULL, or it is in the process of
 *                            shutting down (rna_service_ctx_destroy() has been
 *                            called), or it was not created by
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
rna_service_error_t
rna_service_send_block_device_registration(
                            rna_service_ctx_t            *ctx,
                            rna_service_message_buffer_t *buf,
                            rna_service_response_callback response_callback)
{
    if (buf->h.rmb_message_type != RNA_SERVICE_MESSAGE_TYPE_REG_BLKDEV) {
        return (RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE);
    }
    return (send_registration_or_deregistration(ctx, buf, response_callback));
}


rna_service_error_t
rna_service_send_notification_event(
                            rna_service_ctx_t            *ctx,
                            rna_service_message_buffer_t *buf)
{
    if (buf->h.rmb_message_type !=
                                RNA_SERVICE_MESSAGE_TYPE_NOTIFICATION_EVENT) {
        return (RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE);
    }
    return (send_cfm_non_reg_dereg(ctx, buf, FALSE));
}

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
 *    RNA_SERVICE_ERROR_NONE  On success
 *    RNA_SERVICE_ERROR_INVALID_CTX
 *                            Either ctx is NULL, or it is in the process of
 *                            shutting down (rna_service_ctx_destroy() has been
 *                            called), or it was not created by
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
rna_service_error_t
rna_service_send_block_device_deregistration(
                            rna_service_ctx_t            *ctx,
                            rna_service_message_buffer_t *buf)
{
    if (buf->h.rmb_message_type != RNA_SERVICE_MESSAGE_TYPE_DEREG_BLKDEV) {
        return (RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE);
    }
    return (send_registration_or_deregistration(ctx, buf, NULL));
}


/*!
 * A block device client uses this API to send a block device control response
 * with rna_service.
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
rna_service_error_t
rna_service_send_block_device_control_response(
                            rna_service_ctx_t            *ctx,
                            rna_service_message_buffer_t *buf)
{
    if (buf->h.rmb_message_type !=
                            RNA_SERVICE_MESSAGE_TYPE_CONTROL_BLKDEV_RESPONSE) {
        return (RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE);
    }
    return (send_cfm_non_reg_dereg(ctx, buf, FALSE));
}


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
rna_service_error_t
rna_service_send_control_cs_response(
                            rna_service_ctx_t            *ctx,
                            rna_service_message_buffer_t *buf)
{
    if (buf->h.rmb_message_type !=
                            RNA_SERVICE_MESSAGE_TYPE_CONTROL_CS_RESPONSE) {
        return (RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE);
    }
    return (send_cfm_non_reg_dereg(ctx, buf, FALSE));
}

rna_service_error_t
rna_service_send_md_internal(rna_service_ctx_t            *ctx,
                             rna_service_message_buffer_t *message,
                             rna_service_response_callback response_callback,
                             int                           blocking)
{
    rna_service_message_buffer_internal_t *ibuf;

    if ((NULL == ctx)
      || (ctx->cx_watermark != RNA_SERVICE_CTX_WATERMARK)) {
        rna_dbg_log(RNA_DBG_WARN,
                    "called with NULL or corrupt rna_service_ctx [%p]\n", ctx);
          return (RNA_SERVICE_ERROR_INVALID_CTX);
    }
    if ((message->h.rmb_message_type !=
                                RNA_SERVICE_MESSAGE_TYPE_MD_QUERY)
      && (message->h.rmb_message_type !=
                                RNA_SERVICE_MESSAGE_TYPE_CACHE_INVD)
      && (message->h.rmb_message_type !=
                                RNA_SERVICE_MESSAGE_TYPE_CACHE_MASTER_INVD)
      && (message->h.rmb_message_type !=
                                RNA_SERVICE_MESSAGE_TYPE_CACHE_RESPONSE)
      && (message->h.rmb_message_type !=
                                RNA_SERVICE_MESSAGE_TYPE_CACHE_QUERY_REQUEST)
      && (message->h.rmb_message_type !=
                                RNA_SERVICE_MESSAGE_TYPE_RELOCATE_BLOCK)
      && (message->h.rmb_message_type !=
                                RNA_SERVICE_MESSAGE_TYPE_ABSORB_BLOCK)
      && (message->h.rmb_message_type !=
                                RNA_SERVICE_MESSAGE_TYPE_INVD_HOLD_RESPONSE)) {

        rna_service_free_message_buffer(ctx, message);
        return (RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE);
    }
    ibuf = mbuf_to_ibuf(message);
    if (ibuf->h.rmbi_watermark != MESSAGE_BUFFER_INTERNAL_WATERMARK_ALLOCATED) {
        /*
         * Possibly this struct is already queued or was not allocated by
         * rna_service_alloc_message_buffer().
         */
        /* "message" is not freed here because its integrity cannot 
         * be guaranteed */
        return (RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER);
    }
    if (ibuf->h.rmbi_msg_type != message->h.rmb_message_type) {
        rna_dbg_log(RNA_DBG_WARN,
                    "message type mismatch (%d vs. %d)\n",
                    ibuf->h.rmbi_msg_type,
                    message->h.rmb_message_type);
        rna_service_free_message_buffer(ctx, message);
        return (RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE);
    }
    ibuf->h.rmbi_response_callback = response_callback;
    if (blocking) {
        return (send_md_generic(ctx, ibuf, SEND_MD_GENERIC_FLAG_FORCE));
    } else {
        return (send_md_generic(ctx, ibuf, 0));
    }
}


/**
 * Send the specified message to the appropriate MD and invoke the specified
 * callback when a response arrives.
 *
 * Arguments:
 *    ctx     The caller's rna_service context, created by
 *            rna_service_ctx_create()
 *
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
rna_service_error_t
rna_service_send_md(rna_service_ctx_t            *ctx,
                    rna_service_message_buffer_t *message,
                    rna_service_response_callback response_callback)
{
    return (rna_service_send_md_internal(ctx,
                                         (rna_service_message_buffer_t *)message,
                                         response_callback,
                                         0));
}

/**
 * Send the specified message in a blocking fashion to the appropriate MD and
 * invoke the specified callback when a response arrives. Same as
 * rna_service_cs_send_md except for the blocking behavior (in most cases
 * rna_service_cs_send_md should be used).
 *
 * Arguments:
 *    ctx     The caller's rna_service context, created by
 *            rna_service_ctx_create()
 *
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
 */
rna_service_error_t
rna_service_send_md_nomaxcheck(rna_service_ctx_t            *ctx,
                               rna_service_message_buffer_t *message,
                               rna_service_response_callback response_callback)
{
    return (rna_service_send_md_internal(ctx,
                                         (rna_service_message_buffer_t *)message,
                                         response_callback,
                                         1));
}

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
rna_service_error_t
rna_service_send_svc_conn_registration(
                            rna_service_ctx_t            *ctx,
                            rna_service_message_buffer_t *buf)
{
    if (buf->h.rmb_message_type != RNA_SERVICE_MESSAGE_TYPE_REG_SVC_CONN) {
        return (RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE);
    }
    return (send_registration_or_deregistration(ctx, buf, NULL));
}


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
rna_service_error_t
rna_service_send_svc_conn_deregistration(
                            rna_service_ctx_t            *ctx,
                            rna_service_message_buffer_t *buf)
{
    if (buf->h.rmb_message_type != RNA_SERVICE_MESSAGE_TYPE_DEREG_SVC_CONN) {
        return (RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE);
    }
    return (send_registration_or_deregistration(ctx, buf, NULL));
}


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
 *    RNA_SERVICE_ERROR_NONE  On success
 *    RNA_SERVICE_ERROR_INVALID_CTX
 *                            Either ctx is NULL, or it is in the process of
 *                            shutting down (rna_service_ctx_destroy() has been
 *                            called), or it was not created by
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
rna_service_error_t
rna_service_send_client_event(rna_service_ctx_t            *ctx,
                              rna_service_message_buffer_t *buf)
{
    rna_service_message_buffer_internal_t *ibuf;
    int                                    ret;
    rna_service_send_buf_entry_t          *send_buf;
    struct cfm_cmd                        *cmd;

    if (buf->h.rmb_message_type != RNA_SERVICE_MESSAGE_TYPE_CLIENT_EVENT) {
        return (RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE);
    }
    ibuf = mbuf_to_ibuf(buf);
    if (ibuf->h.rmbi_watermark != MESSAGE_BUFFER_INTERNAL_WATERMARK_ALLOCATED) {
        /*
         * Possibly this struct is already queued or was not allocated by
         * rna_service_alloc_message_buffer().
         */
        return (RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER);
    }
    if (ibuf->h.rmbi_msg_type != buf->h.rmb_message_type) {
        rna_dbg_log(RNA_DBG_WARN,
                    "message type mismatch (%d vs. %d)\n",
                    ibuf->h.rmbi_msg_type,
                    buf->h.rmb_message_type);
        return (RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE);
    }

    if (!rna_service_com_connected(&ctx->cx_primary_cfm_eph)) {
        rna_dbg_log(RNA_DBG_INFO,
                    "no primary cfm, unable to send CONF_MGR_EVENT\n");
        /* Free the message buffer, since there's no reply for this message */
        rna_service_free_message_buffer(ctx, buf);
        /* ignore the error; dropping this message isn't a big deal */
        return (RNA_SERVICE_ERROR_NONE);
    }

    if ((NULL == ctx)
      || (ctx->cx_watermark != RNA_SERVICE_CTX_WATERMARK)
      || (!ctx_add_reference(&ctx))) {
        return (RNA_SERVICE_ERROR_INVALID_CTX);
    }

    ibuf->h.rmbi_response_callback = NULL;

    ret = rna_service_com_get_send_buf(&ctx->cx_primary_cfm_eph,
                                       &send_buf,
                                       TRUE,
                                       NULL);
    if ((NULL == send_buf) || (0 != ret)) {
        rna_dbg_log(RNA_DBG_WARN,
                    "failed to allocate send buffer, unable to send "
                    "CONF_MGR_EVENT\n");
        /* Free the message buffer, since there's no reply for this message */
        rna_service_free_message_buffer(ctx, buf);
        ctx_release_reference(&ctx);
        /* ignore the error; dropping this message isn't a big deal */
        return (RNA_SERVICE_ERROR_NONE);
    }

#if defined(LINUX_KERNEL) || defined(WINDOWS_KERNEL)
    cmd = (struct cfm_cmd *)(com_get_send_buf_mem(send_buf));
#else
    cmd = (struct cfm_cmd *) send_buf->mem;
#endif
    memset(cmd, 0, sizeof(cmd_hdr_t));

    cmd->h.h_type = CONF_MGR_EVENT;

    /*
     * User space code sets this to a value of type RNA_DBG_TYPE,
     * but we're ignoring it for now. 0 isn't any particular type.
     */
    cmd->u.rna_event.rnas.type = 0;

    clock_gettime(CLOCK_REALTIME, &cmd->u.rna_event.rnas.timestamp);

    strncpy( (char*)&cmd->u.rna_event.rnas.data[0],
             buf->u.rmb_client_event.ces_print_buffer,
             sizeof(cmd->u.rna_event.rnas.data));
    /* strncpy may not set a terminating null character, so we do it manually */
    cmd->u.rna_event.rnas.data[sizeof(cmd->u.rna_event.rnas.data)-1] = '\0';

    ret = rna_service_com_send_cfm_cmd(&ctx->cx_primary_cfm_eph,
                                       send_buf,
                                       cfm_cmd_length(cmd),
                                       &ctx->cx_primary_cfm_id);
    if (ret != 0) {
        rna_dbg_log(RNA_DBG_WARN,
                    "failed to send CONF_MGR_EVENT message: %d\n", ret);
    }

    /* Free the message buffer, since there's no reply for this message */
    rna_service_free_message_buffer(ctx, buf);

    ctx_release_reference(&ctx);
    return (RNA_SERVICE_ERROR_NONE);
}


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
 *    RNA_SERVICE_ERROR_NONE  On success
 *    RNA_SERVICE_ERROR_INVALID_CTX
 *                            Either ctx is NULL, or it is in the process of
 *                            shutting down (rna_service_ctx_destroy() has been
 *                            called), or it was not created by
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
rna_service_error_t
rna_service_send_block_device_stats(rna_service_ctx_t            *ctx,
                                    rna_service_message_buffer_t *buf)
{
    rna_service_message_buffer_internal_t *ibuf;
    int                                    ret;
    rna_service_send_buf_entry_t          *send_buf;
    struct cfm_cmd                        *cmd;

    if ((NULL == ctx)
      || (ctx->cx_watermark != RNA_SERVICE_CTX_WATERMARK)) {
          return (RNA_SERVICE_ERROR_INVALID_CTX);
    }
    if (buf->h.rmb_message_type != RNA_SERVICE_MESSAGE_TYPE_BSTAT_RESPONSE) {
        return (RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE);
    }
    ibuf = mbuf_to_ibuf(buf);
    if (ibuf->h.rmbi_watermark != MESSAGE_BUFFER_INTERNAL_WATERMARK_ALLOCATED) {
        /*
         * Possibly this struct is already queued or was not allocated by
         * rna_service_alloc_message_buffer().
         */
        return (RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER);
    }
    if (ibuf->h.rmbi_msg_type != buf->h.rmb_message_type) {
        rna_dbg_log(RNA_DBG_WARN,
                    "message type mismatch (%d vs. %d)\n",
                    ibuf->h.rmbi_msg_type,
                    buf->h.rmb_message_type);
        return (RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE);
    }

    if (!rna_service_com_connected(&ctx->cx_primary_cfm_eph)) {
        rna_dbg_log(RNA_DBG_INFO,
                    "no primary cfm, unable to send CONF_MGR_BSTAT_RESP\n");
        /* Free the message buffer, since there's no reply for this message */
        rna_service_free_message_buffer(ctx, buf);
        /* ignore the error; dropping this message isn't a big deal */
        return (RNA_SERVICE_ERROR_NONE);
    }

    if ((NULL == ctx)
      || (ctx->cx_watermark != RNA_SERVICE_CTX_WATERMARK)
      || (!ctx_add_reference(&ctx))) {
        return (RNA_SERVICE_ERROR_INVALID_CTX);
    }

    ibuf->h.rmbi_response_callback = NULL;

    ret = rna_service_com_get_send_buf(&ctx->cx_primary_cfm_eph,
                                       &send_buf,
                                       TRUE,
                                       NULL);
    if ((NULL == send_buf) || (0 != ret)) {
        rna_dbg_log(RNA_DBG_WARN,
                    "failed to allocate send buffer, unable to send "
                    "CONF_MGR_BSTAT_RESP\n");
        /* Free the message buffer, since there's no reply for this message */
        rna_service_free_message_buffer(ctx, buf);
        ctx_release_reference(&ctx);
        /* ignore the error, we'll hope for better luck on the next stats msg */
        return (RNA_SERVICE_ERROR_NONE);
    }

#if defined(LINUX_KERNEL) || defined(WINDOWS_KERNEL)
    cmd = (struct cfm_cmd *)(com_get_send_buf_mem(send_buf));
#else
    cmd = (struct cfm_cmd *) send_buf->mem;
#endif
    memset(cmd, 0, sizeof(cmd_hdr_t));

    cmd->h.h_type = CONF_MGR_BSTAT_RESP;
    cmd->h.h_cookie = buf->u.rmb_bstat_response.bsr_device_id;
    cmd->u.client_block_device_stats_resp = buf->u.rmb_bstat_response.bsr_stats;

    ret = rna_service_com_send_cfm_cmd(&ctx->cx_primary_cfm_eph,
                                       send_buf,
                                       cfm_cmd_length(cmd),
                                       &ctx->cx_primary_cfm_id);
    if (ret != 0) {
        rna_dbg_log(RNA_DBG_WARN,
                    "Failed to send CONF_MGR_BSTAT_RESP message to CFM: "
                    "%d\n", ret);
    }

    /* Free the message buffer, since there's no reply for this message */
    rna_service_free_message_buffer(ctx, buf);

    ctx_release_reference(&ctx);
    return (RNA_SERVICE_ERROR_NONE);
}


/*!
 * Add the connection status for each configuration manager and metadata
 * server to the specified sprintf buffer.  On return, the specified buffer
 * pointer is incremented to account for the information added to the buffer.
 *
 * Returns:
 *    RNA_SERVICE_ERROR_NONE  On success
 *    RNA_SERVICE_ERROR_INVALID_CTX
 *                            Either ctx is NULL, or it is in the process of
 *                            shutting down (rna_service_ctx_destroy() has been
 *                            called), or it was not created by
 *                            rna_service_ctx_create().
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER
 *                            The specified buffer is NULL.
 */
rna_service_error_t
rna_service_sprintf_connection_status(rna_service_ctx_t  *ctx,
                                      char              **p)
{
    uint32_t  i;

    if ((NULL == p) || (NULL == *p)) {
          return (RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER);
    }

    if ((NULL == ctx)
      || (ctx->cx_watermark != RNA_SERVICE_CTX_WATERMARK)
      || (0 != (ctx->cx_flags & (CX_FLAG_SHUTTING_DOWN | CX_FLAG_SHUT_DOWN)))
      || (!ctx_add_reference(&ctx))) {
        return (RNA_SERVICE_ERROR_INVALID_CTX);
    }

    if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
        /* This failure means we're in the process of shutting down */
        ctx_release_reference(&ctx);
        return (RNA_SERVICE_ERROR_NONE);
    }
    for (i = 0; i < ctx->cx_params.rsp_cfm_count; i++) {
        *p += sprintf(*p,
                      "cfm:  ["RNA_ADDR_FORMAT"]   %s\n",
                      RNA_ADDR(ctx->cx_params.rsp_cfm_addrs[i].sin_addr.s_addr),
                      (find_connected_cfm_by_address(
                                 ctx,
                                 &ctx->cx_params.rsp_cfm_addrs[i].sin_addr,
                                 NULL)) ? "Connected" : "Not connected");
    }
    rna_service_mutex_unlock(&ctx->cx_cfm_mutex);

    if (!rna_service_mutex_lock(&ctx->cx_md_mutex)) {
        /* This failure means we're in the process of shutting down */
        ctx_release_reference(&ctx);
        return (RNA_SERVICE_ERROR_NONE);
    }
    for (i = 0; i < NUM_MD_ORDINALS; i++) {
        if (NULL != ctx->cx_md_table[i]) {
            *p += sprintf(*p,
                          "md:   ["RNA_ADDR_FORMAT"]   Connected\n",
                          RNA_ADDR(ctx->cx_md_table[i]->
                                                mdi_eph.eph_dst_in.sin_addr));
        }
    }
    rna_service_mutex_unlock(&ctx->cx_md_mutex);
    ctx_release_reference(&ctx);
    return (RNA_SERVICE_ERROR_NONE);
}


/*!
 * Return the string representation for the specified rna_service_error_t,
 * for use in log messages.
 */
const char *
rna_service_get_error_string(rna_service_error_t error)
{
    const char * ret = "Unknown";
        // (Note that initializing ret allows us to leave out a default case in
        // the below switch, which allows the compiler to flag a warning if not
        // all cases are covered, if new cases get added in the future).

    switch (error) {
        case RNA_SERVICE_ERROR_NONE:
            ret = "RNA_SERVICE_ERROR_NONE";
            break;
        case RNA_SERVICE_ERROR_WORKQ_INIT_FAILURE:
            ret = "RNA_SERVICE_ERROR_WORKQ_INIT_FAILURE";
            break;
        case RNA_SERVICE_ERROR_COM_INIT_FAILURE:
            ret = "RNA_SERVICE_ERROR_COM_INIT_FAILURE";
            break;
        case RNA_SERVICE_ERROR_INVALID_CTX:
            ret = "RNA_SERVICE_ERROR_INVALID_CTX";
            break;
        case RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER:
            ret = "RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER";
            break;
        case RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE:
            ret = "RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER";
            break;
        case RNA_SERVICE_ERROR_INVALID_RESPONSE_CALLBACK:
            ret = "RNA_SERVICE_ERROR_INVALID_RESPONSE_CALLBACK";
            break;
        case RNA_SERVICE_ERROR_INVALID_PARAMS:
            ret = "RNA_SERVICE_ERROR_INVALID_PARAMS";
            break;
        case RNA_SERVICE_ERROR_NO_MEMORY:
            ret = "RNA_SERVICE_ERROR_NO_MEMORY";
            break;
        case RNA_SERVICE_ERROR_MAX_OUTSTANDING_EXCEEDED:
            ret = "RNA_SERVICE_ERROR_MAX_OUTSTANDING_EXCEEDED";
            break;
    }
    return ret;
}


/*!
 * Return the string representation for the specified cache_req_type_t,
 * for use in log messages.
 */
const char *
get_cache_req_type_string(cache_req_type_t type)
{
    const char * ret = "Unknown";
        // (Note that initializing ret allows us to leave out a default case in
        // the below switch, which allows the compiler to flag a warning if not
        // all cases are covered, if new cases get added in the future).

    switch (type) {
        case CACHE_REQ_TYPE_FULL:
            ret = "CACHE_REQ_TYPE_FULL";
            break;
        case CACHE_REQ_TYPE_BLOCK:
            ret = "CACHE_REQ_TYPE_BLOCK";
            break;
        case CACHE_REQ_TYPE_REPLICA_BLOCK:
            ret = "CACHE_REQ_TYPE_REPLICA_BLOCK";
            break;
        case CACHE_REQ_TYPE_MASTER:
            ret = "CACHE_REQ_TYPE_MASTER";
            break;
        case CACHE_REQ_TYPE_INVALID:
            ret = "CACHE_REQ_TYPE_INVALID";
            break;
    }
    return ret;
}


/*!
 * Return the string representation for the specified cache_lock_t,
 * for use in log messages.
 */
const char *
get_lock_type_string(cache_lock_t type)
{
    const char * ret = "Unknown";
        // (Note that initializing ret allows us to leave out a default case in
        // the below switch, which allows the compiler to flag a warning if not
        // all cases are covered, if new cases get added in the future).

    switch (type) {
        case CACHE_READ_SHARED:
            ret = "Read/Shared";
            break;
        case CACHE_WRITE_EXCLUSIVE:
            ret = "Write/Exclusive";
            break;
        case CACHE_WRITE_SHARED:
            ret = "Write/Shared";
            break;
        case CACHE_WRITE_ONLY_SHARED:
            ret = "Write-Only/Shared";
            break;
        case CACHE_ATOMIC_SHARED:
            ret = "Atomic/Shared";
            break;
        case CACHE_REPLICA:
            ret = "Replica";
            break;
        case CACHE_NO_REFERENCE:
            ret = "No Reference";
            break;
        case CACHE_NO_ACCESS_REFERENCE:
            ret = "No Access Reference";
            break;
    }
    return ret;
}


/*!
 * Return the string representation for the specified cache_write_mode_t,
 * for use in log messages.
 */
const char *
get_write_mode_string(cache_write_mode_t type)
{
    const char * ret = "Unknown";
        // (Note that initializing ret allows us to leave out a default case in
        // the below switch, which allows the compiler to flag a warning if not
        // all cases are covered, if new cases get added in the future).

    switch (type) {
        case CACHE_SCRATCHPAD:
            ret = "Scratchpad";
            break;
        case CACHE_WRITE_THROUGH:
            ret = "Write-Through";
            break;
        case CACHE_WRITE_UPDATE:
            ret = "Write-Update";
            break;
        case CACHE_WRITE_BACK:
            ret = "Write-Back";
            break;
    }
    return ret;
}


/*!
 * Return the string representation for the specified cache_commit_mode_t,
 * for use in log messages.
 */
const char *
get_cache_commit_mode_string(cache_commit_mode_t mode)
{
    const char * ret = "Unknown";
        // (Note that initializing ret allows us to leave out a default case in
        // the below switch, which allows the compiler to flag a warning if not
        // all cases are covered, if new cases get added in the future).

    switch (mode) {
        case DISABLE_COMMIT:
            ret = "Disabled";
            break;
        case CACHE_COMMIT:
            ret = "Cache Server";
            break;
        case CLIENT_COMMIT:
            ret = "Client";
            break;
    }
    return ret;
}


/*!
 * Return the string representation for the specified cache_invd_mode_t,
 * for use in log messages.
 */
const char *
get_cache_invd_mode_string(cache_invd_mode_t mode)
{
    const char * ret = "Unknown";
        // (Note that initializing ret allows us to leave out a default case in
        // the below switch, which allows the compiler to flag a warning if not
        // all cases are covered, if new cases get added in the future).

    switch (mode) {
        case CACHE_INVD_FILE:
            ret = "File";
            break;
        case CACHE_INVD_BLOCK:
            ret = "Block";
            break;
    }
    return ret;
}


/*!
 * Return the string representation for the specified cache_error_persistence_t,
 * for use in log messages.
 */
const char *
get_cache_error_persistence_string(cache_error_persistence_t mode)
{
    const char * ret = "Unknown";
        // (Note that initializing ret allows us to leave out a default case in
        // the below switch, which allows the compiler to flag a warning if not
        // all cases are covered, if new cases get added in the future).

    switch (mode) {
        case CACHE_ERRS_NOT_PERSISTENT:
            ret = "None";
            break;
        case CACHE_ERRS_PERSIST_UNTIL_BLOCK_INVD:
            ret = "Until block/master invalidate";
            break;
        case CACHE_ERRS_PERSIST_UNTIL_MASTER_INVD:
            ret = "Until master invalidate";
            break;
    }
    return ret;
}


/*!
 * Return the string representation for the specified cache_evict_policy_t,
 * for use in log messages.
 */
const char *
get_cache_evict_policy_string(cache_evict_policy_t policy)
{
    const char * ret = "Unknown";
        // (Note that initializing ret allows us to leave out a default case in
        // the below switch, which allows the compiler to flag a warning if not
        // all cases are covered, if new cases get added in the future).

    switch (policy) {
        case CACHE_SERVER_EVICT_POLICY: ret = "CS-initiated"; break;
        case CACHE_CLIENT_EVICT_POLICY: ret = "Client-initiated"; break;
    }
    return ret;
}


/*!
 * Return the string representation for the specified
 * rna_service_message_type_t, for use in log messages.
 */
const char *
rna_service_get_message_type_string(rna_service_message_type_t type)
{
    const char * ret = "Unknown";
        // (Note that initializing ret allows us to leave out a default case in
        // the below switch, which allows the compiler to flag a warning if not
        // all cases are covered, if new cases get added in the future).

    switch (type) {
        case RNA_SERVICE_MESSAGE_TYPE_INVALID:
            ret = "RNA_SERVICE_MESSAGE_TYPE_INVALID";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_MD_QUERY:
            ret = "RNA_SERVICE_MESSAGE_TYPE_MD_QUERY";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_CACHE_INVD:
            ret = "RNA_SERVICE_MESSAGE_TYPE_CACHE_INVD";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_CACHE_MASTER_INVD:
            ret = "RNA_SERVICE_MESSAGE_TYPE_CACHE_MASTER_INVD";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_REG_PATH:
            ret = "RNA_SERVICE_MESSAGE_TYPE_REG_PATH";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_DEREG_PATH:
            ret = "RNA_SERVICE_MESSAGE_TYPE_DEREG_PATH";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_REG_MNT:
            ret = "RNA_SERVICE_MESSAGE_TYPE_REG_MNT";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_DEREG_MNT:
            ret = "RNA_SERVICE_MESSAGE_TYPE_DEREG_MNT";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_REG_BLKDEV:
            ret = "RNA_SERVICE_MESSAGE_TYPE_REG_BLKDEV";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_DEREG_BLKDEV:
            ret = "RNA_SERVICE_MESSAGE_TYPE_DEREG_BLKDEV";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_REG_SVC_CONN:
            ret = "RNA_SERVICE_MESSAGE_TYPE_REG_SVC_CONN";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_DEREG_SVC_CONN:
            ret = "RNA_SERVICE_MESSAGE_TYPE_DEREG_SVC_CONN";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_REG_CACHE_DEVICE:
            ret = "RNA_SERVICE_MESSAGE_TYPE_REG_CACHE_DEVICE";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_REG_CACHE_DEVICE_END:
            ret = "RNA_SERVICE_MESSAGE_TYPE_REG_CACHE_DEVICE_END";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_DEREG_CACHE_DEVICE:
            ret = "RNA_SERVICE_MESSAGE_TYPE_DEREG_CACHE_DEVICE";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_EXPEL_CACHE_DEVICE:
            ret = "RNA_SERVICE_MESSAGE_TYPE_EXPEL_CACHE_DEVICE";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_UNEXPELLED_CACHEDEVS:
            ret = "RNA_SERVICE_MESSAGE_TYPE_UNEXPELLED_CACHEDEVS";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_DEREG_REPLICA_STORE:
            ret = "RNA_SERVICE_MESSAGE_TYPE_DEREG_REPLICA_STORE";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_RESILVER_CACHE_DEVICE_COMPLETE:
            ret = "RNA_SERVICE_MESSAGE_TYPE_RESILVER_CACHE_DEVICE_COMPLETE";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_CS_SHUTDOWN_REQUEST:
            ret = "RNA_SERVICE_MESSAGE_TYPE_CS_SHUTDOWN_REQUEST";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_CS_SHUTDOWN_RESPONSE:
            ret = "RNA_SERVICE_MESSAGE_TYPE_CS_SHUTDOWN_RESPONSE";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_EVENT:
            ret = "RNA_SERVICE_MESSAGE_TYPE_EVENT";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_MD_QUERY_RESPONSE:
            ret = "RNA_SERVICE_MESSAGE_TYPE_MD_QUERY_RESPONSE";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_CACHE_INVD_RESPONSE:
            ret = "RNA_SERVICE_MESSAGE_TYPE_CACHE_INVD_RESPONSE";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_REG_MNT_RESPONSE:
            ret = "RNA_SERVICE_MESSAGE_TYPE_REG_MNT_RESPONSE";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_DEREG_MNT_RESPONSE:
            ret = "RNA_SERVICE_MESSAGE_TYPE_DEREG_MNT_RESPONSE";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_REG_BLKDEV_RESPONSE:
            ret = "RNA_SERVICE_MESSAGE_TYPE_REG_BLKDEV_RESPONSE";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_CREATE_BLKDEV:
            ret = "RNA_SERVICE_MESSAGE_TYPE_CREATE_BLKDEV";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_CONTROL_BLKDEV:
            ret = "RNA_SERVICE_MESSAGE_TYPE_CONTROL_BLKDEV";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_CONTROL_BLKDEV_RESPONSE:
            ret = "RNA_SERVICE_MESSAGE_TYPE_CONTROL_BLKDEV_RESPONSE";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_DEREG_BLKDEV_RESPONSE:
            ret = "RNA_SERVICE_MESSAGE_TYPE_DEREG_BLKDEV_RESPONSE";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_SET_LOG_LEVEL:
            ret = "RNA_SERVICE_MESSAGE_TYPE_SET_LOG_LEVEL";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_CLIENT_EVENT:
            ret = "RNA_SERVICE_MESSAGE_TYPE_CLIENT_EVENT";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_CONF_MGR_REG_RESPONSE:
            ret = "RNA_SERVICE_MESSAGE_TYPE_CONF_MGR_REG_RESPONSE";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_CLIENT_EVENT_REG:
            ret = "RNA_SERVICE_MESSAGE_TYPE_CLIENT_EVENT_REG";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_CLIENT_EVENT_DEREG:
            ret = "RNA_SERVICE_MESSAGE_TYPE_CLIENT_EVENT_DEREG";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_BSTAT_REQUEST:
            ret = "RNA_SERVICE_MESSAGE_TYPE_BSTAT_REQUEST";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_BSTAT_RESPONSE:
            ret = "RNA_SERVICE_MESSAGE_TYPE_BSTAT_RESPONSE";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_EXPEL_CS:
            ret = "RNA_SERVICE_MESSAGE_TYPE_EXPEL_CS";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_CONTROL_CS:
            ret = "RNA_SERVICE_MESSAGE_TYPE_CONTROL_CS";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_CONTROL_CS_RESPONSE:
            ret = "RNA_SERVICE_MESSAGE_TYPE_CONTROL_CS_RESPONSE";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_RELOCATE_BLOCK:
            ret = "RNA_SERVICE_MESSAGE_TYPE_RELOCATE_BLOCK";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_ABSORB_BLOCK:
            ret = "RNA_SERVICE_MESSAGE_TYPE_ABSORB_BLOCK";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_ABSORB_BLOCK_RESPONSE:
            ret = "RNA_SERVICE_MESSAGE_TYPE_ABSORB_BLOCK_RESPONSE";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_INVD_HOLD_RESPONSE:
            ret = "RNA_SERVICE_MESSAGE_TYPE_INVD_HOLD_RESPONSE";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_CS_CLIENT_REG:
            ret = "RNA_SERVICE_MESSAGE_TYPE_CS_CLIENT_REG";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_NOTIFICATION_EVENT:
            ret = "RNA_SERVICE_MESSAGE_TYPE_NOTIFICATION_EVENT";
            break;
        /* Begin SCSI III messages */
        case RNA_SERVICE_MESSAGE_TYPE_UPDATE_SCSI_ITN_RES:
            ret = "RNA_SERVICE_MESSAGE_TYPE_UPDATE_SCSI_ITN_RES";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_UPDATE_SCSI_ITN_REG:
            ret = "RNA_SERVICE_MESSAGE_TYPE_UPDATE_SCSI_ITN_REG";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_CLEAR_SCSI_ITN_RES:
            ret = "RNA_SERVICE_MESSAGE_TYPE_CLEAR_SCSI_ITN_RES";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_ACQUIRE_SCSI_ITN_RES:
            ret = "RNA_SERVICE_MESSAGE_TYPE_ACQUIRE_SCSI_ITN_RES";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_ACQUIRE_SCSI_ITN_REG:
            ret = "RNA_SERVICE_MESSAGE_TYPE_ACQUIRE_SCSI_ITN_REG";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_UPDATE_CLEAR_SCSI_ITN_RES_RESPONSE:
            ret =
              "RNA_SERVICE_MESSAGE_TYPE_UPDATE_CLEAR_SCSI_ITN_RES_RESPONSE";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_ACQUIRE_SCSI_ITN_RES_RESPONSE:
            ret = "RNA_SERVICE_MESSAGE_TYPE_ACQUIRE_SCSI_ITN_RES_RESPONSE";
            break;
        case RNA_SERVICE_MESSAGE_TYPE_ACQUIRE_SCSI_ITN_REG_RESPONSE:
            ret = "RNA_SERVICE_MESSAGE_TYPE_ACQUIRE_SCSI_ITN_REG_RESPONSE";
            break;
        /* End SCSI III messages */
        case RNA_SERVICE_MESSAGE_TYPE_NUM_MD_HASH_PARTITIONS:
            ret = "RNA_SERVICE_MESSAGE_TYPE_NUM_MD_HASH_PARTITIONS";
            break;
    }
    return ret;
}


/*!
 * Return the string representation for the specified
 * rna_service_event_t, for use in log messages.
 */
const char *
rna_service_get_event_type_string(rna_service_event_t event)
{
    const char * ret = "Unknown";
    /* (Note that initializing ret allows us to leave out a default
     * case in the below switch, which would allow the compiler to
     * flag a warning if not all cases are covered, if new cases get
     * added in the future, and rna_service_event_t were an enum).
     */

    switch (event) {
    case RNA_SERVICE_EVENT_NONE:
        ret = "RNA_SERVICE_EVENT_NONE";
        break;
    case RNA_SERVICE_EVENT_INFO_FULLY_CONNECTED:
        ret = "RNA_SERVICE_EVENT_INFO_FULLY_CONNECTED";
        break;
    case RNA_SERVICE_EVENT_CACHE_MOUNT_BLOCKED:
        ret = "RNA_SERVICE_EVENT_CACHE_MOUNT_BLOCKED";
        break;
    case RNA_SERVICE_EVENT_CACHE_MOUNT_UNBLOCKED:
        ret = "RNA_SERVICE_EVENT_CACHE_MOUNT_UNBLOCKED";
        break;
    case RNA_SERVICE_EVENT_KILL_SELF_RESTART:
        ret = "RNA_SERVICE_EVENT_KILL_SELF_RESTART";
        break;
    case RNA_SERVICE_EVENT_KILL_SELF_NO_RESTART:
        ret = "RNA_SERVICE_EVENT_KILL_SELF_NO_RESTART";
        break;
    case RNA_SERVICE_EVENT_DETACHED_FROM_CLUSTER:
        ret = "RNA_SERVICE_EVENT_DETACHED_FROM_CLUSTER";
        break;
    case RNA_SERVICE_EVENT_REJOINED_CLUSTER:
        ret = "RNA_SERVICE_EVENT_REJOINED_CLUSTER";
        break;
    case RNA_SERVICE_EVENT_SEND_SHUTDOWN_REQUEST_TIMEOUT:
        ret = "RNA_SERVICE_EVENT_SEND_SHUTDOWN_REQUEST_TIMEOUT";
        break;
    }
    return ret;
}

/*!
 * Return the string representation for the specified
 * rna_service_client_control_t, for use in log messages.
 */
const char *
rna_service_get_client_control_type_string(rna_service_client_control_t type)
{
    const char * ret = "Unknown";
    /* (Note that initializing ret allows us to leave out a default
     * case in the below switch, which would allow the compiler to
     * flag a warning if not all cases are covered, if new cases get
     * added in the future, and rna_service_event_t were an enum).
     */

    switch (type) {
    case CLIENT_CONTROL_START:
        ret = "CLIENT_CONTROL_START";
        break;
    case CLIENT_CONTROL_FLUSH:
        ret = "CLIENT_CONTROL_FLUSH";
        break;
    case CLIENT_CONTROL_STOP:
        ret = "CLIENT_CONTROL_STOP";
        break;
    case CLIENT_CONTROL_REACTIVATE:
        ret = "CLIENT_CONTROL_REACTIVATE";
        break;
    case CLIENT_CONTROL_DELETE:
        ret = "CLIENT_CONTROL_DELETE";
        break;
    case CLIENT_CONTROL_ADDCLIENT:
        ret = "CLIENT_CONTROL_ADDCLIENT";
        break;
    case CLIENT_CONTROL_REMCLIENT:
        ret = "CLIENT_CONTROL_REMCLIENT";
        break;
    }
    return ret;
}

/*!
 * Dump information about all rna_service communication connections in XML.
 */
int
rna_service_dump_all_connection_info_xml(rna_service_ctx_t *ctx, void *info_file)
{
    int ret;

    if ((NULL == ctx)
      || (ctx->cx_watermark != RNA_SERVICE_CTX_WATERMARK)
      || (!ctx_add_reference(&ctx))) {
        return (-1);
    } else {
        ret = rna_service_com_dump_all_ep_info_xml(ctx->cx_com_instance,
                                                   "rna_service",
                                                   info_file);
        ctx_release_reference(&ctx);
        return (ret);
    }
}


/* -- Public Functions for use by Cache Servers and Metadata Servers Only -- */

/*!
 * Send the specified event to the configuration manager.
 *
 * The caller must be a user of type RNA_SERVICE_USER_TYPE_CACHE_SERVER or
 * RNA_SERVICE_USER_TYPE_METADATA_SERVER.  This function is designed to be
 * used as an argument to rna_dbg_log_register_event_func().
 *
 * Returns:
 *    0 on success
 *    Non-zero on failure
 */
int
rna_service_cs_send_event_to_cfm(void    *arg,
                                 uint32_t event_type,
                                 char    *event_msg)
{
    rna_service_ctx_t *ctx = (rna_service_ctx_t *) arg;
    int ret = 0;
    rna_service_send_buf_entry_t *send_buf;
    struct cfm_cmd *cmd;
    struct histogram *histogram;

    if ((0 == event_type)
      || (NULL == event_msg)
      || (NULL == ctx)
      || (ctx->cx_watermark != RNA_SERVICE_CTX_WATERMARK)) {
        return (-1);
    }

    /*
     * Currently, only histogram records and messages flagged for remote
     * logging are forwarded.
     */
    if (!(event_type & ctx->cx_cfm_event_mask)
        || !(event_type & (RNA_DBG_REMOTE | RNA_DBG_HISTOGRAM))) {
        return (0);
    }

    if (!ctx_add_reference(&ctx)) {
        return (-1);
    }

    /* Just drop the message if the cfm lock is not available */
    if (!rna_service_mutex_trylock(&ctx->cx_cfm_mutex)) {
        ctx_release_reference(&ctx);
        return (0);
    }

    /*
     * Also, drop the message if we don't currently have a connection to the
     * primary CFM.  We could instead queue the message until we have a
     * connection, but we might queue a huge number of messages.
     */
    if (!rna_service_com_connected(&ctx->cx_primary_cfm_eph)) {
        ret = 0;
        goto done;
    }

    if (event_type & ctx->cx_cfm_event_mask) {
        ret = rna_service_com_get_send_buf(&ctx->cx_primary_cfm_eph,
                                           &send_buf,
                                           FALSE,
                                           NULL);
        /*
         * Also, drop the message if a sendbuf isn't immediately available.
         */
        if ((NULL == send_buf) || (0 != ret)) {
            ret = 0;
            goto done;
        }

#if defined(LINUX_KERNEL) || defined(WINDOWS_KERNEL)
        cmd = (struct cfm_cmd*)(com_get_send_buf_mem(send_buf));
#else
        cmd = (struct cfm_cmd*) send_buf->mem;
#endif
        memset(cmd, 0, sizeof(cmd_hdr_t));

        cmd->h.h_type = CONF_MGR_EVENT;
        cmd->u.rna_event.rnas.type = event_type;
        
        clock_gettime(CLOCK_REALTIME, &cmd->u.rna_event.rnas.timestamp);
        
        if (event_type & RNA_DBG_HISTOGRAM) {
            /* I'm so ashamed to be doing this ... */
            histogram = (struct histogram*) event_msg;
            if (0 != histogram_copy_and_truncate(
                            &cmd->u.rna_event.rnas.rna_dbg_histogram.histogram,
                             sizeof(cmd->u.rna_event.rnas.rna_dbg_histogram),
                             HISTOGRAM_MAX_RNA_EVENT_BUCKETS,
                             histogram)) {
                rna_dbg_log(RNA_DBG_ERR,
                            "failed to truncate histogram! (but sending "
                            "anyway)\n");
            }
        } else {
            strncpy((char*)&cmd->u.rna_event.rnas.data[0],
                    event_msg,
                    sizeof(cmd->u.rna_event.rnas.data));
            cmd->u.rna_event.rnas.data[sizeof(cmd->u.rna_event.rnas.data)-1] =
                                                                        '\0';
                    // strncpy does not NULL-terminate if strlen(src) >= n
        }

        ret = rna_service_com_send_cfm_cmd(&ctx->cx_primary_cfm_eph,
                                           send_buf,
                                           cfm_cmd_length(cmd),
                                           &ctx->cx_primary_cfm_id);
        if (ret != 0) {
            rna_dbg_log(RNA_DBG_WARN,
                        "Send failed: %d\n", ret);
        }
    }

done:
    rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
    ctx_release_reference(&ctx);
    return (ret);
}


/*!
 * Send the specified mount action (MOUNT_BLOCKED or MOUNT_UNBLOCKED) to the
 * configuration manager.
 *
 * The caller must be a user of type RNA_SERVICE_USER_TYPE_CACHE_SERVER.
 */
void
rna_service_cs_send_mount_action_to_cfm(void        *arg,
                                        rna_cmd_type action)
{
    rna_service_ctx_t *ctx = (rna_service_ctx_t *) arg;
    int ret;

    if ((NULL == ctx)
      || (ctx->cx_watermark != RNA_SERVICE_CTX_WATERMARK)
      || (!ctx_add_reference(&ctx))) {
        return;
    }

    if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
        // This failure means we're in the process of shutting down; do nothing
        ctx_release_reference(&ctx);
        return;
    }

    ctx->cx_deferred_mount_action = 0;  // previous value is moot
    ret = agent_announce_mount_action(&ctx->cx_primary_cfm_eph, action);
    if (0 == ret) {
        /* Indicate that this message must be retried */
        ctx->cx_deferred_mount_action = action;
    }

    rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
    ctx_release_reference(&ctx);
}


/*!
 * Send MOUNT_BLOCKED to the configuration manager.
 *
 * The caller must be a user of type RNA_SERVICE_USER_TYPE_CACHE_SERVER.
 */
void
rna_service_cs_send_mount_blocked_to_cfm(void *arg)
{
    rna_service_ctx_t *ctx = (rna_service_ctx_t *) arg;
    int ret;

    if ((NULL == ctx)
      || (ctx->cx_watermark != RNA_SERVICE_CTX_WATERMARK)
      || (!ctx_add_reference(&ctx))) {
        return;
    }

    if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
        // This failure means we're in the process of shutting down; do nothing
        ctx_release_reference(&ctx);
        return;
    }

    ctx->cx_deferred_mount_action = 0;  // previous value is moot
    ret = agent_announce_mount_action(&ctx->cx_primary_cfm_eph, MOUNT_BLOCKED);
    if (0 == ret) {
        /* Indicate that this message must be retried */
        ctx->cx_deferred_mount_action = MOUNT_BLOCKED;
    }

    rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
    ctx_release_reference(&ctx);
}


/*!
 * Send MOUNT_UNBLOCKED to the configuration manager.
 *
 * The caller must be a user of type RNA_SERVICE_USER_TYPE_CACHE_SERVER.
 */
void
rna_service_cs_send_mount_unblocked_to_cfm(void *arg)
{
    rna_service_ctx_t *ctx = (rna_service_ctx_t *) arg;
    int ret;

    if ((NULL == ctx)
      || (ctx->cx_watermark != RNA_SERVICE_CTX_WATERMARK)
      || (!ctx_add_reference(&ctx))) {
        return;
    }

    if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
        // This failure means we're in the process of shutting down; do nothing
        ctx_release_reference(&ctx);
        return;
    }

    ctx->cx_deferred_mount_action = 0;  // previous value is moot
    ret = agent_announce_mount_action(&ctx->cx_primary_cfm_eph,
                                      MOUNT_UNBLOCKED);
    if (0 == ret) {
        /* Indicate that this message must be retried */
        ctx->cx_deferred_mount_action = MOUNT_UNBLOCKED;
    }

    rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
    ctx_release_reference(&ctx);
}


/*!
 * Send a CONF_MGR_CS_SHUTDOWN_REQUEST message to the primary CFM.
 *
 * Arguments:
 *    ctx     The caller's rna_service context, created by
 *            rna_service_ctx_create()
 *    buf     A message buffer containing the message to be sent.
 *    send_timeout_sec
 *            If the shutdown request fails to be sent to the primary CFM
 *            within this period, trigger an
 *            RNA_SERVICE_EVENT_SEND_SHUTDOWN_REQUEST_TIMEOUT event.
 *
 * Returns:
 *    RNA_SERVICE_ERROR_NONE  on success
 *    RNA_SERVICE_ERROR_INVALID_CTX
 *                            Either ctx is NULL or it was not created by
 *                            rna_service_ctx_create().
 */
rna_service_error_t
rna_service_cs_send_shutdown_request(
                            struct rna_service_ctx_s     *ctx,
                            rna_service_message_buffer_t *buf,
                            int                           send_timeout_sec)
{
    rna_service_error_t ret;

    if (buf->h.rmb_message_type !=
                                RNA_SERVICE_MESSAGE_TYPE_CS_SHUTDOWN_REQUEST) {
        return (RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE);
    }

    if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
        // This failure means we're in the process of shutting down; do nothing
        ret = RNA_SERVICE_ERROR_NONE;
    } else {
        ctx->cx_send_shutdown_request_timeout_sec = send_timeout_sec;
        rna_service_timer_set(ctx->cx_private,
                             &ctx->cx_send_shutdown_request_timer,
                              shutdown_request_send_timed_out,
                              (uint64_t)ctx,
                              ctx->cx_send_shutdown_request_timeout_sec);
        ctx->cx_send_shutdown_request_timer_is_set = TRUE;
        ctx->cx_send_shutdown_request_in_progress = TRUE;
        rna_service_mutex_unlock(&ctx->cx_cfm_mutex);

        ret = send_cfm_non_reg_dereg(ctx, buf, FALSE);
        if (RNA_SERVICE_ERROR_NONE != ret) {
            if (rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
                rna_service_timer_cancel(&ctx->cx_send_shutdown_request_timer);
                ctx->cx_send_shutdown_request_timer_is_set = FALSE;
                ctx->cx_send_shutdown_request_in_progress = FALSE;
                rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
            }
        }
    }
    return (ret);
}


/**
 * Allocate an rna_service cs_md_message buffer, to be used as an argument to
 * rna_service_cs_send_cache_response().
 *
 * NOTE that once this message buffer has been used as an argument to 
 * rna_service_cs_send_cache_response(), it may not be modified, freed, or
 * re-used.
 *
 * Arguments:
 *    ctx       The caller's rna_service context, created by
 *              rna_service_ctx_create()
 *    msg_type  The type of message that will be stored in the buffer.  Note
 *              that no other message type may be stored in the buffer.
 *    pathname  path to entry, needed to calculate response length
 *
 * Returns:
 *    A pointer to a message buffer on success
 *    NULL on failure
 */
rna_service_cs_md_message_buffer_t *
rna_service_alloc_cs_md_message_buffer(rna_service_ctx_t         *ctx,
                                       rna_service_cs_md_message_type_t
                                                                  msg_type,
                                       const char                *pathname)
{
    rna_service_message_buffer_internal_t *ibuf = NULL;
    uint8_t mempool_id = MEMPOOL_ID_INVALID;

    if ((NULL == ctx)
      || (ctx->cx_watermark != RNA_SERVICE_CTX_WATERMARK)
      || (!ctx_add_reference(&ctx))) {
        return (NULL);
    }

    switch (msg_type) {

        case RNA_SERVICE_MESSAGE_TYPE_CACHE_RESPONSE:
            /* The caller must specify a pathname for this message type */
            if (NULL != pathname) {
                ibuf = mempool_alloc(ctx,
                                     MEMPOOL_ID_CACHE_RESPONSE,
                                     (PATHNAME_LEN - strlen(pathname)) - 1);
                if (NULL != ibuf) {
                    mempool_id = MEMPOOL_ID_CACHE_RESPONSE;
                }
            } else {
                rna_dbg_log(RNA_DBG_ERR,
                            "pathname must be specified for %s\n",
                            rna_service_get_message_type_string(msg_type));
            }
            break;

        case RNA_SERVICE_MESSAGE_TYPE_CACHE_QUERY_REQUEST:
            /* The caller must specify a pathname for this message type */
            if (NULL != pathname) {
                ibuf = rna_service_simple_alloc(
                                RNAS_MESSAGE_SIZE(rna_service_register_path_t, 
                                                  strlen(pathname) + 1));
                if (NULL != ibuf) {
                    /*
                     * The second argument to RNAS_MESSAGE_SIZE is '1' since
                     * we don't want to zero out the *entire* pathname. The
                     * pathname is going to be NULL terminated anyway
                     */ 
                    memset(ibuf, 0, RNAS_MESSAGE_SIZE(
                                        rna_service_cache_query_request_t, 1));
                }
            } else {
                rna_dbg_log(RNA_DBG_ERR,
                            "pathname must be specified for %s\n",
                            rna_service_get_message_type_string(msg_type));
            }

        /*
         * NOTE that there is purposely no default case here, so the compiler
         * catches a failure to list a defined message type.  Specifying an
         * illegal (undefined) type is handled below).
         */
    }

    if (NULL == ibuf) {
        rna_dbg_log(RNA_DBG_WARN,
                    "unable to allocate message buffer for message type "
                    "[%d] [%s]\n",
                    msg_type,
                    rna_service_get_message_type_string(msg_type));
        ctx_release_reference(&ctx);
        return (NULL);
    }

    init_ibuf(ctx, ibuf, msg_type, mempool_id);

    /*
     * NOTE that we do not call ctx_release_reference, since we need to
     * maintain a ctx reference as long as the above pointer to the ctx exists
     * (h.rmbi_ctx).  This reference will be released when this message buffer
     * is freed.
     *
     * Return a pointer to the user-visible portion of this struct.
     */
    return (&ibuf->u.rmbi_cs_md_message_buffer);
}


/**
 * Send the specified message to the appropriate MD and invoke the specified
 * callback when a response arrives.
 *
 * Arguments:
 *    ctx     The caller's rna_service context, created by
 *            rna_service_ctx_create()
 *    message A message buffer containing the message to be sent.
 *            NOTES:
 *            1. The message buffer was must be allocated with the
 *               same value as msg_type.
 *            2. The message buffer must have been allocated by
 *               rna_service_alloc_message_buffer().
 *            3. The message type must have ben set appropriately
 *               (message->h.rmb_message_type).  The following message types
 *               are supported by this function:
 *                   RNA_SERVICE_MESSAGE_TYPE_CACHE_RESPONSE
 *                   RNA_SERVICE_MESSAGE_TYPE_CACHE_QUERY_REQUEST
 *            4. If no response_callback is specified, the message must not
 *               be accessed after this call.  It will be freed by the
 *               rna_service library.
 *               If a response_callback is specified, the message must not be
 *               accessed until it is returned as the 'message_sent' argument
 *               of the response callback.
 *    response_callback
 *            If non-NULL, the callback routine that will be invoked either
 *            when a response to this message is received or when the response
 *            times out (if the user has specified a response timeout).
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
 *                                RNA_SERVICE_MESSAGE_TYPE_CACHE_RESPONSE
 *                                RNA_SERVICE_MESSAGE_TYPE_CACHE_QUERY_REQUEST
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER
 *                            The message buffer specified was not allocated by
 *                            rna_service_alloc_message_buffer() or has not yet
 *                            been returned in a response callback.
 */
rna_service_error_t
rna_service_cs_send_md(struct rna_service_ctx_s           *ctx,
                       rna_service_cs_md_message_buffer_t *message,
                       rna_service_response_callback       response_callback)
{
    return (rna_service_send_md(ctx,
                                (rna_service_message_buffer_t *) message,
                                response_callback));
}

/**
 * Send the specified message to the appropriate MD, ignoring the limits
 * on the maximum number of oustanding messages,  and invoke the specified
 * callback when a response arrives. Same as rna_service_cs_send_md except
 * for the ignoring message limits behavior  (in most cases
 * rna_service_cs_send_md should be used).
 *
 * Arguments:
 *    ctx     The caller's rna_service context, created by
 *            rna_service_ctx_create()
 *    message A message buffer containing the message to be sent.
 *            NOTES:
 *            1. The message buffer was must be allocated with the
 *               same value as msg_type.
 *            2. The message buffer must have been allocated by
 *               rna_service_alloc_message_buffer().
 *            3. The message type must have ben set appropriately
 *               (message->h.rmb_message_type).  The following message types
 *               are supported by this function:
 *                   RNA_SERVICE_MESSAGE_TYPE_CACHE_RESPONSE
 *                   RNA_SERVICE_MESSAGE_TYPE_CACHE_QUERY_REQUEST
 *            4. If no response_callback is specified, the message must not
 *               be accessed after this call.  It will be freed by the
 *               rna_service library.
 *               If a response_callback is specified, the message must not be
 *               accessed until it is returned as the 'message_sent' argument
 *               of the response callback.
 *    response_callback
 *            If non-NULL, the callback routine that will be invoked either
 *            when a response to this message is received or when the response
 *            times out (if the user has specified a response timeout).
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
 *                                RNA_SERVICE_MESSAGE_TYPE_CACHE_RESPONSE
 *                                RNA_SERVICE_MESSAGE_TYPE_CACHE_QUERY_REQUEST
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER
 *                            The message buffer specified was not allocated by
 *                            rna_service_alloc_message_buffer() or has not yet
 *                            been returned in a response callback.
 */
rna_service_error_t
rna_service_cs_send_md_nomaxcheck(struct rna_service_ctx_s           *ctx,
                                  rna_service_cs_md_message_buffer_t *message,
                                  rna_service_response_callback       response_callback)
{
    return (rna_service_send_md_nomaxcheck(ctx,
                                      (rna_service_message_buffer_t *) message,
                                      response_callback));
}


/*!
 * A cache server uses this API to register a cache device with the CFM.
 *
 * Arguments:
 *    ctx     The caller's rna_service context, created by
 *            rna_service_ctx_create()
 *    buf     A message buffer that specifies the message to be sent.
 *            NOTES:
 *            1. The rmb_message_type must be
 *               RNA_SERVICE_MESSAGE_TYPE_REG_CACHE_DEVICE.
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
 *                            RNA_SERVICE_MESSAGE_TYPE_REG_CACHE_DEVICE
 *                            or the message buffer was not allocated as an
 *                            RNA_SERVICE_MESSAGE_TYPE_REG_CACHE_DEVICE.
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER
 *                            The message buffer specified was not allocated by
 *                            rna_service_alloc_message_buffer() or has not yet
 *                            been returned in a response callback.
 */
rna_service_error_t
rna_service_cs_register_cache_device(struct rna_service_ctx_s     *ctx,
                                     rna_service_message_buffer_t *buf)
{
    if (buf->h.rmb_message_type != RNA_SERVICE_MESSAGE_TYPE_REG_CACHE_DEVICE) {
        return (RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE);
    }
    return (send_registration_or_deregistration(ctx, buf, NULL));
}


/*!
 * A cache server uses this API to deregister a failed cache device with the
 * CFM.  The cache device will not be accepted back into the RNA cache until
 * it is explicitly re-added, at which time it will be re-labeled.
 *
 * Arguments:
 *    ctx     The caller's rna_service context, created by
 *            rna_service_ctx_create()
 *    buf     A message buffer that specifies the message to be sent.
 *            NOTES:
 *            1. The rmb_message_type must be
 *               RNA_SERVICE_MESSAGE_TYPE_DEREG_CACHE_DEVICE.
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
 *                            RNA_SERVICE_MESSAGE_TYPE_DEREG_CACHE_DEVICE
 *                            or the message buffer was not allocated as an
 *                            RNA_SERVICE_MESSAGE_TYPE_DEREG_CACHE_DEVICE.
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER
 *                            The message buffer specified was not allocated by
 *                            rna_service_alloc_message_buffer() or has not yet
 *                            been returned in a response callback.
 */
rna_service_error_t
rna_service_cs_deregister_cache_device(struct rna_service_ctx_s     *ctx,
                                       rna_service_message_buffer_t *buf)
{
    if (buf->h.rmb_message_type != RNA_SERVICE_MESSAGE_TYPE_DEREG_CACHE_DEVICE)
    {
        return (RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE);
    }
    return (send_registration_or_deregistration(ctx, buf, NULL));
}


/*!
 * A cache server uses this API to deregister a replica store with the CFM.
 *
 * Arguments:
 *    ctx     The caller's rna_service context, created by
 *            rna_service_ctx_create()
 *    buf     A message buffer that specifies the message to be sent.
 *            NOTES:
 *            1. The rmb_message_type must be
 *               RNA_SERVICE_MESSAGE_TYPE_DEREG_REPLICA_STORE.
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
 *                            RNA_SERVICE_MESSAGE_TYPE_DEREG_REPLICA_STORE
 *                            or the message buffer was not allocated as an
 *                            RNA_SERVICE_MESSAGE_TYPE_DEREG_REPLICA_STORE.
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER
 *                            The message buffer specified was not allocated by
 *                            rna_service_alloc_message_buffer() or has not yet
 *                            been returned in a response callback.
 */
rna_service_error_t
rna_service_cs_deregister_replica_store(struct rna_service_ctx_s     *ctx,
                                        rna_service_message_buffer_t *buf)
{
    if (buf->h.rmb_message_type != RNA_SERVICE_MESSAGE_TYPE_DEREG_REPLICA_STORE)
    {
        return (RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE);
    }
    return (send_registration_or_deregistration(ctx, buf, NULL));
}


/*!
 * A cache server uses this API to indicate that it has finished its initial
 * set of cache device and replica store registrations, which were done on
 * startup as cache devices were discovered.
 *
 * Arguments:
 *    ctx     The caller's rna_service context, created by
 *            rna_service_ctx_create()
 *    cmd     The CONF_MGR_QUERY_CACHE_DEVICE message this call is in
 *            response to
 *
 * Returns:
 *    RNA_SERVICE_ERROR_NONE  On success
 *    RNA_SERVICE_ERROR_INVALID_CTX
 *                            Either ctx is NULL, or it is in the process of
 *                            shutting down (rna_service_ctx_destroy() has been
 *                            called), or it was not created by
 *                            rna_service_ctx_create().
 */
rna_service_error_t
rna_service_cs_initial_cache_device_registrations_complete(
                                                struct rna_service_ctx_s *ctx,
                                                void *cmd)
{
    if ((NULL == ctx)
      || (ctx->cx_watermark != RNA_SERVICE_CTX_WATERMARK)
      || (!ctx_add_reference(&ctx))) {
        rna_dbg_log(RNA_DBG_WARN,
                    "called with NULL or corrupt rna_service_ctx [%p]\n", ctx);
        return (RNA_SERVICE_ERROR_INVALID_CTX);
    }

    if (!rna_service_mutex_lock(&ctx->cx_cfm_mutex)) {
        // This failure means we're in the process of shutting down; do nothing
        return (RNA_SERVICE_ERROR_NONE);
    }
    ctx->cx_cfm_flags |= (CTX_CFM_FLAG_INITIAL_REGISTRATIONS_COMPLETE |
                          CTX_CFM_FLAG_MUST_SEND_CACHEDEV_REGISTRATION_END);
    /*
     * Save the timestamp that will be included in the
     * CONF_MGR_REG_CACHE_DEVICE_END message that will (eventually) be sent as
     * a result of the CTX_CFM_FLAG_MUST_SEND_CACHEDEV_REGISTRATION_END flag
     * being set.
     */
    ctx->cx_cfm_query_cachedev_timestamp =
              ((struct cfm_cmd *)cmd)->u.cache_cfm_query_cachedev.qc_timestamp;

    schedule_waiting_cfm_msgs(ctx, 0);

    rna_service_mutex_unlock(&ctx->cx_cfm_mutex);
    ctx_release_reference(&ctx);
    return (RNA_SERVICE_ERROR_NONE);
}


/*!
 * Send a CONF_MGR_RESILVER_CACHE_DEVICE_COMPLETE message to the primary CFM.
 *
 * Arguments:
 *    ctx     The caller's rna_service context, created by
 *            rna_service_ctx_create()
 *    buf     A message buffer containing the message to be sent.
 *
 * Returns:
 *    RNA_SERVICE_ERROR_NONE  on success
 *    RNA_SERVICE_ERROR_INVALID_CTX
 *                            Either ctx is NULL or it was not created by
 *                            rna_service_ctx_create().
 */
rna_service_error_t
rna_service_cs_send_resilver_cache_device_complete(
                                        struct rna_service_ctx_s     *ctx,
                                        rna_service_message_buffer_t *buf)
{
    return (send_cfm_non_reg_dereg(ctx, buf, FALSE));
}

/*!
 * A cache server uses this API to update the journal contents for
 * a SCSI client reservation with the CFM.
 *
 * Arguments:
 *    ctx     The caller's rna_service context, created by
 *            rna_service_ctx_create()
 *    buf     A message buffer that specifies the message to be sent.
 *            NOTES:
 *            1. The rmb_message_type must be
 *               RNA_SERVICE_MESSAGE_TYPE_UPDATE_SCSI_ITN_RES
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
 *                            RNA_SERVICE_MESSAGE_TYPE_SCSI_ITN_REGISTRATION.
 *                            or the message buffer was not allocated as an
 *                            RNA_SERVICE_MESSAGE_TYPE_SCSI_ITN_REGISTRATION.
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER
 *                            The message buffer specified was not allocated by
 *                            rna_service_alloc_message_buffer() or has not yet
 *                            been returned in a response callback.
 */
rna_service_error_t
rna_service_cs_update_scsi_itn_reservation(
                                    struct rna_service_ctx_s     *ctx,
                                    rna_service_message_buffer_t *buf)
{
    if (buf->h.rmb_message_type !=
            RNA_SERVICE_MESSAGE_TYPE_UPDATE_SCSI_ITN_RES) {
        return (RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE);
    }

    return (send_cfm_non_reg_dereg(ctx, buf, FALSE));
}


/*!
 * A cache server uses this API to update the journal contents for
 * a SCSI client reservation with the CFM.
 *
 * Arguments:
 *    ctx     The caller's rna_service context, created by
 *            rna_service_ctx_create()
 *    buf     A message buffer that specifies the message to be sent.
 *            NOTES:
 *            1. The rmb_message_type must be
 *               RNA_SERVICE_MESSAGE_TYPE_UPDATE_SCSI_ITN_REG
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
 *                            RNA_SERVICE_MESSAGE_TYPE_SCSI_ITN_REGISTRATION.
 *                            or the message buffer was not allocated as an
 *                            RNA_SERVICE_MESSAGE_TYPE_SCSI_ITN_REGISTRATION.
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER
 *                            The message buffer specified was not allocated by
 *                            rna_service_alloc_message_buffer() or has not yet
 *                            been returned in a response callback.
 */
rna_service_error_t
rna_service_cs_update_scsi_itn_registration(
                                    struct rna_service_ctx_s     *ctx,
                                    rna_service_message_buffer_t *buf)
{
    if (buf->h.rmb_message_type !=
            RNA_SERVICE_MESSAGE_TYPE_UPDATE_SCSI_ITN_REG) {
        return (RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE);
    }

    return (send_cfm_non_reg_dereg(ctx, buf, FALSE));
}


/*!
 * A cache server uses this API to update the journal contents for
 * a SCSI client reservation with the CFM.
 *
 * Arguments:
 *    ctx     The caller's rna_service context, created by
 *            rna_service_ctx_create()
 *    buf     A message buffer that specifies the message to be sent.
 *            NOTES:
 *            1. The rmb_message_type must be
 *               RNA_SERVICE_MESSAGE_TYPE_CLEAR_SCSI_ITN_RES
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
 *                            RNA_SERVICE_MESSAGE_TYPE_SCSI_ITN_REGISTRATION.
 *                            or the message buffer was not allocated as an
 *                            RNA_SERVICE_MESSAGE_TYPE_SCSI_ITN_REGISTRATION.
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER
 *                            The message buffer specified was not allocated by
 *                            rna_service_alloc_message_buffer() or has not yet
 *                            been returned in a response callback.
 */
rna_service_error_t
rna_service_cs_clear_scsi_itn_reservation(
                                    struct rna_service_ctx_s     *ctx,
                                    rna_service_message_buffer_t *buf)
{
    if (buf->h.rmb_message_type !=
            RNA_SERVICE_MESSAGE_TYPE_CLEAR_SCSI_ITN_RES) {
        return (RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE);
    }

    return (send_cfm_non_reg_dereg(ctx, buf, FALSE));
}


/*!
 * A cache server uses this API to update the journal contents for
 * a SCSI client reservation with the CFM.
 *
 * Arguments:
 *    ctx     The caller's rna_service context, created by
 *            rna_service_ctx_create()
 *    buf     A message buffer that specifies the message to be sent.
 *            NOTES:
 *            1. The rmb_message_type must be
 *               RNA_SERVICE_MESSAGE_TYPE_ACQUIRE_SCSI_ITN_RES
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
 *                            RNA_SERVICE_MESSAGE_TYPE_SCSI_ITN_REGISTRATION.
 *                            or the message buffer was not allocated as an
 *                            RNA_SERVICE_MESSAGE_TYPE_SCSI_ITN_REGISTRATION.
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER
 *                            The message buffer specified was not allocated by
 *                            rna_service_alloc_message_buffer() or has not yet
 *                            been returned in a response callback.
 */
rna_service_error_t
rna_service_cs_acquire_scsi_itn_reservation(
                                    struct rna_service_ctx_s     *ctx,
                                    rna_service_message_buffer_t *buf)
{
    if (buf->h.rmb_message_type !=
            RNA_SERVICE_MESSAGE_TYPE_ACQUIRE_SCSI_ITN_RES) {
        return (RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE);
    }

    return (send_cfm_non_reg_dereg(ctx, buf, FALSE));
}



/*!
 * A cache server uses this API to update the journal contents for
 * a SCSI client reservation with the CFM.
 *
 * Arguments:
 *    ctx     The caller's rna_service context, created by
 *            rna_service_ctx_create()
 *    buf     A message buffer that specifies the message to be sent.
 *            NOTES:
 *            1. The rmb_message_type must be
 *               RNA_SERVICE_MESSAGE_TYPE_ACQUIRE_SCSI_ITN_REG
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
 *                            RNA_SERVICE_MESSAGE_TYPE_SCSI_ITN_REGISTRATION.
 *                            or the message buffer was not allocated as an
 *                            RNA_SERVICE_MESSAGE_TYPE_SCSI_ITN_REGISTRATION.
 *    RNA_SERVICE_ERROR_INVALID_MESSAGE_BUFFER
 *                            The message buffer specified was not allocated by
 *                            rna_service_alloc_message_buffer() or has not yet
 *                            been returned in a response callback.
 */
rna_service_error_t
rna_service_cs_acquire_scsi_itn_registration(
                                    struct rna_service_ctx_s     *ctx,
                                    rna_service_message_buffer_t *buf)
{
    if (buf->h.rmb_message_type !=
            RNA_SERVICE_MESSAGE_TYPE_ACQUIRE_SCSI_ITN_REG) {
        return (RNA_SERVICE_ERROR_INVALID_MESSAGE_TYPE);
    }

    return (send_cfm_non_reg_dereg(ctx, buf, FALSE));
}

/* -------------------- Primary CFM ID --------------------- */

/**
 * Return the current primary CFM ID.
 *
 * Arguments:
 *    ctx     The caller's rna_service context, created by
 *            rna_service_ctx_create()
 */
extern primary_cfm_id_t *
rna_service_primary_cfm_id(rna_service_ctx_t *ctx)
{
    return (&ctx->cx_primary_cfm_id.pcic_pci);
}


/* ==================== IP Address Parsing Functions ====================== */

/*
 * Various parsing functions used by parse_ip_addr --
 * they only advance the string pointer if parsing is 
 * successful.
 *
 * Returns:
 *  TRUE on success
 *  FALSE on failure
 */

/* Parse an unsigned int, overwrite *value on success. */
static boolean
consume_int(int *value, char **str, const int max)
{
    //int ret = TRUE;
    boolean ret = TRUE;
    int i;
    char temp;
    int tmp_val = 0;

    for (i=0; ; i++) {
        temp = (*str)[i];
        if (isascii(temp) && isdigit(temp)) {
            tmp_val = (tmp_val * 10) + (temp - '0');
        } else {
            break;
        }
    }

    if (0 == i || tmp_val > max) {
        rna_trace("bogus value %d\n", tmp_val);
        ret = FALSE;
    } else {
        *str += i;
        *value = tmp_val;
    }
    return ret;
}

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
char *
rna_service_com_type_string(int type)
{
    if (RC == type) {
        return "-RDMA";
    } else {
        return "";
    }
}

static boolean
consume_com_type(int *type, char **str)
{
    //int ret = TRUE;
    boolean ret = TRUE;
    size_t rclen = strlen("RDMA");
    size_t tcplen = strlen("TCP");

    if (0 == strncmp (*str, "RDMA", rclen)) {
        *type = RC;
        *str += rclen;
    } else if (0 == strncmp (*str, "TCP", tcplen)) {
        *type = IP_TCP;
        *str += tcplen;
    } else {
        ret = FALSE;
    }
    return ret;
}

/* Attempt to consume an expected character. */
static boolean
consume_char(const char c, char **str)
{
    //int ret;
    boolean ret;

    if (c == (*str)[0]) {
        *str = *str+1;
        ret = TRUE;
    } else {
        ret = FALSE;
    }

    return ret;
}

/*
 * True if we're at the end of the string, or if there is whitespace.
 * False if we start at a non-whitespace character.  
 * Does not modify string.
 */
static boolean
end_or_whitespace (char **str)
{
    char c = (*str)[0];

    switch (c) {
        case '\0':
        case '\n':
        case '\t':
        case ' ':
        case ',':
            return TRUE;
        default: break;
    }

    return FALSE;
}

/*
 * Consumes whitespace.
 * May consume a single comma.
 * Returns FALSE if there was no whitespace to consume,
 * unless we're already at the end of the string.
 */
static boolean
consume_whitespace (char **str)
{
    char c;
    int found_ws = FALSE;

    for (;;) {
        c = **str;

        switch (c) {
           /* end of string */
           case '\0':
               return TRUE;
           /* found whitespace */
           case '\n':
           case '\t':
           case ' ':
               found_ws = TRUE;
               break;
           /* found a non-whitespace character */
           default:
               if (found_ws)
                   return TRUE;
               else
                   return FALSE;
        }

        (*str)++;
    }
}

/* Consume a single comma, and/or whitespace. */
static boolean
consume_whitespace_and_comma (char **str)
{
    //int ret = FALSE;
    boolean ret = FALSE;

    ret |= consume_whitespace(str);
    ret |= consume_char(',', str);
    ret |= consume_whitespace(str);

    return ret;
}

/*
 * It's probably possible to do this much more simply with scanf,
 * but I believe this style of parser is more flexible when dealing
 * with strings that can be formatted in more than one way. 
 * If parsing is successful, "rest" is set to point to the remaining 
 * text, if any.  If "rest" is NULL, we consider it an error if
 * there is any remaining text.
 *  
 * This function does not do hostname resolution. 
 *
 * Acceptable formats include: 
 *   a.b.c.d-port-transport 
 *   a.b.c.d-transport-port
 *   a.b.c.d-port
 *   a.b.c.d-transport
 *   a.b.c.d
 *
 * For example: "192.168.0.1-7441-RDMA
 *
 * port_ptr, com_type_ptr, and rest are allowed to be NULL. 
 * addr and port_ptr are returned in network byte order.
 *
 * Returns:
 *  0       on success
 *  -EINVAL on failure
 */

int
rna_service_parse_ip_addr(char *ip, uint32_t *addr, uint16_t *port_ptr, 
                          int *com_type_ptr, char **rest)
{
    int addr_fields[4];
    int port = -1;
    int com_type = -1;
    char* str = ip;
    int ok = TRUE;
    int ret = 0;
    int i;
    size_t invlen = strlen("INVALID");
    int silent = FALSE;

    rna_trace("parse_ip_addr %s\n", ip);

    /* we may have leading whitespace */
    consume_whitespace(&str);

    if (0 == strncmp(str, "INVALID", invlen)) {
        /* fail silently */
        ok = FALSE;
        silent = TRUE;
    } else {
        /* parse the IP address */
        for (i=0; i<4 && ok; i++) {
            addr_fields[i] = 0;
            ok = ok && consume_int(&addr_fields[i], &str, 255);
            if (i < 3) {
                ok = ok && consume_char('.', &str);
            }
        }

        if (!ok) {
            rna_dbg_log(RNA_DBG_ERR, "numerical address parse failed\n");
        } else {
            rna_dbg_log(RNA_DBG_VERBOSE, "addr parsed as %d.%d.%d.%d\n", 
                        addr_fields[0], addr_fields[1],
                        addr_fields[2], addr_fields[3]);
        }
    }

    while (ok && !end_or_whitespace(&str)) {
        ok = ok && consume_char('-', &str);

        if (-1 == port && consume_int(&port, &str, 65535)) {
            ok = TRUE;
        } else if (-1 == com_type && consume_com_type(&com_type, &str)) {
            ok = TRUE;
        } else {
            rna_dbg_log(RNA_DBG_ERR, "port or transport parse failure %s\n",
                        str);
            ok = FALSE;
        }
    }

    /* If the string contains multiple whitespace or comma separated 
     * addresses, that's fine as long as the application passes
     * in a "rest" pointer to capture the remaining text. */
    if (ok) {
        consume_whitespace_and_comma(&str);
        if ( NULL == rest && *str != '\0') {
            rna_dbg_log(RNA_DBG_ERR, "extra text: %s\n", str);
            ok = FALSE;
        }
    }

    if (ok) {

        *addr = 0;
        for (i=0; i<4; i++) {
            *addr *= 256;
            *addr += addr_fields[i];
        }

        *addr = htonl(*addr);

        rna_dbg_log(RNA_DBG_VERBOSE, "parse ok, addr "RNA_ADDR_FORMAT" port %d "
                    "type %d remaining \"%s\"\n", 
                    RNA_ADDR(*addr), port, com_type, str);

        if (-1 != port && NULL != port_ptr) {
            *port_ptr = htons((uint16_t) port);
        }
        if (-1 != com_type && NULL != com_type_ptr) {
             *com_type_ptr = (int)com_type;
        }
        if (NULL != rest) {
             *rest = str;
        }

    } else {
        if (!silent)
            rna_dbg_log(RNA_DBG_ERR, "unable to parse address \"%s\"\n", ip);
        ret = -EINVAL;
    }

    return ret;
}

/*
 * rna_service_fill_event:
 *
 *      Fill in an rna_event structure for sending to the CFM to process
 *
 *      return:
 *       0: Success
 *      -1: buffer overflow (argument list too big)
 *      -2: invalid argument type found
 */
static int
rna_service_fill_event(rna_service_event_msg_t *evt,
                       uint32_t event_id,
                       va_list args)
{
    int ret = 0;
    uint32_t arg_type;
    uint32_t arg_count = 0;
    rna_store_wwn_t *wp = NULL;

    evt->type = RNA_DBG_EVENT;
    
    clock_gettime(CLOCK_REALTIME, &evt->timestamp);
    
    evt->oms_event.oms_event_id = event_id;
    evt->oms_event.oms_arg_count = 0;

    /*
     * Process the va_list and set up the args to send
     */
    arg_count = 0;

    for (;;) {
        arg_type = va_arg(args, uint32_t);
        if (ARG_TYPE_END == arg_type) {
            break;
        }
        if (RNA_OMS_MAX_ARGS <= arg_count) {
            /* too many arguments to the function */
            return -1;
        }
        switch (arg_type) {
        case ARG_TYPE_MODE:
            evt->oms_event.oms_data[arg_count].oms_arg_type = arg_type;
            evt->oms_event.oms_data[arg_count].u.oms_write_mode =
                                    va_arg(args, cache_write_mode_t);
            arg_count++;
            break;
        case ARG_TYPE_SIZE:
            evt->oms_event.oms_data[arg_count].oms_arg_type = arg_type;
            evt->oms_event.oms_data[arg_count].u.oms_size =
                        va_arg(args, uint64_t);
            arg_count++;
            break;
        case ARG_TYPE_CACHEDEV_WWN:
        case ARG_TYPE_CACHEDEV_PATH:
        case ARG_TYPE_STORAGE_PATH_WWN:
        case ARG_TYPE_STORAGE_PATH_PATH:
        case ARG_TYPE_PERSISTENT_WWN:
        case ARG_TYPE_PERSISTENT_PATH:
            wp = va_arg(args, rna_store_wwn_t *);
            evt->oms_event.oms_data[arg_count].oms_arg_type = arg_type;
            memcpy(&evt->oms_event.oms_data[arg_count].u.oms_store_wwn,
                    wp, sizeof(*wp));
            arg_count++;
            break;
        case ARG_TYPE_CACHE_POOL_ID:
        case ARG_TYPE_CACHED_LUN_NAME:
        case ARG_TYPE_JOURNAL_LOCATION:
        case ARG_TYPE_HCN_ID:
        case ARG_TYPE_MGMT_IP:
        case ARG_TYPE_CACHE_NET_IP:
        case ARG_TYPE_SAN_ID:
        case ARG_TYPE_SAN_NAME:
        case ARG_TYPE_SAN_TYPE:
        case ARG_TYPE_HC_VOLUME_ID:
        case ARG_TYPE_SAN_VOLUME_ID:
        case ARG_TYPE_SNAP_ID:
        case ARG_TYPE_STATUS:
            evt->oms_event.oms_data[arg_count].oms_arg_type = arg_type;
            memset(evt->oms_event.oms_data[arg_count].u.oms_string,
                   0, RNA_OMS_ARG_LEN);
            strncpy(evt->oms_event.oms_data[arg_count].u.oms_string,
                    va_arg(args, char *), RNA_OMS_ARG_LEN-1);
            arg_count++;
            break;
        default:
            ret = -2;
            goto done;
            break;
        }
    }
    evt->oms_event.oms_arg_count = arg_count;

done:
    return ret;
}

/*!
 * Send the specified oms event to the configuration manager.
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
int
rna_service_send_oms_event_to_cfm(struct rna_service_ctx_s *ctx,
                                  uint32_t event_id, ...)
{
    int ret;
    rna_service_message_buffer_t *buf;
    va_list ap;

    if ((NULL == ctx)
      || (ctx->cx_watermark != RNA_SERVICE_CTX_WATERMARK)
      || (!ctx_add_reference(&ctx))) {
        return (-1);
    }

    buf = rna_service_alloc_message_buffer(ctx,
                                           RNA_SERVICE_MESSAGE_TYPE_EVENT,
                                           NULL);
    if (NULL == buf) {
        rna_dbg_log(RNA_DBG_WARN,
                    "failed to get send buffer for "
                    "RNA_SERVICE_MESSAGE_TYPE_OMS_EVENT message\n");
        return (-1);
    }

    va_start(ap, event_id);

    /*
     * Fill in the event structure from the supplied data.
     */
    ret = rna_service_fill_event(&buf->u.rmb_event, event_id, ap);
    va_end(ap);
    if (0 != ret) {
        rna_service_free_message_buffer(ctx, buf);
        return (ret);
    }

    if (RNA_SERVICE_ERROR_NONE == send_cfm_non_reg_dereg(ctx, buf, FALSE)) {
        return (0);
    } else {
        return (-1);
    }
}

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
int
rna_service_oms_event_from_cfm(cfm_event_cmd cmd, uint32_t event_id, ...)
{
    int ret = 0;
    rna_service_event_msg_t *evt;

    va_list ap;


    va_start(ap, event_id);
    evt = calloc(1, sizeof(*evt));

    /*
     * Fill in the event structure from the supplied data.
     */
    ret = rna_service_fill_event(evt, event_id, ap);
    va_end(ap);

    if (0 != ret) {
        goto done;
    }

    /*
     * CFM handler function for writing the event
     */
    ret = cmd(NULL, evt);
    if (ret != 0) {
        rna_dbg_log(RNA_DBG_WARN,
                    "Event write failed: %d\n", ret);
    }

done:
    free(evt);
    return (ret);
}
#endif /* ifndef LINUX_KERNEL || WINDOWS_KERNEL */

#ifdef WINDOWS_KERNEL

/* This is ugly, but since numerous definitions are in this .c file, jam this 
 * into the bottom of it; heck, what's another few lines, it's already 16k+ 
 */

typedef struct cfm_timeout_dpc {
    PWORK_ITEM_FUNCTION wrkitm;
    uint64_t context;
}cfm_timeout_dpc_t, *pcfm_timeout_dpc_t;

IO_WORKITEM_ROUTINE rna_service_timeout_workrtn;

// Prototype here to make compiler happy
NTSTATUS  ReturnWorkItemFromGlobalContext( PIO_WORKITEM *pWork);

/****************************************************************************/ 

void
rna_service_queue_reconnect_cfms_to_dpc(PWORK_ITEM_FUNCTION wrkitm,
                                        uint64_t context)
{
	/* Now dump the function off to a system thread */
#ifndef WINDOWS_RNA_SERVICE_TEST_DRIVER_ONLY
	pHW_HBA_EXT pHBAExt;
#endif /* WINDOWS_RNA_SERVICE_TEST_DRIVER_ONLY */
	PIO_WORKITEM pWorkitem = NULL;

	pcfm_timeout_dpc_t pCfmDpcInfo;
	struct rna_service_ctx_s * pRnaSvcCtx = (struct rna_service_ctx_s *)context;

	/* Sometimes the context passed in is a rna_service context and sometimes
	 * it is an internal message buffer.  Figure out which it is, so we can
	 * get the proper rna_service context.  
	 */

	if (RNA_SERVICE_CTX_WATERMARK != pRnaSvcCtx->cx_watermark) {
		rna_service_message_buffer_internal_t *ibuf;
		ibuf = (rna_service_message_buffer_internal_t *) context;
		pRnaSvcCtx = ibuf->h.rmbi_ctx;
	}


#ifdef WINDOWS_RNA_SERVICE_TEST_DRIVER_ONLY
	ReturnWorkItemFromGlobalContext(&pWorkitem);
#else
	// Have to get the HBAExt first.
	pHBAExt = hbaext_from_rna_service_ctx(pRnaSvcCtx);
	ASSERT(NULL != pHBAExt);
	pWorkitem = pHBAExt->pTimeOutWorkItem;
#endif  /* WINDOWS_RNA_SERVICE_TEST_DRIVER_ONLY */

	pCfmDpcInfo = (pcfm_timeout_dpc_t)ExAllocatePoolWithTag(NonPagedPool, sizeof(cfm_timeout_dpc_t), RNA_ALLOC_TAG);

	if (NULL==pCfmDpcInfo) {
		//DoStorageTraceEtw(DbgLvlErr, MpDemoDebugInfo, "ScsiCommandSetup Failed to allocate work parm structure\n");
		return;
	}

	RtlZeroMemory(pCfmDpcInfo, sizeof(cfm_timeout_dpc_t)); 

	pCfmDpcInfo->wrkitm     = wrkitm;
	pCfmDpcInfo->context    = context;

	IoQueueWorkItem(pWorkitem, rna_service_timeout_workrtn, DelayedWorkQueue, pCfmDpcInfo);
}

VOID                        
rna_service_timeout_workrtn(__in PDEVICE_OBJECT  pDummy,   // Not used.
                            __in_opt PVOID       pWkParms) // Parm list pointer.
{
    pcfm_timeout_dpc_t pCfmDpcInfo = (pcfm_timeout_dpc_t)pWkParms;
    PWORK_ITEM_FUNCTION workFunction;
    UNREFERENCED_PARAMETER(pDummy);
    ASSERT(pWkParms);

    workFunction = pCfmDpcInfo->wrkitm;
    workFunction((PVOID)pCfmDpcInfo->context, NULL);

    ExFreePoolWithTag(pCfmDpcInfo, RNA_ALLOC_TAG);
}
#endif /* WINDOWS_KERNEL */
