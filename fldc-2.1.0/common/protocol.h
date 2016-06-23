/**
 * <protocol.h> - Dell Fluid Cache block driver
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

#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_

#include "platform.h"


CODE_IDENT("$URL: https://svn.rnanetworks.com/full/tags/HERMES_2_1_0_RC1/common/protocol.h $ $Id: protocol.h 49452 2016-03-14 21:12:28Z ccasper $")

#include "rna_types.h"
#include "rna_service_id.h"

#include "rna_service.h"
#include "rna_service_cs_md.h"
#include "cachedev.h"

#if defined(LINUX_KERNEL) || defined(WINDOWS_KERNEL)
typedef unsigned char uuid_t[16];
#endif

#include "journal.h"
#include "meta_data.h"
#include "rna_dskattrs_common.h"
#include "rna_byteswap.h"

#if defined(LINUX_KERNEL) || defined(WINDOWS_KERNEL)
#include "rna_hash_common.h"

#ifdef LINUX_KERNEL
#ifdef __powerpc64__
#define __PRI64_PREFIX	"l"
#else
#if defined(__GNUC__) && !defined(__STRICT_ANSI__)
#define  __PRI64_PREFIX  "ll"
#endif
#endif /* __powerpc64__ */


#define PRId64         __PRI64_PREFIX "d"
#define PRIx64         __PRI64_PREFIX "x"
#define PRIu64         __PRI64_PREFIX "u"

#endif /* LINUX_KERNEL */

enum cache_multi_write_mode {
	DISABLE_MULTI_WRITE=0,
	ENABLE_MULTI_WRITE
};

#ifndef WINDOWS_KERNEL
/*Winkern already defines UCHAR_MAX */
#define UCHAR_MAX		255
#endif /*WINDOWS_KERNEL */

#endif	/* LINUX_KERNEL || WINDOWS_KERNEL */




/*  VERSION 2 - client_create_block_device.capacity  changed from uint32_t to uint64_t  */
/*  VERSION 3 - removed file path and now use WWN via rna_store_wwn_t in
 *              rna_service_register_path_t and rna_service_control_cs_t
 *              affecting CACHE_REG_PATH, CACHE_DEREG_PATH,
 *                        CONF_MGR_REG_PATH, CONF_MGR_DEREG_PATH
 */
/*  VERSION 4 - added blocks_base to cache_io_stats to record base when cachedev is removed */
/*  VERSION 5 - added mur_msg_id to mur_url_resp for message catalog access by GUI */
/*  VERSION 6 - added agent_get_ssd/agent_get_ssd_rep to cfm_cmd structure */
/*  VERSION 7 - added prepare_delete_hcc/prepare_delete_hcc_resp to cfm_cmd structure */
/*  VERSION 8 - added message types for remote journal read/write to cfm_cmd structure */
/*  VERSION 9 - added hcckey to agent_reg_resp structure */
/*  VERSION 10 - added FluidCache version and SOAP API version to agent_reg_resp structure */
/*  VERSION 11 - added master block ID to rna_service_create_block_device */
/*  VERSION 12 - added sync_flag to the req_priv_data */
/*  VERSION 13 - added CONF_MGR_CACHE_VIEW_STATUS message */
/*  VERSION 14 - modified the layout of the md_sync_data_end message */
/*  VERSION 15 - increased MAX_WWN_STR_LEN value */
/*  VERSION 16 - added CFM peer info to cfm_journal_init_request */
/*  VERSION 17 - added ccrr_service_id to cache_cfm_reg_resp */
/*  VERSION 18 - added CONF_MGR_CFM_SHUTDOWN_STATUS and
 *               CONF_MGR_CFM_SHUTDOWN_GRANT messages */
/*  VERSION 19 - added generation to CACHE_RSV_ACCESS & CACHE_RSV_ACCESS_RESP */
/*
 * NOTE: When updating, update the copy in comAPIPublic.h as well.
 *       Also determine whether the latest release-specific definition below
 *       needs to be updated too.
 */
#define RNA_PROTOCOL_VERSION 19

// Protocol version for FluidCache V2.0.10
#define RNA_PROTOCOL_2_0_10 16

// Protocol version for FluidCache V2.1.0
#define RNA_PROTOCOL_2_1_0 19

// Minimum protocol version supported for rolling upgrades
#define RNA_PROTOCOL_MIN_VERSION RNA_PROTOCOL_2_0_10

/** Well known port number for the configuration manager
*/
#define CONF_MGR_PORT   7449

/** Listening port number for http, https and /etc/services names
*/
#define FLDC_HTTP_PORT  8080
#define FLDC_HTTP_SVC   "fldc-http"
#define FLDC_HTTPS_PORT 6773
#define FLDC_HTTPS_SVC  "fldc-https"

/** Listening port number for agent http, https and /etc/services names
*/
#define AGENT_HTTP_PORT  8082
#define AGENT_HTTP_SVC   "fldca-http"
#define AGENT_HTTPS_PORT 6774
#define AGENT_HTTPS_SVC  "fldca-https"

/** Default to grabbing first available high port
*/
#define CACHE_PORT		0

/** Default to grabbing first available high port
*/
#define META_DATA_PORT	0

/** Maximum number of ISER ports
 */
#define	MAX_ISER_PORTS	4

/** Maximum length of a file or device name
*/
#define MAX_NAME_LEN	255

/** Maximum length of the client reference private data
 *  This value is a multiple of 8, to avoid causing alignment problems with
 *  fields following it.
 */
#define MAX_PVT_DATA    RNA_SERVICE_PVT_DATA_MAX

/** Maximum length of the hostname
*/
#define MAX_HOST_LEN		128
#define MAX_GROUP_LEN		64
#define MAX_INSTANCE_LEN	64
#define MAX_CPU_STR_LEN		64

#define RNA_DONT_POST_RECV 255

/** Maximum transfer size
 */
#define MAX_TRANSFER_SIZE (256 * 1024)

/** Maximum length of the CLI request/response data 
*/
#define MAX_CLI_DATA   1024

/** An illegal MD ordinal.
 */
#define NULL_MD_ORDINAL     0

#define TCP_DATA_PAYLOAD_LEN 8192

#define RFT_FILENAME_LEN 128
#define RFT_PAYLOAD_LEN 4096

#define MAX_DATA_WRITE_PAYLOAD 4096

/* 
 * Size of dirty list in bytes.  128 bytes is big enough for 512 KB blocks with 
 * a 512 byte sector size. 
 */
#define MAX_DIRTY_LIST_SIZE_BYTES  128

/* Size of dirty list in array items (uint64_ts) */
#define MAX_DIRTY_LIST_SIZE (MAX_DIRTY_LIST_SIZE_BYTES/sizeof(uint64_t))

/* Size of dirty list in bits */
#define MAX_DIRTY_LIST_BITS (MAX_DIRTY_LIST_SIZE_BYTES * 8)

/*
 * The rate at which EMPTY_PING messages are sent to non-primary CFMs.  This
 * time should be smaller than the time a server takes to restart after being
 * power-cycled.
 */
#define NON_PRIMARY_CFM_PING_SEC  60

/*
 * Total time (in seconds) allowed for an IOS to complete, starting at
 * allocation, ending at block request completion.  should be greater than
 * service library MD query timeout (rsp_metadata_query_response_timeout).
 *
 * The use of RNA_SHARED_IO_TIMEOUT_SECONDS allows us to keep I/O-related
 * timeouts about the same.
 */
#define RNABLK_IO_TIMEOUT           RNA_SHARED_IO_TIMEOUT_SECONDS

#ifdef __KERNEL__
typedef unsigned char rna_boolean;
#else
typedef gboolean rna_boolean;
#endif // __KERNEL__

/** Peer state. For peering this defines connected state.
 */
typedef enum {
    PEER_DISCONNECTED_PRIMARY = 0,
    PEER_CONNECTED_PRIMARY,
    PEER_CONNECTED_SECONDARY
} peer_state_type;


/* Graceful shutdown states */
typedef enum shutdown_state_e {
    SHUTDOWN_STATE_UNINITIALIZED = 0,
    SHUTDOWN_STATE_NONE,
    SHUTDOWN_STATE_SHUTDOWN_REQUESTED,
    SHUTDOWN_STATE_SHUTDOWN_IN_PROGRESS,
} shutdown_state_t;

static inline const char * get_shutdown_state_string(shutdown_state_t state)
{
    const char * ret = NULL;

    switch (state) {
    case SHUTDOWN_STATE_UNINITIALIZED:
        ret = "SHUTDOWN_STATE_UNINITIALIZED";
        break;
    case SHUTDOWN_STATE_NONE:
        ret = "SHUTDOWN_STATE_NONE";
        break;
    case SHUTDOWN_STATE_SHUTDOWN_REQUESTED:
        ret = "SHUTDOWN_STATE_SHUTDOWN_REQUESTED";
        break;
    case SHUTDOWN_STATE_SHUTDOWN_IN_PROGRESS:
        ret = "SHUTDOWN_STATE_SHUTDOWN_IN_PROGRESS";
        break;
    default:
        ret = "unknown";
    }
    return ret;
}

/*
 * A unique identifier which each service instance is given by the Manager
 */
typedef uint64_t rna_service_key;

#define bswap_rna_service_key bswap_64

/** Command specifier. Each command structure has a unique type identified.
*/

typedef enum {
	META_DATA_QUERY=1,   /**< MD Query */
	META_DATA_RESPONSE,  /**< MD Query Response */
	CACHE_REGISTER,      /**< Cache Server registration with MD service */
	CACHE_REGISTER_RESP, /**< Cache Server registration response */
	CACHE_QUERY,         /**< Cache data query */
	CACHE_RESPONSE,      /**< Cache data query response */
	CACHE_RESPONSE_RESPONSE,
                         /**< MD's response to a CACHE_RESPONSE */
	CACHE_QUERY_REQ,     /**< Cache query request */
	CACHE_QUERY_REQ_RESPONSE,
                         /**< Cache query request response */
	CACHE_CHANGE_REF,    /**< Change reference on a cache entry */
	CACHE_INVD,          /**< Cache invalidate. (eviction) */
	CACHE_INVD_REP,      /**< Cache invalidate response */
	CACHE_LOCK_INVD,     /**< Cache lock invalidate */
	CACHE_LOCK_INVD_REP, /**< Cache lock invalidate response */
	CACHE_RSV_ACCESS_V18,/**< Cache SCSI Reservation access change */
	CACHE_RSV_ACCESS_RESP,/**< Cache SCSI Reservation access change response */
	CACHE_MASTER_INVD,   /**< Cache master block record invalidate (Invalidate full file) */
	CACHE_CFM_EVT,       /**< CFM Event */
	CACHE_REG_PATH,  /**< Register storage path state with MD */
    RESEND_REQ,  /**< Request to resend the specified message */
	CONF_MGR_CONF_GET,   /**< CFM configuration file request */
	CONF_MGR_CONF_RESPONSE, /**< CFM configuration file response */
	CONF_MGR_REGISTER,	 /**< CFM registration */
	CONF_MGR_REG_RESPONSE, /**< CFM registration response */
	CONF_MGR_QUERY_CACHE_DEVICE,  /**< CFM request registration of cache dev. */
	CONF_MGR_REG_CACHE,  /**< cache server register with CFM */
	CONF_MGR_REG_CACHE_RESPONSE,  /**< response to cache server registration */
	CONF_MGR_REG_CACHE_DEVICE,  /**< CS register cache device with CFM */
	CONF_MGR_REG_CACHE_DEVICE_END, /**< end of cache device registrations */
	CONF_MGR_DEREG_CACHE_DEVICE,  /**< CS deregister cache device with CFM */
	CONF_MGR_UPDATE_CACHE_DEVICE,  /**< CFM enable/update cache device */
	CONF_MGR_RESILVER_CACHE_DEVICE_COMPLETE,  /**< cache device's replica stores have been re-silvered */
	CONF_MGR_RESILVER_CACHE_DEVICE_COMPLETE_RESP,  /**< response to the above */
	CONF_MGR_EXPEL_CACHE_DEVICE,  /**< CFM expel cache device */
	CONF_MGR_DEREG_REPLICA_STORE,  /**< CFM deregister replica store */
	CONF_MGR_ABSORB_REPLICA_STORE, /**< CFM absorb replica store */
	CONF_MGR_DELETE_REPLICA_STORE, /**< CFM delete replica store */
	CONF_MGR_REG_MD,     /**< CFM register Metadata server */
	CONF_MGR_REG_MD_RESPONSE, /**< Response to CFM register Metadata server */
	CONF_MGR_UNEXPELLED_CACHEDEVS, /**< The set of unexpelled cache devices */
	CONF_MGR_CONN_REG,     /**< Register service connection with CFM */
	CONF_MGR_DISCONN_REG, /**< Register service disconnection with CFM */
	CONF_MGR_CONFIG,
	CONF_MGR_QUERY,
    CONF_MGR_QUERY_CACHED_LUN, /**  < CFM request registration of a path */
	CONF_MGR_REG_PATH,  /**< Register storage path state with CFM */
    /* Cached LUN snapshot */
    CONF_MGR_CACHED_LUN_WRITE_ALL_INITIATE,
    CONF_MGR_CACHED_LUN_WRITE_ALL_CONCLUDE,
    /* cache server shutdown request and response */
    CONF_MGR_CS_SHUTDOWN_REQ,
    CONF_MGR_CS_SHUTDOWN_RESP,
    /* VFS client */
	CONF_MGR_REG_CLIENT,
	CONF_MGR_REG_CLIENT_RESP,
	CONF_MGR_REG_CLIENT_MOUNT,
	CONF_MGR_DEREG_CLIENT_MOUNT,
	CONF_MGR_DEREG_CLIENT,
    /* Block client */
    CONF_MGR_BLOCK_DEVICE_CREATE,
	CONF_MGR_REG_BLOCK_DEVICE,
    CONF_MGR_REG_BLOCK_DEVICE_RESP,
	CONF_MGR_DEREG_BLOCK_DEVICE,
	CONF_MGR_MD_PARTITION_MAP,
	CONF_MGR_MD_REPORT,
	CONF_MGR_NOTIFICATION_EVENT,  /**< notification event from client */
	CONF_MGR_EVENT,
	CONF_MGR_EVENT_REG, /**< Event registration. (Recv log messages) */
	CONF_MGR_EVENT_DEREG, /**< Event de-registration. (no longer recv log messages) */
	CONF_MGR_CSTAT_REQ, /**< Cache stat request */
	CONF_MGR_CSTAT_RESP, /**< Cache stat response */
	CONF_MGR_CONTROL, /**< Control message from CFM */
	CONF_MGR_CONTROL_REJECT, /**< Rejection of control message from CFM */
    CONF_MGR_ACTIVE_CS_CACHE_DEVICES,
    CONF_MGR_CACHE_VIEW_STATUS,
    CONF_MGR_CACHE_VIEW_STATUS_REQ,
	AGENT_REGISTER,  /**< Agent registration */
	AGENT_REG_RESPONSE, /**< Agent registration response */
	AGENT_DISCONNECT, /**< Agent disconnect */
	AGENT_CMD, /**< Agent command to start / stop services */
	AGENT_QUERY,/**< Agent query (status) */
	RFT_PULL, /**< Remote file transfer pull */
	RFT_START, /**< Remote file transfer start */
	RFT_DATA, /**< Remote file transfer data message */
	RFT_DONE, /**< Remote file transfer Complete */
	RFT_ABORT, /**< Remote file transfer abort transfer */
	RFT_RESPONSE, /**< Remote file transfer general response */
	RFT_OPEN,/**< Remote file transfer open request */
	RFT_READ,/**< Remote file transfer read request */
	RFT_WRITE,/**< Remote file transfer write request */
	RFT_LSEEK,/**< Remote file transfer lseek request */
	RFT_FSTAT,/**< Remote file transfer fstat request */
	RFT_CLOSE,	/**< Remote file transfer close request */
	PING, /**< Ping */
	AGENT_TO_CFM_PING, /**< Ping sent by an agent to the primary CFM */
	MD_TO_CFM_PING, /**< Ping sent by an MD to the primary CFM */
	CS_TO_CFM_PING, /**< Ping sent by a CS to the primary CFM */
	FSCLIENT_TO_CFM_PING, /**< Ping sent by a filesystem client to the primary CFM */
    EMPTY_PING, /**< non-quorum ping sent to a non-primary CFM */
	RNA_ECHO, /**< Echo */
	MCP_CONTROL, /**< Master Control Message */
	MOUNT_BLOCKED,
	MOUNT_UNBLOCKED,
	CONF_MGR_BSTAT_REQ, /**< Block client stat request */
	CONF_MGR_BSTAT_RESP, /**< Block client stat response */
    META_DATA_SYNC_REQUEST, /**< MD requests sync of a metadata partition */
    META_DATA_SYNC_DATA, /**< MD hash table data sent by an MD */
    META_DATA_SYNC_DATA_END, /**< the end of a set of MD hash table data */
    CS_SYNC_DATA, /**< MD hash table data sent by a CS */
    CS_SYNC_DATA_END, /**< end of a set of MD hash table data sent by a CS */
    META_DATA_SYNC_DONE, /**< MD done syncing */
	MCP_URL_REQ,   /**< UI xml file request */
	MCP_URL_RESP,   /**< UI xml file response */
    CACHE_DEREF_REQUEST, /**< Used by cache servers to 'anonymously' request ref changes */
    CACHE_DEREF_REQUEST_RESP, /**< Notify CS that set of deref changes is complete */
    CACHE_CHANGE_REF_RESP, /**< Response to reference change request */
    CACHE_TRANS_REQ, /**< Request for client reference change */
    CONF_MGR_BLOCK_DEVICE_CONTROL, /**<Request from CFM to control block device */
    CONF_MGR_BLOCK_DEVICE_CONTROL_RESP, /**<Response from client to control block device request */
    CONF_MGR_CONTROL_CS, /**<Request from CFM to control cache server */
    CONF_MGR_CONTROL_CS_RESP, /**<Response from CS to CFM control request */
    CONF_MGR_SERVICE_DEREG, /**< CFM deregister overrides service registration */
	CACHE_WRITE_SAME,   /**< Handle SCSI WRITE_SAME command */
	CACHE_WRITE_SAME_RESP,   /**< Respond to client issuing SCSI WRITE_SAME command */
    CACHE_RELOCATE_BLOCK, /**< CS suggests relocation of cache block to MD */
    CACHE_ABSORB_BLOCK, /**< CS notification to MD that it's absorbing a block from a replica store */
    CACHE_ABSORB_BLOCK_RESP, /**< Response to the above message */
    CACHE_INVD_HOLD, /**< Cache invalidate. (stop short of eviction) */
    CACHE_INVD_HOLD_RESP, /**< Cache invalidate hold response. (stop short of eviction) */
    CACHE_COPY_DONE, /**< CS sends this to other CS after block copy is completed */
    CACHE_COMP_WR,      /**< SCSI COMPARE and WRITE command */
    CACHE_COMP_WR_RESP, /**< Respond to client's SCSI COMPARE and WRITE command */
    CONF_MGR_LOCAL_CS_REG, /* Tells client CS connection info for use in DAS mode */
    CACHE_DEREG_PATH,  /**< Deregister storage path state with MD */
    CONF_MGR_DEREG_PATH, /**< Deregister storage path state with CFM */
    CACHE_REPLICA_STORE_CREATE, /**< CS-to-CS msg requesting creation of replica store */
    CACHE_REPLICA_STORE_CREATE_RESP, /**< response to CACHE_REPLICA_STORE_CREATE */
    CACHE_REPLICA_STORE_REMOVE, /**< CS-to-CS msg requesting removal of replica store */
    CACHE_REPLICA_STORE_REMOVE_RESP, /**< response to CACHE_REPLICA_STORE_REMOVE */
    CACHE_FAIL_CACHE_DEVICE, /**< CS-to-Client/Client-to-CS msg reports bad cache-device */
    CACHE_FAIL_CACHE_DEVICE_RESP, /**< Client-to-CS response to to FAIL_CACHE_DEVICE msg */
    BLOCK_CLIENT_MOUNT_NOT_DONE, /* mount not attempted by block client udev */
    BLOCK_CLIENT_MOUNT_OK,       /* mount completed successfully by block client udev */
    BLOCK_CLIENT_MOUNT_FAILED,   /* attempted mount has failed by block client udev */
    AGENT_GET_SSD,  /**< Agent ssd list request */
    AGENT_GET_SSD_REP, /**< Agent ssd list response */
    CONF_MGR_PREPARE_DELETE_HCC, /**< Agent->CFM Prepare HCC Delete request */
    CONF_MGR_PREPARE_DELETE_HCC_RESP, /**< CFM->Agent Prepare HCC Delete response */
    CONF_MGR_JOURNAL_READ_REQ,  /**< CFM->CFM read remote journal block */
    CONF_MGR_JOURNAL_READ_RESP, /**< CFM->CFM response to remote journal block read */
    CONF_MGR_JOURNAL_WRITE_REQ, /**< CFM->CFM write remote journal block */
    CONF_MGR_JOURNAL_WRITE_RESP,/**< CFM->CFM response to remove journal block write */
    CACHE_SCSI_PASSTHRU, /**< Passthru SCSI */
    CACHE_SCSI_PASSTHRU_RESP, /**< Response to Passthru SCSI */
    CACHE_SCSI_UNITATTN, /**< CS-to-Client report async SCSI Unit Attention */ 
    CACHE_REG_PING, /**< ping registration request */
    CACHE_REG_PING_RESP, /**< ping registration response */
    CONF_MGR_JOURNAL_INIT_REQ,  /**< CFM->CFM Validate CFM journal data with other nodes (request)*/
    CONF_MGR_JOURNAL_INIT_RESP, /**< CFM->CFM Validate CFM journal data with other nodes (response)*/
    /* SCSI III reservation journaling */
    CONF_MGR_CS_UPDATE_SCSI_ITN_RES,
    CONF_MGR_CS_UPDATE_SCSI_ITN_REG,
    CONF_MGR_CS_CLEAR_SCSI_ITN_RES,
    CONF_MGR_CS_ACQUIRE_SCSI_ITN_RES,
    CONF_MGR_CS_ACQUIRE_SCSI_ITN_REG,
    CONF_MGR_CS_UPDATE_CLEAR_SCSI_ITN_RES_RESP,
    CONF_MGR_CS_ACQUIRE_SCSI_ITN_RES_RESP,
    CONF_MGR_CS_ACQUIRE_SCSI_ITN_REG_RESP,
    /* SCSI III reservation journaling ending */
    CONF_MGR_JOURNAL_JOIN_REQ,  /**< CFM->CFM add CFM journal mirror to primary cfm */
    AGENT_CANCEL_UPGRADE, /** CFM->AGENT cancel upgrade process */
    RFT_COPY,	/**< Remote file transfer copy request */

    CS_TO_CLIENT_PING, /**< used by CS to check if client connections are still alive */
    AGENT_JNL_RECV_MIRROR, /**< AGENT->CFM request a new control cmd to get journal mirror */
    MD_CLIENT_PING,    /**< ping between clients & MD's to make sure connection is alive */
    /* CFM shutdown request and response */
    CONF_MGR_CFM_SHUTDOWN_STATUS,
    CONF_MGR_CFM_SHUTDOWN_GRANT,
	CONF_MGR_REG_CACHE_RESPONSE_V2,  /**< V2 response to cache server registration */
	CACHE_RSV_ACCESS        /**< Cache SCSI Reservation access change */
} rna_cmd_type;

INLINE const char * get_cmd_type_string (rna_cmd_type type)
{
    const char * ret = NULL;

    switch (type) {
        case META_DATA_QUERY:
            ret = "META_DATA_QUERY";
            break;
        case META_DATA_RESPONSE:
            ret = "META_DATA_RESPONSE";
            break;
        case CACHE_REGISTER:
            ret = "CACHE_REGISTER";
            break;
        case CACHE_REGISTER_RESP:
            ret = "CACHE_REGISTER_RESP";
            break;
        case CACHE_QUERY:
            ret = "CACHE_QUERY";
            break;
        case CACHE_RESPONSE:
            ret = "CACHE_RESPONSE";
            break;
        case CACHE_RESPONSE_RESPONSE:
            ret = "CACHE_RESPONSE_RESPONSE";
            break;
        case CACHE_QUERY_REQ:
            ret = "CACHE_QUERY_REQ";
            break;
        case CACHE_QUERY_REQ_RESPONSE:
            ret = "CACHE_QUERY_REQ_RESPONSE";
            break;
        case CACHE_CHANGE_REF:
            ret = "CACHE_CHANGE_REF";
            break;
        case CACHE_INVD:
            ret = "CACHE_INVD";
            break;
        case CACHE_INVD_REP:
            ret = "CACHE_INVD_REP";
            break;
        case CACHE_INVD_HOLD:
            ret = "CACHE_INVD_HOLD";
            break;
        case CACHE_INVD_HOLD_RESP:
            ret = "CACHE_INVD_HOLD_RESP";
            break;
        case CACHE_LOCK_INVD:
            ret = "CACHE_LOCK_INVD";
            break;
        case CACHE_LOCK_INVD_REP:
            ret = "CACHE_LOCK_INVD_REP";
            break;
        case CACHE_RSV_ACCESS:
            ret = "CACHE_RSV_ACCESS";
            break;
        case CACHE_RSV_ACCESS_V18:
            ret = "CACHE_RSV_ACCESS_V18";
            break;
        case CACHE_RSV_ACCESS_RESP:
            ret = "CACHE_RSV_ACCESS_RESP";
            break;
        case CACHE_MASTER_INVD:
            ret = "CACHE_MASTER_INVD";
            break;
        case CACHE_CFM_EVT:
            ret = "CACHE_CFM_EVT";
            break;
	    case CACHE_REG_PATH:
	        ret = "CACHE_REG_PATH";
	        break;
	    case CACHE_DEREG_PATH:
	        ret = "CACHE_DEREG_PATH";
	        break;
        case CACHE_RELOCATE_BLOCK:
            ret = "CACHE_RELOCATE_BLOCK";
            break;
        case CACHE_ABSORB_BLOCK:
            ret = "CACHE_ABSORB_BLOCK";
            break;
        case CACHE_ABSORB_BLOCK_RESP:
            ret = "CACHE_ABSORB_BLOCK_RESP";
            break;
        case RESEND_REQ:
            ret = "RESEND_REQ";
            break;
        case CONF_MGR_CONF_GET:
            ret = "CONF_MGR_CONF_GET";
            break;
        case CONF_MGR_CONF_RESPONSE:
            ret = "CONF_MGR_CONF_RESPONSE";
            break;
        case CONF_MGR_REGISTER:
            ret = "CONF_MGR_REGISTER";
            break;
        case CONF_MGR_REG_RESPONSE:
            ret = "CONF_MGR_REG_RESPONSE";
            break;
        case CONF_MGR_REG_CACHE:
            ret = "CONF_MGR_REG_CACHE";
            break;
        case CONF_MGR_REG_CACHE_RESPONSE:
            ret = "CONF_MGR_REG_CACHE_RESPONSE";
            break;
        case CONF_MGR_REG_CACHE_RESPONSE_V2:
            ret = "CONF_MGR_REG_CACHE_RESPONSE_V2";
            break;
        case CONF_MGR_REG_CACHE_DEVICE:
            ret = "CONF_MGR_REG_CACHE_DEVICE";
            break;
        case CONF_MGR_REG_CACHE_DEVICE_END:
            ret = "CONF_MGR_REG_CACHE_DEVICE_END";
            break;
        case CONF_MGR_DEREG_CACHE_DEVICE:
            ret = "CONF_MGR_DEREG_CACHE_DEVICE";
            break;
        case CONF_MGR_UPDATE_CACHE_DEVICE:
            ret = "CONF_MGR_UPDATE_CACHE_DEVICE";
            break;
        case CONF_MGR_RESILVER_CACHE_DEVICE_COMPLETE:
            ret = "CONF_MGR_RESILVER_CACHE_DEVICE_COMPLETE";
            break;
        case CONF_MGR_RESILVER_CACHE_DEVICE_COMPLETE_RESP:
            ret = "CONF_MGR_RESILVER_CACHE_DEVICE_COMPLETE_RESP";
            break;
        case CONF_MGR_NOTIFICATION_EVENT:
            ret = "CONF_MGR_NOTIFICATION_EVENT";
            break;
        case CONF_MGR_QUERY_CACHE_DEVICE:
            ret = "CONF_MGR_QUERY_CACHE_DEVICE";
            break;
        case CONF_MGR_EXPEL_CACHE_DEVICE:
            ret = "CONF_MGR_EXPEL_CACHE_DEVICE";
            break;
        case CONF_MGR_DEREG_REPLICA_STORE:
            ret = "CONF_MGR_DEREG_REPLICA_STORE";
            break;
        case CONF_MGR_ABSORB_REPLICA_STORE:
            ret = "CONF_MGR_ABSORB_REPLICA_STORE";
            break;
        case CONF_MGR_DELETE_REPLICA_STORE:
            ret = "CONF_MGR_DELETE_REPLICA_STORE";
            break;
        case CONF_MGR_REG_MD:
            ret = "CONF_MGR_REG_MD";
            break;
        case CONF_MGR_REG_MD_RESPONSE:
            ret = "CONF_MGR_REG_MD_RESPONSE";
            break;
        case CONF_MGR_CONN_REG:
            ret = "CONF_MGR_CONN_REG";
            break;
        case CONF_MGR_DISCONN_REG:
            ret = "CONF_MGR_DISCONN_REG";
            break;
        case CONF_MGR_CONFIG:
            ret = "CONF_MGR_CONFIG";
            break;
        case CONF_MGR_QUERY:
            ret = "CONF_MGR_QUERY";
            break;
        case CONF_MGR_REG_CLIENT:
            ret = "CONF_MGR_REG_CLIENT";
            break;
        case CONF_MGR_QUERY_CACHED_LUN:
            ret = "CONF_MGR_QUERY_CACHED_LUN";
            break;
	    case CONF_MGR_REG_PATH:
	        ret = "CONF_MGR_REG_PATH";
	        break;
	    case CONF_MGR_DEREG_PATH:
	        ret = "CONF_MGR_DEREG_PATH";
	        break;
        case CONF_MGR_CACHED_LUN_WRITE_ALL_INITIATE:
            ret = "CONF_MGR_CACHED_LUN_WRITE_ALL_INITIATE";
            break;
        case CONF_MGR_CACHED_LUN_WRITE_ALL_CONCLUDE:
            ret = "CONF_MGR_CACHED_LUN_WRITE_ALL_CONCLUDE";
            break;
        case CONF_MGR_CS_SHUTDOWN_REQ:
            ret = "CONF_MGR_CS_SHUTDOWN_REQ";
            break;
        case CONF_MGR_CS_SHUTDOWN_RESP:
            ret = "CONF_MGR_CS_SHUTDOWN_RESP";
            break;
        case CONF_MGR_REG_CLIENT_MOUNT:
            ret = "CONF_MGR_REG_CLIENT_MOUNT";
            break;
        case CONF_MGR_DEREG_CLIENT_MOUNT:
            ret = "CONF_MGR_DEREG_CLIENT_MOUNT";
            break;
        case CONF_MGR_DEREG_CLIENT:
            ret = "CONF_MGR_DEREG_CLIENT";
            break;
        case CONF_MGR_BLOCK_DEVICE_CREATE:
            ret = "CONF_MGR_BLOCK_DEVICE_CREATE";
            break;
        case CONF_MGR_BLOCK_DEVICE_CONTROL:
            ret = "CONF_MGR_BLOCK_DEVICE_CONTROL";
            break;
        case CONF_MGR_BLOCK_DEVICE_CONTROL_RESP:
            ret = "CONF_MGR_BLOCK_DEVICE_CONTROL_RESP";
            break;
        case CONF_MGR_REG_BLOCK_DEVICE:
            ret = "CONF_MGR_REG_BLOCK_DEVICE";
            break;
        case CONF_MGR_REG_BLOCK_DEVICE_RESP:
            ret = "CONF_MGR_REG_BLOCK_DEVICE_RESP";
            break;
        case CONF_MGR_DEREG_BLOCK_DEVICE:
            ret = "CONF_MGR_DEREG_BLOCK_DEVICE";
            break;
        case CONF_MGR_MD_PARTITION_MAP:
            ret = "CONF_MGR_MD_PARTITION_MAP";
            break;
        case CONF_MGR_MD_REPORT:
            ret = "CONF_MGR_MD_REPORT";
            break;
        case CONF_MGR_CONTROL_CS:
            ret = "CONF_MGR_CONTROL_CS";
            break;
        case CONF_MGR_CONTROL_CS_RESP:
            ret = "CONF_MGR_CONTROL_CS_RESP";
            break;
        case CONF_MGR_EVENT:
            ret = "CONF_MGR_EVENT";
            break;
        case CONF_MGR_EVENT_REG:
            ret = "CONF_MGR_EVENT_REG";
            break;
        case CONF_MGR_EVENT_DEREG:
            ret = "CONF_MGR_EVENT_DEREG";
            break;
        case CONF_MGR_CSTAT_REQ:
            ret = "CONF_MGR_CSTAT_REQ";
            break;
        case CONF_MGR_CSTAT_RESP:
            ret = "CONF_MGR_CSTAT_RESP";
            break;
        case CONF_MGR_BSTAT_REQ:
            ret = "CONF_MGR_BSTAT_REQ";
            break;
        case CONF_MGR_BSTAT_RESP:
            ret = "CONF_MGR_BSTAT_RESP";
            break;
        case CONF_MGR_CONTROL:
            ret = "CONF_MGR_CONTROL";
            break;
        case CONF_MGR_CONTROL_REJECT:
            ret = "CONF_MGR_CONTROL_REJECT";
            break;
        case CONF_MGR_ACTIVE_CS_CACHE_DEVICES:
            ret = "CONF_MGR_ACTIVE_CS_CACHE_DEVICES";
            break;
        case CONF_MGR_CACHE_VIEW_STATUS:
            ret = "CONF_MGR_CACHE_VIEW_STATUS";
            break;
        case CONF_MGR_CACHE_VIEW_STATUS_REQ:
            ret = "CONF_MGR_CACHE_VIEW_STATUS_REQ";
            break;
        case AGENT_REGISTER:
            ret = "AGENT_REGISTER";
            break;
        case AGENT_REG_RESPONSE:
            ret = "AGENT_REG_RESPONSE";
            break;
        case AGENT_DISCONNECT:
            ret = "AGENT_DISCONNECT";
            break;
        case AGENT_CMD:
            ret = "AGENT_CMD";
            break;
        case AGENT_QUERY:
            ret = "AGENT_QUERY";
            break;
        case RFT_PULL:
            ret = "RFT_PULL";
            break;
        case RFT_START:
            ret = "RFT_START";
            break;
        case RFT_DATA:
            ret = "RFT_DATA";
            break;
        case RFT_DONE:
            ret = "RFT_DONE";
            break;
        case RFT_ABORT:
            ret = "RFT_ABORT";
            break;
        case RFT_RESPONSE:
            ret = "RFT_RESPONSE";
            break;
        case RFT_OPEN:
            ret = "RFT_OPEN";
            break;
        case RFT_READ:
            ret = "RFT_READ";
            break;
        case RFT_WRITE:
            ret = "RFT_WRITE";
            break;
        case RFT_LSEEK:
            ret = "RFT_LSEEK";
            break;
        case RFT_FSTAT:
            ret = "RFT_FSTAT";
            break;
        case RFT_CLOSE:
            ret = "RFT_CLOSE";
            break;
        case PING:
            ret = "PING";
            break;
        case AGENT_TO_CFM_PING:
            ret = "AGENT_TO_CFM_PING";
            break;
        case MD_TO_CFM_PING:
            ret = "MD_TO_CFM_PING";
            break;
        case CS_TO_CFM_PING:
            ret = "CS_TO_CFM_PING";
            break;
        case FSCLIENT_TO_CFM_PING:
            ret = "FSCLIENT_TO_CFM_PING";
            break;
        case EMPTY_PING:
            ret = "EMPTY_PING";
            break;
        case RNA_ECHO:
            ret = "ECHO";
            break;
        case MCP_CONTROL:
            ret = "MCP_CONTROL";
            break;
        case MOUNT_BLOCKED:
            ret = "MOUNT_BLOCKED";
            break;
        case MOUNT_UNBLOCKED:
            ret = "MOUNT_UNBLOCKED";
            break;
        case META_DATA_SYNC_DATA:
            ret = "META_DATA_SYNC_DATA";
            break;
        case META_DATA_SYNC_DATA_END:
            ret = "META_DATA_SYNC_DATA_END";
            break;
        case CS_SYNC_DATA:
            ret = "CS_SYNC_DATA";
            break;
        case CS_SYNC_DATA_END:
            ret = "CS_SYNC_DATA_END";
            break;
        case META_DATA_SYNC_REQUEST:
            ret = "META_DATA_SYNC_REQUEST";
            break;
        case META_DATA_SYNC_DONE:
            ret = "META_DATA_SYNC_DONE";
            break;
        case MCP_URL_REQ:
            ret = "MCP_URL_REQ";
            break;
        case MCP_URL_RESP:
            ret = "MCP_URL_RESP";
            break;
        case CACHE_DEREF_REQUEST:
            ret = "CACHE_DEREF_REQUEST";
            break;
        case CACHE_DEREF_REQUEST_RESP:
            ret = "CACHE_DEREF_REQUEST_RESP";
            break;
        case CACHE_CHANGE_REF_RESP:
            ret = "CACHE_CHANGE_REF_RESP";
            break;
        case CACHE_TRANS_REQ:
            ret = "CACHE_TRANS_REQ";
            break;
        case CONF_MGR_SERVICE_DEREG:
            ret = "CONF_MGR_SERVICE_DEREG";
            break;
        case CACHE_WRITE_SAME:
            ret = "CACHE_WRITE_SAME";
            break;
        case CACHE_WRITE_SAME_RESP:
            ret = "CACHE_WRITE_SAME_RESP";
            break;
        case CACHE_COPY_DONE:
            ret = "CACHE_COPY_DONE";
            break;
        case CACHE_COMP_WR:
            ret = "CACHE_COMP_WR";
            break;
        case CACHE_COMP_WR_RESP:
            ret = "CACHE_COMP_WR_RESP";
            break;
        case CONF_MGR_LOCAL_CS_REG:
            ret = "CONF_MGR_LOCAL_CS_REG";
            break;
        case CACHE_REPLICA_STORE_CREATE:
            ret = "CACHE_REPLICA_STORE_CREATE";
            break;
        case CACHE_REPLICA_STORE_CREATE_RESP:
            ret = "CACHE_REPLICA_STORE_CREATE_RESP";
            break;
        case CACHE_REPLICA_STORE_REMOVE:
            ret = "CACHE_REPLICA_STORE_REMOVE";
            break;
        case CACHE_REPLICA_STORE_REMOVE_RESP:
            ret = "CACHE_REPLICA_STORE_REMOVE_RESP";
            break;
        case CACHE_FAIL_CACHE_DEVICE:
            ret = "CACHE_FAIL_CACHE_DEVICE";
            break;
        case CACHE_FAIL_CACHE_DEVICE_RESP:
            ret = "CACHE_FAIL_CACHE_DEVICE_RESP";
            break;
        case CACHE_SCSI_PASSTHRU:
            ret = "CACHE_SCSI_PASSTHRU";
            break;
        case CACHE_SCSI_PASSTHRU_RESP:
            ret = "CACHE_SCSI_PASSTHRU_RESP";
            break;
        case CACHE_SCSI_UNITATTN:
            ret = "CACHE_SCSI_UNITATTN";
            break;
        case CACHE_REG_PING:
            ret = "CACHE_REG_PING";
            break;
        case CACHE_REG_PING_RESP:
            ret = "CACHE_REG_PING_RESP";
            break;
        case CONF_MGR_REG_CLIENT_RESP:
            ret = "CONF_MGR_REG_CLIENT_RESP";
            break;
        case BLOCK_CLIENT_MOUNT_NOT_DONE:
            ret = "MOUNT_NOT_DONE";
            break;
        case BLOCK_CLIENT_MOUNT_OK:
            ret = "MOUNT_OK";
            break;
        case BLOCK_CLIENT_MOUNT_FAILED:
            ret = "MOUNT_FAILED";
            break;
        case AGENT_GET_SSD:
            ret = "AGENT_GET_SSD";
            break;
        case AGENT_GET_SSD_REP:
            ret = "AGENT_GET_SSD_REP";
            break;
        case CONF_MGR_PREPARE_DELETE_HCC:
            ret = "CONF_MGR_PREPARE_DELETE_HCC";
            break;
        case CONF_MGR_PREPARE_DELETE_HCC_RESP:
            ret = "CONF_MGR_PREPARE_DELETE_HCC_RESP";
            break;
        case CONF_MGR_JOURNAL_READ_REQ:
            ret = "CONF_MGR_JOURNAL_READ_REQ";
            break;
        case CONF_MGR_JOURNAL_READ_RESP:
            ret = "CONF_MGR_JOURNAL_READ_RESP";
            break;
        case CONF_MGR_JOURNAL_WRITE_REQ:
            ret = "CONF_MGR_JOURNAL_WRITE_REQ";
            break;
        case CONF_MGR_JOURNAL_WRITE_RESP:
            ret = "CONF_MGR_JOURNAL_WRITE_RESP";
            break;
        case CONF_MGR_JOURNAL_INIT_REQ:
            ret = "CONF_MGR_JOURNAL_INIT_REQ";
            break;
        case CONF_MGR_JOURNAL_INIT_RESP:
            ret = "CONF_MGR_JOURNAL_INIT_RESP";
            break;
        case CONF_MGR_JOURNAL_JOIN_REQ:
            ret = "CONF_MGR_JOURNAL_JOIN_REQ";
            break;
        /* SCSI III reservation journaling */
        case CONF_MGR_CS_UPDATE_SCSI_ITN_RES:
            ret = "CONF_MGR_CS_UPDATE_SCSI_ITN_RES";
            break;
        case CONF_MGR_CS_UPDATE_SCSI_ITN_REG:
            ret = "CONF_MGR_CS_UPDATE_SCSI_ITN_REG";
            break;
        case CONF_MGR_CS_CLEAR_SCSI_ITN_RES:
            ret = "CONF_MGR_CS_CLEAR_SCSI_ITN_RES";
            break;
        case CONF_MGR_CS_ACQUIRE_SCSI_ITN_RES:
            ret = "CONF_MGR_CS_ACQUIRE_SCSI_ITN_RES";
            break;
        case CONF_MGR_CS_ACQUIRE_SCSI_ITN_REG:
            ret = "CONF_MGR_CS_ACQUIRE_SCSI_ITN_REG";
            break;
        case CONF_MGR_CS_UPDATE_CLEAR_SCSI_ITN_RES_RESP:
            ret = "CONF_MGR_CS_UPDATE_CLEAR_SCSI_ITN_RES_RESP";
            break;
        case CONF_MGR_CS_ACQUIRE_SCSI_ITN_RES_RESP:
            ret = "CONF_MGR_CS_ACQUIRE_SCSI_ITN_RES_RESP";
            break;
        case CONF_MGR_CS_ACQUIRE_SCSI_ITN_REG_RESP:
            ret = "CONF_MGR_CS_ACQUIRE_SCSI_ITN_REG_RESP";
            break;
        case AGENT_CANCEL_UPGRADE:
            ret = "AGENT_CANCEL_UPGRADE";
            break;
        case AGENT_JNL_RECV_MIRROR:
            ret = "AGENT_JNL_RECV_MIRROR";
            break;
        case RFT_COPY:
            ret = "RFT_COPY";
            break;
        case CS_TO_CLIENT_PING:
            ret = "CS_TO_CLIENT_PING";
            break;
        case MD_CLIENT_PING:
            ret = "MD_CLIENT_PING";
            break;
        case CONF_MGR_CFM_SHUTDOWN_STATUS:
            ret = "CONF_MGR_CFM_SHUTDOWN_STATUS";
            break;
        case CONF_MGR_CFM_SHUTDOWN_GRANT:
            ret = "CONF_MGR_CFM_SHUTDOWN_GRANT";
            break;
        default:
            ret = "CONF_MGR_UNKNOWN";
            break;
    }
    return ret;
}

/** Client type identifier.  Used for USR_TYPE_CFM_CLIENT connections to select
 * client type specific behavior (e.g. sending block device create commands).
 *
 * NOTE that if this enum changes, the equivalent enum in rna_service.h must
 * also be changed.
*/
typedef enum {
    CLIENT_TYPE_FILE=0,     /* VFS and other legacy clients */
    CLIENT_TYPE_BLOCK,      /* Block device client */
} client_type;

INLINE const char * get_client_type_string (client_type type)
{
    const char * ret = "UNKNOWN";

	switch(type){
    case CLIENT_TYPE_FILE:
        ret = "file";
        break;
    case CLIENT_TYPE_BLOCK:
        ret = "block";
        break;
	}
	return ret;
}

/** MD Request Type Identifier.
Indicates to the MD service what type of Metadata is being requested.
*/
enum md_req_type{	
	MD_REQ_TYPE_MASTER_REG = 0, /**< Master Meta Data Record */
	MD_REQ_TYPE_MASTER_DEREG,
	MD_REQ_TYPE_BLOCK_REQ,
	MD_REQ_TYPE_USER
};

/** Interface Type
Used when establishing a connection to force a particular transport or to report what transport is being used
*/
typedef enum {
	RNA_IF_TYPE_UNKNOWN,
	RNA_IF_TYPE_IB,
	RNA_IF_TYPE_ETH,
	RNA_IF_TYPE_IWARP
} rna_if_type;

INLINE const char * rna_if_type_string (rna_if_type type)
{
    const char * ret = "RNA_IF_TYPE_UNKNOWN";

    switch (type) {
        case RNA_IF_TYPE_UNKNOWN: ret = "RNA_IF_TYPE_UNKNOWN"; break;
        case RNA_IF_TYPE_IB: ret = "RNA_IF_TYPE_IB"; break;
        case RNA_IF_TYPE_ETH: ret = "RNA_IF_TYPE_ETH"; break;
        case RNA_IF_TYPE_IWARP: ret = "RNA_IF_TYPE_IWARP"; break;
    }
    return ret;
}

/** Interface Status
Common status codes for the rna_if_type
*/
typedef enum {
	RNA_IF_STATUS_UNKNOWN,
	RNA_IF_STATUS_UP,
	RNA_IF_STATUS_DOWN
} rna_if_status;

INLINE const char * rna_if_status_string (rna_if_status status)
{
    const char * ret = "RNA_IF_STATUS_UNKNOWN";

    switch (status) {
        case RNA_IF_STATUS_UNKNOWN: ret = "RNA_IF_STATUS_UNKNOWN"; break;
        case RNA_IF_STATUS_UP: ret = "RNA_IF_STATUS_UP"; break;
        case RNA_IF_STATUS_DOWN: ret = "RNA_IF_STATUS_DOWN"; break;
    }
    return ret;
}

/** Cache evict cause
Indicates reason a cache block was evicted
*/
enum cache_evict_cause {
    CACHE_EVICT_CAUSE_NOT_SPECIFIED = 0,    /**< Cause not specified, or not an eviction */
    CACHE_EVICT_CAUSE_MASTER_INVALIDATE,    /**< Evicted because of master invalidate */
    CACHE_EVICT_CAUSE_WRITE_LOCK,           /**< Evicted because a write lock was granted */
    CACHE_EVICT_CAUSE_PROACTIVE_EVICTION,   /**< Evicted proactively */
    CACHE_EVICT_CAUSE_FILE_MODIFIED,        /**< Evicted because CS detected the file changed */
    CACHE_EVICT_CAUSE_ENTRY_STALE,          /**< Evicted because client detected the file changed */
    CACHE_EVICT_CAUSE_CLIENT_ERROR,         /**< Evicted because client encountered an error */
    CACHE_EVICT_CAUSE_CS_DISCONNECT,        /**< Evicted because a CS disconnected from the MD */
    CACHE_EVICT_CAUSE_MD_ERROR,             /**< Evicted because MD encountered an error */
    CACHE_EVICT_CAUSE_USER,                 /**< Evicted by specific user action */
};

INLINE const char * get_cache_evict_cause_string (enum cache_evict_cause cause)
{
    const char * ret = "Unknown";
    switch (cause) {
    case CACHE_EVICT_CAUSE_NOT_SPECIFIED:       ret = "CACHE_EVICT_CAUSE_NOT_SPECIFIED"; break;
    case CACHE_EVICT_CAUSE_MASTER_INVALIDATE:   ret = "CACHE_EVICT_CAUSE_MASTER_INVALIDATE"; break;
    case CACHE_EVICT_CAUSE_WRITE_LOCK:          ret = "CACHE_EVICT_CAUSE_WRITE_LOCK"; break;
    case CACHE_EVICT_CAUSE_PROACTIVE_EVICTION:  ret = "CACHE_EVICT_CAUSE_PROACTIVE_EVICTION"; break;
    case CACHE_EVICT_CAUSE_FILE_MODIFIED:       ret = "CACHE_EVICT_CAUSE_FILE_MODIFIED"; break;
    case CACHE_EVICT_CAUSE_ENTRY_STALE:         ret = "CACHE_EVICT_CAUSE_ENTRY_STALE"; break;
    case CACHE_EVICT_CAUSE_CLIENT_ERROR:        ret = "CACHE_EVICT_CAUSE_CLIENT_ERROR"; break;
    case CACHE_EVICT_CAUSE_CS_DISCONNECT:       ret = "CACHE_EVICT_CAUSE_CS_DISCONNECT"; break;
    case CACHE_EVICT_CAUSE_MD_ERROR:            ret = "CACHE_EVICT_CAUSE_MD_ERROR"; break;
    case CACHE_EVICT_CAUSE_USER:                ret = "CACHE_EVICT_CAUSE_USER"; break;
    }
    return ret;
}

/** Cache Response Code
Status code used in response to cache query requests
*/
typedef enum {
	CACHE_RESP_CODE_OK = 0,
	CACHE_RESP_CODE_LOCKED,
	CACHE_RESP_CODE_NOFILE,
	CACHE_RESP_CODE_FILE_ERROR,
	CACHE_RESP_CODE_NOSPACE,
	CACHE_RESP_CODE_BADLOCK, /**< client request bad lock transition */
	CACHE_RESP_CODE_EAGAIN, /**< client needs to resend query to MD */
	CACHE_RESP_CODE_EINVAL, /**< request was invalid */
	CACHE_RESP_CODE_OFFLINE, /**< CS is going offline */
	CACHE_RESP_CODE_RELOCATE, /**< CS is relocating block */
    CACHE_RESP_CODE_CACHEDEV_ERROR, /**< Cache Device I/O error */
    CACHE_RESP_CODE_STORAGE_ERROR, /**< Storage Device I/O error */
} cache_resp_code;

#define get_cache_resp_code get_cache_resp_code_string
INLINE const char * get_cache_resp_code_string(cache_resp_code code)
{
    const char * ret = "Unknown";
    switch (code) {
        case CACHE_RESP_CODE_OK: ret = "CACHE_RESP_CODE_OK"; break;
        case CACHE_RESP_CODE_LOCKED: ret = "CACHE_RESP_CODE_LOCKED"; break;
        case CACHE_RESP_CODE_NOFILE: ret = "CACHE_RESP_CODE_NOFILE"; break;
        case CACHE_RESP_CODE_FILE_ERROR: ret = "CACHE_RESP_CODE_FILE_ERROR"; break;
        case CACHE_RESP_CODE_NOSPACE: ret = "CACHE_RESP_CODE_NOSPACE"; break;
        case CACHE_RESP_CODE_BADLOCK: ret = "CACHE_RESP_CODE_BADLOCK"; break;
        case CACHE_RESP_CODE_EAGAIN: ret = "CACHE_RESP_CODE_EAGAIN"; break;
        case CACHE_RESP_CODE_EINVAL: ret = "CACHE_RESP_CODE_EINVAL"; break;
        case CACHE_RESP_CODE_OFFLINE: ret = "CACHE_RESP_CODE_OFFLINE"; break;
        case CACHE_RESP_CODE_RELOCATE: ret = "CACHE_RESP_CODE_RELOCATE"; break;
        case CACHE_RESP_CODE_CACHEDEV_ERROR: ret = "CACHE_RESP_CODE_CACHEDEV_ERROR"; break;
        case CACHE_RESP_CODE_STORAGE_ERROR: ret = "CACHE_RESP_CODE_STORAGE_ERROR"; break;
    }
    return ret;
}

/** Cache State Query Type Codes
Used to query specific aspects of a cache block.
*/
enum cache_state_query_type{
	CACHE_STATE_QUERY_OFFSET=1 /**< Get the current storage offset for pub/sub type blocks */
};

/** Request action type
Indicates the action type of the request
*/
enum req_crud {
	REQ_CREATE = 1,
	REQ_READ,
	REQ_UPDATE,
	REQ_DELETE,
};

INLINE const char * get_req_crud_string (enum req_crud req)
{
    const char * ret = "Unknown";
    switch (req) {
        case REQ_CREATE: ret = "Request Create"; break;
        case REQ_READ: ret = "Request Read"; break;
        case REQ_UPDATE: ret = "Request Update"; break;
        case REQ_DELETE: ret = "Request Delete"; break;
    }
    return ret;
}

/** 
 * \fn INLINE void bswap_rna_if_info(struct rna_if_info *data)
 * \brief Byteswap  struct rna_if_info
 * @param data an integer argument.
 * \warning Use only if explicitly handling byteswap routines, otherwise use the high level message byteswap routines
*/
INLINE void bswap_rna_if_info(struct rna_if_info *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->addr = bswap_32(data->addr);
	data->port = bswap_16(data->port);
	//uint8_t type;
	//uint8_t status;
	data->rank = bswap_32(data->rank);
	//char name[RNA_IF_NAME_LEN];
#endif
}


/** RNA abstraction for memory registration info
Required fields to initiate RDMA reads/writes
*/
struct mem_reg_info{
	rna_addr_t buf;    /**< local memory address that is being made accessible */
	rna_rkey_t rkey;   /**< RDMA RKEY associated with buf */
	uint32_t length; /**< Length of buffer */
};

INLINE void bswap_mem_reg_info(struct mem_reg_info *data)
{
    UNREFERENCED_PARAMETER(data);		
#if CPU_BE
	bswap_rna_addr_t(&data->buf);
	bswap_rna_rkey_t(&data->rkey);
	data->length = bswap_32(data->length);
#endif
}

/** Register for events
 * Registration for events such as notifications, errors, warnings, configuration changes etc.
 * To deregister for events simply register with the event_mast of 0.
 * The cookie should be unique per ep.
 *
 * Since this message is also the response from registration with the CFM certain values that are
 * of interest to a newly started MD are returned as well.
 */
DECLARE_PACKED_STRUCT(rna_event_reg) {
	uint64_t cookie;     /**< Response cookie to associate registration with a local object. */
	uint64_t key;        /**< Secret key to register */
	uint32_t event_mask; /**< Event types to register for. */
	uint32_t num_cache_svrs;        /**< number of cache servers to expect registration from */
} END_PACKED_STRUCT(rna_event_reg) ;

INLINE void bswap_rna_event_reg(struct rna_event_reg *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->cookie = bswap_64(data->cookie);
	data->key = bswap_64(data->key);
	data->event_mask = bswap_32(data->event_mask);
	data->num_cache_svrs = bswap_32(data->num_cache_svrs);
#endif
}

DECLARE_PACKED_STRUCT(rna_event) {
    rna_service_event_msg_t rnas;
} END_PACKED_STRUCT(rna_event);

INLINE void bswap_rna_event(struct rna_event *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    bswap_rna_service_event_msg_t(&data->rnas);
#endif
}



/** request to meta data for a file 
*/
DECLARE_PACKED_STRUCT(md_req) {
    uint64_t        req_msg_id; /**< requester's message ID, which is returned
                                 *   unchanged by the metadata server
                                 */
    uint64_t        req_gen;    /**< generation number of requester's
                                 *   cfm_md_partition_map
                                 */
    rna_hash_key_t  path_key;   /**< Path key (MD5 of the pathname). 24 bytes */
    uint8_t         path_key_valid;
                                /**< Indicates the path key has already been
                                 *   computed and is present (path_key above) */
    uint8_t         pad[7];     /**< For future use (and for 64-bit alignment)*/
    /*
     * =====================================================================
     * NOTE that new fields for this struct should either be added to the
     * rna_service_metadata_query_t (in rna_service.h) or should be added
     * above this point.  Fields should be added in such a way that alignment
     * is maintained for 32-bit and 64-bit fields.
     * =====================================================================
     */
    rna_service_metadata_query_t
                    rnas;       /**< (variable-size struct) */
    /*
     * Since the above struct ends with a variable-length pathname, the purpose
     * of the following field is to pad this struct out to its maximum possible
     * size, so sizeof(struct cache_cmd) returns the maximum size of any
     * cache_cmd.
     */
    char            __pathname_pad[PATHNAME_LEN-1];
} END_PACKED_STRUCT(md_req);

INLINE void bswap_md_req(struct md_req *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->req_msg_id = bswap_64(data->req_msg_id);
	data->req_gen = bswap_64(data->req_gen);
	bswap_rna_hash_key_t(&data->path_key);
    bswap_rna_service_metadata_query_t(&data->rnas);
#endif
}

INLINE void bswap_rna_if_table(struct rna_if_table *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    data->table_entries = bswap_32(data->table_entries);
	for(i=0;i<data->table_entries;i++){
		bswap_rna_if_info(&data->ifs[i]);
	}
#endif
}

INLINE void bswap_rna_addr_t(rna_addr_t *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->device_id = bswap_64(data->device_id);
	data->base_addr = bswap_64(data->base_addr);
#endif
}

INLINE void bswap_rna_rkey_t(rna_rkey_t *addr)
{
    UNREFERENCED_PARAMETER(addr);	
#if CPU_BE
	*data = bswap_64(*addr);
#endif
}

/** meta data server response
 */
DECLARE_PACKED_STRUCT(md_rep) {
	uint64_t req_msg_id;		   /**< Requester's message ID, which is
									*   ignored and returned unchanged by the
									*   metadata server
									*/
    /*
     * =====================================================================
     * NOTE that new fields for this struct should either be added to the
     * rna_service_metadata_query_response_t (rna_service.h) or should be added
     * above this point.  Fields should be added in such a way that alignment
     * is maintained for 32-bit and 64-bit fields.
     * =====================================================================
     */
    rna_service_metadata_query_response_t
            rnas;
} END_PACKED_STRUCT(md_rep);

INLINE void bswap_sockaddr_in(struct sockaddr_in *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->sin_port = bswap_16(data->sin_port);
	//data->sin_addr.s_addr = bswap_32(data->sin_addr.s_addr);
#endif
}

INLINE void bswap_md_rep(struct md_rep *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->req_msg_id = bswap_64(data->req_msg_id);
    bswap_rna_service_metadata_response_t(&data->rnas);
#endif
}


/*
 * Used in struct cfm_md_active_cs_cache_devices to provide information about
 * an active cache device.
 */
DECLARE_PACKED_STRUCT(md_cachedev_info) {
    union {
        cachedev_id_t           acd_rna_id;
        cachedev_id_internal_t  acd_rna_internal_id;
    };
    uint64_t                acd_size_bytes;
    cachedev_physical_id_t  acd_physical_id;
} END_PACKED_STRUCT(md_cachedev_info);

INLINE void
bswap_md_cachedev_info(struct md_cachedev_info *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    data->msd_file_size = bswap_64(data->acd_rna_id);
    data->msd_file_size = bswap_64(data->acd_size_bytes);
#endif
}

/*
 * A flag for the acd_flags field to indicate that the specified cache server
 * is in the process of shutting down, so should not be assigned any blocks.
 */
#define ACD_FLAGS_SHUTTING_DOWN         0x1

/*
 * A CONF_MGR_ACTIVE_CS_CACHE_DEVICES message from the CFM to an MD,
 * which specifies the set of active cache devices managed by a cache server.
 */
DECLARE_PACKED_STRUCT(cfm_md_active_cs_cache_devices) {
    struct rna_service_id   acd_cs_id;  /* CS that manages these cachedevs*/
    uint16_t                acd_flags;
    uint16_t                acd_pad1;   /* for future use */
    uint32_t                acd_pad2;   /* for future use */
    struct md_cachedev_info acd_cds[MAX_CACHE_DEVICES_PER_CS];
                                        /* Information about each cachedev */
} END_PACKED_STRUCT(cfm_md_active_cs_cache_devices);

INLINE void
bswap_cfm_md_active_cs_cache_devices(
                                struct cfm_md_active_cs_cache_devices *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    int i;

	bswap_rna_service_id(&data->acd_cs_id);
    for (i = 0; i < MAX_CACHE_DEVICES_PER_CS; i++) {
        bswap_md_cachedev_info(&date->acd_cds[i]);
    }
#endif
}


/*
 * A CONF_MGR_CACHE_VIEW_STATUS message from the CFM.
 */
DECLARE_PACKED_STRUCT(cfm_cache_view_status) {
    uint8_t cvs_cache_view_complete;                /* TRUE if the cache view
                                                     * is complete;
                                                     * otherwise FALSE
                                                     */
    uint8_t cvs_cache_view_and_recoveries_complete; /* TRUE if the cache view
                                                     * is complete and all
                                                     * recoveries have
                                                     * completed;
                                                     * otherwise FALSE
                                                     */
} END_PACKED_STRUCT(cfm_cache_view_status);

INLINE void
bswap_cfm_cache_view_status(struct cfm_cache_view_status *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
#endif
}


/*
 * A CONF_MGR_CACHE_VIEW_STATUS_REQ message to the CFM.
 */
DECLARE_PACKED_STRUCT(cfm_cache_view_status_req) {
    uint8_t cvsr_pad;
} END_PACKED_STRUCT(cfm_cache_view_status_req);

INLINE void
bswap_cfm_cache_view_status_req(struct cfm_cache_view_status_req *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
#endif
}


DECLARE_PACKED_STRUCT(md_sync_data) {
    struct rna_service_id  msd_cs_service_id;
    cachedev_id_t          msd_cd_id;
    rna_hash_key_t         msd_hash_key; // 24 bytes
    uint8_t                msd_state;
    uint8_t                msd_write_commit_flag;
    uint8_t                msd_pad[2];   /**< for future use */
    uint32_t               msd_sync_num; /**< Requester's sync request number */
    uint64_t               msd_file_size;
    uint64_t               msd_block_size;
    common_meta_data_t     c;          /**< Common metadata stored by both the
                                        *   MDs and the CSs.
                                        */
    char                   msd_path[PATHNAME_LEN];
} END_PACKED_STRUCT(md_sync_data);

INLINE void bswap_md_sync_data(struct md_sync_data *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	bswap_rna_service_id(&data->msd_cs_service_id);
    bswap_rna_hash_key_t(&data->msd_hash_key);
    data->msd_partition = bswap_32(data->msd_sync_num);
    data->msd_file_size = bswap_64(data->msd_file_size);
    data->msd_block_size = bswap_64(data->msd_block_size);
    bswap_common_meta_data(&data->c);
#endif
}


INLINE void
bswap_cfm_md_partition_map(struct cfm_md_partition_map *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    int i;

	data->pm_generation = bswap_64(data->pm_generation);
	data->pm_num_hash_partitions = bswap_16(data->pm_num_hash_partitions);
    for (i = 0; i < MAX_MD_HASH_PARTITIONS; i++) {
        data->pm_partition_assignments[i] =
                                bswap_16(data->pm_partition_assignments[i]);
    }
#endif
}

#define MSE_FLAG_REJECTED_NODATA    (1 << 0)
            /* The sync request has been rejected because this MD
             * hasn't yet populated the requested partition, so has nothing to
             * send.
             */
#define MSE_FLAG_REJECTED_NOTOWNED  (1 << 1)
            /* The sync request has been rejected because neither this MD
             * nor the requesting MD own the requested partition.
             */
#define MSE_FLAG_REJECTED_EXPELLED  (1 << 2)
            /* The sync request has been rejected because the requester
             * has been expelled from the cluster.  The requesting MD may
             * have lost its connection with the primary CFM, so may not
             * have been notified about the expel.
             */

DECLARE_PACKED_STRUCT(md_sync_data_end) {
    uint64_t       mse_paxos_seqno;
    uint32_t       mse_sync_num;   /**< Requester's sync request number */
    uint32_t       mse_sync_gen;   /**< Request-ee's sync generation */
    uint16_t       mse_partition;  /**< hash partition number */
    uint8_t        mse_can_create_metadata_entries;
    uint8_t        mse_flags;
    uint32_t       mse_pad;        /**< for future use (and 64-bit alignment) */
    struct cfm_md_partition_map
                   mse_partition_map;  // sender's current partition map
} END_PACKED_STRUCT(md_sync_data_end);

INLINE void bswap_md_sync_data_end(struct md_sync_data *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    data->mse_paxos_seqno = bswap_64(data->mse_paxos_seqno);
    data->mse_sync_num = bswap_32(data->mse_sync_num);
    data->mse_sync_gen = bswap_32(data->mse_sync_gen);
    data->mse_partition = bswap_16(data->mse_partition);
    bswap_cfm_md_partition_map(&data->mse_partition_map);
#endif
}


DECLARE_PACKED_STRUCT(cs_sync_data_end) {
    uint32_t       cde_sync_num;   /**< Requester's sync request number */
    uint16_t       cde_partition;   // hash partition number
} END_PACKED_STRUCT(cs_sync_data_end);

INLINE void bswap_cs_sync_data_end(struct md_sync_data *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    data->cde_sync_num = bswap_32(data->cde_sync_num);
    data->hash_rid = bswap_16(data->cde_partition);
#endif
}

DECLARE_PACKED_STRUCT(md_sync_request) {
    struct rna_service_id msr_service_id; /**< Unique Service ID */
	struct rna_if_table   msr_if_tbl;     /**< Network interfaces available. */
    uint32_t              msr_ordinal;    /**< The sender's MD ordinal */
    uint32_t              msr_sync_num;   /**< Sender's sync request number */
    uint32_t              msr_sync_gen;   /**< Request-ee's sync generation */
    uint16_t              msr_partition;  /**< The partition to be sync'd */
    uint16_t              msr_pad1;       /**< for future use */
    struct cfm_md_partition_map
                          msr_partition_map;  /**< MD's current partition map */
} END_PACKED_STRUCT(md_sync_request);

INLINE void bswap_md_sync_request(struct md_sync_request *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    int i;
	bswap_rna_service_id(&data->msr_service_id);
    data->msr_sync_num = bswap_32(data->msr_sync_num);
    data->msr_sync_gen = bswap_32(data->msr_sync_gen);
    data->msr_partition = bswap_16(data->msr_partition);
    bswap_rna_if_table(data->msr_if_table);
    bswap_cfm_md_partition_map(&data->msr_partition_map);
#endif
}

/*
 * Standard command header.  This struct should remain a multiple of 8 bytes
 * in size, to avoid skewing alignment in the message it heads.
 */
typedef struct cmd_hdr_s {
	uint32_t         h_type;    /**< message type (@see rna_cmd_type) */
	int32_t          h_error;   /**< error code, if this msg is a response */
	uint64_t         h_cookie; 	/**< sender's cookie */
	primary_cfm_id_t h_pci;     /**< What the sender believes to be the ID of
                                 *   the current or most recent primary CFM
                                 */
} cmd_hdr_t;

INLINE void bswap_cmd_hdr (cmd_hdr_t *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    data->h_type = bswap_32(data->h_type);
    data->h_error = bswap_32(data->h_error);
    data->h_cookie = bswap_64(data->h_cookie);
    bswap_primary_cfm_id_t(&data->h_pci);
#endif
}

DECLARE_PACKED_STRUCT(md_sync_cmd) {
    cmd_hdr_t  h;   // must be first
    union {
		struct md_sync_request  md_sync_request;
		struct md_sync_data     md_sync_data;
		struct md_sync_data_end md_sync_data_end;
		struct cs_sync_data_end cs_sync_data_end;
    } u;
} END_PACKED_STRUCT(md_sync_cmd);

INLINE void bswap_md_sync_cmd (struct md_sync_cmd *cmd, int in)
{
    UNREFERENCED_PARAMETER(cmd);	
    UNREFERENCED_PARAMETER(in);	
#if CPU_BE
	if(in){
        bswap_cmd_hdr(&cmd->h);
		data->sync_gen = bswap_32(data->sync_gen);
	}
	switch(cmd->h.h_type){
        case META_DATA_SYNC_REQUEST:
            bswap_md_sync_request(&cmd->u.md_sync_request);
            break;
        case META_DATA_SYNC_DATA:
        case CS_SYNC_DATA:
            bswap_md_sync_data(&cmd->u.md_sync_data);
            break;
        case META_DATA_SYNC_DATA_END:
            bswap_md_sync_data_end(&cmd->u.md_sync_data_end);
            break;
        case CS_SYNC_DATA_END:
            bswap_md_sync_data_end(&cmd->u.cs_sync_data_end);
            break;
        case META_DATA_SYNC_DONE:
            // NOOP
            break
		default:
#ifndef __KERNEL__
			printf("bswap_cache_cmd: type mismatch: %d\n",cmd->h.h_type);
			assert(0);
#endif
    }
#endif
}

#if defined(LINUX_USER) || defined(WINDOWS_USER)
INLINE void rna_write_cache_req_type_xml(FILE *fd, cache_req_type_t type)
{
    fprintf(fd, "<cache_req_type id=\"%d\" name=\"%s\"/>\n", type, get_cache_req_type_string(type));
}

INLINE void rna_write_cache_req_types_xml(FILE *fd)
{
    fprintf(fd, "<cache_req_types>\n");
    rna_write_cache_req_type_xml(fd, CACHE_REQ_TYPE_INVALID);
    rna_write_cache_req_type_xml(fd, CACHE_REQ_TYPE_FULL);
    rna_write_cache_req_type_xml(fd, CACHE_REQ_TYPE_BLOCK);
    rna_write_cache_req_type_xml(fd, CACHE_REQ_TYPE_MASTER);
    rna_write_cache_req_type_xml(fd, CACHE_REQ_TYPE_REPLICA_BLOCK);
    fprintf(fd, "</cache_req_types>\n");
}
#endif

/** cache server's registration with meta_data server 
 * The Cache server registers itself with the Meta data manager informing it of its capabilities.
 */
DECLARE_PACKED_STRUCT(cache_reg) {
    struct rna_service_id service_id; /**< Unique Service ID */
    uint64_t            cr_cs_membership_generation; /**< The most recent cs membership generation number received from the primary CFM */
	char                hostname[MAX_HOST_LEN];   /**< Hostname for ease of use */
	uint64_t			max_mem; /**< Maximum memory allocatable to cache data */
	rna_rkey_t          ping_rkey; /**< rkey for ping RDMA reads */
	rna_addr_t          ping_buf; /** pointer for ping RDMA reads */
	uint32_t            status; /**< Can be used to indicate that the cache server is up, but unuseable. */
	struct rna_if_table if_tbl;     /**< Network interfaces available. */
} END_PACKED_STRUCT(cache_reg);

INLINE void bswap_cache_reg(struct cache_reg *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	bswap_rna_service_id(&data->service_id);
    data->cr_cs_membership_generation =
                                bswap_64(data->cr_cs_membership_generation);
	//char                hostname[MAX_HOST_LEN];
	data->max_mem = bswap_64(data->max_mem);
	bswap_rna_rkey_t(&data->ping_rkey);
	bswap_rna_addr_t(&data->ping_buf);
    data->status = bswap_32(data->status);
    bswap_rna_if_table(data->msr_if_table);
#endif
}

/** cache server's registration response from the meta_data server 
 */
DECLARE_PACKED_STRUCT(cache_reg_resp) {
    uint64_t crr_cs_membership_generation; /**< The most recent cs membership generation number received from the primary CFM */
	uint64_t block_size; /**< Block size to use */
	uint64_t block_threshold; /**< Any file of size less then this value will be cached as a full file */	
	rna_addr_t ping_buf; /** pointer for ping RDMA reads */
	rna_rkey_t ping_rkey; /**< rkey for ping RDMA reads */
	uint8_t  status; /**< Status. 0=success. non-zero=failure */
} END_PACKED_STRUCT(cache_reg_resp);

INLINE void bswap_cache_reg_resp(struct cache_reg_resp *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    data->crr_cs_membership_generation =
                                bswap_64(data->crr_cs_membership_generation);
    data->block_size = bswap_64(data->block_size);
    data->block_threshold = bswap_32(data->block_threshold);
	bswap_rna_rkey_t(&data->ping_rkey);
	bswap_rna_addr_t(&data->ping_buf);
#endif
}

/** Maximum number of SAN interfaces (iSCSI IQN, FC PWWN, etc.)
 */
#define MAX_SAN_IF 8


/** Maximum length of SAN type string
 */
#define MAX_SAN_TYPE_LEN 64
/** Maximum length of SAN id string
 */
#define MAX_SAN_ID_LEN 256

/** path to location of iSCSI initiator name
 */
#define ISCSI_INAME_PATH "/sys/class/iscsi_session/session*/initiatorname"

/** path to location of fiber channel port identifiers
 */
#define FC_PORT_ID_PATH "/sys/class/fc_host/*/port_name"

/** temporary path to store and lookup SAN interface identifiers
 */
#define SAN_IF_DISC_TMP "/tmp/fldc_san_if_discovery"

/** SAN interface information
 */
DECLARE_PACKED_STRUCT(san_if_info) {
    char san_if_type[MAX_SAN_TYPE_LEN];
    char san_if_id[MAX_SAN_ID_LEN];
} END_PACKED_STRUCT(san_if_info);

/** Agent iser device information
 */
DECLARE_PACKED_STRUCT(iser_hba) {
    char devname[MAX_NAME_LEN];
    char devipaddr[16];
} END_PACKED_STRUCT(iser_hba);

/** Agent registration message sent to the CFM.
	Generates an agent_reg_resp message from the CFM.
 */
DECLARE_PACKED_STRUCT(agent_cfm_reg) {
    struct rna_service_id service_id; /**< Unique Service ID */
    uint64_t              pid; /**< pid of agent process */
	char                  hostname[MAX_HOST_LEN];   /**< Hostname of agent system */
	char                  cpu[MAX_CPU_STR_LEN]; /**< CPU string from host system */
	uint64_t              num_pages;  /**< Total number of memory pages */
	uint64_t              page_size;  /**< Memory page size */
	uint64_t              cookie;	/**< Agent specified cookie */
	//struct rna_if_info    if_tbl[MAX_NET_IF]; /**< Network interfaces configured on host system */
	uint32_t              num_cpu; /**< Total number of CPUs on system */
	uint8_t               byte_order; /**< BIG Endian=1, Little Endian=0 */
    uuid_t                hcn_id; /**< Agent's HCN ID */
    uint8_t               san_if_count; /**< Agent's SAN interface count */
    struct san_if_info    san_ifs[MAX_SAN_IF]; /**< Agent's SAN interface information */
    char                  os_type[MAX_NAME_LEN]; /**< Agent's OS type string */
    char                  acr_os_release[MAX_INSTANCE_LEN]; /**< Agent's OS release string */
    char                  acr_sw_version[MAX_INSTANCE_LEN]; /**< Agent's FLDC SW version string */
    char                  acr_api_version[MAX_INSTANCE_LEN]; /**< Agent's SOAP version string */
    struct iser_hba       iser_hba[MAX_ISER_PORTS];
    int                   num_iser_devices;
} END_PACKED_STRUCT(agent_cfm_reg);

INLINE void bswap_agent_cfm_reg(struct agent_cfm_reg *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    bswap_rna_service_id(&data->rna_service_id);
	//char cpu[64];
	data->pid = bswap_64(data->pid);
	data->num_cpu = bswap_32(data->num_cpu);
	data->num_pages = bswap_64(data->num_pages);
	data->page_size = bswap_64(data->page_size);
	data->cookie = bswap_64(data->cookie);
#endif
}

/** Retrieve stats from the agent. Upon recieving this message the agent responds with the
    agent_stats_rep message 
 */
DECLARE_PACKED_STRUCT(agent_get_stats) {
	uint32_t type;	
} END_PACKED_STRUCT(agent_get_stats);

INLINE void bswap_agent_get_stats(struct agent_get_stats *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->type = bswap_32(data->type);
#endif
}

/** Agent statistics report 
 */
DECLARE_PACKED_STRUCT(agent_stats_rep) {
    uint64_t uptime;    /**< Seconds since boot */
    uint64_t loads[3];  /**< 1, 5, and 15 minute load averages */
    uint64_t totalram;  /**< Total usable main memory size */
    uint64_t freeram;   /**< Available memory size */
    uint64_t sharedram; /**< Amount of shared memory */
    uint64_t bufferram; /**< Memory used by buffers */
    uint64_t totalswap; /**< Total swap space size */
    uint64_t freeswap;  /**< swap space still available */
    uint64_t procs;     /**< Number of current processes */
    uint64_t totalhigh; /**< Total high memory size */
    uint64_t freehigh;  /**< Available high memory size */
    uint64_t mem_unit;  /**< Memory unit size in bytes */
    uint8_t  update_pending; /**< Software update pending */
    uint8_t  pad[7];  /**< for future use (and 64-bit alignment) */
} END_PACKED_STRUCT(agent_stats_rep);

INLINE void bswap_agent_stats_rep(struct agent_stats_rep *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->uptime = bswap_64(data->uptime);
	// TODO: Verify that the array need not be reordered as well.
	data->loads[0] = bswap_64(data->loads[0]);
	data->loads[1] = bswap_64(data->loads[1]);
	data->loads[2] = bswap_64(data->loads[2]);
	data->totalram = bswap_64(data->totalram);
	data->freeram = bswap_64(data->freeram);
	data->sharedram = bswap_64(data->sharedram);
	data->bufferram = bswap_64(data->bufferram);
	data->totalswap = bswap_64(data->totalswap);
	data->freeswap = bswap_64(data->freeswap);
	data->procs = bswap_64(data->procs);
	data->totalhigh = bswap_64(data->totalhigh);
	data->freehigh = bswap_64(data->freehigh);
	data->mem_unit = bswap_64(data->mem_unit);
    data->heartbeat = bswap_64(data->heartbeat);
#endif
}

/*
 * Agent SSD list request
 */
DECLARE_PACKED_STRUCT(agent_get_ssd) {
    uint32_t pad;
} END_PACKED_STRUCT(agent_get_ssd);

INLINE void bswap_agent_ssd(struct agent_get_ssd *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->pad = bswap_32(data->pad);
#endif
}

/*
 * Agent SSD list response
 */

#define AGENT_SSD_LIST_START   0x1
#define AGENT_SSD_LIST_END     0x2
#define AGENT_SSD_LIST_EMPTY   0x4
DECLARE_PACKED_STRUCT(agent_get_ssd_rep) {
    uint32_t    gs_list_state;
    uuid_t      gs_hcn_id;
    char        gs_dev_model[MAX_CACHEDEV_MODEL_LEN];
    char        gs_dev_path[MAX_CACHEDEV_PATH_LEN];
    char        gs_dev_wwn_str[MAX_WWN_STR_LEN];
    char        gs_dev_in_use[MAX_IN_USE_STR_LEN];
    uint64_t    gs_dev_size_bytes;
} END_PACKED_STRUCT(agent_get_ssd_rep);

INLINE void bswap_agent_ssd_rep(struct agent_get_ssd_rep *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    data->gs_list_state = bswap_32(data->gs_list_state);
    data->gs_dev_size_bytes = bswap_64(data->gs_dev_size_bytes);
    // TODO: does uuid_t need to be swapped?

#endif
}

/*
 * CFM prepare_delete_hcc request
 */
DECLARE_PACKED_STRUCT(cfm_prepare_delete_hcc) {
    int32_t delete_hcc_timeout;
} END_PACKED_STRUCT(cfm_prepare_delete_hcc);

INLINE void bswap_cfm_prepare_delete_hcc(struct cfm_prepare_delete_hcc *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->delete_hcc_timeout = bswap_32(data->delete_hcc_timeout);
#endif
}

/*
 * CFM prepare_delete_hcc response
 */

#define CFM_DELETE_HCC_OK                       0x00
#define CFM_DELETE_HCC_NOT_PRIMARY              0x01
#define CFM_DELETE_HCC_VOL_EXIST                0x02
#define CFM_DELETE_HCC_SAN_EXIST                0x04
#define CFM_DELETE_HCC_SSD_EXIST                0x08
#define CFM_DELETE_HCC_CACHE_VIEW_INCOMPLETE    0x10

DECLARE_PACKED_STRUCT(cfm_prepare_delete_hcc_resp) {
    uint32_t delete_hcc_result;
} END_PACKED_STRUCT(cfm_prepare_delete_hcc_resp);

INLINE void bswap_cfm_prepare_delete_hcc_resp(struct cfm_prepare_delete_hcc_resp *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    data->delete_hcc_result = bswap_32(data->delete_hcc_result);
#endif
}


/*
 * Request ID structure for the following CFM/Journal messages
 */
DECLARE_PACKED_STRUCT(journal_request_id) {
    /*
     * The primary_cfm_id_t of the primary CFM making this request
     */
    primary_cfm_id_t             iri_cfm_id;
    uint64_t                     iri_sequence_number;
} END_PACKED_STRUCT(journal_request_id)
INLINE void bswap_journal_request_id(struct journal_request_id *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    bswap_rna_service_id(&data->iri_service_id);
    data->iri_sequence_number = bswap_64(data->iri_sequence_number);
#endif
}

/*
 * CFM journal init data
 */
struct init_peer_info {
    struct in_addr  ipi_addr;
    int             ipi_rank;
};

DECLARE_PACKED_STRUCT(cfm_journal_init_request) {
    uuid_t         jir_hcc_id;      /* Cluster ID */
    uint64_t       jir_generation;  /* journal generation */
    time_t         jir_time;        /* journal transaction time */
    uint32_t       jir_primary_mode;/* node in primary journal mode */
    journal_digest_t jir_hash;      /* superblock hash */
    uint32_t       jir_peer_count;
    struct init_peer_info  jir_peer_info[RNA_SERVICE_CFMS_MAX]; /* cfm rank info */
} END_PACKED_STRUCT(cfm_journal_init_request);

INLINE void bswap_journal_init_req(struct cfm_journal_init_request *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
     data->jir_generation = bswap_64(data->jir_generation);
     data->jir_time = bswap_64(data->jir_time);
     data->jir_primary_mode = bswap_32(data->jir_primary_mode);
     data->jir_jir_peer_count = bswap_32(data->jir_peer_count);
#endif
}

/*
 * CFM journal init data response
 */
DECLARE_PACKED_STRUCT(cfm_journal_init_response) {
    uint64_t       jip_status;
} END_PACKED_STRUCT(cfm_journal_init_response);

INLINE void bswap_journal_init_resp(struct cfm_journal_init_response *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
     data->jip_status = bswap_64(data->jip_status);
#endif
}
#define JIP_STATUS_OK               0
#define JIP_HCCID_MISMATCH          1
#define JIP_JOURNAL_GENERATION_ERR  2


/*
 * CFM journal read request
 */
DECLARE_PACKED_STRUCT(cfm_journal_read_request) {
    journal_request_id_t         jrs_request_id;
    /*
     * The  transaction generation number (js_transaction_gen from the
     * journal superblock) that this read request is part of
     */
    uint64_t                     jrs_transaction_id;
    /*
     * The location of the journal mirror from which a block is
     * to be read
     */
    journal_location_t           jrs_location;
    /*
     * Indicates whether the block number below specifies a physical
     * block, an L1 block, or a logical block
     */
    journal_blocknum_t           jrs_blocknum_type;
    /* The block number of the block to be read */
    uint32_t                     jrs_blocknum;
} END_PACKED_STRUCT(cfm_journal_read_request);

INLINE void bswap_journal_read_req(struct cfm_journal_read_request *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
     bswap_journal_request_id(&data->jrs_request_id);
     data->jrr_transaction_id = bswap_64(data->jrr_transaction_id);
     data->jrs_location = bswap_32(data->jrs_location);
     data->jrs_blocknum_type = bswap_32(data->jrs_blocknum_type);
     data->jrs_blocknum = bswap_32(data->jrs_blocknum);
#endif
}

/*
 * CFM journal read response
 */
DECLARE_PACKED_STRUCT(cfm_journal_read_response) {
    /*
     * The request ID specified in the cfm_journal_read_request message
     */
    journal_request_id_t      jrr_request_id;
    /*
     * The status of this read request
     */
    journal_io_status_t       jrr_status;
    /*
     * If the read was successful, the content
     * of the requested journal block
     */
    journal_block_t           jrr_content;
} END_PACKED_STRUCT(cfm_journal_read_response);

INLINE void bswap_journal_read_resp(struct cfm_journal_read_response *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
     bswap_journal_request_id(&data->jrs_request_id);
     data->jrr_status = bswap_32(data->jrr_status);
#error "Swap journal block?"
#endif
}

/*
 * CFM journal write request
 */
DECLARE_PACKED_STRUCT(cfm_journal_write_request) {
    /*
     * Set of CFMs known to the sending CFM
     */
    uint32_t                    jws_cfm_count;
    struct sockaddr_in          jws_cfm_addr_tbl[MAX_NET_IF];
    /*
     * The ID of this journal block write request
     */
    journal_request_id_t         jws_request_id;
    /*
     * The  transaction generation number (js_transaction_gen from the
     * journal superblock) that this write request is part of
     */
    uint64_t                     jws_transaction_id;
    /*
     * The location of the journal mirror to which a block is
     * to be written
     */
    journal_location_t           jws_location;
    /*
     * Indicates whether the block number below specifies a physical
     * block, an L1 block, or a  logical block
     */
    journal_blocknum_t           jws_blocknum_type;
    /*
     * The block number of the block to be written
     */
    uint32_t                     jws_blocknum;
    /*
     * TRUE if a flush is to be performed after the write has completed;
     * otherwise FALSE
     */
    rna_boolean                  jws_flush_flag;
    /*
     * The content of the block to be written
     */
    journal_block_t              jws_content;
} END_PACKED_STRUCT(cfm_journal_write_request);

INLINE void bswap_journal_write_req(struct cfm_journal_write_request *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
     bswap_journal_request_id(&data->jws_request_id);
     data->jws_transaction_id = bswap_64(data->jws_transaction_id);
     data->jws_location = bswap_32(data->jws_location);
     data->jws_blocknum_type = bswap_32(data->jws_blocknum_type);
     data->jws_blocknum = bswap_32(data->jws_blocknum);
     // jws_flush_flag 8 bits
     // journal_block_t ??
#error "Swap Journal Block?"
#endif
}


/*
 * CFM journal write request
 */
DECLARE_PACKED_STRUCT(cfm_journal_write_response) {
    /*
     * The request ID specified in the cfm_journal_write_request message
     */
    journal_request_id_t      jwr_request_id;
    /*
     * The status of this write request
     */
    journal_io_status_t       jwr_status;
} END_PACKED_STRUCT(cfm_journal_write_response);

INLINE void bswap_journal_write_resp(struct cfm_journal_write_response *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    bswap_journal_request_id(&data->jws_request_id);
    data->jwr_status = bswap_32(data->jwr_status);
#endif
}


/** CFM registration response
 */
DECLARE_PACKED_STRUCT(cfm_reg_resp) {
	rna_addr_t ping_buf; /** pointer for ping RDMA reads */
	rna_rkey_t ping_rkey; /**< rkey for ping RDMA reads */
} END_PACKED_STRUCT(cfm_reg_resp);

INLINE void bswap_cfm_reg_resp(struct cfm_reg_resp *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	bswap_rna_rkey_t(&data->ping_rkey);
	bswap_rna_addr_t(&data->ping_buf);
#endif
}


/** CFM Metadata host report.
 *  Sent by the CFM whenever any membership change occurs in the set of
 *  metadata servers.
 */
DECLARE_PACKED_STRUCT(cfm_md_host_rep) {
    struct rna_service_id
                        md_service_id; /**< Unique Service ID */
	char                md_host[MAX_HOST_LEN];
                                    /*!	Metadata server hostname (used for
                                     *	reporting and logs)
                                     */
	struct rna_if_table md_if_tbl;
                                    /*!	Network interfaces available.  */
    uint32_t            md_ordinal; /*!	This MD's ordinal in the current set
                                     *   of MDs.  This value must be less than
                                     *   MAX_MDS.
                                     */
    uint32_t            md_num_configured;
                                    /*! The number of configured MDs in the
                                     *  group.
                                     */
} END_PACKED_STRUCT(cfm_md_host_rep);

INLINE void bswap_cfm_md_host_rep(struct cfm_md_host_rep *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    bswap_rna_service_id(&data->rna_service_id);
	//	char md_host[MAX_HOST_LEN];
    bswap_rna_if_table(data->md_if_tbl);
	data->md_ordinal = bswap_32(data->md_ordinal);
	data->md_num_configured = bswap_32(data->md_num_configured);
#endif
}


/** Agent registration response.
	Sent from the CFM to the agent in response to the agent_cfm_reg message */
DECLARE_PACKED_STRUCT(agent_reg_resp) {
	uint64_t cookie;
	uint32_t master;    /* Flag indicating to the CFM if it is master */
	uint32_t failover_evt_flag;
	uint32_t reset_flag;
    char     hccid[16]; /* CFM reports its host cache cluster id */
    uint64_t hcckey;    /* CFM reports its host cache cluster authentication token */
    char     hccname[129]; /* CFM reports host cache cluster name */
} END_PACKED_STRUCT(agent_reg_resp);

INLINE void bswap_agent_reg_resp(struct agent_reg_resp *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->cookie = bswap_64(data->cookie);
	data->master = bswap_32(data->master);
	data->failover_evt_flag = bswap_32(data->failover_evt_flag);
	data->reset_flag = bswap_32(data->reset_flag);
    // char hccid[16];
    data->hcckey = bswap_64(data->hcckey);
#endif
}

typedef enum {
	APP_CTL_START = 1,
	APP_CTL_STOP,
	APP_CTL_RESTART,
	APP_CTL_CORE,
	APP_CTL_SET_LOG_LEVEL,
    CFM_PROMOTION,
    CFM_DEMOTION,
    CACHE_MOUNT_BLOCKED,
    CACHE_MOUNT_UNBLOCKED,
    APP_CTL_UPDATE_STATS,
	APP_CTL_DELETE,
    CFM_DELETE,
    APP_CTL_ADD_PATH,
    APP_CTL_REMOVE_PATH,
    APP_CTL_FLUSH_PATH,
    APP_CTL_ADD_CACHE_DEVICE,
    APP_CTL_REMOVE_CACHE_DEVICE,
    APP_CTL_REACTIVATE_CACHE_DEVICE,
    APP_CTL_DROP_CONNECTION, /* for testing purposes only, disconnects EPs */
    APP_CTL_MODIFY_CACHE_MODE,
    JNL_RECV_MIRROR, /* Sent to agent to reqest that it retrieve journal mirror */
    APP_HCC_SHUTDOWN, /* Sent to agent to support HCC shutdown*/
    APP_SEND_PHONEHOME, /* Sent to agent to create and send phone home data collection*/
} app_control_type;

INLINE const char * get_app_control_type_string (app_control_type type)
{
    const char * ret = NULL;

    switch (type) {
        case APP_CTL_START: ret = "APP_CTL_START"; break;
        case APP_CTL_STOP: ret = "APP_CTL_STOP"; break;
        case APP_CTL_RESTART: ret = "APP_CTL_RESTART"; break;
        case APP_CTL_CORE: ret = "APP_CTL_CORE"; break;
        case APP_CTL_SET_LOG_LEVEL: ret = "APP_CTL_SET_LOG_LEVEL"; break;
        case CFM_PROMOTION: ret = "CFM_PROMOTION"; break;
        case CFM_DEMOTION: ret = "CFM_DEMOTION"; break;
        case CACHE_MOUNT_BLOCKED: ret = "CACHE_MOUNT_BLOCKED"; break;
        case CACHE_MOUNT_UNBLOCKED: ret = "CACHE_MOUNT_UNBLOCKED"; break;
        case APP_CTL_UPDATE_STATS: ret = "APP_CTL_UPDATE_STATS"; break;
        case APP_CTL_DELETE: ret = "APP_CTL_DELETE"; break;
        case CFM_DELETE: ret = "CFM_DELETE"; break;
        case APP_CTL_ADD_PATH: ret = "APP_CTL_ADD_PATH"; break;
        case APP_CTL_REMOVE_PATH: ret = "APP_CTL_REMOVE_PATH"; break;
        case APP_CTL_FLUSH_PATH: ret = "APP_CTL_FLUSH_PATH"; break;
        case APP_CTL_ADD_CACHE_DEVICE: ret = "APP_CTL_ADD_CACHE_DEVICE"; break;
        case APP_CTL_REMOVE_CACHE_DEVICE: ret = "APP_CTL_REMOVE_CACHE_DEVICE"; break;
        case APP_CTL_REACTIVATE_CACHE_DEVICE: ret = "APP_CTL_REACTIVATE_CACHE_DEVICE"; break;
        case APP_CTL_DROP_CONNECTION: ret = "APP_CTL_DROP_CONNECTION"; break;
        case APP_CTL_MODIFY_CACHE_MODE: ret = "APP_CTL_MODIFY_CACHE_MODE"; break;
        case JNL_RECV_MIRROR: ret = "JNL_RECV_MIRROR"; break;
        case APP_HCC_SHUTDOWN: ret = "APP_HCC_SHUTDOWN"; break;
        case APP_SEND_PHONEHOME: ret = "APP_SEND_PHONEHOME"; break;
        default: ret = "unknown";
    }
    return ret;
}

/** Start / Stop cache services via the agent.
    Message is sent via the CFM
 */
DECLARE_PACKED_STRUCT(agent_app_control) {
    struct rna_service_id service_id;
	uint32_t              control;
} END_PACKED_STRUCT(agent_app_control);

INLINE void bswap_agent_app_control(struct agent_app_control *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->app_type = bswap_32(data->app_type);
	data->control = bswap_32(data->control);
    bswap_rna_service_id(&data->rna_service_id);
#endif
}


/** Metadata statistics
 * NOTE that is any fields are added to this struct,
 * reinitialize_hash_partition() must be modified to deal with the new fields.
 */
DECLARE_PACKED_STRUCT(md_stats) {
	uint64_t cache_mem;
	uint64_t cache_blocks;
	uint64_t cache_files;
	uint64_t full_files;
	uint64_t requests;
	uint64_t block_found;
	uint64_t block_not_found;
	uint64_t insertions;
	uint64_t evictions;
	uint64_t write_evictions;
	uint64_t write_lock_time;
	uint32_t cache_managers;
    uint32_t ms_pad;            // For future use
} END_PACKED_STRUCT(md_stats);

INLINE void bswap_md_stats(struct md_stats *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->cache_mem = bswap_64(data->cache_mem);
	data->cache_blocks = bswap_64(data->cache_blocks);
	data->cache_files = bswap_64(data->cache_files);
	data->full_files = bswap_64(data->full_files);
	data->requests = bswap_64(data->requests);
	data->block_found = bswap_64(data->block_found);
	data->block_not_found = bswap_64(data->block_not_found);
	data->insertions = bswap_64(data->insertions);
	data->evictions = bswap_64(data->evictions);
	data->write_evictions = bswap_64(data->write_evictions);
	data->write_lock_time = bswap_64(data->write_lock_time);
	data->cache_managers = bswap_32(data->cache_managers);
#endif
}

/** cache server's reply to cache request 
 */
DECLARE_PACKED_STRUCT(cache_io_stats) {
	atomic64_t cache_blocks; /**< Cache block count **/
	atomic64_t cumulative_cache_blocks; /**< Cumulative cache block count **/
	atomic64_t read_count; /**< Cache fill read ops (cache server) */
	atomic64_t read_fail_count; /**< Cache fill read op failures (cache server) */
	atomic64_t slow_read_count; /**< Cache fill read ops that took longer than io_latency_threshold (cache server) */
	atomic64_t read_bytes; /**< Cache fill bytes read (cache server) */
	atomic64_t hit_read_time; /**< Cumulative read time for cache hits (file cilent) cache fills (cache server, in nanoseconds) */
	atomic64_t write_count; /**< Cache fill read ops (cache server) */
	atomic64_t write_fail_count; /**< Cache flush write op failures (cache server) */
	atomic64_t slow_write_count; /**< Cache flush write ops that took longer than io_latency_threshold (cache server) */
	atomic64_t write_bytes; /**< Cache flush bytes written (cache server) */
	atomic64_t write_bytes_dirty; /**< Cache flush bytes written that are dirty (cache server) */
	atomic64_t write_time;    /**< Cumulative write time for cache flushes (cache server, in nanoseconds) */
	atomic64_t write_clat;    /**< Cumulative write time (completion time or completion latency) for cache flushes (cache server, in nanoseconds) */
	atomic64_t fstat_count; /**< Cache fstat ops (cache server) */
	atomic64_t fstat_fail_count; /**< Cache fstat op failures (cache server) */
	atomic64_t slow_fstat_count; /**< Cache fstat ops that took longer than io_latency_threshold (cache server) */
	atomic64_t fstat_time;    /**< Cumulative fstat time (cache server, in nanoseconds) */
	atomic64_t open_count; /**< Cache lfs opens ops (cache server) */
	atomic64_t open_fail_count; /**< Cache lfs open failures (cache server) */
	atomic64_t slow_open_count; /**< Cache lfs opens that took longer than io_latency_threshold (cache server) */
	atomic64_t open_time;    /**< Cumulative cache lfs open time (cache server, in nanoseconds) */
    atomic64_t blocks_read_referenced;  /**< Current blocks with >0 read references */
    atomic64_t blocks_write_referenced;  /**< Current blocks with >0 write references */
    atomic64_t blocks_write_only_referenced;  /**< Current blocks with >0 write-only references */
    atomic64_t blocks_no_reference;  /**< Current blocks with no references */
    atomic64_t blocks_dirty;  /**< Current blocks on flush list */
    atomic64_t blocks_flushing;  /**< Current blocks with flush writes pending */
    atomic64_t flush_write_ops_pending;  /**< Current flush write io count */
    atomic64_t bytes_flushing;  /**< Current bytes in pending flush writes */
    atomic64_t blocks_filling;  /**< Current blocks with fill reads pending */
    atomic64_t bytes_filling;  /**< Current bytes in pending fill reads */
    atomic64_t blocks_priority_flushing;  /**< Current blocks with priority flush writes pending */
    atomic64_t blocks_invalidate_flushing;  /**< Current invalidating / evicting blocks with flush writes pending */
    atomic64_t cumulative_replica_blocks;  /**< Total replica blocks ever allocated */
    atomic64_t replica_blocks;  /**< Current replica block count */
    atomic64_t replica_bytes;  /**< Current total of bytes in replica blocks */
    atomic64_t cumulative_uncached_blocks;  /**< Total uncached blocks ever allocated */
    atomic64_t uncached_blocks;  /**< Current uncached block count */
    atomic64_t uncached_bytes;  /**< Current total of bytes in uncached blocks */
    atomic64_t bytes_read_referenced;  /**< Current bytes with >0 read references */
    atomic64_t bytes_write_referenced;  /**< Current bytes with >0 write references */
    atomic64_t bytes_write_only_referenced;  /**< Current bytes with >0 write-only references */
    atomic64_t bytes_no_reference;  /**< Current bytes with no references */
    atomic64_t bytes_dirty;  /**< Current bytes on flush list */
	atomic64_t client_write_ops; /**< Client to CS write ops completed */
	atomic64_t client_write_bytes; /**< Client to CS write bytes completed */
	atomic64_t client_write_ops_pending; /**< Client to CS write ops in progress */
	atomic64_t client_write_bytes_pending; /**< Client to CS write bytes in progress */
	atomic64_t client_write_ops_overlapping; /**< Client to CS write ops that overlapped in-progress ops */
    atomic64_t contiguous_dirty_bytes; /**< Contiguous dirty bytes per the DSM */
    atomic64_t contiguous_dirty_chunks; /**< Contiguous dirty chunks per the DSM */
    atomic64_t inserts; /**< Cache block insertions */
    atomic64_t evictions; /**< Cache block evictions */
    atomic64_t evicted; /**< Cache bytes evicted */
    atomic64_t evict_age; /**< Cumulative Cache blocks age in nanoseconds at eviction */
    atomic64_t blocks_dirty_base; /**< cachedev blocks dirty at removal */
    atomic64_t reconns_pending; /**< Number of replica blocks pending reconnection 
                                 * Incremented only when a block moves to 
                                 * RNA_REPLICA_DISCONNECTED state from any state
                                 * other than RNA_REPLICA_RECONNECTING.
                                 * Incremented only when a block moves to 
                                 * RNA_REPLICA_RECONNECTING state from any state
                                 * other than RNA_REPLICA_DISCONNECTE.
                                 * Remains unchanged when block moves between
                                 * RNA_REPLICA_DISCONNECTED and RNA_REPLICA_RECONNECTING.
                                 * Decremented whenever the block moves from 
                                 * RNA_REPLICA_DISCONNECTED or
                                 * RNA_REPLICA_RECONNECTING to any other state.
                                 */
    atomic64_t replica_blocks_base; /**< cachedev replica blocks at removal */
    atomic64_t write_through_io_bytes; /**< Number of bytes writen directly to disk (in parallel to cache) */
	atomic64_t client_write_same_ops; /**< Client to CS write same ops completed */
	atomic64_t client_write_same_bytes; /**< Client to CS write same bytes completed */
	atomic64_t client_comp_and_write_ops; /**< Client to CS comp and write ops completed */
	atomic64_t client_read_ops; /**< Client to CS read ops completed */
	atomic64_t client_read_bytes; /**< Client to CS read bytes completed */
	atomic64_t client_read_ops_pending; /**< Client to CS read ops in progress */
	atomic64_t client_read_bytes_pending; /**< Client to CS read bytes in progress */
	atomic64_t uncached_io_ops; /**< Uncached IO ops completed */
	atomic64_t uncached_io_bytes; /**< Number of bytes read/writen directly to disk (by-passing cache) */
	atomic64_t uncached_io_ops_pending; /**< Uncached IO ops in progress */
	atomic64_t uncached_io_bytes_pending; /**< Uncached IO bytes in progress */
} END_PACKED_STRUCT(cache_io_stats);

#define HIST_SIZE 256
/** Cache statistics
 *
 * Used by FS client and by cache servers. See field details for
 * applicability and units for each source.
 */
DECLARE_PACKED_STRUCT(cache_stats) {
	//uint64_t cache_hits; /**< (file client) */
	//uint64_t pc_hits; /**< (file client) */
	//uint64_t cache_miss; /**< (file client) */
	//atomic_t cache_eof; /**< (apparently debug) */
	//atomic_t fd_info_miss; /**< (apparently debug) */
	//atomic_t cache_connect_miss; /**< (apparently debug) */
	//atomic_t cache_invalid_miss; /**< (apparently debug) */
	//atomic_t ep_invalid_miss; /**< (apparently debug) */
	//atomic_t md_unconnected; /**< (apparently debug) */
	//atomic_t shm_hash_unconnected; /**< (apparently debug) */
	//atomic_t shm_hash_invalid; /**< (apparently debug) */
	atomic64_t cache_mem;
	atomic64_t used_mem;
	atomic64_t nonevict_mem;
	atomic64_t cache_nonevict_blocks;
	atomic_t cache_add_count;
	atomic_t cache_rem_count; 
	atomic_t cache_nonevict_add_count;
	atomic_t cache_nonevict_rem_count; 
    atomic64_t evicted;   /**< bytes evicted **/
	atomic64_t evicted_master_invalidate;   /**< bytes @see CACHE_EVICT_CAUSE_MASTER_INVALIDATE **/
	atomic64_t evicted_write_lock;   /**< bytes @see CACHE_EVICT_CAUSE_WRITE_LOCK **/
	atomic64_t evicted_proactive_eviction;   /**< bytes @see CACHE_EVICT_CAUSE_PROACTIVE_EVICTION **/
	atomic64_t evicted_file_modified;   /**< bytes @see CACHE_EVICT_CAUSE_FILE_MODIFIED **/
	atomic64_t blocks_evicted;   /**< blocks evicted **/
	//atomic_t rt_count;/**< (file client) */
	//atomic_t rt_time;	/**< cache read-in latency (file client) */
	//uint64_t pc_hit_read_time; /**< Cumulative read time for lower page cache (file client) */
	//uint64_t miss_read_time;   /**< Cumulative read time for cache misses (file client) */
	//uint64_t app_read_latency; /**< (file client) */
	//uint64_t app_read_throughput; /**< (file client) */
	//atomic64_t trans_recd_count; /**< (cache server) */
	//atomic64_t trans_recd_data; /**< (cache server) */
	//atomic64_t trans_sent_count; /**< (cache server) */
	//atomic64_t trans_sent_data; /**< (cache server) */
	atomic64_t flush_count; /**< (cache server) */
	atomic64_t flush_data; /**< (cache server) */
	atomic64_t cache_mem_eagain; /**< number of EAGAINs sent to client due to
                                   *  fragmentation/allocation issues */
	atomic64_t cache_state_eagain; /**< number of EAGAINs sent to client due to
                                     *  entry state race issues */
	atomic64_t cache_path_eagain; /**< number of EAGAINs sent to client due to
                                    *  backing store issues */
    struct cache_io_stats io_stats;
    atomic_t cs_multipath_enabled;  /**< TRUE if multipath support was detected when last checked */
    atomic_t cs_detached;           /**< TRUE if cache server is detached from cluster */
    atomic_t cs_detach_count;       /**< Number of times detached from cluster */
    atomic_t cs_rejoin_count;       /**< Number of times detached from cluster */
} END_PACKED_STRUCT(cache_stats);

/** 
	NOTE: We only need to swap cache stats if the byteordering of the remote host is different then 
	      the CFM. Otherwise the bytes will be misordered since they are not standardized on little endian
*/
INLINE void bswap_cache_stats(struct cache_stats *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    int i;
	data->heartbeat = bswap_32(data->heartbeat);
	//data->cache_hits = bswap_64(data->cache_hits);
	//data->pc_hits = bswap_64(data->pc_hits);
	//data->cache_miss = bswap_64(data->cache_miss);
	//data->cache_eof = bswap_32(data->cache_eof);
	//data->fd_info_miss = bswap_32(data->fd_info_miss);
	//data->cache_connect_miss = bswap_32(data->cache_connect_miss);
	//data->cache_invalid_miss = bswap_32(data->cache_invalid_miss);
	//data->ep_invalid_miss = bswap_32(data->ep_invalid_miss);
	//data->md_unconnected = bswap_32(data->md_unconnected);
	//data->shm_hash_unconnected = bswap_32(data->shm_hash_unconnected);
	//data->shm_hash_invalid = bswap_32(data->shm_hash_invalid);
	data->cache_mem = bswap_64(data->cache_mem);
	data->used_mem = bswap_64(data->used_mem);
	data->nonevict_mem = bswap_64(data->nonevict_mem);
	data->cache_blocks = bswap_64(data->cache_blocks);
	data->cache_nonevict_blocks = bswap_64(data->cache_nonevict_blocks);
	data->cache_add_count = bswap_32(data->cache_add_count);
	data->cache_rem_count = bswap_32(data->cache_rem_count);
	data->cache_nonevict_add_count = bswap_32(data->cache_nonevict_add_count);
	data->cache_nonevict_rem_count = bswap_32(data->cache_nonevict_rem_count);
	data->evicted = bswap_64(data->evicted);
	data->blocks_evicted = bswap_64(data->blocks_evicted);
	//data->rt_count = bswap_32(data->rt_count);
	//data->rt_time = bswap_32(data->rt_time);
	data->read_count = bswap_64(data->read_count);
	data->read_fail_count = bswap_64(data->read_fail_count);
	data->slow_read_count = bswap_64(data->slow_read_count);
	data->read_bytes = bswap_64(data->read_bytes);
	data->hit_read_time = bswap_64(data->hit_read_time);
	//data->pc_hit_read_time = bswap_64(data->pc_hit_read_time);
	//data->miss_read_time = bswap_64(data->miss_read_time);
	data->fstat_count = bswap_64(data->fstat_count);
	data->fstat_fail_count = bswap_64(data->fstat_fail_count);
	data->slow_fstat_count = bswap_64(data->slow_fstat_count);
	data->fstat_time = bswap_64(data->fstat_time);
	data->open_count = bswap_64(data->open_count);
	data->open_fail_count = bswap_64(data->open_fail_count);
	data->slow_open_count = bswap_64(data->slow_open_count);
	data->open_time = bswap_64(data->open_time);
	data->client_con_count = bswap_32(data->client_con_count);
	//data->app_read_latency = bswap_64(data->app_read_latency);
	//data->app_read_throughput = bswap_64(data->app_read_throughput);
	data->trans_recd_count = bswap_64(data->trans_recd_count);
	data->trans_recd_data = bswap_64(data->trans_recd_data);
	data->trans_sent_count = bswap_64(data->trans_sent_count);
	data->trans_sent_data = bswap_64(data->trans_sent_data);
	data->flush_count = bswap_64(data->flush_count);
	data->flush_data = bswap_64(data->flush_data);
#endif
}

DECLARE_PACKED_STRUCT(cache_stats_hist) {
	uint32_t hit_read_hist[HIST_SIZE]; /**< (file client) */
	uint32_t miss_read_hist[HIST_SIZE]; /**< (file client) */
	uint32_t pchit_read_hist[HIST_SIZE]; /**< page cache hits (file client) */
	uint32_t rdma_read_hist[HIST_SIZE]; /**< (file client) */
	uint32_t read_size_hist[HIST_SIZE]; /**< (file client) */
	uint32_t inflight_hist[HIST_SIZE]; /**< (file client) */
	uint32_t metadata_hist[HIST_SIZE]; /**< (file client) */
} END_PACKED_STRUCT(cache_stats_hist);

INLINE void bswap_cache_stats_hist(struct cache_stats_hist *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    int i;

    for (i=0; i<HIST_SIZE; i++) {
        data->hit_read_hist[i] = bswap32(data->hit_read_hist[i]);
        data->miss_read_hist[i] = bswap32(data->miss_read_hist[i]);
        data->pchit_read_hist[i] = bswap32(data->pchit_read_hist[i]); /**< page cache hits */
        data->rdma_read_hist[i] = bswap32(data->rdma_read_hist[i]);
        data->read_size_hist[i] = bswap32(data->read_size_hist[i]);
        data->inflight_hist[i] = bswap32(data->inflight_hist[i]);
        data->metadata_hist[i] = bswap32(data->metadata_hist[i]);
    }
#endif
}

/** Ping message between agent and CFM 
 */

DECLARE_PACKED_STRUCT(agent_ping) {
	uint64_t         loc_cnt; /* Send the number of ping's we have recieved */
    time_t           ap_quorum_heartbeat_timeout_sec;
} END_PACKED_STRUCT(agent_ping);

INLINE void bswap_agent_ping(struct agent_ping *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->loc_cnt = bswap_64(data->loc_cnt);
	data->ap_quorum_heartbeat_timeout_sec =
                            bswap_32(data->ap_quorum_heartbeat_timeout_sec);
#endif
}

/** Ping message sent by an MD to the primary CFM
 */

DECLARE_PACKED_STRUCT(md_to_cfm_ping) {
	char mcp_pad;   /* For future use */
} END_PACKED_STRUCT(md_to_cfm_ping);

INLINE void bswap_md_to_cfm_ping(struct md_to_cfm_ping *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	bswap_md_stats(&data->ping_md_stats);
#endif
}

/** Ping message sent by a CS to the primary CFM
 */

DECLARE_PACKED_STRUCT(cs_to_cfm_ping) {
	char ccp_pad;   /* For future use */
} END_PACKED_STRUCT(cs_to_cfm_ping);

INLINE void bswap_cs_to_cfm_ping(struct cs_to_cfm_ping *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
#endif
}

/** Ping message sent by a FS client to the primary CFM
 */

DECLARE_PACKED_STRUCT(fsclient_to_cfm_ping) {
    char fcp_pad;   /* For future use */
} END_PACKED_STRUCT(fsclient_to_cfm_ping);

INLINE void bswap_fsclient_to_cfm_ping(struct fsclient_to_cfm_ping *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	bswap_cache_stats(&data->ping_fsclient_stats);
#endif
}

/* Used to send protocol messages byteswapping when necessary */
/** Cache request message.
    This message causes the cache to populate and adds a reference on the cache block. If the cache
	sync_num is already created a reference is created 
 */
DECLARE_PACKED_STRUCT(cache_req) {
    uint64_t           cq_msg_id;
    rna_hash_key_t     hash_key; // 24 bytes
    /*
     * NOTE: if a new uint8_t needs to be declared, take it from cq_pad to
     * preserve alignment.
     */
	uint8_t        	   pre_cache_flag; /**< Set when message is to pre-cache it and not reference it (boolean) */
    uint8_t            write_commit_flag;
    uint8_t            orig_ref_type;
    uint8_t            cs_selection_policy;
    uint8_t            delete_restored; /**< Used to delete restored replica blocks */
    uint8_t            delete_restored_high_priority;
    uint8_t            pvt_data_len;
    uint8_t            cq_pad[1];  /**< for future use (and 64-bit alignment) */
    uint64_t           block_size;
    union {
        char           pvt_data[MAX_PVT_DATA];
        uint8_t        cq_has_client_id; // used only for master-blk CS QUERY;
                                         //   (pvt_data_len must be 0!)
    } u;
	uint32_t		   cq_page_size;
	uint64_t		   new_offset;
    uint64_t           cq_service_id_data; /**< Service ID data (only for block move)*/
    cachedev_id_t      cq_cachedev_id;     /**< MD-assigned cache device */
    cachedev_id_t      cq_repstore_id;     /**< For replica reqs;
                                             *  The ID of the replica store */
    uint64_t           cqrr_cs_rid;  /**< cqr_cs_rid from CACHE_QUERY_REQ valid
                                      *   only for CACHE_QUERY_REQ_RESPONSE */
    common_meta_data_t c;          /**< Common metadata stored by both the
                                    *   MDs and the CSs.
                                    */
    /*
     * Note: for master-blk CS QUERY, cr_path is overloaded to hold two values.
     * An rsv_client_id_t is appended immediately following the path string.
     * (Note it is appending following the EOS character of the string, so
     * the string can still be operated upon as a normal string!).
     * A 'cq_has_client_id' value of 1 indicates the presence of the
     * 'rsv_client_id_t'.
     */
    char               cr_path[PATHNAME_LEN];
} END_PACKED_STRUCT(cache_req);

INLINE void bswap_cache_req(struct cache_req *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->cq_msg_id = bswap_64(data->cq_msg_id);
	bswap_rna_hash_key_t(&data->hash_key);
	data->pvt_data_len = bswap_32(data->pvt_data_len);
	data->block_size = bswap_64(data->block_size);
	data->cq_page_size = bswap_32(data->cq_page_size);
	data->new_offset = bswap_64(data->new_offset);
	data->cq_service_id_data = bswap_64(data->cq_service_id_data);
	data->cq_repstore_id = bswap_64(data->cq_repstore_id);
    bswap_common_meta_data(&data->c);
#endif
}

/** Cache query request message.
 *
 * This message is sent by a CS to an MD to request it to send a cache
 * query(cache_req) that's apparently not been sent.  An MD can fail to send a
 * cache query if an MD failover happens after a new metadata entry has been
 * inserted into the hash table but before a cache query has been sent.
 */
DECLARE_PACKED_STRUCT(cache_query_req) {
    uint64_t              cqr_msg_id;
    uint64_t              cqr_partition_map_gen;
                                     /**< generation number of requester's
                                      *   partition_map
                                      */
    struct rna_service_id cqr_service_id; /**< Unique Service ID */
    rna_hash_key_t        cqr_hash_key; // 24 bytes
    uint64_t              cqr_md_rid;
    uint64_t              cqr_cs_rid;
    cachedev_id_t         cqr_cachedev_id;
} END_PACKED_STRUCT(cache_query_req);

INLINE void bswap_cache_query_req(struct cache_req *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->cqr_msg_id = bswap_64(data->cqr_msg_id);
	data->cqr_partition_map_gen = bswap_64(data->cqr_partition_map_gen);
    bswap_rna_service_id(&data->cqr_service_id);
	bswap_rna_hash_key_t(&data->cqr_hash_key);
#endif
}

/** Cache flush report for pub/sub (not used in write-back). 
	Indicates to client that cache data has been flushed to persistent store 

    Used only for pub/sub.  For write-back flush notifications, @see cache_flush_complete
 */
DECLARE_PACKED_STRUCT(cache_flush_rep) {
	uint64_t start; /**< Data region start */
	uint64_t end; /**< Data region end */
	char	 pvt_data[MAX_PVT_DATA]; /**< Client private data. (Associates to client file or object) */
	uint32_t pvt_data_len; /**< Client private data length */
} END_PACKED_STRUCT(cache_flush_rep);

INLINE void bswap_cache_flush_rep(struct cache_flush_rep *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->offset = bswap_64(data->offset);
	data->pvt_data_len = bswap_32(data->pvt_data_len);
#endif
}

/** Cache state query. 
	Clients can use this to query aspects about the cache block.
 */
DECLARE_PACKED_STRUCT(cache_state_query) {
	uint64_t rid; /**< Cache server RID for cache block */
	char	 pvt_data[MAX_PVT_DATA]; /**< Client private data. (Associates to client file or object) */	
	uint32_t pvt_data_len; /**< Client private data length */
	uint8_t type; /**< Query type @see cache_state_query_type */
} END_PACKED_STRUCT(cache_state_query);

INLINE void bswap_cache_state_query(struct cache_state_query *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->rid = bswap_64(data->rid);
#endif
}


/** Cache state query. 
	Clients can use this to query aspects about the cache block.
 */
DECLARE_PACKED_STRUCT(cache_state_query_resp) {
	uint64_t rid; /**< CS RID for cache block */
	uint64_t offset; /**< Current offset of committed data on storage */
	uint64_t data_to_commit; /**< Data in buffer ready to commit to storage */
	uint32_t ref_count; /**< Cache block reference count. (IE. Number of clients connected to this block) */
	uint32_t pvt_data_len; /**< Client private data length */
	char	 pvt_data[MAX_PVT_DATA]; /**< Client private data. (Associates to client file or object) */
	int8_t   status; /**< 0=OK, 1=FAIL */
	uint8_t  lock_state; /**< Cache block lock state */
} END_PACKED_STRUCT(cache_state_query_resp);


INLINE void bswap_cache_state_query_resp(struct cache_state_query_resp *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->rid = bswap_64(data->rid);
	data->offset = bswap_64(data->offset);
	data->data_to_commit = bswap_64(data->data_to_commit);	
	data->ref_count = bswap_32(data->ref_count);
	data->pvt_data_len = bswap_32(data->pvt_data_len);
#endif
}

/*
 * Flags used for ccr_flags in a cache_cfm_reg message.
 */
#define CACHE_CFM_REG_FLAG_REREGISTRATION    (1 << 0)
                                /* Set if this is NOT the CS's first
                                 * registration with a CFM since starting.
                                 * Not set if this is the CS's first
                                 * registration.
                                 */
#define CACHE_CFM_REG_FLAG_ACTIVATED         (1 << 1)
                                /* Set if this CS has already been activated */

/** Registration of a cache server with the CFM (CONF_MGR_REG_CACHE) */
DECLARE_PACKED_STRUCT(cache_cfm_reg) {
    struct rna_service_id service_id; /**< Unique Service ID */
	char	              hostname[MAX_HOST_LEN];  /* Host name for ease of use */
    uint64_t              ccr_cs_membership_generation; /**< The most recent cs membership generation number received from the primary CFM */
	uint64_t              pid;           /**< Can be used for debugging. */
	rna_addr_t	          stat_buf;
	rna_rkey_t	          stat_rkey;
	uint64_t	          max_mem;
	uint64_t              ping_buf; /** pointer for ping RDMA reads */
    uint64_t              host_total_mem; /**< Host's "total memory" */
    uint64_t              host_avail_mem; /**< Host's available memory at registration time */
    struct rna_if_table   cs_if_tbl;     /**< Network interfaces available. */
    struct cfm_md_partition_map
                          ccr_partition_map;  /**< CS's current partition map */
	rna_rkey_t            ping_rkey; /**< rkey for ping RDMA reads */
	uint32_t	          stat_length;   /**< In just for debugging / verification purposes. We can remove once verified */
	uint8_t		          byte_order;
    uint8_t               ccr_flags;  /**< See CACHE_CFM_REG_FLAG_* above */
} END_PACKED_STRUCT(cache_cfm_reg);

INLINE void bswap_cache_cfm_reg(struct cache_cfm_reg *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    bswap_rna_service_id(&data->service_id);
    data->ccr_cs_membership_generation =
                                bswap_64(data->ccr_cs_membership_generation);
	data->port = bswap_32(data->port);
	data->pid = bswap_64(data->pid);
	bswap_rna_addr_t(&data->stat_buf);
	bswap_rna_rkey_t(&data->stat_rkey);
	data->stat_length = bswap_32(data->stat_length);
	data->max_mem = bswap_64(data->max_mem);
	bswap_rna_rkey_t(&data->ping_rkey);
    data->ping_buf = bswap_64(data->ping_buf);
    data->host_total_mem = bswap_64(data->host_total_mem);
    data->host_avail_mem = bswap_64(data->host_avail_mem);
    bswap_rna_if_table(data->cs_if_table);
    bswap_cfm_md_partition_map(&data->ccr_partition_map);
#endif
}

/*
 * A response status included in a registration response message from the CFM.
 */
typedef enum cfm_reg_status_e {
    CFM_REG_RESP_OK = 0,    /* registration accepted by the CFM */
    CFM_REG_RESP_RESTART,   /* registration denied, restart */
    CFM_REG_RESP_NO_RESTART /* registration denied, do not restart */
} cfm_reg_status_t;

/** Response to a registration of a cache server with the CFM
 * (CONF_MGR_REG_CACHE_RESPONSE)
 */
DECLARE_PACKED_STRUCT(cache_cfm_reg_resp) {
    uint64_t ccrr_cs_membership_generation; /**< The most recent cs membership generation number received from the primary CFM */
    uint16_t ccrr_num_md_hash_partitions; /**< The number of MD hash partitions */
	cfm_reg_status_t ccrr_status;
} END_PACKED_STRUCT(cache_cfm_reg_resp);

INLINE void bswap_cache_cfm_reg_resp(struct cache_cfm_reg_resp *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    data->ccrr_cs_membership_generation =
                                bswap_64(data->ccrr_cs_membership_generation);
#endif
}

/** Response to a registration of a cache server with the CFM
 * (CONF_MGR_REG_CACHE_RESPONSE_V2)
 */
DECLARE_PACKED_STRUCT(cache_cfm_reg_resp_V2) {
    uint64_t ccrr_cs_membership_generation; /**< The most recent cs membership generation number received from the primary CFM */
    rna_service_id_t ccrr_service_id; /* The CS's updated service ID (with
                                       * start_time updated)
                                       */
    uint16_t ccrr_num_md_hash_partitions; /**< The number of MD hash partitions */
	cfm_reg_status_t ccrr_status;
} END_PACKED_STRUCT(cache_cfm_reg_resp_V2);

INLINE void bswap_cache_cfm_reg_resp_V2(struct cache_cfm_reg_resp_V2 *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    data->ccrr_cs_membership_generation =
                                bswap_64(data->ccrr_cs_membership_generation);
#endif
}

typedef struct query_cachedev {
    rna_store_wwn_t qc_wwn;         /* The cache device's wwn */
    uint8_t         qc_new;         /* 1 if this is a new (uninitialized) cache
                                     * device.  Otherwise 0.
                                     */
    uint8_t         qc_state;       /* If qc_new is 0, this indicates the expected
                                     * state for the device (see cl_state).
                                     */
} query_cachedev_t;


/** Query cache device message (CONF_MGR_QUERY_CACHE_DEVICE).  The CFM sends
 *  a CS the set of cache devices that it expects the CS to register.
 */
DECLARE_PACKED_STRUCT(cache_cfm_query_cachedev) {
    struct timespec  qc_timestamp;
    uint32_t         qc_num_cds;    /* Number of cache devices listed in the
                                     * qc_cds array
                                     */
    uint32_t         qc_pad;        /* For future use (and 64-bit alignment) */
    query_cachedev_t qc_cds[MAX_CACHE_DEVICES_PER_CS];
                                    /* Each cache device's world-wide name */
} END_PACKED_STRUCT(cache_cfm_query_cachedev);

INLINE void bswap_cache_cfm_query_cachedev(
                                    struct cache_cfm_query_cachedev *data)
{
    UNREFERENCED_PARAMETER(data);	
    /* NOOP, all chars */
}


/** Registration of a cache device with the CFM (CONF_MGR_REG_CACHE_DEVICE) */
DECLARE_PACKED_STRUCT(cache_cfm_reg_cachedev) {
    rna_service_register_cache_device_t rnas;
} END_PACKED_STRUCT(cache_cfm_reg_cachedev);

INLINE void bswap_cache_cfm_reg_cachedev(
                                        struct cache_cfm_reg_cachedev *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    bswap_rna_service_register_cache_device_t(&data->rnas);
#endif
}

/** End of cache device registrations with the CFM
 * (CONF_MGR_REG_CACHE_DEVICE_END)
 * */
DECLARE_PACKED_STRUCT(cache_cfm_reg_cachedev_end) {
    struct timespec  rce_timestamp;
} END_PACKED_STRUCT(cache_cfm_reg_cachedev_end);

INLINE void bswap_cache_cfm_reg_cachedev_end(
                                    struct cache_cfm_reg_cachedev_end *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
#endif
}

/** Deregistration of a cache device with the CFM (CONF_MGR_DEREG_CACHE_DEVICE)
 */
DECLARE_PACKED_STRUCT(cache_cfm_dereg_cachedev) {
    rna_service_deregister_cache_device_t rnas;
} END_PACKED_STRUCT(cache_cfm_dereg_cachedev);

INLINE void bswap_cache_cfm_dereg_cachedev(
                                        struct cache_cfm_dereg_cachedev *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    bswap_rna_service_deregister_cache_device_t(&data->rnas);
#endif
}


/** Update cache device message (CONF_MGR_UPDATE_CACHE_DEVICE)
 */
DECLARE_PACKED_STRUCT(cache_cfm_update_cachedev) {
    uint64_t               uc_resilver_request_number;
    journal_cache_device_t uc_cachedev;     /* The new state of the cache
                                             * device and all its replica
                                             * stores
                                             */
} END_PACKED_STRUCT(cache_cfm_update_cachedev);

INLINE void bswap_cache_cfm_update_cachedev(
                                    struct cache_cfm_update_cachedev *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    data->uc_resilver_request_number =
                                bswap_64(data->uc_resilver_request_number);
    bswap_journal_cache_device_t(&data->uc_cachedev);
#endif
}


/**
 * Notify the CFM that all of the cache device's unflushed dirty blocks are
 * now replicated on its replica store(s)
 * (CONF_MGR_RESILVER_CACHE_DEVICE_COMPLETE)
 */
DECLARE_PACKED_STRUCT(cache_cfm_resilver_cachedev_complete) {
    rna_service_resilver_cache_device_complete_t rnas;
} END_PACKED_STRUCT(cache_cfm_resilver_cachedev_complete);

INLINE void bswap_cache_cfm_resilver_cachedev_complete(
                            struct cache_cfm_resilver_cachedev_complete *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    bswap_rna_service_resilver_cache_device_complete(&data->rnas);
#endif
}


/**
 * CONF_MGR_RESILVER_CACHE_DEVICE_COMPLETE_RESP, which is a response to a
 * CONF_MGR_RESILVER_CACHE_DEVICE_COMPLETE
 */
DECLARE_PACKED_STRUCT(cache_cfm_resilver_cachedev_complete_resp) {
    uint64_t    req_msg_id; /**< Requester's message ID, which is returned
                             *   unchanged by the cfm
                             */
} END_PACKED_STRUCT(cache_cfm_resilver_cachedev_complete_resp);

INLINE void bswap_cache_cfm_resilver_cachedev_complete_resp(
                        struct cache_cfm_resilver_cachedev_complete_resp *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->req_msg_id = bswap_64(data->req_msg_id);
#endif
}


/** Expel cache device message (CONF_MGR_EXPEL_CACHE_DEVICE)
 */
DECLARE_PACKED_STRUCT(cache_cfm_expel_cachedev) {
    rna_service_expel_cache_device_t rnas;
} END_PACKED_STRUCT(cache_cfm_expel_cachedev);

INLINE void bswap_cache_cfm_expel_cachedev(
                                    struct cache_cfm_expel_cachedev *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    bswap_rna_service_expel_cache_device(&data->rnas);
#endif
}

/** Deregistration of a replica store with the CFM
 * (CONF_MGR_DEREG_REPLICA_STORE)
 */
DECLARE_PACKED_STRUCT(cache_cfm_dereg_repstore) {
    rna_service_deregister_replica_store_t rnas;
} END_PACKED_STRUCT(cache_cfm_dereg_repstore);

INLINE void bswap_cache_cfm_dereg_repstore(
                                    struct cache_cfm_dereg_repstore *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    bswap_rna_service_deregister_replica_store_t(&data->rnas);
#endif
}

/** Request by a CFM to a CS to aborb/delete a replica store
 * (CONF_MGR_ABSORB_REPLICA_STORE/CONF_MGR_DELETE_REPLICA_STORE)
 */
DECLARE_PACKED_STRUCT(cache_cfm_repstore) {
    cachedev_id_t   ccrs_repstore_id;       /* The ID of the replica store */
    cachedev_id_t   ccrs_host_cachedev_id;  /* The ID of the cache device that
                                             * contains the above replica store
                                             */
    cachedev_id_t   ccrs_served_cachedev_id; /* The ID of the cache device
                                              * whose blocks are replicated
                                              * in the above replica store
                                              */
    uint64_t        ccrs_resilver_request_number;
                                             /* used for
                                              * CONF_MGR_ABSORB_REPLICA_STORE
                                              * messages only.
                                              */
} END_PACKED_STRUCT(cache_cfm_repstore);

INLINE void bswap_cache_cfm_repstore(struct cache_cfm_repstore *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->ccrs_repstore_id = bswap_64(data->ccrs_repstore_id);
	data->ccrs_host_cachedev_id = bswap_64(data->ccrs_host_cachedev_id);
	data->ccrs_served_cachedev_id = bswap_64(data->ccrs_served_cachedev_id);
	data->ccrs_resilver_request_number =
                                bswap_64(data->ccrs_resilver_request_number);
#endif
}

/** CACHE_FAIL_CACHE_DEVICE/CACHE_FAIL_CACHE_DEVICE_RESP structure
 *
 * This message is sent by a client to a CS to inform the CS of a cache
 * device failure detected by the client.
 */
DECLARE_PACKED_STRUCT(cache_fail_cd) {
    cachedev_id_t cfcd_id;      /**< ID of failed cache-device */
} END_PACKED_STRUCT(cache_fail_cd);


INLINE void bswap_cache_fail_cd(struct cache_fail_cd *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    data->cfcd_id = bswap_64(data->cfcd_id);
#endif
}

typedef enum {
	CS_CONTROL_TYPE_ENABLE_DISABLE = 0,
	CS_CONTROL_TYPE_ENABLE_PATH,
	CS_CONTROL_TYPE_DISABLE_PATH,
	CS_CONTROL_TYPE_ADD_PATH,
	CS_CONTROL_TYPE_REMOVE_PATH,
    CS_CONTROL_TYPE_FLUSH_PATH,
    CS_CONTROL_TYPE_CHANGE_MODE
} cs_control_type;

/** control message from CFM to cache server
 */
DECLARE_PACKED_STRUCT(control_cs) {
    rna_service_control_cs_t rnas;
} END_PACKED_STRUCT(control_cs);

INLINE void bswap_control_cs(struct control_cs *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    bswap_rna_service_control_cs_t(&data->rnas);
#endif
}

/** control response from cache server to CFM
 */
DECLARE_PACKED_STRUCT(control_cs_resp) {
    uint32_t    type; //< type of control response;
    uint32_t    result; //< Value indicating progress or final result
    uint8_t     final;  //< non-zero indicates this is the final response
} END_PACKED_STRUCT(control_cs_resp);

INLINE void bswap_control_cs_resp(struct control_cs_resp *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->type = bswap_32(data->type);
	data->result = bswap_32(data->result);
	//uint8_t     final;
#endif
}

/*
 * Flags used for ccr_flags in a client_cfm_reg message.
 */
#define CLIENT_CFM_REG_FLAG_REREGISTRATION          (1 << 0)
                                /* Set if this is NOT the clients first
                                 * registration with a CFM since starting.
                                 * Not set if this is the client's first
                                 * registration.
                                 */
#define CLIENT_CFM_REG_FLAG_BLOCK_DEVICES_CREATED   (1 << 1)
                                /* Set if block devices (i.e. cached LUNs)
                                 * have been created by the client.
                                 */


/** Client registration with the CFM 
 */
DECLARE_PACKED_STRUCT(client_cfm_reg) {
    struct rna_service_id service_id; /**< Unique Service ID */
	struct sockaddr_in client_addr;
	char        hostname[MAX_HOST_LEN];
    struct cfm_md_partition_map
                lcr_partition_map;  /**< client's current partition map */
	rna_addr_t	stat_buf;
    // if table
    uint32_t    client_type;   /**< @see client_type enum. 0=generic/file */
	rna_rkey_t	stat_rkey;
	uint32_t	stat_length;   /**< In just for debugging / verification purposes. We can remove once verified */
	uint8_t		byte_order;
    uint8_t     lcr_flags;  /**< See CLIENT_CFM_REG_FLAG_* above */
} END_PACKED_STRUCT(client_cfm_reg);

INLINE void bswap_client_cfm_reg(struct client_cfm_reg *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    bswap_rna_service_id(&data->rna_service_id);
	bswap_sockaddr_in(&data->client_addr);
	//char        hostname[64];
	data->client_type = bswap_32(data->client_type);
	bswap_rna_addr_t(&data->stat_buf);
	bswap_rna_rkey_t(&data->stat_rkey);
	data->stat_length = bswap_32(data->stat_length);
    bswap_cfm_md_partition_map(&data->lcr_partition_map);
#endif
}

DECLARE_PACKED_STRUCT(cfm_client_resp) {
    uint32_t   per_device_connections;
	uint32_t   default_block_size;
} END_PACKED_STRUCT(cfm_client_resp);

INLINE void bswap_cfm_client_resp(struct cfm_client_resp *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->per_device_connections = bswap_32(data->per_device_connections);
	data->default_block_size = bswap_32(data->default_block_size);
#endif
}
/** Client message to the CFM when a mount is created.
 */
#define client_mount_reg rna_service_register_mount
#define bswap_client_mount_reg bswap_rna_service_register_mount_t

/** Client message to the CFM when a cache mount is unmounted.
 */
#define client_mount_dereg rna_service_deregister_mount
#define bswap_client_mount_dereg bswap_rna_service_deregister_mount_t


/** Query cache lun message (CONF_MGR_QUERY_CACHED_LUN).  The CFM sends
 *  to the CS a query message for each cached LUN that it is requesting
 *  registrations for.
 *
 *  cached LUNs do not have the requirement for batching queries and
 *  registration responses that cache devices have.  So keep this simpler.
 */
DECLARE_PACKED_STRUCT(cache_cfm_query_cached_lun) {
    cached_lun_registration_info_t qcl_info;
} END_PACKED_STRUCT(cache_cfm_query_cached_lun);

INLINE void bswap_cache_cfm_query_cached_lun(
                                    struct cache_cfm_query_cached_lun *data)
{
    /* XXX This is TBD */
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    printf("bswap_cache_cfm_query_cached_lun: not implemented yet\n");
	assert(0);
#endif
}

/** put cached lun into write-all mode (CONF_MGR_CACHED_LUN_WRITE_ALL_INITIATE).
 * The CFM sends this message to a CS to enable write-all mode on a
 * cached lun, in support of preparing for a snapshot on that cached lun.
 */
DECLARE_PACKED_STRUCT(cache_cfm_cached_lun_write_all_initiate) {
    struct rna_service_id   wai_cfm_service_id;
    uint64_t                wai_snap_time;
    rna_store_wwn_t         wai_lun_wwn;
} END_PACKED_STRUCT(cache_cfm_cached_lun_write_all_initiate);

INLINE void bswap_cache_cfm_cached_lun_write_all_initiate(
                     struct cache_cfm_cached_lun_write_all_initiate *data)
{
    /* XXX This is TBD */
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    printf("cache_cfm_cached_lun_write_all_initiate: not implemented yet\n");
    assert(0);
#endif
}

/** turn off write-all mode on a cached lun
 * CONF_MGR_CACHED_LUN_WRITE_ALL_CONCLUDE.  This is send to the cfm after
 * the snapshot on the cached lun is complete, or if we are cancelling
 * a snapshot that is in progress.
 */
DECLARE_PACKED_STRUCT(cache_cfm_cached_lun_write_all_conclude) {
    struct rna_service_id   wac_cfm_service_id;
    uint64_t                wac_snap_time;
    rna_store_wwn_t         wac_lun_wwn;
} END_PACKED_STRUCT(cache_cfm_cached_lun_write_all_conclude);
INLINE void bswap_cache_cfm_cached_lun_write_all_conclude(
                struct cache_cfm_cached_lun_write_all_conclude *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    printf"cache_cfm_cached_lun_write_all_conclude: not implemented yet\n");
    assert(0);
#endif
}


/**
 * CONF_MGR_CS_SHUTDOWN_REQ.  This message is sent by a cache server to the
 * cfm being signaled to shut down.
 */
DECLARE_PACKED_STRUCT(cache_cfm_shutdown_req) {
    rna_service_cs_shutdown_request_t rnas;
} END_PACKED_STRUCT(cache_cfm_shutdown_req);

INLINE void bswap_cache_cfm_shutdown_req(struct cache_cfm_shutdown_req *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    bswap_rna_service_cs_shutdown_request(&data->rnas);
#endif
}


/**
 * CONF_MGR_CS_SHUTDOWN_RESP.  This message is sent by the primary CFM to
 * a cache server that has requested to be allowed a graceful shut down.
 */
DECLARE_PACKED_STRUCT(cache_cfm_shutdown_resp) {
    uint64_t    req_msg_id; /**< Requester's message ID, which is returned
                             *   unchanged by the cfm
                             */
    uint8_t     sr_success;
} END_PACKED_STRUCT(cache_cfm_shutdown_resp);

INLINE void bswap_cache_cfm_shutdown_resp(struct cache_cfm_shutdown_resp *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->req_msg_id = bswap_64(data->req_msg_id);
#endif
}


/**
 * CONF_MGR_CFM_SHUTDOWN_STATUS.  This message is sent by a peer cfm to the
 * primary cfm to indicate whether it has a shutdown request outstanding.
 */
DECLARE_PACKED_STRUCT(cfm_shutdown_status) {
    shutdown_state_t    csr_shutdown_state;
} END_PACKED_STRUCT(cfm_shutdown_status);


/**
 * CONF_MGR_CFM_SHUTDOWN_GRANT.  This message is sent by the primary CFM to
 * a peer CFM that has requested to be allowed a graceful shut down.
 */
DECLARE_PACKED_STRUCT(cfm_shutdown_grant) {
    uint64_t     csrr_pad;
} END_PACKED_STRUCT(cfm_shutdown_grant);


// Begin SCSI III reservation messages

/**
 * CONF_MGR_CS_UPDATE_SCSI_ITN_RES,
 * This message is sent by a cache server to the CFM to journal
 * SCSI III reservation state for a LUN.
 *
 * The primary CFM in turn retuns a message of type
 * CONF_MGR_CS_UPDATE_CLEAR_SCSI_ITN_RES_RESP to signal that the
 * requested changes are committed to the journal.
 */
DECLARE_PACKED_STRUCT(cache_cfm_update_scsi_itn_reservation) {
    rna_service_update_scsi_itn_reservation_t rnas;
} END_PACKED_STRUCT(cache_cfm_update_scsi_itn_reservation);

INLINE void bswap_cache_cfm_update_scsi_itn_reservation_t(
    cache_cfm_update_scsi_itn_reservation_t *data) 
{
        UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    bswap_rna_service_update_scsi_itn_reservation_t(&data->rnas);
#endif
}

/**
 * CONF_MGR_CS_UPDATE_SCSI_ITN_REG,
 * This message is sent by a cache server to the CFM to journal
 * SCSI III client registration state for a LUN.
 *
 * The primary CFM in turn retuns a message of type
 * CONF_MGR_CS_UPDATE_CLEAR_SCSI_ITN_RES_RESP to signal that the
 * requested changes are committed to the journal.
 */
DECLARE_PACKED_STRUCT(cache_cfm_update_scsi_itn_registration) {
    rna_service_update_scsi_itn_registration_t rnas;
} END_PACKED_STRUCT(cache_cfm_update_scsi_itn_registration);

INLINE void bswap_cache_cfm_update_scsi_itn_registration_t(
    cache_cfm_update_scsi_itn_registration_t *data) 
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    bswap_rna_service_update_scsi_itn_registration_t(&data->rnas);
#endif
}

/**
 * CONF_MGR_CS_CLEAR_SCSI_ITN_RES,
 * This message is sent by a cache server to the CFM to clear SCSI III
 * reservation and all client registrations for a LUN from the journal;
 *
 * The primary CFM in turn retuns a message of type
 * CONF_MGR_CS_UPDATE_CLEAR_SCSI_ITN_RES_RESP to signal that the
 * requested changes are committed to the journal.
 */
DECLARE_PACKED_STRUCT(cache_cfm_clear_scsi_itn_reservation) {
    rna_service_clear_scsi_itn_reservation_t   rnas;
} END_PACKED_STRUCT(cache_cfm_clear_scsi_itn_reservation);

INLINE void bswap_cache_cfm_clear_scsi_itn_reservation_t(
    cache_cfm_clear_scsi_itn_reservation_t *data) 
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    bswap_rna_service_clear_scsi_itn_reservation_t(&data->rnas);
#endif
}

/**
 * CONF_MGR_CS_ACQUIRE_SCSI_ITN_RES,
 * This message is sent by a cache server to the CFM to retrieve SCSI III
 * reservation state for a LUN from the journal.
 *
 * The requested info information is returned in a
 * CONF_MGR_CS_ACQUIRE_SCSI_ITN_RES_RESP message.
 */
DECLARE_PACKED_STRUCT(cache_cfm_acquire_scsi_itn_res) {
    rna_service_acquire_scsi_itn_res_t   rnas;
} END_PACKED_STRUCT(cache_cfm_acquire_scsi_itn_res);

INLINE void bswap_cache_cfm_acquire_scsi_itn_reservation_t(
    cache_cfm_clear_scsi_itn_reservation_t *data) 
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    bswap_rna_service_clear_scsi_itn_reservation_t(&data->rnas);
#endif
}

/**
 * CONF_MGR_CS_ACQUIRE_SCSI_ITN_REG,
 * This message is sent by a cache server to the CFM to retrieve SCSI III
 * registration state for a LUN, LUN client pair from the journal.
 *
 * The requested info information is returned in a
 * CONF_MGR_CS_ACQUIRE_SCSI_ITN_REG_RESP message.
 */
DECLARE_PACKED_STRUCT(cache_cfm_acquire_scsi_itn_reg) {
    rna_service_acquire_scsi_itn_reg_t rnas;
} END_PACKED_STRUCT(cache_cfm_acquire_scsi_itn_reg);

INLINE void bswap_cache_cfm_acquire_scsi_itn_reg_t(
    cache_cfm_acquire_scsi_itn_reg_t *data) 
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    bswap_rna_service_clear_scsi_itn_registration_t(&data->rnas);
#endif
}

/**
 * CONF_MGR_CS_UPDATE_CLEAR_SCSI_ITN_RES_RESP,
 * This message is sent by the primary CFM to a cache server to
 * indicate that the journal update or clear request of SCSI III
 * reservation and/or registration state has completed.
 * It is a common response for the CONF_MGR_CS_UPDATE_SCSI_ITN_RES,
 * CONF_MGR_CS_UPDATE_SCSI_ITN_REG, and CONF_MGR_CS_CLEAR_SCSI_ITN_RES
 * messages above.
 */
DECLARE_PACKED_STRUCT(cache_cfm_update_clear_scsi_itn_resg_resp) {
    rna_service_update_clear_scsi_itn_resg_resp_t rnas;
} END_PACKED_STRUCT(cache_cfm_update_clear_scsi_itn_resg_resp);

INLINE void bswap_cache_cfm_update_clear_scsi_itn_resg_resp_t(
    cache_cfm_update_clear_scsi_itn_resg_resp_t *data) 
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    bswap_rna_service_update_clear_scsi_itn_resg_resp_t(&data->rnas);
#endif
}

/**
 * CONF_MGR_CS_ACQUIRE_SCSI_ITN_RES_RESP,
 * This message is sent by the primary CFM to a cache server to
 * return SCSI III reservation.  It is sent in response to a
 * CONF_MGR_CS_ACQUIRE_SCSI_ITN_RES message.
 */
DECLARE_PACKED_STRUCT(cache_cfm_acquire_scsi_itn_res_resp) {
    rna_service_acquire_scsi_itn_res_resp_t  rnas;
} END_PACKED_STRUCT(cache_cfm_acquire_scsi_itn_res_resp);

INLINE void bswap_cache_cfm_acquire_scsi_itn_res_resp_t(
    cache_cfm_acquire_scsi_itn_res_resp_t *data) 
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    bswap_rna_service_acquire_scsi_itn_res_resp_t(&data->rnas);
#endif
}


/**
 * CONF_MGR_CS_ACQUIRE_SCSI_ITN_REG_RESP,
 * This message is sent by the parimary CFM to a cache server to
 * return SCSI III registration for a LUN, LUN client pair.  It is sent
 * in response to a CONF_MGR_CS_ACQUIRE_SCSI_ITN_REG message.
 */
DECLARE_PACKED_STRUCT(cache_cfm_acquire_scsi_itn_reg_resp) {
    rna_service_acquire_scsi_itn_reg_resp_t  rnas;
} END_PACKED_STRUCT(cache_cfm_acquire_scsi_itn_reg_resp);

INLINE void bswap_cache_cfm_acquire_scsi_itn_reg_resp_t(
    cache_cfm_acquire_scsi_itn_reg_resp_t *data) 
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    bswap_rna_service_acquire_scsi_itn_reg_resp_t(&data->rnas);
#endif
}

/** Storage path registration amongst CS/CFM/MD
 */
DECLARE_PACKED_STRUCT(path_reg) {
    rna_service_register_path_t rnas;
}END_PACKED_STRUCT(path_reg);
#define bswap_path_reg bswap_rna_service_register_path_t
 
typedef enum {
    RNA_VOL_NORMAL      = 0,
    RNA_VOL_LOWSPACE    = 1,
    RNA_VOL_OUTOFSPACE  = 2
} rna_volspace_status;

/** Block device create message from CFM to block client
 */
DECLARE_PACKED_STRUCT(client_create_block_device) {
    char        name[MAX_NAME_LEN]; //< Bare name, not a path
    uint64_t    capacity;           //< MB
    uint64_t    ref_block_target; /**< used to set total target */
    uint64_t    read_ref_block_target; /**< used to set read target */
    uint64_t    write_ref_block_target; /**< used to set write target */
    uint64_t    read_ref_block_limit; /**< used to set read limit */
    uint64_t    ref_block_limit; /**< used to set total limit */
    uint64_t    write_ref_block_limit; /**< used to set write limit */
    uint64_t    ccb_master_block_id;  /**< master_block_id for LUN */
    uint32_t    default_block_size;   /**< desired cache block size (bytes) */
    uint32_t    persist_access_uid; /**< uid used to access persistent storage */
    uint32_t    persist_access_gid; /**< gid used to access persistent storage */
    uint32_t    path_md_policy;    /* md client affinity policy enum */
    uint8_t     shared;
    uint8_t     ccb_das;            /**< TRUE if the device is in single node  mode */
    uint8_t     thin_status;        /**< rna_volspace_status */ 
    char        persist_location[PATHNAME_LEN];  /**< Pathname to persistent storage for device */
    char        class_name[MAX_NAME_LEN]; //< Bare name, not a path
    char        class_params[MAX_NAME_LEN]; //< param string
} END_PACKED_STRUCT(client_create_block_device);

INLINE void bswap_client_create_block_device(struct client_create_block_device *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    //char        name[MAX_NAME_LEN];
    data->capacity = bswap_64(data->capacity);
    data->read_ref_block_target = bswap_64(data->read_ref_block_target);
    data->write_ref_block_target = bswap_64(data->write_ref_block_target);
    data->read_ref_block_limit = bswap_64(data->read_ref_block_limit);
    data->write_ref_block_limit = bswap_64(data->write_ref_block_limit);
    data->default_block_size = bswap_32(data->default_block_size);
    data->persist_access_uid = bswap_32(data->persist_access_uid);
    data->persist_access_gid = bswap_32(data->persist_access_gid);
    data->path_md_policy = bswap_32(data->path_md_policy);
    //uint_8      shared;
#endif
}

/** Block device control message from CFM to block client
 */
DECLARE_PACKED_STRUCT(client_control_block_device) {
    uint32_t    type; //< type of control; flush, stop, delete
    char        name[MAX_NAME_LEN]; //< Bare name, not a path
} END_PACKED_STRUCT(client_control_block_device);

INLINE void bswap_client_control_block_device(struct client_control_block_device *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->type = bswap_32(data->type);
    //char        name[MAX_NAME_LEN];
#endif
}

/** Block device control response from block client to CFM
 */
DECLARE_PACKED_STRUCT(client_control_block_device_resp) {
    uint32_t    type; //< type of control response; flush, stop, delete
    uint32_t    result; //< Value indicating progress or final result
    uint8_t     final;  //< non-zero indicates this is the final response
    char        name[MAX_NAME_LEN]; //< Bare name, not a path
} END_PACKED_STRUCT(client_control_block_device_resp);

INLINE void bswap_client_control_block_device_resp(struct client_control_block_device_resp *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->type = bswap_32(data->type);
	data->result = bswap_32(data->result);
	//uint8_t     final;
    //char        name[MAX_NAME_LEN];
#endif
}

/** Client message to the CFM when a block device has been or is being created
 */
DECLARE_PACKED_STRUCT(client_block_device_reg) {
	uint64_t    req_msg_id; /**< Requester's message ID, which is ignored and
                             *   returned unchanged by the cfm
                             */
    rna_service_register_block_device_t
                rnas;
    /*
     * Since the above struct ends with a variable-length pathname, the purpose
     * of the following field is to pad this struct out to its maximum possible
     * size, so sizeof(struct cache_cmd) returns the maximum size of any
     * cache_cmd.
     */
    char            __name[PATHNAME_LEN-1];
} END_PACKED_STRUCT(client_block_device_reg);

INLINE void bswap_client_block_device_reg(struct client_block_device_reg *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->req_msg_id = bswap_64(data->req_msg_id);
    bswap_rna_service_register_block_device_t(&data->rnas);
#endif
}

/** Client generic asynchronous event message to the CFM 
 */
DECLARE_PACKED_STRUCT(client_notification_event) {
	uint32_t    event; /** event ID generated by client */
	uint64_t    cookie; /** cookie from cfm soap context */
    char        persist_location[PATH_MAX+1];
} END_PACKED_STRUCT(client_notification_event);

INLINE void bswap_client_notification_event(struct client_notification_event *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->event = bswap_32(data->event);
	data->cookie = bswap_64(data->cookie);
#endif
}

/** CFM response to the client (client_block_device_reg) indicating
 * that the requested device can be created, or acknowledging the
 * registration of an existing device (e.g. after a CFM reconnect)
 */
DECLARE_PACKED_STRUCT(client_block_device_reg_resp) {
    uint64_t    req_msg_id; /**< Requester's message ID, which is ignored and
                             *   returned unchanged by the cfm
                             */
    rna_service_register_block_device_response_t
                rnas;
} END_PACKED_STRUCT(client_block_device_reg_resp);

INLINE void bswap_client_block_device_reg_resp(struct client_block_device_reg_resp *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->req_msg_id = bswap_64(data->req_msg_id);
    data->capacity = bswap_32(data->capacity);
    //uint_8      available;
#endif
}

/*
 * Flags used in the mcr_flags field
 */
#define MCR_FLAG_PARTITIONS_ASSIGNED    (1 << 0)
                                /* Set if the MD believes it has metadata
                                 * partitions assigned to it
                                 */
#define MCR_FLAG_REREGISTRATION         (1 << 1)
                                /* Set if this is NOT the clients first
                                 * registration with a CFM since starting.
                                 * Not set if this is the client's first
                                 * registration.
                                 */

/** Client message to the CFM when a block device has been deleted
 */
#define client_block_device_dereg rna_service_deregister_block_device
#define bswap_client_block_device_dereg bswap_rna_service_deregister_block_device_t

/** Registration of a metadata server with the CFM
 */
DECLARE_PACKED_STRUCT(md_cfm_reg) {
    struct rna_service_id service_id; /**< Unique Service ID */
	char	              hostname[MAX_HOST_LEN];  /**< Host name for ease of use */
	uint64_t              pid;           /**< Can be used for debugging. */
	rna_addr_t	          stat_buf;
	rna_rkey_t	          stat_rkey;
	uint32_t	          stat_length;   /**< In just for debugging / verification purposes. We can remove once verified */
	uint32_t              port;          /**< Local port being used for cache */
	rna_rkey_t            ping_rkey; /**< rkey for ping RDMA reads */
	rna_addr_t	          ping_buf; /**< pointer for ping RDMA reads */
    uint64_t              mcr_cs_membership_generation; /**< The most recent cs membership generation number received from the primary CFM */
	struct rna_if_table   md_if_tbl;     /**< Network interfaces available. */
    struct cfm_md_partition_map mcr_partition_map;  /**< MD's current partition map */
    uint16_t              mcr_ordinal; /**< MD's ordinal if known, otherwise NULL_MD_ORDINAL */
	uint8_t		          mcr_flags;
	uint8_t		          byte_order;
} END_PACKED_STRUCT(md_cfm_reg);

INLINE void bswap_md_cfm_reg(struct md_cfm_reg *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    bswap_rna_service_id(&data->rna_service_id);
	data->port = bswap_32(data->port);
	data->configured_port = bswap_32(data->configured_port);
	data->pid = bswap_64(data->pid);
	bswap_rna_addr_t(&data->stat_buf);
	bswap_rna_rkey_t(&data->stat_rkey);
	data->stat_length = bswap_32(data->stat_length);
    bswap_rna_if_table(data->md_if_tbl);
	bswap_rna_rkey_t(&data->ping_rkey);
    data->ping_buf = bswap_64(data->ping_buf);
    data->ping_buf = bswap_16(data->mcr_ordinal);
    bswap_cfm_md_partition_map(&data->mcr_partition_map);
#endif
}

/** Response to a registration of a metadata server with the CFM
 * (CONF_MGR_REG_MD_RESPONSE)
 */
DECLARE_PACKED_STRUCT(md_cfm_reg_resp) {
    uint64_t         mcrr_cs_membership_generation;
                                            /* The most recent cs membership
                                             * generation number received from
                                             * the primary CFM
                                             */
	cfm_reg_status_t mcrr_status;
	int              mcrr_paxos_use_tcp;
} END_PACKED_STRUCT(md_cfm_reg_resp);

INLINE void bswap_md_cfm_reg_resp(struct md_cfm_reg_resp *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    int i;

    data->mcrr_cs_membership_generation =
                                bswap_64(data->mcrr_cs_membership_generation);
    data->mcrr_status = bswap_32(data->mcrr_status);
    data->mcrr_paxos_use_tcp = bswap_32(data->mcrr_paxos_use_tcp);
#endif
}

/** A message from the primary CFM, containing the current set of unexpelled
 * cache devices, together with the next available cache device ID
 * (CONF_MGR_UNEXPELLED_CACHEDEVS).
 */
DECLARE_PACKED_STRUCT(cfm_unexpelled_cachedevs) {
    rna_service_unexpelled_cachedevs_t  uc;
} END_PACKED_STRUCT(cfm_unexpelled_cachedevs);

INLINE void bswap_cfm_unexpelled_cachedevs(
                                    struct cfm_unexpelled_cachedevs *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    bswap_rna_service_unexpelled_cachedevs(&data->uc);
#endif
}

DECLARE_PACKED_STRUCT(cfm_control) {
	uint32_t            type;
    union {
        struct {
            gboolean    stop_cfm;
            gboolean    just_unload_driver;
        } agent_shutdown;
        struct {
            uint32_t    log_level;
        }       set_log_level;
		struct {
			char     config_patch[RFT_FILENAME_LEN];
		} filename;
        struct {
            uint32_t      ccg_config_gen;
			unsigned char _pad[4];
            unsigned char md5[16];
            time_t        mtime;
            time_t        time;
	        unsigned char _pad2[4];
            uint32_t      cfm_count;
            struct sockaddr_in cfm_addr_tbl[MAX_NET_IF];
            int           cfm_com_type_tbl[MAX_NET_IF];
        } generation;
        struct {
            uint64_t      cdc_eph;
            uint32_t      cdc_gen;
        } cca_drop_connection;
        struct {
            time_t        phc_time;
            unsigned char phc_hostname[MAX_HOST_LEN];
            unsigned char phc_type[8];
            unsigned char phc_collect_args[MAX_NAME_LEN];
            unsigned char phc_id[MAX_NAME_LEN];
        } cc_phonehome_control;
    }        arg;
} END_PACKED_STRUCT(cfm_control);

INLINE void bswap_cfm_control(struct cfm_control *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->type = bswap_32(data->type);
	data->arg.cca_drop_connection.cdc_eph =
        bswap_64(data->arg.cca_drop_connection.cdc_eph);
	data->arg.cca_drop_connection.cdc_gen =
        bswap_32(data->arg.cca_drop_connection.eph_gen);
#endif
}

/*
 * A message sent by a recipient of a cfm_control message to indicate that the
 * sender of the cfm_control appears to no longer be the primary CFM.  The ID
 * of the more recent primary CFM is included in the message.
 */
DECLARE_PACKED_STRUCT(cfm_control_reject) {
    primary_cfm_id_t  ccr_rejected_id;   /* The CFM ID that's being rejected */
} END_PACKED_STRUCT(cfm_control_reject);

INLINE void bswap_cfm_control_reject(struct cfm_control_reject *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	bswap_primary_cfm_id_t(&data->ccr_primary_cfm_id);
#endif
}


/** Sent to the cfm to request a configuration. Configuration files are assigned
    by the hostname and group name.
 */
DECLARE_PACKED_STRUCT(cfm_config_get) {
	char	              hostname[MAX_HOST_LEN];  /**< Host name of entity. */ 
    struct rna_service_id service_id;
} END_PACKED_STRUCT(cfm_config_get);

INLINE void bswap_cfm_config_get(struct cfm_config_get *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	//char	    hostname[64];  /* Host name for ease of use */ 
    bswap_rna_service_id(&data->rna_service_id);
#endif
}

/** Configuration file information sent as a response to the cfm_config_get message.
    The configuration files can be read via the RFT commands. 
 */
DECLARE_PACKED_STRUCT(cfm_config_resp) {
	uint8_t res;
	char    cfg_file[PATHNAME_LEN];	
	char    policy_file[PATHNAME_LEN];	
} END_PACKED_STRUCT(cfm_config_resp);

INLINE void bswap_cfm_config_resp(struct cfm_config_resp *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	//uint8_t res;
	//char    cfg_file[PATHNAME_LEN];	
	//char    policy_file[PATHNAME_LEN];	
#endif
}

/** Request cache statistics from a cache server.
    (In RDMA enabled environments the cache stats can be read directly. This provides 
	support for reading the stats via send/recv messages)
 */
DECLARE_PACKED_STRUCT(cache_stats_req) {
	uint32_t type;
} END_PACKED_STRUCT(cache_stats_req);

/* 
	NOTE: We only need to swap cache stats if the byteordering of the remote host is different then 
	      the CFM. Otherwise the bytes will be misordered since they are not standardized on little endian
*/
INLINE void bswap_cache_stats_req(struct cache_stats_req *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->type = bswap_32(data->type);
#endif
}

INLINE void bswap_blkdev_stats(struct blkdev_stats *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    int i;
    data->writes = bswap_64(data->writes);
    data->reads = bswap64(data->reads);
    data->sends = bswap64(data->sends);
    data->queries = bswap64(data->queries);
    data->in_queue = bswap64(data->in_queue);
    data->hist_queue_usage = bswap64(data->hist_queue_usage);
    data->retries = bswap64(data->retries);
    data->failed_blocks = bswap64(data->failed_blocks);
    for (i=0; i<BLKDEV_STATS_HISTORY_COUNT; i++) {
        data->histo[i] = bswap64(data->histo[i]);
    }
    data->bytes_out = bswap64(data->bytes_out);
    data->bytes_in = bswap64(data->bytes_in);
#endif
}

DECLARE_PACKED_STRUCT(hist_stats) {
	uint32_t hit_read_hist[HIST_SIZE]; /**< (file client) */
	uint32_t miss_read_hist[HIST_SIZE]; /**< (file client) */
	uint32_t pchit_read_hist[HIST_SIZE]; /**< page cache hits (file client) */
	uint32_t rdma_read_hist[HIST_SIZE]; /**< (file client) */
	uint32_t read_size_hist[HIST_SIZE]; /**< (file client) */
	uint32_t inflight_hist[HIST_SIZE]; /**< (file client) */
	uint32_t metadata_hist[HIST_SIZE]; /**< (file client) */
} END_PACKED_STRUCT(hist_stats);

/* Flags used in the cr_flags field */
#define CACHE_REP_FLAG_RESEND   0x1
                            /* This message is a re-send */

/** cache server's reply to cache request 
 */
DECLARE_PACKED_STRUCT(cache_rep) {
	uint64_t	  cr_msg_id;/**< Message ID, which is ignored and returned
                            * unchanged by the metadata server
							*/
    uint64_t      cr_gen;   /**< generation number of requester's partition_map */
    cachedev_id_t cr_store_id; /**< Cache device ID.  Will be a replica ID
                                 *  in response to replica requests */
    /*
     * =====================================================================
     * NOTE that new fields for this struct should either be added to the
     * rna_service_cache_response_t (in rna_service.h) or should be added
     * above this point.  Fields should be added in such a way that alignment
     * is maintained for 32-bit and 64-bit fields.
     * =====================================================================
     */
    rna_service_cache_response_t
                  rnas;
    /*
     * Since the above struct ends with a variable-length pathname, the purpose
     * of the following field is to pad this struct out to its maximum possible
     * size, so sizeof(struct cache_cmd) returns the maximum size of any
     * cache_cmd.
     */
    uint8_t       cr_flags;
    char          __pathname_pad[PATHNAME_LEN-1];
} END_PACKED_STRUCT(cache_rep);

INLINE void bswap_cache_rep(struct cache_rep *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->cr_msg_id = bswap_64(data->cr_msg_id);
	data->cr_gen = bswap_64(data->cr_gen);
	data->cache_buf = bswap_64(data->cache_buf);
	bswap_rna_rkey_t(&data->rkey);
	data->length = bswap_32(data->length);
	data->rid = bswap_64(data->rid);
	data->cookie = bswap_64(data->cookie);
	//uint8_t     cache_type;
	//uint8_t		lock_type;/* read_shared or write_exclusive */	
	data->reader_uid = bswap_32(data->reader_uid);
	data->reader_gid = bswap_32(data->reader_gid);
	data->block_number = bswap_64(data->block_number);
	data->block_size = bswap_64(data->block_size);
	data->mem_locked = bswap_64(data->mem_locked);
	data->mem_locked_gen = bswap_64(data->mem_locked_gen);
	data->mem_used = bswap_64(data->mem_used);
	data->mem_used_gen = bswap_64(data->mem_used_gen);
	//char           pathname[PATHNAME_LEN];	
	bswap_rna_hash_key_t(&data->path_key);
	data->pvt_data_len = bswap_32(data->pvt_data_len);
	//char	 		pvt_data[MAX_PVT_DATA];		
	data->mtime_sec = bswap_64(data->mtime_sec);
	data->mtime_nsec = bswap_64(data->mtime_nsec);
	data->file_size = bswap_64(data->file_size);
	data->cache_pid = bswap_64(data->cache_pid);
	//char           pathname[PATHNAME_LEN];	
#endif
}

/** metadata server's reply to a cache_rep
 */
DECLARE_PACKED_STRUCT(cache_rep_rep) {
	uint64_t	crr_msg_id;/**< The cr_msg_id from the cache_rep */
}END_PACKED_STRUCT(cache_rep_rep);

INLINE void bswap_cache_rep_rep(struct cache_rep_rep *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->crr_msg_id = bswap_64(data->crr_msg_id);
#endif
}

/** Cache data send to the cache server. Used in publish subscribe mode of
 * operation 
 */
DECLARE_PACKED_STRUCT(cache_data_write) {
	uint64_t rid;        /**< Returned from the cache query. */
	uint64_t offset;     /**< Offset into the file */
	uint64_t length;     /**< payload length */
	uint8_t resp_req;    /**< Response from the CS required once all clients have been updated */
	uint8_t multi_write_msg;    /**< Indicates that this message is of a multi-writer variety. */
	/**< NOTE NOTE: This should be the last field in the structure */
	
	uint8_t data[MAX_DATA_WRITE_PAYLOAD];  /* Payload */

} END_PACKED_STRUCT(cache_data_write);

INLINE void bswap_cache_data_write(struct cache_data_write *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->rid = bswap_64(data->rid);
	data->offset = bswap_64(data->offset);
	data->length = bswap_64(data->length);
#endif
}

#define SCSI_MAX_CMD_LEN    16
#define SCSI_MAX_SENSE_LEN  16
#define SCSI_MAX_DATA_PAYLOAD   TCP_DATA_PAYLOAD_LEN

DECLARE_PACKED_STRUCT(cache_scsi_passthru_resp) {
    uint8_t cs_status;                // cache_resp_code
    uint8_t op_status;                // operation status
                                      // (currently a Linux errno value
                                      //  -- this is going to need changing
                                      // in order to also support Windows!)
    uint8_t scsi_status;
    uint8_t sense_length;
    uint32_t xferd_length;
    uint8_t sense[SCSI_MAX_SENSE_LEN];
    /* last field */
    uint8_t data[SCSI_MAX_DATA_PAYLOAD];
} END_PACKED_STRUCT(cache_scsi_passthru_resp);

INLINE void bswap_cache_scsi_passthru_resp(
                            struct cache_scsi_passthru_resp *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->xferd_length = bswap_32(data->xferd_length);
#endif
}

DECLARE_PACKED_STRUCT(cache_scsi_passthru) {
    rsv_itn_id_t itn_id;
    uint64_t rid;
    uint8_t cmd_len;
    uint8_t writing;
    uint8_t reset_action;  /* this is part of LUN reset */
    uint8_t has_itn_id;
    uint32_t xfer_length;
    uint8_t scsi_command[SCSI_MAX_CMD_LEN];
    /* last field */
    struct cache_scsi_passthru_resp response;
} END_PACKED_STRUCT(cache_scsi_passthru);

INLINE void bswap_cache_scsi_passthru(struct cache_scsi_passthru *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->rid = bswap_64(data->rid);
	data->xfer_length = bswap_32(data->xfer_length);
#endif
}

/*
 * cache_scsi_unitattn.csu_ua_code values.
 *   Notes:
 *      The SAM4 spec says these UNIT ATTENTION conditions are all of equal
 *      precedence.  However, note our implementation will effectively impose
 *      a precedence in reporting; lower values will be reported first...
 */
#define UA_INVALID                      0   // treat 0 as an invalid value!
#define UA_LOW_SPACE                    1   // asc=0x38/ascq=0x7
                                            // Thin Provisioning Soft
                                            //  Threshold Reached
#define UA_RESERVATIONS_PREEMPTED       2   // asc=0x2a/ascq=0x3
#define UA_RESERVATIONS_RELEASED        3   // asc=0x2a/ascq=0x4
#define UA_REGISTRATIONS_PREEMPTED      4   // asc=0x2a/ascq=0x5

DECLARE_PACKED_STRUCT(cache_scsi_unitattn) {
    uint8_t         csu_ua_code;
    uint8_t         csu_n_itns;
    uint8_t         csu_pad[2];
    rsv_itn_id_t    csu_itn_list[MAX_PER_CLIENT_INITIATORS];
    /*
     * Keep variable length csu_pathname at end of structure!
     */
    char            csu_pathname[PATHNAME_LEN];
} END_PACKED_STRUCT(cache_scsi_unitattn);


INLINE void bswap_cache_scsi_unitattn(struct cache_scsi_unitattn *data)
{
    UNREFERENCED_PARAMETER(data);
#if CPU_BE
    /* nothing to swap currently */
#endif
}

/** Cache reference activate. Used in publish subscribe mode of operation to enable dynamic 
    updates. Sent by the client after processing the cache_rep message.
 */
DECLARE_PACKED_STRUCT(cache_ref_activate) {
	uint64_t rid;        /** Returned from the cache query. */
	uint64_t file_size;
	uint32_t page_size;
	uint8_t  no_sync_flag; /** Don't resend any data, just send new data */
} END_PACKED_STRUCT(cache_ref_activate);


INLINE void bswap_cache_ref_activate(struct cache_ref_activate *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->rid = bswap_64(data->rid);
#endif
}

/** Cache data ready message. (Sent from the cache server to subscribers)
 */
DECLARE_PACKED_STRUCT(cache_data_ready) {
	uint64_t rid;
	uint64_t offset;
	uint64_t length;
	char	 pvt_data[MAX_PVT_DATA];
	uint32_t pvt_data_len;
	uint8_t  multi_writer_msg;
	uint8_t  pad[3];  // for future use
	
	/* NOTE NOTE: This should be the last field in the structure */
	uint8_t data[MAX_DATA_WRITE_PAYLOAD];

} END_PACKED_STRUCT(cache_data_ready);

INLINE void bswap_cache_data_ready(struct cache_data_ready *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->offset = bswap_64(data->offset);
	data->length = bswap_64(data->length);
	//data->data
	data->length = bswap_64(data->length);
	data->pvt_data_len = bswap_32(data->pvt_data_len);
#endif
}

/** Read file data via the cache server.
    Note: This is used in publish/subscribe mode of operation to sync the client with
	      the cache server. 
 */
DECLARE_PACKED_STRUCT(cache_data_read) {
	uint64_t	cookie;
	rna_addr_t	cache_buf;
	rna_rkey_t	rkey;
	uint32_t	length;
	uint64_t    offset;
	uint64_t    rid; /** Cache record ID. */
	char	 	pvt_data[MAX_PVT_DATA];
	uint32_t	pvt_data_len;
} END_PACKED_STRUCT(cache_data_read);

INLINE void bswap_cache_data_read(struct cache_data_read *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->cookie = bswap_64(data->cookie);
	bswap_rna_addr_t(&data->cache_buf);
	bswap_rna_rkey_t(&data->rkey);
	data->length = bswap_32(data->length);
	data->offset = bswap_64(data->offset);
	data->rid = bswap_64(data->rid);
	//char	 	pvt_data[MAX_PVT_DATA];
	data->pvt_data_len = bswap_32(data->pvt_data_len);
#endif
}

/** cache server's reply to cache request 
 */
DECLARE_PACKED_STRUCT(cache_data_read_resp) {
	uint64_t	cookie;
	uint32_t    segment;
	uint32_t    status;
	char	 	pvt_data[MAX_PVT_DATA];
	uint32_t	pvt_data_len;
	uint32_t	data_len;
	char	 	data[TCP_DATA_PAYLOAD_LEN];	
} END_PACKED_STRUCT(cache_data_read_resp);

INLINE void bswap_cache_data_read_resp(struct cache_data_read_resp *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->cookie = bswap_64(data->cookie);
	data->segment = bswap_32(data->segment);
	data->status = bswap_32(data->status);
	//char	 	pvt_data[MAX_PVT_DATA];
	data->pvt_data_len = bswap_32(data->pvt_data_len);
	data->data_len = bswap_32(data->data_len);
	//char	 	data[TCP_DATA_PAYLOAD_LEN];	
#endif
}

/* Flags used in the ci_flags field */
#define CACHE_INVD_FLAG_RESEND   0x1
                            /* This message is a re-send */

/** invalidate cache for given file 
 */
DECLARE_PACKED_STRUCT(cache_invd) {
    uint64_t        req_msg_id; /**< Requester's message ID, which is returned
                                 *   unchanged by the metadata server
                                 */
    uint64_t        invd_gen;   /**< generation number of requester's
                                 *   partition_map
                                 */
    rna_hash_key_t  hash_key;   /**< MD5 of the pathname. 24 bytes */
    uint8_t 	    ack_required;
    uint8_t         cleanup_required;
    uint8_t         ci_flags;
    uint8_t         pad[5];     /**< For future use (and for 64-bit alignment)*/
    /*
     * =====================================================================
     * NOTE that new fields for this struct should either be added to the
     * rna_service_cache_invalidate_t (in rna_service.h) or should be added
     * above this point.  Fields should be added in such a way that alignment
     * is maintained for 32-bit and 64-bit fields.
     * =====================================================================
     */
    rna_service_cache_invalidate_t
                    rnas;       /**< MUST BE LAST (variable-size struct) */
    /*
     * Since the above struct ends with a variable-length pathname, the purpose
     * of the following field is to pad this struct out to its maximum possible
     * size, so sizeof(struct cache_cmd) returns the maximum size of any
     * cache_cmd.
     */
    char            __pathname_pad[PATHNAME_LEN-1];
} END_PACKED_STRUCT(cache_invd);

INLINE void bswap_cache_invd(struct cache_invd *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->req_msg_id = bswap_64(data->req_msg_id);
	data->invd_gen = bswap_64(data->invd_gen);
	bswap_rna_hash_key_t(&data->hash_key);
    bswap_rna_service_cache_invalidate_t(&data->rnas);
#endif
}

/** CACHE_RSV_ACCESS_V18 -- supports SCSI reservations
 *      - Message sent by CS to client
 *  (Version of structure corresponding to RNA_PROTOCOL_VERSION <= 18)
 */
DECLARE_PACKED_STRUCT(cache_rsv_access_v18) {
    uint8_t         cra_n_itns;
    uint8_t         cra_other_access;
    uint8_t         cra_need_response;
    uint8_t         cra_pad[1];
    rsv_itn_id_t    cra_itn_list[MAX_PER_CLIENT_INITIATORS];
    /*
     * Keep variable length cra_pathname at end of structure!
     */
    char            cra_pathname[PATHNAME_LEN];
} END_PACKED_STRUCT(cache_rsv_access_v18);

/** CACHE_RSV_ACCESS -- supports SCSI reservations
 *      - Message sent by CS to client
 *  (latest/greatest version of cache_rsv_access structure)
 */
DECLARE_PACKED_STRUCT(cache_rsv_access) {
    uint8_t         cra_n_itns;
    uint8_t         cra_other_access;
    uint8_t         cra_need_response;
    uint8_t         cra_pad[1];
    uint32_t        cra_generation;
    rsv_itn_id_t    cra_itn_list[MAX_PER_CLIENT_INITIATORS];
    /*
     * Keep variable length cra_pathname at end of structure!
     */
    char            cra_pathname[PATHNAME_LEN];
} END_PACKED_STRUCT(cache_rsv_access);

INLINE void bswap_cache_rsv_access(struct cache_rsv_access *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    data->cra_generation = bswap_32(data->cra_generation);
#endif
}

/** CACHE_RSV_ACCESS_RESP -- supports SCSI reservations
 *      - Message sent by client to CS in response to CACHE_RSV_ACCESS message
 */
DECLARE_PACKED_STRUCT(cache_rsv_access_resp) {
    uint32_t        crar_generation;
} END_PACKED_STRUCT(cache_rsv_access_resp);


INLINE void bswap_cache_rsv_access_resp(struct cache_rsv_access_resp *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    data->crar_generation = bswap_32(data->crar_generation);
#endif
}

/** Request to resend the specified message
 */
DECLARE_PACKED_STRUCT(resend_req) {
	uint64_t	res_msg_id; /**< Message ID of message to be resent */
    uint64_t    res_gen; /**< generation number of requester's partition_map */
}END_PACKED_STRUCT(resend_req);

INLINE void bswap_resend_req(struct resend_req *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->res_msg_id = bswap_64(data->res_msg_id);
	data->res_gen = bswap_64(data->res_gen);
#endif
}

DECLARE_PACKED_STRUCT(cache_deref_req) {
    cachedev_id_t cachedev_id;    /**< target cache device id */
    uint64_t      deref_bytes;    /**< number of bytes CS wants reclaimable */
} END_PACKED_STRUCT(cache_deref_req);

INLINE void bswap_cache_deref_req(struct cache_deref_req *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    data->cachedev_id = bswap_64(data->cachedev_id);
	data->deref_bytes = bswap_64(data->deref_bytes);
#endif
}


DECLARE_PACKED_STRUCT(cache_deref_req_resp) {
    uint64_t requested_bytes; /**< number of bytes CS asked for */
    uint64_t derefed_bytes;   /**< number of bytes derefed */
}END_PACKED_STRUCT(cache_deref_req_resp);

INLINE void bswap_cache_deref_req_resp(struct cache_deref_req_resp *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->requested_bytes = bswap_64(data->requested_bytes);
    data->derefed_bytes = bswap_64(data->derefed_bytes);
#endif
}

/*
 * Flags used in the ccr_flags field
 */
#define CCR_NEEDRESP            (1 << 0) 
                                /* Set if client expects a response
                                 * back from the CHANGE_REF request.
                                 */
#define CCR_HIPRI               (1 << 1)
                                /* Set to indicate the client believes the
                                 * blk can be completely discarded (used
                                 * only for a deref CHANGE_REF).
                                 */

DECLARE_PACKED_STRUCT(cache_change_ref) {
    uint64_t cookie;            /**< client-defined cookie */
    cachedev_id_t ccr_repstore_id;  /**< For replica (deref) reqs;
                                     *  The ID of the replica store */
    uint8_t  orig_reference;    /**< client start reference */
    uint8_t  desired_reference; /**< End reference */
    uint8_t  ccr_flags;         /**< see flag definitions */
} END_PACKED_STRUCT(cache_change_ref);

INLINE void bswap_cache_change_ref(struct cache_change_ref *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	//data->orig_reference = bswap_8(data->orig_reference);
	//data->desired_reference = bswap_8(data->desired_reference);
	//data->crr_flags = bswap_8(data->crr_flags);
	data->cookie = bswap_32(data->cookie);
	data->ccr_repstore_id = bswap_64(data->ccr_repstore_id);
#endif
}

// cache change reference response
DECLARE_PACKED_STRUCT(cache_change_ref_resp) {
    uint8_t  old_ref_type;    /**< previous reference held by client */
    uint8_t  new_ref_type;    /**< current reference held by client */
    uint8_t  status;          /**< 0=success anything else indicates an error */
    uint8_t  unused;
    uint64_t cookie;          /**< client-defined cookie */
} END_PACKED_STRUCT(cache_change_ref_resp);

INLINE void bswap_cache_change_ref_resp(struct cache_change_ref_resp *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->old_ref_type = bswap_8(data->old_ref_type);
	data->new_ref_type = bswap_8(data->new_ref_type);
	data->status = bswap_8(data->status);
	data->cookie = bswap_64(data->cookie);
#endif
}

#define RNA_WRITE_SAME_SIZE      (512)
/* cache write same command */
DECLARE_PACKED_STRUCT(cache_write_same_req) {
    uint64_t            ws_rid;
    uint64_t            ws_start_lba;
    uint32_t            ws_numblocks;
    uint32_t            ws_sector_size;
    uint8_t             ws_unmap;
    uint8_t             ws_data[RNA_WRITE_SAME_SIZE];
} END_PACKED_STRUCT(cache_write_same_req);

INLINE void bswap_cache_write_same_req(struct cache_write_same_req *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    data->ws_rid = bswap_64(data->ws_rid);
    data->ws_start_lba = bswap_64(data->ws_start_lba);
    data->ws_numblocks = bswap_32(data->ws_numblocks);
    data->ws_sector_size = bswap_32(data->ws_sector_size);
#endif
}

/* cache write same response */
DECLARE_PACKED_STRUCT(cache_write_same_resp) {
    uint8_t             wsr_status;     // 0 = success.
} END_PACKED_STRUCT(cache_write_same_resp);

INLINE void bswap_cache_write_same_resp(struct cache_write_same_resp *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    data->wsr_status = bswap_8(data->wsr_status);
#endif
}

/* 
 * Combined WRITE_SAME request and response allocated on client.  Only
 * the request part is transmitted, but using
 * cache_cmd.u.cache_write_same_req.  This struct is for allocating
 * the request and response buffers in the client in a single
 * allocated region.
 *
 * Do not transmit this struct.  Transmit cache_write_same_req. 
 *
 * This struct will never be received, but cache_write_same_resp will.
 */
DECLARE_PACKED_STRUCT(cache_write_same_req_resp_buf) {
    cache_write_same_req_t     wsb_req;   /**< overlaps cache_write_same_req in cache_cmd.u */
    /* TBD: Consider alignment padding here */
    cache_write_same_resp_t    wsb_resp;  /**< follows without overlapping cache_write_same_req in cache_cmd.u */
} END_PACKED_STRUCT(cache_write_same_req_resp_buf);

/* bswap_cache_write_same_req_resp_buf() not needed nor desired */

/* XXX It would be best to put all these sizes in a common place. */
#define RNA_COMPARE_AND_WRITE_SIZE      (512)
#if RNA_COMPARE_AND_WRITE_SIZE != RNABLK_SECTOR_SIZE
/* currently we require COMPARE_AND_WRITE size to equal sector size */
#error "COMPARE_AND_WRITE assumption broken; unsupported sector size"
#endif

typedef enum {
    RNA_CW_STATUS_SUCCESS = 0,
    RNA_CW_STATUS_MISCOMPARE,   // Verification failed
    RNA_CW_STATUS_MISC,
} rna_comp_and_write_status_t; 

/* cache compare and exchange response */
DECLARE_PACKED_STRUCT(cache_comp_and_write_resp) {
    uint16_t                    cwr_miscompare_offset;
    uint8_t                     cwr_cmp_status;
    uint8_t                     cwr_status;     // cache_resp_code
} END_PACKED_STRUCT(cache_comp_and_write_resp);

INLINE void bswap_cache_comp_and_write_resp(struct cache_comp_and_write_resp *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    data->cwr_miscompare_offset = bswap_16(data->cwr_miscompare_offset);
    data->cwr_status = bswap_8(data->cwr_status);
    data->cwr_cmp_status = bswap_8(data->cwr_status);
#endif
}

/* cache compare and exchange request */
DECLARE_PACKED_STRUCT(cache_comp_and_write_req) {
    uint64_t            cw_rid;
    uint64_t            cw_blk_offset;
    /* current code is dependent on cw_verify & cw_write being contiguous */
    uint8_t             cw_verify[RNA_COMPARE_AND_WRITE_SIZE];
    uint8_t             cw_write[RNA_COMPARE_AND_WRITE_SIZE];
    struct cache_comp_and_write_resp cw_resp;
} END_PACKED_STRUCT(cache_comp_and_write_req);

INLINE void bswap_cache_comp_and_write_req(struct cache_comp_and_write_req *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    data->cw_rid = bswap_64(data->cw_rid);
    data->cw_blk_offset = bswap_64(data->cw_blk_offset);
#endif
}

/*
 * this is an unsolicited message from the CS to clients notifying
 * them that it needs them to change their reference type on a block.
 * a response is ALWAYS required for this message
 */
DECLARE_PACKED_STRUCT(cache_trans_req) {
    uint8_t  ctr_cur_ref;                /**< current reference held by client */
    uint8_t  ctr_new_ref;                /**< new reference client will hold */
    uint8_t  pad[2];
    uint64_t ctr_block_num;              /**< block number */
    char     ctr_pathname[PATHNAME_LEN]; /**< path */
} END_PACKED_STRUCT(cache_trans_req);

INLINE void bswap_cache_trans_req(struct cache_trans_req *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->cis_cur_ref_type = bswap_8(data->ctr_cur_ref);
	data->cis_new_ref_type = bswap_8(data->ctr_new_ref);
	data->cis_block_num = bswap_64(data->ctr_block_num);
#endif
}

DECLARE_PACKED_STRUCT(cache_relocate_block) {
    uint64_t            crb_md_rid;         /**< md rid */
    struct sockaddr_in  crb_dst_in;         /**< client's address */
    uint8_t             crb_hash_partition; /**< cache entry partition */
} END_PACKED_STRUCT(cache_relocate_block);

INLINE void bswap_cache_relocate_block(struct cache_relocate_block *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    data->crb_md_rid = bswap_64(data->crb_md_rid);
    bswap_sockaddr_in(&data->crb_dst_in);
    //data->crb_hash_partition = bswap_8(data->crb_hash_partition);
#endif
}

/*
 * CACHE_ABSORB_BLOCK message sent by a cache server to a metadata server to
 * anounce that the cache server is absorbing the specified block, which it
 * previously stored in the specified replica store.
 */
DECLARE_PACKED_STRUCT(cache_absorb_block) {
	uint64_t	cab_msg_id;            /**< Message ID of message */
    uint64_t    cab_partition_map_gen; /**< generation number of requester's
                                        *   cfm_md_partition_map
                                        */
    rna_service_cache_absorb_block_t rnas;

    /*
     * Since the above struct ends with a variable-length pathname, the purpose
     * of the following field is to pad this struct out to its maximum possible
     * size, so sizeof(struct cache_cmd) returns the maximum size of any
     * cache_cmd.
     */
    char            __pathname_pad[PATHNAME_LEN-1];
} END_PACKED_STRUCT(cache_absorb_block);

INLINE void bswap_cache_absorb_block(struct cache_absorb_block *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    data->cab_msg_id = bswap_64(data->cab_msg_id);
    data->cab_partition_map_gen = bswap_64(data->cab_partition_map_gen);
    bswap_rna_service_cache_absorb_block(&data->rnas);
#endif
}

/*
 * CACHE_ABSORB_BLOCK_RESP message sent by a metadata server to a cache server
 * to respond to a CACHE_ABSORB_BLOCK message.
 */
DECLARE_PACKED_STRUCT(cache_absorb_block_resp) {
	uint64_t	cabr_msg_id;           /**< Message ID of message */
    rna_service_cache_absorb_block_response_t
                rnas;
} END_PACKED_STRUCT(cache_absorb_block_resp);

INLINE void bswap_cache_absorb_block_resp(
                                        struct cache_absorb_block_resp *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    data->cabr_msg_id = bswap_64(data->cabr_msg_id);
    bswap_rna_service_cache_absorb_block_response(&data->rnas);
#endif
}

DECLARE_PACKED_STRUCT(cache_invd_hold) {
    rna_hash_key_t         cih_hash_key; // 24 bytes
    common_meta_data_t     c;         /**< Common metadata stored by both the
                                       *   MDs and the CSs.
                                       */
    char                   cih_path[PATHNAME_LEN];
} END_PACKED_STRUCT(cache_invd_hold);

INLINE void bswap_cache_invd_hold(struct cache_invd_hold *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    bswap_rna_hash_key_t(&data->cih_hash_key);
    bswap_common_meta_data(&data->c);
#endif
}


DECLARE_PACKED_STRUCT(cache_invd_hold_resp) {
    uint64_t               cihr_md_rid;
    uint32_t               cihr_cs_policy;
    uint8_t                cihr_hash_partition;
    uint8_t                cihr_cancel;
} END_PACKED_STRUCT(cache_invd_hold_resp);

INLINE void bswap_cache_invd_hold_resp(struct cache_invd_hold_resp *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    bswap_rna_hash_key_t(&data->cihr_hash_key);
    data->cihr_cs_policy = bswap_32(data->cihr_cs_policy);
    //data->cihr_hash_partition = bswap_8(data->cihr_hash_partition);
    //data->cihr_cancel = bswap_8(data->cihr_cancel);
#endif
}


/** Cache block copy done sent from new CS to old CS
 */
DECLARE_PACKED_STRUCT(cache_copy_done) {
    rna_hash_key_t  ccd_path_key;   /**< Path key (MD5 of the pathname).  bytes */
    uint64_t        ccd_block_num;
    char            ccd_path[1];    /**< variable-length field (declared
                                     *   length 1 rather than 0 to avoid
                                     *   upseting the windows compiler, which
                                     *   warns about fields that follow
                                     *   variable-length fields).
                                     *   MUST BE LAST (except for following pad)
                                     */
    /*
     * Since the above array is variable-length, the purpose of the following
     * field is to pad this struct out to its maximum possible size, so
     * sizeof(struct cache_cmd) returns the maximum size of any cache_cmd.
     */
    char __pathname_pad[PATHNAME_LEN-1];
} END_PACKED_STRUCT(cache_copy_done);

INLINE void bswap_cache_copy_done(struct cache_copy_done *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    bswap_rna_hash_key_t(&data->ccd_path_key);
    data->ccd_block_num = bswap_64(data->ccd_block_num);
    //char ccd_path[PATHNAME_LEN]
#endif
}

DECLARE_PACKED_STRUCT(cache_replica_store_create) {
    cachedev_id_t   crsc_repstore_id;        /* The ID of the replica store
                                              * to be created
                                              */
    cachedev_id_t   crsc_host_cachedev_id;   /* The ID of the cache device that
                                              * contains the replica store to be
                                              * created
                                              */
    cachedev_id_t   crsc_served_cachedev_id; /* The ID of the cache device
                                              * whose blocks are replicated
                                              * in this replica store
                                              */
    uint8_t         crsc_type;               /* DAS vs. SAN */
} END_PACKED_STRUCT(cache_replica_store_create);

INLINE void bswap_cache_replica_store_create(struct cache_replica_store_create *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->crsc_repstore_id = bswap_64(data->crsc_repstore_id);
	data->crsc_host_cachedev_id = bswap_64(data->crsc_host_cachedev_id);
	data->crsc_served_cachedev_id = bswap_64(data->crsc_served_cachedev_id);
#endif
}

DECLARE_PACKED_STRUCT(cache_replica_store_create_resp) {
    cachedev_id_t   crscr_repstore_id;        /* crsc_repstore_id from the request */
    cachedev_id_t   crscr_host_cachedev_id;   /* crsc_host_cachedev_id from the request */
    cachedev_id_t   crscr_served_cachedev_id; /* crsc_served_cachedev_id from the request */
    uint8_t         crscr_type;               /* crsc_type from the request */
} END_PACKED_STRUCT(cache_replica_store_create_resp);

INLINE void bswap_cache_replica_store_create_resp(struct cache_replica_store_create_resp *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->crscr_repstore_id = bswap_64(data->crscr_repstore_id);
	data->crscr_host_cachedev_id = bswap_64(data->crscr_host_cachedev_id);
	data->crscr_served_cachedev_id = bswap_64(data->crscr_served_cachedev_id);
#endif
}

DECLARE_PACKED_STRUCT(cache_replica_store_remove) {
    cachedev_id_t   crsr_repstore_id;       /* The ID of the replica store
                                             * to be removed
                                             */
    cachedev_id_t   crsr_host_cachedev_id;  /* The ID of the cache device that
                                             * contains the replica store to be
                                             * recovered
                                             */
    cachedev_id_t   crsr_served_cachedev_id; /* The ID of the cache device
                                              * whose blocks are replicated
                                              * in this replica store
                                              */
} END_PACKED_STRUCT(cache_replica_store_remove);

INLINE void bswap_cache_replica_store_remove(struct cache_replica_store_remove *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->crsr_repstore_id = bswap_64(data->crsr_repstore_id);
	data->crsr_host_cachedev_id = bswap_64(data->crsr_host_cachedev_id);
	data->crsr_served_cachedev_id = bswap_64(data->crsr_served_cachedev_id);
#endif
}

DECLARE_PACKED_STRUCT(cache_replica_store_remove_resp) {
    cachedev_id_t   crsrr_repstore_id;        /* crsr_repstore_id from the request */
    cachedev_id_t   crsrr_host_cachedev_id;   /* crsr_host_cachedev_id from the request */
    cachedev_id_t   crsrr_served_cachedev_id; /* crsr_served_cachedev_id from the request */
} END_PACKED_STRUCT(cache_replica_store_remove_resp);

INLINE void bswap_cache_replica_store_remove_resp(struct cache_replica_store_remove_resp *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->crsrr_repstore_id = bswap_64(data->crsrr_repstore_id);
	data->crsrr_host_cachedev_id = bswap_64(data->crsrr_host_cachedev_id);
	data->crsrr_served_cachedev_id = bswap_64(data->crsrr_served_cachedev_id);
#endif
}

/** cache server's registration with the primary cache server.
 * For writeback replication, the primary cache server asks the
 * secondary for it's ping registration information. The secondary
 * responds by sending the ping information.
 */
DECLARE_PACKED_STRUCT(cache_reg_ping) {
    struct rna_service_id crp_service_id;
} END_PACKED_STRUCT(cache_reg_ping);

INLINE void bswap_cache_reg_ping(struct cache_reg_ping *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	bswap_rna_service_id(&data->crp_service_id);
#endif
}


DECLARE_PACKED_STRUCT(cache_reg_ping_resp) {
    struct rna_service_id crpr_service_id; /**< Unique Service ID */
	rna_rkey_t          crpr_ping_rkey; /**< rkey for ping RDMA reads */
	rna_addr_t          crpr_ping_buf; /** pointer for ping RDMA reads */
} END_PACKED_STRUCT(cache_reg_ping_resp);


INLINE void bswap_cache_reg_ping_resp(struct cache_reg_ping_resp *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	bswap_rna_service_id(&data->crpr_service_id);
	bswap_rna_rkey_t(&data->crpr_ping_rkey);
	bswap_rna_addr_t(&data->crpr_ping_buf);
#endif
}


/** Cache command parent structure 
 */
DECLARE_PACKED_STRUCT(cache_cmd) {
    cmd_hdr_t  h;   // must be first
	union {
		struct md_req md_query;
		struct md_rep md_rep;
		struct path_reg path_reg;
		struct cache_reg cache_reg;
		struct cache_reg_resp cache_reg_resp;
		struct cache_req cache_req;
		struct cache_rep cache_rep;
		struct cache_rep_rep cache_rep_rep;
		struct cache_query_req cache_query_req;
		struct cache_invd cache_invd;
		struct cache_rsv_access cache_rsv_access;
		struct cache_rsv_access_v18 cache_rsv_access_v18;
		struct cache_rsv_access_resp cache_rsv_access_resp;
        struct resend_req resend_req;
		struct cache_data_read cache_data_read;
		struct cache_data_read_resp cache_data_read_resp;
		struct cache_data_write cache_data_write;
		struct cache_data_ready cache_data_ready;
		struct cache_flush_rep cache_flush_rep;    /**< for pub/sub */
		struct cache_state_query cache_state_query;
		struct cache_state_query_resp cache_state_query_resp;
		struct rna_event rna_event;
		struct cache_ref_activate cache_ref_activate;
		struct cache_deref_req cache_deref_req;
		struct cache_deref_req_resp cache_deref_req_resp;
		struct cache_change_ref cache_change_ref;
		struct cache_change_ref_resp cache_change_ref_resp;
		struct cache_trans_req cache_trans_req;
		struct cache_write_same_req cache_write_same_req;
		struct cache_write_same_resp cache_write_same_resp;
		struct cache_write_same_req_resp_buf cache_write_same_req_resp_buf;  /**< not transmitted */
		struct cache_relocate_block relocate_block;
		struct cache_absorb_block cache_absorb_block;
		struct cache_absorb_block_resp cache_absorb_block_resp;
		struct cache_invd_hold cache_invd_hold;
		struct cache_invd_hold_resp cache_invd_hold_resp;
		struct cache_copy_done cache_copy_done;
        struct cache_comp_and_write_req cache_comp_wr_req;
        struct cache_comp_and_write_resp cache_comp_wr_resp;
        struct cache_replica_store_create cache_replica_store_create;
        struct cache_replica_store_create_resp cache_replica_store_create_resp;
        struct cache_replica_store_remove cache_replica_store_remove;
        struct cache_replica_store_remove_resp cache_replica_store_remove_resp;
        struct cache_fail_cd cache_fail_cd;
        struct cache_scsi_passthru cache_scsi_passthru;
        struct cache_scsi_passthru_resp cache_scsi_passthru_resp;
        struct cache_scsi_unitattn cache_scsi_unitattn;
        struct cache_reg_ping cache_reg_ping;
        struct cache_reg_ping_resp cache_reg_ping_resp;
	}u;
} END_PACKED_STRUCT(cache_cmd);

INLINE void bswap_cache_cmd(struct cache_cmd *data,int in)
{
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(in);	
#if CPU_BE
	if(in){
        bswap_cmd_hdr(&cmd->h);
	}
	
	switch(data->h.h_type){
		case META_DATA_QUERY:
			bswap_md_req(&data->u.md_query);
			break;
		case META_DATA_RESPONSE:
			bswap_md_rep(&data->u.md_rep);
			break;
		case CACHE_REGISTER:
			bswap_cache_reg(&data->u.cache_reg);
			break;
		case CACHE_REGISTER_RESP:
			bswap_cache_reg_resp(&data->u.cache_reg_resp);
			break;
		case CACHE_QUERY:
			bswap_cache_req(&data->u.cache_req);
			break;
		case CACHE_RESPONSE:
			bswap_cache_rep(&data->u.cache_rep);
			break;
		case CACHE_QUERY_REQ:
			bswap_cache_query_req(&data->u.cache_query_req);
			break;
		case CACHE_RESPONSE_RESPONSE:
			bswap_cache_rep(&data->u.cache_rep_rep);
			break;
		case CACHE_INVD:
		case CACHE_INVD_REP:
		case CACHE_MASTER_INVD:
			bswap_cache_invd(&data->u.cache_invd);
            break
		case RESEND_REQ:
            bswap_resend_req(data->u.resend_req);
			break;
		case CACHE_CHANGE_REF:
			bswap_cache_change_ref(&data->u.cache_change_ref);
			break;
		case CACHE_CFM_EVT:
			break;
		
		case RNA_ECHO:
			break;
		case CACHE_CHANGE_REF_REQUEST:
            bswap_cache_change_ref_req(&data->u.cache_change_ref_req);
            break;
		case CACHE_CHANGE_REF_RESP:
            bswap_cache_change_ref_resp(&data->u.cache_change_ref_resp);
            break;		
		case CACHE_REG_PATH:
		case CACHE_DEREG_PATH:
			bswap_path_reg(&data->u.path_reg.rnas);
			break;
		case CACHE_TRANS_REQ:
            bswap_cache_trans_req(&data->u.cache_trans_req);
            break;
		case CACHE_WRITE_SAME:
            bswap_cache_write_same_req(&data->u.cache_write_same_req);
            break;
		case CACHE_WRITE_SAME_RESP:
            bswap_cache_write_same_req(&data->u.cache_write_same_resp);
            break;
		case CACHE_RELOCATE_BLOCK:
            bswap_cache_relocate_block(&data->u.relocate_block);
            break;
		case CACHE_ABSORB_BLOCK:
            bswap_cache_absorb_block(&data->u.cache_absorb_block);
            break;
		case CACHE_ABSORB_BLOCK_RESP:
            bswap_cache_absorb_block_resp(&data->u.cache_absorb_block_resp);
            break;
		case CACHE_INVD_HOLD:
			bswap_cache_invd_hold(&data->u.cache_invd_hold);
            break
		case CACHE_INVD_HOLD_RESP:
			bswap_cache_invd_hold_resp(&data->u.cache_invd_hold_resp);
            break
		case CACHE_COPY_DONE:
			bswap_cache_copy_done(&data->u.cache_copy_done);
            break
        case CACHE_COMP_WR:
            bswap_cache_comp_and_write_req(&data->u.cache_comp_wr_req);
            break;
        case CACHE_COMP_WR_RESP:
            bswap_cache_comp_and_write_resp(&data->u.cache_comp_wr_resp);
            break;
        case CACHE_REPLICA_STORE_CREATE:
            bswap_cache_replica_store_create(&data->u.cache_replica_store_create);
            break;
        case CACHE_REPLICA_STORE_CREATE_RESP:
            bswap_cache_replica_store_create_resp(&data->u.cache_replica_store_create_resp);
            break;
        case CACHE_REPLICA_STORE_REMOVE:
            bswap_cache_replica_store_remove(&data->u.cache_replica_store_create);
            break;
        case CACHE_REPLICA_STORE_REMOVE_RESP:
            bswap_cache_replica_store_remove_resp(&data->u.cache_replica_store_create_resp);
            break;
        case CACHE_SCSI_PASSTHRU:
            bswap_cache_scsi_passthru(&data->u.cache_scsi_passthru);
            break;
        case CACHE_SCSI_PASSTHRU_RESP:
            bswap_cache_scsi_passthru_resp(&data->u.cache_scsi_passthru_resp);
            break;
        case CACHE_SCSI_UNITATTN:
            bswap_cache_scsi_unitattn(&data->u.cache_scsi_unitattn);
            break;
        case CACHE_FAIL_CACHE_DEVICE:
        case CACHE_FAIL_CACHE_DEVICE_RESP:
            bswap_cache_fail_cd(&data->u.cache_fail_cd);
            break;
        case CACHE_REG_PING:
            bswap_cache_reg_ping(&data->u.cache_reg_ping);
            break;
        case CACHE_REG_PING_RESP:
            bswap_cache_reg_ping_resp(&data->u.cache_reg_ping_resp);
            break;
		default:
#ifndef __KERNEL__
			printf("bswap_cache_cmd: type mismatch: %d\n",data->h.h_type);
			assert(0);
#endif
			break;	
	}	
	if(!in){
		data->h.h_type = bswap_32(data->h.h_type);
		data->h.h_cookie = bswap_64(data->h.h_cookie);
	}
#endif
}

typedef enum {
    MCP_NOOP = 0,   
    MCP_STOP_ALL,       /**< stop all services */
    MCP_START_ALL,      /**< start all services */
    MCP_RESTART_ALL,    /**< restart all services */
    MCP_SEG_SERVERS,    /**< dump core for all services */
    MCP_SEG_ALL,        /**< dump core for all services and agents */
    MCP_SET_LOG_LEVEL   /**< change the log level on all services */
} mcp_control_type;

/** Sent by CLI to the cfm to request config operation.
 */
DECLARE_PACKED_STRUCT(mcp_url_req) {
	uint8_t		mug_type; /**< Type of request POST, GET, PUT, DELETE */
	char	    mug_url[PATHNAME_LEN];  /**< Relative URL of entity. */ 
	char	    mug_query[PATHNAME_LEN];  /**< query string (parameters) */ 
	char	    mug_payload[MAX_CLI_DATA];  /**< payload */ 
	uint64_t    mug_token; /**< User token. Used to associate requests with specific instances */
} END_PACKED_STRUCT(mcp_url_req);

INLINE void bswap_mcp_url_req(struct mcp_url_req *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	//uint8_t	mug_type;  /* request type */
	//char	    mug_url[PATHNAME_LEN];  /* Relative URL */ 
	//char	    mug_query[PATHNAME_LEN];  /* query string */ 
	//char	    mug_payload[MAX_CLI_DATA];  /* payload */ 
	data->mug_token = bswap_64(data->mug_token);
#endif
}

/** Information sent as a response to the mcp_url_req message.
    The file paths in mur_location can be read via the RFT commands. 
 */
DECLARE_PACKED_STRUCT(mcp_url_resp) {
    uint64_t mur_cookie; /**< cookie to identify session */
    uint32_t mur_maxage;  /**< session maximum age */
    uint32_t mur_progress;  /**< response progress information */
	uint16_t mur_res; /**< response code */
    uint8_t mur_eom;  /**< non-zero indicates end of response messages */
	char    mur_location[PATHNAME_LEN];	/**< file redirect for RFT transfer */
	char    mur_hypertext[MAX_CLI_DATA];	/**< hypertext msg */
    uint32_t mur_msg_id;       /**< message catalog iD */
    uint8_t  unused[1];        /**< alignment padding */
    uint64_t __work_area[16];  /**< receiver should ignore this portion of response */
} END_PACKED_STRUCT(mcp_url_resp);

INLINE void bswap_mcp_url_resp(struct mcp_url_resp *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->mur_cookie = bswap_64(data->mur_cookie);
	data->mur_maxage = bswap_32(data->mur_maxage);
	data->mur_progress = bswap_32(data->mur_progress);
	data->mur_res = bswap_16(data->mur_res);
	data->mur_msg_id = bswap_32(data->mur_msg_id);
    //uint8_t mur_eom;
	//char    mur_location[PATHNAME_LEN];	
	//char    mur_hypertext[MAX_CLI_DATA];	
#endif
}


DECLARE_PACKED_STRUCT(mcp_cmd) {
	uint32_t type;
    union { 
        struct {
            uint32_t       log_level;
            agent_app_type which_app_types;
        } set_log_level;
		struct mcp_url_req mcp_url_req;
		struct mcp_url_resp mcp_url_resp;
		unsigned char _pad[9228];
    } arg;
} END_PACKED_STRUCT(mcp_cmd);

INLINE void bswap_mcp_cmd(struct mcp_cmd *data, int in)
{
    UNREFERENCED_PARAMETER(data);	
    UNREFERENCED_PARAMETER(in);	
#if CPU_BE
	if(in){
        data->type = bswap_32(data->type);
	}
	switch(data->type){
		case MCP_URL_REQ:
			bswap_mcp_url_req(&data->arg.mcp_url_req);
			break;
		case MCP_URL_RESP:
			bswap_mcp_url_resp(&data->arg.mcp_url_resp);
			break;
    }
	if (!in) {
        data->type = bswap_32(data->type);
    }
#endif
}

DECLARE_PACKED_STRUCT(cfm_service_reg) {
	char                  hostname[MAX_HOST_LEN];   /**< Hostname for ease of use */
    struct rna_service_id service_id; /**< Unique Service ID */
    uint64_t              csr_cs_membership_generation; /**< For message type
                                           * CONF_MGR_DISCONN_REG and connection
                                           * type USR_TYPE_CACHE only
                                           */
    uint16_t              csr_md_ordinal; /**< For message type
                                           * CONF_MGR_CONN_REG and connection
                                           * type USR_TYPE_CFM_META only
                                           */
    uint8_t               conn_details_valid; /**< TRUE is tansport type and src/dst_in are present */
    uint8_t               csr_cache_view_is_complete;
                                          /**< This field is valid only for CS
                                           *   disconnect messages sent by the
                                           *   CFM.  TRUE if the cache view is
                                           *   currently valid; otherwise FALSE
                                           */
    uint8_t               transport_type; /**< Transport type as seen by connection reporter.  @see com_type enum */
    uint8_t               csr_pad[3];     /**< Use these entries for new fields
                                           */
	struct sockaddr_in    src_in;         /**< Connection reporter's address */
	struct sockaddr_in    dst_in;         /**< Connection reporter's address */
	struct rna_if_table   csr_if_tbl;     /**< Network interfaces available. */
} END_PACKED_STRUCT(cfm_service_reg);

INLINE void bswap_cfm_service_reg (struct cfm_service_reg *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	//char hostname[MAX_HOST_LEN];
    bswap_rna_service_id(&data->rna_service_id);
	data->type = bswap_16(data->md_ordinal);
	bswap_sockaddr_in(&data->src_in);
	bswap_sockaddr_in(&data->dst_in);
    bswap_rna_if_table(data->msr_if_table);
#endif
}

/** Update Configuration Manager Request message from CFM to client, agent,
 *  cache, meta data
 */
DECLARE_PACKED_STRUCT(update_cfm_req) {
	uint32_t			action; /**< add or delete @see req_crud */
	uint32_t			rank; /**< CFM rank (ignored on delete) */
	struct sockaddr_in	addr; /**< ipv4 address of CFM */
	uint32_t			com_type; /**< perferred transport type to connect to CFM */
} END_PACKED_STRUCT(update_cfm_req);

INLINE void bswap_update_cfm_req(struct update_cfm_req *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
    data->action = bswap_32(data->action);
	bswap_sockaddr_in(&data->addr);
    data->rank = bswap_32(data->rank);
    data->com_type = bswap_32(data->com_type);
	//char	addr[INET_ADDRSTRLEN + 1];
#endif
}

/*
 * Agent upgade cancel notification
 */
DECLARE_PACKED_STRUCT(agent_cancel_upgrade) {
    uint32_t pad;
} END_PACKED_STRUCT(agent_cancel_upgrade);

INLINE void bswap_agent_cancel_upgrad(struct agent_cancel_upgrade *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->pad = bswap_32(data->pad);
#endif
}

/*
 * AGENT request a new JRL_RECV_MIRROR control from primary cfm
 */
DECLARE_PACKED_STRUCT(agent_jnl_recv_mirror_req) {
    uuid_t                jrm_hcc_id;                   /**< Cluster ID */
    uint64_t              jrm_pci_generation;           /**< primary cfm generation */
    struct rna_service_id jrm_service_id;               /**< Agent Service ID */
    char                  jrm_hostname[MAX_HOST_LEN];   /**< Hostname of agent system */
} END_PACKED_STRUCT(agent_jnl_recv_mirror_req);


INLINE void bswap_agent_jnl_recv_mirror(struct agent_jnl_recv_mirror_req *data)
{
    UNREFERENCED_PARAMETER(data);
#if CPU_BE
    data->jrm_pci_generation = bswap_64(data->jrm_pci_generation);
    bswap_rna_service_id(&data->jrm_service_id);
#endif
}

/** Cfm command parent structure.
    Used for communication with the CFM 
 */
DECLARE_PACKED_STRUCT(cfm_cmd) {
    cmd_hdr_t          h;   // must be first
	union {
		struct cache_cfm_reg cache_cfm_reg;
		struct cache_cfm_reg_resp cache_cfm_reg_resp;
		struct cache_cfm_reg_resp_V2 cache_cfm_reg_resp_V2;
		struct cache_cfm_query_cachedev cache_cfm_query_cachedev;
		struct cache_cfm_reg_cachedev cache_cfm_reg_cachedev;
		struct cache_cfm_reg_cachedev_end cache_cfm_reg_cachedev_end;
		struct cache_cfm_dereg_cachedev cache_cfm_dereg_cachedev;
		struct cache_cfm_update_cachedev cache_cfm_update_cachedev;
		struct cache_cfm_expel_cachedev cache_cfm_expel_cachedev;
		struct cache_cfm_dereg_repstore cache_cfm_dereg_repstore;
		struct cache_cfm_repstore cache_cfm_repstore;
        struct cache_cfm_resilver_cachedev_complete
                                    cache_cfm_resilver_cachedev_complete;
        struct cache_cfm_resilver_cachedev_complete_resp
                                    cache_cfm_resilver_cachedev_complete_resp;
		struct md_cfm_reg md_cfm_reg;
		struct md_cfm_reg_resp md_cfm_reg_resp;
        struct cfm_unexpelled_cachedevs cfm_unexpelled_cachedevs;
        struct cfm_md_active_cs_cache_devices cfm_md_active_cs_cache_devices;
        struct cfm_cache_view_status cfm_cache_view_status;
        struct cfm_cache_view_status_req cfm_cache_view_status_req;
		struct cfm_service_reg cfm_service_reg;
		struct cfm_config_get cfm_config_get;
		struct cfm_config_resp cfm_config_resp;
		struct client_cfm_reg client_cfm_reg;
		struct cfm_client_resp cfm_client_resp;
		struct client_mount_reg client_mount_reg;
		struct client_mount_dereg client_mount_dereg; 
        struct cache_cfm_query_cached_lun cache_cfm_query_cached_lun;
        struct path_reg path_reg;
        struct cache_cfm_cached_lun_write_all_initiate
                                        cache_cfm_cached_lun_write_all_initiate;
        struct cache_cfm_cached_lun_write_all_conclude
                                        cache_cfm_cached_lun_write_all_conclude;
        struct cache_cfm_shutdown_req cache_cfm_shutdown_req;
        struct cfm_shutdown_status cfm_shutdown_status;
        struct cfm_shutdown_grant cfm_shutdown_grant;
        struct cache_cfm_shutdown_resp cache_cfm_shutdown_resp;
        struct client_create_block_device client_create_block_device;
        struct client_control_block_device client_control_block_device;
        struct client_control_block_device_resp
                                        client_control_block_device_resp;
        struct client_block_device_reg client_block_device_reg;
        struct client_block_device_reg_resp client_block_device_reg_resp;
        struct client_block_device_dereg client_block_device_dereg;
        struct client_notification_event client_notification_event;
        struct blkdev_stats client_block_device_stats_resp;
		struct cfm_reg_resp cfm_reg_resp;
		struct cfm_md_host_rep cfm_md_host_rep;
		struct cfm_md_partition_map cfm_md_partition_map;
		struct rna_event rna_event;
		struct rna_event_reg rna_event_reg;
		struct cache_invd cache_invd_req;
		struct cache_stats cache_stats_rep;
		struct cache_stats_req cache_stats_req;
		struct agent_cfm_reg agent_cfm_reg;
		struct agent_reg_resp agent_reg_resp;
		struct agent_get_stats agent_get_stats;
		struct agent_stats_rep agent_stats_rep;
		struct agent_app_control agent_app_control;
		struct agent_ping agent_ping;
		struct md_to_cfm_ping md_to_cfm_ping;
		struct cs_to_cfm_ping cs_to_cfm_ping;
		struct fsclient_to_cfm_ping fsclient_to_cfm_ping;
		struct cfm_control cfm_control;	
		struct cfm_control_reject cfm_control_reject;	
		struct update_cfm_req update_cfm_req;
		struct control_cs control_cs;
		struct control_cs_resp control_cs_resp;
        struct agent_get_ssd agent_get_ssd;
        struct agent_get_ssd_rep agent_get_ssd_rep;
        struct cfm_prepare_delete_hcc cfm_prepare_delete_hcc;
        struct cfm_prepare_delete_hcc_resp cfm_prepare_delete_hcc_resp;
        struct cfm_journal_read_request journal_read_req;
        struct cfm_journal_read_response journal_read_resp;
        struct cfm_journal_write_request journal_write_req;
        struct cfm_journal_write_response journal_write_resp;
        struct cfm_journal_init_request journal_init_req;
        struct cfm_journal_init_response journal_init_resp;
        /* Begin SCSI III reservation messages */
        cache_cfm_update_scsi_itn_reservation_t
                    cache_cfm_update_scsi_itn_reservation;
        cache_cfm_update_scsi_itn_registration_t
                    cache_cfm_update_scsi_itn_registration;
        cache_cfm_clear_scsi_itn_reservation_t
                    cache_cfm_clear_scsi_itn_reservation;
        cache_cfm_acquire_scsi_itn_res_t
                    cache_cfm_acquire_scsi_itn_reservation;
        cache_cfm_acquire_scsi_itn_reg_t
                    cache_cfm_acquire_scsi_itn_registration;
        cache_cfm_update_clear_scsi_itn_resg_resp_t
                    cache_cfm_update_clear_scsi_itn_resg_response;
        cache_cfm_acquire_scsi_itn_res_resp_t
                    cache_cfm_acquire_scsi_itn_reservation_response;
        cache_cfm_acquire_scsi_itn_reg_resp_t
                    cache_cfm_acquire_scsi_itn_registration_response;
        /* end SCSI III reservation messages */
        struct agent_cancel_upgrade agent_cancel_upgrade;
        struct agent_jnl_recv_mirror_req agent_jnl_recv_mirror;
        uint8_t _pad[8232 - sizeof(cmd_hdr_t)];
	}u;		

} END_PACKED_STRUCT(cfm_cmd);

INLINE void bswap_cfm_cmd(struct cfm_cmd *data, int in)
{
    UNREFERENCED_PARAMETER(data);	
    UNREFERENCED_PARAMETER(in);	
#if CPU_BE
	if(in){
        bswap_cmd_hdr(&cmd->h);
	}
	switch(data->h.h_type){
		case CONF_MGR_REG_CACHE:
			bswap_cache_cfm_reg(&data->u.cache_cfm_reg);
			break;
		case CONF_MGR_REG_CACHE_RESPONSE:
			bswap_cache_cfm_reg_resp(&data->u.cache_cfm_reg_resp);
			break;
		case CONF_MGR_REG_CACHE_RESPONSE_V2:
			bswap_cache_cfm_reg_resp_V2(&data->u.cache_cfm_reg_resp_V2);
			break;
		case CONF_MGR_QUERY_CACHE_DEVICE:
			bswap_cache_cfm_query_cachedev(
                            &data->u.cache_cfm_query_cachedev);
			break;
		case CONF_MGR_REG_CACHE_DEVICE:
			bswap_cache_cfm_reg_cachedev(&data->u.cache_cfm_reg_cachedev);
			break;
		case CONF_MGR_REG_CACHE_DEVICE_END:
			bswap_cache_cfm_reg_cachedev(&data->u.cache_cfm_reg_cachedev_end);
			break;
		case CONF_MGR_UPDATE_CACHE_DEVICE:
			bswap_cache_cfm_update_cache_device(
                            &data->u.cache_cfm_update_cachedev);
			break;
		case CONF_MGR_RESILVER_CACHE_DEVICE_COMPLETE:
			bswap_cache_cfm_resilver_cache_device_complete(
                            &data->u.cache_cfm_resilver_cachedev_complete);
			break;
		case CONF_MGR_RESILVER_CACHE_DEVICE_COMPLETE_RESP:
			bswap_cache_cfm_resilver_cache_device_complete_resp(
                            &data->u.cache_cfm_resilver_cachedev_complete_resp);
			break;
		case CONF_MGR_EXPEL_CACHE_DEVICE:
			bswap_cache_cfm_expel_cache_device(
                            &data->u.cache_cfm_expel_cachedev);
			break;
		case CONF_MGR_ABSORB_REPLICA_STORE:
		case CONF_MGR_DELETE_REPLICA_STORE:
			bswap_cache_cfm_repstore(&data->u.cache_cfm_repstore);
			break;
		case CONF_MGR_REG_MD:
			bswap_md_cfm_reg(&data->u.md_cfm_reg);
			break;
		case CONF_MGR_REG_MD_RESPONSE:
			bswap_md_cfm_reg_resp(&data->u.md_cfm_reg_resp);
			break;
		case CONF_MGR_UNEXPELLED_CACHEDEVS:
			bswap_cfm_unexpelled_cachedevs(&data->u.cfm_unexpelled_cachedevs);
			break;
		case CONF_MGR_CONN_REG:
		case CONF_MGR_DISCONN_REG:
		case CONF_MGR_SERVICE_DEREG:
			bswap_cfm_service_reg(&data->u.cfm_service_reg);
			break;
		case CONF_MGR_CONF_GET:
			bswap_cfm_config_get(&data->u.cfm_config_get);
			break;
		case CONF_MGR_CONF_RESPONSE:
			bswap_cfm_config_resp(&data->u.cfm_config_resp);
			break;
		case CONF_MGR_REG_CLIENT:
			bswap_client_cfm_reg(&data->u.client_cfm_reg);
			break;
		case CONF_MGR_REG_CLIENT_MOUNT:
			bswap_client_mount_reg(&data->u.client_mount_reg);
			break;
        case CONF_MGR_QUERY_CACHED_LUN:
            bswap_cache_cfm_query_cached_lun(
                    &data->u.cache_cfm_query_cached_lun);
            break;
		case CONF_MGR_REG_PATH:
		case CONF_MGR_DEREG_PATH:
			bswap_path_reg(&data->u.path_reg.rnas);
			break;
        case CONF_MGR_CACHED_LUN_WRITE_ALL_INITIATE:
            bswap_cache_cfm_cached_lun_write_all_initiate(
                    &data->u.cache_cfm_cached_lun_write_all_initiate);
            break;
        case CONF_MGR_CACHED_LUN_WRITE_ALL_CONCLUDE:
            bswap_cache_cfm_cached_lun_write_all_conclude(
                    &data->u.cache_cfm_cached_lun_write_all_conclude);
            break;
        case CONF_MGR_CS_SHUTDOWN_REQ:
            bswap_cache_cfm_shutdown_req(&data->u.cache_cfm_shutdown_req);
            break;
        case CONF_MGR_CS_SHUTDOWN_RERP:
            bswap_cache_cfm_shutdown_resp(&data->u.cache_cfm_shutdown_resp);
            break;
		case CONF_MGR_REG_RESPONSE:
			bswap_cfm_reg_resp(&data->u.cfm_reg_resp);
			break;
		case CONF_MGR_DEREG_CLIENT_MOUNT:
			bswap_client_mount_dereg(&data->u.client_mount_dereg);
			break;	
		case CONF_MGR_BLOCK_DEVICE_CREATE:
			bswap_client_create_block_device(&data->u.client_create_block_device);
			break;
		case CONF_MGR_BLOCK_DEVICE_CONTROL:
			bswap_client_control_block_device(&data->u.client_control_block_device);
			break;
		case CONF_MGR_BLOCK_DEVICE_CONTROL_RESP:
			bswap_client_control_block_device_resp(&data->u.client_control_block_device_resp);
			break;
		case CONF_MGR_REG_BLOCK_DEVICE:
			bswap_client_block_device_reg(&data->u.client_block_device_reg);
			break;
		case CONF_MGR_REG_BLOCK_DEVICE_RESP:
			bswap_client_block_device_reg_resp(&data->u.client_block_device_reg_resp);
			break;
		case CONF_MGR_DEREG_BLOCK_DEVICE:
			bswap_client_block_device_dereg(&data->u.client_block_device_dereg);
			break;
		case CONF_MGR_MD_PARTITION_MAP:
			bswap_cfm_md_partition_map(&data->u.cfm_md_partition_map);
			break;
		case CONF_MGR_MD_REPORT:
			bswap_rna_event(&data->u.rna_event);
			break;
		case CONF_MGR_EVENT_REG:
			bswap_rna_event_reg(&data->u.rna_event_reg);
			break;
		case CONF_MGR_EVENT_DEREG:
			bswap_rna_event_dereg(&data->u.rna_event_dereg);
			break;
		case CONF_MGR_CSTAT_REQ:
			bswap_cache_stats_req(&data->u.cache_stats_req);
			break;
		case CONF_MGR_CSTAT_RESP:
			bswap_cache_stats(&data->u.cache_stats);
			break;
		case CONF_MGR_CONTROL:
			bswap_cfm_control(&data->u.cfm_control);
			break;
		case CONF_MGR_CONTROL_REJECT:
			bswap_cfm_control_reject(&data->u.cfm_control_reject);
			break;
		case CONF_MGR_ACTIVE_CS_CACHE_DEVICES:
			bswap_cfm_control_reject(&data->u.cfm_md_active_cs_cache_devices);
			break;
		case CONF_MGR_CACHE_VIEW_STATUS:
			bswap_cfm_control_reject(&data->u.cfm_cache_view_status);
			break;
		case CONF_MGR_CACHE_VIEW_STATUS_REQ:
			bswap_cfm_control_reject(&data->u.cfm_cache_view_status_req);
			break;
		case AGENT_REGISTER:
			bswap_agent_cfm_reg(&data->u.agent_cfm_reg);
			break;
		case AGENT_REG_RESPONSE:
			bswap_agent_reg_resp(&data->u.agent_reg_resp);
			break;
		case AGENT_CMD: // TODO: rename to APP_CONTROL
			bswap_agent_app_control(&data->u.agent_app_control);
			break;
		case PING: // TODO: rename to AGENT_PING
		case EMPTY_PING:
			bswap_agent_ping(&data->u.agent_ping);
			break;
		case AGENT_TO_CFM_PING:  // identical to an AGENT_STATS_REP
			bswap_agent_stats_rep(&data->u.agent_stats_rep);
			break;
		case MD_TO_CFM_PING:
			bswap_md_to_cfm_ping(&data->u.md_to_cfm_ping);
			break;
		case CS_TO_CFM_PING:
			bswap_cs_to_cfm_ping(&data->u.cs_to_cfm_ping);
			break;
		case FSCLIENT_TO_CFM_PING:
			bswap_fsclient_to_cfm_ping(&data->u.fsclient_to_cfm_ping);
			break;
		case AGENT_DISCONNECT:
			// Note: agent disconnect command has no payload data.
			//bswap_agent_disconnect(&data->u.agent_disconnect);
			break;
		case CONF_MGR_CONTROL_CS:
			bswap_control_cs(&data->u.control_cs);
			break;
		case CONF_MGR_CONTROL_CS_RESP:
			bswap_control_cs_resp(&data->u.control_cs_resp);
			break;
		case CACHE_MASTER_INVD:
			bswap_cache_invd(&data->u.cache_invd_req);
			break;
		case AGENT_GET_SSD:
			bswap_agent_get_ssd(&data->u.agent_get_ssd);
			break;
		case AGENT_GET_SSD_REP:
			bswap_agent_get_ssd_rep(&data->u.agent_get_ssd_rep);
			break;
		case CONF_MGR_PREPARE_DELETE_HCC:
			bswap_cfm_prepare_delete_hcc(&data->u.prepare_delete_hcc);
			break;
		case CONF_MGR_PREPARE_DELETE_HCC_RESP:
			bswap_cfm_prepare_delete_hcc_resp(&data->u.prepare_delete_hcc_resp);
			break;
		case CONF_MGR_JOURNAL_READ_REQ:
			bswap_journal_read_req(&data->u.journal_read_req);
			break;
		case CONF_MGR_JOURNAL_READ_RESP:
			bswap_journal_read_resp(&data->u.journal_read_resp);
			break;
		case CONF_MGR_JOURNAL_WRITE_REQ:
			bswap_journal_write_req(&data->u.journal_write_req);
			break;
		case CONF_MGR_JOURNAL_WRITE_RESP:
			bswap_journal_write_resp(&data->u.journal_write_resp);
			break;
		case CONF_MGR_JOURNAL_INIT_REQ:
			bswap_journal_init_req(&data->u.journal_init_req);
			break;
		case CONF_MGR_JOURNAL_INIT_RESP:
			bswap_journal_init_resp(&data->u.journal_init_resp);
			break;
		case CONF_MGR_JOURNAL_JOIN_REQ:
			bswap_journal_init_req(&data->u.journal_init_req);
			break;
        /* begin SCSI III reservation messages */
        case CONF_MGR_CS_UPDATE_SCSI_ITN_RES:
            bswap_cache_cfm_update_scsi_itn_reservation_t(
                            &data->u.update_scsi_itn_reservation);
            break;
        case CONF_MGR_CS_UPDATE_SCSI_ITN_REG:
            bswap_cache_cfm_update_scsi_itn_registration_t(
                            &data->u.update_scsi_itn_registration);
            break;
        case CONF_MGR_CS_CLEAR_SCSI_ITN_RES:
            bswap_cache_cfm_clear_scsi_itn_reservation_t(
                            &data->u.clear_scsi_itn_reservation);
            break;
        case CONF_MGR_CS_ACQUIRE_SCSI_ITN_RES:
            bswap_cache_cfm_acquire_scsi_itn_reservation_t(
                            &data->u.acquire_scsi_itn_reservation);
            break;
        case CONF_MGR_CS_ACQUIRE_SCSI_ITN_REG:
            bswap_cache_cfm_acquire_scsi_itn_registration_t(
                            &data->u.acquire_scsi_itn_registration);
            break;
        case CONF_MGR_CS_UPDATE_CLEAR_SCSI_ITN_RES_RESP:
            bswap_cache_cfm_update_clear_scsi_itn_resg_resp_t(
                            &data->u.update_clear_scsi_itn_resg_response);
            break;
        case CONF_MGR_CS_ACQUIRE_SCSI_ITN_RES_RESP:
            bswap_cache_cfm_acquire_scsi_itn_res_resp_t(
                            &data->u.acquire_scsi_itn_reservation_response);
            break;
        case CONF_MGR_CS_ACQUIRE_SCSI_ITN_REG_RESP:
            bswap_cache_cfm_acquire_scsi_itn_reg_resp_t(
                            &data->u.acquire_scsi_itn_registration_response);
            break;
        /* end SCSI III reservation messages */
        case AGENT_CANCEL_UPGRADE:
            bswap_agent_get_ssd(&data->u.agent_cancel_upgrade);
            break;
        case AGENT_JNL_RECV_MIRROR:
            bswap_agent_jnl_recv_mirror(&data->u.agent_jnl_recv_mirror);
            break;
        default:
#ifndef __KERNEL__
            printf("bswap_cfm_cmd: type mismatch: %d\n",data->h.h_type);
            assert(0);
#endif
            break;
    }
    if(!in){
        data->h.h_type = bswap_32(data->h.h_type);
        data->h.h_cookie = bswap_64(data->h.h_cookie);
    }
#endif
}

DECLARE_PACKED_STRUCT(rft_msg_pull) {
    uint64_t client_cookie;             // rft_info index used on client side
	uint32_t type;
	char filename[RFT_FILENAME_LEN];
} END_PACKED_STRUCT(rft_msg_pull);

INLINE void bswap_rft_msg_pull(struct rft_msg_pull *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->client_cookie = bswap_64(data->client_cookie);
	data->type = bswap_32(data->type);
	//char filename[RFT_FILENAME_LEN];
#endif
}

DECLARE_PACKED_STRUCT(rft_msg_start) {
	uint32_t type;
	uint8_t md5_present;	
    uint8_t pad[3];                     ///< for future use
	char filename[RFT_FILENAME_LEN];
	uint64_t size;
	uint64_t server_cookie;             ///< rft_info index used on server side
    uint64_t client_cookie;             ///< rft_info index used on client side
	char md5[16];
} END_PACKED_STRUCT(rft_msg_start);

INLINE void bswap_rft_msg_start(struct rft_msg_start *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->type = bswap_32(data->type);
	//char filename[RFT_FILENAME_LEN];
	data->size = bswap_64(data->size);
	data->server_cookie = bswap_64(data->server_cookie);
	data->client_cookie = bswap_64(data->client_cookie);
	//char md5[16];
	//uint8_t md5_present;	
#endif
}

DECLARE_PACKED_STRUCT(rft_msg_open) {
	char     filename[RFT_FILENAME_LEN];
	uint32_t oflag;
} END_PACKED_STRUCT(rft_msg_open);

INLINE void bswap_rft_msg_open(struct rft_msg_open *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	//char     filename[RFT_FILENAME_LEN];
	data->oflag = bswap_32(data->oflag);
#endif
}

DECLARE_PACKED_STRUCT(rft_msg_open_resp) {
	uint32_t rft_id;
	uint32_t rft_errno;
} END_PACKED_STRUCT(rft_msg_open_resp);

INLINE void bswap_rft_msg_open_resp(struct rft_msg_open_resp *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->rft_id = bswap_32(data->rft_id);
	data->rft_errno = bswap_32(data->rft_errno);
#endif
}

DECLARE_PACKED_STRUCT(rft_msg_read) {
	uint32_t rft_id;
	uint32_t len;
} END_PACKED_STRUCT(rft_msg_read);

INLINE void bswap_rft_msg_read(struct rft_msg_read *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->rft_id = bswap_32(data->rft_id);
	data->len = bswap_32(data->len);
#endif
}

DECLARE_PACKED_STRUCT(rft_msg_read_resp) {
	uint32_t  bytes_read;
	uint32_t rft_errno;
	uint8_t data[RFT_PAYLOAD_LEN];
} END_PACKED_STRUCT(rft_msg_read_resp);

INLINE void bswap_rft_msg_read_resp(struct rft_msg_read_resp *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->bytes_read = bswap_32(data->bytes_read);
	//uint8_t data[RFT_PAYLOAD_LEN];
	data->rft_errno = bswap_32(data->rft_errno);
#endif
}

DECLARE_PACKED_STRUCT(rft_msg_write) {
	uint32_t rft_id;	
	uint32_t bytes;
	uint8_t data[RFT_PAYLOAD_LEN];
} END_PACKED_STRUCT(rft_msg_write);

INLINE void bswap_rft_msg_write(struct rft_msg_write *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->rft_id = bswap_32(data->rft_id);
	data->bytes = bswap_32(data->bytes);
	//uint8_t data[RFT_PAYLOAD_LEN];
#endif
}

DECLARE_PACKED_STRUCT(rft_msg_write_resp) {
	uint32_t  bytes_written;
	uint32_t rft_errno;
} END_PACKED_STRUCT(rft_msg_write_resp);

INLINE void bswap_rft_msg_write_resp(struct rft_msg_write_resp *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->bytes_written = bswap_32(data->bytes_written);
	data->rft_errno = bswap_32(data->rft_errno);
#endif
}

DECLARE_PACKED_STRUCT(rft_msg_fstat) {
	uint32_t rft_id;
} END_PACKED_STRUCT(rft_msg_fstat);

INLINE void bswap_rft_msg_fstat(struct rft_msg_fstat *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->rft_id = bswap_32(data->rft_id);
#endif
}

DECLARE_PACKED_STRUCT(rft_msg_fstat_resp) {
	uint64_t size;
	uint32_t res;
	uint32_t rft_errno;
} END_PACKED_STRUCT(rft_msg_fstat_resp);

INLINE void bswap_rft_msg_fstat_resp(struct rft_msg_fstat_resp *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->res = bswap_32(data->res);
	data->size = bswap_64(data->size);
	data->rft_errno = bswap_32(data->rft_errno);
#endif
}

DECLARE_PACKED_STRUCT(rft_msg_lseek) {
	uint64_t pos;
	uint32_t rft_id;
	uint32_t whence;
} END_PACKED_STRUCT(rft_msg_lseek);

INLINE void bswap_rft_msg_lseek(struct rft_msg_lseek *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->rft_id = bswap_32(data->rft_id);
	data->pos = bswap_64(data->pos);
	data->whence = bswap_32(data->whence);
#endif
}

DECLARE_PACKED_STRUCT(rft_msg_lseek_resp) {
	uint32_t res;
	uint32_t rft_errno;
} END_PACKED_STRUCT(rft_msg_lseek_resp);

INLINE void bswap_rft_msg_lseek_resp(struct rft_msg_lseek_resp *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->res = bswap_32(data->res);
	data->rft_errno = bswap_32(data->rft_errno);
#endif
}

DECLARE_PACKED_STRUCT(rft_msg_close) {
	uint32_t rft_id;
} END_PACKED_STRUCT(rft_msg_close);

INLINE void bswap_rft_msg_close(struct rft_msg_close *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->rft_id = bswap_32(data->rft_id);
#endif
}

DECLARE_PACKED_STRUCT(rft_msg_close_resp) {
	uint32_t res;
	uint32_t rft_errno;
} END_PACKED_STRUCT(rft_msg_close_resp);

INLINE void bswap_rft_msg_close_resp(struct rft_msg_close_resp *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->res = bswap_32(data->res);
	data->rft_errno = bswap_32(data->rft_errno);
#endif
}

DECLARE_PACKED_STRUCT(rft_msg_data) {
	uint32_t block;
	uint32_t len;
	uint64_t server_cookie;
	uint64_t client_cookie;
	uint8_t data[RFT_PAYLOAD_LEN];
} END_PACKED_STRUCT(rft_msg_data);

INLINE void bswap_rft_msg_data(struct rft_msg_data *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->block = bswap_32(data->block);
	data->len = bswap_32(data->len);
	data->server_cookie = bswap_64(data->server_cookie);
	data->client_cookie = bswap_64(data->client_cookie);
	//uint8_t data[RFT_PAYLOAD_LEN];
#endif
}

DECLARE_PACKED_STRUCT(rft_msg_abort) {
	uint64_t cookie;
	uint64_t rem_cookie;
} END_PACKED_STRUCT(rft_msg_abort);

INLINE void bswap_rft_msg_abort(struct rft_msg_abort *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->cookie = bswap_64(data->cookie);
	data->rem_cookie = bswap_64(data->rem_cookie);
#endif
}

DECLARE_PACKED_STRUCT(rft_msg_response) {
	uint64_t server_cookie;
	uint64_t client_cookie;
	uint32_t status;
} END_PACKED_STRUCT(rft_msg_response);

INLINE void bswap_rft_msg_response(struct rft_msg_response *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->cookie = bswap_64(data->server_cookie);
	data->cookie = bswap_64(data->client_cookie);
	data->status = bswap_32(data->status);
#endif
}

DECLARE_PACKED_STRUCT(rft_msg_done) {
	uint64_t server_cookie;
	uint64_t client_cookie;
} END_PACKED_STRUCT(rft_msg_done);

INLINE void bswap_rft_msg_done(struct rft_msg_done *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->server_cookie = bswap_64(data->server_cookie);
	data->client_cookie = bswap_64(data->client_cookie);
#endif
}

DECLARE_PACKED_STRUCT(rft_msg_copy) {
	uint32_t type;
	char     loc_filename[RFT_FILENAME_LEN];
	char     rem_filename[RFT_FILENAME_LEN];
} END_PACKED_STRUCT(rft_msg_copy);

INLINE void bswap_rft_msg_copy(struct rft_msg_copy *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->type = bswap_32(data->type);
	//char     loc_filename[RFT_FILENAME_LEN];
	//char     rem_filename[RFT_FILENAME_LEN];
#endif
}

DECLARE_PACKED_STRUCT(rft_msg_copy_resp) {
	uint32_t res;
	uint32_t rft_errno;
} END_PACKED_STRUCT(rft_msg_copy_resp);

INLINE void bswap_rft_msg_copy_resp(struct rft_msg_copy_resp *data)
{
    UNREFERENCED_PARAMETER(data);	
#if CPU_BE
	data->res = bswap_32(data->res);
	data->rft_errno = bswap_32(data->rft_errno);
#endif
}


DECLARE_PACKED_STRUCT(rft_cmd) {
	uint64_t cookie;
	uint32_t type;
	uint8_t resp;
    uint8_t pad[3];
	union {
		struct rft_msg_pull rft_msg_pull;
		struct rft_msg_start rft_msg_start;
		struct rft_msg_data rft_msg_data;
		struct rft_msg_abort rft_msg_abort;
		struct rft_msg_response rft_msg_response;
		struct rft_msg_done rft_msg_done;
		struct rft_msg_open rft_msg_open;
		struct rft_msg_open_resp rft_msg_open_resp;
		struct rft_msg_read rft_msg_read;
		struct rft_msg_read_resp rft_msg_read_resp;
		struct rft_msg_write rft_msg_write;
		struct rft_msg_write_resp rft_msg_write_resp;
		struct rft_msg_fstat rft_msg_fstat;
		struct rft_msg_fstat_resp rft_msg_fstat_resp;
		struct rft_msg_lseek rft_msg_lseek;
		struct rft_msg_lseek_resp rft_msg_lseek_resp;
		struct rft_msg_close rft_msg_close;
		struct rft_msg_close_resp rft_msg_close_resp;
		struct rft_msg_copy rft_msg_copy;
		struct rft_msg_copy_resp rft_msg_copy_resp;
	}u;		
} END_PACKED_STRUCT(rft_cmd);

INLINE void bswap_rft_cmd(struct rft_cmd *data,int in)
{
    UNREFERENCED_PARAMETER(data);	
    UNREFERENCED_PARAMETER(in);	
#if CPU_BE
	if(in){
		data->type = bswap_32(data->type);
		data->cookie = bswap_64(data->cookie);
	}
	//uint8_t resp;
	switch(data->type){
		case RFT_PULL:
			bswap_rft_msg_pull(&data->u.rft_msg_pull);
			break;
		case RFT_START:
			bswap_rft_msg_start(&data->u.rft_msg_start);
			break;
		case RFT_DATA:
			bswap_rft_msg_data(&data->u.rft_msg_data);
			break;
		case RFT_ABORT:
			bswap_rft_msg_abort(&data->u.rft_msg_abort);
			break;
		case RFT_RESPONSE:
			bswap_rft_msg_response(&data->u.rft_msg_response);
			break;
		case RFT_DONE:
			bswap_rft_msg_done(&data->u.rft_msg_done);
			break;
		case RFT_OPEN:
			if(data->resp)
				bswap_rft_msg_open_resp(&data->u.rft_msg_open_resp);
			else
				bswap_rft_msg_open(&data->u.rft_msg_open);
			
			break;
		case RFT_READ:
			if(data->resp)
				bswap_rft_msg_read_resp(&data->u.rft_msg_read_resp);
			else
				bswap_rft_msg_read(&data->u.rft_msg_read);
				
			break;
		case RFT_WRITE:
			if(data->resp)
				bswap_rft_msg_write_resp(&data->u.rft_msg_write_resp);
			else
				bswap_rft_msg_write(&data->u.rft_msg_write);
			
			break;
		case RFT_FSTAT:
			if(data->resp)
				bswap_rft_msg_fstat_resp(&data->u.rft_msg_fstat_resp);
			else
				bswap_rft_msg_fstat(&data->u.rft_msg_fstat);
				
			break;
		case RFT_LSEEK:
			if(data->resp)
				bswap_rft_msg_lseek_resp(&data->u.rft_msg_lseek_resp);
			else
				bswap_rft_msg_lseek(&data->u.rft_msg_lseek);
				
			break;
		case RFT_CLOSE:
			if(data->resp)
				bswap_rft_msg_close_resp(&data->u.rft_msg_close_resp);
			else		
				bswap_rft_msg_close(&data->u.rft_msg_close);
				
			break;
		case RFT_COPY:
			if(data->resp)
				bswap_rft_msg_copy_resp(&data->u.rft_msg_copy_resp);
			else		
				bswap_rft_msg_copy(&data->u.rft_msg_copy);
				
			break;
		default:
#ifndef __KERNEL__
			printf("bswap_rft_cmd: type mismatch %d\n",data->type);
			assert(0);
#endif	// !__KERNEL__
			break;
	}
	if(!in){
		data->type = bswap_32(data->type);
		data->cookie = bswap_64(data->cookie);
	}
#endif	// CPU_BE
}

#if defined(LINUX_USER) || defined(WINDOWS_USER)
/* Intra Node IPC data structures */

enum ipc_msg_type {
	IPC_MD_GET=1,
	IPC_MD_REP,
	IPC_MD_BLOCK_GET
};

#if !defined(_GNU_SOURCE)
struct msgbuf {
	long int mtype; /* type of received/sent message */
	char mtext[1];  /* text of the message */
};
#endif

DECLARE_PACKED_STRUCT(ipc_md_req) {
	char     pathname[PATHNAME_LEN];	
	uint64_t size;
	uint32_t open_flag;
	uint32_t open_mode;
	uint64_t block_number;
	uint64_t master_block_id; /* For linking records */
	rna_hash_key_t path_key; /* Note: For block records this is the base key. 24 bytes */
	uint8_t  cache_type; /* Block or Open call */
} END_PACKED_STRUCT(ipc_md_req);

DECLARE_PACKED_STRUCT(ipc_md_block_req) {
	uint32_t block_index;
	uint32_t num_blocks;
	rna_hash_key_t base_key;
} END_PACKED_STRUCT(ipc_md_block_req);

DECLARE_PACKED_STRUCT(ipc_cc_init) {
	uint64_t pid;
	char     appname[PATHNAME_LEN];
} END_PACKED_STRUCT(ipc_cc_init);

DECLARE_PACKED_STRUCT(ipc_cc_fini) {
	uint64_t pid;
} END_PACKED_STRUCT(ipc_cc_fini);


struct ipc_msg {
	union {
		struct ipc_md_req md_req;
		struct ipc_md_block_req block_req;
		struct ipc_cc_init init;
		struct ipc_cc_fini fini;
	}u;
};
#endif	// !__KERNEL__

DECLARE_PACKED_STRUCT(cfm_mgmt_get_state) {
	int a;
} END_PACKED_STRUCT(cfm_mgmt_get_state);

/*
Get state
Start CM
Stop CM
Add Group
Start Group
Stop Group
Rem Group
Add MD
Add CM
Get Perf Graph
Get Cur Stats

*/

struct cfm_mgm_msg{
	union {
		struct cfm_mgmt_get_state cfm_mgmt_get_state;
	}u;
};

/*
 * Return the length of an uninitialized cache command of the specified type
 */
INLINE size_t
empty_cache_cmd_length(int cmd_type)
{
    switch (cmd_type) {
        case META_DATA_QUERY:
            return sizeof(cmd_hdr_t) + sizeof(struct md_req) - PATHNAME_LEN;
            break;
        case META_DATA_RESPONSE:
            return sizeof(cmd_hdr_t) + sizeof(struct md_rep);
            break;
        case CACHE_REGISTER:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_reg);
            break;
        case CACHE_REGISTER_RESP:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_reg_resp);
            break;
        case CACHE_QUERY:
        case CACHE_QUERY_REQ_RESPONSE:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_req) - PATHNAME_LEN;
            break;
        case CACHE_RESPONSE:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_rep) - PATHNAME_LEN;
            break;
        case CACHE_RESPONSE_RESPONSE:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_rep_rep);
            break;
        case CACHE_QUERY_REQ:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_query_req);
            break;
        case CACHE_INVD:
        case CACHE_INVD_REP:
        case CACHE_LOCK_INVD:
        case CACHE_LOCK_INVD_REP:
        case CACHE_MASTER_INVD:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_invd) - PATHNAME_LEN;
            break;
        case CACHE_RSV_ACCESS:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_rsv_access)
                    - PATHNAME_LEN;
            break;
        case CACHE_RSV_ACCESS_V18:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_rsv_access_v18)
                    - PATHNAME_LEN;
            break;
        case CACHE_RSV_ACCESS_RESP:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_rsv_access_resp);
            break;
        case RESEND_REQ:
            return sizeof(cmd_hdr_t) + sizeof(struct resend_req);
            break;
        case CACHE_CHANGE_REF:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_change_ref);
            break;
        case CACHE_CFM_EVT:
            /* leave the buffer size at its default for this message type */
            return sizeof(struct cache_cmd);
            break;
        case RNA_ECHO:
            /* leave the buffer size at its default for this message type */
            return sizeof(struct cache_cmd);
            break;
        case CACHE_DEREF_REQUEST:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_deref_req);
            break;
        case CACHE_DEREF_REQUEST_RESP:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_deref_req_resp);
            break;
        case CACHE_CHANGE_REF_RESP:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_change_ref_resp);
            break;
        case CACHE_TRANS_REQ:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_trans_req) -
                                                                 PATHNAME_LEN;
            break;
        case CACHE_REG_PATH:
        case CACHE_DEREG_PATH:
            return sizeof(cmd_hdr_t) + sizeof(struct path_reg);
            break;
        case CACHE_WRITE_SAME:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_write_same_req);
            break;
        case CACHE_WRITE_SAME_RESP:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_write_same_resp);
            break;
        case CACHE_RELOCATE_BLOCK:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_relocate_block);
            break;
        case CACHE_ABSORB_BLOCK:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_absorb_block);
            break;
        case CACHE_ABSORB_BLOCK_RESP:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_absorb_block_resp);
            break;
        case CACHE_INVD_HOLD:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_invd_hold);
            break;
        case CACHE_INVD_HOLD_RESP:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_invd_hold_resp);
            break;
        case CACHE_COPY_DONE:
            return (sizeof(cmd_hdr_t) + sizeof(struct cache_copy_done) - PATHNAME_LEN);
            break;
        case CACHE_COMP_WR:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_comp_and_write_req);
            break;
        case CACHE_COMP_WR_RESP:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_comp_and_write_resp);
            break;
        case CACHE_REPLICA_STORE_CREATE:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_replica_store_create);
            break;
        case CACHE_REPLICA_STORE_CREATE_RESP:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_replica_store_create_resp);
            break;
        case CACHE_REPLICA_STORE_REMOVE:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_replica_store_remove);
            break;
        case CACHE_REPLICA_STORE_REMOVE_RESP:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_replica_store_remove_resp);
            break;
        case CACHE_SCSI_PASSTHRU:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_scsi_passthru);
            break;
        case CACHE_SCSI_PASSTHRU_RESP:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_scsi_passthru_resp);
            break;
        case CACHE_SCSI_UNITATTN:
            return (sizeof(cmd_hdr_t) + sizeof(struct cache_scsi_unitattn)
                    - PATHNAME_LEN);
            break;
        case CACHE_FAIL_CACHE_DEVICE:
        case CACHE_FAIL_CACHE_DEVICE_RESP:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_fail_cd);
            break;
        case CACHE_REG_PING:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_reg_ping);
            break;
        case CACHE_REG_PING_RESP:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_reg_ping_resp);
            break;
        case CS_TO_CLIENT_PING:
            return sizeof(cmd_hdr_t);
            break;
        case MD_CLIENT_PING:
            return sizeof(cmd_hdr_t);
            break;
        default:
#if defined(LINUX_USER) || defined(WINDOWS_USER)
            printf("%s: type mismatch: %d\n",__location__, cmd_type);
            assert(0);
#endif
            return sizeof(struct cache_cmd);
            break;  
    }   
}

/*
 * Return the length of the specified cache_cmd.
 */
INLINE size_t cache_cmd_length(struct cache_cmd *cmd)
{
    switch (cmd->h.h_type) {
        /*
         * Commands with pathnames
         */
		case META_DATA_QUERY:
            return ((empty_cache_cmd_length(cmd->h.h_type) +
                     strlen(cmd->u.md_query.rnas.mqs_pathname) + 1));
			break;
		case CACHE_ABSORB_BLOCK:
            return (empty_cache_cmd_length(cmd->h.h_type) +
                    (strlen(cmd->u.cache_absorb_block.rnas.cab_query_cmd.
                            mqs_pathname) + 1));
			break;
		case CACHE_QUERY:
		case CACHE_QUERY_REQ_RESPONSE:
            return ((empty_cache_cmd_length(cmd->h.h_type) +
                     strlen(cmd->u.cache_req.cr_path) + 1) +
                     (cmd->u.cache_req.pvt_data_len == 0
                      && cmd->u.cache_req.u.cq_has_client_id
                      ? sizeof(rsv_client_id_t) : 0));
			break;
		case CACHE_RESPONSE:
            return ((empty_cache_cmd_length(cmd->h.h_type) +
                     strlen(cmd->u.cache_rep.rnas.cr_pathname) + 1));
			break;
		case CACHE_INVD:
		case CACHE_INVD_REP:
        case CACHE_LOCK_INVD:
        case CACHE_LOCK_INVD_REP:
		case CACHE_MASTER_INVD:
            return (empty_cache_cmd_length(cmd->h.h_type) +
                    strlen(cmd->u.cache_invd.rnas.cis_pathname) + 1);
			break;
        case CACHE_RSV_ACCESS:
            return (empty_cache_cmd_length(cmd->h.h_type) +
                     strlen(cmd->u.cache_rsv_access.cra_pathname) + 1);
            break;
        case CACHE_RSV_ACCESS_V18:
            return (empty_cache_cmd_length(cmd->h.h_type) +
                     strlen(cmd->u.cache_rsv_access_v18.cra_pathname) + 1);
            break;
        case CACHE_CHANGE_REF:
            return empty_cache_cmd_length(cmd->h.h_type);
            break;
        case CACHE_TRANS_REQ:
            return ((empty_cache_cmd_length(cmd->h.h_type) +
                     strlen(cmd->u.cache_trans_req.ctr_pathname) + 1));
            break;
        case CACHE_COPY_DONE:
            return ((empty_cache_cmd_length(cmd->h.h_type) +
                     strlen(cmd->u.cache_copy_done.ccd_path) + 1));
            break;
	    case CACHE_REG_PATH:
	    case CACHE_DEREG_PATH:
            return empty_cache_cmd_length(cmd->h.h_type);
        /*
         * Commands without pathnames
         */
	    case CACHE_SCSI_PASSTHRU:
            return empty_cache_cmd_length(cmd->h.h_type);
            break;
	    case CACHE_SCSI_PASSTHRU_RESP:
            return empty_cache_cmd_length(cmd->h.h_type);
            break;
        case CACHE_SCSI_UNITATTN:
            return ((empty_cache_cmd_length(cmd->h.h_type) +
                     strlen(cmd->u.cache_scsi_unitattn.csu_pathname) + 1));
            break;
	    case CACHE_REG_PING:
            return empty_cache_cmd_length(cmd->h.h_type);
            break;
	    case CACHE_REG_PING_RESP:
            return empty_cache_cmd_length(cmd->h.h_type);
            break;
		default:
            return (empty_cache_cmd_length(cmd->h.h_type));
			break;
	}	
}

/*
 * Return the length of the specified cfm_cmd.
 */
INLINE size_t cfm_cmd_length(struct cfm_cmd *cmd)
{
	switch(cmd->h.h_type){
		case CONF_MGR_REG_CACHE:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_cfm_reg);
			break;
		case CONF_MGR_REG_CACHE_RESPONSE:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_cfm_reg_resp);
			break;
		case CONF_MGR_REG_CACHE_RESPONSE_V2:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_cfm_reg_resp_V2);
			break;
		case CONF_MGR_QUERY_CACHE_DEVICE:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_cfm_query_cachedev);
			break;
		case CONF_MGR_REG_CACHE_DEVICE:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_cfm_reg_cachedev) +
                strlen(cmd->u.cache_cfm_reg_cachedev.rnas.cdr_error_str) + 1;
			break;
		case CONF_MGR_REG_CACHE_DEVICE_END:
            return sizeof(cmd_hdr_t) +
                                    sizeof(struct cache_cfm_reg_cachedev_end);
			break;
		case CONF_MGR_DEREG_CACHE_DEVICE:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_cfm_dereg_cachedev);
			break;
		case CONF_MGR_UPDATE_CACHE_DEVICE:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_cfm_update_cachedev);
			break;
		case CONF_MGR_RESILVER_CACHE_DEVICE_COMPLETE:
            return sizeof(cmd_hdr_t) +
                        sizeof(struct cache_cfm_resilver_cachedev_complete);
			break;
		case CONF_MGR_RESILVER_CACHE_DEVICE_COMPLETE_RESP:
            return sizeof(cmd_hdr_t) +
                    sizeof(struct cache_cfm_resilver_cachedev_complete_resp);
			break;
		case CONF_MGR_NOTIFICATION_EVENT:
            return sizeof(cmd_hdr_t) +
                    sizeof(struct client_notification_event);
		case CONF_MGR_EXPEL_CACHE_DEVICE:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_cfm_expel_cachedev);
			break;
		case CONF_MGR_ABSORB_REPLICA_STORE:
		case CONF_MGR_DELETE_REPLICA_STORE:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_cfm_repstore);
			break;
        case CONF_MGR_DEREG_REPLICA_STORE:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_cfm_dereg_repstore);
            break;
		case CONF_MGR_REG_MD:
            return sizeof(cmd_hdr_t) + sizeof(struct md_cfm_reg);
			break;
		case CONF_MGR_REG_MD_RESPONSE:
            return sizeof(cmd_hdr_t) + sizeof(struct md_cfm_reg_resp);
			break;
		case CONF_MGR_UNEXPELLED_CACHEDEVS:
            return sizeof(cmd_hdr_t) + sizeof(struct cfm_unexpelled_cachedevs);
			break;
		case CONF_MGR_CONN_REG:
		case CONF_MGR_DISCONN_REG:
		case CONF_MGR_SERVICE_DEREG:
        case CONF_MGR_LOCAL_CS_REG:
            return sizeof(cmd_hdr_t) + sizeof(struct cfm_service_reg);
			break;
		case CONF_MGR_CONF_GET:
            return sizeof(cmd_hdr_t) + sizeof(struct cfm_config_get);
			break;
		case CONF_MGR_CONF_RESPONSE:
            return sizeof(cmd_hdr_t) + sizeof(struct cfm_config_resp);
			break;
		case CONF_MGR_REG_CLIENT:
            return sizeof(cmd_hdr_t) + sizeof(struct client_cfm_reg);
			break;
		case CONF_MGR_REG_CLIENT_RESP:
            return sizeof(cmd_hdr_t) + sizeof(struct cfm_client_resp);
			break;
		case CONF_MGR_REG_CLIENT_MOUNT:
            return sizeof(cmd_hdr_t) + sizeof(struct client_mount_reg);
			break;
        case CONF_MGR_QUERY_CACHED_LUN:
            return sizeof(cmd_hdr_t) +
                    sizeof(struct cache_cfm_query_cached_lun);
            break;
		case CONF_MGR_REG_PATH:
		case CONF_MGR_DEREG_PATH:
            return sizeof(cmd_hdr_t) + sizeof(struct path_reg);
			break;
		case CONF_MGR_REG_RESPONSE:
            return sizeof(cmd_hdr_t) + sizeof(struct cfm_reg_resp);
			break;
		case CONF_MGR_DEREG_CLIENT_MOUNT:
            return sizeof(cmd_hdr_t) + sizeof(struct client_mount_dereg);
			break;	
        case CONF_MGR_BLOCK_DEVICE_CREATE:
            return sizeof(cmd_hdr_t) +
                                sizeof(struct client_create_block_device);
            break;
        case CONF_MGR_BLOCK_DEVICE_CONTROL:
            return sizeof(cmd_hdr_t) +
                                sizeof(struct client_control_block_device);
            break;
        case CONF_MGR_BLOCK_DEVICE_CONTROL_RESP:
            return sizeof(cmd_hdr_t) +
                                sizeof(struct client_control_block_device_resp);
            break;
        case CONF_MGR_REG_BLOCK_DEVICE:
            return sizeof(cmd_hdr_t) +
                                sizeof(struct client_block_device_reg);
            break;
        case CONF_MGR_REG_BLOCK_DEVICE_RESP:
            return sizeof(cmd_hdr_t) +
                                sizeof(struct client_block_device_reg_resp);
            break;
        case CONF_MGR_DEREG_BLOCK_DEVICE:
            return sizeof(cmd_hdr_t) +
                                sizeof(struct client_block_device_dereg) +
                     strlen(cmd->u.client_block_device_dereg.dbs_name) + 1;
            break;
		case CONF_MGR_MD_REPORT:
            return sizeof(cmd_hdr_t) + sizeof(struct cfm_md_host_rep);
            break;
        case CONF_MGR_CONTROL_CS:
            return (sizeof(cmd_hdr_t) + sizeof(struct control_cs));
            break;
        case CONF_MGR_CONTROL_CS_RESP:
            return sizeof(cmd_hdr_t) + sizeof(struct control_cs_resp);
            break;
		case CONF_MGR_EVENT:
            return sizeof(cmd_hdr_t) + sizeof(struct rna_event);
			break;
		case CONF_MGR_EVENT_REG:
			return sizeof(cmd_hdr_t) + sizeof(struct rna_event_reg);
			break;
		case CONF_MGR_EVENT_DEREG:
			// Note: this command has no payload data.
            return sizeof(cmd_hdr_t);
			break;
		case CONF_MGR_CSTAT_REQ:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_stats_req);
			break;
		case CONF_MGR_CSTAT_RESP:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_stats);
			break;
		case CONF_MGR_CONTROL:
            return sizeof(cmd_hdr_t) + sizeof(struct cfm_control);
			break;
		case CONF_MGR_CONTROL_REJECT:
            return sizeof(cmd_hdr_t) + sizeof(struct cfm_control_reject);
			break;
		case CONF_MGR_ACTIVE_CS_CACHE_DEVICES:
            return sizeof(cmd_hdr_t) +
                            sizeof(struct cfm_md_active_cs_cache_devices);
			break;
		case CONF_MGR_CACHE_VIEW_STATUS:
            return sizeof(cmd_hdr_t) + sizeof(struct cfm_cache_view_status);
			break;
		case CONF_MGR_CACHE_VIEW_STATUS_REQ:
            return sizeof(cmd_hdr_t) + sizeof(struct cfm_cache_view_status_req);
			break;
		case AGENT_REGISTER:
            return sizeof(cmd_hdr_t) + sizeof(struct agent_cfm_reg);
			break;
		case AGENT_REG_RESPONSE:
            return sizeof(cmd_hdr_t) + sizeof(struct agent_reg_resp);
			break;
		case AGENT_CMD: // TODO: rename to APP_CONTROL
            return sizeof(cmd_hdr_t) + sizeof(struct agent_app_control);
			break;
		case PING: // TODO: rename to AGENT_PING
		case EMPTY_PING:
            return sizeof(cmd_hdr_t) + sizeof(struct agent_ping);
			break;
		case AGENT_TO_CFM_PING:  // identical to an AGENT_STATS_REP
            return sizeof(cmd_hdr_t) + sizeof(struct agent_stats_rep);
			break;
		case MD_TO_CFM_PING:
            return sizeof(cmd_hdr_t) + sizeof(struct md_to_cfm_ping);
			break;
		case CS_TO_CFM_PING:
            return sizeof(cmd_hdr_t) + sizeof(struct cs_to_cfm_ping);
			break;
		case FSCLIENT_TO_CFM_PING:
            return sizeof(cmd_hdr_t) + sizeof(struct fsclient_to_cfm_ping);
			break;
		case AGENT_DISCONNECT:
			// Note: agent disconnect command has no payload data.
            return sizeof(cmd_hdr_t);
			break;
		case MOUNT_BLOCKED:
		case MOUNT_UNBLOCKED:
		case CONF_MGR_BSTAT_REQ:
            return sizeof(cmd_hdr_t);
			break;
		case CONF_MGR_BSTAT_RESP:
            return sizeof(cmd_hdr_t) + sizeof(struct blkdev_stats);
			break;
        case CONF_MGR_MD_PARTITION_MAP:
            return sizeof(cmd_hdr_t) + sizeof(struct cfm_md_partition_map);
			break;
        case CACHE_MASTER_INVD:
            return (sizeof(cmd_hdr_t) + sizeof(struct cache_invd)
                             - PATHNAME_LEN 
                             + strlen(cmd->u.cache_invd_req.rnas.cis_pathname)
                             + 1);
            break;
		case AGENT_GET_SSD:
            return sizeof(cmd_hdr_t) + sizeof(struct agent_get_ssd);
			break;
		case AGENT_GET_SSD_REP:
            return sizeof(cmd_hdr_t) + sizeof(struct agent_get_ssd_rep);
			break;
		case CONF_MGR_PREPARE_DELETE_HCC:
            return sizeof(cmd_hdr_t) + sizeof(struct cfm_prepare_delete_hcc);
			break;
		case CONF_MGR_PREPARE_DELETE_HCC_RESP:
            return sizeof(cmd_hdr_t) +
                        sizeof(struct cfm_prepare_delete_hcc_resp);
			break;
        case CONF_MGR_CACHED_LUN_WRITE_ALL_INITIATE:
            return sizeof(cmd_hdr_t) +
                        sizeof(struct cache_cfm_cached_lun_write_all_initiate);
            break;
        case CONF_MGR_CACHED_LUN_WRITE_ALL_CONCLUDE:
            return sizeof(cmd_hdr_t) +
                        sizeof(struct cache_cfm_cached_lun_write_all_conclude);
            break;
        case CONF_MGR_CS_SHUTDOWN_REQ:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_cfm_shutdown_req);
            break;
        case CONF_MGR_CS_SHUTDOWN_RESP:
            return sizeof(cmd_hdr_t) + sizeof(struct cache_cfm_shutdown_resp);
            break;
        case CONF_MGR_CFM_SHUTDOWN_STATUS:
            return sizeof(cmd_hdr_t) + sizeof(struct cfm_shutdown_status);
            break;
        case CONF_MGR_CFM_SHUTDOWN_GRANT:
            return sizeof(cmd_hdr_t) + sizeof(struct cfm_shutdown_grant);
            break;
		case CONF_MGR_JOURNAL_READ_REQ:
            return sizeof(cmd_hdr_t) + sizeof(struct cfm_journal_read_request);
			break;
		case CONF_MGR_JOURNAL_READ_RESP:
            return sizeof(cmd_hdr_t) + sizeof(struct cfm_journal_read_response);
			break;
		case CONF_MGR_JOURNAL_WRITE_REQ:
            return sizeof(cmd_hdr_t) + sizeof(struct cfm_journal_write_request);
			break;
		case CONF_MGR_JOURNAL_WRITE_RESP:
            return sizeof(cmd_hdr_t) + sizeof(struct cfm_journal_write_response);
			break;
		case CONF_MGR_JOURNAL_INIT_REQ:
            return sizeof(cmd_hdr_t) + sizeof(struct cfm_journal_init_request);
			break;
		case CONF_MGR_JOURNAL_JOIN_REQ:
            return sizeof(cmd_hdr_t) + sizeof(struct cfm_journal_init_request);
			break;
		case CONF_MGR_JOURNAL_INIT_RESP:
            return sizeof(cmd_hdr_t) + sizeof(struct cfm_journal_init_response);
			break;
        /* Begin SCSI III reservation messages */
        case CONF_MGR_CS_UPDATE_SCSI_ITN_RES:
            return sizeof(cmd_hdr_t) +
                         sizeof(cache_cfm_update_scsi_itn_reservation_t);
            break;
        case CONF_MGR_CS_UPDATE_SCSI_ITN_REG:
            return sizeof(cmd_hdr_t) +
                         sizeof(cache_cfm_update_scsi_itn_registration_t);
            break;
        case CONF_MGR_CS_CLEAR_SCSI_ITN_RES:
            return sizeof(cmd_hdr_t) +
                         sizeof(cache_cfm_clear_scsi_itn_reservation_t);
            break;
        case CONF_MGR_CS_ACQUIRE_SCSI_ITN_RES:
            return sizeof(cmd_hdr_t) +
                         sizeof(cache_cfm_acquire_scsi_itn_res_t);
            break;
        case CONF_MGR_CS_ACQUIRE_SCSI_ITN_REG:
            return sizeof(cmd_hdr_t) +
                         sizeof(cache_cfm_acquire_scsi_itn_reg_t);
            break;
        case CONF_MGR_CS_UPDATE_CLEAR_SCSI_ITN_RES_RESP:
            return sizeof(cmd_hdr_t) +
                         sizeof(cache_cfm_update_clear_scsi_itn_resg_resp_t);
            break;
        case CONF_MGR_CS_ACQUIRE_SCSI_ITN_RES_RESP:
            return sizeof(cmd_hdr_t) +
                         sizeof(cache_cfm_acquire_scsi_itn_res_resp_t);
            break;
        case CONF_MGR_CS_ACQUIRE_SCSI_ITN_REG_RESP:
            return sizeof(cmd_hdr_t) +
                         sizeof(cache_cfm_acquire_scsi_itn_reg_resp_t);
            break;
        /* end SCSI III reservation messages */
		case AGENT_CANCEL_UPGRADE:
            return sizeof(cmd_hdr_t) + sizeof(struct agent_cancel_upgrade);
			break;
		case AGENT_JNL_RECV_MIRROR:
            return sizeof(cmd_hdr_t) + sizeof(struct agent_jnl_recv_mirror_req);
			break;

            /*
             * Command types used internally by the MD to
             * process partition tables from these
             * commands on a cfm workq
             */
        case META_DATA_SYNC_REQUEST:
            return sizeof(cmd_hdr_t) + sizeof(struct md_sync_request);
            break;
        case META_DATA_SYNC_DATA_END:
            return sizeof(cmd_hdr_t) + sizeof(struct md_sync_data_end);
            break;

        default:
#if defined(LINUX_USER) || defined(WINDOWS_USER)
			printf("%s: type mismatch: %d\n",__location__,cmd->h.h_type);
			assert(0);
#endif
            return sizeof(struct cfm_cmd);
            break;
	}
}

/*
 * Return the length of an uninitialized md_sync_cmd of the specified type
 */
INLINE int empty_md_sync_cmd_length(int cmd_type)
{
    switch(cmd_type){
        case META_DATA_SYNC_REQUEST:
        case META_DATA_SYNC_DONE:
            return sizeof(cmd_hdr_t) + sizeof(struct md_sync_request);
            break;
        case META_DATA_SYNC_DATA:
        case CS_SYNC_DATA:
            return sizeof(cmd_hdr_t) + sizeof(struct md_sync_data) -
                                                                PATHNAME_LEN;
            break;
        case META_DATA_SYNC_DATA_END:
            return sizeof(cmd_hdr_t) + sizeof(struct md_sync_data_end);
            break;
        case CS_SYNC_DATA_END:
            return sizeof(cmd_hdr_t) + sizeof(struct cs_sync_data_end);
            break;
        default:
#if defined (LINUX_USER) || defined (WINDOWS_USER)
            printf("%s: type mismatch: %d\n",__location__,cmd_type);
            assert(0);
#endif
            return sizeof(struct md_sync_cmd);
            break;
    }
}

/*
 * Return the length of the specified md_sync_cmd.
 */
INLINE size_t md_sync_cmd_length(struct md_sync_cmd *cmd)
{
    switch(cmd->h.h_type){
        /*
         * Commands with pathnames
         */
        case META_DATA_SYNC_DATA:
        case CS_SYNC_DATA:
            return (empty_md_sync_cmd_length(cmd->h.h_type) +
                    strlen(cmd->u.md_sync_data.msd_path) + 1);
            break;
        /*
         * Commands without pathnames
         */
        default:
            return empty_md_sync_cmd_length(cmd->h.h_type);
            break;
    }
}

struct cache_or_cfm_cmd {
    union {
        struct cache_cmd    cache_cmd;
        struct cfm_cmd      cfm_cmd;
    } u;
};

INLINE rna_boolean
match_rna_service_id(const struct rna_service_id *service_id1,
                     const struct rna_service_id *service_id2,
                     int                          match_timestamp)
{
    return ((service_id1->u.hash == service_id2->u.hash) &&
            (!match_timestamp ||
             (service_id1->start_time == service_id2->start_time)));
}

/* TODO: 
		1. Provide a compile option to disable byteswapping. 
		2. Runtime detection if swapping is necessary.
*/

/*
 * SCSI Reservation related access states assigned to client(s).
 * Note: these are intentionally ordered by decreasing access.
 */
typedef enum {
    RSV_ACC_READWRITE,
    RSV_ACC_READONLY,
    RSV_ACC_NONE,
} rsv_access_t;

/*
 * Return a negative value if access_1 is more restrictive than access_2,
 * 0 if access_1 is the same as access_2,
 * and a positive value if access_1 is less restrictive than access_2.
 */
INLINE int
rsv_access_compare(rsv_access_t access_1, rsv_access_t access_2)
{
    return (access_2 - access_1);
}

/* Return TRUE if 'access_1' is more restrictive than 'access_2' */
#define rsv_access_is_less(acc1, acc2) \
    (rsv_access_compare((acc1), (acc2)) < 0)

INLINE const char *
rsv_access_string(rsv_access_t access)
{
    const char * ret = NULL;

    switch (access) {
        case RSV_ACC_NONE:
            ret = "NOACCESS";
            break;
        case RSV_ACC_READONLY:
            ret = "READONLY";
            break;
        case RSV_ACC_READWRITE:
            ret = "READWRITE";
            break;
    }
    return ret;
}

/* An initializer for a primary_cfm_id_t */
#define PRIMARY_CFM_ID_INITIALIZER    \
    {0, {INADDR_NONE}}
#if defined(LINUX_USER) || defined(WINDOWS_USER)

/*
 * A container for storing a primary_cfm_id_t.
 */
typedef struct primary_cfm_id_container_s {
    pthread_mutex_t   pcic_mutex;       /* A mutex to allow pcic_pci to be
                                         * read/written consistently.
                                         */
    /* The following are guarded by pcic_mutex: */
    primary_cfm_id_t  pcic_pci;         /* ID of the current primary CFM */
} primary_cfm_id_container_t;

/* An initializer for a primary_cfm_id_container_t */
#define PRIMARY_CFM_ID_CONTAINER_INITIALIZER    \
    {PTHREAD_MUTEX_INITIALIZER,                 \
     PRIMARY_CFM_ID_INITIALIZER}

/*
 * Copy a primary cfm id from the specified primary cfm id container to the the
 * specified primary cfm id.
 */
INLINE void
copy_primary_cfm_id(primary_cfm_id_container_t *source,
                    primary_cfm_id_t           *dest)
{
    if (NULL == source) {
        memset(dest, 0, sizeof(*dest));
    } else {
        pthread_mutex_lock(&source->pcic_mutex);
        *dest = source->pcic_pci;
        pthread_mutex_unlock(&source->pcic_mutex);
    }
}

INLINE int
com_send_cache_cmd(com_ep_handle_t            *eph,
                   struct send_buf_entry      *cmd,
                   primary_cfm_id_container_t *pcic)
{
    /* Reduce the send buf length to the actual length of the message.  */
    cmd->length = cache_cmd_length((struct cache_cmd *)cmd->mem);

    copy_primary_cfm_id(pcic, &((struct cfm_cmd *)cmd->mem)->h.h_pci);
	bswap_cache_cmd((struct  cache_cmd*)cmd->mem,0);
	return com_send(eph,cmd);
}

INLINE int
com_send_cfm_cmd(com_ep_handle_t            *eph,
                 struct send_buf_entry      *cmd,
                 primary_cfm_id_container_t *pcic)
{
    /* Reduce the send buf length to the actual length of the message.  */
    cmd->length = cfm_cmd_length((struct cfm_cmd *)cmd->mem);

    copy_primary_cfm_id(pcic, &((struct cfm_cmd *)cmd->mem)->h.h_pci);
	bswap_cfm_cmd((struct cfm_cmd*)cmd->mem,0);
	return com_send(eph,cmd);
}

INLINE int com_send_rft_cmd(com_ep_handle_t *eph, struct send_buf_entry *cmd){
    cmd->length = sizeof(struct rft_cmd);
	bswap_rft_cmd((struct  rft_cmd*)cmd->mem,0);
	return com_send(eph,cmd);
}

INLINE int com_send_mcp_cmd(com_ep_handle_t *eph, struct send_buf_entry *cmd){
    cmd->length = sizeof(struct mcp_cmd);
	bswap_mcp_cmd((struct  mcp_cmd*)cmd->mem,0);
	return com_send(eph,cmd);
}

INLINE int com_send_md_sync_cmd(com_ep_handle_t *eph, struct send_buf_entry *cmd){
    /* Reduce the send buf length to the actual length of the message.  */
    cmd->length = md_sync_cmd_length((struct md_sync_cmd *)cmd->mem);

	bswap_md_sync_cmd((struct md_sync_cmd*)cmd->mem, FALSE);
	return com_send(eph,cmd);
}

#endif	// !__KERNEL__

#endif	// _PROTOCOL_H_

/* Emacs settings */
/* 
 * Local Variables:
 * c-basic-offset: 4
 * c-file-offsets: ((substatement-open . 0))
 * tab-width: 4
 * End:
 */
