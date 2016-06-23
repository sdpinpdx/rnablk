/**
 * <rna_service_cs_md.h> - Dell Fluid Cache block driver
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
 * A set of rna_service APIs used only by cache servers and metadata servers
 * (i.e. rna_service users of type RNA_SERVICE_USER_TYPE_CACHE_SERVER or
 * RNA_SERVICE_USER_TYPE_METADATA_SERVER).
 */
#ifndef _RNA_SERVICE_CS_MD_H_
#define _RNA_SERVICE_CS_MD_H_

#include "platform.h"

CODE_IDENT("$URL: https://svn.rnanetworks.com/full/tags/HERMES_2_1_0_RC1/common/rna_service_cs_md.h $ $Id: rna_service_cs_md.h 42068 2015-04-07 17:30:41Z pkrueger $")

/*
 * A cache response message (RNA_SERVICE_MESSAGE_TYPE_CACHE_RESPONSE).
 */
DECLARE_PACKED_STRUCT(rna_service_cache_response) {
    uint64_t    cr_cookie;
    rna_addr_t  cr_cache_buf;
    rna_rkey_t  cr_rkey;
    rna_addr_t  cr_direct_cache_buf;  /**< If direct access to the block (DMA
                                       *   or RDMA) is possible cr_direct_rkey
                                       *   will be nonzero and direct_cache_buf
                                       *   will be valid */
    rna_rkey_t  cr_direct_rkey;
    uint32_t    cr_length;
    uint32_t    cr_pvt_data_len;
    uint64_t    cr_rid; /**< Cache record ID. */
    uint64_t    cr_cache_cookie;
                            /**< cookie from the cache manager to identify
                             **< the cache block on any subsequent operations
                             */
    rna_service_hash_key_t
                cr_path_key; /**< Path key (MD5 sum of the pathname) 24 bytes */
    cachedev_id_t
                cr_cachedev_id;  /**< ID of cache-device */
    uint8_t     cr_status; /**< 0=success anything else indicates an error */
    uint8_t     cr_cache_type;
    uint8_t     cr_write_mode; /**< write trough, scratchpad @see cache_write_mode_t */
    uint8_t     cr_invd_mode; /**< file or block @see cache_invd_mode_t */
    uint8_t     cr_evict_policy; /**< Controls if/when cache blocks are evicted. @see cache_evict_policy_t */
    uint8_t     cr_hash_partition;
    uint8_t     cr_ref_type;       /**< type of reference currently held by client */
    uint8_t     cr_orig_ref_type;  /**< type of reference previously held by client */
    uint32_t    cr_reader_uid; /**< uid file block was read into cache as */
    uint32_t    cr_reader_gid; /**< gid file block was read into cache as */
    uint64_t    cr_block_number;
    uint64_t    cr_block_size;
    uint64_t    cr_mem_locked;  /**< used by the MD to get an accurate view of
                             **< amount of memory locked by the cache server */
    uint64_t    cr_mem_locked_gen;  /**< used by the MD to assure that obsolete
                                 **< information isn't used */
    uint64_t    cr_mem_used;    /**< used by the MD to get an accurate view of
                             **< amount of memory available on cache server  */
    uint64_t    cr_mem_used_gen;    /**< used by the MD to assure that obsolete
                                 **< information isn't used */
    uint64_t    cr_mtime_sec; /**< last modified time stamp the cache block */
    uint64_t    cr_mtime_nsec;
    uint64_t    cr_file_size; /**< Used to sync file size for write_update mode of operation */
    uint64_t    cr_cache_pid; /**< PID of cache server, used for local client direct memory copy */
    char        cr_pvt_data[RNA_SERVICE_PVT_DATA_MAX];
    char        cr_pathname[1]; /*! Full path name of the file as a variable-
                                 *  length string (declared length 1 rather
                                 *  than 0 to avoid upsetting the windows
                                 *  compiler, which warns about fields that
                                 *  follow variable-length fields).
                                 *  MUST BE LAST.
                                 */
} END_PACKED_STRUCT(rna_service_cache_response);


/*
 * A cache query request message (RNA_SERVICE_MESSAGE_TYPE_CACHE_QUERY_REQUEST).
 */
DECLARE_PACKED_STRUCT(rna_service_cache_query_request) {
    uint8_t     cqr_cache_type;     /*! Master or Block record.  @see
                                     *  cache_req_type_t
                                     */
    uint8_t     cqr_unused[7]; /**< alignment padding */
    uint64_t    cqr_md_rid;
    uint64_t    cqr_cs_rid;
    cachedev_id_t
                cqr_cachedev_id;
    uint64_t    cqr_block_number;
    char        cqr_pathname[1];/*! Full path name of the file as a variable-
                                 *  length string (declared length 1 rather
                                 *  than 0 to avoid upsetting the windows
                                 *  compiler).  MUST BE LAST.
                                 */
} END_PACKED_STRUCT(rna_service_cache_query_request);


/* (Make sure these values don't collide with rna_service_message_type_t) */
typedef enum rna_service_cs_md_message_type_e {
    /* Messages to send: */
    RNA_SERVICE_MESSAGE_TYPE_CACHE_RESPONSE = 100,
    RNA_SERVICE_MESSAGE_TYPE_CACHE_QUERY_REQUEST = 101,
} PACKED rna_service_cs_md_message_type_t;


/*!
 * A buffer for a message sent to a cache server or metadata server
 * (RNA_SERVICE_USER_TYPE_CACHE_SERVER or RNA_SERVICE_USER_TYPE_METADATA_SERVER)
 */
DECLARE_PACKED_STRUCT(rna_service_cs_md_message_buffer) {
    rna_service_message_buffer_header_t     h;
    union {
        rna_service_cache_response_t cmb_cache_response;
        rna_service_cache_query_request_t cmb_cache_query_request;
    } u;
} END_PACKED_STRUCT(rna_service_cs_md_message_buffer);


/*!
 * This function is an rna_service callback that's used by cache servers only
 * (RNA_SERVICE_USER_TYPE_CACHE_SERVER), and is invoked if an asynchronous
 * message (a message that isn't a response to a message from this cache
 * server) is received.  These messages are CACHE_QUERY, CACHE_DEREF, and
 * CACHE_MASTER_INVD.  Note that each of these message types can be received
 * from either MDs or clients.  This callback is invoked when these messages
 * are received from MDs.
 *
 * NOTE that the callback function is responsible for freeing the message
 * using rna_service_free_message_buffer().
 *
 * Arguments:
 *    ctx        The user's rna_service context, as created by
 *               rna_service_ctx_create.
 *
 *    message   A pointer to a message of one of the above types.
 */
typedef void (*rna_service_async_cs_msg_callback) (
                                            struct rna_service_ctx_s *ctx,
                                            void                     *message);

/*!
 * This function is an rna_service callback that's used by cache servers only
 * (RNA_SERVICE_USER_TYPE_CACHE_SERVER), and is invoked if a sync request
 * message is received from a metadata server.
 *
 * NOTE that the callback function is NOT responsible for freeing the message.
 *
 * Arguments:
 *    eph       The ep header for the ep that should be used for the sync
 *    message   A pointer to the message received
 */
typedef int (*rna_service_sync_request_callback) (
#if defined(LINUX_USER) || defined(WINDOWS_USER)
                                                 com_ep_handle_t *eph,
#else   // com_ep_handle_t doesn't exist at kernel level
                                                 void            *eph,
#endif  // __KERNEL__
                                                 void            *message);

/*!
  * Structure that contains all rna_service configuration options for cache
  * servers (users of type RNA_SERVICE_USER_TYPE_CACHE_SERVER).
  */
typedef struct rna_service_cs_params_s {
    uint64_t                    csp_cs_max_mem;
                                    /*! Maximum memory allocatable to cache data
                                     */
    uint64_t                    csp_cs_total_mem;
                                    /*! Cache server's "total memory" */
    uint64_t                    csp_cs_avail_mem;
                                    /*! Cache server's available memory */
    uint32_t                    csp_cs_status;
                                    /*! CACHE_AVAILABLE or CACHE_UNAVAILABLE,
                                     *  depending on whether the cache server
                                     *  has all the necessary mounts.
                                     */
    int                         csp_cs_workq_threads;
                                    /*! The number of work queue threads used
                                     *  to handle cfm messages.
                                     */
    void                       *csp_cs_path_data;
    void                       *csp_cs_ping_data;
    int                         csp_cs_ping_data_length;
    time_t                      csp_cache_response_timeout;
                                    /*! The amount of time the cache server is
                                     *  willing to wait for a response to a
                                     *  RNA_SERVICE_MESSAGE_TYPE_CACHE_RESPONSE
                                     *  (rna_service_cache_response_t)
                                     *  message, in seconds.
                                     *  This timeout is also used for
                                     *  RNA_SERVICE_MESSAGE_TYPE_CACHE_QUERY_REQUEST
                                     *  and RNA_SERVICE_MESSAGE_TYPE_REG_PATH.
                                     *
                                     *  0 indicates the cache server is willing
                                     *  to wait forever.
                                     */
    rna_service_async_cs_msg_callback
                                csp_cs_async_msg_callback;
                                    /*! Callback invoked if a cache-server
                                     *  specific asynchronous message is
                                     *  received (for example, an
                                     *  rna_service_cache_query,
                                     *  rna_service_cache_deref, or
                                     *  rna_service_master_invd).
                                     *
                                     *  May be NULL, if the user isn't
                                     *  interested in these messages.
                                     */
    rna_service_sync_request_callback
                                csp_sync_request_callback;
                                    /*! Callback invoked if a sync request is
                                     *  received from a metadata server.
                                     */
    struct rna_if_table csp_cs_if_tbl;
                                    /**< Network interfaces available. */
} rna_service_cs_params_t;


/*!
  * Structure that contains all rna_service configuration options for metadata
  * servers (users of type RNA_SERVICE_USER_TYPE_METADATA_SERVER).
  */
typedef struct rna_service_md_params_s {
    uint64_t                    mdp_pad;
} rna_service_md_params_t;


/*
 * Cache servers and metadata servers must use the following in place of
 * rna_service_ctx_create().
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
extern rna_service_error_t
rna_service_cs_md_ctx_create(rna_service_params_t      *params,
                             rna_service_cs_params_t   *cs_params,
                             rna_service_md_params_t   *md_params,
                             struct rna_service_ctx_s **ctxpp);


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
extern int
rna_service_cs_send_event_to_cfm(void *arg,
                                 uint32_t event_type,
                                 char *event_msg);


/*!
 * Send MOUNT_BLOCKED to the configuration manager.
 *
 * The caller must be a user of type RNA_SERVICE_USER_TYPE_CACHE_SERVER.
 */
extern void
rna_service_cs_send_mount_blocked_to_cfm(void *arg);


/*!
 * Send MOUNT_UNBLOCKED to the configuration manager.
 *
 * The caller must be a user of type RNA_SERVICE_USER_TYPE_CACHE_SERVER.
 */
extern void
rna_service_cs_send_mount_unblocked_to_cfm(void *arg);


/*!
 * Allocate an rna_service cs_md_message buffer.
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
extern rna_service_cs_md_message_buffer_t *
rna_service_alloc_cs_md_message_buffer(struct rna_service_ctx_s  *ctx,
                                       rna_service_cs_md_message_type_t
                                                                  msg_type,
                                       const char                *pathname);


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
extern rna_service_error_t
rna_service_cs_send_md(struct rna_service_ctx_s           *ctx,
                       rna_service_cs_md_message_buffer_t *message,
                       rna_service_response_callback       response_callback);


/**
 * Send the specified message to the appropriate MD, ignoring limits on the
 * maximum number of oustanding messages, and invoke the specified callback
 * when a response arrives. Same as rna_service_cs_send_md except for 
 * not checking limits on outstanding messages. (in most cases 
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
extern rna_service_error_t
rna_service_cs_send_md_nomaxcheck(struct rna_service_ctx_s           *ctx,
                                  rna_service_cs_md_message_buffer_t *message,
                                  rna_service_response_callback       response_callback);

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
 *    RNA_SERVICE_ERROR_NO_MEMORY
 *                            Memory allocation failed.
 */
extern rna_service_error_t
rna_service_cs_register_cache_device(struct rna_service_ctx_s     *ctx,
                                     rna_service_message_buffer_t *buf);


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
extern rna_service_error_t
rna_service_cs_deregister_cache_device(struct rna_service_ctx_s     *ctx,
                                       rna_service_message_buffer_t *buf);


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
extern rna_service_error_t
rna_service_cs_deregister_replica_store(struct rna_service_ctx_s     *ctx,
                                        rna_service_message_buffer_t *buf);


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
extern rna_service_error_t
rna_service_cs_initial_cache_device_registrations_complete(
                                                struct rna_service_ctx_s *ctx,
                                                void *cmd);


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
extern rna_service_error_t
rna_service_cs_send_resilver_cache_device_complete(
                                        struct rna_service_ctx_s     *ctx,
                                        rna_service_message_buffer_t *buf);


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
extern rna_service_error_t
rna_service_cs_send_shutdown_request(
                            struct rna_service_ctx_s     *ctx,
                            rna_service_message_buffer_t *buf,
                            int                           send_timeout_sec);

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
                                    rna_service_message_buffer_t *buf);

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
                                    rna_service_message_buffer_t *buf);
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
                                    rna_service_message_buffer_t *buf);

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
                                    rna_service_message_buffer_t *buf);

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
                                    rna_service_message_buffer_t *buf);
#endif // _RNA_SERVICE_CS_MD_H_
