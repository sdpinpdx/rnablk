/**
 * <rnablk_protocol.c> - Dell Fluid Cache block driver
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
 * Here you will find all functions that deal with protocol and rna_service
 * messages
 */

#include "rnablk_protocol.h"
#include "rnablk_io_state.h"
#include "rnablk_cache.h"
#include "rnablk_util.h"
#include "rnablk_queue_dispatch.h"
#include "rnablk_device.h"
#include "rnablk_data_transfer.h"
#include "rnablk_globals.h"
#include "rnablk_scsi.h"
#include "rnablk_comatose.h" // for rnablk_stop_devs
#include "trace.h"

#ifdef WINDOWS_KERNEL
#include "rna_service_win_workqueue.h"
#include "rna_vsmp.h"
#include <stdio.h>
#endif

struct cache_req_pvt_data {
    ios_tag_t   tag;
};

struct md_req_pvt_data {
    uint64_t    device_id;      //< Handle to block device structure
};

rna_service_params_t rna_service_params;

/*
 * Single Node DAS mode support
 * The CFM sends a message to fill in these for
 * the local CS. This is used for
 * paths that are flagged as DAS (rbd_das in the
 * rnablk struct).
 */
struct rna_if_table    rbd_cs_if;    /* CS address info */
struct rna_service_id rbd_cs_svc_id; /* CS service ID info */

atomic_t  rbd_local_cs_connect = {FALSE};

int fldc_default_block_size = 0;

/* private prototypes */

static void
rnablk_process_change_ref_response(struct com_ep *ep,
                                   struct io_state *ios,
                                   void *data);

static void
rnablk_process_cache_response(struct com_ep *ep,
                              struct io_state *ios,
                              void *data);

static void
process_write_same_response(struct com_ep *ep,
                            struct io_state *ios,
                            struct cache_cmd *cmd);
static void
process_comp_and_write_response(struct com_ep *ep,
                                struct io_state *ios,
                                struct cache_cmd *cmd);
static void
process_scsi_passthru_response(struct com_ep *ep,
                               struct io_state *ios,
                               struct cache_cmd *cmd);

static void rnablk_process_scsi_unitattn(struct com_ep *ep,
                             struct cache_cmd *cmd);

static void rnablk_process_cache_rsv_access(struct com_ep    *ep,
                                struct cache_cmd *cmd);

static void
rnablk_queue_cache_trans_req(struct com_ep    *ep,
                             struct cache_cmd *cmd);

int rnablk_metadata_query(struct io_state *ios);

static int
rnablk_das_metadata_query(struct rnablk_device *dev,
                          struct rna_service_ctx_s *ctx,
                          rna_service_message_buffer_t *mbuf,
                          rna_service_response_callback response_callback);

int rnablk_deferred_process_create_block_device(
                            struct rna_service_ctx_s     *ctx,
                            rna_service_message_buffer_t *message);
int rnablk_deferred_process_control_block_device(
                                    struct rna_service_ctx_s     *ctx,
                                    rna_service_message_buffer_t *message);

static void rnablk_do_rsv_access_resp(struct rnablk_device *dev,
                        boolean is_reduce, uint32_t generation,
                        boolean is_initial_check);

static int
rnablk_get_cmd_status(struct cache_cmd *cmd)
{
    int status;

    switch (cmd->h.h_type) {
    case CACHE_CHANGE_REF_RESP:
        status = cmd->u.cache_change_ref_resp.status;
        break;
    case CACHE_RESPONSE:
        status = cmd->u.cache_rep.rnas.cr_status;
        break;
    case CACHE_WRITE_SAME_RESP:
        status = cmd->u.cache_write_same_resp.wsr_status;
        break;
    case CACHE_COMP_WR_RESP:
        status = cmd->u.cache_comp_wr_resp.cwr_status;
        break;
    case CACHE_SCSI_PASSTHRU_RESP:
        status = cmd->u.cache_scsi_passthru_resp.cs_status;
        break;
    default:
        rna_printk(KERN_ERR, "cmd=%p type [%s] unexpected type\n",
                   cmd, get_cmd_type_string(cmd->h.h_type));
        status = 0;
    }
    return status;
}

/*
 * this function is basicaly just one big switch to route protocol messages
 * to the proper processing function
 */
void
rnablk_process_recv_cmp(struct cache_cmd *cmd,
                        struct com_ep    *ep,
                        int               status)
{
    struct io_state *ios            = NULL;
    struct rnablk_server_conn *conn = NULL;
    ios_tag_t ios_tag;
    
    BUG_ON(NULL == cmd);
    BUG_ON(NULL == ep);
    conn = (struct rnablk_server_conn *)(com_get_ep_context(ep));
    ios_tag = (ios_tag_t)cmd->h.h_cookie;

    if (likely(CACHE_INVD != cmd->h.h_type &&
               CACHE_RSV_ACCESS != cmd->h.h_type &&
               CACHE_RSV_ACCESS_V18 != cmd->h.h_type &&
               CACHE_TRANS_REQ != cmd->h.h_type &&
               CACHE_FAIL_CACHE_DEVICE != cmd->h.h_type &&
               CACHE_SCSI_UNITATTN != cmd->h.h_type &&
               CS_TO_CLIENT_PING != cmd->h.h_type)) {
        ios = rnablk_cookie_to_ios_get(ios_tag);
    }

    RNABLK_BUG_ON(ios != NULL && (NULL == ios->blk || NULL == ios->dev),
                  "ios [%p] tag ["TAGFMT"] type [%s] has NULL blk [%p] or NULL "
                  "dev [%p]\n",
                  ios, TAGFMTARGS(ios->tag), rnablk_op_type_string(ios->type),
                  ios->blk, ios->dev);

    rnablk_trc_master(NULL != ios && IS_MASTER_BLK(ios->blk),
                      "%sios [%p] tag ["TAGFMT"] block [%"PRIu64"] conn "
                      "["CONNFMT"] op=%s cmd [%s] state [%s] ref [%s]\n",
                      IS_MASTER_BLK(ios->blk) ? "MASTER " : "", ios,
                      TAGFMTARGS(ios->tag), ios->blk->block_number,
                      CONNFMTARGS(conn), rnablk_op_type_string(ios->type),
                      get_cmd_type_string(cmd->h.h_type),
                      rnablk_cache_blk_state_string(ios->blk->state),
                      get_lock_type_string(ios->blk->ref_type));

    if (unlikely((NULL == ios) &&
                 (CACHE_INVD != cmd->h.h_type) &&
                 (CACHE_RSV_ACCESS != cmd->h.h_type) &&
                 (CACHE_RSV_ACCESS_V18 != cmd->h.h_type) &&
                 (CACHE_FAIL_CACHE_DEVICE != cmd->h.h_type) &&
                 (CACHE_TRANS_REQ != cmd->h.h_type) &&
                 (CACHE_SCSI_UNITATTN != cmd->h.h_type) &&
                 (CS_TO_CLIENT_PING != cmd->h.h_type))) {
        rna_printk(KERN_ERR, "ios tag ["TAGFMT"] not in tree cmd type [%s] "
                   "server ["rna_service_id_format"]\n",
                   TAGFMTARGS(ios_tag),
                   get_cmd_type_string(cmd->h.h_type),
                   rna_service_id_get_string(&conn->id));
    } else {
        rna_printk(KERN_INFO, "type [%s] cookie [0x%"PRIx64"] ep [%p] "
                   "user_type [%s] ios [%p] tag ["TAGFMT"] dev [%s]\n",
                   get_cmd_type_string(cmd->h.h_type),
                   cmd->h.h_cookie,
                   ep,
                   get_user_type_string(com_get_ep_user_type(ep)),
                   ios,
                   (NULL != ios) ? TAGFMTARGS(ios->tag) : 0,
                   (NULL != ios) ? ios->dev->name : "NULL");

        if(unlikely(!rnablk_verify_conn(conn))) {
            if (likely(NULL != ios)) {
                rna_printk(KERN_ERR,
                          "ep [%p] has NULL or invalid conn - type [%s] ios "
                          "[%p] tag ["TAGFMT"] queue_state [%s] dev [%s] "
                          "block [%"PRIu64"]\n",
                          ep, get_cmd_type_string(cmd->h.h_type), ios,
                          TAGFMTARGS(ios_tag), rnablk_ios_q_string(
                          ios_queuestate_get(ios)),
                          ios->dev->name,
                          ios->blk->block_number);
                rnablk_end_request(ios, -EIO);
            } else {
                rna_printk(KERN_ERR,
                          "ep [%p] has NULL or invalid conn - type [%s] ios "
                          "[%p]\n", ep, get_cmd_type_string(cmd->h.h_type),
                          ios);
            }
        } else if (likely( ios != NULL )) {
#ifdef RNA_USE_IOS_TIMERS
            if (unlikely(atomic_read(&ios->ios_timer_fired))) {
                rna_printk(KERN_ERR,
                           "received response for expired ios [%p] tag "
                           "["TAGFMT"] type [%s] "
                           "from conn ["rna_service_id_format"]\n",
                           ios, TAGFMTARGS(ios->tag),
                           rnablk_op_type_string(ios->type),
                           rna_service_id_get_string(&conn->id));
            }
#endif

            if (likely(USR_TYPE_CACHE == com_get_ep_user_type(ep))) {
                if (!ios_queuestate_test_and_set(ios,
                                                IOS_QS_DISPATCH,
                                                IOS_QS_DISPATCH_COMPLETING)) {
                    rnablk_trc_discon(1, "ios [%p] taken care of (qs=%d), do "
                                      "nothing\n", ios,
                                      ios_queuestate_get(ios));
                } else {
                    dec_in_flight(ios->dev, ios);
                    if (CACHE_RESPONSE != cmd->h.h_type
                        && unlikely(rnablk_detect_cache_failure(ios,
                                    rnablk_get_cmd_status(cmd),
                                    CACHE_RESP_CODE_CACHEDEV_ERROR,
                                    FALSE))) {
                        /*
                         * Nothing more to do; we leave the ios on the dispatch
                         * queue for later reissue (and our call above
                         * initiated cachedev-failure processing if needed).
                         *
                         * Note CACHE_RESPONSE requires special handling
                         * for this cache-device failure scenario, because we
                         * don't yet know what cache-device the blk is
                         * associated with.  It gets taken care of in
                         * rnablk_process_cache_response().
                         */
                        if (CACHE_WRITE_SAME_RESP == cmd->h.h_type
                            || CACHE_COMP_WR_RESP == cmd->h.h_type) {
                            /*
                             * Do "cleanup" of associated counters as though
                             * normal completion occurred, but leave the
                             * ios on the dispatch_queue to be re-issued
                             * during offline_cachedev processing.
                             */
                            rnablk_undo_conn_io(ios, FALSE);
                        }
                        RNABLK_BUG_ON(!ios_queuestate_test_and_set(ios,
                                      IOS_QS_DISPATCH_COMPLETING,
                                      IOS_QS_DISPATCH_FAILED_REDO),
                                      "ios=%p unexpected qstate=%d\n", ios,
                                      ios_queuestate_get(ios));
                    } else switch( cmd->h.h_type ) {
                        case CACHE_CHANGE_REF_RESP:
                            TRACE(DBG_FLAG_VERBOSE,"Change_Ref response ios "
                                  "[%p] tag ["TAGFMT"] cmd [%p]\n", 
                                  ios, TAGFMTARGS(ios->tag), cmd);
                            rnablk_io_completed(ios);
                            rnablk_process_change_ref_response(ep, ios, cmd);
                            break;
                        case CACHE_RESPONSE:
                            if (unlikely((0 !=
                                         cmd->u.cache_rep.rnas.cr_status))) {
                                if ((CACHE_RESP_CODE_EAGAIN ==
                                     cmd->u.cache_rep.rnas.cr_status) ||
                                   (CACHE_RESP_CODE_OFFLINE ==
                                    cmd->u.cache_rep.rnas.cr_status)) {
                                    atomic_inc(&conn->eagains);
                                } else {
                                    rna_printk(KERN_ERR,
                                    "err [%s][%d] cmd [%s] cookie [0x%"PRIx64"]"
                                    " ep [%p] user_type [%s] ios [%p] tag "
                                    "["TAGFMT"] dev [%s]\n",
                                    get_cache_resp_code(cmd->u.cache_rep.rnas.cr_status),
                                    cmd->u.cache_rep.rnas.cr_status,
                                    get_cmd_type_string(cmd->h.h_type),
                                    cmd->h.h_cookie,
                                    ep, get_user_type_string(com_get_ep_user_type(ep)),
                                    ios, TAGFMTARGS(ios->tag), ios->dev->name);
                                }
                            }
                            // remove from dispatch queue
                            rnablk_io_completed(ios);
                            rnablk_process_cache_response( ep,ios,cmd );
                            break;
                        case CACHE_WRITE_SAME_RESP:
                            rnablk_io_completed(ios);
                            process_write_same_response(ep, ios, cmd);
                            break;
                        case CACHE_COMP_WR_RESP:
                            rnablk_io_completed(ios);
                            process_comp_and_write_response(ep, ios, cmd);
                            break;
                        case CACHE_SCSI_PASSTHRU_RESP:
                            rnablk_io_completed(ios);
                            process_scsi_passthru_response(ep, ios, cmd);
                            break;
                        default:
                            TRACE(DBG_FLAG_VERBOSE,"unexpected cache server "
                                  "response [%d] with ios [%p] tag "
                                  "["TAGFMT"]\n", cmd->h.h_type,
                                  ios, TAGFMTARGS(ios->tag));
                            break;
                    }
                }
            } else {
                TRACE(DBG_FLAG_VERBOSE,"unexpected user type [%d (%s)] "
                      "received with ios [%p] tag ["TAGFMT"]\n",
                       com_get_ep_user_type(ep),
                       get_user_type_string(com_get_ep_user_type(ep)),
                       ios, TAGFMTARGS(ios->tag));
            }
        } else { // NULL == ios
            rna_printk(KERN_DEBUG, "ep [%p], conn [%p]\n", ep, conn);
            rnablk_trc_master(1, "conn ["CONNFMT"] cmd=%s\n", CONNFMTARGS(conn),
                              get_cmd_type_string(cmd->h.h_type));
            if (likely(conn)) {
                if (likely(!status)) {
                    if (likely(USR_TYPE_CACHE == com_get_ep_user_type(ep))) {

                        switch( cmd->h.h_type ) {
                        case CACHE_INVD:
                            rnablk_process_cache_invd(ep, cmd, FALSE);
                            break;
                        case CACHE_RSV_ACCESS:
                        case CACHE_RSV_ACCESS_V18:
                            rnablk_process_cache_rsv_access(ep, cmd);
                            break;
                        case CACHE_FAIL_CACHE_DEVICE:
                            rnablk_trc_discon(1, "Received FAIL_CACHE_DEVICE "
                                              "for cachedev=%"PRIx64
                                              " conn ["CONNFMT"]\n",
                                              cmd->u.cache_fail_cd.cfcd_id,
                                              CONNFMTARGS(conn));
                            rnablk_trigger_offline_cache_device(conn,
                                        cmd->u.cache_fail_cd.cfcd_id,
                                        CD_OFFLINE_FAIL);
                            break;
                        case CACHE_SCSI_UNITATTN:
                            rnablk_process_scsi_unitattn(ep, cmd);
                            break;
                        case CACHE_TRANS_REQ:
                            rnablk_queue_cache_trans_req(ep, cmd);
                            break;

                        case CS_TO_CLIENT_PING:
                            /* No action needed. */
                            break;

                        default:
                            rna_printk(KERN_WARNING,
                                       "unexpected message from CS received "
                                       "on cmd [%s] tag ["TAGFMT"] with no "
                                       "IOS\n",
                                       get_cmd_type_string( cmd->h.h_type ),
                                       TAGFMTARGS(ios_tag));
                        }
                        rnablk_schedule_conn_dispatch(conn);
                    } else {
                        switch (com_get_ep_user_type(ep)) {
                        case USR_TYPE_CFM_CLIENT:
                            TRACE( DBG_FLAG_VERBOSE,"unexpected message from CFM received cmd %s\n",
                                   get_cmd_type_string( cmd->h.h_type ) );
                            break;
                        case USR_TYPE_META_CACHE:
                            TRACE( DBG_FLAG_VERBOSE,"unexpected message from MD received on cmd %s\n",
                                   get_cmd_type_string( cmd->h.h_type ) );
                            break;
                        default:
                            TRACE( DBG_FLAG_VERBOSE,"unexpected user type %d [%s] received\n",
                                   com_get_ep_user_type(ep),
                                   get_user_type_string(
                                   com_get_ep_user_type(ep)));
                            break;
                        }
                    }
                } else {
                    TRACE(DBG_FLAG_VERBOSE,
                          "error [%d] in recv callback on ep [%p] type [%s] "
                          "ios tag ["TAGFMT"]\n",
                          status, ep, get_user_type_string(
                          com_get_ep_user_type(ep)), TAGFMTARGS(ios_tag));
                }
            } else {
                TRACE(DBG_FLAG_VERBOSE,
                      "No ios or connection for tag ["TAGFMT"] user type [%s] "
                      "received on ep [%p]\n", TAGFMTARGS(ios_tag),
                      get_user_type_string(com_get_ep_user_type(ep)), ep);
            }
        }
    }
    if (likely(NULL != ios)) {
        rnablk_ios_release(ios);
    }
}

/*
 * Marshal and send Cache Block Query to Cache Server
 */
int
rnablk_cache_block_query(struct io_state *ios, struct buf_entry *buf_entry)
{
    struct com_ep   *ep;
    struct cache_cmd *cmd;
    cache_req_type_t req_type;
    cache_lock_t lock_type;
    cache_write_mode_t write_mode;
    ENTER;

    rnablk_trace_ios(ios);
    ep = rnablk_get_ios_ep(ios);

    /*
     * Keep a reference on the ios until we're fully done accessing it,
     * just in case we hit the unlikely race where the ios completes before
     * we finish with it.
     */
    rnablk_ios_ref(ios);

    rnablk_trc_master(IS_MASTER_BLK(ios->blk),
                      "MASTER ios [%p] tag ["TAGFMT"] type [%s] state [%s] "
                      "ref [%s]\n", ios, TAGFMTARGS(ios->tag),
                      rnablk_op_type_string(ios->type),
                      rnablk_cache_blk_state_string(ios->blk->state),
                      get_lock_type_string(ios->blk->ref_type));

    TRACE(DBG_FLAG_VERBOSE,"device [%s] ios [%p] tag ["TAGFMT"] type [%s]\n",
          ios->dev->name, ios, TAGFMTARGS(ios->tag),
          rnablk_op_type_string(ios->type));

    BUG_ON(NULL == buf_entry);
    cmd = (struct cache_cmd *)(com_get_send_buf_mem(buf_entry));

    write_mode = dev_is_persistent(ios->dev) ? CACHE_WRITE_BACK
                                             : CACHE_SCRATCHPAD; 

    /* Note the ios->type is overwritten below when the ios is reused */
    if (IS_MASTER_BLK(ios->blk)) {
        req_type  = CACHE_REQ_TYPE_MASTER;
        lock_type = CACHE_WRITE_SHARED;
    } else {
        RNABLK_BUG_ON(!IOS_HAS_IOREQ(ios), "No ioreq? device [%s] ios [%p] "
                      "type [%s] block [%llu]\n", ios->blk->dev->name, ios,
                      rnablk_op_type_string(ios->type), ios->blk->block_number);
        req_type  = CACHE_REQ_TYPE_BLOCK;
        lock_type = CACHE_READ_SHARED;
        if (dev_is_persistent(ios->dev)) {
            if (!rnablk_needed_lock(ios, &lock_type)) {
                // IOS requeued, do not send
                goto not_sent;
            }
        }
    }

    memset(cmd, 0, empty_cache_cmd_length(CACHE_QUERY));
                // don't clear 'pathname', since it's huge and we set it below
    cmd->h.h_type   = CACHE_QUERY;
    cmd->h.h_cookie = (uint64_t)ios->tag;
    cmd->u.cache_req.c = ios->c;

    memcpy(&cmd->u.cache_req.hash_key, &ios->blk->hash_key,
           sizeof(cmd->u.cache_req.hash_key));

    cmd->u.cache_req.c.co_cache_req_type = req_type;
    cmd->u.cache_req.c.co_lock_type      = lock_type;
    cmd->u.cache_req.c.co_write_mode     = write_mode;
    cmd->u.cache_req.c.co_invd_mode      = CACHE_INVD_BLOCK;
    cmd->u.cache_req.c.co_block_num      = ios->blk->block_number;
    cmd->u.cache_req.c.co_master_block_id  = ios->dev->dv_master_block_id;
    cmd->u.cache_req.block_size          = ios->dev->cache_blk_size;
    cmd->u.cache_req.orig_ref_type       = ios->blk->ref_type;
    cmd->u.cache_req.delete_restored     = FALSE; /* create the entry if needed */
    cmd->u.cache_req.cq_cachedev_id      = ios->blk->cb_cachedev_id; // Use MD-specified cachedev ID, if any

    /*
     * If this is a das device, then use the cache servers master block rid
     * which will be used in the cache server to insert into the
     * master_block_tree.
     */
    if (dev_is_das(ios->dev)) {
        rnablk_trc_master(IS_MASTER_BLK(ios->blk),
                          "MASTER set das master_block_id=%"PRId64"\n",
                          cmd->u.cache_req.c.co_master_block_id);
        rna_printk(KERN_DEBUG, "Set das master_block_id to [%"PRId64"]\n",
                   cmd->u.cache_req.c.co_master_block_id);
    }
    /* 
     * Currently master block UPGRADE change goes through cache query instead
     * of change_ref.
     */ 
    RNABLK_BUG_ON(!((CACHE_NO_REFERENCE == cmd->u.cache_req.orig_ref_type) ||
                  (CACHE_REQ_TYPE_MASTER == req_type)),
                  "orig_ref_type=%d req_type=%d cmd=%p ios=%p\n",
                  cmd->u.cache_req.orig_ref_type, req_type, cmd, ios);

    BUG_ON(!cache_ref_is_valid_transition(cmd->u.cache_req.orig_ref_type,
                                          lock_type));

    /*
     * strcpy is used instead of strncpy to avoid the cost of null-filling the
     * destination buffer out to the maximum string length, as strncpy does.
     */
    strcpy(cmd->u.cache_req.cr_path, ios->dev->cache_file_name);

    if (unlikely(RNABLK_LOCK_MASTER_BLK == ios->type)) {
        rsv_client_id_t *cip;

        cip = (rsv_client_id_t *)(cmd->u.cache_req.cr_path +
                                  strlen(cmd->u.cache_req.cr_path) + 1);
        cmd->u.cache_req.u.cq_has_client_id = 1;
        *cip = rnablk_client_id;
    }

    cmd->u.cache_req.cq_page_size            = PAGE_SIZE;

    /* We should get this from the masterblock, but set it anyway */
    if (dev_is_persistent(ios->dev)) {
        cmd->u.cache_req.c.co_evict_policy   = CACHE_SERVER_EVICT_POLICY;
    } else {
        cmd->u.cache_req.c.co_evict_policy   = CACHE_CLIENT_EVICT_POLICY;
    }

    TRACE(DBG_FLAG_VERBOSE,
          "device [%s] start sector [%llu] block [%llu] type [%s] "
          "ios [%p] tag ["TAGFMT"] req_type [%s] master_block_id [%"PRIu64"] "
          "old ref [%s] new ref [%s]\n",
          ios->dev->name,
          ios->start_sector,
          ios->blk->block_number,
          rnablk_op_type_string(ios->type),
          ios, TAGFMTARGS(ios->tag),
          get_cache_req_type_string(req_type),
          ios->dev->dv_master_block_id,
          rnablk_cache_blk_state_string(ios->blk->state),
          get_lock_type_string (lock_type));

    bswap_cache_cmd( cmd,0 );

    ios->issue_time_ns = getrawmonotonic_ns();

    ret = com_send(ep, buf_entry, (int)cache_cmd_length(cmd));
    if (unlikely(ret)) {
        goto not_sent;
    }

 out:
    rnablk_trc_master(IS_MASTER_BLK(ios->blk), "MASTER done (ret=%d)\n", ret);
    rnablk_ios_release(ios);
    EXIT;

 not_sent:
    if (NULL != buf_entry) {
        struct rnablk_server_conn *conn;
        com_put_send_buf(ep, buf_entry);
        conn = rnablk_get_ios_conn(ios);
        if (NULL != conn) {
            atomic_dec(&conn->send_bufs_in_use);
        }
    }
    goto out;
}

int
dispatch_generic_cmd(struct io_state *ios, struct buf_entry *buf_entry)
{
    struct cache_cmd *cmd;
    struct com_ep *ep;
    boolean expect_response = TRUE;
    ENTER;

    BUG_ON(NULL == ios);
    BUG_ON(NULL == ios->dev);
    BUG_ON(NULL == ios->blk);

    TRACE(DBG_FLAG_VERBOSE, "ios [%p] tag [%llu]\n", ios, ios->tag);
    rnablk_trace_ios(ios);

    rnablk_update_io_stats(ios);

    ep = rnablk_get_ios_ep(ios);

    cmd = (struct cache_cmd *)com_get_send_buf_mem(buf_entry);
    memcpy(cmd, ios->cmd, cache_cmd_length(ios->cmd));

    cmd->h.h_cookie = (uint64_t)ios->tag;
    cmd->h.h_error = 0;

    switch (ios->type) {
    case RNABLK_SCSI_PASSTHRU:
        cmd->u.cache_scsi_passthru.rid = ios->blk->rid;
        bswap_cache_scsi_passthru(&cmd->u.cache_scsi_passthru);
        break;

    case RNABLK_COMP_AND_WRITE:
        cmd->u.cache_comp_wr_req.cw_rid = ios->blk->rid;
        bswap_cache_comp_and_write_req(&cmd->u.cache_comp_wr_req);
        break;

    case RNABLK_WRITE_SAME:
        cmd->u.cache_write_same_req.ws_rid = ios->blk->rid;
        bswap_cache_write_same_req(&cmd->u.cache_write_same_req);
        break;

    case RNABLK_RSV_ACCESS_RESP:
        cmd->h.h_cookie = ios->blk->rid;  // here we use cookie for rid
        expect_response = FALSE;
        break;

    default:
        RNABLK_BUG_ON(TRUE, "unexpected ios type %s ios [%p] block [%llu] "
                      "state [%s]\n", rnablk_op_type_string(ios->type), ios,
                      ios->blk->block_number,
                      rnablk_cache_blk_state_string(ios->blk->state));
    }
                    
    ios->issue_time_ns = getrawmonotonic_ns();
    inc_in_flight(ios->dev, ios);
    ret = com_send(ep, buf_entry, (int)cache_cmd_length(cmd));
    if (unlikely(ret)) {
        struct rnablk_server_conn *conn;

        com_put_send_buf(ep, buf_entry);
        conn = rnablk_get_ios_conn(ios);
        if (NULL != conn) {
            atomic_dec(&conn->send_bufs_in_use);
        }
        GOTO(io_done, -EIO);
    }

    if (!expect_response) {
        GOTO(io_done, 0);
    }

 out:
    EXIT;

 io_done:
    dec_in_flight(ios->dev, ios);
    rnablk_io_completed(ios);
    rnablk_end_request(ios, ret);
    goto out;
}

/*
 * Fill out the cache_change_ref command to send to the cache server.
 */
void
rnablk_create_change_ref_cmd(struct cache_cmd *cmd,
                             struct io_state *ios,
                             uint64_t rid,
                             struct cache_blk *blk,
                             cache_lock_t orig_ref,
                             cache_lock_t desired_ref,
                             uint32_t flags)
{
    uint8_t ccr_flags;

    if (0 == flags) {
        ccr_flags = CCR_NEEDRESP;
    } else {
        ccr_flags = 0;
        if (!(flags & DEREF_NO_RESP)) {
            ccr_flags |= CCR_NEEDRESP;
        }
        if (flags & DEREF_HIPRI) {
            ccr_flags |= CCR_HIPRI;
        }
    }
    cmd->h.h_type   = CACHE_CHANGE_REF;
    cmd->h.h_error  = 0;
    cmd->h.h_cookie = rid;
    cmd->u.cache_change_ref.orig_reference = orig_ref;
    cmd->u.cache_change_ref.desired_reference = desired_ref;

    RNABLK_BUG_ON(!cache_ref_is_valid_transition(cmd->u.cache_change_ref.
                                          orig_reference, desired_ref),
                  "ios [%p] block [%llu] orig_ref [%s] desired_ref [%s]\n",
                  ios, blk->block_number, get_lock_type_string(orig_ref),
                  get_lock_type_string(desired_ref));

    /* ios->tag used for response header cookie */
    cmd->u.cache_change_ref.cookie = ios->tag;
    cmd->u.cache_change_ref.ccr_repstore_id = 0;
    cmd->u.cache_change_ref.ccr_flags = ccr_flags;
}


/*!
 * rna_service callback invoked when a response to a block_device_registration message
 * (rna_service_register_block_device_t) is received.
 *
 * Arguments:
 *	ctx				The user's rna_service context, as created by
 *					rna_service_ctx_create.
 *
 *	message_sent	Pointer to the specification for the message that was
 *					responded to.  This message buffer was the 'buf'
 *					argument to the rna_service_send_block_device_registration()
 *					call that sent the message that has been responded to.
 *
 *	response		If status is RNA_SERVICE_RESPONSE_STATUS_SUCCESS, this is
 *					a pointer to the response to the above message; otherwise
 *					NULL.
 *
 * status			The status of the response:
 *	RNA_SERVICE_RESPONSE_STATUS_SUCCESS		A response has been successfully
 *											received.
 *	RNA_SERVICE_RESPONSE_STATUS_SEND_TIMED_OUT
 *											There is no connection to the
 *											recipient.  The message was not
 *											sent, because it timed out before
 *											a connection could be made.
 *											'response' is NULL.
 *	RNA_SERVICE_RESPONSE_STATUS_RESPONSE_TIMED_OUT
 *											The message was sent, but the
 *											user-specified response timeout
 *											elapsed before a response was
 *											received; 'response' is NULL.
 *	RNA_SERVICE_RESPONSE_STATUS_CANCELED	Not currently implemented.
 */
static void
process_block_device_registration_response(struct rna_service_ctx_s     *ctx,
                                    rna_service_message_buffer_t *message_sent,
                                    rna_service_message_buffer_t *response,
                                    rna_service_response_status_t status)
{
	int ret=0;
    rna_service_register_block_device_t *sent;
    rna_service_register_block_device_response_t *resp;
    struct rnablk_device *dev = NULL;
#ifdef WINDOWS_KERNEL
    pHW_HBA_EXT pHBAExt;
#else
    struct new_utsname *uts_name;
#endif

#ifdef WINDOWS_KERNEL
    pHBAExt = hbaext_from_rna_service_ctx(ctx);
    ASSERT(NULL != pHBAExt);
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,20)
    uts_name = &system_utsname;
#else
    uts_name = utsname();
#endif

	if (status != RNA_SERVICE_RESPONSE_STATUS_SUCCESS) {
		rna_printk(KERN_ERR, "%s %d: no response received for metadata query, "
				   "giving up.  Status %d\n", __FUNCTION__, __LINE__, status);
		ret = -1;
		goto done;
	} else if (NULL == message_sent) {
		rna_printk(KERN_ERR, "%s %d: no message_sent\n", __FUNCTION__,__LINE__);
		ret = -1;
		goto done;
	} else if (message_sent->h.rmb_message_type !=
								RNA_SERVICE_MESSAGE_TYPE_REG_BLKDEV) {
		rna_printk(KERN_ERR, "%s %d: invalid sent message type %d\n",
				   __FUNCTION__, __LINE__, message_sent->h.rmb_message_type);
		ret = -1;
		goto done;
	} else if (NULL == response) {
		rna_printk(KERN_ERR, "%s %d: no response\n", __FUNCTION__, __LINE__);
		ret = -1;
		goto done;
	} else if (response->h.rmb_message_type !=
								RNA_SERVICE_MESSAGE_TYPE_REG_BLKDEV_RESPONSE) {
		rna_printk(KERN_ERR, "%s %d: invalid response message type %d\n",
				   __FUNCTION__, __LINE__, response->h.rmb_message_type);
		ret = -1;
		goto done;
	}

    sent = &message_sent->u.rmb_register_block_device;
    resp = &response->u.rmb_register_block_device_response;

#ifdef WINDOWS_KERNEL
    dev = rnablk_find_device_by_addr((void*)resp->rbr_device, pHBAExt);
#else
    dev = rnablk_find_device_by_addr((void*)resp->rbr_device);
#endif

    if (NULL == dev) {
		rna_printk(KERN_ERR, "%s %d: block device registration reply for non-existent device object [0x%"PRIx64"]\n",
				   __FUNCTION__, __LINE__, resp->rbr_device);
        ret = -1;
        goto done;
    } else {
		rna_printk(KERN_INFO, "%s %d: block device registration reply for device object [0x%"PRIx64"] status [%s]\n",
				   __FUNCTION__, __LINE__, resp->rbr_device, get_rnablk_cache_status_string(atomic_read(&dev->stats.status)));
    }

    if (RNABLK_CACHE_CONNECTING == atomic_read(&dev->stats.status)) {
        if( resp->rbr_available ) {
            /* If the device already exists with a different capacity than was specified here, adapt */
            if (!dev_is_persistent(dev) &&
                (dev->device_cap != resp->rbr_capacity)) {
                if (dev->device_cap != 0) {
                    rna_printk(KERN_ERR,
                               "%s: Device rnablk_%s was created locally with capacity %"PRIu64" Bytes, "
                               "but will be changed to %"PRIu64" Bytes as specified by the CFM\n",
                               __FUNCTION__, dev->name, dev->device_cap, resp->rbr_capacity );
                }
                dev->device_cap = resp->rbr_capacity;
            }
            /* The CFM's opinion on the device's sharable flag wins */
            if (resp->rbr_shared){
                dev_set_shareable(dev);
            } else {
                dev_clear_shareable(dev);
            }

            if (dev_is_persistent(dev)) {
                strncpy(&dev->cache_file_name[0], &dev->persist_location[0], sizeof(dev->cache_file_name));
            } else {
                if (dev_is_shareable(dev)) {
                    strncpy(dev->cache_file_name,
                            dev->name,
                            sizeof(dev->cache_file_name));
                } else {
                    snprintf(dev->cache_file_name,
                            sizeof(dev->cache_file_name),
                            "%s-%s",
                            dev->name,
#ifdef WINDOWS_KERNEL
                            node_name);
#else
                            uts_name->nodename);
#endif /*WINDOWS_KERNEL*/
                }
            }

            /* Lock the masterblock for this device to learn the actual cache block size */
            rnablk_lock_master_blk(dev);
        } else {
            rna_printk(KERN_ERR, "%s: insufficient space to create device %s\n",
                       __FUNCTION__,dev->name );
        }
    } else {
        /* We re-registered a previously created/registered device with the CFM */
        if(!resp->rbr_available) {
            rna_printk(KERN_ERR, "%s: CFM now claims insufficient space for existing device %s\n",
                       __FUNCTION__,dev->name );
        }
        if ((dev->device_cap != resp->rbr_capacity) &&
            (dev->device_cap != 0)) {
#ifdef WINDOWS_KERNEL
            rna_printk(KERN_ERR, "%s: Device %s was previously created with capacity [%"PRIu64"], "
                       "but the CFM now claims it should be [%"PRIu64"]. Device size unchanged.\n",
                       __FUNCTION__, 
                       dev->name,
                       dev->device_cap, resp->rbr_capacity );
#else
            rna_printk(KERN_ERR, "%s: Device %s was previously created with capacity [%"PRIu64"], "
                       "but the CFM now claims it should be [%"PRIu64"]. Device size unchanged.\n",
                       __FUNCTION__, 
                       dev->disk->disk_name,
                       dev->device_cap, resp->rbr_capacity );
#endif /*WINDOWS_KERNEL*/
        }
        if (dev_is_shareable(dev) != resp->rbr_shared) {
#ifdef WINDOWS_KERNEL
            rna_printk(KERN_ERR, "%s: Device %s was previously created as an %s device, "
                       "but the CFM now claims it should be %s. Device remains %s.\n",
                       __FUNCTION__,
                       dev->name,
                       dev_is_shareable(dev)?"shared":"unshared",
                       resp->rbr_shared?"shared":"unshared",
                       dev_is_shareable(dev)?"shared":"unshared");
#else
            rna_printk(KERN_ERR, "%s: Device %s was previously created as an %s device, "
                       "but the CFM now claims it should be %s. Device remains %s.\n",
                       __FUNCTION__,
                       dev->disk->disk_name,
                       dev_is_shareable(dev)?"shared":"unshared",
                       resp->rbr_shared?"shared":"unshared",
                       dev_is_shareable(dev)?"shared":"unshared");
#endif /*WINDOWS_KERNEL*/
        }
    }

 done:
    if (NULL != dev) {
        rnablk_dev_release(dev);
    }
	(void)rna_service_free_message_buffer(ctx, message_sent);
    if (NULL != response) {
        (void)rna_service_free_message_buffer(ctx, response);
    }
}

/**
 * Register (/re-register) a block device with the CFM(s)
 *
 * Originally called on an MD promotion.  
 *
 * TODO: Since rna_service tracks all local registrations and re-sends them
 * to (new) CFMs, we can now do this as soon as we have the information.
 *
 * TODO: (really?) runs in kthread context
 */
static void rnablk_register_dev_with_cfm( struct rnablk_device *dev )
{
	rna_service_message_buffer_t *msgbuf;
    rna_service_error_t ret;
#ifdef WINDOWS_KERNEL
    struct rna_service_ctx_s *rna_service_ctx;
#endif

    ENTERV;

#ifdef WINDOWS_KERNEL
    rna_service_ctx = dev->pHBAExt->hba_rna_service_ctx;
#endif

	/*
	 * Allocate an rna_service message buffer.
	 */
	msgbuf = rna_service_alloc_message_buffer(rna_service_ctx,
                                              RNA_SERVICE_MESSAGE_TYPE_REG_BLKDEV,
                                              dev->name);
	if (NULL == msgbuf) {
        rna_printk(KERN_ERR, "%s: failed to allocate message buffer!!\n",
				   __FUNCTION__);
        GOTO( out,-ENOMEM );
	}


    TRACE( DBG_FLAG_VERBOSE,
           "CFM block device registration of dev %s [%p] "
           "master_block_id [%"PRIu64"]\n",
           dev->name,dev,
           dev->dv_master_block_id);

    // This appears in cmd->h.h_cookie on the CFM, and comes back to us in
    // rbr_device in the registration response.
    msgbuf->h.rmb_message_type = RNA_SERVICE_MESSAGE_TYPE_REG_BLKDEV;
    msgbuf->u.rmb_register_block_device.rbs_device = (uint64_t)dev;
    msgbuf->u.rmb_register_block_device.cookie = dev->rbd_cfm_cookie;
    /* save the soap context here for callback later */
    strcpy(msgbuf->u.rmb_register_block_device.rbs_name, dev->name);
    msgbuf->u.rmb_register_block_device.rbs_master_block_id =
        dev->dv_master_block_id;
    msgbuf->u.rmb_register_block_device.rbs_capacity = dev->device_cap;  /* Bytes */
    msgbuf->u.rmb_register_block_device.rbs_cache_block_size = (uint32_t) dev->cache_blk_size; /* Bytes */
    msgbuf->u.rmb_register_block_device.rbs_shared = dev_is_shareable(dev);
    /* 
     * Registration is informational for devices that have already
     * been created.  For devices being created we're asking the CFM
     * if there's space yet.
     */
    msgbuf->u.rmb_register_block_device.rbs_existing =
        (RNABLK_CACHE_CONNECTING != atomic_read(&dev->stats.status));

    if (dev_is_persistent(dev)) {
        strncpy(&msgbuf->u.rmb_register_block_device.rbs_persist_location[0],
                &dev->persist_location[0], 
                min(sizeof(dev->persist_location), 
                    sizeof(msgbuf->u.rmb_register_block_device.rbs_persist_location)));
        msgbuf->u.rmb_register_block_device.rbs_persist_access_uid = dev->access_uid;
        msgbuf->u.rmb_register_block_device.rbs_persist_access_gid = dev->access_gid;
    }

	ret = rna_service_send_block_device_registration(rna_service_ctx,
                                                     msgbuf,
                                                     process_block_device_registration_response);

	if (ret != RNA_SERVICE_ERROR_NONE) {
        rna_printk(KERN_ERR,
                   "%s: rna_service_send_block_device_registration failed: %s\n",
				   __FUNCTION__, rna_service_get_error_string(ret));
        GOTO( out,-EINVAL );
    }

    rna_printk(KERN_ERR, "Registering [%s] with CFM using device id [%p]\n", dev->name, dev);

out:
    EXITV;

}

static int rnablk_deregister_dev_with_cfm( struct rnablk_device *dev )
{
	rna_service_message_buffer_t *msgbuf;
    rna_service_error_t rnas_ret;
#ifdef WINDOWS_KERNEL
    struct rna_service_ctx_s *rna_service_ctx;
#endif

    ENTER;

#ifdef WINDOWS_KERNEL
    rna_service_ctx = dev->pHBAExt->hba_rna_service_ctx;
#endif

	/*
	 * Allocate an rna_service message buffer.
	 */
	msgbuf = rna_service_alloc_message_buffer(rna_service_ctx,
                                              RNA_SERVICE_MESSAGE_TYPE_DEREG_BLKDEV,
                                              dev->name);
	if (NULL == msgbuf) {
        rna_printk(KERN_ERR, "%s: failed to allocate message buffer!!\n",
				   __FUNCTION__);
        GOTO( out,-ENOMEM );
	}

    TRACE( DBG_FLAG_VERBOSE,
           "CFM block device deregistration of dev %s [%p]\n",
           dev->name,dev );

    // This appears in cmd->h.h_cookie on the CFM, and comes back to us in
    // rbr_device in the deregistration response.
    msgbuf->h.rmb_message_type = RNA_SERVICE_MESSAGE_TYPE_DEREG_BLKDEV;
    msgbuf->u.rmb_deregister_block_device.dbs_device = (uint64_t)dev;
    /* 
     * 
     */
    msgbuf->u.rmb_deregister_block_device.dbs_freed = TRUE; 
    strcpy(msgbuf->u.rmb_deregister_block_device.dbs_name, dev->name);

	rnas_ret = rna_service_send_block_device_deregistration(rna_service_ctx,
                                                            msgbuf);
	if (rnas_ret != RNA_SERVICE_ERROR_NONE) {
        rna_printk(KERN_ERR,
                   "%s: rna_service_send_block_device_deregistration failed: %s\n",
				   __FUNCTION__, rna_service_get_error_string(ret));
        GOTO( out,-EINVAL );
    }

    rna_printk(KERN_ERR, "Deregistering [%s] with CFM using device id [%p]\n", dev->name, dev);

out:
    EXIT;
}

/**
 * Register a CS connection with the CFM(s)
 *
 * runs in kthread context (connection manager thread)
 */
void rnablk_register_cs_conn_with_cfm(struct rnablk_server_conn *conn)
{
	rna_service_message_buffer_t *msgbuf;
    rna_service_error_t ret;
    struct com_ep *ep = NULL;
#ifdef WINDOWS_KERNEL
    struct sockaddr_in src_in;
    struct sockaddr_in dst_in;
    struct rna_service_ctx_s* rna_service_ctx;
#endif /*WINDOWS_KERNEL*/
    ENTERV;

#ifdef WINDOWS_KERNEL
    rna_service_ctx = rna_service_ctx_from_conn(conn);
#endif
	/*
	 * Allocate an rna_service message buffer.
	 */
	msgbuf = rna_service_alloc_message_buffer(rna_service_ctx,
                                              RNA_SERVICE_MESSAGE_TYPE_REG_SVC_CONN,
                                              NULL);
	if (NULL == msgbuf) {
        rna_printk(KERN_ERR, "%s: failed to allocate message buffer!!\n",
				   __FUNCTION__);
        GOTO( out,-ENOMEM );
	}

    ep = rnablk_conn_get_ep(conn);

    if (unlikely(NULL == ep)) {
            rna_printk(KERN_ERR,
                       "CS ["rna_service_id_format"] has NULL EP\n",
                       rna_service_id_get_string(&conn->id));
        GOTO(out, -EINVAL);
    }

    //TRACE(DBG_FLAG_VERBOSE,
    rna_printk(KERN_ERR,
               "Registering connection to ["rna_service_id_format"] [%p]\n",
               rna_service_id_get_string(&conn->id),
               conn);

    msgbuf->h.rmb_message_type = RNA_SERVICE_MESSAGE_TYPE_REG_SVC_CONN;
    memcpy(&msgbuf->u.rmb_register_svc_conn.rsc_service_id,
           &conn->id,
           sizeof(msgbuf->u.rmb_register_svc_conn.rsc_service_id));
    msgbuf->u.rmb_register_svc_conn.rsc_transport_type = com_get_ep_transport_type(ep);

#ifdef WINDOWS_KERNEL
	//TODO: Need to add code to check return code
	com_get_ep_src_in_ex(conn->ep, &src_in, sizeof(src_in));
    com_get_ep_dst_in_ex(conn->ep, &dst_in, sizeof(dst_in));
    memcpy(&msgbuf->u.rmb_register_svc_conn.rsc_src_in,
           &src_in,
           sizeof(msgbuf->u.rmb_register_svc_conn.rsc_src_in));
    memcpy(&msgbuf->u.rmb_register_svc_conn.rsc_dst_in,
           &dst_in,
           sizeof(msgbuf->u.rmb_register_svc_conn.rsc_dst_in));
#else
    memcpy(&msgbuf->u.rmb_register_svc_conn.rsc_src_in,
           &ep->src_in,
           sizeof(msgbuf->u.rmb_register_svc_conn.rsc_src_in));
    memcpy(&msgbuf->u.rmb_register_svc_conn.rsc_dst_in,
           &ep->dst_in,
           sizeof(msgbuf->u.rmb_register_svc_conn.rsc_dst_in));
#endif //WINDOWS_KERNEL
    com_release_ep(ep);

	ret = rna_service_send_svc_conn_registration(rna_service_ctx,
                                                 msgbuf);
	if (ret != RNA_SERVICE_ERROR_NONE) {
        rna_printk(KERN_ERR,
                   "%s: rna_service_send_svc_conn_registration failed: %s\n",
				   __FUNCTION__, rna_service_get_error_string(ret));
        GOTO( out,-EINVAL );
    }

out:
    EXITV;
}

/**
 * Deregister a CS connection with the CFM(s)
 *
 * runs in kthread context (connection manager thread)
 */
void rnablk_deregister_cs_conn_with_cfm(struct rnablk_server_conn *conn)
{
	rna_service_message_buffer_t *msgbuf;
    rna_service_error_t ret;
#ifdef WINDOWS_KERNEL
    struct rna_service_ctx_s* rna_service_ctx;
#endif /*WINDOWS_KERNEL*/
    ENTERV;

#ifdef WINDOWS_KERNEL
    rna_service_ctx = rna_service_ctx_from_conn(conn);
#endif
	/*
	 * Allocate an rna_service message buffer.
	 */
	msgbuf = rna_service_alloc_message_buffer(rna_service_ctx,
                                              RNA_SERVICE_MESSAGE_TYPE_DEREG_SVC_CONN,
                                              NULL);
	if (NULL == msgbuf) {
        rna_printk(KERN_ERR, "%s: failed to allocate message buffer!!\n",
				   __FUNCTION__);
        GOTO( out,-ENOMEM );
	}

    //TRACE(DBG_FLAG_VERBOSE,
    rna_printk(KERN_ERR,
               "Deregistering connection to ["rna_service_id_format"] [%p]\n",
               rna_service_id_get_string(&conn->id),
               conn);

    msgbuf->h.rmb_message_type = RNA_SERVICE_MESSAGE_TYPE_DEREG_SVC_CONN;
    memcpy(&msgbuf->u.rmb_deregister_svc_conn.dsc_service_id,
           &conn->id,
           sizeof(msgbuf->u.rmb_deregister_svc_conn.dsc_service_id));

	ret = rna_service_send_svc_conn_deregistration(rna_service_ctx,
                                                   msgbuf);
	if (ret != RNA_SERVICE_ERROR_NONE) {
        rna_printk(KERN_ERR,
                   "%s: rna_service_send_svc_conn_deregistration failed: %s\n",
				   __FUNCTION__, rna_service_get_error_string(ret));
        GOTO( out,-EINVAL );
    }

    rna_printk(KERN_ERR,
               "Deregistering connection to ["rna_service_id_format"] [%p]\n",
               rna_service_id_get_string(&conn->id),
               conn);
out:
    EXITV;
}


/*!
 * rna_service callback invoked when a response to an md_query message
 * (rna_service_metadata_query_t) is received.
 *
 * Arguments:
 *	ctx				The user's rna_service context, as created by
 *					rna_service_ctx_create.
 *
 *	message_sent	Pointer to the specification for the message that was
 *					responded to.  This message buffer was the 'buf'
 *					argument to the rna_service_send_metadata_query()
 *					call that sent the message that has been responded to.
 *
 *	response		If status is RNA_SERVICE_RESPONSE_STATUS_SUCCESS, this is
 *					a pointer to the response to the above message; otherwise
 *					NULL.
 *
 * status			The status of the response:
 *	RNA_SERVICE_RESPONSE_STATUS_SUCCESS		A response has been successfully
 *											received.
 *	RNA_SERVICE_RESPONSE_STATUS_SEND_TIMED_OUT
 *											There is no connection to the
 *											recipient.  The message was not
 *											sent, because it timed out before
 *											a connection could be made.
 *											'response' is NULL.
 *	RNA_SERVICE_RESPONSE_STATUS_RESPONSE_TIMED_OUT
 *											The message was sent, but the
 *											user-specified response timeout
 *											elapsed before a response was
 *											received; 'response' is NULL.
 *	RNA_SERVICE_RESPONSE_STATUS_CANCELED	Not currently implemented.
 */
static void
rnablk_process_metadata_query_response(struct rna_service_ctx_s     *ctx,
                                       rna_service_message_buffer_t *message_sent,
                                       rna_service_message_buffer_t *response,
                                       rna_service_response_status_t status)
{
	int ret=0;
    struct io_state *ios = NULL;
    struct rnablk_server_conn *conn;
    lockstate_t flags;
    rna_service_metadata_query_t *sent;
    rna_service_metadata_query_response_t *resp;
    int retry_delay_msecs = -1;
    struct list_head *ios_pos;
    struct io_state *ios_iter = NULL;
    mutexstate_t mutex_lock_handle;

    sent = &message_sent->u.rmb_metadata_query;

    /* For CACHE_REQ_TYPE_BLOCK MD queries, the cookie is an ios tag */
    ios = rnablk_cookie_to_ios_get(sent->mqs_cookie);

    if (NULL == ios) {
        rna_printk(KERN_ERR, "MD BLOCK reply for non-existent ios tag "
                   "[%"PRIu64"]\n", sent->mqs_cookie);
        ret = -EIO;
        goto done;
    }
    rna_printk(KERN_DEBUG, "MD BLOCK reply for ios [%p] tag ["TAGFMT"] "
               "type [%s] block [%llu] state [%s]\n",
               ios, TAGFMTARGS(ios->tag),
               rnablk_op_type_string(ios->type), ios->blk->block_number,
               rnablk_cache_blk_state_string(ios->blk->state));
    if (!rnablk_clear_ios_timer(ios)) {
        /*
         * If this ios gets timed out while doing the MD query,
         * rnablk_cache_timeout() will simply finish/fail the ios.
         * To avoid possible races between this response arriving
         * and the ios timing out, clear the timeout here.
         * If we successfully cleared it, then all is well.
         * Otherwise, we raced with the timer firing, and the ios
         * has already been "finished" with an error.  We can't do any
         * further processing of it...!
         */
        rna_printk(KERN_ERR, "Received MD query response for ios [%p] "
                   "tag ["TAGFMT"] type [%s] block [%llu] state [%s] "
                   "after timeout, ignoring response.\n",
                   ios, TAGFMTARGS(ios->tag),
                   rnablk_op_type_string(ios->type), ios->blk->block_number,
                   rnablk_cache_blk_state_string(ios->blk->state));
        /* 'ret' must be 0, so we don't do rnablk_end_request()! */
        goto done;
    }
    rnablk_trace_ios(ios);

    dec_in_flight(ios->dev, ios);
    rnablk_io_completed(ios);

	if (status != RNA_SERVICE_RESPONSE_STATUS_SUCCESS) {
        rna_printk(KERN_ERR, "no response received for MD query for ios [%p] "
                   "tag ["TAGFMT"] type [%s] block [%llu] state [%s]\n",
                   ios, TAGFMTARGS(ios->tag),
                   rnablk_op_type_string(ios->type), ios->blk->block_number,
                   rnablk_cache_blk_state_string(ios->blk->state));
        ret = -EIO;
		goto done;
	} else if (NULL == message_sent) {
        rna_printk(KERN_ERR, "no message sent for ios [%p] tag ["TAGFMT"] "
                   "type [%s] block [%llu] state [%s]\n",
                   ios, TAGFMTARGS(ios->tag),
                   rnablk_op_type_string(ios->type), ios->blk->block_number,
                   rnablk_cache_blk_state_string(ios->blk->state));
        ret = -EIO;
		goto done;
	} else if (message_sent->h.rmb_message_type !=
								RNA_SERVICE_MESSAGE_TYPE_MD_QUERY) {
        rna_printk(KERN_ERR, "invalid sent message type %d for ios [%p] tag "
                   "["TAGFMT"] type [%s] block [%llu] state [%s]\n",
                   message_sent->h.rmb_message_type, ios, TAGFMTARGS(ios->tag),
                   rnablk_op_type_string(ios->type), ios->blk->block_number,
                   rnablk_cache_blk_state_string(ios->blk->state));
        ret = -EIO;
		goto done;
	} else if (NULL == response) {
        rna_printk(KERN_ERR, "no response for ios [%p] tag ["TAGFMT"] "
                   "type [%s] block [%llu] state [%s]\n",
                   ios, TAGFMTARGS(ios->tag),
                   rnablk_op_type_string(ios->type), ios->blk->block_number,
                   rnablk_cache_blk_state_string(ios->blk->state));
        ret = -EIO;
		goto done;
	} else if (response->h.rmb_message_type !=
								RNA_SERVICE_MESSAGE_TYPE_MD_QUERY_RESPONSE) {
        rna_printk(KERN_ERR, "invalid response message type %d for ios [%p] "
                   "tag ["TAGFMT"] type [%s] block [%llu] state [%s]\n",
                   response->h.rmb_message_type, ios, TAGFMTARGS(ios->tag),
                   rnablk_op_type_string(ios->type), ios->blk->block_number,
                   rnablk_cache_blk_state_string(ios->blk->state));
        ret = -EIO;
		goto done;
	}

    /* not safe to deref response above as it is NULL in the timeout case */
    resp = &response->u.rmb_metadata_query_response;

    if ((-EAGAIN == resp->mqr_error) ||
        (-EBUSY == resp->mqr_error)) {

        if (!MASTER_BLK_IS_CONNECTED(ios->dev)) {
            rnablk_lock_master_blk(ios->dev);
        }

        rnablk_lock_blk_irqsave(ios->blk, flags);


        if (ios->blk->connection_failures ==
                atomic_read(&ios->ios_connection_failures)) {
            /* only increment for first IOS to hit this */
            ios->blk->connection_failures++;
        }
        rnablk_unset_blk_ep(ios->blk);

        atomic_inc(&ios->ios_connection_failures);

        if (!rnablk_cache_blk_state_transition(ios->blk,
                               RNABLK_CACHE_BLK_CONNECT_PENDING,
                               RNABLK_CACHE_BLK_DISCONNECTED)) {
            rna_printk(KERN_WARNING, "dev [%s] block [%"PRIu64"] unexpected "
                       "state [%s] ios [%p]\n", ios->blk->dev->name,
                       ios->blk->block_number,
                       rnablk_cache_blk_state_string(ios->blk->state), ios);
        }

        /*
         * EAGAIN may indicate that we are waiting for an absorption,
         * which are of indeterminate duration due to their reliance
         * of flushing.  which all means that we need to be more
         * patient.
         */

        /* reset all IOS timers for this block while we hold the lock */
        if (-EAGAIN == resp->mqr_error) {
            rnablk_retrack_ios(ios);
            rna_printk(KERN_INFO,
                       "MD sent [EAGAIN] for dev [%s] block [%"PRIu64"] "
                       "reset timer for ios [%p] tag ["TAGFMT"]\n",
                       sent->mqs_pathname,
                       sent->mqs_block_num,
                       ios, TAGFMTARGS(ios->tag));
            list_for_each(ios_pos, &ios->blk->bl) {
                ios_iter = list_entry(ios_pos, struct io_state, l);
                /* this will update the tag generation and reset the timer */
                rnablk_retrack_ios(ios_iter);
                rna_printk(KERN_INFO,
                           "MD sent [EAGAIN] for dev [%s] block [%"PRIu64"] "
                           "reset timer for ios [%p] tag ["TAGFMT"]\n",
                           sent->mqs_pathname,
                           sent->mqs_block_num,
                           ios_iter, TAGFMTARGS(ios_iter->tag));
            }
        }

        rnablk_unlock_blk_irqrestore(ios->blk, flags);

        if ((0 != max_connection_failures) &&
            (max_connection_failures <= ios->blk->connection_failures)) {
            /* we have exceeded the failure count, this block is bad */
            rna_printk(KERN_ERR,
                       "MD sent %s for dev [%s] block [%"PRIu64"], exceeded failure count [%d]\n",
                       (-EAGAIN == resp->mqr_error ? "EAGAIN" : "EBUSY"),
                       sent->mqs_pathname,
                       sent->mqs_block_num,
                       max_connection_failures);
            ret = -EIO;
        } else {
            if (-EBUSY == resp->mqr_error) {
                /* EBUSY indicates block is being relocated to another CS */
                retry_delay_msecs = RNABLK_BUSY_DELAY_MS;
            } else {
                /*
                 * back off on multiple retries.
                 * never delay by more than half the total IOS timeout value.
                 */
                retry_delay_msecs = min(((rnablk_io_timeout / 2) * MSEC_PER_SEC),
                       (RNABLK_EAGAIN_DELAY_MS * ios->blk->connection_failures));
            }
            rnablk_queue_delayed_request(ios, retry_delay_msecs);
            rna_printk(KERN_ERR, "MD sent [%s] for dev [%s] block [%"PRIu64"] "
                       "ios [%p] tag ["TAGFMT"] resending with [%d] sec delay\n",
                       (-EAGAIN == resp->mqr_error ? "EAGAIN" : "EBUSY"),
                       sent->mqs_pathname,
                       sent->mqs_block_num,
                       ios, TAGFMTARGS(ios->tag),
                       retry_delay_msecs / (int)MSEC_PER_SEC);
        }
        goto done;
    } else if (0 != resp->mqr_error) {
        rna_printk(KERN_ERR,
                   "MD response for dev [%s] block [%"PRIu64"] is [%d]\n",
                   ios->dev->name,
                   ios->blk->block_number,
                   resp->mqr_error );
        if(-ENXIO == resp->mqr_error) {
            /* MD returns this status for blocks that were on cache servers that have failed. */
            ret = -EIO;
        } else {
            ret = resp->mqr_error;
        }
        goto done;
    }

    if (CACHE_REQ_TYPE_BLOCK != resp->c.co_cache_req_type) {
        rna_printk(KERN_ERR, "Unexpected MD response type [%s] for ios [%p] "
                   "tag ["TAGFMT"] type [%s] block [%llu] state [%s]\n",
                   get_cache_req_type_string(resp->c.co_cache_req_type),
                   ios, TAGFMTARGS(ios->tag),
                   rnablk_op_type_string(ios->type), ios->blk->block_number,
                   rnablk_cache_blk_state_string(ios->blk->state));

        ret = -EIO;
        goto done;
    }

    if (ios->dev->dv_master_block_id != resp->c.co_master_block_id) {
        rna_printk(KERN_ERR,
                  "master_block_id mismatch! "
                  "ios: [%"PRIu64"] resp [%"PRIu64"]\n",
                  ios->dev->dv_master_block_id,
                  resp->c.co_master_block_id);
        ret = -EIO;
        goto done;
    }


    /* If this is any other conn than g_md_conn, it's unsafe to call
     * rnablk_unset_blk_ep() without grabbing the conn's block list lock
     */
    conn = rnablk_get_ios_conn(ios);
    if (g_md_conn != conn) {
        rna_printk(KERN_WARNING, "ios [%p] tag ["TAGFMT"] type [%s] for [%s] "
                   "block [%"PRIu64"] in state [%s], connected to conn "
                   "["rna_service_id_format"] MD response specified "
                   "["rna_service_id_format"], not MD conn\n",
                   ios, TAGFMTARGS(ios->tag),
                   rnablk_op_type_string(ios->type),
                   ios->blk->dev->name,
                   ios->blk->block_number,
                   rnablk_cache_blk_state_string(ios->blk->state),
                   rna_service_id_get_string(&conn->id),
                   rna_service_id_get_string(&resp->mqr_service_id));

        rna_block_mutex_lock(&conn->block_list_lock, &mutex_lock_handle);
    }

    rnablk_lock_blk_irqsave(ios->blk, flags);
    rnablk_unset_blk_ep(ios->blk);

    if (ios->blk->connection_failures > 0) {
        /*
         * Reset all ios connection_failure counters for this block
         * since we got a successful MD response for it.
         * (Need the blk lock to traverse the bl list).
         */
        ios->blk->connection_failures = 0;
        atomic_set(&ios->ios_connection_failures, 0);
        list_for_each(ios_pos, &ios->blk->bl) {
            ios_iter = list_entry(ios_pos, struct io_state, l);
            atomic_set(&ios_iter->ios_connection_failures, 0);
        }
    }

    if (g_md_conn != conn) {
        rna_block_mutex_unlock(&conn->block_list_lock, &mutex_lock_handle);
    }

    if(RNABLK_CACHE_BLK_CONNECT_PENDING != ios->blk->state) {
        rna_printk(((RNABLK_CACHE_BLK_INVALID == ios->blk->state)
                   ? KERN_INFO : KERN_ERR),
                   "ios [%p] tag ["TAGFMT"] type [%s] for [%s] block "
                   "[%"PRIu64"] in unexpected state [%s]\n",
                   ios, TAGFMTARGS(ios->tag),
                   rnablk_op_type_string(ios->type),
                   ios->blk->dev->name,
                   ios->blk->block_number,
                   rnablk_cache_blk_state_string(ios->blk->state));
        // FAIL
        rnablk_unlock_blk_irqrestore(ios->blk, flags);

        rnablk_end_request(ios, -EIO);
    } else {
        rna_printk(KERN_DEBUG,
                   "MD query response for block [%"PRIu64"] dev [%s] using "
                   "device id [%p]\n",
                   resp->c.co_block_num,
                   ios->dev->name,
                   ios->dev);
        ios->blk->cb_cachedev_id = resp->mqr_cachedev_id;

        rnablk_unlock_blk_irqrestore(ios->blk, flags);
        rnablk_md_send_cache_query_from_md_response(resp, ios);
    }

done:
    if (NULL != ios) {
        if (0 != ret) {
            rnablk_end_request(ios, ret);
            rnablk_mark_cache_blk_bad_and_drain(ios->blk, TRUE);
        }
        rnablk_ios_release(ios);
    }

    (void)rna_service_free_message_buffer(ctx, message_sent);
    if (NULL != response) {
        (void)rna_service_free_message_buffer(ctx, response);
    }
}

/*
 * runs in kthread context
 *
 * inlining discouraged because it increases the caller's stack usage
 * more than we'd like
 */
int
rnablk_metadata_query(struct io_state *ios)
{
	rna_service_message_buffer_t *mbuf = NULL;
    rna_service_metadata_query_t *query;
    cache_lock_t lock_type = CACHE_READ_SHARED;
    cache_write_mode_t write_mode = CACHE_SCRATCHPAD;
#ifdef WINDOWS_KERNEL
    struct rna_service_ctx_s *rna_service_ctx;
#endif
    ENTER;

    rnablk_trace_ios(ios);

    /*
     * Keep a reference on the ios until we're fully done accessing it,
     * just in case we hit the unlikely race where the ios completes before
     * we finish with it.
     */
    rnablk_ios_ref(ios);

    // if the driver is unloading skip this query
    if (unlikely(atomic_read(&shutdown))) {
        goto out;
    }

#ifdef WINDOWS_KERNEL
    rna_service_ctx = ios->dev->pHBAExt->hba_rna_service_ctx;
#endif

    if (dev_is_persistent(ios->dev)) {
        write_mode = CACHE_WRITE_BACK;
        if (!IOS_HAS_IOREQ(ios)) {
            lock_type = CACHE_WRITE_SHARED;
        } else {
            switch (ios->ios_iotype) {
            case IOS_IOTYPE_WRITE:
            case IOS_IOTYPE_WRITE_SAME:
                lock_type = rnablk_use_write_only
                            ? CACHE_WRITE_ONLY_SHARED
                            : CACHE_WRITE_SHARED;
                break;

            case IOS_IOTYPE_READ:
                lock_type = CACHE_READ_SHARED;
                break;

            case IOS_IOTYPE_COMP_WR:
                lock_type = CACHE_WRITE_SHARED;
                break;

            default:
                RNABLK_BUG_ON(TRUE, "unexpected iotype [%d] ios [%p "
                              "block [%llu]\n", ios->ios_iotype, ios,
                              ios->blk->block_number);
            }
        }
    }

	/*
	 * Allocate an rna_service message buffer.
	 */
	mbuf = rna_service_alloc_message_buffer(rna_service_ctx,
                                            RNA_SERVICE_MESSAGE_TYPE_MD_QUERY,
                                            ios->dev->cache_file_name);

	if (NULL == mbuf) {
        rna_printk(KERN_ERR, "%s: failed to allocate message buffer!!\n",
				   __FUNCTION__);
		ret = -ENOMEM;
		goto err;
	}

	/*
	 * Initialize the rna_service message buffer as a metadata query message.
	 */
    query = &mbuf->u.rmb_metadata_query;
	mbuf->h.rmb_message_type = RNA_SERVICE_MESSAGE_TYPE_MD_QUERY;
    query->mqs_cookie = (uint64_t)ios->tag;
	query->mqs_request_type = CACHE_REQ_TYPE_BLOCK;
	query->mqs_lock_type = lock_type;
	query->mqs_write_mode = write_mode;
	query->mqs_invd_mode = CACHE_INVD_BLOCK;
    //query->mqs_block_size = dev->cache_blk_size;
    /* Let MD use block size from master block */
    query->mqs_block_size = 0;
	query->mqs_block_num = ios->blk->block_number;
	query->mqs_master_block_id = ios->dev->dv_master_block_id;
    if (dev_is_persistent(ios->dev)) {
        query->mqs_evict_policy = CACHE_SERVER_EVICT_POLICY;
    } else {
        query->mqs_evict_policy = CACHE_CLIENT_EVICT_POLICY;
    }
	query->mqs_pvt_data_len = 0;

    if (dev_is_persistent(ios->dev)) {
        // allow blocks to failover from cache server to cache server
        query->mqs_error_persistence = CACHE_ERRS_NOT_PERSISTENT;
    } else {
        query->mqs_error_persistence = CACHE_ERRS_PERSIST_UNTIL_MASTER_INVD;
    }
    query->mqs_path_md_policy = atomic_get(&ios->dev->path_md_policy);

    strcpy(query->mqs_pathname, ios->dev->cache_file_name);

    rna_trace("file [%s] cache_type [%s] lock type [%s] block [%"PRId64"] "
			  "uid [%u] gid [%u] master_block_id [%"PRIu64"]\n",
              query->mqs_pathname,
              get_cmd_type_string(query->mqs_request_type),
              get_lock_type_string(query->mqs_lock_type),
              query->mqs_block_num,
              query->mqs_reader_uid,
              query->mqs_reader_gid,
              query->mqs_master_block_id);

	/*
	 * Send the metadata query.
	 */
    if (!dev_is_das(ios->dev)) {
	    ret = rna_service_send_md(rna_service_ctx,
                                  mbuf,
                                  rnablk_process_metadata_query_response);
    } else {
        /*
         * If this device is in DAS mode, then call the simulated
         * MD query that bypasses sending to the MD and fabricates the
         * response.
         */
        ret = rnablk_das_metadata_query(ios->dev, rna_service_ctx, mbuf,
                                        rnablk_process_metadata_query_response);
    }
	if (ret != RNA_SERVICE_ERROR_NONE) {
        printk( "%s: failed to send MD query: %s\n",
                __location__, rna_service_get_error_string(ret) );
		(void)rna_service_free_message_buffer(rna_service_ctx, mbuf);
	} else {
        rna_printk(KERN_DEBUG, "MD query for block [%"PRIu64"] dev [%s] "
                   "using device id [%p]\n", ios->blk->block_number,
                   ios->dev->name, ios->dev);
    }

 out:
    rnablk_ios_release(ios);
    EXIT;
 err:
    goto out;
}

/*!
 * rna_service callback invoked when a response to the md_query message
 * (rna_service_metadata_query_t) for an rnablk_lock_master_blk is received.
 *
 * Arguments:
 *	ctx				The user's rna_service context, as created by
 *					rna_service_ctx_create.
 *
 *	message_sent	Pointer to the specification for the message that was
 *					responded to.  This message buffer was the 'buf'
 *					argument to the rna_service_send_metadata_query()
 *					call that sent the message that has been responded to.
 *
 *	response		If status is RNA_SERVICE_RESPONSE_STATUS_SUCCESS, this is
 *					a pointer to the response to the above message; otherwise
 *					NULL.
 *
 * status			The status of the response:
 *	RNA_SERVICE_RESPONSE_STATUS_SUCCESS		A response has been successfully
 *											received.
 *	RNA_SERVICE_RESPONSE_STATUS_SEND_TIMED_OUT
 *											There is no connection to the
 *											recipient.  The message was not
 *											sent, because it timed out before
 *											a connection could be made.
 *											'response' is NULL.
 *	RNA_SERVICE_RESPONSE_STATUS_RESPONSE_TIMED_OUT
 *											The message was sent, but the
 *											user-specified response timeout
 *											elapsed before a response was
 *											received; 'response' is NULL.
 *	RNA_SERVICE_RESPONSE_STATUS_CANCELED	Not currently implemented.
 */
static void
rnablk_process_lock_master_blk_response(struct rna_service_ctx_s     *ctx,
                                    rna_service_message_buffer_t *message_sent,
                                    rna_service_message_buffer_t *response,
                                    rna_service_response_status_t status)
{
    struct rnablk_device *dev = NULL;
    rna_service_metadata_query_t *sent;
    rna_service_metadata_query_response_t *resp;
    struct io_state *ios;
    lockstate_t flags;
    boolean queue_retry = FALSE;
    boolean error = FALSE;

#ifdef WINDOWS_KERNEL
    struct rna_service_ctx_s *rna_service_ctx = ctx;
#endif

    rnablk_trc_master(1, "got response: status=%d\n", status);
    sent = &message_sent->u.rmb_metadata_query;

    /* For CACHE_REQ_TYPE_MASTER MD queries, the cookie is an ios tag */
    ios = rnablk_cookie_to_ios_get(sent->mqs_cookie);

    if (NULL == ios) {
        rna_printk(KERN_ERR, "MD BLOCK reply for non-existent ios tag "
                   "[%"PRIu64"]\n", sent->mqs_cookie);
        error = TRUE;
        goto done;
    } 
    BUG_ON(RNABLK_LOCK_MASTER_BLK != ios->type);

    if (!rnablk_clear_ios_timer(ios)) {
        /*
         * If this ios gets timed out while doing the MD query,
         * rnablk_cache_timeout() will simply finish/fail the ios.
         * To avoid possible races between this response arriving
         * and the ios timing out, clear the timeout here.
         * If we successfully cleared it, then all is well.
         * Otherwise, we raced with the timer firing, and the ios
         * has already been "finished" with an error.  We can't do any
         * further processing of it...!
         */
        rna_printk(KERN_ERR, "Received MD query response for ios [%p] "
                   "tag ["TAGFMT"] type [%s] block [%llu] state [%s] "
                   "after timeout, ignoring response.\n",
                   ios, TAGFMTARGS(ios->tag),
                   rnablk_op_type_string(ios->type), ios->blk->block_number,
                   rnablk_cache_blk_state_string(ios->blk->state));
        /* 'error' must be 0, so we don't do rnablk_ios_finish()! */
        goto done;
    }

    dev = ios->dev;
    rna_printk(KERN_DEBUG, "MD BLOCK reply for ios [%p] tag ["TAGFMT"] device "
               "[%s] status %d\n", ios, TAGFMTARGS(ios->tag), dev->name,
               status);
    rnablk_trace_ios(ios);
    dec_in_flight(ios->dev, ios);
    rnablk_io_completed(ios);

    rnablk_lock_blk_irqsave(ios->blk, flags);
    BUG_ON(g_md_conn != rnablk_get_ios_conn(ios));
    BUG_ON(RNABLK_CACHE_BLK_CONNECT_PENDING != ios->blk->state);
    /* unset the MD ep in all cases -- we'll set it to the CS ep on success */
    rnablk_unset_blk_ep(ios->blk);
    rnablk_unlock_blk_irqrestore(ios->blk, flags);

    if (status != RNA_SERVICE_RESPONSE_STATUS_SUCCESS) {
        rna_printk(KERN_ERR, "MD response timed out for dev [%s] master "
                   "block, resending with delay\n", sent->mqs_pathname);
        queue_retry = TRUE;
        goto done;
    } else if (NULL == response
               || message_sent->h.rmb_message_type !=
                                RNA_SERVICE_MESSAGE_TYPE_MD_QUERY
                || response->h.rmb_message_type !=
                                RNA_SERVICE_MESSAGE_TYPE_MD_QUERY_RESPONSE) {
        rna_printk(KERN_ERR, "Unexpected query or response type: query=%d "
                   "reponse=%d\n", message_sent->h.rmb_message_type,
                   response ? response->h.rmb_message_type : -1);
        error = TRUE;
        goto done;
    }

    /* not safe to deref response above as it is NULL in the timeout case */
    resp = &response->u.rmb_metadata_query_response;

    if (-EAGAIN == resp->mqr_error) {
        rna_printk(KERN_ERR, "MD sent EAGAIN for dev [%s] master block, "
                   "resending with delay\n", sent->mqs_pathname);
        queue_retry = TRUE;
        goto done;
    }

    if (-ENXIO == resp->mqr_error) {
        rna_printk(KERN_ERR, "MD sent ENXIO for dev [%s] master block, "
                   "indicating failed master block.\n", sent->mqs_pathname);
        /*
         * Resume processing. For scratchpad, io to the non-failed blocks will
         * succeed. For persistent devices this should not happen
         */
        rnablk_queue_restart_dev_blks(dev);
        error = TRUE;
        goto done;
    }

    if (0 != resp->mqr_error) {
        rna_printk(KERN_ERR, "MD sent error [%d] for dev [%s] master block\n",
                   resp->mqr_error, sent->mqs_pathname);
        error = TRUE;
        goto done;
    }

    if (CACHE_REQ_TYPE_MASTER != resp->c.co_cache_req_type) {
        rna_printk(KERN_ERR, "Unexpected MD response type [%s]\n", 
                   get_cache_req_type_string(resp->c.co_cache_req_type));
        error = TRUE;
        goto done;
    }

    // record the cache block size for future use
    if (resp->mqr_block_size) {
        if (dev->cache_blk_size != resp->mqr_block_size) {
            rna_printk(KERN_ERR, "MD reports block size of [%"PRIu64"].  "
                       "Adjusting block size on [%s] from [%llu]\n",
                       resp->mqr_block_size, 
                       dev->name,
                       dev->cache_blk_size);
            dev->cache_blk_size = resp->mqr_block_size;
            BUG_ON(dev->cache_blk_size > RNABLK_MAX_CACHE_BLK_SIZE);
        }
    } else {
        rna_printk(KERN_ERR, "MD reports block size of 0, reverting to "
                   "default [%llu]\n", dev->cache_blk_size);
    }

    BUG_ON(dev->dv_master_block_id != resp->mqr_master_block_id);

    rnablk_md_send_cache_query_from_md_response(resp, ios);

 done:
    if (NULL != ios) {
        if (queue_retry || error) {
            rnablk_lock_blk_irqsave(ios->blk, flags);
            (void)rnablk_cache_blk_state_transition(ios->blk,
                                          RNABLK_CACHE_BLK_CONNECT_PENDING,
                                          RNABLK_CACHE_BLK_DISCONNECTED);
            rnablk_unlock_blk_irqrestore(ios->blk, flags);
            rnablk_ios_finish(ios);
        }
        rnablk_ios_release(ios);
    }
    if (queue_retry) {
        rnablk_queue_delayed_master_blk_lock(dev);
    }
    if (error && NULL != dev) {
        rnablk_device_fail(dev);
    }

    (void)rna_service_free_message_buffer(rna_service_ctx, message_sent);
    if (NULL != response) {
        (void)rna_service_free_message_buffer(rna_service_ctx, response);
    }
    rnablk_trc_master(1, "done (err=%d)\n", error);
}

/*
 * rnablk_master_lock_register()
 *  Checks if there is already an active LOCK_MASTER_BLK operation in
 *  progress for this MASTER blk, and if so, returns FALSE.
 *  Otherwise sets the state to show that one is in progress and returns
 *  TRUE.
 *
 * caller must hold blk's bl lock
 */
#ifdef WINDOWS_KERNEL
#pragma warning(push)
#pragma warning(disable : 4146)
#endif

static boolean
rnablk_master_lock_register(struct cache_blk *blk)
{
    RNABLK_DBG_BUG_ON(!IS_MASTER_BLK(blk), "blk [%p] isn't MASTER blk!\n", blk);

    if (!atomic_bit_test_and_set(&blk->cb_flags, BLK_F_MASTER_LOCK_ACTIVE)) {
        return FALSE;
    }
    return TRUE;
}

#ifdef WINDOWS_KERNEL
#pragma warning(pop)
#endif

/*
 * rnablk_master_lock_unregister()
 *  This routine clears the MASTER blk state indicating that there's
 *  an active LOCK_MASTER_BLK in-progress.
 *  This should only be called after the caller has previously done a
 *  successful rnablk_master_lock_register().
 *  (The blk lock is not needed if the above protocol is followed!).
 */
void
rnablk_master_lock_unregister(struct cache_blk *blk)
{
    RNABLK_DBG_BUG_ON(!IS_MASTER_BLK(blk), "blk [%p] isn't MASTER blk!\n", blk);

    RNABLK_BUG_ON(!atomic_bit_test_and_clear(&blk->cb_flags,
                                             BLK_F_MASTER_LOCK_ACTIVE),
                  "no LOCK_MASTER_BLK in progress for dev [%s] blk=%p\n",
                  blk->dev->name, blk);
    return;
}

// runs in kthread context, called when device registration completes
void
rnablk_lock_master_blk(struct rnablk_device *dev)
{
	rna_service_message_buffer_t *mbuf;
    rna_service_metadata_query_t *query;
    struct rnablk_server_conn *conn;
    struct cache_blk *blk = NULL;
    struct io_state *ios = NULL;
    cache_write_mode_t write_mode;
    cache_lock_t lock_type;
    lockstate_t flags;
    boolean transitioned = FALSE;
    mutexstate_t mutex_lock_handle;

#ifdef WINDOWS_KERNEL
    struct rna_service_ctx_s *rna_service_ctx;
#endif
    ENTER;

    BUG_ON(&null_device == dev);

#ifdef WINDOWS_KERNEL
    rna_service_ctx = dev->pHBAExt->hba_rna_service_ctx;
#endif

    // if the driver is unloading or detached skip this query
    if(atomic_read(&shutdown) ||
       atomic_read(&rna_service_detached) ||
       rnablk_dev_is_shutdown(dev)) {
        goto out;
    }

    blk = MASTER_BLK(dev);
    rnablk_trc_master(1, "MASTER st=%s l=%s\n",
                      rnablk_cache_blk_state_string(blk->state),
                      get_lock_type_string(blk->ref_type));

    rnablk_lock_blk_irqsave(blk, flags);
    if (rnablk_blk_connected(blk)) {
        rnablk_unlock_blk_irqrestore(blk, flags);
        rna_printk(KERN_ERR, "master block is already connected, do nothing\n");
        goto out;
    }

    /* Determine if there's already an active LOCK_MASTER in progress */
    if (!rnablk_master_lock_register(blk)) {
        rnablk_unlock_blk_irqrestore(blk, flags);
        rna_printk(KERN_WARNING, "Lock MASTER for dev [%s] already in "
                   "progress, do nothing\n", blk->dev->name);
        goto out;
    }

    if (!rnablk_cache_blk_state_transition(blk,
                                          RNABLK_CACHE_BLK_DISCONNECTED,
                                          RNABLK_CACHE_BLK_CONNECT_PENDING)
        && !rnablk_cache_blk_state_transition(blk,
                                          RNABLK_CACHE_BLK_DISCONN_PENDING,
                                          RNABLK_CACHE_BLK_CONNECT_PENDING)) {
        rnablk_master_lock_unregister(blk);
        rnablk_unlock_blk_irqrestore(blk, flags);
        rna_printk(KERN_ERR, "dev [%s] master block in unexpected state [%s]\n",
                   blk->dev->name, rnablk_cache_blk_state_string(blk->state));
        goto out;
    }
    if (NULL != (conn = blk->cb_conn)) {     // clear stale CS conn info
        rnablk_unlock_blk_irqrestore(blk, flags);
        rna_block_mutex_lock(&conn->block_list_lock, &mutex_lock_handle);
        rnablk_lock_blk_irqsave(blk, flags);
        if (conn == blk->cb_conn) {
            rnablk_blk_put_cachedev(blk, conn);
            blk->cb_conn = NULL;
        } else if (NULL != blk->cb_conn) {
            rna_printk(KERN_WARNING, "dev [%s] master block unexpected "
                       "conn change: old conn ["CONNFMT"] new "
                       "conn ["CONNFMT"]\n",
                       blk->dev->name, CONNFMTARGS(conn),
                       CONNFMTARGS(blk->cb_conn));
        }
        rna_block_mutex_unlock(&conn->block_list_lock, &mutex_lock_handle);
    }

    /* no need to save irq flags because this is a nested lock */
    rna_spin_lock(dev->rbd_event_lock);
    blk->rid = 0;                       // clear RID for CACHE_RSV_ACCESS_RESP
    dev->rbd_rsv.rrs_is_valid = FALSE;
    rna_spin_unlock(dev->rbd_event_lock);

    rnablk_set_blk_ep(blk, MD_CONN_EP_METAVALUE);
    rnablk_unlock_blk_irqrestore(blk, flags);
    transitioned = TRUE;

    if ((ret = rnablk_alloc_ios_admin(dev, ios)) != 0) {
        rna_printk(KERN_ERR, "%s: failed to allocate ios buffer!\n",
				   __FUNCTION__);
		goto err;
	}
    ios->type = RNABLK_LOCK_MASTER_BLK;
    atomic_bit_set(&ios->ios_atomic_flags, IOS_AF_MASTER_LOCK);

	/*
	 * Allocate an rna_service message buffer.
	 */
	mbuf = rna_service_alloc_message_buffer(rna_service_ctx,
                                            RNA_SERVICE_MESSAGE_TYPE_MD_QUERY,
                                            dev->cache_file_name);
	if (NULL == mbuf) {
        rna_printk(KERN_ERR, "%s: failed to allocate message buffer!!\n",
				   __FUNCTION__);
		goto err;
	}

    if (dev_is_persistent(dev)) {
        write_mode = CACHE_WRITE_BACK;
        lock_type = CACHE_WRITE_SHARED;
    } else {
        write_mode = CACHE_SCRATCHPAD;
        lock_type = CACHE_READ_SHARED;
    }

	/*
	 * Initialize the rna_service message buffer as a metadata query message.
	 */
    query = &mbuf->u.rmb_metadata_query;
	mbuf->h.rmb_message_type = RNA_SERVICE_MESSAGE_TYPE_MD_QUERY;
    query->mqs_cookie = (uint64_t)ios->tag;
	query->mqs_request_type = CACHE_REQ_TYPE_MASTER;
	query->mqs_lock_type = lock_type;
	query->mqs_write_mode = write_mode;
	query->mqs_invd_mode = CACHE_INVD_BLOCK;
    query->mqs_path_md_policy = atomic_get(&dev->path_md_policy);
    if (dev_is_persistent(dev)) {
        // allow blocks to failover from cache server to cache server
        query->mqs_error_persistence = CACHE_ERRS_NOT_PERSISTENT;
        query->mqs_evict_policy = CACHE_SERVER_EVICT_POLICY;
    } else {
        query->mqs_error_persistence = CACHE_ERRS_PERSIST_UNTIL_MASTER_INVD;
        query->mqs_evict_policy = CACHE_CLIENT_EVICT_POLICY;
    }
    query->mqs_block_size = dev->cache_blk_size;
	query->mqs_block_num = 0;
    query->mqs_master_block_id = dev->dv_master_block_id;
    query->mqs_pvt_data_len = 0;

    strcpy(query->mqs_pathname, dev->cache_file_name);

    rna_trace("file [%s] cache_type [%s] lock type [%s] block [%"PRId64"] "
              "size [%"PRId64"] uid [%u] gid [%u] policy [%d]\n",
              query->mqs_pathname,
              get_cmd_type_string(query->mqs_request_type),
              get_lock_type_string(query->mqs_lock_type),
              query->mqs_block_num,
              query->mqs_block_size,
              query->mqs_reader_uid,
              query->mqs_reader_gid,
              query->mqs_path_md_policy);

    rnablk_set_ios_blk(ios, blk);
    rnablk_set_ios_ep(ios, MD_CONN_EP_METAVALUE);
    rnablk_io_dispatched(ios);    
    inc_in_flight(dev, ios);

	/*
	 * Send the metadata query.
	 */
    rnablk_trc_master(1, "send query ios [%p] tag ["TAGFMT"] (das=%d)\n",
                      ios, TAGFMTARGS(ios->tag), dev_is_das(dev));

    if (!dev_is_das(dev)) {
	    ret = rna_service_send_md(rna_service_ctx,
                                  mbuf,
                                  rnablk_process_lock_master_blk_response);
    } else {
        /*
         * If this device is in DAS mode, then call the simulated
         * MD query that bypasses sending to the MD and fabricates the
         * response.
         */
	    ret = rnablk_das_metadata_query(dev, rna_service_ctx, mbuf,
                                    rnablk_process_lock_master_blk_response);
    }
	if (ret != RNA_SERVICE_ERROR_NONE) {
        rna_printk(KERN_ERR, "%s: failed to send cache request: %s\n",
                   __location__, rna_service_get_error_string(ret));
        dec_in_flight(dev, ios);
		(void)rna_service_free_message_buffer(rna_service_ctx, mbuf);
    }

out:
    EXITV;

err:
    if (blk) {
        if (transitioned) { // restore blk state
            rnablk_lock_blk_irqsave(blk, flags);
            rnablk_unset_blk_ep(blk);
            (void)rnablk_cache_blk_state_transition(blk,
                                          RNABLK_CACHE_BLK_CONNECT_PENDING,
                                          RNABLK_CACHE_BLK_DISCONNECTED);
            rnablk_unlock_blk_irqrestore(blk, flags);
        }
        if (NULL != ios) {
            rnablk_ios_finish(ios);
        } else {
            rnablk_master_lock_unregister(blk);
        }
    }
    atomic_set(&dev->stats.status, RNABLK_CACHE_OFFLINE);
    goto out;
}

// runs in kthread context
static void rnablk_send_device_stats( struct rnablk_device *dev )
{
	rna_service_message_buffer_t *msgbuf;
    rna_service_error_t ret;
#ifdef WINDOWS_KERNEL
    struct rna_service_ctx_s* rna_service_ctx;
#endif /*WINDOWS_KERNEL*/

    if ((NULL == dev) ||
        /* rnablk_dev_is_shutdown(dev) || */
        atomic_read(&shutdown) ||
        atomic_read(&rna_service_detached)) {
        goto out;
    }

    rna_printk(KERN_DEBUG, "Sending stats for device %s\n", dev->name);

#ifdef WINDOWS_KERNEL
    rna_service_ctx = dev->pHBAExt->hba_rna_service_ctx;
#endif

	/*
	 * Allocate an rna_service message buffer.
	 */
	msgbuf = rna_service_alloc_message_buffer(rna_service_ctx,
                                              RNA_SERVICE_MESSAGE_TYPE_BSTAT_RESPONSE,
                                              NULL);
	if (NULL == msgbuf) {
        rna_printk(KERN_ERR, "%s: failed to allocate message buffer!!\n",
				   __FUNCTION__);
        GOTO( out,-ENOMEM );
	}

    msgbuf->h.rmb_message_type = RNA_SERVICE_MESSAGE_TYPE_BSTAT_RESPONSE;
    msgbuf->u.rmb_bstat_response.bsr_device_id = (uint64_t)dev;
    msgbuf->u.rmb_bstat_response.bsr_stats = dev->stats;

    if (atomic_read(&msgbuf->u.rmb_bstat_response.bsr_stats.openers) < 0) {
        /*
         * The CFM doesn't expect/handle our special negative openers value,
         * so fix it to just reflect there are no openers.
         */
        atomic_set(&msgbuf->u.rmb_bstat_response.bsr_stats.openers, 0);
    }

	ret = rna_service_send_block_device_stats(rna_service_ctx, msgbuf);
	if (ret != RNA_SERVICE_ERROR_NONE) {
        rna_printk(KERN_ERR,
                   "%s: rna_service_send_block_device_stats failed: %s\n",
				   __FUNCTION__, rna_service_get_error_string(ret));
        GOTO( err,-EINVAL );
    }

out:
    return;
err:
    goto out;
}

/**
 * Sends one bstat response for each device
 */
static void rnablk_process_bstat_request(struct rna_service_ctx_s     *ctx,
                                         rna_service_message_buffer_t *message)
{
    struct rnablk_device *dev;
    struct list_head *pos;
    unsigned char oldirql = 0;
#ifdef WINDOWS_KERNEL
    pHW_HBA_EXT pHBAExt;
#endif
    ENTER;

	UNREFERENCED_PARAMETER(ret);

    rna_printk(KERN_DEBUG, "Got bstat request\n");

#ifdef WINDOWS_KERNEL
    pHBAExt = hbaext_from_rna_service_ctx(ctx);
    rna_down_read(&pHBAExt->hba_rnablk_dev_list_lock, &oldirql);
    list_for_each( pos, &pHBAExt->hba_rnablk_dev_list ) {
        dev = list_entry( pos,struct rnablk_device,l );
        rnablk_send_device_stats(dev);
    }
    rna_up_read(&pHBAExt->hba_rnablk_dev_list_lock, oldirql);
#else
    rna_down_read( &rnablk_dev_list_lock, &oldirql );
    list_for_each( pos,&rnablk_dev_list ) {
        dev = list_entry( pos,struct rnablk_device,l );
        rnablk_send_device_stats(dev);
    }
    rna_up_read( &rnablk_dev_list_lock, oldirql );
#endif

    EXITV;
}

/*!
 * rna_service callback invoked when an rna_service event occurs.
 *
 * Arguments:
 *    ctx        The user's rna_service context, as created by
 *               rna_service_ctx_create.
 *
 *    event      The event that occurred.
 */
static void
process_rna_service_event(struct rna_service_ctx_s *ctx,
                          const rna_service_event_t event)
{
#ifdef WINDOWS_KERNEL
    pHW_HBA_EXT pHBAExt;
    pHBAExt = hbaext_from_rna_service_ctx(ctx);
#endif

    switch (event) {
    case RNA_SERVICE_EVENT_NONE:
        /* This shouldn't happen */
        rna_printk(KERN_ERR,
                    "%s: Received RNA_SERVICE_EVENT_NONE event\n",
                    __location__);
        break;
    case RNA_SERVICE_EVENT_INFO_FULLY_CONNECTED:
        /*
         * We now (through rna_service) have connections to the CFM and all the
         * MDs.
         */
        rna_printk(KERN_ERR, "Fully connected to CFM and MDs\n");
        atomic_set(&g_conn_status, RNABLK_CACHE_ONLINE);
        /* complete just allows one waiter through - complete_all is
         * like setting a latch */
#ifndef WINDOWS_KERNEL
        complete_all(&rna_service_connect_comp);
#endif /*WINDOWS_KERNEL*/
        break;
    case RNA_SERVICE_EVENT_CACHE_MOUNT_BLOCKED:
    case RNA_SERVICE_EVENT_CACHE_MOUNT_UNBLOCKED:
        rna_printk(KERN_ERR, "Ignoring rna_service event type %s\n",
                   rna_service_get_event_type_string(event));
        break;
    case RNA_SERVICE_EVENT_DETACHED_FROM_CLUSTER:
        rnablk_process_detach();
        break;
    case RNA_SERVICE_EVENT_REJOINED_CLUSTER:
        rnablk_process_rejoin();
        break;
    /*
     * Purposely leaving out a default: case, so the compiler will complain if
     * any events are unhandled.
     */
    }
}

/*
 * Process a message indicating that a cache server has been expelled from the
 * cluster.
 *
 */
static void rnablk_process_expel_cs(struct rna_service_ctx_s     *ctx,
                                    rna_service_message_buffer_t *message)
{
    struct rnablk_server_conn *conn = NULL;
    unsigned char oldirql = 0;

    rna_down_read(&svr_conn_lock, &oldirql);
    conn = rnablk_cache_search(&cache_conn_root,
                               &message->u.rmb_expel_cs.ecs_service_id);
    rna_up_read(&svr_conn_lock, oldirql);

    if (rnablk_conn_connected(conn)) {
        rna_printk(KERN_NOTICE,
                   "Disconnecting from expelled CS ["rna_service_id_format"]\n",
                   rna_service_id_get_string(
                                    &message->u.rmb_expel_cs.ecs_service_id));
        atomic_bit_set(&conn->rsc_flags, RSC_F_EXPELLED);
        rnablk_queue_conn_disconnect(conn);
    }
}

/*
 * rnablk_process_expel_cache_device
 *  Process an RNA_SERVICE_MESSAGE_TYPE_EXPEL_CD message by
 *  offlining the indicated cache device and performing any necessary
 *  cleanup of associated state.
 */
static void
rnablk_process_expel_cache_device(struct rna_service_ctx_s *ctx,
                                  rna_service_message_buffer_t *message)
{
    struct rnablk_server_conn *conn;
    unsigned char oldirql = 0;

    cachedev_id_t cachedev_id =
                        message->u.rmb_expel_cache_device.ced_cachedev_id;
    boolean is_reactivate = (boolean)
                        message->u.rmb_expel_cache_device.ced_reactivating_flag;
    rnablk_cachedev_t *cachedev;
    ENTERV;

    rna_down_read(&svr_conn_lock, &oldirql);
    conn = rnablk_cache_search(&cache_conn_root,
                               &message->u.rmb_expel_cache_device.ced_cs_id);
    rna_up_read(&svr_conn_lock, oldirql);
    if (NULL != conn) {
        rna_printk(KERN_NOTICE, "cachedev [%#"PRIx64"] on CS ["CONNADDRFMT"] "
                   "%s\n", message->u.rmb_expel_cache_device.ced_cachedev_id,
                   CONNADDRFMTARGS(conn),
                   is_reactivate ? "reactivating" : "expelling");

        cachedev = rnablk_get_conn_cachedev(conn, cachedev_id, FALSE);
        rnablk_trc_discon(1, "Do %s of cachedev=%"PRIx64"%s\n",
                          is_reactivate ? "reactivating" : "expelling",
                          cachedev_id, NULL == cachedev ?
                          " - cachedev not found, nothing to do" : "");
        if (NULL != cachedev) {
            if (!is_reactivate
                || atomic_bit_is_set(&cachedev->rcd_state, RCD_STATE_FROZEN)) {
                rnablk_trigger_offline_cache_device(conn, cachedev_id,
                                                    CD_OFFLINE_EXPEL);
            } else {
                atomic_set(&cachedev->rcd_state, RCD_STATE_ONLINE);
            }
            rnablk_put_cachedev(cachedev);
        }
    } else {
        rna_printk(KERN_NOTICE, "cachedev [%#"PRIx64"] %s, conn not found, "
                   "ignoring\n",
                   message->u.rmb_expel_cache_device.ced_cachedev_id,
                   is_reactivate ? "reactivating" : "expelling");
    }
    EXITV;
}

void
rnablk_process_unexpelled_cachedevs(struct rna_service_ctx_s *ctx,
                                    rna_service_message_buffer_t *message)
{
    rnablk_check_for_expelled_cachedevs(&message->u.rmb_unexpelled_cachedevs);
}

/*!
 * rna_service callback invoked if an asynchronous message (a message with
 * no response, is received.  These messages are:
 *
 *  rna_service_set_log_level_t       RNA_SERVICE_MESSAGE_TYPE_SET_LOG_LEVEL
 *  rna_service_client_event_t        RNA_SERVICE_MESSAGE_TYPE_CLIENT_EVENT
 *  rna_service_client_event_reg_t    RNA_SERVICE_MESSAGE_TYPE_CLIENT_EVENT_REG
 *  rna_service_client_event_dereg_t  RNA_SERVICE_MESSAGE_TYPE_CLIENT_EVENT_DEREG
 *  rna_service_create_block_device_t RNA_SERVICE_MESSAGE_TYPE_CREATE_BLKDEV
 *  rna_service_control_block_device_t RNA_SERVICE_MESSAGE_TYPE_CONTROL_BLKDEV
 *
 * NOTE that the callback function is responsible for freeing the message
 * using rna_service_free_message_buffer().
 *
 * Arguments:
 *    ctx        The user's rna_service context, as created by
 *               rna_service_ctx_create.
 *
 *    message
 *               A message of type RNA_SERVICE_SET_LOG_LEVEL
 *                                          (rna_service_set_log_level_t),
 *               RNA_SERVICE_MESSAGE_TYPE_CLIENT_EVENT_REG
 *                                          (rna_service_client_event_reg_t),
 *               RNA_SERVICE_MESSAGE_TYPE_CLIENT_EVENT_DEREG
 *                                          (rna_service_client_event_dereg_t),
 *               RNA_SERVICE_MESSAGE_TYPE_CLIENT_EVENT
 *                                          (rna_service_client_event_t),
 *               or RNA_SERVICE_MESSAGE_TYPE_CS_CLIENT_REG
 *                                          (rna_service_cache_client_reg_t).
 */
#ifndef WINDOWS_KERNEL
static 
#endif
void
process_async_message(struct rna_service_ctx_s     *ctx,
                      rna_service_message_buffer_t *message)
{
    int     free_message = 1;

    switch (message->h.rmb_message_type) {
    case RNA_SERVICE_MESSAGE_TYPE_SET_LOG_LEVEL:
        /* log level change messages are currently ignored */
        break;
    case RNA_SERVICE_MESSAGE_TYPE_CLIENT_EVENT_REG:
        /* event registration messages are currently ignored */
        break;
    case RNA_SERVICE_MESSAGE_TYPE_CLIENT_EVENT_DEREG:
        /* event deregistartion messages are currently ignored */
        break;
    case RNA_SERVICE_MESSAGE_TYPE_CLIENT_EVENT:
        printk("rna: remote event: %s\n",
               message->u.rmb_client_event.ces_print_buffer);
        break;
    case RNA_SERVICE_MESSAGE_TYPE_CREATE_BLKDEV:
        free_message = 0;       /* device create dpc frees message */
        rnablk_deferred_process_create_block_device(ctx, message);
        break;
    case RNA_SERVICE_MESSAGE_TYPE_CONTROL_BLKDEV:
        free_message = 0;       /* device control dpc frees message */
        rnablk_deferred_process_control_block_device(ctx, message);
        break;
    case RNA_SERVICE_MESSAGE_TYPE_BSTAT_REQUEST:
        rnablk_process_bstat_request(ctx, message);
        break;
    case RNA_SERVICE_MESSAGE_TYPE_EXPEL_CS:
        rnablk_process_expel_cs(ctx, message);
        break;
    case RNA_SERVICE_MESSAGE_TYPE_EXPEL_CACHE_DEVICE:
        rnablk_process_expel_cache_device(ctx, message);
        break;
    case RNA_SERVICE_MESSAGE_TYPE_UNEXPELLED_CACHEDEVS:
        rnablk_process_unexpelled_cachedevs(ctx, message);
        break;
    case RNA_SERVICE_MESSAGE_TYPE_CS_CLIENT_REG:
        rbd_cs_if = message->u.rmb_cache_client_reg.ccr_if_table;
        rbd_cs_svc_id = message->u.rmb_cache_client_reg.ccr_service_id;
        rna_printk(KERN_INFO,
                   "RNA_SERVICE_MESSAGE_TYPE_CS_CLIENT_CONNECT\n");
        rna_printk(KERN_INFO,
               "CS Service ID ["rna_service_id_format"]\n",
               rna_service_id_get_string(&rbd_cs_svc_id));
        if (FALSE == atomic_cmpxchg(&rbd_local_cs_connect, FALSE, TRUE)) {
            rna_printk(KERN_DEBUG,
                   "CS Connection received\n");
        } else {
            rna_printk(KERN_WARNING,
                   "CS connection info already received, ignoring\n");
        }
        break;
    case RNA_SERVICE_MESSAGE_TYPE_CONF_MGR_REG_RESPONSE:
        if (message->u.rmb_cfm_client_resp.per_device_connections > 0) { 
            rnablk_per_device_connections = message->u.rmb_cfm_client_resp.per_device_connections;
        }
        if (message->u.rmb_cfm_client_resp.default_block_size > 0) {
            fldc_default_block_size = message->u.rmb_cfm_client_resp.default_block_size;
        }
        break;
    default:
        rna_printk(KERN_ERR,
                   "process_async_message called with unhandled message "
                   "type %d\n", message->h.rmb_message_type);
        break;
    }
    if (free_message) {
        (void) rna_service_free_message_buffer(ctx, message);
    }
}

/**
 * Create rna_service context, and all the CFM & MD connections that
 * implies.  Done once for the whole driver when we discover (all of)
 * our CFM addresses.
 */
int
rnablk_service_init(void *arg)
{
    rna_service_error_t rnas_ret;
    unsigned char oldirql;
    //struct rnablk_device *dev = (struct rnablk_device *)arg;

#ifdef WINDOWS_KERNEL
    struct rna_service_ctx_s *rna_service_ctx;
    prna_service_win_init_handles_t pRnaSvcWinInfo = (rna_service_win_init_handles_t *) arg;
    pHW_HBA_EXT pHBAExt = pRnaSvcWinInfo->pHBAExt;
    int com_type = 80;
#else
    int i;
#endif

    ENTER;

    atomic_set(&g_conn_status, RNABLK_CACHE_CONNECTING);
    atomic_set( &shutdown,0 );

    /* Make an rnablk_server_conn object for throttling & queueing rna_service MD queries */
    g_md_conn = rnablk_make_server_conn(NULL, NULL, NULL, NULL, 0);
    g_md_conn->ep = MD_CONN_EP_METAVALUE;
#ifdef WINDOWS_KERNEL
    g_md_conn->pHBAExt = pHBAExt;
#endif
#ifdef WINDOWS_KERNEL
	atomic_bit_clear(&g_md_conn->rsc_flags, RSC_F_DISPATCHING);
#endif /*WINDOWS_KERNEL*/
	atomic_set(&g_md_conn->state, RNABLK_CONN_CONNECTED);

    /*
     * Must acquire the lock, because rnablk_cs_ping_worker() thread is
     * already running and accessing cache_conn_root tree...
     */
    rna_down_read(&svr_conn_lock, &oldirql);
    rnablk_cache_insert(&cache_conn_root, g_md_conn);
    rna_up_read(&svr_conn_lock, oldirql);

    /* Initialize the rna_service component */
    rna_service_params.rsp_user_type = RNA_SERVICE_USER_TYPE_BLOCK_CLIENT;

    if (strlen(node_name)) {
        strncpy(rna_service_params.rsp_node_name, node_name,
            sizeof(rna_service_params.rsp_node_name) - 1);
    }

    rna_service_params.rsp_flags = RNA_SERVICE_FLAG_PING_CFM;
    rna_service_params.rsp_transports = 0;
            // Currently, this driver doesn't specify a communication transport
            // preference, though that may change in the future.
#ifdef RNA_USE_IOS_TIMERS
    rna_service_params.rsp_metadata_query_response_timeout = rnablk_io_timeout;
#else
    rna_service_params.rsp_metadata_query_response_timeout = 0;
#endif /* RNA_USE_IOS_TIMERS */
    rna_service_params.rsp_cache_invalidate_response_timeout = 1200;
    rna_service_params.rsp_block_device_reg_response_timeout = 1200;
    rna_service_params.rsp_event_callback = process_rna_service_event;
    rna_service_params.rsp_async_msg_callback = process_async_message;
    rna_service_params.rsp_md_ping_rate = MD_PING_INTERVAL;  // in seconds
#ifdef WINDOWS_KERNEL
    rna_service_params.rsp_cfm_count = 1;

    ret = rna_service_parse_ip_addr(pRnaSvcWinInfo->cfmIpAddr, 
                                    (uint32_t *)&(rna_service_params.rsp_cfm_addrs[0].sin_addr.s_addr), 
                                    &( rna_service_params.rsp_cfm_addrs[0].sin_port), 
                                    &com_type, 
                                    NULL);

    rna_service_params.rsp_cfm_addrs[0].sin_family = AF_INET;
    rna_service_params.rsp_cfm_com_types[0] = IP_TCP;

#else
    rna_service_params.rsp_cfm_count = cfm_config_info.cfm_count;
    for (i = 0; i < cfm_config_info.cfm_count; i++) {
        rna_service_params.rsp_cfm_addrs[i] = cfm_config_info.cfms[i].ip_addr;
        rna_service_params.rsp_cfm_com_types[i] = cfm_config_info.cfms[i].com_type;
    }
#endif /*WINDOWS_KERNEL*/
    rnas_ret = rna_service_ctx_create(&rna_service_params, &rna_service_ctx);
    if (RNA_SERVICE_ERROR_NONE != rnas_ret) {
        atomic_set(&g_conn_status, RNABLK_CACHE_OFFLINE);
        rna_printk(KERN_ERR, "%s: failed to create rna_service context: %s\n",
                   __FUNCTION__, rna_service_get_error_string(rnas_ret));
        GOTO( out,-ENOMEM );
    }

#ifdef WINDOWS_KERNEL
    pRnaSvcWinInfo->pHBAExt->hba_rna_service_ctx = rna_service_ctx;
    pRnaSvcWinInfo->pHBAExt->hbakey_rna_service_ctx = rna_service_ctx;
#endif

out:
    EXIT;
}

/**
 * Update our CFM addresses.
 */
int
rnablk_process_cfms_update(int cfm_count, struct sockaddr_in *online_cfms)
{
#ifndef WINDOWS_KERNEL
    rna_service_error_t rnas_ret;
#endif /* ~WINDOWS_KERNEL*/

    ENTER;
#ifdef WINDOWS_KERNEL
    GOTO( out,-EINVAL );
#else
    rnas_ret = rna_service_cfms_update(cfm_count,
                                       online_cfms,
                                       rna_service_ctx);
    if (RNA_SERVICE_ERROR_NONE != rnas_ret) {
        rna_printk(KERN_WARNING, "%s: failed to update cfms: %s\n",
                   __FUNCTION__, rna_service_get_error_string(rnas_ret));
        GOTO( out,-EAGAIN );
    }
#endif /*WINDOWS_KERNEL*/
out:
    EXIT;
}

INLINE void
rnablk_save_cmd_latency(struct io_state *ios, struct cache_cmd *cmd)
{
    unsigned long flags;
    uint64_t time;
    int index = -1;
    
#ifdef WINDOWS_KERNEL
    pHW_HBA_EXT pHBAExt = ios->dev->pHBAExt;
#endif

    time = (getrawmonotonic_ns() - ios->issue_time_ns);
    
    if (RNABLK_CACHE_QUERY == ios->type) {
        if (CACHE_WRITE_ONLY_SHARED == cmd->u.cache_rep.rnas.cr_ref_type) {
            index = RNABLK_LATENCY_WO_QUERY;
        } else {
            index = RNABLK_LATENCY_QUERY;
        }
    } else if (RNABLK_CHANGE_REF == ios->type) {
        if (CACHE_NO_REFERENCE == cmd->u.cache_change_ref_resp.new_ref_type) {
            index = RNABLK_LATENCY_DEREF;
        } else if ((CACHE_WRITE_ONLY_SHARED == 
                    cmd->u.cache_change_ref_resp.old_ref_type) &&
                   (CACHE_WRITE_SHARED == 
                    cmd->u.cache_change_ref_resp.new_ref_type)) {
            index = RNABLK_LATENCY_WO_TO_W;
        }
    }
    if (-1 != index) {
        rna_spin_lock_irqsave(latency_stats.ls_spinlock, flags);
        atomic_inc(&latency_stats.ls_count[index]);
        latency_stats.ls_time[index] += time;
        if (time < latency_stats.ls_min[index]) {
            latency_stats.ls_min[index] = time;
        }
        if (time > latency_stats.ls_max[index]) {
            latency_stats.ls_max[index] = time;
        }
        rna_spin_unlock_irqrestore(latency_stats.ls_spinlock, flags);
    }
}

//
// Handles CACHE_RESPONSE for normal blocks, which makes blocks valid, supplies
// RDMA info, and references from none to an acquired state.
INLINE void
rnablk_process_cache_block_response_internal(struct com_ep *ep,
                                             struct io_state *ios,
                                             uint8_t status,
                                             uint8_t ref_type,
                                             uint8_t orig_ref_type,
                                             cachedev_id_t cachedev_id)
{
    struct cache_blk *blk = ios->blk;
    struct rnablk_server_conn *conn;
    lockstate_t irqflags;
    boolean need_invalidate = FALSE;
    long max_retries;
    long retry_delay_ms;
    struct sockaddr_in dst_in;
    mutexstate_t mutex_handle;

    conn = (struct rnablk_server_conn *)com_get_ep_context(ep);

    rnablk_lock_blk_irqsave(blk, irqflags);

 recheck_state:
    switch (blk->state) {
    case RNABLK_CACHE_BLK_CONNECT_PENDING:
        break;          // this is the expected/normal state

    case RNABLK_CACHE_BLK_INVALID:
        rna_printk(KERN_INFO, "ignoring ios [%p] tag ["TAGFMT"] type [%s] "
                   "for [%s] block [%"PRIu64"] in state [%s]\n",
                   ios, TAGFMTARGS(ios->tag), rnablk_op_type_string(ios->type),
                   blk->dev->name, blk->block_number,
                   rnablk_cache_blk_state_string(blk->state));
        rnablk_unlock_blk_irqrestore(blk, irqflags);
        rnablk_end_request(ios, -EIO);
        return;

    case RNABLK_CACHE_BLK_INVALIDATE_PENDING:
        if (0 == status) {
            /*
             * CS gave us a valid reference, but the response raced with
             * an INVD.  Easiest way to handle it is to transition as for
             * normal successful QUERY, then initiate the invalidate.
             */
            rnablk_cache_blk_state_set(blk, RNABLK_CACHE_BLK_CONNECT_PENDING);
            need_invalidate = TRUE;
        } else {
            /*
             * XXX don't think this case should actually happen.  If we got
             * back an error from CS, then it shouldn't have had any reference
             * from this client and thus shouldn't have sent us an INVD...
             */

            /* need the conn lock to unset_blk_ep ... */
            rnablk_unlock_blk_irqrestore(blk, irqflags);
            rna_block_mutex_lock(&conn->block_list_lock, &mutex_handle);
            rnablk_lock_blk_irqsave(blk, irqflags);
            if (RNABLK_CACHE_BLK_INVALIDATE_PENDING != blk->state) {
                rna_block_mutex_unlock(&conn->block_list_lock, &mutex_handle);
                goto recheck_state;
            }
            rnablk_unset_blk_ep(blk);
            RNABLK_BUG_ON(!rnablk_cache_blk_state_transition(blk,
                           RNABLK_CACHE_BLK_INVALIDATE_PENDING,
                           RNABLK_CACHE_BLK_DISCONNECTED),
                           "block [%llu] unexpected state [%s] ios [%p]\n",
                           blk->block_number,
                           rnablk_cache_blk_state_string(blk->state), ios);
            rnablk_unlock_blk_irqrestore(blk, irqflags);
            rna_block_mutex_unlock(&conn->block_list_lock, &mutex_handle);
            rna_printk(KERN_WARNING, "Requeuing ios [%p] tag ["TAGFMT"] "
                       "block [%llu] due to racing INVD\n", ios,
                       TAGFMTARGS(ios->tag), blk->block_number);
            rnablk_queue_delayed_request(ios, RNABLK_EAGAIN_DELAY_MS);
            return;
        }
        break;

    case RNABLK_CACHE_BLK_DISCONN_PENDING:
    case RNABLK_CACHE_BLK_DISCONNECTED:
        /* Put I/O in queue so it can be re-started "from scratch" */
        rna_printk(KERN_INFO, "Queuing ios [%p] tag ["TAGFMT"] type [%s] "
                   "for [%s] block [%"PRIu64"] in state [%s]\n",
                   ios, TAGFMTARGS(ios->tag), rnablk_op_type_string(ios->type),
                   blk->dev->name, blk->block_number,
                   rnablk_cache_blk_state_string(blk->state));
        rnablk_queue_blk_io_nolock(blk, ios, QUEUE_HEAD);
        rnablk_unlock_blk_irqrestore(blk, irqflags);
        return;

    default:
        RNABLK_BUG_ON(TRUE, "ios [%p] tag ["TAGFMT"] block [%llu] in "
                      "unexpected state [%s] for query response\n",
                      ios, TAGFMTARGS(ios->tag), blk->block_number,
                      rnablk_cache_blk_state_string(blk->state));
    }

    rnablk_unlock_blk_irqrestore(blk, irqflags);

    if (unlikely(0 != status)) {
        if ((CACHE_RESP_CODE_EAGAIN == status) ||
            (CACHE_RESP_CODE_OFFLINE == status) ||
            (CACHE_RESP_CODE_RELOCATE == status) ||
            (CACHE_RESP_CODE_CACHEDEV_ERROR == status) ||
            (CACHE_RESP_CODE_BADLOCK == status &&
             dev_is_persistent(ios->dev))) {

            switch (status) {
            case CACHE_RESP_CODE_OFFLINE:
                retry_delay_ms = RNABLK_OFFLINE_DELAY_MS;
                break;
            case CACHE_RESP_CODE_RELOCATE:
                retry_delay_ms = RNABLK_RELOCATE_DELAY_MS;
                break;
            default:
                retry_delay_ms = RNABLK_EAGAIN_DELAY_MS;
                break;
            }

            max_retries = (rnablk_io_timeout * MSEC_PER_SEC) / retry_delay_ms;


            if (unlikely(atomic_read(&ios->blk->dev->failed))) {
                rna_printk(KERN_NOTICE, "ending ios [%p] tag ["TAGFMT"] "
                           "type [%s] for failed device [%s] "
                           "block [%"PRIu64"] state [%s]\n",
                           ios,
                           TAGFMTARGS(ios->tag),
                           rnablk_op_type_string(ios->type),
                           blk->dev->name,
                           blk->block_number,
                           rnablk_cache_blk_state_string(blk->state));
                /* this will drop the conn reference on the blk */
                rnablk_mark_cache_blk_bad_and_drain(blk, TRUE);
                rnablk_end_request(ios, -EIO);
            } else if (atomic_read(&blk->retries) >= max_retries) {
                 dst_in = get_dest_sockaddr_from_ep(ep);

				 rna_printk(KERN_WARNING,
                           "Error [%s] from CS ["NIPQUAD_FMT"] for query of "
                           "block [%llu] on device [%s] after [%d] tries, "
                           "failing block\n",
                           get_cache_resp_code(status),
                           NIPQUAD(dst_in.sin_addr.s_addr),
                           blk->block_number,
                           ios->dev->name,
                           atomic_read(&blk->retries));

                /* this will drop the conn reference on the blk */
                rnablk_mark_cache_blk_bad_and_drain(blk, TRUE);
                rnablk_end_request(ios, -EIO);
            } else {
                if (0 == atomic_read(&blk->retries)) {
                    dst_in = get_dest_sockaddr_from_ep(ep);

                    /* avoid message spew by logging only once (per episode) */
                    rna_printk(KERN_INFO,
                           "Error [%s] from CS ["NIPQUAD_FMT"] for query of "
                           "block [%llu] in state [%s] on device [%s] "
                           "ios [%p] tag ["TAGFMT"], retrying\n",
                           get_cache_resp_code(status),
                           NIPQUAD(dst_in.sin_addr.s_addr),
                           blk->block_number,
                           rnablk_cache_blk_state_string(blk->state),
                           ios->dev->name, ios, TAGFMTARGS(ios->tag));
                }

                /* We already hold a ref on blk here */
                rna_block_mutex_lock(&conn->block_list_lock, &mutex_handle);
                rnablk_lock_blk_irqsave(blk, irqflags);
                if (RNABLK_CACHE_BLK_CONNECT_PENDING != blk->state) {
                    rna_block_mutex_unlock(&conn->block_list_lock, &mutex_handle);
                    goto recheck_state;
                }

                atomic_inc(&blk->retries);
                rnablk_unset_blk_ep(blk);
                /* do state transition while block lock is held */
                RNABLK_BUG_ON(!rnablk_cache_blk_state_transition(blk,
                               RNABLK_CACHE_BLK_CONNECT_PENDING,
                               RNABLK_CACHE_BLK_DISCONNECTED),
                               "blk=%p [%llu] unexpected state [%s] ios [%p]\n",
                               blk, blk->block_number,
                               rnablk_cache_blk_state_string(blk->state), ios);
                rnablk_unlock_blk_irqrestore(blk, irqflags);
                rna_block_mutex_unlock(&conn->block_list_lock, &mutex_handle);
                rnablk_trc_discon(CACHE_RESP_CODE_CACHEDEV_ERROR
                                  == status,
                                  "CACHEDEV_ERROR: ios [%p] tag ["TAGFMT"] "
                                  "block [%llu] state [%s] ref [%s] "
                                  "type [%s]\n", ios, TAGFMTARGS(ios->tag),
                                  ios->blk->block_number,
                                  rnablk_cache_blk_state_string(
                                  ios->blk->state),
                                  get_lock_type_string(ios->blk->ref_type),
                                  rnablk_op_type_string(ios->type));
                rnablk_queue_delayed_request(ios, retry_delay_ms);
            }
        } else {
            dst_in = get_dest_sockaddr_from_ep(ep);

            rna_printk(KERN_ERR,
                       "Error [%s] from CS ["NIPQUAD_FMT"] for query of blk "
                       "[%llu] on device [%s]\n",
                       get_cache_resp_code(status),
                       NIPQUAD(dst_in.sin_addr.s_addr),
                       blk->block_number,
                       ios->dev->name );

            /* this will drop the conn reference on the blk */
            rnablk_mark_cache_blk_bad_and_drain(blk, TRUE);
            rnablk_end_request(ios, -EIO);
        }
    } else {
        if (likely(0 != cachedev_id)) {
            if (unlikely(0 != rnablk_blk_get_cachedev(blk, cachedev_id,
                                    conn, ios_writes_data(ios)))) {
                rna_printk(KERN_ERR,
                           "[%s] block [%"PRIu64"] memory not available, "
                           "failing ios [%p] tag ["TAGFMT"] type [%s]\n",
                           blk->dev->name,
                           blk->block_number,
                           ios, TAGFMTARGS(ios->tag),
                           rnablk_op_type_string(ios->type));
                rnablk_end_request(ios, -EIO);
                return;
            }
        }

        if (0 != atomic_read(&blk->retries)) {
            rna_printk(KERN_INFO, "ios [%p] tag ["TAGFMT"] "
              "block [%llu] got ref [%s] for device [%s] after %d "
              "retries\n", ios, TAGFMTARGS(ios->tag), blk->block_number,
              get_lock_type_string(ref_type),
              ios->dev->name, atomic_read(&blk->retries));
            atomic_set(&blk->retries, 0);
        }


        /* blk_cachedev was set via rnablk_blk_get_cachedev() above */
        blk->cb_dev_conn = rnablk_next_cachedev_conn(blk->blk_cachedev);
        rnablk_get_local_dev(blk, conn);

        rnablk_lock_blk_irqsave(blk, irqflags);
        if (RNABLK_CACHE_BLK_CONNECT_PENDING != blk->state) {
            goto recheck_state;
        }
        rnablk_cs_query_blk_transition(blk, (cache_lock_t)ref_type,
                                       (cache_lock_t)orig_ref_type);
        rnablk_trace_ios(ios);
        rnablk_cache_blk_update_dev_counts(blk);

        if (need_invalidate) {
            /*
             * This completion actually raced with the CS asking to have
             * the blk invalidated.  Do the INVD now, and queue this ios
             * up for after.
             */
            rnablk_queue_blk_io_nolock(blk, ios, QUEUE_HEAD);
            RNABLK_BUG_ON(!rnablk_cache_blk_state_transition(blk,
                          blk->state, RNABLK_CACHE_BLK_INVALIDATE_PENDING),
                          "blk=%p [%llu] unexpected state [%s] ios [%p]\n",
                          blk, blk->block_number,
                          rnablk_cache_blk_state_string(blk->state), ios);
            rnablk_queue_deref(blk, FALSE);
        } else {
            /*
             * queue this request for RDMA
             * Do the drain atomically (wrt held blk lock) with the
             * queue_io_request(), to avoid issues with racing
             * cache-device failures, etc.
             */
            rnablk_retrack_ios( ios );
            queue_io_request(ios, blk, FORCE_QUEUED_IO);
            rnablk_cache_blk_drain_nolock(blk, &irqflags);
        }
        rnablk_unlock_blk_irqrestore(blk, irqflags);

        rnablk_start_blk_io(blk, TRUE);
    }

    /* 'conn' may be different after queue_io_request, so reset it */
    if (NULL != (conn = rnablk_get_ios_conn(ios))) {
        rnablk_schedule_conn_dispatch(conn);
    }
}

// runs in kthread context
static void
rnablk_process_cache_block_response(struct com_ep *ep,
                                    struct io_state *ios, 
                                    void *data)
{
    struct cache_cmd *cmd = (struct cache_cmd *)data;
    struct cache_blk *blk = ios->blk;
    struct rnablk_server_conn *conn;

    rnablk_trace_ios(ios);

    BUG_ON(!((CACHE_REQ_TYPE_BLOCK == cmd->u.cache_rep.rnas.cr_cache_type)));

    conn = (struct rnablk_server_conn *)(com_get_ep_context(ep));

    rnablk_save_cmd_latency(ios, cmd);
    rnablk_cache_blk_ref(blk);

    TRACE( DBG_FLAG_VERBOSE, "response from CS "
           "["rna_service_id_format"] for sector [%"PRIu64"] on "
           "device [%s] ios [%p] tag ["TAGFMT"] has block [%llu]\n",
           rna_service_id_get_string(&conn->id),
           ios->start_sector, ios->dev->name, ios, TAGFMTARGS(ios->tag),
           blk->block_number);
    RNABLK_BUG_ON_BLK((boolean)rnablk_cache_blk_state_is_bogus(blk->state), blk);

    if (unlikely(net_link_mask & RNABLK_NL_BLK_STATE)) {
        printnl_atomic("[%d] [%s] response from CS "
                       "["rna_service_id_format"] for block [%llu] on "
                       "device [%s] state [%s] server has ref [%s] status[%s]\n",
                       current->pid,
                       __FUNCTION__,
                       rna_service_id_get_string(&conn->id),
                       blk->block_number,
                       ios->dev->name,
                       rnablk_cache_blk_state_string(blk->state),
                       get_lock_type_string(cmd->u.cache_rep.rnas.cr_ref_type),
                       get_cache_resp_code(cmd->u.cache_rep.rnas.cr_status));
    }

#ifdef TEST_OFFLINE_CACHE_DEVICE
    if (test_cachedev_fail_cache_resp
        && test_cachedev_fail_cache_resp == cmd->u.cache_rep.rnas.cr_cachedev_id
        && 0 == cmd->u.cache_rep.rnas.cr_status) {
        rna_printk(KERN_ERR, "Injecting CACHEDEV_ERROR for ios [%p] tag "
                   "["TAGFMT"] block [%llu]\n", ios, TAGFMTARGS(ios->tag),
                   blk->block_number);
        test_cachedev_fail_cache_resp = 0;
        cmd->u.cache_rep.rnas.cr_status = CACHE_RESP_CODE_CACHEDEV_ERROR;
    }
#endif /* TEST_OFFLINE_CACHE_DEVICE */
#ifdef TEST_STORAGE_ERROR
    if (0 == cmd->u.cache_rep.rnas.cr_status
        && atomic_add_unless(&blk->dev->rbd_test_err_inject, -1, 0)) {
        rna_printk(KERN_ERR, "Injecting STORAGE_ERROR for ios [%p] tag "
                   "["TAGFMT"] block [%llu]\n", ios, TAGFMTARGS(ios->tag),
                   blk->block_number);
        cmd->u.cache_rep.rnas.cr_status = CACHE_RESP_CODE_STORAGE_ERROR;
    }
#endif /* TEST_STORAGE_ERROR */
    
    if (0 == cmd->u.cache_rep.rnas.cr_status) {
        // initialize the cache blk with info from the cache server
        blk->rid          = cmd->u.cache_rep.rnas.cr_cache_cookie;
        blk->raddr        = cmd->u.cache_rep.rnas.cr_cache_buf;
        blk->rkey         = cmd->u.cache_rep.rnas.cr_rkey;
        blk->rlen         = cmd->u.cache_rep.rnas.cr_length;
        blk->direct_raddr = cmd->u.cache_rep.rnas.cr_direct_cache_buf;
        blk->direct_rkey  = cmd->u.cache_rep.rnas.cr_direct_rkey;
    }

    rnablk_process_cache_block_response_internal(ep, ios,
                            cmd->u.cache_rep.rnas.cr_status,
                            cmd->u.cache_rep.rnas.cr_ref_type,
                            cmd->u.cache_rep.rnas.cr_orig_ref_type,
                            cmd->u.cache_rep.rnas.cr_cachedev_id);

    /* Drop ref obtained above via rnablk_cache_blk_get() */
    rnablk_cache_blk_release(blk);
}

// runs in kthread context
//
// Handles CACHE_RESPONSE for master blocks, which makes blocks valid, supplies
// RDMA info, and moves references from none towards write.  Used to go from
// WRITE_SHARED to WRITE_EXCLUSIVE for SCSI reservations.
static void 
rnablk_process_cache_master_block_response(struct com_ep *ep, 
                                           struct io_state *ios, void *data)
{
    struct cache_cmd *cmd = (struct cache_cmd *)data;
    struct cache_blk *blk;
    struct rnablk_server_conn *conn = NULL;
    int do_register = FALSE;
    uint64_t new_cap;
    struct rnablk_device *dev = ios->dev;
    lockstate_t irqflags;
    unsigned char oldirql = 0;
    struct sockaddr_in dst_in;
    mutexstate_t mutex_lock_handle;

#ifdef WINDOWS_KERNEL
    pHW_HBA_EXT pHBAExt = ios->dev->pHBAExt;
#endif
    ENTER;

    rnablk_trc_master(1, "start: ios [%p] tag ["TAGFMT"] type [%s] state [%s] "
                      "ref [%s]\n", ios, TAGFMTARGS(ios->tag),
                      rnablk_op_type_string(ios->type), 
                      rnablk_cache_blk_state_string(ios->blk->state),
                      get_lock_type_string(ios->blk->ref_type));
    rnablk_trace_ios(ios);

    BUG_ON(CACHE_REQ_TYPE_MASTER != cmd->u.cache_rep.rnas.cr_cache_type);
    BUG_ON(NULL == ios->blk);

	UNREFERENCED_PARAMETER(ret);

    conn = (struct rnablk_server_conn *)(com_get_ep_context(ep));

    /* Since master_block never goes away, no need to grab reference here */
    blk = ios->blk;
    RNABLK_BUG_ON_BLK((boolean)rnablk_cache_blk_state_is_bogus(blk->state), blk);
    dst_in = get_dest_sockaddr_from_ep(ep);

    if ((CACHE_RESP_CODE_EAGAIN == cmd->u.cache_rep.rnas.cr_status) ||
        (CACHE_RESP_CODE_OFFLINE == cmd->u.cache_rep.rnas.cr_status)) {
        rna_block_mutex_lock(&conn->block_list_lock, &mutex_lock_handle);
        rnablk_lock_blk_irqsave(blk, irqflags);
        if (!rnablk_cache_blk_state_transition(blk,
                                        RNABLK_CACHE_BLK_CONNECT_PENDING,
                                        RNABLK_CACHE_BLK_DISCONNECTED)) {
            rna_printk(KERN_ERR, "failed to restore MASTER blk state, "
                       "cur state [%s]\n",
                       rnablk_cache_blk_state_string(blk->state));
        }
        rnablk_unset_blk_ep(blk);
        rnablk_unlock_blk_irqrestore(blk, irqflags);
        rna_block_mutex_unlock(&conn->block_list_lock, &mutex_lock_handle);
        /* limit message spew; only log 1st time (per episode) */
        if (0 == atomic_read(&blk->retries)) {
            rna_printk(KERN_WARNING,
                       "Error [%s] from CS ["NIPQUAD_FMT"] for query for "
                       "master block on device [%s], retrying\n",
                       get_cache_resp_code(cmd->u.cache_rep.rnas.cr_status),
                       NIPQUAD(dst_in.sin_addr.s_addr),
                       dev->name);
        }
        atomic_inc(&blk->retries);
        /*
         * Try again (go back to the MD).
         * Note we want to 'finish' this ios before queuing the new
         * LOCK_MASTER_BLK, to ensure we don't race with our LOCK_MASTER
         * serialization mechanism (which won't start a new operation until
         * the ios for the current one is finished).
         */
        rnablk_ios_finish(ios);
        ios = NULL;     // clear to avoid finishing again below
        rnablk_queue_delayed_master_blk_lock(dev);
    } else if (0 != cmd->u.cache_rep.rnas.cr_status) {
        rna_printk(KERN_ERR,
                   "Error [%s] from CS ["NIPQUAD_FMT"] for master block on device [%s]\n",
                   get_cache_resp_code(cmd->u.cache_rep.rnas.cr_status),
                   NIPQUAD(dst_in.sin_addr.s_addr),
                   dev->name );     
        rna_block_mutex_lock(&conn->block_list_lock, &mutex_lock_handle);
        rnablk_lock_blk_irqsave(blk, irqflags);
        if (!rnablk_cache_blk_state_transition(blk,
                                        RNABLK_CACHE_BLK_CONNECT_PENDING,
                                        RNABLK_CACHE_BLK_DISCONNECTED)) {
            rna_printk(KERN_ERR, "failed to restore MASTER blk state, "
                       "cur state [%s]\n",
                       rnablk_cache_blk_state_string(blk->state));
        }
        rnablk_unset_blk_ep(blk);
        rnablk_unlock_blk_irqrestore(blk, irqflags);
        rna_block_mutex_unlock(&conn->block_list_lock, &mutex_lock_handle);
        atomic_set(&dev->stats.status, RNABLK_CACHE_OFFLINE);
    } else if (0 != atomic_read(&shutdown) ||
               rnablk_dev_is_shutdown(dev)) {
        rna_printk(KERN_ERR,
                   "Shutdown in progress, not registering master block on "
                   "device [%s]\n", dev->name );
        atomic_set(&dev->stats.status, RNABLK_CACHE_OFFLINE);
    } else {
#define RRS_VALID_MSLEEP_TIME   100                              // 100 mS
#define MAX_RRS_VALID_RETRIES   ((3*MSEC_PER_SEC)/RRS_VALID_MSLEEP_TIME)
                                                                 // ~3 seconds
        /*
         * XXXcorene - A temporary solution to making sure we process
         * the CACHE_RSV_ACCESS message before we finish the LOCK_MASTER_BLK.
         * (The CS always sends the CACHE_RSV_ACCESS before sending this
         * response, so we're just guarding against the race where they're
         * both being processed in parallel.)
         */
        int n_retry;
        for (n_retry = 0; n_retry < MAX_RRS_VALID_RETRIES; n_retry++) {
            if (dev->rbd_rsv.rrs_is_valid) {
                break;
            }
            msleep_interruptible(RRS_VALID_MSLEEP_TIME);
        }

        RNABLK_DBG_BUG_ON(!dev->rbd_rsv.rrs_is_valid,
                          "dev [%s] received LOCK_MASTER_BLOCK response "
                          " from CS ["NIPQUAD_FMT"] but haven't received "
                          "reservation access info\n",
                          dev->name, NIPQUAD(dst_in.sin_addr.s_addr));
        rna_printk(KERN_NOTICE,
                   "Locked masterblock for [%s] with device "
                   "master_block_id [%"PRIu64"] on CS ["NIPQUAD_FMT"] "
                   "rsv_valid [%d]\n",
                   dev->name, dev->dv_master_block_id,
                   NIPQUAD(dst_in.sin_addr.s_addr),
                   dev->rbd_rsv.rrs_is_valid);

        /* We now have a reference on the masterblock */
#ifdef WINDOWS_KERNEL
        rna_down_read(&pHBAExt->hba_rnablk_dev_list_lock, &oldirql);
#else
        rna_down_read( &rnablk_dev_list_lock, &oldirql );
#endif
        atomic_set(&blk->retries, 0);
        blk->rid = cmd->u.cache_rep.rnas.cr_cache_cookie;
        rnablk_trc_master(1, "set rid=%llu\n", blk->rid);
        new_cap = cmd->u.cache_rep.rnas.cr_file_size;
        if (dev_is_persistent(dev)) {
            if (new_cap != dev->device_cap) {
                /* This is where the actual size of a persistent block
                   device is discovered.  We get the size in bytes, and
                   convert it to the capacity in megabytes */
                rna_printk(KERN_ERR,
                           "Persistent device [%s] capacity is [%"PRIu64"] "
                           "(was [%"PRIu64"])\n",
                           dev->name,
                           new_cap,
                           dev->device_cap);
                dev->device_cap = new_cap;

                rnablk_register_dev_with_cfm(dev);
            }
        }
        rnablk_cs_query_blk_transition(blk,
                            (cache_lock_t)cmd->u.cache_rep.rnas.cr_ref_type,
                            (cache_lock_t)cmd->u.cache_rep.rnas.cr_orig_ref_type);
        atomic_bit_set(&dev->rbd_io_allowed, RBD_FIO_MASTER_LOCKED);

        atomic_set(&dev->stats.status, RNABLK_CACHE_ONLINE);
        if (atomic_read(&dev->registered_with_os)) {
            /*
             * We're reconnecting to a failed master bock.
             * Finish this ios before queuing the restart to avoid the
             * (extremely slim!) possibility of a race where a new LOCK_MASTER
             * could get dropped because this one is still "in-progress" and
             * we could wind up wedged with ios' waiting on the blk->bl queue.
             */
            rnablk_ios_finish(ios);
            ios = NULL;     // clear to avoid finishing again below
            if (dev_io_allowed(dev)) {
                rna_printk(KERN_NOTICE, "restarting block queue for "
                           "device [%s]\n", dev->name);
                rnablk_queue_restart_dev_blks(dev);
            } else {
                rna_printk(KERN_NOTICE, "not restarting block queue for "
                           "device [%s], i/o currently prohibited\n",
                           dev->name);
            }
        } else if (0 != dev->device_cap) {
            do_register = TRUE;
        }
#ifdef WINDOWS_KERNEL
        rna_up_read(&pHBAExt->hba_rnablk_dev_list_lock, oldirql);
#else
        rna_up_read( &rnablk_dev_list_lock, oldirql );
#endif

        /* ios may be NULL now, so don't try to use it! */

        if( do_register ) {
            rnablk_trc_master(1, "registering for first time\n");
            rnablk_deferred_register_block_device(dev);
        } else {
            rnablk_trc_master(1, "already registered\n");
            TRACE(DBG_FLAG_VERBOSE,
                  "not registering device [%s] dev->registered_with_os "
                  "[%d] device_cap [%"PRIu64"]\n",
                  dev->name,
                  atomic_read(&dev->registered_with_os),
                  dev->device_cap);
        }
    }

    if (NULL != ios) {
        rnablk_ios_finish(ios);
    }
    rnablk_trc_master(1, "done: st=%s l=%s\n",
                      rnablk_cache_blk_state_string(blk->state),
                      get_lock_type_string(blk->ref_type));
    EXITV;
}

// runs in kthread context
//
// Handles CACHE_RESPONSE, which makes blocks valid, supplies
// RDMA info, and moves references from none towards write.
static void 
rnablk_process_cache_response(struct com_ep *ep, struct io_state *ios, void *data)
{
    struct cache_cmd *cmd = (struct cache_cmd *)data;
    ENTERV;

    rnablk_trace_ios(ios);

    TRACE(DBG_FLAG_VERBOSE,
          "cache response of type [%s] status [%s] for device [%s] ios [%p] "
          "tag ["TAGFMT"]\n",
          get_cache_req_type_string(cmd->u.cache_rep.rnas.cr_cache_type),
          get_cache_resp_code(cmd->u.cache_rep.rnas.cr_status),
          ios->dev->name,
          ios, TAGFMTARGS(ios->tag));

    switch(cmd->u.cache_rep.rnas.cr_cache_type) {
    case CACHE_REQ_TYPE_BLOCK:
        rnablk_process_cache_block_response(ep, ios, data);
        break;
    case CACHE_REQ_TYPE_MASTER:
        rnablk_process_cache_master_block_response(ep, ios, data);
        break;
    default:
        rna_printk(KERN_ERR, "IGNORING cache response of type [%s] for device [%s]\n", 
                   get_cache_req_type_string(cmd->u.cache_rep.rnas.cr_cache_type), ios->dev->name);
        // free the io state for this request
        rnablk_ios_finish(ios);
    }
    EXITV;
}

//
// May run in kthread context, or else in a workqueue context.
//
INLINE void
rnablk_process_change_ref_response_internal(struct com_ep *ep,
                                            struct io_state *ios,
                                            uint8_t status,
                                            uint8_t new_ref_type,
                                            uint8_t old_ref_type)
{
    struct cache_blk *blk = ios->blk;
    struct rnablk_server_conn *conn;
    boolean io_queued = FALSE;
    lockstate_t irqflags;
    boolean need_invalidate = FALSE;
    long max_retries;
    long retry_delay_ms;
    rnablk_cache_blk_state_t state;
    struct sockaddr_in dst_in;
    mutexstate_t mutex_lock_handle;

    conn = (struct rnablk_server_conn *)(com_get_ep_context(ep));

    rnablk_lock_blk_irqsave(blk, irqflags);

    if (TRUE == atomic_cmpxchg(&blk->cb_write_reference_pending, TRUE, FALSE)) {
        /*
         * this was a proactive write reference release,
         * decrement counter for cache server.
         */
        atomic_dec(&conn->rsc_outstanding_write_releases);
        rna_printk(KERN_DEBUG, "downgraded block [%llu] [%d/%d]\n",
                   blk->block_number,
                   atomic_read(&conn->rsc_outstanding_write_releases),
                   rnablk_write_reference_release_max_outstanding);
    }

 recheck_state:
    state = blk->state;

    switch (state) {
    case RNABLK_CACHE_BLK_CHANGE_PENDING:
        break;              // normal/expected state.  all is well.

    case RNABLK_CACHE_BLK_DISCONN_PENDING:
        if ((0 == status
             && CACHE_NO_REFERENCE != new_ref_type)
            || (0 != status && CACHE_NO_REFERENCE != blk->ref_type)) {
            /*
             * We dropped the reference while this CHANGE_REF was
             * in-progress. This could happen due to shutdown (from
             * rnablk_deref_cache_blks()), etc.
             * Queue I/O for later.
             */
            rnablk_queue_blk_io_nolock(blk, ios, QUEUE_HEAD);
            rnablk_unlock_blk_irqrestore(blk, irqflags);
            return;
        }
        /* otherwise, this is the normal/expected state. */
        break;

    case RNABLK_CACHE_BLK_INVALID:
        rna_printk(KERN_INFO, "ignoring ios [%p] tag ["TAGFMT"] type [%s] "
                   "for [%s] block [%"PRIu64"] in state [%s]\n",
                   ios, TAGFMTARGS(ios->tag), rnablk_op_type_string(ios->type),
                   blk->dev->name, blk->block_number,
                   rnablk_cache_blk_state_string(blk->state));
        rnablk_unlock_blk_irqrestore(blk, irqflags);
        rnablk_end_request(ios, -EIO);
        return;

    case RNABLK_CACHE_BLK_INVALIDATE_PENDING:
        if (0 == status) {
            state = (CACHE_NO_REFERENCE == new_ref_type)
                     ? RNABLK_CACHE_BLK_DISCONN_PENDING
                     : RNABLK_CACHE_BLK_CHANGE_PENDING;
            rnablk_cache_blk_state_set(blk, state);
            need_invalidate = TRUE;
        } else {
            rnablk_queue_blk_io_nolock(blk, ios, QUEUE_HEAD);
            if (!rnablk_blk_has_dispatched_io(blk)) {
                rnablk_queue_deref(blk, FALSE);
            }
            rnablk_unlock_blk_irqrestore(blk, irqflags);
            return;
        }
        break;

    case RNABLK_CACHE_BLK_DISCONNECTED:
        /* Put I/O in queue so it can be re-started "from scratch" */
        rnablk_queue_blk_io_nolock(blk, ios, QUEUE_HEAD);
        rnablk_unlock_blk_irqrestore(blk, irqflags);
        rnablk_cache_blk_drain(blk);
        return;
        
    default:
        RNABLK_BUG_ON(TRUE, "ios [%p] tag ["TAGFMT"] block [%llu] in "
                      "unexpected state [%s] for CHANGE_REF response\n",
                      ios, TAGFMTARGS(ios->tag), blk->block_number,
                      rnablk_cache_blk_state_string(blk->state));
    }

    rnablk_unlock_blk_irqrestore(blk, irqflags);

    if (unlikely(CACHE_RESP_CODE_EAGAIN == status
                 || CACHE_RESP_CODE_OFFLINE == status
                 || (0 != status && !dev_is_persistent(ios->dev)))) {
        retry_delay_ms = CACHE_RESP_CODE_EAGAIN == status
                         ? RNABLK_EAGAIN_DELAY_MS : RNABLK_OFFLINE_DELAY_MS;
        max_retries = (rnablk_io_timeout * MSEC_PER_SEC) / retry_delay_ms;

        /* restore original blk state */
        rna_block_mutex_lock(&conn->block_list_lock, &mutex_lock_handle);
        rnablk_lock_blk_irqsave(blk, irqflags);
        if (blk->state != state) {  // state changed out from under us
            rna_block_mutex_unlock(&conn->block_list_lock, &mutex_lock_handle);
            goto recheck_state;
        }
        RNABLK_BUG_ON(!rnablk_cs_change_req_blk_transition(conn, blk,
                                                           blk->ref_type),
                      "failed state transition blk=%p [%llu] state [%s] "
                      "ios [%p]\n", blk, blk->block_number,
                      rnablk_cache_blk_state_string(blk->state), ios);
        rnablk_unlock_blk_irqrestore(blk, irqflags);
        rna_block_mutex_unlock(&conn->block_list_lock, &mutex_lock_handle);

        if (atomic_read(&blk->retries) < max_retries) {

            if (0 == atomic_read(&blk->retries)) {
                /* avoid on-going message spew; only log once (per episode) */
                rna_printk(KERN_INFO, "Error [%s] for [%s] ios [%p] tag "
                           "["TAGFMT"] block [%llu] transition from [%s] to "
                           "[%s], retrying\n",
                           get_cache_resp_code(status),
                           ios->dev->name, ios, TAGFMTARGS(ios->tag),
                           blk->block_number,
                           get_lock_type_string(old_ref_type),
                           get_lock_type_string(new_ref_type));
            }
            atomic_inc(&blk->retries);
            rnablk_retrack_ios(ios);
            rnablk_queue_delayed_request(ios, retry_delay_ms);
        } else {
            dst_in = get_dest_sockaddr_from_ep(ep);
            rna_printk(KERN_ERR, "Error [%s] from CS ["NIPQUAD_FMT"] for "
                       "change_ref of block [%llu] on device [%s] state [%s] "
                       "transition from ref [%s] to [%s], failing after %d "
                       "retries\n",
                       get_cache_resp_code(status),
                       NIPQUAD(dst_in.sin_addr.s_addr),
                       blk->block_number, ios->dev->name,
                       rnablk_cache_blk_state_string(blk->state),
                       get_lock_type_string(old_ref_type),
                       get_lock_type_string(new_ref_type),
                       atomic_read(&blk->retries));

            /* this will drop the conn reference on the blk */
            rnablk_mark_cache_blk_bad_and_drain(blk, FALSE);
            rnablk_end_request(ios, -EIO);
        } 
    } else if (unlikely(0 != status)) {
        dst_in = get_dest_sockaddr_from_ep(ep);
        rna_printk(KERN_ERR, "Error [%s] from CS ["NIPQUAD_FMT"] for "
                   "change_ref of block [%llu] on device [%s]\n",
                   get_cache_resp_code(status),
                   NIPQUAD(dst_in.sin_addr.s_addr),
                   blk->block_number,
                   ios->dev->name );

        /* restore original blk state */
        rna_block_mutex_lock(&conn->block_list_lock, &mutex_lock_handle);
        rnablk_lock_blk_irqsave(blk, irqflags);
        if (blk->state != state) {      // state changed out from under us
            rna_block_mutex_unlock(&conn->block_list_lock, &mutex_lock_handle);
            goto recheck_state;
        }
        RNABLK_BUG_ON(!rnablk_cs_change_req_blk_transition(conn, blk,
                      blk->ref_type),
                      "failed state transition blk=%p [%llu] state [%s] "
                      "ios [%p]\n", blk, blk->block_number,
                      rnablk_cache_blk_state_string(blk->state), ios);
        rnablk_unlock_blk_irqrestore(blk, irqflags);
        rna_block_mutex_unlock(&conn->block_list_lock, &mutex_lock_handle);
        /* this will drop the conn reference on the blk */
        rnablk_mark_cache_blk_bad_and_drain(blk, FALSE);
        rnablk_end_request(ios, -EIO);
    } else {        /* status == SUCCESS */
        TRACE(DBG_FLAG_VERBOSE,
              "block [%llu] transition from ref [%s] to [%s] for device "
              "[%s] status [%s]\n",
              blk->block_number,
              get_lock_type_string(old_ref_type),
              get_lock_type_string(new_ref_type),
              ios->dev->name,
              get_cache_resp_code(status));

        rna_block_mutex_lock(&conn->block_list_lock, &mutex_lock_handle);
        rnablk_lock_blk_irqsave(blk, irqflags);
        if (blk->state != state) {
            rna_block_mutex_unlock(&conn->block_list_lock, &mutex_lock_handle);
            goto recheck_state;
        }
        RNABLK_BUG_ON(!rnablk_cs_change_req_blk_transition(conn, blk,
                      new_ref_type),
                      "block [%llu] bad assumption state [%s] ios [%p] "
                      "tag ["TAGFMT"]\n", blk->block_number,
                      rnablk_cache_blk_state_string(blk->state), ios,
                      TAGFMTARGS(ios->tag));

        if (0 != atomic_read(&blk->retries)) {
            /*
             * if we previously had to retry this ios, log that we finally
             * succeeded with it!
             */
            rna_printk(KERN_INFO, "ios [%p] tag ["TAGFMT"] block [%llu] "
                       "transition " "SUCCESS from ref [%s] to [%s] for "
                       "device [%s] status [%s], after %d retries\n",
                       ios, TAGFMTARGS(ios->tag), blk->block_number,
                       get_lock_type_string(old_ref_type),
                       get_lock_type_string(new_ref_type),
                       ios->dev->name, get_cache_resp_code(status),
                       atomic_read(&blk->retries));
            atomic_set(&blk->retries, 0);
        }

        RNABLK_BUG_ON(IS_MASTER_BLK(blk), "Master blk not expected here! "
                      "ios [%p] type [%s] oldref [%s] newref [%s] for "
                      "device [%s] status [%s]\n", ios,
                      rnablk_op_type_string(ios->type),
                       get_lock_type_string(old_ref_type),
                       get_lock_type_string(new_ref_type),
                       ios->dev->name, get_cache_resp_code(status));

        rnablk_cache_blk_update_dev_counts(blk);
        RNABLK_BUG_ON(IOS_HAS_IOREQ(ios)
                      && blk->state == RNABLK_CACHE_BLK_DISCONNECTED,
                      "ios w/request set blk state to disconnected "
                      "ios [%p] tag ["TAGFMT"] block [%llu]\n", ios,
                      TAGFMTARGS(ios->tag), blk->block_number);
        if (IOS_HAS_IOREQ(ios)) {
            if (need_invalidate) {
                rnablk_queue_blk_io_nolock(blk, ios, QUEUE_HEAD);
            } else {
                /* 
                 * If there is an I/O request associated with this ios,
                 * blk is now in the right state to perform the I/O...
                 */
                rnablk_retrack_ios(ios);
                queue_io_request(ios, blk, FORCE_QUEUED_IO);
            }
            io_queued = TRUE;   // either way ios was queued...
        }
        
        if (need_invalidate && !rnablk_blk_has_dispatched_io(blk)) {
            RNABLK_BUG_ON(!rnablk_cache_blk_state_transition(blk,
                          blk->state, RNABLK_CACHE_BLK_INVALIDATE_PENDING),
                          "blk=%p [%llu] unexpected state [%s] ios [%p]\n",
                          blk, blk->block_number,
                          rnablk_cache_blk_state_string(blk->state), ios);
            rnablk_queue_deref(blk, FALSE);
        }

        rnablk_unlock_blk_irqrestore(blk, irqflags);
        rna_block_mutex_unlock(&conn->block_list_lock, &mutex_lock_handle);

        dst_in = get_dest_sockaddr_from_ep(ep);
        // Change ref operations end here
        TRACE(DBG_FLAG_VERBOSE, "device [%s] block [%llu] change_ref ios [%p] "
              "tag ["TAGFMT"] from CS ["NIPQUAD_FMT"] complete\n",
              ios->dev->name, blk->block_number, ios, TAGFMTARGS(ios->tag),
              NIPQUAD(dst_in.sin_addr.s_addr));

        if (!io_queued) {
            /* if the ios wasn't queued for I/O, we can release it now */
            rnablk_end_request(ios, 0);
        }
        if (!need_invalidate) {
            rnablk_cache_blk_drain(blk);
        }
    }

    /* 'conn' may be different after queue_io_request, so reset it */
    if (NULL != (conn = rnablk_get_ios_conn(ios))) {
        rnablk_schedule_conn_dispatch(conn);
    }
}

//
// runs in kthread context
//
// Handles CACHE_CHANGE_REF_RESP, which may not have an associated
// block-layer request.
static void
rnablk_process_change_ref_response(struct com_ep *ep,
                                   struct io_state *ios, 
                                   void *data)
{
    struct cache_cmd *cmd = (struct cache_cmd *)data;
    struct rnablk_server_conn *conn = NULL;
    struct cache_blk *blk = ios->blk;

    rnablk_trace_ios(ios);

    conn = (struct rnablk_server_conn *)(com_get_ep_context(ep));
    rnablk_save_cmd_latency(ios, cmd);

    rnablk_cache_blk_ref(blk);
    rnablk_process_change_ref_response_internal(ep, ios,
                               cmd->u.cache_change_ref_resp.status,
                               cmd->u.cache_change_ref_resp.new_ref_type,
                               cmd->u.cache_change_ref_resp.old_ref_type);
    rnablk_cache_blk_release(blk);
}

int
rnablk_send_deref_complete(struct com_ep *ep,
                           uint32_t       requested_bytes,
                           uint32_t       derefed_bytes)
{
    struct io_state *ios = NULL;
    struct sockaddr_in dst_in;
    ENTER;

    rnablk_trc_master(1, "start\n");
    BUG_ON(NULL == ep);

    ret = rnablk_alloc_ios_admin(&null_device, ios);
    if (likely(0 == ret)) {
        rnablk_set_ios_blk(ios, MASTER_BLK(&null_device));
        rnablk_set_ios_ep(ios, ep);
        ios->type = RNABLK_DEREF_REQUEST_RESP;
        
        dst_in = get_dest_sockaddr_from_ep(ep);
        rna_printk(KERN_INFO,
                   "sending deref request response to CS ["NIPQUAD_FMT"] "
                   "requested_bytes [%u] derefed_bytes [%u]\n",
                   NIPQUAD(dst_in.sin_addr.s_addr),
                   requested_bytes,
                   derefed_bytes);
        ios->cmd->h.h_type   = CACHE_DEREF_REQUEST_RESP;
        ios->cmd->h.h_error  = 0;
        /* might want to associate responses with requests. see coment above */
        ios->cmd->h.h_cookie = 0;

        ios->cmd->u.cache_deref_req_resp.requested_bytes = requested_bytes;
        ios->cmd->u.cache_deref_req_resp.derefed_bytes = derefed_bytes;

        if (likely(0 == (ret = queue_command(ios)))) {
            rnablk_schedule_conn_dispatch((struct rnablk_server_conn *)com_get_ep_context(ep));
        } else {
            rnablk_ios_finish(ios);
        }
    }

    rnablk_trc_master(1, "done - ret=%d\n", ret);
    EXIT;
}

void
rnablk_process_cache_invd(struct com_ep    *ep,
                          struct cache_cmd *cmd,
                          boolean is_from_sysfs)
{
    int ret = 0;
    struct rnablk_device *dev = NULL;
    struct cache_blk *blk = NULL;
    struct cache_invd * invd = NULL;
    sector_t start_sector;
    lockstate_t flags;
    struct rnablk_server_conn *conn = NULL;
    unsigned char oldirql = 0;

#ifdef WINDOWS_KERNEL
    pHW_HBA_EXT pHBAExt;
#endif

    BUG_ON(NULL == ep);
    BUG_ON(NULL == cmd);
    invd = &cmd->u.cache_invd;

    rna_printk(KERN_DEBUG,
               "Got cache invalidate for [%s] block [%"PRId64"]\n",
               invd->rnas.cis_pathname,
               invd->rnas.cis_block_num);

#ifdef WINDOWS_KERNEL
    pHBAExt = hbaext_from_com_ep(ep);
    rna_down_read(&pHBAExt->hba_rnablk_dev_list_lock, &oldirql);
    dev = rnablk_find_device_by_path_nolock(invd->rnas.cis_pathname, pHBAExt);
#else
    rna_down_read( &rnablk_dev_list_lock, &oldirql );
    dev = rnablk_find_device_by_path_nolock(invd->rnas.cis_pathname);
#endif

    if (unlikely(NULL == dev)) {
        rna_printk(KERN_ERR,
                   "could not find dev for cache path [%s]\n",
                   invd->rnas.cis_pathname);
        ret = -EINVAL;
    } else if (unlikely(-1 == invd->rnas.cis_block_num)) {
        rna_printk(KERN_ERR,
                   "Got master block invalidate for device [%s]\n",
                   invd->rnas.cis_pathname);
        /* The caller must schedule the dispatch of the command queued below */
        if (0 == rnablk_send_master_change_ref(dev, NULL,
                                               RNABLK_MASTER_DEREF_NORESP,
                                               CACHE_NO_REFERENCE)) {
            rnablk_start_blk_io(MASTER_BLK(dev), FALSE);
        }

        rnablk_queue_delayed_master_blk_lock(dev);
    } else {
        start_sector = (invd->rnas.cis_block_num * dev->cache_blk_size) / RNABLK_SECTOR_SIZE;
        // Takes a ref on the block
        blk = rnablk_cache_blk_get(dev, start_sector);

        if (unlikely(NULL == blk)) {
            rna_printk(KERN_ERR,
                       "could not find block for cache path [%s] block [%"PRId64"]\n",
                       invd->rnas.cis_pathname,
                       invd->rnas.cis_block_num);
            ret = -EINVAL;
        } else if (unlikely(blk->block_number != invd->rnas.cis_block_num)) {
            rna_printk(KERN_ERR,
                       "got wrong block number [%"PRId64"] for cache path [%s] block [%"PRId64"]\n",
                       blk->block_number,
                       invd->rnas.cis_pathname,
                       invd->rnas.cis_block_num);
            ret = -EINVAL;
        } else {
            if (unlikely(net_link_mask & RNABLK_NL_BLK_STATE)) {
                conn = rnablk_get_ep_conn(ep);

                printnl_atomic("[%d] [%s] invalidate from CS "
                               "["rna_service_id_format"] for block [%llu] on "
                               "device [%s] state [%s] server has ref [%s] status[%s]\n",
                               current->pid,
                               __FUNCTION__,
                               rna_service_id_get_string(&conn->id),
                               blk->block_number,
                               blk->dev->name,
                               rnablk_cache_blk_state_string(blk->state),
                               get_lock_type_string(cmd->u.cache_rep.rnas.cr_ref_type),
                               get_cache_resp_code(cmd->u.cache_rep.rnas.cr_status));
            }

            rnablk_lock_blk_irqsave(blk, flags);
            if (unlikely(rnablk_blk_disconnected(blk))) {
                rna_printk(KERN_INFO,
                           "ignoring [%s] block [%"PRId64"] in state [%s]\n",
                           dev->name,
                           blk->block_number,
                           rnablk_cache_blk_state_string(blk->state));
            } else if (unlikely(is_from_sysfs
                       && (rnablk_cache_blk_state_is_invalidate_pending(
                          blk->state) ||
                          !rnablk_cache_blk_state_is_connected(blk->state)))) {
                rna_printk(KERN_NOTICE,
                           "Ignoring INVD of [%s] block [%"PRId64"] in state "
                           "[%s] injected via sysfs\n",
                           dev->name, blk->block_number,
                           rnablk_cache_blk_state_string(blk->state));
            } else if (likely(!rnablk_blk_has_dispatched_io(blk))) {
                rnablk_cache_blk_state_set(blk,
                                           RNABLK_CACHE_BLK_INVALIDATE_PENDING);
                /* queue to avoid blocking on IOS allocation and send buffers */
                rnablk_queue_deref(blk, FALSE);
            } else if (unlikely
                       (!rnablk_cache_blk_state_is_connected(blk->state) &&
                        !rnablk_cache_blk_state_is_queryable(blk->state))) {
                rna_printk(KERN_ERR,
                           "[%s] block [%"PRId64"] in unexpected state [%s]\n",
                           dev->name,
                           blk->block_number,
                           rnablk_cache_blk_state_string(blk->state));
                BUG_ON(TRUE);
            } else {
                rna_printk(KERN_INFO,
                           "[%s] block [%"PRIu64"] state [%s] refcnt "
                           "["BLKCNTFMT"] inflight_ios [%d] dispq "
                           "[%s] blq [%s]\n", dev->name, blk->block_number,
                           rnablk_cache_blk_state_string(blk->state),
                           BLKCNTFMTARGS(blk),
                           atomic_read(&blk->inflight_ios),
                           list_empty(&blk->dispatch_queue) ?
                           "EMPTY" : "NOT EMPTY", list_empty(&blk->bl) ?
                           "EMPTY" : "NOT EMPTY");
                rnablk_cache_blk_state_set(blk,
                                           RNABLK_CACHE_BLK_INVALIDATE_PENDING);
            }
            rnablk_unlock_blk_irqrestore(blk, flags);
        }
        if (likely(NULL != blk)) {
            // ref from rnablk_cache_blk_get()
            rnablk_cache_blk_release(blk);
        }
    }

#ifdef WINDOWS_KERNEL
    rna_up_read(&pHBAExt->hba_rnablk_dev_list_lock, oldirql);
#else
    rna_up_read( &rnablk_dev_list_lock, oldirql );
#endif

    if (NULL != dev) {
        rnablk_dev_release(dev);
    }
}

static void
rnablk_process_cache_rsv_access(struct com_ep    *ep,
                                struct cache_cmd *cmd)
{
    struct rnablk_device *dev = NULL;
    rsv_access_t new_client_access;
    boolean do_quiesce;
    boolean is_reserve;
    boolean found_self = FALSE;
    boolean restart_dev_io = TRUE;
    unsigned long irqflags;
    struct sockaddr_in dst_in;
    uint8_t n_itns;
    uint8_t other_access;
    uint8_t need_response;
    uint32_t generation;
    rsv_itn_id_t *itn_list;
    char *pathname;
    int i;
#ifdef WINDOWS_KERNEL
    pHW_HBA_EXT pHBAExt;
#endif

    if (CACHE_RSV_ACCESS == cmd->h.h_type) {
        n_itns = cmd->u.cache_rsv_access.cra_n_itns;
        other_access = cmd->u.cache_rsv_access.cra_other_access;
        need_response = cmd->u.cache_rsv_access.cra_need_response;
        generation = cmd->u.cache_rsv_access.cra_generation;
        itn_list = cmd->u.cache_rsv_access.cra_itn_list;
        pathname = cmd->u.cache_rsv_access.cra_pathname;
    } else {    // CACHE_RSV_ACCESS_V18
        n_itns = cmd->u.cache_rsv_access_v18.cra_n_itns;
        other_access = cmd->u.cache_rsv_access_v18.cra_other_access;
        need_response = cmd->u.cache_rsv_access_v18.cra_need_response;
        itn_list = cmd->u.cache_rsv_access_v18.cra_itn_list;
        pathname = cmd->u.cache_rsv_access_v18.cra_pathname;
        generation = 0;     // will be modified below
    }

#ifdef WINDOWS_KERNEL
    pHBAExt = hbaext_from_com_ep(ep);
    dev = rnablk_find_device_by_path(pathname, pHBAExt);
#else
    dev = rnablk_find_device_by_path(pathname);
#endif /*WINDOWS_KERNEL*/    
    
    if (NULL == dev) {
        rna_printk(KERN_ERR, "RSV_ACCESS [%s] request for unknown "
                   "device [%s]\n", rsv_access_string(other_access), pathname);
        return;
    }

    if (0 == generation) {
        /*
         * Old-style CACHE_RSV_ACCESS_V18 didn't have a generation #.
         * Instead block client managed its own.
         * (CS is guaranteed to never send a gen# of 0, so this test works).
         */
        generation = dev->rbd_rsv.rrs_generation + 1;
    }

    /*
     * Set 'is_reserve' to TRUE if this RSV_ACCESS message is directly
     * associated with an active RESERVE operation.  The alternative is
     * that it was sent in association with a LOCK_MASTER response and
     * we need to do some different handling depending on which it is.
     * [Note we are deriving this information from the fact that currently
     * cra_need_response is always set for RESERVE operations and not set
     * for the LOCK_MASTER case!]
     */
    is_reserve = (need_response != 0);

    dst_in = get_dest_sockaddr_from_ep(ep);
    rna_printk(KERN_RSV, "Got RSV_ACCESS%s for device [%s] from "
               "CS ["NIPQUAD_FMT"]: oaccess [%s] nitns [%d] gen [%u] "
               "resp [%d] \n",
               CACHE_RSV_ACCESS == cmd->h.h_type ? "" : "_V18",
               dev->name, NIPQUAD(dst_in.sin_addr.s_addr),
               rsv_access_string(other_access), n_itns, generation,
               need_response);

    rna_spin_lock_irqsave(dev->rbd_event_lock, irqflags);
    dev->rbd_rsv.rrs_is_valid = TRUE;
    dev->rbd_rsv.rrs_generation = generation;

    for (i = 0; i < n_itns; i++) {
        if (match_itn_id(&rnablk_itn_id, &itn_list[i])) {
            RNABLK_BUG_ON(found_self, "dev [%s] client itn found in list "
                          "more than once\n", dev->name);
            found_self = TRUE;
        } else {
            dev->rbd_rsv.rrs_itn_list[i] = itn_list[i];
        }
    }
    dev->rbd_rsv.rrs_n_itns = i;
    dev->rbd_rsv.rrs_other_access = other_access;
    new_client_access = found_self ? RSV_ACC_READWRITE
                                   : dev->rbd_rsv.rrs_other_access;
    do_quiesce = rsv_access_is_less(new_client_access, RSV_ACC_READWRITE);
    rna_printk(KERN_RSV, "client_access %schanging: found=%d quiesce=%d "
               "new=%s cur=%s\n",
               new_client_access == dev->rbd_rsv.rrs_client_access
               ? "NOT " : "", found_self, do_quiesce,
               rsv_access_string(new_client_access),
               rsv_access_string(dev->rbd_rsv.rrs_client_access));
    dev->rbd_rsv.rrs_client_access = new_client_access;

    if (RSV_ACK_NEED_CS == dev->rbd_rsv.rrs_ack_needed) {
        if (is_reserve) {
            rna_printk(KERN_ERR, "Received access-change-notification for "
                       "dev [%s] while waiting for external access-change-ack, "
                       "failing device\n", dev->name);
            rnablk_device_fail(dev);
        } else if (!do_quiesce) {
            /* Reset client "quiescing" state (in case it's active) */
            atomic_set(&dev->rbd_rsv.rrs_wait, FALSE);
        }
    }

    if (is_reserve) {
        dev->rbd_rsv.rrs_ack_needed = RSV_ACK_NEED_CS;
    } else if (rnablk_controls_access(dev) || !do_quiesce) {
        dev->rbd_rsv.rrs_ack_needed = RSV_ACK_NEED_NONE;
    } else {
        /*
         * This is the case where tgt controls access, we're reducing
         * access, and this is a LOCK_MASTER rather than a RESERVE.
         * For this case, I/O on the device is disallowed until we receive
         * the acknowledgement from tgtd that it has processed our
         * reservation access change event.
         */ 
        dev->rbd_rsv.rrs_ack_needed = RSV_ACK_NEED_CLIENT;
        atomic_bit_set(&dev->rbd_io_allowed, RBD_FIO_NEED_RSV_ACK);
        restart_dev_io = FALSE;
    }

    /*
     * Clear RBD_FIO_NEED_RSV_ACK if our new 'rrs_ack_needed' is not
     * RSV_ACK_NEED_CLIENT, and then determine here if we need to restart
     * I/O for the device.
     * (We need to restart if RBD_FIO_NEED_RSV_ACK was previously set and
     * I/O is now allowed on the device).
     */
    if (restart_dev_io
        && (!atomic_bit_test_and_clear(&dev->rbd_io_allowed,
                                       RBD_FIO_NEED_RSV_ACK)
            || !dev_io_allowed(dev))) {
        restart_dev_io = FALSE;
    }

    wake_up_all(&dev->rbd_event_wait);
    rna_spin_unlock_irqrestore(dev->rbd_event_lock, irqflags);

    if (is_reserve && rnablk_controls_access(dev)) {
        rnablk_do_rsv_access_resp(dev, do_quiesce, generation, TRUE);
    }

    if (restart_dev_io) {
        rna_printk(KERN_NOTICE, "restarting block queue for device [%s]\n",
                   dev->name);
        rnablk_queue_restart_dev_blks(dev);
    }

    rnablk_dev_release(dev);
}

static void 
process_write_same_response(struct com_ep *ep, struct io_state *ios, 
                            struct cache_cmd *cmd)
{
    struct cache_write_same_resp *resp = &cmd->u.cache_write_same_resp;
    struct cache_blk *blk = ios->blk;

    RNABLK_BUG_ON(CACHE_WRITE_SAME_RESP != cmd->h.h_type,
                  "ios [%p] unexpected cmd type %d\n", ios, cmd->h.h_type);

    rnablk_dec_inflight_ios(blk);

    /* add a reference to blk so we can queue the deref if appropriate */
    rnablk_cache_blk_ref(blk);
    if (process_common_special_response(ep, ios, resp->wsr_status)
        && ios->nr_sectors >= ios->dev->rbd_large_write_sects) {
        /*
         * If the ios was completed, then try to deref the associated
         * cache blk; don't want to leave it around taking up space in
         * the cache when it isn't likely to be accessed again.
         */
        rnablk_queue_deref(blk, TRUE);
    }
    rnablk_cache_blk_release(blk);
}

static void
process_comp_and_write_response(struct com_ep *ep, struct io_state *ios,
                                struct cache_cmd *cmd)
{
    struct cache_comp_and_write_req *req = &ios->cmd->u.cache_comp_wr_req;
    struct cache_comp_and_write_resp *resp = &cmd->u.cache_comp_wr_resp;
    struct cache_blk *blk = ios->blk;

    BUG_ON(CACHE_COMP_WR_RESP != cmd->h.h_type);

    memcpy(&req->cw_resp, resp, sizeof(*resp));
    rnablk_dec_inflight_ios(blk);

    process_common_special_response(ep, ios, resp->cwr_status);
}

static void
process_scsi_passthru_response(struct com_ep *ep, struct io_state *ios,
                               struct cache_cmd *cmd)
{
    struct cache_scsi_passthru *cs = &ios->cmd->u.cache_scsi_passthru;
    struct cache_scsi_passthru_resp *sr = &cmd->u.cache_scsi_passthru_resp;

    if (CACHE_RESP_CODE_OK == sr->cs_status) {
        /*
         * Only overwrite our 'response' buffer if the CS returned
         * a success reponse_code.  Otherwise, we may need to retry the
         * command, and since our "write" data is stored in the sr->data
         * buffer, the * retry won't go too well if we clobber it!
         */
        memcpy(&cs->response, sr, sizeof(*sr));
    }
    process_common_special_response(ep, ios, sr->cs_status);
}

static void
rnablk_process_scsi_unitattn(struct com_ep    *ep,
                             struct cache_cmd *cmd)
{
    struct rnablk_device *dev;
    struct cache_scsi_unitattn *uap;
    struct rnablk_unitattn_state_s *duap;
    unsigned long irqflags;
    int n_new_pending = 0;
    int avail_idx;
    int code;
    int i, j;
#ifdef WINDOWS_KERNEL
    pHW_HBA_EXT pHBAExt;
#endif

    uap = &cmd->u.cache_scsi_unitattn;

#ifdef WINDOWS_KERNEL
    pHBAExt = hbaext_from_com_ep(ep);
    dev = rnablk_find_device_by_path(uap->csu_pathname, pHBAExt);
#else
    dev = rnablk_find_device_by_path(uap->csu_pathname);
#endif

    if (NULL == dev) {
        rna_printk(KERN_ERR, "SCSI_UNITATTN request for unknown "
                   "device [%s]: code=%#hhx\n", uap->csu_pathname,
                   uap->csu_ua_code);
        return;
    }
    duap = &dev->rbd_ua_state;
    code = uap->csu_ua_code;

    rna_printk(KERN_RSV, "Got SCSI_UNITATTN request device [%s] code [%d] "
               "n_itns [%d]\n", dev->name, code, uap->csu_n_itns);

    rna_spin_lock_irqsave(dev->rbd_event_lock, irqflags);

    for (i = 0; i < uap->csu_n_itns; i++) {
        if (match_itn_id(&rnablk_itn_id, &uap->csu_itn_list[i])) {
            /*
             * This UNITATTN is direct to the client itself.
             * But rnablk doesn't care about UNITATTN, so just ignore it!
             */
            continue;
        }
        avail_idx = -1;
        for (j = 0; j < duap->rus_n_itns; j++) {
            if (duap->rus_ini_unitattn[j] == 0 && avail_idx == -1) {
                avail_idx = j;
            }
            if (match_itn_id_for_initiator(&uap->csu_itn_list[i],
                                           duap->rus_ini_list[j])) {
                if (!(duap->rus_ini_unitattn[j] & (1 << code))) {
                    duap->rus_ini_unitattn[j] |= (1 << code);
                    n_new_pending++;
                }
                break;
            }
        }
        if (j == duap->rus_n_itns) {
            if (avail_idx != -1) {
                j = avail_idx;
            } else {
                duap->rus_n_itns++;
            }
            rsv_copy_initiator(&duap->rus_ini_list[j],
                               &rsv_itn_initiator(&uap->csu_itn_list[i]));
            duap->rus_ini_unitattn[j] = (1 << code);
            n_new_pending++;
        }
    }
    if (n_new_pending) {
        duap->rus_n_pending += n_new_pending;
        wake_up_all(&dev->rbd_event_wait);
    }
    rna_spin_unlock_irqrestore(dev->rbd_event_lock, irqflags);

    rnablk_dev_release(dev);
}

// Caller must call rnablk_next_request() if they want query to be dispatched
int
rnablk_cache_blk_send_change_ref(struct cache_blk       *blk,
                                 cache_lock_t           new_ref,
                                 uint32_t               flags)
{
    int              ret = 0;

    struct io_state *ios;

    ret = rnablk_alloc_ios_admin(blk->dev, ios);
    if (unlikely(0 != ret)) {
        return ret;
    }

    ios->type = !(flags & DEREF_NO_RESP) ? RNABLK_CHANGE_REF
                                         : RNABLK_CHANGE_REF_NORESP;
    ios->start_sector = blk->start_sector;

    rnablk_set_ios_blk(ios, blk);

    ret = rnablk_submit_change_ref(ios, blk->ref_type, new_ref, flags);
    if (unlikely(0 != ret)) {
        rnablk_ios_finish(ios);
    }

    return ret;
}

static void
rnablk_process_cache_trans_req(rnablk_workq_cb_arg_t arg)
{
    struct work_struct *work = (struct work_struct *)arg;
    struct rnablk_work *w = container_of(work, struct rnablk_work, work);
    struct rnablk_trans_req_wf_data *wd = &w->data.rwd_rnablk_trans_req_wf;
    struct rnablk_device *dev = wd->tr_dev;
    struct cache_blk *blk;
    sector_t start_sector;
    lockstate_t flags;
    
    uint64_t start_seconds = get_seconds();

    start_sector = (wd->tr_block_num * dev->cache_blk_size) /
                    RNABLK_SECTOR_SIZE;

    // Takes a ref on the block
    blk = rnablk_cache_blk_get(dev, start_sector);

    if (unlikely(NULL == blk)) {
        rna_printk(KERN_ERR, "could not find block for device [%s] "
                   "block [%"PRId64"]\n", dev->name, wd->tr_block_num);
    } else if (unlikely(blk->block_number != wd->tr_block_num)) {
        rna_printk(KERN_ERR, "got wrong block number [%"PRId64"] for "
                   "device [%s] block [%"PRId64"]\n",
                   blk->block_number, dev->name, wd->tr_block_num);
    } else {
        rnablk_lock_blk_irqsave(blk, flags);
        if (unlikely(rnablk_blk_disconnected(blk) ||
                     (RNABLK_CACHE_BLK_INVALID == blk->state))) {
            rnablk_unlock_blk_irqrestore(blk, flags);
            rna_printk(KERN_WARNING,
                       "[%s] Ignoring transition request from [%s] -> "
                       "[%s] for block [%"PRId64"] in state [%s]\n",
                       dev->name,
                       get_lock_type_string(wd->tr_cur_ref),
                       get_lock_type_string(wd->tr_new_ref),
                       blk->block_number,
                       rnablk_cache_blk_state_string(blk->state));
        } else if (likely((CACHE_WRITE_ONLY_SHARED == wd->tr_cur_ref) &&
                          (CACHE_WRITE_SHARED == wd->tr_new_ref))) {
            /* Handle write-only -> write transition */
            if (unlikely(RNABLK_CACHE_BLK_CHANGE_PENDING == blk->state)) {
                /*
                 * Looks like we're already in the process of
                 * transitioning, so just drop this one on the floor.
                 */
                rna_printk(KERN_WARNING,
                           "[%s] Ignoring transition request from [%s] -> "
                           "[%s] for block [%"PRId64"] in state [%s]\n",
                           dev->name,
                           get_lock_type_string(wd->tr_cur_ref),
                           get_lock_type_string(wd->tr_new_ref),
                           blk->block_number,
                           rnablk_cache_blk_state_string(blk->state));
                rnablk_unlock_blk_irqrestore(blk, flags);
            } else if (unlikely(!rnablk_cache_blk_state_transition(blk,
                                    RNABLK_CACHE_BLK_CONNECTED_WRITE_ONLY,
                                    RNABLK_CACHE_BLK_CHANGE_PENDING))) {
                rna_printk(KERN_ERR,
                           "[%s] block [%"PRId64"] in unexpected state [%s]\n",
                           dev->name,
                           blk->block_number,
                           rnablk_cache_blk_state_string(blk->state));
                rnablk_unlock_blk_irqrestore(blk, flags);
            } else {
                /*
                 * temporarily inc within lock; send_change_ref will do
                 * real inc
                 */
                rnablk_cache_blk_ioref(blk, NULL);
                rnablk_unlock_blk_irqrestore(blk, flags);
                (void)rnablk_cache_blk_send_change_ref(blk,
                                                CACHE_WRITE_SHARED, 0);
                rnablk_cache_blk_iorel(blk, NULL);  // undo temp ref
                rnablk_start_blk_io(blk, FALSE);
                rna_printk(KERN_DEBUG,
                           "[%s] Transitioning on request from [%s] -> "
                           "[%s] for block [%"PRId64"] in state [%s]\n",
                           dev->name,
                           get_lock_type_string(wd->tr_cur_ref),
                           get_lock_type_string(wd->tr_new_ref),
                           blk->block_number,
                           rnablk_cache_blk_state_string(blk->state));
            }            
        } else if (unlikely(CACHE_ATOMIC_SHARED == wd->tr_new_ref)) {
            /* Handle transition to atomic reference */
            if (unlikely(RNABLK_CACHE_BLK_CHANGE_PENDING == blk->state)) {
                rna_printk(KERN_WARNING,
                           "[%s] Ignoring transition request from [%s] -> "
                           "[%s] for block [%"PRId64"] in state [%s]\n",
                           dev->name,
                           get_lock_type_string(wd->tr_cur_ref),
                           get_lock_type_string(wd->tr_new_ref),
                           blk->block_number,
                           rnablk_cache_blk_state_string(blk->state));
                rnablk_unlock_blk_irqrestore(blk, flags);
            } else if (unlikely(
                    !rnablk_cache_blk_start_atomic_state_transition(blk))) {
                rna_printk(KERN_ERR,
                           "[%s] block [%"PRId64"] in unexpected state [%s]\n",
                           dev->name,
                           blk->block_number,
                           rnablk_cache_blk_state_string(blk->state));
                rnablk_unlock_blk_irqrestore(blk, flags);
            } else {
                /*
                 * temporarily inc within lock; send_change_ref will do
                 * real inc
                 */
                rnablk_cache_blk_ioref(blk, NULL);
                rnablk_unlock_blk_irqrestore(blk, flags);
                (void)rnablk_cache_blk_send_change_ref(blk,
                                                CACHE_ATOMIC_SHARED, 0);
                rnablk_cache_blk_iorel(blk, NULL);  // undo temp ref
                rnablk_start_blk_io(blk, FALSE);
            }            
        } else {
            rna_printk(KERN_ERR,
                       "[%s] Unexpected transition request from [%s] -> "
                       "[%s] for block [%"PRId64"] in state [%s]\n",
                       dev->name,
                       get_lock_type_string(wd->tr_cur_ref),
                       get_lock_type_string(wd->tr_new_ref),
                       blk->block_number,
                       rnablk_cache_blk_state_string(blk->state));
            BUG_ON(TRUE);
        }
    }
    if (NULL != blk) {
        rnablk_cache_blk_release(blk);
    }

    rnablk_dev_release(dev);        // release ref on dev taken when queued
    rnablk_mempool_free(w, work_cache_info);
    rnablk_finish_workq_work(start_seconds);
}

/*
 * rnablk_queue_cache_trans_req()
 *  Queue a task to process a CACHE_TRANS_REQ request.
 *
 *  IMPORTANT NOTE:
 *      Processing for this request needs to be queued rather than processed
 *      in-line in the completion callback thread because it may require the
 *      allocation of an io_state (admin) structure and thus may block
 *      waiting for one.  But waiting in the recv callback thread may block
 *      other requests from being processed, and those blocked requests
 *      may be the ones holding io_state structures, thus causing a
 *      deadlock, since they are unable to run and thus are unable to
 *      free their io_state structures. (This is not theoretical; ran
 *      into this problem when DEREF's were happening. DEREF's can suck
 *      up a lot of io_state structures.  The responses to the
 *      CACHE_CHANGE_REF's got blocked behind a CACHE_TRANS_REQ, etc).
 */
static void
rnablk_queue_cache_trans_req(struct com_ep    *ep,
                             struct cache_cmd *cmd)
{
    struct rnablk_device *dev = NULL;
    struct cache_trans_req * req = NULL;
    struct rnablk_work *w;
#ifdef WINDOWS_KERNEL
    pHW_HBA_EXT pHBAExt;
#endif

    BUG_ON(NULL == cmd);

    req = &cmd->u.cache_trans_req;

    rna_printk(KERN_INFO,
               "transition request [%s] [%"PRId64"] [%s] -> [%s]\n",
               req->ctr_pathname,
               req->ctr_block_num,
               get_lock_type_string(req->ctr_cur_ref),
               get_lock_type_string(req->ctr_new_ref));
    
#ifdef WINDOWS_KERNEL
    pHBAExt = hbaext_from_com_ep(ep);
    dev = rnablk_find_device_by_path(req->ctr_pathname, pHBAExt);
#else
    dev = rnablk_find_device_by_path(req->ctr_pathname);
#endif /* WINDOWS_KERNEL */

    if (unlikely(NULL == dev)) {
        rna_printk(KERN_ERR, "could not find dev for cache path [%s]\n",
                   req->ctr_pathname);
        return;
    }
    
    w = rnablk_mempool_alloc(work_cache_info);
    if (likely(NULL != w)) {
        w->data.rwd_rnablk_trans_req_wf.tr_dev = dev;
        w->data.rwd_rnablk_trans_req_wf.tr_block_num = req->ctr_block_num;
        w->data.rwd_rnablk_trans_req_wf.tr_cur_ref = req->ctr_cur_ref;
        w->data.rwd_rnablk_trans_req_wf.tr_new_ref = req->ctr_new_ref;
        RNA_INIT_WORK(&w->work, rnablk_process_cache_trans_req, w);
        /* this task allocates an ios, so use ios_workq */
        rna_queue_work(ios_workq, &w->work);
    } else {
        rna_printk(KERN_ERR, "failed to allocate work item\n");
        rnablk_dev_release(dev);
    }
}

/*
 * rnablk_send_fail_cachedev
 *  Send either a FAIL_CACHE_DEVICE notification or a FAIL_CACHE_DEVICE_RESP
 *  response to the Cache Server.
 *
 * Notes:
 *  1) Note that the CACHE_FAIL_CACHE_DEVICE message is used in a dual-purpose
 *     manner.  In all cases, when the cache-server detects (or is notified
 *     of) a cache device failure, it will send this message to all of its
 *     clients.  However, if we (the client) detect the cache failure before
 *     being notified of it by the cache-server, then the client sends this
 *     message to the cache-server to notify it about the failure.
 *
 *     When the client is on the receiving end of this message, it must send
 *     a response back to the cache-server once it has taken steps to ensure
 *     that no further requests or i/o's will be directed to the cache-server
 *     for the failing cache-device.
 *
 *     So, just to clarify the sequence of events:
 *      1) If the client detects a cache-device failure (via a failed local
 *         dma) prior to being notified of the failure by the cache-server,
 *         it sends a CACHE_FAIL_CACHE_DEVICE message to the cache-server.
 *      2) When a cache-server discovers a cache-device failure (either
 *         via its own operations or via receiving a CACHE_FAIL_CACHE_DEVICE
 *         message from one of its clients), then it sends a
 *         CACHE_FAIL_CACHE_DEVICE message to all of its clients.
 *      3) A client, upon receiving a CACHE_FAIL_CACHE_DEVICE message from
 *         a cache-server, takes steps to offline the cache-device so that
 *         it issues no more requests for that cache-device, and then
 *         sends back a CACHE_FAIL_CACHE_DEVICE_RESP response message to that
 *         cache-server.
 */
void
rnablk_send_fail_cachedev(struct rnablk_server_conn *conn,
                          cachedev_id_t cachedev_id,
                          boolean send_response)
{
    struct buf_entry *buf_entry;
    struct cache_cmd *cmd;
    int ret;

    rna_printk(KERN_NOTICE, "Send FAIL_CACHE_DEVICE%s for "
               "cachedev [%#"PRIx64"] to conn ["CONNFMT"]\n",
               send_response ? "_RESP" : "", cachedev_id, CONNFMTARGS(conn));

    if ((NULL == conn) || (NULL == conn->ep) ||
       (MD_CONN_EP_METAVALUE == conn->ep)) {

        rna_printk(KERN_ERR,"Failed to CS connection dropping "
                   "FAIL_CACHE_DEVICE message for cachedev [%#"PRIx64"]\n",
                   cachedev_id);
        return;
    }

    ret = com_get_send_buf(conn->ep, &buf_entry, FALSE);
    if (unlikely((0 != ret) || (NULL == buf_entry))) {
        atomic_inc(&conn->send_buf_alloc_failures);
        rna_printk(KERN_ERR,"Failed to get send buf, dropping "
                   "FAIL_CACHE_DEVICE message for cachedev [%#"PRIx64"]\n",
                   cachedev_id);
        return;
    }
    atomic_inc(&conn->send_bufs_allocated);
    atomic_inc(&conn->send_bufs_in_use);
    cmd = com_get_send_buf_mem(buf_entry);
    memset(&cmd->h, 0, sizeof(cmd->h));
    cmd->h.h_type = send_response ? CACHE_FAIL_CACHE_DEVICE_RESP
                                  : CACHE_FAIL_CACHE_DEVICE;
    cmd->u.cache_fail_cd.cfcd_id = cachedev_id;
    ret = com_send(conn->ep, buf_entry, (int)cache_cmd_length(cmd));
    if (unlikely(ret)) {
        com_put_send_buf(conn->ep, buf_entry);
        atomic_dec(&conn->send_bufs_in_use);
    }

}


static void
rnablk_process_create_block_device(struct rna_service_ctx_s     *ctx,
                                   rna_service_message_buffer_t *message)
{
    struct rnablk_device *dev = NULL;
    rna_service_create_block_device_t *create_block_device_msg = &message->u.rmb_create_block_device;
#ifdef WINDOWS_KERNEL
    pHW_HBA_EXT pHBAExt;
#endif
    ENTER;

    rna_printk(KERN_ERR, 
               "Processing create for blkdev [%s] [%s] "
               "master_block_id [%"PRIu64"]\n", 
               create_block_device_msg->cbs_name,
               create_block_device_msg->cbs_persist_location,
               create_block_device_msg->cbs_master_block_id);

#ifdef WINDOWS_KERNEL
    pHBAExt = hbaext_from_rna_service_ctx(ctx);
    ASSERT(NULL != pHBAExt);
    if (NULL != (dev = rnablk_find_device(create_block_device_msg->cbs_name, pHBAExt))) {
        rna_printk( KERN_INFO, "Device %s already exists. Re-registering.\n", 
                    create_block_device_msg->cbs_name );

        if(dev->dv_master_block_id !=
                create_block_device_msg->cbs_master_block_id) {
            rna_printk(KERN_ERR,
                       "Mismatching master_block_id's: "
                       "old: [%"PRIu64"] new: [%"PRIu64" Device [%s]\n",
                       dev->dv_master_block_id,
                       create_block_device_msg->cbs_master_block_id,
                       create_block_device_msg->cbs_name);
            GOTO( out,-EINVAL);
        }

        atomic_set(&dev->path_md_policy, create_block_device_msg->cbs_path_md_policy);
    } else {
        dev = Allocate_Device(create_block_device_msg->cbs_name, pHBAExt);
#else
    if (NULL != (dev = rnablk_find_device(create_block_device_msg->cbs_name))) {
        rna_printk( KERN_INFO, "Device %s already exists. Re-registering.\n", 
                    create_block_device_msg->cbs_name );

        if(dev->dv_master_block_id !=
                create_block_device_msg->cbs_master_block_id) {
            rna_printk(KERN_ERR,
                       "Mismatching master_block_id's: "
                       "old: [%"PRIu64"] new: [%"PRIu64" Device [%s]\n",
                       dev->dv_master_block_id,
                       create_block_device_msg->cbs_master_block_id,
                       create_block_device_msg->cbs_name);
            GOTO( out,-EINVAL);
        }

        atomic_set(&dev->path_md_policy, create_block_device_msg->cbs_path_md_policy);
    } else {
        dev = rnablk_make_device(create_block_device_msg->cbs_name);
#endif

        if (NULL == dev) {
            rna_printk(KERN_ERR, "Failed to create device %s\n", 
                       create_block_device_msg->cbs_name);
            GOTO( out,-ENOMEM );
        }

        dev->dv_master_block_id = create_block_device_msg->cbs_master_block_id;

        if ('\0' != create_block_device_msg->cbs_persist_location[0]) {
            dev_set_persistent(dev);
            dev_set_freeable(dev);
            if (!fldc_default_block_size) {
                dev->cache_blk_size = RNABLK_DEFAULT_PERSIST_CACHE_BLK_SIZE;
            } else {
                dev->cache_blk_size = fldc_default_block_size;
            }
            strncpy(&dev->persist_location[0],
                    &create_block_device_msg->cbs_persist_location[0],
                    min(sizeof(dev->persist_location),
                        sizeof(create_block_device_msg->cbs_persist_location)));
            dev->access_uid = create_block_device_msg->cbs_persist_access_uid;
            dev->access_gid = create_block_device_msg->cbs_persist_access_gid;

            atomic_set(&dev->path_md_policy, create_block_device_msg->cbs_path_md_policy);
            dev->rbd_cfm_cookie = create_block_device_msg->cookie;
            if (create_block_device_msg->cbs_das) {
                dev_set_das(dev);
                rna_printk(KERN_WARNING,
                           "device [%s] created in Single Node DAS mode\n",
                           dev->name);
            } else {
                dev_clear_das(dev);
            }
        } else {
            dev_clear_persistent(dev);
            // These limits do not apply to scratchpad devices
        }

        if (0 != create_block_device_msg->cbs_cache_block_size) {
            dev->cache_blk_size = min(RNABLK_MAX_CACHE_BLK_SIZE, 
                                      (int)create_block_device_msg->cbs_cache_block_size);
        }
        /*
         * By default, set the "large_write" qualifying size as 1/4 of the
         * cache_blk size.
         */
        dev->rbd_large_write_sects = (dev->cache_blk_size / 4)
                                      / RNABLK_SECTOR_SIZE;
        if ('\0' != create_block_device_msg->cbs_class_name[0]) {
            strncpy(&dev->class_name[0],
                    &create_block_device_msg->cbs_class_name[0],
                    min(sizeof(dev->class_name),
                        sizeof(create_block_device_msg->cbs_class_name)));
        }
        if ('\0' != create_block_device_msg->cbs_class_params[0]) {
            strncpy(&dev->class_params[0],
                    &create_block_device_msg->cbs_class_params[0],
                    min(sizeof(dev->class_params),
                        sizeof(create_block_device_msg->cbs_class_params)));
        }

        if (create_block_device_msg->cbs_shared) {
            dev_set_shareable(dev);
        } else {
            dev_clear_shareable(dev);
        }

        if (dev_is_shareable(dev)) {
            dev_clear_freeable(dev);
        }

        dev->device_cap = create_block_device_msg->cbs_capacity;
        if (RNABLK_CACHE_OFFLINE != atomic_cmpxchg(&dev->stats.status,
                                                    RNABLK_CACHE_OFFLINE,
                                                    RNABLK_CACHE_CONNECTING)) {
            rna_printk(KERN_ERR,
                       "device [%s] in unexpected state [%s]\n",
                       dev->name,
                       get_rnablk_cache_status_string(atomic_read(&dev->stats.status)));
        } else {
            rna_printk(KERN_ERR,
                       "device [%s] capacity [%"PRIu64"] block size [%llu]\n",
                       dev->name,
                       dev->device_cap,
                       dev->cache_blk_size);

            /* Register device with CFM */
            rnablk_register_dev_with_cfm(dev);

            /* Finally, make the configfs node for this device */
            rnablk_make_device_item(dev->name);
        }
    }

    // thin-provision update
    rna_printk(KERN_ERR, "Info: Device %s thinprov %d\n", dev->name,
               create_block_device_msg->cbs_thin_status);

    rnablk_device_process_thinprov_state(dev,create_block_device_msg->cbs_thin_status);
    
    rnablk_dev_release(dev);    // release local ref on dev

 out:
    EXITV;
}

/* Called only from the single slow_workq thread */
static void rnablk_process_create_block_device_dpc(rnablk_workq_cb_arg_t arg)
{
    struct work_struct *work                = (struct work_struct *)arg;
    struct rnablk_create_delete_work *w     = container_of(work, struct rnablk_create_delete_work, work);
    struct rna_service_ctx_s *ctx           = w->ctx;
    rna_service_message_buffer_t *message   = w->message;

    rnablk_mempool_free(w, create_cache_info);

    if (!atomic_read(&shutdown) && enable_creates) {
        rnablk_process_create_block_device(ctx, message);
    } else {
        rna_printk(KERN_ERR, 
                   "Create for blkdev [%s] aborted for shutdown\n", 
                   message->u.rmb_create_block_device.cbs_name);
    }
    (void) rna_service_free_message_buffer(ctx, message);
}

int
rnablk_deferred_process_create_block_device(struct rna_service_ctx_s *ctx,
                                          rna_service_message_buffer_t *message)
{
    int ret = 0;

    rna_service_create_block_device_t *create_block_device_msg = &message->u.rmb_create_block_device;
    struct rnablk_create_delete_work *w;

    if (atomic_read(&shutdown)) {
        goto out;
    }

    if (!enable_creates) {
        goto out;
    }

    rna_printk(KERN_ERR,
               "Got create for blkdev [%s] policy [%d]\n",
               create_block_device_msg->cbs_name, 
               create_block_device_msg->cbs_path_md_policy);

    if( (w = rnablk_mempool_alloc( create_cache_info )) == NULL ) {
        rna_printk(KERN_ERR,
                   "failed to alloc work object for blkdev [%s]\n",
                   create_block_device_msg->cbs_name);
        GOTO( out,-ENOMEM );
    }

    RNA_INIT_WORK(&w->work, rnablk_process_create_block_device_dpc, w);
    w->ctx      = ctx;
    w->message  = message;
    rna_queue_work(slow_workq, &w->work);

  out:
    return ret;
}

static void rnablk_control_block_response(struct rna_service_ctx_s     *ctx,
                                         rna_service_control_block_device_t *msg,
                                         int result,
                                         int final)
{
    rna_service_message_buffer_t *msgbuf;
    rna_service_error_t ret;

    rna_printk(KERN_INFO,
               "Sending control type [%d] for blkdev [%s] cookie [%"PRIu64"]\n",
                msg->cbs_type,
                msg->cbs_name,
                msg->cbs_cookie);

    /*
     * Allocate an rna_service message buffer.
     */
    msgbuf = rna_service_alloc_message_buffer(ctx,
                                              RNA_SERVICE_MESSAGE_TYPE_CONTROL_BLKDEV_RESPONSE,
                                              msg->cbs_name);
    if (NULL == msgbuf) {
        rna_printk(KERN_ERR, "%s: failed to allocate message buffer!!\n",
                   __FUNCTION__);
        GOTO( out,-ENOMEM );
    }

    msgbuf->h.rmb_message_type = RNA_SERVICE_MESSAGE_TYPE_CONTROL_BLKDEV_RESPONSE;
    msgbuf->u.rmb_control_block_device_response.cbr_cookie = msg->cbs_cookie;
    msgbuf->u.rmb_control_block_device_response.cbr_type = msg->cbs_type;
    msgbuf->u.rmb_control_block_device_response.cbr_result = (uint32_t)result;
    msgbuf->u.rmb_control_block_device_response.cbr_final = (uint8_t)final;
    strcpy(msgbuf->u.rmb_control_block_device_response.cbr_name, msg->cbs_name);

    ret = rna_service_send_block_device_control_response(ctx, msgbuf);
    if (ret != RNA_SERVICE_ERROR_NONE) {
        rna_printk(KERN_ERR,
                   "%s: rna_service_send_block_device_control_response failed: %s\n",
                   __FUNCTION__, rna_service_get_error_string(ret));
        GOTO( err,-EINVAL );
    }


out:
    return;
err:
    goto out;
}

static void
rnablk_process_delete_block_device(struct rna_service_ctx_s     *ctx,
                                   rna_service_message_buffer_t *message)
{
    struct rnablk_device *dev = NULL;
    rna_service_control_block_device_t *delete_block_device_msg
                                    = &message->u.rmb_control_block_device;
    int retval = 0;
#ifdef WINDOWS_KERNEL
    pHW_HBA_EXT pHBAExt;
#endif

    rna_printk(KERN_INFO, "Processing delete for blkdev [%s]\n", 
               delete_block_device_msg->cbs_name);

#ifdef WINDOWS_KERNEL
    pHBAExt = hbaext_from_rna_service_ctx(ctx);
    ASSERT(NULL != pHBAExt);
    if (NULL == (dev = rnablk_find_device(delete_block_device_msg->cbs_name, pHBAExt))) {
#else
    if (NULL == (dev = rnablk_find_device(delete_block_device_msg->cbs_name))) {
#endif
        rna_printk(KERN_INFO, "Device %s does not exist.\n", 
                   delete_block_device_msg->cbs_name);
        retval = -ENODEV;
    } else if (dev_openers_is_open(dev)) {
        rna_printk(KERN_INFO, "Device %s is opened.\n",
                   delete_block_device_msg->cbs_name);
        retval = -EMLINK;
#ifdef NOTYET
    } else if (RNABLK_CACHE_OFFLINE != atomic_read(&dev->stats.status)) {
        rna_printk(KERN_ERR, "Device %s is not offline.\n", 
                   delete_block_device_msg->cbs_name);
        retval = -EINVAL;
#endif /* NOTYET */
    } else if (0 == (retval = rnablk_deregister_dev_with_cfm(dev))) {
        if ((RNABLK_CACHE_ONLINE == atomic_cmpxchg(&dev->stats.status,
                                                RNABLK_CACHE_ONLINE,
                                                RNABLK_CACHE_DISCONNECTING))
            || (RNABLK_CACHE_CONNECTING == atomic_cmpxchg(&dev->stats.status,
                                                RNABLK_CACHE_CONNECTING,
                                                RNABLK_CACHE_DISCONNECTING))) {
            rnablk_disconnect_device(dev);
        }
        rnablk_remove_device_item(delete_block_device_msg->cbs_name);
    }
    rnablk_control_block_response(ctx, delete_block_device_msg, retval, 1);

    if (NULL != dev) {
        rnablk_dev_release(dev);
    }
}

/* Called only from the single slow_workq thread */
static void rnablk_process_delete_block_device_dpc(rnablk_workq_cb_arg_t arg)
{
    struct work_struct *work                = (struct work_struct *)arg;
    struct rnablk_create_delete_work *w     = container_of(work, struct rnablk_create_delete_work, work);
    struct rna_service_ctx_s *ctx           = w->ctx;
    rna_service_message_buffer_t *message   = w->message;

    rnablk_mempool_free(w, create_cache_info);

    if (!atomic_read(&shutdown)) {
        rnablk_process_delete_block_device(ctx, message);
    } else {
        rna_printk(KERN_ERR, 
                   "delete for blkdev [%s] aborted for shutdown\n", 
                   message->u.rmb_control_block_device.cbs_name);
    }
    (void) rna_service_free_message_buffer(ctx, message);
}


static int
rnablk_process_stop_block_device(struct rna_service_ctx_s     *ctx,
                                 rna_service_message_buffer_t *message)
{
    struct rnablk_device *dev = NULL;
    rna_service_control_block_device_t *stop_block_device_msg = &message->u.rmb_control_block_device;
#ifdef WINDOWS_KERNEL
    pHW_HBA_EXT pHBAExt;
#endif

    ENTER;

#ifdef WINDOWS_KERNEL
    pHBAExt = hbaext_from_rna_service_ctx(ctx);
    ASSERT(NULL != pHBAExt);
    if (NULL == (dev = rnablk_find_device(stop_block_device_msg->cbs_name, pHBAExt))) {
#else
    if (NULL == (dev = rnablk_find_device(stop_block_device_msg->cbs_name))) {
#endif /*WINDOWS_KERNEL*/
        rna_printk( KERN_ERR, "Device %s does not exist.\n", 
                    stop_block_device_msg->cbs_name );
        ret = -ENODEV;
    } else {
        ret = rnablk_stop_device_item( stop_block_device_msg->cbs_name );
    }
    rnablk_control_block_response(ctx, stop_block_device_msg, ret, 1);
    if (NULL != dev) {
        rnablk_dev_release(dev);
    }
    EXIT;
}

/* Called only from the single slow_workq thread */
static void rnablk_process_stop_block_device_dpc(rnablk_workq_cb_arg_t arg)
{
    struct work_struct *work                = (struct work_struct *)arg;
    struct rnablk_create_delete_work *w     = container_of(work, struct rnablk_create_delete_work, work);
    struct rna_service_ctx_s *ctx           = w->ctx;
    rna_service_message_buffer_t *message   = w->message;

    rnablk_mempool_free(w, create_cache_info);

    if (!atomic_read(&shutdown)) {
        rnablk_process_stop_block_device(ctx, message);
    } else {
        rna_printk(KERN_ERR, 
                   "stop for blkdev [%s] aborted for shutdown\n", 
                   message->u.rmb_control_block_device.cbs_name);
    }

    (void) rna_service_free_message_buffer(ctx, message);

    return;
}

static int
rnablk_process_reactivate_block_device(struct rna_service_ctx_s *ctx,
                                       rna_service_message_buffer_t *message)
{
    struct rnablk_device *dev = NULL;
    rna_service_control_block_device_t *reactivate_msg =
                                    &message->u.rmb_control_block_device;
    lockstate_t flags;
#ifdef WINDOWS_KERNEL
    pHW_HBA_EXT pHBAExt;
#endif

    ENTER;

#ifdef WINDOWS_KERNEL
    pHBAExt = hbaext_from_rna_service_ctx(ctx);
    ASSERT(NULL != pHBAExt);
    if (NULL == (dev = rnablk_find_device(reactivate_msg->cbs_name, pHBAExt))) {
#else
    if (NULL == (dev = rnablk_find_device(reactivate_msg->cbs_name))) {
#endif /*WINDOWS_KERNEL*/

        rna_printk(KERN_ERR, "Device %s does not exist.\n", 
                   reactivate_msg->cbs_name );
        ret = -ENODEV;
    } else {
        if (TRUE == atomic_read(&dev->failed)) {
            rna_printk(KERN_NOTICE, "Reactivating device %s\n",
                       reactivate_msg->cbs_name);
            rnablk_free_cache_blks(dev, TRUE);
            atomic_set(&dev->failed, FALSE);
            dev->stats.failed_blocks = 0;
        } else {
            rna_printk(KERN_INFO, "Device %s does not require reactivating.\n",
                       reactivate_msg->cbs_name );
        }
        if (!MASTER_BLK_IS_CONNECTED(dev)) {
            /*
             * As part of device failure, if we got disconnected
             * from the cache server that owned this master block,
             * we would have gone through and marked all the blocks
             * associated with that conn as INVALID (including the
             * master block).
             *
             * If the master block is marked INVALID, change it to
             * DISCONNECTED prior to relocking it.
             */
            rnablk_lock_blk_irqsave(MASTER_BLK(dev), flags);
            if (rnablk_cache_blk_state_transition(MASTER_BLK(dev),
                                                  RNABLK_CACHE_BLK_INVALID,
                                                  RNABLK_CACHE_BLK_DISCONNECTED)) {
                rna_printk(KERN_NOTICE, "Marked master block for device %s "
                           "as disconnected prior to re-locking it\n",
                           reactivate_msg->cbs_name);
            }
            rnablk_unlock_blk_irqrestore(MASTER_BLK(dev), flags);
            rnablk_lock_master_blk(dev);
        }
    }

    rnablk_control_block_response(ctx, reactivate_msg, ret, 1);
    if (NULL != dev) {
        rnablk_dev_release(dev);
    }
    EXIT;
}

/* Called only from the single slow_workq thread */
static void
rnablk_process_reactivate_block_device_dpc(rnablk_workq_cb_arg_t arg)
{
    struct work_struct *work = (struct work_struct *)arg;
    struct rnablk_create_delete_work *w = container_of(work,
                                        struct rnablk_create_delete_work, work);
    struct rna_service_ctx_s *ctx = w->ctx;
    rna_service_message_buffer_t *message = w->message;

    rnablk_mempool_free(w, create_cache_info);

    if (!atomic_read(&shutdown)) {
        rnablk_process_reactivate_block_device(ctx, message);
    } else {
        rna_printk(KERN_ERR, 
                   "reactivate for blkdev [%s] aborted for shutdown\n", 
                   message->u.rmb_control_block_device.cbs_name);
    }

    (void)rna_service_free_message_buffer(ctx, message);

    return;
}

/* Client control is not supported.
 * Send a response back to CFM.
 */
static void rnablk_process_notsup_block_device_dpc(rnablk_workq_cb_arg_t arg)
{
    struct work_struct *work                = (struct work_struct *)arg;
    struct rnablk_create_delete_work *w     = container_of(work, struct rnablk_create_delete_work, work);
    struct rna_service_ctx_s *ctx           = w->ctx;
    rna_service_message_buffer_t *message   = w->message;

    rnablk_mempool_free(w, create_cache_info);

    rnablk_control_block_response(ctx, &message->u.rmb_control_block_device, -EINVAL, 1);

    (void) rna_service_free_message_buffer(ctx, message);

    return;
}



int
rnablk_deferred_process_control_block_device(
                                    struct rna_service_ctx_s     *ctx,
                                    rna_service_message_buffer_t *message)
{
    rna_service_control_block_device_t *control_block_device_msg =
                                    &message->u.rmb_control_block_device;
    struct rnablk_create_delete_work *w;
    int ret = 0;

    if (atomic_read(&shutdown)) {
        goto out;
    }

    rna_printk(KERN_INFO,
               "Got control type [%d] for blkdev [%s] cookie [%"PRIu64"]\n",
                control_block_device_msg->cbs_type,
                control_block_device_msg->cbs_name,
                control_block_device_msg->cbs_cookie);

    if( (w = rnablk_mempool_alloc( create_cache_info )) == NULL ) {
        GOTO( out,-ENOMEM );
    }

    rna_printk(KERN_INFO,
               "Queueing control type [%d] for blkdev [%s]\n",
                control_block_device_msg->cbs_type,
                control_block_device_msg->cbs_name);

    switch(control_block_device_msg->cbs_type) {
            case CLIENT_CONTROL_STOP:
                RNA_INIT_WORK(&w->work, rnablk_process_stop_block_device_dpc, w);
                break;
            case CLIENT_CONTROL_DELETE:
            case CLIENT_CONTROL_REMCLIENT:
                RNA_INIT_WORK(&w->work, rnablk_process_delete_block_device_dpc, w);
                break;
            case CLIENT_CONTROL_REACTIVATE:
                RNA_INIT_WORK(&w->work,
                              rnablk_process_reactivate_block_device_dpc, w);
                break;
            default:
                RNA_INIT_WORK(&w->work, rnablk_process_notsup_block_device_dpc, w);
                break;
    }
    w->ctx      = ctx;
    w->message  = message;
    rna_queue_work(slow_workq, &w->work);

 out:
    return ret;
}

/*
 * Process queued simulated MD query response
 */
static void
rnablk_das_mdq_response_wf(rnablk_workq_cb_arg_t arg)
{
    struct work_struct *work = (struct work_struct *)arg;
    struct rnablk_work *w = container_of(work, struct rnablk_work, work);
    struct rnablk_das_mdq_response_wf_data *wd = &w->data.rwd_rnablk_das_mdq_response_wf;
    uint64_t start_seconds = get_seconds();
    ENTERV;

    wd->callback(wd->ctx, wd->mbuf, wd->rbuf, RNA_SERVICE_RESPONSE_STATUS_SUCCESS);

    rnablk_mempool_free(w, work_cache_info);
    rnablk_finish_workq_work(start_seconds);
    EXITV;
}

#define MDQ_PRINT_LEVEL KERN_DEBUG
static void
rnablk_print_md_query_response(rna_service_message_buffer_t *rbuf)
{
    uint32_t i;

    rna_service_metadata_query_response_t *resp = &rbuf->u.rmb_metadata_query_response;
    rna_printk(MDQ_PRINT_LEVEL, "cookie [%"PRIu64"]\n",
        resp->mqr_cookie);
    rna_printk(MDQ_PRINT_LEVEL, "block size [%"PRIu64"]\n",
        resp->mqr_block_size);
    rna_printk(MDQ_PRINT_LEVEL, "service id ["rna_service_id_format"]\n",
        rna_service_id_get_string(&resp->mqr_service_id));
    rna_printk(MDQ_PRINT_LEVEL, "if_table entries [%d]\n",
            resp->mqr_if_table.table_entries);
    for (i = 0; i < resp->mqr_if_table.table_entries; i++) {
        rna_printk(MDQ_PRINT_LEVEL, "if_table[%d] - ["NIPQUAD_FMT"/%d] (%s)\n",
            i,
            NIPQUAD(resp->mqr_if_table.ifs[i].addr),
            resp->mqr_if_table.ifs[i].port,
            com_get_transport_type_string(resp->mqr_if_table.ifs[i].type));
    }
    rna_printk(MDQ_PRINT_LEVEL, "master_block_id [%"PRIu64"]\n",
        resp->mqr_master_block_id);
    // rna_printk(MDQ_PRINT_LEVEL, "hash key"
    rna_printk(MDQ_PRINT_LEVEL, "cache reqest type [%d]\n",
        resp->c.co_cache_req_type);
    rna_printk(MDQ_PRINT_LEVEL, "CO  master_block_id [%"PRIu64"]\n",
        resp->c.co_master_block_id);
    rna_printk(MDQ_PRINT_LEVEL, "evict policy [%d]\n",
         resp->c.co_evict_policy);
    rna_printk(MDQ_PRINT_LEVEL, "lock type [%s]\n",
        get_lock_type_string(resp->c.co_lock_type));
    rna_printk(MDQ_PRINT_LEVEL, "write mode [%d]\n",
         resp->c.co_write_mode);
    rna_printk(MDQ_PRINT_LEVEL, "invd mode [%d]\n",
         resp->c.co_invd_mode);
    rna_printk(MDQ_PRINT_LEVEL, "block num [%"PRIu64"]\n",
         resp->c.co_block_num);
}

/*
 * Process a simulated MD query for use with a DAS device
 * (operating without an MD).
 *
 *  - create a rna_service_metadata_query_response_t message buffer.
 *  - fill in with data from source message buffer rmb_metadata_query
 *    and other locations.
 *  - Queue the response_callback for processing.
 */
static int
rnablk_das_metadata_query(struct rnablk_device *dev,
                          struct rna_service_ctx_s *ctx,
                          rna_service_message_buffer_t *mbuf,
                          rna_service_response_callback response_callback)
{
    rna_service_metadata_query_t *query;

    rna_service_message_buffer_t *rbuf;
    rna_service_metadata_query_response_t *resp;

    rna_hash_key_t hash_key;

    int ret = RNA_SERVICE_ERROR_NONE;

    struct rnablk_work *w = NULL;
    struct rnablk_das_mdq_response_wf_data *wd = NULL;

    query =  &mbuf->u.rmb_metadata_query;
    rna_printk(MDQ_PRINT_LEVEL,
               "Simulated MD query for DAS device:\n");

    /*
     * rbuf is freed in the response callback.
     */
    rbuf = rna_service_alloc_message_buffer(ctx,
                                            RNA_SERVICE_MESSAGE_TYPE_MD_QUERY_RESPONSE,
                                            dev->cache_file_name);
    if (NULL == rbuf) {
        rna_printk(KERN_ERR, "%s: failed to allocate message buffer!!\n",
                 __FUNCTION__);
        ret = -ENOMEM;
        goto err;
    }

    rbuf->h.rmb_message_type = RNA_SERVICE_MESSAGE_TYPE_MD_QUERY_RESPONSE;
    resp =  &rbuf->u.rmb_metadata_query_response;
    resp->mqr_cookie = query->mqs_cookie;
    resp->mqr_block_size = dev->cache_blk_size;
    resp->mqr_service_id = rbd_cs_svc_id;
    resp->mqr_if_table = rbd_cs_if;

    resp->mqr_master_block_id = dev->dv_master_block_id;

    rna_hash_compute_key_path(query->mqs_pathname, strlen(query->mqs_pathname),
                              &hash_key);
    switch (query->mqs_request_type) {
    case CACHE_REQ_TYPE_BLOCK:
        rna_hash_convert_key_to_block_key(&hash_key, query->mqs_block_num);
        break;
    case CACHE_REQ_TYPE_MASTER:
        rna_hash_convert_key_to_master_key(&hash_key);
        break;
    }

	memcpy(&resp->mqr_path_key,
            &hash_key,
            sizeof(resp->mqr_path_key));

    resp->c.co_cache_req_type = query->mqs_request_type;
    resp->c.co_evict_policy = query->mqs_evict_policy;
    resp->c.co_error_persistence = 0;
    resp->c.co_lock_type = query->mqs_lock_type;
    resp->c.co_write_mode = query->mqs_write_mode;
    resp->c.co_invd_mode = query->mqs_invd_mode;
    resp->c.co_partition = 0;
    resp->c.co_md_rid = 0;
    resp->c.co_block_num = query->mqs_block_num;
    resp->c.co_reader_uid = 0;
    resp->c.co_reader_gid = 0;

    resp->c.co_master_block_id = dev->dv_master_block_id;

    rnablk_print_md_query_response(rbuf);

    /*
     * If we haven't received local CS connection info yet, then retry later
     */
    resp->mqr_error = 0;
    if (atomic_read(&rbd_local_cs_connect) == FALSE) {
        rna_printk(KERN_WARNING,
                   "Simulated MD query return EAGAIN, local CS data not available yet\n");
        resp->mqr_error = -EAGAIN;
    }

    /*
     * Set up and queue the simulated MD query response for processing
     */
    if (unlikely(NULL == (w = rnablk_mempool_alloc(work_cache_info)))) {
        /*
         * free rbuf now, since the call back isn't called.
         * The caller will free mbuf if we return non-success status.
         */
        (void)rna_service_free_message_buffer(ctx, rbuf);
        ret = -ENOMEM;
        goto err;
    }
    RNABLK_INIT_RNABLK_WORK(w, wd, rnablk_das_mdq_response_wf);
    wd->ctx = ctx;
    wd->mbuf = mbuf;
    wd->rbuf = rbuf;
    wd->callback = response_callback;
    rna_queue_work(mt_workq, &w->work);
err:
    return ret;
}

void
rnablk_notify_mount_event(struct rnablk_device *dev, int32_t value)
{
   rna_service_message_buffer_t *msgbuf = NULL;
   rna_service_error_t ret;
   struct rna_service_ctx_s *ctx = NULL;

   if (!dev->rbd_cfm_cookie)
       return;

   ENTERV;

#ifdef WINDOWS_KERNEL
   ctx = dev->pHBAExt->hba_rna_service_ctx;
#else
   ctx = rna_service_ctx;
#endif
   rna_printk(KERN_INFO, "cookie=0x%"PRIx64" udev event=%d device_name=%s\n",   dev->rbd_cfm_cookie, value, dev->persist_location);

	/*
	 * Allocate an rna_service message buffer.
	 */
	msgbuf = rna_service_alloc_message_buffer(ctx,
                                              RNA_SERVICE_MESSAGE_TYPE_NOTIFICATION_EVENT,
                                              NULL);

	if (NULL == msgbuf) {
        rna_printk(KERN_ERR, "%s: failed to allocate message buffer!!\n",
				   __FUNCTION__);
        GOTO( out,-ENOMEM );
	}

    msgbuf->h.rmb_message_type = RNA_SERVICE_MESSAGE_TYPE_NOTIFICATION_EVENT;

    if ( value == 0 ) 
        msgbuf->u.rmb_notification_event.event = BLOCK_CLIENT_MOUNT_NOT_DONE;
    else if ( value == 1 )
        msgbuf->u.rmb_notification_event.event = BLOCK_CLIENT_MOUNT_OK;
    else if ( value == 2 )
        msgbuf->u.rmb_notification_event.event = BLOCK_CLIENT_MOUNT_FAILED;
    else {
        rna_printk(KERN_ERR, "invalid mount event=[%d]\n", value);
        (void) rna_service_free_message_buffer(ctx, msgbuf);
        GOTO( out,-EINVAL );
    }

    msgbuf->u.rmb_notification_event.cookie = dev->rbd_cfm_cookie;
    dev->rbd_cfm_cookie = 0;
    memset(&msgbuf->u.rmb_notification_event.persist_location, '\0', PATH_MAX+1 );
    strncpy(msgbuf->u.rmb_notification_event.persist_location, dev->persist_location, PATH_MAX);

    /* notification will be sent to interested nodes only */
	ret = rna_service_send_notification_event(ctx, msgbuf);
	if (ret != RNA_SERVICE_ERROR_NONE) {
        rna_printk(KERN_ERR,
                   "%s: rna_service_send_ntofication event failed: %s\n",
				   __FUNCTION__, rna_service_get_error_string(ret));
        GOTO( out,-EINVAL );
    }
out:
    EXITV;
}

/*
 * Called when service library has indicated that we have stopped recieving
 * pings.  Stops incoming I/O queues.
 */
void
rnablk_process_detach(void)
{
    if (RNA_SERVICE_JOINED == atomic_cmpxchg(&rna_service_detached,
                                             RNA_SERVICE_JOINED,
                                             RNA_SERVICE_DETACHED)) {
        rna_printk(KERN_ERR,
                   "Detached from cluster, stopping I/O and connection queues\n");
        rnablk_stop_devs();
        rnablk_svcctl_freeze();
    } else {
        rna_printk(KERN_ERR,
                   "Already detached, ignoring service event\n");
    }
}

void
rnablk_process_rejoin(void)
{
    if (RNA_SERVICE_DETACHED == atomic_cmpxchg(&rna_service_detached,
                                               RNA_SERVICE_DETACHED,
                                               RNA_SERVICE_JOINED)) {
        rna_printk(KERN_ERR,
                   "Rejoined cluster, starting I/O and connection queues\n");
        rnablk_svcctl_unfreeze();
        rnablk_schedule_wake_up_all();
        rnablk_start_devs(NULL, TRUE);
    } else {
        rna_printk(KERN_ERR, "Not detached or in detached_shutdown state, "
                   "ignoring service event\n");
    }
}

static int
rnablk_send_master_rsv_access_resp(struct rnablk_device *dev,
                                   uint32_t generation)
{
    struct cache_blk *blk;
    struct io_state *ios;
    struct cache_cmd *cmd;
    struct com_ep *ep;
    int ret = 0;

    blk = MASTER_BLK(dev);
    rnablk_trc_master(1, "start: blk [%p] ref [%s] refcnt "
                      "["BLKCNTFMT"]\n", blk,
                      get_lock_type_string(blk->ref_type),
                      BLKCNTFMTARGS(blk));
    if (!rnablk_blk_connected(blk)
        || NULL == (ep = blk->ep)
        || MD_CONN_EP_METAVALUE == ep) {
        rna_printk(KERN_ERR, "device [%s] master block not connected\n",
                   dev->name);
        return -ENODEV;
    }

    ret = rnablk_alloc_ios(dev, NULL, IOREQ_TYPE_NOREQ, RSV_ACC_NONE,
                           FALSE, TRUE, 1, &ios);

	if (unlikely(0 != ret)) {
        return ret;
    }

    ios->start_sector = -1;
    ios->type = RNABLK_RSV_ACCESS_RESP;

    rnablk_set_ios_blk(ios, blk);

    cmd = ios->cmd;
    cmd->h.h_type = CACHE_RSV_ACCESS_RESP;
    cmd->h.h_error = 0;
    cmd->u.cache_rsv_access_resp.crar_generation = generation;

    rnablk_queue_request(RNABLK_RSV_ACCESS_RESP, ep, ios, blk,
                         NO_FORCE_QUEUED_IO, FALSE);
    rnablk_trc_master(ret != 0, "error=%d\n", ret);
    return 0;
}

void
rnablk_rsv_access_process_ack(struct rnablk_device *dev,
                              rsv_ack_phase ack_phase,
                              uint32_t generation,
                              boolean is_external_ack)
{
    unsigned long irqflags;
    boolean restart_dev_io = FALSE;
    int ret;

    rna_printk(KERN_RSV, "Processing rsv_access ack for device [%s] "
                "ack_needed=%s ack_phase=%d gen=%u is_extern=%d\n",
                dev->name, RSV_ACK_NEED_NONE == dev->rbd_rsv.rrs_ack_needed
                ? "NONE" : RSV_ACK_NEED_CS == dev->rbd_rsv.rrs_ack_needed
                ? "CS" : "CLIENT", ack_phase, generation, is_external_ack);
    rna_spin_lock_irqsave(dev->rbd_event_lock, irqflags);

    switch (dev->rbd_rsv.rrs_ack_needed) {
    case RSV_ACK_NEED_NONE:
        rna_spin_unlock_irqrestore(dev->rbd_event_lock, irqflags);
        rna_printk(KERN_RSV, "Dropping external ACK for dev [%s], not needed\n",
                   dev->name);
        break;      // nothing to do

    case RSV_ACK_NEED_CS:
        if (RSV_ACK_QUIESCE_COMPLETE == ack_phase) {
            dev->rbd_rsv.rrs_ack_needed = RSV_ACK_NEED_NONE;
            rna_spin_unlock_irqrestore(dev->rbd_event_lock, irqflags);

            ret = rnablk_send_master_rsv_access_resp(dev, generation);
            if (unlikely(0 != ret)) {
                rna_printk(KERN_ERR, "failed to send RSV_ACCESS_RESP for "
                           "dev [%s]: ret=%d\n", dev->name, ret);
            }
        } else {
            rna_spin_unlock_irqrestore(dev->rbd_event_lock, irqflags);
        }
        break;
            
    case RSV_ACK_NEED_CLIENT:
        /*
         * tgtd will send the ACK_QUIESCE_COMPLETE immediately if I/O is
         * already complete.  However, if there is outstanding I/O that
         * it needs to wait for, it will immediately send an
         * ACK_QUIESCE_INITIATED, and then after all I/O has finished
         * quiescing, it will send the ACK_QUIESCE_COMPLETE.
         *
         * The block client must restart I/O when it receives the
         * ACK_QUIESCE_INITIATED, or else the outstanding I/O can never
         * quiesce, since it is being held here in the block client.
         *
         * However, note that to handle the former case, where tgtd doesn't
         * send the ACK_QUIESCE_INITIATED, but only the ACK_QUIESCE_COMPLETE,
         * we need to make sure to clear the RBD_FIO_NEED_RSV_ACK flag and
         * restart I/O for either case (if needed).
         */
        switch (ack_phase) {
        case RSV_ACK_QUIESCE_COMPLETE:
            dev->rbd_rsv.rrs_ack_needed = RSV_ACK_NEED_NONE;

            /* fallthru to RSV_ACK_QUIESCE_INITIATED */

        case RSV_ACK_QUIESCE_INITIATED:
            if (atomic_bit_test_and_clear(&dev->rbd_io_allowed,
                                          RBD_FIO_NEED_RSV_ACK)
                && dev_io_allowed(dev)) {
                restart_dev_io = TRUE;
            }
            break;

        default:
            rna_printk(KERN_ERR, "Unexpected ack_phase [%d] for dev [%s]\n",
                       ack_phase, dev->name);
            break;
        }

        rna_spin_unlock_irqrestore(dev->rbd_event_lock, irqflags);

        if (restart_dev_io) {
            rna_printk(KERN_NOTICE, "restarting block queue for device [%s]\n",
                       dev->name);
            rnablk_queue_restart_dev_blks(dev);
        }
        break;
    }

    return;
}

/*
 * rnablk_do_rsv_access_resp
 *  This should only end up being called when rnablk is controlling
 *  reservation access.
 */
static void
rnablk_do_rsv_access_resp(struct rnablk_device *dev, boolean is_reduce,
                          uint32_t generation, boolean is_initial_check)
{
    rsv_access_t access;
    boolean send_resp = TRUE;

    if (is_reduce) {
        /* If we're reducing access, must wait for I/O to drain */

        access = dev->rbd_rsv.rrs_client_access;

        if (is_initial_check) {
            atomic_set(&dev->rbd_rsv.rrs_wait, TRUE);
        }

        if (0 != atomic_read(&dev->rbd_n_write)
            || (RSV_ACC_NONE == access && 0 != atomic_read(&dev->rbd_n_read))) {
            /* not quiesced yet */
            send_resp = FALSE;
        } else if (TRUE != atomic_cmpxchg(&dev->rbd_rsv.rrs_wait,
                                          TRUE, FALSE)) {
            /* somebody else beat us to it */
            send_resp = FALSE;
        }
    }

    if (send_resp) {
        rnablk_rsv_access_process_ack(dev, RSV_ACK_QUIESCE_COMPLETE, generation,
                                      FALSE);
    }

    return;
}

static void
rnablk_rsv_access_wf(rnablk_workq_cb_arg_t arg)
{
    struct work_struct *work = (struct work_struct *)arg;
    struct rnablk_work *w = container_of(work, struct rnablk_work, work);
    struct rnablk_rsv_access_wf_data *wd = &w->data.rwd_rnablk_rsv_access_wf;
    struct rnablk_device *dev = wd->dev;
    uint64_t       start_seconds = get_seconds();

    rna_printk(KERN_RSV, "rsv_access complete for [%s] access [%s]\n",
               dev->name, rsv_access_string(dev->rbd_rsv.rrs_client_access));

    if (unlikely(rnablk_dev_is_shutdown(dev)) ||
        unlikely(atomic_read(&shutdown))) {
        rna_printk(KERN_RSV, "shutting down, do nothing\n");
        goto out;
    }

    /* 'is_reduce' is TRUE because we only get here for "reduce" changes */
    rnablk_do_rsv_access_resp(dev, TRUE, dev->rbd_rsv.rrs_generation, FALSE);

 out:
    rnablk_dev_release(dev);
    rnablk_mempool_free(w, work_cache_info);
    rnablk_finish_workq_work(start_seconds);
}

static void
rnablk_queue_rsv_access_finish(struct rnablk_device *dev)
{
    struct rnablk_work *w = NULL;
    struct rnablk_rsv_access_wf_data *wd = NULL;

    if (likely(!rnablk_dev_is_shutdown(dev)) &&
        likely(!atomic_read(&shutdown))) {
        if (unlikely((w = rnablk_mempool_alloc( work_cache_info )) == NULL)) {
            rna_printk(KERN_ERR, "Failed to allocate workq item\n");
        } else {
            RNABLK_INIT_RNABLK_WORK(w, wd, rnablk_rsv_access_wf);
            rnablk_dev_acquire(dev);
            wd->dev = dev;
            /* this task allocates an ios, so use ios_workq */
            rna_queue_work(ios_workq, &w->work);
        }
    }
}

void
rnablk_dec_device_iocnt(struct rnablk_device *dev, boolean is_write)
{
    atomic_t *iocntp = is_write ? &dev->rbd_n_write : &dev->rbd_n_read;

    if (0 == atomic_dec_return(iocntp) && atomic_read(&dev->rbd_rsv.rrs_wait)) {
        /*
         * We still may have outstanding I/O that needs to complete,
         * (i.e. in the case where it's NOACCESS and there are still
         * outstanding reads).  But that's okay; queued task will
         * double-check.
         */
        rna_printk(KERN_RSV, "%s count went zero and have waiter; "
                   "queue rsv_access_finish\n", is_write ? "write" : "read");
        rnablk_queue_rsv_access_finish(dev);
    }
}

int
rnablk_reservation_access_check(struct rnablk_device *dev, rsv_access_t access)
{
    boolean is_write = FALSE;

    if (rsv_access_is_less(dev->rbd_rsv.rrs_client_access, access)
        && rnablk_controls_access(dev)) {
        return -EBUSY;
    }

    switch (access) {
    case RSV_ACC_READWRITE:
        atomic_inc(&dev->rbd_n_write);
        is_write = TRUE;
        break;
    case RSV_ACC_READONLY:
        atomic_inc(&dev->rbd_n_read);
        break;
    case RSV_ACC_NONE:
        return 0;
    }

    /*
     * Check for access again, in case we hit a race.
     */
    if (rsv_access_is_less(dev->rbd_rsv.rrs_client_access, access)
        && rnablk_controls_access(dev)) {
        rnablk_dec_device_iocnt(dev, is_write);
        return -EBUSY;
    }
    return 0;
}
