/**
 * <rnablk_cache.h> - Dell Fluid Cache block driver
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
#include "rnablk_globals.h"
#ifdef WINDOWS_KERNEL
#include "comAPIPublic.h"
#endif

#define MD_CONN_EP_METAVALUE  ((void*)1)

struct cachedev_list {
    cachedev_id_t cdl_ids[MAX_CACHE_DEVICES_PER_CLUSTER];
    int cdl_n_cachedevs;
};


int rnablk_cache_connected(struct com_ep *ep);
void rnablk_blk_put_cachedev(struct cache_blk *blk,
                             struct rnablk_server_conn *conn);
void rnablk_put_cachedev(rnablk_cachedev_t *cachedev);
void rnablk_process_conn_disconnect(struct rnablk_server_conn *conn);

INLINE int rnablk_conn_connected (struct rnablk_server_conn *conn)
{
    return ((NULL != conn) &&
            (RNABLK_CONN_CONNECTED == atomic_read(&conn->state)));
}

struct com_ep * rnablk_conn_get_ep(struct rnablk_server_conn *conn);


struct rnablk_server_conn *
rnablk_make_server_conn(struct rna_service_id *service_id,
                        struct rna_if_table *if_table,
                        struct rnablk_server_conn *p_conn,
                        rnablk_cachedev_t *cachedev,
                        int idx);

void
rnablk_queue_conn_disconnect(struct rnablk_server_conn *conn);

void
rnablk_queue_ios_timeout_conn_disconnect(struct io_state *ios);

void
rnablk_drop_connection(struct rnablk_server_conn *conn);

boolean
rnablk_detect_cache_failure_debug(const char *function, const int line,
                                  struct io_state *ios, int ios_status,
                                  int cachedev_fail_status, boolean notify_cs);

#define rnablk_detect_cache_failure(io, err, fs, n) \
    rnablk_detect_cache_failure_debug(__FUNCTION__, __LINE__, (io), \
                                     (err), (fs), (n))


int rnablk_verify_conn(struct rnablk_server_conn *conn);

void rnablk_disconnect_cache(struct rnablk_device *dev);

void rnablk_undo_conn_io(struct io_state *ios, boolean lock_held);

void
rnablk_trigger_offline_cache_device(struct rnablk_server_conn *conn,
                                    cachedev_id_t cachedev_id, int reason);

INLINE struct com_ep *rnablk_get_ios_ep(struct io_state *ios)
{
    BUG_ON(NULL==ios);
    if (RNABLK_MD_QUERY == ios->type) {
        return MD_CONN_EP_METAVALUE;
    } else {
        return ios->ep;
    }
}

void
rnablk_md_send_cache_query_from_md_response(
                            rna_service_metadata_query_response_t *resp,
                            struct io_state                       *ios);

rnablk_cachedev_t *
rnablk_get_conn_cachedev(struct rnablk_server_conn *conn,
                         cachedev_id_t cachedev_id,
                         boolean do_insert);
int
rnablk_blk_get_cachedev(struct cache_blk *blk,
                        cachedev_id_t cachedev_id,
                        struct rnablk_server_conn *conn,
                        boolean);

struct rnablk_server_conn *
rnablk_next_cachedev_conn(rnablk_cachedev_t *cachedev);

void rnablk_init_null_structs(void);

void rnablk_free_server_conns(void);
void rnablk_cleanup_blk(struct cache_blk *blk);

INLINE struct rnablk_server_conn *rnablk_get_ep_conn(struct com_ep *ep)
{
    struct rnablk_server_conn * conn = NULL;
    if (NULL != ep) {
        if (unlikely(MD_CONN_EP_METAVALUE==ep)) {
            conn = g_md_conn;
        } else {
#ifdef WINDOWS_KERNEL
			conn = (struct rnablk_server_conn *)com_get_ep_context(ep);
#else
            conn = (struct rnablk_server_conn *)ep->context;
#endif /*WINDOWS_KERNEL*/
        }
    }
    return conn;
}

INLINE struct rnablk_server_conn *rnablk_get_ios_conn(struct io_state *ios)
{
    BUG_ON(NULL==ios);
    return rnablk_get_ep_conn(ios->ep);
}

int rnablk_verify_conn_in_tree(struct rb_root            *root,
                               struct rnablk_server_conn *conn);

INLINE const char * rnablk_conn_state_string(rnablk_conn_state state)
{
    const char * ret= "Unknown";

    switch (state) {
        case RNABLK_CONN_DISCONNECTED: ret = "RNABLK_CONN_DISCONNECTED"; break;
        case RNABLK_CONN_CONNECT_PENDING: ret = "RNABLK_CONN_CONNECT_PENDING"; break;
        case RNABLK_CONN_CONNECTED: ret = "RNABLK_CONN_CONNECTED"; break;
        case RNABLK_CONN_DISCONNECT_PENDING: ret = "RNABLK_CONN_DISCONNECT_PENDING"; break;
        case RNABLK_CONN_DISCONNECT_INPROG: ret = "RNABLK_CONN_DISCONNECT_INPROG"; break;
    }
    return ret;
}

int rnablk_server_conn_debug_dump(struct rnablk_server_conn *conn);
int rnablk_cache_conn_foreach(RNABLK_CACHE_FOREACH_CB cb,
                              void                   *ctx);

void rnablk_operate_on_conn_cachedevs(struct rnablk_server_conn *conn,
                                 rnablk_cachedev_t *cachedev,
                                 void *func_arg,
                                 void  per_cachedev_func(
                                       struct rnablk_server_conn *,
                                       rnablk_cachedev_t *,
                                       void *));
void rnablk_detached_shutdown_cleanup_conns(void);

void rnablk_check_for_expelled_cachedevs(
                                 rna_service_unexpelled_cachedevs_t *uc);
int rnablk_get_conn_cachedev_list(struct rnablk_server_conn *conn,
                                  void *opaque_arg);
