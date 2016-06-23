/**
 * <rnablk_protocol.h> - Dell Fluid Cache block driver
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

void
rnablk_process_recv_cmp(struct cache_cmd *cmd,
                        struct com_ep    *ep,
                        int               status);

void
rnablk_create_change_ref_cmd(struct cache_cmd *cmd,
                             struct io_state *ios,
                             uint64_t rid,
                             struct cache_blk *blk,
                             cache_lock_t orig_ref,
                             cache_lock_t desired_ref,
                             uint32_t flags);

int
rnablk_cache_blk_send_change_ref(struct cache_blk       *blk,
                                 cache_lock_t           new_ref,
                                 uint32_t               flags);

void
rnablk_send_fail_cachedev(struct rnablk_server_conn *conn,
                          cachedev_id_t cachedev_id,
                          boolean send_response);

void rnablk_register_cs_conn_with_cfm(struct rnablk_server_conn *conn);

void rnablk_deregister_cs_conn_with_cfm(struct rnablk_server_conn *conn);

int
rnablk_send_deref_complete(struct com_ep *ep,
                           uint32_t       requested_bytes,
                           uint32_t       derefed_bytes);

void
rnablk_process_cache_invd(struct com_ep    *ep,
                          struct cache_cmd *cmd,
                          boolean is_from_sysfs);

void
rnablk_lock_master_blk(struct rnablk_device *dev);

void rnablk_master_lock_unregister(struct cache_blk *blk);

int rnablk_service_init(void *arg);
int rnablk_process_cfms_update(int cfm_count, struct sockaddr_in *online_cfms);
int rnablk_metadata_query(struct io_state *ios);
int rnablk_cache_block_query(struct io_state *ios, struct buf_entry *buf_entry);
int dispatch_generic_cmd(struct io_state *ios, struct buf_entry *buf_entry);

void rnablk_process_detach(void);
void rnablk_process_rejoin(void);

INLINE int
dispatch_scsi_passthru(struct io_state *ios, struct buf_entry *buf_entry)
{
    return dispatch_generic_cmd(ios, buf_entry);
}

void rnablk_dec_device_iocnt(struct rnablk_device *dev, boolean is_write);

int rnablk_reservation_access_check(struct rnablk_device *dev, 
                                    rsv_access_t access);

void rnablk_rsv_access_process_ack(struct rnablk_device *dev,
                              rsv_ack_phase ack_phase,
                              uint32_t generation,
                              boolean is_external_ack);
