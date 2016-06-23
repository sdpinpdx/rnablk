/**
 * <eth_rdma.h> - Dell Fluid Cache block driver
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

#ifndef _ETH_RDMA_H_
#define _ETH_RDMA_H_

#include "platform.h"

#define ETH_RDMA_DATA_LEN 4096

#define ETH_RDMA_NUM_SEND_BUF 8
#define ETH_RDMA_NUM_RECV_BUF 8

#define ETH_MAX_SEND_RETRIES 10

#if defined(LINUX_USER) || defined(WINDOWS_USER)
#include "com.h"
#include "rna_com.h"
#include "eth_rkey.h"
struct com_ep;
struct buf_entry;
struct com_io_req;
#endif

enum com_rdma_status{
	RDMA_STATUS_OK,
	RDMA_STATUS_ERR,
	RDMA_STATUS_RKEY_INV,
	RDMA_STATUS_ADDR_INV,
	RDMA_STATUS_LEN_INV
};

enum com_rdma_msg_type{
	RDMA_MSG_TYPE_READ,
	RDMA_MSG_TYPE_WRITE,
	RDMA_MSG_TYPE_READ_RESP,
	RDMA_MSG_TYPE_WRITE_RESP
};

enum com_rdma_msg_flags{
	RDMA_MSG_FLAG_RESP_REQ = 0x01
};

DECLARE_PACKED_STRUCT(com_rdma_hdr) {
	uint32_t status;
	uint32_t flags;
	uint64_t cookie;
	uint64_t payload_len;
	uint64_t pkt_len;    /* May be less then len when the rdma operation is less the len */
	uint64_t pkt_offset; /* Start offset, nonzero when the rdma operation is broken up */
} END_PACKED_STRUCT(com_rdma_hdr);

INLINE void bswap_com_rdma_hdr(struct com_rdma_hdr *data)
{	
#if CPU_BE
	data->status = bswap_32(data->status);
	data->flags = bswap_32(data->flags);
	data->cookie = bswap_64(data->cookie);
	data->payload_len = bswap_64(data->payload_len);	
	data->pkt_len = bswap_64(data->pkt_len);	
	data->pkt_offset = bswap_64(data->pkt_offset);	
#endif
}

DECLARE_PACKED_STRUCT(com_rdma_req) {
	rna_addr_t addr;
	uint64_t rkey;
	uint64_t len;
    uint64_t bounce_buf_addr;
} END_PACKED_STRUCT(com_rdma_req);

INLINE void bswap_com_rdma_req( struct com_rdma_req *data )
{
#if CPU_BE
	data->addr.base_addr = bswap_64(data->addr.base_addr);
	data->addr.device_id = bswap_64(data->addr.device_id);
	data->len = bswap_64(data->len);
	data->rkey = bswap_64(data->rkey);
#endif
}

DECLARE_PACKED_STRUCT(com_rdma_read_resp) {
	uint8_t data[1];
} END_PACKED_STRUCT(com_rdma_read_resp);

INLINE void bswap_com_rdma_read_resp(struct com_rdma_read_resp *data)
{
#if CPU_BE
	//uint8_t data[ETH_RDMA_DATA_LEN];
#endif
}

DECLARE_PACKED_STRUCT(com_rdma_write_resp) {
	uint8_t unused;
} END_PACKED_STRUCT(com_rdma_write_resp);

INLINE void bswap_com_rdma_write_resp(struct com_rdma_write_resp *data)
{
#if CPU_BE
	bswap_com_rdma_hdr(&data->hdr);
	//uint8_t status;
#endif
}

DECLARE_PACKED_STRUCT(com_rdma_msg) {
	uint32_t msg_type;  /* com_rdma_msg_type (RDMA_MSG_TYPE_*, not ETH_IO_*) */
	struct com_rdma_hdr hdr;
	union {
		struct com_rdma_req        com_rdma_req;
		struct com_rdma_read_resp  com_rdma_read_resp;
		struct com_rdma_write_resp com_rdma_write_resp;
	}u;
} END_PACKED_STRUCT(com_rdma_msg);

INLINE void bswap_com_rdma_msg(struct com_rdma_msg *data){
#if CPU_BE
	data->msg_type = bswap_32(data->msg_type);
	data->flags = bswap_32(data->flags);
	
	bswap_com_rdma_hdr(&data->hdr);
	
	switch(data->msg_type){
		case RDMA_MSG_TYPE_READ:
		case RDMA_MSG_TYPE_WRITE:
			bswap_com_rdma_req(&data->u.com_rdma_req);
			break;
		case RDMA_MSG_TYPE_READ_RESP:
			bswap_com_rdma_read_resp(&data->u.com_rdma_read_resp);
			break;
		case RDMA_MSG_TYPE_WRITE_RESP:
			bswap_com_rdma_write_resp(&data->u.com_rdma_write_resp);
			break;
		default:
#if defined(LINUX_USER) || defined(WINDOWS_USER)
			printf("bswap_cache_cmd: type mismatch: %d\n",data->type);
			assert(0);
#endif
			break;	
	}	
#endif
	
}

INLINE void bswap_com_conx_reply(struct com_conx_reply *data)
{
#if CPU_BE
    data->version = bswap_32(data->version);
    data->proto_version = bswap_32(data->proto_version);
    bswap_in_addr(&data->src_addr);
    data->port = bswap_32(data->port);
    data->status = bswap_32(data->status);
    bswap_rna_addr_t(&data->bounce_buffer_addr);
    bswap_rna_rkey_t(&data->bounce_buffer_rkey);
    data->bounce_buffer_size = bswap_64(data->bounce_buffer_size);
#else
	UNREFERENCED_PARAMETER(data);
#endif
}

#if defined(LINUX_USER) || defined(WINDOWS_USER)
struct ethconx_entry;
extern int eth_rdma_completion(struct eth_rkey_hdl *hdl, struct com_ep *ep, char *ep_name, struct ethconx_entry *eth_conx, char ep_user_type, void *buf, uint64_t buf_offset, uint64_t *buf_len);
extern int eth_do_rdma_read(struct com_ep *ep, struct buf_entry *rdma_buf, struct ethconx_entry *eth_conx,
                 user_type_t ep_user_type, struct com_mr_region *reg, rna_addr_t remote_addr,
                 rna_rkey_t remote_rkey, rna_addr_t local_addr, int size, void *context, char signaled, uint32_t flags);
extern int eth_do_rdma_write(struct com_ep *ep, struct buf_entry *rdma_buf, struct ethconx_entry *eth_conx,
				  user_type_t ep_user_type, struct  com_mr_region *reg, rna_addr_t remote_addr,
				  rna_rkey_t remote_rkey, rna_addr_t local_addr, int size, void *context, char signaled, uint32_t flags);		
extern int eth_send_read_resp(struct com_ep *ep, uint64_t cookie, int status, rna_addr_t addr, struct rna_reg_buffer *buf, uint64_t len, rna_rkey_t rkey);
extern int eth_send_write_resp(struct com_ep *ep, uint64_t cookie, int status);

extern int ib_send_read_resp(struct com_ep *ep, uint64_t cookie, int status, 
                             rna_addr_t addr, struct rna_reg_buffer *buf, 
                             uint64_t len, rna_rkey_t rkey,
                             uint64_t bb_addr);
int ib_send_write_resp(struct com_ep *ep, uint64_t cookie, int status);
int ib_do_rdma_write(struct com_ep *ep,
                     struct buf_entry *rdma_buf,
                     struct  com_mr_region *reg,
                     rna_addr_t remote_addr,
                     rna_rkey_t remote_rkey,
                     rna_addr_t local_addr,
                     int size,
                     void *context,
                     char signaled,
                     uint32_t flags);
int ib_do_rdma_read(struct com_ep *ep,
                    struct buf_entry *rdma_buf,
                    struct  com_mr_region *reg,
                    rna_addr_t remote_addr,
                    rna_rkey_t remote_rkey,
                    rna_addr_t local_addr,
                    int size,
                    void *context,
                    char signaled,
                    uint32_t flags);


/* rdma_server.c operations */
extern int send_read_resp(struct com_ep *ep, uint64_t cookie, int status, 
                          rna_addr_t addr, struct rna_reg_buffer *buf, 
                          uint64_t len, rna_rkey_t rkey, uint64_t bb_addr);
extern int send_write_resp(struct com_ep *ep, uint64_t cookie, int status);
extern int process_rdma_read_req(struct eth_rkey_hdl *rkey_hdl, struct com_ep *ep, struct com_rdma_msg *req);
struct com_inbound_rdma_write_ctx;
extern void inbound_rdma_write_final_completion(void *cb_ctx);
extern int process_rdma_write_req(struct com_inbound_rdma_write_ctx *rdma_ctx,
                                  char *data, uint64_t offset, uint64_t *data_len);
struct com_inbound_rdma_read_resp_ctx;
extern int process_rdma_read_response(struct com_inbound_rdma_read_resp_ctx *rdma_ctx, 
                                      char *data, int offset, uint64_t *data_len);
extern int process_rdma_write_response(struct com_ep *ep, com_ep_handle_t *eph, 
                                       struct com_io_req *p_io_req, 
                                       struct com_rdma_msg *rdma_msg);
#endif

/**
 * Debugging functions, for helping to figure out mismatches between client
 * and server.  Comment or ifdef these out when things start working.
 */
void rna_debug_print_com_rdma_hdr(int dbg_level, const char *caller, struct com_rdma_hdr * hdr);
char * rna_dbg_get_com_msg_type(uint8_t type);
char * rna_dbg_get_com_status_type(uint8_t type);

#define ETH_RDMA_BUF_SIZE sizeof(struct com_rdma_msg)

/* How much of the bounce buffer can be used for one IO */
#define CS_DEFAULT_BOUNCE_BUFFER_SEGMENT_BYTES (32 * 1024L)

/* 
 * Total space for bounce buffer (currently using 32-bit atomic to track what's
 * available)
 */
#define CS_DEFAULT_NUM_BOUNCE_BUFFER_SEGMENTS (32L)

#define CS_DEFAULT_BOUNCE_BUFFER_BYTES \
                                  (CS_DEFAULT_NUM_BOUNCE_BUFFER_SEGMENTS * \
                                   CS_DEFAULT_BOUNCE_BUFFER_SEGMENT_BYTES)
#endif /* _ETH_RDMA_H_ */
