/**
 * <rna_com_envelope.h> - Dell Fluid Cache block driver
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

#pragma once

#include "platform.h"

#if defined(LINUX_USER) || defined(WINDOWS_USER)
#include "com.h"
#include "rna_com.h"
#include "eth_rkey.h"
#else
struct com_ep;
#include "rna_byteswap.h"
#include "rna_types.h"

#endif

#define ENVELOPE_MAGIC_COOKIE 0x171E
#define ENVELOPE_VERSION      0x0003

/* High bit of recv_acks field is to ack an unsolicited ack. */
#define ACK_ACK_BIT           15

/* 
 * When simulating rdmas via sends, we enforce a minimum send buffer
 * size so that we always have room for the rdma header and a
 * reasonably-sized payload.
 */
#define DEFAULT_RDMA_SENDBUF_PAYLOAD 8192
#define MAX_RDMA_VIA_SEND_SIZE (DEFAULT_RDMA_SENDBUF_PAYLOAD)
#define DEFAULT_RDMA_SENDBUF_SIZE                                   \
    (DEFAULT_RDMA_SENDBUF_PAYLOAD + sizeof(struct com_rdma_msg))

#define DEFAULT_RDMA_BOUNCE_BUFFER_MAX_IO_SIZE      (32 * 1024)

enum env_type{
	ENV_TYPE_UNSET,     // Invalid
	ENV_TYPE_HANDSHAKE, // Handshake (used in TCP for connection setup)
	ENV_TYPE_PROTO,     // Protocol Message
	ENV_TYPE_RDMA,      // RDMA Message (fake RDMA I/O)
	ENV_TYPE_ACK        // Empty envelope used by unsolicited ack
};

DECLARE_PACKED_STRUCT(rna_com_envelope) {
    uint16_t envelope_boundary;   // set to ENVELOPE_MAGIC_COOKIE
    uint16_t envelope_version;    // set to ENVELOPE_VERSION
    uint16_t rna_connection_type; // see the user_type enum in protocol.h for values
    uint16_t msg_type;            // Handshake(private data), RDMA, or proto message
    uint32_t msg_body_size;       // size of message body
    uint32_t tid;                 // transaction id. (for tracing messages)
    uint16_t recv_acks;           // messages recieved and processed since last ack, 
                                  // high bit acks unsolicited ack
    uint16_t pad;
} END_PACKED_STRUCT(rna_com_envelope);

/**
 * byteswap the envelope - Necessary to call when pulling the envelope off the 
 * in order to maintain compatibility between different Endian based systems 
 */
INLINE void bswap_com_envelope(struct rna_com_envelope *e)
{
#if CPU_BE
	e->envelope_boundary = bswap_16(e->envelope_boundary);
	e->envelope_version = bswap_16(e->envelope_version);
	e->rna_connection_type = bswap_16(e->rna_connection_type);
	e->msg_type = bswap_16(e->msg_type);
	e->msg_body_size = bswap_32(e->msg_body_size);
	e->tid = bswap_32(e->tid);
	e->recv_acks = bswap_16(e->recv_acks);
#endif
}

/**
 * initialize an rna_com_envelope struct
 *
 * @param env - the rna_com_envelope struct
 * @param user_type - the type of the sender - helpful when / if messages of different types are sent on same socket
 * @param msg_size - size of this message payload
 * @param msg_type - @see struct env_type type. (HANDSHAKE,PROTO,RDMA)
 * @param tid - transaction ID for debugging
 * @param recv_acks - count of newly freed recv buffers, 
 *                    to notify peer of its send window
 */
INLINE void 
com_envelope_init(struct rna_com_envelope *env, user_type_t user_type,
                  uint32_t msg_size, int msg_type, uint32_t tid,
                  uint16_t recv_acks)
{
    env->envelope_boundary   = ENVELOPE_MAGIC_COOKIE;
    env->envelope_version    = ENVELOPE_VERSION;
    env->rna_connection_type = (uint16_t)user_type;
    env->msg_type            = msg_type;
    env->msg_body_size       = msg_size;
    env->tid                 = tid;
    env->recv_acks           = recv_acks;
    env->pad                 = 0;
}

/**
 * Return the number of receives for which we have not yet sent an ack,
 * usually used to get the recv_acks argument to com_envelope_init.  
 * Resets the counter to zero.  We don't have to do this for every 
 * envelope we send, but we should.
 */
uint16_t
com_get_reset_unacked_recvs(struct com_ep *ep);

/**
 * In case we decide not to send a message, we need to 
 * return the acks we did not send. 
 */
void
com_restore_unacked_recvs(struct com_ep *ep, struct rna_com_envelope *env);

/** 
 * Pull acks from an envelope, do necessary accounting to increase the
 * send window, and/or queue necessary work.  We must call this once
 * for every envelope we receive.
 */
void
com_process_acks(struct com_ep *ep, struct rna_com_envelope *env);

/**
 * Validate that an envelope is valid and matches our version
 *
 * @param env - the rna_com_envelope struct
 */
INLINE int 
com_envelope_validate( struct rna_com_envelope *env )
{
	if((env->envelope_boundary == ENVELOPE_MAGIC_COOKIE) &&
	   (env->envelope_version == ENVELOPE_VERSION)){
		return 0;
	}
	
	return -1;
}
