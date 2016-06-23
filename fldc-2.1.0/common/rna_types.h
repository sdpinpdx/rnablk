/**
 * <rna_types.h> - Dell Fluid Cache block driver
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

#if defined(LINUX_USER) || defined(WINDOWS_USER)
#include <stdio.h>
#include <string.h>
#endif

#ifdef WINDOWS_KERNEL
#include <stdio.h>
#endif

#include "platform.h"
#include "platform_network.h"

/** Maximum length of the pathname allowed
*/
#define RNABLK_SECTOR_SIZE              512
#define RNABLK_SECTOR_SHIFT             9

/// Maximum number of backing stores/cached luns and block devices allowed
#define RNA_MAX_BACKING_STORES          64

#define DEFAULT_BLOCK_SIZE              (512 * 1024)
#define RNA_SHARED_IO_TIMEOUT_SECONDS   (120)

#define IOV_ENTRY_SRC_BASE_ADDR(iov, entry) iov[entry].iov_src_offset
#define IOV_SRC_BASE_ADDR(iov) IOV_ENTRY_SRC_BASE_ADDR(iov, 0)

#define IOV_ENTRY_DST_BASE_ADDR(iov, entry) iov[entry].iov_dst_offset
#define IOV_DST_BASE_ADDR(iov) IOV_ENTRY_DST_BASE_ADDR(iov, 0)

/** Connection Type identifier. Used when establishing a connection between components.
Each type will have an associated message length.
*/
typedef enum {
	USR_TYPE_CACHE=1,   /**< Used for client-CS connections */
	USR_TYPE_META_CACHE,
	USR_TYPE_CACHE_CLIENT, /**< Used for CS-CS connections */
	USR_TYPE_META_CLIENT,
	USR_TYPE_CFM,       /**< Used to download the configuration from the cfm */
	USR_TYPE_CFM_PEER,
	USR_TYPE_CFM_META,
	USR_TYPE_CFM_CACHE,
	USR_TYPE_CFM_CLIENT,
	USR_TYPE_CFM_AGENT, /* =10 */
	USR_TYPE_AGENT,
	USR_TYPE_RFT,
	USR_TYPE_PAXOS,
	USR_TYPE_MD_SYNC,   /**< Used to sync metadata partition mirrors */
	USR_TYPE_COM_RDMA,  /* Used in COM library as an internal RDMA channel */
	USR_TYPE_MCP,       /**< Master Control Program */
	USR_TYPE_INTERNAL,  /**< XXX: HACK used for internal cache references */
	USR_TYPE_CFM_JOURNAL, /**< Used for journal operations between CFMs */

    /* 
     * Used for the unit test client.  Keep this last and keep it the same
     * value as found in comtest_protocol.h.
     */
    USR_TYPE_UNIT_TEST_CLIENT = 254,
} user_type_t;

INLINE const char * get_user_type_string (user_type_t type)
{
    const char * ret = "Unknown";

	switch(type){
		case USR_TYPE_CACHE:
			ret = "Cache Client";
            break;
		case USR_TYPE_META_CACHE:
			ret = "Meta Cache";
            break;
		case USR_TYPE_CACHE_CLIENT:
			ret = "Cache Cache";
            break;
		case USR_TYPE_META_CLIENT:
			ret = "Meta Client";
            break;
		case USR_TYPE_CFM:
			ret = "CFM";
            break;
		case USR_TYPE_CFM_META:
			ret = "CFM Meta";
            break;
		case USR_TYPE_CFM_CACHE:
			ret = "CFM Cache";
            break;
		case USR_TYPE_CFM_CLIENT:
			ret = "CFM Client";
            break;
		case USR_TYPE_CFM_AGENT:
			ret = "CFM Agent";
            break;
		case USR_TYPE_AGENT:
			ret = "Agent";
            break;
		case USR_TYPE_RFT:
			ret = "RFT";
            break;
		case USR_TYPE_COM_RDMA:  
			ret = "Com RDMA";	
            break;
        case USR_TYPE_CFM_PEER:
            ret = "Peer configuration manager";
            break;
        case USR_TYPE_PAXOS:
            ret = "Peer Metadata Server";
            break;
        case USR_TYPE_MCP:
            ret = "Master Control Program";
            break;
        case USR_TYPE_MD_SYNC:
            ret = "Metadata Sync";
            break;
        case USR_TYPE_INTERNAL:
            ret = "Internal";
            break;
        case USR_TYPE_CFM_JOURNAL:
            ret = "CFM journal manager";
            break;
        case USR_TYPE_UNIT_TEST_CLIENT:
            ret = "unit tester";
            break;
	}
	return ret;
}

typedef uint64_t rna_rkey_t;


typedef union {
    uint64_t     data;
    struct {
        uint32_t dev_num;
        int32_t  fd; /* it is important that this is signed (`man open`) */
    } info;
} rna_device_id_t;

typedef struct rna_addr {
    rna_device_id_t device_id;
    uint64_t        base_addr;
}rna_addr_t;

typedef struct rna_iovec {
    void *incoming_ep;      /* If not NULL, indicates the com_ep on
                             * which the data was written.  It's NULL
                             * for other types of operations (e.g., compare
                             * and write or write same). */
    int from_in_ep_bb;      /* Signals that the data is from incoming ep's 
                             * bounce buffer */
    off_t iov_src_offset;   /* absolute offset into the src */
    size_t iov_len;         /* length of data */
    off_t iov_dst_offset;   /* absolute offset into the dst */
} rna_iovec_t;

/* Given two addr_ts and corresponding lengths, return true if the
 * region described by the second addr_t and length is a subregion of
 * the first addr_t and length. */
/* Removed comparing lengths to 'greater than or equal' to zero as 
 * they are unsigned they will always be greater than or equal to zero.
 * MSFT kernel compiler enables all warnings which is why it was found there.
 */ 
INLINE int
rna_addr_t_is_subregion(rna_addr_t a, uint64_t alen, rna_addr_t b, uint64_t blen)
{
   return b.base_addr >= a.base_addr && 
          b.base_addr + blen <= a.base_addr + alen;
}

INLINE rna_addr_t
ptr_to_rna_addr_t(void *ptr)
{
    rna_addr_t addr;
    addr.device_id.data = 0;
    addr.base_addr = (uint64_t)ptr;
    
    return addr;
}

INLINE int 
rna_device_id_t_equal(rna_device_id_t a, rna_device_id_t b)
{
    return a.data == b.data;
}

INLINE int
rna_device_id_t_iszero(rna_device_id_t a)
{
    return a.data == 0;
}

typedef enum {
    COM_CONX_OK,
    COM_CONX_FAILED
} com_conx_status;

/* Reply to a conection request.  This needs to match user-space headers. */
DECLARE_PACKED_STRUCT(com_conx_reply) {
    uint32_t version;          /* Com version */
    uint32_t proto_version;    /* Negotiated application protocol version */
    struct in_addr src_addr;   /* Tell caller what address they are sending from */
    uint32_t src_port;
    uint32_t status;
    /* 
     * Used to map the bounce buffer address when local 
     * XXX Not applicable to SAN and currently not fully implemented for DAS.
     */
    uint64_t src_pid;
    /* Allows sender to DMA to these addresses to avoid memory copies */
    rna_addr_t bounce_buffer_addr;
    /* 
     * DMA address size. (Other side of the connection may carve it up 
     * as it wishes 
     */
    uint64_t bounce_buffer_size;
    /* RKEY. Non-zero when RDMA may be used with the bounce buffer */
    rna_rkey_t bounce_buffer_rkey;
} END_PACKED_STRUCT(com_conx_reply);
/*
 * SCSI Reservation related definitions/data structs
 */

#define MAX_PER_CLIENT_INITIATORS   8       // maximum supported SCSI
                                            // "initiators" per client.

typedef uint64_t rsv_key_t;     // PERSISTENT_RESERVE reservation key

#define RSV_KEY_UNREGISTERED            0

DECLARE_PACKED_STRUCT(rsv_client_id) {
    unsigned char _rci_id[16];
} END_PACKED_STRUCT(rsv_client_id);

#define match_client_id(c1, c2) \
    (memcmp((c1)._rci_id, (c2)._rci_id, sizeof((c1)._rci_id)) == 0)

static rsv_client_id_t NULL_RSV_CLIENT_ID;

INLINE rsv_client_id_t
null_rsv_client_id_use_var(void)
{
    /* quiet compiler warning turned to error about unused variable */
    return NULL_RSV_CLIENT_ID;
}

INLINE void 
_rsv_client_id_to_str(rsv_client_id_t *p_cid, char *str, int maxlen)
{
    if (maxlen > 0) {
        snprintf(str, maxlen, "%02hhx%02hhx%02hhx%02hhx-%02hhx%02hhx-"
            "%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
           p_cid->_rci_id[0], p_cid->_rci_id[1], p_cid->_rci_id[2],
           p_cid->_rci_id[3], p_cid->_rci_id[4], p_cid->_rci_id[5],
           p_cid->_rci_id[6], p_cid->_rci_id[7], p_cid->_rci_id[8],
           p_cid->_rci_id[9], p_cid->_rci_id[10], p_cid->_rci_id[11],
           p_cid->_rci_id[12], p_cid->_rci_id[13], p_cid->_rci_id[14],
           p_cid->_rci_id[15]);
        str[maxlen-1] = '\0';
    }
}

INLINE char *
rsv_client_id_get_string(rsv_client_id_t *p_cid)
{
    static char client_str[64];
    
    _rsv_client_id_to_str(p_cid, client_str, sizeof(client_str));
    return client_str;
}

/* returns 1 on success, 0 on failure */
INLINE int
rsv_str_to_client_id(rsv_client_id_t *p_cid, char *str)
{
    int c, csub;
    int i, j;

    if (NULL == str) {
        goto bad;   // no client string provided!
    }

    for (i = 0; i < sizeof(*p_cid) && *str; i++) {
        while (*str == '-' && *str) {
            str++;
        }
        if (*(str+1) == 0 || *(str+1) == '-') {
            goto bad;   // bad format
        }

        c = 0;
        for (j = 0; j < 2; j++) {
            c *= 16;
            csub  = *str++;
            if (csub >= '0' && csub <= '9') {
                csub -= '0';
            } else if (csub >= 'A' && csub <= 'F') {
                csub = 10 + (csub - 'A');
            } else if (csub >= 'a' && csub <= 'f') {
                csub = 10 + (csub - 'a');
            } else {
                goto bad;   // bad format
            }
            c += csub;
        }
        p_cid->_rci_id[i] = (uint8_t)c;
    }
    if (i != sizeof(*p_cid) || *str) {
        goto bad;           // bad length
    }
    return 1;

 bad:
    memset(p_cid, 0, sizeof(*p_cid));
    return 0;
}

INLINE void
rsv_copy_client_id(rsv_client_id_t *c_dst, rsv_client_id_t *c_src)
{
    memcpy(c_dst->_rci_id, c_src->_rci_id, sizeof(*c_dst));
}

DECLARE_PACKED_STRUCT(rsv_initiator) {
    unsigned char _ri_id[20];
} END_PACKED_STRUCT(rsv_initiator);

#define match_initiator(i1, i2) \
    (memcmp((i1)._ri_id, (i2)._ri_id, sizeof((i1)._ri_id)) == 0)

static rsv_initiator_t NULL_RSV_INITIATOR;

INLINE rsv_initiator_t
null_rsv_initiator_use_var(void)
{
    /* quiet compiler warning turned to error about unused variable */
    return NULL_RSV_INITIATOR;
}

#ifndef WINDOWS_KERNEL
INLINE void
_rsv_initiator_to_str(rsv_initiator_t *p_ini, char *str, int maxlen)
{
    int ret, len = 0;
    int i;

    if (maxlen > 0) {
        maxlen -= 1;        // make sure there's room for EOS

        for (i = 0; i < sizeof(*p_ini) && len < maxlen; i++) {
            ret = snprintf(str+len, maxlen - len,
                           "%02hhx", p_ini->_ri_id[i]);
            len += ret;
        }
        str[maxlen-1] = '\0';
    }
}

INLINE char *
rsv_initiator_get_string(rsv_initiator_t *p_ini)
{
    static char initiator_str[64];

    _rsv_initiator_to_str(p_ini, initiator_str, sizeof(initiator_str));
    return initiator_str;
}
#endif /* !WINDOWS_KERNEL */

INLINE void
rsv_copy_initiator(rsv_initiator_t *i_dst, rsv_initiator_t *i_src)
{
    memcpy(i_dst->_ri_id, i_src->_ri_id, sizeof(i_dst->_ri_id));
}

DECLARE_PACKED_STRUCT(rsv_itn_id) {
    rsv_client_id_t     _rii_client_id;
    rsv_initiator_t     _rii_ini_id;
} END_PACKED_STRUCT(rsv_itn_id);

#define rsv_itn_client(ip)      ((ip)->_rii_client_id)
#define rsv_itn_initiator(ip)   ((ip)->_rii_ini_id)

static rsv_itn_id_t NULL_RSV_ITN_ID;

INLINE rsv_itn_id_t null_rsv_itn_id_use_var(void)
{
    /* quiet compiler warning turned to error about unused variable */
    return NULL_RSV_ITN_ID;
}

#define match_itn_id(i1, i2)    \
    (match_client_id((i1)->_rii_client_id, (i2)->_rii_client_id) \
     && match_initiator((i1)->_rii_ini_id, (i2)->_rii_ini_id))

#define match_itn_id_for_client(ip, c) \
        match_client_id((ip)->_rii_client_id, (c))

#define match_itn_id_for_initiator(ip, i) \
        match_initiator((ip)->_rii_ini_id, (i))


#define rsv_itn_id_fmt          "%s:%s"
#define rsv_itn_id_string(idp) \
    rsv_client_id_get_string(&(idp)->_rii_client_id), \
    rsv_initiator_get_string(&(idp)->_rii_ini_id)



INLINE void
rsv_make_itn_id(rsv_itn_id_t *itn_id, rsv_client_id_t *client_id,
                rsv_initiator_t *initiator)
{
    memcpy(&itn_id->_rii_client_id, client_id, sizeof(itn_id->_rii_client_id));
    memcpy(&itn_id->_rii_ini_id, initiator, sizeof(itn_id->_rii_ini_id));
}

INLINE void
rsv_copy_itn_id(rsv_itn_id_t *p_dst, rsv_itn_id_t *p_src)
{
    memcpy(p_dst, p_src, sizeof(*p_dst));
}

/* SCSI-2 or SCSI-3 reservation */
typedef enum {
    RSV_MODE_NONE,
    RSV_MODE_SCSI2,
    RSV_MODE_SCSI3,
} rsv_mode_t;

INLINE const char *
get_rsv_mode_t_string(rsv_mode_t mode) {
    switch (mode) {
    case RSV_MODE_NONE:
        return "RSV_MODE_NONE";
        break;
    case RSV_MODE_SCSI2:
        return "RSV_MODE_SCSI2";
        break;
    case RSV_MODE_SCSI3:
        return "RSV_MODE_SCSI3";
        break;
        /* no default - handle all cases */
    }
    return "!UNKNOWN!";
}

/*
 * Reservation types.
 *  Note that the only reservation types supported for our initial
 *  release are RSV_TYPE_EXCL and RSV_TYPE_WRITE_RO
 *  (because this is all Compellent supports).
 *  (SCSI-2 reservations are RSV_TYPE_EXCL.)
 */
typedef enum {
    RSV_TYPE_INVALID    = -1,
    RSV_TYPE_NONE       = 0x00,         // no reservation
    RSV_TYPE_EXCL       = 0x10,         // Exclusive reservation
    RSV_TYPE_EXCL_RO    = 0x11,         // Exclusive / Registrants Only
    RSV_TYPE_EXCL_AR    = 0x12,         // Exclusive / All Registrants
    RSV_TYPE_WRITE      = 0x20,         // Write-Exclusive reservation
    RSV_TYPE_WRITE_RO   = 0x21,         // Write-Exclusive / Registrants Only
    RSV_TYPE_WRITE_AR   = 0x22,         // Write-Exclusive / All Registrants
} rsv_type_t;

INLINE const char *
get_rsv_type_t_string(rsv_type_t type) {
    switch (type) {
    case RSV_TYPE_INVALID:
        return "RSV_TYPE_INVALID";
        break;
    case RSV_TYPE_NONE:
        return "RSV_TYPE_NONE";
        break;
    case RSV_TYPE_EXCL:
        return "RSV_TYPE_EXCL";
        break;
    case RSV_TYPE_EXCL_RO:
        return "RSV_TYPE_EXCL_RO";
        break;
    case RSV_TYPE_EXCL_AR:
        return "RSV_TYPE_EXCL_AR";
        break;
    case RSV_TYPE_WRITE:
        return "RSV_TYPE_WRITE";
        break;
    case RSV_TYPE_WRITE_RO:
        return "RSV_TYPE_WRITE_RO";
        break;
    case RSV_TYPE_WRITE_AR:
        return "RSV_TYPE_WRITE_AR";
        break;
    }
    return "!UNKNOWN!";
}

#define rsv_type_is_excl(t)             (((t) & 0x30) == 0x10)
#define rsv_type_is_registrant(t)       (((t) & 0x3) != 0)
#define rsv_type_is_ro(t)               (((t) & 0x3) == 1)
#define rsv_type_is_ar(t)               (((t) & 0x3) == 2)

DECLARE_PACKED_STRUCT(rsv_registration_entry) {
    rsv_itn_id_t    rreg_itn_id;
    rsv_key_t       rreg_key;
} END_PACKED_STRUCT(rsv_registration_entry);

#define rsv_registration_entry_fmt  "%s:%s:%"PRIu64

#define rsv_registration_entry_string(rrep) \
    rsv_client_id_get_string(&(rrep)->rreg_itn_id._rii_client_id), \
    rsv_initiator_get_string(&(rrep)->rreg_itn_id._rii_ini_id), \
    (rrep)->rreg_key

/*********************** end reservation stuff ****************************/
