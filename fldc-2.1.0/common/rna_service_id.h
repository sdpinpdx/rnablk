/**
 * <rna_service_id.h> - Dell Fluid Cache block driver
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

#ifndef _RNA_SERVICE_ID_H_
#define _RNA_SERVICE_ID_H_

#include "platform.h"

CODE_IDENT("$URL: https://svn.rnanetworks.com/full/tags/HERMES_2_1_0_RC1/common/rna_service_id.h $ $Id: rna_service_id.h 48107 2016-01-08 20:09:36Z pkrueger $")

typedef enum {
	APP_TYPE_MD = 1,
	APP_TYPE_CS,
	APP_TYPE_CLIENT,
	APP_TYPE_CFM,
	APP_TYPE_AGENT,
    APP_TYPE_APS,
	APP_TYPE_APP,
	APP_TYPE_TGT
} agent_app_type;

INLINE const char * agent_app_type_string (agent_app_type type)
{
    const char * ret = "unknown";
    switch (type) {
        case APP_TYPE_MD: ret = "APP_TYPE_MD"; break;
        case APP_TYPE_CS: ret = "APP_TYPE_CS"; break;
        case APP_TYPE_CLIENT: ret = "APP_TYPE_CLIENT"; break;
        case APP_TYPE_CFM: ret = "APP_TYPE_CFM"; break;
        case APP_TYPE_AGENT: ret = "APP_TYPE_AGENT"; break;
        case APP_TYPE_APS: ret = "APP_TYPE_APS"; break;
        case APP_TYPE_APP: ret = "APP_TYPE_APP"; break;
        case APP_TYPE_TGT: ret = "APP_TYPE_TGT"; break;
    }
    return ret;
}

/*!
 * Service ID
 *
 * @see rna_service_id
 */
DECLARE_PACKED_STRUCT(rna_service_id_data) {
    uint32_t    address;
    uint8_t     number;    // a.k.a. instance
    uint8_t     group;
    uint16_t    type;      /**< @see agent_app_type */
} END_PACKED_STRUCT(rna_service_id_data);


/** A service ID identifies (an instance of) a cluster service (CFM, CS, MD,
 * etc.).  An rna_service_id is also used to identify clients (which aren't
 * technically services) by reserving some instance IDs that are hard coded
 * into the various clients (VFS, block) so we can tell them apart.  If we
 * ever have a lot of user mode clients sharing an implementation, there will
 * need to be a mechanism for allocating unique instance IDs at install or
 * run time.
 *
 * To print, @see rna_service_id_get_string 
 */
DECLARE_PACKED_STRUCT(rna_service_id) {
    // use union for speed/ease of comparison
    union {
        struct rna_service_id_data data;
        uint64_t                   hash;
    } u;
    uint64_t    start_time;
                        /* NOTE that the start_times used by most RNA
                         * components (all except CSs) are set using
                         * get_monotonic_timestamp.  These timestanps are
                         * monotonic only w.r.t. node reboots.  A reboot
                         * re-initializes the time values returned by
                         * get_monotonic_timestamp.
                         *
                         * For CSs, the start_time is instead filled by by the
                         * CFM with an 'instance ID'.  CFM-assigned instance
                         * IDs are guaranteed to increase monotonically
                         * throughout the lifetime of the cluster.
                         */
} END_PACKED_STRUCT(rna_service_id);


INLINE void bswap_rna_service_id(struct rna_service_id *data)
{
	UNREFERENCED_PARAMETER(data);

#if CPU_BE
    data->address = bswap_32(data->address);
    //uint8_t     number;
    //uint8_t     group;
    data->type = bswap_16(data->type);
    data->start_time = bswap_64(data->start_time);
#endif
}


#define rna_service_id_format \
            "address ["RNA_ADDR_FORMAT"] "\
            "number [%d] "\
            "group [%d] "\
            "type [%s] "\
            "hash [%"PRIu64"] "\
            "time [%"PRIu64"]"


#define rna_service_id_get_string(__rsegs_service_id) \
    RNA_ADDR((__rsegs_service_id)->u.data.address),\
    (__rsegs_service_id)->u.data.number,\
    (__rsegs_service_id)->u.data.group,\
    agent_app_type_string((__rsegs_service_id)->u.data.type),\
    (__rsegs_service_id)->u.hash,\
    (__rsegs_service_id)->start_time


#define RNA_ADDR_FORMAT "%u.%u.%u.%u"
#ifdef LINUX_KERNEL
# define RNA_ADDR(val) NIPQUAD(val)
#elif defined WINDOWS_KERNEL
# define _RNA_ADDR(val) ((RtlUlongByteSwap(val) >> 24) & 0xff), ((RtlUlongByteSwap(val) >> 16) & 0xff),\
                        ((RtlUlongByteSwap(val) >> 8) & 0xff), ((RtlUlongByteSwap(val) >> 0) & 0xff)
# define RNA_ADDR(val) _RNA_ADDR(*(in_addr_t*)(&(val)))
# define RNA_SIN_ADDR(val) _RNA_ADDR((val).s_addr)
# define RNA_SOCKADDR_IN_ADDR(val) RNA_SIN_ADDR((val).sin_addr)

#else
# define _RNA_ADDR(val) ((ntohl(val) >> 24) & 0xff), ((ntohl(val) >> 16) & 0xff), ((ntohl(val) >> 8) & 0xff), ((ntohl(val) >> 0) & 0xff)
# define RNA_ADDR(val) _RNA_ADDR(*(in_addr_t*)(&(val)))
# define RNA_SIN_ADDR(val) _RNA_ADDR((val).s_addr)
# define RNA_SOCKADDR_IN_ADDR(val) RNA_SIN_ADDR((val).sin_addr)
#endif // LINUX_KERNEL


#if defined(WINDOWS_KERNEL)
INLINE void
rna_write_service_id_xml(RNA_FILE                  *fd,
                         char                  *name,
                         struct rna_service_id *service_id)
{
	UNREFERENCED_PARAMETER(fd);
	UNREFERENCED_PARAMETER(name);
	UNREFERENCED_PARAMETER(service_id);
}

#elif !defined(LINUX_KERNEL)
INLINE void
rna_write_service_id_xml(FILE                  *fd,
                         char                  *name,
                         struct rna_service_id *service_id)
{
	uint32_t x;
    fprintf(fd, "<service_id");
    if (NULL != name) {
        fprintf(fd, " name=\"");
        rna_fprintf_escaped(fd, "%s", name);
        fprintf(fd, "\"");
    }
    fprintf(fd, " hash=\"%"PRIx64"\"", service_id->u.hash);

    x = service_id->u.data.address;
    fprintf(fd, " addr=\"" RNA_ADDR_FORMAT "\"",
            RNA_ADDR(x));

    fprintf(fd, " number=\"%u\"", service_id->u.data.number);
    fprintf(fd, " group=\"%u\"", service_id->u.data.group);
    fprintf(fd, " type=\""); 
    rna_fprintf_escaped(fd, "%s",
                        agent_app_type_string(service_id->u.data.type));
    fprintf(fd, "\"");
    fprintf(fd, " start_time=\"%"PRIu64"\"", service_id->start_time);
    fprintf(fd, "/>\n");
}

#endif //LINUX_KERNEL

#endif  // _RNA_SERVICE_ID_H_
