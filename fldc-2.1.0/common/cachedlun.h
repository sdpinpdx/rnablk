/**
 * <cachedlun.h> - Dell Fluid Cache block driver
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

#ifndef _CACHEDLUN_H_
#define _CACHEDLUN_H_

#include "platform.h"

CODE_IDENT("$URL: $ $Id: $")

#include "rna_service_id.h"
#include "rna_dskattrs_common.h"

typedef enum cached_lun_san_type_e {
    CLS_NO_SAN = 0,
    CLS_CML_SAN = 1,
    CLS_EQL_SAN = 2,
    CLS_SIM_SAN = 3
} cached_lun_san_type_t;

INLINE const char* get_cached_lun_san_type_string(cached_lun_san_type_t san_type)
{
    const char * ret = NULL;

    switch (san_type) {
    case CLS_NO_SAN:
        ret = "CLS_NO_SAN";
        break;
    case CLS_CML_SAN:
        ret = "CLS_CML_SAN";
        break;
    case CLS_EQL_SAN:
        ret = "CLS_EQL_SAN";
        break;
    case CLS_SIM_SAN:
        ret = "CLS_SIM_SAN";
        break;
    default:
        ret = "unknown";
    }
    return ret;
}

/* some day we may want to support 256 reservation clients.
 *  @todo: add support for daisy-chaining more blocks, so we can support
 *  more clients.
 */
#define MAX_ITN_REGISTRATIONS 1024  /* XXX DMO */

typedef struct cached_lun_reservation_state_s {
    rsv_itn_id_t       clr_reservation_holder_itn_id;
    rsv_key_t          clr_reservation_holder_key;
    rsv_mode_t         clr_reservation_mode;
    rsv_type_t         clr_reservation_type;
    gboolean           clr_reservation_aptpl;
    uint64_t           clr_reservation_generation;
    int                clr_registration_itn_count;
    int                clr_registration_chain_block;    /* future expansion */
} cached_lun_reservation_state_t;

/*
 * Structure defining journal block content for a cached lun.
 *
 * So this contains only a LUN's wwn (so that we know this journal block
 * represents that LUN), and run-time state information that needs to
 * be preserved across instances of the configuration manager.
 */
typedef struct cached_lun_journal_info_s {
    rna_store_wwn_t lji_wwn;
    uint8_t         lji_lun_state;
    uint8_t         lji_flush_on_shutdown;
    uint8_t         lji_evict_on_shutdown;
    uint8_t         lji_md_policy;
    uint32_t        lji_cache_block_size;
    uint64_t        lji_capacity;
    uint64_t        lji_master_block_id;
    cached_lun_reservation_state_t
                    lji_reservation_state;
    uint8_t         lji_config_cache_mode;
    uint8_t         lji_active_cache_mode;
    uint8_t         lji_pad2;
    uint8_t         lji_pad3;
} cached_lun_journal_info_t;

/* XXX */

#define OPTS_STR_SIZE (63)
#define TYPE_STR_SIZE (63)
#define MD_POLICY_STR_SIZE  (63)

/* XXX figure out proper place for this */
#ifndef  UNIT_SERIALNO_SIZE
#define UNIT_SERIALNO_SIZE  (128)
#endif

/*
 * Structure to contain information regarding cached LUN configurations.
 * similar to but different from path_io_cfg_t
 *
 * This resides in the cached lun journal block, and also in some of the
 * query and registration messages for paths/cached LUNs.
 *
 * The char arrays in this structure reserve space
 * for a string's terminating null character.
 *
 * This structure should go away soon.
 */
typedef struct cached_lun_registration_info_s {
    rna_store_wwn_t     clri_wwn;
    rna_store_wwn_t     clri_orig_wwn;
    char                clri_alias_serialno[UNIT_SERIALNO_SIZE];
    char                clri_orig_serialno[UNIT_SERIALNO_SIZE];
    uint8_t             clri_alias_serialno_len;
    uint8_t             clri_orig_serialno_len;
    char                clri_type[TYPE_STR_SIZE + 1];
    char                clri_opts[OPTS_STR_SIZE + 1];
    char                clri_md_policy[MD_POLICY_STR_SIZE + 1];
    uint8_t             clri_path_state; /* enum path_state */
    uint8_t             clri_ptype;      /* enum  path_type */
    uint8_t             clri_active_cache_mode;  /* enum path_mode_t */
    uint8_t             clri_config_cache_mode;  /* enum path_mode_t */
    uint32_t            clri_retry_timeout;
    uint32_t            clri_num_retries;
    int                 clri_removing;  /* 1 --> device is being removed  */
    int                 clri_san_type;
    int                 clri_das;
    int                 clri_flush_on_shutdown;
    int                 clri_evict_on_shutdown;
    uint32_t            clri_cache_block_size;
    uint64_t            clri_capacity;   /* capacity in bytes of cached LUN */
    uint64_t            clri_master_block_id;
    rna_service_id_t    clri_snap_cfm_service_id;
    uint64_t            clri_snap_cfm_time;
    int                 clri_snap_write_all_flags;
} cached_lun_registration_info_t;

#endif  // _CACHEDLUN_H_
