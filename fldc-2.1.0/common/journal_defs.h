/**
 * <journal_defs.h> - Dell Fluid Cache block driver
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

#ifndef _JOURNAL_DEFS_H_
#define _JOURNAL_DEFS_H_

struct j_mgmt_ip {
    in_addr_t       hc_addr;
    uint16_t        hc_port;
};
/* Maximum HCC event handlers supported */
#define J_MAX_EVENT_HANDLERS 8

#define J_EVENT_HANDLER_ID_LEN 128
struct j_eventhandler_info {
    char                jehi_id[J_EVENT_HANDLER_ID_LEN];
    struct j_mgmt_ip    jehi_mgmt_ip;
};

#define J_MAX_BIND_INTERFACES 16

#define J_DEV_ID_LEN 128
#define J_SERIAL_LEN 128
struct j_scsi_info {
    char    jsi_device_id[J_DEV_ID_LEN];
    char    jsi_serial_number[J_SERIAL_LEN];
};

// Max number of mask rules per LUN
// Note: should be the same as MAX_LUN_MASK_RULES in conf_lib.h
#define J_MAX_LUN_MASK_RULES 16

struct j_lun_mask_info {
    rna_store_wwn_t jlmi_wwn;
    uint16_t        jlmi_rules[J_MAX_LUN_MASK_RULES];
};

#define J_SAN_ID_LEN 128
#define J_SAN_NAME_LEN 128
#define J_SAN_TYPE_LEN 4   /* CML/EQL/SIM */
#define J_SAN_STATUS_LEN 9 /* up/down/degraded */

#define J_SAN_VOL_ID_LEN 128
#define J_HC_VOL_ID_LEN 128
#define J_VOL_NAME_LEN 128
#define J_SCSI_ID_LEN 128
#define J_CACHE_MODE_LEN 128 /* writethrough/readthrough/readwritethrough */
#define J_CACHE_POLICY_LEN 128 /* proportional/clientaffinity */

#define J_MAX_HOST_LEN 128
#define J_MAX_NAME_LEN 255
#define J_MAX_WWN_STR_LEN 40

/*
 * Use this as the starting block number for the journal_read_next iterator
 * to start at the first allocated block.
 */
#define JOURNAL_FIRST_BLOCK             0


/* The size, in bytes, of a journal block */
#define JOURNAL_BLOCK_SIZE_BYTES        4096


/*
 * The size, in bytes, of a single sector write.  We assume that a single
 * sector can be written atomically, without risk of a torn write.
 */
#define JOURNAL_SINGLE_SECTOR_SIZE_BYTES 512


/*
 * The maximum size of the CFM journal, in bytes (i.e. the amount of space set
 * aside for the journal in the cache devices).
 */
#define JOURNAL_SIZE_MAX_BYTES          (10 * 1024 * 1024)


/*
 * The CFM journal is replicated.  The number of journal replicas.
 */
#define NUM_JOURNAL_MIRRORS             3


#endif /* _JOURNAL_DEFS_H_ */
