/**
 * <rna_scsi.h>
 *      Low-level SCSI definitions not defined in standard system
 *      header files.
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

#ifndef _RNA_SCSI_H_
#define _RNA_SCSI_H_

#include "platform.h"

CODE_IDENT("$URL$")

/* SCSI command opcodes not defined by linux scsi.h */

#ifndef EXTENDED_COPY
#define EXTENDED_COPY       0x83
#endif

#ifndef COMPARE_AND_WRITE
#define COMPARE_AND_WRITE   0x89
#endif

#ifndef WRITE_VERIFY_16
#define WRITE_VERIFY_16     0x8e
#endif


/* minimum sense length (when sense data is available) */
#define SCSI_MIN_REQ_SENSE_DESC_LEN         8

/* PERSISTENT_RESERVE_IN service actions */
#define SCSI_RSVIN_SA_READ_KEYS         0x00
#define SCSI_RSVIN_SA_READ_RESERVATION  0x01

/* PERSISTENT_RESERVE_OUT service actions */
#define SCSI_RSVOUT_SA_REGISTER                         0x00
#define SCSI_RSVOUT_SA_RESERVE                          0x01
#define SCSI_RSVOUT_SA_RELEASE                          0x02
#define SCSI_RSVOUT_SA_CLEAR                            0x03
#define SCSI_RSVOUT_SA_PREEMPT                          0x04
#define SCSI_RSVOUT_SA_PREEMPT_AND_ABORT                0x05
#define SCSI_RSVOUT_SA_REGISETER_AND_IGNORE_EXISTING_KEY 0x06
#define SCSI_RSVOUT_SA_REGISTER_AND_MOVE                0x07

/* SERVICE_ACTION_IN service actions */
#define SCSI_SAI_SA_READ_CAPACITY_16    0x10
#define SCSI_SAI_SA_GET_LBA_STATUS      0x12


/* ASC (Additional Sense Code) definitions */ 
#define SCSI_ASC_LBA_OUT_OF_RANGE                       0x21
#define SCSI_ASC_INVALID_FIELD_IN_CDB                   0x24
#define SCSI_ASC_INVALID_FIELD_IN_PARAMETER_LIST        0x26
#define SCSI_ASC_PARAMETER_LIST_LENGTH_ERROR            0x1a
#define SCSI_ASC_MISCOMPARE_DURING_VERIFY               0x1d
#define SCSI_ASC_LUN_NOT_READY                          0x04

/* ASCQ (Additional Sense Code Qualifier) definitions */
#define SCSI_ASCQ_INVALID_RELEASE_OF_PERSISTENT_RESERVATION  0x4  // 0x26:0x04
#define SCSI_ASCQ_LUN_TRANSITIONING                     0x0a   // 0x04:0x0a

/* PERSISTENT_RESERVE_OUT command structure & definitions */

DECLARE_PACKED_STRUCT(scsi_rsvout_cmd) {
    uint8_t             roc_opcode;
    uint8_t             roc_svc_action;
    uint8_t             roc_scope_type;
    uint8_t             roc_rsvd1[2];
    uint32_t            roc_parm_list_len;
    uint8_t             roc_control;
} END_PACKED_STRUCT(scsi_rsvout_cmd);

#define rsvout_cmd_scope(v) (((v) >> 4) & 0xf)
#define rsvout_cmd_type(v)  ((v) & 0xf)

#define SCSI_RSVOUT_SCOPE_LU        0       // LUN scope

#define SCSI_RSVOUT_TYPE_WR_EXCL    0x01    // write-exclusive
#define SCSI_RSVOUT_TYPE_EXCL       0x03    // exclusive
#define SCSI_RSVOUT_TYPE_WR_EXCL_RO 0x05    // write-exclusive registrants-only
#define SCSI_RSVOUT_TYPE_EXCL_RO    0x06    // exclusive registrants-only
#define SCSI_RSVOUT_TYPE_WR_EXCL_AR 0x07    // write-exclusive all-registrants
#define SCSI_RSVOUT_TYPE_EXCL_AR    0x08    // exclusive all-registrants

/* PERSISTENT_RESERVE_OUT parameter data */
DECLARE_PACKED_STRUCT(scsi_rsvout_param_list) {
    uint64_t            ropl_key;
    uint64_t            ropl_sa_key;
    uint32_t            ropl_pad1;
    uint8_t             ropl_flags;
#define     SCSI_RSVOUT_F_APTPL         0x01
#define     SCSI_RSVOUT_F_ALL_TG_PT     0x04
#define     SCSI_RSVOUT_F_SPEC_I_PT     0x08
    uint8_t             ropl_pad2[3];
} END_PACKED_STRUCT(scsi_rsvout_param_list);


/* PERSISTENT_RESERVE_IN READ_KEYS parameter data */
DECLARE_PACKED_STRUCT(scsi_rsvin_readkeys_data) {
    uint32_t            rirk_generation;
    uint32_t            rirk_len;
    uint64_t            rirk_keys[0];
} END_PACKED_STRUCT(scsi_rsvin_readkeys_data);


/* PERSISTENT_RESERVE_IN READ_RSEERVATION parameter data */
DECLARE_PACKED_STRUCT(scsi_rsvin_readrsv_data) {
    uint32_t            rirr_generation;
    uint32_t            rirr_len;
    uint64_t            rirr_key;
    uint32_t            rirr_unused;
    uint8_t             rirr_reserved1;
    uint8_t             rirr_scope_type;
    uint16_t            rirr_unused2;
} END_PACKED_STRUCT(scsi_rsvin_readrsv_data);


/* WRITE_SAME_10 command */
DECLARE_PACKED_STRUCT(rnablk_write_same) {
    uint8_t             ws10_opcode;
    uint8_t             ws10_flags;
    uint32_t            ws10_lba;
    uint8_t             ws10_group;
    uint16_t            ws10_num_lbas;
    uint8_t             ws10_control;
} END_PACKED_STRUCT(rnablk_write_same);

/* WRITE_SAME_16 command */
DECLARE_PACKED_STRUCT(rnablk_write_same_16) {
    uint8_t             ws16_opcode;
    uint8_t             ws16_flags;
    uint64_t            ws16_lba;
    uint32_t            ws16_num_lbas;
    uint8_t             ws16_group;
    uint8_t             ws16_control;
} END_PACKED_STRUCT(rnablk_write_same_16);

/* UNMAP_10 command */
DECLARE_PACKED_STRUCT(rnablk_unmap10) {
    uint8_t             um10_opcode;
    uint8_t             um10_flags;
    uint32_t            um10_reserved;
    uint8_t             um10_group;
    uint16_t            um10_param_list_len; /* bytes */
    uint8_t             um10_control;
} END_PACKED_STRUCT(rnablk_unmap10);

/* UNMAP_10 descriptor */
DECLARE_PACKED_STRUCT(rnablk_unmap10_blk_desc) {
    uint64_t            umb_lba;
    uint32_t            umb_num_lbas;
    uint32_t            umb_reserved;
} END_PACKED_STRUCT(rnablk_unmap10_blk_desc);

/* UNMAP_10 parameter data */
DECLARE_PACKED_STRUCT(rnablk_unmap10_param_list) {
    uint16_t            ump_data_len;
    uint16_t            ump_blk_desc_len;
    uint32_t            ump_reserved;
    rnablk_unmap10_blk_desc_t ump_blk_desc[1]; /* at least 1 */
} END_PACKED_STRUCT(rnablk_unmap10_param_list);

/* IOCTLs & payloads */
struct rnablk_rsv_access {
    uint8_t         rra_n_itns;
    uint8_t         rra_other_access;
    uint8_t         rra_pad[2];
    rsv_initiator_t rra_ini_list[MAX_PER_CLIENT_INITIATORS];
};

#define RSV_INITIATOR_SHA1_SZ   20  // 20 bytes for SHA1 hash representation
                                    // of SCSI initiator ID
struct rnablk_ioc_scsi_event {
    uint16_t rise_ua_asc;
    uint8_t  rise_outofspace;
    uint8_t  rise_pad;
    rsv_initiator_t rise_ua_ini;
    uint32_t rise_access_gen;
    struct rnablk_rsv_access rise_acl;
};

struct rnablk_ioc_tgt_hdr {
    rsv_initiator_t rith_ini;
    /* has to be last */
    void    *rith_sg_hdr;  /* __user */
};

struct rnablk_ioc_rsv_ack {
    int      rira_phase;    // for valid values, see rsv_ack_phase
    uint32_t rira_gen;
};

typedef enum {
    RSV_ACK_NONE,
    RSV_ACK_QUIESCE_INITIATED,      // quiescing has been initiated
    RSV_ACK_QUIESCE_COMPLETE        // quiescing is complete
} rsv_ack_phase;

struct rnablk_ioc_tgt_register {
    char ritr_path[256];
};

#define RNABLK_IOC_SCSI_EVENT_WAIT  \
                _IOWR('f', 0x80, struct rnablk_ioc_scsi_event)
#define RNABLK_IOC_TGT_SG_IO  \
                _IOWR('f', 0x81, struct rnablk_ioc_tgt_hdr)
#define RNABLK_IOC_SCSI_RSV_ACCESS_ACK  \
                _IOWR('f', 0x82, struct rnablk_ioc_rsv_ack)
#define RNABLK_IOC_CTL_REGISTER \
                _IOW('f', 0x83, struct rnablk_ioc_tgt_register)

#endif	// _RNA_SCSI_H_

/* Emacs settings */
/* 
 * Local Variables:
 * c-basic-offset: 4
 * c-file-offsets: ((substatement-open . 0))
 * tab-width: 4
 * End:
 */
