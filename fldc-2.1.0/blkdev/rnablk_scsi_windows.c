/**
 * <rnablk_scsi_windows.c> - Dell Fluid Cache block driver
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

#include "rb.h"
#include "rnablk_scsi.h"
#include "rnablk_io_state.h"
#include "rnablk_device.h"
#include "rnablk_queue_dispatch.h"
#include "rnablk_comatose.h" // for rnablk_set_req_refcount
#include "rnablk_protocol.h"
#include "rna_scsi.h"
#include "rna_vsmp.h"
#include "trace.h"
#include <srbhelper.h>

typedef struct rnablk_special_completion_s {
    KEVENT spc_complete;
    int spc_status;
    atomic_t spc_retries;
    atomic_t spc_in_progress;    // for users that want to limit number in progress
} rnablk_special_completion_t;

static BOOLEAN scsi_status_is_good(uint8_t status)
{
    if ((status == SCSISTAT_GOOD)
        || (status == SCSISTAT_INTERMEDIATE)
        || (status == SCSISTAT_INTERMEDIATE_COND_MET)) {
            return TRUE;
    }
    return FALSE;
}

static int
rnablk_sense_to_caller(PSCSI_REQUEST_BLOCK pSrb, u8 status, const u8 *sense_buf,
                       int sense_len, int internal_cmd)
{
    int res = 0;
    UCHAR sense_len_wr = 0;
    UCHAR scsiStatus;
    PVOID pSenseInfoBuffer;
    UCHAR senseInfoBufferLength;
    ULONG flags;

    if (scsi_status_is_good(status)) {
        SrbSetSenseInfoBufferLength(pSrb, 0);
        SrbSetScsiStatus(pSrb, status);
        pSrb->SrbStatus = SRB_STATUS_SUCCESS;
    } else {
        SrbSetDataTransferLength(pSrb, 0);
        SrbSetScsiStatus(pSrb, status);
        pSrb->SrbStatus = SRB_STATUS_ERROR;  

        flags = SrbGetSrbFlags(pSrb);

        if ( !(flags & SRB_FLAGS_DISABLE_AUTOSENSE)) {
            SrbGetScsiData((PSTORAGE_REQUEST_BLOCK)pSrb, NULL, NULL, &scsiStatus, &pSenseInfoBuffer, &senseInfoBufferLength);

            if (sense_len && pSenseInfoBuffer) {
                sense_len_wr = (UCHAR) (MIN(senseInfoBufferLength, sense_len));
                RtlCopyMemory(pSenseInfoBuffer, sense_buf, sense_len_wr);
                SrbSetSenseInfoBufferLength(pSrb, sense_len_wr);
                pSrb->SrbStatus |= SRB_STATUS_AUTOSENSE_VALID;  
            }
        }
    }

    return res;
}

static int
rnablk_sense_to_user(PSCSI_REQUEST_BLOCK pSrb, u8 status, const u8 *sense_buf,
                     int sense_len)
{
    /* call the wrapper fn... not internal_cmd */
    return rnablk_sense_to_caller(pSrb, status, sense_buf, sense_len, 0);
}

typedef struct scsi_command_info_s {
    uint8_t sci_opcode;
    uint8_t sci_cmdlen;
    uint8_t sci_writemode;          // true if cmd requires write permission
    rsv_access_t sci_min_access;    // minimum device access needed to execute
                                    // command (related to device reservations)
    char    *sci_name;              // string name for opcode (may be null)
    int     (*sci_handler)(struct rnablk_device *, rsv_itn_id_t *,
                           PSCSI_REQUEST_BLOCK, uint8_t *, rsv_access_t);
} scsi_command_info_t;

#define scsi_cmd_len(cmd)    rnablk_scsi_cmd_ptrs[(cmd)]->sci_cmdlen
#define scsi_cmd_name(cmd)   rnablk_scsi_cmd_ptrs[(cmd)]->sci_name
#define scsi_cmd_writemode(cmd) (rnablk_scsi_cmd_ptrs[(cmd)]->sci_writemode != 0)
#define scsi_cmd_minaccess(cmd) rnablk_scsi_cmd_ptrs[(cmd)]->sci_min_access

static int rnablk_process_scsi_passthru(struct rnablk_device *dev,
                                               rsv_itn_id_t *p_itn_id,
                                               PSCSI_REQUEST_BLOCK pSrb,
                                               uint8_t *scsi_cmd,
                                               rsv_access_t min_access);

static int rnablk_process_scsi_compare_and_write(struct rnablk_device *dev,
                                                 rsv_itn_id_t *p_itn_id,
                                                 PSCSI_REQUEST_BLOCK pSrb,
                                                 uint8_t *scsi_cmd,
                                                 rsv_access_t min_access);

static int rnablk_process_scsi_write_same(struct rnablk_device *dev,
                                          rsv_itn_id_t *p_itn_id,
                                          PSCSI_REQUEST_BLOCK pSrb,
                                          uint8_t *scsi_cmd,
                                          rsv_access_t min_access);

static int rnablk_process_scsi_unmap(struct rnablk_device *dev,
                                     rsv_itn_id_t *p_itn_id,
                                     PSCSI_REQUEST_BLOCK pSrb,
                                     uint8_t *scsi_cmd,
                                     rsv_access_t min_access);

static int rnablk_process_scsi_turs(struct rnablk_device *dev,
                                    rsv_itn_id_t *p_itn_id,
                                    PSCSI_REQUEST_BLOCK pSrb,
                                    uint8_t *scsi_cmd,
                                    rsv_access_t min_access);

static int rnablk_reject_scsi_command(PSCSI_REQUEST_BLOCK pSrb);

static int rnablk_process_scsi_service_action_in(struct rnablk_device *dev,
                                                 rsv_itn_id_t *p_itn_id,
                                                 PSCSI_REQUEST_BLOCK pSrb,
                                                 uint8_t *scsi_cmd,
                                                 rsv_access_t min_access);

#ifndef SCSIOP_COMPARE_WRITE
#define SCSIOP_COMPARE_WRITE  0x89
#endif


static scsi_command_info_t rnablk_scsi_commands[] = {
    { SCSIOP_COMPARE_WRITE, 16, 1, RSV_ACC_READWRITE,
        "COMPARE_AND_WRITE",
        rnablk_process_scsi_compare_and_write },
    { SCSIOP_FORMAT_UNIT, 6, 1, RSV_ACC_READWRITE,
        "FORMAT_UNIT",
        rnablk_process_scsi_passthru },
    { SCSIOP_INQUIRY, 6, 0, RSV_ACC_NONE,
        "INQUIRY",
        rnablk_process_scsi_passthru },
    { SCSIOP_MODE_SENSE, 6, 0, RSV_ACC_READONLY,
        "MODE_SENSE_6",
        rnablk_process_scsi_passthru },
    { SCSIOP_MODE_SENSE10, 10, 0, RSV_ACC_READONLY,
        "MODE_SENSE_10",
        rnablk_process_scsi_passthru },
    { SCSIOP_PERSISTENT_RESERVE_IN, 10, 0, RSV_ACC_NONE,
        "PERSISTENT_RESERVE_IN",
        rnablk_process_scsi_passthru },
    /* note: rsvtn access checking happens at Cache Server for RESERVE_OUT */
    { SCSIOP_PERSISTENT_RESERVE_OUT, 10, 1, RSV_ACC_NONE,
        "PERSISTENT_RESERVE_OUT",
        rnablk_process_scsi_passthru },
    { SCSIOP_READ_CAPACITY, 10, 0, RSV_ACC_NONE,
        "READ_CAPACITY",
        rnablk_process_scsi_passthru },
    { SCSIOP_READ_CAPACITY16, 16, 0, RSV_ACC_NONE,
        "READ_CAPACITY_16",
        rnablk_process_scsi_passthru },
    { SCSIOP_RELEASE_UNIT, 6, 1, RSV_ACC_READWRITE,
        "RELEASE_6",
        rnablk_process_scsi_passthru },
    { SCSIOP_RELEASE_UNIT10, 10, 1, RSV_ACC_READWRITE,
        "RELEASE_10",
        rnablk_process_scsi_passthru },
    { SCSIOP_REQUEST_SENSE, 6, 0, RSV_ACC_NONE,
        "REQUEST_SENSE",
        rnablk_process_scsi_passthru },
    { SCSIOP_RESERVE_UNIT, 6, 1, RSV_ACC_READWRITE,
        "RESERVE_6",
        rnablk_process_scsi_passthru, },
    { SCSIOP_RESERVE_UNIT10, 10, 1, RSV_ACC_READWRITE,
        "RESERVE_10",
        rnablk_process_scsi_passthru, },
    /* note: rsvtn access for below depends on subcommand */
    { SCSIOP_SERVICE_ACTION_IN16, 16, 0, RSV_ACC_NONE,
        "SERVICE_ACTION_IN",
        rnablk_process_scsi_service_action_in },
    { SCSIOP_TEST_UNIT_READY, 6, 0, RSV_ACC_NONE,
        "TEST_UNIT_READY",
        rnablk_process_scsi_turs },
    { SCSIOP_UNMAP, 10, 1, RSV_ACC_READWRITE,
        "UNMAP",
        rnablk_process_scsi_unmap },
    { SCSIOP_WRITE_SAME, 10, 1, RSV_ACC_READWRITE,
        "WRITE_SAME_10",
        rnablk_process_scsi_write_same },
    { SCSIOP_WRITE_SAME16, 16, 1, RSV_ACC_READWRITE,
        "WRITE_SAME_16",
        rnablk_process_scsi_write_same },
};
int rnablk_n_scsi_commands =
                sizeof(rnablk_scsi_commands)/sizeof(scsi_command_info_t);

static scsi_command_info_t** rnablk_scsi_cmd_ptrs = NULL;

static uint8_t rnablk_max_scsi_command = 0;

//
// Dynamically build a table of pointers to supported comamnds that we can
// index into directly by opcode.
//
int rnablk_build_win_scsi_table(void)
{
    SIZE_T allocBytes;
    int i;

    for ( i = 0; i < rnablk_n_scsi_commands; i++ ) {
        if (rnablk_scsi_commands[i].sci_opcode > rnablk_max_scsi_command) {
            rnablk_max_scsi_command = rnablk_scsi_commands[i].sci_opcode;
        }
    }

    allocBytes = sizeof(scsi_command_info_t*) * (rnablk_max_scsi_command + 1);
    rnablk_scsi_cmd_ptrs = ExAllocatePoolWithTag(NonPagedPool, allocBytes, MP_TAG_SCSI);

    if (rnablk_scsi_cmd_ptrs != NULL) {
        RtlZeroMemory(rnablk_scsi_cmd_ptrs, allocBytes);
    }
    else {
        return -1;
    }

    for ( i = 0; i < rnablk_n_scsi_commands; i++ ) {
        rnablk_scsi_cmd_ptrs[rnablk_scsi_commands[i].sci_opcode] = &rnablk_scsi_commands[i];
    }

    return 0;
}

void rnablk_cleanup_win_scsi_table(void)
{
    if (rnablk_scsi_cmd_ptrs) {
        ExFreePoolWithTag(rnablk_scsi_cmd_ptrs, MP_TAG_SCSI);
        rnablk_scsi_cmd_ptrs = NULL;
    }
}

int
rnablk_sg_io(struct rnablk_device *dev, rsv_itn_id_t *p_itn_id,
             PSCSI_REQUEST_BLOCK pSrb)
{
    uint8_t scsi_command[SCSI_MAX_CMD_LEN];
    uint8_t cmd;
    int ret = 0;
    UCHAR cdbLength;
    PCDB pCdb;

    cdbLength = SrbGetCdbLength(pSrb);
    pCdb = SrbGetCdb(pSrb);

    if (cdbLength > 0 && cdbLength <= sizeof(scsi_command)) {
        RtlZeroMemory(scsi_command, sizeof(scsi_command));
        RtlCopyMemory(scsi_command, pCdb, cdbLength);
    } else {
        return -EINVAL;
    }

    cmd = scsi_command[0];
    if (cmd > rnablk_max_scsi_command
        || NULL == rnablk_scsi_cmd_ptrs[cmd]
        || NULL == rnablk_scsi_cmd_ptrs[cmd]->sci_handler) {
        rna_printk(KERN_DEBUG, "scsi cmd %#hhx not supported for passthru, "
            "failing\n", cmd);
        KdPrint(("rnablk_sg_io:  SCSI cmd %#hhx not supported for passthrough\n", cmd));
        // default handler
        ret = rnablk_reject_scsi_command(pSrb);

    } else if (0 == rnablk_reservation_access_check(dev,
                                                    scsi_cmd_minaccess(cmd))) {
        rna_printk(KERN_DEBUG, "Issuing scsi cmd %s\n", scsi_cmd_name(cmd));
        ret = rnablk_scsi_cmd_ptrs[cmd]->sci_handler(dev, p_itn_id, pSrb,
                                                    scsi_command,
                                                    scsi_cmd_minaccess(cmd));
        rna_printk(KERN_DEBUG, "scsi cmd %s done, ret=%d\n", scsi_cmd_name(cmd),
                   ret);
        if (-ENODEV == ret || -ENOMEM == ret || -EBUSY == ret) {
            /* can be retried */
            uint8_t sense[SCSI_MIN_REQ_SENSE_DESC_LEN];
            memset(sense, 0, sizeof(sense));
            sense[0] = SCSI_SENSE_ERRORCODE_DESCRIPTOR_CURRENT;
            sense[1] = SCSI_SENSE_NOT_READY;
            sense[2] = SCSI_ADSENSE_LUN_NOT_READY; // LUN not ready
            sense[3] = 0xa; // transitioning
            ret = rnablk_sense_to_user(pSrb, SCSISTAT_CHECK_CONDITION, sense,
                                       SCSI_MIN_REQ_SENSE_DESC_LEN);
        }
        if (RSV_ACC_NONE != scsi_cmd_minaccess(cmd)) {
            rnablk_dec_device_iocnt(dev, scsi_cmd_writemode(cmd));
        }
    } else {
        rna_printk(KERN_DEBUG, "Can't issue scsi cmd %s due to RSV CONFLICT\n",
                   scsi_cmd_name(cmd));
        rnablk_sense_to_user(pSrb, SCSISTAT_RESERVATION_CONFLICT, NULL, 0);
    }

    return ret;
}

/* byte[5]=LBPU:LBPWS:LBPWS10:RSVD[2]:LBPRZ:ANC_SUP:DP */
#define VPD_BLOCK_PROVISIONING_FOR_UNMAP        (1 << 7)   // LBPU
#define VPD_BLOCK_PROVISIONING_FOR_WRITE_SAME   (3 << 5)   // LBPWS:LBPWS10

static void
rnablk_transform_vpd_page_data(uint8_t vpd_page_num,
                               uint8_t *data, uint32_t len)
{
    switch (vpd_page_num) {
    case VPD_BLOCK_LIMITS:
        if (rnablk_scsi_unmap_disable) {
            /* clear 4 UNMAP related 32-bit fields from byte[20] */
            if (len >= 36) {
                memset(&data[20], 0, 16);
            }
        } else {
            /*
             * We can set values that fit our implementation:
             *  e.g., number of descriptors > 1
             * For now, we'll leave this data alone (passthru)
             */
        }
        break;

    case VPD_LOGICAL_BLOCK_PROVISIONING:
        /* 
         * Set or clear bits based on whether we support UNMAP and WRITE_SAME
         * (CS does't need the backing device to support either command)
         */
        if (rnablk_scsi_unmap_disable) {
            data[5] &= ~VPD_BLOCK_PROVISIONING_FOR_UNMAP;
        } else {
            data[5] |= VPD_BLOCK_PROVISIONING_FOR_UNMAP;
        }
        if (rnablk_scsi_write_same_disable) {
            data[5] &= ~VPD_BLOCK_PROVISIONING_FOR_WRITE_SAME;
        } else {
            data[5] |= VPD_BLOCK_PROVISIONING_FOR_WRITE_SAME;
        }
        break;

    default:
        break;
    }

    return;
}

#define RNABLK_SG_IO_USER      0
#define RNABLK_SG_IO_INTERNAL  1
#define RNABLK_SG_LUN_RESET    (1 << 1 | RNABLK_SG_IO_INTERNAL)
static int
rnablk_process_scsi_passthru_ext(struct rnablk_device *dev,
                                        rsv_itn_id_t *p_itn_id,
                                        PSCSI_REQUEST_BLOCK pSrb,
                                        uint8_t *scsi_cmd,
                                        rsv_access_t min_access,
                                        int cmd_src)
{
    rnablk_special_completion_t complete;
    struct io_state *ios = NULL;
    struct cache_scsi_passthru *cs;
    struct cache_scsi_passthru_resp *sr;
    boolean ios_issued = FALSE;
    struct cache_blk *blk;
    struct com_ep *ep;
    int internal_cmd = cmd_src & RNABLK_SG_IO_INTERNAL;
    UCHAR cdbLength;
    ULONG dataXferLength;
    PVOID pDataBuffer;
    ULONG srbFlags;

    ENTER;

    cdbLength = SrbGetCdbLength(pSrb);
    dataXferLength = SrbGetDataTransferLength(pSrb);
    pDataBuffer = SrbGetDataBuffer(pSrb);
    srbFlags = SrbGetSrbFlags(pSrb);

    /* do command error checking */

    if (cdbLength > sizeof(cs->scsi_command)) {
        GOTO(out, -EINVAL);
    }

    if (dataXferLength > SCSI_MAX_DATA_PAYLOAD
        || dataXferLength > sizeof(sr->data)) {
        rna_printk(KERN_DEBUG, "passthru data too big: xfer_len=%d "
                   "MAX_PAYLOAD=%d bufsz=%lu\n",
                   dataXferLength, SCSI_MAX_DATA_PAYLOAD,
                   sizeof(sr->data));
        GOTO(out, -EINVAL);
    }

    KeInitializeEvent(&complete.spc_complete, NotificationEvent, FALSE);
    complete.spc_status = 0;
    atomic_set(&complete.spc_retries, 0);
    atomic_set(&complete.spc_in_progress, 1);

    ret = rnablk_alloc_ios(dev, &complete, IOREQ_TYPE_SPC, min_access, FALSE,
                           TRUE, 1, &ios);
    if (unlikely(0 != ret)) {
        GOTO(out, ret);
    }

    ios->pOS_Srb = pSrb;
    ios->cmd->h.h_type = CACHE_SCSI_PASSTHRU;

    /*
     * Grab an extra reference on the ios.  We need to keep it around after
     * it completes in order to extract sense and/or user data from
     * the ios->cmd structure.
     */
    rnablk_ios_ref(ios);

    /* do initialization of the cache_cmd */

    cs = &ios->cmd->u.cache_scsi_passthru;
    sr = &cs->response;

    if (NULL != p_itn_id) {
        cs->has_itn_id = 1;
        rsv_copy_itn_id(&cs->itn_id, p_itn_id);
    }
    RtlCopyMemory(cs->scsi_command, scsi_cmd, cdbLength);
    cs->cmd_len = cdbLength;
    cs->xfer_length = dataXferLength;

    cs->writing = (srbFlags & SRB_FLAGS_DATA_OUT)?1:0;
    cs->reset_action = (RNABLK_SG_LUN_RESET == cmd_src) ? 1 : 0;
    
    if (cs->writing) {
        RtlCopyMemory(sr->data, pDataBuffer, dataXferLength);
    }

    /* finish ios setup and kick it off */

    blk = MASTER_BLK(ios->dev);
    if (!rnablk_blk_connected(blk) || NULL == (ep = blk->ep) || MD_CONN_EP_METAVALUE == ep) {

        rna_printk(KERN_ERR, "device [%s] master block not connected\n",ios->dev->name);
        GOTO(out, -ENODEV);
    }

    rnablk_set_ios_blk(ios, blk);

    rnablk_svcctl_register();

    /*
     * Recheck blk & ep state after the call to rnablk_svcctl_register();
     * we could have been blocked there awhile (if the client was in a frozen
     * state), so the blk & ep state could have changed on us...
     */
    if (!rnablk_blk_connected(blk) || NULL == (ep = blk->ep)|| MD_CONN_EP_METAVALUE == ep) {
        
        rna_printk(KERN_ERR, "device [%s] master block not connected\n",ios->dev->name);
        rnablk_svcctl_deregister();
        GOTO(out, -ENODEV);
    }
    
    rnablk_set_ios_timer(ios);

    rnablk_queue_request(RNABLK_SCSI_PASSTHRU, ep, ios, blk, NO_FORCE_QUEUED_IO, FALSE);
    
    rnablk_svcctl_deregister();

    ios_issued = TRUE;

    /* wait for it to finish and do error handling */

    KeWaitForSingleObject(&complete.spc_complete, Executive, KernelMode, FALSE, NULL);

    if (unlikely(0 != complete.spc_status && 0 == sr->cs_status)) {
        sr->cs_status = (uint8_t) complete.spc_status;
    }

    if (0 != sr->cs_status) {
        /* some kind of cache error; generate a SCSI error out of it */
        if (CACHE_RESP_CODE_EINVAL != sr->cs_status) {
            sr->scsi_status = SCSISTAT_CHECK_CONDITION;
            RtlZeroMemory(sr->sense, 8);
            sr->sense[0] = SCSI_SENSE_ERRORCODE_FIXED_CURRENT;
            sr->sense[2] = SCSI_SENSE_MEDIUM_ERROR;
            sr->sense_length = 8;
            ret = 0;
        } else {
            ret = -EINVAL;
        }
    } else if (0 != sr->op_status) {
        ret = -sr->op_status;       // convert into a negative errno
        rna_printk(KERN_DEBUG, "Got op_status err=%hhd\n", ret);
    }
    if (0 == ret) {
        /* success... hdr & sense are available */
        ret = rnablk_sense_to_caller(pSrb, sr->scsi_status, sr->sense,
                                     sr->sense_length, internal_cmd);
        if (ret) {
                rna_printk(KERN_DEBUG, "copy sense data %s failed\n",
                                       internal_cmd ? "internal" : "to user");
        }
        else if (scsi_status_is_good(sr->scsi_status) && !cs->writing) {
            uint32_t datalen;
            if (SCSIOP_INQUIRY == scsi_cmd[0] && 0 != scsi_cmd[2]) {
                /* INQUIRY with non-zero VPD page */
                rnablk_transform_vpd_page_data(scsi_cmd[2],
                                               sr->data, sr->xferd_length);
            }
            datalen = MIN(dataXferLength, sr->xferd_length);
            RtlCopyMemory(pDataBuffer, sr->data, datalen);
            dataXferLength = datalen;
        }
    }

 out:
    if (NULL != ios) {
        rnablk_ios_release(ios);
        if (!ios_issued) {
            rnablk_end_request(ios, 0);    // cleans up ios & bio
        }
    }
    return ret;
}

static int
rnablk_process_scsi_passthru(struct rnablk_device *dev,
                                    rsv_itn_id_t *p_itn_id,
                                    PSCSI_REQUEST_BLOCK pSrb,
                                    uint8_t *scsi_cmd,
                                    rsv_access_t min_access)
{
    /* call the wrapper fn... not internal_cmd */
    return rnablk_process_scsi_passthru_ext(dev, p_itn_id, pSrb, scsi_cmd,
                                            min_access, RNABLK_SG_IO_USER);
}

static int
rnablk_process_scsi_compare_and_write(struct rnablk_device *dev,
                                      rsv_itn_id_t *p_itn_id,
                                      PSCSI_REQUEST_BLOCK pSrb,
                                      uint8_t *scsi_cmd,
                                      rsv_access_t min_access)
{
    rnablk_special_completion_t complete;
    struct io_state *ios = NULL;
    struct cache_comp_and_write_req *req;
    struct cache_comp_and_write_resp *resp;
    uint8_t sense[SCSI_MAX_SENSE_LEN];
    int sense_len = 0;
    uint8_t scsi_status = SCSISTAT_GOOD;
    boolean ios_issued = FALSE;
    uint64_t lba;
    uint32_t miscomp_offset = 0;
    UCHAR cdbLength;
    ULONG dataXferLength;
    ULONG srbFlags;
    PVOID pDataBuffer;
#define     cmd_num_lbas    scsi_cmd[13]
#define     cmd_lba         scsi_cmd[2]
    ENTER;

    cdbLength = SrbGetCdbLength(pSrb);
    dataXferLength = SrbGetDataTransferLength(pSrb);
    srbFlags = SrbGetSrbFlags(pSrb);
    pDataBuffer = SrbGetDataBuffer(pSrb);

    /* do command error checking */

    if (dataXferLength != RNA_COMPARE_AND_WRITE_SIZE * 2) {
        rna_printk(KERN_DEBUG, "unsupported compare_and_write data length %d\n",
                   dataXferLength);
        GOTO(out, -EINVAL);
    }
    if ( ! (srbFlags & SRB_FLAGS_DATA_OUT)) {
        rna_printk(KERN_DEBUG, "unsupported compare_and_write direction. SrbFlags 0x%08x\n",
                   srbFlags);
        GOTO(out, -EINVAL);
    }

    if (scsi_cmd_len(scsi_cmd[0]) != cdbLength) {
        rna_printk(KERN_DEBUG, "incorrect COMPARE_AND_WRITE command length: "
                   "%d\n", cdbLength);
        GOTO(out, -EINVAL);
    }

    if (cmd_num_lbas != 1) {        // all we support for now!
        if (cmd_num_lbas != 0) {
            rna_printk(KERN_DEBUG, "error num_lbas=%hhd\n", cmd_num_lbas);
            scsi_status = SCSISTAT_CHECK_CONDITION;
            memset(sense, 0, sizeof(sense));
            sense[0] = SCSI_SENSE_ERRORCODE_DESCRIPTOR_CURRENT;
            sense[1] = SCSI_SENSE_ILLEGAL_REQUEST;
            sense[2] = SCSI_ASC_INVALID_FIELD_IN_CDB;
            sense_len = SCSI_MIN_REQ_SENSE_DESC_LEN;
        }
        GOTO(out, 0);
    }

    KeInitializeEvent(&complete.spc_complete, NotificationEvent, FALSE);
    complete.spc_status = 0;
    atomic_set(&complete.spc_retries, 0);
    atomic_set(&complete.spc_in_progress, 1);

    ret = rnablk_alloc_ios(dev, &complete, IOREQ_TYPE_SPC, min_access, FALSE,TRUE, 1, &ios);
    
    if (unlikely(0 != ret)) {
        GOTO(out, -ret);
    }

    /*
     * Grab a extra reference on the ios.  We need to keep it around after
     * it completes in order to extract response status from
     * the ios->cmd structure.
     */
    rnablk_ios_ref(ios);

    /* do initialization of the cache_cmd */

    req = &ios->cmd->u.cache_comp_wr_req;
    resp = &req->cw_resp;

    /* assume cw_verify & cw_write bufs are contiguous & in order */
    RtlCopyMemory(req->cw_verify, pDataBuffer, RNA_COMPARE_AND_WRITE_SIZE * 2);

    lba = RtlUlonglongByteSwap(*(uint64_t *)&cmd_lba);

    req->cw_blk_offset = (lba % (dev->cache_blk_size >> RNABLK_SECTOR_SHIFT))
                          << RNABLK_SECTOR_SHIFT;

    ios->cmd->h.h_type = CACHE_COMP_WR;

    /* finish ios setup and kick it off */

    ios->ios_iotype = IOS_IOTYPE_COMP_WR;

    ios->start_sector = lba;
    ios->nr_sectors = 1;

    rnablk_svcctl_register();
    rnablk_process_request(ios);
    rnablk_svcctl_deregister();

    ios_issued = TRUE;

    /* wait for it to finish and do error handling */

    KeWaitForSingleObject(&complete.spc_complete, Executive, KernelMode, FALSE, NULL);

    if (unlikely(0 != complete.spc_status && 0 == resp->cwr_status)) {
        resp->cwr_status = (uint8_t) complete.spc_status;
    }
    if (0 != resp->cwr_status) {
        /* some kind of cache error; generate a SCSI error out of it */
        scsi_status = SCSISTAT_CHECK_CONDITION;
        memset(sense, 0, sizeof(sense));
        sense[0] = SCSI_SENSE_ERRORCODE_FIXED_CURRENT;
        sense[2] = SCSI_SENSE_MEDIUM_ERROR;
        sense[7] = SCSI_ADSENSE_NO_SENSE;
        sense_len = 8;
        ret = 0;
    } else if (RNA_CW_STATUS_MISCOMPARE == resp->cwr_cmp_status) {
        scsi_status = SCSISTAT_CHECK_CONDITION;
        memset(sense, 0, sizeof(sense));
        sense[0] = SCSI_SENSE_ERRORCODE_FIXED_CURRENT | 0x80;     // 0x80 == VALID bit, because we're setting Information field.
        sense[2] = SCSI_SENSE_MISCOMPARE;
        miscomp_offset = (uint32_t) resp->cwr_miscompare_offset;
        *(uint32_t *)(&sense[3]) = RtlUlongByteSwap(miscomp_offset);
        sense[7] = 6;         // Additional sense length
        sense[12] = SCSI_ASC_MISCOMPARE_DURING_VERIFY;
        sense_len = 14;
    }

 out:
    if (NULL != ios) {
        rnablk_ios_release(ios);
        if (!ios_issued) {
            rnablk_end_request(ios, 0);    // cleans up ios & bio
        }
    }
    if (0 == ret) {
        /* success... */
        ret = rnablk_sense_to_user(pSrb, scsi_status, sense, sense_len);
    }
    return ret;
}

#define WS_FLAGS_OBSOLETE   0x01
#define WS_FLAGS_LBDATA     0x02
#define WS_FLAGS_PBDATA     0x04 
#define WS_FLAGS_UNMAP      0x08
#define WS_FLAGS_ANCHOR     0x10
#define WS_FLAGS_WRPROTECT  0xE0

#define MAX_CONCURRENT_WRITE_SAME_IOS           24      // arbitrary choice!

#define IS_WS_UNMAP   1
#define IS_SCSI_UNMAP 2
static int
rnablk_issue_write_same_ios(struct rnablk_device *dev,
                            PSCSI_REQUEST_BLOCK pSrb,
                            uint64_t lba,
                            uint32_t nsectors,
                            uint8_t unmap_type,
                            rsv_access_t min_access)
{
    rnablk_special_completion_t ws_completion;
    struct cache_write_same_req *req;
    struct cache_write_same_resp *resp;
    uint32_t sectors_per_block;
    uint32_t nsect_in_blk;
    struct io_state *ios;
    PVOID pDataBuffer;
    ENTER;

    pDataBuffer = SrbGetDataBuffer(pSrb);

    KeInitializeEvent(&ws_completion.spc_complete, SynchronizationEvent, FALSE);
    ws_completion.spc_status = 0;
    atomic_set(&ws_completion.spc_retries, 0);
    atomic_set(&ws_completion.spc_in_progress, 0);

    sectors_per_block = (uint32_t)(dev->cache_blk_size >> RNABLK_SECTOR_SHIFT);
    nsect_in_blk = min(nsectors, sectors_per_block -
                       (uint32_t)(lba % sectors_per_block));
    
    while (nsectors) {
        /* Limit the number of ios this request can have in-flight at a time */
        if (atomic_read(&ws_completion.spc_in_progress) >= MAX_CONCURRENT_WRITE_SAME_IOS) {
            KeWaitForSingleObject(&ws_completion.spc_complete, Executive, KernelMode, FALSE, NULL);
            if (ws_completion.spc_status != 0) {
                GOTO(drain, 0);
            }
        }

        ret = rnablk_alloc_ios(dev, &ws_completion, IOREQ_TYPE_SPC, min_access,
                               FALSE, TRUE, 1, &ios);
        if (unlikely(0 != ret)) {
            GOTO(drain, ret);
        }
        
        /* do initialization of the cache_cmd */

        req = &ios->cmd->u.cache_write_same_req;
        resp = &ios->cmd->u.cache_write_same_req_resp_buf.wsb_resp;

        if (IS_SCSI_UNMAP != unmap_type) {
            /* no more data for SCSI UNMAP command */
            RtlCopyMemory(req->ws_data, pDataBuffer, RNA_WRITE_SAME_SIZE);
        } else {
            /* initialize to 0 for SCSI_UNMAP */
            RtlZeroMemory(req->ws_data, sizeof(req->ws_data));
        }

        req->ws_start_lba = lba;
        req->ws_numblocks = nsect_in_blk;
        req->ws_sector_size = RNABLK_SECTOR_SIZE;
        req->ws_unmap = (unmap_type != 0);

        ios->cmd->h.h_type = CACHE_WRITE_SAME;

        /* finish ios setup and kick it off */

        ios->ios_iotype = IOS_IOTYPE_WRITE_SAME;
        ios->start_sector = lba;
        ios->nr_sectors = nsect_in_blk;

        /* adjust for next time through loop... */
        lba += nsect_in_blk;
        nsectors -= nsect_in_blk;
        nsect_in_blk = min(nsectors, sectors_per_block);

        atomic_inc(&ws_completion.spc_in_progress);

        rnablk_svcctl_register();
        rnablk_process_request(ios);
        rnablk_svcctl_deregister();
    }

drain:
    while (atomic_read(&ws_completion.spc_in_progress) > 0) {
        KeWaitForSingleObject(&ws_completion.spc_complete, Executive, KernelMode, FALSE, NULL);
    }

    if (0 != ws_completion.spc_status) {
        ret = -EIO;
    }

    return ret;
}

static int
rnablk_process_scsi_unmap(struct rnablk_device *dev,
                          rsv_itn_id_t *p_itn_id,
                          PSCSI_REQUEST_BLOCK pSrb,
                          uint8_t *scsi_cmd,
                          rsv_access_t min_access)
{
    rnablk_unmap10_t *cmd = (rnablk_unmap10_t*)scsi_cmd;
    uint8_t sense[SCSI_MAX_SENSE_LEN];
    int sense_len = 0;
    uint8_t scsi_status = SCSISTAT_GOOD;

    uint8_t param_data[RNABLK_SECTOR_SIZE];
    rnablk_unmap10_param_list_t *param_list;
    rnablk_unmap10_blk_desc_t *blk_desc;
    int i, num_desc;

    uint16_t param_list_len;
    uint64_t lba;
    uint32_t num_lbas;

    UCHAR cdbLength;
    ULONG dataXferLength;
    ULONG srbFlags;
    PVOID pDataBuffer;

    ENTER;

    cdbLength = SrbGetCdbLength(pSrb);
    dataXferLength = SrbGetDataTransferLength(pSrb);
    srbFlags = SrbGetSrbFlags(pSrb);
    pDataBuffer = SrbGetDataBuffer(pSrb);

    /* do command error checking */
    if (scsi_cmd_len(scsi_cmd[0]) != cdbLength) {
        rna_printk(KERN_DEBUG, "incorrect UNMAP cmd-length: %d\n",
                   cdbLength);
        GOTO(out, -EINVAL);
    }
    if (dataXferLength >= RNABLK_SECTOR_SIZE) {
        rna_printk(KERN_DEBUG, "unsupported UNMAP data-length %d\n",
                   dataXferLength);
        GOTO(out, -EINVAL);
    }
    if ( ! (srbFlags & SRB_FLAGS_DATA_OUT)) {
        rna_printk(KERN_DEBUG, "unsupported UNMAP direction. SrbFlags 0x%08x\n",
                   srbFlags);
        GOTO(out, -EINVAL);
    }

    switch (scsi_cmd[0]) {        
    case SCSIOP_UNMAP:
        param_list_len = RtlUshortByteSwap(cmd->um10_param_list_len);
        break;
    default:
        rna_printk(KERN_DEBUG, "unsupported unmap opcodce %d\n",
                   cmd->um10_opcode);
        GOTO(out, -EINVAL);
    }

    rna_printk(KERN_DEBUG, "UNMAP(%x) data[%d]\n",
                           scsi_cmd[0], param_list_len);
    if (param_list_len == 0) {
        /* no data; return success */
        GOTO(out, 0);
    }
    if (param_list_len < 8) {
        /* SBC-3 */
        rna_printk(KERN_DEBUG, "UNMAP bad param-list length\n");
        scsi_status = SCSISTAT_CHECK_CONDITION;
        memset(sense, 0, sizeof(sense));
        sense[0] = SCSI_SENSE_ERRORCODE_DESCRIPTOR_CURRENT;
        sense[1] = SCSI_SENSE_ILLEGAL_REQUEST;
        sense[2] = SCSI_ASC_PARAMETER_LIST_LENGTH_ERROR;
        sense_len = SCSI_MIN_REQ_SENSE_DESC_LEN;
        GOTO(out, 0);
    }
    if (param_list_len < sizeof(*param_list)) {
        /* not even 1 full block-descriptor; ignore */
        GOTO(out, 0);
    }
    if (cmd->um10_flags) {
        rna_printk(KERN_DEBUG, "UNMAP ANCHOR flag not supported\n");
        scsi_status = SCSISTAT_CHECK_CONDITION;
        memset(sense, 0, sizeof(sense));
        sense[0] = SCSI_SENSE_ERRORCODE_DESCRIPTOR_CURRENT;
        sense[1] = SCSI_SENSE_ILLEGAL_REQUEST;
        sense[2] = SCSI_ASC_INVALID_FIELD_IN_CDB;
        sense_len = SCSI_MIN_REQ_SENSE_DESC_LEN;
        GOTO(out, 0);
    }

    /* get user-data; it is an extension of the command */
    RtlCopyMemory(param_data, pDataBuffer, param_list_len);

    param_list = (rnablk_unmap10_param_list_t*)param_data;
    num_desc = (int)(RtlUshortByteSwap(param_list->ump_blk_desc_len) / sizeof(*blk_desc));
    rna_printk(KERN_DEBUG, "Total blk_desc[%d]\n", num_desc);

    /* parse block-descriptors for lba & num_lbas */
    blk_desc = &param_list->ump_blk_desc[0];
    for (i = 0; i < num_desc; i++, blk_desc++) {
        lba = RtlUlonglongByteSwap(blk_desc->umb_lba);
        num_lbas = RtlUlongByteSwap(blk_desc->umb_num_lbas);
        rna_printk(KERN_DEBUG, "blk_desc[%d] %"PRId64" %d\n", i, lba, num_lbas);
        /* send CACHE_WRITE_SAME with unmap flag */
        ret = rnablk_issue_write_same_ios(dev, pSrb, lba, num_lbas,
                                          IS_SCSI_UNMAP, min_access);
        if (0 != ret)
            break;
    }

    if (-EIO == ret) {
        scsi_status = SCSISTAT_CHECK_CONDITION;
        memset(sense, 0, sizeof(sense));
        sense[0] = SCSI_SENSE_ERRORCODE_FIXED_CURRENT;
        sense[2] = SCSI_SENSE_MEDIUM_ERROR;
        sense[7] = SCSI_ADSENSE_NO_SENSE;
        sense_len = 8;
        ret = 0;        
    }

 out:
    if (0 == ret) {
        ret = rnablk_sense_to_user(pSrb, scsi_status, sense, sense_len);
    }
    return ret;
}

static int
rnablk_process_scsi_write_same(struct rnablk_device *dev,
                               rsv_itn_id_t *p_itn_id,
                               PSCSI_REQUEST_BLOCK pSrb,
                               uint8_t *scsi_cmd,
                               rsv_access_t min_access)
{
    rnablk_write_same_t *ws_cmd = (rnablk_write_same_t*)scsi_cmd;
    rnablk_write_same_16_t *ws16_cmd = (rnablk_write_same_16_t*)scsi_cmd;
    uint8_t sense[SCSI_MAX_SENSE_LEN];
    int sense_len = 0;
    uint8_t scsi_status = SCSISTAT_GOOD;
    uint8_t ws_flags;
    uint64_t lba;
    uint32_t num_lbas;
    UCHAR cdbLength;
    ULONG dataXferLength;
    ULONG srbFlags;

    ENTER;

    cdbLength = SrbGetCdbLength(pSrb);
    dataXferLength = SrbGetDataTransferLength(pSrb);
    srbFlags = SrbGetSrbFlags(pSrb);

    /* do command error checking */
    if (scsi_cmd_len(scsi_cmd[0]) != cdbLength) {
        rna_printk(KERN_DEBUG, "incorrect WRITE_SAME command length: "
                   "%d\n", cdbLength);
        GOTO(out, -EINVAL);
    }
    if (dataXferLength != RNA_WRITE_SAME_SIZE) {
        rna_printk(KERN_DEBUG, "unsupported write_same data length %d\n",
                   dataXferLength);
        GOTO(out, -EINVAL);
    }
    if ( ! (srbFlags & SRB_FLAGS_DATA_OUT)) {
        rna_printk(KERN_DEBUG, "unsupported write_same direction. SrbFlags 0x%08x\n",
                   srbFlags);
        GOTO(out, -EINVAL);
    }
    switch (scsi_cmd[0]) {        
    case SCSIOP_WRITE_SAME:
        /* Get WRITE_SAME params */
        ws_flags = ws_cmd->ws10_flags;
        lba = RtlUlongByteSwap(ws_cmd->ws10_lba);
        num_lbas = RtlUshortByteSwap(ws_cmd->ws10_num_lbas);
        break;
    case SCSIOP_WRITE_SAME16:
        /* Get WRITE_SAME_16 params */
        ws_flags = ws16_cmd->ws16_flags;
        lba = RtlUlonglongByteSwap(ws16_cmd->ws16_lba);
        num_lbas = RtlUlongByteSwap(ws16_cmd->ws16_num_lbas);
        break;
    default:
        rna_printk(KERN_DEBUG, "unsupported write_same opcodce %d\n",
                   ws_cmd->ws10_opcode);
        GOTO(out, -EINVAL);
    }

    rna_printk(KERN_DEBUG, "Info: command=0x%0x\n", scsi_cmd[0]);
    rna_printk(KERN_DEBUG, "Info: flags=0x%0x\n", ws_flags);
    rna_printk(KERN_DEBUG, "Info: lba=%"PRId64"\n", lba);
    rna_printk(KERN_DEBUG, "Info: num_lbas=%d\n", num_lbas);

    /* TBD: Error on WS_FLAGS_OBSOLETE, PBDATA, LBDATA, and/or WRPROTECT? */

    if (ws_flags & WS_FLAGS_ANCHOR) {
        rna_printk(KERN_DEBUG, "WRITE_SAME ANCHOR flag not supported\n");
        scsi_status = SCSISTAT_CHECK_CONDITION;
        memset(sense, 0, sizeof(sense));
        sense[0] = SCSI_SENSE_ERRORCODE_DESCRIPTOR_CURRENT;
        sense[1] = SCSI_SENSE_ILLEGAL_REQUEST;
        sense[2] = SCSI_ASC_INVALID_FIELD_IN_CDB;
        sense_len = SCSI_MIN_REQ_SENSE_DESC_LEN;
        GOTO(out, 0);
    }

    ret = rnablk_issue_write_same_ios(dev, pSrb, lba, num_lbas,
                              (ws_flags & WS_FLAGS_UNMAP) ? IS_WS_UNMAP : 0,
                              min_access);

    /* TBD: WS specific failures ? */
    if (-EIO == ret) {
        scsi_status = SCSISTAT_CHECK_CONDITION;
        memset(sense, 0, sizeof(sense));
        sense[0] = SCSI_SENSE_ERRORCODE_FIXED_CURRENT;
        sense[2] = SCSI_SENSE_MEDIUM_ERROR;
        sense[7] = SCSI_ADSENSE_NO_SENSE;
        sense_len = 8;
        ret = 0;        
    }

 out:
    if (0 == ret) {
        ret = rnablk_sense_to_user(pSrb, scsi_status, sense, sense_len);
    }
    return ret;
}

static int
rnablk_process_scsi_turs(struct rnablk_device *dev,
                         rsv_itn_id_t *p_itn_id,
                         PSCSI_REQUEST_BLOCK pSrb,
                         uint8_t *scsi_cmd,
                         rsv_access_t min_access)
{
    uint8_t sense[SCSI_MAX_SENSE_LEN];
    int sense_len = 0;
    uint8_t scsi_status = SCSISTAT_GOOD;

    /* if block-device is failed, we can't accept IO */
    if (unlikely(atomic_read(&dev->failed))) {
        scsi_status = SCSISTAT_CHECK_CONDITION;
        memset(sense, 0, sizeof(sense));
        sense[0] = SCSI_SENSE_ERRORCODE_DESCRIPTOR_CURRENT;
        sense[1] = SCSI_SENSE_NOT_READY;
        sense[2] = SCSI_ADSENSE_LUN_NOT_READY; // LUN not ready
        sense[3] = 0xa; // transitioning
        sense_len = SCSI_MIN_REQ_SENSE_DESC_LEN;
    }

    return rnablk_sense_to_user(pSrb, scsi_status, sense, sense_len);
}

static int
rnablk_reject_scsi_command(PSCSI_REQUEST_BLOCK pSrb)
{
    int ret;
    int sense_len = 14;
    uint8_t sense[SCSI_MAX_SENSE_LEN];

    pSrb->SrbStatus = SRB_STATUS_INVALID_REQUEST;

    RtlZeroMemory(sense, sizeof(sense));
    sense[0] = SCSI_SENSE_ERRORCODE_FIXED_CURRENT;
    sense[2] = SCSI_SENSE_ILLEGAL_REQUEST;
    sense[7] = 6;    // Additional sense byte count
    sense[12] = SCSI_ADSENSE_ILLEGAL_COMMAND;   // invalid opcode
    sense[13] = 0x00;

    ret = rnablk_sense_to_user(pSrb, SCSISTAT_CHECK_CONDITION,
                               sense, sense_len);
    return ret;
}

static int
rnablk_process_scsi_service_action_in(struct rnablk_device *dev,
                                      rsv_itn_id_t *p_itn_id,
                                      PSCSI_REQUEST_BLOCK pSrb,
                                      uint8_t *scsi_cmd,
                                      rsv_access_t min_access)
{
    rsv_access_t needed_access;
    int ret;

    switch (scsi_cmd[1]) {
    case SCSI_SAI_SA_READ_CAPACITY_16:
        needed_access = RSV_ACC_NONE;
        break;

    case SCSI_SAI_SA_GET_LBA_STATUS:
        needed_access = RSV_ACC_READONLY;
        break;

    // @todo: ATOMIC_TEST_AND_SET??

    default:
        rna_printk(KERN_DEBUG, "SCSI passthru of %s opcode %#hhx "
                   "is not supported, failing\n", scsi_cmd_name(*scsi_cmd),
                   scsi_cmd[1]);

        return rnablk_reject_scsi_command(pSrb);
    }

    if (0 == rnablk_reservation_access_check(dev, needed_access)) {
        ret = rnablk_process_scsi_passthru(dev, p_itn_id, pSrb, scsi_cmd,
                                            needed_access);
        if (RSV_ACC_NONE != needed_access) {
            rnablk_dec_device_iocnt(dev, RSV_ACC_READONLY == needed_access
                                    ? FALSE : TRUE); 
        }
    } else {
        ret = rnablk_sense_to_user(pSrb, SCSISTAT_RESERVATION_CONFLICT, NULL, 0);
    }
    return ret;
}


/* returns TRUE if the ios gets 'finished' here. */
boolean
process_common_special_response(struct com_ep *ep, struct io_state *ios,
                                cache_resp_code status)
{
    rnablk_special_completion_t *cmp;
    long retry_delay_ms;
    long max_retries;
    int iostat = 0;
    struct sockaddr_in dst_in;

    cmp = (rnablk_special_completion_t *)ios->ios_spc_req;

    if (unlikely(CACHE_RESP_CODE_EAGAIN == status
                 || CACHE_RESP_CODE_OFFLINE == status
                 || (0 != status && !dev_is_persistent(ios->dev)))) {
        retry_delay_ms = CACHE_RESP_CODE_EAGAIN == status
                         ? RNABLK_EAGAIN_DELAY_MS : RNABLK_OFFLINE_DELAY_MS;
        max_retries = (rnablk_io_timeout * MSEC_PER_SEC) / retry_delay_ms;

        if (atomic_read(&cmp->spc_retries) < max_retries
            || CACHE_RESP_CODE_OFFLINE == status) {

            if (0 == atomic_read(&cmp->spc_retries)) {
                /* avoid on-going message spew; only log once (per episode) */
                rna_printk(KERN_RSV, "Error [%s] for [%s] ios [%p] tag "
                           "["TAGFMT"] type [%s] block [%llu] state [%s] "
                           "ref [%s], retrying\n",
                           get_cache_resp_code(status),
                           ios->dev->name, ios, TAGFMTARGS(ios->tag),
                           rnablk_op_type_string(ios->type),
                           ios->blk->block_number,
                           rnablk_cache_blk_state_string(ios->blk->state),
                           get_lock_type_string(ios->blk->ref_type));
            }
            atomic_inc(&cmp->spc_retries);
            rnablk_retrack_ios(ios);
            rnablk_queue_delayed_request(ios, retry_delay_ms);
            return FALSE; 
        } else {
            dst_in = get_dest_sockaddr_from_ep(ep);
            rna_printk(KERN_ERR, "Error [%s] from CS ["NIPQUAD_FMT"] for "
                       "[%s] ios [%p] tag ["TAGFMT"] type [%s] block [%llu] "
                       "state [%s] ref [%s] on device [%s], failing after "
                       "%d retries\n",
                       get_cache_resp_code(status),
                       NIPQUAD(dst_in.sin_addr.s_addr),
                       ios->dev->name, ios, TAGFMTARGS(ios->tag),
                       rnablk_op_type_string(ios->type),
                       ios->blk->block_number,
                       rnablk_cache_blk_state_string(ios->blk->state),
                       get_lock_type_string(ios->blk->ref_type),
                       ios->dev->name,
                       atomic_read(&cmp->spc_retries));
            iostat = -EIO;
        } 
    } else if (unlikely(0 != status)) {
            dst_in = get_dest_sockaddr_from_ep(ep);
            rna_printk(KERN_ERR, "Error [%s] from CS ["NIPQUAD_FMT"] for "
                   "[%s] ios [%p] tag ["TAGFMT"] type [%s] block [%llu] "
                   "state [%s] ref [%s] on device [%s]\n",
                   get_cache_resp_code(status),
                   NIPQUAD(dst_in.sin_addr.s_addr),
                   ios->dev->name, ios, TAGFMTARGS(ios->tag),
                   rnablk_op_type_string(ios->type),
                   ios->blk->block_number,
                   rnablk_cache_blk_state_string(ios->blk->state),
                   get_lock_type_string(ios->blk->ref_type),
                   ios->dev->name);
        iostat = -EIO;
    }

    if (0 != status && 0 == cmp->spc_status) {
        cmp->spc_status = status;
    }
    rnablk_end_request(ios, iostat);
    return TRUE;
}

int
rnablk_sg_reset(struct rnablk_device *dev)
{
    uint8_t             scsi_release[6] = {SCSIOP_RELEASE_UNIT};
    SCSI_REQUEST_BLOCK  Srb;
    int                 ret;

    //
    // The NO_DATA_TRANSFER flag is redundant because the memset
    // will make the SrbFlags field 0, but setting the field with
    // this flag documents what we are doing and if for some reason
    // in the future NO_DATA_TRANSFER is a different value (i.e., 
    // presently it is 0) then the code will still work as expected.
    //
    memset(&Srb, 0, sizeof(SCSI_REQUEST_BLOCK));
    Srb.Length = sizeof(SCSI_REQUEST_BLOCK);
    Srb.CdbLength = sizeof(scsi_release);
    Srb.SrbFlags = SRB_FLAGS_NO_DATA_TRANSFER;

    /* internal command */
    ret = rnablk_process_scsi_passthru_ext(dev, 0, &Srb, scsi_release,
                                           RSV_ACC_NONE, RNABLK_SG_LUN_RESET);
    if (0 == ret)
        ret = Srb.SrbStatus;

    return ret;
}

void
rnablk_end_special(struct io_state *ios, int error)
{
    rnablk_special_completion_t *cmpl = (rnablk_special_completion_t *)
                                           ios->ios_spc_req;

    ios->ios_spc_req = NULL;
    ios->ios_req_type = IOREQ_TYPE_NOREQ;
    if (0 != error && 0 == cmpl->spc_status) {
        cmpl->spc_status = CACHE_RESP_CODE_STORAGE_ERROR;
    }
    atomic_dec(&cmpl->spc_in_progress);
    KeSetEvent(&cmpl->spc_complete, 0, FALSE);
}


void
rnablk_device_process_thinprov_state(struct rnablk_device *dev,
                                     int thinprov_state)
{
    switch (thinprov_state) {
    case RNA_VOL_LOWSPACE:
    case RNA_VOL_NORMAL:
    case RNA_VOL_OUTOFSPACE:
        InterlockedExchange((LONG volatile *)&dev->thinState, thinprov_state);
        break; 

    default:
        rna_printk(KERN_ERR, "Unexpected thin provision state value [%d] for "
                   "device [%s]\n", thinprov_state, dev->name);
        break;
    }
}

/*
 * rnablk_io_scsi_sense
 *
 * Fill in sense data for IO requests, if needed.
 * For Writes, check to see if thin provisioning state needs to be reported.
 *
 */
void rnablk_io_scsi_sense(struct rnablk_device *dev, PSCSI_REQUEST_BLOCK pSrb, int err)
{
    // Initialize status and sense_len to assume everything is OK.
    // For success case, we'll get to the rnablk_sense_to_user call
    // without doing anything else.
    // Other conditions will set sense data along the way.

    uint8_t status = SCSISTAT_GOOD;
    int sense_len = 0;
    uint8_t addtl_sense = 6;
    uint8_t sense[SCSI_MAX_SENSE_LEN];
    LONG currentState;
    PHW_SRB_EXTENSION pSrbExtension;

    pSrbExtension = (PHW_SRB_EXTENSION) SrbGetMiniportContext(pSrb);

    if (pSrbExtension->isWrite) {
        // See if "low space" state has been set.  If so, clear it and report it so we
        // only report it once.

        currentState = InterlockedCompareExchange((LONG volatile*)&dev->thinState, 
                                                  RNA_VOL_NORMAL, RNA_VOL_LOWSPACE);

        if (RNA_VOL_LOWSPACE == currentState) {
            status = SCSISTAT_CHECK_CONDITION;
            sense_len = 8 + addtl_sense;
            RtlZeroMemory(sense, sizeof(sense));
            sense[0] = SCSI_SENSE_ERRORCODE_FIXED_CURRENT;
            sense[2] = SCSI_SENSE_UNIT_ATTENTION;
            sense[7] = addtl_sense;    // Additional sense byte count
            sense[12] = SCSI_ADSENSE_LB_PROVISIONING;
            sense[13] = SCSI_SENSEQ_SOFT_THRESHOLD_REACHED;
        }
        else {
//            if (0 != err) {
//                status = SCSISTAT_CHECK_CONDITION;
//                RtlZeroMemory(sense, sizeof(sense));
//                sense_len = 8 + addtl_sense;

                if (RNA_VOL_OUTOFSPACE == currentState) {
                                    status = SCSISTAT_CHECK_CONDITION;
                                    RtlZeroMemory(sense, sizeof(sense));
                                    sense_len = 8 + addtl_sense;

                    sense[0] = SCSI_SENSE_ERRORCODE_FIXED_CURRENT;
                    sense[2] = SCSI_SENSE_DATA_PROTECT;
                    sense[7] = addtl_sense;    // Additional sense byte count
                    sense[12] = SCSI_ADSENSE_WRITE_PROTECT;
                    sense[13] = SCSI_SENSEQ_SPACE_ALLOC_FAILED_WRITE_PROTECT;
                }
                else {
                    if (0!=err) {  //test
                                    status = SCSISTAT_CHECK_CONDITION;
                                    RtlZeroMemory(sense, sizeof(sense));
                                    sense_len = 8 + addtl_sense;

                    sense[0] = SCSI_SENSE_ERRORCODE_FIXED_CURRENT;
                    sense[2] = SCSI_SENSE_MEDIUM_ERROR;
                    sense[7] = addtl_sense;    // Additional sense byte count
                    sense[12] = SCSI_ADSENSE_WRITE_ERROR;
                    sense[13] = 0x00;
                    }  //test
                }
//            }
        }
    }
    else {
        if (0 != err) {
            status = SCSISTAT_CHECK_CONDITION;
            sense_len = 8 + addtl_sense;
            RtlZeroMemory(sense, sizeof(sense));
            sense[0] = SCSI_SENSE_ERRORCODE_FIXED_CURRENT;
            sense[2] = SCSI_SENSE_MEDIUM_ERROR;
            sense[7] = addtl_sense;    // Additional sense byte count
            sense[12] = SCSI_ADSENSE_UNRECOVERED_ERROR;
            sense[13] = SCSI_SENSEQ_UNRECOVERED_READ_ERROR;
        }
    }

    rnablk_sense_to_user(pSrb, status, sense, sense_len);
}


