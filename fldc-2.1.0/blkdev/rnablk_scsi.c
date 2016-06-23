/**
 * <rnablk_scsi.c> - Dell Fluid Cache block driver
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
#include "trace.h"

typedef struct rnablk_special_completion_s {
    struct completion spc_complete;
    int spc_status;
    atomic_t spc_retries;
} rnablk_special_completion_t;

static int
rnablk_data_from_caller(struct sg_io_hdr *hdr, void *to, unsigned long n,
                        int internal_cmd)
{
    int res = 0, i;
    void *index = to;
    unsigned long not_copied;
    size_t remaining = n, xfer_len;

    if (hdr->iovec_count > 0) {
        struct sg_iovec *sgl = hdr->dxferp;
        for (i = 0; i < hdr->iovec_count; i++) {
            xfer_len = min(remaining, sgl[i].iov_len);
            if (! internal_cmd) {
                not_copied = copy_from_user(index, __user sgl[i].iov_base,
                                            xfer_len);
                if (not_copied) {
                    res = -EFAULT;
                    break;
                }
            } else {
                memcpy(index, sgl[i].iov_base, xfer_len);
            }
            index += xfer_len;
            remaining -= xfer_len;
            if (remaining == 0)
                break;
        }
        return res;
    }
    if (! internal_cmd) {
        not_copied = copy_from_user(to, __user hdr->dxferp, n);
        if (not_copied)
            res = -EFAULT;
    } else {
        memcpy(to, hdr->dxferp, n);
    }
    return res;
}

static int
rnablk_data_from_user(struct sg_io_hdr *hdr, void *to, unsigned long n)
{
    /* call the wrapper fn... not internal_cmd */
    return rnablk_data_from_caller(hdr, to, n, 0);
}

static int
rnablk_data_to_caller(struct sg_io_hdr *hdr, void *from, unsigned long n,
                      int internal_cmd)
{
    int res = 0, i;
    void *index = from;
    unsigned long not_copied;
    size_t remaining = n, xfer_len;

    if (hdr->iovec_count > 0) {
        struct sg_iovec *sgl = hdr->dxferp;
        for (i = 0; i < hdr->iovec_count; i++) {
            xfer_len = min(remaining, sgl[i].iov_len);
            if (! internal_cmd) {
                not_copied = copy_to_user(__user sgl[i].iov_base, index, xfer_len);
                if (not_copied) {
                    res = -EFAULT;
                    break;
                }
            } else {
                memcpy(sgl[i].iov_base, index, xfer_len);
            }
            index += xfer_len;
            remaining -= xfer_len;
            if (remaining == 0)
                break;
        }
        return res;
    }
    if (! internal_cmd) {
        not_copied = copy_to_user(__user hdr->dxferp, from, n);
        if (not_copied)
            res = -EFAULT;
    } else {
        memcpy(hdr->dxferp, from, n);
    }
    return res;
}

static int
rnablk_data_to_user(struct sg_io_hdr *hdr, void *to, unsigned long n)
{
    /* call the wrapper fn... not internal_cmd */
    return rnablk_data_to_caller(hdr, to, n, 0);
}

static int
rnablk_sense_to_caller(struct sg_io_hdr *hdr, u8 status, const u8 *sense_buf,
                       int sense_len, int internal_cmd)
{
    int res = 0;

    hdr->sb_len_wr = 0;

    /*
     * Since we're only passing in an 8-bit status, these fields are
     * always going to be 0.
     */
    hdr->msg_status = 0;
    hdr->host_status = 0;
    hdr->driver_status = 0;

    if (scsi_status_is_good(status)) {
        hdr->status = 0;
        hdr->masked_status = 0;
    } else {
        hdr->status = status;
        hdr->masked_status = status_byte(status);

        if (sense_len && hdr->sbp) {
            hdr->sb_len_wr = min_t(u8, hdr->mx_sb_len, sense_len);
            if (! internal_cmd) {
                if (copy_to_user(__user hdr->sbp, sense_buf, hdr->sb_len_wr)) {
                    res = -EFAULT;
                }
            } else {
                memcpy(hdr->sbp, sense_buf, hdr->sb_len_wr);
            }
        }
    }
    return res;
}

static int
rnablk_sense_to_user(struct sg_io_hdr *hdr, u8 status, const u8 *sense_buf,
                     int sense_len)
{
    /* call the wrapper fn... not internal_cmd */
    return rnablk_sense_to_caller(hdr, status, sense_buf, sense_len, 0);
}

/* called with queue lock held */
static void
rnablk_passthru_req_endio(struct request *rq, int error)
{
    struct completion *waiting = rq->end_io_data;

    /* save status & complete */
    rq->end_io_data = NULL;

    /* don't "put" the request; the i/o initiator needs it when woken up */
    /* __blk_put_request(rq->q, rq); */

    complete(waiting);
}

typedef struct scsi_command_info_s {
    uint8_t sci_opcode;
    uint8_t sci_cmdlen;
    uint8_t sci_writemode;          // true if cmd requires write permission
    rsv_access_t sci_min_access;    // minimum device access needed to execute
                                    // command (related to device reservations)
    char    *sci_name;              // string name for opcode (may be null)
    int     (*sci_handler)(struct rnablk_device *, rsv_itn_id_t *,
                           struct sg_io_hdr *, uint8_t *, rsv_access_t);
} scsi_command_info_t;

#define scsi_cmd_len(cmd)    rnablk_scsi_commands[(cmd)].sci_cmdlen
#define scsi_cmd_name(cmd)   rnablk_scsi_commands[(cmd)].sci_name
#define scsi_cmd_writemode(cmd) (rnablk_scsi_commands[(cmd)].sci_writemode != 0)
#define scsi_cmd_minaccess(cmd) rnablk_scsi_commands[(cmd)].sci_min_access

static int rnablk_process_scsi_passthru(struct rnablk_device *dev,
                                               rsv_itn_id_t *p_itn_id,
                                               struct sg_io_hdr *hdr,
                                               uint8_t *scsi_cmd,
                                               rsv_access_t min_access);
static int rnablk_process_scsi_read_or_write(struct rnablk_device *dev,
                                             rsv_itn_id_t *p_itn_id,
                                             struct sg_io_hdr *hdr,
                                             uint8_t *scsi_cmd,
                                             rsv_access_t min_access);
static int rnablk_process_scsi_compare_and_write(struct rnablk_device *dev,
                                                 rsv_itn_id_t *p_itn_id,
                                                 struct sg_io_hdr *hdr,
                                                 uint8_t *scsi_cmd,
                                                 rsv_access_t min_access);
static int rnablk_process_scsi_write_same(struct rnablk_device *dev,
                                          rsv_itn_id_t *p_itn_id,
                                          struct sg_io_hdr *hdr,
                                          uint8_t *scsi_cmd,
                                          rsv_access_t min_access);
static int rnablk_process_scsi_unmap(struct rnablk_device *dev,
                                     rsv_itn_id_t *p_itn_id,
                                     struct sg_io_hdr *hdr,
                                     uint8_t *scsi_cmd,
                                     rsv_access_t min_access);
static int rnablk_process_scsi_not_implemented_yet(struct rnablk_device *dev,
                                                   rsv_itn_id_t *p_itn_id,
                                                   struct sg_io_hdr *hdr,
                                                   uint8_t *scsi_cmd,
                                                   rsv_access_t min_access);
static int rnablk_process_scsi_turs(struct rnablk_device *dev,
                                    rsv_itn_id_t *p_itn_id,
                                    struct sg_io_hdr *hdr,
                                    uint8_t *scsi_cmd,
                                    rsv_access_t min_access);
static int rnablk_reject_scsi_command(struct sg_io_hdr *hdr, uint8_t *cmd);
static int rnablk_process_scsi_service_action_in(struct rnablk_device *dev,
                                                 rsv_itn_id_t *p_itn_id,
                                                 struct sg_io_hdr *hdr,
                                                 uint8_t *scsi_cmd,
                                                 rsv_access_t min_access);
static int rnablk_process_scsi_maintenance_in(struct rnablk_device *dev,
                                                 rsv_itn_id_t *p_itn_id,
                                                 struct sg_io_hdr *hdr,
                                                 uint8_t *scsi_cmd,
                                                 rsv_access_t min_access);


static scsi_command_info_t rnablk_scsi_commands[] = {
    [COMPARE_AND_WRITE] { COMPARE_AND_WRITE, 16, 1, RSV_ACC_READWRITE,
                          "COMPARE_AND_WRITE",
                          rnablk_process_scsi_compare_and_write },
    [EXTENDED_COPY]     { EXTENDED_COPY, 16, 1, RSV_ACC_READWRITE,
                          "EXTENDED_COPY",
                          rnablk_process_scsi_not_implemented_yet, },
    [FORMAT_UNIT]       { FORMAT_UNIT, 6, 1, RSV_ACC_READWRITE,
                          "FORMAT_UNIT",
                          rnablk_process_scsi_passthru },
    [INQUIRY]           { INQUIRY, 6, 0, RSV_ACC_NONE,
                          "INQUIRY",
                          rnablk_process_scsi_passthru },
    [MODE_SENSE]        { MODE_SENSE, 6, 0, RSV_ACC_READONLY,
                          "MODE_SENSE_6",
                          rnablk_process_scsi_passthru },
    [MODE_SENSE_10]     { MODE_SENSE_10, 10, 0, RSV_ACC_READONLY,
                          "MODE_SENSE_10",
                          rnablk_process_scsi_passthru },
    [PERSISTENT_RESERVE_IN] { PERSISTENT_RESERVE_IN, 10, 0, RSV_ACC_NONE,
                          "PERSISTENT_RESERVE_IN",
                          rnablk_process_scsi_passthru },
    /* note: rsvtn access checking happens at Cache Server for RESERVE_OUT */
    [PERSISTENT_RESERVE_OUT] { PERSISTENT_RESERVE_OUT, 10, 1, RSV_ACC_NONE,
                          "PERSISTENT_RESERVE_OUT",
                          rnablk_process_scsi_passthru },
    [READ_6]            { READ_6, 6, 0, RSV_ACC_READONLY,
                          "READ_6",
                          rnablk_process_scsi_read_or_write },
    [READ_10]           { READ_10, 10, 0, RSV_ACC_READONLY,
                          "READ_10",
                          rnablk_process_scsi_read_or_write },
    [READ_12]           { READ_12, 12, 0, RSV_ACC_READONLY,
                          "READ_12",
                          rnablk_process_scsi_read_or_write },
    [READ_16]           { READ_16, 16, 0, RSV_ACC_READONLY,
                          "READ_16",
                          rnablk_process_scsi_read_or_write },
    [READ_CAPACITY]     { READ_CAPACITY, 10, 0, RSV_ACC_NONE,
                          "READ_CAPACITY",
                          rnablk_process_scsi_passthru },
    [RELEASE]           { RELEASE, 6, 1, RSV_ACC_READWRITE,
                          "RELEASE_6",
                          rnablk_process_scsi_passthru },
    [RELEASE_10]        { RELEASE_10, 10, 1, RSV_ACC_READWRITE,
                          "RELEASE_10",
                          rnablk_process_scsi_passthru },
    [REPORT_LUNS]       { REPORT_LUNS, 12, 0, RSV_ACC_NONE,
                          "REPORT_LUNS",
                          rnablk_process_scsi_passthru },
    [REQUEST_SENSE]     { REQUEST_SENSE, 6, 0, RSV_ACC_NONE,
                          "REQUEST_SENSE",
                          rnablk_process_scsi_passthru },
    [RESERVE]           { RESERVE, 6, 1, RSV_ACC_READWRITE,
                          "RESERVE_6",
                          rnablk_process_scsi_passthru, },
    [RESERVE_10]        { RESERVE_10, 10, 1, RSV_ACC_READWRITE,
                          "RESERVE_10",
                          rnablk_process_scsi_passthru, },
    /* note: rsvtn access for below depends on subcommand */
    [SERVICE_ACTION_IN] { SERVICE_ACTION_IN, 16, 0, RSV_ACC_NONE,
                          "SERVICE_ACTION_IN",
                          rnablk_process_scsi_service_action_in },
    [TEST_UNIT_READY]   { TEST_UNIT_READY, 6, 0, RSV_ACC_NONE,
                          "TEST_UNIT_READY",
                          rnablk_process_scsi_turs },
    [UNMAP]             { UNMAP, 10, 1, RSV_ACC_READWRITE,
                          "UNMAP",
                          rnablk_process_scsi_unmap },
    [WRITE_6]           { WRITE_6, 6, 1, RSV_ACC_READWRITE,
                          "WRITE_6",
                          rnablk_process_scsi_read_or_write },
    [WRITE_10]          { WRITE_10, 10, 1, RSV_ACC_READWRITE,
                          "WRITE_10",
                          rnablk_process_scsi_read_or_write },
    [WRITE_12]          { WRITE_12, 12, 1, RSV_ACC_READWRITE,
                          "WRITE_12",
                          rnablk_process_scsi_read_or_write },
    [WRITE_16]          { WRITE_16, 16, 1, RSV_ACC_READWRITE,
                          "WRITE_16",
                          rnablk_process_scsi_read_or_write },
    [WRITE_SAME]        { WRITE_SAME, 10, 1, RSV_ACC_READWRITE,
                          "WRITE_SAME_10",
                          rnablk_process_scsi_write_same },
    [WRITE_SAME_16]     { WRITE_SAME_16, 16, 1, RSV_ACC_READWRITE,
                          "WRITE_SAME_16",
                          rnablk_process_scsi_write_same },
    [WRITE_VERIFY]      { WRITE_VERIFY, 10, 1, RSV_ACC_READWRITE,
                          "WRITE_VERIFY",
                          rnablk_process_scsi_read_or_write },
    [WRITE_VERIFY_12]   { WRITE_VERIFY_12, 12, 1, RSV_ACC_READWRITE,
                          "WRITE_VERIFY_12",
                          rnablk_process_scsi_read_or_write },
    [WRITE_VERIFY_16]   { WRITE_VERIFY_16, 16, 1, RSV_ACC_READWRITE,
                          "WRITE_VERIFY_16",
                          rnablk_process_scsi_read_or_write },
    /* note: rsvtn access for below depends on subcommand */
    [MAINTENANCE_IN]    { MAINTENANCE_IN, 12, 0, RSV_ACC_NONE,
                          "MAINTENANCE_IN",
                          rnablk_process_scsi_maintenance_in },
};
int rnablk_n_scsi_commands =
                sizeof(rnablk_scsi_commands)/sizeof(scsi_command_info_t);

int
rnablk_sg_io(struct rnablk_device *dev, rsv_itn_id_t *p_itn_id,
             struct sg_io_hdr *hdr, fmode_t mode)
{
    uint8_t scsi_command[SCSI_MAX_CMD_LEN];
    uint8_t cmd;
    int ret = 0;

    if (hdr->interface_id != 'S' || hdr->cmd_len > BLK_MAX_CDB) {
        return -EINVAL;
    }

    if (hdr->cmd_len > 0 && hdr->cmd_len <= sizeof(scsi_command)) {
        memset(scsi_command, 0, sizeof(scsi_command));
        if (copy_from_user(scsi_command, __user hdr->cmdp, hdr->cmd_len)) {
            rna_printk(KERN_DEBUG, "copy passthru cmd from user failed\n");
            return -EFAULT;
        }
    } else {
        return -EINVAL;
    }

    if (hdr->dxfer_len) {
        switch (hdr->dxfer_direction) {
        case SG_DXFER_TO_DEV:
        case SG_DXFER_TO_FROM_DEV:
        case SG_DXFER_FROM_DEV:
            break;

        default:
            return -EINVAL;
        }
    } else {
        hdr->dxfer_direction = SG_DXFER_NONE;
    }

    cmd = scsi_command[0];
    if (cmd >= rnablk_n_scsi_commands
        || NULL == rnablk_scsi_commands[cmd].sci_handler) {
        rna_printk(KERN_DEBUG, "scsi cmd %#hhx not supported for passthru, "
                   "failing\n", cmd);
        // default handler
        ret = rnablk_reject_scsi_command(hdr, scsi_command);
    } else if (0 == rnablk_reservation_access_check(dev,
                                                    scsi_cmd_minaccess(cmd))) {
        rna_printk(KERN_DEBUG, "Issuing scsi cmd %s\n", scsi_cmd_name(cmd));
        ret = rnablk_scsi_commands[cmd].sci_handler(dev, p_itn_id, hdr,
                                                    scsi_command,
                                                    scsi_cmd_minaccess(cmd));
        rna_printk(KERN_DEBUG, "scsi cmd %s done, ret=%d\n", scsi_cmd_name(cmd),
                   ret);
        if (-ENODEV == ret || -ENOMEM == ret || -EBUSY == ret) {
            /* can be retried */
            uint8_t sense[SCSI_MIN_REQ_SENSE_DESC_LEN];
            memset(sense, 0, sizeof(sense));
            sense[0] = 0x72;
            sense[1] = NOT_READY;
            sense[2] = SCSI_ASC_LUN_NOT_READY;
            sense[3] = SCSI_ASCQ_LUN_TRANSITIONING;
            ret = rnablk_sense_to_user(hdr, SAM_STAT_CHECK_CONDITION, sense,
                                       SCSI_MIN_REQ_SENSE_DESC_LEN);
        }
        if (RSV_ACC_NONE != scsi_cmd_minaccess(cmd)) {
            rnablk_dec_device_iocnt(dev, scsi_cmd_writemode(cmd));
        }
    } else {
        rna_printk(KERN_DEBUG, "Can't issue scsi cmd %s due to RSV CONFLICT\n",
                   scsi_cmd_name(cmd));
        hdr->resid = hdr->dxfer_len;
        rnablk_sense_to_user(hdr, SAM_STAT_RESERVATION_CONFLICT, NULL, 0);
    }

    return ret;
}

typedef enum vpd_page_numbers_s {
    /* we want to change the response for these */
    VPD_BLOCK_LIMITS = 0xb0,
    VPD_BLOCK_PROVISIONING = 0xb2,
} vpd_page_numbers_t;

/* byte[5]=LBPU:LBPWS:LBPWS10:RSVD[2]:LBPRZ:ANC_SUP:DP */
#define VPD_BLOCK_PROVISIONING_FOR_UNMAP        (1 << 7)   // LBPU
#define VPD_BLOCK_PROVISIONING_FOR_WRITE_SAME   (3 << 5)   // LBPWS:LBPWS10

static void
rnablk_transform_vpd_page_data(uint8_t vpd_page_num,
                               uint8_t *data, uint8_t len)
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

    case VPD_BLOCK_PROVISIONING:
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
                                 struct sg_io_hdr *hdr,
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
    boolean hold_ios = FALSE;
    ENTER;

    /* do command error checking */

    if (hdr->cmd_len > sizeof(cs->scsi_command)) {
        GOTO(out, -EINVAL);
    }

    if (hdr->dxfer_len > SCSI_MAX_DATA_PAYLOAD
        || hdr->dxfer_len > sizeof(sr->data)) {
        rna_printk(KERN_DEBUG, "passthru data too big: xfer_len=%d "
                   "MAX_PAYLOAD=%d queue_max=%d bufsz=%lu\n",
                   hdr->dxfer_len, SCSI_MAX_DATA_PAYLOAD,
                   rna_queue_max_sectors(dev->q) << 9, sizeof(sr->data));
        GOTO(out, -EINVAL);
    }

    init_completion(&complete.spc_complete);
    complete.spc_status = 0;
    atomic_set(&complete.spc_retries, 0);

    ret = rnablk_alloc_ios(dev, &complete, IOREQ_TYPE_SPC, min_access, FALSE,
                           FALSE, 1, &ios);
    if (unlikely(0 != ret)) {
        GOTO(out, ret);
    }

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
    memcpy(cs->scsi_command, scsi_cmd, hdr->cmd_len);
    cs->cmd_len = hdr->cmd_len;
    cs->xfer_length = hdr->dxfer_len;

    cs->writing = (SG_DXFER_TO_DEV == hdr->dxfer_direction);
    cs->reset_action = (RNABLK_SG_LUN_RESET == cmd_src) ? 1 : 0;

    if (cs->writing) {
        if (rnablk_data_from_caller(hdr, sr->data, hdr->dxfer_len,
                                    internal_cmd)) {
            rna_printk(KERN_DEBUG, "copy passthru data %s failed\n",
                                   internal_cmd ? "internal" : "from user");
            GOTO(out, -EFAULT);
        }
    }

    /* finish ios setup and kick it off */

    blk = MASTER_BLK(ios->dev);

    rnablk_set_ios_blk(ios, blk);

    rnablk_svcctl_register();

    if (!rnablk_blk_connected(blk)
        || NULL == (ep = blk->ep)
        || MD_CONN_EP_METAVALUE == ep) {
        hold_ios = TRUE;
    }
    
    rnablk_set_ios_timer(ios);

    if (!hold_ios && dev_io_allowed(dev)) {
        rnablk_queue_request(RNABLK_SCSI_PASSTHRU, ep, ios, blk,
                             NO_FORCE_QUEUED_IO, FALSE);
    } else {
        rna_printk(KERN_NOTICE, "No MASTER so stall passthru for device [%s] "
                   "ios [%p] scmd [%#hhx]\n", dev->name, ios,
                   cs->scsi_command[0]);
        hold_ios = TRUE;
        ios->type = RNABLK_SCSI_PASSTHRU;
        rnablk_queue_blk_io(blk, ios, QUEUE_TAIL);
    }
    rnablk_svcctl_deregister();
    ios_issued = TRUE;

    /* wait for it to finish and do error handling */

    wait_for_completion(&complete.spc_complete);

    if (hold_ios) {
        /* we may want to be less verbose here eventually, but for now.. */
        rna_printk(KERN_NOTICE, "device [%s]: stalled ios [%p] completed "
                   "(spcstat=%d csstat=%#hhx)\n", dev->name, ios,
                   complete.spc_status, sr->cs_status);
    }

    if (unlikely(0 != complete.spc_status && 0 == sr->cs_status)) {
        sr->cs_status = complete.spc_status;
    }

    if (0 != sr->cs_status) {
        /* some kind of cache error; generate a SCSI error out of it */
        if (CACHE_RESP_CODE_EINVAL != sr->cs_status) {
            sr->scsi_status = SAM_STAT_CHECK_CONDITION;
            memset(sr->sense, 0, 8);
            sr->sense[0] = 0x70;
            sr->sense[2] = MEDIUM_ERROR;
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
        hdr->resid = hdr->dxfer_len - sr->xferd_length;
        ret = rnablk_sense_to_caller(hdr, sr->scsi_status, sr->sense,
                                     sr->sense_length, internal_cmd);
        if (ret) {
                rna_printk(KERN_DEBUG, "copy sense data %s failed\n",
                                       internal_cmd ? "internal" : "to user");
        } else if (scsi_status_is_good(sr->scsi_status) && !cs->writing) {
            if (INQUIRY == scsi_cmd[0] && 0 != scsi_cmd[2]) {
                /* INQUIRY with non-zero VPD page */
                rnablk_transform_vpd_page_data(scsi_cmd[2],
                                               sr->data, sr->xferd_length);
            }
            ret = rnablk_data_to_caller(hdr, sr->data, hdr->dxfer_len,
                                        internal_cmd);
            if (ret) {
                rna_printk(KERN_DEBUG, "copy passthru data %s failed\n",
                                       internal_cmd ? "internal" : "to user");
            }
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
                                    struct sg_io_hdr *hdr,
                                    uint8_t *scsi_cmd,
                                    rsv_access_t min_access)
{
    /* call the wrapper fn... not internal_cmd */
    return rnablk_process_scsi_passthru_ext(dev, p_itn_id, hdr, scsi_cmd,
                                            min_access, RNABLK_SG_IO_USER);
}

static int
rnablk_process_scsi_read_or_write(struct rnablk_device *dev,
                                  rsv_itn_id_t *p_itn_id,
                                  struct sg_io_hdr *hdr,
                                  uint8_t *scsi_cmd,
                                  rsv_access_t min_access)
{
    struct completion complete;
    struct request *rq = NULL;
    struct bio *bio;
    uint8_t scsi_status = SAM_STAT_GOOD;
    uint8_t sense[SCSI_MAX_SENSE_LEN];
    struct io_state *ios[RNABLK_MAX_SUB_IO];
    int n_ios;
    int sense_len = 0;
    uint64_t lba;
    uint32_t xfer_len;
    int error = 0;
    int i;
    ENTER;

    switch (scsi_cmd[0]) {
    case READ_6:
    case WRITE_6:
        lba = ((scsi_cmd[1] & 0x1f) << 16) | (scsi_cmd[2] << 8) | scsi_cmd[3];
        xfer_len = scsi_cmd[4];
        break;

    case READ_10:
    case WRITE_10:
    case WRITE_VERIFY:
        lba = be32_to_cpu(*(uint32_t *)&scsi_cmd[2]);
        xfer_len = be16_to_cpu(*(uint16_t *)&scsi_cmd[7]);
        break;

    case READ_12:
    case WRITE_12:
    case WRITE_VERIFY_12:
        lba = be32_to_cpu(*(uint32_t *)&scsi_cmd[2]);
        xfer_len = be32_to_cpu(*(uint32_t *)&scsi_cmd[6]);
        break;

    case READ_16:
    case WRITE_16:
    case WRITE_VERIFY_16:
        lba = be64_to_cpu(*(uint64_t *)&scsi_cmd[2]);
        xfer_len = be32_to_cpu(*(uint32_t *)&scsi_cmd[10]);
        break;

    default:
        RNABLK_BUG_ON(TRUE, "unexpected scsi_cmd = %#hhx\n", scsi_cmd[0]);
    }
    rna_printk(KERN_DEBUG, "scsi cmd=%#hhx name=%s lba=%llu xfer_len=%u\n",
               scsi_cmd[0], scsi_cmd_name(scsi_cmd[0]), lba, xfer_len);

    /* do bio and ios generic setup */

    if (scsi_cmd_writemode(scsi_cmd[0]) !=
        (SG_DXFER_TO_DEV == hdr->dxfer_direction)) {
        /* data direction doesn't match actual scsi cmd direction */
        GOTO(out, -EINVAL);
    }

	rq = blk_get_request(dev->q, (SG_DXFER_TO_DEV == hdr->dxfer_direction)
                         ? WRITE : READ, GFP_KERNEL);
    if (NULL == rq) {
        GOTO(out, -ENOMEM);
    }
    init_completion(&complete);
	rq->cmd_type = REQ_TYPE_BLOCK_PC;
	rq->timeout = msecs_to_jiffies(hdr->timeout);
    rq->end_io = rnablk_passthru_req_endio;
    rq->end_io_data = &complete;
    rq->__sector = lba;
    rq->__data_len = xfer_len * RNABLK_SECTOR_SIZE;

    if (hdr->iovec_count) {
		const int size = sizeof(struct sg_iovec) * hdr->iovec_count;
		size_t iov_data_len;
		struct sg_iovec *iov;

		iov = kmalloc(size, GFP_KERNEL);
		if (!iov) {
            GOTO(out, -ENOMEM);
		}

		if (copy_from_user(iov, hdr->dxferp, size)) {
			kfree(iov);
            GOTO(out, -EFAULT);
		}

		/* SG_IO howto says that the shorter of the two wins */
		iov_data_len = iov_length((struct iovec *)iov, hdr->iovec_count);
		if (hdr->dxfer_len < iov_data_len) {
			hdr->iovec_count = iov_shorten((struct iovec *)iov,
						                   hdr->iovec_count,
						                   hdr->dxfer_len);
			iov_data_len = hdr->dxfer_len;
		}

		ret = blk_rq_map_user_iov(dev->q, rq, NULL, iov, hdr->iovec_count,
					              iov_data_len, GFP_KERNEL);
		kfree(iov);
	} else if (hdr->dxfer_len) {
		ret = blk_rq_map_user(dev->q, rq, NULL, hdr->dxferp, hdr->dxfer_len,
				              GFP_KERNEL);
    }
        
    if (0 != ret) {
        rna_printk(KERN_ERR, "mapping err: iovec_cnt=%d dxferp=%p dxfer_len=%d "
                   "ret=%d\n", hdr->iovec_count, hdr->dxferp, hdr->dxfer_len,
                   ret);
        GOTO(out, ret);
    }

    rnablk_set_req_refcount(rq, 0);

    // Request in range of device size?
    if (unlikely(((blk_rq_pos(rq) + blk_rq_sectors(rq))
                   << RNABLK_SECTOR_SHIFT) > dev->device_cap)) {
        rna_printk(KERN_ERR,
                   "[%s] sector [%"PRIu64"] beyond end of device [%"PRIu64"]\n",
                   dev->name,
                   (uint64_t)(blk_rq_pos(rq) + blk_rq_sectors(rq)),
                   (dev->device_cap >> RNABLK_SECTOR_SHIFT));
        GOTO(out, -EIO);
    }

    if (NULL != rq->bio) {
        /*
         * The functions used above to create the rq bio list do not
         * initialize 'bi_sector'.  However, rnablk_rq_map_sg() requires
         * it to be set (at least for the first bio!).  So set it here!
         */
        rq->bio->bi_sector = blk_rq_pos(rq);
    }

    // coalesce the scatter list and divide into valid sub-requests
    if (unlikely((n_ios = rnablk_rq_map_sg(dev, dev->q, rq, &ios[0])) < 0)) {
        rna_printk(KERN_ERR, "rnablk_rq_map_sg error: n_io=%d\n", n_ios);
        GOTO(out, -EIO);
    }

    // submit sub-requests
    rnablk_svcctl_register();
    for (i=0; i < n_ios; i++) {
        /*
         * Clear DEVIOCNT flag so we don't try to decrement device
         * iocnt during end_request.  rnablk_sg_io() is taking care of
         * the decrement in this case, since this operation is handled
         * synchronously.
         */
        atomic_bit_clear(&ios[i]->ios_atomic_flags, IOS_AF_DEVIOCNT);
        rnablk_process_request(ios[i]);
    }
    rnablk_svcctl_deregister();

    wait_for_completion(&complete);

 out:
    if (-EIO == ret || (NULL != rq && rq->errors)) {
        scsi_status = SAM_STAT_CHECK_CONDITION;
        memset(sense, 0, sizeof(sense));
        sense[0] = 0x70;
        sense[2] = MEDIUM_ERROR;
        sense[7] = 0;
        sense_len = 8;
        ret = 0;
    }
        
    if (NULL != rq) {
        while (NULL != (bio = rq->bio)) {
            rq->bio = bio->bi_next;
            bio_put(bio);
        }
        blk_put_request(rq);
    }

    if (0 == ret) {
        /* success... hdr & sense are available */
        hdr->resid = (SAM_STAT_GOOD == scsi_status) ? 0 : hdr->dxfer_len;
        ret = rnablk_sense_to_user(hdr, scsi_status, sense, sense_len);
    }
    return ret;
}

static int
rnablk_process_scsi_compare_and_write(struct rnablk_device *dev,
                                      rsv_itn_id_t *p_itn_id,
                                      struct sg_io_hdr *hdr,
                                      uint8_t *scsi_cmd,
                                      rsv_access_t min_access)
{
    rnablk_special_completion_t complete;
    struct io_state *ios = NULL;
    struct cache_comp_and_write_req *req;
    struct cache_comp_and_write_resp *resp;
    uint8_t sense[SCSI_MAX_SENSE_LEN];
    int sense_len = 0;
    uint8_t scsi_status = SAM_STAT_GOOD;
    boolean ios_issued = FALSE;
    uint64_t lba;
#define     cmd_num_lbas    scsi_cmd[13]
#define     cmd_lba         scsi_cmd[2]
    ENTER;

    /* do command error checking */

    if (hdr->dxfer_len != RNA_COMPARE_AND_WRITE_SIZE * 2) {
        rna_printk(KERN_DEBUG, "unsupported compare_and_write data length %d\n",
                   hdr->dxfer_len);
        GOTO(out, -EINVAL);
    }
    if (SG_DXFER_TO_DEV != hdr->dxfer_direction) {
        rna_printk(KERN_DEBUG, "unsupported compare_and_write direction: %d\n",
                   hdr->dxfer_direction);
        GOTO(out, -EINVAL);
    }

    if (scsi_cmd_len(scsi_cmd[0]) != hdr->cmd_len) {
        rna_printk(KERN_DEBUG, "incorrect COMPARE_AND_WRITE command length: "
                   "%d\n", hdr->cmd_len);
        GOTO(out, -EINVAL);
    }

    if (cmd_num_lbas != 1) {        // all we support for now!
        if (cmd_num_lbas != 0) {
            rna_printk(KERN_DEBUG, "error num_lbas=%hhd\n", cmd_num_lbas);
            scsi_status = SAM_STAT_CHECK_CONDITION;
            memset(sense, 0, sizeof(sense));
            sense[0] = 0x72;
            sense[1] = ILLEGAL_REQUEST;
            sense[2] = SCSI_ASC_INVALID_FIELD_IN_CDB;
            sense_len = SCSI_MIN_REQ_SENSE_DESC_LEN;
        }
        GOTO(out, 0);
    }

    init_completion(&complete.spc_complete);
    complete.spc_status = 0;
    atomic_set(&complete.spc_retries, 0);

    ret = rnablk_alloc_ios(dev, &complete, IOREQ_TYPE_SPC, min_access, FALSE,
                           FALSE, 1, &ios);
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
    if (rnablk_data_from_user(hdr, req->cw_verify,
                              RNA_COMPARE_AND_WRITE_SIZE * 2)) {
        rna_printk(KERN_DEBUG, "copy compare_write data from user failed\n");
        GOTO(out, -EFAULT);
    }

    lba = be64_to_cpu(*(uint64_t *)&cmd_lba);

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

    wait_for_completion(&complete.spc_complete);

    if (unlikely(0 != complete.spc_status && 0 == resp->cwr_status)) {
        resp->cwr_status = complete.spc_status;
    }
    if (0 != resp->cwr_status) {
        /* some kind of cache error; generate a SCSI error out of it */
        scsi_status = SAM_STAT_CHECK_CONDITION;
        memset(sense, 0, sizeof(sense));
        sense[0] = 0x70;
        sense[2] = MEDIUM_ERROR;
        sense[7] = 0;
        sense_len = 8;
        ret = 0;
    } else if (RNA_CW_STATUS_MISCOMPARE == resp->cwr_cmp_status) {
        scsi_status = SAM_STAT_CHECK_CONDITION;
        memset(sense, 0, sizeof(sense));
        sense[0] = 0x70 | 0x80;     // 0x80 == VALID bit
        sense[2] = MISCOMPARE;
        *(uint32_t *)(&sense[3]) = cpu_to_be16(resp->cwr_miscompare_offset);
        sense[7] = 6;
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
        /* success... hdr & sense are available */
        hdr->resid = 0;
        ret = rnablk_sense_to_user(hdr, scsi_status, sense, sense_len);
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
                            struct sg_io_hdr *hdr,
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
    int ios_in_progress = 0;
    struct io_state *ios;
    ENTER;

    init_completion(&ws_completion.spc_complete);
    ws_completion.spc_status = 0;
    atomic_set(&ws_completion.spc_retries, 0);

    sectors_per_block = dev->cache_blk_size >> RNABLK_SECTOR_SHIFT;
    nsect_in_blk = min(nsectors, sectors_per_block -
                       (uint32_t)(lba % sectors_per_block));
    
    while (nsectors) {
        /* Limit the number of ios this request can have in-flight at a time */
        if (ios_in_progress >= MAX_CONCURRENT_WRITE_SAME_IOS) {
            wait_for_completion(&ws_completion.spc_complete);
            ios_in_progress--;
            if (ws_completion.spc_status != 0) {
                GOTO(drain, 0);
            }
        }

        ret = rnablk_alloc_ios(dev, &ws_completion, IOREQ_TYPE_SPC, min_access,
                               FALSE, FALSE, 1, &ios);
        if (unlikely(0 != ret)) {
            GOTO(drain, ret);
        }
        
        /* do initialization of the cache_cmd */

        req = &ios->cmd->u.cache_write_same_req;
        resp = &ios->cmd->u.cache_write_same_req_resp_buf.wsb_resp;

        /* only WRITE_SAME (w/ or w/o UNMAP flag) can have any more data */
        if (IS_SCSI_UNMAP != unmap_type) {
            if (rnablk_data_from_user(hdr, req->ws_data, RNA_WRITE_SAME_SIZE)) {
                rna_printk(KERN_DEBUG, "copy write_same data from user failed\n");
                rnablk_ios_finish(ios);
                GOTO(drain, -EFAULT);
            }
        } else {
            /* initialize to 0 for SCSI UNMAP */
            memset(req->ws_data, 0, sizeof(req->ws_data));
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

        rnablk_svcctl_register();
        rnablk_process_request(ios);
        rnablk_svcctl_deregister();

        ios_in_progress++;
    }

 drain:
    while (ios_in_progress) {
        wait_for_completion(&ws_completion.spc_complete);
        ios_in_progress--;
    }

    if (0 != ws_completion.spc_status) {
        ret = -EIO;
    }

    return ret;
}

static int
rnablk_process_scsi_unmap(struct rnablk_device *dev,
                          rsv_itn_id_t *p_itn_id,
                          struct sg_io_hdr *hdr,
                          uint8_t *scsi_cmd,
                          rsv_access_t min_access)
{
    rnablk_unmap10_t *cmd = (rnablk_unmap10_t*)scsi_cmd;
    uint8_t sense[SCSI_MAX_SENSE_LEN];
    int sense_len = 0;
    uint8_t scsi_status = SAM_STAT_GOOD;

    uint8_t param_data[RNABLK_SECTOR_SIZE];
    rnablk_unmap10_param_list_t *param_list;
    rnablk_unmap10_blk_desc_t *blk_desc;
    int i, num_desc;

    uint16_t param_list_len;
    uint64_t lba;
    uint32_t num_lbas;
    ENTER;

    if (rnablk_scsi_unmap_disable) {
        rna_printk(KERN_DEBUG, "ignoring disabled UNMAP command\n");
        GOTO(out, -EOPNOTSUPP);
    }

    /* do command error checking */
    if (scsi_cmd_len(scsi_cmd[0]) != hdr->cmd_len) {
        rna_printk(KERN_DEBUG, "incorrect UNMAP cmd-length: %d\n",
                   hdr->cmd_len);
        GOTO(out, -EINVAL);
    }
    if (hdr->dxfer_len >= RNABLK_SECTOR_SIZE) {
        rna_printk(KERN_DEBUG, "unsupported UNMAP data-length %d\n",
                   hdr->dxfer_len);
        GOTO(out, -EINVAL);
    }
    if (SG_DXFER_TO_DEV != hdr->dxfer_direction) {
        rna_printk(KERN_DEBUG, "unsupported UNMAP direction: %d\n",
                   hdr->dxfer_direction);
        GOTO(out, -EINVAL);
    }

    switch (scsi_cmd[0]) {        
    case UNMAP:
        param_list_len = be16_to_cpu(cmd->um10_param_list_len);
        break;
    default:
        rna_printk(KERN_DEBUG, "unsupported unmap opcodce %d\n",
                   cmd->um10_opcode);
        GOTO(out, -EOPNOTSUPP);
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
        scsi_status = SAM_STAT_CHECK_CONDITION;
        memset(sense, 0, sizeof(sense));
        sense[0] = 0x72;
        sense[1] = ILLEGAL_REQUEST;
        sense[2] = SCSI_ASC_PARAMETER_LIST_LENGTH_ERROR;
        sense_len = SCSI_MIN_REQ_SENSE_DESC_LEN;
        GOTO(out, 0);
    }
    if (param_list_len < sizeof(*param_list)) {
        /* not even 1 full block-descriptor; ignore */
        GOTO(out, 0);
    }
    if (cmd->um10_flags) {
        rna_printk(KERN_DEBUG, "UNMAP ANCHOR flag not suported\n");
        scsi_status = SAM_STAT_CHECK_CONDITION;
        memset(sense, 0, sizeof(sense));
        sense[0] = 0x72;
        sense[1] = ILLEGAL_REQUEST;
        sense[2] = SCSI_ASC_INVALID_FIELD_IN_CDB;
        sense_len = SCSI_MIN_REQ_SENSE_DESC_LEN;
        GOTO(out, 0);
    }

    /* get user-data; it is an extension of the command */
    if (rnablk_data_from_user(hdr, param_data, param_list_len)) {
        rna_printk(KERN_DEBUG, "copy UNMAP data from user failed\n");
        GOTO(out, -EFAULT);
    }

    param_list = (rnablk_unmap10_param_list_t*)param_data;
    num_desc = be16_to_cpu(param_list->ump_blk_desc_len) / sizeof(*blk_desc);
    rna_printk(KERN_DEBUG, "Total blk_desc[%d]\n", num_desc);

    /* parse block-descriptors for lba & num_lbas */
    blk_desc = &param_list->ump_blk_desc[0];
    for (i = 0; i < num_desc; i++, blk_desc++) {
        lba = be64_to_cpu(blk_desc->umb_lba);
        num_lbas = be32_to_cpu(blk_desc->umb_num_lbas);
        rna_printk(KERN_DEBUG, "blk_desc[%d] %"PRId64" %d\n", i, lba, num_lbas);
        /* send CACHE_WRITE_SAME with unmap flag */
        ret = rnablk_issue_write_same_ios(dev, hdr, lba, num_lbas,
                                          IS_SCSI_UNMAP, min_access);
        if (0 != ret)
            break;
    }

    if (-EIO == ret) {
        scsi_status = SAM_STAT_CHECK_CONDITION;
        memset(sense, 0, sizeof(sense));
        sense[0] = 0x70;
        sense[2] = MEDIUM_ERROR;
        sense[7] = 0;
        sense_len = 8;
        ret = 0;        
    }

 out:
    if (0 == ret) {
        dev->stats.unmap_requests++;
        /* success... hdr & sense are available */
        hdr->resid = 0;
        ret = rnablk_sense_to_user(hdr, scsi_status, sense, sense_len);
    } else if (-EOPNOTSUPP == ret) {
        ret = rnablk_reject_scsi_command(hdr, scsi_cmd);
    }
    return ret;
}

static int
rnablk_process_scsi_write_same(struct rnablk_device *dev,
                               rsv_itn_id_t *p_itn_id,
                               struct sg_io_hdr *hdr,
                               uint8_t *scsi_cmd,
                               rsv_access_t min_access)
{
    rnablk_write_same_t *ws_cmd = (rnablk_write_same_t*)scsi_cmd;
    rnablk_write_same_16_t *ws16_cmd = (rnablk_write_same_16_t*)scsi_cmd;
    uint8_t sense[SCSI_MAX_SENSE_LEN];
    int sense_len = 0;
    uint8_t scsi_status = SAM_STAT_GOOD;
    uint8_t ws_flags;
    uint64_t lba;
    uint32_t num_lbas;
    ENTER;

    if (rnablk_scsi_write_same_disable) {
        rna_printk(KERN_DEBUG, "ignoring disabled WRITE_SAME command\n");
        GOTO(out, -EOPNOTSUPP);
    }

    /* do command error checking */
    if (scsi_cmd_len(scsi_cmd[0]) != hdr->cmd_len) {
        rna_printk(KERN_DEBUG, "incorrect WRITE_SAME command length: "
                   "%d\n", hdr->cmd_len);
        GOTO(out, -EINVAL);
    }
    if (hdr->dxfer_len != RNA_WRITE_SAME_SIZE) {
        rna_printk(KERN_DEBUG, "unsupported write_same data length %d\n",
                   hdr->dxfer_len);
        GOTO(out, -EINVAL);
    }
    if (SG_DXFER_TO_DEV != hdr->dxfer_direction) {
        rna_printk(KERN_DEBUG, "unsupported write_same direction: %d\n",
                   hdr->dxfer_direction);
        GOTO(out, -EINVAL);
    }
    switch (scsi_cmd[0]) {        
    case WRITE_SAME:
        /* Get WRITE_SAME params */
        ws_flags = ws_cmd->ws10_flags;
        lba = be32_to_cpu(ws_cmd->ws10_lba);
        num_lbas = be16_to_cpu(ws_cmd->ws10_num_lbas);
        break;
    case WRITE_SAME_16:
        /* Get WRITE_SAME_16 params */
        ws_flags = ws16_cmd->ws16_flags;
        lba = be64_to_cpu(ws16_cmd->ws16_lba);
        num_lbas = be32_to_cpu(ws16_cmd->ws16_num_lbas);
        break;
    default:
        rna_printk(KERN_DEBUG, "unsupported write_same opcodce %d\n",
                   ws_cmd->ws10_opcode);
        GOTO(out, -EOPNOTSUPP);
    }

    rna_printk(KERN_DEBUG, "Info: command=0x%0x\n", scsi_cmd[0]);
    rna_printk(KERN_DEBUG, "Info: flags=0x%0x\n", ws_flags);
    rna_printk(KERN_DEBUG, "Info: lba=%"PRId64"\n", lba);
    rna_printk(KERN_DEBUG, "Info: num_lbas=%d\n", num_lbas);

    /* TBD: Error on WS_FLAGS_OBSOLETE, PBDATA, LBDATA, and/or WRPROTECT? */

    if (ws_flags & WS_FLAGS_ANCHOR) {
        rna_printk(KERN_DEBUG, "WRITE_SAME ANCHOR flag not suported\n");
        scsi_status = SAM_STAT_CHECK_CONDITION;
        memset(sense, 0, sizeof(sense));
        sense[0] = 0x72;
        sense[1] = ILLEGAL_REQUEST;
        sense[2] = SCSI_ASC_INVALID_FIELD_IN_CDB;
        sense_len = SCSI_MIN_REQ_SENSE_DESC_LEN;
        GOTO(out, 0);
    }

    ret = rnablk_issue_write_same_ios(dev, hdr, lba, num_lbas,
                              (ws_flags & WS_FLAGS_UNMAP) ? IS_WS_UNMAP : 0,
                              min_access);

    /* TBD: WS specific failures ? */
    if (-EIO == ret) {
        scsi_status = SAM_STAT_CHECK_CONDITION;
        memset(sense, 0, sizeof(sense));
        sense[0] = 0x70;
        sense[2] = MEDIUM_ERROR;
        sense[7] = 0;
        sense_len = 8;
        ret = 0;        
    }

 out:
    if (0 == ret) {
        /* success... hdr & sense are available */
        dev->stats.write_same_requests++;
        hdr->resid = 0;
        ret = rnablk_sense_to_user(hdr, scsi_status, sense, sense_len);
    } else if (-EOPNOTSUPP == ret) {
        ret = rnablk_reject_scsi_command(hdr, scsi_cmd);
    }
    return ret;
}

static int
rnablk_process_scsi_turs(struct rnablk_device *dev,
                         rsv_itn_id_t *p_itn_id,
                         struct sg_io_hdr *hdr,
                         uint8_t *scsi_cmd,
                         rsv_access_t min_access)
{
    uint8_t sense[SCSI_MAX_SENSE_LEN];
    int sense_len = 0;
    uint8_t scsi_status = SAM_STAT_GOOD;

    /* if block-device is failed, we can't accept IO */
    if (unlikely(atomic_read(&dev->failed))) {
        scsi_status = SAM_STAT_CHECK_CONDITION;
        memset(sense, 0, sizeof(sense));
        sense[0] = 0x72;
        sense[1] = NOT_READY;
        sense[2] = 0x4; // LUN not ready
        sense[3] = 0x0; // no cause
        sense_len = SCSI_MIN_REQ_SENSE_DESC_LEN;
    }

    return rnablk_sense_to_user(hdr, scsi_status, sense, sense_len);
}

static char *
stringify_scsi_command(uint8_t *scsi_cmd, int cmd_len)
{
    static char str[128];
    int len = 0;
    int i;

    for (i = 0; i < cmd_len &&  len < sizeof(str); i++) {
        len += snprintf(str+len, sizeof(str)-len, "%hhx ", scsi_cmd[i]);
    }
    if (len < sizeof(str)) {
        snprintf(str+len, sizeof(str)-len, "(len=%d)", cmd_len);
    }
    str[sizeof(str)-1] = '\0';
    return str;
}

static int
rnablk_reject_scsi_command(struct sg_io_hdr *hdr, uint8_t *cmd)
{
    int ret, sense_len = 14;
    uint8_t sense[SCSI_MAX_SENSE_LEN];

    rna_printk(KERN_DEBUG, "Rejecting unsupported scsi command [%s]\n",
               stringify_scsi_command(cmd, hdr->cmd_len));

    memset(sense, 0, sizeof(sense));
    sense[0] = 0x70;    // fixed format w/ no information
    sense[2] = ILLEGAL_REQUEST;
    sense[7] = 6;       // Additional sense bytes
    /* 0x20/0x00: INVALID COMMAND OPCODE */
    sense[12] = 0x20;   // ASC
    sense[13] = 0x0;    // ASCQ

    ret = rnablk_sense_to_user(hdr, SAM_STAT_CHECK_CONDITION,
                               sense, sense_len);
    return ret;
}

static int
rnablk_process_scsi_not_implemented_yet(struct rnablk_device *dev,
                                        rsv_itn_id_t *p_itn_id,
                                        struct sg_io_hdr *hdr,
                                        uint8_t *scsi_cmd,
                                        rsv_access_t min_access)
{
    int ret;

    /* this is a temporary situation - push to kernel-log */
    rna_printk(KERN_WARNING, "Support for SCSI passthru of %s not implemented "
               "yet!\n", scsi_cmd_name(*scsi_cmd));

    ret = rnablk_reject_scsi_command(hdr, scsi_cmd);
    return ret;
}

static int
rnablk_process_scsi_service_action_in(struct rnablk_device *dev,
                                      rsv_itn_id_t *p_itn_id,
                                      struct sg_io_hdr *hdr,
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

        return rnablk_reject_scsi_command(hdr, scsi_cmd);
    }

    if (0 == rnablk_reservation_access_check(dev, needed_access)) {
        ret = rnablk_process_scsi_passthru(dev, p_itn_id, hdr, scsi_cmd,
                                            needed_access);
        if (RSV_ACC_NONE != needed_access) {
            rnablk_dec_device_iocnt(dev, RSV_ACC_READONLY == needed_access
                                    ? FALSE : TRUE); 
        }
    } else {
        hdr->resid = hdr->dxfer_len;
        ret = rnablk_sense_to_user(hdr, SAM_STAT_RESERVATION_CONFLICT, NULL, 0);
    }
    return ret;
}

static int
rnablk_process_scsi_maintenance_in(struct rnablk_device *dev,
                                   rsv_itn_id_t *p_itn_id,
                                   struct sg_io_hdr *hdr,
                                   uint8_t *scsi_cmd,
                                   rsv_access_t min_access)
{
    rsv_access_t needed_access;
    int cmd = scsi_cmd[1] & 0x1f;
    int ret;

    switch (cmd) {
    case MI_REPORT_TARGET_PGS:
        needed_access = RSV_ACC_NONE;
        break;

    default:
        rna_printk(KERN_DEBUG, "SCSI passthru of %s opcode %#hhx "
                   "is not supported, failing\n", scsi_cmd_name(*scsi_cmd),
                   scsi_cmd[1]);

        return rnablk_reject_scsi_command(hdr, scsi_cmd);
    }

    if (0 == rnablk_reservation_access_check(dev, needed_access)) {
        ret = rnablk_process_scsi_passthru(dev, p_itn_id, hdr, scsi_cmd,
                                            needed_access);
        if (RSV_ACC_NONE != needed_access) {
            rnablk_dec_device_iocnt(dev, RSV_ACC_READONLY == needed_access
                                    ? FALSE : TRUE); 
        }
    } else {
        hdr->resid = hdr->dxfer_len;
        ret = rnablk_sense_to_user(hdr, SAM_STAT_RESERVATION_CONFLICT, NULL, 0);
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
            rna_printk(KERN_ERR, "Error [%s] from CS ["NIPQUAD_FMT"] for "
                       "[%s] ios [%p] tag ["TAGFMT"] type [%s] block [%llu] "
                       "state [%s] ref [%s] on device [%s], failing after "
                       "%d retries\n",
                       get_cache_resp_code(status),
                       NIPQUAD(ep->dst_in.sin_addr.s_addr),
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
            rna_printk(KERN_ERR, "Error [%s] from CS ["NIPQUAD_FMT"] for "
                   "[%s] ios [%p] tag ["TAGFMT"] type [%s] block [%llu] "
                   "state [%s] ref [%s] on device [%s]\n",
                   get_cache_resp_code(status),
                   NIPQUAD(ep->dst_in.sin_addr.s_addr),
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


/* IOCTL interface for testing other special request handling. */
int rnablk_generic_special_request(struct rnablk_device *dev, unsigned int ioctl)
{
    unsigned long   flags;
    int             ret = 0;
    struct request *req;

    BUG_ON(NULL == dev);
    req = blk_get_request(dev->q, WRITE, GFP_KERNEL);
    if (NULL == req) {
        rna_printk(KERN_ERR,
                   "unable to get req for device [%s]\n",
                   dev->name);
        ret = -ENOMEM;
    } else {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
        req->flags |= REQ_SPECIAL;
#else
        req->cmd_type = REQ_TYPE_SPECIAL;
#endif
        switch(ioctl) {
#ifdef NOT_YET
        case RNABLK_IOCTL_EXTENDED_COPY:
            req->special = &rnablk_extended_copy_special_data;
            break;
        case RNABLK_IOCTL_RECEIVE_COPY_RESULTS:
            req->special = &rnablk_receive_copy_results_special_data;
            break;
#endif
        default:
            rna_printk(KERN_ERR, "IOCTL %d not handled here.\n", ioctl);
            ret = -EINVAL;
        }
        if (0 == ret) {
            ret = blk_execute_rq(dev->q, dev->disk, req, TRUE);
            rna_printk(KERN_INFO,
                       "write same for device [%s] err [%d]\n",
                       dev->name,
                       req->errors);
            ret = req->errors;
            blk_put_request(req);
        }
    }
    return ret;
}

// Handler for the scsi command.
int rnablk_send_generic_special_request(struct rnablk_device *dev,
                                        struct request       *req)
{
    rnablk_special_hdr_t *command_hdr;
    
    BUG_ON(NULL == dev);
    BUG_ON(NULL == req);
    BUG_ON(NULL == req->special);
    
    command_hdr = (rnablk_special_hdr_t *)req->special;
    // TODO:  Pass command on to cache server
    blk_complete_request(req);
    
    return 0;
}


int
rnablk_sg_reset(struct rnablk_device *dev)
{
    struct sg_io_hdr hdr;
    uint8_t scsi_release[6] = { RELEASE };
    int ret;

    memset(&hdr, 0, sizeof(hdr));
    hdr.cmd_len = sizeof(scsi_release);
    hdr.cmdp = scsi_release;
    hdr.dxfer_len = 0;
    hdr.dxfer_direction = SG_DXFER_NONE;

    /* internal command */
    ret = rnablk_process_scsi_passthru_ext(dev, 0, &hdr, hdr.cmdp,
                                           RSV_ACC_NONE, RNABLK_SG_LUN_RESET);
    if (0 == ret)
        ret = hdr.status;

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
    complete(&cmpl->spc_complete);
}

static void
rnablk_ua_code_to_asc(int ua_code, uint16_t *ascval)
{
    switch (ua_code) {

    case UA_REGISTRATIONS_PREEMPTED:
        /* REGISTRATIONS PREEMPTED */
        *ascval = (0x2a << 8) | 0x5;
        break;

    case UA_RESERVATIONS_PREEMPTED:
        /* RESERVATIONS PREEMPTED */
        *ascval = (0x2a << 8) | 0x3;
        break;

    case UA_RESERVATIONS_RELEASED:
        /* RESERVATIONS RELEASED */
        *ascval = (0x2a << 8) | 0x4;
        break;

    case UA_LOW_SPACE:
        /* THIN PROVISIONING SOFT THRESHOLD REACHED */
        *ascval = (0x38 << 8) | 0x7;
        break;

    default:
        rna_printk(KERN_WARNING, "unknown UNIT ATTENTION code [%d]\n", ua_code);
        *ascval = 0;
        break;
    }
    return;
}

/*
 * rnablk_retrieve_unitattn()
 *  Must be called with dev rbd_event_lock held
 *
 * Return value:
 *  The return value is the UNITATTN code of the retrieved unitattn,
 *  or 0 if there aren't any to retrieve.  If a valid UNITATTN is returned,
 *  then the rsv_itn_id_t that it should be "sent" to is returned in 'p_ini'.
 *  (A returned itn of zero's indicates the UNITATTN should be sent to
 *  everybody).
 */
int
rnablk_retrieve_unitattn(struct rnablk_device *dev, rsv_initiator_t *p_ini)
{
    struct rnablk_unitattn_state_s *duap = &dev->rbd_ua_state;
    int ua_code = 0;
    int i;

    if (duap->rus_n_pending) {
        if (duap->rus_all_unitattn) {
            ua_code = ffs(duap->rus_all_unitattn) - 1;
            duap->rus_all_unitattn &= ~(1 << ua_code);
            rsv_copy_initiator(p_ini, &NULL_RSV_INITIATOR);
        } else {
            for (i = 0; i < duap->rus_n_itns; i++) {
                if (0 != duap->rus_ini_unitattn[i]) {
                    ua_code = ffs(duap->rus_ini_unitattn[i]) - 1;
                    duap->rus_ini_unitattn[i] &= ~(1 << ua_code);
                    rsv_copy_initiator(p_ini, &duap->rus_ini_list[i]);
                    break;
                }
            }
        }
        RNABLK_BUG_ON(0 == ua_code, "UNITATTN state out-of-sync for "
                      "dev [%s] dev=%p\n", dev->name, dev);
        duap->rus_n_pending--;
    }
    return ua_code;
}

/*
 * rnablk_wait_for_scsi_event()
 *  Waits for a UNIT ATTENTION condition or for a changed state for
 *  device-access state (i.e. due to SCSI reservation) or thin-provisioning
 *  state.  This routine will also return if interrupted or if the device
 *  gets shutdown.
 *  If a UNIT ATTENTION condition is found, this routine clears the
 *  condition before returning.
 *
 * Returns 0 on success or a negative errno on failure.
 */
int
rnablk_wait_for_scsi_event(struct rnablk_device *dev,
                           struct rnablk_ioc_scsi_event *evp)
{
    DEFINE_WAIT(wait);
    unsigned long irqflags;
    int i, ret = 0;
    int ua_code = 0;

    rna_printk(KERN_NOTICE, "waiting for event on device [%s] (gen=%u "
               "oos=%hhu)\n", dev->name, evp->rise_access_gen,
               evp->rise_outofspace);
    rna_spin_lock_irqsave(dev->rbd_event_lock, irqflags);

    while (!dev->rbd_ua_state.rus_n_pending
           && evp->rise_access_gen == dev->rbd_rsv.rrs_generation
           && evp->rise_outofspace ==
              rbd_event_is_set(dev, RBD_EV_OUTOFSPACE)) {
        prepare_to_wait(&dev->rbd_event_wait, &wait, TASK_INTERRUPTIBLE);
        if (unlikely(rnablk_dev_is_shutdown(dev))
                     || 0 != atomic_read(&dev->failed)) {
            ret = -ENODEV;
            break;
        }
        rna_spin_unlock_irqrestore(dev->rbd_event_lock, irqflags);
        if (signal_pending(current)) {
            rna_spin_lock_irqsave(dev->rbd_event_lock, irqflags);
            ret = -EINTR;
            break;
        }
        schedule();
        rna_spin_lock_irqsave(dev->rbd_event_lock, irqflags);
    }
    finish_wait(&dev->rbd_event_wait, &wait);

    if (0 == ret) {
        /* unit-attention */
        if (dev->rbd_ua_state.rus_n_pending) {
            ua_code = rnablk_retrieve_unitattn(dev, &evp->rise_ua_ini);
            rnablk_ua_code_to_asc(ua_code, &evp->rise_ua_asc);
        } else {
            evp->rise_ua_asc = 0;
        }
        /* reservation-access */
        if (evp->rise_access_gen != dev->rbd_rsv.rrs_generation) {
            evp->rise_acl.rra_n_itns = dev->rbd_rsv.rrs_n_itns;
            evp->rise_acl.rra_other_access = dev->rbd_rsv.rrs_other_access;
            for (i = 0; i < evp->rise_acl.rra_n_itns; i++) {
                rsv_copy_initiator(&evp->rise_acl.rra_ini_list[i],
                                   &rsv_itn_initiator(&dev->rbd_rsv.rrs_itn_list[i]));
            }
            evp->rise_access_gen = dev->rbd_rsv.rrs_generation;
        }
        /* out-of-space state */
        evp->rise_outofspace = rbd_event_is_set(dev, RBD_EV_OUTOFSPACE);
    }

    rna_spin_unlock_irqrestore(dev->rbd_event_lock, irqflags);
    rna_printk(KERN_NOTICE, "event wakeup on device [%s] ret=%d "
               "(ua=%d gen=%u oos=%hhu)\n", dev->name, ret, ua_code != 0,
               evp->rise_access_gen, evp->rise_outofspace);

    return ret;
}

void
rnablk_device_process_thinprov_state(struct rnablk_device *dev,
                                     int thinprov_state)
{
    boolean do_wakeup = FALSE;
    unsigned long irqflags;

    rna_spin_lock_irqsave(dev->rbd_event_lock, irqflags);

    switch (thinprov_state) {
    case RNA_VOL_LOWSPACE:
        dev->rbd_ua_state.rus_all_unitattn = (1 << UA_LOW_SPACE);
        dev->rbd_ua_state.rus_n_pending++;
        do_wakeup = TRUE;

        /* fallthrough */

    case RNA_VOL_NORMAL:
        if (rbd_event_is_set(dev, RBD_EV_OUTOFSPACE)) {
            rbd_event_clear(dev, RBD_EV_OUTOFSPACE);
            do_wakeup = TRUE;
        }
        break;

    case RNA_VOL_OUTOFSPACE:
        if (!rbd_event_is_set(dev, RBD_EV_OUTOFSPACE)) {
            rbd_event_set(dev, RBD_EV_OUTOFSPACE);
            do_wakeup = TRUE;
        }
        break; 

    default:
        rna_printk(KERN_ERR, "Unexpected thin provision state value [%d] for "
                   "device [%s]\n", thinprov_state, dev->name);
        break;
    }
    if (do_wakeup) {
        wake_up_all(&dev->rbd_event_wait);
    }
    rna_spin_unlock_irqrestore(dev->rbd_event_lock, irqflags);
}
