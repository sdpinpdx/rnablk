//******************************************************************************
//*      Copyright (c) 1988-2013 Dell Inc.                                     *
//*      This program contains proprietary and confidential information.       *
//*      All rights reserved.                                                  *
//******************************************************************************

#ifndef _CMD_QUEUE_H_
#define _CMD_QUEUE_H_

#include "platform.h"
#include "util.h"
#include "rna_dskattrs_common.h"
#include "journal_defs.h"

#define CMD_QUEUE_THREADS 1     // command work queue must have only one thread
#define CMD_QUEUE_SIZE    128
#define CMD_QUEUE_THREAD_PRIORITY RNA_UTIL_THREAD_PRIORITY_MID
#define CMD_QUEUE_THREAD_CANCEL_FLAG JOIN_WORKQ_THREADS

// Command Queue Object Types
typedef enum {
    CMD_QUEUE_OBJ_NONE          = 0,
    CMD_QUEUE_OBJ_CACHE_DEVICE,
    CMD_QUEUE_OBJ_STORAGE_PATH,
    CMD_QUEUE_OBJ_BLOCK_DEVICE,
    CMD_QUEUE_OBJ_CACHE_SERVER,
    CMD_QUEUE_OBJ_HCN,
    CMD_QUEUE_OBJ_HCC_MNTNC_START,
    CMD_QUEUE_OBJ_HCC_MNTNC_CANCEL,
    CMD_QUEUE_OBJ_HCC,
    CMD_QUEUE_OBJ_INVALID
} cq_obj_t;

// Command Queue Operations Type
typedef enum {
    CMD_QUEUE_OP_NONE           = 0,
    CMD_QUEUE_OP_ADD            = 1,
    CMD_QUEUE_OP_REMOVE         = 2,
    CMD_QUEUE_OP_REACTVATE      = 4,
    CMD_QUEUE_OP_ATTACH         = 8,
    CMD_QUEUE_OP_DETACH         = 16,
    CMD_QUEUE_OP_MAP            = 32,
    CMD_QUEUE_OP_UNMAP          = 64,
    CMD_QUEUE_OP_PREPARE        = 128,
    CMD_QUEUE_OP_SHUTDOWN       = 256,
    CMD_QUEUE_OP_INVALID        = 512
} cq_op_t;

// Command Queue Options
typedef enum {
    CMD_QUEUE_OPT_NONE          = 0,
    CMD_QUEUE_OPT_FORCE_REMOVE  = 1,
    CMD_QUEUE_OPT_AUTO_REMOVE   = 2,
    CMD_QUEUE_OPT_REACTIVATE    = 4,
    CMD_QUEUE_OPT_DISCARD_DIRTY = 8,
    CMD_QUEUE_OPT_ALL_PATHS     = 16,
    CMD_QUEUE_OPT_EVENT         = 32,
    CMD_QUEUE_OPT_INVALID       = 64
} cq_opt_t;

typedef struct cq_cd_data_s {
    char                cdd_id[J_MAX_WWN_STR_LEN];
    char                cdd_host[J_MAX_HOST_LEN];
    cq_opt_t            cdd_opts;
} cq_cd_data_t;

typedef struct cq_sp_data_s {
    struct j_scsi_info  spd_alias_scsi;
    char                spd_host[J_MAX_HOST_LEN];
    cq_opt_t            spd_opts;
} cq_sp_data_t;

typedef struct cq_bd_data_s {
    char                bdd_name[J_MAX_HOST_LEN];
    char                bdd_host[J_MAX_HOST_LEN];
    cq_opt_t            bdd_opts;
} cq_bd_data_t;

typedef struct cq_cs_data_s {
    char                csd_name[J_MAX_HOST_LEN];
    cq_opt_t            csd_opts;
} cq_cs_data_t;

typedef struct cq_hcn_data_s {
    char                hcnd_id[J_MAX_NAME_LEN];
    char                hcnd_host[J_MAX_HOST_LEN];
    char                hcnd_addr[16];
    uint16_t            hcnd_port;
    cq_opt_t            hcnd_opts;
} cq_hcn_data_t;

typedef struct cq_mntnc_data_s {
    uint64_t            timeout;
    cq_opt_t            mntnc_opts;
} cq_mntnc_data_t;

typedef struct cq_hcc_data_s {
    cq_opt_t            hccd_opts;
} cq_hcc_data_t;

typedef struct cmd_queue_data_s {
    cq_obj_t        cq_obj;
    cq_op_t         cq_op;
    uint64_t        cq_sequence;
    uint32_t        cq_journal_block;
    uint32_t        cq_cb_id;
    char            cq_token[J_MAX_NAME_LEN];
    union {
        cq_cd_data_t    cdd;
        cq_sp_data_t    spd;
        cq_bd_data_t    bdd;
        cq_cs_data_t    csd;
        cq_hcn_data_t   hcnd;
        cq_mntnc_data_t mntncd;
        cq_hcc_data_t   hccd;
        uint8_t         pad[(JOURNAL_SINGLE_SECTOR_SIZE_BYTES * 2) -
                            sizeof(cq_obj_t) -
                            sizeof(cq_op_t) -
                            sizeof(uint64_t) -
                            sizeof(uint64_t) -
                            J_MAX_NAME_LEN];
    } u;
} cmd_queue_data_t;

#if defined(LINUX_USER) || defined(WINDOWS_USER)
int cmd_queue_create(struct rna_work_queue **wq);
void cmd_queue_destroy(struct rna_work_queue *wq);
int cmd_queue_add(struct rna_work_queue *wq, rna_work_cb cq_cb, cmd_queue_data_t *cq_d);

INLINE char *
cmd_queue_obj_str(cq_obj_t ob)
{
    char *p = "UNKNOWN";

    switch(ob) {
    case CMD_QUEUE_OBJ_NONE:
        p = "CMD_QUEUE_OBJ_NONE";
        break;
    case CMD_QUEUE_OBJ_CACHE_DEVICE:
        p = "CMD_QUEUE_OBJ_CACHE_DEVICE";
        break;
    case CMD_QUEUE_OBJ_STORAGE_PATH:
        p = "CMD_QUEUE_OBJ_STORAGE_PATH";
        break;
    case CMD_QUEUE_OBJ_BLOCK_DEVICE:
        p = "CMD_QUEUE_OBJ_BLOCK_DEVICE";
        break;
    case CMD_QUEUE_OBJ_CACHE_SERVER:
        p = "CMD_QUEUE_OBJ_CACHE_SERVER";
        break;
    case CMD_QUEUE_OBJ_HCN:
        p = "CMD_QUEUE_OBJ_HCN";
        break;
    case CMD_QUEUE_OBJ_HCC_MNTNC_START:
        p = "CMD_QUEUE_OBJ_MAINTENANCE_MODE_PREPARE";
        break;
        case CMD_QUEUE_OBJ_HCC_MNTNC_CANCEL:
        p = "CMD_QUEUE_OBJ_MAINTENANCE_MODE_CANCEL";
        break;
    case CMD_QUEUE_OBJ_HCC:
        p = "CMD_QUEUE_OBJ_HCC";
        break;
    case CMD_QUEUE_OBJ_INVALID:
        p = "CMD_QUEUE_OBJ_INVALID";
        break;
    }

    return p;
}

INLINE char *
cmd_queue_op_str(cq_op_t op)
{
    char *p = "UNKNOWN";

    switch(op) {
    case CMD_QUEUE_OP_NONE:
        p = "CMD_QUEUE_OP_NONE";
        break;
    case CMD_QUEUE_OP_ADD:
        p = "CMD_QUEUE_OP_ADD";
        break;
    case CMD_QUEUE_OP_REMOVE:
        p = "CMD_QUEUE_OP_REMOVE";
        break;
    case CMD_QUEUE_OP_REACTVATE:
        p = "CMD_QUEUE_OP_REACTVATE";
        break;
    case CMD_QUEUE_OP_ATTACH:
        p = "CMD_QUEUE_OP_ATTACH";
        break;
    case CMD_QUEUE_OP_DETACH:
        p = "CMD_QUEUE_OP_DETACH";
        break;
    case CMD_QUEUE_OP_MAP:
        p = "CMD_QUEUE_OP_MAP";
        break;
    case CMD_QUEUE_OP_UNMAP:
        p = "CMD_QUEUE_OP_UNMAP";
        break;
    case CMD_QUEUE_OP_PREPARE:
        p = "CMD_QUEUE_OP_PREPARE";
        break;
    case CMD_QUEUE_OP_SHUTDOWN:
        p = "CMD_QUEUE_OP_SHUTDOWN";
        break;
    case CMD_QUEUE_OP_INVALID:
        p = "CMD_QUEUE_OP_INVALID";
        break;
    }

    return p;
}

INLINE char *
cmd_queue_opt_str(cq_opt_t opt)
{
    char *p = "UNKNOWN";

    switch(opt) {
    case CMD_QUEUE_OPT_NONE:
        p = "CMD_QUEUE_OPT_NONE";
        break;
    case CMD_QUEUE_OPT_FORCE_REMOVE:
        p = "CMD_QUEUE_OPT_FORCE_REMOVE";
        break;
    case CMD_QUEUE_OPT_AUTO_REMOVE:
        p = "CMD_QUEUE_OPT_AUTO_REMOVE";
        break;
    case CMD_QUEUE_OPT_REACTIVATE:
        p = "CMD_QUEUE_OPT_REACTIVATE";
        break;
    case CMD_QUEUE_OPT_DISCARD_DIRTY:
        p = "CMD_QUEUE_OPT_DISCARD_DIRTY";
        break;
    case CMD_QUEUE_OPT_ALL_PATHS:
        p = "CMD_QUEUE_OPT_ALL_PATHS";
        break;
    case CMD_QUEUE_OPT_EVENT:
        p = "CMD_QUEUE_OPT_EVENT";
        break;
    case CMD_QUEUE_OPT_INVALID:
        p = "CMD_QUEUE_OPT_INVALID";
        break;
    }

    return p;
}

#endif

#endif // _CMD_QUEUE_H_

