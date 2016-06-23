/**
 * <rnablk_comatose.h> - Dell Fluid Cache block driver
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
#ifdef WINDOWS_KERNEL
#include "rnablk_win_device.h"
#include "rnablk_win_util.h"
#endif

void rnablk_stop_devs (void);

void rnablk_start_devs(struct rnablk_server_conn *conn, boolean do_all_devs);

void rnablk_clear_dev_queue_stop_flag(struct rnablk_device *dev,
                                      enum rnablk_queue_stop_flags stop_flag);

void rnablk_end_req(struct io_state *ios, int error);

void rnablk_enable_enforcer(void);

#ifdef blk_special_request
#define RNA_SPECIAL_REQ(x) blk_special_request(x)
#else
#ifdef PLATFORM_WINDOWS
#define RNA_SPECIAL_REQ(x) ((x)->cmd_type == REQ_TYPE_SPECIAL)
#else
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
#define RNA_SPECIAL_REQ(x) (RNA_REQ_FLAGS(x) & REQ_SPECIAL)
#else
#define RNA_SPECIAL_REQ(x) ((x)->cmd_type == REQ_TYPE_SPECIAL)
#endif
#endif //PLATFORM_WINDOWS
#endif

#ifdef PLATFORM_WINDOWS
#define RNA_REQ_FLAGS(x) (x)->cmd_flags
#else
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
#define RNA_REQ_FLAGS(x) (x)->flags
#else
#define RNA_REQ_FLAGS(x) (x)->cmd_flags
#endif
#endif //PLATFORM_WINDOWS

typedef enum {
    RNABLK_RESERVE_SPECIAL = 1,
    RNABLK_RELEASE_SPECIAL,
    RNABLK_EXTENDED_COPY_SPECIAL,
    RNABLK_RECEIVE_COPY_RESULTS_SPECIAL,
} rnablk_special_req_t;

typedef struct rnablk_special_hdr_s {
    rnablk_special_req_t        sh_type;
    atomic_t                    sh_refcount;
} rnablk_special_hdr_t;

typedef struct rnablk_special_write_same_command_s {
    rnablk_special_hdr_t        sws_hdr;
    uint64_t                    sws_start_lba;
    uint32_t                    sws_num_blocks;
    uint8_t                     sws_unmap;
    char                        sws_contents[RNABLK_SECTOR_SIZE]; // What to write
} rnablk_special_write_same_command_t;

typedef struct rnablk_special_compare_and_write_command_s {
    rnablk_special_hdr_t                scw_hdr;
    uint64_t                            scw_lba;
    uint16_t                            scw_result_miscompare_offset;
    uint8_t                             scw_result_miscompare;
    /* What should be there now */
    char                                scw_verify[RNABLK_SECTOR_SIZE]; 
    /* What we want to be there */
    char                                scw_write[RNABLK_SECTOR_SIZE];  
} rnablk_special_compare_and_write_command_t;


/* ==========================================================================
 *   Not used in Windows
 * ==========================================================================
 */
#ifndef WINDOWS_KERNEL
void rnablk_dec_req_refcount(struct request *req);
void rnablk_inc_req_refcount(struct request *req);
void rnablk_set_req_refcount(struct request *req, int value);
void rnablk_strategy(struct request_queue *q);
void rnablk_softirq_done(struct request *req);
int rnablk_prep_fn(struct request_queue *q, struct request *req);

INLINE int
rnablk_remaining_stack(void)
{
    char dummy;
    char *stack_end_ptr;

    stack_end_ptr = (char *)(current_thread_info()) + sizeof(struct thread_info);
    return &dummy - stack_end_ptr;
}

INLINE const char * rnablk_special_req_string(struct request *req)
{
    const char * ret = "Unknown";
    rnablk_special_req_t type = ((rnablk_special_hdr_t *)req->special)->sh_type;

    switch (type) {
    case RNABLK_RESERVE_SPECIAL: ret = "RNABLK_RESERVE_SPECIAL"; break;
    case RNABLK_RELEASE_SPECIAL: ret = "RNABLK_RELEASE_SPECIAL"; break;
    case RNABLK_EXTENDED_COPY_SPECIAL: ret = "RNABLK_EXTENDED_COPY_SPECIAL"; break;
    case RNABLK_RECEIVE_COPY_RESULTS_SPECIAL: ret = "RNABLK_RECEIVE_COPY_RESULTS_SPECIAL"; break;
    }
    return ret;
}
#endif /*WINDOWS_KERNEL*/

/*
 * Ordered command handling
 *
 * Most of the things we used to apply ordering to here will be detected and handled
 * for all clients in the CS.
 */
INLINE boolean
rnablk_command_is_ordered(struct io_state *ios)
{
#ifdef WINDOWS_KERNEL
	UNREFERENCED_PARAMETER(ios);
	return 0;
#else
    return ((NULL != ios) && IOS_HAS_REQ(ios) && 
            RNA_SPECIAL_REQ(ios->req) && ios->req->special &&
            ((RNABLK_RESERVE_SPECIAL == 
              ((rnablk_special_hdr_t *)ios->req->special)->sh_type)));
#endif /*WINDOWS_KERNEL*/
}

