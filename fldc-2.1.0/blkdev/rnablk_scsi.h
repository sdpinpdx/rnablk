/*
 * <rnablk_scsi.h> - Dell Fluid Cache block driver
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
#pragma once
#include "rb.h"

#ifdef WINDOWS_KERNEL
#include <storport.h>
#else
#include <scsi/scsi.h>
#include "scsi/sg.h"
#endif  // WINDOWS_KERNEL

/* ===========================================================
 * Common between Linux and Windows.
 * ===========================================================
 */
void 
rnablk_end_special(struct io_state *ios, 
                   int error);

boolean 
process_common_special_response(struct com_ep *ep, 
                                struct io_state *ios,
                                cache_resp_code status);

int 
rnablk_sg_reset(struct rnablk_device *dev);

void 
rnablk_device_process_thinprov_state(struct rnablk_device *dev,
                                     int thinprov_state);

/* ===========================================================
 * Linux Specific or Linux Only.
 * ===========================================================
 */
#ifndef WINDOWS_KERNEL

int 
rnablk_generic_special_request(struct rnablk_device *dev,
                               unsigned int ioctl);

int 
rnablk_send_generic_special_request(struct rnablk_device *dev,
                                    struct request *req);

/* TODO--once we figure out additional parameters, we'll need to pass those on. */
#define rnablk_send_extended_copy_request(DEV, REQ) \
    rnablk_send_generic_special_request(DEV, REQ)

#define rnablk_send_receive_copy_results_request(DEV, REQ)  \
    rnablk_send_generic_special_request(DEV, REQ)

int 
rnablk_sg_io(struct rnablk_device *dev, 
             rsv_itn_id_t *p_itn_id,
             struct sg_io_hdr *hdr, 
             fmode_t mode);

int 
rnablk_wait_for_scsi_event(struct rnablk_device *dev,
                           struct rnablk_ioc_scsi_event *evp);


#endif /*WINDOWS_KERNEL*/


/* ===========================================================
 *  Windows Specific or Windows Only.
 * ===========================================================
 */

#ifdef WINDOWS_KERNEL
#define MP_TAG_SCSI              'csCF'

int 
rnablk_build_win_scsi_table(void);

void 
rnablk_cleanup_win_scsi_table(void);

int 
rnablk_sg_io(struct rnablk_device *dev, 
             rsv_itn_id_t *p_itn_id,
             PSCSI_REQUEST_BLOCK pSrb);

UCHAR
ResetHBADevices(
    __in const UCHAR PathId,
    __in const UCHAR TargetId
    );

void 
rnablk_io_scsi_sense(struct rnablk_device *dev, PSCSI_REQUEST_BLOCK pSrb, int err);

#endif
