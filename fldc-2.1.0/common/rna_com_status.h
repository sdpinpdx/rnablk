/**
 * <rna_com_status.h> - Dell Fluid Cache block driver
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

/**
 * @file
 *
 * @section DESCRIPTION
 * Status values shared between userland and kernel
 */

#pragma once

#include "platform.h"


/* callback response status codes (must all be negative) */
enum rna_com_cb_resp_status {
    CB_RESP_INVALID_RKEY = -9,
    CB_RESP_OFFLINE = -8,
    CB_RESP_BOTTOM_FAIL = -7,
    CB_RESP_TOP_FAIL = -6,
    CB_RESP_STORAGE_FAIL = -5,
    CB_RESP_CACHE_FAIL = -4,
    CB_RESP_INVALID = -3,
    CB_RESP_EAGAIN = -2,
    CB_RESP_FAIL = -1,
    CB_RESP_SUCCESS = 0
};

/**< Returns nonzero if the rna_com_cb_resp_status indicates a failure */
INLINE int rna_com_cb_resp_status_is_failure(enum rna_com_cb_resp_status status) 
{
    return (status < 0);
}

INLINE const char * get_rna_com_cb_resp_status_string (enum rna_com_cb_resp_status status)
{
    const char * ret = "Unknown";

    /* Lump all non-failures into the success code */
    if (!rna_com_cb_resp_status_is_failure(status)) {
        status = CB_RESP_SUCCESS;
    }
	switch(status){
    case CB_RESP_INVALID:
        ret = "CB_RESP_INVALID";
        break;
    case CB_RESP_OFFLINE:
        ret = "CB_RESP_OFFLINE";
        break;
    case CB_RESP_EAGAIN:
        ret = "CB_RESP_EAGAIN";
        break;
    case CB_RESP_FAIL:
        ret = "CB_RESP_FAIL";
        break;
    case CB_RESP_SUCCESS:
        ret = "CB_RESP_SUCCESS";
        break;
    case CB_RESP_STORAGE_FAIL:
        ret = "CB_RESP_STORAGE_FAIL";
        break;
    case CB_RESP_CACHE_FAIL:
        ret = "CB_RESP_CACHE_FAIL";
        break;
    case CB_RESP_TOP_FAIL:
        ret = "CB_RESP_TOP_FAIL";
        break;
    case CB_RESP_BOTTOM_FAIL:
        ret = "CB_RESP_BOTTOM_FAIL";
        break;
    case CB_RESP_INVALID_RKEY:
        ret = "CB_RESP_INVALID_RKEY";
        break;
	}
	return ret;
}
