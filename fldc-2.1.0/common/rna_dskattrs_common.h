/**
 * <rna_dskattrs_common.h> - Dell Fluid Cache block driver
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

#pragma once

#include "platform.h"

//#ifndef __KERNEL__
#if defined(LINUX_USER) || defined(WINDOWS_USER)
#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include "util.h"
#endif


#define MAX_WWN_STR_LEN (50)
#define MAX_IN_USE_STR_LEN (256)
#define MAX_CACHEDEV_MODEL_LEN  (64)

/* Definitions for storage wwn structures */

/* WWN Code Set value indicates the type of the data represented
 * found in fields of (e.g.) the wwn designator fields of page 0x83.
 * These can be found in Table 23 "Code set enumeration" of the
 * spc4r17 (T10/1731-D Revision 17)
 *
 * At this time rna code accepts only BINARY_CODE_SET
 */

typedef enum wwn_code_set_e {
    ANY_CODE_SET = -1,
    RESERVED_CODE_SET = 0,
    BINARY_CODE_SET = 1,
    ASCII_CODE_SET = 2,
    UTF_8_CODE_SET = 3,
} wwn_code_set_t;

/* Of the designator types listed below, we have experience only
 * with the NAA_id type. NAA_id identifier type has sub-types 2, 3, 5, and 6.
 * Types 2, 3, and 5 wwns are 8-bytes in length. Type 6 wwn is 16-bytes in
 * length.  * NAA ids all use binary_code_set type values.
 *
 * WWNs for ATA devices are always NAA sub-type 5.
 *
 * It seems possible we could also encounter the EUI_64_based_id.
 * These can be in 8, 12, or 16 byte wwid values and also use binary_code_set
 * encoding.
 *
 * We have no experience with the other designator type or code set types.
 *
 * Particuarly the SCSI_name_string_id can be up to 256 bytes in length.
 * There is no room in the structures we are using in our metadata for this
 * type of identifier.
 *
 * At this time rna code accepts only NAA_ID_TYPE
 * and also MD5_LOGICAL_LUN_ID_TYPE due to broken nvme devices.
 *
 * Ascii form of MD5_LOGICAL_LUN_ID_TYPE will have a prefix string
 * "MD5."
 *
 * ATA WWN
 */
typedef enum wwn_designator_type_e {
    ANY_ID_TYPE                     = -1,
    VENDOR_SPECIFIC_ID_TYPE         = 0,
    T10_VENDOR_ID_TYPE              = 1,
    EUI_64_BASED_ID_TYPE            = 2,
    NAA_ID_TYPE                     = 3,
    REL_TARGET_PORT_ID_TYPE         = 4,
    TARGET_PORT_GROUP_ID_TYPE       = 5,
    LUN_UNIT_GROUP_ID_TYPE          = 6,
    MD5_LOGICAL_LUN_ID_TYPE         = 7,
    SCSI_NAME_STRING_ID_TYPE        = 8,
} wwn_designator_type_t;

#define MD5_ASCII_WWN_PREFIX    "MD5."

/* This is the rna presentation of an wwn for a storage device.
 * These structures are stored in the metadata on the flash devices,
 * and they are used in by the CLI and chache daemons to uniquely
 * identify devices.
 *
 * This is sized to fit in three 64-bit words.
 *
 * As seen from the notes above, designator (or wwn) types come
 * in several varieties and sizes.
 *
 * We expect that the rna product will actually encounter only two or three
 * variants, most likely all NAA types.
 *
 * The wwn_id field is space for the unique identifier part of the wwn.
 * In the case of wwns that are shorter than 16 bytes, the data bytes of the
 * wwn occupy the low bytes of this array. The unused bytes in this array
 * will be zero.
 *
 * The actual length of the wwn stored in rwwn_id[] is stored in
 * rwwn_id_len.
 *
 * The rwwn_id_type specifies in more detail the format of the wwn, and
 * also the agency that guarantees the wwn's uniqueness.  See table
 * 459 in the spc4r17 document, T10/1731-D Revision 17
 *
 * The rwwn_cset indicates the character set type that is used in the
 * rwwn_id[].
 *
 */
typedef struct rna_store_wwn {
    uint8_t rwwn_id[16];
    uint8_t rwwn_pad[4];
    uint8_t rwwn_id_len;
    uint8_t rwwn_id_partition;
    uint8_t rwwn_id_type;
    uint8_t rwwn_id_code_set;
} rna_store_wwn_t;

#ifndef __KERNEL__
/* Produce human readable strings from the content of a wwn structure.
 *
 * Returns 0 on success, otherwise a negative error code.
 *
 * If an invalid wwn is passed in,
 *      return value will be -EINVAL
 *      err_str_p will point to an informative error string.
 *
 * If a memory allocation failure has occurred,
 *      return value will be -ENOMEM
 *      err_str_p will be NULL.
 *
 * ALL strings and structures returned by this function are the responsibility
 * of the caller to free().
 */
int
rna_create_wwn_strings(const rna_store_wwn_t *rna_wwn,
                       char **id_str_p,
                       char **id_type_str_p,
                       char **id_code_set_str_p,
                       char **err_str_p);

/*
 * allocate and initialize a rna_store_wwn_t structure, and strings
 * useful for displaying the wwn.
 *
 * If a failure occurs internal, return a -errno, and err_str_p will
 * point to an error string.  Note, error strings are STATICALLY allocated.
 * so callers of this routine must NEVER free() them.
 *
 * however, other objects malloc()'d here and returned to the caller are
 * the caller's responsibility to free().
 *
 * Hopefully, the caller gets ALL objects returned to it on success, or
 * it gets NONE on failures.
 *
 * Returns 0 on success.
 * returns negative errno on failure.
 */
int
rna_create_real_wwn(const uint8_t *id,
                    int id_len,
                    int id_partition,
                    int id_type,
                    int id_code_set,
                    rna_store_wwn_t **rna_wwn_p,
                    char **id_str_p,
                    char **id_type_str_p,
                    char **id_code_set_str_p,
                    char **err_str_p);


/* Create a wwn from a hexadecimal ascii identity string.
 *
 * The string may have a hexadecimal partition number, for example:
 *
 *      6782BCB04CA44E0016701BCA06121549_02
 *
 * We'll define the maximum wwn string  length to be 40 bytes, really
 * only 35 bytes is needed.
 *
 * If there is no partition number extension, then it is assumed the
 * partition number is 0.
 *
 * This string must be terminated with a 0 character.
 *
 * hexadecimal digits can be lower or upper case.
 *
 * For now, we assume all wwns are of type NAA_id.
 * The string must be of the correct lenth, and have the proper subtype
 * numbers to fit into the recognized NAA_id requirements.
 *
 */
int
rna_create_real_wwn_from_string(char *id_str,
                                rna_store_wwn_t **rna_wwn_p,
                                char **err_str_p);

/*
 * Compare two wwn structures.
 * Return 1 if they are equal.  0 if not.
 */
INLINE int
rna_wwn_is_equal(rna_store_wwn_t *w1, rna_store_wwn_t *w2)
{
    return memcmp(w1, w2, sizeof(rna_store_wwn_t)) == 0;
}

/*
 * Strips white spaces from begining and at the end of argument string.
 * The modified string is returned.
 * Caller must free the modified string.
 */
char *
strip_spaces(char *str);
#endif
