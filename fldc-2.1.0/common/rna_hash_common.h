/**
 * <rna_hash_common.h> - Dell Fluid Cache block driver
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

CODE_IDENT("$URL: https://svn.rnanetworks.com/full/tags/HERMES_2_1_0_RC1/common/rna_hash_common.h $ $Id: rna_hash_common.h 22394 2013-06-21 23:44:34Z pkrueger $")

#include "md5.h"

/*
 * NOTE that if this value is changed to a value that's not a multiple of 8,
 * the declaration of the keycmp field in an rna_hash_key_t may need to change,
 * and rna_rbhash_cmp_key and rna_rbhash_compute_index will need to change.
 */
#define RNA_HASH_KEY_SIZE 16

/*
 * A 64-bit RID.
 *
 * A RID is a unique ID for a hash table entry, composed of the following
 * bitfields:
 *      First 40 bits:  The index of the node in the slab it resides in
 *      Next 8 bits:    The index of the slab containing the entry
 *      Next 8 bits:    The hash partition that the entry belongs to
 *      Next 8 bits     A generation number used to verify that the entry
 *                      hasn't been re-allocated for another use since the
 *                      RID was created
 */
#define RID_NODE_INDEX_STARTBIT     0
#define RID_NODE_INDEX_NUMBITS      40
#define RID_NODE_INDEX_BITMASK      ((0x1LL << RID_NODE_INDEX_NUMBITS) - 1)
#define RID_SLAB_INDEX_STARTBIT     40
#define RID_SLAB_INDEX_NUMBITS      8
#define RID_SLAB_INDEX_BITMASK      ((0x1LL << RID_SLAB_INDEX_NUMBITS) - 1)
#define RID_PARTITION_STARTBIT      48
#define RID_PARTITION_NUMBITS        8
#define RID_PARTITION_BITMASK       ((0x1LL << RID_PARTITION_NUMBITS) - 1)
#define RID_GEN_STARTBIT            56
#define RID_GEN_NUMBITS             8
#define RID_GEN_BITMASK             ((0x1LL << RID_GEN_NUMBITS) - 1)

/*
 * Note that the p_type declaration below currently allows no more than 8 types.
 */
enum rna_key_ptype{
	RNA_HASH_PRI_TYPE_FILE = 0,
	RNA_HASH_PRI_TYPE_BLOCK,
	RNA_HASH_PRI_TYPE_USER,
	RNA_HASH_PRI_TYPE_TAIL
};

/*
 * Note that this struct must be no larger than 64 bits.
 *
 * (Note in the following that, since p_type is declared at the most
 * significant end of data (on intel architectures), it could be expanded
 * in the future without changing how existing 'data' fields are interpreted,
 * as long as no 'data' fields use the most significant bits).
 */
DECLARE_PACKED_STRUCT(key_private_data) {
	uint64_t data :  61;
	uint64_t p_type: 3;
} END_PACKED_STRUCT(key_private_data);

INLINE void bswap_key_private_data(struct key_private_data *data)
{
	UNREFERENCED_PARAMETER(data);

#if CPU_BE
	data->data = bswap_64(data->data);
#endif
}

DECLARE_PACKED_STRUCT(rna_hash_key) {
    union {
        uint8_t  key[RNA_HASH_KEY_SIZE];
        /*
         * The following is used for doing fast key comparisons.  Note that it
         * assumes that RNA_HASH_KEY_SIZE is a multiple of 8.  An assert in
         * rna_rbhash_alloc() checks for this.
         */
        uint64_t keycmp[RNA_HASH_KEY_SIZE/8];
    };
    union {
        struct   key_private_data pri;
        uint64_t pricmp;    /* Used for doing fast hash key comparisons, this
                             * field combines pri.data and pri.p_type.
                             */
    };
} END_PACKED_STRUCT(rna_hash_key);

INLINE void bswap_rna_hash_key_t(rna_hash_key_t *data)
{
	UNREFERENCED_PARAMETER(data);
#if CPU_BE
	// TODO: Verify key does not require swapping. This will depend on how the key placed into the array and if it is treated as
	//       as an array or masked to 32/64 bit quantities.
	bswap_key_private_data(&data->pri);
#endif
}

/*
 * Return the hash partition the specified hash key falls into.  This routine
 * assumes the maximum number of partitions is no greater than UCHAR_MAX + 1,
 * since only one byte of the hash key is used.  This limit can easily be
 * expanded in the future by using more of the hash key, if desired.
 *
 * Both the 'p_type' and 'data' fields are taken into account, so a master
 * block won't collide with block 0.
 *
 * Since both this hash partition calculation and the hash index (i.e. bucket)
 * calculation (rna_rbhash_compute_index()) use key->pricmp as input, each
 * function must be careful to use different portions of key->pricmp, to avoid
 * introducing a dependence.  If these calculations aren't independent, some
 * indexes in some partitions may never be used, because the set of blocks that
 * would map to those indexes always map to other partitions (see MVP-7575).
 *
 * To keep the calculation independent, this function uses only the low
 * order RID_PARTITION_NUMBITS bits of key->pricmp, and
 * rna_rbhash_compute_index() uses only the higher-order bits.
 *
 * The '23' in the following is just a useful prime number.  Because it's prime,
 * the blocks in a multi-block object will be evenly distributed among the
 * partitions.  Any prime number will do, but 23 provides a particularly good
 * walk of the partitions.
 *
 * Arguments:
 *     hash_key                 The hash key from which the hash partition is
 *                              to be extracted
 *     hash_partition_bitmask   A bitmask indicating the range of partitions
 *                              (number of partitions - 1, where the number of
 *                              partitions is a power of 2).
 */
INLINE int
hashkey_to_partition(rna_hash_key_t *hash_key,
                     uint32_t        hash_partition_bitmask)
{
    return ((int)((hash_key->key[0] +
                 ((hash_key->pricmp & ((1 << RID_PARTITION_NUMBITS) - 1))
                                        * 23)) & hash_partition_bitmask));
}


typedef enum {
	RNA_HASH_RET_SUCCESS = 0,
	RNA_HASH_RET_BUSY,
	RNA_HASH_RET_NOT_FOUND,
	RNA_HASH_RET_INVALID,
	RNA_HASH_RET_NO_RESOURCES,
	RNA_HASH_RET_ITEM_DEL_OK,
	RNA_HASH_RET_ITEM_DEL_PEND,
	RNA_HASH_RET_ITEM_DEL_FAIL,
	RNA_HASH_RET_MD5_ERR,
	RNA_HASH_RET_BAD_INDEX,
	RNA_HASH_RET_INV_PARAM,
    RNA_HASH_RET_ZERO_REFS,  /* Indicates this deref dropped refcount to 0
                              * without deleting the node. */
    RNA_HASH_RET_COLLISION,  /* Indicates an insertion failure due to
                              * collision. */
}rna_hash_ret_code_t;

INLINE const char * rna_hash_get_ret_code_string(rna_hash_ret_code_t ret_code)
{
    const char * ret = "Unknown";

    switch (ret_code) {
    case RNA_HASH_RET_SUCCESS: ret = "RNA_HASH_RET_SUCCESS"; break;
    case RNA_HASH_RET_BUSY: ret = "RNA_HASH_RET_BUSY"; break;
    case RNA_HASH_RET_NOT_FOUND: ret = "RNA_HASH_RET_NOT_FOUND"; break;
    case RNA_HASH_RET_INVALID: ret = "RNA_HASH_RET_INVALID"; break;
    case RNA_HASH_RET_NO_RESOURCES: ret = "RNA_HASH_RET_NO_RESOURCES"; break;
    case RNA_HASH_RET_ITEM_DEL_OK: ret = "RNA_HASH_RET_ITEM_DEL_OK"; break;
    case RNA_HASH_RET_ITEM_DEL_PEND: ret = "RNA_HASH_RET_ITEM_DEL_PEND"; break;
    case RNA_HASH_RET_ITEM_DEL_FAIL: ret = "RNA_HASH_RET_ITEM_DEL_FAIL"; break;
    case RNA_HASH_RET_MD5_ERR: ret = "RNA_HASH_RET_MD5_ERR"; break;
    case RNA_HASH_RET_BAD_INDEX: ret = "RNA_HASH_RET_BAD_INDEX"; break;
    case RNA_HASH_RET_INV_PARAM: ret = "RNA_HASH_RET_INV_PARAM"; break;
    case RNA_HASH_RET_ZERO_REFS: ret = "RNA_HASH_RET_ZERO_REFS"; break;
    case RNA_HASH_RET_COLLISION: ret = "RNA_HASH_RET_COLLISION"; break;
    }

    return ret;
}

/* Compute the hash key value */
INLINE rna_hash_ret_code_t
rna_hash_compute_key_path(char           *path,
                          size_t          path_len,
                          rna_hash_key_t *key)
{
    if ((NULL == path) || (NULL == key)) {
        return RNA_HASH_RET_INV_PARAM;
    }

    MD5((unsigned char*)path,path_len, &key->key[0]);

    key->pri.p_type = RNA_HASH_PRI_TYPE_FILE;
    key->pri.data = 0;

    return RNA_HASH_RET_SUCCESS;
}

/*
 * Convert a hash key of any type (path, block, tail, or master) to a block
 * hash key for the specified block.  This routine avoids the memcpy done by
 * rna_hash_compute_key_block().
 */
INLINE rna_hash_ret_code_t
rna_hash_convert_key_to_block_key(rna_hash_key_t *key,
                                  uint64_t        block_number)
{
    if (NULL == key) {
        return RNA_HASH_RET_INV_PARAM;
    }

    key->pri.p_type = RNA_HASH_PRI_TYPE_BLOCK;
    key->pri.data = block_number;

    return RNA_HASH_RET_SUCCESS;
}

/*
 * Convert a hash key of any type (path, block, tail, or master) to a master
 * hash key.  This routine avoids the memcpy done by
 * rna_hash_compute_key_master().
 */
INLINE rna_hash_ret_code_t
rna_hash_convert_key_to_master_key(rna_hash_key_t *key)
{
    if (NULL == key) {
        return RNA_HASH_RET_INV_PARAM;
    }

    key->pri.p_type = 0;
    key->pri.data = 0;

    return RNA_HASH_RET_SUCCESS;
}
