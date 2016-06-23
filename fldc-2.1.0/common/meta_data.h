/**
 * <metadata.h> - Dell Fluid Cache block driver
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

#ifndef INCLUDED_META_DATA_H
#define INCLUDED_META_DATA_H

#include "platform.h"
#include "rna_hash_common.h"

#ifndef WINDOWS_KERNEL
#ifndef UCHAR_MAX
# define UCHAR_MAX      255
#endif
#endif //WINDOWS_KERNEL


CODE_IDENT("$URL: https://svn.rnanetworks.com/full/tags/HERMES_2_1_0_RC1/common/meta_data.h $ $Id: meta_data.h 38022 2014-11-04 15:28:20Z mhaverkamp $")

/** Maximum number of metadata hash partitions.
 *  IMPORTANT NOTES:
 *  1. This value should not be greater than UCHAR_MAX.  If a value larger
 *     than that is needed, rbhash_rid_to_partition() and hashkey_to_partition()
 *     will need to be be modified.
 */
#define MAX_MD_HASH_PARTITIONS 32

/** The maximum number of MDs.  Note that it's pointless to have more MDs than
 *  MAX_MD_HASH_PARTITIONS, since each MD must be assigned at least one hash
 *  partition to service.  This value can currently be increased with no
 *  negative effect beyond increasing the sizes of a couple of internal arrays.
 *  In the future, however, if rolling upgrade are supported, doing so would
 *  break rolling upgrades, since it would allow a new MD to be assigned an
 *  ordinal (by the CFM) that's too large for down-rev nodes' MD tables.
 */
#define MAX_MDS             MAX_MD_HASH_PARTITIONS

/** Number of MD ordinals.  THIS VALUE MUST BE >= MAX_MDS and <= 2^16!  (It can
 *  be made larger than 2^16 if the fields it's stored in are expanded from
 *  uint16_t). We allow more ordinals than MDs, to alow ordinals to be assigned
 *  sparsely, to make it easier to detect an unresponsive MD that has been
 *  booted from the cluster and suddenly becomes responsive and returns to the
 *  cluster.
 */
#define NUM_MD_ORDINALS     (UCHAR_MAX + 1)

/** CFM Metadata partition map (CONF_MGR_MD_PARTITION_MAP)
 *
 *  This struct (which is sometimes sent as a message by the CFM when a
 *  membership change occurs in the set of metadata servers) specifies
 *  which MD has been assigned to each metadata hash partition.
 *  (As background, the global metadata hash space is divided into equal-sized
 *  partitions, each of which is assigned to an MD to service).
 *
 * NOTE that though this message is a cfm_cmd, it must not be larger than a
 * cache_cmd, since cache servers (using rna_service) sometimes send these
 * messages to MDs in sendbufs sized to cache_cmd.
 */
DECLARE_PACKED_STRUCT(cfm_md_partition_map) {
    uint64_t         pm_generation; /*! The generation number of this partition
                                     *  map
                                     */
	uint16_t	     pm_num_hash_partitions;
									/*! The number of partitions the metadata
									 *	hash space is divided into (and the
									 *	number of entries in
									 *	pm_partition_assignments[])
									 */
    uint8_t          pm_group;       /*! Group this partition map applies to */
    uint8_t          pm_pad1;        /*! For future use */
    uint32_t         pm_pad2;        /*! For future use */
	uint16_t         pm_partition_assignments[MAX_MD_HASH_PARTITIONS + 1];
                                    /*!	For each metadata hash partition,
                                     *	the ordinal of the MD that's assigned
                                     *	to service requests within that
                                     *	partition
									 */
} END_PACKED_STRUCT(cfm_md_partition_map);

/*
 * MD cache servers policy type.
 */
#define MD_POLICY_PROPORTIONAL      (1 << 0)
#define MD_POLICY_CLIENTAFFINITY    (1 << 1)

#define MD_POLICY_PROPORTIONAL_STR "proportional"
#define MD_POLICY_CLIENTAFFINITY_STR "clientaffinity"
#define MD_POLICY_DEFAULT_STR "defaultpolicy"


/*
 * Determine which MD hash partition the specified block is assigned to.
 * Called by metadata_hashkey_to_partition and rna_service_hashkey_to_partition
 */
INLINE int
md_hashkey_to_partition(rna_hash_key_t *key,
                              uint32_t        hash_partition_bitmask)
{

    if ((0 == key->pri.p_type) && (0 == key->pri.data)) {
        /*
         * This is a key for a master block.  All master blocks are placed
         * in the last MD hash partition, which greatly simplifies ordered
         * locking when a metadata_vlock for both a block's partition and its
         * master block's partition are needed (as in prepare_paxos_insert()).
         * (Note that hash_partition_bitmask is the highest numbered partition).
         */
        return (hash_partition_bitmask);
    } else {
        /* This is a key for a non-master block */
        return (hashkey_to_partition(key, hash_partition_bitmask));
    }
}


INLINE const char *
get_md_policy_str(int policy)
{
    const char *ret = NULL;
    switch (policy) {
        case MD_POLICY_PROPORTIONAL:
            ret = MD_POLICY_PROPORTIONAL_STR;
            break;
        case MD_POLICY_CLIENTAFFINITY:
            ret = MD_POLICY_CLIENTAFFINITY_STR;
            break;
        default:
            ret = MD_POLICY_PROPORTIONAL_STR;
            break;
    }
    return (ret);
}

INLINE uint32_t
get_md_policy_enum(const char *policy)
{
    if (!policy) {
        return MD_POLICY_PROPORTIONAL;
    } else if (!strcmp(policy, MD_POLICY_PROPORTIONAL_STR)) {
        return MD_POLICY_PROPORTIONAL;
    } else if (!strcmp(policy, MD_POLICY_CLIENTAFFINITY_STR)) {
        return MD_POLICY_CLIENTAFFINITY;
    } else {
        return MD_POLICY_PROPORTIONAL;
    }

}

INLINE int
is_valid_policy(uint32_t policy)
{
    if (policy == MD_POLICY_PROPORTIONAL ||
        policy == MD_POLICY_CLIENTAFFINITY) {
        return 1;
    }
    return 0;
}
#endif
