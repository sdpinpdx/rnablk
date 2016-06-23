/**
 * <cachedev.h> - Dell Fluid Cache block driver
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

#ifndef _CACHEDEV_H_
#define _CACHEDEV_H_

#include "platform.h"

CODE_IDENT("$URL: https://svn.rnanetworks.com/full/tags/HERMES_2_1_0_RC1/common/cachedev.h $ $Id: cachedev.h 42871 2015-05-07 00:03:28Z speterson $")

#include "rna_service_id.h"

#include "rna_dskattrs_common.h"

/* Support for RNA cache devices */

/*
 * The maximum size of a cache device globally unique physical ID.
 */
#define CACHEDEV_PHYSICAL_ID_SIZE_MAX   32

/*
 * The maximum length of a cache device path
 */
#define MAX_CACHEDEV_PATH_LEN           128

/*
 * An invalid cache device ID (cachedev_id_t).
 */
#define NULL_CACHEDEV_ID                0

/*
 * The maximum number of replica stores a cache device can use (i.e. the
 * maximum number of replica stores on which it can replicate its unflushed
 * dirty blocks -- not the maximum number of replica stores it can host).
 * N-way write-back replication is supported, but only up to this limit.
 */
#define MAX_REPLICA_STORES_USED          5

/*
 * The maximum number of replica stores a cache device can host (i.e. the
 * maximum number of replica stores that can be contained in a cache device).
 */
#define MAX_REPLICA_STORES_HOSTED       64


/*
 * The maximum number of cache devices a cache server can host.  This constant
 * can be increased, if need be, with little negative effect.
 */
#define MAX_CACHE_DEVICES_PER_CS        32


/*
 * The maximum number of cache devices a cluster can host.  Increasing this
 * constant increases the size of a struct md_cfm_reg_resp, and therefore a
 * struct cfm_cmd.
 */
#define MAX_CACHE_DEVICES_PER_CLUSTER   1024


/*
 * Cache device type.
 */
typedef enum cachedev_type_e {
    CACHEDEV_TYPE_FLASH = 0,
    CACHEDEV_TYPE_DISK,
    CACHEDEV_TYPE_RAM,  /* Cache devices that are not assigned replica stores
                         * are from this point on.
                         */
    CACHEDEV_TYPE_NULL,
    CACHEDEV_TYPE_MAX,  /* MUST BE LAST */
} cachedev_type_t;

INLINE const char *
get_cachedev_type_string(cachedev_type_t type)
{
    const char * ret = NULL;

    switch (type) {
    case CACHEDEV_TYPE_FLASH:
        ret = "CACHEDEV_TYPE_FLASH";
        break;
    case CACHEDEV_TYPE_DISK:
        ret = "CACHEDEV_TYPE_DISK";
        break;
    case CACHEDEV_TYPE_NULL:
        ret = "CACHEDEV_TYPE_NULL";
        break;
    case CACHEDEV_TYPE_RAM:
        ret = "CACHEDEV_TYPE_RAM";
        break;
    case CACHEDEV_TYPE_MAX:
        ret = "CACHEDEV_TYPE_MAX";
        break;
    }
    return (ret);
}

/*
 * An internal RNA-assigned ID that's clusterwide-unique, but not globally-
 * unique), to identify the cache devices and replica stores belonging to
 * a cluster.
 *
 * A cache device ID of 0 is invalid.
 */
typedef uint64_t cachedev_id_t;

/*
 * The internal version of a cache device ID, which exposes the internal
 * structure of the ID.  Again, a cache device ID of 0 is invalid.
 */

#if defined(WINDOWS_USER) || defined(WINDOWS_KERNEL)
#pragma warning ( push )
#pragma warning(disable: 4214; disable: 4201)     /* disable non standard bit-field warnings */
#endif  /* WINDOWS_USER || WINDOWS_KERNEL */

typedef struct cachedev_id_internal_s {
    uint64_t    cid_seqno:            40;   /* Starting with 1, cache device
                                             * sequence numbers are assigned
                                             * (sequentially) by the primary
                                             * CFM whenever a cache device is
                                             * registered for the first time
                                             * or re-initialized after being
                                             * recovered and retired, or
                                             * whenever a new replica store is
                                             * created.
                                             */
    uint64_t    cid_private:          8;    /* Unused field set aside for use by
                                             * applications
                                             */
    uint64_t    cid_device_type:      8;    /* Flash, disk, RAM, etc. 
                                            * (see cachedev_type_t) */
    uint64_t    cid_device_subtype:   7;    /* The device subtype is used to
                                             * differentiate fast flash from
                                             * slow flash, fast disk from slow
                                             * disk, etc.
                                             */
    uint64_t    cid_is_replica_store: 1;    /* 0 indicates a cache device;
                                             * 1 indicates a replica store
                                             */
} cachedev_id_internal_t;

#if defined(LINUX_USER) || defined(WINDOWS_USER)
INLINE void rna_dump_cachedev_id_internal_xml(FILE *info_file, 
                                              char *name, 
                                              cachedev_id_internal_t *id)
{
    fprintf(info_file, "<cache_device_id");
    if (NULL != name) {
        fprintf(info_file, " name=\"%s\"", name);
    }
    fprintf(info_file, " seqno=\"0x%"PRIx64"\"", (uint64_t)id->cid_seqno);
    fprintf(info_file, " device_type=\"%s\"", get_cachedev_type_string(id->cid_device_type));
    fprintf(info_file, " device_subtype=\"%d\"", id->cid_device_subtype);
    fprintf(info_file, " is_replica_store=\"%d\"", id->cid_is_replica_store);
    fprintf(info_file, "/>\n");
}
#endif //(LINUX_USER) || defined(WINDOWS_USER)

/*
 * Returns:
 *     1 if the specified cache device is a replica store
 *     0 otherwise
 */
INLINE int
cachedev_is_replica_store(cachedev_id_t *cdi)
{
    return (int)(((cachedev_id_internal_t *)cdi)->cid_is_replica_store);
}

/* returns contents of 8-bit private value inside cache device ID */
INLINE uint8_t
cachedev_id_get_private(cachedev_id_t *cdi)
{
    return (uint8_t)(((cachedev_id_internal_t *)cdi)->cid_private);
}

/* sets contents of 8-bit private value inside cache device ID */
INLINE void
cachedev_id_set_private(cachedev_id_t *cdi, uint8_t priv_date)
{
    ((cachedev_id_internal_t *)cdi)->cid_private = priv_date;
}

/*
 * Returns the cache device type embedded in the specified cachedev_id_t.
 */
INLINE cachedev_type_t
cachedev_type(cachedev_id_t *cdi)
{
    return ((cachedev_type_t)
                        (((cachedev_id_internal_t *)cdi)->cid_device_type));
}

/*
 * A cache device globally unique physical ID.
 */
typedef struct cachedev_physical_id_s {
    union {
        rna_store_wwn_t cpi_wwn;

        /*
         * Make sure that the size of the cachedev_physical_id_t
         * remains "CACHEDEV_PHYSICAL_ID_SIZE_MAX" regardless
         * of any changes to the size of cpi_wwn
         */
        char    cpi_physical_id[CACHEDEV_PHYSICAL_ID_SIZE_MAX];
    } u;
} cachedev_physical_id_t;

#if defined(LINUX_USER) || defined(WINDOWS_USER)
INLINE void rna_dump_cachedev_physical_id_xml(FILE *info_file,
                                              char *name,
                                              cachedev_physical_id_t *id)
{
    int     ret;
    char   *wwn_str = NULL;

    ret = rna_create_wwn_strings(&id->u.cpi_wwn, &wwn_str,
                                 NULL, NULL, NULL);

    fprintf(info_file, "<cache_device_physical_id");
    if (NULL != name) {
        fprintf(info_file, " name=\"%s\"", name);
    }
    fprintf(info_file, " id=\"%s\"/>\n", wwn_str != NULL ? wwn_str : "NULL");
    if (NULL != wwn_str) {
        rna_free(wwn_str);
    }
}
#endif //(LINUX_USER) || defined(WINDOWS_USER)

/*
 * A globally unique cluster ID.  
 */
typedef struct rna_cluster_id_s {
    unsigned char    cid_id[16];     /* The GUID that identifies the cluster */
} rna_cluster_id_t;

#if defined(LINUX_USER) || defined(WINDOWS_USER)
INLINE void rna_dump_cluster_id_xml(FILE *info_file, 
                                    char *name, 
                                    rna_cluster_id_t *id)
{
    int     i;

    fprintf(info_file, "<cluster_id");
    if (NULL != name) {
        fprintf(info_file, " name=\"%s\"", name);
    }
    fprintf(info_file, " id=\"0x");
    for (i=0; i<sizeof(id->cid_id); i++) {
        fprintf(info_file, "%02x", id->cid_id[i]);
    }
    fprintf(info_file, "\"");
    fprintf(info_file, "/>\n");
}
#endif //(LINUX_USER) || defined(WINDOWS_USER)

/*
 * A cache device label.
 */
typedef struct cachedev_label_s {
    uint64_t                cl_magic;       /* Identifies this as an RNA cache
                                             * device label
                                             */
    rna_cluster_id_t        cl_cluster_id;  /* The ID of the RNA cluster this
                                             * cache device belongs to
                                             */
    cachedev_physical_id_t  cl_physical_id; /* The globally unique physical ID
                                             * of the cache device
                                             */
    union {
        cachedev_id_t       cl_rna_id;      /* The RNA-assigned clusterwide-
                                             * unique ID of the cache device
                                             * (more compact than the physical
                                             * ID)
                                             */
        cachedev_id_internal_t
                            cl_rna_internal_id;
                                            /* The internal version of the
                                             * above, which exposes its
                                             * internal structure.  Note that
                                             * the cache device's type and
                                             * subtype, and whether it's a
                                             * replica store, are encoded in
                                             * this ID.
                                             */
    };
    uint64_t                cl_device_bytes;
                                            /* The size of the cache device,
                                             * in bytes
                                             */
    uint8_t                 cl_state:5;     /* The state of the cache device
                                             * (see cachedev_state_t)
                                             * (low-order bits of byte).
                                             */
    uint8_t                 cl_unused:1;    /* For future use (for example,
                                             * can be used to expand cl_state
                                             * if necessary)
                                             */
    uint8_t                 cl_reactivating_flag:1;
                                            /* 1 if this cache device is in
                                             * the process of being
                                             * reactivated from a failed state
                                             * (as opposed to from a
                                             * failed-and-recovered state).
                                             *
                                             * (This is the second-highest-
                                             * order bit in this byte).
                                             */
    uint8_t                 cl_removing_flag:1;
                                            /* 1 if this cache device was in
                                             * the CACHEDEV_STATE_REMOVING
                                             * state before  the current state.
                                             * In this case, removal should
                                             * proceed once the current state
                                             * has been dealt with.
                                             * (This is the high-order bit in
                                             * this byte).
                                             */
    uint8_t                 cl_shutdown_state;
                                            /*
                                             * The state the cache device was
                                             * in when it was shutdown.
                                             * (see cachedev_shutdown_state_t)
                                             */
    uint8_t                 cl_version_number;
                                            /* The version number of the cache
                                             * device layout
                                             */
    uint8_t                 cl_type;        /* Cache device type, see
                                             * cachedev_type_t
                                             */
    char                    cl_dev_path[MAX_CACHEDEV_PATH_LEN];
                                            /* The current path name for the
                                             * cache device
                                             */
} cachedev_label_t;

#if defined(WINDOWS_USER) || defined(WINDOWS_KERNEL)
/* Re-enable non-standard bit field warning */
#pragma warning(pop)
#endif  /* WINDOWS_USER || WINDOWS_KERNEL */


INLINE void
bswap_cachedev_label_t(cachedev_label_t *data)
{
	UNREFERENCED_PARAMETER(data);
#if CPU_BE
    data->cl_magic = bswap_64(data->cl_magic);
    data->cl_rna_id = bswap_64(data->cl_rna_id);
    data->cl_device_bytes = bswap_64(data->cl_device_bytes);
#endif
}

/**
 * The state of a cache device.  NOTE that the size of cl_state allows no more
 * than 32 states to be used.  If more are needed, the size of cl_state should
 * be increased.
 */
typedef enum cachedev_state_e {
    CACHEDEV_STATE_INACTIVE = 0,
                /**
                 * A cache device that's been expelled from the cluster (after
                 * its CS became uncommunicative or died) or a cache device
                 * that's never been registered (this is a cache device's
                 * initial state).
                 */
    CACHEDEV_STATE_ACTIVE,
                /**
                 * The cache device is ready for use or in use.  If a cache
                 * device in this state is lost, but its replica store exists
                 * and is active, the cache device's dirty unflushed blocks can
                 * all be recovered from its replica store.
                 *
                 * Consider using cachedev_state_is_active() to test for this.
                 */
    CACHEDEV_STATE_DISCONNECTING,
                /**
                 * The cache server that manages a cache device that was
                 * previously CACHEDEV_STATE_ACTIVE has died or has become
                 * uncommunicative.  The cache device's dirty unflushed blocks
                 * are being recovered from its replica store(s).  Once
                 * recovery has completed, the state of the cache device will
                 * become CACHEDEV_STATE_INACTIVE.
                 */
    CACHEDEV_STATE_REMOVING,
                /**
                 * At the user's request, the cache device is being removed
                 * from the RNA cache.  Its dirty blocks are in the process
                 * of being flushed or reassigned to their replica store's
                 * cache device, and its clean blocks are in the process of
                 * being invalidated.  Once finished, the entry for the cache
                 * device will be removed from the journal.
                 */
    CACHEDEV_STATE_REMOVED,
                /**
                 * The cache device has been removed from the RNA cache, and
                 * no longer has any cached blocks stored on it (so no longer
                 * has any replica blocks).
                 */
    CACHEDEV_STATE_FAILING,
                /**
                 * The cache device failed a read or write operation, so should
                 * not be used again in the RNA cache (unless explicitly
                 * re-labeled).  The cache device's unflushed dirty blocks are
                 * being recovered from its replica store.  Once completed,
                 * this cache device will transition to the
                 * CACHEDEV_STATE_FAILED_AND_RECOVERED state.
                 */
    CACHEDEV_STATE_FAILED_AND_RECOVERED,
                /**
                 * After a failure, the cache device's dirty unflushed blocks
                 * have all been recovered from its replica store(s) and the
                 * cache device has been expelled.
                 */
    CACHEDEV_STATE_ACTIVE_CLEAN,
                /**
                 * A cache device that contains no dirty blocks.  If such a
                 * cache device is lost, no recovery of dirty blocks is
                 * necessary, it transitions directly to
                 * CACHEDEV_STATE_INACTIVE.
                 *
                 * Consider using cachedev_state_is_active() to test for this.
                 */
    CACHEDEV_STATE_SHUTTING_DOWN,
                /**
                 * The cache server that manages a cache device that was
                 * previously CACHEDEV_STATE_ACTIVE or
                 * CACHEDEV_STATE_ACTIVE_CLEAN is shutting down.  Its dirty
                 * blocks are in the process of being flushed or reassigned
                 * to their replica store's cache device, and its clean blocks
                 * are in the process of being invalidated.  Once finished, 
                 * his cache device will transition to the
                 * CACHEDEV_STATE_INACTIVE state.
                 */
} cachedev_state_t;

/** 
 * If a device is in the FAILED_AND_RECOVERED, REMOVED, or INACTIVE state we 
 * don't want to reuse data.
 *
 * Inline chosen here so argument expression is evaluated only once 
 * (e.g. atomic_get)
 */
INLINE int cachedev_state_may_be_restored(cachedev_state_t state)
{
    return ((CACHEDEV_STATE_FAILED_AND_RECOVERED != state) &&
            (CACHEDEV_STATE_REMOVED != state) &&
            (CACHEDEV_STATE_INACTIVE != state));
}

/*
 * When queried for the 2nd or subsequent time,
 * a cache server should not create an entry for a cache device
 * in any of these states. A cache device in one of these states
 * should already have an entry in the CS
 */
INLINE int cache_dev_should_exist(cachedev_state_t state)
{
    return ((CACHEDEV_STATE_REMOVING == state) ||
            (CACHEDEV_STATE_REMOVED == state) ||
            (CACHEDEV_STATE_FAILING == state) ||
            (CACHEDEV_STATE_SHUTTING_DOWN == state));
}

/** 
 * TRUE if the device is in one of the active states
 *
 * Inline chosen here so argument expression is evaluated only once (e.g. atomic_get)
 */
INLINE int cachedev_state_is_active(cachedev_state_t state)
{
    return ((CACHEDEV_STATE_ACTIVE_CLEAN == state) ||
            (CACHEDEV_STATE_ACTIVE == state));
}

/** 
 * TRUE if the device is in one of the states in which it may create replica stores
 * or replica blocks
 *
 * Inline chosen here so argument expression is evaluated only once (e.g. atomic_get)
 */
INLINE int cachedev_state_allows_repstore_create(cachedev_state_t state)
{
    return (cachedev_state_is_active(state) ||
            /* These two states will be more relevant when we do real resilvering */
            (CACHEDEV_STATE_REMOVING == state) ||
            (CACHEDEV_STATE_SHUTTING_DOWN == state));
}

INLINE const char *
get_cachedev_state_string(cachedev_state_t state)
{
    const char * ret = NULL;

    switch (state) {
    case CACHEDEV_STATE_INACTIVE:
        ret = "CACHEDEV_STATE_INACTIVE";
        break;
    case CACHEDEV_STATE_ACTIVE:
        ret = "CACHEDEV_STATE_ACTIVE";
        break;
    case CACHEDEV_STATE_DISCONNECTING:
        ret = "CACHEDEV_STATE_DISCONNECTING";
        break;
    case CACHEDEV_STATE_REMOVING:
        ret = "CACHEDEV_STATE_REMOVING";
        break;
    case CACHEDEV_STATE_REMOVED:
        ret = "CACHEDEV_STATE_REMOVED";
        break;
    case CACHEDEV_STATE_FAILING:
        ret = "CACHEDEV_STATE_FAILING";
        break;
    case CACHEDEV_STATE_FAILED_AND_RECOVERED:
        ret = "CACHEDEV_STATE_FAILED_AND_RECOVERED";
        break;
    case CACHEDEV_STATE_ACTIVE_CLEAN:
        ret = "CACHEDEV_STATE_ACTIVE_CLEAN";
        break;
    case CACHEDEV_STATE_SHUTTING_DOWN:
        ret = "CACHEDEV_STATE_SHUTTING_DOWN";
        break;
    }
    return (ret);
}

/*
 * Indication of how the device was shutdown.
 */
typedef enum cachedev_shutdown_state_e {
    /*
     * The cache device was cleanly shutdown by the cache server.
     */
    CACHEDEV_SHUTDOWN_STATE_CLEAN = 0,
    /*
     * The cache device was shutdown unexpectedly in an undetermined state.
     */
    CACHEDEV_SHUTDOWN_STATE_UNCLEAN,
} cachedev_shutdown_state_t;

INLINE const char* 
get_cachedev_shutdown_state_string(cachedev_shutdown_state_t state)
{
    const char* ret = "UNKNOWN";

    switch(state) {
    case CACHEDEV_SHUTDOWN_STATE_CLEAN:
        ret = "CLEAN SHUTDOWN";
        break;
    case CACHEDEV_SHUTDOWN_STATE_UNCLEAN:
        ret = "UNCLEAN SHUTDOWN OR IN USE";
        break;
    }
    return ret;
}

#if defined(LINUX_USER) || defined(WINDOWS_USER)
INLINE void rna_dump_cachedev_label_xml(FILE *info_file, cachedev_label_t *label)
{
    fprintf(info_file, "<cache_device_label");
    fprintf(info_file, " dev_path=\"%s\"", label->cl_dev_path);
    fprintf(info_file, " rna_id=\"0x%"PRIx64"\"", label->cl_rna_id);
    fprintf(info_file, " section_bytes=\"%"PRId64"\"", label->cl_device_bytes);
    fprintf(info_file, " state=\"%s\"", get_cachedev_state_string(label->cl_state));
    fprintf(info_file, " shutdown_state=\"%s\"", get_cachedev_shutdown_state_string(label->cl_shutdown_state));
    fprintf(info_file, " version_number=\"%d\"", label->cl_version_number);
    fprintf(info_file, " type=\"%s\"", get_cachedev_type_string(label->cl_type));
    fprintf(info_file, ">\n");
    
    rna_dump_cluster_id_xml(info_file, NULL, &label->cl_cluster_id);
    rna_dump_cachedev_physical_id_xml(info_file, NULL, &label->cl_physical_id);
    rna_dump_cachedev_id_internal_xml(info_file, NULL, &label->cl_rna_internal_id);
    fprintf(info_file, "</cache_device_label>\n");
}
#endif //(LINUX_USER) || defined(WINDOWS_USER)

/*
 * Information about a cache device
 */
typedef struct cachedev_info_s {
    struct rna_service_id cd_host_cache_server;
                                    /* The cache server that manages this
                                     * cache device (i.e. the ID of the cache
                                     * server on the node where this cache
                                     * device is located)
                                     */
    uint64_t              cd_resilver_request_number;
                                    /* This value is incremented each time
                                     * the primary CFM initiates a resilver
                                     * or re-host operation.
                                     */
    uint64_t              cd_resilver_event_request;
                                    /*
                                     * This value is set to the
                                     * cd_request_number when a resilvering
                                     * event is output to keep track of
                                     * which resilvering completion it
                                     * goes with.
                                     */
    cachedev_label_t      cd_label; /* The RNA-created label on the cache
                                     * device
                                     */
    char                  cd_cs_hostname[128];
                                    /* The hostname of the cache server where
                                     * this cache device is located
                                     */
} cachedev_info_t;

/*
 * The state of a replica store
 */
typedef enum replica_store_state_e {
    REPLICA_STORE_STATE_INACTIVE = 0,   /* This state must be zero */
                /*
                 * For a current replica store:
                 * Either this replica store has not yet been assigned a host
                 * cache device (in which case the above 'host cache device'
                 * field is empty) or it has been deleted (in which case the
                 * above 'host cache device' field is not empty).
                 *
                 * For a previous replica store:
                 * This entry in the previous replica stores array is empty.
                 */
    REPLICA_STORE_STATE_ACTIVE,
                /*
                 * For a current replica store:
                 * Ready for use or in use
                 *
                 * For a previous replica store:
                 * A replica store re-host operation is in progress. The blocks
                 * belonging to this (previous) replica store are being moved
                 * to this current replica store.
                 */
    REPLICA_STORE_STATE_RESILVERING_IN_PROGRESS,
                /*
                 * For a current replica store:
                 * This replica store is in the process of being resilvered
                 * (i.e. it doesn't yet contain all of the cache device's
                 * unflushed dirty blocks).
                 *
                 * For a previous replica store:
                 * Not a valid state; a previous replica store is never
                 * resilvered
                 */
    REPLICA_STORE_STATE_RECOVERY_IN_PROGRESS,
                /*
                 * For either a current or a previous replica store:
                 * The cache device served by this replica store has been lost,
                 * so the unflushed dirty blocks belonging to that cache device
                 * that are contained in this replica store must be recovered
                 * from this replica store.  Those blocks are being absorbed
                 * by the cache device that hosts this replica store.  If a
                 * replica store is in this state, then the state of its served
                 * cache device is CACHEDEV_STATE_RETIRED.
                 */
} replica_store_state_t;

INLINE const char *
get_replica_store_state_string(replica_store_state_t state)
{
    const char * ret = NULL;

    switch (state) {
    case REPLICA_STORE_STATE_INACTIVE:
        ret = "REPLICA_STORE_STATE_INACTIVE";
        break;
    case REPLICA_STORE_STATE_ACTIVE:
        ret = "REPLICA_STORE_STATE_ACTIVE";
        break;
    case REPLICA_STORE_STATE_RESILVERING_IN_PROGRESS:
        ret = "REPLICA_STORE_STATE_RESILVERING_IN_PROGRESS";
        break;
    case REPLICA_STORE_STATE_RECOVERY_IN_PROGRESS:
        ret = "REPLICA_STORE_STATE_RECOVERY_IN_PROGRESS";
        break;
    }
    return (ret);
}

#endif  // _CACHEDEV_H_
