/**
 * <event_log.h> - Dell Fluid Cache block driver
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

#ifndef _EVENT_LOG_H_
#define _EVENT_LOG_H_

#include "platform.h"

CODE_IDENT("$URL: $ $Id:$")

#if defined(LINUX_USER) || defined(WINDOWS_USER)
#include <time.h>
#endif

#include "util.h"

/* Version number of the event log layout */
#define EVENTLOG_VERSION 1

/*
 * Maximum number of events supported -- may be increased
 * as long as the the number is smaller than sizeof(event_count)
 * in the superblock.
 *
 * Once this number of events have been logged the log
 * will wrap.
 */
#define EVENTLOG_MAXEVENTS 8192

/*
 * Magic number for the event log superblock
 */
#define EVENTLOG_SB_MAGIC 0xfeedface

/*
 * Size of the superblock in bytes (must never be greater
 * than 512)
 */
#define EVENTLOG_SB_SIZE_BYTES  512

/*
 * Offset at which the superblock is placed in the event
 * log
 */
#define EVENTLOG_SB_OFFSET 0

/*
 * Magic number for the event log records
 */
#define EVENTLOG_RECORD_MAGIC 0xdeadbeef

/*
 * Length of a variable argument string.
 *
 * In theory this string can be much larger (upto 4096)
 * but realistically it's going to be much shorter.
 */
#define EVENTLOG_VARARGS_LEN 1000

/*
 * Maximum number of variable arguments supported
 */
#define EVENTLOG_MAX_VARARGS 4

/*
 * Size of an event log record in bytes (must be a power
 * of two)
 */
#define EVENTLOG_RECORD_SIZE_BYTES 4096

/*
 * Location of the event log
 */
#define EVENTLOG_DATA_DIR "/opt/dell/fluidcache/cfm/"
#define EVENTLOG_LOG EVENTLOG_DATA_DIR"cfm.log.events"

/*
 * Event log file offset after which we'll wrap around
 */
#define EVENTLOG_MAX_FILE_OFFSET (EVENTLOG_SB_SIZE_BYTES + \
        (EVENTLOG_RECORD_SIZE_BYTES * EVENTLOG_MAXEVENTS))

/*
 * Default limit of the number of events
 */
#define EVENTLOG_DEFAULT_LIMIT 10 

/*
 * Header part of the superblock record.
 */
typedef struct eventlog_sb_header {
    uint8_t     ev_version;        /* multiple versions may be
                                    * supported at some point
                                    */
    uint64_t    ev_creation_time;  /* XXX may not be needed */
    uint32_t    ev_magic;          /* magic number */
    uint64_t    reserved;          /* for future use */
} eventlog_sb_header_t;

/*
 * Data part of the superblock record that often
 * changes.
 */
typedef struct eventlog_sb_data {
    atomic_t    ev_event_count;        /* must be able to accomodate max.
                                        * number of events supported
                                        */
    atomic_t    ev_generation_number; /* current generation number */
    atomic_t    ev_last_event_marker; /* byte counter for the last event */
    uint64_t    ev_reserved;          /* for future use */
} eventlog_sb_data_t;

/*
 * Definition for the superblock record
 */
typedef struct eventlog_superblock {
    eventlog_sb_header_t    h;
    union {
        eventlog_sb_data_t  d;
        /*
         * Pad to ensure that the superblock never crosses
         * a 512-byte sector boundary
         */
        uint8_t             pad[(EVENTLOG_SB_SIZE_BYTES -
                                 sizeof(eventlog_sb_header_t))];
    } u;
} eventlog_superblock_t;

/*
 * Header part of an event log record header
 */
typedef struct eventlog_record_header {
    uint32_t    ev_eventid;            /* Dell event id */
    uint64_t    ev_generation_number;  /* generation number when event logged */
    time_t      ev_time;               /* time at which the event was recorded */
    uint32_t    ev_magic;              /* magic number */
    uint64_t    reserved;              /* for future use */
} eventlog_record_header_t;

/* Very important to keep types in the same order as eventArgType enumeration in hccapi.xsd */
typedef enum arg_type {
    ARG_TYPE_SIZE, /* size_t */
    ARG_TYPE_MODE, /* cache_write_mode_t */

    ARG_TYPE_CACHE_POOL_ID, /* GUID HCC ID */

    /* The cfm looks these up in the global_cachedev_list_head */
    ARG_TYPE_CACHEDEV_WWN,  /* rna_store_wwn_t */
    ARG_TYPE_CACHEDEV_PATH, /* rna_store_wwn_t */

    ARG_TYPE_STORAGE_PATH_WWN,  /* rna_store_wwn_t */
    ARG_TYPE_STORAGE_PATH_PATH, /* rna_store_wwn_t */

    ARG_TYPE_PERSISTENT_WWN,    /* rna_store_wwn_t */
    ARG_TYPE_PERSISTENT_PATH,   /* rna_store_wwn_t */

    ARG_TYPE_JOURNAL_LOCATION,  /* char* */

    ARG_TYPE_CACHED_LUN_NAME,   /* char* */

    ARG_TYPE_HCN_ID,            /* char* */

    ARG_TYPE_MGMT_IP,           /* char* */

    ARG_TYPE_CACHE_NET_IP,      /* char* */

    ARG_TYPE_SAN_ID,            /* char* */

    ARG_TYPE_SAN_NAME,          /* char* */

    ARG_TYPE_SAN_TYPE,          /* char* */

    ARG_TYPE_HC_VOLUME_ID,      /* char* */

    ARG_TYPE_SAN_VOLUME_ID,     /* char* */

    ARG_TYPE_SNAP_ID,           /* char* */

    ARG_TYPE_STATUS,            /* char* */

    /* used to terminate the va_list */
    ARG_TYPE_END
} arg_type_t;

/*
 * Variable arguments for an event
 */
typedef struct eventlog_record_vararg {
    arg_type_t  ev_argtype;
    char        ev_argval[EVENTLOG_VARARGS_LEN];
} eventlog_record_vararg_t;

/*
 * Data part of an event log record
 */
typedef struct eventlog_record_data {
    uint8_t                     ev_args_count;
    eventlog_record_vararg_t    ev_arg[EVENTLOG_MAX_VARARGS];
} eventlog_record_data_t;

/*
 * Definition for the event log record
 */
typedef struct eventlog_record {
    eventlog_record_header_t    h;
    union {
        eventlog_record_data_t  d;
        /*
         * Pad to ensure that the record never crosses
         * a 512-byte sector boundary
         */
        uint8_t                 pad[(EVENTLOG_RECORD_SIZE_BYTES -
                                     sizeof(eventlog_record_header_t))];
    } u;
} eventlog_record_t;

#if defined(LINUX_USER) || defined(WINDOWS_USER)
int event_log_init(char *logname, gboolean force);
void event_log_fini(void);
int event_log_write(eventlog_record_t *record);
int event_log_read(eventlog_record_t *record, int index);
GList *eventlog_read_by_generation_num(int generation_num, int limit);
GList *eventlog_read_by_time(time_t time, int limit);
GList *eventlog_read_last_n_events(int num_events);
void eventlog_free_events(GList *record_list);
void eventlog_print_events(GList *record_list);
void dump_log(char *logname);
void dump_superblock(char *logname);
#endif

#endif
