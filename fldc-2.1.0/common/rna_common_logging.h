/**
 * <rna_log.h> - Dell Fluid Cache logging mechanism
 *
 * Copyright (c) 2012-13 Dell  Inc 
 *
 */

#pragma once

#include "platform.h"

#ifdef PLATFORM_WINDOWS
    #include "rna_common_logging_windows.h"

    #ifdef WINDOWS_USER
        #include <assert.h>  
    #endif 
#else
/* Linux*/
    #include "rna_common_logging_linux.h"
    
    #ifdef LINUX_KERNEL
        #include <linux/in.h> /*Needed for sockaddr_in */
    #else
        /* Linux User */
        #include <unistd.h>
        #include <glib.h>  /* Needed for gboolean */
    #endif /* LINUX Kernel vs user */
#endif

#include "high_resolution_log.h"

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define __location__ __FILE__ ":" TOSTRING(__LINE__)

// pid_t is an int
#define RNA_PID_T_FMT		"d"

// loff_t is a long long
#define RNA_LOFF_T_FMT		"llu"

// atomic_t is an int
#define RNA_ATOMIC_T_FMT	"d"

// page->index is long int
#define RNA_PAGE_INDEX_FMT  	"lu"


/* 
 * Keeping these inside the 'main' log file as they are generic enough to 
 * 3 of the 4 platforms of interest makes sense to keep in 1 file vs
 * creating multiple copies of the same enum/defines 
 */

#if defined(LINUX_USER) || defined(PLATFORM_WINDOWS)

/* 
DBG LOG LEVEL USAGE:
    RNA_DBG_ERR  - Errors. Failures which adversly affect the operation of the program.
    RNA_DBG_WARN - Warnings. Failures which should be acknolwedged or tended to, but the program can contine to operate
    RNA_DBG_INFO - Informational. Log message that assists the end user to know the program is operating. 
    RNA_DBG_VERBOSE - Debuging level. If trace is compiled in, it is included here.

    --- Component masks -- (*Note*: The component masks are currently used very sparsely)
    RNA_DBG_COM - Com library messages. All messages from the com library will have this bit set.
    RNA_DBG_CLIENT - Client library messages. All messages originating from the core client code will have this bit set.
    RNA_DBG_CACHE - Cache Server. 
    RNA_DBG_CFM - Configuration Manager
    RNA_DBG_HASH - Hash code debugging
    RNA_DBG_META_MGR - Metadata server debugging 
    RNA_DBG_DATA_ACCESS - 
    RNA_DBG_BOUNCE_BUF  - 
    RNA_DBG_SECURITY    - security related routines

    --- Special Masks ---
    RNA_DBG_REMOTE - Instructions to log this message to the CFM as well as locally
    RNA_DBG_HISTOGRAM - Message is actually a struct histogram and has special processing
    RNA_DBG_MSG - Unmaskable messages. (Startup/Version/Shutdown)
    RNA_DBG_EVENT - Event management messages. Messages made available to
                    OMSA/OME.

*/
typedef enum {
    RNA_DBG_NONE        = 0x00000000,
    RNA_DBG_ERR         = 0x00000001,
    RNA_DBG_WARN        = 0x00000002,
    RNA_DBG_INFO        = 0x00000004,
    RNA_DBG_CLIENT      = 0x00000008,
    RNA_DBG_CACHE       = 0x00000010,
    RNA_DBG_META_MGR    = 0x00000020,
    RNA_DBG_COM         = 0x00000040,
    RNA_DBG_HASH        = 0x00000080,
    RNA_DBG_CFM         = 0x00000100,
    RNA_DBG_DATA_ACCESS = 0x00000200,
    RNA_DBG_BOUNCE_BUF  = 0x00000400,
    RNA_DBG_SECURITY    = 0x00000800, /* message is security related */
    RNA_DBG_VERBOSE     = 0x00001000,
    RNA_DBG_REMOTE      = 0x00002000, /* If set send message to remote reciever */
    RNA_DBG_HISTOGRAM   = 0x00004000, /* If set, the message is actually a struct histogram */
    RNA_DBG_MSG         = 0x00008000, /* non-maskable message type */
    RNA_DBG_EVENT       = 0x00010000  /* If set, the message is an oms_event struct message */
} RNA_DBG_TYPE;

#define RNA_DBG_SECURITY_MSG         (RNA_DBG_SECURITY | RNA_DBG_MSG)
#define RNA_DBG_SECURITY_ERR         (RNA_DBG_SECURITY | RNA_DBG_ERR)
#define RNA_DBG_SECURITY_WARN        (RNA_DBG_SECURITY | RNA_DBG_WARN)
#define RNA_DBG_SECURITY_INFO        (RNA_DBG_SECURITY | RNA_DBG_NONE)      /* NONE, but really INFO */
#define RNA_DBG_SECURITY_VERBOSE     (RNA_DBG_SECURITY | RNA_DBG_VERBOSE)

#define RNA_DBG_COM_VERBOSE          (RNA_DBG_COM      | RNA_DBG_VERBOSE)
#define RNA_DBG_CLIENT_VERBOSE       (RNA_DBG_CLIENT   | RNA_DBG_VERBOSE)
#define RNA_DBG_CACHE_VERBOSE        (RNA_DBG_CACHE    | RNA_DBG_VERBOSE)
#define RNA_DBG_META_MGR_VERBOSE     (RNA_DBG_META_MGR | RNA_DBG_VERBOSE)
#define RNA_DBG_HASH_VERBOSE         (RNA_DBG_HASH     | RNA_DBG_VERBOSE)

#define RNA_DBG_ERR_REM              (RNA_DBG_ERR      | RNA_DBG_REMOTE)
#define RNA_DBG_WARN_REM             (RNA_DBG_WARN     | RNA_DBG_REMOTE)
#define RNA_DBG_INFO_REM             (RNA_DBG_INFO     | RNA_DBG_REMOTE)
#define RNA_DBG_VERBOSE_REM          (RNA_DBG_VERBOSE  | RNA_DBG_REMOTE)
#define RNA_DBG_MSG_REM              (RNA_DBG_MSG      | RNA_DBG_REMOTE)

#define RNA_DBG_CACHE_REM            (RNA_DBG_CACHE    | RNA_DBG_REMOTE)
#define RNA_DBG_CFM_TRACE            (RNA_DBG_CFM      | RNA_DBG_VERBOSE)  /* VERBOSE, but really trace */

typedef enum {
    RNA_DBG_DEST_NONE   = 0x0001,
    RNA_DBG_DEST_STDOUT = 0x0001,
    RNA_DBG_DEST_SYSLOG = 0x0002,
    RNA_DBG_DEST_FILE   = 0x0004,
    RNA_DBG_DEST_UNUSED = 0x0008,
    RNA_DBG_DEST_CFG    = 0x0010
} RNA_DBG_DEST;

// this is used by rna_dbg_log_ratelimited
struct ratelimit
{
    uint64_t last;  // timestamp of most recent successful event
    uint64_t timeout; // nsecs until a timeout expires
    int last_prio;  // priority of most recent successful event
    int dropped; // number of events dropped sice most recent success
};

#define RNA_DBG_LOG_FILE_DIRECTORY      "/opt/dell/fluidcache/cfm"
#define RNA_DBG_LOG_FILE                RNA_DBG_LOG_FILE_DIRECTORY"/cfm.log"
#define RNA_DBG_DEFERRED_FLUSH_DISABLED 0
#define RNA_DBG_LOG_SAVED_FILES         9
#define RNA_DBG_LOG_FLUSH_DELAY         1

extern RNA_DBG_TYPE g_rna_dbg_type;
extern RNA_DBG_DEST g_rna_dbg_dest;
extern RNA_FILE *   g_rna_dbg_log_file;
extern char *       g_rna_dbg_log_file_location;
extern int          g_rna_configured_dbg_log_size;

#define RNA_DBG_HRL_FILE RNA_DBG_LOG_FILE_DIRECTORY"/cfm.log.hrl"

extern RNA_DBG_TYPE g_rna_hrl_type;
extern char *       g_rna_dbg_hrl_file_location;
extern int          g_rna_configured_dbg_hrl_size;
extern hrl_t *      g_rna_dbg_hrl_mmap;

struct histogram;
extern void rna_dbg_histograms_init(void);
typedef void (*histogram_dump_fn)(void *context,
                                  struct histogram *histogram);
extern void rna_dbg_histograms_dump(void *context,
                                    histogram_dump_fn dump_fn);
//extern void rna_fprintf_escaped(FILE *stream, const char *format, ...);
extern void rna_fprintf_escaped(RNA_FILE *stream, const char *format, ...);

extern void __rna_dbg_log(const char *function, const int line,
    RNA_DBG_TYPE type, struct timespec * time, const char *fmt, ...) FORMAT((printf,5,6));
extern void rna_dbg_hrl_init(void);
extern void rna_dbg_log_init(void);
extern void rna_dbg_log_register_event_func(int (*func)(void *, uint32_t, char *),
                                            void *arg);
extern void __rna_dbg_log_ratelimited(const char *function,
                            const int line,
                            struct ratelimit *rl, int prio,
                            RNA_DBG_TYPE type, const char *fmt,  ...);
extern char* rna_dbg_log_timestamp(char *            timestamp,
                                   size_t            timestamp_size,
                                   struct timespec * event_time);
extern void init_ratelimit(struct ratelimit *rl, uint64_t millisec);
extern int ratelimited(struct ratelimit *rl, int prio);
extern int ratelimited_setrate(struct ratelimit *rl, int prio, uint64_t millisec);
extern void __log_dropped(const char *function, const int line,
                          RNA_DBG_TYPE type, struct ratelimit *rl);

/* extern void rna_write_sockaddr_in_xml(FILE *fd, char *name, struct sockaddr_in *addr); */

/*
 * Function for use when debug traces are turned off so
 * that the compiler won't complain when macros use
 * comma lists
 */
INLINE void null_func()
{
}

#define log_dropped(type, rl) \
	__log_dropped(__FUNCTION__, __LINE__, type, rl);

#if defined(_RNA_DBG_)

#ifndef WINDOWS_KERNEL

#if ( defined ( PLATFORM_WINDOWS ) )
    #define rna_log_filter(type) ((type) & (g_rna_dbg_type | RNA_DBG_MSG))
#else   /* PLATFORM_WINDOWS */
    #define rna_log_filter_log(type) ((type) & (g_rna_dbg_type | RNA_DBG_MSG))
    #define rna_log_filter_hrl(type) ((type) & (g_rna_hrl_type | RNA_DBG_MSG))
    #define rna_log_filter(type)     (rna_log_filter_log(type) || rna_log_filter_hrl(type))
#endif   /* PLATFORM_WINDOWS */

#define rna_dbg_log(type, fmt, ...) \
    ((! rna_log_filter(type)) ? (void) 1 : __rna_dbg_log(__FUNCTION__, __LINE__, type, NULL, fmt, ##__VA_ARGS__))
#endif /*WINDOWS_KERNEL */

#define rna_dbg_log_time(type, eventtime, fmt, ...) \
    ((! rna_log_filter(type)) ? (void) 1 : __rna_dbg_log(__FUNCTION__, __LINE__, type, eventtime, fmt, ##__VA_ARGS__))

#define rna_dbg_log_ratelimited(rl, prio, type, fmt, ...) \
    __rna_dbg_log_ratelimit(__FUNCTION__, __LINE__ rl, prio, type, 0, fmt, ##__VA_ARGS__)

#else  /* !_RNA_DBG_*/

#ifndef WINDOWS_KERNEL
#define rna_dbg_log(...) null_func()
#endif /*WINDOWS_KERNEL */

#endif /* !_RNA_DBG_ */

#if defined(_RNA_DBG_TRACE_)
#define rna_trace(...) \
        rna_dbg_log(RNA_DBG_VERBOSE, ##__VA_ARGS__)
#else
#define rna_trace(...) null_func()
#endif

#define rna_log_assert(expr) \
    _rna_log_assert((expr), #expr, __FILE__, __LINE__)

#if defined(_RNA_DBG_ASSERT_)
    #define debug_assert(expr) assert(expr)
#ifndef WINDOWS_KERNEL
    #define rna_debug_log_assert(expr) rna_log_assert(expr)
#endif /* WINDOWS_KERNEL */
#else
    #define debug_assert(expr) null_func()
#ifndef WINDOWS_KERNEL
    #define rna_debug_log_assert(expr) null_func()
#endif /*WINDOWS_KERNEL */
#endif


INLINE void
_rna_log_assert(gboolean expr, const char *e, const char *file, const int line)
{
	UNREFERENCED_PARAMETER(line);
	UNREFERENCED_PARAMETER(file);
	UNREFERENCED_PARAMETER(e);

    if (unlikely(!expr)) {
        rna_dbg_log(RNA_DBG_ERR, "assert(%s) failed at %s:%d\n",
                    e, file, line);
#if defined(LINUX_USER)
        /* Let message queue drain */
        sleep(2);
#endif
#if defined(LINUX_USER) || defined(WINDOWS_USER)
		fflush(g_rna_dbg_log_file);
        assert(0);
#elif defined(WINDOWS_KERNEL)
        NT_ASSERT(0);
#endif /* WINDOWS_USER */

    }
}


#endif /* LINUX_USER or PLATFORM_WINDOWS */
