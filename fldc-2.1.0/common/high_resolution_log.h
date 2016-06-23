/*--------------------------------------------------------------------
**
**          DELL INC. PROPRIETARY INFORMATION
**
** This software is supplied under the terms of a license agreement or
** nondisclosure agreement with Dell Inc. and may not be copied or
** disclosed except in accordance with the terms of that agreement.
**
** Copyright (c) 2013 Dell Inc. All rights reserved.
**
**--------------------------------------------------------------------*/

#include "platform.h"                   // WINDOWS_* / LINUX_* platform defs

CODE_IDENT("$URL: $ $Id: $")

#ifndef __HIGH_RESOLUTION_LOG_H__
#define __HIGH_RESOLUTION_LOG_H__


#if ( defined ( WINDOWS_USER ) )
    #include "glib.h"                   // gboolean
#elif ( defined ( LINUX_USER ) )
    #include <glib.h>                   // gboolean
    #include <stdint.h>                 // standard integer types
#endif

#define RNA_DBG_HRL_BUFFER_SIZE_DEFAULT 10
#define RNA_DBG_HRL_BUFFER_OFFSET       ( 3 * sizeof ( uint64_t ) )

static const uint32_t k_HRL_backup_copies_default = 5;

typedef struct hrl_s
{
    uint64_t    buffer_size;                        /* hrl buffer size (bytes)  */
    uint64_t    first_entry;                        /* offset to first entry    */
    uint64_t    offset;                             /* offset to next entry     */
    char        data [ 1 ];                         /* hrl data                 */
}
    hrl_t;
    
void    add_hrl_entry ( const char *      entry );
void    create_hrl    ( const gboolean    use_syslog
                      , const uint64_t    buffer_size
                      , const uint32_t    backup_copies );
void    sync_hrl      (       void );

#endif  /* __HIGH_RESOLUTION_LOG_H__ */
