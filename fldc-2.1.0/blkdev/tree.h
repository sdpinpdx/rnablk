/**
 * <tree.h> - Dell Fluid Cache block driver
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

#ident "$URL$ $Id$"

#ifndef INCLUDED_TREE_H
#define INCLUDED_TREE_H
#include "platform.h"
#include "platform_atomic.h"

#ifdef WINDOWS_KERNEL
/*
#include <WinDef.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <sys/timeb.h>
#include <stddef.h>
*/
#include "rna_service_id.h"

#else
#ifndef _LINUX_RBTREE_H
#include <linux/rbtree.h>
#endif
#endif

#include "rna_byteswap.h"
#include "rna_types.h"
#include "rna_hash_common.h"
#include "rna_cache_structs.h"

int rnablk_cache_insert(struct rb_root            *root,
                        struct rnablk_server_conn *conn);
void rnablk_cache_remove(struct rb_root            *root,
                         struct rnablk_server_conn *conn);
int rnablk_cache_foreach (struct rb_root         *root,
                          RNABLK_CACHE_FOREACH_CB cb,
                          void                   *ctx);
struct rnablk_server_conn *rnablk_cache_search(struct rb_root        *root,
                                               struct rna_service_id *id);
struct rnablk_server_conn *rnablk_cache_search_next(struct rb_root        *root,
                                               uint64_t key);

int rnablk_cache_blk_insert( struct rb_root *root,struct cache_blk *blk );
void rnablk_cache_blk_remove( struct rb_root *root,struct cache_blk *blk );
void rnablk_cache_blk_foreach(struct rb_root    *root,
                              RNA_BLK_FOREACH_CB cb,
                              void              *ctx,
                              uint64_t           start_key,
                              uint64_t          *end_key_p);
struct cache_blk *rnablk_cache_blk_search( struct rb_root *root,
                             uint64_t start_sector);
struct cache_blk *rnablk_cache_blk_search_next(struct rb_root *root,
                             uint64_t search_key,
                             uint64_t *next_key);


#ifdef WINDOWS_KERNEL
struct cache_blk ** rb_first(struct rb_root *root, PVOID * restartKey);
struct cache_blk ** rb_next(struct rb_root *root, PVOID * restartKey);

BOOLEAN rnablk_cache_init_ep_root(struct rb_root * root);
BOOLEAN rnablk_cache_blk_init_cache_blk_root(struct rb_root * root);
VOID rnablk_cache_free_ep_root(struct rb_root *root);
VOID rnablk_cache_blk_free_cache_blk_root(struct rb_root * root);

NTSTATUS initializeLookAsideList();
void freeLookAsideList();

#endif /*WINDOWS_KERNEL*/

#endif  //INCLUDED_TREE_H
