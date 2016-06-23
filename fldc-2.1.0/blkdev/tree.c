/**
 * <tree.c> - Dell Fluid Cache block driver
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

#include <linux/kernel.h>
#include <linux/rwsem.h>
#include <linux/rbtree.h>
#include "rna_com_linux_kernel.h"
#include "trace.h"
#include "rb.h"

enum tag_direction {
    TAG_MATCH,
    TAG_LEFT,
    TAG_RIGHT
};

/* Cache Block Tree */
struct cache_blk *rnablk_cache_blk_search( struct rb_root *root,uint64_t key )
{
    struct cache_blk *blk = NULL;
    struct rb_node *n = root->rb_node;
    ENTER;

    while( n ) {
        blk = rb_entry( n,struct cache_blk,rbn );
        if( key < blk->start_sector ) {
            n   = n->rb_left;
            blk = NULL;
        }
        else if( key > blk->end_sector ) {
            n   = n->rb_right;
            blk = NULL;
        }
        else
            break;
    }

    EXITPTR( blk );
}

static inline int __cache_blk_insert( struct rb_root *root,uint64_t key,struct rb_node *rb_node )
{
    struct rb_node **p = &root->rb_node;
    struct rb_node *parent = NULL;
    struct cache_blk *blk;

    while( *p ) {
        parent = *p;
        blk    = rb_entry( parent,struct cache_blk,rbn );
        if( key < blk->start_sector )
            p = &(*p)->rb_left;
        else if( key > blk->end_sector )
            p = &(*p)->rb_right;
        else
            return 1;
    }

    rb_link_node( rb_node,parent,p );

    return 0;
}

// returns 1 if entry already exists, and 0 if not
int rnablk_cache_blk_insert( struct rb_root *root,struct cache_blk *blk )
{
    ENTER;

    if( !(ret = __cache_blk_insert( root,blk->start_sector,&blk->rbn )) )
        rb_insert_color( &blk->rbn,root );

    EXIT;
}

void rnablk_cache_blk_remove( struct rb_root *root,struct cache_blk *blk )
{
    rb_erase(&blk->rbn, root);
}

/*
 * Return the rbtree node that has the cache_blk with the closest
 * key greater or equal to the specified key.  Returns NULL if none found.
 */
static struct rb_node *
rnablk_cache_blk_search_ge(struct rb_root *root, uint64_t key)
{
    enum tag_direction tag_choice = TAG_MATCH;
    struct rb_node *n = NULL;
    struct rb_node *next_n;
    struct cache_blk *blk;

    next_n = root->rb_node;
    while (next_n) {
        blk = rb_entry(next_n, struct cache_blk, rbn);
        n = next_n;
        if (key < blk->start_sector) {
            next_n = n->rb_left;
            tag_choice = TAG_LEFT;
        } else if (key > blk->end_sector) {
            next_n = n->rb_right;
            tag_choice = TAG_RIGHT;
        } else {
            tag_choice = TAG_MATCH;
            break;
        }
    }

    if (TAG_RIGHT == tag_choice) {
        n = rb_next(n);
    }
    return n;
}

/*
 * Find and return the first cache_blk entry that has a key greater than
 * or equal to the search_key specified.  Also return the key of the
 * subsequent cache_blk entry in that tree.  (If there is no subsequent
 * cache_blk entry, then returns the found key plus 1 for 'next_key').
 *
 * Returns NULL if no entry is found that matches the criteria.
 * (In that case, 'next_key' will be set to equal the original search_key).
 */
struct cache_blk *
rnablk_cache_blk_search_next(struct rb_root *root,
                             uint64_t search_key,
                             uint64_t *next_key)
{
    struct cache_blk *blk = NULL;
    struct rb_node *n;

    *next_key = search_key;

    n = rnablk_cache_blk_search_ge(root, search_key);

    if (NULL != n) {
        struct rb_node *next_n;
        struct cache_blk *next_blk =  NULL;

        blk = rb_entry(n, struct cache_blk, rbn);

        next_n = rb_next(n);
        if (NULL != next_n) {
            next_blk = rb_entry(next_n, struct cache_blk, rbn);
            *next_key = next_blk->start_sector;
        } else {
            *next_key = blk->end_sector + 1;
        }
    }

    return (blk);
}


/* Cache End Point Tree */
struct rnablk_server_conn *rnablk_cache_search(struct rb_root        *root,
                                               struct rna_service_id *id)
{
    struct rnablk_server_conn *conn = NULL;
    struct rb_node *n = root->rb_node;
    uint64_t cs_key;
    uint64_t key;
    ENTER;

    BUG_ON(NULL == root);
    BUG_ON(NULL == id);

    key = id->u.hash;

    while( n ) {
        conn = rb_entry( n,struct rnablk_server_conn,rbn );
        cs_key = conn->id.u.hash;
        if( key < cs_key ) {
            n  = n->rb_left;
            conn = NULL;
        }
        else if( key > cs_key ) {
            n  = n->rb_right;
            conn = NULL;
        }
        else
            break;
    }

    EXITPTR( conn );
}

static inline int __cache_insert(struct rb_root            *root,
                                 struct rna_service_id     *id,
                                 struct rb_node            *rb_node)
{
    struct rb_node **p = &root->rb_node;
    struct rb_node *parent = NULL;
    struct rnablk_server_conn *conn = NULL;
    uint64_t cs_key;
    uint64_t key;

    BUG_ON(NULL == root);
    BUG_ON(NULL == rb_node);
    BUG_ON(NULL == id);

    key = id->u.hash;

    while( *p ) {
        parent  = *p;
        conn    = rb_entry( parent,struct rnablk_server_conn,rbn );
        cs_key = conn->id.u.hash;
        if( key < cs_key )
            p = &(*p)->rb_left;
        else if( key > cs_key )
            p = &(*p)->rb_right;
        else
            return 1;
    }

    rb_link_node( rb_node,parent,p );

    return 0;
}

// returns 1 if entry already exists, and 0 if not
int rnablk_cache_insert(struct rb_root            *root,
                        struct rnablk_server_conn *conn)
{
    ENTER;

    if( !(ret = __cache_insert(root, &conn->id, &conn->rbn )) )
        rb_insert_color( &conn->rbn,root );

    EXIT;
}

void rnablk_cache_remove(struct rb_root            *root,
                         struct rnablk_server_conn *conn)
{
    BUG_ON(NULL == root);
    BUG_ON(NULL == conn);
    rb_erase(&conn->rbn, root);
}

int rnablk_cache_foreach (struct rb_root         *root,
                          RNABLK_CACHE_FOREACH_CB cb,
                          void                   *ctx)
{
    struct rnablk_server_conn *conn;
    struct rb_node *n = root->rb_node;
    int ret = 0;

    BUG_ON(NULL == root);

    n = rb_first(root);

    while ((NULL != n) && (0 == ret)) {
        conn = rb_entry(n, struct rnablk_server_conn, rbn);
        ret = cb(conn, ctx);
        n = rb_next(n);
    }
    return ret;
}

/*
 * Return the rbtree node that has the rnablk_server_conn entry with the
 * closest key greater or equal to the specified key.  Returns NULL if
 * none found.
 */
static struct rb_node *
rnablk_cache_search_ge(struct rb_root *root, uint64_t key)
{
    enum tag_direction tag_choice = TAG_MATCH;
    struct rb_node *n = NULL;
    struct rb_node *next_n;
    struct rnablk_server_conn *conn;
    uint64_t conn_key;

    next_n = root->rb_node;
    while (next_n) {
        conn = rb_entry(next_n, struct rnablk_server_conn, rbn);
        n = next_n;
        conn_key = conn->id.u.hash;

        if (key < conn_key) {
            next_n = n->rb_left;
            tag_choice = TAG_LEFT;
        } else if (key > conn_key) {
            next_n = n->rb_right;
            tag_choice = TAG_RIGHT;
        } else {
            tag_choice = TAG_MATCH;
            break;
        }
    }

    if (TAG_RIGHT == tag_choice) {
        n = rb_next(n);
    }
    return n;
}

/*
 * Find and return the first rnablk_server_conn entry that has a key greater
 * than or equal to the search_key specified.
 *
 * Returns NULL if no entry is found that matches the criteria.
 */
struct rnablk_server_conn *
rnablk_cache_search_next(struct rb_root *root, uint64_t search_key)
{
    struct rnablk_server_conn *conn = NULL;
    struct rb_node *n;

    n = rnablk_cache_search_ge(root, search_key);
    if (NULL != n) {
        conn = rb_entry(n, struct rnablk_server_conn, rbn);
    }
    return (conn);
}


/* IOS Tree */
#ifdef RNA_USE_IOS_TREE
struct io_state *rnablk_ios_search( struct rb_root *root,uint64_t key )
{
    struct io_state *ios = NULL;
    struct rb_node *n = root->rb_node;
    ENTER;

    while( n ) {
        ios = rb_entry( n,struct io_state,rbn );
        if( key < ios->tag ) {
            n   = n->rb_left;
            ios = NULL;
        }
        else if( key > ios->tag ) {
            n   = n->rb_right;
            ios = NULL;
        }
        else
            break;
    }

    EXITPTR( ios );
}


/* Find the rb node containing an ios with a tag which is greaterh
 * than or equal to key.
 *
 * return a  pointer to that NODE, (or NULL).
 */
static struct rb_node *rnablk_ios_search_ge(struct rb_root *root,
                                              uint64_t key)
{
    struct rb_node *n = NULL;

    if (key == 0)  {
        n = rb_first(root);
    } else {
        enum tag_direction tag_choice = TAG_MATCH;
        struct rb_node *saved_n = NULL;
        struct io_state *ios = NULL;

        n = root->rb_node;
        while( n ) {
            ios = rb_entry(n, struct io_state, rbn);
            saved_n = n;
            if(key < ios->tag) {
                ios = NULL;
                n  = n->rb_left;
                tag_choice = TAG_LEFT;
            } else if(key > ios->tag) {
                ios = NULL;
                n  = n->rb_right;
                tag_choice = TAG_RIGHT;
            } else {
                tag_choice = TAG_MATCH;
                break;
            }
        }

        if ((TAG_MATCH != tag_choice) && (NULL != saved_n)) {
            n = (TAG_LEFT == tag_choice) ? saved_n : rb_next(saved_n);
        }
    }

    return n;
}

struct io_state *rnablk_ios_search_next(struct rb_root *root,
                                        uint64_t key,
                                        ios_tag_t *next_tag)
{
    struct io_state *ios = NULL;
    struct rb_node *n;
    ENTER;

    *next_tag = 0;

    n = rnablk_ios_search_ge(root, key);

    if (NULL != n) {
        struct rb_node *next_n;
        struct io_state  *next_ios =  NULL;

        ios =  rb_entry(n, struct  io_state, rbn);

        next_n = rb_next(n);
        if (NULL != next_n) {
            next_ios = rb_entry(next_n, struct io_state, rbn);
            *next_tag = next_ios->tag;
        }
    }

    EXITPTR( ios );
}

static inline int __ios_insert( struct rb_root *root,uint64_t key,struct rb_node *rb_node )
{
    struct rb_node **p = &root->rb_node;
    struct rb_node *parent = NULL;
    struct io_state *ios;

    while( *p ) {
        parent = *p;
        ios    = rb_entry( parent,struct io_state,rbn );
        if( key < ios->tag )
            p = &(*p)->rb_left;
        else if( key > ios->tag )
            p = &(*p)->rb_right;
        else
            return 1;
    }

    rb_link_node( rb_node,parent,p );

    return 0;
}

// returns 1 if entry already exists, and 0 if not
int rnablk_ios_insert( struct rb_root *root,struct io_state *ios )
{
    ENTER;

    if( !(ret = __ios_insert( root,ios->tag,&ios->rbn )) )
        rb_insert_color( &ios->rbn,root );

    EXIT;
}
#endif // IOS tree

void rnablk_cache_blk_foreach(struct rb_root    *root,
                              RNA_BLK_FOREACH_CB cb,
                              void              *ctx,
                              uint64_t           start_key,
                              uint64_t          *end_key_p)
{
    struct cache_blk *blk  = NULL;
    struct rb_node   *n    = NULL;
    struct rb_node   *next = NULL;
    int               ret  = 0;

    BUG_ON(NULL == root);

    if (0 != start_key) {
        blk = rnablk_cache_blk_search(root, start_key);
        if (NULL != blk) {
            n = &blk->rbn;
        }
    }

    if (NULL == n) {
        n = rb_first(root);
    }
    while (NULL != n) {
        blk = rb_entry(n, struct cache_blk, rbn);
        next = rb_next(n);
        ret = cb(blk, ctx);
        if (0 != ret) {
            break;
        }
        n = next;
    }
    if (NULL != end_key_p) {
        if (NULL == n) {
            *end_key_p = 0;
        } else {
            *end_key_p = blk->start_sector;
        }
    }
}

int rnablk_verify_conn_in_tree(struct rb_root            *root,
                               struct rnablk_server_conn *conn)
{
    struct rb_node *n   = NULL;
    int             ret = 0;

    BUG_ON(NULL == root);
    BUG_ON(NULL == conn);

    n = rb_first(root);

    while( n ) {
        if (conn == rb_entry( n,struct rnablk_server_conn,rbn )) {
            ret = TRUE;
            break;
        }
        n = rb_next(n);
    }
    return ret;
}
