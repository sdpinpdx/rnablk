/**
 * <rnablk_util.c> - Dell Fluid Cache block driver
 *
 * Copyright (c) 2013 Dell  Inc
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

#include "rb.h"
#include "rnablk_io_state.h"
#include "rnablk_cache.h"
#include "rnablk_util.h"
#include "trace.h"

#ifdef WINDOWS_KERNEL
#include <stdio.h>
#endif /*WINDOWS_KERNEL*/

#ifdef IOS_TIMEOUT_TEST
boolean ios_timeout_test;
#endif /* IOS_TIMEOUT_TEST */

int rnablk_get_ios_debug_info(ios_tag_t search_tag,
                              struct rnablk_cache_ios_debug_info *ios_info)
{
    ios_tag_t next_tag = 0;

    return  (int)next_tag;
}

#define EP_STR_LEN  (24)
#define IOS_TIMEOUT_SCRIPT_LEN  (132)
char ios_timeout_script[IOS_TIMEOUT_SCRIPT_LEN];

static int rnablk_ios_timeout_resume(struct rnablk_server_conn *conn,
                                      void *ctx)
{
    if ((NULL != conn) && 
        atomic_bit_test_and_clear(&conn->rsc_flags, RSC_F_IOS_TMO_DEFERRED)) {
        rnablk_queue_conn_disconnect(conn);
    }
    return 0;
}

/* store cfs string into a persistent buffer. Remove any newline characters.
 * make sure it fits into the space available and is NULL terminated.
 */
INLINE int
store_cfs_str(char *dst, int dst_len, const char *src, int src_len)
{
    char *newline_p;
    int ret_len;

    /* make sure there's room for NULL character */
    if (src_len >= dst_len) {
        return  -1;
    }

    memcpy(dst, src, src_len);
    dst[src_len] = 0;
    ret_len = src_len;
    newline_p = strchr(dst, '\n');
    if (NULL != newline_p) {
        *newline_p = 0;
        ret_len = (int) (newline_p - dst);
    }
    return ret_len;
}

struct rnablk_ios_timeout_helper_work {
    struct work_struct work;
    struct io_state *ios;
    struct rnablk_server_conn *conn;
    boolean test;
};

/* invoke the usermode callback handler on the first ios timeout only.
 * If for some reason (memory allocation) the usermode helper fails,
 * then resume the conn timeout.
 *
 * This code runs at softirq level, as does the ios timeout handler.
 * so memory allocations are atomic and can fail.
 * If this is a problem, then maybe do this on the slow queue instead.
 */
static void
rnablk_ios_timeout_invoke_helper(struct io_state *ios,
                                 struct rnablk_server_conn *conn)
{
    char *dev_namestr = NULL;
    char ep_string[EP_STR_LEN];
    char ep_ip_string[64];
    char *argv[5];
    int result;

    static char *envp[] = {
        "HOME=/var/crash",
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin:/opt/dell/fluidcache/bin",
        NULL
    };

    /* redundant test. callers should be checking first */
    if (FALSE == ios_timeout_script_active) {
        rna_printk(KERN_ERR, "timeout script was deactiviated\n");
        goto err;
    }

    if (NULL == conn->ep) {
        rna_printk(KERN_ERR, "Not invoking timeout helper for "
                   "conn ["CONNFMT"] due to NULL ep\n", CONNFMTARGS(conn));
        goto err;
    }

    if (NULL == ios->dev) {
        rna_printk(KERN_ERR, "NULL ios->dev\n");
        goto err;
    }


    dev_namestr = ios->dev->name;
    sprintf(ep_string, "0x%p", conn->ep);
    sprintf(ep_ip_string, RNA_ADDR_FORMAT, RNA_ADDR(conn->id.u.data.address));

    argv[0] = ios_timeout_script;
    argv[1] = dev_namestr;
    argv[2] = ep_string;
    argv[3] = ep_ip_string;
    argv[4] = NULL;

    rna_printk(KERN_ERR,  "Invoking user-mode timeout helper for ep [%p] "
               "conn ["CONNFMT"] ios [%p] device [%s]\n", conn->ep,
               CONNFMTARGS(conn), ios, ios->dev->name);

#ifdef WINDOWS_KERNEL
	UNREFERENCED_PARAMETER(result);
#else
    result = call_usermodehelper(argv[0], argv, envp, 1);
    if (0 != result) {
        rna_printk(KERN_ERR, "call_usermodehlper error %d\n", result);
        goto err;
    }
#endif /*WINDOWS_KERNEL*/
    goto out;

err:

    rnablk_ios_timeout_resume(conn, NULL);

out:
    rna_printk(KERN_ERR,  "User-mode timeout helper completed for ep [%p] "
               "conn ["CONNFMT"]\n", conn->ep, CONNFMTARGS(conn));
}

static void
rnablk_queued_timeout_helper(rnablk_workq_cb_arg_t arg)
{
    struct work_struct *dpc_work;
    struct rnablk_ios_timeout_helper_work *w;

    dpc_work = (struct work_struct *)arg;
    w = container_of(dpc_work, struct rnablk_ios_timeout_helper_work, work);

    rnablk_ios_timeout_invoke_helper(w->ios, w->conn);
    rnablk_ios_release(w->ios);
    kfree(w);
}

int
rnablk_queue_timeout_helper_for_conn(struct rnablk_server_conn *conn,
                                     struct io_state *ios,
                                     boolean test)
{
    struct rnablk_ios_timeout_helper_work *w;
    int ret = 0;

    if (FALSE == test) {
        if (!atomic_bit_test_and_set(&conn->rsc_flags,
                                     RSC_F_IOS_TMO_DEFERRED)) {
            /* this conn's timeout is already deferred */
            goto out;
        }
        rna_printk(KERN_INFO, "queue timeout helper for ep [%p] "
                   "conn ["CONNFMT"] ios [%p] device [%s]\n", conn->ep,
                   CONNFMTARGS(conn), ios, ios->dev->name);
    }

    if (atomic_read(&shutdown)) {
        ret = -1;
        goto out;
    }

#ifdef WINDOWS_KERNEL
	w = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(*w), RNA_ALLOC_TAG);
#else
    w = kmalloc(sizeof(*w), GFP_ATOMIC);
#endif /*WINDOWS_KERNEL*/
    if (NULL == w) {
        rna_printk(KERN_ERR, "kmalloc failed\n");
        ret = -1;
        goto out;
    }

    rnablk_ios_ref(ios);        // add reference to ios

    RNA_INIT_WORK(&w->work, rnablk_queued_timeout_helper, w);
    w->ios = ios;
    w->conn = conn;
    rna_queue_work(slow_workq, &w->work);

out:
    return ret;
}

struct rnablk_timeout_helper_conn_arg {
    struct io_state *thc_ios;
    struct rnablk_server_conn *thc_conn;
    boolean thc_found_conn;
    boolean thc_test;
};

int
rnablk_timeout_helper_conn_wrapper(struct rnablk_server_conn *conn,
                                   void *opaque_arg)
{
    struct rnablk_timeout_helper_conn_arg *p_arg =
                        (struct rnablk_timeout_helper_conn_arg *)opaque_arg;

    if (conn == g_md_conn) {
        return 0;
    }

    if (conn->id.u.data.address == p_arg->thc_conn->id.u.data.address) {
        p_arg->thc_found_conn = TRUE;
    }    
    rnablk_queue_timeout_helper_for_conn(conn, p_arg->thc_ios, p_arg->thc_test);
    
    return 0; 
}
    
static void
rnablk_process_ios_timeout_helper_dpc(rnablk_workq_cb_arg_t arg)
{
    struct work_struct *dpc_work;
    struct rnablk_ios_timeout_helper_work *w;
    struct rnablk_timeout_helper_conn_arg carg;

    dpc_work = (struct work_struct *)arg;
    w = container_of(dpc_work, struct rnablk_ios_timeout_helper_work, work);

    if (TRUE == w->test
        || !atomic_bit_is_set(&w->conn->rsc_flags, RSC_F_IOS_TMO_DEFERRED)) {
        carg.thc_ios = w->ios;
        carg.thc_conn = w->conn;
        carg.thc_found_conn = FALSE;
        carg.thc_test = w->test;

        (void)rnablk_cache_conn_foreach(rnablk_timeout_helper_conn_wrapper,
                                        &carg);

        if (!carg.thc_found_conn) {
            /* (this shouldn't be able to happen, actually!) */
            rna_printk(KERN_WARNING, "didn't find ios conn ["CONNFMT"]??\n",
                       CONNFMTARGS(w->conn));        
            rnablk_queue_timeout_helper_for_conn(w->conn, w->ios, w->test);
        }
    }
    rnablk_ios_release(w->ios);
    kfree(w);
}

int
rnablk_deferred_process_ios_timeout_helper(struct io_state *ios,
                                           struct rnablk_server_conn *conn,
                                           boolean test)
{
    struct rnablk_ios_timeout_helper_work *w;
    int ret = 0;

    if (FALSE == ios_timeout_script_active) {
        rna_printk(KERN_ERR, "timeout script was deactiviated\n");
        goto out;
    }

    if (NULL == conn) {
        rna_printk(KERN_ERR, "NULL conn\n");
        goto out;
    }

    if (NULL == ios->dev) {
        rna_printk(KERN_ERR, "NULL ios->dev\n");
        goto out;
    }

    if (FALSE == test
        && atomic_bit_is_set(&conn->rsc_flags, RSC_F_IOS_TMO_DEFERRED)) {
        /*
         * Let's assume that this conn and any others we care about have
         * already been handled by timeout helper if this flag is set,
         * and so take a shortcut out of here!
         */
        goto out;
    }

    if (atomic_read(&shutdown)) {
        ret = -1;
        goto out;
    }

#ifdef WINDOWS_KERNEL
	w = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(*w), RNA_ALLOC_TAG);
#else
    w = kmalloc(sizeof(*w), GFP_ATOMIC);
#endif /*WINDOWS_KERNEL*/
    if (NULL == w) {
        rna_printk(KERN_ERR, "kmalloc failed\n");
        ret = -1;
        goto out;
    }

    rna_printk(KERN_INFO, "Queueing ios timeout helper: conn ["CONNFMT"] "
               "ios [%p]\n", CONNFMTARGS(conn), ios);
    RNA_INIT_WORK(&w->work, rnablk_process_ios_timeout_helper_dpc, w);
    rnablk_ios_ref(ios);
    w->ios = ios;
    w->conn = conn;
    w->test = test;
    rna_queue_work(slow_workq, &w->work);

 out:
    return ret;
}

int rnablk_ios_timeout_script_store(const char *buf, int len)
{
    int ret;
    ret = store_cfs_str(ios_timeout_script,
                        sizeof(ios_timeout_script),
                        buf,
                        len);
    if (0 > ret) {
        return -1;
    }
    ios_timeout_script_active = (ret > 0) ? TRUE : FALSE;
    return 0;
}

int rnablk_ios_timeout_script_show(char *page)
{
    int len;
    if (FALSE == ios_timeout_script_active) {
        return 0;
    }
    len = sprintf(page, "%s\n", ios_timeout_script);
    return len;
}

static int
rnablk_validate_ep(struct rnablk_server_conn *conn, void *opaque_ep)
{
    struct com_ep *ep = (struct com_ep *)opaque_ep;
    struct rnablk_server_conn *dev_conn;
    rnablk_cachedev_t *cdp;
    struct list_head *ent;
    lockstate_t flags;
    int i;

    if (conn->ep == ep) {
        return 1;
    }
    
    rna_spin_in_stack_lock_irqsave(conn->sc_lock, flags);
    list_for_each(ent, &conn->rsc_cachedevs) {
        cdp = list_entry(ent, rnablk_cachedev_t, rcd_link);
        for (i = 0; i < RNABLK_MAX_DEV_CONNS; i++) {
            if (NULL != (dev_conn = cdp->rcd_conns[i])) {
                if (dev_conn->ep == ep) {
                    rna_spin_in_stack_unlock_irqrestore(conn->sc_lock, flags);
                    return 1;
                }
            }
        }
    }
    rna_spin_in_stack_unlock_irqrestore(conn->sc_lock, flags);
    return 0;
}

static struct com_ep *
rnablk_string_to_ep(char *ep_string)
{
#ifndef WINDOWS_KERNEL
    struct com_ep *ep;

    ep = (struct com_ep *)simple_strtoull(ep_string, NULL, 0);
    if (NULL == ep || MD_CONN_EP_METAVALUE == ep) {
        return NULL;
    }

    if (rnablk_cache_foreach(&cache_conn_root, rnablk_validate_ep, ep)) {
        return ep;
    }
#endif /* WINDOWS_KERNEL */

    return NULL;
}

#define TEST_BUF_MAX    (EP_STR_LEN + NAME_MAX + 6)

int rnablk_ios_timeout_script_test_store(const char *buf, int len)
{
    struct io_state *ios = NULL;
    struct rnablk_device *blkdev = NULL;
    /*char ep_string[EP_STR_LEN];*/
    char *cfs_str = NULL;
    int cfs_str_len;
    char *ep_str;
    char *dev_namestr;
    struct com_ep *ep;
    int ret = -1;

    if (FALSE == ios_timeout_script_active) {
        goto out;
    }

    /* get space to hold a persistent copy of cfs string */
#ifdef WINDOWS_KERNEL
	cfs_str = (char *)ExAllocatePoolWithTag(NonPagedPoolNx, TEST_BUF_MAX, RNA_ALLOC_TAG);
#else
    cfs_str = kmalloc(TEST_BUF_MAX, GFP_KERNEL);
#endif /*WINDOWS_KERNEL*/
    if (NULL == cfs_str) {
        rna_printk(KERN_ERR, "allocating cfs string buffer failed\n");
        goto out;
    }

    cfs_str_len = store_cfs_str(cfs_str, TEST_BUF_MAX, buf, len);
    if (0 >= cfs_str_len) {
        rna_printk(KERN_ERR, "cfs string is malformed\n");
        goto out;
    }

    /* NULL terminate the ep argument, find beginning of device name */
    ep_str = cfs_str;
    dev_namestr = strchr(cfs_str, ' ');
    if (NULL == dev_namestr) {
        rna_printk(KERN_ERR, "dev name string malformed\n");
        goto out;
    }
    *dev_namestr = 0;
    dev_namestr++;

    /* get a pointer  */
    ep = rnablk_string_to_ep(ep_str);
    if (NULL == ep) {
        rna_printk(KERN_ERR, "end point string malformed\n");
        goto out;
    }

#ifdef WINDOWS_KERNEL
	ios = (struct io_state *)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(struct io_state), RNA_ALLOC_TAG);
#else
    ios = kmalloc(sizeof(struct io_state), GFP_KERNEL);
#endif /*WINDOWS_KERNEL*/
    if (NULL == ios) {
        rna_printk(KERN_ERR, "failed to allocate dummy io state\n");
        goto out;
    }

#ifdef WINDOWS_KERNEL
	blkdev = (struct rnablk_device *)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(struct rnablk_device), RNA_ALLOC_TAG);
#else
    blkdev = kmalloc(sizeof(struct rnablk_device), GFP_KERNEL);
#endif /*WINDOWS_KERNEL*/
    if (NULL == blkdev) {
        rna_printk(KERN_ERR, "failed to allocate dummy rnablk_device\n");
        goto  out;
    }

    ios->ep = ep;
    ios->dev = blkdev;
    strncpy(blkdev->name, dev_namestr, NAME_MAX);

    ret = rnablk_deferred_process_ios_timeout_helper(ios, com_get_ep_context(ep), TRUE);
    if (ret == -1) {
        rna_printk(KERN_ERR, "deferred process failed %d\n", ret);
        goto out;
    }

    rna_printk(KERN_INFO, "ios_timeout_test completed ret\n");
    ret = 0;

out:
    if (NULL != blkdev) {
        kfree(blkdev);
    }
    if (NULL != ios) {
        kfree(ios);
    }
    if (NULL != cfs_str) {
        kfree(cfs_str);
    }

    return ret;
}

int
rnablk_ios_timeout_script_finish_store(const char *buf, int len)
{
    char ep_string[EP_STR_LEN];
    struct com_ep *ep;
    unsigned char oldirql = 0;
    int ret;

    ret = store_cfs_str(ep_string, sizeof(ep_string), buf, len);
    if (0 >= ret){
        return -1;
    }

    if (0 == strcmp(ep_string, "all")) {
        rna_down_read(&svr_conn_lock, &oldirql);
        rnablk_cache_foreach(&cache_conn_root, rnablk_ios_timeout_resume, NULL);
        rna_up_read(&svr_conn_lock, oldirql);
    } else {
        ep = rnablk_string_to_ep(ep_string);
        if (NULL == ep) {
            rna_printk(KERN_WARNING, "ep [%s] not found, no action taken\n",
                       ep_string);
            return -1;
        }
        rna_printk(KERN_INFO, "timeout helper finished for ep [%p] "
                   "context [%p]\n", ep, com_get_ep_context(ep));
        rnablk_ios_timeout_resume(com_get_ep_context(ep), NULL);
    }

    return 0;
}

#ifdef IOS_TIMEOUT_TEST
int rnablk_ios_timeout_test_store(const char *buf, int len)
{
    char todo_string[12];
    int ret;

    ret = store_cfs_str(todo_string, sizeof(todo_string), buf, len);
    if (0 >= ret){
        return -1;
    }

    if (0 == strcmp(todo_string, "e")) {
        ios_timeout_test = TRUE;
        return 0;
    } else if (0 == strcmp(todo_string, "d")) {
        ios_timeout_test = FALSE;
        return 0;
    }

    return -1;
}

int rnablk_ios_timeout_test_show(char *page)
{
    int len;

    len = sprintf(page,
                  "timeout test %s\n",
                  (TRUE == ios_timeout_test) ?  "enabled" : "disabled");
    return len;
}
#endif /* IOS_TIMEOUT_TEST */

#ifndef WINDOWS_KERNEL
/*
 * Latency stats are handled in Windows through WMI.  
 * See RNA_StorPortVirtualMiniport.mof and Rna_vsmp_wmi.c 
 * for details. 
 */
INLINE char *
rnablk_get_latency_stat_string(int index) 
{
    switch (index) {
    case RNABLK_LATENCY_QUERY:
        return "QUERY";
    case RNABLK_LATENCY_WO_QUERY:
        return "WO_QUERY";
    case RNABLK_LATENCY_WO_TO_W:
        return "WO_TO_WRITE";
    case RNABLK_LATENCY_DEREF:
        return "DEREF";
    default:
        return "UNKNOWN";
    }
}

int rnablk_print_latency_stats(char *buf, int buf_size)
{
    int len;
    unsigned long flags;
    int i;
    char *cp = buf;

    ENTER;
    *buf = '\0';
    rna_spin_lock_irqsave(latency_stats.ls_spinlock, flags);
    for (i = 0; i < RNABLK_NUM_LATENCY_STATS; i++) {
        len = snprintf(cp, buf_size,
                       "%15s: number [%12d] total (ns) [%15"PRIu64"] average [%10"PRIu64"] "
                       "min [%10"PRIu64"] max [%10"PRIu64"]\n",
                       rnablk_get_latency_stat_string(i),
                       atomic_read(&latency_stats.ls_count[i]),
                       latency_stats.ls_time[i],
                       (0 == atomic_read(&latency_stats.ls_count[i])) ? 0 :
                       latency_stats.ls_time[i] / 
                       atomic_read(&latency_stats.ls_count[i]),
                       (0 == atomic_read(&latency_stats.ls_count[i])) ? 0 :
                       latency_stats.ls_min[i],
                       latency_stats.ls_max[i]);
        cp += len;
        buf_size -= len;
    }
    rna_spin_unlock_irqrestore(latency_stats.ls_spinlock, flags);
    ret = strlen(buf);
    EXIT;
}
#endif /*WINDOWS_KERNEL*/

