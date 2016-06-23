/**
 * <rna_proc_ep.c> - Dell Fluid Cache block driver
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

#include "../include/rna_common.h"
#include "../include/rna_atomic64.h"
#include "rna_com_linux_kernel.h"
#include "rna_proc_ep.h"
#include "rna_com_kernel.h"
#include <linux/proc_fs.h>

#ifdef ENABLE_PROC_EP

/* Not really a synchronization primitive, just a flag
 * to catch coding errors like  accidentally adding proc 
 * files before they have a directory to go into, or
 * trying to cleanup when the proc directory hasn't
 * been initialized. */
int setup_done = 0;

/* This lock might not be necessary, but we'll use it
 * anyway to be safe. */
rna_spinlock_t proc_ep_lock;

/* Read callback function.  Data is the pointer to the com_ep.
 * Some of this is copied from com_dump_ep_state().
 *
 * We trust that the ep is still around; the proc file gets
 * deleted before the ep is freed.  It may be possible to
 * read from freed data if one thread reads from the proc 
 * file while a separate kernel thread frees the ep, but I'm
 * not sure there's anything we can do about that.
 *  
 * If remove_proc_entry() blocks until all accesses to that 
 * proc file complete, then this isn't a problem.  Unfortunately,
 * this doesn't seem to be the case for 2.6.18.  There is a
 * patch against 2.6.20 in the mm tree that fixes this:
 * http://kernel.org/pub/linux/kernel/people/akpm/patches/2.6/2.6.20-rc6/2.6.20-rc6-mm3/broken-out/fix-rmmod-read-write-races-in-proc-entries.patch
 */

int proc_ep_read(char *buf, char **start, off_t offset, 
                 int maxlen, int *eof, void *data)
{
    char * p = buf;
    struct com_ep * ep = (struct com_ep *) data;
    int ret = 0;

    /*rna_spin_lock(ep->lock);*/

    if (NULL == ep) {
        ret = -EAGAIN;
    } else {

        /* We don't bother with getting a lock on primary_cm_ep
         * here, since 
         * a) reading from pointers is atomic. 
         * b) nothing bad will happen if we get a bogus value */


#if 0
	/* The com layer doesn't know about CFMs and MDs.
	 * Perhaps we should add an extra ep callback, so
	 * the application can print additional data.  */

        if (ep == primary_cm_ep) {
            p += sprintf(p, "Primary CFM\n");
        }

        /* Same as above. */
        if (ep == g_md_ep) {
            p += sprintf(p, "Primary MD\n");
        }
#endif

        p += sprintf(p, "ep pointer  %p\n", ep);
        p += sprintf(p, "user type   %s\n",
                get_user_type_string(ep->user_type));
        p += sprintf(p, "ttype       %s\n",
                com_get_transport_type_string(
                    com_get_transport_type(ep->transport_handle)));

        p += sprintf(p, "state       %s\n",
                     get_ep_state_string(com_ep_state(ep)));
        p += sprintf(p, "ref count   %d\n", atomic_read(&ep->ref_count));
        p += sprintf(p, "local addr  " NIPQUAD_FMT ":%d\n",
                     NIPQUAD(ep->dst_in.sin_addr.s_addr),
                     ep->dst_in.sin_port);
        p += sprintf(p, "remote addr " NIPQUAD_FMT ":%d\n",
                     NIPQUAD(ep->src_in.sin_addr.s_addr),
                     ep->src_in.sin_port);
        p += sprintf(p, "recv        %d\n", atomic_read(&ep->recv_posted));
        p += sprintf(p, "total number received %"PRId64"\n", 
                     rna_atomic64_read(&ep->ep_num_recvs));
        p += sprintf(p, "send        %d\n", atomic_read(&ep->send_posted));
        p += sprintf(p, "num_send %d, min_send_avail %d, total number sent %"
                     PRId64"\n", 
                     ep->num_send,
                     atomic_read(&ep->min_send_avail),
                     rna_atomic64_read(&ep->ep_num_sends));
        p += sprintf(p, "rdma posted  %d\n", atomic_read(&ep->rdma_posted));
        p += sprintf(p, "num_rdma %d, min_rdma_avail %d\n", 
                     ep->num_rdma,
                     atomic_read(&ep->min_rdma_avail));
        p = com_print_bb_stats(ep, p);
        p += sprintf(p, "\n\n");
    }

    /*rna_spin_unlock(ep->lock);*/

    if (0==ret)
        return (p-buf);
    else
        return ret;
}

/* Write callback.
 * Note: once we call com_disconnect, it's no longer safe 
 * to access the ep - it may have been freed.  */
int proc_ep_write(struct file *file, const char __user *buffer,
                           unsigned long count, void *data)
{
    char s[64];
    //int result;
    struct com_ep * ep = (struct com_ep *) data;
    int ret = 0;

    rna_spin_lock(proc_ep_lock);

    if (NULL == ep) {
        ret = -EAGAIN;
    } else if (count >= 64) {
        ret = -EINVAL;
    } else if (copy_from_user (&s, buffer, count)) {
        ret = -EFAULT;
    } else {
 
        s[count] = '\0';

        if (strcmp(s, "disconnect\n") == 0) {
            rna_printk(KERN_ERR, "Manually resetting ep %p\n", ep);
            com_disconnect(ep);

        /* todo: "reset cfm" should be moved to a separate, static proc file, so
         * we can reset the cfm ep even if there aren't any active eps. */
        } else if (strcmp(s, "reset cfm\n") == 0) {
            /* 0 is success */
            /* result = rna_maybe_reconnect_cm_servers(); 
            rna_printk(KERN_ERR, "Manually resetting CFM ep: rna_maybe_reconnect_cm_servers %s\n", 
                       result?"failed":"succeeded" ); */
            rna_printk (KERN_ERR, "ep reset disabled for now\n");
        } else {
            rna_printk(KERN_ERR, 
                       "unrecognized command given in write callback\n");
        }

    }

    rna_spin_unlock(proc_ep_lock);

    if (0==ret)
        return count;
    else
        return ret;
}

/* If name is null, we create a name based on the hex 
 * representation of the com_ep pointer. */
void ep_create_proc(struct com_ep * ep, const char* name) 
{
    struct proc_dir_entry *pde;
    char namebuf[64];
    struct proc_dir_entry *proc_ep_root =
                            ep->transport_handle->proc_connections;

    BUG_ON(NULL == ep);

    rna_spin_lock(proc_ep_lock);

    if (NULL == name) {
        snprintf(namebuf, 64, "ep-%p", ep);
        namebuf[63] = '\0';
        name = namebuf;
    }

    rna_trace("Creating ep proc file %s for %lx\n",
               name, (unsigned long) ep);

    if (NULL != ep->procfile) {
        rna_printk(KERN_ERR, "procfile already exists\n");
    } else if (!setup_done || NULL == proc_ep_root) {
        rna_printk(KERN_ERR, "proc_ep_root not setup, "
                             "ep_create_proc called too soon\n");
    } else {    
       pde = create_proc_entry(name, S_IFREG|S_IRUGO, proc_ep_root);
       if (NULL == pde) {
           rna_printk(KERN_ERR, "create_proc_entry failed\n");
       } else {
           /*pde->owner      = THIS_MODULE; */
           pde->data       = (void*)ep;
           pde->read_proc  = proc_ep_read;
           pde->write_proc = proc_ep_write;

           ep->procfile = pde;
       }
    }

    rna_spin_unlock(proc_ep_lock);
}


void ep_update_proc_name(struct com_ep * ep, const char* name)
{
    BUG_ON(NULL == ep);

    ep_delete_proc(ep);
    ep_create_proc(ep, name);
}

void ep_delete_proc(struct com_ep * ep)
{
    struct proc_dir_entry *proc_ep_root =
                                ep->transport_handle->proc_connections;
    BUG_ON(NULL == ep);

    rna_spin_lock(proc_ep_lock);
    if (NULL == ep->procfile) {
        rna_printk(KERN_ERR, 
                   "tried to delete procfile that doesn't exist\n");
    } else {
        /* This may reduce the chance that a concurrent user of 
         * the procfile will access freed memory. */
        ep->procfile->read_proc = NULL;
        ep->procfile->write_proc = NULL;

        remove_proc_entry(ep->procfile->name, proc_ep_root);
        ep->procfile = NULL;
    }
    rna_spin_unlock(proc_ep_lock);
}

/* helper function to generate a name for a com handle */
static void com_name(struct rna_transport_handle* com_handle, char* dst)
{
   sprintf(dst, "com-instance-%d", com_handle->id);
}

void proc_ep_init(void) {
   rna_spin_lock_init(proc_ep_lock);
   setup_done = 1;
}

void proc_ep_cleanup(void) {
   return;
}

/* Initialize proc directory for a particular com instance.
 * This must be called before ep_create_proc etc.. 
*/
void proc_ep_init_instance (struct rna_transport_handle *com_handle, 
                            struct proc_dir_entry *proc_dir_root)
{
    char newdirname[64];

    BUG_ON(0==setup_done);

    if (com_handle->proc_connections) {
        rna_printk(KERN_ERR, "called twice %p\n", com_handle->proc_connections);
    } else {
        if (NULL == proc_dir_root) {
            rna_printk(KERN_ERR, "no root, creating in /proc\n");
        }

        com_name(com_handle, newdirname);
        rna_printk(KERN_INFO, "new proc name: %s\n", newdirname);
        rna_spin_lock(proc_ep_lock);
        com_handle->proc_connections = proc_mkdir(newdirname, proc_dir_root);
        rna_spin_unlock(proc_ep_lock);
    }
}

/* All of the ep proc files need to be deleted before calling this. */
void proc_ep_cleanup_instance (struct rna_transport_handle *com_handle,
                               struct proc_dir_entry* proc_dir_root) 
{
    char dirname[64];
    int ret;

    BUG_ON(0==setup_done);
 
    if (NULL == com_handle->proc_connections) {
         rna_printk(KERN_ERR, "proc_connections is NULL\n");
    } else {
        com_name(com_handle, dirname);
        rna_spin_lock(proc_ep_lock);

        /* This returns void, so we can't check for errors. */
        remove_proc_entry(dirname, proc_dir_root);
        com_handle->proc_connections = NULL;

        rna_spin_unlock(proc_ep_lock);
    }
}

#else /* ENABLE_PROC_EP */
void ep_create_proc(struct com_ep *ep, const char *name) {}
void ep_update_proc_name(struct com_ep *ep, const char *name) {}
void ep_delete_proc(struct com_ep *ep) {}
void proc_ep_init (void) {}
void proc_ep_cleanup (void) {}
void proc_ep_init_instance (struct rna_transport_handle *com_handle, 
                            struct proc_dir_entry *proc_dir) {}
void proc_ep_cleanup_instance (struct rna_transport_handle *com_handle,
                               struct proc_dir_entry *proc_dir) {}
#endif /* ENABLE_PROC_EP */
