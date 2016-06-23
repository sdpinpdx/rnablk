/**
 * <rna_proc_ep.h> - Dell Fluid Cache block driver
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

#include <linux/proc_fs.h>

void ep_create_proc(struct com_ep * ep, const char* name);
void ep_update_proc_name(struct com_ep * ep, const char* name);
void ep_delete_proc(struct com_ep * ep);
void proc_ep_init (void);
void proc_ep_cleanup (void);
void proc_ep_init_instance (struct rna_transport_handle *com_handle, 
                            struct proc_dir_entry *proc_dir);
void proc_ep_cleanup_instance (struct rna_transport_handle *com_handle,
                               struct proc_dir_entry *proc_dir);

