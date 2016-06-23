/**
 * <rnablk_callbacks.h> - Dell Fluid Cache block driver
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

#ifdef WINDOWS_KERNEL
int 
rnablk_connect_cb(struct com_ep *ep, void *ep_ctx);

int
rnablk_disconn_cb(struct com_ep *ep, void *ctxt);

void
rnablk_destructor_cb(const struct com_ep *ep, void *ep_ctx);

int
rnablk_recv_cb(struct com_ep *ep, void *ep_ctx, void *data, int len, int status);

int
rnablk_rdma_send_completion(struct com_ep *ep, void *ep_ctx, void *data, int status);

int
rnablk_io_completion(struct com_ep *ep, void *ep_ctx, void *data, int status);

#else
void
rnablk_com_init(struct rna_com **com_ctx_p,
                struct com_attr *com_attr);
#endif /*WINDOWS_KERNEL*/


int rnablk_data_op_complete_common(struct io_state *ios, int err);
