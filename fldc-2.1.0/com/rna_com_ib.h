/**
 * <rna_com_ib.h> - Dell Fluid Cache block driver
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

/* IB-specific data declarations go in here.  This gets included by
 * rna_com_linux_impl.h.
 * We want to be able to compile the com layer even if IB isn't available,
 * so if DISABLE_IB is set, we define the necessary IB structures.
 */

#pragma once
#include "platform.h"

#include "rna_service.h"
//#include "../rna_service/rna_service_kernel.h"
#include "../include/rna_common_kernel_types.h"


#ifdef WINDOWS_KERNEL
#include "rna_service_win_workqueue.h"
#else
#include <linux/dma-mapping.h> // for dma_data_direction
#include <linux/workqueue.h>
#include <rdma/ib_verbs.h>
#endif /* WINDOWS_KERNEL */

#include "rna_byteswap.h"
#include "../include/config.h"


struct req_priv_data; // defined in rna_com_linux_impl.h

struct rdma_buf {
	struct ib_device	*ib_device;
	struct ib_mr		*mr;
	size_t               size;
	void				*rdma_mem;
	dma_addr_t			rdma_mem_dma;
	enum dma_data_direction direction;
};

#define COM_NUM_WC 50

#define RNA_MAX_RDMA_WR 1024

/*
 * RNA_MAX_SGE
 *  Important Notes:
 *  With the current rnablk driver implementation, we need a MAX_SGE
 *  value of at least 32 in order to allow a full, default-sized (i.e. 128K)
 *  cache block to be accessed by a single 'ios'.
 *  (The math is that a single sgl entry maps 4K, so 32 * 4K == 128K)
 *  So as of the first release, I am bumping the value to 32.  Note the
 *  1st release is DAS only, and no IB.  [See MVP-7376.]
 *
 *  However, retaining the below ancient note that describes why we were
 *  using a value of 29 before.  Assuming these hw (sw?) limitations still
 *  exist wrt IB cards/drivers, we may have to revisit this down the road
 *  when we need to support IB once again.  (Ideally at that point, we'll
 *  want to change the driver to support per-transport-type values for
 *  max_sge, rather than a single global value.)
 *
 *  Here's the old comment:
 *   * NOTE: Setting this higher then 29 may cause a system panic or spurious
 *   *       disconnect with particular HCAs. Specifically the one below..
 *   *       Mellanox Technologies MT25418
 *   *          [ConnectX VPI PCIe 2.0 2.5GT/s - IB DDR / 10GigE] (rev a0)
 *   *       a setting of 29 appears to be safe.
 *
 * Here's a NEWER comment (July 2013).  Enabling IB, it seems that
 *      rdma writes work a value of 32.
 *      rdma reads work a value of 30, but the connection drops for 31.
 *      So we are using 29 just to be safe.
 */
#ifndef _DISABLE_IB_
#define RNA_MAX_SGE     29
#else
#define RNA_MAX_SGE     32
#endif

//typedef struct WORK_ITEM rna_service_work_t;

struct cq_ctx {
	struct ib_cq		    *cq;
	rna_service_wait_obj	wait_obj;	
    rna_service_work_t 	    work;    
	//struct rna_ib_wc        ibwc[COM_NUM_WC];
	struct com_ep 	        *ep;
};

struct cq_wc_ctx {
	int				pid;
	struct	ib_wc	*wc_array;
};

#ifdef WINDOWS_KERNEL 

#else
struct ib_work {
    //struct work_struct w;
    workstruct_t w;
    struct com_ep *ep;
    //rna_ib_wc_t wc;
    struct ib_wc wc;
};
#endif 


