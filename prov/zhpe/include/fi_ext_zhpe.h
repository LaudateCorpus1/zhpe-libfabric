/*
 * Copyright (c) 2018-2019 Hewlett Packard Enterprise Development LP.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _FI_EXT_ZHPE_H_
#define _FI_EXT_ZHPE_H_

#include <stdbool.h>

#include <rdma/fabric.h>

#ifdef  __cplusplus
extern "C" {
#endif

#define FI_ZHPE_OPS_V1		"zhpe_ops_v1"

#define FI_ZHPE_FAM_RKEY	(0)
#define FI_ZHPE_MSA_RKEY	(1)

enum fi_zhpe_mmap_cache_mode {
	FI_ZHPE_MMAP_CACHE_WB	= 0,
	FI_ZHPE_MMAP_CACHE_WC	= 1,
	FI_ZHPE_MMAP_CACHE_WT	= 2,
	FI_ZHPE_MMAP_CACHE_UC	= 3,
};

struct fi_zhpe_mmap_desc {
	/* Public portion of descriptor */
	void			*addr;
	size_t			length;
};

#define FI_ZHPE_EP_COUNTERS_VERSION (0)

struct fi_zhpe_ep_counters {
	uint32_t		version;
	uint32_t		len;
	uint64_t		hw_atomics;
	uint64_t		rx_oos;
	uint64_t		tx_retry;
};

/* zhpe provider specific ops */
struct fi_zhpe_ext_ops_v1 {
	int (*lookup)(const char *url, void **sa, size_t *sa_len);
	int (*mmap)(void *addr, size_t length, int prot, int flags,
		    off_t offset, struct fid_ep *ep, fi_addr_t fi_addr,
		    uint64_t key, enum fi_zhpe_mmap_cache_mode cache_mode,
		    struct fi_zhpe_mmap_desc **mmap_desc);
	int (*munmap)(struct fi_zhpe_mmap_desc *mmap_desc);
	int (*commit)(struct fi_zhpe_mmap_desc *mmap_desc,
		      const void *addr, size_t length, bool fence,
		      bool invalidate, bool wait);
	int (*ep_counters)(struct fid_ep *ep,
			   struct fi_zhpe_ep_counters *counters);
};

#ifdef  __cplusplus
}; /* extern "C" */
#endif

#endif /* _FI_EXT_ZHPE_H_ */
