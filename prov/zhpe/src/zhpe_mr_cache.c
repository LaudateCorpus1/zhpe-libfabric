/*
 * Copyright (c) 2017 Intel Corporation, Inc.  All rights reserved.
 * Copyright (c) 2018-2019 Hewlett Packard Enterprise Development LP.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You m"ay choose to be licensed under the terms of the GNU
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

#include <zhpe.h>

#define ZHPE_SUBSYS	FI_LOG_DOMAIN

#define QACCESS_RD	(ZHPEQ_MR_PUT | ZHPEQ_MR_GET_REMOTE | ZHPEQ_MR_SEND)
#define QACCESS_WR	(ZHPEQ_MR_GET | ZHPEQ_MR_PUT_REMOTE | ZHPEQ_MR_RECV)
#define QACCESS_RW	(QACCESS_RD | QACCESS_WR)

static inline struct zhpeq_key_data **entry_data(struct ofi_mr_entry *entry)
{
	return (void *)entry->data;
}

static int zhpe_mr_reg_cached(struct zhpe_dom *zdom, const void *buf,
			      size_t len,  uint32_t qaccess,
			      struct zhpeq_key_data **qkdata_out)
{
	int			ret;
	struct iovec		iov = {
		.iov_base	= (void *)buf,
		.iov_len	= len,
	};
	struct fi_mr_attr	attr = {
		.mr_iov		= &iov,
		.iov_count	= 1,
		/*
		 * The cache implementation ignores access. Our
		 * add_region function will try for read/write and
		 * then try read-only. It will be up to this routine to
		 * check the returned flags and see if they are acceptable.
		 */
		.access		= 0,
	};
	struct zhpeq_key_data	*qkdata = NULL;
	struct ofi_mr_entry	*entry;

	ret = ofi_mr_cache_search(&zdom->cache, &attr, &entry);
	if (OFI_UNLIKELY(ret < 0))
		goto done;
	qkdata = *entry_data(entry);
	if ((qkdata->z.access & qaccess & QACCESS_RW) !=
	    (qaccess & QACCESS_RW)) {
		ret = -EFAULT;
		qkdata = NULL;
		ofi_mr_cache_delete(&zdom->cache, entry);
		goto done;
	}

 done:
	*qkdata_out = qkdata;

	return ret;
}

static int zhpe_mr_free_cached(struct zhpe_dom *zhpe,
			       struct zhpeq_key_data *qkdata)
{
	ofi_mr_cache_delete(&zhpe->cache, qkdata->cache_entry);

	return 0;
}

static int zhpe_mr_cache_add_region(struct ofi_mr_cache *cache,
				    struct ofi_mr_entry *entry)
{
	int			ret;
	struct zhpe_dom		*zdom = udom2zdom(cache->domain);
	void			*buf = entry->info.iov.iov_base;
	size_t			len = entry->info.iov.iov_len;
	struct zhpeq_key_data	*qkdata;

	ret = zhpeq_mr_reg(zdom->zqdom, buf, len, QACCESS_RW, &qkdata);
	if (ret < 0) {
		if (ret != -EFAULT)
			goto done;
		/* Possible read-only mapping. */
		ret = zhpeq_mr_reg(zdom->zqdom, buf, len, QACCESS_RD, &qkdata);
		if (ret < 0)
			goto done;
	}
	qkdata->cache_entry = entry;
	*entry_data(entry) = qkdata;

 done:
	return ret;
}

static void zhpe_mr_cache_delete_region(struct ofi_mr_cache *cache,
					struct ofi_mr_entry *entry)
{
	struct zhpeq_key_data   *qkdata = *entry_data(entry);
	int			rc;

	rc = zhpeq_qkdata_free(qkdata);
	if (rc < 0)
		ZHPE_LOG_ERROR("zhpeq_qkdata_free() error %d:%s\n",
			       rc, fi_strerror(-rc));
}

void zhpe_dom_mr_cache_destroy(struct zhpe_dom *zdom)
{
	if (zdom->qkdata_mr_reg == zhpe_mr_reg_cached) {
		ofi_mr_cache_cleanup(&zdom->cache);
		zdom->qkdata_mr_reg = NULL;
	}
}

int zhpe_dom_mr_cache_init(struct zhpe_dom *zdom)
{
	int			ret = 0;

	if (!zhpe_mr_cache_enable)
		goto done;

	zdom->cache.entry_data_size = sizeof(struct zhpe_mr *);
	zdom->cache.add_region = zhpe_mr_cache_add_region;
	zdom->cache.delete_region = zhpe_mr_cache_delete_region;
	ret = ofi_mr_cache_init(&zdom->util_domain, default_monitor,
				&zdom->cache);
	if (ret < 0)
		goto done;
	zdom->qkdata_mr_reg = zhpe_mr_reg_cached;
	zdom->qkdata_mr_free = zhpe_mr_free_cached;

 done:
	return ret;
}
