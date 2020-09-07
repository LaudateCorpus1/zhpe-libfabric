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

struct zhpe_mr_cache_data {
	struct zhpeq_key_data	*qkdata;
};

static inline struct zhpe_mr_cache_data *entry_data(struct ofi_mr_entry *entry)
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
	struct ofi_mr_entry	*entry;
	struct zhpe_mr_cache_data *cdata;
	int64_t			old;
	uint64_t		notify_start;
	uint64_t		notify_end;

	*qkdata_out = NULL;
	for (;;) {
		ret = ofi_mr_cache_search(&zdom->cache, &attr, &entry);
		if (OFI_UNLIKELY(ret < 0))
			goto done;
		cdata = entry_data(entry);
		/*
		 * Mark entry as active, bit zero used by driver as
		 * a shoot down flag.
		 */
		old = atm_add(cdata->qkdata->active_uptr, 2);
		zhpe_stats_stamp_dbg(__func__, __LINE__,
				     (uintptr_t)cdata->qkdata->active_uptr, old,
				     (uintptr_t)buf, len);
		if (old & 1) {
			/* Shot down: clean up stale entries and retry. */
			atm_sub(cdata->qkdata->active_uptr, 2);
			ofi_mr_cache_delete(&zdom->cache, entry);
			/* Clean anything overlapping the pages. */
			notify_start = page_down((uintptr_t)buf);
			notify_end = page_up((uintptr_t)buf + len);
			mutex_lock(&mm_lock);
			ofi_mr_cache_notify(&zdom->cache, TO_PTR(notify_start),
					    notify_end - notify_start);
			mutex_unlock(&mm_lock);
			ofi_mr_cache_flush(&zdom->cache, false);
			continue;
		}
		break;
	}
	if ((cdata->qkdata->z.access & qaccess & QACCESS_RW) !=
	    (qaccess & QACCESS_RW)) {
		ret = -EFAULT;
		ofi_mr_cache_delete(&zdom->cache, entry);
		goto done;
	}

	*qkdata_out = cdata->qkdata;
	ret = 0;

done:
	return ret;
}

static int zhpe_mr_free_cached(struct zhpe_dom *zdom,
			       struct zhpeq_key_data *qkdata)
{
	struct ofi_mr_entry	*entry = qkdata->cache_entry;
	int64_t			old;

	/* Deactivate entry. */
	old = atm_sub(qkdata->active_uptr, 2);
	zhpe_stats_stamp_dbg(__func__, __LINE__,
			     (uintptr_t)qkdata->active_uptr, old, 0, 0);
	assert_always(!(old & 1));
	assert_always(old >= 2);
	ofi_mr_cache_delete(&zdom->cache, entry);

	return 0;
}

static int zhpe_mr_cache_add_region(struct ofi_mr_cache *cache,
				    struct ofi_mr_entry *entry)
{
	int			ret;
	struct zhpe_mr_cache_data *cdata = entry_data(entry);
	struct zhpe_dom		*zdom = udom2zdom(cache->domain);
	void			*buf = entry->info.iov.iov_base;
	size_t			len = entry->info.iov.iov_len;

	/* Flush shot down registrations before new registration. */
	ofi_mr_cache_flush(cache, false);
	ret = zhpeq_mr_reg(zdom->zqdom, buf, len, QACCESS_RW, &cdata->qkdata);
	if (ret < 0) {
		if (ret != -EFAULT)
			goto done;
		/* Possible read-only mapping. */
		ret = zhpeq_mr_reg(zdom->zqdom, buf, len, QACCESS_RD,
				   &cdata->qkdata);
		if (ret < 0)
			goto done;
	}
	cdata->qkdata->cache_entry = entry;

 done:
	/* zhpeq_mr_reg() will set cdata->qkdata to NULL on error. */

	return ret;
}

static void zhpe_mr_cache_delete_region(struct ofi_mr_cache *cache,
					struct ofi_mr_entry *entry)
{
	struct zhpe_mr_cache_data *cdata = entry_data(entry);
	int			rc;

	if (OFI_UNLIKELY(!cdata->qkdata))
		return;

	rc = zhpeq_qkdata_free(cdata->qkdata);
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

static void noop_monitor_init(struct ofi_mem_monitor *monitor)
{
}

static int noop_monitor_subscribe(struct ofi_mem_monitor *notifier,
				  const void *addr, size_t len)
{
	return 0;
}

static void noop_monitor_unsubscribe(struct ofi_mem_monitor *notifier,
				     const void *addr, size_t len)
{
}

/* Our driver is performing the monitor functionality. */
static struct dlist_entry	noop_dentry;

static struct ofi_mem_monitor	noop_monitor = {
	.list			= DLIST_INIT(&noop_monitor.list),
	.init			= noop_monitor_init,
	.cleanup		= noop_monitor_init,
	.subscribe		= noop_monitor_subscribe,
	.unsubscribe		= noop_monitor_unsubscribe,
};

int zhpe_dom_mr_cache_init(struct zhpe_dom *zdom)
{
	int			ret = 0;

	if (!zhpe_mr_cache_enable)
		goto done;

	ret = zhpeq_feature_enable(ZHPE_FEATURE_MR_OVERLAP_CHECKING);
	if (ret < 0)
		goto done;
	zdom->cache.entry_data_size = sizeof(struct zhpe_mr_cache_data);
	zdom->cache.add_region = zhpe_mr_cache_add_region;
	zdom->cache.delete_region = zhpe_mr_cache_delete_region;
	/* Wiggle around monitor init for now. */
	dlist_insert_head(&noop_dentry, &noop_monitor.list);
	ret = ofi_mr_cache_init(&zdom->util_domain, &noop_monitor,
				&zdom->cache);
	if (ret < 0)
		goto done;
	zdom->qkdata_mr_reg = zhpe_mr_reg_cached;
	zdom->qkdata_mr_free = zhpe_mr_free_cached;

 done:
	return ret;
}

#ifndef NDEBUG

static void mr_cache_dump_handler(struct ofi_rbmap *rbmap, void *handler_arg,
				  struct ofi_rbnode *rbnode)
{
	struct ofi_mr_entry	*entry = rbnode->data;
	struct zhpe_mr_cache_data *cdata = entry_data(entry);

	fprintf(stderr,
                "0x%016" PRIx64 "/0x%016" PRIx64 "/%ld/%d\n",
		(uintptr_t)entry->info.iov.iov_base, entry->info.iov.iov_len,
		*cdata->qkdata->active_uptr, entry->use_cnt);
}


void zhpe_mr_cache_dump(struct ofi_mr_cache *cache)
{
	ofi_rbmap_walk(cache->storage.storage, NULL, mr_cache_dump_handler);
}

#endif
