/*
 * Copyright (c) 2014 Intel Corporation, Inc.  All rights reserved.
 * Copyright (c) 2016 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2017-2019 Hewlett Packard Enterprise Development LP.  All rights reserved.
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

#include <zhpe.h>

#define ZHPE_LOG_DBG(...) _ZHPE_LOG_DBG(FI_LOG_FABRIC, __VA_ARGS__)
#define ZHPE_LOG_ERROR(...) _ZHPE_LOG_ERROR(FI_LOG_FABRIC, __VA_ARGS__)

pthread_mutex_t zhpe_fabdom_close_mutex = PTHREAD_MUTEX_INITIALIZER;

static struct fi_ops_fabric zhpe_fab_ops = {
	.size			= sizeof(struct fi_ops_fabric),
	.domain			= zhpe_domain,
#ifdef NOTYET
	.passive_ep		= zhpe_msg_passive_ep,
#else
	.passive_ep		= fi_no_passive_ep,
#endif
	.eq_open		= zhpe_eq_open,
	.wait_open		= ofi_wait_fd_open,
	.trywait		= ofi_trywait,
};

static int zhpe_fabric_close(fid_t fid)
{
	int			ret;
	struct zhpe_fabric	*zfab;

	zfab = fid2zfab(fid);
	mutex_lock(&zhpe_fabdom_close_mutex);
	ret = ofi_fabric_close(&zfab->util_fabric);
	mutex_unlock(&zhpe_fabdom_close_mutex);
	if (ret >= 0)
		free(zfab);

	return  ret;
}

static int zhpe_ext_lookup(const char *url, void **sa, size_t *sa_len)
{
	int			ret = -FI_EINVAL;
	const char		fam_pfx[] = "zhpe:///fam";
	const size_t		fam_pfx_len = strlen(fam_pfx);
	const char		ion_pfx[] = "zhpe:///ion";
	const size_t		ion_pfx_len = strlen(ion_pfx);
	const char		*p = url;
	uint			gcid;
	struct sockaddr_zhpe	*sz;
	char			*e;
	ulong			v;

	if (!sa)
		goto done;
	*sa = NULL;
	if (!url || !sa_len || !zhpeq_is_asic())
		goto done;
	if (!strncmp(url, fam_pfx, fam_pfx_len)) {
		gcid = 40;
		p += fam_pfx_len;
	} else if (!strncmp(url, ion_pfx, ion_pfx_len)) {
		gcid = 0;
		p += ion_pfx_len;
	} else
		goto done;
	if (!*p)
		goto done;
	errno = 0;
	v = strtoul(p, &e, 0);
	if (errno) {
		ret = -errno;
		goto done;
	}
	if (*e)
		goto done;
	*sa_len = 2 * sizeof(*sz);
	sz = calloc(1, *sa_len);
	if (!sz) {
		ret = -errno;
		goto done;
	}
	*sa = sz;
	sz->sz_family = AF_ZHPE;
	gcid += v;
	sz->sz_uuid[0] = gcid >> 20;
	sz->sz_uuid[1] = gcid >> 12;
	sz->sz_uuid[2] = gcid >> 4;
	sz->sz_uuid[3] = gcid << 4;
	sz->sz_queue = ZHPE_SA_TYPE_FAM;
	*sa  = sz;
	ret = 0;
 done:
	return ret;
}

static int mmap_get_rkey(struct fid_ep *ep, fi_addr_t fi_addr, uint64_t key,
			 struct zhpe_rkey_data **rkey)
{
	int			ret = -FI_EINVAL;
	int64_t			tindex = -1;
	struct zhpe_key		zkey = { .key = key };
	struct zhpe_ep		*zep;
	struct zhpe_ep_attr	*zep_attr;
	struct zhpe_tx_ctx	*tx_ctx;
	struct zhpe_conn	*conn;
	struct zhpe_pe_entry	*pe_entry;
	struct zhpe_pe_compstat *cstat;
	struct zhpe_pe_compstat cval;
	struct zhpe_msg_hdr	ohdr;

	*rkey = NULL;

	switch (ep->fid.fclass) {

	case FI_CLASS_EP:
		zep = fid2zep(&ep->fid);
		tx_ctx = zep->attr->tx_ctx;
		zep_attr = zep->attr;
		break;

	case FI_CLASS_TX_CTX:
		tx_ctx = container_of(ep, struct zhpe_tx_ctx, ctx);
		zep_attr = tx_ctx->ep_attr;
		break;

	default:
		goto done;
	}

	ret = zhpe_ep_get_conn(zep_attr, fi_addr, &conn);
	if (ret < 0)
		goto done;
	*rkey = zhpe_conn_rkey_get(conn, &zkey);
	if (*rkey)
		goto done;

	ret = zhpe_tx_reserve(conn->ztx, 0);
	if (ret < 0)
		goto done;
	tindex = ret;
	pe_entry = &conn->ztx->pentries[tindex];
	pe_entry->pe_root.handler = NULL;
	pe_entry->pe_root.conn = conn;
	pe_entry->pe_root.context = NULL;
	cstat = &pe_entry->pe_root.compstat;
	cstat->status = 0;
	cstat->completions = 0;
	cstat->flags = 0;
	pe_entry->rstate.cnt = 1;
	pe_entry->rstate.missing = 1;
	pe_entry->riov[0].iov_key = key;
	pe_entry->riov[0].iov_len = 0;

	ohdr.rx_id = zhpe_get_rx_id(tx_ctx, fi_addr);
	ohdr.pe_entry_id = htons(tindex);
	zhpe_pe_rkey_request(conn, ohdr, &pe_entry->rstate,
			     &cstat->completions);
	for (;;) {
		cval = atm_load_rlx(cstat);
		if (!cval.completions)
			break;
		if (zep_attr->domain->util_domain.data_progress ==
		    FI_PROGRESS_AUTO) {
			sched_yield();
			continue;
		}
		zhpe_pe_progress_tx_ctx(zep_attr->domain->pe, tx_ctx);
	}
	ret = cval.status;
	if (ret < 0)
		goto done;
	*rkey = zhpe_conn_rkey_get(conn, &zkey);
	if (!*rkey)
		ret = -FI_ENOKEY;

 done:
	if (tindex != -1)
		zhpe_tx_release(pe_entry);

	return ret;
}

struct fi_zhpe_mmap_desc_private {
	struct fi_zhpe_mmap_desc pub;
	struct zhpeq_mmap_desc  *zmdesc;
};

static int zhpe_ext_mmap(void *addr, size_t length, int prot, int flags,
			 off_t offset, struct fid_ep *ep, fi_addr_t fi_addr,
			 uint64_t key, enum fi_zhpe_mmap_cache_mode cache_mode,
			 struct fi_zhpe_mmap_desc **mmap_desc)
{
	int			ret = -FI_EINVAL;
	uint32_t		zq_cache_mode = 0;
	struct fi_zhpe_mmap_desc_private *mdesc = NULL;
	struct zhpe_rkey_data	*rkey = NULL;

	if (!mmap_desc)
		goto done;
	*mmap_desc = NULL;
	if (!ep)
		goto done;

	switch (cache_mode) {

	case FI_ZHPE_MMAP_CACHE_WB:
		zq_cache_mode |= ZHPEQ_MR_REQ_CPU_WB;
		break;

	case FI_ZHPE_MMAP_CACHE_WC:
		zq_cache_mode |= ZHPEQ_MR_REQ_CPU_WC;
		break;

	case FI_ZHPE_MMAP_CACHE_WT:
		zq_cache_mode |= ZHPEQ_MR_REQ_CPU_WT;
		break;

	case FI_ZHPE_MMAP_CACHE_UC:
		zq_cache_mode |= ZHPEQ_MR_REQ_CPU_UC;
		break;

	default:
		goto done;
	}

	ret  = mmap_get_rkey(ep, fi_addr, key, &rkey);
	if (ret < 0)
		goto done;
	mdesc = calloc(1, sizeof(*mdesc));
	if (!mdesc) {
		ret = -FI_ENOMEM;
		goto done;
	}
	mdesc->pub.length = length;

	ret = zhpeq_mmap(rkey->kdata, zq_cache_mode,
			 addr, length, prot, flags, offset, &mdesc->zmdesc);

 done:
	if (ret >= 0) {
		mdesc->pub.addr = mdesc->zmdesc->addr;
		*mmap_desc = &mdesc->pub;
		ret = 0;
	} else
		free(mdesc);
	zhpe_rkey_put(rkey);

	return ret;
}

static int zhpe_ext_munmap(struct fi_zhpe_mmap_desc *mmap_desc)
{
	int			ret = -FI_EINVAL;
	struct fi_zhpe_mmap_desc_private *mdesc =
		container_of(mmap_desc, struct fi_zhpe_mmap_desc_private, pub);

	if (!mmap_desc)
		goto done;
	ret = zhpeq_mmap_unmap(mdesc->zmdesc);
	free(mdesc);

 done:
	return ret;
}

static int zhpe_ext_commit(struct fi_zhpe_mmap_desc *mmap_desc,
			   const void *addr, size_t length, bool fence,
			   bool invalidate, bool wait)
{
	struct fi_zhpe_mmap_desc_private *mdesc =
		container_of(mmap_desc, struct fi_zhpe_mmap_desc_private, pub);

	return zhpeq_mmap_commit((mmap_desc ? mdesc->zmdesc : NULL),
				 addr, length, fence, invalidate, wait);
}

static int zhpe_ext_ep_counters(struct fid_ep *fid_ep,
				struct fi_zhpe_ep_counters *counters)
{
	int			ret = -FI_EINVAL;
	struct zhpe_ep		*zep;
	struct zhpe_ep_attr	*zep_attr;
	struct zhpe_tx_ctx	*tx_ctx;

	if (!fid_ep || !counters ||
	    counters->version != FI_ZHPE_EP_COUNTERS_VERSION ||
	    counters->len != sizeof(*counters))
		goto done;

	switch (fid_ep->fid.fclass) {

	case FI_CLASS_EP:
		zep = fid2zep(&fid_ep->fid);
		tx_ctx = zep->attr->tx_ctx;
		zep_attr = zep->attr;
		break;

	case FI_CLASS_TX_CTX:
		tx_ctx = container_of(fid_ep, struct zhpe_tx_ctx, ctx);
		zep_attr = tx_ctx->ep_attr;
		break;

	default:
		goto done;
	}

	counters->hw_atomics = atm_load_rlx(&zep_attr->counters.hw_atomics);
	ret = 0;
 done:

	return ret;
}

static struct fi_zhpe_ext_ops_v1 zhpe_ext_ops_v1 = {
	.lookup			= zhpe_ext_lookup,
	.mmap			= zhpe_ext_mmap,
	.munmap			= zhpe_ext_munmap,
	.commit			= zhpe_ext_commit,
	.ep_counters		= zhpe_ext_ep_counters,
};

static int zhpe_fabric_ops_open(struct fid *fid, const char *ops_name,
				uint64_t flags, void **ops, void *context)
{
	int			ret = -FI_EINVAL;

	if (!fid || fid->fclass != FI_CLASS_FABRIC ||
	    !ops_name || flags || context)
		goto done;

	if (strcmp(ops_name, FI_ZHPE_OPS_V1))
		goto done;

	*ops = &zhpe_ext_ops_v1;
	ret = 0;
 done:

	return ret;
}

static struct fi_ops zhpe_fab_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = zhpe_fabric_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = zhpe_fabric_ops_open,
};

int zhpe_fabric(struct fi_fabric_attr *attr, struct fid_fabric **fabric,
		void *context)
{
	int			ret = -FI_EINVAL;
	struct zhpe_fabric	*zfab = NULL;

	if (!attr || !fabric)
		goto done;

	ret = -FI_ENOMEM;
	zfab = calloc(1, sizeof(*zfab));
	if (!zfab)
		goto done;

	ret = ofi_fabric_init(&zhpe_prov, &zhpe_fabric_attr, attr,
			      &zfab->util_fabric, context);
	if (ret < 0)
		goto done;

	zfab->util_fabric.fabric_fid.fid.ops = &zhpe_fab_fi_ops;
	zfab->util_fabric.fabric_fid.ops = &zhpe_fab_ops;
	*fabric = &zfab->util_fabric.fabric_fid;
 done:
	if (ret < 0)
		free(zfab);

	return ret;
}

int zhpe_getinfo(uint32_t api_version, const char *node, const char *service,
		 uint64_t flags, const struct fi_info *hints,
		 struct fi_info **info_out)
{
	int			ret = -FI_ENODATA;
	struct fi_info		*info1 = NULL;
	int			rc;
	struct fi_info		*info;

	/*
	 * info is not a chain of infos from other providers, it is
	 * just a variable for us to return our infos in; util_getinfo()
	 * will clobber it.
	 */
	rc = zhpeq_init(ZHPEQ_API_VERSION);
	if (rc < 0) {
		ZHPE_LOG_ERROR("zhpeq_init() returned error:%s\n",
			       strerror(-rc));
		goto done;
	}

	if (!(node ||
	      (!(flags & FI_SOURCE) && hints &&
	       (hints->src_addr || hints->dest_addr)))) {
		flags |= FI_SOURCE;
		if (!service)
			service = "0";
        }

	mutex_lock(&zhpe_fabdom_close_mutex);
	ret = util_getinfo(&zhpe_util_prov, api_version, node, service, flags,
			  hints, info_out);
	mutex_unlock(&zhpe_fabdom_close_mutex);
	if (ret < 0)
		goto done;

	info1 = *info_out;
	if (info1->src_addr)
		zhpe_straddr_dbg(FI_LOG_FABRIC, "src_addr", info1->src_addr);
	if (info1->dest_addr)
		zhpe_straddr_dbg(FI_LOG_FABRIC, "dst_addr", info1->dest_addr);

	/* Fixup return values based on hints. */
	if (!hints) {
		/* Fixup supported modes and default queue size. */
		info1->mode |= ZHPE_EP_MODE_SUPPORTED;
		if (FI_VERSION_LT(api_version, FI_VERSION(1, 5)))
			info1->mode |= FI_LOCAL_MR;
		else
			info1->domain_attr->mr_mode |=
				ZHPE_DOM_MR_MODE_SUPPORTED;
		info1->rx_attr->mode |= ZHPE_EP_MODE_SUPPORTED;
		info1->rx_attr->size = ZHPE_EP_DEF_RX_SZ;
		info1->tx_attr->mode |= ZHPE_EP_MODE_SUPPORTED;
		info1->tx_attr->size = ZHPE_EP_DEF_TX_SZ;
	} else {
		/*
		 * util_getinfo() only preserves required modes; allow
		 * supported modes.
		 */
		info1->mode |= (hints->mode & ZHPE_EP_MODE_SUPPORTED);
		if (FI_VERSION_LT(api_version, FI_VERSION(1, 5)))
			info1->mode |= (hints->mode & FI_LOCAL_MR);
		else if (hints->domain_attr)
			info1->domain_attr->mr_mode |=
				(hints->domain_attr->mr_mode &
				 ZHPE_DOM_MR_MODE_SUPPORTED);
		if (hints->rx_attr) {
			info1->rx_attr->mode |= (hints->rx_attr->mode &
						 ZHPE_EP_MODE_SUPPORTED);
			if (!hints->rx_attr->size)
				info1->rx_attr->size = ZHPE_EP_DEF_RX_SZ;
		}
		if (hints->tx_attr) {
			info1->tx_attr->mode |= (hints->tx_attr->mode &
						 ZHPE_EP_MODE_SUPPORTED);
			if (!hints->tx_attr->size)
				info1->tx_attr->size = ZHPE_EP_DEF_TX_SZ;
		}
	}
	for (info = info1->next; info; info = info->next) {
		info->mode = info1->mode;
		info->domain_attr->mr_mode = info1->domain_attr->mr_mode;
		info->rx_attr->mode = info1->rx_attr->mode;
		info->rx_attr->size = info1->rx_attr->size;
		info->tx_attr->mode = info1->tx_attr->mode;
		info->tx_attr->size = info1->tx_attr->size;
	}
 done:

	return ret;
}

void fi_zhpe_fini(void)
{
}

ZHPE_INI
{
	fi_param_define(&zhpe_prov, "pe_waittime", FI_PARAM_INT,
			"How many milliseconds to spin while waiting"
			" for progress");

	fi_param_define(&zhpe_prov, "max_conn_retry", FI_PARAM_INT,
			"Number of connection retries before reporting"
			" as failure");

	fi_param_define(&zhpe_prov, "def_av_sz", FI_PARAM_INT,
			"Default address vector size");

	fi_param_define(&zhpe_prov, "def_cq_sz", FI_PARAM_INT,
			"Default completion queue size");

	fi_param_define(&zhpe_prov, "def_eq_sz", FI_PARAM_INT,
			"Default event queue size");

	fi_param_define(&zhpe_prov, "pe_affinity", FI_PARAM_STRING,
			"If specified, bind the progress thread to the"
			" indicated range(s) of Linux virtual processor ID(s)."
			" This option is currently not supported on OS X."
			" Usage: id_start[-id_end[:stride]][,]");

	fi_param_define(&zhpe_prov, "ep_max_eager_sz", FI_PARAM_SIZE_T,
			"Maximum size of eager message");

	fi_param_define(&zhpe_prov, "mr_cache_enable", FI_PARAM_BOOL,
			"Enable/disable registration cache");

	fi_param_define(&zhpe_prov, "mr_cache_merge_regions", FI_PARAM_BOOL,
			"Enable/disable merging cache regions");

	fi_param_define(&zhpe_prov, "mr_cache_max_cnt", FI_PARAM_SIZE_T,
			"Maximum number of registrations in cache");

	fi_param_define(&zhpe_prov, "mr_cache_max_size", FI_PARAM_SIZE_T,
			"Maximum total size of cached registrations");

	fi_param_get_int(&zhpe_prov, "pe_waittime", &zhpe_pe_waittime);
	fi_param_get_int(&zhpe_prov, "max_conn_retry", &zhpe_conn_retry);
	fi_param_get_int(&zhpe_prov, "def_av_sz", &zhpe_av_def_sz);
	fi_param_get_int(&zhpe_prov, "def_cq_sz", &zhpe_cq_def_sz);
	fi_param_get_int(&zhpe_prov, "def_eq_sz", &zhpe_eq_def_sz);
	fi_param_get_str(&zhpe_prov, "pe_affinity", &zhpe_pe_affinity_str);
	fi_param_get_size_t(&zhpe_prov, "ep_max_eager_sz",
			    &zhpe_ep_max_eager_sz);
	fi_param_get_bool(&zhpe_prov, "mr_cache_enable", &zhpe_mr_cache_enable);

	return &zhpe_prov;
}
