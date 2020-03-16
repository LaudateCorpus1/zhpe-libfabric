/*
 * Copyright (c) 2014 Intel Corporation, Inc.  All rights reserved.
 * Copyright (c) 2016 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2017-2020 Hewlett Packard Enterprise Development LP.  All rights reserved.
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

#define ZHPE_SUBSYS	FI_LOG_FABRIC

struct zhpeq_attr		zhpeq_attr;

static struct fi_ops_fabric zhpe_fab_ops = {
	.size			= sizeof(struct fi_ops_fabric),
	.domain			= zhpe_domain,
#ifdef NOTYET
	.passive_ep		= zhpe_pep_open,
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
	ret = ofi_fabric_close(&zfab->util_fabric);
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
	if (!url || !sa_len)
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
	zhpeu_install_gcid_in_uuid(sz->sz_uuid, gcid);
	sz->sz_queue = htonl(ZHPE_SZQ_FLAGS_FAM);
	*sa  = sz;
	ret = 0;
 done:
	return ret;
}

static void *mmap_rkey_wait_prep(void *prep_arg)
{
	int			*status_ptr = prep_arg;

	*status_ptr = 1;

	return status_ptr;
}

static void mmap_rkey_wait_handler(void *handler_arg, int status)
{
	int			*status_ptr = handler_arg;

	*status_ptr = status;
}

static int mmap_rkey_lookup(struct fid_ep *fid_ep, fi_addr_t fi_addr,
			    uint64_t key, struct zhpe_rkey **rkey_out)
{
	int			ret = 0;
       	struct zhpe_ctx		*zctx = fid2zctx(&fid_ep->fid);
	struct zhpe_rkey	*rkey = NULL;
	struct zhpe_conn	*conn;

	zctx_lock(zctx);
	conn = zhpe_conn_av_lookup(zctx, fi_addr);
	if (OFI_UNLIKELY(conn->eflags)) {
		ret = zhpe_conn_eflags_error(conn->eflags);
		zctx_unlock(zctx);
		goto done;
	}

	rkey = zhpe_rma_rkey_lookup(conn, key, mmap_rkey_wait_prep,
				    mmap_rkey_wait_handler, &ret);

	while (ret > 0) {
		zctx_unlock(zctx);
		zhpeu_yield();
		zctx_lock(zctx);
	}
	if (ret < 0)
		zhpe_rma_rkey_put(rkey);

 done:
	*rkey_out = rkey;

	return ret;
}

struct fi_zhpe_mmap_desc_private {
	struct fi_zhpe_mmap_desc pub;
	struct zhpeq_mmap_desc  *zmdesc;
	struct zhpe_rkey *rkey;
};

static int zhpe_ext_mmap(void *addr, size_t length, int prot, int flags,
			 off_t offset, struct fid_ep *ep, fi_addr_t fi_addr,
			 uint64_t key, enum fi_zhpe_mmap_cache_mode cache_mode,
			 struct fi_zhpe_mmap_desc **mmap_desc)
{
	int			ret = -FI_EINVAL;
	uint32_t		zq_cache_mode = 0;
	struct fi_zhpe_mmap_desc_private *mdesc = NULL;

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

	mdesc = calloc(1, sizeof(*mdesc));
	if (!mdesc) {
		ret = -FI_ENOMEM;
		goto done;
	}
	mdesc->pub.length = length;

	ret  = mmap_rkey_lookup(ep, fi_addr, key, &mdesc->rkey);
	if (ret < 0)
		goto done;

	ret = zhpeq_mmap(mdesc->rkey->qkdata, zq_cache_mode,
			 addr, length, prot, flags, offset, &mdesc->zmdesc);

 done:
	if (ret >= 0) {
		mdesc->pub.addr = mdesc->zmdesc->addr;
		*mmap_desc = &mdesc->pub;
		ret = 0;
	} else {
		zhpe_rma_rkey_put(mdesc->rkey);
		free(mdesc);
	}

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
	zhpe_rma_rkey_put(mdesc->rkey);
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
	struct zhpe_ctx		*zctx = fid2zctx(&fid_ep->fid);

	if (!fid_ep || !counters ||
	    counters->version != FI_ZHPE_EP_COUNTERS_VERSION ||
	    counters->len != sizeof(*counters))
		goto done;

	zctx_lock(zctx);
	counters->hw_atomics = zctx->hw_atomics;
	zctx_unlock(zctx);
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

static int get_addr(uint32_t *addr_format, uint64_t flags,
		    const char *node, const char *service,
		    void **addr, size_t *addrlen)
{
	int			ret = -FI_EINVAL;
	uint64_t		queue;
	char			*ep;
	struct sockaddr_zhpe	*sz;

	/* ZZZ: Until we have address lookup. */
	if (node && strcmp(node, "localhost"))
		goto done;
	if (service) {
		errno = 0;
		queue = strtoull(service, &ep, 0);
		if (errno) {
			ret = -errno;
			goto done;
		}
		if (*ep || queue >= UINT32_MAX)
			goto done;
	} else
		queue = 0;

	sz = calloc(1, sizeof(*sz));
	if (!sz) {
		ret = -FI_ENOMEM;
		goto done;
	}
	ret = zhpeq_get_src_zaddr(sz, queue, !(flags & FI_SOURCE));
	if (ret < 0) {
		free(sz);
		goto done;
	}
	*addr = sz;
	*addrlen = sizeof(*sz);
	*addr_format = FI_ADDR_ZHPE;
	ret = 0;

 done:
	return ret;
}

static int get_src_addr(uint32_t addr_format,
			const void *dest_addr, size_t dest_addrlen,
			void **src_addr, size_t *src_addrlen)
{
	int			ret = FI_EINVAL;
	struct sockaddr_zhpe	*sz;

	if (addr_format != FI_FORMAT_UNSPEC && addr_format != FI_ADDR_ZHPE)
		goto done;
	if (!zhpe_addr_valid(dest_addr, dest_addrlen))
		goto done;

	sz = calloc(1, sizeof(*sz));
	if (!sz) {
		ret = -FI_ENOMEM;
		goto done;
	}
	ret = zhpeq_get_src_zaddr(sz, 0, false);
	if (ret < 0) {
		free(sz);
		goto done;
	}
	*src_addr = sz;
	*src_addrlen = sizeof(*sz);
	ret = 0;

 done:
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
	 * This routine returns either zero or -FI_ENODATA. Other errors
	 * will be logged, but not returned to the caller.
	 *
	 * NOTE: zhpeq_init() below will only update zhpeq_attr the first time
	 * it is called.
	 */
	rc = zhpeq_init(ZHPEQ_API_VERSION, &zhpeq_attr);
	if (rc < 0) {
		ZHPE_LOG_ERROR("zhpeq_init() error %d:%s\n",
			       rc, fi_strerror(-rc));
		goto done;
	}

	rc = util_getinfo_genaddr(&zhpe_util_prov, api_version, node, service,
				  flags, hints, info_out,
				  get_addr, get_src_addr);
	if (rc < 0) {
		if (rc != -FI_ENODATA)
			ZHPE_LOG_ERROR("util_getinfo() error %d:%s\n",
				       rc, fi_strerror(-rc));
		goto done;
	}

	/*
	 * NOTE: src_addr and dest_addr should be the same across all infos.
	 *
	 * If there are no addrs then, get a src_addr.
	 */
	info1 = *info_out;
	if (!info1->src_addr && !info1->dest_addr) {
		rc = get_addr(&info1->addr_format, FI_SOURCE, NULL, "0",
			      &info1->src_addr, &info1->src_addrlen);
		if (rc < 0) {
			ZHPE_LOG_ERROR("get_addr() error %d:%s\n",
				       rc, fi_strerror(-rc));
			goto done;
		}
		for (info = info1->next; info; info = info->next) {
			info->src_addr = zhpeu_sockaddr_dup(info1->src_addr);
			if (!info->src_addr) {
				rc = -FI_ENOMEM;
				ZHPE_LOG_ERROR("zhpeu_sockaddr_dup() error"
					       " %d:%s\n",
					       rc, fi_strerror(-rc));
				goto done;
			}
			info->addr_format = info1->addr_format;
			info->src_addrlen = info1->src_addrlen;
		}
	}

	if (info1->src_addr)
		_zhpe_straddr_dbg(FI_LOG_FABRIC, "src_addr", info1->src_addr);
	if (info1->dest_addr)
		_zhpe_straddr_dbg(FI_LOG_FABRIC, "dst_addr", info1->dest_addr);

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
	ret = 0;

 done:
	if (ret < 0) {
		if (info1)
			fi_freeinfo(info1);
		*info_out = NULL;
	}

	return ret;
}

void fi_zhpe_fini(void)
{
}

ZHPE_INI
{
	fi_param_define(&zhpe_prov, "def_av_sz", FI_PARAM_INT,
			"Default address vector size");

	fi_param_define(&zhpe_prov, "def_cq_sz", FI_PARAM_INT,
			"Default completion queue size");

	fi_param_define(&zhpe_prov, "def_eq_sz", FI_PARAM_INT,
			"Default event queue size");

	fi_param_define(&zhpe_prov, "ep_rx_poll_timeout", FI_PARAM_INT,
			"RX polling in usec before sleeping");

	fi_param_define(&zhpe_prov, "ep_max_eager_sz", FI_PARAM_SIZE_T,
			"Maximum size of eager message");

	fi_param_define(&zhpe_prov, "mr_cache_enable", FI_PARAM_BOOL,
			"Enable/disable registration cache");

	fi_param_get_int(&zhpe_prov, "def_av_sz", &zhpe_av_def_sz);
	fi_param_get_int(&zhpe_prov, "def_cq_sz", &zhpe_cq_def_sz);
	fi_param_get_int(&zhpe_prov, "def_eq_sz", &zhpe_eq_def_sz);
	fi_param_get_int(&zhpe_prov, "ep_rx_poll_timeout",
			 &zhpe_ep_rx_poll_timeout);
	fi_param_get_size_t(&zhpe_prov, "ep_max_eager_sz",
			    &zhpe_ep_max_eager_sz);
	fi_param_get_bool(&zhpe_prov, "mr_cache_enable", &zhpe_mr_cache_enable);

	return &zhpe_prov;
}
