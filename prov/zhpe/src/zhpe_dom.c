/*
 * Copyright (c) 2014 Intel Corporation, Inc.  All rights reserved.
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

#define ZHPE_LOG_DBG(...) _ZHPE_LOG_DBG(FI_LOG_DOMAIN, __VA_ARGS__)
#define ZHPE_LOG_ERROR(...) _ZHPE_LOG_ERROR(FI_LOG_DOMAIN, __VA_ARGS__)

static int zhpe_dom_close(struct fid *fid)
{
	int			ret = -FI_EBUSY;
	struct zhpe_domain	*zdom = fid2zdom(fid);
	RbtIterator		*rbt;
	struct zhpe_mr		*zmr;

	if (ofi_atomic_get32(&zdom->util_domain.ref) != 1)
		goto done;

	if (zdom->cache_inited)
		zhpe_mr_cache_destroy(zdom);

	if (zdom->mr_tree) {
		/*
		 * Only uncached entries should remain in the tree and
		 * we should be the only thread has a reference.
		 */
		while ((rbt  = rbtBegin(zdom->mr_tree))) {
			zmr = zhpe_rbtKeyValue(zdom->mr_tree, rbt);
			assert(!zmr->entry);
			zmr->use_count = 1;
			zhpe_mr_put(zmr);
		}
		rbtDelete(zdom->mr_tree);
	}

	mutex_lock(&zhpe_fabdom_close_mutex);
	ret = ofi_domain_close(&zdom->util_domain);
	mutex_unlock(&zhpe_fabdom_close_mutex);
	if (ret < 0)
		goto done;

	if (zdom->pe)
		zhpe_pe_finalize(zdom->pe);
	if (zdom->zqdom)
		zhpeq_domain_free(zdom->zqdom);
	free(zdom);
 done:

	return ret;
}

static void zhpe_zmr_get_uncached(struct zhpe_mr *zmr)
{
	uint32_t		old MAYBE_UNUSED;

	assert(!zmr->entry);
	old = atm_inc(&zmr->use_count);
	assert(old > 0);
}

int zhpe_zmr_put_uncached(struct zhpe_mr *zmr)
{
	int			ret = 0;
	struct zhpe_domain	*zdom;
	RbtIterator		*rbt;
	struct zhpe_kexp_data	*kexp;
	int32_t			old;

	if (!zmr)
		goto done;

	assert(!zmr->entry);

	zdom = zmr->zdom;

	old = atm_dec(&zmr->use_count);
	assert(old > 0);
	if (old > 1)
		goto done;

	fastlock_acquire(zdom->mr_lock);
	rbt = zhpe_zkey_rbtFind(zdom->mr_tree, &zmr->zkey);
	if (rbt)
		rbtErase(zdom->mr_tree, rbt);
	fastlock_release(zdom->mr_lock);
	while (!dlist_empty(&zmr->kexp_list)) {
		dlist_pop_front(&zmr->kexp_list, struct zhpe_kexp_data,
				kexp, lentry);
		/* FIXME:race with conn going away? */
		mutex_lock(&kexp->conn->ztx->mutex);
		rbt = zhpe_zkey_rbtFind(kexp->conn->kexp_tree, &zmr->zkey);
		if (rbt)
			rbtErase(kexp->conn->kexp_tree, rbt);
		mutex_unlock(&kexp->conn->ztx->mutex);
		zhpe_send_key_revoke(kexp->conn, &zmr->zkey);
		free(kexp);
	}
	zhpeq_qkdata_free(zmr->kdata);
	free(zmr);
 done:

	return ret;
}

int zhpe_mr_close(struct fid *fid)
{
	return zhpe_mr_put(fid2zmr(fid));
}

static struct zhpe_mr_ops zmr_ops_uncached = {
	.fi_ops = {
		.size		= sizeof(struct fi_ops),
		.close		= zhpe_mr_close,
		.bind		= fi_no_bind,
		.control	= fi_no_control,
		.ops_open	= fi_no_ops_open,
	},
	.get			= zhpe_zmr_get_uncached,
	.put			= zhpe_zmr_put_uncached,
};

struct zhpe_mr *zhpe_mr_find(struct zhpe_domain *zdom,
			     const struct zhpe_key *zkey)
{
	struct zhpe_mr		*ret = NULL;
	RbtIterator		*rbt;

	fastlock_acquire(zdom->mr_lock);
	rbt = zhpe_zkey_rbtFind(zdom->mr_tree, zkey);
	if (rbt) {
		ret = zhpe_rbtKeyValue(zdom->mr_tree, rbt);
		zhpe_mr_get(ret);
	}
	fastlock_release(zdom->mr_lock);

	return ret;
}

int zhpe_zmr_reg(struct zhpe_domain *zdom, const void *buf,
		 size_t len, uint32_t qaccess, uint64_t key,
		 struct zhpe_mr *zmr, struct zhpe_mr_ops *ops)
{
	int			ret = 0;
	RbtIterator		*rbt;

	dlist_init(&zmr->kexp_list);
	zmr->mr_fid.fid.fclass = FI_CLASS_MR;
	zmr->mr_fid.fid.ops = &ops->fi_ops;
	zmr->mr_fid.mem_desc = zmr;
	zmr->mr_fid.key = key;
	zmr->zdom = zdom;
	zmr->flags = 0;
	zmr->use_count = 1;
	zmr->zkey.key = key;
	zmr->zkey.internal = !!(qaccess & ZHPE_MR_KEY_INT);

	ret = zhpeq_mr_reg(zdom->zqdom, buf, len, qaccess, &zmr->kdata);
	ZHPE_LOG_DBG("dom %p buf %p len 0x%lx qa 0x%x key 0x%lx/%d ret %d\n",
		     zdom, buf, len, qaccess, key, zmr->zkey.internal, ret);
	if (ret < 0) {
		ZHPE_LOG_ERROR("Failed to register memory 0x%lx-0x%lx,"
			       " error %d:%s\n",
			       (uintptr_t)buf, (uintptr_t)buf + len - 1,
			       ret, fi_strerror(-ret));
		goto done;
	}

	fastlock_acquire(zdom->mr_lock);
	rbt = zhpe_zkey_rbtFind(zdom->mr_tree, &zmr->zkey);
	if (rbt)
		ret = -FI_ENOKEY;
	else
		zhpe_zmr_rbtInsert(zdom->mr_tree, zmr);
	fastlock_release(zdom->mr_lock);
	if (OFI_UNLIKELY(ret < 0)) {
		zhpeq_qkdata_free(zmr->kdata);
		zmr->kdata = NULL;
		goto done;
	}

 done:
	return ret;
}

int zhpe_mr_reg_int_uncached(struct zhpe_domain *zdom, const void *buf,
			     size_t len, uint64_t access, uint32_t qaccess,
			     struct fid_mr **fid_mr)
{
	int			ret;
	struct zhpe_mr		*zmr;

	*fid_mr = NULL;
	zmr = malloc(sizeof(*zmr));
	if (!zmr)
		return -FI_ENOMEM;
	zmr->entry = NULL;
	qaccess |= ZHPE_MR_KEY_INT | zhpe_convert_access(access);

	ret = zhpe_zmr_reg(zdom, buf, len, qaccess, atm_inc(&zdom->mr_zhpe_key),
			   zmr, &zmr_ops_uncached);
	if (ret < 0) {
		free(zmr);
		goto done;
	}
	*fid_mr = &zmr->mr_fid;
 done:

	return ret;
}

int zhpe_mr_reg_int_iov(struct zhpe_domain *zdom,
			struct zhpe_iov_state *lstate)
{
	int			ret = 0;
	struct zhpe_iov		*liov = lstate->viov;
	uint8_t			missing = lstate->missing;
 	int			i;
	struct fid_mr		*fid_mr;
	struct zhpe_mr		*zmr;

        for (i = ffs(missing) - 1; i >= 0;
	     (missing &= ~(1U << i), i = ffs(missing) - 1)) {
		zmr = liov[i].iov_desc;
		if (zmr)
			continue;
		ret = zdom->reg_int(zdom, liov[i].iov_base, liov[i].iov_len,
				      ZHPE_MR_ACCESS_ALL, 0, &fid_mr);
		if (ret < 0)
			break;
		liov[i].iov_len |= ZHPE_ZIOV_LEN_KEY_INT;
		zmr = fid2zmr(&fid_mr->fid);
		liov[i].iov_desc = zmr;
		ret = zhpeq_lcl_key_access(zmr->kdata, liov[i].iov_base, 0, 0,
					   &liov[i].iov_zaddr);
		if (ret < 0)
			break;
	}

	return ret;
}

static int zhpe_regattr(struct fid *fid, const struct fi_mr_attr *attr,
			uint64_t flags, struct fid_mr **mr_fid)
{
	int			ret = -FI_EINVAL;
	uint32_t		qaccess = 0;
	struct zhpe_mr		*zmr = NULL;
	struct zhpe_domain	*zdom;
	uint64_t		key;
	struct fi_eq_entry	eq_entry;

	if (!mr_fid)
		goto done;
	*mr_fid = NULL;
	if (!fid || fid->fclass != FI_CLASS_DOMAIN ||
	    !attr || !attr->mr_iov || attr->iov_count != 1 ||
	    (attr->access & ~(FI_SEND | FI_RECV | FI_READ | FI_WRITE |
			      FI_REMOTE_READ | FI_REMOTE_WRITE)) ||
	    flags)
		goto done;

	zdom = fid2zdom(fid);

	zmr = malloc(sizeof(*zmr));
	if (!zmr) {
		ret = -FI_ENOMEM;
		goto done;
	}
	zmr->entry = NULL;

	key = attr->requested_key;
	if (zdom->util_domain.mr_mode & FI_MR_PROV_KEY)
		key = atm_inc(&zdom->mr_user_key);
	if (!(zdom->util_domain.mr_mode & FI_MR_VIRT_ADDR))
		qaccess |= ZHPEQ_MR_KEY_ZERO_OFF;
	qaccess |= zhpe_convert_access(attr->access);

	ret = zhpe_zmr_reg(zdom, attr->mr_iov[0].iov_base,
			   attr->mr_iov[0].iov_len, qaccess, key,
			   zmr, &zmr_ops_uncached);
	if (ret < 0) {
		free(zmr);
		zmr = NULL;
		goto done;
	}
	if (zdom->mr_events) {
		zmr->mr_fid.fid.context = attr->context;
		eq_entry.context = attr->context;
		eq_entry.fid = &zdom->util_domain.domain_fid.fid;
		ret = zhpe_eq_report_event(zdom->util_domain.eq,
					   FI_MR_COMPLETE, &eq_entry,
					   sizeof(eq_entry));
		if (ret < 0)
			goto done;
	}
	*mr_fid = &zmr->mr_fid;
 done:
	if (ret < 0)
		zhpe_mr_put(zmr);

	return ret;
}

static int zhpe_regv(struct fid *fid, const struct iovec *iov,
		     size_t count, uint64_t access,
		     uint64_t offset, uint64_t requested_key,
		     uint64_t flags, struct fid_mr **fid_mr, void *context)
{
	struct fi_mr_attr	attr = {
		attr.mr_iov	= iov,
		attr.iov_count	= count,
		attr.access	= access,
		attr.offset	= offset,
		attr.requested_key = requested_key,
		attr.context	= context,
	};

	return zhpe_regattr(fid, &attr, flags, fid_mr);
}

static int zhpe_reg(struct fid *fid, const void *buf, size_t len,
		    uint64_t access, uint64_t offset, uint64_t requested_key,
		    uint64_t flags, struct fid_mr **fid_mr, void *context)
{
	struct iovec		iov = {
		iov.iov_base	= (void *)buf,
		iov.iov_len	= len,
	};

	return zhpe_regv(fid, &iov, 1, access,  offset, requested_key,
			 flags, fid_mr, context);
}

static int zhpe_dom_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{
	int			ret = -FI_EINVAL;
	struct zhpe_domain	*zdom;
	struct util_eq		*eq;

	if (!bfid || bfid->fclass != FI_CLASS_EQ || (flags & ~FI_REG_MR))
		goto done;

	zdom = fid2zdom(fid);
	eq = &fid2zeq(bfid)->util_eq;

	ret = ofi_domain_bind_eq(&zdom->util_domain, eq);
	if (ret < 0)
		goto done;

	if (flags & FI_REG_MR)
		zdom->mr_events = true;
 done:

	return ret;
}

static int do_endpoint(struct fid_domain *fid_domain, struct fi_info *info,
		       struct fid_ep **fid_ep, void *context, size_t fclass)
{
	int			ret = -FI_EINVAL;
	struct fi_info		*prov_info;
	struct zhpe_domain	*zdom;
	struct zhpe_ep		*zep;

	if (!fid_ep)
		goto done;
	*fid_ep = NULL;
	if (!fid_domain || !info || !info->ep_attr)
		goto done;

	switch (info->ep_attr->type) {

	case FI_EP_RDM:
		prov_info = &zhpe_info_rdm;
		break;

	case FI_EP_MSG:
		prov_info = &zhpe_info_msg;
		break;

	default:
		ret = -FI_ENOPROTOOPT;
		goto done;
	}

	zdom = fid2zdom(&fid_domain->fid);
	ret = ofi_check_ep_attr(&zhpe_util_prov,
				zfab_api_version(zdom2zfab(zdom)),
				prov_info, info);
	if (ret < 0)
		goto done;
	ret = zhpe_alloc_endpoint(zdom, prov_info, info, &zep, context, fclass);
	if (ret < 0)
		goto done;

	*fid_ep = &zep->ep;
 done:

	return ret;
}

static int zhpe_endpoint(struct fid_domain *fid_domain, struct fi_info *info,
			 struct fid_ep **sep, void *context)
{
	return do_endpoint(fid_domain, info, sep, context, FI_CLASS_EP);
}

static int zhpe_scalable_ep(struct fid_domain *fid_domain, struct fi_info *info,
			    struct fid_ep **sep, void *context)
{
	/* FIXME: Scalable EP */
	return -FI_ENOSYS;
#ifdef NOTYET
	return do_endpoint(fid_domain, info, sep, context, FI_CLASS_SEP);
#endif
}

static struct fi_ops zhpe_dom_fi_ops = {
	.size			= sizeof(struct fi_ops),
	.close			= zhpe_dom_close,
	.bind			= zhpe_dom_bind,
	.control		= fi_no_control,
	.ops_open		= fi_no_ops_open,
};

static struct fi_ops_domain zhpe_dom_ops = {
	.size			= sizeof(struct fi_ops_domain),
	.av_open		= zhpe_av_open,
	.cq_open		= zhpe_cq_open,
	.endpoint		= zhpe_endpoint,
	.scalable_ep		= zhpe_scalable_ep,
	.cntr_open		= zhpe_cntr_open,
	.poll_open		= fi_poll_create,
	.stx_ctx		= fi_no_stx_context,
	.srx_ctx		= fi_no_srx_context,
	.query_atomic		= zhpe_query_atomic,
};

static struct fi_ops_mr zhpe_dom_mr_ops = {
	.size			= sizeof(struct fi_ops_mr),
	.reg			= zhpe_reg,
	.regv			= zhpe_regv,
	.regattr		= zhpe_regattr,
};

int zhpe_domain(struct fid_fabric *fid_fabric, struct fi_info *info,
		struct fid_domain **fid_domain, void *context)
{
	int			ret = -FI_EINVAL;
	struct zhpe_domain	*zdom = NULL;
	struct zhpe_fabric	*zfab;

	if (!fid_domain)
		goto done;
	*fid_domain = NULL;
	if (!fid_fabric || !info || !info->domain_attr)
		goto done;

	zfab = fid2zfab(&fid_fabric->fid);

	ret = ofi_check_domain_attr(&zhpe_prov, zfab_api_version(zfab),
				    &zhpe_domain_attr, info);
	if (ret < 0) {
		free(zdom);
		goto done;
	}

	ret = -FI_ENOMEM;
	zdom = calloc_cachealigned(1, sizeof(*zdom));
	if (!zdom)
		goto done;

	ret = ofi_domain_init(&zfab->util_fabric.fabric_fid, info,
			      &zdom->util_domain, context);

	if (zdom->util_domain.data_progress == FI_PROGRESS_AUTO)
		zdom->util_domain.threading = FI_THREAD_SAFE;

	if (ret < 0) {
		free(zdom);
		zdom = NULL;
		goto done;
	}
	zdom->mr_lock = &zdom->util_domain.lock;

	if (zdom->util_domain.mr_mode == FI_MR_BASIC)
		zdom->util_domain.mr_mode = OFI_MR_BASIC_MAP;

	ret = -FI_ENOMEM;
	zdom->pe = zhpe_pe_init(zdom);
	if (!zdom->pe)
		goto done;

	zdom->mr_tree = rbtNew(zhpe_compare_zkeys);
	if (!zdom->mr_tree)
		goto done;

	zdom->reg_int = zhpe_mr_reg_int_uncached;

	ret = zhpe_mr_cache_init(zdom);
	if (ret < 0)
		goto done;

	ret = zhpeq_domain_alloc(&zdom->zqdom);
	if (ret < 0)
		goto done;

	*fid_domain = &zdom->util_domain.domain_fid;
	zdom->util_domain.domain_fid.fid.ops = &zhpe_dom_fi_ops;
	zdom->util_domain.domain_fid.ops = &zhpe_dom_ops;
	zdom->util_domain.domain_fid.mr = &zhpe_dom_mr_ops;
 done:
	if (ret < 0 && zdom)
		zhpe_dom_close(&zdom->util_domain.domain_fid.fid);

       return ret;
}
