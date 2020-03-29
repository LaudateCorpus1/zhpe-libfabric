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

#define ZHPE_SUBSYS	FI_LOG_DOMAIN

static void dom_mr_free(struct zhpe_mr *zmr)
{
	struct zhpe_dom		*zdom = zmr->zdom;
	struct zhpeq_key_data	*qkdata = zmr->qkdata;
	int			rc MAYBE_UNUSED;

	/* Must be called with zdom_lock() held. */
	dlist_remove(&zmr->dentry);
	zhpe_buf_free(&zdom->zmr_pool, zmr);
	zdom_unlock(zdom);

	if (OFI_LIKELY(qkdata != NULL)) {
		rc = zdom->qkdata_mr_free(zdom, qkdata);
		assert(!rc);
	}
}

static int zhpe_dom_close(struct fid *fid)

{
	int			ret = -FI_EBUSY;
	struct zhpe_dom		*zdom = fid2zdom(fid);
	struct zhpe_mr		*zmr;
	int			rc;

	if (ofi_atomic_get32(&zdom->util_domain.ref) != 1)
		goto done;
	/*
	 * zdom locking should not be *required* past this point, but
	 * it gets used in some place because it is easier that
	 * arranging non-locking variants.
	 */
	zhpe_pe_fini(zdom->pe);
	ret = 0;
	while (!dlist_empty(&zdom->zmr_list)) {
		zmr = container_of(zdom->zmr_list.next, struct zhpe_mr,
				   dentry);
		dlist_remove(&zmr->dentry);
		assert_always(dlist_empty(&zmr->kexp_list));
		if (OFI_UNLIKELY(zmr->mr_fid.key != FI_KEY_NOTAVAIL) &&
		    !zmr->closed) {
			rc = ofi_mr_map_remove(zdom2map(zdom), zmr->mr_fid.key);
			ret = zhpeu_update_error(ret, rc);
		}
		zdom_lock(zdom);
		dom_mr_free(zmr);
		/* zdom_lock was dropped. */
	}
	free(zdom->reg_page);
	zdom->reg_page = NULL;
	zhpe_dom_mr_cache_destroy(zdom);
	ret = zhpeu_update_error(ret, zhpeq_domain_free(zdom->zqdom));
	zhpe_bufpool_destroy(&zdom->zmr_pool);
	ret = zhpeu_update_error(ret, ofi_domain_close(&zdom->util_domain));
	mutex_destroy(&zdom->kexp_teardown_mutex);
	ofi_rbmap_cleanup(&zdom->kexp_tree);
	free(zdom);

 done:
	return ret;
}

static int zhpe_mr_close(struct fid *fid)
{
	struct zhpe_mr		*zmr = fid2zmr(fid);
	struct zhpe_dom		*zdom = zmr->zdom;
	uint64_t		key = zmr->mr_fid.key;
	struct zhpe_kexp	*kexp;
	struct dlist_entry	*next;
	int			val;
	int			rc MAYBE_UNUSED;

	/*
	 * We have to send the KEY_REVOKE messages and wait for the KEY_RELEASE
	 * response to occur before we can free the actual registration.
	 *
	 * Races are possible and structures are at risk of being deleted
	 * out from under us. Unfortunately, there are also lock inversion
	 * problems since the natural order of locks is ctx-to-dom, but
	 * we are going from dom-to-ctx.
	 *
	 * The kexp_teardown_mutex blocks dom_cleanup() and this blocks
	 * the destruction of the zctx and the conns. We will wait here
	 * for the released flag to be set by either KEY_RELEASE or
	 * SHUTDOWN messages.
	 */
	zdom_lock(zdom);
	zmr->closed = true;
	if (OFI_UNLIKELY(!dlist_empty(&zmr->kexp_list))) {
		zdom_unlock(zdom);

		/* Block ctx cleanup. */
		mutex_lock(&zdom->kexp_teardown_mutex);

		zdom_lock(zdom);
		/* Mark all the entries as revoking. */
		dlist_foreach_container(&zmr->kexp_list, struct zhpe_kexp,
					kexp, dentry) {
			assert_always(!kexp->revoking);
			kexp->revoking = true;
		}
		/*
		 * March through the list sending revokes. We're going to
		 * drop and reacquire the dom lock, so we can acquire the
		 * ctx lock, but the zmr->closed, kexp->revoking, and
		 * kexp_teardown_mutex should keep everything stable.
		 *
		 * So, so, ugly.
		 */
		dlist_foreach_container(&zmr->kexp_list, struct zhpe_kexp,
					kexp, dentry) {
			zdom_unlock(zdom);
			zctx_lock(kexp->conn->zctx);
			zhpe_send_key_revoke(kexp->conn, kexp->tkey.key);
			zctx_unlock(kexp->conn->zctx);
			zdom_lock(zdom);
		}

		/* Allow ctx cleanup. */
		mutex_unlock(&zdom->kexp_teardown_mutex);

		/*
		 * And the ugliness continues:
		 *
		 * So, now we wait for all the KEY_RELEASEs or SHUTDOWNs.
		 * As above, the exerything is kept stable since only we remove
		 * things.
		 *
		 * ZZZ:forever? We need the driver to do more in terms
		 * of cleanup. Perhaps we can add keepalive in the driver
		 * instead of the network.
		 */
		while (!dlist_empty(&zmr->kexp_list)) {
			dlist_foreach_container_safe(&zmr->kexp_list,
						     struct zhpe_kexp,
						     kexp, dentry, next) {
				assert_always(kexp->revoking);
				if (kexp->released) {
					dlist_remove(&kexp->dentry);
					free(kexp);
					continue;
				}
				/* Do progress. */
				zdom_unlock(zdom);
				/*
				 * May acquire and drop zctx_lock();
				 * may also yield the core.
				 */
				zhpe_ctx_cleanup_progress(kexp->conn->zctx,
							  false);
				zdom_lock(zdom);
			}
		}
	} else {
		if (OFI_UNLIKELY(key != FI_KEY_NOTAVAIL)) {
			rc = ofi_mr_map_remove(zdom2map(zdom), key);
			assert(!rc);
		}
	}

	val = ofi_atomic_dec32(&zmr->ref);
	assert_always(val >= 0);
	if (OFI_LIKELY(!val)) {
		/* Lock will be dropped. */
		dom_mr_free(zmr);
	} else
		zdom_unlock(zdom);

	return 0;
}

static struct fi_ops mr_fi_ops = {
	.size			= sizeof(struct fi_ops),
	.close			= zhpe_mr_close,
	.bind			= fi_no_bind,
	.control		= fi_no_control,
	.ops_open		= fi_no_ops_open,
};

void zhpe_dom_mr_free(struct zhpe_mr *zmr)
{
	struct zhpe_dom		*zdom = zmr->zdom;

	assert_always(zmr->mr_fid.key == FI_KEY_NOTAVAIL || zmr->closed);

	zdom_lock(zdom);
	dom_mr_free(zmr);
	/* zdom_lock was dropped. */
}

struct dom_cleanup_data {
	void			*filter_data;
	bool			(*filter)(struct dom_cleanup_data *clean,
					  struct ofi_rbnode *rbnode);
};

static bool dom_cleanup_filter_ctx(struct dom_cleanup_data *cleanup,
				   struct ofi_rbnode *rbnode)
{
	struct zhpe_kexp	*kcur = rbnode->data;

	if ((void *)kcur->conn->zctx != cleanup->filter_data)
		return false;

	/*
	 * We abort because there is nothing we can do to protect
	 * ourselves at this point and we need the driver to do
	 * its cleanup.
	 */
	if (OFI_UNLIKELY((kcur->conn->eflags & ZHPE_CONN_EFLAG_SHUTDOWN3) !=
			 ZHPE_CONN_EFLAG_SHUTDOWN3))
		abort();

	return true;
}

static bool dom_cleanup_filter_conn(struct dom_cleanup_data *cleanup,
				    struct ofi_rbnode *rbnode)
{
	struct zhpe_kexp	*kcur = rbnode->data;

	return ((void *)kcur->conn == cleanup->filter_data);
}

static void dom_cleanup_walk(struct ofi_rbmap *map, void *handler_arg,
			     struct ofi_rbnode *rbnode)
{
	struct dom_cleanup_data	*cleanup = handler_arg;
	struct zhpe_kexp	*kcur;

	if (!cleanup->filter(cleanup, rbnode))
		return;
	kcur = rbnode->data;
	ofi_rbmap_delete(map, rbnode);
	if (kcur->revoking)
		kcur->released = true;
	else {
		dlist_remove(&kcur->dentry);
		free(kcur);
	}
}

static void dom_cleanup(struct zhpe_dom *zdom, void *filter_data,
			bool (*filter)(struct dom_cleanup_data *cleanup,
				       struct ofi_rbnode *rbnode))
{
	struct dom_cleanup_data cleanup = {
		.filter_data	= filter_data,
		.filter		= filter,
	};

 	zdom_lock(zdom);
	ofi_rbmap_walk(&zdom->kexp_tree, &cleanup, dom_cleanup_walk);
	zdom_unlock(zdom);
}

void zhpe_dom_cleanup_ctx(struct zhpe_ctx *zctx)
{
	struct zhpe_dom		*zdom = zctx2zdom(zctx);

	/* Block races with zhpe_mr_close. */
	mutex_lock(&zdom->kexp_teardown_mutex);

	dom_cleanup(zdom, zctx, dom_cleanup_filter_ctx);

	mutex_unlock(&zdom->kexp_teardown_mutex);
}

void zhpe_dom_cleanup_conn(struct zhpe_conn *conn)
{
	struct zhpe_dom		*zdom = zctx2zdom(conn->zctx);

	dom_cleanup(zdom, conn, dom_cleanup_filter_conn);
}

void zhpe_dom_key_release(struct zhpe_conn *conn, uint64_t key)
{
	struct zhpe_dom		*zdom = zctx2zdom(conn->zctx);
	struct zhpe_mem_tree_key tkey = {
		.rem_gcid	= conn->tkey.rem_gcid,
		.rem_rspctxid	= conn->rem_rspctxid,
		.key		= key,
	};
	struct ofi_rbnode	*rbnode;
	struct zhpe_kexp	*kexp;

	/*
	 * This should only occur in response to a revoke, so the entry
	 * must exist.
	 */
 	zdom_lock(zdom);
	rbnode = ofi_rbmap_find(&zdom->kexp_tree, &tkey);
	assert_always(rbnode);
	kexp = rbnode->data;
	ofi_rbmap_delete(&zdom->kexp_tree, rbnode);
	assert_always(kexp->revoking);
	kexp->released = true;
 	zdom_unlock(zdom);
}

void zhpe_dom_key_export(struct zhpe_conn *conn, uint64_t key)
{
	struct zhpe_ctx		*zctx = conn->zctx;
	struct zhpe_dom		*zdom = zctx2zdom(zctx);
	struct zhpe_kexp	*kexp;
	int			rc;
	char			blob[ZHPEQ_MAX_KEY_BLOB];
	size_t			blob_len;
	struct ofi_rbnode	*rbnode;
	struct fi_mr_attr	*attr;

	/*
	 * zctx_lock() should be held.
	 * The rkey tree on the sender and message sequencing should
	 * guarantee that no entry exists, but the key may be gone.
	 */
	kexp = xmalloc(sizeof(*kexp));
	kexp->tkey.rem_gcid = conn->tkey.rem_gcid,
	kexp->tkey.rem_rspctxid	= conn->rem_rspctxid,
	kexp->tkey.key = key;
	kexp->conn = conn;
	dlist_init(&kexp->dentry);
	kexp->revoking = false;
	kexp->released = false;

	rbnode = ofi_rbmap_find(zdom2map(zdom)->rbtree, &key);
	if (OFI_LIKELY(rbnode != NULL)) {
		attr = rbnode->data;
		kexp->zmr = attr->context;
		assert_always((uintptr_t)attr->mr_iov[0].iov_base ==
			      kexp->zmr->qkdata->z.vaddr);
		if (OFI_LIKELY(!kexp->zmr->closed)) {
			rc = ofi_rbmap_insert(&zdom->kexp_tree, &kexp->tkey,
					      kexp, NULL);
			assert_always(!rc);
			dlist_insert_tail(&kexp->dentry, &kexp->zmr->kexp_list);
			blob_len = sizeof(blob);
			rc = zhpeq_qkdata_export(kexp->zmr->qkdata,
						 kexp->zmr->qaccess,
						 blob, &blob_len);
			assert_always(!rc);
			zhpe_send_key_response(conn, key, blob, blob_len);
			return;
		}
	}

	/* No key. */
	free(kexp);
	zhpe_send_key_response(conn, key, NULL, 0);
}

int zhpe_dom_mr_reg(struct zhpe_dom *zdom, const void *buf, size_t len,
		    uint32_t qaccess, bool link, struct zhpe_mr **zmr_out)
{
	int			ret = -FI_ENOMEM;
	struct zhpe_mr		*zmr;

	zmr = zhpe_buf_alloc(&zdom->zmr_pool);
	if (OFI_UNLIKELY(!zmr))
		goto done;

	zmr->mr_fid.fid.fclass = FI_CLASS_MR;
	zmr->mr_fid.fid.context = NULL;
	zmr->mr_fid.fid.ops = &mr_fi_ops;
	zmr->mr_fid.mem_desc = zmr;
	zmr->mr_fid.key = FI_KEY_NOTAVAIL;
	zmr->zdom = zdom;
	zmr->qkdata = NULL;
	dlist_init(&zmr->kexp_list);
	dlist_init(&zmr->dentry);
	zmr->qaccess = qaccess;
	ofi_atomic_initialize32(&zmr->ref, 1);

	ret = zdom->qkdata_mr_reg(zdom, buf, len, qaccess, &zmr->qkdata);
	ZHPE_LOG_DBG("dom %p buf %p len 0x%lx qa 0x%x ret %d\n",
		     zdom, buf, len, qaccess, ret);
	if (ret < 0) {
		ZHPE_LOG_ERROR("Failed to register memory %p-%p qa 0x%x,"
			       " error %d:%s\n", buf, VPTR(buf, len - 1),
			       qaccess, ret, fi_strerror(-ret));
		goto done;
	}
	/* Optimize caching case. */
	if (OFI_LIKELY(link)) {
		zdom_lock(zdom);
		dlist_insert_tail(&zmr->dentry, &zdom->zmr_list);
		zdom_unlock(zdom);
	}

 done:
	if (ret < 0) {
		zhpe_dom_mr_put(zmr);
		zmr = NULL;
	}
	*zmr_out = zmr;

	return ret;
}

static int zhpe_regattr(struct fid *fid, const struct fi_mr_attr *attr,
			uint64_t flags, struct fid_mr **fid_mr_out)
{
	int			ret = -FI_EINVAL;
	struct zhpe_mr		*zmr = NULL;
	struct zhpe_dom		*zdom;
	uint64_t		key;
	struct fi_eq_entry	eq_entry;

	if (!fid_mr_out)
		goto done;
	*fid_mr_out = NULL;
	if (!fid || fid->fclass != FI_CLASS_DOMAIN ||
	    !attr || !attr->mr_iov || attr->iov_count != 1 ||
	    (attr->access & ~(FI_SEND | FI_RECV | FI_READ | FI_WRITE |
			      FI_REMOTE_READ | FI_REMOTE_WRITE)) ||
	    flags)
		goto done;

	zdom = fid2zdom(fid);

	ret = zhpe_dom_mr_reg(zdom, attr->mr_iov[0].iov_base,
			      attr->mr_iov[0].iov_len,
			      access2qaccess(attr->access), false, &zmr);
	if (ret < 0)
		goto done;
	zdom_lock(zdom);
	ret = ofi_mr_map_insert(zdom2map(zdom), attr, &key, zmr);
	dlist_insert_tail(&zmr->dentry, &zdom->zmr_list);
	zdom_unlock(zdom);
	if (ret < 0)
		goto done;
	zmr->mr_fid.fid.context = attr->context;
	zmr->mr_fid.key = key;

	if (zdom->mr_events) {
		eq_entry.context = attr->context;
		eq_entry.fid = &zdom->util_domain.domain_fid.fid;
		ret = zhpe_eq_report_event(zdom->util_domain.eq,
					   FI_MR_COMPLETE, &eq_entry,
					   sizeof(eq_entry));
		if (ret < 0)
			goto done;
	}
	*fid_mr_out = &zmr->mr_fid;
	ret = 0;

 done:
	if (ret < 0)
		zhpe_dom_mr_put(zmr);

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
	struct zhpe_dom		*zdom;
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
	.endpoint		= zhpe_ep_open,
	.scalable_ep		= zhpe_sep_open,
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

static int zhpe_mr_reg_uncached(struct zhpe_dom *zdom, const void *buf,
				size_t len, uint32_t qaccess,
				struct zhpeq_key_data **qkdata_out)
{
	return zhpeq_mr_reg(zdom->zqdom, buf, len, qaccess, qkdata_out);
}

static int zhpe_mr_free_uncached(struct zhpe_dom *zhpe,
				  struct zhpeq_key_data *qkdata)
{
	return zhpeq_qkdata_free(qkdata);
}

int zhpe_domain(struct fid_fabric *fid_fabric, struct fi_info *info,
		struct fid_domain **fid_domain, void *context)
{
	int			ret = -FI_EINVAL;
	struct zhpe_dom		*zdom = NULL;
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
	dlist_init(&zdom->zmr_list);
	ofi_rbmap_init(&zdom->kexp_tree, zhpe_compare_mem_tkeys);
	mutex_init(&zdom->kexp_teardown_mutex, NULL);

	ret = ofi_domain_init(&zfab->util_fabric.fabric_fid, info,
			      &zdom->util_domain, context);

	if (zdom->util_domain.data_progress == FI_PROGRESS_AUTO)
		zdom->util_domain.threading = FI_THREAD_SAFE;

	if (ret < 0) {
		free(zdom);
		zdom = NULL;
		goto done;
	}

	/* Fixups. */
	zdom->util_domain.threading = FI_THREAD_SAFE;
	if (zdom->util_domain.mr_mode == FI_MR_BASIC)
		zdom->util_domain.mr_mode = OFI_MR_BASIC_MAP;

	ret = zhpe_bufpool_create(&zdom->zmr_pool, "zmr_pool",
				  sizeof(struct zhpe_mr),
				  zhpeu_init_time->l1sz, 0, 0, 0, NULL, NULL);
	if (ret < 0)
		goto done;

	zdom->qkdata_mr_reg = zhpe_mr_reg_uncached;
	zdom->qkdata_mr_free = zhpe_mr_free_uncached;

	ret = zhpe_dom_mr_cache_init(zdom);
	if (ret < 0)
		goto done;

	ret = zhpeq_domain_alloc(&zdom->zqdom);
	if (ret < 0)
		goto done;

	zdom->reg_page = xmalloc_aligned(page_size, page_size);
	ret = zhpe_dom_mr_reg(zdom, zdom->reg_page, page_size,
			      access2qaccess(ZHPE_MR_ACCESS_ALL), true,
			      &zdom->reg_zmr);
	if (ret < 0)
		goto done;

	zdom->pe = zhpe_pe_init(zdom);
	if (!zdom->pe) {
		ret = -FI_ENOMEM;
		goto done;
	}

	*fid_domain = &zdom->util_domain.domain_fid;
	zdom->util_domain.domain_fid.fid.ops = &zhpe_dom_fi_ops;
	zdom->util_domain.domain_fid.ops = &zhpe_dom_ops;
	zdom->util_domain.domain_fid.mr = &zhpe_dom_mr_ops;

 done:
	if (ret < 0 && zdom)
		zhpe_dom_close(&zdom->util_domain.domain_fid.fid);

       return ret;
}
