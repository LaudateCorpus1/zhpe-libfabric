/*
 * Copyright (c) 2013-2014 Intel Corporation. All rights reserved.
 * Copyright (c) 2016 Cisco Systems, Inc. All rights reserved.
 * Copyright (c) 2017-2020 Hewlett Packard Enterprise Development LP.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenFabrics.org BSD license below:
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

#define ZHPE_SUBSYS	FI_LOG_EP_CTRL

/* Assumptions. */
static_assert(offsetof(struct util_ep, ep_fid.fid) == 0, "ep_fid");

static void set_fid_ep(struct zhpe_ep *zep, struct fid_ep *fid_ep,
		       size_t fclass, void *context);

static pthread_mutex_t	shutdown_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t	shutdown_cond = PTHREAD_COND_INITIALIZER;

static void rkey_cleanup_walk(struct ofi_rbmap *map, void *handler_arg,
			      struct ofi_rbnode *rbnode)
{
	struct zhpe_rkey	*rkey = rbnode->data;

	zhpe_rma_rkey_free(rkey);
}

static size_t shutdown_check(struct zhpe_ctx *zctx, size_t idx)
{
	struct zhpe_conn	*conn;

	/* zhpe_ctx() must be locked. */
	for (; idx < zctx->conn_pool.max_index; idx++) {
		conn = zhpe_ibuf_get(&zctx->conn_pool, idx);
		if (!conn)
			continue;
		if (OFI_UNLIKELY((conn->eflags & ZHPE_CONN_EFLAG_SHUTDOWN3) !=
				 ZHPE_CONN_EFLAG_SHUTDOWN3))
			break;
		if (OFI_UNLIKELY(conn->tx_queued))
			break;
		if (OFI_UNLIKELY(conn->rx_zseq.rx_oos_list != NULL))
			break;
		if (OFI_UNLIKELY(!dlist_empty(&zctx->rx_work_list)))
			break;
	}

	return idx;
}

static int do_shutdown(struct zhpe_ctx *zctx)
{
	int			ret = -FI_EBUSY;
	size_t			i;
	struct zhpe_conn        *conn;
	time_t			start;

	/* Send a shutdown on every connection. */
	zctx_lock(zctx);
	for (i = 1; i < zctx->conn_pool.max_index; i++) {
		if (i % 0x1F == 0) {
			/*
			 * May drop and reacquire zctx_lock() or
			 * yield the core.
			 */
			zhpe_ctx_cleanup_progress(zctx, true);
		}
		conn = zhpe_ibuf_get(&zctx->conn_pool, i);
		if (!conn)
			continue;
		conn->eflags |= ZHPE_CONN_EFLAG_SHUTDOWN1;
		if (conn->eflags & ~ZHPE_CONN_EFLAG_SHUTDOWN1)
			continue;
		zhpe_msg_prov_no_eflags(conn, ZHPE_OP_SHUTDOWN, NULL, 0, 0,
					conn->tx_seq++);
	}
	/* Poll for shutdown completion. */
	start = time(NULL);
	for (;;) {
		i = shutdown_check(zctx, i);
		if (i >= zctx->conn_pool.max_index && !zctx->tx_queued) {
			ret = 0;
			break;
		}
		if (time(NULL) - start > 30)
			break;
		/* May drop and reacquire zctx_lock() or yield the core. */
		zhpe_ctx_cleanup_progress(zctx, true);
	}
	ofi_rbmap_walk(&zctx->rkey_tree, NULL, rkey_cleanup_walk);
	zctx_unlock(zctx);
	/*
	 * We need to clean up the key export structures for this context.
	 * If the orderly shutdown failed for any connection with an
	 * exported key, then this check will abort the process.
	 */
	zhpe_dom_cleanup_ctx(zctx);
	/* Free any imported rkeys, as well. */

	return ret;
}

static int zhpe_ctx_shutdown(struct zhpe_ctx *zctx)
{
	int			ret = 0;

	mutex_lock(&shutdown_mutex);
	if (zctx->shutdown == ZHPE_CTX_SHUTDOWN_UP) {
		zctx_lock(zctx);
		zctx->shutdown = ZHPE_CTX_SHUTDOWN_IN_PROGRESS;
		zctx_unlock(zctx);
		mutex_unlock(&shutdown_mutex);
		ret = do_shutdown(zctx);
		mutex_lock(&shutdown_mutex);
		zctx_lock(zctx);
		if (ret < 0)
			zctx->shutdown = ZHPE_CTX_SHUTDOWN_FAILED;
		else
			zctx->shutdown = ZHPE_CTX_SHUTDOWN;
		zctx_unlock(zctx);
	} else {
		while (zctx->shutdown == ZHPE_CTX_SHUTDOWN_IN_PROGRESS)
			cond_wait(&shutdown_cond, &shutdown_mutex);
		if  (zctx->shutdown == ZHPE_CTX_SHUTDOWN)
			ret = 0;
		else
			ret = -EBUSY;
	}
	mutex_unlock(&shutdown_mutex);

	ZHPE_LOG_INFO("shutdown returned %d\n", ret);
	assert(!ret);

	return ret;
}

static int zhpe_ctx_qfree(struct zhpe_ctx *zctx)
{
	int			ret = 0;
	int			rc;
	uint			i;

	/* Close connections and free queues. */
	zhpe_ctx_shutdown(zctx);
	zhpe_pe_del_ctx(zctx);
	zctx_lock(zctx);
	zhpe_conn_cleanup(zctx);
	rc = zhpeq_tq_free(zctx->ztq_hi);
	ret = zhpeu_update_error(ret, rc);
	if (rc < 0)
		ZHPE_LOG_ERROR("zhpe_tq_free() error %d\n", rc);
	for (i = 0; i < ZHPE_MAX_SLICES; i++) {
		rc = zhpeq_tq_free(zctx->ztq_lo[i]);
		ret = zhpeu_update_error(ret, rc);
		if (rc < 0)
			ZHPE_LOG_ERROR("zhpe_tq_free() error %d\n", rc);
	}
	if (zctx->zrq) {
		rc = zhpeq_rq_epoll_del(zctx->zrq);
		ret = zhpeu_update_error(ret, rc);
		if (rc < 0)
			ZHPE_LOG_ERROR("zhpe_rq_epoll_del() error %d\n",
					       rc);
	}
	rc = zhpeq_rq_free(zctx->zrq);
	ret = zhpeu_update_error(ret, rc);
	if (rc < 0)
		ZHPE_LOG_ERROR("zhpe_rq_free() error %d\n", rc);
	zctx_unlock(zctx);

	return ret;
}

static int zhpe_ctx_qalloc(struct zhpe_ctx *zctx)
{
	int			ret = 0;
	struct zhpe_ep		*zep = zctx->zep;
	struct zhpe_dom		*zdom = zctx2zdom(zctx);
	struct zhpeq_dom	*zqdom = zdom->zqdom;
	struct fi_info		*info = zep->info;
	size_t			tx_size = info->tx_attr->size;
	size_t			rx_size = info->rx_attr->size;
	bool			manual;
	size_t			i;
	struct sockaddr_zhpe	sz;
	uint32_t		qspecific;

	manual = (zdom->util_domain.data_progress == FI_PROGRESS_MANUAL);

	zctx_lock(zctx);
	/* High priority for ENQA. */
	ret = zhpeq_tq_alloc(zqdom, tx_size, tx_size, 0, ZHPEQ_PRIO_HI, 0,
			     &zctx->ztq_hi);
	if (ret < 0) {
		ZHPE_LOG_ERROR("zhpe_tq_alloc() error %d\n", ret);
		goto done;
	}
	/* Low priority for RMA. */
	for (i = 0; i < zhpeq_attr.z.num_slices; i++) {
		/* ZZZ: Traffic class? */
		ret = zhpeq_tq_alloc(zqdom, tx_size, tx_size, 0, ZHPEQ_PRIO_LO,
				     1U << i, &zctx->ztq_lo[i]);
		if (ret < 0) {
			ZHPE_LOG_ERROR("zhpe_tq_alloc() error %d\n", ret);
			goto done;
		}
	}
	if (info->src_addr && info->src_addrlen) {
		qspecific = ((struct sockaddr_zhpe *)info->src_addr)->sz_queue;
		qspecific = ntohl(qspecific);
	} else
		qspecific = 0;
	ret = zhpeq_rq_alloc_specific(zqdom, rx_size, qspecific, &zctx->zrq);
	if (ret < 0) {
		ZHPE_LOG_ERROR("zhpe_rq_alloc() error %d\n", ret);
		goto done;
	}
	ret = zhpeq_rq_epoll_add(zdom->pe->zepoll, zctx->zrq,
				 zhpe_pe_epoll_handler, zctx,
				 zhpe_ep_rx_poll_timeout, manual);
	if (ret < 0) {
		ZHPE_LOG_ERROR("zhpe_rq_epoll_add() error %d\n", ret);
		goto done;
	}
	i = sizeof(sz);
	ret = zhpeq_rq_get_addr(zctx->zrq, &sz, &i);
	if (ret < 0) {
		ZHPE_LOG_ERROR("zhpe_rq_get_addr() error %d\n", ret);
		goto done;
	}
	if (!zctx->ctx_idx)
		memcpy(zep->uuid, sz.sz_uuid, sizeof(zep->uuid));
	zctx->lcl_gcid = zhpeu_uuid_to_gcid(sz.sz_uuid);
	zctx->lcl_rspctxid = ntohl(sz.sz_queue);

	/* Allocate the ctx_ptrs array twice the size of the cmdq. */
	i = zctx->ztq_hi->tqinfo.cmdq.ent * 2;
	i = min(i, (size_t)UINT16_MAX);
	zctx->ctx_ptrs = calloc(i, sizeof(*zctx->ctx_ptrs));
	if (!zctx->ctx_ptrs) {
		ret = -FI_ENOMEM;
		goto done;
	}
	/* Set up a linked list, zero is the end-of-list. */
	while (i > 2) {
		i--;
		zctx->ctx_ptrs[i - 1] = TO_PTR(i);
	}
	zctx->ctx_ptrs_free = 1;

	ret = 0;

 done:
	zctx_unlock(zctx);
	if (ret >= 0 && !manual)
		zhpe_pe_add_ctx(zctx);

	return ret;
}

static int zhpe_ctx_close(struct fid *fid)
{
	int			ret = 0;
	struct zhpe_ctx		*zctx = fid2zctx(fid);
	int32_t			old;

	/*
	 * Just hammer the appropriate fid_ep & pointers with zeroes;
	 * any attempt to continue use the fid will fault/abort.
	 */

	zctx_lock(zctx);
	switch (fid->fclass) {

	case FI_CLASS_RX_CTX:
		if (zctx->close & ZHPE_CTX_CLOSE_RX)
			return -EBUSY;
		zctx->close |= ZHPE_CTX_CLOSE_RX;
		break;

	case FI_CLASS_TX_CTX:
		if (zctx->close & ZHPE_CTX_CLOSE_TX)
			return -EBUSY;
		zctx->close |= ZHPE_CTX_CLOSE_TX;
		break;

	default:
		return -EINVAL;

	}
	if ((zctx->close & ZHPE_CTX_CLOSE_ALL) == ZHPE_CTX_CLOSE_ALL) {
		old = ofi_atomic_dec32(&zctx->zep->num_ctx_open);
		assert_always(old > 0);
	}
	zctx_unlock(zctx);

	return ret;
}

static int zhpe_ctx_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{
	int			ret = -FI_EINVAL;
	struct zhpe_ep		*zep = fid2zep(fid);
	struct zhpe_ctx		*zctx = fid2zctx(fid);

	if (!bfid)
		goto done;

	if (!zep->disabled) {
		ret = -FI_EBUSY;
		goto done;
	}

	/* Handle uneven tx/rx context case. */
	switch (bfid->fclass) {

	case FI_CLASS_CQ:
		if (zctx->ctx_idx >= zep->num_tx_ctx && (flags & FI_TRANSMIT))
			goto done;
		if (zctx->ctx_idx >= zep->num_rx_ctx && (flags & FI_RECV))
			goto done;
		break;

	case FI_CLASS_CNTR:
		if (zctx->ctx_idx >= zep->num_tx_ctx &&
		    (flags & (FI_SEND | FI_READ | FI_WRITE)))
			goto done;
		if (zctx->ctx_idx >= zep->num_rx_ctx &&
		    (flags & (FI_RECV | FI_REMOTE_READ | FI_REMOTE_WRITE)))
			goto done;
		break;
	}
	zctx_lock(zctx);
	ret = ofi_ep_bind(&zctx->util_ep, bfid, flags);
	zctx_unlock(zctx);

 done:
	return ret;
}

static int zhpe_getopflags(struct zhpe_ctx *zctx, bool rx_valid,
			   bool tx_valid, uint64_t *flags)
{
	int			ret = -FI_EINVAL;

	switch (*flags & (FI_TRANSMIT | FI_RECV)) {

	case FI_RECV:
		if (!rx_valid)
			break;
		*flags = zctx->util_ep.rx_op_flags;
		ret = 0;
		break;

	case FI_TRANSMIT:
		if (!tx_valid)
			break;
		*flags = zctx->util_ep.tx_op_flags;
		ret = 0;
		break;

	}

	return ret;
}

static int zhpe_setopflags(struct zhpe_ctx *zctx, bool rx_valid, bool tx_valid,
			   const uint64_t *flags)
{
	int			ret = -FI_EINVAL;
	uint64_t		v64 = *flags;

	switch (v64 & (FI_TRANSMIT | FI_RECV)) {

	case FI_RECV:
		if (!rx_valid)
			break;
		v64 &= ~FI_RECV;
		if (v64 & ~ZHPE_EP_RX_OP_FLAGS)
			break;
		zctx->util_ep.rx_op_flags = v64;
		zctx->util_ep.rx_msg_flags = (v64 & FI_COMPLETION);
		ret = 0;
		break;

	case FI_TRANSMIT:
		if (!tx_valid)
			break;
		v64 &= ~FI_TRANSMIT;
		if (v64 & ~ZHPE_EP_TX_OP_FLAGS)
			break;
		zctx->util_ep.tx_op_flags = v64;
		zctx->util_ep.tx_msg_flags = (v64 & FI_COMPLETION);
		ret = 0;
		break;

	}

	return ret;
}

static int zhpe_ctx_control(struct fid *fid, int command, void *arg)
{
	int			ret = -FI_EINVAL;
	struct zhpe_ctx		*zctx = fid2zctx(fid);

	zctx_lock(zctx);
	switch (command) {

	case FI_GETOPSFLAG:

		if (!arg)
			break;

		switch (fid->fclass) {

		case FI_CLASS_EP:
			ret = zhpe_getopflags(zctx, true, true, arg);
			break;

		case FI_CLASS_RX_CTX:
			ret = zhpe_getopflags(zctx, true, false, arg);
			break;

		case FI_CLASS_TX_CTX:
			ret = zhpe_getopflags(zctx, false, true, arg);
			break;

		}
		break;

	case FI_SETOPSFLAG:

		if (!arg)
			break;

		switch (fid->fclass) {

		case FI_CLASS_EP:
			ret = zhpe_setopflags(zctx, true, true, arg);
			break;

		case FI_CLASS_RX_CTX:
			ret = zhpe_setopflags(zctx, true, false, arg);
			break;

		case FI_CLASS_TX_CTX:
			ret = zhpe_setopflags(zctx, false, true, arg);
			break;

		}
		break;

	default:
		ret = -FI_ENOSYS;
		break;
	}
	zctx_unlock(zctx);

	return ret;
}

static struct fi_ops zhpe_ctx_fi_ops = {
	.size			= sizeof(struct fi_ops),
	.close			= zhpe_ctx_close,
	.bind			= zhpe_ctx_bind,
	.control		= zhpe_ctx_control,
	.ops_open		= fi_no_ops_open,
};

static ssize_t zhpe_ctx_rx_cancel(struct fid *fid, void *op_context)
{
	ssize_t			ret = -FI_ENOENT;
	struct zhpe_ctx		*zctx = fid2zctx(fid);
	struct zhpe_rx_entry	*rx_entry;
	struct dlist_entry	*dentry;
	struct dlist_entry	*dnext;

	zctx_lock(zctx);
	dlist_foreach_safe(&zctx->rx_match_tagged.user_list, dentry, dnext) {
		rx_entry = container_of(dentry, struct zhpe_rx_entry, dentry);
		if (op_context != rx_entry->op_context)
			continue;

		ret = 0;
		dlist_remove(&rx_entry->dentry);
		dlist_insert_tail(&rx_entry->dentry, &zctx->rx_work_list);
		rx_entry->src_flags = 0;
		zhpe_rx_complete(rx_entry, -FI_ECANCELED);
		break;
	}
	dlist_foreach_safe(&zctx->rx_match_untagged.user_list, dentry, dnext) {
		rx_entry = container_of(dentry, struct zhpe_rx_entry, dentry);
		if (op_context != rx_entry->op_context)
			continue;

		ret = 0;
		dlist_remove(&rx_entry->dentry);
		dlist_insert_tail(&rx_entry->dentry, &zctx->rx_work_list);
		rx_entry->src_flags = 0;
		zhpe_rx_complete(rx_entry, -FI_ECANCELED);
		break;
	}
	zctx_unlock(zctx);

 	return ret;
}

struct fi_ops_ep zhpe_ep_ops = {
	.size			= sizeof(struct fi_ops_ep),
	.cancel			= zhpe_ctx_rx_cancel,
	.getopt			= fi_no_getopt,
	.setopt			= fi_no_setopt,
	.tx_ctx			= fi_no_tx_ctx,
	.rx_ctx			= fi_no_rx_ctx,
	.rx_size_left		= fi_no_rx_size_left,
	.tx_size_left		= fi_no_tx_size_left,
};

static int zhpe_ep_enable(struct zhpe_ep *zep)
{
	int			ret = 0;
	size_t			i;

	zep_lock(zep);
	if (zep->disabled == ZHPE_EP_DISABLED)
		zep->disabled = ZHPE_EP_DISABLED_ENABLE_IN_PROGRESS;
	else
		ret = -FI_EOPBADSTATE;
	zep_unlock(zep);

	for (i = 0; i < zep->num_ctx; i++) {
		ret = zhpe_ctx_qalloc(zep->zctx[i]);
		if (ret < 0) {
			while (i > 0)
				zhpe_ctx_qfree(zep->zctx[i]);
			goto done;
		}
	}
	zep_lock(zep);
	zep->disabled = ZHPE_EP_DISABLED_ENABLED;
	zep_unlock(zep);
	ret = 0;

 done:
	return ret;
}

static int zhpe_ep_free(struct zhpe_ep *zep);

static int zhpe_ep_close(struct fid *fid)
{
	struct zhpe_ep		*zep = fid2zep(fid);

	if (ofi_atomic_get32(&zep->num_ctx_open))
		return -FI_EBUSY;

	return zhpe_ep_free(zep);
}

static int zhpe_ep_control(struct fid *fid, int command, void *arg)
{
	int			ret = -FI_EINVAL;
	struct zhpe_ep		*zep = fid2zep(fid);

	if (command == FI_ENABLE) {
		if (!arg)
		    ret = zhpe_ep_enable(zep);
	} else
		ret = zhpe_ctx_control(fid, command, arg);

	return ret;
}

static struct fi_ops zhpe_ep_fi_ops= {
	.size			= sizeof(struct fi_ops),
	.close			= zhpe_ep_close,
	.bind			= zhpe_ctx_bind,
	.control		= zhpe_ep_control,
	.ops_open		= fi_no_ops_open,
};

static int zhpe_sep_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{
	int			ret = -FI_EINVAL;
	struct zhpe_ep		*zep = fid2zep(fid);
	struct zhpe_ctx		*zctx;
	size_t			i;

	if (!bfid)
		goto done;

	if (bfid->fclass != FI_CLASS_AV)
		goto done;

	for (i = 0; i < zep->num_ctx; i++) {
		zctx = zep->zctx[i];
		ret = zhpe_ctx_bind(&zctx->util_ep.ep_fid.fid, bfid, flags);
		if (ret < 0)
			break;
	}

 done:
	return ret;
}

static int zhpe_sep_control(struct fid *fid, int command, void *arg)
{
	int			ret = -FI_EINVAL;

	if (command == FI_ENABLE) {
		if (!arg)
		    ret = zhpe_ep_enable(fid2zep(fid));
	}

	return ret;
}

struct fi_ops zhpe_sep_fi_ops= {
	.size			= sizeof(struct fi_ops),
	.close			= zhpe_ep_close,
	.bind			= zhpe_sep_bind,
	.control		= zhpe_sep_control,
	.ops_open		= fi_no_ops_open,
};

static int zhpe_sep_tx_ctx(struct fid_ep *fid_ep, int index,
			   struct fi_tx_attr *attr,
			   struct fid_ep **fid_ep_out, void *context)
{
	int			ret = -FI_EINVAL;
	struct zhpe_ep		*zep = fid2zep(&fid_ep->fid);
	struct zhpe_ctx		*zctx;
	struct fid_ep		*fid_tx;

	if (!fid_ep_out)
		goto done;
	*fid_ep_out = NULL;
	if (index < 0 || index >= zep->num_tx_ctx)
		goto done;
	/* We ignore the ctx-specific attrs, as is allowed. */

	if (!zep->disabled) {
		ret = -FI_EOPBADSTATE;
		goto done;
	}

	ret = 0;
	zctx = zep->zctx[index];
	zctx_lock(zctx);
	if (!zctx->zep) {
		fid_tx = &zctx->util_ep.ep_fid;
		set_fid_ep(zep, fid_tx, FI_CLASS_TX_CTX, context);
		*fid_ep_out = fid_tx;
		ofi_atomic_inc32(&zep->num_ctx_open);
		/* We must return the attrs, if a pointer is provided. */
		if (attr)
			*attr = *zep->info->tx_attr;
	} else
		ret = -FI_EBUSY;
	zctx_unlock(zctx);

 done:
	return ret;
}

static int zhpe_sep_rx_ctx(struct fid_ep *fid_ep, int index,
			   struct fi_rx_attr *attr,
			   struct fid_ep **fid_ep_out, void *context)
{
	int			ret = -FI_EINVAL;
	struct zhpe_ep		*zep = fid2zep(&fid_ep->fid);
	struct zhpe_ctx		*zctx;
	struct fid_ep		*fid_rx;

	if (!fid_ep_out)
		goto done;
	*fid_ep_out = NULL;
	if (index < 0 || index >= (int)zep->num_rx_ctx)
		goto done;
	/* We ignore the ctx-specific attrs, as is allowed. */

	if (!zep->disabled) {
		ret = -FI_EOPBADSTATE;
		goto done;
	}

	ret = 0;
	zctx = zep->zctx[index];
	zctx_lock(zctx);
	if (!zctx->rx_ep.zep) {
		fid_rx = &zctx->rx_ep.ep_fid;
		set_fid_ep(zep, fid_rx, FI_CLASS_RX_CTX, context);
		*fid_ep_out = fid_rx;
		ofi_atomic_inc32(&zep->num_ctx_open);
		/* We must return the attrs, if a pointer is provided. */
		if (attr)
			*attr = *zep->info->rx_attr;
	} else
		ret = -FI_EBUSY;
	zctx_unlock(zctx);

 done:
	return ret;
}

struct fi_ops_ep zhpe_sep_ops = {
	.size			= sizeof(struct fi_ops_ep),
	.cancel			= fi_no_cancel,
	.getopt			= fi_no_getopt,
	.setopt			= fi_no_setopt,
	.tx_ctx			= zhpe_sep_tx_ctx,
	.rx_ctx			= zhpe_sep_rx_ctx,
	.rx_size_left		= fi_no_rx_size_left,
	.tx_size_left		= fi_no_tx_size_left,
};

static void rx_entry_init_fn(struct ofi_bufpool_region *region, void *buf)
{
	struct zhpe_rx_entry *rx_entry = buf;

	rx_entry->zctx = region->pool->attr.context;
	zhpe_iov_state_init(&rx_entry->lstate, &zhpe_iov_state_ziov3_ops,
			    rx_entry->liov, ZHPE_EP_MAX_IOV);
	zhpe_iov_state_init(&rx_entry->rstate, &zhpe_iov_state_iovec_ops,
			    rx_entry->riov, ZHPE_EP_MAX_IOV);
	zhpe_iov_state_init(&rx_entry->bstate, &zhpe_iov_state_iovec_ops,
			    rx_entry->riov + ZHPE_EP_MAX_IOV, 1);
	rx_entry->tx_entry.ptrs[1] = &rx_entry->rstate;
	rx_entry->tx_entry.rma_get = true;
}

static void rma_entry_init_fn(struct ofi_bufpool_region *region, void *buf)
{
	struct zhpe_rma_entry *rma_entry = buf;

	rma_entry->zctx = region->pool->attr.context;
	zhpe_iov_state_init(&rma_entry->lstate, &zhpe_iov_state_ziov3_ops,
			    rma_entry->liov, ZHPE_EP_MAX_IOV);
	zhpe_iov_state_init(&rma_entry->rstate, &zhpe_iov_state_ziov3_ops,
			    rma_entry->riov, ZHPE_EP_MAX_IOV);
	rma_entry->tx_entry.tx_handler = ZHPE_TX_HANDLE_RMA;
	rma_entry->tx_entry.ptrs[0] = &rma_entry->lstate;
	rma_entry->tx_entry.ptrs[1] = &rma_entry->rstate;
}

static int zhpe_no_close(struct fid *fid)
{
	return -FI_ENOSYS;
}

static struct fi_ops zhpe_ep_fi_bad_ops = {
	.size			= sizeof(struct fi_ops),
	.close			= zhpe_no_close,
	.bind			= fi_no_bind,
	.control		= fi_no_control,
	.ops_open		= fi_no_ops_open,
};

static struct fi_ops_ep zhpe_ep_bad_ops = {
	.size			= sizeof(struct fi_ops_ep),
	.cancel			= fi_no_cancel,
	.getopt			= fi_no_getopt,
	.setopt			= fi_no_setopt,
	.tx_ctx			= fi_no_tx_ctx,
	.rx_ctx			= fi_no_rx_ctx,
	.rx_size_left		= fi_no_rx_size_left,
	.tx_size_left		= fi_no_tx_size_left,
};

static struct fi_ops_collective zhpe_ep_collective_bad_ops = {
	.size			= sizeof(struct fi_ops_collective),
	.barrier		= fi_coll_no_barrier,
	.broadcast		= fi_coll_no_broadcast,
	.alltoall		= fi_coll_no_alltoall,
	.allreduce		= fi_coll_no_allreduce,
	.allgather		= fi_coll_no_allgather,
	.reduce_scatter		= fi_coll_no_reduce_scatter,
	.reduce			= fi_coll_no_reduce,
	.scatter		= fi_coll_no_scatter,
	.gather			= fi_coll_no_gather,
	.msg			= fi_coll_no_msg,
};

static void set_fid_ep(struct zhpe_ep *zep, struct fid_ep *fid_ep,
		       size_t fclass, void *context)
{
	struct fi_info		*info = zep->info;
	uint64_t		tx_caps = info->tx_attr->caps;
	uint64_t		tx_mode = info->tx_attr->mode;
	uint64_t		rx_caps = info->rx_attr->caps;
	uint			op_idx;

	fid_ep->fid.fclass = fclass;
	fid_ep->fid.context = context;

	fid_ep->fid.ops = &zhpe_ep_fi_bad_ops;
	fid_ep->ops = &zhpe_ep_bad_ops;
	fid_ep->cm = &zhpe_ep_cm_bad_ops;
	fid_ep->collective = &zhpe_ep_collective_bad_ops;

	/* Compute an index to set msg/tag ops. */
	op_idx = 0;
	if (tx_caps & FI_FENCE)
		op_idx |= 1;
	if (rx_caps & FI_DIRECTED_RECV)
		op_idx |= 2;
	if (tx_mode & (FI_CONTEXT | FI_CONTEXT2))
		op_idx |= 4;

	switch (fclass) {

	case FI_CLASS_SEP:
		fid_ep->fid.ops = &zhpe_sep_fi_ops;
		fid_ep->ops = &zhpe_sep_ops;
		fid_ep->cm = &zhpe_ep_cm_ops;
		break;

	case FI_CLASS_EP:
		fid_ep->fid.ops = &zhpe_ep_fi_ops;
		fid_ep->ops = &zhpe_ep_ops;
		fid_ep->cm = &zhpe_ep_cm_ops;

		switch (op_idx) {

		case 0:
			fid_ep->msg = &zhpe_ep_msg_ops;
			fid_ep->tagged = &zhpe_ep_tagged_ops;
			fid_ep->rma = &zhpe_ep_rma_ops;
			fid_ep->atomic = &zhpe_ep_atomic_ops;
			break;

		case 1:
			fid_ep->msg = &zhpe_ep_msg_f_ops;
			fid_ep->tagged = &zhpe_ep_tagged_f_ops;
			fid_ep->rma = &zhpe_ep_rma_f_ops;
			fid_ep->atomic = &zhpe_ep_atomic_f_ops;
			break;

		case 2:
			fid_ep->msg = &zhpe_ep_msg_d_ops;
			fid_ep->tagged = &zhpe_ep_tagged_d_ops;
			fid_ep->rma = &zhpe_ep_rma_ops;
			fid_ep->atomic = &zhpe_ep_atomic_ops;
			break;

		case 3:
			fid_ep->msg = &zhpe_ep_msg_df_ops;
			fid_ep->tagged = &zhpe_ep_tagged_df_ops;
			fid_ep->rma = &zhpe_ep_rma_f_ops;
			fid_ep->atomic = &zhpe_ep_atomic_f_ops;
			break;

		case 4:
			fid_ep->msg = &zhpe_ep_msg_c_ops;
			fid_ep->tagged = &zhpe_ep_tagged_c_ops;
			fid_ep->rma = &zhpe_ep_rma_ops;
			fid_ep->atomic = &zhpe_ep_atomic_c_ops;
			break;

		case 5:
			fid_ep->msg = &zhpe_ep_msg_cf_ops;
			fid_ep->tagged = &zhpe_ep_tagged_cf_ops;
			fid_ep->rma = &zhpe_ep_rma_f_ops;
			fid_ep->atomic = &zhpe_ep_atomic_cf_ops;
			break;

		case 6:
			fid_ep->msg = &zhpe_ep_msg_cd_ops;
			fid_ep->tagged = &zhpe_ep_tagged_cd_ops;
			fid_ep->rma = &zhpe_ep_rma_ops;
			fid_ep->atomic = &zhpe_ep_atomic_c_ops;
			break;

		case 7:
			fid_ep->msg = &zhpe_ep_msg_cdf_ops;
			fid_ep->tagged = &zhpe_ep_tagged_cdf_ops;
			fid_ep->rma = &zhpe_ep_rma_f_ops;
			fid_ep->atomic = &zhpe_ep_atomic_cf_ops;
			break;
		}

		if (!((tx_caps | rx_caps) & FI_MSG))
			fid_ep->msg = &zhpe_ep_msg_bad_ops;
		if (!((tx_caps | rx_caps) & FI_TAGGED))
			fid_ep->tagged = &zhpe_ep_tagged_bad_ops;
		if (!((tx_caps | rx_caps) & FI_RMA))
			fid_ep->rma = &zhpe_ep_rma_bad_ops;
		if (!((tx_caps | rx_caps) & FI_ATOMIC))
			fid_ep->atomic = &zhpe_ep_atomic_bad_ops;
		break;

	case FI_CLASS_RX_CTX:
		if (zep->ep.ep_fid.fid.fclass == FI_CLASS_EP)
			break;
		fid_ep->fid.ops = &zhpe_ctx_fi_ops;
		fid_ep->ops = &zhpe_ep_ops;
		fid_ep->rma = &zhpe_ep_rma_bad_ops;
		fid_ep->atomic = &zhpe_ep_atomic_bad_ops;

		switch (op_idx & 2) {

		case 0:
			fid_ep->msg = &zhpe_ep_msg_rx_ops;
			fid_ep->tagged = &zhpe_ep_tagged_rx_ops;
			break;

		case 2:
			fid_ep->msg = &zhpe_ep_msg_d_rx_ops;
			fid_ep->tagged = &zhpe_ep_tagged_d_rx_ops;
			break;

		}

		if (!((tx_caps | rx_caps) & FI_MSG))
			fid_ep->msg = &zhpe_ep_msg_bad_ops;
		if (!((tx_caps | rx_caps) & FI_TAGGED))
			fid_ep->tagged = &zhpe_ep_tagged_bad_ops;
		break;

	case FI_CLASS_TX_CTX:
		if (zep->ep.ep_fid.fid.fclass == FI_CLASS_EP)
			break;

		switch (op_idx & 5) {

		case 0:
			fid_ep->msg = &zhpe_ep_msg_tx_ops;
			fid_ep->tagged = &zhpe_ep_tagged_tx_ops;
			fid_ep->rma = &zhpe_ep_rma_ops;
			fid_ep->atomic = &zhpe_ep_atomic_ops;
			break;

		case 1:
			fid_ep->msg = &zhpe_ep_msg_f_tx_ops;
			fid_ep->tagged = &zhpe_ep_tagged_f_tx_ops;
			fid_ep->rma = &zhpe_ep_rma_f_ops;
			fid_ep->atomic = &zhpe_ep_atomic_f_ops;
			break;

		case 4:
			fid_ep->msg = &zhpe_ep_msg_c_tx_ops;
			fid_ep->tagged = &zhpe_ep_tagged_c_tx_ops;
			fid_ep->rma = &zhpe_ep_rma_ops;
			fid_ep->atomic = &zhpe_ep_atomic_c_ops;
			break;

		case 5:
			fid_ep->msg = &zhpe_ep_msg_cf_tx_ops;
			fid_ep->tagged = &zhpe_ep_tagged_cf_tx_ops;
			fid_ep->rma = &zhpe_ep_rma_f_ops;
			fid_ep->atomic = &zhpe_ep_atomic_cf_ops;
			break;
		}

		if (!((tx_caps | rx_caps) & FI_MSG))
			fid_ep->msg = &zhpe_ep_msg_bad_ops;
		if (!((tx_caps | rx_caps) & FI_TAGGED))
			fid_ep->tagged = &zhpe_ep_tagged_bad_ops;
		if (!((tx_caps | rx_caps) & FI_RMA))
			fid_ep->rma = &zhpe_ep_rma_bad_ops;
		if (!((tx_caps | rx_caps) & FI_ATOMIC))
			fid_ep->atomic = &zhpe_ep_atomic_bad_ops;
		break;

	default:
		abort();
	}
}

static int zhpe_ctx_free(struct zhpe_ctx *zctx)
{
	int			ret = 0;
	int			rc;

	if (!zctx)
		goto done;

	zhpe_ctx_qfree(zctx);
	zhpe_slab_destroy(&zctx->eager);
	zhpe_conn_fini(zctx);
	if (zctx->util_ep.domain) {
		rc = ofi_endpoint_close(&zctx->util_ep);
		ret = zhpeu_update_error(ret, rc);
	}
	zhpe_bufpool_destroy(&zctx->rx_oos_pool);
	zhpe_bufpool_destroy(&zctx->rx_entry_pool);
	zhpe_bufpool_destroy(&zctx->tx_queue_pool);
	zhpe_bufpool_destroy(&zctx->tx_rma_pool);
	zhpe_bufpool_destroy(&zctx->tx_ctx_pool);
	ofi_rbmap_cleanup(&zctx->rkey_tree);
	free(zctx);

 done:
	return ret;
}

static int zhpe_ctx_alloc(struct zhpe_ep *zep, uint8_t ctx_idx,
			  void *context, struct zhpe_ctx **zctx_out)
{
	int			ret = -FI_ENOMEM;
	struct fi_info		*info = zep->info;
	struct zhpe_ctx		*zctx;
	void			(*progress)(struct util_ep *ep);
	size_t			buffer_size;

	zctx = calloc_cachealigned(1, sizeof(*zctx));
	if (!zctx)
		goto done;

	/* Things that can't fail. */
	zctx->zep = zep;
	zctx->zctx = zctx;
	zctx->rx_ep.zep = zep;
	zctx->rx_ep.zctx = zctx;
	dlist_init(&zctx->pe_dentry);
	dlist_init(&zctx->tx_dequeue_list);
	zctx->ctx_idx = ctx_idx;
	dlist_init(&zctx->rx_match_tagged.user_list);
	dlist_init(&zctx->rx_match_tagged.wire_list);
	dlist_init(&zctx->rx_match_untagged.user_list);
	dlist_init(&zctx->rx_match_untagged.wire_list);
	dlist_init(&zctx->rx_work_list);
	ofi_rbmap_init(&zctx->rkey_tree, zhpe_compare_mem_tkeys);

	if (zep->zdom->util_domain.data_progress == FI_PROGRESS_MANUAL) {
		progress = zhpe_ofi_ep_progress;
		zctx->pe_ctx_ops = &zhpe_pe_ctx_ops_manual;
	} else {
		progress = NULL;
		zctx->pe_ctx_ops = &zhpe_pe_ctx_ops_auto_rx_active;
	}

	ret = ofi_endpoint_init(&zep->zdom->util_domain.domain_fid,
				&zhpe_util_prov, info, &zctx->util_ep,
				context, progress);
	if (ret < 0) {
		ZHPE_LOG_ERROR("ofi_endpoint_init() error %d\n", ret);
		goto done;
	}

	ret = zhpe_bufpool_create(&zctx->tx_ctx_pool, "tx_ctx_pool",
				  sizeof(struct zhpe_tx_entry_ctx),
				  zhpeu_init_time->l1sz, 0, 0,
				  OFI_BUFPOOL_NO_TRACK, NULL, NULL);
	if (ret < 0)
		goto done;

	ret = zhpe_bufpool_create(&zctx->tx_rma_pool, "tx_rma_pool",
				  sizeof(struct zhpe_rma_entry),
				  zhpeu_init_time->l1sz, 0, 0,
				  OFI_BUFPOOL_NO_TRACK,
				  rma_entry_init_fn, zctx);
	if (ret < 0)
		goto done;

	ret = zhpe_bufpool_create(&zctx->tx_queue_pool, "tx_queue_pool",
				  sizeof(struct zhpe_tx_queue_entry),
				  zhpeu_init_time->l1sz, 0, 0,
				  OFI_BUFPOOL_NO_TRACK, NULL, NULL);
	if (ret < 0)
		goto done;

	ret = zhpe_bufpool_create(&zctx->rx_entry_pool, "rx_entry_pool",
				  sizeof(struct zhpe_rx_entry),
				  zhpeu_init_time->l1sz, 0, 0,
				  OFI_BUFPOOL_NO_TRACK, rx_entry_init_fn, zctx);
	if (ret < 0)
		goto done;

	ret = zhpe_bufpool_create(&zctx->rx_oos_pool, "rx_oos_pool",
				  sizeof(struct zhpeq_rx_oos),
				  zhpeu_init_time->l1sz, 0, 0,
				  OFI_BUFPOOL_NO_TRACK, NULL, NULL);
	if (ret < 0)
		goto done;

	ret = zhpe_conn_init(zctx);
	if (ret < 0)
		goto done;

	buffer_size = ZHPE_EP_DEF_BUFFERED;
	if (info->rx_attr->total_buffered_recv > 0)
		buffer_size = info->rx_attr->total_buffered_recv;
	ret = zhpe_slab_init(&zctx->eager, buffer_size, zep->zdom);
	if (ret < 0)
		goto done;

	*zctx_out = zctx;
	ret = 0;

done:
	if (ret < 0)
		zhpe_ctx_free(zctx);

	return ret;
}

static int zhpe_ep_free(struct zhpe_ep *zep)
{
	int			ret = 0;
	size_t			i;

	if (!zep)
		goto done;

	for (i = 0; i < zep->num_ctx; i++)
		ret = zhpeu_update_error(ret, zhpe_ctx_free(zep->zctx[i]));
	ofi_atomic_dec32(&zep->zdom->util_domain.ref);
	fastlock_destroy(&zep->lock);
	free(zep);

 done:
	return ret;
}

static int zhpe_ep_alloc(struct zhpe_dom *zdom, size_t fclass,
			 struct fi_info *info, void *context,
			 struct zhpe_ep **zep_out)
{
	int			ret = -FI_ENOMEM;
	struct zhpe_ep		*zep;
	const struct fi_info	*prov_info;
	size_t			num_ctx;
	size_t			req;
	size_t			i;

	if (fclass == FI_CLASS_EP)
		num_ctx = 1;
	else
		num_ctx = max(info->ep_attr->rx_ctx_cnt,
			      info->ep_attr->tx_ctx_cnt);

	req = sizeof(zep->zctx[0]) * num_ctx + sizeof(*zep);
	zep = calloc_cachealigned(1, req);
	if (!zep)
		goto done;

	fastlock_init(&zep->lock);
	zep->ep.zep = zep;
	zep->info = fi_dupinfo(info);
	zep->zdom = zdom;
	zep->num_ctx = num_ctx;
	ofi_atomic_initialize32(&zep->num_ctx_open, 0);
	zep->disabled = 2;
	ofi_atomic_inc32(&zdom->util_domain.ref);
	/* Check for fi_dupinfo() failure after initializing no-brainers. */
	if (!zep->info)
		goto done;
	info = zep->info;

	for (prov_info = zhpe_util_prov.info; prov_info;
	     prov_info = prov_info->next) {
		if (prov_info->ep_attr->type == info->ep_attr->type)
			break;
	}
	info->rx_attr->caps |= info->caps;
	info->rx_attr->caps &= prov_info->rx_attr->caps;
	info->rx_attr->mode |= info->mode;
	info->rx_attr->mode &= prov_info->rx_attr->mode;
	info->tx_attr->caps |= info->caps;
	info->tx_attr->caps &= prov_info->tx_attr->caps;
	info->tx_attr->mode |= info->mode;
	info->tx_attr->mode &= prov_info->tx_attr->mode;
	info->domain_attr->caps |= info->caps;
	info->domain_attr->caps &= prov_info->domain_attr->caps;

	if (fclass == FI_CLASS_EP) {
		zep->num_rx_ctx = 1;
		zep->num_tx_ctx = 1;
	} else {
		zep->num_rx_ctx = info->ep_attr->rx_ctx_cnt;
		zep->num_tx_ctx = info->ep_attr->tx_ctx_cnt;
	}
	for (i = 0; i < zep->num_ctx; i++) {
		ret = zhpe_ctx_alloc(zep, i, context, &zep->zctx[i]);
		if (ret < 0)
			goto done;
	}
	zep->ep.zctx = zep->zctx[0];

	set_fid_ep(zep, &zep->ep.ep_fid, fclass, context);
	*zep_out = zep;
	ret = 0;

 done:
	if (ret < 0)
		zhpe_ep_free(zep);

	return ret;
}

int zhpe_ep_open(struct fid_domain *fid_domain, struct fi_info *info,
		 struct fid_ep **fid_ep_out, void *context)
{
	int			ret = -EINVAL;
	struct zhpe_dom		*zdom = fid2zdom(&fid_domain->fid);
	struct zhpe_ep		*zep;

	if (!fid_ep_out)
		goto done;
	*fid_ep_out = NULL;
	if (!info)
		goto done;

	ret = zhpe_ep_alloc(zdom, FI_CLASS_EP, info, context, &zep);
	if (ret < 0)
		goto done;
	*fid_ep_out = &zep->ep.ep_fid;
	ret = 0;

 done:
	return ret;
}

int zhpe_sep_open(struct fid_domain *fid_domain, struct fi_info *info,
		  struct fid_ep **fid_ep_out, void *context)
{
#ifdef NOT_YET
	int			ret = -FI_EINVAL;
	struct zhpe_dom		*zdom = fid2zdom(&fid_domain->fid);
	struct zhpe_ep		*zep;

	if (!fid_ep_out)
		goto done;
	*fid_ep_out = NULL;
	if (!info)
		goto done;

	ret = zhpe_ep_alloc(zdom, FI_CLASS_SEP, info, context, &zep);
	if (ret < 0)
		goto done;
	*fid_ep_out = &zep->ep.ep_fid;
	ret = 0;

 done:
	return ret;
#else
	return -FI_ENOSYS;
#endif

}
