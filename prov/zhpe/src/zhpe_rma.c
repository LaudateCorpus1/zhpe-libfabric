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

#define ZHPE_SUBSYS	FI_LOG_EP_DATA

/* Assumptions. */
static_assert(ZHPE_EP_MAX_IOV == 2, "iov_len");

int zhpe_compare_mem_tkeys(struct ofi_rbmap *map, void *key, void *data)
{
	int			ret;
	struct zhpe_mem_tree_key *k1 = key;
	struct zhpe_mem_tree_key *k2 = data;

	ret = arithcmp(k1->rem_gcid, k2->rem_gcid);
	if (ret)
		return ret;
	ret = arithcmp(k1->rem_rspctxid, k2->rem_rspctxid);
	if (ret)
		return ret;
	ret = arithcmp(k1->key, k2->key);

	return ret;
}

void zhpe_rma_rkey_free(struct zhpe_rkey *rkey)
{
	/* rkey->conn->zctx lock must be held. */
	if (rkey->qkdata) {
		zhpeq_qkdata_free(rkey->qkdata);
		zhpe_send_key_release(rkey->conn, rkey->tkey.key);
	}
	free(rkey);
}

void zhpe_rma_rkey_import(struct zhpe_conn *conn, uint64_t key,
			  const char *blob, size_t blob_len)
{
	/* conn->zctx lock must be held. */
	struct zhpe_ctx		*zctx = conn->zctx;
	struct zhpe_mem_tree_key tkey = {
		.rem_gcid	= conn->tkey.rem_gcid,
		.rem_rspctxid	= conn->rem_rspctxid,
		.key		= key,
	};
	struct ofi_rbnode	*rbnode;
	struct zhpe_rkey	*rkey;
	struct zhpe_rkey_wait	*rkey_wait;
	struct dlist_entry	*next;
	int			status;
	int			rc;

	/* Sequencing and locking on the sender means the entry must exist. */
	rbnode = ofi_rbmap_find(&zctx->rkey_tree, &tkey);
	assert_always(rbnode != NULL);
	rkey = rbnode->data;
	if (OFI_LIKELY(blob_len)) {
		rc = zhpeq_qkdata_import(zctx2zdom(zctx)->zqdom,
					 conn->addr_cookie, blob, blob_len,
					 &rkey->qkdata);
		assert_always(!rc);
		rc = zhpeq_zmmu_reg(rkey->qkdata);
		assert_always(!rc);
		if (conn->rem_rma_flags & FI_ZHPE_RMA_ZERO_OFF)
			rkey->offset = rkey->qkdata->z.vaddr;
		status = 0;
	} else {
		ofi_rbmap_delete(&zctx->rkey_tree, rbnode);
		status = -FI_ENOKEY;
	}

	dlist_foreach_container_safe(&rkey->rkey_wait_list,
				     struct zhpe_rkey_wait, rkey_wait, dentry,
				     next) {
		rkey_wait->handler(rkey_wait->handler_arg, status);
		dlist_remove(&rkey_wait->dentry);
		free(rkey_wait);
	}

	if (OFI_UNLIKELY(status < 0))
		zhpe_rma_rkey_free(rkey);
}

void zhpe_rma_rkey_revoke(struct zhpe_conn *conn, uint64_t key)
{
	/* conn->zctx lock must be held. */
	struct zhpe_ctx		*zctx = conn->zctx;
	struct zhpe_mem_tree_key tkey = {
		.rem_gcid	= conn->tkey.rem_gcid,
		.rem_rspctxid	= conn->rem_rspctxid,
		.key		= key,
	};
	struct ofi_rbnode	*rbnode;
	struct zhpe_rkey	*rkey;

	/* Sequencing and locking on the sender means the entry must exist. */
	rbnode = ofi_rbmap_find(&zctx->rkey_tree, &tkey);
	assert_always(rbnode);
	rkey = rbnode->data;
	ofi_rbmap_delete(&zctx->rkey_tree, rbnode);
	zhpe_rma_rkey_put(rkey);
}

struct zhpe_rkey *
zhpe_rma_rkey_lookup(struct zhpe_conn *conn, uint64_t key,
		     void *(*wait_prep)(void *prep_arg),
		     void (*wait_handler)(void *handler_arg, int status),
		     void *prep_arg)
{
	struct zhpe_rkey	*rkey;
	struct zhpe_ctx		*zctx = conn->zctx;
	struct zhpe_mem_tree_key tkey = {
		.rem_gcid	= conn->tkey.rem_gcid,
		.rem_rspctxid	= conn->rem_rspctxid,
		.key		= key,
	};
	struct zhpe_rkey_wait   *rkey_wait;
	struct ofi_rbnode	*rbnode;
	int			rc;

	rbnode = ofi_rbmap_find(&zctx->rkey_tree, &tkey);
	if (OFI_UNLIKELY(!rbnode)) {
		rkey = xmalloc(sizeof(*rkey));
		rkey->tkey = tkey;
		rkey->conn = conn;
		rkey->offset = 0;
		rkey->qkdata = NULL;
		dlist_init(&rkey->rkey_wait_list);
		rkey->ref = 2;
		rc = ofi_rbmap_insert(&zctx->rkey_tree, &tkey, rkey, NULL);
		assert_always(!rc);
		zhpe_send_key_request(conn, &key, 1);
	} else {
		rkey = rbnode->data;
		zhpe_rma_rkey_get(rkey);
		if (OFI_LIKELY(rkey->qkdata != NULL))
			return rkey;
	}

	/* Build the wait list entry: wait_prep returns the handler_arg. */
	rkey_wait = xmalloc(sizeof(*rkey_wait));
	rkey_wait->handler = wait_handler;
	rkey_wait->handler_arg = wait_prep(prep_arg);
	dlist_insert_tail(&rkey_wait->dentry, &rkey->rkey_wait_list);

	return rkey;
}

static void rma_rkey_fixup(struct zhpe_rma_entry *rma_entry)
{
	int			rc;
	struct zhpe_iov3	*riov;
	uint32_t		qaccess;

	if (OFI_UNLIKELY(!rma_entry->rstate.cnt))
		return;
	qaccess = (rma_entry->tx_entry.rma_get ? ZHPEQ_MR_GET_REMOTE :
		   ZHPEQ_MR_PUT_REMOTE);
	riov = rma_entry->riov;
	riov->iov_base += riov->iov_rkey->offset;
	rc = zhpeq_rem_key_access(riov->iov_rkey->qkdata, riov->iov_base,
				  riov->iov_len, qaccess, &riov->iov_base);
	zhpe_cstat_update_status(&rma_entry->tx_entry.cstat, rc);
	if (rma_entry->rstate.cnt > 1) {
		riov++;
		riov->iov_base += riov->iov_rkey->offset;
		rc = zhpeq_rem_key_access(riov->iov_rkey->qkdata,
					  riov->iov_base, riov->iov_len,
					  qaccess, &riov->iov_base);
		zhpe_cstat_update_status(&rma_entry->tx_entry.cstat, rc);
	}
}

static void *rma_rkey_wait_prep(void *prep_arg)
{
	struct zhpe_rma_entry	*rma_entry = prep_arg;
	struct zhpe_tx_entry	*tx_entry = &rma_entry->tx_entry;

	tx_entry->cstat.completions++;
	tx_entry->cstat.flags |= ZHPE_CS_FLAG_KEY_WAIT;

	return rma_entry;
}

static void rma_rkey_wait_handler(void *handler_arg, int status)
{
	struct zhpe_rma_entry	*rma_entry = handler_arg;
	struct zhpe_tx_entry	*tx_entry = &rma_entry->tx_entry;

	zhpe_cstat_update_status(&tx_entry->cstat, status);
	if (tx_entry->cstat.completions-- > 1)
		return;
	assert(!tx_entry->cstat.completions);
	if (OFI_LIKELY(!tx_entry->cstat.status))
		rma_rkey_fixup(rma_entry);
	tx_entry->cstat.flags &= ~ZHPE_CS_FLAG_KEY_WAIT;
	if (OFI_UNLIKELY(tx_entry->cstat.flags & ZHPE_CS_FLAG_FENCE))
		return;

	zhpe_rma_tx_start(rma_entry);
}

static void rma_rkey_lookup(struct zhpe_rma_entry *rma_entry,
			    const struct fi_rma_iov *urma)

{
	struct zhpe_tx_entry	*tx_entry = &rma_entry->tx_entry;
	struct zhpe_iov3	*riov;

	riov = &rma_entry->riov[rma_entry->rstate.cnt++];
	riov->iov_rkey = zhpe_rma_rkey_lookup(tx_entry->conn, urma->key,
					      rma_rkey_wait_prep,
					      rma_rkey_wait_handler, rma_entry);
	riov->iov_base = urma->addr;
	riov->iov_len = urma->len;
}

void zhpe_rma_tx_start(struct zhpe_rma_entry *rma_entry)
{
	struct zhpe_tx_entry	*tx_entry = &rma_entry->tx_entry;
	struct zhpe_conn	*conn = tx_entry->conn;

	/* conn->zctx lock must be held. */
	if (OFI_LIKELY(!tx_entry->cstat.status)) {
		if (!(tx_entry->cstat.flags & ZHPE_CS_FLAG_RMA_DONE)) {
			if (OFI_LIKELY(!conn->eflags)) {
				zhpe_iov_rma(tx_entry, ZHPE_SEG_MAX_BYTES,
					     ZHPE_SEG_MAX_OPS);
				return;
			}
			tx_entry->cstat.status =
				zhpe_conn_eflags_error(conn->eflags);
		}
		if (OFI_UNLIKELY(conn->rem_rma_flags & rma_entry->op_flags))
			zhpe_send_writedata(conn, rma_entry->op_flags,
					    rma_entry->cq_data);
	}

	zhpe_rma_complete(rma_entry);
}

static void rma_iov_start(struct zhpe_rma_entry *rma_entry, uint64_t opt_flags,
			  const struct fi_rma_iov *urma, size_t urma_cnt)
{
	struct zhpe_tx_entry	*tx_entry = &rma_entry->tx_entry;
	struct zhpe_conn	*conn = tx_entry->conn;
	struct zhpe_ctx		*zctx = conn->zctx;
	struct zhpe_tx_queue_entry *txqe;

	assert(urma_cnt <= ZHPE_EP_MAX_IOV);
	if (OFI_LIKELY(urma_cnt > 0)) {
		rma_rkey_lookup(rma_entry,  &urma[0]);
		if (OFI_LIKELY(urma_cnt > 1))
			rma_rkey_lookup(rma_entry, &urma[1]);
	}
	/*
	 * The context tracks the notional RMA outstanding,
	 * not the number of actual I/Os.
	 */
	/* Optimize for immediate send. */
	zhpe_iov_state_reset(&rma_entry->lstate);
	zhpe_iov_state_reset(&rma_entry->rstate);
	zhpe_conn_fence_check(tx_entry, opt_flags, rma_entry->op_flags);

	if (OFI_UNLIKELY(tx_entry->cstat.flags & ZHPE_CS_FLAG_FENCE)) {
		tx_entry->cstat.flags |= ZHPE_CS_FLAG_QUEUED;
		zctx->tx_queued++;
		txqe = zhpe_buf_alloc(&zctx->tx_queue_pool);
		txqe->tx_entry = tx_entry;
		dlist_insert_tail(&txqe->dentry, &conn->tx_queue);
	} else if (OFI_LIKELY(!tx_entry->cstat.completions)) {
		rma_rkey_fixup(rma_entry);
		zhpe_rma_tx_start(rma_entry);
	}
	zctx->pe_ctx_ops->signal(zctx);
}


static int rma_iov_op(struct zhpe_ctx *zctx, void *op_context, uint64_t cq_data,
		      uint64_t op_flags, uint64_t opt_flags, bool get,
		      const struct iovec *uiov, void **udesc, size_t uiov_cnt,
		      const struct fi_rma_iov *urma, size_t urma_cnt,
		      uint64_t total, fi_addr_t rem_addr)
{
	int			rc;
	struct zhpe_conn	*conn;
	struct zhpe_rma_entry	*rma_entry;

	if (OFI_UNLIKELY(zctx->zep->disabled))
		return -FI_EOPBADSTATE;

	zctx_lock(zctx);
	zhpe_stats_start(zhpe_stats_subid(RMA, 10));
	conn = zhpe_conn_av_lookup(zctx, rem_addr);
	zhpe_stats_stop(zhpe_stats_subid(RMA, 10));

	zhpe_stats_start(zhpe_stats_subid(RMA, 40));
	rma_entry = zhpe_rma_entry_alloc(zctx);
	rma_entry->tx_entry.conn = conn;
	rma_entry->tx_entry.rma_get = get;
	rma_entry->op_flags = op_flags;
	rma_entry->op_context = op_context;

	if (OFI_UNLIKELY(total <= ZHPEQ_MAX_IMM)) {
		if (OFI_LIKELY(total)) {
			zhpe_stats_start(zhpe_stats_subid(RMA, 20));
			zhpe_get_uiov_buffered(uiov, udesc, uiov_cnt,
					       &rma_entry->lstate);
			zhpe_stats_stop(zhpe_stats_subid(RMA, 20));
			if (!get && (op_flags & FI_INJECT)) {
				zhpe_copy_iov_to_mem(rma_entry->inline_data,
						     total, &rma_entry->lstate);
				zhpe_iov_state_reset(&rma_entry->lstate);
				rma_entry->lstate.cnt = 1;
				rma_entry->liov[0].iov_base =
					(uintptr_t)rma_entry->inline_data;
				rma_entry->liov[0].iov_len = total;
			}
		} else {
			/* Too much trouble to special case any further. */
			rma_entry->lstate.cnt = 0;
			rma_entry->tx_entry.cstat.flags |=
				ZHPE_CS_FLAG_RMA_DONE;
		}
	} else {
		zhpe_stats_start(zhpe_stats_subid(RMA, 20));
		zctx_unlock(zctx);
		rc = zhpe_get_uiov(zctx, uiov, udesc, uiov_cnt,
				   (get ? ZHPEQ_MR_GET : ZHPEQ_MR_PUT),
				   rma_entry->liov);
		zctx_lock(zctx);
		zhpe_stats_stop(zhpe_stats_subid(RMA, 20));
		if (OFI_UNLIKELY(rc < 0)) {
			zhpe_rma_entry_free(rma_entry);
			zctx_unlock(zctx);

			return rc;
		}
		rma_entry->lstate.cnt = rc;
		rma_entry->lstate.held = true;
	}

	/* Check eflags after we may have dropped and reacquired the lock. */
	if (OFI_UNLIKELY(conn->eflags)) {
		rc = zhpe_conn_eflags_error(conn->eflags);
		zhpe_rma_entry_free(rma_entry);
		zctx_unlock(zctx);
		return rc;
	}

	zhpe_stats_start(zhpe_stats_subid(RMA, 30));
	rma_iov_start(rma_entry, opt_flags, urma, urma_cnt);
	zhpe_stats_stop(zhpe_stats_subid(RMA, 30));
	zctx_unlock(zctx);

	return 0;
}

#define RD_FLAGS	(ZHPE_EP_TX_OP_FLAGS | FI_MORE)
#define WR_FLAGS	(RD_FLAGS | FI_REMOTE_CQ_DATA)

#define RMA_OPS(_name, _opt)						\
									\
static ssize_t zhpe_rma_readmsg##_name(struct fid_ep *fid_ep,		\
				       const struct fi_msg_rma *msg,	\
				       uint64_t flags)			\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt);			\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
	uint64_t		bad_mask;				\
	uint64_t		total_uiov;				\
	uint64_t		total;					\
									\
	zhpe_stats_start(zhpe_stats_subid(RMA, 0));			\
									\
	bad_mask = ~(RD_FLAGS |						\
		     ((opt_flags & ZHPE_OPT_FENCE) ? FI_FENCE : 0));	\
	if (OFI_UNLIKELY(!msg || msg->iov_count > ZHPE_EP_MAX_IOV ||	\
			 (msg->iov_count && !msg->msg_iov) ||		\
			 msg->rma_iov_count > ZHPE_EP_MAX_IOV ||	\
			 (msg->rma_iov_count && !msg->rma_iov) ||	\
			 (flags & bad_mask))) {				\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	ret = zhpe_get_uiov_len(msg->msg_iov, msg->iov_count,		\
				&total_uiov);				\
	if (OFI_UNLIKELY(ret < 0))					\
		goto done;						\
	ret = zhpe_get_urma_len(msg->rma_iov, msg->rma_iov_count,	\
				&total);				\
	if (OFI_UNLIKELY(ret < 0))					\
		goto done;						\
	if (total_uiov != total) {					\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = flags | zctx->util_ep.tx_msg_flags | FI_READ;	\
									\
	ret = rma_iov_op(zctx, msg->context, msg->data,			\
			 op_flags, opt_flags, true,			\
			 msg->msg_iov, msg->desc, msg->iov_count,	\
			 msg->rma_iov, msg->rma_iov_count,		\
			 total, msg->addr);				\
									\
 done:									\
	zhpe_stats_stop(zhpe_stats_subid(RMA, 0));			\
									\
	return ret;							\
}									\
									\
static ssize_t zhpe_rma_readv##_name(struct fid_ep *fid_ep,		\
				     const struct iovec *iov,		\
				     void **desc, size_t count,		\
				     fi_addr_t src_addr,		\
				     uint64_t raddr, uint64_t rkey,	\
				     void *op_context)			\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt);			\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
	struct fi_rma_iov	rma_iov;				\
	uint64_t		total;					\
									\
	zhpe_stats_start(zhpe_stats_subid(RMA, 0));			\
									\
	if (OFI_UNLIKELY(count > ZHPE_EP_MAX_IOV ||			\
			 (count && (!iov || !desc)))) {			\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	ret = zhpe_get_uiov_len(iov, count, &total);			\
	if (OFI_UNLIKELY(ret < 0))					\
		goto done;						\
									\
	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = zctx->util_ep.tx_op_flags | FI_READ;			\
									\
	rma_iov.addr = raddr;						\
	rma_iov.key = rkey;						\
	rma_iov.len = total;						\
									\
	ret = rma_iov_op(zctx, op_context, 0,				\
			 op_flags, opt_flags, true,			\
			 iov, desc, count, &rma_iov, 1,			\
			 total, src_addr);				\
									\
 done:									\
	zhpe_stats_stop(zhpe_stats_subid(RMA, 0));			\
									\
	return ret;							\
}									\
									\
static ssize_t zhpe_rma_read##_name(struct fid_ep *fid_ep, void *buf,	\
				    size_t len,	void *desc,		\
				    fi_addr_t src_addr,			\
				    uint64_t raddr, uint64_t rkey,	\
				    void *op_context)			\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt);			\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
	struct iovec		msg_iov;				\
	struct fi_rma_iov	rma_iov;				\
									\
	zhpe_stats_start(zhpe_stats_subid(RMA, 0));			\
									\
	if (OFI_UNLIKELY(len && !buf)) {				\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = zctx->util_ep.tx_op_flags | FI_READ;			\
									\
	msg_iov.iov_base = buf;						\
	msg_iov.iov_len = len;						\
									\
	rma_iov.addr = raddr;						\
	rma_iov.key = rkey;						\
	rma_iov.len = len;						\
									\
	ret = rma_iov_op(zctx, op_context, 0,				\
			 op_flags, opt_flags, true,			\
			 &msg_iov, &desc, 1, &rma_iov, 1,		\
			 len, src_addr);				\
									\
 done:									\
	zhpe_stats_stop(zhpe_stats_subid(RMA, 0));			\
									\
	return ret;							\
}									\
									\
static ssize_t zhpe_rma_writemsg##_name(struct fid_ep *fid_ep,		\
					const struct fi_msg_rma *msg,	\
					uint64_t flags)			\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt);			\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
	uint64_t		bad_mask;				\
	uint64_t		total_uiov;				\
	uint64_t		total;					\
									\
	zhpe_stats_start(zhpe_stats_subid(RMA, 0));			\
									\
	bad_mask = ~(WR_FLAGS |						\
		     ((opt_flags & ZHPE_OPT_FENCE) ? FI_FENCE : 0));	\
	if (OFI_UNLIKELY(!msg || msg->iov_count > ZHPE_EP_MAX_IOV ||	\
			 (msg->iov_count && !msg->msg_iov) ||		\
			 msg->rma_iov_count > ZHPE_EP_MAX_IOV ||	\
			 (msg->rma_iov_count && !msg->rma_iov) ||	\
			 (flags & bad_mask))) {				\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	ret = zhpe_get_uiov_len(msg->msg_iov, msg->iov_count,		\
				&total_uiov);				\
	if (OFI_UNLIKELY(ret < 0))					\
		goto done;						\
	ret = zhpe_get_urma_len(msg->rma_iov, msg->rma_iov_count,	\
				&total);				\
	if (OFI_UNLIKELY(ret < 0))					\
		goto done;						\
	if (total_uiov != total) {					\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = flags | zctx->util_ep.tx_msg_flags | FI_WRITE;	\
									\
	ret = rma_iov_op(zctx, msg->context, msg->data,			\
			 op_flags, opt_flags, false,			\
			 msg->msg_iov, msg->desc, msg->iov_count,	\
			 msg->rma_iov, msg->rma_iov_count,		\
			 total, msg->addr);				\
									\
 done:									\
	zhpe_stats_stop(zhpe_stats_subid(RMA, 0));			\
									\
	return ret;							\
}									\
									\
static ssize_t zhpe_rma_writev##_name(struct fid_ep *fid_ep,		\
				      const struct iovec *iov,		\
				      void **desc, size_t count,	\
				      fi_addr_t dst_addr,		\
				      uint64_t raddr, uint64_t rkey,	\
				      void *op_context)			\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt);			\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
	struct fi_rma_iov	rma_iov;				\
	uint64_t		total;					\
									\
	zhpe_stats_start(zhpe_stats_subid(RMA, 0));			\
									\
	if (OFI_UNLIKELY(count > ZHPE_EP_MAX_IOV ||			\
			 (count && (!iov || !desc)))) {			\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	ret = zhpe_get_uiov_len(iov, count, &total);			\
	if (OFI_UNLIKELY(ret < 0))					\
		goto done;						\
									\
	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = zctx->util_ep.tx_op_flags | FI_WRITE;		\
									\
	rma_iov.addr = raddr;						\
	rma_iov.key = rkey;						\
	rma_iov.len = total;						\
									\
	ret = rma_iov_op(zctx, op_context, 0,				\
			 op_flags, opt_flags, false,			\
			 iov, desc, count, &rma_iov, 1,			\
			 total, dst_addr);				\
									\
 done:									\
	zhpe_stats_stop(zhpe_stats_subid(RMA, 0));			\
									\
	return ret;							\
}									\
									\
static ssize_t zhpe_rma_write##_name(struct fid_ep *fid_ep,		\
				     const void *buf, size_t len,	\
				     void *desc, fi_addr_t dst_addr,	\
				     uint64_t raddr, uint64_t rkey,	\
				     void *op_context)			\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt);			\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
	struct iovec		msg_iov;				\
	struct fi_rma_iov	rma_iov;				\
									\
	zhpe_stats_start(zhpe_stats_subid(RMA, 0));			\
									\
	if (OFI_UNLIKELY(len && !buf)) {				\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = zctx->util_ep.tx_op_flags | FI_WRITE;		\
									\
	msg_iov.iov_base = (void *)buf;					\
	msg_iov.iov_len = len;						\
									\
	rma_iov.addr = raddr;						\
	rma_iov.key = rkey;						\
	rma_iov.len = len;						\
									\
	ret = rma_iov_op(zctx, op_context, 0,				\
			 op_flags, opt_flags, false,			\
			 &msg_iov, &desc, 1, &rma_iov, 1,		\
			 len, dst_addr);				\
									\
 done:									\
	zhpe_stats_stop(zhpe_stats_subid(RMA, 0));			\
									\
	return ret;							\
}									\
									\
static ssize_t zhpe_rma_writedata##_name(struct fid_ep *fid_ep,		\
					 const void *buf, size_t len,	\
					 void *desc, uint64_t cq_data,	\
					 fi_addr_t dst_addr,		\
					 uint64_t raddr, uint64_t rkey,	\
					 void *op_context)		\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt);			\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
	struct iovec		msg_iov;				\
	struct fi_rma_iov	rma_iov;				\
									\
	zhpe_stats_start(zhpe_stats_subid(RMA, 0));			\
									\
	if (OFI_UNLIKELY(len && !buf)) {				\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = (zctx->util_ep.tx_op_flags | FI_WRITE |		\
		    FI_REMOTE_CQ_DATA);					\
									\
	msg_iov.iov_base = (void *)buf;					\
	msg_iov.iov_len = len;						\
									\
	rma_iov.addr = raddr;						\
	rma_iov.key = rkey;						\
	rma_iov.len = len;						\
									\
	ret = rma_iov_op(zctx, op_context, cq_data,			\
			 op_flags, opt_flags, false,			\
			 &msg_iov, &desc, 1, &rma_iov, 1,		\
			 len, dst_addr);				\
									\
 done:									\
	zhpe_stats_stop(zhpe_stats_subid(RMA, 0));			\
									\
	return ret;							\
}									\
									\
static ssize_t zhpe_rma_inject##_name(struct fid_ep *fid_ep,		\
				      const void *buf, size_t len,	\
				      fi_addr_t dst_addr,		\
				      uint64_t raddr, uint64_t rkey)	\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt);			\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
	struct iovec		msg_iov;				\
	struct fi_rma_iov	rma_iov;				\
									\
	zhpe_stats_start(zhpe_stats_subid(RMA, 0));			\
									\
	if (OFI_UNLIKELY(len && !buf)) {				\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	if (len > ZHPE_MAX_IMM) {					\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = zctx->util_ep.inject_op_flags | FI_WRITE;		\
									\
	msg_iov.iov_base = (void *)buf;					\
	msg_iov.iov_len = len;						\
									\
	rma_iov.addr = raddr;						\
	rma_iov.key = rkey;						\
	rma_iov.len = len;						\
									\
	ret = rma_iov_op(zctx, NULL, 0,					\
			 op_flags, opt_flags, false,			\
			 &msg_iov, NULL, 1, &rma_iov, 1,		\
			 len, dst_addr);				\
									\
	zhpe_stats_stop(zhpe_stats_subid(RMA, 0));			\
									\
 done:									\
	return ret;							\
}									\
									\
static ssize_t								\
zhpe_rma_injectdata##_name(struct fid_ep *fid_ep,			\
			   const void *buf, size_t len,			\
			   uint64_t cq_data, fi_addr_t dst_addr,	\
			   uint64_t raddr, uint64_t rkey)		\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt);			\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
	struct iovec		msg_iov;				\
	struct fi_rma_iov	rma_iov;				\
									\
	zhpe_stats_start(zhpe_stats_subid(RMA, 0));			\
									\
	if (OFI_UNLIKELY(len && !buf)) {				\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	if (len > ZHPE_MAX_IMM) {					\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = (zctx->util_ep.inject_op_flags | FI_WRITE |		\
		    FI_REMOTE_CQ_DATA);					\
									\
	msg_iov.iov_base = (void *)buf;					\
	msg_iov.iov_len = len;						\
									\
	rma_iov.addr = raddr;						\
	rma_iov.key = rkey;						\
	rma_iov.len = len;						\
									\
	ret = rma_iov_op(zctx, NULL, cq_data,				\
			 op_flags, opt_flags, false,			\
			 &msg_iov, NULL, 1, &rma_iov, 1,		\
			 len, dst_addr);				\
									\
	zhpe_stats_stop(zhpe_stats_subid(RMA, 0));			\
									\
 done:									\
	return ret;							\
}									\
									\
struct fi_ops_rma zhpe_ep_rma##_name##_ops = {				\
	.size			= sizeof(struct fi_ops_rma),		\
	.read			= zhpe_rma_read##_name,			\
	.readv			= zhpe_rma_readv##_name,		\
	.readmsg		= zhpe_rma_readmsg##_name,		\
	.write			= zhpe_rma_write##_name,		\
	.writev			= zhpe_rma_writev##_name,		\
	.writemsg		= zhpe_rma_writemsg##_name,		\
	.inject			= zhpe_rma_inject##_name,		\
	.injectdata		= zhpe_rma_injectdata##_name,		\
	.writedata		= zhpe_rma_writedata##_name,		\
}

RMA_OPS(  , 0);
RMA_OPS(_f, ZHPE_OPT_FENCE);

struct fi_ops_rma zhpe_ep_rma_bad_ops = {
	.size			= sizeof(struct fi_ops_rma),
	.read			= fi_no_rma_read,
	.readv			= fi_no_rma_readv,
	.readmsg		= fi_no_rma_readmsg,
	.write			= fi_no_rma_write,
	.writev			= fi_no_rma_writev,
	.writemsg		= fi_no_rma_writemsg,
	.inject			= fi_no_rma_inject,
	.injectdata		= fi_no_rma_injectdata,
	.writedata		= fi_no_rma_writedata,
};
