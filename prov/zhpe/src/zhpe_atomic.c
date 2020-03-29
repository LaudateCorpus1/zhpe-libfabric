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

/* Assumptions. */
static_assert(FI_DATATYPE_LAST <= UINT8_MAX, "FI_DATATYPE_LAST");
static_assert(FI_ATOMIC_OP_LAST <= UINT8_MAX, "FI_ATOMIC_OP_LAST");
static_assert(sizeof(float) == 4, "float");
static_assert(sizeof(double) == 8, "float");

struct atomic_op {
	uint64_t		operands[2];
	uint64_t		raddr;
	uint64_t		rkey;
	uint8_t			fi_op;
	uint8_t			fi_type;
	uint8_t			bytes;
	uint8_t			hw_op;
	uint8_t			hw_type;
	uint8_t			hw_handler;
	bool			hw_fam_only;
};

static int get_atomic_1op(struct atomic_op *aop, enum fi_datatype datatype,
			  enum fi_op op, const void *op0)
{
	if (OFI_UNLIKELY(!op0))
		return -FI_EINVAL;

	switch (datatype) {

	case FI_INT8:
	case FI_UINT8:
		aop->fi_type = FI_UINT8;
		aop->bytes = sizeof(uint8_t);
		zhpeu_fab_atomic_load(aop->fi_type, op0, &aop->operands[0]);
		aop->hw_type = ZHPEQ_ATOMIC_SIZE_NONE;
		break;

	case FI_INT16:
	case FI_UINT16:
		aop->fi_type = FI_UINT16;
		aop->bytes = sizeof(uint16_t);
		zhpeu_fab_atomic_load(aop->fi_type, op0, &aop->operands[0]);
		aop->hw_type = ZHPEQ_ATOMIC_SIZE_NONE;
		break;

	case FI_INT32:
	case FI_UINT32:
		aop->fi_type = FI_UINT32;
		aop->bytes = sizeof(uint32_t);
		zhpeu_fab_atomic_load(aop->fi_type, op0, &aop->operands[0]);
		aop->hw_type = ZHPEQ_ATOMIC_SIZE32;
		aop->hw_handler = ZHPE_TX_HANDLE_ATM_HW_RES32;
		break;

	case FI_INT64:
	case FI_UINT64:
		aop->fi_type = FI_UINT64;
		aop->bytes = sizeof(uint64_t);
		zhpeu_fab_atomic_load(aop->fi_type, op0, &aop->operands[0]);
		aop->hw_type = ZHPEQ_ATOMIC_SIZE64;
		aop->hw_handler = ZHPE_TX_HANDLE_ATM_HW_RES64;
		break;

	case FI_FLOAT:
		/* ZZZ: if this works on x86, it won't be portable. */
		if (OFI_UNLIKELY(op != FI_ATOMIC_READ && op != FI_ATOMIC_WRITE))
			return -FI_EOPNOTSUPP;
		aop->fi_type = FI_FLOAT;
		aop->bytes = sizeof(float);
		zhpeu_fab_atomic_load(FI_UINT32, op0, &aop->operands[0]);
		aop->hw_type = ZHPEQ_ATOMIC_SIZE32;
		aop->hw_handler = ZHPE_TX_HANDLE_ATM_HW_RES32;
		break;

	case FI_DOUBLE:
		/* ZZZ: if this works on x86, it won't be portable. */
		if (OFI_UNLIKELY(op != FI_ATOMIC_READ && op != FI_ATOMIC_WRITE))
			return -FI_EOPNOTSUPP;
		aop->fi_type = FI_DOUBLE;
		aop->bytes = sizeof(double);
		zhpeu_fab_atomic_load(FI_UINT64, op0, &aop->operands[0]);
		aop->hw_type = ZHPEQ_ATOMIC_SIZE64;
		aop->hw_handler = ZHPE_TX_HANDLE_ATM_HW_RES64;
		break;

	default:
		return -FI_EOPNOTSUPP;
	}

	aop->fi_op = op;

	switch (op) {

	case FI_ATOMIC_READ:
		aop->operands[0] = 0;
		aop->hw_op = ZHPEQ_ATOMIC_ADD;
		aop->hw_fam_only = false;
		break;

	case FI_ATOMIC_WRITE:
		aop->hw_op = ZHPEQ_ATOMIC_SWAP;
		aop->hw_fam_only = false;
		break;

	case FI_BAND:
		aop->hw_op = ZHPEQ_ATOMIC_AND;
		aop->hw_fam_only = true;
		break;

	case FI_BOR:
		aop->hw_op = ZHPEQ_ATOMIC_OR;
		aop->hw_fam_only = true;
		break;

	case FI_BXOR:
		aop->hw_op = ZHPEQ_ATOMIC_XOR;
		aop->hw_fam_only = true;
		break;

	case FI_SUM:
		aop->hw_op = ZHPEQ_ATOMIC_ADD;
		aop->hw_fam_only = false;
		break;

	default:
		return -FI_EOPNOTSUPP;
	}

	return 0;
}

static int get_atomic_2op(struct atomic_op *aop, enum fi_datatype datatype,
			  enum fi_op op, const void *op0, const void *op1)
{
	if (OFI_UNLIKELY(!op0 || !op1))
		return -FI_EINVAL;

	switch (datatype) {

	case FI_INT8:
	case FI_UINT8:
		aop->fi_type = FI_UINT8;
		aop->bytes = sizeof(uint8_t);
		zhpeu_fab_atomic_load(aop->fi_type, op0, &aop->operands[0]);
		zhpeu_fab_atomic_load(aop->fi_type, op1, &aop->operands[1]);
		aop->hw_type = ZHPEQ_ATOMIC_SIZE_NONE;
		break;

	case FI_INT16:
	case FI_UINT16:
		aop->fi_type = FI_UINT16;
		aop->bytes = sizeof(uint16_t);
		zhpeu_fab_atomic_load(aop->fi_type, op0, &aop->operands[0]);
		zhpeu_fab_atomic_load(aop->fi_type, op1, &aop->operands[1]);
		aop->hw_type = ZHPEQ_ATOMIC_SIZE_NONE;
		break;

	case FI_INT32:
	case FI_UINT32:
		aop->fi_type = FI_UINT32;
		aop->bytes = sizeof(uint32_t);
		zhpeu_fab_atomic_load(aop->fi_type, op0, &aop->operands[0]);
		zhpeu_fab_atomic_load(aop->fi_type, op1, &aop->operands[1]);
		aop->hw_type = ZHPEQ_ATOMIC_SIZE32;
		aop->hw_handler = ZHPE_TX_HANDLE_ATM_HW_RES32;
		break;

	case FI_INT64:
	case FI_UINT64:
		aop->fi_type = FI_UINT64;
		aop->bytes = sizeof(uint64_t);
		zhpeu_fab_atomic_load(aop->fi_type, op0, &aop->operands[0]);
		zhpeu_fab_atomic_load(aop->fi_type, op1, &aop->operands[1]);
		aop->hw_type = ZHPEQ_ATOMIC_SIZE64;
		aop->hw_handler = ZHPE_TX_HANDLE_ATM_HW_RES64;
		break;

	default:
		return -FI_EOPNOTSUPP;
	}

	aop->fi_op = op;
	aop->hw_fam_only = false;

	switch (op) {

	case FI_CSWAP:
		aop->hw_op = ZHPEQ_ATOMIC_CAS;
		break;

	case FI_MSWAP:
		aop->hw_op = ZHPEQ_ATOMIC_NONE;

 		switch (aop->fi_type) {

 		case ZHPEQ_ATOMIC_SIZE32:
			if (OFI_LIKELY((uint32_t)aop->operands[0] ==
				       ~(uint32_t)0)) {
				aop->operands[0] = aop->operands[1];
 				aop->hw_op = ZHPEQ_ATOMIC_SWAP;
			}
 			break;

 		case ZHPEQ_ATOMIC_SIZE64:
			if (OFI_LIKELY((uint64_t)aop->operands[0] ==
				       ~(uint64_t)0)) {
				aop->operands[0] = aop->operands[1];
 				aop->hw_op = ZHPEQ_ATOMIC_SWAP;
			}
 			break;

		default:
			break;
		}

		break;

	default:
		return -FI_EOPNOTSUPP;
	}

	return 0;
}

static struct zhpe_tx_entry *get_tx_entry(struct zhpe_conn *conn,
					  uint64_t opt_flags, void *op_context,
					  uint handler)
{
	struct zhpe_tx_entry	*tx_entry;
	struct zhpe_tx_entry_ctx *tx_entry_ctx;

	if ((opt_flags & ZHPE_OPT_CONTEXT) && OFI_LIKELY(op_context != NULL)) {
		tx_entry = op_context;
		tx_entry->tx_handler = handler;
	} else {
		tx_entry_ctx = zhpe_buf_alloc(&conn->zctx->tx_ctx_pool);
		tx_entry_ctx->op_context = op_context;
		tx_entry = &tx_entry_ctx->tx_entry;
		tx_entry->tx_handler = handler + 1;
	}
	tx_entry->conn = conn;

	return tx_entry;
}

static void atomic_rkey_fixup(struct zhpe_tx_entry *tx_entry,
			      union zhpe_hw_wq_entry *wqe)
{
	struct zhpe_rkey	*rkey = tx_entry->ptrs[0];
	int			rc;
	uint32_t		qaccess;
	size_t			len;

	qaccess = (ZHPEQ_MR_GET_REMOTE | ZHPEQ_MR_PUT_REMOTE);
	len  = (wqe->atm.size == ZHPEQ_ATOMIC_SIZE64 ?
		sizeof(uint64_t) : sizeof(uint32_t));
	wqe->atm.rem_addr += rkey->offset;
	rc = zhpeq_rem_key_access(rkey->qkdata, wqe->atm.rem_addr, len,
				  qaccess, &wqe->atm.rem_addr);
	zhpe_cstat_update_status(&tx_entry->cstat, rc);
}

static void atomic_hw_msg(union zhpe_hw_wq_entry *wqe, struct atomic_op *aop);

struct atomic_rkey_wait_prep_data {
	struct zhpe_tx_entry	*tx_entry;
	struct zhpe_tx_queue_entry *txqe;
};

static void *atomic_rkey_wait_prep(void *prep_arg)
{
	struct atomic_rkey_wait_prep_data *prep = prep_arg;
	struct zhpe_tx_entry	*tx_entry = prep->tx_entry;
	struct zhpe_conn	*conn = tx_entry->conn;
	struct zhpe_ctx		*zctx = conn->zctx;

	prep->txqe = zhpe_buf_alloc(&zctx->tx_queue_pool);
	prep->txqe->tx_entry = tx_entry;
	tx_entry->cstat.flags |= ZHPE_CS_FLAG_KEY_WAIT;

	return prep->txqe;
}

static void atomic_rkey_wait_handler(void *handler_arg, int status)
{
	struct zhpe_tx_queue_entry *txqe = handler_arg;
	struct zhpe_tx_entry	*tx_entry = txqe->tx_entry;
	struct zhpe_conn	*conn = tx_entry->conn;
	struct zhpe_ctx		*zctx = conn->zctx;
	int32_t			res;
	union zhpe_hw_wq_entry	*wqe;

	assert(tx_entry->cstat.completions == 1);
	zhpe_cstat_update_status(&tx_entry->cstat, status);
	if (OFI_LIKELY(!tx_entry->cstat.status))
		atomic_rkey_fixup(tx_entry, &txqe->wqe);
	if (OFI_UNLIKELY(conn->eflags))
		zhpe_cstat_update_status(&tx_entry->cstat,
					 zhpe_conn_eflags_error(conn->eflags));
	if (OFI_UNLIKELY(tx_entry->cstat.status)) {
		dlist_remove(&txqe->dentry);
		zhpe_tx_call_handler_fake(tx_entry, 0);
		zhpe_buf_free(&zctx->tx_queue_pool, txqe);
		return;
	}
	tx_entry->cstat.flags &= ~ZHPE_CS_FLAG_KEY_WAIT;
	if (OFI_UNLIKELY(tx_entry->cstat.flags & ZHPE_CS_FLAG_FENCE))
		return;

	zctx->tx_queued++;
	res = zhpeq_tq_reserve(zctx->ztq_hi);
	if (OFI_UNLIKELY(res < 0)) {
		assert_always(res == -EAGAIN);
		if (!(tx_entry->cstat.flags & ZHPE_CS_FLAG_QUEUED)) {
			tx_entry->cstat.flags |= ZHPE_CS_FLAG_QUEUED;
			/* Insert in front of any fenced I/Os. */
			dlist_insert_head(&txqe->dentry, &conn->tx_queue);
		}
		return;
	}
	conn->tx_queued++;
	wqe = zhpeq_tq_get_wqe(zctx->ztq_hi, res);
	zhpeq_tq_set_context(zctx->ztq_hi, res, tx_entry);
	memcpy(wqe, &txqe->wqe, sizeof(*wqe));
	zhpeq_tq_insert(zctx->ztq_hi, res);
	zhpeq_tq_commit(zctx->ztq_hi);
	zctx->hw_atomics++;
	zhpe_buf_free(&zctx->tx_queue_pool, txqe);
}

static void atomic_hw_msg(union zhpe_hw_wq_entry *wqe, struct atomic_op *aop)
{
	struct zhpe_hw_wq_atomic *aqe;

	aqe = zhpeq_tq_atomic(wqe, 0, aop->hw_type, aop->hw_op, aop->raddr);

	if (OFI_LIKELY(aop->hw_type == ZHPEQ_ATOMIC_SIZE64)) {
		aqe->operands64[0] = aop->operands[0];
		aqe->operands64[1] = aop->operands[1];
	} else {
		aqe->operands32[0] = aop->operands[0];
		aqe->operands32[1] = aop->operands[1];
	}
}

static void atomic_hw(struct zhpe_conn *conn, struct atomic_op *aop,
		      uint64_t op_flags, uint64_t opt_flags,
		      void *op_context, void *result)
{
	struct zhpe_ctx		*zctx = conn->zctx;
	struct zhpe_tx_entry	*tx_entry;
	int32_t			reservation[1];
	union zhpe_hw_wq_entry	*wqe[1];
	uint8_t			cs_flags;
	struct zhpe_rkey	*rkey;
	struct atomic_rkey_wait_prep_data wait_prep;

	if (OFI_LIKELY(op_flags & FI_COMPLETION))
		cs_flags = ZHPE_CS_FLAG_COMPLETION;
	else
		cs_flags = 0;
	/* We need a real completion structure for rkey tracking. */
	tx_entry = get_tx_entry(conn, opt_flags, op_context, aop->hw_handler);
	zhpe_cstat_init(&tx_entry->cstat, 1, cs_flags);
	tx_entry->ptrs[1] = result;

	wait_prep.tx_entry = tx_entry;
	rkey = zhpe_rma_rkey_lookup(conn, aop->rkey, atomic_rkey_wait_prep,
				    atomic_rkey_wait_handler, &wait_prep);
	tx_entry->ptrs[0] = rkey;

	zhpe_conn_fence_check(tx_entry, opt_flags, op_flags);

	if (OFI_LIKELY(rkey->qkdata != NULL)) {
		zhpe_tx_reserve(zctx->ztq_hi, tx_entry, 1, wqe,	reservation);
		atomic_hw_msg(wqe[0], aop);
		atomic_rkey_fixup(tx_entry, wqe[0]);
		zhpeq_tq_insert(zctx->ztq_hi, reservation[0]);
		zhpeq_tq_commit(zctx->ztq_hi);
		zctx->hw_atomics++;
	} else {
		atomic_hw_msg(&wait_prep.txqe->wqe, aop);
		if (tx_entry->cstat.flags & ZHPE_CS_FLAG_FENCE) {
			tx_entry->cstat.flags |= ZHPE_CS_FLAG_QUEUED;
			zctx->tx_queued++;
			dlist_insert_tail(&wait_prep.txqe->dentry,
					  &conn->tx_queue);
		}
	}
}

static void atomic_em(struct zhpe_conn *conn, struct atomic_op *aop,
		      uint64_t op_flags, uint64_t opt_flags,
		      void *op_context, void *result)
{
	struct zhpe_ctx		*zctx = conn->zctx;
	struct zhpe_tx_entry	*tx_entry;
	int32_t			reservation[1];
	union zhpe_hw_wq_entry	*wqe[1];
	uint8_t			cs_flags;
	uint8_t			op_zflags;
	struct zhpe_msg		*msg;
	struct zhpe_msg_atomic_request *areq;

	if (OFI_LIKELY(op_flags & FI_COMPLETION))
		cs_flags = ZHPE_CS_FLAG_COMPLETION | ZHPE_CS_FLAG_REMOTE_STATUS;
	else
		cs_flags = 0;
	/* Do we need a real completion structure? */
	if (OFI_LIKELY(result || cs_flags)) {
		/* Yes. */
		tx_entry = get_tx_entry(conn, opt_flags, op_context,
					ZHPE_TX_HANDLE_ATM_EM);
		tx_entry->cmp_idx = 0;
		op_zflags = ZHPE_OP_FLAG_DELIVERY_COMPLETE;
		zhpe_cstat_init(&tx_entry->cstat, 2, cs_flags);
		tx_entry->ptrs[1] = result;
	} else
		/* No: use shared inject structure. */
		tx_entry = &conn->tx_entry_inject;

	zhpe_conn_fence_check(tx_entry, opt_flags, op_flags);

	zhpe_tx_reserve(zctx->ztq_hi, tx_entry, 1, wqe, reservation);

	msg = zhpeq_tq_enqa(wqe[0], 0, conn->tkey.rem_gcid, conn->rem_rspctxid);
	zhpe_msg_hdr_init(&msg->hdr, ZHPE_OP_ATOMIC_REQUEST, op_zflags,
			  0, 0, conn->rem_conn_idxn,
			  htons(tx_entry->cmp_idx), conn->tx_seq++);

	areq = (void *)msg->payload;
	areq->operandsn[0] = htobe64(aop->operands[0]);
	areq->operandsn[1] = htobe64(aop->operands[1]);
	areq->raddrn = htobe64(aop->raddr);
	areq->rkeyn = htobe64(aop->rkey);
	areq->fi_op = aop->fi_op;
	areq->fi_type = aop->fi_type;
	areq->bytes = aop->bytes;

	zhpeq_tq_insert(zctx->ztq_hi, reservation[0]);
	zhpeq_tq_commit(zctx->ztq_hi);
}

static int atomic_op(struct zhpe_ctx *zctx,  struct atomic_op *aop,
		     uint64_t op_flags, uint64_t opt_flags,
		     void *op_context, void *result, fi_addr_t dst_addr)
{
	struct zhpe_conn	*conn;
	int			rc;

	if (OFI_UNLIKELY(zctx->zep->disabled))
		return -FI_EOPBADSTATE;

	zctx_lock(zctx);
	zhpe_stats_start(zhpe_stats_subid(ATM, 10));
	conn = zhpe_conn_av_lookup(zctx, dst_addr);
	zhpe_stats_stop(zhpe_stats_subid(ATM, 10));
	if (OFI_UNLIKELY(conn->eflags)) {
		rc = zhpe_conn_eflags_error(conn->eflags);
		zctx_unlock(zctx);
		return rc;
	}

	if (OFI_LIKELY(aop->hw_op != ZHPEQ_ATOMIC_NONE &&
		       aop->hw_type != ZHPEQ_ATOMIC_SIZE_NONE &&
		       !(aop->hw_fam_only && !conn->fam)))
		atomic_hw(conn, aop, op_flags, opt_flags, op_context, result);
	else if (OFI_LIKELY(!conn->fam))
		atomic_em(conn, aop, op_flags, opt_flags, op_context, result);
	else {
		zctx_unlock(zctx);
		return -FI_EOPNOTSUPP;
	}

	zctx->pe_ctx_ops->signal(zctx);
	zctx_unlock(zctx);

	return 0;
}

static int zhpe_atomic_valid(struct fid_ep *fid_ep, enum fi_datatype datatype,
			     enum fi_op op, size_t *count)
{
	struct fi_atomic_attr attr;
	int ret;

	/* domain parameter is ignored - okay to pass in NULL */
	ret = zhpe_query_atomic(NULL, datatype, op, &attr, 0);
	if (!ret)
		*count = attr.count;

	return ret;
}

static int zhpe_atomic_fetch_valid(struct fid_ep *fid_ep,
				   enum fi_datatype datatype, enum fi_op op,
				   size_t *count)
{
	struct fi_atomic_attr attr;
	int ret;

	/* domain parameter is ignored - okay to pass in NULL */
	ret = zhpe_query_atomic(NULL, datatype, op, &attr, FI_FETCH_ATOMIC);
	if (!ret)
		*count = attr.count;

	return ret;
}

static int zhpe_atomic_cswap_valid(struct fid_ep *fid_ep,
				   enum fi_datatype datatype, enum fi_op op,
				   size_t *count)
{
	struct fi_atomic_attr attr;
	int ret;

	/* domain parameter is ignored - okay to pass in NULL */
	ret = zhpe_query_atomic(NULL, datatype, op, &attr, FI_COMPARE_ATOMIC);
	if (!ret)
		*count = attr.count;

	return ret;
}

#define ATM_FLAGS	(ZHPE_EP_TX_OP_FLAGS | FI_MORE)

#define ATM_OPS(_name, _opt)						\
									\
static ssize_t								\
zhpe_atomic_writemsg##_name(struct fid_ep *fid_ep,			\
			    const struct fi_msg_atomic *msg,		\
			    uint64_t flags)				\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt);			\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
	uint64_t		bad_mask;				\
	const void		*op0;					\
	struct atomic_op	aop;					\
									\
	zhpe_stats_start(zhpe_stats_subid(RMA, 0));			\
									\
	bad_mask = ~(ATM_FLAGS |					\
		     ((opt_flags & ZHPE_OPT_FENCE) ? FI_FENCE : 0));	\
	if (OFI_UNLIKELY(!msg || !msg->msg_iov || !msg->rma_iov ||	\
			 msg->iov_count != 1 ||				\
			 msg->msg_iov[0].count != 1 ||			\
			 msg->rma_iov_count != 1 ||			\
			 msg->rma_iov[0].count != 1 ||			\
			 (flags & bad_mask))) {				\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	op0 = msg->msg_iov[0].addr;					\
	ret = get_atomic_1op(&aop, msg->datatype, msg->op, op0);	\
	if (OFI_UNLIKELY(ret < 0))					\
		goto done;						\
									\
	aop.raddr = msg->rma_iov[0].addr;				\
	aop.rkey = msg->rma_iov[0].key;					\
									\
	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = flags | zctx->util_ep.tx_msg_flags;			\
									\
	ret = atomic_op(zctx, &aop, op_flags, opt_flags,		\
			msg->context, NULL, msg->addr);			\
									\
 done:									\
	zhpe_stats_stop(zhpe_stats_subid(RMA, 0));			\
									\
	return ret;							\
}									\
									\
static ssize_t								\
zhpe_atomic_writev##_name(struct fid_ep *fid_ep,			\
			  const struct fi_ioc *iov,			\
			  void **desc, size_t count,			\
			  fi_addr_t dst_addr, uint64_t raddr,		\
			  uint64_t rkey, enum fi_datatype datatype,	\
			  enum fi_op op, void *op_context)		\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt);			\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
	const void		*op0;					\
	struct atomic_op	aop;					\
									\
	zhpe_stats_start(zhpe_stats_subid(RMA, 0));			\
									\
	if (OFI_UNLIKELY(!iov || !desc || count != 1 ||			\
			 iov[0].count != 1)) {				\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	op0 = iov[0].addr;						\
	ret = get_atomic_1op(&aop, datatype, op, op0);			\
	if (OFI_UNLIKELY(ret < 0))					\
		goto done;						\
									\
	aop.raddr = raddr;						\
	aop.rkey = rkey;						\
									\
	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = zctx->util_ep.tx_msg_flags;				\
									\
	ret = atomic_op(zctx, &aop, op_flags, opt_flags,		\
			op_context, NULL, dst_addr);			\
									\
 done:									\
	zhpe_stats_stop(zhpe_stats_subid(RMA, 0));			\
									\
	return ret;							\
}									\
									\
static ssize_t								\
zhpe_atomic_write##_name(struct fid_ep *fid_ep, const void *buf,	\
			 size_t count, void *desc, fi_addr_t dst_addr,	\
			 uint64_t raddr, uint64_t rkey,			\
			 enum fi_datatype datatype, enum fi_op op,	\
			 void *op_context)				\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt);			\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
	const void		*op0;					\
	struct atomic_op	aop;					\
									\
	zhpe_stats_start(zhpe_stats_subid(RMA, 0));			\
									\
	if (OFI_UNLIKELY(!buf || count != 1)) {				\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	op0 = buf;							\
	ret = get_atomic_1op(&aop, datatype, op, op0);			\
	if (OFI_UNLIKELY(ret < 0))					\
		goto done;						\
									\
	aop.raddr = raddr;						\
	aop.rkey = rkey;						\
									\
	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = zctx->util_ep.tx_msg_flags;				\
									\
	ret = atomic_op(zctx, &aop, op_flags, opt_flags,		\
			op_context, NULL, dst_addr);			\
									\
 done:									\
	zhpe_stats_stop(zhpe_stats_subid(RMA, 0));			\
									\
	return ret;							\
}									\
									\
static ssize_t								\
zhpe_atomic_inject##_name(struct fid_ep *fid_ep, const void *buf,	\
			  size_t count, fi_addr_t dst_addr,		\
			  uint64_t raddr, uint64_t rkey,		\
			  enum fi_datatype datatype, enum fi_op op)	\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt);			\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
	const void		*op0;					\
	struct atomic_op	aop;					\
									\
	zhpe_stats_start(zhpe_stats_subid(RMA, 0));			\
									\
	if (OFI_UNLIKELY(!buf || count != 1)) {				\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	op0 = buf;							\
	ret = get_atomic_1op(&aop, datatype, op, op0);			\
	if (OFI_UNLIKELY(ret < 0))					\
		goto done;						\
									\
	aop.raddr = raddr;						\
	aop.rkey = rkey;						\
									\
	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = zctx->util_ep.tx_msg_flags;				\
									\
	ret = atomic_op(zctx, &aop, op_flags, opt_flags,		\
			NULL, NULL, dst_addr);				\
									\
 done:									\
	zhpe_stats_stop(zhpe_stats_subid(RMA, 0));			\
									\
	return ret;							\
}									\
									\
static ssize_t								\
zhpe_atomic_fetchmsg##_name(struct fid_ep *fid_ep,			\
			    const struct fi_msg_atomic *msg,		\
			    struct fi_ioc *resultv,			\
			    void **result_desc,				\
			    size_t result_count, uint64_t flags)	\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt);			\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
	uint64_t		bad_mask;				\
	const void		*op0;					\
	void			*result;				\
	struct atomic_op	aop;					\
									\
	zhpe_stats_start(zhpe_stats_subid(RMA, 0));			\
									\
	bad_mask = ~(ATM_FLAGS |					\
		     ((opt_flags & ZHPE_OPT_FENCE) ? FI_FENCE : 0));	\
	if (OFI_UNLIKELY(!msg || !msg->msg_iov || !msg->rma_iov ||	\
			 !resultv || !result_desc ||			\
			 msg->iov_count != 1 ||				\
			 msg->msg_iov[0].count != 1 ||			\
			 msg->rma_iov_count != 1 ||			\
			 msg->rma_iov[0].count != 1 ||			\
			 result_count != 1 || resultv[0].count != 1 ||	\
			 (flags & bad_mask))) {				\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
 									\
	op0 = msg->msg_iov[0].addr;					\
	ret = get_atomic_1op(&aop, msg->datatype, msg->op, op0);	\
	if (OFI_UNLIKELY(ret < 0))					\
		goto done;						\
									\
	aop.raddr = msg->rma_iov[0].addr;				\
	aop.rkey = msg->rma_iov[0].key;					\
	result = resultv[0].addr;					\
									\
	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = flags | zctx->util_ep.tx_msg_flags;			\
									\
	ret = atomic_op(zctx, &aop, op_flags, opt_flags,		\
			msg->context, result, msg->addr);		\
									\
 done:									\
	zhpe_stats_stop(zhpe_stats_subid(RMA, 0));			\
									\
	return ret;							\
}									\
 									\
static ssize_t								\
zhpe_atomic_fetchv##_name(struct fid_ep *fid_ep,			\
			  const struct fi_ioc *iov,			\
			  void **desc, size_t count,			\
			  struct fi_ioc *resultv, void **result_desc,	\
			  size_t result_count, fi_addr_t dst_addr,	\
			  uint64_t raddr, uint64_t rkey,		\
			  enum fi_datatype datatype, enum fi_op op,	\
			  void *op_context)				\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt);			\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
	const void		*op0;					\
	void			*result;				\
	struct atomic_op	aop;					\
									\
	zhpe_stats_start(zhpe_stats_subid(RMA, 0));			\
									\
	if (OFI_UNLIKELY(!iov || !desc || !resultv || !result_desc ||	\
			 count != 1 || iov[0].count != 1 ||		\
			 result_count != 1 ||				\
			 resultv[0].count != 1)) {			\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	op0 = iov[0].addr;						\
	ret = get_atomic_1op(&aop, datatype, op, op0);			\
	if (OFI_UNLIKELY(ret < 0))					\
		goto done;						\
									\
	aop.raddr = raddr;						\
	aop.rkey = rkey;						\
	result = resultv[0].addr;					\
									\
	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = zctx->util_ep.tx_msg_flags;				\
									\
	ret = atomic_op(zctx, &aop, op_flags, opt_flags,		\
			op_context, result, dst_addr);			\
									\
 done:									\
	zhpe_stats_stop(zhpe_stats_subid(RMA, 0));			\
									\
	return ret;							\
}									\
									\
static ssize_t								\
zhpe_atomic_fetch##_name(struct fid_ep *fid_ep, const void *buf,	\
			 size_t count, void *desc,			\
			 void *result, void *result_desc,		\
			 fi_addr_t dst_addr, uint64_t raddr,		\
			 uint64_t rkey,	enum fi_datatype datatype,	\
			 enum fi_op op, void *op_context)		\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt);			\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
	const void		*op0;					\
	struct atomic_op	aop;					\
									\
	zhpe_stats_start(zhpe_stats_subid(RMA, 0));			\
									\
	if (OFI_UNLIKELY(!buf || !result || count != 1)) {		\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	op0 = buf;							\
	ret = get_atomic_1op(&aop, datatype, op, op0);			\
	if (OFI_UNLIKELY(ret < 0))					\
		goto done;						\
									\
	aop.raddr = raddr;						\
	aop.rkey = rkey;						\
									\
	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = zctx->util_ep.tx_msg_flags;				\
									\
	ret = atomic_op(zctx, &aop, op_flags, opt_flags,		\
			op_context, result, dst_addr);			\
									\
 done:									\
	zhpe_stats_stop(zhpe_stats_subid(RMA, 0));			\
									\
	return ret;							\
}									\
									\
static ssize_t								\
zhpe_atomic_comparemsg##_name(struct fid_ep *fid_ep,			\
			      const struct fi_msg_atomic *msg,		\
			      const struct fi_ioc *comparev,		\
			      void **compare_desc,			\
			      size_t compare_count,			\
			      struct fi_ioc *resultv,			\
			      void **result_desc,			\
			      size_t result_count, uint64_t flags)	\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt);			\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
	uint64_t		bad_mask;				\
	const void		*op0;					\
	const void		*op1;					\
	void			*result;				\
	struct atomic_op	aop;					\
									\
	zhpe_stats_start(zhpe_stats_subid(RMA, 0));			\
									\
	bad_mask = ~(ATM_FLAGS |					\
		     ((opt_flags & ZHPE_OPT_FENCE) ? FI_FENCE : 0));	\
	if (OFI_UNLIKELY(!msg || !msg->msg_iov || !msg->rma_iov ||	\
			 !comparev || !compare_desc ||			\
			 !resultv || !result_desc ||			\
			 msg->iov_count != 1 ||				\
			 msg->msg_iov[0].count != 1 ||			\
			 msg->rma_iov_count != 1 ||			\
			 msg->rma_iov[0].count != 1 ||			\
			 compare_count != 1 ||				\
			 comparev[0].count != 1 ||			\
			 result_count != 1 || resultv[0].count != 1 ||	\
			 (flags & bad_mask))) {				\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
 									\
	op0 = comparev[0].addr;						\
	op1 = msg->msg_iov[0].addr;					\
	ret = get_atomic_2op(&aop, msg->datatype, msg->op, op0, op1);	\
	if (OFI_UNLIKELY(ret < 0))					\
		goto done;						\
									\
	aop.raddr = msg->rma_iov[0].addr;				\
	aop.rkey = msg->rma_iov[0].key;					\
	result = resultv[0].addr;					\
									\
	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = flags | zctx->util_ep.tx_msg_flags;			\
									\
	ret = atomic_op(zctx, &aop, op_flags, opt_flags,		\
			msg->context, result, msg->addr);		\
									\
 done:									\
	zhpe_stats_stop(zhpe_stats_subid(RMA, 0));			\
									\
	return ret;							\
}									\
									\
static ssize_t								\
zhpe_atomic_comparev##_name(struct fid_ep *fid_ep,			\
			    const struct fi_ioc *iov, void **desc,	\
			    size_t count,				\
			    const struct fi_ioc *comparev,		\
			    void **compare_desc, size_t compare_count,	\
			    struct fi_ioc *resultv, void **result_desc,	\
			    size_t result_count, fi_addr_t dst_addr,	\
			    uint64_t raddr, uint64_t rkey,		\
			    enum fi_datatype datatype, enum fi_op op,	\
			    void *op_context)				\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt);			\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
	const void		*op0;					\
	const void		*op1;					\
	void			*result;				\
	struct atomic_op	aop;					\
									\
	zhpe_stats_start(zhpe_stats_subid(RMA, 0));			\
									\
	if (OFI_UNLIKELY(!iov || !desc || !comparev || !compare_desc ||	\
			 !resultv || !result_desc ||			\
			 count != 1 || iov[0].count != 1 ||		\
			 compare_count != 1 ||				\
			 comparev[0].count != 1 ||			\
			 result_count != 1 ||				\
			 resultv[0].count != 1)) {			\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	op0 = comparev[0].addr;						\
	op1 = iov[0].addr;						\
	ret = get_atomic_2op(&aop, datatype, op, op0, op1);		\
	if (OFI_UNLIKELY(ret < 0))					\
		goto done;						\
									\
	aop.raddr = raddr;						\
	aop.rkey = rkey;						\
	result = resultv[0].addr;					\
									\
	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = zctx->util_ep.tx_msg_flags;				\
									\
	ret = atomic_op(zctx, &aop, op_flags, opt_flags,		\
			op_context, result, dst_addr);			\
									\
 done:									\
	zhpe_stats_stop(zhpe_stats_subid(RMA, 0));			\
									\
	return ret;							\
}									\
									\
static ssize_t								\
zhpe_atomic_compare##_name(struct fid_ep *fid_ep,			\
			   const void *buf, size_t count, void *desc,	\
			   const void *compare, void *compare_desc,	\
			   void *result, void *result_desc,		\
			   fi_addr_t dst_addr, uint64_t raddr,		\
			   uint64_t rkey, enum fi_datatype datatype,	\
			   enum fi_op op, void *op_context)		\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt);			\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
	const void		*op0;					\
	const void		*op1;					\
	struct atomic_op	aop;					\
									\
	zhpe_stats_start(zhpe_stats_subid(RMA, 0));			\
									\
	if (OFI_UNLIKELY(!buf || !compare || !result || count != 1)) {	\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	op0 = compare;							\
	op1 = buf;							\
	ret = get_atomic_2op(&aop, datatype, op, op0, op1);		\
	if (OFI_UNLIKELY(ret < 0))					\
		goto done;						\
									\
	aop.raddr = raddr;						\
	aop.rkey = rkey;						\
									\
	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = zctx->util_ep.tx_msg_flags;				\
									\
	ret = atomic_op(zctx, &aop, op_flags, opt_flags,		\
			op_context, result, dst_addr);			\
									\
 done:									\
	zhpe_stats_stop(zhpe_stats_subid(RMA, 0));			\
									\
	return ret;							\
}									\
									\
 struct fi_ops_atomic zhpe_ep_atomic##_name##_ops = {			\
	.size			= sizeof(struct fi_ops_atomic),		\
	.write			= zhpe_atomic_write##_name,		\
	.writev			= zhpe_atomic_writev##_name,		\
	.writemsg		= zhpe_atomic_writemsg##_name,		\
	.inject			= zhpe_atomic_inject##_name,		\
	.readwrite		= zhpe_atomic_fetch##_name,		\
	.readwritev		= zhpe_atomic_fetchv##_name,		\
	.readwritemsg		= zhpe_atomic_fetchmsg##_name,		\
	.compwrite		= zhpe_atomic_compare##_name,		\
	.compwritev		= zhpe_atomic_comparev##_name,		\
	.compwritemsg		= zhpe_atomic_comparemsg##_name,	\
	.writevalid		= zhpe_atomic_valid,			\
	.readwritevalid		= zhpe_atomic_fetch_valid,		\
	.compwritevalid		= zhpe_atomic_cswap_valid,		\
}

ATM_OPS(   , 0);
ATM_OPS(_f , ZHPE_OPT_FENCE);
ATM_OPS(_c , ZHPE_OPT_CONTEXT);
ATM_OPS(_cf, ZHPE_OPT_CONTEXT | ZHPE_OPT_FENCE);

struct fi_ops_atomic zhpe_ep_atomic_bad_ops = {
	.size			= sizeof(struct fi_ops_atomic),
	.write			= fi_no_atomic_write,
	.writev			= fi_no_atomic_writev,
	.writemsg		= fi_no_atomic_writemsg,
	.inject			= fi_no_atomic_inject,
	.readwrite		= fi_no_atomic_readwrite,
	.readwritev		= fi_no_atomic_readwritev,
	.readwritemsg		= fi_no_atomic_readwritemsg,
	.compwrite		= fi_no_atomic_compwrite,
	.compwritev		= fi_no_atomic_compwritev,
	.compwritemsg		= fi_no_atomic_compwritemsg,
	.writevalid		= fi_no_atomic_writevalid,
	.readwritevalid		= fi_no_atomic_readwritevalid,
	.compwritevalid		= fi_no_atomic_compwritevalid,
};

static int check_atomic_op_int(enum fi_op op)
{
	switch (op) {

	case FI_ATOMIC_READ:
	case FI_ATOMIC_WRITE:
	case FI_BAND:
	case FI_BOR:
	case FI_BXOR:
	case FI_CSWAP:
	case FI_MSWAP:
	case FI_SUM:
		return 0;

	default:
		return -FI_EOPNOTSUPP;
	}
}

static int check_atomic_op_float(enum fi_op op)
{
	switch (op) {

	case FI_ATOMIC_READ:
	case FI_ATOMIC_WRITE:
		return 0;

	default:
		return -FI_EOPNOTSUPP;
	}
}

/* Domain parameter is ignored, okay to pass in NULL */
int zhpe_query_atomic(struct fid_domain *domain,
		      enum fi_datatype datatype, enum fi_op op,
		      struct fi_atomic_attr *attr, uint64_t flags)
{
	int			ret;

	ret = ofi_atomic_valid(&zhpe_prov, datatype, op, flags);
	if (ret < 0)
		return ret;

	attr->count = 1;

	switch (datatype) {

	case FI_INT8:
	case FI_UINT8:
		attr->size = sizeof(uint8_t);
		ret = check_atomic_op_int(op);
		break;

	case FI_INT16:
	case FI_UINT16:
		attr->size = sizeof(uint16_t);
		ret = check_atomic_op_int(op);
		break;

	case FI_INT32:
	case FI_UINT32:
		attr->size = sizeof(uint32_t);
		ret = check_atomic_op_int(op);
		break;

	case FI_INT64:
	case FI_UINT64:
		attr->size = sizeof(uint64_t);
		ret = check_atomic_op_int(op);
		break;

	case FI_FLOAT:
		attr->size = sizeof(float);
		ret = check_atomic_op_float(op);
		break;

	case FI_DOUBLE:
		attr->size = sizeof(double);
		ret = check_atomic_op_float(op);
		break;

	default:
		ret = -FI_EOPNOTSUPP;
		break;
	}


	return ret;
}

int zhpe_atomic_op(enum fi_datatype type, enum fi_op op,
		   uint64_t operand0, uint64_t operand1,
		   void *dst, uint64_t *original)
{
    return zhpeu_fab_atomic_op(type, op, operand0, operand1,
			       dst, original);
}

int zhpe_atomic_load(enum fi_datatype type, const void *src, uint64_t *value)
{
    return zhpeu_fab_atomic_load(type, src, value);
}

int zhpe_atomic_store(enum fi_datatype type, void *dst, uint64_t value)
{
    return zhpeu_fab_atomic_store(type, dst, value);
}

int zhpe_atomic_copy(enum fi_datatype type, const void *src, void *dst)
{
    return zhpeu_fab_atomic_copy(type, src, dst);
}
