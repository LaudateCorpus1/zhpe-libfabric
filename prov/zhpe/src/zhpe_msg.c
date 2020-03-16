/*
 * Copyright (c) 2014-2015 Intel Corporation, Inc.  All rights reserved.
 * Copyright (c) 2017-2020 Hewlett Packard Enterprise Development LP.  All rights reserved.
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

#define ZHPE_SUBSYS	FI_LOG_EP_CTRL

/* Assumptions. */
static_assert(ZHPE_EP_MAX_IOV == 2, "iov_len");
static_assert(sizeof(struct zhpe_msg) == ZHPE_MAX_ENQA, "zhpe_msg");
static_assert(sizeof(struct zhpe_tx_entry) <= sizeof(struct fi_context),
	      "tx_entry");

static bool rx_match_any(struct zhpe_rx_match_info *user,
			 struct zhpe_rx_match_info *wire)
{
	return true;
}

static bool rx_match_src(struct zhpe_rx_match_info *user,
			 struct zhpe_rx_match_info *wire)
{
	return (user->conn == wire->conn);
}

static bool rx_match_tag(struct zhpe_rx_match_info *user,
			 struct zhpe_rx_match_info *wire)
{
	return ((user->tag & user->ignore) == (wire->tag & user->ignore));
}

static bool rx_match_tag_src(struct zhpe_rx_match_info *user,
			     struct zhpe_rx_match_info *wire)
{
	return (rx_match_tag(user, wire) && rx_match_src(user, wire));
}

static int rx_match_info_init(struct zhpe_ctx *zctx, uint64_t opt_flags,
			      struct zhpe_rx_match_info *minfo,
			      fi_addr_t src_addr, uint64_t tag, uint64_t ignore)
{
	if ((opt_flags & ZHPE_OPT_DIRECTED_RECV) &&
	    src_addr != FI_ADDR_UNSPEC) {
		zhpe_stats_start(zhpe_stats_subid(SEND, 10));
		minfo->conn = zhpe_conn_av_lookup(zctx, src_addr);
		zhpe_stats_stop(zhpe_stats_subid(SEND, 10));
		if (OFI_UNLIKELY(minfo->conn->eflags))
			return zhpe_conn_eflags_error(minfo->conn->eflags);

		if (opt_flags & ZHPE_OPT_TAGGED) {
			minfo->match_fn = rx_match_tag_src;
			minfo->tag = tag;
			minfo->ignore = ~ignore;
		} else
			minfo->match_fn = rx_match_src;
	} else {
		if (opt_flags & ZHPE_OPT_TAGGED) {
			minfo->match_fn = rx_match_tag;
			minfo->tag = tag;
			minfo->ignore = ~ignore;
		} else
			minfo->match_fn = rx_match_any;
	}

	return 0;
}

static int get_buf_zmr(struct zhpe_ctx *zctx, void *base, size_t len,
		       void *udesc, uint32_t qaccess, struct zhpe_mr **zmr_out)
{
	int			ret;
	struct zhpe_mr		*zmr;

	/* Optimize the potentially really slow case. */
	zmr = udesc;
	if (OFI_UNLIKELY(!zmr))
		ret = zhpe_dom_mr_reg(zctx2zdom(zctx), base, len, qaccess,
				      true, zmr_out);
	else {
		ret = zhpeq_lcl_key_access(zmr->qkdata, base, len, qaccess);
		if (OFI_LIKELY(ret >= 0)) {
			zhpe_dom_mr_get(zmr);
			*zmr_out = zmr;
		}
	}

	return ret;
}

int zhpe_get_uiov(struct zhpe_ctx *zctx,
		  const struct iovec *uiov, void **udesc, size_t uiov_cnt,
		  uint32_t qaccess, struct zhpe_iov3 *liov)
{
	int			rc;
	struct zhpe_mr		*zmr;

	assert(uiov_cnt > 0);
	assert(uiov_cnt <= ZHPE_EP_MAX_IOV);
	liov[0].iov_base = (uintptr_t)uiov[0].iov_base;
	liov[0].iov_len = uiov[0].iov_len;
	rc = get_buf_zmr(zctx, uiov[0].iov_base, uiov[0].iov_len,
			 udesc[0], qaccess, &zmr);
	liov[0].iov_desc = zmr;
	if (OFI_UNLIKELY(rc < 0))
		return rc;
	if (OFI_LIKELY(uiov_cnt == 1))
		return 1;
	liov[1].iov_base = (uintptr_t)uiov[1].iov_base;
	liov[1].iov_len = uiov[1].iov_len;
	rc = get_buf_zmr(zctx, uiov[1].iov_base, uiov[1].iov_len,
			 udesc[1], qaccess, &zmr);
	liov[1].iov_desc = zmr;
	if (OFI_UNLIKELY(rc < 0)) {
		zhpe_dom_mr_put(liov[0].iov_desc);
		return rc;
	}

	return 2;
}

int zhpe_get_uiov_maxlen(struct zhpe_ctx *zctx,
			 const struct iovec *uiov, void **udesc,
			 size_t uiov_cnt, uint32_t qaccess, uint64_t maxlen,
			 struct zhpe_iov3 *liov)
{
	int			rc;
	struct zhpe_mr		*zmr;
	uint64_t		len;

	assert(uiov_cnt > 0);
	assert(uiov_cnt <= ZHPE_EP_MAX_IOV);
	assert(maxlen > 0);
	liov[0].iov_base = (uintptr_t)uiov[0].iov_base;
	len = max((uint64_t)uiov[0].iov_len, maxlen);
	maxlen -= len;
	liov[0].iov_len = len;
	rc = get_buf_zmr(zctx, uiov[0].iov_base, len,
			 udesc[0], qaccess, &zmr);
	liov[0].iov_desc = zmr;
	if (OFI_UNLIKELY(rc < 0))
		return rc;
	if (OFI_LIKELY(uiov_cnt == 1))
		return 1;
	if (OFI_UNLIKELY(!maxlen))
		return 1;
	liov[1].iov_base = (uintptr_t)uiov[1].iov_base;
	len = max((uint64_t)uiov[1].iov_len, maxlen);
	maxlen -= len;
	liov[1].iov_len = len;
	rc = get_buf_zmr(zctx, uiov[1].iov_base, len,
			 udesc[1], qaccess, &zmr);
	liov[1].iov_desc = zmr;
	if (OFI_UNLIKELY(rc < 0)) {
		zhpe_dom_mr_put(liov[0].iov_desc);
		return rc;
	}

	return 2;
}

static int recv_peek_claim(struct zhpe_ctx *zctx,
			   const struct fi_msg_tagged *msg,
			   uint64_t op_flags, uint64_t opt_flags,
			   uint64_t peek_flags)
{
	int			rc;
	struct zhpe_rx_entry	*rx_wire;
	struct zhpe_rx_match_info user_info;

	if (OFI_UNLIKELY(zctx->zep->disabled))
		return -FI_EOPBADSTATE;

	op_flags |= FI_RECV | FI_TAGGED;

	switch (peek_flags) {

	case FI_CLAIM:
		if (OFI_UNLIKELY(!msg->context))
			return -FI_EINVAL;
		zctx_lock(zctx);
		rx_wire = ((struct fi_context *)msg->context)->internal[0];
		rx_wire->op_context = msg->context;
		rx_wire->op_flags |= op_flags;
		zhpe_rx_start_recv_user(rx_wire, msg->msg_iov, msg->desc,
					msg->iov_count);
		zctx_unlock(zctx);

		return 0;

	case FI_CLAIM | FI_DISCARD:
		if (OFI_UNLIKELY(!msg->context))
			return -FI_EINVAL;
		zctx_lock(zctx);
		rx_wire = ((struct fi_context *)msg->context)->internal[0];
		zhpe_cq_report_success(zctx->util_ep.rx_cq, FI_RECV | FI_TAGGED,
				       msg->context, 0, NULL, 0,
				       rx_wire->match_info.tag);
		zhpe_rx_discard_recv(rx_wire);
		zctx_unlock(zctx);

		return 0;

	case FI_PEEK | FI_CLAIM:
		if (OFI_UNLIKELY(!msg->context))
			return -FI_EINVAL;
		/* FALLTHROUGH */

	case FI_PEEK | FI_DISCARD:
	case FI_PEEK:
		/* We don't return data for FI_PEEK | FI_CLAIM. */
		zctx_lock(zctx);
		rc = rx_match_info_init(zctx, opt_flags, &user_info, msg->addr,
					 msg->tag, msg->ignore);
		if (OFI_LIKELY(rc >= 0)) {
			zhpe_rx_peek_recv(zctx, &user_info, op_flags,
					  msg->context);
			rc = 0;
			zctx_unlock(zctx);
		}

		return rc;

	default:
		return -FI_EINVAL;
	}
}

static int recv_iov(struct zhpe_ctx *zctx, const struct iovec *uiov,
		    void **udesc, size_t uiov_cnt,
		    fi_addr_t src_addr, void *op_context,
		    uint64_t tag, uint64_t ignore,
		    uint64_t op_flags, uint64_t opt_flags)
{
	int			rc;
	struct zhpe_rx_entry	*rx_user = NULL;
	struct zhpe_rx_entry	*rx_wire;
	struct zhpe_rx_match_info user_info;
	struct zhpe_rx_match_lists *match_lists;
	uint64_t		total_user;

	if (OFI_UNLIKELY(zctx->zep->disabled))
		return -FI_EOPBADSTATE;

	rc = zhpe_get_uiov_len(uiov, uiov_cnt, &total_user);
	if (OFI_UNLIKELY(rc < 0))
		return rc;

	if (opt_flags & ZHPE_OPT_TAGGED) {
		op_flags |= FI_RECV | FI_TAGGED;
		match_lists = &zctx->rx_match_tagged;
	} else {
		op_flags |= FI_RECV | FI_MSG;
		match_lists = &zctx->rx_match_untagged;
	}

	zctx_lock(zctx);
	rc = rx_match_info_init(zctx, opt_flags, &user_info, src_addr, tag,
				ignore);
	if (OFI_UNLIKELY(rc < 0)) {
		zctx_unlock(zctx);
		return rc;
	}

	zhpe_stats_start(zhpe_stats_subid(RECV, 40));
	dlist_foreach_container(&match_lists->wire_list,
				struct zhpe_rx_entry, rx_wire, dentry) {
		if (!user_info.match_fn(&user_info, &rx_wire->match_info))
			continue;
		ZHPE_LOG_DBG("rx_wire: %p ctx: %p flags: 0x%" PRIx64 "\n",
			     rx_wire, zctx, op_flags);
		dlist_remove(&rx_wire->dentry);
		dlist_insert_tail(&rx_wire->dentry, &zctx->rx_work_list);
		rx_wire->total_user = total_user;
		rx_wire->op_context = op_context;
		rx_wire->op_flags |= op_flags;
		zhpe_rx_start_recv_user(rx_wire, uiov, udesc, uiov_cnt);
		zhpe_stats_stop(zhpe_stats_subid(RECV, 40));
		zctx_unlock(zctx);

		return 0;
	}
	zhpe_stats_stop(zhpe_stats_subid(RECV, 40));

	rx_user = zhpe_rx_entry_alloc(zctx);
	rx_user->total_user = total_user;
	rx_user->op_context = op_context;
	rx_user->op_flags = op_flags;
	rx_user->match_info = user_info;
	rx_user->matched = false;
	dlist_insert_tail(&rx_user->dentry, &match_lists->user_list);
	ZHPE_LOG_DBG("rx_user: %p zctx: %p flags: 0x%" PRIx64 "\n",
		     rx_user, zctx, op_flags);
	if (OFI_UNLIKELY(!total_user)) {
		rx_user->lstate_ready = true;
		zctx_unlock(zctx);

		return 0;
	}

	rx_user->lstate_ready = false;
	/*
	 * Unfortunately, regardless of the length of the receive
	 * buffer, the sender can be trying to send a large message
	 * to a tiny buffer and we just won't know until later.
	 * Register/hold in the hope that there will be reuse.
	 *
	 * ZZZ: registration thread?
	 *
	 * Dropping the lock here adds a lot of edges.
	 */
	zhpe_stats_start(zhpe_stats_subid(RECV, 20));
	zctx_unlock(zctx);
	rc = zhpe_get_uiov(zctx, uiov, udesc, uiov_cnt,
			   ZHPEQ_MR_RECV, rx_user->liov);
	zctx_lock(zctx);
	zhpe_stats_stop(zhpe_stats_subid(RECV, 20));
	/* Registration/access error? */
	if (OFI_UNLIKELY(rc < 0)) {
		/* Yes. */
		if (rx_user->matched) {
			zhpe_rx_complete(rx_user, rc);
			rc = 0;
		} else {
			dlist_remove(&rx_user->dentry);
			zhpe_rx_entry_free(rx_user);
		}
		zctx_unlock(zctx);

		return rc;
	}
	/* No, registration succeeded: start I/O if we matched. */
	rx_user->lstate.cnt = rc;
	rx_user->lstate.held = true;
	rx_user->lstate_ready = true;
	if (rx_user->matched)
		zhpe_rx_start_recv(rx_user, rx_user->rx_state);
	zctx_unlock(zctx);

	return 0;
}

static void send_zmr_put(void **ptrs, size_t cnt)
{
	size_t			i;

	for (i = 0; i < cnt; i++)
		zhpe_dom_mr_put(ptrs[i]);
}

static int tx_reserve(struct zhpeq_tq *ztq, struct zhpe_tx_entry *tx_entry,
		      uint n_entries, union zhpe_hw_wq_entry **wqe,
		      int32_t *reservation)
{
	struct zhpe_conn	*conn = tx_entry->conn;
	int32_t			res;
	uint			i;

	for (i = 0; i < n_entries; i++) {
		res = zhpeq_tq_reserve(ztq);
		if (OFI_UNLIKELY(res < 0)) {
			assert_always(res == -EAGAIN);
			while (i > 0) {
				i--;
				zhpeq_tq_unreserve(ztq, reservation[i]);
			}
			zhpe_conn_flags_set(conn, ZHPE_CONN_FLAG_BACKOFF);

			return -EAGAIN;
		}
		reservation[i] = res;
		wqe[i] = zhpeq_tq_get_wqe(ztq, res);
		zhpeq_tq_set_context(ztq, res, tx_entry);
	}

	if (OFI_LIKELY(zhpe_tx_entry_slot_alloc(tx_entry))) {
		/* The conn tracks operations that are acutally dispatched. */
		tx_entry->conn->tx_queued += n_entries;
		tx_entry->conn->zctx->tx_queued += n_entries;
		return 0;
	}

	zhpe_conn_flags_set(conn, ZHPE_CONN_FLAG_BACKOFF);
	while (i > 0) {
		i--;
		zhpeq_tq_unreserve(ztq, reservation[i]);
	}

	return -EAGAIN;
}

static void tx_queue_alloc(struct zhpe_conn *conn,
			   struct zhpe_tx_entry *tx_entry,
			   uint n_entries, union zhpe_hw_wq_entry **wqe,
			   int32_t *reservation)
{
	struct zhpe_ctx		*zctx = conn->zctx;
	struct zhpe_tx_queue_entry *txqe;
	uint			i;

	for (i = 0; i < n_entries; i++) {
		txqe = zhpe_buf_alloc(&zctx->tx_queue_pool);
		tx_entry->cstat.flags |= ZHPE_CS_FLAG_QUEUED;
		txqe->tx_entry = tx_entry;
		wqe[i] = &txqe->wqe;
		dlist_insert_tail(&txqe->dentry, &conn->tx_queue);
		reservation[i] = ZHPEQ_INSERT_NONE << 16;
	}
}

void zhpe_tx_reserve(struct zhpeq_tq *ztq, struct zhpe_tx_entry *tx_entry,
		     uint n_entries, union zhpe_hw_wq_entry **wqe,
		     int32_t *reservation)
{
	struct zhpe_conn	*conn = tx_entry->conn;
	int			rc;

	if (OFI_LIKELY(!conn->flags)) {
		rc = tx_reserve(ztq, tx_entry, n_entries, wqe, reservation);
		if (OFI_UNLIKELY(rc >= 0))
			return;
	}

	/* zctx->ctx_queued incremented for queued operations, too. */
	tx_entry->cstat.flags |= ZHPE_CS_FLAG_QUEUED;
	conn->zctx->tx_queued += n_entries;
	tx_queue_alloc(conn, tx_entry, n_entries, wqe, reservation);
}

static void send_inline_msg1(struct zhpe_conn *conn,
			     union zhpe_hw_wq_entry *wqe,
			     const void *buf, size_t len, uint8_t op,
			     uint8_t op_zflags,  uint64_t tag, uint64_t cq_data,
			     uint16_t cmp_idx)
{
	struct zhpe_msg		*msg = (void *)&wqe->enqa.payload;
	union zhpe_msg_payload	*pay = (void *)&msg->payload;
	size_t			i;

	zhpeq_tq_enqa(wqe, 0, conn->tkey.rem_gcid, conn->rem_rspctxid);
	zhpe_msg_hdr_init(&msg->hdr, op, op_zflags, 0, len, conn->rem_conn_idxn,
			  htons(cmp_idx), conn->tx_seq++);

	i = 0;
	if (op & ZHPE_OP_SEND_TX)
		pay->data[i++] = htobe64(tag);
	if (op & ZHPE_OP_SEND_DX)
		pay->data[i++] = htobe64(cq_data);
	memcpy(&pay->data[i], buf, len);
}

static void send_inline_msg2(struct zhpe_conn *conn,
			     union zhpe_hw_wq_entry *wqe,
			     const void *buf, size_t len)
{
	struct zhpe_msg		*msg = (void *)&wqe->enqa.payload;
	union zhpe_msg_payload	*pay = (void *)&msg->payload;

	zhpeq_tq_enqa(wqe, 0, conn->tkey.rem_gcid, conn->rem_rspctxid);
	zhpe_msg_hdr_init(&msg->hdr, ZHPE_OP_SEND_F, 0, 0, len,
			  conn->rem_conn_idxn, 0, conn->tx_seq++);

	memcpy(pay, buf, len);
}

static uint64_t extra_bytes(uint8_t op)
{
	uint64_t		ret = 0;

	if (op & ZHPE_OP_SEND_TX)
		ret += sizeof(uint64_t);
	if (op & ZHPE_OP_SEND_DX)
		ret += sizeof(uint64_t);

	return ret;
}

static struct zhpe_tx_entry *get_tx_entry(struct zhpe_conn *conn,
					  uint64_t opt_flags, void *op_context)
{
	struct zhpe_tx_entry	*tx_entry;
	struct zhpe_tx_entry_ctx *tx_entry_ctx;

	if ((opt_flags & ZHPE_OPT_CONTEXT) && OFI_LIKELY(op_context != NULL)) {
		tx_entry = op_context;
		if (opt_flags & ZHPE_OPT_TAGGED)
			tx_entry->tx_handler = ZHPE_TX_HANDLE_TAG;
		else
			tx_entry->tx_handler = ZHPE_TX_HANDLE_MSG;
	} else {
		tx_entry_ctx = zhpe_buf_alloc(&conn->zctx->tx_ctx_pool);
		tx_entry_ctx->op_context = op_context;
		tx_entry = &tx_entry_ctx->tx_entry;
		if (opt_flags & ZHPE_OPT_TAGGED)
			tx_entry->tx_handler = ZHPE_TX_HANDLE_TAG_FREE;
		else
			tx_entry->tx_handler = ZHPE_TX_HANDLE_MSG_FREE;
	}
	tx_entry->conn = conn;
	tx_entry->ptr_cnt = 0;

	return tx_entry;
}

static int send_inline(struct zhpe_ctx *zctx, void *op_context, uint64_t tag,
		       uint64_t cq_data, uint64_t op_flags, uint64_t opt_flags,
		       uint8_t op, const char *buf, size_t len,
		       fi_addr_t dst_addr)
{
	struct zhpe_conn	*conn;
	struct zhpe_tx_entry    *tx_entry;
	uint64_t		extra = extra_bytes(op);
	uint8_t			op_zflags;
	size_t			cpy_len;
	int32_t			reservation[2];
	union zhpe_hw_wq_entry	*wqe[2];
	int			rc;

	if (OFI_UNLIKELY(zctx->zep->disabled))
		return -FI_EOPBADSTATE;

	zctx_lock(zctx);
	zhpe_stats_start(zhpe_stats_subid(SEND, 10));
	conn = zhpe_conn_av_lookup(zctx, dst_addr);
	zhpe_stats_stop(zhpe_stats_subid(SEND, 10));
	if (OFI_UNLIKELY(conn->eflags)) {
		rc = zhpe_conn_eflags_error(conn->eflags);
		zctx_unlock(zctx);
		return rc;
	}

	zhpe_stats_start(zhpe_stats_subid(SEND, 40));

	/* Do we need a real completion structure? (Optimize for inject.) */
	if (OFI_UNLIKELY(op_flags & FI_COMPLETION)) {
		/* Yes. */
		tx_entry = get_tx_entry(conn, opt_flags, op_context);
		zhpe_cstat_init(&tx_entry->cstat, 1, ZHPE_CS_FLAG_COMPLETION);
		op_zflags = 0;
		if (OFI_UNLIKELY(op_flags &
				 (FI_DELIVERY_COMPLETE | FI_MATCH_COMPLETE))) {
			tx_entry->cstat.completions++;
			tx_entry->cstat.flags |= ZHPE_CS_FLAG_REMOTE_STATUS;
			op_zflags |= ZHPE_OP_FLAG_DELIVERY_COMPLETE;
		}
	} else {
		/* No: use shared inject structure. */
		tx_entry = &conn->tx_entry_inject;
		op_zflags = 0;
	}

	zhpe_conn_fence_check(tx_entry, opt_flags, op_flags);

	/* Favor shortest messages. */
	if (OFI_LIKELY(len + extra < ZHPE_MAX_MSG_PAYLOAD)) {
		zhpe_tx_reserve(zctx->ztq_hi, tx_entry, 1, wqe, reservation);
		send_inline_msg1(conn, wqe[0], buf, len, op, op_zflags, tag,
				 cq_data, tx_entry->cmp_idx);
		zhpeq_tq_insert(zctx->ztq_hi, reservation[0]);
	} else {
		tx_entry->cstat.completions++;
		zhpe_tx_reserve(zctx->ztq_hi, tx_entry, 2, wqe, reservation);
		cpy_len = ZHPE_MAX_MSG_PAYLOAD - extra;
		send_inline_msg1(conn, wqe[0], buf, cpy_len,
				 (op | ZHPE_OP_SEND_MX), op_zflags, tag,
				 cq_data, tx_entry->cmp_idx);
		buf = VPTR(buf, cpy_len);
		len -= cpy_len;
		send_inline_msg2(conn, wqe[1], buf, len);
		zhpeq_tq_insert(zctx->ztq_hi, reservation[0]);
		zhpeq_tq_insert(zctx->ztq_hi, reservation[1]);
	}
	zhpeq_tq_commit(zctx->ztq_hi);
	zctx->pe_ctx_ops->signal(zctx);
	zhpe_stats_stop(zhpe_stats_subid(SEND, 40));
	zctx_unlock(zctx);

	return 0;
}

static int send_get_uiov(struct zhpe_ctx *zctx,
			 const struct iovec *uiov, void **udesc,
			 size_t uiov_cnt, void **ptrs)
{
	int			rc;
	struct zhpe_mr		*zmr;

	assert(uiov_cnt > 0);
	assert(uiov_cnt <= ZHPE_EP_MAX_IOV);
	rc = get_buf_zmr(zctx, uiov[0].iov_base, uiov[0].iov_len,
			 udesc[0], ZHPEQ_MR_SEND, &zmr);
	ptrs[0] = zmr;
	if (OFI_UNLIKELY(rc < 0))
		return rc;
	if (OFI_LIKELY(uiov_cnt == 1))
		return 1;
	rc = get_buf_zmr(zctx, uiov[1].iov_base, uiov[1].iov_len,
			 udesc[1], ZHPEQ_MR_SEND, &zmr);
	ptrs[1] = zmr;
	if (OFI_UNLIKELY(rc < 0)) {
		zhpe_dom_mr_put(ptrs[0]);
		return rc;
	}

	return 2;
}

static size_t send_iov_iov(union zhpe_hw_wq_entry *wqe, size_t i,
			   const struct iovec *uiov)
{
	struct zhpe_msg		*msg = (void *)&wqe->enqa.payload;
	union zhpe_msg_payload	*pay = (void *)msg->payload;

	pay->data[i++] = htobe64((uintptr_t)uiov->iov_base);
	pay->data[i++] = htobe64(uiov->iov_len);

	return i;
}

static size_t send_iov_hdr1(struct zhpe_conn *conn,
			    union zhpe_hw_wq_entry *wqe,
			    uint8_t op, uint8_t op_zflags, uint64_t tag,
			    uint64_t cq_data, uint8_t uiov_cnt,
			    uint16_t cmp_idx)
{
	struct zhpe_msg		*msg = (void *)&wqe->enqa.payload;
	union zhpe_msg_payload	*pay = (void *)&msg->payload;
	size_t			i;

	zhpeq_tq_enqa(wqe, 0, conn->tkey.rem_gcid, conn->rem_rspctxid);
	zhpe_msg_hdr_init(&msg->hdr, op, op_zflags, 0, uiov_cnt,
			  conn->rem_conn_idxn, htons(cmp_idx), conn->tx_seq++);

	i = 0;
	if (op & ZHPE_OP_SEND_TX)
		pay->data[i++] = htobe64(tag);
	if (op & ZHPE_OP_SEND_DX)
		pay->data[i++] = htobe64(cq_data);

	return i;
}

static void send_iov_hdr2(struct zhpe_conn *conn,
			  union zhpe_hw_wq_entry *wqe)
{
	struct zhpe_msg		*msg = (void *)&wqe->enqa.payload;

	zhpeq_tq_enqa(wqe, 0, conn->tkey.rem_gcid, conn->rem_rspctxid);
	zhpe_msg_hdr_init(&msg->hdr, ZHPE_OP_SEND_F, 0, 0, 0,
			  conn->rem_conn_idxn, 0, conn->tx_seq++);
}

static int send_iov(struct zhpe_ctx *zctx, void *op_context, uint64_t tag,
		    uint64_t cq_data, uint64_t op_flags, uint64_t opt_flags,
		    uint8_t op, const struct iovec *uiov, void **udesc,
		    size_t uiov_cnt, fi_addr_t dst_addr)
{
	int			rc;
	uint8_t			op_zflags;
	int32_t			reservation[2];
	union zhpe_hw_wq_entry	*wqe[2];
	struct zhpe_conn	*conn;
	struct zhpe_tx_entry    *tx_entry;
	void			*ptrs[ZHPE_EP_MAX_IOV];
	size_t			i;
	uint64_t		total_user;
	char			*bptr;
	char			buf[ZHPE_EP_MAX_INLINE_MSG] INT64_ALIGNED;

	if (OFI_UNLIKELY(zctx->zep->disabled))
		return -FI_EOPBADSTATE;

	rc = zhpe_get_uiov_len(uiov, uiov_cnt, &total_user);
	if (OFI_UNLIKELY(rc < 0))
		return rc;

	if (OFI_LIKELY(total_user <= ZHPE_EP_MAX_INLINE_MSG)) {
		if (OFI_LIKELY(uiov_cnt == 1))
			bptr = uiov[0].iov_base;
		else {
			for (i = 0, bptr = buf; i < uiov_cnt;
			     i++, bptr += uiov[i].iov_len)
				memcpy(bptr, uiov[i].iov_base, uiov[i].iov_len);
			bptr = buf;
		}
		op |= ZHPE_OP_SEND_IX;
		rc = send_inline(zctx, op_context, tag, cq_data, op_flags,
				 opt_flags, op, bptr, total_user, dst_addr);
		return rc;
	}

	if (OFI_UNLIKELY(op_flags & FI_INJECT))
		return -FI_EINVAL;

	zhpe_stats_start(zhpe_stats_subid(SEND, 20));
	rc = send_get_uiov(zctx, uiov, udesc, uiov_cnt, ptrs);
	zhpe_stats_stop(zhpe_stats_subid(SEND, 20));
	if (OFI_UNLIKELY(rc < 0))
		return rc;

	zctx_lock(zctx);
	zhpe_stats_start(zhpe_stats_subid(SEND, 10));
	conn = zhpe_conn_av_lookup(zctx, dst_addr);
	zhpe_stats_stop(zhpe_stats_subid(SEND, 10));
	if (OFI_UNLIKELY(conn->eflags)) {
		send_zmr_put(ptrs, rc);
		rc = zhpe_conn_eflags_error(conn->eflags);
		zctx_unlock(zctx);
		return rc;
	}

	zhpe_stats_start(zhpe_stats_subid(SEND, 40));
	/* We need a real completion structure. */
	tx_entry = get_tx_entry(conn, opt_flags, op_context);
	tx_entry->ptr_cnt = rc;
	tx_entry->cmp_idx = 0;
	memcpy(tx_entry->ptrs, ptrs, sizeof(tx_entry->ptrs));
	zhpe_cstat_init(&tx_entry->cstat, uiov_cnt + 1,
			ZHPE_CS_FLAG_REMOTE_STATUS);
	if (OFI_LIKELY(op_flags & FI_COMPLETION)) {
		tx_entry->cstat.flags |= ZHPE_CS_FLAG_COMPLETION;
		if (OFI_UNLIKELY(op_flags &
				 (FI_DELIVERY_COMPLETE | FI_MATCH_COMPLETE)))
			op_zflags = ZHPE_OP_FLAG_DELIVERY_COMPLETE;
		else
			op_zflags = ZHPE_OP_FLAG_TRANSMIT_COMPLETE;
	} else
		op_zflags = ZHPE_OP_FLAG_TRANSMIT_COMPLETE;

	zhpe_conn_fence_check(tx_entry, opt_flags, op_flags);

	if (uiov_cnt == 1) {
		zhpe_tx_reserve(zctx->ztq_hi, tx_entry, 1, wqe, reservation);
		i = send_iov_hdr1(conn, wqe[0], op, op_zflags, tag, cq_data,
				  uiov_cnt, tx_entry->cmp_idx);
		send_iov_iov(wqe[0], i, &uiov[0]);
		zhpeq_tq_insert(zctx->ztq_hi, reservation[0]);
		goto done_unlock;
	}

	/* Two uiovs. */
	if ((op & (ZHPE_OP_SEND_DX | ZHPE_OP_SEND_TX)) ==
	    (ZHPE_OP_SEND_DX | ZHPE_OP_SEND_TX)) {
		/* Needs two messages. */
		zhpe_tx_reserve(zctx->ztq_hi, tx_entry, 2, wqe, reservation);
		i = send_iov_hdr1(conn, wqe[0], (op | ZHPE_OP_SEND_MX),
				  op_zflags, tag, cq_data, uiov_cnt,
				  tx_entry->cmp_idx);
		assert(i == 2);
		send_iov_iov(wqe[0], i, &uiov[0]);
		send_iov_hdr2(conn, wqe[1]);
		send_iov_iov(wqe[1], 0, &uiov[1]);
		zhpeq_tq_insert(zctx->ztq_hi, reservation[0]);
		zhpeq_tq_insert(zctx->ztq_hi, reservation[1]);
	} else {
		/* Fits in one message. */
		zhpe_tx_reserve(zctx->ztq_hi, tx_entry, 1, wqe, reservation);
		i = send_iov_hdr1(conn, wqe[0], op, op_zflags, tag, cq_data,
				  uiov_cnt, tx_entry->cmp_idx);
		assert(i == 1);
		i = send_iov_iov(wqe[0], i, &uiov[0]);
		send_iov_iov(wqe[0], i, &uiov[1]);
		zhpeq_tq_insert(zctx->ztq_hi, reservation[0]);
	}

 done_unlock:
	zhpeq_tq_commit(zctx->ztq_hi);
	zctx->pe_ctx_ops->signal(zctx);
	zctx_unlock(zctx);
	zhpe_stats_stop(zhpe_stats_subid(SEND, 40));

	return 0;
}

#define PEEK_FLAGS	(FI_CLAIM | FI_DISCARD | FI_PEEK)
#define RECV_FLAGS	(ZHPE_EP_RX_OP_FLAGS | PEEK_FLAGS | FI_MORE)
#define SEND_FLAGS	(ZHPE_EP_TX_OP_FLAGS | FI_MORE | FI_REMOTE_CQ_DATA)

#define MSG_RX_OPS(_name, _opt)						\
									\
static ssize_t zhpe_recvmsg##_name(struct fid_ep *fid_ep,		\
				   const struct fi_msg *msg,		\
				   uint64_t flags)			\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt);			\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
									\
	zhpe_stats_start(zhpe_stats_subid(RECV, 0));			\
									\
	if (OFI_UNLIKELY(!msg || msg->iov_count > ZHPE_EP_MAX_IOV ||	\
			 (msg->iov_count && !msg->msg_iov) ||		\
			 (flags & ~RECV_FLAGS))) {			\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
       	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = flags | zctx->util_ep.rx_msg_flags;			\
									\
	ret = recv_iov(zctx, msg->msg_iov, msg->desc, msg->iov_count,	\
		       msg->addr, msg->context, 0, 0,			\
		       op_flags, opt_flags);				\
									\
 done:									\
	zhpe_stats_stop(zhpe_stats_subid(RECV, 0));			\
									\
	return ret;							\
} 									\
									\
static ssize_t zhpe_recvv##_name(struct fid_ep *fid_ep,			\
				 const struct iovec *iov,		\
				 void **desc, size_t count,		\
				 fi_addr_t src_addr, void *op_context)	\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt);			\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
									\
	zhpe_stats_start(zhpe_stats_subid(RECV, 0));			\
									\
	if (OFI_UNLIKELY(count > ZHPE_EP_MAX_IOV ||			\
			 (count && (!iov || !desc)))) {			\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = zctx->util_ep.rx_op_flags;				\
									\
	ret = recv_iov(zctx, iov, desc, count,				\
		       src_addr, op_context, 0, 0,			\
		       op_flags, opt_flags);				\
									\
 done:									\
	zhpe_stats_stop(zhpe_stats_subid(RECV, 0));			\
									\
	return ret;							\
}									\
									\
static ssize_t zhpe_recv##_name(struct fid_ep *fid_ep, void *buf,	\
				size_t len, void *desc,			\
				fi_addr_t src_addr, void *op_context)	\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt);			\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
	struct iovec		iov[1];					\
									\
	zhpe_stats_start(zhpe_stats_subid(RECV, 0));			\
									\
	if (OFI_UNLIKELY(len && !buf)) {				\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = zctx->util_ep.rx_op_flags;				\
	iov[0].iov_base = buf;						\
	iov[0].iov_len = len;						\
									\
	ret = recv_iov(zctx, iov, &desc, 1,				\
		       src_addr, op_context, 0, 0,			\
		       op_flags, opt_flags);				\
									\
 done:									\
	zhpe_stats_stop(zhpe_stats_subid(RECV, 0));			\
									\
	return ret;							\
}									\
									\
struct fi_ops_msg zhpe_ep_msg##_name##_rx_ops = {			\
	.size			= sizeof(struct fi_ops_msg),		\
	.recv			= zhpe_recv##_name,			\
	.recvv			= zhpe_recvv##_name,			\
	.recvmsg		= zhpe_recvmsg##_name,			\
	.send			= fi_no_msg_send,			\
	.sendv			= fi_no_msg_sendv,			\
	.sendmsg		= fi_no_msg_sendmsg,			\
	.inject			= fi_no_msg_inject,			\
	.senddata		= fi_no_msg_senddata,			\
	.injectdata		= fi_no_msg_injectdata,			\
};

#define MSG_TX_OPS(_name, _opt)						\
									\
static ssize_t zhpe_sendmsg##_name(struct fid_ep *fid_ep,		\
				   const struct fi_msg *msg,		\
				   uint64_t flags)			\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt);			\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
	uint64_t		bad_mask;				\
	uint8_t			op;					\
									\
	zhpe_stats_start(zhpe_stats_subid(SEND, 0));			\
									\
	bad_mask = ~(SEND_FLAGS |					\
		     ((opt_flags & ZHPE_OPT_FENCE) ? FI_FENCE : 0));	\
	if (OFI_UNLIKELY(!msg || msg->iov_count > ZHPE_EP_MAX_IOV ||	\
			 (msg->iov_count && !msg->msg_iov) ||		\
			 (flags & bad_mask))) {				\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = flags | zctx->util_ep.tx_msg_flags;			\
									\
	if (flags & FI_REMOTE_CQ_DATA)					\
		op = ZHPE_OP_SEND_D;					\
	else								\
		op = ZHPE_OP_SEND;					\
									\
	ret = send_iov(zctx, msg->context, 0, msg->data,		\
		       op_flags, opt_flags, op,				\
		       msg->msg_iov, msg->desc, msg->iov_count,		\
		       msg->addr);					\
									\
 done:									\
	zhpe_stats_stop(zhpe_stats_subid(SEND, 0));			\
									\
	return ret;							\
}									\
									\
static ssize_t zhpe_sendv##_name(struct fid_ep *fid_ep,			\
				 const struct iovec *iov,		\
				 void **desc, size_t count,		\
				 fi_addr_t dst_addr, void *op_context)	\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt);			\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
	uint8_t			op;					\
									\
	zhpe_stats_start(zhpe_stats_subid(SEND, 0));			\
									\
	if (OFI_UNLIKELY(count > ZHPE_EP_MAX_IOV ||			\
			 (count && (!iov || !desc)))) {			\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = zctx->util_ep.tx_op_flags;				\
	op = ZHPE_OP_SEND;						\
									\
 	ret = send_iov(zctx, op_context, 0, 0,				\
		       op_flags, opt_flags, op,				\
		       iov, desc, count, dst_addr);			\
									\
done:									\
	zhpe_stats_stop(zhpe_stats_subid(SEND, 0));			\
									\
	return ret;							\
}									\
									\
static ssize_t zhpe_send##_name(struct fid_ep *fid_ep,			\
				const void *buf, size_t len,		\
				void *desc, fi_addr_t dst_addr,		\
				void *op_context)			\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt);			\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
	uint8_t			op;					\
	struct iovec		iov[1];					\
									\
	zhpe_stats_start(zhpe_stats_subid(SEND, 0));			\
									\
	if (OFI_UNLIKELY(len && !buf)) {				\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = zctx->util_ep.tx_op_flags;				\
	op = ZHPE_OP_SEND;						\
	iov[0].iov_base = (void *)buf;					\
	iov[0].iov_len = len;						\
									\
 	ret = send_iov(zctx, op_context, 0, 0,				\
		       op_flags, opt_flags, op,				\
		       iov, &desc, 1, dst_addr);			\
									\
 done:									\
	zhpe_stats_stop(zhpe_stats_subid(SEND, 0));			\
									\
	return ret;							\
}									\
									\
static ssize_t zhpe_senddata##_name(struct fid_ep *fid_ep,		\
				    const void *buf, size_t len,	\
				    void *desc, uint64_t data,		\
				    fi_addr_t dst_addr,			\
				    void *op_context)			\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt);			\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
	uint8_t			op;					\
	struct iovec		iov[1];					\
									\
	zhpe_stats_start(zhpe_stats_subid(SEND, 0));			\
									\
	if (OFI_UNLIKELY(len && !buf)) {				\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = zctx->util_ep.tx_op_flags;				\
	op = ZHPE_OP_SEND_D;						\
	iov[0].iov_base = (void *)buf;					\
	iov[0].iov_len = len;						\
									\
 	ret = send_iov(zctx, op_context, 0, data,			\
		       op_flags, opt_flags, op,				\
		       iov, &desc, 1, dst_addr);			\
									\
 done:									\
	zhpe_stats_stop(zhpe_stats_subid(SEND, 0));			\
									\
	return ret;							\
}									\
									\
static ssize_t zhpe_inject##_name(struct fid_ep *fid_ep,		\
				  const void *buf, size_t len,		\
				  fi_addr_t dst_addr)			\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt);			\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
	uint8_t			op;					\
									\
	zhpe_stats_start(zhpe_stats_subid(SEND, 0));			\
									\
	if (OFI_UNLIKELY(len && !buf)) {				\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = zctx->util_ep.inject_op_flags;			\
	op = ZHPE_OP_SEND_I;						\
									\
	ret = send_inline(zctx, NULL, 0, 0, op_flags, opt_flags,	\
			  op, buf, len, dst_addr);			\
									\
 done:									\
	zhpe_stats_stop(zhpe_stats_subid(SEND, 0));			\
									\
	return ret;							\
}									\
									\
static ssize_t zhpe_injectdata##_name(struct fid_ep *fid_ep,		\
					 const void *buf, size_t len,	\
					 uint64_t data,			\
					 fi_addr_t dst_addr)		\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt);			\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
	uint8_t			op;					\
									\
	zhpe_stats_start(zhpe_stats_subid(SEND, 0));			\
									\
	if (OFI_UNLIKELY(len && !buf)) {				\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = zctx->util_ep.inject_op_flags;			\
	op = ZHPE_OP_SEND_ID;						\
									\
	ret = send_inline(zctx, NULL, 0, 0, op_flags, opt_flags,	\
			  op, buf, len, dst_addr);			\
									\
 done:									\
	zhpe_stats_stop(zhpe_stats_subid(SEND, 0));			\
									\
	return ret;							\
}									\
									\
struct fi_ops_msg zhpe_ep_msg##_name##_tx_ops = {			\
	.size			= sizeof(struct fi_ops_msg),		\
	.recv			= fi_no_msg_recv,			\
	.recvv			= fi_no_msg_recvv,			\
	.recvmsg		= fi_no_msg_recvmsg,			\
	.send			= zhpe_send##_name,			\
	.sendv			= zhpe_sendv##_name,			\
	.sendmsg		= zhpe_sendmsg##_name,			\
	.inject			= zhpe_inject##_name,			\
	.senddata		= zhpe_senddata##_name,			\
	.injectdata		= zhpe_injectdata##_name,		\
}

#define MSG_OPS(_name, _rxname, _txname)				\
									\
struct fi_ops_msg zhpe_ep_msg##_name##_ops = {				\
	.size			= sizeof(struct fi_ops_msg),		\
	.recv			= zhpe_recv##_rxname,			\
	.recvv			= zhpe_recvv##_rxname,			\
	.recvmsg		= zhpe_recvmsg##_rxname,		\
	.send			= zhpe_send##_txname,			\
	.sendv			= zhpe_sendv##_txname,			\
	.sendmsg		= zhpe_sendmsg##_txname,		\
	.inject			= zhpe_inject##_txname,			\
	.senddata		= zhpe_senddata##_txname,		\
	.injectdata		= zhpe_injectdata##_txname,		\
}

MSG_RX_OPS(   , 0);
MSG_RX_OPS(_d , ZHPE_OPT_DIRECTED_RECV);
MSG_TX_OPS(   , 0);
MSG_TX_OPS(_f , ZHPE_OPT_FENCE);
MSG_TX_OPS(_c , ZHPE_OPT_CONTEXT);
MSG_TX_OPS(_cf, ZHPE_OPT_CONTEXT | ZHPE_OPT_FENCE);

MSG_OPS(    ,   ,    );
MSG_OPS(_f  ,   , _f );
MSG_OPS(_d  , _d,    );
MSG_OPS(_df , _d, _f );
MSG_OPS(_c  ,   , _c );
MSG_OPS(_cf ,   , _f );
MSG_OPS(_cd , _d, _c );
MSG_OPS(_cdf, _d, _cf);

struct fi_ops_msg zhpe_ep_msg_bad_ops = {
	.size			= sizeof(struct fi_ops_msg),
	.recv			= fi_no_msg_recv,
	.recvv			= fi_no_msg_recvv,
	.recvmsg		= fi_no_msg_recvmsg,
	.send			= fi_no_msg_send,
	.sendv			= fi_no_msg_sendv,
	.sendmsg		= fi_no_msg_sendmsg,
	.inject			= fi_no_msg_inject,
	.senddata		= fi_no_msg_senddata,
	.injectdata		= fi_no_msg_injectdata,
};

#define TMSG_RX_OPS(_name, _opt)					\
									\
static ssize_t zhpe_trecvmsg##_name(struct fid_ep *fid_ep,		\
				    const struct fi_msg_tagged *msg,	\
				    uint64_t flags)			\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt) | ZHPE_OPT_TAGGED;	\
	struct zhpe_ctx		*zctx;					\
	uint64_t		peek_flags;				\
	uint64_t		op_flags;				\
									\
	zhpe_stats_start(zhpe_stats_subid(RECV, 0));			\
									\
	if (OFI_UNLIKELY(!msg || msg->iov_count > ZHPE_EP_MAX_IOV ||	\
			 (msg->iov_count && !msg->msg_iov) ||		\
			 (flags & ~RECV_FLAGS))) {			\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
       	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = flags | zctx->util_ep.rx_msg_flags;			\
									\
	peek_flags = (flags & (FI_PEEK | FI_CLAIM | FI_DISCARD));	\
	if (peek_flags)							\
		ret = recv_peek_claim(zctx, msg, op_flags, opt_flags,	\
				      peek_flags);			\
	else								\
		ret = recv_iov(zctx, msg->msg_iov, msg->desc,		\
			       msg->iov_count, msg->addr, msg->context,	\
			       msg->tag, msg->ignore, op_flags,		\
			       opt_flags);				\
									\
 done:									\
	zhpe_stats_stop(zhpe_stats_subid(RECV, 0));			\
									\
	return ret;							\
}									\
									\
static ssize_t zhpe_trecvv##_name(struct fid_ep *fid_ep,		\
				  const struct iovec *iov,		\
				  void **desc, size_t count,		\
				  fi_addr_t src_addr, uint64_t tag,	\
				  uint64_t ignore, void *op_context)	\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt) | ZHPE_OPT_TAGGED;	\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
									\
	zhpe_stats_start(zhpe_stats_subid(RECV, 0));			\
									\
	if (OFI_UNLIKELY(count > ZHPE_EP_MAX_IOV ||			\
			 (count && (!iov || !desc)))) {			\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = zctx->util_ep.rx_op_flags;				\
									\
	ret = recv_iov(zctx, iov, desc, count,				\
		       src_addr, op_context, tag, 0,			\
		       op_flags, opt_flags);				\
									\
 done:									\
	zhpe_stats_stop(zhpe_stats_subid(RECV, 0));			\
									\
	return ret;							\
}									\
									\
static ssize_t zhpe_trecv##_name(struct fid_ep *fid_ep, void *buf,	\
				 size_t len, void *desc,		\
				 fi_addr_t src_addr, uint64_t tag,	\
				 uint64_t ignore, void *op_context)	\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt) | ZHPE_OPT_TAGGED;	\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
	struct iovec		iov[1];					\
									\
	zhpe_stats_start(zhpe_stats_subid(RECV, 0));			\
									\
	if (OFI_UNLIKELY(len && !buf)) {				\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = zctx->util_ep.rx_op_flags;				\
	iov[0].iov_base = buf;						\
	iov[0].iov_len = len;						\
									\
	ret = recv_iov(zctx, iov, &desc, 1,				\
		       src_addr, op_context, tag, 0,			\
		       op_flags, opt_flags);				\
									\
 done:									\
	zhpe_stats_stop(zhpe_stats_subid(RECV, 0));			\
									\
	return ret;							\
}									\
									\
struct fi_ops_tagged zhpe_ep_tagged##_name##_rx_ops = {			\
	.size			= sizeof(struct fi_ops_tagged),		\
	.recv			= zhpe_trecv##_name,			\
	.recvv			= zhpe_trecvv##_name,			\
	.recvmsg		= zhpe_trecvmsg##_name,			\
	.send			= fi_no_tagged_send,			\
	.sendv			= fi_no_tagged_sendv,			\
	.sendmsg		= fi_no_tagged_sendmsg,			\
	.inject			= fi_no_tagged_inject,			\
	.senddata		= fi_no_tagged_senddata,		\
	.injectdata		= fi_no_tagged_injectdata,		\
}

#define TMSG_TX_OPS(_name, _opt)					\
									\
static ssize_t zhpe_tsendmsg##_name(struct fid_ep *fid_ep,		\
				    const struct fi_msg_tagged *msg,	\
				    uint64_t flags)			\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt) | ZHPE_OPT_TAGGED;	\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
	uint64_t		bad_mask;				\
	uint8_t			op;					\
									\
	zhpe_stats_start(zhpe_stats_subid(SEND, 0));			\
									\
	bad_mask = ~(SEND_FLAGS |					\
		     ((opt_flags & ZHPE_OPT_FENCE) ? FI_FENCE : 0));	\
	if (OFI_UNLIKELY(!msg || msg->iov_count > ZHPE_EP_MAX_IOV ||	\
			 (msg->iov_count && !msg->msg_iov) ||		\
			 (flags & bad_mask))) {				\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = flags | zctx->util_ep.tx_msg_flags;			\
									\
	if (flags & FI_REMOTE_CQ_DATA)					\
		op = ZHPE_OP_SEND_DT;					\
	else								\
		op = ZHPE_OP_SEND_T;					\
									\
	ret = send_iov(zctx, msg->context, msg->tag, msg->data,		\
		       op_flags, opt_flags, op,				\
		       msg->msg_iov, msg->desc, msg->iov_count,		\
		       msg->addr);					\
									\
 done:									\
	zhpe_stats_stop(zhpe_stats_subid(SEND, 0));			\
									\
	return ret;							\
}									\
									\
static ssize_t zhpe_tsendv##_name(struct fid_ep *fid_ep,		\
				  const struct iovec *iov,		\
				  void **desc, size_t count,		\
				  fi_addr_t dst_addr, uint64_t tag,	\
				  void *op_context)			\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt) | ZHPE_OPT_TAGGED;	\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
	uint8_t			op;					\
									\
	zhpe_stats_start(zhpe_stats_subid(SEND, 0));			\
									\
	if (OFI_UNLIKELY(count > ZHPE_EP_MAX_IOV ||			\
			 (count && (!iov || !desc)))) {			\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = zctx->util_ep.tx_op_flags;				\
	op = ZHPE_OP_SEND_T;						\
									\
 	ret = send_iov(zctx, op_context, tag, 0,			\
		       op_flags, opt_flags, op,				\
		       iov, desc, count, dst_addr);			\
									\
 done:									\
	zhpe_stats_stop(zhpe_stats_subid(SEND, 0));			\
									\
	return ret;							\
}									\
									\
static ssize_t zhpe_tsend##_name(struct fid_ep *fid_ep,			\
				    const void *buf, size_t len,	\
				    void *desc, fi_addr_t dst_addr,	\
				    uint64_t tag, void *op_context)	\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt) | ZHPE_OPT_TAGGED;	\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
	uint8_t			op;					\
	struct iovec		iov[1];					\
									\
	zhpe_stats_start(zhpe_stats_subid(SEND, 0));			\
									\
	if (OFI_UNLIKELY(len && !buf)) {				\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = zctx->util_ep.tx_op_flags;				\
	op = ZHPE_OP_SEND_T;						\
	iov[0].iov_base = (void *)buf;					\
	iov[0].iov_len = len;						\
									\
 	ret = send_iov(zctx, op_context, tag, 0,			\
		       op_flags, opt_flags, op,				\
		       iov, &desc, 1, dst_addr);			\
									\
 done:									\
	zhpe_stats_stop(zhpe_stats_subid(SEND, 0));			\
									\
	return ret;							\
}									\
									\
static ssize_t zhpe_tsenddata##_name(struct fid_ep *fid_ep,		\
				     const void *buf, size_t len,	\
				     void *desc, uint64_t data,		\
				     fi_addr_t dst_addr,		\
				     uint64_t tag, void *op_context)	\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt) | ZHPE_OPT_TAGGED;	\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
	uint8_t			op;					\
	struct iovec		iov[1];					\
									\
	zhpe_stats_start(zhpe_stats_subid(SEND, 0));			\
									\
	if (OFI_UNLIKELY(len && !buf)) {				\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = zctx->util_ep.tx_op_flags;				\
	op = ZHPE_OP_SEND_DT;						\
	iov[0].iov_base = (void *)buf;					\
	iov[0].iov_len = len;						\
									\
 	ret = send_iov(zctx, op_context, tag, data,			\
		       op_flags, opt_flags, op,				\
		       iov, &desc, 1, dst_addr);			\
									\
 done:									\
	zhpe_stats_stop(zhpe_stats_subid(SEND, 0));			\
									\
	return ret;							\
}									\
									\
static ssize_t zhpe_tinject##_name(struct fid_ep *fid_ep,		\
				   const void *buf, size_t len,		\
				   fi_addr_t dst_addr, uint64_t tag)	\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt) | ZHPE_OPT_TAGGED;	\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
	uint8_t			op;					\
									\
	zhpe_stats_start(zhpe_stats_subid(SEND, 0));			\
									\
	if (OFI_UNLIKELY(len && !buf)) {				\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = zctx->util_ep.inject_op_flags;			\
	op = ZHPE_OP_SEND_IT;						\
									\
	ret = send_inline(zctx, NULL, tag, 0, op_flags, opt_flags,	\
			  op, buf, len, dst_addr);			\
									\
 done:									\
	zhpe_stats_stop(zhpe_stats_subid(SEND, 0));			\
									\
	return ret;							\
}									\
									\
static ssize_t zhpe_tinjectdata##_name(struct fid_ep *fid_ep,		\
				       const void *buf,	size_t len,	\
				       uint64_t cq_data,		\
				       fi_addr_t dst_addr,		\
				       uint64_t tag)			\
{									\
	int			ret;					\
	uint64_t		opt_flags = (_opt) | ZHPE_OPT_TAGGED;	\
	struct zhpe_ctx		*zctx;					\
	uint64_t		op_flags;				\
	uint8_t			op;					\
									\
	zhpe_stats_start(zhpe_stats_subid(SEND, 0));			\
									\
	if (OFI_UNLIKELY(len && !buf)) {				\
		ret = -FI_EINVAL;					\
		goto done;						\
	}								\
									\
	zctx = fid2zctx(&fid_ep->fid);					\
	op_flags = zctx->util_ep.inject_op_flags;			\
	op = ZHPE_OP_SEND_IDT;						\
									\
	ret = send_inline(zctx, NULL, tag, cq_data, op_flags,		\
			  opt_flags, op, buf, len, dst_addr);		\
									\
 done:									\
	zhpe_stats_stop(zhpe_stats_subid(SEND, 0));			\
									\
	return ret;							\
}									\
									\
struct fi_ops_tagged zhpe_ep_tagged##_name##_tx_ops = {			\
	.size			= sizeof(struct fi_ops_tagged),		\
	.recv			= fi_no_tagged_recv,			\
	.recvv			= fi_no_tagged_recvv,			\
	.recvmsg		= fi_no_tagged_recvmsg,			\
	.send			= zhpe_tsend##_name,			\
	.sendv			= zhpe_tsendv##_name,			\
	.sendmsg		= zhpe_tsendmsg##_name,			\
	.inject			= zhpe_tinject##_name,			\
	.senddata		= zhpe_tsenddata##_name,		\
	.injectdata		= zhpe_tinjectdata##_name,		\
};

#define TMSG_OPS(_name, _rxname, _txname)				\
									\
struct fi_ops_tagged zhpe_ep_tagged##_name##_ops = {			\
	.size			= sizeof(struct fi_ops_tagged),		\
	.recv			= zhpe_trecv##_rxname,			\
	.recvv			= zhpe_trecvv##_rxname,			\
	.recvmsg		= zhpe_trecvmsg##_rxname,		\
	.send			= zhpe_tsend##_txname,			\
	.sendv			= zhpe_tsendv##_txname,			\
	.sendmsg		= zhpe_tsendmsg##_txname,		\
	.inject			= zhpe_tinject##_txname,		\
	.senddata		= zhpe_tsenddata##_txname,		\
	.injectdata		= zhpe_tinjectdata##_txname,		\
}

TMSG_RX_OPS(   , 0);
TMSG_RX_OPS(_d , ZHPE_OPT_DIRECTED_RECV);
TMSG_TX_OPS(   , 0);
TMSG_TX_OPS(_f , ZHPE_OPT_FENCE);
TMSG_TX_OPS(_c , ZHPE_OPT_CONTEXT);
TMSG_TX_OPS(_cf, ZHPE_OPT_CONTEXT | ZHPE_OPT_FENCE);

TMSG_OPS(    ,   ,    );
TMSG_OPS(_f  ,   , _f );
TMSG_OPS(_d  , _d,    );
TMSG_OPS(_df , _d, _f );
TMSG_OPS(_c  ,   , _c );
TMSG_OPS(_cf ,   , _f );
TMSG_OPS(_cd , _d, _c );
TMSG_OPS(_cdf, _d, _cf);

struct fi_ops_tagged zhpe_ep_tagged_bad_ops = {
	.size			= sizeof(struct fi_ops_tagged),
	.recv			= fi_no_tagged_recv,
	.recvv			= fi_no_tagged_recvv,
	.recvmsg		= fi_no_tagged_recvmsg,
	.send			= fi_no_tagged_send,
	.sendv			= fi_no_tagged_sendv,
	.sendmsg		= fi_no_tagged_sendmsg,
	.inject			= fi_no_tagged_inject,
	.senddata		= fi_no_tagged_senddata,
	.injectdata		= fi_no_tagged_injectdata,
};

static void send_inline_special(struct zhpe_conn *conn, uint8_t op,
				const void *buf, size_t len,
				uint16_t conn_idxn, uint16_t cmp_idxn,
				uint32_t tx_seq, uint32_t dgcid,
				uint32_t rspctxid, union zhpe_hw_wq_entry *wqe)
{
	struct zhpe_msg		*msg;

	assert(len <= ZHPE_MAX_MSG_PAYLOAD);

	msg = zhpeq_tq_enqa(wqe, 0, dgcid, rspctxid);
	zhpe_msg_hdr_init(&msg->hdr, op, 0, 0, len, conn_idxn,
			  cmp_idxn, tx_seq);
	memcpy(msg->payload, buf, len);
}

void zhpe_msg_prov_no_eflags(struct zhpe_conn *conn, uint8_t op,
			     const void *payload, size_t paylen,
			     uint16_t cmp_idxn, uint32_t tx_seq)
{
	struct zhpe_ctx		*zctx = conn->zctx;
	int32_t			reservation[1];
	union zhpe_hw_wq_entry	*wqe[1];

	/* Assume conn->zctx is locked. */
	zhpe_tx_reserve(zctx->ztq_hi, &conn->tx_entry_prov, 1,
			wqe, reservation);
	send_inline_special(conn, op, payload, paylen, conn->rem_conn_idxn,
			    cmp_idxn, tx_seq, conn->tkey.rem_gcid,
			    conn->rem_rspctxid, wqe[0]);
	zhpeq_tq_insert(zctx->ztq_hi, reservation[0]);
	zhpeq_tq_commit(zctx->ztq_hi);
	/* Need to signal only from user contexts. */
}

void zhpe_msg_prov(struct zhpe_conn *conn, uint8_t op, const void *payload,
		   size_t paylen, uint16_t cmp_idxn, uint32_t tx_seq)
{
	if (OFI_UNLIKELY(conn->eflags))
		return;

	zhpe_msg_prov_no_eflags(conn, op, payload, paylen, cmp_idxn, tx_seq);
}

void zhpe_msg_connect(struct zhpe_ctx *zctx, uint8_t op,
		      const void *payload, size_t paylen, uint32_t tx_seq,
		      uint32_t dgcid, uint32_t rspctxid)
{
	struct zhpe_conn	*conn = zctx->conn0;
	int32_t			reservation[1];
	union zhpe_hw_wq_entry	*wqe[1];

	/* Assume conn->zctx is locked. */
	zhpe_tx_reserve(zctx->ztq_hi, &conn->tx_entry_prov, 1,
			wqe, reservation);
	send_inline_special(conn, op, payload, paylen, 0, 0, tx_seq,
			    dgcid, rspctxid, wqe[0]);
	zhpeq_tq_insert(zctx->ztq_hi, reservation[0]);
	zhpeq_tq_commit(zctx->ztq_hi);
	zctx->pe_ctx_ops->signal(zctx);
}

void zhpe_msg_rx_list_error(struct zhpe_conn *conn,
			    struct zhpe_rx_match_lists *match_lists, int error)
{
	struct zhpe_rx_entry	*rx_entry;
	struct dlist_entry	*next;

	/* This now only works when connections fail. */
	assert_always(error < 0);
	assert_always(error >= INT16_MIN);

	dlist_foreach_container_safe(&match_lists->user_list,
				     struct zhpe_rx_entry, rx_entry,
				     dentry, next)
		zhpe_rx_complete(rx_entry, error);

	/* Currently the only consumer is connect and this should be true. */
	assert_always(dlist_empty(&match_lists->wire_list));
}
