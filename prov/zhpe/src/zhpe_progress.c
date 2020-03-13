/*
 * Copyright (c) 2014 Intel Corporation, Inc.  All rights reserved.
 * Copyright (c) 2016 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2017-2018 Hewlett Packard Enterprise Development LP.  All rights reserved.
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

#define ZHPE_LOG_DBG(...) _ZHPE_LOG_DBG(FI_LOG_EP_DATA, __VA_ARGS__)
#define ZHPE_LOG_ERROR(...) _ZHPE_LOG_ERROR(FI_LOG_EP_DATA, __VA_ARGS__)

/* Debugging hook. */
#define set_rx_state(_rx_entry, _state)			\
do {							\
	struct zhpe_rx_entry *__rx_entry = (_rx_entry);	\
	__rx_entry->rx_state = (_state);		\
} while (0)

static void zhpe_pe_tx_rma(struct zhpe_pe_entry *pe_entry,
			   void (*completion)(struct zhpe_pe_entry *pe_entry));
static void zhpe_pe_tx_handle_rx_rma(struct zhpe_pe_root *pe_root,
				     struct zhpeq_cq_entry *zq_cqe);
static int zhpe_pe_writedata(struct zhpe_pe_entry *pe_entry);

static inline void rx_update_status(struct zhpe_rx_entry *rx_entry,
				    int status)
{
	if (OFI_UNLIKELY(status < 0) && rx_entry->status >= 0)
		rx_entry->status = status;
}

static void zhpe_pe_report_complete(struct zhpe_cqe *zcqe,
				    int32_t err, uint64_t rem)
{
	struct zhpe_comp	*comp = zcqe->comp;
	struct zhpe_cq		*zcq;
	struct fid_cq		*fid_cq;
	struct zhpe_eq		*zeq;
	struct zhpe_cntr	*zcntr;
	uint8_t			event;
	int			rc;

	if (zcqe->cqe.flags & ZHPE_NO_COMPLETION)
		return;

	switch (zcqe->cqe.flags & (FI_SEND | FI_RECV | FI_READ | FI_WRITE |
				   FI_REMOTE_READ | FI_REMOTE_WRITE)) {

	case FI_SEND:
		zcq = comp->send_cq;
		event = comp->send_cq_event;
		zcntr = zcqe->comp->send_cntr;
		break;

	case FI_RECV:
		zcq = comp->recv_cq;
		event = comp->recv_cq_event;
		zcntr = zcqe->comp->recv_cntr;
		break;

	case FI_READ:
		zcq = comp->send_cq;
		event = comp->send_cq_event;
		zcntr = zcqe->comp->read_cntr;
		break;

	case FI_WRITE:
		zcq = comp->send_cq;
		event = comp->send_cq_event;
		zcntr = zcqe->comp->write_cntr;
		break;

	case FI_REMOTE_READ:
		zcq = NULL;
		event = 0;
		zcntr = zcqe->comp->rem_read_cntr;
		break;

	case FI_REMOTE_WRITE:
		if (zcqe->cqe.flags & FI_REMOTE_CQ_DATA)
			zcq = comp->recv_cq;
		else
			zcq = NULL;
		event = 0;
		zcntr = zcqe->comp->rem_write_cntr;
		break;

	default:
		if (zcqe->cqe.flags & FI_REMOTE_CQ_DATA) {
			zcq = comp->recv_cq;
			event = 0;
			zcntr = NULL;
			break;
		}
		ZHPE_LOG_ERROR("Unexpected flags 0x%Lx\n",
			       (ullong)zcqe->cqe.flags);
		abort();
	}
	if (OFI_UNLIKELY(err < 0)) {
		if (zcntr)
			fi_cntr_adderr(&zcntr->util_cntr.cntr_fid, 1);
		if (zcq)
			zhpe_cq_report_error(&zcq->util_cq, &zcqe->cqe, rem,
					     -err, err, NULL, 0);
		return;
	}
	if (zcntr)
		zhpe_cntr_inc(zcntr);
	if (zcq && (!event || (zcqe->cqe.flags & FI_COMPLETION))) {
		rc = zhpe_cq_report_success(&zcq->util_cq, &zcqe->cqe);
		if (rc < 0) {
			ZHPE_LOG_ERROR("Failed to report completion %p: %d\n",
				       zcqe, rc);
			zeq = comp->eq;
			fid_cq = &zcq->util_cq.cq_fid;
			if (zeq)
				zhpe_eq_report_error(&zeq->util_eq,
						     &fid_cq->fid,
						     zcqe->cqe.op_context,
						     zcqe->cqe.data,
						     FI_ENOSPC, 0, NULL, 0);
		}
	}
}

static inline void
zhpe_pe_rx_multi_report_complete(struct zhpe_rx_ctx *rx_ctx,
				 const struct zhpe_rx_entry *rx_entry)
{
	struct zhpe_cqe		zcqe = {
		.cqe = {
			.op_context = rx_entry->context,
			.flags = ((rx_entry->flags & FI_COMPLETION) |
				  FI_MULTI_RECV),
		},
	};

	zhpe_pe_report_complete(&zcqe, 0, 0);
}

static inline void
zhpe_pe_rx_report_complete(struct zhpe_rx_ctx *rx_ctx,
			   const struct zhpe_rx_entry *rx_entry,
			   int status, uint64_t rem)
{
	struct zhpe_cqe		zcqe = {
		.addr = rx_entry->addr,
		.comp = &rx_ctx->comp,
		.cqe = {
			.op_context = rx_entry->context,
			.flags = rx_entry->flags,
			.len = rx_entry->total_len,
			.buf = rx_entry->buf,
			.data = rx_entry->cq_data,
			.tag = rx_entry->tag,
		},
	};

	zhpe_pe_report_complete(&zcqe, status, rem);
}

void _zhpe_pe_tx_report_complete(const struct zhpe_pe_entry *pe_entry)
{
	const struct zhpe_pe_root *pe_root = &pe_entry->pe_root;
	struct zhpe_conn	*conn = pe_root->conn;
	struct zhpe_cqe		zcqe = {
		.addr = conn->fi_addr,
		.comp = &conn->tx_ctx->comp,
		.cqe = {
			.op_context = pe_root->context,
			.flags = (pe_entry->flags &
				  ~(FI_REMOTE_READ | FI_REMOTE_WRITE)),
		},
	};

	zhpe_pe_report_complete(&zcqe, pe_root->compstat.status, pe_entry->rem);
}

static void zhpe_pe_rx_discard_recv(struct zhpe_rx_entry *rx_entry)
{
	struct zhpe_conn	*conn = rx_entry->conn;
	struct zhpe_rx_ctx	*rx_ctx = conn->rx_ctx;
	struct zhpe_msg_hdr	zhdr;

	dlist_remove_init(&rx_entry->lentry);
	if (rx_entry->rx_state == ZHPE_RX_STATE_EAGER) {
		dlist_insert_tail(&rx_entry->lentry, &rx_ctx->rx_work_list);
		set_rx_state(rx_entry, ZHPE_RX_STATE_DISCARD);
	} else {
		zhdr = rx_entry->zhdr;
		zhpe_rx_release_entry(rx_entry);
		if (zhdr.flags & ZHPE_MSG_ANY_COMPLETE)
			zhpe_send_status_rem(conn, zhdr, 0, 0);
	}
}

void zhpe_pe_rx_complete(struct zhpe_rx_ctx *rx_ctx,
			 struct zhpe_rx_entry *rx_entry, int status)
{
	struct zhpe_rx_entry	*rx_user = rx_entry->rx_user;

	/* Assumed:rx_entry on work list and we are only user. */
	dlist_remove_init(&rx_entry->lentry);
	if (status >= 0 && rx_entry->rem)
		status = -FI_ETRUNC;
	rx_update_status(rx_entry, status);
	zhpe_pe_rx_report_complete(rx_ctx, rx_entry, rx_entry->status,
				   rx_entry->rem);
	if (rx_entry->zhdr.flags & ZHPE_MSG_ANY_COMPLETE)
		zhpe_send_status_rem(rx_entry->conn, rx_entry->zhdr,
				     rx_entry->status, rx_entry->rem);
	zhpe_rx_release_entry(rx_entry);
	if (rx_user) {
		if (rx_user->flags & FI_MULTI_RECV) {
			rx_user->multi_cnt--;
			if (rx_user->multi_cnt ||
			    !dlist_empty(&rx_user->lentry))
				goto done;
			zhpe_pe_rx_multi_report_complete(rx_ctx, rx_user);
		}
		zhpe_rx_release_entry(rx_user);
	}
 done:
	zhpe_stats_stop(zhpe_stats_subid(RECV, 0));
}

static void rx_handle_send_rma_complete(struct zhpe_rx_entry *rx_entry)
{
	struct zhpe_rx_ctx	*rx_ctx = rx_entry->rx_free->rx_ctx;
	struct zhpe_pe_entry	*pe_entry = rx_entry->pe_entry;

	switch (rx_entry->rx_state) {

	case ZHPE_RX_STATE_RND_DIRECT:
		rx_entry->rem  = pe_entry->rem;
		zhpe_pe_rx_complete(rx_ctx, rx_entry,
				    pe_entry->pe_root.compstat.status);
		break;

	case ZHPE_RX_STATE_EAGER:
	case ZHPE_RX_STATE_DISCARD:
		rx_update_status(rx_entry, pe_entry->pe_root.compstat.status);
		if (rx_entry->zhdr.flags & ZHPE_MSG_TRANSMIT_COMPLETE) {
			zhpe_send_status_rem(rx_entry->conn, rx_entry->zhdr,
					     rx_entry->status, pe_entry->rem);
			rx_entry->zhdr.flags &= ~ZHPE_MSG_TRANSMIT_COMPLETE;
		}
		if (rx_entry->rx_state == ZHPE_RX_STATE_DISCARD)
			zhpe_pe_rx_discard_recv(rx_entry);
		else
			set_rx_state(rx_entry, ZHPE_RX_STATE_EAGER_DONE);
		break;

	case ZHPE_RX_STATE_RND_BUF:
	case ZHPE_RX_STATE_EAGER_CLAIMED:
		zhpe_iov_state_reset(&pe_entry->lstate);
		rx_entry->rem -=
			copy_iov(&rx_entry->lstate, &pe_entry->lstate,
				 rx_entry->total_len - pe_entry->rem);
		zhpe_pe_rx_complete(rx_ctx, rx_entry,
				    pe_entry->pe_root.compstat.status);
		break;

	default:
		ZHPE_LOG_ERROR("rx_entry %p in bad state %d\n",
			       rx_entry, rx_entry->rx_state);
	}

	return;
}

void zhpe_pe_rx_peek_recv(struct zhpe_rx_ctx *rx_ctx,
			  fi_addr_t fiaddr, uint64_t tag, uint64_t ignore,
			  uint64_t flags, struct fi_context *context)
{
	struct zhpe_rx_entry	*rx_buffered;
	struct zhpe_cqe		zcqe = {
		.comp = &rx_ctx->comp,
		.cqe = {
			.op_context = context,
		},
	};

	/* Locking is provided by the caller. */
	dlist_foreach_container(&rx_ctx->rx_buffered_list,
				struct zhpe_rx_entry, rx_buffered, lentry) {
		if (!zhpe_rx_match_entry(rx_buffered, true, fiaddr, tag,
					 ignore, flags))
			continue;
		goto found;
	}
	zcqe.addr = fiaddr;
	zcqe.cqe.flags = flags;
	zcqe.cqe.tag = tag;
	zhpe_pe_report_complete(&zcqe, -FI_ENOMSG, 0);
	goto done;
 found:
	zcqe.addr = rx_buffered->addr;
	zcqe.cqe.flags = rx_buffered->flags | (flags & FI_COMPLETION);
	zcqe.cqe.len = rx_buffered->total_len;
	zcqe.cqe.data = rx_buffered->cq_data;
	zcqe.cqe.tag = rx_buffered->tag;
	if (flags & FI_DISCARD) {
		zhpe_pe_rx_discard_recv(rx_buffered);
	} else if (flags & FI_CLAIM) {
		context->internal[0] = rx_buffered;
		dlist_remove(&rx_buffered->lentry);
		dlist_insert_tail(&rx_buffered->lentry, &rx_ctx->rx_work_list);
	}
	zhpe_pe_report_complete(&zcqe, 0, 0);
 done:
	return;
}

static inline int rx_send_start_buf(struct zhpe_rx_entry *rx_entry,
				    enum zhpe_rx_state state)
{
	int			ret;
	struct zhpe_pe_entry	*pe_entry;

	pe_entry = rx_entry->pe_entry;
	ret = zhpe_slab_alloc(&rx_entry->rx_free->rx_ctx->eager,
			      rx_entry->total_len, pe_entry->liov);
	if (ret >= 0) {
		set_rx_state(rx_entry, state);
		rx_entry->slab = true;
		zhpe_iov_state_init(&pe_entry->lstate,
				    &zhpe_iov_state_ziovl_ops, pe_entry->liov);
		pe_entry->lstate.cnt = 1;
		pe_entry->pe_root.handler(&pe_entry->pe_root, NULL);
	}

	return ret;
}

static inline void
rx_send_start_rnd(struct zhpe_rx_entry *rx_entry, struct zhpe_iov_state *lstate,
		  bool check_missing)
{
	int			rc;
	struct zhpe_pe_entry	*pe_entry;
	struct zhpe_rx_ctx	*rx_ctx;

	if (check_missing && OFI_UNLIKELY(lstate->missing) &&
	    rx_entry->total_len <= zhpe_ep_max_eager_sz) {
		rc = rx_send_start_buf(rx_entry, ZHPE_RX_STATE_RND_BUF);
		if (rc >= 0)
			goto done;
		rx_ctx = rx_entry->rx_free->rx_ctx;
		rc = zhpe_mr_reg_int_iov(rx_ctx->domain, lstate);
		if (rc < 0) {
			zhpe_pe_rx_complete(rx_ctx, rx_entry, rc);
			goto done;
		}
	}
	pe_entry = rx_entry->pe_entry;
	pe_entry->lstate = *lstate;
	pe_entry->lstate.missing = 0;
	pe_entry->pe_root.handler(&pe_entry->pe_root, NULL);
 done:

	return;
}

static inline void rx_user_claim(struct zhpe_rx_entry *rx_buffered,
				 struct zhpe_rx_entry *rx_user, bool multi)
{
	struct zhpe_iov_state	rstate;
	struct zhpe_pe_entry	*pe_entry;
	uint64_t		avail;

	rx_buffered->rx_user = rx_user;
	rx_buffered->flags |= (rx_user->flags & FI_COMPLETION);
	rx_buffered->context = rx_user->context;
	rx_buffered->lstate = rx_user->lstate;
	if (multi) {
		rx_buffered->buf = zhpe_iov_state_ptr(&rx_buffered->lstate);
		avail = zhpe_iov_state_avail(&rx_buffered->lstate);
		if (avail > rx_buffered->total_len) {
			if (avail - rx_buffered->total_len <
			    rx_buffered->conn->rx_ctx->min_multi_recv)
				dlist_remove_init(&rx_user->lentry);
			else
				zhpe_iov_state_adv(&rx_user->lstate,
						   rx_buffered->total_len);
		} else
			dlist_remove_init(&rx_user->lentry);
		rx_user->multi_cnt++;
	}

	switch (rx_buffered->rx_state) {

	case ZHPE_RX_STATE_RND_DIRECT:
		rx_send_start_rnd(rx_buffered, &rx_user->lstate, !multi);
		break;

	case ZHPE_RX_STATE_EAGER:
		set_rx_state(rx_buffered, ZHPE_RX_STATE_EAGER_CLAIMED);
		break;

	case ZHPE_RX_STATE_EAGER_DONE:
		pe_entry = rx_buffered->pe_entry;
		rstate = pe_entry->lstate;
		zhpe_iov_state_reset(&rstate);
		avail = rx_buffered->total_len - pe_entry->rem;
		rx_buffered->rem -=
			copy_iov(&rx_buffered->lstate, &rstate, avail);
		zhpe_pe_rx_complete(rx_buffered->conn->rx_ctx, rx_buffered,
				    pe_entry->pe_root.compstat.status);
		break;

	case ZHPE_RX_STATE_INLINE:
		rx_buffered->rem -=
			copy_mem_to_iov(&rx_buffered->lstate,
					rx_buffered->inline_data,
					rx_buffered->rem);
		zhpe_pe_rx_complete(rx_buffered->conn->rx_ctx, rx_buffered, 0);
		break;

	default:
		ZHPE_LOG_ERROR("rx_buffered %p in bad state %d\n",
			       rx_buffered, rx_buffered->rx_state);
		abort();
	}

	return;
}

void zhpe_pe_rx_post_recv(struct zhpe_rx_ctx *rx_ctx,
			  struct zhpe_rx_entry *rx_user)
{
	struct zhpe_rx_entry	*rx_buffered;

	dlist_foreach_container(&rx_ctx->rx_buffered_list,
				struct zhpe_rx_entry, rx_buffered, lentry) {
		if (!zhpe_rx_match_entry(rx_buffered, true, rx_user->addr,
					 rx_user->tag, rx_user->ignore,
					 rx_user->flags))
			continue;
		dlist_remove(&rx_buffered->lentry);
		dlist_insert_tail(&rx_buffered->lentry, &rx_ctx->rx_work_list);
		rx_user_claim(rx_buffered, rx_user, false);
		goto done;
	}
	dlist_insert_tail(&rx_user->lentry, &rx_ctx->rx_posted_list);
 done:
	zhpe_pe_signal(rx_ctx->domain->pe);

	return;
}

void zhpe_pe_rx_post_recv_multi(struct zhpe_rx_ctx *rx_ctx,
			  struct zhpe_rx_entry *rx_user)
{
	struct zhpe_rx_entry	*rx_buffered;

	rx_user->multi_cnt = 0;
	dlist_insert_tail(&rx_user->lentry, &rx_ctx->rx_posted_list);

	dlist_foreach_container(&rx_ctx->rx_buffered_list,
				struct zhpe_rx_entry, rx_buffered, lentry) {
		if (!zhpe_rx_match_entry(rx_buffered, true, rx_user->addr,
					 rx_user->tag, rx_user->ignore,
					 rx_user->flags))
			continue;
		dlist_remove(&rx_buffered->lentry);
		dlist_insert_tail(&rx_buffered->lentry, &rx_ctx->rx_work_list);
		rx_user_claim(rx_buffered, rx_user, true);
		if (dlist_empty(&rx_user->lentry))
			break;
	}
 	zhpe_pe_signal(rx_ctx->domain->pe);

	return;
}

void zhpe_pe_rx_claim_recv(struct zhpe_rx_entry *rx_claimed,
			   struct zhpe_rx_entry *rx_user)
{
	struct zhpe_rx_ctx	*rx_ctx;

	if (rx_user->flags & FI_DISCARD) {
		rx_ctx = rx_claimed->conn->rx_ctx;
		zhpe_pe_rx_report_complete(rx_ctx, rx_user, 0, 0);
		zhpe_rx_release_entry(rx_user);
		zhpe_pe_rx_discard_recv(rx_claimed);
		goto done;
	}
	rx_user_claim(rx_claimed, rx_user, false);
 done:
	return;
}

static inline int tx_update_compstat(struct zhpe_pe_entry *pe_entry, int status)
{
	struct zhpe_pe_compstat *cstat = &pe_entry->pe_root.compstat;
	struct zhpe_pe_compstat	old;
	struct zhpe_pe_compstat	new;

	if (OFI_UNLIKELY(status < 0)) {
		for (old = atm_load_rlx(cstat);;) {
			if (old.status >= 0)
				new.status = status;
			else
				new.status = old.status;
			new.completions = old.completions - 1;
			new.flags = old.flags;
			if (atm_cmpxchg(cstat, &old, new))
				break;
		}
	} else
		old.completions = atm_dec(&cstat->completions);

	assert(old.completions > 0);

	return old.completions - 1;
}

static inline void tx_update_status(struct zhpe_pe_entry *pe_entry, int status)
{
	struct zhpe_pe_compstat *cstat = &pe_entry->pe_root.compstat;
	int16_t			old;

	if (OFI_LIKELY(status >= 0))
		return;

	for (old = atm_load_rlx(&cstat->status);;) {
		if (old < 0)
			break;
		if (atm_cmpxchg(&cstat->status, &old, status))
			break;
	}
}

static inline int tx_cqe_status(struct zhpeq_cq_entry *zq_cqe)
{
	return ((!zq_cqe || zq_cqe->z.status == ZHPEQ_CQ_STATUS_SUCCESS) ?
		0 : -FI_EIO);
}

void zhpe_pe_tx_handle_entry(struct zhpe_pe_root *pe_root,
			     struct zhpeq_cq_entry *zq_cqe)
{
	struct zhpe_pe_entry	*pe_entry =
		container_of(pe_root, struct zhpe_pe_entry, pe_root);
	struct zhpe_pe_entry	*pe_entryu;

	if (!tx_update_compstat(pe_entry, tx_cqe_status(zq_cqe))) {
		if (!(pe_entry->pe_root.compstat.flags & ZHPE_PE_PROV)) {
			zhpe_pe_tx_report_complete(pe_entry,
						   FI_TRANSMIT_COMPLETE |
						   FI_DELIVERY_COMPLETE);
		} else if ((pe_entryu = pe_entry->pe_root.context)) {
			zhpe_pe_tx_report_complete(pe_entryu,
						   FI_TRANSMIT_COMPLETE |
						   FI_DELIVERY_COMPLETE);
			zhpe_tx_release(pe_entryu);
		}
		zhpe_tx_release(pe_entry);
	}
}

static void zhpe_pe_rx_handle_status(struct zhpe_conn *conn,
				     struct zhpe_msg_hdr *zhdr)
{
	union zhpe_msg_payload	*zpay;
	struct zhpe_pe_entry	*pe_entry;

	pe_entry = &conn->ztx->pentries[ntohs(zhdr->pe_entry_id)];

	zpay = zhpe_pay_ptr(conn, zhdr, 0, __alignof__(*zpay));
	tx_update_status(pe_entry, ntohs(zpay->status.status));
	/* pe_entry->rem only updated under rx_ctx locking */
	if (zpay->status.rem_valid)
		pe_entry->rem = be64toh(zpay->status.rem);

	pe_entry->pe_root.handler(&pe_entry->pe_root, NULL);
}

static void zhpe_pe_rx_handle_writedata(struct zhpe_conn *conn,
					struct zhpe_msg_hdr *zhdr)
{
	struct zhpe_cqe		zcqe = {
		.addr = conn->fi_addr,
		.comp = &conn->rx_ctx->comp,
	};
	union zhpe_msg_payload	*zpay;

	zpay = zhpe_pay_ptr(conn, zhdr, 0, __alignof__(*zpay));
	zcqe.cqe.flags = (be64toh(zpay->writedata.flags) &
			  (FI_REMOTE_READ | FI_REMOTE_WRITE |
			   FI_REMOTE_CQ_DATA | FI_RMA | FI_ATOMIC));
	zcqe.cqe.data = be64toh(zpay->writedata.cq_data);
	zhpe_pe_report_complete(&zcqe, 0, 0);
}

static void zhpe_pe_rx_handle_atomic(struct zhpe_conn *conn,
				     struct zhpe_msg_hdr *zhdr)
{
	int32_t			status = -FI_ENOKEY;
	uint64_t		orig;
	union zhpe_msg_payload	*zpay;
	uint64_t		o64;
	uint64_t		c64;
	void			*dst;
	struct zhpe_mr		*zmr;
	uint64_t		dontcare;
	struct zhpe_key		zkey;

	zpay = zhpe_pay_ptr(conn, zhdr, 0, __alignof__(*zpay));

	o64 = be64toh(zpay->atomic_req.operand);
	c64 = be64toh(zpay->atomic_req.compare);
	dst = (void *)(uintptr_t)be64toh(zpay->atomic_req.vaddr);

	zkey.key = be64toh(zpay->atomic_req.zkey.key);
	zkey.internal = !!zpay->atomic_req.zkey.internal;
	zmr = zhpe_mr_find(conn->ep_attr->domain, &zkey);
	if (zmr) {
		status = zhpeq_lcl_key_access(
			zmr->kdata, dst, zpay->atomic_req.datasize,
			ZHPEQ_MR_GET_REMOTE | ZHPEQ_MR_PUT_REMOTE, &dontcare);
		zhpe_mr_put(zmr);
		if (status < 0)
			goto done;
	}

	status = zhpeu_fab_atomic_op(zpay->atomic_req.datatype,
				     zpay->atomic_req.op, o64, c64, dst, &orig);
 done:

	if (zhdr->flags & ZHPE_MSG_DELIVERY_COMPLETE)
		zhpe_send_status_rem(conn, *zhdr, status, orig);
}

void zhpe_pe_complete_key_response(struct zhpe_conn *conn,
				   struct zhpe_msg_hdr ohdr, int rc)
{
	struct zhpe_pe_entry	*pe_entry;

	pe_entry = &conn->ztx->pentries[ntohs(ohdr.pe_entry_id)];
	tx_update_compstat(pe_entry, rc);

	if (pe_entry->pe_root.handler)
		pe_entry->pe_root.handler(&pe_entry->pe_root, NULL);
}

static void zhpe_pe_rx_handle_key_import(struct zhpe_conn *conn,
					 struct zhpe_msg_hdr *zhdr)
{
	union zhpe_msg_payload	*zpay;
	size_t			blob_len;

	zpay = zhpe_pay_ptr(conn, zhdr, 0, __alignof__(*zpay));
	blob_len = zhdr->inline_len - (zpay->key_data.blob - (char *)zhdr);
	zhpe_conn_rkey_import(conn, *zhdr, be64toh(zpay->key_data.key),
			      zpay->key_data.blob, blob_len, NULL);
}

static void zhpe_pe_rx_handle_key_request(struct zhpe_conn *conn,
					  struct zhpe_msg_hdr *zhdr)
{
	int			rc = 0;
	struct zhpe_domain	*domain;
	union zhpe_msg_payload	*zpay;
	size_t			i;
	size_t			keys;
	struct zhpe_mr		*zmr;
	struct zhpe_key		zkey;

	zpay = zhpe_pay_ptr(conn, zhdr, 0, __alignof__(*zpay));
	keys = ((zhdr->inline_len - ((char *)zpay - (char *)zhdr)) /
		sizeof(zpay->key_req.zkeys[0]));
	domain = conn->ep_attr->domain;
	for (i = 0; i < keys; i++) {
		if (rc >= 0) {
			memcpy(&zkey, &zpay->key_req.zkeys[i], sizeof(zkey));
			zkey.key = be64toh(zkey.key);
			zkey.internal = !!zkey.internal;
			zmr = zhpe_mr_find(domain, &zkey);
			if (zmr) {
				rc = zhpe_conn_key_export(conn, *zhdr, zmr);
				zhpe_mr_put(zmr);
			} else
				rc = -FI_ENOKEY;
		}
		if (rc < 0)
			zhpe_send_status(conn, *zhdr, rc);
	}
}

static void zhpe_pe_rx_handle_key_revoke(struct zhpe_conn *conn,
					 struct zhpe_msg_hdr *zhdr)
{
	int			rc;
	union zhpe_msg_payload	*zpay;
	size_t			i;
	size_t			keys;
	struct zhpe_key		zkey;

	zpay = zhpe_pay_ptr(conn, zhdr, 0, __alignof__(*zpay));
	keys = ((zhdr->inline_len - ((char *)zpay - (char *)zhdr)) /
		sizeof(zpay->key_req.zkeys[0]));
	for (i = 0; i < keys; i++) {
		memcpy(&zkey, &zpay->key_req.zkeys[i], sizeof(zkey));
		zkey.key = be64toh(zkey.key);
		zkey.internal = !!zkey.internal;
		rc = zhpe_conn_rkey_revoke(conn, *zhdr, &zkey);
		if (rc < 0) {
			ZHPE_LOG_ERROR("key revoke returned %d\n", rc);
			abort();
		}
	}
}

void zhpe_pe_retry_tx_ring1(struct zhpe_pe_retry *pe_retry)
{
	int			rc;
	int64_t			tindex = -1;
	struct zhpe_pe_entry	*pe_entry;
	struct zhpe_conn	*conn;
	struct zhpe_msg_hdr	*rhdr;
	struct zhpe_msg_hdr	*zhdr;
	uint64_t		lzaddr;
	struct zhpe_pe_root	*pe_root;

	pe_entry = pe_retry->data;
	pe_root = &pe_entry->pe_root;
	conn = pe_root->conn;
	rhdr = (void *)(pe_entry + 1);
	zhpe_tx_reserve_vars(rc, pe_root->handler, conn, pe_root->context,
			     tindex, pe_entry, zhdr, lzaddr, requeue,
			     (pe_root->compstat.flags & ZHPE_PE_PROV));
	memcpy(zhdr, rhdr, rhdr->inline_len);
	rc = zhpe_pe_tx_ring(pe_entry, zhdr, lzaddr, zhdr->inline_len);
	if (rc < 0) {
		ZHPE_LOG_ERROR("Retry failed %d\n", rc);
		abort();
	}
	zhpe_pe_retry_free(conn->ztx, pe_retry);

	return;
 requeue:
	zhpe_conn_pull(conn);
	zhpe_pe_retry_insert(conn->ztx, pe_retry);
}

void zhpe_pe_retry_tx_ring2(struct zhpe_pe_retry *pe_retry)
{
	int			rc;
	struct zhpe_pe_entry	*pe_entry;
	struct zhpe_conn	*conn;
	size_t			off;
	struct zhpe_msg_hdr	*zhdr;
	uint64_t		lzaddr;

	pe_entry = pe_retry->data;
	conn = pe_entry->pe_root.conn;
	off = zhpe_ring_off(conn, pe_entry - conn->ztx->pentries);
	zhdr = (void *)(conn->ztx->zentries + off);
	lzaddr = conn->ztx->lz_zentries + off;
	rc = zhpe_pe_tx_ring(pe_entry, zhdr, lzaddr, zhdr->inline_len);
	if (rc < 0) {
		ZHPE_LOG_ERROR("Retry failed %d\n", rc);
		abort();
	}
	zhpe_pe_retry_free(conn->ztx, pe_retry);
}

static inline int zhpe_pe_rem_setup(struct zhpe_conn *conn,
				    struct zhpe_iov_state *rstate,
				    bool get)
{
	int			ret = 0;
	struct zhpe_iov		*riov = rstate->viov;
	uint8_t			missing = rstate->missing;
	int			i;
	struct zhpe_key		zkey;
	struct zhpe_rkey_data	*rkey;

        for (i = ffs(missing) - 1; i >= 0;
	     (missing &= ~(1U << i), i = ffs(missing) - 1)) {
		zhpe_ziov_to_zkey(&riov[i], &zkey);
		rkey = zhpe_conn_rkey_get(conn, &zkey);
		if (OFI_UNLIKELY(!rkey)) {
			ZHPE_LOG_ERROR("No rkey data for 0x%Lx/%d\n",
				       (ullong)zkey.key, zkey.internal);
			ret = -FI_ENOKEY;
			break;
		}
		/* rkey no longer missing. */
		riov[i].iov_rkey = rkey;
		ret = zhpeq_rem_key_access(rkey->kdata, riov[i].iov_raddr,
					   zhpe_ziov_len(&riov[i]),
					   (get ? ZHPEQ_MR_GET_REMOTE :
					    ZHPEQ_MR_PUT_REMOTE),
					   &riov[i].iov_zaddr);
		if (ret < 0) {
			ZHPE_LOG_ERROR("zhpeq_rem_key_access() returned %d\n",
				       ret);
			break;
		}
	}
	rstate->missing = missing;

	return ret;
}

static inline void rx_riov_init(struct zhpe_rx_entry *rx_entry,
				union zhpe_msg_payload *zpay)
{
	struct zhpe_pe_entry	*pe_entry = rx_entry->pe_entry;

	pe_entry->riov[0].iov_len = be64toh(zpay->indirect.len);
	pe_entry->riov[0].iov_base = TO_PTR(be64toh(zpay->indirect.vaddr));
	pe_entry->riov[0].iov_key = be64toh(zpay->indirect.key);
	pe_entry->riov[0].iov_zaddr = 0;
	zhpe_iov_state_init(&pe_entry->rstate, &zhpe_iov_state_ziovr_ops,
			    pe_entry->riov);
	pe_entry->rstate.cnt = 1;
	pe_entry->rstate.missing = 1;
}

static inline void rx_basic_init(struct zhpe_rx_entry *rx_entry,
				 struct zhpe_conn *conn,
				 struct zhpe_msg_hdr *zhdr,
				 uint64_t msg_len, uint64_t tag,
				 uint64_t cq_data, uint64_t flags)
{
	rx_entry->buf = NULL;
	rx_entry->conn = conn;
	rx_entry->rem = msg_len;
	rx_entry->total_len = msg_len;
	rx_entry->addr = conn->fi_addr;
	rx_entry->cq_data = cq_data;
	rx_entry->tag = tag;
	rx_entry->zhdr = *zhdr;
	rx_entry->flags |= flags;
}

static inline void rx_buffered_inline_init(struct zhpe_rx_entry *rx_buffered,
					   struct zhpe_msg_hdr *zhdr)
{
	struct zhpe_conn	*conn = rx_buffered->conn;
	void			*src;

	src = zhpe_pay_ptr(conn, zhdr, 0, sizeof(int));
	memcpy(rx_buffered->inline_data, src, rx_buffered->total_len);
	set_rx_state(rx_buffered, ZHPE_RX_STATE_INLINE);
}

static inline int zhpe_pe_rx_pe_entry(struct zhpe_rx_entry *rx_entry)
{
	int			ret = 0;
	struct zhpe_pe_entry	*pe_entry;
	int64_t			tindex;

	tindex = zhpe_tx_reserve(rx_entry->conn->ztx, 0);
	if (OFI_LIKELY(tindex >= 0)) {
		pe_entry = &rx_entry->conn->ztx->pentries[tindex];
		pe_entry->pe_root.compstat.status = 0;
		pe_entry->pe_root.compstat.completions = 0;
	} else {
		pe_entry = calloc(1, sizeof(*pe_entry));
		if (!pe_entry) {
			ret = -FI_ENOMEM;
			goto done;
		}
		pe_entry->pe_root.compstat.flags |= ZHPE_PE_RETRY;
	}
	pe_entry->pe_root.handler = zhpe_pe_tx_handle_rx_rma;
	pe_entry->pe_root.conn = rx_entry->conn;
	pe_entry->pe_root.context = rx_entry;
	pe_entry->pe_root.compstat.status = 0;
	pe_entry->pe_root.compstat.completions = 1;
	pe_entry->pe_root.compstat.flags |= ZHPE_PE_KEY_WAIT;
	pe_entry->rem = rx_entry->total_len;
	pe_entry->flags = FI_READ;
 done:
	rx_entry->pe_entry = pe_entry;

	return ret;
}

static void rx_handle_send_match(struct zhpe_rx_entry *rx_buffered)
{
	struct zhpe_conn	*conn = rx_buffered->conn;
	struct zhpe_rx_ctx	*rx_ctx = conn->rx_ctx;
	struct zhpe_rx_entry	*rx_user;

	dlist_foreach_container(&rx_ctx->rx_posted_list, struct zhpe_rx_entry,
				rx_user, lentry) {
		if (!zhpe_rx_match_entry(rx_user, false, conn->fi_addr,
					 rx_buffered->tag, rx_user->ignore,
					 rx_buffered->flags))
			continue;
		dlist_insert_tail(&rx_buffered->lentry, &rx_ctx->rx_work_list);
		if (rx_user->flags & FI_MULTI_RECV)
			rx_user_claim(rx_buffered, rx_user, true);
		else {
			dlist_remove_init(&rx_user->lentry);
			rx_user_claim(rx_buffered, rx_user, false);
		}
		return;
	}
	dlist_insert_tail(&rx_buffered->lentry, &rx_ctx->rx_buffered_list);
}

static void zhpe_pe_rx_handle_send(struct zhpe_conn *conn,
				   struct zhpe_msg_hdr *zhdr)
{
	uint64_t		flags = 0;
	struct zhpe_rx_ctx	*rx_ctx = conn->rx_ctx;
	uint64_t		tag = 0;
	uint64_t		cq_data = 0;
	union zhpe_msg_payload	*zpay = NULL;
	struct zhpe_rx_entry	*rx_entry;
	uint64_t		msg_len;
	uint64_t		*data;

	if (zhdr->flags & ZHPE_MSG_INLINE) {
		msg_len = zhdr->inline_len;
		data = zhpe_pay_ptr(conn, zhdr, msg_len, __alignof__(*data));
		if (zhdr->flags & ZHPE_MSG_TAGGED) {
			flags |= FI_TAGGED;
			tag = be64toh(*data++);
		}
		if (zhdr->flags & ZHPE_MSG_REMOTE_CQ_DATA) {
			flags |= FI_REMOTE_CQ_DATA;
			cq_data = be64toh(*data++);
		}
	}  else {
		zpay = zhpe_pay_ptr(conn, zhdr, 0, __alignof__(*zpay));
		msg_len = be64toh(zpay->indirect.len) & ~ZHPE_ZIOV_LEN_KEY_INT;
		if (zhdr->flags & ZHPE_MSG_TAGGED) {
			flags |= FI_TAGGED;
			tag = be64toh(zpay->indirect.tag);
		}
		if (zhdr->flags & ZHPE_MSG_REMOTE_CQ_DATA) {
			flags |= FI_REMOTE_CQ_DATA;
			cq_data = be64toh(zpay->indirect.cq_data);
		}
	}

	rx_entry = zhpe_rx_new_entry(&rx_ctx->rx_prog_free);
	if (!rx_entry) {
		ZHPE_LOG_ERROR("Out of memory\n");
		abort();
	}
	rx_basic_init(rx_entry, conn, zhdr, msg_len, tag, cq_data, flags);
	if (zhdr->flags & ZHPE_MSG_INLINE)
		rx_buffered_inline_init(rx_entry, zhdr);
	else {
		if (zhpe_pe_rx_pe_entry(rx_entry) < 0) {
			ZHPE_LOG_ERROR("Out of memory\n");
			abort();
		}
		rx_riov_init(rx_entry, zpay);
		if (rx_entry->total_len > zhpe_ep_max_eager_sz ||
		    rx_send_start_buf(rx_entry, ZHPE_RX_STATE_EAGER) < 0)
			set_rx_state(rx_entry, ZHPE_RX_STATE_RND_DIRECT);
	}
	/* Throw the entry to the rx_ctx for further processing. */
	zhpeu_atm_snatch_insert(&rx_entry->rx_free->rx_ctx->rx_match_list,
				&rx_entry->rx_match_next);
}

void zhpe_pe_tx_rma_completion(struct zhpe_pe_entry *pe_entry)
{
	int			rc;

	if (pe_entry->pe_root.compstat.status >= 0 &&
	    (pe_entry->flags &
	     (FI_REMOTE_READ | FI_REMOTE_WRITE | FI_REMOTE_CQ_DATA)) &&
	    !pe_entry->pe_root.conn->fam) {
		rc = zhpe_pe_writedata(pe_entry);
		if (rc >= 0)
			return;
		tx_update_status(pe_entry, rc);
	}
	zhpe_pe_tx_report_complete(pe_entry,
				   FI_TRANSMIT_COMPLETE | FI_DELIVERY_COMPLETE);
	zhpe_tx_release(pe_entry);
}

static void zhpe_pe_rx_rma_completion(struct zhpe_pe_entry *pe_entry)
{
	struct zhpe_rx_entry	*rx_entry = pe_entry->pe_root.context;

	/* We cannot change the rx_entry state in the tx context. */
	zhpeu_atm_snatch_insert(&rx_entry->rx_free->rx_ctx->rx_iodone_list,
				&rx_entry->rx_iodone_next);
}

void zhpe_pe_tx_handle_rma(struct zhpe_pe_root *pe_root,
			  struct zhpeq_cq_entry *zq_cqe)
{
	struct zhpe_pe_entry	*pe_entry =
		container_of(pe_root, struct zhpe_pe_entry, pe_root);

	if (!tx_update_compstat(pe_entry, tx_cqe_status(zq_cqe))) {
		if (zq_cqe &&
		    ((pe_entry->flags & (FI_INJECT | FI_READ)) ==
		     (FI_INJECT | FI_READ)))
		    copy_mem_to_iov(&pe_entry->lstate, zq_cqe->z.result.data,
				    ZHPEQ_IMM_MAX);

		zhpe_pe_tx_rma(pe_entry, zhpe_pe_tx_rma_completion);
	}
}

static void zhpe_pe_tx_handle_rx_rma(struct zhpe_pe_root *pe_root,
				     struct zhpeq_cq_entry *zq_cqe)
{
	struct zhpe_pe_entry	*pe_entry =
		container_of(pe_root, struct zhpe_pe_entry, pe_root);

	zhpe_stats_start(zhpe_stats_subid(RECV, 1010));
	if (!tx_update_compstat(pe_entry, tx_cqe_status(zq_cqe)))
		zhpe_pe_tx_rma(pe_entry, zhpe_pe_rx_rma_completion);
	zhpe_stats_stop(zhpe_stats_subid(RECV, 1010));
}

static void zhpe_pe_retry_tx_rma(struct zhpe_pe_retry *pe_retry)
{
	struct zhpe_pe_entry	*pe_entry = pe_retry->data;
	struct zhpe_conn	*conn = pe_entry->pe_root.conn;
	struct zhpe_pe_entry	*new;
	int64_t			tindex;
	uint8_t			pe_flags;

	if (!(pe_entry->pe_root.compstat.flags & ZHPE_PE_RETRY)) {
		pe_entry->pe_root.handler(&pe_entry->pe_root, NULL);
		goto done;
	}
	/* We're a malloc'd blob and not a real pe_entry. */
	tindex = zhpe_tx_reserve(conn->ztx, 0);
	if (tindex < 0)
		goto requeue;
	new = &conn->ztx->pentries[tindex];
	pe_flags = new->pe_root.compstat.flags;
	pe_flags |= (pe_entry->pe_root.compstat.flags & ~ZHPE_PE_RETRY);
	*new = *pe_entry;
	new->pe_root.compstat.flags = pe_flags;
	new->lstate.viov = new->liov;
	new->rstate.viov = new->riov;
	free(pe_entry);
	new->pe_root.handler(&new->pe_root, NULL);
 done:
	free(pe_retry);
	return;

 requeue:
	zhpe_pe_retry_insert(conn->ztx, pe_retry);
}

static int zhpe_pe_writedata(struct zhpe_pe_entry *pe_entry)
{
	struct zhpe_msg_hdr	ohdr;
	struct zhpe_msg_writedata writedata;

	ohdr.op_type = ZHPE_OP_WRITEDATA;
	ohdr.rx_id = pe_entry->rx_id;
	writedata.flags = htobe64(pe_entry->flags);
	writedata.cq_data = htobe64(pe_entry->cq_data);

	return zhpe_tx_op(pe_entry->pe_root.conn, ohdr,
			  ZHPE_PE_PROV | ZHPE_PE_RETRY,
			  &writedata, sizeof(writedata), pe_entry);
}

static void
zhpe_pe_tx_rma(struct zhpe_pe_entry *pe_entry,
	       void (*completion)(struct zhpe_pe_entry *pe_entry))
{
	int			rc;

	assert(pe_entry->pe_root.compstat.completions == 0);
	if (OFI_UNLIKELY(pe_entry->pe_root.compstat.status < 0))
		goto complete;

	if (OFI_UNLIKELY(pe_entry->pe_root.compstat.flags & ZHPE_PE_KEY_WAIT)) {
		pe_entry->pe_root.compstat.flags &= ~ZHPE_PE_KEY_WAIT;
		rc = zhpe_pe_rem_setup(pe_entry->pe_root.conn,
				       &pe_entry->rstate,
				       !(pe_entry->flags & FI_WRITE));
		tx_update_status(pe_entry, rc);
		if (rc < 0)
			goto complete;
	}
	if (!pe_entry->rem)
		goto complete;
	if (pe_entry->flags & FI_INJECT) {
		if (pe_entry->flags & FI_READ)
			rc = zhpe_iov_to_get_imm(
				&pe_entry->pe_root, pe_entry->rem,
				&pe_entry->rstate, &pe_entry->rem);
		else
			rc = zhpe_put_imm_to_iov(
				&pe_entry->pe_root, pe_entry->inline_data,
				pe_entry->rem, &pe_entry->rstate,
				&pe_entry->rem);
	} else
		rc = zhpe_iov_op(&pe_entry->pe_root,
				 &pe_entry->lstate, &pe_entry->rstate,
				 ZHPE_SEG_MAX_BYTES, ZHPE_SEG_MAX_OPS,
				 ((pe_entry->flags & FI_READ) ?
				  zhpe_iov_op_get : zhpe_iov_op_put),
				 &pe_entry->rem);
	if (rc > 0)
		goto done;
	if (rc < 0) {
		if (rc == -FI_EAGAIN) {
			rc = zhpe_pe_retry(pe_entry->pe_root.conn->ztx,
					   zhpe_pe_retry_tx_rma, pe_entry,
					   NULL);
			if (rc >= 0)
				goto done;
		}
		tx_update_status(pe_entry, rc);
	}

 complete:
	completion(pe_entry);
 done:
	return;
}

void zhpe_pe_rkey_request(struct zhpe_conn *conn, struct zhpe_msg_hdr ohdr,
			  struct zhpe_iov_state *rstate, int8_t *completions)
{
	struct zhpe_iov		*ziov = rstate->viov;
	uint			missing = rstate->missing;
	int			i;
	uint			j;
	struct zhpe_msg_key_request key_req;
	struct zhpe_key		zkey;

	for (i = ffs(missing) - 1, j = 0; i >= 0;
	     (missing &= ~(1U << i), i = ffs(missing) - 1)) {
		zhpe_ziov_to_zkey(&ziov[i], &zkey);
		zkey.key = htobe64(zkey.key);
		memcpy(&key_req.zkeys[j++], &zkey, sizeof(key_req.zkeys[0]));
		(*completions)++;
	}
	ohdr.op_type = ZHPE_OP_KEY_REQUEST;
	zhpe_prov_op(conn, ohdr, ZHPE_PE_RETRY,
		     &key_req, sizeof(key_req.zkeys[0]) * j);
}

void zhpe_pe_tx_handle_atomic(struct zhpe_pe_root *pe_root,
			      struct zhpeq_cq_entry *zq_cqe)
{
	struct zhpe_pe_entry	*pe_entry =
		container_of(pe_root, struct zhpe_pe_entry, pe_root);
	int			rc MAYBE_UNUSED;

	if (tx_update_compstat(pe_entry, tx_cqe_status(zq_cqe)))
		goto done;
	if (pe_entry->pe_root.compstat.status < 0)
		goto complete;

	if (pe_entry->result) {
		rc = zhpeu_fab_atomic_store(pe_entry->result_type,
					    pe_entry->result, pe_entry->rem);
		assert(!rc);
	}

 complete:
	zhpe_pe_tx_report_complete(pe_entry,
				   FI_TRANSMIT_COMPLETE | FI_DELIVERY_COMPLETE);
	zhpe_tx_release(pe_entry);

 done:
	return;
}

int zhpe_pe_tx_hw_atomic(struct zhpe_pe_entry *pe_entry)
{
	int64_t			ret;
	struct zhpe_pe_root	*pe_root = &pe_entry->pe_root;
	struct zhpe_conn	*conn = pe_root->conn;
	struct zhpe_tx		*ztx = conn->ztx;
	int64_t			zindex = -1;

	ret = zhpeq_reserve(ztx->zq, 1);
	if (ret < 0)
		goto done;
	zindex = ret;

	ret = zhpeq_atomic(ztx->zq, zindex, false, true,
			   pe_entry->atomic_size, pe_entry->atomic_op,
			   zhpe_iov_state_zaddr(&pe_entry->rstate),
			   pe_entry->atomic_operands, &pe_entry->pe_root);

	ret = zhpe_zq_commit_spin(ztx->zq, zindex, 1);
	if (ret < 0)
		goto done;
	atm_inc(&conn->ep_attr->counters.hw_atomics);
	zhpe_stats_pause_all();
	zhpeq_signal(ztx->zq);
	zhpe_stats_restart_all();
	zhpe_pe_signal(conn->ep_attr->domain->pe);
 done:
	if (OFI_UNLIKELY(ret < 0))
		zhpe_tx_free_res(conn, -1, zindex, -1, pe_root->compstat.flags);

	return ret;
}

void zhpe_pe_tx_handle_hw_atomic(struct zhpe_pe_root *pe_root,
				 struct zhpeq_cq_entry *zq_cqe)
{
	struct zhpe_pe_entry	*pe_entry =
		container_of(pe_root, struct zhpe_pe_entry, pe_root);
	int			rc;

	rc = tx_update_compstat(pe_entry, tx_cqe_status(zq_cqe));
	assert(!rc);
	if (pe_entry->pe_root.compstat.status < 0)
		goto complete;

	if (pe_entry->pe_root.compstat.flags & ZHPE_PE_KEY_WAIT) {
		pe_entry->pe_root.compstat.flags &= ~ZHPE_PE_KEY_WAIT;
		rc = zhpe_pe_rem_setup(pe_entry->pe_root.conn,
				       &pe_entry->rstate,
				       !(pe_entry->flags & FI_WRITE));
		if (rc >= 0) {
			pe_entry->pe_root.compstat.completions = 1;
			rc = zhpe_pe_tx_hw_atomic(pe_entry);
			if (rc >= 0)
				goto done;
		}
		tx_update_status(pe_entry, rc);
		goto complete;
	}
	if (pe_entry->result) {
		rc = zhpeu_fab_atomic_copy(pe_entry->result_type,
					   zq_cqe->z.result.data,
					   pe_entry->result);
		assert(!rc);
	}

 complete:
	zhpe_pe_tx_report_complete(pe_entry,
				   FI_TRANSMIT_COMPLETE |FI_DELIVERY_COMPLETE);
	zhpe_tx_release(pe_entry);
 done:
	return;
}

static inline void zhpe_pe_progress_rx_queue(struct zhpe_tx *ztx)
{
	struct zhpe_rx_local	*rx_ringl;
	struct zhpe_conn	*conn;
	struct zhpe_msg_hdr	*zhdr;
	uint32_t		idx;
	uint8_t			valid;
	struct zhpeu_atm_list_next *poll_cur;

	/* Poll all connections for traffic.
	 * Don't need to care about tail race since list only grows longer.
	 */
	for (poll_cur = atm_load_rlx(&ztx->rx_poll_list.head); poll_cur;
	     poll_cur = atm_load_rlx(&poll_cur->next)) {
		conn = container_of(poll_cur, struct zhpe_conn, rx_poll_next);
		/* Read new entries in ring. */
		rx_ringl = &conn->rx_local;
		for (;; rx_ringl->head++) {
			idx = rx_ringl->head & rx_ringl->cmn.mask;
			valid = ((rx_ringl->head &
				  (rx_ringl->cmn.mask + 1)) ?
				 0 : ZHPE_MSG_VALID_TOGGLE);
			zhdr = (void *)(rx_ringl->zentries +
					zhpe_ring_off(conn, idx));
			if ((zhdr->flags & ZHPE_MSG_VALID_TOGGLE) != valid)
				break;

			switch (zhdr->op_type) {

			case ZHPE_OP_ATOMIC:
				zhpe_pe_rx_handle_atomic(conn, zhdr);
				break;

			case ZHPE_OP_KEY_EXPORT:
			case ZHPE_OP_KEY_RESPONSE:
				zhpe_stats_start(zhpe_stats_subid(RECV, 1020));
				zhpe_pe_rx_handle_key_import(conn, zhdr);
				zhpe_stats_stop(zhpe_stats_subid(RECV, 1020));
				break;

			case ZHPE_OP_KEY_REQUEST:
				zhpe_pe_rx_handle_key_request(conn, zhdr);
				break;

			case ZHPE_OP_KEY_REVOKE:
				zhpe_pe_rx_handle_key_revoke(conn, zhdr);
				break;

			case ZHPE_OP_SEND:
				zhpe_stats_start(zhpe_stats_subid(RECV, 1000));
				zhpe_pe_rx_handle_send(conn, zhdr);
				zhpe_stats_stop(zhpe_stats_subid(RECV, 1000));
				break;

			case ZHPE_OP_STATUS:
				zhpe_pe_rx_handle_status(conn, zhdr);
				break;

			case ZHPE_OP_WRITEDATA:
				zhpe_pe_rx_handle_writedata(conn, zhdr);
				break;

			default:
				ZHPE_LOG_ERROR("Illegal opcode %d\n",
					       zhdr->op_type);
				abort();
			}
			/* Track completions so information are what
			 * entries are free can flow back to tx side.
			 */
			zhpe_rx_local_release(conn, idx);
		}
	}
}

static inline bool _zhpe_pe_progress_rx_ctx(struct zhpe_rx_ctx *rx_ctx)
{
	bool			ret;
	struct zhpe_rx_entry	*rx_entry;
	struct zhpeu_atm_snatch_head rxh_list;
	struct zhpeu_atm_list_next *rxh_cur;
	struct zhpeu_atm_list_next *rxh_next;


	/* Process pending handlers. */
	zhpeu_atm_snatch_list(&rx_ctx->rx_iodone_list, &rxh_list);
	for (rxh_cur = rxh_list.head; rxh_cur; rxh_cur = rxh_next) {
		rx_entry = container_of(rxh_cur, struct zhpe_rx_entry,
					rx_iodone_next);
		rxh_next = atm_load_rlx(&rxh_cur->next);
		if (rxh_next == ZHPEU_ATM_LIST_END)
			rxh_next = NULL;
		zhpe_stats_start(zhpe_stats_subid(RECV, 1030));
		rx_handle_send_rma_complete(rx_entry);
		zhpe_stats_stop(zhpe_stats_subid(RECV, 1030));
	}
	zhpeu_atm_snatch_list(&rx_ctx->rx_match_list, &rxh_list);
	for (rxh_cur = rxh_list.head; rxh_cur; rxh_cur = rxh_next) {
		rx_entry = container_of(rxh_cur, struct zhpe_rx_entry,
					rx_match_next);
		rxh_next = atm_load_rlx(&rxh_cur->next);
		if (rxh_next == ZHPEU_ATM_LIST_END)
			rxh_next = NULL;
		zhpe_stats_start(zhpe_stats_subid(RECV, 1040));
		rx_handle_send_match(rx_entry);
		zhpe_stats_stop(zhpe_stats_subid(RECV, 1040));
	}

	ret = (!dlist_empty(&rx_ctx->rx_posted_list) ||
	       !dlist_empty(&rx_ctx->rx_buffered_list) ||
	       !dlist_empty(&rx_ctx->rx_work_list));

	return ret;
}

static bool zhpe_pe_progress_rx_ctx_locked(struct zhpe_rx_ctx *rx_ctx)
{
	bool			ret;

	mutex_lock(&rx_ctx->mutex);
	ret = _zhpe_pe_progress_rx_ctx(rx_ctx);
	mutex_unlock(&rx_ctx->mutex);

	return ret;
}

static bool zhpe_pe_progress_rx_ctx_unlocked(struct zhpe_rx_ctx *rx_ctx)
{
	return _zhpe_pe_progress_rx_ctx(rx_ctx);
}

void zhpe_pe_progress_rx_ctx(struct zhpe_pe *pe, struct zhpe_rx_ctx *rx_ctx)
{
	struct zhpe_tx		*ztx = atm_load_rlx(&rx_ctx->ep_attr->ztx);

	if (OFI_LIKELY(!!ztx)) {
			if (ztx->progress != rx_ctx->tx_progress_last)
				pe->progress_queue(ztx);
			rx_ctx->tx_progress_last = ztx->progress + 1;
	}
	pe->progress_rx(rx_ctx);
}

static inline bool zhpe_pe_progress_tx_queue(struct zhpe_tx *ztx)
{
	bool			ret;
	struct zhpeq_cq_entry	zq_cqe[ZHPE_RING_TX_CQ_ENTRIES];
	ssize_t			entries;
	ssize_t			i;
	void			*context;
	struct zhpe_pe_root	*pe_root;
	struct zhpe_pe_retry	*pe_retry;
	struct zhpeu_atm_snatch_head atm_list;
	struct zhpeu_atm_list_next *atm_cur;
	struct zhpeu_atm_list_next *atm_next;

	if (!ztx)
		return false;

	entries = zhpeq_cq_read(ztx->zq, zq_cqe, ARRAY_SIZE(zq_cqe));
	if (entries < 0) {
		ret = entries;
		ZHPE_LOG_ERROR("zhpeq_cq_read() error %d\n", ret);
		abort();
	}
	for (i = 0; i < entries; i++) {
		context = zq_cqe[i].z.context;
		if (context == ZHPE_CONTEXT_IGNORE_PTR) {
			if (zq_cqe[i].z.status == ZHPEQ_CQ_STATUS_SUCCESS)
				continue;
			ZHPE_LOG_ERROR("Send of control I/O failed\n");
			abort();
		}
		pe_root = context;
		pe_root->handler(pe_root, &zq_cqe[i]);
	}
	zhpeu_atm_snatch_list(&ztx->pe_retry_list, &atm_list);
	if (OFI_UNLIKELY(!!atm_list.head)) {
		for (atm_cur = atm_list.head; atm_cur; atm_cur = atm_next) {
			pe_retry = container_of(atm_cur, struct zhpe_pe_retry,
						next);
			atm_next = atm_load_rlx(&atm_cur->next);
			if (atm_next == ZHPEU_ATM_LIST_END)
				atm_next = NULL;
			pe_retry->handler(pe_retry);
		}
		ret = true;
	} else
		/* Test is only racy if other threads involved and they should
		 * be signaling the progress thread.
		 */
		ret = ((atm_load_rlx(&ztx->ufree.count) +
			atm_load_rlx(&ztx->pfree.count)) != ztx->mask + 1);

	return ret;
}

static bool zhpe_pe_progress_queue_locked(struct zhpe_tx *ztx)
{
	bool			ret;

	mutex_lock(&ztx->mutex);
	ret = zhpe_pe_progress_tx_queue(ztx);
	zhpe_pe_progress_rx_queue(ztx);
	mutex_unlock(&ztx->mutex);

	return ret;
}

static bool zhpe_pe_progress_queue_unlocked(struct zhpe_tx *ztx)
{
	bool			ret;

	ret = zhpe_pe_progress_tx_queue(ztx);
	zhpe_pe_progress_rx_queue(ztx);
	ztx->progress++;

	return ret;
}

void zhpe_pe_progress_tx_ctx(struct zhpe_pe *pe, struct zhpe_tx_ctx *tx_ctx)
{
	struct zhpe_tx		*ztx = atm_load_rlx(&tx_ctx->ep_attr->ztx);

	if (OFI_LIKELY(!!ztx))
		pe->progress_queue(ztx);
}

#if !defined __APPLE__ && !defined _WIN32
static void zhpe_thread_set_affinity(char *s)
{
	char *saveptra = NULL, *saveptrb = NULL, *saveptrc = NULL;
	char *a, *b, *c;
	int j, first, last, stride;
	cpu_set_t mycpuset;
	pthread_t mythread;

	mythread = pthread_self();
	CPU_ZERO(&mycpuset);

	a = strtok_r(s, ",", &saveptra);
	while (a) {
		first = last = -1;
		stride = 1;
		b = strtok_r(a, "-", &saveptrb);
		assert(b);
		first = atoi(b);
		/* Check for range delimiter */
		b = strtok_r(NULL, "-", &saveptrb);
		if (b) {
			c = strtok_r(b, ":", &saveptrc);
			assert(c);
			last = atoi(c);
			/* Check for stride */
			c = strtok_r(NULL, ":", &saveptrc);
			if (c)
				stride = atoi(c);
		}

		if (last == -1)
			last = first;

		for (j = first; j <= last; j += stride)
			CPU_SET(j, &mycpuset);
		a =  strtok_r(NULL, ",", &saveptra);
	}

	j = pthread_setaffinity_np(mythread, sizeof(cpu_set_t), &mycpuset);
	if (j != 0)
		ZHPE_LOG_ERROR("pthread_setaffinity_np failed\n");
}
#endif

static void zhpe_pe_set_affinity(void)
{
	if (zhpe_pe_affinity_str == NULL)
		return;

#if !defined __APPLE__ && !defined _WIN32
	zhpe_thread_set_affinity(zhpe_pe_affinity_str);
#else
	ZHPE_LOG_ERROR("*** FI_SOCKETS_PE_AFFINITY is not supported on OS X\n");
#endif
}

static int pe_work_queue(struct zhpe_pe *pe, zhpeu_worker worker, void *data)
{

	int			ret;
	struct zhpeu_work	work;
	bool			do_auto;

	do_auto = (pe->domain->util_domain.data_progress == FI_PROGRESS_AUTO);
	zhpeu_work_init(&work);
	zhpeu_work_queue(&pe->work_head, &work, worker, data,
			 true, true, !do_auto);
	if (do_auto)
		zhpeu_work_wait(&pe->work_head, &work, false, true);
	else
		while (zhpeu_work_process(&pe->work_head, true, true));
	ret = work.status;
	zhpeu_work_destroy(&work);

	return ret;
}

static bool pe_add_queue(struct zhpeu_work_head
			    *head, struct zhpeu_work *work)
{
	struct zhpe_pe		*pe =
		container_of(head, struct zhpe_pe, work_head);
	struct zhpe_tx		*ztx = work->data;

	if (dlist_empty(&ztx->pe_lentry))
		dlist_insert_tail(&ztx->pe_lentry, &pe->queue_list);

	return false;
}

void zhpe_pe_add_queue(struct zhpe_tx *ztx)
{
	pe_work_queue(ztx->ep_attr->domain->pe, pe_add_queue, ztx);
}

static bool pe_remove_queue(struct zhpeu_work_head *head,
			    struct zhpeu_work *work)
{
	struct zhpe_tx		*ztx = work->data;

	dlist_remove_init(&ztx->pe_lentry);

	return false;
}

void zhpe_pe_remove_queue(struct zhpe_tx *ztx)
{
	if (!ztx)
		return;

	pe_work_queue(ztx->ep_attr->domain->pe, pe_remove_queue, ztx);
}

void zhpe_pe_add_tx_ctx(struct zhpe_tx_ctx *ztx_ctx)
{
}

void zhpe_pe_remove_tx_ctx(struct zhpe_tx_ctx *tx_ctx)
{
}

static bool pe_add_rx_ctx(struct zhpeu_work_head *head,
			  struct zhpeu_work *work)
{
	struct zhpe_pe		*pe =
		container_of(head, struct zhpe_pe, work_head);
	struct zhpe_rx_ctx	*rx_ctx = work->data;

	if (dlist_empty(&rx_ctx->pe_lentry))
		dlist_insert_tail(&rx_ctx->pe_lentry, &pe->rx_list);

	return false;
}

void zhpe_pe_add_rx_ctx(struct zhpe_rx_ctx *rx_ctx)
{
	pe_work_queue(rx_ctx->domain->pe, pe_add_rx_ctx, rx_ctx);
}

static bool pe_remove_rx_ctx(struct zhpeu_work_head *head,
			     struct zhpeu_work *work)
{
	struct zhpe_rx_ctx	*rx_ctx = work->data;

	dlist_remove_init(&rx_ctx->pe_lentry);

	return false;
}

void zhpe_pe_remove_rx_ctx(struct zhpe_rx_ctx *rx_ctx)
{
	if (!rx_ctx)
		return;

	pe_work_queue(rx_ctx->domain->pe, pe_remove_rx_ctx, rx_ctx);
}

static bool zhpe_pe_progress(struct zhpe_pe *pe)
{
	bool			ret = false;
	struct zhpe_tx		*ztx;
	struct zhpe_rx_ctx	*rx_ctx;

	dlist_foreach_container(&pe->queue_list, struct zhpe_tx, ztx, pe_lentry)
		ret |= pe->progress_queue(ztx);
	dlist_foreach_container(&pe->rx_list, struct zhpe_rx_ctx, rx_ctx,
				pe_lentry)
		ret |= pe->progress_rx(rx_ctx);

	return ret;
}

static void *zhpe_pe_progress_thread(void *data)
{
	struct zhpe_pe		*pe = (struct zhpe_pe *)data;
	bool			locked = false;
	uint64_t		wait_beg = 0;
	uint64_t		wait_end;
	bool			outstanding;

	ZHPE_LOG_DBG("Progress thread started\n");
	zhpe_pe_set_affinity();

	while (OFI_LIKELY(atm_load_rlx(&pe->do_progress))) {
		outstanding = false;
		if (locked || zhpeu_work_queued(&pe->work_head)) {
			outstanding |=
				zhpeu_work_process(&pe->work_head,
						   !locked, true);
			locked = false;
		}

		outstanding |= zhpe_pe_progress(pe);
		/* Don't sleep if there is outstanding work. */
		if (outstanding) {
			wait_beg = 0;
			continue;
		}
		/* Or if we've been told not to. */
		if (!zhpe_pe_waittime)
			continue;
		wait_end = fi_gettime_us();
		if (!wait_beg) {
			/* Clock starts when we don't have any work. */
			wait_beg = wait_end;
			continue;
		}
		if ((fi_gettime_us() - wait_beg) < (uint64_t)zhpe_pe_waittime)
			continue;
		/* Signaled? */
		if (!zhpeu_thr_wait_sleep_fast(&pe->work_head.thr_wait))
			continue;
		/* Time to sleep. */
		(void)zhpeu_thr_wait_sleep_slow(&pe->work_head.thr_wait,
						zhpe_pe_waittime, true, false);
		locked = true;
		wait_beg = 0;
	}
	if (locked)
		mutex_unlock(&pe->work_head.thr_wait.mutex);

 	ZHPE_LOG_DBG("Progress thread terminated\n");

	return NULL;
}

struct zhpe_pe *zhpe_pe_init(struct zhpe_domain *domain)
{
	struct zhpe_pe *pe;

	pe = calloc_cachealigned(1, sizeof(*pe));
	if (!pe)
		return NULL;

	zhpeu_work_head_init(&pe->work_head);
	dlist_init(&pe->queue_list);
	dlist_init(&pe->rx_list);
	pe->domain = domain;

	if (zhpe_needs_locking(domain)) {
		pe->progress_queue = zhpe_pe_progress_queue_locked;
		pe->progress_rx = zhpe_pe_progress_rx_ctx_locked;
	} else {
		pe->progress_queue = zhpe_pe_progress_queue_unlocked;
		pe->progress_rx = zhpe_pe_progress_rx_ctx_unlocked;
	}

	if (domain->util_domain.data_progress == FI_PROGRESS_AUTO) {
		atm_store(&pe->do_progress, 1);
		if (pthread_create(&pe->progress_thread, NULL,
				   zhpe_pe_progress_thread, (void *)pe)) {
			ZHPE_LOG_ERROR("Couldn't create progress thread\n");
			atm_store(&pe->do_progress, 0);

			return NULL;
		}
	}

	ZHPE_LOG_DBG("PE init: OK\n");

	return pe;
}

void zhpe_pe_finalize(struct zhpe_pe *pe)
{
	assert(dlist_empty(&pe->queue_list));
	assert(dlist_empty(&pe->rx_list));

	if (pe->domain->util_domain.data_progress == FI_PROGRESS_AUTO) {
		atm_store_rlx(&pe->do_progress, 0);
		zhpe_pe_signal(pe);
		pthread_join(pe->progress_thread, NULL);
	}

	zhpeu_work_head_destroy(&pe->work_head);
	free(pe);

	ZHPE_LOG_DBG("Progress engine finalize: OK\n");
}
