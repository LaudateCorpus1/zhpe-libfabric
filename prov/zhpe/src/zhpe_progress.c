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
 * SOFTWARE.5B
 */

#include <zhpe.h>

#define ZHPE_SUBSYS	FI_LOG_EP_DATA

static void tx_entry_report_complete(const struct zhpe_tx_entry *tx_entry,
				     uint64_t flags, void *op_context);

/* Debugging hook. */
#define rx_set_state(_rx_entry, _state)			\
do {							\
	struct zhpe_rx_entry *__rx_entry = (_rx_entry);	\
	__rx_entry->rx_state = (_state);		\
} while (0)

static void cntr_adderr(struct util_cntr *cntr)
{
	if (cntr)
		fi_cntr_adderr(&cntr->cntr_fid, 1);
}

void zhpe_send_status(struct zhpe_conn *conn, uint16_t cmp_idxn, int32_t status)
{
	struct zhpe_msg_status	msg_status;

	/* cmp_idxn is in network byte order. */
	assert(ntohs(cmp_idxn));

	assert((int16_t)status == status);
	msg_status.statusn = htons(status);

	zhpe_msg_prov(conn, ZHPE_OP_STATUS, &msg_status, sizeof(msg_status),
		      cmp_idxn, conn->tx_seq++);
}

void zhpe_send_writedata(struct zhpe_conn *conn, uint64_t op_flags,
			 uint64_t cq_data)
{
	struct zhpe_msg_writedata wdata;

	wdata.op_flagsn = htobe64(op_flags);
	wdata.cq_datan = htobe64(cq_data);

	zhpe_msg_prov(conn, ZHPE_OP_WRITEDATA, &wdata, sizeof(wdata),
		      0, conn->tx_seq++);
}

void zhpe_send_key_release(struct zhpe_conn *conn, uint64_t key)
{
	struct zhpe_msg_key_release krel;

	krel.keyn = htobe64(key);
	zhpe_msg_prov(conn, ZHPE_OP_KEY_RELEASE, &krel, sizeof(krel),
		      0, conn->tx_seq++);
}

void zhpe_send_key_request(struct zhpe_conn *conn, uint64_t *keys,
			   size_t n_keys)
{
	size_t			i;
	struct zhpe_msg_key_request kreq;
	size_t			len;

	for (i = 0; i < n_keys; i++)
		kreq.keysn[i] = htobe64(keys[i]);
	len = (offsetof(struct zhpe_msg_key_request, keysn) +
	       sizeof(kreq.keysn[0]) * n_keys);
	zhpe_msg_prov(conn, ZHPE_OP_KEY_REQUEST, &kreq, len, 0, conn->tx_seq++);
}

void zhpe_send_key_response(struct zhpe_conn *conn, uint64_t key,
			    char *blob, size_t blob_len)
{
	struct zhpe_msg_key_response krsp;
	size_t			len;

	assert(blob_len <= ZHPEQ_MAX_KEY_BLOB);
	krsp.keyn = htobe64(key);
	memcpy(krsp.blob, blob, blob_len);
	len = offsetof(struct zhpe_msg_key_response, blob) + blob_len;
	zhpe_msg_prov(conn, ZHPE_OP_KEY_RESPONSE, &krsp, len,
		      0, conn->tx_seq++);
}

void zhpe_send_key_revoke(struct zhpe_conn *conn, uint64_t key)
{
	struct zhpe_msg_key_revoke krev;

	krev.keyn = htobe64(key);
	zhpe_msg_prov(conn, ZHPE_OP_KEY_REVOKE, &krev, sizeof(krev),
		      0, conn->tx_seq++);
}

static void send_atomic_result(struct zhpe_conn *conn, uint16_t cmp_idxn,
			       uint64_t result, uint8_t fi_type)
{
	struct zhpe_msg_atomic_result ares;

	/* cmp_idxn is in network byte order. */
	assert(ntohs(cmp_idxn));

	ares.resultn = htobe64(result);
	ares.fi_type = fi_type;

	zhpe_msg_prov(conn, ZHPE_OP_ATOMIC_RESULT, &ares, sizeof(ares),
		      cmp_idxn, conn->tx_seq++);
}

static void tx_conn_retry(struct zhpe_tx_entry *tx_entry, uint16_t index)
{
	struct zhpe_conn	*conn = tx_entry->conn;
	struct zhpe_ctx		*zctx = conn->zctx;
	union zhpe_hw_wq_entry	*wqe = &zctx->ztq_hi->mem[index];
	struct zhpe_msg		*msg = (void *)&wqe->enqa.payload;
	struct zhpe_tx_queue_entry *txqe;
	struct zhpe_tx_queue_entry *txqe_inlist;
	struct zhpe_msg		*msg_inlist;
	uint32_t		msg_seq;

	txqe = zhpe_buf_alloc(&zctx->tx_queue_pool);
	txqe->tx_entry = tx_entry;
	txqe->wqe = *wqe;
	if (!(conn->flags & ZHPE_CONN_FLAG_BACKOFF))
		conn->tx_dequeue_last = get_cycles_approx();
	zhpe_conn_flags_set(conn, ZHPE_CONN_FLAG_BACKOFF);
	if (msg->hdr.retry == conn->tx_backoff_idx &&
	    conn->tx_backoff_idx < ZHPE_EP_MAX_BACKOFF)
		conn->tx_backoff_idx++;
	tx_entry->cstat.flags |= ZHPE_CS_FLAG_QUEUED;
	zctx->tx_queued++;
	/* Let's keep the queue ordered with a simple insertion. */
	msg_seq = ntohl(msg->hdr.seqn);
	dlist_foreach_container(&conn->tx_queue, struct zhpe_tx_queue_entry,
				txqe_inlist, dentry) {
		if (!(txqe_inlist->tx_entry->cstat.flags & ZHPE_CS_FLAG_RMA)) {
			msg_inlist = (void *)&wqe->enqa.payload;
			if (msg_seq > ntohl(msg_inlist->hdr.seqn))
				continue;
		}
		dlist_insert_before(&txqe->dentry, &txqe_inlist->dentry);
		return;
	}
	dlist_insert_tail(&txqe->dentry, &conn->tx_queue);
}

static int tx_cstat_update_cqe(struct zhpe_tx_entry *tx_entry,
			       struct zhpe_cq_entry *cqe, bool msg)
{
	struct zhpe_compstat	*cstat = &tx_entry->cstat;
	uint8_t			hwstatus = cqe->status;

	if (OFI_LIKELY(hwstatus == ZHPE_HW_CQ_STATUS_SUCCESS))
		goto done;

	if (msg &&
	    OFI_LIKELY(hwstatus == ZHPE_HW_CQ_STATUS_GENZ_RDM_QUEUE_FULL)) {
		tx_conn_retry(tx_entry, cqe->index);

		return cstat->completions;
	}

	if ((cstat->flags & ZHPE_CS_FLAG_ZERROR) || cstat->status < 0)
		goto done;

	cstat->status = cqe->status;
	cstat->flags |= ZHPE_CS_FLAG_ZERROR;
	/* ZZZ: Think on this. */
	if (cstat->flags & ZHPE_CS_FLAG_REMOTE_STATUS) {
		/* The remote status will not be sent, free ctx_ptrs slot. */
		if (OFI_LIKELY(tx_entry->cmp_idx))
			zhpe_tx_entry_slot_free(tx_entry, tx_entry->cmp_idx);
		cstat->flags &= ~ZHPE_CS_FLAG_REMOTE_STATUS;
		cstat->completions--;
	}
	tx_entry->conn->eflags |= ZHPE_CONN_EFLAG_ERROR;

	ZHPE_LOG_ERROR("genz error 0x%x\n", hwstatus);

 done:
	cstat->completions--;

	return cstat->completions;
}

static void tx_handle_msg_inject(struct zhpe_tx_entry *tx_entry,
				 struct zhpe_cq_entry *cqe)
{
	struct zhpe_conn	*conn = tx_entry->conn;
	struct zhpe_ctx		*zctx = conn->zctx;
	struct util_ep		*ep = &zctx->util_ep;
	uint8_t			hwstatus = cqe->status;

	if (OFI_LIKELY(!hwstatus)) {
		/* Success. */
		ep->tx_cntr_inc(ep->tx_cntr);
		return;
	}

	if (OFI_LIKELY(hwstatus == ZHPE_HW_CQ_STATUS_GENZ_RDM_QUEUE_FULL)) {
		tx_conn_retry(tx_entry, cqe->index);
		return;
	}

	ZHPE_LOG_ERROR("genz error 0x%x\n", hwstatus);
	cntr_adderr(ep->tx_cntr);
}

static void tx_handle_msg_prov(struct zhpe_tx_entry *tx_entry,
			       struct zhpe_cq_entry *cqe)
{
	uint8_t			hwstatus = cqe->status;

	if (OFI_LIKELY(!hwstatus))
		return;

	if (OFI_LIKELY(hwstatus == ZHPE_HW_CQ_STATUS_GENZ_RDM_QUEUE_FULL)) {
		tx_conn_retry(tx_entry, cqe->index);
		return;
	}

	ZHPE_LOG_ERROR("genz error 0x%x\n", hwstatus);
}

static void tx_handle_msg_cmn(struct zhpe_tx_entry *tx_entry,
			      struct zhpe_cq_entry *cqe, uint64_t flags,
			      bool free)
{
	struct zhpe_conn	*conn = tx_entry->conn;
	struct zhpe_ctx		*zctx = conn->zctx;
	int			completions;
	struct zhpe_tx_entry_ctx *tx_entry_ctx;
	size_t			i;

	completions = tx_cstat_update_cqe(tx_entry, cqe, true);
	assert(completions >= 0);
	if (OFI_UNLIKELY(completions))
	    return;

	if (OFI_UNLIKELY(tx_entry->ptr_cnt)) {
		for (i = 0; i < tx_entry->ptr_cnt; i++)
			zhpe_dom_mr_put(tx_entry->ptrs[i]);
	}

	if (free) {
		tx_entry_ctx = container_of(tx_entry, struct zhpe_tx_entry_ctx,
					    tx_entry);
		tx_entry_report_complete(tx_entry, flags,
					 tx_entry_ctx->op_context);
		zhpe_buf_free(&zctx->tx_ctx_pool, tx_entry_ctx);
	} else
		tx_entry_report_complete(tx_entry, flags, tx_entry);
}

static void tx_handle_msg(struct zhpe_tx_entry *tx_entry,
			  struct zhpe_cq_entry *cqe)
{
	tx_handle_msg_cmn(tx_entry, cqe, FI_SEND | FI_MSG, false);
}

static void tx_handle_msg_free(struct zhpe_tx_entry *tx_entry,
			       struct zhpe_cq_entry *cqe)
{
	tx_handle_msg_cmn(tx_entry, cqe, FI_SEND | FI_MSG, true);
}

static void tx_handle_tag(struct zhpe_tx_entry *tx_entry,
			  struct zhpe_cq_entry *cqe)
{
	tx_handle_msg_cmn(tx_entry, cqe, FI_SEND | FI_TAGGED, false);
}

static void tx_handle_tag_free(struct zhpe_tx_entry *tx_entry,
			       struct zhpe_cq_entry *cqe)
{
	tx_handle_msg_cmn(tx_entry, cqe, FI_SEND | FI_TAGGED, true);
}

static void tx_handle_rx_get_buf(struct zhpe_tx_entry *tx_entry,
				 struct zhpe_cq_entry *cqe)
{
	struct zhpe_conn	*conn = tx_entry->conn;
	int			completions;
	struct zhpe_rx_entry	*rx_entry;

	completions = tx_cstat_update_cqe(tx_entry, cqe, false);
	assert(completions >= 0);
	if (OFI_UNLIKELY(completions))
	    return;

	rx_entry = container_of(tx_entry, struct zhpe_rx_entry,	tx_entry);

	switch (rx_entry->rx_state) {

	case ZHPE_RX_STATE_DISCARD:
		zhpe_rx_discard_recv(rx_entry);
		break;

	case ZHPE_RX_STATE_EAGER:
		if (OFI_LIKELY(rx_entry->src_flags &
			       ZHPE_OP_FLAG_TRANSMIT_COMPLETE)) {
			zhpe_send_status(conn, rx_entry->src_cmp_idxn,
					 rx_entry->tx_entry.cstat.status);
			rx_entry->src_flags &= ~ZHPE_OP_FLAG_ANY_COMPLETE;
		}
		rx_set_state(rx_entry, ZHPE_RX_STATE_EAGER_DONE);
		break;

	case ZHPE_RX_STATE_EAGER_CLAIMED:
		zhpe_iov_state_reset(&rx_entry->lstate);
		zhpe_iov_state_reset(&rx_entry->bstate);
		zhpe_copy_iov(&rx_entry->lstate, &rx_entry->bstate);
		zhpe_rx_complete(rx_entry, rx_entry->tx_entry.cstat.status);
		break;

	default:
		ZHPE_LOG_ERROR("rx_entry %p in bad state %d\n",
			       rx_entry, rx_entry->rx_state);
	}
}

static void tx_handle_rx_get_rnd(struct zhpe_tx_entry *tx_entry,
				 struct zhpe_cq_entry *cqe)
{
	struct zhpe_conn	*conn = tx_entry->conn;
	int			completions;
	struct zhpe_rx_entry	*rx_entry;

	completions = tx_cstat_update_cqe(tx_entry, cqe, false);
	assert(completions >= 0);
	if (OFI_UNLIKELY(completions))
	    return;

	rx_entry = container_of(tx_entry, struct zhpe_rx_entry, tx_entry);

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
	}

	zhpe_rx_complete(rx_entry, rx_entry->tx_entry.cstat.status);
}

static void tx_handle_rma(struct zhpe_tx_entry *tx_entry,
			  struct zhpe_cq_entry *cqe)
{
	int			completions;
	struct zhpe_rma_entry	*rma_entry;

	completions = tx_cstat_update_cqe(tx_entry, cqe, false);
	assert(completions >= 0);
	if (OFI_UNLIKELY(completions))
	    return;

	rma_entry = container_of(tx_entry, struct zhpe_rma_entry, tx_entry);
	zhpe_rma_tx_start(rma_entry);
}

static void tx_handle_atm_em(struct zhpe_tx_entry *tx_entry,
			     struct zhpe_cq_entry *cqe)
{
	tx_handle_msg_cmn(tx_entry, cqe, FI_ATOMIC, false);
}

static void tx_handle_atm_em_free(struct zhpe_tx_entry *tx_entry,
				  struct zhpe_cq_entry *cqe)
{
	tx_handle_msg_cmn(tx_entry, cqe, FI_ATOMIC, true);
}

static void tx_handle_atm_hw_cmn(struct zhpe_tx_entry *tx_entry, bool free)
{
	struct zhpe_conn	*conn = tx_entry->conn;
	struct zhpe_ctx		*zctx = conn->zctx;
	struct zhpe_tx_entry_ctx *tx_entry_ctx;

	zhpe_rma_rkey_put(tx_entry->ptrs[0]);

	if (free) {
		tx_entry_ctx = container_of(tx_entry, struct zhpe_tx_entry_ctx,
					    tx_entry);
		tx_entry_report_complete(tx_entry, FI_ATOMIC,
					 tx_entry_ctx->op_context);
		zhpe_buf_free(&zctx->tx_ctx_pool, tx_entry_ctx);
	} else
		tx_entry_report_complete(tx_entry, FI_ATOMIC, tx_entry);
}

static void tx_handle_atm_hw_res32(struct zhpe_tx_entry *tx_entry,
				   struct zhpe_cq_entry *cqe)
{
	int			completions;

	completions = tx_cstat_update_cqe(tx_entry, cqe, false);
	assert(completions >= 0);
	if (OFI_UNLIKELY(completions))
	    return;

	if (OFI_LIKELY(!tx_entry->cstat.status && tx_entry->ptrs[1]))
		zhpeu_fab_atomic_store(FI_UINT32, (uint32_t *)tx_entry->ptrs[1],
				       cqe->result.atomic32);

	tx_handle_atm_hw_cmn(tx_entry, false);
}

static void tx_handle_atm_hw_res32_free(struct zhpe_tx_entry *tx_entry,
					struct zhpe_cq_entry *cqe)
{
	int			completions;

	completions = tx_cstat_update_cqe(tx_entry, cqe, false);
	assert(completions >= 0);
	if (OFI_UNLIKELY(completions))
	    return;

	if (OFI_LIKELY(!tx_entry->cstat.status && tx_entry->ptrs[1]))
		zhpeu_fab_atomic_store(FI_UINT32, (uint32_t *)tx_entry->ptrs[1],
				       cqe->result.atomic32);

	tx_handle_atm_hw_cmn(tx_entry, true);
}

static void tx_handle_atm_hw_res64(struct zhpe_tx_entry *tx_entry,
				   struct zhpe_cq_entry *cqe)
{
	int			completions;

	completions = tx_cstat_update_cqe(tx_entry, cqe, false);
	assert(completions >= 0);
	if (OFI_UNLIKELY(completions))
	    return;

	if (OFI_LIKELY(!tx_entry->cstat.status && tx_entry->ptrs[1]))
		zhpeu_fab_atomic_store(FI_UINT64, (uint64_t *)tx_entry->ptrs[1],
				       cqe->result.atomic64);

	tx_handle_atm_hw_cmn(tx_entry, false);
}

static void tx_handle_atm_hw_res64_free(struct zhpe_tx_entry *tx_entry,
					struct zhpe_cq_entry *cqe)
{
	int			completions;

	completions = tx_cstat_update_cqe(tx_entry, cqe, false);
	assert(completions >= 0);
	if (OFI_UNLIKELY(completions))
	    return;

	if (OFI_LIKELY(!tx_entry->cstat.status && tx_entry->ptrs[1]))
		zhpeu_fab_atomic_store(FI_UINT64, (uint64_t *)tx_entry->ptrs[1],
				       cqe->result.atomic64);

	tx_handle_atm_hw_cmn(tx_entry, true);
}

typedef void (*tx_handler_fn)(struct zhpe_tx_entry *tx_entry,
			      struct zhpe_cq_entry *cqe);

static tx_handler_fn tx_handlers[] = {
	[ZHPE_TX_HANDLE_MSG_INJECT]	= tx_handle_msg_inject,
	[ZHPE_TX_HANDLE_MSG_PROV]	= tx_handle_msg_prov,
	[ZHPE_TX_HANDLE_MSG]		= tx_handle_msg,
	[ZHPE_TX_HANDLE_MSG_FREE]	= tx_handle_msg_free,
	[ZHPE_TX_HANDLE_TAG]		= tx_handle_tag,
	[ZHPE_TX_HANDLE_TAG_FREE]	= tx_handle_tag_free,
	[ZHPE_TX_HANDLE_RX_GET_BUF]	= tx_handle_rx_get_buf,
	[ZHPE_TX_HANDLE_RX_GET_RND]	= tx_handle_rx_get_rnd,
	[ZHPE_TX_HANDLE_RMA]		= tx_handle_rma,
	[ZHPE_TX_HANDLE_ATM_EM]		= tx_handle_atm_em,
	[ZHPE_TX_HANDLE_ATM_EM_FREE]	= tx_handle_atm_em_free,
	[ZHPE_TX_HANDLE_ATM_HW_RES32]	= tx_handle_atm_hw_res32,
	[ZHPE_TX_HANDLE_ATM_HW_RES32_FREE] = tx_handle_atm_hw_res32_free,
	[ZHPE_TX_HANDLE_ATM_HW_RES64]	= tx_handle_atm_hw_res64,
	[ZHPE_TX_HANDLE_ATM_HW_RES64_FREE] = tx_handle_atm_hw_res64_free,
};

static void tx_call_handler(struct zhpe_tx_entry *tx_entry,
			    struct zhpe_cq_entry *cqe)
{
	tx_handler_fn		handler;

	assert(tx_entry->tx_handler < ARRAY_SIZE(tx_handlers));
	handler = tx_handlers[tx_entry->tx_handler];
	assert(handler);

	handler(tx_entry, cqe);
}

void zhpe_tx_call_handler_fake(struct zhpe_tx_entry *tx_entry,
			       uint8_t cqe_status)
{
	struct zhpe_cq_entry	cqe;

	cqe.status = cqe_status;
	tx_call_handler(tx_entry, &cqe);
}

static void zhpe_rx_entry_report_complete(const struct zhpe_rx_entry *rx_entry,
					  int err)
{
	struct util_ep		*ep = &rx_entry->zctx->util_ep;
	uint64_t		rem;

	if (OFI_UNLIKELY(rx_entry->total_wire > rx_entry->total_user)) {
		if (OFI_LIKELY(err >= 0)) {
			err = -FI_ETRUNC;
			rem = rx_entry->total_wire - rx_entry->total_user;
		}
	} else
		rem = 0;

	if (OFI_LIKELY(err >= 0)) {
		ep->rx_cntr_inc(ep->rx_cntr);
		if (!zhpe_cq_report_needed(ep->rx_cq, rx_entry->op_flags))
			return;
		zhpe_cq_report_success(ep->rx_cq, rx_entry->op_flags,
				       rx_entry->op_context,
				       rx_entry->total_user, NULL,
				       rx_entry->cq_data,
				       rx_entry->match_info.tag);
		return;
	}

	cntr_adderr(ep->rx_cntr);
	if (!zhpe_cq_report_needed(ep->rx_cq, rx_entry->op_flags))
		return;
	zhpe_cq_report_error(ep->rx_cq, rx_entry->op_flags,
			     rx_entry->op_context, rx_entry->total_user, NULL,
			     rx_entry->cq_data, rx_entry->match_info.tag, rem,
			     err, 0);
}

static void tx_entry_report_complete(const struct zhpe_tx_entry *tx_entry,
				     uint64_t flags, void *op_context)
{
	struct util_ep		*ep = &tx_entry->conn->zctx->util_ep;
	int			err;
	int			prov_errno;

	flags |= zopflags2op(tx_entry->cstat.flags);
	if (OFI_LIKELY(!tx_entry->cstat.status)) {
		ep->tx_cntr_inc(ep->tx_cntr);
		if (!zhpe_cq_report_needed(ep->tx_cq, flags))
			return;
		zhpe_cq_report_success(ep->tx_cq, flags, op_context, 0, NULL,
				       0, 0);
		return;
	}

	cntr_adderr(ep->tx_cntr);
	if (!zhpe_cq_report_needed(ep->tx_cq, flags))
		return;
	if (tx_entry->cstat.flags & ZHPE_CS_FLAG_ZERROR) {
		err = -FI_EIO;
		prov_errno = tx_entry->cstat.status;
	} else {
		err = tx_entry->cstat.status;
		prov_errno = 0;
	}
	zhpe_cq_report_error(ep->tx_cq, flags, op_context, 0, NULL, 0, 0, 0,
			     err, prov_errno);
}

void zhpe_rma_complete(struct zhpe_rma_entry *rma_entry)
{
	tx_entry_report_complete(&rma_entry->tx_entry, rma_entry->op_flags,
				 rma_entry->op_context);
	zhpe_rma_entry_free(rma_entry);
}

void zhpe_rx_discard_recv(struct zhpe_rx_entry *rx_entry)
{
	struct zhpe_ctx		*zctx = rx_entry->zctx;

	dlist_remove_init(&rx_entry->dentry);
	if (rx_entry->rx_state == ZHPE_RX_STATE_EAGER) {
		dlist_insert_tail(&rx_entry->dentry, &zctx->rx_work_list);
		rx_set_state(rx_entry, ZHPE_RX_STATE_DISCARD);
	} else {
		if (rx_entry->src_flags & ZHPE_OP_FLAG_ANY_COMPLETE)
			zhpe_send_status(rx_entry->tx_entry.conn,
					 rx_entry->src_cmp_idxn, 0);
		zhpe_rx_entry_free(rx_entry);
	}
}

void zhpe_rx_complete(struct zhpe_rx_entry *rx_entry, int status)
{
	dlist_remove_init(&rx_entry->dentry);
	zhpe_rx_entry_report_complete(rx_entry, status);
	if (OFI_UNLIKELY(rx_entry->src_flags & ZHPE_OP_FLAG_ANY_COMPLETE))
		zhpe_send_status(rx_entry->tx_entry.conn,
				 rx_entry->src_cmp_idxn, status);
	zhpe_rx_entry_free(rx_entry);
 	zhpe_stats_stop(zhpe_stats_subid(RECV, 0));
}

void zhpe_rx_peek_recv(struct zhpe_ctx *zctx,
		       struct zhpe_rx_match_info *user_info, uint64_t flags,
		       struct fi_context *op_context)
{
	struct zhpe_rx_entry	*rx_wire;
	struct util_ep		*ep = &zctx->util_ep;

	/* Locking is provided by the caller. */
	dlist_foreach_container(&zctx->rx_match_tagged.wire_list,
				struct zhpe_rx_entry, rx_wire, dentry) {
		if (!user_info->match_fn(user_info, &rx_wire->match_info))
			continue;
		goto found;
	}
	if (!zhpe_cq_report_needed(ep->rx_cq, flags))
		return;
	zhpe_cq_report_error(ep->rx_cq, flags, op_context, 0, NULL, 0,
			     user_info->tag, 0, -FI_ENOMSG, 0);
	return;
 found:
	flags |= rx_wire->op_flags;
	if (!zhpe_cq_report_needed(ep->rx_cq, flags))
		return;
	zhpe_cq_report_success(ep->rx_cq, flags,
			       op_context, rx_wire->total_wire, NULL,
			       rx_wire->cq_data, rx_wire->match_info.tag);
	if (flags & FI_DISCARD)
		zhpe_rx_discard_recv(rx_wire);
	else if (flags & FI_CLAIM) {
		op_context->internal[0] = rx_wire;
		dlist_remove(&rx_wire->dentry);
		dlist_insert_tail(&rx_wire->dentry, &zctx->rx_work_list);
	}
}

static void rx_send_start_buf(struct zhpe_rx_entry *rx_entry)
{
	int			rc;

	rc = zhpe_slab_alloc(&rx_entry->zctx->eager,
			     rx_entry->total_wire, rx_entry->bstate.viov);
	if (OFI_UNLIKELY(rc < 0))
		return;

	rx_set_state(rx_entry, ZHPE_RX_STATE_EAGER);
	zhpe_iov_state_reset(&rx_entry->bstate);
	rx_entry->tx_entry.ptrs[0] = &rx_entry->bstate;
	zhpe_iov_state_reset(&rx_entry->rstate);
	rx_entry->bstate.cnt = 1;
	rx_entry->tx_entry.tx_handler = ZHPE_TX_HANDLE_RX_GET_BUF;
	zhpe_cstat_init(&rx_entry->tx_entry.cstat, 0, ZHPE_CS_FLAG_RMA);
	zhpe_iov_rma(&rx_entry->tx_entry, ZHPE_SEG_MAX_BYTES, ZHPE_SEG_MAX_OPS);
}

static void rx_send_start_rnd(struct zhpe_rx_entry *rx_entry)
{

	zhpe_iov_state_reset(&rx_entry->lstate);
	rx_entry->tx_entry.ptrs[0] = &rx_entry->lstate;
	zhpe_iov_state_reset(&rx_entry->rstate);
	rx_entry->tx_entry.tx_handler = ZHPE_TX_HANDLE_RX_GET_RND;
	zhpe_cstat_init(&rx_entry->tx_entry.cstat, 0, ZHPE_CS_FLAG_RMA);
	zhpe_iov_rma(&rx_entry->tx_entry, ZHPE_SEG_MAX_BYTES, ZHPE_SEG_MAX_OPS);
}

void zhpe_rx_start_recv(struct zhpe_rx_entry *rx_matched,
			enum zhpe_rx_state rx_state)
{
	/* zctx_lock must be locked. */
	switch (rx_state) {

	case ZHPE_RX_STATE_RND:
		if (OFI_UNLIKELY(!rx_matched->lstate_ready)) {
			rx_set_state(rx_matched, rx_state);
			rx_matched->matched = true;
			return;
		}
		rx_send_start_rnd(rx_matched);
		break;

	case ZHPE_RX_STATE_EAGER:
		rx_set_state(rx_matched, ZHPE_RX_STATE_EAGER_CLAIMED);
		break;

	case ZHPE_RX_STATE_EAGER_DONE:
		zhpe_iov_state_reset(&rx_matched->lstate);
		zhpe_iov_state_reset(&rx_matched->bstate);
		zhpe_copy_iov(&rx_matched->lstate, &rx_matched->bstate);
		zhpe_rx_complete(rx_matched, rx_matched->tx_entry.cstat.status);
		break;

	case ZHPE_RX_STATE_INLINE:
		if (OFI_UNLIKELY(!rx_matched->lstate_ready)) {
			rx_set_state(rx_matched, rx_state);
			rx_matched->matched = true;
			return;
		}
		zhpe_iov_state_reset(&rx_matched->lstate);
		zhpe_copy_mem_to_iov(&rx_matched->lstate,
				     rx_matched->inline_data,
				     rx_matched->total_wire);
		zhpe_rx_complete(rx_matched, 0);
		break;

	case ZHPE_RX_STATE_INLINE_M:
	case ZHPE_RX_STATE_RND_M:
		break;

	default:
		ZHPE_LOG_ERROR("rx_matched %p in bad state %d\n",
			       rx_matched, rx_matched->rx_state);
		abort();
	}

	return;
}

void zhpe_rx_start_recv_user(struct zhpe_rx_entry *rx_matched,
			     const struct iovec *uiov, void **udesc,
			     size_t uiov_cnt)
{
	struct zhpe_ctx		*zctx = rx_matched->zctx;
	int			rc;
	size_t			len;

	/* zctx_lock must be locked. */
	rc = zhpe_get_uiov_len(uiov, uiov_cnt, &rx_matched->total_user);
	if (OFI_UNLIKELY(rc < 0))
		goto error_complete;

	switch ((enum zhpe_rx_state)rx_matched->rx_state) {

	case ZHPE_RX_STATE_RND:
		zctx_unlock(zctx);
		/* Restrict possible registration to minimum needed. */
		len = min(rx_matched->total_wire, rx_matched->total_user);
		zhpe_stats_start(zhpe_stats_subid(RECV, 20));
		rc = zhpe_get_uiov_maxlen(zctx, uiov, udesc, uiov_cnt,
					  ZHPEQ_MR_RECV, len, rx_matched->liov);
		zhpe_stats_stop(zhpe_stats_subid(RECV, 20));
		zctx_lock(zctx);
		if (OFI_UNLIKELY(rc < 0))
			goto error_complete;
		rx_matched->lstate.cnt = rc;
		rx_matched->lstate.held = true;
		rx_send_start_rnd(rx_matched);
		zctx->pe_ctx_ops->signal(zctx);
		break;

	case ZHPE_RX_STATE_RND_M:
		/* We don't know what will be needed, register everything. */
		zctx_unlock(zctx);
		zhpe_stats_start(zhpe_stats_subid(RECV, 20));
		rc = zhpe_get_uiov(zctx, uiov, udesc, uiov_cnt,
				   ZHPEQ_MR_RECV, rx_matched->liov);
		zhpe_stats_stop(zhpe_stats_subid(RECV, 20));
		zctx_lock(zctx);
		if (OFI_UNLIKELY(rc < 0))
			goto error_complete;
		rx_matched->lstate.cnt = rc;
		rx_matched->lstate.held = true;
		if (OFI_LIKELY(rx_matched->rx_state == ZHPE_RX_STATE_RND)) {
			rx_send_start_rnd(rx_matched);
			zctx->pe_ctx_ops->signal(zctx);
		} else
			rx_matched->matched = true;
		break;

	case ZHPE_RX_STATE_EAGER:
		zhpe_get_uiov_buffered(uiov, udesc, uiov_cnt,
				       &rx_matched->lstate);
		rx_set_state(rx_matched, ZHPE_RX_STATE_EAGER_CLAIMED);
		break;

	case ZHPE_RX_STATE_EAGER_DONE:
		zhpe_get_uiov_buffered(uiov, udesc, uiov_cnt,
				       &rx_matched->lstate);
		zhpe_iov_state_reset(&rx_matched->lstate);
		zhpe_iov_state_reset(&rx_matched->bstate);
		zhpe_copy_iov(&rx_matched->lstate, &rx_matched->bstate);
		zhpe_rx_complete(rx_matched, rx_matched->tx_entry.cstat.status);
		break;

	case ZHPE_RX_STATE_INLINE:
		zhpe_get_uiov_buffered(uiov, udesc, uiov_cnt,
				       &rx_matched->lstate);
		zhpe_iov_state_reset(&rx_matched->lstate);
		zhpe_copy_mem_to_iov(&rx_matched->lstate,
				     rx_matched->inline_data,
				     rx_matched->total_wire);
		zhpe_rx_complete(rx_matched, 0);
		break;

	case ZHPE_RX_STATE_INLINE_M:
		zhpe_get_uiov_buffered(uiov, udesc, uiov_cnt,
				       &rx_matched->lstate);
		rx_matched->matched = true;
		break;

	default:
		ZHPE_LOG_ERROR("rx_matched %p in bad state %d\n",
			       rx_matched, rx_matched->rx_state);
		abort();
	}

	return;

 error_complete:
	zhpe_rx_complete(rx_matched, rc);
}

static void rx_handle_msg_status(struct zhpe_conn *conn, struct zhpe_msg *msg)
{
	struct zhpe_ctx		*zctx = conn->zctx;
	struct zhpe_msg_status	*status = (void *)msg->payload;
	size_t			cmp_idx = ntohs(msg->hdr.cmp_idxn);
	struct zhpe_tx_entry	*tx_entry;

	assert(cmp_idx != 0);

	/* Get tx_entry and free ctx_ptrs slot. */
	tx_entry = zctx->ctx_ptrs[cmp_idx];
	zhpe_tx_entry_slot_free(tx_entry, cmp_idx);

	zhpe_cstat_update_status(&tx_entry->cstat,
				 (int16_t)ntohs(status->statusn));
	zhpe_tx_call_handler_fake(tx_entry, 0);
}

static void rx_handle_msg_shutdown(struct zhpe_conn *conn, struct zhpe_msg *msg)
{
	conn->eflags |= ZHPE_CONN_EFLAG_SHUTDOWN2;
	if (!(conn->eflags & ~ZHPE_CONN_EFLAG_SHUTDOWN2))
		zhpe_msg_prov_no_eflags(conn, ZHPE_OP_SHUTDOWN, NULL,
					0, 0, conn->tx_seq++);
	zhpe_dom_cleanup_conn(conn);
}

static void rx_handle_msg_key_release(struct zhpe_conn *conn,
				  struct zhpe_msg *msg)
{
	struct zhpe_msg_key_release *krel = (void *)msg->payload;

	zhpe_dom_key_release(conn, be64toh(krel->keyn));
}

static void rx_handle_msg_key_request(struct zhpe_conn *conn,
				  struct zhpe_msg *msg)
{
	struct zhpe_msg_key_request *kreq = (void *)msg->payload;
	size_t			i;
	size_t			n_keys;

	n_keys = ((msg->hdr.len -
		   offsetof(struct zhpe_msg_key_request, keysn)) /
		  sizeof(kreq->keysn[0]));
	for (i = 0; i < n_keys; i++)
		zhpe_dom_key_export(conn, be64toh(kreq->keysn[i]));
}

static void rx_handle_msg_key_response(struct zhpe_conn *conn,
				       struct zhpe_msg *msg)
{
	struct zhpe_msg_key_response *krsp = (void *)msg->payload;
	size_t			blob_len;

	blob_len = (msg->hdr.len -
		    offsetof(struct zhpe_msg_key_response, blob));
	zhpe_rma_rkey_import(conn, be64toh(krsp->keyn), krsp->blob, blob_len);
}

static void rx_handle_msg_key_revoke(struct zhpe_conn *conn,
				     struct zhpe_msg *msg)
{
	struct zhpe_msg_key_revoke *krev = (void *)msg->payload;

	zhpe_rma_rkey_revoke(conn, be64toh(krev->keyn));
}

static void rx_handle_msg_writedata(struct zhpe_conn *conn,
				    struct zhpe_msg *msg)
{
	struct zhpe_ctx		*zctx = conn->zctx;
	struct util_ep		*ep = &zctx->util_ep;
	struct zhpe_msg_writedata *wdata = (void *)msg->payload;
	uint64_t		op_flags;
	uint64_t		cq_flags;

	op_flags = be64toh(wdata->op_flagsn);
	cq_flags = (op_flags & (FI_ATOMIC | FI_RMA)) | FI_COMPLETION;
	if (op_flags & FI_READ) {
		ep->rem_rd_cntr_inc(ep->rem_rd_cntr);
		cq_flags |= FI_REMOTE_READ;
	}
	if (op_flags & FI_WRITE) {
		ep->rem_wr_cntr_inc(ep->rem_wr_cntr);
		cq_flags |= FI_REMOTE_WRITE;
	}
	if ((op_flags & FI_REMOTE_CQ_DATA) && ep->rx_cq)
		zhpe_cq_report_success(ep->rx_cq, FI_COMPLETION, NULL, 0, NULL,
				       be64toh(wdata->cq_datan), 0);
}

static void rx_handle_msg_atomic_request(struct zhpe_conn *conn,
					 struct zhpe_msg *msg)
{
	int32_t			status;
	struct zhpe_ctx		*zctx = conn->zctx;
	struct zhpe_dom		*zdom = zctx2zdom(zctx);
	struct zhpe_msg_atomic_request *areq = (void *)msg->payload;
	uint32_t		qaccess;
	uint64_t		orig;
	uint64_t		operands[2];
	uint64_t		key;
	uint64_t		dst;
	struct zhpe_mr		*zmr;
	struct ofi_rbnode	*rbnode;
	struct fi_mr_attr	*attr;

	operands[0] = be64toh(areq->operandsn[0]);
	operands[1] = be64toh(areq->operandsn[1]);
	dst = be64toh(areq->raddrn);
	key = be64toh(areq->rkeyn);

	/*
	 * ZZZ:We lock to look up the key and do an actual atomic while holding
	 * the lock. If we think we're going to have have a bunch of
	 * operation in parallel, we need to revisit the locking on the zmr
	 * lookup, but at least any unrelated user threads don't need the
	 * lock.
	 */
	qaccess = ZHPEQ_MR_GET_REMOTE | ZHPEQ_MR_PUT_REMOTE;
	zdom_lock(zdom);
	rbnode = ofi_rbmap_find(zdom2map(zdom)->rbtree, &key);
	if (OFI_LIKELY(rbnode != NULL)) {
		attr = rbnode->data;
		zmr = attr->context;
		dst += attr->offset;
		if (OFI_LIKELY((zmr->qaccess & qaccess) == qaccess))
			status = zhpeq_lcl_key_access(zmr->qkdata, TO_PTR(dst),
						      areq->bytes, qaccess);
		else
			status = -FI_EINVAL;
		if (OFI_LIKELY(status >= 0))
			status = zhpeu_fab_atomic_op(areq->fi_type, areq->fi_op,
						     operands[0], operands[1],
						     TO_PTR(dst), &orig);
	} else
		status = -FI_ENOKEY;
	zdom_unlock(zdom);

	if (OFI_LIKELY(msg->hdr.flags & ZHPE_OP_FLAG_DELIVERY_COMPLETE)) {
		if (OFI_LIKELY(status >= 0))
			send_atomic_result(conn, msg->hdr.cmp_idxn, orig,
					   areq->fi_type);
		else
			zhpe_send_status(conn, msg->hdr.cmp_idxn, status);
	}
}

static void rx_handle_msg_atomic_result(struct zhpe_conn *conn,
					struct zhpe_msg *msg)
{
	struct zhpe_ctx		*zctx = conn->zctx;
	struct zhpe_msg_atomic_result *ares = (void *)msg->payload;
	size_t			cmp_idx = ntohs(msg->hdr.cmp_idxn);
	struct zhpe_tx_entry	*tx_entry;

	assert(cmp_idx != 0);

	/* Get tx_entry and free ctx_ptrs slot. */
	tx_entry = zctx->ctx_ptrs[cmp_idx];
	zhpe_tx_entry_slot_free(tx_entry, cmp_idx);

	if (OFI_LIKELY(tx_entry->ptrs[1] != NULL))
		zhpeu_fab_atomic_store(ares->fi_type, tx_entry->ptrs[1],
				       be64toh(ares->resultn));
	zhpe_tx_call_handler_fake(tx_entry, 0);
}

static size_t rx_wire_get_riov(struct zhpe_rx_entry *rx_wire,
			       struct zhpe_msg *msg, size_t i)
{
	struct iovec		*iov = &rx_wire->riov[rx_wire->rstate.cnt];
	union zhpe_msg_payload	*pay = (void *)msg->payload;

	iov->iov_base = TO_PTR(be64toh(pay->data[i++]) +
			       rx_wire->tx_entry.conn->rx_reqzmmu);
	iov->iov_len = be64toh(pay->data[i++]);
	rx_wire->total_wire += iov->iov_len;
	rx_wire->rstate.cnt++;

	return i;
}

static void rx_handle_msg_final_inline(struct zhpe_conn *conn,
				       struct zhpe_msg *msg)
{
	struct zhpe_rx_entry	*rx_wire = conn->rx_pending;
	union zhpe_msg_payload	*pay = (void *)msg->payload;

	memcpy(rx_wire->inline_data + rx_wire->total_wire, pay, msg->hdr.len);
	rx_wire->total_wire += msg->hdr.len;
	/* Optimize immediate delivery. */
	if (OFI_LIKELY(rx_wire->matched))
		zhpe_rx_start_recv(rx_wire, ZHPE_RX_STATE_INLINE);
	else
		rx_set_state(rx_wire, ZHPE_RX_STATE_INLINE);
}

static void rx_handle_msg_final_iov(struct zhpe_conn *conn,
				    struct zhpe_msg *msg)
{
	struct zhpe_rx_entry	*rx_wire = conn->rx_pending;

	rx_wire_get_riov(rx_wire, msg, 0);
	if (OFI_LIKELY(rx_wire->matched))
		zhpe_rx_start_recv(rx_wire, ZHPE_RX_STATE_RND);
	else {
		rx_set_state(rx_wire, ZHPE_RX_STATE_RND);
		if (OFI_LIKELY(rx_wire->total_wire < zhpe_ep_max_eager_sz))
			rx_send_start_buf(rx_wire);
	}
}

static void rx_wire_init(struct zhpe_rx_entry *rx_wire, struct zhpe_conn *conn,
			 struct zhpe_msg *msg, size_t i, uint64_t tag,
			 bool matched)
{
	union zhpe_msg_payload	*pay = (void *)msg->payload;

	rx_wire->tx_entry.conn = conn;
	rx_wire->match_info.tag = tag;
	rx_wire->total_wire = 0;
	rx_wire->rstate.cnt = 0;
	rx_wire->src_cmp_idxn = msg->hdr.cmp_idxn;
	rx_wire->src_flags = msg->hdr.flags;
	if (msg->hdr.op & ZHPE_OP_SEND_DX) {
		rx_wire->cq_data = be64toh(pay->data[i++]);
		rx_wire->op_flags |= FI_REMOTE_CQ_DATA;
	}
	if (msg->hdr.op & ZHPE_OP_SEND_IX) {
		rx_wire->total_wire = msg->hdr.len;
		memcpy(rx_wire->inline_data, &pay->data[i], msg->hdr.len);
		if (msg->hdr.op & ZHPE_OP_SEND_MX) {
			rx_set_state(rx_wire, ZHPE_RX_STATE_INLINE_M);
			conn->rx_pending = rx_wire;
			conn->rx_pending_fn = rx_handle_msg_final_inline;
			rx_wire->matched = matched;
		}  else {
			if (matched)
				zhpe_rx_start_recv(rx_wire,
						   ZHPE_RX_STATE_INLINE);
			else
				rx_set_state(rx_wire, ZHPE_RX_STATE_INLINE);
		}

		return;
	}

	i = rx_wire_get_riov(rx_wire, msg, i);
	if (OFI_UNLIKELY(msg->hdr.len > 1) && i < ARRAY_SIZE(pay->data) - 2)
		rx_wire_get_riov(rx_wire, msg, i);

	if (msg->hdr.op & ZHPE_OP_SEND_MX) {
		rx_set_state(rx_wire, ZHPE_RX_STATE_RND_M);
		conn->rx_pending = rx_wire;
		conn->rx_pending_fn = rx_handle_msg_final_iov;
		rx_wire->matched = matched;
	}  else {
		if (matched)
			zhpe_rx_start_recv(rx_wire, ZHPE_RX_STATE_RND);
		else {
			rx_set_state(rx_wire, ZHPE_RX_STATE_RND);
			if (rx_wire->total_wire < zhpe_ep_max_eager_sz)
				rx_send_start_buf(rx_wire);
		}
	}
}

static void rx_handle_msg_send(struct zhpe_conn *conn, struct zhpe_msg *msg)
{
	struct zhpe_ctx		*zctx = conn->zctx;
	union zhpe_msg_payload	*pay = (void *)msg->payload;
	struct zhpe_rx_match_info wire_info;
	struct zhpe_rx_match_lists *match_lists;
	struct zhpe_rx_entry	*rx_user;
	struct zhpe_rx_entry	*rx_wire;
	size_t			i;

	i = 0;
	if (msg->hdr.op & ZHPE_OP_SEND_TX) {
		wire_info.tag = be64toh(pay->data[i++]);
		match_lists = &zctx->rx_match_tagged;
	} else
		match_lists = &zctx->rx_match_untagged;
	wire_info.conn = conn;

	dlist_foreach_container(&match_lists->user_list, struct zhpe_rx_entry,
				rx_user, dentry) {
		if (!rx_user->match_info.match_fn(&rx_user->match_info,
						  &wire_info))
			continue;
		dlist_remove(&rx_user->dentry);
		dlist_insert_tail(&rx_user->dentry, &zctx->rx_work_list);
		rx_wire = rx_user;
		rx_wire_init(rx_wire, conn, msg, i, wire_info.tag, true);
		return;
	}

	rx_wire = zhpe_rx_entry_alloc(zctx);
	rx_wire->match_info.conn = conn;
	rx_wire->op_flags = 0;
	dlist_insert_tail(&rx_wire->dentry, &match_lists->wire_list);
	rx_wire_init(rx_wire, conn, msg, i, wire_info.tag, false);
}

static void rx_handle_msg(struct zhpe_conn *conn, struct zhpe_msg *msg)
{
	switch (msg->hdr.op) {

	case ZHPE_OP_CONNECT2:
		zhpe_conn_connect2_rx(conn, msg);
		break;

	case ZHPE_OP_CONNECT3:
		zhpe_conn_connect3_rx(conn, msg);
		break;

	case ZHPE_OP_CONNECT_STATUS:
		zhpe_conn_connect_status_rx(conn, msg);
		break;

	case ZHPE_OP_STATUS:
		rx_handle_msg_status(conn, msg);
		break;

	case ZHPE_OP_SHUTDOWN:
		rx_handle_msg_shutdown(conn, msg);
		break;

	case ZHPE_OP_KEY_RELEASE:
		rx_handle_msg_key_release(conn, msg);
		break;

	case ZHPE_OP_KEY_REQUEST:
		rx_handle_msg_key_request(conn, msg);
		break;

	case ZHPE_OP_KEY_RESPONSE:
		rx_handle_msg_key_response(conn, msg);
		break;

	case ZHPE_OP_KEY_REVOKE:
		rx_handle_msg_key_revoke(conn, msg);
		break;

	case ZHPE_OP_WRITEDATA:
		rx_handle_msg_writedata(conn, msg);
		break;

	case ZHPE_OP_ATOMIC_REQUEST:
		rx_handle_msg_atomic_request(conn, msg);
		break;

	case ZHPE_OP_ATOMIC_RESULT:
		rx_handle_msg_atomic_result(conn, msg);
		break;

	case ZHPE_OP_SEND_F:
		zhpe_stats_start(zhpe_stats_subid(RECV, 1100));
		conn->rx_pending_fn(conn, msg);
		zhpe_stats_stop(zhpe_stats_subid(RECV, 1100));
		break;

	case ZHPE_OP_SEND_I:
	case ZHPE_OP_SEND_ID:
	case ZHPE_OP_SEND_IT:
	case ZHPE_OP_SEND_IDT:
	case ZHPE_OP_SEND_IM:
	case ZHPE_OP_SEND_IDM:
	case ZHPE_OP_SEND_ITM:
	case ZHPE_OP_SEND_IDTM:
	case ZHPE_OP_SEND:
	case ZHPE_OP_SEND_D:
	case ZHPE_OP_SEND_T:
	case ZHPE_OP_SEND_DT:
	case ZHPE_OP_SEND_M:
	case ZHPE_OP_SEND_DM:
	case ZHPE_OP_SEND_TM:
	case ZHPE_OP_SEND_DTM:
		/*
		 * ZZZ: check that the compiler is inling the cases
		 * separately.
		 */
		zhpe_stats_start(zhpe_stats_subid(RECV, 1100));
		rx_handle_msg_send(conn, msg);
		zhpe_stats_stop(zhpe_stats_subid(RECV, 1100));
		break;

	default:
		ZHPE_LOG_ERROR("Illegal opcode %u\n", msg->hdr.op);
		abort();
	}
}

struct zhpeq_rx_oos *zhpe_rx_oos_alloc(struct zhpeq_rx_seq *zseq)
{
	struct zhpe_conn       *conn = container_of(zseq, struct zhpe_conn,
						    rx_zseq);

	return zhpe_buf_alloc(&conn->zctx->rx_oos_pool);
}

void zhpe_rx_oos_free(struct zhpeq_rx_seq *zseq, struct zhpeq_rx_oos *rx_oos)
{
	struct zhpe_conn       *conn = container_of(zseq, struct zhpe_conn,
						    rx_zseq);

	return zhpe_buf_free(&conn->zctx->rx_oos_pool, rx_oos);
}

static void rx_oos_msg_handler(void *handler_data,
			       struct zhpe_enqa_payload *epay)
{
	struct zhpe_conn	*conn = handler_data;
	struct zhpe_msg		*msg = (void *)epay;

	rx_handle_msg(conn, msg);
}

static void rx_oos_msg_handler_connected(struct zhpe_conn *conn,
					 struct zhpe_rdm_entry *rqe)
{
	struct zhpe_msg		*msg = (void *)&rqe->payload;
	uint32_t		rx_seq = ntohl(msg->hdr.seqn);

	if (rx_seq == conn->rx_zseq.seq) {
		rx_handle_msg(conn, msg);
		conn->rx_zseq.seq++;
		zhpeq_rx_oos_spill(&conn->rx_zseq, UINT32_MAX,
				   rx_oos_msg_handler, conn);
		if (unlikely(!conn->rx_zseq.rx_oos_list))
			conn->rx_msg_handler = zhpe_rx_msg_handler_connected;
	} else
		zhpeq_rx_oos_insert(&conn->rx_zseq, (void *)msg, rx_seq);
}

void zhpe_rx_msg_handler_connected(struct zhpe_conn *conn,
				   struct zhpe_rdm_entry *rqe)
{
	struct zhpe_msg		*msg = (void *)&rqe->payload;
	uint32_t		rx_seq = ntohl(msg->hdr.seqn);

	if (OFI_LIKELY(rx_seq == conn->rx_zseq.seq)) {
		rx_handle_msg(conn, msg);
		conn->rx_zseq.seq++;
	} else {
		zhpeq_rx_oos_insert(&conn->rx_zseq, (void *)msg, rx_seq);
		conn->rx_msg_handler = rx_oos_msg_handler_connected;
	}
}

void zhpe_rx_msg_handler_unconnected(struct zhpe_conn *conn,
				     struct zhpe_rdm_entry *rqe)
{
	struct zhpe_ctx		*zctx = conn->zctx;
	struct zhpe_msg		*msg = (void *)&rqe->payload;

	/* ZZZ: Add version checking. */
	switch (msg->hdr.op) {

	case ZHPE_OP_CONNECT1:
		zhpe_conn_connect1_rx(zctx, msg, rqe->hdr.sgcid);
		break;

	case ZHPE_OP_CONNECT1_NAK:
		zhpe_conn_connect1_nak_rx(zctx, msg);
		break;

	default:
		ZHPE_LOG_ERROR("Illegal opcode %u\n", msg->hdr.op);
		abort();
	}
}

void zhpe_rx_msg_handler_drop(struct zhpe_conn *conn,
			      struct zhpe_rdm_entry *rqe)
{
}

static int ctx_progress_rx(struct zhpe_ctx *zctx)
{
	struct zhpe_rdm_entry	*rqe;
	struct zhpe_msg		*msg;
	struct zhpe_conn	*conn;

	if (OFI_UNLIKELY(!(rqe = zhpeq_rq_entry(zctx->zrq))))
		return 0;

	do {
		msg = (void *)&rqe->payload;
		conn = zhpe_ibuf_get(&zctx->conn_pool,
				     ntohs(msg->hdr.conn_idxn));
		conn->rx_msg_handler(conn, rqe);
		zhpeq_rq_entry_done(zctx->zrq, rqe);
		zhpeq_rq_head_update(zctx->zrq, 0);
	} while (OFI_LIKELY((rqe = zhpeq_rq_entry(zctx->zrq)) != NULL));

	return 1;
}

static void ctx_progress_ztq(struct zhpe_ctx *zctx, struct zhpeq_tq *ztq)
{
	struct zhpe_cq_entry	*cqe;
	struct zhpe_tx_entry	*tx_entry;

	while (OFI_LIKELY((cqe = zhpeq_tq_cq_entry(ztq)) != NULL)) {
		tx_entry = zhpeq_tq_cq_context(ztq, cqe);
		tx_entry->conn->tx_queued--;
		zctx->tx_queued--;
		assert(zctx->tx_queued >= 0);
		tx_call_handler(tx_entry, cqe);
		zhpeq_tq_cq_entry_done(ztq, cqe);
	}
}

static int ctx_progress_tx(struct zhpe_ctx *zctx)
{
	uint32_t		i;
	struct zhpe_conn	*conn;
	struct dlist_entry	*next;

	ctx_progress_ztq(zctx, zctx->ztq_hi);
	for (i = 0; i < zhpeq_attr.z.num_slices; i++)
		ctx_progress_ztq(zctx, zctx->ztq_lo[i]);
	if (OFI_UNLIKELY(!dlist_empty(&zctx->tx_dequeue_list))) {
		dlist_foreach_container_safe(&zctx->tx_dequeue_list,
					     struct zhpe_conn, conn,
					     tx_dequeue_dentry, next)
			conn->tx_dequeue(conn);
	}

	return (zctx->tx_queued != 0);
}

static void pe_ctx_null_op(struct zhpe_ctx *zctx)
{
}

static int pe_ctx_null_progress_op(struct zhpe_pe *pe, struct zhpe_ctx *zctx)
{
	return 0;
}

static int pe_ctx_progress(struct zhpe_pe *pe, struct zhpe_ctx *zctx);
static int pe_ctx_progress_tx(struct zhpe_pe *pe, struct zhpe_ctx *zctx);

static struct zhpe_pe_ctx_ops pe_ctx_ops_auto_tx_active = {
	.progress	= pe_ctx_progress_tx,
	.signal		= pe_ctx_null_op,
};

static void pe_ctx_signal(struct zhpe_ctx *zctx)
{
	/* zctx_lock() must be held. */
	zctx->pe_ctx_ops = &pe_ctx_ops_auto_tx_active;
	zhpeu_thr_wait_signal(&zctx2zdom(zctx)->pe->work_head.thr_wait);
}

static struct zhpe_pe_ctx_ops pe_ctx_ops_auto_tx_idle = {
	.progress	= pe_ctx_progress_tx,
	.signal		= pe_ctx_signal,
};

struct zhpe_pe_ctx_ops zhpe_pe_ctx_ops_auto_rx_active = {
	.progress	= pe_ctx_progress,
	.signal		= pe_ctx_null_op,
};

struct zhpe_pe_ctx_ops zhpe_pe_ctx_ops_manual = {
	.progress	= pe_ctx_null_progress_op,
	.signal		= pe_ctx_null_op,
};

static int pe_ctx_age_rx(struct zhpe_pe *pe, struct zhpe_ctx *zctx)
{
	/* zctx_lock() must be held. */
	if (zhpeq_rq_epoll_check(zctx->zrq, pe->now) &&
	    zhpeq_rq_epoll_enable(zctx->zrq)) {
		zctx->pe_ctx_ops = &pe_ctx_ops_auto_tx_idle;
		return 0;
	}

	return 1;
}

static int pe_ctx_age_tx(struct zhpe_pe *pe, struct zhpe_ctx *zctx)
{
	/* zctx_lock() must be held. */
	if (zhpeq_rq_epoll_check(zctx->zrq, pe->now)) {
		zctx->pe_ctx_ops = &pe_ctx_ops_auto_tx_idle;
		return 0;
	}

	return 1;
}

void zhpe_ctx_cleanup_progress(struct zhpe_ctx *zctx, bool locked)
{
	struct zhpe_dom		*zdom = zctx2zdom(zctx);
	int			rc;

	if (zdom->util_domain.data_progress == FI_PROGRESS_MANUAL) {
		if (!locked)
			zctx_lock(zctx);
		rc = ctx_progress_rx(zctx) | ctx_progress_tx(zctx);
		if (!rc) {
			zctx_unlock(zctx);
			zhpeu_yield();
			if (locked)
				zctx_lock(zctx);
		} else if (!locked)
			zctx_unlock(zctx);
	}
	else if (locked) {
		zctx_unlock(zctx);
		zhpeu_yield();
		zctx_lock(zctx);
	} else
		zhpeu_yield();
}

void zhpe_ofi_ep_progress(struct util_ep *ep)
{
	struct zhpe_ctx		*zctx = uep2zctx(ep);

	/* Manual progress for context via cq/cntr. */
	if (!zctx_trylock(zctx))
		return;
	ctx_progress_rx(zctx);
	ctx_progress_tx(zctx);
	zctx_unlock(zctx);
}

static int pe_ctx_progress_tx(struct zhpe_pe *pe, struct zhpe_ctx *zctx)
{
	int			ret;

	/* Automatic progress for context; zctx_lock() must be held. */
	ret = ctx_progress_tx(zctx);
	if (OFI_UNLIKELY(!ret))
		ret = pe_ctx_age_tx(pe, zctx);

	return ret;
}

static int pe_ctx_progress(struct zhpe_pe *pe, struct zhpe_ctx *zctx)
{
	int			ret;

	/* Automatic progress for context; zctx_lock() must be held. */
	ret = ctx_progress_rx(zctx) | ctx_progress_tx(zctx);
	if (OFI_UNLIKELY(!ret))
		ret = pe_ctx_age_rx(pe, zctx);

	return ret;
}

void zhpe_pe_epoll_handler(struct zhpeq_rq *zrq, void *handler_data)
{
	struct zhpe_ctx		*zctx = handler_data;

	zctx_lock(zctx);
	zctx->pe_ctx_ops = &zhpe_pe_ctx_ops_auto_rx_active;
	zctx_unlock(zctx);
}

static int pe_work_queue(struct zhpe_pe *pe, zhpeu_worker worker, void *data)
{

	int			ret;
	struct zhpeu_work	work;

	zhpeu_work_init(&work);
	zhpeu_work_queue(&pe->work_head, &work, worker, data,
			 true, true, false);
	zhpeu_work_wait(&pe->work_head, &work, false, true);
	ret = work.status;
	zhpeu_work_destroy(&work);

	return ret;
}

static bool pe_add_progress(struct zhpeu_work_head *head,
			    struct zhpeu_work *work)
{
	struct zhpe_pe		*pe =
		container_of(head, struct zhpe_pe, work_head);
	struct zhpe_pe_progress	*zprog = work->data;

	if (dlist_empty(&zprog->pe_dentry))
		dlist_insert_tail(&zprog->pe_dentry, &pe->progress_list);

	return false;
}

void zhpe_pe_add_progress(struct zhpe_dom *zdom,
			  struct zhpe_pe_progress *zprog)
{
	pe_work_queue(zdom->pe, pe_add_progress, zprog);
}

static bool pe_del_progress(struct zhpeu_work_head *head,
			       struct zhpeu_work *work)
{
	struct zhpe_pe_progress	*zprog = work->data;

	dlist_remove_init(&zprog->pe_dentry);

	return false;
}

void zhpe_pe_del_progress(struct zhpe_dom *zdom,
			  struct zhpe_pe_progress *zprog)
{
	pe_work_queue(zdom->pe, pe_del_progress, zprog);
}

static bool pe_add_ctx(struct zhpeu_work_head *head,
		       struct zhpeu_work *work)
{
	struct zhpe_pe		*pe =
		container_of(head, struct zhpe_pe, work_head);
	struct zhpe_ctx		*zctx = work->data;

	if (dlist_empty(&zctx->pe_dentry))
		dlist_insert_tail(&zctx->pe_dentry, &pe->ctx_list);

	return false;
}

void zhpe_pe_add_ctx(struct zhpe_ctx *zctx)
{
	struct zhpe_dom		*zdom = zctx2zdom(zctx);

	pe_work_queue(zdom->pe, pe_add_ctx, zctx);
}

static bool pe_del_ctx(struct zhpeu_work_head *head,
			  struct zhpeu_work *work)
{
	struct zhpe_ctx		*zctx = work->data;

	dlist_remove_init(&zctx->pe_dentry);

	return false;
}

void zhpe_pe_del_ctx(struct zhpe_ctx *zctx)
{
	struct zhpe_dom		*zdom = zctx2zdom(zctx);

	pe_work_queue(zdom->pe, pe_del_ctx, zctx);
}

static int pe_progress(struct zhpe_pe *pe)
{
	int			ret = 0;
	struct zhpe_pe_progress	*zprog;
	struct zhpe_ctx		*zctx;
	struct dlist_entry	*next;

	pe->now = get_cycles_approx();
	dlist_foreach_container_safe(&pe->progress_list,
				     struct zhpe_pe_progress, zprog, pe_dentry,
				     next)
		ret |= zprog->pe_progress(zprog);

	dlist_foreach_container_safe(&pe->ctx_list, struct zhpe_ctx, zctx,
				     pe_dentry, next) {
		if (OFI_LIKELY(zctx_trylock(zctx))) {
			ret |= zctx->pe_ctx_ops->progress(pe, zctx);
			zctx_unlock(zctx);
		} else
			ret = 1;
	}

	return ret;
}

static void *zhpe_pe_thread(void *data)
{
	struct zhpe_pe		*pe = (struct zhpe_pe *)data;
	int			outstanding = 0;
	int			rc;

	ZHPE_LOG_DBG("Progress thread started\n");

	while (OFI_LIKELY(!pe->pe_exit)) {
		rc = zhpeq_rq_epoll(pe->zepoll, (outstanding ? 0 : -1),
				    NULL, true);
		assert_always(rc >= 0);

		if (OFI_UNLIKELY(zhpeu_work_queued(&pe->work_head)) &&
		    zhpeu_work_process(&pe->work_head, true, true))
			outstanding = 1;
		else
			outstanding = 0;

		outstanding |= pe_progress(pe);
	}

 	ZHPE_LOG_DBG("Progress thread terminated\n");

	return NULL;
}

static bool pe_signal(struct zhpeu_thr_wait *thr_wait)
{
	struct zhpe_pe		*pe = container_of(thr_wait, struct zhpe_pe,
						   work_head.thr_wait);

	(void)zhpeq_rq_epoll_signal(pe->zepoll);

	return false;
}

static void pe_free(struct zhpe_pe *pe)
{
	assert_always(dlist_empty(&pe->progress_list));
	assert_always(dlist_empty(&pe->ctx_list));

	zhpeq_rq_epoll_free(pe->zepoll);
	zhpeu_work_head_destroy(&pe->work_head);
	free(pe);
}

struct zhpe_pe *zhpe_pe_init(struct zhpe_dom *zdom)
{
	struct zhpe_pe		*pe;
	int			rc;

	pe = calloc_cachealigned(1, sizeof(*pe));
	if (!pe)
		return NULL;

	zhpeu_work_head_signal_init(&pe->work_head, pe_signal, NULL);
	dlist_init(&pe->progress_list);
	dlist_init(&pe->ctx_list);
	pe->zdom = zdom;

	rc = zhpeq_rq_epoll_alloc(&pe->zepoll);
	if (rc < 0) {
		ZHPE_LOG_ERROR("zhpeq_rq_epoll_alloc() error %d:%s\n",
			       rc, fi_strerror(-rc));
		pe_free(pe);

		return NULL;
	}

	if (pthread_create(&pe->progress_thread, NULL, zhpe_pe_thread,
			   (void *)pe)) {
		ZHPE_LOG_ERROR("Couldn't create progress thread\n");
		pe_free(pe);

		return NULL;
	}
	ZHPE_LOG_DBG("PE init: OK\n");

	return pe;
}

void zhpe_pe_fini(struct zhpe_pe *pe)
{
	if (!pe)
		return;

	pe->pe_exit = 1;
	pe_signal(&pe->work_head.thr_wait);
	pthread_join(pe->progress_thread, NULL);

	pe_free(pe);

	ZHPE_LOG_DBG("Progress engine finalize: OK\n");
}
