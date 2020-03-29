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

#define ZHPE_SUBSYS	FI_LOG_EP_CTRL

/* Assumptions. */
static_assert(FI_READ * 2 == FI_WRITE, "FI_WRITE");

static void conn_dequeue_rma(struct zhpe_conn *conn,
			     struct zhpe_tx_queue_entry *txqe)
{
	struct zhpe_tx_entry	*tx_entry = txqe->tx_entry;

	zhpe_iov_rma(tx_entry, ZHPE_SEG_MAX_BYTES, ZHPE_SEG_MAX_OPS);
	if (OFI_UNLIKELY(!tx_entry->cstat.completions))
		return;

	conn->zctx->tx_queued--;
	assert(conn->zctx->tx_queued >= 0);
	tx_entry->cstat.flags &= ~ZHPE_CS_FLAG_QUEUED;
	dlist_remove(&txqe->dentry);
	zhpe_buf_free(&conn->zctx->tx_queue_pool, txqe);
}

static void conn_dequeue_wqe(struct zhpe_conn *conn,
			     struct zhpe_tx_queue_entry *txqe)
{
	struct zhpe_ctx		*zctx = conn->zctx;
	struct zhpe_tx_entry	*tx_entry = txqe->tx_entry;
	union zhpe_hw_wq_entry	*wqe;
	struct zhpe_msg		*msg;
	int32_t			reservation;

	reservation = zhpeq_tq_reserve(zctx->ztq_hi);
	if (OFI_UNLIKELY(reservation < 0)) {
		assert(reservation == -EAGAIN);
		return;
	}

	if (OFI_LIKELY(txqe->wqe.hdr.opcode == ZHPE_HW_OPCODE_ENQA)) {
		if (OFI_UNLIKELY(!zhpe_tx_entry_slot_alloc(tx_entry))) {
			zhpeq_tq_unreserve(zctx->ztq_hi, reservation);
			return;
		}
		msg = (void *)&txqe->wqe.enqa.payload;
		msg->hdr.cmp_idxn = htons(tx_entry->cmp_idx);
	}

	conn->tx_queued++;
	/* "Consumes" the zctx->tx_queued that was added when queued. */

	tx_entry->cstat.flags &= ~ZHPE_CS_FLAG_QUEUED;
	wqe = zhpeq_tq_get_wqe(zctx->ztq_hi, reservation);
	zhpeq_tq_set_context(zctx->ztq_hi, reservation, tx_entry);
	memcpy(wqe, &txqe->wqe, sizeof(*wqe));
	zhpeq_tq_insert(zctx->ztq_hi, reservation);
	zhpeq_tq_commit(zctx->ztq_hi);
	zctx->pe_ctx_ops->signal(zctx);
	dlist_remove(&txqe->dentry);
	zhpe_buf_free(&zctx->tx_queue_pool, txqe);
}

static void conn_dequeue_wqe_throttled(struct zhpe_conn *conn,
				      struct zhpe_tx_queue_entry *txqe)
{
	/* For now, no throttling. */
	conn_dequeue_wqe(conn, txqe);
}

static void conn_dequeue(struct zhpe_conn *conn)
{
	struct zhpe_tx_queue_entry *txqe;

	if (dlist_empty(&conn->tx_queue)) {
		if (OFI_LIKELY(conn->flags != ZHPE_CONN_FLAG_CLEANUP))
			return;
		conn->flags = 0;
		dlist_remove_init(&conn->tx_dequeue_dentry);
		return;
	}

	/* One at a time: round-robin tx queue amongst conns. */
	txqe = container_of(conn->tx_queue.next, struct zhpe_tx_queue_entry,
			    dentry);

	/* Handle RMA retry. */
	if (OFI_UNLIKELY(txqe->tx_entry->cstat.flags & ZHPE_CS_FLAG_RMA)) {
		conn_dequeue_rma(conn, txqe);
		return;
	}

	/* Assume backoff is the reason we're here. */
	if (OFI_LIKELY(conn->flags & ZHPE_CONN_FLAG_BACKOFF))
		conn_dequeue_wqe_throttled(conn, txqe);
	else
		conn_dequeue_wqe(conn, txqe);
}

void zhpe_conn_dequeue_fence(struct zhpe_conn *conn)
{
	struct zhpe_tx_queue_entry *txqe;

	if (OFI_UNLIKELY(dlist_empty(&conn->tx_queue)))
		/* Should never get here because of fence logic below. */
		assert_always(false);

	/* One at a time: round-robin tx queue amongst conns. */
	txqe = container_of(conn->tx_queue.next, struct zhpe_tx_queue_entry,
			    dentry);

	if (txqe->tx_entry->cstat.flags & ZHPE_CS_FLAG_FENCE) {
		if (OFI_LIKELY(conn->tx_queued))
			return;
		/* A fenced RMA/Atomic could be waiting on key responses. */
		if (txqe->tx_entry->cstat.flags & ZHPE_CS_FLAG_KEY_WAIT)
			return;
		txqe->tx_entry->cstat.flags &= ~ZHPE_CS_FLAG_FENCE;
		conn->tx_fences--;
		assert_always(conn->tx_fences >= 0);
		if (OFI_LIKELY(!conn->tx_fences))
			conn->tx_dequeue = conn_dequeue;
	}

	/* Handle RMA retry. */
	if (OFI_UNLIKELY(txqe->tx_entry->cstat.flags & ZHPE_CS_FLAG_RMA)) {
		conn_dequeue_rma(conn, txqe);
		return;
	}

	/* Assume backoff isn't the reason we're here. */
	if (OFI_UNLIKELY(conn->flags & ZHPE_CONN_FLAG_BACKOFF))
		conn_dequeue_wqe_throttled(conn, txqe);
	else
		conn_dequeue_wqe(conn, txqe);
}

static void conn_dequeue_connect(struct zhpe_conn *conn)
{
	struct zhpe_tx_queue_entry *txqe;
	struct zhpe_msg		*msg;

	if (!(conn->flags & ZHPE_CONN_FLAG_CONNECT_MASK)) {
		if (conn->tx_fences)
			conn->tx_dequeue = zhpe_conn_dequeue_fence;
		else
			conn->tx_dequeue = conn_dequeue;
		conn->tx_dequeue(conn);
		return;
	}
	if (dlist_empty(&conn->tx_queue))
		return;

	/* One at a time: round-robin tx queue amongst conns. */
	txqe = container_of(conn->tx_queue.next, struct zhpe_tx_queue_entry,
			    dentry);

	msg = (void *)&txqe->wqe.enqa.payload;

	switch (msg->hdr.op) {

	case ZHPE_OP_CONNECT2:
	case ZHPE_OP_CONNECT3:
		break;

	default:
		return;
	}

	/* Assume backoff isn't the reason we're here. */
	if (OFI_UNLIKELY(conn->flags & ZHPE_CONN_FLAG_BACKOFF))
		conn_dequeue_wqe_throttled(conn, txqe);
	else
		conn_dequeue_wqe(conn, txqe);
}

struct zhpe_conn *zhpe_conn_alloc(struct zhpe_ctx *zctx)
{
	struct zhpe_conn	*conn;

	conn = zhpe_ibuf_alloc(&zctx->conn_pool);
	conn->zctx = zctx;
	conn->tx_entry_inject.conn = conn;
	conn->tx_entry_inject.tx_handler = ZHPE_TX_HANDLE_MSG_INJECT;
	conn->tx_entry_prov.conn = conn;
	conn->tx_entry_prov.tx_handler = ZHPE_TX_HANDLE_MSG_PROV;
	dlist_init(&conn->tx_queue);
	dlist_init(&conn->tx_dequeue_dentry);
	conn->tx_dequeue = conn_dequeue_connect;
	conn->rx_msg_handler = zhpe_rx_msg_handler_connected;
	conn->rx_zseq.alloc = zhpe_rx_oos_alloc;
	conn->rx_zseq.free = zhpe_rx_oos_free;
	do {
		conn->rx_zseq.seq = random();
	} while (!conn->rx_zseq.seq);
	conn->fiaddr = FI_ADDR_NOTAVAIL;

	return conn;
}

static struct zhpe_conn *
conn_tree_lookup(struct zhpe_ctx *zctx, struct zhpe_conn_tree_key *tkey,
		 bool *new)
{
	struct zhpe_conn	*conn;
	struct ofi_rbnode	*rbnode;
	int			rc;

	rbnode = ofi_rbmap_find(&zctx->conn_tree, tkey);
	if (OFI_LIKELY(rbnode != NULL)) {
		*new = false;

		return rbnode->data;
	}

	*new = true;
	conn = zhpe_conn_alloc(zctx);
	conn->tkey = *tkey;
	rc = ofi_rbmap_insert(&zctx->conn_tree, &conn->tkey, conn, NULL);
	assert_always(!rc);

	return conn;
}

static void conn_connect_fixup(struct zhpe_conn *conn,
			       struct dlist_entry *queue_head, uint32_t msgs)
{
	struct zhpe_tx_queue_entry *txqe;
	struct zhpe_msg		*msg;

	conn->tx_seq += msgs;
	dlist_init(queue_head);
	dlist_splice_tail(queue_head, &conn->tx_queue);
	dlist_foreach_container(queue_head, struct zhpe_tx_queue_entry,
				txqe, dentry) {
		if (txqe->tx_entry->cstat.flags & ZHPE_CS_FLAG_RMA)
			continue;
		/* Fix rspctxid, sequence, and conn_idx. */
		msg = zhpeq_tq_enqa(&txqe->wqe, 0,
				    conn->tkey.rem_gcid, conn->rem_rspctxid);
		msg->hdr.seqn = htonl(conn->tx_seq++);
		msg->hdr.conn_idxn = conn->rem_conn_idxn;
	}
}

static void conn_connect_status_tx(struct zhpe_conn *conn, int status,
				   uint32_t tx_seq)
{
	struct zhpe_msg_connect_status connect_status;

	assert((int16_t)status == status);
	connect_status.statusn = htons(status);
	zhpe_msg_prov_no_eflags(conn, ZHPE_OP_CONNECT_STATUS, &connect_status,
				sizeof(connect_status), 0, tx_seq);
}

static void conn_tx_queue_flush(struct zhpe_conn *conn, int error)
{
	struct zhpe_ctx		*zctx = conn->zctx;
	bool			first = true;
	struct zhpe_tx_queue_entry *txqe;
	struct zhpe_tx_entry	*tx_entry;
	struct dlist_entry	*next;
	struct zhpe_msg		*msg;

	/*
	 * This is only useful when the connection protocol fails. This
	 * is because none of the real traffic has been sent.
	 */
	assert_always(error < 0);
	assert_always(error >= INT16_MIN);

	dlist_foreach_container_safe(&conn->tx_queue,
				     struct zhpe_tx_queue_entry, txqe,
				     dentry, next) {
		tx_entry = txqe->tx_entry;
		/* Unwind tx_seq. */
		if (OFI_UNLIKELY(first) &&
		    !(tx_entry->cstat.flags & ZHPE_CS_FLAG_RMA)) {
			msg = (void *)&txqe->wqe.enqa.payload;
			conn->tx_seq = ntohl(msg->hdr.seqn);
			first = false;
		}
		if (tx_entry->cstat.status >= 0)
			tx_entry->cstat.status = error;
		tx_entry->cstat.completions = 1;
		dlist_remove(&txqe->dentry);
		zhpe_buf_free(&zctx->tx_queue_pool, txqe);
		zhpe_tx_call_handler_fake(tx_entry, 0xFF);
	}
}

static void conn_connect_error(struct zhpe_conn *conn, int error, bool send)
{
	struct zhpe_ctx		*zctx = conn->zctx;

	assert_always(error < 0);
	assert_always(error >= INT16_MIN);

	/*
	 * ZZZ:Delete the conn from the tree and the index-map. However,
	 * leave the conn structure in existence to deal with any
	 * late messages.
	 */
	(void)ofi_rbmap_find_delete(&zctx->conn_tree, &conn->tkey);
	if (conn->fiaddr != FI_ADDR_NOTAVAIL) {
		ofi_idm_clear(&zctx->conn_av_idm,
			      zhpe_av_get_tx_idx(zctx2zav(zctx), conn->fiaddr));
		conn->fiaddr = FI_ADDR_NOTAVAIL;
	}
	/* Return error for any pending ops. */
	conn_tx_queue_flush(conn, error);
	conn->eflags |= ZHPE_CONN_EFLAG_ERROR;
	conn->rx_msg_handler = zhpe_rx_msg_handler_drop;
	if (send)
		conn_connect_status_tx(conn, error, conn->tx_seq++);
}

static uint8_t conn_wire_rma_flags(struct zhpe_ctx *zctx)
{
	uint8_t			ret = 0;

	if (zctx->util_ep.rem_rd_cntr)
		ret |= ZHPE_CONN_RMA_REM_RD;
	if (zctx->util_ep.rem_wr_cntr)
		ret |= ZHPE_CONN_RMA_REM_WR;
	if (!(zdom2map(zctx2zdom(zctx))->mode & FI_MR_VIRT_ADDR))
		ret |= ZHPE_CONN_RMA_ZERO_OFF;

	return ret;
}

static uint64_t conn_rem_rma_flags(uint64_t wire_rma_flags)
{
	uint64_t		ret = FI_REMOTE_CQ_DATA;

	if (wire_rma_flags & ZHPE_CONN_RMA_ZERO_OFF)
		ret |= FI_ZHPE_RMA_ZERO_OFF;
	wire_rma_flags &= ZHPE_CONN_RMA_REM_OP;
	ret |= wire_rma_flags * FI_READ;

	return ret;
}

static void conn_connect1_tx(struct zhpe_conn *conn, uuid_t uuid)
{
	struct zhpe_ctx		*zctx = conn->zctx;
	struct zhpe_msg_connect1 connect1;

	connect1.versionn = htons(ZHPE_PROTO_VERSION);
	connect1.src_conn_idxn = htons(zhpe_ibuf_index(&zctx->conn_pool, conn));
	connect1.src_rspctxid0n = htonl(zctx->zep->zctx[0]->lcl_rspctxid);
	connect1.src_rspctxidn = htonl(zctx->lcl_rspctxid);
	connect1.src_ctx_idx = htons(zctx->ctx_idx);
	connect1.dst_ctx_idx = htons(conn->tkey.rem_ctx_idx);
	connect1.src_rma_flags = conn_wire_rma_flags(zctx);
	memcpy(connect1.dst_uuid, uuid, sizeof(connect1.dst_uuid));

	zhpe_msg_connect(zctx, ZHPE_OP_CONNECT1, &connect1, sizeof(connect1),
			 conn->rx_zseq.seq, conn->tkey.rem_gcid,
			 conn->tkey.rem_rspctxid0);
}

static void conn_connect1_nak_tx(struct zhpe_ctx *zctx,
				 struct zhpe_conn_tree_key *tkey,
				 uint16_t rem_conn_idxn, int error)
{
	struct zhpe_msg_connect1_nak nak;

	assert_always(error < 0);
	assert_always(error >= INT16_MIN);

	nak.version = htons(ZHPE_PROTO_VERSION);
	assert((int16_t)error == error);
	nak.errorn = htons(error);
	nak.ctx_idx = htons(tkey->rem_ctx_idx);
	nak.conn_idxn = rem_conn_idxn;
	zhpe_msg_connect(zctx, ZHPE_OP_CONNECT1_NAK, &nak, sizeof(nak), 0,
			 tkey->rem_gcid, tkey->rem_rspctxid0);
}

static void conn_connect23_tx(struct zhpe_conn *conn)
{
	int			rc;
	struct zhpe_ctx		*zctx = conn->zctx;
	struct zhpe_msg_connect2 connect2;
	struct zhpe_msg_connect3 connect3;
	size_t			blob_off;
	size_t			blob_len;
	struct dlist_entry	queue_head;
	uint32_t		tx_seq;
	uint32_t		msgs;

	connect2.rspctxidn = htonl(zctx->lcl_rspctxid);
	connect2.rx_seqn = htonl(conn->rx_zseq.seq);
	connect2.conn_idxn = htons(zhpe_ibuf_index(&zctx->conn_pool, conn));
	connect2.rma_flags = conn_wire_rma_flags(zctx);
	memcpy(connect2.uuid, zctx->zep->uuid, sizeof(connect2.uuid));

	blob_off = offsetof(struct zhpe_msg_connect3, blob);
	blob_len = sizeof(connect3) - blob_off;
	rc = zhpeq_qkdata_export(zctx2zdom(zctx)->reg_zmr->qkdata,
				 zctx2zdom(zctx)->reg_zmr->qkdata->z.access,
				 connect3.blob, &blob_len);
	assert_always(rc >= 0);
	if (rc < 0) {
		conn_connect_error(conn, rc, true);
		return;
	}

	msgs = 2;
	if (conn->flags & ZHPE_CONN_FLAG_CONNECT1)
		msgs++;
	tx_seq = conn->tx_seq;
	conn_connect_fixup(conn, &queue_head, msgs);
	zhpe_msg_prov_no_eflags(conn, ZHPE_OP_CONNECT2, &connect2,
				sizeof(connect2), 0, tx_seq++);
	zhpe_msg_prov_no_eflags(conn, ZHPE_OP_CONNECT3, &connect3,
				blob_off + blob_len, 0, tx_seq++);
	if (msgs == 3)
		conn_connect_status_tx(conn, 0, tx_seq++);
	dlist_splice_tail(&conn->tx_queue, &queue_head);
}

void zhpe_conn_connect1_rx(struct zhpe_ctx *zctx, struct zhpe_msg *msg,
			   uint32_t rem_gcid)
{
	struct zhpe_msg_connect1 *connect1 = (void *)msg->payload;
	struct zhpe_conn_tree_key tkey = {
		.rem_gcid	= rem_gcid,
		.rem_rspctxid0	= ntohl(connect1->src_rspctxid0n),
		.rem_ctx_idx	= ntohs(connect1->src_ctx_idx),
	};
	uint16_t		rem_conn_idxn = connect1->src_conn_idxn;
	struct zhpe_ctx		*cctx;
	struct zhpe_conn	*conn;
	bool			new;
	int			rc;

	if (ntohs(connect1->versionn) != ZHPE_PROTO_VERSION) {
		rc = -EPROTO;
		goto err;
	} else if (zctx->shutdown) {
		rc = -FI_EBUSY;
		goto err;
	} else if (connect1->dst_ctx_idx >= zctx->zep->num_rx_ctx) {
		rc = -ENXIO;
		goto err;
	}

	/* ZZZ: nested locks. */
	cctx = zctx->zep->zctx[connect1->dst_ctx_idx];
	if (cctx != zctx)
		zctx_lock(cctx);
	conn = conn_tree_lookup(cctx, &tkey, &new);
	if (!new) {
		/* Some ugly stale edges? */
		if (!(conn->flags & ZHPE_CONN_FLAG_CONNECT))
			return;
		/* Some kind of race: lower address wins. */
		rc = arithcmp(rem_gcid, cctx->lcl_gcid);
		if (!rc)
		    rc = arithcmp(tkey.rem_rspctxid0,
				  cctx->zep->zctx[0]->lcl_rspctxid);
		/* Quit if higher or self. */
		if (rc >= 0)
			return;
	}
	assert_always(!conn->rem_rspctxid);
	assert_always(!(conn->flags & ZHPE_CONN_FLAG_CONNECT1));
	zhpe_conn_flags_set(conn, ZHPE_CONN_FLAG_CONNECT1);
	conn->tx_seq = ntohl(msg->hdr.seqn);
	conn->rem_conn_idxn = rem_conn_idxn;
	conn->rem_rspctxid = ntohl(connect1->src_rspctxidn);
	conn->rem_rma_flags = conn_rem_rma_flags(connect1->src_rma_flags);
	conn_connect23_tx(conn);
	if (cctx != zctx)
		zctx_unlock(cctx);

	return;

 err:
	conn_connect1_nak_tx(zctx, &tkey, rem_conn_idxn, rc);
}

void zhpe_conn_connect1_nak_rx(struct zhpe_ctx *zctx,
			       struct zhpe_msg *msg)
{
	struct zhpe_msg_connect1_nak *nak = (void *)msg->payload;
	struct zhpe_ctx		*cctx;
	struct zhpe_conn	*conn;
	int			error;

	cctx = zctx->zep->zctx[ntohs(nak->ctx_idx)];
	if (cctx != zctx)
		zctx_lock(cctx);
	conn = zhpe_ibuf_get(&zctx->conn_pool, ntohs(nak->conn_idxn));
	error = (int16_t)ntohs(nak->errorn);
	assert_always(error < 0);
	conn_connect_error(conn, error, false);
	if (cctx != zctx)
		zctx_unlock(cctx);
}

void zhpe_conn_connect2_rx(struct zhpe_conn *conn, struct zhpe_msg *msg)
{
	struct zhpe_ctx		*zctx = conn->zctx;
	struct zhpe_msg_connect2 *connect2 = (void *)msg->payload;
	struct sockaddr_zhpe	sz = {
		.sz_family	= AF_ZHPE,
		.sz_queue	= connect2->rspctxidn,
	};
	struct zhpe_av		*zav = zctx2zav(zctx);
	int			rc;

	assert_always(!conn->eflags);
	assert_always(conn->flags & ZHPE_CONN_FLAG_CONNECT_MASK);
	if (!conn->rem_rspctxid) {
		conn->tx_seq = ntohl(connect2->rx_seqn);
		conn->rem_rspctxid = ntohl(sz.sz_queue);
		conn->rem_conn_idxn = connect2->conn_idxn;
		conn->rem_rma_flags = conn_rem_rma_flags(connect2->rma_flags);
	} else
		assert_always(conn->flags & ZHPE_CONN_FLAG_CONNECT1);

	memcpy(sz.sz_uuid, connect2->uuid, sizeof(sz.sz_uuid));
	zav_lock(zav);
	(void)zhpe_av_update_addr_unsafe(zav, &sz);
	zav_unlock(zav);
	rc = zhpeq_domain_insert_addr(zctx2zdom(zctx)->zqdom, &sz,
				      &conn->addr_cookie);
	assert_always(rc >= 0);
	if (rc < 0)
		conn_connect_error(conn, rc, true);
}

void zhpe_conn_connect3_rx(struct zhpe_conn *conn, struct zhpe_msg *msg)
{
	struct zhpe_ctx		*zctx = conn->zctx;
	struct zhpe_msg_connect3 *connect3 = (void *)msg->payload;
	size_t			blob_len;
	int			rc;

	/* connect2 failed? */
	if (!conn->addr_cookie)
		return;

	assert_always(!conn->eflags);
	assert_always(conn->flags & ZHPE_CONN_FLAG_CONNECT_MASK);
	assert_always(conn->rem_rspctxid);

	blob_len = msg->hdr.len - offsetof(struct zhpe_msg_connect3, blob);
	rc = zhpeq_qkdata_import(zctx2zdom(zctx)->zqdom, conn->addr_cookie,
				 connect3->blob, blob_len, &conn->qkdata);
	assert_always(!rc);
	if (OFI_UNLIKELY(rc < 0)) {
		conn_connect_error(conn, rc, true);
		return;
	}
	rc = zhpeq_zmmu_reg(conn->qkdata);
	assert_always(rc >= 0);
	if (OFI_UNLIKELY(rc < 0)) {
		conn_connect_error(conn, rc, true);
		return;
	}
	conn->rx_reqzmmu = conn->qkdata->z.zaddr - conn->qkdata->z.vaddr;
	if (conn->flags & ZHPE_CONN_FLAG_CONNECT1)
		conn->flags &= ~ZHPE_CONN_FLAG_CONNECT_MASK;
	else
		conn_connect23_tx(conn);
}

void zhpe_conn_connect_status_rx(struct zhpe_conn *conn, struct zhpe_msg *msg)
{
	struct zhpe_msg_connect_status *connect_status = (void *)msg->payload;
	int			status;

	status = (int16_t)ntohs(connect_status->statusn);

	assert_always(!conn->eflags);

	if (status >= 0) {
		assert_always(conn->flags & ZHPE_CONN_FLAG_CONNECT_MASK);
		conn->flags &= ~ZHPE_CONN_FLAG_CONNECT_MASK;
		return;
	}
	conn_connect_error(conn, status, false);
}

static void conn_fam_setup(struct zhpe_conn *conn, struct sockaddr_zhpe *sz)
{
	struct zhpe_ctx		*zctx = conn->zctx;
	struct zhpeq_dom	*zqdom = zctx2zdom(conn->zctx)->zqdom;
	size_t			n_qkdata = 0;
	struct zhpeq_key_data	*qkdata[2];
	struct zhpe_rkey	*rkey;
	size_t			i;
	int			rc;

	/* zctx_lock() must be held. */
	rc = zhpeq_domain_insert_addr(zqdom, sz, &conn->addr_cookie);
	if (rc < 0) {
		ZHPE_LOG_ERROR("%s,%u:zhpeq_fam_qkdata() error %d\n",
			       __func__, __LINE__, rc);
		goto error;
	}
	/* Get qkdata entries for FAM.*/
	n_qkdata = ARRAY_SIZE(qkdata);
	rc = zhpeq_fam_qkdata(zqdom, conn->addr_cookie, qkdata, &n_qkdata);
	if (rc < 0) {
		ZHPE_LOG_ERROR("%s,%u:zhpeq_fam_qkdata() error %d\n",
			       __func__, __LINE__, rc);
		goto error;
	}
	for (i = 0; i < n_qkdata; i++) {
		rc = zhpeq_zmmu_reg(qkdata[i]);
		if (rc < 0) {
			ZHPE_LOG_ERROR("%s,%u:zhpeq_zmmu_reg() error %d\n",
				       __func__, __LINE__, rc);
			break;
		}
	}
	if (rc < 0) {
		for (i = 0; i < n_qkdata; i++)
			zhpeq_qkdata_free(qkdata[i]);
		goto error;
	}
	for (i = 0; i < n_qkdata; i++) {
		rkey = xmalloc(sizeof(*rkey));
		rkey->tkey.rem_gcid = conn->tkey.rem_gcid;
		rkey->tkey.rem_rspctxid = conn->rem_rspctxid;
		rkey->tkey.key = i;
		rkey->conn = conn;
		rkey->qkdata = qkdata[i];
		dlist_init(&rkey->rkey_wait_list);
		rkey->ref = 1;
		rc = ofi_rbmap_insert(&zctx->rkey_tree, &rkey->tkey, rkey,
				       NULL);
		assert_always(rc >= 0);
	}
	conn->fam = true;

	return;

 error:
	conn->eflags |= ZHPE_CONN_EFLAG_ERROR;
}

static struct zhpe_conn conn_error = {
	.eflags			= ZHPE_CONN_EFLAG_ERROR,
};

struct zhpe_conn *zhpe_conn_av_lookup(struct zhpe_ctx *zctx, fi_addr_t fiaddr)
{
	struct zhpe_conn	*conn;
	struct zhpe_av		*zav = zctx2zav(zctx);
	uint64_t		av_idx = zhpe_av_get_tx_idx(zav, fiaddr);
	struct sockaddr_zhpe	*sz;
	struct sockaddr_zhpe	sz_copy;
	struct zhpe_conn_tree_key tkey;
	bool			new;
	int			rc MAYBE_UNUSED;

	conn = ofi_idm_lookup(&zctx->conn_av_idm, av_idx);
	if (OFI_LIKELY(conn != NULL))
		return conn;
	zav = zctx2zav(zctx);
	fastlock_acquire(&zav->util_av.lock);
	sz = zhpe_av_get_addr_unsafe(zav, fiaddr);
	if (OFI_UNLIKELY(!sz)) {
		fastlock_release(&zav->util_av.lock);

		return &conn_error;
	}
	memcpy(&sz_copy, sz, sizeof(sz_copy));
	fastlock_release(&zav->util_av.lock);

	tkey.rem_gcid = zhpeu_uuid_to_gcid(sz_copy.sz_uuid);
	tkey.rem_rspctxid0 = ntohl(sz_copy.sz_queue);
	tkey.rem_ctx_idx = zhpe_av_get_rx_idx(zav, fiaddr);
	conn = conn_tree_lookup(zctx, &tkey, &new);
	rc = ofi_idm_set(&zctx->conn_av_idm, av_idx, conn);
	assert_always(rc != -1);
	conn->fiaddr = fiaddr;
	if (!new)
		return conn;

	if ((tkey.rem_rspctxid0 & ZHPE_SZQ_FLAGS_MASK) == ZHPE_SZQ_FLAGS_FAM)
		conn_fam_setup(conn, &sz_copy);
	else {
		zhpe_conn_flags_set(conn, ZHPE_CONN_FLAG_CONNECT);
		conn_connect1_tx(conn, sz_copy.sz_uuid);
	}

	return conn;
}

static int compare_conn_tkeys(struct ofi_rbmap *map, void *vkey,
			      void *vconn)
{
	int			ret;
	struct zhpe_conn_tree_key *k1 = vkey;
	struct zhpe_conn_tree_key *k2 = &((struct zhpe_conn *)vconn)->tkey;

	ret = arithcmp(k1->rem_gcid, k2->rem_gcid);
	if (ret)
		goto done;
	ret = arithcmp(k1->rem_rspctxid0, k2->rem_rspctxid0);
	if (ret)
		goto done;
	ret = arithcmp(k1->rem_ctx_idx, k2->rem_ctx_idx);

 done:
	return ret;
}

int zhpe_conn_init(struct zhpe_ctx *zctx)
{
	int			ret = -FI_ENOMEM;

	ofi_rbmap_init(&zctx->conn_tree, compare_conn_tkeys);

	ret = zhpe_ibufpool_create(&zctx->conn_pool, "conn_pool",
				   sizeof(struct zhpe_conn),
				   zhpeu_init_time->l1sz, 0, 0,
				   OFI_BUFPOOL_NO_TRACK, NULL, NULL);
	if (ret < 0)
		goto done;
	zctx->conn0 = zhpe_conn_alloc(zctx);
	assert_always(zctx->conn_pool.max_index == 1);
	zctx->conn0->rx_msg_handler = zhpe_rx_msg_handler_unconnected;
	ret = 0;

 done:
	return ret;
}

void zhpe_conn_fini(struct zhpe_ctx *zctx)
{
	if (zctx->conn_tree.root)
		ofi_rbmap_cleanup(&zctx->conn_tree);
	zctx->conn_tree.root = NULL;
	ofi_idm_reset(&zctx->conn_av_idm);
	if (zctx->conn0) {
		zhpe_ibuf_free(&zctx->conn_pool, zctx->conn0);
		zctx->conn0 = NULL;
	}
	zhpe_ibufpool_destroy(&zctx->conn_pool);
}

void zhpe_conn_cleanup(struct zhpe_ctx *zctx)
{
	struct zhpe_dom		*zdom = zctx2zdom(zctx);
	struct zhpe_conn	*conn;
	size_t			i;

	for (i = zctx->conn_pool.max_index; i > 1;) {
		i--;
		conn = zhpe_ibuf_get(&zctx->conn_pool, i);
		if (!conn)
			continue;
		assert_always(conn->zctx);
		zhpeq_qkdata_free(conn->qkdata);
		conn->qkdata = NULL;
		zhpeq_domain_remove_addr(zdom->zqdom, conn->addr_cookie);
		zhpe_ibuf_free(&zctx->conn_pool, conn);
	}
	zctx->conn_pool.max_index = i;
}

int zhpe_conn_eflags_error(uint8_t eflags)
{
	if (eflags & ~ZHPE_CONN_EFLAG_SHUTDOWN3)
		return -FI_EIO;

	return -FI_ESHUTDOWN;
}

