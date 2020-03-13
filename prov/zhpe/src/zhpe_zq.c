/*
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

#define ZHPE_LOG_DBG(...) _ZHPE_LOG_DBG(FI_LOG_EP_CTRL, __VA_ARGS__)
#define ZHPE_LOG_INFO(...) _ZHPE_LOG_INFO(FI_LOG_EP_CTRL, __VA_ARGS__)
#define ZHPE_LOG_ERROR(...) _ZHPE_LOG_ERROR(FI_LOG_EP_CTRL, __VA_ARGS__)

struct mem_wire_msg1 {
	uint32_t		rx_ring_size;
};

struct mem_wire_msg2 {
	uint64_t		key;
};

void zhpe_tx_free(struct zhpe_tx *ztx)
{
	struct zhpe_pe_retry	*pe_retry;
	struct zhpeu_atm_snatch_head atm_list;
	struct zhpeu_atm_list_next *atm_cur;
	struct zhpeu_atm_list_next *atm_next;

	if (!ztx)
		return;

	zhpeu_atm_snatch_list(&ztx->pe_retry_list, &atm_list);
	for (atm_cur = atm_list.head; atm_cur; atm_cur = atm_next) {
		pe_retry = container_of(atm_cur, struct zhpe_pe_retry, next);
		atm_next = atm_load_rlx(&atm_cur->next);
		if (atm_next == ZHPEU_ATM_LIST_END) {
			atm_next = NULL;
			break;
		}
		zhpe_pe_retry_free(ztx, pe_retry);
	}
	while ((atm_cur = zhpeu_atm_fifo_pop(&ztx->pe_retry_free_list))) {
		pe_retry = container_of(atm_cur, struct zhpe_pe_retry, next);
		free(pe_retry);
	}

	zhpe_mr_put(ztx->zmr);
	zhpeq_free(ztx->zq);
	free(ztx->pentries);
	free(ztx->zentries);
	ztx->zentries = NULL;
	mutex_destroy(&ztx->mutex);
	free(ztx);
}

static int do_tx_setup(struct zhpe_ep_attr *ep_attr, struct zhpe_tx **ztx_out)
{
	int			ret = -FI_ENOMEM;
	struct zhpe_tx		*ztx = NULL;
	uint32_t		qlen;
	uint32_t		i;
	size_t			req;
	struct fid_mr		*mr;
	struct zhpe_free_index	ufree;
	struct zhpe_free_index	pfree;

	ztx = calloc_cachealigned(1, sizeof(*ztx));
	if (!ztx)
		goto done;
	dlist_init(&ztx->pe_lentry);
	ztx->ep_attr = ep_attr;
	qlen = roundup_power_of_two(ep_attr->ep->tx_attr.size) * 2;
	ztx->mask = qlen - 1;
	ztx->use_count = 1;
	zhpeu_atm_fifo_init(&ztx->pe_retry_free_list);
	mutex_init(&ztx->mutex, NULL);

	/* Allocate memory */
	req = sizeof(*ztx->pentries) * qlen;
	ret = -posix_memalign((void **)&ztx->pentries,
			      ofi_sysconf(_SC_PAGESIZE), req);
	if (ret < 0) {
		ztx->pentries = NULL;
		goto done;
	}
	memset(ztx->pentries, 0, req);
	/* user free list */
	ufree.seq = 0;
	ufree.index = 0;
	ufree.count = qlen / 2;
	/* status/index in last entry doesn't matter, since it will
	 * never be checked because xfree.count will be zero.
	 */
	for (i = 0; i < qlen / 2  - 1; i++)
		ztx->pentries[i].pe_root.compstat.status = i + 1;
	atm_store_rlx(&ztx->ufree, ufree);
	/* provider free list */
	pfree.seq = 0;
	pfree.index = ++i;
	pfree.count = qlen / 2;
	for (; i < qlen - 1; i++)
		ztx->pentries[i].pe_root.compstat.status = i + 1;
	atm_store_rlx(&ztx->pfree, pfree);

	req = ZHPE_RING_ENTRY_LEN * qlen;
	ret = -posix_memalign((void **)&ztx->zentries,
			      ofi_sysconf(_SC_PAGESIZE), req);
	if (ret < 0) {
		ztx->zentries = NULL;
		goto done;
	}

	/* Allocate queue from bridge. */
	ret = zhpeq_alloc(ep_attr->domain->zqdom, qlen, qlen,
			  0, 0, 0, &ztx->zq);
	if (ret < 0)  {
		ZHPE_LOG_ERROR("zhpeq_alloc() error %d\n", ret);
		goto done;
	}
	memset(ztx->zentries, 0, req);

	/* Register zentries memory. */
	ret = zhpe_mr_reg_int_uncached(ep_attr->domain, ztx->zentries, req,
				       FI_WRITE, 0, &mr);
	if (ret < 0) {
		ZHPE_LOG_ERROR("zhpe_mr_reg_int_uncached() error %d\n", ret);
		goto done;
	}
	ztx->zmr = container_of(mr, struct zhpe_mr, mr_fid);
	ret = zhpeq_lcl_key_access(ztx->zmr->kdata, ztx->zentries,
				   0, 0, &ztx->lz_zentries);
	if (ret < 0) {
		ZHPE_LOG_ERROR("zhpeq_lcl_key_access() error %d\n", ret);
		goto done;
	}

 done:
	if (ret < 0) {
		zhpe_tx_put(ztx);
		ztx = NULL;
	}
	atm_store_rlx(ztx_out, ztx);

	return ret;
}

static inline void *scoreboard_alloc(struct zhpe_rx_common *rx_cmn)
{
	const size_t		size = sizeof(*rx_cmn->scoreboard);
	const uint32_t		bits = size * CHAR_BIT;

	rx_cmn->scoreboard = calloc((rx_cmn->mask + bits) / bits, size);

	return rx_cmn->scoreboard;
}

static void zhpe_tx_handle_conn_pull(struct zhpe_pe_root *pe_root,
				     struct zhpeq_cq_entry *zq_cqe)
{
	struct zhpe_conn	*conn = pe_root->conn;
	struct zhpe_rx_peer_visible *peer = (void *)&zq_cqe->z.result;

	if (zq_cqe->z.status == ZHPEQ_CQ_STATUS_SUCCESS)
		atm_store_rlx(&conn->rx_remote.tail.shadow_head,
			      ntohl(atm_load_rlx(&peer->completed)));
	else
		ZHPE_LOG_ERROR("status : %d\n", zq_cqe->z.status);
	atm_dec(&conn->rx_remote.pull_busy);
}

static void do_rx_free(struct zhpe_conn *conn)
{
	zhpe_rkey_put(conn->rx_remote.cmn.rkey);
	conn->rx_remote.cmn.rkey = NULL;
	zhpe_mr_put(conn->rx_local.cmn.zmr);
	conn->rx_local.cmn.zmr = NULL;
	free(conn->rx_local.zentries);
	conn->rx_local.zentries = NULL;
	free(conn->rx_local.cmn.scoreboard);
	conn->rx_local.cmn.scoreboard = NULL;
	free(conn->rx_remote.cmn.scoreboard);
	conn->rx_remote.cmn.scoreboard = NULL;
}

static int do_rx_setup(struct zhpe_conn *conn, int conn_fd)
{
	int			ret;
	struct zhpe_ep_attr	*ep_attr = conn->ep_attr;
	struct zhpe_ep		*ep = conn->ep_attr->ep;
	struct zhpe_rx_local	*rx_ringl = &conn->rx_local;
	struct zhpe_rx_remote	*rx_ringr = &conn->rx_remote;
	char			blob[ZHPEQ_KEY_BLOB_MAX];
	struct zhpe_msg_hdr	ohdr = { .op_type = 0 };
	struct mem_wire_msg1	mem_msg1;
	struct mem_wire_msg2	mem_msg2;
	size_t			blob_len;
	uint32_t		qlenl;
	uint32_t		qlenr;
	struct fid_mr		*mr;
	size_t			off;
	size_t			req;

	memset(rx_ringl, 0, sizeof(*rx_ringl));
	memset(rx_ringr, 0, sizeof(*rx_ringr));
	rx_ringr->pull_pe_root.handler = zhpe_tx_handle_conn_pull;
	rx_ringr->pull_pe_root.conn = conn;

	/* rx ring will be the same as the tx size. */
	qlenr = roundup_power_of_two(ep->tx_attr.size) * 2;
	mem_msg1.rx_ring_size = htonl(qlenr);
	if (conn_fd != -1) {
		ret = zhpe_send_blob(conn_fd, &mem_msg1, sizeof(mem_msg1));
		if (ret < 0)
			goto done;
		ret = zhpe_recv_fixed_blob(conn_fd, &mem_msg1,
					   sizeof(mem_msg1));
		if (ret < 0)
			goto done;
	}
	qlenl = ntohl(mem_msg1.rx_ring_size);

	rx_ringl->cmn.mask = qlenl - 1;
	rx_ringr->cmn.mask = qlenr - 1;

	ret = -FI_ENOMEM;

	/* Allocate local rx ring memory. */
	if (!scoreboard_alloc(&rx_ringl->cmn))
		goto done;

	/* +1 for peer visible cache line. */
	req = ZHPE_RING_ENTRY_LEN * (qlenl + 1);
	ret = -posix_memalign((void **)&rx_ringl->zentries,
			      ofi_sysconf(_SC_PAGESIZE), req);
	if (ret < 0) {
		rx_ringl->zentries = NULL;
		goto done;
	}
	memset(rx_ringl->zentries, 0, req);

	/* Register zentries memory. */
	ret = zhpe_mr_reg_int_uncached(ep_attr->domain, rx_ringl->zentries, req,
				       FI_REMOTE_READ | FI_REMOTE_WRITE,
				       ZHPEQ_MR_KEY_ZERO_OFF, &mr);
	if (ret < 0) {
		ZHPE_LOG_ERROR("zhpe_mr_reg_int_uncached() error %d\n", ret);
		goto done;
	}
	rx_ringl->cmn.zmr = container_of(mr, struct zhpe_mr, mr_fid);

	/* Exchange key information. */
	blob_len = sizeof(blob);
	ret = zhpeq_qkdata_export(rx_ringl->cmn.zmr->kdata, blob, &blob_len);
	if (ret < 0) {
		ZHPE_LOG_ERROR("zhpeq_qkdata_export() error %d\n", ret);
		goto done;
	}

	mem_msg2.key = htobe64(fi_mr_key(mr));
	if (conn_fd != -1) {
		ret = zhpe_send_blob(conn_fd, &mem_msg2, sizeof(mem_msg2));
		if (ret < 0)
			goto done;
		ret = zhpe_send_blob(conn_fd, blob, blob_len);
		if (ret < 0)
			goto done;
		ret = zhpe_recv_fixed_blob(conn_fd, &mem_msg2,
					   sizeof(mem_msg2));
		if (ret < 0)
			goto done;
		ret = zhpe_recv_fixed_blob(conn_fd, blob, blob_len);
		if (ret < 0)
			goto done;
	}

	ret = zhpe_conn_rkey_import(conn, ohdr, be64toh(mem_msg2.key),
				    blob, blob_len, &rx_ringr->cmn.rkey);
	if (ret < 0) {
		ZHPE_LOG_ERROR("zhpeq_conn_key_import() error %d\n", ret);
		goto done;
	}
	ret = zhpeq_rem_key_access(rx_ringr->cmn.rkey->kdata, 0, 0, 0,
				   &rx_ringr->rz_zentries);
	if (ret < 0) {
		ZHPE_LOG_ERROR("zhpeq_rem_key_access() error %d\n", ret);
		goto done;
	}
	/* Set up pushed locations. */
	off = ZHPE_RING_ENTRY_LEN * qlenl;
	rx_ringl->peer_visible = (void *)(rx_ringl->zentries + off);
	off = ZHPE_RING_ENTRY_LEN * qlenr;
	rx_ringr->rz_peer_visible = rx_ringr->rz_zentries + off;
 done:
	if (ret < 0)
		do_rx_free(conn);

	return ret;
}

int zhpe_compare_zkeys(void *vk1, void *vk2)
{
	struct zhpe_key		*k1 = (void *)vk1;
	struct zhpe_key		*k2 = (void *)vk2;

	if (k1->key < k2->key)
		return -1;
	else if (k1->key > k2->key)
		return 1;

	return memcmp(&k1->internal, &k2->internal, sizeof(k1->internal));
}

int zhpe_conn_z_setup(struct zhpe_conn *conn, int conn_fd)
{
	int			ret = 0;
	struct zhpe_ep_attr	*ep_attr = conn->ep_attr;
	union sockaddr_in46	sa;
	size_t			sa_len = sizeof(sa);

	mutex_lock(&ep_attr->conn_mutex);
	if (!ep_attr->ztx)
		ret = do_tx_setup(ep_attr, &ep_attr->ztx);
	if (ret >= 0) {
		conn->ztx = ep_attr->ztx;
		atm_inc(&ep_attr->ztx->use_count);
	}
	mutex_unlock(&ep_attr->conn_mutex);
	if (ret < 0)
		goto done;
	zhpe_pe_add_queue(ep_attr->ztx);
	/* Init remote mr tree. */
	dlist_init(&conn->rkey_deferred_list);
	ret = -FI_ENOMEM;
	conn->rkey_tree = rbtNew(zhpe_compare_zkeys);
	if (!conn->rkey_tree)
		goto done;
	conn->kexp_tree = rbtNew(zhpe_compare_zkeys);
	if (!conn->kexp_tree)
		goto done;
	/* Get address index. */
	ret = zhpeq_backend_exchange(conn->ztx->zq, conn_fd, &sa, &sa_len);
	if (ret < 0) {
		ZHPE_LOG_ERROR("%s,%u:zhpeq_backend_exchange() error %d\n",
			       __func__, __LINE__, ret);
		goto done;
	}
	ret = zhpeq_backend_open(conn->ztx->zq, &sa);
	if (ret < 0) {
		ZHPE_LOG_ERROR("%s,%u:zhpeq_backend_open() error %d\n",
			       __func__, __LINE__, ret);
		goto done;
	}
	conn->zq_index = ret;

	/* Exchange information and setup rx rings */
	ret = do_rx_setup(conn, conn_fd);
	if (ret < 0)
		goto done;
	/* FIXME: Rethink for multiple contexts. */
	conn->tx_ctx = ep_attr->tx_ctx;
	conn->rx_ctx = ep_attr->rx_ctx;
	mutex_lock(&ep_attr->conn_mutex);
	conn->state = ZHPE_CONN_STATE_READY;
	zhpeu_atm_snatch_insert(&conn->ztx->rx_poll_list,
				&conn->rx_poll_next);
	mutex_unlock(&ep_attr->conn_mutex);
	cond_broadcast(&ep_attr->conn_cond);
	ret = 0;

 done:
	return ret;
}

int zhpe_conn_fam_setup(struct zhpe_conn *conn)
{
	int			ret = 0;
	struct zhpe_ep_attr	*ep_attr = conn->ep_attr;
	size_t			n_qkdata = 0;
	struct zhpeq_key_data	*qkdata[2];
	struct zhpe_rkey_data	*new;
	size_t			i;

	mutex_lock(&ep_attr->conn_mutex);
	if (!ep_attr->ztx)
		ret = do_tx_setup(ep_attr, &ep_attr->ztx);
	if (ret >= 0) {
		conn->ztx = ep_attr->ztx;
		atm_inc(&ep_attr->ztx->use_count);
	}
	mutex_unlock(&ep_attr->conn_mutex);
	if (ret < 0)
		goto done;
	zhpe_pe_add_queue(ep_attr->ztx);
	/* Init remote mr tree. */
	dlist_init(&conn->rkey_deferred_list);
	ret = -FI_ENOMEM;
	conn->rkey_tree = rbtNew(zhpe_compare_zkeys);
	if (!conn->rkey_tree)
		goto done;

	/* Get address index. */
	ret = zhpeq_backend_open(conn->ztx->zq, &conn->addr);
	if (ret < 0) {
		ZHPE_LOG_ERROR("%s,%u:zhpeq_backend_open() error %d\n",
			       __func__, __LINE__, ret);
		goto done;
	}
	conn->zq_index = ret;

	/* Get qkdata entries for FAM.*/
	n_qkdata = ARRAY_SIZE(qkdata);
	ret = zhpeq_fam_qkdata(ep_attr->domain->zqdom, conn->zq_index,
			       qkdata, &n_qkdata);
	if (ret < 0) {
		ZHPE_LOG_ERROR("%s,%u:zhpeq_fam_qkdata() error %d\n",
			       __func__, __LINE__, ret);
		goto done;
	}
	for (i = 0; i < n_qkdata; i++) {
		new = malloc(sizeof(*new));
		if (!new) {
			ret = -FI_ENOMEM;
			goto done;
		}
		atm_inc(&conn->ztx->use_count);
		new->ztx = conn->ztx;
		new->zkey.key = i;
		new->zkey.internal = false;
		new->kdata = NULL;
		new->ohdr = (struct zhpe_msg_hdr){ 0 };
		new->use_count = 1;
		zhpe_rkey_rbtInsert(conn->rkey_tree, new);
		/* Create requester ZMMU entry for qkdata. */
		ret = zhpeq_zmmu_reg(qkdata[i]);
		if (ret < 0) {
			ZHPE_LOG_ERROR("%s,%u:zhpeq_req() error %d\n",
				       __func__, __LINE__, ret);
			goto done;
		}
		new->kdata = qkdata[i];
		qkdata[i] = NULL;
	}
	/* FIXME: Rethink for multiple contexts. */
	conn->tx_ctx = ep_attr->tx_ctx;
	conn->rx_ctx = ep_attr->rx_ctx;
	mutex_lock(&ep_attr->conn_mutex);
	conn->state = ZHPE_CONN_STATE_READY;
	mutex_unlock(&ep_attr->conn_mutex);
	cond_broadcast(&ep_attr->conn_cond);
	ret = 0;
 done:
	if (ret < 0) {
		for (i = 0; i < n_qkdata; i++)
			zhpeq_qkdata_free(qkdata[i]);
	}

	return ret;
}

void zhpe_rkey_free(struct zhpe_rkey_data *rkey)
{
	zhpeq_qkdata_free(rkey->kdata);
	zhpe_tx_put(rkey->ztx);
	free(rkey);
}

void zhpe_conn_z_free(struct zhpe_conn *conn)
{
	RbtIterator		*rbt;
	struct zhpe_rkey_data	*rkey;
	struct zhpe_kexp_data	*kexp;

	if (conn->rkey_tree) {
		/* Is lock initialized? */
		if (conn->kexp_tree) {
			/* FIXME: Think about driver disconnect. */
			mutex_lock(&conn->ztx->mutex);
			while ((rbt = rbtBegin(conn->kexp_tree)))  {
				kexp = zhpe_rbtKeyValue(conn->kexp_tree, rbt);
				rbtErase(conn->kexp_tree, rbt);
				dlist_remove(&kexp->lentry);
				free(kexp);
			}
			rbtDelete(conn->kexp_tree);
			mutex_unlock(&conn->ztx->mutex);
		}
		while (!dlist_empty(&conn->rkey_deferred_list)) {
			dlist_pop_front(&conn->rkey_deferred_list,
					struct zhpe_rkey_data, rkey, lentry);
			zhpe_rkey_free(rkey);
		}
		while ((rbt = rbtBegin(conn->rkey_tree)))  {
			rkey = zhpe_rbtKeyValue(conn->rkey_tree, rbt);
			rbtErase(conn->rkey_tree, rbt);
			zhpe_rkey_free(rkey);
		}
		rbtDelete(conn->rkey_tree);
		conn->rkey_tree = NULL;
	}
	do_rx_free(conn);
	if (conn->zq_index != FI_ADDR_NOTAVAIL)
		zhpeq_backend_close(conn->ztx->zq, conn->zq_index);
	zhpe_tx_put(conn->ztx);
}

int __zhpe_conn_pull(struct zhpe_conn *conn)
{
	int			ret = 0;
	struct zhpe_rx_remote	*rx_ringr = &conn->rx_remote;
	uint32_t		zindex;

	ret = zhpeq_reserve(conn->ztx->zq, 1);
	if (ret < 0)
		goto done;
	zindex = ret;
	ret = zhpeq_geti(conn->ztx->zq, zindex, false,
			 sizeof(struct zhpe_rx_peer_visible),
			 rx_ringr->rz_peer_visible,
			 &rx_ringr->pull_pe_root);
	if (ret < 0)
		goto done;
	ret = zhpe_zq_commit_spin(conn->ztx->zq, zindex, 1);

 done:
	if (ret < 0)
		ZHPE_LOG_ERROR("pull failed:error %d\n", ret);

	return ret;
}

int zhpe_tx_free_res(struct zhpe_conn *conn, int64_t tindex,
		     int64_t zindex, int64_t rindex, uint8_t pe_flags)
{
	int			ret = 0;
	struct zhpe_tx		*ztx = conn->ztx;

	if (!conn)
		goto done;

	/* We assume ordered allocation: zq then rx ring; tx_buf can
	 * be freed without problems. index < 0 indicates item was
	 * not allocated.
	 */
	if (tindex >= 0)
		zhpe_tx_release(&ztx->pentries[tindex]);

	if (zindex < 0)
		goto done;

	/* If no rx_ring space, send NOP to bridge. */
	if (rindex < 0) {
		ret = zhpeq_nop(ztx->zq, zindex, false,
				ZHPE_CONTEXT_IGNORE_PTR);
		if (ret < 0)
			goto done;
		goto commit;
	}

	/* Send NOP to receive ring... this shouldn't happen since
	 * we shouldn't reserve the ring slot until we have all the
	 * resources; so just abort.
	 */
	abort();

commit:
	ret = zhpe_zq_commit_spin(ztx->zq, zindex, 1);
	if (ret < 0)
		goto done;
 done:

	return ret;
}

#define	CHUNK_SIZE_OFF		offsetof(struct zhpe_slab_free_entry, size)
#define	CHUNK_DATA_OFF		offsetof(struct zhpe_slab_free_entry, lentry)
#define CHUNK_SIZE_SIZE		(CHUNK_DATA_OFF - CHUNK_SIZE_OFF)
#define CHUNK_SIZE_MIN \
	(sizeof(struct zhpe_slab_free_entry) - CHUNK_DATA_OFF)
#define CHUNK_SIZE_PINUSE	((uintptr_t)1)
#define CHUNK_SIZE_MASK		(~(sizeof(uintptr_t) - 1))

static inline void *ptr_to_chunk(void *ptr)
{
	return ((char *)ptr - CHUNK_DATA_OFF);
}

static inline size_t chunk_size(size_t csize)
{
	return (csize & CHUNK_SIZE_MASK) + CHUNK_SIZE_SIZE;
}

static inline void *_next_chunk(struct zhpe_slab_free_entry *chunk)
{
	return ((char *)chunk + chunk_size(chunk->size));
}

static inline void *_prev_chunk(struct zhpe_slab_free_entry *chunk)
{
	return ((char *)chunk - chunk_size(chunk->prev_size));
}

static inline void *prev_chunk(struct zhpe_slab_free_entry *chunk)
{
	if (chunk->size & CHUNK_SIZE_PINUSE)
		return NULL;
	return _prev_chunk(chunk);
}

#if 0

#define CHUNK_SIZE_SEEN		((uintptr_t)4)

static uint64_t			slab_check_path;
static void			*slab_check_ptr[4];
struct zhpe_slab_free_entry	slab_check_chunk[4];

static void slab_check_save_path(uint shift)
{
	if (!shift)
		slab_check_path = 0;
	else
		slab_check_path |= (1 << shift);
}

static void slab_check_save(struct zhpe_slab_free_entry *chunk, uint idx)
{
	if (idx >= ARRAY_SIZE(slab_check_ptr) ||
	    idx >= ARRAY_SIZE(slab_check_chunk))
		abort();
	if (!idx) {
		memset(slab_check_ptr, 0, sizeof(slab_check_ptr));
		memset(slab_check_chunk, 0, sizeof(slab_check_chunk));
	} else if (idx == 3) {
		/* nextnext */
		if (!(slab_check_chunk[2].size & CHUNK_SIZE_MASK))
			return;
	}
	slab_check_ptr[idx] = chunk;
	if (chunk)
		slab_check_chunk[idx] = *chunk;
}

static void slab_check(struct zhpe_slab *slab)
{
	struct zhpe_slab_free_entry *prev;
	struct zhpe_slab_free_entry *chunk;
	struct zhpe_slab_free_entry *next;
	struct zhpe_slab_free_entry *free;
	size_t			free_count;

	/* Clear seen bits in free list. */
	dlist_foreach_container(&slab->free_list, struct zhpe_slab_free_entry,
				free, lentry)
		free->size &= ~CHUNK_SIZE_SEEN;

	free_count = 0;
	prev = NULL;
	chunk = (void *)((char *)slab->mem - CHUNK_SIZE_OFF);
	for (;;) {
		/* All free chunks should have had their SEEN bit cleared. */
		next = _next_chunk(chunk);
		if (!(next->size & CHUNK_SIZE_PINUSE)) {
			if (chunk->size & CHUNK_SIZE_SEEN)
				abort();
			chunk->size |= CHUNK_SIZE_SEEN;
			free_count++;
			if (_prev_chunk(next) != chunk)
				abort();
		}
		/* Current chunk and previous agree? */
		if (prev) {
			if (!(chunk->size & CHUNK_SIZE_PINUSE) &&
			    _prev_chunk(chunk) != prev)
				abort();
		}
		/* End marker? */
		if (!(next->size & CHUNK_SIZE_MASK)) {
			/* End marker in write place? */
			if (next != (void *)((char *)slab->mem + slab->size -
					     CHUNK_DATA_OFF))
				abort();
			break;
		}
		/* Shuffle. */
		prev = chunk;
		chunk = next;
	}

	/* Check seen bits in free list. */
	dlist_foreach_container(&slab->free_list, struct zhpe_slab_free_entry,
				free, lentry) {
		if (!free_count)
			abort();
		if (!(free->size & CHUNK_SIZE_SEEN))
			abort();
		free->size &= ~CHUNK_SIZE_SEEN;
	}
}

static void slab_check_freed(struct zhpe_slab *slab,
			     struct zhpe_slab_free_entry *freed)
{
	struct zhpe_slab_free_entry *chunk;
	struct zhpe_slab_free_entry *next;

	chunk = (void *)((char *)slab->mem - CHUNK_SIZE_OFF);
	for (;;) {
		if (chunk == freed)
			break;
		next = _next_chunk(chunk);
		/* End marker? */
		if (!(next->size & CHUNK_SIZE_MASK))
			abort();
		chunk = next;
	}
}

#else

static inline void slab_check_save_path(uint shift)
{
}

static inline void slab_check_save(struct zhpe_slab_free_entry *chunk,
				   uint idx)
{
}

static inline void slab_check(struct zhpe_slab *slab)
{
}

static void slab_check_freed(struct zhpe_slab *slab,
			     struct zhpe_slab_free_entry *freed)
{
}

#endif

int zhpe_slab_init(struct zhpe_slab *slab, size_t size,
		   struct zhpe_domain *domain)
{
	int			ret = -FI_ENOMEM;
	struct zhpe_slab_free_entry *chunk;
	struct fid_mr		*fid_mr;

	/* Align to pointer size boundary; assumed to be power of 2
	 * and greater than 2; so bit 0 will always be zero.
	 */
	size = (size + ~CHUNK_SIZE_MASK) & CHUNK_SIZE_MASK;
	slab->size = size;
	dlist_init(&slab->free_list);
	slab->mem = malloc(size);
	if (!slab->mem)
		goto done;
	ret = 0;
	if (size < CHUNK_SIZE_MIN + 2 * CHUNK_SIZE_SIZE)
		goto done;
	size -= 2 * CHUNK_SIZE_SIZE;
	chunk = (void *)((char *)slab->mem - CHUNK_SIZE_OFF);
	chunk->size = (size | CHUNK_SIZE_PINUSE);
	dlist_insert_tail(&chunk->lentry, &slab->free_list);
	chunk = _next_chunk(chunk);
	chunk->size = 0;

	ret = zhpe_mr_reg_int_uncached(domain, slab->mem, slab->size,
				       FI_READ | FI_WRITE, 0, &fid_mr);
	if (ret < 0) {
		ZHPE_LOG_ERROR("zhpe_mr_reg_int_uncached() error %d\n", ret);
		goto done;
	}
	slab->zmr = fid2zmr(&fid_mr->fid);
 done:
	return ret;
}

void zhpe_slab_destroy(struct zhpe_slab *slab)
{
	if (slab->mem) {
		slab_check(slab);
		zhpe_mr_put(slab->zmr);
		slab->zmr = NULL;
		free(slab->mem);
		slab->mem = NULL;
	}
}

int zhpe_slab_alloc(struct zhpe_slab *slab, size_t size, struct zhpe_iov *ziov)
{
	int			ret = -ENOMEM;
	struct zhpe_slab_free_entry *chunk;
	struct zhpe_slab_free_entry *next;

	if (!slab->mem)
		goto done;

	ziov->iov_len = size | ZHPE_ZIOV_LEN_KEY_INT;
	size = (size + ~CHUNK_SIZE_MASK) & CHUNK_SIZE_MASK;
	if (size < CHUNK_SIZE_MIN)
		size = CHUNK_SIZE_MIN;
	/* Just first fit because it is fast and entries are transient.
	 * Every free entry should have the PINUSE bit set because,
	 * otherwise, it would be merged with another block.
	 */
	dlist_foreach_container(&slab->free_list, struct zhpe_slab_free_entry,
				chunk, lentry) {
		if (chunk->size >= size)
			goto found;
	}
	goto done;
 found:
	/* Do we have space to divide the chunk?
	 * We need space for the pointers (CHUNK_SIZE_MIN) +
	 * space for prev_size (CHUNK_SIZE_OFF).
	 */
	if (chunk->size - size <= CHUNK_SIZE_MIN + CHUNK_SIZE_SIZE + 1) {
		/* No. */
		dlist_remove(&chunk->lentry);
		ziov->iov_base = ((char *)chunk + CHUNK_DATA_OFF);
	} else {
		chunk->size -= size + CHUNK_SIZE_SIZE;
		next = _next_chunk(chunk);
		next->prev_size = (chunk->size & CHUNK_SIZE_MASK);
		next->size = size;
		ziov->iov_base = ((char *)next + CHUNK_DATA_OFF);
		chunk = next;
	}
	next = _next_chunk(chunk);
	next->size |= CHUNK_SIZE_PINUSE;
	slab_check(slab);
	ziov->iov_desc = slab->zmr;
	(void)zhpeq_lcl_key_access(slab->zmr->kdata, ziov->iov_base, size,
				   0, &ziov->iov_zaddr);
	ret = 0;
 done:
	return ret;
}

void zhpe_slab_free(struct zhpe_slab *slab, void *ptr)
{
	struct zhpe_slab_free_entry *chunk;
	struct zhpe_slab_free_entry *next;
	struct zhpe_slab_free_entry *nextnext;
	struct zhpe_slab_free_entry *prev;

	if (!ptr)
		return;
	chunk = ptr_to_chunk(ptr);
	slab_check(slab);
	slab_check_freed(slab, chunk);
	slab_check_save_path(0);
	slab_check_save(chunk, 0);
	prev = prev_chunk(chunk);
	slab_check_save(prev, 1);
	/* Combine with prev or create new free entry? */
	if (prev) {
		slab_check_save_path(1);
		prev->size += chunk_size(chunk->size);
		chunk = prev;
	} else {
		slab_check_save_path(2);
		dlist_insert_head(&chunk->lentry, &slab->free_list);
	}
	next = _next_chunk(chunk);
	slab_check_save(next, 2);
	nextnext = _next_chunk(next);
	slab_check_save(nextnext, 3);
	/* next is end of slab or in use? */
	if (!(next->size & CHUNK_SIZE_MASK) ||
	    (nextnext->size & CHUNK_SIZE_PINUSE)) {
		/* Yes: Update prev flag and size. */
		slab_check_save_path(3);
		next->prev_size = (chunk->size & CHUNK_SIZE_MASK);
		next->size &= ~CHUNK_SIZE_PINUSE;
		goto done;
	}
	/* No: combine chunk with next. */
	slab_check_save_path(3);
	chunk->size += chunk_size(next->size);
	nextnext->prev_size = (chunk->size & CHUNK_SIZE_MASK);
	dlist_remove(&next->lentry);
 done:
	return;
}

int zhpe_iov_op_get(struct zhpeq *zq, uint32_t zindex, bool fence,
		    void *lptr, uint64_t lza, size_t len, uint64_t rza,
		    void *context)
{
	return zhpeq_get(zq, zindex, fence, lza, len, rza, context);
}

int zhpe_iov_op_get_imm(struct zhpeq *zq, uint32_t zindex, bool fence,
			  void *lptr, uint64_t lza, size_t len, uint64_t rza,
			  void *context)
{
	if (len > ZHPEQ_IMM_MAX)
		abort();

	return zhpeq_geti(zq, zindex, fence, len, rza, context);
}

int zhpe_iov_op_put(struct zhpeq *zq, uint32_t zindex, bool fence,
		    void *lptr, uint64_t lza, size_t len, uint64_t rza,
		    void *context)
{
	int			ret;

	if (len <= ZHPEQ_IMM_MAX)
		ret = zhpeq_puti(zq, zindex, fence, lptr, len, rza, context);
	else
		ret = zhpeq_put(zq, zindex, fence, lza, len, rza, context);

	return ret;
}

int zhpe_iov_op(struct zhpe_pe_root *pe_root,
		struct zhpe_iov_state *lstate,
		struct zhpe_iov_state *rstate,
		size_t max_bytes, uint8_t max_ops,
		int (*op)(struct zhpeq *zq, uint32_t zindex, bool fence,
			  void *lptr, uint64_t lza, size_t len,
			  uint64_t rza, void *context),
		size_t *rem)
{
	int64_t			ret = 0;
	struct zhpeq		*zq = pe_root->conn->ztx->zq;
	int64_t			zindex = -1;
	size_t			ops = 0;
	size_t			bytes = 0;
	int			rc;
	size_t			len;
	size_t			llen;
	size_t			rlen;
	uint64_t		lza;
	uint64_t		rza;
	void			*lptr;

	while (*rem > 0 && ops < max_ops && bytes < max_bytes) {

		llen = zhpe_iov_state_len(lstate);
		rlen = zhpe_iov_state_len(rstate);
		len = *rem;
		if (len > llen)
			len = llen;
		if (len > rlen)
			len = rlen;
		if (!len)
			break;

		if (zindex < 0) {
			ret = zhpeq_reserve(zq, 1);
			if (ret < 0)
				break;
			zindex = ret;
		} else {
			ret = zhpeq_reserve_next(zq, zindex);
			if (ret < 0) {
				/*
				 * Can only be EAGAIN, suppress error and
				 * commit earlier ops.
				 */
				ret = 0;
				break;
			}
		}

		lptr = zhpe_iov_state_ptr(lstate);
		lza = zhpe_iov_state_zaddr(lstate);
		rza = zhpe_iov_state_zaddr(rstate);

		ret = op(zq, zindex + ops, false, lptr, lza, len, rza, pe_root);
		/* Bump ops for potential error handling. */
		if (ret < 0) {
			zhpeq_nop(zq, zindex + ops, false,
				  ZHPE_CONTEXT_IGNORE_PTR);
			ops++;
			break;
		}

		ops++;
		bytes += len;
		*rem -= len;
		zhpe_iov_state_adv(lstate, len);
		zhpe_iov_state_adv(rstate, len);
	}
	if (ops) {
		pe_root->compstat.completions += ops;
		rc = zhpe_zq_commit_spin(zq, zindex, ops);
		if (rc < 0 && ret >= 0)
			ret = rc;
	}

	return (ret < 0 ? ret : ops);
}

int zhpe_put_imm_to_iov(struct zhpe_pe_root *pe_root, void *lbuf,
			size_t llen, struct zhpe_iov_state *rstate,
			size_t *rem)
{
	struct zhpe_iov		liov = {
		.iov_base = lbuf,
		.iov_len = llen,
	};
	struct zhpe_iov_state	lstate = {
		.ops		= &zhpe_iov_state_ziovl_ops,
		.viov		= &liov,
		.cnt		= 1,
	};

	if (llen > ZHPEQ_IMM_MAX)
		return -FI_EINVAL;

	return zhpe_iov_op(pe_root, &lstate, rstate, llen, 1,
			   zhpe_iov_op_put, rem);
}


int zhpe_iov_to_get_imm(struct zhpe_pe_root *pe_root,
			size_t llen, struct zhpe_iov_state *rstate,
			size_t *rem)
{
	struct zhpe_iov		liov = {
		.iov_len = llen,
	};
	struct zhpe_iov_state	lstate = {
		.ops		= &zhpe_iov_state_ziovl_ops,
		.viov		= &liov,
		.cnt		= 1,
	};

	if (llen > ZHPEQ_IMM_MAX)
		return -FI_EINVAL;

	return zhpe_iov_op(pe_root, &lstate, rstate, llen, 1,
			   zhpe_iov_op_get_imm, rem);
}

void zhpe_send_status_rem(struct zhpe_conn *conn, struct zhpe_msg_hdr ohdr,
			  int32_t status, uint64_t rem)
{
	struct zhpe_msg_status	msg_status;

	msg_status.rem = htobe64(rem);
	assert((int16_t)status == status);
	msg_status.status = htons(status);
	msg_status.rem_valid = true;
	ohdr.op_type = ZHPE_OP_STATUS;

	zhpe_prov_op(conn, ohdr, ZHPE_PE_RETRY,
		     &msg_status, sizeof(msg_status));
}

void zhpe_send_status(struct zhpe_conn *conn, struct zhpe_msg_hdr ohdr,
		      int32_t status)
{
	struct zhpe_msg_status	msg_status;

	assert((int16_t)status == status);
	msg_status.status = htons(status);
	msg_status.rem_valid = false;
	ohdr.op_type = ZHPE_OP_STATUS;

	zhpe_prov_op(conn, ohdr, ZHPE_PE_RETRY,
		     &msg_status, sizeof(msg_status));
}

void zhpe_send_key_revoke(struct zhpe_conn *conn,
			  const struct zhpe_key *zkey)
{
	struct zhpe_msg_hdr	ohdr = {
		.op_type	= ZHPE_OP_KEY_REVOKE,
	};
	struct zhpe_msg_key_request key_req;

	ohdr.seq = htons(atm_inc(&conn->kexp_seq));
	key_req.zkeys[0].key = htobe64(zkey->key);
	key_req.zkeys[0].internal = zkey->internal;

	zhpe_prov_op(conn, ohdr, ZHPE_PE_RETRY,
		     &key_req, sizeof(key_req.zkeys[0]));
}

static inline struct zhpe_rkey_data *conn_rkey_get(struct zhpe_conn *conn,
						   const struct zhpe_key *zkey)
{
	struct zhpe_rkey_data	*ret;
	RbtIterator		*rbt;

	rbt = zhpe_zkey_rbtFind(conn->rkey_tree, zkey);
	if (!rbt)
		return NULL;
	ret = zhpe_rbtKeyValue(conn->rkey_tree, rbt);
	atm_inc(&ret->use_count);

	return ret;
}

struct zhpe_rkey_data *zhpe_conn_rkey_get(struct zhpe_conn *conn,
					  const struct zhpe_key *zkey)
{
	struct zhpe_rkey_data	*ret;

	ret = conn_rkey_get(conn, zkey);

	return ret;
}

int zhpe_conn_key_export(struct zhpe_conn *conn, struct zhpe_msg_hdr ohdr,
			 struct zhpe_mr *zmr)
{
	int			ret = 0;
	struct zhpe_domain	*domain = conn->ep_attr->domain;
	struct zhpe_kexp_data	*new = NULL;
	struct zhpe_msg_key_data msg_data = { .key = htobe64(zmr->mr_fid.key) };
	uint8_t			pe_flags = 0;
	size_t			blob_len;
	RbtIterator		*rbt;
	int			rc;
	uint16_t		seq;
	size_t			pay_len;

	rbt = zhpe_zkey_rbtFind(conn->kexp_tree, &zmr->zkey);

	if (ohdr.op_type == ZHPE_OP_KEY_REQUEST) {
		/* A response is always expected. */
		ohdr.op_type = ZHPE_OP_KEY_RESPONSE;
	} else if (!rbt)
		/* Only send if we have not already done so. */
		ohdr.op_type = ZHPE_OP_KEY_EXPORT;
	else
		goto done;

	blob_len = sizeof(msg_data.blob);
	ret = zhpeq_qkdata_export(zmr->kdata, msg_data.blob, &blob_len);
	if (ret < 0)
		goto done;

	seq = atm_inc(&conn->kexp_seq);
	ohdr.seq = htons(seq);
	pay_len = offsetof(struct zhpe_msg_key_data, blob) + blob_len;
	ret = zhpe_prov_op(conn, ohdr, pe_flags, &msg_data, pay_len);
	/* If zhpe_prov_op() returns -FI_EAGAIN, we don't want to create
	 * the rkey data. If KEY_EXPORT failed, we try to rewind the sequence;
	 * if that can't be done, we must force it out to fill the sequence
	 * remotely. We must also return -FI_EAGAIN to tell the caller to
	 * retry. A KEY_RESPONSE is always forced out and the error is
	 * hidden.
	 */
	if (ret == -FI_EAGAIN) {
		if (ohdr.op_type == ZHPE_OP_KEY_RESPONSE)
			ret = 0;
		else {
			seq++;
			if (atm_cmpxchg(&conn->kexp_seq, &seq, seq - 1))
				goto done;
		}
		pe_flags |= ZHPE_PE_RETRY;
		rc = zhpe_prov_op(conn, ohdr, pe_flags, &msg_data, pay_len);
		if (rc < 0)
			ret = rc;
		goto done;
	} else if (ret < 0)
		goto done;

	/* Create rkey data. This is racy, but will become less so when
	 * everything is sequenced.
	 */
	rbt = zhpe_zkey_rbtFind(conn->kexp_tree, &zmr->zkey);
	if (!rbt) {
		new = malloc(sizeof(*new));
		if (!new) {
			ret = -FI_ENOMEM;
			goto done;
		}
		new->conn = conn;
		new->zkey = zmr->zkey;
		zhpe_kexp_rbtInsert(conn->kexp_tree, new);
		fastlock_acquire(&domain->util_domain.lock);
		dlist_insert_tail(&new->lentry, &zmr->kexp_list);
		fastlock_release(&domain->util_domain.lock);
	}

 done:
	return ret;
}

static void process_rkey_revoke(struct zhpe_conn *conn,
				const struct zhpe_key *zkey)
{
	RbtIterator		*rbt;

	rbt = zhpe_zkey_rbtFind(conn->rkey_tree, zkey);
	if (rbt) {
		zhpe_rkey_put(zhpe_rbtKeyValue(conn->rkey_tree, rbt));
		rbtErase(conn->rkey_tree, rbt);
	}
}

static void process_rkey_import(struct zhpe_conn *conn,
				struct zhpe_rkey_data *new)
{
	RbtIterator		*rbt;

	rbt = zhpe_zkey_rbtFind(conn->rkey_tree, &new->zkey);
	if (rbt) {
		zhpe_rkey_put(zhpe_rbtKeyValue(conn->rkey_tree, rbt));
		rbtErase(conn->rkey_tree, rbt);
	}
	zhpe_rkey_rbtInsert(conn->rkey_tree, new);
	if (new->ohdr.op_type == ZHPE_OP_KEY_RESPONSE)
		zhpe_pe_complete_key_response(conn, new->ohdr, 0);
}

static void process_rkey_deferred(struct zhpe_conn *conn)
{
	struct zhpe_rkey_data	*new;
	struct dlist_entry      *dlist;

	while (!dlist_empty(&conn->rkey_deferred_list)) {
		dlist = conn->rkey_deferred_list.next;
		new = container_of(dlist, struct zhpe_rkey_data, lentry);
		if (new->ohdr.seq != conn->rkey_seq)
			break;
		conn->rkey_seq++;
		dlist_remove(dlist);

		switch (new->ohdr.op_type) {

		case ZHPE_OP_KEY_REVOKE:
			process_rkey_revoke(conn, &new->zkey);
			free(new);
			break;

		default:
			process_rkey_import(conn, new);
			break;
		}
	}
}

static void insert_rkey_deferred(struct zhpe_conn *conn,
				 struct zhpe_rkey_data *new)
{
	struct dlist_entry      *dlist;
	struct zhpe_rkey_data	*cur;

	dlist_foreach(&conn->rkey_deferred_list, dlist) {
		cur = container_of(dlist, struct zhpe_rkey_data,  lentry);
		if (cur->ohdr.seq > new->ohdr.seq) {
			dlist_insert_before(&new->lentry, &cur->lentry);
			return;
		}
	}
	dlist_insert_tail(&new->lentry, &conn->rkey_deferred_list);
}

int zhpe_conn_rkey_import(struct zhpe_conn *conn, struct zhpe_msg_hdr ohdr,
			   uint64_t key, const void *blob, size_t blob_len,
			   struct zhpe_rkey_data **rkey_out)
{
	int			ret = 0;
	struct zhpe_rkey_data	*new = NULL;
	struct zhpeq_key_data	*kdata = NULL;

	ret = zhpeq_qkdata_import(zhpeq_dom(conn->ztx->zq), conn->zq_index,
				  blob, blob_len, &kdata);
	if (ret < 0)
		goto done;
	ret = zhpeq_zmmu_reg(kdata);
	if (ret < 0)
		goto done;

	ohdr.seq = ntohs(ohdr.seq);
	new = malloc(sizeof(*new));
	if (!new) {
		ret = -FI_ENOMEM;
		goto done;
	}
	atm_inc(&conn->ztx->use_count);
	new->ztx = conn->ztx;
	new->zkey.key = key;
	new->zkey.internal = !!(kdata->z.access & ZHPE_MR_KEY_INT);
	new->kdata = kdata;
	new->ohdr = ohdr;
	new->use_count = 1;
	if (rkey_out) {
		new->use_count++;
		*rkey_out = new;
	}

	if (ohdr.op_type != ZHPE_OP_NONE) {
		if (ohdr.seq != conn->rkey_seq) {
			insert_rkey_deferred(conn, new);
			goto done;
		}
		conn->rkey_seq++;
	}
	process_rkey_import(conn, new);
	process_rkey_deferred(conn);

 done:
	return ret;
}

int zhpe_conn_rkey_revoke(struct zhpe_conn *conn, struct zhpe_msg_hdr ohdr,
			  const struct zhpe_key *zkey)
{
	int			ret = 0;
	struct zhpe_rkey_data	*new = NULL;

	ohdr.seq = ntohs(ohdr.seq);
	if (ohdr.seq == conn->rkey_seq) {
		conn->rkey_seq++;
		process_rkey_revoke(conn, zkey);
		process_rkey_deferred(conn);
		goto done;
	}
	/* Deferred processing. */
	new = malloc(sizeof(*new));
	if (!new) {
		ret = -FI_ENOMEM;
		goto done;
	}
	new->zkey = *zkey;
	new->ohdr = ohdr;
	insert_rkey_deferred(conn, new);
	process_rkey_deferred(conn);

 done:
	return ret;
}

static int check_read(size_t req, ssize_t res)
{
	int			ret = 0;

	if (res == -1) {
		ret = -errno;
		ZHPE_LOG_ERROR("read(): error %d\n", ret);
		goto done;
	}
	if (res != req) {
		ZHPE_LOG_ERROR("read(): read %Ld of %Lu bytes\n",
			       (llong)res, (ullong)req);
		ret = -EIO;
		goto done;
	}
 done:
	return ret;
}

static int check_write(size_t req, ssize_t res)
{
	int			ret = 0;

	if (res == -1) {
		ret = -errno;
		ZHPE_LOG_ERROR("write(): error %d\n", ret);
		goto done;
	}
	if (res != req) {
		ZHPE_LOG_ERROR("write(): wrote %Ld of %Lu bytes\n",
			       (llong)res, (ullong)req);
		ret = -EIO;
		goto done;
	}
 done:
	return ret;
}

int zhpe_send_blob(int sock_fd, const void *blob, size_t blob_len)
{
	int			ret = -FI_EINVAL;
	uint32_t		wlen = blob_len;
	size_t			req;
	ssize_t			res;

	if (!blob) {
		blob_len = 0;
		wlen = UINT32_MAX;
	} else if (blob_len >= UINT32_MAX)
		goto done;
	wlen = htonl(wlen);
	req = sizeof(wlen);
	res = ofi_write_socket(sock_fd, &wlen, req);
	ret = check_write(req, res);
	if (ret < 0)
		goto done;
	if (!blob_len)
		goto done;
	req = blob_len;
	res = ofi_write_socket(sock_fd, blob, req);
	ret = check_write(req, res);
 done:

	return ret;
}

int zhpe_recv_fixed_blob(int sock_fd, void *blob, size_t blob_len)
{
	int			ret;
	uint32_t		wlen;
	size_t			req;
	ssize_t			res;

	req = sizeof(wlen);
	res = ofi_read_socket(sock_fd, &wlen, req);
	ret = check_read(req, res);
	if (ret < 0)
		goto done;
	req = ntohl(wlen);
	if (req != blob_len) {
		ZHPE_LOG_ERROR("Expected %Lu bytes, saw %Lu\n",
			       (ullong)blob_len, (ullong)res);
		ret = -EINVAL;
		goto done;
	}
	res = ofi_read_socket(sock_fd, blob, req);
	ret = check_read(req, res);
 done:

	return ret;
}

static void *zhpe_iov_ptr(const struct zhpe_iov_state *state)
{
	struct iovec		*iov = state->viov;

	return ((char *)iov[state->idx].iov_base + state->off);
}

static void *zhpe_ziovl_ptr(const struct zhpe_iov_state *state)
{
	struct zhpe_iov		*iov = state->viov;

	return ((char *)iov[state->idx].iov_base + state->off);
}

static uint64_t zhpe_iov_len(const struct zhpe_iov_state *state)
{
	struct iovec		*iov = state->viov;

	return (iov[state->idx].iov_len - state->off);
}

static uint64_t zhpe_ziovx_len(const struct zhpe_iov_state *state)
{
	struct zhpe_iov		*iov = state->viov;

	return (iov[state->idx].iov_len - state->off);
}

static uint64_t zhpe_ziovx_zaddr(const struct zhpe_iov_state *state)
{
	struct zhpe_iov		*iov = state->viov;

	return iov[state->idx].iov_zaddr + state->off;
}

struct zhpe_iov_state_ops zhpe_iov_state_iovec_ops = {
	.iov_ptr		= zhpe_iov_ptr,
	.iov_len		= zhpe_iov_len,
};

struct zhpe_iov_state_ops zhpe_iov_state_ziovl_ops = {
	.iov_ptr		= zhpe_ziovl_ptr,
	.iov_len		= zhpe_ziovx_len,
	.iov_zaddr		= zhpe_ziovx_zaddr,
};

struct zhpe_iov_state_ops zhpe_iov_state_ziovr_ops = {
	.iov_len		= zhpe_ziovx_len,
	.iov_zaddr		= zhpe_ziovx_zaddr,
};

uint64_t zhpe_iov_state_adv(struct zhpe_iov_state *state, uint64_t incr)
{
	uint64_t		slen;

	slen = zhpe_iov_state_len(state);
	state->off += incr;
	if (state->off == slen) {
		state->idx++;
		state->off = 0;
	}

	return (state->idx >= state->cnt);
}

uint64_t zhpe_iov_state_avail(const struct zhpe_iov_state *state)
{
	uint64_t		ret;
	struct zhpe_iov		*ziov = state->viov;
	size_t			i;

	assert(state->ops != &zhpe_iov_state_iovec_ops);
	ret = zhpe_iov_state_len(state);
	for (i = state->idx + 1; i < state->cnt; i++)
		ret += zhpe_ziov_len(&ziov[i]);

	return ret;
}

size_t copy_iov(struct zhpe_iov_state *dstate, struct zhpe_iov_state *sstate,
		size_t n)
{
	size_t			ret = 0;
	size_t			len;
	size_t			slen;
	size_t			dlen;
	char			*sptr;
	char			*dptr;

	while (n > 0 &&
	       !zhpe_iov_state_empty(sstate) &&
	       !zhpe_iov_state_empty(dstate)) {
		slen = zhpe_iov_state_len(sstate);
		sptr = zhpe_iov_state_ptr(sstate);
		dlen = zhpe_iov_state_len(dstate);
		dptr = zhpe_iov_state_ptr(dstate);

		len = n;
		if (len > slen)
			len = slen;
		if (len > dlen)
			len = dlen;
		memcpy(dptr, sptr, len);

		ret += len;
		n -= len;
		zhpe_iov_state_adv(sstate, len);
		zhpe_iov_state_adv(dstate, len);
	}

	return ret;
}

size_t copy_iov_to_mem(void *dst, struct zhpe_iov_state *sstate, size_t n)
{
	struct iovec		diov = {
		.iov_base	= dst,
		.iov_len	= n,
	};
	struct zhpe_iov_state	dstate = {
		.ops		= &zhpe_iov_state_iovec_ops,
		.viov		= &diov,
		.cnt		= 1,
	};

	return copy_iov(&dstate, sstate, n);
}

size_t copy_mem_to_iov(struct zhpe_iov_state *dstate, const void *src, size_t n)
{
	struct iovec		siov = {
		.iov_base	= (void *)src,
		.iov_len	= n,
	};
	struct zhpe_iov_state	sstate = {
		.ops		= &zhpe_iov_state_iovec_ops,
		.viov		= &siov,
		.cnt		= 1,
	};

	return copy_iov(dstate, &sstate, n);
}

char *zhpe_straddr(char *buf, size_t *len,
		   uint32_t addr_format, const void *addr)
{
	char			*ret = NULL;
	char			*s;
	char			*colon;
	int			size;
	unsigned short		family;

	if (!buf || !len || !*len || !addr)
		goto done;
	buf[0] = '\0';
	if (addr_format == FI_FORMAT_UNSPEC) {
		family = sockaddr_family(addr);
		if (family == AF_INET || family == AF_INET6)
			addr_format = FI_SOCKADDR;
		else if (family != AF_ZHPE)
			goto done;
	}
	if (addr_format != FI_FORMAT_UNSPEC) {
		ret = (char *)ofi_straddr(buf, len, addr_format, addr);
		goto done;
	}
	/* A zhpe address. */
	s = sockaddr_str(addr);
	if (!s)
		goto done;
	/* Leading characters are xxx: */
	colon = strchr(s, ':');
	if (!colon)
		colon = s;
	else
		colon++;
	size = snprintf(buf, *len, "fi_addr_zhpe://%s", colon);
	free(s);
	if (size < 0) {
		size = -1;
		goto done;
	}
	/* Make sure that possibly truncated messages have a null terminator. */
	buf[*len - 1] = '\0';
	*len = size;
	ret = buf;
 done:

	return ret;
}

char *zhpe_astraddr(uint32_t addr_format, const void *addr)
{
	char			*ret;
	char			*buf = NULL;
	char			first_buf[1];
	size_t			len;

	len = sizeof(first_buf);
	ret = zhpe_straddr(first_buf, &len, addr_format, addr);
	if (!ret)
		goto done;
	buf = malloc(len);
	if (!buf)
		goto done;
	ret = (char *)zhpe_straddr(buf, &len, addr_format, addr);
	if (!ret)
		free(buf);
 done:

	return ret;
}

void zhpe_straddr_log(const char *callf, uint line, enum fi_log_level level,
		      enum fi_log_subsys subsys, const char *log_str,
		      const void *addr)
{
	char			*addr_str = NULL;

	if (!fi_log_enabled(&zhpe_prov, level, subsys))
		return;
	addr_str = zhpe_astraddr(FI_FORMAT_UNSPEC, addr);
	fi_log(&zhpe_prov, level, subsys, callf, line,
	       "%s: %s\n", log_str, (addr_str ?: ""));
	free(addr_str);
}

#if ENABLE_DEBUG

static int zmr_print(void *datap)
{
	struct zhpe_mr		*zmr = datap;

	fprintf(stderr, "zmr  %p key 0x%Lx/%d use_count %d\n",
		zmr, (ullong)zmr->zkey.key, zmr->zkey.internal, zmr->use_count);

	return 0;
}

static int rkey_print(void *datap)
{
	struct zhpe_rkey_data	*rkey = datap;

	fprintf(stderr, "rkey %p key 0x%Lx/%d use_count %d\n",
		rkey, (ullong)rkey->zkey.key, rkey->zkey.internal,
		rkey->use_count);

	return 0;
}

static int kexp_print(void *datap)
{
	struct zhpe_kexp_data	*kexp = datap;

	fprintf(stderr, "kexp %p key 0x%Lx/%d conn %p\n",
		kexp, (ullong)kexp->zkey.key, kexp->zkey.internal, kexp->conn);

	return 0;
}

static int tree_work(RbtHandle *tree, int (*work)(void *data))
{
	int			ret = 0;
	RbtIterator		rbt;

	rbt = rbtBegin(tree);
	if (!rbt)
		return 0;
	do {
		ret = work(zhpe_rbtKeyValue(tree, rbt));
		if (ret)
			break;
	} while ((rbt = rbtNext(tree, rbt)));

	return ret;
}

void zhpe_zmr_dump(struct zhpe_domain *domain)
{
	tree_work(domain->mr_tree, zmr_print);
}

void zhpe_rkey_dump(struct zhpe_conn *conn)
{
	tree_work(conn->rkey_tree, rkey_print);
}

void zhpe_kexp_dump(struct zhpe_conn *conn)
{
	tree_work(conn->kexp_tree, kexp_print);
}

int gdb_hook_noabort;

void gdb_hook(void)
{
	if (!gdb_hook_noabort)
		abort();
}

#endif
