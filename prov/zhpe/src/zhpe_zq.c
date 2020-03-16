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

#define ZHPE_SUBSYS	FI_LOG_EP_CTRL

#define	CHUNK_SIZE_OFF		offsetof(struct zhpe_slab_free_entry, size)
#define	CHUNK_DATA_OFF		offsetof(struct zhpe_slab_free_entry, dentry)
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
				free, dentry)
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
				free, dentry) {
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
		   struct zhpe_dom *zdom)
{
	int			ret = -FI_ENOMEM;
	struct zhpe_slab_free_entry *chunk;

	/* Align to pointer size boundary; assumed to be power of 2
	 * and greater than 2; so bit 0 will always be zero.
	 */
	size = (size + ~CHUNK_SIZE_MASK) & CHUNK_SIZE_MASK;
	slab->size = size;
	dlist_init(&slab->free_list);
	slab->mem = _malloc_aligned(page_size, size);
	if (!slab->mem)
		goto done;
	ret = 0;
	if (size < CHUNK_SIZE_MIN + 2 * CHUNK_SIZE_SIZE)
		goto done;
	size -= 2 * CHUNK_SIZE_SIZE;
	chunk = (void *)((char *)slab->mem - CHUNK_SIZE_OFF);
	chunk->size = (size | CHUNK_SIZE_PINUSE);
	dlist_insert_tail(&chunk->dentry, &slab->free_list);
	chunk = _next_chunk(chunk);
	chunk->size = 0;

	ret = zhpe_dom_mr_reg(zdom, slab->mem, slab->size, true,
			      ZHPEQ_MR_PUT | ZHPEQ_MR_GET_REMOTE, &slab->zmr);
	if (ret < 0) {
		ZHPE_LOG_ERROR("zhpe_mr_reg() error %d\n", ret);
		goto done;
	}

 done:
	return ret;
}

void zhpe_slab_destroy(struct zhpe_slab *slab)
{
	if (slab->mem) {
		slab_check(slab);
		zhpe_dom_mr_put(slab->zmr);
		slab->zmr = NULL;
		free(slab->mem);
		slab->mem = NULL;
	}
}

int zhpe_slab_alloc(struct zhpe_slab *slab, size_t size, struct iovec *iov)
{
	int			ret = -ENOMEM;
	struct zhpe_slab_free_entry *chunk;
	struct zhpe_slab_free_entry *next;

	if (!slab->mem)
		goto done;

	iov->iov_len = size;
	size = (size + ~CHUNK_SIZE_MASK) & CHUNK_SIZE_MASK;
	if (size < CHUNK_SIZE_MIN)
		size = CHUNK_SIZE_MIN;
	/* Just first fit because it is fast and entries are transient.
	 * Every free entry should have the PINUSE bit set because,
	 * otherwise, it would be merged with another block.
	 */
	dlist_foreach_container(&slab->free_list, struct zhpe_slab_free_entry,
				chunk, dentry) {
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
		dlist_remove(&chunk->dentry);
		iov->iov_base = ((char *)chunk + CHUNK_DATA_OFF);
	} else {
		chunk->size -= size + CHUNK_SIZE_SIZE;
		next = _next_chunk(chunk);
		next->prev_size = (chunk->size & CHUNK_SIZE_MASK);
		next->size = size;
		iov->iov_base = ((char *)next + CHUNK_DATA_OFF);
		chunk = next;
	}
	next = _next_chunk(chunk);
	next->size |= CHUNK_SIZE_PINUSE;
	slab_check(slab);
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
		dlist_insert_head(&chunk->dentry, &slab->free_list);
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
	dlist_remove(&next->dentry);
 done:
	return;
}

static void iov_rma_puti(union zhpe_hw_wq_entry *wqe,
			 void *lptr, uint64_t len, uint64_t rza)
{
	memcpy(zhpeq_tq_puti(wqe, 0, len, rza), lptr, len);
}

static void iov_rma_get(union zhpe_hw_wq_entry *wqe,
			void *lptr, uint64_t len, uint64_t rza)
{
	zhpeq_tq_get(wqe, 0, (uintptr_t)lptr, len, rza);
}

static void iov_rma_put(union zhpe_hw_wq_entry *wqe,
			void *lptr, uint64_t len, uint64_t rza)
{
	zhpeq_tq_put(wqe, 0, (uintptr_t)lptr, len, rza);
}

void zhpe_iov_rma(struct zhpe_tx_entry *tx_entry,
		  uint64_t max_seg_bytes, uint32_t max_seg_ops)
{
	struct zhpe_conn	*conn = tx_entry->conn;
	struct zhpe_ctx		*zctx = conn->zctx;
	struct zhpe_iov_state	*lstate = tx_entry->ptrs[0];
	struct zhpe_iov_state	*rstate = tx_entry->ptrs[1];
	uint32_t		ops;
	union zhpe_hw_wq_entry	*wqe;
	int32_t			reservation;
	struct zhpeq_tq		*ztq;
	uint64_t		len;
	uint64_t		llen;
	uint64_t		rlen;
	uint64_t		rza;
	void			*lptr;
	void			(*op)(union zhpe_hw_wq_entry *wqe,
				      void *lptr, uint64_t len, uint64_t rza);
	void			(*opi)(union zhpe_hw_wq_entry *wqe,
				       void *lptr, uint64_t len, uint64_t rza);
	uint32_t		i;
	struct zhpe_tx_queue_entry *txqe;

	assert(!tx_entry->cstat.completions);
	if (tx_entry->rma_get) {
		op = iov_rma_get;
		/* Get immediate too much trouble. */
		opi = iov_rma_get;
	} else {
		op = iov_rma_put;
		opi = iov_rma_puti;
	}

	for (i = 0; i < zhpeq_attr.z.num_slices; i++) {
		ztq = zctx->ztq_lo[zctx->tx_ztq_rotor++];
		if (OFI_UNLIKELY(zctx->tx_ztq_rotor >= zhpeq_attr.z.num_slices))
			zctx->tx_ztq_rotor = 0;

		for (ops = 0; ops < max_seg_ops; ops++) {
			llen = zhpe_iov_state_len(lstate);
			rlen = zhpe_iov_state_len(rstate);
			len = max_seg_bytes;
			len = min(len, llen);
			len = min(len, rlen);
			if (!len) {
				zhpeq_tq_commit(ztq);
				tx_entry->cstat.flags |= ZHPE_CS_FLAG_RMA_DONE;
				return;
			}

			reservation = zhpeq_tq_reserve(ztq);
			if (OFI_UNLIKELY(reservation < 0)) {
				assert_always(reservation == -EAGAIN);
				break;
			}
			conn->tx_queued++;
			zctx->tx_queued++;
			wqe = zhpeq_tq_get_wqe(ztq, reservation);
			zhpeq_tq_set_context(ztq, reservation, tx_entry);

			lptr = zhpe_iov_state_ptr(lstate);
			rza = zhpe_iov_state_addr(rstate);

			/* Optimize short transfers; matters less if big. */
			if (OFI_LIKELY(len <= ZHPEQ_MAX_IMM))
				opi(wqe, lptr, len, rza);
			else
				op(wqe, lptr, len, rza);
			zhpeq_tq_insert(ztq, reservation);

			zhpe_iov_state_adv(lstate, len);
			zhpe_iov_state_adv(rstate, len);
			tx_entry->cstat.completions++;
		}

		zhpeq_tq_commit(ztq);
	}

	/* Progress made? */
	if (OFI_UNLIKELY(!tx_entry->cstat.completions)) {
		/* No: queue for retry? */
		if (!(tx_entry->cstat.flags & ZHPE_CS_FLAG_QUEUED)) {
			/* Yes, queue for retry. */
			tx_entry->cstat.flags |= ZHPE_CS_FLAG_QUEUED;
			zctx->tx_queued++;
			txqe = zhpe_buf_alloc(&zctx->tx_queue_pool);
			txqe->tx_entry = tx_entry;
			/* Insert in front of any fenced I/Os. */
			dlist_insert_head(&txqe->dentry, &conn->tx_queue);
		}
	}
}

static uint64_t zhpe_iov_addr(const struct zhpe_iov_state *state)
{
	struct iovec		*iov = state->viov;

	return (uintptr_t)VPTR(iov[state->idx].iov_base, state->off);
}

static uint64_t zhpe_ziov3_addr(const struct zhpe_iov_state *state)
{
	struct zhpe_iov3	*iov = state->viov;

	return (uintptr_t)VPTR(iov[state->idx].iov_base, state->off);
}

static uint64_t zhpe_iov_len(const struct zhpe_iov_state *state)
{
	struct iovec		*iov = state->viov;

	return (iov[state->idx].iov_len - state->off);
}

static uint64_t zhpe_ziov3_len(const struct zhpe_iov_state *state)
{
	struct zhpe_iov3	*iov = state->viov;

	return (iov[state->idx].iov_len - state->off);
}

static uint64_t zhpe_iov_avail(const struct zhpe_iov_state *state)
{
	uint64_t		ret;
	struct iovec		*iov = state->viov;
	size_t			i;

	ret = iov[state->idx].iov_len - state->off;
	for (i = state->idx + 1; i < state->cnt; i++)
		ret += iov[i].iov_len;

	return ret;
}

static uint64_t zhpe_ziov3_avail(const struct zhpe_iov_state *state)
{
	uint64_t		ret;
	struct zhpe_iov3	*iov = state->viov;
	size_t			i;

	ret = iov[state->idx].iov_len - state->off;
	for (i = state->idx + 1; i < state->cnt; i++)
		ret += iov[i].iov_len;

	return ret;
}

struct zhpe_iov_state_ops zhpe_iov_state_iovec_ops = {
	.iov_addr		= zhpe_iov_addr,
	.iov_len		= zhpe_iov_len,
	.avail			= zhpe_iov_avail,
};

struct zhpe_iov_state_ops zhpe_iov_state_ziov3_ops = {
	.iov_addr		= zhpe_ziov3_addr,
	.iov_len		= zhpe_ziov3_len,
	.avail			= zhpe_ziov3_avail,
};

bool zhpe_iov_state_adv(struct zhpe_iov_state *state, uint64_t incr)
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

uint64_t zhpe_copy_iov(struct zhpe_iov_state *dstate,
		       struct zhpe_iov_state *sstate)
{
	uint64_t		ret = 0;
	uint64_t		len;
	uint64_t		slen;
	uint64_t		dlen;
	char			*sptr;
	char			*dptr;

	for (;;) {
		slen = zhpe_iov_state_len(sstate);
		dlen = zhpe_iov_state_len(dstate);
		len = slen;
		len = min(len, dlen);
		if (!len)
			break;

		sptr = zhpe_iov_state_ptr(sstate);
		dptr = zhpe_iov_state_ptr(dstate);
		memcpy(dptr, sptr, len);

		ret += len;
		zhpe_iov_state_adv(sstate, len);
		zhpe_iov_state_adv(dstate, len);
	}

	return ret;
}

uint64_t zhpe_copy_iov_to_mem(void *dst, uint64_t dst_len,
			      struct zhpe_iov_state *sstate)
{
	struct iovec		diov = {
		.iov_base	= dst,
		.iov_len	= dst_len,
	};
	struct zhpe_iov_state	dstate = {
		.ops		= &zhpe_iov_state_iovec_ops,
		.viov		= &diov,
		.cnt		= 1,
	};

	return zhpe_copy_iov(&dstate, sstate);
}

uint64_t zhpe_copy_mem_to_iov(struct zhpe_iov_state *dstate, const void *src,
			    uint64_t src_len)
{
	struct iovec		siov = {
		.iov_base	= (void *)src,
		.iov_len	= src_len,
	};
	struct zhpe_iov_state	sstate = {
		.ops		= &zhpe_iov_state_iovec_ops,
		.viov		= &siov,
		.cnt		= 1,
	};

	return zhpe_copy_iov(dstate, &sstate);
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
		family = zhpeu_sockaddr_family(addr);
		if (family == AF_INET || family == AF_INET6)
			addr_format = FI_SOCKADDR;
		else if (family == AF_ZHPE)
			addr_format = FI_ADDR_ZHPE;
		else
			goto done;
	}
	if (addr_format != FI_ADDR_ZHPE) {
		ret = (char *)ofi_straddr(buf, len, addr_format, addr);
		goto done;
	}
	/* A zhpe address. */
	s = zhpeu_sockaddr_str(addr);
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

static int
do_ofi_bufpool_create(struct ofi_bufpool **pool, const char *name,
		      size_t size, size_t alignment,
		      size_t max_cnt, size_t chunk_cnt, int flags,
		      void (*init_fn)(struct ofi_bufpool_region *region,
				      void *buf),
		      void *context)
{
	int			ret;
	struct ofi_bufpool_attr attr = {
		.size		= size,
		.alignment 	= (alignment ?: 16),
		.max_cnt	= max_cnt,
		.chunk_cnt	= (chunk_cnt ?: 32),
		.flags		= flags,
		.init_fn	= init_fn,
		.context	= context,
	};

	ret = ofi_bufpool_create_attr(&attr, pool);
	if (ret < 0) {
		*pool = NULL;
		ZHPE_LOG_ERROR("ofi_bufpool_create(%s) error %d\n", name, ret);
	}

	return ret;
}

int zhpe_bufpool_create(struct zhpe_bufpool *zpool, const char *name,
			size_t size, size_t alignment,
			size_t max_cnt, size_t chunk_cnt, int flags,
			void (*init_fn)(struct ofi_bufpool_region *region,
					void *buf),
			void *context)
{
	assert(!(flags & OFI_BUFPOOL_INDEXED));

	zpool->name = name;

	return do_ofi_bufpool_create(&zpool->pool, name, size, alignment,
				     max_cnt, chunk_cnt, flags, init_fn,
				     context);
}

int zhpe_ibufpool_create(struct zhpe_ibufpool *zpool, const char *name,
			 size_t size, size_t alignment,
			 size_t max_cnt, size_t chunk_cnt, int flags,
			 void (*init_fn)(struct ofi_bufpool_region *region,
					 void *buf),
			 void *context)
{
	assert(!(flags & OFI_BUFPOOL_INDEXED));

	zpool->name = name;
	flags |= OFI_BUFPOOL_INDEXED;

	return do_ofi_bufpool_create(&zpool->pool, name, size, alignment,
				     max_cnt, chunk_cnt, flags, init_fn,
				     context);
}

void zhpe_bufpool_destroy(struct zhpe_bufpool *zpool)
{
	if (zpool->pool)
		ofi_bufpool_destroy(zpool->pool);
	zpool->pool = NULL;
}

void zhpe_ibufpool_destroy(struct zhpe_ibufpool *zpool)
{
	if (zpool->pool)
		ofi_bufpool_destroy(zpool->pool);
	zpool->pool = NULL;
}

void *zhpe_buf_alloc(struct zhpe_bufpool *zpool)
{
	void			*ret = ofi_buf_alloc(zpool->pool);

	assert_always(ret);

	return ret;
}

void *zhpe_ibuf_alloc(struct zhpe_ibufpool *zpool)
{
	void			*ret = ofi_ibuf_alloc(zpool->pool);
	size_t			index;

	assert_always(ret);
	index = ofi_buf_index(ret);
	if (OFI_LIKELY(index >= zpool->max_index))
		zpool->max_index = index + 1;

	return ret;
}

void zhpe_buf_free(struct zhpe_bufpool *zpool, void *buf)
{
	if (OFI_LIKELY(buf != NULL))
		ofi_buf_free(buf);
}

void zhpe_ibuf_free(struct zhpe_ibufpool *zpool, void *buf)
{
	if (OFI_LIKELY(buf != NULL))
		ofi_ibuf_free(buf);
}

#ifdef ENABLE_DEBUG

static void zmr_print(struct zhpe_mr *zmr, bool indent)
{
	const char		*istr = (indent ? "    " : "");

	fprintf(stderr, "%szmr  %p key 0x%" PRIx64 " ref %d closed %d\n",
		istr, zmr, zmr->mr_fid.key, ofi_atomic_get32(&zmr->ref),
		zmr->closed);
}


static void kexp_print(struct zhpe_kexp *kexp, bool indent)
{
	const char		*istr = (indent ? "    " : "");

	fprintf(stderr, "%skexp %p key 0x%" PRIx64 " conn %p\n",
		istr, kexp, kexp->tkey.key, kexp->conn);
}

static void rkey_dump_walk(struct ofi_rbmap *tree, void *arg,
			   struct ofi_rbnode *rbnode)
{
	struct zhpe_rkey	*rkey = rbnode->data;

	fprintf(stderr, "rkey %p key 0x%" PRIx64 " ref %d\n",
		rkey, rkey->tkey.key, rkey->ref);
}

static void kexp_dump_walk(struct ofi_rbmap *tree, void *arg,
			   struct ofi_rbnode *rbnode)
{
	struct zhpe_kexp	*kexp = rbnode->data;

	kexp_print(kexp, false);
	zmr_print(kexp->zmr, true);
}

void zhpe_zmr_dump(struct zhpe_dom *zdom)
{
	struct zhpe_mr		*zmr;
	struct zhpe_kexp	*kexp;

	dlist_foreach_container(&zdom->zmr_list, struct zhpe_mr, zmr, dentry) {
		zmr_print(zmr, false);
		dlist_foreach_container(&zmr->kexp_list, struct zhpe_kexp,
					kexp, dentry)
			kexp_print(kexp, true);
	}
}

void zhpe_rkey_dump(struct zhpe_ctx *zctx)
{
	ofi_rbmap_walk(&zctx->rkey_tree, NULL, rkey_dump_walk);
}

void zhpe_kexp_dump(struct zhpe_dom *zdom)
{
	ofi_rbmap_walk(&zdom->kexp_tree, NULL, kexp_dump_walk);
}

int gdb_hook_noabort;

void gdb_hook(void)
{
	if (!gdb_hook_noabort)
		abort();
}

#endif
