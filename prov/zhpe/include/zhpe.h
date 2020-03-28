/*
 * Copyright (c) 2014 Intel Corporation, Inc.  All rights reserved.
 * Copyright (c) 2016 Cisco Systems, Inc. All rights reserved.
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

#ifndef _ZHPE_H_
#define _ZHPE_H_

#include "config.h"

#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include <ofi_atomic.h>
#include <ofi_iov.h>
#include <ofi_prov.h>
#include <ofi_util.h>
#include <rdma/providers/fi_log.h>

#include <zhpeq.h>
#include <zhpeq_util.h>
#include <zhpeq_util_fab_atomic.h>
#include <fi_ext_zhpe.h>

#include <zhpe_stats.h>

#define _ZHPE_LOG_DBG(subsys, ...) FI_DBG(&zhpe_prov, subsys, __VA_ARGS__)
#define _ZHPE_LOG_INFO(subsys, ...) FI_INFO(&zhpe_prov, subsys, __VA_ARGS__)
#define _ZHPE_LOG_ERROR(subsys, ...) FI_WARN(&zhpe_prov, subsys, __VA_ARGS__)

#define ZHPE_LOG_DBG(...)	_ZHPE_LOG_DBG(ZHPE_SUBSYS, __VA_ARGS__)
#define ZHPE_LOG_INFO(...)	_ZHPE_LOG_INFO(ZHPE_SUBSYS, __VA_ARGS__)
#define ZHPE_LOG_ERROR(...)	_ZHPE_LOG_ERROR(ZHPE_SUBSYS, __VA_ARGS__)

void zhpe_straddr_log(const char *func, uint line, enum fi_log_level level,
		      enum fi_log_subsys subsys, const char *str,
		      const void *addr);

char *zhpe_straddr(char *buf, size_t *len,
		   uint32_t addr_format, const void *addr);

char *zhpe_astraddr(uint32_t addr_format, const void *addr);

#define _zhpe_straddr_log(...)					\
	zhpe_straddr_log(__func__, __LINE__, __VA_ARGS__)

#ifdef ENABLE_DEBUG
#define _zhpe_straddr_dbg(...)					\
	_zhpe_straddr_log(FI_LOG_DEBUG, __VA_ARGS__)
void gdb_hook(void);
#else
#define zhpe_straddr_log_dbg(_subsys, ...)
#endif

extern int			zhpe_av_def_sz;
extern int			zhpe_cq_def_sz;
extern int			zhpe_eq_def_sz;
extern int			zhpe_ep_rx_poll_timeout;
extern size_t			zhpe_ep_max_eager_sz;
extern int			zhpe_mr_cache_enable;

extern struct zhpeq_attr	zhpeq_attr;
extern struct fi_fabric_attr	zhpe_fabric_attr;
extern struct fi_domain_attr	zhpe_domain_attr;
extern struct fi_info		zhpe_info_msg;
extern struct fi_info		zhpe_info_rdm;
extern struct fi_provider	zhpe_prov;
extern struct util_prov		zhpe_util_prov;

extern struct fi_ops_msg	zhpe_ep_msg_ops;
extern struct fi_ops_msg	zhpe_ep_msg_f_ops;
extern struct fi_ops_msg	zhpe_ep_msg_d_ops;
extern struct fi_ops_msg	zhpe_ep_msg_df_ops;
extern struct fi_ops_msg	zhpe_ep_msg_c_ops;
extern struct fi_ops_msg	zhpe_ep_msg_cf_ops;
extern struct fi_ops_msg	zhpe_ep_msg_cd_ops;
extern struct fi_ops_msg	zhpe_ep_msg_cdf_ops;

extern struct fi_ops_msg	zhpe_ep_msg_tx_ops;
extern struct fi_ops_msg	zhpe_ep_msg_f_tx_ops;
extern struct fi_ops_msg	zhpe_ep_msg_c_tx_ops;
extern struct fi_ops_msg	zhpe_ep_msg_cf_tx_ops;

extern struct fi_ops_msg	zhpe_ep_msg_rx_ops;
extern struct fi_ops_msg	zhpe_ep_msg_d_rx_ops;

extern struct fi_ops_tagged	zhpe_ep_tagged_ops;
extern struct fi_ops_tagged	zhpe_ep_tagged_f_ops;
extern struct fi_ops_tagged	zhpe_ep_tagged_d_ops;
extern struct fi_ops_tagged	zhpe_ep_tagged_df_ops;
extern struct fi_ops_tagged	zhpe_ep_tagged_c_ops;
extern struct fi_ops_tagged	zhpe_ep_tagged_cf_ops;
extern struct fi_ops_tagged	zhpe_ep_tagged_cd_ops;
extern struct fi_ops_tagged	zhpe_ep_tagged_cdf_ops;

extern struct fi_ops_tagged	zhpe_ep_tagged_tx_ops;
extern struct fi_ops_tagged	zhpe_ep_tagged_f_tx_ops;
extern struct fi_ops_tagged	zhpe_ep_tagged_c_tx_ops;
extern struct fi_ops_tagged	zhpe_ep_tagged_cf_tx_ops;

extern struct fi_ops_tagged	zhpe_ep_tagged_rx_ops;
extern struct fi_ops_tagged	zhpe_ep_tagged_d_rx_ops;

extern struct fi_ops_rma	zhpe_ep_rma_ops;
extern struct fi_ops_rma	zhpe_ep_rma_f_ops;

extern struct fi_ops_atomic	zhpe_ep_atomic_ops;
extern struct fi_ops_atomic	zhpe_ep_atomic_c_ops;
extern struct fi_ops_atomic	zhpe_ep_atomic_f_ops;
extern struct fi_ops_atomic	zhpe_ep_atomic_cf_ops;

extern struct fi_ops_cm		zhpe_ep_cm_ops;

extern struct fi_ops_msg	zhpe_ep_msg_bad_ops;
extern struct fi_ops_tagged	zhpe_ep_tagged_bad_ops;
extern struct fi_ops_rma	zhpe_ep_rma_bad_ops;
extern struct fi_ops_atomic	zhpe_ep_atomic_bad_ops;
extern struct fi_ops_cm		zhpe_ep_cm_bad_ops;

static inline void *zhpe_mremap(void *old_address, size_t old_size,
				size_t new_size)
{
#ifdef __APPLE__
	return (void *) -1;
#elif defined __FreeBSD__
	return (void *) -1;
#else
	return mremap(old_address, old_size, new_size, 0);
#endif
}

#define ZHPE_AV_MAX_CTX_BITS	(8)

#define ZHPE_DOM_MR_MODE_REQUIRED					\
	(FI_MR_ALLOCATED)
#define ZHPE_DOM_MR_MODE_SUPPORTED					\
	(ZHPE_DOM_MR_MODE_REQUIRED | FI_MR_PROV_KEY |			\
	 FI_MR_VIRT_ADDR | FI_MR_LOCAL)

#define ZHPE_EP_DEF_BUFFERED	(1024U * 1024)
#define ZHPE_EP_DEF_RX_SZ	(16383U)
#define ZHPE_EP_DEF_TX_SZ	(1023U)
#define ZHPE_EP_MAX_BACKOFF	(10U)
#define ZHPE_EP_MAX_CTX		(1U << ZHPE_AV_MAX_CTX_BITS)
#define ZHPE_EP_MAX_INLINE_MSG	(64U)
#define ZHPE_EP_MAX_IOV		(2U)
#define ZHPE_EP_MODE_REQUIRED	(0)
#define ZHPE_EP_MODE_SUPPORTED						\
	(ZHPE_EP_MODE_REQUIRED | FI_CONTEXT | FI_CONTEXT2)
#define ZHPE_EP_RX_OP_FLAGS	(FI_COMPLETION)
#define ZHPE_EP_TX_OP_FLAGS						\
	(FI_INJECT | FI_INJECT_COMPLETE | FI_TRANSMIT_COMPLETE |	\
	 FI_DELIVERY_COMPLETE | FI_COMPLETION)

#define ZHPE_PROTO_VERSION	(1)

#define ZHPE_SEG_MAX_BYTES	((size_t)16 * 1024 * 1024)
#define ZHPE_SEG_MAX_OPS	(ZHPE_EP_MAX_IOV)

/* it must be adjusted if error data size in CQ/EQ
 * will be larger than ZHPE_EP_MAX_CM_DATA_SZ */
#define ZHPE_MAX_ERR_CQ_EQ_DATA_SZ ZHPE_EP_MAX_CM_DATA_SZ

struct zhpe_fabric {
	struct util_fabric	util_fabric;
};

static inline struct zhpe_fabric *fid2zfab(struct fid *fid)
{
	assert(fid->fclass == FI_CLASS_FABRIC);
	return container_of(fid, struct zhpe_fabric,
			    util_fabric.fabric_fid.fid);
}

static inline struct zhpe_fabric *ufab2zfab(struct util_fabric *fab)
{
	return container_of(fab, struct zhpe_fabric, util_fabric);
}

static inline uint32_t zfab_api_version(struct zhpe_fabric *zfab)
{
	return zfab->util_fabric.fabric_fid.api_version;
}

#define ZHPE_RING_ENTRY_LEN		((size_t)64)

struct zhpe_free_index {
	uint32_t		seq;
	uint16_t		index;
	uint16_t		count;
} INT64_ALIGNED;

struct zhpe_rx_tail {
	uint32_t		tail;
	uint32_t		shadow_head;
} INT64_ALIGNED;


/*
 * Free entry:on pointer boundary.
 * Bit 0 of size zero => prev_size valid
 */

struct zhpe_slab_limit {
	size_t			current;
	size_t			limit;
	size_t			entry_max;
};

struct zhpe_slab_free_entry {
	uintptr_t		prev_size;
	uintptr_t		size;
	struct dlist_entry	dentry;
};

struct zhpe_slab {
	void			*mem;
	uint32_t		size;
	struct dlist_entry	free_list;
	struct zhpe_mr		*zmr;
	int32_t			use_count;
};

struct zhpe_mem_tree_key {
	uint32_t		rem_gcid;
	uint32_t		rem_rspctxid;
	uint64_t		key;
};

struct zhpe_rkey {
	struct zhpe_mem_tree_key tkey;
	struct zhpe_conn	*conn;
	struct zhpeq_key_data	*qkdata;
	uint64_t		offset;
	struct dlist_entry	rkey_wait_list;
	int32_t			ref;
};

struct zhpe_rkey_wait {
	struct dlist_entry	dentry;
	void			(*handler)(void *handler_arg, int status);
	void			*handler_arg;
};

struct zhpe_kexp {
	struct zhpe_mem_tree_key tkey;
	struct zhpe_conn	*conn;
	struct zhpe_mr		*zmr;
	struct dlist_entry	dentry;
	bool			revoking;
	bool			released;
};

enum {
	ZHPE_CS_FLAG_COMPLETION		= 0x01,
	ZHPE_CS_FLAG_REMOTE_STATUS	= 0x02,
	ZHPE_CS_FLAG_FENCE		= 0x04,
	ZHPE_CS_FLAG_RMA		= 0x08,
	ZHPE_CS_FLAG_RMA_DONE		= 0x10,
	ZHPE_CS_FLAG_KEY_WAIT		= 0x20,
	ZHPE_CS_FLAG_QUEUED		= 0x40,
	ZHPE_CS_FLAG_ZERROR		= 0x80,
};

enum {
	ZHPE_OP_FLAG_TRANSMIT_COMPLETE	= 0x01,
	ZHPE_OP_FLAG_DELIVERY_COMPLETE	= 0x02,
	ZHPE_OP_FLAG_ANY_COMPLETE	= 0x03,
};

/* Need to atomically update status, completions, flags in some cases. */
struct zhpe_compstat {
	int16_t			status;
	int8_t			completions;
	uint8_t			flags;
} INT32_ALIGNED;

static inline void zhpe_cstat_init(struct zhpe_compstat *cstat,
				   int8_t completions, uint8_t flags)
{
	cstat->status = 0;
	cstat->completions = completions;
	cstat->flags = flags;
}

static inline void zhpe_cstat_update_status(struct zhpe_compstat *cstat,
					    int16_t status)
{
	if (OFI_LIKELY(status >= 0))
		return;

	if ((cstat->flags & ZHPE_CS_FLAG_ZERROR) || cstat->status < 0)
		return;

	cstat->status = status;
}

/*
 * Completion handlers done as an index into an array to fit things into
 * fi_context.
 */

enum {
	ZHPE_TX_HANDLE_MSG_INJECT,
	ZHPE_TX_HANDLE_MSG_PROV,
	ZHPE_TX_HANDLE_MSG,
	ZHPE_TX_HANDLE_MSG_FREE,
	ZHPE_TX_HANDLE_TAG,
	ZHPE_TX_HANDLE_TAG_FREE,
	ZHPE_TX_HANDLE_RX_GET_BUF,
	ZHPE_TX_HANDLE_RX_GET_RND,
	ZHPE_TX_HANDLE_RMA,
	ZHPE_TX_HANDLE_ATM_EM,
	ZHPE_TX_HANDLE_ATM_EM_FREE,
	ZHPE_TX_HANDLE_ATM_HW_RES32,
	ZHPE_TX_HANDLE_ATM_HW_RES32_FREE,
	ZHPE_TX_HANDLE_ATM_HW_RES64,
	ZHPE_TX_HANDLE_ATM_HW_RES64_FREE,
};

/* Fits in a FI_CONTEXT */
struct zhpe_tx_entry {
	struct zhpe_conn	*conn;
	void			*ptrs[2];
	struct zhpe_compstat	cstat;
	uint16_t		cmp_idx;
	union {
		uint8_t		ptr_cnt;
		uint8_t		rma_get;
	};
	uint8_t			tx_handler;
};

/* Just a little bigger to hold a context pointer. */
struct zhpe_tx_entry_ctx {
	struct zhpe_tx_entry	tx_entry;
	void			*op_context;
};

struct zhpe_msg;

enum {
	ZHPE_CONN_FLAG_BACKOFF	= 0x01,
	ZHPE_CONN_FLAG_CLEANUP	= 0x02,
	ZHPE_CONN_FLAG_CONNECT	= 0x04,
	ZHPE_CONN_FLAG_CONNECT1	= 0x08,
	ZHPE_CONN_FLAG_CONNECT_MASK = 0x0C,
	ZHPE_CONN_FLAG_FENCE	= 0x10,
};

enum {
	ZHPE_CONN_EFLAG_ERROR	= 0x01,
	ZHPE_CONN_EFLAG_SHUTDOWN1 = 0x02,
	ZHPE_CONN_EFLAG_SHUTDOWN2 = 0x04,
	ZHPE_CONN_EFLAG_SHUTDOWN3 = 0x06,
};

enum {
	ZHPE_CONN_RMA_REM_RD	= 0x01,
	ZHPE_CONN_RMA_REM_WR	= 0x02,
	ZHPE_CONN_RMA_REM_OP	= 0x03,
	ZHPE_CONN_RMA_ZERO_OFF	= 0x04,
};

/* Provider-specific "op" flag. */
#define FI_ZHPE_RMA_ZERO_OFF	((uint64_t)1 << 63)

struct zhpe_conn_tree_key {
	uint32_t	        rem_gcid;
	uint32_t		rem_rspctxid0;
	uint8_t			rem_ctx_idx;
};

struct zhpe_conn {
	struct zhpe_tx_entry	tx_entry_inject;
	struct zhpe_tx_entry	tx_entry_prov;
	struct zhpe_ctx		*zctx;
	uint32_t		tx_seq;
	int32_t			tx_queued;
	struct dlist_entry	tx_queue;
	struct dlist_entry	tx_dequeue_dentry;
	uint64_t		tx_dequeue_last;
	void			(*tx_dequeue)(struct zhpe_conn *conn);
	uint64_t		tx_backoff_timestamp;
	int32_t			tx_fences;
	uint8_t			tx_backoff_idx;

	struct zhpe_conn_tree_key tkey;
	uint64_t		rem_rma_flags;
	uint32_t		rem_rspctxid;
	uint16_t		rem_conn_idxn;

	void			(*rx_msg_handler)(struct zhpe_conn *conn,
						  struct zhpe_rdm_entry *rqe);
	struct zhpe_rx_entry	*rx_pending;
	void			(*rx_pending_fn)(struct zhpe_conn *conn,
						 struct zhpe_msg *msg);

	uint64_t		rx_reqzmmu;
	struct zhpeq_rx_seq	rx_zseq;

	uint64_t		fiaddr;
	struct zhpeq_key_data	*qkdata;
	void			*addr_cookie;

	uint8_t			eflags;
	uint8_t			flags;
	bool			fam;
};

struct zhpe_dom;

typedef  int (*qkdata_mr_reg_fn)(struct zhpe_dom *zdom, const void *buf,
				 size_t len, uint32_t qaccess,
				 struct zhpeq_key_data **qkdata_out);
typedef  int (*qkdata_mr_free_fn)(struct zhpe_dom *zdom,
				  struct zhpeq_key_data *qkdata);

struct zhpe_pe_progress {
	struct dlist_entry	pe_dentry;
	bool			(*pe_progress)(struct zhpe_pe_progress *zprog);
};

struct zhpe_bufpool {
	const char		*name;
	struct ofi_bufpool	*pool;
};

struct zhpe_ibufpool {
	const char		*name;
	struct ofi_bufpool	*pool;
	size_t			max_index;
};

int zhpe_bufpool_create(struct zhpe_bufpool *zpool, const char *name,
			size_t size, size_t alignment,
			size_t max_cnt, size_t chunk_cnt, int flags,
			void (*init_fn)(struct ofi_bufpool_region *region,
					void *buf),
			void *context);
int zhpe_ibufpool_create(struct zhpe_ibufpool *zpool, const char *name,
			 size_t size, size_t alignment,
			 size_t max_cnt, size_t chunk_cnt, int flags,
			 void (*init_fn)(struct ofi_bufpool_region *region,
					 void *buf),
			 void *context);
void zhpe_bufpool_destroy(struct zhpe_bufpool *zpool);
void zhpe_ibufpool_destroy(struct zhpe_ibufpool *zpool);
void *zhpe_buf_alloc(struct zhpe_bufpool *zpool);
void *zhpe_ibuf_alloc(struct zhpe_ibufpool *zpool);
void zhpe_buf_free(struct zhpe_bufpool *zpool, void *buf);
void zhpe_ibuf_free(struct zhpe_ibufpool *zpool, void *buf);

static inline void *zhpe_ibuf_get(struct zhpe_ibufpool *zpool, size_t index)
{
	void			*ret;

	/*
	 * ibufs don't have entirely solid semantics, if you ask for
	 * an index higher that has been allocated, you run the risk
	 * of getting a bad pointer, so you need to track the maximum
	 * index. If you free an ibuf, ofi_bufpool_get_ibuf() doesn't
	 * know, so you need to have an in-use flag that initialized
	 * properly when the bufpool chunks are allocated.
	 */
	if (OFI_LIKELY(index < zpool->max_index))
		ret = ofi_bufpool_get_ibuf(zpool->pool, index);
	else
		ret = NULL;

	return ret;
}

static inline size_t zhpe_ibuf_index(struct zhpe_ibufpool *zpool, void *buf)
{
	/* Adding the zpool argument for type checking. */
	return ofi_buf_index(buf);
}

struct zhpe_dom {
	struct util_domain	util_domain;
	struct zhpeq_dom	*zqdom;

	struct zhpe_pe		*pe;

	struct zhpe_bufpool	zmr_pool;
	struct dlist_entry	zmr_list;
	void			*reg_page;
	struct zhpe_mr		*reg_zmr;

	qkdata_mr_reg_fn	qkdata_mr_reg;
	qkdata_mr_free_fn	qkdata_mr_free;
	struct ofi_mr_cache	cache;

	struct ofi_rbmap	kexp_tree;
	pthread_mutex_t		kexp_teardown_mutex;

	bool			mr_events;
};

static inline struct zhpe_dom *fid2zdom(struct fid *fid)
{
	assert(fid->fclass == FI_CLASS_DOMAIN);
	return container_of(fid, struct zhpe_dom,
			    util_domain.domain_fid.fid);
}

static inline struct zhpe_dom *udom2zdom(struct util_domain *dom)
{
	return container_of(dom, struct zhpe_dom, util_domain);
}

static inline struct zhpe_fabric *zdom2zfab(struct zhpe_dom *zdom)
{
	return ufab2zfab(zdom->util_domain.fabric);
}

static inline struct ofi_mr_map *zdom2map(struct zhpe_dom *zdom)
{
	return &zdom->util_domain.mr_map;
}

static inline void zdom_lock(struct zhpe_dom *zdom)
{
	fastlock_acquire(&zdom->util_domain.lock);
}

static inline bool zdom_trylock(struct zhpe_dom *zdom)
{
	return !fastlock_tryacquire(&zdom->util_domain.lock);
}

static inline void zdom_unlock(struct zhpe_dom *zdom)
{
	fastlock_release(&zdom->util_domain.lock);
}

struct zhpe_cntr {
	struct util_cntr	util_cntr;
};

static inline struct zhpe_cntr *fid2zcntr(struct fid *fid)
{
	assert(fid->fclass == FI_CLASS_CNTR);
	return container_of(fid, struct zhpe_cntr, util_cntr.cntr_fid.fid);
}

static inline struct zhpe_cntr *ucntr2zcntr(struct util_cntr *cntr)
{
	return container_of(cntr, struct zhpe_cntr, util_cntr);
}

static inline struct zhpe_dom *zcntr2zdom(struct zhpe_cntr *zcntr)
{
	return udom2zdom(zcntr->util_cntr.domain);
}

struct zhpe_mr {
	struct fid_mr		mr_fid;
	struct zhpe_dom		*zdom;
	struct zhpeq_key_data	*qkdata;
	struct dlist_entry	kexp_list;
	struct dlist_entry	dentry;
	ofi_atomic32_t		ref;
	bool		        closed;
};

static inline struct zhpe_mr *fid2zmr(struct fid *fid)
{
	assert(fid->fclass == FI_CLASS_MR);
	return container_of(fid, struct zhpe_mr, mr_fid.fid);
}

#define FI_ADDR_BITS		(sizeof(fi_addr_t) * CHAR_BIT)

/* We're going to ignore most of the util_av logic. */

struct zhpe_av_entry {
	int32_t			use_cnt;
	struct sockaddr_zhpe	sz;
};

struct zhpe_av {
	struct util_av		util_av;
	struct ofi_rbmap	zav_tree;
	struct zhpe_ibufpool	zav_entry_pool;
	fi_addr_t		av_idx_mask;
	fi_addr_t		rx_ctx_mask;
	int			rx_ctx_bits;
	int			rx_ctx_shift;
};

static inline struct zhpe_av *fid2zav(struct fid *fid)
{
	assert(fid->fclass == FI_CLASS_AV);
	return container_of(fid, struct zhpe_av, util_av.av_fid.fid);
}

static inline struct zhpe_av *uav2zav(struct util_av *av)
{
	return container_of(av, struct zhpe_av, util_av);
}

static inline struct zhpe_dom *zav2zdom(struct zhpe_av *zav)
{
	return container_of(zav->util_av.domain, struct zhpe_dom,
			    util_domain);
}

static inline void zav_lock(struct zhpe_av *zav)
{
	fastlock_acquire(&zav->util_av.lock);
}

static inline void zav_unlock(struct zhpe_av *zav)
{
	fastlock_release(&zav->util_av.lock);
}

enum zhpe_msg_ops {
	/* CONNECTX must be first. */
	ZHPE_OP_CONNECT1,
	ZHPE_OP_CONNECT1_NAK,
	ZHPE_OP_CONNECT2,
	ZHPE_OP_CONNECT3,
	ZHPE_OP_CONNECT_STATUS,
	ZHPE_OP_STATUS,
	ZHPE_OP_SHUTDOWN,

	ZHPE_OP_KEY_RELEASE,
	ZHPE_OP_KEY_REQUEST,
	ZHPE_OP_KEY_RESPONSE,
	ZHPE_OP_KEY_REVOKE,
	ZHPE_OP_WRITEDATA,
	ZHPE_OP_ATOMIC_REQUEST,
	ZHPE_OP_ATOMIC_RESULT,

	ZHPE_OP_SEND_C,
	ZHPE_OP_SEND_F,

	/*
	 * An explosion of opcodes for inline/rendevous to reduce the number
	 * of conditionals later in the path with a smart compiler.
	 *
	 * bit 0 (I): 1 => inline, 0 => rendezvous
	 * bit 1 (D): 1 => cq_data, 0 => none
	 * bit 2 (T): 1 => tag, 0 => none
	 * bit 3 (M): 1 => mult-packet message, 0 => one packet msg
	 * bit 4-7  : 0x10 means send
	 *
	 * (above)
	 * SEND_C : a continuation of the multi-packet message
	 * SEND_F : final message in a multi-packet message.
	 *
	 */
	ZHPE_OP_SEND		= 0x10,
	ZHPE_OP_SEND_IX		= 0x01,	/* Inline */
	ZHPE_OP_SEND_DX		= 0x02, /* Data */
	ZHPE_OP_SEND_TX		= 0x04, /* Tagged */
	ZHPE_OP_SEND_MX		= 0x08, /* Multi */

	/* Convenience defintions */
	ZHPE_OP_SEND_I		= ZHPE_OP_SEND | ZHPE_OP_SEND_IX,
	ZHPE_OP_SEND_ID		= ZHPE_OP_SEND_I | ZHPE_OP_SEND_DX,
	ZHPE_OP_SEND_IT		= ZHPE_OP_SEND_I | ZHPE_OP_SEND_TX,
	ZHPE_OP_SEND_IDT	= ZHPE_OP_SEND_ID | ZHPE_OP_SEND_TX,
	ZHPE_OP_SEND_IM		= ZHPE_OP_SEND_I | ZHPE_OP_SEND_MX,
	ZHPE_OP_SEND_IDM	= ZHPE_OP_SEND_ID | ZHPE_OP_SEND_MX,
	ZHPE_OP_SEND_ITM	= ZHPE_OP_SEND_IT | ZHPE_OP_SEND_MX,
	ZHPE_OP_SEND_IDTM	= ZHPE_OP_SEND_IDT | ZHPE_OP_SEND_MX,
	ZHPE_OP_SEND_D		= ZHPE_OP_SEND | ZHPE_OP_SEND_DX,
	ZHPE_OP_SEND_T		= ZHPE_OP_SEND | ZHPE_OP_SEND_TX,
	ZHPE_OP_SEND_M		= ZHPE_OP_SEND | ZHPE_OP_SEND_MX,
	ZHPE_OP_SEND_DT		= ZHPE_OP_SEND_D | ZHPE_OP_SEND_T,
	ZHPE_OP_SEND_DM		= ZHPE_OP_SEND_D | ZHPE_OP_SEND_M,
	ZHPE_OP_SEND_TM		= ZHPE_OP_SEND_T | ZHPE_OP_SEND_M,
	ZHPE_OP_SEND_DTM	= ZHPE_OP_SEND_DT | ZHPE_OP_SEND_M,
};

static_assert(ZHPE_OP_SEND_F < ZHPE_OP_SEND, "send collision");

struct zhpe_iov_state {
	struct zhpe_iov_state_ops *ops;
	uint64_t		off;
	void			*viov;
	uint64_t		zbase;
	uint8_t			idx;
	uint8_t			cnt;
	uint8_t			max;
	bool			held;
};

struct zhpe_iov_state_ops {
	uint64_t	(*iov_addr)(const struct zhpe_iov_state *state);
	uint64_t	(*iov_len)(const struct zhpe_iov_state *state);
	uint64_t	(*avail)(const struct zhpe_iov_state *state);
};

struct zhpe_iov3 {
	uint64_t		iov_base;
	uint64_t		iov_len;
	union {
		struct zhpe_rkey *iov_rkey;
		struct zhpe_mr	*iov_desc;
	};
};

extern struct zhpe_iov_state_ops zhpe_iov_state_iovec_ops;
extern struct zhpe_iov_state_ops zhpe_iov_state_ziov3_ops;

static inline void zhpe_iov_state_init(struct zhpe_iov_state *state,
				       struct zhpe_iov_state_ops *ops,
				       void *viov, uint8_t viov_max)
{
	state->off = 0;
	state->viov = viov;
	state->idx = 0;
	state->cnt = 0;
	state->max = viov_max;
	state->held = false;
	state->ops = ops;
}

static inline int zhpe_iov_state_empty(const struct zhpe_iov_state *state)
{
	return (state->idx >= state->cnt);
}

static inline void zhpe_iov_state_reset(struct zhpe_iov_state *state)
{
	state->off = 0;
	state->idx = 0;
}

static inline void *zhpe_iov_state_ptr(const struct zhpe_iov_state *state)
{
	return (void *)(uintptr_t)state->ops->iov_addr(state);
}

static inline uint64_t zhpe_iov_state_len(const struct zhpe_iov_state *state)
{
	if (zhpe_iov_state_empty(state))
		return 0;

	return state->ops->iov_len(state);
}

static inline uint64_t zhpe_iov_state_addr(const struct zhpe_iov_state *state)
{
	return state->ops->iov_addr(state);
}

static inline uint64_t zhpe_iov_state_avail(const struct zhpe_iov_state *state)
{
	return state->ops->avail(state);
}

bool zhpe_iov_state_adv(struct zhpe_iov_state *state, uint64_t incr);
uint64_t zhpe_iov_state_avail(const struct zhpe_iov_state *state);
uint64_t zhpe_copy_iov(struct zhpe_iov_state *dstate,
		       struct zhpe_iov_state *sstate);
uint64_t zhpe_copy_iov_to_mem(void *dst, uint64_t dst_len,
			      struct zhpe_iov_state *sstate);
uint64_t zhpe_copy_mem_to_iov(struct zhpe_iov_state *dstate, const void *src,
			      uint64_t src_len);
void zhpe_iov_rma(struct zhpe_tx_entry *tx_entry,
		  uint64_t max_seg_bytes, uint32_t max_seg_ops);

void zhpe_tx_reserve(struct zhpeq_tq *ztq, struct zhpe_tx_entry *tx_entry,
		     uint n_entries, union zhpe_hw_wq_entry **wqe,
		     int32_t *reservation);

#define ZHPE_MR_ACCESS_ALL						\
	(FI_READ|FI_WRITE|FI_REMOTE_READ|FI_REMOTE_WRITE|FI_SEND|FI_RECV)

struct zhpe_eq {
	struct util_eq		util_eq;
};

static inline struct zhpe_eq *fid2zeq(struct fid *fid)
{
	assert(fid->fclass == FI_CLASS_EQ);
	return container_of(fid, struct zhpe_eq, util_eq.eq_fid.fid);
}

static inline struct zhpe_eq *ueq2zeq(struct util_eq *eq)
{
	return container_of(eq, struct zhpe_eq, util_eq);
}

static inline struct zhpe_fabric *zeq2zfab(struct zhpe_eq *zeq)
{
	return ufab2zfab(zeq->util_eq.fabric);
}

struct zhpe_optlock {
	fastlock_t		lock;
	ofi_fastlock_acquire_t	acquire;
	ofi_fastlock_release_t	release;
};

void zhpe_optlock_init(struct zhpe_optlock *lock, bool must_lock);
void zhpe_optlock_destroy(struct zhpe_optlock *lock);

static inline void zhpe_optlock_lock(struct zhpe_optlock *lock)
{
	lock->acquire(&lock->lock);
}

static inline void zhpe_optlock_unlock(struct zhpe_optlock *lock)
{
	lock->release(&lock->lock);
}

struct zhpe_rx_match_info {
	bool			(*match_fn)(struct zhpe_rx_match_info *user,
					    struct zhpe_rx_match_info *wire);
	struct zhpe_conn	*conn;
	uint64_t		tag;
	uint64_t		ignore;
};

struct zhpe_rx_match_lists {
	struct dlist_entry	user_list;
	struct dlist_entry	wire_list;
};

/*
 * The ep_fid is at the begining of the util_op. There's a static assert in
 * zhpe_fabric to insure these remains true so fid2zep() and fid2zctx()
 * work properly.
 */
struct zhpe_ep_fid {
	struct zhpe_ep		*zep;
	struct zhpe_ctx		*zctx;
	struct fid_ep		ep_fid;
};

enum {
	ZHPE_CTX_SHUTDOWN_UP = 0,
	ZHPE_CTX_SHUTDOWN_IN_PROGRESS,
	ZHPE_CTX_SHUTDOWN,
	ZHPE_CTX_SHUTDOWN_FAILED,
};


struct zhpe_pe_ctx_ops {
	int		(*progress)(struct zhpe_pe *pe, struct zhpe_ctx *zctx);
	void		(*signal)(struct zhpe_ctx *zctx);
};

extern struct zhpe_pe_ctx_ops zhpe_pe_ctx_ops_auto_rx_active;
extern struct zhpe_pe_ctx_ops zhpe_pe_ctx_ops_manual;

enum {
	ZHPE_CTX_CLOSE_RX	= 0x1,
	ZHPE_CTX_CLOSE_TX	= 0x2,
	ZHPE_CTX_CLOSE_ALL	= 0x3,
};

struct zhpe_ctx {
	/*
	 * I don't see a reason for separate tx and rx contexts because
	 * we need pairs of XDM and RDM queues for protocol reasons, but
	 * I need separate fids so I can have the proper user semantics.
	 * I could have two util_eps, but nothing in the util code really cares
	 * and I find that annoying. So, I created thee zhpe_ep_fid so I didn't
	 * have to do that. The position of the pointers and the util_ep must
	 * correspond to the ep_fid so the fid2zep() and fid2zctx() above.
	 */
	struct zhpe_ep		*zep;
	struct zhpe_ctx		*zctx;
	struct util_ep		util_ep;
	struct zhpe_ep_fid	rx_ep;

	struct dlist_entry	pe_dentry;
	struct zhpe_pe_ctx_ops	*pe_ctx_ops;
	struct dlist_entry	tx_dequeue_list;

	/* context structures if fi_context not available. */
	struct zhpe_bufpool	tx_ctx_pool;
	void			**ctx_ptrs;
	uint16_t		ctx_ptrs_free;

	/* Operation info for RMA/Atomics. */
	struct zhpe_bufpool	tx_rma_pool;

	/* Queue entries. */
	struct zhpe_bufpool	tx_queue_pool;

	struct zhpeq_tq		*ztq_hi;
	struct zhpeq_tq		*ztq_lo[ZHPE_MAX_SLICES];

	uint32_t		tx_size;
	int32_t			tx_queued;
	uint32_t		tx_ztq_rotor;

	uint8_t		        ctx_idx;
	uint8_t			shutdown;
	uint8_t			close;

	struct zhpe_bufpool	rx_entry_pool;
	struct zhpe_bufpool	rx_oos_pool;

	struct zhpeq_rq		*zrq;

	struct zhpe_rx_match_lists rx_match_tagged;
	struct zhpe_rx_match_lists rx_match_untagged;
	struct dlist_entry	rx_work_list;

	uint32_t		rx_queued;

	uint32_t		lcl_gcid;
	uint32_t		lcl_rspctxid;

	struct zhpe_ibufpool	conn_pool;
	struct zhpe_conn	*conn0;
	/* ZZZ: index_map without conditionals? */
	struct index_map	conn_av_idm;
	struct ofi_rbmap	conn_tree;
	struct ofi_rbmap	rkey_tree;

	struct zhpe_slab	eager;

	uint64_t		hw_atomics;
};

static inline bool zhpe_tx_entry_slot_alloc(struct zhpe_tx_entry *tx_entry)
{
	struct zhpe_ctx		*zctx;

	/*
	 * Operations that need remote status need a context slot;
	 * optimize for inject/inline case that doesn't require one.
	 * zero is reserved, so return zero on failure.
	 */
	if (OFI_LIKELY(!(tx_entry->cstat.flags & ZHPE_CS_FLAG_REMOTE_STATUS)))
		return true;

	assert(!tx_entry->cmp_idx);
	zctx = tx_entry->conn->zctx;
	tx_entry->cmp_idx = zctx->ctx_ptrs_free;
	if (OFI_UNLIKELY(!tx_entry->cmp_idx))
		return false;

	zctx->ctx_ptrs_free = (uintptr_t)zctx->ctx_ptrs[tx_entry->cmp_idx];
	zctx->ctx_ptrs[tx_entry->cmp_idx] = tx_entry;

	return true;
}

static inline void zhpe_tx_entry_slot_free(struct zhpe_tx_entry *tx_entry,
					   uint16_t cmp_idx)
{
	struct zhpe_ctx		*zctx = tx_entry->conn->zctx;

	/* Caller must check or "know". */
	assert(cmp_idx);

	zctx = tx_entry->conn->zctx;
	zctx->ctx_ptrs[cmp_idx] = TO_PTR(zctx->ctx_ptrs_free);
	zctx->ctx_ptrs_free = cmp_idx;
}

enum {
	ZHPE_EP_DISABLED = 2,
	ZHPE_EP_DISABLED_ENABLE_IN_PROGRESS = 1,
	ZHPE_EP_DISABLED_ENABLED = 0,
};

struct zhpe_ep {
	struct zhpe_ep_fid	ep;
	fastlock_t		lock;

	struct zhpe_dom		*zdom;
	struct fi_info		*info;

	uuid_t			uuid;

	ofi_atomic32_t		num_ctx_open;
	uint8_t			num_ctx;
	uint8_t			num_tx_ctx;
	uint8_t			num_rx_ctx;
	uint8_t			disabled;

	struct zhpe_ctx		*zctx[];
};

static inline struct zhpe_ep *fid2zep(struct fid *fid)
{
	assert(fid->fclass == FI_CLASS_EP || fid->fclass == FI_CLASS_SEP);
	return container_of(fid, struct zhpe_ep_fid, ep_fid.fid)->zep;
}

static inline struct zhpe_ctx *fid2zctx(struct fid *fid)
{
	assert(fid->fclass == FI_CLASS_EP || fid->fclass == FI_CLASS_SEP ||
	       fid->fclass == FI_CLASS_TX_CTX ||
	       fid->fclass == FI_CLASS_RX_CTX);
	return container_of(fid, struct zhpe_ep_fid, ep_fid.fid)->zctx;
}

static inline struct zhpe_ctx *uep2zctx(struct util_ep *ep)
{
	return container_of(ep, struct zhpe_ctx, util_ep);
}

static inline struct zhpe_dom *zctx2zdom(struct zhpe_ctx *zctx)
{
	return container_of(zctx->util_ep.domain, struct zhpe_dom,
			    util_domain);
}

static inline struct zhpe_av *zctx2zav(struct zhpe_ctx *zctx)
{
	return container_of(zctx->util_ep.av, struct zhpe_av, util_av);
}

static inline void zep_lock(struct zhpe_ep *zep)
{
	fastlock_acquire(&zep->lock);
}

static inline void zep_unlock(struct zhpe_ep *zep)
{
	fastlock_release(&zep->lock);
}

static inline void zctx_lock(struct zhpe_ctx *zctx)
{
	fastlock_acquire(&zctx->util_ep.lock);
}

static inline bool zctx_trylock(struct zhpe_ctx *zctx)
{
	return !fastlock_tryacquire(&zctx->util_ep.lock);
}

static inline void zctx_unlock(struct zhpe_ctx *zctx)
{
	fastlock_release(&zctx->util_ep.lock);
}

enum zhpe_rx_state {
	ZHPE_RX_STATE_IDLE,
	ZHPE_RX_STATE_INLINE,
	ZHPE_RX_STATE_INLINE_M,
	ZHPE_RX_STATE_RND,
	ZHPE_RX_STATE_RND_M,
	ZHPE_RX_STATE_EAGER,
	ZHPE_RX_STATE_EAGER_CLAIMED,
	ZHPE_RX_STATE_EAGER_DONE,
	ZHPE_RX_STATE_DISCARD,
};

struct zhpe_rx_entry {
	struct dlist_entry	dentry;
	struct zhpe_tx_entry	tx_entry;
	struct zhpe_ctx		*zctx;

	struct zhpe_rx_match_info match_info;

	void			*op_context;
	uint64_t		op_flags;
	uint64_t		cq_data;
	uint64_t		total_user;
	uint64_t		total_wire;

	struct zhpe_iov_state	lstate;
	struct zhpe_iov_state	rstate;
	struct zhpe_iov_state	bstate;
	struct zhpe_iov3	liov[ZHPE_EP_MAX_IOV];
	union {
		struct iovec	riov[ZHPE_EP_MAX_IOV + 1];
		char		inline_data[ZHPE_EP_MAX_INLINE_MSG];
	};

	uint16_t		src_cmp_idxn;
	uint8_t			src_flags;
	uint8_t			rx_state;
	bool			matched;
	bool			lstate_ready;
};

struct zhpe_msg_hdr {
	uint8_t			op;
	uint8_t			flags;
	uint8_t		        retry;
	uint8_t			len;		/* Inline bytes or IOVs */
	uint16_t		conn_idxn;	/* n => network byte order */
	uint16_t		cmp_idxn;
	uint32_t		seqn;
};

static inline void zhpe_msg_hdr_init(struct zhpe_msg_hdr *hdr,
				     uint8_t op, uint8_t flags, uint8_t retry,
				     uint8_t len, uint16_t conn_idxn,
				     uint16_t cmp_idxn, uint32_t seq)
{
	hdr->op = op;
	hdr->flags = flags;
	hdr->retry = retry;
	hdr->len = len;
	hdr->conn_idxn = conn_idxn;
	hdr->cmp_idxn = cmp_idxn;
	hdr->seqn = htonl(seq);
}

#define ZHPE_MAX_MSG_PAYLOAD	(ZHPE_MAX_ENQA - sizeof(struct zhpe_msg_hdr))

struct zhpe_msg_key_release {
	uint64_t		keyn;
};

struct zhpe_msg_key_request {
	uint64_t		keysn[ZHPE_EP_MAX_IOV];
};

struct zhpe_msg_key_response {
	uint64_t		keyn;
	char			blob[ZHPEQ_MAX_KEY_BLOB];
};

struct zhpe_msg_key_revoke {
	uint64_t		keyn;
};

struct zhpe_msg_status {
	int16_t			statusn;
};

struct zhpe_msg_atomic_request {
	uint64_t		operandsn[2];
	uint64_t		raddrn;
	uint64_t		rkeyn;
	uint8_t			fi_op;
	uint8_t			fi_type;
	uint8_t			bytes;
};

struct zhpe_msg_atomic_result {
	uint64_t		resultn;
	uint8_t			fi_type;
};

struct zhpe_msg_writedata {
	uint64_t		op_flagsn;
	uint64_t		cq_datan;
};

struct zhpe_msg_connect1 {
	uint16_t		versionn;
	uint16_t		src_conn_idxn;
	uint32_t		src_rspctxid0n;
	uint32_t		src_rspctxidn;
	uint8_t			src_rma_flags;
	uint8_t			src_ctx_idx;
	uint8_t			dst_ctx_idx;
	uuid_t			dst_uuid;
};

struct zhpe_msg_connect1_nak {
	uint16_t		version;
	int16_t			errorn;
	uint16_t		conn_idxn;
	uint8_t			ctx_idx;
};

struct zhpe_msg_connect2 {
	uint32_t		rx_seqn;
	uint32_t		rspctxidn;
	uint16_t		conn_idxn;
	uint8_t		        rma_flags;
	uuid_t			uuid;
};

struct zhpe_msg_connect3 {
	char			blob[ZHPE_MAX_MSG_PAYLOAD];
};

struct zhpe_msg_connect_status {
	int16_t			statusn;
};

/* ENQA has a 52 byte payload; 12 bytes header, 40 byte payload. */

union zhpe_msg_payload {
	uint64_t		data[ZHPE_MAX_MSG_PAYLOAD / sizeof(uint64_t)];
	struct zhpe_msg_atomic_result atomic_result;
	struct zhpe_msg_atomic_request atomic_request;
	struct zhpe_msg_connect1 connect1;
	struct zhpe_msg_connect1_nak connect1_nak;
	struct zhpe_msg_connect2 connect2;
	struct zhpe_msg_connect3 connect3;
	struct zhpe_msg_connect_status connect_status;
	struct zhpe_msg_key_release key_release;
	struct zhpe_msg_key_request key_request;
	struct zhpe_msg_key_response key_response;
	struct zhpe_msg_key_revoke key_revoke;
	struct zhpe_msg_status	status;
	struct zhpe_msg_writedata writedata;
};

struct zhpe_tx_queue_entry {
	union zhpe_hw_wq_entry	wqe;
	struct dlist_entry	dentry;
	struct zhpe_tx_entry	*tx_entry;
};

/*
 * I don't see a way to get the compiler to align things the way I want
 * if I include the payload structure.
 *
 * All numeric quanitities bigger that a byte need to be sent in network
 * byte order.
 */
struct zhpe_msg {
	struct zhpe_msg_hdr	hdr;
	char			payload[ZHPE_MAX_MSG_PAYLOAD];
};

struct zhpe_rma_entry {
	struct zhpe_tx_entry	tx_entry;
	struct zhpe_ctx		*zctx;
	void			*op_context;
	uint64_t		op_flags;
	struct zhpe_iov_state	lstate;
	struct zhpe_iov_state   rstate;
	struct zhpe_iov3	liov[ZHPE_EP_MAX_IOV];
	struct zhpe_iov3	riov[ZHPE_EP_MAX_IOV];
	union {
		char		inline_data[ZHPEQ_MAX_IMM];
		struct {
			void	*result;
			uint64_t atomic_operands[2];
			uint8_t atomic_op;
			uint8_t atomic_size;
			uint8_t	result_type;
		};
	};
	struct dlist_entry	rkey_wait_dentry;
	uint64_t		cq_data;
};

struct zhpe_pe {
	struct zhpeu_work_head	work_head;
	struct zhpe_dom		*zdom;

	struct zhpeq_rq_epoll	*zepoll;
	struct dlist_entry	progress_list;
	struct dlist_entry	ctx_list;
	uint64_t		now;
	pthread_t		progress_thread;
	uint32_t		active_cnt;
	bool		        pe_exit;
};

struct zhpe_cq {
	struct util_cq		util_cq;
};

static inline struct zhpe_cq *fid2zcq(struct fid *fid)
{
	assert(fid->fclass == FI_CLASS_CQ);
	return container_of(fid, struct zhpe_cq, util_cq.cq_fid.fid);
}

static inline struct zhpe_cq *ucq2zcq(struct util_cq *cq)
{
	return container_of(cq, struct zhpe_cq, util_cq);
}

static inline struct zhpe_dom *zcq2zdom(struct zhpe_cq *zcq)
{
	return udom2zdom(zcq->util_cq.domain);
}

extern pthread_mutex_t zhpe_fabdom_close_mutex;

void fi_zhpe_fini(void);
int zhpe_getinfo(uint32_t api_version, const char *node, const char *service,
		 uint64_t flags, const struct fi_info *hints,
		 struct fi_info **info_out);
int zhpe_fabric(struct fi_fabric_attr *attr, struct fid_fabric **fabric,
		void *context);

int zhpe_domain(struct fid_fabric *fabric, struct fi_info *info,
		struct fid_domain **dom, void *context);

int zhpe_query_atomic(struct fid_domain *domain,
		      enum fi_datatype datatype, enum fi_op op,
		      struct fi_atomic_attr *attr, uint64_t flags);

int zhpe_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr,
		 struct fid_cq **cq, void *context);

static inline bool zhpe_cq_report_needed(struct util_cq *cq, uint64_t flags)
{
	return (cq && (flags & (FI_MULTI_RECV | FI_COMPLETION)));
}
static inline uint64_t zhpe_cq_sanitize_flags(uint64_t flags)
{
	return (flags & (FI_SEND | FI_RECV | FI_RMA | FI_ATOMIC |
			 FI_MSG | FI_TAGGED | FI_READ | FI_WRITE |
			 FI_REMOTE_READ | FI_REMOTE_WRITE |
			 FI_REMOTE_CQ_DATA | FI_MULTI_RECV));
}

static inline void zhpe_cq_report_success(struct util_cq *cq,
					  uint64_t flags, void *op_context,
					  uint64_t len, void *buf,
					  uint64_t cq_data, uint64_t tag)
{
	int			rc;

	flags = zhpe_cq_sanitize_flags(flags);
	rc = ofi_cq_write(cq, op_context, flags, len, buf, cq_data, tag);
	assert_always(rc >= 0);
	if (cq->wait)
		util_cq_signal(cq);
}

void zhpe_cq_report_error(struct util_cq *cq,
			  uint64_t flags, void *op_context, uint64_t len,
			  void *buf, uint64_t cq_data, uint64_t tag,
			  size_t olen, int err, int prov_errno);

int zhpe_eq_open(struct fid_fabric *fabric_fid, struct fi_eq_attr *attr,
		 struct fid_eq **eq_fid, void *context);
ssize_t zhpe_eq_report_event(struct util_eq *eq, uint32_t event,
			     const void *buf, size_t len);
ssize_t zhpe_eq_report_error(struct util_eq *eq, fid_t fid, void *context,
			     uint64_t data, int err, int prov_errno,
			     void *err_data, size_t err_data_size);

int zhpe_cntr_open(struct fid_domain *domain_fid, struct fi_cntr_attr *attr,
		   struct fid_cntr **cntr_fid, void *context);

static inline void zhpe_cntr_inc(struct zhpe_cntr *zcntr)
{
	ofi_cntr_inc(&zcntr->util_cntr);
}

static inline uint64_t zhpe_cntr_read(struct zhpe_cntr *zcntr)
{
	return ofi_atomic_get64(&zcntr->util_cntr.cnt);
}

int zhpe_av_open(struct fid_domain *fid_domain, struct fi_av_attr *attr,
		 struct fid_av **fid_av_out, void *context);
void *zhpe_av_get_addr_unsafe(struct zhpe_av *zav, fi_addr_t fi_addr);
struct zhpe_av_entry *
zhpe_av_update_addr_unsafe(struct zhpe_av *zav,
			   const struct sockaddr_zhpe *sz_new);

int zhpe_ep_open(struct fid_domain *fid_domain, struct fi_info *info,
		 struct fid_ep **fid_ep_out, void *context);
int zhpe_sep_open(struct fid_domain *fid_domain, struct fi_info *info,
		  struct fid_ep **fid_ep_out, void *context);

int zhpe_set_fd_cloexec(int fd);
int zhpe_set_fd_nonblock(int fd);

void zhpe_rx_msg_handler_connected(struct zhpe_conn *conn,
				   struct zhpe_rdm_entry *rqe);
void zhpe_rx_msg_handler_unconnected(struct zhpe_conn *conn,
				     struct zhpe_rdm_entry *rqe);
void zhpe_rx_msg_handler_drop(struct zhpe_conn *conn,
			      struct zhpe_rdm_entry *rqe);
struct zhpeq_rx_oos *zhpe_rx_oos_alloc(struct zhpeq_rx_seq *zseq);
void zhpe_rx_oos_free(struct zhpeq_rx_seq *zseq, struct zhpeq_rx_oos *rx_oos);

void zhpe_send_atomic_result(struct zhpe_conn *conn, uint16_t cmp_idxn,
			     int32_t status, uint64_t result);
void zhpe_send_key_release(struct zhpe_conn *conn, uint64_t key);
void zhpe_send_key_request(struct zhpe_conn *conn, uint64_t *keys,
			   size_t n_keys);
void zhpe_send_key_response(struct zhpe_conn *conn,
			    uint64_t key, char *blob, size_t blob_len);
void zhpe_send_key_revoke(struct zhpe_conn *conn, uint64_t key);
void zhpe_send_writedata(struct zhpe_conn *conn, uint64_t op_flags,
			 uint64_t cq_data);

struct zhpe_pe *zhpe_pe_init(struct zhpe_dom *domain);
void zhpe_pe_fini(struct zhpe_pe *pe);
void zhpe_pe_add_progress(struct zhpe_dom *zdom,
			  struct zhpe_pe_progress *zprog);
void zhpe_pe_del_progress(struct zhpe_dom *zdom,
			  struct zhpe_pe_progress *zprog);
void zhpe_pe_add_ctx(struct zhpe_ctx *zctx);
void zhpe_pe_del_ctx(struct zhpe_ctx *zctx);
void zhpe_pe_epoll_handler(struct zhpeq_rq *zrq, void *handler_data);
void zhpe_ofi_ep_progress(struct util_ep *util_ep);
void zhpe_ctx_cleanup_progress(struct zhpe_ctx *zctx, bool locked);

void zhpe_rx_peek_recv(struct zhpe_ctx *zctx,
		       struct zhpe_rx_match_info *user_info, uint64_t flags,
		       struct fi_context *context);
void zhpe_rx_discard_recv(struct zhpe_rx_entry *rx_entry);
void zhpe_rx_start_recv_user(struct zhpe_rx_entry *rx_matched,
			     const struct iovec *uiov, void **udesc,
			     size_t uiov_cnt);
void zhpe_rx_start_recv(struct zhpe_rx_entry *rx_matched,
			enum zhpe_rx_state rx_state);
void zhpe_rx_complete(struct zhpe_rx_entry *rx_entry, int status);

void zhpe_tx_call_handler(struct zhpe_tx_entry *tx_entry,
			  struct zhpe_cq_entry *cqe);
void zhpe_tx_call_handler_fake(struct zhpe_tx_entry *tx_entry,
			       uint8_t iostatus);

int zhpe_slab_init(struct zhpe_slab *mem, size_t size,
		   struct zhpe_dom *domain);
void zhpe_slab_destroy(struct zhpe_slab *mem);
int zhpe_slab_alloc(struct zhpe_slab *slab, size_t size, struct iovec *iov);
void zhpe_slab_free(struct zhpe_slab *mem, void *ptr);

void zhpe_msg_prov(struct zhpe_conn *conn, uint8_t op, const void *payload,
		   size_t paylen, uint16_t cmp_idxn, uint32_t tx_seq);
void zhpe_msg_prov_no_eflags(struct zhpe_conn *conn, uint8_t op,
			     const void *payload, size_t paylen,
			     uint16_t cmp_idxn, uint32_t tx_seq);
void zhpe_msg_connect(struct zhpe_ctx *zctx, uint8_t op,
		      const void *payload, size_t paylen, uint32_t tx_seq,
		      uint32_t dgcid, uint32_t rspctxid);

int zhpe_dom_mr_reg(struct zhpe_dom *zdom, const void *buf, size_t len,
		    uint32_t qaccess, bool link, struct zhpe_mr **zmr_out);
void zhpe_dom_mr_free(struct zhpe_mr *zmr);
void zhpe_dom_cleanup_ctx(struct zhpe_ctx *zctx);
void zhpe_dom_cleanup_conn(struct zhpe_conn *conn);
void zhpe_dom_key_release(struct zhpe_conn *conn, uint64_t key);
void zhpe_dom_key_export(struct zhpe_conn *conn, uint64_t key);
int zhpe_dom_mr_cache_init(struct zhpe_dom *zdom);
void zhpe_dom_mr_cache_destroy(struct zhpe_dom *zdom);

static inline void zhpe_dom_mr_put(struct zhpe_mr *zmr)
{
	int			val;

	if (OFI_UNLIKELY(!zmr))
		return;

	val = ofi_atomic_dec32(&zmr->ref);
	if (val > 0)
		return;
	assert(val == 0);

	zhpe_dom_mr_free(zmr);
}

static inline void zhpe_dom_mr_get(struct zhpe_mr *zmr)
{
	int			val MAYBE_UNUSED;

	val = ofi_atomic_inc32(&zmr->ref);
	assert(val > 1);
}

int zhpe_compare_mem_tkeys(struct ofi_rbmap *map, void *key, void *data);

void zhpe_rma_rkey_free(struct zhpe_rkey *rkey);
void zhpe_rma_rkey_revoke(struct zhpe_conn *conn, uint64_t key);
void zhpe_rma_rkey_import(struct zhpe_conn *conn, uint64_t key,
			  const char *blob, size_t blob_len);
struct zhpe_rkey *
zhpe_rma_rkey_lookup(struct zhpe_conn *conn, uint64_t key,
		     void *(*wait_prep)(void *prep_arg),
		     void (*wait_handler)(void *handler_arg, int status),
		     void *prep_arg);
void zhpe_rma_tx_start(struct zhpe_rma_entry *rma_entry);
void zhpe_rma_complete(struct zhpe_rma_entry *rma_entry);

static inline void zhpe_rma_rkey_put(struct zhpe_rkey *rkey)
{
	int32_t			val;

	/* rkey->conn->zctx lock must be held. */
	if (OFI_UNLIKELY(!rkey))
		return;

	val = --(rkey->ref);
	if (val > 0)
		return;
	assert(val == 0);

	zhpe_rma_rkey_free(rkey);
}

static inline void zhpe_rma_rkey_get(struct zhpe_rkey *rkey)
{
	int			val MAYBE_UNUSED;

	val = ++(rkey->ref);
	assert(val > 1);
}

static inline uint64_t zopflags2op(uint8_t zop_flags)
{
	uint64_t		ret = 0;

	if (zop_flags & ZHPE_CS_FLAG_COMPLETION)
		ret |= FI_COMPLETION;

	return ret;
}

/* Collision between caps and modes, use own flags. */
enum {
	ZHPE_OPT_CONTEXT	= 0x0001,
	ZHPE_OPT_FENCE		= 0x0002,
	ZHPE_OPT_TAGGED		= 0x0004,
	ZHPE_OPT_DIRECTED_RECV	= 0x0008,
};

struct zhpe_conn *zhpe_conn_alloc(struct zhpe_ctx *zctx);
void zhpe_conn_connect1_rx(struct zhpe_ctx *zctx, struct zhpe_msg *msg,
			   uint32_t rem_gcid);
void zhpe_conn_connect1_nak_rx(struct zhpe_ctx *zctx, struct zhpe_msg *msg);
void zhpe_conn_connect2_rx(struct zhpe_conn *conn, struct zhpe_msg *msg);
void zhpe_conn_connect3_rx(struct zhpe_conn *conn, struct zhpe_msg *msg);
void zhpe_conn_connect_status_rx(struct zhpe_conn *conn, struct zhpe_msg *msg);
struct zhpe_conn *zhpe_conn_av_lookup(struct zhpe_ctx *zctx, fi_addr_t fiaddr);
int zhpe_conn_init(struct zhpe_ctx *zctx);
void zhpe_conn_fini(struct zhpe_ctx *zctx);
void zhpe_conn_cleanup(struct zhpe_ctx *zctx);
void zhpe_conn_dequeue_fence(struct zhpe_conn *conn);
int zhpe_conn_eflags_error(uint8_t eflags);

static inline void zhpe_conn_flags_set(struct zhpe_conn *conn, uint8_t flags)
{
	if (!conn->flags)
		dlist_insert_tail(&conn->tx_dequeue_dentry,
				  &conn->zctx->tx_dequeue_list);
	conn->flags |= flags | ZHPE_CONN_FLAG_CLEANUP;
}

static inline void zhpe_conn_fence_check(struct zhpe_tx_entry *tx_entry,
					 uint64_t opt_flags, uint64_t op_flags)
{
	struct zhpe_conn	*conn = tx_entry->conn;

	if (!(opt_flags & ZHPE_OPT_FENCE) ||
	    OFI_LIKELY(!(op_flags & FI_FENCE)))
		return;

	/* Optimize immediate send. */
	if (OFI_UNLIKELY(!conn->flags && !conn->tx_queued &&
			 dlist_empty(&conn->tx_queue)))
		return;
	zhpe_conn_flags_set(conn, ZHPE_CONN_FLAG_FENCE);
	conn->tx_dequeue = zhpe_conn_dequeue_fence;
	conn->tx_fences++;
	tx_entry->cstat.flags |= ZHPE_CS_FLAG_FENCE | ZHPE_CS_FLAG_QUEUED;
}

int zhpe_conn_fam_setup(struct zhpe_conn *conn);

static inline uint32_t access2qaccess(uint64_t access)
{
	uint32_t		ret = 0;

	if (access & (FI_READ | FI_RECV))
		ret |= ZHPEQ_MR_GET;
	if (access & (FI_WRITE | FI_SEND))
		ret |= ZHPEQ_MR_PUT;
	if (access & (FI_REMOTE_READ | FI_SEND))
		ret |= ZHPEQ_MR_GET_REMOTE;
	if (access & FI_REMOTE_WRITE)
		ret |= ZHPEQ_MR_PUT_REMOTE;

	return ret;
}

static_assert(ZHPE_EP_MAX_IOV == 2, "iov_len");

static inline int zhpe_get_uiov_len(const struct iovec *uiov,
				    size_t uiov_cnt, size_t *total_user)
{
	uint64_t		next_len;

	assert(uiov_cnt <= ZHPE_EP_MAX_IOV);
	if (OFI_UNLIKELY(!uiov_cnt)) {
		*total_user = 0;
		return 0;
	}
	if (OFI_UNLIKELY(!uiov))
		return -FI_EINVAL;
	*total_user = uiov[0].iov_len;
	if (OFI_UNLIKELY(uiov_cnt > 1)) {
		next_len = *total_user + uiov[1].iov_len;
		if (OFI_UNLIKELY(next_len < *total_user))
			return -FI_EOVERFLOW;
		*total_user = next_len;
	}

	return 0;
}

static inline int zhpe_get_urma_len(const struct fi_rma_iov *urma,
				    size_t urma_cnt, size_t *total_urma)
{
	uint64_t		next_len;

	assert(urma_cnt <= ZHPE_EP_MAX_IOV);
	if (OFI_UNLIKELY(!urma_cnt)) {
		*total_urma = 0;
		return 0;
	}
	if (OFI_UNLIKELY(!urma))
		return -FI_EINVAL;
	*total_urma = urma[0].len;
	if (OFI_UNLIKELY(urma_cnt > 1)) {
		next_len = *total_urma + urma[1].len;
		if (OFI_UNLIKELY(next_len < *total_urma))
			return -FI_EOVERFLOW;
		*total_urma = next_len;
	}

	return 0;
}

static inline void zhpe_get_uiov_buffered(const struct iovec *uiov,
					  void **udesc, size_t uiov_cnt,
					  struct zhpe_iov_state *lstate)
{
	struct zhpe_iov3	*liov = lstate->viov;

	assert(uiov_cnt <= ZHPE_EP_MAX_IOV);
	lstate->cnt = uiov_cnt;
	if (OFI_UNLIKELY(!uiov_cnt))
		return;
	liov[0].iov_base = (uintptr_t)uiov[0].iov_base;
	liov[0].iov_len = uiov[0].iov_len;
	if (OFI_UNLIKELY(uiov_cnt > 1)) {
		liov[1].iov_base = (uintptr_t)uiov[1].iov_base;
		liov[1].iov_len = uiov[1].iov_len;
	}
}

static inline void zhpe_lstate_release(struct zhpe_iov_state *lstate)
{
	struct zhpe_iov3	*liov = lstate->viov;

	/* Optimize for inline. */
	if (OFI_LIKELY(!lstate->held))
		return;
	zhpe_dom_mr_put(liov[0].iov_desc);
	if (lstate->cnt > 1)
		zhpe_dom_mr_put(liov[1].iov_desc);
}

static inline void zhpe_rstate_release(struct zhpe_iov_state *rstate)
{
	struct zhpe_iov3	*riov = rstate->viov;

	if (OFI_UNLIKELY(!rstate->cnt))
		return;
	zhpe_rma_rkey_put(riov[0].iov_rkey);
	if (rstate->cnt > 1)
		zhpe_rma_rkey_put(riov[1].iov_rkey);
}

static inline void zhpe_rx_entry_free(struct zhpe_rx_entry *rx_entry)
{
	if (OFI_UNLIKELY(rx_entry->bstate.cnt))
		zhpe_slab_free(&rx_entry->zctx->eager,
			       rx_entry->riov[ZHPE_EP_MAX_IOV].iov_base);
	zhpe_lstate_release(&rx_entry->lstate);
	zhpe_buf_free(&rx_entry->zctx->rx_entry_pool, rx_entry);
}

static inline struct zhpe_rx_entry *zhpe_rx_entry_alloc(struct zhpe_ctx *zctx)
{
	struct zhpe_rx_entry	*rx_entry;

	rx_entry = zhpe_buf_alloc(&zctx->rx_entry_pool);
	rx_entry->rx_state = ZHPE_RX_STATE_IDLE;
	rx_entry->lstate.held = false;
	rx_entry->bstate.cnt = 0;

	return rx_entry;
}

static inline void zhpe_rma_entry_free(struct zhpe_rma_entry *rma_entry)
{
	zhpe_lstate_release(&rma_entry->lstate);
	zhpe_rstate_release(&rma_entry->rstate);
	zhpe_buf_free(&rma_entry->zctx->tx_rma_pool, rma_entry);
}

static inline struct zhpe_rma_entry *zhpe_rma_entry_alloc(struct zhpe_ctx *zctx)
{
	struct zhpe_rma_entry	*rma_entry;

	rma_entry = zhpe_buf_alloc(&zctx->tx_rma_pool);
	if (OFI_UNLIKELY(!rma_entry))
		return NULL;
	zhpe_cstat_init(&rma_entry->tx_entry.cstat, 0, ZHPE_CS_FLAG_RMA);
	rma_entry->lstate.held = false;
	rma_entry->rstate.cnt = 0;

	return rma_entry;
}

static inline uint8_t zhpe_av_get_rx_idx(struct zhpe_av *zav,
					 fi_addr_t fiaddr)
{
	/* The mask is needed to cover the rx_ctx_bits == 0 case. */
	fiaddr &= ~zav->av_idx_mask;
	return (fiaddr >> zav->rx_ctx_shift);
}

static inline uint64_t zhpe_av_get_tx_idx(struct zhpe_av *zav,
					  fi_addr_t fiaddr)
{
	return (fiaddr << zav->rx_ctx_bits) | zhpe_av_get_rx_idx(zav, fiaddr);
}

int zhpe_get_buf_zmr(struct zhpe_ctx *zctx, void *base, size_t len,
		     void *udesc, struct zhpe_mr **zmr_out);
int zhpe_get_uiov(struct zhpe_ctx *zctx,
		  const struct iovec *uiov, void **udesc, size_t uiov_cnt,
		  uint32_t qaccess, struct zhpe_iov3 *liov);
int zhpe_get_uiov_maxlen(struct zhpe_ctx *zctx,
			 const struct iovec *uiov, void **udesc,
			 size_t uiov_cnt, uint32_t qaccess, uint64_t maxlen,
			 struct zhpe_iov3 *liov);
int zhpe_get_urma_total(const struct fi_rma_iov *urma, size_t urma_cnt,
			uint32_t qaccess, uint64_t total,
			struct zhpe_rma_entry *rma_entry);

static inline bool zhpe_addr_valid(const void *sa, size_t sa_len)
{
	const struct sockaddr_zhpe *sz = sa;

	/* Allow address to be larger...could hide extra data. */
	return (sz->sz_family == AF_ZHPE && sa_len >= sizeof(*sz));
}

int zhpe_atomic_op(enum fi_datatype type, enum fi_op op,
		   uint64_t operand0, uint64_t operand1,
		   void *dst, uint64_t *original);
int zhpe_atomic_load(enum fi_datatype type, const void *src, uint64_t *value);
int zhpe_atomic_store(enum fi_datatype type, void *dst, uint64_t value);
int zhpe_atomic_copy(enum fi_datatype type, const void *src, void *dst);

#endif /* _ZHPE_H_ */
