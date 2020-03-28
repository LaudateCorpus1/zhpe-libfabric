/*
 * Copyright (c) 2014 Intel Corporation, Inc.  All rights reserved.
 * Copyright (c) 2016 Cisco Systems, Inc. All rights reserved.
 * Copyright (c) 2017-2019 Hewlett Packard Enterprise Development LP.  All rights reserved.
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

void zhpe_straddr_log(const char *func, uint line, enum fi_log_level level,
		       enum fi_log_subsys subsys, const char *str,
		       const void *addr);

char *zhpe_straddr(char *buf, size_t *len,
		   uint32_t addr_format, const void *addr);

char *zhpe_astraddr(uint32_t addr_format, const void *addr);

#define _zhpe_straddr_log(...)					\
	zhpe_straddr_log(__func__, __LINE__, __VA_ARGS__)

#ifdef ENABLE_DEBUG
#define zhpe_straddr_dbg(...)					\
	_zhpe_straddr_log(FI_LOG_DEBUG, __VA_ARGS__)
void gdb_hook(void);
#else
#define zhpe_straddr_log_dbg(_subsys, ...)
#endif

static inline int zhpe_sa_family(uint32_t addr_format)
{
	switch (addr_format) {

	case FI_SOCKADDR_IN:
		return AF_INET;

	case FI_SOCKADDR_IN6:
		return AF_INET6;

	case FI_SOCKADDR:
	case FI_FORMAT_UNSPEC:
		return AF_UNSPEC;

	default:
		abort();
	}
}

extern int			zhpe_pe_waittime;
extern int			zhpe_conn_retry;
extern int			zhpe_cm_def_map_sz;
extern int			zhpe_av_def_sz;
extern int			zhpe_cq_def_sz;
extern int			zhpe_eq_def_sz;
extern char			*zhpe_pe_affinity_str;
extern size_t			zhpe_ep_max_eager_sz;
extern int			zhpe_mr_cache_enable;

extern struct fi_fabric_attr	zhpe_fabric_attr;
extern struct fi_domain_attr	zhpe_domain_attr;
extern struct fi_info		zhpe_info_msg;
extern struct fi_info		zhpe_info_rdm;
extern struct fi_provider	zhpe_prov;
extern struct util_prov		zhpe_util_prov;

extern struct fi_ops_msg	zhpe_ep_msg_ops_locked;
extern struct fi_ops_tagged	zhpe_ep_tagged_locked;
extern struct fi_ops_msg	zhpe_ep_msg_ops_unlocked;
extern struct fi_ops_tagged	zhpe_ep_tagged_unlocked;
extern struct fi_ops_rma	zhpe_ep_rma;
extern struct fi_ops_atomic	zhpe_ep_atomic;

/* For the moment, we're going to assume these will always use locks. */
extern struct fi_ops_cm zhpe_ep_cm_ops;
extern struct fi_ops_ep zhpe_ep_ops;
extern struct fi_ops zhpe_ep_fi_ops;
extern struct fi_ops_ep zhpe_ctx_ep_ops;

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

#define ZHPE_DOM_MR_MODE_REQUIRED					\
	(FI_MR_ALLOCATED)
#define ZHPE_DOM_MR_MODE_SUPPORTED					\
	(ZHPE_DOM_MR_MODE_REQUIRED | FI_MR_PROV_KEY |			\
	 FI_MR_VIRT_ADDR | FI_MR_LOCAL)

#define ZHPE_EP_DEF_RX_SZ	(16383U)
#define ZHPE_EP_DEF_TX_SZ	(1023U)
#define ZHPE_EP_MAX_CM_DATA_SZ  (256)
#define ZHPE_EP_MAX_CTX_BITS	(16)
#define ZHPE_EP_MAX_IOV_LEN	(1ULL << 31)
#define ZHPE_EP_MAX_IOV_LIMIT	(1)
#define ZHPE_EP_MAX_RETRY	(5)
#define ZHPE_EP_MIN_MULTI_RECV	(64)
#define ZHPE_EP_MODE_REQUIRED	(0)
#define ZHPE_EP_MODE_SUPPORTED						\
	(ZHPE_EP_MODE_REQUIRED | FI_CONTEXT | FI_CONTEXT2)

#define ZHPE_SEG_MAX_BYTES	(16UL * 1024 * 1024)
#define ZHPE_SEG_MAX_OPS	(2)

enum {
	ZHPE_CONN_ACTION_NEW,
	ZHPE_CONN_ACTION_DROP,
	ZHPE_CONN_ACTION_SELF,
	ZHPE_CONN_ACTION_SAMEHOST,
};

enum {
	ZHPE_CONN_STATE_INIT,
	ZHPE_CONN_STATE_RACED,
	ZHPE_CONN_STATE_READY,
};

#define ZHPE_EP_CQ_FLAGS (FI_SEND | FI_TRANSMIT | FI_RECV | \
			FI_SELECTIVE_COMPLETION)
#define ZHPE_EP_CNTR_FLAGS (FI_SEND | FI_RECV | FI_READ | \
			FI_WRITE | FI_REMOTE_READ | FI_REMOTE_WRITE)

#define ZHPE_NO_COMPLETION	(1ULL << 60)
#define ZHPE_USE_OP_FLAGS	(1ULL << 61)
#define ZHPE_TRIGGERED_OP	(1ULL << 62)
#define ZHPE_PROV_FLAGS		(0xFULL << 60)

#define ZHPE_BAD_FLAGS_MASK	(0xFULL << 60)

/* it must be adjusted if error data size in CQ/EQ
 * will be larger than ZHPE_EP_MAX_CM_DATA_SZ */
#define ZHPE_MAX_ERR_CQ_EQ_DATA_SZ ZHPE_EP_MAX_CM_DATA_SZ

enum {
	ZHPE_SIGNAL_RD_FD = 0,
	ZHPE_SIGNAL_WR_FD
};

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

#define ZHPE_RING_TX_CQ_ENTRIES		(16)

struct zhpe_free_index {
	uint32_t		seq;
	uint16_t		index;
	uint16_t		count;
} INT64_ALIGNED;

struct zhpe_rx_tail {
	uint32_t		tail;
	uint32_t		shadow_head;
} INT64_ALIGNED;


#define MS_PER_SEC		(1000UL)
#define US_PER_SEC		(1000000UL)
#define NS_PER_SEC		(1000000000UL)

/* Free entry:on pointer boundary.
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
	struct dlist_entry	lentry;
};

struct zhpe_slab {
	void			*mem;
	uint32_t		size;
	struct dlist_entry	free_list;
	struct zhpe_mr		*zmr;
	int32_t			use_count;
};

struct zhpe_msg_hdr {
	uint16_t		seq;
	uint16_t		pe_entry_id;
	uint8_t			op_type;
	uint8_t			rx_id;
	uint8_t			flags;
	union {
		uint8_t		inline_len;
	};
} __attribute__ ((aligned(4)));

struct zhpe_key {
	uint64_t		key;
	uint8_t			internal;
} __attribute__((aligned(8), packed));

int zhpe_compare_zkeys(void *k1p, void *k2p);

struct zhpe_rkey_data {
	struct zhpe_tx		*ztx;
	struct zhpeq_key_data	*kdata;
	struct zhpe_key		zkey;
	struct dlist_entry	lentry;
	struct zhpe_msg_hdr	ohdr;
	int32_t			use_count;
};

struct zhpe_kexp_data {
	struct zhpe_conn	*conn;
	struct dlist_entry	lentry;
	struct zhpe_key		zkey;
};

struct zhpe_tx {
	struct dlist_entry	pe_lentry;
	struct zhpe_ep_attr	*ep_attr;
	char			*zentries;
	struct zhpe_pe_entry	*pentries;
	struct zhpe_mr		*zmr;
	uint64_t		lz_zentries;
	struct zhpe_free_index	ufree;
	struct zhpe_free_index	pfree;
	struct zhpeq		*zq;
	pthread_mutex_t		mutex;
	uint32_t		mask;
	int32_t			use_count;
	uint32_t		progress;
	struct zhpeu_atm_list_ptr pe_retry_free_list;
	struct zhpeu_atm_snatch_head pe_retry_list;
	struct zhpeu_atm_snatch_head rx_poll_list CACHE_ALIGNED;

};

struct zhpe_rx_common {
	union {
		struct zhpe_mr	*zmr;		/* Local */
		struct zhpe_rkey_data *rkey;	/* Remote. */
	};
	unsigned long		*scoreboard;
	uint32_t		completed;
	uint32_t		mask;
};

/* peer_visible items are stored in network byte order. */
struct zhpe_rx_peer_visible {
	uint32_t		completed;
};

struct zhpe_pe_root;

#define ZHPE_PE_PROV			(0x01)
#define ZHPE_PE_RETRY			(0x02)
#define ZHPE_PE_KEY_WAIT		(0x04)
#define ZHPE_PE_INUSE			(0x08)

struct zhpe_conn;

/* Need to atomically update status and completion in some cases. */
struct zhpe_pe_compstat {
	int16_t			status;
	int8_t			completions;
	uint8_t			flags;
} INT32_ALIGNED;

struct zhpe_pe_root {
	void			(*handler)(struct zhpe_pe_root *pe_root,
					   struct zhpeq_cq_entry *zq_cqe);
	struct zhpe_conn	*conn;
	void			*context;
	struct zhpe_pe_compstat	compstat;
};

struct zhpe_rx_remote {
	struct zhpe_rx_common	cmn;
	uint64_t		rz_zentries;
	uint64_t		rz_peer_visible;
	uint32_t		completed;
	struct zhpe_pe_root	pull_pe_root;
	struct zhpe_rx_tail	tail CACHE_ALIGNED;
	int32_t			pull_busy;
};

struct zhpe_rx_local {
	struct zhpe_rx_common	cmn;
	char			*zentries;
	struct zhpe_rx_peer_visible *peer_visible;
	uint32_t		head;
};

struct zhpe_conn {
	union sockaddr_in46	addr;
	struct zhpe_ep_attr	*ep_attr;
	fi_addr_t		fi_addr;
	struct dlist_entry	ep_lentry;
	struct zhpeu_atm_list_next rx_poll_next;
	struct zhpe_tx_ctx	*tx_ctx;
	struct zhpe_rx_ctx	*rx_ctx;
	fi_addr_t		zq_index;
	struct zhpe_tx		*ztx;
	struct zhpe_rx_local	rx_local;
	struct zhpe_rx_remote	rx_remote;
	/* rkey stuff locked by rx_ctx->mutex */
	RbtHandle		rkey_tree;
	struct dlist_entry	rkey_deferred_list;
	uint16_t		rkey_seq;
	/* kexp stuff locked by tx_ctx->mutex */
	RbtHandle		kexp_tree;
	uint16_t		kexp_seq;

	uint8_t			state;
	bool			local;
	bool			fam;
};

struct zhpe_domain {
	struct util_domain	util_domain;
	struct zhpeq_dom	*zqdom;

	fastlock_t		*mr_lock;
	RbtHandle		mr_tree;
	uint64_t		mr_user_key;
	uint64_t		mr_zhpe_key;
	struct zhpe_pe		*pe;

	int			(*reg_int)(struct zhpe_domain *zdom,
					   const void *buf, size_t len,
					   uint64_t access, uint32_t qaccess,
					   struct fid_mr **mr);
	struct ofi_mr_cache	cache;
	bool			cache_inited;
	bool			mr_events;
};

static inline struct zhpe_domain *fid2zdom(struct fid *fid)
{
	assert(fid->fclass == FI_CLASS_DOMAIN);
	return container_of(fid, struct zhpe_domain,
			    util_domain.domain_fid.fid);
}

static inline struct zhpe_domain *udom2zdom(struct util_domain *dom)
{
	return container_of(dom, struct zhpe_domain, util_domain);
}

static inline struct zhpe_fabric *zdom2zfab(struct zhpe_domain *zdom)
{
	return ufab2zfab(zdom->util_domain.fabric);
}

struct zhpe_trigger {
	struct dlist_entry	lentry;
	struct fi_trigger_threshold threshold;
	struct fid_ep		*fid_ep;
	uint64_t		flags;
	enum fi_op_type		op_type;

	union {
		struct {
			struct fi_msg msg;
			struct iovec msg_iov[ZHPE_EP_MAX_IOV_LIMIT];
			void *desc[ZHPE_EP_MAX_IOV_LIMIT];
		} msg;

		struct {
			struct fi_msg_tagged msg;
			struct iovec msg_iov[ZHPE_EP_MAX_IOV_LIMIT];
			void *desc[ZHPE_EP_MAX_IOV_LIMIT];
		} tmsg;

		struct {
			struct fi_msg_rma msg;
			struct iovec msg_iov[ZHPE_EP_MAX_IOV_LIMIT];
			void *desc[ZHPE_EP_MAX_IOV_LIMIT];
			struct fi_rma_iov rma_iov[ZHPE_EP_MAX_IOV_LIMIT];
		} rma;

		struct {
			struct fi_msg_atomic msg;
			struct fi_ioc msg_iov[ZHPE_EP_MAX_IOV_LIMIT];
			void *desc[ZHPE_EP_MAX_IOV_LIMIT];
			struct fi_rma_ioc rma_iov[ZHPE_EP_MAX_IOV_LIMIT];
			struct fi_ioc comparev[ZHPE_EP_MAX_IOV_LIMIT];
			void *compare_desc[ZHPE_EP_MAX_IOV_LIMIT];
			size_t compare_count;
			struct fi_ioc resultv[ZHPE_EP_MAX_IOV_LIMIT];
			void *result_desc[ZHPE_EP_MAX_IOV_LIMIT];
			size_t result_count;
		} atomic;
	} op;
};

struct zhpe_cntr {
	struct util_cntr	util_cntr;

	fastlock_t		trigger_lock;
	struct dlist_entry	trigger_list;

	/* Keep until we integrate util_ep. */
	fastlock_t		list_lock;
	struct dlist_entry	ep_list;
	struct dlist_entry	rx_list;
	struct dlist_entry	tx_list;
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

static inline struct zhpe_domain *zcntr2zdom(struct zhpe_cntr *zcntr)
{
	return udom2zdom(zcntr->util_cntr.domain);
}

struct zhpe_mr_ops {
	struct fi_ops		fi_ops;
	void			(*get)(struct zhpe_mr *zmr);
	int			(*put)(struct zhpe_mr *zmr);
};

struct zhpe_mr {
	struct fid_mr		mr_fid;
	struct zhpe_domain	*zdom;
	uint64_t		flags;
	struct zhpeq_key_data	*kdata;
	struct dlist_entry	kexp_list;
	struct zhpe_key		zkey;
	int32_t			use_count;
	struct ofi_mr_entry	*entry;
	struct zhpe_mr		*next;
};

static inline struct zhpe_mr *fid2zmr(struct fid *fid)
{
	assert(fid->fclass == FI_CLASS_MR);
	return container_of(fid, struct zhpe_mr, mr_fid.fid);
}

static inline struct zhpe_mr_ops *zmr2zops(struct zhpe_mr *zmr)
{
	return container_of(zmr->mr_fid.fid.ops, struct zhpe_mr_ops, fi_ops);
}

struct zhpe_av_addr {
	union sockaddr_in46	addr;
};

struct zhpe_av_table_hdr {
	uint64_t		size;
	uint64_t		stored;
};

struct zhpe_av {
	struct fid_av av_fid;
	struct zhpe_domain *domain;
	int32_t ref;
	struct fi_av_attr attr;
	uint64_t mask;
	int rx_ctx_bits;
	socklen_t addrlen;
	struct zhpe_eq *eq;
	struct zhpe_av_table_hdr *table_hdr;
	struct zhpe_av_addr *table;
	uint64_t *idx_arr;
	struct util_shm shm;
	int    shared;
	struct dlist_entry ep_list;
	fastlock_t list_lock;
};

static inline struct zhpe_av *fid2zav(struct fid *fid)
{
	assert(fid->fclass == FI_CLASS_AV);
	return container_of(fid, struct zhpe_av, av_fid.fid);
}

static inline struct zhpe_domain *zav2zdom(struct zhpe_av *zav)
{
	return zav->domain;
}

#define ZHPE_MSG_TRANSMIT_COMPLETE	(0x01)
#define ZHPE_MSG_DELIVERY_COMPLETE	(0x02)
#define ZHPE_MSG_REMOTE_CQ_DATA		(0x04)
#define ZHPE_MSG_TAGGED			(0x08)
#define ZHPE_MSG_INLINE			(0x10)
#define ZHPE_MSG_VALID_TOGGLE		(0x80)

#define ZHPE_MSG_ANY_COMPLETE \
	(ZHPE_MSG_TRANSMIT_COMPLETE | ZHPE_MSG_DELIVERY_COMPLETE)

enum {
	/* wire protocol */
        ZHPE_OP_NONE = 0,
	ZHPE_OP_NOP,
	ZHPE_OP_SEND,
	ZHPE_OP_STATUS,

	ZHPE_OP_WRITEDATA,

	ZHPE_OP_ATOMIC,

	ZHPE_OP_KEY_REQUEST,
	ZHPE_OP_KEY_RESPONSE,
	ZHPE_OP_KEY_EXPORT,
	ZHPE_OP_KEY_REVOKE,
	ZHPE_OP_SHUTDOWN,
};

struct zhpe_iov_state {
	struct zhpe_iov_state_ops *ops;
	uint64_t		off;
	void			*viov;
	uint8_t			idx;
	uint8_t			cnt;
	uint8_t			missing;
};

struct zhpe_iov_state_ops {
	void		*(*iov_ptr)(const struct zhpe_iov_state *state);
	uint64_t	(*iov_len)(const struct zhpe_iov_state *state);
	uint64_t	(*iov_zaddr)(const struct zhpe_iov_state *state);
};

struct zhpe_iov {
	union {
		void		*iov_base;
		uint64_t	iov_raddr;
	};
	uint64_t		iov_len;
	union {
		uint64_t	iov_key;
		struct zhpe_rkey_data *iov_rkey;
		struct zhpe_mr	*iov_desc;
	};
	uint64_t		iov_zaddr;
};

extern struct zhpe_iov_state_ops zhpe_iov_state_iovec_ops;
extern struct zhpe_iov_state_ops zhpe_iov_state_ziovl_ops;
extern struct zhpe_iov_state_ops zhpe_iov_state_ziovr_ops;

static inline void zhpe_iov_state_init(struct zhpe_iov_state *state,
				       struct zhpe_iov_state_ops *ops,
				       void *viov)
{
	state->off = 0;
	state->viov = viov;
	state->idx = 0;
	state->cnt = 0;
	state->missing = 0;
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
	return state->ops->iov_ptr(state);
}

static inline uint64_t zhpe_iov_state_len(const struct zhpe_iov_state *state)
{
	if (zhpe_iov_state_empty(state))
		return 0;

	return state->ops->iov_len(state);
}

static inline uint64_t zhpe_iov_state_zaddr(const struct zhpe_iov_state *state)
{
	return state->ops->iov_zaddr(state);
}

uint64_t zhpe_iov_state_adv(struct zhpe_iov_state *state, uint64_t incr);
uint64_t zhpe_iov_state_avail(const struct zhpe_iov_state *state);
size_t copy_iov(struct zhpe_iov_state *dstate, struct zhpe_iov_state *sstate,
		size_t n);
size_t copy_iov_to_mem(void *dst, struct zhpe_iov_state *sstate, size_t n);
size_t copy_mem_to_iov(struct zhpe_iov_state *dstate, const void *src,
		       size_t n);

#define ZHPE_ZIOV_LEN_KEY_INT	(0x8000000000000000UL)

static inline uint64_t zhpe_ziov_len(const struct zhpe_iov *ziov)
{
	return (ziov->iov_len & ~ZHPE_ZIOV_LEN_KEY_INT);
}

static inline void zhpe_ziov_to_zkey(struct zhpe_iov *ziov,
				     struct zhpe_key *zkey)
{
	zkey->key = ziov->iov_key;
	zkey->internal = !!(ziov->iov_len & ZHPE_ZIOV_LEN_KEY_INT);
}

#define ZHPE_MR_ACCESS_ALL \
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

struct zhpe_comp {
	uint8_t send_cq_event;
	uint8_t recv_cq_event;
	char reserved[2];

	struct zhpe_cq	*send_cq;
	struct zhpe_cq	*recv_cq;

	struct zhpe_cntr *send_cntr;
	struct zhpe_cntr *recv_cntr;
	struct zhpe_cntr *read_cntr;
	struct zhpe_cntr *write_cntr;
	struct zhpe_cntr *rem_read_cntr;
	struct zhpe_cntr *rem_write_cntr;

	struct zhpe_eq *eq;
};

struct zhpe_cm_entry {
	int sock;
	int do_listen;
	int signal_fds[2];
	uint64_t next_msg_id;
	fastlock_t lock;
	int is_connected;
	pthread_t listener_thread;
	struct dlist_entry msg_list;
	bool			listener_thread_valid;
};

struct zhpe_conn_listener {
	int sock;
	int do_listen;
	int signal_fds[2];
	pthread_t listener_thread;
	bool			listener_thread_valid;
};

struct zhpe_ep_attr {
	size_t			fclass;
	size_t min_multi_recv;

	int32_t ref;
	struct zhpe_eq *eq;
	struct zhpe_av *av;
	struct zhpe_domain *domain;

	struct zhpe_rx_ctx *rx_ctx;
	struct zhpe_tx_ctx *tx_ctx;

	struct zhpe_rx_ctx **rx_array;
	struct zhpe_tx_ctx **tx_array;
	uint32_t num_rx_ctx;
	uint32_t num_tx_ctx;

	struct dlist_entry rx_ctx_lentry;
	struct dlist_entry tx_ctx_lentry;

	struct fi_info info;
	struct fi_ep_attr ep_attr;

	enum fi_ep_type ep_type;
	union sockaddr_in46	src_addr;
	union sockaddr_in46	dest_addr;
	in_port_t		msg_src_port;
	in_port_t		msg_dest_port;

	bool			is_enabled;
	bool			rma_event;
	struct zhpe_cm_entry cm;
	struct zhpe_conn_listener listener;

	pthread_mutex_t		conn_mutex;
	pthread_cond_t		conn_cond;
	struct dlist_entry	conn_list;
	struct index_map	av_idm;

	/* Lower-level data */
	struct zhpe_tx		*ztx;
	/* We need to get back to the ep and it less pain to have a pointer.
	 * I have no clue why the ep_attr is where everything hides.
	 */
	struct zhpe_ep		*ep;
	struct fi_zhpe_ep_counters counters;
};

struct zhpe_ep {
	struct fid_ep ep;
	struct fi_tx_attr tx_attr;
	struct fi_rx_attr rx_attr;
	struct zhpe_ep_attr *attr;
};

static inline struct zhpe_ep *fid2zep(struct fid *fid)
{
	assert(fid->fclass == FI_CLASS_EP);
	return container_of(fid, struct zhpe_ep, ep.fid);
}

static inline struct zhpe_domain *zep2zdom(struct zhpe_ep *zep)
{
	return zep->attr->domain;
}

struct zhpe_pep {
	struct fid_pep		pep;
	struct zhpe_fabric	*zhpe_fab;
	struct zhpe_cm_entry	cm;
        union sockaddr_in46	src_addr;
	struct fi_info		info;
	struct zhpe_eq		*eq;
	int			name_set;
};

struct zhpe_pe_retry;
typedef void (*zhpe_pe_retry_handler)(struct zhpe_pe_retry *pe_retry);

struct zhpe_pe_retry {
	struct zhpeu_atm_list_next next;
	zhpe_pe_retry_handler	handler;
	void			*data;
	void			(*freedata)(void *data);
};

enum zhpe_rx_state {
	ZHPE_RX_STATE_IDLE,
	ZHPE_RX_STATE_INLINE,
	ZHPE_RX_STATE_RND_BUF,
	ZHPE_RX_STATE_RND_DIRECT,
	ZHPE_RX_STATE_EAGER,
	ZHPE_RX_STATE_EAGER_CLAIMED,
	ZHPE_RX_STATE_EAGER_DONE,
	ZHPE_RX_STATE_DISCARD,
};

struct zhpe_rx_entry_free {
	struct zhpe_rx_ctx	*rx_ctx;
	struct zhpeu_atm_list_ptr rx_fifo_list;
	struct ofi_bufpool	*rx_entry_pool;
};

struct zhpe_rx_entry {
	struct dlist_entry	lentry;
	struct zhpe_rx_entry_free *rx_free;
	struct zhpeu_atm_list_next rx_match_next;
	struct zhpeu_atm_list_next rx_iodone_next;
	struct zhpe_rx_entry	*rx_user;
	struct zhpe_conn	*conn;
	void			*context;
	struct zhpe_pe_entry	*pe_entry;

	uint64_t		flags;
	uint64_t		addr;
	uint64_t		cq_data;
	uint64_t		tag;
	uint64_t		ignore;
	uint64_t		total_len;
	uint64_t		rem;
	void			*buf;
	struct zhpe_msg_hdr	zhdr;

	struct zhpe_iov_state	lstate;
	struct zhpe_iov		liov[ZHPE_EP_MAX_IOV_LIMIT];
	union {
		int32_t		multi_cnt;
		char		inline_data[ZHPE_RING_ENTRY_LEN];
	};
	int			status;
	uint8_t			rx_state;
	bool			slab;
};

struct zhpe_rx_ctx {
	struct fid_ep		ctx;
	pthread_mutex_t		mutex;
	struct zhpe_ep_attr	*ep_attr;
	struct zhpe_av		*av;
	struct zhpe_eq		*eq;
 	struct zhpe_domain	*domain;
	struct dlist_entry	pe_lentry;
	struct dlist_entry	cq_lentry;
	struct zhpe_comp	comp;

	struct fi_rx_attr	attr;
	uint8_t			rx_id;
	bool			enabled;

	struct zhpe_slab	eager;
	size_t			min_multi_recv;
	struct dlist_entry	rx_posted_list;
	struct dlist_entry	rx_buffered_list;
	struct dlist_entry	rx_work_list;

	struct zhpe_rx_entry_free rx_user_free CACHE_ALIGNED;
	struct zhpeu_atm_snatch_head rx_match_list;
	struct zhpeu_atm_snatch_head rx_iodone_list;
	uint32_t		tx_progress_last;
	struct zhpe_rx_entry_free rx_prog_free CACHE_ALIGNED;
};

struct zhpe_tx_ctx {
	struct fid_ep		ctx;
	pthread_mutex_t		mutex;
	struct zhpe_ep_attr	*ep_attr;
	struct zhpe_av		*av;
	struct zhpe_eq		*eq;
 	struct zhpe_domain	*domain;
	struct dlist_entry	pe_lentry;
	struct dlist_entry	cq_lentry;
	struct zhpe_comp	comp;

	struct fi_tx_attr	attr;
	uint8_t			tx_id;
	bool			enabled;
};

struct zhpe_msg_send_indirect {
	uint64_t		tag;
	uint64_t		cq_data;
	uint64_t		vaddr;
	uint64_t		len;
	uint64_t		key;
	char			end[0];
};

struct zhpe_msg_key_request {
	/* ZHPE_EP_MAX_IOV_LIMIT currently 1, max 4 */
	struct zhpe_key		zkeys[ZHPE_EP_MAX_IOV_LIMIT];
	char			end[0];
};

struct zhpe_msg_key_data {
	uint64_t		key;
	char			blob[ZHPEQ_KEY_BLOB_MAX];
};

/* Must fit in 32 bytes for put-immediate-based implementation. */
struct zhpe_msg_status {
	uint64_t		rem;
	int16_t			status;
	uint8_t			rem_valid;
	char			end[0];
};

struct zhpe_msg_atomic_req {
	uint64_t		operands[2];
	uint64_t		vaddr;
	struct zhpe_key		zkey;
	uint8_t			op;
	uint8_t			datatype;
	uint8_t			datasize;
	char			end[0];
};

struct zhpe_msg_writedata {
	uint64_t		flags;
	uint64_t		cq_data;
	char			end[0];
};

/* This structure can only be 40 bytes to fit in ENQA with 8-byte alignment.
 * However, there are 4 bytes free between the header and payload, in that
 * case. It will be used for inline sends, but nothing else, at the moment.
 */
union zhpe_msg_payload {
	struct zhpe_msg_send_indirect indirect;
	struct zhpe_msg_status	status;
	struct zhpe_msg_atomic_req atomic_req;
	struct zhpe_msg_writedata writedata;
	struct zhpe_msg_key_request key_req;
	struct zhpe_msg_key_data key_data;
};

/* PE entry type */

struct zhpe_cqe {
	fi_addr_t		addr;
	struct zhpe_comp	*comp;
	struct fi_cq_tagged_entry cqe;
};

struct zhpe_pe_entry {
	struct zhpe_pe_root	pe_root;
	uint64_t		flags;
	uint64_t		rem;
	struct zhpe_iov_state	lstate;
	struct zhpe_iov_state   rstate;
	struct zhpe_iov		liov[ZHPE_EP_MAX_IOV_LIMIT];
	struct zhpe_iov		riov[ZHPE_EP_MAX_IOV_LIMIT];
	union {
		char		inline_data[ZHPEQ_IMM_MAX];
		struct {
			void	*result;
			uint64_t atomic_operands[2];
			uint8_t atomic_op;
			uint8_t atomic_size;
			uint8_t	result_type;
		};
	};
	uint64_t		cq_data;
	uint8_t			rx_id;
};

struct zhpe_pe {
	struct zhpeu_work_head	work_head;
	struct zhpe_domain	*domain;
	int64_t			waittime;

	bool			(*progress_queue)(struct zhpe_tx *ztx);
	bool			(*progress_rx)(struct zhpe_rx_ctx *rx_ctx);

	struct dlist_entry	queue_list;
	struct dlist_entry	rx_list;

	pthread_t		progress_thread;
	bool			do_progress;
};

struct zhpe_cq {
	struct util_cq		util_cq;

	/* Keep until we integrate util_ep. */
	fastlock_t		list_lock;
	struct dlist_entry	ep_list;
	struct dlist_entry	rx_list;
	struct dlist_entry	tx_list;
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

static inline struct zhpe_domain *zcq2zdom(struct zhpe_cq *zcq)
{
	return udom2zdom(zcq->util_cq.domain);
}

struct zhpe_conn_hdr {
	uint8_t type;
	uint8_t reserved[3];
	uint16_t port;
	uint16_t cm_data_sz;
	/* cm data follows cm_data_sz */
};

struct zhpe_conn_req {
	struct zhpe_conn_hdr	hdr;
	union sockaddr_in46	src_addr;
	uint64_t		caps;
	char			cm_data[0];
};

enum {
	ZHPE_CONN_REQ,
	ZHPE_CONN_ACCEPT,
	ZHPE_CONN_REJECT,
	ZHPE_CONN_SHUTDOWN,
};

struct zhpe_conn_req_handle {
	struct fid		handle;
	struct zhpe_conn_req	*req;
	int			zhpe_fd;
	int			is_accepted;
	struct zhpe_pep		*pep;
	struct zhpe_ep		*ep;
	size_t			paramlen;
	pthread_t		req_handler;
	union sockaddr_in46	dest_addr;
	struct dlist_entry	lentry;
	char			cm_data[ZHPE_EP_MAX_CM_DATA_SZ];
	bool			req_handler_valid;
};

struct zhpe_host_list_entry {
	char hostname[HOST_NAME_MAX];
	struct slist_entry entry;
};

extern pthread_mutex_t zhpe_fabdom_close_mutex;

void fi_zhpe_fini(void);
int zhpe_getinfo(uint32_t api_version, const char *node, const char *service,
		 uint64_t flags, const struct fi_info *hints,
		 struct fi_info **info);
int zhpe_fabric(struct fi_fabric_attr *attr, struct fid_fabric **fabric,
		void *context);

int zhpe_domain(struct fid_fabric *fabric, struct fi_info *info,
		struct fid_domain **dom, void *context);

int zhpe_query_atomic(struct fid_domain *domain,
		      enum fi_datatype datatype, enum fi_op op,
		      struct fi_atomic_attr *attr, uint64_t flags);

int zhpe_alloc_endpoint(struct zhpe_domain *zhpe_dom,
			struct fi_info *prov_info, struct fi_info *info,
			struct zhpe_ep **ep, void *context, size_t fclass);
int zhpe_msg_passive_ep(struct fid_fabric *fabric, struct fi_info *info,
			struct fid_pep **pep, void *context);
int zhpe_ep_enable(struct fid_ep *ep);
int zhpe_ep_disable(struct fid_ep *ep);

int zhpe_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr,
		 struct fid_cq **cq, void *context);
int zhpe_cq_report_success(struct util_cq *cq, struct fi_cq_tagged_entry *tcqe);
int zhpe_cq_report_error(struct util_cq *cq, struct fi_cq_tagged_entry *tcqe,
			 size_t olen, int err, int prov_err,
			 const void *err_data, size_t err_data_size);
void zhpe_cq_add_tx_ctx(struct zhpe_cq *cq, struct zhpe_tx_ctx *tx_ctx);
void zhpe_cq_remove_tx_ctx(struct zhpe_cq *cq, struct zhpe_tx_ctx *tx_ctx);
void zhpe_cq_add_rx_ctx(struct zhpe_cq *cq, struct zhpe_rx_ctx *rx_ctx);
void zhpe_cq_remove_rx_ctx(struct zhpe_cq *cq, struct zhpe_rx_ctx *rx_ctx);


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
void zhpe_cntr_add_tx_ctx(struct zhpe_cntr *cntr, struct zhpe_tx_ctx *tx_ctx);
void zhpe_cntr_remove_tx_ctx(struct zhpe_cntr *cntr,
			     struct zhpe_tx_ctx *tx_ctx);
void zhpe_cntr_add_rx_ctx(struct zhpe_cntr *cntr, struct zhpe_rx_ctx *rx_ctx);
void zhpe_cntr_remove_rx_ctx(struct zhpe_cntr *cntr,
			     struct zhpe_rx_ctx *rx_ctx);

struct zhpe_rx_ctx *
zhpe_rx_ctx_alloc(const struct fi_rx_attr *attr, void *context,
		  struct zhpe_domain *domain);

void zhpe_rx_ctx_free(struct zhpe_rx_ctx *rx_ctx);

struct zhpe_tx_ctx *zhpe_tx_ctx_alloc(const struct fi_tx_attr *attr,
				      void *context);
void zhpe_tx_ctx_free(struct zhpe_tx_ctx *tx_ctx);

int zhpe_av_open(struct fid_domain *domain, struct fi_av_attr *attr,
		 struct fid_av **av, void *context);
int zhpe_av_compare_addr(struct zhpe_av *av, fi_addr_t addr1, fi_addr_t addr2);
int zhpe_av_get_addr_index(struct zhpe_av *av, const void *addr,
			   size_t *av_index);
int zhpe_av_get_addr(struct zhpe_av *av, size_t av_index,
		     union sockaddr_in46 *sa);

int zhpe_ep_get_conn(struct zhpe_ep_attr *ep_attr, fi_addr_t index,
		     struct zhpe_conn **pconn);
int zhpe_ep_connect(struct zhpe_ep_attr *attr, struct zhpe_conn *conn);
struct zhpe_conn *zhpe_conn_lookup(struct zhpe_ep_attr *ep_attr,
				   const union sockaddr_in46 *addr,
				   bool local);
struct zhpe_conn *zhpe_conn_insert(struct zhpe_ep_attr *ep_attr,
				   const union sockaddr_in46 *addr,
				   bool local);
ssize_t zhpe_conn_send_src_addr(struct zhpe_ep_attr *ep_attr,
				struct zhpe_tx_ctx *tx_ctx,
				struct zhpe_conn *conn);
int zhpe_conn_listen(struct zhpe_ep_attr *ep_attr);
void zhpe_conn_release_entry(struct zhpe_ep_attr *attr,
			     struct zhpe_conn *conn);
void zhpe_conn_list_destroy(struct zhpe_ep_attr *attr);
int zhpe_set_sockopts_connect(int sock);
int zhpe_set_sockopts_listen(int sock);
int zhpe_set_sockopts_accept(int sock);
int zhpe_set_sockopt_reuseaddr(int sock);
int zhpe_set_sockopt_nodelay(int sock);
int zhpe_set_fd_cloexec(int fd);
int zhpe_set_fd_nonblock(int fd);
int zhpe_listen(const struct fi_info *info,
		union sockaddr_in46 *ep_addr, int backlog);

int zhpe_conn_z_setup(struct zhpe_conn *conn, int conn_fd);
int zhpe_conn_fam_setup(struct zhpe_conn *conn);
void zhpe_conn_z_free(struct zhpe_conn *conn);
void zhpe_send_status_rem(struct zhpe_conn *conn,
			  struct zhpe_msg_hdr ohdr, int32_t status,
			  uint64_t rem);
void zhpe_send_status(struct zhpe_conn *conn,
		      struct zhpe_msg_hdr ohdr, int32_t status);
void zhpe_send_key_revoke(struct zhpe_conn *conn, const struct zhpe_key *zkey);
void zhpe_pe_complete_key_response(struct zhpe_conn *conn,
				   struct zhpe_msg_hdr ohdr, int rc);

static inline void zhpe_pe_signal(struct zhpe_pe *pe)
{
	zhpeu_thr_wait_signal(&pe->work_head.thr_wait);
}

struct zhpe_pe *zhpe_pe_init(struct zhpe_domain *domain);
void zhpe_pe_add_queue(struct zhpe_tx *ztx);
void zhpe_pe_add_tx_ctx(struct zhpe_tx_ctx *tx_ctx);
void zhpe_pe_add_rx_ctx(struct zhpe_rx_ctx *rx_ctx);
void zhpe_pe_progress_tx_ctx(struct zhpe_pe *pe, struct zhpe_tx_ctx *tx_ctx);
void zhpe_pe_progress_rx_ctx(struct zhpe_pe *pe, struct zhpe_rx_ctx *rx_ctx);
void zhpe_pe_remove_queue(struct zhpe_tx *ztx);
void zhpe_pe_remove_tx_ctx(struct zhpe_tx_ctx *tx_ctx);
void zhpe_pe_remove_rx_ctx(struct zhpe_rx_ctx *rx_ctx);
void zhpe_pe_finalize(struct zhpe_pe *pe);
void zhpe_pe_tx_handle_entry(struct zhpe_pe_root *pe_root,
			     struct zhpeq_cq_entry *zq_cqe);
void zhpe_pe_rx_peek_recv(struct zhpe_rx_ctx *rx_ctx, fi_addr_t addr,
			  uint64_t tag, uint64_t ignore,
			  uint64_t flags, struct fi_context *context);
void zhpe_pe_rx_claim_recv(struct zhpe_rx_entry *rx_claimed,
			   struct zhpe_rx_entry *rx_entry);
void zhpe_pe_rx_post_recv(struct zhpe_rx_ctx *rx_ctx,
			  struct zhpe_rx_entry *rx_entry);
void zhpe_pe_rx_post_recv_multi(struct zhpe_rx_ctx *rx_ctx,
				struct zhpe_rx_entry *rx_entry);
void zhpe_pe_rx_complete(struct zhpe_rx_ctx *rx_ctx,
			 struct zhpe_rx_entry *rx_entry, int status);
void zhpe_pe_tx_rma_completion(struct zhpe_pe_entry *pe_entry);
void zhpe_pe_tx_handle_rma(struct zhpe_pe_root *pe_root,
			   struct zhpeq_cq_entry *zq_cqe);
void zhpe_pe_tx_handle_atomic(struct zhpe_pe_root *pe_root,
			      struct zhpeq_cq_entry *zq_cqe);
void zhpe_pe_tx_handle_hw_atomic(struct zhpe_pe_root *pe_root,
				 struct zhpeq_cq_entry *zq_cqe);
int zhpe_pe_tx_hw_atomic(struct zhpe_pe_entry *pe_entry);
void zhpe_pe_rkey_request(struct zhpe_conn *conn, struct zhpe_msg_hdr ohdr,
			  struct zhpe_iov_state *rstate, int8_t *completions);

ssize_t zhpe_do_recvmsg(struct fid_ep *ep, const void *vmsg, uint64_t flags,
			bool tagged);
ssize_t zhpe_do_sendmsg(struct fid_ep *ep, const void *vmsg, uint64_t flags,
			bool tagged);
ssize_t zhpe_do_rma_msg(struct fid_ep *ep, const struct fi_msg_rma *msg,
			uint64_t flags);
ssize_t zhpe_do_tx_atomic(struct fid_ep *ep,
			  const struct fi_msg_atomic *msg,
			  const struct fi_ioc *comparev, void **compare_desc,
			  size_t compare_count, struct fi_ioc *resultv,
			  void **result_desc, size_t result_count,
			  uint64_t flags);

int zhpe_queue_work(struct zhpe_domain *dom, struct fi_deferred_work *work);
ssize_t zhpe_queue_rma_op(struct fid_ep *ep, const struct fi_msg_rma *msg,
			  uint64_t flags, enum fi_op_type op_type);
ssize_t zhpe_queue_atomic_op(struct fid_ep *ep,
			     const struct fi_msg_atomic *msg,
			     const struct fi_ioc *comparev,
			     size_t compare_count,
			     struct fi_ioc *resultv, size_t result_count,
			     uint64_t flags, enum fi_op_type op_type);
ssize_t zhpe_queue_tmsg_op(struct fid_ep *ep, const struct fi_msg_tagged *msg,
			   uint64_t flags, enum fi_op_type op_type);
ssize_t zhpe_queue_msg_op(struct fid_ep *ep, const struct fi_msg *msg,
			  uint64_t flags, enum fi_op_type op_type);
ssize_t zhpe_queue_cntr_op(struct fi_deferred_work *work, uint64_t flags);
void zhpe_cntr_check_trigger_list(struct zhpe_cntr *cntr);

int zhpe_tx_free_res(struct zhpe_conn *conn, int64_t tindex, int64_t zindex,
		     int64_t rindex, uint8_t pe_flags);
int zhpe_slab_init(struct zhpe_slab *mem, size_t size,
		   struct zhpe_domain *domain);
void zhpe_slab_destroy(struct zhpe_slab *mem);
int zhpe_slab_alloc(struct zhpe_slab *slab, size_t size, struct zhpe_iov *iov);
void zhpe_slab_free(struct zhpe_slab *mem, void *ptr);
int zhpe_iov_op_get(struct zhpeq *zq, uint32_t zindex, bool fence,
		    void *lptr, uint64_t lza, size_t len, uint64_t rza,
		    void *context);
int zhpe_iov_op_get_imm(struct zhpeq *zq, uint32_t zindex, bool fence,
			void *lptr, uint64_t lza, size_t len, uint64_t rza,
			void *context);
int zhpe_iov_op_put(struct zhpeq *zq, uint32_t zindex, bool fence,
		    void *lptr, uint64_t lza, size_t len, uint64_t rza,
		    void *context);
int zhpe_iov_op(struct zhpe_pe_root *pe_root,
		struct zhpe_iov_state *lstate,
		struct zhpe_iov_state *rstate,
		size_t max_bytes, uint8_t max_ops,
		int (*op)(struct zhpeq *zq, uint32_t zindex, bool fence,
			  void *lptr, uint64_t lza, size_t len,
			  uint64_t rza, void *context),
		size_t *rem);
int zhpe_put_imm_to_iov(struct zhpe_pe_root *pe_root, void *lbuf,
			size_t llen, struct zhpe_iov_state *rstate,
			size_t *rem);
int zhpe_iov_to_get_imm(struct zhpe_pe_root *pe_root,
			size_t llen, struct zhpe_iov_state *rstate,
			size_t *rem);

#define ZHPE_MR_KEY_INT		(ZHPEQ_MR_FLAG1)

int zhpe_zmr_reg(struct zhpe_domain *domain, const void *buf,
		 size_t len, uint32_t qaccess, uint64_t key,
		 struct zhpe_mr *zmr, struct zhpe_mr_ops *ops);
int zhpe_zmr_put_uncached(struct zhpe_mr *zmr);

int zhpe_mr_reg_int_uncached(struct zhpe_domain *domain, const void *buf,
			     size_t len, uint64_t access, uint32_t qaccess,
			     struct fid_mr **mr);
int zhpe_mr_reg_int_iov(struct zhpe_domain *domain,
			struct zhpe_iov_state *state);
int zhpe_mr_close(struct fid *fid);

#define ZHPE_CONTEXT_IGNORE	((uintptr_t)1)
#define ZHPE_CONTEXT_IGNORE_PTR	((void *)ZHPE_CONTEXT_IGNORE)

int __zhpe_conn_pull(struct zhpe_conn *conn);

static inline uint32_t _zhpe_rx_tail_inuse(struct zhpe_rx_tail cur)
{
	return (cur.tail - cur.shadow_head);
}

static inline uint32_t zhpe_rx_tail_inuse(struct zhpe_rx_tail *tailp)
{
	return _zhpe_rx_tail_inuse(atm_load_rlx(tailp));
}

static inline void
zhpe_conn_pull(struct zhpe_conn *conn)
{
	int			rc;
	const uint32_t		threshold = (conn->rx_remote.cmn.mask + 1) / 4;

	/* Check if we want to pull; threshold is pulled out of the air. */
	if (zhpe_rx_tail_inuse(&conn->rx_remote.tail) < threshold)
		goto done;
	/* Is there a pull in progress or, given that atomic is a CPU fence,
	 * has shadow_head updated?
	 */
	if (atm_inc(&conn->rx_remote.pull_busy) == 1 ||
	    zhpe_rx_tail_inuse(&conn->rx_remote.tail) < threshold) {
		/* Yes. */
		atm_dec(&conn->rx_remote.pull_busy);
		goto done;
	}
	rc = __zhpe_conn_pull(conn);
	if (rc < 0)
		atm_dec(&conn->rx_remote.pull_busy);
 done:
	return;
}

static inline int64_t zhpe_tx_reserve(struct zhpe_tx *ztx, uint8_t pe_flags)
{
	int64_t			ret;
	struct zhpe_free_index	*freep;
	struct zhpe_free_index	old;
	struct zhpe_free_index	new;
	struct zhpe_pe_entry	*pe_entry;

	freep = ((pe_flags & ZHPE_PE_PROV) ? &ztx->pfree : &ztx->ufree);
	for (old = atm_load_rlx(freep) ;;) {
		if (!old.count) {
			ret = -FI_EAGAIN;
			goto done;
		}
		pe_entry = &ztx->pentries[old.index];
		new.index = pe_entry->pe_root.compstat.status;
		new.count = old.count - 1;
		new.seq = old.seq + 1;
		if (atm_cmpxchg(freep, &old, new))
			break;
	}
	ret = old.index;
	pe_entry->pe_root.compstat.flags = ZHPE_PE_INUSE;
	zhpe_iov_state_init(&pe_entry->lstate, &zhpe_iov_state_ziovl_ops,
			    pe_entry->liov);
	zhpe_iov_state_init(&pe_entry->rstate, &zhpe_iov_state_ziovr_ops,
			    pe_entry->riov);
 done:
	return ret;
}

static inline int zhpe_mr_put(struct zhpe_mr *zmr)
{
	if (!zmr)
		return 0;

	return zmr2zops(zmr)->put(zmr);
}

static inline void zhpe_tx_put(struct zhpe_tx *ztx)
{
	int32_t			old;
	extern void zhpe_tx_free(struct zhpe_tx *ztx);


	if (!ztx)
		return;
	old = atm_dec(&ztx->use_count);
	assert(old > 0);
	if (old > 1)
		return;

	zhpe_tx_free(ztx);
}

void zhpe_rkey_free(struct zhpe_rkey_data *rkey);

static inline void zhpe_rkey_put(struct zhpe_rkey_data *rkey)
{
	int32_t			old;

	if (!rkey)
		return;
	old = atm_dec(&rkey->use_count);
	assert(old > 0);
	if (old > 1)
		return;

	zhpe_rkey_free(rkey);
}

static inline void zhpe_lstate_release(struct zhpe_iov_state *lstate)
{
	uint			missing = lstate->missing;
	struct zhpe_iov		*ziov = lstate->viov;
	int			i;

	for (i = ffs(missing) - 1; i >= 0;
	     (missing &= ~(1U << i), i = ffs(missing) - 1))
		zhpe_mr_put(ziov[i].iov_desc);
}

static inline void zhpe_rstate_release(struct zhpe_iov_state *rstate)
{
	struct zhpe_iov		*ziov = rstate->viov;
	int			i;

	for (i = 0; i < rstate->cnt; i++) {
		if (rstate->missing & (1U << i))
			continue;
		zhpe_rkey_put(ziov[i].iov_rkey);
	}
}

static inline void
zhpe_tx_release(struct zhpe_pe_entry *pe_entry)
{
	struct zhpe_conn	*conn = pe_entry->pe_root.conn;
	struct zhpe_tx		*ztx = conn->ztx;
	uint32_t		tindex;
	struct zhpe_free_index	*freep;
	struct zhpe_free_index	old;
	struct zhpe_free_index	new;

	pe_entry->pe_root.compstat.flags &= ~ZHPE_PE_INUSE;

	zhpe_lstate_release(&pe_entry->lstate);
	zhpe_rstate_release(&pe_entry->rstate);

	tindex = pe_entry - ztx->pentries;
	freep = ((pe_entry->pe_root.compstat.flags & ZHPE_PE_PROV) ?
		 &ztx->pfree : &ztx->ufree);
	for (old = atm_load_rlx(freep) ;;) {
		pe_entry->pe_root.compstat.status = old.index;
		new.index = tindex;
		new.count = old.count + 1;
		new.seq = old.seq + 1;
		if (atm_cmpxchg(freep, &old, new))
			break;
	}
}

static inline uint32_t
zhpe_rx_remote_avail(struct zhpe_rx_remote *rx_ringr)
{
	/* Can be stale, but never too large. */
	return rx_ringr->cmn.mask + 1 - zhpe_rx_tail_inuse(&rx_ringr->tail);
}

static inline size_t zhpe_ring_off(struct zhpe_conn *conn, uint32_t index)
{
	return ZHPE_RING_ENTRY_LEN * index;
}

static inline void *
zhpe_pay_ptr(struct zhpe_conn *conn, struct zhpe_msg_hdr *zhdr,
	     size_t off, size_t alignment)
{
	off += ofi_get_aligned_size(sizeof(*zhdr), sizeof(int));
	off = ofi_get_aligned_size(off, alignment);

	return (char *)zhdr + off;
}

#define zhpe_tx_reserve_vars(_ret, _handler, _conn, _context,		\
			     _tindex, _pe_entry, _zhdr, _lzaddr, _err,	\
			     _pe_flags)					\
do {									\
	struct zhpe_tx		*_ztx = (_conn)->ztx;			\
	size_t			_off;					\
									\
	(_ret) = 0;							\
	if (!zhpe_rx_remote_avail(&(_conn)->rx_remote))			\
		(_ret) = -FI_EAGAIN;					\
	if ((_ret) >= 0)						\
		(_ret) = zhpe_tx_reserve(_ztx, (_pe_flags));		\
	if ((_ret) >= 0) {						\
		(_tindex) = (_ret);					\
		_off = zhpe_ring_off(conn, (_tindex));			\
		(_lzaddr) = _ztx->lz_zentries + _off;			\
		(_zhdr) = (void *)(_ztx->zentries + _off);		\
		(_pe_entry) = &_ztx->pentries[(_tindex)];		\
	} else if ((_pe_flags) & ZHPE_PE_RETRY) {			\
		if ((_ret) != -FI_EAGAIN)				\
			goto _err; 					\
		(_ret) = -FI_ENOMEM;					\
		(_pe_entry) = malloc(sizeof(*(_pe_entry)) +		\
				     ZHPE_RING_ENTRY_LEN);		\
		if (!(_pe_entry))					\
			goto _err;					\
		(_zhdr) = (void *)((_pe_entry) + 1);			\
		(_pe_entry)->pe_root.compstat.flags = ZHPE_PE_RETRY;	\
	} else								\
		goto _err;						\
	(_pe_entry)->pe_root.handler = (_handler);			\
	(_pe_entry)->pe_root.conn = (_conn);				\
	(_pe_entry)->pe_root.context = (_context);			\
	(_pe_entry)->pe_root.compstat.status = 0;			\
	(_pe_entry)->pe_root.compstat.completions = 1;			\
	(_pe_entry)->pe_root.compstat.flags |=				\
		((_pe_flags) & ~ZHPE_PE_RETRY);				\
} while (0)

static inline int64_t
zhpe_rx_remote_reserve(struct zhpe_conn *conn, struct zhpe_msg_hdr *hdr)
{
	int64_t			ret = -FI_EAGAIN;
	struct zhpe_rx_remote	*rx_ringr = &conn->rx_remote;
	uint32_t		rlen = conn->rx_remote.cmn.mask + 1;
	struct zhpe_rx_tail	old;
	struct zhpe_rx_tail	new;
	uint32_t		avail;

	for (old = atm_load_rlx(&rx_ringr->tail) ;;) {
		avail = rlen - _zhpe_rx_tail_inuse(old);
		if (!avail)
			goto done;
		new.tail = old.tail + 1;
		new.shadow_head = old.shadow_head;
		if (atm_cmpxchg(&rx_ringr->tail, &old, new))
			break;
	}
	ret = (old.tail & rx_ringr->cmn.mask);
	if (old.tail & rlen)
	    hdr->flags &= ~ZHPE_MSG_VALID_TOGGLE;
	else
	    hdr->flags |= ZHPE_MSG_VALID_TOGGLE;
 done:
	return ret;
}

static inline uint32_t
zhpe_rx_scoreboard(struct zhpe_rx_common *rx_cmn, uint32_t rindex,
		   uint32_t completed)
{
	const uint32_t		bits = sizeof(*rx_cmn->scoreboard) * CHAR_BIT;
	const uint32_t		shift_mask = bits - 1;
	uint32_t		sindex;
	uint64_t		smask;

	/* Update scoreboard bitmask for completed op; only updated and
	 * checked from the progress thread.
	 */
	smask = (1UL << (rindex & shift_mask));
	sindex = rindex / bits;
	rx_cmn->scoreboard[sindex] |= smask;
	/* Try to advance completed. */
	for (;; completed++) {
		rindex = (completed & rx_cmn->mask);
		smask = (1UL << (rindex & shift_mask));
		sindex = rindex / bits;
		if (!(rx_cmn->scoreboard[sindex] & smask))
			break;
		rx_cmn->scoreboard[sindex] &= ~smask;
	}

	return completed;
}

static inline void
zhpe_rx_local_release(struct zhpe_conn *conn, uint32_t rindex)
{
	uint32_t		*comp =
		&conn->rx_local.peer_visible->completed;
	uint32_t		completed;

	completed = ntohl(atm_load_rlx(comp));
	completed = zhpe_rx_scoreboard(&conn->rx_local.cmn, rindex, completed);
	atm_store_rlx(comp, htonl(completed));
}

static inline bool
zhpe_rx_match_entry(struct zhpe_rx_entry *rx_entry, bool entry_buffered,
		    fi_addr_t addr, uint64_t tag, uint64_t ignore,
		    uint64_t flags)
{
	fi_addr_t		oaddr;

	if ((rx_entry->flags & FI_TAGGED) != (flags & FI_TAGGED))
		return false;
	if ((rx_entry->tag & ~ignore) != (tag & ~ignore))
		return false;
	if (entry_buffered) {
		/* addr is from user and sanitized. */
		if (addr == FI_ADDR_UNSPEC)
			return true;
		oaddr = rx_entry->conn->fi_addr;
		/* Racing, but do_recvmsg will fix it. */
		if (oaddr == FI_ADDR_NOTAVAIL)
			return false;
	} else {
		/* rx_entry->addr is from user and sanitized */
		oaddr = rx_entry->addr;
		if (oaddr == FI_ADDR_UNSPEC)
			return true;
		/* Racing, but do_recvmsg will fix it. */
		if (addr == FI_ADDR_NOTAVAIL)
			return false;
	}

	/* XXX: Allow different fi_addrs with the same address? */
	return (addr == oaddr);
}

static inline void zhpe_pe_retry_insert(struct zhpe_tx *ztx,
					struct zhpe_pe_retry *pe_retry)
{
	zhpeu_atm_snatch_insert(&ztx->pe_retry_list, &pe_retry->next);
}

static inline void zhpe_pe_retry_free(struct zhpe_tx *ztx,
				      struct zhpe_pe_retry *pe_retry)
{
	if (pe_retry->freedata)
		pe_retry->freedata(pe_retry->data);
	zhpeu_atm_fifo_push(&ztx->pe_retry_free_list, &pe_retry->next);
}

static inline int zhpe_pe_retry(struct zhpe_tx *ztx,
				zhpe_pe_retry_handler handler, void *data,
				void (*freedata)(void *data))
{
	struct zhpe_pe_retry	*pe_retry;
	struct zhpeu_atm_list_next *next;


	next = zhpeu_atm_fifo_pop(&ztx->pe_retry_free_list);
	if (next)
		pe_retry = container_of(next, struct zhpe_pe_retry, next);
	else
		pe_retry = malloc(sizeof(*pe_retry));
	if (!pe_retry)
		return -FI_ENOMEM;

	pe_retry->handler = handler;
	pe_retry->data = data;
	pe_retry->freedata = freedata;
	zhpe_pe_retry_insert(ztx, pe_retry);

	return 0;
}

void zhpe_pe_retry_tx_ring1(struct zhpe_pe_retry *pe_retry);
void zhpe_pe_retry_tx_ring2(struct zhpe_pe_retry *pe_retry);

#define ZHPE_MASK_COMPLETE \
	(FI_INJECT_COMPLETE | FI_TRANSMIT_COMPLETE | FI_DELIVERY_COMPLETE)

static inline uint64_t
zhpe_tx_fixup_completion(uint64_t flags, uint64_t op_flags,
			 struct zhpe_tx_ctx *tx_ctx)
{
	/* Not sendmsg (no OP_FLAGS) or no selective completion, default to
	 * FI_TRANSMIT_COMPLETE.
	 */
	if (flags & ZHPE_USE_OP_FLAGS)
		flags |= op_flags | FI_TRANSMIT_COMPLETE;
	else if (!tx_ctx->comp.send_cq_event)
		flags |= FI_TRANSMIT_COMPLETE;
	if (flags & FI_DELIVERY_COMPLETE)
		flags &= ~(FI_INJECT_COMPLETE | FI_TRANSMIT_COMPLETE);
	else if (flags & FI_TRANSMIT_COMPLETE)
		flags &= ~FI_INJECT_COMPLETE;

	return flags;
}

void _zhpe_pe_tx_report_complete(const struct zhpe_pe_entry *pe_entry);

static inline void zhpe_pe_tx_report_complete(struct zhpe_pe_entry *pe_entry,
					      uint64_t flags)
{
	if (flags & pe_entry->flags)
		_zhpe_pe_tx_report_complete(pe_entry);
}

static inline int zhpe_zq_commit_spin(struct zhpeq *zq, uint32_t qindex,
				      uint32_t n_entries)
{
	int			ret;
	int			i;

	ret = zhpeq_commit(zq, qindex, n_entries);
	if (OFI_LIKELY(ret >= 0) || ret != -EAGAIN)
		return ret;

	for (;;) {
		for (i = 0; i < 10; i++) {
			ret = zhpeq_commit(zq, qindex, n_entries);
			if (ret != -EAGAIN)
				return ret;
		}
		sched_yield();
	}
}

static inline int zhpe_pe_tx_ring(struct zhpe_pe_entry *pe_entry,
				  struct zhpe_msg_hdr *zhdr, uintptr_t zbuf,
				  size_t len)
{
	int64_t			ret = -EINVAL;
	struct zhpe_pe_root	*pe_root = &pe_entry->pe_root;
	struct zhpe_conn	*conn = pe_root->conn;
	struct zhpe_tx		*ztx = conn->ztx;
	int64_t			zindex = -1;
	int64_t			rindex = -1;
	uint64_t		rzaddr;

	if (OFI_UNLIKELY(pe_root->compstat.flags & ZHPE_PE_RETRY)) {
		ret = zhpe_pe_retry(conn->ztx, zhpe_pe_retry_tx_ring1,
				    pe_root, zhpeu_free_ptr);
		goto done;
	}

	ret = zhpeq_reserve(ztx->zq, 1);
	if (ret < 0)
		goto done;
	zindex = ret;
	ret = zhpe_rx_remote_reserve(conn, zhdr);
	if (ret < 0)
		goto done;
	rindex = ret;
	rzaddr = conn->rx_remote.rz_zentries + zhpe_ring_off(conn, rindex);

	if (len <= ZHPEQ_IMM_MAX)
		ret = zhpeq_puti(ztx->zq, zindex, false, zhdr, len,
				 rzaddr, pe_root);
	else if (len <= ZHPE_RING_ENTRY_LEN)
		ret = zhpeq_put(ztx->zq, zindex, false, zbuf, len,
				rzaddr, pe_root);
	else
		ret = -FI_EINVAL;
	if (ret < 0)
		goto done;
	ret = zhpe_zq_commit_spin(ztx->zq, zindex, 1);
	if (ret < 0)
		goto done;
	zhpe_stats_pause_all();
	zhpeq_signal(ztx->zq);
	zhpe_stats_restart_all();
	zhpe_pe_signal(conn->ep_attr->domain->pe);
 done:
	if (OFI_LIKELY(ret >= 0))
		zhpe_pe_tx_report_complete(pe_entry, FI_INJECT_COMPLETE);
	else {
		zhpe_tx_free_res(conn, -1, zindex, rindex,
				 pe_root->compstat.flags);
		if (ret == -FI_EAGAIN &&
		    (pe_root->compstat.flags & ZHPE_PE_PROV))
			ret = zhpe_pe_retry(conn->ztx, zhpe_pe_retry_tx_ring2,
					    pe_entry, NULL);
	}
	/* Must be done after zhpe_zq_commit_spin() to prevent deadlock. */
	zhpe_conn_pull(conn);

	return ret;
}

static inline int zhpe_tx_op(struct zhpe_conn *conn, struct zhpe_msg_hdr ohdr,
			     uint8_t pe_flags, void *pay, size_t pay_len,
			     void *context)
{
	int			ret;
	int64_t			tindex = -1;
	uint64_t		lzaddr = 0;
	struct zhpe_pe_entry	*pe_entry;
	struct zhpe_msg_hdr	*zhdr;
	union zhpe_msg_payload	*zpay;
	size_t			cmd_len;

	zhpe_tx_reserve_vars(ret, zhpe_pe_tx_handle_entry, conn, context,
			     tindex, pe_entry, zhdr, lzaddr, done, pe_flags);
	pe_entry->flags = 0;
	*zhdr = ohdr;
	if (!(pe_flags & ZHPE_PE_PROV))
		zhdr->pe_entry_id = htons(tindex);
	zhdr->flags = 0;
	zpay = zhpe_pay_ptr(conn, zhdr, 0, __alignof__(*zpay));
	memcpy(zpay, pay, pay_len);
	cmd_len = ((char *)zpay - (char *)zhdr) + pay_len;
	zhdr->inline_len = cmd_len;
	ret = zhpe_pe_tx_ring(pe_entry, zhdr, lzaddr, cmd_len);
 done:
 	if (ret < 0 && (pe_flags & ZHPE_PE_RETRY)) {
		_ZHPE_LOG_ERROR(FI_LOG_CORE,
				"Failed to send provider op %d\n", ret);
		abort();
	}

	return ret;
}

static inline int zhpe_prov_op(struct zhpe_conn *conn,
			       struct zhpe_msg_hdr ohdr, uint8_t pe_flags,
			       void *pay, size_t pay_len)
{
	pe_flags |= ZHPE_PE_PROV;
	return zhpe_tx_op(conn, ohdr, pe_flags, pay, pay_len, NULL);
}

struct zhpe_rkey_data *zhpe_conn_rkey_get(struct zhpe_conn *conn,
					  const struct zhpe_key *zkey);

int zhpe_conn_rkey_revoke(struct zhpe_conn *conn, struct zhpe_msg_hdr ohdr,
			  const struct zhpe_key *zkey);

struct zhpe_mr *zhpe_mr_find(struct zhpe_domain *domain,
			     const struct zhpe_key *zkey);

static inline void zhpe_mr_get(struct zhpe_mr *zmr)
{
	zmr2zops(zmr)->get(zmr);
}

int zhpe_conn_key_export(struct zhpe_conn *conn, struct zhpe_msg_hdr ohdr,
			 struct zhpe_mr *zmr);
int zhpe_conn_rkey_import(struct zhpe_conn *conn, struct zhpe_msg_hdr ohdr,
			  uint64_t key, const void *blob, size_t blob_len,
			  struct zhpe_rkey_data **rkey_out);

int zhpe_send_blob(int sock_fd, const void *blob, size_t blob_len);
int zhpe_recv_fixed_blob(int sock_fd, void *blob, size_t blob_len);

const char *zhpe_ntop(const union sockaddr_in46 *sin46, char *buf, size_t len);
void zhpe_getaddrinfo_hints_init(struct addrinfo *hints, int family);
int zhpe_getaddrinfo(const char *node, const char *service,
		     struct addrinfo *hints, struct addrinfo **res);
struct addrinfo *zhpe_findaddrinfo(struct addrinfo *res, int family);
int zhpe_gethostaddr(sa_family_t family, union sockaddr_in46 *addr);
int zhpe_checklocaladdr(const struct ifaddrs *ifaddrs,
			const union sockaddr_in46 *sa);

static inline uint32_t zhpe_convert_access(uint64_t access) {
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

static inline struct zhpe_rx_entry *
zhpe_rx_new_entry(struct zhpe_rx_entry_free *rx_free)
{
	struct zhpe_rx_entry	*ret;
	struct zhpeu_atm_list_next *next;

	next = zhpeu_atm_fifo_pop(&rx_free->rx_fifo_list);
	if (OFI_LIKELY(!!next))
		ret = container_of(next, struct zhpe_rx_entry, rx_match_next);
	else
		ret = ofi_buf_alloc(rx_free->rx_entry_pool);
	if (!ret)
		goto done;
	_ZHPE_LOG_DBG(FI_LOG_EP_DATA,
		      "New rx_entry: %p, free: %p\n", ret, rx_free);
	ret->rx_free = rx_free;
	ret->pe_entry = NULL;
	ret->rx_user = NULL;
	ret->status = 0;
	ret->rx_state = ZHPE_RX_STATE_IDLE;
	ret->slab = false;
	ret->flags = FI_MSG | FI_RECV;
	zhpe_iov_state_init(&ret->lstate, &zhpe_iov_state_ziovl_ops, ret->liov);
	dlist_init(&ret->lentry);
 done:

	return ret;
}

static inline void zhpe_rx_release_entry(struct zhpe_rx_entry *rx_entry)
{
	struct zhpe_rx_entry_free *rx_free = rx_entry->rx_free;
	struct zhpe_iov		*liov;
	struct zhpe_pe_entry	*pe_entry;

	if (!rx_entry)
		return;
	assert(dlist_empty(&rx_entry->lentry));
	pe_entry = rx_entry->pe_entry;
	if (pe_entry) {
		if (rx_entry->slab) {
			liov = pe_entry->liov;
			zhpe_slab_free(&rx_free->rx_ctx->eager, liov->iov_base);
		}
		if (pe_entry->pe_root.compstat.flags & ZHPE_PE_RETRY)
			free(rx_entry);
		else
			zhpe_tx_release(pe_entry);
	}
	if (rx_free == &rx_free->rx_ctx->rx_user_free)
		zhpe_lstate_release(&rx_entry->lstate);
	zhpeu_atm_fifo_push(&rx_free->rx_fifo_list, &rx_entry->rx_match_next);
	_ZHPE_LOG_DBG(FI_LOG_EP_DATA, "Releasing rx_entry: %p\n", rx_entry);
}

static inline uint8_t zhpe_get_rx_id(struct zhpe_tx_ctx *tx_ctx,
				     fi_addr_t fiaddr)
{
	uint8_t			ret = 0;
	struct zhpe_av		*av = tx_ctx->av;

	if (av && av->rx_ctx_bits)
		ret = ((uint64_t)fiaddr) >> (64 - av->rx_ctx_bits);

	return ret;

}

static inline bool zhpe_needs_locking(struct zhpe_domain *zdom)
{
	if (zdom->util_domain.data_progress == FI_PROGRESS_AUTO)
		return true;

	switch (zdom->util_domain.threading) {

	case FI_THREAD_COMPLETION:
	case FI_THREAD_DOMAIN:
		return false;

	default:

		return true;
	}
}

int zhpe_mr_cache_init(struct zhpe_domain *domain);
void zhpe_mr_cache_destroy(struct zhpe_domain *domain);

int zhpe_check_user_iov(const struct iovec *uiov, void **udesc,
			size_t uiov_cnt, uint32_t qaccess,
			struct zhpe_iov_state *lstate, size_t liov_max,
			size_t *total_len);

int zhpe_check_user_rma(const struct fi_rma_iov *urma, size_t urma_cnt,
			uint32_t qaccess,
			struct zhpe_iov_state *rstate, size_t riov_max,
			size_t *total_len, struct zhpe_conn *conn);

/* Type checked rbt calls. */

static inline RbtIterator
zhpe_zkey_rbtFind(RbtHandle h, const struct zhpe_key *zkey)
{
	return rbtFind(h, (void *)zkey);
}

static inline void
zhpe_kexp_rbtInsert(RbtHandle h, struct zhpe_kexp_data *kexp)
{
	RbtStatus		rc;

	rc = rbtInsert(h, &kexp->zkey, kexp);
	assert(rc == RBT_STATUS_OK);
	(void)rc;
}

static inline void
zhpe_rkey_rbtInsert(RbtHandle h, struct zhpe_rkey_data *rkey)
{
	RbtStatus		rc;

	rc = rbtInsert(h, &rkey->zkey, rkey);
	assert(rc == RBT_STATUS_OK);
	(void)rc;
}

static inline void
zhpe_zmr_rbtInsert(RbtHandle h, struct zhpe_mr *zmr)
{
	RbtStatus		rc;

	rc = rbtInsert(h, &zmr->zkey, zmr);
	assert(rc == RBT_STATUS_OK);
	(void)rc;
}

static inline void *zhpe_rbtKeyValue(RbtHandle h, RbtIterator i)
{
	void			*keyp;
	void			*kval;

	rbtKeyValue(h, i, &keyp, &kval);

	return kval;
}

int zhpe_atomic_op(enum fi_datatype type, enum fi_op op,
		   uint64_t operand0, uint64_t operand1,
		   void *dst, uint64_t *original);
int zhpe_atomic_load(enum fi_datatype type, const void *src, uint64_t *value);
int zhpe_atomic_store(enum fi_datatype type, void *dst, uint64_t value);
int zhpe_atomic_copy(enum fi_datatype type, const void *src, void *dst);

#endif /* _ZHPE_H_ */
