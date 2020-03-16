/*
 * Copyright (c) 2014-2017 Intel Corporation, Inc.  All rights reserved.
 * Copyright (c) 2016-2017, Cisco Systems, Inc. All rights reserved.
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

#define ZHPE_SUBSYS	FI_LOG_AV

void *zhpe_av_get_addr_unsafe(struct zhpe_av *zav, fi_addr_t fi_addr)
{
	struct zhpe_av_entry	*zav_entry;

	fi_addr &= zav->av_idx_mask;
	zav_entry = zhpe_ibuf_get(&zav->zav_entry_pool, fi_addr);
	if (OFI_UNLIKELY(!zav_entry || zav_entry->use_cnt <= 0))
		return NULL;
	else
		return &zav_entry->sz;
}

static bool av_valid_addr(const void *addr)
{
	const struct sockaddr_zhpe *sz = addr;
	uint32_t		sz_queue;

	switch (sz->sz_family) {

	case AF_ZHPE:
		sz_queue = ntohl(sz->sz_queue);
		return (sz_queue != ZHPE_SZQ_WILDCARD &&
			sz_queue != ZHPE_SZQ_INVAL);

	default:
		return false;

	}
}

struct zhpe_av_entry *
zhpe_av_update_addr_unsafe(struct zhpe_av *zav,
			   const struct sockaddr_zhpe *sz_new)
{
	struct zhpe_av_entry	*zav_entry;
	struct sockaddr_zhpe	*sz_old;
	struct ofi_rbnode	*rbnode;
	char			*str_old;
	char			*str_new;

	/* zav_lock() must be held. */
	rbnode = ofi_rbmap_find(&zav->zav_tree, (void *)sz_new);
	if (!rbnode)
		return NULL;
	zav_entry = rbnode->data;
	sz_old = &zav_entry->sz;
	if (!memcmp(sz_old->sz_uuid, sz_new->sz_uuid, sizeof(sz_old->sz_uuid)))
		goto done;

	/* We now know the full UUID. */
	if (zhpeu_uuid_gcid_only(sz_old->sz_uuid))
		memcpy(sz_old->sz_uuid, sz_new->sz_uuid,
		       sizeof(sz_old->sz_uuid));
	else if (!zhpeu_uuid_gcid_only(sz_new->sz_uuid)) {
		/* A different UUID. Just return an error and log, for now. */
		str_old = zhpeu_sockaddr_str(sz_old);
		str_new = zhpeu_sockaddr_str(sz_new);
		ZHPE_LOG_ERROR("UUID collision %s %s\n", str_old, str_new);
		abort();
		free(str_old);
		free(str_new);
	}

 done:
	return zav_entry;
}

static int zhpe_av_insert_addr(struct zhpe_av *zav, const void *addr,
			       fi_addr_t *fi_addr_out)
{
	int			ret;
	fi_addr_t		fi_addr = FI_ADDR_NOTAVAIL;
	struct sockaddr_zhpe	*sz_new = (void *)addr;
	struct zhpe_av_entry	*zav_entry;

	if (!av_valid_addr(addr)) {
		_zhpe_straddr_log(FI_LOG_WARN, ZHPE_SUBSYS, "Invalid address",
				  addr);
		ret = -FI_EADDRNOTAVAIL;
		goto done_unlocked;
	}

	zav_lock(zav);
	zav_entry = zhpe_av_update_addr_unsafe(zav, addr);
	if (zav_entry) {
		fi_addr = zhpe_ibuf_index(&zav->zav_entry_pool, zav_entry);
		zav_entry->use_cnt++;
		ret = 0;
		goto done;
	}
	zav_entry = zhpe_ibuf_alloc(&zav->zav_entry_pool);
	assert(zav_entry->use_cnt == 0);
	zav_entry->use_cnt = 1;
	fi_addr = zhpe_ibuf_index(&zav->zav_entry_pool, zav_entry);
	memcpy(&zav_entry->sz, sz_new, sizeof(zav_entry->sz));
	ret = ofi_rbmap_insert(&zav->zav_tree, &zav_entry->sz, zav_entry, NULL);
	assert_always(!ret);

 done:
	zav_unlock(zav);

 done_unlocked:
	if (ret >= 0) {
	    _zhpe_straddr_dbg(ZHPE_SUBSYS, "av_insert addr", addr);
	    ZHPE_LOG_DBG("av_insert fi_addr: %" PRIu64 "\n", fi_addr);
	}

	if (fi_addr_out)
		*fi_addr_out = fi_addr;

	return ret;
}

static int zhpe_av_insertv(struct util_av *av, const void *addr, size_t addrlen,
			   size_t count, fi_addr_t *fi_addr, void *context)
{
	int			ret;
	struct zhpe_av		*zav = uav2zav(av);
	int			success_cnt = 0;
	size_t			i;

	ZHPE_LOG_DBG("inserting %zu addresses\n", count);
	for (i = 0; i < count; i++) {
		ret = zhpe_av_insert_addr(zav, (const char *)addr + i * addrlen,
					  fi_addr ? &fi_addr[i] : NULL);
		if (!ret)
			success_cnt++;
		else if (av->eq)
			ofi_av_write_event(av, i, -ret, context);
	}

	ZHPE_LOG_DBG("%d addresses successful\n", success_cnt);
	if (av->eq) {
		ofi_av_write_event(av, success_cnt, 0, context);
		ret = 0;
	} else {
		ret = success_cnt;
	}

	return ret;
}

static int zhpe_av_insert(struct fid_av *av_fid, const void *addr,
			  size_t count, fi_addr_t *fi_addr, uint64_t flags,
			  void *context)
{
	int			ret;
	struct zhpe_av		*zav = fid2zav(&av_fid->fid);
	struct util_av		*av = &zav->util_av;

	ret = ofi_verify_av_insert(av, flags);
	if (ret < 0)
		return ret;

	return zhpe_av_insertv(av, addr, sizeof(struct sockaddr_zhpe),
			       count, fi_addr, context);
}

static int zhpe_av_remove(struct fid_av *av_fid, fi_addr_t *fi_addr,
			  size_t count, uint64_t flags)
{
	int			ret = 0;
	struct zhpe_av		*zav = fid2zav(&av_fid->fid);
	struct zhpe_av_entry	*zav_entry;
	size_t			i;

	if (flags) {
		ZHPE_LOG_ERROR("invalid flags\n");
		return -FI_EINVAL;
	}

	/* See ofi_ip_av_remove() for why reverse order. */
	zav_lock(zav);
	for (i = count; i > 0; ) {
		i--;
		zav_entry = zhpe_ibuf_get(&zav->zav_entry_pool,
					  fi_addr[i] & zav->av_idx_mask);
		if (OFI_UNLIKELY(!zav_entry || zav_entry->use_cnt <= 0)) {
			ret = -FI_ENOENT;
			ZHPE_LOG_ERROR("removal of fi_addr %"PRIu64" failed\n",
				       fi_addr[i]);
			continue;
		}
		if (--(zav_entry->use_cnt))
			continue;
		zhpe_ibuf_free(&zav->zav_entry_pool, zav_entry);
	}
	zav_unlock(zav);

	return ret;
}

/* Caller should free *addr */
static int zhpe_av_nodesym_getaddr(struct util_av *av, const char *node,
				   size_t nodecnt, const char *service,
				   size_t svccnt, void **addr, size_t *addrlen)
{
	int			ret = 0;
	size_t			count = nodecnt * svccnt;
	char			name[FI_NAME_MAX];
	char			svc[FI_NAME_MAX];
	struct sockaddr_zhpe	*sz;
	size_t			name_len;
	size_t			n;
	size_t			s;
	size_t			name_index;
	size_t			svc_index;
	char			*e;

	*addrlen = sizeof(struct sockaddr_zhpe);
	*addr = calloc(nodecnt * svccnt, *addrlen);
	if (!*addr) {
		ret = -FI_ENOMEM;
		goto done;
	}

	sz = *addr;

	for (name_len = strlen(node); isdigit(node[name_len - 1]); )
		name_len--;

	memcpy(name, node, name_len);
	ret = -FI_EINVAL;
	errno = 0;
	name_index = strtoul(node + name_len, &e, 0);
	if (errno != 0) {
                ret = -errno;
                goto done;
	}
	if (*e != '\0')
                goto done;
	svc_index = strtoul(service, &e, 0);
	if (errno != 0) {
                ret = -errno;
                goto done;
	}
	if (*e != '\0')
                goto done;

	for (n = 0; n < nodecnt; n++) {
		if (nodecnt == 1) {
			strncpy(name, node, sizeof(name) - 1);
			name[FI_NAME_MAX - 1] = '\0';
		} else {
			snprintf(name + name_len, sizeof(name) - name_len - 1,
				 "%zu", name_index + n);
		}

		for (s = 0; s < svccnt; s++) {
			if (svccnt == 1) {
				strncpy(svc, service, sizeof(svc) - 1);
				svc[FI_NAME_MAX - 1] = '\0';
			} else {
				snprintf(svc, sizeof(svc) - 1,
					 "%zu", svc_index + s);
			}
			FI_INFO(av->prov, FI_LOG_AV, "resolving %s:%s for AV "
				"insert\n", node, service);

			ret = zhpeq_get_zaddr(node, service, sz);
			if (ret < 0)
				goto done;
			sz++;
		}
	}
	ret = count;
done:
	if (ret < 0) {
		free(*addr);
		*addr = NULL;
	}

	return ret;
}

/* Caller should free *addr */
int zhpe_av_sym_getaddr(struct util_av *av, const char *node,
			size_t nodecnt, const char *service,
			size_t svccnt, void **addr, size_t *addrlen)
{
	if (strlen(node) >= FI_NAME_MAX || strlen(service) >= FI_NAME_MAX) {
		FI_WARN(av->prov, FI_LOG_AV,
			"node or service name is too long\n");
		return -FI_ENOSYS;
	}

	FI_INFO(av->prov, FI_LOG_AV, "insert symmetric host names\n");
	return zhpe_av_nodesym_getaddr(av, node, nodecnt, service,
				       svccnt, addr, addrlen);
}

static int zhpe_av_insertsym(struct fid_av *av_fid, const char *node,
			     size_t nodecnt, const char *service, size_t svccnt,
			     fi_addr_t *fi_addr, uint64_t flags, void *context)
{
	int			ret;
	struct util_av		*av;
	void			*addr;
	size_t			addrlen;
	int			count;

	av = container_of(av_fid, struct util_av, av_fid);
	ret = ofi_verify_av_insert(av, flags);
	if (ret < 0)
		return ret;

	count = zhpe_av_sym_getaddr(av, node, nodecnt, service,
				    svccnt, &addr, &addrlen);
	if (count <= 0)
		return count;

	ret = zhpe_av_insertv(av, addr, addrlen, count,	fi_addr, context);
	free(addr);

	return ret;
}

static int zhpe_av_insertsvc(struct fid_av *av_fid, const char *node,
			     const char *service, fi_addr_t *fi_addr,
			     uint64_t flags, void *context)
{
	return zhpe_av_insertsym(av_fid, node, 1, service, 1, fi_addr, flags,
				 context);
}

static int zhpe_av_lookup(struct fid_av *av_fid, fi_addr_t fi_addr,
			  void *addr, size_t *addrlen)
{
	int			ret = -FI_EINVAL;
	struct zhpe_av		*zav = fid2zav(&av_fid->fid);
	struct sockaddr_zhpe	*sz;
	size_t			outlen;

	if (!av_fid || !addr || !addrlen)
		goto done;

	outlen = MIN(*addrlen, zav->util_av.addrlen);
	*addrlen = zav->util_av.addrlen;
	zav_lock(zav);
	sz = zhpe_av_get_addr_unsafe(zav, fi_addr);
	if (sz)
		memcpy(addr, sz, outlen);
	zav_unlock(zav);
	if (!sz) {
		ret = -FI_ENOENT;
		goto done;
	}
	ret = 0;
 done:

	return ret;
}

const char *zhpe_av_straddr(struct fid_av *av, const void *addr,
			    char *buf, size_t *len)
{
	return zhpe_straddr(buf, len, FI_FORMAT_UNSPEC, addr);
}

static struct fi_ops_av zhpe_av_ops = {
	.size			= sizeof(struct fi_ops_av),
	.insert			= zhpe_av_insert,
	.insertsvc		= zhpe_av_insertsvc,
	.insertsym		= zhpe_av_insertsym,
	.remove			= zhpe_av_remove,
	.lookup			= zhpe_av_lookup,
	.straddr		= zhpe_av_straddr,
};

static int zhpe_av_close(struct fid *fid)
{
	int			ret = -FI_EINVAL;
	struct zhpe_av		*zav = fid2zav(fid);

	if (!fid)
		goto done;
	ret = ofi_av_close_lightweight(&zav->util_av);
	if (ret < 0)
		goto done;
	ofi_rbmap_cleanup(&zav->zav_tree);
	zhpe_ibufpool_destroy(&zav->zav_entry_pool);
	free(zav);
 done:
	return ret;
}

static struct fi_ops zhpe_av_fi_ops = {
	.size			= sizeof(struct fi_ops),
	.close			= zhpe_av_close,
	.bind			= ofi_av_bind,
	.control		= fi_no_control,
	.ops_open		= fi_no_ops_open,
};

/*
 * Replacing the hash with a tree so I can have control of the
 * matching function. Should be painless and we rarely do
 * lookups/insertions.
 */

static int compare_av_addrs(struct ofi_rbmap *map, void *vkey,
			    void *ventry)
{
	int			ret;
	struct sockaddr_zhpe	*k1 = vkey;
	struct sockaddr_zhpe	*k2 = &((struct zhpe_av_entry *)ventry)->sz;
	uint32_t		gcid1 = zhpeu_uuid_to_gcid(k1->sz_uuid);
	uint32_t		gcid2 = zhpeu_uuid_to_gcid(k2->sz_uuid);
	uint32_t		sz_queue1 = ntohl(k1->sz_queue);
	uint32_t		sz_queue2 = ntohl(k2->sz_queue);

	ret = arithcmp(gcid1, gcid2);
	if (ret)
		goto done;
	ret = arithcmp(sz_queue1, sz_queue2);

 done:
	return ret;
}

int zhpe_av_open(struct fid_domain *domain_fid, struct fi_av_attr *attr,
		 struct fid_av **fid_av_out, void *context)
{
	int			ret = -FI_EINVAL;
	struct util_domain	*dom =
		container_of(domain_fid, struct util_domain, domain_fid);
	struct zhpe_av		*zav = NULL;
	struct fi_av_attr	av_attr;

	if (!fid_av_out)
		goto done;
	*fid_av_out = NULL;
	if (!domain_fid || !attr || attr->rx_ctx_bits < 0 ||
	    attr->rx_ctx_bits >= ZHPE_AV_MAX_CTX_BITS ||
	    (attr->flags & ~FI_EVENT))
		goto done;

	av_attr = *attr;
	if (av_attr.type == FI_AV_UNSPEC)
		av_attr.type = FI_AV_TABLE;
	if (!av_attr.count)
		av_attr.count = zhpe_av_def_sz;

	zav = _calloc_cachealigned(1, sizeof(*zav));
	if (!zav) {
		ret = -FI_ENOMEM;
		goto done;
	}
	ofi_rbmap_init(&zav->zav_tree, compare_av_addrs);
	zav->rx_ctx_bits = attr->rx_ctx_bits;
	zav->av_idx_mask =  ~((uint64_t)0);
	if (zav->rx_ctx_bits) {
		zav->av_idx_mask >>= zav->rx_ctx_bits;
		zav->rx_ctx_shift = FI_ADDR_BITS - zav->rx_ctx_bits;
	}

	ret = ofi_av_init_lightweight(dom, &av_attr, &zav->util_av, context);
	if (ret < 0) {
		free(zav);
		goto done;
	}
	ret = zhpe_ibufpool_create(&zav->zav_entry_pool, "zav_entry_pool",
				   sizeof(struct zhpe_av_entry) ,
				   0, 0, 0, OFI_BUFPOOL_NO_TRACK, NULL, NULL);
	if (ret < 0) {
		zhpe_av_close(&zav->util_av.av_fid.fid);
		goto done;
	}

	zav->util_av.flags = av_attr.flags;
	zav->util_av.av_fid.fid.ops = &zhpe_av_fi_ops;
	zav->util_av.av_fid.ops = &zhpe_av_ops;
	*fid_av_out = &zav->util_av.av_fid;

 done:
	return ret;
}
