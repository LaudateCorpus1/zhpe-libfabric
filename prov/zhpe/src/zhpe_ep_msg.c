/*
 * Copyright (c) 2014 Intel Corporation, Inc.  All rights reserved.
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

#define ZHPE_SUBSYS	FI_LOG_EP_CTRL

static int zhpe_ep_cm_getname(fid_t fid, void *addr, size_t *addrlen)
{
	int			ret;
	struct zhpe_ctx		*zctx = fid2zctx(fid);
	size_t			oaddrlen;

	if (zctx->zep->disabled)
		return -FI_EOPBADSTATE;
	if (!addrlen)
		return -FI_EINVAL;

	/*
	 * Quirky semantics: getting the semantics right required changes
	 * right in zhpeq_rq_get_addr() and in zhpe backend.
	 */
	oaddrlen = *addrlen;
	ret = zhpeq_rq_get_addr(zctx->zrq, addr, addrlen);
	if (ret >= 0) {
		/* Sanitize return value. */
		ret = 0;
		if (*addrlen > oaddrlen)
			ret = -FI_ETOOSMALL;
	}

	return ret;
}

#ifdef NOTYET

static int zhpe_pep_create_listener(struct zhpe_pep *pep)
{
	int			ret;

	ret = zhpe_listen(&pep->info, &pep->src_addr, zhpe_cm_def_map_sz);
	if (ret < 0)
		goto done;
	pep->cm.sock = ret;
	pep->name_set = 1;
 done:
	return ret;
}

static int zhpe_ep_cm_setname(fid_t fid, void *addr, size_t addrlen)
{
	union sockaddr_in46	*sa = addr;
	struct zhpe_ep		*zhpe_ep;
	struct zhpe_pep		*zhpe_pep;

	if (!zhpeu_sockaddr_valid(addr, addrlen, true))
		return -FI_EINVAL;

	switch (fid->fclass) {

	case FI_CLASS_EP:
	case FI_CLASS_SEP:
		zhpe_ep = container_of(fid, struct zhpe_ep, ep.fid);
		if (!zhpe_ep->attr->listener.listener_thread_valid)
			return -FI_EINVAL;
		if (sa->sa_family !=
		    zhpe_sa_family(zhpe_ep->attr->info.addr_format))
			return -FI_EINVAL;
		zhpeu_sockaddr_cpy(&zhpe_ep->attr->src_addr, sa);
		return zhpe_conn_listen(zhpe_ep->attr);
	case FI_CLASS_PEP:
		zhpe_pep = container_of(fid, struct zhpe_pep, pep.fid);
		if (!zhpe_pep->cm.listener_thread_valid)
			return -FI_EINVAL;
		if (sa->sa_family !=
		    zhpe_sa_family(zhpe_pep->info.addr_format))
			return -FI_EINVAL;
		zhpeu_sockaddr_cpy(&zhpe_pep->src_addr, sa);
		return zhpe_pep_create_listener(zhpe_pep);
	default:
		ZHPE_LOG_ERROR("Invalid argument\n");
		return -FI_EINVAL;
	}
}

static int zhpe_ep_cm_getpeer(struct fid_ep *ep, void *addr, size_t *addrlen)
{
	size_t			len = *addrlen;
	struct zhpe_ep		*zhpe_ep;
	union sockaddr_in46	*dest_addr;

	zhpe_ep = container_of(ep, struct zhpe_ep, ep);
	dest_addr = &zhpe_ep->attr->dest_addr;
	*addrlen = zhpeu_sockaddr_len(dest_addr);
	if (!*addrlen)
		return -FI_EOPBADSTATE;

	memcpy(addr, dest_addr, MIN(len, *addrlen));

	return (*addrlen <= len) ? 0 : -FI_ETOOSMALL;
}

static int zhpe_cm_send(int fd, const void *buf, int len)
{
	int ret, done = 0;

	while (done != len) {
		ret = ofi_send_socket(fd, (const char*) buf + done, len - done, MSG_NOSIGNAL);
		if (ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				continue;
			ZHPE_LOG_ERROR("failed to write to fd: %s\n", strerror(errno));
			return -FI_EIO;
		}
		done += ret;
	}
	return 0;
}

static int zhpe_cm_recv(int fd, void *buf, int len)
{
	int ret, done = 0;
	while (done != len) {
		ret = recv(fd, (char*) buf + done, len - done, 0);
		if (ret <= 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				continue;
			ZHPE_LOG_ERROR("failed to read from fd: %s\n", strerror(errno));
			return -FI_EIO;
		}
		done += ret;
	}
	return 0;
}

static void zhpe_ep_wait_shutdown(struct zhpe_ep *ep)
{
	int ret, do_report = 0;
	char tmp = 0;
	struct pollfd poll_fds[2];
	struct zhpe_conn_hdr msg;
	struct fi_eq_cm_entry cm_entry = {0};

	poll_fds[0].fd = ep->attr->cm.sock;
	poll_fds[1].fd = ep->attr->cm.signal_fds[1];
	poll_fds[0].events = poll_fds[1].events = POLLIN;

	while (*((volatile int*) &ep->attr->cm.do_listen)) {
		ret = poll(poll_fds, 2, -1);
		if (ret > 0) {
			if (poll_fds[1].revents & POLLIN) {
				ret = ofi_read_socket(ep->attr->cm.signal_fds[1], &tmp, 1);
				if (ret != 1) {
					ZHPE_LOG_DBG("Invalid signal\n");
					break;
				}
				continue;
			}
		} else {
			break;
		}

		if (zhpe_cm_recv(ep->attr->cm.sock, &msg, sizeof(msg)))
			break;

		if (msg.type == ZHPE_CONN_SHUTDOWN)
			break;
	}

	fastlock_acquire(&ep->attr->cm.lock);
	if (ep->attr->cm.is_connected) {
		do_report = 1;
		ep->attr->cm.is_connected = 0;
	}
	fastlock_release(&ep->attr->cm.lock);

	if (do_report) {
		cm_entry.fid = &ep->ep.fid;
		ZHPE_LOG_DBG("reporting FI_SHUTDOWN\n");
		if (zhpe_eq_report_event(ep->attr->eq, FI_SHUTDOWN,
					 &cm_entry, sizeof(cm_entry), 0))
			ZHPE_LOG_ERROR("Error in writing to EQ\n");
	}
	ofi_close_socket(ep->attr->cm.sock);
}

static void zhpe_ep_cm_report_connect_fail(struct zhpe_ep *ep,
					   void *param, size_t paramlen)
{
	ZHPE_LOG_DBG("reporting FI_REJECT\n");
	if (zhpe_eq_report_error(ep->attr->eq, &ep->ep.fid, NULL, 0,
				 FI_ECONNREFUSED, -FI_ECONNREFUSED,
				 param, paramlen))
		ZHPE_LOG_ERROR("Error in writing to EQ\n");
}

static void *zhpe_ep_cm_connect_handler(void *data)
{
	int zhpe_fd, ret;
	struct zhpe_conn_req_handle *handle = data;
	struct zhpe_conn_req *req = handle->req;
	struct zhpe_conn_hdr response;
	struct zhpe_ep *ep = handle->ep;
	void *param = NULL;
	struct fi_eq_cm_entry *cm_entry = NULL;
	int cm_data_sz, response_port;

	zhpe_fd = ofi_socket(handle->dest_addr.sa_family, SOCK_STREAM,
			     IPPROTO_TCP);
	if (zhpe_fd < 0) {
		ZHPE_LOG_ERROR("no socket\n");
		zhpe_ep_cm_report_connect_fail(handle->ep, NULL, 0);
		goto out;
	}

	ret = connect(zhpe_fd, (struct sockaddr *)&handle->dest_addr,
		      sizeof(handle->dest_addr));
	if (ret < 0) {
		ZHPE_LOG_ERROR("connect failed : %s\n", strerror(errno));
		goto err;
	}
	ret = zhpe_set_sockopts_connect(zhpe_fd);
	if (ret < 0)
		goto err;

	if (zhpe_cm_send(zhpe_fd, req, sizeof(*req)))
		goto err;
	if (handle->paramlen && zhpe_cm_send(zhpe_fd, handle->cm_data, handle->paramlen))
		goto err;

	if (zhpe_cm_recv(zhpe_fd, &response, sizeof(response)))
		goto err;

	cm_data_sz = ntohs(response.cm_data_sz);
	response_port = ntohs(response.port);
	if (cm_data_sz) {
		param = calloc(1, cm_data_sz);
		if (!param)
			goto err;

		if (zhpe_cm_recv(zhpe_fd, param, cm_data_sz))
			goto err;
	}

	if (response.type == ZHPE_CONN_REJECT) {
		zhpe_ep_cm_report_connect_fail(handle->ep, param, cm_data_sz);
		ofi_close_socket(zhpe_fd);
	} else {
		cm_entry = calloc(1, sizeof(*cm_entry) +
				  ZHPE_EP_MAX_CM_DATA_SZ);
		if (!cm_entry)
			goto err;

		cm_entry->fid = &ep->ep.fid;
		memcpy(&cm_entry->data, param, cm_data_sz);
		ep->attr->cm.is_connected = 1;
		ep->attr->cm.do_listen = 1;
		ep->attr->cm.sock = zhpe_fd;
		ep->attr->msg_dest_port = response_port;
		ZHPE_LOG_DBG("got accept - port: %d\n", response_port);

		ZHPE_LOG_DBG("Reporting FI_CONNECTED\n");
		if (zhpe_eq_report_event(ep->attr->eq, FI_CONNECTED, cm_entry,
					 sizeof(*cm_entry) + cm_data_sz, 0))
			ZHPE_LOG_ERROR("Error in writing to EQ\n");
		zhpe_ep_wait_shutdown(ep);
	}
	goto out;
err:
	ZHPE_LOG_ERROR("io failed : %s\n", strerror(errno));
	zhpe_ep_cm_report_connect_fail(handle->ep, NULL, 0);
	ofi_close_socket(zhpe_fd);
out:
	free(param);
	free(cm_entry);
	free(handle->req);
	free(handle);
	return NULL;
}

static int zhpe_ep_cm_connect(struct fid_ep *ep, const void *addr,
			      const void *param, size_t paramlen)
{
	struct zhpe_conn_req *req = NULL;
	struct zhpe_conn_req_handle *handle = NULL;
	struct zhpe_ep *_ep;
	struct zhpe_eq *_eq;

	_ep = container_of(ep, struct zhpe_ep, ep);
	_eq = _ep->attr->eq;
	if (!_eq || !addr || (paramlen > ZHPE_EP_MAX_CM_DATA_SZ))
		return -FI_EINVAL;

	if (!_ep->attr->listener.listener_thread_valid &&
	    zhpe_conn_listen(_ep->attr))
		return -FI_EINVAL;

	zhpeu_sockaddr_cpy(&_ep->attr->dest_addr, addr);

	req = calloc(1, sizeof(*req));
	if (!req)
		return -FI_ENOMEM;

	handle = calloc(1, sizeof(*handle));
	if (!handle)
		goto out;

	req->hdr.type = ZHPE_CONN_REQ;
	req->hdr.port = htons(_ep->attr->msg_src_port);
	req->hdr.cm_data_sz = htons(paramlen);
	req->caps = _ep->attr->info.caps;
	zhpeu_sockaddr_cpy(&req->src_addr, &_ep->attr->src_addr);
	zhpeu_sockaddr_cpy(&handle->dest_addr, addr);

	handle->ep = _ep;
	handle->req = req;
	if (paramlen) {
		handle->paramlen = paramlen;
		memcpy(handle->cm_data, param, paramlen);
	}

	if (_ep->attr->cm.listener_thread_valid &&
	    pthread_join(_ep->attr->cm.listener_thread, NULL))
		ZHPE_LOG_DBG("failed to join cm listener\n");
	_ep->attr->cm.listener_thread_valid = false;

	if (pthread_create(&_ep->attr->cm.listener_thread, NULL,
			   zhpe_ep_cm_connect_handler, handle)) {
		ZHPE_LOG_ERROR("failed to create cm thread\n");
		goto out;
	}
	_ep->attr->cm.listener_thread_valid = true;
	return 0;
out:
	free(req);
	free(handle);
	return -FI_ENOMEM;
}

static void *zhpe_cm_accept_handler(void *data)
{
	int ret;
	struct zhpe_conn_hdr reply;
	struct zhpe_conn_req_handle *hreq = data;
	struct zhpe_ep_attr *ep_attr;
	struct fi_eq_cm_entry cm_entry;

	ep_attr = hreq->ep->attr;
	ep_attr->msg_dest_port = ntohs(hreq->req->hdr.port);

	reply.type = ZHPE_CONN_ACCEPT;
	reply.port = htons(ep_attr->msg_src_port);
	reply.cm_data_sz = htons(hreq->paramlen);
	ret = zhpe_cm_send(hreq->zhpe_fd, &reply, sizeof(reply));
	if (ret) {
		ZHPE_LOG_ERROR("failed to reply\n");
		return NULL;
	}

	if (hreq->paramlen && zhpe_cm_send(hreq->zhpe_fd, hreq->cm_data, hreq->paramlen)) {
		ZHPE_LOG_ERROR("failed to send userdata\n");
		return NULL;
	}

	cm_entry.fid = &hreq->ep->ep.fid;
	ZHPE_LOG_DBG("reporting FI_CONNECTED\n");
	if (zhpe_eq_report_event(ep_attr->eq, FI_CONNECTED, &cm_entry,
				 sizeof(cm_entry), 0))
		ZHPE_LOG_ERROR("Error in writing to EQ\n");
	ep_attr->cm.is_connected = 1;
	ep_attr->cm.do_listen = 1;
	ep_attr->cm.sock = hreq->zhpe_fd;
	zhpe_ep_wait_shutdown(hreq->ep);

	if (pthread_join(hreq->req_handler, NULL))
		ZHPE_LOG_DBG("failed to join req-handler\n");
	free(hreq->req);
	free(hreq);
	return NULL;
}

static int zhpe_ep_cm_accept(struct fid_ep *ep, const void *param, size_t paramlen)
{
	struct zhpe_conn_req_handle *handle;
	struct zhpe_ep *_ep;

	_ep = container_of(ep, struct zhpe_ep, ep);
	if (!_ep->attr->eq || paramlen > ZHPE_EP_MAX_CM_DATA_SZ)
		return -FI_EINVAL;

	if (!_ep->attr->listener.listener_thread_valid &&
	    zhpe_conn_listen(_ep->attr))
		return -FI_EINVAL;

	handle = container_of(_ep->attr->info.handle,
			      struct zhpe_conn_req_handle, handle);
	if (!handle || handle->handle.fclass != FI_CLASS_CONNREQ) {
		ZHPE_LOG_ERROR("invalid handle for cm_accept\n");
		return -FI_EINVAL;
	}

	handle->ep = _ep;
	handle->paramlen = 0;
	handle->is_accepted = 1;
	if (paramlen) {
		handle->paramlen = paramlen;
		memcpy(handle->cm_data, param, paramlen);
	}

	if (_ep->attr->cm.listener_thread_valid &&
	    pthread_join(_ep->attr->cm.listener_thread, NULL))
		ZHPE_LOG_DBG("failed to join cm listener\n");
	_ep->attr->cm.listener_thread_valid = false;

	if (pthread_create(&_ep->attr->cm.listener_thread, NULL,
			   zhpe_cm_accept_handler, handle)) {
		ZHPE_LOG_ERROR("Couldnt create accept handler\n");
		return -FI_ENOMEM;
	}
	_ep->attr->cm.listener_thread_valid = true;

	return 0;
}

static int zhpe_ep_cm_shutdown(struct fid_ep *ep, uint64_t flags)
{
	struct zhpe_ep *_ep;
	struct fi_eq_cm_entry cm_entry = {0};
	struct zhpe_conn_hdr msg = {0};
	char c = 0;

	_ep = container_of(ep, struct zhpe_ep, ep);
	fastlock_acquire(&_ep->attr->cm.lock);
	if (_ep->attr->cm.is_connected) {
		msg.type = ZHPE_CONN_SHUTDOWN;
		if (zhpe_cm_send(_ep->attr->cm.sock, &msg, sizeof(msg)))
			ZHPE_LOG_DBG("failed to send shutdown msg\n");
		_ep->attr->cm.is_connected = 0;
		_ep->attr->cm.do_listen = 0;
		if (ofi_write_socket(_ep->attr->cm.signal_fds[0], &c, 1) != 1)
			ZHPE_LOG_DBG("Failed to signal\n");

		cm_entry.fid = &_ep->ep.fid;
		ZHPE_LOG_DBG("reporting FI_SHUTDOWN\n");
		if (zhpe_eq_report_event(_ep->attr->eq, FI_SHUTDOWN,
					 &cm_entry, sizeof(cm_entry), 0))
			ZHPE_LOG_ERROR("Error in writing to EQ\n");
	}
	fastlock_release(&_ep->attr->cm.lock);
	zhpe_ep_disable(ep);
	return 0;
}

#endif

struct fi_ops_cm zhpe_ep_cm_ops = {
	.size = sizeof(struct fi_ops_cm),
#ifdef NOT_YET
	.setname = zhpe_ep_cm_setname,
#else
	.setname = fi_no_setname,
#endif
	.getname = zhpe_ep_cm_getname,
#ifdef NOT_YET
	.getpeer = zhpe_ep_cm_getpeer,
#else
	.getpeer = fi_no_getpeer,
#endif
	.connect = fi_no_connect,
	.listen = fi_no_listen,
	.accept = fi_no_accept,
	.reject = fi_no_reject,
#ifdef NOTYET
	.shutdown = zhpe_ep_cm_shutdown,
#else
	.shutdown = fi_no_shutdown,
#endif
	.join = fi_no_join,
};

struct fi_ops_cm zhpe_ep_cm_bad_ops = {
	.size			= sizeof(struct fi_ops_cm),
	.setname		= fi_no_setname,
	.getname		= fi_no_getname,
	.getpeer		= fi_no_getpeer,
	.connect		= fi_no_connect,
	.listen			= fi_no_listen,
	.accept			= fi_no_accept,
	.reject			= fi_no_reject,
	.shutdown		= fi_no_shutdown,
	.join			= fi_no_join,
};

#ifdef NOTYET

static int zhpe_pep_fi_bind(fid_t fid, struct fid *bfid, uint64_t flags)
{
	struct zhpe_pep *pep;
	struct zhpe_eq *eq;

	pep = container_of(fid, struct zhpe_pep, pep.fid);

	if (bfid->fclass != FI_CLASS_EQ)
		return -FI_EINVAL;

	eq = container_of(bfid, struct zhpe_eq, eq.fid);
	if (pep->zhpe_fab != eq->zhpe_fab) {
		ZHPE_LOG_ERROR("Cannot bind Passive EP and EQ on different fabric\n");
		return -FI_EINVAL;
	}
	pep->eq = eq;
	return 0;
}

static int zhpe_pep_fi_close(fid_t fid)
{
	int ret;
	char c = 0;
	struct zhpe_pep *pep;

	pep = container_of(fid, struct zhpe_pep, pep.fid);
	pep->cm.do_listen = 0;
	ret = ofi_write_socket(pep->cm.signal_fds[0], &c, 1);
	if (ret != 1)
		ZHPE_LOG_DBG("Failed to signal\n");

	if (pep->cm.listener_thread_valid &&
	    pthread_join(pep->cm.listener_thread, NULL)) {
		ZHPE_LOG_DBG("pthread join failed\n");
	}

	ofi_close_socket(pep->cm.signal_fds[0]);
	ofi_close_socket(pep->cm.signal_fds[1]);
	fastlock_destroy(&pep->cm.lock);

	free(pep);
	return 0;
}

static struct fi_ops zhpe_pep_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = zhpe_pep_fi_close,
	.bind = zhpe_pep_fi_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

static struct fi_info *zhpe_ep_msg_get_info(struct zhpe_pep *pep,
					    struct zhpe_conn_req *req)
{
	struct fi_info hints;
	uint64_t requested, supported;

	requested = req->caps & ZHPE_EP_MSG_PRI_CAP;
	supported = pep->info.caps & ZHPE_EP_MSG_PRI_CAP;
	supported = (supported & FI_RMA) ?
		(supported | FI_REMOTE_READ | FI_REMOTE_WRITE) : supported;
	if ((requested | supported) != supported)
		return NULL;

	hints = pep->info;
	hints.caps = req->caps;
	return zhpe_fi_info(pep->zhpe_fab->fab_fid.api_version,
			    &hints, &pep->src_addr, &req->src_addr,
			    ZHPE_EP_MSG_CAP, ZHPE_MODE,
			    &zhpe_msg_ep_attr, &zhpe_msg_tx_attr,
			    &zhpe_msg_rx_attr);
}

static void *zhpe_pep_req_handler(void *data)
{
	int ret, entry_sz;
	struct fi_info *info;
	struct zhpe_conn_req *conn_req = NULL;
	struct fi_eq_cm_entry *cm_entry = NULL;
	struct zhpe_conn_req_handle *handle = data;
	int req_cm_data_sz;
	char c = 0;

	conn_req = calloc(1, sizeof(*conn_req) + ZHPE_EP_MAX_CM_DATA_SZ);
	if (!conn_req) {
		ZHPE_LOG_ERROR("cannot allocate memory\n");
		goto err;
	}

	ret = zhpe_cm_recv(handle->zhpe_fd, conn_req, sizeof(*conn_req));
	if (ret) {
		ZHPE_LOG_ERROR("IO failed\n");
		goto err;
	}

	req_cm_data_sz = ntohs(conn_req->hdr.cm_data_sz);
	if (req_cm_data_sz) {
		ret = zhpe_cm_recv(handle->zhpe_fd, conn_req->cm_data,
				   req_cm_data_sz);
		if (ret) {
			ZHPE_LOG_ERROR("IO failed for cm-data\n");
			goto err;
		}
	}

	info = zhpe_ep_msg_get_info(handle->pep, conn_req);
	if (info == NULL) {
		handle->paramlen = 0;
		fastlock_acquire(&handle->pep->cm.lock);
		dlist_insert_tail(&handle->lentry, &handle->pep->cm.msg_list);
		fastlock_release(&handle->pep->cm.lock);

		if (ofi_write_socket(handle->pep->cm.signal_fds[0], &c, 1) != 1)
			ZHPE_LOG_DBG("Failed to signal\n");
		free(conn_req);
		return NULL;
	}

	cm_entry = calloc(1, sizeof(*cm_entry) + req_cm_data_sz);
	if (!cm_entry) {
		ZHPE_LOG_ERROR("cannot allocate memory\n");
		goto err;
	}

	handle->handle.fclass = FI_CLASS_CONNREQ;
	handle->req = conn_req;

	entry_sz = sizeof(*cm_entry) + req_cm_data_sz;
	cm_entry->fid = &handle->pep->pep.fid;
	cm_entry->info = info;
	cm_entry->info->handle = &handle->handle;
	memcpy(cm_entry->data, conn_req->cm_data, req_cm_data_sz);

	ZHPE_LOG_DBG("reporting conn-req to EQ\n");
	if (zhpe_eq_report_event(handle->pep->eq, FI_CONNREQ, cm_entry, entry_sz, 0))
		ZHPE_LOG_ERROR("Error in writing to EQ\n");

	free(cm_entry);
	return NULL;
err:
	ofi_close_socket(handle->zhpe_fd);
	free(cm_entry);
	free(conn_req);
	free(handle);
	return NULL;
}

static void zhpe_pep_check_msg_list(struct zhpe_pep *pep)
{
	struct dlist_entry *entry;
	struct zhpe_conn_req_handle *hreq;
	struct zhpe_conn_hdr reply;

	fastlock_acquire(&pep->cm.lock);
	while (!dlist_empty(&pep->cm.msg_list)) {
		entry = pep->cm.msg_list.next;
		dlist_remove(entry);
		hreq = container_of(entry, struct zhpe_conn_req_handle,
				    lentry);

		reply.type = ZHPE_CONN_REJECT;
		reply.cm_data_sz = htons(hreq->paramlen);

		ZHPE_LOG_DBG("sending reject message\n");
		if (zhpe_cm_send(hreq->zhpe_fd, &reply, sizeof(reply))) {
			ZHPE_LOG_ERROR("failed to reply\n");
			break;
		}

		if (hreq->paramlen && zhpe_cm_send(hreq->zhpe_fd, hreq->cm_data,
						   hreq->paramlen)) {
			ZHPE_LOG_ERROR("failed to send userdata\n");
			break;
		}

		if (pthread_join(hreq->req_handler, NULL))
			ZHPE_LOG_DBG("failed to join req-handler\n");
		ofi_close_socket(hreq->zhpe_fd);
		free(hreq->req);
		free(hreq);
	}
	fastlock_release(&pep->cm.lock);
}

static void *zhpe_pep_listener_thread(void *data)
{
	struct zhpe_pep *pep = (struct zhpe_pep *) data;
	struct zhpe_conn_req_handle *handle = NULL;
	struct pollfd poll_fds[2];

	int ret = 0, conn_fd;
	char tmp = 0;

	ZHPE_LOG_DBG("Starting listener thread for PEP: %p\n", pep);
	poll_fds[0].fd = pep->cm.sock;
	poll_fds[1].fd = pep->cm.signal_fds[1];
	poll_fds[0].events = poll_fds[1].events = POLLIN;
	while (*((volatile int *) &pep->cm.do_listen)) {
		ret = poll(poll_fds, 2, -1);
		if (ret > 0) {
			if (poll_fds[1].revents & POLLIN) {
				ret = ofi_read_socket(pep->cm.signal_fds[1], &tmp, 1);
				if (ret != 1)
					ZHPE_LOG_DBG("Invalid signal\n");
				zhpe_pep_check_msg_list(pep);
				continue;
			}
		} else {
			break;
		}

		conn_fd = accept(pep->cm.sock, NULL, 0);
		if (conn_fd == -1) {
			ZHPE_LOG_ERROR("failed to accept: %d\n", errno);
			continue;
		}

		if (zhpe_set_sockopts_connect(conn_fd) < 0) {
			ofi_close_socket(conn_fd);
			break;
		}

		handle = calloc(1, sizeof(*handle));
		if (!handle) {
			ZHPE_LOG_ERROR("cannot allocate memory\n");
			ofi_close_socket(conn_fd);
			break;
		}

		handle->zhpe_fd = conn_fd;
		handle->pep = pep;

		if (pthread_create(&handle->req_handler, NULL,
				   zhpe_pep_req_handler, handle)) {
			ZHPE_LOG_ERROR("failed to create req handler\n");
			ofi_close_socket(conn_fd);
			free(handle);
		}
		handle->req_handler_valid = true;
	}

	ZHPE_LOG_DBG("PEP listener thread exiting\n");
	ofi_close_socket(pep->cm.sock);
	return NULL;
}

static int zhpe_pep_start_listener_thread(struct zhpe_pep *pep)
{
	if (pthread_create(&pep->cm.listener_thread, NULL,
			   zhpe_pep_listener_thread, (void *)pep)) {
		ZHPE_LOG_ERROR("Couldn't create listener thread\n");
		return -FI_EINVAL;
	}
	pep->cm.listener_thread_valid = true;
	return 0;
}

static int zhpe_pep_listen(struct fid_pep *pep)
{
	struct zhpe_pep *_pep;
	_pep = container_of(pep, struct zhpe_pep, pep);
	if (_pep->cm.listener_thread)
		return 0;

	if (!_pep->cm.do_listen && zhpe_pep_create_listener(_pep)) {
		ZHPE_LOG_ERROR("Failed to create pep thread\n");
		return -FI_EINVAL;
	}

	return zhpe_pep_start_listener_thread(_pep);
}

static int zhpe_pep_reject(struct fid_pep *pep, fid_t handle,
		const void *param, size_t paramlen)
{
	struct zhpe_conn_req_handle *hreq;
	struct zhpe_conn_req *req;
	struct zhpe_pep *_pep;
	char c = 0;

	_pep = container_of(pep, struct zhpe_pep, pep);
	hreq = container_of(handle, struct zhpe_conn_req_handle, handle);
	req = hreq->req;
	if (!req || hreq->handle.fclass != FI_CLASS_CONNREQ || hreq->is_accepted)
		return -FI_EINVAL;

	hreq->paramlen = 0;
	if (paramlen) {
		memcpy(hreq->cm_data, param, paramlen);
		hreq->paramlen = paramlen;
	}

	fastlock_acquire(&_pep->cm.lock);
	dlist_insert_tail(&hreq->lentry, &_pep->cm.msg_list);
	fastlock_release(&_pep->cm.lock);

	if (ofi_write_socket(_pep->cm.signal_fds[0], &c, 1) != 1)
		ZHPE_LOG_DBG("Failed to signal\n");
	return 0;
}

static struct fi_ops_cm zhpe_pep_cm_ops = {
	.size = sizeof(struct fi_ops_cm),
	.setname = zhpe_ep_cm_setname,
	.getname = zhpe_ep_cm_getname,
	.getpeer = fi_no_getpeer,
	.connect = fi_no_connect,
	.listen = zhpe_pep_listen,
	.accept = fi_no_accept,
	.reject = zhpe_pep_reject,
	.shutdown = fi_no_shutdown,
	.join = fi_no_join,
};


int zhpe_pep_getopt(fid_t fid, int level, int optname,
		      void *optval, size_t *optlen)
{
	if (level != FI_OPT_ENDPOINT || optname != FI_OPT_CM_DATA_SIZE)
		return -FI_ENOPROTOOPT;

	if (*optlen < sizeof(size_t)) {
		*optlen = sizeof(size_t);
		return -FI_ETOOSMALL;
	}
	*((size_t *) optval) = ZHPE_EP_MAX_CM_DATA_SZ;
	*optlen = sizeof(size_t);
	return 0;
}

static struct fi_ops_ep zhpe_pep_ops = {
	.size = sizeof(struct fi_ops_ep),
	.getopt = zhpe_pep_getopt,
	.setopt = fi_no_setopt,
	.tx_ctx = fi_no_tx_ctx,
	.rx_ctx = fi_no_rx_ctx,
	.rx_size_left = fi_no_rx_size_left,
	.tx_size_left = fi_no_tx_size_left,
};

int zhpe_msg_sep(struct fid_domain *domain, struct fi_info *info,
		 struct fid_ep **sep, void *context)
{
	int ret;
	struct zhpe_ep *endpoint;

	ret = zhpe_msg_endpoint(domain, info, &endpoint, context, FI_CLASS_SEP);
	if (ret)
		return ret;

	*sep = &endpoint->ep;
	return 0;
}

int zhpe_msg_passive_ep(struct fid_fabric *fabric, struct fi_info *info,
			struct fid_pep **pep, void *context)
{
	int			ret = 0;
	struct addrinfo		*rai = NULL;
	struct addrinfo		ai;
	struct zhpe_pep		*_pep;

	if (info) {
		ret = zhpe_verify_info(fabric->api_version, info, FI_SOURCE);
		if (ret) {
			ZHPE_LOG_DBG("Cannot support requested options!\n");
			return ret;
		}
	}

	_pep = calloc(1, sizeof(*_pep));
	if (!_pep)
		return -FI_ENOMEM;

	if (info) {
		if (info->src_addr)
			zhpeu_sockaddr_cpy(&_pep->src_addr, info->src_addr);
		else {
			zhpe_getaddrinfo_hints_init(&ai, zhpe_sa_family(info));
			ai.ai_flags |= AI_PASSIVE;
			ret = zhpe_getaddrinfo(NULL, "0", &ai, &rai);
			if (ret < 0)
				goto err;
			zhpeu_sockaddr_cpy(&_pep->src_addr, rai->ai_addr);
			freeaddrinfo(rai);
		}
		_pep->info = *info;
	} else {
		ZHPE_LOG_ERROR("invalid fi_info\n");
		ret = -FI_EINVAL;
		goto err;
	}

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, _pep->cm.signal_fds);
	if (ret) {
		ret = -errno;
		goto err;
	}

	fi_fd_nonblock(_pep->cm.signal_fds[1]);
	dlist_init(&_pep->cm.msg_list);

	_pep->pep.fid.fclass = FI_CLASS_PEP;
	_pep->pep.fid.context = context;
	_pep->pep.fid.ops = &zhpe_pep_fi_ops;
	_pep->pep.cm = &zhpe_pep_cm_ops;
	_pep->pep.ops = &zhpe_pep_ops;
	fastlock_init(&_pep->cm.lock);

	_pep->zhpe_fab = container_of(fabric, struct zhpe_fabric, fab_fid);
	*pep = &_pep->pep;
	return 0;
err:
	free(_pep);
	return ret;
}

#endif
