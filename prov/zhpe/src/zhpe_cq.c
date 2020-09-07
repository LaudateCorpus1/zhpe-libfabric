/*
 * Copyright (c) 2013-2017 Intel Corporation, Inc.  All rights reserved.
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
 * SOFTWARE.
 */

#include <zhpe.h>

#define ZHPE_SUBSYS	FI_LOG_CQ

static void cq_progress_dummy(struct util_cq *cq)
{
}

void zhpe_cq_report_error(struct util_cq *cq,
			  uint64_t flags, void *op_context, uint64_t len,
			  void *buf, uint64_t cq_data, uint64_t tag,
			  size_t olen, int err, int prov_errno)
{
	int			rc;
	struct fi_cq_err_entry	err_entry;

	assert(err < 0);
	flags = zhpe_cq_sanitize_flags(flags);

	err_entry.op_context	= op_context;
	err_entry.flags		= flags;
	err_entry.len		= len;
	err_entry.buf		= buf;
	err_entry.data		= cq_data;
	err_entry.tag		= tag;
	err_entry.olen		= olen;
	err_entry.err		= -err;
	err_entry.prov_errno	= prov_errno;
	err_entry.err_data	= NULL;
	err_entry.err_data_size = 0;

	rc = ofi_cq_write_error(cq, &err_entry);
	if (OFI_UNLIKELY(rc < 0)) {
		ZHPE_LOG_ERROR("error %d:%s\n", rc, fi_strerror(-rc));
		/* The only reason the util_cq fails is ENOMEM. */
		abort();
	}
}

static int zhpe_cq_close(struct fid *fid)
{
	int			ret;
	struct zhpe_cq		*zcq;

	zcq = fid2zcq(fid);
	ret = ofi_cq_cleanup(&zcq->util_cq);
	if (ret < 0)
		goto done;
	free(zcq);
	ret = 0;

 done:
	return ret;
}

static ssize_t zhpe_cq_sreadfrom(struct fid_cq *cq_fid, void *buf,
				 size_t count, fi_addr_t *src_addr,
				 const void *cond, int timeout)
{
	int			ret;

	for (;;) {
		ret = ofi_cq_sreadfrom(cq_fid, buf, count, src_addr, cond,
				       timeout);
#ifdef NDEBUG
		break;
#else
		/* Cover over signal issues when debugging. */
		if (ret != -FI_EINTR)
			break;
#endif
	}

	return ret;
}

static ssize_t zhpe_cq_sread(struct fid_cq *cq_fid, void *buf, size_t count,
			     const void *cond, int timeout)

{
	int			ret;

	for (;;) {
		ret = ofi_cq_sread(cq_fid, buf, count, cond, timeout);
#ifdef NDEBUG
		break;
#else
		/* Cover over signal issues when debugging. */
		if (ret != -FI_EINTR)
			break;
#endif
	}

	return ret;
}

static const char *zhpe_cq_strerror(struct fid_cq *cq, int prov_errno,
				    const void *err_data, char *buf, size_t len)
{
	const char		*ret;

	switch (prov_errno) {

	case ZHPE_HW_CQ_STATUS_SUCCESS:
		ret = "command success";
		break;

	case ZHPE_HW_CQ_STATUS_XDM_PUT_READ_ERROR:
		ret = "put read error";
		break;

	case ZHPE_HW_CQ_STATUS_XDM_BAD_COMMAND:
		ret = "bad command";
		break;

	case ZHPE_HW_CQ_STATUS_GENZ_UNSUPPORTED_REQ:
		ret = "unsupported request";
		break;

	case ZHPE_HW_CQ_STATUS_GENZ_MALFORMED_PKT:
		ret = "malformed packet";
		break;

	case ZHPE_HW_CQ_STATUS_GENZ_PKT_EXECUTION_ERROR:
		ret = "packet execution error";
		break;

	case ZHPE_HW_CQ_STATUS_GENZ_INVALID_PERMISSION:
		ret = "invalid access permission";
		break;

	case ZHPE_HW_CQ_STATUS_GENZ_COMP_CONTAINMENT:
		ret = "component containment triggered";
		break;

	case ZHPE_HW_CQ_STATUS_GENZ_RDM_QUEUE_FULL:
		ret = "RDM queue full";
		break;

	case ZHPE_HW_CQ_STATUS_GENZ_UNSUPPORTED_SVC:
		ret = "unsupported service";
		break;

	case ZHPE_HW_CQ_STATUS_GENZ_RETRIES_EXCEEDED:
		ret = "retries succeeded";
		break;

	default:
		ret = "unexpected";
		break;

	}

	if (buf && len) {
		strncpy(buf, ret, len - 1);
		buf[len - 1] = '\0';
	}

	return ret;
}

static struct fi_ops_cq zhpe_cq_ops = {
	.size = sizeof(struct fi_ops_cq),
	.read = ofi_cq_read,
	.readfrom = ofi_cq_readfrom,
	.readerr = ofi_cq_readerr,
	.sread = zhpe_cq_sread,
	.sreadfrom = zhpe_cq_sreadfrom,
	.signal = ofi_cq_signal,
	.strerror = zhpe_cq_strerror,
};

static struct fi_ops zhpe_cq_fi_ops = {
	.size		= sizeof(struct fi_ops),
	.close		= zhpe_cq_close,
	.bind		= fi_no_bind,
	.control	= ofi_cq_control,
	.ops_open	= fi_no_ops_open,
};

int zhpe_cq_open(struct fid_domain *fid_domain, struct fi_cq_attr *attr,
		 struct fid_cq **fid_cq, void *context)
{
	int			ret = -FI_EINVAL;
	struct zhpe_dom		*zdom = fid2zdom(&fid_domain->fid);
	struct zhpe_cq		*zcq = NULL;
	ofi_cq_progress_func	progress;
	struct fi_cq_attr	cq_attr;

	if (!fid_cq)
		goto done;
	*fid_cq = NULL;
	if (!fid_domain || !attr)
		goto done;
	if (attr->flags & ~FI_AFFINITY)
		goto done;

	cq_attr = *attr;
	if (!cq_attr.size)
		cq_attr.size = zhpe_cq_def_sz;

	zcq = calloc(1, sizeof(*zcq));
	if (!zcq) {
		ret = -FI_ENOMEM;
		goto done;
	}

	if (zdom->util_domain.data_progress == FI_PROGRESS_MANUAL)
		progress = ofi_cq_progress;
	else
		progress = cq_progress_dummy;

	ret = ofi_cq_init(&zhpe_prov, fid_domain, &cq_attr, &zcq->util_cq,
			  progress, context);
	if (ret < 0)
		goto done;

	*fid_cq = &zcq->util_cq.cq_fid;
	(*fid_cq)->ops = &zhpe_cq_ops;
	(*fid_cq)->fid.ops = &zhpe_cq_fi_ops;

 done:
	if (ret < 0)
		free(zcq);

	return ret;
}
