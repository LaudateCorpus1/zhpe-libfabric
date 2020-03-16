/*
 * Copyright (c) 2014,2018 Intel Corporation, Inc.  All rights reserved.
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

#include <zhpe.h>

#define ZHPE_SUBSYS	FI_LOG_EQ

ssize_t zhpe_eq_report_event(struct util_eq *eq, uint32_t event,
			     const void *buf, size_t len)
{
	return ofi_eq_write(&eq->eq_fid, event, buf, len, 0);
}

ssize_t zhpe_eq_report_error(struct util_eq *eq, fid_t fid, void *context,
                             uint64_t data, int err, int prov_errno,
                             void *err_data, size_t err_data_size)
{
        ssize_t                 ret = -FI_ENOMEM;
	void			*err_data_buf = NULL;
        struct fi_eq_err_entry  err_entry;

        if (err_data && err_data_size) {
                err_data_buf = malloc(err_data_size);
                if (!err_data_buf)
                        goto done;
                memcpy(err_data_buf, err_data, err_data_size);
        } else
		err_data_size = 0;

        err_entry.fid		= fid;
        err_entry.context	= context;
        err_entry.data		= data;
        err_entry.err		= err;
        err_entry.prov_errno	= prov_errno;
        err_entry.err_data	= err_data_buf;
        err_entry.err_data_size	= err_data_size;

	ret = ofi_eq_write(&eq->eq_fid, 0, &err_entry, sizeof(err_entry),
			   UTIL_FLAG_ERROR);
 done:
	if (ret < 0) {
		free(err_data_buf);
		ZHPE_LOG_ERROR("error %d:%s\n", (int)ret, fi_strerror(-ret));
	}

        return ret;
}

static int zhpe_eq_close(struct fid *fid)
{
	int			ret;
	struct zhpe_eq		*zeq;

	zeq = fid2zeq(fid);
	ret = ofi_eq_cleanup(fid);
	if (ret < 0)
		goto done;
	free(zeq);
 done:

	return ret;
}

static struct fi_ops zhpe_eq_fi_ops = {
	.size			= sizeof(struct fi_ops),
	.close			= zhpe_eq_close,
	.bind			= fi_no_bind,
	.control		= ofi_eq_control,
	.ops_open		= fi_no_ops_open,
};

int zhpe_eq_open(struct fid_fabric *fid_fabric, struct fi_eq_attr *attr,
		 struct fid_eq **fid_eq, void *context)
{
	int			ret = -FI_EINVAL;
	struct zhpe_eq		*zeq = NULL;
	struct fi_eq_attr	eq_attr;

	if (!fid_eq)
		goto done;
	*fid_eq = NULL;
	if (!fid_fabric || !attr)
		goto done;

	eq_attr = *attr;
	if (!eq_attr.size)
		eq_attr.size = zhpe_eq_def_sz;

	zeq = calloc(1, sizeof(*zeq));
	if (!zeq) {
		ret = -FI_ENOMEM;
		goto done;
	}

	ret = ofi_eq_init(fid_fabric, &eq_attr, &zeq->util_eq.eq_fid, context);
	if (ret < 0)
		goto done;

	*fid_eq = &zeq->util_eq.eq_fid;
	(*fid_eq)->fid.ops = &zhpe_eq_fi_ops;
 done:
	if (ret < 0)
		free(zeq);

	return ret;
}
