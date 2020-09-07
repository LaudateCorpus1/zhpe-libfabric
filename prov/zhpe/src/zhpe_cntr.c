/*
 * Copyright (c) 2014 Intel Corporation, Inc.  All rights reserved.
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

#define ZHPE_SUBSYS	FI_LOG_CNTR

static void cntr_progress_dummy(struct util_cntr *cntr)
{
}

static int zhpe_cntr_control(struct fid *fid, int command, void *arg)
{
	struct util_cntr *cntr;

	cntr = &fid2zcntr(fid)->util_cntr;

	switch (command) {

	case FI_GETWAIT:
		if (!cntr->wait)
			return -FI_ENODATA;
		return fi_control(&cntr->wait->wait_fid.fid, FI_GETWAIT, arg);
	default:
		FI_INFO(&zhpe_prov, FI_LOG_CNTR, "Unsupported command\n");
		return -FI_ENOSYS;
	}
}

static int zhpe_cntr_close(struct fid *fid)
{
	int			ret;
	struct zhpe_cntr	*zcntr;

	zcntr = fid2zcntr(fid);
	ret = ofi_cntr_cleanup(&zcntr->util_cntr);
	if (ret < 0)
		goto done;
	free(zcntr);
	ret = 0;

 done:
	return ret;
}

static struct fi_ops zhpe_cntr_fi_ops = {
	.size		= sizeof(struct fi_ops),
	.close		= zhpe_cntr_close,
	.bind		= fi_no_bind,
	.control	= zhpe_cntr_control,
	.ops_open	= fi_no_ops_open,
};

int zhpe_cntr_open(struct fid_domain *fid_domain, struct fi_cntr_attr *attr,
		   struct fid_cntr **fid_cntr, void *context)
{
	int			ret = -FI_EINVAL;
	struct zhpe_dom		*zdom = fid2zdom(&fid_domain->fid);
	struct zhpe_cntr	*zcntr = NULL;
	ofi_cntr_progress_func	progress;

	if (!fid_cntr)
		goto done;
	*fid_cntr = NULL;
	if (!fid_domain || !attr)
		goto done;

	zcntr = calloc(1, sizeof(*zcntr));
	if (!zcntr) {
		ret = -FI_ENOMEM;
		goto done;
	}

	if (zdom->util_domain.data_progress == FI_PROGRESS_MANUAL)
		progress = ofi_cntr_progress;
	else
		progress = cntr_progress_dummy;

	ret = ofi_cntr_init(&zhpe_prov, fid_domain, attr, &zcntr->util_cntr,
			    progress, context);
	if (ret < 0)
		goto done;

	*fid_cntr = &zcntr->util_cntr.cntr_fid;
	(*fid_cntr)->fid.ops = &zhpe_cntr_fi_ops;
 done:
	if (ret < 0)
		free(zcntr);

	return ret;
}
