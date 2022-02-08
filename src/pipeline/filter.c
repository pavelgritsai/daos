/**
 * (C) Copyright 2016-2021 Intel Corporation.
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */

#define D_LOGFAC	DD_FAC(pipeline)

#include <math.h>
#include <string.h>
#include "pipeline_internal.h"
#include <daos/common.h>

#define NTYPES 8
#define TOTALFUNCS 110

static filter_func_t *filter_func_ptrs[TOTALFUNCS] = { filter_func_eq_i1,
						       filter_func_eq_i2,
						       filter_func_eq_i4,
						       filter_func_eq_i8,
						       filter_func_eq_r4,
						       filter_func_eq_r8,
						       filter_func_eq_st,
						       filter_func_eq_raw,
						       filter_func_in_i1,
						       filter_func_in_i2,
						       filter_func_in_i4,
						       filter_func_in_i8,
						       filter_func_in_r4,
						       filter_func_in_r8,
						       filter_func_in_st,
						       filter_func_in_raw,
						       filter_func_ne_i1,
						       filter_func_ne_i2,
						       filter_func_ne_i4,
						       filter_func_ne_i8,
						       filter_func_ne_r4,
						       filter_func_ne_r8,
						       filter_func_ne_st,
						       filter_func_ne_raw,
						       filter_func_lt_i1,
						       filter_func_lt_i2,
						       filter_func_lt_i4,
						       filter_func_lt_i8,
						       filter_func_lt_r4,
						       filter_func_lt_r8,
						       filter_func_lt_st,
						       filter_func_lt_raw,
						       filter_func_le_i1,
						       filter_func_le_i2,
						       filter_func_le_i4,
						       filter_func_le_i8,
						       filter_func_le_r4,
						       filter_func_le_r8,
						       filter_func_le_st,
						       filter_func_le_raw,
						       filter_func_ge_i1,
						       filter_func_ge_i2,
						       filter_func_ge_i4,
						       filter_func_ge_i8,
						       filter_func_ge_r4,
						       filter_func_ge_r8,
						       filter_func_ge_st,
						       filter_func_ge_raw,
						       filter_func_gt_i1,
						       filter_func_gt_i2,
						       filter_func_gt_i4,
						       filter_func_gt_i8,
						       filter_func_gt_r4,
						       filter_func_gt_r8,
						       filter_func_gt_st,
						       filter_func_gt_raw,
						       filter_func_add_i1,
						       filter_func_add_i2,
						       filter_func_add_i4,
						       filter_func_add_i8,
						       filter_func_add_r4,
						       filter_func_add_r8,
						       filter_func_sub_i1,
						       filter_func_sub_i2,
						       filter_func_sub_i4,
						       filter_func_sub_i8,
						       filter_func_sub_r4,
						       filter_func_sub_r8,
						       filter_func_mul_i1,
						       filter_func_mul_i2,
						       filter_func_mul_i4,
						       filter_func_mul_i8,
						       filter_func_mul_r4,
						       filter_func_mul_r8,
						       filter_func_div_i1,
						       filter_func_div_i2,
						       filter_func_div_i4,
						       filter_func_div_i8,
						       filter_func_div_r4,
						       filter_func_div_r8,
						       aggr_func_sum_i1,
						       aggr_func_sum_i2,
						       aggr_func_sum_i4,
						       aggr_func_sum_i8,
						       aggr_func_sum_r4,
						       aggr_func_sum_r8,
						       aggr_func_max_i1,
						       aggr_func_max_i2,
						       aggr_func_max_i4,
						       aggr_func_max_i8,
						       aggr_func_max_r4,
						       aggr_func_max_r8,
						       aggr_func_min_i1,
						       aggr_func_min_i2,
						       aggr_func_min_i4,
						       aggr_func_min_i8,
						       aggr_func_min_r4,
						       aggr_func_min_r8,
						       filter_func_like_st,
						       filter_func_isnull_raw,
						       filter_func_isnotnull_raw,
						       filter_func_not,
						       filter_func_and,
						       filter_func_or };

void
pipeline_aggregations_fixavgs(daos_pipeline_t *pipeline, double total,
			      d_sg_list_t *sgl_agg)
{
	uint32_t		i;
	double			*buf;
	char			*part_type;
	size_t			part_type_s;

	for (i = 0; i < pipeline->num_aggr_filters; i++)
	{
		part_type = (char *) pipeline->aggr_filters[i]->parts[0]->part_type.iov_buf;
		part_type_s = pipeline->aggr_filters[i]->parts[0]->part_type.iov_len;
		if (!strncmp(part_type, "DAOS_FILTER_FUNC_AVG", part_type_s))
		{
			buf = (double *) sgl_agg[i].sg_iovs->iov_buf;
			*buf = *buf / total;
		}
	}
}

void
pipeline_aggregations_init(daos_pipeline_t *pipeline, d_sg_list_t *sgl_agg)
{
	uint32_t		i;
	double			*buf;
	daos_filter_part_t	*part;
	char			*part_type;
	size_t			part_type_s;

	for (i = 0; i < pipeline->num_aggr_filters; i++)
	{
		part      = pipeline->aggr_filters[i]->parts[0];
		buf       = (double *) sgl_agg[i].sg_iovs->iov_buf;
		part_type   = (char *) part->part_type.iov_buf;
		part_type_s = part->part_type.iov_len;

		if (!strncmp(part_type, "DAOS_FILTER_FUNC_MAX", part_type_s))
		{
			*buf = -INFINITY;
		}
		else if (!strncmp(part_type, "DAOS_FILTER_FUNC_MIN", part_type_s))
		{
			*buf = INFINITY;
		}
		else
		{
			*buf = 0;
		}
	}
}

static uint32_t
calc_type_idx(char *type, size_t type_len)
{
	if (!strncmp(type, "DAOS_FILTER_TYPE_INTEGER1", type_len))
	{
		return 0;
	}
	else if (!strncmp(type, "DAOS_FILTER_TYPE_INTEGER2", type_len))
	{
		return 1;
	}
	else if (!strncmp(type, "DAOS_FILTER_TYPE_INTEGER4", type_len))
	{
		return 2;
	}
	else if (!strncmp(type, "DAOS_FILTER_TYPE_INTEGER8", type_len))
	{
		return 3;
	}
	else if (!strncmp(type, "DAOS_FILTER_TYPE_REAL4", type_len))
	{
		return 4;
	}
	else if (!strncmp(type, "DAOS_FILTER_TYPE_REAL8", type_len))
	{
		return 5;
	}
	else if (!strncmp(type, "DAOS_FILTER_TYPE_STRING", type_len))
	{
		return 6;
	}
	else
	{
		return 7;
	}
}

static uint32_t
calc_base_idx(daos_filter_part_t **parts, uint32_t idx)
{
	char		*part_type;
	size_t		part_type_s;

	part_type   = (char *) parts[idx]->part_type.iov_buf;
	part_type_s = parts[idx]->part_type.iov_len;

	if (!strncmp(part_type, "DAOS_FILTER_FUNC_EQ", part_type_s))
	{
		return 0;
	}
	else if (!strncmp(part_type, "DAOS_FILTER_FUNC_IN", part_type_s))
	{
		return NTYPES;
	}
	else if (!strncmp(part_type, "DAOS_FILTER_FUNC_NE", part_type_s))
	{
		return NTYPES * 2;
	}
	else if (!strncmp(part_type, "DAOS_FILTER_FUNC_LT", part_type_s))
	{
		return NTYPES * 3;
	}
	else if (!strncmp(part_type, "DAOS_FILTER_FUNC_LE", part_type_s))
	{
		return NTYPES * 4;
	}
	else if (!strncmp(part_type, "DAOS_FILTER_FUNC_GE", part_type_s))
	{
		return NTYPES * 5;
	}
	else if (!strncmp(part_type, "DAOS_FILTER_FUNC_GT", part_type_s))
	{
		return NTYPES * 6;
	}
	else if (!strncmp(part_type, "DAOS_FILTER_FUNC_ADD", part_type_s))
	{
		return NTYPES * 7;
	}
	else if (!strncmp(part_type, "DAOS_FILTER_FUNC_SUB", part_type_s))
	{
		return (NTYPES * 7) + (NTYPES - 2);
	}
	else if (!strncmp(part_type, "DAOS_FILTER_FUNC_MUL", part_type_s))
	{
		return (NTYPES * 7) + ((NTYPES - 2) * 2);
	}
	else if (!strncmp(part_type, "DAOS_FILTER_FUNC_DIV", part_type_s))
	{
		return (NTYPES * 7) + ((NTYPES - 2) * 3);
	}
	else if (!strncmp(part_type, "DAOS_FILTER_FUNC_SUM", part_type_s) ||
		 !strncmp(part_type, "DAOS_FILTER_FUNC_AVG", part_type_s))
	{
		return (NTYPES * 7) + ((NTYPES - 2) * 4);
	}
	else if (!strncmp(part_type, "DAOS_FILTER_FUNC_MAX", part_type_s))
	{
		return (NTYPES * 7) + ((NTYPES - 2) * 5);
	}
	else if (!strncmp(part_type, "DAOS_FILTER_FUNC_MIN", part_type_s))
	{
		return (NTYPES * 7) + ((NTYPES - 2) * 6);
	}
	else if (!strncmp(part_type, "DAOS_FILTER_FUNC_LIKE", part_type_s))
	{
		return (NTYPES * 7) + ((NTYPES - 2) * 7);
	}
	else if (!strncmp(part_type, "DAOS_FILTER_FUNC_ISNULL", part_type_s))
	{
		return (NTYPES * 7) + ((NTYPES - 2) * 7) + 1;
	}
	else if (!strncmp(part_type, "DAOS_FILTER_FUNC_ISNOTNULL", part_type_s))
	{
		return (NTYPES * 7) + ((NTYPES - 2) * 7) + 2;
	}
	else if (!strncmp(part_type, "DAOS_FILTER_FUNC_NOT", part_type_s))
	{
		return (NTYPES * 7) + ((NTYPES - 2) * 7) + 3;
	}
	else if (!strncmp(part_type, "DAOS_FILTER_FUNC_AND", part_type_s))
	{
		return (NTYPES * 7) + ((NTYPES - 2) * 7) + 4;
	}
	else /* if (!strncmp(part_type, "DAOS_FILTER_FUNC_OR", part_type_s)) */
	{
		return (NTYPES * 7) + ((NTYPES - 2) * 7) + 5;
	}
}

static uint32_t
calc_num_operands(daos_filter_part_t **parts, uint32_t idx)
{
	daos_filter_part_t	*child_part;
	char			*part_type;
	size_t			part_type_s;
	uint32_t		nops = 0;

	part_type   = (char *) parts[idx]->part_type.iov_buf;
	part_type_s = parts[idx]->part_type.iov_len;

	if (!strncmp(part_type, "DAOS_FILTER_FUNC_EQ", part_type_s)  ||
	    !strncmp(part_type, "DAOS_FILTER_FUNC_IN", part_type_s)  ||
	    !strncmp(part_type, "DAOS_FILTER_FUNC_NE", part_type_s)  ||
	    !strncmp(part_type, "DAOS_FILTER_FUNC_LT", part_type_s)  ||
	    !strncmp(part_type, "DAOS_FILTER_FUNC_LE", part_type_s)  ||
	    !strncmp(part_type, "DAOS_FILTER_FUNC_GE", part_type_s)  ||
	    !strncmp(part_type, "DAOS_FILTER_FUNC_GT", part_type_s)  ||
	    !strncmp(part_type, "DAOS_FILTER_FUNC_AND", part_type_s) ||
	    !strncmp(part_type, "DAOS_FILTER_FUNC_OR", part_type_s)  ||
	    !strncmp(part_type, "DAOS_FILTER_FUNC_ADD", part_type_s) ||
	    !strncmp(part_type, "DAOS_FILTER_FUNC_SUB", part_type_s) ||
	    !strncmp(part_type, "DAOS_FILTER_FUNC_MUL", part_type_s) ||
	    !strncmp(part_type, "DAOS_FILTER_FUNC_DIV", part_type_s) ||
	    !strncmp(part_type, "DAOS_FILTER_FUNC_LIKE", part_type_s))
	{
		nops = 2;
		if (!strncmp(part_type, "DAOS_FILTER_FUNC_IN", part_type_s))
		{
			child_part = parts[idx + 2];

			if (!strncmp((char *) child_part->part_type.iov_buf,
				     "DAOS_FILTER_CONST",
				     child_part->part_type.iov_len))
			{
				nops += child_part->num_constants - 1;
			}
		}
	}
	else if (!strncmp(part_type, "DAOS_FILTER_FUNC_ISNULL", part_type_s)    ||
		 !strncmp(part_type, "DAOS_FILTER_FUNC_ISNOTNULL", part_type_s) ||
		 !strncmp(part_type, "DAOS_FILTER_FUNC_NOT", part_type_s)       ||
		 !strncmp(part_type, "DAOS_FILTER_FUNC_SUM", part_type_s)       ||
		 !strncmp(part_type, "DAOS_FILTER_FUNC_MIN", part_type_s)       ||
		 !strncmp(part_type, "DAOS_FILTER_FUNC_MAX", part_type_s)       ||
		 !strncmp(part_type, "DAOS_FILTER_FUNC_AVG", part_type_s))
	{
		nops = 1;
	}

	return nops;
}

static int
compile_filter(daos_filter_t *filter, struct filter_compiled_t *comp_filter,
	       uint32_t *part_idx, uint32_t *comp_part_idx,
	       char **type, size_t *type_len)
{
	uint32_t			nops;
	uint32_t			func_idx;
	uint32_t			i;
	char				*part_type;
	size_t				part_type_s;
	size_t				comp_size;
	struct filter_part_compiled_t	*comp_part;
	int				rc;
	uint32_t			idx;


	part_type   = (char *) filter->parts[*part_idx]->part_type.iov_buf;
	part_type_s = filter->parts[*part_idx]->part_type.iov_len;

	comp_part   = &comp_filter->parts[*comp_part_idx];
	*comp_part  = (struct filter_part_compiled_t) { 0 };

	if (part_type_s < strlen("DAOS_FILTER_FUNC"))
	{
		comp_size = part_type_s;
	}
	else
	{
		comp_size = strlen("DAOS_FILTER_FUNC");
	}

	if (strncmp(part_type, "DAOS_FILTER_FUNC", comp_size)) /** != FUNC */
	{
		comp_part->data_offset = filter->parts[*part_idx]->data_offset;
		comp_part->data_len = filter->parts[*part_idx]->data_len;
		*type = (char *) filter->parts[*part_idx]->data_type.iov_buf;
		*type_len = filter->parts[*part_idx]->data_type.iov_len;

		if (!strncmp(part_type, "DAOS_FILTER_AKEY", part_type_s))
		{
			comp_part->iov = &filter->parts[*part_idx]->akey;
			comp_part->filter_func = getdata_func_akey;
		}
		else if (!strncmp(part_type, "DAOS_FILTER_CONST", part_type_s))
		{
			comp_part->iov = &filter->parts[*part_idx]->constant[0];
			comp_part->filter_func = getdata_func_const;

			for (i = 1;
			     i < filter->parts[*part_idx]->num_constants;
			     i++)
			{
				*comp_part_idx += 1;
				comp_part = &comp_filter->parts[*comp_part_idx];
				*comp_part =
					(struct filter_part_compiled_t) { 0 };
				comp_part->iov =
					&filter->parts[*part_idx]->constant[i];
				comp_part->filter_func = getdata_func_const;
			}
		}
		else if (!strncmp(part_type, "DAOS_FILTER_DKEY", part_type_s))
		{
			comp_part->filter_func = getdata_func_dkey;
		}
		D_GOTO(exit, rc = 0);
	}

	nops = calc_num_operands(filter->parts, *part_idx);
	comp_part->num_operands = nops;

	/** recursive calls for function parameters */
	idx	= *part_idx;
	for (i = 0; i < nops; i++)
	{
		*comp_part_idx	+= 1;
		*part_idx	+= 1;
		rc = compile_filter(filter, comp_filter, part_idx,
				    comp_part_idx, type, type_len);
		if (rc != 0)
		{
			D_GOTO(exit, rc);
		}
	}

	func_idx  = calc_base_idx(filter->parts, idx);

	if (func_idx < (NTYPES * 7) + ((NTYPES - 2) * 7))
	{
		func_idx += calc_type_idx(*type, *type_len);
	}

	comp_part->filter_func = filter_func_ptrs[func_idx];

exit:
	return rc;
}

static int
compile_filters(daos_filter_t **ftrs, uint32_t nftrs,
		struct filter_compiled_t *c_ftrs)
{
	uint32_t		part_idx;
	uint32_t		comp_part_idx;
	uint32_t		comp_num_parts;
	uint32_t 		i, j;
	int			rc = 0;
	daos_filter_part_t	*part;
	char			*type;
	size_t			type_len;

	for (i = 0; i < nftrs; i++)
	{
		comp_num_parts = ftrs[i]->num_parts;
		for (j = 0; j < ftrs[i]->num_parts; j++)
		{
			part = ftrs[i]->parts[j];

			if (!strncmp((char *) part->part_type.iov_buf,
				     "DAOS_FILTER_CONST",
				     part->part_type.iov_len))
			{
				comp_num_parts += part->num_constants - 1;
			}
		}

		D_ALLOC_ARRAY(c_ftrs[i].parts, comp_num_parts);
		if (c_ftrs[i].parts == NULL)
		{
			D_GOTO(exit, rc = -DER_NOMEM);
		}
		c_ftrs[i].num_parts = comp_num_parts;

		part_idx	= 0;
		comp_part_idx	= 0;
		type		= NULL;
		type_len	= 0;
		rc = compile_filter(ftrs[i], &c_ftrs[i], &part_idx,
				    &comp_part_idx, &type, &type_len);
		if (rc != 0)
		{
			D_GOTO(exit, rc);
		}
	}
exit:
	return rc;
}

int
pipeline_compile(daos_pipeline_t *pipe, struct pipeline_compiled_t *comp_pipe)
{
	int rc = 0;

	comp_pipe->num_filters		= 0;
	comp_pipe->filters		= NULL;
	comp_pipe->num_aggr_filters	= 0;
	comp_pipe->aggr_filters		= NULL;

	if (pipe->num_filters > 0)
	{
		D_ALLOC_ARRAY(comp_pipe->filters, pipe->num_filters);
		if (comp_pipe->filters == NULL)
		{
			D_GOTO(exit, rc = -DER_NOMEM);
		}
		comp_pipe->num_filters = pipe->num_filters;

		rc = compile_filters(pipe->filters, pipe->num_filters,
				     comp_pipe->filters);
		if (rc != 0)
		{
			D_GOTO(exit, rc);
		}
	}
	if (pipe->num_aggr_filters > 0)
	{
		D_ALLOC_ARRAY(comp_pipe->aggr_filters, pipe->num_aggr_filters);
		if (comp_pipe->aggr_filters == NULL)
		{
			D_GOTO(exit, rc = -DER_NOMEM);
		}
		comp_pipe->num_aggr_filters = pipe->num_aggr_filters;

		rc = compile_filters(pipe->aggr_filters, pipe->num_aggr_filters,
				     comp_pipe->aggr_filters);
		if (rc != 0)
		{
			D_GOTO(exit, rc);
		}
	}
exit:
	return rc;
}

void
pipeline_compile_free(struct pipeline_compiled_t *comp_pipe)
{
	uint32_t i;

	if (comp_pipe->num_filters > 0)
	{
		for (i = 0; i < comp_pipe->num_filters; i++)
		{
			if (comp_pipe->filters[i].num_parts > 0)
			{
				D_FREE(comp_pipe->filters[i].parts);
			}
		}
		D_FREE(comp_pipe->filters);
	}
	if (comp_pipe->num_aggr_filters > 0)
	{
		for (i = 0; i < comp_pipe->num_aggr_filters; i++)
		{
			if (comp_pipe->aggr_filters[i].num_parts > 0)
			{
				D_FREE(comp_pipe->aggr_filters[i].parts);
			}
		}
		D_FREE(comp_pipe->aggr_filters);
	}
}
