/**
 * (C) Copyright 2022 Intel Corporation.
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */

#ifndef __DAOS_CHK_H__
#define __DAOS_CHK_H__

#include <gurt/list.h>
#include <daos_prop.h>
#include <daos_types.h>
#include <daos/btree.h>

struct chk_policy {
	uint32_t		cp_class;
	uint32_t		cp_action;
};

/* Time information on related component: system, pool or target. */
struct chk_time {
	/* The time of check instance being started on the component. */
	uint64_t		ct_start_time;
	union {
		/* The time of the check instance completed, failed or stopped on the component. */
		uint64_t	ct_stop_time;
		/* The estimated remaining time to complete the check on the component. */
		uint64_t	ct_left_time;
	};
};

/* Inconsistency statistics on related component: system, pool or target. */
struct chk_statistics {
	/* The count of total found inconsistency on the component. */
	uint64_t		cs_total;
	/* The count of repaired inconsistency on the component. */
	uint64_t		cs_repaired;
	/* The count of ignored inconsistency on the component. */
	uint64_t		cs_ignored;
	/* The count of fail to repaired inconsistency on the component. */
	uint64_t		cs_failed;
};

struct chk_query_target {
	d_rank_t		cqt_rank;
	uint32_t		cqt_tgt;
	uint32_t		cqt_ins_status;
	uint32_t		cqt_padding;
	struct chk_statistics	cqt_statistics;
	struct chk_time		cqt_time;
};

struct chk_query_pool_shard {
	uuid_t			 cqps_uuid;
	uint32_t		 cqps_status;
	uint32_t		 cqps_phase;
	struct chk_statistics	 cqps_statistics;
	struct chk_time		 cqps_time;
	uint32_t		 cqps_rank;
	uint32_t		 cqps_target_nr;
	struct chk_query_target	*cqps_targets;
};

/* Warp of chk_query_pool_shard. */
struct chk_query_pool_warp {
	/* Link to chk_query_pool::cqp_shards. */
	d_list_t			cqpw_link;
	struct chk_query_pool_shard	cqpw_shard;
};

struct chk_query_pool {
	uuid_t			cqp_uuid;
	char			cqp_label[DAOS_PROP_MAX_LABEL_BUF_LEN];
	/* List of chk_query_pool_shard_warp. */
	d_list_t		cqp_shards;
};

struct chk_query_result {
	uint32_t		cqr_ins_status;
	uint32_t		cqr_ins_phase;
	struct chk_statistics	cqr_statistics;
	struct chk_time		cqr_time;
	struct btr_root		cqr_pools_btr;
	daos_handle_t		cqr_pools_hdl;
};

typedef int (*chk_query_cb_t)(void *args, void *data);

typedef int (*chk_prop_cb_t)(void *buf, struct chk_policy **policies, int cnt, uint32_t flags);

int chk_leader_start(uint32_t rank_nr, d_rank_t *ranks, uint32_t policy_nr,
		     struct chk_policy **policies, uint32_t pool_nr, uuid_t pools[],
		     uint32_t flags, int32_t phase);

int chk_leader_stop(uint32_t pool_nr, uuid_t pools[]);

int chk_leader_query(uint32_t pool_nr, uuid_t pools[], chk_query_cb_t query_cb, void *buf);

int chk_leader_prop(chk_prop_cb_t prop_cb, void *buf);

int chk_leader_act(uint64_t seq, uint32_t act, bool for_all);

#endif /* __DAOS_CHK_H__ */
