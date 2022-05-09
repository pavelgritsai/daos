/**
 * (C) Copyright 2022 Intel Corporation.
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */

#define D_LOGFAC	DD_FAC(chk)

#include <daos/rpc.h>
#include <daos/btree.h>
#include <daos/btree_class.h>
#include <daos_srv/daos_chk.h>
#include <daos_srv/daos_engine.h>

#include "chk_internal.h"

static void
chk_free_clues(uint32_t clue_nr, struct ds_pool_clue *clues)
{
	/* XXX: Release the buffers with Liwei's patch. */
}

static void
ds_chk_start_hdlr(crt_rpc_t *rpc)
{
	struct chk_start_in	*csi = crt_req_get(rpc);
	struct chk_start_out	*cso = crt_reply_get(rpc);
	struct ds_pool_clue	*clues = NULL;
	uint32_t		 clue_nr = 0;
	uint32_t		 phase = 0;
	int			 rc;

	rc = chk_engine_start(csi->csi_gen, csi->csi_ranks.ca_count, csi->csi_ranks.ca_arrays,
			      csi->csi_policies.ca_count,
			      (struct chk_policy **)csi->csi_policies.ca_arrays,
			      csi->csi_uuids.ca_count, csi->csi_uuids.ca_arrays,
			      csi->csi_flags, csi->csi_phase, csi->csi_leader_rank,
			      &phase, &clue_nr, &clues);

	cso->cso_status = rc;
	cso->cso_rank = dss_self_rank();
	cso->cso_phase = phase;
	cso->cso_clues.ca_count = clue_nr;
	cso->cso_clues.ca_arrays = clues;
	rc = crt_reply_send(rpc);
	if (rc != 0)
		D_ERROR("Failed to reply check start: "DF_RC"\n", DP_RC(rc));

	chk_free_clues(clue_nr, clues);
}

static void
ds_chk_stop_hdlr(crt_rpc_t *rpc)
{
	struct chk_stop_in	*csi = crt_req_get(rpc);
	struct chk_stop_out	*cso = crt_reply_get(rpc);
	int			 rc;

	rc = chk_engine_stop(csi->csi_gen, csi->csi_uuids.ca_count, csi->csi_uuids.ca_arrays);

	cso->cso_status = rc;
	cso->cso_rank = dss_self_rank();
	rc = crt_reply_send(rpc);
	if (rc != 0)
		D_ERROR("Failed to reply check stop: "DF_RC"\n", DP_RC(rc));
}

static void
ds_chk_query_hdlr(crt_rpc_t *rpc)
{
	struct chk_query_in		*cqi = crt_req_get(rpc);
	struct chk_query_out		*cqo = crt_reply_get(rpc);
	struct chk_query_pool_shard	*shards = NULL;
	int				 rc;

	rc = chk_engine_query(cqi->cqi_gen, cqi->cqi_uuids.ca_count, cqi->cqi_uuids.ca_arrays,
			      &shards);

	if (rc < 0) {
		cqo->cqo_status = rc;
		cqo->cqo_shards.ca_count = 0;
		cqo->cqo_shards.ca_arrays = NULL;
	} else {
		cqo->cqo_status = 0;
		cqo->cqo_shards.ca_count = rc;
		cqo->cqo_shards.ca_arrays = shards;
	}

	rc = crt_reply_send(rpc);
	if (rc != 0)
		D_ERROR("Failed to reply check query: "DF_RC"\n", DP_RC(rc));

	D_FREE(shards);
}

static void
ds_chk_mark_hdlr(crt_rpc_t *rpc)
{
	struct chk_mark_in	*cmi = crt_req_get(rpc);
	struct chk_mark_out	*cmo = crt_reply_get(rpc);
	int			 rc;

	rc = chk_engine_mark_rank_dead(cmi->cmi_gen, cmi->cmi_rank, cmi->cmi_version);

	cmo->cmo_status = rc;
	rc = crt_reply_send(rpc);
	if (rc != 0)
		D_ERROR("Failed to reply check mark rank dead: "DF_RC"\n", DP_RC(rc));
}

static void
ds_chk_act_hdlr(crt_rpc_t *rpc)
{
	struct chk_act_in	*cai = crt_req_get(rpc);
	struct chk_act_out	*cao = crt_reply_get(rpc);
	int			 rc;

	rc = chk_engine_act(cai->cai_gen, cai->cai_seq, cai->cai_cla, cai->cai_act, cai->cai_flags);

	cao->cao_status = rc;
	rc = crt_reply_send(rpc);
	if (rc != 0)
		D_ERROR("Failed to reply check act: "DF_RC"\n", DP_RC(rc));
}

static void
ds_chk_report_hdlr(crt_rpc_t *rpc)
{
	struct chk_report_in	*cri = crt_req_get(rpc);
	struct chk_report_out	*cro = crt_reply_get(rpc);
	int			 rc;

	rc = chk_leader_report(cri->cri_gen, cri->cri_ics_class, cri->cri_ics_action,
			       cri->cri_ics_result, cri->cri_rank, cri->cri_target,
			       (char *)cri->cri_pool, (char *)cri->cri_cont, &cri->cri_obj,
			       &cri->cri_dkey, &cri->cri_akey, cri->cri_msg,
			       cri->cri_options.ca_count, cri->cri_options.ca_arrays,
			       cri->cri_details.ca_count, cri->cri_details.ca_arrays,
			       false, &cro->cro_seq);

	cro->cro_status = rc;
	rc = crt_reply_send(rpc);
	if (rc != 0)
		D_ERROR("Failed to reply check report: "DF_RC"\n", DP_RC(rc));
}

static void
ds_chk_rejoin_hdlr(crt_rpc_t *rpc)
{
	struct chk_rejoin_in	*cri = crt_req_get(rpc);
	struct chk_rejoin_out	*cro = crt_reply_get(rpc);
	int			 rc;

	rc = chk_leader_rejoin(cri->cri_gen, cri->cri_rank, cri->cri_phase);

	cro->cro_status = rc;
	rc = crt_reply_send(rpc);
	if (rc != 0)
		D_ERROR("Failed to reply check rejoin: "DF_RC"\n", DP_RC(rc));
}

static int
ds_chk_init(void)
{
	int	rc;

	rc = dbtree_class_register(DBTREE_CLASS_CHK_POOL, 0, &chk_pool_ops);
	if (rc != 0)
		goto out;

	rc = dbtree_class_register(DBTREE_CLASS_CHK_RANK, 0, &chk_rank_ops);
	if (rc != 0)
		goto out;

	rc = dbtree_class_register(DBTREE_CLASS_CHK_PA, 0, &chk_pending_ops);
	if (rc != 0)
		goto out;

	rc = chk_iv_init();

out:
	return rc;
}

static int
ds_chk_fini(void)
{
	return chk_iv_fini();
}

static int
ds_chk_setup(void)
{
	int	rc;

	/* Do NOT move chk_vos_init into ds_chk_init, because sys_db is not ready at that time. */
	chk_vos_init();

	rc = chk_leader_init();
	if (rc != 0)
		goto out_vos;

	rc = chk_engine_init();
	if (rc != 0)
		goto out_leader;

	/*
	 * Currently, we do NOT support leader to rejoin the former check instance. Because we do
	 * not support leader switch, during current leader down time, the reported inconsistency
	 * and related repair result are lost. Under such case, the admin has to stop and restart
	 * the check explicitly.
	 */

	chk_engine_rejoin();

	goto out_done;

out_leader:
	chk_leader_fini();
out_vos:
	chk_vos_fini();
out_done:
	return rc;
}

static int
ds_chk_cleanup(void)
{
	chk_engine_pause();
	chk_leader_pause();
	chk_engine_fini();
	chk_leader_fini();
	chk_vos_fini();

	return 0;
}

#define X(a, b, c, d, e)	\
{				\
	.dr_opc       = a,	\
	.dr_hdlr      = d,	\
	.dr_corpc_ops = e,	\
}

static struct daos_rpc_handler chk_handlers[] = {
	CHK_PROTO_SRV_RPC_LIST,
};

#undef X

struct dss_module chk_module = {
	.sm_name		= "chk",
	.sm_mod_id		= DAOS_CHK_MODULE,
	.sm_ver			= DAOS_CHK_VERSION,
	.sm_init		= ds_chk_init,
	.sm_fini		= ds_chk_fini,
	.sm_setup		= ds_chk_setup,
	.sm_cleanup		= ds_chk_cleanup,
	.sm_proto_count		= 1,
	.sm_proto_fmt		= &chk_proto_fmt,
	.sm_cli_count		= 0,
	.sm_handlers		= chk_handlers,
};
