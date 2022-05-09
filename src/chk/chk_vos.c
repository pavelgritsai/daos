/**
 * (C) Copyright 2022 Intel Corporation.
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */

#define D_LOGFAC	DD_FAC(chk)

#include <daos_srv/vos.h>
#include <daos_srv/daos_chk.h>
#include <daos_srv/daos_engine.h>

#include "chk_internal.h"

static struct sys_db	*chk_db;

static int
chk_db_fetch(char *key, int key_size, void *val, int val_size)
{
	d_iov_t	key_iov;
	d_iov_t	val_iov;

	d_iov_set(&key_iov, key, key_size);
	d_iov_set(&val_iov, val, val_size);

	return chk_db->sd_fetch(chk_db, CHK_DB_TABLE, &key_iov, &val_iov);
}

static int
chk_db_update(char *key, int key_size, void *val, int val_size)
{
	d_iov_t	key_iov;
	d_iov_t	val_iov;
	int	rc;

	if (chk_db->sd_tx_begin) {
		rc = chk_db->sd_tx_begin(chk_db);
		if (rc != 0)
			return rc;
	}

	d_iov_set(&key_iov, key, key_size);
	d_iov_set(&val_iov, val, val_size);

	rc = chk_db->sd_upsert(chk_db, CHK_DB_TABLE, &key_iov, &val_iov);

	if (chk_db->sd_tx_end)
		rc = chk_db->sd_tx_end(chk_db, rc);

	return rc;
}

static int
chk_db_delete(char *key, int key_size)
{
	d_iov_t	key_iov;
	int	rc;

	if (chk_db->sd_tx_begin) {
		rc = chk_db->sd_tx_begin(chk_db);
		if (rc != 0)
			return rc;
	}

	d_iov_set(&key_iov, key, key_size);

	rc = chk_db->sd_delete(chk_db, CHK_DB_TABLE, &key_iov);

	if (chk_db->sd_tx_end)
		rc = chk_db->sd_tx_end(chk_db, rc);

	return rc;
}

static int
chk_db_traverse(sys_db_trav_cb_t cb, void *args)
{
	return chk_db->sd_traverse(chk_db, CHK_DB_TABLE, cb, args);
}

int
chk_bk_fetch_leader(struct chk_bookmark *cbk)
{
	int	rc;

	rc = chk_db_fetch(CHK_BK_LEADER, strlen(CHK_BK_LEADER), cbk, sizeof(*cbk));
	if (rc != 0 && rc != -DER_ENOENT)
		D_ERROR("Failed to fetch leader bookmark on rank %u: "DF_RC"\n",
			dss_self_rank(), DP_RC(rc));

	return rc;
}

int
chk_bk_update_leader(struct chk_bookmark *cbk)
{
	int	rc;

	rc = chk_db_update(CHK_BK_LEADER, strlen(CHK_BK_LEADER), cbk, sizeof(*cbk));
	if (rc != 0)
		D_ERROR("Failed to update leader bookmark on rank %u: "DF_RC"\n",
			dss_self_rank(), DP_RC(rc));

	return rc;
}

int
chk_bk_delete_leader(void)
{
	int	rc;

	rc = chk_db_delete(CHK_BK_LEADER, strlen(CHK_BK_LEADER));
	if (rc != 0)
		D_ERROR("Failed to delete leader bookmark on rank %u: "DF_RC"\n",
			dss_self_rank(), DP_RC(rc));

	return rc;
}

int
chk_bk_fetch_engine(struct chk_bookmark *cbk)
{
	int	rc;

	rc = chk_db_fetch(CHK_BK_ENGINE, strlen(CHK_BK_ENGINE), cbk, sizeof(*cbk));
	if (rc != 0 && rc != -DER_ENOENT)
		D_ERROR("Failed to fetch engine bookmark on rank %u: "DF_RC"\n",
			dss_self_rank(), DP_RC(rc));

	return rc;
}

int
chk_bk_update_engine(struct chk_bookmark *cbk)
{
	int	rc;

	rc = chk_db_update(CHK_BK_ENGINE, strlen(CHK_BK_ENGINE), cbk, sizeof(*cbk));
	if (rc != 0)
		D_ERROR("Failed to update engine bookmark on rank %u: "DF_RC"\n",
			dss_self_rank(), DP_RC(rc));

	return rc;
}

int
chk_bk_delete_engine(void)
{
	int	rc;

	rc = chk_db_delete(CHK_BK_ENGINE, strlen(CHK_BK_ENGINE));
	if (rc != 0)
		D_ERROR("Failed to delete engine bookmark on rank %u: "DF_RC"\n",
			dss_self_rank(), DP_RC(rc));

	return rc;
}

int
chk_bk_fetch_pool(struct chk_bookmark *cbk, uuid_t uuid)
{
	int	rc;

	rc = chk_db_fetch((char *)uuid, sizeof(uuid), cbk, sizeof(*cbk));
	if (rc != 0 && rc != -DER_ENOENT)
		D_ERROR("Failed to fetch pool "DF_UUID" bookmark on rank %u: "DF_RC"\n",
			DP_UUID(uuid), dss_self_rank(), DP_RC(rc));

	return rc;
}

int
chk_bk_update_pool(struct chk_bookmark *cbk, uuid_t uuid)
{
	int	rc;

	rc = chk_db_update((char *)uuid, sizeof(uuid), cbk, sizeof(*cbk));
	if (rc != 0)
		D_ERROR("Failed to update pool "DF_UUID" bookmark on rank %u: "DF_RC"\n",
			DP_UUID(uuid), dss_self_rank(), DP_RC(rc));

	return rc;
}

int
chk_bk_delete_pool(uuid_t uuid)
{
	int	rc;

	rc = chk_db_delete((char *)uuid, sizeof(uuid));
	if (rc != 0)
		D_ERROR("Failed to delete pool "DF_UUID" bookmark on rank %u: "DF_RC"\n",
			DP_UUID(uuid), dss_self_rank(), DP_RC(rc));

	return rc;
}

int
chk_prop_fetch(struct chk_property *cpp)
{
	int	rc;

	rc = chk_db_fetch(CHK_PROPERTY, strlen(CHK_PROPERTY), cpp, sizeof(*cpp));
	if (rc != 0 && rc != -DER_ENOENT)
		D_ERROR("Failed to fetch check property on rank %u: "DF_RC"\n",
			dss_self_rank(), DP_RC(rc));

	return rc;
}

int
chk_prop_update(struct chk_property *cpp)
{
	int	rc;

	rc = chk_db_update(CHK_PROPERTY, strlen(CHK_PROPERTY), cpp,
			   offsetof(struct chk_property, cp_ranks_bitmap) + cpp->cp_bitmap_sz);
	if (rc != 0)
		D_ERROR("Failed to update check property on rank %u: "DF_RC"\n",
			dss_self_rank(), DP_RC(rc));

	return rc;
}

int
chk_traverse_pools(sys_db_trav_cb_t cb, void *args)
{
	int	rc;

	rc = chk_db_traverse(cb, args);
	if (rc < 0)
		D_ERROR("Failed to traverse pools on rank %u for pause: "DF_RC"\n",
			dss_self_rank(), DP_RC(rc));

	return rc;
}

void
chk_vos_init(void)
{
	chk_db = vos_db_get();
}

void
chk_vos_fini(void)
{
	chk_db = NULL;
}
