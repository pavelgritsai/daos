/**
 * (C) Copyright 2022 Intel Corporation.
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */

#ifndef VOS_TASKS_H
#define VOS_TASKS_H

#include <gurt/types.h>
#include <daos/object.h>
#include <daos_types.h>
#include <daos_obj.h>

#include <spdk/env.h>

typedef int (*task_comp_cb_t)(void *cb_args, int rc);

enum task_op {
	VOS_OBJ_UPDATE = 1,
	VOS_OBJ_FETCH,
	VOS_OBJ_PUNCH,
	VOS_OBJ_GET_NUM_DKEYS,
	VOS_OBJ_LIST_DKEYS,
};

struct vos_client_obj_list_args {
	daos_handle_t coh;
	daos_unit_oid_t oid;
	/* number of KEYs */
	uint32_t *nr;
	/* total buffer length of KEYs */
	uint64_t *len;
	/* Key descriptor used for key enumeration */
	daos_key_desc_t	*kds;
	/* data buffer to store KEYs */
	void *buf;
};

struct vos_client_obj_rw_args {
	daos_handle_t coh;
	daos_unit_oid_t oid;
	daos_epoch_t epoch;
	uint32_t pm_ver;
	uint64_t flags;
	daos_key_t *dkey;
	unsigned int akey_nr;
	daos_key_t *akeys;
	unsigned int iod_nr;
	daos_iod_t *iods;
	d_sg_list_t *sgls;
	struct dtx_handle *dth;
};

struct vos_client_task {
	void *cb_args;
	task_comp_cb_t cb_fn;

	int rc;
	sem_t sem;

	enum task_op opc;

	union {
		struct vos_client_obj_rw_args	obj_rw;
		struct vos_client_obj_list_args	obj_list;
	} args;
};

struct spdk_ring *vos_target_create_tasks(const char *name, size_t count);
void vos_target_free_tasks(struct spdk_ring *tasks);

#endif
