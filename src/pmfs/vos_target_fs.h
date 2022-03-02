/**
 * (C) Copyright 2016-2021 Intel Corporation.
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */
/**
 * This file is part of vos
 *
 * vos/vos_target_fs.h
 */
 #ifndef __VOS_TARGET_FS_H__
 #define __VOS_TARGET_FS_H__
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <inttypes.h>
 #include <daos_srv/vos.h>
 #include "vos_target_engine.h"

struct ring_list {
	const char *ring_name;
	struct spdk_ring *task_ring;
	d_list_t rl;
};

struct vos_fs_cmd_args {
	daos_handle_t oh;	/* opened object */
	daos_obj_id_t oid;	/* object ID */
	daos_unit_oid_t uoid;	/* object shard IDs (for VOS) */
	daos_epoch_t epoch;
	pthread_t pid;
	pthread_mutex_t g_pro_lock;
	double *duration;
	bool force_exit;
	const char *vfcmd;
	struct ring_list *task_ring_list;
	struct vos_client_task *vct;
	struct pmfs_context *pmfs_ctx;
	int status;
};

struct spdk_ring *vos_task_get_ring(const char *name, void *arg);
void vos_task_bind_ring(const char *name, struct spdk_ring *ring,
			struct ring_list *ring_list);
void vos_task_process_init(void *arg);
void vos_task_process(void *arg);
void vos_task_process_fini(void *arg);
 #endif
