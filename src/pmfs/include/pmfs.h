/**
 * (C) Copyright 2022 Intel Corporation.
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */

#ifndef __PMFS_H__
#define __PMFS_H__

#include <dirent.h>
#include <daos_types.h>


/** Maximum Name length */
#define PMFS_MAX_NAME		NAME_MAX
/** Maximum PATH length */
#define PMFS_MAX_PATH		PATH_MAX

#define PMFS_BALANCED	4 /** PMFS operations using a DTX */
#define PMFS_RELAXED	0 /** PMFS operations do not use a DTX (default mode). */
#define PMFS_RDONLY	O_RDONLY
#define PMFS_RDWR	O_RDWR

/** Maximum tasks */
#define PMFS_MAX_TASKS	128

/** D-key name of SB metadata */
#define SB_DKEY		"PMFS_SB_METADATA"

#define SB_AKEYS	6
/** A-key name of SB magic */
#define MAGIC_NAME	"PMFS_MAGIC"
/** A-key name of SB version */
#define SB_VERSION_NAME	"PMFS_SB_VERSION"
/** A-key name of DFS Layout Version */
#define LAYOUT_NAME	"PMFS_LAYOUT_VERSION"
/** A-key name of Default chunk size */
#define CS_NAME		"PMFS_CHUNK_SIZE"
/** Consistency mode of the DFS container. */
#define MODE_NAME	"PMFS_MODE"
/** Allocated maximum OID value */
#define OID_VALUE	"PMFS_OID_VALUE"

/** Magic Value */
#define PMFS_SB_MAGIC	0xda05df50da05df50
/** PMFS SB version value */
#define PMFS_SB_VERSION	2
/** PMFS Layout Version Value */
#define PMFS_LAYOUT_VERSION	2
/** Array object stripe size for regular files */
#define PMFS_DEFAULT_CHUNK_SIZE	1048576

/** Number of A-keys for attributes in any object entry */
#define INODE_AKEYS	8
#define INODE_AKEY_NAME	"PMFS_INODE"
#define MODE_IDX	0
#define OID_IDX		(sizeof(mode_t))
#define ATIME_IDX	(OID_IDX + sizeof(daos_obj_id_t))
#define MTIME_IDX	(ATIME_IDX + sizeof(time_t))
#define CTIME_IDX	(MTIME_IDX + sizeof(time_t))
#define CSIZE_IDX	(CTIME_IDX + sizeof(time_t))
#define FSIZE_IDX	(CSIZE_IDX + sizeof(daos_size_t))
#define SYML_IDX	(FSIZE_IDX + sizeof(daos_size_t))

/** OIDs for Superblock and Root objects */
#define RESERVED_LO	0
#define SB_HI		0
#define ROOT_HI		1

/** Max recursion depth for symlinks */
#define PMFS_MAX_RECURSION	40

/** struct holding attributes for a PMFS container */
struct  pmfs_attr {
	/** Optional user ID for DFS container. */
	uint64_t da_id;
	/** Default Chunk size for all files in container */
	daos_size_t da_chunk_size;
	/** Default Object Class for all objects in the container */
	uint32_t da_oclass_id;
	/*
	 * Consistency mode for the PMFS container: PMFS_RELAXED, PMFS_BALANCED.
	 * If set to 0 or more generally not set to balanced explicitly, relaxed
	 * mode will be used. In the future, Balanced mode will be the default.
	 */
	uint32_t da_mode;
};

/** object struct that is instantiated for a PMFS open object */
struct pmfs_obj {
	/* Reference number */
	int			ref;
	/** DAOS object ID */
	daos_obj_id_t		oid;
	/** mode_t containing permissions & type */
	mode_t			mode;
	/** open access flags */
	int			flags;
	/** DAOS object ID of the parent of the object */
	daos_obj_id_t		parent_oid;
	/** entry name of the object in the parent */
	char			name[PMFS_MAX_NAME + 1];
	/** File size */
	daos_size_t		file_size;
	/** Symlink value if object is a symbolic link */
	char			*value;
	/** Default chunk size for all entries in dir */
	daos_size_t		chunk_size;
};

/** pmfs struct that is instantiated for a mounted PMFS namespace */
struct pmfs {
	/** flag to indicate whether the dfs is mounted */
	bool			mounted;
	/** flag to indicate whether pmfs is mounted with balanced mode (DTX) */
	bool			use_dtx;
	/** lock for threadsafety */
	pthread_mutex_t		lock;
	/** uid - inherited from container. */
	uid_t			uid;
	/** gid - inherited from container. */
	gid_t			gid;
	/** Access mode (RDONLY, RDWR) */
	int			amode;
	/** Open pool handle of the DFS */
	daos_handle_t		poh;
	/** Open container handle of the DFS */
	daos_handle_t		coh;
	/** Object ID reserved for this DFS (see oid_gen below) */
	daos_obj_id_t		oid;
	/** superblock object OID */
	daos_obj_id_t		super_oid;
	/** Root object info */
	struct pmfs_obj		root;
	/** PMFS container attributes (Default chunk size, etc.) */
	struct pmfs_attr	attr;
	/** Task ring list */
	struct spdk_ring	*task_ring;
};

struct pmfs_entry {
	/** mode (permissions + entry type) */
	mode_t			mode;
	/* Length of value string, not including NULL byte */
	uint16_t		value_len;
	/** Object ID if not a symbolic link */
	daos_obj_id_t		oid;
	/* Time of last access */
	time_t			atime;
	/* Time of last modification */
	time_t			mtime;
	/* Time of last status change */
	time_t			ctime;
	/** chunk size of file or default for all files in a dir */
	daos_size_t		chunk_size;
	/** size of regular file */
	daos_size_t		file_size;
	/** Sym Link value */
	char			*value;
};

int pmfs_mkfs(daos_handle_t poh, uuid_t uuid);
int pmfs_mount(daos_handle_t poh, daos_handle_t coh, int flags, struct pmfs **pmfs);
int pmfs_umount(struct pmfs *pmfs);
int pmfs_mkdir(struct pmfs *pmfs, struct pmfs_obj *parent, const char *name,
	       mode_t mode);
int pmfs_listdir(struct pmfs *pmfs, struct pmfs_obj *obj, uint32_t *nr);
int pmfs_remove(struct pmfs *pmfs, struct pmfs_obj *parent, const char *name, bool force,
		daos_obj_id_t *oid);
int pmfs_open(struct pmfs *pmfs, struct pmfs_obj *parent, const char *name, mode_t mode,
	      int flags, daos_size_t chunk_size, const char *value,
	      struct pmfs_obj **_obj);
int pmfs_readdir(struct pmfs *pmfs, struct pmfs_obj *obj, uint32_t *nr, struct dirent *dirs);
int pmfs_release(struct pmfs_obj *obj);
int pmfs_lookup(struct pmfs *pmfs, const char *path, int flags, struct pmfs_obj **_obj,
		mode_t *mode, struct stat *stbuf);
int pmfs_punch(struct pmfs *pmfs, struct pmfs_obj *obj, daos_off_t offset, daos_size_t len);
int pmfs_write_sync(struct pmfs *pmfs, struct pmfs_obj *obj, d_sg_list_t *usr_sgl, daos_off_t off);
int pmfs_read_sync(struct pmfs *pmfs, struct pmfs_obj *obj, d_sg_list_t *usr_sgl, daos_off_t off,
		   daos_size_t *read_size);
int pmfs_stat(struct pmfs *pmfs, struct pmfs_obj *parent, const char *name, struct stat *stbuf);
int pmfs_truncate(struct pmfs *pmfs, struct pmfs_obj *obj, daos_size_t len);
int pmfs_rename(struct pmfs *pmfs, struct pmfs_obj *parent, const char *old_name,
		const char *new_name);
int pmfs_obj_get_file_size(struct pmfs *pmfs, struct pmfs_obj *obj, daos_size_t *fsize);
#endif /* __PMFS_H__ */
