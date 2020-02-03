/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *  Copyright (C) 2020 Hyunchul Lee <hyc.lee@gmail.com>
 */
#ifndef _FSCK_H
#define _FSCK_H

#include "exfat_iconv.h"
#include "list.h"

typedef __u32 clus_t;

struct exfat_inode {
	struct exfat_inode	*parent;
	struct list_head	children;
	struct list_head	sibling;
	struct list_head	list;
	clus_t			first_clus;
	__u16			attr;
	__u64			size;
	bool			is_contiguous;
	off_t			dentry_file_offset;
	__le16			name[0];	/* only for directory */
};

#define EXFAT_NAME_MAX			255
#define VOLUME_LABEL_BUFFER_SIZE	(EXFAT_DECSTR_MAX_BUFSIZE(	\
						VOLUME_LABEL_MAX_LEN))
#define NAME_BUFFER_SIZE		(EXFAT_ENCSTR_MAX_BUFSIZE(	\
						EXFAT_NAME_MAX))

struct exfat_de_iter {
	struct exfat		*exfat;
	struct exfat_inode	*parent;
	unsigned char		*dentries;	/* cluster * 2 allocated */
	unsigned int		read_size;	/* cluster size */
	off_t			de_file_offset;	/* offset in dentries buffer */
	off_t			next_read_offset;
	int			max_skip_dentries;
};

struct exfat {
	struct exfat_blk_dev	*blk_dev;
	struct pbr		*bs;
	char			volume_label[VOLUME_LABEL_BUFFER_SIZE];
	struct exfat_inode	*root;
	struct list_head	dir_list;
	struct exfat_de_iter	de_iter;
	__u32			*alloc_bitmap;
	__u64			bit_count;
};

#define EXFAT_CLUSTER_SIZE(pbr) (1 << ((pbr)->bsx.sect_size_bits +	\
					(pbr)->bsx.sect_per_clus_bits))
#define EXFAT_SECTOR_SIZE(pbr) (1 << (pbr)->bsx.sect_size_bits)

#endif
