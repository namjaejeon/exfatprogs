/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *  Copyright (C) 2022 Hyunchul Lee <hyc.lee@gmail.com>
 */

#ifndef _DIR_H_
#define _DIR_H_

struct exfat;
struct exfat_inode;
struct buffer_desc;

struct exfat_de_iter {
	struct exfat		*exfat;
	struct exfat_inode	*parent;
	struct buffer_desc	*buffer_desc;		/* cluster * 2 */
	__u32			ra_next_clus;
	unsigned int		ra_begin_offset;
	unsigned int		ra_partial_size;
	unsigned int		read_size;		/* cluster size */
	unsigned int		write_size;		/* sector size */
	off_t			de_file_offset;
	off_t			next_read_offset;
	int			max_skip_dentries;
};

int exfat_de_iter_init(struct exfat_de_iter *iter, struct exfat *exfat,
		       struct exfat_inode *dir, struct buffer_desc *bd);
int exfat_de_iter_get(struct exfat_de_iter *iter,
		      int ith, struct exfat_dentry **dentry);
int exfat_de_iter_get_dirty(struct exfat_de_iter *iter,
			    int ith, struct exfat_dentry **dentry);
int exfat_de_iter_flush(struct exfat_de_iter *iter);
int exfat_de_iter_advance(struct exfat_de_iter *iter, int skip_dentries);

#endif
