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

struct exfat_lookup_filter {
	struct {
		uint8_t		type;
		/* return 0 if matched, return 1 if not matched,
		 * otherwise return errno
		 */
		int		(*filter)(struct exfat_de_iter *iter,
					  void *param, int *dentry_count);
		void		*param;
	} in;
	struct {
		struct exfat_dentry	*dentry_set;
		int			dentry_count;
		off_t			file_offset;
		/* device offset where the dentry_set locates, or
		 * the empty slot locates or EOF if not found.
		 */
		off_t			dev_offset;
	} out;
};

int exfat_de_iter_init(struct exfat_de_iter *iter, struct exfat *exfat,
		       struct exfat_inode *dir, struct buffer_desc *bd);
int exfat_de_iter_get(struct exfat_de_iter *iter,
		      int ith, struct exfat_dentry **dentry);
int exfat_de_iter_get_dirty(struct exfat_de_iter *iter,
			    int ith, struct exfat_dentry **dentry);
int exfat_de_iter_flush(struct exfat_de_iter *iter);
int exfat_de_iter_advance(struct exfat_de_iter *iter, int skip_dentries);
off_t exfat_de_iter_device_offset(struct exfat_de_iter *iter);
off_t exfat_de_iter_file_offset(struct exfat_de_iter *iter);

int exfat_lookup_dentry_set(struct exfat *exfat, struct exfat_inode *parent,
			    struct exfat_lookup_filter *filter);
int exfat_lookup_file(struct exfat *exfat, struct exfat_inode *parent,
		      const char *name, struct exfat_lookup_filter *filter_out);
int exfat_create_file(struct exfat *exfat, struct exfat_inode *parent,
		      const char *name, unsigned short attr);

#endif
