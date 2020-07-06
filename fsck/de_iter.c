// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2020 Hyunchul Lee <hyc.lee@gmail.com>
 */
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "exfat_ondisk.h"
#include "libexfat.h"
#include "fsck.h"

static ssize_t write_block(struct exfat_de_iter *iter, unsigned int block)
{
	off_t device_offset;
	struct exfat *exfat = iter->exfat;
	struct buffer_desc *desc;
	unsigned int i;

	desc = &iter->buffer_desc[block & 0x01];
	device_offset = exfat_c2o(exfat, desc->p_clus) + desc->offset;

	for (i = 0; i < iter->read_size / iter->write_size; i++) {
		if (desc->dirty[i]) {
			if (exfat_write(exfat->blk_dev->dev_fd,
					desc->buffer + i * iter->write_size,
					iter->write_size,
					device_offset + i * iter->write_size)
					!= (ssize_t)iter->write_size)
				return -EIO;
			desc->dirty[i] = 0;
		}
	}
	return 0;
}

static ssize_t read_block(struct exfat_de_iter *iter, unsigned int block)
{
	struct exfat *exfat = iter->exfat;
	struct buffer_desc *desc, *prev_desc;
	off_t device_offset;
	int ret;

	desc = &iter->buffer_desc[block & 0x01];
	if (block == 0) {
		desc->p_clus = iter->parent->first_clus;
		desc->offset = 0;
	}

	/* if the buffer already contains dirty dentries, write it */
	if (write_block(iter, block))
		return -EIO;

	if (block > 0) {
		if (block > iter->parent->size / iter->read_size)
			return EOF;

		prev_desc = &iter->buffer_desc[(block-1) & 0x01];
		if (prev_desc->offset + 2 * iter->read_size <=
				exfat->clus_size) {
			desc->p_clus = prev_desc->p_clus;
			desc->offset = prev_desc->offset + iter->read_size;
		} else {
			ret = get_next_clus(exfat, iter->parent,
					prev_desc->p_clus, &desc->p_clus);
			desc->offset = 0;
			if (!ret && desc->p_clus == EXFAT_EOF_CLUSTER)
				return EOF;
			else if (ret)
				return ret;
		}
	}

	device_offset = exfat_c2o(exfat, desc->p_clus) + desc->offset;
	return exfat_read(exfat->blk_dev->dev_fd, desc->buffer,
			iter->read_size, device_offset);
}

int exfat_de_iter_init(struct exfat_de_iter *iter, struct exfat *exfat,
				struct exfat_inode *dir)
{
	iter->exfat = exfat;
	iter->parent = dir;
	iter->write_size = exfat->sect_size;
	iter->read_size = exfat->clus_size <= 4*KB ? exfat->clus_size : 4 * KB;

	if (!iter->buffer_desc)
		iter->buffer_desc = exfat->buffer_desc;

	if (read_block(iter, 0) != (ssize_t)iter->read_size) {
		exfat_err("failed to read directory entries.\n");
		return -EIO;
	}

	iter->de_file_offset = 0;
	iter->next_read_offset = iter->read_size;
	iter->max_skip_dentries = 0;
	return 0;
}

int exfat_de_iter_get(struct exfat_de_iter *iter,
			int ith, struct exfat_dentry **dentry)
{
	off_t next_de_file_offset;
	ssize_t ret;
	unsigned int block;

	next_de_file_offset = iter->de_file_offset +
			ith * sizeof(struct exfat_dentry);
	block = (unsigned int)(next_de_file_offset / iter->read_size);

	if (next_de_file_offset + sizeof(struct exfat_dentry) >
		iter->parent->size)
		return EOF;
	/* the dentry must be in current, or next block which will be read */
	if (block > iter->de_file_offset / iter->read_size + 1)
		return -ERANGE;

	/* read next cluster if needed */
	if (next_de_file_offset >= iter->next_read_offset) {
		ret = read_block(iter, block);
		if (ret != (ssize_t)iter->read_size)
			return ret;
		iter->next_read_offset += iter->read_size;
	}

	if (ith + 1 > iter->max_skip_dentries)
		iter->max_skip_dentries = ith + 1;

	*dentry = (struct exfat_dentry *)
			(iter->buffer_desc[block & 0x01].buffer +
			next_de_file_offset % iter->read_size);
	return 0;
}

int exfat_de_iter_get_dirty(struct exfat_de_iter *iter,
			int ith, struct exfat_dentry **dentry)
{
	off_t next_file_offset;
	unsigned int block;
	int ret, sect_idx;

	ret = exfat_de_iter_get(iter, ith, dentry);
	if (!ret) {
		next_file_offset = iter->de_file_offset +
				ith * sizeof(struct exfat_dentry);
		block = (unsigned int)(next_file_offset / iter->read_size);
		sect_idx = (int)((next_file_offset % iter->read_size) /
				iter->write_size);
		iter->buffer_desc[block & 0x01].dirty[sect_idx] = 1;
	}

	return ret;
}

int exfat_de_iter_flush(struct exfat_de_iter *iter)
{
	if (write_block(iter, 0) || write_block(iter, 1))
		return -EIO;
	return 0;
}

/*
 * @skip_dentries must be the largest @ith + 1 of exfat_de_iter_get
 * since the last call of exfat_de_iter_advance
 */
int exfat_de_iter_advance(struct exfat_de_iter *iter, int skip_dentries)
{
	if (skip_dentries != iter->max_skip_dentries)
		return -EINVAL;

	iter->max_skip_dentries = 0;
	iter->de_file_offset = iter->de_file_offset +
				skip_dentries * sizeof(struct exfat_dentry);
	return 0;
}

off_t exfat_de_iter_file_offset(struct exfat_de_iter *iter)
{
	return iter->de_file_offset;
}
