#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "exfat_ondisk.h"
#include "libexfat.h"
#include "fsck.h"

static ssize_t exfat_file_read(struct exfat *exfat, struct exfat_inode *node,
			void *buf, size_t total_size, off_t file_offset)
{
	size_t clus_size;
	clus_t start_l_clus, l_clus, p_clus;
	unsigned int clus_offset;
	int ret;
	off_t device_offset;
	ssize_t read_size;
	size_t remain_size;

	if (file_offset >= (off_t)node->size)
		return EOF;

	clus_size = EXFAT_CLUSTER_SIZE(exfat->bs);
	total_size = MIN(total_size, node->size - file_offset);
	remain_size = total_size;

	if (remain_size == 0)
		return 0;

	start_l_clus = file_offset / clus_size;
	clus_offset = file_offset % clus_size;
	if (start_l_clus >= node->last_lclus &&
			node->last_pclus != EXFAT_EOF_CLUSTER) {
		l_clus = node->last_lclus;
		p_clus = node->last_pclus;
	} else {
		l_clus = 0;
		p_clus = node->first_clus;
	}

	while (p_clus != EXFAT_EOF_CLUSTER) {
		if (exfat_invalid_clus(exfat, p_clus))
			return -EINVAL;
		if (l_clus < start_l_clus)
			goto next_clus;

		read_size = MIN(remain_size, clus_size - clus_offset);
		device_offset = exfat_c2o(exfat, p_clus) + clus_offset;
		if (exfat_read(exfat->blk_dev->dev_fd, buf, read_size,
					device_offset) != read_size)
			return -EIO;

		clus_offset = 0;
		buf = (char *)buf + read_size;
		remain_size -= read_size;
		if (remain_size == 0)
			goto out;

next_clus:
		l_clus++;
		ret = inode_get_clus_next(exfat, node, p_clus, &p_clus);
		if (ret)
			return ret;
	}
out:
	node->last_lclus = l_clus;
	node->last_pclus = p_clus;
	return total_size - remain_size;
}

int exfat_de_iter_init(struct exfat_de_iter *iter, struct exfat *exfat,
						struct exfat_inode *dir)
{
	ssize_t ret;

	if (!iter->dentries) {
		iter->read_size = EXFAT_CLUSTER_SIZE(exfat->bs);
		iter->dentries = malloc(iter->read_size * 2);
		if (!iter->dentries) {
			exfat_err("failed to allocate memory\n");
			return -ENOMEM;
		}
	}

	ret = exfat_file_read(exfat, dir, iter->dentries, iter->read_size, 0);
	if (ret != iter->read_size) {
		exfat_err("failed to read directory entries.\n");
		return -EIO;
	}

	iter->exfat = exfat;
	iter->parent = dir;
	iter->de_file_offset = 0;
	iter->next_read_offset = iter->read_size;
	iter->max_skip_dentries = 0;
	return 0;
}

int exfat_de_iter_get(struct exfat_de_iter *iter,
				int ith, struct exfat_dentry **dentry)
{
	off_t de_next_file_offset;
	unsigned int de_next_offset;
	bool need_read_1_clus = false;
	int ret;

	de_next_file_offset = iter->de_file_offset +
			ith * sizeof(struct exfat_dentry);

	if (de_next_file_offset + sizeof(struct exfat_dentry) >
		round_down(iter->parent->size, sizeof(struct exfat_dentry)))
		return EOF;

	/*
	 * dentry must be in current cluster, or next cluster which
	 * will be read
	 */
	if (de_next_file_offset -
		(iter->de_file_offset / iter->read_size) * iter->read_size >=
		iter->read_size * 2)
		return -ERANGE;

	de_next_offset = de_next_file_offset % (iter->read_size * 2);

	/* read a cluster if needed */
	if (de_next_file_offset >= iter->next_read_offset) {
		void *buf;

		need_read_1_clus = de_next_offset < iter->read_size;
		buf = need_read_1_clus ?
			iter->dentries : iter->dentries + iter->read_size;

		ret = exfat_file_read(iter->exfat, iter->parent, buf,
			iter->read_size, iter->next_read_offset);
		if (ret == EOF) {
			return EOF;
		} else if (ret <= 0) {
			exfat_err("failed to read a cluster. %d\n", ret);
			return ret;
		}
		iter->next_read_offset += iter->read_size;
	}

	if (ith + 1 > iter->max_skip_dentries)
		iter->max_skip_dentries = ith + 1;

	*dentry = (struct exfat_dentry *) (iter->dentries + de_next_offset);
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
