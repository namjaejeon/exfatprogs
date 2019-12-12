/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *  Copyright (C) 2019 Namjae Jeon <linkinjeon@gmail.com>
 */

#ifndef _MKFS_H

#define DEFAULT_CLUSTER_SIZE	(1024 * 1024)
#define DEFAULT_SECTOR_SIZE	(512)
#define MIN_NUM_SECTOR		(2048)
#define MAX_CLUSTER_SIZE	(32*1024*1024)

struct exfat_mkfs_info {
	int total_clu_cnt;
	int used_clu_cnt;
	int fat_byte_off;
	int fat_byte_len;
	int clu_byte_off;
	int bitmap_byte_off;
	int bitmap_byte_len;
	int ut_byte_off;
	int ut_start_clu;
	int ut_clus_off;
	int ut_byte_len;
	int root_byte_off;
	int root_byte_len;
	int root_start_clu;
};

struct exfat_mkfs_info finfo;

int exfat_create_upcase_table(struct exfat_blk_dev *bd,
		struct exfat_user_input *ui);

#endif /* !_MKFS_H */
