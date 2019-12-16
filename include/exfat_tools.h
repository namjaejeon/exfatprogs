/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *  Copyright (C) 2019 Namjae Jeon <linkinjeon@gmail.com>
 */

#ifndef _EXFAT_TOOLS_H

#define EXFAT_MIN_NUM_SEC_VOL		(2048)
#define EXFAT_MAX_NUM_SEC_VOL		((2 << 64) - 1)

#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)

/* Upcase tabel macro */
#define EXFAT_UPCASE_TABLE_SIZE		(5836)

enum {
	BOOT_SEC_NUM = 0,
	EXBOOT_SEC_NUM,
	EXBOOT_SEC8_NUM = 8,
	OEM_SEC_NUM,
	RESERVED_SEC_NUM,
	CHECKSUM_NUM,
};

struct exfat_blk_dev {
	int dev_fd;
	unsigned long long size;
	unsigned int sector_size;
	unsigned int sector_size_bits;
	unsigned int num_sectors;
	unsigned int num_clusters;
};

struct exfat_user_input {
	char dev_name[255];
	unsigned int cluster_size;
	unsigned int sec_per_clu;
};

void exfat_set_bit(struct exfat_blk_dev *bd, char *bitmap,
		unsigned int clu);

void exfat_clear_bit(struct exfat_blk_dev *bd, char *bitmap,
		unsigned int clu);

/*
 * Exfat Print
 */

unsigned int print_level;

#define EXFAT_ERROR	(0)
#define EXFAT_DEBUG	(1)

#define exfat_msg(level, fmt, ...)					\
	do {								\
		if (print_level >= level) {				\
			printf("[%s:%4d] " fmt,				\
				__func__, __LINE__, ##__VA_ARGS__);	\
		}							\
	} while (0)							\

#endif /* !_EXFA_TOOLS_H */
