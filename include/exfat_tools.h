/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *  Copyright (C) 2019 Namjae Jeon <linkinjeon@gmail.com>
 */

#ifndef _EXFAT_TOOLS_H

#include <stdbool.h>
#include <wchar.h>

#define EXFAT_MIN_NUM_SEC_VOL		(2048)
#define EXFAT_MAX_NUM_SEC_VOL		((2 << 64) - 1)

#define EXFAT_MAX_NUM_CLUSTER		(0xFFFFFFF5)

#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)

/* Upcase tabel macro */
#define EXFAT_UPCASE_TABLE_SIZE		(5836)

enum {
	BOOT_SEC_IDX = 0,
	EXBOOT_SEC_IDX,
	EXBOOT_SEC_NUM = 8,
	OEM_SEC_IDX,
	RESERVED_SEC_IDX,
	CHECKSUM_SEC_IDX,
	BACKUP_BOOT_SEC_IDX,
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
	bool quick;
	char volume_label[22];
};

void exfat_set_bit(struct exfat_blk_dev *bd, char *bitmap,
		unsigned int clu);
void exfat_clear_bit(struct exfat_blk_dev *bd, char *bitmap,
		unsigned int clu);
wchar_t exfat_bad_char(wchar_t w);
void boot_calc_checksum(unsigned char *sector, unsigned short size,
		bool is_boot_sec, unsigned int *checksum);

/*
 * Exfat Print
 */

static unsigned int print_level;

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
