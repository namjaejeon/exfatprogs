/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *  Copyright (C) 2020 Hyunchul Lee <hyc.lee@gmail.com>
 */
#ifndef _REPAIR_H
#define _REPAIR_H

#define ER_BS_CHECKSUM			0x00000001
#define ER_BS_BOOT_REGION		0x00000002
#define ER_DE_CHECKSUM			0x00001001
#define ER_DE_UNKNOWN			0x00001002
#define ER_DE_FILE			0x00001010
#define ER_DE_SECONDARY_COUNT		0x00001011
#define ER_DE_STREAM			0x00001020
#define ER_DE_NAME			0x00001030
#define ER_DE_NAME_HASH			0x00001031
#define ER_DE_NAME_LEN			0x00001032
#define ER_FILE_VALID_SIZE		0x00002001
#define ER_FILE_INVALID_CLUS		0x00002002
#define ER_FILE_FIRST_CLUS		0x00002003
#define ER_FILE_SMALLER_SIZE		0x00002004
#define ER_FILE_LARGER_SIZE		0x00002005
#define ER_FILE_DUPLICATED_CLUS		0x00002006
#define ER_FILE_ZERO_NOFAT		0x00002007

typedef unsigned int er_problem_code_t;
struct exfat_fsck;

bool exfat_repair_ask(struct exfat_fsck *fsck, er_problem_code_t prcode,
		      const char *fmt, ...);

#endif
