/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *  Copyright (C) 2020 Hyunchul Lee <hyc.lee@gmail.com>
 */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "exfat_ondisk.h"
#include "libexfat.h"
#include "repair.h"
#include "exfat_fs.h"
#include "exfat_dir.h"
#include "fsck.h"

struct exfat_repair_problem {
	er_problem_code_t	prcode;
	unsigned int		flags;
	unsigned int		prompt_type;
};

/* Problem flags */
#define ERF_PREEN_YES		0x00000001
#define ERF_DEFAULT_YES		0x00000002
#define ERF_DEFAULT_NO		0x00000004

/* Prompt types */
#define ERP_FIX			0x00000001
#define ERP_TRUNCATE		0x00000002
#define ERP_DELETE		0x00000003

static const char *prompts[] = {
	"Repair",
	"Fix",
	"Truncate",
	"Delete",
};

static struct exfat_repair_problem problems[] = {
	{ER_BS_CHECKSUM, ERF_PREEN_YES, ERP_FIX},
	{ER_BS_BOOT_REGION, 0, ERP_FIX},
	{ER_DE_CHECKSUM, ERF_PREEN_YES, ERP_DELETE},
	{ER_DE_UNKNOWN, ERF_PREEN_YES, ERP_DELETE},
	{ER_DE_FILE, ERF_PREEN_YES, ERP_DELETE},
	{ER_DE_SECONDARY_COUNT, ERF_PREEN_YES, ERP_DELETE},
	{ER_DE_STREAM, ERF_PREEN_YES, ERP_DELETE},
	{ER_DE_NAME, ERF_PREEN_YES, ERP_DELETE},
	{ER_DE_NAME_HASH, ERF_PREEN_YES, ERP_FIX},
	{ER_DE_NAME_LEN, ERF_PREEN_YES, ERP_FIX},
	{ER_FILE_VALID_SIZE, ERF_PREEN_YES, ERP_FIX},
	{ER_FILE_INVALID_CLUS, ERF_PREEN_YES, ERP_TRUNCATE},
	{ER_FILE_FIRST_CLUS, ERF_PREEN_YES, ERP_TRUNCATE},
	{ER_FILE_SMALLER_SIZE, ERF_PREEN_YES, ERP_TRUNCATE},
	{ER_FILE_LARGER_SIZE, ERF_PREEN_YES, ERP_TRUNCATE},
	{ER_FILE_DUPLICATED_CLUS, ERF_PREEN_YES, ERP_TRUNCATE},
	{ER_FILE_ZERO_NOFAT, ERF_PREEN_YES, ERP_FIX},
};

static struct exfat_repair_problem *find_problem(er_problem_code_t prcode)
{
	unsigned int i;

	for (i = 0; i < sizeof(problems)/sizeof(problems[0]); i++) {
		if (problems[i].prcode == prcode) {
			return &problems[i];
		}
	}
	return NULL;
}

static bool ask_repair(struct exfat_fsck *fsck, struct exfat_repair_problem *pr)
{
	bool repair = false;
	char answer[8];

	if (fsck->options & FSCK_OPTS_REPAIR_NO ||
	    pr->flags & ERF_DEFAULT_NO)
		repair = false;
	else if (fsck->options & FSCK_OPTS_REPAIR_YES ||
		 pr->flags & ERF_DEFAULT_YES)
		repair = true;
	else {
		if (fsck->options & FSCK_OPTS_REPAIR_ASK) {
			do {
				printf(". %s (y/N)? ",
					prompts[pr->prompt_type]);
				fflush(stdout);

				if (fgets(answer, sizeof(answer), stdin)) {
					if (strcasecmp(answer, "Y\n") == 0)
						return true;
					else if (strcasecmp(answer, "\n") == 0
						|| strcasecmp(answer, "N\n") == 0)
						return false;
				}
			} while (1);
		} else if (fsck->options & FSCK_OPTS_REPAIR_AUTO &&
			   pr->flags & ERF_PREEN_YES)
			repair = true;
	}

	printf(". %s (y/N)? %c\n", prompts[pr->prompt_type],
		repair ? 'y' : 'n');
	return repair;
}

bool exfat_repair_ask(struct exfat_fsck *fsck, er_problem_code_t prcode,
		      const char *desc, ...)
{
	struct exfat_repair_problem *pr = NULL;
	va_list ap;

	pr = find_problem(prcode);
	if (!pr) {
		exfat_err("unknown problem code. %#x\n", prcode);
		return false;
	}

	va_start(ap, desc);
	vprintf(desc, ap);
	va_end(ap);

	if (ask_repair(fsck, pr)) {
		if (pr->prompt_type & ERP_TRUNCATE)
			fsck->dirty_fat = true;
		fsck->dirty = true;
		return true;
	} else {
		return false;
	}
}
