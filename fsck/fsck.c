// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2019 Namjae Jeon <linkinjeon@gmail.com>
 *   Copyright (C) 2020 Hyunchul Lee <hyc.lee@gmail.com>
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>

#include "exfat_ondisk.h"
#include "exfat_tools.h"

enum fsck_ui_options {
	FSCK_OPTS_REPAIR	= 0x01,
};

struct fsck_user_input {
	struct exfat_user_input		ei;
	enum fsck_ui_options		options;
};

static struct option opts[] = {
	{"version",	no_argument,	NULL,	'V' },
	{"verbose",	no_argument,	NULL,	'v' },
	{"help",	no_argument,	NULL,	'h' },
	{"?",		no_argument,	NULL,	'?' },
	{NULL,		0,		NULL,	 0  }
};

static void usage(char *name)
{
	fprintf(stderr, "Usage: %s\n", name);
	fprintf(stderr, "\t-r | --repair	Repair\n");
	fprintf(stderr, "\t-V | --version	Show version\n");
	fprintf(stderr, "\t-v | --verbose	Print debug\n");
	fprintf(stderr, "\t-h | --help		Show help\n");

	exit(EXIT_FAILURE);
}

int main(int argc, char * const argv[])
{
	int c, ret;
	struct fsck_user_input ui = {0,};
	struct exfat_blk_dev bd = {0,};

	opterr = 0;
	while ((c = getopt_long(argc, argv, "Vvh", opts, NULL)) != EOF) {
		switch (c) {
		case 'r':
			ui.options |= FSCK_OPTS_REPAIR;
			ui.ei.writeable = true;
			break;
		case 'V':
			show_version();
			break;
		case 'v':
			if (print_level < EXFAT_DEBUG)
				print_level++;
			break;
		case '?':
		case 'h':
		default:
			usage(argv[0]);
		}
	}

	if (optind != argc - 1)
		usage(argv[0]);

	printf("fsck.ext4 %s\n", EXFAT_TOOLS_VERSION);

	strncpy(ui.ei.dev_name, argv[optind], sizeof(ui.ei.dev_name));
	ret = exfat_get_blk_dev_info(&ui.ei, &bd);
	if (ret < 0) {
		exfat_err("failed to open %s. %d\n", ui.ei.dev_name, ret);
		return ret;
	}

	close(bd.dev_fd);
	return ret;
}
