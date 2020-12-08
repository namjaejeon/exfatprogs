// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2020 Namjae Jeon <linkinjeon@kernel.org>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <locale.h>

#include "exfat_ondisk.h"
#include "libexfat.h"

static void usage(void)
{
	fprintf(stderr, "Usage: exfatlabel\n");
	fprintf(stderr, "\t-V | --version                        Show version\n");
	fprintf(stderr, "\t-h | --help                           Show help\n");

	exit(EXIT_FAILURE);
}

static struct option opts[] = {
	{"version",		no_argument,		NULL,	'V' },
	{"help",		no_argument,		NULL,	'h' },
	{"?",			no_argument,		NULL,	'?' },
	{NULL,			0,			NULL,	 0  }
};

int main(int argc, char *argv[])
{
	int c;
	int ret = EXIT_FAILURE;
	struct exfat_blk_dev bd;
	struct exfat_user_input ui;
	bool version_only = false;
	off_t root_clu_off;

	init_user_input(&ui);

	if (!setlocale(LC_CTYPE, ""))
		exfat_err("failed to init locale/codeset\n");

	opterr = 0;
	while ((c = getopt_long(argc, argv, "Vh", opts, NULL)) != EOF)
		switch (c) {
		case 'V':
			version_only = true;
			break;
		case '?':
		case 'h':
		default:
			usage();
	}

	show_version();
	if (version_only)
		exit(EXIT_FAILURE);

	if (argc < 2)
		usage();

	memset(ui.dev_name, 0, sizeof(ui.dev_name));
	snprintf(ui.dev_name, sizeof(ui.dev_name), "%s", argv[1]);

	ret = exfat_get_blk_dev_info(&ui, &bd);
	if (ret < 0)
		goto out;

	root_clu_off = exfat_get_root_entry_offset(&bd);
	if (root_clu_off < 0)
		goto out;

	if (argc == 2)
		ret = exfat_get_volume_label(&bd, root_clu_off);
	else
		ret = exfat_set_volume_label(&bd, argv[2], root_clu_off);

out:
	return ret;
}
