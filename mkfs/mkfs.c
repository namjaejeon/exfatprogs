// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2019 Namjae Jeon <linkinjeon@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>

#include "exfat.h"

static void usage(void)
{       
	fprintf(stderr, "exfat-tools version : %s\n", EXFAT_TOOLS_VERSION);
	fprintf(stderr, "Usage: mkfs.exfat\n");

	fprintf(stderr, "\t-v | --verbose\n");

	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	int c;
        int ret = EXIT_FAILURE;

        opterr = 0;
        while ((c = getopt(argc, argv, "c:i:a:d:u:p:vh")) != EOF)
                switch (c) {
                case 'v':
                        break;
                case '?':
                case 'h':
                default:
                        usage();
        }

	return 0;
}
