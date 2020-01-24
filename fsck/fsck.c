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
#include <errno.h>

#include "exfat_ondisk.h"
#include "exfat_tools.h"
#include "list.h"

enum fsck_ui_options {
	FSCK_OPTS_REPAIR	= 0x01,
};

struct fsck_user_input {
	struct exfat_user_input		ei;
	enum fsck_ui_options		options;
};

typedef __u32 clus_t;

enum exfat_file_attr {
	EXFAT_FA_NONE		= 0x00,
	EXFAT_FA_DIR		= 0x01,
};

struct exfat_node {
	struct exfat_node	*parent;
	struct list_head	children;
	struct list_head	sibling;
	struct list_head	list;
	clus_t			first_clus;
	__u16			attr;
	__u64			size;
	bool			is_contiguous;
	off_t			dentry_file_offset;
	__le16			name[0];	/* only for directory */
};

#define EXFAT_NAME_MAX		255
#define UTF16_NAME_BUFFER_SIZE	((EXFAT_NAME_MAX + 1) * sizeof(__le16))
#define UTF8_NAME_BUFFER_SIZE	(EXFAT_NAME_MAX * 3 + 1)

struct exfat {
	struct exfat_blk_dev	*blk_dev;
	struct pbr		*bs;
	char			volume_label[VOLUME_LABEL_MAX_LEN*3+1];
	struct exfat_node	*root;
	struct list_head	dir_list;
	__u32			*alloc_bitmap;
	__u64			bit_count;
};

struct exfat_stat {
	long		dir_count;
	long		file_count;
	long		dir_free_count;
	long		file_free_count;
};

struct exfat_stat exfat_stat;

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

static struct exfat_node *alloc_exfat_node(__u16 attr)
{
	struct exfat_node *node;
	int size;

	size = offsetof(struct exfat_node, name) + UTF16_NAME_BUFFER_SIZE;
	node = (struct exfat_node *)calloc(1, size);
	if (!node) {
		exfat_err("failed to allocate exfat_node\n");
		return NULL;
	}

	node->parent = NULL;
	INIT_LIST_HEAD(&node->children);
	INIT_LIST_HEAD(&node->sibling);
	INIT_LIST_HEAD(&node->list);

	if (attr & ATTR_SUBDIR)
		exfat_stat.dir_count++;
	else
		exfat_stat.file_count++;
	node->attr = attr;
	return node;
}

static void free_exfat_node(struct exfat_node *node)
{
	if (node->attr & ATTR_SUBDIR)
		exfat_stat.dir_free_count++;
	else
		exfat_stat.file_free_count++;
	free(node);
}

static struct exfat *alloc_exfat(struct exfat_blk_dev *bd)
{
	struct exfat *exfat;

	exfat = (struct exfat *)calloc(1, sizeof(*exfat));
	if (!exfat) {
		exfat_err("failed to allocate exfat\n");
		return NULL;
	}

	exfat->blk_dev = bd;
	INIT_LIST_HEAD(&exfat->dir_list);
	return exfat;
}

static void free_exfat(struct exfat *exfat)
{
	if (exfat) {
		free(exfat->bs);
		free(exfat);
	}
}

void exfat_show_stat(struct exfat *exfat)
{
	exfat_debug("Found directories: %ld\n", exfat_stat.dir_count);
	exfat_debug("Found files: %ld\n", exfat_stat.file_count);
	exfat_debug("Found leak directories: %ld\n",
			exfat_stat.dir_count - exfat_stat.dir_free_count);
	exfat_debug("Found leak files: %ld\n",
			exfat_stat.file_count - exfat_stat.file_free_count);
}

int main(int argc, char * const argv[])
{
	int c, ret;
	struct fsck_user_input ui = {0,};
	struct exfat_blk_dev bd = {0,};
	struct exfat *exfat = NULL;

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

	exfat = alloc_exfat(&bd);
	if (!exfat) {
		ret = -ENOMEM;
		goto err;
	}

	exfat_show_stat(exfat);
err:
	free_exfat(exfat);
	close(bd.dev_fd);
	return ret;
}
