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

#define EXFAT_CLUSTER_SIZE(pbr) (1 << ((pbr)->bsx.sect_size_bits +	\
					(pbr)->bsx.sect_per_clus_bits))
#define EXFAT_SECTOR_SIZE(pbr) (1 << (pbr)->bsx.sect_size_bits)

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
		if (exfat->bs)
			free(exfat->bs);
		free(exfat);
	}
}

static inline bool exfat_invalid_clus(struct exfat *exfat, clus_t clus)
{
	return clus < EXFAT_FIRST_CLUSTER ||
	(clus - EXFAT_FIRST_CLUSTER) > le32_to_cpu(exfat->bs->bsx.clu_count);
}

static int node_get_clus_next(struct exfat *exfat, struct exfat_node *node,
				clus_t clus, clus_t *next)
{
	off_t offset;

	if (exfat_invalid_clus(exfat, clus))
		return -EINVAL;

	if (node->is_contiguous) {
		*next = clus + 1;
		return 0;
	}

	offset = le32_to_cpu(exfat->bs->bsx.fat_offset) <<
				exfat->bs->bsx.sect_size_bits;
	offset += sizeof(clus_t) * clus;

	if (exfat_read(exfat->blk_dev->dev_fd, next, sizeof(*next), offset)
			!= sizeof(*next))
		return -EIO;
	*next = le32_to_cpu(*next);
	return 0;
}

static bool node_get_clus_count(struct exfat *exfat, struct exfat_node *node,
							clus_t *clus_count)
{
	clus_t clus;

	clus = node->first_clus;
	*clus_count = 0;

	do {
		if (exfat_invalid_clus(exfat, clus)) {
			exfat_err("bad cluster. 0x%x\n", clus);
			return false;
		}

		if (node_get_clus_next(exfat, node, clus, &clus) != 0) {
			exfat_err(
				"broken cluster chain. (previous cluster 0x%x)\n",
				clus);
			return false;
		}

		(*clus_count)++;
	} while (clus != EXFAT_EOF_CLUSTER);
	return true;
}

static int boot_region_checksum(struct exfat *exfat)
{
	__le32 checksum;
	unsigned short size;
	void *sect;
	int i;

	size = EXFAT_SECTOR_SIZE(exfat->bs);
	sect = malloc(size);
	if (!sect)
		return -ENOMEM;

	checksum = 0;

	boot_calc_checksum((unsigned char *)exfat->bs, size, true, &checksum);
	for (i = 1; i < 11; i++) {
		if (exfat_read(exfat->blk_dev->dev_fd, sect, size, i * size) !=
				(ssize_t)size) {
			free(sect);
			return -EIO;
		}
		boot_calc_checksum(sect, size, false, &checksum);
	}

	if (exfat_read(exfat->blk_dev->dev_fd, sect, size, i * size) !=
			(ssize_t)size) {
		free(sect);
		return -EIO;
	}
	for (i = 0; i < size/sizeof(checksum); i++) {
		if (le32_to_cpu(((__le32 *)sect)[i]) != checksum) {
			exfat_err("invalid checksum. 0x%x\n",
					le32_to_cpu(((__le32 *)sect)[i]));
			free(sect);
			return -EIO;
		}
	}

	free(sect);
	return 0;
}

static bool exfat_boot_region_check(struct exfat *exfat)
{
	struct pbr *bs;
	ssize_t ret;

	bs = (struct pbr *)malloc(sizeof(struct pbr));
	if (!bs) {
		exfat_err("failed to allocate memory\n");
		return false;
	}

	exfat->bs = bs;

	ret = exfat_read(exfat->blk_dev->dev_fd, bs, sizeof(*bs), 0);
	if (ret != sizeof(*bs)) {
		exfat_err("failed to read a boot sector. %ld\n", ret);
		goto err;
	}

	if (memcmp(bs->bpb.oem_name, "EXFAT   ", 8) != 0) {
		exfat_err("failed to find exfat file system.\n");
		goto err;
	}

	if (EXFAT_SECTOR_SIZE(bs) < 512) {
		exfat_err("too small sector size: %d\n", EXFAT_SECTOR_SIZE(bs));
		goto err;
	}

	if (EXFAT_CLUSTER_SIZE(bs) > 32U * 1024 * 1024) {
		exfat_err("too big cluster size: %d\n", EXFAT_CLUSTER_SIZE(bs));
		goto err;
	}

	ret = boot_region_checksum(exfat);
	if (ret) {
		exfat_err("failed to verify the checksum of a boot region. %ld\n",
			ret);
		goto err;
	}

	if (bs->bsx.fs_version[1] != 1 || bs->bsx.fs_version[0] != 0) {
		exfat_err("unsupported exfat version: %d.%d\n",
				bs->bsx.fs_version[1], bs->bsx.fs_version[0]);
		goto err;
	}

	if (bs->bsx.num_fats != 1) {
		exfat_err("unsupported FAT count: %d\n", bs->bsx.num_fats);
		goto err;
	}

	if (le64_to_cpu(bs->bsx.vol_length) * EXFAT_SECTOR_SIZE(bs) >
			exfat->blk_dev->size) {
		exfat_err("too large sector count: %llu\n, expected: %llu\n",
				le64_to_cpu(bs->bsx.vol_length),
				exfat->blk_dev->num_sectors);
		goto err;
	}

	if (le32_to_cpu(bs->bsx.clu_count) * EXFAT_CLUSTER_SIZE(bs) >
			exfat->blk_dev->size) {
		exfat_err("too large cluster count: %u, expected: %u\n",
				le32_to_cpu(bs->bsx.clu_count),
				exfat->blk_dev->num_clusters);
		goto err;
	}

	return true;
err:
	free(bs);
	exfat->bs = NULL;
	return false;
}

static bool exfat_root_dir_check(struct exfat *exfat)
{
	struct exfat_node *root;
	int ret;
	clus_t clus_count;

	root = alloc_exfat_node(ATTR_SUBDIR);
	if (!root) {
		exfat_err("failed to allocate memory\n");
		return false;
	}

	root->first_clus = le32_to_cpu(exfat->bs->bsx.root_cluster);
	if (!node_get_clus_count(exfat, root, &clus_count)) {
		exfat_err("failed to follow the cluster chain of root. %d\n",
			ret);
		goto err;
	}
	root->size = clus_count * EXFAT_CLUSTER_SIZE(exfat->bs);

	exfat->root = root;
	exfat_debug("root directory: start cluster[0x%x] size[0x%llx]\n",
		root->first_clus, root->size);
	return true;
err:
	free_exfat_node(root);
	exfat->root = NULL;
	return false;
}

void exfat_show_info(struct exfat *exfat)
{
	exfat_info("volume label [%s]\n",
			exfat->volume_label);
	exfat_info("Bytes per sector: %d\n",
			1 << le32_to_cpu(exfat->bs->bsx.sect_size_bits));
	exfat_info("Sectors per cluster: %d\n",
			1 << le32_to_cpu(exfat->bs->bsx.sect_per_clus_bits));
	exfat_info("Cluster heap count: %d(0x%x)\n",
			le32_to_cpu(exfat->bs->bsx.clu_count),
			le32_to_cpu(exfat->bs->bsx.clu_count));
	exfat_info("Cluster heap offset: %#x\n",
			le32_to_cpu(exfat->bs->bsx.clu_offset));
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

	exfat_debug("verifying boot regions...\n");
	if (!exfat_boot_region_check(exfat)) {
		exfat_err("failed to verify boot regions.\n");
		goto err;
	}

	exfat_show_info(exfat);

	exfat_debug("verifying root directory...\n");
	if (!exfat_root_dir_check(exfat)) {
		exfat_err("failed to verify root directory.\n");
		goto out;
	}

out:
	exfat_show_stat(exfat);
err:
	free_exfat(exfat);
	close(bd.dev_fd);
	return ret;
}
