// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2019 Namjae Jeon <linkinjeon@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>
#include <errno.h>

#include "exfat_ondisk.h"
#include "exfat_tools.h"
#include "mkfs.h"

static void calc_checksum(char *sector, unsigned short size,
		bool is_boot_sec, unsigned int *checksum)
{
	unsigned int index;

	for (index = 0; index < size; index++)
	{
		if (is_boot_sec == true &&
		    ((index == 106) || (index == 107) || (index == 112)))
			continue;
		*checksum = ((*checksum & 1) ? 0x80000000 : 0) +
			(*checksum >> 1) + (unsigned int)sector[index];
	}
}

static void exfat_setup_boot_sector(struct pbr *ppbr,
		struct exfat_blk_dev *bd, struct exfat_user_input *ui)
{
	struct bpb64 *pbpb = &ppbr->bpb;
	struct bsx64 *pbsx = &ppbr->bsx;

	/* Fill exfat BIOS paramemter block */
	pbpb->jmp_boot[0] = 0xeb;
	pbpb->jmp_boot[1] = 0x76;
	pbpb->jmp_boot[2] = 0x90;
	memcpy(pbpb->oem_name, "EXFAT   ", 8);	
	memset(pbpb->res_zero, 0, 53);

	/* Fill exfat extend BIOS paramemter block */
	pbsx->vol_offset = 0;
	pbsx->vol_length = cpu_to_le64(bd->size / bd->sector_size);
	pbsx->fat_offset = cpu_to_le32(finfo.fat_byte_off / bd->sector_size);
	pbsx->fat_length = cpu_to_le32(finfo.fat_byte_len / bd->sector_size);
	pbsx->clu_offset = cpu_to_le32(finfo.clu_byte_off / bd->sector_size);
	pbsx->clu_count = cpu_to_le32(finfo.total_clu_cnt);
	pbsx->root_cluster = cpu_to_le32(finfo.root_byte_off / ui->cluster_size);
	pbsx->vol_serial = 1234;
	pbsx->vol_flags = 0;
	pbsx->sect_size_bits = bd->sector_size_bits;
	pbsx->sect_per_clus_bits = ui->sec_per_clu / 32;
	pbsx->num_fats = 1;
	/* fs_version[0] : minor and fs_version[1] : major */
	pbsx->fs_version[0] = 0;
	pbsx->fs_version[1] = 1;
	memset(pbsx->reserved2, 0, 7);

	memset(ppbr->boot_code, 0, 390); 
	ppbr->signature = cpu_to_le16(PBR_SIGNATURE);
}

static int exfat_write_sector(struct exfat_blk_dev *bd, void *buf, unsigned int sec_off)
{
	int bytes;
	unsigned long long offset = sec_off * bd->sector_size;

	lseek(bd->dev_fd, offset, SEEK_SET);
	bytes = write(bd->dev_fd, buf, bd->sector_size);
	if (bytes != bd->sector_size)
		return -1;
	return 0;
}

static int exfat_write_boot_sectors(struct exfat_blk_dev *bd,
		struct exfat_user_input *ui, unsigned int *checksum)
{
	struct pbr *ppbr;
	int ret;

	ppbr = malloc(sizeof(struct pbr));
	if (!ppbr) {
		printf("Cannot allocate pbr: out of memory\n");
		return -1;
	}
	memset(ppbr, 0, sizeof(struct pbr));

	exfat_setup_boot_sector(ppbr, bd, ui);

	/* write main boot sector */
	ret = exfat_write_sector(bd, ppbr, 0);
	if (ret < 0) {
		ret = -1;
		goto free_ppbr;
	}

	/* write backup boot sector */
	ret = exfat_write_sector(bd, ppbr, 1);
	if (ret < 0) {
		ret = -1;
		goto free_ppbr;
	}

	calc_checksum((char *)ppbr, sizeof(struct pbr), true, checksum);

free_ppbr:
	free(ppbr);
	return 0;
}

static int exfat_write_extended_boot_sectors(struct exfat_blk_dev *bd,
		unsigned int *checksum)
{
	int sec_idx;
	struct expbr ep;

	memset(&ep, 0, EXBOOT_SEC8_NUM * bd->sector_size);
	for (sec_idx = EXBOOT_SEC_NUM; sec_idx <= EXBOOT_SEC8_NUM; sec_idx++) {
		int ret;

		ep.eb[sec_idx - 1].signature = cpu_to_le16(0xAA55);
		if (exfat_write_sector(bd, &ep, sec_idx))
			return -1;

		calc_checksum((char *) &ep, sizeof(struct expbr), false, checksum);
	}

	return 0;
}

static int exfat_write_oem_sector(struct exfat_blk_dev *bd,
		unsigned int *checksum)
{
	char *oem;

	oem = malloc(bd->sector_size);
	if (oem)
		return -1;

	memset(oem, 0xFF, bd->sector_size);
	if (exfat_write_sector(bd, oem, OEM_SEC_NUM))
		return -1;

	calc_checksum((char *)oem, bd->sector_size, false, checksum);
}

static int exfat_write_checksum_sector(struct exfat_blk_dev *bd,
		unsigned int checksum)
{
	int *checksum_buf;

	checksum_buf = malloc(bd->sector_size);
	if (checksum_buf)
		return -1;

	memset(checksum_buf, checksum, bd->sector_size / sizeof(int));
	if (exfat_write_sector(bd, checksum_buf, OEM_SEC_NUM))
		return -1;
}

static int exfat_create_volume_boot_record(struct exfat_blk_dev *bd,
		struct exfat_user_input *ui)
{
	int ret;
	unsigned int checksum;

	ret = exfat_write_boot_sectors(bd, ui, &checksum);
	if (ret)
		return ret;

	ret = exfat_write_extended_boot_sectors(bd, &checksum);
	if (ret)
		return ret;

	ret = exfat_write_oem_sector(bd, &checksum);
	if (ret)
		return ret;

	ret = exfat_write_checksum_sector(bd, checksum);
	return ret;
}

static int write_fat_entry(int fd, unsigned int entry,
		unsigned long long offset)
{
	int nbyte;

	lseek(fd, finfo.fat_byte_off + (offset * sizeof(int)), SEEK_SET);
	nbyte = write(fd, (char *) &entry, sizeof(unsigned int));
	if (nbyte != sizeof(int))
		return -1;
}

static int exfat_create_fat_table(struct exfat_blk_dev *bd,
		struct exfat_user_input *ui)
{
	int ret, clu, clu_cnt, bitmap_clu_cnt, ut_cnt, root_cnt;
	int count;

	/* fat entry 0 should be media type field(0xF8) */
	ret = write_fat_entry(bd->dev_fd, 0xfffffff8, 0);
	if (ret)
		return ret;

	/* fat entry 1 is historical precedence(0xFFFFFFFF) */
	ret = write_fat_entry(bd->dev_fd, 0xffffffff, 1);
	if (ret)
		return ret;

	/* write bitmap entries */
	count = EXFAT_FIRST_CLUSTER + (finfo.bitmap_byte_len / ui->cluster_size);
	for (clu = EXFAT_FIRST_CLUSTER; clu < count; clu++) {
		ret = write_fat_entry(bd->dev_fd, clu, clu * sizeof(int));
		if (ret)
			return ret;
	}

	/* write upcase table entries */
	count += finfo.ut_byte_len / ui->cluster_size;
	finfo.ut_start_clu = clu;
	for (; clu < count; clu++) {
		ret = write_fat_entry(bd->dev_fd, clu, clu);
		if (ret)
			return ret;
	}

	/* write root directory entries */
	count += finfo.root_byte_len / ui->cluster_size;
	finfo.root_start_clu = clu;
	for (; clu < count; clu++) {
		ret = write_fat_entry(bd->dev_fd, clu, clu);
		if (ret)
			return ret;
	}

	finfo.used_clu_cnt = count;

	return ret;
}

static int exfat_create_bitmap(struct exfat_blk_dev *bd,
		struct exfat_user_input *ui)
{
	char *bitmap;
	int i,nbytes;

	bitmap = malloc(finfo.bitmap_byte_len);
	if (!bitmap)
		return -1;

	for (i = 0; i < finfo.used_clu_cnt; i++)
		exfat_set_bit(bd, bitmap, i);

	lseek(bd->dev_fd, finfo.bitmap_byte_off, SEEK_SET);
	nbytes = write(bd->dev_fd, bitmap, finfo.bitmap_byte_len);
	if (nbytes != finfo.bitmap_byte_len)
		return -1;

	return 0;
}

static int exfat_create_root_dir(struct exfat_blk_dev *bd,
		struct exfat_user_input *ui)
{
	struct exfat_dentry ed[3];
	int dentries_len = sizeof(struct exfat_dentry) * 3;
	int nbytes;

	/* Set volume label entry */
	ed[0].type = EXFAT_VOLUME;
	strcpy(ed[0].vol_label, "EXFAT");
	ed[0].vol_char_cnt = strlen("EXFAT");

	/* Set bitmap entry */
	ed[1].type = EXFAT_BITMAP;
	ed[1].bitmap_flags = 0;
	ed[1].bitmap_start_clu = EXFAT_FIRST_CLUSTER;
	ed[1].bitmap_size = finfo.bitmap_byte_len;

	/* Set upcase table entry */
	ed[2].type = EXFAT_UPCASE;
	ed[2].upcase_checksum = cpu_to_le32(0xe619d30d);
	ed[2].upcase_start_clu = finfo.ut_start_clu;
	ed[2].upcase_size = EXFAT_UPCASE_TABLE_SIZE;

	lseek(bd->dev_fd, finfo.root_byte_off, SEEK_SET);
	nbytes = write(bd->dev_fd, ed, dentries_len);
	if (nbytes != dentries_len)
		return -1;

	return 0;
}

int exfat_get_blk_dev_info(struct exfat_user_input *ui, struct exfat_blk_dev *bd)
{
	int fd, ret = -1;
	unsigned long long blk_dev_size;

	fd = open(ui->dev_name, O_RDWR);
	if (fd < 0)
		return -1;

	blk_dev_size = lseek(fd, 0, SEEK_END);
	if (blk_dev_size <= 0) {
		perror("exfat-tools\n");
		goto out;
	}

	bd->size = blk_dev_size;
	bd->sector_size = DEFAULT_SECTOR_SIZE;
	bd->sector_size_bits = 9;
	bd->num_sectors = blk_dev_size / DEFAULT_SECTOR_SIZE;
	if (bd->num_sectors < MIN_NUM_SECTOR) {
		printf(" \n");
		goto out;
	}
	bd->num_clusters = blk_dev_size / ui->cluster_size;

	ret = 0;
	bd->dev_fd = fd;
out:
	return ret;
}

static void usage(void)
{       
	fprintf(stderr, "exfat-tools version : %s\n", EXFAT_TOOLS_VERSION);
	fprintf(stderr, "Usage: mkfs.exfat\n");

	fprintf(stderr, "\t-v | --verbose\n");

	exit(EXIT_FAILURE);
}

static int verify_user_input(struct exfat_blk_dev *bd,
		struct exfat_user_input *ui)
{
	ui->sec_per_clu = ui->cluster_size / bd->sector_size;
	return 0;
}

static void make_exfat_layout_info(struct exfat_blk_dev *bd,
		struct exfat_user_input *ui)
{
	int num_bitmap_clu;

	if (DEFAULT_CLUSTER_SIZE < ui->sec_per_clu)
		finfo.fat_byte_off = ui->cluster_size;
	else
		finfo.fat_byte_off = DEFAULT_CLUSTER_SIZE;
	finfo.fat_byte_len = round_up((bd->num_clusters * sizeof(int)),
		ui->cluster_size);
	finfo.clu_byte_off = round_up(finfo.fat_byte_off + finfo.fat_byte_len,
		DEFAULT_CLUSTER_SIZE);
	finfo.total_clu_cnt = (bd->size - finfo.clu_byte_off) / ui->cluster_size;
	finfo.bitmap_byte_off = EXFAT_REVERVED_CLUSTERS * ui->cluster_size;
	finfo.bitmap_byte_len = round_up(finfo.total_clu_cnt, 8) / 8;
	finfo.ut_byte_off = finfo.bitmap_byte_off + finfo.bitmap_byte_len;
	finfo.ut_start_clu = finfo.ut_byte_off / ui->cluster_size;
	finfo.ut_byte_len = EXFAT_UPCASE_TABLE_SIZE;
	finfo.root_byte_off = finfo.ut_byte_off + finfo.ut_byte_len;
	finfo.root_start_clu = finfo.root_byte_off / ui->cluster_size;
	finfo.root_byte_len = sizeof(struct exfat_dentry) * 3;
}

int main(int argc, char *argv[])
{
	int c;
        int ret = EXIT_FAILURE;
	char *blk_dev_name;
	struct exfat_blk_dev bd;
	struct exfat_user_input ui;

	/*
	 * Default cluster size, Need to adjust default cluster size
	 * according to device size
	 */
	ui.cluster_size = 128 * 1024;

        opterr = 0;
        while ((c = getopt(argc, argv, "s:vh")) != EOF)
                switch (c) {
                case 'c':
			ui.cluster_size = atoi(optarg);
			if (ui.cluster_size > MAX_CLUSTER_SIZE) {
				printf("cluster size(%d) exceeds max cluster size(%d)",
						ui.cluster_size, MAX_CLUSTER_SIZE);
				goto out;
			}
			break;
                case 'v':
                        break;
                case '?':
                case 'h':
                default:
                        usage();
        }

	if (argc - optind != 1)
		usage();

	memset(ui.dev_name, 0, 255);
	strncpy(ui.dev_name, argv[optind], 255);

	ret = exfat_get_blk_dev_info(&ui, &bd);
	if (ret < 0)
		goto out;

	ret = verify_user_input(&bd, &ui);
	if (ret < 0)
		goto out;

	make_exfat_layout_info(&bd, &ui);

	ret = exfat_create_volume_boot_record(&bd, &ui);
	if (ret)
		goto out;

	ret = exfat_create_fat_table(&bd, &ui);
	if (ret)
		goto out;

	ret = exfat_create_bitmap(&bd, &ui);
	if (ret)
		goto out;

	ret = exfat_create_upcase_table(&bd, &ui);
	if (ret)
		goto out;

	ret = exfat_create_root_dir(&bd, &ui);

out:
	return ret;
}
