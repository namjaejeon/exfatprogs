/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *  Copyright (C) 2020 Hyunchul Lee <hyc.lee@gmail.com>
 */

#include <stdio.h>
#include <errno.h>
#include <iconv.h>

#include "exfat_ondisk.h"
#include "exfat_tools.h"
#include "exfat_iconv.h"

int exfat_iconv_open(struct exfat_iconv *ei)
{
	ei->enc_charset = "UTF-16LE";
	ei->dec_charset = "UTF-8";

	ei->enc_cd = iconv_open(ei->enc_charset, ei->dec_charset);
	if (ei->enc_cd == (iconv_t)-1)
		goto err;

	ei->dec_cd = iconv_open(ei->dec_charset, ei->enc_charset);
	if (ei->dec_cd == (iconv_t)-1) {
		iconv_close(ei->enc_cd);
		goto err;
	}

	return 0;
err:
	if (errno == EINVAL)
		exfat_err("conversion between %s and %s is not avaiable\n",
			ei->enc_charset, ei->dec_charset);
	else
		exfat_err("error at iconv_open: %d\n", -errno);
	return -errno;
}

void exfat_iconv_close(struct exfat_iconv *ei)
{
	iconv_close(ei->enc_cd);
	iconv_close(ei->dec_cd);
}

static int iconv_conv(iconv_t cd, char *in_str, size_t in_size,
			char *out_str, size_t out_size)
{
	size_t size = out_size;

	if (iconv(cd, &in_str, &in_size, &out_str, &size) < 0) {
		if (errno == E2BIG)
			exfat_err("input string is too long\n");
		else if (errno == EINVAL || errno == EILSEQ)
			exfat_err("invaild character sequence\n");
		return -errno;
	}
	if (size > 0)
		*out_str = '\0';
	return out_size - size;
}

int exfat_iconv_enc(struct exfat_iconv *ei, char *in_str, size_t in_size,
		char *out_str, size_t out_size)
{
	return iconv_conv(ei->enc_cd, in_str, in_size, out_str, out_size);
}

int exfat_iconv_dec(struct exfat_iconv *ei, char *in_str, size_t in_size,
		char *out_str, size_t out_size)
{
	return iconv_conv(ei->dec_cd, in_str, in_size, out_str, out_size);
}

int exfat_iconv_encstr_len(char *in_str, size_t in_size)
{
	size_t i = 0;
	__le16 *str = (__le16 *)in_str;

	while (le16_to_cpu(str[i]) && i < in_size/2)
		i++;
	return i;
}
