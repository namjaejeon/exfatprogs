/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *  Copyright (C) 2020 Hyunchul Lee <hyc.lee@gmail.com>
 */
#ifndef _EXFAT_ICONV_H
#define _EXFAT_ICONV_H

#include <iconv.h>

/* length to byte size */
#define EXFAT_ENCSTR_MAX_BUFSIZE(__len)	(((__len) + 1) * 2)	/* UTF-16 */
#define EXFAT_DECSTR_MAX_BUFSIZE(__len)	((__len) * 3 + 1)	/* UTF-8 */

struct exfat_iconv {
	iconv_t		enc_cd;
	iconv_t		dec_cd;
	const char	*enc_charset;
	const char	*dec_charset;
};

int exfat_iconv_open(struct exfat_iconv *ei);
void exfat_iconv_close(struct exfat_iconv *ei);

int exfat_iconv_enc(struct exfat_iconv *ei, char *in_str, size_t in_size,
		char *out_str, size_t out_size);
int exfat_iconv_dec(struct exfat_iconv *ei, char *in_str, size_t in_size,
		char *out_str, size_t out_size);

int exfat_iconv_encstr_len(char *in_str, size_t in_size);

#endif
