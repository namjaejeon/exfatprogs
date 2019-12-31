// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2019 Namjae Jeon <linkinjeon@gmail.com>
 */

#include "exfat_ondisk.h"
#include "exfat_tools.h"

#if defined(__LITTLE_ENDIAN)
#define BITOP_LE_SWIZZLE        0
#elif defined(__BIG_ENDIAN)
#define BITOP_LE_SWIZZLE	(~0x7)
#endif

#define BIT_MASK(nr)            ((1) << ((nr) % 32))
#define BIT_WORD(nr)            ((nr) / 32)

static inline void set_bit(int nr, volatile unsigned int *addr)
{
        unsigned long mask = BIT_MASK(nr);
        unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);

        *p  |= mask;
}

static inline void clear_bit(int nr, volatile unsigned int *addr)
{
        unsigned long mask = BIT_MASK(nr);
        unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);

        *p &= ~mask;
}

static inline void set_bit_le(int nr, void *addr)
{
	set_bit(nr ^ BITOP_LE_SWIZZLE, addr);
}

static inline void clear_bit_le(int nr, void *addr)
{
	clear_bit(nr ^ BITOP_LE_SWIZZLE, addr);
}

void exfat_set_bit(struct exfat_blk_dev *bd, char *bitmap,
		unsigned int clu)
{
	int i, b;

	i = clu >> (bd->sector_size_bits + 3);
	b = clu & ((bd->sector_size << 3) - 1);

	set_bit_le(b, bitmap);
}

void exfat_clear_bit(struct exfat_blk_dev *bd, char *bitmap,
		unsigned int clu)
{
	int i, b;

	i = clu >> (bd->sector_size_bits + 3);
	b = clu & ((bd->sector_size << 3) - 1);

	clear_bit_le(b, bitmap);
}

wchar_t exfat_bad_char(wchar_t w)
{
	return (w < 0x0020)
		|| (w == '*') || (w == '?') || (w == '<') || (w == '>')
		|| (w == '|') || (w == '"') || (w == ':') || (w == '/')
		|| (w == '\\');
}

void boot_calc_checksum(unsigned char *sector, unsigned short size,
		bool is_boot_sec, unsigned int *checksum)
{
	unsigned int index;

	for (index = 0; index < size; index++)
	{
		if (is_boot_sec == true &&
		    ((index == 106) || (index == 107) || (index == 112)))
			continue;
		*checksum = ((*checksum & 1) ? 0x80000000 : 0) +
			(*checksum >> 1) + sector[index];
	}
}
