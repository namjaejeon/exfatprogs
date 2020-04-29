AM_CFLAGS = -Wall -include $(top_srcdir)/config.h -I$(top_srcdir)/include -fno-common
fsck_exfat_LDADD = $(top_builddir)/lib/libexfat.a

sbin_PROGRAMS = fsck.exfat

fsck_exfat_SOURCES = fsck.c repair.c

man_MANS = fsck.exfat.8
