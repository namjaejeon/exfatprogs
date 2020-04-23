AM_CFLAGS = -Wall -Werror -Wunused-parameter \
	    -Wno-address-of-packed-member \
	    -include $(top_srcdir)/config.h -I$(top_srcdir)/include -fno-common
label_exfat_LDADD = $(top_builddir)/lib/libexfat.la

sbin_PROGRAMS = label.exfat

label_exfat_SOURCES = label.c
