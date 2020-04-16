AC_PREREQ([2.68])

AC_INIT([exfatprogs], [exfatprogs_version],
	[linkinjeon@gmail.com])

AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign tar-pax dist-xz subdir-objects])

AC_LANG([C])
AC_PROG_CC
AC_PROG_CC_STDC
AM_SILENT_RULES([yes])
AC_PROG_LIBTOOL
AC_SYS_LARGEFILE
AC_C_BIGENDIAN

PKG_PROG_PKG_CONFIG([0.9])

AC_CONFIG_FILES([
	Makefile
	lib/Makefile
	mkfs/Makefile
	fsck/Makefile
])

AC_OUTPUT
