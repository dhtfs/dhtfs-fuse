dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.60)

AC_INIT([dhtfs-fuse], [0.9])

AC_CONFIG_HEADERS([src/dhtfs-config.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_SRCDIR([src/dhtfs.c])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([1.9 no-dist-gzip dist-xz foreign])

# Use pretty build output with automake >= 1.11
m4_ifdef([AM_SILENT_RULES],
         [AM_SILENT_RULES([yes])],
         [AM_DEFAULT_VERBOSITY=1 AC_SUBST(AM_DEFAULT_VERBOSITY)])

if test -z $CFLAGS; then
    CFLAGS="-g"
fi
CFLAGS="$CFLAGS -Wall"
AC_SUBST(CFLAGS)

# Checks for required programs.
AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_INSTALL
AC_PROG_RANLIB

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([string.h sys/types.h unistd.h linux/btrfs.h])

# Checks for libraries.
AC_SEARCH_LIBS([ceil], [m])

# =======================================================================
# Check for required packages
# =======================================================================
FUSE_REQUIRED_VERSION=2.6
GLIB_REQUIRED_VERSION=2.40
THRIFT_REQUIRED_VERSION=0.11

PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES(FUSE, [
        fuse >= $FUSE_REQUIRED_VERSION
])
AC_SUBST(FUSE_CFLAGS)
AC_SUBST(FUSE_LIBS)

PKG_CHECK_MODULES(GLIB, [
        glib-2.0 >= $GLIB_REQUIRED_VERSION
        gobject-2.0 >= $GLIB_REQUIRED_VERSION
        gthread-2.0 >= $GLIB_REQUIRED_VERSION
])
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)

PKG_CHECK_MODULES(THRIFT, [
        thrift_c_glib >= $THRIFT_REQUIRED_VERSION
])
AC_SUBST(THRIFT_CFLAGS)
AC_SUBST(THRIFT_LIBS)

# libbtrfsutil
AC_CHECK_LIB(btrfsutil, btrfs_util_is_subvolume, [], [
        echo "btrfsutil not found."; exit -1
])

# =======================================================================
# Write the Makefiles
# =======================================================================
AC_CONFIG_FILES([
Makefile
data/Makefile
src/Makefile
src/thrift/Makefile
])

AC_OUTPUT

echo "

                    ${PACKAGE} ${VERSION}
                    ==========

        Prefix:                      ${prefix}
        Source code location:        ${srcdir}
        Compiler:                    ${CC}
        CFLAGS:                      ${CFLAGS}
"
