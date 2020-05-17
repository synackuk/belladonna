AC_PREREQ([2.69])
AC_INIT([belladonna], 1.0, [synackuk.dev])


AM_INIT_AUTOMAKE([foreign subdir-objects])

AC_CONFIG_SRCDIR([src/])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AC_PROG_CC
AC_PROG_RANLIB
AM_PROG_AR

AC_HEADER_STDC
AC_CHECK_HEADERS([stdint.h stdlib.h string.h])

AC_C_CONST
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([strdup strerror strndup])

PKG_CHECK_MODULES(libfragmentzip, libfragmentzip >= 58)
PKG_CHECK_MODULES(zlib, zlib >= 1.2)
PKG_CHECK_MODULES(libzip, libzip >= 1.5.1)
PKG_CHECK_MODULES(libirecovery, libirecovery >= 0.2.0)
PKG_CHECK_MODULES(libimobiledevice, libimobiledevice-1.0 >= 1.2.1)
PKG_CHECK_MODULES(libplist, libplist >= 1.12)
PKG_CHECK_MODULES(openssl, openssl >= 0.9.8)
PKG_CHECK_MODULES(libcurl, libcurl >= 7.0)


AC_CHECK_FUNCS([strsep strcspn mkstemp realpath])

GLOBAL_CFLAGS = "-Wno-multichar -DIDEVICERESTORE_NOMAIN=1"

AC_MSG_CHECKING([whether we need platform-specific build settings])
case ${host_os} in
  *mingw32*|*cygwin*)
    AC_MSG_RESULT([yes])
    win32=true
    GLOBAL_CFLAGS+="-DWIN32 -D__LITTLE_ENDIAN__=1"
    ;;
  darwin*)
    AC_MSG_RESULT([yes])
    AC_DEFINE([_DARWIN_BETTER_REALPATH], [1], [Use better method for realpath])
    ;;
  *)
    AC_MSG_RESULT([yes])
    ;;
esac


AC_SYS_LARGEFILE

m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

AC_CONFIG_FILES([Makefile src/Makefile tools/Makefile])
AC_OUTPUT
