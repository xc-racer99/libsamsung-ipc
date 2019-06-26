AC_INIT([libsamsung-ipc], [0.3.2], [contact@replicant.us], [libsamsung-ipc])
AC_CONFIG_SRCDIR([Makefile.am])
AC_CONFIG_HEADERS(config.h)
AM_INIT_AUTOMAKE([dist-bzip2 subdir-objects])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_PROG_CC
AM_PROG_CC_C_O
AC_GNU_SOURCE
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

AC_SUBST(CFLAGS)
AC_SUBST(CPPFLAGS)
AC_SUBST(LDFLAGS)

OPENSSL_REQUIRED=1.0.0e

#------------------------------------------------------------------------------
# pkg-config

PKG_PROG_PKG_CONFIG

#------------------------------------------------------------------------------
# openssl

PKG_CHECK_MODULES(OPENSSL, openssl >= $OPENSSL_REQUIRED)
AC_SUBST(OPENSSL_CFLAGS)
AC_SUBST(OPENSSL_LIBS)

#------------------------------------------------------------------------------
# check for debugging
AC_ARG_ENABLE(debug,
  [  --enable-debug            Enable debug build (default=disabled)],
  [debug=$enableval],
  [debug="no"])
AM_CONDITIONAL( [WANT_DEBUG], [test x"$debug" = x"yes"])

#------------------------------------------------------------------------------

AC_CONFIG_FILES([
    Makefile
    samsung-ipc.pc
    include/Makefile
    samsung-ipc/Makefile
    tools/Makefile
])
AC_OUTPUT

#------------------------------------------------------------------------------
# info

echo "------------------------------------------------------------------------"
echo "$PACKAGE_NAME $PACKAGE_VERSION"
echo "------------------------------------------------------------------------"
echo
echo "Configuration Options:"
echo
echo "  debug build.............: $debug"
echo
echo "  prefix..................: $prefix"
echo
echo "------------------------------------------------------------------------"
echo
echo "Now type 'make' to compile and 'make install' to install this package."

