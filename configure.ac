dnl Skyld AV

dnl Initialization
AC_INIT([skyldav], [0.4], [xypron.glpk@gmx.de])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

dnl Archiver support.
AM_PROG_AR

dnl Enhanced libtool support.
LT_INIT

dnl Compiler check
AC_PROG_CC
AC_CHECK_PROG([have_cc],[$CC],[yes],[no])
if test [$have_cc] != [yes]; then
  AC_MSG_ERROR([$CC is missing])
fi
AC_PROG_CXX
AC_CHECK_PROG([have_cxx],[$CXX],[yes],[no])
if test [$have_cxx] != [yes]; then
  AC_MSG_ERROR([$CXX is missing])
fi

dnl Provide $(LN_S)
AC_PROG_LN_S

dnl Configure macros
AC_CONFIG_MACRO_DIR([m4])

dnl Load pkg.m4
PKG_PROG_PKG_CONFIG

dnl Create config.h
AC_CONFIG_HEADERS([config.h])

AC_ARG_VAR([SKYLDAVLOGFILE],
  [logfile, default is '/run/skyldav/log'])

if test [x$SKYLDAVLOGFILE] = [x]; then
  SKYLDAVLOGFILE="/run/skyldav/log"
fi
AC_DEFINE_UNQUOTED([LOGFILE], "${SKYLDAVLOGFILE}", [Skyld AV log file])

dnl Set compiler flags
dnl add large file support on 32bit systems
CPPFLAGS="-D_FILE_OFFSET_BITS=64 $CPPFLAGS"
dnl adjust include path
CPPFLAGS="-I. $CPPFLAGS"

dnl set linker flags
LDFLAGS="-g $LDFLAGS"

AC_ARG_WITH(notification,
AC_HELP_STRING([--with-notification],
   [Provide desktop notification [[default=yes]]]),
   [case $withval in
      yes | no) ;;
      *) AC_MSG_ERROR([invalid value '$withval' for --with-notification]);;
      esac],
   [with_notification=yes])

AM_CONDITIONAL([NOTIFICATION], [test "x$with_notification" = "xyes"])
if test "x$with_notification" = "xyes"; then
  PKG_CHECK_MODULES([NOTIFY], [gtk+-2.0 >= 2.20.1 libnotify >= 0.5.0])
  AC_CHECK_HEADER([canberra.h], [],
    [AC_MSG_ERROR([canberra.h header not found])])
  NOTIFY_LIBS="-lcanberra $NOTIFY_LIBS"
fi
AC_CHECK_HEADER([libmount/libmount.h], [],
  [AC_MSG_ERROR([libmount/libmount.h header not found])])
AC_CHECK_HEADER([sys/capability.h], [],
  [AC_MSG_ERROR([sys/capability.h header not found])])
PKG_CHECK_MODULES([SKYLDAV], [libclamav >= 0.97.8])
SKYLDAV_LIBS="-lcap -lmount $SKYLDAV_LIBS"

dnl Thread support
AX_PTHREAD(have_pthread=yes,have_pthread=no)
AC_MSG_NOTICE([PTHREAD_CC=$PTHREAD_CC])
AC_MSG_NOTICE([PTHREAD_CCFLAGS=$PTHREAD_CFLAGS])
AC_MSG_NOTICE([PTHREAD_LIBS=$PTHREAD_LIBS])
CC="$PTHREAD_CC"
CPPFLAGS="$PTHREAD_CFLAGS $CPPFLAGS"
LDFLAGS="$PTHREAD_LIBS $LDFLAGS"

AC_MSG_NOTICE([CPPFLAGS = $CPPFLAGS])
AC_MSG_NOTICE([LDFLAGS  = $LDFLAGS])
AC_MSG_NOTICE([NOTIFY_LIBS = $NOTIFY_LIBS])
AC_MSG_NOTICE([SKYLDAV_LIBS = $SKYLDAV_LIBS])

dnl Check includes
AC_CHECK_HEADER([pthread.h],
  [],
  [AC_MSG_ERROR([pthread.h not found])]
  )

dnl Doxygen
DX_INIT_DOXYGEN(["Skyld AV"], [$srcdir/Doxyfile])

dnl Makefiles
AC_CONFIG_FILES([
  Makefile
  man/Makefile
  src/Makefile
  src/notify/Makefile
  src/skyldav/Makefile
  test/Makefile
  ])

dnl Generate files
AC_OUTPUT
