dnl Skyld AV

dnl Initialization
AC_INIT([skyldav], [0.1], [xypron.glpk@gmx.de])
AM_INIT_AUTOMAKE
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

dnl Create config.h
AC_CONFIG_HEADERS([config.h])

dnl Set compiler flags
CPPFLAGS="-I`cd $srcdir && pwd`/src $CPPFLAGS"
CPPFLAGS="`pkg-config --cflagslibclamav` $CPPFLAGS"
LDFLAGS="-lcap $LDFLAGS"
LDFLAGS="`pkg-config --libs libclamav` $LDFLAGS"

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

dnl Check includes
AC_CHECK_HEADER([pthread.h],
  [],
  [AC_MSG_ERROR([pthread.h not found])]
  )

dnl Doxygen
DX_INIT_DOXYGEN(["Statistics for MySQL"], [$srcdir/Doxyfile])

dnl Makefiles
AC_CONFIG_FILES([
  Makefile
  man/Makefile
  src/Makefile
  test/Makefile
  ])

dnl Generate files
AC_OUTPUT
