AM_CFLAGS = -DLOGDIR='"$(localstatedir)/log/skyldav/"'

library_includedir=$(includedir)/skyldav
library_include_HEADERS = \
  conf.h \
  pollfanotify.h \
  pollmounts.h \
  virusscan.h

lib_LTLIBRARIES = libskyldav.la
libskyldav_la_SOURCES = \
  conf.c \
  pollfanotify.c \
  pollmounts.c \
  virusscan.c

libskyldav_la_LDFLAGS = -version-info 1:0:1

bin_PROGRAMS = \
  skyldav

skyldav_LDADD = libskyldav.la
skyldav_SOURCES = skyldav.c
