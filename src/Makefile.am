AM_CFLAGS = -DLOGDIR='"$(localstatedir)/log/skyldav/"'

library_includedir=$(includedir)/skyldav
library_include_HEADERS = \
  conf.h \
  MountPolling.h \
  pollfanotify.h \
  StringSet.h \
  virusscan.h

lib_LTLIBRARIES = libskyldav.la

libskyldav_la_SOURCES = \
  conf.c \
  MountPolling.cc \
  pollfanotify.c \
  StringSet.cc \
  virusscan.c

libskyldav_la_LDFLAGS = -version-info 1:0:1

bin_PROGRAMS = \
  skyldav

skyldav_LDADD = libskyldav.la
skyldav_SOURCES = main.cc
