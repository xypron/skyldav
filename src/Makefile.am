AM_CFLAGS = -DLOGDIR='"$(localstatedir)/log/skyldav/"'

library_includedir=$(includedir)/skyldav
library_include_HEADERS = \
  conf.h \
  listmounts.h \
  MountPolling.h \
  FanotifyPolling.h \
  StringSet.h \
  ThreadPool.h \
  VirusScan.h

lib_LTLIBRARIES = libskyldav.la

libskyldav_la_SOURCES = \
  conf.c \
  listmounts.c \
  MountPolling.cc \
  FanotifyPolling.c \
  StringSet.cc \
  ThreadPool.cc \
  VirusScan.cc

libskyldav_la_LDFLAGS = -version-info 1:0:1

bin_PROGRAMS = \
  skyldav

skyldav_LDADD = libskyldav.la
skyldav_SOURCES = main.cc
