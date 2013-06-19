libskyldav_la_CPPFLAGS = \
  $(SKYLDAV_CFLAGS)

library_includedir=$(includedir)/skyldav
library_include_HEADERS = \
  conf.h \
  listmounts.h \
  Messaging.h \
  MountPolling.h \
  FanotifyPolling.h \
  StringSet.h \
  ThreadPool.h \
  VirusScan.h

lib_LTLIBRARIES = libskyldav.la

libskyldav_la_SOURCES = \
  conf.c \
  listmounts.c \
  Messaging.cc \
  MountPolling.cc \
  FanotifyPolling.cc \
  StringSet.cc \
  ThreadPool.cc \
  VirusScan.cc

libskyldav_la_LDFLAGS = \
  -version-info 1:0:1 \
  $(SKYLDAV_LIBS)

bin_PROGRAMS = \
  skyldav

skyldav_LDADD = libskyldav.la
skyldav_SOURCES = main.cc
