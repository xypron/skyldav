libskyldav_la_LDFLAGS = \
  -version-info 4:0:4 \
  $(SKYLDAV_LIBS)

libskyldav_la_CPPFLAGS = \
  $(SKYLDAV_CFLAGS)

library_includedir=$(includedir)/skyldav
library_include_HEADERS = \
  conf.h \
  listmounts.h \
  Environment.h \
  Messaging.h \
  MountPolling.h \
  FanotifyPolling.h \
  ScanCache.h \
  StringSet.h \
  ThreadPool.h \
  VirusScan.h

lib_LTLIBRARIES = libskyldav.la

libskyldav_la_SOURCES = \
  conf.c \
  listmounts.c \
  Environment.cc \
  Messaging.cc \
  MountPolling.cc \
  FanotifyPolling.cc \
  ScanCache.cc \
  StringSet.cc \
  ThreadPool.cc \
  VirusScan.cc

sbin_PROGRAMS = \
  skyldav

skyldav_LDFLAGS = \
  $(SKYLDAV_LIBS)
skyldav_LDADD = libskyldav.la
skyldav_SOURCES = skyldav.h main.cc

check:
	./skyldav --version
