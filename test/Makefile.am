CPPFLAGS = -I../src/skyldav
LDADD = ../src/skyldav/libskyldav.la

check_PROGRAMS = \
  testScanCache

testScanCache_SOURCES = testScanCache.cc

check:
	./testScanCache$(EXEEXT)
