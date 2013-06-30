CPPFLAGS = -I../src/skyldav -D_FILE_OFFSET_BITS=64
LDADD = ../src/skyldav/libskyldav.la

check_PROGRAMS = \
  testScanCache

testScanCache_SOURCES = testScanCache.cc

check:
	./testScanCache$(EXEEXT)
