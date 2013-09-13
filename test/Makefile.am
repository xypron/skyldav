AM_CPPFLAGS = -I../src/skyldav -D_FILE_OFFSET_BITS=64
LDADD = ../src/skyldav/libskyldav.la

check_PROGRAMS = \
  testScanCache

noinst_PROGRAMS = \
  loadTest

testScanCache_SOURCES = testScanCache.cc

loadTest_SOURCES = loadTest.cc

check:
	./testScanCache$(EXEEXT)

loadtest:
	./loadTest$(EXEEXT)
