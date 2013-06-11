EXTRA_DIST = \
skyldav.1

all:
	gzip -c skyldav.1 > skyldav.1.gz

clean-local:
	rm -f *.gz
	rm -f *~

install:
	mkdir -p -m 755 $(DESTDIR)${mandir}/man1/;true
	install -m 644 skyldav.1.gz $(DESTDIR)${mandir}/man1/skyldav.1.gz

check:
