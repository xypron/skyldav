SUBDIRS = man src test

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = doc examples m4 \
  autogen.sh Doxyfile doxyheader.html

clean-local:
	rm -rf doc/doxygen

install-data-local: \
  install-skyldav-examples \
  install-skyldav-conf \
  install-skyldavnotify-desktop

install-skyldav-examples:
	mkdir -p $(DESTDIR)$(docdir)/examples/
	cp -rf $(srcdir)/examples/* $(DESTDIR)$(docdir)/examples/

install-skyldav-conf:
	mkdir -p $(DESTDIR)$(sysconfdir)
	test -e $(DESTDIR)$(sysconfdir)/skyldav.conf || \
	cp examples/etc/skyldav.conf $(DESTDIR)$(sysconfdir)

if NOTIFICATION
install-skyldavnotify-desktop:
	mkdir -p $(DESTDIR)/etc/xdg/autostart/
	test -e $(DESTDIR)/etc/xdg/autostart/skyldavnotify.desktop || \
	cp examples/etc/xdg/autostart/skyldavnotify.desktop \
	$(DESTDIR)/etc/xdg/autostart/
else
install-skyldavnotify-desktop:
endif

dist-hook:
	rm -rf $(distdir)/doc/doxygen
	rm -f $(distdir)/doc/version.html
	rm -rf `find $(distdir) -name '*~'`
	rm -rf `find $(distdir) -name .git`
	rm -rf `find $(distdir) -name '*.bak'`
	
documentation:
	doxygen

loadtest:
	cd test && $(MAKE) loadtest
