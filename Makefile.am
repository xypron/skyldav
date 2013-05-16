SUBDIRS = man src test

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = doc examples m4 w32 w64 \
  autogen.sh Doxyfile doxyheader.html

clean-local:
	rm -rf doc/doxygen

install-data-local:
	mkdir -p $(DESTDIR)$(docdir)/examples/
	cp -rf $(srcdir)/examples/* $(DESTDIR)$(docdir)/examples/

dist-hook:
	rm -rf $(distdir)/doc/doxygen
	rm -f $(distdir)/doc/version.html
	rm -rf `find $(distdir) -name '*~'`
	rm -rf `find $(distdir) -name .git`
	rm -rf `find $(distdir) -name '*.bak'`
	
documentation:
	doxygen
