## Process this file with automake to produce Makefile.in.

SUBDIRS = lib @ZEBRA@ @BGPD@ @RIPD@ @RIPNGD@ @OSPFD@ @OSPF6D@ @VTYSH@ doc @OLSR6D@

EXTRA_DIST = aclocal.m4 SERVICES TODO REPORTING-BUGS vtysh/Makefile.in \
	vtysh/Makefile.am

dist-hook:
	test -d $(distdir)/conftools || mkdir -f $(distdir)/conftools
	cp -p $(srcdir)/conftools/config.guess $(distdir)/conftools
	cp -p $(srcdir)/conftools/config.sub $(distdir)/conftools
	cp -p $(srcdir)/conftools/install-sh $(distdir)/conftools
	cp -p $(srcdir)/conftools/missing $(distdir)/conftools
	cp -p $(srcdir)/conftools/mkinstalldirs $(distdir)/conftools
	mkdir $(distdir)/tools
	cp -p $(srcdir)/tools/*.pl $(distdir)/tools
	cp -p $(srcdir)/tools/*.el $(distdir)/tools
	cp -p $(srcdir)/tools/*.cgi $(distdir)/tools
	mkdir $(distdir)/init
	mkdir $(distdir)/init/redhat
	cp -p $(srcdir)/init/redhat/*.init $(distdir)/init/redhat
	cp -p $(srcdir)/init/redhat/zebra.* $(distdir)/init/redhat
