## Process this file with automake to produce Makefile.in.

INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"
INSTALL_SDATA=@INSTALL@ -m 600

noinst_LIBRARIES = libolsr6.a
sbin_PROGRAMS = olsr6d

libolsr6_a_SOURCES = \
	olsr6d.c olsr_neighbor.c olsr_interface.c \
	olsr_host_network_association.c \
	olsr_interface_association.c olsr_packet.c olsr_link.c \
	olsr_route.c olsr_topology_control.c olsr_mpr.c olsr_zebra.c olsr_global_connectivity.c

noinst_HEADERS = \
	olsr_common.h olsr_node.h olsr_packet.h

olsr6d_SOURCES = \
	olsr_main.c $(libolsr6_a_SOURCES)

olsr6d_LDADD = ../lib/libzebra.a

sysconf_DATA = olsr6d.conf.sample

EXTRA_DIST = $(sysconf_DATA)

install-sysconfDATA: $(sysconf_DATA)
	@$(NORMAL_INSTALL)
	$(mkinstalldirs) $(DESTDIR)$(sysconfdir)
	@list='$(sysconf_DATA)'; for p in $$list; do \
	  if test -f $(srcdir)/$$p; then \
	    echo " $(INSTALL_SDATA) $(srcdir)/$$p $(DESTDIR)$(sysconfdir)/$$p"; \
	    $(INSTALL_SDATA) $(srcdir)/$$p $(DESTDIR)$(sysconfdir)/$$p; \
	  else if test -f $$p; then \
	    echo " $(INSTALL_SDATA) $$p $(DESTDIR)$(sysconfdir)/$$p"; \
	    $(INSTALL_SDATA) $$p $(DESTDIR)$(sysconfdir)/$$p; \
	  fi; fi; \
	done
