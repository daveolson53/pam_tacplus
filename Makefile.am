###########################################################################
## File:        ./Makefile.am
## Versions:    $Id: Makefile.am,v 1.3 2010/06/11 12:04:29 j-nijhof Exp $
## Created:     2010/06/09
## Modified 2016
## Copyright 2015, 2016 Cumulus Networks, Inc.  All rights reserved.
##
###########################################################################

ACLOCAL_AMFLAGS = -I config
AUTOMAKE_OPTIONS = subdir-objects

bin_PROGRAMS = tacc
tacc_SOURCES = tacc.c
tacc_CFLAGS = $(AM_CFLAGS) -I $(top_srcdir)/libtac/include
tacc_LDFLAGS = -L.libs -ltac $(OPENSSL_LIBS)
dist_man_MANS = tacc.1 tacplus_servers.5


# This applies to all the libs, but it should only be for pam_tacplus.so
moduledir = @pamdir@

module_LTLIBRARIES = pam_tacplus.la
lib_LTLIBRARIES = libtac.la

libtac_includedir = $(oldincludedir)/tacplus

libtac_include_HEADERS = \
libtac/include/tacplus.h \
libtac/include/libtac.h

nodist_libtac_include_HEADERS = \
libtac/include/cdefs.h

libtac_la_SOURCES = \
libtac/lib/acct_r.c \
libtac/lib/acct_s.c \
libtac/lib/attrib.c \
libtac/lib/authen_r.c \
libtac/lib/authen_s.c \
libtac/lib/author_r.c \
libtac/lib/author_s.c \
libtac/lib/connect.c \
libtac/lib/cont_s.c \
libtac/lib/crypt.c \
libtac/lib/hdr_check.c \
libtac/lib/header.c \
libtac/lib/magic.c \
libtac/lib/magic.h \
libtac/lib/md5.c \
libtac/lib/md5.h \
libtac/lib/messages.c \
libtac/lib/messages.h \
libtac/lib/read_wait.c \
libtac/lib/version.c \
libtac/lib/xalloc.c \
libtac/lib/xalloc.h \
$(libtac_include_HEADERS)
libtac_la_CFLAGS = $(AM_CFLAGS) -I $(top_srcdir)/libtac/include
libtac_la_LIBADD = -lpthread $(OPENSSL_LIBS)
libtac_la_LDFLAGS = -version-info 2:0:0 -shared -Wl,--no-undefined \
	-export-symbols-regex '^tac_'


pam_tacplus_la_SOURCES = pam_tacplus.h \
pam_tacplus.c \
support.h \
support.c
pam_tacplus_la_CFLAGS = $(AM_CFLAGS) -I $(top_srcdir)/libtac/include
pam_tacplus_la_LDFLAGS = -module -avoid-version -shared
pam_tacplus_la_LIBADD = -L.libs -ltac -ltacplus_map -lpam $(OPENSSL_LIBS)
# no versioning for this, since it's always installed as pam_tacplus.so
# and not ever used as a link library

EXTRA_DIST = pam_tacplus.spec libtac.pc.in
if DOC
dist_doc_DATA = sample.pam README.md AUTHORS ChangeLog
endif

MAINTAINERCLEANFILES = Makefile.in config.h.in configure aclocal.m4 \
                       config/config.guess  config/config.sub  config/depcomp \
                       config/install-sh config/ltmain.sh config/missing

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libtac.pc

clean-generic:
	rm -rf autom4te*.cache 
	rm -f *.rej *.orig *.lang

install-data-hook:
	${INSTALL} -d $(DESTDIR)$(sysconfdir)
	${INSTALL} -m 600 tacplus_servers $(DESTDIR)$(sysconfdir)

