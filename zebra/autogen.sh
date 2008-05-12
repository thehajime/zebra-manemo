#! /bin/sh
#
# Update autoconf/automake/libtool
#
rm -f config.cache
rm -f Makefile.in
rm -f aclocal.m4
rm -f config.h.in
rm -f configure
aclocal
autoheader
autoconf
#libtoolize -c --force
automake --foreign -a -c
