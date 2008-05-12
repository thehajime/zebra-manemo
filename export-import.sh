#!/bin/sh

DATE=`date "+%Y%m%d"`

set -x

cvs -d:pserver:anoncvs@anoncvs.zebra.org:/cvsroot export -D${DATE} zebra

cvs -d :ext:cpu.sfc.wide.ad.jp:/home/tazaki/cvsroot/ import -I! -ko -m "import zebra-cvs-${DATE}" zebra-mndpd zebra zebra-cvs-${DATE}

# cd ${CURDIR}/src
#        cvs update -jnetbsd-current-20070615 -jnetbsd-current-20070707 -dP
#                     ~~~~~~~~~~~~~~~~~~~~~~~   ~~~~~~~~~~~~~~~~~~~~~~~
#                  (the tag of the previously   (the tag just imported
#                   imported NetBSD)             NetBSD)
