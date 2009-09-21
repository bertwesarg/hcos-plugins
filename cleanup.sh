#!/bin/sh

# stuff to preserve:
#.
#./COPYING
#./INSTALL
#./NEWS
#./README
#./ChangeLog
#./AUTHORS
#./verbose-dump
#./verbose-dump/verbose-dump.c
#./verbose-dump/parameter.def
#./bootstrap.sh
#./cleanup.sh
#./Makefile.am
#./configure.in

set -x

make clean
make distclean

rm -f config.h.in
rm -f config.h

rm -f aclocal.m4
rm -rf autom4te.cache
rm -f stamp-h1

rm -rf config

rm -f libtool

rm -f configure
rm -f config.log config.status

rm -f Makefile
rm -f Makefile.in

rm -f verbose-dump/Makefile.in
rm -f verbose-dump/Makefile
rm -f lock-trace/Makefile.in
rm -f lock-trace/Makefile
rm -rf plugin/.deps
rm -rf plugin/.libs
