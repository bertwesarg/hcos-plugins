#!/bin/bash

set -x

mkdir -p config

# Create an aclocal file with macros for libtool.
touch aclocal.m4

if [ -e /usr/local/share/aclocal/libtool.m4 ]
then
	cat /usr/local/share/aclocal/libtool.m4 >> aclocal.m4
fi

if [ -e /usr/share/aclocal/libtool.m4 ]
then
	cat /usr/share/aclocal/libtool.m4 >> aclocal.m4
fi

libtoolize --copy
aclocal
autoheader
automake --gnu --add-missing
autoconf

cp -r config config.new
rm -rf config
mv config.new config
