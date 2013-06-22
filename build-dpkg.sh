#!/bin/sh
#
# Builds Debian package.

# Make distribution file.
./autogen.sh
./configure
make dist

# Extract to build directory
rm -rf skyldav*
tar -xzf skyld*.tar.gz
cd skyld*

# Add debian files
cp ../debian -r .

# Build
dpkg-buildpackage

