#!/bin/sh
#
# Builds Debian package.

# Clean up
rm -rf skyldav*

# Make distribution file.
./autogen.sh
./configure
make dist

# Extract to build directory
tar -xzf skyld*.tar.gz
cd skyld*

# Add debian files
cp ../debian -r .

# Build
dpkg-buildpackage

