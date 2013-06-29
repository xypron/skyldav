#!/bin/sh
#
# Builds Debian package.

# Clean up
git clean

# Make distribution files.
./autogen.sh
./configure

# Build
dpkg-buildpackage

