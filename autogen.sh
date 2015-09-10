#!/bin/bash

set -e
set -x

srcdir=$(dirname $0)
test -f "$srcdir/configure.ac"

# TODO(vonhollen): Add gtk-doc support.
# gtkdocize --docdir "$srcdir/docs" --flavour no-tmpl

mkdir "$srcdir/m4"
autoreconf --force --install --verbose $@ "$srcdir"
