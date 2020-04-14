#!/bin/bash

dir=$(dirname $0)
dir=$(cd $dir;pwd -P)
ddir=$(cd $dir/..;pwd -P)

pushd $ddir/docs/source
# create rst files
$dir/python -m sphinx.apidoc -f -o . ../..
# create html documents
$dir/python -m sphinx $ddir/docs/source $ddir/docs/build
# open index in default browser
xdg-open $ddir/docs/build/index.html

