#!/bin/bash

cd `dirname $0`
cd ..
find . -iname "*.log" | xargs gzip
