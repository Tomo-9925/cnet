#!/bin/bash

<< COMMENTOUT
usage: ./compress_log_files.sh

Description:
Compress all log files in the project using the gzip command.
COMMENTOUT

cd `dirname $0`
cd ..
find . -iname "*.log" | xargs gzip
