#!/usr/bin/env bash

<< COMMENTOUT
usage: ./measure_http_time [url n]

Description:
Use the curl command to display the time and status of communication.
COMMENTOUT

url=${1:-"http://10.1.123.5:8080"}
n=${2:-"50"}

acquisition_data=("http_code" "speed_download" "time_connect" "time_pretransfer" "time_starttransfer" "time_total")

curl_option=$(echo ${acquisition_data[@]} | awk '{for (i=1; i<=NF; i++) printf("%%{%s} ", $i) }' | sed -e "s/ /\\\\t/g" | sed 's/..$/\\n/')

echo ${acquisition_data[@]} | tr " " "\t"
for ((i=0; i<$n; i++)); do
  curl $url -s -o /dev/null -w $curl_option
done
