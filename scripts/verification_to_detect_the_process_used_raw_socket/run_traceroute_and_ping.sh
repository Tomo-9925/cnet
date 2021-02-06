#!/usr/bin/env bash

traceroute_host=${1:-"158.217.2.147"}
ping_host=${2:-"10.1.3.10"}
send_num=${2:-"3"}

traceroute_result_file="./traceroute_result.txt"
ping_result_file="./ping_result.txt"
pids=()

traceroute -q $send_num -I $traceroute_host &> $traceroute_result_file &
pids+=($!)

ping -c $send_num $ping_host &> $ping_result_file &
pids+=($!)

wait ${pids[@]}
cat $traceroute_result_file $ping_result_file
