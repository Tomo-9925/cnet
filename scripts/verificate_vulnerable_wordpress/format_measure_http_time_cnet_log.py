#!/usr/bin/env python

import argparse
import csv
import typing

def output_format_cnet_log(src_path, out_path, target_ip: str) -> None:
  src_file = open(src_path, 'r')
  out_file = open(out_path, 'w')
  try:
    while True:
      src_line = src_file.readline()

  except:
    src_file.close
    out_file.close
    import traceback
    traceback.print_exc()

if __name__ == '__main__':
  arg_parser = argparse.ArgumentParser(description='Format the cnet.log created by "measure_http_time.sh"')
  arg_parser.add_argument('-s', '--src', default='cnet.log', help='Specify the log file path for cnet.')
  arg_parser.add_argument('-o', '--out', default='formatted.tsv', help='Specify the output file path.')
  arg_parser.add_argument('-t', '--target-ip', default='10.1.6.25', help='Specify the IP address of the target to be formatted.')
  args = arg_parser.parse_args
  output_format_cnet_log(arg_parser.src, arg_parser.out, arg_parser.target_ip)
