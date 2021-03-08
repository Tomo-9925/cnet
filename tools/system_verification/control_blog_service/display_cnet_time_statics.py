#!/usr/bin/env python

import argparse
import numpy as np
import os
import pandas as pd
import pyperclip
import re
import typing

def output_format_cnet_log(src_path, out_path, target_ip: str) -> None:
  max_column_num = 0
  with open(src_path, 'r') as src_file:
    column_num = 0
    for src_line in src_file:
      if not ('accepted' in src_line and target_ip in src_line):
        continue
      if 'has_used_cache="false"' in src_line:
        max_column_num = max(max_column_num, column_num)
        column_num = 0
      column_num += 1
  with open(src_path, 'r') as src_file, open(out_path, 'w') as out_file:
    column_num = 0
    for src_line in src_file:
      if not ('accepted' in src_line and target_ip in src_line):
        continue
      if 'has_used_cache="false"' in src_line:
        if column_num == 0:
          continue
        for i in range(max_column_num-column_num):
          out_file.write(",")
        out_file.write("\n")
        column_num = 0
      extract_time = re.search(r'processing_time="([\d\.]+.s)"', src_line).group(1)
      writing_time = extract_time.replace('µ', 'u')
      out_file.write('"{}",'.format(writing_time))
      column_num += 1
    out_file.write("\n")

def get_dataframe(out_path: str) -> pd.DataFrame:
  df = pd.read_csv(out_path, header=None)
  for column_name in df:
    df[column_name] = pd.to_timedelta(df[column_name])
  return df

def print_describes(df: pd.DataFrame) -> None:
  first_times = df.iloc[:, 0].dropna()
  first_time_describe = first_times.describe()

  the_others_times = df.iloc[:, 1].dropna()
  for column_name in df.iloc[:, 2:]:
    s = df[column_name].dropna()
    the_others_times = pd.concat([the_others_times, s])
  the_others_time_describe = the_others_times.describe()

  all_times = pd.concat([first_times, the_others_times])
  all_time_describe = all_times.describe()
  describe_df = pd.DataFrame({'first_packets': first_time_describe, 'the_other_packets': the_others_time_describe, 'all_packets': all_time_describe})
  describe_df = describe_df.applymap(lambda x: x.microseconds/1000 if type(x) is pd.Timedelta else x)
  print(describe_df)
  pyperclip.copy(describe_df.to_latex())

if __name__ == '__main__':
  arg_parser = argparse.ArgumentParser(description='Format the cnet.log created by "measure_http_time.sh"')
  arg_parser.add_argument('-s', '--src', type=str, default='cnet.log', help='Specify the log file path for cnet.')
  arg_parser.add_argument('-o', '--out', type=str, default='formatted.csv', help='Specify the output temporary file path.')
  arg_parser.add_argument('-t', '--target-ip', type=str, default='10.1.6.25', help='Specify the IP address of the target to be formatted.')
  args = arg_parser.parse_args()
  output_format_cnet_log(args.src, args.out, args.target_ip)
  df = get_dataframe(args.out)
  print_describes(df)
