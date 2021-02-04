#!/usr/bin/env python

import argparse
import pandas as pd
import pyperclip
import typing

def get_dataframe(src_path: str) -> pd.DataFrame:
  df = pd.read_csv(src_path, sep="\t")
  del(df['http_code'])
  del(df['speed_download'])
  return df*1000

def print_describes(df: pd.DataFrame) -> None:
  describe_df = df.describe()
  print(describe_df)
  pyperclip.copy(describe_df.to_latex())  # LaTeXのテーブルをクリップボードにコピー

if __name__ == '__main__':
  arg_parser = argparse.ArgumentParser(description='Format the curl log created by "measure_http_time.sh"')
  arg_parser.add_argument('-s', '--src', type=str, default='with_cnet.tsv', help='Specify the log file path for curl log.')
  args = arg_parser.parse_args()
  df = get_dataframe(args.src)
  print_describes(df)
