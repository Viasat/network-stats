#!/usr/bin/env python3

import argparse
import re
from pathlib import Path

if __name__ == "__main__":
    cmd_parser = argparse.ArgumentParser(description="Tool that splits csv files created by network-stats into 5 minute long files")
    cmd_parser.add_argument("-i", "--input", help="csv file to be split; will not be modified", type=argparse.FileType('r'))
    cmd_parser.add_argument("-o", "--output", help="Directory to put split files")
    args = cmd_parser.parse_args()
    output_path = Path(args.output)
    if output_path.is_dir():
        time_pattern = re.compile('\d+')
        file_header = args.input.readline()
        file_start_time = 0
        file_name_int = 0
        
        output_file = None
        for line in args.input:
            time = int(time_pattern.match(line).group())
            if time > file_start_time + 300:
                file_name = str(file_name_int) + '.csv'
                output_file_path = output_path / file_name
                output_file = output_file_path.open('w')
                output_file.write(file_header)
                file_start_time = time
                file_name_int+=1
            output_file.write(line)
    else:
        print("Output is not a directory")