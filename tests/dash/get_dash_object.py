#!/usr/bin/env python3

import sys
import argparse
import os
import re

import dash_api.utils as utils


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--table_name",
        "-t",
        required=True,
        type=str
    )
    parser.add_argument(
        "--key",
        "-k",
        type=str
    )
    args = parser.parse_args()

    table_name = args.table_name.replace("|", ":").split(":")[0]

    cmd =  'sonic-db-cli DPU_APPL_DB keys \"*\"'
    cmdout = ''
    with os.popen(cmd) as fp:
        cmdout = fp.read()

    if args.key is None:
        return cmdout

    if not re.search(f'{args.table_name}:{args.key}', cmdout):
        return ""

    cmd = f'sonic-db-cli DPU_APPL_DB HGET {args.table_name}:{args.key} \"pb\" 2> /dev/null'
    cmdout = ''
    with os.popen(cmd) as fp:
        cmdout = fp.buffer.read()

    binary = cmdout
    json_str = utils.PbBinaryToJsonString(table_name.encode("utf-8"), binary)
    print(json_str)
    return json_str

if __name__ == "__main__":
    main()

