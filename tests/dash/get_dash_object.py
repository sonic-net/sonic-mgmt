#!/usr/bin/env python3

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
    parser.add_argument(
        "--statedb",
        "-s",
        action="store_true"
    )
    args = parser.parse_args()

    table_name = args.table_name.replace("|", ":").split(":")[0]

    cmd =  'sonic-db-cli DPU_APPL_DB keys \"*\"'
    cmdout = ''
    with os.popen(cmd) as fp:
        cmdout = fp.read()

    if args.key is None:
        print(cmdout)
        return cmdout

    if not re.search(f'{args.table_name}:{args.key}', cmdout):
        return ""

    if args.statedb:
        cmd = f'sonic-db-cli DPU_APPL_STATE_DB HGETALL \"{args.table_name}|{args.key}\" 2> /dev/null'
        cmdout = ''
        with os.popen(cmd) as fp:
            cmdout = fp.buffer.read()
            cmdout = cmdout.decode('utf-8').strip()
        print(cmdout)
        return cmdout

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

