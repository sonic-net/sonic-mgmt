#!/usr/bin/env python3

import argparse
import logging
import os
import sys
import datetime
import traceback
import tarfile
import gzip
from concurrent.futures import ThreadPoolExecutor

_self_dir = os.path.dirname(os.path.abspath(__file__))
base_path = os.path.realpath(os.path.join(_self_dir, ".."))
if base_path not in sys.path:
    sys.path.append(base_path)
ansible_path = os.path.realpath(os.path.join(_self_dir, "../ansible"))
if ansible_path not in sys.path:
    sys.path.append(ansible_path)

from devutil.devices.factory import init_testbed_sonichosts  # noqa: E402

logger = logging.getLogger(__name__)

RC_INIT_FAILED = 1
RC_GET_TECHSUPPORT_FAILED = 2
TECHSUPPORT_SAVE_PATH = '../tests/logs/'
LOGS_DIR = os.path.join(_self_dir, TECHSUPPORT_SAVE_PATH)


def get_techsupport(sonichost, time_since):
    """Runs 'show techsupport' on SONiC devices and saves the output to logs/"""
    try:
        # Run "show techsupport" command
        result = sonichost.command(f"show techsupport --since {time_since}")
        if result['rc'] == 0:
            tar_file = result['stdout_lines'][-1]
            tar_file_name = tar_file.split("/")[-1]
            sonichost.fetch_no_slurp(src=tar_file, dest=TECHSUPPORT_SAVE_PATH, flat=True)
            return tar_file_name

    except Exception as e:
        logger.info(f"Failed to get techsupport for {e}")
        sys.exit(RC_GET_TECHSUPPORT_FAILED)


def extract_dump_tar_gz(tar_file_path, extract_path):
    with tarfile.open(tar_file_path, 'r') as tar:
        members = tar.getmembers()
        for member in members:
            logger.info("Extracting {} {}".format(member.path, member.name))
            if "log/syslog" in member.path:
                try:
                    logger.info("Extracting {} {} to {}".format(member.path, member.name, extract_path))
                    tar.extract(member, path=extract_path)
                except Exception as e:
                    logger.info("Error extracting {} {}: {}".format(member.path, member.name, e))


def extract_gz_file(gz_file_path):
    extracted_file_path = os.path.splitext(gz_file_path)[0]
    try:
        with gzip.open(gz_file_path, 'rb') as f_in:
            with open(extracted_file_path, 'wb') as f_out:
                f_out.write(f_in.read())
        os.remove(gz_file_path)
    except Exception as e:
        logger.info("Extract gz file {} failed: {}".format(gz_file_path, str(e)))
        traceback.print_exc()


def extract_dump_file(testbed_name_with_idx, hostname, tar_file_name):
    try:
        # extract dump file
        dump_file_path = os.path.join(TECHSUPPORT_SAVE_PATH, tar_file_name)
        extract_dump_tar_gz(dump_file_path, TECHSUPPORT_SAVE_PATH)

        # rename dump file
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        new_file_name = testbed_name_with_idx + "_" + hostname + "_" + timestamp
        new_file_path = os.path.join(LOGS_DIR, new_file_name)
        os.rename(os.path.join(_self_dir, dump_file_path), os.path.join(LOGS_DIR, new_file_name + ".tar.gz"))
        os.rename(os.path.join(_self_dir, dump_file_path.split(".tar.gz")[0]), new_file_path)

        # extract syslog gz files
        syslog_dir = os.path.join(new_file_path, "log")
        syslog_gz_files = [file for file in os.listdir(os.path.join(LOGS_DIR, syslog_dir))
                           if file.startswith("syslog") and file.endswith(".gz")]
        logger.info("Syslog files: {}".format(syslog_gz_files))
        for syslog_gz in syslog_gz_files:
            syslog_gz_files_path = os.path.join(syslog_dir, syslog_gz)
            extract_gz_file(syslog_gz_files_path)

    except Exception as e:
        logger.info("Extract dump file failed: " + str(e))
        traceback.print_exc()


def collect_dump_and_extract(sonichost, time_since, testbed_name_with_idx):
    """Function to run tasks in parallel per sonichost"""
    tar_file_name = get_techsupport(sonichost, time_since=time_since)
    extract_dump_file(testbed_name_with_idx=testbed_name_with_idx,
                      hostname=sonichost.hostname, tar_file_name=tar_file_name)


def main(args):
    logger.info("Initializing hosts")
    sonichosts = init_testbed_sonichosts(
        args.inventory, args.testbed_name, testbed_file=args.tbfile, options={"verbosity": args.verbosity}
    )

    if not sonichosts:
        sys.exit(RC_INIT_FAILED)

    if not os.path.exists(LOGS_DIR):
        os.makedirs(LOGS_DIR)

    with ThreadPoolExecutor(max_workers=len(sonichosts)) as executor:
        futures = [
            executor.submit(collect_dump_and_extract, sonichost, args.time_since, args.testbed_name_with_idx)
            for sonichost in sonichosts
        ]
        for future in futures:
            future.result()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Tool for getting techsupport logs from SONiC devices."
    )

    parser.add_argument(
        "-i", "--inventory",
        dest="inventory",
        nargs="+",
        help="Ansible inventory file"
    )

    parser.add_argument(
        "-t", "--testbed-name",
        type=str,
        required=True,
        dest="testbed_name",
        help="Testbed name."
    )

    parser.add_argument(
        "-n", "--testbed-name-with-idx",
        type=str,
        required=True,
        dest="testbed_name_with_idx",
        help="Testbed name with idx."
    )

    parser.add_argument(
        "-f",
        type=str,
        dest="tbfile",
        default="testbed.yaml",
        help="Testbed definition file."
    )

    parser.add_argument(
        "-s",
        type=str,
        dest="time_since",
        default="yesterday",
        help="Collect dump since."
    )

    parser.add_argument(
        "-v", "--verbosity",
        type=int,
        dest="verbosity",
        default=2,
        help="Log verbosity (0-3)."
    )

    args = parser.parse_args()
    main(args)
