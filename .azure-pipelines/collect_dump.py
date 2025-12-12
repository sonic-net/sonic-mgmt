#!/usr/bin/env python3

import argparse
import datetime
import gzip
import logging
import os
import sys
import tarfile
import traceback
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
logger.setLevel(logging.INFO)

if not logger.handlers:  # prevent adding multiple handlers
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

RC_INIT_FAILED = 1
RC_GET_TECHSUPPORT_FAILED = 2
TECHSUPPORT_SAVE_PATH = '../tests/logs/'
LOGS_DIR = os.path.join(_self_dir, TECHSUPPORT_SAVE_PATH)


def get_techsupport(sonichost, time_since, dump_dir):
    """Runs 'show techsupport' on SONiC devices and saves the output to dump_dir/"""
    try:
        logger.info(f"[{sonichost.hostname}] Running 'show techsupport --since {time_since}' ...")
        result = sonichost.command(f"show techsupport --since {time_since}")
        if result['rc'] == 0:
            tar_file = result['stdout_lines'][-1]
            tar_file_name = os.path.basename(tar_file)
            sonichost.fetch_no_slurp(src=tar_file, dest=dump_dir, flat=True)
            return tar_file_name
        logger.error(f"[{sonichost.hostname}] Failed to generate techsupport (rc={result['rc']})")
        return None

    except Exception as e:
        logger.info(f"[{sonichost.hostname}] Failed to get techsupport: {e}")
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


def extract_dump_file(testbed_name_with_idx, hostname, tar_file_name, dump_dir):
    try:
        # extract dump file
        dump_file_path = os.path.join(dump_dir, tar_file_name)
        logger.info(f"[{hostname}] Extracting dump file {dump_file_path}")
        extract_dump_tar_gz(dump_file_path, dump_dir)

        # rename dump file
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        new_file_name = f"{testbed_name_with_idx}_{hostname}_{timestamp}"
        new_file_path = os.path.join(dump_dir, new_file_name)

        logger.info(f"[{hostname}] Renaming dump to {new_file_path}")
        os.rename(dump_file_path, os.path.join(dump_dir, new_file_name + ".tar.gz"))
        os.rename(dump_file_path.split(".tar.gz")[0], new_file_path)

        # extract syslog gz files
        syslog_dir = os.path.join(new_file_path, "log")
        syslog_gz_files = [
            file for file in os.listdir(syslog_dir)
            if file.startswith("syslog") and file.endswith(".gz")
        ]
        logger.info(f"[{hostname}] Extracting {len(syslog_gz_files)} syslog files")
        for syslog_gz in syslog_gz_files:
            syslog_gz_files_path = os.path.join(syslog_dir, syslog_gz)
            extract_gz_file(syslog_gz_files_path)

        logger.info(f"[{hostname}] Dump extraction completed")
    except Exception as e:
        logger.exception(f"[{hostname}] ERROR during extraction: {e}")
        traceback.print_exc()


def collect_dump_and_extract(sonichost, time_since, testbed_name_with_idx, dump_dir):
    logger.info(f"[{sonichost.hostname}] Starting dump collection ...")
    tar_file_name = get_techsupport(sonichost, time_since=time_since, dump_dir=dump_dir)
    if tar_file_name:
        extract_dump_file(testbed_name_with_idx=testbed_name_with_idx,
                          hostname=sonichost.hostname,
                          tar_file_name=tar_file_name,
                          dump_dir=dump_dir)
    else:
        logger.warning(f"[{sonichost.hostname}] No dump file collected.")


def main(args):
    logger.info("Initializing hosts")
    sonichosts = init_testbed_sonichosts(
        args.inventory, args.testbed_name, testbed_file=args.tbfile, options={"verbosity": args.verbosity}
    )

    if not sonichosts:
        sys.exit(RC_INIT_FAILED)

    if not os.path.exists(args.dump_dir):
        os.makedirs(args.dump_dir)

    with ThreadPoolExecutor(max_workers=len(sonichosts)) as executor:
        futures = [
            executor.submit(collect_dump_and_extract,
                            sonichost, args.time_since, args.testbed_name_with_idx, args.dump_dir)
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

    parser.add_argument(
        "--dump-dir",
        type=str,
        dest="dump_dir",
        default=LOGS_DIR,
        help="Directory to store collected dumps."
    )

    args = parser.parse_args()
    main(args)
