#!/usr/bin/env python2

import argparse
import logging
import sys

from devutil.devices import init_localhost, init_sonichosts, init_testbed_sonichosts
from devutil.sonic_helpers import upgrade_image

logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format="%(asctime)s %(filename)s#%(lineno)d %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


DISK_USED_PERCENT = 50

RC_INIT_FAILED = 1
RC_UPGRADE_FAILED = 3
RC_INVALID_ARGS = 5


def main(args):

    localhost = init_localhost(args.inventory, options={"verbosity": args.verbosity})
    if not localhost:
        sys.exit(RC_INIT_FAILED)

    if args.testbed_name:
        sonichosts = init_testbed_sonichosts(args.inventory, args.testbed_name, options={"verbosity": args.verbosity})
    else:
        sonichosts = init_sonichosts(args.inventory, args.devices, options={"verbosity": args.verbosity})
    if not sonichosts:
        sys.exit(RC_INIT_FAILED)

    result = upgrade_image(
        sonichosts,
        localhost,
        args.image_url,
        upgrade_type=args.upgrade_type,
        disk_used_percent=args.disk_used_percent,
        onie_pause_time=args.pause_time
    )
    if not result:
        sys.exit(RC_UPGRADE_FAILED)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Tool for SONiC image upgrade.")

    parser.add_argument(
        "-i", "--inventory",
        type=str,
        dest="inventory",
        required=True,
        help="Ansible inventory file")

    group = parser.add_mutually_exclusive_group()

    group.add_argument(
        "-d", "--device",
        type=str,
        dest="devices",
        help="Name of the device to be upgraded."
             "Mutually exclusive with testbed name argument."
    )

    group.add_argument(
        "-t", "--testbed-name",
        type=str,
        dest="testbed_name",
        help="Testbed name. DUTs of the specified testbed will be upgraded."
             "This argument is mutually exclusive with device name argument '-d' or '--device'."
    )

    parser.add_argument(
        "-u", "--url",
        type=str,
        dest="image_url",
        required=True,
        help="SONiC image url."
    )

    parser.add_argument(
        "-y", "--type",
        type=str,
        choices=["sonic", "onie"],
        dest="upgrade_type",
        required=False,
        default="sonic",
        help="Upgrade type."
    )

    parser.add_argument(
        "-f", "--tbfile",
        type=str,
        dest="tbfile",
        default="testbed.yaml",
        help="Testbed definition file."
    )

    parser.add_argument(
        "-p", "--pause-time",
        type=int,
        dest="pause_time",
        default=0,
        help="Seconds to pause after ONIE upgrade."
    )

    parser.add_argument(
        "--disk-used-percent",
        type=int,
        dest="disk_used_percent",
        default=50,
        help="Disk used percent."
    )

    parser.add_argument(
        "-v", "--verbosity",
        type=int,
        dest="verbosity",
        default=2,
        help="Log verbosity."
    )

    args = parser.parse_args()

    if not args.testbed_name and not args.devices:
        logger.error("Either testbed name or dut devices must be specified.")
        parser.print_help()
        sys.exit(RC_INVALID_ARGS)

    main(args)
