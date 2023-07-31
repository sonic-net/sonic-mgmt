#!/usr/bin/env python3

"""Script for upgrading SONiC image for nightly tests.

Main purpose of this script is to upgrade SONiC image for nightly tests. Based on the arguments passed in, the script
may power cycle the devices before upgrade. Or only power cycle the devices only when they are unreachable.

Before upgrade to the target image, this script may upgrade to a previous image firstly. This is to avoid that the
devices are already running the target image. Then image upgrading could be skipped. The problem is that the current
image may has been updated by people for debugging purpose. Upgrade to a previous image firstly can ensure that the
target image is clean.
"""
import argparse
import logging
import os
import requests
import sys

_self_dir = os.path.dirname(os.path.abspath(__file__))
base_path = os.path.realpath(os.path.join(_self_dir, ".."))
if base_path not in sys.path:
    sys.path.append(base_path)
ansible_path = os.path.realpath(os.path.join(_self_dir, "../ansible"))
if ansible_path not in sys.path:
    sys.path.append(ansible_path)


from devutil.devices.factory import init_localhost, init_testbed_sonichosts         # noqa E402
from devutil.devices.sonic import upgrade_image                                     # noqa E402

from tests.common.plugins.pdu_controller.pdu_manager import pdu_manager_factory     # noqa E402

logger = logging.getLogger(__name__)


RC_INIT_FAILED = 1
RC_UPGRADE_PREV_FAILED = 2
RC_UPGRADE_FAILED = 3
RC_ENABLE_FIPS_FAILED = 4


def validate_args(args):
    _log_level_map = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warning": logging.WARNING,
        "error": logging.ERROR,
        "critical": logging.CRITICAL
    }
    logging.basicConfig(
        stream=sys.stdout,
        level=_log_level_map[args.log_level],
        format="%(asctime)s %(filename)s#%(lineno)d %(levelname)s - %(message)s"
    )

    args.skip_prev_image = False
    if not args.prev_image_url:
        args.prev_image_url = "{}.PREV.1".format(args.image_url)
    logger.info("PREV_IMAGE_URL={}".format(args.prev_image_url))

    try:
        res_prev_image = requests.head(args.prev_image_url, timeout=20)
        if res_prev_image.status_code != 200:
            logger.info("Not able to get prev_image at {}, skip upgrading to prev_image.".format(args.prev_image_url))
            args.skip_prev_image = True
    except Exception as e:
        logger.info(
            "Downloading prev image {} failed with {}, skip upgrading to prev image".format(
                args.prev_image_url, repr(e)
            )
        )
        args.skip_prev_image = True


def get_pdu_managers(sonichosts, conn_graph_facts):
    """Get PDU managers for all the devices to be upgraded.

    Args:
        sonichosts (SonicHosts): Instance of class SonicHosts
        conn_graph_facts (dict): Connection graph dict.

    Returns:
        dict: A dict of PDU managers. Key is device hostname. Value is the PDU manager object for the device.
    """
    pdu_managers = {}
    for hostname in sonichosts.hostnames:
        pdu_links = conn_graph_facts["device_pdu_links"][hostname]
        pdu_hostnames = [peer_info["peerdevice"] for peer_info in pdu_links.values()]
        pdu_vars = {}
        for pdu_hostname in pdu_hostnames:
            pdu_vars[pdu_hostname] = sonichosts.get_host_visible_vars(pdu_hostname)

        pdu_managers[hostname] = pdu_manager_factory(hostname, None, conn_graph_facts, pdu_vars)
    return pdu_managers


def main(args):
    logger.info("Validating arguments")
    validate_args(args)

    logger.info("Initializing hosts")
    localhost = init_localhost(args.inventory, options={"verbosity": args.verbosity})
    sonichosts = init_testbed_sonichosts(
        args.inventory, args.testbed_name, testbed_file=args.tbfile, options={"verbosity": args.verbosity}
    )

    if not localhost or not sonichosts:
        sys.exit(RC_INIT_FAILED)

    conn_graph_facts = localhost.conn_graph_facts(
        hosts=sonichosts.hostnames,
        filepath=os.path.join(ansible_path, "files")
    )["ansible_facts"]

    if args.always_power_cycle or args.power_cycle_unreachable:
        pdu_managers = get_pdu_managers(sonichosts, conn_graph_facts)

    # Power cycle before upgrade
    if args.always_power_cycle:
        logger.info("Power cycle before upgrade")
        for hostname, pdu_manager in pdu_managers.items():
            logger.info("Turn off power outlets to {}".format(hostname))
            pdu_manager.turn_off_outlet()
        localhost.pause(seconds=30, prompt="Pause between power off/on")
        for hostname, pdu_manager in pdu_managers.items():
            logger.info("Turn on power outlets to {}".format(hostname))
            pdu_manager.turn_on_outlet()
        localhost.pause(seconds=180, prompt="Add some sleep to allow power cycled DUTs to come back")

    # Power cycle when unreachable
    elif args.power_cycle_unreachable:
        logger.info("Power cycle unreachable")
        ping_results = {}
        needs_sleep = False
        for hostname, ip in zip(sonichosts.hostnames, sonichosts.ips):
            logger.info("Ping {} @{} from localhost".format(hostname, ip))
            ping_failed = localhost.command(
                "timeout 2 ping {} -c 1".format(ip), module_ignore_errors=True
            ).get("localhost", {}).get("failed")
            if ping_failed:
                logger.info("Ping {} @{} from localhost failed. Going to power off it".format(hostname, ip))
                ping_results[hostname] = ping_failed
                pdu_managers[hostname].turn_off_outlet()
                needs_sleep = True

        if needs_sleep:
            localhost.pause(seconds=30, prompt="Pause between power off/on")

        for hostname, ping_failed in ping_results.items():
            if ping_failed:
                logger.info("Power on {}".format(hostname))
                pdu_managers[hostname].turn_on_outlet()

        if needs_sleep:
            localhost.pause(seconds=180, prompt="Add some sleep to allow power cycled DUTs to come back")

    # Upgrade to prev image
    if not args.skip_prev_image:
        logger.info("upgrade to prev image at {}".format(args.prev_image_url))
        upgrade_success = upgrade_image(
            sonichosts,
            localhost,
            args.prev_image_url,
            upgrade_type=args.upgrade_type,
            onie_pause_time=args.onie_pause_time
        )

        if not upgrade_success:
            logger.error("Upgrade prev_image {} failed".format(args.prev_image_url))
            sys.exit(RC_UPGRADE_PREV_FAILED)
        else:
            logger.info("Upgraded to prev_image {}.".format(args.prev_image_url))

        for hostname, version in sonichosts.sonic_version.items():
            logger.info("SONiC host {} current version {}".format(hostname, version.get("build_version")))

    # Upgrade to target image
    logger.info("upgrade to target image at {}".format(args.image_url))
    upgrade_success = upgrade_image(
        sonichosts,
        localhost,
        args.image_url,
        upgrade_type=args.upgrade_type,
        onie_pause_time=args.onie_pause_time
    )
    if not upgrade_success:
        logger.error("Upgrade image {} failed".format(args.image_url))
        sys.exit(RC_UPGRADE_FAILED)
    else:
        logger.info("Upgraded to image {}".format(args.prev_image_url))
    for hostname, version in sonichosts.sonic_version.items():
        logger.info("SONiC host {} current version {}".format(hostname, version.get("build_version")))

    # Enable FIPS
    if args.enable_fips:
        logger.info("Need to enable FIPS")
        try:
            sonichosts.command("sonic-installer set-fips", module_attrs={"become": True})
            sonichosts.command("shutdown -r now", module_attrs={"become": True, "async": 300, "poll": 0})
        except Exception as e:
            logger.error("Failed to enable FIPS mode: {}".repr(e))
            sys.exit(RC_ENABLE_FIPS_FAILED)

    localhost.pause(seconds=180, prompt="Pause after reboot")
    logger.info("===== UPGRADE IMAGE DONE =====")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Tool for SONiC image upgrade during nightly tests.")

    parser.add_argument(
        "-i", "--inventory",
        nargs="+",
        dest="inventory",
        help="Ansible inventory file")

    parser.add_argument(
        "-t", "--testbed-name",
        type=str,
        required=True,
        dest="testbed_name",
        help="Testbed name. DUTs of the specified testbed will be upgraded."
    )

    parser.add_argument(
        "-u", "--url",
        type=str,
        dest="image_url",
        required=True,
        help="SONiC image url."
    )

    parser.add_argument(
        "--prev-url",
        type=str,
        dest="prev_image_url",
        default=None,
        help="SONiC image url."
    )

    parser.add_argument(
        "--tbfile",
        type=str,
        dest="tbfile",
        default="testbed.yaml",
        help="Testbed definition file."
    )

    parser.add_argument(
        "--always-power-cycle",
        type=bool,
        dest="always_power_cycle",
        default=False,
        help="Always power cycle DUTs before upgrade."
    )

    parser.add_argument(
        "--power-cycle-unreachable",
        type=bool,
        dest="power_cycle_unreachable",
        default=True,
        help="Only power cycle unreachable DUTs."
    )

    parser.add_argument(
        "--onie-pause-time",
        type=int,
        dest="onie_pause_time",
        default=30,
        help="Seconds to pause after booted into onie."
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
        "--enable-fips",
        type=bool,
        dest="enable_fips",
        required=False,
        default=False,
        help="Enable FIPS."
    )

    parser.add_argument(
        "-v", "--verbosity",
        type=int,
        dest="verbosity",
        default=2,
        help="Log verbosity (0-3)."
    )

    parser.add_argument(
        "--log-level",
        type=str,
        dest="log_level",
        choices=["debug", "info", "warning", "error", "critical"],
        default="debug",
        help="Loglevel"
    )

    args = parser.parse_args()
    main(args)
