#!/usr/bin/env python3

import argparse
import logging
import os
import sys
import ipaddress
import traceback
from common import do_power_cycle, check_sonic_installer, posix_shell_aboot, posix_shell_onie

_self_dir = os.path.dirname(os.path.abspath(__file__))
base_path = os.path.realpath(os.path.join(_self_dir, "../.."))
if base_path not in sys.path:
    sys.path.append(base_path)
ansible_path = os.path.realpath(os.path.join(_self_dir, "../../ansible"))
if ansible_path not in sys.path:
    sys.path.append(ansible_path)

from devutil.devices.factory import init_localhost, init_testbed_sonichosts  # noqa E402
from dut_connection import duthost_ssh, duthost_console, get_ssh_info # noqa E402
from testbed_status import dut_lose_management_ip  # noqa F401

logger = logging.getLogger(__name__)

RC_INIT_FAILED = 1

"""
This script must be run under folder "sonic-mgmt/ansible"
SSH connection success: check if sonic-installer is usable, if not, do power cycle.

If console fails, do power cycle
"""


def recover_via_console(sonichost, conn_graph_facts, localhost, mgmt_ip, image_url, hwsku):
    try:
        dut_console = duthost_console(sonichost, conn_graph_facts)

        do_power_cycle(sonichost, conn_graph_facts, localhost)

        device_type = hwsku.split('-')[0].lower()

        if device_type in ["arista"]:
            posix_shell_aboot(dut_console, mgmt_ip, image_url)
        elif device_type in ["nexus"]:
            posix_shell_onie(dut_console, mgmt_ip, image_url, is_nexus=True)
        elif device_type in ["mellanox", "cisco", "acs", "celestica", "force10"]:
            is_celestica = device_type in ["celestica"]
            posix_shell_onie(dut_console, mgmt_ip, image_url, is_celestica=is_celestica)
        elif device_type in ["nokia"]:
            posix_shell_onie(dut_console, mgmt_ip, image_url, is_nokia=True)
        else:
            raise Exception("We don't support this type of testbed.")

        dut_lose_management_ip(sonichost, conn_graph_facts, localhost, mgmt_ip)
    except Exception as e:
        traceback.print_exc()
        raise Exception(e)


def recover_testbed(sonichosts, conn_graph_facts, localhost, image_url, hwsku):
    for sonichost in sonichosts:
        # Get dut ip with network mask
        mgmt_ip = conn_graph_facts["device_info"][sonichost.hostname]["ManagementIp"]

        need_to_recover = False
        for i in range(3):
            dut_ssh = duthost_ssh(sonichost)

            if type(dut_ssh) == tuple:
                logger.info("SSH success.")

                # May recover from boot loader, need to delete image file
                sonichost.shell("sudo rm -f /host/{}".format(image_url.split("/")[-1]),
                                module_ignore_errors=True)

                # Add ip info into /etc/network/interface
                extra_vars = {
                    'addr': mgmt_ip.split('/')[0],
                    'mask': ipaddress.ip_interface(mgmt_ip).with_netmask.split('/')[1],
                    'gwaddr': list(ipaddress.ip_interface(mgmt_ip).network.hosts())[0],
                    'mgmt_ip': mgmt_ip,
                    'brd_ip': ipaddress.ip_interface(mgmt_ip).network.broadcast_address,
                    'network': str(ipaddress.ip_interface(mgmt_ip).network).split('/')[0]
                }
                sonichost.vm.extra_vars.update(extra_vars)
                sonichost.template(src="../.azure-pipelines/recover_testbed/interfaces.j2",
                                   dest="/etc/network/interfaces")

                # Add management ip info into config_db.json
                sonichost.template(src="../.azure-pipelines/recover_testbed/mgmt_ip.j2",
                                   dest="/etc/sonic/mgmt_ip.json")
                sonichost.shell("configlet -u -j {}".format("/etc/sonic/mgmt_ip.json"))

                sonichost.shell("sudo config save -y")

                sonic_username = dut_ssh[0]
                sonic_password = dut_ssh[1]
                sonic_ip = dut_ssh[2]

                try:
                    check_sonic_installer(sonichost, sonic_username, sonic_password, sonic_ip, image_url)
                    break
                # TODO: specify which Exception it is
                except Exception as e:
                    logger.info("Exception caught while executing cmd. Error message: {}".format(e))
                    need_to_recover = True
            else:
                # Do power cycle
                need_to_recover = True

            if need_to_recover:
                recover_via_console(sonichost, conn_graph_facts, localhost, mgmt_ip, image_url, hwsku)


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


def main(args):
    logger.info("Validating arguments")
    validate_args(args)

    logger.info("Initializing hosts")
    localhost = init_localhost(args.inventory, options={"verbosity": args.verbosity})
    sonichosts = init_testbed_sonichosts(
        args.inventory, args.testbed_name, testbed_file=args.tbfile,
        options={"verbosity": args.verbosity, "become": "True"}
    )

    if not localhost or not sonichosts:
        sys.exit(RC_INIT_FAILED)

    conn_graph_facts = localhost.conn_graph_facts(
        hosts=sonichosts.hostnames,
        filepath=os.path.join(ansible_path, "files")
    )["ansible_facts"]

    recover_testbed(sonichosts, conn_graph_facts, localhost, args.image, args.hwsku)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Tool for getting sonic device version.")

    parser.add_argument(
        "-i", "--inventory",
        dest="inventory",
        nargs="+",
        help="Ansible inventory file")

    parser.add_argument(
        "-t", "--testbed-name",
        type=str,
        required=True,
        dest="testbed_name",
        help="Testbed name."
    )

    parser.add_argument(
        "--tbfile",
        type=str,
        dest="tbfile",
        default="testbed.yaml",
        help="Testbed definition file."
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

    parser.add_argument(
        "--image",
        type=str,
        dest="image",
        required=True,
        help="The image url"
    )

    parser.add_argument(
        "--hwsku",
        type=str,
        dest="hwsku",
        required=True,
        help="Hwsku of DUT"
    )

    args = parser.parse_args()
    main(args)
