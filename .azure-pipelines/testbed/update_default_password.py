#!/usr/bin/env python3

import argparse
import csv
import hashlib
import json
import logging
import os
import sys
import yaml
import requests

from datetime import datetime

logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format="%(asctime)s %(filename)s#%(lineno)d %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)

_self_dir = os.path.dirname(os.path.abspath(__file__))
# base_path = os.path.realpath(os.path.join(_self_dir, "../.."))
# if base_path not in sys.path:
#     sys.path.append(base_path)
ANSIBLE_PATH = os.path.realpath(os.path.join(_self_dir, "../../ansible"))

if ANSIBLE_PATH not in sys.path:
    sys.path.append(ANSIBLE_PATH)

GRAPH_PATH = os.path.join(ANSIBLE_PATH, "files")


from devutil.devices.factory import init_hosts


def get_dut_testbed_mapping(testbeds):
    dut_testbed_mapping = {}
    for testbed in testbeds:
        for dut in testbed["dut"]:
            if dut not in dut_testbed_mapping:
                dut_testbed_mapping[dut] = testbed["conf-name"]
    return dut_testbed_mapping


def get_testbeds():
    """
    Get testbeds info from Elastictest management API
    """
    try:
        # Use the same API as testbed mgmt page
        url = "https://sonic-elastictest-prod-management-webapp.azurewebsites.net/api/v1/testbeds"
        access_token = os.environ.get("ACCESS_TOKEN", None)
        if not access_token:
            raise Exception("No valid access_token for getting testbeds from Elastictest")

        headers = {
            'Authorization': 'Bearer {}'.format(access_token)
        }
        response = requests.get(url, headers=headers, timeout=10).json()

        # If the response is successful, the returned content will be like:
        # { "success": True, "errmsg": "", "data": [{testbed1}, {testbed2}, ...]
        if not response['success']:
            raise Exception("Get testbed failed: {}".format(response["errmsg"]))
        return response['data']
    except Exception as e:
        logger.error('Get testbeds failed with exception: {}'.format(repr(e)))
        return []


def get_dut_devices_from_graph(group):
    graph_devices_csv = os.path.join(GRAPH_PATH, "sonic_{}_devices.csv".format(group))
    if not os.path.exists(graph_devices_csv):
        logger.error("Graph file {} does not exist".format(graph_devices_csv))
        return []
    try:
        with open(graph_devices_csv) as csvfile:
            reader = csv.DictReader(csvfile)
            rows = [row for row in reader]
        devices = [row["Hostname"] for row in rows if row["Type"] == "DevSonic"]
        return sorted(devices)
    except Exception as e:
        logger.error("Get devices from {} failed with: {}".format(graph_devices_csv, repr(e)))

    return []


def is_testbed_free(testbed, current_time):
    release_time = testbed.get("release_time", None)
    if release_time is None:
        return True
    return datetime.fromisoformat(release_time) < current_time


def get_expected_password_hash():
    """Get expected password hash from secrets.json
    """
    secrets_json_path = os.path.join(ANSIBLE_PATH, "group_vars/all/secrets.json")
    if not os.path.exists(secrets_json_path):
        raise Exception("File {} does not exist".format(secrets_json_path))

    secrets = json.loads(open(secrets_json_path).read())

    altpasswords = secrets.get("secret_group_vars", {}).get("str", {}).get("altpasswords", None)
    if altpasswords is None or not isinstance(altpasswords, list) or not altpasswords:
        raise Exception("Expected a list secret_group_vars['str']['altpasswords'] in secrets.json")

    # Always assume DUTs should use the first password in secret_group_vars['str']['altpasswords']
    expected_password = altpasswords[0]
    expected_password_hash = hashlib.sha256(expected_password.encode()).hexdigest()
    return expected_password_hash


def main(args):
    inventory = args.inventory
    testbed_file = args.testbed_file

    try:
        # Get DUT to testbed mapping
        defined_testbeds = yaml.safe_load(open(testbed_file, "r").read())
        dut_testbed_mapping = get_dut_testbed_mapping(defined_testbeds)

        # Get dut devices from devices csv. Result should be a list of DUT hostnames
        dut_devices = get_dut_devices_from_graph(os.path.basename(inventory))
        if not dut_devices:
            logger.error("No DUT devices found from {}. Unable to proceed".format(inventory))
            sys.exit(1)

        # Get all testbed from Elastictest management API
        db_testbeds = get_testbeds()
        if not db_testbeds:
            logger.error("Unable to get testbed status from Elastictest. Unable to proceed.")
            sys.exit(1)

        # The testbeds get from Elastictest management API is a list.
        # Convert it to a dict indexed by testbed name.
        # Only pick PHYSICAL testbed
        db_testbeds_dict = {
            testbed["name"]: testbed for testbed in db_testbeds if testbed["testbed_type"] == "PHYSICAL"
        }

        target_duts = []   # List of hostname of target SONiC DUTs
        locked_duts = []   # List of hostname of SONiC DUTs in locked testbed
        notb_duts = []     # List of hostname of SONiC DUTs not in any testbed

        unreachable_duts = []
        reachable_duts = []
        reachable_and_failed_duts = []
        already_updated_duts = []
        to_be_updated_duts = []
        updated_duts = []
        update_failed_duts = []

        # Find out list of devices should try updating default password
        current_time = datetime.utcnow()
        for dut in dut_devices:
            testbed_name = dut_testbed_mapping.get(dut, None)
            if not testbed_name:
                # DUT is not in any testbed, can update its default password
                notb_duts.append(dut)
                target_duts.append(dut)
                continue

            # Check if the testbed is free
            if testbed_name in db_testbeds_dict:
                if is_testbed_free(db_testbeds_dict[testbed_name], current_time):
                    target_duts.append(dut)
                else:
                    locked_duts.append(dut)
            else:
                logger.warning(f"For DUT {dut}, its testbed {testbed_name} is not tracked in DB")

        if len(target_duts) > 0:
            # Initialize AnsibleHosts object for interacting with the target duts by ansible
            target_hosts = init_hosts(
                inventory, target_duts, options={"verbosity": 3}
            )

            # Probe the target duts using "current_password" action plugin to find out hash of their current password
            results = target_hosts.command(
                "whoami",
                module_attrs={"action": "current_password", "args": {"argv": ["whoami"]}},
                module_ignore_errors=True
            )

            # Examin the probe result. Find out duts not using expected password.
            expected_password_hash = get_expected_password_hash()

            for dut_name, dut_result in results.items():
                if dut_result['reachable']:
                    reachable_duts.append(dut_name)
                    if dut_result["failed"]:
                        reachable_and_failed_duts.append(dut_name)
                    else:
                        if dut_result["current_password_hash"] == expected_password_hash:
                            already_updated_duts.append(dut_name)
                        else:
                            to_be_updated_duts.append(dut_name)
                else:
                    unreachable_duts.append(dut_name)
        else:
            logger.info("No target_duts for updating password")

        if len(to_be_updated_duts) > 0:
            # Initialize AnsibleHosts object for interacting with the duts need to update default password
            to_be_updated_hosts = init_hosts(inventory, to_be_updated_duts)

            # Update password on the duts
            results = to_be_updated_hosts.shell(
                "echo {{ ansible_ssh_user }}:{{ ansible_altpasswords[0] }} | sudo chpasswd",
                module_ignore_errors=True,
                verbosity=1
            )

            # Examin the update results
            for dut_name, dut_result in results.items():
                if dut_result["failed"]:
                    update_failed_duts.append(dut_name)
                else:
                    updated_duts.append(dut_name)
        else:
            logger.info("All target_duts are using updated password")


        logger.info("========================== DETAILS =============================")
        logger.info("duts in graph csv: {}".format(json.dumps(dut_devices, indent=2)))
        logger.info("testbeds in DB: {}".format(json.dumps(list(db_testbeds_dict.keys()), indent=2)))
        logger.info("duts in locked testbeds: {}".format(json.dumps(locked_duts, indent=2)))
        logger.info("duts not in any testbeds: {}".format(json.dumps(notb_duts, indent=2)))
        logger.info("target duts: {}".format(json.dumps(target_duts, indent=2)))
        logger.info("target duts, unreachable: {}".format(json.dumps(unreachable_duts, indent=2)))
        logger.info("target duts, reachable: {}".format(json.dumps(reachable_duts, indent=2)))
        logger.info("target duts, reachable and failed: {}".format(json.dumps(reachable_and_failed_duts, indent=2)))
        logger.info("target duts, already updated: {}".format(json.dumps(already_updated_duts, indent=2)))
        logger.info("target duts, to be updated: {}".format(json.dumps(to_be_updated_duts, indent=2)))
        logger.info("target duts, updated duts by this run: {}".format(json.dumps(updated_duts, indent=2)))
        logger.info("target duts, update failed duts by this run: {}".format(json.dumps(update_failed_duts, indent=2)))

        # Log report
        logger.info("========================== SUMMARY =============================")
        logger.info("Total DUTs defined in graph csv: {}".format(len(dut_devices)))
        logger.info("Total testbeds in DB: {}".format(len(list(db_testbeds_dict.keys()))))
        logger.info("Total DUTs in locked testbed: {}".format(len(locked_duts)))
        logger.info("Total DUTs not in any testbed: {}".format(len(notb_duts)))
        logger.info("Total target DUTs for updating password: {}".format(len(target_duts)))
        logger.info("Target DUTs, unreachable: {}".format(len(unreachable_duts)))
        logger.info("Target DUTs, reachable: {}".format(len(reachable_duts)))
        logger.info("Target DUTs, reachable and failed: {}".format(len(reachable_and_failed_duts)))
        logger.info("Target DUTs, already updated: {}".format(len(already_updated_duts)))
        logger.info("Target DUTs, to be updated: {}".format(len(to_be_updated_duts)))
        logger.info("Target DUTs, updated duts by this run: {}".format(len(updated_duts)))
        logger.info("Target DUTs, update failed duts by this run: {}".format(len(update_failed_duts)))

        sys.exit(0)

    except Exception as e:
        logger.error("Exception raised: {}".format(repr(e)))
        sys.exit(1)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Tool for updating DUT's default password.")

    parser.add_argument(
        "-i", "--inventory",
        dest="inventory",
        help="Ansible inventory file")

    parser.add_argument(
        "-t", "--testbed-file",
        dest="testbed_file",
        help="Testbed file"
    )

    args = parser.parse_args()

    main(args)
