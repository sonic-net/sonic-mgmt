import json
import logging
import os
import yaml

from .ansible_hosts import AnsibleHost
from .ansible_hosts import AnsibleHosts
from .ansible_hosts import NoAnsibleHostError
from .ansible_hosts import MultipleAnsibleHostsError
from .sonic import SonicHosts

logger = logging.getLogger(__name__)

_self_dir = os.path.dirname(os.path.abspath(__file__))
ansible_path = os.path.realpath(os.path.join(_self_dir, "../../"))


def init_localhost(inventories=None, options={}, hostvars={}):
    try:
        return AnsibleHost(inventories, "localhost", options=options.copy(), hostvars=hostvars.copy())
    except (NoAnsibleHostError, MultipleAnsibleHostsError) as e:
        logger.error(
            "Failed to initialize localhost from inventories '{}', exception: {}".format(str(inventories), repr(e))
        )
        return None


def init_host(inventories, host_pattern, options={}, hostvars={}):
    try:
        return AnsibleHost(inventories, host_pattern, options=options.copy(), hostvars=hostvars.copy())
    except NoAnsibleHostError as e:
        logger.error(
            "No host '{}' in inventories '{}', exception: {}".format(host_pattern, inventories, repr(e))
        )
        return None
    except MultipleAnsibleHostsError as e:
        logger.error(
            "Multiple hosts '{}' in inventories '{}', exception: {}".format(host_pattern, inventories, repr(e))
        )
        return None


def init_hosts(inventories, host_pattern, options={}, hostvars={}):
    try:
        return AnsibleHosts(inventories, host_pattern, options=options.copy(), hostvars=hostvars.copy())
    except NoAnsibleHostError as e:
        logger.error(
            "No hosts '{}' in inventories '{}', exception: {}".format(host_pattern, inventories, repr(e))
        )
        return None


def init_sonichosts(inventories, host_pattern, options={}, hostvars={}):
    try:
        return SonicHosts(inventories, host_pattern, options=options.copy(), hostvars=hostvars.copy())
    except NoAnsibleHostError as e:
        logger.error(
            "No hosts '{}' in inventories '{}', exception: {}".format(host_pattern, inventories, repr(e))
        )
        return None


def init_testbed_sonichosts(inventories, testbed_name, testbed_file="testbed.yaml", options={}, hostvars={}):
    testbed_file_path = os.path.join(ansible_path, testbed_file)
    with open(testbed_file_path) as f:
        testbeds = yaml.safe_load(f.read())

    duts = None
    for testbed in testbeds:
        if testbed["conf-name"] == testbed_name:
            duts = testbed["dut"]   # Type is list, historic reason.
            break

    if not duts:
        logger.error("No testbed with name '{}' in testbed file {}".format(testbed_name, testbed_file_path))
        return None

    sonichosts = init_sonichosts(inventories, duts, options=options.copy(), hostvars=hostvars.copy())
    if sonichosts and sonichosts.hosts_count != len(duts):
        logger.error(
            "Unmatched testbed duts: '{}', inventory: '{}', found hostnames: '{}'".format(
                json.dumps(duts),
                inventories,
                json.dumps(sonichosts.hostnames)
            )
        )
        return None

    return sonichosts
