import json
import logging
import os
import yaml

from ansible_hosts import AnsibleHosts, AnsibleHost
from devutil.ansible_hosts import NoAnsibleHostError, MultipleAnsibleHostsError

logger = logging.getLogger(__name__)

_self_dir = os.path.dirname(os.path.abspath(__file__))
ansible_path = os.path.realpath(os.path.join(_self_dir, "../"))


class SonicHosts(AnsibleHosts):
    SUPPORTED_UPGRADE_TYPES = ["onie", "sonic"]

    def __init__(self, inventories, host_pattern, options={}, hostvars={}):
        super(SonicHosts, self).__init__(inventories, host_pattern, options=options.copy(), hostvars=hostvars.copy())

    @property
    def sonic_version(self):
        try:
            output = self.command("cat /etc/sonic/sonic_version.yml")
            versions = {}
            for hostname in self.hostnames:
                versions[hostname] = yaml.safe_load(output[hostname]["stdout"])
            return versions
        except Exception as e:
            logger.error("Failed to run `cat /etc/sonic/sonic_version.yml`: {}".format(repr(e)))
            return {}


def init_localhost(inventories, options={}, hostvars={}):
    try:
        return AnsibleHost(inventories, "localhost", options=options.copy(), hostvars=hostvars.copy())
    except (NoAnsibleHostError, MultipleAnsibleHostsError) as e:
        logger.error(
            "Failed to initialize localhost from inventories '{}', exception: {}".format(str(inventories), repr(e))
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
