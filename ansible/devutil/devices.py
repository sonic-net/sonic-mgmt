import json
import logging
import os
import yaml

from ansible_hosts import AnsibleHosts, AnsibleHost
from devutil.ansible_hosts import NoAnsibleHostError, MultipleAnsibleHostsError, RunAnsibleModuleFailed

logger = logging.getLogger(__name__)

_self_dir = os.path.dirname(os.path.abspath(__file__))
ansible_path = os.path.realpath(os.path.join(_self_dir, "../"))


class SonicHosts(AnsibleHosts):
    SUPPORTED_UPGRADE_TYPES = ["onie", "sonic"]

    def __init__(self, inventories, hosts_pattern, options={}, hostvars={}):
        super(SonicHosts, self).__init__(inventories, hosts_pattern, options=options.copy(), hostvars=hostvars.copy())

    def _upgrade_by_sonic(self, image_url, disk_used_percent):
        try:
            self.reduce_and_add_sonic_images(
                disk_used_pcent=disk_used_percent,
                new_image_url=image_url,
                module_attrs={"become": True}
            )
            self.shell("reboot", module_attrs={"become": True, "async": 300, "poll": 0})
            return True
        except RunAnsibleModuleFailed as e:
            logger.error(
                "SONiC upgrade image failed, devices: {}, url: {}, error: {}".format(
                    str(self.hostnames), image_url, repr(e)
                )
            )
            return False

    def _upgrade_by_onie(self, localhost, image_url, pause_time):
        try:
            self.shell("grub-editenv /host/grub/grubenv set next_entry=ONIE", module_attrs={"become": True})
            self.shell(
                'sleep 2 && shutdown -r now "Boot into onie."',
                module_attrs={"become": True, "async": 5, "poll": 0}
            )

            for i in range(len(self.ipaddrs)):
                localhost.wait_for(
                    host=self.ipaddrs[i],
                    port=22,
                    state="started",
                    search_regex="OpenSSH",
                    delay=60 if i == 0 else 0,
                    timeout=300,
                    module_attrs={"changed_when": False}
                )
            if pause_time > 0:
                localhost.pause(
                    seconds=pause_time, prompt="Pause {} seconds for ONIE initialization".format(str(pause_time))
                )
            self.onie(
                install="yes",
                url=image_url,
                module_attrs={"connection": "onie"}
            )
            return True
        except RunAnsibleModuleFailed as e:
            logger.error(
                "ONIE upgrade image failed, devices: {}, url: {}, error: {}".format(
                    str(self.hostnames), image_url, repr(e)
                )
            )
            return False

    def _post_upgrade_actions(self, localhost, disk_used_percent):
        try:
            for i in range(len(self.ipaddrs)):
                localhost.wait_for(
                    host=self.ipaddrs[i],
                    port=22,
                    state="started",
                    search_regex="OpenSSH",
                    delay=180 if i == 0 else 0,
                    timeout=600,
                    module_attrs={"changed_when": False}
                )
            localhost.pause(seconds=60, prompt="Wait for SONiC initialization")

            # PR https://github.com/sonic-net/sonic-buildimage/pull/12109 decreased the sshd timeout
            # This change may cause timeout when executing `generate_dump -s yesterday`.
            # Increase this time after image upgrade
            self.shell(
                'sed -i "s/^ClientAliveInterval [0-9].*/ClientAliveInterval 900/g" /etc/ssh/sshd_config '
                '&& systemctl restart sshd',
                module_attrs={"become": True}
            )

            self.command("config bgp startup all", module_attrs={"become": True})
            self.command("config save -y", module_attrs={"become": True})
            self.reduce_and_add_sonic_images(
                disk_used_pcent=disk_used_percent,
                module_attrs={"become": True}
            )
            return True
        except RunAnsibleModuleFailed as e:
            logger.error(
                "Post upgrade actions failed, devices: {}, error: {}".format(str(self.hostnames), repr(e))
            )
            return False

    def upgrade_image(self, localhost, image_url, upgrade_type="sonic", disk_used_percent=50, onie_pause_time=0):
        if upgrade_type not in self.SUPPORTED_UPGRADE_TYPES:
            logger.error(
                "Upgrade type '{}' is not in SUPPORTED_UPGRADE_TYPES={}".format(
                    upgrade_type, self.SUPPORTED_UPGRADE_TYPES
                )
            )
            return False

        if upgrade_type == "sonic":
            upgrade_result = self._upgrade_by_sonic(image_url, disk_used_percent)
        elif upgrade_type == "onie":
            upgrade_result = self._upgrade_by_onie(localhost, image_url, onie_pause_time)
        if not upgrade_result:
            return False

        return self._post_upgrade_actions(localhost, disk_used_percent)

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


def init_localhost(inventory, options={}, hostvars={}):
    try:
        return AnsibleHost(inventory, "localhost", options=options.copy(), hostvars=hostvars.copy())
    except (NoAnsibleHostError, MultipleAnsibleHostsError) as e:
        logger.error(
            "Failed to initialize localhost from inventory '{}', exception: {}".format(str(inventory), repr(e))
        )
        return None


def init_hosts(inventory, hosts_pattern, options={}, hostvars={}):
    try:
        return AnsibleHosts(inventory, hosts_pattern, options=options.copy(), hostvars=hostvars.copy())
    except NoAnsibleHostError as e:
        logger.error(
            "No hosts '{}' in inventory '{}', exception: {}".format(hosts_pattern, inventory, repr(e))
        )
        return None


def init_sonichosts(inventory, hosts_pattern, options={}, hostvars={}):
    try:
        return SonicHosts(inventory, hosts_pattern, options=options.copy(), hostvars=hostvars.copy())
    except NoAnsibleHostError as e:
        logger.error(
            "No hosts '{}' in inventory '{}', exception: {}".format(hosts_pattern, inventory, repr(e))
        )
        return None


def init_testbed_sonichosts(inventory, testbed_name, testbed_file="testbed.yaml", options={}, hostvars={}):
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

    sonichosts = init_sonichosts(inventory, duts, options=options.copy(), hostvars=hostvars.copy())
    if sonichosts and sonichosts.hosts_count != len(duts):
        logger.error(
            "Unmatched testbed duts: '{}', inventory: '{}', found hostnames: '{}'".format(
                json.dumps(duts),
                inventory,
                json.dumps(sonichosts.hostnames)
            )
        )
        return None

    return sonichosts
