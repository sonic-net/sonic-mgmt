import os
import pytest
from ..fanout_base import BaseFanoutHandler
from tests.common.errors import RunAnsibleModuleFail
from ansible.inventory.manager import InventoryManager
from ansible.parsing.dataloader import DataLoader

MAX_OPENFLOW_RULE_ID = 65535
RUN_ANSIBLE_PLAYBOOK = "cd {ansible_path}; ansible-playbook {playbook} -i {inventory} -l {fanout_host} --extra-vars \"{extra_vars}\" -vvvvv"
# Ansible config files
LAB_CONNECTION_GRAPH_PATH = os.path.normpath((os.path.join(os.path.dirname(__file__), "../../../../ansible/files")))
ANSIBLE_ROOT = os.path.normpath((os.path.join(__file__, "../../../../../ansible")))
# Ansible playbook which executes Jinja template
ANSIBLE_PLAYBOOK = os.path.join(os.path.dirname(__file__), "exec_template.yml")
# Jinja template which delete specific openflow rule
DEL_RULE_TEMPLATE = os.path.join(os.path.dirname(__file__), "mlnx_del_of_rule.j2")


def is_mellanox_devices(hwsku):
    """
    A helper function to check if a given sku is Mellanox device
    """
    hwsku = hwsku.lower()
    return 'mellanox' in hwsku \
        or 'msn' in hwsku \
        or 'mlnx' in hwsku

def find_inventory_file(hostname, inventory_files):
    """
    Find correct inventory file for given host
    """
    for inventory_file in inventory_files:
        dataloader = DataLoader()
        inv_mgr = InventoryManager(loader=dataloader, sources=inventory_files)
        if hostname in inv_mgr.hosts.keys():
            return inventory_file
    return None
class FanoutHandler(BaseFanoutHandler):
    def __init__(self, duthost, localhost, inventory_files):
        self.initialized = False
        self.rule_id = MAX_OPENFLOW_RULE_ID
        self.is_mellanox = False

        # Ansible localhost fixture which calls ansible playbook on the local host
        self.ansible_localhost = localhost
        try:
            dut_facts = self.ansible_localhost.conn_graph_facts(host=duthost.hostname, filepath=LAB_CONNECTION_GRAPH_PATH)["ansible_facts"]
        except RunAnsibleModuleFail as e:
            if  "cannot find info for" in e.results['msg']:
                return
            else:
                raise e

        self.fanout_host = dut_facts["device_conn"][duthost.hostname]["Ethernet0"]["peerdevice"]
        try:   
            fanout_facts = self.ansible_localhost.conn_graph_facts(host=self.fanout_host, filepath=LAB_CONNECTION_GRAPH_PATH)["ansible_facts"]
        except RunAnsibleModuleFail as e:
            if  "cannot find info for" in e.results['msg']:
                return
            else:
                raise e

        fanout_sku = fanout_facts['device_info'][self.fanout_host]['HwSku']
        if not is_mellanox_devices(fanout_sku):
            return

        self.fanout_inventory_file = find_inventory_file(self.fanout_host, inventory_files)
        if not self.fanout_inventory_file:
            return

        self.fanout_trunk_port = None
        for iface, iface_info in fanout_facts["device_port_vlans"][self.fanout_host].items():
            if iface_info["mode"] == "Trunk":
                self.fanout_trunk_port = iface[iface.find("/") + 1:]
                break
        else:
            raise Exception("Unable to identify Fanout Trunk port")
        
        self.is_mellanox = True

    def update_config(self, **kwargs):
        """
        Execute Jinja template on fanout switch which creates openflow rule.
        @kwargs: Parameters used as 'extra-vars' for 'ansible-playbook' CLI utility.
        """
        for attempt in range(100):
            kwargs["rule_id"] = self.rule_id
            kwargs["trunk_port"] = "eth{}".format(self.fanout_trunk_port)
            extra_vars = ""
            for key, value in kwargs.items():
                extra_vars += "{}={} ".format(key, value)

            add_flow = RUN_ANSIBLE_PLAYBOOK.format(ansible_path=ANSIBLE_ROOT, playbook=ANSIBLE_PLAYBOOK, inventory=self.fanout_inventory_file,
                                                        fanout_host=self.fanout_host, extra_vars=extra_vars)

            res = self.ansible_localhost.shell(add_flow)
            if res["rc"] != 0:
                raise Exception("Unable to add openflow rule\n{}".format(res["stdout"]))

            if "already exist" in res["stdout"]:
                self.rule_id = random.randint(300, 65500)
                continue
            break
        else:
            raise Exception("Unable to add openflow rule. To many rules already exist.\n{}".format(res["stdout"]))
        self.initialized = True

    def restore_config(self):
        """ Delete openflow rule to clear previous configuration """
        if self.initialized:
            del_flow = RUN_ANSIBLE_PLAYBOOK.format(ansible_path=ANSIBLE_ROOT, playbook=ANSIBLE_PLAYBOOK, inventory=self.fanout_inventory_file,
                                                        fanout_host=self.fanout_host,
                                                        extra_vars="rule_id={} template_path={}".format(self.rule_id,
                                                                                                DEL_RULE_TEMPLATE))
            res = self.ansible_localhost.shell(del_flow)
            if res["rc"] != 0:
                raise Exception("Unable to delete openflow rule\n{}".format(res["stdout"]))
        self.initialized = False
