#!/usr/bin/python
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.multi_servers_utils import MultiServersUtils
import re
import yaml
import traceback
import ipaddress
import os

# NOTE:
# Direct usage of Ansible internal controller APIs (DataLoader, InventoryManager, etc.)
# from within custom modules is no longer supported/recommended starting Ansible 2.14.
# This module previously attempted to import and use InventoryManager to resolve
# host variables. We now always parse the provided inventory YAML file directly
# using standard YAML loading which keeps the module self‑contained and future proof.

DOCUMENTATION = '''
module: testbed_vm_info
version_added: 2.0.0.2
short_description: Gather related VM management information for a testbed topology
description:
    - When deploying a testbed topology with VMs connected to SONiC, gather neighbor VM management IPs
        and full topology information used for generating SONiC minigraph files.
    - Updated for Ansible >= 2.14 compatibility by removing direct usage of internal Ansible controller APIs.
options:
    base_vm:
        description: Base VM name defined in testbed.csv for the deployed topology.
        required: true
        type: str
    topo:
        description: Topology name defined in testbed.csv for the deployed topology.
        required: true
        type: str
    vm_file:
        description: Path to the VM inventory YAML file.
        required: false
        type: str
        default: veos
    servers_info:
        description: Optional mapping describing multi-server VM allocation. If provided, used to derive VM name
                     mapping.
        required: false
        type: dict
notes:
    - This module no longer imports ansible.parsing.dataloader or ansible.inventory.manager; inventory data is parsed
      directly via YAML.
    - The inventory file must be accessible from the target host where this module runs.
author:
    - SONiC Community
returns:
    ansible_facts:
        description: Collected facts.
        returned: always
        type: dict
        contains:
            neighbor_eosvm_mgmt:
                description: Mapping of neighbor device logical names to VM management IPs.
                type: dict
            topoall:
                description: Raw topology YAML content loaded from topology definition file.
                type: dict
'''

EXAMPLES = '''
- name: Gather VM information
    testbed_vm_info:
        base_vm: "VM0100"
        topo: "t1"
        vm_file: "veos"  # path accessible to the target host
'''

# Here are the assumption/expectation of files to gather VM information,
# if the file location or name changes, please modify it here
TOPO_PATH = 'vars/'
VM_INV_FILE = 'veos'
TGEN_MGMT_NETWORK = '10.65.32.0/24'


class TestbedVMFacts:
    """
    Retrieve testbed VMs management information that for a specified toplogy defined in testbed.yaml

    """

    def __init__(self, toponame, base_vm, vm_file, servers_info):
        CLET_SUFFIX = "-clet"
        self.toponame = re.sub(CLET_SUFFIX + "$", "", toponame)
        self.topofile = os.path.join(TOPO_PATH, f'topo_{self.toponame}.yml')
        self.base_vm = base_vm
        self.vm_file = vm_file
        self.servers_info = servers_info
        self._inventory_cache = None  # lazy‑loaded parsed inventory content

    def get_neighbor_eos(self):
        eos = {}
        with open(self.topofile) as f:
            vm_topology = yaml.safe_load(f)
        self.topoall = vm_topology

        if self.servers_info:
            return MultiServersUtils.generate_vm_name_mapping(
                self.servers_info,
                vm_topology['topology']['VMs']
            )

        if len(self.base_vm) > 2:
            vm_start_index = int(self.base_vm[2:])
            vm_name_fmt = 'VM%0{}d'.format(len(self.base_vm) - 2)
        else:
            if 'tgen' in self.toponame:
                vm_start_index = 0
                vm_name_fmt = 'VM%05d'
            else:
                return eos

        for eos_name, eos_value in vm_topology['topology']['VMs'].items():
            vm_name = vm_name_fmt % (vm_start_index + eos_value['vm_offset'])
            eos[eos_name] = vm_name
        return eos

    def get_neighbor_dpu(self):
        dpu = {}
        with open(self.topofile) as f:
            vm_topology = yaml.safe_load(f)
        self.topoall = vm_topology

        if len(self.base_vm) > 2:
            vm_start_index = int(self.base_vm[2:])
            vm_name_fmt = 'VM%0{}d'.format(len(self.base_vm) - 2)

        if 'DPUs' not in vm_topology['topology']:
            return dpu

        for dpu_name, dpu_value in vm_topology['topology']['DPUs'].items():
            vm_name = vm_name_fmt % (vm_start_index + dpu_value['vm_offset'])
            dpu[dpu_name] = vm_name

        return dpu

    def _load_inventory(self):
        if self._inventory_cache is not None:
            return self._inventory_cache
        if not os.path.exists(self.vm_file):
            raise IOError(f"Inventory file not found: {self.vm_file}")
        with open(self.vm_file, 'r') as f:
            try:
                data = yaml.safe_load(f) or {}
            except yaml.YAMLError as e:
                raise ValueError(f"Failed to parse inventory yaml {self.vm_file}: {e}")
        self._inventory_cache = data
        return data

    def gather_veos_vms(self):
        """Parse inventory YAML and return a mapping host-> {ansible_host: ip} for groups named vms_*"""
        yaml_data = self._load_inventory()
        result_dict = {}
        # inventory may have 'all' root with children pointing to group names
        # We flatten by directly scanning top-level keys for vms_* groups.
        for group_name, group_content in yaml_data.items():
            if not isinstance(group_content, dict):
                continue
            if group_name.startswith('vms_'):
                hosts_section = group_content.get('hosts', {}) or {}
                for host_name, host_info in hosts_section.items():
                    if isinstance(host_info, dict):
                        result_dict[host_name] = {'ansible_host': host_info.get('ansible_host', '')}
        return result_dict


def main():
    module = AnsibleModule(
        argument_spec=dict(
            base_vm=dict(required=True, type='str'),
            topo=dict(required=True, type='str'),
            servers_info=dict(required=False, type='dict', default={}),
            vm_file=dict(default=VM_INV_FILE, type='str')
        ),
        supports_check_mode=True
    )
    m_args = module.params
    topo_type = m_args['topo']
    if 'ptf' in topo_type:
        module.exit_json(ansible_facts={'neighbor_eosvm_mgmt': {}})

    vm_mgmt_ip = {}
    try:
        vm_facts = TestbedVMFacts(
            m_args['topo'], m_args['base_vm'], m_args['vm_file'], m_args['servers_info'])
        neighbor_eos = vm_facts.get_neighbor_eos()
        neighbor_eos.update(vm_facts.get_neighbor_dpu())
        hosts = vm_facts.gather_veos_vms()
        tgen_mgmt_ips = list(ipaddress.ip_network(TGEN_MGMT_NETWORK.encode().decode()))
        for index, eos in enumerate(neighbor_eos):
            vm_name = neighbor_eos[eos]
            if 'tgen' in topo_type:
                vm_mgmt_ip[eos] = str(tgen_mgmt_ips[index])
            elif vm_name in hosts:
                vm_mgmt_ip[eos] = hosts[vm_name]['ansible_host']
            else:
                err_msg = "Cannot find the vm {} in VM inventory file {}, please make sure you have enough VMs" \
                          "for the topology you are using."
                module.fail_json(msg=err_msg.format(vm_name, vm_facts.vm_file))
        module.exit_json(
            ansible_facts={'neighbor_eosvm_mgmt': vm_mgmt_ip, 'topoall': vm_facts.topoall})
    except (IOError, OSError):
        module.fail_json(msg='Can not find VM file {} or {}'.format(
            m_args['vm_file'], VM_INV_FILE))
    except Exception:
        module.fail_json(msg=traceback.format_exc())


if __name__ == "__main__":
    main()
