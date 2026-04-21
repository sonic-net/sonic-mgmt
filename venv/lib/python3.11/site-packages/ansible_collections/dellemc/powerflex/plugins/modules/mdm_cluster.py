#!/usr/bin/python

# Copyright: (c) 2022, Dell Technologies
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

""" Ansible module for managing MDM Cluster on PowerFlex"""

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r'''
module: mdm_cluster
version_added: '1.3.0'
short_description: Manage MDM cluster on Dell PowerFlex
description:
- Managing MDM cluster and MDMs on PowerFlex storage system includes
  adding/removing standby MDM, modify MDM name and virtual interface.
- It also includes getting details of MDM cluster, modify MDM cluster
  ownership, cluster mode, and performance profile.
author:
- Bhavneet Sharma (@sharmb5) <ansible.team@dell.com>
extends_documentation_fragment:
  - dellemc.powerflex.powerflex
options:
  mdm_name:
    description:
    - The name of the MDM. It is unique across the PowerFlex array.
    - Mutually exclusive with I(mdm_id).
    - If mdm_name passed in add standby operation, then same name will be
      assigned to the new standby mdm.
    type: str
  mdm_id:
    description:
    - The ID of the MDM.
    - Mutually exclusive with I(mdm_name).
    type: str
  mdm_new_name:
    description:
    - To rename the MDM.
    type: str
  standby_mdm:
    description:
    - Specifies add standby MDM parameters.
    type: dict
    suboptions:
      mdm_ips:
        description:
        - List of MDM IPs that will be assigned to new MDM. It can contain
          IPv4 addresses.
        required: true
        type: list
        elements: str
      role:
        description:
        - Role of new MDM.
        required: true
        choices: ['Manager', 'TieBreaker']
        type: str
      management_ips:
        description:
        - List of management IPs to manage MDM. It can contain IPv4
          addresses.
        type: list
        elements: str
      port:
        description:
        - Specifies the port of new MDM.
        type: int
      allow_multiple_ips:
        description:
        - Allow the added node to have different number of IPs from the
          primary node.
        type: bool
      virtual_interfaces:
        description:
        - List of NIC interfaces that will be used for virtual IP addresses.
        type: list
        elements: str
  is_primary:
    description:
    - Set I(is_primary) as C(true) to change MDM cluster ownership from the current
      master MDM to different MDM.
    - Set I(is_primary) as C(false), will return MDM cluster details.
    - New owner MDM must be an MDM with a manager role.
    type: bool
  cluster_mode:
    description:
    - Mode of the cluster.
    choices: ['OneNode', 'ThreeNodes', 'FiveNodes']
    type: str
  mdm:
    description:
    - Specifies parameters to add/remove MDMs to/from the MDM cluster.
    type: list
    elements: dict
    suboptions:
      mdm_id:
        description:
        - ID of MDM that will be added/removed to/from the cluster.
        type: str
      mdm_name:
        description:
        - Name of MDM that will be added/removed to/from the cluster.
        type: str
      mdm_type:
        description:
        - Type of the MDM.
        - Either I(mdm_id) or I(mdm_name) must be passed with mdm_type.
        required: true
        choices: ['Secondary', 'TieBreaker']
        type: str
  mdm_state:
    description:
    - Mapping state of MDM.
    choices: ['present-in-cluster', 'absent-in-cluster']
    type: str
  virtual_ip_interfaces:
    description:
    - List of interfaces to be used for virtual IPs.
    - The order of interfaces must be matched with virtual IPs assigned to the
      cluster.
    - Interfaces of the primary and secondary type MDMs are allowed to modify.
    - The I(virtual_ip_interfaces) is mutually exclusive with I(clear_interfaces).
    type: list
    elements: str
  clear_interfaces:
    description:
    - Clear all virtual IP interfaces.
    - The I(clear_interfaces) is mutually exclusive with I(virtual_ip_interfaces).
    type: bool
  performance_profile:
    description:
    - Apply performance profile to cluster MDMs.
    choices: ['Compact', 'HighPerformance']
    type: str
  state:
    description:
    - State of the MDM cluster.
    choices: ['present', 'absent']
    required: true
    type: str
notes:
  - Parameters I(mdm_name) or I(mdm_id) are mandatory for rename and modify virtual IP
    interfaces.
  - Parameters I(mdm_name) or I(mdm_id) are not required while modifying performance
    profile.
  - For change MDM cluster ownership operation, only changed as true will be
    returned and for idempotency case MDM cluster details will be returned.
  - Reinstall all SDC after changing ownership to some newly added MDM.
  - To add manager standby MDM, MDM package must be installed with manager
    role.
  - The I(check_mode) is supported.
'''

EXAMPLES = r'''
- name: Add a standby MDM
  dellemc.powerflex.mdm_cluster:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    mdm_name: "mdm_1"
    standby_mdm:
      mdm_ips:
        - "10.x.x.x"
      role: "TieBreaker"
      management_ips:
        - "10.x.y.z"
    state: "present"

- name: Remove a standby MDM
  dellemc.powerflex.mdm_cluster:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    mdm_name: "mdm_1"
    state: "absent"

- name: Switch cluster mode from 3 node to 5 node MDM cluster
  dellemc.powerflex.mdm_cluster:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    cluster_mode: "FiveNodes"
    mdm:
      - mdm_id: "5f091a8a013f1100"
        mdm_type: "Secondary"
      - mdm_name: "mdm_1"
        mdm_type: "TieBreaker"
    sdc_state: "present-in-cluster"
    state: "present"

- name: Switch cluster mode from 5 node to 3 node MDM cluster
  dellemc.powerflex.mdm_cluster:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    cluster_mode: "ThreeNodes"
    mdm:
      - mdm_id: "5f091a8a013f1100"
        mdm_type: "Secondary"
      - mdm_name: "mdm_1"
        mdm_type: "TieBreaker"
    sdc_state: "absent-in-cluster"
    state: "present"

- name: Get the details of the MDM cluster
  dellemc.powerflex.mdm_cluster:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    state: "present"

- name: Change ownership of MDM cluster
  dellemc.powerflex.mdm_cluster:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    mdm_name: "mdm_2"
    is_primary: true
    state: "present"

- name: Modify performance profile
  dellemc.powerflex.mdm_cluster:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    performance_profile: "HighPerformance"
    state: "present"

- name: Rename the MDM
  dellemc.powerflex.mdm_cluster:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    mdm_name: "mdm_1"
    mdm_new_name: "new_mdm_1"
    state: "present"

- name: Modify virtual IP interface of the MDM
  dellemc.powerflex.mdm_cluster:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    mdm_name: "mdm_1"
    virtual_ip_interface:
      - "ens224"
    state: "present"

- name: Clear virtual IP interface of the MDM
  dellemc.powerflex.mdm_cluster:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    mdm_name: "mdm_1"
    clear_interfaces: true
    state: "present"
'''

RETURN = r'''
changed:
    description: Whether or not the resource has changed.
    returned: always
    type: bool
    sample: 'false'
mdm_cluster_details:
    description: Details of the MDM cluster.
    returned: When MDM cluster exists
    type: dict
    contains:
        id:
            description: The ID of the MDM cluster.
            type: str
        name:
            description: Name of MDM cluster.
            type: str
        clusterMode:
            description: Mode of the MDM cluster.
            type: str
        master:
            description: The details of the master MDM.
            type: dict
            contains:
                id:
                    description: ID of the MDM.
                    type: str
                name:
                    description: Name of the MDM.
                    type: str
                port:
                    description: Port of the MDM.
                    type: str
                ips:
                    description: List of IPs for master MDM.
                    type: list
                managementIPs:
                    description: List of management IPs for master MDM.
                    type: list
                role:
                    description: Role of MDM.
                    type: str
                status:
                    description: Status of MDM.
                    type: str
                versionInfo:
                    description: Version of MDM.
                    type: str
                virtualInterfaces:
                    description: List of virtual interfaces
                    type: list
                opensslVersion:
                    description: OpenSSL version.
                    type: str
        slaves:
            description: The list of the secondary MDMs.
            type: list
            elements: dict
            contains:
                id:
                    description: ID of the MDM.
                    type: str
                name:
                    description: Name of the MDM.
                    type: str
                port:
                    description: Port of the MDM.
                    type: str
                ips:
                    description: List of IPs for secondary MDM.
                    type: list
                managementIPs:
                    description: List of management IPs for secondary MDM.
                    type: list
                role:
                    description: Role of MDM.
                    type: str
                status:
                    description: Status of MDM.
                    type: str
                versionInfo:
                    description: Version of MDM.
                    type: str
                virtualInterfaces:
                    description: List of virtual interfaces
                    type: list
                opensslVersion:
                    description: OpenSSL version.
                    type: str
        tieBreakers:
            description: The list of the TieBreaker MDMs.
            type: list
            elements: dict
            contains:
                id:
                    description: ID of the MDM.
                    type: str
                name:
                    description: Name of the MDM.
                    type: str
                port:
                    description: Port of the MDM.
                    type: str
                ips:
                    description: List of IPs for tie-breaker MDM.
                    type: list
                managementIPs:
                    description: List of management IPs for tie-breaker MDM.
                    type: list
                role:
                    description: Role of MDM.
                    type: str
                status:
                    description: Status of MDM.
                    type: str
                versionInfo:
                    description: Version of MDM.
                    type: str
                opensslVersion:
                    description: OpenSSL version.
                    type: str
        standbyMDMs:
            description: The list of the standby MDMs.
            type: list
            elements: dict
            contains:
                id:
                    description: ID of the MDM.
                    type: str
                name:
                    description: Name of the MDM.
                    type: str
                port:
                    description: Port of the MDM.
                    type: str
                ips:
                    description: List of IPs for MDM.
                    type: list
                managementIPs:
                    description: List of management IPs for MDM.
                    type: list
                role:
                    description: Role of MDM.
                    type: str
                status:
                    description: Status of MDM.
                    type: str
                versionInfo:
                    description: Version of MDM.
                    type: str
                virtualInterfaces:
                    description: List of virtual interfaces.
                    type: list
                opensslVersion:
                    description: OpenSSL version.
                    type: str
        clusterState:
            description: State of the MDM cluster.
            type: str
        goodNodesNum:
            description: Number of Nodes in MDM cluster.
            type: int
        goodReplicasNum:
            description: Number of nodes for Replication.
            type: int
        virtualIps:
            description: List of virtual IPs.
            type: list
    sample: {
        "clusterState": "ClusteredNormal",
        "clusterMode": "ThreeNodes",
        "goodNodesNum": 3,
        "master": {
            "virtualInterfaces": [
                "ens1"
            ],
            "managementIPs": [
                "10.x.y.z"
            ],
            "ips": [
                "10.x.y.z"
            ],
            "versionInfo": "R3_6.0.0",
            "opensslVersion": "OpenSSL 1.0.2k-fips  26 Jan 2017",
            "role": "Manager",
            "status": "Normal",
            "name": "sample_mdm",
            "id": "5908d328581d1400",
            "port": 9011
        },
        "perfProfile": "HighPerformance",
        "slaves": [
            {
                "virtualInterfaces": [
                    "ens1"
                ],
                "managementIPs": [
                    "10.x.x.z"
                ],
                "ips": [
                    "10.x.x.z"
                ],
                "versionInfo": "R3_6.0.0",
                "opensslVersion": "OpenSSL 1.0.2k-fips  26 Jan 2017",
                "role": "Manager",
                "status": "Normal",
                "name": "sample_mdm1",
                "id": "5908d328581d1401",
                "port": 9011
            }
        ],
        "tieBreakers": [
            {
                "virtualInterfaces": [],
                "managementIPs": [],
                "ips": [
                    "10.x.y.y"
                ],
                "versionInfo": "R3_6.0.0",
                "opensslVersion": "N/A",
                "role": "TieBreaker",
                "status": "Normal",
                "id": "5908d328581d1402",
                "port": 9011
            }
        ],
        "standbyMDMs": [
            {
                "virtualInterfaces": [],
                "managementIPs": [
                    "10.x.z.z"
                ],
                "ips": [
                    "10.x.z.z"
                ],
                "versionInfo": "R3_6.0.0",
                "opensslVersion": "N/A",
                "role": "TieBreaker",
                "status": "Normal",
                "id": "5908d328581d1403",
                "port": 9011
            }
        ],
        "goodReplicasNum": 2,
        "id": "cdd883cf00000002"
    }
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.powerflex.plugins.module_utils.storage.dell \
    import utils
import copy

LOG = utils.get_logger('mdm_cluster')


class PowerFlexMdmCluster(object):
    """Class with MDM cluster operations"""

    def __init__(self):
        """ Define all parameters required by this module"""
        self.module_params = utils.get_powerflex_gateway_host_parameters()
        self.module_params.update(get_powerflex_mdm_cluster_parameters())

        mut_ex_args = [['mdm_name', 'mdm_id'],
                       ['virtual_ip_interfaces', 'clear_interfaces']]

        required_together_args = [['cluster_mode', 'mdm', 'mdm_state']]

        # initialize the Ansible module
        self.module = AnsibleModule(
            argument_spec=self.module_params,
            supports_check_mode=True,
            mutually_exclusive=mut_ex_args,
            required_together=required_together_args)

        utils.ensure_required_libs(self.module)

        self.not_exist_msg = "MDM {0} does not exists in MDM cluster."
        self.exist_msg = "MDM already exists in the MDM cluster"
        try:
            self.powerflex_conn = utils.get_powerflex_gateway_host_connection(
                self.module.params)
            LOG.info("Got the PowerFlex system connection object instance")
            LOG.info('Check Mode Flag %s', self.module.check_mode)
        except Exception as e:
            LOG.error(str(e))
            self.module.fail_json(msg=str(e))

    def set_mdm_virtual_interface(self, mdm_id=None, mdm_name=None,
                                  virtual_ip_interfaces=None,
                                  clear_interfaces=None,
                                  mdm_cluster_details=None):
        """Modify the MDM virtual IP interface.
        :param mdm_id: ID of MDM
        :param mdm_name: Name of MDM
        :param virtual_ip_interfaces: List of virtual IP interfaces
        :param clear_interfaces: clear virtual IP interfaces of MDM.
        :param mdm_cluster_details: Details of MDM cluster
        :return: True if modification of virtual interface or clear operation
                 successful
        """

        name_or_id = mdm_id if mdm_id else mdm_name
        if mdm_name is None and mdm_id is None:
            err_msg = "Please provide mdm_name/mdm_id to modify virtual IP" \
                      " interfaces the MDM."
            LOG.error(err_msg)
            self.module.fail_json(msg=err_msg)
        mdm_details = self.\
            is_mdm_name_id_exists(mdm_name=mdm_name, mdm_id=mdm_id,
                                  cluster_details=mdm_cluster_details)
        if mdm_details is None:
            err_msg = self.not_exist_msg.format(name_or_id)
            self.module.fail_json(msg=err_msg)

        mdm_id = mdm_details['id']
        modify_list = []
        modify_list, clear = is_modify_mdm_virtual_interface(
            virtual_ip_interfaces, clear_interfaces, mdm_details)

        if modify_list is None and not clear:
            LOG.info("No change required in MDM virtual IP interfaces.")
            return False

        try:
            log_msg = "Modifying MDM virtual interfaces to %s " \
                      "or %s" % (str(modify_list), clear)
            LOG.debug(log_msg)
            if not self.module.check_mode:
                self.powerflex_conn.system.modify_virtual_ip_interface(
                    mdm_id=mdm_id, virtual_ip_interfaces=modify_list,
                    clear_interfaces=clear)
            return True
        except Exception as e:
            error_msg = "Failed to modify the virtual IP interfaces of MDM " \
                        "{0} with error {1}".format(name_or_id, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def set_performance_profile(self, performance_profile=None,
                                cluster_details=None):
        """ Set the performance profile of Cluster MDMs
        :param performance_profile: Specifies the performance profile of MDMs
        :param cluster_details: Details of MDM cluster
        :return: True if updated successfully
        """

        if self.module.params['state'] == 'present' and performance_profile:
            if cluster_details['perfProfile'] != performance_profile:
                try:
                    if not self.module.check_mode:
                        self.powerflex_conn.system.\
                            set_cluster_mdm_performance_profile(performance_profile=performance_profile)
                    return True
                except Exception as e:
                    error_msg = "Failed to update performance profile to {0} " \
                                "with error {1}.".format(performance_profile,
                                                         str(e))
                    LOG.error(error_msg)
                    self.module.fail_json(msg=error_msg)
            return False
        return False

    def rename_mdm(self, mdm_name=None, mdm_id=None, mdm_new_name=None,
                   cluster_details=None):
        """Rename the MDM
        :param mdm_name: Name of the MDM.
        :param mdm_id: ID of the MDM.
        :param mdm_new_name: New name of the MDM.
        :param cluster_details: Details of the MDM cluster.
        :return: True if successfully renamed.
        """

        name_or_id = mdm_id if mdm_id else mdm_name
        if mdm_name is None and mdm_id is None:
            err_msg = "Please provide mdm_name/mdm_id to rename the MDM."
            self.module.fail_json(msg=err_msg)
        mdm_details = self.\
            is_mdm_name_id_exists(mdm_name=mdm_name, mdm_id=mdm_id,
                                  cluster_details=cluster_details)
        if mdm_details is None:
            err_msg = self.not_exist_msg.format(name_or_id)
            self.module.fail_json(msg=err_msg)

        mdm_id = mdm_details['id']
        try:
            if ('name' in mdm_details and
                mdm_new_name != mdm_details['name']) or \
                    'name' not in mdm_details:
                log_msg = "Modifying the MDM name from %s to " \
                          "%s." % (mdm_name, mdm_new_name)
                LOG.info(log_msg)
                if not self.module.check_mode:
                    self.powerflex_conn.system.rename_mdm(
                        mdm_id=mdm_id, mdm_new_name=mdm_new_name)
                return True
        except Exception as e:
            error_msg = "Failed to rename the MDM {0} with error {1}.".\
                format(name_or_id, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def is_none_name_id_in_switch_cluster_mode(self, mdm):
        """ Check whether mdm dict have mdm_name and mdm_id or not"""

        for node in mdm:
            if node['mdm_id'] and node['mdm_name']:
                msg = "parameters are mutually exclusive: mdm_name|mdm_id"
                self.module.fail_json(msg=msg)

    def change_cluster_mode(self, cluster_mode, mdm, cluster_details):
        """change the MDM cluster mode.
        :param cluster_mode: specifies the mode of MDM cluster
        :param mdm: A dict containing parameters to change MDM cluster mode
        :param cluster_details: Details of MDM cluster
        :return: True if mode changed successfully
        """

        self.is_none_name_id_in_switch_cluster_mode(mdm=mdm)

        if cluster_mode == cluster_details['clusterMode']:
            LOG.info("MDM cluster is already in required mode.")
            return False

        add_secondary = []
        add_tb = []
        remove_secondary = []
        remove_tb = []
        if self.module.params['state'] == 'present' and \
                self.module.params['mdm_state'] == 'present-in-cluster':
            add_secondary, add_tb = self.cluster_expand_list(mdm, cluster_details)
        elif self.module.params['state'] == 'present' and \
                self.module.params['mdm_state'] == 'absent-in-cluster':
            remove_secondary, remove_tb = self.\
                cluster_reduce_list(mdm, cluster_details)
        try:
            if not self.module.check_mode:
                self.powerflex_conn.system.switch_cluster_mode(
                    cluster_mode=cluster_mode, add_secondary=add_secondary,
                    remove_secondary=remove_secondary, add_tb=add_tb,
                    remove_tb=remove_tb)
            return True
        except Exception as e:
            err_msg = "Failed to change the MDM cluster mode with error " \
                      "{0}".format(str(e))
            LOG.error(err_msg)
            self.module.fail_json(msg=err_msg)

    def gather_secondarys_ids(self, mdm, cluster_details):
        """ Prepare a list of secondary MDMs for switch cluster mode
            operation"""

        secondarys = []

        for node in mdm:
            name_or_id = node['mdm_name'] if node['mdm_name'] else \
                node['mdm_id']

            if node['mdm_type'] == 'Secondary' and node['mdm_id'] is not None:
                mdm_details = self. \
                    is_mdm_name_id_exists(mdm_id=node['mdm_id'],
                                          cluster_details=cluster_details)
                if mdm_details is None:
                    err_msg = self.not_exist_msg.format(name_or_id)
                    self.module.fail_json(msg=err_msg)
                secondarys.append(node['mdm_id'])

            elif node['mdm_type'] == 'Secondary' and node['mdm_name'] is not None:
                mdm_details = self. \
                    is_mdm_name_id_exists(mdm_name=node['mdm_name'],
                                          cluster_details=cluster_details)
                if mdm_details is None:
                    err_msg = self.not_exist_msg.format(name_or_id)
                    self.module.fail_json(msg=err_msg)
                else:
                    secondarys.append(mdm_details['id'])
        return secondarys

    def cluster_expand_list(self, mdm, cluster_details):
        """Whether MDM cluster expansion is required or not.
        """
        add_secondary = []
        add_tb = []

        if 'standbyMDMs' not in cluster_details:
            err_msg = "No Standby MDMs found. To expand cluster size, " \
                      "first add standby MDMs."
            LOG.error(err_msg)
            self.module.fail_json(msg=err_msg)

        add_secondary = self.gather_secondarys_ids(mdm, cluster_details)
        for node in mdm:
            name_or_id = node['mdm_name'] if node['mdm_name'] else \
                node['mdm_id']

            if node['mdm_type'] == 'TieBreaker' and \
                    node['mdm_id'] is not None:
                add_tb.append(node['mdm_id'])

            elif node['mdm_type'] == 'TieBreaker' and \
                    node['mdm_name'] is not None:
                mdm_details = self. \
                    is_mdm_name_id_exists(mdm_name=node['mdm_name'],
                                          cluster_details=cluster_details)

                if mdm_details is None:
                    err_msg = self.not_exist_msg.format(name_or_id)
                    self.module.fail_json(msg=err_msg)
                else:
                    add_tb.append(mdm_details['id'])

        log_msg = "expand List are: %s, %s" % (add_secondary, add_tb)
        LOG.debug(log_msg)
        return add_secondary, add_tb

    def cluster_reduce_list(self, mdm, cluster_details):
        """Whether MDM cluster reduction is required or not.
        """
        remove_secondary = []
        remove_tb = []

        remove_secondary = self.gather_secondarys_ids(mdm, cluster_details)
        for node in mdm:
            name_or_id = node['mdm_name'] if node['mdm_name'] else \
                node['mdm_id']

            if node['mdm_type'] == 'TieBreaker' and \
                    node['mdm_id'] is not None:
                mdm_details = self. \
                    is_mdm_name_id_exists(mdm_id=node['mdm_id'],
                                          cluster_details=cluster_details)

                if mdm_details is not None and mdm_details.get('id'):
                    remove_tb.append(mdm_details.get('id'))
                else:
                    err_msg = self.not_exist_msg.format(name_or_id)
                    self.module.fail_json(msg=err_msg)

            elif node['mdm_type'] == 'TieBreaker' and \
                    node['mdm_name'] is not None:
                mdm_details = self.\
                    is_mdm_name_id_exists(mdm_name=node['mdm_name'],
                                          cluster_details=cluster_details)
                if mdm_details is None:
                    err_msg = self.not_exist_msg.format(name_or_id)
                    self.module.fail_json(msg=err_msg)
                else:
                    remove_tb.append(mdm_details['id'])

        log_msg = "Reduce List are: %s, %s." % (remove_secondary, remove_tb)
        LOG.debug(log_msg)
        return remove_secondary, remove_tb

    def perform_add_standby(self, mdm_name, standby_payload):
        """ Perform SDK call to add a standby MDM

        :param mdm_name: Name of new standby MDM
        :param standby_payload: Parameters dict to add a standby MDM
        :return: True if standby MDM added successfully
        """
        try:
            if not self.module.check_mode:
                self.powerflex_conn.system.add_standby_mdm(
                    mdm_ips=standby_payload['mdm_ips'],
                    role=standby_payload['role'],
                    management_ips=standby_payload['management_ips'],
                    mdm_name=mdm_name, port=standby_payload['port'],
                    allow_multiple_ips=standby_payload['allow_multiple_ips'],
                    virtual_interface=standby_payload['virtual_interfaces'])
            return True
        except Exception as e:
            err_msg = "Failed to Add a standby MDM with error {0}.".format(
                str(e))
            LOG.error(err_msg)
            self.module.fail_json(msg=err_msg)

    def is_id_new_name_in_add_mdm(self):
        """ Check whether mdm_id or mdm_new_name present in Add standby MDM"""

        if self.module.params['mdm_id'] or self.module.params['mdm_new_name']:
            err_msg = "Parameters mdm_id/mdm_new_name are not allowed while" \
                      " adding a standby MDM. Please try with valid " \
                      "parameters to add a standby MDM."
            LOG.error(err_msg)
            self.module.fail_json(msg=err_msg)

    def add_standby_mdm(self, mdm_name, standby_mdm, cluster_details):
        """ Adding a standby MDM"""

        if self.module.params['state'] == 'present' and \
                standby_mdm is not None and \
                (self.check_mdm_exists(standby_mdm['mdm_ips'],
                                       cluster_details)):
            self.is_id_new_name_in_add_mdm()
            mdm_details = self.\
                is_mdm_name_id_exists(mdm_name=mdm_name,
                                      cluster_details=cluster_details)
            if mdm_details:
                LOG.info("Standby MDM %s exits in the system", mdm_name)
                return False, cluster_details

            standby_payload = prepare_standby_payload(standby_mdm)
            standby_add = self.perform_add_standby(mdm_name, standby_payload)

            if standby_add:
                cluster_details = self.get_mdm_cluster_details()
                msg = "Fetched the MDM cluster details {0} after adding a " \
                      "standby MDM".format(str(cluster_details))
                LOG.info(msg)
                return True, cluster_details
        return False, cluster_details

    def remove_standby_mdm(self, mdm_name, mdm_id, cluster_details):
        """ Remove the Standby MDM
        :param mdm_id: ID of MDM that will become owner of MDM cluster
        :param mdm_name: Name of MDM that will become owner of MDM cluster
        :param cluster_details: Details of MDM cluster
        :return: True if MDM removed successful
        """

        name_or_id = mdm_id if mdm_id else mdm_name
        if mdm_id is None and mdm_name is None:
            err_msg = "Either mdm_name or mdm_id is required while removing" \
                      " the standby MDM."
            LOG.error(err_msg)
            self.module.fail_json(msg=err_msg)
        mdm_details = self. \
            is_mdm_name_id_exists(mdm_name=mdm_name, mdm_id=mdm_id,
                                  cluster_details=cluster_details)
        if mdm_details is None:
            LOG.info("MDM %s not exists in MDM cluster.", name_or_id)
            return False
        mdm_id = mdm_details['id']

        try:
            if not self.module.check_mode:
                self.powerflex_conn.system.remove_standby_mdm(mdm_id=mdm_id)
            return True
        except Exception as e:
            error_msg = "Failed to remove the standby MDM {0} from the MDM " \
                        "cluster with error {1}".format(name_or_id, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def change_ownership(self, mdm_id=None, mdm_name=None,
                         cluster_details=None):
        """ Change the ownership of MDM cluster.
        :param mdm_id: ID of MDM that will become owner of MDM cluster
        :param mdm_name: Name of MDM that will become owner of MDM cluster
        :param cluster_details: Details of MDM cluster
        :return: True if Owner of MDM cluster change successful
        """

        name_or_id = mdm_id if mdm_id else mdm_name
        if mdm_id is None and mdm_name is None:
            err_msg = "Either mdm_name or mdm_id is required while changing" \
                      " ownership of MDM cluster."
            LOG.error(err_msg)
            self.module.fail_json(msg=err_msg)

        mdm_details = self.\
            is_mdm_name_id_exists(mdm_name=mdm_name, mdm_id=mdm_id,
                                  cluster_details=cluster_details)
        if mdm_details is None:
            err_msg = self.not_exist_msg.format(name_or_id)
            self.module.fail_json(msg=err_msg)

        mdm_id = mdm_details['id']

        if mdm_details['id'] == cluster_details['master']['id']:
            LOG.info("MDM %s is already Owner of MDM cluster.", name_or_id)
            return False
        else:
            try:
                if not self.module.check_mode:
                    self.powerflex_conn.system.\
                        change_mdm_ownership(mdm_id=mdm_id)
                return True
            except Exception as e:
                error_msg = "Failed to update the Owner of MDM cluster to " \
                            "MDM {0} with error {1}".format(name_or_id,
                                                            str(e))
                LOG.error(error_msg)
                self.module.fail_json(msg=error_msg)

    def find_mdm_in_secondarys(self, mdm_name=None, mdm_id=None,
                               cluster_details=None, name_or_id=None):
        """Whether MDM exists with mdm_name or id in secondary MDMs"""

        if 'slaves' in cluster_details:
            for mdm in cluster_details['slaves']:
                if ('name' in mdm and mdm_name == mdm['name']) or \
                        mdm_id == mdm['id']:
                    LOG.info("MDM %s found in Secondarys MDM.", name_or_id)
                    return mdm

    def find_mdm_in_tb(self, mdm_name=None, mdm_id=None,
                       cluster_details=None, name_or_id=None):
        """Whether MDM exists with mdm_name or id in tie-breaker MDMs"""

        if 'tieBreakers' in cluster_details:
            for mdm in cluster_details['tieBreakers']:
                if ('name' in mdm and mdm_name == mdm['name']) or \
                        mdm_id == mdm['id']:
                    LOG.info("MDM %s found in tieBreakers MDM.", name_or_id)
                    return mdm

    def find_mdm_in_standby(self, mdm_name=None, mdm_id=None,
                            cluster_details=None, name_or_id=None):
        """Whether MDM exists with mdm_name or id in standby MDMs"""

        if 'standbyMDMs' in cluster_details:
            for mdm in cluster_details['standbyMDMs']:
                if ('name' in mdm and mdm_name == mdm['name']) or \
                        mdm_id == mdm['id']:
                    LOG.info("MDM %s found in standby MDM.", name_or_id)
                    return mdm

    def is_mdm_name_id_exists(self, mdm_id=None, mdm_name=None,
                              cluster_details=None):
        """Whether MDM exists with mdm_name or id """

        name_or_id = mdm_id if mdm_id else mdm_name
        # check in master MDM
        if ('name' in cluster_details['master'] and mdm_name == cluster_details['master']['name']) \
                or mdm_id == cluster_details['master']['id']:
            LOG.info("MDM %s is master MDM.", name_or_id)
            return cluster_details['master']

        # check in secondary MDMs
        secondary_mdm = []
        secondary_mdm = self.\
            find_mdm_in_secondarys(mdm_name=mdm_name, mdm_id=mdm_id,
                                   cluster_details=cluster_details,
                                   name_or_id=name_or_id)
        if secondary_mdm is not None:
            return secondary_mdm

        # check in tie-breaker MDMs
        tb_mdm = []
        tb_mdm = self.find_mdm_in_tb(mdm_name=mdm_name, mdm_id=mdm_id,
                                     cluster_details=cluster_details,
                                     name_or_id=name_or_id)
        if tb_mdm is not None:
            return tb_mdm

        # check in standby MDMs
        standby_mdm = self.find_mdm_in_standby(mdm_name=mdm_name,
                                               mdm_id=mdm_id,
                                               cluster_details=cluster_details,
                                               name_or_id=name_or_id)
        if standby_mdm is not None:
            return standby_mdm

        LOG.info("MDM %s does not exists in MDM Cluster.", name_or_id)
        return None

    def get_mdm_cluster_details(self):
        """Get MDM cluster details
        :return: Details of MDM Cluster if existed.
        """

        try:
            mdm_cluster_details = self.powerflex_conn.system.\
                get_mdm_cluster_details()

            if len(mdm_cluster_details) == 0:
                msg = "MDM cluster not found"
                LOG.error(msg)
                self.module.fail_json(msg=msg)

            # Append Performance profile
            resp = self.get_system_details()
            if resp is not None:
                mdm_cluster_details['perfProfile'] = resp['perfProfile']

            # Append list of configured MDM IP addresses
            gateway_configuration_details = self.powerflex_conn.system.\
                get_gateway_configuration_details()
            if gateway_configuration_details is not None:
                mdm_cluster_details['mdmAddresses'] = gateway_configuration_details['mdmAddresses']

            return mdm_cluster_details

        except Exception as e:
            error_msg = "Failed to get the MDM cluster with error {0}."
            error_msg = error_msg.format(str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def check_ip_in_secondarys(self, standby_ip, cluster_details):
        """whether standby IPs present in secondary MDMs"""

        if 'slaves' in cluster_details:
            for secondary_mdm in cluster_details['slaves']:
                current_secondary_ips = secondary_mdm['ips']
                for ips in standby_ip:
                    if ips in current_secondary_ips:
                        LOG.info(self.exist_msg)
                        return False
        return True

    def check_ip_in_tbs(self, standby_ip, cluster_details):
        """whether standby IPs present in tie-breaker MDMs"""

        if 'tieBreakers' in cluster_details:
            for tb_mdm in cluster_details['tieBreakers']:
                current_tb_ips = tb_mdm['ips']
                for ips in standby_ip:
                    if ips in current_tb_ips:
                        LOG.info(self.exist_msg)
                        return False
        return True

    def check_ip_in_standby(self, standby_ip, cluster_details):
        """whether standby IPs present in standby MDMs"""

        if 'standbyMDMs' in cluster_details:
            for stb_mdm in cluster_details['standbyMDMs']:
                current_stb_ips = stb_mdm['ips']
                for ips in standby_ip:
                    if ips in current_stb_ips:
                        LOG.info(self.exist_msg)
                        return False
        return True

    def check_mdm_exists(self, standby_ip=None, cluster_details=None):
        """Check whether standby MDM exists in MDM Cluster"""

        # check in master node
        current_master_ips = cluster_details['master']['ips']
        for ips in standby_ip:
            if ips in current_master_ips:
                LOG.info(self.exist_msg)
                return False

        # check in secondary nodes
        in_secondary = self.check_ip_in_secondarys(standby_ip=standby_ip,
                                                   cluster_details=cluster_details)
        if not in_secondary:
            return False

        # check in tie-breaker nodes
        in_tbs = self.check_ip_in_tbs(standby_ip=standby_ip,
                                      cluster_details=cluster_details)
        if not in_tbs:
            return False

        # check in Standby nodes
        in_standby = self.check_ip_in_standby(standby_ip=standby_ip,
                                              cluster_details=cluster_details)
        if not in_standby:
            return False

        LOG.info("New Standby MDM does not exists in MDM cluster")
        return True

    def get_system_details(self):
        """Get system details
        :return: Details of PowerFlex system
        """

        try:
            resp = self.powerflex_conn.system.get()
            if len(resp) == 0:
                self.module.fail_json(msg="No system exist on the given "
                                          "host.")
            if len(resp) > 1:
                self.module.fail_json(msg="Multiple systems exist on the "
                                          "given host.")
            return resp[0]
        except Exception as e:
            msg = "Failed to get system id with error %s" % str(e)
            LOG.error(msg)
            self.module.fail_json(msg=msg)

    def validate_parameters(self):
        """Validate the input parameters"""

        name_params = ['mdm_name', 'mdm_id', 'mdm_new_name']
        msg = "Please provide the valid {0}"

        for n_item in name_params:
            if self.module.params[n_item] is not None and \
                    (len(self.module.params[n_item].strip()) or
                     self.module.params[n_item].count(" ") > 0) == 0:
                err_msg = msg.format(n_item)
                self.module.fail_json(msg=err_msg)

    def perform_module_operation(self):
        """
        Perform different actions on MDM cluster based on parameters passed in
        the playbook
        """
        mdm_name = self.module.params['mdm_name']
        mdm_id = self.module.params['mdm_id']
        mdm_new_name = self.module.params['mdm_new_name']
        standby_mdm = copy.deepcopy(self.module.params['standby_mdm'])
        is_primary = self.module.params['is_primary']
        cluster_mode = self.module.params['cluster_mode']
        mdm = copy.deepcopy(self.module.params['mdm'])
        mdm_state = self.module.params['mdm_state']
        virtual_ip_interfaces = self.module.params['virtual_ip_interfaces']
        clear_interfaces = self.module.params['clear_interfaces']
        performance_profile = self.module.params['performance_profile']
        state = self.module.params['state']

        # result is a dictionary to contain end state and MDM cluster details
        changed = False
        result = dict(
            changed=False,
            mdm_cluster_details={}
        )
        self.validate_parameters()

        mdm_cluster_details = self.get_mdm_cluster_details()
        msg = "Fetched the MDM cluster details {0}".\
            format(str(mdm_cluster_details))
        LOG.info(msg)

        standby_changed = False
        performance_changed = False
        renamed_changed = False
        interface_changed = False
        remove_changed = False
        mode_changed = False
        owner_changed = False

        # Add standby MDM
        standby_changed, mdm_cluster_details = self.\
            add_standby_mdm(mdm_name, standby_mdm, mdm_cluster_details)

        # Update performance profile
        performance_changed = self.\
            set_performance_profile(performance_profile, mdm_cluster_details)

        # Rename MDM
        if state == 'present' and mdm_new_name:
            renamed_changed = self.rename_mdm(mdm_name, mdm_id, mdm_new_name,
                                              mdm_cluster_details)

        # Change MDM virtual IP interfaces
        if state == 'present' and (virtual_ip_interfaces or clear_interfaces):
            interface_changed = self.\
                set_mdm_virtual_interface(mdm_id, mdm_name,
                                          virtual_ip_interfaces,
                                          clear_interfaces,
                                          mdm_cluster_details)
        # change cluster mode
        if state == 'present' and cluster_mode and mdm and mdm_state:
            mode_changed = self.change_cluster_mode(cluster_mode, mdm,
                                                    mdm_cluster_details)

        # Remove standby MDM
        if state == 'absent':
            remove_changed = self.remove_standby_mdm(mdm_name, mdm_id,
                                                     mdm_cluster_details)

        # change ownership of MDM cluster
        if state == 'present' and is_primary:
            owner_changed = self.change_ownership(mdm_id, mdm_name,
                                                  mdm_cluster_details)

        # Setting Changed Flag
        changed = update_change_flag(standby_changed, performance_changed,
                                     renamed_changed, interface_changed,
                                     mode_changed, remove_changed,
                                     owner_changed)

        # Returning the updated MDM cluster details
        # Checking whether owner of MDM cluster has changed
        if owner_changed:
            mdm_cluster_details = {}
        else:
            mdm_cluster_details = self.get_mdm_cluster_details()

        result['mdm_cluster_details'] = mdm_cluster_details
        result['changed'] = changed
        self.module.exit_json(**result)


def update_change_flag(standby_changed, performance_changed, renamed_changed,
                       interface_changed, mode_changed, remove_changed,
                       owner_changed):
    """ Update the changed flag based on the operation performed in the task"""

    if standby_changed or performance_changed or renamed_changed or \
            interface_changed or mode_changed or remove_changed or \
            owner_changed:
        return True
    return False


def prepare_standby_payload(standby_mdm):
    """prepare the payload for add standby MDM"""
    payload_dict = {}
    for mdm_keys in standby_mdm:
        if standby_mdm[mdm_keys]:
            payload_dict[mdm_keys] = standby_mdm[mdm_keys]
        else:
            payload_dict[mdm_keys] = None
    return payload_dict


def is_modify_mdm_virtual_interface(virtual_ip_interfaces, clear_interfaces,
                                    mdm_details):
    """Check if modification in MDM virtual IP interface required."""

    modify_list = []
    clear = False
    existing_interfaces = mdm_details['virtualInterfaces']

    # Idempotency check for virtual IP interface
    if clear_interfaces is None and \
            len(existing_interfaces) == len(virtual_ip_interfaces) and \
            set(existing_interfaces) == set(virtual_ip_interfaces):
        LOG.info("No changes required for virtual IP interface.")
        return None, False

    # Idempotency check for clear_interfaces
    if clear_interfaces and len(mdm_details['virtualInterfaces']) == 0:
        LOG.info("No change required for clear interface.")
        return None, False

    # clearing all virtual IP interfaces of MDM
    elif clear_interfaces and len(mdm_details['virtualInterfaces']) != 0 and \
            virtual_ip_interfaces is None:
        LOG.info("Clear all interfaces of the MDM.")
        clear = True
        return None, clear

    if virtual_ip_interfaces and clear_interfaces is None:
        for interface in virtual_ip_interfaces:
            modify_list.append(interface)
        return modify_list, clear


def get_powerflex_mdm_cluster_parameters():
    """This method provide parameter required for the MDM cluster
    module on PowerFlex"""
    return dict(
        mdm_name=dict(), mdm_id=dict(), mdm_new_name=dict(),
        virtual_ip_interfaces=dict(type='list', elements='str'),
        clear_interfaces=dict(type='bool'), is_primary=dict(type='bool'),
        standby_mdm=dict(type='dict', options=dict(
            mdm_ips=dict(type='list', elements='str', required=True),
            role=dict(required=True, choices=['Manager', 'TieBreaker']),
            management_ips=dict(type='list', elements='str'),
            port=dict(type='int'), allow_multiple_ips=dict(type='bool'),
            virtual_interfaces=dict(type='list', elements='str'))),
        cluster_mode=dict(choices=['OneNode', 'ThreeNodes', 'FiveNodes']),
        mdm=dict(type='list', elements='dict',
                 options=dict(mdm_id=dict(), mdm_name=dict(),
                              mdm_type=dict(required=True,
                                            choices=['Secondary', 'TieBreaker']))),
        mdm_state=dict(choices=['present-in-cluster', 'absent-in-cluster']),
        performance_profile=dict(choices=['Compact', 'HighPerformance']),
        state=dict(required=True, type='str', choices=['present', 'absent'])
    )


def main():
    """ Perform actions on MDM cluster based on user input from playbook"""
    obj = PowerFlexMdmCluster()
    obj.perform_module_operation()


if __name__ == '__main__':
    main()
