#!/usr/bin/python
# Copyright: (c) 2020-2025, Dell Technologies
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module for managing host on Unity"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: host

version_added: '1.1.0'

short_description: Manage Host operations on Unity

description:
- The Host module contains the operations
  Creation of a Host,
  Addition of initiators to Host,
  Removal of initiators from Host,
  Modification of host attributes,
  Get details of a Host,
  Deletion of a Host,
  Addition of network address to Host,
  Removal of network address from Host.

extends_documentation_fragment:
  - dellemc.unity.unity

author:
- Rajshree Khare (@kharer5) <ansible.team@dell.com>

options:
  host_name:
    description:
    - Name of the host.
    - Mandatory for host creation.
    type: str

  host_id:
    description:
    - Unique identifier of the host.
    - Host Id is auto generated during creation.
    - Except create, all other operations require either I(host_id) or Ihost_name).
    type: str

  description:
    description:
    - Host description.
    type: str

  host_os:
    description:
    - Operating system running on the host.
    choices: ['AIX', 'Citrix XenServer', 'HP-UX', 'IBM VIOS', 'Linux',
    'Mac OS', 'Solaris', 'VMware ESXi', 'Windows Client', 'Windows Server']
    type: str

  new_host_name:
    description:
    - New name for the host.
    - Only required in rename host operation.
    type: str

  initiators:
    description:
    - List of initiators to be added/removed to/from host.
    type: list
    elements: str

  initiator_state:
    description:
    - State of the initiator.
    choices: [present-in-host , absent-in-host]
    type: str

  network_address:
    description:
    - Network address to be added/removed to/from the host.
    - Enter valid IPV4 or host name.
    type: str

  network_address_state:
    description:
    - State of the Network address.
    choices: [present-in-host , absent-in-host]
    type: str

  state:
    description:
    - State of the host.
    choices: [present , absent]
    type: str
    required: true

notes:
  - The I(check_mode) is not supported.
'''

EXAMPLES = r'''
- name: Create empty Host
  host:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    host_name: "ansible-test-host"
    host_os: "Linux"
    description: "ansible-test-host"
    state: "present"

- name: Create Host with Initiators
  host:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    host_name: "ansible-test-host-1"
    host_os: "Linux"
    description: "ansible-test-host-1"
    initiators:
      - "iqn.1994-05.com.redhat:c38e6e8cfd81"
      - "20:00:00:90:FA:13:81:8D:10:00:00:90:FA:13:81:8D"
    initiator_state: "present-in-host"
    state: "present"

- name: Modify Host using host_id
  host:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    host_id: "Host_253"
    new_host_name: "ansible-test-host-2"
    host_os: "Mac OS"
    description: "Ansible tesing purpose"
    state: "present"

- name: Add Initiators to Host
  host:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    host_name: "ansible-test-host-2"
    initiators:
      - "20:00:00:90:FA:13:81:8C:10:00:00:90:FA:13:81:8C"
    initiator_state: "present-in-host"
    state: "present"

- name: Get Host details using host_name
  host:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    host_name: "ansible-test-host-2"
    state: "present"

- name: Get Host details using host_id
  host:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    host_id: "Host_253"
    state: "present"

- name: Delete Host
  host:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    host_name: "ansible-test-host-2"
    state: "absent"

- name: Add network address to Host
  host:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    host_name: "{{host_name}}"
    network_address: "192.168.1.2"
    network_address_state: "present-in-host"
    state: "present"

- name: Delete network address from Host
  host:
    unispherehost: "{{unispherehost}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    host_name: "{{host_name}}"
    network_address: "192.168.1.2"
    network_address_state: "absent-in-host"
    state: "present"
'''

RETURN = r'''
changed:
    description: Whether or not the resource has changed.
    returned: always
    type: bool
    sample: true

host_details:
    description: Details of the host.
    returned: When host exists.
    type: dict
    contains:
        id:
            description: The system ID given to the host.
            type: str
        name:
            description: The name of the host.
            type: str
        description:
            description: Description about the host.
            type: str
        fc_host_initiators:
            description: Details of the FC initiators associated with
                         the host.
            type: list
            contains:
                id:
                    description: Unique identifier of the FC initiator path.
                    type: str
                name:
                    description: FC Qualified Name (WWN) of the initiator.
                    type: str
                paths:
                    description: Details of the paths associated with the FC initiator.
                    type: list
                    contains:
                        id:
                            description: Unique identifier of the path.
                            type: str
                        is_logged_in:
                            description: Indicates whether the host initiator is logged into the storage system.
                            type: bool
        iscsi_host_initiators:
            description: Details of the ISCSI initiators associated
                         with the host.
            type: list
            contains:
                id:
                    description: Unique identifier of the ISCSI initiator path.
                    type: str
                name:
                    description: ISCSI Qualified Name (IQN) of the initiator.
                    type: str
                paths:
                    description: Details of the paths associated with the ISCSI initiator.
                    type: list
                    contains:
                        id:
                            description: Unique identifier of the path.
                            type: str
                        is_logged_in:
                            description: Indicates whether the host initiator is logged into the storage system.
                            type: bool
        network_addresses:
            description: List of network addresses mapped to the host.
            type: list
        os_type:
            description: Operating system running on the host.
            type: str
        type:
            description: HostTypeEnum of the host.
            type: str
        host_luns:
            description: Details of luns attached to host.
            type: list
    sample: {
        "auto_manage_type": "HostManageEnum.UNKNOWN",
        "datastores": null,
        "description": "ansible-test-host-1",
        "existed": true,
        "fc_host_initiators": [
            {
                "id": "HostInitiator_1",
                "name": "HostName_1",
                "paths": [
                    {
                        "id": "HostInitiator_1_Id1",
                        "is_logged_in": true
                    },
                    {
                        "id": "HostInitiator_1_Id2",
                        "is_logged_in": true
                    }
                ]
            }
        ],
        "hash": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER",
        "health": {
            "UnityHealth": {
                "hash": 8764429420954
            }
        },
        "host_container": null,
        "host_luns": [],
        "host_polled_uuid": null,
        "host_pushed_uuid": null,
        "host_uuid": null,
        "host_v_vol_datastore": null,
        "id": "Host_2198",
        "iscsi_host_initiators": [
            {
                "id": "HostInitiator_2",
                "name": "HostName_2",
                "paths": [
                    {
                        "id": "HostInitiator_2_Id1",
                        "is_logged_in": true
                    },
                    {
                        "id": "HostInitiator_2_Id2",
                        "is_logged_in": true
                    }
                ]
            }
        ],
        "last_poll_time": null,
        "name": "ansible-test-host-1",
        "network_addresses": [],
        "os_type": "Linux",
        "registration_type": null,
        "storage_resources": null,
        "tenant": null,
        "type": "HostTypeEnum.HOST_MANUAL",
        "vms": null
    }
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.unity.plugins.module_utils.storage.dell \
    import utils
import ipaddress

LOG = utils.get_logger('host')

application_type = "Ansible/1.7.1"


class Host(object):
    """Class with Host operations"""

    def __init__(self):
        """ Define all parameters required by this module"""

        self.module_params = utils.get_unity_management_host_parameters()
        self.module_params.update(get_host_parameters())

        mutually_exclusive = [['host_name', 'host_id']]
        required_one_of = [['host_name', 'host_id']]
        required_together = [['network_address', 'network_address_state']]

        """ initialize the ansible module """
        self.module = AnsibleModule(argument_spec=self.module_params,
                                    supports_check_mode=False,
                                    mutually_exclusive=mutually_exclusive,
                                    required_together=required_together,
                                    required_one_of=required_one_of)
        utils.ensure_required_libs(self.module)

        self.unity = utils.get_unity_unisphere_connection(self.module.params, application_type)
        LOG.info('Got the unity instance for provisioning on Unity')

    def get_host_count(self, host_name):
        """ To get the count of hosts with same host_name """

        hosts = []
        host_count = 0
        hosts = utils.host.UnityHostList.get(cli=self.unity._cli,
                                             name=host_name)
        host_count = len(hosts)
        return host_count

    def get_host_details(self, host_id=None, host_name=None):
        """ Get details of a given host """

        host_id_or_name = host_id if host_id else host_name
        try:
            LOG.info("Getting host %s details", host_id_or_name)
            if host_id:
                host_details = self.unity.get_host(_id=host_id)
                if host_details.name is None:
                    return None
            if host_name:

                ''' get the count of hosts with same host_name '''
                host_count = self.get_host_count(host_name)

                if host_count < 1:
                    return None
                elif host_count > 1:
                    error_message = "Duplicate hosts found: There are "\
                                    + host_count + " hosts(s) with the same" \
                                    " host_name: " + host_name
                    LOG.error(error_message)
                    self.module.fail_json(msg=error_message)
                else:
                    host_details = self.unity.get_host(name=host_name)

            return host_details
        except utils.HttpError as e:
            if e.http_status == 401:
                msg = 'Incorrect username or password provided.'
                LOG.error(msg)
                self.module.fail_json(msg=msg)
            else:
                msg = "Got HTTP Connection Error while getting host " \
                      "details %s : Error %s " % (host_id_or_name, str(e))
                LOG.error(msg)
                self.module.fail_json(msg=msg)
        except utils.UnityResourceNotFoundError as e:
            error_message = "Failed to get details of host " \
                            "{0} with error {1}".format(host_id_or_name,
                                                        str(e))
            LOG.error(error_message)
            return None
        except Exception as e:
            error_message = "Got error %s while getting details of host %s" \
                            % (str(e), host_id_or_name)
            LOG.error(error_message)
            self.module.fail_json(msg=error_message)

    def create_host(self, host_name):
        """ Create a new host """
        try:
            description = self.module.params['description']
            host_os = self.module.params['host_os']
            host_type = utils.HostTypeEnum.HOST_MANUAL
            initiators = self.module.params['initiators']
            initiator_state = self.module.params['initiator_state']
            empty_initiators_flag = False

            if (initiators and initiator_state == 'absent-in-host'):
                error_message = "Incorrect 'initiator_state' given."
                LOG.error(error_message)
                self.module.fail_json(msg=error_message)

            if (initiators is None or len(initiators) == 0
                    or not initiator_state
                    or initiator_state == 'absent-in-host'):
                empty_initiators_flag = True

            """ if any of the Initiators is invalid or already mapped """
            if (initiators and initiator_state == 'present-in-host'):
                unmapped_initiators \
                    = self.get_list_unmapped_initiators(initiators)
                if unmapped_initiators is None \
                        or len(unmapped_initiators) < len(initiators):
                    error_message = "Provide valid initiators."
                    LOG.error(error_message)
                    self.module.fail_json(msg=error_message)
            if not empty_initiators_flag:
                self.validate_initiators(initiators)
            LOG.info("Creating empty host %s ", host_name)
            new_host = utils.host.UnityHost.create(self.unity._cli, name=host_name, desc=description,
                                                   os=host_os, host_type=host_type)
            if not empty_initiators_flag:
                host_details = self.unity.get_host(name=host_name)
                LOG.info("Adding initiators to %s host", host_name)
                result, new_host \
                    = self.add_initiator_to_host(host_details, initiators)
            return True, new_host
        except Exception as e:
            error_message = "Got error %s while creation of host %s" \
                            % (str(e), host_name)
            LOG.error(error_message)
            self.module.fail_json(msg=error_message)

    def validate_initiators(self, initiators):
        results = []
        for item in initiators:
            results.append(utils.is_initiator_valid(item))
        if False in results:
            error_message = "One or more initiator provided is not valid, please provide valid initiators"
            LOG.error(error_message)
            self.module.fail_json(msg=error_message)

    def get_host_initiators_list(self, host_details):
        """ Get the list of existing initiators in host"""

        existing_initiators = []
        if host_details.fc_host_initiators is not None:
            fc_len = len(host_details.fc_host_initiators)
            if fc_len > 0:
                for count in range(fc_len):
                    """ get initiator 'wwn' id"""
                    ini_id \
                        = host_details.fc_host_initiators.initiator_id[count]

                    """ update existing_initiators list with 'wwn' """
                    existing_initiators.append(ini_id)

        if host_details.iscsi_host_initiators is not None:
            iscsi_len = len(host_details.iscsi_host_initiators)
            if iscsi_len > 0:
                for count in range(iscsi_len):
                    """ get initiator 'iqn' id"""
                    ini_id \
                        = host_details.iscsi_host_initiators.\
                        initiator_id[count]

                    """ update existing_initiators list with 'iqn' """
                    existing_initiators.append(ini_id)
        return existing_initiators

    def is_host_modified(self, host_details):
        """ Determines whether the Host details are to be updated or not """
        LOG.info("Checking host attribute values.")
        modified_flag = False

        if (self.module.params['description'] is not None
            and self.module.params['description']
            != host_details.description) \
                or (self.module.params['host_os'] is not None
                    and self.module.params['host_os'] != host_details.os_type) \
                or (self.module.params['new_host_name'] is not None
                    and self.module.params[
                        'new_host_name'] != host_details.name) \
                or (self.module.params['initiators'] is not None
                    and self.module.params['initiators']
                    != self.get_host_initiators_list(host_details)):
            LOG.info("Modification required.")
            modified_flag = True

        return modified_flag

    def modify_host(self, host_details, new_host_name=None, description=None,
                    host_os=None):
        """  Modify a host """
        try:
            hosts = utils.host.UnityHostList.get(cli=self.unity._cli)
            host_names_list = hosts.name
            for name in host_names_list:
                if new_host_name == name:
                    error_message = "Cannot modify name, new_host_name: " \
                                    + new_host_name + " already in use."
                    LOG.error(error_message)
                    self.module.fail_json(msg=error_message)
            host_details.modify(name=new_host_name, desc=description,
                                os=host_os)
            return True

        except Exception as e:
            error_message = "Got error %s while modifying host %s" \
                            % (str(e), host_details.name)
            LOG.error(error_message)
            self.module.fail_json(msg=error_message)

    def get_list_unmapped_initiators(self, initiators, host_id=None):
        """ Get the list of those initiators which are
            not mapped to any host"""

        unmapped_initiators = []
        for id in initiators:
            initiator_details = utils.host.UnityHostInitiatorList \
                .get(cli=self.unity._cli, initiator_id=id) \
                ._get_properties()

            """ if an already existing initiator is passed along with an
                unmapped initiator"""
            if None in initiator_details["parent_host"]:
                unmapped_initiators.append(initiator_details
                                           ["initiator_id"][0])
            elif not initiator_details["parent_host"]:
                unmapped_initiators.append(id)
            else:
                error_message = "Initiator " + id + " mapped to another Host."
                LOG.error(error_message)
                self.module.fail_json(msg=error_message)
        return unmapped_initiators

    def add_initiator_to_host(self, host_details, initiators):
        """ Add initiator to host """

        try:
            existing_initiators = self.get_host_initiators_list(host_details)

            """ if current and exisitng initiators are same"""
            if initiators \
                    and (set(initiators).issubset(set(existing_initiators))):
                LOG.info("Initiators are already present in host: %s",
                         host_details.name)
                return False, host_details

            """ get the list of non-mapped initiators out of the
                given initiators"""
            host_id = host_details.id
            unmapped_initiators \
                = self.get_list_unmapped_initiators(initiators, host_id)

            """ if any of the Initiators is invalid or already mapped """
            if unmapped_initiators is None \
                    or len(unmapped_initiators) < len(initiators):
                error_message = "Provide valid initiators."
                LOG.error(error_message)
                self.module.fail_json(msg=error_message)

            LOG.info("Adding initiators to host %s", host_details.name)
            for id in unmapped_initiators:
                host_details.add_initiator(uid=id)
                updated_host \
                    = self.unity.get_host(name=host_details.name)
            return True, updated_host

        except Exception as e:
            error_message = "Got error %s while adding initiator to host %s" \
                            % (str(e), host_details.name)
            LOG.error(error_message)
            self.module.fail_json(msg=error_message)

    def remove_initiator_from_host(self, host_details, initiators):
        """ Remove initiator from host """

        try:
            existing_initiators = self.get_host_initiators_list(host_details)

            if existing_initiators is None:
                LOG.info("No exisiting initiators in host: %s",
                         host_details.name)
                return False, host_details

            if not (set(initiators).issubset(set(existing_initiators))):
                LOG.info("Initiators already absent in host: %s",
                         host_details.name)
                return False, host_details

            LOG.info("Removing initiators from host %s", host_details.name)

            if len(initiators) > 1:
                self.check_if_initiators_logged_in(initiators)

            for id in initiators:
                initiator_details = utils.host.UnityHostInitiatorList \
                    .get(cli=self.unity._cli, initiator_id=id) \
                    ._get_properties()

                """ if initiator has no active paths, then remove it """
                if initiator_details["paths"][0] is None:
                    LOG.info("Initiator Path does not exist.")
                    host_details.delete_initiator(uid=id)
                    updated_host \
                        = self.unity.get_host(name=host_details.name)

                else:
                    """ Checking for initiator logged_in state """
                    for path in initiator_details["paths"][0]["UnityHostInitiatorPathList"]:
                        path_id = path["UnityHostInitiatorPath"]["id"]

                        path_id_obj = utils.host.UnityHostInitiatorPathList \
                            .get(cli=self.unity._cli, _id=path_id)

                        path_id_details = path_id_obj._get_properties()

                        """ if is_logged_in is True, can't remove initiator"""
                        if (path_id_details["is_logged_in"]):
                            error_message = "Cannot remove initiator "\
                                            + id + ", as it is logged in " \
                                                   "the with host."
                            LOG.error(error_message)
                            self.module.fail_json(msg=error_message)

                        elif (not path_id_details["is_logged_in"]):
                            """ if is_logged_in is False, remove initiator """
                            path_id_obj.delete()

                        else:
                            """ if logged_in state does not exist """
                            error_message = " logged_in state does not " \
                                            "exist for initiator " + id + "."
                            LOG.error(error_message)
                            self.module.fail_json(msg=error_message)

                    host_details.delete_initiator(uid=id)
                    updated_host \
                        = self.unity.get_host(name=host_details.name)

            return True, updated_host

        except Exception as e:
            error_message = "Got error %s while removing initiator from " \
                            "host %s" \
                            % (str(e), host_details.name)
            LOG.error(error_message)
            self.module.fail_json(msg=error_message)

    def check_if_initiators_logged_in(self, initiators):
        """ Checks if any of the initiators is of type logged-in"""

        for item in initiators:
            initiator_details = (utils.host.UnityHostInitiatorList
                                 .get(cli=self.unity._cli, initiator_id=item)
                                 ._get_properties())
            if initiator_details["paths"][0] is not None and "UnityHostInitiatorPathList" in initiator_details["paths"][0]:
                error_message = "Removal operation cannot be done since host has logged in initiator(s)"
                LOG.error(error_message)
                self.module.fail_json(msg=error_message)

    def delete_host(self, host_details):
        """ Delete an existing host """

        try:
            host_details.delete()
            return True
        except Exception as e:
            error_message = "Got error %s while deletion of host %s" \
                            % (str(e), host_details.name)
            LOG.error(error_message)
            self.module.fail_json(msg=error_message)

    def get_iscsi_host_initiators_details(self, iscsi_host_initiators):
        """ Get the details of existing ISCSI initiators in host"""

        iscsi_initiator_list = []
        for iscsi in iscsi_host_initiators:
            iscsi_initiator_details = self.unity.get_initiator(_id=iscsi.id)
            iscsi_path_list = []
            if iscsi_initiator_details.paths is not None:
                for path in iscsi_initiator_details.paths:
                    iscsi_path_list.append({
                        'id': path.id,
                        'is_logged_in': path.is_logged_in
                    })
            iscsi_initiator_list.append({
                'id': iscsi_initiator_details.id,
                'name': iscsi_initiator_details.initiator_id,
                'paths': iscsi_path_list
            })
        return iscsi_initiator_list

    def get_host_network_address_list(self, host_details):
        network_address_list = []
        if host_details and host_details.host_ip_ports is not None:
            for port in host_details.host_ip_ports:
                network_address_list.append(port.address)
        return network_address_list

    def manage_network_address(self, host_details, network_address_list,
                               network_address, network_address_state):
        try:
            is_mapped = False
            changed = False
            for addr in network_address_list:
                if addr.lower() == network_address.lower():
                    is_mapped = True
                    break
            if not is_mapped and network_address_state == 'present-in-host':
                LOG.info("Adding network address %s to Host %s", network_address,
                         host_details.name)
                host_details.add_ip_port(network_address)
                changed = True
            elif is_mapped and network_address_state == 'absent-in-host':
                LOG.info("Deleting network address %s from Host %s", network_address,
                         host_details.name)
                host_details.delete_ip_port(network_address)
                changed = True

            if changed:
                updated_host = self.unity.get_host(name=host_details.name)
                network_address_list = self.get_host_network_address_list(updated_host)
            return network_address_list, changed
        except Exception as e:
            error_message = "Got error %s while modifying network address %s of host %s" \
                            % (str(e), network_address, host_details.name)
            LOG.error(error_message)
            self.module.fail_json(msg=error_message)

    def get_host_lun_list(self, host_details):
        """ Get luns attached to host"""
        host_luns_list = []
        if host_details and host_details.host_luns is not None:
            for lun in host_details.host_luns.lun:
                host_lun = {"name": lun.name, "id": lun.id}
                host_luns_list.append(host_lun)
        return host_luns_list

    def get_fc_host_initiators_details(self, fc_host_initiators):
        """ Get the details of existing FC initiators in host"""

        fc_initiator_list = []
        for fc in fc_host_initiators:
            fc_initiator_details = self.unity.get_initiator(_id=fc.id)
            fc_path_list = []
            if fc_initiator_details.paths is not None:
                for path in fc_initiator_details.paths:
                    fc_path_list.append({
                        'id': path.id,
                        'is_logged_in': path.is_logged_in
                    })
            fc_initiator_list.append({
                'id': fc_initiator_details.id,
                'name': fc_initiator_details.initiator_id,
                'paths': fc_path_list
            })
        return fc_initiator_list

    def perform_module_operation(self):
        """ Perform different actions on host based on user parameter
            chosen in playbook """

        host_name = self.module.params['host_name']
        host_id = self.module.params['host_id']
        description = self.module.params['description']
        host_os = self.module.params['host_os']
        new_host_name = self.module.params['new_host_name']
        initiator_state = self.module.params['initiator_state']
        initiators = self.module.params['initiators']
        network_address = self.module.params['network_address']
        network_address_state = self.module.params['network_address_state']
        state = self.module.params['state']

        if host_name and len(host_name) > 255:
            err_msg = "'host_name' is greater than 255 characters."
            LOG.error(err_msg)
            self.module.fail_json(msg=err_msg)

        if new_host_name and len(new_host_name) > 255:
            err_msg = "'new_host_name' is greater than 255 characters."
            LOG.error(err_msg)
            self.module.fail_json(msg=err_msg)

        if description and len(description) > 255:
            err_msg = "'description' is greater than 255 characters."
            LOG.error(err_msg)
            self.module.fail_json(msg=err_msg)

        if not initiators and initiator_state:
            err_msg = "'initiator_state' is given, " \
                      "'initiators' are not specified"
            LOG.error(err_msg)
            self.module.fail_json(msg=err_msg)

        if not initiator_state and initiators:
            err_msg = "'initiators' are given, " \
                      "'initiator_state' is not specified"
            LOG.error(err_msg)
            self.module.fail_json(msg=err_msg)

        # result is a dictionary that contains changed status and
        # host details
        result = dict(
            changed=False,
            host_details={}
        )

        ''' Get host details based on host_name/host_id'''
        host_details = self.get_host_details(host_id, host_name)
        if not host_details and state == 'present':
            if host_id:
                err_msg = "Invalid argument 'host_id' while " \
                          "creating a host"
                LOG.error(err_msg)
                self.module.fail_json(msg=err_msg)
            if not host_name:
                err_msg = "host_name is required to create a host"
                LOG.error(err_msg)
                self.module.fail_json(msg=err_msg)
            if new_host_name:
                err_msg = "Invalid argument 'new_host_name' while " \
                          "creating a host"
                LOG.error(err_msg)
                self.module.fail_json(msg=err_msg)

            if (initiators and initiator_state == 'absent-in-host'):
                error_message = "Incorrect 'initiator_state' given."
                LOG.error(error_message)
                self.module.fail_json(msg=error_message)

            # Create new host
            LOG.info("Creating host: %s", host_name)
            result['changed'], host_details \
                = self.create_host(host_name)
            result['host_details'] = host_details._get_properties()

        # Modify host (Attributes and ADD/REMOVE Initiators)
        elif (state == 'present' and host_details):
            modified_flag = self.is_host_modified(host_details)
            if modified_flag:

                # Modify host
                result['changed'] = self.modify_host(host_details,
                                                     new_host_name,
                                                     description,
                                                     host_os)
                if new_host_name:
                    host_details = self.get_host_details(host_id,
                                                         new_host_name)
                else:
                    host_details = self.get_host_details(host_id, host_name)
                result['host_details'] = host_details._get_properties()

                # Add Initiators to host
                if (initiator_state == 'present-in-host' and initiators
                        and len(initiators) > 0):
                    LOG.info("Adding Initiators to Host %s",
                             host_details.name)
                    result['changed'], host_details \
                        = self.add_initiator_to_host(host_details, initiators)
                    result['host_details'] = host_details._get_properties()

            else:
                LOG.info('Host modification is not applicable, '
                         'as none of the attributes has changed.')
                result['changed'] = False
                result['host_details'] = host_details._get_properties()

        # Remove initiators from host
        if (host_details and initiator_state == 'absent-in-host'
                and initiators and len(initiators) > 0):
            LOG.info("Removing Initiators from Host %s",
                     host_details.name)
            result['changed'], host_details \
                = self.remove_initiator_from_host(host_details,
                                                  initiators)
            result['host_details'] = host_details._get_properties()

        """ display WWN/IQN w.r.t. initiators mapped to host,
            if host exists """
        if host_details and host_details.fc_host_initiators is not None:
            host_details.fc_host_initiators = self.get_fc_host_initiators_details(host_details.fc_host_initiators)
            result['host_details'] = host_details._get_properties()
        if host_details and host_details.iscsi_host_initiators is not None:
            host_details.iscsi_host_initiators = self.get_iscsi_host_initiators_details(host_details.iscsi_host_initiators)
            result['host_details'] = host_details._get_properties()

        ''' Get host luns details and network addresses'''
        if result['host_details']:
            result['host_details']['host_luns'] = self.get_host_lun_list(host_details)
            result['host_details']['network_addresses'] = self.get_host_network_address_list(host_details)
            if 'host_ip_ports' in result['host_details']:
                del result['host_details']['host_ip_ports']

        # manage network address
        if host_details is not None and network_address_state is not None:
            self.validate_network_address_params(network_address)
            network_address_list, changed = self.manage_network_address(
                host_details,
                result['host_details']['network_addresses'],
                network_address,
                network_address_state)
            result['host_details']['network_addresses'] = network_address_list
            result['changed'] = changed

        # Delete a host
        if state == 'absent':
            if host_details:
                LOG.info("Deleting host %s", host_details.name)
                result['changed'] = self.delete_host(host_details)
            else:
                result['changed'] = False
            result['host_details'] = []

        self.module.exit_json(**result)

    def validate_network_address_params(self, network_address):
        if '.' in network_address and not is_valid_ip(network_address):
            err_msg = 'Please enter valid IPV4 address for network address'
            LOG.error(err_msg)
            self.module.fail_json(msg=err_msg)

        if len(network_address) < 1 or len(network_address) > 63:
            err_msg = "'network_address' should be in range of 1 to 63 characters."
            LOG.error(err_msg)
            self.module.fail_json(msg=err_msg)

        if utils.has_special_char(network_address) or ' ' in network_address:
            err_msg = 'Please enter valid IPV4 address or host name for network address'
            LOG.error(err_msg)
            self.module.fail_json(msg=err_msg)


def is_valid_ip(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def get_host_parameters():
    """This method provides parameters required for the ansible host
    module on Unity"""
    return dict(
        host_name=dict(required=False, type='str'),
        host_id=dict(required=False, type='str'),
        description=dict(required=False, type='str'),
        host_os=dict(required=False, type='str',
                     choices=['AIX', 'Citrix XenServer', 'HP-UX',
                              'IBM VIOS', 'Linux', 'Mac OS', 'Solaris',
                              'VMware ESXi', 'Windows Client',
                              'Windows Server']),
        new_host_name=dict(required=False, type='str'),
        initiators=dict(required=False, type='list', elements='str'),
        initiator_state=dict(required=False, type='str',
                             choices=['present-in-host',
                                      'absent-in-host']),
        network_address=dict(required=False, type='str'),
        network_address_state=dict(required=False, type='str',
                                   choices=['present-in-host',
                                            'absent-in-host']),
        state=dict(required=True, type='str',
                   choices=['present', 'absent'])
    )


def main():
    """ Create Unity host object and perform action on it
        based on user input from playbook"""
    obj = Host()
    obj.perform_module_operation()


if __name__ == '__main__':
    main()
