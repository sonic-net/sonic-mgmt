#!/usr/bin/python

# Copyright: (c) 2024, Dell Technologies
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

""" Ansible module for managing NVMe hosts on Dell Technologies PowerFlex"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
module: nvme_host
version_added: '2.6.0'
short_description: Manage NVMe hosts on Dell PowerFlex
description:
- Managing NVMe hosts on PowerFlex storage system includes creating, getting details of NVMe hosts
  , modifying and deleting NVMe hosts.

author:
- Peter Cao (@P-Cao) <ansible.team@dell.com>

extends_documentation_fragment:
  - dellemc.powerflex.powerflex

options:
  max_num_paths:
    description:
    - Maximum number of paths per volume. Used to create or modify the NVMe host.
    type: str
  max_num_sys_ports:
    description:
    - Maximum number of ports per protection domain. Used to create or modify the NVMe host.
    type: str
  nqn:
    description:
    - NQN of the NVMe host. Used to create, get or modify the NVMe host.
    - To retrieve NQN of NVMe host, use command :command:`cat /etc/nvme/hostnqn`
    type: str
  nvme_host_name:
    description:
    - Name of the NVMe host.
    - Specify either I(nvme_host_name), I(nqn) for create, get or rename operation.
    type: str
  nvme_host_new_name:
    description:
    - New name of the NVMe host. Used to rename the NVMe host.
    - Only used for updates. Ignored during creation.
    type: str
  state:
    description:
    - State of the NVMe host.
    choices: ['present', 'absent']
    default: present
    type: str
attributes:
  check_mode:
    description: Runs task to validate without performing action on the target
                 machine.
    support: full
  diff_mode:
    description: Runs the task to report the changes made or to be made.
    support: full
"""

EXAMPLES = r"""
- name: Create NVMe host
  dellemc.powerflex.nvme_host:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: "{{ validate_certs }}"
    nqn: "{{ nqn }}"
    nvme_host_name: "{{ nvme_host_name }}"
    state: "present"

- name: Rename nvme_host using NVMe host id
  dellemc.powerflex.nvme_host:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: "{{ validate_certs }}"
    nvme_host_name: "{{ nvme_host_name }}"
    nvme_host_new_name: "{{ nvme_host_new_name }}"
    state: "present"

- name: Set maximum number of paths per volume and maximum Number of Ports Per Protection Domain of nvme_host
  dellemc.powerflex.nvme_host:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: "{{ validate_certs }}"
    nvme_host_name: "{{ nvme_host_name }}"
    max_num_paths: "{{ max_num_paths }}"
    max_num_sys_ports: "{{ max_num_sys_ports }}"
    state: "present"

- name: Remove nvme_host
  dellemc.powerflex.nvme_host:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: "{{ validate_certs }}"
    nvme_host_name: "{{ nvme_host_name }}"
    state: "absent"
"""

RETURN = r"""
changed:
    description: Whether or not the resource has changed.
    returned: always
    type: bool
    sample: 'false'

nvme_host_details:
    description: Details of the NVMe host.
    returned: When NVMe host exists
    type: dict
    contains:
        hostOsFullType:
            description: Full type of the host OS.
            type: str
        hostType:
            description: Type of the host.
            type: str
        id:
            description: ID of the NVMe host.
            type: str
        installedSoftwareVersionInfo:
            description: Installed software version information.
            type: str
        kernelBuildNumber:
            description: Kernel build number.
            type: str
        kernelVersion:
            description: Kernel version.
            type: str
        links:
            description: Links related to the NVMe host.
            type: list
            contains:
                href:
                    description: Hyperlink reference.
                    type: str
                rel:
                    description: Relation type.
                    type: str
        max_num_paths:
            description: Maximum number of paths per volume. Used to create or modify the NVMe host.
            type: int
        max_num_sys_ports:
            description: Maximum number of ports per protection domain. Used to create or modify the NVMe host.
            type: int
        mdmConnectionState:
            description: MDM connection state.
            type: str
        mdmIpAddressesCurrent:
            description: Current MDM IP addresses.
            type: list
        name:
            description: Name of the NVMe host.
            type: str
        nqn:
            description: NQN of the NVMe host. Used to create, get or modify the NVMe host.
            type: str
        osType:
            description: OS type.
            type: str
        peerMdmId:
            description: Peer MDM ID.
            type: str
        perfProfile:
            description: Performance profile.
            type: str
        sdcAgentActive:
            description: Whether the SDC agent is active.
            type: bool
        sdcApproved:
            description: Whether an SDC has approved access to the system.
            type: bool
        sdcApprovedIps:
            description: SDC approved IPs.
            type: list
        sdcGuid:
            description: SDC GUID.
            type: str
        sdcIp:
            description: SDC IP address.
            type: str
        sdcIps:
            description: SDC IP addresses.
            type: list
        sdcType:
            description: SDC type.
            type: str
        sdrId:
            description: SDR ID.
            type: str
        sdtId:
            description: SDT ID.
            type: str
        softwareVersionInfo:
            description: Software version information.
            type: str
        systemId:
            description: ID of the system.
            type: str
        versionInfo:
            description: Version information.
            type: str
    sample: {
        "hostOsFullType": "Generic",
        "systemId": "264ec85b3855280f",
        "name": "name",
        "sdcApproved": null,
        "sdcAgentActive": null,
        "mdmIpAddressesCurrent": null,
        "sdcIp": null,
        "sdcIps": null,
        "osType": null,
        "perfProfile": null,
        "peerMdmId": null,
        "sdtId": null,
        "mdmConnectionState": null,
        "softwareVersionInfo": null,
        "socketAllocationFailure": null,
        "memoryAllocationFailure": null,
        "versionInfo": null,
        "sdcType": null,
        "nqn": "nqn.org.nvmexpress:uuid",
        "maxNumPaths": 6,
        "maxNumSysPorts": 10,
        "sdcGuid": null,
        "installedSoftwareVersionInfo": null,
        "kernelVersion": null,
        "kernelBuildNumber": null,
        "sdcApprovedIps": null,
        "hostType": "NVMeHost",
        "sdrId": null,
        "id": "1040d67200010000",
        "links": [
            {
                "rel": "self",
                "href": "/api/instances/Host::1040d67200010000"
            },
            {
                "rel": "/api/Host/relationship/Volume",
                "href": "/api/instances/Host::1040d67200010000/relationships/Volume"
            },
            {
                "rel": "/api/Host/relationship/NvmeController",
                "href": "/api/instances/Host::1040d67200010000/relationships/NvmeController"
            },
            {
                "rel": "/api/parent/relationship/systemId",
                "href": "/api/instances/System::264ec85b3855280f"
            }
        ]
    }
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.powerflex.plugins.module_utils.storage.dell.libraries.powerflex_base \
    import PowerFlexBase
from ansible_collections.dellemc.powerflex.plugins.module_utils.storage.dell import (
    utils,
)

LOG = utils.get_logger("nvme")


class PowerFlexNVMeHost(PowerFlexBase):
    """Class with NVMe host operations"""

    def __init__(self):
        """Define all parameters required by this module"""
        required_one_of = [["nvme_host_name", "nqn"]]

        ansible_module_params = {
            'argument_spec': get_powerflex_nvme_host_parameters(),
            'supports_check_mode': True,
            'required_one_of': required_one_of
        }
        super().__init__(AnsibleModule, ansible_module_params)

        self.result = dict(
            changed=False,
            nvme_host_details={},
            diff={}
        )

    def validate_parameters(self, nvme_host_params):
        """Validate the input parameters
        :param nvme_host_params: The dict of NVMe host parameters
        :type nvme_host_params: dict
        """

        host_identifiers = ["nvme_host_name", "nqn",
                            "max_num_paths", "max_num_sys_ports"]
        for param in host_identifiers:
            if (
                nvme_host_params[param] is not None
                and len(nvme_host_params[param].strip()) == 0
            ):
                msg = f"Provide valid {param}"
                LOG.error(msg)
                self.module.fail_json(msg=msg)

    def get_nvme_host(self, nvme_host_id=None, nvme_host_name=None, nqn=None):
        """Get the NVMe host Details
        :param nvme_host_name: The name of the NVMe host
        :param nvme_host_di: The ID of the NVMe host
        :return: The dict containing NVMe host details
        """
        id_name_map = {
            "id": nvme_host_id,
            "nqn": nqn,
            "name": nvme_host_name
        }
        id_name = next(((key, value) for key, value in id_name_map.items() if value), None)

        try:
            filter_field = None
            filter_value = None

            if id_name:
                filter_field, filter_value = id_name

            all_host_details = self.powerflex_conn.sdc.get()
            # Assign names to unnamed NVMe hosts and find the target host
            for nvme_host in all_host_details:
                if nvme_host.get("name") is None:
                    nvme_host["name"] = f"NVMeHost:{nvme_host['id']}"

            if filter_field is None or filter_value is None:
                return all_host_details[0] if all_host_details else None

            nvme_host_details = [
                host_entity for host_entity in all_host_details
                if host_entity.get(filter_field) == filter_value and host_entity.get('hostType') == 'NVMeHost'
            ]

            return nvme_host_details[0] if nvme_host_details else None

        except Exception as e:
            errormsg = "Failed to get NVMe host with error: %s" % str(e)
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def create_nvme_host(self, nvme_host_params):
        """Create the NVMe host
        :param nvme_host_params: The dict of NVMe host parameters
        :type nvme_host_params: dict
        :return: The dict containing NVMe host details
        """
        try:
            if not nvme_host_params['nqn']:
                errormsg = "nqn is required for creating NVMe host"
                LOG.error(errormsg)
                self.module.fail_json(msg=errormsg)

            if self.module._diff:
                self.result.update({"diff": {"before": {}, "after":
                                             {"nqn": nvme_host_params.get('nqn'),
                                              "nvme_host_name": nvme_host_params.get('nvme_host_name'),
                                              "max_num_paths": nvme_host_params.get('max_num_paths'),
                                              "max_num_sys_ports": nvme_host_params.get('max_num_sys_ports')}}})
            if not self.module.check_mode:
                msg = (f"Creating NVMe host with nqn: {nvme_host_params['nqn']}")
                LOG.info(msg)
                self.powerflex_conn.host.create(
                    nqn=nvme_host_params['nqn'],
                    name=nvme_host_params['nvme_host_name'],
                    max_num_paths=nvme_host_params['max_num_paths'],
                    max_num_sys_ports=nvme_host_params['max_num_sys_ports'],
                )
            return self.get_nvme_host(nqn=nvme_host_params['nqn'])

        except Exception as e:
            errormsg = "Create NVMe host operation failed with " "error %s" % str(e)
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def delete_nvme_host(self, nvme_host_details):
        """Remove the NVMe host
        :param nvme_host_id: The ID of the NVMe host
        :type nvme_host_id: str
        :return: The dict containing NVMe host details
        """
        try:
            nvme_host_id = nvme_host_details['id']
            if self.module._diff:
                self.result.update({"diff": {"before": nvme_host_details, "after": {}}})

            if not self.module.check_mode:
                LOG.info(msg=f"Deleting NVMe host {nvme_host_id}")
                self.powerflex_conn.sdc.delete(nvme_host_id)
                return None
            return self.get_nvme_host(nvme_host_id=nvme_host_id)

        except Exception as e:
            errormsg = f"Failed to remove NVMe host {nvme_host_id} with error {str(e)}"
            LOG.error(errormsg)
            self.module.fail_json(msg=errormsg)

    def modify_nvme_host(self, nvme_host_details, nvme_host_params):
        """
        Modifies the NVMe host with the given details.

        Args:
            nvme_host_details (dict): The details of the NVMe host.
            nvme_host_params (dict): The parameters for modification.

        Returns:
            bool: True if the NVMe host was modified, False otherwise.

        Raises:
            Exception: If there was an error renaming the NVMe host or modifying its properties.
        """
        modified, modified_fields, before_dict, after_dict = False, [], {}, {}
        version_check = self._get_api_version_and_check()

        modification_funcs = {
            "nvme_host_new_name": {
                "field": "name",
                "modify_func": lambda: self.powerflex_conn.sdc.rename(sdc_id=nvme_host_details["id"], name=nvme_host_params['nvme_host_new_name']),
                "condition": nvme_host_params['nvme_host_new_name'] and nvme_host_params['nvme_host_new_name'] != nvme_host_details["name"],
            },
            "max_num_paths": {
                "field": "maxNumPaths",
                "modify_func": lambda: self.powerflex_conn.host.modify_max_num_paths(host_id=nvme_host_details["id"],
                                                                                     max_num_paths=nvme_host_params['max_num_paths']),
                "condition": nvme_host_params['max_num_paths'] and nvme_host_params['max_num_paths'] != str(nvme_host_details["maxNumPaths"]),
            },
            "max_num_sys_ports": {
                "field": "maxNumSysPorts",
                "modify_func": lambda: self.powerflex_conn.host.modify_max_num_sys_ports(host_id=nvme_host_details["id"],
                                                                                         max_num_sys_ports=nvme_host_params['max_num_sys_ports']),
                "condition": nvme_host_params['max_num_sys_ports'] and nvme_host_params['max_num_sys_ports'] != str(nvme_host_details["maxNumSysPorts"]),
            },
        }

        for k, v in modification_funcs.items():
            if v["condition"]:
                before_dict[v["field"]] = nvme_host_details[v["field"]]
                after_dict[v["field"]] = nvme_host_params[k]
                try:
                    if not self.module.check_mode:
                        v["modify_func"]()
                    modified_fields.append(v["field"])
                    modified = True
                except Exception as e:
                    self.handle_exception("modify", v["field"], e, version_check, nvme_host_details, modified_fields)

        if self.module._diff and modified:
            self.result.update({"diff": {"before": before_dict, "after": after_dict}})

        return modified, self.get_nvme_host(nvme_host_id=nvme_host_details['id'])

    def handle_exception(self, operation, field, ex, version_check, nvme_host_details, modified_fields):
        """
        Handles exceptions that occur during the modification of NVMe host fields.

        Args:
            operation (str): The operation being performed.
            field (str): The field being modified.
            ex (Exception): The exception that occurred.
            version_check (bool): Whether the version check is enabled.
            nvme_host_details (dict): The details of the NVMe host.
            modified_fields (list): The list of modified fields.

        Returns:
            None

        Raises:
            Exception: If the modification fails.

        """
        version_support_err = f"Updating the NVMe host {field} is not supported in PowerFlex versions earlier than 4.6"
        ex_msg = version_support_err if version_check and field != "name" else str(ex)
        msg = f"Successfully modified the following fields: {', '.join(modified_fields)}" if modified_fields else ""
        errormsg = f"Failed to {operation} NVMe host {nvme_host_details['id']} {field} with error {ex_msg}. {msg}"
        LOG.error(errormsg)
        self.module.fail_json(msg=errormsg)

    def _get_api_version_and_check(self):
        """
        Get the API version and check if it is less than version 4.6.

        Returns:
            bool: True if the API version is less than version 4.6, False otherwise.
        """
        api_version = self.powerflex_conn.system.get()[0]['mdmCluster']['master']['versionInfo']
        version_check = utils.is_version_less_than_4_6(api_version)
        return version_check


def get_powerflex_nvme_host_parameters():
    """This method provide parameters for the Ansible NVMe host module on
    PowerFlex"""
    return dict(
        nqn=dict(type="str"),
        nvme_host_name=dict(type="str"),
        nvme_host_new_name=dict(type="str"),
        max_num_paths=dict(type="str"),
        max_num_sys_ports=dict(type="str"),
        state=dict(default="present", type="str", choices=["present", "absent"]),
    )


class NVMeHostExitHandler():
    def handle(self, nvme_host_obj, nvme_host_details):
        if nvme_host_details:
            nvme_host_obj.result['nvme_host_details'] = nvme_host_details
        else:
            nvme_host_obj.result['nvme_host_details'] = {}
        nvme_host_obj.module.exit_json(**nvme_host_obj.result)


class NVMeHostDeleteHandler():
    def handle(self, nvme_host_obj, nvme_host_params, nvme_host_details):
        if nvme_host_params['state'] == 'absent' and nvme_host_details:
            nvme_host_details = nvme_host_obj.delete_nvme_host(nvme_host_details)
            nvme_host_obj.result['changed'] = True

        NVMeHostExitHandler().handle(nvme_host_obj, nvme_host_details)


class NVMeHostModifyHandler():
    def handle(self, nvme_host_obj, nvme_host_params, nvme_host_details, create_flag=False):
        if not create_flag and nvme_host_params['state'] == 'present' and nvme_host_details:
            changed, nvme_host_details = nvme_host_obj.modify_nvme_host(nvme_host_details, nvme_host_params)
            # if created or modified, set changed to true
            nvme_host_obj.result['changed'] |= changed

        NVMeHostDeleteHandler().handle(nvme_host_obj, nvme_host_params, nvme_host_details)


class NVMeHostCreateHandler():
    def handle(self, nvme_host_obj, nvme_host_params, nvme_host_details):
        create_flag = False
        if nvme_host_params['state'] == 'present' and not nvme_host_details:
            nvme_host_details = nvme_host_obj.create_nvme_host(nvme_host_params)
            nvme_host_obj.result['changed'] = True
            create_flag = True

        NVMeHostModifyHandler().handle(nvme_host_obj, nvme_host_params, nvme_host_details, create_flag)


class NVMeHostHandler():
    def handle(self, nvme_host_obj, nvme_host_params):
        nvme_host_obj.validate_parameters(nvme_host_params=nvme_host_params)
        nvme_host_details = nvme_host_obj.get_nvme_host(nvme_host_name=nvme_host_params['nvme_host_name'],
                                                        nqn=nvme_host_params['nqn'])
        NVMeHostCreateHandler().handle(nvme_host_obj, nvme_host_params, nvme_host_details)


def main():
    """Create PowerFlex NVMe host and perform actions on it
    based on user input from playbook"""
    obj = PowerFlexNVMeHost()
    NVMeHostHandler().handle(obj, obj.module.params)


if __name__ == "__main__":
    main()
