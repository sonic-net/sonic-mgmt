#!/usr/bin/python

# Copyright: (c) 2024, Dell Technologies
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

""" Ansible module for managing SDT on Dell Technologies PowerFlex"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
module: sdt
version_added: '2.6.0'
short_description: Manage SDT (also called NVMe Target) on Dell PowerFlex
description:
- Managing SDT (also called NVMe Target) on PowerFlex storage system includes
  creating new SDT, getting details of SDT, managing IP or role of SDT,
  modifying attributes of SDT, and deleting SDT.
- Support only for Powerflex 4.5 versions and above.
author:
- Yuhao Liu (@RayLiu7) <yuhao_liu@dell.com>
extends_documentation_fragment:
  - dellemc.powerflex.powerflex
options:
  discovery_port:
    description:
    - Discovery port of the SDT.
    type: int
  maintenance_mode:
    description:
    - Maintenance mode state of the SDT.
    choices: ['active', 'inactive']
    type: str
  nvme_port:
    description:
    - NVMe port of the SDT.
    type: int
  protection_domain_name:
    description:
    - The name of the protection domain.
    type: str
  sdt_ip_list:
    description:
    - Dictionary of IPs and their roles for the SDT.
    - At least one IP-role is mandatory while creating a SDT.
    - IP-roles can be updated as well.
    type: list
    elements: dict
    suboptions:
      ip:
        description:
        - IP address of the SDT.
        type: str
        required: true
      role:
        description:
        - Role assigned to the SDT IP address.
        choices: ['StorageOnly', 'HostOnly', 'StorageAndHost']
        type: str
        required: true
  sdt_name:
    description:
    - The name of the SDT.
    - Mandatory for all operations.
    - It is unique across the PowerFlex array.
    required: true
    type: str
  sdt_new_name:
    description:
    - SDT new name, can only be used for renaming the SDT.
    - Only used for updates. Ignored during creation.
    type: str
  state:
    description:
    - State of the SDT.
    choices: ['present', 'absent']
    default: present
    type: str
  storage_port:
    description:
    - Storage port of the SDT.
    type: int
attributes:
  check_mode:
    description: Runs task to validate without performing action on the target
                 machine.
    support: full
  diff_mode:
    description: Runs the task to report the changes made or to be made.
    support: full
notes:
  - IP addresses, and IP address roles must be configured for each SDT.
  - You can assign both storage and host roles to the same target IP addresses.
  - Alternatively, assign the storage role to one target IP address, and add
    another target IP address for the host role.
  - Both roles must be configured on each NVMe target.
"""

EXAMPLES = r"""
- name: Create SDT
  dellemc.powerflex.sdt:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: "{{ validate_certs }}"
    sdt_name: "sdt_example"
    sdt_ip_list:
      - ip: "172.169.xx.xx"
        role: "StorageAndHost"
      - ip: "172.169.yy.yy"
        role: "StorageAndHost"
    protection_domain_name: "PD1"
    storage_port: 12200
    nvme_port: 4420
    discovery_port: 8009
    state: "present"

- name: Rename SDT
  dellemc.powerflex.sdt:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: "{{ validate_certs }}"
    sdt_name: "sdt_example"
    sdt_new_name: "sdt_new_example"
    state: "present"

- name: Modify SDT port
  dellemc.powerflex.sdt:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: "{{ validate_certs }}"
    sdt_name: "sdt_example"
    nvme_port: 4421
    discovery_port: 8008
    state: "present"

- name: Change maintenance mode
  dellemc.powerflex.sdt:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: "{{ validate_certs }}"
    sdt_name: "sdt_example"
    maintenance_mode: "active"
    state: "present"

- name: Set IP and role to SDT
  dellemc.powerflex.sdt:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: "{{ validate_certs }}"
    sdt_name: "sdt_example"
    sdt_ip_list:
      - ip: "172.169.xx.xx"
        role: "StorageAndHost"
      - ip: "172.169.zz.zz"
        role: "StorageAndHost"
    state: "present"

- name: Remove SDT
  dellemc.powerflex.sdt:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: "{{ validate_certs }}"
    sdt_name: "sdt_example"
    state: "absent"
"""

RETURN = r"""
changed:
    description: Whether or not the resource has changed.
    returned: always
    type: bool
    sample: 'false'
sdt_details:
    description: Details of the SDT.
    returned: When SDT exists
    type: dict
    contains:
        authenticationError:
            description: Indicates authentication error.
            type: str
        certificateInfo:
            description: Information about certificate.
            type: dict
            contains:
                issuer:
                    description: Issuer of the certificate.
                    type: str
                subject:
                    description: Subject of the certificate.
                    type: str
                thumbprint:
                    description: Thumbprint of the certificate.
                    type: str
                validFrom:
                    description: Date and time the certificate is valid from.
                    type: str
                validFromAsn1Format:
                    description: Valid from date in ASN.1 format.
                    type: str
                validTo:
                    description: Date and time the certificate is valid to.
                    type: str
                validToAsn1Format:
                    description: Valid to date in ASN.1 format.
                    type: str
        discoveryPort:
            description: Discovery port.
            type: int
        faultSetId:
            description: Fault set ID.
            type: str
        id:
            description: SDS ID.
            type: str
        ipList:
            description: SDS IP list.
            type: list
            contains:
                ip:
                    description: IP present in the SDS.
                    type: str
                role:
                    description: Role of the SDS IP.
                    type: str
        links:
            description: SDS links.
            type: list
            contains:
                href:
                    description: SDS instance URL.
                    type: str
                rel:
                    description: SDS's relationship with different entities.
                    type: str
        maintenanceState:
            description: Maintenance state.
            type: str
        mdmConnectionState:
            description: MDM connection state.
            type: str
        membershipState:
            description: Membership state.
            type: str
        name:
            description: Name of the SDS.
            type: str
        nvmePort:
            description: NVMe port.
            type: int
        persistentDiscoveryControllersNum:
            description: Number of persistent discovery controllers.
            type: int
        protectionDomainId:
            description: Protection Domain ID.
            type: str
        protectionDomainName:
            description: Protection Domain Name.
            type: str
        sdtState:
            description: SDS state.
            type: str
        softwareVersionInfo:
            description: SDS software version information.
            type: str
        storagePort:
            description: Storage port.
            type: int
        systemId:
            description: System ID.
            type: str
    sample: {
        "authenticationError": "None",
        "certificateInfo": {
            "issuer": "/GN=MDM/CN=CA-804696a4dbe1d90f/L=Hopkinton/ST=Massachusetts/C=US/O=EMC/OU=ASD",
            "subject": "/GN=sdt-comp-0/CN=host41/L=Hopkinton/ST=Massachusetts/C=US/O=EMC/OU=ASD",
            "thumbprint": "07:1E:FC:48:03:42:E6:45:14:1D:AA:97:1F:4F:B9:B2:B4:11:99:09",
            "validFrom": "Oct 8 02:35:00 2024 GMT",
            "validFromAsn1Format": "241008023500Z",
            "validTo": "Oct 7 03:35:00 2034 GMT",
            "validToAsn1Format": "341007033500Z"
        },
        "discoveryPort": 8009,
        "faultSetId": null,
        "id": "917d28ed00000000",
        "ipList": [
            {
                "ip": "172.169.xx.xx",
                "role": "StorageAndHost"
            },
            {
                "ip": "172.169.yy.yy",
                "role": "StorageAndHost"
            }
        ],
        "links": [
            {
                "href": "/api/instances/Sdt::917d28ed00000000",
                "rel": "self"
            },
            {
                "href": "/api/instances/Sdt::917d28ed00000000/relationships/Statistics",
                "rel": "/api/Sdt/relationship/Statistics"
            },
            {
                "href": "/api/instances/ProtectionDomain::b4787fa100000000",
                "rel": "/api/parent/relationship/protectionDomainId"
            }
        ],
        "maintenanceState": "NoMaintenance",
        "mdmConnectionState": "Connected",
        "membershipState": "Joined",
        "name": "Sdt-pf460-svm-1",
        "nvmePort": 4420,
        "persistentDiscoveryControllersNum": 0,
        "protectionDomainId": "b4787fa100000000",
        "protectionDomainName": "PD1",
        "sdtState": "Normal",
        "softwareVersionInfo": "R4_5.2100.0",
        "storagePort": 12200,
        "systemId": "804696a4dbe1d90f"
}
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.powerflex.plugins.module_utils.storage.dell import (
    utils,
)
from ansible_collections.dellemc.powerflex.plugins.module_utils.storage.dell.libraries.powerflex_base import (
    PowerFlexBase,
)
from ansible_collections.dellemc.powerflex.plugins.module_utils.storage.dell.libraries.configuration import (
    Configuration,
)
import copy

LOG = utils.get_logger("sdt")

SDT_IP_LIST_INVALID_ERROR_MSG = "Provide valid values for sdt_ip_list as 'ip' and 'role' for Create or Modify operations."
SDT_NAME_INVALID_ERROR_MSG = (
    "Provide valid value for name for the creation or modification of the SDT."
)
PD_INVALID_ERROR_MSG = "Protection Domain is a mandatory parameter for creating an SDT. Enter a valid value."


class PowerFlexSDT(PowerFlexBase):
    """Class with SDT operations"""

    def __init__(self):
        """Define all parameters required by this module"""
        self.module_params = utils.get_powerflex_gateway_host_parameters()
        self.module_params.update(get_powerflex_sdt_parameters())

        # initialize the Ansible module
        ansible_module_params = {
            "argument_spec": get_powerflex_sdt_parameters(),
            "supports_check_mode": True,
        }
        super().__init__(AnsibleModule, ansible_module_params)

        self.result.update({"changed": False, "sdt_details": {}, "diff": {}})

    def validate_ip_parameter(self, sdt_ip_list):
        """Validate the input parameters"""

        if sdt_ip_list is None or len(sdt_ip_list) == 0:
            error_msg = SDT_IP_LIST_INVALID_ERROR_MSG
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def get_sdt_details(self, sdt_name=None, sdt_id=None):
        """Get SDT details
        :param sdt_name: Name of the SDT
        :type sdt_name: str
        :param sdt_id: ID of the SDT
        :type sdt_id: str
        :return: Details of SDT if it exists
        :rtype: dict
        """

        id_or_name = sdt_id if sdt_id else sdt_name

        try:
            if sdt_name:
                sdt_details = self.powerflex_conn.sdt.get(
                    filter_fields={"name": sdt_name}
                )
            else:
                sdt_details = self.powerflex_conn.sdt.get(filter_fields={"id": sdt_id})

            if len(sdt_details) == 0:
                msg = "SDT with identifier '%s' not found" % id_or_name
                LOG.info(msg)
                return None

            return sdt_details[0]

        except Exception as e:
            error_msg = "Failed to get the SDT '%s' with error '%s'" % (
                id_or_name,
                str(e),
            )
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def get_diff_after(self, sdt_params, sdt_details):
        """Get diff between playbook input and sdt details
        :param sdt_params: Dictionary of parameters input from playbook
        :param sdt_params: Dictionary of sdt details
        :return: Dictionary of parameters of differences"""

        if sdt_params["state"] == "absent":
            return {}
        else:
            diff_dict = {}
            if sdt_details is None:
                diff_dict = {
                    "discovery_port": sdt_params["discovery_port"],
                    "nvme_port": sdt_params["nvme_port"],
                    "protection_domain_name": sdt_params["protection_domain_name"],
                    "sdt_ip_list": sdt_params["sdt_ip_list"],
                    "sdt_name": sdt_params["sdt_name"],
                    "storage_port": sdt_params["storage_port"],
                }
            else:
                diff_dict = copy.deepcopy(sdt_details)
                modify_dict = self.is_sdt_modify_required(sdt_params, diff_dict)
                for key in modify_dict.keys():
                    diff_dict[key] = modify_dict[key]
            return diff_dict

    def is_sdt_modify_required(self, sdt_params, sdt_details):
        """
        Check if the SDT needs to be modified.
        :param sdt_params: Dictionary of parameters input from playbook
        :param sdt_details: Dictionary of sdt details
        :return: Dictionary of parameters of differences
        """
        modify_dict = self.to_modify(
            sdt_details=sdt_details,
            sdt_new_name=sdt_params["sdt_new_name"],
            storage_port=sdt_params["storage_port"],
            nvme_port=sdt_params["nvme_port"],
            discovery_port=sdt_params["discovery_port"],
            maintenance_mode=sdt_params["maintenance_mode"],
        )
        if sdt_params["sdt_ip_list"]:
            ips_to_add, ips_to_remove, roles_to_update = self.classify_ip_list_change(
                sdt_params["sdt_ip_list"], sdt_details["ipList"]
            )
            if ips_to_add or ips_to_remove or roles_to_update:
                modify_dict["ipList"] = sdt_params["sdt_ip_list"]
        return modify_dict

    def get_protection_domain(
        self, protection_domain_name=None, protection_domain_id=None
    ):
        """Get the details of a protection domain in a given PowerFlex storage
        system"""
        return Configuration(self.powerflex_conn, self.module).get_protection_domain(
            protection_domain_name=protection_domain_name,
            protection_domain_id=protection_domain_id,
        )

    def validate_create(self, protection_domain_id, sdt_ip_list, sdt_name):

        if sdt_name is None or len(sdt_name.strip()) == 0:
            error_msg = SDT_NAME_INVALID_ERROR_MSG
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

        if protection_domain_id is None:
            error_msg = PD_INVALID_ERROR_MSG
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

        self.validate_ip_parameter(sdt_ip_list)

    def create_sdt(
        self,
        protection_domain_id,
        sdt_ip_list,
        sdt_name,
        storage_port=None,
        nvme_port=None,
        discovery_port=None,
    ):
        """Create SDT
        :param protection_domain_id: ID of the Protection Domain
        :type protection_domain_id: str
        :param sdt_ip_list: List of one or more IP addresses and
                            their roles
        :type sdt_ip_list: list[dict]
        :param sdt_name: SDT name
        :type sdt_name: str
        :param storage_port: Storage port of SDT
        :type storage_port: int
        :param nvme_port: NVMe port of SDT
        :type nvme_port: int
        :param discovery_port: Discovery port of SDT
        :type discovery_port: int
        :return: dict
        """
        try:

            # Restructure IP-role parameter format
            self.validate_create(
                protection_domain_id=protection_domain_id,
                sdt_ip_list=sdt_ip_list,
                sdt_name=sdt_name,
            )

            if not self.module.check_mode:
                create_params = (
                    "protection_domain_id: %s,"
                    " sdt_ip_list: %s,"
                    " sdt_name: %s,"
                    " storage_port: %s,"
                    " nvme_port: %s,"
                    " discovery_port: %s"
                    % (
                        protection_domain_id,
                        sdt_ip_list,
                        sdt_name,
                        storage_port,
                        nvme_port,
                        discovery_port,
                    )
                )
                LOG.info("Creating SDT with params: %s", create_params)

                self.powerflex_conn.sdt.create(
                    protection_domain_id=protection_domain_id,
                    sdt_ips=sdt_ip_list,
                    sdt_name=sdt_name,
                    storage_port=storage_port,
                    nvme_port=nvme_port,
                    discovery_port=discovery_port,
                )
            return self.get_sdt_details(sdt_name=sdt_name)

        except Exception as e:
            error_msg = f"Create SDT {sdt_name} operation failed with error {str(e)}"
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def to_modify(
        self,
        sdt_details,
        sdt_new_name,
        storage_port,
        nvme_port,
        discovery_port,
        maintenance_mode,
    ):
        """
        :param sdt_details: Details of the SDT
        :type sdt_details: dict
        :param sdt_new_name: New name of SDT
        :type sdt_new_name: str
        :param storage_port: Storage port of SDT
        :type storage_port: int
        :param nvme_port: NVMe port of SDT
        :type nvme_port: int
        :param discovery_port: Discovery port of SDT
        :type discovery_port: int
        :param maintenance_mode: Maintenance mode of SDT
        :type maintenance_mode: str
        :return: Dictionary containing the attributes of SDT which are to be
                 updated
        :rtype: dict
        """
        modify_dict = {}

        if sdt_new_name is not None and sdt_new_name != sdt_details["name"]:
            modify_dict["name"] = sdt_new_name

        if storage_port is not None and storage_port != sdt_details["storagePort"]:
            modify_dict["storagePort"] = storage_port
        if nvme_port is not None and nvme_port != sdt_details["nvmePort"]:
            modify_dict["nvmePort"] = nvme_port
        if (
            discovery_port is not None
            and discovery_port != sdt_details["discoveryPort"]
        ):
            modify_dict["discoveryPort"] = discovery_port

        if maintenance_mode is not None:
            if (
                maintenance_mode == "active"
                and sdt_details["maintenanceState"] != "InMaintenance"
            ):
                modify_dict["maintenanceState"] = "active"
            if (
                maintenance_mode == "inactive"
                and sdt_details["maintenanceState"] != "NoMaintenance"
            ):
                modify_dict["maintenanceState"] = "inactive"

        return modify_dict

    def modify_sdt_attributes(self, sdt_id, modify_dict):
        """
        Modify SDT attributes
            :param sdt_id: SDT ID
            :type sdt_id: str
            :param modify_dict: Dictionary containing the attributes of SDT
                                which are to be updated
            :type modify_dict: dict
            :return: Boolean indicating if the operation is successful
        """
        try:
            msg = (
                "Dictionary containing attributes which are to be"
                " updated is '%s'." % (str(modify_dict))
            )
            LOG.info(msg)

            if not self.module.check_mode:
                if "name" in modify_dict:
                    self.powerflex_conn.sdt.rename(sdt_id, modify_dict["name"])
                    msg = (
                        "The name of the SDT is updated to '%s' successfully."
                        % modify_dict["name"]
                    )
                    LOG.info(msg)

                if "storagePort" in modify_dict:
                    self.powerflex_conn.sdt.set_storage_port(
                        sdt_id, modify_dict["storagePort"]
                    )
                    msg = (
                        "The storage port is updated to '%s' successfully."
                        % modify_dict["storagePort"]
                    )
                    LOG.info(msg)

                if "nvmePort" in modify_dict:
                    self.powerflex_conn.sdt.set_nvme_port(
                        sdt_id, modify_dict["nvmePort"]
                    )
                    msg = (
                        "The nvme port is updated to '%s' successfully."
                        % modify_dict["nvmePort"]
                    )
                    LOG.info(msg)

                if "discoveryPort" in modify_dict:
                    self.powerflex_conn.sdt.set_discovery_port(
                        sdt_id, modify_dict["discoveryPort"]
                    )
                    msg = (
                        "The discovery port is updated to '%s' successfully."
                        % modify_dict["discoveryPort"]
                    )
                    LOG.info(msg)

                if "maintenanceState" in modify_dict:
                    mode_map = {
                        "active": self.powerflex_conn.sdt.enter_maintenance_mode,
                        "inactive": self.powerflex_conn.sdt.exit_maintenance_mode,
                    }
                    mode_func = mode_map.get(modify_dict["maintenanceState"])
                    if mode_func:
                        mode_func(sdt_id)
                        msg = (
                            "The maintenance mode is updated to '%s' successfully."
                            % modify_dict["maintenanceState"]
                        )
                        LOG.info(msg)

            return True
        except Exception as e:
            error_msg = "Failed to update the SDT '%s' with error '%s'" % (
                sdt_id,
                str(e),
            )
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def classify_ip_list_change(self, sdt_ip_list, sdt_details_ip_list):
        # identify IPs to add or remove or roles to update

        ips_to_add = []
        ips_to_remove = []
        roles_to_update = []

        # Check if any new IPs need to be added
        for ip_source in sdt_ip_list:
            if not any(
                ip_dest["ip"] == ip_source["ip"] for ip_dest in sdt_details_ip_list
            ):
                ips_to_add.append(ip_source)

        # Check if any IPs need to be removed
        for ip_source in sdt_details_ip_list:
            if not any(ip_dest["ip"] == ip_source["ip"] for ip_dest in sdt_ip_list):
                ips_to_remove.append(ip_source)

        # Check if any IPs need to have their roles updated
        for ip_source in sdt_ip_list:
            for ip_dest in sdt_details_ip_list:
                if (
                    ip_dest["ip"] == ip_source["ip"]
                    and ip_dest["role"] != ip_source["role"]
                ):
                    roles_to_update.append(ip_source)

        return ips_to_add, ips_to_remove, roles_to_update

    def add_ip(self, sdt_details, sdt_ip_list):
        """Add IP to SDT
        :param sdt_details: Details of the SDT
        :type sdt_details: str
        :param sdt_ip_list: List of one or more IP addresses and
                            their roles
        :type sdt_ip_list: list[dict]
        :return: Boolean indicating if add IP operation is successful
        """
        try:
            if not self.module.check_mode:
                for ip in sdt_ip_list:
                    LOG.info("IP to add: %s", ip["ip"])
                    self.powerflex_conn.sdt.add_ip(
                        sdt_id=sdt_details["id"], ip=ip["ip"], role=ip["role"]
                    )
                    LOG.info("IP added successfully.")
            return True
        except Exception as e:
            error_msg = "Add IP to SDT '%s' operation failed with " "error '%s'" % (
                sdt_details["name"],
                str(e),
            )
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def remove_ip(self, sdt_details, sdt_ip_list):
        """Remove IP from SDT
        :param sdt_details: Details of the SDT
        :type sdt_details: str
        :param sdt_ip_list: List of one or more IP addresses and
                            their roles.
        :type sdt_ip_list: list[dict]
        :return: Boolean indicating if remove IP operation is successful
        """
        try:
            if not self.module.check_mode:
                for ip in sdt_ip_list:
                    LOG.info("IP to remove: %s", ip["ip"])
                    self.powerflex_conn.sdt.remove_ip(
                        sdt_id=sdt_details["id"], ip=ip["ip"]
                    )
                    LOG.info("IP removed successfully.")
            return True
        except Exception as e:
            error_msg = (
                "Remove IP from SDT '%s' operation failed with "
                "error '%s'" % (sdt_details["name"], str(e))
            )
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def update_role(self, sdt_details, sdt_ip_list):
        """Update IP's role for an SDT
        :param sdt_details: Details of the SDT
        :type sdt_details: str
        :param sdt_ip_list: List of one or more IP addresses and
                            their roles
        :type sdt_ip_list: list[dict]
        :return: Boolean indicating if update role operation is successful
        """
        try:
            if not self.module.check_mode:
                for ip in sdt_ip_list:
                    LOG.info("ip role to update: %s", ip)
                    self.powerflex_conn.sdt.set_ip_role(
                        sdt_id=sdt_details["id"], ip=ip["ip"], role=ip["role"]
                    )
                    msg = "The role '%s' for IP '%s' is updated " "successfully." % (
                        ip["role"],
                        ip["ip"],
                    )
                    LOG.info(msg)
            return True
        except Exception as e:
            error_msg = (
                "Update role of IP for SDT '%s' operation failed "
                "with error '%s'" % (sdt_details["name"], str(e))
            )
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def delete_sdt(self, sdt_details):
        """Delete SDT
        :param sdt_details: Details of SDT
        :type sdtsdt_details_id: str
        :return: dict
        """
        try:
            if not self.module.check_mode:
                self.powerflex_conn.sdt.delete(sdt_details["id"])
                return None
            return self.get_sdt_details(sdt_id=sdt_details["id"])
        except Exception as e:
            error_msg = "Delete SDT '%s' operation failed with error '%s'" % (
                sdt_details["name"],
                str(e),
            )
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def show_output(self, sdt_id):
        """Show SDT details
        :param sdt_id: ID of the SDT
        :type sdt_id: str
        :return: Details of SDT
        :rtype: dict
        """

        try:
            sdt_details = self.powerflex_conn.sdt.get(filter_fields={"id": sdt_id})

            if len(sdt_details) == 0:
                msg = "SDT with identifier '%s' not found" % sdt_id
                LOG.error(msg)
                return None

            # Append protection domain name
            if (
                "protectionDomainId" in sdt_details[0]
                and sdt_details[0]["protectionDomainId"]
            ):
                pd_details = self.get_protection_domain(
                    protection_domain_id=sdt_details[0]["protectionDomainId"]
                )
                sdt_details[0]["protectionDomainName"] = pd_details["name"]

            return sdt_details[0]

        except Exception as e:
            error_msg = "Failed to get the SDT '%s' with error '%s'" % (sdt_id, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def validate_names(self, sdt_params):
        params = [sdt_params["sdt_name"], sdt_params["sdt_new_name"]]
        for param in params:
            if param is not None and len(param.strip()) == 0:
                error_msg = SDT_NAME_INVALID_ERROR_MSG
                LOG.error(error_msg)
                self.module.fail_json(msg=error_msg)


def get_powerflex_sdt_parameters():
    """This method provide parameters required for the SDT module on
    PowerFlex"""
    return dict(
        sdt_name=dict(required=True),
        sdt_new_name=dict(),
        protection_domain_name=dict(),
        sdt_ip_list=dict(
            type="list",
            elements="dict",
            options=dict(
                ip=dict(required=True),
                role=dict(
                    required=True, choices=["StorageAndHost", "StorageOnly", "HostOnly"]
                ),
            ),
        ),
        storage_port=dict(type="int"),
        nvme_port=dict(type="int"),
        discovery_port=dict(type="int"),
        maintenance_mode=dict(type="str", choices=["active", "inactive"]),
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )


class SDTExitHandler:
    """SDT Handler to manage the output."""

    def handle(self, sdt_obj, sdt_details):
        if sdt_details:
            sdt_obj.result["sdt_details"] = sdt_obj.show_output(
                sdt_id=sdt_details["id"]
            )
        else:
            sdt_obj.result["sdt_details"] = None
        sdt_obj.module.exit_json(**sdt_obj.result)


class SDTDeleteHandler:
    """SDT Handler to process the delete operation."""

    def handle(self, sdt_obj, sdt_params, sdt_details):
        if sdt_params["state"] == "absent" and sdt_details:
            sdt_details = sdt_obj.delete_sdt(sdt_details)
            sdt_obj.result["changed"] = True

        SDTExitHandler().handle(sdt_obj, sdt_details)


class SDTChangeIPListHandler:
    """SDT Handler to process the IP list change operation."""

    def handle(self, sdt_obj, sdt_params, sdt_details, create_sdt_flag, sdt_ip_list):
        if (
            sdt_params["state"] == "present"
            and sdt_ip_list
            and sdt_details
            and not create_sdt_flag
        ):
            sdt_obj.validate_ip_parameter(sdt_ip_list)
            ips_to_add, ips_to_remove, roles_to_update = (
                sdt_obj.classify_ip_list_change(sdt_ip_list, sdt_details["ipList"])
            )

            if ips_to_add:
                sdt_obj.add_ip(sdt_details, ips_to_add)
            if roles_to_update:
                sdt_obj.update_role(sdt_details, roles_to_update)
            if ips_to_remove:
                sdt_obj.remove_ip(sdt_details, ips_to_remove)

            if ips_to_add or roles_to_update or ips_to_remove:
                sdt_obj.result["changed"] = True

        SDTDeleteHandler().handle(sdt_obj, sdt_params, sdt_details)


class SDTModifyHandler:
    """SDT Handler to process the attribute modify operation."""

    def handle(self, sdt_obj, sdt_params, sdt_details, create_sdt_flag, sdt_ip_list):
        if sdt_params["state"] == "present" and sdt_details and not create_sdt_flag:
            modify_dict = sdt_obj.to_modify(
                sdt_details=sdt_details,
                sdt_new_name=sdt_params["sdt_new_name"],
                storage_port=sdt_params["storage_port"],
                nvme_port=sdt_params["nvme_port"],
                discovery_port=sdt_params["discovery_port"],
                maintenance_mode=sdt_params["maintenance_mode"],
            )
            if modify_dict:
                sdt_obj.modify_sdt_attributes(
                    sdt_id=sdt_details["id"], modify_dict=modify_dict
                )
                sdt_obj.result["changed"] = True

        SDTChangeIPListHandler().handle(
            sdt_obj, sdt_params, sdt_details, create_sdt_flag, sdt_ip_list
        )


class SDTCreateHandler:
    """SDT Handler to process the create operation."""

    def handle(self, sdt_obj, sdt_params, sdt_details, protection_domain_id):
        create_sdt_flag = False
        sdt_ip_list = copy.deepcopy(sdt_params["sdt_ip_list"])
        if sdt_params["state"] == "present" and not sdt_details:
            sdt_details = sdt_obj.create_sdt(
                sdt_name=sdt_params["sdt_name"],
                protection_domain_id=protection_domain_id,
                sdt_ip_list=sdt_ip_list,
                storage_port=sdt_params["storage_port"],
                nvme_port=sdt_params["nvme_port"],
                discovery_port=sdt_params["discovery_port"],
            )
            sdt_obj.result["changed"] = True
            create_sdt_flag = True

        SDTModifyHandler().handle(
            sdt_obj, sdt_params, sdt_details, create_sdt_flag, sdt_ip_list
        )


class SDTHandler:
    """SDT Handler to preprocess the operation."""

    def handle(self, sdt_obj, sdt_params):
        sdt_obj.validate_names(sdt_params=sdt_params)
        sdt_details = sdt_obj.get_sdt_details(sdt_params["sdt_name"])
        protection_domain_id = None
        if sdt_params["protection_domain_name"]:
            protection_domain_id = sdt_obj.get_protection_domain(
                protection_domain_name=sdt_params["protection_domain_name"]
            )["id"]

        before_dict = {}
        diff_dict = {}
        diff_dict = sdt_obj.get_diff_after(sdt_params, sdt_details)
        if sdt_details is None:
            before_dict = {}
        else:
            before_dict = sdt_details
        if sdt_obj.module._diff:
            sdt_obj.result["diff"] = dict(before=before_dict, after=diff_dict)

        SDTCreateHandler().handle(
            sdt_obj, sdt_params, sdt_details, protection_domain_id
        )


def main():
    """Create PowerFlex SDT object and perform action on it
    based on user input from playbook."""
    obj = PowerFlexSDT()
    SDTHandler().handle(obj, obj.module.params)


if __name__ == "__main__":
    main()
