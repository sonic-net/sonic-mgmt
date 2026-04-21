#!/usr/bin/python

# (c) 2025, NetApp Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""NetApp StorageGRID - Manage SNMP monitoring"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {
    "metadata_version": "1.0",
    "status": ["preview"],
    "supported_by": "community",
}


DOCUMENTATION = """
module: na_sg_grid_snmp
short_description: Configure SNMP agent on StorageGRID.
extends_documentation_fragment:
    - netapp.storagegrid.netapp.sg
version_added: '21.15.0'
author: NetApp Ansible Team (@vinaykus) <ng-ansibleteam@netapp.com>
description:
  - Configure SNMP monitoring on NetApp StorageGRID.
options:
  state:
    description:
    - The snmp agent should be present.
    choices: ['present']
    default: 'present'
    type: str
  enable_snmp:
    description:
    - Enable or disable SNMP monitoring.
    type: bool
    default: false
  community_strings:
    description:
    - List of community strings.
    type: list
    elements: str
  ro_users:
    description:
    - USM users allowed read-only access.
    type: list
    elements: str
  sys_location:
    description:
    - SNMP system location.
    type: str
  sys_contact:
    description:
    - SNMP system contact.
    type: str
  trap_community:
    description:
    - SNMP trap community.
    type: str
  auth_trap_enable:
    description:
    - 1 - enable SNMP authentication traps.
    - 2 - disable SNMP authentication traps.
    choices: [1, 2]
    default: 2
    type: int
  disable_notifications:
    description:
    - Disable all SNMP notifications.
    type: bool
    default: false
  trap_destinations:
    description:
    - SNMP trap destinations for V1, V2C, and Inform notifications.
    type: list
    elements: dict
    suboptions:
      type:
        description:
        - SNMP trap destination type.
        choices: ['trapsink', 'trap2sink', 'informsink', 'trapsess', 'informsess']
        type: str
        required: true
      host:
        description:
        - SNMP trap destination host.
        type: str
        required: true
      port:
        description:
        - SNMP trap destination port.
        type: int
      community:
        description:
        - SNMP trap destination community (cannot be used with C(usm_user)).
        type: str
      usm_user:
        description:
        - USM user to send notification under (cannot be used with C(community)).
        type: str
      protocol:
        description:
        - SNMP trap destination protocol.
        choices: ['udp', 'tcp']
        default: 'udp'
        type: str
  agent_addresses:
    description:
    - Local binding addresses for the SNMP agent.
    type: list
    elements: dict
    suboptions:
      protocol:
        description:
        - SNMP agent address protocol.
        choices: ['udp', 'udp6', 'tcp', 'tcp6']
        default: 'udp'
        type: str
      network:
        description:
        - SNMP agent local network interface address.
        choices: ['grid', 'admin', 'client', 'all']
        default: 'all'
        type: str
      port:
        description:
        - SNMP agent local address port.
        type: int
        default: 161
  usm_users:
    description:
    - USM user.
    type: list
    elements: dict
    suboptions:
      name:
        description:
        - USM user name.
        type: str
        required: true
      security_level:
        description:
        - USM user security level.
        choices: ['authNoPriv', 'authPriv']
        type: str
        required: true
      auth_protocol:
        description:
        - USM user authentication protocol.
        choices: ['SHA']
        type: str
        required: true
      auth_passphrase:
        description:
        - USM user authentication passphrase.
        type: str
        required: true
      priv_protocol:
        description:
        - USM user privacy protocol.
        choices: ['AES']
        type: str
      priv_passphrase:
        description:
        - USM user privacy passphrase.
        type: str
      authoritative_engine_id:
        description:
        - The engine ID to use for localized key hashing. From 5 to 32 bytes in hex.
        - Only for use on users specified in informsess trap destinations.
        type: str
"""

EXAMPLES = """
- name: Configure SNMP monitoring
  na_sg_grid_snmp:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    enable_snmp: true
    community_strings:
      - public
    sys_location: RTP-L1-R23S10
    sys_contact: storage-support@example.com
    trap_community: public
    auth_trap_enable: 2
    disable_notifications: false
    trap_destinations:
      - type: trapsink
        host: 172.12.10.100
        port: 162
        community: public
        protocol: udp
    agent_addresses:
      - protocol: udp
        network: admin
        port: 161

- name: Configure usm user
  na_sg_grid_snmp:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    enable_snmp: true
    usm_users:
      - name: user1
        security_level: authNoPriv
        auth_protocol: SHA
        auth_passphrase: password
        priv_protocol: AES
        priv_passphrase: privpass
"""

RETURN = """
resp:
    description: Returns information about the StorageGRID SNMP agent.
    returned: If state is 'present'.
    type: dict
    sample: {
        "enable_snmp": false,
        "community_strings": [
            "public"
        ],
        "rousers": [
            "user1"
        ],
        "sysLocation": "RTP-L1-R23S10",
        "sysContact": "storage-support@example.com",
        "trapcommunity": "public",
        "authtrapenable": 2,
        "disable_notifications": false,
        "trap_destinations": [
            {
                "type": "trapsink",
                "host": "172.16.10.100",
                "port": 162,
                "community": "public",
                "usmUser": "user1",
                "protocol": "udp"
            }
        ],
        "agent_addresses": [
            {
                "protocol": "udp",
                "network": "admin",
                "port": 161
            }
        ],
        "usm_users": [
            {
                "name": "user1",
                "securityLevel": "authPriv",
                "authProtocol": "SHA",
                "authPassphrase": "authpass",
                "privProtocol": "AES",
                "privPassphrase": "privpass",
                "authoritativeEngineId": "0x803f482ba75d00000000"
            }
        ]
    }
"""

import ansible_collections.netapp.storagegrid.plugins.module_utils.netapp as netapp_utils
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp import SGRestAPI


class SgSnmp:
    """
    Configure SNMP monitoring on NetApp StorageGRID
    """

    def __init__(self):
        """
        Parse arguments, setup state variables,
        check parameters and ensure request module is installed
        """
        self.argument_spec = netapp_utils.na_storagegrid_host_argument_spec()
        self.argument_spec.update(
            dict(
                state=dict(type="str", choices=["present"], default="present"),
                enable_snmp=dict(required=False, type="bool", default=False),
                community_strings=dict(required=False, type="list", elements="str"),
                ro_users=dict(required=False, type="list", elements="str"),
                sys_location=dict(required=False, type="str"),
                sys_contact=dict(required=False, type="str"),
                trap_community=dict(required=False, type="str"),
                auth_trap_enable=dict(required=False, type="int", choices=[1, 2], default=2),
                disable_notifications=dict(required=False, type="bool", default=False),
                trap_destinations=dict(
                    required=False,
                    type="list",
                    elements="dict",
                    options=dict(
                        type=dict(required=True, type="str", choices=["trapsink", "trap2sink", "informsink", "trapsess", "informsess"]),
                        host=dict(required=True, type="str"),
                        port=dict(required=False, type="int"),
                        community=dict(required=False, type="str"),
                        usm_user=dict(required=False, type="str"),
                        protocol=dict(required=False, type="str", choices=["udp", "tcp"], default="udp"),
                    )
                ),
                agent_addresses=dict(
                    required=False,
                    type="list",
                    elements="dict",
                    options=dict(
                        protocol=dict(required=False, type="str", choices=["udp", "udp6", "tcp", "tcp6"], default="udp"),
                        network=dict(required=False, type="str", choices=["grid", "admin", "client", "all"], default="all"),
                        port=dict(required=False, type="int", default=161),
                    )
                ),
                usm_users=dict(
                    required=False,
                    type="list",
                    elements="dict",
                    options=dict(
                        name=dict(required=True, type="str"),
                        security_level=dict(required=True, type="str", choices=["authNoPriv", "authPriv"]),
                        auth_protocol=dict(required=True, type="str", choices=["SHA"]),
                        auth_passphrase=dict(required=True, type="str", no_log=True),
                        priv_protocol=dict(required=False, type="str", choices=["AES"]),
                        priv_passphrase=dict(required=False, type="str", no_log=True),
                        authoritative_engine_id=dict(required=False, type="str"),
                    )
                )
            )
        )

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )
        self.na_helper = NetAppModule()

        # set up state variables
        self.parameters = self.na_helper.set_parameters(self.module.params)
        # Calling generic SG rest_api class
        self.rest_api = SGRestAPI(self.module)
        # Get API version
        self.rest_api.get_sg_product_version(api_root="grid")

        # Checking for the parameters passed and create new parameters list
        self.data = {}

        if self.parameters["enable_snmp"] is not None:
            self.data["enable_snmp"] = self.parameters["enable_snmp"]
        if self.parameters.get("community_strings") is not None:
            self.data["community_strings"] = self.parameters["community_strings"]
        if self.parameters.get("ro_users") is not None:
            self.data["rousers"] = self.parameters["ro_users"]
        if self.parameters.get("sys_location"):
            self.data["sysLocation"] = self.parameters["sys_location"]
        if self.parameters.get("sys_contact"):
            self.data["sysContact"] = self.parameters["sys_contact"]
        if self.parameters.get("trap_community"):
            self.data["trapcommunity"] = self.parameters["trap_community"]
        if self.parameters.get("auth_trap_enable"):
            self.data["authtrapenable"] = self.parameters["auth_trap_enable"]
        if self.parameters["disable_notifications"] is not None:
            self.data["disable_notifications"] = self.parameters["disable_notifications"]

        if self.parameters.get("trap_destinations"):
            self.data["trap_destinations"] = [
                {
                    "type": trap_destination["type"],
                    "host": trap_destination["host"],
                    "port": trap_destination.get("port"),
                    "community": trap_destination.get("community"),
                    "usmUser": trap_destination.get("usm_user"),
                    "protocol": trap_destination.get("protocol"),
                }
                for trap_destination in self.parameters["trap_destinations"]
            ]

        if self.parameters.get("agent_addresses"):
            self.data["agent_addresses"] = self.parameters["agent_addresses"]

        if self.parameters.get("usm_users"):
            self.data["usm_users"] = [
                {
                    "name": usm_user["name"],
                    "securityLevel": usm_user["security_level"],
                    "authProtocol": usm_user["auth_protocol"],
                    "authPassphrase": usm_user["auth_passphrase"],
                    "privProtocol": usm_user.get("priv_protocol"),
                    "privPassphrase": usm_user.get("priv_passphrase"),
                    "authoritativeEngineId": usm_user.get("authoritative_engine_id"),
                }
                for usm_user in self.parameters["usm_users"]
            ]

    def get_snmp_config(self):
        """ Get SNMP configuration """
        api = "api/v4/grid/snmp"
        response, error = self.rest_api.get(api)

        if error:
            self.module.fail_json(msg=error)
        else:
            return response["data"]

    def update_snmp_config(self):
        """ Update SNMP configuration """
        api = "api/v4/grid/snmp"
        response, error = self.rest_api.put(api, self.data)

        if error:
            self.module.fail_json(msg=error)
        else:
            return response["data"]

    def apply(self):
        ''' Apply SNMP configuration '''

        current_snmp = self.get_snmp_config()

        cd_action = self.na_helper.get_cd_action(current_snmp, self.parameters)

        if cd_action is None and self.parameters["state"] == "present":
            if not current_snmp["enable_snmp"] and not self.parameters["enable_snmp"]:
                self.module.exit_json(changed=False, msg="SNMP is disabled.")

            # Remove passphrases from usm_users for both current_snmp and self.data to make it idempotent
            if current_snmp.get("usm_users") and self.data.get("usm_users"):
                current_usm_users = {user["name"]: user for user in current_snmp["usm_users"]}
                for user in self.data.get("usm_users"):
                    if user["name"] in current_usm_users:
                        current_usm_users[user["name"]].pop("authPassphrase", None)
                        current_usm_users[user["name"]].pop("privPassphrase", None)
                        user.pop("authPassphrase", None)
                        user.pop("privPassphrase", None)

            modify = self.na_helper.get_modified_attributes(current_snmp, self.data)

        result_message = ""
        resp_data = current_snmp
        if self.na_helper.changed:
            if self.module.check_mode:
                pass
            elif modify:
                resp_data = self.update_snmp_config()
                result_message = "SNMP configuration updated successfully."

        self.module.exit_json(changed=self.na_helper.changed, msg=result_message, resp=resp_data)


def main():
    """
    Main function
    """
    na_sg_grid_snmp = SgSnmp()
    na_sg_grid_snmp.apply()


if __name__ == "__main__":
    main()
