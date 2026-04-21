#!/usr/bin/python

# (c) 2025, NetApp Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""NetApp StorageGRID - Manage Grid Proxy Settings"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}


DOCUMENTATION = """
module: na_sg_grid_proxy_settings
short_description: NetApp StorageGRID manage proxy settings for the grid.
extends_documentation_fragment:
    - netapp.storagegrid.netapp.sg
version_added: '21.15.0'
author: NetApp Ansible Team (@aamirs) <ng-ansibleteam@netapp.com>
description:
  - Update NetApp StorageGRID Proxy settings configuration.
options:
  state:
    description:
    - Proxy settings should be present.
    choices: ['present']
    default: 'present'
    type: str
  enable:
    description:
    - Enable use of the Admin Node proxy.
    type: bool
  host_name:
    description:
    - The IP address or hostname of the Admin Node proxy.
    type: str
  host_port:
    description:
    - Port for the Admin Node proxy.
    type: int
  username:
    description:
    - Username for the Admin Node proxy.
    type: str
  password:
    description:
    - Password for the Admin Node proxy.
    type: str
  ca_bundle:
    description:
    - CA certificate bundle in concatenated PEM-encoding for TLS enabled connection; null when TLS is disabled.
    type: str
  proxy:
    description:
    - The address of the Storage Node proxy to use for external requests. Can be either protocol://hostname:port or
      protocol://ip:port, where protocol is one of http or socks5.
    type: str
"""

EXAMPLES = """
- name: update Proxy settings on StorageGRID
  na_sg_grid_proxy_settings:
    state: present
    enable: true
    host_name: "proxy.example.com"
    host_port: 8080
    username: "MyProxyUsername"
    password: "MyProxyPassword"
    ca_bundle: "<CA certificates in concatenated PEM-encoding>"
    proxy: "http://myproxy.example.com:8080"
"""

RETURN = """
resp:
    description: Returns information about the StorageGRID proxy settings.
    returned: If state is 'present'.
    type: dict
    sample: {
        "enable": true,
        "hostname": "proxy.example.com",
        "hostPort": 8080,
        "username": "MyProxyUsername",
        "password": null,
        "caBundle": null,
        "proxy": "http://myproxy.example.com:8080"
    }
"""

import ansible_collections.netapp.storagegrid.plugins.module_utils.netapp as netapp_utils
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp import SGRestAPI


class SgGridProxySetting(object):
    """
    modify proxy settings for StorageGRID
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
                enable=dict(required=False, type="bool"),
                host_name=dict(required=False, type="str"),
                host_port=dict(required=False, type="int"),
                username=dict(required=False, type="str"),
                password=dict(required=False, type="str", no_log=True),
                ca_bundle=dict(required=False, type="str"),
                proxy=dict(required=False, type="str")
            )
        )

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_if=[("state", "present", ["host_name", "host_port", "proxy"])],
            supports_check_mode=True,
        )

        self.na_helper = NetAppModule()

        # set up state variables
        self.parameters = self.na_helper.set_parameters(self.module.params)
        # Calling generic SG rest_api class
        self.rest_api = SGRestAPI(self.module)
        # Checking for the parameters passed and create new parameters list
        self.data = {}
        self.storage_data = {}
        if self.parameters.get("host_name"):
            self.data["hostname"] = self.parameters["host_name"]
        if self.parameters.get("host_port"):
            self.data["hostPort"] = self.parameters["host_port"]
        if self.parameters.get("ca_bundle"):
            self.data["caBundle"] = self.parameters["ca_bundle"]
        if self.parameters.get("enable") is not None:
            self.data["enable"] = self.parameters["enable"]
        if self.parameters.get("username"):
            self.data["username"] = self.parameters["username"]
        if self.parameters.get("proxy"):
            self.storage_data["proxy"] = self.parameters["proxy"]

    def get_admin_proxy(self):
        # Check if tenant account exists
        # Return tenant account info if found, or None
        api = "api/v4/private/admin-proxy"

        response, error = self.rest_api.get(api)
        if error:
            self.module.fail_json(msg=error)

        return response["data"]

    def update_admin_proxy(self):
        api = "api/v4/private/admin-proxy"
        response, error = self.rest_api.put(api, self.data)
        if error:
            self.module.fail_json(msg=error)
        return response["data"]

    def get_storage_proxy(self):
        # Check if tenant account exists
        # Return tenant account info if found, or None
        api = "api/v4/private/storage-proxy"

        response, error = self.rest_api.get(api)
        if error:
            self.module.fail_json(msg=error)

        return response["data"]

    def update_storage_proxy(self):
        api = "api/v4/private/storage-proxy"
        response, error = self.rest_api.put(api, self.storage_data)
        if error:
            self.module.fail_json(msg=error)

        return response["data"]

    def apply(self):
        ''' Apply Proxy settings '''

        update_storage = False
        update_admin = False

        storage_proxy = self.get_storage_proxy()
        admin_proxy = self.get_admin_proxy()

        cd_action = {"storage_proxy": None, "admin_proxy": None}

        if storage_proxy:
            cd_action["storage_proxy"] = self.na_helper.get_cd_action(storage_proxy, self.parameters)

        if admin_proxy:
            cd_action["admin_proxy"] = self.na_helper.get_cd_action(admin_proxy, self.parameters)

        if cd_action["storage_proxy"] is None and self.parameters["state"] == "present":
            update_storage = False
            update_storage = self.na_helper.get_modified_attributes(storage_proxy, self.storage_data)
            update_storage = True

        if cd_action["admin_proxy"] is None and self.parameters["state"] == "present":
            update_admin = False

            if admin_proxy.get("password") == self.data.get("password"):
                admin_proxy.pop("password", None)

            update_admin = self.na_helper.get_modified_attributes(admin_proxy, self.data)
            update_admin = True

        result_message = ""
        resp_data = {}

        if self.na_helper.changed:
            if self.module.check_mode:
                pass
            else:
                if update_storage:
                    storage_resp = self.update_storage_proxy()
                    if storage_resp:
                        resp_data.update(storage_resp)

                if update_admin:
                    admin_resp = self.update_admin_proxy()
                    if admin_resp:
                        resp_data.update(admin_resp)
                result_message = "proxy settings updated successfully."

        self.module.exit_json(changed=self.na_helper.changed, msg=result_message, resp=resp_data)


def main():
    """
    Main function
    """
    na_sg_grid_proxy_settings = SgGridProxySetting()
    na_sg_grid_proxy_settings.apply()


if __name__ == "__main__":
    main()
