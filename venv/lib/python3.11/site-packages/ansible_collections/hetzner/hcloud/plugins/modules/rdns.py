#!/usr/bin/python

# Copyright: (c) 2019, Hetzner Cloud GmbH <info@hetzner-cloud.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import annotations

DOCUMENTATION = """
---
module: rdns

short_description: Create and manage reverse DNS entries on the Hetzner Cloud.


description:
    - Create, update and delete reverse DNS entries on the Hetzner Cloud.

author:
    - Lukas Kaemmerling (@lkaemmerling)

options:
    server:
        description:
            - Name or ID of the Hetzner Cloud server you want to add the reverse DNS entry to.
        type: str
    floating_ip:
        description:
            - Name or ID of the Hetzner Cloud Floating IP you want to add the reverse DNS entry to.
        type: str
    primary_ip:
        description:
            - Name or ID of the Hetzner Cloud Primary IP you want to add the reverse DNS entry to.
        type: str
    load_balancer:
        description:
            - Name or ID of the Hetzner Cloud Load Balancer you want to add the reverse DNS entry to.
        type: str
    ip_address:
        description:
            - The IP address that should point to I(dns_ptr).
        type: str
        required: true
    dns_ptr:
        description:
            - The DNS address the I(ip_address) should resolve to.
            - Omit the param to reset the reverse DNS entry to the default value.
        type: str
    state:
        description:
            - State of the reverse DNS entry.
        default: present
        choices: [ absent, present ]
        type: str

extends_documentation_fragment:
- hetzner.hcloud.hcloud
"""

EXAMPLES = """
- name: Create a reverse DNS entry for a server
  hetzner.hcloud.rdns:
    server: my-server
    ip_address: 123.123.123.123
    dns_ptr: example.com
    state: present

- name: Create a reverse DNS entry for a Floating IP
  hetzner.hcloud.rdns:
    floating_ip: my-floating-ip
    ip_address: 123.123.123.123
    dns_ptr: example.com
    state: present

- name: Create a reverse DNS entry for a Primary IP
  hetzner.hcloud.rdns:
    primary_ip: my-primary-ip
    ip_address: 123.123.123.123
    dns_ptr: example.com
    state: present

- name: Create a reverse DNS entry for a Load Balancer
  hetzner.hcloud.rdns:
    load_balancer: my-load-balancer
    ip_address: 123.123.123.123
    dns_ptr: example.com
    state: present

- name: Ensure the reverse DNS entry is absent (remove if needed)
  hetzner.hcloud.rdns:
    server: my-server
    ip_address: 123.123.123.123
    dns_ptr: example.com
    state: absent
"""

RETURN = """
hcloud_rdns:
    description: The reverse DNS entry
    returned: always
    type: complex
    contains:
        server:
            description: Name of the server
            type: str
            returned: always
            sample: my-server
        floating_ip:
            description: Name of the Floating IP
            type: str
            returned: always
            sample: my-floating-ip
        primary_ip:
            description: Name of the Primary IP
            type: str
            returned: always
            sample: my-primary-ip
        load_balancer:
            description: Name of the Load Balancer
            type: str
            returned: always
            sample: my-load-balancer
        ip_address:
            description: The IP address that point to the DNS ptr
            type: str
            returned: always
            sample: 123.123.123.123
        dns_ptr:
            description: The DNS that resolves to the IP
            type: str
            returned: always
            sample: example.com
"""

import ipaddress
from typing import Any

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.hcloud import AnsibleHCloud
from ..module_utils.vendor.hcloud import HCloudException
from ..module_utils.vendor.hcloud.floating_ips import BoundFloatingIP
from ..module_utils.vendor.hcloud.load_balancers import BoundLoadBalancer
from ..module_utils.vendor.hcloud.primary_ips import BoundPrimaryIP
from ..module_utils.vendor.hcloud.servers import BoundServer


class AnsibleHCloudReverseDNS(AnsibleHCloud):
    represent = "hcloud_rdns"

    hcloud_resource: BoundServer | BoundFloatingIP | BoundLoadBalancer | BoundPrimaryIP | None = None
    hcloud_rdns: dict[str, Any] | None = None

    def _prepare_result(self):
        result = {
            "server": None,
            "floating_ip": None,
            "load_balancer": None,
            "ip_address": self.hcloud_rdns["ip_address"],
            "dns_ptr": self.hcloud_rdns["dns_ptr"],
        }

        if self.module.params.get("server"):
            result["server"] = self.hcloud_resource.name
        elif self.module.params.get("floating_ip"):
            result["floating_ip"] = self.hcloud_resource.name
        elif self.module.params.get("load_balancer"):
            result["load_balancer"] = self.hcloud_resource.name
        elif self.module.params.get("primary_ip"):
            result["primary_ip"] = self.hcloud_resource.name
        return result

    def _get_resource(self):
        try:
            if self.module.params.get("server"):
                self.hcloud_resource = self._client_get_by_name_or_id(
                    "servers",
                    self.module.params.get("server"),
                )
            elif self.module.params.get("floating_ip"):
                self.hcloud_resource = self._client_get_by_name_or_id(
                    "floating_ips",
                    self.module.params.get("floating_ip"),
                )
            elif self.module.params.get("primary_ip"):
                self.hcloud_resource = self._client_get_by_name_or_id(
                    "primary_ips",
                    self.module.params.get("primary_ip"),
                )
            elif self.module.params.get("load_balancer"):
                self.hcloud_resource = self._client_get_by_name_or_id(
                    "load_balancers",
                    self.module.params.get("load_balancer"),
                )
        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    def _get_rdns(self):
        ip_address = self.module.params.get("ip_address")

        try:
            ip_address_obj = ipaddress.ip_address(ip_address)
        except ValueError:
            self.module.fail_json(msg=f"The given IP address is not valid: {ip_address}")

        if ip_address_obj.version == 4:
            if self.module.params.get("server"):
                if self.hcloud_resource.public_net.ipv4.ip == ip_address:
                    self.hcloud_rdns = {
                        "ip_address": self.hcloud_resource.public_net.ipv4.ip,
                        "dns_ptr": self.hcloud_resource.public_net.ipv4.dns_ptr,
                    }
                else:
                    self.module.fail_json(msg="The selected server does not have this IP address")
            elif self.module.params.get("floating_ip"):
                if self.hcloud_resource.ip == ip_address:
                    self.hcloud_rdns = {
                        "ip_address": self.hcloud_resource.ip,
                        "dns_ptr": self.hcloud_resource.dns_ptr[0]["dns_ptr"],
                    }
                else:
                    self.module.fail_json(msg="The selected Floating IP does not have this IP address")
            elif self.module.params.get("primary_ip"):
                if self.hcloud_resource.ip == ip_address:
                    self.hcloud_rdns = {
                        "ip_address": self.hcloud_resource.ip,
                        "dns_ptr": self.hcloud_resource.dns_ptr[0]["dns_ptr"],
                    }
                else:
                    self.module.fail_json(msg="The selected Primary IP does not have this IP address")
            elif self.module.params.get("load_balancer"):
                if self.hcloud_resource.public_net.ipv4.ip == ip_address:
                    self.hcloud_rdns = {
                        "ip_address": self.hcloud_resource.public_net.ipv4.ip,
                        "dns_ptr": self.hcloud_resource.public_net.ipv4.dns_ptr,
                    }
                else:
                    self.module.fail_json(msg="The selected Load Balancer does not have this IP address")

        elif ip_address_obj.version == 6:
            if self.module.params.get("server"):
                for ipv6_address_dns_ptr in self.hcloud_resource.public_net.ipv6.dns_ptr:
                    if ipv6_address_dns_ptr["ip"] == ip_address:
                        self.hcloud_rdns = {
                            "ip_address": ipv6_address_dns_ptr["ip"],
                            "dns_ptr": ipv6_address_dns_ptr["dns_ptr"],
                        }
            elif self.module.params.get("floating_ip"):
                for ipv6_address_dns_ptr in self.hcloud_resource.dns_ptr:
                    if ipv6_address_dns_ptr["ip"] == ip_address:
                        self.hcloud_rdns = {
                            "ip_address": ipv6_address_dns_ptr["ip"],
                            "dns_ptr": ipv6_address_dns_ptr["dns_ptr"],
                        }
            elif self.module.params.get("primary_ip"):
                for ipv6_address_dns_ptr in self.hcloud_resource.dns_ptr:
                    if ipv6_address_dns_ptr["ip"] == ip_address:
                        self.hcloud_rdns = {
                            "ip_address": ipv6_address_dns_ptr["ip"],
                            "dns_ptr": ipv6_address_dns_ptr["dns_ptr"],
                        }
            elif self.module.params.get("load_balancer"):
                for ipv6_address_dns_ptr in self.hcloud_resource.public_net.ipv6.dns_ptr:
                    if ipv6_address_dns_ptr["ip"] == ip_address:
                        self.hcloud_rdns = {
                            "ip_address": ipv6_address_dns_ptr["ip"],
                            "dns_ptr": ipv6_address_dns_ptr["dns_ptr"],
                        }

    def _create_rdns(self):
        self.module.fail_on_missing_params(required_params=["dns_ptr"])
        params = {
            "ip": self.module.params.get("ip_address"),
            "dns_ptr": self.module.params.get("dns_ptr"),
        }

        if not self.module.check_mode:
            try:
                action = self.hcloud_resource.change_dns_ptr(**params)
                action.wait_until_finished()
            except HCloudException as exception:
                self.fail_json_hcloud(exception)
        self._mark_as_changed()
        self._get_resource()
        self._get_rdns()

    def _update_rdns(self):
        dns_ptr = self.module.params.get("dns_ptr")
        if dns_ptr != self.hcloud_rdns["dns_ptr"]:
            params = {
                "ip": self.module.params.get("ip_address"),
                "dns_ptr": dns_ptr,
            }

            if not self.module.check_mode:
                try:
                    action = self.hcloud_resource.change_dns_ptr(**params)
                    action.wait_until_finished()
                except HCloudException as exception:
                    self.fail_json_hcloud(exception)
            self._mark_as_changed()
            self._get_resource()
            self._get_rdns()

    def present_rdns(self):
        self._get_resource()
        self._get_rdns()
        if self.hcloud_rdns is None:
            self._create_rdns()
        else:
            self._update_rdns()

    def delete_rdns(self):
        self._get_resource()
        self._get_rdns()
        if self.hcloud_rdns is not None:
            if not self.module.check_mode:
                try:
                    self.hcloud_resource.change_dns_ptr(ip=self.hcloud_rdns["ip_address"], dns_ptr=None)
                except HCloudException as exception:
                    self.fail_json_hcloud(exception)
            self._mark_as_changed()
        self.hcloud_rdns = None

    @classmethod
    def define_module(cls):
        return AnsibleModule(
            argument_spec=dict(
                server={"type": "str"},
                floating_ip={"type": "str"},
                load_balancer={"type": "str"},
                primary_ip={"type": "str"},
                ip_address={"type": "str", "required": True},
                dns_ptr={"type": "str"},
                state={
                    "choices": ["absent", "present"],
                    "default": "present",
                },
                **super().base_module_arguments(),
            ),
            required_one_of=[["server", "floating_ip", "load_balancer", "primary_ip"]],
            mutually_exclusive=[["server", "floating_ip", "load_balancer", "primary_ip"]],
            supports_check_mode=True,
        )


def main():
    module = AnsibleHCloudReverseDNS.define_module()

    hcloud = AnsibleHCloudReverseDNS(module)
    state = module.params["state"]
    if state == "absent":
        hcloud.delete_rdns()
    elif state == "present":
        hcloud.present_rdns()

    module.exit_json(**hcloud.get_result())


if __name__ == "__main__":
    main()
