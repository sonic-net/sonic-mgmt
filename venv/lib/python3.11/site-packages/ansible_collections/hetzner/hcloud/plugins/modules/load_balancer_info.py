#!/usr/bin/python

# Copyright: (c) 2020, Hetzner Cloud GmbH <info@hetzner-cloud.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import annotations

DOCUMENTATION = """
---
module: load_balancer_info

short_description: Gather infos about your Hetzner Cloud Load Balancers.


description:
    - Gather infos about your Hetzner Cloud Load Balancers..

author:
    - Lukas Kaemmerling (@LKaemmerling)

options:
    id:
        description:
            - The ID of the Load Balancers you want to get.
            - The module will fail if the provided ID is invalid.
        type: int
    name:
        description:
            - The name of the Load Balancers you want to get.
        type: str
    label_selector:
        description:
            - The label selector for the Load Balancers you want to get.
        type: str
extends_documentation_fragment:
- hetzner.hcloud.hcloud

"""

EXAMPLES = """
- name: Gather hcloud load_balancer infos
  hetzner.hcloud.load_balancer_info:
  register: output

- name: Print the gathered infos
  debug:
    var: output
"""

RETURN = """
hcloud_load_balancer_info:
    description: The load_balancer infos as list
    returned: always
    type: complex
    contains:
        id:
            description: Numeric identifier of the Load Balancer
            returned: always
            type: int
            sample: 1937415
        name:
            description: Name of the Load Balancer
            returned: always
            type: str
            sample: my-Load-Balancer
        load_balancer_type:
            description: Name of the Load Balancer type of the Load Balancer
            returned: always
            type: str
            sample: cx22
        ipv4_address:
            description: Public IPv4 address of the Load Balancer
            returned: always
            type: str
            sample: 116.203.104.109
        ipv6_address:
            description: Public IPv6 address of the Load Balancer
            returned: always
            type: str
            sample: 2a01:4f8:1c1c:c140::1
        location:
            description: Name of the location of the Load Balancer
            returned: always
            type: str
            sample: fsn1
        labels:
            description: User-defined labels (key-value pairs)
            returned: always
            type: dict
        delete_protection:
            description: True if Load Balancer is protected for deletion
            type: bool
            returned: always
            sample: false
        disable_public_interface:
            description: True if Load Balancer public interface is disabled
            type: bool
            returned: always
            sample: false
        targets:
            description: The targets of the Load Balancer
            returned: always
            type: complex
            contains:
                type:
                    description: Type of the Load Balancer Target
                    type: str
                    returned: always
                    sample: server
                load_balancer:
                    description: Name of the Load Balancer
                    type: str
                    returned: always
                    sample: my-LoadBalancer
                server:
                    description: Name of the Server
                    type: str
                    returned: if I(type) is server
                    sample: my-server
                label_selector:
                    description: Label Selector
                    type: str
                    returned: if I(type) is label_selector
                    sample: application=backend
                ip:
                    description: IP of the dedicated server
                    type: str
                    returned: if I(type) is ip
                    sample: 127.0.0.1
                use_private_ip:
                    description:
                        - Route the traffic over the private IP of the Load Balancer through a Hetzner Cloud Network.
                        - Load Balancer needs to be attached to a network. See M(hetzner.hcloud.load_balancer_network)
                    type: bool
                    sample: true
                    returned: always
                health_status:
                    description:
                        - List of health statuses of the services on this target. Only present for target types "server" and "ip".
                    type: list
                    returned: if I(type) is server or ip
                    contains:
                        listen_port:
                            description: Load Balancer Target listen port
                            type: int
                            returned: always
                            sample: 80
                        status:
                            description: Load Balancer Target status
                            type: str
                            choices: [healthy, unhealthy, unknown]
                            returned: always
                            sample: healthy
        services:
            description: all services from this Load Balancer
            returned: Always
            type: complex
            contains:
                listen_port:
                    description: The port the service listens on, i.e. the port users can connect to.
                    returned: always
                    type: int
                    sample: 443
                protocol:
                    description: Protocol of the service
                    returned: always
                    type: str
                    sample: http
                destination_port:
                    description:
                       - The port traffic is forwarded to, i.e. the port the targets are listening and accepting connections on.
                    returned: always
                    type: int
                    sample: 80
                proxyprotocol:
                    description:
                        - Enable the PROXY protocol.
                    returned: always
                    type: bool
                    sample: false
                http:
                    description: Configuration for HTTP and HTTPS services
                    returned: always
                    type: complex
                    contains:
                        cookie_name:
                            description: Name of the cookie which will be set when you enable sticky sessions
                            returned: always
                            type: str
                            sample: HCLBSTICKY
                        cookie_lifetime:
                            description: Lifetime of the cookie which will be set when you enable sticky sessions, in seconds
                            returned: always
                            type: int
                            sample: 3600
                        certificates:
                            description: List of Names or IDs of certificates
                            returned: always
                            type: list
                            elements: str
                        sticky_sessions:
                            description: Enable or disable sticky_sessions
                            returned: always
                            type: bool
                            sample: true
                        redirect_http:
                            description: Redirect Traffic from Port 80 to Port 443, only available if protocol is https
                            returned: always
                            type: bool
                            sample: false
                health_check:
                    description: Configuration for health checks
                    returned: always
                    type: complex
                    contains:
                        protocol:
                            description: Protocol the health checks will be performed over
                            returned: always
                            type: str
                            sample: http
                        port:
                            description: Port the health check will be performed on
                            returned: always
                            type: int
                            sample: 80
                        interval:
                            description: Interval of health checks, in seconds
                            returned: always
                            type: int
                            sample: 15
                        timeout:
                            description: Timeout of health checks, in seconds
                            returned: always
                            type: int
                            sample: 10
                        retries:
                            description: Number of retries until a target is marked as unhealthy
                            returned: always
                            type: int
                            sample: 3
                        http:
                            description: Additional Configuration of health checks with protocol http/https
                            returned: always
                            type: complex
                            contains:
                                domain:
                                    description: Domain we will set within the HTTP HOST header
                                    returned: always
                                    type: str
                                    sample: example.com
                                path:
                                    description: Path we will try to access
                                    returned: always
                                    type: str
                                    sample: /
                                response:
                                    description: Response we expect, if response is not within the health check response the target is unhealthy
                                    returned: always
                                    type: str
                                status_codes:
                                    description: List of HTTP status codes we expect to get when we perform the health check.
                                    returned: always
                                    type: list
                                    elements: str
                                    sample: ["2??","3??"]
                                tls:
                                    description: Verify the TLS certificate, only available if health check protocol is https
                                    returned: always
                                    type: bool
                                    sample: false
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.hcloud import AnsibleHCloud
from ..module_utils.vendor.hcloud import HCloudException
from ..module_utils.vendor.hcloud.load_balancers import (
    BoundLoadBalancer,
    LoadBalancerService,
    LoadBalancerTarget,
)


class AnsibleHCloudLoadBalancerInfo(AnsibleHCloud):
    represent = "hcloud_load_balancer_info"

    hcloud_load_balancer_info: list[BoundLoadBalancer] | None = None

    def _prepare_result(self):
        tmp = []

        for load_balancer in self.hcloud_load_balancer_info:
            if load_balancer is None:
                continue

            tmp.append(
                {
                    "id": load_balancer.id,
                    "name": load_balancer.name,
                    "ipv4_address": load_balancer.public_net.ipv4.ip,
                    "ipv6_address": load_balancer.public_net.ipv6.ip,
                    "private_ipv4_address": load_balancer.private_net[0].ip if len(load_balancer.private_net) else None,
                    "load_balancer_type": load_balancer.load_balancer_type.name,
                    "location": load_balancer.location.name,
                    "labels": load_balancer.labels,
                    "delete_protection": load_balancer.protection["delete"],
                    "disable_public_interface": False if load_balancer.public_net.enabled else True,
                    "targets": [self._prepare_target_result(target) for target in load_balancer.targets],
                    "services": [self._prepare_service_result(service) for service in load_balancer.services],
                }
            )
        return tmp

    @staticmethod
    def _prepare_service_result(service: LoadBalancerService):
        http = None
        if service.protocol != "tcp":
            http = {
                "cookie_name": service.http.cookie_name,
                "cookie_lifetime": service.http.cookie_lifetime,
                "redirect_http": service.http.redirect_http,
                "sticky_sessions": service.http.sticky_sessions,
                "certificates": [certificate.name for certificate in service.http.certificates],
            }
        health_check = {
            "protocol": service.health_check.protocol,
            "port": service.health_check.port,
            "interval": service.health_check.interval,
            "timeout": service.health_check.timeout,
            "retries": service.health_check.retries,
        }
        if service.health_check.protocol != "tcp":
            health_check["http"] = {
                "domain": service.health_check.http.domain,
                "path": service.health_check.http.path,
                "response": service.health_check.http.response,
                "certificates": service.health_check.http.status_codes,
                "tls": service.health_check.http.tls,
            }
        return {
            "protocol": service.protocol,
            "listen_port": service.listen_port,
            "destination_port": service.destination_port,
            "proxyprotocol": service.proxyprotocol,
            "http": http,
            "health_check": health_check,
        }

    @staticmethod
    def _prepare_target_result(target: LoadBalancerTarget):
        result = {
            "type": target.type,
            "use_private_ip": target.use_private_ip,
        }
        if target.type == "server":
            result["server"] = target.server.name
        elif target.type == "label_selector":
            result["label_selector"] = target.label_selector.selector
        elif target.type == "ip":
            result["ip"] = target.ip.ip

        if target.health_status is not None:
            result["health_status"] = [
                {
                    "listen_port": item.listen_port,
                    "status": item.status,
                }
                for item in target.health_status
            ]

        return result

    def get_load_balancers(self):
        try:
            if self.module.params.get("id") is not None:
                self.hcloud_load_balancer_info = [self.client.load_balancers.get_by_id(self.module.params.get("id"))]
            elif self.module.params.get("name") is not None:
                self.hcloud_load_balancer_info = [
                    self.client.load_balancers.get_by_name(self.module.params.get("name"))
                ]
            else:
                params = {}
                label_selector = self.module.params.get("label_selector")
                if label_selector:
                    params["label_selector"] = label_selector

                self.hcloud_load_balancer_info = self.client.load_balancers.get_all(**params)

        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    @classmethod
    def define_module(cls):
        return AnsibleModule(
            argument_spec=dict(
                id={"type": "int"},
                name={"type": "str"},
                label_selector={"type": "str"},
                **super().base_module_arguments(),
            ),
            supports_check_mode=True,
        )


def main():
    module = AnsibleHCloudLoadBalancerInfo.define_module()
    hcloud = AnsibleHCloudLoadBalancerInfo(module)

    hcloud.get_load_balancers()
    result = hcloud.get_result()

    ansible_info = {"hcloud_load_balancer_info": result["hcloud_load_balancer_info"]}
    module.exit_json(**ansible_info)


if __name__ == "__main__":
    main()
