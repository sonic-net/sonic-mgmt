#!/usr/bin/python

# Copyright: (c) 2020, Hetzner Cloud GmbH <info@hetzner-cloud.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import annotations

DOCUMENTATION = """
---
module: load_balancer_service

short_description: Create and manage the services of cloud Load Balancers on the Hetzner Cloud.


description:
    - Create, update and manage the services of cloud Load Balancers on the Hetzner Cloud.

author:
    - Lukas Kaemmerling (@LKaemmerling)
version_added: 0.1.0
options:
    load_balancer:
        description:
            - Name or ID of the Hetzner Cloud Load Balancer the service belongs to
        type: str
        required: true
    listen_port:
        description:
            - The port the service listens on, i.e. the port users can connect to.
        type: int
        required: true
    destination_port:
        description:
            - The port traffic is forwarded to, i.e. the port the targets are listening and accepting connections on.
            - Required if services does not exist and protocol is tcp.
        type: int
    protocol:
        description:
            - Protocol of the service.
            - Required if Load Balancer does not exist.
        type: str
        choices: [ http, https, tcp ]
    proxyprotocol:
        description:
            - Enable the PROXY protocol.
        type: bool
        default: False
    http:
        description:
            - Configuration for HTTP and HTTPS services
        type: dict
        suboptions:
            cookie_name:
                description:
                    - Name of the cookie which will be set when you enable sticky sessions
                type: str
            cookie_lifetime:
                description:
                    - Lifetime of the cookie which will be set when you enable sticky sessions, in seconds
                type: int
            certificates:
                description:
                    - List of Names or IDs of certificates
                type: list
                elements: str
            sticky_sessions:
                description:
                    - Enable or disable sticky_sessions
                type: bool
                default: False
            redirect_http:
                description:
                    - Redirect Traffic from Port 80 to Port 443, only available if protocol is https
                type: bool
                default: False
    health_check:
        description:
            - Configuration for health checks
        type: dict
        suboptions:
            protocol:
                description:
                    - Protocol the health checks will be performed over
                type: str
                choices: [ http, https, tcp ]
            port:
                description:
                    - Port the health check will be performed on
                type: int
            interval:
                description:
                    - Interval of health checks, in seconds
                type: int
            timeout:
                description:
                    - Timeout of health checks, in seconds
                type: int
            retries:
                description:
                    - Number of retries until a target is marked as unhealthy
                type: int
            http:
                description:
                    - Additional Configuration of health checks with protocol http/https
                type: dict
                suboptions:
                    domain:
                        description:
                            - Domain we will set within the HTTP HOST header
                        type: str
                    path:
                        description:
                            - Path we will try to access
                        type: str
                    response:
                        description:
                            - Response we expect, if response is not within the health check response the target is unhealthy
                        type: str
                    status_codes:
                        description:
                            - List of HTTP status codes we expect to get when we perform the health check.
                        type: list
                        elements: str
                    tls:
                        description:
                            - Verify the TLS certificate, only available if health check protocol is https
                        type: bool
                        default: False
    state:
        description:
            - State of the Load Balancer.
        default: present
        choices: [ absent, present ]
        type: str
extends_documentation_fragment:
- hetzner.hcloud.hcloud
"""

EXAMPLES = """
- name: Create a basic Load Balancer service with Port 80
  hetzner.hcloud.load_balancer_service:
    load_balancer: my-load-balancer
    protocol: http
    listen_port: 80
    state: present

- name: Ensure the Load Balancer is absent (remove if needed)
  hetzner.hcloud.load_balancer_service:
    load_balancer: my-Load Balancer
    protocol: http
    listen_port: 80
    state: absent
"""

RETURN = """
hcloud_load_balancer_service:
    description: The Load Balancer service instance
    returned: Always
    type: complex
    contains:
        load_balancer:
            description: The name of the Load Balancer where the service belongs to
            returned: always
            type: str
            sample: my-load-balancer
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
from ..module_utils.vendor.hcloud import APIException, HCloudException
from ..module_utils.vendor.hcloud.certificates import BoundCertificate
from ..module_utils.vendor.hcloud.load_balancers import (
    BoundLoadBalancer,
    LoadBalancerHealtCheckHttp,
    LoadBalancerHealthCheck,
    LoadBalancerService,
    LoadBalancerServiceHttp,
)


class AnsibleHCloudLoadBalancerService(AnsibleHCloud):
    represent = "hcloud_load_balancer_service"

    hcloud_load_balancer: BoundLoadBalancer | None = None
    hcloud_load_balancer_service: LoadBalancerService | None = None

    def _prepare_result(self):
        http = None
        if self.hcloud_load_balancer_service.protocol != "tcp":
            http = {
                "cookie_name": self.hcloud_load_balancer_service.http.cookie_name,
                "cookie_lifetime": self.hcloud_load_balancer_service.http.cookie_lifetime,
                "redirect_http": self.hcloud_load_balancer_service.http.redirect_http,
                "sticky_sessions": self.hcloud_load_balancer_service.http.sticky_sessions,
                "certificates": [
                    certificate.name for certificate in self.hcloud_load_balancer_service.http.certificates
                ],
            }
        health_check = {
            "protocol": self.hcloud_load_balancer_service.health_check.protocol,
            "port": self.hcloud_load_balancer_service.health_check.port,
            "interval": self.hcloud_load_balancer_service.health_check.interval,
            "timeout": self.hcloud_load_balancer_service.health_check.timeout,
            "retries": self.hcloud_load_balancer_service.health_check.retries,
        }
        if self.hcloud_load_balancer_service.health_check.protocol != "tcp":
            health_check["http"] = {
                "domain": self.hcloud_load_balancer_service.health_check.http.domain,
                "path": self.hcloud_load_balancer_service.health_check.http.path,
                "response": self.hcloud_load_balancer_service.health_check.http.response,
                "status_codes": self.hcloud_load_balancer_service.health_check.http.status_codes,
                "tls": self.hcloud_load_balancer_service.health_check.http.tls,
            }
        return {
            "load_balancer": self.hcloud_load_balancer.name,
            "protocol": self.hcloud_load_balancer_service.protocol,
            "listen_port": self.hcloud_load_balancer_service.listen_port,
            "destination_port": self.hcloud_load_balancer_service.destination_port,
            "proxyprotocol": self.hcloud_load_balancer_service.proxyprotocol,
            "http": http,
            "health_check": health_check,
        }

    def _get_load_balancer(self):
        try:
            self.hcloud_load_balancer = self._client_get_by_name_or_id(
                "load_balancers",
                self.module.params.get("load_balancer"),
            )
            self._get_load_balancer_service()
        except HCloudException as exception:
            self.fail_json_hcloud(exception)

    def _create_load_balancer_service(self):
        self.module.fail_on_missing_params(required_params=["protocol"])
        if self.module.params.get("protocol") == "tcp":
            self.module.fail_on_missing_params(required_params=["destination_port"])

        params = {
            "protocol": self.module.params.get("protocol"),
            "listen_port": self.module.params.get("listen_port"),
            "proxyprotocol": self.module.params.get("proxyprotocol"),
        }

        if self.module.params.get("destination_port"):
            params["destination_port"] = self.module.params.get("destination_port")

        if self.module.params.get("http"):
            params["http"] = self.__get_service_http(http_arg=self.module.params.get("http"))

        if self.module.params.get("health_check"):
            params["health_check"] = self.__get_service_health_checks(
                health_check=self.module.params.get("health_check")
            )

        if not self.module.check_mode:
            try:
                action = self.hcloud_load_balancer.add_service(LoadBalancerService(**params))
                action.wait_until_finished()
            except HCloudException as exception:
                self.fail_json_hcloud(exception)
        self._mark_as_changed()
        self._get_load_balancer()
        self._get_load_balancer_service()

    def __get_service_http(self, http_arg):
        service_http = LoadBalancerServiceHttp(certificates=[])
        if http_arg.get("cookie_name") is not None:
            service_http.cookie_name = http_arg.get("cookie_name")
        if http_arg.get("cookie_lifetime") is not None:
            service_http.cookie_lifetime = http_arg.get("cookie_lifetime")
        if http_arg.get("sticky_sessions") is not None:
            service_http.sticky_sessions = http_arg.get("sticky_sessions")
        if http_arg.get("redirect_http") is not None:
            service_http.redirect_http = http_arg.get("redirect_http")
        if http_arg.get("certificates") is not None:
            certificates = http_arg.get("certificates")
            if certificates is not None:
                for certificate_id_or_name in certificates:
                    certificate: BoundCertificate = self._client_get_by_name_or_id(
                        "certificates",
                        certificate_id_or_name,
                    )
                    service_http.certificates.append(certificate)

        return service_http

    def __get_service_health_checks(self, health_check):
        service_health_check = LoadBalancerHealthCheck()
        if health_check.get("protocol") is not None:
            service_health_check.protocol = health_check.get("protocol")
        if health_check.get("port") is not None:
            service_health_check.port = health_check.get("port")
        if health_check.get("interval") is not None:
            service_health_check.interval = health_check.get("interval")
        if health_check.get("timeout") is not None:
            service_health_check.timeout = health_check.get("timeout")
        if health_check.get("retries") is not None:
            service_health_check.retries = health_check.get("retries")
        if health_check.get("http") is not None:
            health_check_http = health_check.get("http")
            service_health_check.http = LoadBalancerHealtCheckHttp()
            if health_check_http.get("domain") is not None:
                service_health_check.http.domain = health_check_http.get("domain")
            if health_check_http.get("path") is not None:
                service_health_check.http.path = health_check_http.get("path")
            if health_check_http.get("response") is not None:
                service_health_check.http.response = health_check_http.get("response")
            if health_check_http.get("status_codes") is not None:
                service_health_check.http.status_codes = health_check_http.get("status_codes")
            if health_check_http.get("tls") is not None:
                service_health_check.http.tls = health_check_http.get("tls")

        return service_health_check

    def _update_load_balancer_service(self):
        changed = False
        try:
            params = {
                "listen_port": self.module.params.get("listen_port"),
            }

            if self.module.params.get("destination_port") is not None:
                if self.hcloud_load_balancer_service.destination_port != self.module.params.get("destination_port"):
                    params["destination_port"] = self.module.params.get("destination_port")
                    changed = True

            if self.module.params.get("protocol") is not None:
                if self.hcloud_load_balancer_service.protocol != self.module.params.get("protocol"):
                    params["protocol"] = self.module.params.get("protocol")
                    changed = True

            if self.module.params.get("proxyprotocol") is not None:
                if self.hcloud_load_balancer_service.proxyprotocol != self.module.params.get("proxyprotocol"):
                    params["proxyprotocol"] = self.module.params.get("proxyprotocol")
                    changed = True

            if self.module.params.get("http") is not None:
                params["http"] = self.__get_service_http(http_arg=self.module.params.get("http"))
                changed = True

            if self.module.params.get("health_check") is not None:
                params["health_check"] = self.__get_service_health_checks(
                    health_check=self.module.params.get("health_check")
                )
                changed = True

            if changed and not self.module.check_mode:
                action = self.hcloud_load_balancer.update_service(LoadBalancerService(**params))
                action.wait_until_finished()
                self._get_load_balancer()
        except HCloudException as exception:
            self.fail_json_hcloud(exception)

        if changed:
            self._mark_as_changed()

    def _get_load_balancer_service(self):
        for service in self.hcloud_load_balancer.services:
            if self.module.params.get("listen_port") == service.listen_port:
                self.hcloud_load_balancer_service = service

    def present_load_balancer_service(self):
        self._get_load_balancer()
        if self.hcloud_load_balancer_service is None:
            self._create_load_balancer_service()
        else:
            self._update_load_balancer_service()

    def delete_load_balancer_service(self):
        try:
            self._get_load_balancer()
            if self.hcloud_load_balancer_service is not None:
                if not self.module.check_mode:
                    try:
                        action = self.hcloud_load_balancer.delete_service(self.hcloud_load_balancer_service)
                        action.wait_until_finished()
                    except HCloudException as exception:
                        self.fail_json_hcloud(exception)
                self._mark_as_changed()
            self.hcloud_load_balancer_service = None
        except APIException as exception:
            self.fail_json_hcloud(exception)

    @classmethod
    def define_module(cls):
        return AnsibleModule(
            argument_spec=dict(
                load_balancer={"type": "str", "required": True},
                listen_port={"type": "int", "required": True},
                destination_port={"type": "int"},
                protocol={
                    "type": "str",
                    "choices": ["http", "https", "tcp"],
                },
                proxyprotocol={"type": "bool", "default": False},
                http={
                    "type": "dict",
                    "options": dict(
                        cookie_name={"type": "str"},
                        cookie_lifetime={"type": "int"},
                        sticky_sessions={"type": "bool", "default": False},
                        redirect_http={"type": "bool", "default": False},
                        certificates={"type": "list", "elements": "str"},
                    ),
                },
                health_check={
                    "type": "dict",
                    "options": dict(
                        protocol={
                            "type": "str",
                            "choices": ["http", "https", "tcp"],
                        },
                        port={"type": "int"},
                        interval={"type": "int"},
                        timeout={"type": "int"},
                        retries={"type": "int"},
                        http={
                            "type": "dict",
                            "options": dict(
                                domain={"type": "str"},
                                path={"type": "str"},
                                response={"type": "str"},
                                status_codes={"type": "list", "elements": "str"},
                                tls={"type": "bool", "default": False},
                            ),
                        },
                    ),
                },
                state={
                    "choices": ["absent", "present"],
                    "default": "present",
                },
                **super().base_module_arguments(),
            ),
            supports_check_mode=True,
        )


def main():
    module = AnsibleHCloudLoadBalancerService.define_module()

    hcloud = AnsibleHCloudLoadBalancerService(module)
    state = module.params.get("state")
    if state == "absent":
        hcloud.delete_load_balancer_service()
    elif state == "present":
        hcloud.present_load_balancer_service()

    module.exit_json(**hcloud.get_result())


if __name__ == "__main__":
    main()
