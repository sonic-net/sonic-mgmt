#!/usr/bin/python

# (c) 2024, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: na_santricity_discover
short_description: NetApp E-Series discover E-Series storage systems
description: Module searches a subnet range and returns any available E-Series storage systems.
author:
    - Nathan Swartz (@swartzn)
    - Vu Tran (@VuTran007)
options:
    subnet_mask:
        description:
            - This is the IPv4 search range for discovering E-Series storage arrays.
            - IPv4 subnet mask specified in CIDR form. Example 192.168.1.0/24 would search the range 192.168.1.0 to 192.168.1.255.
            - Be sure to include all management paths in the search range.
        type: str
        required: true
    ports:
        description:
            - This option specifies which ports to be tested during the discovery process.
            - The first usable port will be used in the returned API url.
        type: list
        elements: int
        default: [8443]
        required: false
    proxy_url:
        description:
            - Web Services Proxy REST API URL. Example https://192.168.1.100:8443/devmgr/v2/
        type: str
        required: false
    proxy_username:
        description:
            - Web Service Proxy username
        type: str
        required: false
    proxy_password:
        description:
            - Web Service Proxy user password
        type: str
        required: false
    proxy_validate_certs:
        description:
            - Whether to validate Web Service Proxy SSL certificate
        type: bool
        default: true
        required: false
    prefer_embedded:
        description:
            - Give preference to Web Services Embedded when an option exists for both Web Services Proxy and Embedded.
            - Web Services Proxy will be utilized when available by default.
        type: bool
        default: false
        required: false
notes:
    - Only available for platforms E2800 or later (SANtricity Web Services Embedded REST API must be available).
    - All E-Series storage systems with SANtricity version 11.62 or later will be discovered.
    - Only E-Series storage systems without a set admin password running SANtricity versions prior to 11.62 will be discovered.
    - Use SANtricity Web Services Proxy to discover all systems regardless of SANricity version or password.
requirements:
    - ipaddress
"""

EXAMPLES = """
- name: Discover all E-Series storage systems on the network.
  na_santricity_discover:
    subnet_mask: 192.168.1.0/24
"""

RETURN = """
systems_found:
    description: Success message
    returned: on success
    type: dict
    sample: '{"012341234123": {
                "addresses": ["192.168.1.184", "192.168.1.185"],
                "api_urls": ["https://192.168.1.184:8443/devmgr/v2/", "https://192.168.1.185:8443/devmgr/v2/"],
                "label": "ExampleArray01",
                "proxy_ssid: "",
                "proxy_required": false},
              "012341234567": {
                "addresses": ["192.168.1.23", "192.168.1.24"],
                "api_urls": ["https://192.168.1.100:8443/devmgr/v2/"],
                "label": "ExampleArray02",
                "proxy_ssid": "array_ssid",
                "proxy_required": true}}'
"""

import json
import multiprocessing
import threading
from time import sleep

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.netapp_eseries.santricity.plugins.module_utils.santricity import request
from ansible.module_utils._text import to_native

try:
    import ipaddress
except ImportError:
    HAS_IPADDRESS = False
else:
    HAS_IPADDRESS = True

try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse


class NetAppESeriesDiscover:
    """Discover E-Series storage systems."""
    MAX_THREAD_POOL_SIZE = 256
    CPU_THREAD_MULTIPLE = 32
    SEARCH_TIMEOUT = 30
    DEFAULT_CONNECTION_TIMEOUT_SEC = 30
    DEFAULT_DISCOVERY_TIMEOUT_SEC = 300

    def __init__(self):
        ansible_options = dict(subnet_mask=dict(type="str", required=True),
                               ports=dict(type="list", elements="int", required=False, default=[8443]),
                               proxy_url=dict(type="str", required=False),
                               proxy_username=dict(type="str", required=False),
                               proxy_password=dict(type="str", required=False, no_log=True),
                               proxy_validate_certs=dict(type="bool", default=True, required=False),
                               prefer_embedded=dict(type="bool", default=False, required=False))

        required_together = [["proxy_url", "proxy_username", "proxy_password"]]
        self.module = AnsibleModule(argument_spec=ansible_options, required_together=required_together)
        args = self.module.params

        self.subnet_mask = args["subnet_mask"]
        self.prefer_embedded = args["prefer_embedded"]
        self.ports = []
        self.proxy_url = args["proxy_url"]
        if args["proxy_url"]:
            parsed_url = list(urlparse.urlparse(args["proxy_url"]))
            parsed_url[2] = "/devmgr/utils/about"
            self.proxy_about_url = urlparse.urlunparse(parsed_url)
            parsed_url[2] = "/devmgr/v2/"
            self.proxy_url = urlparse.urlunparse(parsed_url)
            self.proxy_username = args["proxy_username"]
            self.proxy_password = args["proxy_password"]
            self.proxy_validate_certs = args["proxy_validate_certs"]

        for port in args["ports"]:
            if str(port).isdigit() and 0 < port < 2 ** 16:
                self.ports.append(str(port))
            else:
                self.module.fail_json(msg="Invalid port! Ports must be positive numbers between 0 and 65536.")

        self.systems_found = {}

    def check_ip_address(self, systems_found, address):
        """Determine where an E-Series storage system is available at a specific ip address."""
        for port in self.ports:
            if port == "8080":
                url = "http://%s:%s/" % (address, port)
            else:
                url = "https://%s:%s/" % (address, port)

            try:
                rc, about = request(url + "devmgr/v2/storage-systems/1/about", validate_certs=False, force_basic_auth=False, ignore_errors=True)
                if about["serialNumber"] in systems_found:
                    systems_found[about["serialNumber"]]["api_urls"].append(url)
                else:
                    systems_found.update({about["serialNumber"]: {"api_urls": [url], "label": about["name"],
                                                                  "addresses": [], "proxy_ssid": "", "proxy_required": False}})
                break
            except Exception as error:
                try:
                    rc, sa_data = request(url + "devmgr/v2/storage-systems/1/symbol/getSAData", validate_certs=False, force_basic_auth=False,
                                          ignore_errors=True)
                    if rc == 401:  # Unauthorized
                        self.module.warn(
                            "Fail over and discover any storage system without a set admin password. This will discover systems without a set password"
                            " such as newly deployed storage systems. Address [%s]." % address)
                        # Fail over and discover any storage system without a set admin password. This will cover newly deployed systems.
                        rc, graph = request(url + "graph", validate_certs=False, url_username="admin", url_password="", timeout=self.SEARCH_TIMEOUT)
                        sa_data = graph["sa"]["saData"]

                    if sa_data["chassisSerialNumber"] in systems_found:
                        systems_found[sa_data["chassisSerialNumber"]]["api_urls"].append(url)
                    else:
                        systems_found.update({sa_data["chassisSerialNumber"]: {"api_urls": [url], "label": sa_data["storageArrayLabel"],
                                                                               "addresses": [], "proxy_ssid": "", "proxy_required": False}})
                    break
                except Exception as error:
                    pass

    def no_proxy_discover(self):
        """Discover E-Series storage systems using embedded web services."""
        thread_pool_size = min(multiprocessing.cpu_count() * self.CPU_THREAD_MULTIPLE, self.MAX_THREAD_POOL_SIZE)
        subnet = list(ipaddress.ip_network(u"%s" % self.subnet_mask))

        thread_pool = []
        search_count = len(subnet)
        for start in range(0, search_count, thread_pool_size):
            end = search_count if (search_count - start) < thread_pool_size else start + thread_pool_size

            for address in subnet[start:end]:
                thread = threading.Thread(target=self.check_ip_address, args=(self.systems_found, address))
                thread_pool.append(thread)
                thread.start()
            for thread in thread_pool:
                thread.join()

    def verify_proxy_service(self):
        """Verify proxy url points to a web services proxy."""
        try:
            rc, about = request(self.proxy_about_url, validate_certs=self.proxy_validate_certs)
            if not about["runningAsProxy"]:
                self.module.fail_json(msg="Web Services is not running as a proxy!")
        except Exception as error:
            self.module.fail_json(msg="Proxy is not available! Check proxy_url. Error [%s]." % to_native(error))

    def test_systems_found(self, systems_found, serial, label, addresses):
        """Verify and build api urls."""
        api_urls = []
        for address in addresses:
            for port in self.ports:
                if port == "8080":
                    url = "http://%s:%s/devmgr/" % (address, port)
                else:
                    url = "https://%s:%s/devmgr/" % (address, port)

                try:
                    rc, response = request(url + "utils/about", validate_certs=False, timeout=self.SEARCH_TIMEOUT)
                    api_urls.append(url + "v2/")
                    break
                except Exception as error:
                    pass
        systems_found.update({serial: {"api_urls": api_urls,
                                       "label": label,
                                       "addresses": addresses,
                                       "proxy_ssid": "",
                                       "proxy_required": False}})

    def proxy_discover(self):
        """Search for array using it's chassis serial from web services proxy."""
        self.verify_proxy_service()
        subnet = ipaddress.ip_network(u"%s" % self.subnet_mask)

        try:
            rc, request_id = request(self.proxy_url + "discovery", method="POST", validate_certs=self.proxy_validate_certs,
                                     force_basic_auth=True, url_username=self.proxy_username, url_password=self.proxy_password,
                                     data=json.dumps({"startIP": str(subnet[0]), "endIP": str(subnet[-1]),
                                                      "connectionTimeout": self.DEFAULT_CONNECTION_TIMEOUT_SEC}))

            # Wait for discover to complete
            try:
                for iteration in range(self.DEFAULT_DISCOVERY_TIMEOUT_SEC):
                    rc, discovered_systems = request(self.proxy_url + "discovery?requestId=%s" % request_id["requestId"],
                                                     validate_certs=self.proxy_validate_certs,
                                                     force_basic_auth=True, url_username=self.proxy_username, url_password=self.proxy_password)
                    if not discovered_systems["discoverProcessRunning"]:
                        thread_pool = []
                        for discovered_system in discovered_systems["storageSystems"]:
                            addresses = []
                            for controller in discovered_system["controllers"]:
                                addresses.extend(controller["ipAddresses"])

                            # Storage systems with embedded web services.
                            if "https" in discovered_system["supportedManagementPorts"] and self.prefer_embedded:

                                thread = threading.Thread(target=self.test_systems_found,
                                                          args=(self.systems_found, discovered_system["serialNumber"], discovered_system["label"], addresses))
                                thread_pool.append(thread)
                                thread.start()

                            # Storage systems without embedded web services.
                            else:
                                self.systems_found.update({discovered_system["serialNumber"]: {"api_urls": [self.proxy_url],
                                                                                               "label": discovered_system["label"],
                                                                                               "addresses": addresses,
                                                                                               "proxy_ssid": "",
                                                                                               "proxy_required": True}})
                        for thread in thread_pool:
                            thread.join()
                        break
                    sleep(1)
                else:
                    self.module.fail_json(msg="Timeout waiting for array discovery process. Subnet [%s]" % self.subnet_mask)
            except Exception as error:
                self.module.fail_json(msg="Failed to get the discovery results. Error [%s]." % to_native(error))
        except Exception as error:
            self.module.fail_json(msg="Failed to initiate array discovery. Error [%s]." % to_native(error))

    def update_proxy_with_proxy_ssid(self):
        """Determine the current proxy ssid for all discovered-proxy_required storage systems."""
        # Discover all added storage systems to the proxy.
        systems = []
        try:
            rc, systems = request(self.proxy_url + "storage-systems", validate_certs=self.proxy_validate_certs,
                                  force_basic_auth=True, url_username=self.proxy_username, url_password=self.proxy_password)
        except Exception as error:
            self.module.fail_json(msg="Failed to ascertain storage systems added to Web Services Proxy.")

        for system_key, system_info in self.systems_found.items():
            if system_info["proxy_required"]:
                for system in systems:
                    if system_key == system["chassisSerialNumber"]:
                        system_info["proxy_ssid"] = system["id"]

    def discover(self):
        """Discover E-Series storage systems."""
        missing_packages = []
        if not HAS_IPADDRESS:
            missing_packages.append("ipaddress")

        if missing_packages:
            self.module.fail_json(msg="Python packages are missing! Packages [%s]." % ", ".join(missing_packages))

        if self.proxy_url:
            self.proxy_discover()
            self.update_proxy_with_proxy_ssid()
        else:
            self.no_proxy_discover()

        self.module.exit_json(msg="Discover process complete.", systems_found=self.systems_found, changed=False)


def main():
    discover = NetAppESeriesDiscover()
    discover.discover()


if __name__ == "__main__":
    main()
