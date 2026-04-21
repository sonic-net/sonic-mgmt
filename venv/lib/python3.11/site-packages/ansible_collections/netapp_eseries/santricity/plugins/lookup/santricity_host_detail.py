# (c) 2024, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
    name: santricity_host_detail
    author:
        - Nathan Swartz (@swartzn)
        - Vu Tran (@VuTran007)
    short_description: Expands the host information from santricity_host lookup
    description:
        - Expands the host information from santricity_host lookup to include system and port information
    options:
        hosts:
            description:
                - E-Series storage array inventory, hostvars[inventory_hostname].
                - Run na_santricity_facts prior to calling
            required: True
            type: list
            elements: raw
        hosts_info:
            description:
                - The registered results from the setup module from each expected_hosts, hosts_info['results'].
                - Collected results from the setup module for each expected_hosts from the results of the santricity_host lookup plugin.
            required: True
            type: list
            elements: raw
        host_interface_ports:
            description:
                - List of dictionaries containing "stdout_lines" which is a list of iqn/wwpns for each expected_hosts from the results of
                  the santricity_host lookup plugin.
                - Register the results from the shell module that is looped over each host in expected_hosts. The command issued should result
                  in a newline delineated list of iqns, nqns, or wwpns.
            required: True
            type: list
            elements: raw
        protocol:
            description:
                - Storage system interface protocol (iscsi, sas, fc, ib-iser, ib-srp, nvme_ib, nvme_fc, or nvme_roce)
            required: True
            type: str

"""
import re
from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase


class LookupModule(LookupBase):
    def run(self, hosts, hosts_info, host_interface_ports, protocol, **kwargs):
        if isinstance(hosts, list):
            hosts = hosts[0]

        if "expected_hosts" not in hosts:
            raise AnsibleError("Invalid argument: hosts must contain the output from santricity_host lookup plugin.")
        if not isinstance(hosts_info, list):
            raise AnsibleError("Invalid argument: hosts_info must contain the results from the setup module for each"
                               " expected_hosts found in the output of the santricity_host lookup plugin.")
        if not isinstance(host_interface_ports, list):
            raise AnsibleError("Invalid argument: host_interface_ports must contain list of dictionaries containing 'stdout_lines' key"
                               " which is a list of iqns, nqns, or wwpns for each expected_hosts from the results of the santricity_host lookup plugin")
        if protocol not in ["iscsi", "sas", "fc", "ib_iser", "ib_srp", "nvme_ib", "nvme_fc", "nvme_roce"]:
            raise AnsibleError("Invalid argument: protocol must one of the following: iscsi, sas, fc, ib_iser, ib_srp, nvme_ib, nvme_fc, nvme_roce.")

        for host in hosts["expected_hosts"].keys():
            sanitized_hostname = re.sub("[.:-]", "_", host)[:20]

            # Add host information to expected host
            for info in hosts_info:
                if info["item"] == host:

                    # Determine host type
                    if "host_type" not in hosts["expected_hosts"][host].keys():
                        if info["ansible_facts"]["ansible_os_family"].lower() == "windows":
                            hosts["expected_hosts"][host]["host_type"] = "windows"
                        elif info["ansible_facts"]["ansible_os_family"].lower() in ["redhat", "debian", "suse"]:
                            hosts["expected_hosts"][host]["host_type"] = "linux dm-mp"

                    # Update hosts object
                    hosts["expected_hosts"][host].update({"sanitized_hostname": sanitized_hostname, "ports": []})

            # Add SAS ports
            for interface in host_interface_ports:
                if interface["item"] == host and "stdout_lines" in interface.keys():
                    if protocol == "sas":
                        for index, address in enumerate([base[:-1] + str(index) for base in interface["stdout_lines"] for index in range(8)]):
                            label = "%s_%s" % (sanitized_hostname, index)
                            hosts["expected_hosts"][host]["ports"].append({"type": "sas", "label": label, "port": address})
                    elif protocol == "ib_iser" or protocol == "ib_srp":
                        for index, address in enumerate(interface["stdout_lines"]):
                            label = "%s_%s" % (sanitized_hostname, index)
                            hosts["expected_hosts"][host]["ports"].append({"type": "ib", "label": label, "port": address})
                    elif protocol == "nvme_ib":
                        for index, address in enumerate(interface["stdout_lines"]):
                            label = "%s_%s" % (sanitized_hostname, index)
                            hosts["expected_hosts"][host]["ports"].append({"type": "nvmeof", "label": label, "port": address})
                    elif protocol == "nvme_fc":
                        for index, address in enumerate(interface["stdout_lines"]):
                            label = "%s_%s" % (sanitized_hostname, index)
                            hosts["expected_hosts"][host]["ports"].append({"type": "nvmeof", "label": label, "port": address})
                    elif protocol == "nvme_roce":
                        for index, address in enumerate(interface["stdout_lines"]):
                            label = "%s_%s" % (sanitized_hostname, index)
                            hosts["expected_hosts"][host]["ports"].append({"type": "nvmeof", "label": label, "port": address})
                    else:
                        for index, address in enumerate(interface["stdout_lines"]):
                            label = "%s_%s" % (sanitized_hostname, index)
                            hosts["expected_hosts"][host]["ports"].append({"type": protocol, "label": label, "port": address})

        return [hosts]
