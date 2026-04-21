#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2025, Florian Paul Azim Hoberg (@gyptazy) <florian.hoberg@credativ.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
module: proxmox_node
version_added: 1.2.0
short_description: Manage Proxmox VE nodes
description:
  - Manage the Proxmox VE nodes itself.
author: Florian Paul Azim Hoberg (@gyptazy)
attributes:
  check_mode:
    support: full
  diff_mode:
    support: none
options:
  node_name:
    description:
      - The targeted node to perform actions on.
    type: str
    required: true
  power_state:
    description:
      - Manages the power state of the node.
    type: str
    required: false
    choices: ["online", "offline"]
  certificates:
    description:
      - Manages the x509 certificates of the node.
    type: dict
    suboptions:
      cert:
        description:
          - The public certificate file (including chain) in PEM format.
        type: str
      key:
        description:
          - The private key file in PEM format.
        type: str
      state:
        description:
          - Defines the actions for the certificate.
        choices: ["present", "absent"]
        type: str
      restart:
        description:
          - Restart pveproxy to rehash the new certificates.
        type: bool
        default: false
      force:
        description:
          - Overwrite existing custom or ACME certificate files.
        type: bool
        default: false
  dns:
    description:
      - Manages the resolving DNS options of the node.
    type: dict
    suboptions:
      dns1:
        description:
          - The IP address of the first DNS resolver.
        type: str
      dns2:
        description:
          - The IP address of the second DNS resolver.
        type: str
      dns3:
        description:
          - The IP address of the third DNS resolver.
        type: str
      search:
        description:
          - The default search domain.
        type: str
        required: true
  subscription:
    description:
      - Manages the license subscription of the node.
    type: dict
    suboptions:
      state:
        description:
          - Defines the actions for the subscription file.
        choices: ["present", "absent"]
        type: str
      key:
        description:
          - The subscription license key.
        type: str
extends_documentation_fragment:
  - community.proxmox.proxmox.actiongroup_proxmox
  - community.proxmox.proxmox.documentation
  - community.proxmox.attributes
"""

EXAMPLES = r"""
- name: Start a Proxmox VE Node
  community.proxmox.node:
    api_host: proxmoxhost
    api_user: root@pam
    api_password: password123
    validate_certs: false
    node_name: de-cgn01-virt01
    power_state: online
- name: Update SSL certificates on a Proxmox VE Node
  community.proxmox.node:
    api_host: proxmoxhost
    api_user: root@pam
    api_password: password123
    validate_certs: false
    node_name: de-cgn01-virt01
    certificates:
        key: /opt/ansible/key.pem
        cert: /opt/ansible/cert.pem
        state: present
        force: false
- name: Place a subscription license on a Proxmox VE Node
  community.proxmox.node:
    api_host: proxmoxhost
    api_user: root@pam
    api_password: password123
    validate_certs: false
    node_name: de-cgn01-virt01
    subscription:
        state: present
        key: ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ0123456789
"""

RETURN = r"""
certificates:
  description: Status message about the certificate on the node.
  returned: success
  type: str
  sample: "Certificate for node 'dev-virt01' is already present."
changed:
  description: Indicates whether any changes were made.
  returned: success
  type: bool
  sample: true
dns:
  description: Status message about the DNS configuration on the node.
  returned: success
  type: str
  sample: "DNS configuration for node 'dev-virt01' has been updated."
power_state:
  description: Status message about the power state of the node.
  returned: success
  type: str
  sample: "Node 'dev-virt01' is already online."
"""


import ssl
import hashlib
import re
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.proxmox.plugins.module_utils.proxmox import (
    proxmox_auth_argument_spec, ProxmoxAnsible)


class ProxmoxNodeAnsible(ProxmoxAnsible):
    def get_nodes(self):
        nodes = {"nodes": {}}
        for node in self.proxmox_api.nodes.get():
            nodes["nodes"][node["node"]] = {}
            nodes["nodes"][node["node"]]["name"] = node["node"]
            nodes["nodes"][node["node"]]["status"] = node["status"]
        return nodes

    def validate_node_name(self, nodes):
        node_name = self.module.params.get("node_name")
        if node_name not in nodes["nodes"]:
            self.module.fail_json(msg=f"Node '{node_name}' not found in the Proxmox cluster.")

    def read_file(self, file_path):
        try:
            with open(file_path, 'r') as file_handler:
                file_content = file_handler.read()
                return file_content
        except Exception as e:
            self.module.fail_json(msg=f"Failed to read certificate or key file: {e}")

    def get_certificate_fingerprints_file(self, pem_data, hash_alg='sha256'):
        certs = re.findall(
            r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
            pem_data,
            re.DOTALL
        )

        fingerprints = []
        for cert_body in certs:
            full_pem = f"-----BEGIN CERTIFICATE-----{cert_body}-----END CERTIFICATE-----"
            der = ssl.PEM_cert_to_DER_cert(full_pem)
            digest = getattr(hashlib, hash_alg)(der).hexdigest()
            # Format the fingerprint as uppercase hex pairs separated by colons to match Proxmox's output
            # e.g., "A1:B2:C3:D4:E5:F6:G7:H8:I9:J0:K1:L2:M3:N4:O5:P6:Q7:R8:S9:T0"
            formatted = ":".join(digest[i:i + 2].upper() for i in range(0, len(digest), 2))
            fingerprints.append(formatted)
        return fingerprints

    def get_certificate_fingerprints_api(self, certificates):
        fingerprints = []
        for cert in certificates:
            fingerprints.append(cert.get("fingerprint"))
        return fingerprints

    def bool_to_int(self, value):
        if isinstance(value, bool):
            return 1 if value else 0
        elif isinstance(value, int):
            return value
        else:
            self.module.fail_json(msg=f"Invalid boolean value: {value}. Expected a boolean or integer.")

    def dicts_differ(self, d1, d2):
        keys = set(d1) | set(d2)
        return any(d1.get(k) != d2.get(k) for k in keys)

    def power_state(self, nodes):
        node_power_state = self.module.params.get("power_state")
        node_name = self.module.params.get("node_name")
        changed = False
        result_power_state = "Unchanged"

        if node_power_state == "online":
            if nodes["nodes"][node_name]["status"] == "online":
                changed = False
                result_power_state = f"Node '{node_name}' is already online."
            else:
                if not self.module.check_mode:
                    self.proxmox_api.nodes(node_name).wakeonlan.post(node_name=node_name)
                changed = True
                result_power_state = f"Node '{node_name}' has been powered on."

        if node_power_state == "offline":
            if nodes["nodes"][node_name]["status"] != "online":
                changed = False
                result_power_state = f"Node '{node_name}' is already offline."
            else:
                if not self.module.check_mode:
                    self.proxmox_api.nodes(node_name).status.post(command="shutdown")
                changed = True
                result_power_state = f"Node '{node_name}' has been powered off."

        return changed, result_power_state

    def certificates(self):
        node_certificate_state = self.module.params.get("certificates", {}).get("state", "show")
        node_name = self.module.params.get("node_name")
        force = self.bool_to_int(self.module.params.get("certificates", {}).get("force", False))
        changed = False
        result_certificates = "Unchanged"

        try:
            current_cert = self.proxmox_api.nodes(node_name).certificates.custom.get()
        except Exception as e:
            current_cert = self.proxmox_api.nodes(node_name).certificates.info.get()

        if node_certificate_state == "present":
            cert_path = self.module.params.get("certificates", {}).get("cert")
            key_path = self.module.params.get("certificates", {}).get("key")
            cert = self.read_file(cert_path)
            key = self.read_file(key_path)
            fingerprints_file = self.get_certificate_fingerprints_file(cert)
            fingerprints_api = self.get_certificate_fingerprints_api(current_cert)

            if all(fp in fingerprints_api for fp in fingerprints_file):
                changed = False
                result_certificates = f"Certificate for node '{node_name}' is already present."
            else:
                if not self.module.check_mode:
                    try:
                        self.proxmox_api.nodes(node_name).certificates.custom.post(certificates=cert, key=key, force=force)
                    except Exception as e:
                        self.module.fail_json(msg="Failed to upload certificate. Certificate is already present. Please use 'force' to overwrite it.")
                    self.proxmox_api.nodes(node_name).services("pveproxy").restart.post()
                changed = True
                result_certificates = f"Certificate for node '{node_name}' has been uploaded."

        if node_certificate_state == "absent":
            custom_cert = True
            try:
                custom_cert = self.proxmox_api.nodes(node_name).certificates.custom.get()
            except Exception as e:
                custom_cert = False

            if custom_cert:
                if not self.module.check_mode:
                    try:
                        self.proxmox_api.nodes(node_name).certificates.custom.delete()
                    except Exception as e:
                        pass
                    self.proxmox_api.nodes(node_name).services("pveproxy").restart.post()
                changed = True
                result_certificates = f"Certificate for node '{node_name}' has been removed."

        return changed, result_certificates

    def dns(self):
        node_name = self.module.params.get("node_name")
        dns1 = self.module.params.get("dns", {}).get("dns1", None)
        dns2 = self.module.params.get("dns", {}).get("dns2", None)
        dns3 = self.module.params.get("dns", {}).get("dns3", None)
        search = self.module.params.get("dns", {}).get("search", None)
        dns_config_current = self.proxmox_api.nodes(node_name).dns.get()
        changed = False
        result_dns = "Unchanged"

        dns_config = {}
        if dns1:
            dns_config['dns1'] = dns1
        if dns2:
            dns_config['dns2'] = dns2
        if dns3:
            dns_config['dns3'] = dns3
        if search:
            dns_config['search'] = search

        if self.dicts_differ(dns_config_current, dns_config):
            if not self.module.check_mode:
                self.proxmox_api.nodes(node_name).dns.put(**dns_config)
            changed = True
            result_dns = f"DNS configuration for node '{node_name}' has been updated."

        return changed, result_dns

    def subscription(self):
        subscription_state = self.module.params.get("subscription", {}).get("state")
        node_name = self.module.params.get("node_name")
        subscription_current = self.proxmox_api.nodes(node_name).subscription.get()
        changed = False
        result_subscription = "Unchanged"

        if subscription_state == "present":
            license_key = self.module.params.get("subscription", {}).get("key", None)
            if subscription_current.get("key", None) != license_key:
                if not self.module.check_mode:
                    try:
                        self.proxmox_api.nodes(node_name).subscription.put(key=license_key)
                    except Exception as e:
                        self.module.fail_json(msg=f"Failed to upload subscription key: {e}")
                changed = True
                result_subscription = f"License subscription for node '{node_name}' has been uploaded."

        if subscription_state == "absent":
            if subscription_current.get("status", None) != "notfound":
                if not self.module.check_mode:
                    try:
                        self.proxmox_api.nodes(node_name).subscription.delete()
                    except Exception as e:
                        self.module.fail_json(msg=f"Failed to delete subscription key: {e}")
                changed = True
                result_subscription = f"License subscription for node '{node_name}' has been deleted."

        return changed, result_subscription


def main():
    module_args = proxmox_auth_argument_spec()

    node_args = dict(
        node_name=dict(type='str', required=True),
        power_state=dict(choices=['online', 'offline']),
        certificates=dict(
            type='dict',
            options=dict(
                cert=dict(type='str', required=False, no_log=True),
                key=dict(type='str', required=False, no_log=True),
                state=dict(type='str', required=False, choices=['present', 'absent']),
                restart=dict(type='bool', default=False, required=False),
                force=dict(type='bool', default=False, required=False),
            )
        ),
        dns=dict(
            type='dict',
            options=dict(
                dns1=dict(type='str', default=None, required=False),
                dns2=dict(type='str', default=None, required=False),
                dns3=dict(type='str', default=None, required=False),
                search=dict(type='str', required=True),
            )
        ),
        subscription=dict(
            type='dict',
            options=dict(
                state=dict(type='str', required=False, choices=['present', 'absent']),
                key=dict(type='str', default=None, required=False, no_log=True),
            )
        )
    )

    module_args.update(node_args)

    module = AnsibleModule(
        argument_spec=module_args,
        required_one_of=[('api_password', 'api_token_id')],
        required_together=[('api_token_id', 'api_token_secret')],
        supports_check_mode=True,
    )

    # Initialize objects and avoid re-polling the current
    # nodes in the cluster in each function call.
    proxmox = ProxmoxNodeAnsible(module)
    nodes = proxmox.get_nodes()
    proxmox.validate_node_name(nodes)
    result = {"changed": False}

    # Actions
    if module.params.get("power_state") is not None:
        changed, power_result = proxmox.power_state(nodes)
        result["changed"] = result["changed"] or changed
        result["power_state"] = power_result

    if module.params.get("certificates") is not None:
        changed, cert_result = proxmox.certificates()
        result["changed"] = result["changed"] or changed
        result["certificates"] = cert_result

    if module.params.get("dns") is not None:
        changed, dns_result = proxmox.dns()
        result["changed"] = result["changed"] or changed
        result["dns"] = dns_result

    if module.params.get("subscription") is not None:
        changed, subscription_result = proxmox.subscription()
        result["changed"] = result["changed"] or changed
        result["subscription"] = subscription_result

    module.exit_json(**result)


if __name__ == '__main__':
    main()
