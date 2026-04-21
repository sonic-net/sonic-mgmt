#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell EMC
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_pki
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_pki
version_added: 2.3.0
short_description: 'Manages PKI attributes of Enterprise Sonic'
description: 'Manages PKI attributes of Enterprise Sonic'
author: Eric Seifert (@seiferteric)
notes:
  - 'Tested against Dell Enterprise SONiC 4.1.0'
options:
  config:
    description: The provided configuration
    type: dict
    suboptions:
      trust_stores:
        description: Store of CA Certificates
        type: list
        elements: dict
        suboptions:
          name:
            type: str
            required: True
            description: The name of the Trust Store
          ca_name:
            type: list
            elements: str
            description: List of CA certificates in the trust store.
      security_profiles:
        description: Application Security Profiles
        type: list
        elements: dict
        suboptions:
          profile_name:
            type: str
            required: True
            description: Profile Name
          certificate_name:
            type: str
            description: Host Certificate Name
          trust_store:
            type: str
            description: Name of associated trust_store
          revocation_check:
            description: Require certificate revocation check succeeds
            type: bool
          peer_name_check:
            description: Require peer name is verified
            type: bool
          key_usage_check:
            description: Require key usage is enforced
            type: bool
          cdp_list:
            description: Global list of CDP's
            type: list
            elements: str
          ocsp_responder_list:
            description: Global list of OCSP responders
            type: list
            elements: str
  state:
    description:
      - The state of the configuration after module completion.
    type: str
    choices: ['merged', 'deleted', 'replaced', 'overridden']
    default: merged
"""

EXAMPLES = """
# Using "merged" state for initial config
#
# Before state:
# -------------
#
# sonic# show running-configuration | grep crypto
# sonic#
#
- name: "Initial Config"
  dellemc.enterprise_sonic.sonic_pki:
    config:
      security_profiles:
        - profile_name: rest
          ocsp_responder_list:
            - http://example.com/ocspa
            - http://example.com/ocspb
          certificate_name: host
          trust_store: default-ts
      trust_stores:
        - name: default-ts
          ca_name:
            - CA2
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration | grep crypto
# crypto trust_store default-ts ca-cert CA2
# crypto security-profile rest
# crypto security-profile trust_store rest default-ts
# crypto security-profile certificate rest host
# crypto security-profile ocsp-list rest http://example.com/ocspa,http://example.com/ocspb

# Using "deleted" state to remove configuration
#
# Before state:
# ------------
#
# sonic# show running-configuration | grep crypto
# crypto trust_store default-ts ca-cert CA2
# crypto security-profile rest
# crypto security-profile trust_store rest default-ts
# crypto security-profile certificate rest host
# crypto security-profile ocsp-list rest http://example.com/ocsp
#
- name: PKI Delete Test
  hosts: datacenter
  gather_facts: true
  connection: httpapi
  tasks:
    - name: Remove trust_store from security-profile
      dellemc.enterprise_sonic.sonic_pki:
        config:
          security_profiles:
            - profile_name: rest
              trust_store: default-ts
        state: deleted
# After state:
# ------------
#
# sonic# show running-configuration | grep crypto
# crypto trust_store default-ts ca-cert CA2
# crypto security-profile rest
# crypto security-profile certificate rest host
# crypto security-profile ocsp-list rest http://example.com/ocsp

# Using "overridden" state

# Before state:
# ------------
#
# sonic# show running-configuration | grep crypto
# crypto trust_store default-ts ca-cert CA2
# crypto security-profile rest
# crypto security-profile trust_store rest default-ts
# crypto security-profile certificate rest host
# crypto security-profile ocsp-list rest http://example.com/ocspa,http://example.com/ocspb
#
- name: "Overridden Config"
  dellemc.enterprise_sonic.sonic_pki:
    config:
      security_profiles:
        - profile_name: telemetry
          ocsp_responder_list:
            - http://example.com/ocspb
          revocation_check: true
          trust_store: telemetry-ts
          certificate_name: host
      trust_stores:
        - name: telemetry-ts
          ca_name: CA
    state: overridden
# After state:
# -----------
#
# sonic# show running-configuration | grep crypto
# crypto trust_store telemetry-ts ca-cert CA
# crypto security-profile telemetry revocation_check true
# crypto security-profile trust_store telemetry telemetry-ts
# crypto security-profile certificate telemetry host
# crypto security-profile ocsp-list telemetry http://example.com/ocspb

# Using "replaced" state to update config

# Before state:
# ------------
#
# sonic# show running-configuration | grep crypto
# crypto trust_store default-ts ca-cert CA2
# crypto security-profile rest
# crypto security-profile trust_store rest default-ts
# crypto security-profile certificate rest host
# crypto security-profile ocsp-list rest http://example.com/ocspa,http://example.com/ocspb
#
- name: "Replace Config"
  dellemc.enterprise_sonic.sonic_pki:
    config:
      security_profiles:
        - profile_name: rest
          ocsp_responder_list:
            - http://example.com/ocsp
          revocation_check: false
          trust_store: default-ts
          certificate_name: host
    state: replaced
# After state:
# -----------
#
# sonic# show running-configuration | grep crypto
# crypto trust_store default-ts ca-cert CA2
# crypto security-profile rest
# crypto security-profile trust_store rest default-ts
# crypto security-profile certificate rest host
# crypto security-profile ocsp-list rest http://example.com/ocsp
"""

RETURN = """
before:
  description: The configuration prior to the module invocation.
  returned: always
  type: dict
  sample: >
    The configuration returned will always be in the same format
    as the parameters above.
after:
  description: The resulting configuration module invocation.
  returned: when changed
  type: dict
  sample: >
    The configuration returned will always be in the same format
    as the parameters above.
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
  sample: ['command 1', 'command 2', 'command 3']
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.pki.pki import PkiArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.pki.pki import Pki


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=PkiArgs.argument_spec,
                           supports_check_mode=True)

    result = Pki(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
