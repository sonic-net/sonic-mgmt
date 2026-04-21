#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_mgmt_servers
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_mgmt_servers
version_added: 2.5.0
notes:
- Tested against Enterprise SONiC Distribution by Dell Technologies.
- Supports C(check_mode).
short_description: Manage management servers configuration on SONiC
description:
  - This module provides configuration management of management servers for devices running SONiC
author: S. Talabi (@stalabi1)
options:
  config:
    description:
      - Management servers configuration
    type: dict
    suboptions:
      rest:
        description:
          REST server configuration
        type: dict
        suboptions:
          api_timeout:
            description:
              - Maximum time in seconds the REST server will wait for a REST API request-response cycle to complete
              - Range 0-4294967295
            type: int
            default: 900
          client_auth:
            description:
              - Client authentication methods list
              - Specify as a comma separated list. Options for list are password, jwt, cert, and none.
            type: str
            default: password,jwt
          log_level:
            description:
              - Log level of REST server, range 0-255
            type: int
            default: 0
          port:
            description:
              - Port that the REST server listens on, range 0-65535
            type: int
            default: 443
          read_timeout:
            description:
              - Maximum time in seconds the REST server will wait for an HTTP request-response cycle to complete
              - Range 0-4294967295
            type: int
            default: 15
          req_limit:
            description:
              - Maximum number of concurrent requests that the client can make to the REST server
              - Range 0-4294967295
            type: int
          security_profile:
            description:
              - Name of security profile
            type: str
          shutdown:
            description:
              - Enables/disables REST server from listening on the port
            type: bool
          vrf:
            description:
              - Name of VRF
            type: str
            choices:
              - mgmt
          cipher_suite:
            version_added: 3.1.0
            description:
              - Cipher suites used for TLS connection with the clients
              - Specify as a comma separated list. Options are ecdhe-ecdsa-with-aes-256-gcm-SHA384,
                 ecdhe-ecdsa-with-chacha20-poly1305-SHA256 and ecdhe-ecdsa-with-aes-128-gcm-SHA256.
            type: str
            default: ecdhe-ecdsa-with-aes-256-gcm-SHA384,ecdhe-ecdsa-with-chacha20-poly1305-SHA256,ecdhe-ecdsa-with-aes-128-gcm-SHA256
      telemetry:
        description:
          - Telemetry server configuration
        type: dict
        suboptions:
          api_timeout:
            description:
              - Maximum time in seconds the telemetry server will wait for a gNMI request-response cycle to complete
              - Range 0-4294967295
            type: int
            default: 0
          client_auth:
            description:
              - Client authentication methods list
              - Specify as a comma separated list. Options for list are password, jwt, cert, and none.
            type: str
            default: password,jwt
          jwt_refresh:
            description:
              - Duration of time in seconds before JWT expires and can be refreshed
              - Range 0-4294967295
            type: int
            default: 900
          jwt_valid:
            description:
              - Duration of time in seconds for which JWT is valid on the telemetry server
              - Range 0-4294967295
            type: int
            default: 3600
          log_level:
            description:
              - Log level of telemetry server, range 0-255
            type: int
            default: 0
          port:
            description:
              - Port that the telemetry server listens on, range 0-65535
            type: int
            default: 8080
          security_profile:
            description:
              - Name of security profile
            type: str
          vrf:
            description:
              - Name of VRF
            type: str
            choices:
              - mgmt
  state:
    description:
      - The state of the configuration after module completion.
    type: str
    choices:
      - merged
      - deleted
      - overridden
      - replaced
    default: merged
"""

EXAMPLES = """
# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show ip rest
#
# Log level is 0
# Port is 443
# Request limit is not-set
# Read timeout is 15 seconds
# Client authentication mode is password,jwt
# Security profile is not-set
# API timeout is 900 seconds
# vrf is not-set
# Cipher suite is ecdhe-ecdsa-with-aes-256-gcm-SHA384,ecdhe-ecdsa-with-chacha20-poly1305-SHA256,ecdhe-ecdsa-with-aes-128-gcm-SHA256
#
# sonic# show ip telemetry
#
# Log level is 0
# JWT valid is 3600 seconds
# JWT refresh is 900 seconds
# Port is 8080
# Client authentication mode is password,jwt
# Security profile is not-set
# API timeout is 0 seconds
# vrf is not-set

- name: Merge mgmt servers configuration
  dellemc.enterprise_sonic.sonic_mgmt_servers:
    config:
      rest:
        api_timeout: 120
        client_auth: password
        log_level: 6
        port: 443
        read_timeout: 60
        req_limit: 100
        security_profile: profile1
        shutdown: true
        vrf: mgmt
        cipher_suite: ecdhe-ecdsa-with-aes-256-gcm-SHA384
      telemetry:
        api_timeout: 45
        client_auth: cert,jwt
        jwt_refresh: 80
        jwt_valid: 300
        log_level: 10
        port: 1234
        security_profile: profile2
        vrf: mgmt
    state: merged

# After state:
# ------------
#
# sonic# show ip rest
#
# Log level is 6
# Port is 443, disabled
# Request limit is 100
# Read timeout is 60 seconds
# Client authentication mode is password
# Security profile is profile1
# API timeout is 120 seconds
# vrf is mgmt
# Cipher suite is ecdhe-ecdsa-with-aes-256-gcm-SHA384
#
# sonic# show ip telemetry
#
# Log level is 10
# JWT valid is 300 seconds
# JWT refresh is 80 seconds
# Port is 1234
# Client authentication mode is cert,jwt
# Security profile is profile2
# API timeout is 45 seconds
# vrf is mgmt


# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show ip rest
#
# Log level is 6
# Port is 443, disabled
# Request limit is 100
# Read timeout is 60 seconds
# Client authentication mode is password
# Security profile is profile1
# API timeout is 120 seconds
# vrf is mgmt
# Cipher suite is ecdhe-ecdsa-with-aes-256-gcm-SHA384
#
# sonic# show ip telemetry
#
# Log level is 10
# JWT valid is 300 seconds
# JWT refresh is 80 seconds
# Port is 1234
# Client authentication mode is cert,jwt
# Security profile is profile2
# API timeout is 45 seconds
# vrf is mgmt

- name: Replace mgmt servers configuration
  dellemc.enterprise_sonic.sonic_mgmt_servers:
    config:
      rest:
        api_timeout: 180
        vrf: mgmt
        cipher_suite: ecdhe-ecdsa-with-aes-256-gcm-SHA384,ecdhe-ecdsa-with-chacha20-poly1305-SHA256
      telemetry:
        log_level: 25
        security_profile: profile2
    state: replaced

# After state:
# ------------
#
# sonic# show ip rest
#
# Log level is 0
# Port is 443
# Request limit is not-set
# Read timeout is 15 seconds
# Client authentication mode is password,jwt
# Security profile is not-set
# API timeout is 180 seconds
# vrf is mgmt
# Cipher suite is ecdhe-ecdsa-with-aes-256-gcm-SHA384,ecdhe-ecdsa-with-chacha20-poly1305-SHA256
#
# sonic# show ip telemetry
#
# Log level is 25
# JWT valid is 3600 seconds
# JWT refresh is 900 seconds
# Port is 8080
# Client authentication mode is password,jwt
# Security profile is profile2
# API timeout is 0 seconds
# vrf is not-set


# Using "overridden" state
#
# Before state:
# -------------
#
# sonic# show ip rest
#
# Log level is 6
# Port is 443, disabled
# Request limit is 100
# Read timeout is 60 seconds
# Client authentication mode is password
# Security profile is profile1
# API timeout is 120 seconds
# vrf is mgmt
# Cipher suite is ecdhe-ecdsa-with-aes-256-gcm-SHA384,ecdhe-ecdsa-with-chacha20-poly1305-SHA256
#
# sonic# show ip telemetry
#
# Log level is 10
# JWT valid is 300 seconds
# JWT refresh is 80 seconds
# Port is 1234
# Client authentication mode is cert,jwt
# Security profile is profile2
# API timeout is 45 seconds
# vrf is mgmt

- name: Override mgmt servers configuration
  dellemc.enterprise_sonic.sonic_mgmt_servers:
    config:
      rest:
        api_timeout: 120
        client_auth: password
        log_level: 6
        port: 443
        read_timeout: 60
        req_limit: 100
        security_profile: profile1
        shutdown: true
        vrf: mgmt
        cipher_suite: ecdhe-ecdsa-with-aes-128-gcm-SHA256,ecdhe-ecdsa-with-aes-256-gcm-SHA384
    state: overridden

# After state:
# ------------
#
# sonic# show ip rest
#
# Log level is 6
# Port is 443, disabled
# Request limit is 100
# Read timeout is 60 seconds
# Client authentication mode is password
# Security profile is profile1
# API timeout is 120 seconds
# vrf is mgmt
# Cipher suite is ecdhe-ecdsa-with-aes-128-gcm-SHA256,ecdhe-ecdsa-with-aes-256-gcm-SHA384
#
# sonic# show ip telemetry
#
# Log level is 0
# JWT valid is 3600 seconds
# JWT refresh is 900 seconds
# Port is 8080
# Client authentication mode is password,jwt
# Security profile is not-set
# API timeout is 0 seconds
# vrf is not-set


# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show ip rest
#
# Log level is 6
# Port is 443, disabled
# Request limit is 100
# Read timeout is 60 seconds
# Client authentication mode is password
# Security profile is profile1
# API timeout is 120 seconds
# vrf is mgmt
# Cipher suite is ecdhe-ecdsa-with-aes-128-gcm-SHA256,ecdhe-ecdsa-with-aes-256-gcm-SHA384
#
# sonic# show ip telemetry
#
# Log level is 10
# JWT valid is 300 seconds
# JWT refresh is 80 seconds
# Port is 1234
# Client authentication mode is cert,jwt
# Security profile is profile2
# API timeout is 45 seconds
# vrf is mgmt

- name: Delete mgmt servers configuration
  dellemc.enterprise_sonic.sonic_mgmt_servers:
    config:
      rest:
        api_timeout: 120
        client_auth: password
        log_level: 6
        port: 443
        read_timeout: 60
        req_limit: 100
        security_profile: profile1
        shutdown: true
        vrf: mgmt
        cipher_suite: ecdhe-ecdsa-with-aes-256-gcm-SHA384,ecdhe-ecdsa-with-aes-128-gcm-SHA256
      telemetry:
        api_timeout: 45
        client_auth: cert,jwt
        jwt_refresh: 80
        jwt_valid: 300
        log_level: 10
        port: 1234
        security_profile: profile2
        vrf: mgmt
    state: deleted

# After state:
# ------------
#
# sonic# show ip rest
#
# Log level is 0
# Port is 443
# Request limit is not-set
# Read timeout is 15 seconds
# Client authentication mode is password,jwt
# Security profile is not-set
# API timeout is 900 seconds
# vrf is not-set
# Cipher suite is ecdhe-ecdsa-with-aes-256-gcm-SHA384,ecdhe-ecdsa-with-chacha20-poly1305-SHA256,ecdhe-ecdsa-with-aes-128-gcm-SHA256
#
# sonic# show ip telemetry
#
# Log level is 0
# JWT valid is 3600 seconds
# JWT refresh is 900 seconds
# Port is 8080
# Client authentication mode is password,jwt
# Security profile is not-set
# API timeout is 0 seconds
# vrf is not-set
"""

RETURN = """
before:
  description: The configuration prior to the module invocation.
  returned: always
  type: list
  sample: >
    The configuration returned will always be in the same format
    as the parameters above.
after:
  description: The resulting configuration module invocation.
  returned: when changed
  type: list
  sample: >
    The configuration returned will always be in the same format
    as the parameters above.
after(generated):
  description: The generated configuration from module invocation.
  returned: when C(check_mode)
  type: list
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.mgmt_servers.mgmt_servers import Mgmt_serversArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.mgmt_servers.mgmt_servers import Mgmt_servers


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=Mgmt_serversArgs.argument_spec,
                           supports_check_mode=True)

    result = Mgmt_servers(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
