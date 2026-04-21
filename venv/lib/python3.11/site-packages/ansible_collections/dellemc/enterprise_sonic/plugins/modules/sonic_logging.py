#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_logging
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: sonic_logging
version_added: 2.1.0
notes:
  - Supports C(check_mode).
short_description: Manage logging configuration on SONiC.
description:
  - This module provides configuration management of logging for devices running SONiC.
author: "M. Zhang (@mingjunzhang2019)"
options:
  config:
    description:
      - Specifies logging related configurations.
    type: dict
    suboptions:
      remote_servers:
        type: list
        elements: dict
        description:
          - Remote logging sever configuration.
        suboptions:
          host:
            type: str
            description:
              - IPv4/IPv6 address or host name of the remote logging server.
            required: true
          remote_port:
            type: int
            description:
              - Destination port number for logging messages sent to the server.
          source_interface:
            type: str
            description:
              - Source interface used as source ip for sending logging packets.
          message_type:
            type: str
            description:
              - Type of messages that remote server receives. Defaults to "log" value.
            choices:
              - log
              - event
              - audit
              - auditd-system
          severity:
            version_added: 3.1.0
            type: str
            description:
              - The log severity filter for remote syslog server. Defaults to "notice" value.
            choices:
              - debug
              - info
              - notice
              - warning
              - error
              - critical
              - alert
              - emergency
          protocol:
            type: str
            description:
              - Type of the protocol for sending the  messages. Defaults to "UDP" value.
            choices:
              - TCP
              - TLS
              - UDP
          vrf:
            type: str
            description:
              - VRF name used by remote logging server.
      security_profile:
        type: str
        version_added: 3.1.0
        description:
          - Specifies the security profile name for the global syslog settings.
  state:
    description:
      - The state of the configuration after module completion.
    type: str
    choices:
      - merged
      - replaced
      - overridden
      - deleted
    default: merged
"""

EXAMPLES = """
# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show logging servers
# ----------------------------------------------------------------------------------------------------------
# HOST            PORT      SOURCE-INTERFACE    VRF            MESSAGE-TYPE   SEVERITY            PROTOCOL
# ----------------------------------------------------------------------------------------------------------
# 10.11.0.2       5         Ethernet24          -              event          notice              udp
# 10.11.1.1       616       Ethernet8           -              log            alert               tcp
# log1.dell.com   6         Ethernet28          -              audit          notice              udp
# 10.11.1.2       116       Ethernet6           -              log            notice              tls
#
# sonic# show running-configuration | grep logging
# !
# logging security-profile default
# !

- name: Delete logging server configuration
  sonic_logging:
    config:
      remote_servers:
        - host: 10.11.0.2
        - host: log1.dell.com
        - host: 10.11.1.1
          message_type: log
          protocol: tcp
          source_interface: Ethernet8
          severity: alert
      security_profile: "default"
    state: deleted

# After state:
# ------------
#
# sonic# show logging servers
# ----------------------------------------------------------------------------------------------------------
# HOST            PORT      SOURCE-INTERFACE    VRF            MESSAGE-TYPE   SEVERITY            PROTOCOL
# ----------------------------------------------------------------------------------------------------------
# 10.11.1.1       616       -                   -              log            notice              udp
# 10.11.1.2       116       Ethernet6           -              log            notice              tls
#
# sonic# show running-configuration | grep logging
# sonic#
#
# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show logging servers
# ----------------------------------------------------------------------------------------------------------
# HOST            PORT      SOURCE-INTERFACE    VRF            MESSAGE-TYPE   SEVERITY            PROTOCOL
# ----------------------------------------------------------------------------------------------------------
# 10.11.1.1       616       Ethernet8           -              log            notice              tcp
#
# sonic# show running-configuration | grep logging
# sonic#
- name: Merge logging server configuration
  sonic_logging:
    config:
      remote_servers:
        - host: 10.11.0.2
          remote_port: 5
          protocol: TCP
          source_interface: Ethernet24
          message_type: event
        - host: 10.11.0.1
          remote_port: 4
          protocol: TLS
          source_interface: Ethernet2
        - host: 10.11.1.1
          severity: error
        - host: log1.dell.com
          remote_port: 6
          protocol: udp
          source_interface: Ethernet28
          message_type: audit
      security_profile: "default"
    state: merged

# After state:
# ------------
# sonic# show logging servers
# ----------------------------------------------------------------------------------------------------------
# HOST            PORT      SOURCE-INTERFACE    VRF            MESSAGE-TYPE   SEVERITY            PROTOCOL
# ----------------------------------------------------------------------------------------------------------
# 10.11.0.2       5         Ethernet24          -              event          notice              udp
# 10.11.0.1       4         Ethernet2           -              log            notice              tls
# 10.11.1.1       616       Ethernet8           -              log            error               tcp
# log1.dell.com   6         Ethernet28          -              audit          notice              udp
# sonic# show running-configuration | grep logging
# !
# logging security-profile default
# !
#
#
# Using "overridden" state
#
# Before state:
# -------------
#
# sonic# show logging servers
# ----------------------------------------------------------------------------------------------------------
# HOST            PORT      SOURCE-INTERFACE    VRF            MESSAGE-TYPE   SEVERITY            PROTOCOL
# ----------------------------------------------------------------------------------------------------------
# 10.11.1.1       616       Ethernet8           -              log            notice              tcp
# 10.11.1.2       626       Ethernet16          -              event          emergency           udp
# 10.11.1.3       626       Ethernet14          -              log            notice              tls
#
# sonic# show running-configuration | grep logging
# !
# logging security-profile default
# !
- name: Override logging server configuration
  sonic_logging:
    config:
      remote_servers:
        - host: 10.11.1.2
          remote_port: 622
          protocol: TCP
          source_interface: Ethernet24
          message_type: audit
          severity: alert
    state: overridden
#
# After state:
# ------------
# sonic# show logging servers
# ----------------------------------------------------------------------------------------------------------
# HOST            PORT      SOURCE-INTERFACE    VRF            MESSAGE-TYPE   SEVERITY            PROTOCOL
# ----------------------------------------------------------------------------------------------------------
# 10.11.1.2       622       Ethernet24          -              audit          alert               tcp
# sonic# show running-configuration | grep logging
# sonic#
#
# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show logging servers
# ----------------------------------------------------------------------------------------------------------
# HOST            PORT      SOURCE-INTERFACE    VRF            MESSAGE-TYPE   SEVERITY            PROTOCOL
# ----------------------------------------------------------------------------------------------------------
# 10.11.1.1       616       Ethernet8           -              log            notice              tcp
# 10.11.1.2       626       Ethernet16          -              event          notice              udp
#
# sonic# show running-configuration | grep logging
# sonic#
- name: Replace logging server configuration
  sonic_logging:
    config:
      remote_servers:
        - host: 10.11.1.2
          remote_port: 622
          protocol: UDP
          message_type: audit
          severity: debug
      security_profile: "default"
    state: replaced
#
# After state:
# ------------
#
# "MESSAGE-TYPE" has default value of "log"
#
# ----------------------------------------------------------------------------------------------------------
# HOST            PORT      SOURCE-INTERFACE    VRF            MESSAGE-TYPE   SEVERITY            PROTOCOL
# ----------------------------------------------------------------------------------------------------------
# 10.11.1.1       616       Ethernet8           -              log            notice              tcp
# 10.11.1.2       622       -                   -              audit          debug               udp
# sonic# show running-configuration | grep logging
# !
# logging security-profile default
# !
#
"""

RETURN = """
before:
  description: The configuration prior to the module invocation.
  type: list
  returned: always
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
  description: The generated configuration module invocation.
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.logging.logging import LoggingArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.logging.logging import Logging


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(argument_spec=LoggingArgs.argument_spec,
                           supports_check_mode=True)

    result = Logging(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
