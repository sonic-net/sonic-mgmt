#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for nxos_ntp_global
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: nxos_ntp_global
short_description: NTP Global resource module.
description:
- This module manages ntp configuration on devices running Cisco NX-OS.
version_added: 2.6.0
notes:
- Tested against NX-OS 9.3.6 on Cisco Nexus Switches.
- This module works with connection C(network_cli) and C(httpapi).
- Tested against Cisco MDS NX-OS 9.2(2) with connection C(network_cli).
author: Nilashish Chakraborty (@NilashishC)
options:
  running_config:
    description:
    - This option is used only with state I(parsed).
    - The value of this option should be the output received from the NX-OS device
      by executing the command B(show running-config ntp).
    - The state I(parsed) reads the configuration from C(running_config) option and
      transforms it into Ansible structured data as per the resource module's argspec
      and the value is then returned in the I(parsed) key within the result.
    type: str
  config:
    description: A dict of ntp configuration.
    type: dict
    suboptions:
      access_group:
        description:
          - NTP access-group.
          - This option is unsupported on MDS switches.
        type: dict
        suboptions:
          match_all:
            description: Scan ACLs present in all ntp access groups.
            type: bool
          peer:
            description: Access-group peer.
            type: list
            elements: dict
            suboptions:
              access_list:
                description: Name of access list.
                type: str
          query_only:
            description: Access-group query-only.
            type: list
            elements: dict
            suboptions:
              access_list:
                description: Name of access list.
                type: str
          serve:
            description: Access-group serve.
            type: list
            elements: dict
            suboptions:
              access_list:
                description: Name of access list.
                type: str
          serve_only:
            description: Access-group serve-only.
            type: list
            elements: dict
            suboptions:
              access_list:
                description: Name of access list.
                type: str
      allow:
        description: Enable/Disable the packets.
        type: dict
        suboptions:
          control:
            description: Control mode packets.
            type: dict
            suboptions:
              rate_limit:
                description: Rate-limit delay.
                type: int
          private:
            description: Enable/Disable Private mode packets.
            type: bool
      authenticate:
        description: Enable/Disable authentication.
        type: bool
      authentication_keys:
        description: NTP authentication key.
        type: list
        elements: dict
        suboptions:
          id:
            description: Authentication key number (range 1-65535).
            type: int
          key:
            description: Authentication key.
            type: str
          encryption:
            description:
              - 0 for Clear text
              - 7 for Encrypted
            type: int
      logging:
        description: Enable/Disable logging of NTPD Events.
        type: bool
      master:
        description:
          - Act as NTP master clock.
          - This option is unsupported on MDS switches.
        type: dict
        suboptions:
          stratum:
            description: Stratum number.
            type: int
      passive:
        description:
          - NTP passive command.
          - This option is unsupported on MDS switches.
        type: bool
      peers:
        description: NTP Peers.
        type: list
        elements: dict
        suboptions:
          peer:
            description: Hostname/IP address of the NTP Peer.
            type: str
          key_id:
            description: Keyid to be used while communicating to this server.
            type: int
          maxpoll:
            description:
              - Maximum interval to poll a peer.
              - Poll interval in secs to a power of 2.
            type: int
          minpoll:
            description:
              - Minimum interval to poll a peer.
              - Poll interval in secs to a power of 2.
            type: int
          prefer:
            description:
              - Preferred Server.
            type: bool
          vrf:
            description:
              - Display per-VRF information.
              - This option is unsupported on MDS switches.
            type: str
            aliases: ["use_vrf"]
      servers:
        description: NTP servers.
        type: list
        elements: dict
        suboptions:
          server:
            description: Hostname/IP address of the NTP Peer.
            type: str
          key_id:
            description: Keyid to be used while communicating to this server.
            type: int
          maxpoll:
            description:
              - Maximum interval to poll a peer.
              - Poll interval in secs to a power of 2.
            type: int
          minpoll:
            description:
              - Minimum interval to poll a peer.
              - Poll interval in secs to a power of 2.
            type: int
          prefer:
            description:
              - Preferred Server.
            type: bool
          vrf:
            description:
              - Display per-VRF information.
              - This option is not applicable for MDS switches.
            type: str
            aliases: ["use_vrf"]
      source:
        description:
          - Source of NTP packets.
          - This option is unsupported on MDS switches.
        type: str
      source_interface:
        description: Source interface sending NTP packets.
        type: str
      trusted_keys:
        description: NTP trusted-key number.
        type: list
        elements: dict
        suboptions:
          key_id:
            description: Trusted-Key number.
            type: int
  state:
    description:
    - The state the configuration should be left in.
    - The states I(replaced) and I(overridden) have identical
      behaviour for this module.
    - Please refer to examples for more details.
    type: str
    choices:
    - merged
    - replaced
    - overridden
    - deleted
    - parsed
    - gathered
    - rendered
    default: merged
"""

EXAMPLES = """
# Using merged

# Before state:
# -------------
# nxos-9k-rdo# show running-config ntp
# nxos-9k-rdo#

- name: Merge the provided configuration with the existing running configuration
  cisco.nxos.nxos_ntp_global: &id001
    config:
      access_group:
        peer:
          - access_list: PeerAcl1
        serve:
          - access_list: ServeAcl1
      authenticate: true
      authentication_keys:
        - id: 1001
          key: vagwwtKfkv
          encryption: 7
        - id: 1002
          key: vagwwtKfkvgthz
          encryption: 7
      logging: true
      master:
        stratum: 2
      peers:
        - peer: 192.0.2.1
          key_id: 1
          maxpoll: 15
          minpoll: 5
          vrf: default
        - peer: 192.0.2.2
          key_id: 2
          prefer: true
          vrf: siteA
      servers:
        - server: 198.51.100.1
          key_id: 2
          vrf: default
        - server: 203.0.113.1
          key_id: 1
          vrf: siteB

# Task output
# -------------
#  before: {}
#
#  commands:
#    - "ntp authenticate"
#    - "ntp logging"
#    - "ntp master 2"
#    - "ntp authentication-keys 1001 md5 vagwwtKfkv 7"
#    - "ntp authentication-keys 1002 md5 vagwwtKfkvgthz 7"
#    - "ntp peer 192.0.2.1 use-vrf default key 1 minpoll 5 maxpoll 15"
#    - "ntp peer 192.0.2.2 prefer use-vrf siteA key 2"
#    - "ntp server 198.51.100.1 use-vrf default key 2"
#    - "ntp server 203.0.113.1 use-vrf siteB key 1"
#    - "ntp access-group peer PeerAcl1"
#    - "ntp access-group serve ServeAcl1"
#
#  after:
#    access_group:
#      peer:
#        - access_list: PeerAcl1
#      serve:
#       - access_list: ServeAcl1
#    authenticate: true
#    authentication_keys:
#      - id: 1001
#        key: vagwwtKfkv
#        encryption: 7
#      - id: 1002
#        key: vagwwtKfkvgthz
#        encryption: 7
#    logging: true
#    master:
#     stratum: 2
#    peers:
#      - peer: 192.0.2.1
#        key_id: 1
#        maxpoll: 15
#        minpoll: 5
#        vrf: default
#      - peer: 192.0.2.2
#        key_id: 2
#        prefer: true
#        vrf: siteA
#    servers:
#      - server: 198.51.100.1
#        key_id: 2
#        vrf: default
#      - server: 203.0.113.1
#        key_id: 1
#        vrf: siteB

# After state:
# ------------
# nxos-9k-rdo# show running-config ntp
# ntp authenticate
# ntp logging
# ntp master 2
# ntp authentication-keys 1001 md5 vagwwtKfkv 7
# ntp authentication-keys 1002 md5 vagwwtKfkvgthz 7
# ntp peer 192.0.2.1 use-vrf default key 1 minpoll 5 maxpoll 15
# ntp peer 192.0.2.2 prefer use-vrf siteA key 2
# ntp server 198.51.100.1 use-vrf default key 2
# ntp server 203.0.113.1 use-vrf siteB key 1
# ntp access-group peer PeerAcl1
# ntp access-group serve ServeAcl1

# Using replaced

# Before state:
# ------------
# nxos-9k-rdo# show running-config ntp
# ntp authenticate
# ntp logging
# ntp master 2
# ntp authentication-keys 1001 md5 vagwwtKfkv 7
# ntp authentication-keys 1002 md5 vagwwtKfkvgthz 7
# ntp peer 192.0.2.1 use-vrf default key 1 minpoll 5 maxpoll 15
# ntp peer 192.0.2.2 prefer use-vrf siteA key 2
# ntp server 198.51.100.1 use-vrf default key 2
# ntp server 203.0.113.1 use-vrf siteB key 1
# ntp access-group peer PeerAcl1
# ntp access-group serve ServeAcl1

- name: Replace logging global configurations of listed logging global with provided configurations
  cisco.nxos.nxos_ntp_global:
    config:
      access_group:
        peer:
          - access_list: PeerAcl2
        serve:
          - access_list: ServeAcl2
      logging: true
      master:
        stratum: 2
      peers:
        - peer: 192.0.2.1
          key_id: 1
          maxpoll: 15
          minpoll: 5
          vrf: default
        - peer: 192.0.2.5
          key_id: 2
          prefer: true
          vrf: siteA
      servers:
        - server: 198.51.100.1
          key_id: 2
          vrf: default
    state: replaced

# Task output
# -------------
#  before:
#    access_group:
#      peer:
#        - access_list: PeerAcl1
#      serve:
#       - access_list: ServeAcl1
#    authenticate: true
#    authentication_keys:
#      - id: 1001
#        key: vagwwtKfkv
#        encryption: 7
#      - id: 1002
#        key: vagwwtKfkvgthz
#        encryption: 7
#    logging: true
#    master:
#     stratum: 2
#    peers:
#      - peer: 192.0.2.1
#        key_id: 1
#        maxpoll: 15
#        minpoll: 5
#        vrf: default
#      - peer: 192.0.2.2
#        key_id: 2
#        prefer: true
#        vrf: siteA
#    servers:
#      - server: 198.51.100.1
#        key_id: 2
#        vrf: default
#      - server: 203.0.113.1
#        key_id: 1
#        vrf: siteB
#
#  commands:
#    - "no ntp authenticate"
#    - "no ntp authentication-keys 1001 md5 vagwwtKfkv 7"
#    - "no ntp authentication-keys 1002 md5 vagwwtKfkvgthz 7"
#    - "ntp peer 192.0.2.5 prefer use-vrf siteA key 2"
#    - "no ntp peer 192.0.2.2 prefer use-vrf siteA key 2"
#    - "no ntp server 203.0.113.1 use-vrf siteB key 1"
#    - "ntp access-group peer PeerAcl2"
#    - "no ntp access-group peer PeerAcl1"
#    - "ntp access-group serve ServeAcl2"
#    - "no ntp access-group serve ServeAcl1"
#
#  after:
#    access_group:
#      peer:
#        - access_list: PeerAcl2
#      serve:
#        - access_list: ServeAcl2
#    logging: true
#    master:
#      stratum: 2
#    peers:
#      - peer: 192.0.2.1
#        key_id: 1
#        maxpoll: 15
#        minpoll: 5
#        vrf: default
#      - peer: 192.0.2.5
#        key_id: 2
#        prefer: true
#        vrf: siteA
#    servers:
#      - server: 198.51.100.1
#        key_id: 2
#        vrf: default

# After state:
# ------------
# nxos-9k-rdo# show running-config ntp
# ntp logging
# ntp master 2
# ntp peer 192.0.2.1 use-vrf default key 1 minpoll 5 maxpoll 15
# ntp peer 192.0.2.5 prefer use-vrf siteA key 2
# ntp server 198.51.100.1 use-vrf default key 2
# ntp access-group peer PeerAcl2
# ntp access-group serve ServeAcl2

# Using deleted to delete all logging configurations

# Before state:
# ------------
# nxos-9k-rdo# show running-config ntp

- name: Delete all logging configuration
  cisco.nxos.nxos_ntp_global:
    state: deleted

# Task output
# -------------
#  before:
#    access_group:
#      peer:
#        - access_list: PeerAcl1
#      serve:
#       - access_list: ServeAcl1
#    authenticate: true
#    authentication_keys:
#      - id: 1001
#        key: vagwwtKfkv
#        encryption: 7
#      - id: 1002
#        key: vagwwtKfkvgthz
#        encryption: 7
#    logging: true
#    master:
#     stratum: 2
#    peers:
#      - peer: 192.0.2.1
#        key_id: 1
#        maxpoll: 15
#        minpoll: 5
#        vrf: default
#      - peer: 192.0.2.2
#        key_id: 2
#        prefer: true
#        vrf: siteA
#    servers:
#      - server: 198.51.100.1
#        key_id: 2
#        vrf: default
#      - server: 203.0.113.1
#        key_id: 1
#        vrf: siteB
#
#  commands:
#    - "no ntp authenticate"
#    - "no ntp logging"
#    - "no ntp master 2"
#    - "no ntp authentication-keys 1001 md5 vagwwtKfkv 7"
#    - "no ntp authentication-keys 1002 md5 vagwwtKfkvgthz 7"
#    - "no ntp peer 192.0.2.1 use-vrf default key 1 minpoll 5 maxpoll 15"
#    - "no ntp peer 192.0.2.2 prefer use-vrf siteA key 2"
#    - "no ntp server 198.51.100.1 use-vrf default key 2"
#    - "no ntp server 203.0.113.1 use-vrf siteB key 1"
#    - "no ntp access-group peer PeerAcl1"
#    - "no ntp access-group serve ServeAcl1"
#
#  after: {}

# After state:
# ------------
# nxos-9k-rdo# show running-config ntp
# nxos-9k-rdo#

# Using rendered

- name: Render platform specific configuration lines with state rendered (without connecting to the device)
  cisco.nxos.nxos_ntp_global:
    config:
      access_group:
        peer:
          - access_list: PeerAcl1
        serve:
          - access_list: ServeAcl1
      authenticate: true
      authentication_keys:
        - id: 1001
          key: vagwwtKfkv
          encryption: 7
        - id: 1002
          key: vagwwtKfkvgthz
          encryption: 7
      logging: true
      master:
        stratum: 2
      peers:
        - peer: 192.0.2.1
          key_id: 1
          maxpoll: 15
          minpoll: 5
          vrf: default
        - peer: 192.0.2.2
          key_id: 2
          prefer: true
          vrf: siteA
      servers:
        - server: 198.51.100.1
          key_id: 2
          vrf: default
        - server: 203.0.113.1
          key_id: 1
          vrf: siteB
    state: rendered

# Task Output (redacted)
# -----------------------
#  rendered:
#    - "ntp authenticate"
#    - "ntp logging"
#    - "ntp master 2"
#    - "ntp authentication-keys 1001 md5 vagwwtKfkv 7"
#    - "ntp authentication-keys 1002 md5 vagwwtKfkvgthz 7"
#    - "ntp peer 192.0.2.1 use-vrf default key 1 minpoll 5 maxpoll 15"
#    - "ntp peer 192.0.2.2 prefer use-vrf siteA key 2"
#    - "ntp server 198.51.100.1 use-vrf default key 2"
#    - "ntp server 203.0.113.1 use-vrf siteB key 1"
#    - "ntp access-group peer PeerAcl1"
#    - "ntp access-group serve ServeAcl1"

# Using parsed

# parsed.cfg
# ------------
# ntp authenticate
# ntp logging
# ntp master 2
# ntp authentication-keys 1001 md5 vagwwtKfkv 7
# ntp authentication-keys 1002 md5 vagwwtKfkvgthz 7
# ntp peer 192.0.2.1 use-vrf default key 1 minpoll 5 maxpoll 15
# ntp peer 192.0.2.2 prefer use-vrf siteA key 2
# ntp server 198.51.100.1 use-vrf default key 2
# ntp server 203.0.113.1 use-vrf siteB key 1
# ntp access-group peer PeerAcl1
# ntp access-group serve ServeAcl1

- name: Parse externally provided ntp configuration
  cisco.nxos.nxos_ntp_global:
    running_config: "{{ lookup('file', './fixtures/parsed.cfg') }}"
    state: parsed

# Task output (redacted)
# -----------------------
# parsed:
#    access_group:
#      peer:
#        - access_list: PeerAcl1
#      serve:
#       - access_list: ServeAcl1
#    authenticate: true
#    authentication_keys:
#      - id: 1001
#        key: vagwwtKfkv
#        encryption: 7
#      - id: 1002
#        key: vagwwtKfkvgthz
#        encryption: 7
#    logging: true
#    master:
#     stratum: 2
#    peers:
#      - peer: 192.0.2.1
#        key_id: 1
#        maxpoll: 15
#        minpoll: 5
#        vrf: default
#      - peer: 192.0.2.2
#        key_id: 2
#        prefer: true
#        vrf: siteA
#    servers:
#      - server: 198.51.100.1
#        key_id: 2
#        vrf: default
#      - server: 203.0.113.1
#        key_id: 1
#        vrf: siteB
"""

RETURN = """
before:
  description: The configuration prior to the module execution.
  returned: when I(state) is C(merged), C(replaced), C(overridden), C(deleted) or C(purged)
  type: dict
  sample: >
    This output will always be in the same format as the
    module argspec.
after:
  description: The resulting configuration after module execution.
  returned: when changed
  type: dict
  sample: >
    This output will always be in the same format as the
    module argspec.
commands:
  description: The set of commands pushed to the remote device.
  returned: when I(state) is C(merged), C(replaced), C(overridden), C(deleted) or C(purged)
  type: list
  sample:
    - ntp master stratum 2
    - ntp peer 198.51.100.1 use-vrf test maxpoll 7
    - ntp authentication-key 10 md5 wawyhanx2 7
    - ntp access-group peer PeerAcl1
    - ntp access-group peer PeerAcl2
    - ntp access-group query-only QueryAcl1
rendered:
  description: The provided configuration in the task rendered in device-native format (offline).
  returned: when I(state) is C(rendered)
  type: list
  sample:
    - ntp master stratum 2
    - ntp peer 198.51.100.1 use-vrf test maxpoll 7
    - ntp authentication-key 10 md5 wawyhanx2 7
    - ntp access-group peer PeerAcl1
    - ntp access-group peer PeerAcl2
    - ntp access-group query-only QueryAcl1
gathered:
  description: Facts about the network resource gathered from the remote device as structured data.
  returned: when I(state) is C(gathered)
  type: list
  sample: >
    This output will always be in the same format as the
    module argspec.
parsed:
  description: The device native config provided in I(running_config) option parsed into structured data as per module argspec.
  returned: when I(state) is C(parsed)
  type: list
  sample: >
    This output will always be in the same format as the
    module argspec.
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.argspec.ntp_global.ntp_global import (
    Ntp_globalArgs,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.config.ntp_global.ntp_global import (
    Ntp_global,
)


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(
        argument_spec=Ntp_globalArgs.argument_spec,
        mutually_exclusive=[["config", "running_config"]],
        required_if=[
            ["state", "merged", ["config"]],
            ["state", "replaced", ["config"]],
            ["state", "overridden", ["config"]],
            ["state", "rendered", ["config"]],
            ["state", "parsed", ["running_config"]],
        ],
        supports_check_mode=True,
    )

    result = Ntp_global(module).execute_module()
    module.exit_json(**result)


if __name__ == "__main__":
    main()
