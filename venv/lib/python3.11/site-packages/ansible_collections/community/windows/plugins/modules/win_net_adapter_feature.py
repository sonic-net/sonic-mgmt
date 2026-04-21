#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, ライトウェルの人 <jiro.higuchi@shi-g.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = r'''
---
module: win_net_adapter_feature
version_added: 1.2.0
short_description: Enable or disable certain network adapters.
description:
  - Enable or disable some network components of a certain network adapter or all the network adapters.
options:
  interface:
    description:
      - Name of Network Adapter Interface. For example, C(Ethernet0) or C(*).
    type: list
    elements: str
    required: yes
  state:
    description:
      - Specify the state of ms_tcpip6 of interfaces.
    type: str
    choices: [ enabled, disabled ]
    default: enabled
    required: no
  component_id:
    description:
      - Specify the below component_id of network adapters.
      - component_id (DisplayName)
      - C(ms_implat) (Microsoft Network Adapter Multiplexor Protocol)
      - C(ms_lltdio) (Link-Layer Topology Discovery Mapper I/O Driver)
      - C(ms_tcpip6) (Internet Protocol Version 6 (TCP/IPv6))
      - C(ms_tcpip) (Internet Protocol Version 4 (TCP/IPv4))
      - C(ms_lldp) (Microsoft LLDP Protocol Driver)
      - C(ms_rspndr) (Link-Layer Topology Discovery Responder)
      - C(ms_msclient) (Client for Microsoft Networks)
      - C(ms_pacer) (QoS Packet Scheduler)
      - If you'd like to set custom adapters like 'Juniper Network Service', get the I(component_id) by running the C(Get-NetAdapterBinding) cmdlet.
    type: list
    elements: str
    required: yes

author:
  - ライトウェルの人 (@jirolin)
'''


EXAMPLES = r'''
- name: enable multiple interfaces of multiple interfaces
  community.windows.win_net_adapter_feature:
    interface:
      - 'Ethernet0'
      - 'Ethernet1'
    state: enabled
    component_id:
      - ms_tcpip6
      - ms_server

- name: Enable ms_tcpip6 of all the Interface
  community.windows.win_net_adapter_feature:
    interface: '*'
    state: enabled
    component_id:
      - ms_tcpip6
'''
