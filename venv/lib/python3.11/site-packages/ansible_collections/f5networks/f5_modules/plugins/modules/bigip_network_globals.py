#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2019, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_network_globals
short_description: Manage network global settings on BIG-IP
description:
  - Module to manage STP, Multicast, DAG, LLDP and Self Allow global settings on a BIG-IP.
version_added: "1.0.0"
options:
  stp:
    description:
      - Manage global settings for STP on BIG-IP.
    type: dict
    suboptions:
      config_name:
        description:
          - Specifies the configuration name. The accepted length is from 1 to 32 characters.
          - Only has effect when the C(mode) is C(mstp).
        type: str
      config_revision:
        description:
          - Specifies the revision level of the MSTP configuration, when C(mode) is C(mstp).
          - You must specify a number in the range of 0 to 65535.
        type: int
      description:
        description:
          - User-defined description.
        type: str
      fwd_delay:
        description:
          - The number of seconds for which an interface was blocked from forwarding network traffic after a
            reconfiguration of the spanning tree topology. This parameter has no effect when C(rstp) or C(mstp) modes
            are used, as long as all bridges in the spanning tree use the RSTP or MSTP protocol.
          - If any legacy STP bridges are present, neighboring bridges must fall back to the old protocol,
            whose reconfiguration time is affected by the forward delay value.
          - The valid range is 4 to 30.
        type: int
      hello_time:
        description:
          - Specifies the time interval in seconds between the periodic transmissions that communicate spanning tree
            information to the adjacent bridges in the network.
          - The hello time set by default on the device is optimal in virtually all cases. F5 recommends that you do
            not change the hello time.
          - The valid range is 1 to 10.
        type: int
      max_age:
        description:
          - Specifies the number of seconds for which spanning tree information received from other bridges is
            considered valid.
          - The valid range is 6 to 40 seconds.
        type: int
      max_hops:
        description:
          - Specifies the maximum number of hops an MSTP packet may travel before it is discarded.
          - This option only takes effect when C(mode) is C(mstp).
          - The number of hops must be in the range of 1 to 255.
        type: int
      mode:
        description:
          - Specifies the spanning tree mode.
          - "The C(mstp), C(rstp) and C(stp) options are only supported on hardware platforms. Attempting to set these
            modes on VE type platforms will result in failure. The only valid options on VE type platforms are:
            C(passthru) and C(disabled)."
        type: str
        choices:
          - disabled
          - mstp
          - passthru
          - rstp
          - stp
      transmit_hold:
        description:
          - Specifies the absolute limit on the number of spanning tree protocol packets the traffic management system
            may transmit on a port in any hello time interval.
          - The valid range is 1 to 10 packets.
        type: int
  multicast:
    description:
      - Manage multicast traffic configuration options.
    type: dict
    suboptions:
      max_pending_packets:
        description:
          - Specifies the maximum number of packet queued on behalf of a single incomplete MFC entry.
          - The valid range is 0 - 4294967295.
        type: int
      max_pending_routes:
        description:
          - Specifies the number of incomplete MFC entries each TMM will allow to exist at one time.
          - The valid range is 0 - 4294967295.
        type: int
      route_lookup_timeout:
        description:
          - Specifies maximum lifetime of an incomplete MFC entry, in seconds.
          - The valid range is 0 - 4294967295.
        type: int
      rate_limit:
        description:
          - When C(true), the DB variable C(switchboard.maxmcastrate) setting controls the multicast packet per second rate
            limiting in the switch.
        type: bool
  dag:
    description:
      -  Manage global disaggregation settings.
    type: dict
    suboptions:
      round_robin_mode:
        description:
          - Specifies whether the round robin disaggregator (DAG) on a blade can disaggregate packets to all the TMMs
            in the system or only to the TMMs local to the blade.
          - When C(global), the DAG will disaggregate packets to all TMMs in the system.
          - When C(local), the DAG will disaggregate packets only to the TMMs local to the blade.
        type: str
        choices:
          - global
          - local
      icmp_hash:
        description:
          - Specifies the ICMP hash for ICMP echo request and ICMP echo reply in SW DAG.
          - When C(icmp), ICMP echo request and ICMP echo reply are disaggregated based on ICMP id.
          - When C(ipicmp), ICMP echo request and ICMP echo reply are disaggregated based on ICMP id and IP addresses.
          - This option is only available in C(TMOS) version C(13.x) and above.
        type: str
        choices:
          - icmp
          - ipicmp
      dag_ipv6_prefix_len:
        description:
          - Specifies whether SPDAG or IPv6 prefix DAG should be used to disaggregate IPv6 traffic when vlan cmp hash
            is set to C(src-ip) or C(dst-ip).
          - The valid value range is 0 - 128, with C(128) value SPAG is in use.
          - This option is only available in TMOS version C(13.x) and above.
        type: int
  lldp:
    description:
      - Manage LLDP configuration options.
    type: dict
    suboptions:
      enabled:
        description:
          - Specifies the current status of LLDP.
          - When C(true), the LLDP is enabled globally on the device.
          - When C(false), the LLDP is disabled globally on the device.
        type: bool
      max_neighbors_per_port:
        description:
          - Specifies the maximum number of neighbors per port.
          - The valid value range is 0 - 65535.
        type: int
      reinit_delay:
        description:
          - Specifies the maximum number of seconds to wait after reaching the TTL interval before resetting TTL timer.
          - The valid value range is 0 - 65535.
        type: int
      tx_delay:
        description:
          - Specifies the number of seconds to wait for LLDP to initialize on an interface before sending LLDP message.
          - The valid value range is 0 - 65535.
        type: int
      tx_hold:
        description:
          - "Specifies the multiplier that determines the LLDP Time to Live (TTL). TTL is determined by multiplying
            this value and C(tx_interval)."
          - The valid value range is 0 - 65535.
        type: int
      tx_interval:
        description:
          - Specifies the interval devices use to send LLDP information from each of their interfaces.
          - The valid value range is 0 - 65535.
        type: int
  self_allow:
    description:
      - Manage Self Allow global configuration options.
    type: dict
    suboptions:
      defaults:
        description:
          - The default set of protocols and ports allowed by a self IP if the self IP allow-service setting is
            B(default).
        type: list
        elements: dict
        suboptions:
          protocol:
            description:
              - The protocol name to be set.
            type: str
          port:
            description:
              - The port number to be set.
              - The valid value range is 0 - 65535.
            type: int
      all:
        description:
          - Sets B(all) or B(none) ports and protocols as a system wide C(self_allow) setting.
          - When C(true), the self_allow allows all protocols and ports. This is the equivalent of setting B(all) option
            in C(TMSH).
          - When C(false), the self_allow allows no protocols and ports. This is the equivalent of setting B(none) option
            in C(TMSH).
        type: bool
    version_added: "1.1.0"
extends_documentation_fragment: f5networks.f5_modules.f5
author:
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Update STP settings
  bigip_network_globals:
    stp:
      config_name: foobar
      config_revision: 1
      max_hops: 20
      mode: mstp
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost

- name: Update DAG settings
  bigip_network_globals:
    dag:
      icmp_hash: ipicmp
      round_robin_mode: local
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost

- name: Update multiple settings
  bigip_network_globals:
    stp:
      config_name: foobar
      config_revision: 1
      max_hops: 20
      mode: mstp
    dag:
      icmp_hash: ipicmp
      round_robin_mode: local
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost
'''

RETURN = r'''
stp:
  description: Manage global settings for STP on BIG-IP.
  type: complex
  returned: changed
  contains:
    config_name:
      description: The configuration name.
      returned: changed
      type: str
      sample: foobar
    config_revision:
      description: The revision level of the MSTP configuration.
      returned: changed
      type: int
      sample: 2
    description:
      description: User-defined description.
      returned: changed
      type: str
      sample: My description
    fwd_delay:
      description: The number of seconds for which an interface was blocked from forwarding network traffic.
      returned: changed
      type: int
      sample: 4
    hello_time:
      description: The time interval at seconds between the periodic transmissions of spanning tree information.
      returned: changed
      type: int
      sample: 2
    max_age:
      description: The number of seconds that spanning tree information received from other bridges is considered valid.
      returned: changed
      type: int
      sample: 30
    max_hops:
      description: The maximum number of hops an MSTP packet may travel before it is discarded.
      returned: changed
      type: int
      sample: 15
    mode:
      description: The spanning tree mode.
      returned: changed
      type: str
      sample: mstp
    transmit_hold:
      description:
        - The limit on the number of STP the traffic management system may transmit on a port in any hello
          time interval.
      returned: changed
      type: int
      sample: 5
  sample: hash/dictionary of values
multicast:
  description: Manage multicast traffic configuration options.
  type: complex
  returned: changed
  contains:
    max_pending_packets:
      description: The maximum number of packet queued on behalf of a single incomplete MFC entry.
      returned: changed
      type: int
      sample: 3000
    max_pending_routes:
      description: The number of incomplete MFC entries each TMM will allow to exist at one time.
      returned: changed
      type: int
      sample: 50
    route_lookup_timeout:
      description: The maximum lifetime of an incomplete MFC entry, in seconds.
      returned: changed
      type: int
      sample: 20
    rate_limit:
      description: Enables DB variable control over multicast packet per second rate limiting in the switch.
      returned: changed
      type: bool
      sample: true
  sample: hash/dictionary of values
dag:
  description: Manage multicast traffic configuration options.
  type: complex
  returned: changed
  contains:
    round_robin_mode:
      description: The mode of operation of the DAG on a blade.
      returned: changed
      type: str
      sample: local
    icmp_hash:
      description: Specifies the ICMP hash for the ICMP echo request and ICMP echo reply in SW DAG.
      returned: changed
      type: str
      sample: ipicmp
    dag_ipv6_prefix_len:
      description: Specifies whether SPDAG or IPv6 prefix DAG should be used to disaggregate IPv6 traffic.
      returned: changed
      type: int
      sample: 128
  sample: hash/dictionary of values
lldp:
  description: Manage multicast traffic configuration options.
  type: complex
  returned: changed
  contains:
    enabled:
      description: The current status of LLDP.
      returned: changed
      type: bool
      sample: true
    max_neighbors_per_port:
      description: The maximum number of neighbors per port.
      returned: changed
      type: int
      sample: 128
    reinit_delay:
      description: The maximum number of seconds to wait before resetting the TTL timer after reaching the TTL interval.
      returned: changed
      type: int
      sample: 30
    tx_delay:
      description: The number of seconds to wait for LLDP to initialize on an interface before sending LLDP message.
      returned: changed
      type: int
      sample: 500
    tx_hold:
      description: The multiplier that determines the LLDP Time to Live.
      returned: changed
      type: int
      sample: 10
    tx_interval:
      description: The interval devices use to send LLDP information from each of their interfaces.
      returned: changed
      type: int
      sample: 240
  sample: hash/dictionary of values
self_allow:
  description: Manages self_allow system wide settings.
  type: complex
  returned: changed
  contains:
    defaults:
      description: The default set of protocols and ports allowed by a self IP.
      type: complex
      returned: changed
      contains:
        protocol:
          description: The protocol name to be set.
          returned: changed
          type: str
          sample: tcp
        port:
          description: The port number to be set.
          returned: changed
          type: int
          sample: 443
      sample: hash/dictionary of values
    all:
      description: Allows all or none ports and protocols as a system wide self_allow setting.
      returned: changed
      type: bool
      sample: true
  sample: hash/dictionary of values
'''
from datetime import datetime

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six import string_types

from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, f5_argument_spec, flatten_boolean
)
from ..module_utils.compare import (
    cmp_str_with_none, cmp_simple_list
)
from ..module_utils.icontrol import tmos_version
from ..module_utils.teem import send_teem


class Parameters(AnsibleF5Parameters):
    api_map = {}

    api_attributes = []

    returnables = [
        'stp',
        'dag',
        'multicast',
        'lldp',
        'self_allow',
    ]

    updatables = [
        'stp_config_name',
        'stp_config_revision',
        'stp_description',
        'stp_fwd_delay',
        'stp_hello_time',
        'stp_max_age',
        'stp_max_hops',
        'stp_mode',
        'stp_transmit_hold',
        'mcast_max_pending_packets',
        'mcast_max_pending_routes',
        'mcast_rate_limit',
        'mcast_route_lookup_timeout',
        'dag_round_robin',
        'dag_ipv6_prefix_len',
        'dag_icmp_hash',
        'lldp_enabled',
        'lldp_disabled',
        'lldp_max_neighbors_per_port',
        'lldp_reinit_delay',
        'lldp_tx_delay',
        'lldp_tx_hold',
        'lldp_tx_interval',
        'self_allow_all',
        'self_allow_defaults',
    ]


class ApiParameters(Parameters):
    @property
    def stp_config_name(self):
        if self._values['stp'] is None:
            return None
        return self._values['stp'].get('configName', None)

    @property
    def stp_config_revision(self):
        if self._values['stp'] is None:
            return None
        return self._values['stp']['configRevision']

    @property
    def stp_description(self):
        if self._values['stp'] is None:
            return None
        return self._values['stp'].get('description', None)

    @property
    def stp_fwd_delay(self):
        if self._values['stp'] is None:
            return None
        return self._values['stp']['fwdDelay']

    @property
    def stp_hello_time(self):
        if self._values['stp'] is None:
            return None
        return self._values['stp']['helloTime']

    @property
    def stp_max_age(self):
        if self._values['stp'] is None:
            return None
        return self._values['stp']['maxAge']

    @property
    def stp_max_hops(self):
        if self._values['stp'] is None:
            return None
        return self._values['stp']['maxHops']

    @property
    def stp_mode(self):
        if self._values['stp'] is None:
            return None
        return self._values['stp']['mode']

    @property
    def stp_transmit_hold(self):
        if self._values['stp'] is None:
            return None
        return self._values['stp']['transmitHold']

    @property
    def mcast_max_pending_packets(self):
        if self._values['multicast'] is None:
            return None
        return self._values['multicast']['maxPendingPackets']

    @property
    def mcast_max_pending_routes(self):
        if self._values['multicast'] is None:
            return None
        return self._values['multicast']['maxPendingRoutes']

    @property
    def mcast_rate_limit(self):
        if self._values['multicast'] is None:
            return None
        result = flatten_boolean(self._values['multicast']['rateLimit'])
        if result == 'yes':
            return 'enabled'
        if result == 'no':
            return 'disabled'

    @property
    def mcast_route_lookup_timeout(self):
        if self._values['multicast'] is None:
            return None
        return self._values['multicast']['routeLookupTimeout']

    @property
    def dag_round_robin_mode(self):
        if self._values['dag'] is None:
            return None
        return self._values['dag']['roundRobinMode']

    @property
    def dag_ipv6_prefix_len(self):
        if self._values['dag'] is None:
            return None
        return self._values['dag'].get('dagIpv6PrefixLen', None)

    @property
    def dag_icmp_hash(self):
        if self._values['dag'] is None:
            return None
        return self._values['dag'].get('icmpHash', None)

    @property
    def lldp_enabled(self):
        if self._values['lldp'] is None:
            return None
        if 'enabled' in self._values['lldp']:
            result = flatten_boolean(self._values['lldp']['enabled'])
            if result == 'yes':
                return True

    @property
    def lldp_disabled(self):
        if self._values['lldp'] is None:
            return None
        if 'disabled' in self._values['lldp']:
            result = flatten_boolean(self._values['lldp']['disabled'])
            if result == 'yes':
                return True

    @property
    def lldp_max_neighbors_per_port(self):
        if self._values['lldp'] is None:
            return None
        return self._values['lldp']['maxNeighborsPerPort']

    @property
    def lldp_reinit_delay(self):
        if self._values['lldp'] is None:
            return None
        return self._values['lldp']['reinitDelay']

    @property
    def lldp_tx_delay(self):
        if self._values['lldp'] is None:
            return None
        return self._values['lldp']['txDelay']

    @property
    def lldp_tx_hold(self):
        if self._values['lldp'] is None:
            return None
        return self._values['lldp']['txHold']

    @property
    def lldp_tx_interval(self):
        if self._values['lldp'] is None:
            return None
        return self._values['lldp']['txInterval']

    @property
    def self_allow_all(self):
        if self.self_allow_defaults is None:
            return 'no'
        if self.self_allow_defaults == 'all':
            return 'yes'

    @property
    def self_allow_defaults(self):
        if self._values['self_allow'] is None:
            return None
        return self._values['self_allow'].get('defaults', None)


class ModuleParameters(Parameters):
    @property
    def stp_config_name(self):
        if self._values['stp'] is None:
            return None
        if self._values['stp']['config_name'] is None:
            return None
        if len(self._values['stp']['config_name']) > 32:
            raise F5ModuleError(
                "The 'config_name' cannot be more than 32 characters in length."
            )
        return self._values['stp']['config_name']

    @property
    def stp_config_revision(self):
        if self._values['stp'] is None:
            return None
        if self._values['stp']['config_revision'] is None:
            return None
        if 0 <= self._values['stp']['config_revision'] <= 65535:
            return self._values['stp']['config_revision']
        raise F5ModuleError(
            "Valid 'config_revision' must be in range 0 - 65535."
        )

    @property
    def stp_description(self):
        if self._values['stp'] is None:
            return None
        if self._values['stp']['description'] is None:
            return None
        return self._values['stp']['description']

    @property
    def stp_fwd_delay(self):
        if self._values['stp'] is None:
            return None
        if self._values['stp']['fwd_delay'] is None:
            return None
        if 4 <= self._values['stp']['fwd_delay'] <= 30:
            return self._values['stp']['fwd_delay']
        raise F5ModuleError(
            "Valid 'fwd_delay' must be in range 4 - 30 seconds."
        )

    @property
    def stp_hello_time(self):
        if self._values['stp'] is None:
            return None
        if self._values['stp']['hello_time'] is None:
            return None
        if 1 <= self._values['stp']['hello_time'] <= 10:
            return self._values['stp']['hello_time']
        raise F5ModuleError(
            "Valid 'hello_time' must be in range 1 - 10 seconds."
        )

    @property
    def stp_max_age(self):
        if self._values['stp'] is None:
            return None
        if self._values['stp']['max_age'] is None:
            return None
        if 6 <= self._values['stp']['max_age'] <= 40:
            return self._values['stp']['max_age']
        raise F5ModuleError(
            "Valid 'hello_time' must be in range 6 - 40 seconds."
        )

    @property
    def stp_max_hops(self):
        if self._values['stp'] is None:
            return None
        if self._values['stp']['max_hops'] is None:
            return None
        if 1 <= self._values['stp']['max_hops'] <= 255:
            return self._values['stp']['max_hops']
        raise F5ModuleError(
            "Valid 'max_hops' must be in range 1 - 255."
        )

    @property
    def stp_mode(self):
        if self._values['stp'] is None:
            return None
        if self._values['stp']['mode'] is None:
            return None
        return self._values['stp']['mode']

    @property
    def stp_transmit_hold(self):
        if self._values['stp'] is None:
            return None
        if self._values['stp']['transmit_hold'] is None:
            return None
        if 1 <= self._values['stp']['transmit_hold'] <= 10:
            return self._values['stp']['transmit_hold']
        raise F5ModuleError(
            "Valid 'transmit_hold' must be in range 1 - 10 packets."
        )

    @property
    def mcast_max_pending_packets(self):
        if self._values['multicast'] is None:
            return None
        if self._values['multicast']['max_pending_packets'] is None:
            return None
        if 0 <= self._values['multicast']['max_pending_packets'] <= 4294967295:
            return self._values['multicast']['max_pending_packets']
        raise F5ModuleError(
            "Valid 'max_pending_packets' must be in range 0 - 4294967295."
        )

    @property
    def mcast_max_pending_routes(self):
        if self._values['multicast'] is None:
            return None
        if self._values['multicast']['max_pending_routes'] is None:
            return None
        if 0 <= self._values['multicast']['max_pending_routes'] <= 4294967295:
            return self._values['multicast']['max_pending_routes']
        raise F5ModuleError(
            "Valid 'max_pending_routes' must be in range 0 - 4294967295."
        )

    @property
    def mcast_rate_limit(self):
        if self._values['multicast'] is None:
            return None
        result = flatten_boolean(self._values['multicast']['rate_limit'])
        if result == 'yes':
            return 'enabled'
        if result == 'no':
            return 'disabled'

    @property
    def mcast_route_lookup_timeout(self):
        if self._values['multicast'] is None:
            return None
        if self._values['multicast']['route_lookup_timeout'] is None:
            return None
        if 0 <= self._values['multicast']['route_lookup_timeout'] <= 4294967295:
            return self._values['multicast']['route_lookup_timeout']
        raise F5ModuleError(
            "Valid 'route_lookup_timeout' must be in range 0 - 4294967295."
        )

    @property
    def dag_round_robin_mode(self):
        if self._values['dag'] is None:
            return None
        if self._values['dag']['round_robin_mode'] is None:
            return None
        return self._values['dag']['round_robin_mode']

    @property
    def dag_ipv6_prefix_len(self):
        if self._values['dag'] is None:
            return None
        if self._values['dag']['dag_ipv6_prefix_len'] is None:
            return None
        if 0 <= self._values['dag']['dag_ipv6_prefix_len'] <= 128:
            return self._values['dag']['dag_ipv6_prefix_len']
        raise F5ModuleError(
            "Valid 'dag_ipv6_prefix_len' must be in range 0 - 128."
        )

    @property
    def dag_icmp_hash(self):
        if self._values['dag'] is None:
            return None
        if self._values['dag']['icmp_hash'] is None:
            return None
        return self._values['dag']['icmp_hash']

    @property
    def lldp_enabled(self):
        if self._values['lldp'] is None:
            return None
        result = flatten_boolean(self._values['lldp']['enabled'])
        if result == 'yes':
            return True
        return None

    @property
    def lldp_disabled(self):
        if self._values['lldp'] is None:
            return None
        result = flatten_boolean(self._values['lldp']['enabled'])
        if result == 'no':
            return True
        return None

    @property
    def lldp_max_neighbors_per_port(self):
        if self._values['lldp'] is None:
            return None
        if self._values['lldp']['max_neighbors_per_port'] is None:
            return None
        if 0 <= self._values['lldp']['max_neighbors_per_port'] <= 65535:
            return self._values['lldp']['max_neighbors_per_port']
        raise F5ModuleError(
            "Valid 'max_neighbors_per_port' must be in range 0 - 65535."
        )

    @property
    def lldp_reinit_delay(self):
        if self._values['lldp'] is None:
            return None
        if self._values['lldp']['reinit_delay'] is None:
            return None
        if 0 <= self._values['lldp']['reinit_delay'] <= 65535:
            return self._values['lldp']['reinit_delay']
        raise F5ModuleError(
            "Valid 'reinit_delay' must be in range 0 - 65535 seconds."
        )

    @property
    def lldp_tx_delay(self):
        if self._values['lldp'] is None:
            return None
        if self._values['lldp']['tx_delay'] is None:
            return None
        if 0 <= self._values['lldp']['tx_delay'] <= 65535:
            return self._values['lldp']['tx_delay']
        raise F5ModuleError(
            "Valid 'tx_delay' must be in range 0 - 65535 seconds."
        )

    @property
    def lldp_tx_hold(self):
        if self._values['lldp'] is None:
            return None
        if self._values['lldp']['tx_hold'] is None:
            return None
        if 0 <= self._values['lldp']['tx_hold'] <= 65535:
            return self._values['lldp']['tx_hold']
        raise F5ModuleError(
            "Valid 'tx_hold' must be in range 0 - 65535."
        )

    @property
    def lldp_tx_interval(self):
        if self._values['lldp'] is None:
            return None
        if self._values['lldp']['tx_interval'] is None:
            return None
        if 0 <= self._values['lldp']['tx_interval'] <= 65535:
            return self._values['lldp']['tx_interval']
        raise F5ModuleError(
            "Valid 'tx_interval' must be in range 0 - 65535 seconds."
        )

    @property
    def self_allow_defaults(self):
        if self._values['self_allow'] is None:
            return None
        if self.self_allow_all == 'yes':
            return 'all'
        if self.self_allow_all == 'no':
            return 'none'
        result = list()
        for item in self._values['self_allow']['defaults']:
            if not 0 <= item['port'] or not item['port'] <= 65535:
                raise F5ModuleError(
                    "Valid self_allow_defaults port must be in range 0 - 65535."
                )
            to_append = "{0}:{1}".format(item['protocol'], item['port'])
            result.append(to_append)
        return result

    @property
    def self_allow_all(self):
        if self._values['self_allow'] is None:
            return None
        result = flatten_boolean(self._values['self_allow']['all'])
        return result


class Changes(Parameters):
    def to_return(self):
        result = {}
        try:
            for returnable in self.returnables:
                result[returnable] = getattr(self, returnable)
            result = self._filter_params(result)
        except Exception:
            raise
        return result


class UsableChanges(Changes):
    @property
    def stp(self):
        to_filter = dict(
            configName=self._values['stp_config_name'],
            configRevision=self._values['stp_config_revision'],
            description=self._values['stp_description'],
            fwdDelay=self._values['stp_fwd_delay'],
            helloTime=self._values['stp_hello_time'],
            maxAge=self._values['stp_max_age'],
            maxHops=self._values['stp_max_hops'],
            mode=self._values['stp_mode'],
            transmitHold=self._values['stp_transmit_hold']
        )
        result = self._filter_params(to_filter)
        if result:
            return result

    @property
    def multicast(self):
        to_filter = dict(
            maxPendingPackets=self._values['mcast_max_pending_packets'],
            maxPendingRoutes=self._values['mcast_max_pending_routes'],
            rateLimit=self._values['mcast_rate_limit'],
            routeLookupTimeout=self._values['mcast_route_lookup_timeout'],
        )
        result = self._filter_params(to_filter)
        if result:
            return result

    @property
    def dag(self):
        to_filter = dict(
            roundRobinMode=self._values['dag_round_robin_mode'],
            dagIpv6PrefixLen=self._values['dag_ipv6_prefix_len'],
            icmpHash=self._values['dag_icmp_hash'],
        )
        result = self._filter_params(to_filter)
        if result:
            return result

    @property
    def lldp(self):
        to_filter = dict(
            enabled=self._values['lldp_enabled'],
            disabled=self._values['lldp_disabled'],
            maxNeighborsPerPort=self._values['lldp_max_neighbors_per_port'],
            reinitDelay=self._values['lldp_reinit_delay'],
            txDelay=self._values['lldp_tx_delay'],
            txHold=self._values['lldp_tx_hold'],
            txInterval=self._values['lldp_tx_interval'],
        )
        result = self._filter_params(to_filter)
        if result:
            return result

    @property
    def self_allow(self):
        to_filter = dict(
            defaults=self._values['self_allow_defaults'],
        )
        result = self._filter_params(to_filter)
        if result:
            return result


class ReportableChanges(Changes):
    @property
    def stp(self):
        if self._values['stp'] is None:
            return None
        to_filter = dict(
            config_name=self._values['stp'].get('configName', None),
            config_revision=self._values['stp'].get('configRevision', None),
            description=self._values['stp'].get('description', None),
            fwd_delay=self._values['stp'].get('fwdDelay', None),
            hello_time=self._values['stp'].get('helloTime', None),
            max_age=self._values['stp'].get('maxAge', None),
            max_hops=self._values['stp'].get('maxHops', None),
            mode=self._values['stp'].get('mode', None),
            transmit_hold=self._values['stp'].get('transmitHold', None),
        )
        result = self._filter_params(to_filter)
        if result:
            return result

    @property
    def multicast(self):
        if self._values['multicast'] is None:
            return None
        to_filter = dict(
            max_pending_packets=self._values['multicast'].get('maxPendingPackets', None),
            max_pending_routes=self._values['multicast'].get('maxPendingRoutes', None),
            rate_limit=flatten_boolean(self._values['multicast'].get('rateLimit', None)),
            route_lookup_timeout=self._values['multicast'].get('routeLookupTimeout', None)
        )
        result = self._filter_params(to_filter)
        if result:
            return result

    @property
    def dag(self):
        if self._values['dag'] is None:
            return None
        to_filter = dict(
            round_robin_mode=self._values['dag'].get('roundRobinMode', None),
            dag_ipv6_prefix_len=self._values['dag'].get('dagIpv6PrefixLen', None),
            icmp_hash=self._values['dag'].get('icmpHash', None),
        )
        result = self._filter_params(to_filter)
        if result:
            return result

    @property
    def lldp(self):
        if self._values['lldp'] is None:
            return None
        to_filter = dict(
            enabled=self.enabled,
            max_neighbors_per_port=self._values['lldp'].get('maxNeighborsPerPort', None),
            reinit_delay=self._values['lldp'].get('reinitDelay', None),
            tx_delay=self._values['lldp'].get('txDelay', None),
            tx_hold=self._values['lldp'].get('txHold', None),
            tx_interval=self._values['lldp'].get('txInterval', None)
        )
        result = self._filter_params(to_filter)
        if result:
            return result

    @property
    def enabled(self):
        enabled = self._values['lldp'].get('enabled', None)
        disabled = self._values['lldp'].get('disabled', None)
        if enabled:
            return 'yes'
        if disabled:
            return 'no'

    @property
    def self_allow(self):
        if self._values['self_allow'] is None:
            return None
        to_filter = dict(
            defaults=self._parse_self_defaults(),
            all=self._get_all_value(),
        )
        result = self._filter_params(to_filter)
        if result:
            return result

    def _parse_self_defaults(self):
        items = self._values['self_allow'].get('defaults')
        if isinstance(items, list):
            result = dict()
            for item in items:
                result['protocol'] = item.split(':')[0]
                result['port'] = item.split(':')[1]
            return result

    def _get_all_value(self):
        items = self._values['self_allow'].get('defaults')
        if isinstance(items, string_types):
            if items == 'none':
                return 'no'
            if items == 'all':
                return 'yes'


class Difference(object):
    def __init__(self, want, have=None):
        self.want = want
        self.have = have

    def compare(self, param):
        try:
            result = getattr(self, param)
            return result
        except AttributeError:
            return self.__default(param)

    def __default(self, param):
        attr1 = getattr(self.want, param)
        try:
            attr2 = getattr(self.have, param)
            if attr1 != attr2:
                return attr1
        except AttributeError:
            return attr1

    @property
    def stp_config_name(self):
        result = cmp_str_with_none(self.want.stp_config_name, self.have.stp_config_name)
        return result

    @property
    def stp_description(self):
        result = cmp_str_with_none(self.want.stp_description, self.have.stp_description)
        return result

    @property
    def self_allow_defaults(self):
        if self.want.self_allow_defaults is None:
            return None
        if self.want.self_allow_defaults == 'none' and self.have.self_allow_defaults is None:
            return None
        if self.want.self_allow_defaults in ['all', 'none']:
            if isinstance(self.have.self_allow_defaults, string_types):
                if self.want.self_allow_defaults != self.have.self_allow_defaults:
                    return self.want.self_allow_defaults
                else:
                    return None
            if isinstance(self.have.self_allow_defaults, list):
                return self.want.self_allow_defaults
        result = cmp_simple_list(self.want.self_allow_defaults, self.have.self_allow_defaults)
        return result


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.client = F5RestClient(**self.module.params)
        self.want = ModuleParameters(params=self.module.params)
        self.have = ApiParameters()
        self.changes = UsableChanges()

    def _update_changed_options(self):
        diff = Difference(self.want, self.have)
        updatables = Parameters.updatables
        changed = dict()
        for k in updatables:
            change = diff.compare(k)
            if change is None:
                continue
            else:
                if isinstance(change, dict):
                    changed.update(change)
                else:
                    changed[k] = change
        if changed:
            self.changes = UsableChanges(params=changed)
            return True
        return False

    def _announce_deprecations(self, result):
        warnings = result.pop('__warnings', [])
        for warning in warnings:
            self.client.module.deprecate(
                msg=warning['msg'],
                version=warning['version']
            )

    def exec_module(self):
        start = datetime.now().isoformat()
        version = tmos_version(self.client)
        result = dict()

        changed = self.present()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        send_teem(start, self.client, self.module, version)
        return result

    def present(self):
        return self.update()

    def update(self):
        self.have = self.read_current_from_device()
        if not self.should_update():
            return False
        if self.module.check_mode:
            return True
        self.update_on_device()
        return True

    def should_update(self):
        result = self._update_changed_options()
        if result:
            return True
        return False

    def update_on_device(self):
        params = self.changes.to_return()
        if self.changes.stp:
            self.update_on_device_stp(params['stp'])
        if self.changes.multicast:
            self.update_on_device_mcast(params['multicast'])
        if self.changes.dag:
            self.update_on_device_dag(params['dag'])
        if self.changes.lldp:
            self.update_on_device_lldp(params['lldp'])
        if self.changes.self_allow:
            self.update_on_device_self(params['self_allow'])

    def update_on_device_stp(self, params):
        uri = "https://{0}:{1}/mgmt/tm/net/stp-globals/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],

        )
        resp = self.client.api.patch(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True
        raise F5ModuleError(resp.content)

    def update_on_device_mcast(self, params):
        uri = "https://{0}:{1}/mgmt/tm/net/multicast-globals/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],

        )
        resp = self.client.api.patch(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True
        raise F5ModuleError(resp.content)

    def update_on_device_dag(self, params):
        uri = "https://{0}:{1}/mgmt/tm/net/dag-globals/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],

        )
        resp = self.client.api.patch(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True
        raise F5ModuleError(resp.content)

    def update_on_device_lldp(self, params):
        uri = "https://{0}:{1}/mgmt/tm/net/lldp-globals/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],

        )
        resp = self.client.api.patch(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True
        raise F5ModuleError(resp.content)

    def update_on_device_self(self, params):
        uri = "https://{0}:{1}/mgmt/tm/net/self-allow/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],

        )
        resp = self.client.api.patch(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True
        raise F5ModuleError(resp.content)

    def read_current_from_device(self):
        response = dict(
            stp=None,
            multicast=None,
            dag=None,
            lldp=None,
            self_allow=None,
        )
        if self.want.stp:
            response['stp'] = self.read_current_from_device_stp()
        if self.want.multicast:
            response['multicast'] = self.read_current_from_device_mcast()
        if self.want.dag:
            response['dag'] = self.read_current_from_device_dag()
        if self.want.lldp:
            response['lldp'] = self.read_current_from_device_lldp()
        if self.want.self_allow:
            response['self_allow'] = self.read_current_from_device_self()
        return ApiParameters(params=response)

    def read_current_from_device_stp(self):
        uri = "https://{0}:{1}/mgmt/tm/net/stp-globals/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return response
        raise F5ModuleError(resp.content)

    def read_current_from_device_mcast(self):
        uri = "https://{0}:{1}/mgmt/tm/net/multicast-globals/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return response
        raise F5ModuleError(resp.content)

    def read_current_from_device_dag(self):
        uri = "https://{0}:{1}/mgmt/tm/net/dag-globals/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return response
        raise F5ModuleError(resp.content)

    def read_current_from_device_lldp(self):
        uri = "https://{0}:{1}/mgmt/tm/net/lldp-globals/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return response
        raise F5ModuleError(resp.content)

    def read_current_from_device_self(self):
        uri = "https://{0}:{1}/mgmt/tm/net/self-allow/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return response
        raise F5ModuleError(resp.content)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            stp=dict(
                type='dict',
                options=dict(
                    config_name=dict(),
                    config_revision=dict(type='int'),
                    description=dict(),
                    fwd_delay=dict(type='int'),
                    hello_time=dict(type='int'),
                    max_age=dict(type='int'),
                    max_hops=dict(type='int'),
                    mode=dict(
                        choices=['disabled', 'mstp', 'passthru', 'rstp', 'stp']
                    ),
                    transmit_hold=dict(type='int')
                )
            ),
            multicast=dict(
                type='dict',
                options=dict(
                    max_pending_packets=dict(type='int'),
                    max_pending_routes=dict(type='int'),
                    rate_limit=dict(type='bool'),
                    route_lookup_timeout=dict(type='int'),
                )
            ),
            dag=dict(
                type='dict',
                options=dict(
                    dag_ipv6_prefix_len=dict(type='int'),
                    icmp_hash=dict(
                        choices=['icmp', 'ipicmp']
                    ),
                    round_robin_mode=dict(
                        choices=['global', 'local']
                    ),
                )
            ),
            lldp=dict(
                type='dict',
                options=dict(
                    enabled=dict(type='bool'),
                    max_neighbors_per_port=dict(type='int'),
                    reinit_delay=dict(type='int'),
                    tx_delay=dict(type='int'),
                    tx_hold=dict(type='int'),
                    tx_interval=dict(type='int')
                )
            ),
            self_allow=dict(
                type='dict',
                options=dict(
                    defaults=dict(
                        type='list',
                        elements='dict',
                        options=dict(
                            protocol=dict(),
                            port=dict(type='int'),
                        ),
                        required_together=[
                            ['protocol', 'port']
                        ]
                    ),
                    all=dict(type='bool'),
                ),
                mutually_exclusive=[
                    ['defaults', 'all']
                ],
                required_one_of=[
                    ['defaults', 'all']
                ],
            )
        )
        self.argument_spec = {}
        self.argument_spec.update(f5_argument_spec)
        self.argument_spec.update(argument_spec)
        self.required_one_of = [
            ['stp', 'multicast', 'dag', 'lldp', 'self_allow']
        ]


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        required_one_of=spec.required_one_of
    )

    try:
        mm = ModuleManager(module=module)
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
