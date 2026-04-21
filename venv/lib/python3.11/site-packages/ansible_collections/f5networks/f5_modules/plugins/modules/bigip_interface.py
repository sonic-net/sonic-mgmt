#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2019, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_interface
short_description: Module to manage BIG-IP physical interfaces.
description:
  - Module to manage BIG-IP physical interfaces.
version_added: "1.0.0"
options:
  name:
    description:
      - Specifies the name of the interface to manage.
    type: str
    required: True
  description:
    description:
      - User defined description.
    type: str
  enabled:
    description:
      - Specifies the current status of the interface.
      - When C(true), enables the interface to pass traffic.
      - When C(false), disables the interface from passing traffic.
    type: bool
  bundle:
    description:
      - Enables or disables bundle capability.
      - This option is only supported on select hardware platforms and interfaces.
      - "Attempting to enable this option on a C(VE) or any other unsupported platform/interface
        will result in module run failure."
    type: str
    choices:
      - enabled
      - disabled
      - not-supported
  bundle_speed:
    description:
      - Sets the bundle speed, which is applicable only when the bundle is C(true).
      - This option is only supported on selected hardware platforms and interfaces.
      - "Attempting to enable this option on a C(VE) or any other unsupported platform/interface
        will result in module run failure."
    type: str
    choices:
      - 100G
      - 40G
      - not-supported
  force_gigabit_fiber:
    description:
      - Enables or disables forcing of gigabit fiber media.
      - When C(true) for a gigabit fiber interface, the media setting will be forced, and no auto-negotiation will be
        performed.
      - When C(false) auto-negotiation will be performed with just a single gigabit fiber option advertised.
    type: bool
  prefer_port:
    description:
      - Indicates which side of a combo port the interface uses, if both sides have the potential for an external link.
      - The default value for a combo port is sfp. Do not use this option for non-combo ports.
    type: str
    choices:
      - sfp
      - fixed
  media_fixed:
    description:
      - "Specifies the settings for a fixed (non-pluggable) interface."
      - Use this option only with a combo port to specify the media type for the fixed interface,
        when it is not the preferred port.
    type: str
    choices:
      - 100000-FD
      - 100000LR4-FD
      - 10000LR-FD
      - 10000T-FD
      - 1000SX-FD
      - 100TX-FD
      - 10T-HD
      - 20000-FD
      - 40000LR4-FD
      - 100000AR4-FD
      - 100000SR4-FD
      - 10000SFPCU-FD
      - 1000CX-FD
      - 1000T-FD
      - 100TX-HD
      - 12000-FD
      - 21000-FD
      - 40000SR4-FD
      - 100000CR4-FD
      - 10000ER-FD
      - 10000SR-FD
      - 1000LX-FD
      - 1000T-HD
      - 10T-FD
      - 16000-FD
      - 40000-FD
      - 42000-FD
      - auto
      - no-phy
  media_sfp:
    description:
      - "Specifies the settings for an SFP (pluggable) interface."
      - Use this option only with a combo port to specify the media type for the SFP interface,
        when it is not the preferred port.
    type: str
    choices:
      - 100000-FD
      - 100000LR4-FD
      - 10000LR-FD
      - 10000T-FD
      - 1000SX-FD
      - 100TX-FD
      - 10T-HD
      - 20000-FD
      - 40000LR4-FD
      - 100000AR4-FD
      - 100000SR4-FD
      - 10000SFPCU-FD
      - 1000CX-FD
      - 1000T-FD
      - 100TX-HD
      - 12000-FD
      - 21000-FD
      - 40000SR4-FD
      - 100000CR4-FD
      - 10000ER-FD
      - 10000SR-FD
      - 1000LX-FD
      - 1000T-HD
      - 10T-FD
      - 16000-FD
      - 40000-FD
      - 42000-FD
      - auto
      - no-phy
  flow_control:
    description:
      - Specifies how the system controls the sending of PAUSE frames.
      - When C(tx-rx), the interface honors pause frames from its partner,
        and also generates pause frames when necessary.
      - When C(tx), the interface ignores pause frames from its partner, and generates pause frames when necessary.
      - When C(rx), the interface honors pause frames from its partner, but does not generate pause frames.
      - When (none), the flow control is disabled on the interface.
    type: str
    choices:
      - none
      - rx
      - tx
      - tx-rx
  forward_error_correction:
    description:
      - "Enables or disables IEEE 802.3bm Clause 91 Reed-Solomon Forward Error Correction on 100G interfaces. Not valid
        for LR4 media."
      - This option is only supported on selected hardware platforms and interfaces.
      - "Attempting to enable this option on a C(VE) or any other unsupported platform/interface
        will result in module run failure."
    type: str
    choices:
      - enabled
      - disabled
      - not-supported
      - auto
  port_fwd_mode:
    description:
      - Specifies the operation mode.
    type: str
    choices:
      - l3
      - passive
      - virtual-wire
  lldp_admin:
    description:
      - Specifies LLDP settings on an interface level.
      - When C(disabled), the interface neither transmits (sends) LLDP messages to nor receives LLDP messages
        from neighboring devices.
      - When C(txonly), the interface transmits LLDP messages to neighbor devices, but does not receive LLDP messages
        from neighbor devices.
      - When C(rxonly), the interface receives LLDP messages from neighbor devices, but does not transmit LLDP messages
        to neighbor devices.
      - When C(txrx), the interface transmits LLDP messages to and receives LLDP messages from neighboring devices.
    type: str
    choices:
      - disable
      - rxonly
      - txonly
      - txrx
  lldp_tlvmap:
    description:
      - Specifies the content of an LLDP message being sent or received.
      - "Each LLDP attribute specified with this setting is optional and is in the form of Type, Length, Value
        (TLV)."
      - "The three mandatory TLVs not taken into account when calculating this value are: C(Chassis ID), C(Port ID),
        and C(TTL)."
      - The optional attributes that are available have a specific TLV numeric value mapped to them.
      - The C(Port Description) attribute has a TLV value of C(8).
      - The C(System Name) attribute has a TLV value of C(16).
      - The C(System Description) attribute has a TLV value of C(32).
      - The C(System Capabilities) attribute has a TLV value of C(64).
      - The C(Management Address) attribute has a TLV value of C(128).
      - The C(Port VLAN ID) attribute has a TLV value of C(256).
      - The C(VLAN Name) attribute has a TLV value of C(512).
      - The C(Port and Protocol VLAN ID) attribute has a TLV value of C(1024).
      - The C(Protocol Identity) attribute has a TLV value of C(2048).
      - "The C(MAC/PHY Config Status) attribute has a TLV value of C(4096)."
      - The C(Link Aggregation) attribute has a TLV value of C(8192).
      - The C(Max Frame Size) attribute has a TLV value of C(32768).
      - The C(Product Model) attribute has a TLV value of C(65536).
      - The C(lldp_tlvmap) is a numeric value that is a sum of all TLV values of selected attributes.
      - Setting C(lldp_tlvmap) to C(0) will remove all attributes from the interface.
      - Setting C(lldp_tlvmap) to C(114680) will add all attributes to the interface.
    type: int
  stp:
    description:
      - Enables or disables STP.
    type: bool
  stp_auto_edge_port:
    description:
      - Sets STP automatic edge port detection for the interface.
      - "When C(true), the system monitors the interface for incoming STP, RSTP, or MSTP packets. If no such packets are
        received for a sufficient period of time (about three seconds), the interface is automatically given edge port
        status."
      - When C(false), the system never gives the interface edge port status automatically. Any STP setting set on a
        per-interface basis applies to all spanning tree instances.
    type: bool
  stp_edge_port:
    description:
      - Specifies whether the interface connects to an end station instead of another spanning tree bridge.
    type: bool
  stp_link_type:
    description:
      - Specifies the STP link type for the interface.
    type: str
    choices:
      - auto
      - p2p
      - shared
  sflow:
    description:
      -  Specifies sFlow settings for the interface.
    suboptions:
      poll_interval:
        description:
          - Specifies the maximum interval between two pollings, in seconds.
          - For this setting to take effect, C(poll_interval_global) must be set to C(false).
          - The valid range is 0 - 4294967295.
        type: int
      poll_interval_global:
        description:
          - Specifies whether the global interface C(poll_interval) setting overrides the object-level
            C(poll_interval) setting.
          - When C(true)) the C(poll_interval) setting does not take effect.
        type: bool
    type: dict
extends_documentation_fragment: f5networks.f5_modules.f5
author:
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Update Interface Settings
  bigip_interface:
    name: 1.1
    stp: true
    stp_auto_edge_port: false
    stp_edge_port: true
    stp_link_type: shared
    description: my description
    flow_control: tx
    lldp_admin: txrx
    lldp_tlvmap: 8
    force_gigabit_fiber: false
    sflow:
      - poll_interval: 10
      - poll_interval_global: false
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost

- name: Disable Interface
  bigip_interface:
    name: 1.1
    enabled: false
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost

- name: Change sflow interface settings
  bigip_interface:
    name: 1.1
    sflow:
      - poll_interval: 0
      - poll_interval_global: true
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost
'''

RETURN = r'''
description:
  description: User defined description.
  returned: changed
  type: str
  sample: my description
enabled:
  description: The current status of the interface.
  returned: changed
  type: bool
  sample: true
bundle:
  description: Enables or disables bundle capability.
  returned: changed
  type: str
  sample: not-supported
bundle_speed:
  description: The bundle speed.
  returned: changed
  type: str
  sample: 100G
force_gigabit_fiber:
  description: Enables or disables forcing of gigabit fiber media.
  returned: changed
  type: bool
  sample: true
prefer_port:
  description: The side of a combo port the interface uses.
  returned: changed
  type: str
  sample: fixed
media_fixed:
  description: The settings for a fixed interface.
  returned: changed
  type: str
  sample: 100000-FD
media_sfp:
  description: The settings for a SFP interface.
  returned: changed
  type: str
  sample: 100000-FD
flow_control:
  description: Specifies how the system controls the sending of PAUSE frames.
  returned: changed
  type: str
  sample: tx
forward_error_correction:
  description: Enables or disables Forward Error Correction.
  returned: changed
  type: str
  sample: auto
port_fwd_mode:
  description: The operation mode.
  returned: changed
  type: str
  sample: passive
lldp_admin:
  description: The LLDP settings on an interface level.
  returned: changed
  type: str
  sample: txrx
lldp_tlvmap:
  description: The content of an LLDP message being sent or received.
  returned: changed
  type: int
  sample: 136
stp:
  description: Enables or disables STP.
  returned: changed
  type: bool
  sample: false
stp_auto_edge_port:
  description: Sets STP automatic edge port detection for the interface.
  returned: changed
  type: bool
  sample: true
stp_edge_port:
  description: Specifies whether the interface connects to an end station instead of another spanning tree bridge.
  returned: changed
  type: bool
  sample: false
stp_link_type:
  description: The STP link type for the interface.
  returned: changed
  type: str
  sample: shared
sflow:
  description: Specifies sFlow settings for the interface.
  type: complex
  returned: changed
  contains:
    poll_interval_global:
      description: The global sFlow settings override.
      returned: changed
      type: bool
      sample: true
    poll_interval:
      description: The maximum interval in seconds between two pollings.
      returned: changed
      type: int
      sample: 128
  sample: hash/dictionary of values
'''

import copy
from datetime import datetime

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, f5_argument_spec, flatten_boolean,
    transform_name
)
from ..module_utils.compare import cmp_str_with_none
from ..module_utils.icontrol import tmos_version
from ..module_utils.teem import send_teem


class Parameters(AnsibleF5Parameters):
    api_map = {
        'bundleSpeed': 'bundle_speed',
        'flowControl': 'flow_control',
        'forceGigabitFiber': 'force_gigabit_fiber',
        'forwardErrorCorrection': 'forward_error_correction',
        'lldpAdmin': 'lldp_admin',
        'lldpTlvmap': 'lldp_tlvmap',
        'mediaFixed': 'media_fixed',
        'mediaSfp': 'media_sfp',
        'portFwdMode': 'port_fwd_mode',
        'preferPort': 'prefer_port',
        'stpAutoEdgePort': 'stp_auto_edge_port',
        'stpEdgePort': 'stp_edge_port',
        'stpLinkType': 'stp_link_type',
    }

    api_attributes = [
        'bundle',
        'bundleSpeed',
        'description',
        'enabled',
        'disabled',
        'flowControl',
        'forceGigabitFiber',
        'forwardErrorCorrection',
        'lldpAdmin',
        'lldpTlvmap',
        'mediaFixed',
        'mediaSfp',
        'portFwdMode',
        'preferPort',
        'stp',
        'stpAutoEdgePort',
        'stpEdgePort',
        'stpLinkType',
        'sflow',
    ]

    returnables = [
        'description',
        'enabled',
        'disabled',
        'bundle',
        'bundle_speed',
        'force_gigabit_fiber',
        'prefer_port',
        'media_fixed',
        'media_sfp',
        'flow_control',
        'forward_error_correction',
        'port_fwd_mode',
        'lldp_tlvmap',
        'lldp_admin',
        'stp',
        'stp_auto_edge_port',
        'stp_edge_port',
        'stp_link_type',
        'sflow_interval',
        'sflow_global',
    ]

    updatables = [
        'description',
        'enabled',
        'disabled',
        'bundle',
        'bundle_speed',
        'force_gigabit_fiber',
        'prefer_port',
        'media_fixed',
        'media_sfp',
        'flow_control',
        'forward_error_correction',
        'port_fwd_mode',
        'lldp_tlvmap',
        'lldp_admin',
        'stp',
        'stp_auto_edge_port',
        'stp_edge_port',
        'stp_link_type',
        'sflow_interval',
        'sflow_global',
    ]


class ApiParameters(Parameters):
    @property
    def sflow_interval(self):
        if self._values['sflow'] is None:
            return None
        return self._values['sflow']['pollInterval']

    @property
    def sflow_global(self):
        if self._values['sflow'] is None:
            return None
        return self._values['sflow']['pollIntervalGlobal']


class ModuleParameters(Parameters):
    @property
    def enabled(self):
        result = flatten_boolean(self._values['enabled'])
        if result == 'yes':
            return True

    @property
    def disabled(self):
        result = flatten_boolean(self._values['enabled'])
        if result == 'no':
            return True

    @property
    def lldp_tlvmap(self):
        if self._values['lldp_tlvmap'] is None:
            return None
        if self._values['lldp_tlvmap'] == 0:
            return self._values['lldp_tlvmap']
        if 8 <= self._values['lldp_tlvmap'] <= 114680:
            return self._values['lldp_tlvmap']
        raise F5ModuleError(
            "TLV value {0} is out of valid range of: 8 - 114680."
        )

    @property
    def force_gigabit_fiber(self):
        result = flatten_boolean(self._values['force_gigabit_fiber'])
        if result == 'yes':
            return 'enabled'
        if result == 'no':
            return 'disabled'

    @property
    def stp(self):
        result = flatten_boolean(self._values['stp'])
        if result == 'yes':
            return 'enabled'
        if result == 'no':
            return 'disabled'

    @property
    def stp_auto_edge_port(self):
        result = flatten_boolean(self._values['stp_auto_edge_port'])
        if result == 'yes':
            return 'enabled'
        if result == 'no':
            return 'disabled'

    @property
    def stp_edge_port(self):
        result = flatten_boolean(self._values['stp_edge_port'])
        if result == 'yes':
            return 'true'
        if result == 'no':
            return 'false'

    @property
    def sflow_interval(self):
        if self._values['sflow'] is None:
            return None
        if self._values['sflow']['poll_interval'] is None:
            return None
        if 0 <= self._values['sflow']['poll_interval'] <= 4294967295:
            return self._values['sflow']['poll_interval']
        raise F5ModuleError(
            "Valid 'poll_interval' must be in range 0 - 4294967295."
        )

    @property
    def sflow_global(self):
        if self._values['sflow'] is None:
            return None
        result = flatten_boolean(self._values['sflow']['poll_interval_global'])
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
    def sflow(self):
        to_filter = dict(
            pollInterval=self._values['sflow_interval'],
            pollIntervalGlobal=self._values['sflow_global'],
        )
        result = self._filter_params(to_filter)
        if result:
            return result


class ReportableChanges(Changes):
    returnables = [
        'description',
        'enabled',
        'bundle',
        'bundle_speed',
        'force_gigabit_fiber',
        'prefer_port',
        'media_fixed',
        'media_sfp',
        'flow_control',
        'forward_error_correction',
        'port_fwd_mode',
        'lldp_tlvmap',
        'lldp_admin',
        'stp',
        'stp_auto_edge_port',
        'stp_edge_port',
        'stp_link_type',
        'sflow',
    ]

    @property
    def enabled(self):
        enabled = self._values.get('enabled', None)
        disabled = self._values.get('disabled', None)
        if enabled:
            return 'yes'
        if disabled:
            return 'no'

    @property
    def stp(self):
        result = flatten_boolean(self._values['stp'])
        return result

    @property
    def stp_auto_edge_port(self):
        result = flatten_boolean(self._values['stp_auto_edge_port'])
        return result

    @property
    def stp_edge_port(self):
        result = flatten_boolean(self._values['stp_edge_port'])
        return result

    @property
    def sflow(self):
        to_filter = dict(
            poll_interval=self._values['sflow_interval'],
            poll_interval_global=self._values['sflow_global'],
        )
        result = self._filter_params(to_filter)
        if result:
            return result


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
    def description(self):
        result = cmp_str_with_none(self.want.description, self.have.description)
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
        if self.exists():
            return self.update()
        else:
            raise F5ModuleError(
                "The specified interface: {0} does not exist.".format(self.want.name)
            )

    def should_update(self):
        result = self._update_changed_options()
        if result:
            return True
        return False

    def update(self):
        self.have = self.read_current_from_device()
        if not self.should_update():
            return False
        if self.module.check_mode:
            return True
        self.update_on_device()
        return True

    def exists(self):
        uri = "https://{0}:{1}/mgmt/tm/net/interface/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(name=self.want.name)
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status == 404 or 'code' in response and response['code'] == 404:
            return False
        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True

        errors = [401, 403, 409, 500, 501, 502, 503, 504]

        if resp.status in errors or 'code' in response and response['code'] in errors:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)

    def update_on_device(self):
        params = self.changes.api_params()
        uri = "https://{0}:{1}/mgmt/tm/net/interface/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(name=self.want.name)
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
        uri = "https://{0}:{1}/mgmt/tm/net/interface/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(name=self.want.name)
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return ApiParameters(params=response)
        raise F5ModuleError(resp.content)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        self.choices = [
            '100000-FD', '100000LR4-FD', '10000LR-FD', '10000T-FD', '1000SX-FD', '100TX-FD', '10T-HD', '20000-FD',
            '40000LR4-FD', '100000AR4-FD', '100000SR4-FD', '10000SFPCU-FD', '1000CX-FD', '1000T-FD', '100TX-HD',
            '12000-FD', '21000-FD', '40000SR4-FD', '100000CR4-FD', '10000ER-FD', '10000SR-FD', '1000LX-FD', '1000T-HD',
            '10T-FD', '16000-FD', '40000-FD', '42000-FD', 'auto', 'no-phy'
        ]
        self.bundle = ['disabled', 'enabled', 'not-supported']
        self.fec = copy.copy(self.bundle)
        self.fec.append('auto')
        argument_spec = dict(
            name=dict(
                required=True
            ),
            description=dict(),
            enabled=dict(
                type='bool'
            ),
            bundle=dict(choices=self.bundle),
            bundle_speed=dict(
                choices=[
                    '100G', '40G', 'not-supported'
                ]
            ),
            force_gigabit_fiber=dict(type='bool'),
            prefer_port=dict(
                choices=[
                    'fixed', 'sfp'
                ]
            ),
            media_fixed=dict(choices=self.choices),
            media_sfp=dict(choices=self.choices),
            flow_control=dict(
                choices=[
                    'none', 'rx', 'tx', 'tx-rx'
                ]
            ),
            forward_error_correction=dict(choices=self.fec),
            port_fwd_mode=dict(
                choices=[
                    'l3', 'passive', 'virtual-wire'
                ]
            ),
            lldp_tlvmap=dict(type='int'),
            lldp_admin=dict(
                choices=[
                    'disable', 'rxonly', 'txonly', 'txrx'
                ]
            ),
            stp=dict(type='bool'),
            stp_auto_edge_port=dict(type='bool'),
            stp_edge_port=dict(type='bool'),
            stp_link_type=dict(
                choices=['auto', 'p2p', 'shared']
            ),
            sflow=dict(
                type='dict',
                options=dict(
                    poll_interval=dict(type='int'),
                    poll_interval_global=dict(type='bool'),
                )
            )
        )
        self.argument_spec = {}
        self.argument_spec.update(f5_argument_spec)
        self.argument_spec.update(argument_spec)


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
    )

    try:
        mm = ModuleManager(module=module)
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
