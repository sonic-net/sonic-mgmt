#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2017, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_trunk
short_description: Manage trunks on a BIG-IP
description:
  - Manages trunks on a BIG-IP.
version_added: "1.0.0"
options:
  name:
    description:
      - Specifies the name of the trunk.
    type: str
    required: True
  interfaces:
    description:
      - The interfaces that are part of the trunk.
      - To clear the list of interfaces, specify an empty list.
    type: list
    elements: str
  description:
    description:
      - Description of the trunk.
    type: str
  link_selection_policy:
    description:
      - Once the trunk is configured, specifies the policy the trunk uses to determine
        which member link (interface) can handle new traffic.
      - When creating a new trunk, if this value is not specified, the default is C(auto).
      - When C(auto), specifies the system automatically determines which interfaces
        can handle new traffic. For the C(auto) option, the member links must all be the
        same media type and speed.
      - When C(maximum-bandwidth), specifies the system determines which interfaces
        can handle new traffic based on the members' maximum bandwidth.
    type: str
    choices:
      - auto
      - maximum-bandwidth
  frame_distribution_hash:
    description:
      - Specifies the basis for the hash the system uses as the frame distribution
        algorithm. The system uses the resulting hash to determine which interface to
        use for forwarding traffic.
      - When creating a new trunk, if this parameter is not specified, the default is
        C(source-destination-ip).
      - When C(source-destination-mac), specifies the system bases the hash on the
        combined MAC addresses of the source and the destination.
      - When C(destination-mac), specifies the system bases the hash on the MAC
        address of the destination.
      - When C(source-destination-ip), specifies the system bases the hash on the
        combined IP addresses of the source and the destination.
    type: str
    choices:
      - destination-mac
      - source-destination-ip
      - source-destination-mac
  lacp_enabled:
    description:
      - When C(true), specifies the system supports the link aggregation control
        protocol (LACP), which monitors the trunk by exchanging control packets over
        the member links to determine the health of the links.
      - If LACP detects a failure in a member link, it removes the link from the link
        aggregation.
      - When creating a new trunk, if this parameter is not specified, LACP is C(false).
      - LACP is disabled by default for backward compatibility. If this does not apply
        to your network, we recommend that you enable LACP.
    type: bool
  lacp_mode:
    description:
      - Specifies the operation mode for link aggregation control protocol (LACP),
        if LACP is enabled for the trunk.
      - When creating a new trunk, if this parameter is not specified, the default
        is C(active).
      - When C(active), specifies the system periodically sends control packets
        regardless of whether the partner system has issued a request.
      - When C(passive), specifies the system sends control packets only when
        the partner system has issued a request.
    type: str
    choices:
      - active
      - passive
  lacp_timeout:
    description:
      - Specifies the rate at which the system sends the LACP control packets.
      - When creating a new trunk, if this parameter is not specified, the default is
        C(long).
      - When C(long), specifies the system sends an LACP control packet every 30 seconds.
      - When C(short), specifies the system sends an LACP control packet every second.
    type: str
    choices:
      - long
      - short
  qinq_ethertype:
    description:
      - Specifies the ether-type value used for the packets handled on this trunk when
        it is a member in a QinQ VLAN.
      - The ether-type can be set to any string containing a valid hexadecimal 16 bits
        number, or any of the well known ether-types; C(0x8100), C(0x9100), C(0x88a8).
      - This parameter is not supported on Virtual Editions.
      - You should always wrap this value in quotes to prevent Ansible from interpreting
        the value as a literal hexadecimal number and converting it to an integer.
    type: raw
  state:
    description:
      - When C(present), ensures the resource exists.
      - When C(absent), ensures the resource is removed.
    type: str
    choices:
      - present
      - absent
    default: present
extends_documentation_fragment: f5networks.f5_modules.f5
author:
  - Tim Rupp (@caphrim007)
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Create a trunk on hardware
  bigip_trunk:
    name: trunk1
    interfaces:
      - 1.1
      - 1.2
    link_selection_policy: maximum-bandwidth
    frame_distribution_hash: destination-mac
    lacp_enabled: true
    lacp_mode: passive
    lacp_timeout: short
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost
'''

RETURN = r'''
lacp_mode:
  description: Operation mode for LACP if the lacp option is enabled for the trunk.
  returned: changed
  type: str
  sample: active
lacp_timeout:
  description: Rate at which the system sends the LACP control packets.
  returned: changed
  type: str
  sample: long
link_selection_policy:
  description:
    - LACP policy the trunk uses to determine which member link (interface)
      can handle new traffic.
  returned: changed
  type: str
  sample: auto
frame_distribution_hash:
  description: Hash the system uses as the frame distribution algorithm.
  returned: changed
  type: str
  sample: src-dst-ipport
lacp_enabled:
  description: Whether the system supports the link aggregation control protocol (LACP) or not.
  returned: changed
  type: bool
  sample: true
interfaces:
  description: Interfaces that are part of the trunk.
  returned: changed
  type: list
  sample: ['int1', 'int2']
description:
  description: Description of the trunk.
  returned: changed
  type: str
  sample: My trunk
qinq_ethertype:
  description: Ether-type value used for the packets handled on this trunk when it is a member in a QinQ VLAN.
  returned: changed
  type: str
  sample: 0x9100
'''
from datetime import datetime
from ansible.module_utils.basic import AnsibleModule

from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, f5_argument_spec
)
from ..module_utils.compare import cmp_simple_list
from ..module_utils.icontrol import tmos_version
from ..module_utils.teem import send_teem


class Parameters(AnsibleF5Parameters):
    api_map = {
        'lacpMode': 'lacp_mode',
        'lacpTimeout': 'lacp_timeout',
        'linkSelectPolicy': 'link_selection_policy',
        'distributionHash': 'frame_distribution_hash',
        'lacp': 'lacp_enabled',
        'qinqEthertype': 'qinq_ethertype',
    }

    api_attributes = [
        'lacp',
        'lacpMode',
        'lacpTimeout',
        'linkSelectPolicy',
        'distributionHash',
        'interfaces',
        'description',
        'qinqEthertype',
    ]

    returnables = [
        'lacp_mode',
        'lacp_timeout',
        'link_selection_policy',
        'frame_distribution_hash',
        'lacp_enabled',
        'interfaces',
        'description',
        'qinq_ethertype',
    ]

    updatables = [
        'lacp_mode',
        'lacp_timeout',
        'link_selection_policy',
        'frame_distribution_hash',
        'lacp_enabled',
        'interfaces',
        'description',
        'qinq_ethertype',
    ]


class ApiParameters(Parameters):
    @property
    def lacp_enabled(self):
        if self._values['lacp_enabled'] is None:
            return None
        if self._values['lacp_enabled'] == 'enabled':
            return True
        return False

    @property
    def interfaces(self):
        if self._values['interfaces'] is None:
            return None
        result = list(set(self._values['interfaces']))
        result.sort()
        return result


class ModuleParameters(Parameters):
    @property
    def frame_distribution_hash(self):
        if self._values['frame_distribution_hash'] is None:
            return None
        elif self._values['frame_distribution_hash'] == 'source-destination-ip':
            return 'src-dst-ipport'
        elif self._values['frame_distribution_hash'] == 'source-destination-mac':
            return 'src-dst-mac'
        elif self._values['frame_distribution_hash'] == 'destination-mac':
            return 'dst-mac'

    @property
    def interfaces(self):
        if self._values['interfaces'] is None:
            return None
        if len(self._values['interfaces']) == 1 and self._values['interfaces'][0] == '':
            return ''
        result = [str(x) for x in self._values['interfaces']]
        result = list(set(result))
        result.sort()
        return result


class Changes(Parameters):
    def to_return(self):
        result = {}
        try:
            for returnable in self.returnables:
                result[returnable] = getattr(self, returnable)
            result = self._filter_params(result)
        except Exception:
            pass
        return result


class UsableChanges(Changes):
    @property
    def lacp_enabled(self):
        if self._values['lacp_enabled'] is None:
            return None
        if self._values['lacp_enabled']:
            return 'enabled'
        return 'disabled'


class ReportableChanges(Changes):
    @property
    def frame_distribution_hash(self):
        if self._values['frame_distribution_hash'] is None:
            return None
        elif self._values['frame_distribution_hash'] == 'src-dst-ipport':
            return 'source-destination-ip'
        elif self._values['frame_distribution_hash'] == 'src-dst-mac':
            return 'source-destination-mac'
        elif self._values['frame_distribution_hash'] == 'dst-mac':
            return 'destination-mac'

    @property
    def lacp_enabled(self):
        if self._values['lacp_enabled'] is None:
            return None
        if self._values['lacp_enabled'] == 'enabled':
            return True
        return False


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
    def interfaces(self):
        result = cmp_simple_list(self.want.interfaces, self.have.interfaces)
        return result


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.client = F5RestClient(**self.module.params)
        self.want = ModuleParameters(params=self.module.params)
        self.have = ApiParameters()
        self.changes = UsableChanges()

    def _set_changed_options(self):
        changed = {}
        for key in Parameters.returnables:
            if getattr(self.want, key) is not None:
                changed[key] = getattr(self.want, key)
        if changed:
            self.changes = UsableChanges(params=changed)

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

    def should_update(self):
        result = self._update_changed_options()
        if result:
            return True
        return False

    def exec_module(self):
        start = datetime.now().isoformat()
        version = tmos_version(self.client)
        changed = False
        result = dict()
        state = self.want.state

        if state == "present":
            changed = self.present()
        elif state == "absent":
            changed = self.absent()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        send_teem(start, self.client, self.module, version)
        return result

    def _announce_deprecations(self, result):
        warnings = result.pop('__warnings', [])
        for warning in warnings:
            self.client.module.deprecate(
                msg=warning['msg'],
                version=warning['version']
            )

    def present(self):
        if self.exists():
            return self.update()
        else:
            return self.create()

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def update(self):
        self.have = self.read_current_from_device()
        if not self.should_update():
            return False
        if self.module.check_mode:
            return True
        self.update_on_device()
        return True

    def remove(self):
        if self.module.check_mode:
            return True
        self.remove_from_device()
        if self.exists():
            raise F5ModuleError("Failed to delete the resource.")
        return True

    def create(self):
        if self.want.link_selection_policy is None:
            self.want.update({'link_selection_policy': 'auto'})
        if self.want.frame_distribution_hash is None:
            self.want.update({'frame_distribution_hash': 'source-destination-ip'})
        if self.want.lacp_enabled is None:
            self.want.update({'lacp_enabled': False})
        if self.want.lacp_mode is None:
            self.want.update({'lacp_mode': 'active'})
        if self.want.lacp_timeout is None:
            self.want.update({'lacp_timeout': 'long'})
        self._set_changed_options()
        if self.module.check_mode:
            return True
        self.create_on_device()
        return True

    def exists(self):
        uri = "https://{0}:{1}/mgmt/tm/net/trunk/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            self.want.name
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

    def create_on_device(self):
        params = self.changes.api_params()
        params['name'] = self.want.name
        uri = "https://{0}:{1}/mgmt/tm/net/trunk/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.post(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if 'code' in response and response['code'] in [400, 403, 409]:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)

    def update_on_device(self):
        params = self.changes.api_params()
        uri = "https://{0}:{1}/mgmt/tm/net/trunk/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            self.want.name
        )
        resp = self.client.api.patch(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if 'code' in response and response['code'] == 400:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)

    def remove_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/net/trunk/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            self.want.name
        )
        resp = self.client.api.delete(uri)
        if resp.status == 200:
            return True

    def read_current_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/net/trunk/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            self.want.name
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if 'code' in response and response['code'] == 400:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)
        return ApiParameters(params=response)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(required=True),
            interfaces=dict(
                type='list',
                elements='str',
            ),
            link_selection_policy=dict(
                choices=['auto', 'maximum-bandwidth']
            ),
            frame_distribution_hash=dict(
                choices=['destination-mac', 'source-destination-ip', 'source-destination-mac']
            ),
            lacp_enabled=dict(type='bool'),
            lacp_mode=dict(choices=['active', 'passive']),
            lacp_timeout=dict(choices=['short', 'long']),
            description=dict(),
            state=dict(
                default='present',
                choices=['absent', 'present']
            ),
            qinq_ethertype=dict(type='raw'),
        )
        self.argument_spec = {}
        self.argument_spec.update(f5_argument_spec)
        self.argument_spec.update(argument_spec)


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode
    )

    try:
        mm = ModuleManager(module=module)
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
