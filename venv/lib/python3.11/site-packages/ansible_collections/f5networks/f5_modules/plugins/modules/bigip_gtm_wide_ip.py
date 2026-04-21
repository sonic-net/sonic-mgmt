#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2017, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_gtm_wide_ip
short_description: Manages F5 BIG-IP GTM Wide IP
description:
  - Manages the F5 BIG-IP GTM (now BIG-IP DNS) Wide IP.
version_added: "1.0.0"
options:
  pool_lb_method:
    description:
      - Specifies the load balancing method used to select a pool in this wide
        IP. This setting is relevant only when multiple pools are configured
        for a Wide IP.
    type: str
    aliases: ['lb_method']
    choices:
      - round-robin
      - ratio
      - topology
      - global-availability
  name:
    description:
      - Wide IP name. This name must be formatted as a fully qualified
        domain name (FQDN). You can also use the alias C(wide_ip) but this
        is deprecated and will be removed in a future Ansible version.
    type: str
    required: True
    aliases:
      - wide_ip
  type:
    description:
      - Specifies the type of Wide IP. GTM Wide IPs need to be keyed by query
        type in addition to name, because pool members need different attributes
        depending on the response RDATA they are meant to supply.
    type: str
    required: True
    choices:
      - a
      - aaaa
      - cname
      - mx
      - naptr
      - srv
  state:
    description:
      - When C(present) or C(enabled), ensures the Wide IP exists and
        is enabled.
      - When C(absent), ensures the Wide IP has been removed.
      - When C(disabled), ensures the Wide IP exists and is disabled.
    type: str
    choices:
      - present
      - absent
      - disabled
      - enabled
    default: present
  partition:
    description:
      - Device partition to manage resources on.
    type: str
    default: Common
  pools:
    description:
      - The pools you want associated with the Wide IP.
      - If C(ratio) is not provided when creating a new Wide IP, it will default
        to 1.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - The name of the pool to include.
        type: str
        required: True
      ratio:
        description:
          - Ratio for the pool.
          - The system uses this number with the Ratio load balancing method.
          - When C(ratio) is not provided, the module assigns it value of C(0).
        type: int
      order:
        description:
          - Order of the pool in relation to other pools attached to this Wide IP.
          - Pool order is significant when the Global Availability load balancing method is used.
          - When C(order) is not provided, the module assigns it value of C(0).
        type: int
  irules:
    description:
      - List of rules to be applied.
      - If you want to remove all existing iRules, specify a single empty value; C("").
        See the documentation for an example.
    type: list
    elements: str
  aliases:
    description:
      - Specifies alternate domain names for the web site content you are load
        balancing.
      - You can use the same wildcard characters for aliases as you can for actual
        Wide IP names.
    type: list
    elements: str
  last_resort_pool:
    description:
      - Specifies which GTM pool for the system to use as the last resort pool for
        the Wide IP.
      - The valid pools for this parameter are those with the C(type) specified in this
        module.
    type: str
  persistence:
    description:
      - When C(true), ensures when a local DNS makes repetitive requests on
        behalf of a client, the system reconnects the client to the same resource
        as previous requests.
      - When C(false), ensures repetitive requests do not reconnect the client
        to the same resource.
    type: bool
  persistence_ttl:
    description:
      - Specifies the time to maintain a connection between an local DNS and
        a particular virtual server.
    type: int
  persist_cidr_ipv4:
    description:
      - Specifies a mask used to group IPv4 LDNS addresses. This feature
        allows one persistence record to be shared by LDNS addresses
        that match within this mask.
    type: int
  persist_cidr_ipv6:
    description:
      - Specifies a mask used to group IPv6 LDNS addresses. This feature
        allows one persistence record to be shared by LDNS addresses
        that match within this mask.
    type: int
extends_documentation_fragment: f5networks.f5_modules.f5
author:
  - Tim Rupp (@caphrim007)
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Set lb method
  bigip_gtm_wide_ip:
    pool_lb_method: round-robin
    name: my-wide-ip.example.com
    type: a
    provider:
      user: admin
      password: secret
      server: lb.mydomain.com
  delegate_to: localhost

- name: Add iRules to the Wide IP
  bigip_gtm_wide_ip:
    pool_lb_method: round-robin
    name: my-wide-ip.example.com
    type: a
    irules:
      - irule1
      - irule2
    provider:
      user: admin
      password: secret
      server: lb.mydomain.com
  delegate_to: localhost

- name: Remove one iRule from the Virtual Server
  bigip_gtm_wide_ip:
    pool_lb_method: round-robin
    name: my-wide-ip.example.com
    type: a
    irules:
      - irule1
    provider:
      user: admin
      password: secret
      server: lb.mydomain.com
  delegate_to: localhost

- name: Remove all iRules from the Virtual Server
  bigip_gtm_wide_ip:
    pool_lb_method: round-robin
    name: my-wide-ip.example.com
    type: a
    irules: ""
    provider:
      user: admin
      password: secret
      server: lb.mydomain.com
  delegate_to: localhost

- name: Assign a pool with ratio to the Wide IP
  bigip_gtm_wide_ip:
    pool_lb_method: round-robin
    name: my-wide-ip.example.com
    type: a
    pools:
      - name: pool1
        ratio: 100
        order: 2
      - name: pool1
        ratio: 100
        order: 1
    provider:
      user: admin
      password: secret
      server: lb.mydomain.com
  delegate_to: localhost

- name: Assign a pool with persistence to the Wide IP
  bigip_gtm_wide_ip:
    pool_lb_method: round-robin
    name: my-wide-ip.example.com
    type: a
    pools:
      - name: pool1
        persistence: true
        persist_cidr_ipv4: 24
        persist_cidr_ipv6: 120
        persistence_ttl: 3500
    provider:
      user: admin
      password: secret
      server: lb.mydomain.com
  delegate_to: localhost
'''

RETURN = r'''
lb_method:
  description: The new load balancing method used by the Wide IP.
  returned: changed
  type: str
  sample: topology
state:
  description: The new state of the Wide IP.
  returned: changed
  type: str
  sample: disabled
irules:
  description: iRules set on the Wide IP.
  returned: changed
  type: list
  sample: ['/Common/irule1', '/Common/irule2']
aliases:
  description: Aliases set on the Wide IP.
  returned: changed
  type: list
  sample: ['alias1.foo.com', '*.wildcard.domain']
persistence:
  description: Whether pool connections will be persisted.
  returned: changed
  type: bool
  sample: false
persist_cidr_ipv4:
  description: Specifies a mask used to group IPv4 LDNS addresses.
  returned: changed
  type: int
  sample: 32
persist_cidr_ipv6:
  description: Specifies a mask used to group IPv6 LDNS addresses.
  returned: changed
  type: int
  sample: 128
persistence_ttl:
  description: Specifies the persistence TTL between an local DNS and a particular virtual server.
  returned: changed
  type: int
  sample: 3600
'''
from datetime import datetime

from ansible.module_utils.basic import (
    AnsibleModule, env_fallback
)
from ansible.module_utils.six import iteritems

from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, transform_name, f5_argument_spec, flatten_boolean, fq_name, is_valid_fqdn
)
from ..module_utils.icontrol import (
    module_provisioned, tmos_version
)
from ..module_utils.teem import send_teem


class Parameters(AnsibleF5Parameters):
    api_map = {
        'poolLbMode': 'pool_lb_method',
        'rules': 'irules',
        'lastResortPool': 'last_resort_pool',
        'persistCidrIpv4': 'persist_cidr_ipv4',
        'persistCidrIpv6': 'persist_cidr_ipv6',
        'ttlPersistence': 'persistence_ttl',
    }

    updatables = [
        'pool_lb_method',
        'state',
        'pools',
        'irules',
        'enabled',
        'disabled',
        'aliases',
        'last_resort_pool',
        'persist_cidr_ipv4',
        'persist_cidr_ipv6',
        'persistence',
        'persistence_ttl',
    ]

    returnables = [
        'name',
        'pool_lb_method',
        'state',
        'pools',
        'irules',
        'aliases',
        'last_resort_pool',
        'persistence',
        'persist_cidr_ipv4',
        'persist_cidr_ipv6',
        'persistence_ttl',
    ]

    api_attributes = [
        'poolLbMode',
        'enabled',
        'disabled',
        'pools',
        'rules',
        'aliases',
        'lastResortPool',
        'persistence',
        'ttlPersistence',
        'persistCidrIpv4',
        'persistCidrIpv6',
    ]


class ApiParameters(Parameters):
    @property
    def disabled(self):
        if self._values['disabled'] is True:
            return True
        return False

    @property
    def enabled(self):
        if self._values['enabled'] is True:
            return True
        return False

    @property
    def pools(self):
        result = []
        if self._values['pools'] is None:
            return None
        pools = sorted(self._values['pools'], key=lambda x: x['order'])
        for item in pools:
            pool = dict()
            pool.update(item)
            name = '/{0}/{1}'.format(item['partition'], item['name'])
            del pool['nameReference']
            del pool['name']
            del pool['partition']
            pool['name'] = name
            result.append(pool)
        return result

    @property
    def last_resort_pool(self):
        if self._values['last_resort_pool'] in [None, '', 'none']:
            return ''
        return self._values['last_resort_pool']


class ModuleParameters(Parameters):
    @property
    def last_resort_pool(self):
        if self._values['last_resort_pool'] is None:
            return None
        if self._values['last_resort_pool'] in ['', 'none']:
            return 'none'
        return '{0} {1}'.format(
            self.type, fq_name(self.partition, self._values['last_resort_pool'])
        )

    @property
    def pool_lb_method(self):
        if self._values['pool_lb_method'] is None:
            return None
        lb_method = str(self._values['pool_lb_method'])
        return lb_method

    @property
    def type(self):
        if self._values['type'] is None:
            return None
        return str(self._values['type'])

    @property
    def name(self):
        if self._values['name'] is None:
            return None
        if not is_valid_fqdn(self._values['name']):
            raise F5ModuleError(
                "The provided name must be a valid FQDN"
            )
        return self._values['name']

    @property
    def state(self):
        if self._values['state'] == 'enabled':
            return 'present'
        return self._values['state']

    @property
    def enabled(self):
        if self._values['state'] == 'disabled':
            return False
        elif self._values['state'] in ['present', 'enabled']:
            return True
        else:
            return None

    @property
    def disabled(self):
        if self._values['state'] == 'disabled':
            return True
        elif self._values['state'] in ['present', 'enabled']:
            return False
        else:
            return None

    @property
    def pools(self):
        result = []
        if self._values['pools'] is None:
            return None
        for item in self._values['pools']:
            pool = dict()
            if 'name' not in item:
                raise F5ModuleError(
                    "'name' is a required key for items in the list of pools."
                )
            if 'ratio' not in item or item['ratio'] is None:
                pool['ratio'] = 0
            else:
                pool['ratio'] = item['ratio']
            if 'order' not in item or item['order'] is None:
                pool['order'] = 0
            else:
                pool['order'] = item['order']
            pool['name'] = fq_name(self.partition, item['name'])
            result.append(pool)
        if result:
            pools = sorted(result, key=lambda x: x['order'])
            return pools

    @property
    def irules(self):
        results = []
        if self._values['irules'] is None:
            return None
        if len(self._values['irules']) == 1 and self._values['irules'][0] == '':
            return ''
        for irule in self._values['irules']:
            result = fq_name(self.partition, irule)
            results.append(result)
        return results

    @property
    def aliases(self):
        if self._values['aliases'] is None:
            return None
        if len(self._values['aliases']) == 1 and self._values['aliases'][0] == '':
            return ''
        self._values['aliases'].sort()
        return self._values['aliases']

    @property
    def persistence(self):
        if self._values['persistence'] is None:
            return None
        result = flatten_boolean(self._values['persistence'])
        if result is None:
            return None
        if result == 'yes':
            return 'enabled'
        return 'disabled'

    @property
    def persistence_ttl(self):
        if self._values['persistence_ttl'] is None:
            return None
        if 0 <= self._values['persistence_ttl'] <= 4294967295:
            return self._values['persistence_ttl']
        raise F5ModuleError(
            "Valid 'persistence_ttl' must be in range 0 - 4294967295."
        )

    @property
    def persist_cidr_ipv4(self):
        if self._values['persist_cidr_ipv4'] is None:
            return None
        if 0 <= self._values['persist_cidr_ipv4'] <= 4294967295:
            return self._values['persist_cidr_ipv4']
        raise F5ModuleError(
            "Valid 'persist_cidr_ipv4' must be in range 0 - 4294967295."
        )

    @property
    def persist_cidr_ipv6(self):
        if self._values['persist_cidr_ipv6'] is None:
            return None
        if 0 <= self._values['persist_cidr_ipv6'] <= 4294967295:
            return self._values['persist_cidr_ipv6']
        raise F5ModuleError(
            "Valid 'persist_cidr_ipv6' must be in range 0 - 4294967295."
        )


class Changes(Parameters):
    def to_return(self):
        result = {}
        try:
            for returnable in self.returnables:
                change = getattr(self, returnable)
                if isinstance(change, dict):
                    result.update(change)
                else:
                    result[returnable] = change
            result = self._filter_params(result)
        except Exception:
            raise
        return result


class UsableChanges(Changes):
    @property
    def irules(self):
        if self._values['irules'] is None:
            return None
        if self._values['irules'] == '':
            return []
        return self._values['irules']


class ReportableChanges(Changes):
    @property
    def pool_lb_method(self):
        result = dict(
            lb_method=self._values['pool_lb_method'],
            pool_lb_method=self._values['pool_lb_method'],
        )
        return result

    @property
    def last_resort_pool(self):
        if self._values['last_resort_pool'] is None:
            return None
        if self._values['last_resort_pool'] in ['', 'none']:
            return 'none'
        return self._values['last_resort_pool'].split(' ')[1]


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

    def to_tuple(self, items):
        result = []
        for x in items:
            tmp = [(str(k), str(v)) for k, v in iteritems(x)]
            result += tmp
        return result

    def _diff_complex_items(self, want, have):
        if want == [] and have is None:
            return None
        if want is None:
            return None
        w = self.to_tuple(want) if isinstance(want, list) else list()
        h = self.to_tuple(have) if isinstance(have, list) else list()
        if set(w).issubset(set(h)):
            return None
        else:
            return want

    @property
    def last_resort_pool(self):
        if self.want.last_resort_pool is None:
            return None
        if self.want.last_resort_pool == 'none' and self.have.last_resort_pool == '':
            return None
        if self.want.last_resort_pool != self.have.last_resort_pool:
            return self.want.last_resort_pool

    @property
    def state(self):
        if self.want.state == 'disabled' and self.have.enabled:
            return self.want.state
        elif self.want.state in ['present', 'enabled'] and self.have.disabled:
            return self.want.state

    @property
    def pools(self):
        result = self._diff_complex_items(self.want.pools, self.have.pools)
        return result

    @property
    def irules(self):
        if self.want.irules is None:
            return None
        if self.want.irules == '' and self.have.irules is None:
            return None
        if self.want.irules == '' and len(self.have.irules) > 0:
            return []
        if self.have.irules is None:
            return self.want.irules
        if sorted(set(self.want.irules)) != sorted(set(self.have.irules)):
            return self.want.irules

    @property
    def aliases(self):
        if self.want.aliases is None:
            return None
        if self.want.aliases == '' and self.have.aliases is None:
            return None
        if self.want.aliases == '' and len(self.have.aliases) > 0:
            return []
        if self.have.aliases is None:
            return self.want.aliases
        if set(self.want.aliases) != set(self.have.aliases):
            return self.want.aliases


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

    def exec_module(self):
        if not module_provisioned(self.client, 'gtm'):
            raise F5ModuleError(
                "GTM must be provisioned to use this module."
            )
        start = datetime.now().isoformat()
        version = tmos_version(self.client)
        changed = False
        result = dict()
        state = self.want.state

        if state in ["present", "disabled"]:
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
            self.module.deprecate(
                msg=warning['msg'],
                version=warning['version']
            )

    def present(self):
        if self.exists():
            return self.update()
        else:
            return self.create()

    def create(self):
        if self.want.pool_lb_method is None:
            raise F5ModuleError(
                "The 'pool_lb_method' option is required when state is 'present'"
            )
        self._set_changed_options()
        if self.module.check_mode:
            return True
        self.create_on_device()
        return True

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

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def remove(self):
        if self.module.check_mode:
            return True
        self.remove_from_device()
        if self.exists():
            raise F5ModuleError("Failed to delete the Wide IP")
        return True

    def exists(self):
        uri = "https://{0}:{1}/mgmt/tm/gtm/wideip/{2}/{3}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            self.want.type,
            transform_name(self.want.partition, self.want.name)
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
        uri = "https://{0}:{1}/mgmt/tm/gtm/wideip/{2}/{3}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            self.want.type,
            transform_name(self.want.partition, self.want.name)
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
        uri = "https://{0}:{1}/mgmt/tm/gtm/wideip/{2}/{3}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            self.want.type,
            transform_name(self.want.partition, self.want.name)
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return ApiParameters(params=response)
        raise F5ModuleError(resp.content)

    def create_on_device(self):
        params = self.changes.api_params()
        params['name'] = self.want.name
        params['partition'] = self.want.partition
        params['disabled'] = self.want.disabled
        params['enabled'] = self.want.enabled

        uri = "https://{0}:{1}/mgmt/tm/gtm/wideip/{2}/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            self.want.type
        )
        resp = self.client.api.post(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True
        raise F5ModuleError(resp.content)

    def remove_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/gtm/wideip/{2}/{3}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            self.want.type,
            transform_name(self.want.partition, self.want.name)
        )
        response = self.client.api.delete(uri)
        if response.status == 200:
            return True
        raise F5ModuleError(response.content)


class ArgumentSpec(object):
    def __init__(self):
        lb_method_choices = [
            'round-robin', 'topology', 'ratio', 'global-availability',
        ]
        self.supports_check_mode = True
        argument_spec = dict(
            pool_lb_method=dict(
                choices=lb_method_choices,
                aliases=['lb_method']
            ),
            name=dict(
                required=True,
                aliases=['wide_ip']
            ),
            type=dict(
                choices=[
                    'a', 'aaaa', 'cname', 'mx', 'naptr', 'srv'
                ],
                required=True
            ),
            state=dict(
                default='present',
                choices=['absent', 'present', 'enabled', 'disabled']
            ),
            pools=dict(
                type='list',
                elements='dict',
                options=dict(
                    name=dict(required=True),
                    ratio=dict(type='int'),
                    order=dict(type='int')
                )
            ),
            partition=dict(
                default='Common',
                fallback=(env_fallback, ['F5_PARTITION'])
            ),
            irules=dict(
                type='list',
                elements='str',
            ),
            aliases=dict(
                type='list',
                elements='str',
            ),
            last_resort_pool=dict(),
            persistence=dict(type='bool'),
            persistence_ttl=dict(type='int'),
            persist_cidr_ipv4=dict(type='int'),
            persist_cidr_ipv6=dict(type='int'),
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
