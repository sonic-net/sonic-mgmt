#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2016, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_selfip
short_description: Manage Self-IPs on a BIG-IP system
description:
  - Manage Self-IP addresses on a BIG-IP system.
version_added: "1.0.0"
options:
  address:
    description:
      - The IP addresses for the new self IP. This value is ignored upon update
        as addresses themselves cannot be changed after they are created.
      - This value is required when creating new self IPs.
      - IPv4 and IPv6 are supported.
    type: str
  allow_service:
    description:
      - Configure port lockdown for the self IP. By default, the self IP has a
        "default deny" policy. This can be changed to allow TCP and UDP ports,
        as well as specific protocols. This list should contain C(protocol):C(port)
        values.
    type: list
    elements: str
  name:
    description:
      - The name of the self IP to create.
      - If this parameter is not specified, it defaults to the value supplied
        in the C(address) parameter.
    type: str
    required: True
  description:
    description:
      - Description of the traffic selector.
    type: str
  netmask:
    description:
      - The netmask for the self IP. When creating a new self IP, this value
        is required.
    type: str
  state:
    description:
      - When C(present), guarantees the self IP exists with the provided
        attributes.
      - When C(absent), removes the self IP from the system.
    type: str
    choices:
      - absent
      - present
    default: present
  traffic_group:
    description:
      - The traffic group for the self IP addresses in an active-active,
        redundant load balancer configuration. When creating a new self IP, if
        this value is not specified, the default is C(/Common/traffic-group-local-only).
    type: str
  vlan:
    description:
      - The VLAN for the new self IPs. When creating a new self
        IP, this value is required.
    type: str
  route_domain:
    description:
      - The route domain id of the system. When creating a new self IP, if
        this value is not specified, the default value is C(0).
      - This value cannot be changed after it is set.
    type: int
  fw_enforced_policy:
    description:
      - Specifies an AFM policy to attach to Self IP.
    type: str
    version_added: "1.1.0"
  partition:
    description:
      - Device partition to manage resources on. You can set different partitions
        for self IPs, but the address used may not match any other address used
        by a self IP. Thus, self IPs are not isolated by partitions as
        other resources on a BIG-IP are.
    type: str
    default: Common
extends_documentation_fragment: f5networks.f5_modules.f5
author:
  - Tim Rupp (@caphrim007)
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Create Self IP
  bigip_selfip:
    address: 10.10.10.10
    name: self1
    netmask: 255.255.255.0
    vlan: vlan1
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost

- name: Create Self IPv6
  bigip_selfip:
    address: fe80::10
    name: self2
    netmask: "ffff:ffff:ffff:ffff::"
    vlan: vlan1
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
    delegate_to: localhost

- name: Create Self IP with a Route Domain
  bigip_selfip:
    name: self1
    address: 10.10.10.10
    netmask: 255.255.255.0
    vlan: vlan1
    route_domain: 10
    allow_service: default
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost

- name: Delete Self IP
  bigip_selfip:
    name: self1
    state: absent
    provider:
      user: admin
      password: secret
      server: lb.mydomain.com
  delegate_to: localhost

- name: Allow management web UI to be accessed on this Self IP
  bigip_selfip:
    name: self1
    state: absent
    allow_service:
      - tcp:443
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost

- name: Allow HTTPS and SSH access to this Self IP
  bigip_selfip:
    name: self1
    state: absent
    allow_service:
      - tcp:443
      - tcp:22
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost

- name: Allow all services access to this Self IP
  bigip_selfip:
    name: self1
    state: absent
    allow_service:
      - all
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost

- name: Allow only GRE and IGMP protocols access to this Self IP
  bigip_selfip:
    name: self1
    state: absent
    allow_service:
      - gre:0
      - igmp:0
    provider:
      user: admin
      password: secret
      server: lb.mydomain.com
  delegate_to: localhost

- name: Allow all TCP, but no other protocols access to this Self IP
  bigip_selfip:
    name: self1
    state: absent
    allow_service:
      - tcp:0
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost
'''

RETURN = r'''
allow_service:
  description: Services that are allowed via this self IP.
  returned: changed
  type: list
  sample: ['igmp:0','tcp:22','udp:53']
address:
  description: The address for the self IP.
  returned: changed
  type: str
  sample: 192.0.2.10
name:
  description: The name of the self IP.
  returned: created
  type: str
  sample: self1
netmask:
  description: The netmask of the self IP.
  returned: changed
  type: str
  sample: 255.255.255.0
traffic_group:
  description: The traffic group of which the self IP is a member.
  returned: changed
  type: str
  sample: traffic-group-local-only
vlan:
  description: The VLAN set on the self IP.
  returned: changed
  type: str
  sample: vlan1
fw_enforced_policy:
  description: Specifies an AFM policy to be attached to the self IP.
  returned: changed
  type: str
  sample: /Common/afm-blocking-policy
'''

import re
from datetime import datetime

from ansible.module_utils.basic import (
    AnsibleModule, env_fallback
)

from ipaddress import (
    ip_network, ip_interface, ip_address
)

from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, transform_name, f5_argument_spec, fq_name
)
from ..module_utils.compare import cmp_str_with_none
from ..module_utils.ipaddress import (
    is_valid_ip, ipv6_netmask_to_cidr
)
from ..module_utils.icontrol import tmos_version
from ..module_utils.teem import send_teem


class Parameters(AnsibleF5Parameters):
    api_map = {
        'trafficGroup': 'traffic_group',
        'allowService': 'allow_service',
        'fwEnforcedPolicy': 'fw_enforced_policy',
        'fwEnforcedPolicyReference': 'fw_policy_link',
    }

    api_attributes = [
        'trafficGroup',
        'allowService',
        'vlan',
        'address',
        'description',
        'fwEnforcedPolicy',
        'fwEnforcedPolicyReference',
    ]

    updatables = [
        'traffic_group',
        'allow_service',
        'vlan',
        'netmask',
        'address',
        'description',
        'fw_enforced_policy',
        'fw_policy_link',
    ]

    returnables = [
        'traffic_group',
        'allow_service',
        'vlan',
        'route_domain',
        'netmask',
        'address',
        'description',
    ]

    @property
    def vlan(self):
        if self._values['vlan'] is None:
            return None
        return fq_name(self.partition, self._values['vlan'])


class ModuleParameters(Parameters):
    @property
    def address(self):
        address = "{0}%{1}/{2}".format(
            self.ip, self.route_domain, self.netmask
        )
        return address

    @property
    def ip(self):
        if self._values['address'] is None:
            return None
        if is_valid_ip(self._values['address']):
            return self._values['address']
        else:
            raise F5ModuleError(
                'The provided address is not a valid IP address'
            )

    @property
    def traffic_group(self):
        if self._values['traffic_group'] is None:
            return None
        return fq_name(self.partition, self._values['traffic_group'])

    @property
    def route_domain(self):
        if self._values['route_domain'] is None:
            return None
        result = int(self._values['route_domain'])
        return result

    @property
    def netmask(self):
        if self._values['netmask'] is None:
            return None
        result = -1
        try:
            result = int(self._values['netmask'])
            if 0 < result < 256:
                pass
        except ValueError:
            if is_valid_ip(self._values['netmask']):
                addr = ip_address(u'{0}'.format(str(self._values['netmask'])))
                if addr.version == 4:
                    ip = ip_network(u'0.0.0.0/%s' % str(self._values['netmask']))
                    result = ip.prefixlen
                else:
                    result = ipv6_netmask_to_cidr(self._values['netmask'])
        if result < 0:
            raise F5ModuleError(
                'The provided netmask {0} is neither in IP or CIDR format'.format(result)
            )
        return result

    @property
    def allow_service(self):
        """Verifies that a supplied service string has correct format

        The string format for port lockdown is PROTOCOL:PORT. This method
        will verify that the provided input matches the allowed protocols
        and the port ranges before submitting to BIG-IP.

        The only allowed exceptions to this rule are the following values

          * all
          * default
          * none

        These are special cases that are handled differently in the API.
        "all" is set as a string, "default" is set as a one item list, and
        "none" removes the key entirely from the REST API.

        :raises F5ModuleError:
        """
        if self._values['allow_service'] is None:
            return None
        result = []
        allowed_protocols = [
            'eigrp', 'egp', 'gre', 'icmp', 'igmp', 'igp', 'ipip',
            'l2tp', 'ospf', 'pim', 'tcp', 'udp'
        ]
        special_protocols = [
            'all', 'none', 'default'
        ]
        for svc in self._values['allow_service']:
            if svc in special_protocols:
                result = [svc]
                break
            elif svc in allowed_protocols:
                full_service = '{0}:0'.format(svc)
                result.append(full_service)
            else:
                tmp = svc.split(':')
                if tmp[0] not in allowed_protocols:
                    raise F5ModuleError(
                        "The provided protocol '%s' is invalid" % (tmp[0])
                    )
                try:
                    port = int(tmp[1])
                except Exception:
                    raise F5ModuleError(
                        "The provided port '%s' is not a number" % (tmp[1])
                    )

                if port < 0 or port > 65535:
                    raise F5ModuleError(
                        "The provided port '{0}' must be between 0 and 65535".format(port)
                    )
                else:
                    result.append(svc)
        result = sorted(list(set(result)))
        return result

    @property
    def fw_enforced_policy(self):
        if self._values['fw_enforced_policy'] is None:
            return None
        if self._values['fw_enforced_policy'] in ['none', '']:
            return None
        name = self._values['fw_enforced_policy']
        return fq_name(self.partition, name)

    @property
    def fw_policy_link(self):
        policy = self.fw_enforced_policy
        if policy is None:
            return None
        tmp = policy.split('/')
        link = dict(link='https://localhost/mgmt/tm/security/firewall/policy/~{0}~{1}'.format(tmp[1], tmp[2]))
        return link

    @property
    def description(self):
        if self._values['description'] is None:
            return None
        elif self._values['description'] in ['none', '']:
            return ''
        return self._values['description']


class ApiParameters(Parameters):
    @property
    def allow_service(self):
        if self._values['allow_service'] is None:
            return None
        if self._values['allow_service'] == 'all':
            self._values['allow_service'] = ['all']
        return sorted(self._values['allow_service'])

    @property
    def destination_ip(self):
        if self._values['address'] is None:
            return None
        try:
            pattern = r'(?P<rd>%[0-9]+)'
            addr = re.sub(pattern, '', self._values['address'])
            ip = ip_interface(u'{0}'.format(addr))
            return ip.with_prefixlen
        except ValueError:
            raise F5ModuleError(
                "The provided destination is not an IP address"
            )

    @property
    def netmask(self):
        ip = ip_interface(self.destination_ip)
        return int(ip.network.prefixlen)

    @property
    def ip(self):
        result = ip_interface(self.destination_ip)
        return str(result.ip)

    @property
    def description(self):
        if self._values['description'] in [None, 'none']:
            return None
        return self._values['description']


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
    def allow_service(self):
        if self._values['allow_service'] is None:
            return None
        if self._values['allow_service'] == ['all']:
            return 'all'
        return sorted(self._values['allow_service'])


class ReportableChanges(Changes):
    pass


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
    def address(self):
        return None

    @property
    def allow_service(self):
        """Returns services formatted for consumption by f5-sdk update

        The BIG-IP endpoint for services takes different values depending on
        what you want the "allowed services" to be. It can be any of the
        following

            - a list containing "protocol:port" values
            - the string "all"
            - a null value, or None

        This is a convenience function to massage the values the user has
        supplied so that they are formatted in such a way that BIG-IP will
        accept them and apply the specified policy.
        """
        if self.want.allow_service is None:
            return None
        result = self.want.allow_service
        if result[0] == 'none' and self.have.allow_service is None:
            return None
        elif self.have.allow_service is None:
            return result
        elif result[0] == 'all' and self.have.allow_service[0] != 'all':
            return ['all']
        elif result[0] == 'none':
            return []
        elif set(self.want.allow_service) != set(self.have.allow_service):
            return result

    @property
    def netmask(self):
        if self.want.netmask is None:
            return None
        ip = self.have.ip
        if is_valid_ip(ip):
            if self.want.route_domain is not None:
                want = "{0}%{1}/{2}".format(ip, self.want.route_domain, self.want.netmask)
                have = "{0}%{1}/{2}".format(ip, self.want.route_domain, self.have.netmask)
            elif self.have.route_domain is not None:
                want = "{0}%{1}/{2}".format(ip, self.have.route_domain, self.want.netmask)
                have = "{0}%{1}/{2}".format(ip, self.have.route_domain, self.have.netmask)
            else:
                want = "{0}/{1}".format(ip, self.want.netmask)
                have = "{0}/{1}".format(ip, self.have.netmask)
            if want != have:
                return want
        else:
            raise F5ModuleError(
                'The provided address/netmask value "{0}" was invalid'.format(self.have.ip)
            )

    @property
    def traffic_group(self):
        if self.want.traffic_group != self.have.traffic_group:
            return self.want.traffic_group

    @property
    def description(self):
        return cmp_str_with_none(self.want.description, self.have.description)

    @property
    def fw_policy_link(self):
        if self.want.fw_enforced_policy is None:
            return None
        if self.want.fw_enforced_policy == self.have.fw_enforced_policy:
            return None
        if self.want.fw_policy_link != self.have.fw_policy_link:
            return self.want.fw_policy_link


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.client = F5RestClient(**self.module.params)
        self.have = None
        self.want = ModuleParameters(params=self.module.params)
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
        updatables = ApiParameters.updatables
        changed = dict()
        for k in updatables:
            change = diff.compare(k)
            if change is None:
                continue
            else:
                if k in ['netmask']:
                    changed['address'] = change
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

    def present(self):
        if self.exists():
            changed = self.update()
        else:
            changed = self.create()
        return changed

    def absent(self):
        changed = False
        if self.exists():
            changed = self.remove()
        return changed

    def remove(self):
        if self.module.check_mode:
            return True
        self.remove_from_device()
        if self.exists():
            raise F5ModuleError("Failed to delete the Self IP")
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

    def create(self):
        if self.want.address is None or self.want.netmask is None:
            raise F5ModuleError(
                'An address and a netmask must be specified'
            )
        if self.want.vlan is None:
            raise F5ModuleError(
                'A VLAN name must be specified'
            )
        if self.want.route_domain is None:
            rd = self.read_partition_default_route_domain_from_device()
            self.want.update({'route_domain': rd})

        if self.want.traffic_group is None:
            self.want.update({'traffic_group': '/Common/traffic-group-local-only'})
        if self.want.route_domain is None:
            self.want.update({'route_domain': 0})
        if self.want.allow_service:
            if 'all' in self.want.allow_service:
                self.want.update(dict(allow_service=['all']))
            elif 'none' in self.want.allow_service:
                self.want.update(dict(allow_service=[]))
            elif 'default' in self.want.allow_service:
                self.want.update(dict(allow_service=['default']))
        self._set_changed_options()
        if self.module.check_mode:
            return True
        self.create_on_device()
        if self.exists():
            return True
        else:
            raise F5ModuleError("Failed to create the Self IP")

    def exists(self):
        uri = "https://{0}:{1}/mgmt/tm/net/self/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
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

    def create_on_device(self):
        params = self.changes.api_params()
        params['name'] = self.want.name
        params['partition'] = self.want.partition
        uri = "https://{0}:{1}/mgmt/tm/net/self/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.post(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if 'code' in response and response['code'] in [400, 403]:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)

        if self.want.fw_enforced_policy:
            payload = dict(
                fwEnforcedPolicy=self.want.fw_enforced_policy,
                fwEnforcedPolicyReference=self.want.fw_policy_link
            )
            uri = "https://{0}:{1}/mgmt/tm/net/self/{2}".format(
                self.client.provider['server'],
                self.client.provider['server_port'],
                transform_name(self.want.partition, self.want.name),
            )
            resp = self.client.api.patch(uri, json=payload)

            try:
                response = resp.json()
            except ValueError as ex:
                raise F5ModuleError(str(ex))

            if 'code' in response and response['code'] in [400, 403]:
                if 'message' in response:
                    raise F5ModuleError(response['message'])
                else:
                    raise F5ModuleError(resp.content)
        return True

    def update_on_device(self):
        params = self.changes.api_params()
        uri = "https://{0}:{1}/mgmt/tm/net/self/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
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
        uri = "https://{0}:{1}/mgmt/tm/net/self/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        resp = self.client.api.delete(uri)
        if resp.status == 200:
            return True

    def read_current_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/net/self/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
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

    def read_partition_default_route_domain_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/auth/partition/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            self.want.partition
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
        return int(response['defaultRouteDomain'])


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            address=dict(),
            allow_service=dict(
                elements='str',
                type='list',
            ),
            name=dict(required=True),
            netmask=dict(),
            traffic_group=dict(),
            vlan=dict(),
            route_domain=dict(type='int'),
            description=dict(),
            fw_enforced_policy=dict(),
            state=dict(
                default='present',
                choices=['present', 'absent']
            ),
            partition=dict(
                default='Common',
                fallback=(env_fallback, ['F5_PARTITION'])
            )
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
