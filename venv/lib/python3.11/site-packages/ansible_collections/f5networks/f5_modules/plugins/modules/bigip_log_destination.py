#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2017, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_log_destination
short_description: Manages log destinations on a BIG-IP.
description:
  - Manages log destinations on a BIG-IP device.
version_added: "1.0.0"
options:
  name:
    description:
      - Specifies the name of the log destination.
    type: str
    required: True
  type:
    description:
      - Specifies the type of log destination.
      - Once created, this parameter cannot be changed.
    type: str
    choices:
      - remote-high-speed-log
      - remote-syslog
      - arcsight
      - splunk
      - management-port
      - ipfix
    required: True
  description:
    description:
      - The description of the log destination.
    type: str
  syslog_format:
    description:
      - Specifies the method to use to format the logs associated with the remote Syslog log destination.
      - When creating a new log destination (and C(type) is C(remote-syslog)), if this parameter is
        not specified, the default is C(bsd-syslog).
      - The C(syslog) and C(rfc5424) choices are the same.
      - The C(bsd-syslog) and C(rfc3164) choices are the same.
    type: str
    choices:
      - bsd-syslog
      - syslog
      - legacy-bigip
      - rfc5424
      - rfc3164
  forward_to:
    description:
      - When C(type) is C(remote-syslog), specifies the management port log destination, which will
        be used to forward the logs to a single log server, or a remote high-speed log destination,
        which will be used to forward the logs to a pool of remote log servers.
      - When C(type) is C(splunk) or C(arcsight), specifies the log destination to which logs are
        forwarded. This log destination may be a management port destination, a remote high-speed
        log destination, or a remote Syslog destination which is configured to send logs to an
        ArcSight or Splunk server.
      - When creating a new log destination and C(type) is C(remote-syslog), C(splunk), or C(arcsight),
        this parameter is required.
    type: str
  pool:
    description:
      - When C(type) is C(remote-high-speed-log), specifies the existing pool of remote high-speed
        log servers where logs will be sent.
      - When C(type) is C(ipfix), specifies the existing LTM pool of remote IPFIX collectors. Any
        BIG-IP application that uses this log destination sends its IP-traffic logs to this pool
        of collectors.
      - When creating a new destination and C(type) is C(remote-high-speed-log) or C(ipfix), this
        parameter is required.
    type: str
  protocol:
    description:
      - When C(type) is C(remote-high-speed-log), specifies the protocol for the system to use to
        send logs to the pool of remote high-speed log servers, where the logs are stored.
      - When C(type) is C(ipfix), can be IPFIX or Netflow v9, depending on the type of collectors
        you have in the pool that you specify.
      - When C(type) is C(management-port), specifies the protocol used to send messages to the
        specified location.
      - When C(type) is C(management-port), only C(tcp) and C(udp) are valid values.
    type: str
    choices:
      - tcp
      - udp
      - ipfix
      - netflow-9
  distribution:
    description:
      - Specifies the distribution method used by the Remote High Speed Log destination to send
        messages to pool members.
      - When C(adaptive), connections to pool members will be added as required to provide enough
        logging bandwidth. This can have the undesirable effect of logs accumulating on only one
        pool member when it provides sufficient logging bandwidth on its own.
      - When C(balanced), sends each successive log to a new pool member, balancing the logs among
        them according to the pool's load balancing method.
      - When C(replicated), replicates each log to all pool members, for redundancy.
      - When creating a new log destination and C(type) is C(remote-high-speed-log), if this
        parameter is not specified, the default is C(adaptive).
    type: str
    choices:
      - adaptive
      - balanced
      - replicated
  address:
    description:
      - Specifies the IP address that will receive messages from the specified local Log Destination.
      - This parameter is only available when C(type) is C(management-port).
      - When creating a new log destination and C(type) is C(management-port), this parameter
        is required.
    type: str
  port:
    description:
      - Specifies the port of the IP address that will receive messages from the specified local
        Log Destination.
      - This parameter is only available when C(type) is C(management-port).
      - When creating a new log destination and C(type) is C(management-port), this parameter
        is required.
    type: int
  transport_profile:
    description:
      - Is a transport profile based on either TCP or UDP.
      - This profile defines the TCP or UDP options used to send IP-traffic logs
        to the pool of collectors.
      - This parameter is only available when C(type) is C(ipfix).
    type: str
  server_ssl_profile:
    description:
      - If the C(transport_profile) is a TCP profile, you can use this field to
        choose a Secure Socket Layer (SSL) profile for sending logs to the IPFIX
        collectors.
      - An SSL server profile defines how to communicate securely over SSL or
        Transport Layer Security (TLS).
      - This parameter is only available when C(type) is C(ipfix).
    type: str
  template_retransmit_interval:
    description:
      - Enter the time (in seconds) between each transmission of IPFIX templates
        to the pool of IPFIX collectors.
      - The logging destination periodically retransmits all of its IPFIX templates
        at the interval you set in this field. These retransmissions are helpful
        for UDP, a lossy transport mechanism.
      - This parameter is only available when C(type) is C(ipfix).
    type: int
  template_delete_delay:
    description:
      - Enter the time (in seconds) that the BIG-IP device should pause between
        deleting an obsolete IPFIX template and reusing its template ID.
      - This feature is useful for systems where you use iRules to create
        customized IPFIX templates.
    type: int
  partition:
    description:
      - Device partition to manage resources on.
    type: str
    default: Common
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
'''

EXAMPLES = r'''
- name: Create a high-speed logging destination
  bigip_log_destination:
    name: foo
    type: remote-high-speed-log
    pool: my-ltm-pool
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost

- name: Create a remote-syslog logging destination
  bigip_log_destination:
    name: foo
    type: remote-syslog
    syslog_format: rfc5424
    forward_to: my-destination
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost
'''

RETURN = r'''
forward_to:
  description: The new Forward To value.
  returned: changed
  type: str
  sample: /Common/dest1
pool:
  description: The new Pool value.
  returned: changed
  type: str
  sample: /Common/pool1
distribution:
  description: The new Distribution Method value.
  returned: changed
  type: str
  sample: balanced
protocol:
  description: The new Protocol value.
  returned: changed
  type: str
  sample: tcp
syslog_format:
  description: The new Syslog format value.
  returned: changed
  type: str
  sample: syslog
address:
  description: The new Address value.
  returned: changed
  type: str
  sample: 1.2.3.2
port:
  description: The new Port value.
  returned: changed
  type: int
  sample: 2020
template_delete_delay:
  description: The new Template Delete Delay value.
  returned: changed
  type: int
  sample: 20
template_retransmit_interval:
  description: The new Template Retransmit Interval value.
  returned: changed
  type: int
  sample: 200
transport_profile:
  description: The new Transport Profile value.
  returned: changed
  type: str
  sample: /Common/tcp
server_ssl_profile:
  description: The new Server SSL Profile value.
  returned: changed
  type: str
  sample: /Common/serverssl
'''
from datetime import datetime
from ansible.module_utils.basic import (
    AnsibleModule, env_fallback
)

from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, transform_name, f5_argument_spec, fq_name
)
from ..module_utils.compare import cmp_str_with_none
from ..module_utils.icontrol import tmos_version
from ..module_utils.teem import send_teem


class Parameters(AnsibleF5Parameters):
    api_map = {
        'forwardTo': 'forward_to',
        'poolName': 'pool',
        'remoteHighSpeedLog': 'forward_to',
        'format': 'syslog_format',
        'ipAddress': 'address',
        'protocolVersion': 'protocol',
        'templateDeleteDelay': 'template_delete_delay',
        'templateRetransmitInterval': 'template_retransmit_interval',
        'transportProfile': 'transport_profile',
        'serversslProfile': 'server_ssl_profile',
    }

    api_attributes = [
        'forwardTo',
        'distribution',
        'poolName',
        'protocol',
        'remoteHighSpeedLog',
        'format',
        'ipAddress',
        'port',
        'serversslProfile',
        'transportProfile',
        'templateRetransmitInterval',
        'templateDeleteDelay',
        'protocolVersion',
    ]

    returnables = [
        'forward_to',
        'pool',
        'distribution',
        'protocol',
        'syslog_format',
        'address',
        'port',
        'template_delete_delay',
        'template_retransmit_interval',
        'transport_profile',
        'server_ssl_profile',
    ]

    updatables = [
        'forward_to',
        'type',
        'pool',
        'distribution',
        'protocol',
        'syslog_format',
        'address',
        'port',
        'template_delete_delay',
        'template_retransmit_interval',
        'transport_profile',
        'server_ssl_profile',
        'type',
    ]


class ModuleParameters(Parameters):
    @property
    def forward_to(self):
        if self._values['forward_to'] is None:
            return None
        return fq_name(self.partition, self._values['forward_to'])

    @property
    def pool(self):
        if self._values['pool'] is None:
            return None
        return fq_name(self.partition, self._values['pool'])

    @property
    def syslog_format(self):
        if self._values['syslog_format'] is None:
            return None
        result = self._values['syslog_format']
        if result == 'syslog':
            result = 'rfc5424'
        if result == 'bsd-syslog':
            result = 'rfc3164'
        return result

    @property
    def server_ssl_profile(self):
        if self._values['server_ssl_profile'] is None:
            return None
        elif self._values['server_ssl_profile'] in ['', 'none']:
            return ''
        return fq_name(self.partition, self._values['server_ssl_profile'])

    @property
    def transport_profile(self):
        if self._values['transport_profile'] is None:
            return None
        return fq_name(self.partition, self._values['transport_profile'])


class ApiParameters(Parameters):
    pass


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
    pass


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
    def type(self):
        if self.want.type != self.have.type:
            raise F5ModuleError(
                "'type' cannot be changed once it is set."
            )

    @property
    def server_ssl_profile(self):
        return cmp_str_with_none(self.want.server_ssl_profile, self.have.server_ssl_profile)

    @property
    def transport_profile(self):
        return cmp_str_with_none(self.want.transport_profile, self.have.transport_profile)


class BaseManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.client = F5RestClient(**self.module.params)
        self.want = ModuleParameters(params=self.module.params)
        self.have = None
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

    def _validate_creation_parameters(self):
        pass

    def present(self):
        if self.exists():
            return self.update()
        else:
            return self.create()

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
        self._validate_creation_parameters()
        self._set_changed_options()
        if self.module.check_mode:
            return True
        self.create_on_device()
        return True

    def absent(self):
        if self.exists():
            return self.remove()
        return False


class V1Manager(BaseManager):
    """Manages remote-syslog settings

    """

    def _validate_creation_parameters(self):
        if self.want.syslog_format is None:
            self.want.update({'syslog_format': 'bsd-syslog'})
        if self.want.forward_to is None:
            raise F5ModuleError(
                "'forward_to' is required when creating a new remote-syslog destination."
            )

    def exists(self):
        uri = "https://{0}:{1}/mgmt/tm/sys/log-config/destination/remote-syslog/{2}".format(
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
        uri = "https://{0}:{1}/mgmt/tm/sys/log-config/destination/remote-syslog/".format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )
        resp = self.client.api.post(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True
        raise F5ModuleError(resp.content)

    def update_on_device(self):
        params = self.changes.api_params()
        uri = "https://{0}:{1}/mgmt/tm/sys/log-config/destination/remote-syslog/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
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

    def remove_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/sys/log-config/destination/remote-syslog/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        response = self.client.api.delete(uri)

        if response.status in [200, 201]:
            return True
        raise F5ModuleError(response.content)

    def read_current_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/sys/log-config/destination/remote-syslog/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            response['type'] = 'remote-syslog'
            return ApiParameters(params=response)
        raise F5ModuleError(resp.content)


class V2Manager(BaseManager):
    """Manages remote-high-speed-log settings

    """
    def _validate_creation_parameters(self):
        if self.want.protocol is None:
            self.want.update({'protocol': 'tcp'})
        if self.want.distribution is None:
            self.want.update({'distribution': 'adaptive'})
        if self.want.pool is None:
            raise F5ModuleError(
                "'pool' is required when creating a new remote-high-speed-log destination."
            )

    def exists(self):
        uri = "https://{0}:{1}/mgmt/tm/sys/log-config/destination/remote-high-speed-log/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError:
            return False
        if resp.status == 404 or 'code' in response and response['code'] == 404:
            return False
        return True

    def create_on_device(self):
        params = self.changes.api_params()
        params['name'] = self.want.name
        params['partition'] = self.want.partition
        uri = "https://{0}:{1}/mgmt/tm/sys/log-config/destination/remote-high-speed-log/".format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )
        resp = self.client.api.post(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True
        raise F5ModuleError(resp.content)

    def update_on_device(self):
        params = self.changes.api_params()
        uri = "https://{0}:{1}/mgmt/tm/sys/log-config/destination/remote-high-speed-log/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
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

    def remove_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/sys/log-config/destination/remote-high-speed-log/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        response = self.client.api.delete(uri)

        if response.status in [200, 201]:
            return True
        raise F5ModuleError(response.content)

    def read_current_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/sys/log-config/destination/remote-high-speed-log/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            response['type'] = 'remote-high-speed-log'
            return ApiParameters(params=response)
        raise F5ModuleError(resp.content)


class V3Manager(BaseManager):
    def _validate_creation_parameters(self):
        if self.want.forward_to is None:
            raise F5ModuleError(
                "'forward_to' is required when creating a new arcsight destination."
            )

    def exists(self):
        errors = [401, 403, 409, 500, 501, 502, 503, 504]
        uri = "https://{0}:{1}/mgmt/tm/sys/log-config/destination/arcsight/{2}".format(
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

        if resp.status in errors or 'code' in response and response['code'] in errors:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)

    def create_on_device(self):
        params = self.changes.api_params()
        params['name'] = self.want.name
        params['partition'] = self.want.partition
        uri = "https://{0}:{1}/mgmt/tm/sys/log-config/destination/arcsight/".format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )
        resp = self.client.api.post(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True
        raise F5ModuleError(resp.content)

    def update_on_device(self):
        params = self.changes.api_params()
        uri = "https://{0}:{1}/mgmt/tm/sys/log-config/destination/arcsight/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
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

    def remove_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/sys/log-config/destination/arcsight/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        response = self.client.api.delete(uri)

        if response.status in [200, 201]:
            return True
        raise F5ModuleError(response.content)

    def read_current_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/sys/log-config/destination/arcsight/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            response['type'] = 'arcsight'
            return ApiParameters(params=response)
        raise F5ModuleError(resp.content)


class V4Manager(BaseManager):
    """Manager for Splunk
    """

    def _validate_creation_parameters(self):
        if self.want.forward_to is None:
            raise F5ModuleError(
                "'forward_to' is required when creating a new splunk destination."
            )

    def exists(self):
        errors = [401, 403, 409, 500, 501, 502, 503, 504]
        uri = "https://{0}:{1}/mgmt/tm/sys/log-config/destination/splunk/{2}".format(
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

        if resp.status in errors or 'code' in response and response['code'] in errors:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)

    def create_on_device(self):
        params = self.changes.api_params()
        params['name'] = self.want.name
        params['partition'] = self.want.partition
        uri = "https://{0}:{1}/mgmt/tm/sys/log-config/destination/splunk/".format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )
        resp = self.client.api.post(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True
        raise F5ModuleError(resp.content)

    def update_on_device(self):
        params = self.changes.api_params()
        uri = "https://{0}:{1}/mgmt/tm/sys/log-config/destination/splunk/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
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

    def remove_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/sys/log-config/destination/splunk/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        response = self.client.api.delete(uri)

        if response.status in [200, 201]:
            return True
        raise F5ModuleError(response.content)

    def read_current_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/sys/log-config/destination/splunk/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            response['type'] = 'splunk'
            return ApiParameters(params=response)
        raise F5ModuleError(resp.content)


class V5Manager(BaseManager):
    """Manager for Management Port
    """
    def _validate_creation_parameters(self):
        if self.want.address is None:
            raise F5ModuleError(
                "'address' is required when creating a new management-port destination."
            )
        if self.want.port is None:
            raise F5ModuleError(
                "'port' is required when creating a new management-port destination."
            )

    def exists(self):
        errors = [401, 403, 409, 500, 501, 502, 503, 504]
        uri = "https://{0}:{1}/mgmt/tm/sys/log-config/destination/management-port/{2}".format(
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

        if resp.status in errors or 'code' in response and response['code'] in errors:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)

    def create_on_device(self):
        params = self.changes.api_params()
        params['name'] = self.want.name
        params['partition'] = self.want.partition
        uri = "https://{0}:{1}/mgmt/tm/sys/log-config/destination/management-port/".format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )
        resp = self.client.api.post(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True
        raise F5ModuleError(resp.content)

    def update_on_device(self):
        params = self.changes.api_params()
        uri = "https://{0}:{1}/mgmt/tm/sys/log-config/destination/management-port/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
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

    def remove_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/sys/log-config/destination/management-port/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        response = self.client.api.delete(uri)

        if response.status in [200, 201]:
            return True
        raise F5ModuleError(response.content)

    def read_current_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/sys/log-config/destination/management-port/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            response['type'] = 'management-port'
            return ApiParameters(params=response)
        raise F5ModuleError(resp.content)


class V6Manager(BaseManager):
    """Manager for IPFIX
    """
    def _validate_creation_parameters(self):
        if self.want.protocol is None:
            raise F5ModuleError(
                "'protocol' is required when creating a new ipfix destination."
            )
        if self.want.pool is None:
            raise F5ModuleError(
                "'port' is required when creating a new ipfix destination."
            )
        if self.want.transport_profile is None:
            raise F5ModuleError(
                "'transport_profile' is required when creating a new ipfix destination."
            )

    def exists(self):
        errors = [401, 403, 409, 500, 501, 502, 503, 504]
        uri = "https://{0}:{1}/mgmt/tm/sys/log-config/destination/ipfix/{2}".format(
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

        if resp.status in errors or 'code' in response and response['code'] in errors:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)

    def create_on_device(self):
        params = self.changes.api_params()
        params['name'] = self.want.name
        params['partition'] = self.want.partition
        uri = "https://{0}:{1}/mgmt/tm/sys/log-config/destination/ipfix/".format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )
        resp = self.client.api.post(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True
        raise F5ModuleError(resp.content)

    def update_on_device(self):
        params = self.changes.api_params()
        uri = "https://{0}:{1}/mgmt/tm/sys/log-config/destination/ipfix/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
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

    def remove_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/sys/log-config/destination/ipfix/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        response = self.client.api.delete(uri)

        if response.status in [200, 201]:
            return True
        raise F5ModuleError(response.content)

    def read_current_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/sys/log-config/destination/ipfix/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            response['type'] = 'ipfix'
            return ApiParameters(params=response)
        raise F5ModuleError(resp.content)


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.kwargs = kwargs
        self.module = kwargs.get('module', None)

    def exec_module(self):
        if self.module.params['type'] == 'remote-syslog':
            manager = self.get_manager('v1')
        elif self.module.params['type'] == 'remote-high-speed-log':
            manager = self.get_manager('v2')
        elif self.module.params['type'] == 'arcsight':
            manager = self.get_manager('v3')
        elif self.module.params['type'] == 'splunk':
            manager = self.get_manager('v4')
        elif self.module.params['type'] == 'management-port':
            manager = self.get_manager('v5')
        elif self.module.params['type'] == 'ipfix':
            manager = self.get_manager('v6')
        else:
            raise F5ModuleError(
                "Unknown type specified."
            )
        result = manager.exec_module()
        return result

    def get_manager(self, type):
        if type == 'v1':
            return V1Manager(**self.kwargs)
        elif type == 'v2':
            return V2Manager(**self.kwargs)
        elif type == 'v3':
            return V3Manager(**self.kwargs)
        elif type == 'v4':
            return V4Manager(**self.kwargs)
        elif type == 'v5':
            return V5Manager(**self.kwargs)
        elif type == 'v6':
            return V6Manager(**self.kwargs)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(required=True),
            type=dict(
                required=True,
                choices=[
                    'arcsight',
                    'remote-high-speed-log',
                    'remote-syslog',
                    'splunk',
                    'management-port',
                    'ipfix',
                ]
            ),
            description=dict(),
            syslog_format=dict(
                choices=[
                    'bsd-syslog',
                    'syslog',
                    'legacy-bigip',
                    'rfc5424',
                    'rfc3164'
                ]
            ),
            forward_to=dict(),
            pool=dict(),
            protocol=dict(
                choices=['tcp', 'udp', 'ipfix', 'netflow-9']
            ),
            distribution=dict(
                choices=[
                    'adaptive',
                    'balanced',
                    'replicated',
                ]
            ),
            state=dict(
                default='present',
                choices=['present', 'absent']
            ),
            partition=dict(
                default='Common',
                fallback=(env_fallback, ['F5_PARTITION'])
            ),
            address=dict(),
            port=dict(type='int'),
            transport_profile=dict(),
            server_ssl_profile=dict(),
            template_retransmit_interval=dict(type='int'),
            template_delete_delay=dict(type='int'),
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
