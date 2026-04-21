#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2017, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_iapp_service
short_description: Manages TCL iApp services on a BIG-IP
description:
  - Manages TCL iApp services on a BIG-IP.
  - The API the system uses to communicate with on the BIG-IP is C(/mgmt/tm/sys/application/service/).
version_added: "1.0.0"
options:
  name:
    description:
      - The name of the iApp service you want to deploy.
    type: str
    required: True
  template:
    description:
      - The iApp template from which to instantiate a new service. This
        template must exist on your BIG-IP before you can successfully
        create a service.
      - When creating a new service, this parameter is required.
    type: str
  parameters:
    description:
      - A hash of all the required template variables for the iApp template.
        If your parameters are stored in a file (the more common scenario)
        we recommend you use either the C(file) or C(template) lookups
        to supply the expected parameters.
      - These parameters typically consist of the C(lists), C(tables), and
        C(variables) fields.
    type: dict
  force:
    description:
      - Forces the updating of an iApp service, even if the parameters to the
        service have not changed. This option is of particular importance if
        the iApp template that underlies the service has been updated in-place.
        This option is equivalent to re-configuring the iApp if that template
        has changed.
    type: bool
    default: false
  state:
    description:
      - When C(present), ensures the iApp service is created and running.
        When C(absent), ensures the iApp service has been removed.
    type: str
    choices:
      - present
      - absent
    default: present
  partition:
    description:
      - Device partition to manage resources on.
    type: str
    default: Common
  strict_updates:
    description:
      - Indicates whether the application service is tied to the template,
        so when the template is updated, the application service changes to
        reflect the updates.
      - When C(true), disallows any updates to the resources that the iApp
        service has created, if they are not updated directly through the
        iApp.
      - When C(false), allows updates outside of the iApp.
      - If this option is specified in the Ansible task, it takes precedence
        over any similar setting in the iApp Service payload that you provide in
        the C(parameters) field.
    type: bool
  traffic_group:
    description:
      - The traffic group for the iApp service. When creating a new service, if
        this value is not specified, the default of C(/Common/traffic-group-1)
        is used.
      - If this option is specified in the Ansible task, it takes precedence
        over any similar setting in the iApp Service payload that you provide in
        the C(parameters) field.
    type: str
  metadata:
    description:
      - Metadata associated with the iApp service.
      - If this option is specified in the Ansible task, it takes precedence
        over any similar setting in the iApp Service payload that you provide in
        the C(parameters) field.
    type: list
    elements: raw
  description:
    description:
      - Description of the iApp service.
      - If this option is specified in the Ansible task, it takes precedence
        over any similar setting in the iApp Service payload that you provide in
        the C(parameters) field.
    type: str
  device_group:
    description:
      - The device group for the iApp service.
      - If this option is specified in the Ansible task, it takes precedence
        over any similar setting in the iApp Service payload that you provide in
        the C(parameters) field.
    type: str
extends_documentation_fragment: f5networks.f5_modules.f5
author:
  - Tim Rupp (@caphrim007)
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Create HTTP iApp service from iApp template
  bigip_iapp_service:
    name: foo-service
    template: f5.http
    parameters: "{{ lookup('file', 'f5.http.parameters.json') }}"
    state: present
    provider:
      user: admin
      password: secret
      server: lb.mydomain.com
  delegate_to: localhost

- name: Upgrade foo-service to v1.2.0rc4 of the f5.http template
  bigip_iapp_service:
    name: foo-service
    template: f5.http.v1.2.0rc4
    state: present
    provider:
      user: admin
      password: secret
      server: lb.mydomain.com
  delegate_to: localhost

- name: Configure a service using parameters in YAML
  bigip_iapp_service:
    name: tests
    template: web_frontends
    state: present
    parameters:
      variables:
        - name: var__vs_address
          value: 1.1.1.1
        - name: pm__apache_servers_for_http
          value: 2.2.2.1:80
        - name: pm__apache_servers_for_https
          value: 2.2.2.2:80
    provider:
      user: admin
      password: secret
      server: lb.mydomain.com
  delegate_to: localhost

- name: Re-configure a service whose underlying iApp was updated in place
  bigip_iapp_service:
    name: tests
    template: web_frontends
    force: true
    state: present
    parameters:
      variables:
        - name: var__vs_address
          value: 1.1.1.1
        - name: pm__apache_servers_for_http
          value: 2.2.2.1:80
        - name: pm__apache_servers_for_https
          value: 2.2.2.2:80
    provider:
      user: admin
      password: secret
      server: lb.mydomain.com
  delegate_to: localhost

- name: Try to remove the iApp template before the associated Service is removed
  bigip_iapp_template:
    name: web_frontends
    state: absent
    provider:
      user: admin
      password: secret
      server: lb.mydomain.com
  register: result
  failed_when:
    - result is not success
    - "'referenced by one or more applications' not in result.msg"

- name: Configure a service using more complicated parameters
  bigip_iapp_service:
    name: tests
    template: web_frontends
    state: present
    provider:
      user: admin
      password: secret
      server: lb.mydomain.com
    parameters:
      variables:
        - name: var__vs_address
          value: 1.1.1.1
        - name: pm__apache_servers_for_http
          value: 2.2.2.1:80
        - name: pm__apache_servers_for_https
          value: 2.2.2.2:80
      lists:
        - name: irules__irules
          value:
            - foo
            - bar
      tables:
        - name: basic__snatpool_members
        - name: net__snatpool_members
        - name: optimizations__hosts
        - name: pool__hosts
          columnNames:
            - name
          rows:
            - row:
                - internal.company.bar
        - name: pool__members
          columnNames:
            - addr
            - port
            - connection_limit
          rows:
            - row:
                - "none"
                - 80
                - 0
        - name: server_pools__servers
  delegate_to: localhost

- name: Override metadata that may or may not exist in parameters
  bigip_iapp_service:
    name: foo-service
    template: f5.http
    parameters: "{{ lookup('file', 'f5.http.parameters.json') }}"
    metadata:
      - persist: true
        name: data 1
      - persist: true
        name: data 2
    state: present
    provider:
      user: admin
      password: secret
      server: lb.mydomain.com
  delegate_to: localhost
'''

RETURN = r'''
# only common fields returned
'''
from datetime import datetime

from ansible.module_utils.basic import (
    AnsibleModule, env_fallback
)
from ansible.module_utils.six import iteritems

from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, transform_name, f5_argument_spec, flatten_boolean, fq_name
)
from ..module_utils.icontrol import tmos_version
from ..module_utils.urls import build_service_uri
from ..module_utils.teem import send_teem


class Parameters(AnsibleF5Parameters):
    api_map = {
        'strictUpdates': 'strict_updates',
        'trafficGroup': 'traffic_group',
        'deviceGroup': 'device_group',
    }

    returnables = [
        'tables',
        'variables',
        'lists',
        'strict_updates',
        'traffic_group',
        'device_group',
        'metadata',
        'template',
        'description',
    ]

    api_attributes = [
        'tables',
        'variables',
        'template',
        'lists',
        'deviceGroup',
        'inheritedDevicegroup',
        'inheritedTrafficGroup',
        'trafficGroup',
        'strictUpdates',
        # 'metadata',
        'description',
    ]

    updatables = [
        'tables',
        'variables',
        'lists',
        'strict_updates',
        'device_group',
        'traffic_group',
        'metadata',
        'description',
    ]

    def to_return(self):
        result = {}
        try:
            for returnable in self.returnables:
                result[returnable] = getattr(self, returnable)
            result = self._filter_params(result)
        except Exception:
            raise
        return result

    def normalize_tables(self, tables):
        result = []
        for table in tables:
            tmp = dict()
            name = table.get('name', None)
            if name is None:
                raise F5ModuleError(
                    "One of the provided tables does not have a name"
                )
            tmp['name'] = str(name)
            columns = table.get('columnNames', None)
            if columns:
                tmp['columnNames'] = [str(x) for x in columns]
                # You cannot have rows without columns
                rows = table.get('rows', None)
                if rows:
                    tmp['rows'] = []
                    for row in rows:
                        tmp['rows'].append(dict(row=[str(x) for x in row['row']]))
            result.append(tmp)
        result = sorted(result, key=lambda k: k['name'])
        return result

    def normalize_variables(self, variables):
        result = []
        for variable in variables:
            tmp = dict((str(k), str(v)) for k, v in iteritems(variable))
            if 'encrypted' not in tmp:
                # BIG-IP will inject an 'encrypted' key if you don't provide one.
                # If you don't provide one, then we give you the default 'no', by
                # default.
                tmp['encrypted'] = 'no'
            if 'value' not in tmp:
                tmp['value'] = ''

            # This seems to happen only on 12.0.0
            elif tmp['value'] == 'none':
                tmp['value'] = ''
            elif tmp['value'] == 'True':
                tmp['value'] = 'yes'
            elif tmp['value'] == 'False':
                tmp['value'] = 'no'
            elif isinstance(tmp['value'], bool):
                if tmp['value'] is True:
                    tmp['value'] = 'yes'
                else:
                    tmp['value'] = 'no'

            if tmp['encrypted'] == 'True':
                tmp['encrypted'] = 'yes'
            elif tmp['encrypted'] == 'False':
                tmp['encrypted'] = 'no'
            elif isinstance(tmp['encrypted'], bool):
                if tmp['encrypted'] is True:
                    tmp['encrypted'] = 'yes'
                else:
                    tmp['encrypted'] = 'no'

            result.append(tmp)
        result = sorted(result, key=lambda k: k['name'])
        return result

    def normalize_list(self, lists):
        result = []
        for list in lists:
            tmp = dict((str(k), str(v)) for k, v in iteritems(list) if k != 'value')
            if 'encrypted' not in list:
                # BIG-IP will inject an 'encrypted' key if you don't provide one.
                # If you don't provide one, then we give you the default 'no', by
                # default.
                tmp['encrypted'] = 'no'
            if 'value' in list:
                if len(list['value']) > 0:
                    # BIG-IP removes empty values entries, so mimic this behavior
                    # for user-supplied values.
                    tmp['value'] = [str(x) for x in list['value']]

            if tmp['encrypted'] == 'True':
                tmp['encrypted'] = 'yes'
            elif tmp['encrypted'] == 'False':
                tmp['encrypted'] = 'no'
            elif isinstance(tmp['encrypted'], bool):
                if tmp['encrypted'] is True:
                    tmp['encrypted'] = 'yes'
                else:
                    tmp['encrypted'] = 'no'

            result.append(tmp)
        result = sorted(result, key=lambda k: k['name'])
        return result

    def normalize_metadata(self, metadata):
        result = []
        for item in metadata:
            name = item.get('name', None)
            persist = flatten_boolean(item.get('persist', "no"))
            if persist == "yes":
                persist = "true"
            else:
                persist = "false"
            result.append({
                "name": name,
                "persist": persist
            })
        return result


class ApiParameters(Parameters):
    @property
    def metadata(self):
        if self._values['metadata'] is None:
            return None
        return self._values['metadata']

    @property
    def tables(self):
        if self._values['tables'] is None:
            return None
        return self.normalize_tables(self._values['tables'])

    @property
    def lists(self):
        if self._values['lists'] is None:
            return None
        return self.normalize_list(self._values['lists'])

    @property
    def variables(self):
        if self._values['variables'] is None:
            return None
        return self.normalize_variables(self._values['variables'])

    @property
    def device_group(self):
        if self._values['device_group'] in [None, 'none']:
            return None
        return self._values['device_group']


class ModuleParameters(Parameters):
    @property
    def param_lists(self):
        if self._values['parameters'] is None:
            return None
        result = self._values['parameters'].get('lists', None)
        return result

    @property
    def param_tables(self):
        if self._values['parameters'] is None:
            return None
        result = self._values['parameters'].get('tables', None)
        return result

    @property
    def param_variables(self):
        if self._values['parameters'] is None:
            return None
        result = self._values['parameters'].get('variables', None)
        return result

    @property
    def param_metadata(self):
        if self._values['parameters'] is None:
            return None
        result = self._values['parameters'].get('metadata', None)
        return result

    @property
    def param_description(self):
        if self._values['parameters'] is None:
            return None
        result = self._values['parameters'].get('description', None)
        return result

    @property
    def param_traffic_group(self):
        if self._values['parameters'] is None:
            return None
        result = self._values['parameters'].get('trafficGroup', None)
        if not result:
            return result
        return fq_name(self.partition, result)

    @property
    def param_device_group(self):
        if self._values['parameters'] is None:
            return None
        result = self._values['parameters'].get('deviceGroup', None)
        if not result:
            return result
        return fq_name(self.partition, result)

    @property
    def param_strict_updates(self):
        if self._values['parameters'] is None:
            return None
        result = self._values['parameters'].get('strictUpdates', None)
        return flatten_boolean(result)

    @property
    def tables(self):
        if self._values['tables']:
            return self.normalize_tables(self._values['tables'])
        elif self.param_tables:
            return self.normalize_tables(self.param_tables)
        return None

    @property
    def lists(self):
        if self._values['lists']:
            return self.normalize_list(self._values['lists'])
        elif self.param_lists:
            return self.normalize_list(self.param_lists)
        return None

    @property
    def variables(self):
        if self._values['variables']:
            return self.normalize_variables(self._values['variables'])
        elif self.param_variables:
            return self.normalize_variables(self.param_variables)
        return None

    @property
    def metadata(self):
        if self._values['metadata']:
            result = self.normalize_metadata(self._values['metadata'])
        elif self.param_metadata:
            result = self.normalize_metadata(self.param_metadata)
        else:
            return None
        return result

    @property
    def template(self):
        if self._values['template'] is None:
            return None
        return fq_name(self.partition, self._values['template'])

    @property
    def device_group(self):
        if self._values['device_group'] not in [None, 'none']:
            result = fq_name(self.partition, self._values['device_group'])
        elif self.param_device_group not in [None, 'none']:
            result = self.param_device_group
        else:
            return None
        if not result.startswith('/Common/'):
            raise F5ModuleError(
                "Device groups can only exist in /Common"
            )
        return result

    @property
    def traffic_group(self):
        if self._values['traffic_group']:
            result = fq_name(self.partition, self._values['traffic_group'])
        elif self.param_traffic_group:
            result = self.param_traffic_group
        else:
            return None
        if not result.startswith('/Common/'):
            raise F5ModuleError(
                "Traffic groups can only exist in /Common"
            )
        return result

    @property
    def strict_updates(self):
        if self._values['strict_updates'] is not None:
            result = flatten_boolean(self._values['strict_updates'])
        elif self.param_strict_updates is not None:
            result = flatten_boolean(self.param_strict_updates)
        else:
            return None
        if result == 'yes':
            return 'enabled'
        return 'disabled'

    @property
    def description(self):
        if self._values['description']:
            return self._values['description']
        elif self.param_description:
            return self.param_description
        return None


class Changes(Parameters):
    pass


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
    def metadata(self):
        if self.want.metadata is None:
            return None
        if self.have.metadata is None:
            return self.want.metadata
        want = [(k, v) for d in self.want.metadata for k, v in iteritems(d)]
        have = [(k, v) for d in self.have.metadata for k, v in iteritems(d)]
        if set(want) != set(have):
            return dict(
                metadata=self.want.metadata
            )


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
        start = datetime.now().isoformat()
        version = tmos_version(self.client)
        changed = False
        result = dict()
        state = self.want.state

        if state == "present":
            changed = self.present()
        elif state == "absent":
            changed = self.absent()

        changes = self.changes.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        send_teem(start, self.client, self.module, version)
        return result

    def present(self):
        if self.exists():
            return self.update()
        else:
            return self.create()

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def create(self):
        self._set_changed_options()
        if self.want.traffic_group is None:
            self.want.update({'traffic_group': '/Common/traffic-group-1'})
        if not self.template_exists():
            raise F5ModuleError(
                "The specified template does not exist in the provided partition."
            )
        if self.module.check_mode:
            return True
        self.create_on_device()
        return True

    def remove(self):
        if self.module.check_mode:
            return True
        self.remove_from_device()
        if self.exists():
            raise F5ModuleError("Failed to delete the iApp service")
        return True

    def update(self):
        self.have = self.read_current_from_device()
        if not self.should_update() and not self.want.force:
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

    def exists(self):
        base_uri = "https://{0}:{1}/mgmt/tm/sys/application/service/".format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )
        uri = build_service_uri(base_uri, self.want.partition, self.want.name)
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
        if params or self.want.force:
            params['execute-action'] = 'definition'
            base_uri = "https://{0}:{1}/mgmt/tm/sys/application/service/".format(
                self.client.provider['server'],
                self.client.provider['server_port']
            )
            uri = build_service_uri(base_uri, self.want.partition, self.want.name)
            resp = self.client.api.patch(uri, json=params)
            try:
                response = resp.json()
            except ValueError as ex:
                raise F5ModuleError(str(ex))

            if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
                raise F5ModuleError(resp.content)

        if self.changes.metadata:
            params = dict(metadata=self.changes.metadata)
            params.update({'execute-action': 'definition'})
            base_uri = "https://{0}:{1}/mgmt/tm/sys/application/service/".format(
                self.client.provider['server'],
                self.client.provider['server_port']
            )
            uri = build_service_uri(base_uri, self.want.partition, self.want.name)
            resp = self.client.api.patch(uri, json=params)

            try:
                response = resp.json()
            except ValueError as ex:
                raise F5ModuleError(str(ex))

            if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
                raise F5ModuleError(resp.content)

        return True

    def read_current_from_device(self):
        base_uri = "https://{0}:{1}/mgmt/tm/sys/application/service/".format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )
        uri = build_service_uri(base_uri, self.want.partition, self.want.name)
        resp = self.client.api.get(uri)

        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return ApiParameters(params=response)
        raise F5ModuleError(resp.content)

    def template_exists(self):
        name = fq_name(self.want.partition, self.want.template)
        parts = name.split('/')
        uri = "https://{0}:{1}/mgmt/tm/sys/application/template/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(parts[1], parts[2])
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
        uri = "https://{0}:{1}/mgmt/tm/sys/application/service/".format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )
        resp = self.client.api.post(uri, json=params)

        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        if self.changes.metadata:
            payload = dict(metadata=self.changes.metadata)
            base_uri = "https://{0}:{1}/mgmt/tm/sys/application/service/".format(
                self.client.provider['server'],
                self.client.provider['server_port']
            )
            uri = build_service_uri(base_uri, self.want.partition, self.want.name)
            resp = self.client.api.patch(uri, json=payload)
            try:
                response = resp.json()
            except ValueError as ex:
                raise F5ModuleError(str(ex))

            if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
                raise F5ModuleError(resp.content)

        return True

    def remove_from_device(self):
        base_uri = "https://{0}:{1}/mgmt/tm/sys/application/service/".format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )
        uri = build_service_uri(base_uri, self.want.partition, self.want.name)

        # Metadata needs to be zero'd before the service is removed because
        # otherwise, the API will error out saying that "configuration items"
        # currently exist.
        #
        # In other words, the REST API is not able to delete a service while
        # there is existing metadata
        payload = dict(metadata=[])
        resp = self.client.api.patch(uri, json=payload)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201] or 'code' in response and response['code'] not in [200, 201]:
            raise F5ModuleError(resp.content)

        response = self.client.api.delete(uri)

        if response.status in [200, 201]:
            return True
        raise F5ModuleError(response.content)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(required=True),
            template=dict(),
            description=dict(),
            device_group=dict(),
            parameters=dict(
                type='dict'
            ),
            state=dict(
                default='present',
                choices=['absent', 'present']
            ),
            force=dict(
                default='no',
                type='bool'
            ),
            strict_updates=dict(
                type='bool',
            ),
            metadata=dict(
                type='list',
                elements='raw',
            ),
            traffic_group=dict(),
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
