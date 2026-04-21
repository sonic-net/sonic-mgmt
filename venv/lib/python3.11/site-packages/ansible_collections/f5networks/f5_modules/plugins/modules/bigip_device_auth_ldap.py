#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2018, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_device_auth_ldap
short_description: Manage LDAP device authentication settings on BIG-IP
description:
  - Manage LDAP device authentication settings on BIG-IP.
version_added: "1.0.0"
options:
  servers:
    description:
      - Specifies the LDAP servers the system must use to obtain
        authentication information. You must specify a server when you
        create an LDAP configuration object.
    type: list
    elements: str
  port:
    description:
      - Specifies the port the system uses for access to the remote host server.
      - When configuring LDAP device authentication for the first time, the default
        port is C(389) if this parameter is not specified.
    type: int
  remote_directory_tree:
    description:
      - Specifies the file location (tree) of the user authentication database on the
        server.
    type: str
  scope:
    description:
      - Specifies the level of the remote Active Directory or LDAP directory the
        system should search for the user authentication.
    type: str
    choices:
      - sub
      - one
      - base
  bind_dn:
    description:
      - Specifies the distinguished name for the Active Directory or LDAP server user
        ID.
      - The BIG-IP client authentication module does not support Active Directory or
        LDAP servers that do not perform bind referral when authenticating referred
        accounts.
      - Therefore, if you plan to use Active Directory or LDAP as your authentication
        source and want to use referred accounts, make sure your servers perform bind
        referral.
    type: str
  bind_password:
    description:
      - Specifies a password for the Active Directory or LDAP server user ID.
    type: str
  user_template:
    description:
      - Specifies the distinguished name of the user who is logging on.
      - You specify the template as a variable that the system replaces with user-specific
        information during the logon attempt.
      - For example, you could specify a user template such as C(%s@siterequest.com) or
        C(uxml:id=%s,ou=people,dc=siterequest,dc=com).
      - When a user attempts to log on, the system replaces C(%s) with the name the user
        specified in the Basic Authentication dialog box, and passes that as the
        distinguished name for the bind operation.
      - The system passes the associated password as the password for the bind operation.
      - This field can contain only one C(%s) and cannot contain any other format
        specifiers.
    type: str
  check_member_attr:
    description:
      - Checks the member attribute of the user in the remote LDAP or AD group.
    type: bool
  ssl:
    description:
      - Specifies whether the system uses an SSL port to communicate with the LDAP server.
    type: str
    choices:
      - "yes"
      - "no"
      - start-tls
  ca_cert:
    description:
      - Specifies the name of an SSL certificate from a certificate authority (CA).
      - To remove this value, use the reserved value C(none).
    type: str
    aliases: [ ssl_ca_cert ]
  client_key:
    description:
      - Specifies the name of an SSL client key.
      - To remove this value, use the reserved value C(none).
    type: str
    aliases: [ ssl_client_key ]
  client_cert:
    description:
      - Specifies the name of an SSL client certificate.
      - To remove this value, use the reserved value C(none).
    type: str
    aliases: [ ssl_client_cert ]
  validate_certs:
    description:
      - Specifies whether the system checks an SSL peer, as a result of which the
        system requires and verifies the server certificate.
    type: bool
    aliases: [ ssl_check_peer ]
  login_ldap_attr:
    description:
      - Specifies the LDAP directory attribute containing the local user name that is
        associated with the selected directory entry.
      - If this parameter is not specified, when configuring LDAP device authentication for the first time,
        the default port is C(samaccountname).
    type: str
  fallback_to_local:
    description:
      - Specifies the system uses the Local authentication method if the remote
        authentication method is not available.
      - Option only available on C(TMOS 13.0.0) and above.
    type: bool
  referrals:
    description:
      - Specifies whether automatic referral chasing should be enabled.
      - Option only available on C(TMOS 15.1.0) and above.
    type: bool
    version_added: "1.22.0"
  state:
    description:
      - When C(present), ensures the device authentication method exists.
      - When C(absent), ensures the device authentication method does not exist.
      - When C(state) equal to (absent), before you can delete the LDAP configuration, the system must set auth to
        some alternative. The system ships with a system auth called C(local), therefore the system authentication type
        is set to that value on the device upon removal of LDAP configuration.
    type: str
    choices:
      - present
      - absent
    default: present
  update_password:
    description:
      - C(always) always updates the C(bind_password).
      - C(on_create) only sets the C(bind_password) for newly created authentication
        mechanisms.
    type: str
    choices:
      - always
      - on_create
    default: always
  use_for_auth:
    description:
      - Specifies whether or not this auth source is put in use on the system.
      - If C(true), the module sets the current system auth type to the value of C(ldap).
      - If C(false), the module sets the authentication type to C(local), similar behavior to when C(state) is C(absent),
        without removing the configured LDAP resource.
    type: bool
  source_type:
    description:
      - Specifies the auth source for user authentication, should be used with C(use_for_auth).
    type: str
    choices:
      - ldap
      - active-directory
    default: ldap
    version_added: "1.13.0"
extends_documentation_fragment: f5networks.f5_modules.f5
author:
  - Tim Rupp (@caphrim007)
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Create an LDAP authentication object
  bigip_device_auth_ldap:
    name: foo
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost
'''

RETURN = r'''
servers:
  description: LDAP servers used by the system to obtain authentication information.
  returned: changed
  type: list
  sample: ['192.168.1.1', '192.168.1.2']
port:
  description: The port the system uses for access to the remote LDAP server.
  returned: changed
  type: int
  sample: 389
remote_directory_tree:
  description: File location (tree) of the user authentication database on the server.
  returned: changed
  type: str
  sample: "CN=Users,DC=FOOBAR,DC=LOCAL"
scope:
  description: The level of the remote Active Directory or LDAP directory searched for user authentication.
  returned: changed
  type: str
  sample: base
bind_dn:
  description: The distinguished name for the Active Directory or LDAP server user ID.
  returned: changed
  type: str
  sample: "user@foobar.local"
user_template:
  description: The distinguished name of the user who is logging on.
  returned: changed
  type: str
  sample: "uid=%s,ou=people,dc=foobar,dc=local"
check_member_attr:
  description: The user's member attribute in the remote LDAP or AD group.
  returned: changed
  type: bool
  sample: true
ssl:
  description: Specifies whether the system uses an SSL port to communicate with the LDAP server.
  returned: changed
  type: str
  sample: start-tls
ca_cert:
  description: The name of an SSL certificate from a certificate authority.
  returned: changed
  type: str
  sample: My-Trusted-CA-Bundle.crt
client_key:
  description: The name of an SSL client key.
  returned: changed
  type: str
  sample: MyKey.key
client_cert:
  description: The name of an SSL client certificate.
  returned: changed
  type: str
  sample: MyCert.crt
validate_certs:
  description: Indicates if the system checks an SSL peer.
  returned: changed
  type: bool
  sample: true
login_ldap_attr:
  description: The LDAP directory attribute containing the local user name associated with the selected directory entry.
  returned: changed
  type: str
  sample: samaccountname
fallback_to_local:
  description: Specifies the system uses the Local authentication method as fallback
  returned: changed
  type: bool
  sample: true
referrals:
  description: Specifies whether automatic referral chasing should be enabled
  returned: changed
  type: bool
  sample: true
'''

from datetime import datetime
from ansible.module_utils.basic import AnsibleModule

from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, transform_name, f5_argument_spec, flatten_boolean, fq_name
)
from ..module_utils.compare import cmp_str_with_none
from ..module_utils.icontrol import tmos_version
from ..module_utils.teem import send_teem


class Parameters(AnsibleF5Parameters):
    api_map = {
        'bindDn': 'bind_dn',
        'bindPw': 'bind_password',
        'userTemplate': 'user_template',
        'fallback': 'fallback_to_local',
        'referrals': 'referrals',
        'loginAttribute': 'login_ldap_attr',
        'sslCheckPeer': 'validate_certs',
        'sslClientCert': 'client_cert',
        'sslClientKey': 'client_key',
        'sslCaCertFile': 'ca_cert',
        'checkRolesGroup': 'check_member_attr',
        'searchBaseDn': 'remote_directory_tree',
    }

    api_attributes = [
        'bindDn',
        'bindPw',
        'checkRolesGroup',
        'loginAttribute',
        'port',
        'scope',
        'searchBaseDn',
        'servers',
        'ssl',
        'sslCaCertFile',
        'sslCheckPeer',
        'sslClientCert',
        'sslClientKey',
        'userTemplate',
        'referrals',
    ]

    returnables = [
        'bind_dn',
        'bind_password',
        'check_member_attr',
        'fallback_to_local',
        'referrals',
        'login_ldap_attr',
        'port',
        'remote_directory_tree',
        'scope',
        'servers',
        'ssl',
        'ca_cert',
        'validate_certs',
        'client_cert',
        'client_key',
        'user_template',
    ]

    updatables = [
        'bind_dn',
        'bind_password',
        'check_member_attr',
        'fallback_to_local',
        'referrals',
        'login_ldap_attr',
        'port',
        'remote_directory_tree',
        'scope',
        'servers',
        'ssl',
        'ca_cert',
        'validate_certs',
        'client_cert',
        'client_key',
        'user_template',
        'auth_source',
    ]

    @property
    def ca_cert(self):
        if self._values['ca_cert'] is None:
            return None
        elif self._values['ca_cert'] in ['none', '']:
            return ''
        return fq_name(self.partition, self._values['ca_cert'])

    @property
    def client_key(self):
        if self._values['client_key'] is None:
            return None
        elif self._values['client_key'] in ['none', '']:
            return ''
        return fq_name(self.partition, self._values['client_key'])

    @property
    def client_cert(self):
        if self._values['client_cert'] is None:
            return None
        elif self._values['client_cert'] in ['none', '']:
            return ''
        return fq_name(self.partition, self._values['client_cert'])

    @property
    def validate_certs(self):
        return flatten_boolean(self._values['validate_certs'])

    @property
    def check_member_attr(self):
        return flatten_boolean(self._values['check_member_attr'])

    @property
    def login_ldap_attr(self):
        if self._values['login_ldap_attr'] is None:
            return None
        elif self._values['login_ldap_attr'] in ['none', '']:
            return ''
        return self._values['login_ldap_attr']

    @property
    def user_template(self):
        if self._values['user_template'] is None:
            return None
        elif self._values['user_template'] in ['none', '']:
            return ''
        return self._values['user_template']

    @property
    def ssl(self):
        if self._values['ssl'] is None:
            return None
        elif self._values['ssl'] == 'start-tls':
            return 'start-tls'
        return flatten_boolean(self._values['ssl'])

    @property
    def fallback_to_local(self):
        return flatten_boolean(self._values['fallback_to_local'])

    @property
    def referrals(self):
        return flatten_boolean(self._values['referrals'])


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    @property
    def use_for_auth(self):
        return flatten_boolean(self._values['use_for_auth'])

    @property
    def auth_source(self):
        if self._values['use_for_auth'] is None:
            return None
        if self.use_for_auth == 'yes':
            return self._values['source_type']
        if self.use_for_auth == 'no':
            return 'local'


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
    def validate_certs(self):
        if self._values['validate_certs'] is None:
            return None
        elif self._values['validate_certs'] == 'yes':
            return 'enabled'
        return 'disabled'

    @property
    def fallback_to_local(self):
        if self._values['fallback_to_local'] is None:
            return None
        elif self._values['fallback_to_local'] == 'yes':
            return 'true'
        return 'false'

    @property
    def referrals(self):
        if self._values['referrals'] is None:
            return None
        elif self._values['referrals'] == 'yes':
            return 'yes'
        return 'no'

    @property
    def check_member_attr(self):
        if self._values['check_member_attr'] is None:
            return None
        elif self._values['check_member_attr'] == 'yes':
            return 'enabled'
        return 'disabled'

    @property
    def ssl(self):
        if self._values['ssl'] is None:
            return None
        elif self._values['ssl'] == 'start-tls':
            return 'start-tls'
        elif self._values['ssl'] == 'yes':
            return 'enabled'
        return 'disabled'


class ReportableChanges(Changes):
    @property
    def bind_password(self):
        return None

    @property
    def validate_certs(self):
        return flatten_boolean(self._values['validate_certs'])

    @property
    def referrals(self):
        return flatten_boolean(self._values['referrals'])

    @property
    def check_member_attr(self):
        return flatten_boolean(self._values['check_member_attr'])

    @property
    def ssl(self):
        if self._values['ssl'] is None:
            return None
        elif self._values['ssl'] == 'start-tls':
            return 'start-tls'
        return flatten_boolean(self._values['ssl'])


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
    def login_ldap_attr(self):
        return cmp_str_with_none(self.want.login_ldap_attr, self.have.login_ldap_attr)

    @property
    def user_template(self):
        return cmp_str_with_none(self.want.user_template, self.have.user_template)

    @property
    def ca_cert(self):
        return cmp_str_with_none(self.want.ca_cert, self.have.ca_cert)

    @property
    def client_key(self):
        return cmp_str_with_none(self.want.client_key, self.have.client_key)

    @property
    def client_cert(self):
        return cmp_str_with_none(self.want.client_cert, self.have.client_cert)

    @property
    def bind_password(self):
        if self.want.bind_password != self.have.bind_password and self.want.update_password == 'always':
            return self.want.bind_password


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

    def _announce_deprecations(self, result):
        warnings = result.pop('__warnings', [])
        for warning in warnings:
            self.client.module.deprecate(
                msg=warning['msg'],
                version=warning['version']
            )

    def update_auth_source_on_device(self, source):
        """Set the system auth source.

        Configuring the authentication source is only one step in the process of setting
        up an auth source. The other step is to inform the system of the auth source
        you want to use.

        This method is used for situations where

        * The ``use_for_auth`` parameter is set to ``yes``
        * The ``use_for_auth`` parameter is set to ``no``
        * The ``state`` parameter is set to ``absent``

        When ``state`` equal to ``absent``, before you can delete the LDAP configuration,
        you must set the system auth to "something else". The system ships with a system
        auth called "local", so this is the logical "something else" to use.

        When ``use_for_auth`` is no, the same situation applies as when ``state`` equal
        to ``absent`` is done above.

        When ``use_for_auth`` is ``yes``, this method will set the current system auth
        state to the value of source_type.

        Arguments:
            source (string): The source that you want to set on the device.
        """
        params = dict(
            type=source
        )
        uri = 'https://{0}:{1}/mgmt/tm/auth/source/'.format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )

        resp = self.client.api.patch(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True
        raise F5ModuleError(resp.content)

    def update_fallback_on_device(self, fallback):
        params = dict(
            fallback=fallback
        )
        uri = 'https://{0}:{1}/mgmt/tm/auth/source/'.format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )

        resp = self.client.api.patch(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True
        raise F5ModuleError(resp.content)

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
            return self.update()
        else:
            return self.create()

    def absent(self):
        if self.exists():
            return self.remove()
        return False

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
        if self.want.fallback_to_local == 'yes':
            self.update_fallback_on_device('true')
        elif self.want.fallback_to_local == 'no':
            self.update_fallback_on_device('false')
        if self.want.use_for_auth and self.changes.auth_source:
            self.update_auth_source_on_device(self.changes.auth_source)
        return True

    def remove(self):
        if self.module.check_mode:
            return True
        self.update_auth_source_on_device('local')
        self.remove_from_device()
        if self.exists():
            raise F5ModuleError("Failed to delete the resource.")
        return True

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:
            return True
        self.create_on_device()
        if self.want.fallback_to_local == 'yes':
            self.update_fallback_on_device('true')
        elif self.want.fallback_to_local == 'no':
            self.update_fallback_on_device('false')
        if self.want.use_for_auth:
            self.update_auth_source_on_device(self.want.auth_source)
        return True

    def exists(self):
        errors = [401, 403, 409, 500, 501, 502, 503, 504]
        uri = "https://{0}:{1}/mgmt/tm/auth/ldap/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name('Common', 'system-auth')
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
        params['name'] = 'system-auth'
        params['partition'] = 'Common'
        uri = "https://{0}:{1}/mgmt/tm/auth/ldap/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
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
        if not params:
            return
        uri = "https://{0}:{1}/mgmt/tm/auth/ldap/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name('Common', 'system-auth')
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
        uri = "https://{0}:{1}/mgmt/tm/auth/ldap/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name('Common', 'system-auth')
        )
        response = self.client.api.delete(uri)

        if response.status in [200, 201]:
            return True
        raise F5ModuleError(response.content)

    def read_current_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/auth/ldap/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name('Common', 'system-auth')
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            response.update(self.read_current_auth_source_from_device())
            return ApiParameters(params=response)
        raise F5ModuleError(resp.content)

    def read_current_auth_source_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/auth/source".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))
        result = {}
        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            if 'fallback' in response:
                result['fallback'] = response['fallback']
            if 'type' in response:
                result['auth_source'] = response['type']
            return result
        raise F5ModuleError(resp.content)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            servers=dict(
                type='list',
                elements='str',
            ),
            port=dict(type='int'),
            remote_directory_tree=dict(),
            scope=dict(
                choices=['sub', 'one', 'base']
            ),
            bind_dn=dict(),
            source_type=dict(
                default='ldap',
                choices=['ldap', 'active-directory']
            ),
            bind_password=dict(no_log=True),
            user_template=dict(),
            check_member_attr=dict(type='bool'),
            ssl=dict(
                choices=['yes', 'no', 'start-tls']
            ),
            ca_cert=dict(aliases=['ssl_ca_cert']),
            client_key=dict(aliases=['ssl_client_key'], no_log=True),
            client_cert=dict(aliases=['ssl_client_cert']),
            validate_certs=dict(type='bool', aliases=['ssl_check_peer']),
            login_ldap_attr=dict(),
            fallback_to_local=dict(type='bool'),
            referrals=dict(type='bool'),
            use_for_auth=dict(type='bool'),
            update_password=dict(
                default='always',
                choices=['always', 'on_create'],
                no_log=False
            ),
            state=dict(default='present', choices=['absent', 'present']),
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
