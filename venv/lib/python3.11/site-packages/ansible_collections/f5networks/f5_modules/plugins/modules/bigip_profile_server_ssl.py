#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2018, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_profile_server_ssl
short_description: Manages server SSL profiles on a BIG-IP
description:
  - Manages server SSL profiles on a BIG-IP system.
version_added: "1.0.0"
options:
  name:
    description:
      - Specifies the name of the profile.
    type: str
    required: True
  parent:
    description:
      - The parent template of this monitor template. Once this value has
        been set, it cannot be changed.
    type: raw
    default: /Common/serverssl
  ciphers:
    description:
      - Specifies the list of ciphers the system supports. When creating a new
        profile, the default cipher list is provided by the parent profile.
      - When the C(cipher_group) parameter is in use, the C(ciphers) parameter needs to be set to either C(none) or C('').
    type: str
  cipher_group:
    description:
      - Specifies the cipher group to assign to this profile.
      - When the C(ciphers) parameter is in use, the C(cipher_group) must be set to either C(none) or C('').
      - When creating a new profile with C(cipher_group), if the parent profile has C(ciphers) set by default,
        the C(cipher) parameter must be set to C(none) or C('') during creation.
      - The parameter only works on TMOS version 13.x and later.
    type: str
    version_added: "1.12.0"
  renegotiation:
    description:
      - Enables or disables SSL renegotiation.
      - When creating a new profile, the setting is provided by the parent profile.
    type: bool
  secure_renegotiation:
    description:
      - Specifies the method of secure renegotiations for SSL connections. When
        creating a new profile, the setting is provided by the parent profile.
      - When C(request) is set, the system requests secure renegotiation of SSL
        connections.
      - C(require) is a default setting and when set, the system permits initial SSL
        handshakes from clients but terminates renegotiations from unpatched clients.
      - With the C(require-strict) setting, the system requires strict renegotiation of SSL
        connections. In this mode the system refuses connections to insecure servers,
        and terminates existing SSL connections to insecure servers.
    type: str
    choices:
      - require
      - require-strict
      - request
  server_name:
    description:
      - Specifies the fully qualified DNS hostname of the server used in Server Name
        Indication communications. When creating a new profile, the setting is provided
        by the parent profile.
    type: str
  sni_default:
    description:
      - Indicates the system uses this profile as the default SSL profile when there
        is no match to the server name, or when the client provides no SNI extension support.
      - When creating a new profile, the setting is provided by the parent profile.
      - There can be only one SSL profile with this setting enabled.
    type: bool
  sni_require:
    description:
      - Requires the network peers also provide SNI support. This setting only takes
        effect when C(sni_default) is C(true).
      - When creating a new profile, the setting is provided by the parent profile.
    type: bool
  server_certificate:
    description:
      - Specifies the way the system handles server certificates.
      - When C(ignore), specifies the system ignores certificates from server systems.
      - When C(require), specifies the system requires a server to present a valid
        certificate.
    type: str
    choices:
      - ignore
      - require
  certificate:
    description:
      - Specifies the name of the certificate the system uses for server-side SSL
        processing.
    type: str
  key:
    description:
      - Specifies the file name of the SSL key.
    type: str
  chain:
    description:
      - Specifies the certificates-key chain to associate with the SSL profile.
    type: str
  authenticate_name:
    description:
      - Specifies a Common Name (CN) that is embedded in a server certificate.
        The system authenticates a server based on the specified CN.
    type: str
  ca_file:
    description:
      - Specifies a server CA the system trusts.
        The default is (None).
    type: str
  options:
    description:
      - Options the system uses for SSL processing in the form of a list. When
        creating a new profile, the list is provided by the parent profile.
      - When C('') or C(none), all options for SSL processing are disabled.
    type: list
    elements: str
    choices:
      - dont-insert-empty-fragments
      - no-ssl
      - no-dtls
      - no-session-resumption-on-renegotiation
      - no-tlsv1.1
      - no-tlsv1.2
      - no-tlsv1.3
      - single-dh-use
      - tls-rollback-bug
      - no-sslv3
      - no-tls
      - no-tlsv1
      - "none"
  passphrase:
    description:
      - Specifies a passphrase used to encrypt the key.
    type: str
  update_password:
    description:
      - C(always) allows users to update passwords if they choose to do so.
        C(on_create) only sets the password for newly created profiles.
    type: str
    choices:
      - always
      - on_create
    default: always
  ocsp_profile:
    description:
      - Specifies the name of the OCSP profile for purpose of validating the status
        of server certificate.
    type: str
  partition:
    description:
      - Device partition to manage resources on.
    type: str
    default: Common
  state:
    description:
      - When C(present), ensures the profile exists.
      - When C(absent), ensures the profile is removed.
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
- name: Create a new server SSL profile
  bigip_profile_server_ssl:
    name: foo
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost

- name: Create server SSL profile with specific cipher group
  bigip_profile_server_ssl:
    state: present
    name: foo_group
    ciphers: "none"
    cipher_group: "/Common/f5-secure"
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost
'''

RETURN = r'''
ciphers:
  description: The ciphers applied to the profile.
  returned: changed
  type: str
  sample: "!SSLv3:!SSLv2:ECDHE+AES-GCM+SHA256:ECDHE-RSA-AES128-CBC-SHA"
cipher_group:
  description: The cipher group applied to the profile.
  returned: changed
  type: str
  sample: "/Common/f5-secure"
secure_renegotiation:
  description: The method of secure SSL renegotiation.
  returned: changed
  type: str
  sample: request
renegotiation:
  description: Renegotiation of SSL sessions.
  returned: changed
  type: bool
  sample: true
options:
  description: The list of options for SSL processing.
  returned: changed
  type: list
  sample: ['no-ssl', 'no-sslv3']
'''
from datetime import datetime

from ansible.module_utils.basic import (
    AnsibleModule, env_fallback
)

from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, transform_name, f5_argument_spec, flatten_boolean, fq_name, is_empty_list
)
from ..module_utils.icontrol import tmos_version
from ..module_utils.teem import send_teem


class Parameters(AnsibleF5Parameters):
    api_map = {
        'cert': 'certificate',
        'cipherGroup': 'cipher_group',
        'ocsp': 'ocsp_profile',
        'defaultsFrom': 'parent',
        'secureRenegotiation': 'secure_renegotiation',
        'sniDefault': 'sni_default',
        'sniRequire': 'sni_require',
        'serverName': 'server_name',
        'peerCertMode': 'server_certificate',
        'caFile': 'ca_file',
        'authenticateName': 'authenticate_name',
        'tmOptions': 'options',
    }

    api_attributes = [
        'cert',
        'chain',
        'ciphers',
        'cipherGroup',
        'defaultsFrom',
        'key',
        'ocsp',
        'secureRenegotiation',
        'sniDefault',
        'sniRequire',
        'serverName',
        'peerCertMode',
        'renegotiation',
        'caFile',
        'authenticateName',
        'tmOptions',
        'passphrase'
    ]

    returnables = [
        'certificate',
        'chain',
        'ciphers',
        'cipher_group',
        'key',
        'ocsp_profile',
        'secure_renegotiation',
        'parent',
        'sni_default',
        'sni_require',
        'server_name',
        'server_certificate',
        'renegotiation',
        'ca_file',
        'authenticate_name',
        'options',
    ]

    updatables = [
        'certificate',
        'chain',
        'ciphers',
        'cipher_group',
        'key',
        'ocsp_profile',
        'secure_renegotiation',
        'sni_default',
        'sni_require',
        'server_name',
        'server_certificate',
        'renegotiation',
        'parent',
        'ca_file',
        'authenticate_name',
        'options',
    ]

    @property
    def sni_default(self):
        return flatten_boolean(self._values['sni_default'])

    @property
    def certificate(self):
        if self._values['certificate'] is None:
            return None
        if self._values['certificate'] in ['', 'none']:
            return ''
        result = fq_name(self.partition, self._values['certificate'])
        return result

    @property
    def key(self):
        if self._values['key'] is None:
            return None
        if self._values['key'] in ['', 'none']:
            return ''
        result = fq_name(self.partition, self._values['key'])
        return result

    @property
    def chain(self):
        if self._values['chain'] is None:
            return None
        if self._values['chain'] in ['', 'none']:
            return ''
        result = fq_name(self.partition, self._values['chain'])
        return result

    @property
    def ocsp_profile(self):
        if self._values['ocsp_profile'] is None:
            return None
        if self._values['ocsp_profile'] in ['', 'none']:
            return ''
        result = fq_name(self.partition, self._values['ocsp_profile'])
        return result

    @property
    def ca_file(self):
        if self._values['ca_file'] is None:
            return None
        if self._values['ca_file'] in ['', 'none']:
            return ''
        result = fq_name(self.partition, self._values['ca_file'])
        return result


class ApiParameters(Parameters):
    @property
    def sni_require(self):
        return flatten_boolean(self._values['sni_require'])

    @property
    def server_name(self):
        if self._values['server_name'] in [None, 'none']:
            return None
        return self._values['server_name']


class ModuleParameters(Parameters):
    @property
    def server_name(self):
        if self._values['server_name'] is None:
            return None
        if self._values['server_name'] in ['', 'none']:
            return ''
        return self._values['server_name']

    @property
    def parent(self):
        parent = self._values.get("parent")
        if parent in [None, "", "None"]:
            return None
        if parent == "serverssl":
            return "/Common/serverssl"
        result = fq_name(self.partition, self._values['parent'])
        return result

    @property
    def renegotiation(self):
        result = flatten_boolean(self._values['renegotiation'])
        if result is None:
            return None
        if result == 'yes':
            return 'enabled'
        return 'disabled'

    @property
    def sni_require(self):
        require = flatten_boolean(self._values['sni_require'])
        default = self.sni_default
        if require is None:
            return None
        if default in [None, 'no']:
            if require == 'yes':
                raise F5ModuleError(
                    "Cannot set 'sni_require' to {0} if 'sni_default' is set as {1}".format(require, default))
        return require

    @property
    def ciphers(self):
        if self._values['ciphers'] is None:
            return None
        if self._values['ciphers'] in ['', 'none']:
            return 'none'
        if self.cipher_group and self.cipher_group != 'none':
            raise F5ModuleError("The cipher parameter must be set to 'none' if cipher_group is defined.")
        return self._values['ciphers']

    @property
    def cipher_group(self):
        if self._values['cipher_group'] is None:
            return None
        if self._values['cipher_group'] in ['', 'none']:
            return 'none'
        if self.ciphers and self.ciphers != 'none':
            raise F5ModuleError("The cipher_group parameter must be set to 'none' if cipher is defined.")
        result = fq_name(self.partition, self._values['cipher_group'])
        return result

    @property
    def options(self):
        options = self._values['options']
        if options is None:
            return None
        if is_empty_list(options):
            return []
        return options

    @property
    def passphrase(self):
        if self._values['passphrase'] is None:
            return None
        if self._values['passphrase'] in ['', 'none']:
            return ''
        return self._values['passphrase']


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
    def sni_default(self):
        if self._values['sni_default'] is None:
            return None
        elif self._values['sni_default'] == 'yes':
            return 'true'
        else:
            return 'false'

    @property
    def sni_require(self):
        if self._values['sni_require'] is None:
            return None
        elif self._values['sni_require'] == 'yes':
            return 'true'
        else:
            return 'false'


class ReportableChanges(Changes):
    @property
    def sni_default(self):
        result = flatten_boolean(self._values['sni_default'])
        return result

    @property
    def sni_require(self):
        result = flatten_boolean(self._values['sni_require'])
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
    def sni_require(self):
        if self.want.sni_require is None:
            return None
        if self.want.sni_require == 'no':
            if self.have.sni_default == 'yes' and self.want.sni_default is None:
                raise F5ModuleError(
                    "Cannot set 'sni_require' to {0} if 'sni_default' is {1}".format(
                        self.want.sni_require, self.have.sni_default
                    )
                )
        if self.want.sni_require != self.have.sni_require:
            return self.want.sni_require

    @property
    def server_name(self):
        if self.want.server_name is None:
            return None
        if self.want.server_name == '' and self.have.server_name is None:
            return None
        if self.want.server_name != self.have.server_name:
            return self.want.server_name

    @property
    def cipher_group(self):
        if self.want.cipher_group is None:
            return None
        if self.want.cipher_group == 'none' and self.have.cipher_group == 'none':
            return None
        if self.want.cipher_group != self.have.cipher_group:
            return self.want.cipher_group

    @property
    def options(self):
        if self.want.options is None:
            return None
        # starting with v14 options may return as a space delimited string in curly
        # braces, eg "{ option1 option2 }", or simply "none" to indicate empty set
        if self.have.options is None or self.have.options == 'none':
            self.have.options = []
        if not isinstance(self.have.options, list):
            if self.have.options.startswith('{'):
                self.have.options = self.have.options[2:-2].split(' ')
            else:
                self.have.options = [self.have.options]
        if not self.want.options:
            # we don't want options.  If we have any, indicate we should remove, else noop
            return [] if self.have.options else None
        if not self.have.options:
            return self.want.options
        if set(self.want.options) != set(self.have.options):
            return self.want.options


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

    def exists(self):
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/server-ssl/{2}".format(
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

    def update(self):
        self.have = self.read_current_from_device()

        if self.want.update_password == 'always':
            self.want.update({'passphrase': self.want.passphrase})
        else:
            if self.want.passphrase:
                del self.want._values['passphrase']

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
        self._set_changed_options()
        if self.module.check_mode:
            return True
        self.create_on_device()
        return True

    def create_on_device(self):
        params = self.changes.api_params()
        params['name'] = self.want.name
        params['partition'] = self.want.partition
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/server-ssl/".format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )
        params['passphrase'] = self.want.passphrase
        resp = self.client.api.post(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if 'code' in response and response['code'] in [400, 403, 404]:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)

    def update_on_device(self):
        params = self.changes.api_params()
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/server-ssl/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        resp = self.client.api.patch(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if 'code' in response and response['code'] in [400, 404]:
            if 'message' in response:
                raise F5ModuleError(response['message'])
            else:
                raise F5ModuleError(resp.content)

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def remove_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/server-ssl/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        response = self.client.api.delete(uri)
        if response.status == 200:
            return True
        raise F5ModuleError(response.content)

    def read_current_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/server-ssl/{2}".format(
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


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(required=True),
            certificate=dict(),
            chain=dict(),
            key=dict(no_log=True),
            passphrase=dict(no_log=True),
            parent=dict(type='raw', default='/Common/serverssl'),
            ciphers=dict(),
            cipher_group=dict(),
            authenticate_name=dict(),
            ca_file=dict(),
            options=dict(
                type='list',
                elements='str',
                choices=[
                    'dont-insert-empty-fragments',
                    'no-ssl',
                    'no-dtls',
                    'no-session-resumption-on-renegotiation',
                    'no-tlsv1.1',
                    'no-tlsv1.2',
                    'no-tlsv1.3',
                    'single-dh-use',
                    'tls-rollback-bug',
                    'no-sslv3',
                    'no-tls',
                    'no-tlsv1',
                    'none',
                ]
            ),
            secure_renegotiation=dict(
                choices=['require', 'require-strict', 'request']
            ),
            server_certificate=dict(
                choices=['ignore', 'require']
            ),
            state=dict(
                default='present',
                choices=['present', 'absent']
            ),
            update_password=dict(
                default='always',
                choices=['always', 'on_create'],
                no_log=False
            ),
            sni_default=dict(type='bool'),
            sni_require=dict(type='bool'),
            server_name=dict(),
            ocsp_profile=dict(),
            renegotiation=dict(type='bool'),
            partition=dict(
                default='Common',
                fallback=(env_fallback, ['F5_PARTITION'])
            )
        )
        self.argument_spec = {}
        self.argument_spec.update(f5_argument_spec)
        self.argument_spec.update(argument_spec)
        self.required_together = [
            ['certificate', 'key']
        ]


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        required_together=spec.required_together,
    )

    try:
        mm = ModuleManager(module=module)
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
