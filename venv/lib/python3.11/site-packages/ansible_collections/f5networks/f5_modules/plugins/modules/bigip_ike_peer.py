#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2018, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_ike_peer
short_description: Manage IPSec IKE Peer configuration on BIG-IP
description:
  - Manage IPSec IKE Peer configuration on a BIG-IP device.
version_added: "1.0.0"
options:
  name:
    description:
      - Specifies the name of the IKE peer.
    type: str
    required: True
  description:
    description:
      - Description of the IKE peer.
    type: str
  version:
    description:
      - Specifies which version of IKE (Internet Key Exchange) is used.
      - If the system you are configuring is the IPsec initiator, and you select
        both versions, the system tries using IKEv2 for negotiation. If the remote
        peer does not support IKEv2, the IPsec tunnel fails. To use IKEv1 in this
        case, you must deselect Version 2 and try again.
      - If the system you are configuring is the IPsec responder, and you select
        both versions, the IPsec initiator system determines which IKE version to use.
      - When creating a new IKE peer, this value is required.
    type: list
    elements: str
    choices:
      - v1
      - v2
  presented_id_type:
    description:
      - Specifies the identifier type the local system uses to identify
        itself to the peer during IKE Phase 1 negotiations.
    type: str
    choices:
      - address
      - asn1dn
      - fqdn
      - keyid-tag
      - user-fqdn
      - override
  presented_id_value:
    description:
      - Specifies a value for the identity when using a C(presented_id_type) of
        C(override).
      - This is a required value when C(version) includes (Cv2).
    type: str
  verified_id_type:
    description:
      - Specifies the identifier type the local system uses to identify
        the peer during IKE Phase 1 negotiation.
      - This is a required value when C(version) includes (Cv2).
      - When C(user-fqdn), value of C(verified_id_value) must be in the form of
        User @ DNS domain string.
    type: str
    choices:
      - address
      - asn1dn
      - fqdn
      - keyid-tag
      - user-fqdn
      - override
  verified_id_value:
    description:
      - Specifies a value for the identity when using a C(verified_id_type) of
        C(override).
      - This is a required value when C(version) includes (Cv2).
    type: str
  phase1_auth_method:
    description:
      - Specifies the authentication method for phase 1 negotiation.
      - When creating a new IKE peer, if this value is not specified, the default is
        C(rsa-signature).
    type: str
    choices:
      - pre-shared-key
      - rsa-signature
  phase1_lifetime:
    description:
      - Defines the lifetime in minutes of an IKE SA which will be proposed in the phase 1 negotiations.
      - The accepted value range is C(1 - 4294967295) minutes.
      - When creating a new IKE peer, if this value is not specified, the default value set by the system is
        C(1440) minutes.
    type: int
    version_added: "1.1.0"
  phase1_cert:
    description:
      - Specifies the digital certificate to use for the RSA signature.
      - When creating a new IKE peer, if this value is not specified, and
        C(phase1_auth_method) is C(rsa-signature), the default is C(default.crt).
      - This parameter is invalid when C(phase1_auth_method) is C(pre-shared-key).
    type: str
  phase1_key:
    description:
      - Specifies the public key the digital certificate contains.
      - When creating a new IKE peer, if this value is not specified, and
        C(phase1_auth_method) is C(rsa-signature), the default is C(default.key).
      - This parameter is invalid when C(phase1_auth_method) is C(pre-shared-key).
    type: str
  phase1_verify_peer_cert:
    description:
      - In IKEv2, specifies whether the certificate sent by the IKE peer is verified
        using the Trusted Certificate Authorities, a CRL, and/or a peer certificate.
      - In IKEv1, specifies whether the identifier sent by the peer is verified with
        the credentials in the certificate, in the following manner - ASN1DN; specifies
        that the entire certificate subject name is compared with the identifier.
        Address, FQDN, or User FQDN; specifies that the certificate's subjectAltName is
        compared with the identifier. If the two do not match, the negotiation fails.
      - When creating a new IKE peer, if this value is not specified, and
        C(phase1_auth_method) is C(rsa-signature), the default is C(false).
      - This parameter is invalid when C(phase1_auth_method) is C(pre-shared-key).
    type: bool
  preshared_key:
    description:
      - Specifies a string the IKE peers share for authenticating each other.
      - This parameter is only relevant when C(phase1_auth_method) is C(pre-shared-key).
      - This parameter is invalid when C(phase1_auth_method) is C(rsa-signature).
    type: str
  remote_address:
    description:
      - Displays the IP address of the BIG-IP system that is remote to the system
        you are configuring.
    type: str
  phase1_encryption_algorithm:
    description:
      - Specifies the algorithm to use for IKE encryption.
      - IKE C(version) C(v2) does not support C(blowfish), C(camellia), or C(cast128).
    type: str
    choices:
      - 3des
      - des
      - blowfish
      - cast128
      - aes128
      - aes192
      - aes256
      - camellia
  phase1_hash_algorithm:
    description:
      - Specifies the algorithm to use for IKE authentication.
    type: str
    choices:
      - sha1
      - md5
      - sha256
      - sha384
      - sha512
  phase1_perfect_forward_secrecy:
    description:
      - Specifies the Diffie-Hellman group to use for IKE Phase 1 and Phase 2 negotiations.
    type: str
    choices:
      - ecp256
      - ecp384
      - ecp521
      - modp768
      - modp1024
      - modp1536
      - modp2048
      - modp3072
      - modp4096
      - modp6144
      - modp8192
  update_password:
    description:
      - C(always) allows updating passwords if the user chooses to do so.
        C(on_create) only sets the password for newly created IKE peers.
    type: str
    choices:
      - always
      - on_create
    default: always
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
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Create new IKE peer
  bigip_ike_peer:
    name: ike1
    remote_address: 1.2.3.4
    version:
      - v1
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost

- name: Change presented id type - keyid-tag
  bigip_ike_peer:
    name: ike1
    presented_id_type: keyid-tag
    presented_id_value: key1
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost

- name: Remove IKE peer
  bigip_ike_peer:
    name: ike1
    state: absent
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost
'''

RETURN = r'''
presented_id_type:
  description: The new Presented ID Type value of the resource.
  returned: changed
  type: str
  sample: address
verified_id_type:
  description: The new Verified ID Type value of the resource.
  returned: changed
  type: str
  sample: address
phase1_auth_method:
  description: The new IKE Phase 1 Credentials Authentication Method value of the resource.
  returned: changed
  type: str
  sample: rsa-signature
remote_address:
  description: The new Remote Address value of the resource.
  returned: changed
  type: str
  sample: 1.2.2.1
version:
  description: The new list of IKE versions.
  returned: changed
  type: list
  sample: ['v1', 'v2']
phase1_encryption_algorithm:
  description: The new IKE Phase 1 Encryption Algorithm.
  returned: changed
  type: str
  sample: 3des
phase1_hash_algorithm:
  description: The new IKE Phase 1 Authentication Algorithm.
  returned: changed
  type: str
  sample: sha256
phase1_perfect_forward_secrecy:
  description: The new IKE Phase 1 Perfect Forward Secrecy.
  returned: changed
  type: str
  sample: modp1024
phase1_cert:
  description: The new IKE Phase 1 Certificate Credentials.
  returned: changed
  type: str
  sample: /Common/cert1.crt
phase1_key:
  description: The new IKE Phase 1 Key Credentials.
  returned: changed
  type: str
  sample: /Common/cert1.key
phase1_verify_peer_cert:
  description: The new IKE Phase 1 Key Verify Peer Certificate setting.
  returned: changed
  type: bool
  sample: true
verified_id_value:
  description: The new Verified ID Value setting for the Verified ID Type.
  returned: changed
  type: str
  sample: 1.2.3.1
presented_id_value:
  description: The new Presented ID Value setting for the Presented ID Type.
  returned: changed
  type: str
  sample: 1.2.3.1
'''
from datetime import datetime

from ansible.module_utils.basic import (
    AnsibleModule, env_fallback
)

from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, transform_name, f5_argument_spec, flatten_boolean, fq_name
)
from ..module_utils.compare import cmp_str_with_none
from ..module_utils.icontrol import tmos_version
from ..module_utils.teem import send_teem


class Parameters(AnsibleF5Parameters):
    api_map = {
        'myIdType': 'presented_id_type',
        'peersIdType': 'verified_id_type',
        'phase1AuthMethod': 'phase1_auth_method',
        'presharedKeyEncrypted': 'preshared_key',
        'remoteAddress': 'remote_address',
        'version': 'version',
        'phase1EncryptAlgorithm': 'phase1_encryption_algorithm',
        'phase1HashAlgorithm': 'phase1_hash_algorithm',
        'phase1PerfectForwardSecrecy': 'phase1_perfect_forward_secrecy',
        'myCertFile': 'phase1_cert',
        'myCertKeyFile': 'phase1_key',
        'verifyCert': 'phase1_verify_peer_cert',
        'peersIdValue': 'verified_id_value',
        'myIdValue': 'presented_id_value',
        'lifetime': 'phase1_lifetime',
    }

    api_attributes = [
        'myIdType',
        'peersIdType',
        'phase1AuthMethod',
        'presharedKeyEncrypted',
        'remoteAddress',
        'version',
        'phase1EncryptAlgorithm',
        'phase1HashAlgorithm',
        'phase1PerfectForwardSecrecy',
        'myCertFile',
        'myCertKeyFile',
        'verifyCert',
        'peersIdValue',
        'myIdValue',
        'description',
        'lifetime',
    ]

    returnables = [
        'presented_id_type',
        'verified_id_type',
        'phase1_auth_method',
        'preshared_key',
        'remote_address',
        'version',
        'phase1_encryption_algorithm',
        'phase1_hash_algorithm',
        'phase1_perfect_forward_secrecy',
        'phase1_cert',
        'phase1_key',
        'phase1_verify_peer_cert',
        'verified_id_value',
        'presented_id_value',
        'description',
        'phase1_lifetime',
    ]

    updatables = [
        'presented_id_type',
        'verified_id_type',
        'phase1_auth_method',
        'preshared_key',
        'remote_address',
        'version',
        'phase1_encryption_algorithm',
        'phase1_hash_algorithm',
        'phase1_perfect_forward_secrecy',
        'phase1_cert',
        'phase1_key',
        'phase1_verify_peer_cert',
        'verified_id_value',
        'presented_id_value',
        'description',
        'phase1_lifetime',
    ]

    @property
    def phase1_verify_peer_cert(self):
        return flatten_boolean(self._values['phase1_verify_peer_cert'])


class ApiParameters(Parameters):
    @property
    def description(self):
        if self._values['description'] in [None, 'none']:
            return None
        return self._values['description']


class ModuleParameters(Parameters):
    @property
    def phase1_cert(self):
        if self._values['phase1_cert'] is None:
            return None
        if self._values['phase1_cert'] in ['', 'none']:
            return ''
        return fq_name(self.partition, self._values['phase1_cert'])

    @property
    def phase1_key(self):
        if self._values['phase1_key'] is None:
            return None
        if self._values['phase1_key'] in ['', 'none']:
            return ''
        return fq_name(self.partition, self._values['phase1_key'])

    @property
    def phase1_lifetime(self):
        if self._values['phase1_lifetime'] is None:
            return None
        if 1 <= int(self._values['phase1_lifetime']) <= 4294967295:
            return int(self._values['phase1_lifetime'])
        raise F5ModuleError(
            "Valid 'phase1_lifetime' must be in range 1 - 4294967295."
        )

    @property
    def description(self):
        if self._values['description'] is None:
            return None
        elif self._values['description'] in ['none', '']:
            return ''
        return self._values['description']


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
    def phase1_verify_peer_cert(self):
        if self._values['phase1_verify_peer_cert'] is None:
            return None
        elif self._values['phase1_verify_peer_cert'] == 'yes':
            return 'true'
        else:
            return 'false'


class ReportableChanges(Changes):
    @property
    def phase1_verify_peer_cert(self):
        return flatten_boolean(self._values['phase1_verify_peer_cert'])

    @property
    def preshared_key(self):
        return None


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
        return cmp_str_with_none(self.want.description, self.have.description)


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
        uri = "https://{0}:{1}/mgmt/tm/net/ipsec/ike-peer/{2}".format(
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

        if self.changes.version is not None and len(self.changes.version) == 0:
            raise F5ModuleError(
                "At least one version value must be specified."
            )

        if self.changes.phase1_auth_method == 'pre-shared-key':
            if self.changes.preshared_key is None and self.have.preshared_key is None:
                raise F5ModuleError(
                    "A 'preshared_key' must be specified when changing 'phase1_auth_method' "
                    "to 'pre-shared-key'."
                )

        if self.want.update_password == 'always':
            self.want.update({'preshared_key': self.want.preshared_key})
        else:
            if self.want.preshared_key:
                del self.want._values['preshared_key']

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
        if self.changes.version is None:
            raise F5ModuleError(
                "The 'version' parameter is required when creating a new IKE peer."
            )
        if self.changes.phase1_auth_method is None:
            self.changes.update({'phase1_auth_method': 'rsa-signature'})
            if self.changes.phase1_cert is None:
                self.changes.update({'phase1_cert': 'default.crt'})
            if self.changes.phase1_key is None:
                self.changes.update({'phase1_key': 'default.key'})

        if self.module.check_mode:
            return True
        self.create_on_device()
        return True

    def create_on_device(self):
        params = self.changes.api_params()
        params['name'] = self.want.name
        params['partition'] = self.want.partition
        uri = "https://{0}:{1}/mgmt/tm/net/ipsec/ike-peer/".format(
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
        uri = "https://{0}:{1}/mgmt/tm/net/ipsec/ike-peer/{2}".format(
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

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def remove_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/net/ipsec/ike-peer/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        response = self.client.api.delete(uri)

        if response.status in [200, 201]:
            return True
        raise F5ModuleError(response.content)

    def read_current_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/net/ipsec/ike-peer/{2}".format(
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
            return ApiParameters(params=response)
        raise F5ModuleError(resp.content)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(required=True),
            presented_id_type=dict(
                choices=['address', 'asn1dn', 'fqdn', 'keyid-tag', 'user-fqdn', 'override']
            ),
            presented_id_value=dict(),
            verified_id_type=dict(
                choices=['address', 'asn1dn', 'fqdn', 'keyid-tag', 'user-fqdn', 'override']
            ),
            verified_id_value=dict(),
            phase1_auth_method=dict(
                choices=[
                    'pre-shared-key', 'rsa-signature'
                ]
            ),
            preshared_key=dict(no_log=True),
            remote_address=dict(),
            version=dict(
                type='list',
                elements='str',
                choices=['v1', 'v2']
            ),
            phase1_lifetime=dict(type='int'),
            phase1_encryption_algorithm=dict(
                choices=[
                    '3des', 'des', 'blowfish', 'cast128', 'aes128', 'aes192',
                    'aes256', 'camellia'
                ]
            ),
            phase1_hash_algorithm=dict(
                choices=[
                    'sha1', 'md5', 'sha256', 'sha384', 'sha512'
                ]
            ),
            phase1_perfect_forward_secrecy=dict(
                choices=[
                    'ecp256', 'ecp384', 'ecp521', 'modp768', 'modp1024', 'modp1536',
                    'modp2048', 'modp3072', 'modp4096', 'modp6144', 'modp8192'
                ]
            ),
            phase1_cert=dict(),
            phase1_key=dict(no_log=True),
            phase1_verify_peer_cert=dict(type='bool'),
            update_password=dict(
                default='always',
                choices=['always', 'on_create'],
                no_log=False
            ),
            description=dict(),
            state=dict(default='present', choices=['absent', 'present']),
            partition=dict(
                default='Common',
                fallback=(env_fallback, ['F5_PARTITION'])
            )
        )
        self.argument_spec = {}
        self.argument_spec.update(f5_argument_spec)
        self.argument_spec.update(argument_spec)
        self.required_if = [
            ['presented_id_type', 'fqdn', ['presented_id_value']],
            ['presented_id_type', 'keyid-tag', ['presented_id_value']],
            ['presented_id_type', 'user-fqdn', ['presented_id_value']],
            ['presented_id_type', 'override', ['presented_id_value']],

            ['verified_id_type', 'fqdn', ['verified_id_value']],
            ['verified_id_type', 'keyid-tag', ['verified_id_value']],
            ['verified_id_type', 'user-fqdn', ['verified_id_value']],
            ['verified_id_type', 'override', ['verified_id_value']],
        ]
        self.required_together = [
            ['phase1_cert', 'phase1_key']
        ]


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        required_if=spec.required_if,
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
