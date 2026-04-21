#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2017, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_profile_client_ssl
short_description: Manages client SSL profiles on a BIG-IP
description:
  - Manages client SSL profiles on a BIG-IP device.
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
        been set, it cannot be changed. By default, this value is the C(clientssl)
        parent on the C(Common) partition.
    type: str
  ciphers:
    description:
      - Specifies the list of ciphers the system supports.
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
    version_added: "1.2.0"
  cert_key_chain:
    description:
      - One or more certificates and keys to associate with the SSL profile. This
        option is always a list. The keys in the list dictate the details of the
        client/key/chain combination. Note that BIG-IPs can only have one of each
        type of each certificate/key type. This means you can only have one
        RSA, one DSA, and one ECDSA per profile. If you attempt to assign two
        RSA, DSA, or ECDSA certificate/key combo, the device rejects it.
      - This list is a complex list that specifies a number of keys.
    type: list
    elements: dict
    suboptions:
      cert:
        description:
          - Specifies a certificate name for use.
        type: str
        required: True
      key:
        description:
          - Contains a key name.
        type: str
        required: True
      chain:
        description:
          - Contains a certificate chain relevant to the certificate and key
            mentioned previously.
          - This key is optional.
        type: str
      passphrase:
        description:
          - Contains the passphrase of the key file, if required.
          - Passphrases are encrypted on the remote BIG-IP device. Therefore, there is no way
            to compare them when updating a client SSL profile. Due to this, if you specify a
            passphrase, this module will always register a C(changed) event.
        type: str
      true_names:
        description:
          - When C(true), the module does not append C(.crt) and C(.key) extensions to the given certificate and key names.
          - When C(false), the module appends C(.crt) and C(.key) extensions to the given certificate and key names.
        type: bool
        default: false
        version_added: "1.1.0"
  partition:
    description:
      - Device partition to manage resources on.
    type: str
    default: Common
  options:
    description:
      - Options the system uses for SSL processing in the form of a list. When
        creating a new profile, the list is provided by the parent profile.
      - When C('') or C(none), all options for SSL processing are disabled.
    type: list
    elements: str
    choices:
      - netscape-reuse-cipher-change-bug
      - microsoft-big-sslv3-buffer
      - msie-sslv2-rsa-padding
      - ssleay-080-client-dh-bug
      - tls-d5-bug
      - tls-block-padding-bug
      - dont-insert-empty-fragments
      - no-ssl
      - no-dtls
      - no-session-resumption-on-renegotiation
      - no-tlsv1.1
      - no-tlsv1.2
      - no-tlsv1.3
      - single-dh-use
      - ephemeral-rsa
      - cipher-server-preference
      - tls-rollback-bug
      - no-sslv2
      - no-sslv3
      - no-tls
      - no-tlsv1
      - pkcs1-check-1
      - pkcs1-check-2
      - netscape-ca-dn-bug
      - netscape-demo-cipher-change-bug
      - "none"
  secure_renegotiation:
    description:
      - Specifies the method of secure renegotiations for SSL connections. When
        creating a new profile, the setting is provided by the parent profile.
      - When C(request), the system requests secure renegotiation of SSL
        connections.
      - C(require) is a default setting and when set, the system permits initial SSL
        handshakes from clients, but terminates renegotiations from unpatched clients.
      - With the C(require-strict) setting, the system requires strict renegotiation of SSL
        connections. In this mode, the system refuses connections to insecure servers,
        and terminates existing SSL connections to insecure servers.
    type: str
    choices:
      - require
      - require-strict
      - request
  allow_non_ssl:
    description:
      - Enables or disables acceptance of non-SSL connections.
      - When creating a new profile, the setting is provided by the parent profile.
    type: bool
  server_name:
    description:
      - Specifies the fully qualified DNS hostname of the server used in Server Name Indication communications.
        When creating a new profile, the setting is provided by the parent profile.
      - The server name can also be a wildcard string containing the asterisk C(*) character.
    type: str
  sni_default:
    description:
      - Indicates the system uses this profile as the default SSL profile when there is no match to the
        server name, or when the client provides no SNI extension support.
      - When creating a new profile, the setting is provided by the parent profile.
      - There can be only one SSL profile with this setting enabled.
    type: bool
  sni_require:
    description:
      - Requires the network peers also provide SNI support. This setting only takes effect when C(sni_default) is
        set to C(true).
      - When creating a new profile, the setting is provided by the parent profile.
    type: bool
  strict_resume:
    description:
      - Enables or disables the resumption of SSL sessions after an unclean shutdown.
      - When creating a new profile, the setting is provided by the parent profile.
    type: bool
  client_certificate:
    description:
      - Specifies the way the system handles client certificates.
      - When C(ignore), specifies the system ignores certificates from client
        systems.
      - When C(require), specifies the system requires a client to present a
        valid certificate.
      - When C(request), specifies the system requests a valid certificate from a
        client but always authenticate the client.
    type: str
    choices:
      - ignore
      - require
      - request
  client_auth_frequency:
    description:
      - Specifies the frequency of client authentication for an SSL session.
      - When C(once), specifies the system authenticates the client once for an
        SSL session.
      - When C(always), specifies the system authenticates the client once for an
        SSL session and also upon reuse of that session.
    type: str
    choices:
      - once
      - always
  renegotiation:
    description:
      - Enables or disables SSL renegotiation.
      - When creating a new profile, the setting is provided by the parent profile.
    type: bool
  retain_certificate:
    description:
      - When C(true), the client certificate is retained in SSL session.
    type: bool
  cert_auth_depth:
    description:
      - Specifies the maximum number of certificates to be traversed in a client
        certificate chain.
    type: int
  trusted_cert_authority:
    description:
      - Specifies a client CA the system trusts.
    type: str
  advertised_cert_authority:
    description:
      - Specifies the CAs the system advertises to clients is being trusted
        by the profile.
    type: str
  client_auth_crl:
    description:
      - Specifies the name of a file containing a list of revoked client certificates.
    type: str
  allow_expired_crl:
    description:
      - Instructs the system to use the specified CRL file even if it has expired.
    type: bool
  cache_size:
    description:
      - Specifies the number of sessions in the SSL session cache.
      - The valid value range is between 0 and 4194304 inclusive.
      - When creating a new profile, if this parameter is not specified, the default is provided
        by the parent profile.
    type: int
    version_added: "1.0.0"
  cache_timeout:
    description:
      - Specifies the timeout value in seconds of the SSL session cache entries.
      - Acceptable values are between 0 and 86400 inclusive.
      - When creating a new profile, if this parameter is not specified, the default is provided
        by the parent profile.
    type: int
    version_added: "1.0.0"
  state:
    description:
      - When C(present), ensures the profile exists.
      - When C(absent), ensures the profile is removed.
    type: str
    choices:
      - present
      - absent
    default: present
notes:
  - Requires BIG-IP software version >= 12
extends_documentation_fragment: f5networks.f5_modules.f5
author:
  - Tim Rupp (@caphrim007)
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Create client SSL profile
  bigip_profile_client_ssl:
    state: present
    name: my_profile
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost

- name: Create client SSL profile with specific ciphers
  bigip_profile_client_ssl:
    state: present
    name: my_profile
    ciphers: "!SSLv3:!SSLv2:ECDHE+AES-GCM+SHA256:ECDHE-RSA-AES128-CBC-SHA"
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost

- name: Create client SSL profile with specific cipher group
  bigip_profile_client_ssl:
    state: present
    name: my_profile
    ciphers: "none"
    cipher_group: "/Common/f5-secure"
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost

- name: Create client SSL profile with specific SSL options
  bigip_profile_client_ssl:
    state: present
    name: my_profile
    options:
      - no-sslv2
      - no-sslv3
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost

- name: Create client SSL profile require secure renegotiation
  bigip_profile_client_ssl:
    state: present
    name: my_profile
    secure_renegotiation: request
    provider:
      server: lb.mydomain.com
      user: admin
      password: secret
  delegate_to: localhost

- name: Create a client SSL profile with a cert/key/chain setting
  bigip_profile_client_ssl:
    state: present
    name: my_profile
    cert_key_chain:
      - cert: bigip_ssl_cert1
        key: bigip_ssl_key1
        chain: bigip_ssl_cert1
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
options:
  description: The list of options for SSL processing.
  returned: changed
  type: list
  sample: ['no-sslv2', 'no-sslv3']
secure_renegotiation:
  description: The method of secure SSL renegotiation.
  returned: changed
  type: str
  sample: request
allow_non_ssl:
  description: Acceptance of non-SSL connections.
  returned: changed
  type: bool
  sample: true
strict_resume:
  description: Resumption of SSL sessions after an unclean shutdown.
  returned: changed
  type: bool
  sample: true
renegotiation:
  description: Renegotiation of SSL sessions.
  returned: changed
  type: bool
  sample: true
cache_size:
  description: Specifies the number of sessions in the SSL session cache.
  returned: changed
  type: int
  sample: 2000
cache_timeout:
  description: Specifies the timeout value in seconds of the SSL session cache entries.
  returned: changed
  type: int
  sample: 1800
'''

import os
from datetime import datetime

from ansible.module_utils.basic import (
    AnsibleModule, env_fallback
)
from ansible.module_utils.six import iteritems

from ..module_utils.bigip import F5RestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, transform_name, f5_argument_spec, flatten_boolean, fq_name, is_empty_list
)
from ..module_utils.icontrol import tmos_version
from ..module_utils.teem import send_teem


class Parameters(AnsibleF5Parameters):
    api_map = {
        'certKeyChain': 'cert_key_chain',
        'cipherGroup': 'cipher_group',
        'defaultsFrom': 'parent',
        'allowNonSsl': 'allow_non_ssl',
        'secureRenegotiation': 'secure_renegotiation',
        'tmOptions': 'options',
        'sniDefault': 'sni_default',
        'sniRequire': 'sni_require',
        'serverName': 'server_name',
        'peerCertMode': 'client_certificate',
        'authenticate': 'client_auth_frequency',
        'retainCertificate': 'retain_certificate',
        'authenticateDepth': 'cert_auth_depth',
        'caFile': 'trusted_cert_authority',
        'clientCertCa': 'advertised_cert_authority',
        'crlFile': 'client_auth_crl',
        'allowExpiredCrl': 'allow_expired_crl',
        'strictResume': 'strict_resume',
        'cacheSize': 'cache_size',
        'cacheTimeout': 'cache_timeout',
    }

    api_attributes = [
        'ciphers',
        'cipherGroup',
        'certKeyChain',
        'defaultsFrom',
        'tmOptions',
        'secureRenegotiation',
        'allowNonSsl',
        'sniDefault',
        'sniRequire',
        'serverName',
        'peerCertMode',
        'authenticate',
        'retainCertificate',
        'authenticateDepth',
        'caFile',
        'clientCertCa',
        'crlFile',
        'allowExpiredCrl',
        'strictResume',
        'renegotiation',
        'cacheSize',
        'cacheTimeout',
    ]

    returnables = [
        'ciphers',
        'cipher_group',
        'allow_non_ssl',
        'options',
        'secure_renegotiation',
        'cert_key_chain',
        'parent',
        'sni_default',
        'sni_require',
        'server_name',
        'client_certificate',
        'client_auth_frequency',
        'retain_certificate',
        'cert_auth_depth',
        'trusted_cert_authority',
        'advertised_cert_authority',
        'client_auth_crl',
        'allow_expired_crl',
        'strict_resume',
        'renegotiation',
        'cache_size',
        'cache_timeout',
    ]

    updatables = [
        'parent',
        'ciphers',
        'cipher_group',
        'cert_key_chain',
        'allow_non_ssl',
        'options',
        'secure_renegotiation',
        'sni_default',
        'sni_require',
        'server_name',
        'client_certificate',
        'client_auth_frequency',
        'retain_certificate',
        'cert_auth_depth',
        'trusted_cert_authority',
        'advertised_cert_authority',
        'client_auth_crl',
        'allow_expired_crl',
        'strict_resume',
        'renegotiation',
        'cache_size',
        'cache_timeout',
    ]

    @property
    def retain_certificate(self):
        return flatten_boolean(self._values['retain_certificate'])

    @property
    def allow_expired_crl(self):
        return flatten_boolean(self._values['allow_expired_crl'])


class ModuleParameters(Parameters):
    def _key_filename(self, name, true_name):
        if true_name:
            return name
        if name.endswith('.key'):
            return name
        else:
            return name + '.key'

    def _cert_filename(self, name, true_name):
        if true_name:
            return name
        if name.endswith('.crt'):
            return name
        else:
            return name + '.crt'

    def _get_chain_value(self, item, true_name):
        if 'chain' not in item or item['chain'] in ('none', None, 'None'):
            result = 'none'
        else:
            result = self._cert_filename(fq_name(self.partition, item['chain']), true_name)
        return result

    def _get_true_names(self, item):
        if 'true_names' not in item:
            return False
        result = flatten_boolean(item['true_names'])
        if result == 'yes':
            return True
        if result == 'no':
            return False

    @property
    def parent(self):
        if self._values['parent'] is None:
            return None
        if self._values['parent'] == 'clientssl':
            return '/Common/clientssl'
        result = fq_name(self.partition, self._values['parent'])
        return result

    @property
    def cert_key_chain(self):
        if self._values['cert_key_chain'] is None:
            return None
        result = []
        for item in self._values['cert_key_chain']:
            if 'key' in item and 'cert' not in item:
                raise F5ModuleError(
                    "When providing a 'key', you must also provide a 'cert'"
                )
            if 'cert' in item and 'key' not in item:
                raise F5ModuleError(
                    "When providing a 'cert', you must also provide a 'key'"
                )
            item['true_names'] = self._get_true_names(item)
            key = self._key_filename(item['key'], item['true_names'])
            cert = self._cert_filename(item['cert'], item['true_names'])
            chain = self._get_chain_value(item, item['true_names'])
            name = os.path.basename(cert)
            filename, ex = os.path.splitext(name)
            tmp = {
                'name': filename,
                'cert': fq_name(self.partition, cert),
                'key': fq_name(self.partition, key),
                'chain': chain
            }
            if 'passphrase' in item and item['passphrase'] not in ('None', None, 'none'):
                tmp['passphrase'] = item['passphrase']
            result.append(tmp)
        result = sorted(result, key=lambda x: x['name'])
        return result

    @property
    def allow_non_ssl(self):
        result = flatten_boolean(self._values['allow_non_ssl'])
        if result is None:
            return None
        if result == 'yes':
            return 'enabled'
        return 'disabled'

    @property
    def strict_resume(self):
        result = flatten_boolean(self._values['strict_resume'])
        if result is None:
            return None
        if result == 'yes':
            return 'enabled'
        return 'disabled'

    @property
    def renegotiation(self):
        result = flatten_boolean(self._values['renegotiation'])
        if result is None:
            return None
        if result == 'yes':
            return 'enabled'
        return 'disabled'

    @property
    def options(self):
        options = self._values['options']
        if options is None:
            return None
        if is_empty_list(options):
            return []
        return options

    @property
    def sni_require(self):
        require = flatten_boolean(self._values['sni_require'])
        default = self.sni_default
        if require is None:
            return None
        if default in [None, False]:
            if require == 'yes':
                raise F5ModuleError(
                    "Cannot set 'sni_require' to {0} if 'sni_default' is set as {1}".format(require, default))
        if require == 'yes':
            return True
        else:
            return False

    @property
    def trusted_cert_authority(self):
        if self._values['trusted_cert_authority'] is None:
            return None
        if self._values['trusted_cert_authority'] in ['', 'none']:
            return ''
        result = fq_name(self.partition, self._values['trusted_cert_authority'])
        return result

    @property
    def advertised_cert_authority(self):
        if self._values['advertised_cert_authority'] is None:
            return None
        if self._values['advertised_cert_authority'] in ['', 'none']:
            return ''
        result = fq_name(self.partition, self._values['advertised_cert_authority'])
        return result

    @property
    def client_auth_crl(self):
        if self._values['client_auth_crl'] is None:
            return None
        if self._values['client_auth_crl'] in ['', 'none']:
            return ''
        result = fq_name(self.partition, self._values['client_auth_crl'])
        return result

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


class ApiParameters(Parameters):
    @property
    def cert_key_chain(self):
        if self._values['cert_key_chain'] is None:
            return None
        result = []
        for item in self._values['cert_key_chain']:
            tmp = dict(
                name=item['name'],
            )
            for x in ['cert', 'key', 'chain', 'passphrase', 'true_names']:
                if x in item:
                    tmp[x] = item[x]
                if 'chain' not in item:
                    tmp['chain'] = 'none'
            result.append(tmp)
        result = sorted(result, key=lambda y: y['name'])
        return result

    @property
    def sni_default(self):
        result = self._values['sni_default']
        if result is None:
            return None
        if result == 'true':
            return True
        else:
            return False

    @property
    def sni_require(self):
        result = self._values['sni_require']
        if result is None:
            return None
        if result == 'true':
            return True
        else:
            return False

    @property
    def trusted_cert_authority(self):
        if self._values['trusted_cert_authority'] in [None, 'none']:
            return None
        return self._values['trusted_cert_authority']

    @property
    def advertised_cert_authority(self):
        if self._values['advertised_cert_authority'] in [None, 'none']:
            return None
        return self._values['advertised_cert_authority']

    @property
    def client_auth_crl(self):
        if self._values['client_auth_crl'] in [None, 'none']:
            return None
        return self._values['client_auth_crl']

    @property
    def cache_size(self):
        if self._values['cache_size'] is None:
            return None
        if 0 <= self._values['cache_size'] <= 4194304:
            return self._values['cache_size']
        raise F5ModuleError(
            "Valid 'cache_size' must be in range 0 - 4194304 sessions."
        )

    @property
    def cache_timeout(self):
        if self._values['cache_timeout'] is None:
            return None
        if 0 <= self._values['cache_timeout'] <= 4194304:
            return self._values['cache_timeout']
        raise F5ModuleError(
            "Valid 'cache_timeout' must be in range 0 - 86400 seconds."
        )


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
    def retain_certificate(self):
        if self._values['retain_certificate'] is None:
            return None
        elif self._values['retain_certificate'] == 'yes':
            return 'true'
        return 'false'

    @property
    def allow_expired_crl(self):
        if self._values['allow_expired_crl'] is None:
            return None
        elif self._values['allow_expired_crl'] == 'yes':
            return 'enabled'
        return 'disabled'


class ReportableChanges(Changes):
    @property
    def allow_non_ssl(self):
        if self._values['allow_non_ssl'] is None:
            return None
        elif self._values['allow_non_ssl'] == 'enabled':
            return 'yes'
        return 'no'

    @property
    def strict_resume(self):
        if self._values['strict_resume'] is None:
            return None
        elif self._values['strict_resume'] == 'enabled':
            return 'yes'
        return 'no'

    @property
    def retain_certificate(self):
        return flatten_boolean(self._values['retain_certificate'])

    @property
    def allow_expired_crl(self):
        return flatten_boolean(self._values['allow_expired_crl'])


class Difference(object):
    def __init__(self, want, have=None):
        self.want = want
        self.have = have

    def compare(self, param):
        try:
            result = getattr(self, param)
            return result
        except AttributeError:
            result = self.__default(param)
            return result

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
        w = self.to_tuple(want)
        h = self.to_tuple(have)
        if set(w).issubset(set(h)):
            return None
        else:
            return want

    @property
    def cert_key_chain(self):
        result = self._diff_complex_items(self.want.cert_key_chain, self.have.cert_key_chain)
        return result

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

    @property
    def sni_require(self):
        if self.want.sni_require is None:
            return None
        if self.want.sni_require is False:
            if self.have.sni_default is True and self.want.sni_default is None:
                raise F5ModuleError(
                    "Cannot set 'sni_require' to {0} if 'sni_default' is {1}".format(
                        self.want.sni_require, self.have.sni_default)
                )
        if self.want.sni_require == self.have.sni_require:
            return None
        return self.want.sni_require

    @property
    def trusted_cert_authority(self):
        if self.want.trusted_cert_authority is None:
            return None
        if self.want.trusted_cert_authority == '' and self.have.trusted_cert_authority is None:
            return None
        if self.want.trusted_cert_authority != self.have.trusted_cert_authority:
            return self.want.trusted_cert_authority

    @property
    def advertised_cert_authority(self):
        if self.want.advertised_cert_authority is None:
            return None
        if self.want.advertised_cert_authority == '' and self.have.advertised_cert_authority is None:
            return None
        if self.want.advertised_cert_authority != self.have.advertised_cert_authority:
            return self.want.advertised_cert_authority

    @property
    def client_auth_crl(self):
        if self.want.client_auth_crl is None:
            return None
        if self.want.client_auth_crl == '' and self.have.client_auth_crl is None:
            return None
        if self.want.client_auth_crl != self.have.client_auth_crl:
            return self.want.client_auth_crl

    @property
    def ciphers(self):
        if self.want.ciphers is None:
            return None
        if self.want.ciphers == 'none' and self.have.ciphers == 'none':
            return None
        if self.want.ciphers != self.have.ciphers:
            return self.want.ciphers

    @property
    def cipher_group(self):
        if self.want.cipher_group is None:
            return None
        if self.want.cipher_group == 'none' and self.have.cipher_group == 'none':
            return None
        if self.want.cipher_group != self.have.cipher_group:
            return self.want.cipher_group


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
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/client-ssl/{2}".format(
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
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/client-ssl/".format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )
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
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/client-ssl/{2}".format(
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
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/client-ssl/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            transform_name(self.want.partition, self.want.name)
        )
        response = self.client.api.delete(uri)
        if response.status == 200:
            return True
        raise F5ModuleError(response.content)

    def read_current_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/client-ssl/{2}".format(
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
            parent=dict(),
            ciphers=dict(),
            cipher_group=dict(),
            allow_non_ssl=dict(type='bool'),
            secure_renegotiation=dict(
                choices=['require', 'require-strict', 'request']
            ),
            options=dict(
                type='list',
                elements='str',
                choices=[
                    'netscape-reuse-cipher-change-bug',
                    'microsoft-big-sslv3-buffer',
                    'msie-sslv2-rsa-padding',
                    'ssleay-080-client-dh-bug',
                    'tls-d5-bug',
                    'tls-block-padding-bug',
                    'dont-insert-empty-fragments',
                    'no-ssl',
                    'no-dtls',
                    'no-session-resumption-on-renegotiation',
                    'no-tlsv1.1',
                    'no-tlsv1.2',
                    'no-tlsv1.3',
                    'single-dh-use',
                    'ephemeral-rsa',
                    'cipher-server-preference',
                    'tls-rollback-bug',
                    'no-sslv2',
                    'no-sslv3',
                    'no-tls',
                    'no-tlsv1',
                    'pkcs1-check-1',
                    'pkcs1-check-2',
                    'netscape-ca-dn-bug',
                    'netscape-demo-cipher-change-bug',
                    'none',
                ]
            ),
            cert_key_chain=dict(
                type='list',
                elements='dict',
                no_log=True,
                options=dict(
                    cert=dict(required=True),
                    key=dict(required=True, no_log=True),
                    chain=dict(),
                    passphrase=dict(no_log=True),
                    true_names=dict(
                        type='bool',
                        default='no'
                    ),
                )
            ),
            state=dict(
                default='present',
                choices=['present', 'absent']
            ),
            sni_default=dict(type='bool'),
            sni_require=dict(type='bool'),
            server_name=dict(),
            client_certificate=dict(
                choices=['require', 'ignore', 'request']
            ),
            client_auth_frequency=dict(
                choices=['once', 'always']
            ),
            cert_auth_depth=dict(type='int'),
            retain_certificate=dict(type='bool'),
            trusted_cert_authority=dict(),
            advertised_cert_authority=dict(),
            client_auth_crl=dict(),
            allow_expired_crl=dict(type='bool'),
            strict_resume=dict(type='bool'),
            renegotiation=dict(type='bool'),
            cache_size=dict(type='int'),
            cache_timeout=dict(type='int'),
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
