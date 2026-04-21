#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Ansible module to manage CheckPoint Firewall (c) 2019
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: cp_mgmt_opsec_trusted_ca
short_description: Manages opsec-trusted-ca objects on Checkpoint over Web Services API
description:
  - Manages opsec-trusted-ca objects on Checkpoint devices including creating, updating and removing objects.
  - All operations are performed over Web Services API.
  - Available from R82 management version.
version_added: "6.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  name:
    description:
      - Object name.
    type: str
    required: True
  base64_certificate:
    description:
      - Certificate file encoded in base64.
    type: str
  automatic_enrollment:
    description:
      - Certificate automatic enrollment.
    type: dict
    suboptions:
      automatically_enroll_certificate:
        description:
          - Whether to automatically enroll certificate.
        type: bool
      protocol:
        description:
          - Protocol that communicates with the certificate authority. Available only if "automatically-enroll-certificate" parameter is set to true.
        type: str
        choices: ['scep', 'cmpv2', 'cmpv1']
      scep_settings:
        description:
          - Scep protocol settings. Available only if "protocol" is set to "scep".
        type: dict
        suboptions:
          ca_identifier:
            description:
              - Certificate authority identifier.
            type: str
          url:
            description:
              - Certificate authority URL.
            type: str
      cmpv1_settings:
        description:
          - Cmpv1 protocol settings. Available only if "protocol" is set to "cmpv1".
        type: dict
        suboptions:
          direct_tcp_settings:
            description:
              - Direct tcp transport layer settings.
            type: dict
            suboptions:
              ip_address:
                description:
                  - Certificate authority IP address.
                type: str
              port:
                description:
                  - Port number.
                type: int
      cmpv2_settings:
        description:
          - Cmpv2 protocol settings. Available only if "protocol" is set to "cmpv1".
        type: dict
        suboptions:
          transport_layer:
            description:
              - Transport layer.
            type: str
            choices: ['http', 'direct-tcp']
          direct_tcp_settings:
            description:
              - Direct tcp transport layer settings.
            type: dict
            suboptions:
              ip_address:
                description:
                  - Certificate authority IP address.
                type: str
              port:
                description:
                  - Port number.
                type: int
          http_settings:
            description:
              - Http transport layer settings.
            type: dict
            suboptions:
              url:
                description:
                  - Certificate authority URL.
                type: str
  retrieve_crl_from_http_servers:
    description:
      - Whether to retrieve Certificate Revocation List from http servers.
    type: bool
  retrieve_crl_from_ldap_servers:
    description:
      - Whether to retrieve Certificate Revocation List from ldap servers.
    type: bool
  cache_crl:
    description:
      - Cache Certificate Revocation List on the Security Gateway.
    type: bool
  crl_cache_method:
    description:
      - Weather to retrieve new Certificate Revocation List after the certificate expires or after a fixed period.
    type: str
    choices: ['timeout', 'expiration date']
  crl_cache_timeout:
    description:
      - When to fetch new Certificate Revocation List (in minutes).
    type: int
  allow_certificates_from_branches:
    description:
      - Allow only certificates from listed branches.
    type: bool
  branches:
    description:
      - Branches to allow certificates from. Required only if "allow-certificates-from-branches" set to "true".
    type: list
    elements: str
  tags:
    description:
      - Collection of tag identifiers.
    type: list
    elements: str
  color:
    description:
      - Color of the object. Should be one of existing colors.
    type: str
    choices: ['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green', 'khaki', 'orchid', 'dark orange', 'dark sea green',
             'pink', 'turquoise', 'dark blue', 'firebrick', 'brown', 'forest green', 'gold', 'dark gold', 'gray', 'dark gray', 'light green', 'lemon chiffon',
             'coral', 'sea green', 'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive', 'orange', 'red', 'sienna', 'yellow']
  comments:
    description:
      - Comments string.
    type: str
  details_level:
    description:
      - The level of detail for some of the fields in the response can vary from showing only the UID value of the object to a fully detailed
        representation of the object.
    type: str
    choices: ['uid', 'standard', 'full']
  domains_to_process:
    description:
      - Indicates which domains to process the commands on. It cannot be used with the details-level full, must be run from the System Domain only and
        with ignore-warnings true. Valid values are, CURRENT_DOMAIN, ALL_DOMAINS_ON_THIS_SERVER.
    type: list
    elements: str
  ignore_warnings:
    description:
      - Apply changes ignoring warnings.
    type: bool
  ignore_errors:
    description:
      - Apply changes ignoring errors. You won't be able to publish such a changes. If ignore-warnings flag was omitted - warnings will also be ignored.
    type: bool
extends_documentation_fragment: check_point.mgmt.checkpoint_objects
"""

EXAMPLES = """
- name: add-opsec-trusted-ca
  cp_mgmt_opsec_trusted_ca:
    base64_certificate:
      "MIICwjCCAaqgAwIBAgIILdexblpVEMIwDQYJKoZIhvcNAQELBQAwGDEWMBQGA1UEAxMNd3d3Lm9wc2VjLmNvbTAeFw0yMzA2MjUwOTE3MDBaFw0yNTAzMzExNjAwMDBaMBgxFjAUBgNVBAMTDXd3dy5vcH
       lYy5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCjpqCxDaVg+I1b+wqnmjjYtL3v7Tlu/YpMbsKnv+M1gRz6QFUOoSVnxKLo0A7Y4kCqa1OPcHO/LtXuok43F1YZPVKm3xWpY8FmqGqf5
       uGmSwm1HPObcMjwGOyFgwpwEDF5e0UMZ7xtJF8BZ5KKBh3ZfQ1FbmbVqSUPcmOi+NE4JspPlHxX+m6es/yeSGR1A2ezKY7KePTlwVtDe8hiLrYyKG92nka5rkD1QyEIVJ0W5wrnU4nGEDIHeOfT09zroQx
       NLkb51sl4Tog/qw+EraVGIBe/iFnSJoDF37i2mLJqI/t8bel+aGDAxgMx1pO85OClgjPSWL0UIXGI2xrR+JAgMBAAGjEDAOMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAHTs1AutAmSLHF2
       RLJtrRNkso0lMyA7XI7k1TNpTk7TCZLNY0VbUliGbcl+POH4EG8ARUrftnwRDCTBd2BdJTqG2CyNADi+bw8aLvbxok7KH0GlQvGjyfq+sHK12wTl4ULNyYoAPZ01GhXOvkobROdSyjxvBVhxdVo90kj7mH
       v3N83huNhfstDFUBcQCmMkbLuzDUZrl2a1OtqlOdNC6mNvb7Jq9W9vRxGA514e7jqyoM+PwHu5fILx/jmGT8suOUnvbtcDdFhjqixAPer6uSPR0CSbiJvuDy72DPH5mjZK5dQKewNYOZ/BQEsRIBe+Q6eG
       oJqi+cD63cwlw0DCc="
    name: opsec_ca
    state: present

- name: set-opsec-trusted-ca
  cp_mgmt_opsec_trusted_ca:
    name: opsec_ca
    automatic_enrollment:
      automatically_enroll_certificate: true
      protocol: "cmpv1"
      cmpv1_settings:
        direct_tcp_settings:
          ip_address: "1.1.1.1"
    state: present

- name: delete-opsec-trusted-ca
  cp_mgmt_opsec_trusted_ca:
    name: opsec_ca
    state: absent
"""

RETURN = """
cp_mgmt_opsec_trusted_ca:
  description: The checkpoint object created or updated.
  returned: always, except when deleting the object.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_objects, api_call


def main():
    argument_spec = dict(
        name=dict(type='str', required=True),
        base64_certificate=dict(type='str'),
        automatic_enrollment=dict(type='dict', options=dict(
            automatically_enroll_certificate=dict(type='bool'),
            protocol=dict(type='str', choices=['scep', 'cmpv2', 'cmpv1']),
            scep_settings=dict(type='dict', options=dict(
                ca_identifier=dict(type='str'),
                url=dict(type='str')
            )),
            cmpv1_settings=dict(type='dict', options=dict(
                direct_tcp_settings=dict(type='dict', options=dict(
                    ip_address=dict(type='str'),
                    port=dict(type='int')
                ))
            )),
            cmpv2_settings=dict(type='dict', options=dict(
                transport_layer=dict(type='str', choices=['http', 'direct-tcp']),
                direct_tcp_settings=dict(type='dict', options=dict(
                    ip_address=dict(type='str'),
                    port=dict(type='int')
                )),
                http_settings=dict(type='dict', options=dict(
                    url=dict(type='str')
                ))
            ))
        )),
        retrieve_crl_from_http_servers=dict(type='bool'),
        retrieve_crl_from_ldap_servers=dict(type='bool'),
        cache_crl=dict(type='bool'),
        crl_cache_method=dict(type='str', choices=['timeout', 'expiration date']),
        crl_cache_timeout=dict(type='int'),
        allow_certificates_from_branches=dict(type='bool'),
        branches=dict(type='list', elements='str'),
        tags=dict(type='list', elements='str'),
        color=dict(type='str', choices=['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green',
                                        'khaki', 'orchid', 'dark orange', 'dark sea green', 'pink', 'turquoise', 'dark blue', 'firebrick', 'brown',
                                        'forest green', 'gold', 'dark gold', 'gray', 'dark gray', 'light green', 'lemon chiffon', 'coral', 'sea green',
                                        'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive', 'orange', 'red', 'sienna',
                                        'yellow']),
        comments=dict(type='str'),
        details_level=dict(type='str', choices=['uid', 'standard', 'full']),
        domains_to_process=dict(type='list', elements='str'),
        ignore_warnings=dict(type='bool'),
        ignore_errors=dict(type='bool')
    )
    argument_spec.update(checkpoint_argument_spec_for_objects)

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    api_call_object = 'opsec-trusted-ca'

    result = api_call(module, api_call_object)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
