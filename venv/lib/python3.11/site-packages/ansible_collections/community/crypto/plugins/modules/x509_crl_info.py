#!/usr/bin/python
# Copyright (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = r"""
module: x509_crl_info
version_added: '1.0.0'
short_description: Retrieve information on Certificate Revocation Lists (CRLs)
description:
  - This module allows one to retrieve information on Certificate Revocation Lists (CRLs).
author:
  - Felix Fontein (@felixfontein)
extends_documentation_fragment:
  - community.crypto._attributes
  - community.crypto._attributes.info_module
  - community.crypto._attributes.idempotent_not_modify_state
  - community.crypto._cryptography_dep.minimum
  - community.crypto._name_encoding
options:
  path:
    description:
      - Remote absolute path where the generated CRL file should be created or is already located.
      - Either O(path) or O(content) must be specified, but not both.
    type: path
  content:
    description:
      - Content of the X.509 CRL in PEM format, or Base64-encoded X.509 CRL.
      - Either O(path) or O(content) must be specified, but not both.
    type: str
  list_revoked_certificates:
    description:
      - If set to V(false), the list of revoked certificates is not included in the result.
      - This is useful when retrieving information on large CRL files. Enumerating all revoked certificates can take some
        time, including serializing the result as JSON, sending it to the Ansible controller, and decoding it again.
    type: bool
    default: true
    version_added: 1.7.0

notes:
  - All timestamp values are provided in ASN.1 TIME format, in other words, following the C(YYYYMMDDHHMMSSZ) pattern. They
    are all in UTC.
seealso:
  - module: community.crypto.x509_crl
  - plugin: community.crypto.x509_crl_info
    plugin_type: filter
    description: A filter variant of this module.
  - plugin: community.crypto.to_serial
    plugin_type: filter
"""

EXAMPLES = r"""
---
- name: Get information on CRL
  community.crypto.x509_crl_info:
    path: /etc/ssl/my-ca.crl
  register: result

- name: Print the information
  ansible.builtin.debug:
    msg: "{{ result }}"

- name: Get information on CRL without list of revoked certificates
  community.crypto.x509_crl_info:
    path: /etc/ssl/very-large.crl
    list_revoked_certificates: false
  register: result
"""

RETURN = r"""
format:
  description:
    - Whether the CRL is in PEM format (V(pem)) or in DER format (V(der)).
  returned: success
  type: str
  sample: pem
  choices:
    - pem
    - der
issuer:
  description:
    - The CRL's issuer.
    - Note that for repeated values, only the last one will be returned.
    - See O(name_encoding) for how IDNs are handled.
  returned: success
  type: dict
  sample: {"organizationName": "Ansible", "commonName": "ca.example.com"}
issuer_ordered:
  description: The CRL's issuer as an ordered list of tuples.
  returned: success
  type: list
  elements: list
  sample: [["organizationName", "Ansible"], ["commonName": "ca.example.com"]]
last_update:
  description: The point in time from which this CRL can be trusted as ASN.1 TIME.
  returned: success
  type: str
  sample: '20190413202428Z'
next_update:
  description:
    - The point in time from which a new CRL will be issued and the client has to check for it as ASN.1 TIME.
    - Will be C(none) if no such timestamp is present.
  returned: success
  type: str
  sample: '20190413202428Z'
digest:
  description: The signature algorithm used to sign the CRL.
  returned: success
  type: str
  sample: sha256WithRSAEncryption
revoked_certificates:
  description: List of certificates to be revoked.
  returned: success if O(list_revoked_certificates=true)
  type: list
  elements: dict
  contains:
    serial_number:
      description:
        - Serial number of the certificate.
        - This return value is an B(integer). If you need the serial numbers as a colon-separated hex string, such as C(11:22:33),
          you need to convert it to that form with P(community.crypto.to_serial#filter).
      type: int
      sample: 1234
    revocation_date:
      description: The point in time the certificate was revoked as ASN.1 TIME.
      type: str
      sample: '20190413202428Z'
    issuer:
      description:
        - The certificate's issuer.
        - See O(name_encoding) for how IDNs are handled.
      type: list
      elements: str
      sample: ["DNS:ca.example.org"]
    issuer_critical:
      description: Whether the certificate issuer extension is critical.
      type: bool
      sample: false
    reason:
      description:
        - The value for the revocation reason extension.
      type: str
      sample: key_compromise
      choices:
        - unspecified
        - key_compromise
        - ca_compromise
        - affiliation_changed
        - superseded
        - cessation_of_operation
        - certificate_hold
        - privilege_withdrawn
        - aa_compromise
        - remove_from_crl
    reason_critical:
      description: Whether the revocation reason extension is critical.
      type: bool
      sample: false
    invalidity_date:
      description: |-
        The point in time it was known/suspected that the private key was compromised
        or that the certificate otherwise became invalid as ASN.1 TIME.
      type: str
      sample: '20190413202428Z'
    invalidity_date_critical:
      description: Whether the invalidity date extension is critical.
      type: bool
      sample: false
"""


import base64
import binascii
import typing as t

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.crypto.plugins.module_utils._crypto.basic import (
    OpenSSLObjectError,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.module_backends.crl_info import (
    get_crl_info,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.pem import (
    identify_pem_format,
)


def main() -> t.NoReturn:
    module = AnsibleModule(
        argument_spec={
            "path": {"type": "path"},
            "content": {"type": "str"},
            "list_revoked_certificates": {"type": "bool", "default": True},
            "name_encoding": {
                "type": "str",
                "default": "ignore",
                "choices": ["ignore", "idna", "unicode"],
            },
        },
        required_one_of=(["path", "content"],),
        mutually_exclusive=(["path", "content"],),
        supports_check_mode=True,
    )

    content: str | None = module.params["content"]
    path: str | None = module.params["path"]
    if content is None:
        if path is None:
            module.fail_json(msg="One of content and path must be provided")
        try:
            with open(path, "rb") as f:
                data = f.read()
        except (IOError, OSError) as e:
            module.fail_json(msg=f"Error while reading CRL file from disk: {e}")
    else:
        data = content.encode("utf-8")
        if not identify_pem_format(data):
            try:
                data = base64.b64decode(content)
            except (binascii.Error, TypeError) as e:
                module.fail_json(msg=f"Error while Base64 decoding content: {e}")

    list_revoked_certificates: bool = module.params["list_revoked_certificates"]
    try:
        result = get_crl_info(
            module=module,
            content=data,
            list_revoked_certificates=list_revoked_certificates,
        )
        module.exit_json(**result)
    except OpenSSLObjectError as e:
        module.fail_json(msg=str(e))


if __name__ == "__main__":
    main()
