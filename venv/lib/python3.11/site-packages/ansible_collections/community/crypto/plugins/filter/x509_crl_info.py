# Copyright (c) 2022, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = r"""
name: x509_crl_info
short_description: Retrieve information from X.509 CRLs in PEM format
version_added: 2.10.0
author:
  - Felix Fontein (@felixfontein)
description:
  - Provided a X.509 crl in PEM format, retrieve information.
  - This is a filter version of the M(community.crypto.x509_crl_info) module.
options:
  _input:
    description:
      - The content of the X.509 CRL in PEM format.
    type: string
    required: true
  list_revoked_certificates:
    description:
      - If set to V(false), the list of revoked certificates is not included in the result.
      - This is useful when retrieving information on large CRL files. Enumerating all revoked certificates can take some
        time, including serializing the result as JSON, sending it to the Ansible controller, and decoding it again.
    type: bool
    default: true
    version_added: 1.7.0
extends_documentation_fragment:
  - community.crypto._name_encoding
seealso:
  - module: community.crypto.x509_crl_info
  - plugin: community.crypto.to_serial
    plugin_type: filter
"""

EXAMPLES = r"""
---
- name: Show the Organization Name of the CRL's subject
  ansible.builtin.debug:
    msg: >-
      {{
        (
          lookup('ansible.builtin.file', '/path/to/cert.pem')
          | community.crypto.x509_crl_info
        ).issuer.organizationName
      }}
"""

RETURN = r"""
_value:
  description:
    - Information on the CRL.
  type: dict
  contains:
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
      description: The point in time from which a new CRL will be issued and the client has to check for it as ASN.1 TIME.
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
            - This return value is an B(integer). If you need the serial numbers as a colon-separated hex string, such as
              C(11:22:33), you need to convert it to that form with P(community.crypto.to_serial#filter).
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
from collections.abc import Callable

from ansible.errors import AnsibleFilterError
from ansible.module_utils.common.text.converters import to_bytes, to_text

from ansible_collections.community.crypto.plugins.module_utils._crypto.basic import (
    OpenSSLObjectError,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.module_backends.crl_info import (
    get_crl_info,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.pem import (
    identify_pem_format,
)
from ansible_collections.community.crypto.plugins.plugin_utils._filter_module import (
    FilterModuleMock,
)


def x509_crl_info_filter(
    data: str | bytes,
    name_encoding: t.Literal["ignore", "idna", "unicode"] = "ignore",
    list_revoked_certificates: bool = True,
) -> dict[str, t.Any]:
    """Extract information from X.509 PEM certificate."""
    if not isinstance(data, (str, bytes)):
        raise AnsibleFilterError(
            f"The community.crypto.x509_crl_info input must be a text type, not {type(data)}"
        )
    if not isinstance(name_encoding, (str, bytes)):
        raise AnsibleFilterError(
            f"The name_encoding option must be of a text type, not {type(name_encoding)}"
        )
    if not isinstance(list_revoked_certificates, bool):
        raise AnsibleFilterError(
            f"The list_revoked_certificates option must be a boolean, not {type(list_revoked_certificates)}"
        )
    name_encoding = t.cast(
        t.Literal["ignore", "idna", "unicode"], to_text(name_encoding)
    )
    if name_encoding not in ("ignore", "idna", "unicode"):
        raise AnsibleFilterError(
            f'The name_encoding option must be one of the values "ignore", "idna", or "unicode", not "{name_encoding}"'
        )

    data_bytes = to_bytes(data)
    if not identify_pem_format(data_bytes):
        try:
            data_bytes = base64.b64decode(to_text(data_bytes))
        except (binascii.Error, TypeError, ValueError, UnicodeEncodeError):
            pass

    module = FilterModuleMock({"name_encoding": name_encoding})
    try:
        return get_crl_info(
            module=module,
            content=data_bytes,
            list_revoked_certificates=list_revoked_certificates,
        )
    except OpenSSLObjectError as exc:
        raise AnsibleFilterError(str(exc)) from exc


class FilterModule:
    """Ansible jinja2 filters"""

    def filters(self) -> dict[str, Callable]:
        return {
            "x509_crl_info": x509_crl_info_filter,
        }
