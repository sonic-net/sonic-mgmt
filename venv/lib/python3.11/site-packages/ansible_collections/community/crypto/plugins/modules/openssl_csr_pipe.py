#!/usr/bin/python
# Copyright (c) 2017, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = r"""
module: openssl_csr_pipe
short_description: Generate OpenSSL Certificate Signing Request (CSR)
version_added: 1.3.0
description:
  - Please note that the module regenerates an existing CSR if it does not match the module's options, or if it seems to be
    corrupt.
author:
  - Yanis Guenane (@Spredzy)
  - Felix Fontein (@felixfontein)
extends_documentation_fragment:
  - community.crypto._attributes
  - community.crypto._module_csr
attributes:
  check_mode:
    support: full
    details:
      - Since community.crypto 3.0.0, the module ignores check mode and always behaves as if check mode is not active.
options:
  content:
    description:
      - The existing CSR.
    type: str
  privatekey_path:
    description:
      - The path to the private key to use when signing the certificate signing request.
      - Either O(privatekey_path) or O(privatekey_content) must be specified, but not both.
  privatekey_content:
    description:
      - The content of the private key to use when signing the certificate signing request.
      - Either O(privatekey_path) or O(privatekey_content) must be specified, but not both.
seealso:
  - module: community.crypto.openssl_csr
"""

EXAMPLES = r"""
---
- name: Generate an OpenSSL Certificate Signing Request
  community.crypto.openssl_csr_pipe:
    privatekey_path: /etc/ssl/private/ansible.com.pem
    common_name: www.ansible.com
  register: result
- name: Print CSR
  ansible.builtin.debug:
    var: result.csr

- name: Generate an OpenSSL Certificate Signing Request with an inline CSR
  community.crypto.openssl_csr:
    content: "{{ lookup('ansible.builtin.file', '/etc/ssl/csr/www.ansible.com.csr') }}"
    privatekey_content: "{{ private_key_content }}"
    common_name: www.ansible.com
  register: result
- name: Store CSR
  ansible.builtin.copy:
    dest: /etc/ssl/csr/www.ansible.com.csr
    content: "{{ result.csr }}"
  when: result is changed
"""

RETURN = r"""
privatekey:
  description:
    - Path to the TLS/SSL private key the CSR was generated for.
    - Will be V(none) if the private key has been provided in O(privatekey_content).
  returned: changed or success
  type: str
  sample: /etc/ssl/private/ansible.com.pem
subject:
  description: A list of the subject tuples attached to the CSR.
  returned: changed or success
  type: list
  elements: list
  sample: [['CN', 'www.ansible.com'], ['O', 'Ansible']]
subjectAltName:
  description: The alternative names this CSR is valid for.
  returned: changed or success
  type: list
  elements: str
  sample: ['DNS:www.ansible.com', 'DNS:m.ansible.com']
keyUsage:
  description: Purpose for which the public key may be used.
  returned: changed or success
  type: list
  elements: str
  sample: ['digitalSignature', 'keyAgreement']
extendedKeyUsage:
  description: Additional restriction on the public key purposes.
  returned: changed or success
  type: list
  elements: str
  sample: ['clientAuth']
basicConstraints:
  description: Indicates if the certificate belongs to a CA.
  returned: changed or success
  type: list
  elements: str
  sample: ['CA:TRUE', 'pathLenConstraint:0']
ocsp_must_staple:
  description: Indicates whether the certificate has the OCSP Must Staple feature enabled.
  returned: changed or success
  type: bool
  sample: false
name_constraints_permitted:
  description: List of permitted subtrees to sign certificates for.
  returned: changed or success
  type: list
  elements: str
  sample: ['email:.somedomain.com']
name_constraints_excluded:
  description: List of excluded subtrees the CA cannot sign certificates for.
  returned: changed or success
  type: list
  elements: str
  sample: ['email:.com']
csr:
  description: The (current or generated) CSR's content.
  returned: changed or success
  type: str
"""

import typing as t

from ansible_collections.community.crypto.plugins.module_utils._crypto.basic import (
    OpenSSLObjectError,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.module_backends.csr import (
    get_csr_argument_spec,
    select_backend,
)


if t.TYPE_CHECKING:
    from ansible.module_utils.basic import AnsibleModule  # pragma: no cover

    from ansible_collections.community.crypto.plugins.module_utils._crypto.module_backends.csr import (  # pragma: no cover
        CertificateSigningRequestBackend,
    )


class CertificateSigningRequestModule:
    def __init__(
        self, module: AnsibleModule, module_backend: CertificateSigningRequestBackend
    ) -> None:
        self.check_mode = module.check_mode
        self.module = module
        self.module_backend = module_backend
        self.changed = False
        if module.params["content"] is not None:
            self.module_backend.set_existing(
                csr_bytes=module.params["content"].encode("utf-8")
            )

    def generate(self, module: AnsibleModule) -> None:
        """Generate the certificate signing request."""
        if self.module_backend.needs_regeneration():
            self.module_backend.generate_csr()
            self.changed = True

    def dump(self) -> dict[str, t.Any]:
        """Serialize the object into a dictionary."""
        result = self.module_backend.dump(include_csr=True)
        result.update(
            {
                "changed": self.changed,
            }
        )
        return result


def main() -> t.NoReturn:
    argument_spec = get_csr_argument_spec()
    argument_spec.argument_spec.update(
        {
            "content": {"type": "str"},
        }
    )
    module = argument_spec.create_ansible_module(
        supports_check_mode=True,
    )

    try:
        module_backend = select_backend(module)

        csr = CertificateSigningRequestModule(module, module_backend)
        csr.generate(module)
        result = csr.dump()
        module.exit_json(**result)
    except OpenSSLObjectError as exc:
        module.fail_json(msg=str(exc))


if __name__ == "__main__":
    main()
