#!/usr/bin/python
# Copyright (c) 2016-2017, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright (c) 2017, Markus Teufelberger <mteufelberger+ansible@mgit.at>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = r"""
module: x509_certificate
short_description: Generate and/or check OpenSSL certificates
description:
  - It implements a notion of provider (one of V(selfsigned), V(ownca), and V(acme)) for your certificate.
  - Please note that the module regenerates existing certificate if it does not match the module's options, or if it seems
    to be corrupt. If you are concerned that this could overwrite your existing certificate, consider using the O(backup)
    option.
  - Note that this module was called C(openssl_certificate) when included directly in Ansible up to version 2.9. When moved
    to the collection C(community.crypto), it was renamed to M(community.crypto.x509_certificate). From Ansible 2.10 on, it
    can still be used by the old short name (or by C(ansible.builtin.openssl_certificate)), which redirects to M(community.crypto.x509_certificate).
    When using FQCNs or when using the L(collections,https://docs.ansible.com/ansible/latest/user_guide/collections_using.html#using-collections-in-a-playbook)
    keyword, the new name M(community.crypto.x509_certificate) should be used to avoid a deprecation warning.
author:
  - Yanis Guenane (@Spredzy)
  - Markus Teufelberger (@MarkusTeufelberger)
extends_documentation_fragment:
  - ansible.builtin.files
  - community.crypto._attributes
  - community.crypto._attributes.files
  - community.crypto._module_certificate
  - community.crypto._module_certificate.backend_acme_documentation
  - community.crypto._module_certificate.backend_ownca_documentation
  - community.crypto._module_certificate.backend_selfsigned_documentation
attributes:
  check_mode:
    support: full
  safe_file_operations:
    support: full
options:
  state:
    description:
      - Whether the certificate should exist or not, taking action if the state is different from what is stated.
    type: str
    default: present
    choices: [absent, present]

  path:
    description:
      - Remote absolute path where the generated certificate file should be created or is already located.
    type: path
    required: true

  provider:
    description:
      - Name of the provider to use to generate/retrieve the OpenSSL certificate. Please see the examples on how to emulate
        it with M(community.crypto.x509_certificate_info), M(community.crypto.openssl_csr_info), M(community.crypto.openssl_privatekey_info)
        and M(ansible.builtin.assert).
      - Required if O(state) is V(present).
      - The V(entrust) provider has been removed from community.crypto 3.0.0 due to sunsetting of the ECS API.
    type: str
    choices: [acme, ownca, selfsigned]

  return_content:
    description:
      - If set to V(true), will return the (current or generated) certificate's content as RV(certificate).
    type: bool
    default: false
    version_added: '1.0.0'

  backup:
    description:
      - Create a backup file including a timestamp so you can get the original certificate back if you overwrote it with a
        new one by accident.
    type: bool
    default: false

  csr_content:
    version_added: '1.0.0'
  privatekey_content:
    version_added: '1.0.0'
  acme_directory:
    version_added: '1.0.0'
  ownca_content:
    version_added: '1.0.0'
  ownca_privatekey_content:
    version_added: '1.0.0'

seealso:
  - module: community.crypto.x509_certificate_pipe
"""

EXAMPLES = r"""
---
- name: Generate a Self Signed OpenSSL certificate
  community.crypto.x509_certificate:
    path: /etc/ssl/crt/ansible.com.crt
    privatekey_path: /etc/ssl/private/ansible.com.pem
    csr_path: /etc/ssl/csr/ansible.com.csr
    provider: selfsigned

- name: Generate an OpenSSL certificate signed with your own CA certificate
  community.crypto.x509_certificate:
    path: /etc/ssl/crt/ansible.com.crt
    csr_path: /etc/ssl/csr/ansible.com.csr
    ownca_path: /etc/ssl/crt/ansible_CA.crt
    ownca_privatekey_path: /etc/ssl/private/ansible_CA.pem
    provider: ownca

- name: Generate a Let's Encrypt Certificate
  community.crypto.x509_certificate:
    path: /etc/ssl/crt/ansible.com.crt
    csr_path: /etc/ssl/csr/ansible.com.csr
    provider: acme
    acme_accountkey_path: /etc/ssl/private/ansible.com.pem
    acme_challenge_path: /etc/ssl/challenges/ansible.com/

- name: Force (re-)generate a new Let's Encrypt Certificate
  community.crypto.x509_certificate:
    path: /etc/ssl/crt/ansible.com.crt
    csr_path: /etc/ssl/csr/ansible.com.csr
    provider: acme
    acme_accountkey_path: /etc/ssl/private/ansible.com.pem
    acme_challenge_path: /etc/ssl/challenges/ansible.com/
    force: true

# The following example shows how to emulate the behavior of the removed
# "assertonly" provider with the x509_certificate_info, openssl_csr_info,
# openssl_privatekey_info and assert modules:

- name: Get certificate information
  community.crypto.x509_certificate_info:
    path: /etc/ssl/crt/ansible.com.crt
    # for valid_at, invalid_at and valid_in
    valid_at:
      one_day_ten_hours: "+1d10h"
      fixed_timestamp: 20200331202428Z
      ten_seconds: "+10"
  register: result

- name: Get CSR information
  community.crypto.openssl_csr_info:
    # Verifies that the CSR signature is valid; module will fail if not
    path: /etc/ssl/csr/ansible.com.csr
  register: result_csr

- name: Get private key information
  community.crypto.openssl_privatekey_info:
    path: /etc/ssl/csr/ansible.com.key
  register: result_privatekey

- name: Check conditions on certificate, CSR, and private key
  ansible.builtin.assert:
    that:
      # When private key was specified for assertonly, this was checked:
      - result.public_key == result_privatekey.public_key
      # When CSR was specified for assertonly, this was checked:
      - result.public_key == result_csr.public_key
      - result.subject_ordered == result_csr.subject_ordered
      - result.extensions_by_oid == result_csr.extensions_by_oid
      # signature_algorithms check
      - "result.signature_algorithm == 'sha256WithRSAEncryption' or result.signature_algorithm == 'sha512WithRSAEncryption'"
      # subject and subject_strict
      - "result.subject.commonName == 'ansible.com'"
      - "result.subject | length == 1" # the number must be the number of entries you check for
      # issuer and issuer_strict
      - "result.issuer.commonName == 'ansible.com'"
      - "result.issuer | length == 1" # the number must be the number of entries you check for
      # has_expired
      - not result.expired
      # version
      - result.version == 3
      # key_usage and key_usage_strict
      - "'Data Encipherment' in result.key_usage"
      - "result.key_usage | length == 1" # the number must be the number of entries you check for
      # extended_key_usage and extended_key_usage_strict
      - "'DVCS' in result.extended_key_usage"
      - "result.extended_key_usage | length == 1" # the number must be the number of entries you check for
      # subject_alt_name and subject_alt_name_strict
      - "'dns:ansible.com' in result.subject_alt_name"
      - "result.subject_alt_name | length == 1" # the number must be the number of entries you check for
      # not_before and not_after
      - "result.not_before == '20190331202428Z'"
      - "result.not_after == '20190413202428Z'"
      # valid_at, invalid_at and valid_in
      - "result.valid_at.one_day_ten_hours" # for valid_at
      - "not result.valid_at.fixed_timestamp" # for invalid_at
      - "result.valid_at.ten_seconds" # for valid_in
"""

RETURN = r"""
filename:
  description: Path to the generated certificate.
  returned: changed or success
  type: str
  sample: /etc/ssl/crt/www.ansible.com.crt
backup_file:
  description: Name of backup file created.
  returned: changed and if O(backup) is V(true)
  type: str
  sample: /path/to/www.ansible.com.crt.2019-03-09@11:22~
certificate:
  description: The (current or generated) certificate's content.
  returned: if O(state) is V(present) and O(return_content) is V(true)
  type: str
  version_added: '1.0.0'
"""


import os
import typing as t

from ansible_collections.community.crypto.plugins.module_utils._crypto.basic import (
    OpenSSLObjectError,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.module_backends.certificate import (
    get_certificate_argument_spec,
    select_backend,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.module_backends.certificate_acme import (
    AcmeCertificateProvider,
    add_acme_provider_to_argument_spec,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.module_backends.certificate_ownca import (
    OwnCACertificateProvider,
    add_ownca_provider_to_argument_spec,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.module_backends.certificate_selfsigned import (
    SelfSignedCertificateProvider,
    add_selfsigned_provider_to_argument_spec,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.support import (
    OpenSSLObject,
)
from ansible_collections.community.crypto.plugins.module_utils._io import (
    load_file_if_exists,
    write_file,
)


if t.TYPE_CHECKING:
    from ansible.module_utils.basic import AnsibleModule  # pragma: no cover

    from ansible_collections.community.crypto.plugins.module_utils._crypto.module_backends.certificate import (  # pragma: no cover
        CertificateBackend,
    )


class CertificateAbsent(OpenSSLObject):
    def __init__(self, module: AnsibleModule) -> None:
        super().__init__(
            path=module.params["path"],
            state=module.params["state"],
            force=module.params["force"],
            check_mode=module.check_mode,
        )
        self.module = module
        self.return_content: bool = module.params["return_content"]
        self.backup: bool = module.params["backup"]
        self.backup_file: str | None = None

    def generate(self, module: AnsibleModule) -> None:
        pass

    def remove(self, module: AnsibleModule) -> None:
        if self.backup:
            self.backup_file = module.backup_local(self.path)
        super().remove(module)

    def dump(self, check_mode: bool = False) -> dict[str, t.Any]:
        result = {
            "changed": self.changed,
            "filename": self.path,
            "privatekey": self.module.params["privatekey_path"],
            "csr": self.module.params["csr_path"],
        }
        if self.backup_file:
            result["backup_file"] = self.backup_file
        if self.return_content:
            result["certificate"] = None

        return result


class GenericCertificate(OpenSSLObject):
    """Retrieve a certificate using the given module backend."""

    def __init__(self, module: AnsibleModule, module_backend: CertificateBackend):
        super().__init__(
            path=module.params["path"],
            state=module.params["state"],
            force=module.params["force"],
            check_mode=module.check_mode,
        )
        self.module = module
        self.return_content = module.params["return_content"]
        self.backup = module.params["backup"]
        self.backup_file: str | None = None

        self.module_backend = module_backend
        self.module_backend.set_existing(
            certificate_bytes=load_file_if_exists(path=self.path, module=module)
        )

    def generate(self, module: AnsibleModule) -> None:
        if self.module_backend.needs_regeneration():
            if not self.check_mode:
                self.module_backend.generate_certificate()
                result = self.module_backend.get_certificate_data()
                if self.backup:
                    self.backup_file = module.backup_local(self.path)
                write_file(module=module, content=result)
            self.changed = True

        file_args = module.load_file_common_arguments(module.params)
        if module.check_file_absent_if_check_mode(file_args["path"]):
            self.changed = True
        else:
            self.changed = module.set_fs_attributes_if_different(
                file_args, self.changed
            )

    def check(self, module: AnsibleModule, *, perms_required: bool = True) -> bool:
        """Ensure the resource is in its desired state."""
        return (
            super().check(module=module, perms_required=perms_required)
            and not self.module_backend.needs_regeneration()
        )

    def dump(self, check_mode: bool = False) -> dict[str, t.Any]:
        result = self.module_backend.dump(include_certificate=self.return_content)
        result.update(
            {
                "changed": self.changed,
                "filename": self.path,
            }
        )
        if self.backup_file:
            result["backup_file"] = self.backup_file
        return result


def main() -> t.NoReturn:
    argument_spec = get_certificate_argument_spec()
    add_acme_provider_to_argument_spec(argument_spec)
    add_ownca_provider_to_argument_spec(argument_spec)
    add_selfsigned_provider_to_argument_spec(argument_spec)
    argument_spec.argument_spec.update(
        {
            "state": {
                "type": "str",
                "default": "present",
                "choices": ["present", "absent"],
            },
            "path": {"type": "path", "required": True},
            "backup": {"type": "bool", "default": False},
            "return_content": {"type": "bool", "default": False},
        }
    )
    argument_spec.required_if.append(("state", "present", ["provider"]))
    module = argument_spec.create_ansible_module(
        add_file_common_args=True,
        supports_check_mode=True,
    )

    try:
        certificate: GenericCertificate | CertificateAbsent
        if module.params["state"] == "absent":
            certificate = CertificateAbsent(module)

            if module.check_mode:
                result = certificate.dump(check_mode=True)
                result["changed"] = os.path.exists(module.params["path"])
                module.exit_json(**result)

            certificate.remove(module)

        else:
            base_dir = os.path.dirname(module.params["path"]) or "."
            if not os.path.isdir(base_dir):
                module.fail_json(
                    name=base_dir,
                    msg=f"The directory {base_dir} does not exist or the file is not a directory",
                )

            provider = module.params["provider"]
            provider_map: dict[
                str,
                type[AcmeCertificateProvider]
                | type[OwnCACertificateProvider]
                | type[SelfSignedCertificateProvider],
            ] = {
                "acme": AcmeCertificateProvider,
                "ownca": OwnCACertificateProvider,
                "selfsigned": SelfSignedCertificateProvider,
            }

            module_backend = select_backend(
                module=module, provider=provider_map[provider]()
            )
            certificate = GenericCertificate(module, module_backend)
            certificate.generate(module)

        result = certificate.dump()
        module.exit_json(**result)
    except OpenSSLObjectError as exc:
        module.fail_json(msg=str(exc))


if __name__ == "__main__":
    main()
