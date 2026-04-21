# Copyright (c) 2016-2017, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright (c) 2017, Markus Teufelberger <mteufelberger+ansible@mgit.at>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import os
import tempfile
import traceback
import typing as t

from ansible.module_utils.common.text.converters import to_bytes

from ansible_collections.community.crypto.plugins.module_utils._crypto.module_backends.certificate import (
    CertificateBackend,
    CertificateError,
    CertificateProvider,
)


if t.TYPE_CHECKING:
    from ansible.module_utils.basic import AnsibleModule  # pragma: no cover

    from ansible_collections.community.crypto.plugins.module_utils._argspec import (  # pragma: no cover
        ArgumentSpec,
    )


class AcmeCertificateBackend(CertificateBackend):
    def __init__(self, *, module: AnsibleModule) -> None:
        super().__init__(module=module)
        self.accountkey_path: str = module.params["acme_accountkey_path"]
        self.challenge_path: str = module.params["acme_challenge_path"]
        self.use_chain: bool = module.params["acme_chain"]
        self.acme_directory: str = module.params["acme_directory"]
        self.cert_bytes: bytes | None = None

        if self.csr_content is None:
            if self.csr_path is None:
                raise CertificateError(
                    "csr_path or csr_content is required for ownca provider"
                )
            if not os.path.exists(self.csr_path):
                raise CertificateError(
                    f"The certificate signing request file {self.csr_path} does not exist"
                )

        if not os.path.exists(self.accountkey_path):
            raise CertificateError(
                f"The account key {self.accountkey_path} does not exist"
            )

        if not os.path.exists(self.challenge_path):
            raise CertificateError(
                f"The challenge path {self.challenge_path} does not exist"
            )

        self.acme_tiny_path = self.module.get_bin_path("acme-tiny", required=True)

    def generate_certificate(self) -> None:
        """(Re-)Generate certificate."""

        command = [self.acme_tiny_path]
        if self.use_chain:
            command.append("--chain")
        command.extend(["--account-key", self.accountkey_path])
        if self.csr_content is not None:
            # We need to temporarily write the CSR to disk
            fd, tmpsrc = tempfile.mkstemp()
            self.module.add_cleanup_file(tmpsrc)  # Ansible will delete the file on exit
            f = os.fdopen(fd, "wb")
            try:
                f.write(self.csr_content)
            except Exception as err:
                try:
                    f.close()
                except Exception:
                    pass
                self.module.fail_json(
                    msg=f"failed to create temporary CSR file: {err}",
                    exception=traceback.format_exc(),
                )
            f.close()
            command.extend(["--csr", tmpsrc])
        else:
            assert self.csr_path is not None
            command.extend(["--csr", self.csr_path])
        command.extend(["--acme-dir", self.challenge_path])
        command.extend(["--directory-url", self.acme_directory])

        try:
            self.cert_bytes = to_bytes(
                self.module.run_command(command, check_rc=True)[1]
            )
        except OSError as exc:
            raise CertificateError(exc) from exc

    def get_certificate_data(self) -> bytes:
        """Return bytes for self.cert."""
        if self.cert_bytes is None:
            raise AssertionError(
                "Contract violation: cert_bytes is None"
            )  # pragma: no cover
        return self.cert_bytes

    def dump(self, *, include_certificate: bool) -> dict[str, t.Any]:
        result = super().dump(include_certificate=include_certificate)
        result["accountkey"] = self.accountkey_path
        return result


class AcmeCertificateProvider(CertificateProvider):
    def validate_module_args(self, module: AnsibleModule) -> None:
        if module.params["acme_accountkey_path"] is None:
            module.fail_json(
                msg="The acme_accountkey_path option must be specified for the acme provider."
            )
        if module.params["acme_challenge_path"] is None:
            module.fail_json(
                msg="The acme_challenge_path option must be specified for the acme provider."
            )

    def create_backend(self, module: AnsibleModule) -> AcmeCertificateBackend:
        return AcmeCertificateBackend(module=module)


def add_acme_provider_to_argument_spec(argument_spec: ArgumentSpec) -> None:
    argument_spec.argument_spec["provider"]["choices"].append("acme")
    argument_spec.argument_spec.update(
        {
            "acme_accountkey_path": {"type": "path"},
            "acme_challenge_path": {"type": "path"},
            "acme_chain": {"type": "bool", "default": False},
            "acme_directory": {
                "type": "str",
                "default": "https://acme-v02.api.letsencrypt.org/directory",
            },
        }
    )


__all__ = (
    "AcmeCertificateBackend",
    "AcmeCertificateProvider",
    "add_acme_provider_to_argument_spec",
)
