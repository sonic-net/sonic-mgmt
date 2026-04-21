#!/usr/bin/python
# Copyright (c) 2017, Thom Wiggers  <ansible@thomwiggers.nl>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = r"""
module: openssl_dhparam
short_description: Generate OpenSSL Diffie-Hellman Parameters
description:
  - This module allows one to (re)generate OpenSSL DH-params.
  - This module uses file common arguments to specify generated file permissions.
  - Please note that the module regenerates existing DH params if they do not match the module's options. If you are concerned
    that this could overwrite your existing DH params, consider using the O(backup) option.
  - The module can use the cryptography Python library, or the C(openssl) executable. By default, it tries to detect which
    one is available. This can be overridden with the O(select_crypto_backend) option.
requirements:
  - Either cryptography >= 3.3
  - Or OpenSSL binary C(openssl)
author:
  - Thom Wiggers (@thomwiggers)
extends_documentation_fragment:
  - ansible.builtin.files
  - community.crypto._attributes
  - community.crypto._attributes.files
attributes:
  check_mode:
    support: full
  diff_mode:
    support: none
  safe_file_operations:
    support: full
  idempotent:
    support: partial
    details:
      - The module is not idempotent if O(force=true).
options:
  state:
    description:
      - Whether the parameters should exist or not, taking action if the state is different from what is stated.
    type: str
    default: present
    choices: [absent, present]
  size:
    description:
      - Size (in bits) of the generated DH-params.
    type: int
    default: 4096
  force:
    description:
      - Should the parameters be regenerated even it it already exists.
    type: bool
    default: false
  path:
    description:
      - Name of the file in which the generated parameters will be saved.
    type: path
    required: true
  backup:
    description:
      - Create a backup file including a timestamp so you can get the original DH params back if you overwrote them with new
        ones by accident.
    type: bool
    default: false
  select_crypto_backend:
    description:
      - Determines which crypto backend to use.
      - The default choice is V(auto), which tries to use C(cryptography) if available, and falls back to C(openssl).
      - If set to V(openssl), will try to use the OpenSSL C(openssl) executable.
      - If set to V(cryptography), will try to use the L(cryptography,https://cryptography.io/) library.
    type: str
    default: auto
    choices: [auto, cryptography, openssl]
    version_added: "1.0.0"
  return_content:
    description:
      - If set to V(true), will return the (current or generated) DH parameter's content as RV(dhparams).
    type: bool
    default: false
    version_added: "1.0.0"
seealso:
  - module: community.crypto.x509_certificate
  - module: community.crypto.openssl_csr
  - module: community.crypto.openssl_pkcs12
  - module: community.crypto.openssl_privatekey
  - module: community.crypto.openssl_publickey
"""

EXAMPLES = r"""
---
- name: Generate Diffie-Hellman parameters with the default size (4096 bits)
  community.crypto.openssl_dhparam:
    path: /etc/ssl/dhparams.pem

- name: Generate DH Parameters with a different size (2048 bits)
  community.crypto.openssl_dhparam:
    path: /etc/ssl/dhparams.pem
    size: 2048

- name: Force regenerate an DH parameters if they already exist
  community.crypto.openssl_dhparam:
    path: /etc/ssl/dhparams.pem
    force: true
"""

RETURN = r"""
size:
  description: Size (in bits) of the Diffie-Hellman parameters.
  returned: changed or success
  type: int
  sample: 4096
filename:
  description: Path to the generated Diffie-Hellman parameters.
  returned: changed or success
  type: str
  sample: /etc/ssl/dhparams.pem
backup_file:
  description: Name of backup file created.
  returned: changed and if O(backup) is V(true)
  type: str
  sample: /path/to/dhparams.pem.2019-03-09@11:22~
dhparams:
  description: The (current or generated) DH params' content.
  returned: if O(state) is V(present) and O(return_content) is V(true)
  type: str
  version_added: "1.0.0"
"""

import abc
import os
import re
import tempfile
import typing as t

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_text

from ansible_collections.community.crypto.plugins.module_utils._crypto.math import (
    count_bits,
)
from ansible_collections.community.crypto.plugins.module_utils._cryptography_dep import (
    COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION,
    assert_required_cryptography_version,
)
from ansible_collections.community.crypto.plugins.module_utils._io import (
    load_file_if_exists,
    write_file,
)
from ansible_collections.community.crypto.plugins.module_utils._version import (
    LooseVersion,
)


MINIMAL_CRYPTOGRAPHY_VERSION = COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION

try:
    import cryptography
    import cryptography.exceptions
    import cryptography.hazmat.backends
    import cryptography.hazmat.primitives.asymmetric.dh
    import cryptography.hazmat.primitives.serialization

    CRYPTOGRAPHY_VERSION = LooseVersion(cryptography.__version__)
except ImportError:
    CRYPTOGRAPHY_FOUND = False
else:
    CRYPTOGRAPHY_FOUND = True


class DHParameterError(Exception):
    pass


class DHParameterBase:
    def __init__(self, module: AnsibleModule) -> None:
        self.state: t.Literal["absent", "present"] = module.params["state"]
        self.path: str = module.params["path"]
        self.size: int = module.params["size"]
        self.force: bool = module.params["force"]
        self.changed = False
        self.return_content: bool = module.params["return_content"]

        self.backup: bool = module.params["backup"]
        self.backup_file: str | None = None

    @abc.abstractmethod
    def _do_generate(self, module: AnsibleModule) -> None:
        """Actually generate the DH params."""

    def generate(self, module: AnsibleModule) -> None:
        """Generate DH params."""
        changed = False

        # only generate when necessary
        if self.force or not self._check_params_valid(module):
            self._do_generate(module)
            changed = True

        # fix permissions (checking force not necessary as done above)
        if not self._check_fs_attributes(module):
            # Fix done implicitly by
            # AnsibleModule.set_fs_attributes_if_different
            changed = True

        self.changed = changed

    def remove(self, module: AnsibleModule) -> None:
        if self.backup:
            self.backup_file = module.backup_local(self.path)
        try:
            os.remove(self.path)
            self.changed = True
        except OSError as exc:
            module.fail_json(msg=str(exc))

    def check(self, module: AnsibleModule) -> bool:
        """Ensure the resource is in its desired state."""
        if self.force:
            return False
        return self._check_params_valid(module) and self._check_fs_attributes(module)

    @abc.abstractmethod
    def _check_params_valid(self, module: AnsibleModule) -> bool:
        """Check if the params are in the correct state"""

    def _check_fs_attributes(self, module: AnsibleModule) -> bool:
        """Checks (and changes if not in check mode!) fs attributes"""
        file_args = module.load_file_common_arguments(module.params)
        if module.check_file_absent_if_check_mode(file_args["path"]):
            return False
        return not module.set_fs_attributes_if_different(file_args, False)

    def dump(self) -> dict[str, t.Any]:
        """Serialize the object into a dictionary."""

        result: dict[str, t.Any] = {
            "size": self.size,
            "filename": self.path,
            "changed": self.changed,
        }
        if self.backup_file:
            result["backup_file"] = self.backup_file
        if self.return_content:
            content = load_file_if_exists(path=self.path, ignore_errors=True)
            result["dhparams"] = content.decode("utf-8") if content else None

        return result


class DHParameterAbsent(DHParameterBase):
    def __init__(self, module: AnsibleModule) -> None:
        super().__init__(module)

    def _do_generate(self, module: AnsibleModule) -> None:
        """Actually generate the DH params."""

    def _check_params_valid(self, module: AnsibleModule) -> bool:
        """Check if the params are in the correct state"""
        return False


class DHParameterOpenSSL(DHParameterBase):
    def __init__(self, module: AnsibleModule) -> None:
        super().__init__(module)
        self.openssl_bin = module.get_bin_path("openssl", True)

    def _do_generate(self, module: AnsibleModule) -> None:
        """Actually generate the DH params."""
        # create a tempfile
        fd, tmpsrc = tempfile.mkstemp()
        os.close(fd)
        module.add_cleanup_file(tmpsrc)  # Ansible will delete the file on exit
        # openssl dhparam -out <path> <bits>
        command = [self.openssl_bin, "dhparam", "-out", tmpsrc, str(self.size)]
        rc, dummy, err = module.run_command(command, check_rc=False)
        if rc != 0:
            raise DHParameterError(str(err))
        if self.backup:
            self.backup_file = module.backup_local(self.path)
        try:
            module.atomic_move(os.path.abspath(tmpsrc), os.path.abspath(self.path))
        except Exception as e:
            module.fail_json(msg=f"Failed to write to file {self.path}: {str(e)}")

    def _check_params_valid(self, module: AnsibleModule) -> bool:
        """Check if the params are in the correct state"""
        command = [
            self.openssl_bin,
            "dhparam",
            "-check",
            "-text",
            "-noout",
            "-in",
            self.path,
        ]
        rc, out, err = module.run_command(command, check_rc=False)
        result = to_text(out)
        if rc != 0:
            # If the call failed the file probably does not exist or is
            # unreadable
            return False
        # output contains "(xxxx bit)"
        match = re.search(r"Parameters:\s+\((\d+) bit\).*", result)
        if not match:
            return False  # No "xxxx bit" in output

        bits = int(match.group(1))

        # if output contains "WARNING" we've got a problem
        if "WARNING" in result or "WARNING" in to_text(err):
            return False

        return bits == self.size


class DHParameterCryptography(DHParameterBase):
    def __init__(self, module: AnsibleModule) -> None:
        super().__init__(module)

    def _do_generate(self, module: AnsibleModule) -> None:
        """Actually generate the DH params."""
        # Generate parameters
        params = cryptography.hazmat.primitives.asymmetric.dh.generate_parameters(
            generator=2,
            key_size=self.size,
        )
        # Serialize parameters
        result = params.parameter_bytes(
            encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM,
            format=cryptography.hazmat.primitives.serialization.ParameterFormat.PKCS3,
        )
        # Write result
        if self.backup:
            self.backup_file = module.backup_local(self.path)
        write_file(module=module, content=result)

    def _check_params_valid(self, module: AnsibleModule) -> bool:
        """Check if the params are in the correct state"""
        # Load parameters
        try:
            with open(self.path, "rb") as f:
                data = f.read()
            params = cryptography.hazmat.primitives.serialization.load_pem_parameters(
                data
            )
        except Exception:
            return False
        # Check parameters
        bits = count_bits(params.parameter_numbers().p)
        return bits == self.size


def main() -> t.NoReturn:
    """Main function"""

    module = AnsibleModule(
        argument_spec={
            "state": {
                "type": "str",
                "default": "present",
                "choices": ["absent", "present"],
            },
            "size": {"type": "int", "default": 4096},
            "force": {"type": "bool", "default": False},
            "path": {"type": "path", "required": True},
            "backup": {"type": "bool", "default": False},
            "select_crypto_backend": {
                "type": "str",
                "default": "auto",
                "choices": ["auto", "cryptography", "openssl"],
            },
            "return_content": {"type": "bool", "default": False},
        },
        supports_check_mode=True,
        add_file_common_args=True,
    )

    base_dir = os.path.dirname(module.params["path"]) or "."
    if not os.path.isdir(base_dir):
        module.fail_json(
            name=base_dir,
            msg=f"The directory '{base_dir}' does not exist or the file is not a directory",
        )

    dhparam: DHParameterOpenSSL | DHParameterCryptography | DHParameterAbsent
    if module.params["state"] == "present":
        backend = module.params["select_crypto_backend"]
        if backend == "auto":
            # Detection what is possible
            can_use_cryptography = (
                CRYPTOGRAPHY_FOUND
                and LooseVersion(MINIMAL_CRYPTOGRAPHY_VERSION) <= CRYPTOGRAPHY_VERSION
            )
            can_use_openssl = module.get_bin_path("openssl", False) is not None

            # First try cryptography, then OpenSSL
            if can_use_cryptography:
                backend = "cryptography"
            elif can_use_openssl:
                backend = "openssl"

            # Success?
            if backend == "auto":
                module.fail_json(
                    msg=(
                        f"Cannot detect either the required Python library cryptography (>= {MINIMAL_CRYPTOGRAPHY_VERSION}) or the OpenSSL binary openssl"
                    )
                )

        if backend == "openssl":
            dhparam = DHParameterOpenSSL(module)
        elif backend == "cryptography":
            assert_required_cryptography_version(
                module, minimum_cryptography_version=MINIMAL_CRYPTOGRAPHY_VERSION
            )
            dhparam = DHParameterCryptography(module)
        else:
            raise AssertionError("Internal error: unknown backend")  # pragma: no cover

        if module.check_mode:
            result = dhparam.dump()
            result["changed"] = module.params["force"] or not dhparam.check(module)
            module.exit_json(**result)

        try:
            dhparam.generate(module)
        except DHParameterError as exc:
            module.fail_json(msg=str(exc))
    else:
        dhparam = DHParameterAbsent(module)

        if module.check_mode:
            result = dhparam.dump()
            result["changed"] = os.path.exists(module.params["path"])
            module.exit_json(**result)

        if os.path.exists(module.params["path"]):
            try:
                dhparam.remove(module)
            except Exception as exc:
                module.fail_json(msg=str(exc))

    result = dhparam.dump()

    module.exit_json(**result)


if __name__ == "__main__":
    main()
