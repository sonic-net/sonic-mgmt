# Copyright (c) 2018, David Kainz <dkainz@mgit.at> <dave.jokain@gmx.at>
# Copyright (c) 2021, Andrew Pantuso (@ajpantuso) <ajpantuso@gmail.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import abc
import os
import typing as t

from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.common.text.converters import to_bytes, to_text

from ansible_collections.community.crypto.plugins.module_utils._cryptography_dep import (
    COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION,
)
from ansible_collections.community.crypto.plugins.module_utils._openssh.backends.common import (
    KeygenCommand,
    OpensshModule,
    PrivateKey,
    PublicKey,
    parse_private_key_format,
)
from ansible_collections.community.crypto.plugins.module_utils._openssh.cryptography import (
    CRYPTOGRAPHY_VERSION,
    HAS_OPENSSH_SUPPORT,
    InvalidCommentError,
    InvalidPassphraseError,
    InvalidPrivateKeyFileError,
    OpenSSHError,
    OpensshKeypair,
)
from ansible_collections.community.crypto.plugins.module_utils._openssh.utils import (
    any_in,
    file_mode,
    secure_write,
)
from ansible_collections.community.crypto.plugins.module_utils._version import (
    LooseVersion,
)


if t.TYPE_CHECKING:
    from ansible.module_utils.basic import AnsibleModule  # pragma: no cover


class KeypairBackend(OpensshModule, metaclass=abc.ABCMeta):
    def __init__(self, *, module: AnsibleModule) -> None:
        super().__init__(module=module)

        self.comment: str | None = self.module.params["comment"]
        self.private_key_path: str = self.module.params["path"]
        self.public_key_path = self.private_key_path + ".pub"
        self.regenerate: t.Literal[
            "never", "fail", "partial_idempotence", "full_idempotence", "always"
        ] = (
            self.module.params["regenerate"]
            if not self.module.params["force"]
            else "always"
        )
        self.state: t.Literal["present", "absent"] = self.module.params["state"]
        self.type: t.Literal["rsa", "dsa", "rsa1", "ecdsa", "ed25519"] = (
            self.module.params["type"]
        )

        self.size: int = self._get_size(self.module.params["size"])
        self._validate_path()

        self.original_private_key: PrivateKey | None = None
        self.original_public_key: PublicKey | None = None
        self.private_key: PrivateKey | None = None
        self.public_key: PublicKey | None = None

    def _get_size(self, size: int | None) -> int:
        if self.type in ("rsa", "rsa1"):
            result = 4096 if size is None else size
            if result < 1024:
                return self.module.fail_json(
                    msg="For RSA keys, the minimum size is 1024 bits and the default is 4096 bits. "
                    + "Attempting to use bit lengths under 1024 will cause the module to fail."
                )
        elif self.type == "dsa":
            result = 1024 if size is None else size
            if result != 1024:
                return self.module.fail_json(
                    msg="DSA keys must be exactly 1024 bits as specified by FIPS 186-2."
                )
        elif self.type == "ecdsa":
            result = 256 if size is None else size
            if result not in (256, 384, 521):
                return self.module.fail_json(
                    msg="For ECDSA keys, size determines the key length by selecting from one of "
                    + "three elliptic curve sizes: 256, 384 or 521 bits. "
                    + "Attempting to use bit lengths other than these three values for ECDSA keys will "
                    + "cause this module to fail."
                )
        elif self.type == "ed25519":
            # User input is ignored for `key size` when `key type` is ed25519
            result = 256
        else:
            return self.module.fail_json(
                msg=f"{self.type} is not a valid value for key type"
            )

        return result

    def _validate_path(self) -> None:
        self._check_if_base_dir(self.private_key_path)

        if os.path.isdir(self.private_key_path):
            self.module.fail_json(
                msg=f"{self.private_key_path} is a directory. Please specify a path to a file."
            )

    def _execute(self) -> None:
        self.original_private_key = self._load_private_key()
        self.original_public_key = self._load_public_key()

        if self.state == "present":
            self._validate_key_load()

            if self._should_generate():
                self._generate()
            elif not self._public_key_valid():
                self._restore_public_key()

            self.private_key = self._load_private_key()
            self.public_key = self._load_public_key()

            for path in (self.private_key_path, self.public_key_path):
                self._update_permissions(path)
        else:
            if self._should_remove():
                self._remove()

    def _load_private_key(self) -> PrivateKey | None:
        result = None
        if self._private_key_exists():
            try:
                result = self._get_private_key()
            except Exception:
                pass

        return result

    def _private_key_exists(self) -> bool:
        return os.path.exists(self.private_key_path)

    @abc.abstractmethod
    def _get_private_key(self) -> PrivateKey:
        pass

    def _load_public_key(self) -> PublicKey | None:
        result = None
        if self._public_key_exists():
            try:
                result = PublicKey.load(self.public_key_path)
            except (IOError, OSError):
                pass
        return result

    def _public_key_exists(self) -> bool:
        return os.path.exists(self.public_key_path)

    def _validate_key_load(self) -> None:
        if (
            self._private_key_exists()
            and self.regenerate in ("never", "fail", "partial_idempotence")
            and (self.original_private_key is None or not self._private_key_readable())
        ):
            self.module.fail_json(
                msg="Unable to read the key. The key is protected with a passphrase or broken. "
                + "Will not proceed. To force regeneration, call the module with `generate` "
                + "set to `full_idempotence` or `always`, or with `force=true`."
            )

    @abc.abstractmethod
    def _private_key_readable(self) -> bool:
        pass

    def _should_generate(self) -> bool:
        if self.original_private_key is None:
            return True
        if self.regenerate == "never":
            return False
        if self.regenerate == "fail":
            if not self._private_key_valid():
                self.module.fail_json(
                    msg="Key has wrong type and/or size. Will not proceed. "
                    + "To force regeneration, call the module with `generate` set to "
                    + "`partial_idempotence`, `full_idempotence` or `always`, or with `force=true`."
                )
            return False
        if self.regenerate in ("partial_idempotence", "full_idempotence"):
            return not self._private_key_valid()
        return True

    def _private_key_valid(self) -> bool:
        if self.original_private_key is None:
            return False

        return all(
            [
                self.size == self.original_private_key.size,
                self.type == self.original_private_key.type,
                self._private_key_valid_backend(self.original_private_key),
            ]
        )

    @abc.abstractmethod
    def _private_key_valid_backend(self, original_private_key: PrivateKey) -> bool:
        pass

    @OpensshModule.trigger_change
    @OpensshModule.skip_if_check_mode
    def _generate(self) -> None:
        temp_private_key, temp_public_key = self._generate_temp_keypair()

        try:
            self._safe_secure_move(
                [
                    (temp_private_key, self.private_key_path),
                    (temp_public_key, self.public_key_path),
                ]
            )
        except OSError as e:
            self.module.fail_json(msg=str(e))

    def _generate_temp_keypair(self) -> tuple[str, str]:
        temp_private_key = os.path.join(
            self.module.tmpdir, os.path.basename(self.private_key_path)
        )
        temp_public_key = temp_private_key + ".pub"

        try:
            self._generate_keypair(temp_private_key)
        except (IOError, OSError) as e:
            self.module.fail_json(msg=str(e))

        for f in (temp_private_key, temp_public_key):
            self.module.add_cleanup_file(f)

        return temp_private_key, temp_public_key

    @abc.abstractmethod
    def _generate_keypair(self, private_key_path: str) -> None:
        pass

    def _public_key_valid(self) -> bool:
        if self.original_public_key is None:
            return False

        valid_public_key = self._get_public_key()
        if valid_public_key:
            valid_public_key.comment = self.comment

        return self.original_public_key == valid_public_key

    @abc.abstractmethod
    def _get_public_key(self) -> PublicKey | t.Literal[""]:
        pass

    @OpensshModule.trigger_change
    @OpensshModule.skip_if_check_mode
    def _restore_public_key(self) -> None:
        try:
            temp_public_key = self._create_temp_public_key(
                str(self._get_public_key()) + "\n"
            )
            self._safe_secure_move([(temp_public_key, self.public_key_path)])
        except (IOError, OSError):
            self.module.fail_json(
                msg="The public key is missing or does not match the private key. "
                + "Unable to regenerate the public key."
            )

        if self.comment:
            self._update_comment()

    def _create_temp_public_key(self, content: str | bytes) -> str:
        temp_public_key: str = os.path.join(
            self.module.tmpdir, os.path.basename(self.public_key_path)
        )

        default_permissions = 0o644
        existing_permissions = file_mode(self.public_key_path)

        try:
            secure_write(
                path=temp_public_key,
                mode=existing_permissions or default_permissions,
                content=to_bytes(content),
            )
        except (IOError, OSError) as e:
            self.module.fail_json(msg=str(e))
        self.module.add_cleanup_file(temp_public_key)

        return temp_public_key

    @abc.abstractmethod
    def _update_comment(self) -> None:
        pass

    def _should_remove(self) -> bool:
        return self._private_key_exists() or self._public_key_exists()

    @OpensshModule.trigger_change
    @OpensshModule.skip_if_check_mode
    def _remove(self) -> None:
        try:
            if self._private_key_exists():
                os.remove(self.private_key_path)
            if self._public_key_exists():
                os.remove(self.public_key_path)
        except (IOError, OSError) as e:
            self.module.fail_json(msg=str(e))

    @property
    def _result(self) -> dict[str, t.Any]:
        private_key = self.private_key or self.original_private_key
        public_key = self.public_key or self.original_public_key

        return {
            "size": self.size,
            "type": self.type,
            "filename": self.private_key_path,
            "fingerprint": private_key.fingerprint if private_key else "",
            "public_key": str(public_key) if public_key else "",
            "comment": public_key.comment if public_key else "",
        }

    @property
    def diff(self) -> dict[str, t.Any]:
        before = (
            self.original_private_key.to_dict() if self.original_private_key else {}
        )
        before.update(
            self.original_public_key.to_dict() if self.original_public_key else {}
        )

        after = self.private_key.to_dict() if self.private_key else {}
        after.update(self.public_key.to_dict() if self.public_key else {})

        return {
            "before": before,
            "after": after,
        }


class KeypairBackendOpensshBin(KeypairBackend):
    def __init__(self, *, module: AnsibleModule) -> None:
        super().__init__(module=module)

        if self.module.params["private_key_format"] != "auto":
            self.module.fail_json(
                msg="'auto' is the only valid option for 'private_key_format' when 'backend' is not 'cryptography'"
            )

        self.ssh_keygen = KeygenCommand(self.module)

    def _generate_keypair(self, private_key_path: str) -> None:
        self.ssh_keygen.generate_keypair(
            private_key_path=private_key_path,
            size=self.size,
            key_type=self.type,
            comment=self.comment,
            check_rc=True,
        )

    def _get_private_key(self) -> PrivateKey:
        rc, private_key_content, err = self.ssh_keygen.get_private_key(
            private_key_path=self.private_key_path, check_rc=False
        )
        if rc != 0:
            raise ValueError(err)
        return PrivateKey.from_string(private_key_content)

    def _get_public_key(self) -> PublicKey | t.Literal[""]:
        public_key_content = self.ssh_keygen.get_matching_public_key(
            private_key_path=self.private_key_path, check_rc=True
        )[1]
        return PublicKey.from_string(public_key_content)

    def _private_key_readable(self) -> bool:
        rc, _stdout, stderr = self.ssh_keygen.get_matching_public_key(
            private_key_path=self.private_key_path, check_rc=False
        )
        return not (
            rc == 255
            or any_in(
                stderr,
                "is not a public key file",
                "incorrect passphrase",
                "load failed",
            )
        )

    def _update_comment(self) -> None:
        assert self.comment is not None
        try:
            ssh_version = self._get_ssh_version() or "7.8"
            force_new_format = (
                LooseVersion("6.5") <= LooseVersion(ssh_version) < LooseVersion("7.8")
            )
            self.ssh_keygen.update_comment(
                private_key_path=self.private_key_path,
                comment=self.comment or "",
                force_new_format=force_new_format,
                check_rc=True,
            )
        except (IOError, OSError) as e:
            self.module.fail_json(msg=str(e))

    def _private_key_valid_backend(self, original_private_key: PrivateKey) -> bool:
        return True


class KeypairBackendCryptography(KeypairBackend):
    def __init__(self, *, module: AnsibleModule) -> None:
        super().__init__(module=module)

        if self.type == "rsa1":
            self.module.fail_json(
                msg="RSA1 keys are not supported by the cryptography backend"
            )

        self.passphrase = (
            to_bytes(module.params["passphrase"])
            if module.params["passphrase"]
            else None
        )
        key_format: t.Literal["auto", "pkcs1", "pkcs8", "ssh"] = module.params[
            "private_key_format"
        ]
        self.private_key_format = self._get_key_format(key_format)

    def _get_key_format(
        self, key_format: t.Literal["auto", "pkcs1", "pkcs8", "ssh"]
    ) -> t.Literal["SSH", "PKCS1", "PKCS8"]:
        result: t.Literal["SSH", "PKCS1", "PKCS8"] = "SSH"

        if key_format == "auto":
            # Default to OpenSSH 7.8 compatibility when OpenSSH is not installed
            ssh_version = self._get_ssh_version() or "7.8"

            if (
                LooseVersion(ssh_version) < LooseVersion("7.8")
                and self.type != "ed25519"
            ):
                # OpenSSH made SSH formatted private keys available in version 6.5,
                # but still defaulted to PKCS1 format with the exception of ed25519 keys
                result = "PKCS1"
        else:
            result = key_format.upper()  # type: ignore

        return result

    def _generate_keypair(self, private_key_path: str) -> None:
        assert self.type != "rsa1"
        keypair = OpensshKeypair.generate(
            keytype=self.type,
            size=self.size,
            passphrase=self.passphrase,
            comment=self.comment or "",
        )

        encoded_private_key = OpensshKeypair.encode_openssh_privatekey(
            asym_keypair=keypair.asymmetric_keypair, key_format=self.private_key_format
        )
        secure_write(path=private_key_path, mode=0o600, content=encoded_private_key)

        public_key_path = private_key_path + ".pub"
        secure_write(path=public_key_path, mode=0o644, content=keypair.public_key)

    def _get_private_key(self) -> PrivateKey:
        keypair = OpensshKeypair.load(
            path=self.private_key_path, passphrase=self.passphrase, no_public_key=True
        )

        return PrivateKey(
            size=keypair.size,
            key_type=keypair.key_type,
            fingerprint=keypair.fingerprint,
            key_format=parse_private_key_format(path=self.private_key_path),
        )

    def _get_public_key(self) -> PublicKey | t.Literal[""]:
        try:
            keypair = OpensshKeypair.load(
                path=self.private_key_path,
                passphrase=self.passphrase,
                no_public_key=True,
            )
        except OpenSSHError:
            # Simulates the null output of ssh-keygen
            return ""

        return PublicKey.from_string(to_text(keypair.public_key))

    def _private_key_readable(self) -> bool:
        try:
            OpensshKeypair.load(
                path=self.private_key_path,
                passphrase=self.passphrase,
                no_public_key=True,
            )
        except (InvalidPrivateKeyFileError, InvalidPassphraseError):
            return False

        # Cryptography >= 3.0 uses a SSH key loader which does not raise an exception when a passphrase is provided
        # when loading an unencrypted key
        if self.passphrase:
            try:
                OpensshKeypair.load(
                    path=self.private_key_path, passphrase=None, no_public_key=True
                )
                return False
            except (InvalidPrivateKeyFileError, InvalidPassphraseError):
                return True

        return True

    def _update_comment(self) -> None:
        assert self.comment is not None
        keypair = OpensshKeypair.load(
            path=self.private_key_path, passphrase=self.passphrase, no_public_key=True
        )
        try:
            keypair.comment = self.comment
        except InvalidCommentError as e:
            self.module.fail_json(msg=str(e))

        try:
            temp_public_key = self._create_temp_public_key(keypair.public_key + b"\n")
            self._safe_secure_move([(temp_public_key, self.public_key_path)])
        except (IOError, OSError) as e:
            self.module.fail_json(msg=str(e))

    def _private_key_valid_backend(self, original_private_key: PrivateKey) -> bool:
        # avoids breaking behavior and prevents
        # automatic conversions with OpenSSH upgrades
        if self.module.params["private_key_format"] == "auto":
            return True

        return self.private_key_format == original_private_key.format


def select_backend(
    *, module: AnsibleModule, backend: t.Literal["auto", "opensshbin", "cryptography"]
) -> KeypairBackend:
    can_use_cryptography = HAS_OPENSSH_SUPPORT and LooseVersion(
        CRYPTOGRAPHY_VERSION
    ) >= LooseVersion(COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION)
    can_use_opensshbin = bool(module.get_bin_path("ssh-keygen"))

    if backend == "auto":
        if can_use_opensshbin and not module.params["passphrase"]:
            backend = "opensshbin"
        elif can_use_cryptography:
            backend = "cryptography"
        else:
            module.fail_json(
                msg=(
                    f"Cannot find either the OpenSSH binary in the PATH or cryptography >= {COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION} installed on this system"
                )
            )

    if backend == "opensshbin":
        if not can_use_opensshbin:
            module.fail_json(msg="Cannot find the OpenSSH binary in the PATH")
        return KeypairBackendOpensshBin(module=module)
    if backend == "cryptography":
        if not can_use_cryptography:
            module.fail_json(
                msg=missing_required_lib(
                    f"cryptography >= {COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION}"
                )
            )
        return KeypairBackendCryptography(module=module)
    raise ValueError(f"Unsupported value for backend: {backend}")


__all__ = ("KeypairBackend", "select_backend")
