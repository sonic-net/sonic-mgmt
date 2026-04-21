# Copyright (c) 2021, Andrew Pantuso (@ajpantuso) <ajpantuso@gmail.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import abc
import os
import stat
import traceback
import typing as t
from collections.abc import Callable

from ansible_collections.community.crypto.plugins.module_utils._openssh.utils import (
    parse_openssh_version,
)


if t.TYPE_CHECKING:
    from ansible.module_utils.basic import AnsibleModule  # pragma: no cover

    from ansible_collections.community.crypto.plugins.module_utils._openssh.certificate import (  # pragma: no cover
        OpensshCertificateTimeParameters,
    )

    Param = t.ParamSpec("Param")  # pragma: no cover


def restore_on_failure(
    f: Callable[t.Concatenate[AnsibleModule, str | os.PathLike, Param], None],
) -> Callable[t.Concatenate[AnsibleModule, str | os.PathLike, Param], None]:
    def backup_and_restore(
        module: AnsibleModule,
        path: str | os.PathLike,
        *args: Param.args,
        **kwargs: Param.kwargs,
    ) -> None:
        backup_file = module.backup_local(path) if os.path.exists(path) else None

        try:
            f(module, path, *args, **kwargs)
        except Exception:
            if backup_file is not None:
                module.atomic_move(os.path.abspath(backup_file), os.path.abspath(path))
            raise
        if backup_file is not None:
            module.add_cleanup_file(backup_file)

    return backup_and_restore


@restore_on_failure
def safe_atomic_move(
    module: AnsibleModule, path: str | os.PathLike, destination: str | os.PathLike
) -> None:
    module.atomic_move(os.path.abspath(path), os.path.abspath(destination))


def _restore_all_on_failure(
    f: Callable[
        t.Concatenate[
            OpensshModule, list[tuple[str | os.PathLike, str | os.PathLike]], Param
        ],
        None,
    ],
) -> Callable[
    t.Concatenate[
        OpensshModule, list[tuple[str | os.PathLike, str | os.PathLike]], Param
    ],
    None,
]:
    def backup_and_restore(
        self: OpensshModule,
        sources_and_destinations: list[tuple[str | os.PathLike, str | os.PathLike]],
        *args: Param.args,
        **kwargs: Param.kwargs,
    ) -> None:
        backups = [
            (d, self.module.backup_local(d))
            for s, d in sources_and_destinations
            if os.path.exists(d)
        ]

        try:
            f(self, sources_and_destinations, *args, **kwargs)
        except Exception:
            for destination, backup in backups:
                self.module.atomic_move(
                    os.path.abspath(backup), os.path.abspath(destination)
                )
            raise
        for dummy_destination, backup in backups:
            self.module.add_cleanup_file(backup)

    return backup_and_restore


_OpensshModule = t.TypeVar("_OpensshModule", bound="OpensshModule")


class OpensshModule(metaclass=abc.ABCMeta):
    def __init__(self, *, module: AnsibleModule) -> None:
        self.module = module

        self.changed: bool = False
        self.check_mode: bool = self.module.check_mode

    def execute(self) -> t.NoReturn:
        try:
            self._execute()
        except Exception as e:
            self.module.fail_json(
                msg=f"unexpected error occurred: {e}",
                exception=traceback.format_exc(),
            )

        self.module.exit_json(**self.result)

    @abc.abstractmethod
    def _execute(self) -> None:
        pass

    @property
    def result(self) -> dict[str, t.Any]:
        result = self._result

        result["changed"] = self.changed

        if self.module._diff:  # pylint: disable=protected-access
            result["diff"] = self.diff

        return result

    @property
    @abc.abstractmethod
    def _result(self) -> dict[str, t.Any]:
        pass

    @property
    @abc.abstractmethod
    def diff(self) -> dict[str, t.Any]:
        pass

    @staticmethod
    def skip_if_check_mode(
        f: Callable[t.Concatenate[_OpensshModule, Param], None],
    ) -> Callable[t.Concatenate[_OpensshModule, Param], None]:
        def wrapper(
            self: _OpensshModule, *args: Param.args, **kwargs: Param.kwargs
        ) -> None:
            if not self.check_mode:
                f(self, *args, **kwargs)

        return wrapper  # type: ignore

    @staticmethod
    def trigger_change(
        f: Callable[t.Concatenate[_OpensshModule, Param], None],
    ) -> Callable[t.Concatenate[_OpensshModule, Param], None]:
        def wrapper(
            self: _OpensshModule, *args: Param.args, **kwargs: Param.kwargs
        ) -> None:
            f(self, *args, **kwargs)
            self.changed = True

        return wrapper  # type: ignore

    def _check_if_base_dir(self, path: str | os.PathLike) -> None:
        base_dir = os.path.dirname(path) or "."
        if not os.path.isdir(base_dir):
            self.module.fail_json(
                name=base_dir,
                msg=f"The directory {base_dir} does not exist or the file is not a directory",
            )

    def _get_ssh_version(self) -> str | None:
        ssh_bin = self.module.get_bin_path("ssh")
        if not ssh_bin:
            return None
        return parse_openssh_version(
            self.module.run_command([ssh_bin, "-V", "-q"], check_rc=True)[2].strip()
        )

    @_restore_all_on_failure
    def _safe_secure_move(
        self,
        sources_and_destinations: list[tuple[str | os.PathLike, str | os.PathLike]],
    ) -> None:
        """Moves a list of files from 'source' to 'destination' and restores 'destination' from backup upon failure.
        If 'destination' does not already exist, then 'source' permissions are preserved to prevent
        exposing protected data ('atomic_move' uses the 'destination' base directory mask for
        permissions if 'destination' does not already exists).
        """
        for source, destination in sources_and_destinations:
            if os.path.exists(destination):
                self.module.atomic_move(
                    os.path.abspath(source), os.path.abspath(destination)
                )
            else:
                self.module.preserved_copy(source, destination)

    def _update_permissions(self, path: str | os.PathLike) -> None:
        file_args = self.module.load_file_common_arguments(self.module.params)
        file_args["path"] = path

        if not self.module.check_file_absent_if_check_mode(path):
            self.changed = self.module.set_fs_attributes_if_different(
                file_args, self.changed
            )
        else:
            self.changed = True


if t.TYPE_CHECKING:

    class _RunCommandKwarg(t.TypedDict):
        check_rc: t.NotRequired[bool]
        environ_update: t.NotRequired[dict[str, str] | None]


class KeygenCommand:
    def __init__(self, module: AnsibleModule) -> None:
        self._bin_path = module.get_bin_path("ssh-keygen", True)
        self._run_command = module.run_command

    def generate_certificate(
        self,
        *,
        certificate_path: str,
        identifier: str,
        options: list[str] | None,
        pkcs11_provider: str | None,
        principals: list[str] | None,
        serial_number: int | None,
        signature_algorithm: str | None,
        signing_key_path: str,
        cert_type: t.Literal["host", "user"] | None,
        time_parameters: OpensshCertificateTimeParameters,
        use_agent: bool,
        **kwargs: t.Unpack[_RunCommandKwarg],
    ) -> tuple[int, str, str]:
        args = [self._bin_path, "-s", signing_key_path, "-P", "", "-I", identifier]

        if options:
            for option in options:
                args.extend(["-O", option])
        if pkcs11_provider:
            args.extend(["-D", pkcs11_provider])
        if principals:
            args.extend(["-n", ",".join(principals)])
        if serial_number is not None:
            args.extend(["-z", str(serial_number)])
        if cert_type == "host":
            args.extend(["-h"])
        if use_agent:
            args.extend(["-U"])
        if time_parameters.validity_string:
            args.extend(["-V", time_parameters.validity_string])
        if signature_algorithm:
            args.extend(["-t", signature_algorithm])
        args.append(certificate_path)

        return self._run_command(args, **kwargs)

    def generate_keypair(
        self,
        *,
        private_key_path: str,
        size: int,
        key_type: str,
        comment: str | None,
        **kwargs: t.Unpack[_RunCommandKwarg],
    ) -> tuple[int, str, str]:
        args = [
            self._bin_path,
            "-q",
            "-N",
            "",
            "-b",
            str(size),
            "-t",
            key_type,
            "-f",
            private_key_path,
            "-C",
            comment or "",
        ]

        # "y" must be entered in response to the "overwrite" prompt
        data = "y" if os.path.exists(private_key_path) else None

        return self._run_command(args, data=data, **kwargs)

    def get_certificate_info(
        self, *, certificate_path: str, **kwargs: t.Unpack[_RunCommandKwarg]
    ) -> tuple[int, str, str]:
        return self._run_command(
            [self._bin_path, "-L", "-f", certificate_path], **kwargs
        )

    def get_matching_public_key(
        self, *, private_key_path: str, **kwargs: t.Unpack[_RunCommandKwarg]
    ) -> tuple[int, str, str]:
        return self._run_command(
            [self._bin_path, "-P", "", "-y", "-f", private_key_path], **kwargs
        )

    def get_private_key(
        self, *, private_key_path: str, **kwargs: t.Unpack[_RunCommandKwarg]
    ) -> tuple[int, str, str]:
        return self._run_command(
            [self._bin_path, "-l", "-f", private_key_path], **kwargs
        )

    def update_comment(
        self,
        *,
        private_key_path: str,
        comment: str,
        force_new_format: bool = True,
        **kwargs: t.Unpack[_RunCommandKwarg],
    ) -> tuple[int, str, str]:
        if os.path.exists(private_key_path) and not os.access(
            private_key_path, os.W_OK
        ):
            try:
                os.chmod(private_key_path, stat.S_IWUSR + stat.S_IRUSR)
            except (IOError, OSError) as e:
                raise ValueError(
                    f"The private key at {private_key_path} is not writeable preventing a comment update ({e})"
                ) from e

        command = [self._bin_path, "-q"]
        if force_new_format:
            command.append("-o")
        command.extend(["-c", "-C", comment, "-f", private_key_path])
        return self._run_command(command, **kwargs)


_PrivateKey = t.TypeVar("_PrivateKey", bound="PrivateKey")


class PrivateKey:
    def __init__(
        self, *, size: int, key_type: str, fingerprint: str, key_format: str = ""
    ) -> None:
        self._size = size
        self._type = key_type
        self._fingerprint = fingerprint
        self._format = key_format

    @property
    def size(self) -> int:
        return self._size

    @property
    def type(self) -> str:
        return self._type

    @property
    def fingerprint(self) -> str:
        return self._fingerprint

    @property
    def format(self) -> str:
        return self._format

    @classmethod
    def from_string(
        cls: t.Type[_PrivateKey], string: str  # noqa: UP006
    ) -> _PrivateKey:
        properties = string.split()

        return cls(
            size=int(properties[0]),
            key_type=properties[-1][1:-1].lower(),
            fingerprint=properties[1],
        )

    def to_dict(self) -> dict[str, t.Any]:
        return {
            "size": self._size,
            "type": self._type,
            "fingerprint": self._fingerprint,
            "format": self._format,
        }


_PublicKey = t.TypeVar("_PublicKey", bound="PublicKey")


class PublicKey:
    def __init__(self, *, type_string: str, data: str, comment: str | None) -> None:
        self._type_string = type_string
        self._data = data
        self._comment = comment

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented

        return all(
            [
                self._type_string == other._type_string,
                self._data == other._data,
                (
                    (self._comment == other._comment)
                    if self._comment is not None and other._comment is not None
                    else True
                ),
            ]
        )

    def __ne__(self, other: object) -> bool:
        return not self == other

    def __str__(self) -> str:
        return f"{self._type_string} {self._data}"

    @property
    def comment(self) -> str | None:
        return self._comment

    @comment.setter
    def comment(self, value: str | None) -> None:
        self._comment = value

    @property
    def data(self) -> str:
        return self._data

    @property
    def type_string(self) -> str:
        return self._type_string

    @classmethod
    def from_string(cls: type[_PublicKey], string: str) -> _PublicKey:
        properties = string.strip("\n").split(" ", 2)

        return cls(
            type_string=properties[0],
            data=properties[1],
            comment=properties[2] if len(properties) > 2 else "",
        )

    @classmethod
    def load(cls: type[_PublicKey], path: str | os.PathLike) -> _PublicKey | None:
        with open(path, "r", encoding="utf-8") as f:
            properties = f.read().strip(" \n").split(" ", 2)

        if len(properties) < 2:
            return None

        return cls(
            type_string=properties[0],
            data=properties[1],
            comment="" if len(properties) <= 2 else properties[2],
        )

    def to_dict(self) -> dict[str, t.Any]:
        return {
            "comment": self._comment,
            "public_key": self._data,
        }


def parse_private_key_format(
    *,
    path: str | os.PathLike,
) -> t.Literal["SSH", "PKCS8", "PKCS1", ""]:
    with open(path, "r", encoding="utf-8") as file:
        header = file.readline().strip()

    if header == "-----BEGIN OPENSSH PRIVATE KEY-----":
        return "SSH"
    if header == "-----BEGIN PRIVATE KEY-----":
        return "PKCS8"
    if header == "-----BEGIN RSA PRIVATE KEY-----":
        return "PKCS1"

    return ""


__all__ = (
    "restore_on_failure",
    "safe_atomic_move",
    "OpensshModule",
    "KeygenCommand",
    "PrivateKey",
    "PublicKey",
    "parse_private_key_format",
)
