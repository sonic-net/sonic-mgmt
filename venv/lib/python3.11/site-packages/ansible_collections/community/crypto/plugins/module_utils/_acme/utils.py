# Copyright (c) 2016 Michael Gruener <michael.gruener@chaosmoon.net>
# Copyright (c) 2021 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import base64
import datetime
import os
import re
import textwrap
import traceback
import typing as t
from collections.abc import Callable
from urllib.parse import unquote

from ansible_collections.community.crypto.plugins.module_utils._acme.errors import (
    ModuleFailException,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.math import (
    convert_int_to_bytes,
)
from ansible_collections.community.crypto.plugins.module_utils._time import (
    get_now_datetime,
)


if t.TYPE_CHECKING:
    from ansible_collections.community.crypto.plugins.module_utils._acme.backends import (  # pragma: no cover
        CertificateInformation,
        CryptoBackend,
    )


def nopad_b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf8").replace("=", "")


def der_to_pem(der_cert: bytes) -> str:
    """
    Convert the DER format certificate in der_cert to a PEM format certificate and return it.
    """
    content = "\n".join(textwrap.wrap(base64.b64encode(der_cert).decode("utf8"), 64))
    return f"-----BEGIN CERTIFICATE-----\n{content}\n-----END CERTIFICATE-----\n"


def pem_to_der(
    *, pem_filename: str | os.PathLike | None = None, pem_content: str | None = None
) -> bytes:
    """
    Load PEM file, or use PEM file's content, and convert to DER.

    If PEM contains multiple entities, the first entity will be used.
    """
    certificate_lines = []
    if pem_content is not None:
        lines = pem_content.splitlines()
    elif pem_filename is not None:
        try:
            with open(pem_filename, "r", encoding="utf-8") as f:
                lines = list(f)
        except Exception as err:
            raise ModuleFailException(
                f"cannot load PEM file {pem_filename}: {err}",
                exception=traceback.format_exc(),
            ) from err
    else:
        raise ModuleFailException(
            "One of pem_filename and pem_content must be provided"
        )
    header_line_count = 0
    for line in lines:
        if line.startswith("-----"):
            header_line_count += 1
            if header_line_count == 2:
                # If certificate file contains other certs appended
                # (like intermediate certificates), ignore these.
                break
            continue
        certificate_lines.append(line.strip())
    return base64.b64decode("".join(certificate_lines))


def process_links(
    *, info: dict[str, t.Any], callback: Callable[[str, str], None]
) -> None:
    """
    Process link header, calls callback for every link header with the URL and relation as options.

    https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Link
    """
    if "link" in info:
        link = info["link"]
        for url, relation in re.findall(r'<([^>]+)>;\s*rel="(\w+)"', link):
            callback(unquote(url), relation)


def parse_retry_after(
    value: str,
    *,
    relative_with_timezone: bool = True,
    now: datetime.datetime | None = None,
) -> datetime.datetime:
    """
    Parse the value of a Retry-After header and return a timestamp.

    https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Retry-After
    """
    # First try a number of seconds
    try:
        delta = datetime.timedelta(seconds=int(value))
        if now is None:
            now = get_now_datetime(with_timezone=relative_with_timezone)
        return now + delta
    except ValueError:
        pass

    try:
        return datetime.datetime.strptime(value, "%a, %d %b %Y %H:%M:%S GMT")
    except ValueError:
        pass

    raise ValueError(f"Cannot parse Retry-After header value {repr(value)}")


def compute_cert_id(
    *,
    backend: CryptoBackend,
    cert_info: CertificateInformation | None = None,
    cert_filename: str | os.PathLike | None = None,
    cert_content: str | bytes | None = None,
    none_if_required_information_is_missing: bool = False,
) -> str | None:
    # Obtain certificate info if not provided
    if cert_info is None:
        cert_info = backend.get_cert_information(
            cert_filename=cert_filename, cert_content=cert_content
        )

    # Convert Authority Key Identifier to string
    if cert_info.authority_key_identifier is None:
        if none_if_required_information_is_missing:
            return None
        raise ModuleFailException(
            "Certificate has no Authority Key Identifier extension"
        )
    aki = (
        (base64.urlsafe_b64encode(cert_info.authority_key_identifier))
        .decode("ascii")
        .replace("=", "")
    )

    # Convert serial number to string
    serial_bytes = convert_int_to_bytes(cert_info.serial_number)
    if ord(serial_bytes[:1]) >= 128:
        serial_bytes = b"\x00" + serial_bytes
    serial = (base64.urlsafe_b64encode(serial_bytes)).decode("ascii").replace("=", "")

    # Compose cert ID
    return f"{aki}.{serial}"


__all__ = (
    "nopad_b64",
    "der_to_pem",
    "pem_to_der",
    "process_links",
    "parse_retry_after",
    "compute_cert_id",
)
