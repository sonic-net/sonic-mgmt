# Copyright (c) 2016 Michael Gruener <michael.gruener@chaosmoon.net>
# Copyright (c) 2021 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import copy
import datetime
import json
import locale
import time
import typing as t

from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.common.text.converters import to_bytes
from ansible.module_utils.urls import fetch_url

from ansible_collections.community.crypto.plugins.module_utils._acme.backend_cryptography import (
    CRYPTOGRAPHY_ERROR,
    CRYPTOGRAPHY_MINIMAL_VERSION,
    CRYPTOGRAPHY_VERSION,
    HAS_CURRENT_CRYPTOGRAPHY,
    CryptographyBackend,
)
from ansible_collections.community.crypto.plugins.module_utils._acme.backend_openssl_cli import (
    OpenSSLCLIBackend,
)
from ansible_collections.community.crypto.plugins.module_utils._acme.errors import (
    ACMEProtocolException,
    KeyParsingError,
    ModuleFailException,
    NetworkException,
    format_http_status,
)
from ansible_collections.community.crypto.plugins.module_utils._acme.utils import (
    compute_cert_id,
    nopad_b64,
    parse_retry_after,
)
from ansible_collections.community.crypto.plugins.module_utils._argspec import (
    ArgumentSpec,
)
from ansible_collections.community.crypto.plugins.module_utils._time import (
    get_now_datetime,
)


if t.TYPE_CHECKING:
    import http.client  # pragma: no cover
    import os  # pragma: no cover
    import urllib.error  # pragma: no cover

    from ansible.module_utils.basic import AnsibleModule  # pragma: no cover

    from ansible_collections.community.crypto.plugins.module_utils._acme.backends import (  # pragma: no cover
        CertificateInformation,
        CryptoBackend,
    )


# -1 usually means connection problems
RETRY_STATUS_CODES = (-1, 408, 429, 502, 503, 504)

RETRY_COUNT = 20


def _decode_retry(
    *,
    module: AnsibleModule,
    response: urllib.error.HTTPError | http.client.HTTPResponse | None,
    info: dict[str, t.Any],
    retry_count: int,
) -> bool:
    if info["status"] not in RETRY_STATUS_CODES:
        return False

    if retry_count >= RETRY_COUNT:
        raise ACMEProtocolException(
            module=module,
            msg=f"Giving up after {RETRY_COUNT} retries",
            info=info,
            response=response,
        )

    # 429 and 503 should have a Retry-After header (https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Retry-After)
    now = get_now_datetime(with_timezone=True)
    try:
        then = parse_retry_after(
            info.get("retry-after", "10"), relative_with_timezone=True, now=now
        )
        retry_after = (then - now).total_seconds()
        retry_after = min(max(1, retry_after), 60)
    except (TypeError, ValueError):
        retry_after = 10
    module.log(
        f"Retrieved a {format_http_status(info['status'])} HTTP status on {info['url']}, retrying in {retry_after} seconds"
    )

    time.sleep(retry_after)
    return True


def _assert_fetch_url_success(
    *,
    module: AnsibleModule,
    response: urllib.error.HTTPError | http.client.HTTPResponse | None,
    info: dict[str, t.Any],
    allow_redirect: bool = False,
    allow_client_error: bool = True,
    allow_server_error: bool = True,
) -> None:
    if info["status"] < 0:
        raise NetworkException(msg=f"Failure downloading {info['url']}, {info['msg']}")

    if (
        (300 <= info["status"] < 400 and not allow_redirect)
        or (400 <= info["status"] < 500 and not allow_client_error)
        or (info["status"] >= 500 and not allow_server_error)
    ):
        raise ACMEProtocolException(module=module, info=info, response=response)


def _is_failed(
    *, info: dict[str, t.Any], expected_status_codes: t.Iterable[int] | None = None
) -> bool:
    if info["status"] < 200 or info["status"] >= 400:
        return True
    return bool(
        expected_status_codes is not None
        and info["status"] not in expected_status_codes
    )


class ACMEDirectory:
    """
    The ACME server directory. Gives access to the available resources,
    and allows to obtain a Replay-Nonce. The acme_directory URL
    needs to support unauthenticated GET requests; ACME endpoints
    requiring authentication are not supported.
    https://tools.ietf.org/html/rfc8555#section-7.1.1
    """

    def __init__(self, *, module: AnsibleModule, client: ACMEClient) -> None:
        self.module = module
        self.directory_root = module.params["acme_directory"]
        self.version = module.params["acme_version"]

        directory, info = client.get_request(self.directory_root, get_only=True)
        if not isinstance(directory, dict):
            raise ACMEProtocolException(
                module=module,
                msg=f"ACME directory is not a dictionary, but {type(directory)}",
                info=info,
                content_json=directory,
            )
        self.directory = directory

        self.request_timeout = module.params["request_timeout"]

        # Check whether self.version matches what we expect
        if self.version == 2:
            for key in ("newNonce", "newAccount", "newOrder"):
                if key not in self.directory:
                    raise ModuleFailException(
                        "ACME directory does not seem to follow protocol ACME v2"
                    )
            # Make sure that 'meta' is always available
            if "meta" not in self.directory:
                self.directory["meta"] = {}

    def __getitem__(self, key: str) -> t.Any:
        return self.directory[key]

    def __contains__(self, key: str) -> bool:
        return key in self.directory

    def get(self, key: str, default_value: t.Any = None) -> t.Any:
        return self.directory.get(key, default_value)

    def get_nonce(self, resource: str | None = None) -> str:
        url = self.directory["newNonce"]
        if resource is not None:
            url = resource
        retry_count = 0
        while True:
            response, info = fetch_url(
                self.module, url, method="HEAD", timeout=self.request_timeout
            )
            if _decode_retry(
                module=self.module,
                response=response,
                info=info,
                retry_count=retry_count,
            ):
                retry_count += 1
                continue
            if info["status"] not in (200, 204):
                raise NetworkException(
                    f"Failed to get replay-nonce, got status {format_http_status(info['status'])}"
                )
            if "replay-nonce" in info:
                return info["replay-nonce"]
            self.module.log(
                f"HEAD to {url} did return status {format_http_status(info['status'])}, but no replay-nonce header!"
            )
            if retry_count >= 5:
                raise ACMEProtocolException(
                    module=self.module,
                    msg="Was not able to obtain nonce, giving up after 5 retries",
                    info=info,
                    response=response,
                )
            retry_count += 1

    def has_renewal_info_endpoint(self) -> bool:
        return "renewalInfo" in self.directory


class ACMEClient:
    """
    ACME client object. Handles the authorized communication with the
    ACME server.
    """

    def __init__(self, *, module: AnsibleModule, backend: CryptoBackend) -> None:
        # Set to true to enable logging of all signed requests
        self._debug = False

        self.module = module
        self.backend = backend
        self.version = module.params["acme_version"]
        # account_key path and content are mutually exclusive
        self.account_key_file = module.params.get("account_key_src")
        self.account_key_content = module.params.get("account_key_content")
        self.account_key_passphrase = module.params.get("account_key_passphrase")

        # Grab account URI from module parameters.
        # Make sure empty string is treated as None.
        self.account_uri = module.params.get("account_uri") or None

        self.request_timeout = module.params["request_timeout"]

        self.account_key_data = None
        self.account_jwk = None
        self.account_jws_header = None
        if self.account_key_file is not None or self.account_key_content is not None:
            try:
                self.account_key_data = self.parse_key(
                    key_file=self.account_key_file,
                    key_content=self.account_key_content,
                    passphrase=self.account_key_passphrase,
                )
            except KeyParsingError as e:
                raise ModuleFailException(
                    f"Error while parsing account key: {e.msg}"
                ) from e
            self.account_jwk = self.account_key_data["jwk"]
            self.account_jws_header = {
                "alg": self.account_key_data["alg"],
                "jwk": self.account_jwk,
            }
            if self.account_uri:
                # Make sure self.account_jws_header is updated
                self.set_account_uri(self.account_uri)

        self.directory = ACMEDirectory(module=module, client=self)

    def set_account_uri(self, uri: str) -> None:
        """
        Set account URI. For ACME v2, it needs to be used to sending signed
        requests.
        """
        self.account_uri = uri
        if self.account_jws_header:
            self.account_jws_header.pop("jwk", None)
            self.account_jws_header["kid"] = self.account_uri

    def parse_key(
        self,
        *,
        key_file: str | os.PathLike | None = None,
        key_content: str | None = None,
        passphrase: str | None = None,
    ) -> dict[str, t.Any]:
        """
        Parses an RSA or Elliptic Curve key file in PEM format and returns key_data.
        In case of an error, raises KeyParsingError.
        """
        if key_file is None and key_content is None:
            raise AssertionError(
                "One of key_file and key_content must be specified!"
            )  # pragma: no cover
        return self.backend.parse_key(
            key_file=key_file, key_content=key_content, passphrase=passphrase
        )

    @t.overload
    def sign_request(
        self,
        *,
        protected: dict[str, t.Any],
        payload: dict[str, t.Any] | None,
        key_data: dict[str, t.Any],
        encode_payload: t.Literal[True] = True,
    ) -> dict[str, t.Any]: ...

    @t.overload
    def sign_request(
        self,
        *,
        protected: dict[str, t.Any],
        payload: str | bytes | None,
        key_data: dict[str, t.Any],
        encode_payload: t.Literal[False],
    ) -> dict[str, t.Any]: ...

    @t.overload
    def sign_request(
        self,
        *,
        protected: dict[str, t.Any],
        payload: str | bytes | dict[str, t.Any] | None,
        key_data: dict[str, t.Any],
        encode_payload: bool = True,
    ) -> dict[str, t.Any]: ...

    def sign_request(
        self,
        *,
        protected: dict[str, t.Any],
        payload: str | bytes | dict[str, t.Any] | None,
        key_data: dict[str, t.Any],
        encode_payload: bool = True,
    ) -> dict[str, t.Any]:
        """
        Signs an ACME request.
        """
        try:
            if payload is None:
                # POST-as-GET
                payload64 = ""
            else:
                # POST
                if encode_payload:
                    payload = self.module.jsonify(payload).encode("utf8")
                payload64 = nopad_b64(to_bytes(payload))
            protected64 = nopad_b64(self.module.jsonify(protected).encode("utf8"))
        except Exception as e:
            raise ModuleFailException(
                f"Failed to encode payload / headers as JSON: {e}"
            ) from e

        return self.backend.sign(
            payload64=payload64, protected64=protected64, key_data=key_data
        )

    def _log(self, msg: str, *, data: t.Any = None) -> None:
        """
        Write arguments to acme.log when logging is enabled.
        """
        if self._debug:
            with open("acme.log", "ab") as f:
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%s")
                f.write(f"[{timestamp}] {msg}\n".encode("utf-8"))
                if data is not None:
                    f.write(
                        f"{json.dumps(data, indent=2, sort_keys=True)}\n\n".encode(
                            "utf-8"
                        )
                    )

    @t.overload
    def send_signed_request(
        self,
        url: str,
        payload: dict[str, t.Any] | None,
        *,
        key_data: dict[str, t.Any] | None = None,
        jws_header: dict[str, t.Any] | None = None,
        parse_json_result: t.Literal[True] = True,
        encode_payload: t.Literal[True] = True,
        fail_on_error: bool = True,
        error_msg: str | None = None,
        expected_status_codes: t.Iterable[int] | None = None,
    ) -> tuple[object | bytes, dict[str, t.Any]]: ...

    @t.overload
    def send_signed_request(
        self,
        url: str,
        payload: str | bytes | None,
        *,
        key_data: dict[str, t.Any] | None = None,
        jws_header: dict[str, t.Any] | None = None,
        parse_json_result: t.Literal[True] = True,
        encode_payload: t.Literal[False],
        fail_on_error: bool = True,
        error_msg: str | None = None,
        expected_status_codes: t.Iterable[int] | None = None,
    ) -> tuple[object | bytes, dict[str, t.Any]]: ...

    @t.overload
    def send_signed_request(
        self,
        url: str,
        payload: dict[str, t.Any] | None,
        *,
        key_data: dict[str, t.Any] | None = None,
        jws_header: dict[str, t.Any] | None = None,
        parse_json_result: t.Literal[False],
        encode_payload: t.Literal[True] = True,
        fail_on_error: bool = True,
        error_msg: str | None = None,
        expected_status_codes: t.Iterable[int] | None = None,
    ) -> tuple[bytes, dict[str, t.Any]]: ...

    @t.overload
    def send_signed_request(
        self,
        url: str,
        payload: str | bytes | None,
        *,
        key_data: dict[str, t.Any] | None = None,
        jws_header: dict[str, t.Any] | None = None,
        parse_json_result: t.Literal[False],
        encode_payload: t.Literal[False],
        fail_on_error: bool = True,
        error_msg: str | None = None,
        expected_status_codes: t.Iterable[int] | None = None,
    ) -> tuple[bytes, dict[str, t.Any]]: ...

    def send_signed_request(
        self,
        url: str,
        payload: str | bytes | dict[str, t.Any] | None,
        *,
        key_data: dict[str, t.Any] | None = None,
        jws_header: dict[str, t.Any] | None = None,
        parse_json_result: bool = True,
        encode_payload: bool = True,
        fail_on_error: bool = True,
        error_msg: str | None = None,
        expected_status_codes: t.Iterable[int] | None = None,
    ) -> tuple[object | bytes, dict[str, t.Any]]:
        """
        Sends a JWS signed HTTP POST request to the ACME server and returns
        the response as dictionary (if parse_json_result is True) or in raw form
        (if parse_json_result is False).
        https://tools.ietf.org/html/rfc8555#section-6.2

        If payload is None, a POST-as-GET is performed.
        (https://tools.ietf.org/html/rfc8555#section-6.3)
        """
        key_data = key_data or self.account_key_data
        if key_data is None:
            raise ModuleFailException("Missing key data")
        jws_header = jws_header or self.account_jws_header
        if jws_header is None:
            raise ModuleFailException("Missing JWS header")
        failed_tries = 0
        while True:
            protected = copy.deepcopy(jws_header)
            protected["nonce"] = self.directory.get_nonce()
            protected["url"] = url

            self._log("URL", data=url)
            self._log("protected", data=protected)
            self._log("payload", data=payload)
            data = self.sign_request(
                protected=protected,
                payload=payload,
                key_data=key_data,
                encode_payload=encode_payload,
            )
            self._log("signed request", data=data)
            data_str = self.module.jsonify(data)

            headers = {
                "Content-Type": "application/jose+json",
            }
            resp, info = fetch_url(
                self.module,
                url,
                data=data_str,
                headers=headers,
                method="POST",
                timeout=self.request_timeout,
            )
            if _decode_retry(
                module=self.module, response=resp, info=info, retry_count=failed_tries
            ):
                failed_tries += 1
                continue
            _assert_fetch_url_success(module=self.module, response=resp, info=info)
            result: object | bytes = {}

            try:
                # In Python 2, reading from a closed response yields a TypeError.
                # In Python 3, read() simply returns ''
                if resp.closed:
                    raise TypeError
                content = resp.read()
            except (AttributeError, TypeError):
                content = info.pop("body", None)

            if content or not parse_json_result:
                if (
                    parse_json_result
                    and info["content-type"].startswith("application/json")
                ) or 400 <= info["status"] < 600:
                    try:
                        decoded_result = self.module.from_json(content.decode("utf8"))
                        self._log("parsed result", data=decoded_result)
                        # In case of badNonce error, try again (up to 5 times)
                        # (https://tools.ietf.org/html/rfc8555#section-6.7)
                        if (
                            400 <= info["status"] < 600
                            and failed_tries <= 5
                            and isinstance(decoded_result, dict)
                            and decoded_result.get("type")
                            == "urn:ietf:params:acme:error:badNonce"
                        ):
                            failed_tries += 1
                            continue
                        if parse_json_result:
                            result = decoded_result
                        else:
                            result = content
                    except ValueError as exc:
                        raise NetworkException(
                            f"Failed to parse the ACME response: {url} {content}"
                        ) from exc
                else:
                    result = content

            if fail_on_error and _is_failed(
                info=info, expected_status_codes=expected_status_codes
            ):
                raise ACMEProtocolException(
                    module=self.module,
                    msg=error_msg,
                    info=info,
                    content=content,
                    content_json=result if parse_json_result else None,
                )
            return result, info

    @t.overload
    def get_request(
        self,
        uri: str,
        *,
        parse_json_result: t.Literal[True] = True,
        headers: dict[str, str] | None = None,
        get_only: bool = False,
        fail_on_error: bool = True,
        error_msg: str | None = None,
        expected_status_codes: t.Iterable[int] | None = None,
    ) -> tuple[object, dict[str, t.Any]]: ...

    @t.overload
    def get_request(
        self,
        uri: str,
        *,
        parse_json_result: t.Literal[False],
        headers: dict[str, str] | None = None,
        get_only: bool = False,
        fail_on_error: bool = True,
        error_msg: str | None = None,
        expected_status_codes: t.Iterable[int] | None = None,
    ) -> tuple[bytes, dict[str, t.Any]]: ...

    def get_request(
        self,
        uri: str,
        *,
        parse_json_result: bool = True,
        headers: dict[str, str] | None = None,
        get_only: bool = False,
        fail_on_error: bool = True,
        error_msg: str | None = None,
        expected_status_codes: t.Iterable[int] | None = None,
    ) -> tuple[object | bytes, dict[str, t.Any]]:
        """
        Perform a GET-like request. Will try POST-as-GET for ACMEv2, with fallback
        to GET if server replies with a status code of 405.
        """
        if not get_only:
            # Try POST-as-GET
            content, info = self.send_signed_request(
                uri, None, parse_json_result=False, fail_on_error=False
            )
            if info["status"] == 405:
                # Instead, do unauthenticated GET
                get_only = True
        else:
            # Do unauthenticated GET
            get_only = True

        if get_only:
            # Perform unauthenticated GET
            retry_count = 0
            while True:
                resp, info = fetch_url(
                    self.module,
                    uri,
                    method="GET",
                    headers=headers,
                    timeout=self.request_timeout,
                )
                if not _decode_retry(
                    module=self.module,
                    response=resp,
                    info=info,
                    retry_count=retry_count,
                ):
                    break
                retry_count += 1

            _assert_fetch_url_success(module=self.module, response=resp, info=info)

            try:
                # In Python 2, reading from a closed response yields a TypeError.
                # In Python 3, read() simply returns ''
                if resp.closed:
                    raise TypeError
                content = resp.read()
            except (AttributeError, TypeError):
                content = info.pop("body", None)

        # Process result
        parsed_json_result = False
        result: object | bytes
        if parse_json_result:
            result = {}
            if content:
                if info["content-type"].startswith("application/json"):
                    try:
                        result = self.module.from_json(content.decode("utf8"))
                        parsed_json_result = True
                    except ValueError as exc:
                        raise NetworkException(
                            f"Failed to parse the ACME response: {uri} {content!r}"
                        ) from exc
                else:
                    result = content
        else:
            result = content

        if fail_on_error and _is_failed(
            info=info, expected_status_codes=expected_status_codes
        ):
            raise ACMEProtocolException(
                module=self.module,
                msg=error_msg,
                info=info,
                content=content,
                content_json=(
                    t.cast(dict[str, t.Any], result) if parsed_json_result else None
                ),
            )
        return result, info

    def get_renewal_info(
        self,
        *,
        cert_id: str | None = None,
        cert_info: CertificateInformation | None = None,
        cert_filename: str | os.PathLike | None = None,
        cert_content: str | bytes | None = None,
        include_retry_after: bool = False,
        retry_after_relative_with_timezone: bool = True,
    ) -> dict[str, t.Any]:
        if not self.directory.has_renewal_info_endpoint():
            raise ModuleFailException(
                "The ACME endpoint does not support ACME Renewal Information retrieval"
            )

        if cert_id is None:
            cert_id = compute_cert_id(
                backend=self.backend,
                cert_info=cert_info,
                cert_filename=cert_filename,
                cert_content=cert_content,
            )
        url = f"{self.directory.directory['renewalInfo'].rstrip('/')}/{cert_id}"

        data, info = self.get_request(
            url, parse_json_result=True, fail_on_error=True, get_only=True
        )
        if not isinstance(data, dict):
            raise ACMEProtocolException(
                module=self.module,
                msg="Unexpected renewal information",
                info=info,
                content_json=data,
            )

        # Include Retry-After header if asked for
        if include_retry_after and "retry-after" in info:
            try:
                data["retryAfter"] = parse_retry_after(
                    info["retry-after"],
                    relative_with_timezone=retry_after_relative_with_timezone,
                )
            except ValueError:
                pass
        return data


def create_default_argspec(
    *,
    with_account: bool = True,
    require_account_key: bool = True,
    with_certificate: bool = False,
) -> ArgumentSpec:
    """
    Provides default argument spec for the options documented in the acme doc fragment.
    """
    result = ArgumentSpec(
        argument_spec={
            "acme_directory": {"type": "str", "required": True},
            "acme_version": {"type": "int", "choices": [2], "default": 2},
            "validate_certs": {"type": "bool", "default": True},
            "select_crypto_backend": {
                "type": "str",
                "default": "auto",
                "choices": ["auto", "openssl", "cryptography"],
            },
            "request_timeout": {"type": "int", "default": 10},
        },
    )
    if with_account:
        result.update_argspec(
            account_key_src={"type": "path", "aliases": ["account_key"]},
            account_key_content={"type": "str", "no_log": True},
            account_key_passphrase={"type": "str", "no_log": True},
            account_uri={"type": "str"},
        )
        if require_account_key:
            result.update(required_one_of=[["account_key_src", "account_key_content"]])
        result.update(mutually_exclusive=[["account_key_src", "account_key_content"]])
    if with_certificate:
        result.update_argspec(
            csr={"type": "path"},
            csr_content={"type": "str"},
        )
        result.update(
            required_one_of=[["csr", "csr_content"]],
            mutually_exclusive=[["csr", "csr_content"]],
        )
    return result


def create_backend(
    module: AnsibleModule, *, needs_acme_v2: bool = True
) -> CryptoBackend:
    backend = module.params["select_crypto_backend"]

    # Backend autodetect
    if backend == "auto":
        backend = "cryptography" if HAS_CURRENT_CRYPTOGRAPHY else "openssl"

    # Create backend object
    module_backend: CryptoBackend
    if backend == "cryptography":
        if CRYPTOGRAPHY_ERROR is not None:
            # Either we could not import cryptography at all, or there was an unexpected error
            if CRYPTOGRAPHY_VERSION is None:
                msg = missing_required_lib("cryptography")
            else:
                msg = f"Unexpected error while preparing cryptography: {CRYPTOGRAPHY_ERROR.splitlines()[-1]}"
            module.fail_json(msg=msg, exception=CRYPTOGRAPHY_ERROR)
        if not HAS_CURRENT_CRYPTOGRAPHY:
            # We succeeded importing cryptography, but its version is too old.
            mrl = missing_required_lib(
                f"cryptography >= {CRYPTOGRAPHY_MINIMAL_VERSION}"
            )
            module.fail_json(
                msg=f"Found cryptography, but only version {CRYPTOGRAPHY_VERSION}. {mrl}"
            )
        module.debug(
            f"Using cryptography backend (library version {CRYPTOGRAPHY_VERSION})"
        )
        module_backend = CryptographyBackend(module=module)
    elif backend == "openssl":
        module.debug("Using OpenSSL binary backend")
        module_backend = OpenSSLCLIBackend(module=module)
    else:
        module.fail_json(msg=f'Unknown crypto backend "{backend}"!')

    # Check common module parameters
    if not module.params["validate_certs"]:
        module.warn(
            "Disabling certificate validation for communications with ACME endpoint. "
            "This should only be done for testing against a local ACME server for "
            "development purposes, but *never* for production purposes."
        )

    # AnsibleModule() changes the locale, so change it back to C because we rely
    # on datetime.datetime.strptime() when parsing certificate dates.
    locale.setlocale(locale.LC_ALL, "C")

    return module_backend


__all__ = (
    "ACMEDirectory",
    "ACMEClient",
    "create_default_argspec",
    "create_backend",
)
