# Copyright (c) 2016 Michael Gruener <michael.gruener@chaosmoon.net>
# Copyright (c) 2021 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import time
import typing as t
from collections.abc import Callable

from ansible_collections.community.crypto.plugins.module_utils._acme.challenges import (
    Authorization,
    normalize_combined_identifier,
)
from ansible_collections.community.crypto.plugins.module_utils._acme.errors import (
    ACMEProtocolException,
    ModuleFailException,
)
from ansible_collections.community.crypto.plugins.module_utils._acme.utils import (
    nopad_b64,
)


if t.TYPE_CHECKING:
    from ansible_collections.community.crypto.plugins.module_utils._acme.acme import (  # pragma: no cover
        ACMEClient,
    )


_Order = t.TypeVar("_Order", bound="Order")


class Order:
    def __init__(self, *, url: str) -> None:
        self.url = url

        self.data: dict[str, t.Any] | None = None

        self.status: str | None = None
        self.identifiers: list[tuple[str, str]] = []
        self.replaces_cert_id: str | None = None
        self.finalize_uri: str | None = None
        self.certificate_uri: str | None = None
        self.authorization_uris: list[str] = []
        self.authorizations: dict[str, Authorization] = {}

    def _setup(self, *, client: ACMEClient, data: dict[str, t.Any]) -> None:
        self.data = data

        self.status = data["status"]
        self.identifiers = []
        for identifier in data["identifiers"]:
            self.identifiers.append((identifier["type"], identifier["value"]))
        self.replaces_cert_id = data.get("replaces")
        self.finalize_uri = data.get("finalize")
        self.certificate_uri = data.get("certificate")
        self.authorization_uris = data["authorizations"]
        self.authorizations = {}

    @classmethod
    def from_json(
        cls: type[_Order], *, client: ACMEClient, data: dict[str, t.Any], url: str
    ) -> _Order:
        result = cls(url=url)
        result._setup(client=client, data=data)
        return result

    @classmethod
    def from_url(cls: type[_Order], *, client: ACMEClient, url: str) -> _Order:
        result = cls(url=url)
        result.refresh(client=client)
        return result

    @classmethod
    def create(
        cls: type[_Order],
        *,
        client: ACMEClient,
        identifiers: list[tuple[str, str]],
        replaces_cert_id: str | None = None,
        profile: str | None = None,
    ) -> _Order:
        """
        Start a new certificate order (ACME v2 protocol).
        https://tools.ietf.org/html/rfc8555#section-7.4
        """
        acme_identifiers = []
        for identifier_type, identifier in identifiers:
            acme_identifiers.append(
                {
                    "type": identifier_type,
                    "value": identifier,
                }
            )
        new_order: dict[str, t.Any] = {"identifiers": acme_identifiers}
        if replaces_cert_id is not None:
            new_order["replaces"] = replaces_cert_id
        if profile is not None:
            new_order["profile"] = profile
        result, info = client.send_signed_request(
            client.directory["newOrder"],
            new_order,
            error_msg="Failed to start new order",
            expected_status_codes=[201],
        )
        if not isinstance(result, dict):
            raise ACMEProtocolException(
                module=client.module,
                msg="Unexpected new order response",
                content_json=result,
            )
        return cls.from_json(client=client, data=result, url=info["location"])

    @classmethod
    def create_with_error_handling(
        cls: type[_Order],
        *,
        client: ACMEClient,
        identifiers: list[tuple[str, str]],
        error_strategy: t.Literal[
            "auto", "fail", "always", "retry_without_replaces_cert_id"
        ] = "auto",
        error_max_retries: int = 3,
        replaces_cert_id: str | None = None,
        profile: str | None = None,
        message_callback: Callable[[str], None] | None = None,
    ) -> _Order:
        """
        error_strategy can be one of the following strings:

        * ``fail``: simply fail. (Same behavior as ``Order.create()``.)
        * ``retry_without_replaces_cert_id``: if ``replaces_cert_id`` is not ``None``, set it to ``None`` and retry.
          The only exception is an error of type ``urn:ietf:params:acme:error:alreadyReplaced``, that indicates that
          the certificate was already replaced.
        * ``auto``: try to be clever. Right now this is identical to ``retry_without_replaces_cert_id``, but that can
          change at any time in the future.
        * ``always``: always retry until ``error_max_retries`` has been reached.
        """
        tries = 0
        while True:
            tries += 1
            try:
                return cls.create(
                    client=client,
                    identifiers=identifiers,
                    replaces_cert_id=replaces_cert_id,
                    profile=profile,
                )
            except ACMEProtocolException as exc:
                if tries <= error_max_retries + 1 and error_strategy != "fail":
                    if error_strategy == "always":
                        continue

                    if (
                        error_strategy in ("auto", "retry_without_replaces_cert_id")
                        and replaces_cert_id is not None
                        and not (
                            exc.error_code == 409
                            and exc.error_type
                            == "urn:ietf:params:acme:error:alreadyReplaced"
                        )
                    ):
                        if message_callback:
                            message_callback(
                                f"Stop passing `replaces={replaces_cert_id}` due to error {exc.error_code} {exc.error_type} when creating ACME order"
                            )
                        replaces_cert_id = None
                        continue

                raise

    def refresh(self, *, client: ACMEClient) -> bool:
        result, info = client.get_request(self.url)
        if not isinstance(result, dict):
            raise ACMEProtocolException(
                module=client.module,
                msg="Unexpected authorization data",
                info=info,
                content_json=result,
            )
        changed = self.data != result
        self._setup(client=client, data=result)
        return changed

    def load_authorizations(self, *, client: ACMEClient) -> None:
        for auth_uri in self.authorization_uris:
            authz = Authorization.from_url(client=client, url=auth_uri)
            self.authorizations[
                normalize_combined_identifier(authz.combined_identifier)
            ] = authz

    def wait_for_finalization(self, *, client: ACMEClient) -> None:
        while True:
            self.refresh(client=client)
            if self.status in ["valid", "invalid", "pending", "ready"]:
                break
            time.sleep(2)

        if self.status != "valid":
            raise ACMEProtocolException(
                module=client.module,
                msg=f'Failed to wait for order to complete; got status "{self.status}"',
                content_json=self.data,
            )

    def finalize(
        self, *, client: ACMEClient, csr_der: bytes, wait: bool = True
    ) -> None:
        """
        Create a new certificate based on the csr.
        Return the certificate object as dict
        https://tools.ietf.org/html/rfc8555#section-7.4
        """
        if self.finalize_uri is None:
            raise ModuleFailException("finalize_uri must be set")
        new_cert = {
            "csr": nopad_b64(csr_der),
        }
        result, info = client.send_signed_request(
            self.finalize_uri,
            new_cert,
            error_msg="Failed to finalizing order",
            expected_status_codes=[200],
        )
        # It is not clear from the RFC whether the finalize call returns the order object or not.
        # Instead of using the result, we call self.refresh(client) below.

        if wait:
            self.wait_for_finalization(client=client)
        else:
            self.refresh(client=client)
            if self.status not in ["procesing", "valid", "invalid"]:
                raise ACMEProtocolException(
                    module=client.module,
                    msg=f'Failed to finalize order; got status "{self.status}"',
                    info=info,
                    content_json=result,
                )


__all__ = ("Order",)
