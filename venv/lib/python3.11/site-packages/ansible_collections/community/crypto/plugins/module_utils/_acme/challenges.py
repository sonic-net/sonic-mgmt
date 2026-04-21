# Copyright (c) 2016 Michael Gruener <michael.gruener@chaosmoon.net>
# Copyright (c) 2021 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import time
import typing as t

from ansible.module_utils.common.text.converters import to_bytes

from ansible_collections.community.crypto.plugins.module_utils._acme.errors import (
    ACMEProtocolException,
    ModuleFailException,
    format_error_problem,
)
from ansible_collections.community.crypto.plugins.module_utils._acme.utils import (
    nopad_b64,
)


if t.TYPE_CHECKING:
    from ansible.module_utils.basic import AnsibleModule  # pragma: no cover

    from ansible_collections.community.crypto.plugins.module_utils._acme.acme import (  # pragma: no cover
        ACMEClient,
    )


def create_key_authorization(*, client: ACMEClient, token: str) -> str:
    """
    Returns the key authorization for the given token
    https://tools.ietf.org/html/rfc8555#section-8.1
    """
    accountkey_json = json.dumps(
        client.account_jwk, sort_keys=True, separators=(",", ":")
    )
    thumbprint = nopad_b64(hashlib.sha256(accountkey_json.encode("utf8")).digest())
    return f"{token}.{thumbprint}"


def combine_identifier(*, identifier_type: str, identifier: str) -> str:
    return f"{identifier_type}:{identifier}"


def normalize_combined_identifier(identifier: str) -> str:
    identifier_type, identifier = split_identifier(identifier)
    # Normalize DNS names and IPs
    identifier = identifier.lower()
    return combine_identifier(identifier_type=identifier_type, identifier=identifier)


def split_identifier(identifier: str) -> tuple[str, str]:
    parts = identifier.split(":", 1)
    if len(parts) != 2:
        raise ModuleFailException(
            f'Identifier "{identifier}" is not of the form <type>:<identifier>'
        )
    return parts[0], parts[1]


_Challenge = t.TypeVar("_Challenge", bound="Challenge")


class Challenge:
    def __init__(self, *, data: dict[str, t.Any], url: str) -> None:
        self.data = data

        self.type: str = data["type"]
        self.url = url
        self.status: str = data["status"]
        self.token: str | None = data.get("token")

    @classmethod
    def from_json(
        cls: type[_Challenge],
        *,
        client: ACMEClient,
        data: dict[str, t.Any],
        url: str | None = None,
    ) -> _Challenge:
        return cls(data=data, url=url or data["url"])

    def call_validate(self, client: ACMEClient) -> None:
        challenge_response: dict[str, t.Any] = {}
        client.send_signed_request(
            self.url,
            challenge_response,
            error_msg="Failed to validate challenge",
            expected_status_codes=[200, 202],
        )

    def to_json(self) -> dict[str, t.Any]:
        return self.data.copy()

    def get_validation_data(
        self, *, client: ACMEClient, identifier_type: str, identifier: str
    ) -> dict[str, t.Any] | None:
        if self.token is None:
            return None

        token = re.sub(r"[^A-Za-z0-9_\-]", "_", self.token)
        key_authorization = create_key_authorization(client=client, token=token)

        if self.type == "http-01":
            # https://tools.ietf.org/html/rfc8555#section-8.3
            return {
                "resource": f".well-known/acme-challenge/{token}",
                "resource_value": key_authorization,
            }

        if self.type == "dns-01":
            if identifier_type != "dns":
                return None
            # https://tools.ietf.org/html/rfc8555#section-8.4
            resource = "_acme-challenge"
            value = nopad_b64(hashlib.sha256(to_bytes(key_authorization)).digest())
            record = f"{resource}.{identifier[2:] if identifier.startswith('*.') else identifier}"
            return {
                "resource": resource,
                "resource_value": value,
                "record": record,
            }

        if self.type == "tls-alpn-01":
            # https://www.rfc-editor.org/rfc/rfc8737.html#section-3
            if identifier_type == "ip":
                # IPv4/IPv6 address: use reverse mapping (RFC1034, RFC3596)
                resource = ipaddress.ip_address(identifier).reverse_pointer
                if not resource.endswith("."):
                    resource += "."
            else:
                resource = identifier
            b_value = base64.b64encode(
                hashlib.sha256(to_bytes(key_authorization)).digest()
            )
            return {
                "resource": resource,
                "resource_original": combine_identifier(
                    identifier_type=identifier_type, identifier=identifier
                ),
                "resource_value": b_value,
            }

        # Unknown challenge type: ignore
        return None


_Authorization = t.TypeVar("_Authorization", bound="Authorization")


class Authorization:
    def __init__(self, *, url: str) -> None:
        self.url = url

        self.data: dict[str, t.Any] | None = None
        self.challenges: list[Challenge] = []
        self.status: str | None = None
        self.identifier_type: str | None = None
        self.identifier: str | None = None

    def _setup(self, *, client: ACMEClient, data: dict[str, t.Any]) -> None:
        data["uri"] = self.url
        self.data = data
        # While 'challenges' is a required field, apparently not every CA cares
        # (https://github.com/ansible-collections/community.crypto/issues/824)
        if data.get("challenges"):
            self.challenges = [
                Challenge.from_json(client=client, data=challenge)
                for challenge in data["challenges"]
            ]
        else:
            self.challenges = []
        self.status = data["status"]
        self.identifier = data["identifier"]["value"]
        self.identifier_type = data["identifier"]["type"]
        if data.get("wildcard", False):
            self.identifier = f"*.{self.identifier}"

    @classmethod
    def from_json(
        cls: type[_Authorization],
        *,
        client: ACMEClient,
        data: dict[str, t.Any],
        url: str,
    ) -> _Authorization:
        result = cls(url=url)
        result._setup(client=client, data=data)
        return result

    @classmethod
    def from_url(
        cls: type[_Authorization], *, client: ACMEClient, url: str
    ) -> _Authorization:
        result = cls(url=url)
        result.refresh(client=client)
        return result

    @classmethod
    def create(
        cls: type[_Authorization],
        *,
        client: ACMEClient,
        identifier_type: str,
        identifier: str,
    ) -> _Authorization:
        """
        Create a new authorization for the given identifier.
        Return the authorization object of the new authorization
        https://tools.ietf.org/html/draft-ietf-acme-acme-02#section-6.4
        """
        new_authz = {
            "identifier": {
                "type": identifier_type,
                "value": identifier,
            },
        }
        if "newAuthz" not in client.directory.directory:
            raise ACMEProtocolException(
                module=client.module,
                msg="ACME endpoint does not support pre-authorization",
            )
        url = client.directory["newAuthz"]

        result, info = client.send_signed_request(
            url,
            new_authz,
            error_msg="Failed to request challenges",
            expected_status_codes=[200, 201],
        )
        if not isinstance(result, dict):
            raise ACMEProtocolException(
                module=client.module,
                msg="Unexpected authorization creation result",
                content_json=result,
            )
        return cls.from_json(client=client, data=result, url=info["location"])

    @property
    def combined_identifier(self) -> str:
        if self.identifier_type is None or self.identifier is None:
            raise ValueError("Data not present")
        return combine_identifier(
            identifier_type=self.identifier_type, identifier=self.identifier
        )

    def to_json(self) -> dict[str, t.Any]:
        if self.data is None:
            raise ValueError("Data not present")
        return self.data.copy()

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

    def get_challenge_data(self, *, client: ACMEClient) -> dict[str, t.Any]:
        """
        Returns a dict with the data for all proposed (and supported) challenges
        of the given authorization.
        """
        if self.identifier_type is None or self.identifier is None:
            raise ValueError("Data not present")
        data = {}
        for challenge in self.challenges:
            validation_data = challenge.get_validation_data(
                client=client,
                identifier_type=self.identifier_type,
                identifier=self.identifier,
            )
            if validation_data is not None:
                data[challenge.type] = validation_data
        return data

    def raise_error(self, *, error_msg: str, module: AnsibleModule) -> t.NoReturn:
        """
        Aborts with a specific error for a challenge.
        """
        error_details = []
        # multiple challenges could have failed at this point, gather error
        # details for all of them before failing
        for challenge in self.challenges:
            if challenge.status == "invalid":
                msg = f"Challenge {challenge.type}"
                if "error" in challenge.data:
                    problem = format_error_problem(
                        challenge.data["error"],
                        subproblem_prefix=f"{challenge.type}.",
                    )
                    msg = f"{msg}: {problem}"
                error_details.append(msg)
        raise ACMEProtocolException(
            module=module,
            msg=f"Failed to validate challenge for {self.combined_identifier}: {error_msg}. {'; '.join(error_details)}",
            extras={
                "identifier": self.combined_identifier,
                "authorization": self.data,
            },
        )

    def find_challenge(self, *, challenge_type: str) -> Challenge | None:
        for challenge in self.challenges:
            if challenge_type == challenge.type:
                return challenge
        return None

    def wait_for_validation(self, *, client: ACMEClient) -> bool:
        while True:
            self.refresh(client=client)
            if self.status in ["valid", "invalid", "revoked"]:
                break
            time.sleep(2)

        if self.status == "invalid":
            self.raise_error(error_msg='Status is "invalid"', module=client.module)

        return self.status == "valid"

    def call_validate(
        self, *, client: ACMEClient, challenge_type: str, wait: bool = True
    ) -> bool:
        """
        Validate the authorization provided in the auth dict. Returns True
        when the validation was successful and False when it was not.
        """
        challenge = self.find_challenge(challenge_type=challenge_type)
        if challenge is None:
            raise ModuleFailException(
                f'Found no challenge of type "{challenge_type}" for identifier {self.combined_identifier}!'
            )

        challenge.call_validate(client)

        if not wait:
            return self.status == "valid"
        return self.wait_for_validation(client=client)

    def can_deactivate(self) -> bool:
        """
        Deactivates this authorization.
        https://community.letsencrypt.org/t/authorization-deactivation/19860/2
        https://tools.ietf.org/html/rfc8555#section-7.5.2
        """
        return self.status in ("valid", "pending")

    def deactivate(self, *, client: ACMEClient) -> bool | None:
        """
        Deactivates this authorization.
        https://community.letsencrypt.org/t/authorization-deactivation/19860/2
        https://tools.ietf.org/html/rfc8555#section-7.5.2
        """
        if not self.can_deactivate():
            return None
        authz_deactivate = {"status": "deactivated"}
        result, info = client.send_signed_request(
            self.url, authz_deactivate, fail_on_error=False
        )
        if (
            200 <= info["status"] < 300
            and isinstance(result, dict)
            and result.get("status") == "deactivated"
        ):
            self.status = "deactivated"
            return True
        return False

    @classmethod
    def deactivate_url(
        cls: type[_Authorization], *, client: ACMEClient, url: str
    ) -> _Authorization:
        """
        Deactivates this authorization.
        https://community.letsencrypt.org/t/authorization-deactivation/19860/2
        https://tools.ietf.org/html/rfc8555#section-7.5.2
        """
        authz = cls(url=url)
        authz_deactivate = {"status": "deactivated"}
        result, _info = client.send_signed_request(
            url, authz_deactivate, fail_on_error=True
        )
        if not isinstance(result, dict):
            raise ACMEProtocolException(
                module=client.module,
                msg="Unexpected challenge deactivation result",
                content_json=result,
            )
        authz._setup(client=client, data=result)
        return authz


def wait_for_validation(
    *, authzs: t.Iterable[Authorization], client: ACMEClient
) -> None:
    """
    Wait until a list of authz is valid. Fail if at least one of them is invalid or revoked.
    """
    while authzs:
        authzs_next = []
        for authz in authzs:
            authz.refresh(client=client)
            if authz.status in ["valid", "invalid", "revoked"]:
                if authz.status != "valid":
                    authz.raise_error(
                        error_msg='Status is not "valid"', module=client.module
                    )
            else:
                authzs_next.append(authz)
        if authzs_next:
            time.sleep(2)
        authzs = authzs_next


__all__ = (
    "create_key_authorization",
    "combine_identifier",
    "normalize_combined_identifier",
    "split_identifier",
    "Challenge",
    "Authorization",
    "wait_for_validation",
)
