# Copyright (c) 2024 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import os
import typing as t
from collections.abc import Callable

from ansible_collections.community.crypto.plugins.module_utils._acme.account import (
    ACMEAccount,
)
from ansible_collections.community.crypto.plugins.module_utils._acme.acme import (
    ACMEClient,
)
from ansible_collections.community.crypto.plugins.module_utils._acme.certificates import (
    CertificateChain,
    Criterium,
)
from ansible_collections.community.crypto.plugins.module_utils._acme.challenges import (
    Authorization,
    wait_for_validation,
)
from ansible_collections.community.crypto.plugins.module_utils._acme.errors import (
    ModuleFailException,
)
from ansible_collections.community.crypto.plugins.module_utils._acme.io import (
    write_file,
)
from ansible_collections.community.crypto.plugins.module_utils._acme.orders import Order
from ansible_collections.community.crypto.plugins.module_utils._acme.utils import (
    pem_to_der,
)


if t.TYPE_CHECKING:
    from ansible.module_utils.basic import AnsibleModule  # pragma: no cover

    from ansible_collections.community.crypto.plugins.module_utils._acme.backends import (  # pragma: no cover
        CryptoBackend,
    )
    from ansible_collections.community.crypto.plugins.module_utils._acme.certificates import (  # pragma: no cover
        ChainMatcher,
    )
    from ansible_collections.community.crypto.plugins.module_utils._acme.challenges import (  # pragma: no cover
        Challenge,
    )


class ACMECertificateClient:
    """
    ACME v2 client class. Uses an ACME account object and a CSR to
    start and validate ACME challenges and download the respective
    certificates.
    """

    def __init__(
        self,
        *,
        module: AnsibleModule,
        backend: CryptoBackend,
        client: ACMEClient | None = None,
        account: ACMEAccount | None = None,
    ) -> None:
        self.module = module
        self.version = module.params["acme_version"]
        self.csr = module.params.get("csr")
        self.csr_content = module.params.get("csr_content")
        if client is None:
            client = ACMEClient(module=module, backend=backend)
        self.client = client
        if account is None:
            account = ACMEAccount(client=self.client)
        self.account = account
        self.order_uri = module.params.get("order_uri")
        self.order_creation_error_strategy = module.params.get(
            "order_creation_error_strategy", "auto"
        )
        self.order_creation_max_retries = module.params.get(
            "order_creation_max_retries", 3
        )

        # Make sure account exists
        dummy, account_data = self.account.setup_account(allow_creation=False)
        if account_data is None:
            raise ModuleFailException(msg="Account does not exist or is deactivated.")

        if self.csr is not None and not os.path.exists(self.csr):
            raise ModuleFailException(f"CSR {self.csr} not found")

        # Extract list of identifiers from CSR
        if self.csr is not None or self.csr_content is not None:
            self.identifiers: list[tuple[str, str]] | None = (
                self.client.backend.get_ordered_csr_identifiers(
                    csr_filename=self.csr, csr_content=self.csr_content
                )
            )
        else:
            self.identifiers = None

    def parse_select_chain(
        self, select_chain: list[dict[str, t.Any]] | None
    ) -> list[ChainMatcher]:
        select_chain_matcher = []
        if select_chain:
            for criterium_idx, criterium in enumerate(select_chain):
                try:
                    select_chain_matcher.append(
                        self.client.backend.create_chain_matcher(
                            criterium=Criterium(
                                criterium=criterium, index=criterium_idx
                            )
                        )
                    )
                except ValueError as exc:
                    self.module.warn(
                        f"Error while parsing criterium: {exc}. Ignoring criterium."
                    )
        return select_chain_matcher

    def load_order(self) -> Order:
        if not self.order_uri:
            raise ModuleFailException("The order URI has not been provided")
        order = Order.from_url(client=self.client, url=self.order_uri)
        order.load_authorizations(client=self.client)
        return order

    def create_order(
        self, *, replaces_cert_id: str | None = None, profile: str | None = None
    ) -> Order:
        """
        Create a new order.
        """
        if self.identifiers is None:
            raise ModuleFailException("No identifiers have been provided")
        order = Order.create_with_error_handling(
            client=self.client,
            identifiers=self.identifiers,
            error_strategy=self.order_creation_error_strategy,
            error_max_retries=self.order_creation_max_retries,
            replaces_cert_id=replaces_cert_id,
            profile=profile,
            message_callback=self.module.warn,
        )
        self.order_uri = order.url
        order.load_authorizations(client=self.client)
        return order

    def get_challenges_data(
        self, order: Order
    ) -> tuple[list[dict[str, t.Any]], dict[str, list[str]]]:
        """
        Get challenge details.

        Return a tuple of generic challenge details, and specialized DNS challenge details.
        """
        data: list[dict[str, t.Any]] = []
        data_dns: dict[str, list[str]] = {}
        dns_challenge_type = "dns-01"
        for authz in order.authorizations.values():
            # Skip valid authentications: their challenges are already valid
            # and do not need to be returned
            if authz.status == "valid":
                continue
            challenge_data = authz.get_challenge_data(client=self.client)
            data.append(
                {
                    "identifier": authz.identifier,
                    "identifier_type": authz.identifier_type,
                    "challenges": challenge_data,
                }
            )
            dns_challenge = challenge_data.get(dns_challenge_type)
            if dns_challenge:
                values = data_dns.get(dns_challenge["record"])
                if values is None:
                    values = []
                    data_dns[dns_challenge["record"]] = values
                values.append(dns_challenge["resource_value"])
        return data, data_dns

    def check_that_authorizations_can_be_used(self, order: Order) -> None:
        bad_authzs = []
        for authz in order.authorizations.values():
            if authz.status not in ("valid", "pending"):
                bad_authzs.append(
                    f"{authz.combined_identifier} (status={authz.status!r})"
                )
        if bad_authzs:
            bad_authzs_str = ", ".join(sorted(bad_authzs))
            raise ModuleFailException(
                f"Some of the authorizations for the order are in a bad state, so the order can no longer be satisfied: {bad_authzs_str}",
            )

    def collect_invalid_authzs(self, order: Order) -> list[Authorization]:
        return [
            authz
            for authz in order.authorizations.values()
            if authz.status == "invalid"
        ]

    def collect_pending_authzs(self, order: Order) -> list[Authorization]:
        return [
            authz
            for authz in order.authorizations.values()
            if authz.status == "pending"
        ]

    def call_validate(
        self,
        pending_authzs: list[Authorization],
        *,
        get_challenge: Callable[[Authorization], str],
        wait: bool = True,
    ) -> list[tuple[Authorization, str, Challenge | None]]:
        authzs_with_challenges_to_wait_for = []
        for authz in pending_authzs:
            challenge_type = get_challenge(authz)
            authz.call_validate(
                client=self.client, challenge_type=challenge_type, wait=wait
            )
            authzs_with_challenges_to_wait_for.append(
                (
                    authz,
                    challenge_type,
                    authz.find_challenge(challenge_type=challenge_type),
                )
            )
        return authzs_with_challenges_to_wait_for

    def wait_for_validation(self, authzs_to_wait_for: list[Authorization]) -> None:
        wait_for_validation(authzs=authzs_to_wait_for, client=self.client)

    def _download_alternate_chains(
        self, cert: CertificateChain
    ) -> list[CertificateChain]:
        alternate_chains = []
        for alternate in cert.alternates:
            try:
                alt_cert = CertificateChain.download(client=self.client, url=alternate)
            except ModuleFailException as e:
                self.module.warn(
                    f"Error while downloading alternative certificate {alternate}: {e}"
                )
                continue
            if alt_cert.cert is not None:
                alternate_chains.append(alt_cert)
            else:
                self.module.warn(
                    f"Error while downloading alternative certificate {alternate}: no certificate found"
                )
        return alternate_chains

    @t.overload
    def download_certificate(
        self, order: Order, *, download_all_chains: t.Literal[True] = True
    ) -> tuple[CertificateChain, list[CertificateChain]]: ...

    @t.overload
    def download_certificate(
        self, order: Order, *, download_all_chains: t.Literal[False]
    ) -> tuple[CertificateChain, None]: ...

    @t.overload
    def download_certificate(
        self, order: Order, *, download_all_chains: bool = True
    ) -> tuple[CertificateChain, list[CertificateChain] | None]: ...

    def download_certificate(
        self, order: Order, *, download_all_chains: bool = True
    ) -> tuple[CertificateChain, list[CertificateChain] | None]:
        """
        Download certificate from a valid oder.
        """
        if order.status != "valid":
            raise ModuleFailException(
                f"The order must be valid, but has state {order.status!r}!"
            )

        if not order.certificate_uri:
            raise ModuleFailException(
                f"Order's crtificate URL {order.certificate_uri!r} is empty!"
            )

        cert = CertificateChain.download(client=self.client, url=order.certificate_uri)
        if cert.cert is None:
            raise ModuleFailException(
                f"Certificate at {order.certificate_uri} is empty!"
            )

        alternate_chains = None
        if download_all_chains:
            alternate_chains = self._download_alternate_chains(cert)

        return cert, alternate_chains

    @t.overload
    def get_certificate(
        self, order: Order, *, download_all_chains: t.Literal[True] = True
    ) -> tuple[CertificateChain, list[CertificateChain] | None]: ...

    @t.overload
    def get_certificate(
        self, order: Order, *, download_all_chains: t.Literal[False]
    ) -> tuple[CertificateChain, list[CertificateChain] | None]: ...

    @t.overload
    def get_certificate(
        self, order: Order, *, download_all_chains: bool = True
    ) -> tuple[CertificateChain, list[CertificateChain] | None]: ...

    def get_certificate(
        self, order: Order, *, download_all_chains: bool = True
    ) -> tuple[CertificateChain, list[CertificateChain] | None]:
        """
        Request a new certificate and downloads it, and optionally all certificate chains.
        First verifies whether all authorizations are valid; if not, aborts with an error.
        """
        if self.csr is None and self.csr_content is None:
            raise ModuleFailException("No CSR has been provided")
        for authz in order.authorizations.values():
            if authz.status != "valid":
                authz.raise_error(
                    error_msg=f'Status is {authz.status!r} and not "valid"',
                    module=self.module,
                )

        order.finalize(
            client=self.client,
            csr_der=pem_to_der(pem_filename=self.csr, pem_content=self.csr_content),
        )

        return self.download_certificate(order, download_all_chains=download_all_chains)

    def find_matching_chain(
        self,
        *,
        chains: list[CertificateChain],
        select_chain_matcher: t.Iterable[ChainMatcher],
    ) -> CertificateChain | None:
        for criterium_idx, matcher in enumerate(select_chain_matcher):
            for chain in chains:
                if matcher.match(certificate=chain):
                    self.module.debug(
                        f"Found matching chain for criterium {criterium_idx}"
                    )
                    return chain
        return None

    def write_cert_chain(
        self,
        *,
        cert: CertificateChain,
        cert_dest: str | os.PathLike | None = None,
        fullchain_dest: str | os.PathLike | None = None,
        chain_dest: str | os.PathLike | None = None,
    ) -> bool:
        changed = False
        if cert.cert is None:
            raise ValueError("Certificate is not present")

        if cert_dest and write_file(
            module=self.module, dest=cert_dest, content=cert.cert.encode("utf8")
        ):
            changed = True

        if fullchain_dest and write_file(
            module=self.module,
            dest=fullchain_dest,
            content=(cert.cert + "\n".join(cert.chain)).encode("utf8"),
        ):
            changed = True

        if chain_dest and write_file(
            module=self.module,
            dest=chain_dest,
            content=("\n".join(cert.chain)).encode("utf8"),
        ):
            changed = True

        return changed

    def deactivate_authzs(self, order: Order) -> None:
        """
        Deactivates all valid authz's. Does not raise exceptions.
        https://community.letsencrypt.org/t/authorization-deactivation/19860/2
        https://tools.ietf.org/html/rfc8555#section-7.5.2
        """
        if len(order.authorization_uris) > len(order.authorizations):
            for authz_uri in order.authorization_uris:
                authz = None
                try:
                    authz = Authorization.deactivate_url(
                        client=self.client, url=authz_uri
                    )
                except Exception:
                    # ignore errors
                    pass
                if authz is None or authz.status != "deactivated":
                    self.module.warn(
                        warning=f"Could not deactivate authz object {authz_uri}."
                    )
        else:
            for authz in order.authorizations.values():
                try:
                    authz.deactivate(client=self.client)
                except Exception:
                    # ignore errors
                    pass
                if authz.status != "deactivated":
                    self.module.warn(
                        warning=f"Could not deactivate authz object {authz.url}."
                    )


__all__ = ("ACMECertificateClient",)
