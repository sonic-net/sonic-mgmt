# Copyright (c) 2016 Michael Gruener <michael.gruener@chaosmoon.net>
# Copyright (c) 2021 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import abc
import typing as t

from ansible_collections.community.crypto.plugins.module_utils._acme.errors import (
    ModuleFailException,
)
from ansible_collections.community.crypto.plugins.module_utils._acme.utils import (
    der_to_pem,
    process_links,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.pem import (
    split_pem_list,
)


if t.TYPE_CHECKING:
    from ansible_collections.community.crypto.plugins.module_utils._acme.acme import (  # pragma: no cover
        ACMEClient,
    )


_CertificateChain = t.TypeVar("_CertificateChain", bound="CertificateChain")


class CertificateChain:
    """
    Download and parse the certificate chain.
    https://tools.ietf.org/html/rfc8555#section-7.4.2
    """

    def __init__(self, url: str):
        self.url = url
        self.cert: str | None = None
        self.chain: list[str] = []
        self.alternates: list[str] = []

    @classmethod
    def download(
        cls: type[_CertificateChain], *, client: ACMEClient, url: str
    ) -> _CertificateChain:
        content, info = client.get_request(
            url,
            parse_json_result=False,
            headers={"Accept": "application/pem-certificate-chain"},
        )

        if not content or not info["content-type"].startswith(
            "application/pem-certificate-chain"
        ):
            raise ModuleFailException(
                f"Cannot download certificate chain from {url}, as content type is not application/pem-certificate-chain: {content!r} (headers: {info})"
            )

        result = cls(url)

        # Parse data
        certs = split_pem_list(content.decode("utf-8"), keep_inbetween=True)
        if certs:
            result.cert = certs[0]
            result.chain = certs[1:]

        process_links(
            info=info,
            callback=lambda link, relation: result._process_links(  # pylint: disable=protected-access
                client=client, link=link, relation=relation
            ),
        )

        if result.cert is None:
            raise ModuleFailException(
                f"Failed to parse certificate chain download from {url}: {content!r} (headers: {info})"
            )

        return result

    def _process_links(self, *, client: ACMEClient, link: str, relation: str) -> None:
        if relation == "up":
            # Process link-up headers if there was no chain in reply
            if not self.chain:
                chain_result, chain_info = client.get_request(
                    link, parse_json_result=False
                )
                if chain_info["status"] in [200, 201]:
                    self.chain.append(der_to_pem(chain_result))
        elif relation == "alternate":
            self.alternates.append(link)

    def to_json(self) -> dict[str, bytes]:
        if self.cert is None:
            raise ValueError("Has no certificate")
        cert = self.cert.encode("utf8")
        chain = ("\n".join(self.chain)).encode("utf8")
        return {
            "cert": cert,
            "chain": chain,
            "full_chain": cert + chain,
        }


class Criterium:
    def __init__(self, *, criterium: dict[str, t.Any], index: int):
        self.index = index
        self.test_certificates: t.Literal["first", "last", "all"] = criterium[
            "test_certificates"
        ]
        self.subject: dict[str, t.Any] | None = criterium["subject"]
        self.issuer: dict[str, t.Any] | None = criterium["issuer"]
        self.subject_key_identifier: str | None = criterium["subject_key_identifier"]
        self.authority_key_identifier: str | None = criterium[
            "authority_key_identifier"
        ]


class ChainMatcher(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def match(self, *, certificate: CertificateChain) -> bool:
        """
        Check whether a certificate chain (CertificateChain instance) matches.
        """


__all__ = ("CertificateChain", "Criterium", "ChainMatcher")
