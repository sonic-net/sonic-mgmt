# Copyright (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import typing as t

from ansible_collections.community.crypto.plugins.module_utils._crypto.cryptography_crl import (
    TIMESTAMP_FORMAT,
    cryptography_decode_revoked_certificate,
    cryptography_dump_revoked,
    cryptography_get_signature_algorithm_oid_from_crl,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.cryptography_support import (
    cryptography_oid_to_name,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.pem import (
    identify_pem_format,
)
from ansible_collections.community.crypto.plugins.module_utils._cryptography_dep import (
    COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION,
    assert_required_cryptography_version,
)


if t.TYPE_CHECKING:
    from ansible.module_utils.basic import AnsibleModule  # pragma: no cover

    from ansible_collections.community.crypto.plugins.plugin_utils._action_module import (  # pragma: no cover
        AnsibleActionModule,
    )
    from ansible_collections.community.crypto.plugins.plugin_utils._filter_module import (  # pragma: no cover
        FilterModuleMock,
    )

    GeneralAnsibleModule = t.Union[  # noqa: UP007
        AnsibleModule, AnsibleActionModule, FilterModuleMock
    ]  # pragma: no cover


# crypto_utils

MINIMAL_CRYPTOGRAPHY_VERSION = COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION

try:
    from cryptography import x509
except ImportError:
    pass


class CRLInfoRetrieval:
    def __init__(
        self,
        *,
        module: GeneralAnsibleModule,
        content: bytes,
        list_revoked_certificates: bool = True,
    ) -> None:
        # content must be a bytes string
        self.module = module
        self.content = content
        self.list_revoked_certificates = list_revoked_certificates
        self.name_encoding = module.params.get("name_encoding", "ignore")

    def get_info(self) -> dict[str, t.Any]:
        crl_pem = identify_pem_format(self.content)
        try:
            if crl_pem:
                crl = x509.load_pem_x509_crl(self.content)
            else:
                crl = x509.load_der_x509_crl(self.content)
        except ValueError as e:
            self.module.fail_json(msg=f"Error while decoding CRL: {e}")

        result: dict[str, t.Any] = {
            "changed": False,
            "format": "pem" if crl_pem else "der",
            "last_update": None,
            "next_update": None,
            "digest": None,
            "issuer_ordered": None,
            "issuer": None,
        }

        result["last_update"] = crl.last_update.strftime(TIMESTAMP_FORMAT)
        result["next_update"] = (
            crl.next_update.strftime(TIMESTAMP_FORMAT) if crl.next_update else None
        )
        result["digest"] = cryptography_oid_to_name(
            cryptography_get_signature_algorithm_oid_from_crl(crl)
        )
        issuer = []
        for attribute in crl.issuer:
            issuer.append([cryptography_oid_to_name(attribute.oid), attribute.value])
        result["issuer_ordered"] = issuer
        issuer_dict = {}
        for k, v in issuer:
            issuer_dict[k] = v
        result["issuer"] = issuer_dict
        if self.list_revoked_certificates:
            result["revoked_certificates"] = []
            for cert in crl:
                entry = cryptography_decode_revoked_certificate(cert)
                result["revoked_certificates"].append(
                    cryptography_dump_revoked(entry, idn_rewrite=self.name_encoding)
                )

        return result


def get_crl_info(
    *,
    module: GeneralAnsibleModule,
    content: bytes,
    list_revoked_certificates: bool = True,
) -> dict[str, t.Any]:
    assert_required_cryptography_version(
        module, minimum_cryptography_version=MINIMAL_CRYPTOGRAPHY_VERSION
    )
    info = CRLInfoRetrieval(
        module=module,
        content=content,
        list_revoked_certificates=list_revoked_certificates,
    )
    return info.get_info()


__all__ = ("CRLInfoRetrieval", "get_crl_info")
