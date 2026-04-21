# Copyright (c) 2025 Ansible project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

"""
Module utils for cryptography requirements.

Must be kept in sync with plugins/doc_fragments/cryptography_dep.py.
"""

from __future__ import annotations

import traceback
import typing as t

from ansible.module_utils.basic import missing_required_lib

from ansible_collections.community.crypto.plugins.module_utils._version import (
    LooseVersion,
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


_CRYPTOGRAPHY_IMP_ERR: str | None = None  # pylint: disable=invalid-name
_CRYPTOGRAPHY_FILE: str | None = None  # pylint: disable=invalid-name
try:
    import cryptography
    from cryptography import x509  # noqa: F401, pylint: disable=unused-import

except ImportError:
    _CRYPTOGRAPHY_IMP_ERR = traceback.format_exc()  # pylint: disable=invalid-name
    CRYPTOGRAPHY_FOUND = False
    CRYPTOGRAPHY_VERSION = LooseVersion("0.0")  # pylint: disable=invalid-name
else:
    CRYPTOGRAPHY_FOUND = True
    # pylint: disable-next=invalid-name
    CRYPTOGRAPHY_VERSION = LooseVersion(cryptography.__version__)
    _CRYPTOGRAPHY_FILE = cryptography.__file__  # pylint: disable=invalid-name


# Corresponds to the community.crypto.cryptography_dep.minimum doc fragment
COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION = "3.3"


def assert_required_cryptography_version(
    module: GeneralAnsibleModule,
    *,
    minimum_cryptography_version: str = COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION,
) -> None:
    if not CRYPTOGRAPHY_FOUND:
        module.fail_json(
            msg=missing_required_lib(f"cryptography >= {minimum_cryptography_version}"),
            exception=_CRYPTOGRAPHY_IMP_ERR,
        )
    if LooseVersion(minimum_cryptography_version) > CRYPTOGRAPHY_VERSION:
        module.fail_json(
            msg=(
                f"Cannot detect the required Python library cryptography (>= {minimum_cryptography_version})."
                f" Only found a too old version ({CRYPTOGRAPHY_VERSION}) at {_CRYPTOGRAPHY_FILE}."
            ),
        )


__all__ = (
    "COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION",
    "CRYPTOGRAPHY_FOUND",
    "CRYPTOGRAPHY_VERSION",
    "assert_required_cryptography_version",
)
