# Copyright (c) 2016, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations


try:
    import cryptography  # noqa: F401, pylint: disable=unused-import

    HAS_CRYPTOGRAPHY = True
except ImportError:
    # Error handled in the calling module.
    HAS_CRYPTOGRAPHY = False


class OpenSSLObjectError(Exception):
    pass


class OpenSSLBadPassphraseError(OpenSSLObjectError):
    pass


__all__ = ("HAS_CRYPTOGRAPHY", "OpenSSLObjectError", "OpenSSLBadPassphraseError")
