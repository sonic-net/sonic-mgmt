# -*- coding: utf-8 -*-

# Copyright (c) 2024, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""Provide selectors import."""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


# Once we drop support for ansible-core 2.16, we can remove the try/except.

from sys import version_info as _python_version_info


if _python_version_info < (3, 4):
    from ansible.module_utils.compat import selectors  # noqa: F401, pylint: disable=unused-import
else:
    import selectors  # noqa: F401, pylint: disable=unused-import
