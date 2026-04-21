# -*- coding: utf-8 -*-

# Copyright (c) 2023, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


import traceback

from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.common.text.converters import to_text


try:
    import ipaddress
except ImportError:
    IPADDRESS_IMPORT_EXC = traceback.format_exc()
else:
    IPADDRESS_IMPORT_EXC = None  # type: ignore  # TODO


def is_ip_address(server):
    try:
        ipaddress.ip_address(to_text(server))
        return True
    except ValueError:
        return False


def assert_requirements_present(module):
    if IPADDRESS_IMPORT_EXC is not None:
        module.fail_json(
            msg=missing_required_lib('ipaddress'),
            exception=IPADDRESS_IMPORT_EXC,
        )
