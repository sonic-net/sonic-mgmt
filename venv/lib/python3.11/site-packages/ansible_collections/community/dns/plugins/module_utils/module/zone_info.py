# -*- coding: utf-8 -*-
#
# Copyright (c) 2021 Felix Fontein
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# This module_utils is PRIVATE and should only be used by this collection. Breaking changes can occur any time.

from __future__ import absolute_import, division, print_function


__metaclass__ = type


import traceback

from ansible.module_utils.common.text.converters import to_text
from ansible_collections.community.dns.plugins.module_utils.argspec import ArgumentSpec
from ansible_collections.community.dns.plugins.module_utils.zone_record_api import (
    DNSAPIAuthenticationError,
    DNSAPIError,
)

from ._utils import normalize_dns_name


def create_module_argument_spec(provider_information):
    return ArgumentSpec(
        argument_spec={
            'zone_name': {'type': 'str', 'aliases': ['zone']},
            'zone_id': {'type': provider_information.get_zone_id_type()},
        },
        required_one_of=[
            ('zone_name', 'zone_id'),
        ],
        mutually_exclusive=[
            ('zone_name', 'zone_id'),
        ],
    )


def run_module(module, create_api, provider_information):
    try:
        # Create API
        api = create_api()

        # Get zone information
        if module.params.get('zone_name') is not None:
            zone_id = normalize_dns_name(module.params.get('zone_name'))
            zone = api.get_zone_by_name(zone_id)
            if zone is None:
                module.fail_json(msg='Zone not found')
        else:
            zone = api.get_zone_by_id(module.params.get('zone_id'))
            if zone is None:
                module.fail_json(msg='Zone not found')

        module.exit_json(
            changed=False,
            zone_name=zone.name,
            zone_id=zone.id,
            zone_info=zone.info,
        )
    except DNSAPIAuthenticationError as e:
        module.fail_json(msg='Cannot authenticate: {0}'.format(e), error=to_text(e), exception=traceback.format_exc())
    except DNSAPIError as e:
        module.fail_json(msg='Error: {0}'.format(e), error=to_text(e), exception=traceback.format_exc())
