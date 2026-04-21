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
from ansible_collections.community.dns.plugins.module_utils.argspec import (
    ArgumentSpec,
    ModuleOptionProvider,
)
from ansible_collections.community.dns.plugins.module_utils.conversion.base import (
    DNSConversionError,
)
from ansible_collections.community.dns.plugins.module_utils.conversion.converter import (
    RecordConverter,
)
from ansible_collections.community.dns.plugins.module_utils.options import (
    create_record_transformation_argspec,
)
from ansible_collections.community.dns.plugins.module_utils.record import (
    format_record_for_output,
)
from ansible_collections.community.dns.plugins.module_utils.zone_record_api import (
    NOT_PROVIDED,
    DNSAPIAuthenticationError,
    DNSAPIError,
)

from ._utils import get_prefix, normalize_dns_name


def create_module_argument_spec(provider_information):
    return ArgumentSpec(
        argument_spec={
            'what': {'type': 'str', 'choices': ['single_record', 'all_types_for_record', 'all_records'], 'default': 'single_record'},
            'zone_name': {'type': 'str', 'aliases': ['zone']},
            'zone_id': {'type': provider_information.get_zone_id_type()},
            'record': {'type': 'str'},
            'prefix': {'type': 'str'},
            'type': {'type': 'str', 'choices': provider_information.get_supported_record_types(), 'default': None},
        },
        required_if=[
            ('what', 'single_record', ['type']),
            ('what', 'single_record', ['record', 'prefix'], True),
            ('what', 'all_types_for_record', ['record', 'prefix'], True),
        ],
        required_one_of=[
            ('zone_name', 'zone_id'),
        ],
        mutually_exclusive=[
            ('zone_name', 'zone_id'),
            ('record', 'prefix'),
        ],
    ).merge(create_record_transformation_argspec())


def run_module(module, create_api, provider_information):
    option_provider = ModuleOptionProvider(module)
    record_converter = RecordConverter(provider_information, option_provider)
    record_converter.emit_deprecations(module.deprecate)

    filter_record_type = NOT_PROVIDED
    filter_prefix = NOT_PROVIDED
    if module.params.get('what') == 'single_record':
        filter_record_type = module.params.get('type')
        if module.params.get('prefix') is not None:
            filter_prefix = provider_information.normalize_prefix(module.params.get('prefix'))
    elif module.params.get('what') == 'all_types_for_record':
        if module.params.get('prefix') is not None:
            filter_prefix = provider_information.normalize_prefix(module.params.get('prefix'))

    try:
        # Create API
        api = create_api()

        # Get zone information
        if module.params.get('zone_name') is not None:
            zone_in = normalize_dns_name(module.params.get('zone_name'))
            zone = api.get_zone_with_records_by_name(zone_in, prefix=filter_prefix, record_type=filter_record_type)
            if zone is None:
                module.fail_json(msg='Zone not found')
        else:
            zone = api.get_zone_with_records_by_id(module.params.get('zone_id'), prefix=filter_prefix, record_type=filter_record_type)
            if zone is None:
                module.fail_json(msg='Zone not found')
            zone_in = normalize_dns_name(zone.zone.name)

        # Retrieve requested information
        records = []
        if module.params.get('what') in ('single_record', 'all_types_for_record'):
            check_prefix = True
            record_in = normalize_dns_name(module.params.get('record'))
            prefix_in = module.params.get('prefix')
            record_in, prefix = get_prefix(
                normalized_zone=zone_in, normalized_record=record_in, prefix=prefix_in, provider_information=provider_information)
        else:
            check_prefix = False
            prefix = None

        # Find matching records
        records = []
        for record in zone.records:
            if check_prefix:
                if record.prefix != prefix:
                    continue
            records.append((
                (record.prefix + '.' + zone_in) if record.prefix else zone_in,
                record,
            ))

        # Convert records
        only_records = [record for record_name, record in records]
        record_converter.process_multiple_from_api(only_records)
        record_converter.process_multiple_to_user(only_records)

        # Format output
        data = [
            format_record_for_output(record, record_name, prefix=record.prefix)
            for record_name, record in records
        ]
        module.exit_json(
            changed=False,
            records=data,
            zone_id=zone.zone.id,
        )
    except DNSConversionError as e:
        module.fail_json(msg='Error while converting DNS values: {0}'.format(e.error_message), error=e.error_message, exception=traceback.format_exc())
    except DNSAPIAuthenticationError as e:
        module.fail_json(msg='Cannot authenticate: {0}'.format(e), error=to_text(e), exception=traceback.format_exc())
    except DNSAPIError as e:
        module.fail_json(msg='Error: {0}'.format(e), error=to_text(e), exception=traceback.format_exc())
