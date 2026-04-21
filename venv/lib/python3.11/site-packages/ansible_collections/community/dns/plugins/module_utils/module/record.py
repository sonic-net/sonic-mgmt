# -*- coding: utf-8 -*-
#
# Copyright (c) 2017-2021 Felix Fontein
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
    DNSRecord,
    format_record_for_output,
)
from ansible_collections.community.dns.plugins.module_utils.zone_record_api import (
    NOT_PROVIDED,
    DNSAPIAuthenticationError,
    DNSAPIError,
    filter_records,
)

from ._utils import get_prefix, normalize_dns_name


def create_module_argument_spec(provider_information):
    return ArgumentSpec(
        argument_spec={
            'state': {'type': 'str', 'choices': ['present', 'absent'], 'required': True},
            'zone_name': {'type': 'str', 'aliases': ['zone']},
            'zone_id': {'type': provider_information.get_zone_id_type()},
            'record': {'type': 'str'},
            'prefix': {'type': 'str'},
            'ttl': {'type': 'int', 'default': provider_information.get_record_default_ttl()},
            'type': {'choices': provider_information.get_supported_record_types(), 'required': True},
            'value': {'type': 'str', 'required': True},
        },
        required_one_of=[
            ('zone_name', 'zone_id'),
            ('record', 'prefix'),
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

    record_in = normalize_dns_name(module.params.get('record'))
    prefix_in = module.params.get('prefix')
    type_in = module.params.get('type')
    try:
        # Create API
        api = create_api()

        # Get zone information
        if module.params.get('zone_name') is not None:
            zone_in = normalize_dns_name(module.params.get('zone_name'))
            record_in, prefix = get_prefix(
                normalized_zone=zone_in, normalized_record=record_in, prefix=prefix_in, provider_information=provider_information)
            zone = api.get_zone_with_records_by_name(zone_in, prefix=prefix, record_type=type_in)
            if zone is None:
                module.fail_json(msg='Zone not found')
            zone_id = zone.zone.id
            records = zone.records
        elif record_in is not None:
            zone = api.get_zone_with_records_by_id(
                module.params.get('zone_id'),
                record_type=type_in,
                prefix=provider_information.normalize_prefix(prefix_in) if prefix_in is not None else NOT_PROVIDED,
            )
            if zone is None:
                module.fail_json(msg='Zone not found')
            zone_in = normalize_dns_name(zone.zone.name)
            record_in, prefix = get_prefix(
                normalized_zone=zone_in, normalized_record=record_in, prefix=prefix_in, provider_information=provider_information)
            zone_id = zone.zone.id
            records = zone.records
        else:
            zone_id = module.params.get('zone_id')
            prefix = provider_information.normalize_prefix(prefix_in)
            records = api.get_zone_records(
                zone_id,
                record_type=type_in,
                prefix=prefix,
            )
            if records is None:
                module.fail_json(msg='Zone not found')
            zone_in = None
            record_in = None

        # Find matching records
        records = filter_records(records, prefix=prefix)
        record_converter.process_multiple_from_api(records)

        # Parse records
        value_in = module.params.get('value')
        value_in = record_converter.process_value_from_user(type_in, value_in)

        # Compare records
        existing_record = None
        exact_match = False
        ttl_in = module.params.get('ttl')
        for record in records:
            if record.target == value_in:
                existing_record = record
                exact_match = record.ttl == ttl_in
                break

        before = existing_record.clone() if existing_record else None
        after = before
        changed = False

        if module.params.get('state') == 'present':
            if existing_record is None:
                # Create record
                record = DNSRecord()
                record.prefix = prefix
                record.type = type_in
                record.ttl = ttl_in
                record.target = value_in
                api_record = record_converter.clone_to_api(record)
                if not module.check_mode:
                    new_api_record = api.add_record(zone_id, api_record)
                    record = record_converter.clone_from_api(new_api_record)
                after = record
                changed = True
            elif not exact_match:
                # Update record
                record = existing_record
                record.ttl = ttl_in
                api_record = record_converter.clone_to_api(record)
                if not module.check_mode:
                    new_api_record = api.update_record(zone_id, api_record)
                    record = record_converter.clone_from_api(new_api_record)
                after = record
                changed = True
        else:
            if existing_record is not None:
                # Delete record
                api_record = record_converter.clone_to_api(existing_record)
                if not module.check_mode:
                    api.delete_record(zone_id, api_record)
                after = None
                changed = True

        # Compose result
        result = {
            'changed': changed,
            'zone_id': zone_id,
        }
        if module._diff:
            result['diff'] = {
                'before': format_record_for_output(before, record_in, prefix, record_converter=record_converter) if before else {},
                'after': format_record_for_output(after, record_in, prefix, record_converter=record_converter) if after else {},
            }

        module.exit_json(**result)
    except DNSConversionError as e:
        module.fail_json(msg='Error while converting DNS values: {0}'.format(e.error_message), error=e.error_message, exception=traceback.format_exc())
    except DNSAPIAuthenticationError as e:
        module.fail_json(msg='Cannot authenticate: {0}'.format(e), error=to_text(e), exception=traceback.format_exc())
    except DNSAPIError as e:
        module.fail_json(msg='Error: {0}'.format(e), error=to_text(e), exception=traceback.format_exc())
