# -*- coding: utf-8 -*-
#
# Copyright (c) 2021 Felix Fontein
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type

import sys

from ansible_collections.community.dns.plugins.module_utils.zone_record_api import (
    DNSAPIError,
)


if sys.version_info >= (3, 6):
    import typing

    if typing.TYPE_CHECKING:
        from .provider import ProviderInformation  # pragma: no cover
        from .record import DNSRecord  # pragma: no cover
        from .zone_record_api import ZoneRecordAPI  # pragma: no cover


def bulk_apply_changes(
    api,  # type: ZoneRecordAPI
    provider_information,  # type: ProviderInformation
    options,  # TODO type
    zone_id,  # type: str
    records_to_delete=None,  # type: list[DNSRecord] | None
    records_to_change=None,  # type: list[DNSRecord] | None
    records_to_create=None,  # type: list[DNSRecord] | None
    stop_early_on_errors=True,  # type: bool
):  # type: (...) -> tuple[bool, list[DNSAPIError], dict[str, list[DNSRecord]]]
    """
    Update multiple records. If an operation failed, raise a DNSAPIException.

    @param api: A ZoneRecordAPI instance
    @param provider_information: A ProviderInformation object.
    @param options: A object compatible with ModuleOptionProvider that gives access to the module/plugin
                    options.
    @param zone_id: Zone ID to apply changes to
    @param records_to_delete: Optional list of DNS records to delete (DNSRecord)
    @param records_to_change: Optional list of DNS records to change (DNSRecord)
    @param records_to_create: Optional list of DNS records to create (DNSRecord)
    @param bulk_threshold: Minimum number of changes for using the bulk API instead of the regular API
    @param stop_early_on_errors: If set to ``True``, try to stop changes after the first error happens.
                                 This might only work on some APIs.
    @return A tuple (changed, errors, success) where ``changed`` is a boolean which indicates whether a
            change was made, ``errors`` is a list of ``DNSAPIError`` instances for the errors occurred,
            and ``success`` is a dictionary with three lists ``success['deleted']``,
            ``success['changed']`` and ``success['created']``, which list all records that were deleted,
            changed and created, respectively.
    """
    records_to_delete = records_to_delete or []
    records_to_change = records_to_change or []
    records_to_create = records_to_create or []

    has_change = False
    errors = []  # type: list[DNSAPIError]

    bulk_threshold = 2
    if provider_information.supports_bulk_actions():
        bulk_threshold = options.get_option('bulk_operation_threshold')

    success = {
        'deleted': [],
        'changed': [],
        'created': [],
    }  # type: dict[str, list[DNSRecord]]

    # Delete records
    if len(records_to_delete) >= bulk_threshold:
        results = api.delete_records({zone_id: records_to_delete}, stop_early_on_errors=stop_early_on_errors)
        result = results.get(zone_id) or []
        for record, deleted, failed in result:
            has_change |= deleted
            if failed is not None:
                errors.append(failed)
            if deleted:
                success['deleted'].append(record)
        if errors and stop_early_on_errors:
            return has_change, errors, success
    else:
        for record in records_to_delete:
            try:
                deleted = api.delete_record(zone_id, record)
                has_change |= deleted
                if deleted:
                    success['deleted'].append(record)
            except DNSAPIError as e:
                errors.append(e)
                if stop_early_on_errors:
                    return has_change, errors, success

    # Change records
    if len(records_to_change) >= bulk_threshold:
        results = api.update_records({zone_id: records_to_change}, stop_early_on_errors=stop_early_on_errors)
        result = results.get(zone_id) or []
        for record, changed, failed in result:
            has_change |= changed
            if failed is not None:
                errors.append(failed)
            if changed:
                success['changed'].append(record)
        if errors and stop_early_on_errors:
            return has_change, errors, success
    else:
        for record in records_to_change:
            try:
                record = api.update_record(zone_id, record)
                has_change = True
                success['changed'].append(record)
            except DNSAPIError as e:
                errors.append(e)
                if stop_early_on_errors:
                    return has_change, errors, success

    # Create records
    if len(records_to_create) >= bulk_threshold:
        results = api.add_records({zone_id: records_to_create}, stop_early_on_errors=stop_early_on_errors)
        result = results.get(zone_id) or []
        for record, created, failed in result:
            has_change |= created
            if failed is not None:
                errors.append(failed)
            if created:
                success['created'].append(record)
        if errors and stop_early_on_errors:
            return has_change, errors, success
    else:
        for record in records_to_create:
            try:
                record = api.add_record(zone_id, record)
                has_change = True
                success['created'].append(record)
            except DNSAPIError as e:
                errors.append(e)
                if stop_early_on_errors:
                    return has_change, errors, success

    return has_change, errors, success
