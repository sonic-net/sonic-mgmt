# -*- coding: utf-8 -*-
#
# Copyright (c) 2021 Felix Fontein
# Copyright (c) 2020 Markus Bergholz <markuman+spambelongstogoogle@gmail.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# https://dns.hetzner.com/api-docs

from __future__ import absolute_import, division, print_function


__metaclass__ = type


from ansible.module_utils.basic import env_fallback
from ansible_collections.community.dns.plugins.module_utils.argspec import ArgumentSpec
from ansible_collections.community.dns.plugins.module_utils.json_api_helper import (
    ERROR_CODES,
    UNKNOWN_ERROR,
    JSONAPIHelper,
)
from ansible_collections.community.dns.plugins.module_utils.provider import (
    ProviderInformation,
)
from ansible_collections.community.dns.plugins.module_utils.record import DNSRecord
from ansible_collections.community.dns.plugins.module_utils.zone import DNSZone
from ansible_collections.community.dns.plugins.module_utils.zone_record_api import (
    NOT_PROVIDED,
    DNSAPIError,
    ZoneRecordAPI,
    filter_records,
)


def _create_zone_from_json(source):
    zone = DNSZone(source['name'])
    zone.id = source['id']
    info = source.copy()
    info.pop('name')
    info.pop('id')
    if 'legacy_ns' in info:
        info['legacy_ns'] = sorted(info['legacy_ns'])
    zone.info = info
    return zone


def _create_record_from_json(source, record_type=None, has_id=True):
    source = dict(source)
    result = DNSRecord()
    if has_id:
        result.id = source.pop('id')
    result.type = source.pop('type', record_type)
    result.ttl = source.pop('ttl', None)
    name = source.pop('name', None)
    if name == '@':
        name = None
    result.prefix = name
    result.target = source.pop('value')
    source.pop('zone_id', None)
    result.extra.update(source)
    return result


def _record_to_json(record, zone_id):
    result = {
        'name': record.prefix or '@',
        'value': record.target,
        'type': record.type,
        'zone_id': zone_id,
    }
    if record.ttl is not None:
        result['ttl'] = record.ttl
    return result


class HetznerAPI(ZoneRecordAPI, JSONAPIHelper):
    def __init__(self, http_helper, token, api='https://dns.hetzner.com/api/', debug=False):
        JSONAPIHelper.__init__(self, http_helper, token, api=api, debug=debug)

    def _create_headers(self):
        return {
            'Accept': 'application/json',
            'Auth-API-Token': self._token,
        }

    def _extract_only_error_message(self, result):
        # These errors are not documented, but are what I experienced the API seems to return:
        res = ''
        if isinstance(result.get('error'), dict):
            if 'message' in result['error']:
                res = '{0} with error message "{1}"'.format(res, result['error']['message'])
            if 'code' in result['error']:
                res = '{0} (error code {1})'.format(res, result['error']['code'])
        if result.get('message'):
            res = '{0} with message "{1}"'.format(res, result['message'])
        return res

    def _extract_error_message(self, result):
        if result is None:
            return ''
        if isinstance(result, dict):
            res = self._extract_only_error_message(result)
            if res:
                return res
        return ' with data: {0}'.format(result)

    def _validate(self, result=None, info=None, expected=None, method='GET'):
        super(HetznerAPI, self)._validate(result=result, info=info, expected=expected, method=method)
        if isinstance(result, dict):
            error = result.get('error')
            if isinstance(error, dict):
                status = error.get('code')
                if status is None:
                    return
                url = info['url']
                if expected is not None and status in expected:
                    return
                error_code = ERROR_CODES.get(status, UNKNOWN_ERROR)
                more = self._extract_error_message(result)
                raise DNSAPIError(
                    '{0} {1} resulted in API error {2} ({3}){4}'.format(method, url, status, error_code, more))

    def _list_pagination(self, url, data_key, query=None, block_size=100, accept_404=False):
        result = []
        page = 1
        while True:
            query_ = query.copy() if query else {}
            query_['per_page'] = block_size
            query_['page'] = page
            res, info = self._get(url, query_, must_have_content=[200], expected=[200, 404] if accept_404 and page == 1 else [200])
            if accept_404 and page == 1 and info['status'] == 404:
                return None
            result.extend(res[data_key])
            if 'meta' not in res and page == 1:
                return result
            if page >= res['meta']['pagination']['last_page']:
                return result
            page += 1

    def get_zone_by_name(self, name):
        """
        Given a zone name, return the zone contents if found.

        @param name: The zone name (string)
        @return The zone information (DNSZone), or None if not found
        """
        result, dummy = self._get('v1/zones', expected=[200, 404], query={'name': name})
        for zone in result['zones']:
            if zone.get('name') == name:
                return _create_zone_from_json(zone)
        return None

    def get_zone_by_id(self, zone_id):
        """
        Given a zone ID, return the zone contents if found.

        @param zone_id: The zone ID
        @return The zone information (DNSZone), or None if not found
        """
        result, info = self._get('v1/zones/{zone_id}'.format(zone_id=zone_id), expected=[200, 404], must_have_content=[200])
        if info['status'] == 404:
            return None
        return _create_zone_from_json(result['zone'])

    def get_zone_records(self, zone_id, prefix=NOT_PROVIDED, record_type=NOT_PROVIDED):
        """
        Given a zone ID, return a list of records, optionally filtered by the provided criteria.

        @param zone_id: The zone ID
        @param prefix: The prefix to filter for, if provided. Since None is a valid value,
                       the special constant NOT_PROVIDED indicates that we are not filtering.
        @param record_type: The record type to filter for, if provided
        @return A list of DNSrecord objects, or None if zone was not found
        """
        result = self._list_pagination('v1/records', data_key='records', query={'zone_id': zone_id}, accept_404=True)
        if result is None:
            return None
        return filter_records(
            [_create_record_from_json(record) for record in result],
            prefix=prefix,
            record_type=record_type,
        )

    def add_record(self, zone_id, record):
        """
        Adds a new record to an existing zone.

        @param zone_id: The zone ID
        @param record: The DNS record (DNSRecord)
        @return The created DNS record (DNSRecord)
        """
        data = _record_to_json(record, zone_id=zone_id)
        result, info = self._post('v1/records', data=data, expected=[200, 422])
        if info['status'] == 422:
            raise DNSAPIError(
                'The new {type} record with value "{target}" and TTL {ttl} has not been accepted by the server{message}'.format(
                    type=record.type,
                    target=record.target,
                    ttl=record.ttl,
                    message=self._extract_only_error_message(result),
                )
            )
        return _create_record_from_json(result['record'])

    def update_record(self, zone_id, record):
        """
        Update a record.

        @param zone_id: The zone ID
        @param record: The DNS record (DNSRecord)
        @return The DNS record (DNSRecord)
        """
        if record.id is None:
            raise DNSAPIError('Need record ID to update record!')
        data = _record_to_json(record, zone_id=zone_id)
        result, info = self._put('v1/records/{id}'.format(id=record.id), data=data, expected=[200, 422])
        if info['status'] == 422:
            raise DNSAPIError(
                'The updated {type} record with value "{target}" and TTL {ttl} has not been accepted by the server{message}'.format(
                    type=record.type,
                    target=record.target,
                    ttl=record.ttl,
                    message=self._extract_only_error_message(result),
                )
            )
        return _create_record_from_json(result['record'])

    def delete_record(self, zone_id, record):
        """
        Delete a record.

        @param zone_id: The zone ID
        @param record: The DNS record (DNSRecord)
        @return True in case of success (boolean)
        """
        if record.id is None:
            raise DNSAPIError('Need record ID to delete record!')
        dummy, info = self._delete('v1/records/{id}'.format(id=record.id), must_have_content=False, expected=[200, 404])
        return info['status'] == 200

    @staticmethod
    def _append(results_per_zone_id, zone_id, result):
        if zone_id not in results_per_zone_id:
            results_per_zone_id[zone_id] = []
        results_per_zone_id[zone_id].append(result)

    def add_records(self, records_per_zone_id, stop_early_on_errors=True):
        """
        Add new records to an existing zone.

        @param records_per_zone_id: Maps a zone ID to a list of DNS records (DNSRecord)
        @param stop_early_on_errors: If set to ``True``, try to stop changes after the first error happens.
                                     This might only work on some APIs.
        @return A dictionary mapping zone IDs to lists of tuples ``(record, created, failed)``.
                Here ``created`` indicates whether the record was created (``True``) or not (``False``).
                If it was created, ``record`` contains the record ID and ``failed`` is ``None``.
                If it was not created, ``failed`` should be a ``DNSAPIError`` instance indicating why
                it was not created. It is possible that the API only creates records if all succeed,
                in that case ``failed`` can be ``None`` even though ``created`` is ``False``.
        """
        json_records = []
        for zone_id, records in records_per_zone_id.items():
            for record in records:
                json_records.append(_record_to_json(record, zone_id=zone_id))
        data = {'records': json_records}
        # Error 422 means that at least one of the records was not valid
        result, dummy = self._post('v1/records/bulk', data=data, expected=[200, 422])
        results_per_zone_id = {}
        # This is the list of invalid records that was detected before accepting the whole set
        for json_record in result.get('invalid_records') or []:
            record = _create_record_from_json(json_record, has_id=False)
            zone_id = json_record['zone_id']
            self._append(results_per_zone_id, zone_id, (record, False, DNSAPIError(
                'Creating {type} record "{target}" with TTL {ttl} for zone {zoneID} failed with unknown reason'.format(
                    type=record.type,
                    target=record.target,
                    ttl=record.ttl,
                    zoneID=zone_id))))
        # This is the list of valid records that were not processed
        for json_record in result.get('valid_records') or []:
            record = _create_record_from_json(json_record, has_id=False)
            zone_id = json_record['zone_id']
            self._append(results_per_zone_id, zone_id, (record, False, None))
        # This is the list of correctly processed records
        for json_record in result.get('records') or []:
            record = _create_record_from_json(json_record)
            zone_id = json_record['zone_id']
            self._append(results_per_zone_id, zone_id, (record, True, None))
        return results_per_zone_id

    def update_records(self, records_per_zone_id, stop_early_on_errors=True):
        """
        Update multiple records.

        @param records_per_zone_id: Maps a zone ID to a list of DNS records (DNSRecord)
        @param stop_early_on_errors: If set to ``True``, try to stop changes after the first error happens.
                                     This might only work on some APIs.
        @return A dictionary mapping zone IDs to lists of tuples ``(record, updated, failed)``.
                Here ``updated`` indicates whether the record was updated (``True``) or not (``False``).
                If it was not updated, ``failed`` should be a ``DNSAPIError`` instance. If it was
                updated, ``failed`` should be ``None``.  It is possible that the API only updates
                records if all succeed, in that case ``failed`` can be ``None`` even though
                ``updated`` is ``False``.
        """
        # Currently Hetzner's bulk update API seems to be broken, it always returns the error message
        # "An invalid response was received from the upstream server". That's why for now, we always
        # fall back to the default implementation.
        if True:  # pylint: disable=using-constant-test
            return super(HetznerAPI, self).update_records(records_per_zone_id, stop_early_on_errors=stop_early_on_errors)

        json_records = []
        for zone_id, records in records_per_zone_id.items():
            for record in records:
                json_records.append(_record_to_json(record, zone_id=zone_id))
        data = {'records': json_records}
        result, dummy = self._put('v1/records/bulk', data=data, expected=[200])
        results_per_zone_id = {}
        for json_record in result.get('failed_records') or []:
            record = _create_record_from_json(json_record)
            zone_id = json_record['zone_id']
            self._append(results_per_zone_id, zone_id, (record, False, DNSAPIError(
                'Updating {type} record #{id} "{target}" with TTL {ttl} for zone {zoneID} failed with unknown reason'.format(
                    type=record.type,
                    id=record.id,
                    target=record.target,
                    ttl=record.ttl,
                    zoneID=zone_id))))
        for json_record in result.get('records') or []:
            record = _create_record_from_json(json_record)
            zone_id = json_record['zone_id']
            self._append(results_per_zone_id, zone_id, (record, True, None))
        return results_per_zone_id


class HetznerProviderInformation(ProviderInformation):
    def get_supported_record_types(self):
        """
        Return a list of supported record types.
        """
        return ['A', 'AAAA', 'NS', 'MX', 'CNAME', 'RP', 'TXT', 'SOA', 'HINFO', 'SRV', 'DANE', 'TLSA', 'DS', 'CAA']

    def get_zone_id_type(self):
        """
        Return the (short) type for zone IDs, like ``'int'`` or ``'str'``.
        """
        return 'str'

    def get_record_id_type(self):
        """
        Return the (short) type for record IDs, like ``'int'`` or ``'str'``.
        """
        return 'str'

    def get_record_default_ttl(self):
        """
        Return the default TTL for records, like 300, 3600 or None.
        None means that some other TTL (usually from the zone) will be used.
        """
        return None

    def normalize_prefix(self, prefix):
        """
        Given a prefix (string or None), return its normalized form.

        The result should always be None for the trivial prefix, and a non-zero length DNS name
        for a non-trivial prefix.

        If a provider supports other identifiers for the trivial prefix, such as '@', this
        function needs to convert them to None as well.
        """
        return None if prefix in ('@', '') else prefix

    def supports_bulk_actions(self):
        """
        Return whether the API supports some kind of bulk actions.
        """
        return True

    def txt_record_handling(self):
        """
        Return how the API handles TXT records.

        Returns one of the following strings:
        * 'decoded' - the API works with unencoded values
        * 'encoded' - the API works with encoded values
        * 'encoded-no-char-encoding' - the API works with encoded values, but without character encoding
        """
        return 'encoded-no-char-encoding'


def create_hetzner_provider_information():
    return HetznerProviderInformation()


def create_hetzner_argument_spec():
    return ArgumentSpec(
        argument_spec={
            'hetzner_token': {
                'type': 'str',
                'required': True,
                'no_log': True,
                'aliases': ['api_token'],
                'fallback': (env_fallback, ['HETZNER_DNS_TOKEN']),
            },
        },
    )


def create_hetzner_api(option_provider, http_helper):
    return HetznerAPI(http_helper, option_provider.get_option('hetzner_token'))
