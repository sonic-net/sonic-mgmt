# -*- coding: utf-8 -*-
#
# Copyright (c) 2017-2021 Felix Fontein
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# The API documentation can be found here: https://api.ns1.hosttech.eu/api/documentation/

from __future__ import absolute_import, division, print_function


__metaclass__ = type


from ansible_collections.community.dns.plugins.module_utils.json_api_helper import (
    JSONAPIHelper,
)
from ansible_collections.community.dns.plugins.module_utils.record import DNSRecord
from ansible_collections.community.dns.plugins.module_utils.zone import (
    DNSZone,
    DNSZoneWithRecords,
)
from ansible_collections.community.dns.plugins.module_utils.zone_record_api import (
    NOT_PROVIDED,
    DNSAPIError,
    ZoneRecordAPI,
    filter_records,
)


def _create_record_from_json(source, record_type=None):
    source = dict(source)
    result = DNSRecord()
    result.id = source.pop('id')
    result.type = source.pop('type', record_type)
    ttl = source.pop('ttl')
    result.ttl = int(ttl) if ttl is not None else None
    result.extra['comment'] = source.pop('comment')

    name = source.pop('name', None)
    target = None
    if result.type == 'A':
        target = source.pop('ipv4')
    elif result.type == 'AAAA':
        target = source.pop('ipv6')
    elif result.type == 'CAA':
        target = '{0} {1} "{2}"'.format(source.pop('flag'), source.pop('tag'), source.pop('value'))
    elif result.type == 'CNAME':
        target = source.pop('cname')
    elif result.type == 'MX':
        mx_name, name = name, source.pop('ownername')
        target = '{0} {1}'.format(source.pop('pref'), mx_name)
    elif result.type == 'NS':
        name = source.pop('ownername')
        target = source.pop('targetname')
    elif result.type == 'PTR':
        ptr_name, name = name, ''
        target = '{0} {1}'.format(source.pop('origin'), ptr_name)
    elif result.type == 'SRV':
        name = source.pop('service')
        target = '{0} {1} {2} {3}'.format(source.pop('priority'), source.pop('weight'), source.pop('port'), source.pop('target'))
    elif result.type == 'TXT':
        target = source.pop('text')
    elif result.type == 'TLSA':
        target = source.pop('text')
    else:
        raise DNSAPIError('Cannot parse unknown record type: {0}'.format(result.type))

    result.prefix = name or None  # API returns '', we want None
    result.target = target
    result.extra.update(source)
    return result


def _create_zone_from_json(source):
    zone = DNSZone(source['name'])
    zone.id = source['id']
    zone.info = {
        'dnssec': source['dnssec'],
        'dnssec_email': source.get('dnssec_email'),
        'ds_records': source.get('ds_records'),
        'email': source.get('email'),
        'ttl': source['ttl'],
    }
    return zone


def _create_zone_with_records_from_json(source, prefix=NOT_PROVIDED, record_type=NOT_PROVIDED):
    return DNSZoneWithRecords(
        _create_zone_from_json(source),
        filter_records(
            [_create_record_from_json(record) for record in source['records']],
            prefix=prefix,
            record_type=record_type,
        ),
    )


def _record_to_json(record, include_id=False, include_type=True):
    result = {
        'ttl': record.ttl,
        'comment': record.extra.get('comment') or '',
    }
    if include_type:
        result['type'] = record.type
    if include_id:
        result['id'] = record.id

    if record.type == 'A':
        result['name'] = record.prefix or ''
        result['ipv4'] = record.target
    elif record.type == 'AAAA':
        result['name'] = record.prefix or ''
        result['ipv6'] = record.target
    elif record.type == 'CAA':
        result['name'] = record.prefix or ''
        try:
            flag, tag, value = record.target.split(' ', 2)
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            result['flag'] = flag
            result['tag'] = tag
            result['value'] = value
        except Exception as e:
            raise DNSAPIError(
                'Cannot split {0} record "{1}" into flag, tag and value: {2}'.format(
                    record.type, record.target, e))
    elif record.type == 'CNAME':
        result['name'] = record.prefix or ''
        result['cname'] = record.target
    elif record.type == 'MX':
        result['ownername'] = record.prefix or ''
        try:
            pref, name = record.target.split(' ', 1)
            result['pref'] = int(pref)
            result['name'] = name
        except Exception as e:
            raise DNSAPIError(
                'Cannot split {0} record "{1}" into integer preference and name: {2}'.format(
                    record.type, record.target, e))
    elif record.type == 'NS':
        result['ownername'] = record.prefix or ''
        result['targetname'] = record.target
    elif record.type == 'PTR':
        try:
            origin, name = record.target.split(' ', 1)
            result['origin'] = origin
            result['name'] = name
        except Exception as e:
            raise DNSAPIError(
                'Cannot split {0} record "{1}" into origin and name: {2}'.format(
                    record.type, record.target, e))
    elif record.type == 'SRV':
        result['service'] = record.prefix or ''
        try:
            priority, weight, port, target = record.target.split(' ', 3)
            result['priority'] = int(priority)
            result['weight'] = int(weight)
            result['port'] = int(port)
            result['target'] = target
        except Exception as e:
            raise DNSAPIError(
                'Cannot split {0} record "{1}" into integer priority, integer weight, integer port and target: {2}'.format(
                    record.type, record.target, e))
    elif record.type == 'TXT':
        result['name'] = record.prefix or ''
        result['text'] = record.target
    elif record.type == 'TLSA':
        result['name'] = record.prefix or ''
        result['text'] = record.target
    else:
        raise DNSAPIError('Cannot serialize unknown record type: {0}'.format(record.type))

    return result


class HostTechJSONAPI(ZoneRecordAPI, JSONAPIHelper):
    def __init__(self, http_helper, token, api='https://api.ns1.hosttech.eu/api/', debug=False):
        """
        Create a new HostTech API instance with given API token.
        """
        JSONAPIHelper.__init__(self, http_helper, token, api=api, debug=debug)

    def _extract_error_message(self, result):
        if result is None:
            return ''
        if isinstance(result, dict):
            res = ''
            if result.get('message'):
                res = '{0} with message "{1}"'.format(res, result['message'])
            if 'errors' in result:
                if isinstance(result['errors'], dict):
                    for k, v in sorted(result['errors'].items()):
                        if isinstance(v, list):
                            v = '; '.join(v)
                        res = '{0} (field "{1}": {2})'.format(res, k, v)
            if res:
                return res
        return ' with data: {0}'.format(result)

    def _create_headers(self):
        return {
            'accept': 'application/json',
            'authorization': 'Bearer {token}'.format(token=self._token),
        }

    def _list_pagination(self, url, query=None, block_size=100):
        result = []
        offset = 0
        while True:
            query_ = query.copy() if query else {}
            query_['limit'] = block_size
            query_['offset'] = offset
            res, dummy = self._get(url, query_, must_have_content=True, expected=[200])
            result.extend(res['data'])
            if len(res['data']) < block_size:
                return result
            offset += block_size

    def get_zone_with_records_by_id(self, zone_id, prefix=NOT_PROVIDED, record_type=NOT_PROVIDED):
        """
        Given a zone ID, return the zone contents with records if found.

        @param zone_id: The zone ID
        @param prefix: The prefix to filter for, if provided. Since None is a valid value,
                       the special constant NOT_PROVIDED indicates that we are not filtering.
        @param record_type: The record type to filter for, if provided
        @return The zone information with records (DNSZoneWithRecords), or None if not found
        """
        result, info = self._get('user/v1/zones/{0}'.format(zone_id), expected=[200, 404], must_have_content=[200])
        if info['status'] == 404:
            return None
        return _create_zone_with_records_from_json(result['data'], prefix=prefix, record_type=record_type)

    def get_zone_with_records_by_name(self, name, prefix=NOT_PROVIDED, record_type=NOT_PROVIDED):
        """
        Given a zone name, return the zone contents with records if found.

        @param name: The zone name (string)
        @param prefix: The prefix to filter for, if provided. Since None is a valid value,
                       the special constant NOT_PROVIDED indicates that we are not filtering.
        @param record_type: The record type to filter for, if provided
        @return The zone information with records (DNSZoneWithRecords), or None if not found
        """
        result = self._list_pagination('user/v1/zones', query={'query': name})
        for zone in result:
            if zone['name'] == name:
                result, dummy = self._get('user/v1/zones/{0}'.format(zone['id']), expected=[200])
                return _create_zone_with_records_from_json(result['data'], prefix=prefix, record_type=record_type)
        return None

    def get_zone_records(self, zone_id, prefix=NOT_PROVIDED, record_type=NOT_PROVIDED):
        """
        Given a zone ID, return a list of records, optionally filtered by the provided criteria.

        @param zone_id: The zone ID
        @param prefix: The prefix to filter for, if provided. Since None is a valid value,
                       the special constant NOT_PROVIDED indicates that we are not filtering.
        @param record_type: The record type to filter for, if provided
        @return A list of DNSrecord objects, or None if zone was not found
        """
        query = {}
        if record_type is not NOT_PROVIDED:
            query['type'] = record_type.upper()
        result, info = self._get('user/v1/zones/{0}/records'.format(zone_id), query=query, expected=[200, 404], must_have_content=[200])
        if info['status'] == 404:
            return None
        return filter_records(
            [_create_record_from_json(record) for record in result['data']],
            prefix=prefix,
            record_type=record_type,
        )

    def get_zone_by_name(self, name):
        """
        Given a zone name, return the zone contents if found.

        @param name: The zone name (string)
        @return The zone information (DNSZone), or None if not found
        """
        result = self._list_pagination('user/v1/zones', query={'query': name})
        for zone in result:
            if zone['name'] == name:
                # We cannot simply return `_create_zone_from_json(zone)`, since this contains less information!
                return self.get_zone_by_id(zone['id'])
        return None

    def get_zone_by_id(self, zone_id):
        """
        Given a zone ID, return the zone contents if found.

        @param zone_id: The zone ID
        @return The zone information (DNSZone), or None if not found
        """
        result, info = self._get('user/v1/zones/{0}'.format(zone_id), expected=[200, 404], must_have_content=[200])
        if info['status'] == 404:
            return None
        return _create_zone_from_json(result['data'])

    def add_record(self, zone_id, record):
        """
        Adds a new record to an existing zone.

        @param zone_id: The zone ID
        @param record: The DNS record (DNSRecord)
        @return The created DNS record (DNSRecord)
        """
        data = _record_to_json(record, include_id=False, include_type=True)
        result, dummy = self._post('user/v1/zones/{0}/records'.format(zone_id), data=data, expected=[201])
        return _create_record_from_json(result['data'])

    def update_record(self, zone_id, record):
        """
        Update a record.

        @param zone_id: The zone ID
        @param record: The DNS record (DNSRecord)
        @return The DNS record (DNSRecord)
        """
        if record.id is None:
            raise DNSAPIError('Need record ID to update record!')
        data = _record_to_json(record, include_id=False, include_type=False)
        result, dummy = self._put('user/v1/zones/{0}/records/{1}'.format(zone_id, record.id), data=data, expected=[200])
        return _create_record_from_json(result['data'])

    def delete_record(self, zone_id, record):
        """
        Delete a record.

        @param zone_id: The zone ID
        @param record: The DNS record (DNSRecord)
        @return True in case of success (boolean)
        """
        if record.id is None:
            raise DNSAPIError('Need record ID to delete record!')
        dummy, info = self._delete('user/v1/zones/{0}/records/{1}'.format(zone_id, record.id), must_have_content=False, expected=[204, 404])
        return info['status'] == 204
