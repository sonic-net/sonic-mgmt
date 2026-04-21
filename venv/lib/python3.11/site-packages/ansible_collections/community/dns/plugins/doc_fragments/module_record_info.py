# -*- coding: utf-8 -*-
#
# Copyright (c) 2021 Felix Fontein
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


class ModuleDocFragment(object):

    # Standard files documentation fragment

    # NOTE: This document fragment needs to be augmented by ZONE_ID_TYPE in a provider document fragment.
    #       The ZONE_ID_TYPE fragment will provide `choices` for the options.type entry.
    DOCUMENTATION = r"""
attributes:
  idempotent:
    support: full
options:
  what:
    description:
      - Describes whether to fetch a single record and type combination, all types for a record, or all records. By default,
        a single record and type combination is fetched.
      - Note that the return value structure depends on this option.
    choices: ['single_record', 'all_types_for_record', 'all_records']
    default: single_record
    type: str
  zone_name:
    description:
      - The DNS zone to modify.
      - Exactly one of O(zone_name) and O(zone_id) must be specified.
    type: str
    aliases:
      - zone
  zone_id:
    description:
      - The ID of the DNS zone to modify.
      - Exactly one of O(zone_name) and O(zone_id) must be specified.
  record:
    description:
      - The full DNS record to retrieve.
      - If O(what) is V(single_record) or V(all_types_for_record), exactly one of O(record) and O(prefix) is required.
    type: str
  prefix:
    description:
      - The prefix of the DNS record.
      - This is the part of O(record) before O(zone_name). For example, if the record to be modified is C(www.example.com)
        for the zone C(example.com), the prefix is V(www). If the record in this example would be C(example.com), the prefix
        would be V('') (empty string).
      - If O(what) is V(single_record) or V(all_types_for_record), exactly one of O(record) and O(prefix) is required.
    type: str
  type:
    description:
      - The type of DNS record to retrieve.
      - Required if O(what) is V(single_record).
    type: str
"""
