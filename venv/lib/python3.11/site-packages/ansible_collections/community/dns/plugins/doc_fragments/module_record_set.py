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
  check_mode:
    support: full
  diff_mode:
    support: full
  idempotent:
    support: full
options:
  state:
    description:
      - Specifies the state of the resource record.
    required: true
    choices: ['present', 'absent']
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
    version_added: 0.2.0
  record:
    description:
      - The full DNS record to create or delete.
      - Exactly one of O(record) and O(prefix) must be specified.
    type: str
  prefix:
    description:
      - The prefix of the DNS record.
      - This is the part of O(record) before O(zone_name). For example, if the record to be modified is C(www.example.com)
        for the zone C(example.com), the prefix is V(www). If the record in this example would be C(example.com), the prefix
        would be V('') (empty string).
      - Exactly one of O(record) and O(prefix) must be specified.
    type: str
    version_added: 0.2.0
  ttl:
    description:
      - The TTL to give the new record, in seconds.
    type: int
  type:
    description:
      - The type of DNS record to create or delete.
    required: true
    type: str
  value:
    description:
      - The new value when creating a DNS record.
      - YAML lists or multiple comma-spaced values are allowed.
      - When deleting a record all values for the record must be specified or it will not be deleted.
      - Must be specified if O(state=present) or when O(on_existing) is not V(replace).
      - Will be ignored if O(state=absent) and O(on_existing=replace).
    type: list
    elements: str
  on_existing:
    description:
      - This option defines the behavior if the record set already exists, but differs from the specified record set. For
        this comparison, O(value) and O(ttl) are used for all records of type O(type) matching the O(prefix) resp. O(record).
      - If set to V(replace), the record will be updated (O(state=present)) or removed (O(state=absent)). This is the old
        O(ignore:overwrite=true) behavior.
      - If set to V(keep_and_fail), the module will fail and not modify the records. This is the old O(ignore:overwrite=false)
        behavior if O(state=present).
      - If set to V(keep_and_warn), the module will warn and not modify the records.
      - If set to V(keep), the module will not modify the records. This is the old O(ignore:overwrite=false) behavior if O(state=absent).
      - If O(state=absent) and the value is not V(replace), O(value) must be specified.
    default: replace
    type: str
    choices:
      - replace
      - keep_and_fail
      - keep_and_warn
      - keep
"""
