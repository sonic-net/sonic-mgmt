#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = r"""
module: wait_for_txt
short_description: Wait for TXT entries to be available on all authoritative nameservers
version_added: 0.1.0
description:
  - Wait for TXT entries with specific values to show up on B(all) authoritative nameservers for the DNS name.
extends_documentation_fragment:
  - community.dns.attributes
  - community.dns.attributes.idempotent_not_modify_state
attributes:
  check_mode:
    support: full
    details:
      - This action does not modify state.
    version_added: 2.4.0
  diff_mode:
    support: N/A
    details:
      - This action does not modify state.
author:
  - Felix Fontein (@felixfontein)
options:
  records:
    description:
      - A list of DNS names with TXT entries to look out for.
    required: true
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - A DNS name, like V(www.example.com).
        type: str
        required: true
      values:
        description:
          - The TXT values to look for.
          - The alias O(records[].entries) has been added in community.dns 3.4.0.
        aliases:
          - entries
        type: list
        elements: str
        required: true
      mode:
        description:
          - Comparison modes for the values in O(records[].values).
          - If V(subset), O(records[].values) should be a (not necessarily proper) subset of the TXT values set for the DNS
            name.
          - If V(superset), O(records[].values) should be a (not necessarily proper) superset of the TXT values set for the
            DNS name. This includes the case that no TXT entries are set.
          - If V(superset_not_empty), O(records[].values) should be a (not necessarily proper) superset of the TXT values
            set for the DNS name, assuming at least one TXT record is present.
          - If V(equals), O(records[].values) should be the same set of strings as the TXT values for the DNS name (up to
            order).
          - If V(equals_ordered), O(records[].values) should be the same ordered list of strings as the TXT values for the
            DNS name.
        type: str
        default: subset
        choices:
          - subset
          - superset
          - superset_not_empty
          - equals
          - equals_ordered
  query_retry:
    description:
      - Number of retries for DNS query timeouts.
    type: int
    default: 3
  query_timeout:
    description:
      - Timeout per DNS query in seconds.
    type: float
    default: 10
  timeout:
    description:
      - Global timeout for waiting for all records in seconds.
      - If not set, will wait indefinitely.
    type: float
  max_sleep:
    description:
      - Maximal amount of seconds to sleep between two rounds of probing the TXT records.
    type: float
    default: 10
  always_ask_default_resolver:
    description:
      - When set to V(true) (default), will use the default resolver to find the authoritative nameservers of a subzone. See
        O(server) for how to configure the default resolver.
      - When set to V(false), will use the authoritative nameservers of the parent zone to find the authoritative nameservers
        of a subzone. This only makes sense when the nameservers were recently changed and have not yet propagated.
    type: bool
    default: true
  servfail_retries:
    description:
      - How often to retry on SERVFAIL errors.
    type: int
    default: 0
    version_added: 2.6.0
  server:
    description:
      - The DNS server(s) to use to look up the result. Must be a list of one or more IP addresses.
      - By default, the system's standard resolver is used.
    type: list
    elements: str
    version_added: 2.7.0
requirements:
  - dnspython >= 1.15.0 (maybe older versions also work)
"""

EXAMPLES = r"""
- name: Wait for a TXT entry to appear
  community.dns.wait_for_txt:
    records:
      # We want that www.example.com has a single TXT record with value 'Hello world!'.
      # There should not be any other TXT record for www.example.com.
      - name: www.example.com
        values: "Hello world!"
        mode: equals
      # We want that example.com has a specific SPF record set.
      # We do not care about other TXT records.
      - name: www.example.com
        values: "v=spf1 a mx -all"
        mode: subset
"""

RETURN = r"""
records:
  description:
    - Results on the TXT records queried.
    - The entries are in a 1:1 correspondence to the entries of the O(records) parameter, in exactly the same order.
  returned: always
  type: list
  elements: dict
  contains:
    name:
      description:
        - The DNS name this check is for.
      returned: always
      type: str
      sample: example.com
    done:
      description:
        - Whether the check completed.
      returned: always
      type: bool
      sample: false
    values:
      description:
        - For every authoritative nameserver for the DNS name, lists the TXT records retrieved during the last lookup made.
        - Once the check completed for all TXT records retrieved, the TXT records for this DNS name are no longer checked.
        - If these are multiple TXT entries for a nameserver, the order is as it was received from that nameserver. This might
          not be the same order provided in the check.
        - B(The field has been renamed) to RV(records[].entries) in community.dns 3.4.0.
          While the old name will be around for a longer time, prefer using the new one.
      returned: lookup was done at least once
      type: dict
      elements: list
    entries:
      description:
        - For every authoritative nameserver for the DNS name, lists the TXT records retrieved during the last lookup made.
        - Once the check completed for all TXT records retrieved, the TXT records for this DNS name are no longer checked.
        - If these are multiple TXT entries for a nameserver, the order is as it was received from that nameserver. This might
          not be the same order provided in the check.
        - This field has been called RV(records[].values) before.
      returned: lookup was done at least once
      type: dict
      elements: list
      sample:
        ns1.example.com:
          - TXT value 1
          - TXT value 2
        ns2.example.com:
          - TXT value 2
      version_added: 3.4.0
    check_count:
      description:
        - How often the TXT records for this DNS name were checked.
      returned: always
      type: int
      sample: 3
  sample:
    - name: example.com
      done: true
      entries: [a, b, c]
      check_count: 1
    - name: foo.example.org
      done: false
      check_count: 0
completed:
  description:
    - How many of the checks were completed.
  returned: always
  type: int
  sample: 3
"""

import time


try:
    from time import monotonic
except ImportError:
    from time import clock as monotonic  # type: ignore

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_text
from ansible_collections.community.dns.plugins.module_utils.resolver import (
    ResolveDirectlyFromNameServers,
    assert_requirements_present,
    guarded_run,
)


try:
    import dns.rdatatype
except ImportError:
    pass  # handled in assert_requirements_present()


def lookup(resolver, name):
    result = {}
    txts = resolver.resolve(name, rdtype=dns.rdatatype.TXT)
    for key, txt in txts.items():
        res = []
        if txt is not None:
            for data in txt:
                line = []
                for txtstring in data.strings:
                    line.append(to_text(txtstring))
                res.append(u''.join(line))
        result[key] = res
        txts[key] = []
    return result


def validate_check(record_values, expected_values, comparison_mode):
    if comparison_mode == 'subset':
        return set(expected_values) <= set(record_values)

    if comparison_mode == 'superset':
        return set(expected_values) >= set(record_values)

    if comparison_mode == 'superset_not_empty':
        return bool(record_values) and set(expected_values) >= set(record_values)

    if comparison_mode == 'equals':
        return sorted(record_values) == sorted(expected_values)

    if comparison_mode == 'equals_ordered':
        return record_values == expected_values

    raise AssertionError('Internal error!')  # pragma: no cover


class Waiter(object):
    def __init__(self, module):
        self.module = module

        self.resolver = ResolveDirectlyFromNameServers(
            timeout=self.module.params['query_timeout'],
            timeout_retries=self.module.params['query_retry'],
            servfail_retries=self.module.params['servfail_retries'],
            always_ask_default_resolver=self.module.params['always_ask_default_resolver'],
            server_addresses=self.module.params['server'],
        )
        self.records = self.module.params['records']
        self.timeout = self.module.params['timeout']
        self.max_sleep = self.module.params['max_sleep']

        self.results = [None] * len(self.records)
        for index, record in enumerate(self.records):
            self.results[index] = {
                'name': record['name'],
                'done': False,
                'check_count': 0,
            }
        self.finished_checks = 0

    def _run(self):
        start_time = monotonic()

        step = 0
        while True:
            has_timeout = False
            if self.timeout is not None:
                expired = monotonic() - start_time
                has_timeout = expired > self.timeout

            done = True
            for index, record in enumerate(self.records):
                if self.results[index]['done']:
                    continue
                txts = lookup(self.resolver, record['name'])
                self.results[index]['values'] = txts
                self.results[index]['entries'] = txts
                self.results[index]['check_count'] += 1
                if txts and all(validate_check(txt, record['values'], record['mode']) for txt in txts.values()):
                    self.results[index]['done'] = True
                    self.finished_checks += 1
                else:
                    done = False

            if done:
                self.module.exit_json(
                    msg='All checks passed',
                    **self._generate_additional_results()
                )

            if has_timeout:
                self.module.fail_json(
                    msg='Timeout ({0} out of {1} check(s) passed).'.format(self.finished_checks, len(self.records)),
                    **self._generate_additional_results()
                )

            # Simple quadratic sleep with maximum wait of max_sleep seconds
            wait = min(2 + step * 0.5, self.max_sleep)
            if self.timeout is not None:
                # Make sure we do not exceed the timeout by much by waiting
                expired = monotonic() - start_time
                wait = max(min(wait, self.timeout - expired + 0.1), 0.1)

            time.sleep(wait)
            step += 1

    def _generate_additional_results(self):
        return {
            'records': self.results,
            'completed': self.finished_checks,
        }

    def run(self):
        guarded_run(self._run, self.module, generate_additional_results=self._generate_additional_results)


def main():
    module = AnsibleModule(
        argument_spec={
            'records': {'required': True, 'type': 'list', 'elements': 'dict', 'options': {
                'name': {'required': True, 'type': 'str'},
                'values': {'required': True, 'type': 'list', 'elements': 'str', 'aliases': ['entries']},
                'mode': {'type': 'str', 'default': 'subset', 'choices': ['subset', 'superset', 'superset_not_empty', 'equals', 'equals_ordered']},
            }},
            'query_retry': {'type': 'int', 'default': 3},
            'query_timeout': {'type': 'float', 'default': 10},
            'timeout': {'type': 'float'},
            'max_sleep': {'type': 'float', 'default': 10},
            'always_ask_default_resolver': {'type': 'bool', 'default': True},
            'servfail_retries': {'type': 'int', 'default': 0},
            'server': {'type': 'list', 'elements': 'str'},
        },
        supports_check_mode=True,
    )
    assert_requirements_present(module)

    waiter = Waiter(module)
    waiter.run()


if __name__ == "__main__":
    main()
