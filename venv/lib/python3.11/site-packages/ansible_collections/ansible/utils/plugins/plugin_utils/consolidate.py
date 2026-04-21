#
# -*- coding: utf-8 -*-
# Copyright 2022 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

"""
The consolidate plugin code
"""
from __future__ import absolute_import, division, print_function


__metaclass__ = type

import itertools

from ansible.errors import AnsibleFilterError


def _raise_error(err):
    """Raise an error message, prepend with filter name

    Args:
        filter (str): Filter name
        msg (str): Message specific to filter supplied

    Raises:
        AnsibleFilterError: AnsibleError with filter name and message
    """
    tmp_err = []
    tmplt_err = "Error when using plugin 'consolidate': '{filter}' reported {msg}"
    for filter in list(err.keys()):
        if err.get(filter):
            msg = ", ".join(err.get(filter))
            tmp_err.append(tmplt_err.format(filter=filter, msg=msg))
    error = "; ".join(tmp_err)
    raise AnsibleFilterError(error)


def fail_on_filter(validator_func):
    """Decorator to fail on supplied filters

    Args:
        validator_func (func): Function that generates failure messages

    Returns:
        raw: Value without errors if generated and not failed
    """

    def update_err(*args, **kwargs):
        """Filters return value or raises error as per supplied parameters

        Returns:
            any: Return value to the function call
        """
        res, err = validator_func(*args, **kwargs)
        if any(
            [
                err.get("fail_missing_match_key"),
                err.get("fail_duplicate"),
                err.get("fail_missing_match_value"),
            ],
        ):
            _raise_error(err)
        return res

    return update_err


@fail_on_filter
def check_missing_match_key_duplicate(data_sources, fail_missing_match_key, fail_duplicate):
    """Check if the match_key specified is present in all the supplied data,
    also check for duplicate data accross all the data sources

    Args:
        data_sources (list): list of dicts as data sources
        fail_missing_match_key (bool): Fails if match_keys not present in data set
        fail_duplicate (bool): Fails if duplicate data present in a data
    Returns:
        list: list of unique keys based on specified match_keys
    """
    results, errors_match_key, errors_duplicate = [], [], []
    for ds_idx, data_source in enumerate(data_sources, start=1):
        match_key = data_source["match_key"]
        ds_values = []

        for dd_idx, data_dict in enumerate(data_source["data"], start=1):
            try:
                ds_values.append(data_dict[match_key])
            except KeyError:
                if fail_missing_match_key:
                    errors_match_key.append(
                        "missing match key '{match_key}' in data source {ds_idx} in list entry {dd_idx}".format(
                            match_key=match_key,
                            ds_idx=ds_idx,
                            dd_idx=dd_idx,
                        ),
                    )
                continue

        if sorted(set(ds_values)) != sorted(ds_values) and fail_duplicate:
            errors_duplicate.append(
                "duplicate values in data source {ds_idx}".format(ds_idx=ds_idx),
            )
        results.append(set(ds_values))
    return results, {
        "fail_missing_match_key": errors_match_key,
        "fail_duplicate": errors_duplicate,
    }


@fail_on_filter
def check_missing_match_values(matched_keys, fail_missing_match_value):
    """Checks values to match be consistent over all the whole data source

    Args:
        matched_keys (list): list of unique keys based on specified match_keys
        fail_missing_match_value (bool): Fail if match_key value is missing in a data set
    Returns:
        set: set of unique values
    """
    all_values = set(itertools.chain.from_iterable(matched_keys))
    if not fail_missing_match_value:
        return all_values, {}
    errors_match_values = []
    for ds_idx, ds_values in enumerate(matched_keys, start=1):
        missing_match = all_values - ds_values
        if missing_match:
            m_matches = ", ".join(missing_match)
            errors_match_values.append(
                "missing match value {m_matches} in data source {ds_idx}".format(
                    ds_idx=ds_idx,
                    m_matches=m_matches,
                ),
            )
    return all_values, {"fail_missing_match_value": errors_match_values}


def consolidate_facts(data_sources, all_values):
    """Iterate over all the data sources and consolidate the data

    Args:
        data_sources (list): supplied data sources
        all_values (set): a set of keys to iterate over

    Returns:
        list: list of consolidated data
    """

    consolidated_facts = {}
    for data_source in data_sources:
        match_key = data_source["match_key"]
        source = data_source["name"]
        data_dict = {d[match_key]: d for d in data_source["data"] if match_key in d}
        for value in sorted(all_values):
            if value not in consolidated_facts:
                consolidated_facts[value] = {}
            consolidated_facts[value][source] = data_dict.get(value, {})
    return consolidated_facts


def consolidate(
    data_sources,
    fail_missing_match_key,
    fail_missing_match_value,
    fail_duplicate,
):
    """Calls data validation and consolidation functions

    Args:
        data_source (list): list of dicts as data sources
        fail_missing_match_key (bool, optional): Fails if match_keys not present in data set. Defaults to False.
        fail_missing_match_value (bool, optional): Fails if matching attribute missing in a data. Defaults to False.
        fail_duplicate (bool, optional): Fails if duplicate data present in a data. Defaults to False.

    Returns:
        list: list of dicts of validated and consolidated data
    """

    key_sets = check_missing_match_key_duplicate(
        data_sources,
        fail_missing_match_key,
        fail_duplicate,
    )
    key_vals = check_missing_match_values(key_sets, fail_missing_match_value)
    consolidated_facts = consolidate_facts(data_sources, key_vals)
    return consolidated_facts
