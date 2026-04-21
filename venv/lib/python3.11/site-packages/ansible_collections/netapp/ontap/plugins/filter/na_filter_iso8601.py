# (c) 2022, NetApp, Inc
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
Filters for ISO 8601 durations
'''

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible.errors import AnsibleFilterError
from ansible.module_utils._text import to_native

IMPORT_ERROR = None
try:
    import isodate
except ImportError as exc:
    IMPORT_ERROR = to_native(exc)


class FilterModule:
    ''' Ansible jinja2 filters '''

    def filters(self):
        return {
            'iso8601_duration_to_seconds': iso8601_duration_to_seconds,
            'iso8601_duration_from_seconds': iso8601_duration_from_seconds,
        }


def check_for_import():
    if IMPORT_ERROR:
        raise AnsibleFilterError("isodate python package is required:  %s" % IMPORT_ERROR)


def iso8601_duration_to_seconds(duration):
    check_for_import()
    try:
        dt_duration = isodate.parse_duration(duration)
    except Exception as exc:
        raise AnsibleFilterError("iso8601_duration_to_seconds - error: %s - expecting PnnYnnMnnDTnnHnnMnnS, received: %s" % (to_native(exc), duration))
    return dt_duration.total_seconds()


def iso8601_duration_from_seconds(seconds, format=None):
    check_for_import()
    try:
        duration = isodate.Duration(seconds=seconds)
        iso8601_duration = isodate.duration_isoformat(duration, format=isodate.D_DEFAULT if format is None else format)
    except Exception as exc:
        raise AnsibleFilterError("iso8601_duration_from_seconds - error: %s - received: %s" % (to_native(exc), seconds))
    return iso8601_duration
