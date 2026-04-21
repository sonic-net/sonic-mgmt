# Copyright 2016 Red Hat | Ansible
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


import json
import re
from datetime import timedelta

from ansible.module_utils.basic import env_fallback
from ansible.module_utils.common.collections import is_sequence
from ansible_collections.community.docker.plugins.module_utils._six import string_types, urlparse
from ansible.module_utils.common.text.converters import to_text

try:
    import ipaddress
    HAS_IPADDRESS = True
except ImportError:
    HAS_IPADDRESS = False


DEFAULT_DOCKER_HOST = 'unix:///var/run/docker.sock'
DEFAULT_TLS = False
DEFAULT_TLS_VERIFY = False
DEFAULT_TLS_HOSTNAME = 'localhost'  # deprecated
DEFAULT_TIMEOUT_SECONDS = 60

DOCKER_COMMON_ARGS = dict(
    docker_host=dict(type='str', default=DEFAULT_DOCKER_HOST, fallback=(env_fallback, ['DOCKER_HOST']), aliases=['docker_url']),
    tls_hostname=dict(type='str', fallback=(env_fallback, ['DOCKER_TLS_HOSTNAME'])),
    api_version=dict(type='str', default='auto', fallback=(env_fallback, ['DOCKER_API_VERSION']), aliases=['docker_api_version']),
    timeout=dict(type='int', default=DEFAULT_TIMEOUT_SECONDS, fallback=(env_fallback, ['DOCKER_TIMEOUT'])),
    ca_path=dict(type='path', aliases=['ca_cert', 'tls_ca_cert', 'cacert_path']),
    client_cert=dict(type='path', aliases=['tls_client_cert', 'cert_path']),
    client_key=dict(type='path', aliases=['tls_client_key', 'key_path']),
    tls=dict(type='bool', default=DEFAULT_TLS, fallback=(env_fallback, ['DOCKER_TLS'])),
    use_ssh_client=dict(type='bool', default=False),
    validate_certs=dict(type='bool', default=DEFAULT_TLS_VERIFY, fallback=(env_fallback, ['DOCKER_TLS_VERIFY']), aliases=['tls_verify']),
    debug=dict(type='bool', default=False)
)

DOCKER_COMMON_ARGS_VARS = dict([
    [option_name, 'ansible_docker_%s' % option_name]
    for option_name in DOCKER_COMMON_ARGS
    if option_name != 'debug'
])

DOCKER_MUTUALLY_EXCLUSIVE = []

DOCKER_REQUIRED_TOGETHER = [
    ['client_cert', 'client_key']
]

DEFAULT_DOCKER_REGISTRY = 'https://index.docker.io/v1/'
BYTE_SUFFIXES = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']


def is_image_name_id(name):
    """Check whether the given image name is in fact an image ID (hash)."""
    if re.match('^sha256:[0-9a-fA-F]{64}$', name):
        return True
    return False


def is_valid_tag(tag, allow_empty=False):
    """Check whether the given string is a valid docker tag name."""
    if not tag:
        return allow_empty
    # See here ("Extended description") for a definition what tags can be:
    # https://docs.docker.com/engine/reference/commandline/tag/
    return bool(re.match('^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}$', tag))


def sanitize_result(data):
    """Sanitize data object for return to Ansible.

    When the data object contains types such as docker.types.containers.HostConfig,
    Ansible will fail when these are returned via exit_json or fail_json.
    HostConfig is derived from dict, but its constructor requires additional
    arguments. This function sanitizes data structures by recursively converting
    everything derived from dict to dict and everything derived from list (and tuple)
    to a list.
    """
    if isinstance(data, dict):
        return dict((k, sanitize_result(v)) for k, v in data.items())
    elif isinstance(data, (list, tuple)):
        return [sanitize_result(v) for v in data]
    else:
        return data


def log_debug(msg, pretty_print=False):
    """Write a log message to docker.log.

    If ``pretty_print=True``, the message will be pretty-printed as JSON.
    """
    with open('docker.log', 'a') as log_file:
        if pretty_print:
            log_file.write(json.dumps(msg, sort_keys=True, indent=4, separators=(',', ': ')))
            log_file.write(u'\n')
        else:
            log_file.write(msg + u'\n')


class DockerBaseClass(object):
    def __init__(self):
        self.debug = False

    def log(self, msg, pretty_print=False):
        pass
        # if self.debug:
        #     log_debug(msg, pretty_print=pretty_print)


def update_tls_hostname(result, old_behavior=False, deprecate_function=None, uses_tls=True):
    if result['tls_hostname'] is None:
        # get default machine name from the url
        parsed_url = urlparse(result['docker_host'])
        result['tls_hostname'] = parsed_url.netloc.rsplit(':', 1)[0]


def compare_dict_allow_more_present(av, bv):
    '''
    Compare two dictionaries for whether every entry of the first is in the second.
    '''
    for key, value in av.items():
        if key not in bv:
            return False
        if bv[key] != value:
            return False
    return True


def compare_generic(a, b, method, datatype):
    '''
    Compare values a and b as described by method and datatype.

    Returns ``True`` if the values compare equal, and ``False`` if not.

    ``a`` is usually the module's parameter, while ``b`` is a property
    of the current object. ``a`` must not be ``None`` (except for
    ``datatype == 'value'``).

    Valid values for ``method`` are:
    - ``ignore`` (always compare as equal);
    - ``strict`` (only compare if really equal)
    - ``allow_more_present`` (allow b to have elements which a does not have).

    Valid values for ``datatype`` are:
    - ``value``: for simple values (strings, numbers, ...);
    - ``list``: for ``list``s or ``tuple``s where order matters;
    - ``set``: for ``list``s, ``tuple``s or ``set``s where order does not
      matter;
    - ``set(dict)``: for ``list``s, ``tuple``s or ``sets`` where order does
      not matter and which contain ``dict``s; ``allow_more_present`` is used
      for the ``dict``s, and these are assumed to be dictionaries of values;
    - ``dict``: for dictionaries of values.
    '''
    if method == 'ignore':
        return True
    # If a or b is None:
    if a is None or b is None:
        # If both are None: equality
        if a == b:
            return True
        # Otherwise, not equal for values, and equal
        # if the other is empty for set/list/dict
        if datatype == 'value':
            return False
        # For allow_more_present, allow a to be None
        if method == 'allow_more_present' and a is None:
            return True
        # Otherwise, the iterable object which is not None must have length 0
        return len(b if a is None else a) == 0
    # Do proper comparison (both objects not None)
    if datatype == 'value':
        return a == b
    elif datatype == 'list':
        if method == 'strict':
            return a == b
        else:
            i = 0
            for v in a:
                while i < len(b) and b[i] != v:
                    i += 1
                if i == len(b):
                    return False
                i += 1
            return True
    elif datatype == 'dict':
        if method == 'strict':
            return a == b
        else:
            return compare_dict_allow_more_present(a, b)
    elif datatype == 'set':
        set_a = set(a)
        set_b = set(b)
        if method == 'strict':
            return set_a == set_b
        else:
            return set_b >= set_a
    elif datatype == 'set(dict)':
        for av in a:
            found = False
            for bv in b:
                if compare_dict_allow_more_present(av, bv):
                    found = True
                    break
            if not found:
                return False
        if method == 'strict':
            # If we would know that both a and b do not contain duplicates,
            # we could simply compare len(a) to len(b) to finish this test.
            # We can assume that b has no duplicates (as it is returned by
            # docker), but we do not know for a.
            for bv in b:
                found = False
                for av in a:
                    if compare_dict_allow_more_present(av, bv):
                        found = True
                        break
                if not found:
                    return False
        return True


class DifferenceTracker(object):
    def __init__(self):
        self._diff = []

    def add(self, name, parameter=None, active=None):
        self._diff.append(dict(
            name=name,
            parameter=parameter,
            active=active,
        ))

    def merge(self, other_tracker):
        self._diff.extend(other_tracker._diff)

    @property
    def empty(self):
        return len(self._diff) == 0

    def get_before_after(self):
        '''
        Return texts ``before`` and ``after``.
        '''
        before = dict()
        after = dict()
        for item in self._diff:
            before[item['name']] = item['active']
            after[item['name']] = item['parameter']
        return before, after

    def has_difference_for(self, name):
        '''
        Returns a boolean if a difference exists for name
        '''
        return any(diff for diff in self._diff if diff['name'] == name)

    def get_legacy_docker_container_diffs(self):
        '''
        Return differences in the docker_container legacy format.
        '''
        result = []
        for entry in self._diff:
            item = dict()
            item[entry['name']] = dict(
                parameter=entry['parameter'],
                container=entry['active'],
            )
            result.append(item)
        return result

    def get_legacy_docker_diffs(self):
        '''
        Return differences in the docker_container legacy format.
        '''
        result = [entry['name'] for entry in self._diff]
        return result


def sanitize_labels(labels, labels_field, client=None, module=None):
    def fail(msg):
        if client is not None:
            client.fail(msg)
        if module is not None:
            module.fail_json(msg=msg)
        raise ValueError(msg)

    if labels is None:
        return
    for k, v in list(labels.items()):
        if not isinstance(k, string_types):
            fail(
                "The key {key!r} of {field} is not a string!".format(
                    field=labels_field, key=k))
        if isinstance(v, (bool, float)):
            fail(
                "The value {value!r} for {key!r} of {field} is not a string or something than can be safely converted to a string!".format(
                    field=labels_field, key=k, value=v))
        labels[k] = to_text(v)


def clean_dict_booleans_for_docker_api(data, allow_sequences=False):
    '''
    Go does not like Python booleans 'True' or 'False', while Ansible is just
    fine with them in YAML. As such, they need to be converted in cases where
    we pass dictionaries to the Docker API (e.g. docker_network's
    driver_options and docker_prune's filters). When `allow_sequences=True`
    YAML sequences (lists, tuples) are converted to [str] instead of str([...])
    which is the expected format of filters which accept lists such as labels.
    '''
    def sanitize(value):
        if value is True:
            return 'true'
        elif value is False:
            return 'false'
        else:
            return str(value)

    result = dict()
    if data is not None:
        for k, v in data.items():
            result[str(k)] = [sanitize(e) for e in v] if allow_sequences and is_sequence(v) else sanitize(v)
    return result


def convert_duration_to_nanosecond(time_str):
    """
    Return time duration in nanosecond.
    """
    if not isinstance(time_str, str):
        raise ValueError('Missing unit in duration - %s' % time_str)

    regex = re.compile(
        r'^(((?P<hours>\d+)h)?'
        r'((?P<minutes>\d+)m(?!s))?'
        r'((?P<seconds>\d+)s)?'
        r'((?P<milliseconds>\d+)ms)?'
        r'((?P<microseconds>\d+)us)?)$'
    )
    parts = regex.match(time_str)

    if not parts:
        raise ValueError('Invalid time duration - %s' % time_str)

    parts = parts.groupdict()
    time_params = {}
    for (name, value) in parts.items():
        if value:
            time_params[name] = int(value)

    delta = timedelta(**time_params)
    time_in_nanoseconds = (
        delta.microseconds + (delta.seconds + delta.days * 24 * 3600) * 10 ** 6
    ) * 10 ** 3

    return time_in_nanoseconds


def normalize_healthcheck_test(test):
    if isinstance(test, (tuple, list)):
        return [str(e) for e in test]
    return ['CMD-SHELL', str(test)]


def normalize_healthcheck(healthcheck, normalize_test=False):
    """
    Return dictionary of healthcheck parameters.
    """
    result = dict()

    # All supported healthcheck parameters
    options = ('test', 'test_cli_compatible', 'interval', 'timeout', 'start_period', 'start_interval', 'retries')

    duration_options = ('interval', 'timeout', 'start_period', 'start_interval')

    for key in options:
        if key in healthcheck:
            value = healthcheck[key]
            if value is None:
                # due to recursive argument_spec, all keys are always present
                # (but have default value None if not specified)
                continue
            if key in duration_options:
                value = convert_duration_to_nanosecond(value)
            if not value and not (healthcheck.get('test_cli_compatible') and key == 'test'):
                continue
            if key == 'retries':
                try:
                    value = int(value)
                except ValueError:
                    raise ValueError(
                        'Cannot parse number of retries for healthcheck. '
                        'Expected an integer, got "{0}".'.format(value)
                    )
            if key == 'test' and value and normalize_test:
                value = normalize_healthcheck_test(value)
            result[key] = value

    return result


def parse_healthcheck(healthcheck):
    """
    Return dictionary of healthcheck parameters and boolean if
    healthcheck defined in image was requested to be disabled.
    """
    if (not healthcheck) or (not healthcheck.get('test')):
        return None, None

    result = normalize_healthcheck(healthcheck, normalize_test=True)

    if result['test'] == ['NONE']:
        # If the user explicitly disables the healthcheck, return None
        # as the healthcheck object, and set disable_healthcheck to True
        return None, True

    return result, False


def omit_none_from_dict(d):
    """
    Return a copy of the dictionary with all keys with value None omitted.
    """
    return dict((k, v) for (k, v) in d.items() if v is not None)


def normalize_ip_address(ip_address):
    """
    Given an IP address as a string, normalize it so that it can be
    used to compare IP addresses as strings.
    """
    if ip_address is None:
        return None
    if HAS_IPADDRESS:
        try:
            return ipaddress.ip_address(ip_address).compressed
        except ValueError:
            # Fallback for invalid addresses: simply return the input
            return ip_address
    # If we don't have ipaddress, simply give up...
    # This mainly affects Python 2.7.
    return ip_address


def normalize_ip_network(network):
    """
    Given a network in CIDR notation as a string, normalize it so that it can be
    used to compare networks as strings.
    """
    if network is None:
        return None
    if HAS_IPADDRESS:
        try:
            return ipaddress.ip_network(network).compressed
        except ValueError:
            # Fallback for invalid networks: simply return the input
            return network
    # If we don't have ipaddress, simply give up...
    # This mainly affects Python 2.7.
    return network
