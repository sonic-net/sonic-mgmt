# Copyright (c) 2022 Felix Fontein <felix@fontein.de>
# Copyright 2016 Red Hat | Ansible
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import abc
import os
import re
import shlex

from functools import partial

from ansible.module_utils.common.text.converters import to_native, to_text
from ansible.module_utils.common.text.formatters import human_to_bytes
from ansible_collections.community.docker.plugins.module_utils._six import string_types

from ansible_collections.community.docker.plugins.module_utils.util import (
    clean_dict_booleans_for_docker_api,
    compare_generic,
    normalize_healthcheck,
    omit_none_from_dict,
    sanitize_labels,
)

from ansible_collections.community.docker.plugins.module_utils._platform import (
    compare_platform_strings,
)

from ansible_collections.community.docker.plugins.module_utils._api.utils.utils import (
    parse_env_file,
)


_DEFAULT_IP_REPLACEMENT_STRING = '[[DEFAULT_IP:iewahhaeB4Sae6Aen8IeShairoh4zeph7xaekoh8Geingunaesaeweiy3ooleiwi]]'


_MOUNT_OPTION_TYPES = dict(
    create_mountpoint=('bind',),
    labels=('volume',),
    no_copy=('volume',),
    non_recursive=('bind',),
    propagation=('bind',),
    read_only_force_recursive=('bind',),
    read_only_non_recursive=('bind',),
    subpath=('volume', 'image'),
    tmpfs_size=('tmpfs',),
    tmpfs_mode=('tmpfs',),
    tmpfs_options=('tmpfs',),
    volume_driver=('volume',),
    volume_options=('volume',),
)


def _get_ansible_type(type):
    if type == 'set':
        return 'list'
    if type not in ('list', 'dict', 'bool', 'int', 'float', 'str'):
        raise Exception('Invalid type "%s"' % (type, ))
    return type


class Option(object):
    def __init__(
        self,
        name,
        type,
        owner,
        ansible_type=None,
        elements=None,
        ansible_elements=None,
        ansible_suboptions=None,
        ansible_aliases=None,
        ansible_choices=None,
        needs_no_suboptions=False,
        default_comparison=None,
        not_a_container_option=False,
        not_an_ansible_option=False,
        copy_comparison_from=None,
        compare=None,
    ):
        self.name = name
        self.type = type
        self.ansible_type = ansible_type or _get_ansible_type(type)
        needs_elements = self.type in ('list', 'set')
        needs_ansible_elements = self.ansible_type in ('list', )
        if elements is not None and not needs_elements:
            raise Exception('elements only allowed for lists/sets')
        if elements is None and needs_elements:
            raise Exception('elements required for lists/sets')
        if ansible_elements is not None and not needs_ansible_elements:
            raise Exception('Ansible elements only allowed for Ansible lists')
        if (elements is None and ansible_elements is None) and needs_ansible_elements:
            raise Exception('Ansible elements required for Ansible lists')
        self.elements = elements if needs_elements else None
        self.ansible_elements = (ansible_elements or _get_ansible_type(elements)) if needs_ansible_elements else None
        needs_suboptions = (self.ansible_type == 'list' and self.ansible_elements == 'dict') or (self.ansible_type == 'dict')
        if ansible_suboptions is not None and not needs_suboptions:
            raise Exception('suboptions only allowed for Ansible lists with dicts, or Ansible dicts')
        if ansible_suboptions is None and needs_suboptions and not needs_no_suboptions and not not_an_ansible_option:
            raise Exception('suboptions required for Ansible lists with dicts, or Ansible dicts')
        self.ansible_suboptions = ansible_suboptions if needs_suboptions else None
        self.ansible_aliases = ansible_aliases or []
        self.ansible_choices = ansible_choices
        comparison_type = self.type
        if comparison_type == 'set' and self.elements == 'dict':
            comparison_type = 'set(dict)'
        elif comparison_type not in ('set', 'list', 'dict'):
            comparison_type = 'value'
        self.comparison_type = comparison_type
        if default_comparison is not None:
            self.comparison = default_comparison
        elif comparison_type in ('list', 'value'):
            self.comparison = 'strict'
        else:
            self.comparison = 'allow_more_present'
        self.not_a_container_option = not_a_container_option
        self.not_an_ansible_option = not_an_ansible_option
        self.copy_comparison_from = copy_comparison_from
        self.compare = (
            lambda param_value, container_value: compare(self, param_value, container_value)
        ) if compare else (
            lambda param_value, container_value: compare_generic(param_value, container_value, self.comparison, self.comparison_type)
        )


class OptionGroup(object):
    def __init__(
        self,
        preprocess=None,
        ansible_mutually_exclusive=None,
        ansible_required_together=None,
        ansible_required_one_of=None,
        ansible_required_if=None,
        ansible_required_by=None,
    ):
        if preprocess is None:
            def preprocess(module, values):
                return values
        self.preprocess = preprocess
        self.options = []
        self.all_options = []
        self.engines = {}
        self.ansible_mutually_exclusive = ansible_mutually_exclusive or []
        self.ansible_required_together = ansible_required_together or []
        self.ansible_required_one_of = ansible_required_one_of or []
        self.ansible_required_if = ansible_required_if or []
        self.ansible_required_by = ansible_required_by or {}
        self.argument_spec = {}

    def add_option(self, *args, **kwargs):
        option = Option(*args, owner=self, **kwargs)
        if not option.not_a_container_option:
            self.options.append(option)
        self.all_options.append(option)
        if not option.not_an_ansible_option:
            ansible_option = {
                'type': option.ansible_type,
            }
            if option.ansible_elements is not None:
                ansible_option['elements'] = option.ansible_elements
            if option.ansible_suboptions is not None:
                ansible_option['options'] = option.ansible_suboptions
            if option.ansible_aliases:
                ansible_option['aliases'] = option.ansible_aliases
            if option.ansible_choices is not None:
                ansible_option['choices'] = option.ansible_choices
            self.argument_spec[option.name] = ansible_option
        return self

    def supports_engine(self, engine_name):
        return engine_name in self.engines

    def get_engine(self, engine_name):
        return self.engines[engine_name]

    def add_engine(self, engine_name, engine):
        self.engines[engine_name] = engine
        return self


class Engine(object):
    min_api_version = None  # string or None
    min_api_version_obj = None  # LooseVersion object or None
    extra_option_minimal_versions = None  # dict[str, dict[str, Any]] or None

    @abc.abstractmethod
    def get_value(self, module, container, api_version, options, image, host_info):
        pass

    def compare_value(self, option, param_value, container_value):
        return option.compare(param_value, container_value)

    @abc.abstractmethod
    def set_value(self, module, data, api_version, options, values):
        pass

    @abc.abstractmethod
    def get_expected_values(self, module, client, api_version, options, image, values, host_info):
        pass

    @abc.abstractmethod
    def ignore_mismatching_result(self, module, client, api_version, option, image, container_value, expected_value, host_info):
        pass

    @abc.abstractmethod
    def preprocess_value(self, module, client, api_version, options, values):
        pass

    @abc.abstractmethod
    def update_value(self, module, data, api_version, options, values):
        pass

    @abc.abstractmethod
    def can_set_value(self, api_version):
        pass

    @abc.abstractmethod
    def can_update_value(self, api_version):
        pass

    @abc.abstractmethod
    def needs_container_image(self, values):
        pass

    @abc.abstractmethod
    def needs_host_info(self, values):
        pass


class EngineDriver(object):
    name = None  # string

    @abc.abstractmethod
    def setup(self, argument_spec, mutually_exclusive=None, required_together=None, required_one_of=None, required_if=None, required_by=None):
        # Return (module, active_options, client)
        pass

    @abc.abstractmethod
    def get_host_info(self, client):
        pass

    @abc.abstractmethod
    def get_api_version(self, client):
        pass

    @abc.abstractmethod
    def get_container_id(self, container):
        pass

    @abc.abstractmethod
    def get_image_from_container(self, container):
        pass

    @abc.abstractmethod
    def get_image_name_from_container(self, container):
        pass

    @abc.abstractmethod
    def is_container_removing(self, container):
        pass

    @abc.abstractmethod
    def is_container_running(self, container):
        pass

    @abc.abstractmethod
    def is_container_paused(self, container):
        pass

    @abc.abstractmethod
    def inspect_container_by_name(self, client, container_name):
        pass

    @abc.abstractmethod
    def inspect_container_by_id(self, client, container_id):
        pass

    @abc.abstractmethod
    def inspect_image_by_id(self, client, image_id):
        pass

    @abc.abstractmethod
    def inspect_image_by_name(self, client, repository, tag):
        pass

    @abc.abstractmethod
    def pull_image(self, client, repository, tag, platform=None):
        pass

    @abc.abstractmethod
    def pause_container(self, client, container_id):
        pass

    @abc.abstractmethod
    def unpause_container(self, client, container_id):
        pass

    @abc.abstractmethod
    def disconnect_container_from_network(self, client, container_id, network_id):
        pass

    @abc.abstractmethod
    def connect_container_to_network(self, client, container_id, network_id, parameters=None):
        pass

    def create_container_supports_more_than_one_network(self, client):
        return False

    @abc.abstractmethod
    def create_container(self, client, container_name, create_parameters, networks=None):
        pass

    @abc.abstractmethod
    def start_container(self, client, container_id):
        pass

    @abc.abstractmethod
    def wait_for_container(self, client, container_id, timeout=None):
        pass

    @abc.abstractmethod
    def get_container_output(self, client, container_id):
        pass

    @abc.abstractmethod
    def update_container(self, client, container_id, update_parameters):
        pass

    @abc.abstractmethod
    def restart_container(self, client, container_id, timeout=None):
        pass

    @abc.abstractmethod
    def kill_container(self, client, container_id, kill_signal=None):
        pass

    @abc.abstractmethod
    def stop_container(self, client, container_id, timeout=None):
        pass

    @abc.abstractmethod
    def remove_container(self, client, container_id, remove_volumes=False, link=False, force=False):
        pass

    @abc.abstractmethod
    def run(self, runner, client):
        pass


def _is_volume_permissions(mode):
    for part in mode.split(','):
        if part not in ('rw', 'ro', 'z', 'Z', 'consistent', 'delegated', 'cached', 'rprivate', 'private', 'rshared', 'shared', 'rslave', 'slave', 'nocopy'):
            return False
    return True


def _parse_port_range(range_or_port, module):
    '''
    Parses a string containing either a single port or a range of ports.

    Returns a list of integers for each port in the list.
    '''
    if '-' in range_or_port:
        try:
            start, end = [int(port) for port in range_or_port.split('-')]
        except Exception:
            module.fail_json(msg='Invalid port range: "{0}"'.format(range_or_port))
        if end < start:
            module.fail_json(msg='Invalid port range: "{0}"'.format(range_or_port))
        return list(range(start, end + 1))
    else:
        try:
            return [int(range_or_port)]
        except Exception:
            module.fail_json(msg='Invalid port: "{0}"'.format(range_or_port))


def _split_colon_ipv6(text, module):
    '''
    Split string by ':', while keeping IPv6 addresses in square brackets in one component.
    '''
    if '[' not in text:
        return text.split(':')
    start = 0
    result = []
    while start < len(text):
        i = text.find('[', start)
        if i < 0:
            result.extend(text[start:].split(':'))
            break
        j = text.find(']', i)
        if j < 0:
            module.fail_json(msg='Cannot find closing "]" in input "{0}" for opening "[" at index {1}!'.format(text, i + 1))
        result.extend(text[start:i].split(':'))
        k = text.find(':', j)
        if k < 0:
            result[-1] += text[i:]
            start = len(text)
        else:
            result[-1] += text[i:k]
            if k == len(text):
                result.append('')
                break
            start = k + 1
    return result


def _preprocess_command(module, values):
    if 'command' not in values:
        return values
    value = values['command']
    if module.params['command_handling'] == 'correct':
        if value is not None:
            if not isinstance(value, list):
                # convert from str to list
                value = shlex.split(to_text(value, errors='surrogate_or_strict'))
            value = [to_text(x, errors='surrogate_or_strict') for x in value]
    elif value:
        # convert from list to str
        if isinstance(value, list):
            value = shlex.split(' '.join([to_text(x, errors='surrogate_or_strict') for x in value]))
            value = [to_text(x, errors='surrogate_or_strict') for x in value]
        else:
            value = shlex.split(to_text(value, errors='surrogate_or_strict'))
            value = [to_text(x, errors='surrogate_or_strict') for x in value]
    else:
        return {}
    return {
        'command': value,
    }


def _preprocess_entrypoint(module, values):
    if 'entrypoint' not in values:
        return values
    value = values['entrypoint']
    if module.params['command_handling'] == 'correct':
        if value is not None:
            value = [to_text(x, errors='surrogate_or_strict') for x in value]
    elif value:
        # convert from list to str.
        value = shlex.split(' '.join([to_text(x, errors='surrogate_or_strict') for x in value]))
        value = [to_text(x, errors='surrogate_or_strict') for x in value]
    else:
        return {}
    return {
        'entrypoint': value,
    }


def _preprocess_env(module, values):
    if not values:
        return {}
    final_env = {}
    if 'env_file' in values:
        parsed_env_file = parse_env_file(values['env_file'])
        for name, value in parsed_env_file.items():
            final_env[name] = to_text(value, errors='surrogate_or_strict')
    if 'env' in values:
        for name, value in values['env'].items():
            if not isinstance(value, string_types):
                module.fail_json(msg='Non-string value found for env option. Ambiguous env options must be '
                                     'wrapped in quotes to avoid them being interpreted. Key: %s' % (name, ))
            final_env[name] = to_text(value, errors='surrogate_or_strict')
    formatted_env = []
    for key, value in final_env.items():
        formatted_env.append('%s=%s' % (key, value))
    return {
        'env': formatted_env,
    }


def _preprocess_healthcheck(module, values):
    if not values:
        return {}
    return {
        'healthcheck': normalize_healthcheck(values['healthcheck'], normalize_test=False),
    }


def _preprocess_convert_to_bytes(module, values, name, unlimited_value=None):
    if name not in values:
        return values
    try:
        value = values[name]
        if unlimited_value is not None and value in ('unlimited', str(unlimited_value)):
            value = unlimited_value
        else:
            value = human_to_bytes(value)
        values[name] = value
        return values
    except ValueError as exc:
        module.fail_json(msg='Failed to convert %s to bytes: %s' % (name, to_native(exc)))


def _preprocess_mac_address(module, values):
    if 'mac_address' not in values:
        return values
    return {
        'mac_address': values['mac_address'].replace('-', ':'),
    }


def _preprocess_networks(module, values):
    if module.params['networks_cli_compatible'] is True and values.get('networks') and 'network_mode' not in values:
        # Same behavior as Docker CLI: if networks are specified, use the name of the first network as the value for network_mode
        # (assuming no explicit value is specified for network_mode)
        values['network_mode'] = values['networks'][0]['name']

    if 'networks' in values:
        for network in values['networks']:
            if network['links']:
                parsed_links = []
                for link in network['links']:
                    parsed_link = link.split(':', 1)
                    if len(parsed_link) == 1:
                        parsed_link = (link, link)
                    parsed_links.append(tuple(parsed_link))
                network['links'] = parsed_links
            if network['mac_address']:
                network['mac_address'] = network['mac_address'].replace('-', ':')

    return values


def _preprocess_sysctls(module, values):
    if 'sysctls' in values:
        for key, value in values['sysctls'].items():
            values['sysctls'][key] = to_text(value, errors='surrogate_or_strict')
    return values


def _preprocess_tmpfs(module, values):
    if 'tmpfs' not in values:
        return values
    result = {}
    for tmpfs_spec in values['tmpfs']:
        split_spec = tmpfs_spec.split(":", 1)
        if len(split_spec) > 1:
            result[split_spec[0]] = split_spec[1]
        else:
            result[split_spec[0]] = ""
    return {
        'tmpfs': result
    }


def _preprocess_ulimits(module, values):
    if 'ulimits' not in values:
        return values
    result = []
    for limit in values['ulimits']:
        limits = dict()
        pieces = limit.split(':')
        if len(pieces) >= 2:
            limits['Name'] = pieces[0]
            limits['Soft'] = int(pieces[1])
            limits['Hard'] = int(pieces[1])
        if len(pieces) == 3:
            limits['Hard'] = int(pieces[2])
        result.append(limits)
    return {
        'ulimits': result,
    }


def _preprocess_mounts(module, values):
    last = dict()

    def check_collision(t, name):
        if t in last:
            if name == last[t]:
                module.fail_json(msg='The mount point "{0}" appears twice in the {1} option'.format(t, name))
            else:
                module.fail_json(msg='The mount point "{0}" appears both in the {1} and {2} option'.format(t, name, last[t]))
        last[t] = name

    if 'mounts' in values:
        mounts = []
        for mount in values['mounts']:
            target = mount['target']
            mount_type = mount['type']

            check_collision(target, 'mounts')

            mount_dict = dict(mount)

            # Sanity checks
            if mount['source'] is None and mount_type not in ('tmpfs', 'volume', 'image', 'cluster'):
                module.fail_json(msg='source must be specified for mount "{0}" of type "{1}"'.format(target, mount_type))
            for option, req_mount_types in _MOUNT_OPTION_TYPES.items():
                if mount[option] is not None and mount_type not in req_mount_types:
                    module.fail_json(
                        msg='{0} cannot be specified for mount "{1}" of type "{2}" (needs type{3} "{4}")'.format(
                            option,
                            target,
                            mount_type,
                            "" if len(req_mount_types) == 1 else "s",
                            '", "'.join(req_mount_types),
                        )
                    )

            # Streamline options
            volume_options = mount_dict.pop('volume_options')
            if mount_dict['volume_driver'] and volume_options:
                mount_dict['volume_options'] = clean_dict_booleans_for_docker_api(volume_options)
            if mount_dict['labels']:
                mount_dict['labels'] = clean_dict_booleans_for_docker_api(mount_dict['labels'])
            if mount_dict['tmpfs_size'] is not None:
                try:
                    mount_dict['tmpfs_size'] = human_to_bytes(mount_dict['tmpfs_size'])
                except ValueError as exc:
                    module.fail_json(msg='Failed to convert tmpfs_size of mount "{0}" to bytes: {1}'.format(target, to_native(exc)))
            if mount_dict['tmpfs_mode'] is not None:
                try:
                    mount_dict['tmpfs_mode'] = int(mount_dict['tmpfs_mode'], 8)
                except Exception as dummy:
                    module.fail_json(msg='tmp_fs mode of mount "{0}" is not an octal string!'.format(target))
            if mount_dict['tmpfs_options']:
                opts = []
                for idx, opt in enumerate(mount_dict['tmpfs_options']):
                    if len(opt) != 1:
                        module.fail_json(msg='tmpfs_options[{1}] of mount "{0}" must be a one-element dictionary!'.format(target, idx + 1))
                    k, v = list(opt.items())[0]
                    if not isinstance(k, str):
                        module.fail_json(msg='key {2!r} in tmpfs_options[{1}] of mount "{0}" must be a string!'.format(target, idx + 1, k))
                    if v is not None and not isinstance(v, str):
                        module.fail_json(msg='value {2!r} in tmpfs_options[{1}] of mount "{0}" must be a string or null/none!'.format(target, idx + 1, v))
                    opts.append([k, v] if v is not None else [k])
                mount_dict['tmpfs_options'] = opts

            # Add result to list
            mounts.append(omit_none_from_dict(mount_dict))
        values['mounts'] = mounts
    if 'volumes' in values:
        new_vols = []
        for vol in values['volumes']:
            parts = vol.split(':')
            if ':' in vol:
                if len(parts) == 3:
                    host, container, mode = parts
                    if not _is_volume_permissions(mode):
                        module.fail_json(msg='Found invalid volumes mode: {0}'.format(mode))
                    if re.match(r'[.~]', host):
                        host = os.path.abspath(os.path.expanduser(host))
                    check_collision(container, 'volumes')
                    new_vols.append("%s:%s:%s" % (host, container, mode))
                    continue
                elif len(parts) == 2:
                    if not _is_volume_permissions(parts[1]) and re.match(r'[.~]', parts[0]):
                        host = os.path.abspath(os.path.expanduser(parts[0]))
                        check_collision(parts[1], 'volumes')
                        new_vols.append("%s:%s:rw" % (host, parts[1]))
                        continue
            check_collision(parts[min(1, len(parts) - 1)], 'volumes')
            new_vols.append(vol)
        values['volumes'] = new_vols
        new_binds = []
        for vol in new_vols:
            host = None
            if ':' in vol:
                parts = vol.split(':')
                if len(parts) == 3:
                    host, container, mode = parts
                    if not _is_volume_permissions(mode):
                        module.fail_json(msg='Found invalid volumes mode: {0}'.format(mode))
                elif len(parts) == 2:
                    if not _is_volume_permissions(parts[1]):
                        host, container, mode = (parts + ['rw'])
            if host is not None:
                new_binds.append('%s:%s:%s' % (host, container, mode))
        values['volume_binds'] = new_binds
    return values


def _preprocess_labels(module, values):
    result = {}
    if 'labels' in values:
        labels = values['labels']
        if labels is not None:
            labels = dict(labels)
            sanitize_labels(labels, 'labels', module=module)
        result['labels'] = labels
    return result


def _preprocess_log(module, values):
    result = {}
    if 'log_driver' not in values:
        return result
    result['log_driver'] = values['log_driver']
    if 'log_options' in values:
        options = {}
        for k, v in values['log_options'].items():
            if not isinstance(v, string_types):
                module.warn(
                    "Non-string value found for log_options option '%s'. The value is automatically converted to '%s'. "
                    "If this is not correct, or you want to avoid such warnings, please quote the value." % (
                        k, to_text(v, errors='surrogate_or_strict'))
                )
            v = to_text(v, errors='surrogate_or_strict')
            options[k] = v
        result['log_options'] = options
    return result


def _preprocess_ports(module, values):
    if 'published_ports' in values:
        if 'all' in values['published_ports']:
            module.fail_json(
                msg='Specifying "all" in published_ports is no longer allowed. Set publish_all_ports to "true" instead '
                    'to randomly assign port mappings for those not specified by published_ports.')

        binds = {}
        for port in values['published_ports']:
            parts = _split_colon_ipv6(to_text(port, errors='surrogate_or_strict'), module)
            container_port = parts[-1]
            protocol = ''
            if '/' in container_port:
                container_port, protocol = parts[-1].split('/')
            container_ports = _parse_port_range(container_port, module)

            p_len = len(parts)
            if p_len == 1:
                port_binds = len(container_ports) * [(_DEFAULT_IP_REPLACEMENT_STRING, )]
            elif p_len == 2:
                if len(container_ports) == 1:
                    port_binds = [(_DEFAULT_IP_REPLACEMENT_STRING, parts[0])]
                else:
                    port_binds = [(_DEFAULT_IP_REPLACEMENT_STRING, port) for port in _parse_port_range(parts[0], module)]
            elif p_len == 3:
                # We only allow IPv4 and IPv6 addresses for the bind address
                ipaddr = parts[0]
                if not re.match(r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$', parts[0]) and not re.match(r'^\[[0-9a-fA-F:]+(?:|%[^\]/]+)\]$', ipaddr):
                    module.fail_json(
                        msg='Bind addresses for published ports must be IPv4 or IPv6 addresses, not hostnames. '
                            'Use the dig lookup to resolve hostnames. (Found hostname: {0})'.format(ipaddr)
                    )
                if re.match(r'^\[[0-9a-fA-F:]+\]$', ipaddr):
                    ipaddr = ipaddr[1:-1]
                if parts[1]:
                    if len(container_ports) == 1:
                        port_binds = [(ipaddr, parts[1])]
                    else:
                        port_binds = [(ipaddr, port) for port in _parse_port_range(parts[1], module)]
                else:
                    port_binds = len(container_ports) * [(ipaddr,)]
            else:
                module.fail_json(
                    msg='Invalid port description "%s" - expected 1 to 3 colon-separated parts, but got %d. '
                        'Maybe you forgot to use square brackets ([...]) around an IPv6 address?' % (port, p_len)
                )

            for bind, container_port in zip(port_binds, container_ports):
                idx = '{0}/{1}'.format(container_port, protocol) if protocol else container_port
                if idx in binds:
                    old_bind = binds[idx]
                    if isinstance(old_bind, list):
                        old_bind.append(bind)
                    else:
                        binds[idx] = [old_bind, bind]
                else:
                    binds[idx] = bind
        values['published_ports'] = binds

    exposed = set()
    if 'exposed_ports' in values:
        for port in values['exposed_ports']:
            port = to_text(port, errors='surrogate_or_strict').strip()
            protocol = 'tcp'
            parts = port.split("/", maxsplit=1)
            if len(parts) == 2:
                port, protocol = parts
            parts = port.split("-", maxsplit=1)
            if len(parts) < 2:
                try:
                    exposed.add((int(port), protocol))
                except ValueError as e:
                    module.fail_json(msg="Cannot parse port {port!r}: {e}".format(port=port, e=e))
            else:
                try:
                    start_port = int(parts[0])
                    end_port = int(parts[1])
                    if start_port > end_port:
                        raise ValueError(
                            "start port must be smaller or equal to end port."
                        )
                except ValueError as e:
                    module.fail_json(msg="Cannot parse port range {port!r}: {e}".format(port=port, e=e))
                for port in range(start_port, end_port + 1):
                    exposed.add((port, protocol))
    if 'published_ports' in values:
        # Any published port should also be exposed
        for publish_port in values['published_ports']:
            if isinstance(publish_port, string_types) and '/' in publish_port:
                port, protocol = publish_port.split('/')
                port = int(port)
            else:
                protocol = 'tcp'
                port = int(publish_port)
            exposed.add((port, protocol))
    values['ports'] = sorted(exposed)
    return values


def _compare_platform(option, param_value, container_value):
    if option.comparison == 'ignore':
        return True
    try:
        return compare_platform_strings(param_value, container_value)
    except ValueError:
        return param_value == container_value


OPTION_AUTO_REMOVE = (
    OptionGroup()
    .add_option('auto_remove', type='bool')
)

OPTION_BLKIO_WEIGHT = (
    OptionGroup()
    .add_option('blkio_weight', type='int')
)

OPTION_CAPABILITIES = (
    OptionGroup()
    .add_option('capabilities', type='set', elements='str')
)

OPTION_CAP_DROP = (
    OptionGroup()
    .add_option('cap_drop', type='set', elements='str')
)

OPTION_CGROUP_NS_MODE = (
    OptionGroup()
    .add_option('cgroupns_mode', type='str', ansible_choices=['private', 'host'])
)

OPTION_CGROUP_PARENT = (
    OptionGroup()
    .add_option('cgroup_parent', type='str')
)

OPTION_COMMAND = (
    OptionGroup(preprocess=_preprocess_command)
    .add_option('command', type='list', elements='str', ansible_type='raw')
)

OPTION_CPU_PERIOD = (
    OptionGroup()
    .add_option('cpu_period', type='int')
)

OPTION_CPU_QUOTA = (
    OptionGroup()
    .add_option('cpu_quota', type='int')
)

OPTION_CPUSET_CPUS = (
    OptionGroup()
    .add_option('cpuset_cpus', type='str')
)

OPTION_CPUSET_MEMS = (
    OptionGroup()
    .add_option('cpuset_mems', type='str')
)

OPTION_CPU_SHARES = (
    OptionGroup()
    .add_option('cpu_shares', type='int')
)

OPTION_ENTRYPOINT = (
    OptionGroup(preprocess=_preprocess_entrypoint)
    .add_option('entrypoint', type='list', elements='str')
)

OPTION_CPUS = (
    OptionGroup()
    .add_option('cpus', type='int', ansible_type='float')
)

OPTION_DETACH_INTERACTIVE = (
    OptionGroup()
    .add_option('detach', type='bool')
    .add_option('interactive', type='bool')
)

OPTION_DEVICES = (
    OptionGroup()
    .add_option('devices', type='set', elements='dict', ansible_elements='str')
)

OPTION_DEVICE_READ_BPS = (
    OptionGroup()
    .add_option('device_read_bps', type='set', elements='dict', ansible_suboptions=dict(
        path=dict(required=True, type='str'),
        rate=dict(required=True, type='str'),
    ))
)

OPTION_DEVICE_WRITE_BPS = (
    OptionGroup()
    .add_option('device_write_bps', type='set', elements='dict', ansible_suboptions=dict(
        path=dict(required=True, type='str'),
        rate=dict(required=True, type='str'),
    ))
)

OPTION_DEVICE_READ_IOPS = (
    OptionGroup()
    .add_option('device_read_iops', type='set', elements='dict', ansible_suboptions=dict(
        path=dict(required=True, type='str'),
        rate=dict(required=True, type='int'),
    ))
)

OPTION_DEVICE_WRITE_IOPS = (
    OptionGroup()
    .add_option('device_write_iops', type='set', elements='dict', ansible_suboptions=dict(
        path=dict(required=True, type='str'),
        rate=dict(required=True, type='int'),
    ))
)

OPTION_DEVICE_REQUESTS = (
    OptionGroup()
    .add_option('device_requests', type='set', elements='dict', ansible_suboptions=dict(
        capabilities=dict(type='list', elements='list'),
        count=dict(type='int'),
        device_ids=dict(type='list', elements='str'),
        driver=dict(type='str'),
        options=dict(type='dict'),
    ))
)

OPTION_DEVICE_CGROUP_RULES = (
    OptionGroup()
    .add_option('device_cgroup_rules', type='list', elements='str')
)

OPTION_DNS_SERVERS = (
    OptionGroup()
    .add_option('dns_servers', type='list', elements='str')
)

OPTION_DNS_OPTS = (
    OptionGroup()
    .add_option('dns_opts', type='set', elements='str')
)

OPTION_DNS_SEARCH_DOMAINS = (
    OptionGroup()
    .add_option('dns_search_domains', type='list', elements='str')
)

OPTION_DOMAINNAME = (
    OptionGroup()
    .add_option('domainname', type='str')
)

OPTION_ENVIRONMENT = (
    OptionGroup(preprocess=_preprocess_env)
    .add_option('env', type='set', ansible_type='dict', elements='str', needs_no_suboptions=True)
    .add_option('env_file', type='set', ansible_type='path', elements='str', not_a_container_option=True)
)

OPTION_ETC_HOSTS = (
    OptionGroup()
    .add_option('etc_hosts', type='set', ansible_type='dict', elements='str', needs_no_suboptions=True)
)

OPTION_GROUPS = (
    OptionGroup()
    .add_option('groups', type='set', elements='str')
)

OPTION_HEALTHCHECK = (
    OptionGroup(preprocess=_preprocess_healthcheck)
    .add_option('healthcheck', type='dict', ansible_suboptions=dict(
        test=dict(type='raw'),
        test_cli_compatible=dict(type='bool', default=False),
        interval=dict(type='str'),
        timeout=dict(type='str'),
        start_period=dict(type='str'),
        start_interval=dict(type='str'),
        retries=dict(type='int'),
    ))
)

OPTION_HOSTNAME = (
    OptionGroup()
    .add_option('hostname', type='str')
)

OPTION_IMAGE = (
    OptionGroup()
    .add_option('image', type='str')
)

OPTION_INIT = (
    OptionGroup()
    .add_option('init', type='bool')
)

OPTION_IPC_MODE = (
    OptionGroup()
    .add_option('ipc_mode', type='str')
)

OPTION_KERNEL_MEMORY = (
    OptionGroup(preprocess=partial(_preprocess_convert_to_bytes, name='kernel_memory'))
    .add_option('kernel_memory', type='int', ansible_type='str')
)

OPTION_LABELS = (
    OptionGroup(preprocess=_preprocess_labels)
    .add_option('labels', type='dict', needs_no_suboptions=True)
)

OPTION_LINKS = (
    OptionGroup()
    .add_option('links', type='set', elements='list', ansible_elements='str')
)

OPTION_LOG_DRIVER_OPTIONS = (
    OptionGroup(preprocess=_preprocess_log, ansible_required_by={'log_options': ['log_driver']})
    .add_option('log_driver', type='str')
    .add_option('log_options', type='dict', ansible_aliases=['log_opt'], needs_no_suboptions=True)
)

OPTION_MAC_ADDRESS = (
    OptionGroup(preprocess=_preprocess_mac_address)
    .add_option('mac_address', type='str')
)

OPTION_MEMORY = (
    OptionGroup(preprocess=partial(_preprocess_convert_to_bytes, name='memory'))
    .add_option('memory', type='int', ansible_type='str')
)

OPTION_MEMORY_RESERVATION = (
    OptionGroup(preprocess=partial(_preprocess_convert_to_bytes, name='memory_reservation'))
    .add_option('memory_reservation', type='int', ansible_type='str')
)

OPTION_MEMORY_SWAP = (
    OptionGroup(preprocess=partial(_preprocess_convert_to_bytes, name='memory_swap', unlimited_value=-1))
    .add_option('memory_swap', type='int', ansible_type='str')
)

OPTION_MEMORY_SWAPPINESS = (
    OptionGroup()
    .add_option('memory_swappiness', type='int')
)

OPTION_STOP_TIMEOUT = (
    OptionGroup()
    .add_option('stop_timeout', type='int', default_comparison='ignore')
)

OPTION_NETWORK = (
    OptionGroup(preprocess=_preprocess_networks)
    .add_option('network_mode', type='str')
    .add_option('networks', type='set', elements='dict', ansible_suboptions=dict(
        name=dict(type='str', required=True),
        ipv4_address=dict(type='str'),
        ipv6_address=dict(type='str'),
        aliases=dict(type='list', elements='str'),
        links=dict(type='list', elements='str'),
        mac_address=dict(type='str'),
    ))
)

OPTION_OOM_KILLER = (
    OptionGroup()
    .add_option('oom_killer', type='bool')
)

OPTION_OOM_SCORE_ADJ = (
    OptionGroup()
    .add_option('oom_score_adj', type='int')
)

OPTION_PID_MODE = (
    OptionGroup()
    .add_option('pid_mode', type='str')
)

OPTION_PIDS_LIMIT = (
    OptionGroup()
    .add_option('pids_limit', type='int')
)

OPTION_PLATFORM = (
    OptionGroup()
    .add_option('platform', type='str', compare=_compare_platform)
)

OPTION_PRIVILEGED = (
    OptionGroup()
    .add_option('privileged', type='bool')
)

OPTION_READ_ONLY = (
    OptionGroup()
    .add_option('read_only', type='bool')
)

OPTION_RESTART_POLICY = (
    OptionGroup(ansible_required_by={'restart_retries': ['restart_policy']})
    .add_option('restart_policy', type='str', ansible_choices=['no', 'on-failure', 'always', 'unless-stopped'])
    .add_option('restart_retries', type='int')
)

OPTION_RUNTIME = (
    OptionGroup()
    .add_option('runtime', type='str')
)

OPTION_SECURITY_OPTS = (
    OptionGroup()
    .add_option('security_opts', type='set', elements='str')
)

OPTION_SHM_SIZE = (
    OptionGroup(preprocess=partial(_preprocess_convert_to_bytes, name='shm_size'))
    .add_option('shm_size', type='int', ansible_type='str')
)

OPTION_STOP_SIGNAL = (
    OptionGroup()
    .add_option('stop_signal', type='str')
)

OPTION_STORAGE_OPTS = (
    OptionGroup()
    .add_option('storage_opts', type='dict', needs_no_suboptions=True)
)

OPTION_SYSCTLS = (
    OptionGroup(preprocess=_preprocess_sysctls)
    .add_option('sysctls', type='dict', needs_no_suboptions=True)
)

OPTION_TMPFS = (
    OptionGroup(preprocess=_preprocess_tmpfs)
    .add_option('tmpfs', type='dict', ansible_type='list', ansible_elements='str')
)

OPTION_TTY = (
    OptionGroup()
    .add_option('tty', type='bool')
)

OPTION_ULIMITS = (
    OptionGroup(preprocess=_preprocess_ulimits)
    .add_option('ulimits', type='set', elements='dict', ansible_elements='str')
)

OPTION_USER = (
    OptionGroup()
    .add_option('user', type='str')
)

OPTION_USERNS_MODE = (
    OptionGroup()
    .add_option('userns_mode', type='str')
)

OPTION_UTS = (
    OptionGroup()
    .add_option('uts', type='str')
)

OPTION_VOLUME_DRIVER = (
    OptionGroup()
    .add_option('volume_driver', type='str')
)

OPTION_VOLUMES_FROM = (
    OptionGroup()
    .add_option('volumes_from', type='set', elements='str')
)

OPTION_WORKING_DIR = (
    OptionGroup()
    .add_option('working_dir', type='str')
)

OPTION_MOUNTS_VOLUMES = (
    OptionGroup(preprocess=_preprocess_mounts)
    .add_option('mounts', type='set', elements='dict', ansible_suboptions=dict(
        target=dict(type='str', required=True),
        source=dict(type='str'),
        type=dict(type='str', choices=['bind', 'volume', 'tmpfs', 'npipe', 'cluster', 'image'], default='volume'),
        read_only=dict(type='bool'),
        consistency=dict(type='str', choices=['default', 'consistent', 'cached', 'delegated']),
        propagation=dict(type='str', choices=['private', 'rprivate', 'shared', 'rshared', 'slave', 'rslave']),
        no_copy=dict(type='bool'),
        labels=dict(type='dict'),
        volume_driver=dict(type='str'),
        volume_options=dict(type='dict'),
        tmpfs_size=dict(type='str'),
        tmpfs_mode=dict(type='str'),
        non_recursive=dict(type='bool'),
        create_mountpoint=dict(type='bool'),
        read_only_non_recursive=dict(type='bool'),
        read_only_force_recursive=dict(type='bool'),
        subpath=dict(type='str'),
        tmpfs_options=dict(type='list', elements='dict'),
    ))
    .add_option('volumes', type='set', elements='str')
    .add_option('volume_binds', type='set', elements='str', not_an_ansible_option=True, copy_comparison_from='volumes')
)

OPTION_PORTS = (
    OptionGroup(preprocess=_preprocess_ports)
    .add_option('exposed_ports', type='set', elements='str', ansible_aliases=['exposed', 'expose'])
    .add_option('publish_all_ports', type='bool')
    .add_option('published_ports', type='dict', ansible_type='list', ansible_elements='str', ansible_aliases=['ports'])
    .add_option('ports', type='set', elements='str', not_an_ansible_option=True, default_comparison='ignore')
)

OPTIONS = [
    OPTION_AUTO_REMOVE,
    OPTION_BLKIO_WEIGHT,
    OPTION_CAPABILITIES,
    OPTION_CAP_DROP,
    OPTION_CGROUP_NS_MODE,
    OPTION_CGROUP_PARENT,
    OPTION_COMMAND,
    OPTION_CPU_PERIOD,
    OPTION_CPU_QUOTA,
    OPTION_CPUSET_CPUS,
    OPTION_CPUSET_MEMS,
    OPTION_CPU_SHARES,
    OPTION_ENTRYPOINT,
    OPTION_CPUS,
    OPTION_DETACH_INTERACTIVE,
    OPTION_DEVICES,
    OPTION_DEVICE_READ_BPS,
    OPTION_DEVICE_WRITE_BPS,
    OPTION_DEVICE_READ_IOPS,
    OPTION_DEVICE_WRITE_IOPS,
    OPTION_DEVICE_REQUESTS,
    OPTION_DEVICE_CGROUP_RULES,
    OPTION_DNS_SERVERS,
    OPTION_DNS_OPTS,
    OPTION_DNS_SEARCH_DOMAINS,
    OPTION_DOMAINNAME,
    OPTION_ENVIRONMENT,
    OPTION_ETC_HOSTS,
    OPTION_GROUPS,
    OPTION_HEALTHCHECK,
    OPTION_HOSTNAME,
    OPTION_IMAGE,
    OPTION_INIT,
    OPTION_IPC_MODE,
    OPTION_KERNEL_MEMORY,
    OPTION_LABELS,
    OPTION_LINKS,
    OPTION_LOG_DRIVER_OPTIONS,
    OPTION_MAC_ADDRESS,
    OPTION_MEMORY,
    OPTION_MEMORY_RESERVATION,
    OPTION_MEMORY_SWAP,
    OPTION_MEMORY_SWAPPINESS,
    OPTION_STOP_TIMEOUT,
    OPTION_NETWORK,
    OPTION_OOM_KILLER,
    OPTION_OOM_SCORE_ADJ,
    OPTION_PID_MODE,
    OPTION_PIDS_LIMIT,
    OPTION_PLATFORM,
    OPTION_PRIVILEGED,
    OPTION_READ_ONLY,
    OPTION_RESTART_POLICY,
    OPTION_RUNTIME,
    OPTION_SECURITY_OPTS,
    OPTION_SHM_SIZE,
    OPTION_STOP_SIGNAL,
    OPTION_STORAGE_OPTS,
    OPTION_SYSCTLS,
    OPTION_TMPFS,
    OPTION_TTY,
    OPTION_ULIMITS,
    OPTION_USER,
    OPTION_USERNS_MODE,
    OPTION_UTS,
    OPTION_VOLUME_DRIVER,
    OPTION_VOLUMES_FROM,
    OPTION_WORKING_DIR,
    OPTION_MOUNTS_VOLUMES,
    OPTION_PORTS,
]
