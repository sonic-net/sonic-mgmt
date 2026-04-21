# Copyright (c) 2022 Felix Fontein <felix@fontein.de>
# Copyright 2016 Red Hat | Ansible
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import re
from time import sleep

from ansible.module_utils.common.text.converters import to_native, to_text

from ansible_collections.community.docker.plugins.module_utils.util import (
    DifferenceTracker,
    DockerBaseClass,
    compare_generic,
    is_image_name_id,
    normalize_ip_address,
    sanitize_result,
)

from ansible_collections.community.docker.plugins.module_utils._api.utils.utils import parse_repository_tag


class Container(DockerBaseClass):
    def __init__(self, container, engine_driver):
        super(Container, self).__init__()
        self.raw = container
        self.id = None
        self.image = None
        self.image_name = None
        self.container = container
        self.engine_driver = engine_driver
        if container:
            self.id = engine_driver.get_container_id(container)
            self.image = engine_driver.get_image_from_container(container)
            self.image_name = engine_driver.get_image_name_from_container(container)
        self.log(self.container, pretty_print=True)

    @property
    def exists(self):
        return True if self.container else False

    @property
    def removing(self):
        return self.engine_driver.is_container_removing(self.container) if self.container else False

    @property
    def running(self):
        return self.engine_driver.is_container_running(self.container) if self.container else False

    @property
    def paused(self):
        return self.engine_driver.is_container_paused(self.container) if self.container else False


class ContainerManager(DockerBaseClass):
    def __init__(self, module, engine_driver, client, active_options):
        self.module = module
        self.engine_driver = engine_driver
        self.client = client
        self.options = active_options
        self.all_options = self._collect_all_options(active_options)
        self.check_mode = self.module.check_mode
        self.param_cleanup = self.module.params['cleanup']
        self.param_container_default_behavior = self.module.params['container_default_behavior']
        self.param_default_host_ip = self.module.params['default_host_ip']
        self.param_debug = self.module.params['debug']
        self.param_force_kill = self.module.params['force_kill']
        self.param_image = self.module.params['image']
        self.param_image_comparison = self.module.params['image_comparison']
        self.param_image_label_mismatch = self.module.params['image_label_mismatch']
        self.param_image_name_mismatch = self.module.params['image_name_mismatch']
        self.param_keep_volumes = self.module.params['keep_volumes']
        self.param_kill_signal = self.module.params['kill_signal']
        self.param_name = self.module.params['name']
        self.param_networks_cli_compatible = self.module.params['networks_cli_compatible']
        self.param_output_logs = self.module.params['output_logs']
        self.param_paused = self.module.params['paused']
        self.param_pull = self.module.params['pull']
        if self.param_pull is True:
            self.param_pull = 'always'
        if self.param_pull is False:
            self.param_pull = 'missing'
        self.param_pull_check_mode_behavior = self.module.params['pull_check_mode_behavior']
        self.param_recreate = self.module.params['recreate']
        self.param_removal_wait_timeout = self.module.params['removal_wait_timeout']
        self.param_healthy_wait_timeout = self.module.params['healthy_wait_timeout']
        if self.param_healthy_wait_timeout <= 0:
            self.param_healthy_wait_timeout = None
        self.param_restart = self.module.params['restart']
        self.param_state = self.module.params['state']
        self._parse_comparisons()
        self._update_params()
        self.results = {'changed': False, 'actions': []}
        self.diff = {}
        self.diff_tracker = DifferenceTracker()
        self.facts = {}
        if self.param_default_host_ip:
            valid_ip = False
            if re.match(r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$', self.param_default_host_ip):
                valid_ip = True
            if re.match(r'^\[[0-9a-fA-F:]+\]$', self.param_default_host_ip):
                valid_ip = True
            if re.match(r'^[0-9a-fA-F:]+$', self.param_default_host_ip):
                self.param_default_host_ip = '[{0}]'.format(self.param_default_host_ip)
                valid_ip = True
            if not valid_ip:
                self.fail('The value of default_host_ip must be an empty string, an IPv4 address, '
                          'or an IPv6 address. Got "{0}" instead.'.format(self.param_default_host_ip))

    def _collect_all_options(self, active_options):
        all_options = {}
        for options in active_options:
            for option in options.options:
                all_options[option.name] = option
        return all_options

    def _collect_all_module_params(self):
        all_module_options = set()
        for option, data in self.module.argument_spec.items():
            all_module_options.add(option)
            if 'aliases' in data:
                for alias in data['aliases']:
                    all_module_options.add(alias)
        return all_module_options

    def _parse_comparisons(self):
        # Keep track of all module params and all option aliases
        all_module_options = self._collect_all_module_params()
        comp_aliases = {}
        for option_name, option in self.all_options.items():
            if option.not_an_ansible_option:
                continue
            comp_aliases[option_name] = option_name
            for alias in option.ansible_aliases:
                comp_aliases[alias] = option_name
        # Process comparisons specified by user
        if self.module.params.get('comparisons'):
            # If '*' appears in comparisons, process it first
            if '*' in self.module.params['comparisons']:
                value = self.module.params['comparisons']['*']
                if value not in ('strict', 'ignore'):
                    self.fail("The wildcard can only be used with comparison modes 'strict' and 'ignore'!")
                for option in self.all_options.values():
                    if option.name == 'networks':
                        # `networks` is special: only update if
                        # some value is actually specified
                        if self.module.params['networks'] is None:
                            continue
                    option.comparison = value
            # Now process all other comparisons.
            comp_aliases_used = {}
            for key, value in self.module.params['comparisons'].items():
                if key == '*':
                    continue
                # Find main key
                key_main = comp_aliases.get(key)
                if key_main is None:
                    if key_main in all_module_options:
                        self.fail("The module option '%s' cannot be specified in the comparisons dict, "
                                  "since it does not correspond to container's state!" % key)
                    if key not in self.all_options or self.all_options[key].not_an_ansible_option:
                        self.fail("Unknown module option '%s' in comparisons dict!" % key)
                    key_main = key
                if key_main in comp_aliases_used:
                    self.fail("Both '%s' and '%s' (aliases of %s) are specified in comparisons dict!" % (key, comp_aliases_used[key_main], key_main))
                comp_aliases_used[key_main] = key
                # Check value and update accordingly
                if value in ('strict', 'ignore'):
                    self.all_options[key_main].comparison = value
                elif value == 'allow_more_present':
                    if self.all_options[key_main].comparison_type == 'value':
                        self.fail("Option '%s' is a value and not a set/list/dict, so its comparison cannot be %s" % (key, value))
                    self.all_options[key_main].comparison = value
                else:
                    self.fail("Unknown comparison mode '%s'!" % value)
        # Copy values
        for option in self.all_options.values():
            if option.copy_comparison_from is not None:
                option.comparison = self.all_options[option.copy_comparison_from].comparison

    def _update_params(self):
        if self.param_networks_cli_compatible is True and self.module.params['networks'] and self.module.params['network_mode'] is None:
            # Same behavior as Docker CLI: if networks are specified, use the name of the first network as the value for network_mode
            # (assuming no explicit value is specified for network_mode)
            self.module.params['network_mode'] = self.module.params['networks'][0]['name']
        if self.param_container_default_behavior == 'compatibility':
            old_default_values = dict(
                auto_remove=False,
                detach=True,
                init=False,
                interactive=False,
                memory='0',
                paused=False,
                privileged=False,
                read_only=False,
                tty=False,
            )
            for param, value in old_default_values.items():
                if self.module.params[param] is None:
                    self.module.params[param] = value

    def fail(self, *args, **kwargs):
        self.client.fail(*args, **kwargs)

    def run(self):
        if self.param_state in ('stopped', 'started', 'present', 'healthy'):
            self.present(self.param_state)
        elif self.param_state == 'absent':
            self.absent()

        if not self.check_mode and not self.param_debug:
            self.results.pop('actions')

        if self.module._diff or self.param_debug:
            self.diff['before'], self.diff['after'] = self.diff_tracker.get_before_after()
            self.results['diff'] = self.diff

        if self.facts:
            self.results['container'] = self.facts

    def wait_for_state(self, container_id, complete_states=None, wait_states=None, accept_removal=False, max_wait=None, health_state=False):
        delay = 1.0
        total_wait = 0
        while True:
            # Inspect container
            result = self.engine_driver.inspect_container_by_id(self.client, container_id)
            if result is None:
                if accept_removal:
                    return result
                msg = 'Encontered vanished container while waiting for container "{0}"'
                self.fail(msg.format(container_id))
            # Check container state
            state_info = result.get('State') or {}
            if health_state:
                state_info = state_info.get('Health') or {}
            state = state_info.get('Status')
            if complete_states is not None and state in complete_states:
                return result
            if wait_states is not None and state not in wait_states:
                msg = 'Encontered unexpected state "{1}" while waiting for container "{0}"'
                self.fail(msg.format(container_id, state), container=result)
            # Wait
            if max_wait is not None:
                if total_wait > max_wait or delay < 1E-4:
                    msg = 'Timeout of {1} seconds exceeded while waiting for container "{0}"'
                    self.fail(msg.format(container_id, max_wait), container=result)
                if total_wait + delay > max_wait:
                    delay = max_wait - total_wait
            sleep(delay)
            total_wait += delay
            # Exponential backoff, but never wait longer than 10 seconds
            # (1.1**24 < 10, 1.1**25 > 10, so it will take 25 iterations
            #  until the maximal 10 seconds delay is reached. By then, the
            #  code will have slept for ~1.5 minutes.)
            delay = min(delay * 1.1, 10)

    def _collect_params(self, active_options):
        parameters = []
        for options in active_options:
            values = {}
            engine = options.get_engine(self.engine_driver.name)
            for option in options.all_options:
                if not option.not_an_ansible_option and self.module.params[option.name] is not None:
                    values[option.name] = self.module.params[option.name]
            values = options.preprocess(self.module, values)
            engine.preprocess_value(self.module, self.client, self.engine_driver.get_api_version(self.client), options.options, values)
            parameters.append((options, values))
        return parameters

    def _needs_container_image(self):
        for options, values in self.parameters:
            engine = options.get_engine(self.engine_driver.name)
            if engine.needs_container_image(values):
                return True
        return False

    def _needs_host_info(self):
        for options, values in self.parameters:
            engine = options.get_engine(self.engine_driver.name)
            if engine.needs_host_info(values):
                return True
        return False

    def present(self, state):
        self.parameters = self._collect_params(self.options)
        container = self._get_container(self.param_name)
        was_running = container.running
        was_paused = container.paused
        container_created = False

        # If the image parameter was passed then we need to deal with the image
        # version comparison. Otherwise we handle this depending on whether
        # the container already runs or not; in the former case, in case the
        # container needs to be restarted, we use the existing container's
        # image ID.
        image, container_image, comparison_image = self._get_image(
            container, needs_container_image=self._needs_container_image())
        self.log(image, pretty_print=True)
        host_info = self.engine_driver.get_host_info(self.client) if self._needs_host_info() else None
        if not container.exists or container.removing:
            # New container
            if container.removing:
                self.log('Found container in removal phase')
            else:
                self.log('No container found')
            if not self.param_image:
                self.fail('Cannot create container when image is not specified!')
            self.diff_tracker.add('exists', parameter=True, active=False)
            if container.removing and not self.check_mode:
                # Wait for container to be removed before trying to create it
                self.wait_for_state(
                    container.id, wait_states=['removing'], accept_removal=True, max_wait=self.param_removal_wait_timeout)
            new_container = self.container_create(self.param_image)
            if new_container:
                container = new_container
            container_created = True
        else:
            # Existing container
            different, differences = self.has_different_configuration(container, container_image, comparison_image, host_info)
            image_different = False
            if self.all_options['image'].comparison == 'strict':
                image_different = self._image_is_different(image, container)
                if self.param_image_name_mismatch == 'recreate' and self.param_image is not None and self.param_image != container.image_name:
                    different = True
                    self.diff_tracker.add('image_name', parameter=self.param_image, active=container.image_name)
            if image_different or different or self.param_recreate:
                self.diff_tracker.merge(differences)
                self.diff['differences'] = differences.get_legacy_docker_container_diffs()
                if image_different:
                    self.diff['image_different'] = True
                self.log("differences")
                self.log(differences.get_legacy_docker_container_diffs(), pretty_print=True)
                image_to_use = self.param_image
                if not image_to_use and container and container.image:
                    image_to_use = container.image
                if not image_to_use:
                    self.fail('Cannot recreate container when image is not specified or cannot be extracted from current container!')
                if container.running:
                    self.container_stop(container.id)
                self.container_remove(container.id)
                if not self.check_mode:
                    self.wait_for_state(
                        container.id, wait_states=['removing'], accept_removal=True, max_wait=self.param_removal_wait_timeout)
                new_container = self.container_create(image_to_use)
                if new_container:
                    container = new_container
                container_created = True
                comparison_image = image

        if container and container.exists:
            container = self.update_limits(container, container_image, comparison_image, host_info)
            container = self.update_networks(container, container_created)

            if state in ('started', 'healthy') and not container.running:
                self.diff_tracker.add('running', parameter=True, active=was_running)
                container = self.container_start(container.id)
            elif state in ('started', 'healthy') and self.param_restart:
                self.diff_tracker.add('running', parameter=True, active=was_running)
                self.diff_tracker.add('restarted', parameter=True, active=False)
                container = self.container_restart(container.id)
            elif state == 'stopped' and container.running:
                self.diff_tracker.add('running', parameter=False, active=was_running)
                self.container_stop(container.id)
                container = self._get_container(container.id)

            if state in ('started', 'healthy') and self.param_paused is not None and container.paused != self.param_paused:
                self.diff_tracker.add('paused', parameter=self.param_paused, active=was_paused)
                if not self.check_mode:
                    try:
                        if self.param_paused:
                            self.engine_driver.pause_container(self.client, container.id)
                        else:
                            self.engine_driver.unpause_container(self.client, container.id)
                    except Exception as exc:
                        self.fail("Error %s container %s: %s" % (
                            "pausing" if self.param_paused else "unpausing", container.id, to_native(exc)
                        ))
                    container = self._get_container(container.id)
                self.results['changed'] = True
                self.results['actions'].append(dict(set_paused=self.param_paused))

        self.facts = container.raw

        if state == 'healthy' and not self.check_mode:
            # `None` means that no health check enabled; simply treat this as 'healthy'
            inspect_result = self.wait_for_state(
                container.id,
                wait_states=['starting', 'unhealthy'],
                complete_states=['healthy', None],
                max_wait=self.param_healthy_wait_timeout,
                health_state=True,
            )
            if inspect_result:
                # Return the latest inspection results retrieved
                self.facts = inspect_result

    def absent(self):
        container = self._get_container(self.param_name)
        if container.exists:
            if container.running:
                self.diff_tracker.add('running', parameter=False, active=True)
                self.container_stop(container.id)
            self.diff_tracker.add('exists', parameter=False, active=True)
            self.container_remove(container.id)

    def _output_logs(self, msg):
        self.module.log(msg=msg)

    def _get_container(self, container):
        '''
        Expects container ID or Name. Returns a container object
        '''
        container = self.engine_driver.inspect_container_by_name(self.client, container)
        return Container(container, self.engine_driver)

    def _get_container_image(self, container, fallback=None):
        if not container.exists or container.removing:
            return fallback
        image = container.image
        if is_image_name_id(image):
            image = self.engine_driver.inspect_image_by_id(self.client, image)
        else:
            repository, tag = parse_repository_tag(image)
            if not tag:
                tag = "latest"
            image = self.engine_driver.inspect_image_by_name(self.client, repository, tag)
        return image or fallback

    def _get_image(self, container, needs_container_image=False):
        image_parameter = self.param_image
        get_container_image = needs_container_image or not image_parameter
        container_image = self._get_container_image(container) if get_container_image else None
        if container_image:
            self.log("current image")
            self.log(container_image, pretty_print=True)
        if not image_parameter:
            self.log('No image specified')
            return None, container_image, container_image
        if is_image_name_id(image_parameter):
            image = self.engine_driver.inspect_image_by_id(self.client, image_parameter)
            if image is None:
                self.client.fail("Cannot find image with ID %s" % (image_parameter, ))
        else:
            repository, tag = parse_repository_tag(image_parameter)
            if not tag:
                tag = "latest"
            image = self.engine_driver.inspect_image_by_name(self.client, repository, tag)
            if not image and self.param_pull == "never":
                self.client.fail("Cannot find image with name %s:%s, and pull=never" % (repository, tag))
            if not image or self.param_pull == "always":
                if not self.check_mode:
                    self.log("Pull the image.")
                    image, alreadyToLatest = self.engine_driver.pull_image(
                        self.client, repository, tag, platform=self.module.params['platform'])
                    if alreadyToLatest:
                        self.results['changed'] = False
                        self.results['actions'].append(dict(pulled_image="%s:%s" % (repository, tag), changed=False))
                    else:
                        self.results['changed'] = True
                        self.results['actions'].append(dict(pulled_image="%s:%s" % (repository, tag), changed=True))
                elif not image or self.param_pull_check_mode_behavior == 'always':
                    # If the image is not there, or pull_check_mode_behavior == 'always', claim we'll
                    # pull. (Implicitly: if the image is there, claim it already was latest unless
                    # pull_check_mode_behavior == 'always'.)
                    self.results['changed'] = True
                    action = dict(pulled_image="%s:%s" % (repository, tag))
                    if not image:
                        action['changed'] = True
                    self.results['actions'].append(action)

        self.log("image")
        self.log(image, pretty_print=True)

        comparison_image = image
        if self.param_image_comparison == 'current-image':
            if not get_container_image:
                container_image = self._get_container_image(container)
            comparison_image = container_image

        return image, container_image, comparison_image

    def _image_is_different(self, image, container):
        if image and image.get('Id'):
            if container and container.image:
                if image.get('Id') != container.image:
                    self.diff_tracker.add('image', parameter=image.get('Id'), active=container.image)
                    return True
        return False

    def _compose_create_parameters(self, image):
        params = {}
        for options, values in self.parameters:
            engine = options.get_engine(self.engine_driver.name)
            if engine.can_set_value(self.engine_driver.get_api_version(self.client)):
                engine.set_value(self.module, params, self.engine_driver.get_api_version(self.client), options.options, values)
        params['Image'] = image
        return params

    def _record_differences(self, differences, options, param_values, engine, container, container_image, image, host_info):
        container_values = engine.get_value(
            self.module, container.raw, self.engine_driver.get_api_version(self.client), options.options, container_image, host_info)
        expected_values = engine.get_expected_values(
            self.module, self.client, self.engine_driver.get_api_version(self.client), options.options, image, param_values.copy(), host_info)
        for option in options.options:
            if option.name in expected_values:
                param_value = expected_values[option.name]
                container_value = container_values.get(option.name)
                match = engine.compare_value(option, param_value, container_value)

                if not match:
                    # No match.
                    if engine.ignore_mismatching_result(self.module, self.client, self.engine_driver.get_api_version(self.client),
                                                        option, image, container_value, param_value, host_info):
                        # Ignore the result
                        continue

                    # Record the differences
                    p = param_value
                    c = container_value
                    if option.comparison_type == 'set':
                        # Since the order does not matter, sort so that the diff output is better.
                        if p is not None:
                            p = sorted(p)
                        if c is not None:
                            c = sorted(c)
                    elif option.comparison_type == 'set(dict)':
                        # Since the order does not matter, sort so that the diff output is better.
                        if option.name == 'expected_mounts':
                            # For selected values, use one entry as key
                            def sort_key_fn(x):
                                return x['target']
                        else:
                            # We sort the list of dictionaries by using the sorted items of a dict as its key.
                            def sort_key_fn(x):
                                return sorted((a, to_text(b, errors='surrogate_or_strict')) for a, b in x.items())
                        if p is not None:
                            p = sorted(p, key=sort_key_fn)
                        if c is not None:
                            c = sorted(c, key=sort_key_fn)
                    differences.add(option.name, parameter=p, active=c)

    def has_different_configuration(self, container, container_image, image, host_info):
        differences = DifferenceTracker()
        update_differences = DifferenceTracker()
        for options, param_values in self.parameters:
            engine = options.get_engine(self.engine_driver.name)
            if engine.can_update_value(self.engine_driver.get_api_version(self.client)):
                self._record_differences(update_differences, options, param_values, engine, container, container_image, image, host_info)
            else:
                self._record_differences(differences, options, param_values, engine, container, container_image, image, host_info)
        has_differences = not differences.empty
        # Only consider differences of properties that can be updated when there are also other differences
        if has_differences:
            differences.merge(update_differences)
        return has_differences, differences

    def has_different_resource_limits(self, container, container_image, image, host_info):
        differences = DifferenceTracker()
        for options, param_values in self.parameters:
            engine = options.get_engine(self.engine_driver.name)
            if not engine.can_update_value(self.engine_driver.get_api_version(self.client)):
                continue
            self._record_differences(differences, options, param_values, engine, container, container_image, image, host_info)
        has_differences = not differences.empty
        return has_differences, differences

    def _compose_update_parameters(self):
        result = {}
        for options, values in self.parameters:
            engine = options.get_engine(self.engine_driver.name)
            if not engine.can_update_value(self.engine_driver.get_api_version(self.client)):
                continue
            engine.update_value(self.module, result, self.engine_driver.get_api_version(self.client), options.options, values)
        return result

    def update_limits(self, container, container_image, image, host_info):
        limits_differ, different_limits = self.has_different_resource_limits(container, container_image, image, host_info)
        if limits_differ:
            self.log("limit differences:")
            self.log(different_limits.get_legacy_docker_container_diffs(), pretty_print=True)
            self.diff_tracker.merge(different_limits)
        if limits_differ and not self.check_mode:
            self.container_update(container.id, self._compose_update_parameters())
            return self._get_container(container.id)
        return container

    def has_network_differences(self, container):
        '''
        Check if the container is connected to requested networks with expected options: links, aliases, ipv4, ipv6
        '''
        different = False
        differences = []

        if not self.module.params['networks']:
            return different, differences

        if not container.container.get('NetworkSettings'):
            self.fail("has_missing_networks: Error parsing container properties. NetworkSettings missing.")

        connected_networks = container.container['NetworkSettings']['Networks']
        for network in self.module.params['networks']:
            network_info = connected_networks.get(network['name'])
            if network_info is None:
                different = True
                differences.append(dict(
                    parameter=network,
                    container=None
                ))
            else:
                diff = False
                network_info_ipam = network_info.get('IPAMConfig') or {}
                if network.get('ipv4_address') and normalize_ip_address(network['ipv4_address']) != normalize_ip_address(network_info_ipam.get('IPv4Address')):
                    diff = True
                if network.get('ipv6_address') and normalize_ip_address(network['ipv6_address']) != normalize_ip_address(network_info_ipam.get('IPv6Address')):
                    diff = True
                if network.get('aliases'):
                    if not compare_generic(network['aliases'], network_info.get('Aliases'), 'allow_more_present', 'set'):
                        diff = True
                if network.get('links'):
                    expected_links = []
                    for link, alias in network['links']:
                        expected_links.append("%s:%s" % (link, alias))
                    if not compare_generic(expected_links, network_info.get('Links'), 'allow_more_present', 'set'):
                        diff = True
                if network.get('mac_address') and network['mac_address'] != network_info.get('MacAddress'):
                    diff = True
                if diff:
                    different = True
                    differences.append(dict(
                        parameter=network,
                        container=dict(
                            name=network['name'],
                            ipv4_address=network_info_ipam.get('IPv4Address'),
                            ipv6_address=network_info_ipam.get('IPv6Address'),
                            aliases=network_info.get('Aliases'),
                            links=network_info.get('Links'),
                            mac_address=network_info.get('MacAddress'),
                        )
                    ))
        return different, differences

    def has_extra_networks(self, container):
        '''
        Check if the container is connected to non-requested networks
        '''
        extra_networks = []
        extra = False

        if not container.container.get('NetworkSettings'):
            self.fail("has_extra_networks: Error parsing container properties. NetworkSettings missing.")

        connected_networks = container.container['NetworkSettings'].get('Networks')
        if connected_networks:
            for network, network_config in connected_networks.items():
                keep = False
                if self.module.params['networks']:
                    for expected_network in self.module.params['networks']:
                        if expected_network['name'] == network:
                            keep = True
                if not keep:
                    extra = True
                    extra_networks.append(dict(name=network, id=network_config['NetworkID']))
        return extra, extra_networks

    def update_networks(self, container, container_created):
        updated_container = container
        if self.all_options['networks'].comparison != 'ignore' or container_created:
            has_network_differences, network_differences = self.has_network_differences(container)
            if has_network_differences:
                if self.diff.get('differences'):
                    self.diff['differences'].append(dict(network_differences=network_differences))
                else:
                    self.diff['differences'] = [dict(network_differences=network_differences)]
                for netdiff in network_differences:
                    self.diff_tracker.add(
                        'network.{0}'.format(netdiff['parameter']['name']),
                        parameter=netdiff['parameter'],
                        active=netdiff['container']
                    )
                self.results['changed'] = True
                updated_container = self._add_networks(container, network_differences)

        purge_networks = self.all_options['networks'].comparison == 'strict' and self.module.params['networks'] is not None
        if purge_networks:
            has_extra_networks, extra_networks = self.has_extra_networks(container)
            if has_extra_networks:
                if self.diff.get('differences'):
                    self.diff['differences'].append(dict(purge_networks=extra_networks))
                else:
                    self.diff['differences'] = [dict(purge_networks=extra_networks)]
                for extra_network in extra_networks:
                    self.diff_tracker.add(
                        'network.{0}'.format(extra_network['name']),
                        active=extra_network
                    )
                self.results['changed'] = True
                updated_container = self._purge_networks(container, extra_networks)
        return updated_container

    def _add_networks(self, container, differences):
        for diff in differences:
            # remove the container from the network, if connected
            if diff.get('container'):
                self.results['actions'].append(dict(removed_from_network=diff['parameter']['name']))
                if not self.check_mode:
                    try:
                        self.engine_driver.disconnect_container_from_network(self.client, container.id, diff['parameter']['id'])
                    except Exception as exc:
                        self.fail("Error disconnecting container from network %s - %s" % (diff['parameter']['name'],
                                                                                          to_native(exc)))
            # connect to the network
            self.results['actions'].append(dict(added_to_network=diff['parameter']['name'], network_parameters=diff['parameter']))
            if not self.check_mode:
                params = {key: value for key, value in diff['parameter'].items() if key not in ('id', 'name')}
                try:
                    self.log("Connecting container to network %s" % diff['parameter']['id'])
                    self.log(params, pretty_print=True)
                    self.engine_driver.connect_container_to_network(self.client, container.id, diff['parameter']['id'], params)
                except Exception as exc:
                    self.fail("Error connecting container to network %s - %s" % (diff['parameter']['name'], to_native(exc)))
        return self._get_container(container.id)

    def _purge_networks(self, container, networks):
        for network in networks:
            self.results['actions'].append(dict(removed_from_network=network['name']))
            if not self.check_mode:
                try:
                    self.engine_driver.disconnect_container_from_network(self.client, container.id, network['name'])
                except Exception as exc:
                    self.fail("Error disconnecting container from network %s - %s" % (network['name'],
                                                                                      to_native(exc)))
        return self._get_container(container.id)

    def container_create(self, image):
        create_parameters = self._compose_create_parameters(image)
        self.log("create container")
        self.log("image: %s parameters:" % image)
        self.log(create_parameters, pretty_print=True)
        networks = {}
        if self.param_networks_cli_compatible and self.module.params['networks']:
            network_list = self.module.params['networks']
            if not self.engine_driver.create_container_supports_more_than_one_network(self.client):
                network_list = network_list[:1]
            for network in network_list:
                networks[network['name']] = {
                    key: value for key, value in network.items()
                    if key not in ('name', 'id')
                }
        self.results['actions'].append(dict(created="Created container", create_parameters=create_parameters, networks=networks))
        self.results['changed'] = True
        new_container = None
        if not self.check_mode:
            try:
                container_id = self.engine_driver.create_container(self.client, self.param_name, create_parameters, networks=networks)
            except Exception as exc:
                self.fail("Error creating container: %s" % to_native(exc))
            return self._get_container(container_id)
        return new_container

    def container_start(self, container_id):
        self.log("start container %s" % (container_id))
        self.results['actions'].append(dict(started=container_id))
        self.results['changed'] = True
        if not self.check_mode:
            try:
                self.engine_driver.start_container(self.client, container_id)
            except Exception as exc:
                self.fail("Error starting container %s: %s" % (container_id, to_native(exc)))

            if self.module.params['detach'] is False:
                status = self.engine_driver.wait_for_container(self.client, container_id)
                self.client.fail_results['status'] = status
                self.results['status'] = status

                if self.module.params['auto_remove']:
                    output = "Cannot retrieve result as auto_remove is enabled"
                    if self.param_output_logs:
                        self.module.warn('Cannot output_logs if auto_remove is enabled!')
                else:
                    output, real_output = self.engine_driver.get_container_output(self.client, container_id)
                    if real_output and self.param_output_logs:
                        self._output_logs(msg=output)

                if self.param_cleanup:
                    self.container_remove(container_id, force=True)
                insp = self._get_container(container_id)
                if insp.raw:
                    insp.raw['Output'] = output
                else:
                    insp.raw = dict(Output=output)
                if status != 0:
                    # Set `failed` to True and return output as msg
                    self.results['failed'] = True
                    self.results['msg'] = output
                return insp
        return self._get_container(container_id)

    def container_remove(self, container_id, link=False, force=False):
        volume_state = (not self.param_keep_volumes)
        self.log("remove container container:%s v:%s link:%s force%s" % (container_id, volume_state, link, force))
        self.results['actions'].append(dict(removed=container_id, volume_state=volume_state, link=link, force=force))
        self.results['changed'] = True
        if not self.check_mode:
            try:
                self.engine_driver.remove_container(self.client, container_id, remove_volumes=volume_state, link=link, force=force)
            except Exception as exc:
                self.client.fail("Error removing container %s: %s" % (container_id, to_native(exc)))

    def container_update(self, container_id, update_parameters):
        if update_parameters:
            self.log("update container %s" % (container_id))
            self.log(update_parameters, pretty_print=True)
            self.results['actions'].append(dict(updated=container_id, update_parameters=update_parameters))
            self.results['changed'] = True
            if not self.check_mode:
                try:
                    self.engine_driver.update_container(self.client, container_id, update_parameters)
                except Exception as exc:
                    self.fail("Error updating container %s: %s" % (container_id, to_native(exc)))
        return self._get_container(container_id)

    def container_kill(self, container_id):
        self.results['actions'].append(dict(killed=container_id, signal=self.param_kill_signal))
        self.results['changed'] = True
        if not self.check_mode:
            try:
                self.engine_driver.kill_container(self.client, container_id, kill_signal=self.param_kill_signal)
            except Exception as exc:
                self.fail("Error killing container %s: %s" % (container_id, to_native(exc)))

    def container_restart(self, container_id):
        self.results['actions'].append(dict(restarted=container_id, timeout=self.module.params['stop_timeout']))
        self.results['changed'] = True
        if not self.check_mode:
            try:
                self.engine_driver.restart_container(self.client, container_id, self.module.params['stop_timeout'] or 10)
            except Exception as exc:
                self.fail("Error restarting container %s: %s" % (container_id, to_native(exc)))
        return self._get_container(container_id)

    def container_stop(self, container_id):
        if self.param_force_kill:
            self.container_kill(container_id)
            return
        self.results['actions'].append(dict(stopped=container_id, timeout=self.module.params['stop_timeout']))
        self.results['changed'] = True
        if not self.check_mode:
            try:
                self.engine_driver.stop_container(self.client, container_id, self.module.params['stop_timeout'])
            except Exception as exc:
                self.fail("Error stopping container %s: %s" % (container_id, to_native(exc)))


def run_module(engine_driver):
    module, active_options, client = engine_driver.setup(
        argument_spec=dict(
            cleanup=dict(type='bool', default=False),
            comparisons=dict(type='dict'),
            container_default_behavior=dict(type='str', default='no_defaults', choices=['compatibility', 'no_defaults']),
            command_handling=dict(type='str', choices=['compatibility', 'correct'], default='correct'),
            default_host_ip=dict(type='str'),
            force_kill=dict(type='bool', default=False, aliases=['forcekill']),
            image=dict(type='str'),
            image_comparison=dict(type='str', choices=['desired-image', 'current-image'], default='desired-image'),
            image_label_mismatch=dict(type='str', choices=['ignore', 'fail'], default='ignore'),
            image_name_mismatch=dict(type='str', choices=['ignore', 'recreate'], default='recreate'),
            keep_volumes=dict(type='bool', default=True),
            kill_signal=dict(type='str'),
            name=dict(type='str', required=True),
            networks_cli_compatible=dict(type='bool', default=True),
            output_logs=dict(type='bool', default=False),
            paused=dict(type='bool'),
            pull=dict(type='raw', choices=['never', 'missing', 'always', True, False], default='missing'),
            pull_check_mode_behavior=dict(type='str', choices=['image_not_present', 'always'], default='image_not_present'),
            recreate=dict(type='bool', default=False),
            removal_wait_timeout=dict(type='float'),
            restart=dict(type='bool', default=False),
            state=dict(type='str', default='started', choices=['absent', 'present', 'healthy', 'started', 'stopped']),
            healthy_wait_timeout=dict(type='float', default=300),
        ),
        required_if=[
            ('state', 'present', ['image']),
        ],
    )

    def execute():
        cm = ContainerManager(module, engine_driver, client, active_options)
        cm.run()
        module.exit_json(**sanitize_result(cm.results))

    engine_driver.run(execute, client)
