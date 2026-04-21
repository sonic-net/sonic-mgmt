# Copyright (c) 2023, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


import abc
import json
import shlex

from ansible.module_utils.basic import AnsibleModule, env_fallback
from ansible.module_utils.common.process import get_bin_path
from ansible.module_utils.common.text.converters import to_native
from ansible_collections.community.docker.plugins.module_utils._six import string_types

from ansible_collections.community.docker.plugins.module_utils.version import LooseVersion

from ansible_collections.community.docker.plugins.module_utils._api.auth import resolve_repository_name

from ansible_collections.community.docker.plugins.module_utils.util import (  # noqa: F401, pylint: disable=unused-import
    DEFAULT_DOCKER_HOST,
    DEFAULT_TLS,
    DEFAULT_TLS_VERIFY,
    DOCKER_MUTUALLY_EXCLUSIVE,
    DOCKER_REQUIRED_TOGETHER,
    sanitize_result,
)


DOCKER_COMMON_ARGS = dict(
    docker_cli=dict(type='path'),
    docker_host=dict(type='str', fallback=(env_fallback, ['DOCKER_HOST']), aliases=['docker_url']),
    tls_hostname=dict(type='str', fallback=(env_fallback, ['DOCKER_TLS_HOSTNAME'])),
    api_version=dict(type='str', default='auto', fallback=(env_fallback, ['DOCKER_API_VERSION']), aliases=['docker_api_version']),
    ca_path=dict(type='path', aliases=['ca_cert', 'tls_ca_cert', 'cacert_path']),
    client_cert=dict(type='path', aliases=['tls_client_cert', 'cert_path']),
    client_key=dict(type='path', aliases=['tls_client_key', 'key_path']),
    tls=dict(type='bool', default=DEFAULT_TLS, fallback=(env_fallback, ['DOCKER_TLS'])),
    validate_certs=dict(type='bool', default=DEFAULT_TLS_VERIFY, fallback=(env_fallback, ['DOCKER_TLS_VERIFY']), aliases=['tls_verify']),
    # debug=dict(type='bool', default=False),
    cli_context=dict(type='str'),
)


class DockerException(Exception):
    pass


class AnsibleDockerClientBase(object):
    def __init__(self, common_args, min_docker_api_version=None, needs_api_version=True):
        self._environment = {}
        if common_args['tls_hostname']:
            self._environment['DOCKER_TLS_HOSTNAME'] = common_args['tls_hostname']
        if common_args['api_version'] and common_args['api_version'] != 'auto':
            self._environment['DOCKER_API_VERSION'] = common_args['api_version']
        self._cli = common_args.get('docker_cli')
        if self._cli is None:
            try:
                self._cli = get_bin_path('docker')
            except ValueError:
                self.fail('Cannot find docker CLI in path. Please provide it explicitly with the docker_cli parameter')

        self._cli_base = [self._cli]
        docker_host = common_args['docker_host']
        if not docker_host and not common_args['cli_context']:
            docker_host = DEFAULT_DOCKER_HOST
        if docker_host:
            self._cli_base.extend(['--host', docker_host])
        if common_args['validate_certs']:
            self._cli_base.append('--tlsverify')
        elif common_args['tls']:
            self._cli_base.append('--tls')
        if common_args['ca_path']:
            self._cli_base.extend(['--tlscacert', common_args['ca_path']])
        if common_args['client_cert']:
            self._cli_base.extend(['--tlscert', common_args['client_cert']])
        if common_args['client_key']:
            self._cli_base.extend(['--tlskey', common_args['client_key']])
        if common_args['cli_context']:
            self._cli_base.extend(['--context', common_args['cli_context']])

        # `--format json` was only added as a shorthand for `--format {{ json . }}` in Docker 23.0
        dummy, self._version, dummy = self.call_cli_json('version', '--format', '{{ json . }}', check_rc=True)
        self._info = None

        if needs_api_version:
            api_version_string = self._version["Server"].get("ApiVersion") or self._version["Server"].get("APIVersion")
            if not isinstance(self._version.get('Server'), dict) or not isinstance(api_version_string, string_types):
                self.fail('Cannot determine Docker Daemon information. Are you maybe using podman instead of docker?')
            self.docker_api_version_str = to_native(api_version_string)
            self.docker_api_version = LooseVersion(self.docker_api_version_str)
            min_docker_api_version = min_docker_api_version or '1.25'
            if self.docker_api_version < LooseVersion(min_docker_api_version):
                self.fail('Docker API version is %s. Minimum version required is %s.' % (self.docker_api_version_str, min_docker_api_version))
        else:
            self.docker_api_version_str = None
            self.docker_api_version = None
            if min_docker_api_version is not None:
                self.fail('Internal error: cannot have needs_api_version=False with min_docker_api_version not None')

    def log(self, msg, pretty_print=False):
        pass
        # if self.debug:
        #     from .util import log_debug
        #     log_debug(msg, pretty_print=pretty_print)

    def get_cli(self):
        return self._cli

    def get_version_info(self):
        return self._version

    def _compose_cmd(self, args):
        return self._cli_base + list(args)

    def _compose_cmd_str(self, args):
        return ' '.join(shlex.quote(a) for a in self._compose_cmd(args))

    @abc.abstractmethod
    # def call_cli(self, *args, check_rc=False, data=None, cwd=None, environ_update=None):
    def call_cli(self, *args, **kwargs):
        # Python 2.7 does not like anything than '**kwargs' after '*args', so we have to do this manually...
        pass

    # def call_cli_json(self, *args, check_rc=False, data=None, cwd=None, environ_update=None, warn_on_stderr=False):
    def call_cli_json(self, *args, **kwargs):
        warn_on_stderr = kwargs.pop('warn_on_stderr', False)
        rc, stdout, stderr = self.call_cli(*args, **kwargs)
        if warn_on_stderr and stderr:
            self.warn(to_native(stderr))
        try:
            data = json.loads(stdout)
        except Exception as exc:
            self.fail(
                'Error while parsing JSON output of {cmd}: {exc}\nJSON output: {stdout}\n\nError output:\n{stderr}'.format(
                    cmd=self._compose_cmd_str(args),
                    exc=to_native(exc),
                    stdout=to_native(stdout),
                    stderr=to_native(stderr),
                ),
                cmd=self._compose_cmd_str(args),
                rc=rc,
                stdout=to_native(stdout),
                stderr=to_native(stderr),
            )
        return rc, data, stderr

    # def call_cli_json_stream(self, *args, check_rc=False, data=None, cwd=None, environ_update=None, warn_on_stderr=False):
    def call_cli_json_stream(self, *args, **kwargs):
        warn_on_stderr = kwargs.pop('warn_on_stderr', False)
        rc, stdout, stderr = self.call_cli(*args, **kwargs)
        if warn_on_stderr and stderr:
            self.warn(to_native(stderr))
        result = []
        try:
            for line in stdout.splitlines():
                line = line.strip()
                if line.startswith(b'{'):
                    result.append(json.loads(line))
        except Exception as exc:
            self.fail(
                'Error while parsing JSON output of {cmd}: {exc}\nJSON output: {stdout}\n\nError output:\n{stderr}'.format(
                    cmd=self._compose_cmd_str(args),
                    exc=to_native(exc),
                    stdout=to_native(stdout),
                    stderr=to_native(stderr),
                ),
                cmd=self._compose_cmd_str(args),
                rc=rc,
                stdout=to_native(stdout),
                stderr=to_native(stderr),
            )
        return rc, result, stderr

    @abc.abstractmethod
    def fail(self, msg, **kwargs):
        pass

    @abc.abstractmethod
    def warn(self, msg):
        pass

    @abc.abstractmethod
    def deprecate(self, msg, version=None, date=None, collection_name=None):
        pass

    def get_cli_info(self):
        if self._info is None:
            dummy, self._info, dummy = self.call_cli_json('info', '--format', '{{ json . }}', check_rc=True)
        return self._info

    def get_client_plugin_info(self, component):
        cli_info = self.get_cli_info()
        if not isinstance(cli_info.get('ClientInfo'), dict):
            self.fail('Cannot determine Docker client information. Are you maybe using podman instead of docker?')
        for plugin in cli_info['ClientInfo'].get('Plugins') or []:
            if plugin.get('Name') == component:
                return plugin
        return None

    def _image_lookup(self, name, tag):
        '''
        Including a tag in the name parameter sent to the Docker SDK for Python images method
        does not work consistently. Instead, get the result set for name and manually check
        if the tag exists.
        '''
        dummy, images, dummy = self.call_cli_json_stream(
            'image', 'ls', '--format', '{{ json . }}', '--no-trunc', '--filter', 'reference={0}'.format(name),
            check_rc=True,
        )
        if tag:
            lookup = "%s:%s" % (name, tag)
            lookup_digest = "%s@%s" % (name, tag)
            response = images
            images = []
            for image in response:
                if image.get('Tag') == tag or image.get('Digest') == tag:
                    images = [image]
                    break
        return images

    def find_image(self, name, tag):
        '''
        Lookup an image (by name and tag) and return the inspection results.
        '''
        if not name:
            return None

        self.log("Find image %s:%s" % (name, tag))
        images = self._image_lookup(name, tag)
        if not images:
            # In API <= 1.20 seeing 'docker.io/<name>' as the name of images pulled from docker hub
            registry, repo_name = resolve_repository_name(name)
            if registry == 'docker.io':
                # If docker.io is explicitly there in name, the image
                # is not found in some cases (#41509)
                self.log("Check for docker.io image: %s" % repo_name)
                images = self._image_lookup(repo_name, tag)
                if not images and repo_name.startswith('library/'):
                    # Sometimes library/xxx images are not found
                    lookup = repo_name[len('library/'):]
                    self.log("Check for docker.io image: %s" % lookup)
                    images = self._image_lookup(lookup, tag)
                if not images:
                    # Last case for some Docker versions: if docker.io was not there,
                    # it can be that the image was not found either
                    # (https://github.com/ansible/ansible/pull/15586)
                    lookup = "%s/%s" % (registry, repo_name)
                    self.log("Check for docker.io image: %s" % lookup)
                    images = self._image_lookup(lookup, tag)
                if not images and '/' not in repo_name:
                    # This seems to be happening with podman-docker
                    # (https://github.com/ansible-collections/community.docker/issues/291)
                    lookup = "%s/library/%s" % (registry, repo_name)
                    self.log("Check for docker.io image: %s" % lookup)
                    images = self._image_lookup(lookup, tag)

        if len(images) > 1:
            self.fail("Daemon returned more than one result for %s:%s" % (name, tag))

        if len(images) == 1:
            rc, image, stderr = self.call_cli_json('image', 'inspect', images[0]['ID'])
            if not image:
                self.log("Image %s:%s not found." % (name, tag))
                return None
            if rc != 0:
                self.fail("Error inspecting image %s:%s - %s" % (name, tag, to_native(stderr)))
            return image[0]

        self.log("Image %s:%s not found." % (name, tag))
        return None

    def find_image_by_id(self, image_id, accept_missing_image=False):
        '''
        Lookup an image (by ID) and return the inspection results.
        '''
        if not image_id:
            return None

        self.log("Find image %s (by ID)" % image_id)
        rc, image, stderr = self.call_cli_json('image', 'inspect', image_id)
        if not image:
            if not accept_missing_image:
                self.fail("Error inspecting image ID %s - %s" % (image_id, to_native(stderr)))
            self.log("Image %s not found." % image_id)
            return None
        if rc != 0:
            self.fail("Error inspecting image ID %s - %s" % (image_id, to_native(stderr)))
        return image[0]


class AnsibleModuleDockerClient(AnsibleDockerClientBase):
    def __init__(self, argument_spec=None, supports_check_mode=False, mutually_exclusive=None,
                 required_together=None, required_if=None, required_one_of=None, required_by=None,
                 min_docker_api_version=None, fail_results=None, needs_api_version=True):

        # Modules can put information in here which will always be returned
        # in case client.fail() is called.
        self.fail_results = fail_results or {}

        merged_arg_spec = dict()
        merged_arg_spec.update(DOCKER_COMMON_ARGS)
        if argument_spec:
            merged_arg_spec.update(argument_spec)
            self.arg_spec = merged_arg_spec

        mutually_exclusive_params = [('docker_host', 'cli_context')]
        mutually_exclusive_params += DOCKER_MUTUALLY_EXCLUSIVE
        if mutually_exclusive:
            mutually_exclusive_params += mutually_exclusive

        required_together_params = []
        required_together_params += DOCKER_REQUIRED_TOGETHER
        if required_together:
            required_together_params += required_together

        self.module = AnsibleModule(
            argument_spec=merged_arg_spec,
            supports_check_mode=supports_check_mode,
            mutually_exclusive=mutually_exclusive_params,
            required_together=required_together_params,
            required_if=required_if,
            required_one_of=required_one_of,
            required_by=required_by or {},
        )

        self.debug = False  # self.module.params['debug']
        self.check_mode = self.module.check_mode
        self.diff = self.module._diff

        common_args = dict((k, self.module.params[k]) for k in DOCKER_COMMON_ARGS)
        super(AnsibleModuleDockerClient, self).__init__(
            common_args, min_docker_api_version=min_docker_api_version, needs_api_version=needs_api_version,
        )

    # def call_cli(self, *args, check_rc=False, data=None, cwd=None, environ_update=None):
    def call_cli(self, *args, **kwargs):
        # Python 2.7 does not like anything than '**kwargs' after '*args', so we have to do this manually...
        check_rc = kwargs.pop('check_rc', False)
        data = kwargs.pop('data', None)
        cwd = kwargs.pop('cwd', None)
        environ_update = kwargs.pop('environ_update', None)
        if kwargs:
            raise TypeError("call_cli() got an unexpected keyword argument '%s'" % list(kwargs)[0])

        environment = self._environment.copy()
        if environ_update:
            environment.update(environ_update)
        rc, stdout, stderr = self.module.run_command(
            self._compose_cmd(args),
            binary_data=True,
            check_rc=check_rc,
            cwd=cwd,
            data=data,
            encoding=None,
            environ_update=environment,
            expand_user_and_vars=False,
            ignore_invalid_cwd=False,
        )
        return rc, stdout, stderr

    def fail(self, msg, **kwargs):
        self.fail_results.update(kwargs)
        self.module.fail_json(msg=msg, **sanitize_result(self.fail_results))

    def warn(self, msg):
        self.module.warn(msg)

    def deprecate(self, msg, version=None, date=None, collection_name=None):
        self.module.deprecate(msg, version=version, date=date, collection_name=collection_name)
