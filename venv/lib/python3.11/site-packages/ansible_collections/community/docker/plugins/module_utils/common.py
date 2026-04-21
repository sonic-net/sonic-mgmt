# Copyright 2016 Red Hat | Ansible
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


import abc
import os
import platform
import re
import sys
import traceback

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible_collections.community.docker.plugins.module_utils._six import Mapping, Sequence, string_types
from ansible.module_utils.parsing.convert_bool import BOOLEANS_TRUE, BOOLEANS_FALSE

from ansible_collections.community.docker.plugins.module_utils.version import LooseVersion

HAS_DOCKER_PY = True
HAS_DOCKER_PY_2 = False
HAS_DOCKER_PY_3 = False
HAS_DOCKER_ERROR = None
HAS_DOCKER_TRACEBACK = None

try:
    from requests.exceptions import SSLError
    from docker import __version__ as docker_version
    from docker.errors import APIError, NotFound, TLSParameterError
    from docker.tls import TLSConfig
    from docker import auth

    if LooseVersion(docker_version) >= LooseVersion('3.0.0'):
        HAS_DOCKER_PY_3 = True
        from docker import APIClient as Client
    elif LooseVersion(docker_version) >= LooseVersion('2.0.0'):
        HAS_DOCKER_PY_2 = True
        from docker import APIClient as Client
    else:
        from docker import Client

except ImportError as exc:
    HAS_DOCKER_ERROR = str(exc)
    HAS_DOCKER_TRACEBACK = traceback.format_exc()
    HAS_DOCKER_PY = False


# The next two imports ``docker.models`` and ``docker.ssladapter`` are used
# to ensure the user does not have both ``docker`` and ``docker-py`` modules
# installed, as they utilize the same namespace are are incompatible
try:
    # docker (Docker SDK for Python >= 2.0.0)
    import docker.models  # noqa: F401, pylint: disable=unused-import
    HAS_DOCKER_MODELS = True
except ImportError:
    HAS_DOCKER_MODELS = False

try:
    # docker-py (Docker SDK for Python < 2.0.0)
    import docker.ssladapter  # noqa: F401, pylint: disable=unused-import
    HAS_DOCKER_SSLADAPTER = True
except ImportError:
    HAS_DOCKER_SSLADAPTER = False


try:
    from requests.exceptions import RequestException  # noqa: F401, pylint: disable=unused-import
except ImportError:
    # Either Docker SDK for Python is no longer using requests, or Docker SDK for Python is not around either,
    # or Docker SDK for Python's dependency requests is missing. In any case, define an exception
    # class RequestException so that our code does not break.
    class RequestException(Exception):
        pass

from ansible_collections.community.docker.plugins.module_utils.util import (  # noqa: F401, pylint: disable=unused-import
    DEFAULT_DOCKER_HOST,
    DEFAULT_TLS,
    DEFAULT_TLS_VERIFY,
    DEFAULT_TLS_HOSTNAME,  # TODO: remove
    DEFAULT_TIMEOUT_SECONDS,
    DOCKER_COMMON_ARGS,
    DOCKER_COMMON_ARGS_VARS,  # TODO: remove
    DOCKER_MUTUALLY_EXCLUSIVE,
    DOCKER_REQUIRED_TOGETHER,
    DEFAULT_DOCKER_REGISTRY,  # TODO: remove
    BYTE_SUFFIXES,  # TODO: remove
    is_image_name_id,  # TODO: remove
    is_valid_tag,  # TODO: remove
    sanitize_result,
    DockerBaseClass,  # TODO: remove
    update_tls_hostname,
    compare_dict_allow_more_present,  # TODO: remove
    compare_generic,  # TODO: remove
    DifferenceTracker,  # TODO: remove
    clean_dict_booleans_for_docker_api,  # TODO: remove
    convert_duration_to_nanosecond,  # TODO: remove
    parse_healthcheck,  # TODO: remove
    omit_none_from_dict,  # TODO: remove
)


MIN_DOCKER_VERSION = "1.8.0"


if not HAS_DOCKER_PY:
    docker_version = None

    # No Docker SDK for Python. Create a place holder client to allow
    # instantiation of AnsibleModule and proper error handing
    class Client(object):  # noqa: F811
        def __init__(self, **kwargs):
            pass

    class APIError(Exception):  # noqa: F811
        pass

    class NotFound(Exception):  # noqa: F811
        pass


def _get_tls_config(fail_function, **kwargs):
    if 'assert_hostname' in kwargs and LooseVersion(docker_version) >= LooseVersion('7.0.0b1'):
        assert_hostname = kwargs.pop('assert_hostname')
        if assert_hostname is not None:
            fail_function(
                "tls_hostname is not compatible with Docker SDK for Python 7.0.0+. You are using"
                " Docker SDK for Python {docker_py_version}. The tls_hostname option (value: {tls_hostname})"
                " has either been set directly or with the environment variable DOCKER_TLS_HOSTNAME."
                " Make sure it is not set, or switch to an older version of Docker SDK for Python.".format(
                    docker_py_version=docker_version,
                    tls_hostname=assert_hostname,
                )
            )
    # Filter out all None parameters
    kwargs = dict((k, v) for k, v in kwargs.items() if v is not None)
    try:
        tls_config = TLSConfig(**kwargs)
        return tls_config
    except TLSParameterError as exc:
        fail_function("TLS config error: %s" % exc)


def is_using_tls(auth):
    return auth['tls_verify'] or auth['tls']


def get_connect_params(auth, fail_function):
    if is_using_tls(auth):
        auth['docker_host'] = auth['docker_host'].replace('tcp://', 'https://')

    result = dict(
        base_url=auth['docker_host'],
        version=auth['api_version'],
        timeout=auth['timeout'],
    )

    if auth['tls_verify']:
        # TLS with verification
        tls_config = dict(
            verify=True,
            assert_hostname=auth['tls_hostname'],
            fail_function=fail_function,
        )
        if auth['cert_path'] and auth['key_path']:
            tls_config['client_cert'] = (auth['cert_path'], auth['key_path'])
        if auth['cacert_path']:
            tls_config['ca_cert'] = auth['cacert_path']
        result['tls'] = _get_tls_config(**tls_config)
    elif auth['tls']:
        # TLS without verification
        tls_config = dict(
            verify=False,
            fail_function=fail_function,
        )
        if auth['cert_path'] and auth['key_path']:
            tls_config['client_cert'] = (auth['cert_path'], auth['key_path'])
        result['tls'] = _get_tls_config(**tls_config)

    if auth.get('use_ssh_client'):
        if LooseVersion(docker_version) < LooseVersion('4.4.0'):
            fail_function("use_ssh_client=True requires Docker SDK for Python 4.4.0 or newer")
        result['use_ssh_client'] = True

    # No TLS
    return result


DOCKERPYUPGRADE_SWITCH_TO_DOCKER = "Try `pip uninstall docker-py` followed by `pip install docker`."
DOCKERPYUPGRADE_UPGRADE_DOCKER = "Use `pip install --upgrade docker` to upgrade."
DOCKERPYUPGRADE_RECOMMEND_DOCKER = "Use `pip install --upgrade docker-py` to upgrade."


class AnsibleDockerClientBase(Client):
    def __init__(self, min_docker_version=None, min_docker_api_version=None):
        if min_docker_version is None:
            min_docker_version = MIN_DOCKER_VERSION
        NEEDS_DOCKER_PY2 = (LooseVersion(min_docker_version) >= LooseVersion('2.0.0'))

        self.docker_py_version = LooseVersion(docker_version)

        if HAS_DOCKER_MODELS and HAS_DOCKER_SSLADAPTER:
            self.fail("Cannot have both the docker-py and docker python modules (old and new version of Docker "
                      "SDK for Python) installed together as they use the same namespace and cause a corrupt "
                      "installation. Please uninstall both packages, and re-install only the docker-py or docker "
                      "python module (for %s's Python %s). It is recommended to install the docker module. Please "
                      "note that simply uninstalling one of the modules can leave the other module in a broken "
                      "state." % (platform.node(), sys.executable))

        if not HAS_DOCKER_PY:
            msg = missing_required_lib("Docker SDK for Python: docker>=5.0.0 (Python >= 3.6) or "
                                       "docker<5.0.0 (Python 2.7)")
            msg = msg + ", for example via `pip install docker` (Python >= 3.6) or " \
                + "`pip install docker==4.4.4` (Python 2.7). The error was: %s"
            self.fail(msg % HAS_DOCKER_ERROR, exception=HAS_DOCKER_TRACEBACK)

        if self.docker_py_version < LooseVersion(min_docker_version):
            msg = "Error: Docker SDK for Python version is %s (%s's Python %s). Minimum version required is %s."
            if not NEEDS_DOCKER_PY2:
                # The minimal required version is < 2.0 (and the current version as well).
                # Advertise docker (instead of docker-py).
                msg += DOCKERPYUPGRADE_RECOMMEND_DOCKER
            elif docker_version < LooseVersion('2.0'):
                msg += DOCKERPYUPGRADE_SWITCH_TO_DOCKER
            else:
                msg += DOCKERPYUPGRADE_UPGRADE_DOCKER
            self.fail(msg % (docker_version, platform.node(), sys.executable, min_docker_version))

        self._connect_params = get_connect_params(self.auth_params, fail_function=self.fail)

        try:
            super(AnsibleDockerClientBase, self).__init__(**self._connect_params)
            self.docker_api_version_str = self.api_version
        except APIError as exc:
            self.fail("Docker API error: %s" % exc)
        except Exception as exc:
            self.fail("Error connecting: %s" % exc)

        self.docker_api_version = LooseVersion(self.docker_api_version_str)
        min_docker_api_version = min_docker_api_version or '1.25'
        if self.docker_api_version < LooseVersion(min_docker_api_version):
            self.fail('Docker API version is %s. Minimum version required is %s.' % (self.docker_api_version_str, min_docker_api_version))

    def log(self, msg, pretty_print=False):
        pass
        # if self.debug:
        #     from .util import log_debug
        #     log_debug(msg, pretty_print=pretty_print)

    @abc.abstractmethod
    def fail(self, msg, **kwargs):
        pass

    def deprecate(self, msg, version=None, date=None, collection_name=None):
        pass

    @staticmethod
    def _get_value(param_name, param_value, env_variable, default_value, type='str'):
        if param_value is not None:
            # take module parameter value
            if type == 'bool':
                if param_value in BOOLEANS_TRUE:
                    return True
                if param_value in BOOLEANS_FALSE:
                    return False
                return bool(param_value)
            if type == 'int':
                return int(param_value)
            return param_value

        if env_variable is not None:
            env_value = os.environ.get(env_variable)
            if env_value is not None:
                # take the env variable value
                if param_name == 'cert_path':
                    return os.path.join(env_value, 'cert.pem')
                if param_name == 'cacert_path':
                    return os.path.join(env_value, 'ca.pem')
                if param_name == 'key_path':
                    return os.path.join(env_value, 'key.pem')
                if type == 'bool':
                    if env_value in BOOLEANS_TRUE:
                        return True
                    if env_value in BOOLEANS_FALSE:
                        return False
                    return bool(env_value)
                if type == 'int':
                    return int(env_value)
                return env_value

        # take the default
        return default_value

    @abc.abstractmethod
    def _get_params(self):
        pass

    @property
    def auth_params(self):
        # Get authentication credentials.
        # Precedence: module parameters-> environment variables-> defaults.

        self.log('Getting credentials')

        client_params = self._get_params()

        params = dict()
        for key in DOCKER_COMMON_ARGS:
            params[key] = client_params.get(key)

        result = dict(
            docker_host=self._get_value('docker_host', params['docker_host'], 'DOCKER_HOST',
                                        DEFAULT_DOCKER_HOST, type='str'),
            tls_hostname=self._get_value('tls_hostname', params['tls_hostname'],
                                         'DOCKER_TLS_HOSTNAME', None, type='str'),
            api_version=self._get_value('api_version', params['api_version'], 'DOCKER_API_VERSION',
                                        'auto', type='str'),
            cacert_path=self._get_value('cacert_path', params['ca_path'], 'DOCKER_CERT_PATH', None, type='str'),
            cert_path=self._get_value('cert_path', params['client_cert'], 'DOCKER_CERT_PATH', None, type='str'),
            key_path=self._get_value('key_path', params['client_key'], 'DOCKER_CERT_PATH', None, type='str'),
            tls=self._get_value('tls', params['tls'], 'DOCKER_TLS', DEFAULT_TLS, type='bool'),
            tls_verify=self._get_value('validate_certs', params['validate_certs'], 'DOCKER_TLS_VERIFY',
                                       DEFAULT_TLS_VERIFY, type='bool'),
            timeout=self._get_value('timeout', params['timeout'], 'DOCKER_TIMEOUT',
                                    DEFAULT_TIMEOUT_SECONDS, type='int'),
            use_ssh_client=self._get_value('use_ssh_client', params['use_ssh_client'], None, False, type='bool'),
        )

        update_tls_hostname(result)

        return result

    def _handle_ssl_error(self, error):
        match = re.match(r"hostname.*doesn\'t match (\'.*\')", str(error))
        if match:
            self.fail("You asked for verification that Docker daemons certificate's hostname matches %s. "
                      "The actual certificate's hostname is %s. Most likely you need to set DOCKER_TLS_HOSTNAME "
                      "or pass `tls_hostname` with a value of %s. You may also use TLS without verification by "
                      "setting the `tls` parameter to true."
                      % (self.auth_params['tls_hostname'], match.group(1), match.group(1)))
        self.fail("SSL Exception: %s" % (error))

    def get_container_by_id(self, container_id):
        try:
            self.log("Inspecting container Id %s" % container_id)
            result = self.inspect_container(container=container_id)
            self.log("Completed container inspection")
            return result
        except NotFound as dummy:
            return None
        except Exception as exc:
            self.fail("Error inspecting container: %s" % exc)

    def get_container(self, name=None):
        '''
        Lookup a container and return the inspection results.
        '''
        if name is None:
            return None

        search_name = name
        if not name.startswith('/'):
            search_name = '/' + name

        result = None
        try:
            for container in self.containers(all=True):
                self.log("testing container: %s" % (container['Names']))
                if isinstance(container['Names'], list) and search_name in container['Names']:
                    result = container
                    break
                if container['Id'].startswith(name):
                    result = container
                    break
                if container['Id'] == name:
                    result = container
                    break
        except SSLError as exc:
            self._handle_ssl_error(exc)
        except Exception as exc:
            self.fail("Error retrieving container list: %s" % exc)

        if result is None:
            return None

        return self.get_container_by_id(result['Id'])

    def get_network(self, name=None, network_id=None):
        '''
        Lookup a network and return the inspection results.
        '''
        if name is None and network_id is None:
            return None

        result = None

        if network_id is None:
            try:
                for network in self.networks():
                    self.log("testing network: %s" % (network['Name']))
                    if name == network['Name']:
                        result = network
                        break
                    if network['Id'].startswith(name):
                        result = network
                        break
            except SSLError as exc:
                self._handle_ssl_error(exc)
            except Exception as exc:
                self.fail("Error retrieving network list: %s" % exc)

        if result is not None:
            network_id = result['Id']

        if network_id is not None:
            try:
                self.log("Inspecting network Id %s" % network_id)
                result = self.inspect_network(network_id)
                self.log("Completed network inspection")
            except NotFound as dummy:
                return None
            except Exception as exc:
                self.fail("Error inspecting network: %s" % exc)

        return result

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
            registry, repo_name = auth.resolve_repository_name(name)
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
            try:
                inspection = self.inspect_image(images[0]['Id'])
            except NotFound:
                self.log("Image %s:%s not found." % (name, tag))
                return None
            except Exception as exc:
                self.fail("Error inspecting image %s:%s - %s" % (name, tag, str(exc)))
            return inspection

        self.log("Image %s:%s not found." % (name, tag))
        return None

    def find_image_by_id(self, image_id, accept_missing_image=False):
        '''
        Lookup an image (by ID) and return the inspection results.
        '''
        if not image_id:
            return None

        self.log("Find image %s (by ID)" % image_id)
        try:
            inspection = self.inspect_image(image_id)
        except NotFound as exc:
            if not accept_missing_image:
                self.fail("Error inspecting image ID %s - %s" % (image_id, str(exc)))
            self.log("Image %s not found." % image_id)
            return None
        except Exception as exc:
            self.fail("Error inspecting image ID %s - %s" % (image_id, str(exc)))
        return inspection

    def _image_lookup(self, name, tag):
        '''
        Including a tag in the name parameter sent to the Docker SDK for Python images method
        does not work consistently. Instead, get the result set for name and manually check
        if the tag exists.
        '''
        try:
            response = self.images(name=name)
        except Exception as exc:
            self.fail("Error searching for image %s - %s" % (name, str(exc)))
        images = response
        if tag:
            lookup = "%s:%s" % (name, tag)
            lookup_digest = "%s@%s" % (name, tag)
            images = []
            for image in response:
                tags = image.get('RepoTags')
                digests = image.get('RepoDigests')
                if (tags and lookup in tags) or (digests and lookup_digest in digests):
                    images = [image]
                    break
        return images

    def pull_image(self, name, tag="latest", platform=None):
        '''
        Pull an image
        '''
        kwargs = dict(
            tag=tag,
            stream=True,
            decode=True,
        )
        if platform is not None:
            kwargs['platform'] = platform
        self.log("Pulling image %s:%s" % (name, tag))
        old_tag = self.find_image(name, tag)
        try:
            for line in self.pull(name, **kwargs):
                self.log(line, pretty_print=True)
                if line.get('error'):
                    if line.get('errorDetail'):
                        error_detail = line.get('errorDetail')
                        self.fail("Error pulling %s - code: %s message: %s" % (name,
                                                                               error_detail.get('code'),
                                                                               error_detail.get('message')))
                    else:
                        self.fail("Error pulling %s - %s" % (name, line.get('error')))
        except Exception as exc:
            self.fail("Error pulling image %s:%s - %s" % (name, tag, str(exc)))

        new_tag = self.find_image(name, tag)

        return new_tag, old_tag == new_tag

    def inspect_distribution(self, image, **kwargs):
        '''
        Get image digest by directly calling the Docker API when running Docker SDK < 4.0.0
        since prior versions did not support accessing private repositories.
        '''
        if self.docker_py_version < LooseVersion('4.0.0'):
            registry = auth.resolve_repository_name(image)[0]
            header = auth.get_config_header(self, registry)
            if header:
                return self._result(self._get(
                    self._url('/distribution/{0}/json', image),
                    headers={'X-Registry-Auth': header}
                ), json=True)
        return super(AnsibleDockerClientBase, self).inspect_distribution(image, **kwargs)


class AnsibleDockerClient(AnsibleDockerClientBase):

    def __init__(self, argument_spec=None, supports_check_mode=False, mutually_exclusive=None,
                 required_together=None, required_if=None, required_one_of=None, required_by=None,
                 min_docker_version=None, min_docker_api_version=None, option_minimal_versions=None,
                 option_minimal_versions_ignore_params=None, fail_results=None):

        # Modules can put information in here which will always be returned
        # in case client.fail() is called.
        self.fail_results = fail_results or {}

        merged_arg_spec = dict()
        merged_arg_spec.update(DOCKER_COMMON_ARGS)
        if argument_spec:
            merged_arg_spec.update(argument_spec)
            self.arg_spec = merged_arg_spec

        mutually_exclusive_params = []
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

        self.debug = self.module.params.get('debug')
        self.check_mode = self.module.check_mode

        super(AnsibleDockerClient, self).__init__(
            min_docker_version=min_docker_version,
            min_docker_api_version=min_docker_api_version)

        if option_minimal_versions is not None:
            self._get_minimal_versions(option_minimal_versions, option_minimal_versions_ignore_params)

    def fail(self, msg, **kwargs):
        self.fail_results.update(kwargs)
        self.module.fail_json(msg=msg, **sanitize_result(self.fail_results))

    def deprecate(self, msg, version=None, date=None, collection_name=None):
        self.module.deprecate(msg, version=version, date=date, collection_name=collection_name)

    def _get_params(self):
        return self.module.params

    def _get_minimal_versions(self, option_minimal_versions, ignore_params=None):
        self.option_minimal_versions = dict()
        for option in self.module.argument_spec:
            if ignore_params is not None:
                if option in ignore_params:
                    continue
            self.option_minimal_versions[option] = dict()
        self.option_minimal_versions.update(option_minimal_versions)

        for option, data in self.option_minimal_versions.items():
            # Test whether option is supported, and store result
            support_docker_py = True
            support_docker_api = True
            if 'docker_py_version' in data:
                support_docker_py = self.docker_py_version >= LooseVersion(data['docker_py_version'])
            if 'docker_api_version' in data:
                support_docker_api = self.docker_api_version >= LooseVersion(data['docker_api_version'])
            data['supported'] = support_docker_py and support_docker_api
            # Fail if option is not supported but used
            if not data['supported']:
                # Test whether option is specified
                if 'detect_usage' in data:
                    used = data['detect_usage'](self)
                else:
                    used = self.module.params.get(option) is not None
                    if used and 'default' in self.module.argument_spec[option]:
                        used = self.module.params[option] != self.module.argument_spec[option]['default']
                if used:
                    # If the option is used, compose error message.
                    if 'usage_msg' in data:
                        usg = data['usage_msg']
                    else:
                        usg = 'set %s option' % (option, )
                    if not support_docker_api:
                        msg = 'Docker API version is %s. Minimum version required is %s to %s.'
                        msg = msg % (self.docker_api_version_str, data['docker_api_version'], usg)
                    elif not support_docker_py:
                        msg = "Docker SDK for Python version is %s (%s's Python %s). Minimum version required is %s to %s. "
                        if LooseVersion(data['docker_py_version']) < LooseVersion('2.0.0'):
                            msg += DOCKERPYUPGRADE_RECOMMEND_DOCKER
                        elif self.docker_py_version < LooseVersion('2.0.0'):
                            msg += DOCKERPYUPGRADE_SWITCH_TO_DOCKER
                        else:
                            msg += DOCKERPYUPGRADE_UPGRADE_DOCKER
                        msg = msg % (docker_version, platform.node(), sys.executable, data['docker_py_version'], usg)
                    else:
                        # should not happen
                        msg = 'Cannot %s with your configuration.' % (usg, )
                    self.fail(msg)

    def report_warnings(self, result, warnings_key=None):
        '''
        Checks result of client operation for warnings, and if present, outputs them.

        warnings_key should be a list of keys used to crawl the result dictionary.
        For example, if warnings_key == ['a', 'b'], the function will consider
        result['a']['b'] if these keys exist. If the result is a non-empty string, it
        will be reported as a warning. If the result is a list, every entry will be
        reported as a warning.

        In most cases (if warnings are returned at all), warnings_key should be
        ['Warnings'] or ['Warning']. The default value (if not specified) is ['Warnings'].
        '''
        if warnings_key is None:
            warnings_key = ['Warnings']
        for key in warnings_key:
            if not isinstance(result, Mapping):
                return
            result = result.get(key)
        if isinstance(result, Sequence):
            for warning in result:
                self.module.warn('Docker warning: {0}'.format(warning))
        elif isinstance(result, string_types) and result:
            self.module.warn('Docker warning: {0}'.format(result))
