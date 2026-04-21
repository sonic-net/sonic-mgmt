# -*- coding: utf-8 -*-
# This code is part of the Ansible collection community.docker, but is an independent component.
# This particular file, and this file only, is based on the Docker SDK for Python (https://github.com/docker/docker-py/)
#
# Copyright (c) 2016-2022 Docker, Inc.
#
# It is licensed under the Apache 2.0 license (see LICENSES/Apache-2.0.txt in this collection)
# SPDX-License-Identifier: Apache-2.0

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import logging
import struct
from functools import partial

from ansible_collections.community.docker.plugins.module_utils._six import PY3, binary_type, iteritems, string_types, raise_from, quote

from .. import auth
from .._import_helper import fail_on_missing_imports
from .._import_helper import HTTPError as _HTTPError
from .._import_helper import InvalidSchema as _InvalidSchema
from .._import_helper import Session as _Session
from ..constants import (DEFAULT_NUM_POOLS, DEFAULT_NUM_POOLS_SSH,
                         DEFAULT_MAX_POOL_SIZE, DEFAULT_TIMEOUT_SECONDS,
                         DEFAULT_USER_AGENT, IS_WINDOWS_PLATFORM,
                         MINIMUM_DOCKER_API_VERSION, STREAM_HEADER_SIZE_BYTES,
                         DEFAULT_DATA_CHUNK_SIZE)
from ..errors import (DockerException, InvalidVersion, TLSParameterError, MissingRequirementException,
                      create_api_error_from_http_exception)
from ..tls import TLSConfig
from ..transport.npipeconn import NpipeHTTPAdapter
from ..transport.npipesocket import PYWIN32_IMPORT_ERROR
from ..transport.unixconn import UnixHTTPAdapter
from ..transport.sshconn import SSHHTTPAdapter, PARAMIKO_IMPORT_ERROR
from ..transport.ssladapter import SSLHTTPAdapter
from ..utils import config, utils, json_stream
from ..utils.decorators import check_resource, update_headers
from ..utils.proxy import ProxyConfig
from ..utils.socket import consume_socket_output, demux_adaptor, frames_iter

from .daemon import DaemonApiMixin


log = logging.getLogger(__name__)


class APIClient(
        _Session,
        DaemonApiMixin):
    """
    A low-level client for the Docker Engine API.

    Example:

        >>> import docker
        >>> client = docker.APIClient(base_url='unix://var/run/docker.sock')
        >>> client.version()
        {u'ApiVersion': u'1.33',
         u'Arch': u'amd64',
         u'BuildTime': u'2017-11-19T18:46:37.000000000+00:00',
         u'GitCommit': u'f4ffd2511c',
         u'GoVersion': u'go1.9.2',
         u'KernelVersion': u'4.14.3-1-ARCH',
         u'MinAPIVersion': u'1.12',
         u'Os': u'linux',
         u'Version': u'17.10.0-ce'}

    Args:
        base_url (str): URL to the Docker server. For example,
            ``unix:///var/run/docker.sock`` or ``tcp://127.0.0.1:1234``.
        version (str): The version of the API to use. Set to ``auto`` to
            automatically detect the server's version. Default: ``1.35``
        timeout (int): Default timeout for API calls, in seconds.
        tls (bool or :py:class:`~docker.tls.TLSConfig`): Enable TLS. Pass
            ``True`` to enable it with default options, or pass a
            :py:class:`~docker.tls.TLSConfig` object to use custom
            configuration.
        user_agent (str): Set a custom user agent for requests to the server.
        credstore_env (dict): Override environment variables when calling the
            credential store process.
        use_ssh_client (bool): If set to `True`, an ssh connection is made
            via shelling out to the ssh client. Ensure the ssh client is
            installed and configured on the host.
        max_pool_size (int): The maximum number of connections
            to save in the pool.
    """

    __attrs__ = _Session.__attrs__ + ['_auth_configs',
                                      '_general_configs',
                                      '_version',
                                      'base_url',
                                      'timeout']

    def __init__(self, base_url=None, version=None,
                 timeout=DEFAULT_TIMEOUT_SECONDS, tls=False,
                 user_agent=DEFAULT_USER_AGENT, num_pools=None,
                 credstore_env=None, use_ssh_client=False,
                 max_pool_size=DEFAULT_MAX_POOL_SIZE):
        super(APIClient, self).__init__()

        fail_on_missing_imports()

        if tls and not base_url:
            raise TLSParameterError(
                'If using TLS, the base_url argument must be provided.'
            )

        self.base_url = base_url
        self.timeout = timeout
        self.headers['User-Agent'] = user_agent

        self._general_configs = config.load_general_config()

        proxy_config = self._general_configs.get('proxies', {})
        try:
            proxies = proxy_config[base_url]
        except KeyError:
            proxies = proxy_config.get('default', {})

        self._proxy_configs = ProxyConfig.from_dict(proxies)

        self._auth_configs = auth.load_config(
            config_dict=self._general_configs, credstore_env=credstore_env,
        )
        self.credstore_env = credstore_env

        base_url = utils.parse_host(
            base_url, IS_WINDOWS_PLATFORM, tls=bool(tls)
        )
        # SSH has a different default for num_pools to all other adapters
        num_pools = num_pools or DEFAULT_NUM_POOLS_SSH if \
            base_url.startswith('ssh://') else DEFAULT_NUM_POOLS

        if base_url.startswith('http+unix://'):
            self._custom_adapter = UnixHTTPAdapter(
                base_url, timeout, pool_connections=num_pools,
                max_pool_size=max_pool_size
            )
            self.mount('http+docker://', self._custom_adapter)
            self._unmount('http://', 'https://')
            # host part of URL should be unused, but is resolved by requests
            # module in proxy_bypass_macosx_sysconf()
            self.base_url = 'http+docker://localhost'
        elif base_url.startswith('npipe://'):
            if not IS_WINDOWS_PLATFORM:
                raise DockerException(
                    'The npipe:// protocol is only supported on Windows'
                )
            if PYWIN32_IMPORT_ERROR is not None:
                raise MissingRequirementException(
                    'Install pypiwin32 package to enable npipe:// support',
                    'pywin32',
                    PYWIN32_IMPORT_ERROR)
            self._custom_adapter = NpipeHTTPAdapter(
                base_url, timeout, pool_connections=num_pools,
                max_pool_size=max_pool_size
            )
            self.mount('http+docker://', self._custom_adapter)
            self.base_url = 'http+docker://localnpipe'
        elif base_url.startswith('ssh://'):
            if PARAMIKO_IMPORT_ERROR is not None and not use_ssh_client:
                raise MissingRequirementException(
                    'Install paramiko package to enable ssh:// support',
                    'paramiko',
                    PARAMIKO_IMPORT_ERROR)
            self._custom_adapter = SSHHTTPAdapter(
                base_url, timeout, pool_connections=num_pools,
                max_pool_size=max_pool_size, shell_out=use_ssh_client
            )
            self.mount('http+docker://ssh', self._custom_adapter)
            self._unmount('http://', 'https://')
            self.base_url = 'http+docker://ssh'
        else:
            # Use SSLAdapter for the ability to specify SSL version
            if isinstance(tls, TLSConfig):
                tls.configure_client(self)
            elif tls:
                self._custom_adapter = SSLHTTPAdapter(
                    pool_connections=num_pools)
                self.mount('https://', self._custom_adapter)
            self.base_url = base_url

        # version detection needs to be after unix adapter mounting
        if version is None or (isinstance(version, string_types) and version.lower() == 'auto'):
            self._version = self._retrieve_server_version()
        else:
            self._version = version
        if not isinstance(self._version, string_types):
            raise DockerException(
                'Version parameter must be a string or None. Found {0}'.format(
                    type(version).__name__
                )
            )
        if utils.version_lt(self._version, MINIMUM_DOCKER_API_VERSION):
            raise InvalidVersion(
                'API versions below {0} are no longer supported by this '
                'library.'.format(MINIMUM_DOCKER_API_VERSION)
            )

    def _retrieve_server_version(self):
        try:
            version_result = self.version(api_version=False)
        except Exception as e:
            raise DockerException(
                'Error while fetching server API version: {0}'.format(e)
            )

        try:
            return version_result["ApiVersion"]
        except KeyError:
            raise DockerException(
                'Invalid response from docker daemon: key "ApiVersion"'
                ' is missing.'
            )
        except Exception as e:
            raise DockerException(
                'Error while fetching server API version: {0}. Response seems to be broken.'.format(e)
            )

    def _set_request_timeout(self, kwargs):
        """Prepare the kwargs for an HTTP request by inserting the timeout
        parameter, if not already present."""
        kwargs.setdefault('timeout', self.timeout)
        return kwargs

    @update_headers
    def _post(self, url, **kwargs):
        return self.post(url, **self._set_request_timeout(kwargs))

    @update_headers
    def _get(self, url, **kwargs):
        return self.get(url, **self._set_request_timeout(kwargs))

    @update_headers
    def _head(self, url, **kwargs):
        return self.head(url, **self._set_request_timeout(kwargs))

    @update_headers
    def _put(self, url, **kwargs):
        return self.put(url, **self._set_request_timeout(kwargs))

    @update_headers
    def _delete(self, url, **kwargs):
        return self.delete(url, **self._set_request_timeout(kwargs))

    def _url(self, pathfmt, *args, **kwargs):
        for arg in args:
            if not isinstance(arg, string_types):
                raise ValueError(
                    'Expected a string but found {0} ({1}) '
                    'instead'.format(arg, type(arg))
                )

        quote_f = partial(quote, safe="/:")
        args = map(quote_f, args)

        if kwargs.get('versioned_api', True):
            return '{0}/v{1}{2}'.format(
                self.base_url, self._version, pathfmt.format(*args)
            )
        else:
            return '{0}{1}'.format(self.base_url, pathfmt.format(*args))

    def _raise_for_status(self, response):
        """Raises stored :class:`APIError`, if one occurred."""
        try:
            response.raise_for_status()
        except _HTTPError as e:
            raise_from(create_api_error_from_http_exception(e), e)

    def _result(self, response, json=False, binary=False):
        if json and binary:
            raise AssertionError('json and binary must not be both True')
        self._raise_for_status(response)

        if json:
            return response.json()
        if binary:
            return response.content
        return response.text

    def _post_json(self, url, data, **kwargs):
        # Go <1.1 cannot unserialize null to a string
        # so we do this disgusting thing here.
        data2 = {}
        if data is not None and isinstance(data, dict):
            for k, v in iteritems(data):
                if v is not None:
                    data2[k] = v
        elif data is not None:
            data2 = data

        if 'headers' not in kwargs:
            kwargs['headers'] = {}
        kwargs['headers']['Content-Type'] = 'application/json'
        return self._post(url, data=json.dumps(data2), **kwargs)

    def _attach_params(self, override=None):
        return override or {
            'stdout': 1,
            'stderr': 1,
            'stream': 1
        }

    def _get_raw_response_socket(self, response):
        self._raise_for_status(response)
        if self.base_url == "http+docker://localnpipe":
            sock = response.raw._fp.fp.raw.sock
        elif self.base_url.startswith('http+docker://ssh'):
            sock = response.raw._fp.fp.channel
        elif PY3:
            sock = response.raw._fp.fp.raw
            if self.base_url.startswith("https://"):
                sock = sock._sock
        else:
            sock = response.raw._fp.fp._sock
        try:
            # Keep a reference to the response to stop it being garbage
            # collected. If the response is garbage collected, it will
            # close TLS sockets.
            sock._response = response
        except AttributeError:
            # UNIX sockets cannot have attributes set on them, but that's
            # fine because we will not be doing TLS over them
            pass

        return sock

    def _stream_helper(self, response, decode=False):
        """Generator for data coming from a chunked-encoded HTTP response."""

        if response.raw._fp.chunked:
            if decode:
                for chunk in json_stream.json_stream(self._stream_helper(response, False)):
                    yield chunk
            else:
                reader = response.raw
                while not reader.closed:
                    # this read call will block until we get a chunk
                    data = reader.read(1)
                    if not data:
                        break
                    if reader._fp.chunk_left:
                        data += reader.read(reader._fp.chunk_left)
                    yield data
        else:
            # Response is not chunked, meaning we probably
            # encountered an error immediately
            yield self._result(response, json=decode)

    def _multiplexed_buffer_helper(self, response):
        """A generator of multiplexed data blocks read from a buffered
        response."""
        buf = self._result(response, binary=True)
        buf_length = len(buf)
        walker = 0
        while True:
            if buf_length - walker < STREAM_HEADER_SIZE_BYTES:
                break
            header = buf[walker:walker + STREAM_HEADER_SIZE_BYTES]
            dummy, length = struct.unpack_from('>BxxxL', header)
            start = walker + STREAM_HEADER_SIZE_BYTES
            end = start + length
            walker = end
            yield buf[start:end]

    def _multiplexed_response_stream_helper(self, response):
        """A generator of multiplexed data blocks coming from a response
        stream."""

        # Disable timeout on the underlying socket to prevent
        # Read timed out(s) for long running processes
        socket = self._get_raw_response_socket(response)
        self._disable_socket_timeout(socket)

        while True:
            header = response.raw.read(STREAM_HEADER_SIZE_BYTES)
            if not header:
                break
            dummy, length = struct.unpack('>BxxxL', header)
            if not length:
                continue
            data = response.raw.read(length)
            if not data:
                break
            yield data

    def _stream_raw_result(self, response, chunk_size=1, decode=True):
        ''' Stream result for TTY-enabled container and raw binary data'''
        self._raise_for_status(response)

        # Disable timeout on the underlying socket to prevent
        # Read timed out(s) for long running processes
        socket = self._get_raw_response_socket(response)
        self._disable_socket_timeout(socket)

        for out in response.iter_content(chunk_size, decode):
            yield out

    def _read_from_socket(self, response, stream, tty=True, demux=False):
        """Consume all data from the socket, close the response and return the
        data. If stream=True, then a generator is returned instead and the
        caller is responsible for closing the response.
        """
        socket = self._get_raw_response_socket(response)

        gen = frames_iter(socket, tty)

        if demux:
            # The generator will output tuples (stdout, stderr)
            gen = (demux_adaptor(*frame) for frame in gen)
        else:
            # The generator will output strings
            gen = (data for (dummy, data) in gen)

        if stream:
            return gen
        else:
            try:
                # Wait for all the frames, concatenate them, and return the result
                return consume_socket_output(gen, demux=demux)
            finally:
                response.close()

    def _disable_socket_timeout(self, socket):
        """ Depending on the combination of python version and whether we are
        connecting over http or https, we might need to access _sock, which
        may or may not exist; or we may need to just settimeout on socket
        itself, which also may or may not have settimeout on it. To avoid
        missing the correct one, we try both.

        We also do not want to set the timeout if it is already disabled, as
        you run the risk of changing a socket that was non-blocking to
        blocking, for example when using gevent.
        """
        sockets = [socket, getattr(socket, '_sock', None)]

        for s in sockets:
            if not hasattr(s, 'settimeout'):
                continue

            timeout = -1

            if hasattr(s, 'gettimeout'):
                timeout = s.gettimeout()

            # Do not change the timeout if it is already disabled.
            if timeout is None or timeout == 0.0:
                continue

            s.settimeout(None)

    @check_resource('container')
    def _check_is_tty(self, container):
        cont = self.inspect_container(container)
        return cont['Config']['Tty']

    def _get_result(self, container, stream, res):
        return self._get_result_tty(stream, res, self._check_is_tty(container))

    def _get_result_tty(self, stream, res, is_tty):
        # We should also use raw streaming (without keep-alive)
        # if we are dealing with a tty-enabled container.
        if is_tty:
            return self._stream_raw_result(res) if stream else \
                self._result(res, binary=True)

        self._raise_for_status(res)
        sep = binary_type()
        if stream:
            return self._multiplexed_response_stream_helper(res)
        else:
            return sep.join(
                list(self._multiplexed_buffer_helper(res))
            )

    def _unmount(self, *args):
        for proto in args:
            self.adapters.pop(proto)

    def get_adapter(self, url):
        try:
            return super(APIClient, self).get_adapter(url)
        except _InvalidSchema as e:
            if self._custom_adapter:
                return self._custom_adapter
            else:
                raise e

    @property
    def api_version(self):
        return self._version

    def reload_config(self, dockercfg_path=None):
        """
        Force a reload of the auth configuration

        Args:
            dockercfg_path (str): Use a custom path for the Docker config file
                (default ``$HOME/.docker/config.json`` if present,
                otherwise ``$HOME/.dockercfg``)

        Returns:
            None
        """
        self._auth_configs = auth.load_config(
            dockercfg_path, credstore_env=self.credstore_env
        )

    def _set_auth_headers(self, headers):
        log.debug('Looking for auth config')

        # If we do not have any auth data so far, try reloading the config
        # file one more time in case anything showed up in there.
        if not self._auth_configs or self._auth_configs.is_empty:
            log.debug("No auth config in memory - loading from filesystem")
            self._auth_configs = auth.load_config(
                credstore_env=self.credstore_env
            )

        # Send the full auth configuration (if any exists), since the build
        # could use any (or all) of the registries.
        if self._auth_configs:
            auth_data = self._auth_configs.get_all_credentials()

            # See https://github.com/docker/docker-py/issues/1683
            if (auth.INDEX_URL not in auth_data and
                    auth.INDEX_NAME in auth_data):
                auth_data[auth.INDEX_URL] = auth_data.get(auth.INDEX_NAME, {})

            log.debug(
                'Sending auth config (%s)',
                ', '.join(repr(k) for k in auth_data.keys())
            )

            if auth_data:
                headers['X-Registry-Config'] = auth.encode_header(
                    auth_data
                )
        else:
            log.debug('No auth config found')

    def get_binary(self, pathfmt, *args, **kwargs):
        return self._result(self._get(self._url(pathfmt, *args, versioned_api=True), **kwargs), binary=True)

    def get_json(self, pathfmt, *args, **kwargs):
        return self._result(self._get(self._url(pathfmt, *args, versioned_api=True), **kwargs), json=True)

    def get_text(self, pathfmt, *args, **kwargs):
        return self._result(self._get(self._url(pathfmt, *args, versioned_api=True), **kwargs))

    def get_raw_stream(self, pathfmt, *args, **kwargs):
        chunk_size = kwargs.pop('chunk_size', DEFAULT_DATA_CHUNK_SIZE)
        res = self._get(self._url(pathfmt, *args, versioned_api=True), stream=True, **kwargs)
        self._raise_for_status(res)
        return self._stream_raw_result(res, chunk_size, False)

    def delete_call(self, pathfmt, *args, **kwargs):
        self._raise_for_status(self._delete(self._url(pathfmt, *args, versioned_api=True), **kwargs))

    def delete_json(self, pathfmt, *args, **kwargs):
        return self._result(self._delete(self._url(pathfmt, *args, versioned_api=True), **kwargs), json=True)

    def post_call(self, pathfmt, *args, **kwargs):
        self._raise_for_status(self._post(self._url(pathfmt, *args, versioned_api=True), **kwargs))

    def post_json(self, pathfmt, *args, **kwargs):
        data = kwargs.pop('data', None)
        self._raise_for_status(self._post_json(self._url(pathfmt, *args, versioned_api=True), data, **kwargs))

    def post_json_to_binary(self, pathfmt, *args, **kwargs):
        data = kwargs.pop('data', None)
        return self._result(self._post_json(self._url(pathfmt, *args, versioned_api=True), data, **kwargs), binary=True)

    def post_json_to_json(self, pathfmt, *args, **kwargs):
        data = kwargs.pop('data', None)
        return self._result(self._post_json(self._url(pathfmt, *args, versioned_api=True), data, **kwargs), json=True)

    def post_json_to_text(self, pathfmt, *args, **kwargs):
        data = kwargs.pop('data', None)
        return self._result(self._post_json(self._url(pathfmt, *args, versioned_api=True), data, **kwargs))

    def post_json_to_stream_socket(self, pathfmt, *args, **kwargs):
        data = kwargs.pop('data', None)
        headers = (kwargs.pop('headers', None) or {}).copy()
        headers.update({
            'Connection': 'Upgrade',
            'Upgrade': 'tcp',
        })
        return self._get_raw_response_socket(
            self._post_json(self._url(pathfmt, *args, versioned_api=True), data, headers=headers, stream=True, **kwargs))

    def post_json_to_stream(self, pathfmt, *args, **kwargs):
        data = kwargs.pop('data', None)
        headers = (kwargs.pop('headers', None) or {}).copy()
        headers.update({
            'Connection': 'Upgrade',
            'Upgrade': 'tcp',
        })
        stream = kwargs.pop('stream', False)
        demux = kwargs.pop('demux', False)
        tty = kwargs.pop('tty', False)
        return self._read_from_socket(
            self._post_json(self._url(pathfmt, *args, versioned_api=True), data, headers=headers, stream=True, **kwargs),
            stream,
            tty=tty,
            demux=demux
        )

    def post_to_json(self, pathfmt, *args, **kwargs):
        return self._result(self._post(self._url(pathfmt, *args, versioned_api=True), **kwargs), json=True)
