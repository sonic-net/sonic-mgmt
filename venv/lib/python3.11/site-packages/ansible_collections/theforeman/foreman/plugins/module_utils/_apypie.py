# pylint: disable=ansible-format-automatic-specification,raise-missing-from
from __future__ import absolute_import, division, print_function
__metaclass__ = type
from typing import Any, Iterable, List, Optional, Set, Tuple, cast  # pylint: disable=unused-import  # noqa: F401


"""
Apypie Action module
"""


class Action(object):
    """
    Apipie Action
    """

    def __init__(self, name, resource, api):
        # type: (str, str, Api) -> None
        self.name = name
        self.resource = resource
        self.api = api

    @property
    def apidoc(self):
        # type: () -> dict
        """
        The apidoc of this action.

        :returns: The apidoc.
        """

        resource_methods = self.api.apidoc['docs']['resources'][self.resource]['methods']
        return [method for method in resource_methods if method['name'] == self.name][0]

    @property
    def routes(self):
        # type: () -> List[Route]
        """
        The routes this action can be invoked by.

        :returns: The routes
        """

        return [Route(route['api_url'], route['http_method'], route['short_description']) for route in self.apidoc['apis']]

    @property
    def params(self):
        # type: () -> List[Param]
        """
        The params accepted by this action.

        :returns: The params.
        """

        return [Param(**param) for param in self.apidoc['params']]

    @property
    def examples(self):
        # type: () -> List[Example]
        """
        The examples of this action.

        :returns: The examples.
        """

        return [Example.parse(example) for example in self.apidoc['examples']]

    def call(self, params=None, headers=None, options=None, data=None, files=None):  # pylint: disable=too-many-arguments
        # type: (Optional[dict], Optional[dict], Optional[dict], Optional[Any], Optional[dict]) -> Optional[dict]
        """
        Call the API to execute the action.

        :param params: The params that should be passed to the API.
        :param headers: Additional headers to be passed to the API.
        :param options: Options
        :param data: Binary data to be submitted to the API.
        :param files: Files to be submitted to the API.

        :returns: The API response.
        """

        return self.api.call(self.resource, self.name, params, headers, options, data, files)

    def find_route(self, params=None):
        # type: (Optional[dict]) -> Route
        """
        Find the best matching route for a given set of params.

        :param params: Params that should be submitted to the API.

        :returns: The best route.
        """

        param_keys = set(self.filter_empty_params(params).keys())
        sorted_routes = sorted(self.routes, key=lambda route: [-1 * len(route.params_in_path), route.path])
        for route in sorted_routes:
            if set(route.params_in_path) <= param_keys:
                return route
        return sorted_routes[-1]

    def validate(self, values, data=None, files=None):
        # type: (dict, Optional[Any], Optional[dict]) -> None
        """
        Validate a given set of parameter values against the required set of parameters.

        :param values: The values to validate.
        :param data: Additional binary data to validate.
        :param files: Additional files to validate.
        """

        self._validate(self.params, values, data, files)

    @staticmethod
    def _add_to_path(path=None, additions=None):
        # type: (Optional[str], Optional[List[str]]) -> str
        if path is None:
            path = ''
        if additions is None:
            additions = []
        for addition in additions:
            if path == '':
                path = "{}".format(addition)
            else:
                path = "{}[{}]".format(path, addition)
        return path

    def _validate(self, params, values, data=None, files=None, path=None):  # pylint: disable=too-many-arguments,too-many-locals
        # type: (Iterable[Param], dict, Optional[Any], Optional[dict], Optional[str]) -> None
        if not isinstance(values, dict):
            raise InvalidArgumentTypesError
        given_params = set(values.keys())
        given_files = set((files or {}).keys())
        given_data = set((data or {}).keys())
        required_params = {param.name for param in params if param.required}
        missing_params = required_params - given_params - given_files - given_data
        if missing_params:
            missing_params_with_path = [self._add_to_path(path, [param]) for param in missing_params]
            message = "The following required parameters are missing: {}".format(', '.join(missing_params_with_path))
            raise MissingArgumentsError(message)

        for param, value in values.items():
            param_descriptions = [p for p in params if p.name == param]
            if param_descriptions:
                param_description = param_descriptions[0]
                if param_description.params and value is not None:
                    if param_description.expected_type == 'array':
                        for num, item in enumerate(value):
                            self._validate(param_description.params, item, path=self._add_to_path(path, [param_description.name, str(num)]))
                    elif param_description.expected_type == 'hash':
                        self._validate(param_description.params, value, path=self._add_to_path(path, [param_description.name]))
                if (param_description.expected_type == 'numeric' and isinstance(value, str)):
                    try:
                        value = int(value)
                    except ValueError:
                        # this will be caught in the next check
                        pass
                if (not param_description.allow_nil and value is None):
                    raise ValueError("{} can't be {}".format(param, value))
                # pylint: disable=too-many-boolean-expressions
                if (value is not None
                        and ((param_description.expected_type == 'boolean' and not isinstance(value, bool) and not (isinstance(value, int) and value in [0, 1]))
                             or (param_description.expected_type == 'numeric' and not isinstance(value, int))
                             or (param_description.expected_type == 'string' and not isinstance(value, (str, int))))):
                    raise ValueError("{} ({}): {}".format(param, value, param_description.validator))

    @staticmethod
    def filter_empty_params(params=None):
        # type: (Optional[dict]) -> dict
        """
        Filter out any params that have no value.

        :param params: The params to filter.

        :returns: The filtered params.
        """
        result = {}
        if params is not None:
            if isinstance(params, dict):
                result = {k: v for k, v in params.items() if v is not None}
            else:
                raise InvalidArgumentTypesError
        return result

    def prepare_params(self, input_dict):
        # type: (dict) -> dict
        """
        Transform a dict with data into one that can be accepted as params for calling the action.

        This will ignore any keys that are not accepted as params when calling the action.
        It also allows generating nested params without forcing the user to care about them.

        :param input_dict: a dict with data that should be used to fill in the params
        :return: :class:`dict` object
        :rtype: dict

        Usage::

            >>> action.prepare_params({'id': 1})
            {'user': {'id': 1}}
        """
        params = self._prepare_params(self.params, input_dict)
        route_params = self._prepare_route_params(input_dict)
        params.update(route_params)
        return params

    def _prepare_params(self, action_params, input_dict):
        # type: (Iterable[Param], dict) -> dict
        result = {}

        for param in action_params:
            if param.expected_type == 'hash' and param.params:
                nested_dict = input_dict.get(param.name, input_dict)
                nested_result = self._prepare_params(param.params, nested_dict)
                if nested_result:
                    result[param.name] = nested_result
            elif param.name in input_dict:
                result[param.name] = input_dict[param.name]

        return result

    def _prepare_route_params(self, input_dict):
        # type: (dict) -> dict
        result = {}

        route = self.find_route(input_dict)

        for url_param in route.params_in_path:
            if url_param in input_dict:
                result[url_param] = input_dict[url_param]

        return result


"""
Apypie Api module
"""


import errno
import glob
import json
from json.decoder import JSONDecodeError  # type: ignore

import os
from urllib.parse import urljoin  # type: ignore
try:
    import requests
except ImportError:
    pass

try:
    from requests_gssapi import HTTPKerberosAuth  # type: ignore
except ImportError:
    try:
        from requests_kerberos import HTTPKerberosAuth  # type: ignore
    except ImportError:
        HTTPKerberosAuth = None

NO_CONTENT = 204


def _qs_param(param):
    # type: (Any) -> Any
    if isinstance(param, bool):
        return str(param).lower()
    return param


class Api(object):
    """
    Apipie API bindings

    :param uri: base URL of the server
    :param username: username to access the API
    :param password: password to access the API
    :param client_cert: client cert to access the API
    :param client_key: client key to access the API
    :param kerberos: use Kerberos/GSSAPI for authentication with the API. Requires either `requests-gssapi` or `requests-kerberos`.
    :param api_version: version of the API. Defaults to `1`
    :param language: prefered locale for the API description
    :param apidoc_cache_base_dir: base directory for building apidoc_cache_dir. Defaults to `~/.cache/apipie_bindings`.
    :param apidoc_cache_dir: where to cache the JSON description of the API. Defaults to `apidoc_cache_base_dir/<URI>`.
    :param apidoc_cache_name: name of the cache file. If there is cache in the `apidoc_cache_dir`, it is used. Defaults to `default`.
    :param verify_ssl: should the SSL certificate be verified. Defaults to `True`.
    :param session: a `requests.Session` compatible object. Defaults to `requests.Session()`.

    Usage::

      >>> import apypie
      >>> api = apypie.Api(uri='https://api.example.com', username='admin', password='changeme')
    """

    def __init__(self, **kwargs):
        self.uri = kwargs.get('uri')
        self.api_version = kwargs.get('api_version', 1)
        self.language = kwargs.get('language')

        # Find where to put the cache by default according to the XDG spec
        # Not using just get('XDG_CACHE_HOME', '~/.cache') because the spec says
        # that the defaut should be used if "$XDG_CACHE_HOME is either not set or empty"
        xdg_cache_home = os.environ.get('XDG_CACHE_HOME', None)
        if not xdg_cache_home:
            xdg_cache_home = '~/.cache'

        apidoc_cache_base_dir = kwargs.get('apidoc_cache_base_dir', os.path.join(os.path.expanduser(xdg_cache_home), 'apypie'))
        apidoc_cache_dir_default = os.path.join(apidoc_cache_base_dir, self.uri.replace(':', '_').replace('/', '_'), 'v{}'.format(self.api_version))
        self.apidoc_cache_dir = kwargs.get('apidoc_cache_dir', apidoc_cache_dir_default)
        self.apidoc_cache_name = kwargs.get('apidoc_cache_name', self._find_cache_name())

        self._session = kwargs.get('session') or requests.Session()
        self._session.verify = kwargs.get('verify_ssl', True)

        self._session.headers['Accept'] = 'application/json;version={}'.format(self.api_version)
        self._session.headers['User-Agent'] = 'apypie (https://github.com/Apipie/apypie)'
        if self.language:
            self._session.headers['Accept-Language'] = self.language

        if kwargs.get('username') and kwargs.get('password'):
            self._session.auth = (kwargs['username'], kwargs['password'])

        if kwargs.get('client_cert') and kwargs.get('client_key'):
            self._session.cert = (kwargs['client_cert'], kwargs['client_key'])

        if kwargs.get('kerberos'):
            if HTTPKerberosAuth is not None:
                self._session.auth = HTTPKerberosAuth()
            else:
                raise ValueError('Kerberos authentication requested, but neither requests-gssapi nor requests-kerberos found.')

        self._apidoc = None

    @property
    def apidoc(self):
        # type: () -> dict
        """
        The full apidoc.

        The apidoc will be fetched from the server, if that didn't happen yet.

        :returns: The apidoc.
        """

        if self._apidoc is None:
            self._apidoc = self._load_apidoc()
        return self._apidoc

    @property
    def apidoc_cache_file(self):
        # type: () -> str
        """
        Full local path to the cached apidoc.
        """

        return os.path.join(self.apidoc_cache_dir, '{0}{1}'.format(self.apidoc_cache_name, self.cache_extension))

    def _cache_dir_contents(self):
        # type: () -> Iterable[str]
        return glob.iglob(os.path.join(self.apidoc_cache_dir, '*{}'.format(self.cache_extension)))

    def _find_cache_name(self, default='default'):
        cache_file = next(self._cache_dir_contents(), None)
        cache_name = default
        if cache_file:
            cache_name = os.path.basename(cache_file)[:-len(self.cache_extension)]
        return cache_name

    def validate_cache(self, cache_name=None):
        # type: (Optional[str]) -> None
        """
        Ensure the cached apidoc matches the one presented by the server.

        :param cache_name: The name of the apidoc on the server.
        """

        if cache_name is not None and cache_name != self.apidoc_cache_name:
            self.clean_cache()
            self.apidoc_cache_name = os.path.basename(os.path.normpath(cache_name))

    def clean_cache(self):
        # type: () -> None
        """
        Remove any locally cached apidocs.
        """

        self._apidoc = None
        for filename in self._cache_dir_contents():
            os.unlink(filename)

    @property
    def resources(self):
        # type: () -> Iterable
        """
        List of available resources.

        Usage::

            >>> api.resources
            ['comments', 'users']
        """
        return sorted(self.apidoc['docs']['resources'].keys())

    def resource(self, name):
        # type: (str) -> Resource
        """
        Get a resource.

        :param name: the name of the resource to load
        :return: :class:`Resource <Resource>` object
        :rtype: apypie.Resource

        Usage::

            >>> api.resource('users')
        """
        if name in self.resources:
            return Resource(self, name)
        message = "Resource '{}' does not exist in the API. Existing resources: {}".format(name, ', '.join(sorted(self.resources)))
        raise KeyError(message)

    def _load_apidoc(self):
        # type: () -> dict
        try:
            with open(self.apidoc_cache_file, 'r') as apidoc_file:  # pylint:disable=all
                api_doc = json.load(apidoc_file)
        except (IOError, JSONDecodeError):
            api_doc = self._retrieve_apidoc()
        return api_doc

    def _retrieve_apidoc(self):
        # type: () -> dict
        try:
            os.makedirs(self.apidoc_cache_dir)
        except OSError as err:
            if err.errno != errno.EEXIST or not os.path.isdir(self.apidoc_cache_dir):
                raise
        response = None
        if self.language:
            response = self._retrieve_apidoc_call('/apidoc/v{0}.{1}.json'.format(self.api_version, self.language), safe=True)
            language_family = self.language.split('_')[0]
            if not response and language_family != self.language:
                response = self._retrieve_apidoc_call('/apidoc/v{0}.{1}.json'.format(self.api_version, language_family), safe=True)
        if not response:
            try:
                response = self._retrieve_apidoc_call('/apidoc/v{}.json'.format(self.api_version))
            except Exception as exc:
                raise DocLoadingError("""Could not load data from {0}: {1}
                  - is your server down?""".format(self.uri, exc))
        if not response:
            raise DocLoadingError("""Could not load data from {0}""".format(self.uri))
        with open(self.apidoc_cache_file, 'w') as apidoc_file:  # pylint:disable=all
            apidoc_file.write(json.dumps(response))
        return response

    def _retrieve_apidoc_call(self, path, safe=False):
        # type: (str, bool) -> Optional[dict]
        try:
            return self.http_call('get', path)
        except Exception:
            if not safe:
                raise
            return None

    def call(self, resource_name, action_name, params=None, headers=None, options=None, data=None, files=None):  # pylint: disable=too-many-arguments
        # type: (str, str, Optional[dict], Optional[dict], Optional[dict], Optional[dict], Optional[dict]) -> Optional[dict]
        """
        Call an action in the API.

        It finds most fitting route based on given parameters
        with other attributes necessary to do an API call.

        :param resource_name: name of the resource
        :param action_name: action_name name of the action
        :param params: Dict of parameters to be sent in the request
        :param headers: Dict of headers to be sent in the request
        :param options: Dict of options to influence the how the call is processed
           * `skip_validation` (Bool) *false* - skip validation of parameters
        :param data: Binary data to be sent in the request
        :param files: Binary files to be sent in the request
        :return: :class:`dict` object
        :rtype: dict

        Usage::

            >>> api.call('users', 'show', {'id': 1})
        """
        if options is None:
            options = {}
        if params is None:
            params = {}

        resource = Resource(self, resource_name)
        action = resource.action(action_name)
        if not options.get('skip_validation', False):
            action.validate(params, data, files)

        return self._call_action(action, params, headers, data, files)

    def _call_action(self, action, params=None, headers=None, data=None, files=None):  # pylint: disable=too-many-arguments
        # type: (Action, Optional[dict], Optional[dict], Optional[dict], Optional[dict]) -> Optional[dict]
        if params is None:
            params = {}

        route = action.find_route(params)
        get_params = {key: value for key, value in params.items() if key not in route.params_in_path}
        return self.http_call(
            route.method,
            route.path_with_params(params),
            get_params,
            headers, data, files)

    def http_call(self, http_method, path, params=None, headers=None, data=None, files=None):  # pylint: disable=too-many-arguments
        # type: (str, str, Optional[dict], Optional[dict], Optional[dict], Optional[dict]) -> Optional[dict]
        """
        Execute an HTTP request.

        :param params: Dict of parameters to be sent in the request
        :param headers: Dict of headers to be sent in the request
        :param data: Binary data to be sent in the request
        :param files: Binary files to be sent in the request

        :return: :class:`dict` object
        :rtype: dict
        """

        full_path = urljoin(self.uri, path)
        kwargs = {
            'verify': self._session.verify,
        }

        if headers:
            kwargs['headers'] = headers

        if params:
            if http_method in ['get', 'head']:
                kwargs['params'] = {k: _qs_param(v) for k, v in params.items()}
            else:
                kwargs['json'] = params
        elif http_method in ['post', 'put', 'patch'] and not data and not files:
            kwargs['json'] = {}

        if files:
            kwargs['files'] = files

        if data:
            kwargs['data'] = data

        request = self._session.request(http_method, full_path, **kwargs)
        request.raise_for_status()
        self.validate_cache(request.headers.get('apipie-checksum'))
        if request.status_code == NO_CONTENT:
            return None
        return request.json()

    @property
    def cache_extension(self):
        # type: () -> str
        """
        File extension for the local cache file.

        Will include the language if set.
        """

        if self.language:
            ext = '.{}.json'.format(self.language)
        else:
            ext = '.json'
        return ext


"""
Apypie Example module
"""


import re

EXAMPLE_PARSER = re.compile(r'(\w+)\s+([^\n]*)\n?(.*)\n(\d+)\n(.*)', re.DOTALL)


class Example(object):  # pylint: disable=too-few-public-methods
    """
    Apipie Example
    """

    def __init__(self, http_method, path, args, status, response):  # pylint: disable=too-many-arguments
        # type: (str, str, str, str, str) -> None
        self.http_method = http_method
        self.path = path
        self.args = args
        self.status = int(status)
        self.response = response

    @classmethod
    def parse(cls, example):
        """
        Parse an example from an apidoc string

        :returns: The parsed :class:`Example`
        """
        parsed = EXAMPLE_PARSER.match(example)
        return cls(*parsed.groups())


"""
Apypie Exceptions
"""


class DocLoadingError(Exception):
    """
    Exception to be raised when apidoc could not be loaded.
    """


class MissingArgumentsError(Exception):
    """
    Exception to be raised when required arguments are missing.
    """


class InvalidArgumentTypesError(Exception):
    """
    Exception to be raised when arguments are of the wrong type.
    """


"""
Apypie Foreman module

opinionated helpers to use Apypie with Foreman
"""

import time

# Foreman supports "per_page=all" since 2.2 (https://projects.theforeman.org/issues/29909)
# But plugins, especially Katello, do not: https://github.com/Katello/katello/pull/11126
# To still be able to fetch all results without pagination, we have this constant for now
PER_PAGE = 2 << 31


class ForemanApiException(Exception):
    """
    General Exception, raised by any issue in ForemanApi
    """

    def __init__(self, msg, error=None):
        if error:
            super().__init__(f'{msg} - {error}')
        else:
            super().__init__(msg)

    @classmethod
    def from_exception(cls, exc, msg):
        """
        Create a ForemanException from any other Exception

        Especially useful to gather the error message from HTTP responses.
        """
        error = None
        if hasattr(exc, 'response') and exc.response is not None:
            try:
                response = exc.response.json()
                if 'error' in response:
                    error = response['error']
                else:
                    error = response
            except Exception:  # pylint: disable=broad-except
                error = exc.response.text
        return cls(msg=msg, error=error)


class ForemanApi(Api):
    """
    `apypie.Api` with default settings and helper functions for Foreman

    Usage::

      >>> import apypie
      >>> api = apypie.ForemanApi(uri='https://foreman.example.com', username='admin', password='changeme')
    """

    def __init__(self, **kwargs):
        self.task_timeout = kwargs.pop('task_timeout', 60)
        self.task_poll = 4
        kwargs['api_version'] = 2
        super().__init__(**kwargs)
        if kwargs.get('kerberos'):
            self.call('users', 'extlogin')

    def _resource(self, resource: str) -> 'Resource':
        if resource not in self.resources:
            raise ForemanApiException(msg=f"The server doesn't know about {resource}, is the right plugin installed?")
        return self.resource(resource)

    def _resource_call(self, resource: str, *args, **kwargs) -> Optional[dict]:
        return self._resource(resource).call(*args, **kwargs)

    def _resource_prepare_params(self, resource: str, action: str, params: dict) -> dict:
        api_action = self._resource(resource).action(action)
        return api_action.prepare_params(params)

    def resource_action(self, resource: str, action: str, params: dict, options=None, data=None, files=None,  # pylint: disable=too-many-arguments
                        ignore_task_errors: bool = False) -> Optional[dict]:
        """
        Perform a generic action on a resource

        Will wait for tasks if the action returns one
        """
        resource_payload = self._resource_prepare_params(resource, action, params)
        if options is None:
            options = {}
        try:
            result = self._resource_call(resource, action, resource_payload, options=options, data=data, files=files)
            is_foreman_task = isinstance(result, dict) and 'action' in result and 'state' in result and 'started_at' in result
            if result and is_foreman_task:
                result = self.wait_for_task(result, ignore_errors=ignore_task_errors)
        except Exception as exc:
            msg = f'Error while performing {action} on {resource}: {exc}'
            raise ForemanApiException.from_exception(exc, msg) from exc
        return result

    def wait_for_task(self, task: dict, ignore_errors: bool = False) -> dict:
        """
        Wait for a foreman-tasks task, polling it every ``self.task_poll`` seconds.

        Will raise a ForemanApiException when task has not finished in ``self.task_timeout`` seconds.
        """
        duration = self.task_timeout
        while task['state'] not in ['paused', 'stopped']:
            duration -= self.task_poll
            if duration <= 0:
                raise ForemanApiException(msg=f"Timeout waiting for Task {task['id']}")
            time.sleep(self.task_poll)

            resource_payload = self._resource_prepare_params('foreman_tasks', 'show', {'id': task['id']})
            task = cast(dict, self._resource_call('foreman_tasks', 'show', resource_payload))
        if not ignore_errors and task['result'] != 'success':
            msg = f"Task {task['action']}({task['id']}) did not succeed. Task information: {task['humanized']['errors']}"
            raise ForemanApiException(msg=msg)
        return task

    def show(self, resource: str, resource_id: int, params: Optional[dict] = None) -> Optional[dict]:
        """
        Execute the ``show`` action on an entity.

        :param resource: Plural name of the api resource to show
        :param resource_id: The ID of the entity to show
        :param params: Lookup parameters (i.e. parent_id for nested entities)

        :return: The entity
        """
        payload = {'id': resource_id}
        if params:
            payload.update(params)
        return self.resource_action(resource, 'show', payload)

    def list(self, resource: str, search: Optional[str] = None, params: Optional[dict] = None) -> list:
        """
        Execute the ``index`` action on an resource.

        :param resource: Plural name of the api resource to show
        :param search: Search string as accepted by the API to limit the results
        :param params: Lookup parameters (i.e. parent_id for nested entities)

        :return: List of results
        """
        payload: dict = {'per_page': PER_PAGE}
        if search is not None:
            payload['search'] = search
        if params:
            payload.update(params)

        result = self.resource_action(resource, 'index', payload)
        if result:
            return result['results']
        return []

    def create(self, resource: str, desired_entity: dict, params: Optional[dict] = None) -> Optional[dict]:
        """
        Create entity with given properties

        :param resource: Plural name of the api resource to manipulate
        :param desired_entity: Desired properties of the entity
        :param params: Lookup parameters (i.e. parent_id for nested entities)

        :return: The new current state of the entity
        """
        payload = desired_entity.copy()
        if params:
            payload.update(params)
        return self.resource_action(resource, 'create', payload)

    def update(self, resource: str, desired_entity: dict, params: Optional[dict] = None) -> Optional[dict]:
        """
        Update entity with given properties

        :param resource: Plural name of the api resource to manipulate
        :param desired_entity: Desired properties of the entity
        :param params: Lookup parameters (i.e. parent_id for nested entities)

        :return: The new current state of the entity
        """
        payload = desired_entity.copy()
        if params:
            payload.update(params)
        return self.resource_action(resource, 'update', payload)

    def delete(self, resource: str, current_entity: dict, params: Optional[dict] = None) -> None:
        """
        Delete a given entity

        :param resource: Plural name of the api resource to manipulate
        :param current_entity: Current properties of the entity
        :param params: Lookup parameters (i.e. parent_id for nested entities)

        :return: The new current state of the entity
        """
        payload = {'id': current_entity['id']}
        if params:
            payload.update(params)
        entity = self.resource_action(resource, 'destroy', payload)

        # this is a workaround for https://projects.theforeman.org/issues/26937
        if entity and isinstance(entity, dict) and 'error' in entity and 'message' in entity['error']:
            raise ForemanApiException(msg=entity['error']['message'])

    def validate_payload(self, resource: str, action: str, payload: dict) -> Tuple[dict, Set[str]]:
        """
        Check whether the payload only contains supported keys.

        :param resource: Plural name of the api resource to check
        :param action: Name of the action to check payload against
        :param payload: API paylod to be checked

        :return: The payload as it can be submitted to the API and set of unssuported parameters
        """
        filtered_payload = self._resource_prepare_params(resource, action, payload)
        unsupported_parameters = set(payload.keys()) - _recursive_dict_keys(filtered_payload)
        return (filtered_payload, unsupported_parameters)


def _recursive_dict_keys(a_dict: dict) -> set:
    """Find all keys of a nested dictionary"""
    keys = set(a_dict.keys())
    for value in a_dict.values():
        if isinstance(value, dict):
            keys.update(_recursive_dict_keys(value))
    return keys


"""
Apypie Inflector module

Based on ActiveSupport Inflector (https://github.com/rails/rails.git)
Inflection rules taken from davidcelis's Inflections (https://github.com/davidcelis/inflections.git)
"""


import re


class Inflections(object):
    """
    Inflections - rules how to convert words from singular to plural and vice versa.
    """

    def __init__(self):
        self.plurals = []
        self.singulars = []
        self.uncountables = []
        self.humans = []
        self.acronyms = {}
        self.acronym_regex = r'/(?=a)b/'

    def acronym(self, word):
        # type: (str) -> None
        """
        Add a new acronym.
        """

        self.acronyms[word.lower()] = word
        self.acronym_regex = '|'.join(self.acronyms.values())

    def plural(self, rule, replacement):
        # type: (str, str) -> None
        """
        Add a new plural rule.
        """

        if rule in self.uncountables:
            self.uncountables.remove(rule)
        if replacement in self.uncountables:
            self.uncountables.remove(replacement)

        self.plurals.insert(0, (rule, replacement))

    def singular(self, rule, replacement):
        # type: (str, str) -> None
        """
        Add a new singular rule.
        """

        if rule in self.uncountables:
            self.uncountables.remove(rule)
        if replacement in self.uncountables:
            self.uncountables.remove(replacement)

        self.singulars.insert(0, (rule, replacement))

    def irregular(self, singular, plural):
        # type: (str, str) -> None
        """
        Add a new irregular rule
        """

        if singular in self.uncountables:
            self.uncountables.remove(singular)
        if plural in self.uncountables:
            self.uncountables.remove(plural)

        sfirst = singular[0]
        srest = singular[1:]

        pfirst = plural[0]
        prest = plural[1:]

        if sfirst.upper() == pfirst.upper():
            self.plural(r'(?i)({}){}$'.format(sfirst, srest), r'\1' + prest)
            self.plural(r'(?i)({}){}$'.format(pfirst, prest), r'\1' + prest)

            self.singular(r'(?i)({}){}$'.format(sfirst, srest), r'\1' + srest)
            self.singular(r'(?i)({}){}$'.format(pfirst, prest), r'\1' + srest)
        else:
            self.plural(r'{}(?i){}$'.format(sfirst.upper(), srest), pfirst.upper() + prest)
            self.plural(r'{}(?i){}$'.format(sfirst.lower(), srest), pfirst.lower() + prest)
            self.plural(r'{}(?i){}$'.format(pfirst.upper(), prest), pfirst.upper() + prest)
            self.plural(r'{}(?i){}$'.format(pfirst.lower(), prest), pfirst.lower() + prest)

            self.singular(r'{}(?i){}$'.format(sfirst.upper(), srest), sfirst.upper() + srest)
            self.singular(r'{}(?i){}$'.format(sfirst.lower(), srest), sfirst.lower() + srest)
            self.singular(r'{}(?i){}$'.format(pfirst.upper(), prest), sfirst.upper() + srest)
            self.singular(r'{}(?i){}$'.format(pfirst.lower(), prest), sfirst.lower() + srest)

    def uncountable(self, *words):
        """
        Add new uncountables.
        """

        self.uncountables.extend(words)

    def human(self, rule, replacement):
        # type: (str, str) -> None
        """
        Add a new humanize rule.
        """

        self.humans.insert(0, (rule, replacement))


class Inflector(object):
    """
    Inflector - perform inflections
    """

    def __init__(self):
        # type: () -> None
        self.inflections = Inflections()
        self.inflections.plural(r'$', 's')
        self.inflections.plural(r'(?i)([sxz]|[cs]h)$', r'\1es')
        self.inflections.plural(r'(?i)([^aeiouy]o)$', r'\1es')
        self.inflections.plural(r'(?i)([^aeiouy])y$', r'\1ies')

        self.inflections.singular(r'(?i)s$', r'')
        self.inflections.singular(r'(?i)(ss)$', r'\1')
        self.inflections.singular(r'([sxz]|[cs]h)es$', r'\1')
        self.inflections.singular(r'([^aeiouy]o)es$', r'\1')
        self.inflections.singular(r'(?i)([^aeiouy])ies$', r'\1y')

        self.inflections.irregular('child', 'children')
        self.inflections.irregular('man', 'men')
        self.inflections.irregular('medium', 'media')
        self.inflections.irregular('move', 'moves')
        self.inflections.irregular('person', 'people')
        self.inflections.irregular('self', 'selves')
        self.inflections.irregular('sex', 'sexes')
        self.inflections.irregular('erratum', 'errata')

        self.inflections.uncountable('equipment', 'information', 'money', 'species', 'series', 'fish', 'sheep', 'police')

    def pluralize(self, word):
        # type: (str) -> str
        """
        Pluralize a word.
        """

        return self._apply_inflections(word, self.inflections.plurals)

    def singularize(self, word):
        # type: (str) -> str
        """
        Singularize a word.
        """

        return self._apply_inflections(word, self.inflections.singulars)

    def _apply_inflections(self, word, rules):
        # type: (str, Iterable[Tuple[str, str]]) -> str
        result = word

        if word != '' and result.lower() not in self.inflections.uncountables:
            for (rule, replacement) in rules:
                result = re.sub(rule, replacement, result)
                if result != word:
                    break

        return result


"""
Apypie Param module
"""


import re

HTML_STRIP = re.compile(r'<\/?[^>]+?>')


class Param(object):  # pylint: disable=too-many-instance-attributes,too-few-public-methods
    """
    Apipie Param
    """

    def __init__(self, **kwargs):
        self.allow_nil = kwargs.get('allow_nil')
        self.description = HTML_STRIP.sub('', kwargs.get('description'))
        self.expected_type = kwargs.get('expected_type')
        self.full_name = kwargs.get('full_name')
        self.name = kwargs.get('name')
        self.params = [Param(**param) for param in kwargs.get('params', [])]
        self.required = bool(kwargs.get('required'))
        self.validator = kwargs.get('validator')


"""
Apypie Resource module
"""


class Resource(object):
    """
    Apipie Resource
    """

    def __init__(self, api, name):
        # type: (Api, str) -> None
        self.api = api
        self.name = name

    @property
    def actions(self):
        # type: () -> List
        """
        Actions available for this resource.

        :returns: The actions.
        """
        return sorted([method['name'] for method in self.api.apidoc['docs']['resources'][self.name]['methods']])

    def action(self, name):
        # type: (str) -> Action
        """
        Get an :class:`Action` for this resource.

        :param name: The name of the action.
        """
        if self.has_action(name):
            return Action(name, self.name, self.api)
        message = "Unknown action '{}'. Supported actions: {}".format(name, ', '.join(sorted(self.actions)))
        raise KeyError(message)

    def has_action(self, name):
        # type: (str) -> bool
        """
        Check whether the resource has a given action.

        :param name: The name of the action.
        """
        return name in self.actions

    def call(self, action, params=None, headers=None, options=None, data=None, files=None):  # pylint: disable=too-many-arguments
        # type: (str, Optional[dict], Optional[dict], Optional[dict], Optional[Any], Optional[dict]) -> Optional[dict]
        """
        Call the API to execute an action for this resource.

        :param action: The action to call.
        :param params: The params that should be passed to the API.
        :param headers: Additional headers to be passed to the API.
        :param options: Options
        :param data: Binary data to be submitted to the API.
        :param files: Files to be submitted to the API.

        :returns: The API response.
        """

        return self.api.call(self.name, action, params, headers, options, data, files)


"""
Apypie Route module
"""

from urllib.parse import quote  # type: ignore


class Route(object):
    """
    Apipie Route
    """

    def __init__(self, path, method, description=""):
        # type: (str, str, str) -> None
        self.path = path
        self.method = method.lower()
        self.description = description

    @property
    def params_in_path(self):
        # type: () -> List
        """
        Params that can be passed in the path (URL) of the route.

        :returns: The params.
        """
        return [part[1:] for part in self.path.split('/') if part.startswith(':')]

    def path_with_params(self, params=None):
        # type: (Optional[dict]) -> str
        """
        Fill in the params into the path.

        :returns: The path with params.
        """
        result = self.path
        if params is not None:
            for param in self.params_in_path:
                if param in params:
                    result = result.replace(':{}'.format(param), quote(str(params[param]), safe=''))
                else:
                    raise KeyError("missing param '{}' in parameters".format(param))
        return result
