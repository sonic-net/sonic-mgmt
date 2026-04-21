# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Kevin Breit (@kbreit) <kevin.breit@kevinbreit.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import time
import re
from ansible.module_utils.basic import json, env_fallback
from ansible.module_utils.common.dict_transformations import camel_dict_to_snake_dict, snake_dict_to_camel_dict, recursive_diff
from ansible.module_utils.urls import fetch_url
from ansible.module_utils.six.moves.urllib.parse import urlencode
from ansible.module_utils._text import to_native


RATE_LIMIT_RETRY_MULTIPLIER = 3
INTERNAL_ERROR_RETRY_MULTIPLIER = 3


def meraki_argument_spec():
    return dict(auth_key=dict(type='str', no_log=True, fallback=(env_fallback, ['MERAKI_KEY']), required=True),
                host=dict(type='str', default='api.meraki.com'),
                use_proxy=dict(type='bool', default=False),
                use_https=dict(type='bool', default=True),
                validate_certs=dict(type='bool', default=True),
                output_format=dict(type='str', choices=['camelcase', 'snakecase'], default='snakecase', fallback=(
                    env_fallback, ['ANSIBLE_MERAKI_FORMAT'])),
                output_level=dict(type='str', default='normal',
                                  choices=['normal', 'debug']),
                timeout=dict(type='int', default=30),
                org_name=dict(type='str', aliases=['organization']),
                org_id=dict(type='str'),
                rate_limit_retry_time=dict(type='int', default=165),
                internal_error_retry_time=dict(type='int', default=60)
                )


class RateLimitException(Exception):
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class InternalErrorException(Exception):
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class HTTPError(Exception):
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class MerakiModule(object):

    def __init__(self, module, function=None):
        self.module = module
        self.params = module.params
        self.result = dict(changed=False)
        self.headers = dict()
        self.function = function
        self.orgs = None
        self.nets = None
        self.org_id = None
        self.net_id = None
        self.check_mode = module.check_mode
        self.key_map = {}
        self.request_attempts = 0

        # normal output
        self.existing = None

        # info output
        self.config = dict()
        self.original = None
        self.proposed = dict()
        self.merged = None
        self.ignored_keys = ['id', 'organizationId']

        # debug output
        self.filter_string = ''
        self.method = None
        self.path = None
        self.response = None
        self.status = None
        self.url = None
        self.body = None

        # rate limiting statistics
        self.retry = 0
        self.retry_time = 0

        # If URLs need to be modified or added for specific purposes, use .update() on the url_catalog dictionary
        self.get_urls = {'organizations': '/organizations',
                         'network': '/organizations/{org_id}/networks',
                         'admins': '/organizations/{org_id}/admins',
                         'configTemplates': '/organizations/{org_id}/configTemplates',
                         'samlymbols': '/organizations/{org_id}/samlRoles',
                         'ssids': '/networks/{net_id}/ssids',
                         'groupPolicies': '/networks/{net_id}/groupPolicies',
                         'staticRoutes': '/networks/{net_id}/staticRoutes',
                         'vlans': '/networks/{net_id}/vlans',
                         'devices': '/networks/{net_id}/devices',
                         }

        # Used to retrieve only one item
        self.get_one_urls = {'organizations': '/organizations/{org_id}',
                             'network': '/networks/{net_id}',
                             }

        # Module should add URLs which are required by the module
        self.url_catalog = {'get_all': self.get_urls,
                            'get_one': self.get_one_urls,
                            'create': None,
                            'update': None,
                            'delete': None,
                            'misc': None,
                            }

        if self.module._debug or self.params['output_level'] == 'debug':
            self.module.warn(
                'Enable debug output because ANSIBLE_DEBUG was set or output_level is set to debug.')

        # TODO: This should be removed as org_name isn't always required
        self.module.required_if = [('state', 'present', ['org_name']),
                                   ('state', 'absent', ['org_name']),
                                   ]
        # self.module.mutually_exclusive = [('org_id', 'org_name'),
        #                                   ]
        self.modifiable_methods = ['POST', 'PUT', 'DELETE']

        self.headers = {'Content-Type': 'application/json',
                        'Authorization': 'Bearer {key}'.format(key=module.params['auth_key']),
                        }

    def define_protocol(self):
        """Set protocol based on use_https parameters."""
        if self.params['use_https'] is True:
            self.params['protocol'] = 'https'
        else:
            self.params['protocol'] = 'http'

    def sanitize_keys(self, data):
        if isinstance(data, dict):
            items = {}
            for k, v in data.items():
                try:
                    items[self.key_map[k]] = self.sanitize_keys(data[k])
                except KeyError:
                    snake_k = re.sub('([a-z0-9])([A-Z])', r'\1_\2', k).lower()
                    # new = {snake_k: data[k]}
                    items[snake_k] = self.sanitize_keys(data[k])
            return items
        elif isinstance(data, list):
            items = []
            for i in data:
                items.append(self.sanitize_keys(i))
            return items
        elif isinstance(data, int) or isinstance(data, str) or isinstance(data, float):
            return data

    def is_update_required(self, original, proposed, optional_ignore=None, force_include=None, debug=False):
        ''' Compare two data-structures '''
        self.ignored_keys.append('net_id')
        if force_include is not None:
            if force_include in self.ignored_keys:
                self.ignored_keys.remove(force_include)
        if optional_ignore is not None:
            # self.fail_json(msg="Keys", ignored_keys=self.ignored_keys, optional=optional_ignore)
            self.ignored_keys = self.ignored_keys + optional_ignore

        if isinstance(original, list):
            if len(original) != len(proposed):
                if debug is True:
                    self.fail_json(msg="Length of lists don't match")
                return True
            for a, b in zip(original, proposed):
                if self.is_update_required(a, b, debug=debug):
                    if debug is True:
                        self.fail_json(msg="List doesn't match", a=a, b=b)
                    return True
        elif isinstance(original, dict):
            try:
                for k, v in proposed.items():
                    if k not in self.ignored_keys:
                        if k in original:
                            if self.is_update_required(original[k], proposed[k], debug=debug):
                                return True
                        else:
                            if debug is True:
                                self.fail_json(msg="Key not in original", k=k)
                            return True
            except AttributeError:
                return True
        else:
            if original != proposed:
                if debug is True:
                    self.fail_json(
                        msg="Fallback", original=original, proposed=proposed)
                return True
        return False

    def generate_diff(self, before, after):
        """Creates a diff based on two objects. Applies to the object and returns nothing.
        """
        try:
            diff = recursive_diff(before, after)
            self.result['diff'] = {'before': diff[0],
                                   'after': diff[1]}
        except AttributeError:  # Normally for passing a list instead of a dict
            diff = recursive_diff({'data': before},
                                  {'data': after})
            self.result['diff'] = {'before': diff[0]['data'],
                                   'after': diff[1]['data']}

    def get_orgs(self):
        """Downloads all organizations for a user."""
        response = self.request('/organizations', method='GET')
        if self.status != 200:
            self.fail_json(msg='Organization lookup failed')
        self.orgs = response
        return self.orgs

    def is_org_valid(self, data, org_name=None, org_id=None):
        """Checks whether a specific org exists and is duplicated.

        If 0, doesn't exist. 1, exists and not duplicated. >1 duplicated.
        """
        org_count = 0
        if org_name is not None:
            for o in data:
                if o['name'] == org_name:
                    org_count += 1
        if org_id is not None:
            for o in data:
                if o['id'] == org_id:
                    org_count += 1
        return org_count

    def get_org_id(self, org_name):
        """Returns an organization id based on organization name, only if unique.

        If org_id is specified as parameter, return that instead of a lookup.
        """
        orgs = self.get_orgs()
        # self.fail_json(msg='ogs', orgs=orgs)
        if self.params['org_id'] is not None:
            if self.is_org_valid(orgs, org_id=self.params['org_id']) is True:
                return self.params['org_id']
        org_count = self.is_org_valid(orgs, org_name=org_name)
        if org_count == 0:
            self.fail_json(msg='There are no organizations with the name {org_name}'.format(
                org_name=org_name))
        if org_count > 1:
            self.fail_json(msg='There are multiple organizations with the name {org_name}'.format(
                org_name=org_name))
        elif org_count == 1:
            for i in orgs:
                if org_name == i['name']:
                    # self.fail_json(msg=i['id'])
                    return str(i['id'])

    def get_nets(self, org_name=None, org_id=None):
        """Downloads all networks in an organization."""
        if org_name:
            org_id = self.get_org_id(org_name)
        path = self.construct_path(
            'get_all', org_id=org_id, function='network', params={'perPage': '1000'})
        r = self.request(path, method='GET', pagination_items=1000)
        if self.status != 200:
            self.fail_json(msg='Network lookup failed')
        self.nets = r
        templates = self.get_config_templates(org_id)
        for t in templates:
            self.nets.append(t)
        return self.nets

    def get_net(self, org_name, net_name=None, org_id=None, data=None, net_id=None):
        ''' Return network information '''
        if not data:
            if not org_id:
                org_id = self.get_org_id(org_name)
            data = self.get_nets(org_id=org_id)
        for n in data:
            if net_id:
                if n['id'] == net_id:
                    return n
            elif net_name:
                if n['name'] == net_name:
                    return n
        return False

    def get_net_id(self, org_name=None, net_name=None, data=None):
        """Return network id from lookup or existing data."""
        if data is None:
            self.fail_json(msg='Must implement lookup')
        for n in data:
            if n['name'] == net_name:
                return n['id']
        self.fail_json(
            msg='No network found with the name {0}'.format(net_name))

    def get_config_templates(self, org_id):
        path = self.construct_path(
            'get_all', function='configTemplates', org_id=org_id)
        response = self.request(path, 'GET')
        if self.status != 200:
            self.fail_json(msg='Unable to get configuration templates')
        return response

    def get_template_id(self, name, data):
        for template in data:
            if name == template['name']:
                return template['id']
        self.fail_json(
            msg='No configuration template named {0} found'.format(name))

    def convert_camel_to_snake(self, data):
        """
        Converts a dictionary or list to snake case from camel case
        :type data: dict or list
        :return: Converted data structure, if list or dict
        """

        if isinstance(data, dict):
            return camel_dict_to_snake_dict(data, ignore_list=('tags', 'tag'))
        elif isinstance(data, list):
            return [camel_dict_to_snake_dict(item, ignore_list=('tags', 'tag')) for item in data]
        else:
            return data

    def convert_snake_to_camel(self, data):
        """
        Converts a dictionary or list to camel case from snake case
        :type data: dict or list
        :return: Converted data structure, if list or dict
        """

        if isinstance(data, dict):
            return snake_dict_to_camel_dict(data)
        elif isinstance(data, list):
            return [snake_dict_to_camel_dict(item) for item in data]
        else:
            return data

    def construct_params_list(self, keys, aliases=None):
        qs = {}
        for key in keys:
            if key in aliases:
                qs[aliases[key]] = self.module.params[key]
            else:
                qs[key] = self.module.params[key]
        return qs

    def encode_url_params(self, params):
        """Encodes key value pairs for URL"""
        return "?{0}".format(urlencode(params))

    def construct_path(self,
                       action,
                       function=None,
                       org_id=None,
                       net_id=None,
                       org_name=None,
                       custom=None,
                       params=None):
        """Build a path from the URL catalog.
        Uses function property from class for catalog lookup.
        """
        built_path = None
        if function is None:
            built_path = self.url_catalog[action][self.function]
        else:
            built_path = self.url_catalog[action][function]
        if org_name:
            org_id = self.get_org_id(org_name)
        if custom:
            built_path = built_path.format(
                org_id=org_id, net_id=net_id, **custom)
        else:
            built_path = built_path.format(org_id=org_id, net_id=net_id)
        if params:
            built_path += self.encode_url_params(params)
        return built_path

    def _set_url(self, path, method, params):
        self.path = path
        self.define_protocol()

        if method is not None:
            self.method = method

        self.url = '{protocol}://{host}/api/v1/{path}'.format(
            path=self.path.lstrip('/'), **self.params)

    @staticmethod
    def _parse_pagination_header(link):
        rels = {'first': None,
                'next': None,
                'prev': None,
                'last': None
                }
        for rel in link.split(','):
            kv = rel.split('rel=')
            # This should return just the URL for <url>
            rels[kv[1]] = kv[0].split('<')[1].split('>')[0].strip()
        return rels

    def _execute_request(self, path, method=None, payload=None, params=None):
        """ Execute query """
        try:
            resp, info = fetch_url(self.module, self.url,
                                   headers=self.headers,
                                   data=payload,
                                   method=self.method,
                                   timeout=self.params['timeout'],
                                   use_proxy=self.params['use_proxy'],
                                   )
            self.status = info['status']

            if self.status == 429:
                self.retry += 1
                if self.retry <= 10:
                    # retry-after isn't returned for over 10 concurrent connections per IP
                    try:
                        self.module.warn("Rate limiter hit, retry {0}...pausing for {1} seconds".format(
                            self.retry, info['Retry-After']))
                        time.sleep(info['Retry-After'])
                    except KeyError:
                        self.module.warn(
                            "Rate limiter hit, retry {0}...pausing for 5 seconds".format(self.retry))
                        time.sleep(5)
                    return self._execute_request(path, method=method, payload=payload, params=params)
                else:
                    self.fail_json(
                        msg="Rate limit retries failed for {url}".format(url=self.url))
            elif self.status == 500:
                self.retry += 1
                self.module.warn(
                    "Internal server error 500, retry {0}".format(self.retry))
                if self.retry <= 10:
                    self.retry_time += self.retry * INTERNAL_ERROR_RETRY_MULTIPLIER
                    time.sleep(self.retry_time)
                    return self._execute_request(path, method=method, payload=payload, params=params)
                else:
                    # raise RateLimitException(e)
                    self.fail_json(
                        msg="Rate limit retries failed for {url}".format(url=self.url))
            elif self.status == 502:
                self.module.warn(
                    "Internal server error 502, retry {0}".format(self.retry))
            elif self.status == 400:
                raise HTTPError("")
            elif self.status >= 400:
                self.fail_json(msg=self.status, url=self.url)
                raise HTTPError("")
        except HTTPError:
            try:
                self.fail_json(msg="HTTP error {0} - {1} - {2}".format(
                    self.status, self.url, json.loads(info['body'])['errors'][0]))
            except json.decoder.JSONDecodeError:
                self.fail_json(
                    msg="HTTP error {0} - {1}".format(self.status, self.url))
        self.retry = 0  # Needs to reset in case of future retries
        return resp, info

    def request(self, path, method=None, payload=None, params=None, pagination_items=None):
        """ Submit HTTP request to Meraki API """
        self._set_url(path, method, params)

        try:
            # Gather the body (resp) and header (info)
            resp, info = self._execute_request(
                path, method=method, payload=payload, params=params)
        except HTTPError:
            self.fail_json(msg="HTTP request to {url} failed with error code {code}".format(
                url=self.url, code=self.status))
        self.response = info['msg']
        self.status = info['status']
        # This needs to be refactored as it's not very clean
        # Looping process for pagination
        if pagination_items is not None:
            data = None
            if 'body' in info:
                self.body = info['body']
            try:
                data = json.loads(to_native(resp.read()))
            except AttributeError:
                self.fail_json(msg="Failure occurred during pagination",
                               response=self.response,
                               status=self.status,
                               body=self.body
                               )
            header_link = self._parse_pagination_header(info['link'])
            while header_link['next'] is not None:
                self.url = header_link['next']
                try:
                    # Gather the body (resp) and header (info)
                    resp, info = self._execute_request(
                        header_link['next'], method=method, payload=payload, params=params)
                except HTTPError:
                    self.fail_json(msg="HTTP request to {url} failed with error code {code}".format(
                        url=self.url, code=self.status))
                header_link = self._parse_pagination_header(info['link'])
                try:
                    data.extend(json.loads(to_native(resp.read())))
                except AttributeError:
                    self.fail_json(msg="Failure occurred during pagination",
                                   response=self.response,
                                   status=self.status,
                                   body=self.body
                                   )
            return data
        else:  # Non-pagination
            if 'body' in info:
                self.body = info['body']
            try:
                return json.loads(to_native(resp.read()))
            except json.decoder.JSONDecodeError:
                return {}
            except AttributeError:
                self.fail_json(msg="Failure occurred",
                               response=self.response,
                               status=self.status,
                               body=self.body
                               )

    def exit_json(self, **kwargs):
        """Custom written method to exit from module."""
        self.result['response'] = self.response
        self.result['status'] = self.status
        if self.retry > 0:
            self.module.warn(
                "Rate limiter triggered - retry count {0}".format(self.retry))
        # Return the gory details when we need it
        if self.params['output_level'] == 'debug':
            self.result['method'] = self.method
            self.result['url'] = self.url
        self.result.update(**kwargs)
        if self.params['output_format'] == 'camelcase':
            self.module.deprecate("Update your playbooks to support snake_case format instead of camelCase format.",
                                  date="2022-06-01",
                                  collection_name="cisco.meraki")
        else:
            if 'data' in self.result:
                try:
                    self.result['data'] = self.convert_camel_to_snake(
                        self.result['data'])
                    self.result['diff'] = self.convert_camel_to_snake(
                        self.result['diff'])
                except (KeyError, AttributeError):
                    pass
        self.module.exit_json(**self.result)

    def fail_json(self, msg, **kwargs):
        """Custom written method to return info on failure."""
        self.result['response'] = self.response
        self.result['status'] = self.status

        if self.params['output_level'] == 'debug':
            if self.url is not None:
                self.result['method'] = self.method
                self.result['url'] = self.url

        self.result.update(**kwargs)
        self.module.fail_json(msg=msg, **self.result)
