# -*- coding: utf-8 -*-
# Copyright (C) 2016 Guido Günther <agx@sigxcpu.org>, Daniel Lobato Garcia <dlobatog@redhat.com>
# Copyright (c) 2018 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# pylint: disable=raise-missing-from
# pylint: disable=super-with-arguments

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = '''
    name: foreman
    short_description: Foreman inventory source
    requirements:
        - requests >= 1.1
    description:
        - Get inventory hosts from Foreman.
        - Can use the Reports API (default) or the Hosts API to fetch information about the hosts.
        - The Reports API is faster with many hosts.
        - The Reports API requires the C(foreman_ansible) plugin to be installed on the Foreman server.
        - Some options only work when using the Reports API.
        - Uses a YAML configuration file that ends with ``foreman.(yml|yaml)``.
    extends_documentation_fragment:
        - inventory_cache
        - constructed
    options:
      plugin:
        description: token that ensures this is a source file for the C(foreman) plugin.
        required: true
        choices: ['theforeman.foreman.foreman']
      url:
        description:
          - URL of the Foreman server.
        required: true
        env:
            - name: FOREMAN_SERVER
            - name: FOREMAN_SERVER_URL
            - name: FOREMAN_URL
      user:
        description:
          - Username accessing the Foreman server.
        required: true
        env:
            - name: FOREMAN_USER
            - name: FOREMAN_USERNAME
      password:
        description:
          - Password of the user accessing the Foreman server.
        required: true
        env:
            - name: FOREMAN_PASSWORD
      validate_certs:
        description:
          - Whether or not to verify the TLS certificates of the Foreman server.
        type: boolean
        default: true
        env:
            - name: FOREMAN_VALIDATE_CERTS
      group_prefix:
        description: prefix to apply to foreman groups
        default: foreman_
      vars_prefix:
        description: prefix to apply to host variables, does not include facts nor params
        default: foreman_
      want_facts:
        description: Toggle, if True the plugin will retrieve host facts from the server
        type: boolean
        default: false
      want_params:
        description: Toggle, if true the inventory will retrieve 'all_parameters' information as host vars
        type: boolean
        default: false
      want_hostcollections:
        description: Toggle, if true the plugin will create Ansible groups for host collections
        type: boolean
        default: false
      legacy_hostvars:
        description:
            - Toggle, if true the plugin will build legacy hostvars present in the foreman script
            - Places hostvars in a dictionary with keys `foreman`, `foreman_facts`, and `foreman_params`
        type: boolean
        default: false
      host_filters:
        description: This can be used to restrict the list of returned host
        type: string
      batch_size:
        description: Number of hosts per batch that will be retrieved from the Foreman API per individual call
        type: int
        default: 250
      use_reports_api:
        description: Use Reports API.
        type: boolean
        default: true
      foreman:
        description:
          - Foreman server related configuration, deprecated.
          - You can pass I(use_reports_api) in this dict to enable the Reports API.
          - Only for backward compatibility.
      report:
        description:
          - Report API specific configuration, deprecated.
          - You can pass the Report API specific params as part of this dict, instead of the main configuration.
          - Only for backward compatibility.
        type: dict
      poll_interval:
        description: The polling interval between 2 calls to the report_data endpoint while polling.
        type: int
        default: 10
      max_timeout:
        description: Timeout before falling back to old host API when using report_data endpoint while polling.
        type: int
        default: 600
      want_organization:
        description:
          - Toggle, if true the inventory will fetch organization the host belongs to and create groupings for the same.
          - Only applies to inventories using the Reports API - attribute is ignored otherwise.
        type: boolean
        default: true
      want_location:
        description:
          - Toggle, if true the inventory will fetch location the host belongs to and create groupings for the same.
          - Only applies to inventories using the Reports API - attribute is ignored otherwise.
        type: boolean
        default: true
      want_ipv4:
        description:
          - Toggle, if true the inventory will fetch ipv4 address of the host.
          - Only applies to inventories using the Reports API - attribute is ignored otherwise.
        type: boolean
        default: true
      want_ipv6:
        description:
          - Toggle, if true the inventory will fetch ipv6 address of the host.
          - Only applies to inventories using the Reports API - attribute is ignored otherwise.
        type: boolean
        default: true
      want_host_group:
        description:
          - Toggle, if true the inventory will fetch host_groups and create groupings for the same.
          - Only applies to inventories using the Reports API - attribute is ignored otherwise.
        type: boolean
        default: true
      want_subnet:
        description:
          - Toggle, if true the inventory will fetch subnet.
          - Only applies to inventories using the Reports API - attribute is ignored otherwise.
        type: boolean
        default: true
      want_subnet_v6:
        description:
          -  Toggle, if true the inventory will fetch ipv6 subnet.
          - Only applies to inventories using the Reports API - attribute is ignored otherwise.
        type: boolean
        default: true
      want_smart_proxies:
        description:
          - Toggle, if true the inventory will fetch smart proxy that the host is registered to.
          - Only applies to inventories using the Reports API - attribute is ignored otherwise.
        type: boolean
        default: true
      want_content_facet_attributes:
        description:
          - Toggle, if true the inventory will fetch content view details that the host is tied to.
          - Only applies to inventories using the Reports API - attribute is ignored otherwise.
        type: boolean
        default: true
      hostnames:
        description:
          - A list of templates in order of precedence to compose inventory_hostname.
          - If the template results in an empty string or None value it is ignored.
        type: list
        elements: str
        default: ['name']
'''

EXAMPLES = '''
# my.foreman.yml
plugin: theforeman.foreman.foreman
url: https://foreman.example.com
user: ansibleinventory
password: changeme
# Only fetch hosts in the Web Engineering organization
host_filters: 'organization="Web Engineering"'
# Use short names (not FQDN) for the hosts in the intentory
hostnames:
  - name.split('.')[0]
'''
import copy
import json
from ansible_collections.theforeman.foreman.plugins.module_utils._version import LooseVersion
from collections.abc import MutableMapping
from time import sleep
from ansible.errors import AnsibleError
from ansible.module_utils.common.text.converters import to_bytes, to_native, to_text
from ansible.plugins.inventory import BaseInventoryPlugin, Cacheable, to_safe_group_name, Constructable

# 3rd party imports
try:
    import requests
    if LooseVersion(requests.__version__) < LooseVersion('1.1.0'):
        raise ImportError
    from requests.auth import HTTPBasicAuth
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class InventoryModule(BaseInventoryPlugin, Cacheable, Constructable):
    ''' Host inventory parser for ansible using foreman as source. '''

    NAME = 'theforeman.foreman.foreman'

    def __init__(self):

        super(InventoryModule, self).__init__()
        self.MINIMUM_FOREMAN_VERSION_FOR_REPORTS_API = '1.24.0'
        # from config
        self.foreman_url = None

        self.session = None
        self.cache_key = None
        self.use_cache = None

        if not HAS_REQUESTS:
            raise AnsibleError('This script requires python-requests 1.1 as a minimum version')

    def verify_file(self, path):

        valid = False
        if super(InventoryModule, self).verify_file(path):
            if path.endswith(('foreman.yaml', 'foreman.yml')):
                valid = True
            else:
                self.display.vvv('Skipping due to inventory source not ending in "foreman.yaml" nor "foreman.yml"')
        return valid

    def _get_session(self):
        if not self.session:
            self.session = requests.session()
            self.session.auth = HTTPBasicAuth(self.get_option('user'), to_bytes(self.get_option('password')))
            self.session.verify = self.get_option('validate_certs')
        return self.session

    def _get_json(self, url, ignore_errors=None, params=None):

        if not self.use_cache or url not in self._cache.get(self.cache_key, {}):

            if self.cache_key not in self._cache:
                self._cache[self.cache_key] = {url: ''}

            results = []
            s = self._get_session()
            if params is None:
                params = {}
            params['page'] = 1
            params['per_page'] = self.get_option('batch_size')
            while True:
                # workaround to address the follwing issues where 'verify' is overridden in Requests:
                #   - https://github.com/psf/requests/issues/3829
                #   - https://github.com/psf/requests/issues/5209
                ret = s.get(url, params=params, verify=self.get_option('validate_certs'))

                if ignore_errors and ret.status_code in ignore_errors:
                    break
                ret.raise_for_status()
                json = ret.json()

                # process results
                # FIXME: This assumes 'return type' matches a specific query,
                #        it will break if we expand the queries and they dont have different types
                if 'results' not in json:  # pylint: disable=no-else-break
                    # /hosts/:id dos not have a 'results' key
                    results = json
                    break
                elif isinstance(json['results'], MutableMapping):
                    # /facts are returned as dict in 'results'
                    if not isinstance(results, MutableMapping):
                        results = {}

                    # check for end of paging
                    if len(json['results']) == 0:
                        break

                    for host, facts in json['results'].items():
                        if host not in results:
                            results[host] = {}
                        results[host].update(facts)

                    # get next page
                    params['page'] += 1
                else:
                    # /hosts 's 'results' is a list of all hosts, returned is paginated
                    results = results + json['results']

                    # check for end of paging
                    if len(results) >= json['subtotal']:
                        break
                    if len(json['results']) == 0:
                        self.display.warning("Did not make any progress during loop. expected %d got %d" % (json['subtotal'], len(results)))
                        break

                    # get next page
                    params['page'] += 1

            self._cache[self.cache_key][url] = results

        return self._cache[self.cache_key][url]

    def _get_hosts(self):
        url = "%s/api/v2/hosts" % self.foreman_url
        params = {}
        if self.get_option('host_filters'):
            params['search'] = self.get_option('host_filters')
        return self._get_json(url, params=params)

    def _get_all_params_by_id(self, hid):
        url = "%s/api/v2/hosts/%s" % (self.foreman_url, hid)
        ret = self._get_json(url, [404])
        if not ret or not isinstance(ret, MutableMapping) or not ret.get('all_parameters', False):
            return {}
        return ret.get('all_parameters')

    def _get_facts_by_id(self, hid):
        url = "%s/api/v2/hosts/%s/facts" % (self.foreman_url, hid)
        return self._get_json(url)

    def _get_host_data_by_id(self, hid):
        url = "%s/api/v2/hosts/%s" % (self.foreman_url, hid)
        return self._get_json(url)

    def _get_facts(self, host):
        """Fetch all host facts of the host"""

        ret = self._get_facts_by_id(host['id'])
        if len(ret.values()) == 0:
            facts = {}
        elif len(ret.values()) == 1:
            facts = list(ret.values())[0]
        else:
            raise ValueError("More than one set of facts returned for '%s'" % host)
        return facts

    def _get_hostvars(self, host, vars_prefix='', omitted_vars=()):
        hostvars = {}
        for k, v in host.items():
            if k not in omitted_vars:
                hostvars[vars_prefix + k] = v
        return hostvars

    def _fetch_params(self):
        options = ("no", "yes")
        params = dict()

        report_options = self.get_option('report') or {}

        self.want_location = report_options.get('want_location', self.get_option('want_location'))
        self.want_organization = report_options.get('want_organization', self.get_option('want_organization'))
        self.want_IPv4 = report_options.get('want_ipv4', self.get_option('want_ipv4'))
        self.want_IPv6 = report_options.get('want_ipv6', self.get_option('want_ipv6'))
        self.want_host_group = report_options.get('want_host_group', self.get_option('want_host_group'))
        self.want_hostcollections = report_options.get('want_hostcollections', self.get_option('want_hostcollections'))
        self.want_subnet = report_options.get('want_subnet', self.get_option('want_subnet'))
        self.want_subnet_v6 = report_options.get('want_subnet_v6', self.get_option('want_subnet_v6'))
        self.want_smart_proxies = report_options.get('want_smart_proxies', self.get_option('want_smart_proxies'))
        self.want_content_facet_attributes = report_options.get('want_content_facet_attributes', self.get_option('want_content_facet_attributes'))
        self.want_params = self.get_option('want_params')
        self.want_facts = self.get_option('want_facts')
        self.host_filters = self.get_option('host_filters')

        params["Organization"] = options[self.want_organization]
        params["Location"] = options[self.want_location]
        params["IPv4"] = options[self.want_IPv4]
        params["IPv6"] = options[self.want_IPv6]
        params["Facts"] = options[self.want_facts]
        params["Host Group"] = options[self.want_host_group]
        params["Host Collections"] = options[self.want_hostcollections]
        params["Subnet"] = options[self.want_subnet]
        params["Subnet v6"] = options[self.want_subnet_v6]
        params["Smart Proxies"] = options[self.want_smart_proxies]
        params["Content Attributes"] = options[self.want_content_facet_attributes]
        params["Host Parameters"] = options[self.want_params]
        if self.host_filters:
            params["Hosts"] = self.host_filters
        return params

    def _use_inventory_report(self):
        use_inventory_report = self.get_option('use_reports_api')
        # backward compatibility
        try:
            use_inventory_report = self.get_option('foreman').get('use_reports_api')
        except Exception:
            pass
        if not use_inventory_report:
            return False
        status_url = "%s/api/v2/status" % self.foreman_url
        result = self._get_json(status_url)
        foreman_version = (LooseVersion(result.get('version')) >= LooseVersion(self.MINIMUM_FOREMAN_VERSION_FOR_REPORTS_API))
        return foreman_version

    def _post_request(self):
        url = "%s/ansible/api/v2/ansible_inventories/schedule" % self.foreman_url
        params = {'input_values': self._fetch_params()}

        if self.use_cache and url in self._cache.get(self.cache_key, {}):
            return self._cache[self.cache_key][url]

        if self.cache_key not in self._cache:
            self._cache[self.cache_key] = {}

        session = self._get_session()
        self.poll_interval = self.get_option('poll_interval')
        self.max_timeout = self.get_option('max_timeout')
        # backward compatibility
        try:
            self.poll_interval = int(self.get_option('report').get('poll_interval'))
            self.max_timeout = int(self.get_option('report').get('max_timeout'))
        except Exception:
            pass
        max_polls = self.max_timeout / self.poll_interval
        ret = session.post(url, json=params)
        if not ret:
            raise Exception("Error scheduling inventory report on foreman. Please check foreman logs!")
        data_url = "{0}/{1}".format(self.foreman_url, ret.json().get('data_url'))
        polls = 0
        response = session.get(data_url)
        while response:
            if response.status_code != 204 or polls > max_polls:
                break
            sleep(self.poll_interval)
            polls += 1
            response = session.get(data_url)
        if not response:
            raise Exception("Error receiving inventory report from foreman. Please check foreman logs!")
        elif (response.status_code == 204 and polls > max_polls):
            raise Exception("Timeout receiving inventory report from foreman. Check foreman server and max_timeout in foreman.yml")
        else:
            self._cache[self.cache_key][url] = json.loads(response.json())
            return self._cache[self.cache_key][url]

    def _populate(self):
        if self._use_inventory_report():
            self._populate_report_api()
        else:
            self._populate_host_api()

    def _get_hostname(self, properties, hostnames, strict=False):
        hostname = None
        errors = []

        for preference in hostnames:
            try:
                hostname = self._compose(preference, properties)
            except Exception as e:  # pylint: disable=broad-except
                if strict:
                    raise AnsibleError("Could not compose %s as hostnames - %s" % (preference, to_native(e)))
                else:
                    errors.append(
                        (preference, str(e))
                    )
            if hostname:
                return to_text(hostname)

        raise AnsibleError(
            'Could not template any hostname for host, errors for each preference: %s' % (
                ', '.join(['%s: %s' % (pref, err) for pref, err in errors])
            )
        )

    def _populate_report_api(self):
        self.groups = dict()
        self.hosts = dict()

        # We need a deep copy of the data, as we modify it below and this would also modify the cache
        host_data = copy.deepcopy(self._post_request())

        self.group_prefix = self.get_option('group_prefix')

        hostnames = self.get_option('hostnames')
        strict = self.get_option('strict')

        for host in host_data:
            if not host:
                continue

            composed_host_name = self._get_hostname(host, hostnames, strict=strict)

            if (composed_host_name in self._cache.keys()):
                continue

            host_name = self.inventory.add_host(composed_host_name)

            group_name = host.get('hostgroup_title', host.get('hostgroup_name'))
            if group_name:
                group_name = to_safe_group_name('%s%s' % (self.get_option('group_prefix'), group_name.lower().replace(" ", "")))
                group_name = self.inventory.add_group(group_name)
                self.inventory.add_child(group_name, host_name)

            host_params = host.pop('host_parameters', {})
            fact_list = host.pop('facts', {})

            if self.get_option('legacy_hostvars'):
                hostvars = self._get_hostvars(host)
                self.inventory.set_variable(host_name, 'foreman', hostvars)
            else:
                omitted_vars = ('name', 'hostgroup_title', 'hostgroup_name')
                hostvars = self._get_hostvars(host, self.get_option('vars_prefix'), omitted_vars)

                for k, v in hostvars.items():
                    try:
                        self.inventory.set_variable(host_name, k, v)
                    except ValueError as e:
                        self.display.warning("Could not set host info hostvar for %s, skipping %s: %s" % (host, k, to_text(e)))

            content_facet_attributes = host.get('content_attributes', {}) or {}
            if self.get_option('want_facts'):
                self.inventory.set_variable(host_name, 'foreman_facts', fact_list)

            # Create ansible groups for hostgroup
            group = 'host_group'
            group_name = host.get(group)
            if group_name:
                parent_name = None
                group_label_parts = []
                for part in group_name.split('/'):
                    group_label_parts.append(part.lower().replace(" ", ""))
                    gname = to_safe_group_name('%s%s' % (self.get_option('group_prefix'), '/'.join(group_label_parts)))
                    result_gname = self.inventory.add_group(gname)
                    if parent_name:
                        self.inventory.add_child(parent_name, result_gname)
                    parent_name = result_gname
                self.inventory.add_child(result_gname, host_name)

            # Create ansible groups for environment, location and organization
            for group in ['environment', 'location', 'organization']:
                val = host.get('%s' % group)
                if val:
                    safe_key = to_safe_group_name('%s%s_%s' % (
                        to_text(self.group_prefix),
                        group,
                        to_text(val).lower()
                    ))
                    env_lo_org = self.inventory.add_group(safe_key)
                    self.inventory.add_child(env_lo_org, host_name)

            for group in ['lifecycle_environment', 'content_view']:
                val = content_facet_attributes.get('%s_name' % group)
                if val:
                    safe_key = to_safe_group_name('%s%s_%s' % (
                        to_text(self.group_prefix),
                        group,
                        to_text(val).lower()
                    ))
                    le_cv_group = self.inventory.add_group(safe_key)
                    self.inventory.add_child(le_cv_group, host_name)
            params = host_params

            if self.want_hostcollections:
                hostcollections = host.get('host_collections')

                if hostcollections:
                    # Create Ansible groups for host collections
                    for hostcollection in hostcollections:
                        try:
                            host_collection_group_name = to_safe_group_name('%shostcollection_%s' % (
                                to_text(self.group_prefix),
                                to_text(hostcollection).lower()
                            ))
                            hostcollection_group = self.inventory.add_group(host_collection_group_name)
                            self.inventory.add_child(hostcollection_group, host_name)
                        except ValueError as e:
                            self.display.warning("Could not create groups for host collections for %s, skipping: %s" % (host_name, to_text(e)))

            # set host vars from params
            if self.get_option('want_params'):
                if self.get_option('legacy_hostvars'):
                    self.inventory.set_variable(host_name, 'foreman_params', params)
                else:
                    for k, v in params.items():
                        try:
                            self.inventory.set_variable(host_name, k, v)
                        except ValueError as e:
                            self.display.warning("Could not set hostvar %s to '%s' for the '%s' host, skipping:  %s" %
                                                 (k, to_native(v), host, to_native(e)))
            hostvars = self.inventory.get_host(host_name).get_vars()
            self._set_composite_vars(self.get_option('compose'), hostvars, host_name, strict)
            self._add_host_to_composed_groups(self.get_option('groups'), hostvars, host_name, strict)
            self._add_host_to_keyed_groups(self.get_option('keyed_groups'), hostvars, host_name, strict)

    def _populate_host_api(self):
        hostnames = self.get_option('hostnames')
        strict = self.get_option('strict')
        for host in self._get_hosts():
            if not host:
                continue

            composed_host_name = self._get_hostname(host, hostnames, strict=strict)

            if (composed_host_name in self._cache.keys()):
                continue

            host_name = self.inventory.add_host(composed_host_name)

            # create directly mapped groups
            group_name = host.get('hostgroup_title', host.get('hostgroup_name'))
            if group_name:
                parent_name = None
                group_label_parts = []
                for part in group_name.split('/'):
                    group_label_parts.append(part.lower().replace(" ", ""))
                    gname = to_safe_group_name('%s%s' % (self.get_option('group_prefix'), '/'.join(group_label_parts)))
                    result_gname = self.inventory.add_group(gname)
                    if parent_name:
                        self.inventory.add_child(parent_name, result_gname)
                    parent_name = result_gname
                self.inventory.add_child(result_gname, host_name)

            if self.get_option('legacy_hostvars'):
                hostvars = self._get_hostvars(host)
                self.inventory.set_variable(host_name, 'foreman', hostvars)
            else:
                omitted_vars = ('name', 'hostgroup_title', 'hostgroup_name')
                hostvars = self._get_hostvars(host, self.get_option('vars_prefix'), omitted_vars)

                for k, v in hostvars.items():
                    try:
                        self.inventory.set_variable(host_name, k, v)
                    except ValueError as e:
                        self.display.warning("Could not set host info hostvar for %s, skipping %s: %s" % (host, k, to_text(e)))

            # set host vars from params
            if self.get_option('want_params'):
                params = self._get_all_params_by_id(host['id'])
                filtered_params = {}
                for p in params:
                    if 'name' in p and 'value' in p:
                        filtered_params[p['name']] = p['value']

                if self.get_option('legacy_hostvars'):
                    self.inventory.set_variable(host_name, 'foreman_params', filtered_params)
                else:
                    for k, v in filtered_params.items():
                        try:
                            self.inventory.set_variable(host_name, k, v)
                        except ValueError as e:
                            self.display.warning("Could not set hostvar %s to '%s' for the '%s' host, skipping:  %s" %
                                                 (k, to_native(v), host, to_native(e)))

            # set host vars from facts
            if self.get_option('want_facts'):
                self.inventory.set_variable(host_name, 'foreman_facts', self._get_facts(host))

            # create group for host collections
            if self.get_option('want_hostcollections'):
                host_data = self._get_host_data_by_id(host['id'])
                hostcollections = host_data.get('host_collections')
                if hostcollections:
                    # Create Ansible groups for host collections
                    for hostcollection in hostcollections:
                        try:
                            hostcollection_group = to_safe_group_name('%shostcollection_%s' % (self.get_option('group_prefix'),
                                                                      hostcollection['name'].lower().replace(" ", "")))
                            hostcollection_group = self.inventory.add_group(hostcollection_group)
                            self.inventory.add_child(hostcollection_group, host_name)
                        except ValueError as e:
                            self.display.warning("Could not create groups for host collections for %s, skipping: %s" % (host_name, to_text(e)))

            hostvars = self.inventory.get_host(host_name).get_vars()
            self._set_composite_vars(self.get_option('compose'), hostvars, host_name, strict)
            self._add_host_to_composed_groups(self.get_option('groups'), hostvars, host_name, strict)
            self._add_host_to_keyed_groups(self.get_option('keyed_groups'), hostvars, host_name, strict)

    def parse(self, inventory, loader, path, cache=True):

        super(InventoryModule, self).parse(inventory, loader, path)

        self.load_cache_plugin()

        # read config from file, this sets 'options'
        self._read_config_data(path)

        # get connection host
        self.foreman_url = self.get_option('url')
        self.cache_key = self.get_cache_key(path)
        self.use_cache = cache and self.get_option('cache')

        # actually populate inventory
        self._populate()
