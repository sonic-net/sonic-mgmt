# -*- coding: utf-8 -*-
# (c) Matthias Dellweg (ATIX AG) 2017

# pylint: disable=raise-missing-from
# pylint: disable=super-with-arguments

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import hashlib
import json
import os
import operator
import re
import traceback

from contextlib import contextmanager

from collections import defaultdict
from functools import wraps

from ansible.module_utils.basic import AnsibleModule, missing_required_lib, env_fallback
from ansible.module_utils.common.text.converters import to_bytes, to_native
from ansible.module_utils import six

try:
    from ansible_collections.theforeman.foreman.plugins.module_utils._version import LooseVersion
except ImportError:
    from plugins.module_utils._version import LooseVersion

try:
    try:
        from ansible_collections.theforeman.foreman.plugins.module_utils import _apypie as apypie
    except ImportError:
        from plugins.module_utils import _apypie as apypie
    import requests.exceptions
    HAS_APYPIE = True
    APYPIE_IMP_ERR = None
    inflector = apypie.Inflector()
except ImportError:
    HAS_APYPIE = False
    APYPIE_IMP_ERR = traceback.format_exc()

try:
    import yaml
    HAS_PYYAML = True
    PYYAML_IMP_ERR = None
except ImportError:
    HAS_PYYAML = False
    PYYAML_IMP_ERR = traceback.format_exc()

parameter_foreman_spec = dict(
    id=dict(invisible=True),
    name=dict(required=True),
    value=dict(type='raw', required=True),
    parameter_type=dict(default='string', choices=['string', 'boolean', 'integer', 'real', 'array', 'hash', 'yaml', 'json']),
    hidden_value=dict(type='bool'),
)

parameter_ansible_spec = {k: v for (k, v) in parameter_foreman_spec.items() if k != 'id'}

_PLUGIN_RESOURCES = {
    'ansible': 'ansible_roles',
    'discovery': 'discovery_rules',
    'katello': 'subscriptions',
    'openscap': 'scap_contents',
    'remote_execution': 'remote_execution_features',
    'scc_manager': 'scc_accounts',
    'snapshot_management': 'snapshots',
    'templates': 'templates',
}

ENTITY_KEYS = dict(
    hostgroups='title',
    locations='title',
    operatingsystems='title',
    # TODO: Organizations should be search by title (as foreman allows nested orgs) but that's not the case ATM.
    #       Applying this will need to record a lot of tests that is out of scope for the moment.
    # organizations='title',
    scap_contents='title',
    users='login',
)

PER_PAGE = 2 << 31


class NoEntity(object):
    pass


def _exception2fail_json(msg='Generic failure: {0}'):
    """
    Decorator to convert Python exceptions into Ansible errors that can be reported to the user.
    """

    def decor(f):
        @wraps(f)
        def inner(self, *args, **kwargs):
            try:
                return f(self, *args, **kwargs)
            except Exception as e:
                err_msg = "{0}: {1}".format(e.__class__.__name__, to_native(e))
                self.fail_from_exception(e, msg.format(err_msg))
        return inner
    return decor


def _check_patch_needed(introduced_version=None, fixed_version=None, plugins=None):
    """
    Decorator to check whether a specific apidoc patch is required.

    :param introduced_version: The version of Foreman the API bug was introduced.
    :type introduced_version: str, optional
    :param fixed_version: The version of Foreman the API bug was fixed.
    :type fixed_version: str, optional
    :param plugins: Which plugins are required for this patch.
    :type plugins: list, optional
    """

    def decor(f):
        @wraps(f)
        def inner(self, *args, **kwargs):
            if plugins is not None and not all(self.has_plugin(plugin) for plugin in plugins):
                return

            if fixed_version is not None and self.foreman_version >= LooseVersion(fixed_version):
                return

            if introduced_version is not None and self.foreman_version < LooseVersion(introduced_version):
                return

            return f(self, *args, **kwargs)
        return inner
    return decor


class KatelloMixin():
    """
    Katello Mixin to extend a :class:`ForemanAnsibleModule` (or any subclass) to work with Katello entities.

    This includes:

    * add a required ``organization`` parameter to the module
    * add Katello to the list of required plugins
    """

    def __init__(self, **kwargs):
        foreman_spec = dict(
            organization=dict(type='entity', required=True),
        )
        foreman_spec.update(kwargs.pop('foreman_spec', {}))
        required_plugins = kwargs.pop('required_plugins', [])
        required_plugins.append(('katello', ['*']))
        super(KatelloMixin, self).__init__(foreman_spec=foreman_spec, required_plugins=required_plugins, **kwargs)


class TaxonomyMixin(object):
    """
    Taxonomy Mixin to extend a :class:`ForemanAnsibleModule` (or any subclass) to work with taxonomic entities.

    This adds optional ``organizations`` and ``locations`` parameters to the module.
    """

    def __init__(self, **kwargs):
        foreman_spec = dict(
            organizations=dict(type='entity_list'),
            locations=dict(type='entity_list'),
        )
        foreman_spec.update(kwargs.pop('foreman_spec', {}))
        super(TaxonomyMixin, self).__init__(foreman_spec=foreman_spec, **kwargs)


class ParametersMixinBase(object):
    """
    Base Class for the Parameters Mixins.

    Provides a function to verify no duplicate parameters are set.
    """

    def validate_parameters(self):
        parameters = self.foreman_params.get('parameters')
        if parameters is not None:
            parameter_names = [param['name'] for param in parameters]
            duplicate_params = set([x for x in parameter_names if parameter_names.count(x) > 1])
            if duplicate_params:
                self.fail_json(msg="There are duplicate keys in 'parameters': {0}.".format(duplicate_params))


class ParametersMixin(ParametersMixinBase):
    """
    Parameters Mixin to extend a :class:`ForemanAnsibleModule` (or any subclass) to work with entities that support parameters.

    This allows to submit parameters to Foreman in the same request as modifying the main entity, thus making the parameters
    available to any action that might be triggered when the entity is saved.

    By default, parametes are submited to the API using the ``<entity_name>_parameters_attributes`` key.
    If you need to override this, set the ``PARAMETERS_FLAT_NAME`` attribute to the key that shall be used instead.

    This adds optional ``parameters`` parameter to the module. It also enhances the ``run()`` method to properly handle the
    provided parameters.
    """

    def __init__(self, **kwargs):
        self.entity_name = kwargs.pop('entity_name', self.entity_name_from_class)
        parameters_flat_name = getattr(self, "PARAMETERS_FLAT_NAME", None) or '{0}_parameters_attributes'.format(self.entity_name)
        foreman_spec = dict(
            parameters=dict(type='list', elements='dict', options=parameter_ansible_spec, flat_name=parameters_flat_name),
        )
        foreman_spec.update(kwargs.pop('foreman_spec', {}))
        super(ParametersMixin, self).__init__(foreman_spec=foreman_spec, **kwargs)

        self.validate_parameters()

    def run(self, **kwargs):
        entity = self.lookup_entity('entity', params={'show_hidden_parameters': True})
        if not self.desired_absent:
            if entity and 'parameters' in entity:
                entity['parameters'] = parameters_list_to_str_list(entity['parameters'])
            parameters = self.foreman_params.get('parameters')
            if parameters is not None:
                self.foreman_params['parameters'] = parameters_list_to_str_list(parameters)

        return super(ParametersMixin, self).run(**kwargs)


class NestedParametersMixin(ParametersMixinBase):
    """
    Nested Parameters Mixin to extend a :class:`ForemanAnsibleModule` (or any subclass) to work with entities that support parameters,
    but require them to be managed in separate API requests.

    This adds optional ``parameters`` parameter to the module. It also enhances the ``run()`` method to properly handle the
    provided parameters.
    """

    def __init__(self, **kwargs):
        foreman_spec = dict(
            parameters=dict(type='nested_list', foreman_spec=parameter_foreman_spec),
        )
        foreman_spec.update(kwargs.pop('foreman_spec', {}))
        super(NestedParametersMixin, self).__init__(foreman_spec=foreman_spec, **kwargs)

        self.validate_parameters()

    def run(self, **kwargs):
        new_entity = super(NestedParametersMixin, self).run(**kwargs)
        if new_entity:
            scope = {'{0}_id'.format(self.entity_name): new_entity['id']}
            self.ensure_scoped_parameters(scope)
        return new_entity

    def ensure_scoped_parameters(self, scope):
        parameters = self.foreman_params.get('parameters')
        if parameters is not None:
            entity = self.lookup_entity('entity')
            if self.state == 'present' or (self.state == 'present_with_defaults' and entity is None):
                if entity:
                    current_parameters = {parameter['name']: parameter for parameter in self.list_resource('parameters', params=scope)}
                else:
                    current_parameters = {}
                desired_parameters = {parameter['name']: parameter for parameter in parameters}

                for name in desired_parameters:
                    desired_parameter = desired_parameters[name]
                    desired_parameter['value'] = parameter_value_to_str(desired_parameter['value'], desired_parameter['parameter_type'])
                    current_parameter = current_parameters.pop(name, None)
                    if current_parameter:
                        if 'hidden_value?' in current_parameter:
                            current_parameter['hidden_value'] = current_parameter.pop('hidden_value?')
                        if 'parameter_type' not in current_parameter:
                            current_parameter['parameter_type'] = 'string'
                        current_parameter['value'] = parameter_value_to_str(current_parameter['value'], current_parameter['parameter_type'])
                    self.ensure_entity(
                        'parameters', desired_parameter, current_parameter, state="present", foreman_spec=parameter_foreman_spec, params=scope)
                for current_parameter in current_parameters.values():
                    self.ensure_entity(
                        'parameters', None, current_parameter, state="absent", foreman_spec=parameter_foreman_spec, params=scope)


class HostMixin(ParametersMixin):
    """
    Host Mixin to extend a :class:`ForemanAnsibleModule` (or any subclass) to work with host-related entities (Hosts, Hostgroups).

    This adds many optional parameters that are specific to Hosts and Hostgroups to the module.
    It also includes :class:`ParametersMixin`.
    """

    def __init__(self, **kwargs):
        foreman_spec = dict(
            compute_resource=dict(type='entity'),
            compute_profile=dict(type='entity'),
            domain=dict(type='entity'),
            subnet=dict(type='entity'),
            subnet6=dict(type='entity', resource_type='subnets'),
            root_pass=dict(no_log=True),
            realm=dict(type='entity'),
            architecture=dict(type='entity'),
            operatingsystem=dict(type='entity'),
            medium=dict(aliases=['media'], type='entity'),
            ptable=dict(type='entity'),
            pxe_loader=dict(choices=['PXELinux BIOS', 'PXELinux UEFI', 'Grub UEFI', 'Grub2 BIOS', 'Grub2 ELF',
                                     'Grub2 UEFI', 'Grub2 UEFI SecureBoot', 'Grub2 UEFI HTTP', 'Grub2 UEFI HTTPS',
                                     'Grub2 UEFI HTTPS SecureBoot', 'iPXE Embedded', 'iPXE UEFI HTTP', 'iPXE Chain BIOS', 'iPXE Chain UEFI', 'None']),
            environment=dict(type='entity'),
            puppetclasses=dict(type='entity_list', resolve=False),
            config_groups=dict(type='entity_list'),
            puppet_proxy=dict(type='entity', resource_type='smart_proxies'),
            puppet_ca_proxy=dict(type='entity', resource_type='smart_proxies'),
            openscap_proxy=dict(type='entity', resource_type='smart_proxies'),
            content_source=dict(type='entity', scope=['organization'], resource_type='smart_proxies'),
            lifecycle_environment=dict(type='entity', scope=['organization']),
            kickstart_repository=dict(type='entity', scope=['organization'], optional_scope=['lifecycle_environment', 'content_view'],
                                      resource_type='repositories'),
            content_view=dict(type='entity', scope=['organization'], optional_scope=['lifecycle_environment']),
            activation_keys=dict(no_log=False),
        )
        foreman_spec.update(kwargs.pop('foreman_spec', {}))
        required_plugins = kwargs.pop('required_plugins', []) + [
            ('katello', ['activation_keys', 'content_source', 'lifecycle_environment', 'kickstart_repository', 'content_view']),
            ('openscap', ['openscap_proxy']),
        ]
        mutually_exclusive = kwargs.pop('mutually_exclusive', []) + [['medium', 'kickstart_repository']]
        super(HostMixin, self).__init__(foreman_spec=foreman_spec, required_plugins=required_plugins, mutually_exclusive=mutually_exclusive, **kwargs)

    def run(self, **kwargs):
        entity = self.lookup_entity('entity')

        if not self.desired_absent:
            if 'activation_keys' in self.foreman_params:
                if 'parameters' not in self.foreman_params:
                    parameters = [param for param in (entity or {}).get('parameters', []) if param['name'] != 'kt_activation_keys']
                else:
                    parameters = self.foreman_params['parameters']
                ak_param = {'name': 'kt_activation_keys', 'parameter_type': 'string', 'value': self.foreman_params.pop('activation_keys')}
                self.foreman_params['parameters'] = parameters + [ak_param]
            elif 'parameters' in self.foreman_params and entity is not None:
                current_ak_param = next((param for param in entity.get('parameters') if param['name'] == 'kt_activation_keys'), None)
                desired_ak_param = next((param for param in self.foreman_params['parameters'] if param['name'] == 'kt_activation_keys'), None)
                if current_ak_param and desired_ak_param is None:
                    self.foreman_params['parameters'].append(current_ak_param)

        self.validate_parameters()

        return super(HostMixin, self).run(**kwargs)


class ForemanAnsibleModule(AnsibleModule):
    """ Baseclass for all foreman related Ansible modules.
        It handles connection parameters and adds the concept of the `foreman_spec`.
        This adds automatic entities resolution based on provided attributes/ sub entities options.

        It adds the following options to foreman_spec 'entity' and 'entity_list' types:

        * search_by (str): Field used to search the sub entity. Defaults to 'name' unless `parent` was set, in which case it defaults to `title`.
        * search_operator (str): Operator used to search the sub entity. Defaults to '='. For fuzzy search use '~'.
        * resource_type (str): Resource type used to build API resource PATH. Defaults to pluralized entity key.
        * resolve (boolean): Defaults to 'True'. If set to false, the sub entity will not be resolved automatically
        * ensure (boolean): Defaults to 'True'. If set to false, it will be removed before sending data to the foreman server.
    """

    def __init__(self, **kwargs):
        # State recording for changed and diff reporting
        self._changed = False
        self._before = defaultdict(list)
        self._after = defaultdict(list)
        self._after_full = defaultdict(list)

        self.foreman_spec, gen_args = _foreman_spec_helper(kwargs.pop('foreman_spec', {}))
        argument_spec = dict(
            server_url=dict(required=True, fallback=(env_fallback, ['FOREMAN_SERVER_URL', 'FOREMAN_SERVER', 'FOREMAN_URL'])),
            username=dict(required=False, fallback=(env_fallback, ['FOREMAN_USERNAME', 'FOREMAN_USER'])),
            password=dict(required=False, no_log=True, fallback=(env_fallback, ['FOREMAN_PASSWORD'])),
            validate_certs=dict(type='bool', default=True, fallback=(env_fallback, ['FOREMAN_VALIDATE_CERTS'])),
            use_gssapi=dict(type='bool', default=False, fallback=(env_fallback, ['FOREMAN_USE_GSSAPI'])),
            ca_path=dict(type='path', default=None, fallback=(env_fallback, ['FOREMAN_CA_PATH'])),
        )
        argument_spec.update(gen_args)
        argument_spec.update(kwargs.pop('argument_spec', {}))
        supports_check_mode = kwargs.pop('supports_check_mode', True)
        required_if = kwargs.pop('required_if', [])
        required_if.append(('use_gssapi', False, ('username', 'password')))

        self.required_plugins = kwargs.pop('required_plugins', [])

        super(ForemanAnsibleModule, self).__init__(argument_spec=argument_spec, supports_check_mode=supports_check_mode, required_if=required_if, **kwargs)

        aliases = {alias for arg in argument_spec.values() for alias in arg.get('aliases', [])}
        self.foreman_params = _recursive_dict_without_none(self.params, aliases)

        self.check_requirements()

        self._foremanapi_server_url = self.foreman_params.pop('server_url')
        self._foremanapi_username = self.foreman_params.pop('username', None)
        self._foremanapi_password = self.foreman_params.pop('password', None)
        self._foremanapi_validate_certs = self.foreman_params.pop('validate_certs')
        self._foremanapi_ca_path = self.foreman_params.pop('ca_path', None)
        self._foremanapi_use_gssapi = self.foreman_params.pop('use_gssapi')

        if self._foremanapi_server_url.lower().startswith('http://'):
            self.warn("You have configured a plain HTTP server URL. All communication will happen unencrypted.")
        elif not self._foremanapi_server_url.lower().startswith('https://'):
            self.fail_json(msg="The server URL needs to be either HTTPS or HTTP!")

        self.task_timeout = 60

        self._thin_default = False
        self.state = 'undefined'

    @contextmanager
    def api_connection(self):
        """
        Execute a given code block after connecting to the API.

        When the block has finished, call :func:`exit_json` to report that the module has finished to Ansible.
        """

        self.connect()
        yield
        self.exit_json()

    @property
    def changed(self):
        return self._changed

    def set_changed(self):
        self._changed = True

    def _patch_host_update(self):
        _host_methods = self.foremanapi.apidoc['docs']['resources']['hosts']['methods']

        _host_update = next(x for x in _host_methods if x['name'] == 'update')
        for param in ['location_id', 'organization_id']:
            _host_update_taxonomy_param = next((x for x in _host_update['params'] if x['name'] == param), None)
            if _host_update_taxonomy_param is not None:
                _host_update['params'].remove(_host_update_taxonomy_param)

    @_check_patch_needed(fixed_version='2.2.0', plugins=['remote_execution'])
    def _patch_subnet_rex_api(self):
        """
        This is a workaround for the broken subnet apidoc in foreman remote execution.
        See https://projects.theforeman.org/issues/19086 and https://projects.theforeman.org/issues/30651
        """

        _subnet_rex_proxies_parameter = {
            u'validations': [],
            u'name': u'remote_execution_proxy_ids',
            u'show': True,
            u'description': u'\n<p>Remote Execution Proxy IDs</p>\n',
            u'required': False,
            u'allow_nil': True,
            u'allow_blank': False,
            u'full_name': u'subnet[remote_execution_proxy_ids]',
            u'expected_type': u'array',
            u'metadata': None,
            u'validator': u'',
        }
        _subnet_methods = self.foremanapi.apidoc['docs']['resources']['subnets']['methods']

        _subnet_create = next(x for x in _subnet_methods if x['name'] == 'create')
        _subnet_create_params_subnet = next(x for x in _subnet_create['params'] if x['name'] == 'subnet')
        _subnet_create_params_subnet['params'].append(_subnet_rex_proxies_parameter)

        _subnet_update = next(x for x in _subnet_methods if x['name'] == 'update')
        _subnet_update_params_subnet = next(x for x in _subnet_update['params'] if x['name'] == 'subnet')
        _subnet_update_params_subnet['params'].append(_subnet_rex_proxies_parameter)

    @_check_patch_needed(introduced_version='2.1.0', fixed_version='2.3.0')
    def _patch_subnet_externalipam_group_api(self):
        """
        This is a workaround for the broken subnet apidoc for External IPAM.
        See https://projects.theforeman.org/issues/30890
        """

        _subnet_externalipam_group_parameter = {
            u'validations': [],
            u'name': u'externalipam_group',
            u'show': True,
            u'description': u'\n<p>External IPAM group - only relevant when IPAM is set to external</p>\n',
            u'required': False,
            u'allow_nil': True,
            u'allow_blank': False,
            u'full_name': u'subnet[externalipam_group]',
            u'expected_type': u'string',
            u'metadata': None,
            u'validator': u'',
        }
        _subnet_methods = self.foremanapi.apidoc['docs']['resources']['subnets']['methods']

        _subnet_create = next(x for x in _subnet_methods if x['name'] == 'create')
        _subnet_create_params_subnet = next(x for x in _subnet_create['params'] if x['name'] == 'subnet')
        _subnet_create_params_subnet['params'].append(_subnet_externalipam_group_parameter)

        _subnet_update = next(x for x in _subnet_methods if x['name'] == 'update')
        _subnet_update_params_subnet = next(x for x in _subnet_update['params'] if x['name'] == 'subnet')
        _subnet_update_params_subnet['params'].append(_subnet_externalipam_group_parameter)

    @_check_patch_needed(plugins=['katello'])
    def _patch_organization_update_api(self):
        """
        This is a workaround for the broken organization update apidoc in Katello.
        See https://projects.theforeman.org/issues/27538
        """

        _organization_methods = self.foremanapi.apidoc['docs']['resources']['organizations']['methods']

        _organization_update = next(x for x in _organization_methods if x['name'] == 'update')
        _organization_update_params_organization = next(x for x in _organization_update['params'] if x['name'] == 'organization')
        _organization_update_params_organization['required'] = False

    @_check_patch_needed(plugins=['katello'])
    def _patch_cv_filter_rule_api(self):
        """
        This is a workaround for missing params of CV Filter Rule update controller in Katello.
        See https://projects.theforeman.org/issues/30908
        """

        _content_view_filter_rule_methods = self.foremanapi.apidoc['docs']['resources']['content_view_filter_rules']['methods']

        _content_view_filter_rule_create = next(x for x in _content_view_filter_rule_methods if x['name'] == 'create')
        _content_view_filter_rule_update = next(x for x in _content_view_filter_rule_methods if x['name'] == 'update')

        for param_name in ['uuid', 'errata_ids', 'date_type', 'module_stream_ids']:
            create_param = next((x for x in _content_view_filter_rule_create['params'] if x['name'] == param_name), None)
            update_param = next((x for x in _content_view_filter_rule_update['params'] if x['name'] == param_name), None)
            if create_param is not None and update_param is None:
                _content_view_filter_rule_update['params'].append(create_param)

    @_check_patch_needed(fixed_version='3.5.0', plugins=['katello'])
    def _patch_ak_product_content_per_page(self):
        """
        This is a workaround for the API not exposing the per_page param on the product_content endpoint
        See https://projects.theforeman.org/issues/35633
        """

        _per_page_param = {
            "name": "per_page",
            "full_name": "per_page",
            "description": "\n<p>Number of results per page to return</p>\n",
            "required": False,
            "allow_nil": False,
            "allow_blank": False,
            "validator": "Must be a number.",
            "expected_type": "numeric",
            "metadata": None,
            "show": True,
            "validations": []
        }

        _ak_methods = self.foremanapi.apidoc['docs']['resources']['activation_keys']['methods']

        _ak_product_content = next(x for x in _ak_methods if x['name'] == 'product_content')

        if next((x for x in _ak_product_content['params'] if x['name'] == 'per_page'), None) is None:
            _ak_product_content['params'].append(_per_page_param)

    @_check_patch_needed(fixed_version='3.5.0', plugins=['katello'])
    def _patch_organization_ignore_types_api(self):
        """
        This is a workaround for the missing ignore_types in the organization apidoc in Katello.
        See https://projects.theforeman.org/issues/35687
        """

        _ignore_types_param = {
            "name": "ignore_types",
            "full_name": "organization[ignore_types]",
            "description": "\n<p>List of resources types that will be automatically associated</p>\n",
            "required": False,
            "allow_nil": True,
            "allow_blank": False,
            "validator": "Must be an array of any type",
            "expected_type": "array",
            "metadata": None,
            "show": True,
            "validations": []
        }

        _organization_methods = self.foremanapi.apidoc['docs']['resources']['organizations']['methods']

        _organization_create = next(x for x in _organization_methods if x['name'] == 'create')
        _organization_update = next(x for x in _organization_methods if x['name'] == 'update')
        if next((x for x in _organization_create['params'] if x['name'] == 'ignore_types'), None) is None:
            _organization_create['params'].append(_ignore_types_param)
            _organization_update['params'].append(_ignore_types_param)

    @_check_patch_needed(fixed_version='3.8.0', plugins=['katello'])
    def _patch_products_repositories_allow_nil_credential(self):
        """
        This is a workaround for the missing allow_nil: true in the Products and Repositories controllers
        See https://projects.theforeman.org/issues/36497
        """

        for resource in ['products', 'repositories']:
            methods = self.foremanapi.apidoc['docs']['resources'][resource]['methods']
            for action in ['create', 'update']:
                resource_action = next(x for x in methods if x['name'] == action)
                for param in ['gpg_key_id', 'ssl_ca_cert_id', 'ssl_client_cert_id', 'ssl_client_key_id']:
                    resource_param = next(x for x in resource_action['params'] if x['name'] == param)
                    resource_param['allow_nil'] = True

    def check_requirements(self):
        if not HAS_APYPIE:
            self.fail_json(msg=missing_required_lib("requests"), exception=APYPIE_IMP_ERR)

    @_exception2fail_json(msg="Failed to connect to Foreman server: {0}")
    def connect(self):
        """
        Connect to the Foreman API.

        This will create a new ``apypie.Api`` instance using the provided server information,
        check that the API is actually reachable (by calling :func:`status`),
        apply any required patches to the apidoc and ensure the server has all the plugins installed
        that are required by the module.
        """

        verify_ssl = self._foremanapi_ca_path if (self._foremanapi_validate_certs and self._foremanapi_ca_path) else self._foremanapi_validate_certs
        self.foremanapi = apypie.ForemanApi(
            uri=self._foremanapi_server_url,
            username=to_bytes(self._foremanapi_username),
            password=to_bytes(self._foremanapi_password),
            verify_ssl=verify_ssl,
            kerberos=self._foremanapi_use_gssapi,
            task_timeout=self.task_timeout,
        )

        _status = self.status()
        self.foreman_version = LooseVersion(_status.get('version', '0.0.0'))
        self.apply_apidoc_patches()
        self.check_required_plugins()

    def apply_apidoc_patches(self):
        """
        Apply patches to the local apidoc representation.
        When adding another patch, consider that the endpoint in question may depend on a plugin to be available.
        If possible, make the patch only execute on specific server/plugin versions.
        """

        self._patch_host_update()

        self._patch_subnet_rex_api()
        self._patch_subnet_externalipam_group_api()

        # Katello
        self._patch_organization_update_api()
        self._patch_cv_filter_rule_api()
        self._patch_ak_product_content_per_page()
        self._patch_organization_ignore_types_api()
        self._patch_products_repositories_allow_nil_credential()

    @_exception2fail_json(msg="Failed to connect to Foreman server: {0}")
    def status(self):
        """
        Call the ``status`` API endpoint to ensure the server is reachable.

        :return: The full API response
        :rtype: dict
        """

        return self.foremanapi.resource('home').call('status')

    @_exception2fail_json(msg='Failed to show resource: {0}')
    def show_resource(self, resource, resource_id, params=None):
        """
        Execute the ``show`` action on an entity.

        :param resource: Plural name of the api resource to show
        :type resource: str
        :param resource_id: The ID of the entity to show
        :type resource_id: int
        :param params: Lookup parameters (i.e. parent_id for nested entities)
        :type params: Union[dict,None], optional
        """

        return self.foremanapi.show(resource, resource_id, params)

    @_exception2fail_json(msg='Failed to list resource: {0}')
    def list_resource(self, resource, search=None, params=None):
        """
        Execute the ``index`` action on an resource.

        :param resource: Plural name of the api resource to show
        :type resource: str
        :param search: Search string as accepted by the API to limit the results
        :type search: str, optional
        :param params: Lookup parameters (i.e. parent_id for nested entities)
        :type params: Union[dict,None], optional
        """

        return self.foremanapi.list(resource, search, params)

    def find_resource(self, resource, search, params=None, failsafe=False, thin=None):
        list_params = {}
        if params is not None:
            list_params.update(params)
        if thin is None:
            thin = self._thin_default
        list_params['thin'] = thin
        results = self.list_resource(resource, search, list_params)
        if len(results) == 1:
            result = results[0]
        elif failsafe:
            result = None
        else:
            if len(results) > 1:
                error_msg = "too many ({0})".format(len(results))
            else:
                error_msg = "no"
            self.fail_json(msg="Found {0} results while searching for {1} with {2}".format(error_msg, resource, search))
        if result and not thin:
            result = self.show_resource(resource, result['id'], params=params)
        return result

    def find_resource_by(self, resource, search_field, value, **kwargs):
        if not value:
            return NoEntity
        search = '{0}{1}"{2}"'.format(search_field, kwargs.pop('search_operator', '='), value)
        return self.find_resource(resource, search, **kwargs)

    def find_resource_by_name(self, resource, name, **kwargs):
        return self.find_resource_by(resource, 'name', name, **kwargs)

    def find_resource_by_title(self, resource, title, **kwargs):
        return self.find_resource_by(resource, 'title', title, **kwargs)

    def find_resource_by_id(self, resource, obj_id, **kwargs):
        return self.find_resource_by(resource, 'id', obj_id, **kwargs)

    def find_resources_by_name(self, resource, names, **kwargs):
        return [self.find_resource_by_name(resource, name, **kwargs) for name in names]

    def find_operatingsystem(self, name, failsafe=False, **kwargs):
        result = self.find_resource_by_title('operatingsystems', name, failsafe=True, **kwargs)
        if not result:
            result = self.find_resource_by('operatingsystems', 'title', name, search_operator='~', failsafe=failsafe, **kwargs)
        return result

    def find_puppetclass(self, name, environment=None, params=None, failsafe=False, thin=None):
        if thin is None:
            thin = self._thin_default
        if environment:
            scope = {'environment_id': environment}
        else:
            scope = {}
        if params is not None:
            scope.update(params)
        search = 'name="{0}"'.format(name)
        results = self.list_resource('puppetclasses', search, params=scope)

        # verify that only one puppet module is returned with only one puppet class inside
        # as provided search results have to be like "results": { "ntp": [{"id": 1, "name": "ntp" ...}]}
        # and get the puppet class id
        if len(results) == 1 and len(list(results.values())[0]) == 1:
            result = list(results.values())[0][0]
            if thin:
                return {'id': result['id']}
            else:
                return result

        if failsafe:
            return None
        else:
            self.fail_json(msg='No data found for name="%s"' % search)

    def find_puppetclasses(self, names, **kwargs):
        return [self.find_puppetclass(name, **kwargs) for name in names]

    def find_cluster(self, name, compute_resource):
        cluster = self.find_compute_resource_parts('clusters', name, compute_resource, None, ['ovirt', 'vmware'])

        # workaround for https://projects.theforeman.org/issues/31874
        if compute_resource['provider'].lower() == 'vmware':
            path_or_name = cluster.get('full_path', cluster['name'])
            cluster['_api_identifier'] = path_or_name
        else:
            cluster['_api_identifier'] = cluster['id']

        return cluster

    def find_network(self, name, compute_resource, cluster=None):
        return self.find_compute_resource_parts('networks', name, compute_resource, cluster, ['ovirt', 'vmware', 'google', 'azurerm'])

    def find_storage_domain(self, name, compute_resource, cluster=None):
        return self.find_compute_resource_parts('storage_domains', name, compute_resource, cluster, ['ovirt', 'vmware'])

    def find_storage_pod(self, name, compute_resource, cluster=None):
        return self.find_compute_resource_parts('storage_pods', name, compute_resource, cluster, ['vmware'])

    def find_compute_resource_parts(self, part_name, name, compute_resource, cluster=None, supported_crs=None):
        if supported_crs is None:
            supported_crs = []

        if compute_resource['provider'].lower() not in supported_crs:
            return {'id': name, 'name': name}

        additional_params = {'id': compute_resource['id']}
        if cluster is not None:
            # apypie will quote the params for us, but we need to do it twice for the cluster_id
            # see https://projects.theforeman.org/issues/35438
            # and https://github.com/theforeman/hammer-cli-foreman/pull/604
            # and https://github.com/theforeman/foreman/pull/9383
            # and https://httpd.apache.org/docs/current/mod/core.html#allowencodedslashes
            additional_params['cluster_id'] = six.moves.urllib.parse.quote(cluster['_api_identifier'], safe='')
        api_name = 'available_{0}'.format(part_name)
        available_parts = self.resource_action('compute_resources', api_name, params=additional_params,
                                               ignore_check_mode=True, record_change=False)['results']
        part = next((part for part in available_parts
                     if str(part['name']) == str(name) or str(part['id']) == str(name) or part.get('full_path') == str(name)),
                    None)
        if part is None:
            err_msg = "Could not find {0} '{1}' on compute resource '{2}'.".format(part_name, name, compute_resource.get('name'))
            self.fail_json(msg=err_msg)
        return part

    def scope_for(self, key, scoped_resource=None):
        # workaround for https://projects.theforeman.org/issues/31714
        if scoped_resource in ['content_views', 'repositories'] and key == 'lifecycle_environment':
            scope_key = 'environment'
        else:
            scope_key = key
        return {'{0}_id'.format(scope_key): self.lookup_entity(key)['id']}

    def set_entity(self, key, entity):
        self.foreman_params[key] = entity

    def lookup_entity(self, key, params=None):
        if key not in self.foreman_params:
            return None

        entity_spec = self.foreman_spec[key]
        if _is_resolved(entity_spec, self.foreman_params[key]):
            # Already looked up or not an entity(_list) so nothing to do
            return self.foreman_params[key]

        result = self._lookup_entity(self.foreman_params[key], entity_spec, params)
        self.set_entity(key, result)
        return result

    def _lookup_entity(self, identifier, entity_spec, params=None):
        if identifier is NoEntity:
            return NoEntity
        resource_type = entity_spec['resource_type']
        failsafe = entity_spec.get('failsafe', False)
        thin = entity_spec.get('thin', True)
        if params:
            params = params.copy()
        else:
            params = {}
        try:
            for scope in entity_spec.get('scope', []):
                params.update(self.scope_for(scope, resource_type))
            for optional_scope in entity_spec.get('optional_scope', []):
                if optional_scope in self.foreman_params:
                    params.update(self.scope_for(optional_scope, resource_type))

        except TypeError:
            if failsafe:
                if entity_spec.get('type') == 'entity':
                    result = None
                else:
                    result = [None for value in identifier]
            else:
                self.fail_json(msg="Failed to lookup scope {0} while searching for {1}.".format(entity_spec['scope'], resource_type))
        else:
            # No exception happend => scope is in place
            if resource_type == 'operatingsystems':
                if entity_spec.get('type') == 'entity':
                    result = self.find_operatingsystem(identifier, params=params, failsafe=failsafe, thin=thin)
                else:
                    result = [self.find_operatingsystem(value, params=params, failsafe=failsafe, thin=thin) for value in identifier]
            elif resource_type == 'puppetclasses':
                if entity_spec.get('type') == 'entity':
                    result = self.find_puppetclass(identifier, params=params, failsafe=failsafe, thin=thin)
                else:
                    result = [self.find_puppetclass(value, params=params, failsafe=failsafe, thin=thin) for value in identifier]
            else:
                if entity_spec.get('type') == 'entity':
                    result = self.find_resource_by(
                        resource=resource_type,
                        value=identifier,
                        search_field=entity_spec.get('search_by', ENTITY_KEYS.get(resource_type, 'name')),
                        search_operator=entity_spec.get('search_operator', '='),
                        failsafe=failsafe, thin=thin, params=params,
                    )
                else:
                    result = [self.find_resource_by(
                        resource=resource_type,
                        value=value,
                        search_field=entity_spec.get('search_by', ENTITY_KEYS.get(resource_type, 'name')),
                        search_operator=entity_spec.get('search_operator', '='),
                        failsafe=failsafe, thin=thin, params=params,
                    ) for value in identifier]
        return result

    def auto_lookup_entities(self):
        self.auto_lookup_nested_entities()
        return [
            self.lookup_entity(key)
            for key, entity_spec in self.foreman_spec.items()
            if entity_spec.get('resolve', True) and entity_spec.get('type') in {'entity', 'entity_list'}
        ]

    def auto_lookup_nested_entities(self):
        for key, entity_spec in self.foreman_spec.items():
            if entity_spec.get('type') in {'nested_list'}:
                for nested_key, nested_spec in entity_spec['foreman_spec'].items():
                    for item in self.foreman_params.get(key, []):
                        if (nested_key in item and nested_spec.get('resolve', True)
                                and not _is_resolved(nested_spec, item[nested_key])):
                            item[nested_key] = self._lookup_entity(item[nested_key], nested_spec)

    def record_before(self, resource, entity):
        if isinstance(entity, dict):
            to_record = _recursive_dict_without_none(entity)
        else:
            to_record = entity
        self._before[resource].append(to_record)

    def record_after(self, resource, entity):
        if isinstance(entity, dict):
            to_record = _recursive_dict_without_none(entity)
        else:
            to_record = entity
        self._after[resource].append(to_record)

    def record_after_full(self, resource, entity):
        self._after_full[resource].append(entity)

    @_exception2fail_json(msg='Failed to ensure entity state: {0}')
    def ensure_entity(self, resource, desired_entity, current_entity, params=None, state=None, foreman_spec=None):
        """
        Ensure that a given entity has a certain state

        :param resource: Plural name of the api resource to manipulate
        :type resource: str
        :param desired_entity: Desired properties of the entity
        :type desired_entity: dict
        :param current_entity: Current properties of the entity or None if nonexistent
        :type current_entity: Union[dict,None]
        :param params: Lookup parameters (i.e. parent_id for nested entities)
        :type params: dict, optional
        :param state: Desired state of the entity (optionally taken from the module)
        :type state: str, optional
        :param foreman_spec: Description of the entity structure (optionally taken from module)
        :type foreman_spec: dict, optional

        :return: The new current state of the entity
        :rtype: Union[dict,None]
        """
        if state is None:
            state = self.state
        if foreman_spec is None:
            foreman_spec = self.foreman_spec
        else:
            foreman_spec, _dummy = _foreman_spec_helper(foreman_spec)

        updated_entity = None

        self.record_before(resource, _flatten_entity(current_entity, foreman_spec))

        if state == 'present_with_defaults':
            if current_entity is None:
                updated_entity = self._create_entity(resource, desired_entity, params, foreman_spec)
        elif state == 'present':
            if current_entity is None:
                updated_entity = self._create_entity(resource, desired_entity, params, foreman_spec)
            else:
                updated_entity = self._update_entity(resource, desired_entity, current_entity, params, foreman_spec)
        elif state == 'copied':
            if current_entity is not None:
                updated_entity = self._copy_entity(resource, desired_entity, current_entity, params)
        elif state == 'reverted':
            if current_entity is not None:
                updated_entity = self._revert_entity(resource, current_entity, params)
        elif state == 'new_snapshot':
            updated_entity = self._create_entity(resource, desired_entity, params, foreman_spec)
        elif state == 'absent':
            if current_entity is not None:
                updated_entity = self._delete_entity(resource, current_entity, params)
        else:
            self.fail_json(msg='Not a valid state: {0}'.format(state))

        self.record_after(resource, _flatten_entity(updated_entity, foreman_spec))
        self.record_after_full(resource, updated_entity)

        return updated_entity

    def _validate_supported_payload(self, resource, action, payload):
        """
        Check whether the payload only contains supported keys.
        Emits a warning for keys that are not part of the apidoc.

        :param resource: Plural name of the api resource to check
        :type resource: str
        :param action: Name of the action to check payload against
        :type action: str
        :param payload: API paylod to be checked
        :type payload: dict

        :return: The payload as it can be submitted to the API
        :rtype: dict
        """
        filtered_payload, unsupported_parameters = self.foremanapi.validate_payload(resource, action, payload)
        if unsupported_parameters:
            warn_msg = "The following parameters are not supported by your server when performing {0} on {1}: {2}. They were ignored."
            self.warn(warn_msg.format(action, resource, unsupported_parameters))
        return filtered_payload

    def _create_entity(self, resource, desired_entity, params, foreman_spec):
        """
        Create entity with given properties

        :param resource: Plural name of the api resource to manipulate
        :type resource: str
        :param desired_entity: Desired properties of the entity
        :type desired_entity: dict
        :param params: Lookup parameters (i.e. parent_id for nested entities)
        :type params: dict, optional
        :param foreman_spec: Description of the entity structure
        :type foreman_spec: dict

        :return: The new current state of the entity
        :rtype: dict
        """
        payload = _flatten_entity(desired_entity, foreman_spec)
        self._validate_supported_payload(resource, 'create', payload)
        self.set_changed()
        if not self.check_mode:
            return self.foremanapi.create(resource, payload, params)
        else:
            fake_entity = desired_entity.copy()
            fake_entity['id'] = -1
            return fake_entity

    def _update_entity(self, resource, desired_entity, current_entity, params, foreman_spec):
        """
        Update a given entity with given properties if any diverge

        :param resource: Plural name of the api resource to manipulate
        :type resource: str
        :param desired_entity: Desired properties of the entity
        :type desired_entity: dict
        :param current_entity: Current properties of the entity
        :type current_entity: dict
        :param params: Lookup parameters (i.e. parent_id for nested entities)
        :type params: dict, optional
        :param foreman_spec: Description of the entity structure
        :type foreman_spec: dict

        :return: The new current state of the entity
        :rtype: dict
        """
        payload = {}
        desired_entity = _flatten_entity(desired_entity, foreman_spec)
        current_flat_entity = _flatten_entity(current_entity, foreman_spec)
        for key, value in desired_entity.items():
            foreman_type = foreman_spec[key].get('type', 'str')
            new_value = value
            old_value = current_flat_entity.get(key)
            # String comparison needs extra care in face of unicode
            if foreman_type == 'str':
                old_value = to_native(old_value)
                new_value = to_native(new_value)
            # ideally the type check would happen via foreman_spec.elements
            # however this is not set for flattened entries and setting it
            # confuses _flatten_entity
            elif foreman_type == 'list' and value and isinstance(value[0], dict):
                # special handling for parameters created by ParametersMixin
                # they are defined as a list of dict, but the dicts should be really handled like
                # entities, which means we only want to update the user-provided details
                if key.endswith('_parameters_attributes'):
                    for new_param in new_value:
                        old_param = next((x for x in old_value if x['name'] == new_param['name']), None)
                        if old_param is not None:
                            for pop_key in set(old_param.keys()) - set(new_param.keys()):
                                old_param.pop(pop_key)
                if 'name' in value[0]:
                    sort_key = 'name'
                else:
                    sort_key = list(value[0].keys())[0]
                new_value = sorted(new_value, key=operator.itemgetter(sort_key))
                old_value = sorted(old_value, key=operator.itemgetter(sort_key))
            if new_value != old_value:
                payload[key] = value
        # workaround to ensure LCE and CV are always sent together, even if only one changed
        # using the values from the existing entity, so the user doesn't need to pass it in their playbook
        if resource == 'hosts':
            if 'content_view_id' in payload and 'lifecycle_environment_id' not in payload:
                payload['lifecycle_environment_id'] = current_flat_entity['lifecycle_environment_id']
            elif 'lifecycle_environment_id' in payload and 'content_view_id' not in payload:
                payload['content_view_id'] = current_flat_entity['content_view_id']
        elif resource == 'activation_keys':
            if 'content_view_id' in payload and 'environment_id' not in payload:
                payload['environment_id'] = current_flat_entity['environment_id']
            elif 'environment_id' in payload and 'content_view_id' not in payload:
                payload['content_view_id'] = current_flat_entity['content_view_id']
        if self._validate_supported_payload(resource, 'update', payload):
            self.set_changed()
            payload['id'] = current_flat_entity['id']
            if not self.check_mode:
                return self.foremanapi.update(resource, payload, params)
            else:
                # In check_mode we emulate the server updating the entity
                fake_entity = current_flat_entity.copy()
                fake_entity.update(payload)
                return fake_entity
        else:
            # Nothing needs changing
            return current_entity

    def _copy_entity(self, resource, desired_entity, current_entity, params):
        """
        Copy a given entity

        :param resource: Plural name of the api resource to manipulate
        :type resource: str
        :param desired_entity: Desired properties of the entity
        :type desired_entity: dict
        :param current_entity: Current properties of the entity
        :type current_entity: dict
        :param params: Lookup parameters (i.e. parent_id for nested entities)
        :type params: dict, optional

        :return: The new current state of the entity
        :rtype: dict
        """
        payload = {
            'id': current_entity['id'],
            'new_name': desired_entity['new_name'],
        }
        if params:
            payload.update(params)
        return self.resource_action(resource, 'copy', payload)

    def _revert_entity(self, resource, current_entity, params):
        """
        Revert a given entity

        :param resource: Plural name of the api resource to manipulate
        :type resource: str
        :param current_entity: Current properties of the entity
        :type current_entity: dict
        :param params: Lookup parameters (i.e. parent_id for nested entities)
        :type params: dict, optional

        :return: The new current state of the entity
        :rtype: dict
        """
        payload = {'id': current_entity['id']}
        if params:
            payload.update(params)
        return self.resource_action(resource, 'revert', payload)

    def _delete_entity(self, resource, current_entity, params):
        """
        Delete a given entity

        :param resource: Plural name of the api resource to manipulate
        :type resource: str
        :param current_entity: Current properties of the entity
        :type current_entity: dict
        :param params: Lookup parameters (i.e. parent_id for nested entities)
        :type params: dict, optional

        :return: The new current state of the entity
        :rtype: Union[dict,None]
        """
        self.set_changed()
        if not self.check_mode:
            return self.foremanapi.delete(resource, current_entity, params)
        else:
            return None

    def resource_action(self, resource, action, params, options=None, data=None, files=None,
                        ignore_check_mode=False, record_change=True, ignore_task_errors=False):
        try:
            result = None
            if ignore_check_mode or not self.check_mode:
                result = self.foremanapi.resource_action(resource, action, params, options, data, files, ignore_task_errors)
        except Exception as e:
            msg = 'Error while performing {0} on {1}: {2}'.format(
                action, resource, to_native(e))
            self.fail_from_exception(e, msg)
        if record_change and not ignore_check_mode:
            # If we were supposed to ignore check_mode we can assume this action was not a changing one.
            self.set_changed()
        return result

    def wait_for_task(self, task, ignore_errors=False):
        return self.foremanapi.wait_for_task(task, ignore_errors)

    def fail_from_exception(self, exc, msg):
        fail = {'msg': msg}
        if isinstance(exc, requests.exceptions.HTTPError):
            try:
                response = exc.response.json()
                if 'error' in response:
                    fail['error'] = response['error']
                else:
                    fail['error'] = response
            except Exception:
                fail['error'] = exc.response.text
        self.fail_json(**fail)

    def exit_json(self, changed=False, **kwargs):
        kwargs['changed'] = changed or self.changed
        if 'diff' not in kwargs and (self._before or self._after):
            kwargs['diff'] = {'before': self._before,
                              'after': self._after}
        if 'entity' not in kwargs and self._after_full:
            kwargs['entity'] = self._after_full
        super(ForemanAnsibleModule, self).exit_json(**kwargs)

    def has_plugin(self, plugin_name):
        try:
            resource_name = _PLUGIN_RESOURCES[plugin_name]
        except KeyError:
            raise Exception("Unknown plugin: {0}".format(plugin_name))
        return resource_name in self.foremanapi.resources

    def check_required_plugins(self):
        missing_plugins = []
        for (plugin, params) in self.required_plugins:
            for param in params:
                if (param in self.foreman_params or param == '*') and not self.has_plugin(plugin):
                    if param == '*':
                        param = 'the whole module'
                    missing_plugins.append("{0} (for {1})".format(plugin, param))
        if missing_plugins:
            missing_msg = "The server is missing required plugins: {0}.".format(', '.join(missing_plugins))
            self.fail_json(msg=missing_msg)


class ForemanStatelessEntityAnsibleModule(ForemanAnsibleModule):
    """ Base class for Foreman entities without a state. To use it, subclass it with the following convention:
        To manage my_entity entity, create the following sub class::

            class ForemanMyEntityModule(ForemanStatelessEntityAnsibleModule):
                pass

        and use that class to instantiate module::

            module = ForemanMyEntityModule(
                argument_spec=dict(
                    [...]
                ),
                foreman_spec=dict(
                    [...]
                ),
            )

        It adds the following attributes:

        * entity_key (str): field used to search current entity. Defaults to value provided by `ENTITY_KEYS` or 'name' if no value found.
        * entity_name (str): name of the current entity.
          By default deduce the entity name from the class name (eg: 'ForemanProvisioningTemplateModule' class will produce 'provisioning_template').
        * entity_opts (dict): Dict of options for base entity. Same options can be provided for subentities described in foreman_spec.

        The main entity is referenced with the key `entity` in the `foreman_spec`.
    """

    def __init__(self, **kwargs):
        self.entity_key = kwargs.pop('entity_key', 'name')
        self.entity_name = kwargs.pop('entity_name', self.entity_name_from_class)
        entity_opts = kwargs.pop('entity_opts', {})

        super(ForemanStatelessEntityAnsibleModule, self).__init__(**kwargs)

        if 'resource_type' not in entity_opts:
            entity_opts['resource_type'] = inflector.pluralize(self.entity_name)
        if 'thin' not in entity_opts:
            # Explicit None to trigger the _thin_default mechanism lazily
            entity_opts['thin'] = None
        if 'failsafe' not in entity_opts:
            entity_opts['failsafe'] = True
        if 'search_operator' not in entity_opts:
            entity_opts['search_operator'] = '='
        if 'search_by' not in entity_opts:
            entity_opts['search_by'] = ENTITY_KEYS.get(entity_opts['resource_type'], 'name')

        self.foreman_spec.update(_foreman_spec_helper(dict(
            entity=dict(
                type='entity',
                flat_name='id',
                ensure=False,
                **entity_opts
            ),
        ))[0])

        if 'parent' in self.foreman_spec and self.foreman_spec['parent'].get('type') == 'entity':
            # ensure parent and entity are the same type
            self.foreman_spec['parent']['resource_type'] = self.foreman_spec['entity']['resource_type']
            if 'failsafe' not in self.foreman_spec['parent']:
                self.foreman_spec['parent']['failsafe'] = True
            current, parent = split_fqn(self.foreman_params[self.entity_key])
            if isinstance(self.foreman_params.get('parent'), six.string_types):
                if parent:
                    self.fail_json(msg="Please specify the parent either separately, or as part of the title.")
                parent = self.foreman_params['parent']
            elif parent:
                self.foreman_params['parent'] = parent
            self.foreman_params[self.entity_key] = current
            self.foreman_params['entity'] = build_fqn(current, parent)
        else:
            self.foreman_params['entity'] = self.foreman_params.get(self.entity_key)

    @property
    def entity_name_from_class(self):
        """
        The entity name derived from the class name.

        The class name must follow the following name convention:

        * It starts with ``Foreman`` or ``Katello``.
        * It ends with ``Module``.

        This will convert the class name ``ForemanMyEntityModule`` to the entity name ``my_entity``.

        Examples:

        * ``ForemanArchitectureModule`` => ``architecture``
        * ``ForemanProvisioningTemplateModule`` => ``provisioning_template``
        * ``KatelloProductMudule`` => ``product``
        """
        # Convert current class name from CamelCase to snake_case
        class_name = re.sub(r'(?<=[a-z])[A-Z]|[A-Z](?=[^A-Z])', r'_\g<0>', self.__class__.__name__).lower().strip('_')
        # Get entity name from snake case class name
        return '_'.join(class_name.split('_')[1:-1])


class ForemanInfoAnsibleModule(ForemanStatelessEntityAnsibleModule):
    """
    Base class for Foreman info modules that fetch information about entities
    """
    def __init__(self, **kwargs):
        self._resources = []
        foreman_spec = dict(
            name=dict(),
            search=dict(),
            organization=dict(type='entity'),
            location=dict(type='entity'),
        )
        foreman_spec.update(kwargs.pop('foreman_spec', {}))
        mutually_exclusive = kwargs.pop('mutually_exclusive', [])
        if not foreman_spec['name'].get('invisible', False):
            mutually_exclusive.extend([['name', 'search']])
        super(ForemanInfoAnsibleModule, self).__init__(foreman_spec=foreman_spec, mutually_exclusive=mutually_exclusive, **kwargs)

    def run(self, **kwargs):
        """
        lookup entities
        """
        self.auto_lookup_entities()

        resource = self.foreman_spec['entity']['resource_type']

        if 'name' in self.foreman_params:
            self._info_result = {self.entity_name: self.lookup_entity('entity')}
        else:
            _flat_entity = _flatten_entity(self.foreman_params, self.foreman_spec)
            self._info_result = {resource: self.list_resource(resource, self.foreman_params.get('search'), _flat_entity)}

    def exit_json(self, **kwargs):
        kwargs.update(self._info_result)
        super(ForemanInfoAnsibleModule, self).exit_json(**kwargs)


class ForemanEntityAnsibleModule(ForemanStatelessEntityAnsibleModule):
    """ Base class for Foreman entities. To use it, subclass it with the following convention:
        To manage my_entity entity, create the following sub class::

            class ForemanMyEntityModule(ForemanEntityAnsibleModule):
                pass

        and use that class to instantiate module::

            module = ForemanMyEntityModule(
                argument_spec=dict(
                    [...]
                ),
                foreman_spec=dict(
                    [...]
                ),
            )

        This adds a `state` parameter to the module and provides the `run` method for the most
        common usecases.
    """

    def __init__(self, **kwargs):
        argument_spec = dict(
            state=dict(choices=['present', 'absent'], default='present'),
        )
        argument_spec.update(kwargs.pop('argument_spec', {}))
        super(ForemanEntityAnsibleModule, self).__init__(argument_spec=argument_spec, **kwargs)

        self.state = self.foreman_params.pop('state')
        self.desired_absent = self.state == 'absent'
        self._thin_default = self.desired_absent

    def run(self, **kwargs):
        """ lookup entities, ensure entity, remove sensitive data, manage parameters.
        """
        parent_name = self.foreman_params.get('parent')
        if ('parent' in self.foreman_spec and self.foreman_spec['parent'].get('type') == 'entity'
                and 'parent' in self.foreman_params and self.lookup_entity('parent') is None):
            if self.desired_absent:
                # Parent does not exist so just exit here
                return None
            else:
                self.fail_json(msg="Couldn't find parent '{0}' for '{1}'.".format(parent_name, self.foreman_params['name']))
        if not self.desired_absent:
            self.auto_lookup_entities()
        entity = self.lookup_entity('entity')

        if not self.desired_absent:
            updated_key = "updated_" + self.entity_key
            if entity and updated_key in self.foreman_params:
                self.foreman_params[self.entity_key] = self.foreman_params.pop(updated_key)

        params = kwargs.get('params', {})
        for scope in self.foreman_spec['entity'].get('scope', []):
            params.update(self.scope_for(scope))
        for optional_scope in self.foreman_spec['entity'].get('optional_scope', []):
            if optional_scope in self.foreman_params:
                params.update(self.scope_for(optional_scope))
        new_entity = self.ensure_entity(self.foreman_spec['entity']['resource_type'], self.foreman_params, entity, params=params)
        new_entity = self.remove_sensitive_fields(new_entity)

        return new_entity

    def remove_sensitive_fields(self, entity):
        """ Set fields with 'no_log' option to None """
        if entity:
            for blacklisted_field in self.blacklisted_fields:
                entity[blacklisted_field] = None
        return entity

    @property
    def blacklisted_fields(self):
        return [key for key, value in self.foreman_spec.items() if value.get('no_log', False)]


class ForemanTaxonomicAnsibleModule(TaxonomyMixin, ForemanAnsibleModule):
    """
    Combine :class:`ForemanAnsibleModule` with the :class:`TaxonomyMixin` Mixin.
    """

    pass


class ForemanTaxonomicEntityAnsibleModule(TaxonomyMixin, ForemanEntityAnsibleModule):
    """
    Combine :class:`ForemanEntityAnsibleModule` with the :class:`TaxonomyMixin` Mixin.
    """

    pass


class ForemanScapDataStreamModule(ForemanTaxonomicEntityAnsibleModule):
    def __init__(self, **kwargs):
        foreman_spec = dict(
            original_filename=dict(type='str'),
            scap_file=dict(type='path'),
        )
        foreman_spec.update(kwargs.pop('foreman_spec', {}))
        super(ForemanScapDataStreamModule, self).__init__(foreman_spec=foreman_spec, **kwargs)

    def run(self, **kwargs):
        entity = self.lookup_entity('entity')

        if not self.desired_absent:
            if not entity and 'scap_file' not in self.foreman_params:
                self.fail_json(msg="Content of scap_file not provided. XML containing SCAP content is required.")

            if 'scap_file' in self.foreman_params and 'original_filename' not in self.foreman_params:
                self.foreman_params['original_filename'] = os.path.basename(self.foreman_params['scap_file'])

            if 'scap_file' in self.foreman_params:
                with open(self.foreman_params['scap_file']) as input_file:
                    self.foreman_params['scap_file'] = input_file.read()

            if entity and 'scap_file' in self.foreman_params:
                digest = hashlib.sha256(self.foreman_params['scap_file'].encode("utf-8")).hexdigest()
                # workaround for https://projects.theforeman.org/issues/29409
                digest_stripped = hashlib.sha256(self.foreman_params['scap_file'].strip().encode("utf-8")).hexdigest()
                if entity['digest'] in [digest, digest_stripped]:
                    self.foreman_params.pop('scap_file')

        return super(ForemanScapDataStreamModule, self).run(**kwargs)


class KatelloAnsibleModule(KatelloMixin, ForemanAnsibleModule):
    """
    Combine :class:`ForemanAnsibleModule` with the :class:`KatelloMixin` Mixin.
    """

    pass


class KatelloScopedMixin(KatelloMixin):
    """
    Enhances :class:`KatelloMixin` with scoping by ``organization`` as required by Katello.
    """

    def __init__(self, **kwargs):
        entity_opts = kwargs.pop('entity_opts', {})
        if 'scope' not in entity_opts:
            entity_opts['scope'] = ['organization']
        elif 'organization' not in entity_opts['scope']:
            entity_opts['scope'].append('organization')
        super(KatelloScopedMixin, self).__init__(entity_opts=entity_opts, **kwargs)


class KatelloInfoAnsibleModule(KatelloScopedMixin, ForemanInfoAnsibleModule):
    """
    Combine :class:`ForemanInfoAnsibleModule` with the :class:`KatelloScopedMixin` Mixin.
    """

    pass


class KatelloEntityAnsibleModule(KatelloScopedMixin, ForemanEntityAnsibleModule):
    """
    Combine :class:`ForemanEntityAnsibleModule` with the :class:`KatelloScopedMixin` Mixin.
    """

    pass


class KatelloContentExportBaseModule(KatelloAnsibleModule):

    def __init__(self, **kwargs):
        foreman_spec = dict(
            chunk_size_gb=dict(required=False, type='int'),
            format=dict(required=False, type='str', choices=['syncable', 'importable']),
            from_history_id=dict(required=False, type='int'),
        )
        argument_spec = dict(
            incremental=dict(required=False, type='bool'),
        )

        foreman_spec.update(kwargs.pop('foreman_spec', {}))
        argument_spec.update(kwargs.pop('argument_spec', {}))

        self.export_action = kwargs.pop('export_action')

        super(KatelloContentExportBaseModule, self).__init__(foreman_spec=foreman_spec, argument_spec=argument_spec, **kwargs)

        # needs to happen after super().__init__()
        self.task_timeout = 12 * 60 * 60

    def run(self, **kwargs):
        incremental = self.params['incremental']
        endpoint = 'content_export_incrementals' if incremental else 'content_exports'

        if self.params.get('from_history_id') and incremental is not True:
            self.fail_json(msg='from_history_id is only valid for incremental exports')

        if 'chunk_size_gb' in self.foreman_params and self.foreman_params['format'] == 'syncable':
            self.fail_json(msg='chunk_size_gb is only valid for importable exports')

        self.auto_lookup_entities()

        payload = _flatten_entity(self.foreman_params, self.foreman_spec)
        task = self.resource_action(endpoint, self.export_action, payload)

        self.exit_json(task=task)


class KatelloContentImportBaseModule(KatelloAnsibleModule):

    def __init__(self, **kwargs):
        foreman_spec = dict(
            path=dict(required=True, type='str'),
            metadata_file=dict(required=False, type='str'),
            metadata=dict(required=False, type='dict')
        )
        argument_spec = {}
        foreman_spec.update(kwargs.pop('foreman_spec', {}))
        argument_spec.update(kwargs.pop('argument_spec', {}))

        self.import_action = kwargs.pop('import_action')

        super(KatelloContentImportBaseModule, self).__init__(foreman_spec=foreman_spec,
                                                             required_one_of=[['metadata', 'metadata_file']],
                                                             argument_spec=argument_spec, **kwargs)

        # needs to happen after super().__init__()
        self.task_timeout = 12 * 60 * 60

    def run(self, **kwargs):
        metadata_file = self.params.get('metadata_file')
        self.auto_lookup_entities()
        payload = _flatten_entity(self.foreman_params, self.foreman_spec)

        if payload.get("metadata") is None and metadata_file:
            payload["metadata"] = json.load(open(metadata_file))
            payload.pop("metadata_file")

        endpoint = 'content_imports'
        task = self.resource_action(endpoint, self.import_action, payload)
        self.exit_json(task=task)


def _foreman_spec_helper(spec):
    """Extend an entity spec by adding entries for all flat_names.
    Extract Ansible compatible argument_spec on the way.
    """
    foreman_spec = {}
    argument_spec = {}

    _FILTER_SPEC_KEYS = {
        'ensure',
        'failsafe',
        'flat_name',
        'foreman_spec',
        'invisible',
        'optional_scope',
        'resolve',
        'resource_type',
        'scope',
        'search_by',
        'search_operator',
        'thin',
        'type',
    }
    _VALUE_SPEC_KEYS = {
        'ensure',
        'type',
    }
    _ENTITY_SPEC_KEYS = {
        'failsafe',
        'optional_scope',
        'resolve',
        'resource_type',
        'scope',
        'search_by',
        'search_operator',
        'thin',
    }

    # _foreman_spec_helper() is called before we call check_requirements() in the __init__ of ForemanAnsibleModule
    # and thus before the if HAS APYPIE check happens.
    # We have to ensure that apypie is available before using it.
    # There is two cases where we can call _foreman_spec_helper() without apypie available:
    # * When the user calls the module but doesn't have the right Python libraries installed.
    #   In this case nothing will works and the module will warn the user to install the required library.
    # * When Ansible generates docs from the argument_spec. As the inflector is only used to build foreman_spec and not argument_spec,
    #   This is not a problem.
    #
    # So in conclusion, we only have to verify that apypie is available before using it.
    # Lazy evaluation helps there.
    for key, value in spec.items():
        foreman_value = {k: v for (k, v) in value.items() if k in _VALUE_SPEC_KEYS}
        argument_value = {k: v for (k, v) in value.items() if k not in _FILTER_SPEC_KEYS}

        foreman_type = value.get('type')
        ansible_invisible = value.get('invisible', False)
        flat_name = value.get('flat_name')

        if foreman_type == 'entity':
            if not flat_name:
                flat_name = '{0}_id'.format(key)
            foreman_value['resource_type'] = HAS_APYPIE and inflector.pluralize(key)
            foreman_value.update({k: v for (k, v) in value.items() if k in _ENTITY_SPEC_KEYS})
        elif foreman_type == 'entity_list':
            argument_value['type'] = 'list'
            argument_value['elements'] = value.get('elements', 'str')
            if not flat_name:
                flat_name = '{0}_ids'.format(HAS_APYPIE and inflector.singularize(key))
            foreman_value['resource_type'] = key
            foreman_value.update({k: v for (k, v) in value.items() if k in _ENTITY_SPEC_KEYS})
        elif foreman_type == 'nested_list':
            argument_value['type'] = 'list'
            argument_value['elements'] = 'dict'
            foreman_value['foreman_spec'], argument_value['options'] = _foreman_spec_helper(value['foreman_spec'])
            foreman_value['ensure'] = value.get('ensure', False)
        elif foreman_type:
            argument_value['type'] = foreman_type

        if flat_name:
            foreman_value['flat_name'] = flat_name
            foreman_spec[flat_name] = {}
            # When translating to a flat name, the flattened entry should get the same "type"
            # as Ansible expects so that comparison still works for non-strings
            if argument_value.get('type') is not None:
                foreman_spec[flat_name]['type'] = argument_value['type']

        foreman_spec[key] = foreman_value

        if not ansible_invisible:
            argument_spec[key] = argument_value

    return foreman_spec, argument_spec


def _flatten_entity(entity, foreman_spec):
    """Flatten entity according to spec"""
    result = {}
    if entity is None:
        entity = {}
    for key, value in entity.items():
        if key in foreman_spec and foreman_spec[key].get('ensure', True) and value is not None:
            spec = foreman_spec[key]
            flat_name = spec.get('flat_name', key)
            property_type = spec.get('type', 'str')
            if property_type == 'entity':
                if value is not NoEntity:
                    result[flat_name] = value['id']
                else:
                    result[flat_name] = None
            elif property_type == 'entity_list':
                result[flat_name] = sorted(val['id'] for val in value)
            elif property_type == 'nested_list':
                result[flat_name] = [_flatten_entity(ent, foreman_spec[key]['foreman_spec']) for ent in value]
            else:
                result[flat_name] = value
    return result


def _recursive_dict_without_none(a_dict, exclude=None):
    """
    Remove all entries with `None` value from a dict, recursively.
    Also drops all entries with keys in `exclude` in the top level.
    """
    if exclude is None:
        exclude = []

    result = {}

    for (k, v) in a_dict.items():
        if v is not None and k not in exclude:
            if isinstance(v, dict):
                v = _recursive_dict_without_none(v)
            elif isinstance(v, list) and v and isinstance(v[0], dict):
                v = [_recursive_dict_without_none(element) for element in v]
            result[k] = v

    return result


def _is_resolved(spec, what):
    if spec.get('type') not in ('entity', 'entity_list'):
        return True

    if spec.get('type') == 'entity' and (what is None or isinstance(what, dict)):
        return True

    if spec.get('type') == 'entity_list' and isinstance(what, list) and what and (what[0] is None or isinstance(what[0], dict)):
        return True

    return False


# Helper for (global, operatingsystem, ...) parameters
def parameter_value_to_str(value, parameter_type):
    """Helper to convert the value of parameters to string according to their parameter_type."""
    if parameter_type in ['real', 'integer']:
        parameter_string = str(value)
    elif parameter_type in ['array', 'hash', 'yaml', 'json']:
        parameter_string = json.dumps(value, sort_keys=True)
    else:
        parameter_string = value
    return parameter_string


# Helper for converting lists of parameters
def parameters_list_to_str_list(parameters):
    filtered_params = []
    for param in parameters:
        if 'hidden_value?' in param:
            param['hidden_value'] = param.pop('hidden_value?')
        new_param = {k: v for (k, v) in param.items() if k in parameter_ansible_spec.keys()}
        new_param['value'] = parameter_value_to_str(new_param['value'], new_param.get('parameter_type', 'string'))
        filtered_params.append(new_param)
    return filtered_params


# Helper for templates
def parse_template(template_content, module):
    if not HAS_PYYAML:
        module.fail_json(msg=missing_required_lib("PyYAML"), exception=PYYAML_IMP_ERR)

    try:
        template_dict = {}
        data = re.search(
            r'<%#([^%]*([^%]*%*[^>%])*%*)%>', template_content)
        if data:
            datalist = data.group(1)
            if datalist[-1] == '-':
                datalist = datalist[:-1]
            template_dict = yaml.safe_load(datalist)
        # No metadata, import template anyway
        template_dict['template'] = template_content
    except Exception as e:
        module.fail_json(msg='Error while parsing template: ' + to_native(e))
    return template_dict


def parse_template_from_file(file_name, module):
    try:
        with open(file_name) as input_file:
            template_content = input_file.read()
            template_dict = parse_template(template_content, module)
    except Exception as e:
        module.fail_json(msg='Error while reading template file: ' + to_native(e))
    return template_dict


# Helper for titles
def split_fqn(title):
    """ Split fully qualified name (title) in name and parent title """
    fqn = title.split('/')
    if len(fqn) > 1:
        name = fqn.pop()
        return (name, '/'.join(fqn))
    else:
        return (title, None)


def build_fqn(name, parent=None):
    if parent:
        return "%s/%s" % (parent, name)
    else:
        return name


# Helper for puppetclasses
def ensure_puppetclasses(module, entity_type, entity, expected_puppetclasses=None):
    if expected_puppetclasses is not None:
        puppetclasses_resource = '{0}_classes'.format(entity_type)
        expected_puppetclasses = module.find_puppetclasses(expected_puppetclasses, environment=entity['environment_id'], thin=True)
        current_puppetclasses = entity.get('puppetclasses', [])
        current_puppetclass_ids = [pc['id'] for pc in current_puppetclasses]
        previous_puppetclass_ids = current_puppetclass_ids[:]
        for puppetclass in expected_puppetclasses:
            if puppetclass['id'] in current_puppetclass_ids:
                # Nothing to do, prevent removal
                previous_puppetclass_ids.remove(puppetclass['id'])
            else:
                payload = {'{0}_id'.format(entity_type): entity['id'], 'puppetclass_id': puppetclass['id']}
                module.ensure_entity(puppetclasses_resource, {}, None, params=payload, state='present', foreman_spec={})
                # Add to entity for reporting
                current_puppetclass_ids.append(puppetclass['id'])

        for leftover_puppetclass in previous_puppetclass_ids:
            payload = {'{0}_id'.format(entity_type): entity['id']}
            module.ensure_entity(
                puppetclasses_resource, {}, {'id': leftover_puppetclass},
                params=payload, state='absent', foreman_spec={},
            )
            current_puppetclass_ids.remove(leftover_puppetclass)
        entity['puppetclass_ids'] = current_puppetclass_ids


# Helper constants
OS_LIST = ['AIX',
           'Altlinux',
           'Archlinux',
           'Coreos',
           'Debian',
           'Fcos',
           'Freebsd',
           'Gentoo',
           'Junos',
           'NXOS',
           'Rancheros',
           'Redhat',
           'Rhcos',
           'Solaris',
           'Suse',
           'VRP',
           'Windows',
           'Xenserver',
           ]

TEMPLATE_KIND_LIST = [
    'Bootdisk',
    'cloud-init',
    'finish',
    'host_init_config',
    'iPXE',
    'job_template',
    'kexec',
    'POAP',
    'provision',
    'PXEGrub',
    'PXEGrub2',
    'PXELinux',
    'registration',
    'script',
    'user_data',
    'ZTP',
]

# interface specs
interfaces_spec = dict(
    id=dict(invisible=True),
    mac=dict(),
    ip=dict(),
    ip6=dict(),
    type=dict(choices=['interface', 'bmc', 'bond', 'bridge']),
    name=dict(),
    subnet=dict(type='entity'),
    subnet6=dict(type='entity', resource_type='subnets'),
    domain=dict(type='entity'),
    identifier=dict(),
    managed=dict(type='bool'),
    primary=dict(type='bool'),
    provision=dict(type='bool'),
    execution=dict(type='bool'),
    username=dict(),
    password=dict(no_log=True),
    provider=dict(choices=['IPMI', 'Redfish', 'SSH']),
    virtual=dict(type='bool'),
    tag=dict(),
    mtu=dict(type='int'),
    attached_to=dict(),
    mode=dict(choices=[
        'balance-rr',
        'active-backup',
        'balance-xor',
        'broadcast',
        '802.3ad',
        'balance-tlb',
        'balance-alb',
    ]),
    attached_devices=dict(type='list', elements='str'),
    bond_options=dict(),
    compute_attributes=dict(type='dict'),
)
