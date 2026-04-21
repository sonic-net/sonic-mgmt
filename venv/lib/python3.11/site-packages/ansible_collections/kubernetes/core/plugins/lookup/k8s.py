#
#  Copyright 2018 Red Hat | Ansible
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
    name: k8s

    short_description: Query the K8s API

    author:
      - Chris Houseknecht (@chouseknecht)
      - Fabian von Feilitzsch (@fabianvf)

    description:
      - Uses the Kubernetes Python client to fetch a specific object by name, all matching objects within a
        namespace, or all matching objects for all namespaces, as well as information about the cluster.
      - Provides access the full range of K8s APIs.
      - Enables authentication via config file, certificates, password or token.
    notes:
      - While querying, please use C(query) or C(lookup) format with C(wantlist=True) to provide an easier and more
        consistent interface. For more details, see
        U(https://docs.ansible.com/ansible/latest/plugins/lookup.html#forcing-lookups-to-return-lists-query-and-wantlist-true).
    options:
      cluster_info:
        description:
        - Use to specify the type of cluster information you are attempting to retrieve. Will take priority
          over all the other options.
      api_version:
        description:
        - Use to specify the API version. If I(resource definition) is provided, the I(apiVersion) from the
          I(resource_definition) will override this option.
        default: v1
      kind:
        description:
        - Use to specify an object model. If I(resource definition) is provided, the I(kind) from a
          I(resource_definition) will override this option.
        required: true
      resource_name:
        description:
        - Fetch a specific object by name. If I(resource definition) is provided, the I(metadata.name) value
          from the I(resource_definition) will override this option.
      namespace:
        description:
        - Limit the objects returned to a specific namespace. If I(resource definition) is provided, the
          I(metadata.namespace) value from the I(resource_definition) will override this option.
      label_selector:
        description:
        - Additional labels to include in the query. Ignored when I(resource_name) is provided.
      field_selector:
        description:
        - Specific fields on which to query. Ignored when I(resource_name) is provided.
      resource_definition:
        description:
        - "Provide a YAML configuration for an object. NOTE: I(kind), I(api_version), I(resource_name),
          and I(namespace) will be overwritten by corresponding values found in the provided I(resource_definition)."
      src:
        description:
        - "Provide a path to a file containing a valid YAML definition of an object dated. Mutually
          exclusive with I(resource_definition). NOTE: I(kind), I(api_version), I(resource_name), and I(namespace)
          will be overwritten by corresponding values found in the configuration read in from the I(src) file."
        - Reads from the local file system. To read from the Ansible controller's file system, use the file lookup
          plugin or template lookup plugin, combined with the from_yaml filter, and pass the result to
          I(resource_definition). See Examples below.
      host:
        description:
        - Provide a URL for accessing the API. Can also be specified via K8S_AUTH_HOST environment variable.
      api_key:
        description:
        - Token used to authenticate with the API. Can also be specified via K8S_AUTH_API_KEY environment variable.
      kubeconfig:
        description:
        - Path to an existing Kubernetes config file. If not provided, and no other connection
          options are provided, the Kubernetes client will attempt to load the default
          configuration file from I(~/.kube/config). Can also be specified via K8S_AUTH_KUBECONFIG environment
          variable.
      context:
        description:
        - The name of a context found in the config file. Can also be specified via K8S_AUTH_CONTEXT environment
          variable.
      username:
        description:
        - Provide a username for authenticating with the API. Can also be specified via K8S_AUTH_USERNAME environment
          variable.
      password:
        description:
        - Provide a password for authenticating with the API. Can also be specified via K8S_AUTH_PASSWORD environment
          variable.
      client_cert:
        description:
        - Path to a certificate used to authenticate with the API. Can also be specified via K8S_AUTH_CERT_FILE
          environment
          variable.
        aliases: [ cert_file ]
      client_key:
        description:
        - Path to a key file used to authenticate with the API. Can also be specified via K8S_AUTH_KEY_FILE environment
          variable.
        aliases: [ key_file ]
      ca_cert:
        description:
        - Path to a CA certificate used to authenticate with the API. Can also be specified via K8S_AUTH_SSL_CA_CERT
          environment variable.
        aliases: [ ssl_ca_cert ]
      validate_certs:
        description:
        - Whether or not to verify the API server's SSL certificates. Can also be specified via K8S_AUTH_VERIFY_SSL
          environment variable.
        type: bool
        aliases: [ verify_ssl ]

    requirements:
      - "python >= 3.9"
      - "kubernetes >= 24.2.0"
      - "PyYAML >= 3.11"
"""

EXAMPLES = """
- name: Fetch a list of namespaces
  set_fact:
    projects: "{{ query('kubernetes.core.k8s', api_version='v1', kind='Namespace') }}"

- name: Fetch all deployments
  set_fact:
    deployments: "{{ query('kubernetes.core.k8s', kind='Deployment') }}"

- name: Fetch all deployments in a namespace
  set_fact:
    deployments: "{{ query('kubernetes.core.k8s', kind='Deployment', namespace='testing') }}"

- name: Fetch a specific deployment by name
  set_fact:
    deployments: "{{ query('kubernetes.core.k8s', kind='Deployment', namespace='testing', resource_name='elastic') }}"

- name: Fetch with label selector
  set_fact:
    service: "{{ query('kubernetes.core.k8s', kind='Service', label_selector='app=galaxy') }}"

# Use parameters from a YAML config

- name: Load config from the Ansible controller filesystem
  set_fact:
    config: "{{ lookup('file', 'service.yml') | from_yaml }}"

- name: Using the config (loaded from a file in prior task), fetch the latest version of the object
  set_fact:
    service: "{{ query('kubernetes.core.k8s', resource_definition=config) }}"

- name: Use a config from the local filesystem
  set_fact:
    service: "{{ query('kubernetes.core.k8s', src='service.yml') }}"
"""

RETURN = """
  _list:
    description:
      - One ore more object definitions returned from the API.
    type: list
    elements: dict
    sample:
        - kind: ConfigMap
          apiVersion: v1
          metadata:
            creationTimestamp: "2022-03-04T13:59:49Z"
            name: my-config-map
            namespace: default
            resourceVersion: "418"
            uid: 5714b011-d090-4eac-8272-a0ea82ec0abd
          data:
            key1: val1
"""

import os

from ansible.errors import AnsibleError
from ansible.module_utils.common._collections_compat import KeysView
from ansible.module_utils.common.validation import check_type_bool
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.client import (
    get_api_client,
)
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.resource import (
    create_definitions,
)

try:
    enable_turbo_mode = check_type_bool(os.environ.get("ENABLE_TURBO_MODE"))
except TypeError:
    enable_turbo_mode = False

if enable_turbo_mode:
    try:
        from ansible_collections.cloud.common.plugins.plugin_utils.turbo.lookup import (
            TurboLookupBase as LookupBase,
        )
    except ImportError:
        from ansible.plugins.lookup import LookupBase  # noqa: F401
else:
    from ansible.plugins.lookup import LookupBase  # noqa: F401

try:
    from kubernetes.dynamic.exceptions import NotFoundError

    HAS_K8S_MODULE_HELPER = True
    k8s_import_exception = None
except ImportError as e:
    HAS_K8S_MODULE_HELPER = False
    k8s_import_exception = e


class KubernetesLookup(object):
    def __init__(self):
        if not HAS_K8S_MODULE_HELPER:
            raise Exception(
                "Requires the Kubernetes Python client. Try `pip install kubernetes`. Detail: {0}".format(
                    k8s_import_exception
                )
            )

        self.kind = None
        self.name = None
        self.namespace = None
        self.api_version = None
        self.label_selector = None
        self.field_selector = None
        self.include_uninitialized = None
        self.resource_definition = None
        self.helper = None
        self.connection = {}

    def fail(self, msg=None):
        raise AnsibleError(msg)

    def run(self, terms, variables=None, **kwargs):
        self.params = kwargs
        self.client = get_api_client(**kwargs)

        cluster_info = kwargs.get("cluster_info")
        if cluster_info == "version":
            return [self.client.client.version]
        if cluster_info == "api_groups":
            if isinstance(self.client.resources.api_groups, KeysView):
                return [list(self.client.resources.api_groups)]
            return [self.client.resources.api_groups]

        self.kind = kwargs.get("kind")
        self.name = kwargs.get("resource_name")
        self.namespace = kwargs.get("namespace")
        self.api_version = kwargs.get("api_version", "v1")
        self.label_selector = kwargs.get("label_selector")
        self.field_selector = kwargs.get("field_selector")
        self.include_uninitialized = kwargs.get("include_uninitialized", False)

        resource_definition = kwargs.get("resource_definition")
        src = kwargs.get("src")
        if src:
            definitions = create_definitions(params=dict(src=src))
            if definitions:
                self.kind = definitions[0].kind
                self.name = definitions[0].name
                self.namespace = definitions[0].namespace
                self.api_version = definitions[0].api_version or "v1"
        if resource_definition:
            self.kind = resource_definition.get("kind", self.kind)
            self.api_version = resource_definition.get("apiVersion", self.api_version)
            self.name = resource_definition.get("metadata", {}).get("name", self.name)
            self.namespace = resource_definition.get("metadata", {}).get(
                "namespace", self.namespace
            )

        if not self.kind:
            raise AnsibleError(
                "Error: no Kind specified. Use the 'kind' parameter, or provide an object YAML configuration "
                "using the 'resource_definition' parameter."
            )

        resource = self.client.resource(self.kind, self.api_version)
        try:
            params = dict(
                name=self.name,
                namespace=self.namespace,
                label_selector=self.label_selector,
                field_selector=self.field_selector,
            )
            k8s_obj = self.client.get(resource, **params)
        except NotFoundError:
            return []

        if self.name:
            return [k8s_obj.to_dict()]

        return k8s_obj.to_dict().get("items")


class LookupModule(LookupBase):
    def _run(self, terms, variables=None, **kwargs):
        return KubernetesLookup().run(terms, variables=variables, **kwargs)

    run = _run if not hasattr(LookupBase, "run_on_daemon") else LookupBase.run_on_daemon
