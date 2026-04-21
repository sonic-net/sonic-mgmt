# Copyright: (c) 2021, Red Hat | Ansible
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import hashlib
import os
from typing import Any, Dict, List, Optional

from ansible_collections.kubernetes.core.plugins.module_utils.args_common import (
    AUTH_ARG_MAP,
    AUTH_ARG_SPEC,
    AUTH_PROXY_HEADERS_SPEC,
)
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.core import (
    requires as _requires,
)
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.exceptions import (
    CoreException,
)

try:
    from ansible_collections.kubernetes.core.plugins.module_utils import (
        k8sdynamicclient,
    )
    from ansible_collections.kubernetes.core.plugins.module_utils.client.discovery import (
        LazyDiscoverer,
    )
except ImportError:
    # Handled in module setup
    pass

try:
    import kubernetes
    from kubernetes.dynamic.exceptions import (
        ResourceNotFoundError,
        ResourceNotUniqueError,
    )
    from kubernetes.dynamic.resource import Resource
except ImportError:
    # kubernetes import error is handled in module setup
    # This is defined only for the sake of Ansible's checked import requirement
    Resource = Any  # type: ignore

try:
    import urllib3

    urllib3.disable_warnings()
except ImportError:
    # Handled in module setup
    pass


_pool = {}


class unique_string(str):
    _low = None

    def __hash__(self):
        return id(self)

    def __eq__(self, other):
        return self is other

    def lower(self):
        if self._low is None:
            lower = str.lower(self)
            if str.__eq__(lower, self):
                self._low = self
            else:
                self._low = unique_string(lower)
        return self._low


def _create_auth_spec(module=None, **kwargs) -> Dict:
    auth: Dict = {}
    # If authorization variables aren't defined, look for them in environment variables
    for true_name, arg_name in AUTH_ARG_MAP.items():
        if module and module.params.get(arg_name) is not None:
            auth[true_name] = module.params.get(arg_name)
        elif arg_name in kwargs and kwargs.get(arg_name) is not None:
            auth[true_name] = kwargs.get(arg_name)
        elif true_name in kwargs and kwargs.get(true_name) is not None:
            # Aliases in kwargs
            auth[true_name] = kwargs.get(true_name)
        elif arg_name == "proxy_headers":
            # specific case for 'proxy_headers' which is a dictionary
            proxy_headers = {}
            for key in AUTH_PROXY_HEADERS_SPEC.keys():
                env_value = os.getenv(
                    "K8S_AUTH_PROXY_HEADERS_{0}".format(key.upper()), None
                )
                if env_value is not None:
                    if AUTH_PROXY_HEADERS_SPEC[key].get("type") == "bool":
                        env_value = env_value.lower() not in ["0", "false", "no"]
                    proxy_headers[key] = env_value
            if proxy_headers is not {}:
                auth[true_name] = proxy_headers
        else:
            env_value = os.getenv(
                "K8S_AUTH_{0}".format(arg_name.upper()), None
            ) or os.getenv("K8S_AUTH_{0}".format(true_name.upper()), None)
            if env_value is not None:
                if AUTH_ARG_SPEC[arg_name].get("type") == "bool":
                    env_value = env_value.lower() not in ["0", "false", "no"]
                auth[true_name] = env_value

    return auth


def _load_config(auth: Dict) -> None:
    kubeconfig = auth.get("kubeconfig")
    optional_arg = {
        "context": auth.get("context"),
        "persist_config": auth.get("persist_config"),
    }
    if kubeconfig:
        if isinstance(kubeconfig, str):
            kubernetes.config.load_kube_config(config_file=kubeconfig, **optional_arg)
        elif isinstance(kubeconfig, dict):
            kubernetes.config.load_kube_config_from_dict(
                config_dict=kubeconfig, **optional_arg
            )
    else:
        kubernetes.config.load_kube_config(config_file=None, **optional_arg)


def _create_configuration(auth: Dict):
    def auth_set(*names: list) -> bool:
        return all(auth.get(name) for name in names)

    if auth_set("host"):
        # Removing trailing slashes if any from hostname
        auth["host"] = auth.get("host").rstrip("/")

    if (
        auth_set("username", "password", "host")
        or auth_set("api_key", "host")
        or auth_set("cert_file", "key_file", "host")
    ):
        # We have enough in the parameters to authenticate, no need to load incluster or kubeconfig
        pass
    elif auth_set("kubeconfig") or auth_set("context"):
        try:
            _load_config(auth)
        except Exception as err:
            raise err

    else:
        # First try to do incluster config, then kubeconfig
        try:
            kubernetes.config.load_incluster_config()
        except kubernetes.config.ConfigException:
            try:
                _load_config(auth)
            except Exception as err:
                raise err

    # Override any values in the default configuration with Ansible parameters
    # As of kubernetes-client v12.0.0, get_default_copy() is required here
    try:
        configuration = kubernetes.client.Configuration().get_default_copy()
    except AttributeError:
        configuration = kubernetes.client.Configuration()

    for key, value in auth.items():
        if key in AUTH_ARG_MAP.keys() and value is not None:
            if key == "api_key":
                setattr(
                    configuration, key, {"authorization": "Bearer {0}".format(value)}
                )
            elif key == "proxy_headers":
                headers = urllib3.util.make_headers(**value)
                setattr(configuration, key, headers)
            else:
                setattr(configuration, key, value)

    return configuration


def _create_headers(module=None, **kwargs):
    header_map = {
        "impersonate_user": "Impersonate-User",
        "impersonate_groups": "Impersonate-Group",
    }

    headers = {}
    for arg_name, header_name in header_map.items():
        value = None
        if module and module.params.get(arg_name) is not None:
            value = module.params.get(arg_name)
        elif arg_name in kwargs and kwargs.get(arg_name) is not None:
            value = kwargs.get(arg_name)
        else:
            value = os.getenv("K8S_AUTH_{0}".format(arg_name.upper()), None)
            if value is not None:
                if AUTH_ARG_SPEC[arg_name].get("type") == "list":
                    value = [x for x in value.split(",") if x != ""]
        if value:
            headers[header_name] = value
    return headers


def _configuration_digest(configuration, **kwargs) -> str:
    m = hashlib.sha256()
    for k in AUTH_ARG_MAP:
        if not hasattr(configuration, k):
            v = None
        else:
            v = getattr(configuration, k)
        if v and k in ["ssl_ca_cert", "cert_file", "key_file"]:
            with open(str(v), "r") as fd:
                content = fd.read()
                m.update(content.encode())
        else:
            m.update(str(v).encode())
    for k, v in kwargs.items():
        content = "{0}: {1}".format(k, v)
        m.update(content.encode())
    digest = m.hexdigest()

    return digest


def _set_header(client, header, value):
    if isinstance(value, list):
        for v in value:
            client.set_default_header(header_name=unique_string(header), header_value=v)
    else:
        client.set_default_header(header_name=header, header_value=value)


def cache(func):
    def wrapper(*args, **kwargs):
        client = None
        hashable_kwargs = {}
        for k, v in kwargs.items():
            if isinstance(v, list):
                hashable_kwargs[k] = ",".join(sorted(v))
            else:
                hashable_kwargs[k] = v
        digest = _configuration_digest(*args, **hashable_kwargs)
        if digest in _pool:
            client = _pool[digest]
        else:
            client = func(*args, **kwargs)
            _pool[digest] = client

        return client

    return wrapper


@cache
def create_api_client(configuration, **headers):
    client = kubernetes.client.ApiClient(configuration)
    for header, value in headers.items():
        _set_header(client, header, value)
    return k8sdynamicclient.K8SDynamicClient(client, discoverer=LazyDiscoverer)


class K8SClient:
    """A Client class for K8S modules.

    This class has the primary purpose to proxy the kubernetes client and resource objects.
    If there is a need for other methods or attributes to be proxied, they can be added here.
    """

    K8S_SERVER_DRY_RUN = "All"

    def __init__(self, configuration, client, dry_run: bool = False) -> None:
        self.configuration = configuration
        self.client = client
        self.dry_run = dry_run

    @property
    def resources(self) -> List[Any]:
        return self.client.resources

    def _find_resource_with_prefix(
        self, prefix: str, kind: str, api_version: str
    ) -> Resource:
        for attribute in ["kind", "name", "singular_name"]:
            try:
                return self.client.resources.get(
                    **{"prefix": prefix, "api_version": api_version, attribute: kind}
                )
            except (ResourceNotFoundError, ResourceNotUniqueError):
                pass
        return self.client.resources.get(
            prefix=prefix, api_version=api_version, short_names=[kind]
        )

    def resource(self, kind: str, api_version: str) -> Resource:
        """Fetch a kubernetes client resource.

        This will attempt to find a kubernetes resource trying, in order, kind,
        name, singular_name and short_names.
        """
        try:
            if api_version == "v1":
                return self._find_resource_with_prefix("api", kind, api_version)
        except ResourceNotFoundError:
            pass
        return self._find_resource_with_prefix(None, kind, api_version)

    def _ensure_dry_run(self, params: Dict) -> Dict:
        if self.dry_run:
            params["dry_run"] = self.K8S_SERVER_DRY_RUN
        return params

    def validate(
        self, resource, version: Optional[str] = None, strict: Optional[bool] = False
    ):
        return self.client.validate(resource, version, strict)

    def get(self, resource, **params):
        return resource.get(**params)

    def delete(self, resource, **params):
        return resource.delete(**self._ensure_dry_run(params))

    def apply(self, resource, definition, namespace, **params):
        return resource.apply(
            definition, namespace=namespace, **self._ensure_dry_run(params)
        )

    def create(self, resource, definition, **params):
        return resource.create(definition, **self._ensure_dry_run(params))

    def replace(self, resource, definition, **params):
        return resource.replace(definition, **self._ensure_dry_run(params))

    def patch(self, resource, definition, **params):
        return resource.patch(definition, **self._ensure_dry_run(params))


def get_api_client(module=None, **kwargs: Optional[Any]) -> K8SClient:
    auth_spec = _create_auth_spec(module, **kwargs)
    if module:
        requires = module.requires
    else:
        requires = _requires
    if isinstance(auth_spec.get("kubeconfig"), dict):
        requires("kubernetes", "17.17.0", "to use in-memory config")
    if auth_spec.get("no_proxy"):
        requires("kubernetes", "19.15.0", "to use the no_proxy feature")

    try:
        configuration = _create_configuration(auth_spec)
        headers = _create_headers(module, **kwargs)
        client = create_api_client(configuration, **headers)
    except kubernetes.config.ConfigException as e:
        msg = "Could not create API client: {0}".format(e)
        raise CoreException(msg) from e

    dry_run = False
    if module and module.server_side_dry_run:
        dry_run = True

    k8s_client = K8SClient(
        configuration=configuration,
        client=client,
        dry_run=dry_run,
    )

    return k8s_client
