from __future__ import absolute_import, division, print_function

__metaclass__ = type


def list_dict_str(value):
    if isinstance(value, (list, dict, str)):
        return value
    raise TypeError


AUTH_PROXY_HEADERS_SPEC = dict(
    proxy_basic_auth=dict(type="str", no_log=True),
    basic_auth=dict(type="str", no_log=True),
    user_agent=dict(type="str"),
)

AUTH_ARG_SPEC = {
    "kubeconfig": {"type": "raw", "no_log": True},
    "context": {},
    "host": {},
    "api_key": {"no_log": True},
    "username": {},
    "password": {"no_log": True},
    "validate_certs": {"type": "bool", "aliases": ["verify_ssl"]},
    "ca_cert": {"type": "path", "aliases": ["ssl_ca_cert"]},
    "client_cert": {"type": "path", "aliases": ["cert_file"]},
    "client_key": {"type": "path", "aliases": ["key_file"]},
    "proxy": {"type": "str"},
    "no_proxy": {"type": "str"},
    "proxy_headers": {"type": "dict", "options": AUTH_PROXY_HEADERS_SPEC},
    "persist_config": {"type": "bool"},
    "impersonate_user": {},
    "impersonate_groups": {"type": "list", "elements": "str"},
}

WAIT_ARG_SPEC = dict(
    wait=dict(type="bool", default=False),
    wait_sleep=dict(type="int", default=5),
    wait_timeout=dict(type="int", default=120),
    wait_condition=dict(
        type="dict",
        default=None,
        options=dict(
            type=dict(),
            status=dict(default=True, choices=[True, False, "Unknown"]),
            reason=dict(),
        ),
    ),
)

# Map kubernetes-client parameters to ansible parameters
AUTH_ARG_MAP = {
    "kubeconfig": "kubeconfig",
    "context": "context",
    "host": "host",
    "api_key": "api_key",
    "username": "username",
    "password": "password",
    "verify_ssl": "validate_certs",
    "ssl_ca_cert": "ca_cert",
    "cert_file": "client_cert",
    "key_file": "client_key",
    "proxy": "proxy",
    "no_proxy": "no_proxy",
    "proxy_headers": "proxy_headers",
    "persist_config": "persist_config",
}

NAME_ARG_SPEC = {
    "kind": {},
    "name": {},
    "namespace": {},
    "api_version": {"default": "v1", "aliases": ["api", "version"]},
}

COMMON_ARG_SPEC = {
    "state": {"default": "present", "choices": ["present", "absent"]},
    "force": {"type": "bool", "default": False},
}

RESOURCE_ARG_SPEC = {
    "resource_definition": {"type": list_dict_str, "aliases": ["definition", "inline"]},
    "src": {"type": "path"},
}

ARG_ATTRIBUTES_BLACKLIST = ("property_path",)

DELETE_OPTS_ARG_SPEC = {
    "propagationPolicy": {"choices": ["Foreground", "Background", "Orphan"]},
    "gracePeriodSeconds": {"type": "int"},
    "preconditions": {
        "type": "dict",
        "options": {"resourceVersion": {"type": "str"}, "uid": {"type": "str"}},
    },
}
