from __future__ import absolute_import, division, print_function

from ansible.module_utils.basic import env_fallback

__metaclass__ = type


HELM_AUTH_ARG_SPEC = dict(
    binary_path=dict(type="path"),
    context=dict(
        type="str",
        aliases=["kube_context"],
        fallback=(env_fallback, ["K8S_AUTH_CONTEXT"]),
    ),
    kubeconfig=dict(
        type="raw",
        aliases=["kubeconfig_path"],
        fallback=(env_fallback, ["K8S_AUTH_KUBECONFIG"]),
        no_log=True,
    ),
    host=dict(type="str", fallback=(env_fallback, ["K8S_AUTH_HOST"])),
    ca_cert=dict(
        type="path",
        aliases=["ssl_ca_cert"],
        fallback=(env_fallback, ["K8S_AUTH_SSL_CA_CERT"]),
    ),
    validate_certs=dict(
        type="bool",
        default=True,
        aliases=["verify_ssl"],
        fallback=(env_fallback, ["K8S_AUTH_VERIFY_SSL"]),
    ),
    api_key=dict(
        type="str",
        no_log=True,
        fallback=(env_fallback, ["K8S_AUTH_API_KEY"]),
    ),
)

HELM_AUTH_MUTUALLY_EXCLUSIVE = [
    ("context", "ca_cert"),
    ("context", "validate_certs"),
]
