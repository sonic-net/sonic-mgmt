# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The utils file for all netaddr tests
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

from functools import wraps

from ansible import errors
from ansible.errors import AnsibleError
from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.six import ensure_text

from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
    check_argspec,
)


try:
    import ipaddress

    HAS_IPADDRESS = True
except ImportError:
    HAS_IPADDRESS = False


def ip_network(ip):
    """PY2 compat shim, PY2 requires unicode"""

    if not HAS_IPADDRESS:
        raise AnsibleError(missing_required_lib("ipaddress"))

    return ipaddress.ip_network(ensure_text(ip))


def ip_address(ip):
    """PY2 compat shim, PY2 requires unicode"""

    if not HAS_IPADDRESS:
        raise AnsibleError(missing_required_lib("ipaddress"))

    return ipaddress.ip_address(ensure_text(ip))


def _need_ipaddress(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not HAS_IPADDRESS:
            raise AnsibleError(missing_required_lib("ipaddress"))
        return func(*args, **kwargs)

    return wrapper


def _is_subnet_of(network_a, network_b):
    try:
        if network_a._version != network_b._version:
            return False
        return (
            network_b.network_address <= network_a.network_address
            and network_b.broadcast_address >= network_a.broadcast_address
        )
    except Exception:
        return False


def _validate_args(plugin, doc, params):
    """argspec validator utility function"""

    valid, argspec_result, updated_params = check_argspec(doc, plugin + " test", **params)

    if not valid:
        raise AnsibleError(
            "{argspec_result} with errors: {argspec_errors}".format(
                argspec_result=argspec_result.get("msg"),
                argspec_errors=argspec_result.get("errors"),
            ),
        )


def _need_netaddr(f_name, *args, **kwargs):
    raise errors.AnsibleFilterError(missing_required_lib("netaddr"))
