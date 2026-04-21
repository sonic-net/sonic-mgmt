# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# Copyright (c) 2020-2022, Laurent Nicolas <laurentn@netapp.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

""" Support class for NetApp ansible modules

    Provides accesss to ipaddress - mediating unicode issues with python2.7
"""

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.module_utils._text import to_native

try:
    import ipaddress
    HAS_IPADDRESS_LIB = True
    IMPORT_ERROR = None
except ImportError as exc:
    HAS_IPADDRESS_LIB = False
    IMPORT_ERROR = to_native(exc)


def _check_ipaddress_is_present(module):
    '''
    report error at runtime rather than when attempting to load the module
    '''
    if HAS_IPADDRESS_LIB:
        return None
    module.fail_json(msg="Error: the python ipaddress package is required for this module.  Import error: %s" % IMPORT_ERROR)


def _get_ipv4orv6_address(ip_address, module):
    '''
    return IPV4Adress or IPV6Address object
    '''
    _check_ipaddress_is_present(module)
    # python 2.7 requires unicode format
    ip_addr = u'%s' % ip_address
    try:
        return ipaddress.ip_address(ip_addr)
    except ValueError as exc:
        error = 'Error: Invalid IP address value %s - %s' % (ip_address, to_native(exc))
        module.fail_json(msg=error)


def _get_ipv4orv6_network(ip_address, netmask, strict, module):
    '''
    return IPV4Network or IPV6Network object
    '''
    _check_ipaddress_is_present(module)
    # python 2.7 requires unicode format
    ip_addr = u'%s/%s' % (ip_address, netmask) if netmask is not None else u'%s' % ip_address
    try:
        return ipaddress.ip_network(ip_addr, strict)
    except ValueError as exc:
        error = 'Error: Invalid IP network value %s' % ip_addr
        if 'has host bits set' in to_native(exc):
            error += '.  Please specify a network address without host bits set'
        elif netmask is not None:
            error += '.  Check address and netmask values'
        error += ': %s.' % to_native(exc)
        module.fail_json(msg=error)


def _check_ipv6_has_prefix_length(ip_address, netmask, module):
    ip_address = _get_ipv4orv6_address(ip_address, module)
    if not isinstance(ip_address, ipaddress.IPv6Address) or isinstance(netmask, int):
        return
    if ':' in netmask:
        module.fail_json(msg='Error: only prefix_len is supported for IPv6 addresses, got %s' % netmask)


def validate_ip_address_is_network_address(ip_address, module):
    '''
    Validate if the given IP address is a network address (i.e. it's host bits are set to 0)
    ONTAP doesn't validate if the host bits are set,
    and hence doesn't add a new address unless the IP is from a different network.
    So this validation allows the module to be idempotent.
    :return: None
    '''
    dummy = _get_ipv4orv6_network(ip_address, None, True, module)


def validate_and_compress_ip_address(ip_address, module):
    '''
    0's in IPv6 addresses can be compressed to save space
    This will be a noop for IPv4 address
    In addition, it makes sure the address is in a valid format
    '''
    # return compressed value for IPv6 and value in . notation for IPv4
    return str(_get_ipv4orv6_address(ip_address, module))


def netmask_length_to_netmask(ip_address, length, module):
    '''
    input: ip_address and netmask length
    output: netmask in dot notation
    '''
    return str(_get_ipv4orv6_network(ip_address, length, False, module).netmask)


def netmask_to_netmask_length(ip_address, netmask, module):
    '''
    input: ip_address and netmask in dot notation for IPv4, expanded netmask is not supported for IPv6
           netmask as int or a str representaiton of int is also accepted
    output: netmask length as int
    '''
    _check_ipv6_has_prefix_length(ip_address, netmask, module)
    return _get_ipv4orv6_network(ip_address, netmask, False, module).prefixlen
