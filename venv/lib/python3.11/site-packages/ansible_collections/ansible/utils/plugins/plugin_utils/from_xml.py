#
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

"""
The from_xml plugin code
"""
from __future__ import absolute_import, division, print_function


__metaclass__ = type

from ansible.errors import AnsibleFilterError


try:
    import xmltodict

    HAS_XMLTODICT = True
except ImportError:
    HAS_XMLTODICT = False


def _raise_error(msg):
    """Raise an error message, prepend with filter name
    :param msg: The message
    :type msg: str
    :raises: AnsibleError
    """
    error = "Error when using plugin 'from_xml': {msg}".format(msg=msg)
    raise AnsibleFilterError(error)


def from_xml(data, engine):
    """Convert data which is in xml to json"
    :param data: The data passed in (data|from_xml(...))
    :type data: xml
    :param engine: Conversion library default=xml_to_dict
    """
    if engine == "xmltodict":
        if not HAS_XMLTODICT:
            _raise_error("Missing required library xmltodict")
        try:
            res = xmltodict.parse(data, dict_constructor=dict)
        except Exception:
            _raise_error("Input Xml is not valid")
        return res
    else:
        error = "engine: {engine} is not supported ".format(engine=engine)
        _raise_error(error)
