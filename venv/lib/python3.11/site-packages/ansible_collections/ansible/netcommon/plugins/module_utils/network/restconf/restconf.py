# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# (c) 2018 Red Hat Inc.
#
# Simplified BSD License (see LICENSES/BSD-2-Clause.txt or https://opensource.org/licenses/BSD-2-Clause)
# SPDX-License-Identifier: BSD-2-Clause

from __future__ import absolute_import, division, print_function


__metaclass__ = type

from ansible.module_utils.connection import Connection


def get(module, path=None, content=None, fields=None, output="json"):
    if path is None:
        raise ValueError("path value must be provided")
    if content:
        path += "?" + "content=%s" % content
    if fields:
        path += "?" + "field=%s" % fields

    accept = None
    if output == "xml":
        accept = "application/yang-data+xml"

    connection = Connection(module._socket_path)
    return connection.send_request(None, path=path, method="GET", accept=accept)


def edit_config(module, path=None, content=None, method="GET", format="json"):
    if path is None:
        raise ValueError("path value must be provided")

    content_type = None
    if format == "xml":
        content_type = "application/yang-data+xml"

    connection = Connection(module._socket_path)
    return connection.send_request(content, path=path, method=method, content_type=content_type)
