# -*- coding: utf-8 -*-

# Copyright (c), RavenDB
# GNU General Public License v3.0 or later (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


class ModuleDocFragment(object):
    # RavenDB documentation fragment
    DOCUMENTATION = '''
    options:
        url:
            description:
                - URL of the RavenDB server.
                - Must include the scheme (http or https), hostname, and port.
            required: true
            type: str
        database_name:
            description:
                - Name of the database.
                - Must be a valid name containing only letters, numbers, dashes, and underscores.
            required: true
            type: str
        certificate_path:
            description:
                - Path to a client certificate (PEM format) for secured communication.
            required: false
            type: str
        ca_cert_path:
            description:
                - Path to a trusted CA certificate file to verify the RavenDB server's certificate.
            required: false
            type: str

    attributes:
        check_mode:
            support: full
            description: Can run in check_mode and return changed status prediction without modifying target. If not supported, the action will be skipped.

    notes:
    - The role C(ravendb.ravendb.ravendb_python_client_prerequisites) must be applied before using this module.
    - Requires the ASP.NET Core Runtime to be installed on the target system.

    requirements:
    - python >= 3.9
    - ravendb python client
    - ASP.NET Core Runtime
    - requests
    - Role ravendb.ravendb.ravendb_python_client_prerequisites must be installed before using this module.
    '''
