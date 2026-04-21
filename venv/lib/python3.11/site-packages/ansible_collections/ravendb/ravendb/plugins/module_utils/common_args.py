# -*- coding: utf-8 -*-

# Copyright (c), RavenDB
# GNU General Public License v3.0 or later (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


def ravendb_common_argument_spec():
    """

    Return a dictionary with common arguments for RavenDB modules.
    """
    return dict(
        url=dict(
            type='str', required=True
        ),
        database_name=dict(
            type='str', required=True
        ),
        certificate_path=dict(
            type='str', required=False
        ),
        ca_cert_path=dict(
            type='str', required=False
        ),
    )
