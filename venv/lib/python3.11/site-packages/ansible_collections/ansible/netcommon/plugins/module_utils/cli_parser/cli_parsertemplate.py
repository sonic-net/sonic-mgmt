# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# (c) 2020 Red Hat Inc.
#
# Simplified BSD License (see LICENSES/BSD-2-Clause.txt or https://opensource.org/licenses/BSD-2-Clause)
# SPDX-License-Identifier: BSD-2-Clause

"""A shim class for the NetworkTemplate
this was done in case there is a need to
modify the resource module parser class
or extend it a split it from the cli parsers.
"""
from __future__ import absolute_import, division, print_function


__metaclass__ = type

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.network_template import (
    NetworkTemplate,
)


class CliParserTemplate(NetworkTemplate):
    """The parser template base class"""

    def __init__(self, lines=None):
        super(CliParserTemplate, self).__init__(lines=lines, tmplt=self)
