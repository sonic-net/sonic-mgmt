# -*- coding: utf-8 -*-

# Copyright (c), RavenDB
# GNU General Public License v3.0 or later (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


class NodeSpec(object):
    def __init__(self, tag, url, leader_url, node_type="Member"):
        self.tag = tag
        self.url = url
        self.leader_url = leader_url
        self.node_type = node_type

    @property
    def is_watcher(self):
        return self.node_type == "Watcher"
