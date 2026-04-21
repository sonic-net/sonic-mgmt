# Copyright (c) 2019-2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


from ansible_collections.community.docker.plugins.module_utils.selectors import selectors

from ansible_collections.community.docker.plugins.module_utils.socket_handler import (
    DockerSocketHandlerBase,
)


class DockerSocketHandler(DockerSocketHandlerBase):
    def __init__(self, display, sock, log=None, container=None):
        super(DockerSocketHandler, self).__init__(sock, selectors, log=lambda msg: display.vvvv(msg, host=container))
