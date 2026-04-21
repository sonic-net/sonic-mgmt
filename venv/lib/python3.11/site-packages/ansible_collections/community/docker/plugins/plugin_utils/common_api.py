# Copyright (c) 2019-2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


from ansible.errors import AnsibleConnectionFailure
from ansible.utils.display import Display

from ansible_collections.community.docker.plugins.module_utils.common_api import (
    AnsibleDockerClientBase,
)

from ansible_collections.community.docker.plugins.module_utils.util import (
    DOCKER_COMMON_ARGS,
)


class AnsibleDockerClient(AnsibleDockerClientBase):
    def __init__(self, plugin, min_docker_api_version=None):
        self.plugin = plugin
        self.display = Display()
        super(AnsibleDockerClient, self).__init__(
            min_docker_api_version=min_docker_api_version)

    def fail(self, msg, **kwargs):
        if kwargs:
            msg += '\nContext:\n' + '\n'.join('  {0} = {1!r}'.format(k, v) for (k, v) in kwargs.items())
        raise AnsibleConnectionFailure(msg)

    def deprecate(self, msg, version=None, date=None, collection_name=None):
        self.display.deprecated(msg, version=version, date=date, collection_name=collection_name)

    def _get_params(self):
        return dict([
            (option, self.plugin.get_option(option))
            for option in DOCKER_COMMON_ARGS
        ])
