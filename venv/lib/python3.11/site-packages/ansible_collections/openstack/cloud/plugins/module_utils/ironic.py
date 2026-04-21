#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
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


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.openstack.cloud.plugins.module_utils.openstack import openstack_full_argument_spec


def ironic_argument_spec(**kwargs):
    spec = dict(
        auth_type=dict(),
        ironic_url=dict(),
    )
    spec.update(kwargs)
    return openstack_full_argument_spec(**spec)


# TODO(dtantsur): inherit the collection's base module
class IronicModule(AnsibleModule):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._update_ironic_auth()

    def _update_ironic_auth(self):
        """Validate and update authentication parameters for ironic."""
        if (
            self.params['auth_type'] in [None, 'None', 'none']
            and self.params['ironic_url'] is None
            and not self.params['cloud']
            and not (self.params['auth']
                     and self.params['auth'].get('endpoint'))
        ):
            self.fail_json(msg=("Authentication appears to be disabled, "
                                "Please define either ironic_url, or cloud, "
                                "or auth.endpoint"))

        if (
            self.params['ironic_url']
            and self.params['auth_type'] in [None, 'None', 'none']
            and not (self.params['auth']
                     and self.params['auth'].get('endpoint'))
        ):
            self.params['auth'] = dict(
                endpoint=self.params['ironic_url']
            )
