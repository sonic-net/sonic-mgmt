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

    Provides accesss to application resources using REST calls
"""

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class RestApplication():
    """Helper methods to manage application and application components"""
    def __init__(self, rest_api, svm_name, app_name):
        self.svm_name = svm_name
        self.app_name = app_name
        self.app_uuid = None
        self.rest_api = rest_api

    def _set_application_uuid(self):
        """Use REST application/applications to get application uuid"""
        api = 'application/applications'
        query = {'svm.name': self.svm_name, 'name': self.app_name}
        record, error = rest_generic.get_one_record(self.rest_api, api, query)
        if error is None and record is not None:
            self.app_uuid = record['uuid']
        return None, error

    def get_application_uuid(self):
        """Use REST application/applications to get application uuid"""
        error = None
        if self.app_uuid is None:
            dummy, error = self._set_application_uuid()
        return self.app_uuid, error

    def get_application_details(self, template=None):
        """Use REST application/applications to get application details"""
        uuid, error = self.get_application_uuid()
        if error:
            return uuid, error
        if uuid is None:    # not found
            return None, None
        query = dict(fields='name,%s,statistics' % template) if template else None
        api = 'application/applications/%s' % uuid
        return rest_generic.get_one_record(self.rest_api, api, query)

    def create_application(self, body):
        """Use REST application/applications san template to create one or more LUNs"""
        dummy, error = self.fail_if_uuid('create_application')
        if error is not None:
            return dummy, error
        api = 'application/applications'
        query = {'return_records': 'true'}
        response, error = rest_generic.post_async(self.rest_api, api, body, query)
        if error and 'Unexpected argument' in error and 'exclude_aggregates' in error:
            error += '  "exclude_aggregates" requires ONTAP 9.9.1 GA or later.'
        return response, error

    def patch_application(self, body):
        """Use REST application/applications san template to add one or more LUNs"""
        dummy, error = self.fail_if_no_uuid()
        if error is not None:
            return dummy, error
        api = 'application/applications'
        query = {'return_records': 'true'}
        return rest_generic.patch_async(self.rest_api, api, self.app_uuid, body, query)

    def create_application_body(self, template_name, template_body, smart_container=True):
        if not isinstance(smart_container, bool):
            error = "expecting bool value for smart_container, got: %s" % smart_container
            return None, error
        body = {
            'name': self.app_name,
            'svm': {'name': self.svm_name},
            'smart_container': smart_container,
            template_name: template_body
        }
        return body, None

    def delete_application(self):
        """Use REST application/applications to delete app"""
        dummy, error = self.fail_if_no_uuid()
        if error is not None:
            return dummy, error
        api = 'application/applications'
        response, error = rest_generic.delete_async(self.rest_api, api, self.app_uuid)
        self.app_uuid = None
        return response, error

    def get_application_components(self):
        """Use REST application/applications to get application components"""
        dummy, error = self.fail_if_no_uuid()
        if error is not None:
            return dummy, error
        api = 'application/applications/%s/components' % self.app_uuid
        return rest_generic.get_0_or_more_records(self.rest_api, api)

    def get_application_component_uuid(self):
        """Use REST application/applications to get component uuid
           Assume a single component per application
        """
        dummy, error = self.fail_if_no_uuid()
        if error is not None:
            return dummy, error
        api = 'application/applications/%s/components' % self.app_uuid
        record, error = rest_generic.get_one_record(self.rest_api, api, fields='uuid')
        if error is None and record is not None:
            return record['uuid'], None
        return None, error

    def get_application_component_details(self, comp_uuid=None):
        """Use REST application/applications to get application components"""
        dummy, error = self.fail_if_no_uuid()
        if error is not None:
            return dummy, error
        if comp_uuid is None:
            # assume a single component
            comp_uuid, error = self.get_application_component_uuid()
            if error:
                return comp_uuid, error
        if comp_uuid is None:
            error = 'no component for application %s' % self.app_name
            return None, error
        api = 'application/applications/%s/components/%s' % (self.app_uuid, comp_uuid)
        return rest_generic.get_one_record(self.rest_api, api)

    def get_application_component_backing_storage(self):
        """Use REST application/applications to get component uuid.

           Assume a single component per application
        """
        dummy, error = self.fail_if_no_uuid()
        if error is not None:
            return dummy, error
        response, error = self.get_application_component_details()
        if error or response is None:
            return response, error
        return response['backing_storage'], None

    def fail_if_no_uuid(self):
        """Prevent a logic error."""
        if self.app_uuid is None:
            msg = 'function should not be called before application uuid is set.'
            return None, msg
        return None, None

    def fail_if_uuid(self, fname):
        """Prevent a logic error."""
        if self.app_uuid is not None:
            msg = 'function %s should not be called when application uuid is set: %s.' % (fname, self.app_uuid)
            return None, msg
        return None, None
