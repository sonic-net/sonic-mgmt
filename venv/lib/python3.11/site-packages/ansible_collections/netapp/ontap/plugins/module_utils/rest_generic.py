# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# Copyright (c) 2021, Laurent Nicolas <laurentn@netapp.com>
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

""" Support functions for NetApp ansible modules

    Provides common processing for responses and errors from REST calls
"""

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import ansible_collections.netapp.ontap.plugins.module_utils.rest_response_helpers as rrh


def build_query_with_fields(query, fields):
    ''' for GET requests'''
    if fields is not None and query is None:
        query = {}
    if fields is not None:
        query['fields'] = fields
    return query


def build_query_with_timeout(query, timeout):
    ''' for POST, PATCH, DELETE requests'''
    params = {} if query else None
    if timeout > 0:
        # without return_timeout, REST returns immediately with a 202 and a job link
        #   but the job status is 'running'
        # with return_timeout, REST returns quickly with a 200 and a job link
        #   and the job status is 'success'
        params = dict(return_timeout=timeout)
    if query is not None:
        params.update(query)
    return params


def get_one_record(rest_api, api, query=None, fields=None):
    query = build_query_with_fields(query, fields)
    response, error = rest_api.get(api, query)
    record, error = rrh.check_for_0_or_1_records(api, response, error, query)
    return record, error


def get_0_or_more_records(rest_api, api, query=None, fields=None):
    query = build_query_with_fields(query, fields)
    response, error = rest_api.get(api, query)
    records, error = rrh.check_for_0_or_more_records(api, response, error)
    return records, error


def post_async(rest_api, api, body, query=None, timeout=30, job_timeout=30, headers=None, raw_error=False, files=None):
    # see delete_async for async and sync operations and status codes
    response, error = rest_api.post(api, body=body, params=build_query_with_timeout(query, timeout), headers=headers, files=files)
    # limit the polling interval to something between 5 seconds and 60 seconds
    increment = min(max(job_timeout / 6, 5), 60)
    response, error = rrh.check_for_error_and_job_results(api, response, error, rest_api, increment=increment, timeout=job_timeout, raw_error=raw_error)
    return response, error


def patch_async(rest_api, api, uuid_or_name, body, query=None, timeout=30, job_timeout=30, headers=None, raw_error=False, files=None):
    # cluster does not use uuid or name, and query based PATCH does not use UUID (for restit)
    api = '%s/%s' % (api, uuid_or_name) if uuid_or_name is not None else api
    response, error = rest_api.patch(api, body=body, params=build_query_with_timeout(query, timeout), headers=headers, files=files)
    increment = min(max(job_timeout / 6, 5), 60)
    response, error = rrh.check_for_error_and_job_results(api, response, error, rest_api, increment=increment, timeout=job_timeout, raw_error=raw_error)
    return response, error


def delete_async(rest_api, api, uuid, query=None, body=None, timeout=30, job_timeout=30, headers=None, raw_error=False):
    # query based DELETE does not use UUID (for restit)
    api = '%s/%s' % (api, uuid) if uuid is not None else api
    response, error = rest_api.delete(api, body=body, params=build_query_with_timeout(query, timeout), headers=headers)
    increment = min(max(job_timeout / 6, 5), 60)
    response, error = rrh.check_for_error_and_job_results(api, response, error, rest_api, increment=increment, timeout=job_timeout, raw_error=raw_error)
    return response, error
