# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# Copyright (c) 2020, Laurent Nicolas <laurentn@netapp.com>
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


def api_error(api, error):
    """format error message for api error, if error is present"""
    return "calling: %s: got %s." % (api, error) if error is not None else None


def no_response_error(api, response):
    """format error message for empty response"""
    return "calling: %s: no response %s." % (api, repr(response))


def job_error(response, error):
    """format error message for job error"""
    return "job reported error: %s, received %s." % (error, repr(response))


def unexpected_response_error(api, response, query=None):
    """format error message for reponse not matching expectations"""
    msg = "calling: %s: unexpected response %s." % (api, repr(response))
    if query:
        msg += " for query: %s" % repr(query)
    return response, msg


def get_num_records(response):
    """ num_records is not always present
        if absent, count the records or assume 1
    """
    if 'num_records' in response:
        return response['num_records']
    return len(response['records']) if 'records' in response else 1


def check_for_0_or_1_records(api, response, error, query=None):
    """return None if no record was returned by the API
       return record if one record was returned by the API
       return error otherwise (error, no response, more than 1 record)
    """
    if error:
        return (None, api_error(api, error)) if api else (None, error)
    if not response:
        return None, no_response_error(api, response)
    num_records = get_num_records(response)
    if num_records == 0:
        return None, None     # not found
    if num_records != 1:
        return unexpected_response_error(api, response, query)
    if 'records' in response:
        return response['records'][0], None
    return response, None


def check_for_0_or_more_records(api, response, error):
    """return None if no record was returned by the API
       return records if one or more records was returned by the API
       return error otherwise (error, no response)
    """
    if error:
        return (None, api_error(api, error)) if api else (None, error)
    if not response:
        return None, no_response_error(api, response)
    if get_num_records(response) == 0:
        return None, None     # not found
    if 'records' in response:
        return response['records'], None
    error = 'No "records" key in %s' % response
    return (None, api_error(api, error)) if api else (None, error)


def check_for_error_and_job_results(api, response, error, rest_api, **kwargs):
    """report first error if present
       otherwise call wait_on_job and retrieve job response or error
    """
    format_error = not kwargs.pop('raw_error', False)
    if error:
        if format_error:
            error = api_error(api, error)
    # we expect two types of response
    #   a plain response, for synchronous calls
    #   or a job response, for asynchronous calls
    # and it's possible to expect both when 'return_timeout' > 0
    #
    # when using a query instead of UUID, REST return jobs (a list of jobs) rather than a single job
    # only restit can send a query, all other calls are using a UUID.
    elif isinstance(response, dict):
        job = None
        if 'job' in response:
            job = response['job']
        elif 'jobs' in response:
            if response['num_records'] > 1:
                error = "multiple jobs in progress, can't check status"
            else:
                job = response['jobs'][0]
        if job:
            job_response, error = rest_api.wait_on_job(job, **kwargs)
            if error:
                if format_error:
                    error = job_error(response, error)
            else:
                response['job_response'] = job_response
    return response, error
