# -*- coding: utf-8 -*-
# This code is part of the Ansible collection community.docker, but is an independent component.
# This particular file, and this file only, is based on the Docker SDK for Python (https://github.com/docker/docker-py/)
#
# Copyright (c) 2016-2022 Docker, Inc.
#
# It is licensed under the Apache 2.0 license (see LICENSES/Apache-2.0.txt in this collection)
# SPDX-License-Identifier: Apache-2.0

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ._import_helper import HTTPError as _HTTPError

from ansible.module_utils.common.text.converters import to_native
from ansible_collections.community.docker.plugins.module_utils._six import raise_from


class DockerException(Exception):
    """
    A base class from which all other exceptions inherit.

    If you want to catch all errors that the Docker SDK might raise,
    catch this base exception.
    """


def create_api_error_from_http_exception(e):
    """
    Create a suitable APIError from requests.exceptions.HTTPError.
    """
    response = e.response
    try:
        explanation = response.json()['message']
    except ValueError:
        explanation = to_native((response.content or '').strip())
    cls = APIError
    if response.status_code == 404:
        if explanation and ('No such image' in str(explanation) or
                            'not found: does not exist or no pull access'
                            in str(explanation) or
                            'repository does not exist' in str(explanation)):
            cls = ImageNotFound
        else:
            cls = NotFound
    raise_from(cls(e, response=response, explanation=explanation), e)


class APIError(_HTTPError, DockerException):
    """
    An HTTP error from the API.
    """
    def __init__(self, message, response=None, explanation=None):
        # requests 1.2 supports response as a keyword argument, but
        # requests 1.1 does not
        super(APIError, self).__init__(message)
        self.response = response
        self.explanation = explanation

    def __str__(self):
        message = super(APIError, self).__str__()

        if self.is_client_error():
            message = '{0} Client Error for {1}: {2}'.format(
                self.response.status_code, self.response.url,
                self.response.reason)

        elif self.is_server_error():
            message = '{0} Server Error for {1}: {2}'.format(
                self.response.status_code, self.response.url,
                self.response.reason)

        if self.explanation:
            message = '{0} ("{1}")'.format(message, self.explanation)

        return message

    @property
    def status_code(self):
        if self.response is not None:
            return self.response.status_code

    def is_error(self):
        return self.is_client_error() or self.is_server_error()

    def is_client_error(self):
        if self.status_code is None:
            return False
        return 400 <= self.status_code < 500

    def is_server_error(self):
        if self.status_code is None:
            return False
        return 500 <= self.status_code < 600


class NotFound(APIError):
    pass


class ImageNotFound(NotFound):
    pass


class InvalidVersion(DockerException):
    pass


class InvalidRepository(DockerException):
    pass


class InvalidConfigFile(DockerException):
    pass


class InvalidArgument(DockerException):
    pass


class DeprecatedMethod(DockerException):
    pass


class TLSParameterError(DockerException):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg + (". TLS configurations should map the Docker CLI "
                           "client configurations. See "
                           "https://docs.docker.com/engine/articles/https/ "
                           "for API details.")


class NullResource(DockerException, ValueError):
    pass


class ContainerError(DockerException):
    """
    Represents a container that has exited with a non-zero exit code.
    """
    def __init__(self, container, exit_status, command, image, stderr):
        self.container = container
        self.exit_status = exit_status
        self.command = command
        self.image = image
        self.stderr = stderr

        err = ": {0}".format(stderr) if stderr is not None else ""
        msg = ("Command '{0}' in image '{1}' returned non-zero exit "
               "status {2}{3}").format(command, image, exit_status, err)

        super(ContainerError, self).__init__(msg)


class StreamParseError(RuntimeError):
    def __init__(self, reason):
        self.msg = reason


class BuildError(DockerException):
    def __init__(self, reason, build_log):
        super(BuildError, self).__init__(reason)
        self.msg = reason
        self.build_log = build_log


class ImageLoadError(DockerException):
    pass


def create_unexpected_kwargs_error(name, kwargs):
    quoted_kwargs = ["'{0}'".format(k) for k in sorted(kwargs)]
    text = ["{0}() ".format(name)]
    if len(quoted_kwargs) == 1:
        text.append("got an unexpected keyword argument ")
    else:
        text.append("got unexpected keyword arguments ")
    text.append(', '.join(quoted_kwargs))
    return TypeError(''.join(text))


class MissingContextParameter(DockerException):
    def __init__(self, param):
        self.param = param

    def __str__(self):
        return ("missing parameter: {0}".format(self.param))


class ContextAlreadyExists(DockerException):
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return ("context {0} already exists".format(self.name))


class ContextException(DockerException):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return (self.msg)


class ContextNotFound(DockerException):
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return ("context '{0}' not found".format(self.name))


class MissingRequirementException(DockerException):
    def __init__(self, msg, requirement, import_exception):
        self.msg = msg
        self.requirement = requirement
        self.import_exception = import_exception

    def __str__(self):
        return (self.msg)
