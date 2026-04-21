# -*- coding: utf-8 -*-
# This code is part of the Ansible collection community.docker, but is an independent component.
# This particular file, and this file only, is based on the Docker SDK for Python (https://github.com/docker/docker-py/)
#
# Copyright (c) 2016-2025 Docker, Inc.
#
# It is licensed under the Apache 2.0 license (see LICENSES/Apache-2.0.txt in this collection)
# SPDX-License-Identifier: Apache-2.0

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible_collections.community.docker.plugins.module_utils._six import raise_from

from .. import errors

from .config import (
    METAFILE,
    get_current_context_name,
    get_meta_dir,
    write_context_name_to_docker_config,
)
from .context import Context


def create_default_context():
    host = None
    if os.environ.get('DOCKER_HOST'):
        host = os.environ.get('DOCKER_HOST')
    return Context("default", "swarm", host, description="Current DOCKER_HOST based configuration")


class ContextAPI(object):
    """Context API.
    Contains methods for context management:
    create, list, remove, get, inspect.
    """
    DEFAULT_CONTEXT = None

    @classmethod
    def get_default_context(cls):
        context = cls.DEFAULT_CONTEXT
        if context is None:
            context = create_default_context()
            cls.DEFAULT_CONTEXT = context
        return context

    @classmethod
    def create_context(
            cls, name, orchestrator=None, host=None, tls_cfg=None,
            default_namespace=None, skip_tls_verify=False):
        """Creates a new context.
        Returns:
            (Context): a Context object.
        Raises:
            :py:class:`docker.errors.MissingContextParameter`
                If a context name is not provided.
            :py:class:`docker.errors.ContextAlreadyExists`
                If a context with the name already exists.
            :py:class:`docker.errors.ContextException`
                If name is default.

        Example:

        >>> from docker.context import ContextAPI
        >>> ctx = ContextAPI.create_context(name='test')
        >>> print(ctx.Metadata)
        {
            "Name": "test",
            "Metadata": {},
            "Endpoints": {
                "docker": {
                    "Host": "unix:///var/run/docker.sock",
                    "SkipTLSVerify": false
                }
            }
        }
        """
        if not name:
            raise errors.MissingContextParameter("name")
        if name == "default":
            raise errors.ContextException(
                '"default" is a reserved context name')
        ctx = Context.load_context(name)
        if ctx:
            raise errors.ContextAlreadyExists(name)
        endpoint = "docker"
        if orchestrator and orchestrator != "swarm":
            endpoint = orchestrator
        ctx = Context(name, orchestrator)
        ctx.set_endpoint(
            endpoint, host, tls_cfg,
            skip_tls_verify=skip_tls_verify,
            def_namespace=default_namespace)
        ctx.save()
        return ctx

    @classmethod
    def get_context(cls, name=None):
        """Retrieves a context object.
        Args:
            name (str): The name of the context

        Example:

        >>> from docker.context import ContextAPI
        >>> ctx = ContextAPI.get_context(name='test')
        >>> print(ctx.Metadata)
        {
            "Name": "test",
            "Metadata": {},
            "Endpoints": {
                "docker": {
                "Host": "unix:///var/run/docker.sock",
                "SkipTLSVerify": false
                }
            }
        }
        """
        if not name:
            name = get_current_context_name()
        if name == "default":
            return cls.get_default_context()
        return Context.load_context(name)

    @classmethod
    def contexts(cls):
        """Context list.
        Returns:
            (Context): List of context objects.
        Raises:
            :py:class:`docker.errors.APIError`
                If something goes wrong.
        """
        names = []
        for dirname, dummy, fnames in os.walk(get_meta_dir()):
            for filename in fnames:
                if filename == METAFILE:
                    filepath = os.path.join(dirname, filename)
                    try:
                        with open(filepath, "r") as f:
                            data = json.load(f)
                        name = data["Name"]
                        if name == "default":
                            raise ValueError('"default" is a reserved context name')
                        names.append(name)
                    except Exception as e:
                        raise_from(errors.ContextException(
                            "Failed to load metafile {filepath}: {e}".format(filepath=filepath, e=e),
                        ), e)

        contexts = [cls.get_default_context()]
        for name in names:
            context = Context.load_context(name)
            if not context:
                raise errors.ContextException("Context {context} cannot be found".format(context=name))
            contexts.append(context)
        return contexts

    @classmethod
    def get_current_context(cls):
        """Get current context.
        Returns:
            (Context): current context object.
        """
        return cls.get_context()

    @classmethod
    def set_current_context(cls, name="default"):
        ctx = cls.get_context(name)
        if not ctx:
            raise errors.ContextNotFound(name)

        err = write_context_name_to_docker_config(name)
        if err:
            raise errors.ContextException(
                'Failed to set current context: {err}'.format(err=err))

    @classmethod
    def remove_context(cls, name):
        """Remove a context. Similar to the ``docker context rm`` command.

        Args:
            name (str): The name of the context

        Raises:
            :py:class:`docker.errors.MissingContextParameter`
                If a context name is not provided.
            :py:class:`docker.errors.ContextNotFound`
                If a context with the name does not exist.
            :py:class:`docker.errors.ContextException`
                If name is default.

        Example:

        >>> from docker.context import ContextAPI
        >>> ContextAPI.remove_context(name='test')
        >>>
        """
        if not name:
            raise errors.MissingContextParameter("name")
        if name == "default":
            raise errors.ContextException(
                'context "default" cannot be removed')
        ctx = Context.load_context(name)
        if not ctx:
            raise errors.ContextNotFound(name)
        if name == get_current_context_name():
            write_context_name_to_docker_config(None)
        ctx.remove()

    @classmethod
    def inspect_context(cls, name="default"):
        """Inspect a context. Similar to the ``docker context inspect`` command.

        Args:
            name (str): The name of the context

        Raises:
            :py:class:`docker.errors.MissingContextParameter`
                If a context name is not provided.
            :py:class:`docker.errors.ContextNotFound`
                If a context with the name does not exist.

        Example:

        >>> from docker.context import ContextAPI
        >>> ContextAPI.remove_context(name='test')
        >>>
        """
        if not name:
            raise errors.MissingContextParameter("name")
        if name == "default":
            return cls.get_default_context()()
        ctx = Context.load_context(name)
        if not ctx:
            raise errors.ContextNotFound(name)

        return ctx()
