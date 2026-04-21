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


class StoreError(RuntimeError):
    pass


class CredentialsNotFound(StoreError):
    pass


class InitializationError(StoreError):
    pass


def process_store_error(cpe, program):
    message = cpe.output.decode('utf-8')
    if 'credentials not found in native keychain' in message:
        return CredentialsNotFound(
            'No matching credentials in {0}'.format(
                program
            )
        )
    return StoreError(
        'Credentials store {0} exited with "{1}".'.format(
            program, cpe.output.decode('utf-8').strip()
        )
    )
