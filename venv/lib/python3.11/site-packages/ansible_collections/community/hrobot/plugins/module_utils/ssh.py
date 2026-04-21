# -*- coding: utf-8 -*-

# Copyright (c), Felix Fontein <felix@fontein.de>, 2019
# Simplified BSD License (see LICENSES/BSD-2-Clause.txt or https://opensource.org/licenses/BSD-2-Clause)
# SPDX-License-Identifier: BSD-2-Clause

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible.module_utils.basic import AVAILABLE_HASH_ALGORITHMS as _AVAILABLE_HASH_ALGORITHMS

import base64
import binascii
import re


_SPACE_RE = re.compile(' +')
_FINGERPRINT_PART = re.compile('^[0-9a-f]{2}$')


class FingerprintError(Exception):
    pass


def remove_comment(public_key):
    return ' '.join(_SPACE_RE.split(public_key.strip())[:2])


def normalize_fingerprint(fingerprint, size=16):
    if ':' in fingerprint:
        fingerprint = fingerprint.split(':')
    else:
        fingerprint = [fingerprint[i:i + 2] for i in range(0, len(fingerprint), 2)]
    if len(fingerprint) != size:
        raise FingerprintError(
            'Fingerprint must consist of {0} 8-bit hex numbers: got {1} 8-bit hex numbers instead'.format(size, len(fingerprint)))
    for i, part in enumerate(fingerprint):
        new_part = part.lower()
        if len(new_part) < 2:
            new_part = '0{0}'.format(new_part)
        if not _FINGERPRINT_PART.match(new_part):
            raise FingerprintError(
                'Fingerprint must consist of {0} 8-bit hex numbers: number {1} is invalid: "{2}"'.format(size, i + 1, part))
        fingerprint[i] = new_part
    return ':'.join(fingerprint)


def extract_fingerprint(public_key, alg='md5', size=16):
    try:
        public_key = _SPACE_RE.split(public_key.strip())[1]
    except IndexError:
        raise FingerprintError(
            'Error while extracting fingerprint from public key data: cannot split public key into at least two parts')
    try:
        public_key = base64.b64decode(public_key)
    except (binascii.Error, TypeError) as exc:
        raise FingerprintError(
            'Error while extracting fingerprint from public key data: {0}'.format(exc))
    try:
        algorithm = _AVAILABLE_HASH_ALGORITHMS[alg]
    except KeyError:
        raise FingerprintError(
            'Hash algorithm {0} is not available. Possibly running in FIPS mode.'.format(alg.upper()))
    digest = algorithm()
    digest.update(public_key)
    return normalize_fingerprint(digest.hexdigest(), size=size)
