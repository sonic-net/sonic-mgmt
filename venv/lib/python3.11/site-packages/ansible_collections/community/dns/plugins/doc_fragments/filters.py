# -*- coding: utf-8 -*-
#
# Copyright (c) 2022 Felix Fontein
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


class ModuleDocFragment(object):

    DOCUMENTATION = r"""
options:
  icann_only:
    description:
      - This controls whether only entries from the ICANN section of the Public Suffix List are used, or also entries from
        the Private section. For example, C(.co.uk) is in the ICANN section, but C(github.io) is in the Private section.
    type: boolean
    default: false
"""

    PUBLIC_SUFFIX = r"""
options:
  keep_unknown_suffix:
    description:
      - This treats unknown TLDs as valid public suffixes. So for example the public suffix
        of C(example.tlddoesnotexist) is C(.tlddoesnotexist) if this is V(true). If set to
        V(false), it will return an empty string in this case.
      - This option corresponds to whether the global wildcard rule C(*) in the Public
        Suffix List is used or not.
    type: boolean
    default: true
"""

    REGISTERABLE_DOMAIN = r"""
options:
  only_if_registerable:
    description:
      - This controls the behavior in case there is no label in front of the public suffix.
        This is the case if the DNS name itself is a public suffix.
      - If set to V(false), in this case the public suffix is treated as a registrable domain.
      - If set to V(true) (default), the registrable domain of a public suffix is interpreted as an
        empty string.
    type: boolean
    default: true
  keep_unknown_suffix:
    description:
      - This treats unknown TLDs as valid public suffixes. So for example the public suffix of
        C(example.tlddoesnotexist) is C(.tlddoesnotexist) if this is V(true), and hence the
        registrable domain of C(www.example.tlddoesnotexist) is C(example.tlddoesnotexist).
        If set to V(false), the registrable domain of C(www.example.tlddoesnotexist) is
        C(tlddoesnotexist).
      - This option corresponds to whether the global wildcard rule C(*) in the Public Suffix List
        is used or not.
    type: boolean
    default: true
"""

    GET = r"""
options:
  normalize_result:
    description:
      - This controls whether the result is reconstructed from the normalized name used during lookup. During normalization,
        ulabels are converted to alabels, and every label is converted to lowercase. For example, the ulabel C(ëçãmplê) is
        converted to C(xn--mpl-llatwb) (puny-code), and C(Example.COM) is converted to C(example.com).
    type: boolean
    default: false
"""
