# -*- coding: utf-8 -*-
# Copyright 2020 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


"""
flatten a complex object to dot bracket notation
"""
from __future__ import absolute_import, division, print_function


__metaclass__ = type

import re

from ansible.module_utils.common._collections_compat import Mapping, MutableMapping


def to_paths(var, prepend, wantlist):
    if prepend:
        var = {prepend: var}

    def flatten(data, name="", out=None):
        if out is None:
            out = {}
        if isinstance(data, (dict, Mapping, MutableMapping)):
            if data:
                for key, val in data.items():
                    if name:
                        if re.match("^[a-zA-Z_][a-zA-Z0-9_]*$", key):
                            nname = name + ".{key}".format(key=key)
                        else:
                            nname = name + "['{key}']".format(key=key)
                    else:
                        nname = key
                    flatten(val, nname, out)
            elif name:
                out[name] = {}
            else:
                out = {}
        elif isinstance(data, list):
            if data:
                for idx, val in enumerate(data):
                    flatten(val, "{name}[{idx}]".format(name=name, idx=idx), out)
            elif name:
                out[name] = []
            else:
                out = []
        else:
            out[name] = data
        return out

    out = flatten(var)
    if wantlist:
        return [out]
    return out
