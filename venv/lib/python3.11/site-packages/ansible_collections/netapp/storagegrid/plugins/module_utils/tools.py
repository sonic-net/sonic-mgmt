# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# Copyright (c) 2020, NetApp Ansible Team <ng-ansibleteam@netapp.com>
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

from __future__ import absolute_import, division, print_function

__metaclass__ = type


def first_inside_second_dict_or_list(d1, d2):
    """
    This method is used for PUT operations, where a desired state (d1) is compared against the current state (d2).
    Evaluates whether a update is needed or not.
    None values in the desired state are skipped and ignored.
    This method checks, whether d1 is a subset of d2, it does not prove equality.
    """
    if not isinstance(d1, type(d2)):
        raise AssertionError("Inputs are not of same type. Got %s and %s." % (type(d1), type(d2)))
    answer = True

    if isinstance(d1, dict):
        for key, value in d1.items():
            # key only exists in d1
            if value is None:
                continue
            if key not in d2.keys():
                return False
            else:
                value2 = d2[key]
            # keys exist in both, but values are different
            if value != value2:
                # both values can be compared
                if isinstance(value, type(value2)):
                    if isinstance(value, (str, int, float, bool)):
                        return False
                    # recursion! dict or list inside here
                    elif isinstance(value, (dict, list)):
                        # takes care that a answer="false" is not overwritten with answer="true". Once answer is false, it should ever be.
                        # Do not return at this point, as we are in a loop and have to check all elements.
                        if answer:
                            answer = first_inside_second_dict_or_list(value, value2)
                        else:
                            return False
                    else:
                        raise Exception("Unknown type in dictionary: %s.") % (type(value))
                # values are different
                else:
                    return False

    elif isinstance(d1, list):
        if len(d1) == 0:
            return answer
        else:
            if not all(isinstance(x, type(d1[0])) for x in d1):
                raise AssertionError("all elements in a list must be of same type. Not the case for: %s." % (d1))
        # case if list elements are "simple": strings, integers, bools, none
        if isinstance(d1[0], (str, int, float, bool, type(None))):
            if not set(d1).issubset(set(d2)):
                return False
        # case if list elements are "complex": recursion! dict or list inside here
        elif isinstance(d1[0], dict):
            for item in d1:
                if any(first_inside_second_dict_or_list(item, item2) for item2 in d2):
                    continue
                else:
                    return False
        elif isinstance(d1[0], list):
            raise Exception("Feature missing: nested lists are not supported yet.")
        else:
            raise Exception("Unsupported type inside dictionary or list: %s.") % (type(d1[0]))

    else:
        raise Exception("Unsupported input type %s.") % (type(d1))

    return answer
