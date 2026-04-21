# This code is strewn with things that are not defined on Python3 (unicode,
# long, etc) but they are all shielded by version checks.  This is also an
# upstream vendored file that we're not going to modify on our own
# pylint: disable=undefined-variable
#
# Copyright (c) 2010-2024 Benjamin Peterson
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Extracted from https://github.com/benjaminp/six/blob/7d2a0e96602b83cd082896c8c224a87f1efe2111/six.py
# SPDX-License-Identifier: MIT

from __future__ import absolute_import, division, print_function


__metaclass__ = type

import sys as _sys


# Useful for very coarse version differentiation.
PY2 = _sys.version_info[0] == 2
PY3 = _sys.version_info[0] > 2


if PY3:
    string_types = (str,)
    integer_types = (int,)
    binary_type = bytes
    text_type = str

    def iteritems(d):
        return d.items()

    from shlex import quote as shlex_quote  # pylint: disable=unused-import
    from collections.abc import Mapping, Sequence  # pylint: disable=unused-import
    from queue import Empty  # pylint: disable=unused-import
    from urllib.parse import quote, urlparse  # pylint: disable=unused-import
else:
    string_types = (basestring,)  # noqa: F821, pylint: disable=undefined-variable
    integer_types = (int, long)  # noqa: F821, pylint: disable=undefined-variable
    binary_type = str
    text_type = unicode  # noqa: F821, pylint: disable=undefined-variable

    def iteritems(d):
        return d.iteritems()

    from pipes import quote as shlex_quote
    from collections import Mapping, Sequence
    from Queue import Empty
    from urllib import quote
    from urlparse import urlparse

if PY3:
    import builtins as _builtins
    getattr(_builtins, "exec")("""def raise_from(value, from_value):
    try:
        raise value from from_value
    finally:
        value = None
""")
else:
    def raise_from(value, from_value):
        raise value


def add_metaclass(metaclass):
    """Class decorator for creating a class with a metaclass."""
    def wrapper(cls):
        orig_vars = cls.__dict__.copy()
        slots = orig_vars.get('__slots__')
        if slots is not None:
            if isinstance(slots, str):
                slots = [slots]
            for slots_var in slots:
                orig_vars.pop(slots_var)
        orig_vars.pop('__dict__', None)
        orig_vars.pop('__weakref__', None)
        if hasattr(cls, '__qualname__'):
            orig_vars['__qualname__'] = cls.__qualname__
        return metaclass(cls.__name__, cls.__bases__, orig_vars)
    return wrapper
