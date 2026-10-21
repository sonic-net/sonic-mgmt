"""Encode literal values for PTF's Python-assignment command-line contract."""
import keyword
import math
import re


PARAMETER_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')


def serialize_test_params(params):
    if not isinstance(params, dict):
        raise ValueError('test_params must be an object')
    for name, value in params.items():
        if (not isinstance(name, str) or not PARAMETER_NAME.fullmatch(name)
                or keyword.iskeyword(name) or name.startswith('__')):
            raise ValueError('invalid PTF parameter name: {!r}'.format(name))
        if type(value) not in (str, int, float, bool, type(None)):
            raise ValueError('test_params values must be scalars')
        if type(value) is float and not math.isfinite(value):
            raise ValueError('test_params values must be finite')
    return ';'.join('{}={!r}'.format(name, params[name]) for name in sorted(params))
