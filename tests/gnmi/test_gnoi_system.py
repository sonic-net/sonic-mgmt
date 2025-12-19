import pytest
import logging
import json

#from .helper import gnoi_request
#from tests.common.helpers.assertions import pytest_assert
import re

pytestmark = [
    pytest.mark.topology('any')
]


"""
This module contains tests for the gNOI System API.
"""


def extract_first_json_substring(s):
    """
    Extract the first JSON substring from a given string.

    :param s: The input string containing JSON substring.
    :return: The first JSON substring if found, otherwise None.
    """

    json_pattern = re.compile(r'\{.*?\}')
    match = json_pattern.search(s)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            logging.error("Failed to parse JSON: {}".format(match.group()))
            return None
    return None
