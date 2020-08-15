"""Tests for the JUnit XML parser."""
import os
import re
import pytest

from test_reporting.junit_xml_parser import validate_junit_xml_stream, validate_junit_xml_file
from test_reporting.junit_xml_parser import parse_test_result, JUnitXMLValidationError


VALID_TEST_RESULT = """<?xml version="1.0" encoding="utf-8"?>
<testsuite errors="1" failures="1" name="pytest" skipped="0" tests="3" time="214.054">
    <properties>
        <property name="topology" value="t0"/>
        <property name="markers" value=""/>
        <property name="host" value="vlab-01"/>
        <property name="asic" value="vs"/>
        <property name="platform" value="x86_64-kvm_x86_64-r0"/>
        <property name="hwsku" value="Force10-S6000"/>
        <property name="os_version" value="master.449-9c22d19b"/>
    </properties>
    <testcase classname="bgp.test_bgp" file="bgp/test_bgp.py" line="161" name="test_bgp_fact" time="109.472" />
    <testcase classname="bgp.test_bgp" file="bgp/test_bgp.py" line="248" name="test_bgp_speaker" time="46.316">
        <failure message="test machine go brr">
            this is definitely a stacktrace
        </failure>
    </testcase>
    <testcase classname="acl.test_acl" file="acl/test_acl.py" line="257" name="test_acl" time="58.161">
        <error message="test machine broke">
            also a stacktrace
        </error>
    </testcase>
</testsuite>"""

VALID_TEST_RESULT_FILE = os.path.join(os.path.dirname(__file__), "files/sample_tr.xml")

EXPECTED_JSON_OUTPUT = {
    "test_cases": {
        "acl": [
            {
                "classname": "acl.test_acl",
                "error": "test machine broke",
                "file": "acl/test_acl.py",
                "line": "257",
                "name": "test_acl",
                "time": "58.161"
            }
        ],
        "bgp": [
            {
                "classname": "bgp.test_bgp",
                "file": "bgp/test_bgp.py",
                "line": "161",
                "name": "test_bgp_fact",
                "time": "109.472"
            },
            {
                "classname": "bgp.test_bgp",
                "failure": "test machine go brr",
                "file": "bgp/test_bgp.py",
                "line": "248",
                "name": "test_bgp_speaker",
                "time": "46.316"
            }
        ]
    },
    "test_metadata": {
        "asic": "vs",
        "host": "vlab-01",
        "hwsku": "Force10-S6000",
        "os_version": "master.449-9c22d19b",
        "platform": "x86_64-kvm_x86_64-r0",
        "topology": "t0"
    },
    "test_summary": {
        "errors": "1",
        "failures": "1",
        "skipped": "0",
        "tests": "3",
        "time": "214.054"
    }
}

BILLION_LAUGHS_ATTACK = """<!DOCTYPE xmlbomb [
<!ENTITY a "1234567890" >
<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">
<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;">
<!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;">
]>
<bomb>&d;</bomb>
"""

QUADRATIC_BLOWUP_ATTACK = """
<!DOCTYPE bomb [
<!ENTITY a "xxxxxxx">
]>
<bomb>&a;&a;&a;</bomb>
"""

EXTERNAL_ENTITY_EXPANSION_ATTACK = """<!DOCTYPE external [
<!ENTITY ee SYSTEM "http://www.python.org/some.xml">
]>
<root>&ee;</root>
"""

DTD_RETRIEVAL_ATTACK = """<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
    <head/>
    <body>text</body>
</html>
"""


def test_valid_junit_xml():
    validate_junit_xml_stream(VALID_TEST_RESULT)


@pytest.mark.parametrize("encoding", ["utf-8", "ascii"])
def test_valid_junit_xml_byte_stream(encoding):
    validate_junit_xml_stream(bytes(VALID_TEST_RESULT, encoding))


@pytest.mark.parametrize("input_string", [None, ""])
def test_invalid_junit_xml_missing_xml(input_string):
    with pytest.raises(JUnitXMLValidationError, match="could not parse provided XML stream"):
        validate_junit_xml_stream(input_string)


def test_invalid_junit_xml_too_large():
    with pytest.raises(JUnitXMLValidationError, match="provided stream is too large"):
        validate_junit_xml_stream("a" * int(10e7))


@pytest.mark.parametrize("token,replacement", [("</", "<"), ("</properties>", "")])
def test_invalid_junit_xml_broken_xml(token, replacement):
    test_string = VALID_TEST_RESULT.replace(token, replacement)
    with pytest.raises(JUnitXMLValidationError, match="could not parse provided XML stream"):
        validate_junit_xml_stream(test_string)


@pytest.mark.parametrize(
    "token,replacement,message",
    [
        ("testsuite", "fail", ".* tag not found on root element"),
        ("errors", "bunnies", ".* not found in .* element"),
        ("0", "rabbits", "invalid type .* expected a number, .*"),
    ],
)
def test_invalid_junit_xml_testsuite_errors(token, replacement, message):
    test_string = VALID_TEST_RESULT.replace(token, replacement)
    with pytest.raises(JUnitXMLValidationError, match=message):
        validate_junit_xml_stream(test_string)


def test_invalid_junit_xml_no_metadata():
    test_string = re.sub(r"<properties>[\s\S]*?</properties>", "", VALID_TEST_RESULT)
    with pytest.raises(JUnitXMLValidationError, match="metadata element .* not found"):
        validate_junit_xml_stream(test_string)


@pytest.mark.parametrize(
    "token,replacement,message",
    [
        ("name=", "foo=", 'invalid metadata element: "name" not found in .*'),
        ("asic", "basic", "unexpected metadata element: .*"),
        ("hwsku", "host", "duplicate metadata element: .*"),
        ("value", "salut", 'invalid metadata element: no "value" field provided .*'),
    ],
)
def test_invalid_junit_xml_metadata_errors(token, replacement, message):
    test_string = VALID_TEST_RESULT.replace(token, replacement)
    with pytest.raises(JUnitXMLValidationError, match=message):
        validate_junit_xml_stream(test_string)


def test_invalid_junit_xml_no_test_cases():
    test_string = re.sub(r"<testcase[\s\S]*?</testcase>", "", VALID_TEST_RESULT)
    with pytest.raises(JUnitXMLValidationError, match="No test cases found"):
        validate_junit_xml_stream(test_string)


@pytest.mark.parametrize(
    "token,replacement,message",
    [
        ("classname", "hehe", ".* not found in test case .*"),
        ('name="test_acl"', "", '.* not found in test case "Name Not Found"'),
        ('message="test machine go brr"', "", "no message found for failure .*"),
        ('message="test machine broke"', "", "no message found for error .*"),
    ],
)
def test_invalid_junit_xml_test_case_errors(token, replacement, message):
    test_string = VALID_TEST_RESULT.replace(token, replacement)
    with pytest.raises(JUnitXMLValidationError, match=message):
        validate_junit_xml_stream(test_string)


exploits = {
    "billion laughs": BILLION_LAUGHS_ATTACK,
    "quadratic blowup": QUADRATIC_BLOWUP_ATTACK,
    "external entity": EXTERNAL_ENTITY_EXPANSION_ATTACK,
    "dtd retrieval": DTD_RETRIEVAL_ATTACK,
}


@pytest.mark.parametrize(
    "exploit_string", ["billion laughs", "quadratic blowup", "external entity", "dtd retrieval"]
)
def test_invalid_junit_xml_exploits(exploit_string):
    with pytest.raises(JUnitXMLValidationError, match="could not parse provided XML stream"):
        validate_junit_xml_stream(exploits[exploit_string])


def test_json_output_from_string():
    root = validate_junit_xml_stream(VALID_TEST_RESULT)
    assert parse_test_result(root) == EXPECTED_JSON_OUTPUT


@pytest.mark.parametrize("encoding", ["utf-8", "ascii"])
def test_json_output_from_byte_stream(encoding):
    root = validate_junit_xml_stream(bytes(VALID_TEST_RESULT, encoding))
    assert parse_test_result(root) == EXPECTED_JSON_OUTPUT


def test_json_output_from_file():
    root = validate_junit_xml_file(VALID_TEST_RESULT_FILE)
    assert parse_test_result(root) == EXPECTED_JSON_OUTPUT


def test_xml_file_not_found():
    with pytest.raises(JUnitXMLValidationError, match="file not found"):
        validate_junit_xml_file("nonexistent.xml")
