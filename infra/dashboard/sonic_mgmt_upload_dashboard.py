#!/usr/bin/env python3
import argparse
import glob
import json
import sys
import os
import time
import requests
import tarfile
from pathlib import Path
import paramiko
import shlex
import re 
from requests.auth import HTTPBasicAuth
from urllib.request import urlopen
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from db_tool_sonicsol import PostgresDBConnectionSonicSol
from populate_test_case_table_sonicsol import analyze_all_test_cases
import defusedxml.ElementTree as ET

NODE_NAME = os.getenv("NODE_NAME", "unknown")
JENKINS_JOB_BASE_NAME = os.getenv("JOB_BASE_NAME")
RING_4_JOB_BASE_NAME = "management_full_run_test"

PLATFORM_NPU_FILE_MAP = os.path.dirname(os.path.realpath(__file__)) + '/sonic_mgmt_platform_to_npu.json'
SERVER_CREDS_MAP = os.path.dirname(os.path.realpath(__file__)) + '/server_creds.json'

TEST_REPORT_CLIENT_VERSION = (1, 1, 0)

MAXIMUM_XML_SIZE = 20e7  # 20MB
MAXIMUM_SUMMARY_SIZE = 1024  # 1MB

# Fields found in the testsuite/root section of the JUnit XML file.
TESTSUITES_TAG = "testsuites"
TESTSUITE_TAG = "testsuite"
REQUIRED_TESTSUITE_ATTRIBUTES = {
    ("time", float),
    ("tests", int),
    ("skipped", int),
    ("failures", int),
    ("errors", int),
    ("timestamp", str)
}
EXTRA_XML_SUMMARY_ATTRIBUTES = {
    ("xfails", int)
}
# Fields found in the metadata/properties section of the JUnit XML file.
# FIXME: These are specific to pytest, needs to be extended to support spytest.
PROPERTIES_TAG = "properties"
PROPERTY_TAG = "property"
REQUIRED_METADATA_PROPERTIES = [
    "topology",
    "testbed",
    "timestamp",
    "host",
    "asic",
    "platform",
    "hwsku",
    "os_version",
]

# Fields found in the testcase sections of the JUnit XML file.
TESTCASE_TAG = "testcase"
REQUIRED_TESTCASE_ATTRIBUTES = [
    "classname",
    "file",
    "line",
    "name",
    "time",
]

# Fields found in the testcase/properties section of the JUnit XML file.
# FIXME: These are specific to pytest, needs to be extended to support spytest.
TESTCASE_PROPERTIES_TAG = "properties"
TESTCASE_PROPERTY_TAG = "property"
REQUIRED_TESTCASE_PROPERTIES = [
    "start",
    "end",
    "CustomMsg"
]

REQUIRED_TESTCASE_JSON_FIELDS = ["result", "error", "summary"]


class JUnitXMLValidationError(Exception):
    """Expected errors that are thrown while validating the contents of the JUnit XML file."""

class TestResultJSONValidationError(Exception):
    """Expected errors that are thrown while validating the contents of the Test Result JSON file."""


def validate_json_file(path):
    if not os.path.exists(path):
        print(f"{path} not found")
        return
    if not os.path.isfile(path):
        print(f"{path} is not a JSON file")
        return
    try:
        with open(path) as f:
            test_result_json = json.load(f)
    except Exception as e:
        raise TestResultJSONValidationError(f"Could not load JSON file {path}: {e}") from e

    return test_result_json


def validate_junit_xml_file(document_name):
    """Validate that an XML file is valid JUnit XML.

    Args:
        document_name: The name of the document.

    Returns:
        The root of the validated XML document.

    Raises:
        JUnitXMLValidationError: if any of the following are true:
            - The provided file doesn't exist
            - The provided file exceeds 10MB
            - The provided file is unparseable
            - The provided file is missing required fields
    """
    if not os.path.exists(document_name) or not os.path.isfile(document_name):
        raise JUnitXMLValidationError("file not found")

    if os.path.getsize(document_name) > MAXIMUM_XML_SIZE:
        raise JUnitXMLValidationError("provided file is too large")

    try:
        tree = ET.parse(document_name, forbid_dtd=True)
    except Exception as e:
        raise JUnitXMLValidationError(f"could not parse {document_name}: {e}") from e

    return _validate_junit_xml(tree.getroot())


def validate_junit_xml_archive(directory_name, strict=False):
    """Validate that an XML archive contains valid JUnit XML.

    Args:
        directory_name: The name of the directory containing XML documents.

    Returns:
        A list of roots of validated XML documents.

    Raises:
        JUnitXMLValidationError: if any of the following are true:
            - The provided directory doesn't exist
            - The provided files exceed 10MB
            - Any of the provided files are unparseable
            - Any of the provided files are missing required fields
    """
    if not os.path.exists(directory_name) or not os.path.isdir(directory_name):
        print("directory {} not found".format(directory_name))
        return

    roots = []
    metadata_source = None
    metadata = {}
    doc_list = glob.glob(os.path.join(directory_name, "tr.xml"))
    doc_list += glob.glob(os.path.join(directory_name, "*test*.xml"))
    doc_list += glob.glob(os.path.join(directory_name, "**", "*test*.xml"), recursive=True)
    doc_list = set(doc_list)

    total_size = 0
    for document in doc_list:
        total_size += os.path.getsize(document)

    if total_size > MAXIMUM_XML_SIZE:
        raise JUnitXMLValidationError("provided directory is too large")

    for document in doc_list:
        try:
            root = validate_junit_xml_file(document)
            root_metadata = {k: v for k, v in _parse_test_metadata(root).items()
                             if k in REQUIRED_METADATA_PROPERTIES and k != "timestamp"}

            if root_metadata:
                # All metadata from a single test run should be identical, so we
                # just use the first one we see to validate the rest.
                if not metadata_source:
                    metadata_source = document
                    metadata = root_metadata

                if root_metadata != metadata:
                    raise JUnitXMLValidationError(f"{document} metadata differs from {metadata_source}\n"
                                                  f"{document}: {root_metadata}\n"
                                                  f"{metadata_source}: {metadata}")

            roots.append(root)
        except Exception as e:
            if strict:
                raise JUnitXMLValidationError(f"could not parse {document}: {e}") from e

            print(f"could not parse {document}: {e} - skipping")

    if not roots:
        print("provided directory {} does not contain any valid XML files".format(directory_name))
    return roots

def _validate_junit_xml(root):
    _validate_test_summary(root)
    _validate_test_metadata(root)
    _validate_test_cases(root)

    return root


def _validate_test_summary(root):
    if root.tag == TESTSUITES_TAG:
        testsuit_element = root.find(TESTSUITE_TAG)
        if not testsuit_element:
            raise JUnitXMLValidationError(f"{TESTSUITE_TAG} tag not found")
    elif root.tag == TESTSUITE_TAG:
        testsuit_element = root
    else:
        raise JUnitXMLValidationError(f"Either {TESTSUITES_TAG} or {TESTSUITE_TAG} tag are not found on root element")

    for xml_field, expected_type in REQUIRED_TESTSUITE_ATTRIBUTES:
        if xml_field not in testsuit_element.keys():
            raise JUnitXMLValidationError(f"{xml_field} not found in <{TESTSUITE_TAG}> element")

        try:
            expected_type(testsuit_element.get(xml_field))
        except Exception as e:
            raise JUnitXMLValidationError(
                f"invalid type for {xml_field} in {TESTSUITE_TAG}> element: "
                f"expected a number, received "
                f'"{testsuit_element.get(xml_field)}"'
            ) from e


def _validate_test_metadata(root):
    properties_element = root.find(PROPERTIES_TAG)

    if not properties_element:
        return

    seen_properties = []
    for prop in properties_element.iterfind(PROPERTY_TAG):
        property_name = prop.get("name", None)

        if not property_name:
            continue

        if property_name not in REQUIRED_METADATA_PROPERTIES:
            continue

        if property_name in seen_properties:
            raise JUnitXMLValidationError(
                f"duplicate metadata element: {property_name} seen more than once"
            )

        property_value = prop.get("value", None)

        if property_value is None:  # Some fields may be empty
            raise JUnitXMLValidationError(
                f'invalid metadata element: no "value" field provided for {property_name}'
            )

        seen_properties.append(property_name)

    if set(seen_properties) < set(REQUIRED_METADATA_PROPERTIES):
        raise JUnitXMLValidationError("missing metadata element(s)")


def _validate_test_case_properties(root):
    testcase_properties_element = root.find(TESTCASE_PROPERTIES_TAG)

    if not testcase_properties_element:
        return

    seen_testcase_properties = []
    for testcase_prop in testcase_properties_element.iterfind(TESTCASE_PROPERTY_TAG):
        testcase_property_name = testcase_prop.get("name", None)

        if not testcase_property_name:
            continue

        if testcase_property_name not in REQUIRED_TESTCASE_PROPERTIES:
            continue

        if testcase_property_name in seen_testcase_properties:
            raise JUnitXMLValidationError(
                f"duplicate metadata element: {testcase_property_name} seen more than once"
            )

        testcase_property_value = testcase_prop.get("value", None)

        if testcase_property_value is None:  # Some fields may be empty
            raise JUnitXMLValidationError(
                f'invalid metadata element: no "value" field provided for {testcase_property_name}'
            )

        seen_testcase_properties.append(testcase_property_name)

    missing_testcase_property = set(REQUIRED_TESTCASE_PROPERTIES) - set(seen_testcase_properties)
    if missing_testcase_property:
        print("missing testcase property: {}".format(list(missing_testcase_property)))


def _validate_test_cases(root):
    def _validate_test_case(test_case):
        for attribute in REQUIRED_TESTCASE_ATTRIBUTES:
            if attribute not in test_case.keys():
                raise JUnitXMLValidationError(
                    f'"{attribute}" not found in test case '
                    f"\"{test_case.get('name', 'Name Not Found')}\""
                )
        _validate_test_case_properties(test_case)

    cases = root.findall(TESTCASE_TAG)

    for test_case in cases:
        _validate_test_case(test_case)

def _convert_to_num(num_str):
    try:
        return int(num_str)
    except:
        return float(num_str)

def get_platform_name_npu(platform):
    with open(PLATFORM_NPU_FILE_MAP) as cfg_file:
        PLATFORM_NPU_FILE_MAP_DICT = json.load(cfg_file)

    if platform in PLATFORM_NPU_FILE_MAP_DICT:
        return PLATFORM_NPU_FILE_MAP_DICT[platform]["platform_name"], PLATFORM_NPU_FILE_MAP_DICT[platform]["project"]
    else:
        raise Exception(f"Platform mapping for {platform} DOES NOT EXIST!!")
        
def parse_test_result(roots, build_id, log_link, metadata, sanity_type, image_id, lt_image, result, platform_name, project, sql, gt_image, allure, use_backup):
    """Parse a given XML document into JSON.

    Args:
        root: The root of the XML document to parse.

    Returns:
        A dict containing the parsed test result.
    """
    if not roots:
        print("No XML file needs to be parsed or the file is empty.")
        return

    db = PostgresDBConnectionSonicSol(use_backup)


    build_start_all = None
    build_end_all = None

    result_sum = {}
    values = []

    job_base_name = RING_4_JOB_BASE_NAME

    if JENKINS_JOB_BASE_NAME != RING_4_JOB_BASE_NAME and build_id is None: 
        # Getting Build id to use for populating test_case and result_sum 
        build_id_result = db.get_next_sequence_value("mgmt_full_run_test_build_id_seq")
        build_id = 0 

        job_base_name = "sonic_mgmt_upload"

        if build_id == None:
            raise Exception("Issue with build_id creation!!!")
        else:
            build_id = build_id_result[0][0]
            print(f"BUILD ID FOR THIS RUN: {build_id}")
    
    # Variables needed for test_case analysis
    run_results = [metadata["platform"], metadata["topology"], result[0], project]
    test_names = []
    test_state_map = {}

    for root in roots:
        if root.tag == TESTSUITES_TAG:
            root = root.find(TESTSUITE_TAG)

        
        test_cases = _parse_test_cases(root)
        root_metadata = _parse_test_summary(root)
        test_summary = _extract_test_summary(test_cases)   # Getting test case summary
        if test_cases == {}:
            continue 

        main_key = list(test_cases.keys())[0]

        if len(test_cases[main_key][0]["name"]) == 0 and test_cases[main_key][0]["file"] is None: 
            continue 

        test_script_full_name = test_cases[main_key][0]["file"]

        test_category = test_cases[main_key][0]["classname"].split(".")[0]
        test_script_name = "No_Name.py"

        if test_script_full_name is not None: 
            test_category = test_script_full_name.split("/")[0]
            test_script_name = os.path.basename(test_script_full_name)
        elif test_script_full_name is None: 
            test_script_full_name = test_category + "/" + test_script_name

        for key, value in test_summary.items():
            if key not in result_sum:
                result_sum[key] = _convert_to_num(value)
            else:
                result_sum[key] += _convert_to_num(value)

        # Uploading root results to DB!
        build_start = None 
        build_end = None 

        dt = datetime.fromisoformat(root_metadata['timestamp'])

        if dt.tzinfo:
            dt = dt.astimezone(timezone.utc)

        build_start = dt.replace(tzinfo=None)
        
        if not build_start_all:
            build_start_all = build_start
        else:
            build_start_all = min(build_start_all, build_start)

        tot_time = float(root_metadata["time"])
        
        build_end = build_start + timedelta(seconds=tot_time)
        build_end = build_end.strftime("%Y-%m-%d %H:%M:%S.%f")

        if not build_end_all:
            build_end_all = build_end
        else:
            build_end_all = max(build_end_all, build_end)
        
        for i in range(len(test_cases[main_key])):

            test_state = "Passed"
            if test_cases[main_key][i]['result'] == 'skipped':
                test_state = 'Skipped'
            elif test_cases[main_key][i]['result'] == 'failure':
                test_state = 'Failed'
            elif test_cases[main_key][i]['result'] == 'error':
                test_state = 'Error'
            elif "xfail" in test_cases[main_key][i]['result']:
                test_state = 'XFail'
            
            start_time = None
            end_time = None
            if 'start' in test_cases[main_key][i]:
                start_time = test_cases[main_key][i]['start']
            if 'end' in test_cases[main_key][i]: 
                end_time = test_cases[main_key][i]['end']

            test_names.append(test_cases[main_key][i]['classname'] + "." + test_cases[main_key][i]['name'])
            test_state_map[test_cases[main_key][i]['classname'] + "." + test_cases[main_key][i]['name']] = test_state

            values.append(
                (
                    build_id,
                    job_base_name,
                    start_time,
                    end_time,
                    test_state,
                    test_category,
                    test_cases[main_key][i]['name'],
                    test_cases[main_key][i]['classname'] + "." + test_cases[main_key][i]['name'],
                    None,
                    metadata["platform"],
                    metadata["topology"],
                    None,
                    sanity_type,
                    result[0],
                    None,
                    None,
                    None,
                    allure,
                    "True",
                    image_id,
                    test_cases[main_key][i]['summary'][:512],
                    metadata["hwsku"],
                    test_script_name,
                    test_script_full_name
                )
            )

    #print(values) <-- prints out ALL Test cases
    ret = db.execute_values(sql, values)
    db.conn.commit()

    total = result_sum["total"] = result_sum["tests"]
    del result_sum["tests"]
    passed = result_sum["passed"]
    skipped = result_sum["skipped"]

    success_rate = round(100*passed/(total-skipped), 2)
    if success_rate == 100:
        state = 'pass'
        failure_reason = None
    else:
        state = 'fail'
        failure_reason = "test_cases_failed"
    
    result_sum["success_rate"] = success_rate
    result_sum["state"] = state
    result_sum["failure_reason"] = failure_reason

    state = state.capitalize()

    stream = result[0]
    release =  ".".join(result[0].split('.')[1:-1])
    
    if release == "": 
        release = stream.split('.', 1)[0] # to look for the correct release in streams like 'c-master.ztp.....'

    #populate p2 sanity table
    key_data = {
        "build_id": build_id, 
        "job_base_name": job_base_name, 
        "sonic_image_link": result[1],
        "platform": metadata["platform"],
        "topology": metadata["topology"],
        "run_hw": "True",
        "sku": metadata["hwsku"], 
        "sanity_type": sanity_type, 
        "stream": stream,
        "p2build_job_id": image_id, 
        "release": release,
        "build_state": state, 
        "build_start": str(build_start_all), 
        "build_end": build_end_all, 
        "platform_name": platform_name,
        "project": project, 
        "report_link": allure
    }
    
    if job_base_name == "sonic_mgmt_upload": 
        key_data["log_tarball_link"] = log_link
        db.insert("management_full_run_test", key_data)

    elif job_base_name == RING_4_JOB_BASE_NAME: 
        del key_data["build_id"]
        db.update("management_full_run_test", key_data = {"build_id": build_id}, updated_data = key_data)

    # updating the result_sum separately since is dict type
    db.update("management_full_run_test", key_data = {"build_id": build_id}, updated_data = {"result_sum": json.dumps(result_sum)})

    analyze_all_test_cases(build_id, test_names, test_state_map, run_results, sanity_type, lt_image, image_id, db, metadata["hwsku"], gt_image)

    db.close_connection()

def _parse_test_summary(root):
    test_result_summary = {}
    for attribute, _ in REQUIRED_TESTSUITE_ATTRIBUTES:
        test_result_summary[attribute] = root.get(attribute)

    return test_result_summary

def _extract_test_summary(test_cases):
    test_result_summary = defaultdict(int)
    test_result_summary = {"tests": 0, "failed": 0, "passed": 0, "skipped": 0, "errors": 0, "xfails": 0, "time": 0.0}

    case = None
    for _, cases in test_cases.items():
        for case in cases:
            # Error may occur along with other test results, to count error separately.
            # The result field is unique per test case, either error or failure.
            # xfails is the counter for all kinds of xfail results (include success/failure/error/skipped)
            test_result_summary["tests"] += 1
            test_result_summary["failed"] += case["result"] == "failure"
            test_result_summary["skipped"] += case["result"] == "skipped"
            test_result_summary["errors"] += case["error"]
            test_result_summary["time"] += float(case["time"])
            test_result_summary["xfails"] += \
                case["result"] == "xfail_failure" or case["result"] == \
                "xfail_error" or case["result"] == "xfail_skipped" or case["result"] == "xfail_success"

    test_result_summary = {k: str(v) for k, v in test_result_summary.items()}
    total = int(test_result_summary["failed"]) + int(test_result_summary["skipped"]) \
        + int(test_result_summary["errors"]) + int(test_result_summary["xfails"])
    passed = int(test_result_summary["tests"]) - int(total)
    passed = max(0, passed)
    test_result_summary["passed"] = str(passed)
    if case is None:
        return test_result_summary
    name = case['file']
    return test_result_summary
  
def _parse_test_metadata(root):
    properties_element = root.find(PROPERTIES_TAG)

    if not properties_element:
        return {}

    test_result_metadata = {}
    for prop in properties_element.iterfind(PROPERTY_TAG):
        if prop.get("value"):
            test_result_metadata[prop.get("name")] = prop.get("value")

    return test_result_metadata


def _parse_testcase_properties(root):
    testcase_properties_element = root.find(TESTCASE_PROPERTIES_TAG)

    if not testcase_properties_element:
        return {}

    testcase_properties = {}
    for testcase_prop in testcase_properties_element.iterfind(TESTCASE_PROPERTY_TAG):
        if testcase_prop.get("value"):
            if testcase_prop.get("name") == "CustomMsg":
                if not testcase_properties.get(testcase_prop.get("name")):
                    testcase_properties[testcase_prop.get("name")] = testcase_prop.get("value")
                else:
                    testcase_properties[testcase_prop.get("name")] = testcase_prop.get("value") + ", " + \
                                                                     testcase_properties[testcase_prop.get("name")]
            else:
                testcase_properties[testcase_prop.get("name")] = testcase_prop.get("value")

    return testcase_properties


def _parse_test_cases(root):
    test_case_results = defaultdict(list)

    def _parse_test_case(test_case):
        result = {}

        # FIXME: This is specific to pytest, needs to be extended to support spytest.

        if test_case.get("classname") is None and test_case.get("name") is None: 
            return None, None 

        test_class_tokens = test_case.get("classname").split(".")
        feature = test_class_tokens[0]

        for attribute in REQUIRED_TESTCASE_ATTRIBUTES:
            result[attribute] = test_case.get(attribute)
        for attribute in REQUIRED_TESTCASE_PROPERTIES:
            testcase_properties = _parse_testcase_properties(test_case)
            if attribute in testcase_properties:
                result[attribute] = testcase_properties[attribute]

        # NOTE: "if failure" and "if error" does not work with the ETree library.
        failure = test_case.find("failure")
        error = test_case.find("error")
        skipped = test_case.find("skipped")

        # Any test which marked as xfail will drop out a property to the report xml file.
        # Add prefix "xfail_" to tests which are marked with xfail
        properties_element = test_case.find(PROPERTIES_TAG)
        xfail_case = ""
        if properties_element:
            for prop in properties_element.iterfind(PROPERTY_TAG):
                if prop.get("name") == "xfail":
                    xfail_case = "xfail_"
                    break

        # NOTE: "error" is unique in that it can occur alongside a succesful, failed, or skipped test result.
        # Because of this, we track errors separately so that the error can be correlated with the stage it
        # occurred.
        # By looking into test results from past 300 days, error only occur with skipped test result.
        #
        # If there is *only* an error tag we note that as well, as this indicates that the framework
        # errored out during setup or teardown.
        if failure is not None:
            result["result"] = "{}failure".format(xfail_case)
            summary = failure.get("message", "")
        elif skipped is not None:
            result["result"] = "{}skipped".format(xfail_case)
            summary = skipped.get("message", "")
        elif error is not None:
            result["result"] = "{}error".format(xfail_case)
            summary = error.get("message", "")
        else:
            result["result"] = "{}success".format(xfail_case)
            summary = ""

        result["summary"] = summary[:min(len(summary), MAXIMUM_SUMMARY_SIZE)]
        result["error"] = error is not None

        return feature, result

    incomplete_test = 0 
    for test_case in root.findall("testcase"):
        feature, result = _parse_test_case(test_case)
        if feature is None and result is None: 
            incomplete_test += 1
        else: 
            test_case_results[feature].append(result)
    
    if incomplete_test > 0: 
        print(f"# of Possible Test Cases with INCOMPLETE Data: {incomplete_test}")

    return dict(test_case_results)


def _update_test_metadata(current, update):
    # Case 1: On the very first update, current will be empty since we haven't seen any results yet.
    if not current:
        return update.copy()

    # Case 2: For test cases that are 100% skipped there will be no metadata added, so we need to
    # default to current.
    if not update:
        return current.copy()


def validate_junit_json_file(path):
    """Validate that a JSON file is a valid test report.

    Args:
        path: The path to the JSON file.

    Returns:
        The validated JSON file.

    Raises:
        TestResultJSONValidationError: if any of the following are true:
            - The provided file doesn't exist
            - The provided file is unparseable
            - The provided file is missing required fields
    """
    test_result_json = validate_json_file(path)
    if not test_result_json:
        return
    _validate_json_metadata(test_result_json)
    _validate_json_summary(test_result_json)
    _validate_json_cases(test_result_json)

    return test_result_json


def _validate_json_metadata(test_result_json):
    if "test_metadata" not in test_result_json:
        raise TestResultJSONValidationError("test_metadata section not found in provided JSON file")

    seen_properties = []
    for prop, value in test_result_json["test_metadata"].items():
        if prop not in REQUIRED_METADATA_PROPERTIES:
            continue

        if prop in seen_properties:
            raise TestResultJSONValidationError(
                f"duplicate metadata element: {prop} seen more than once"
            )

        if value is None:  # Some fields may be empty
            raise TestResultJSONValidationError(
                f'invalid metadata element: no "value" field provided for {prop}'
            )

        seen_properties.append(prop)

    if set(seen_properties) < set(REQUIRED_METADATA_PROPERTIES):
        raise TestResultJSONValidationError("missing metadata element(s)")


def _validate_json_summary(test_result_json):
    if "test_summary" not in test_result_json:
        raise TestResultJSONValidationError("test_summary section not found in provided JSON file")

    summary = test_result_json["test_summary"]

    for field, expected_type in REQUIRED_TESTSUITE_ATTRIBUTES:
        if field not in summary:
            raise TestResultJSONValidationError(f"{field} not found in test_summary section")

        try:
            expected_type(summary[field])
        except Exception as e:
            raise TestResultJSONValidationError(
                f"invalid type for {field} in test_summary section: "
                f"expected a number, received "
                f'"{summary[field]}"'
            ) from e


def _validate_json_cases(test_result_json):
    if "test_cases" not in test_result_json:
        raise TestResultJSONValidationError("test_cases section not found in provided JSON file")

    def _validate_test_case(test_case):
        for attribute in REQUIRED_TESTCASE_ATTRIBUTES + REQUIRED_TESTCASE_JSON_FIELDS:
            if attribute not in test_case:
                raise TestResultJSONValidationError(
                    f'"{attribute}" not found in test case '
                    f"\"{test_case.get('name', 'Name Not Found')}\""
                )
        for attribute in REQUIRED_TESTCASE_PROPERTIES:
            if attribute not in test_case:
                print("missing testcase property {} in testcase {}".format(attribute, test_case["classname"]))

    for _, feature in test_result_json["test_cases"].items():
        for test_case in feature:
            _validate_test_case(test_case)


def pull_dir_via_sftp(host, user, password, remote_dir, local_dest, port=22, keep_remote_tar=False):
    print(f"Tarring path {user}@{host}:{remote_dir} and storing to local directory: '{local_dest}'")
    remote_dir = str(remote_dir)
    local_dest = Path(local_dest) / host
    local_dest.mkdir(parents=True, exist_ok=True)

    tarball_name = f"{remote_dir.replace('/', '_')}.tar.gz"
    remote_tar = f"/tmp/{tarball_name}"
    local_tar = local_dest / tarball_name
    tar_cmd = f"set -euo pipefail; tar -czf {shlex.quote(remote_tar)} {remote_dir}"

    if local_tar.exists() and local_tar.is_file():
        msg = f"Tarball '{tarball_name}' already exists in local directory '{local_dest}'! Exit."
        #raise ValueError(msg)
        print(msg)
        return

    """
    relative_path = Path(remote_dir.lstrip('/'))
    possible_path = local_dest / relative_path

    if possible_path.exists(): 
        print(f"{possible_path} already exists. Using previous run directory data Skipping.")
        return possible_path
    """

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=host, username=user, password=password, port=port)

    # Tar the directory on the remote host
    print(f"tar cmd: {tar_cmd}")
    _, stdout, stderr = ssh.exec_command(tar_cmd)
    rc = stdout.channel.recv_exit_status()
    if rc != 0:
        msg = stderr.read().decode()
        ssh.close()
        raise RuntimeError(f"Remote tar failed (rc={rc}): {msg}")

    # Download the tarball via SFTP
    sftp = ssh.open_sftp()
    try:
        sftp.get(remote_tar, str(local_tar))
    finally:
        sftp.close()
    print(f"From {host}, Downloaded {remote_tar} to local: '{local_tar}'")

    # Optionally remove the tarball on the remote
    if not keep_remote_tar:
        ssh.exec_command(f"rm -f {shlex.quote(remote_tar)}")
    ssh.close()

    # Extract locally
    with tarfile.open(local_tar, mode="r:gz") as tf:
         tf.extractall(path=local_dest)

    # Clean up local tar
    try:
        os.remove(str(local_tar))
    except OSError:
        raise Exception("Unable to clean up local tar file")

    relative_path = Path(remote_dir.lstrip('/'))
    final_path = local_dest / relative_path
    print(f"Destination of directory now! {final_path}")
    return final_path

def _run_script():
    parser = argparse.ArgumentParser(
        description="Upload SONiC Mgmt Run Logs to Dashboard/DB.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
            Examples:
            python3 sonic_mgmt_upload_dashboard.py tests/files/directory/ -d --curr_server xxxx --sanity_type xxxxxx --image_id xxxxx --allure https://.... --desc 'ava'
            """,
    )
    parser.add_argument("file_name", metavar="file", type=str, help="A file to validate/parse.")
    parser.add_argument(
        "--directory", "-d", action="store_true", help="Provide a directory instead of a single file.", required=True
    )
    parser.add_argument(
        "--curr_server", type=str, help="Provide the current server of the result run directory.", required=True
    )
    parser.add_argument(
        "--sanity_type", type=str, help="Please provide the sanity_type", required=True
    )
    parser.add_argument(
        "--image_id", type=int, help="Please provide the Image ID.", required=True
    )
    parser.add_argument(
        "--allure", type=str, help="For Manual runs, we need this argument to be provided", required=True
    )
    parser.add_argument(
        "--desc", type=str, help="Provide a description for the run.", required=False
    )
    parser.add_argument(
        "--strict",
        "-s",
        action="store_true",
        help="Fail validation checks if ANY file in a given directory is not parseable."
    )
    parser.add_argument(
        "--validate-only", action="store_true", help="Validate without parsing the file.",
    )
    parser.add_argument(
        "--run_id", type=int, help="Please provide the Build ID of the run", required=False
    )
    parser.add_argument(
        "--project", type=str, help="Please provide the NPU ID of the run", required=False, default=None
    )
    parser.add_argument(
        "--dev",  action="store_true", help='Run in dev mode. Data written to dev dir',
    )

    args = parser.parse_args()

    if JENKINS_JOB_BASE_NAME == RING_4_JOB_BASE_NAME and args.run_id is None: # NEED TO ADD AUTOMATED RUN INFO!!
        raise Exception("Need Build ID for this Job!")

    host = args.curr_server

    with open(SERVER_CREDS_MAP) as server_creds:
        SERVER_CREDS_MAP_DICT = json.load(server_creds)

    if host not in SERVER_CREDS_MAP_DICT: 
        raise Exception("Do not have information for this particular host in mapping!")

    user = SERVER_CREDS_MAP_DICT[host]["user"]
    password = SERVER_CREDS_MAP_DICT[host]["password"]

    local_dest = "/var/www/html/logs/sonic_mgmt/"

    file_name = pull_dir_via_sftp(host, user, password, args.file_name, local_dest)
    log_file = str(file_name)

    prefix_to_remove = '/var/www/html'
    regex_pattern = '^' + re.escape(prefix_to_remove)

    log_link = re.sub(regex_pattern, '', log_file)
    
    if NODE_NAME not in SERVER_CREDS_MAP_DICT:
        raise Exception(f"Do not have information for node {NODE_NAME} in mapping!")

    node_host = SERVER_CREDS_MAP_DICT[NODE_NAME]["host"]

    log_link = "http://" + node_host + log_link + "/"
        
    try:
        if args.directory:
            roots = validate_junit_xml_archive(file_name, args.strict)
    except JUnitXMLValidationError as e:
        print(f"XML validation failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error occured during validation: {e}")
        sys.exit(2)

    metadata = None # Get build info 
    for root in roots: 
        root = _validate_junit_xml(root)

        if root.tag == TESTSUITES_TAG:
            root = root.find(TESTSUITE_TAG)
        
        metadata = _update_test_metadata(metadata, _parse_test_metadata(root))
        if metadata != {}: 
            break 
    
    image_id = args.image_id

    db = PostgresDBConnectionSonicSol(use_backup=False)
    result = db.find_one("pipeline2_build", key_data={"build_id": image_id}, column_list=["stream", "sonic_image_link"])

    if result == None or "https:" in result[0]: 
        raise Exception("This image ID does not exist")
    else:   
        platform_name, project = get_platform_name_npu(metadata["platform"])

        if args.project:
            if type(project) == str and project != args.project: 
                raise Exception(f"Gave wrong NPU ID for platform: {platform_name}")
            elif type(project) == list and args.project not in project: 
                raise Exception(f"Gave wrong NPU ID for platform: {platform_name}")
            else:
                project = args.project 

        if type(project) == list and args.project == None:
            project = "G200"

        # See if previous images are even possible
        image_record = db.get_images(result[0], project, metadata["platform"], image_id)

        # Get closest previous image
        lt_image = 0 
        if len(image_record) > 0: 
            less_than_image = db.get_closest_image_id(result[0], project, metadata["platform"], image_id)
            if less_than_image == None: 
                raise Exception(f"Was not able to find an image id less than {image_id}!!")
            else: 
                lt_image = less_than_image[0][0]

        if lt_image == 0:
            lt_image = None

        # Get closest next image (IF POSSIBLE)
        gt_image = 0 
        great_than_image = db.get_closest_image_id(result[0], project, metadata["platform"], image_id, than_type="greater")
        if len(great_than_image) > 0: 
            gt_image = great_than_image[0][0]  

        if gt_image == 0: 
            gt_image = None

        db.close_connection()

        sql = """
            INSERT INTO test_case 
                (
                    parent_sanity_id, 
                    parent_job_base_name, 
                    start_time, 
                    end_time, 
                    state, 
                    test_category, 
                    test_case_name, 
                    test_case_full_name, 
                    test_tag, 
                    platform, 
                    topology, 
                    pipeline_type, 
                    sanity_type, 
                    stream, 
                    pr_repo_name, 
                    pr_id, 
                    pr_link,
                    report_link,
                    run_hw,
                    image_id,
                    comments,
                    sku, 
                    test_script_name,
                    test_script_full_name
                ) 
            VALUES %s
        """
        build_id = args.run_id

        parse_test_result(roots, build_id, log_link, metadata, args.sanity_type, image_id, lt_image, result, platform_name, project, sql, gt_image, args.allure, args.dev)


if __name__ == "__main__":
    _run_script()
