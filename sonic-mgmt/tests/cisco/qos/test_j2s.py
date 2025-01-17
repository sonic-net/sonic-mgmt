import json
import pytest
import logging
from tests.cisco.common.utils import skip_if_not_sim

J2_TESTS_FILE = "cisco/qos/j2_testcases.json"
COMMON_FILES_PATH = '/usr/share/sonic/device/cisco-8000'
OUTPUT_FILE = "/tmp/cfggen.json"
# Place character at beginning of key string in json file to assert that the key is not
# present in the config.
NO_KEY_CHAR = "^"

pytestmark = [ pytest.mark.topology('t1') ]

def construct_metadata_table(metadata):
    required_fields = ["platform", "hwsku"]
    valid_fields = ["platform", "hwsku", "operator", "type", "resource_type"]
    for required_field in required_fields:
        assert required_field in metadata, "Required field {} missing from j2 test cases".format(required_field)
    for field in metadata:
        assert field in valid_fields, "Invalid field {}, expected one of {}".format(field, valid_fields)
    # Take advantage of json/python-dict similarities to efficiently return device metadata string
    additional_data = {"DEVICE_METADATA": {"localhost": metadata}}
    return str(additional_data).replace("'", '"')

def verify_dict_is_subset(subset, superset, dict_path="root"):
    for key in subset:
        new_dict_path = dict_path + "[" + key + "]"
        assert len(key) > 0, "Key with 0 length at path {}".format(dict_path)
        if key[0] == NO_KEY_CHAR:
            key = key[1:] # Remove no-key indicator
            logging.debug("Verifying config does NOT have key {}".format(new_dict_path))
            assert key not in superset, "Key '{}' was unexpectedly present in config at path {}".format(key, new_dict_path)
            continue
        logging.debug("Verifying config has correct key {}".format(new_dict_path))
        assert key in superset, "Key '{}' missing from config".format(key)
        if isinstance(subset[key], dict):
            verify_dict_is_subset(subset[key], superset[key], new_dict_path)
        else:
            logging.debug("Verifying expected value for key {} = {}".format(new_dict_path, subset[key]))
            assert subset[key] == superset[key], \
                "Expected {} = {}, but got config value {}".format(
                    new_dict_path, subset[key], superset[key])

@pytest.mark.parametrize("buffers_tier", ["t0", "t1"])
def test_mmu_config(duthost, enum_rand_one_per_hwsku_hostname, skip_if_not_sim, verify_cmd, buffers_tier):
    if duthost.facts["asic_type"] != "cisco-8000":
        pytest.skip("Test is only supported for cisco-8000")
    buffers_tier_mapping = {"t0": "5m",
                            "t1": "300m"}
    default_cable_length = buffers_tier_mapping[buffers_tier]
    with open(J2_TESTS_FILE) as f:
        testcases_json = json.load(f)
    for case in testcases_json["testcases"]:
        assert "metadata" in case, "Metadata table listing required in testcases json"
        assert len(case["metadata"]) > 0, "Metadata table requires entries to test"
        assert "results" in case, "Results table required in testcases json"
        for metadata in case["metadata"]:
            # Generate J2s
            metadata_str = construct_metadata_table(metadata)
            output = verify_cmd("sonic-cfggen -t {}/{} -k {} -a '{}'".format(
                COMMON_FILES_PATH,
                "qos.json.j2",
                metadata["hwsku"],
                metadata_str))
            qos = json.loads(output)
            output = verify_cmd("sonic-cfggen -t {}/{} -k {} -a '{}'".format(
                COMMON_FILES_PATH,
                "buffers.json.j2.{}".format(buffers_tier),
                metadata["hwsku"],
                metadata_str))
            buffers = json.loads(output)
            config = dict(qos)
            config.update(buffers)
            # Verify based on test case in j2 testcases file.
            logging.debug("### Verifying with metadata {}".format(metadata_str))
            verify_dict_is_subset(case["results"], config)
            # Verify default cable length if no type was provided
            if "type" not in metadata:
                cable_table = config["CABLE_LENGTH"]["AZURE"]
                for key in cable_table:
                    assert cable_table[key] == default_cable_length, \
                        "cable length {} does not match expected {}".format(cable_table[key], default_cable_length)
