import json
import yaml
import os
import pytest
import logging
from spytest import st
from apis.system.connection import connect_to_device, ssh_disconnect, execute_command

J2_TESTS_FILE = "j2_testcases.json"
COMMON_FILES_PATH = '/usr/share/sonic/device/cisco-8000'
JS_DIR= '/pfc_j2s'
# Place character at beginning of key string in json file to assert that the key is not
# present in the config.
NO_KEY_CHAR = "^"

def construct_metadata_table(metadata):
    required_fields = ["platform", "hwsku"]
    valid_fields = ["platform", "hwsku", "operator", "type", "resource_type"]
    for required_field in required_fields:
        assert required_field in metadata, "Required field {} missing from j2 test cases".format(required_field)
    for field in metadata:
        assert field in valid_fields, "Invalid field {}, expected one of {}".format(field, valid_fields)
    # Take advantage of json/python-dict similarities to efficiently return device metadata string
    additional_data = {"DEVICE_METADATA": {"localhost": dict(metadata)}}
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

def run_mmu_config(buffer_tier):
    buffers_tier_mapping = {"t0": "5m", "t1": "300m"}
    default_cable_length = buffers_tier_mapping[buffer_tier]
    vars = st.get_testbed_vars()
    dut = vars.D1
    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open(dir_path + '/' + J2_TESTS_FILE) as f:
        testcases_json = yaml.safe_load(f)

    for case in testcases_json["testcases"]:
        assert "metadata" in case, "Metadata table listing required in testcases json"
        assert len(case["metadata"]) > 0, "Metadata table requires entries to test"
        assert "results" in case, "Results table required in testcases json"
        for metadata in case["metadata"]:
            # Generate J2s
            metadata_str = construct_metadata_table(metadata)
            cmd="sonic-cfggen -t {}/{}/{} -k {} -a '{}'".format(COMMON_FILES_PATH, JS_DIR, "qos.json.j2", metadata["hwsku"], metadata_str)
            logging.debug('running qos command: {}'.format(cmd))
            output = st.config(dut, cmd, skip_error_check=False, conf=True)
            qosoutput = st.remove_prompt(dut, output)
            with open("/tmp/_qos.json", "w") as json_file:
                json_file.write(cmd + '\n')
                json_file.write(metadata_str + '\n')
                json.dump(qosoutput, json_file, indent=4)
            qos = json.loads(qosoutput)
            buffers_path="buffers.json.j2.{}".format(buffer_tier)
            cp_cmd= "cp {}/{} {}/{}/ ".format(COMMON_FILES_PATH, buffers_path, COMMON_FILES_PATH, JS_DIR)
            output = st.config(dut, cp_cmd, skip_error_check=False, conf=True)
            cmd= "sonic-cfggen -t {}/{}/{} -k {} -a '{}'".format(COMMON_FILES_PATH, JS_DIR, buffers_path, metadata["hwsku"], metadata_str)
            logging.debug('running buffer command: {}'.format(cmd))
            output = st.config(dut, cmd, skip_error_check=False, conf=True)
            bufoutput = st.remove_prompt(dut, output)
            with open("/tmp/_buffers.json", "w") as json_file:
                json_file.write(cmd + '\n')
                json_file.write(metadata_str + '\n')
                json.dump(bufoutput, json_file, indent=4)
            buffers = json.loads(bufoutput)
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

def test_mmu_config():
    dut_type = ""
    cmd_output = st.config(st.get_testbed_vars().D1, "cat /proc/cpuinfo | grep '^model name.: VXR$'")
    if 'VXR' in str(cmd_output.encode('ascii','ignore')):
        dut_type = "sim"
    else:
        dut_type = "hw"
    logging.debug("detected dut type {} in test_mmu_config".format(dut_type))

    if (dut_type != 'sim'):
        pytest.skip("test_mmu_config is only supported on sim", allow_module_level=True)

    for buffer_tier in ["t0", "t1"]:
        run_mmu_config(buffer_tier)
