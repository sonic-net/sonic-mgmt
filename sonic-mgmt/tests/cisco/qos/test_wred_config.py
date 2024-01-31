"""
Tests for verifying the configuration on the DUT 
to match the expected WRED probability configuration
"""
import re
import time
import logging
import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.cisco_data import is_cisco_device
import json

pytestmark = [
    pytest.mark.topology('any')
]

def enable_serviceability_cli(duthost):
    show_command = "sudo show platform npu voq cgm_profile -i Ethernet0 -t 0"
    err_msg = "debug shell server for asic 0 is not running"
    output = duthost.command(show_command)['stdout']
    if err_msg not in output:
        return
    duthost.command("config platform cisco sdk-debug enable")
    time.sleep(20)
    output = duthost.command(show_command)['stdout']
    if err_msg not in output:
        return
    time.sleep(300)
    output = duthost.command(show_command)['stdout']
    if err_msg in output:
        pytest.fail(
            "This test failed since serviceability CLI is not available")


def get_asic_type(duthost):
    dutAsic = None
    output = duthost.command("cat /usr/release_info")['stdout']
    matchObj = re.search(r"PROJECT: ([a-z0-9]+)", output, re.M)
    if matchObj:
        dutAsic = matchObj.group(1)
    pytest_assert(dutAsic, "Cannot identify DUT ASIC type")
    
    return dutAsic


def test_verify_wred_drop_config(duthosts, rand_one_dut_hostname, request):
    """
    @summary: Verify lossy queue output of `show platform npu voq cgm_profile with wred_profile drop probability`
    """
    duthost = duthosts[rand_one_dut_hostname]
    if not is_cisco_device(duthost):
        pytest.skip("Skipping as not a Cisco device")

    enable_serviceability_cli(duthost)
    show_command = "sudo show platform npu voq cgm_profile -i {} -t {} -d"
    port = "Ethernet0"
    tc = 0

    # Set larger thresholds for pacific since lossy eviction to HBM
    drop_probability = 5
    asic_type = get_asic_type(duthost)
    if asic_type == "pacific":
        max_threshold = 62914560
        min_threshold = 12582912
    else:
        max_threshold = 4194304
        min_threshold = 1048576
    
    # Create new WRED profile
    asic = duthost.get_port_asic_instance(port)
    db = 4
    new_wred_profile = "AZURE_LOSSY_test"
    asic.run_redis_cmd(
        argv=[
            "redis-cli", "-n", db, "HMSET", "WRED_PROFILE|{}".format(new_wred_profile),
            'ecn', 'ecn_none', 'green_drop_probability', drop_probability,
            'green_max_threshold', max_threshold, 'green_min_threshold', min_threshold,
            'red_drop_probability', '100', 'red_max_threshold', '0', 'red_min_threshold', '0',
            'wred_green_enable', 'true', 'wred_red_enable', 'true',
            'wred_yellow_enable', 'true', 'yellow_drop_probability', drop_probability,
            'yellow_max_threshold', max_threshold, 'yellow_min_threshold', min_threshold
        ]
    )
    asic.run_redis_cmd(
        argv=[
            "redis-cli", "-n", db, "HGETALL", "WRED_PROFILE|{}".format(new_wred_profile)
        ]
    )

    # Apply new WRED profile to Ethernet0 tc0
    asic.run_redis_cmd(
        argv=[
            "redis-cli", "-n", db, "HSET", "QUEUE|{}|{}".format(port, tc),
            "wred_profile", new_wred_profile
        ]
    )
    asic.run_redis_cmd(
        argv=[
            "redis-cli", "-n", db, "HGETALL", "QUEUE|{}|{}".format(port, tc)
        ]
    )

    # Check CLI output
    result = duthost.command(show_command.format(port, tc))
    traceback_found = "Traceback" in result["stdout"]
    assert not traceback_found, "Traceback found in show platform npu voq for Port"
    assert result["stdout"], "No output for show platform npu voq CLI"
    json_str = result["stdout"].strip()
    try:
        data = json.loads(json_str)
    except Exception as e:
        pytest.fail("JSon load error: {}".format(e))

    if asic_type == "pacific":
        # Check wred drop probablity for hbm
        block_size = 6144
        wred_config = None
        if "wred_config" in data:
            wred_config = data["wred_config"]
        assert (wred_config), "wred drop probability is not set"
        assert (wred_config["action"] == "DROP"), "wred action is not set to DROP"
        
        probabilities = wred_config["probabilities"]
        thresholds = wred_config["thresholds"]
        min_threshold_found = False
        for i in range(len(probabilities)):
            prob = probabilities[i]
            if not min_threshold_found and prob > 0:
                min_threshold_found = True
                assert (thresholds[i] * block_size > min_threshold and thresholds[i-1] * block_size <= min_threshold
                        ), "drop probability at min_threshold is not set correctly"
            if round(prob * 100) == drop_probability:
                assert (thresholds[i] * block_size <= max_threshold and probabilities[i+1] == 1.0
                        ), "drop probability at max_threshold is not set correctly"

    else:
        # Check WRED drop probabilities for SMS
        voq_thresholds = data["bq_list"]
        voq_drop_data = None
        if "voq_drop_probability_g" in data:
            voq_drop_data = data["voq_drop_probability_g"][0]
        assert (voq_drop_data), "drop probability is not set"

        min_threshold_found = False
        for voq_region in range(len(voq_drop_data)):
            prob = voq_drop_data[voq_region][0]
            if not min_threshold_found and prob > 0:
                min_threshold_found = True
                assert (
                voq_thresholds[voq_region] > min_threshold and voq_thresholds[voq_region-1] <= min_threshold
                ), "drop probability at min_threshold is not set correctly, voq_region {} doesn't satisfy {} <= {} < {}".format(voq_region, voq_thresholds[voq_region-1], min_threshold, voq_thresholds[voq_region])
            if round(prob * 100) == drop_probability:
                assert (
                voq_thresholds[voq_region] <= max_threshold and\
                    voq_thresholds[voq_region+1] > max_threshold and\
                        voq_drop_data[voq_region+1][0] == 1.0
                ), "drop probability at max_threshold is not set correctly"

    # Remove WRED profile from Ethernet0 TC0
    asic.run_redis_cmd(
        argv=[
            "redis-cli", "-n", db, "HDEL", "QUEUE|{}|{}".format(port, tc),
            "wred_profile"
        ]
    )

    # Remove wred profile
    asic.run_redis_cmd(
        argv=[
            "redis-cli", "-n", db, "DEL", "WRED_PROFILE|AZURE_LOSSY_test"
        ]
    )
