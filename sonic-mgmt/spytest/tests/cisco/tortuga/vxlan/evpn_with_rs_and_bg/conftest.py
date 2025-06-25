import pytest
import yaml
import json
from spytest import st
import os
import re
import sys
import apis.system.connection as ssh_obj
import requests
import json
from ixnetwork_restpy import Files, SessionAssistant


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

SUPPORTED_VERSIONS = ["202405c"]

def pytest_addoption(parser):
    parser.addoption(
        "--ixia-config-file",
        action="store",
        default="apple_evpn_l2_with_traffic_sim.ixncfg",
        help="Path to the configuration file for IXIA.",
    )
    parser.addoption(
        "--ixia-api-key",
        action="store",
        default="invalid_api_key",
        help="API key for IXIA rest authentication.",
    )
    parser.addoption(
        "--ixia-traffic-profile",
        action="store",
        default="l2",
        help="API key for IXIA rest authentication.",
    )


@pytest.fixture(scope="session")
def command_line_args(request):
    """
    Fixture to capture command line arguments passed to pytest.
    """
    return {
        "ixia_config_file": request.config.getoption("--ixia-config-file"),
        "ixia_api_key": request.config.getoption("--ixia-api-key"),
        "ixia_traffic_profile": request.config.getoption("--ixia-traffic-profile"),
    }


def modify_config_file(config_file, var_dict):

    output_yaml_file = "temp_config.yaml"
    input_yaml_file = config_file
    config_dir = os.path.dirname(os.path.realpath(__file__)) + "/sonic_config/"
    result = os.system(
        "cp {0}{1} {0}{2}".format(config_dir, input_yaml_file, output_yaml_file)
    )
    if result != 0:
        st.report_fail("config file copy failed")
    st.wait(2)
    file_path = config_dir + output_yaml_file
    for item, value in var_dict.items():
        if re.match("(D.D.P.)|(D.T.P.)", item):
            with open(file_path, "r") as fd:
                data = fd.read()
            updated_data = re.sub(item, value, data)
            with open(file_path, "w") as fd:
                fd.write(updated_data)
    return config_dir + output_yaml_file


def get_session_id(api_key):
    """
    Get the session ID from the environment variable.
    """
    wa = st.getwa()
    ixia_vm_ip = wa.net.tb.devices["T1"]["properties"]["ix_server"]

    # Fetch the session ID dynamically
    session_url = f"https://{ixia_vm_ip}:443/api/v1/sessions"
    headers = {
        "content-type": "application/json",
        "x-api-key": f"{api_key}",
    }

    response = requests.request(
        "GET", session_url, headers=headers, verify=False, proxies={"https": None}
    )

    if response.status_code != 200:
        raise Exception(f"Failed to fetch IXIA sessions: {response.text}")

    sessions = response.json()
    if not sessions:
        raise Exception("No active IXIA sessions found.")

    return sessions[0]["id"]


@pytest.fixture(scope="session", autouse=True)
def configure_devices(command_line_args):
    tb_vars = st.ensure_min_topology("D1D3:4")

    output = st.config(tb_vars.D1, "cat /proc/cpuinfo | grep '^model name.: VXR$'")
    try:
        if "VXR" in str(output.encode("ascii", "ignore")):
            dut_type = "sim"
        else:
            dut_type = "hw"
    except Exception:
        dut_type = "hw"

    nodes = {
        "leaf0": tb_vars.D1,
        "leaf1": tb_vars.D2,
        "spine0": tb_vars.D3,
        "spine1": tb_vars.D4,
        "rs1": tb_vars.D5,
        "rs2": tb_vars.D6,
        "l3": tb_vars.D7,
        "bg1": tb_vars.D8,
        "bg2": tb_vars.D9,
    }

    for device_name in ["leaf0", "leaf1", "spine0", "spine1"]:
        device_handle = nodes[device_name]
        output = st.show(device_handle, "show version", skip_error_check=True, skip_template_check=False)
        if not any(match in output[0].get("version") for match in SUPPORTED_VERSIONS):
            st.banner(f"SONiC version is not in {SUPPORTED_VERSIONS} on switch: {device_name}, skipping config")
            pytest.exit(f"SONiC version is not in {SUPPORTED_VERSIONS} on switch: {device_name}, skipping config")
            return

    updated_config_file = modify_config_file("evpn_rs_bg_config.yaml", tb_vars)

    with open(updated_config_file, "r") as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for key, dev in nodes.items():
            try:
                st.config(
                    dev,
                    config_list[key]["sonic"]["config"],
                    skip_error_check=True,
                    skip_error_report=True,
                )
            except Exception:
                pass
            # st.config for vtysh does not work as it sends command directly to prompt and is not able to handle
            # scaled configuration. Loading config from a file is more reliable.
            with open("/tmp/spytest_frr.conf", "w") as fd:
                fd.write(config_list[key]["bgp"]["config"])
            st.upload_file_to_dut(dev, "/tmp/spytest_frr.conf", "/tmp/spytest_frr.conf")
            st.config(dev, "docker cp /tmp/spytest_frr.conf bgp:/")
            st.config(dev, "docker exec bgp bash -c 'vtysh -f /spytest_frr.conf'")
            if "dbjson" in config_list[dev]["sonic"]:
                json_data = config_list[dev]["sonic"]["dbjson"]
                with open("/tmp/sonic_db_json", "w") as db:
                    json.dump(json_data, db)
                st.upload_file_to_dut(dev, "/tmp/sonic_db_json", "/tmp/sonic_db_json")
                st.config(dev, "sudo config load /tmp/sonic_db_json -y")

    wa = st.getwa()

    # Iterate over both devices (bg1 and bg2)
    for device_name in ["bg1", "bg2"]:
        # Fetch access details for the current device
        topo_data = wa.net.tb.devices[device_name]
        ssh_data = wa.net.tb.devices[device_name]["access"]

        # Establish an SSH connection to the device
        s_handle = ssh_obj.connect_to_device(
            ssh_data["ip"],
            topo_data["credentials"]["username"],
            topo_data["credentials"]["password"],
            ssh_data["protocol"],
            ssh_data["port"],
            sudo=False,
        )

        st.log(
            f"Login to {device_name} ---------------------SUCCESS!!!!-------------------------------"
        )

        # Get the directory of the current script
        script_dir = os.path.dirname(os.path.abspath(__file__)) + "/bg_config/"
        config_file = os.path.join(script_dir, f"{device_name}_config.txt")

        with open(config_file, "r") as config:
            for line in config:
                cli = (
                    line.strip()
                )  # Use strip() to remove any trailing whitespace or newline characters
                # Execute each CLI command
                if not cli:
                    continue
                st.log(f"command: {cli}")
                try:
                    ssh_obj.execute_command(s_handle, cli)
                except Exception as e:
                    st.error(f"failed to execute command '{cli}' on {device_name}: {e}")
        ssh_obj.ssh_disconnect(s_handle)

    # Load IXIA configuration and start protocols
    config_file = command_line_args["ixia_config_file"]
    api_key = command_line_args["ixia_api_key"]
    traffic_profile = command_line_args["ixia_traffic_profile"]
    ixia_vm_ip = wa.net.tb.devices["T1"]["properties"]["ix_server"]
    session_id = get_session_id(api_key)

    session_assistant = SessionAssistant(
        IpAddress=ixia_vm_ip,
        UserName="admin",
        Password="admin",
        ApiKey=api_key,
        LogLevel=SessionAssistant.LOGLEVEL_INFO,
        SessionId=int(session_id),
    )

    # load the IXIA configuration file
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, "ixia_config", config_file)
    try:
        session_assistant.Ixnetwork.LoadConfig(Files(config_path, local_file=True))
    except Exception as e:
        st.error(f"failed to load IXIA config file: {e}")
        st.abort_module("module_config_failed", "failed to load IXIA config file")
    # wait for the configuration to be loaded
    st.wait(60)
    try:
        session_assistant.Ixnetwork.StartAllProtocols("sync")
    except Exception as e:
        st.error(f"failed to start all protocols on IXIA: {e}")
        st.abort_module("module_config_failed", "failed to start protocols on IXIA")

    if dut_type == "sim":
        st.log("starting protocols both l2 and l3 on IXIA")
        st.wait(240)

    common_input = {
        "nodes": nodes,
        "dut_type": dut_type,
        "session_assistant": session_assistant,
        "traffic_profile": traffic_profile,
    }
    yield common_input

    # cleanup after tests
    if os.path.exists(updated_config_file):
        os.system(f"rm {updated_config_file}")
    session_assistant.Ixnetwork.StopAllProtocols("sync")
    st.log("stopping all protocols on IXIA")
    st.wait(60)
    session_assistant.Ixnetwork.NewConfig()


@pytest.fixture(scope="session", autouse=True)
def start_stop_ixia():
    """
    overide base fixture under ip_fabric/conftest.py
    """
    pass
