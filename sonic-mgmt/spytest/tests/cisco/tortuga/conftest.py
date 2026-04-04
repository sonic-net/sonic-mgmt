import pytest
import os
import apis.system.logging as slog
from spytest import st
from utilities.parallel import exec_foreach
import tortuga_common_utils as common_obj

devices = []

SPYTEST_ROOT = os.path.join(os.path.dirname(__file__), "../../../spytest")
REMOTE_FILES = os.path.join(os.path.abspath(SPYTEST_ROOT), "remote")
# TODO: get frr-pythontools merged in sonic-frr code to remove version dependency
FRR_PYTHON_TOOLS = "frr-pythontools_8.5.1-0~ubuntu18.04.1_all.deb"
CHECKPOINT_GLOBAL = "tortuga_spytest_global"


@pytest.fixture(scope="session", autouse=True)
def global_config():
    global devices
    vars = st.get_testbed_vars()
    for device in vars['dut_list']:
        if st.get_device_type(device) == "sonic":
            devices.append(device)
            '''
            Save config to avoid seeing following logs:
            sudo: unable to resolve host sonic: Name or service not known
            '''
            config = "sudo config hostname sonic;sudo config save -y"
            st.config(device, config, skip_error_check=False, conf=True)

            st.upload_file_to_dut(device, "{0}/{1}".format(REMOTE_FILES, FRR_PYTHON_TOOLS),
                                  "/tmp/{}".format(FRR_PYTHON_TOOLS))
            st.log("Save config_db and frr initial configuration and use it to cleanup at the end of script")
            st.config(device, "docker cp /tmp/{} bgp:/".format(FRR_PYTHON_TOOLS))
            st.config(device, "docker exec bgp bash -c 'dpkg -i {}'".format(FRR_PYTHON_TOOLS))
            common_obj.create_checkpoint(device, cp=CHECKPOINT_GLOBAL)
            st.config(device, "sudo echo 'service integrated-vtysh-config' > /tmp/vtysh.conf")
            st.config(device, "docker cp /tmp/vtysh.conf bgp:/etc/frr/vtysh.conf")
            st.config(device, "vtysh -c 'write memory'")
            st.config(device, "docker exec bgp bash -c 'cp /etc/frr/frr.conf /tmp/frr.conf'")
    yield global_config
    for device in vars['dut_list']:
        if st.get_device_type(device) == "sonic":
            devices.append(device)
            '''
            To clear up configs during tests
            '''
            config = "sudo config save -y"
            st.config(device, config, skip_error_check=False, conf=True)



@pytest.fixture(scope="module", autouse=True)
def config_cleanup():
    exec_foreach(True, devices, slog.clear_logging)
    yield
    exec_foreach(True, devices, reset_config_db)
    exec_foreach(True, devices, reset_frr_config)


def reset_config_db(dut):
    st.log("Resetting Config by rollback checkpoint")
    common_obj.rollback_checkpoint(dut, cp=CHECKPOINT_GLOBAL)


def reset_frr_config(dut):
    st.config(dut, r"sudo echo 'service integrated-vtysh-config' > /tmp/vtysh.conf")
    st.config(dut, "docker cp /tmp/vtysh.conf bgp:/etc/frr/vtysh.conf")
    st.config(dut, "docker exec bgp bash -c 'python /usr/lib/frr/frr-reload.py --reload /tmp/frr.conf'")
