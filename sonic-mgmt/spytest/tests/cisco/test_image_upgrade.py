
import pytest
import apis.system.basic as basic_obj
from spytest import st, SpyTestDict
import paramiko
from scp import SCPClient
import os

@pytest.fixture(scope="module", autouse=True)
def initial_setup():
    global vars, image_name
    vars = st.get_testbed_vars()

def file_transfer():
    ## Download image to local path ##
    try:
        location = "wget http://10.194.84.241/IMAGES/10257/sonic-cisco-8000.bin"
        image_name = location.split("/")[-1]
        result = os.system(location)
        if result == 0:
            st.log("Temp Image copy passed ")
        else:
            st.report_fail("Temp Image copy failed")
    except Exception as e:
        st.log("Error: {}".format(e))
        st.report_fail("Temp Image copy failed")
    for dut in st.get_dut_names():
        st.banner("Moving Sonic Image file onto: {}".format(dut))
        st.config(dut, "sudo rm *.bin")
        
        scp_upload(local_path = "/data/tests/"+image_name, remote_path= "/home/cisco", hostname = vars.mgmt_ipv4[dut],
         username= st.get_username(dut), password= st.get_password(dut)) 
    os.system("rm {}".format(image_name))
    return image_name
    
def test_image_upgrade():
    image_name = file_transfer()
    install_cmd = "sudo sonic-installer install {} -y".format(image_name)
    for dut in st.get_dut_names():
        st.banner("Running Sonic Installer Command on {}".format(dut)) 
        st.config(dut,"docker ps -a")
        st.config(dut,"show version") 
        st.config(dut, "sudo config save -y")
        st.config(dut, "sudo sonic-installer cleanup -y")
        st.config(dut, "show boot")
        st.config(dut, install_cmd)
        st.config(dut, "show boot")
        st.config(dut, "sudo rm *.bin")
        st.config(dut, "sudo reboot")
    st.wait(600)
    for dut in st.get_dut_names():
        st.config(dut,"docker ps -a")
        st.config(dut,"show version")
    st.report_pass("test_case_passed")

def scp_upload(local_path, remote_path, hostname, username, password, port=22):
    try:
        # Create an SSH client object
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect to the SSH server
        ssh_client.connect(hostname, port=port, username=username, password=password)
        
        # Create an SCP client
        with SCPClient(ssh_client.get_transport()) as scp:
            # Upload the local file to the remote path
            scp.put(local_path, remote_path)
        
        st.log("File uploaded successfully.")
    except Exception as e:
        st.log("Error: {}".format(e))
    finally:
        # Close the SSH connection
        ssh_client.close()
