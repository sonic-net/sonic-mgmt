'''
    Purpose: This may be used to copy image from a specific location to DUT and do sonic-install. 
    Requirements: (before running this testcase) 
        1. copy required image to a server and note down the server's ip, file name and file location.
        2. Please fill server's ip, nodes to install, file name and location in the input file
        3. Make sure web server is running on  the server or copy image to a server that has already web server running
        4. Here is the spytest command to run testcase,
        ./bin/spytest --testbed /data/cnest_solution_topo_hw_cluster3.yaml --device-feature-group master 
        --module-init-max-timeout=28000 --tc-max-timeout=28000 /data/tests/cisco/tortuga/solution/test_cnest_load_image.py i
        --env "input_file=cnest_load_image_input_file.yaml"
    Author: Lenny Dontuboyina <ldontubo@cisco.com>
'''
import os
import pytest
import yaml
import paramiko
from scp import SCPClient
from spytest import st, tgapi, SpyTestDict
import apis.system.basic as basic_obj
import apis.system.reboot as reboot_obj
import threading
from spytest.utils import poll_wait

@pytest.fixture(scope="module", autouse=True)
def initial_setup():
    global vars, test_cfg, inputs_file
    vars = st.get_testbed_vars()
    inputs_file = st.getenv('input_file', None)
    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open(dir_path + '/' + inputs_file) as f:
        test_cfg = yaml.load(f, Loader=yaml.FullLoader)

def scp_upload(local_path, remote_path, hostname, username, password, port=22):
    try:
        # Create an SSH client object
        st.log("Creating SSH Client......")
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect to the SSH server
        st.log("Connecting to SSH Server......{}".format(hostname))
        ssh_client.connect(hostname, port=port, username=username, password=password)
        
        # Create an SCP client
        with SCPClient(ssh_client.get_transport()) as scp:
            # Upload the local file to the remote path
            st.log("Copying file from local {} to remote {}......".format(local_path, remote_path))
            scp.put(local_path, remote_path)
        
        st.log("File uploaded successfully.")
    except Exception as e:
        st.log("ERROR: COPYING FILE FROM LOCAL TO REMOTE NOT SUCCESSFULL......")
        st.log("Error: {}".format(e))
    finally:
        # Close the SSH connection
        st.log("SSH connection closing.")
        ssh_client.close()

def check_dockers_online(dut, timeout=300):
    """
    Check if all dockers are online on the given device.
    
    """
    try:
        st.log("Checking docker status on {}".format(dut))
        count = basic_obj.get_and_match_docker_count(dut)
        if poll_wait(basic_obj.get_and_match_docker_count, timeout, dut, count):
            st.log("All dockers are online on {}".format(dut))
            return True
        else:
            st.error("Dockers are not online on {} after {} seconds".format(dut, timeout))
            return False
    except Exception as err:
        st.error("Error while checking docker status on {}: {}".format(dut, err))
        return False

def restore_helper_file(dut):
    st.config(dut, "mkdir -p /etc/spytest/remote")
    st.config(dut, "cp /etc/sonic/spytest-helper.py /etc/spytest/remote/spytest-helper.py")
    st.config(dut, "ls -lrt /etc | grep spytest")

def sonic_install(i_type,file_name, dut):
    '''
    This helper function to start parallel threads only for sonic-install
    '''
    st.banner("Installing {} image on DUT: {}".format(i_type,dut))
    # Saving config before installation
    st.config(dut, "sudo config save -y")
    st.config(dut, "sudo sonic-installer install {} -y".format(file_name))

def transfer_and_install_image(d_groups, i_files, server_ip):
    """
    Helper function to transfer and install an image on a DUT.
    """
    try:
        st.log("WGET getting image from IMAGES folder.")
        for platform_type in d_groups.keys():
            cmd_string = 'wget http://{}{}{}'.format(server_ip, test_cfg['global']['image_info']['images'][platform_type]['location'], i_files[platform_type])
            wget_result = os.system(cmd_string)
        if wget_result  == 0:
            st.log("{} Image copy Completed".format(platform_type))
        else:
            st.log("WGET Failed....with return value {} for the platform type: {}  ".format(wget_result, platform_type))
            st.error("Failed to transfer SCP")
        for dut in st.get_dut_names():
            for image_type, devices in d_groups.items():
                if dut in devices:
                    st.log("Uploading image to DUT ---> {}.".format(dut))
                    scp_upload(
                        local_path="/data/tests/{}".format(i_files[image_type]),
                        remote_path="/home/cisco",
                        hostname=vars.mgmt_ipv4[dut],
                        username=st.get_username(dut),
                        password=st.get_password(dut)
                    )
        st.wait(15)
        thrds = list()
        for dut in st.get_dut_names():
            for image_type, devices in d_groups.items():
                if dut in devices:
                    thrd = threading.Thread(target=sonic_install, args=(image_type, i_files[image_type], dut), name="sonicinstall_thread_{}".format(dut))
                    thrd.start()
                    thrds.append(thrd)
        for thrd in thrds:
            thrd.join()
            st.banner('Thread {} completed'.format(thrd.name))
    except Exception as e:
        st.error("Failed to transfer or install with Error: {}".format(e))
    #Images are getting deleted from server
    for key in d_groups.keys():
        os.system("rm {}".format(i_files[key]))
    st.log("Image upload to all the DUTS done and Install Image successfully completed")
    return(True)

def test_image_upgrade():
    '''
    This testcase is to copy images depending on the platform on crowsnest cluster 3 test bed.
    Requirement is, images have to be copied on to images directory on 10.29.158.30. There are 
    three types of images need to be copied, superbolt, siren, and carib.
    '''
    tc_id = 'test_image_upgrade'

    # Define device groups and image files dynamically from input file
    device_groups = {}
    image_files = {}
    server_ip = test_cfg['global']['image_info']['server_ip']
    image_info = test_cfg['global']['image_info']['images']

    for key in test_cfg['global']['image_info']['images'].keys():
        device_groups[key] = image_info[key]['node_list']
        image_files[key] = image_info[key]['file_name']

    # Install images on devices
    if not transfer_and_install_image(device_groups, image_files, server_ip):
        st.report_fail("Image file transfer and Install is not completed")

    #Reboot devcies
    threads = list()
    reboot_cmd = "sudo reboot"
    for dut in st.get_dut_names():
        thread = threading.Thread(target=st.config, args=(dut, reboot_cmd), name="reboot_rtr_{}".format(dut))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()
        st.banner('Thread {} completed'.format(thread.name))
    st.wait(300)
    #Post-Reboot Verification
    for dut in st.get_dut_names():
        restore_helper_file(dut)
        st.config(dut,"show version")
        st.config(dut,"show platform summary")
        if not check_dockers_online(dut):
            st.report_fail("Dockers on DUT: {} are not online after upgrade".format(dut))
        st.log("DUT: {} has come online successfully after upgrade...".format(dut))
    st.report_pass("Image upgrade completed")
