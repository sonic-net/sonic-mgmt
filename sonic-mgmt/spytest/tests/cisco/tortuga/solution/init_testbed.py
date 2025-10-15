"""
spytest script to do the following
    1. Load new image
    2. Clean configs on the routers
    3. Set persistent FRR configs
 on all sonic routers in a testbed . 

 Command line options:
    --env "routers=spine0,spine2,leaf1,leaf2" : Specify the routers to run the script on
    --env "image=<image_url>" : Specify the image URL to be used for upgrade 
        Example: --env "image=https://engci-maven.cisco.com/artifactory/whitebox-group/sonic-cicd/Pipeline2_build/sonic-buildimage/sonic-buildimage-cisco.202305.1.tortuga.no-agents-p2-18153-583d0911ec2cf732732bd3443c0163e6b29cc320.tar.gz"


    Sytest options:
    --testbed <testbed_file> : Path to the testbed file
    --device-feature-group <feature_group> : Device feature group to run the script on
    --module-init-max-timeout=<timeout> : Maximum timeout for module initialization
    --tc-max-timeout=<timeout> : Maximum timeout for test case execution
    --skip-init-checks : Skip initial checks before running the script  

 PS:  script should be run with -noconftest option to avoid removing the config file after script exection.



 Example:
 ./bin/spytest --testbed solution_1D_1.yaml --device-feature-group master 
    --module-init-max-timeout=7200 --tc-max-timeout=7200 
    /data/tests/cisco/tortuga/solution/init_testbed.py --skip-init-checks  
    --logs-path run_logs/init_tb --noconftest 

 To run just the clear config and set persistent config test cases, use the following command:
 ./bin/spytest --testbed solution_1D_1.yaml --device-feature-group master 
    --module-init-max-timeout=7200 --tc-max-timeout=7200 /data/tests/cisco/tortuga/solution/init_testbed.py --skip-init-checks  
    --logs-path run_logs/init_tb --noconftest -k TestSetConfigs

 To run just the clear config and set persistent config test cases, use the following command:
 ./bin/spytest --testbed solution_1D_1.yaml --device-feature-group master 
    --module-init-max-timeout=7200 --tc-max-timeout=7200 /data/tests/cisco/tortuga/solution/init_testbed.py --skip-init-checks  
    --logs-path run_logs/init_tb --noconftest -k TestSetConfigs

To run the image upgrade test case, use the following command:
./bin/spytest --testbed solution_1D_1.yaml --device-feature-group master --module-init-max-timeout=7200 --tc-max-timeout=7200 
    /data/tests/cisco/tortuga/solution/init_testbed.py --skip-init-checks  --noconftest -k TestReimage --logs-path run_logs/init_tb
    --env "image=https://engci-maven-master.cisco.com/artifactory/whitebox-group/sonic-cicd/Pipeline2_build/sonic-buildimage/sonic-buildimage-cisco.202405c.2.tortuga.laguna.no-agents-periodic-25986-81298a18e1dbab73bf51e83adec85794a59c6cbe.tar.gz" 
    --env "routers=spine0,leaf0"

Example: Run with input file

./bin/spytest --testbed vxlan_4S4L_topo_HW_sol4.yaml --device-feature-group master --module-init-max-timeout=7200 --tc-max-timeout=7200 
    /data/tests/cisco/tortuga/solution/init_testbed.py --skip-init-checks  --noconft --logs-path run_logs/init_tb 
    --env "input=/data/tests/cisco/tortuga/solution/init_testbed.yaml" -k TestSetConfigs

Example/Synatax of input yaml file:

spine3:
  clean_config: true    # options true/false/reboot (reboot after cleaning config)
leaf0:
  clean_config: reboot
  persistent_config: true  # options true/false
  reimage: &img1
    url: https://engci-maven-master.cisco.com/artifactory/whitebox-group/sonic-cicd/Pipeline2_build/sonic-buildimage/sonic-buildimage-cisco.202405c.2.tortuga.laguna.no-agents-periodic-26597-95e0265181efd404528b060869f78f36130b427f.tar.gz
  initial_config: |
    sudo config int breakout Ethernet1_5 "2x400G" -yfl
    sudo config interface startup Ethernet1_5_1
    sudo config interface startup Ethernet1_5_2
leaf1:
  clean_config: true
  persistent_config: true
  reimage: &img2
    url: https://engci-maven-master.cisco.com/artifactory/whitebox-group/sonic-cicd/Pipeline2_build/sonic-buildimage/sonic-buildimage-cisco.202405c.2.tortuga.no-agents-periodic-25293-c41ced57013ac23ecdf0004d0d20ae6485ab6bbc.tar.gz
leaf2:
  clean_config: reboot
  persistent_config: true
  reimage: *img1 

"""
import threading, subprocess
import pytest
from spytest import st
import vxlan_helper as vxlan_obj
import apis.system.reboot as reboot_obj
import apis.system.basic as basic_obj
from spytest.utils import poll_wait
import paramiko
from scp import SCPClient
import os
import time
import re
import yaml

@pytest.fixture(scope="module", autouse=True)
def initialize_variables():
    global vars, test_cfg
    test_cfg = dict()
    rtr_names = st.getenv('routers', 'all')
    vars = st.get_testbed_vars()
    # img_path = 'https://engci-maven.cisco.com/artifactory/whitebox-group/sonic-cicd/Pipeline2_build/sonic-buildimage/sonic-buildimage-cisco.202305.1.tortuga.no-agents-p2-18153-583d0911ec2cf732732bd3443c0163e6b29cc320.tar.gz'
    test_cfg['img_path'] = st.getenv('image', None)
    test_cfg['input_file'] = st.getenv('input', "")
    test_cfg['local_dir'] = '/tmp/img_upgrd/{}'.format(time.time())
    test_cfg['local_img_paths'] = dict()
    test_cfg['max_boot_time'] = 600
    test_cfg['reimage'] = {'routers' : list()}
    test_cfg['init_cfg'] = {'routers' : list()}
    test_cfg['frr_cfg'] = {'routers' : list()}
    test_cfg['clean_cfg'] = {'routers' : list()}
    vars = st.get_testbed_vars()

    test_cfg['input'] = dict()
    if test_cfg['input_file']:
        with open(test_cfg['input_file']) as fd:
            test_cfg['input'] = yaml.load(fd, Loader=yaml.FullLoader)

    routers = list()
    if rtr_names == 'all':
        # rtr list not provided in command line
        if test_cfg['input']:
            for rtr in test_cfg['input'].keys():
                if not rtr in st.get_dut_names():
                    st.error('Router {} not found in testbed. Ignoring'.format(rtr))
                    continue
                routers.append(rtr)
        else:
            routers = st.get_dut_names()
    else:
        for rtr in rtr_names.split(','):
            if rtr in st.get_dut_names():
                routers.append(rtr)
            else:
                st.error('Router {} not found in testbed. Ignoring'.format(rtr))
    
    if test_cfg['input']:
        for rtr in routers:
            if 'clean_config' in test_cfg['input'][rtr].keys() and \
                test_cfg['input'][rtr]['clean_config']:
                test_cfg['clean_cfg']['routers'].append(rtr)
            if 'persistent_config' in test_cfg['input'][rtr].keys() and \
                test_cfg['input'][rtr]['persistent_config'] is True:
                test_cfg['frr_cfg']['routers'].append(rtr)
            if 'reimage' in test_cfg['input'][rtr].keys() and \
                test_cfg['input'][rtr]['reimage']:
                test_cfg['reimage']['routers'].append(rtr)
            if 'initial_config' in test_cfg['input'][rtr].keys() and \
                test_cfg['input'][rtr]['initial_config']:
                test_cfg['init_cfg']['routers'].append(rtr) 
    else:
        test_cfg['reimage']['routers'] = \
        test_cfg['frr_cfg']['routers'] = \
        test_cfg['clean_cfg']['routers'] = routers
        test_cfg['init_cfg']['routers'] = []

    st.log('Selected routers : {}'.format(routers))
    
    for rtr in routers:
        st.log('Getting docker count for router: {}'.format(rtr))
        test_cfg[rtr] = dict()
        test_cfg[rtr]['docker_count'] = basic_obj.get_and_match_docker_count(rtr)
        st.log('Docker count on router {} : {}'.format(rtr, test_cfg[rtr]['docker_count']))


def parallel_exec(proc, routers, ret_val):
    """
    Test case to set FRR perssistent configs on the testbed routers
    """
    global test_cfg
    threads = list()
    for rtr in routers:
        ret_val[rtr] = {'result': False, 'result_msg': ''}
        thread = threading.Thread(target=proc,
                                    args=(rtr, ret_val[rtr]),
                                    name='thread_rtr_{}'.format(rtr,))
        st.log('Starting Thread {}'.format(thread.name))

        thread.start()
        threads.append(thread)

    for thread in threads:
        st.log('Waiting for thread to complete {}'.format(thread.name))
        thread.join()
        st.log('Thread {} completed'.format(thread.name))

@pytest.mark.usefixtures("file_transfer")
class TestReimage():

    @pytest.mark.usefixtures('file_transfer')
    def test_image_upgrade(self,):
        global test_cfg
        ret_val = dict()

        parallel_exec(self.upgrade_dut, test_cfg['reimage']['routers'],  ret_val)

        dut_passed = []
        dut_failed = []
        for dut in test_cfg['reimage']['routers']:
            if ret_val[dut]['result']:
                st.banner('Image install on {} Passed'.format(dut))
                st.log(' - Upgrade Status : {}'.format(ret_val[dut]['status']))
                st.log(' - Upgrade Result : {}'.format(ret_val[dut]['result_msg']))
                st.log(' - Image Version : {}'.format(ret_val[dut]['verify'].get('version')))
                st.log(' - Number of container Up: {}'.format(ret_val[dut]['verify'].get('docker_cnt')))
                st.log(' - Install time : {} secs'.format(int(ret_val[dut]['verify'].get('install_time'))))
                st.log(' - Containers up time after reboot : {} secs'.format(int(ret_val[dut]['verify'].get('reboot_time'))))
                dut_passed.append(dut)
            else:
                st.banner('Image install on {} Failed'.format(dut))
                st.log(' - Upgrade Status : {} (failed)'.format(ret_val[dut]['status']))
                st.log(' - Upgrade Result : {}'.format(ret_val[dut]['result_msg']))
                st.log(' - Image Version : {}'.format(ret_val[dut]['verify'].get('version', 'NA')))
                st.log(' - Number of container Up: {}'.format(ret_val[dut]['verify'].get('docker_cnt', 'NA')))
                st.log(' - Install time : {} secs'.format(int(ret_val[dut]['verify'].get('install_time', '0'))))
                st.log(' - Containers up time after reboot : {} secs'.format(int(ret_val[dut]['verify'].get('reboot_time', '0'))))
                ret_val = False
                dut_failed.append(dut)

        if ret_val:
            st.banner('Install complete. Pass: {}'.format(dut_passed))
            st.report_pass('test_case_passed')
        else:
            st.banner('Install complete. Pass: {} :: Fail: {}'.format(dut_passed, dut_failed))
            st.report_fail('test_case_failed')

    @pytest.fixture(scope="class")
    def file_transfer(self):
        ## Download image to local path ##
        global test_cfg
        try:
            images = dict()
            img_cntr = 0
            for rtr in test_cfg['reimage']['routers']:

                if test_cfg['img_path']:
                    img = test_cfg['img_path']
                elif test_cfg['input'] and 'reimage' in test_cfg['input'][rtr].keys():
                    img = test_cfg['input'][rtr]['reimage']['url']
                else:
                    raise Exception('Image path not provided in command line')
                if img not in images.values():
                    img_cntr += 1
                    images[img_cntr] = img
                test_cfg[rtr]['image_cntr'] = img_cntr

            for img_cntr in images.keys( ):
                local_dir = os.path.join(test_cfg['local_dir'], str(img_cntr))
                if not os.path.exists(local_dir):
                    st.log('Creating temp image dir : {}'.format(local_dir))
                    os.makedirs(local_dir)

                img = images[img_cntr]
                wget_cmd = 'wget {} -P {}'.format(img, local_dir)
                result = os.system(wget_cmd)
                if result == 0:
                    st.log('Temp Image copy to {} passed'.format(local_dir))
                else:
                    raise Exception('Temp Image copy to {} failed'.format(local_dir))
                img_file = img.split('/')[-1]
                if ".tar" in img_file:
                    cmd = ['tar', '-xvf',  os.path.join(local_dir, img_file), 
                        '-C', local_dir]
                    st.log('Extracting image file from tar ball using command: {}'.format(' '.join(cmd)))
                    sub_proc = subprocess.Popen(cmd,
                                            stdin=subprocess.PIPE,
                                            stderr=subprocess.STDOUT,
                                            stdout=subprocess.PIPE)
                    out, err = sub_proc.communicate()

                    if err:
                        raise Exception('Error when untaring tar ball: {}'.format(err))

                    for line in out.split('\n'):
                        if line.endswith('.bin') and not line.endswith('dev.bin'):
                            test_cfg['local_img_paths'][img_cntr] = os.path.join(local_dir, line)
                            break
                    else:
                        raise Exception('.bin image file not found in tar ball')
                else:
                    test_cfg['local_img_paths'][img_cntr] = os.path.join(local_dir, img_file)
        except Exception as e:
            st.log('Error: {}'.format(e))
            st.report_fail('Temp Image copy failed: {}'.format(e))
        yield
        st.log('Removing temp image dir : {}'.format(test_cfg['local_dir']))
        os.system('rm -rf {}'.format(test_cfg['local_dir']))

    def scp_upload(self, local_path, remote_path, hostname, username, password, port=22):
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
            
            st.log('File uploaded successfully.')
            ret_val =  True
        except Exception as e:
            st.log('Error: {}'.format(e))
            ret_val =  False
        finally:
            # Close the SSH connection
            ssh_client.close()    
        return ret_val 

    def upgrade_dut(self, dut, ret_val):
        """
        Copy image to dut
        install image
        reboot
        check sys health
        """
        global vars, test_cfg
        ret_val['status'] = 'start'
        ret_val['version'] = None
        ret_val['docker_cnt'] = 0
        ret_val['verify'] = {}
        dut_dir = '/home/{}'.format(st.get_username(dut))
        st.banner('Copying Sonic Image file onto Dut {}'.format(dut))
        ret_val['status'] = 'copy'
        st.log('Removing any existing image files on Dut {}'.format(dut))
        st.config(dut, 'sudo rm *.bin')
                
        img_cntr = test_cfg[dut]['image_cntr']
        local_img_path = test_cfg['local_img_paths'][img_cntr]
        st.log('Scp Image file {} to {} dir on Dut {}'.format(local_img_path, 
                                                             dut_dir, dut))
        if not self.scp_upload(local_path = local_img_path, remote_path= dut_dir, 
                    hostname = vars.mgmt_ipv4[dut], 
                    username= st.get_username(dut), password= st.get_password(dut)):
            st.error('Scp Image file {} to {} dir on Dut {} Failed'.format(local_img_path, 
                                                                           dut_dir, dut))
            ret_val['result'] = False
            ret_val['result_msg'] = 'scp image to router failed'
            return
            
        st.banner('Record DUT status before upgrade on {}'.format(dut)) 
        ret_val['status'] = 'precheck'
        verify_data = self.verify_dut_status(dut, {}, init=True)
        if verify_data['result']:
            st.log('Verify status before upgrade passed on {}'.format(dut))
        else:
            st.error('Verify status before upgrade failed on {}'.format(dut))
            ret_val['result'] = False
            ret_val['result_msg'] = 'Pre-check verification failed'
            return
        #st.config(dut, 'sudo sonic-installer cleanup -y')
        st.banner('Running Sonic Installer Command on {}'.format(dut)) 
        st.show(dut, 'sudo config save -y', skip_tmpl=True)
        img_file = local_img_path.split('/')[-1]
        ret_val['status'] = 'install'
        st.banner('Installing new image on {}'.format(dut)) 
        start_time = time.time()
        op = st.show(dut, 'sudo sonic-installer install -y {}'.format(os.path.join(dut_dir,
                                                                                  img_file)), skip_tmpl=True)
        ret_val['verify']['install_time'] = time.time() - start_time
        img_name = None
        for line in op.split('\n'):
            if line.startswith('Installing image '):
                img_name = line.split(' ')[2]
                match = re.search(r'([0-9].*)$', img_name)
                if match:
                    img_name = match.group(1)
                break
            if re.match('^Image .* is already installed', line):
                img_name = line.split(' ')[1]
                break

        op = st.show(dut,'sudo sonic-installer list', skip_tmpl=True)
        available = False
        for line in op.split('\n'):
            if line.startswith('Available:'):
                available = True
            if available and img_name in line:
                inst_img_name = line
                break
        else:
            st.error('Installed image not in installer list on {}'.format(dut))
            ret_val['result'] = False
            ret_val['result_msg'] = 'Image install failed'
            return

        st.show(dut,'sudo sonic-installer set-next-boot {}'.format(inst_img_name), skip_tmpl=True)
        st.show(dut,'sudo sonic-installer list', skip_tmpl=True)
        ret_val['status'] = 'reboot'
        st.banner('Rebooting {}'.format(dut)) 
        start_time = time.time()
        ret_val['verify']['reboot_time'] = 0
        status = st.reboot(dut, clear_skipped_file=True)
        ret_val['verify']['reboot_time'] = time.time() - start_time
        if not status:
            ret_val['result'] = False
            ret_val['result_msg'] = 'Reboot failed'
            st.error(ret_val['result_msg'])
            return

        ret_val['status'] = 'postcheck'
        st.banner('Verify status after upgrade on {}'.format(dut)) 
        verify_data['version'] = img_name
        ret_val['verify'].update(self.verify_dut_status(dut, verify_data))
        if ret_val['verify']['result']:
            st.log('Verify status after upgrade passed on {}'.format(dut))
            ret_val['result_msg'] = 'Upgrade successful'
            ret_val['result'] = True
            ret_val['status'] = 'done'
        else:
            st.error('Verify status after upgrade failed on {}'.format(dut))
            ret_val['result'] = False
            ret_val['result_msg'] = 'Post-check verification failed'
        return

    def verify_dut_status(self, dut, verify_data, init=False):
        """
        Verify basic system parameters
        """
        verify_data['result'] = True
        st.log('Verify container count no Dut({})'.format(dut))
        op = basic_obj.get_docker_ps(dut)
        cnt = 0
        for docker in op:
            if 'Up' in docker['status']: cnt += 1

        st.log('Number of dockers Up on Dut({}) : {}'.format(dut, cnt))
        if not init:
            exp_cnt = verify_data.get('docker_cnt', 0)
            if cnt ==  exp_cnt:
                st.log('Verify container count :: Expected: {} :: Actual: {}: Pass'.format(exp_cnt, cnt))
            else:
                st.error('Verify container count :: Expected: {} :: Actual: {}: Fail'.format(exp_cnt, cnt))
                verify_data['result'] = False
        verify_data['docker_cnt'] = cnt
            
        st.log('Verify Version Dut({})'.format(dut))
        sh_ver = basic_obj.show_version(dut, report=False)
        if not init:
            # TODO : review
            #exp_ver = verify_data['version'].split('_')[-1]
            #match = re.search(r'([0-9].*)$', sh_ver['version'])
            #act_ver = match.group(1) if match else None
            sh_ver_img_pattern1 = "-([0-9]+)-" ; #SONiC.202405c.2.1.0-81I-28928-20250807.235033
            sh_ver_img_pattern2 = ".([0-9]+)-" ; #SONiC.202405c.28930-int-20250807.201428

            for sh_ver_pattern in [sh_ver_img_pattern1, sh_ver_img_pattern2]:
                match_act_ver = re.search(sh_ver_pattern, sh_ver['version'])
                match_exp_ver = re.search(sh_ver_pattern, verify_data['version'])
                exp_ver = match_exp_ver.group(1) if match_exp_ver else exp_ver
                act_ver = match_act_ver.group(1) if match_act_ver else act_ver
                if exp_ver and act_ver:
                    break
            else:
                st.error('show version pattern match error: {}  {}'.format(exp_ver, act_ver))
            if act_ver and exp_ver == act_ver:
                st.log('Verify version :: Expected: {} :: Actual: {}: Pass'.format(exp_ver, act_ver))
            else:
                st.error('Verify version :: Expected: {} :: Actual: {}: Fail'.format(exp_ver, act_ver))
                verify_data['result'] = False
        verify_data['version'] = sh_ver['version']

        st.log('Verify Install list Dut({})'.format(dut))
        st.show(dut,'sudo sonic-installer list', skip_tmpl=True)
        return verify_data


class TestSetConfigs():

    def test_clean_configs(self):
        """
        Test case to clean cofnigds of the testbed routers
        """
        global test_cfg
        st.log('Cleaning configs of routers : {}'.format(test_cfg['clean_cfg']['routers']))
        ret_val = dict()

        parallel_exec(self.clean_cfg, test_cfg['clean_cfg']['routers'], ret_val)

        result = True
        for rtr in test_cfg['clean_cfg']['routers']:
            if ret_val[rtr]['result']:
                st.log('Config clean on router {} : Pass'.format(rtr))
            else:
                st.error('Config clean on router {} : Fail'.format(rtr))
                st.error('  Error message :  {}'.format(ret_val[rtr]['result_msg']))
                result = False

        if result:
            st.report_pass('test_case_passed')
        else:
            st.report_pass('test_case_failed')

    def test_set_persistent_configs(self):
        """
        Test case to set FRR perssistent configs on the testbed routers
        """
        global test_cfg
        st.log('Setting FRR presistent configs on routers : {}'.format(test_cfg['frr_cfg']['routers']))
        ret_val = dict()
    
        parallel_exec(self.set_persistent_cfg, test_cfg['frr_cfg']['routers'], ret_val)

        result = True
        for rtr in test_cfg['frr_cfg']['routers']:

            if ret_val[rtr]['result']:
                st.log('Setting FRR presistent configs on router {} : Pass'.format(rtr))
            else:
                st.error('Setting FRR presistent configs on router {} : Fail'.format(rtr))
                st.error('  Error message :  {}'.format(ret_val[rtr]['result_msg']))
                result = False

        if result:
            st.report_pass('test_case_passed')
        else:
            st.report_pass('test_case_failed')

    def test_set_initial_configs(self):
        """
        Test case to setup initial configs on the testbed routers
        """
        global test_cfg
        st.log('Setting initial configs on routers : {}'.format(test_cfg['init_cfg']['routers']))
        ret_val = dict()
    
        parallel_exec(self.set_initial_cfg, test_cfg['init_cfg']['routers'], ret_val)

        result = True
        for rtr in test_cfg['init_cfg']['routers']:

            if ret_val[rtr]['result']:
                st.log('Setting initial configs on router {} : Pass'.format(rtr))
            else:
                st.error('Setting initial configs on router {} : Fail'.format(rtr))
                st.error('  Error message :  {}'.format(ret_val[rtr]['result_msg']))
                result = False

        if result:
            st.report_pass('test_case_passed')
        else:
            st.report_pass('test_case_failed')


    def verify_docker_count(self, rtr, count):
        """
        Verify the docker count on the router
        :param rtr: Router name
        :param count: Expected docker count
        :return: True if count matches, False otherwise
        """

        if poll_wait(basic_obj.verify_docker_status, 180, rtr, 'Exited'):
        
            if not poll_wait(basic_obj.get_and_match_docker_count, 180, rtr, count):
                return False , "{} : dockers count is not as expected ({}) after config reload.".format(rtr, count)
        else:
            return False, "{} : dockers are not recovered after config reload.".format(rtr)
        return True, "Docker count on {} is as expected ({}).".format(rtr, count)

    def clean_cfg(self, rtr, ret_val):

        global test_cfg
        ret_val['result'] = True
        st.banner("===== Cleaning configs on Router: {} Start =====".format(rtr))
        st.config(rtr, "sudo -s rm /etc/sonic/config_db.json", skip_error_check=True, skip_error_log=True)
        if test_cfg['input'][rtr]['clean_config'] == "reboot":
            status = st.reboot(rtr, clear_skipped_file=True)
        else:
            st.config(rtr, "sudo config-setup factory", skip_error_check=True, skip_error_log=True)
            status = reboot_obj.config_reload(rtr)
        if status:
            ret_val['result_msg'] =  "{} : Config reload done".format(rtr)
            st.log(ret_val['result_msg'])
            ret_val['result'], ret_val['result_msg'] = self.verify_docker_count(rtr, test_cfg[rtr]['docker_count'])
        else:
            ret_val['result_msg'] =  "{} : Config reload failed".format(rtr)
            st.error(ret_val['result_msg'])
            ret_val['result'] = False
            return

        #check docker status
        if ret_val['result']:
            st.banner("===== Cleaning configs on Router: {} Done : {} =====".format(rtr, 'Pass'))
        else:
            st.banner("===== Cleaning configs on Router: {} Done : {} \n{} =====".format(rtr, 'Fail', ret_val['result_msg']))

    def set_persistent_cfg(self, rtr, ret_val):
        global vars
        try:
            st.banner("===== Setting FRR persistent configs on Router: {} Start =====".format(rtr))
            reboot_obj.config_save(rtr)
            vxlan_obj.config_dut(rtr,'bgp', 'do write') 
            with vxlan_obj.ConfigDB(rtr, vars.mgmt_ipv4[rtr], username=st.get_username(rtr), 
                                    password= st.get_password(rtr)) as cfgdb:
                cfgdb.set_leaf_value(['DEVICE_METADATA', 'localhost', 'docker_routing_config_mode'], 
                                     'split-unified')
            
            status = st.reboot(rtr, clear_skipped_file=True)
            if not status:
                ret_val['result'] = False
                ret_val['result_msg'] = "{} : Reboot failed".format(rtr)
                st.error(ret_val['result_msg'])
                return
            else: 
                #check docker status
                ret_val['result'], ret_val['result_msg'] = self.verify_docker_count(rtr, test_cfg[rtr]['docker_count'])
        except Exception as err:
            st.error(err)
            ret_val[rtr]['result'] = False
            ret_val[rtr]['result_msg'] = err

        if ret_val['result']:
            st.banner("===== Setting FRR persistent configs on Router: {} Done : {} =====".format(rtr, 'Pass'))
        else:
            st.banner("===== Setting FRR persistent configs on Router: {} Done : {} \n{} =====".format(rtr, 'Fail', ret_val['result_msg']))

    def set_initial_cfg(self, rtr, ret_val):

        global test_cfg
        ret_val['result'] = True
        st.banner("===== Configuring Initial configs on Router: {} Start =====".format(rtr))
        status = st.config(rtr, test_cfg['input'][rtr]['initial_config'], skip_error_check=True, skip_error_log=True)
        if status:
            ret_val['result_msg'] =  "{} : Initial Config done".format(rtr)
            st.log(ret_val['result_msg'])
        else:
            ret_val['result_msg'] =  "{} : Initial Config failed".format(rtr)
            st.error(ret_val['result_msg'])
            ret_val['result'] = False
            return

        #check docker status
        if ret_val['result']:
            st.banner("===== Initial configs on Router: {} Done : {} =====".format(rtr, 'Pass'))
        else:
            st.banner("===== Initial configs on Router: {} Done : {} \n{} =====".format(rtr, 'Fail', ret_val['result_msg']))

