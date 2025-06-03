import sys
import pexpect
import time
import os
from datetime import datetime
import json
import requests
import logging
import paramiko
import yaml

HW_CONFIG_FILE = "config/hw_cfg.json"

def load_json(filepath):
    """
    Load the json file
    :param filepath:
    :return:
    """
    res = {}

    if os.path.exists(filepath):
        full_filepath = filepath
    else:
        full_filepath = os.path.dirname(os.path.abspath(__file__))
        full_filepath = os.path.join(full_filepath, "../" + filepath)
    
    if not os.path.exists(full_filepath):
        log.error(
            "File not found %s, return empty configuration" % full_filepath)
        return res
    with open(full_filepath, "r") as f:
        res = json.load(f)
    return res

def read_file(filepath):
    """
    Read file content
    :param filepath:
    :return: list of string
    """
    res = []
    if os.path.exists(filepath):
        full_filepath = filepath
    else:
        full_filepath = os.path.dirname(os.path.abspath(__file__))
        full_filepath = os.path.join(full_filepath, "../" + filepath)

    if not os.path.exists(full_filepath):
        log.error(
            "File not found %s, return empty configuration" % full_filepath)
        return res
    with open(full_filepath, "r") as f:
        res = f.readlines()
    return res

def init_logging(name):
    """
    initial logging
    :param name:
    :return:
    """
    log = logging.getLogger('%s' % name)
    log.setLevel(logging.DEBUG)
    fileHander = logging.FileHandler(os.path.join('./', '%s.log' % name))
    fileHander.setLevel(logging.DEBUG)
    streamHandler = logging.StreamHandler()
    streamHandler.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '%(asctime)s [%(filename)s:%(lineno)d] %(levelname)s: '
        '%(message)s')
    fileHander.setFormatter(formatter)
    streamHandler.setFormatter(formatter)
    log.addHandler(fileHander)
    log.addHandler(streamHandler)
    log.info('Start log ################### %s ###################' % name)
    return log

log = init_logging("HW_SANITY_LOGS")

ALLURE_CONFIG_FILE_NAME = "config/allure-config.yaml"

STRESS_DEB = 'stress_1.0.4-4_amd64.deb'
DUT_FAILURE_ERROR = "!!!!!  Prepare DUT failed, skip testing  !!!!!"
SANITY_SCRIPT_ERROR = "Skip rest of the scripts if there is any. ==="
DEFAULT_RUN_LINES = 2
DEFAULT_RUN_STRING = "run_tests.sh"

path = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = "%s/../templates" % path
DEFAULT_LLDP_COUNT = 7
SSH_PORT = 22
#constants
KEY_UP = '\x1b[A'
KEY_DOWN = '\x1b[B'
KEY_RIGHT = '\x1b[C'
KEY_LEFT = '\x1b[D'
newline_prompt = '\n'
telnet_escape_prompt = '\x1b]'
telnet_error_prompt = "telnet: Unable to connect to remote host"
telnet_lab_password = "lab"

SUMMARY_REPORT_FILENAME = "results.json"
COMMON_REPORT_FILENAME = "sonic-whitebox-common.report"
SUMMARY_REPORT_PATH = "../../{}".format(SUMMARY_REPORT_FILENAME)
COMMON_REPORT_PATH = "../../{}".format(COMMON_REPORT_FILENAME)

MAX_PARTS_IMAGE_NAME = 6
START_INDEX_IMAGE = 2
IMAGE_INDEX = 4

streams_list = ["202205", "202305", "202311", "master", "202405c", "202405", "202411"]

BIN_FILE = "sonic-cisco-8000.bin"


#prompts
sonic_login_prompt = "sonic login: "
login_prompt = " login: "
cisco_prompt = "cisco@"
sonic_prompt = "@sonic:"
admin_prompt = "admin@"
pre_sonic_prompt = "/home/cisco# "
pre_admin_prompt = "/home/admin#"
grub_selection = "The highlighted entry will be executed automatically in 4s."
onie_prompt = "ONIE:"
vxr_prompt = "vxr@"
first_login = "Are you sure you want to continue connecting "

passwd_prompt = 'Password'
lower_pass_prompt = 'password'

#credentials/commands to send
dut_username = 'cisco'
dut_password = 'cisco123'
dut_alt_username = 'admin'
dut_alt_password = 'password'
#ucs_m3_1
ucs_m31_host = "sonic-ucs-m3-1"
ucs_m31_username = "rraghav"
ucs_m31_password = "roZes@123"
ucs_m31_cmd_prompt = "rraghav@sonic-ucs-m3-1:"
ucs_m31_scp_prompt = "rraghav@1.72.33.7:/var/www/html/IMAGES"
ucs_m31_images_folder = "/var/www/html/IMAGES"
ucs_m31_wget = "wget "

WHITEBOX_TOKEN = os.getenv("WHITEBOX_TOKEN")
SONIC_TEST_REPO = "wwwin-github.cisco.com/whitebox/sonic-test"
TORTUGA_SONIC_TEST_FOLDER = '/home/sonic/cicd2/sonic-test/'

EMPTY = "{}"
DELETE_CMD = f"find . -maxdepth 1 -type d -mtime +30 -exec rm -rf {EMPTY} \;"

# Parse config file
allure_config = {}
with open(ALLURE_CONFIG_FILE_NAME, "r") as config_file:
    allure_config = yaml.load(config_file, Loader=yaml.FullLoader)
    config_file.close()

allure_directory = allure_config['allure']['local-report-dir']

UNSET_PROXY = "unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy"
MAX_RETRIES = 10
MAX_RETRIES_TIMEOUT = 20

#dictionaries of testbeds

hw_cfg = load_json(HW_CONFIG_FILE)
testbed_info = hw_cfg["testbed-info"]
default_info = hw_cfg["default-info"]

def checkStreamCompatibility(testbed, stream):
    log.info("Started checkStreamCompatibility")
    hw_config = load_json(HW_CONFIG_FILE)
    stream_list = hw_config['testbed-streams'][testbed]
    if stream_list == "None":
        return True
    if stream in stream_list:
        log.info(f"Stream {stream} is compatible with the topology {testbed}!")
        return True
    else:
        log.error(f"Stream {stream} is not compatible with the topology {testbed}!")
        return False

def checkTestbedAvailability(testbed):
    log.info("Started checkTestbedAvailability")
    testbed_info_dict = getTestbedInfoDict(testbed)
    local_ucs = testbed_info_dict['ucs_host_name']
    run_type = testbed_info_dict['run_type_check']

    p2 = sshUtil(testbed_info_dict['ucs_username'], testbed_info_dict['ucs_host'], testbed_info_dict['ucs_password'], None)
    p2.expect(local_ucs)
    if checkForExistingRuns(p2, run_type, local_ucs)>0:
        log.info("Some run_test process already running! Please wait until the current run is finished.")
        return False
    else:
        return True

def cleanUpImageFolder(thread, prompt):
    thread.sendline(DELETE_CMD)
    thread.expect(prompt)
    return thread


def checkSpace(p, testbed):
    ucs = getImageUCS(testbed)
    cmd = ucs['username']+"@"+ucs["host"]
    check = p.expect(["No space left on device", cmd])
    if check == 0:
        log.error(f"Please make some space in UCS, {ucs['host']}")
        return -1
    else:
        return

def scpUtil(thread, scpCommand, password):
    thread.sendline(scpCommand)
    while True:
        i = thread.expect([first_login, lower_pass_prompt, "scp: Connection closed"])
        log.debug(thread.before)
        log.debug(thread.after)
        if i == 0:
            thread.sendline("yes")
        elif i == 1:
            thread.sendline(password)
            break
        else:
            logging.error("Copying was unsuccessful due to authentication error!")
            break

def copyDockerFileToDut(testbed, image_id):
    log.debug("Copy Docker rpc file to DUT to run special tests")
    testbed_info_dict = getTestbedInfoDict(testbed)
    local_ucs = testbed_info_dict['ucs_host_name']
    try:
        p2 = sshUtil(testbed_info_dict['ucs_username'], testbed_info_dict['ucs_host'], testbed_info_dict['ucs_password'], None)
        p2.sendline("docker ps -a")
        p2.expect(local_ucs)
        image_ucs = getImageUCS(testbed)
        
        for ssh in testbed_info_dict['dut_ssh']:
            [p1, prompt] = sshDUTUtil(p2, ssh)
            p1.expect(prompt)
            scp_prompt = image_ucs['scp_prompt']
            pswd = image_ucs['password']
            scpUtil(p1, f'scp {scp_prompt}/{image_id}/docker-syncd-cisco-rpc.gz /home/cisco', pswd)
            p1.expect(prompt)
            p1.close() 
        p2.close()
    except Exception as e:
        log.error(str(e))
    return

def sshUtil(username, host, password, timeout):
    try:
        thread = pexpect.spawn(f'ssh {username}@{host}', timeout=timeout, logfile=sys.stdout, encoding='utf-8')
        log.debug(thread.after)
        while True:
            i = thread.expect([first_login, lower_pass_prompt])
            if i == 0:
                thread.sendline("yes")
            elif i == 1:
                thread.sendline(password)
                break
            else:
                log.error(f"Logging into {host} was not successful!")
                break
        time.sleep(2)
    except Exception as e:
        log.debug(str(e))
        time.sleep(1)
    log.info("Logged in!")
    return thread

def sshDUTUtil(p1, dut_ssh_host, prodImage=False):
    if prodImage == False:
        username = dut_username
        password = dut_password
        prompt = cisco_prompt
    else:
        username = dut_alt_username
        password = dut_alt_password
        prompt = admin_prompt
    log.debug(username)
    log.debug(password)
    log.debug(prompt)
    p1.sendline(f'ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no {username}@{dut_ssh_host}')
    time.sleep(5)

    while True:
        i = p1.expect([first_login, lower_pass_prompt, "Last login: "])
        if i == 0:
            p1.sendline("yes")
        elif i == 1:
            p1.sendline(f'{password}')
        else:
            break
    return [p1, prompt]

def getSonicMgmtContainterName(stream, testbed):
    testbed_info_dict = getTestbedInfoDict(testbed)
    branch = getBranchFromStream(stream)

    return testbed_info_dict[f"sonic_mgmt_container_{branch}"]

def getSonicMgmtFolder(stream, testbed):
    testbed_info_dict = getTestbedInfoDict(testbed)
    branch = getBranchFromStream(stream)
    return testbed_info_dict["sonic_mgmt_folders"][f"{branch}"]

def getBranchFromStream(stream):
    
    for str in streams_list:
        if stream.find(str)>0:
            return str
    
    return "master"

def getDockerExecCommand(stream, testbed):
    branch = getSonicMgmtContainterName(stream, testbed)
    return f"docker exec -it {branch} /bin/bash"

def getTestbedInfoDict(testbed):
    log.info(f"Getting testbed info for '{testbed}'")
    if testbed in testbed_info:
        return testbed_info[testbed]
    else:
        log.error(f"No testbed info found for '{testbed}'!")
        return {}

def getImageUCS(testbed):
    hw_config = load_json(HW_CONFIG_FILE)
    testbed_image_ucs_map = hw_config["testbed_image_ucs_map"]
    file_server = hw_config["file_server_dict"]
    if testbed in testbed_image_ucs_map:
        ucs = testbed_image_ucs_map[testbed]
        if ucs in file_server:
            return file_server[ucs]
        else:
            return
    else:
        return

def create_allure_id(build_id, image_id, testbed="none"):
    return f'ring4-{build_id}-{image_id}-{testbed}'

def checkProdImage(stream):
    return "release" in stream

def telnetConnection(host, port, timeout, logfile_loc, encoding, without_port, testbed_info_dict):
    retries = 0
    while True:
        try:
            if testbed_info_dict is not None and 'need_ucs_mount' in testbed_info_dict and testbed_info_dict['need_ucs_mount'] == "True":
                p = sshUtil(testbed_info_dict['ucs_username'], testbed_info_dict['ucs_host'], testbed_info_dict['ucs_password'], None)
                p.expect(testbed_info_dict['ucs_host_name'])
            if without_port:
                log.info(f"Telnet into host {host}")
                p = pexpect.spawn(f'telnet {host}', timeout=timeout, logfile=logfile_loc, encoding=encoding)
            else:
                log.info(f"Telnet into host {host} {port}")
                p = pexpect.spawn(f'telnet {host} {port}', timeout=timeout, logfile=logfile_loc, encoding=encoding)
            time.sleep(2)
            break
        except Exception as e:
            log.error(f"Exception occured while trying to telnet to {host} {port}, error: {e}")
            retries += 1
            time.sleep(2)
            if retries == MAX_RETRIES:
                log.error(f"Reached maximum retries. Exiting")
                raise
    log.info("telnet connection successful")
    p.sendline()

    p = checkTelnetconnection(p, host, port)
    return p


def telnetLoginUtil(p, stream, changed_creds=False):
    retry_count = 0
    if checkProdImage(stream) == True and changed_creds==False:
        username = dut_alt_username
        password = dut_alt_password
    else:
        username = dut_username
        password = dut_password
    while True:
        i = p.expect([login_prompt, passwd_prompt, "Login incorrect", cisco_prompt, admin_prompt])
        if i == 0:
            # send user name
            p.sendline(username)
        elif i == 1:
            # send password
            p.sendline(password)
        elif i == 2:
            time.sleep(1) # retry 3 times
            if retry_count == 3:
                log.error("Login not successful into DUT")
                return -1
            else:
                retry_count = retry_count+1
        else:
            break
    return

def checkForDockers(p):
    log.info("Check if dockers are up")
    p.sendline("docker ps -a")
    log.info(p.before)
    i = p.expect_exact(["Exited (0)", cisco_prompt, admin_prompt])
    if i == 0:
        log.error("All dockers are not up.")
        return -1
    else:
        log.info("All dockers are up and running")
        return

def checkForMGFailures(p):
    log.info("Check if mini graph has any failures")
    i = p.expect_exact(["failed=1", "unreachable=1" , "Done"])
    if i == 0 or i == 1:
        log.error("Deploy minigraph caused unreachable or failed")
        return -1
    else:
        log.info("Deploy minigraph successful.")
        return

def checkTelnetconnection(p, host, port):
    log.info("Check for connection refused")
    i = p.expect([telnet_error_prompt, "Connected to "])
    if i == 0:
        clearTelnetLine(p, host, port)
        log.info("Cleared line, making new connection")
        p1 = telnetConnection(host, port, 50000, sys.stdout, 'latin-1', False, None)
        return p1
    else:
        return p

def checklldpCount(p, testbed_info_dict):
    cmd = "show lldp table"
    p.sendline(cmd)
    lldp_count = testbed_info_dict["lldp_count"] if "lldp_count" in testbed_info_dict else DEFAULT_LLDP_COUNT
    i = p.expect(["Total entries displayed:  "])
    if i==0:
        p.expect(cisco_prompt)
        count = p.before
        if int(count.replace(" ",""))>=lldp_count:
            log.debug(f"{cmd} looks good")
        else:
            log.error(f"{cmd} count does not meet requirements")
            if 'max_timeout' not in testbed_info_dict:
                return -1
    if 'max_timeout' in testbed_info_dict:
        log.debug("Entered max_timeout block")
        retries_count = 0
        timeout_gap = 60 # try for every 60 sec until timeout is reached
        max_retries_count = (testbed_info_dict['max_timeout'] * timeout_gap)/60
        while retries_count<max_retries_count:
            p.sendline(cmd)
            i = p.expect(["Total entries displayed:  ", "RuntimeError: Sonic database config file doesn't exist at "])
            if i==0 or i==1:
                p.expect(cisco_prompt)
                count = p.before
                if int(count.replace(" ",""))>=lldp_count:
                    log.debug(f"{cmd} looks good")
                    return
                else:
                    log.error(f"{cmd} count does not meet requirements")
            time.sleep(timeout_gap)
            retries_count = retries_count+1
        return -1

def clearTelnetLine(p, host, port):
    p.close()
    log.info("Closing this connection to restart another connection!")
    time.sleep(20)
    p1 = telnetConnection(host, port, 50000, sys.stdout, 'latin-1', True, None)
    p1.expect("Connected to ")
    p1.sendline()
    p1.expect(passwd_prompt)
    p1.sendline(telnet_lab_password)
    p1.expect(">")
    p1.sendline("enable")
    p1.expect(passwd_prompt)
    p1.sendline(telnet_lab_password)
    p1.expect("#")
    num = getLineNumFromTelnetPort(port)
    p1.sendline(f"clear line {num}")
    p1.sendline()
    p1.expect("#")
    p1.sendline("exit")
    p1.expect("Connection closed by foreign host.")
    p1.close()
    return

def getLineNumFromTelnetPort(port):
    num = port[2:]
    if num[:1] == '0':
        num = num[1:]
    return num

def updateGitDir(host, ssh_port, username, password, dir):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, ssh_port, username, password)
        print("connected to host {}".format(host))
        pull_cmd = f'cd {dir}; git remote set-url origin https://{WHITEBOX_TOKEN}@{SONIC_TEST_REPO}.git; git pull'
        exec_command_raise_error(ssh, pull_cmd)
        log.debug('Git pull update complete')
        ssh.close()
        return 0
    except Exception as e:
        print(f"Unexpected Error: {e}")
        return -1

def run_scripts(host, username, password, cmd_list, prompt, ssh_port=SSH_PORT, update_flag="False"):
    log.debug(f"update_flag: {update_flag}")
    if update_flag==True:
        rc = updateGitDir(host, ssh_port, username, password, TORTUGA_SONIC_TEST_FOLDER)
        if rc != 0:
            log.error("git update failed")
            return -1
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    log.debug(f"{host}, {ssh_port}, {username}, {password}")
    log.debug(f"{type(host)}, {type(ssh_port)}, {type(username)}, {type(password)}")
    ssh.connect(host, ssh_port, username, password)
    print("connected to host {}".format(host))
    chan = ssh.invoke_shell()
    resp = ''
    time.sleep(5)
    log.debug(cmd_list)
    
    # run docker command first
    chan.send(f'{cmd_list[0]} \n')
    while ':~' not in resp:
        resp = chan.recv(9999).decode('ascii', 'ignore')
        log.debug(resp)
    time.sleep(5)

    cmd_list = cmd_list[1:]
    for cmd in cmd_list:
        resp = ''
        log.debug(f'{cmd} \n')
        while prompt not in resp:
            chan.send(f'{cmd} \n')
            if cmd.startswith('scp') == True:
                # if wait_for_prompt(chan, first_login, timeout=60):
                #     chan.send(f'yes \n')
                #     resp = chan.recv(9999).decode('utf-8')
                #     log.debug(resp)
                if wait_for_prompt(chan, 'password:', timeout=60):
                    chan.send(f'{password}\n')
                    resp = chan.recv(9999).decode('utf-8')
                    log.debug(resp)
                break
            resp = chan.recv(9999).decode('utf-8')
            time.sleep(3)
            log.debug(resp)
    chan.send('exit \n')
    time.sleep(10)
    chan.close()
    ssh.close()
    return 0

def wait_for_prompt(channel, prompt, timeout=5):
    buff = ''
    start_time = time.time()

    while time.time() - start_time < timeout:
        resp = channel.recv(9999).decode('utf-8')
        log.debug(resp)
        buff += resp
        if prompt in buff:
            return True
        time.sleep(0.1)
    return False

def extract_test_start_time(spytest_results_files):
    for file in spytest_results_files:
        if "summary.txt" in file:
            return "_".join(file.split("_")[1:-1])
        elif "logs.log" in file:
            return "_".join(file.split("_")[1:-1])

# def extract_file_contents_url(target_url):
#     result = requests.get(target_url)
#     soup = BeautifulSoup(result.text, 'html.parser')
#     txtfiles = soup.find_all(title=re.compile(f"\.txt$"))
#     log.debug(txtfiles)
#     filename = []
#     for i in txtfiles:
#         filename.append(i.extract().get_text())
    # return filename

def exec_command_raise_error(client, cmd):
    print(f"executing command: '{cmd}'")
    _, stdout, stderr = client.exec_command(cmd)
    if stdout.channel.recv_exit_status() != 0:
        print(f"Encountered error while executing '{cmd}', stdout: {stdout.readlines()}, stderr: {stderr.readlines()}")
        raise Exception(stdout.channel.recv_exit_status(), stderr.readlines())
    else:
        log.debug(f"Output for {cmd} : {stdout.readlines()}")
    return stdout, stderr

def extract_result_sum(summary_txt, decode=False):
    sum = {"total": 0, "failed": 0, "passed": 0, "skipped": 0, "success_rate": 0.0, "status" : "success"}
    for line in summary_txt:
        if decode == True:
            line = line.decode('utf-8')
        if "=" not in line:
            continue

        key, value = line.split("=")
        key = key.strip()
        value = value.strip()

        if key == "PASS":
            sum["passed"] = int(value)
        elif key == "FAIL":
            sum["failed"] = int(value)
        elif key == "SKIPPED":
            sum["skipped"] = int(value)
        elif key == "Test Count":
            sum["total"] = int(value)
    sum["success_rate"] = round(sum["passed"] / (sum["total"] - sum["skipped"]) * 100, 2) if (sum["total"] - sum["skipped"]) != 0 else 0
    return sum

def collect_spytest_results(testbed, test_suites, image_id, build_id):
    print("Collecting result")

    testbed_info_dict = getTestbedInfoDict(testbed)
    hw_type = testbed_info_dict["hw_type"]
    test_suite_type = (test_suites.split("/")[-1]).split(".")[0]
    testbed_type = testbed.split("-")[-1]
    if "hw_type" in testbed_info_dict:
        image_folder = 'ring4-'+testbed_info_dict["hw_type"]+'-'+image_id+'-'+build_id+'-'+test_suite_type
    else:
        image_folder = 'ring4'+'-'+image_id+'-'+build_id+'-'+testbed_type

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(testbed_info_dict['ucs_host'], "22", testbed_info_dict['ucs_username'], testbed_info_dict['ucs_password'])

    results_folder = f'{testbed_info_dict["sonic_test_dir"]}/{image_folder}'
    log.debug(results_folder)
    
    ftp_client=client.open_sftp()
    spytest_results_files = ftp_client.listdir(results_folder)

    test_start_time = extract_test_start_time(spytest_results_files)
    
    if test_start_time == None:
        return 1, "test_start_time not detected, Summary.txt not available.", None, None

    exec_command_raise_error(client, f"cd {results_folder}; tar -czvf /tmp/{image_folder}_spytest_result.tar.gz *")
    ftp_client.get(f"/tmp/{image_folder}_spytest_result.tar.gz","./spytest_result.tar.gz")
    exec_command_raise_error(client, f"rm -rf /tmp/{image_folder}_spytest_result.tar.gz")

    os.system(f"mkdir {hw_type}_spytest_result_{test_start_time}")
    os.system(f"tar -xvf spytest_result.tar.gz -C {hw_type}_spytest_result_{test_start_time}")

    ret = 0 
    sum = {"total": 0, "failed": 0, "passed": 0, "skipped": 0, "success_rate": 0.0, "status" : "success"}
    try:
        spytest_result_sum_file = open(f"./{hw_type}_spytest_result_{test_start_time}/results_{test_start_time}_summary.txt", 'r')
        spytest_result_sum = spytest_result_sum_file.readlines()
        spytest_result_sum_file.close()

        print(f"Result sum file contents: {spytest_result_sum}")

        sum = extract_result_sum(spytest_result_sum)
    except Exception as e:
        print("Exception! Failed to open result file!")
        log.error(e)
        sum["status"] = "failure"
        ret = 1

    print(f"result summary is: {sum}")

    return ret,"", test_start_time, sum

def upload_result(testbed, test_start_time):
    testbed_info_dict = getTestbedInfoDict(testbed)
    hw_type = testbed_info_dict["hw_type"]
    if test_start_time == None:
        return 1, "test_start_time not detected, Summary.txt not available.", None
    print("Uploading result to server")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect("sonic-ucs-m3-1", username = "ringcicd", password = "cicd_sonic")
    
    ftp_client=client.open_sftp()
    spytest_results_files = os.listdir(f"{hw_type}_spytest_result_{test_start_time}")
    # exec_command_raise_error(ftp_client,f"cd /auto/vxr1/sonic-images/ringcicd/; rm -rf {hw_type}_spytest_result_{test_start_time}")
    ftp_client.mkdir(f"/auto/vxr1/sonic-images/ringcicd/{hw_type}_spytest_result_{test_start_time}")
    
    ftp_client.put(f"./spytest_result.tar.gz", f"/auto/vxr1/sonic-images/ringcicd/{hw_type}_spytest_result_{test_start_time}/spytest_result.tar.gz")
    exec_command_raise_error(client,f"cd /auto/vxr1/sonic-images/ringcicd/{hw_type}_spytest_result_{test_start_time}; tar -xvf spytest_result.tar.gz")
    
    report_link = f"http://172.29.93.10/sonic-images/ringcicd/{hw_type}_spytest_result_{test_start_time}/dashboard.html"
    log_tarball_link = f"http://172.29.93.10/sonic-images/ringcicd/{hw_type}_spytest_result_{test_start_time}"

    print(f"Successfully uploaded test result, url is: http://172.29.93.10/sonic-images/ringcicd/{hw_type}_spytest_result_{test_start_time}/dashboard.html")
    return 0, "", report_link, log_tarball_link

def _get_container_ssh_channel(hostname, username, password, container_name, ssh_port=22):
    """
    SSH into the  VM and exec into container
    return: ssh, ssh_channel
    """

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=hostname, port=ssh_port, username=username, password=password)
    ssh_channel = ssh.invoke_shell()
    buff = ''
    while not buff.endswith(':~$ '):
        resp = ssh_channel.recv(9999)
        buff += resp.decode("ascii")
        log.info(resp.decode("ascii"))
    time.sleep(3)

    # Get into the docker-sonic-mgmt container
    ssh_channel.send('docker exec -it {} /bin/bash \n'.format(container_name))
    buff = ''
    while not buff.endswith(':~$ '):
        resp = ssh_channel.recv(9999)
        buff += resp.decode("ascii")
        log.info(resp.decode("ascii"))
    time.sleep(3)

    return ssh, ssh_channel

def _run_cmd_in_channel(ssh_channel, cmd, check_exit_status, timeout=180):
    """
    Run a command in the container shell
    """

    ssh_channel.send(f'{cmd}\n') 
    if check_exit_status:
        ssh_channel.settimeout(timeout)
        buff = ''
        err_buff = ''
        rcv_timeout = 60
        interval_length = 5

        try:
            while not ssh_channel.exit_status_ready():
                if ssh_channel.recv_ready():
                    resp = ssh_channel.recv(9999)
                    log.info(resp.decode("ascii"))
                    buff += resp.decode("ascii")
                else:
                    rcv_timeout -= interval_length
                if rcv_timeout < 0:
                    break
                else:
                    time.sleep(interval_length)

                if ssh_channel.recv_stderr_ready():
                    error_buff = ssh_channel.recv_stderr(9999)
                    while error_buff:
                        err_buff += error_buff.decode("ascii")
                        error_buff = ssh_channel.recv_stderr(9999)
                    log.info(err_buff)
        except Exception as e:
            log.error('Hit %s' % e)
    else:
        time.sleep(3)
        resp = ssh_channel.recv(9999)
        log.info(resp.decode("ascii"))
    return resp.decode("ascii")

def prep_special_run_commands(testbed, test_suites_arg, test_suites, image_id, build_id, docker_exec_cmd, run_commands_array, docker_container='False'):
    testbed_info_dict = getTestbedInfoDict(testbed)
    test_suites_array = testbed_info_dict["tests_list"] if (test_suites_arg == 'All' and "tests_list" in testbed_info_dict) else [test_suites_arg]
    log.debug(test_suites_array)
    test_suite_type = (test_suites.split("/")[-1]).split(".")[0]
    testbed_type = testbed.split("-")[-1]
    if "hw_type" in testbed_info_dict:
        image_folder = 'ring4-'+testbed_info_dict["hw_type"]+'-'+image_id+'-'+build_id+'-'+test_suite_type
    else:
        image_folder = 'ring4'+'-'+image_id+'-'+build_id+'-'+testbed_type
    cmd_list = list()
    if docker_container == 'True':
        cmd_list.append(docker_exec_cmd)
    cmd_list.append(UNSET_PROXY)
    for cmd in run_commands_array:
        if "optional_run_params" in testbed_info_dict:
            op_params = list(testbed_info_dict["optional_run_params"].keys())
            for param in op_params:
                value = testbed_info_dict["optional_run_params"][param]["default"]
                if param in cmd and test_suites in testbed_info_dict["optional_run_params"][param]:
                    value = testbed_info_dict["optional_run_params"][param][test_suites]
                cmd = cmd.strip().replace("$"+param, value)
        if "$image_id" in cmd:
            cmd = cmd.strip().replace("$image_id", image_id)
        if "$image_folder" in cmd:
            cmd = cmd.strip().replace("$image_folder", image_folder)
        if "$testbed_yaml" in cmd:
            cmd = cmd.strip().replace("$testbed_yaml", testbed_info_dict['testbed_yaml'])
        if "$test_name" in cmd:
            if test_suites == "forwarding":
                fwd_tc = testbed_info_dict["forwarding_test_list"]
                test_params = f"--test-suite={fwd_tc}"
                cmd = cmd.strip().replace("/data/sonic-mgmt/spytest/tests/$test_name", test_params)
            else:
                cmd = cmd.strip().replace("$test_name", test_suites)
        cmd_list.append(cmd)
    return cmd_list

def add_fwd_run_commands(cmd_list, cmd, cfg_location):
    with open(cfg_location, 'r') as file:
        # Read each line in the file
        for line in file:
            if "file:" in line:
                test_name = line.split("file:")[1].strip()
                add_cmd = cmd.strip().replace("$test_name", test_name)
                cmd_list.append(add_cmd)
    return cmd_list

def get_container_local_mount_dir(ssh, container_name, destination_path):
    cmd = f"docker inspect `docker ps -aq  --filter name=^/{container_name}$`"

    _, stdout, stderr = ssh.exec_command(cmd)
    if stdout.channel.recv_exit_status() != 0:
        err = "failed to run {}: {}".format(cmd, stderr.read().decode("ascii").strip())
        log.error(err)
        raise Exception(err)

    container_metadata = json.loads(stdout.read().decode("ascii").strip())
    
    # Sort by "Created" timestamp and get the latest entry
    latest_metadata = max(container_metadata, key=lambda x: x["Created"])

    lastest_mounts = latest_metadata["Mounts"]
    testbed_mount_dir = ""
    for mount in lastest_mounts:
        if mount["Destination"] == destination_path:
            testbed_mount_dir = mount["Source"]
            break

    if testbed_mount_dir == "" :
        err = f"No mount point found for Destination path '{destination_path}' in container {container_name}"
        log.error(err)
        raise Exception(err)

    return testbed_mount_dir


def generate_allure_report_and_copy_to_remote(build_id, testbed, image_id, stream):
    # Get config
    testbed_info_dict = getTestbedInfoDict(testbed)

    hostname = testbed_info_dict['ucs_host']


    # SSH into the testbed server with ssh library
    container_name = getSonicMgmtContainterName(stream, testbed)
    ssh, container_channel = _get_container_ssh_channel(hostname, testbed_info_dict['ucs_username'], testbed_info_dict['ucs_password'], container_name)


    # Get docker mount directory on the testbed server
    destination_path = "/data"
    log.info("determine local mount dir for container path {}:{}".format(container_name, destination_path))
    testbed_mount_dir = get_container_local_mount_dir(ssh, container_name, destination_path)
    log.info("mount dir of container {}:{} on the testbed {}:{}".format(container_name, destination_path, hostname, testbed_mount_dir))


    # Generate allure report
    allure_id = create_allure_id(build_id, image_id, testbed)
    allure_report_directory_name = "allure-report-{}".format(allure_id) 
    _run_cmd_in_channel(container_channel, 'allure generate --name {} -o /tmp/{} {}'.format(allure_id, allure_report_directory_name, allure_directory), False)

    # tar the allure report directory
    _run_cmd_in_channel(container_channel, 'tar -cvzf {}/{}.tar.gz /tmp/{}'.format(destination_path, allure_report_directory_name, allure_report_directory_name), True)

    # remove the allure report directory
    _run_cmd_in_channel(container_channel, 'rm -rf /tmp/{}'.format(allure_report_directory_name), True)

    # Copy the allure report tarball to local
    ftp_client = ssh.open_sftp()
    ftp_client.get('{}/{}.tar.gz'.format(testbed_mount_dir, allure_report_directory_name), '/tmp/{}.tar.gz'.format(allure_report_directory_name))

    # extract the allure report tarball on local
    result = os.system('tar -xvzf /tmp/{}.tar.gz -C /'.format(allure_report_directory_name))
    if result != 0:
        err = "failed to extract the allure report tarball"
        log.error(err)
        return -1, err

    # copy the allure report to remote
    remote_report_dir = allure_config['allure']['remote-report-dir']
    remote_report_dir = remote_report_dir if remote_report_dir.endswith('/') else remote_report_dir + '/'
    result = os.system('cp -R /tmp/{} {}/'.format(allure_report_directory_name, remote_report_dir))
    if result != 0:
        err = "failed to copy the allure report to remote"
        log.error(err)
        return -1, err

    # remove the allure report on local
    os.system('rm -rf /tmp/{}'.format(allure_report_directory_name))
    os.system('rm -rf /tmp/{}.tar.gz'.format(allure_report_directory_name))

    # create report URL
    allure_report_url = "{}/{}/{}".format(allure_config['allure']['server-base-url'], remote_report_dir, allure_report_directory_name)

    ftp_client.close()
    container_channel.close()
    ssh.close()

    log.info("Allure report generated and copied to remote. Report URL: {}".format(allure_report_url))
    return 0, allure_report_url

def getLatestValidAllureReport(build_id, image_id, testbed, stream):
    status_code, allure_report_url = generate_allure_report_and_copy_to_remote(build_id, testbed, image_id, stream)
    if status_code != 0:
        return [None, None]
    log.debug("projects_url: %s" % allure_report_url)
    try:
        url = allure_report_url+'/widgets/summary.json'
        log.debug("Report URL: %s" % url)
        individual_json = getAllureReport(url)
        log.debug("Report json: %s" % individual_json)
        if individual_json["statistic"]["total"] != 0:
            return [individual_json, allure_report_url]
    except Exception as e:
        log.error("Error: "+str(e))
        return [None, None]
    return [None, None]

def getAllureReport(link):
    headers = {
        'Content-Type': 'application/json'
    }
    try:
        r = requests.get(link, headers=headers)
        full_json = r.json()
        return full_json
    except Exception as e:
        log.error("getAllureReport Error: "+str(e))
        return -1

def getTimestampsFromAllure(individual_json):
    start = individual_json["time"]["start"]
    stop = individual_json["time"]["stop"]
    start_dt = datetime.utcfromtimestamp(start//1000).replace(microsecond=start%1000*1000)
    start_date = start_dt.strftime("%Y-%m-%d %H:%M:%S")
    stop_dt = datetime.utcfromtimestamp(stop//1000).replace(microsecond=stop%1000*1000)
    stop_date = stop_dt.strftime("%Y-%m-%d %H:%M:%S")
    return [start_date, stop_date]

def checkForExistingRuns(p, test_string, expect_string):
    # p.sendline(f"ps -aef | grep -i {test_string} | awk {'print $2'}")
    # p.expect(expect_string)
    log.debug(f"get run count on: {test_string}, with {expect_string}")
    p.sendline(f"ps -aef | grep -i '{test_string}'")
    p.expect(expect_string)
    x1 = p.before
    log.debug(x1)
    count = x1.count(f"{test_string}")
    log.debug(f"Count for existing run lines: {count}")
    # DEFAULT_RUN_LINES = 2 because there will be two instances from the stdin and also the grep command which we would want to ignore
    # difference = 1 - 1 run
    # difference = 0 - no runs
    # difference > 1 - multiple runs
    return count-DEFAULT_RUN_LINES

def pollingRuns(testbed_info_dict, test_suites):
    local_ucs = testbed_info_dict['ucs_host_name']
    child = sshUtil(testbed_info_dict['ucs_username'], testbed_info_dict['ucs_host'], testbed_info_dict['ucs_password'], None)
    child.expect(local_ucs)
    while True:
        time.sleep(300) #timeout for 5 minutes
        run_count = checkForExistingRuns(child, DEFAULT_RUN_STRING, local_ucs)
        log.debug(f"checkForExistingRuns: {run_count}")
        if run_count==0:
            return 0
        elif run_count==1:
            log.debug(f"Run is still going on for {test_suites}")
        elif run_count>1:
            log.error(f"Multiple runs happening causing failures")
            child.close()
            return -1
        else:
            log.error(f"Run count below default")
            child.close()
            return -1

def flushChannel(thread):
    while True:
        try:
            thread.read_nonblocking(size=1024)
        except (pexpect.TIMEOUT, pexpect.EOF):
            break
    log.debug("flush complete")

def runIndividualTests(image_id, build_id, testbed, ucs_ssh, thread, test_suites, test_name, skip_folders, skip_tests):
    testbed_info_dict = getTestbedInfoDict(testbed)
    t1 = testbed_info_dict['ucs_tb']
    t2 = testbed_info_dict['mth_tb']
    t = testbed_info_dict['topology']
    skip_tests_string = testbed_info_dict['skip_tests']+" "+skip_tests.replace(",", " ") if 'skip_tests' in testbed_info_dict else skip_tests.replace(",", " ")
    skip_folders_list = testbed_info_dict['skip_folder']+" "+skip_folders.replace(",", " ") if 'skip_folder' in testbed_info_dict else skip_folders.replace(",", " ")
    log.debug(f'skip_folders_list: {skip_folders_list}')
    docker_promt = testbed_info_dict['docker_prompt']
    allure_id = create_allure_id(build_id, image_id, testbed)

    if test_suites.startswith("file:"):
        # if test_suites.startswith("file:"):
        testfile = test_suites.split("file:")[1]
        tests = read_file(testfile)
        # else:
        #     tests = testbed_info_dict["add_folders"].split(" ")
        log.debug("Test list: %s" % tests)
        log.debug(docker_promt)
        for test in tests:
            if test.find("#")==0:
                log.info(f"Test commented {test}")
            else:
                folder = f"sanity_script_tests_{image_id}_{build_id}"
                run_cmd = f"./run_tests.sh -n {t1} -d {t2} -e -rapP -e --alluredir={allure_directory} -u -e -s -c {test} -p /run_logs/{folder} &"
                log.info(f'To check logs of the tests, go to vxr@SONiC:/run_logs/{folder}')
                thread.sendline(run_cmd)
                exp_str = "generated xml file: /data/tests/logs"
                x = thread.expect([DUT_FAILURE_ERROR, exp_str])
                if x == 0:
                    log.error("DUT is not in a stable condition.")
                    return -1
                else:
                    time.sleep(20)
                    log.debug(thread.before)
                    log.debug(docker_promt)
                    thread.expect(docker_promt)
                    thread.sendline()
                    thread.sendline()
                    thread.expect(docker_promt)
        return None
    else:
        folder = f'{image_id}_jenkins_nightly_logs_{build_id}_{test_suites}'  
        dut_flag = "" if "skip_dut_flag" in testbed_info_dict else f" -d {t2} "
        if test_suites == "All":
            extra_params = testbed_info_dict["extra_run_params"] if 'extra_run_params' in testbed_info_dict else ""
            run_cmd = f"./run_tests.sh -n {t1} -d {t2} -m individual -u -e -rapP -e --alluredir={allure_directory} {extra_params} -t {t},any -p /run_logs/{folder} -s \"{skip_tests_string}\" -S \"{skip_folders_list}\" &"
        else:
            extra_params = "-O -e --disable_loganalyzer -e --qos_swap_syncd=False" if test_suites=="qos" else ""
            extra_params = extra_params+" "+testbed_info_dict["extra_run_params"] if 'extra_run_params' in testbed_info_dict else extra_params
            if test_suites.find("[") == 0:
                test_suites = test_suites[1:-1]
                if test_suites in ["pretest", "posttest"]:
                    test_name = f"test_{test_suites}.py"
            now = datetime.now()

            # Format the datetime object as a string
            formatted_time = now.strftime("%Y%m%d%H%M%S")
            test_name_output = test_name.replace("/","_").replace(".py","")
            folder = folder.replace("/","_").replace(".py","")
            run_cmd = f"./run_tests.sh -n {t1}{dut_flag} -e -rapP -e --alluredir={allure_directory} -S \"{skip_folders_list}\" -u {extra_params} -c {test_name} -s \"{skip_tests_string}\" -p /run_logs/{folder} |& tee run_test_{test_name_output}_{formatted_time}.log"
    
    log.debug(f'To check logs of the tests, go to ucs:/run_logs/{folder}')
    thread.sendline(run_cmd)

    if test_suites == "All":
        exp_str = f'generated xml file: /run_logs/{folder}/wan/traffic_test/'
    else:
        exp_str = f'generated xml file: /run_logs/{folder}'
    
    rc = pollingRuns(testbed_info_dict, test_suites)
    if rc!=0:
        log.error("pollingRuns failed")
        thread.close()
        return -1

    x = thread.expect([DUT_FAILURE_ERROR, SANITY_SCRIPT_ERROR, exp_str, docker_promt])
    # log.debug(thread.before)
    time.sleep(60)
    # log.debug(thread.after)
    if x == 0 or x==1:
        log.error("Sanity scripts failed due to an error. Please rerun after fixing issues.")
        return -1
    elif x==2 or x==3:
        time.sleep(60)
        thread.sendline()
        thread.expect(docker_promt)
        log.debug(f"Run completed for {test_suites}!")
        # log.debug(thread.before)
        # flushChannel(thread)
    elif x==3:
        log.debug(f"Run completed for {test_suites}!")
    else:
        log.debug("No expect string match found!")
    time.sleep(60)
    return 0

def removeImageDir(thread, cmd, image, password):
    thread.sendline(f"cd ..")
    thread.expect(cmd)
    time.sleep(10)
    thread.sendline(f"rm -rf {image}")
    x = thread.expect([lower_pass_prompt, "Permission Denied", "permission denied", "Permission denied", "permission Denied", cmd])
    if x == 0:
        thread.sendline(password)
        thread.expect(cmd)
        return 0
    elif x == 1 or x == 2 or x == 3 or x == 4:
        log.error("Image folder not able to delete")
        return -1
    else:
        return 0

def setupMemChecker(stream, testbed, thread, local_ucs):
    testbed_info_dict = getTestbedInfoDict(testbed)
    image_ucs = getImageUCS(testbed)
    scp_prompt = image_ucs['scp_prompt']
    pswd = image_ucs['password']
    p1 = sshUtil(testbed_info_dict['ucs_username'], testbed_info_dict['ucs_host'], testbed_info_dict['ucs_password'], None)
    scpUtil(p1, f'scp /home/sonic/rraguraj/stress_utility/{STRESS_DEB} {scp_prompt}', pswd)
    p1.close()

    scpUtil(thread, f'scp {scp_prompt}/{STRESS_DEB} .', pswd)
    thread.sendline("docker cp /home/cisco/stress_1.0.4-4_amd64.deb telemetry:/")
    thread.expect(cisco_prompt)

    thread.sendline("exit")
    thread.expect(local_ucs)
    # editLineMemChecker(thread, stream, testbed, local_ucs)
    thread.sendline()
    return None

def editLineMemChecker(thread, stream, testbed, local_ucs):
    # Edit line in memory checker test.py
    repo = getSonicMgmtContainterName(stream, testbed)
    testbed_info_dict = getTestbedInfoDict(testbed)
    user = testbed_info_dict['ucs_username']
    local_prompt = "sonic-mgmt/tests/memory_checker"
    thread.sendline(f"cd /home/{user}/{repo}/sonic-test/sonic-mgmt/tests/memory_checker")
    thread.expect(local_prompt)
    log.info("Got into folder")
    thread.sendline("git apply memory_checker.patch")
    
    i = thread.expect(["error: can't open patch 'memory_checker.patch': No such file or directory", "error: patch failed: sonic-mgmt/tests/memory_checker/test_memory_checker.py", local_ucs])
    if i == 0:
        log.error("No patch found")
        return -1
    elif i == 1:
        log.info("Patch already in place maybe. Retrying once.")
        thread.expect(local_prompt)
        thread.sendline("git apply -R memory_checker.patch")
        thread.expect(local_prompt)
        thread.sendline("git apply memory_checker.patch")
        thread.expect(local_prompt)
        log.info("Patch applied successfully")
    elif i == 2:
        log.info("Patch applied successfully")
    return None

def getModefromTestbed(testbed):
    return testbed.split("-")[0]

def extractFromImageName(image_name):
    image = image_name.rsplit("/",1)[-1]
    parts = image.split("-")
    if len(parts)>MAX_PARTS_IMAGE_NAME:
        diff = len(parts)-MAX_PARTS_IMAGE_NAME
        end_index = START_INDEX_IMAGE+(diff+1)
        stream = "-".join(parts[START_INDEX_IMAGE:end_index])
        image_id = parts[IMAGE_INDEX+diff]
    else:
        stream = parts[START_INDEX_IMAGE]
        image_id = parts[IMAGE_INDEX]
    
    return [image, image_id, stream]