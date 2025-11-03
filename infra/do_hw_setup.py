#!/usr/bin/python3
import pexpect
import sys
import time
import argparse
import logging
import paramiko
import os
import yaml
import urllib.parse
from hw_setup_utils import log, lower_pass_prompt, sshUtil, sshDUTUtil, extractFromImageName, getImageUCS, \
    cleanUpImageFolder, removeImageDir, checkSpace, getTestbedInfoDict, checkProdImage, telnetConnection, telnetLoginUtil, checklldpCount, \
    login_prompt, passwd_prompt, cisco_prompt, pre_sonic_prompt, sonic_login_prompt, admin_prompt, pre_admin_prompt, first_login, onie_prompt, \
    DUT_PASSWORD, DUT_USERNAME, BIN_FILE, telnet_escape_prompt, grub_selection, KEY_DOWN, newline_prompt, KEY_UP, checkForDockers, \
    scpUtil, sonic_prompt, getDockerExecCommand, checkForMGFailures, copyDockerFileToDut, getSonicMgmtContainterName, get_container_local_mount_dir, \
    default_info, getSonicMgmtFolder, MAX_RETRIES, MAX_RETRIES_TIMEOUT, ALLURE_CONFIG_FILE_NAME, checkStreamCompatibility, checkTestbedAvailability, \
    channelConnection, checkTortugaImage, CISCO_PASSWORD, CISCO_USERNAME, getBranchFromStream
from utils import _run_cmd_in_ssh


UNSET_HTTP_PROXY = "unset https_proxy http_proxy HTTPS_PROXY HTTP_PROXY"
DEFAULT_DOCKER_COUNT = 13
DEFAULT_IMAGES_FOLDER = "IMAGES/"

REMOVE_TOPO_TIMEOUT_SEC = 60*20
ADD_TOPO_TIMEOUT_SEC = 60*20

DATA_ANSIBLE_PROMPT = r".*\:\/data\/ansible\$"

MTU_HACK_SCRIPT_URL = "http://172.26.235.76/MISC/port_channel_mtu.yml"
MTU_HACK_TIMEOUT = 60*10
MTU_HACK_PATTERN = \
    "for i in {{0..{}}}; do ansible-playbook -i veos  -b -e current_hostname=VM0$(($i+100))   -e ansible_network_os=eos -e ansible_ssh_user=admin -e ansible_ssh_pass=123456 ./port_channel_mtu.yml -vvv  ; done"

# Parse config file
allure_config = {}
with open(ALLURE_CONFIG_FILE_NAME, "r") as config_file:
    allure_config = yaml.load(config_file, Loader=yaml.FullLoader)
    config_file.close()

def precheck(args):
    testbed = args.testbed
    full_link = args.full_link
    [image, image_id, stream] = extractFromImageName(full_link)

    # check git state
    try:
        testbed_info_dict = getTestbedInfoDict(testbed)
        hostname = testbed_info_dict.get('ucs_host')
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=hostname,
                    username=testbed_info_dict['ucs_username'],
                    password=testbed_info_dict['ucs_password'])

        container_name = getSonicMgmtContainterName(stream, testbed)
        destination_path = "/data"
        # log.info("determine local mount dir for container path {}:{}".format(container_name, destination_path))
        testbed_mount_dir = get_container_local_mount_dir(ssh, container_name, destination_path)
        log.info("mount dir of container {}:{} on the testbed {}:{}".format(container_name, destination_path, hostname, testbed_mount_dir))

        log.info("Getting `git status` output for sonic-mgmt")
        git_status, _, _ = _run_cmd_in_ssh(ssh, f"cd {testbed_mount_dir}; git status")
        log.info("Getting `git diff` output for sonic-mgmt")
        git_diff, _, _ = _run_cmd_in_ssh(ssh, f"cd {testbed_mount_dir}; git diff")
        log.info("Getting `git log` output for sonic-mgmt")
        git_diff, _, _ = _run_cmd_in_ssh(ssh, f"cd {testbed_mount_dir}; git log --oneline | head -n 20")
    except Exception as e:
        log.error("Something went wrong while trying to check git state of sonic-mgmt")
        log.error(e)

    if checkStreamCompatibility(testbed, stream) and checkTestbedAvailability(testbed):
        log.debug("Prechecks passed for %s" % full_link)
        return 0
    else:
        log.error("Precheck failed")
        return -1

def add_user(child, username, password, prompt):
    try:
        while True:
            i = child.expect(["The user `cisco' already exists.", lower_pass_prompt, "Adding user `cisco' to group `users' ...", "Is the information correct", "Full Name", "Room Number", "Work Phone", "Home Phone", "Other"])
            log.debug(f"Selected prompt --> {i}")
            if i==0:
                # Delete existing user and add again
                child.sendline("sudo deluser cisco")
                child.expect("Done.") #reset adding user
                child.sendline("sudo adduser cisco")
            elif i==1:
                # Expect the password prompt for the new user
                child.sendline(password)
            elif i==2:
                log.debug("Added user `cisco' to group `users'")
                child.sendline()
                break
            elif i==3:
                child.sendline("Y")
            else:
                child.sendline("")  # Leave blank and press Enter for any other optional field
        # Print the output for debugging
        log.debug(child.before)
        # Check the return status
        if child:
            log.debug(f"User '{username}' added successfully.")
        else:
            log.error(f"Failed to add user '{username}'.")
    except pexpect.exceptions.EOF:
        log.error("Unexpected end of output. Command might have failed.")
    except pexpect.exceptions.TIMEOUT:
        log.error("Operation timed out. Check your inputs or system load.")
    return child


def configure_user_on_prod_images(stream, testbed_info_dict):
    log.debug("configure cisco user on prod images")
    local_ucs = testbed_info_dict['ucs_host_name']
    for ssh in testbed_info_dict['dut_ssh']:
        p1 = sshUtil(testbed_info_dict['ucs_username'], testbed_info_dict['ucs_host'], testbed_info_dict['ucs_password'], None)
        p1.expect(local_ucs)
        log.debug(f"configure_user_on_prod_images on dut: {ssh}")
        [p2, prompt] = sshDUTUtil(p1, ssh, True)
        p2.expect(prompt)
        try:
            commands = [
                "adduser cisco",
                "usermod -aG sudo cisco",
                "usermod -aG docker cisco",
                "config save -y"
            ]
            for command in commands:
                p2.sendline(f"sudo {command}")
                if "adduser" in command:
                    p2 = add_user(p2, DUT_USERNAME, DUT_PASSWORD, prompt)
                p2.expect(prompt)
            time.sleep(120)
            logging.info("User and permissions successfully configured.")
            p2.close()
            p1.close()
        except Exception as e:
            logging.error(f"An error occurred while configuring the user: {e}")
            p2.close()
            p1.close()
            return -1
    return 0
            

def fetch_image_pipeline(args):
    testbed = args.testbed.strip()
    image_ucs = getImageUCS(testbed)
    logging.info("Start login")
    logging.info(image_ucs)
    logging.info(image_ucs['username'])
    user = image_ucs['username']
    host = image_ucs['host']
    pswd = image_ucs['password']
    image_folder = image_ucs['images_folder']


    workspace_root = os.getenv("WORKSPACE")
    build_id = os.getenv('BUILD_ID')

    sonic_image_location = workspace_root+"/build/"+build_id


    # ssh to server
    logging.info(f"SSH to server {host}, {user}/{pswd}")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, 22, user, pswd)

    sftp = ssh.open_sftp()

    print("sftp put file "+sonic_image_location+"/sonic-cisco-8000.bin")
    try:
        sftp.put(sonic_image_location+"/sonic-cisco-8000.bin", f"{image_folder}/{build_id}/sonic-cisco-8000.bin")
        sftp.put(sonic_image_location+"/docker-syncd-cisco-rpc.gz", f"{image_folder}/{build_id}/docker-syncd-cisco-rpc.gz")
    except FileNotFoundError:
        logging.info(f"Path {image_folder}/{build_id} does not exist in server, create one")
        sftp.mkdir(f"{image_folder}/{build_id}")
        sftp.put(sonic_image_location+"/sonic-cisco-8000.bin", f"{image_folder}/{build_id}/sonic-cisco-8000.bin")
        sftp.put(sonic_image_location+"/docker-syncd-cisco-rpc.gz", f"{image_folder}/{build_id}/docker-syncd-cisco-rpc.gz")

    sftp.close() 
    ssh.close()


def fetch_image(args):
    full_link = args.full_link.strip()
    testbed = args.testbed.strip()
    [image, image_id, stream] = extractFromImageName(full_link)
    image_ucs = getImageUCS(testbed)
    log.debug("Fetch image")
    logging.info("Start login")
    logging.info(image_ucs)
    logging.info(image_ucs['username'])
    user = image_ucs['username']
    host = image_ucs['host']
    pswd = image_ucs['password']
    p = sshUtil(user, host, pswd, 10000)
    cmd = image_ucs['username']+"@"+image_ucs["host"]
    p.expect(cmd)
    p.sendline(f"cd {image_ucs['images_folder']}")
    p.expect(cmd)
    p = cleanUpImageFolder(p, cmd)
    image_folder = f'{image_id}'
    p.sendline(f'cd {image_folder}')

    i = p.expect([cmd, "No such file or directory"])
    if i == 0:
        log.debug("Image folder already exists")
        rc = removeImageDir(p, cmd, image_folder, pswd)
        if rc!=0:
            return -1
    
    p.sendline(f'mkdir {image_folder}')
    rc = checkSpace(p, testbed)
    if rc == -1:
        p.close()
        return -1
    p.sendline(f'cd {image_folder}')
    p.expect(cmd)
    logging.debug("downloading")
    p.sendline(UNSET_HTTP_PROXY)
    p.expect(cmd)
    wget = image_ucs['wget']
    p.sendline(f'{wget} {full_link}')
    p.expect(".tar.gz’ saved")
    p.expect(cmd)
    time.sleep(20)
    untar = f'tar -xvf {image}'
    p.sendline(untar)
    checkSpace(p, testbed)
    copy = f'cp sonic*/sonic-cisco-8000.bin .'
    p.sendline(copy)
    checkSpace(p, testbed)
    docker = f'cp sonic*/docker-syncd-cisco-rpc.gz .'
    p.sendline(docker)
    checkSpace(p, testbed)
    p.close()
    return

def image_install(args):
    global testbed_info_dict
    full_link = args.full_link.strip()
    testbed = args.testbed.strip()
    [image, image_id, stream] = extractFromImageName(full_link)
    testbed_info_dict = getTestbedInfoDict(testbed)
    install_mode = args.install_mode.strip()

    if install_mode == "default" or install_mode == None:
        install_mode = testbed_info_dict["installer_mode"] if "installer_mode" in testbed_info_dict else "onie"
    if len(testbed_info_dict['dut_ssh']) >= 1:
        i = 0
        while i<len(testbed_info_dict['dut_ssh']):
            if install_mode == "sonic":
                sonic_install(args, i)
            else:
                onie_install(args, i)
            i = i+1   
    else:
        log.error("Telnet paramaters need to be in an array!")
        return -1
    
    time.sleep(180)
    prod_image = checkProdImage(stream)
    if prod_image==True:
        log.debug("Release image detected, change user creds")
        rc = configure_user_on_prod_images(stream, testbed_info_dict)
        if rc != 0:
            log.error("User cisco was not configured successfully")
            return -1
    if 'extra_onie_check' in testbed_info_dict and install_mode == "onie":
        log.debug("Image installed, check for lldp count")
        for telnet in testbed_info_dict['telnet_details']:
            [host, port] = telnet.split(" ")
            p = telnetConnection(host, port, None, sys.stdout, 'latin-1', False, testbed_info_dict)
            if telnetLoginUtil(p, stream, True) == -1:
                return -1
            checklldpCount(p, testbed_info_dict)
    log.debug("Image loaded and checked")
    return

def onie_install(args, index):
    logging.info("Starting onie_install")
    global testbed_info_dict
    full_link = args.full_link.strip()
    [image, image_id, stream] = extractFromImageName(full_link)
    testbed = args.testbed.strip()
    testbed_info_dict = getTestbedInfoDict(testbed)
    image_ucs = getImageUCS(testbed)
    [host, port] = testbed_info_dict['telnet_details'][index].split(" ")
    p = telnetConnection(host, port, None, sys.stdout, 'latin-1', False, testbed_info_dict)
    expected_prompts = [
        login_prompt, #0
        passwd_prompt, #1
        cisco_prompt, #2
        pre_sonic_prompt, #3
        sonic_login_prompt, #4
        admin_prompt, #5
        pre_admin_prompt, #6
        first_login, #7
        onie_prompt, #8
        'Login incorrect' #9
    ]

    # # login or sudo or onie install
    prod_image = checkProdImage(stream)
    username = DUT_USERNAME
    password = DUT_PASSWORD
    prompt = admin_prompt
    log.debug(f"prod_image: {prod_image}")
    skip_onie = False
    retry_count = 0
    while True:
        time.sleep(2)
        logging.info("Getting prompt")
        i = p.expect(expected_prompts)
        logging.info(f"got prompt #{i} --> '{expected_prompts[i]}'")
        if i == 0 or i == 4:
            # send user name
            p.sendline(username)
        elif i == 1:
            # send password
            p.sendline(password)
        elif i == 2 or i == 5:
            # setup for onie install
            time.sleep(3)
            p.sendline('sudo su')
        elif i == 3 or i == 6:
            # select onie install
            p.sendline('sudo reboot')
            time.sleep(3)
            break
        elif i == 7:
            p.sendline("yes")
        elif i == 8:
            #Handle onie aborts
            time.sleep(60)
            p.send("onie-nos-install ")
            image_folder = f'{image_id}'
            ip = testbed_info_dict['onie_ip'] if "onie_ip" in testbed_info_dict else image_ucs['ip']
            onie_path = testbed_info_dict['onie_path'] if "onie_path" in testbed_info_dict else DEFAULT_IMAGES_FOLDER
            p.send(f'http://{ip}/{onie_path}{image_folder}/{BIN_FILE}')
            p.sendline()
            logging.info(p.after)
            skip_onie = "True"
        elif i == 9:
            time.sleep(1) 
            if retry_count == 3: # retry 3 times
                logging.error("Login not successful into DUT")
                return -1
            else:
                retry_count = retry_count+1
        else:
            logging.error("unexpected prompt, exiting telnet")
            p.sendline(telnet_escape_prompt)
            p.expect('>telnet')
            p.sendline('quit')
            break
    
    logging.info("Reboot done. Waiting for GRUB ONIE selection menu")
    if skip_onie != "True":
        p.expect(grub_selection)
        logging.info("Got GRUB menu, selecting ONIE instead of default image")
        p.send(KEY_DOWN)
        p.send(KEY_DOWN)
        p.send(KEY_DOWN)
        p.send(KEY_DOWN)
        p.sendline(newline_prompt)
        p.expect("Loading ONIE")
        logging.info("Got 'Loading ONIE', waiting for GRUB menu")
        time.sleep(5)


        p.expect("ONIE: Install OS")
        logging.info("Got GRUB menu, ONIE Install Mode by seinding KEY_UP and enter")
        p.sendline(KEY_UP)
        p.sendline(KEY_UP)
        p.sendline(KEY_UP)
        p.sendline(KEY_UP)
        p.sendline(KEY_UP)
        p.sendline(KEY_UP)
        p.sendline(KEY_UP)
        p.sendline(KEY_UP)
        p.sendline(KEY_UP)
        p.sendline(KEY_UP)
        p.sendline(KEY_UP)
        p.sendline(newline_prompt)
        p.sendline(newline_prompt)
        p.sendline(newline_prompt)
        p.sendline(newline_prompt)

        logging.info("Waiting for prompt: 'ONIE: OS Install Mode ...'")
        p.expect("ONIE: OS Install Mode ...")
        logging.info("Got prompt: 'ONIE: OS Install Mode ...'")
        logging.info("Waiting for prompt: 'Info: Sleeping for 20 seconds'")
        logging.debug(p.after)
        p.expect('Info: Sleeping for 20 seconds')
        logging.info("Got prompt: 'Info: Sleeping for 20 seconds'")
        p.sendline(newline_prompt)
        p.sendline(newline_prompt)
        p.sendline(newline_prompt)
        p.sendline('onie-stop')
        p.expect("Stopping: discover...")
        p.expect("done.")
        p.expect(onie_prompt)
        p.send("onie-nos-install ")
        image_folder = f'{image_id}'
        ip = testbed_info_dict['onie_ip'] if "onie_ip" in testbed_info_dict else image_ucs['ip']
        onie_path = testbed_info_dict['onie_path'] if "onie_path" in testbed_info_dict else DEFAULT_IMAGES_FOLDER
        p.send(f'http://{ip}/{onie_path}{image_folder}/{BIN_FILE}')
        p.sendline()

    p.expect("Loading SONiC-OS OS initial ramdisk ...Loading SONiC-OS OS initial ramdisk ...")
    # p.expect("+ exit 0")
    p.sendline(newline_prompt)
    p.sendline(newline_prompt)
    if telnetLoginUtil(p, stream) == -1:
        return -1
    
    logging.info('Install process completed!')

    p.close()
    # Wait for 10 minutes before checking
    log.debug("Timeout for 10 minutes to let everything come up")
    time.sleep(600)

    if 'extra_timeout' in testbed_info_dict:
        # Wait for extra 10 minutes before checking
        log.debug(f"Extra timeout of {testbed_info_dict['extra_timeout']} seconds")
        time.sleep(testbed_info_dict['extra_timeout'])
    
    p = telnetConnection(host, port, None, sys.stdout, 'latin-1', False, testbed_info_dict)
    if telnetLoginUtil(p, stream) == -1:
        return -1
    checkForDockers(p)
    p.sendline(newline_prompt)
    p.expect(admin_prompt)

    log.debug("check for extra onie commands")
    # Send extra commands after loading image, map of what commands to run on which telnet connection
    if 'extra_onie_commands' in testbed_info_dict:
        comds_list = testbed_info_dict['extra_onie_commands'][index]
        log.debug(comds_list)
        for cmd in comds_list:
            if cmd.startswith("scp"):
                scpUtil(p, cmd, testbed_info_dict["ucs_password"])
                p.expect(sonic_prompt)
            elif cmd == "show lldp table":
                log.debug("timeout for 5 mins before checking for lldp")
                time.sleep(300)
                checklldpCount(p, testbed_info_dict)
            elif "reboot" in cmd:
                p.sendline(cmd)
                if telnetLoginUtil(p, stream) == -1:
                    return -1
            else:
                p.sendline(cmd)
                p.expect(sonic_prompt)      
    p.close()
    return

def remove_topo(args):
    testbed = args.testbed.strip()
    full_link = args.full_link.strip()
    [_, _, stream] = extractFromImageName(full_link)
    testbed_info_dict = getTestbedInfoDict(testbed)

    with paramiko.SSHClient() as client:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=testbed_info_dict['ucs_host'],
            username=testbed_info_dict['ucs_username'],
            password=testbed_info_dict['ucs_password']
        )

        remove_topo_cmd = testbed_info_dict.get('remove_topo_cmd')
        if remove_topo_cmd is None:
            log.warning(f"cannot get cmd for remove_topo from testbed_info_dict for testbed {testbed}")
            return 1
        else:
            log.debug(f'got cmd for remove_topo: "{remove_topo_cmd}"')
        remove_topo_outside_docker_cmd = getDockerExecCommand(stream,
                                                              testbed,
                                                              flags='',
                                                              suffix=f'-c "cd /data/ansible; {remove_topo_cmd}"')
        log.info(f"One-liner to remove topo from outside sonic-mgmt docker container:\n{remove_topo_outside_docker_cmd}")
        _, _, rc = _run_cmd_in_ssh(client, remove_topo_outside_docker_cmd, timeout=REMOVE_TOPO_TIMEOUT_SEC)
    return

def load_docker_ptf_image(stream, docker_ptf_url=None):
    log.info('start load_docker_ptf_image')
    global testbed_info_dict  # assuming it's set in add_topo
    # todo these need to be moved to a location where cicd doesn't periodically wipe >30d age files,
    #  and possibly replaced with ones with builtin saithrift version
    STREAM_TO_DOCKER_PTF_MAP = {
        '202305': '',
        '202311': 'http://172.26.235.76/IMAGES/anukverm/docker-ptf_anukverm-202311-05Aug2025-mix.gz',
        '202405': 'http://172.26.235.76/IMAGES/anukverm/docker-ptf_anukverm-202405-27Jun2025-mix.gz',
        '202405c': 'http://172.26.235.76/IMAGES/anukverm/docker-ptf_anukverm-202405-27Jun2025-mix.gz',
        '202411': 'http://172.26.235.76/IMAGES/anukverm/docker-ptf_anukverm-202411-27Jun2025-mix.gz',
        '202501': 'http://172.26.235.76/IMAGES/anukverm/docker-ptf_anukverm-202411-27Jun2025-mix.gz',
        '202505': 'http://172.26.235.76/IMAGES/anukverm/docker-ptf_anukverm-202505-27Jun2025-mix.gz',
        '202511': '',
        'master': 'http://172.26.235.76/IMAGES/anukverm/docker-ptf_anukverm-master-27Jun2025-mix.gz'
    }

    ptf_docker_image_link = docker_ptf_url if docker_ptf_url \
        else STREAM_TO_DOCKER_PTF_MAP.get(stream)
    if not ptf_docker_image_link:
        logging.error(f"unable to find matching docker ptf link for {stream}.")
        return 1
    log.debug(f'ptf_docker_image_link set to {ptf_docker_image_link}')

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=testbed_info_dict['ucs_host'],
        username=testbed_info_dict['ucs_username'],
        password=testbed_info_dict['ucs_password']
    )

    # Step 1: download the right docker on UCS
    # todo `unset` workaround is needed for this to work on testbeds w/ proxies set,
    #  remove later when proxies are standardized on all testbeds, this works for now
    image_filename = ptf_docker_image_link.split('/')[-1]
    _, _, _ = _run_cmd_in_ssh(client, f"rm {image_filename}")
    stdout, stderr, status_code = _run_cmd_in_ssh(client, f'{UNSET_HTTP_PROXY}; wget -nc {ptf_docker_image_link}', timeout=60 * 10)
    log.debug(f"download docker ptf output:\n{stdout}")
    if status_code:
        raise Exception(f"download docker ptf failed: \n{stderr}")

    # Step 2: Load docker ptf
    stdout, stderr, status_code = _run_cmd_in_ssh(client, f"docker load -i {image_filename}")
    log.debug(f"load docker ptf output:\n{stdout}")
    _, _, _ = _run_cmd_in_ssh(client, f"rm {image_filename}")
    if status_code != 0:
        raise Exception(f"load docker ptf failed: \n{stderr}")

    log.info('finish load_docker_ptf_image')
    return

def add_topo(args):
    global testbed_info_dict
    testbed = args.testbed.strip()
    full_link = args.full_link.strip()
    [_, _, stream] = extractFromImageName(full_link)
    testbed_info_dict = getTestbedInfoDict(testbed)

    load_docker_ptf_image(getBranchFromStream(stream), os.getenv("DOCKER_PTF_IMAGE_OVERRIDE"))

    with paramiko.SSHClient() as client:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=testbed_info_dict['ucs_host'],
            username=testbed_info_dict['ucs_username'],
            password=testbed_info_dict['ucs_password']
        )

        add_topo_cmd = testbed_info_dict.get('add_topo_cmd')
        if add_topo_cmd is None:
            log.warning(f"cannot get cmd for add_topo from testbed_info_dict for testbed {testbed}")
            return 1
        else:
            log.debug(f'got cmd for add_topo: "{add_topo_cmd}"')
        add_topo_outside_docker_cmd = getDockerExecCommand(stream,
                                                           testbed,
                                                           flags='',
                                                           suffix=f'-c "cd /data/ansible; {add_topo_cmd}"')
        log.info(f"One-liner to add topo from outside sonic-mgmt docker container:\n{add_topo_outside_docker_cmd}")
        _, _, rc = _run_cmd_in_ssh(client, add_topo_outside_docker_cmd, timeout=ADD_TOPO_TIMEOUT_SEC)
    return

def deploy_mg(args):
    testbed = args.testbed.strip()
    full_link = args.full_link.strip()
    [image, image_id, stream] = extractFromImageName(full_link)
    docker_exec_cmd = getDockerExecCommand(stream, testbed)
    testbed_info_dict = getTestbedInfoDict(testbed)
    local_ucs = testbed_info_dict['ucs_host_name']
    install_mode = args.install_mode.strip()
    if "ucs_tb" not in testbed_info_dict or 'deploy_flag' in testbed_info_dict and testbed_info_dict['deploy_flag'] == 'False':
        log.debug("Deploy minigraph not needed or parameter missing.")
        return  
    if install_mode == "default" or install_mode == None:
        install_mode = testbed_info_dict["installer_mode"] if "installer_mode" in testbed_info_dict else "onie"
    
    tb = testbed_info_dict["ucs_tb"]

    
    p2 = sshUtil(testbed_info_dict['ucs_username'], testbed_info_dict['ucs_host'], testbed_info_dict['ucs_password'], None)
    p2.expect(local_ucs)

    p2.sendline("docker ps -a")
    p2.expect(local_ucs)
    p2.sendline(docker_exec_cmd)
    docker_prompt = testbed_info_dict['docker_prompt']
    p2.expect(docker_prompt)
    p2.sendline("cd /data/ansible")
    p2.expect(":/data/ansible")
    
    p2.sendline(f"./testbed-cli.sh deploy-mg {tb} ./lab ./password.txt")
    if checkForMGFailures(p2) == -1:
        return -1
    logging.debug(p2.after)
    
    time.sleep(20)
    p2.sendline("exit")
    p2.close()

    log.debug("Timeout after deploy_mg")
    time.sleep(200)
    if 'superbolt' in testbed:
        log.debug("Additional 60s timeout for superbolt")
        time.sleep(60)
    
    if ('telnet_flag' in testbed_info_dict and testbed_info_dict['telnet_flag'] == "True") or install_mode == "onie":
        log.debug("check for docker using telnet")
        for telnet in testbed_info_dict['telnet_details']:
            [host, port] = telnet.split(" ")
            p = telnetConnection(host, port, 50000, sys.stdout, 'utf-8', False, testbed_info_dict)
            telnetLoginUtil(p, stream, True)
            if checkforInterfaces("telnet", p) == -1:
                return -1
            p.sendline("show ip bgp summary")
            p.expect(admin_prompt)
            p.close()
    elif install_mode == "sonic":
        if len(testbed_info_dict['dut_ssh']) >= 1:
            i = 0
            while i<len(testbed_info_dict['dut_ssh']):
                log.debug("check for docker using nested_ssh")
                rc = checkforInterfaces("sonic", testbed_info_dict, i)
                if rc != 0:
                    log.error("Interfaces not up")
                    return -1
                i=i+1
    log.info("All dockers are up, ready to run tests!")
    copyDockerFileToDut(testbed, image_id)
    return

def extra_configuration_steps(args):

    # prepare
    testbed = args.testbed.strip()
    full_link = args.full_link.strip()
    [_, _, stream] = extractFromImageName(full_link)
    docker_exec_cmd = getDockerExecCommand(stream, testbed)
    testbed_info_dict = getTestbedInfoDict(testbed)
    local_ucs = testbed_info_dict['ucs_host_name']

    p2 = sshUtil(testbed_info_dict['ucs_username'],
                 testbed_info_dict['ucs_host'],
                 testbed_info_dict['ucs_password'],
                 None)
    p2.expect(local_ucs)
    p2.sendline("docker ps -a")
    p2.expect(local_ucs)
    p2.sendline(docker_exec_cmd)
    docker_prompt = testbed_info_dict['docker_prompt']
    p2.expect(docker_prompt)

    # process mtu arista hack
    mtu_hack_config = testbed_info_dict.get('mtu_hack')
    log.info(f"MTU hack will be applied to testbed: {bool(mtu_hack_config)}")
    if mtu_hack_config:
        vms_count = mtu_hack_config.get('vms_count')
        if vms_count:
            apply_mtu_on_aristas_cmd = MTU_HACK_PATTERN.format(vms_count-1)  # 0...N-1

            p2.sendline("cd /data/ansible")
            p2.expect("")

            p2.sendline(f"{UNSET_HTTP_PROXY}")
            p2.expect("")

            p2.sendline(f"wget -nc {MTU_HACK_SCRIPT_URL}")
            p2.expect(docker_prompt)

            p2.sendline(apply_mtu_on_aristas_cmd)
            p2.expect(DATA_ANSIBLE_PROMPT, timeout=MTU_HACK_TIMEOUT)
            log.info("MTU hack applied")
        else:
            log.error("Unable to read `vms_count` from TB dict `mtu_hack` section. Skipping this step.")

    # install python-saithrift_1.13.0_amd64.deb inside docker ptf container
    SAITHRIFT_DEB_FILENAME = "python-saithrift_1.13.0_amd64.deb"
    SAITHRIFT_DEB_URL = f"http://172.26.235.76/MISC/{SAITHRIFT_DEB_FILENAME}"

    with paramiko.SSHClient() as client:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=testbed_info_dict['ucs_host'],
            username=testbed_info_dict['ucs_username'],
            password=testbed_info_dict['ucs_password']
        )

        container_name = getSonicMgmtContainterName(stream, testbed)
        destination_path = "/data"
        testbed_mount_dir = get_container_local_mount_dir(client, container_name, destination_path)

        # grep 'group-name:' ansible/testbed.yaml | awk -F': ' '{print $2}'
        group_name, _, _ = _run_cmd_in_ssh(client, cmd=f"grep 'group-name:' {testbed_mount_dir}/ansible/testbed.yaml | awk -F': ' '{{print $2}}'")
        group_name = group_name.strip()
        docker_ptf_container_name = f"ptf_{group_name}"

        log.info(f"Installing {SAITHRIFT_DEB_FILENAME} inside {docker_ptf_container_name} container")
        stdout, stderr, status_code = _run_cmd_in_ssh(client, f'{UNSET_HTTP_PROXY}; wget -nc {SAITHRIFT_DEB_URL}', timeout=60 * 5)
        if status_code:
            raise Exception(f"Download {SAITHRIFT_DEB_FILENAME} failed: \n{stderr}")

        stdout, stderr, status_code = _run_cmd_in_ssh(client, f"docker cp {SAITHRIFT_DEB_FILENAME} {docker_ptf_container_name}:/root")
        if status_code != 0:
            raise Exception(f"Copy {SAITHRIFT_DEB_FILENAME} to {docker_ptf_container_name} failed: \n{stderr}")

        stdout, stderr, status_code = _run_cmd_in_ssh(client, f"docker exec {docker_ptf_container_name} bash -c 'dpkg -i {SAITHRIFT_DEB_FILENAME}'")
        if status_code != 0:
            raise Exception(f"Install {SAITHRIFT_DEB_FILENAME} in {docker_ptf_container_name} failed: \n{stderr}")

        _, _, _ = _run_cmd_in_ssh(client, f"rm {SAITHRIFT_DEB_FILENAME}")

        stdout, stderr, status_code = _run_cmd_in_ssh(client, f"docker exec {docker_ptf_container_name} bash -c 'dpkg --list | grep saithrift'")
        log.debug(f"Verify {SAITHRIFT_DEB_FILENAME} installation output:\n{stdout}")

        log.info(f"{SAITHRIFT_DEB_FILENAME} installed successfully inside {docker_ptf_container_name} container")


def install_allure(args):
    # Parse the config and arguments
    testbed = args.testbed.strip()
    full_link = args.full_link.strip()
    [image, image_id, stream] = extractFromImageName(full_link)
    testbed_info_dict = getTestbedInfoDict(testbed)

    if 'allure_flag' in testbed_info_dict and testbed_info_dict["allure_flag"] == "false":
        log.debug("Allure reporting is not used for this test!")
        return
    hostname = testbed_info_dict['ucs_host']

    # Download allure debian package
    allure_package_url = allure_config["allure"]["debian-url"]
    log.info("download allure debian package from {}".format(allure_package_url))
    wget_cmd = f"wget {allure_package_url} -P /tmp"
    os.system(wget_cmd)


    # SSH into the testbed server with ssh library
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=hostname, username=testbed_info_dict['ucs_username'], password=testbed_info_dict['ucs_password'])


    # Get docker mount directory on the testbed server
    container_name = getSonicMgmtContainterName(stream, testbed)
    destination_path = "/data"
    log.info("determine local mount dir for container path {}:{}".format(container_name, destination_path))
    testbed_mount_dir = get_container_local_mount_dir(ssh, container_name, destination_path)
    log.info("mount dir of container {}:{} on the testbed {}:{}".format(container_name, destination_path, hostname, testbed_mount_dir))


    # Copy allure debian package to the testbed server under the docker mount directory
    alure_package_name = os.path.basename(urllib.parse.urlparse(allure_package_url).path)
    log.info("sftp put file /tmp/{} under {}:{}/".format(alure_package_name, hostname, testbed_mount_dir))

    sftp = ssh.open_sftp()
    sftp.put(localpath=f"/tmp/{alure_package_name}", remotepath=f"{testbed_mount_dir}/{alure_package_name}")

    sftp.close() 


    # Install allure inside the container
    log.info("install allure inside the container {} on host {}".format(container_name, hostname))
    cmd = f"docker exec {container_name} bash -c 'sudo dpkg -i {destination_path}/{alure_package_name}'"

    _, stdout, stderr = ssh.exec_command(cmd)
    if stdout.channel.recv_exit_status() != 0:
        log.error("failed to run {}: {}".format(cmd, stderr.read().decode("ascii").strip()))
        return -1


    # Cleanup the allure debian package 
    log.info("cleanup allure debian package from local /tmp/{}".format(alure_package_name))
    clean_cmd = f"rm -f /tmp/{alure_package_name}"
    os.system(clean_cmd)

    log.info("cleanup allure debian package from remote {}/{}".format(testbed_mount_dir, alure_package_name))
    clean_cmd = f"rm -f {testbed_mount_dir}/{alure_package_name}"
    _, stdout, stderr = ssh.exec_command(clean_cmd)
    if stdout.channel.recv_exit_status() != 0:
        log.error("failed to run {}: {}".format(clean_cmd, stderr.read().decode("ascii").strip()))

    
    log.info("allure debian package installed successfully")
    ssh.close()
    return 0


def sonic_install(args, index):
    log.debug("Entered sonic install function")
    global testbed_info_dict
    full_link = args.full_link.strip()
    [image, image_id, stream] = extractFromImageName(full_link)
    testbed = args.testbed.strip()
    testbed_info_dict = getTestbedInfoDict(testbed)
    image_ucs = getImageUCS(testbed)
    ip = testbed_info_dict['scp_ip'] if 'scp_ip' in testbed_info_dict else image_ucs['ip']
    cmd_list = list()
    image_url = testbed_info_dict['install_image_url'].replace("$image_id", image_id) if 'install_image_url' in testbed_info_dict else f'http://{ip}/{DEFAULT_IMAGES_FOLDER}{image_id}/{BIN_FILE}'
    run_comds = []
    if 'sonic_installer_commands' not in testbed_info_dict:
        # add a default set of commands
        run_comds = default_info['sonic_installer_commands']
    else:
        run_comds = testbed_info_dict['sonic_installer_commands']
    for cmd in run_comds:
        if "$image_url" in cmd:
            cmd = cmd.strip().replace("$image_url", image_url)
        cmd_list.append(cmd)
    log.debug(cmd_list)
    username = DUT_USERNAME
    password = DUT_PASSWORD
    if checkTortugaImage(stream):
        username = CISCO_USERNAME
        password = CISCO_PASSWORD

    rc = nested_ssh(testbed_info_dict["ucs_host_name"], testbed_info_dict["ucs_username"], testbed_info_dict["ucs_password"], testbed_info_dict["dut_ssh"][index], username, password, cmd_list, False)
    time.sleep(120)
    log.debug("Image loaded, log into dut again and check for docker count")

    if 'extra_sonic_commands' in testbed_info_dict:
        log.debug("Executing extra_sonic_commands")
        time.sleep(300)
        checkForDockersSonic(testbed, stream, index)
        p2 = sshUtil(testbed_info_dict['ucs_username'], testbed_info_dict['ucs_host'], testbed_info_dict['ucs_password'], None)
        scp_cmd = testbed_info_dict['extra_sonic_commands'][0]
        if "$topology" in scp_cmd:
            topology = args.topology.strip()
            scp_cmd = scp_cmd.strip().replace("$topology", topology)
        if "$sonic-mgmt-folder" in scp_cmd:
            scp_cmd = scp_cmd.strip().replace("$sonic-mgmt-folder", getSonicMgmtFolder(stream, testbed))
        scpUtil(p2, scp_cmd, DUT_PASSWORD)
        time.sleep(30)
        p2.close()
        for ssh in testbed_info_dict['dut_ssh']:
            if len(testbed_info_dict['extra_sonic_commands']) > 1:
                cmd_list = testbed_info_dict['extra_sonic_commands'][1:]
                rc = nested_ssh(testbed_info_dict["ucs_host_name"], testbed_info_dict["ucs_username"], testbed_info_dict["ucs_password"], ssh, username, password, cmd_list, True)
                if rc!=0:
                    log.error("Execution failed in extra_sonic_commands")
    
    # sleep for 5 minutes and check for docker after reboot
    time.sleep(300)
    checkForDockersSonic(testbed, stream, index)

def checkForDockersSonic(testbed, stream, index=0):
    cmd_list = list()
    cmd_list.append('docker ps -a | wc')
    testbed_info_dict = getTestbedInfoDict(testbed)
    docker_count = testbed_info_dict['docker_count'] if 'docker_count' in testbed_info_dict else DEFAULT_DOCKER_COUNT
    # connection gets lost after loading new image, reconnect with retry
    username = DUT_USERNAME
    password = DUT_PASSWORD
    if checkTortugaImage(stream):
        username = CISCO_USERNAME
        password = CISCO_PASSWORD

    return nested_ssh(testbed_info_dict["ucs_host_name"], testbed_info_dict["ucs_username"], testbed_info_dict["ucs_password"], testbed_info_dict["dut_ssh"][index], username, password, cmd_list, True, docker_count)

def nested_ssh(bastion_host, bastion_user, bastion_key, target_host, target_user, target_key, cmd_list, retry, docker_count=None):
    """Connect to a target host via a bastion host using Paramiko."""
    
    # Connect to the bastion host
    bastion_client = paramiko.SSHClient()
    bastion_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    bastion_client.connect(bastion_host, username=bastion_user, password=bastion_key)
    log.debug("First ssh done")
    [target_client, sock_channel] = channelConnection(bastion_client, target_host, target_user, target_key)
    log.debug(f"target_client: {target_client}")
    if target_client == None and retry==True:
        log.debug("Entered retry loop")
        retries = MAX_RETRIES
        while target_client == None and retries!=0:    
            log.debug("target_client is None, retry after timeout")
            time.sleep(100)
            [target_client, sock_channel] = channelConnection(bastion_client, target_host, target_user, target_key)
            log.debug(target_client)
            retries = retries-1
        if retries==0:
            log.error("Reached max retries, Second ssh failed!")
            return -1
    elif target_client == None:
        log.error("Second ssh failed!")
        return -1
    log.debug("Second ssh done. Executing commands...")
    log.debug(cmd_list)
    
    # Execute commands on the target host
    
    image = ""
    for cmd in cmd_list:
        if cmd == 'sudo sonic-installer set-next-boot':
            cmd = f'sudo sonic-installer set-next-boot {image}'
        log.debug(cmd)
        # channel = target_client.get_transport().open_session()
        stdin, stdout, stderr = target_client.exec_command(cmd)
        if cmd == 'sudo sonic-installer list':
            index = 0
            for line in iter(stdout.readline, ""):
                index = index+1
                log.debug(index)
                log.debug(line)
                if index==2:
                    image_type = line.strip().split("-")[1]
                    log.debug(image_type)
                if (index==5 and image_type == "B") or (index==6 and image_type == "A"):
                    image = line
            log.debug(image)
            stdout.channel.recv_exit_status()
            error = stderr.read()
            if error:
                print('There was an error pulling the runtime: {}'.format(error))
        elif cmd.startswith('sudo sonic-installer install'):
            answer = 'y'
            stdin.write(answer + '\n')
            stdin.flush()
            time.sleep(5)
            log.debug(stdout.read().strip())
            stdout.channel.recv_exit_status()
            error = stderr.read()
            if error:
                print('There was an error pulling the runtime: {}'.format(error))
        elif cmd == 'docker ps -a | wc':
            docker_count = int(docker_count) if docker_count is not None else DEFAULT_DOCKER_COUNT
            for line in iter(stdout.readline, ""):
                log.debug(f'line: {line}')
                line_docker_count = line.split("    ")[1].replace(" ", "")
                # Timeout to 10 mins - each retry for 30 seconds
                retries = 1 
                while int(line_docker_count)<int(docker_count):
                    time.sleep(30)
                    stdin, stdout, stderr = target_client.exec_command(cmd)
                    for line in iter(stdout.readline, ""):
                        line_docker_count = line.split("    ")[1].replace(" ", "")
                    retries = retries + 1
                    if retries>=MAX_RETRIES_TIMEOUT:
                        log.error("Timeout exceeded - not all dockers are up.")
                        return -1
                log.debug(int(line_docker_count))
                log.debug(int(docker_count))
                log.debug("All dockers are up.")
                error = stderr.read()
                if error:
                    print('There was an error pulling the runtime: {}'.format(error))
        elif cmd == "show int po":
            int_down = "LACP(A)(Dw)"
            for line in iter(stdout.readline, ""):
                log.debug(line)
                if int_down in line:
                    log.error(f"Some interfaces are down: {line}")
                    target_client.close()
                    bastion_client.close()
                    return -1
            log.debug("All port channels are up.")
            stdout.channel.recv_exit_status()
            error = stderr.read()
            if error:
                print('There was an error pulling the runtime: {}'.format(error))
        else:
            debug_cmd_exec(stdout.channel)
    # Close the connections
    closeConnections(bastion_client, target_client, sock_channel)
    return 0


def debug_cmd_exec(channel):
    # timeout for 60 seconds
    timeout = 60
    start_time = time.time()

    try:
        while True:
            if channel.recv_ready():
                # Read a chunk of data
                output = channel.recv(1024).decode('utf-8')
                if output:
                    log.debug(f"STDOUT: {output.strip()}")
            
            if channel.recv_stderr_ready():
                # Read error data
                error = channel.recv_stderr(1024).decode('utf-8')
                if error:
                    log.debug(f"STDERR: {error.strip()}")

            if channel.exit_status_ready():
                # Command execution finished
                log.debug("Command execution complete.")
                break
            else:
                # Check for timeout
                if time.time() - start_time > timeout:
                    log.error("Command execution timed out.")
                    raise TimeoutError("Command execution exceeded the timeout period.")

            time.sleep(0.1)  # Avoid busy-waiting
    except Exception as e:
        log.error(f"Error while processing output: {e}")
    finally:
        log.debug("Command execution complete.")
    return


def read_stream(stream, name):
    for line in iter(stream.readline, b''):
        log.debug(f"{name}: {line.strip()}")

def closeConnections(bastion_client, target_client, sock_channel):
    target_client.close()  # Close target host client
    sock_channel.close()        # Close the transport channel
    bastion_client.close()
    return

def checkforInterfaces(type, arg, index = 0):
    log.info("Check if interfaces are up")
    time.sleep(10)
    if type == "telnet":
        arg.sendline("show int po")
        i = arg.expect(["LACP(A)(Dw)", admin_prompt])
        if i == 0:
            log.error("All Interfaces are not up.")
            return -1
        else:
            log.info("All interfaces are up and running")
            return
    else:
        cmd_list = list()
        cmd_list.append("show int po")
        cmd_list.append("show ip bgp summary")
        # connection gets lost after loading new image, reconnect
        rc = nested_ssh(arg["ucs_host_name"], arg["ucs_username"], arg["ucs_password"], arg["dut_ssh"][index], DUT_USERNAME, DUT_PASSWORD, cmd_list, True)
    return rc


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Management full run.')
    subparser = parser.add_subparsers(help = "available subcommand:")

    pre_parser = subparser.add_parser("precheck", help = "precheck image")
    pre_parser.add_argument("-t", "--testbed", help = "testbed", required=True)
    pre_parser.add_argument("-f", "--full_link", help = "full link", required=True)
    pre_parser.set_defaults(func=precheck)

    fetch_parser = subparser.add_parser("fetch", help = "fetch image")
    fetch_parser.add_argument("-f", "--full_link", help = "full link", required=True)
    fetch_parser.add_argument("-t", "--testbed", help = "testbed", required=True)
    fetch_parser.set_defaults(func=fetch_image)

    onie_parser = subparser.add_parser("onie", help = "onie install on image")
    onie_parser.add_argument("-f", "--full_link", help = "full link", required=True)
    onie_parser.add_argument("-t", "--testbed", help = "testbed", required=True)
    onie_parser.add_argument("-i", "--install_mode", help = "install_mode")
    onie_parser.add_argument("--topology", help = "Topology type")
    onie_parser.set_defaults(func=image_install)

    remove_topo_parser = subparser.add_parser("remove-topo", help = "remove topo")
    remove_topo_parser.add_argument("-t", "--testbed", help = "testbed", required=True)
    remove_topo_parser.add_argument("-f", "--full_link", help = "full link", required=True)
    remove_topo_parser.set_defaults(func=remove_topo)

    add_topo_parser = subparser.add_parser("add-topo", help="add topo")
    add_topo_parser.add_argument("-t", "--testbed", help="testbed", required=True)
    add_topo_parser.add_argument("-f", "--full_link", help = "full link", required=True)
    add_topo_parser.set_defaults(func=add_topo)

    add_topo_parser = subparser.add_parser("extra_configuration_steps", help="extra steps specific to testbed")
    add_topo_parser.add_argument("-t", "--testbed", help="testbed", required=True)
    add_topo_parser.add_argument("-f", "--full_link", help="full link", required=True)
    add_topo_parser.set_defaults(func=extra_configuration_steps)

    deploy_parser = subparser.add_parser("deploy", help = "deploy mg")
    deploy_parser.add_argument("-t", "--testbed", help = "testbed", required=True)
    deploy_parser.add_argument("-f", "--full_link", help = "full link", required=True)
    deploy_parser.add_argument("-i", "--install_mode", help = "install_mode")
    deploy_parser.set_defaults(func=deploy_mg)

    allure_parser = subparser.add_parser("install-allure", help = "install allure package inside the base container")
    allure_parser.add_argument("-t", "--testbed", help = "testbed", required=True)
    allure_parser.add_argument("-f", "--full_link", help = "full link", required=True)
    allure_parser.set_defaults(func=install_allure)

    fetch_pipeline_parser = subparser.add_parser("fetch-pipeline", help = "fetch image from inside pipeline")
    fetch_pipeline_parser.add_argument("-t", "--testbed", help = "testbed", required=True)
    fetch_pipeline_parser.set_defaults(func=fetch_image_pipeline)

    args = parser.parse_args()

    res = args.func(args)
    sys.exit(res)
