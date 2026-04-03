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
import posixpath
import shlex
from collections import namedtuple
from hw_setup_utils import log, lower_pass_prompt, sshUtil, sshDUTUtil, extractFromImageName, getImageUCS, \
    cleanUpImageFolder, removeImageDir, checkSpace, getTestbedInfoDict, checkProdImage, telnetConnection, telnetLoginUtil, checklldpCount, \
    login_prompt, passwd_prompt, cisco_prompt, pre_sonic_prompt, sonic_login_prompt, admin_prompt, pre_admin_prompt, first_login, onie_prompt, \
    DUT_PASSWORD, DUT_USERNAME, BIN_FILE, telnet_escape_prompt, grub_selection, KEY_DOWN, newline_prompt, KEY_UP, checkForDockers, \
    scpUtil, sonic_prompt, getDockerExecCommand, copyDockerFileToDut, getSonicMgmtContainterName, get_container_local_mount_dir, \
    default_info, getSonicMgmtFolder, MAX_RETRIES, MAX_RETRIES_TIMEOUT, ALLURE_CONFIG_FILE_NAME, checkStreamCompatibility, checkTestbedAvailability, \
    channelConnection, checkTortugaImage, CISCO_PASSWORD, CISCO_USERNAME, getBranchFromStream
from utils import _run_cmd_in_ssh


UNSET_HTTP_PROXY = "unset https_proxy http_proxy HTTPS_PROXY HTTP_PROXY"
DEFAULT_DOCKER_COUNT = 13
DEFAULT_IMAGES_FOLDER = "IMAGES/"

REMOVE_TOPO_TIMEOUT_SEC = 60*20
ADD_TOPO_TIMEOUT_SEC = 60*20
DEPLOY_MG_TIMEOUT = 60*20

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
            log.info("User and permissions successfully configured.")
            p2.close()
            p1.close()
        except Exception as e:
            log.error(f"An error occurred while configuring the user: {e}")
            p2.close()
            p1.close()
            return -1
    return 0
            

def fetch_image_pipeline(args):
    testbed = args.testbed.strip()
    image_ucs = getImageUCS(testbed)
    log.info("Start login")
    log.info(image_ucs)
    log.info(image_ucs['username'])
    user = image_ucs['username']
    host = image_ucs['host']
    pswd = image_ucs['password']
    image_folder = image_ucs['images_folder']


    workspace_root = os.getenv("WORKSPACE")
    build_id = os.getenv('BUILD_ID')

    sonic_image_location = workspace_root+"/build/"+build_id


    # ssh to server
    log.info(f"SSH to server {host}, {user}/{pswd}")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, 22, user, pswd)

    sftp = ssh.open_sftp()

    print("sftp put file "+sonic_image_location+"/sonic-cisco-8000.bin")
    try:
        sftp.put(sonic_image_location+"/sonic-cisco-8000.bin", f"{image_folder}/{build_id}/sonic-cisco-8000.bin")
        sftp.put(sonic_image_location+"/docker-syncd-cisco-rpc.gz", f"{image_folder}/{build_id}/docker-syncd-cisco-rpc.gz")
    except FileNotFoundError:
        log.info(f"Path {image_folder}/{build_id} does not exist in server, create one")
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
    log.info("Start login")
    log.info(image_ucs)
    log.info(image_ucs['username'])
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
    log.debug("downloading")
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

    image_ucs = getImageUCS(testbed)
    host = image_ucs['host']
    image_folder = image_ucs['images_folder']
    build_id = os.getenv('BUILD_ID')

    if install_mode == "default" or install_mode == None:
        install_mode = testbed_info_dict["installer_mode"] if "installer_mode" in testbed_info_dict else "sonic"
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

    # add validation for build_id to make sure there arn't directory traversal characters in it, to prevent accidental deletion of wrong directories in the cleanup step
    if ".." in build_id or "/" in build_id or "\\" in build_id:
        log.error("Invalid build_id detected, potential directory traversal attempt")
        return -1

    remote_build_dir = posixpath.join(str(image_folder).rstrip("/"), str(build_id))
    image_remove_cmd = f"rm -rf {shlex.quote(remote_build_dir)}"

    # ssh to server
    user = image_ucs.get('username')
    pswd = image_ucs.get('password')
    
    log.info(f"SSH to server {host}, {user}/***")
    with paramiko.SSHClient() as ssh:
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=host, port=22, username=user, password=pswd)

        try:
            log.info(f"Removing remote image folder: {remote_build_dir}")
            stdout, stderr, status_code = _run_cmd_in_ssh(ssh, image_remove_cmd, timeout=60 * 10)
            if status_code != 0:
                log.error(f"Failed to cleanup remote image folder. rc={status_code}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}")
                return -1
            log.info("Remote image folder cleanup completed")
        except Exception as e:
            log.error(f"An error occurred while removing the remote image folder. Exception:{e}")
            raise

    return 0

def run_sonic_post_install_commands(p, testbed_info_dict, index):
    if 'sonic_post_install_commands' not in testbed_info_dict:
        log.debug("No sonic_post_install_commands found in testbed config")
        return

    try:
        post_install_cmds = testbed_info_dict['sonic_post_install_commands'][index]
        log.info(f"Executing {len(post_install_cmds)} sonic_post_install_commands for DUT index {index}")

        for cmd in post_install_cmds:
            log.debug(f"Sending SONIC post command: {cmd}")
            p.sendline(cmd)
            time.sleep(5)  # Allow command to execute
            p.expect(pre_admin_prompt)

        time.sleep(5)
        log.info("All sonic_post_install_commands executed successfully")
    except IndexError:
        log.warning(f"No sonic_post_install_commands found for DUT index {index}")
    except Exception as e:
        log.error(f"Error executing sonic_post_install_commands: {e}")
        raise

def run_sonic_pre_install_commands(p, testbed_info_dict, index):
    if 'sonic_pre_install_commands' not in testbed_info_dict:
        log.debug("No sonic_pre_install_commands found in testbed config")
        return
    
    try:
        pre_install_cmds = testbed_info_dict['sonic_pre_install_commands'][index]
        log.info(f"Executing {len(pre_install_cmds)} sonic_pre_install_commands for DUT index {index}")
        
        for cmd in pre_install_cmds:
            log.debug(f"Sending SONIC pre-install command: {cmd}")
            p.sendline(cmd)
            time.sleep(5)  # Allow command to execute
            p.expect(pre_admin_prompt)
        
        time.sleep(5)
        log.info("All sonic_pre_install_commands executed successfully")
    except IndexError:
        log.warning(f"No sonic_pre_install_commands found for DUT index {index}")
    except Exception as e:
        log.error(f"Error executing sonic_pre_install_commands: {e}")
        raise

def run_onie_pre_install_commands(p, testbed_info_dict, index):
    if 'onie_pre_install_commands' not in testbed_info_dict:
        log.debug("No onie_pre_install_commands found in testbed config")
        return
    
    try:
        pre_install_cmds = testbed_info_dict['onie_pre_install_commands'][index]
        log.info(f"Executing {len(pre_install_cmds)} onie_pre_install_commands for DUT index {index}")
        
        for cmd in pre_install_cmds:
            log.debug(f"Sending ONIE pre-install command: {cmd}")
            p.sendline(cmd)
            time.sleep(5)  # Allow command to execute
            p.expect(onie_prompt)
        
        time.sleep(5)
        log.info("All onie_pre_install_commands executed successfully")
    except IndexError:
        log.warning(f"No onie_pre_install_commands found for DUT index {index}")
    except Exception as e:
        log.error(f"Error executing onie_pre_install_commands: {e}")
        raise

def onie_install(args, index):
    log.info(f"Starting onie_install for testbed {args.testbed} DUT index {index}")
    log.info(f"args: {args}")
    global testbed_info_dict
    full_link = args.full_link.strip()
    [image, image_id, stream] = extractFromImageName(full_link)
    testbed = args.testbed.strip()
    testbed_info_dict = getTestbedInfoDict(testbed)
    image_ucs = getImageUCS(testbed)
    [host, port] = testbed_info_dict['telnet_details'][index].split(" ")
    log.info(f"Telnet details for DUT index {index}: host={host}, port={port}")
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
        log.info("Getting prompt")
        i = p.expect(expected_prompts)
        log.info(f"got prompt #{i} --> '{expected_prompts[i]}'")
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
            # Execute pre-install commands before onie-nos-install
            run_onie_pre_install_commands(p, testbed_info_dict, index)
            p.send("onie-nos-install ")
            image_folder = f'{image_id}'
            ip = testbed_info_dict['onie_ip'] if "onie_ip" in testbed_info_dict else image_ucs['ip']
            onie_path = testbed_info_dict['onie_path'] if "onie_path" in testbed_info_dict else DEFAULT_IMAGES_FOLDER
            p.send(f'http://{ip}/{onie_path}{image_folder}/{BIN_FILE}')
            p.sendline()
            log.info(p.after)
            skip_onie = "True"
        elif i == 9:
            time.sleep(1) 
            if retry_count == 3: # retry 3 times
                log.error("Login not successful into DUT")
                return -1
            else:
                retry_count = retry_count+1
        else:
            log.error("unexpected prompt, exiting telnet")
            p.sendline(telnet_escape_prompt)
            p.expect('>telnet')
            p.sendline('quit')
            break
    
    log.info("Reboot done. Waiting for GRUB ONIE selection menu")
    if skip_onie != "True":
        p.expect(grub_selection)
        log.info("Got GRUB menu, selecting ONIE instead of default image")
        p.send(KEY_DOWN)
        p.send(KEY_DOWN)
        p.send(KEY_DOWN)
        p.send(KEY_DOWN)
        p.sendline(newline_prompt)
        p.expect("Loading ONIE")
        log.info("Got 'Loading ONIE', waiting for GRUB menu")
        time.sleep(1)
        p.expect(["ONIE: Install OS", "ONIE: Rescue"])
        log.info("Got GRUB menu, ONIE Install Mode by seinding KEY_UP and enter, allow for ONIE Rescue Mode")
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

        log.info("Waiting for prompt: 'ONIE: OS Install Mode ...'")
        p.expect(["ONIE: OS Install Mode ...", "ONIE: Rescue Mode ..."])
        log.info("Got prompt: 'ONIE: OS Install/Rescue Mode ...'")
        log.info("Waiting for prompt: 'Please press Enter to activate this console.'")
        log.debug(p.after)
        p.expect('Please press Enter to activate this console.')
        log.info("Got prompt: 'Please press Enter to activate this console.'")
        p.sendline(newline_prompt)
        p.sendline(newline_prompt)
        p.sendline(newline_prompt)
        p.sendline('onie-stop')
        p.expect(["Stopping: discover...", "Rescue mode detected. No discover stopped."])
        p.expect(onie_prompt)
        # without DHCP, need to wait for ONIE to try and finish its DHCP flow before setting up the image
        time.sleep(60)
        # Execute pre-install commands before onie-nos-install
        run_onie_pre_install_commands(p, testbed_info_dict, index)
        p.send("onie-nos-install ")
        image_folder = f'{image_id}'
        ip = testbed_info_dict['onie_ip'] if "onie_ip" in testbed_info_dict else image_ucs['ip']
        onie_path = testbed_info_dict['onie_path'] if "onie_path" in testbed_info_dict else DEFAULT_IMAGES_FOLDER
        p.send(f'http://{ip}/{onie_path}{image_folder}/{BIN_FILE}')
        p.sendline()

    p.expect("Loading SONiC-OS OS initial ramdisk ...")
    # p.expect("+ exit 0")
    p.sendline(newline_prompt)
    p.sendline(newline_prompt)
    if telnetLoginUtil(p, stream) == -1:
        return -1
    
    log.info('Install process completed!')

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
        cmds_list = testbed_info_dict['extra_onie_commands'][index]
        log.debug(cmds_list)
        for cmd in cmds_list:
            log.debug(f"Executing extra ONIE command: {cmd}")
            time.sleep(2)
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
            elif "config reload" in cmd:
                log.debug(f"Executing config reload, command: {cmd}")
                time.sleep(30) #give time for reload commands to run before continuing
                p.sendline('\n')
                p.expect(sonic_prompt)
            else:
                p.sendline(cmd)
                p.expect(sonic_prompt)      
    p.close()

    log.info(f"ONIE install completed successfully for testbed {testbed}, DUT index {index} (telnet host {host}, port {port})")
    return

def remove_topo(args):
    testbed = args.testbed.strip()
    full_link = args.full_link.strip()
    [_, _, stream] = extractFromImageName(full_link)
    testbed_info_dict = getTestbedInfoDict(testbed)

    remove_topo_cmd = testbed_info_dict.get('remove_topo_cmd')
    if remove_topo_cmd is None:
        log.warning(f"cannot get cmd for remove_topo from testbed_info_dict for testbed {testbed}")
        log.warning(f"Will continue the execution skipping remove-topo step entirely. Make sure it is intended (e.g. "
                    f"b2b testbed is used), otherwise update the info in hw_cfg.json")
        return 0
    else:
        log.debug(f'got cmd for remove_topo: "{remove_topo_cmd}"')

    with paramiko.SSHClient() as client:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=testbed_info_dict['ucs_host'],
            username=testbed_info_dict['ucs_username'],
            password=testbed_info_dict['ucs_password']
        )

        remove_topo_outside_docker_cmd = getDockerExecCommand(stream,
                                                              testbed,
                                                              flags='',
                                                              suffix=f'-c "cd /data/ansible; {remove_topo_cmd}"')
        log.info(f"One-liner to remove topo from outside sonic-mgmt docker container:\n{remove_topo_outside_docker_cmd}")
        _, _, rc = _run_cmd_in_ssh(client, remove_topo_outside_docker_cmd, timeout=REMOVE_TOPO_TIMEOUT_SEC)
        if rc:
            raise RuntimeError("remove-topo returned non-zero return code. Please check logs.")

    return 0

def load_docker_ptf_image(stream, docker_ptf_url=None):
    log.info('start load_docker_ptf_image')
    global testbed_info_dict  # assuming it's set in add_topo
    STREAM_TO_DOCKER_PTF_MAP = {
        '202405': 'http://172.26.235.76/MISC/docker-ptf_anukverm-202405-27Jun2025-mix.gz',
        '202405c': 'http://172.26.235.76/MISC/docker-ptf_anukverm-202405-27Jun2025-mix.gz',
        '202411': 'http://172.26.235.76/MISC/docker-ptf_anukverm-202411-27Jun2025-mix.gz',
        '202501': 'http://172.26.235.76/MISC/docker-ptf_anukverm-202411-27Jun2025-mix.gz',
        '202505': 'http://172.26.235.76/MISC/docker_ptf_202505_8Oct_azure_tagged_latest.tar',
        '202511': 'http://172.26.235.76/MISC/docker_ptf_202511_9Dec2025_azure_tagged_latest.tar',
        'c-master': 'http://172.26.235.76/MISC/docker_ptf_202505_8Oct_azure_tagged_latest.tar',
        'master': 'http://172.26.235.76/MISC/docker-ptf_anukverm-master-27Jun2025-mix.gz'
    }

    ptf_docker_image_link = docker_ptf_url if docker_ptf_url \
        else STREAM_TO_DOCKER_PTF_MAP.get(stream)
    if not ptf_docker_image_link:
        log.error(f"unable to find matching docker ptf link for {stream}.")
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
    stdout, stderr, status_code = _run_cmd_in_ssh(client, f'{UNSET_HTTP_PROXY}; wget -ncv {ptf_docker_image_link}', timeout=60 * 30)
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

    add_topo_cmd = testbed_info_dict.get('add_topo_cmd')
    if add_topo_cmd is None:
        log.warning(f"Cannot get cmd for add_topo from testbed_info_dict for testbed {testbed}")
        log.warning(f"Will continue the execution skipping add-topo step entirely. Make sure it is intended (e.g. "
                    f"b2b testbed is used), otherwise update the info in hw_cfg.json")
        return 0
    else:
        log.debug(f'got cmd for add_topo: "{add_topo_cmd}"')

    load_docker_ptf_image(getBranchFromStream(stream), os.getenv("DOCKER_PTF_IMAGE_OVERRIDE"))

    with paramiko.SSHClient() as client:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=testbed_info_dict['ucs_host'],
            username=testbed_info_dict['ucs_username'],
            password=testbed_info_dict['ucs_password']
        )

        add_topo_outside_docker_cmd = getDockerExecCommand(stream,
                                                           testbed,
                                                           flags='',
                                                           suffix=f'-c "cd /data/ansible; {add_topo_cmd}"')
        log.info(f"One-liner to add topo from outside sonic-mgmt docker container:\n{add_topo_outside_docker_cmd}")
        _, _, rc = _run_cmd_in_ssh(client, add_topo_outside_docker_cmd, timeout=ADD_TOPO_TIMEOUT_SEC)
        if rc:
            raise RuntimeError("add-topo returned non-zero return code. Please check logs.")


    # install python-saithrift_1.13.0_amd64.deb inside docker ptf container
    SAITHRIFT_DEB_FILENAME = "python-saithrift_1.13.0_amd64.deb"
    SAITHRIFT_DEB_URL = f"http://172.26.235.76/MISC/{SAITHRIFT_DEB_FILENAME}"
    SAITHRIFT_WHEEL_FILENAME = f"switch_sai_thrift-1.13.0-py3-none-any.whl"
    SAITHRIFT_WHEEL_URL = f"http://172.26.235.76/MISC/{SAITHRIFT_WHEEL_FILENAME}"

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

        #
        # install using .deb file -- this is the go-to method before 202511
        #
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

        #
        # install using python wheel -- needed for 202511 (and onward?) MIGSOFTWAR-33560
        #
        log.info(f"Installing {SAITHRIFT_WHEEL_FILENAME} using pip")
        # download the file
        _, _, status_code = _run_cmd_in_ssh(client,
                                            f'{UNSET_HTTP_PROXY}; wget -nc {SAITHRIFT_WHEEL_URL}',
                                            timeout=60 * 5)
        if status_code:
            log.warning(f"Unable to download {SAITHRIFT_WHEEL_FILENAME}")
        # copy into docker-ptf
        _, _, status_code = _run_cmd_in_ssh(client,
                                            f"docker cp {SAITHRIFT_WHEEL_FILENAME} {docker_ptf_container_name}:/root")
        if status_code:
            log.warning(f"Error trying to copy {SAITHRIFT_WHEEL_FILENAME} into {docker_ptf_container_name}")
        # install the package
        _, _, status_code = _run_cmd_in_ssh(client,
                                            f"docker exec {docker_ptf_container_name} bash -c 'pip install {SAITHRIFT_WHEEL_FILENAME}'")
        if status_code:
            log.warning(f"Error attempting to pip install {SAITHRIFT_WHEEL_FILENAME}")
        # verify through import
        verify_saithrift_package_oneliner = f"""docker exec {docker_ptf_container_name} bash -c 'source env-python3/bin/activate; python3 -c "import switch_sai_thrift; print(switch_sai_thrift)"'"""
        _, _, status_code = _run_cmd_in_ssh(client,
                                  verify_saithrift_package_oneliner)
        if status_code:
            log.warning(f"venv-python3 switch_sai_thrift check failed. It might be intended depending on sonic version. Continue.")

    return 0

def deploy_mg(args):
    testbed = args.testbed.strip()
    full_link = args.full_link.strip()
    [image, image_id, stream] = extractFromImageName(full_link)
    testbed_info_dict = getTestbedInfoDict(testbed)
    install_mode = args.install_mode.strip()
    if "ucs_tb" not in testbed_info_dict or 'deploy_flag' in testbed_info_dict and testbed_info_dict['deploy_flag'] == 'False':
        log.debug("Deploy minigraph not needed or parameter missing.")
        return  
    if install_mode == "default" or install_mode == None:
        install_mode = testbed_info_dict["installer_mode"] if "installer_mode" in testbed_info_dict else "sonic"

    deploy_mg_cmd = f'./testbed-cli.sh deploy-mg {testbed_info_dict["ucs_tb"]} ./lab ./password.txt'

    with paramiko.SSHClient() as client:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=testbed_info_dict['ucs_host'],
            username=testbed_info_dict['ucs_username'],
            password=testbed_info_dict['ucs_password']
        )
        deploy_mg_outside_docker_cmd = getDockerExecCommand(stream,
                                                            testbed,
                                                            flags='',
                                                            suffix=f'-c "cd /data/ansible; {deploy_mg_cmd}"')
        log.info(f"One-liner to deploy-mg from outside sonic-mgmt docker container:\n{deploy_mg_outside_docker_cmd}")
        _, _, rc = _run_cmd_in_ssh(client, deploy_mg_outside_docker_cmd, timeout=DEPLOY_MG_TIMEOUT)
        if rc:
            raise RuntimeError("deploy-mg returned non-zero return code. Please check logs.")

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

    log.info("End of extra_configuration_steps")
    return 0


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

    if 'sonic_pre_install_commands' in testbed_info_dict:
        rc = telnet_run_sonic_pre_post_commands(args, index, True)
        if rc!=0:
            log.error("Execution failed in sonic_pre_install_commands")

    rc = nested_ssh(testbed_info_dict["ucs_host_name"], testbed_info_dict["ucs_username"], testbed_info_dict["ucs_password"], testbed_info_dict["dut_ssh"][index], username, password, cmd_list, False)
    if rc:
        raise RuntimeError("Error when trying to install the image via sonic-installer. Please check logs.")

    rc = reboot_all_DUTs(testbed, username=username, password=password)
    if rc:
        raise RuntimeError(f"Rebooting DUTs failed. Please check logs.")

    log.debug("Image loaded, log into dut again and check for docker count")

    if 'sonic_post_install_commands' in testbed_info_dict:
        rc = telnet_run_sonic_pre_post_commands(args, index, False)
        if rc!=0:
            log.error("Execution failed in sonic_post_install_commands")

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

        if "scp " in scp_cmd:  # crutch to enable non-scp cmds to be specified in `extra_sonic_commands`
            scpUtil(p2, scp_cmd, DUT_PASSWORD)
            time.sleep(30)
        else:
            log.debug(f"`Command will NOT BE EXECUTED: \n{scp_cmd}`\nReason: it doesn't contain `scp `")

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

def telnet_run_sonic_pre_post_commands(args, index, pre_sonic=True):
    log.debug("Entered telnet_run_sonic_pre_post_commands function")
    global testbed_info_dict
    full_link = args.full_link.strip()
    [image, image_id, stream] = extractFromImageName(full_link)
    testbed = args.testbed.strip()
    testbed_info_dict = getTestbedInfoDict(testbed)

    username = DUT_USERNAME
    password = DUT_PASSWORD
    if checkTortugaImage(stream):
        username = CISCO_USERNAME
        password = CISCO_PASSWORD
    
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

    # login or sudo or onie install or run pre sonic config commands
    prompt = admin_prompt
    retry_count = 0
    while True:
        time.sleep(2)
        log.info("Getting prompt")
        i = p.expect(expected_prompts)
        log.info(f"got prompt #{i} --> '{expected_prompts[i]}'")
        if i == 0 or i == 4:
            # send user name
            log.info("Sending Username")
            p.sendline(username)
        elif i == 1:
            # send password
            log.info("Sending Password")
            p.sendline(password)
        elif i == 2 or i == 5:
            time.sleep(3)
            log.info("Sending sudo su")
            p.sendline('sudo su')
        elif i == 3 or i == 6:
            log.info("Executing installation commands before sonic installer")
            
            if pre_sonic:
                run_sonic_pre_install_commands(p, testbed_info_dict, index)
            else:
                run_sonic_post_install_commands(p, testbed_info_dict, index)

            time.sleep(3)
            p.close()
            break
        elif i == 7:
            p.sendline("yes")
        elif i == 8:
            p.close()
            onie_install(args, index)
        
        elif i == 9:
            time.sleep(1)
            p.sendline("")
            if retry_count == 3: # retry 3 times
                log.error("Login not successful into DUT")
                p.close()
                return -1
            else:
                retry_count = retry_count+1
        else:
            log.error("unexpected prompt, exiting telnet")
            p.sendline(telnet_escape_prompt)
            p.expect('>telnet')
            p.sendline('quit')
            p.close()
            break
    return 0

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
    log.debug(f"Command list to execute via nested_ssh: {cmd_list}")
    
    # Execute commands on the target host
    
    image = ""
    for cmd in cmd_list:
        log.debug(f"Processing command: `{cmd}`")
        if cmd == 'sudo sonic-installer set-next-boot':
            cmd = f'sudo sonic-installer set-next-boot {image}'
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
            rc = stdout.channel.recv_exit_status()
            error = stderr.read()
            if error:
                log.error('There was an error pulling the runtime: {}'.format(error))
                return rc
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
                rc = stdout.channel.recv_exit_status()
                error = stderr.read()
                if error:
                    log.error('There was an error pulling the runtime: {}'.format(error))
                    return rc
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
            rc = stdout.channel.recv_exit_status()
            error = stderr.read()
            if error:
                log.error('There was an error pulling the runtime: {}'.format(error))
                return rc
        else:
            stdout.channel.settimeout(60)
            rc = stdout.channel.recv_exit_status()
            output = stdout.read().decode('utf-8').strip()
            error = stderr.read().decode('utf-8').strip()
            if output:
                log.debug(f"STDOUT: {output}")
            if error:
                log.warning(f"STDERR: {error}")
            if rc:
                log.error(f"Error during cmd execution `{cmd}`")
                return rc

    # Close the connections
    closeConnections(bastion_client, target_client, sock_channel)
    return 0

def execute_cmd_on_dut(bastion_host, bastion_user, bastion_key,
                       dut_mgmt_ip, dut_username, dut_ssh_password,
                       cmd, timeout=60):
    """
    ssh into the dut using mgmt-ip through the testbed server used as a bastion host,
    then execute the cmd and return (stdout_read, stderr_read, return_code)
    """
    with paramiko.SSHClient() as bastion_client:
        bastion_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        bastion_client.connect(bastion_host, username=bastion_user, password=bastion_key)
        log.debug("First ssh done")
        [target_client, sock_channel] = channelConnection(bastion_client, dut_mgmt_ip, dut_username, dut_ssh_password)
        log.debug(f"target_client: {target_client}")
        _, stdout, stderr = target_client.exec_command(command=cmd,
                                                           timeout=timeout
                                                           )
        stdout_read = stdout.read().decode('utf-8')
        stderr_read = stderr.read().decode('utf-8')
        return_code = stdout.channel.recv_exit_status()
        target_client.close()
        sock_channel.close()
    return stdout_read, stderr_read, return_code

def reboot_all_DUTs(testbed, username=DUT_USERNAME, password=DUT_PASSWORD, wait_seconds_for_reboot=60*5):
    """
    send `sudo reboot` on all DuTs in parallel then sleep some time (5 min by default)
    """
    log.info(f"Entered reboot_all_DUTs function for testbed '{testbed}'")
    testbed_info_dict = getTestbedInfoDict(testbed)

    from functools import partial
    from time import sleep
    from concurrent.futures import as_completed
    from concurrent.futures import ThreadPoolExecutor

    static_params = {
        "bastion_host": testbed_info_dict["ucs_host_name"],
        "bastion_user": testbed_info_dict["ucs_username"],
        "bastion_key": testbed_info_dict["ucs_password"],
        "dut_username": username,
        "dut_ssh_password": password,
        "cmd": "nohup sudo -n reboot >/dev/null 2>&1 &",
        "timeout": 60,
    }
    reboot_dut = partial(execute_cmd_on_dut, **static_params)

    success = True
    with ThreadPoolExecutor(max_workers=len(testbed_info_dict["dut_ssh"])) as pool:
        futures = [pool.submit(reboot_dut, dut_mgmt_ip=dut_mgmt_ip_addr)
                   for dut_mgmt_ip_addr in testbed_info_dict["dut_ssh"]]

        log.debug(f"Sleeping for {wait_seconds_for_reboot}...")
        sleep(wait_seconds_for_reboot)

        for future in as_completed(futures):
            try:
                log.info(future.result())
            except Exception as e:
                log.error(f"Exception {e} while trying to reboot a DUT")
                success = False

    if not success:
        log.error(f"Couldn't reboot all DUTs successfully. ")
        return 1
    else:
        log.info(f"Rebooted all DUTs successfully.")
        return 0


def cisco_system_health(testbed):
    """
    run cisco_system_health.py on each dut in the setup

    param: testbed -  str identifier of the testbed in hw_cfg.json

    return dict{dut_mgmt_ip: namedtuple(stdout, stderr, return_code)}
    """
    run_cisco_system_health_cmd = "python3 /opt/cisco/tools/bin/cisco_system_health.py"
    log.info('Starting cisco_system_health. '
             f'Will run `{run_cisco_system_health_cmd}` '
             'on the DuT.')

    testbed_info_dict = getTestbedInfoDict(testbed)
    results = {}
    for dut_mgmt_ip_addr in testbed_info_dict["dut_ssh"]:
        log.debug(f'Now attempting cisco_system_health for dut with mgmt_ip {dut_mgmt_ip_addr}')
        stdout, stderr, rc = execute_cmd_on_dut(testbed_info_dict["ucs_host_name"],
                                                testbed_info_dict["ucs_username"],
                                                testbed_info_dict["ucs_password"],
                                                dut_mgmt_ip_addr,
                                                DUT_USERNAME,
                                                DUT_PASSWORD,
                                                run_cisco_system_health_cmd,
                                                timeout=60 * 5)
        CiscoSystemHealthResults = namedtuple('CiscoSystemHealthResults', ['stdout', 'stderr', 'return_code'])
        results[dut_mgmt_ip_addr] = CiscoSystemHealthResults(stdout=stdout,
                                                             stderr=stderr,
                                                             return_code=rc)
        log.debug(f'Parsed results for cisco system health for dut {dut_mgmt_ip_addr}:'
                  f'{results[dut_mgmt_ip_addr]}')
    return results

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
