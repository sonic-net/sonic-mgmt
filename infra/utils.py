import logging
import datetime
import paramiko
import time
import os
import re
import argparse
import sys
import json
import yaml
import subprocess
import shutil
from enum import Enum

BASE_LOG_PATH_HW = '/data/tests/'
BASE_UCS_HOME_DIR = '/home/sonic/'
SANITY_LOG_TARBALL = 'sanity_logs.tar.gz'
WORKSPACE = os.getenv("WORKSPACE")
SANITY_LOGS_PATH = 'sanity_logs'

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

log = init_logging("SANITY_LOGS")

# Path to config file
ALLURE_CONFIG_FILE_NAME = "config/allure-config.yaml"
allure_config = {}
with open(ALLURE_CONFIG_FILE_NAME, "r") as config_file:
    allure_config = yaml.load(config_file, Loader=yaml.FullLoader)
    config_file.close()

ALLURE_REPORT_URL_FILE = allure_config['allure']['report-url-file-path']
CICD_LOG_DIR = "/auto/mb/sonic/workspace/sonic-cicd/sanity_logs"
CICD_LOG_URL = "https://allure.cisco.com/auto/mb/sonic/workspace/sonic-cicd/sanity_logs"

SUCCESS_STATUS = "success"
FAILURE_STATUS = "failure"
SANITY_LOGS_PATH = 'sanity_logs'

def _run_cmd_in_ssh(ssh, cmd, timeout=180):
    """
    Run a command in remote host
    """

    if isinstance(cmd, str):
        cmd_str = cmd
    elif isinstance(cmd, list):
        cmd_str = ';'.join(cmd)
    else:
        raise ValueError(f"command passed is neither list or str, cannot create command string. cmd: {cmd}, type: {type(cmd)}")

    # run command inside the container
    stdin, stdout, stderr = ssh.exec_command(cmd_str, timeout=timeout)

    # to prevent buffer blockage
    cmd_output = stdout.read().decode()
    cmd_error = stderr.read().decode()

    # get the exit status
    exit_status = stdout.channel.recv_exit_status()

    log.info(f"Output for command '{cmd_str}': exit_status:{exit_status}\nstdout: {cmd_output}\nstderr: {cmd_error}")
    return cmd_output, cmd_error, exit_status

def _run_cmd_in_ssh_container(ssh, container_name, cmd, timeout=180):
    """
    Run a command in container
    """

    if isinstance(cmd, str):
        cmd_str = cmd
    elif isinstance(cmd, list):
        cmd_str = ';'.join(cmd)
    else:
        raise ValueError(f"command passed is neither list or str, cannot create command string. cmd: {cmd}, type: {type(cmd)}")
    # Escape internal double quotes for safe shell execution
    cmd_str = cmd_str.replace('"', '\\"')
    # run command inside the container
    docker_exec_cmd = f'docker exec {container_name} sh -c "{cmd_str}"'
    return _run_cmd_in_ssh(ssh, docker_exec_cmd, timeout)

def copy_logfiles(ssh, docker_mgmt_container, filename, destination_path):
    
    log.debug("Entered copy_logfiles")

    try:
        ftp_client=ssh.open_sftp()
        # ftp_client.chdir(source)

        source_file_path  = f"{BASE_LOG_PATH_HW}{filename}"
        log.debug(f"log file path: {filename}")

        # copy allure report tar file to the VM
        log.debug("Copying log files from container {}:{} to the UCS:{}".format(docker_mgmt_container, source_file_path, BASE_UCS_HOME_DIR))
        cmd = 'docker cp {}:{} {}\n'.format(docker_mgmt_container, source_file_path, BASE_UCS_HOME_DIR)

        log.debug(f"Execute cmd: {cmd}")
        _, stdout, stderr = ssh.exec_command(cmd)
        if stdout.channel.recv_exit_status() != 0:
            log.error("Error! Could not copy allure report from {}:{} to {}: {}".format(docker_mgmt_container, source_file_path, BASE_UCS_HOME_DIR, stderr.read().decode("ascii")))
            ssh.close()
            ftp_client.close()
            return -1

        # get allure report tar file from the VM
        dst_file_path  = f"{destination_path}/{filename}"
        ftp_client.chdir('.')
        current_directory = ftp_client.getcwd()
        log.debug(f"Current SFTP directory: {current_directory}")
        log.debug("Getting log file from the UCS:{} to {}".format(filename, dst_file_path))
        try:
            ftp_client.get(filename, dst_file_path)
        except Exception as e:
            raise Exception("Error! Could not get log file!")
        # Close the SFTP session and SSH connection
        ftp_client.close()
        return 0

    except Exception as e:
        print(f"An error occurred in copy_logfiles: {e}")
        return -1


def create_sanity_log_tarball(local_log_dir):
    log.debug(f"Current working directory in create_sanity_log_tarball: {os.getcwd()}")
    log.debug(f"CHeck params: tarball: {SANITY_LOG_TARBALL}, path: {SANITY_LOGS_PATH}, local_log_dir: {local_log_dir}")
    tarball_path = f"{local_log_dir}/{SANITY_LOG_TARBALL}"

    try:
        result = subprocess.run(['tar', '-czf', tarball_path, SANITY_LOGS_PATH], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        log.debug("Created tarball sanity_logs.tar.gz")
        log.debug(f"Return code: {result.returncode}")
        log.debug(f"STDOUT: {result.stdout}\n")
        log.debug(f"STDERR:{result.stderr}\n")
        parent_dir = os.path.abspath(os.path.join(local_log_dir, ".."))
        shutil.copy(SANITY_LOG_TARBALL, parent_dir)
    except subprocess.CalledProcessError as e:
        log.error(f"Error creating tarball: {e}")

def upload_log_files_to_log_server(files_to_copy):
    log.debug(f"Current working directory in upload_log_files_to_log_server: {os.getcwd()}")

    user = os.getenv("USER")
    date_formatted = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
    pipeline_type = os.getenv("PIPELINE_TYPE", "manual_sanity")
    build_id = os.getenv("BUILD_ID", f"{user}_{date_formatted}")
    report_repo = os.getenv("REPORT_REPO", f"{CICD_LOG_DIR}/{pipeline_type}")

    # Create the build directory within the 'infra' directory
    os.makedirs(build_id, exist_ok=True)

    log.debug(files_to_copy)
    uploaded_files = []

    # Copy each file from 'infra' to the build directory
    for file_name in files_to_copy:
        if os.path.exists(file_name):
            if os.path.isdir(file_name):
                dest = os.path.join(build_id, os.path.basename(file_name))
                shutil.copytree(file_name, dest, dirs_exist_ok=True)
            else:
                shutil.copy(file_name, build_id)
            uploaded_files.append(file_name)
        else:
            log.debug(f"Warning: {file_name} does not exist and was not copied.")

    
    # Copy the build directory to the report repository
    dest_dir = os.path.join(report_repo, build_id)
    log.debug(f"Copy build dir to repo, build_id: {build_id}, dest_dir: {dest_dir}")
    try:
        if os.path.exists(dest_dir):
            shutil.rmtree(dest_dir)
        shutil.copytree(build_id, dest_dir)
        log_url = f"{CICD_LOG_URL}/{pipeline_type}/{build_id}"
        log.debug(f"uploaded files {uploaded_files} to url: {log_url}")
        return log_url
    except Exception as e:
        log.error(f"Error copying build directory to report repo: {e}")
        return None
    
def print_folder_contents(folder_path):
    """
    Prints the names of all files and subdirectories within a given folder.

    Args:
        folder_path (str): The path to the folder.
    """
    try:
        # Get the list of all files and directories in the specified path
        contents = os.listdir(folder_path)
        print(f"Contents of '{folder_path}':")
        if not contents:
            print("  (Folder is empty)")
        else:
            for item in contents:
                print(f"  - {item}")
    except FileNotFoundError:
        print(f"Error: Folder '{folder_path}' not found.")
    except NotADirectoryError:
        print(f"Error: '{folder_path}' is not a directory.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
