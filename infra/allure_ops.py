#!/usr/bin/python

import argparse
import json
import os
import sys
import paramiko
import yaml

from urllib import parse


# Path to config file
ALLURE_CONFIG_FILE_NAME = "config/allure-config.yaml"
allure_config = {}
with open(ALLURE_CONFIG_FILE_NAME, "r") as config_file:
    allure_config = yaml.load(config_file, Loader=yaml.FullLoader)
    config_file.close()


def _run_cmd_in_ssh(ssh, cmd, timeout=180):
    """
    Run a command in remote host
    """

    # run command inside the container
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)

    # to prevent buffer blockage
    cmd_output = stdout.read().decode()
    cmd_error = stderr.read().decode()

    # get the exit status
    exit_status = stdout.channel.recv_exit_status()

    print(f"Output for command '{cmd}': exit_status:{exit_status}\nstdout: {cmd_output}\nstderr: {cmd_error}")
    return cmd_output, cmd_error, exit_status

def _run_cmd_in_ssh_container(ssh, container_name, cmd, timeout=180):
    """
    Run a command in container
    """

    # run command inside the container
    docker_exec_cmd = f'docker exec {container_name} sh -c "{cmd}"'
    return _run_cmd_in_ssh(ssh, docker_exec_cmd, timeout)

def _create_parser():
    parser = argparse.ArgumentParser(description='Execute commands inside a docker container in a remote server')
    parser.add_argument('--username', type=str, help='ssh username',
                      required=True)
    parser.add_argument('--password', type=str, help='ssh password',
                      required=True)
    parser.add_argument('--host-address', type=str, help='Host address of remote server',
                      required=True)
    parser.add_argument('--ssh-port', type=str, help='optional: ssh port, if applicable',
                      required=False, default='22')
    parser.add_argument('--docker-container-name', type=str, help='name of docker container to go into',
                      required=True,default="")
    
    parser.add_argument('--install-allure', action='store_true', help='install allure inside container')
    
    parser.add_argument('--generate-report', action='store_true', 
                        help='generate report inside container, export it and create URL')
    parser.add_argument('--report-name', required='--generate-report' in sys.argv, type=str, 
                        help='name of the report to be generated - required if --generate-report is specified')
    
    
    return parser

def get_container_local_mount_dir(ssh, container_name, destination_path):
    cmd = f"docker inspect `docker ps -aq  --filter name=^/{container_name}$`"

    _, stdout, stderr = ssh.exec_command(cmd)
    if stdout.channel.recv_exit_status() != 0:
        err = "failed to run {}: {}".format(cmd, stderr.read().decode("ascii").strip())
        print(err)
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
        print(err)
        raise Exception(err)

    return testbed_mount_dir

def install_allure_on_remote_container(ssh, hostname, container_name):

    # Get docker mount directory on the testbed server
    destination_path = "/data"
    print("determine local mount dir for container path {}:{}".format(container_name, destination_path))
    testbed_mount_dir = get_container_local_mount_dir(ssh, container_name, destination_path)
    print("mount dir of container {}:{} on the testbed {}:{}".format(container_name, destination_path, hostname, testbed_mount_dir))

    # Download allure debian package
    allure_debian_url = allure_config['allure']['debian-url']
    if allure_debian_url is None or allure_debian_url == "":
        raise Exception("allure debian package URL is not provided")
    alure_package_name = os.path.basename(parse.urlparse(allure_debian_url).path)
    print("download allure debian package from {} to {}:{}".format(allure_debian_url, hostname, testbed_mount_dir))
    stdout, stderr, status_code = _run_cmd_in_ssh(ssh, f'wget {allure_debian_url} -P {testbed_mount_dir}')
    if status_code != 0:
        raise Exception(f'Failed to download the allure package: stdout: {stdout}, stderr: {stderr}')

    # Install the allure package in the sonic-mgmt container
    stdout, stderr, status_code = _run_cmd_in_ssh_container(ssh, container_name, f'sudo dpkg -i /data/{alure_package_name}')
    if status_code != 0:
        raise Exception(f'Failed to install the allure package: stdout: {stdout}, stderr: {stderr}')
    
    # Verify the allure installation in the sonic-mgmt container
    stdout, stderr, status_code = _run_cmd_in_ssh_container(ssh, container_name, 'allure --version')
    if status_code != 0:
        raise Exception(f'Failed to verify the allure installation: stdout: {stdout}, stderr: {stderr}')

    # Cleanup the downloaded package from the sonic-mgmt container (and the VM)
    stdout, stderr, status_code = _run_cmd_in_ssh_container(ssh, container_name, f'rm /data/{alure_package_name}')
    if status_code != 0:
        raise Exception(f'Failed to cleanup the downloaded package: stdout: {stdout}, stderr: {stderr}')
    
    return 0

def generate_allure_report_and_copy_to_remote(ssh, hostname, container_name, report_name):
    # Check if allure is installed
    stdout, stderr, status_code = _run_cmd_in_ssh_container(ssh, container_name, 'allure --version')
    if status_code != 0:
        err = f'Allure is not installed in the container {container_name}: stdout: {stdout}, stderr: {stderr}'
        print(err)
        raise Exception(err)

    # Get docker mount directory on the testbed server
    destination_path = "/data"
    print("determine local mount dir for container path {}:{}".format(container_name, destination_path))
    testbed_mount_dir = get_container_local_mount_dir(ssh, container_name, destination_path)
    print("mount dir of container {}:{} on the testbed {}:{}".format(container_name, destination_path, hostname, testbed_mount_dir))

    # Generate allure report
    local_report_dir = allure_config['allure']['local-report-dir']
    if local_report_dir is None or local_report_dir == "":
        raise Exception("local report directory is not provided")
    allure_report_directory_name = "allure-report-{}".format(report_name) 
    stdout, stderr, status_code = _run_cmd_in_ssh_container(ssh, container_name, 'allure generate --name {} -o /tmp/{} {}'.format(report_name, allure_report_directory_name, local_report_dir))
    if status_code != 0:
        raise Exception(f'Failed to generate allure report: stdout: {stdout}, stderr: {stderr}')

    # tar the allure report directory
    stdout, stderr, status_code = _run_cmd_in_ssh_container(ssh, container_name, 'tar -cvzf {}/{}.tar.gz /tmp/{}'.format(destination_path, allure_report_directory_name, allure_report_directory_name))
    if status_code != 0:
        raise Exception(f'Failed to archive allure report: stdout: {stdout}, stderr: {stderr}')
    
    # remove the allure report directory
    stdout, stderr, status_code = _run_cmd_in_ssh_container(ssh, container_name, 'rm -rf /tmp/{}'.format(allure_report_directory_name))
    if status_code != 0:
        raise Exception(f'Failed to clean allure report archive from /tmp/{allure_report_directory_name}: stdout: {stdout}, stderr: {stderr}')
    
    # Copy the allure report tarball to local
    print("Copying allure report tarball to local")
    ftp_client = ssh.open_sftp()
    ftp_client.get('{}/{}.tar.gz'.format(testbed_mount_dir, allure_report_directory_name), '/tmp/{}.tar.gz'.format(allure_report_directory_name))

    # remove the allure report tarball on remote
    stdout, stderr, status_code = _run_cmd_in_ssh_container(ssh, container_name, 'rm -rf {}/{}.tar.gz'.format(destination_path, allure_report_directory_name))
    if status_code != 0:
        raise Exception(f'Failed to clean allure report archive from {destination_path}/{allure_report_directory_name}.tar.gz: stdout: {stdout}, stderr: {stderr}')

    # extract the allure report tarball on local
    result = os.system('tar -xvzf /tmp/{}.tar.gz -C /'.format(allure_report_directory_name))
    if result != 0:
        raise Exception(f'Failed to extract the allure report tarball')

    # copy the allure report to remote
    remote_report_dir = allure_config['allure']['remote-report-dir'] 
    if remote_report_dir is None or remote_report_dir == "":
        raise Exception("remote report directory is not provided")
    remote_report_dir = remote_report_dir if remote_report_dir.endswith('/') else remote_report_dir + '/'
    result = os.system('cp -R /tmp/{} {}/'.format(allure_report_directory_name, remote_report_dir))
    if result != 0:
        raise Exception(f'Failed to copy the allure report to remote')

    # remove the allure report on local
    os.system('rm -rf /tmp/{}'.format(allure_report_directory_name))
    os.system('rm -rf /tmp/{}.tar.gz'.format(allure_report_directory_name))

    # create report URL
    allure_base_url = allure_config['allure']['server-base-url']
    if allure_base_url is None or allure_base_url == "":
        raise Exception("allure base URL is not provided")
    allure_report_url = "{}/{}/{}".format(allure_base_url, remote_report_dir, allure_report_directory_name)

    ftp_client.close()

    print("Allure report generated and copied to remote. Report URL: {}".format(allure_report_url))
    return 0, allure_report_url


def main():
    argparser = _create_parser()
    args = vars(argparser.parse_args())

    username = args['username']
    password = args['password']
    host_address = args['host_address']
    ssh_port = args['ssh_port']
    docker_container_name = args['docker_container_name']
    install_allure = args['install_allure']
    generate_report = args['generate_report']
    report_name = args['report_name'] if generate_report else ""

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=host_address, port=ssh_port, username=username, password=password, timeout=120, banner_timeout=120)

    if install_allure:
        install_allure_on_remote_container(ssh, host_address, docker_container_name)
    if generate_report:
        generate_allure_report_and_copy_to_remote(ssh, host_address, docker_container_name, report_name)
    return

if __name__ == '__main__':
  main()