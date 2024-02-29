#!/usr/bin/python

import argparse
import paramiko
import time

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
    parser.add_argument('--command', type=str, help='command to run inside container',
                      required=True)
    return parser

def main():
    argparser = _create_parser()
    args = vars(argparser.parse_args())

    username = args['username']
    password = args['password']
    host_address = args['host_address']
    ssh_port = args['ssh_port']
    docker_container_name = args['docker_container_name']
    command = args['command']

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host_address, ssh_port, username, password)

    print(f"connected to host {host_address}")
    chan = ssh.invoke_shell()
    resp = ''
    while ':~$' not in resp:
        resp = chan.recv(9999).decode("ascii")
        print(resp)
    time.sleep(3)

    print(f"Going into container '{docker_container_name}' to run command")
    chan.send(f'docker exec {docker_container_name} -it /bin/bash \n')
    time.sleep(3)
    resp = ''
    while ':~$' not in resp:
        resp = chan.recv(9999).decode("ascii")
        print(resp)
    time.sleep(3)

    print(f"sending command {command}")
    chan.send(command+"\n")
    chan.send("cd ~\n") #go back to home dir after command is complete
    time.sleep(3)
    resp = ''
    while ':~$' not in resp:
        resp = chan.recv(9999).decode("ascii")
        print(resp)
    time.sleep(3)


    print("sending command done, getting return code")
    chan.send("echo $?\n")
    time.sleep(3)
    resp = ''
    while ':~$' not in resp:
        resp = chan.recv(9999).decode("ascii")
        print(resp)
    time.sleep(3)




if __name__ == '__main__':
  main()


