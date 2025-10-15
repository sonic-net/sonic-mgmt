"""
script to clean configs from sonic routers in a testbed . 
Pre-Req:
    * Needs testbed yaml file to get device connectivity information
    * On h/w devices. if startup config is needed . make this startup config file
        /home/cisco/config_db.json.clean

Syntax
python clean_tb.py -t <path to testbed file> [-r <comma seperated list of routers] [-s]

-t : testbed file
-r : comma sperated list of routers to clean . all routers are cleaned  if not specified
     Example: "leaf0,leaf1"
-s : flag for sim testbed

Syntax Example:
python clean_tb.py -t ./vxlan_4S4L_topo_HW_sol2.yaml
"""
import paramiko
import threading
import argparse
import yaml


# pip install paramiko
commands_sim = [
    "sudo -s rm /etc/sonic/config_db.json",
    "sudo config-setup factory",
    "sudo -s config load /host/tortuga_config.db -y",
    "sudo -s config hostname sonic; config save -y",
    "sudo config reload -y -f",
]

commands_hw = [
    "sudo -s rm /etc/sonic/config_db.json",
    "sudo config-setup factory",
    "sudo cp /home/cisco/config_db.json.clean /etc/sonic/config_db.json",
    "sudo config reload -y",
    "sudo -s config hostname sonic; sudo config save -y",
]

def clean_rtr(rtr, commands):

    print('Cleaning router : {} : {}'.format(rtr['name'] , rtr['ip']))
    print("===== Cleaning Router: {} Start =====".format(rtr['name']))
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(rtr['ip'], username=rtr['username'], password=rtr['password'])
    for command in commands:
        print("{} ##### Executing command: {} #####".format(rtr, command))
        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(command)
        for line in ssh_stdout:
            print("{} >>>>> {}".format(rtr, line.strip('\n')))
    ssh.close()
    print("===== Cleaning Router: {} Done =====".format(rtr))

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="clean testbed script")
    parser.add_argument('-t', '--testbed',
                        help="full path of testbed file",
                        required=True,
                        )
    parser.add_argument("-r", "--routers",
                        help="coma seperated router names as in testbed file. example leaf0,leaf1",
                        default="all")
    parser.add_argument("-s", "--sim",
                    help="flags",
                    action='store_true')
    args = parser.parse_args()

    def ignore_line(loader, tag_suffix, node):
        return 'ignore'

    yaml.add_multi_constructor('', ignore_line)
    with open(args.testbed) as fd:
        testbed = yaml.load(fd, Loader=yaml.FullLoader)
    routers = dict()
    for node, node_info in testbed['devices'].items():
        if node_info['device_type'] == 'DevSonic':
            routers[node] = {
                             'name': node,
                             'ip': node_info['access']['ip'],
                             'username': node_info['credentials']['username'],
                             'password': node_info['credentials']['password']}
    if not args.routers == 'all':
        temp_routers = dict()
        for node in args.routers.split(','):
            if node not in routers.keys():
                temp_routers[node] = routers[node]
            else:
                print('Node {} not found in testbed'.format(node))
        routers = temp_routers
    
    commands = commands_sim if args.sim else commands_hw

    print('Cleaning routers : {}'.format(routers.keys()))
    threads = list()
    for rtr in routers.keys():
        thread = threading.Thread(target=clean_rtr,
                                  args=(routers[rtr], commands),
                                  name='clean_rtr_{}'.format(rtr))
        print('Starting Thread {}'.format(thread.name))

        thread.start()
        threads.append(thread)

    for thread in threads:
        print('Waiting for thread to complete {}'.format(thread.name))
        thread.join()
        print('Thread {} complete'.format(thread.name))

