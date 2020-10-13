import os
import sys
import subprocess
import argparse
import tempfile

import utilities.common as utils

def _fp_write(fp, data):
    fp.write(data.encode())

def ansible_playbook(playbook, host_list, username, password, logs_path=None):

    ansible_cfg = os.path.join(os.path.dirname(__file__), '..', "ansible", "ansible.cfg")
    ansible_cfg = os.path.abspath(ansible_cfg)
    ansible_dir = os.path.dirname(sys.executable)
    ansible_exe = os.path.join(ansible_dir, "ansible-playbook")

    if logs_path: os.environ["ANSIBLE_LOCAL_TEMP"] = logs_path
    os.environ["ANSIBLE_CONFIG"] = ansible_cfg
    # added the SSH_ARGS as environment variable to supress host checking as the nodes
    # in the case would be dut's with dynamic inventory.
    os.environ["ANSIBLE_SSH_ARGS"] = "-o ControlMaster=auto -o ControlPersist=60s -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"
    fp = tempfile.NamedTemporaryFile(delete=False)
    _fp_write(fp, "[hosts]\n")
    for host in host_list:
        _fp_write(fp, "{}\n".format(host))
    _fp_write(fp, "[hosts:vars]\n")
    _fp_write(fp, "ansible_user={}\n".format(username))
    _fp_write(fp, "ansible_password={}\n".format(password))
    fp.close()
    configs="\n".join(utils.read_lines(fp.name))

    cmd = "{} -i {} {}".format(ansible_exe, fp.name, playbook)
    #print("Executing", cmd)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    out, err = proc.communicate()
    proc.wait()
    os.unlink(fp.name)
    if proc.returncode != 0:
        msg = ["Error: Failed to execute ansible playbook '{}'".format(playbook)]
        msg.append("errcode: {} error: ('{}')".format(proc.returncode, err.strip()))
        msg.append("output: {}".format(out))
        msg.append("config: {}".format(configs))
        return "\n".join(msg)
    for line in out.splitlines():
        print(line)
    return out

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='SpyTest ansible helper.')

    parser.add_argument("--playbook", action="store", default=None,
                        required=True, help="execute given ansible playbook yaml.")
    parser.add_argument("--hosts", action="store", default=None, nargs="+",
                        required=True, help="ansible hosts.")
    parser.add_argument("--username", action="store", default=None,
                        required=True, help="ansible username for all hosts.")
    parser.add_argument("--password", action="store", default=None,
                        required=True, help="ansible password for all hosts.")

    args, unknown = parser.parse_known_args()

    ansible_playbook(args.playbook, args.hosts, args.username, args.password)

