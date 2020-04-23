from shutil import copyfile
import yaml
import datetime
import os
import argparse

""""
Testbed Processing

Requirement:
    python version: 2.X
    python package: PyYAML 3.12 (or later)

PyYaml Install Instructions:
    [1] Download PyYAML from https://pyyaml.org/wiki/PyYAML
    [2] Unpack the archive
    [3] Install the package by executing (python setup.py install)
    [4] Test if installation was successful (python setup.py test)

Usage:
    put TestbedProcessing.py and testbed.yaml under sonic-mgmt/ansible
    python TestbedProcessing.py
    python TestbedProcessing.py -i testbed.yaml

Arguments:
    -i : the testbed.yaml file to parse
    -basedir : the basedir for the project
    -backupdir : the backup directory for the files

Script Procedure
    [1] Backup the files we will be copying
    [2] Load testbed.yaml into dictionaries for easy processing
    [3] Generate the files via methods defined below
"""

# ARGUMENTS TO PARSE
parser = argparse.ArgumentParser(description="Process testbed.yml file")
parser.add_argument('-i', help='a file for the testbed processing script', nargs="?", default="testbed-new.yaml")
parser.add_argument('-basedir', help='base directory to find the files, points to /sonic-mgmt/ansible', default="")
parser.add_argument('-backupdir', help='backup directory to store files,  points to /sonic-mgmt/ansible/backup',nargs="?", default="backup")
args = parser.parse_args()

# FILES TO BACKUP
main_file = "group_vars/vm_host/main.yml"
vmHostCreds_file = "group_vars/vm_host/creds.yml"
labLinks_file = "files/sonic_lab_links.csv"
testbed_file = "testbed.csv"
devices_file = "files/sonic_lab_devices.csv"
eosCred_file = "group_vars/eos/creds.yml"
fanoutSecrets_file = "group_vars/fanout/secrets.yml"
labSecrets_file = "group_vars/lab/secrets.yml"
lab_file = "lab"
inventory_file = "inventory"
dockerRegistry_file = "vars/docker_registry.yml"
veos_file = "veos"
# the number of host_var files vary. therefore, backup process creates a list of all files under host_vars folder, iterates through the list, and copies them to backup directory

#Backup List
#backupList does not encompass host_var files because the number of host_var files vary. therefore, backup process creates a list of all files under host_vars folder, iterates through the list, and copies them to backup directory
backupList = []
backupList.append(main_file)
backupList.append(vmHostCreds_file)
backupList.append(labLinks_file)
backupList.append(testbed_file)
backupList.append(devices_file)
backupList.append(eosCred_file)
backupList.append(fanoutSecrets_file)
backupList.append(labSecrets_file)
backupList.append(lab_file)
backupList.append(inventory_file)
backupList.append(dockerRegistry_file)
backupList.append(veos_file)

#Backup Directories
now = datetime.datetime.now()
timestamp = str(now.month) + "_" + str(now.day) + "_" + str(now.year) + "_" + str(now.hour) + str(now.minute) + "_" + str(now.second)
os.makedirs(args.backupdir + "/" + timestamp)  # create folder in backup directory labeled with the current timestamp
os.makedirs(args.backupdir + "/" + timestamp + "/files")  # create files folder under the timestamped folder
os.makedirs(args.backupdir + "/" + timestamp + "/host_vars")  # create host_vars folder under the timestamped folder
os.makedirs(args.backupdir + "/" + timestamp + "/group_vars")  # create group_vars folder under the timestamped folder
os.makedirs(args.backupdir + "/" + timestamp + "/group_vars/eos")  # create group_vars/eos folder under the timestamped folder
os.makedirs(args.backupdir + "/" + timestamp + "/group_vars/fanout")  # create group_vars/fanout folder under the timestamped folder
os.makedirs(args.backupdir + "/" + timestamp + "/group_vars/lab")  # create group_vars/lab folder under the timestamped folder
os.makedirs(args.backupdir + "/" + timestamp + "/group_vars/vm_host")  # create group_vars/vm_host folder under the timestamped folder
os.makedirs(args.backupdir + "/" + timestamp + "/vars")  # create vars folder under the timestamped folder

"""
represent_none(self, _)
modifies yaml to replace null values with blanks
SOURCE: https://stackoverflow.com/questions/37200150/can-i-dump-blank-instead-of-null-in-yaml-pyyaml/37201633#3720163
"""
def represent_none(self, _):
    return self.represent_scalar('tag:yaml.org,2002:null', '')
yaml.add_representer(type(None), represent_none)


"""
generateDictionary(data, result, category)
@:parameter data - the dictionary to iterate through
@:parameter result - the resulting dictionary
Generates the dictionaries that are used when creating csv, yml, or text files
"""
def generateDictionary(data, result, category):
    for key, value in data[category].items():
        result.update({key: value})


"""
makeMain(data, outfile)
@:parameter data - the dictionary to look through
@:parameter outfile - the file to write to
makeMain generates the vm_host/main.yml file
it pulls two sets of information; dictionary data and proxy data
"""
def makeMain(data, outfile):
    veos = data
    dictData = {
        "root_path": veos.get("root_path"),
        "vm_images_url": veos.get("vm_images_url"),
        "cd_image_filename": veos.get("cd_image_filename"),
        "hdd_image_filename": veos.get("hdd_image_filename"),
        "skip_image_downloading": veos.get("skip_image_downloading"),
        "vm_console_base": veos.get("vm_console_base"),
        "memory": veos.get("memory"),
        "max_fp_num": veos.get("max_fp_num"),
        "ptf_bp_ip": veos.get("ptf_bp_ip"),
        "ptf_bp_ipv6": veos.get("ptf_bp_ipv6")
    }
    proxy = {
        "proxy_env": {
            "http_proxy": veos.get("proxy_env").get("http_proxy"),
            "https_proxy": veos.get("proxy_env").get("https_proxy")
        }
    }
    with open(outfile, "w") as toWrite:
        yaml.dump(dictData, stream=toWrite, default_flow_style=False)
        toWrite.write("# proxy\n")
        yaml.dump(proxy, stream=toWrite, default_flow_style=False)


"""
makeVMHost_cred(data, outfile)
@:parameter data - the dictionary to look for (in this case: veos)
@:parameter outfile - the file to write to
generates /group_vars/vm_host/creds.yml
pulls ansible_user, ansible_password, ansible_become_pass from vm_host_ansible into a dictionary
"""
def makeVMHostCreds(data, outfile):
    veos = data
    result = {
        "ansible_user": veos.get("vm_host_ansible").get("ansible_user"),
        "ansible_password": veos.get("vm_host_ansible").get("ansible_password"),
        "ansible_become_pass": veos.get("vm_host_ansible").get("ansible_become_pass")
    }
    with open(outfile, "w") as toWrite:
        toWrite.write("---\n")
        yaml.dump(result, stream=toWrite, default_flow_style=False)

"""
makeSonicLabDevices(data, outfile)
@:parameter data - the dictionary to look through (devices dictionary)
@:parameter outfile - the file to write to
generates files/sonic_lab_devices.csv by pulling hostname, managementIP, hwsku, and type
error handling: checks if attribute values are None type or string "None"
"""
def makeSonicLabDevices(data, outfile):
    csv_columns = "Hostname,ManagementIp,HwSku,Type"
    topology = data
    csv_file = outfile

    try:
        with open(csv_file, "w") as f:
            f.write(csv_columns + "\n")
            for device, deviceDetails in topology.items():
                hostname = device
                managementIP = str(deviceDetails.get("ansible").get("ansible_host"))
                hwsku = deviceDetails.get("hwsku")
                devType = deviceDetails.get("device_type")

                # catch empty values
                if not managementIP:
                    managementIP = ""
                if not hwsku:
                    hwsku = ""
                if not devType:
                    devType = ""

                row = hostname + "," + managementIP + "," + hwsku + "," + devType
                f.write(row + "\n")
    except IOError:
        print("I/O error: makeSonicLabDevices")


"""
makeTestbed(data, outfile)
@:parameter data - the dictionary to look through (devices dictionary)
@:parameter outfile - the file to write to
generates /testbed.csv by pulling confName, groupName, topo, ptf_image_name, ptf_ip, server, vm_base, dut, and comment
error handling: checks if attribute values are None type or string "None"
"""
def makeTestbed(data, outfile):
    csv_columns = "# conf-name,group-name,topo,ptf_image_name,ptf,ptf_ip,server,vm_base,dut,comment"
    topology = data
    csv_file = outfile

    try:
        with open(csv_file, "w") as f:
            f.write(csv_columns + "\n")
            for group, groupDetails in topology.items():
                confName = group
                groupName = groupDetails.get("group-name")
                topo = groupDetails.get("topo")
                ptf_image_name = groupDetails.get("ptf_image_name")
                ptf_ip = groupDetails.get("ptf_ip")
                server = groupDetails.get("server")
                vm_base = groupDetails.get("vm_base")
                dut = groupDetails.get("dut")
                ptf = groupDetails.get("ptf")
                comment = groupDetails.get("comment")

                # catch empty types
                if not groupName:
                    groupName = ""
                if not topo:
                    topo = ""
                if not ptf_image_name:
                    ptf_image_name = ""
                if not ptf_ip:
                    ptf_ip = ""
                if not server:
                    server = ""
                if not vm_base:
                    vm_base = ""
                if not dut:
                    dut = ""
                if not ptf:
                    ptf = ""
                if not comment:
                    comment = ""

                row = confName + "," + groupName + "," + topo + "," + ptf_image_name + "," + ptf + "," + ptf_ip + "," + server + "," + vm_base + "," + dut + "," + comment
                f.write(row + "\n")
    except IOError:
        print("I/O error: issue creating testbed.csv")


"""
makeSonicLabLinks(data, outfile)
@:parameter data - the dictionary to look through (devices dictionary)
@:parameter outfile - the file to write to
generates /files/sonic_lab_links.csv by pulling startPort, endPort, bandWidth, vlanID, vlanMode
error handling: checks if attribute values are None type or string "None"
"""
def makeSonicLabLinks(data, outfile):
    csv_columns = "StartDevice,StartPort,EndDevice,EndPort,BandWidth,VlanID,VlanMode"
    topology = data
    csv_file = outfile

    try:
        with open(csv_file, "w") as f:
            f.write(csv_columns + "\n")
            for key, item in topology.items():
                startDevice = key
                interfacesDetails = item.get("interfaces")

                for startPort, element in interfacesDetails.items():
                    startPort = startPort
                    endDevice = element.get("EndDevice")
                    endPort = element.get("EndPort")
                    bandWidth = element.get("Bandwidth")
                    vlanID = element.get("VlanID")
                    vlanMode = element.get("VlanMode")

                    # catch empty values
                    if not endDevice:
                        endDevice = ""
                    if not endPort:
                        endPort = ""
                    if not bandWidth:
                        bandWidth = ""
                    if not vlanID:
                        vlanID = ""
                    if not vlanMode:
                        vlanMode = ""

                    row = startDevice + "," + startPort + "," + endDevice + "," + endPort + "," + str(bandWidth) + "," + str(vlanID) + "," + vlanMode
                    f.write(row + "\n")
    except IOError:
        print("I/O error: issue creating sonic_lab_links.csv")


"""
makeEOS_creds(data, outfile)
@:parameter data - the dictionary to look through
@:parameter outfile - the file to write to
Generate /group_vars/eos/creds.yml
Works by looking through veos dictionary and pulling ansible_user and ansible_password under eos_ansible
"""
def makeEOSCreds(data, outfile):
    veos = data
    result = {
        "ansible_user": veos.get("eos_ansible").get("ansible_user"),
        "ansible_password": veos.get("eos_ansible").get("ansible_password")
    }
    with open(outfile, "w") as toWrite:
        toWrite.write("---\n")
        yaml.dump(result, stream=toWrite, default_flow_style=False)


"""
makeFanout_secrets(data, outfile)
@:parameter data - reads from devices dictionary
@:parameter outfile - the file to write to
Makes /group_vars/fanout/secrets.yml
Finds the fanout secret credentials by using "fanout" as the value to search for under device_type
Under github and personal topology configuration, there is only one designated fanout switch credential
"""
def makeFanoutSecrets(data, outfile):
    devices = data
    result = dict()

    for key, value in devices.items():
        if "fanout" in value.get("device_type").lower():
            result.update({"ansible_ssh_user": value.get("ansible").get("ansible_ssh_user")})
            result.update({"ansible_ssh_pass": value.get("ansible").get("ansible_ssh_pass")})

    with open(outfile, "w") as toWrite:
        yaml.dump(result, stream=toWrite, default_flow_style=False)


"""
makeLab_secrets(data, outfile)
@:parameter data - reads from devices dictionary
@:parameter outfile - the file to write to
Makes /group_vars/lab/secrets.yml
Finds the lab device to generate the secret.yml file using "server" as the value to search for under device_type
Under github and personal topology configuration, there is only one designated lab server
"""
def makeLabSecrets(data, outfile):
    devices = data
    result = dict()

    for key, value in devices.items():
        if "server" in value.get("device_type").lower():
            result.update({"ansible_ssh_pass": value.get("ansible").get("ansible_ssh_pass")})
            result.update({"ansible_become_pass": value.get("ansible").get("ansible_become_pass")})
            result.update({"sonicadmin_user": value.get("ansible").get("sonicadmin_user")})
            result.update({"sonicadmin_password": value.get("ansible").get("sonicadmin_password")})
            result.update({"sonicadmin_initial_password": value.get("ansible").get("sonicadmin_initial_password")})

    with open(outfile, "w") as toWrite:
        yaml.dump(result, stream=toWrite, default_flow_style=False)

"""
makeLab(data, veos, devices, outfile)
@:parameter data - reads from devices-groups, this helps separate the function into 3 components; children, host, vars
@:parameter devices - reads from devices
@:parameter testbed - reads from testbed (to accomodate for PTF container(s))
@:parameter outfile - writes to lab
"""
def makeLab(data, devices, testbed, outfile):
    deviceGroup = data
    with open(outfile, "w") as toWrite:
        for key, value in deviceGroup.items():
            #children section
            if "children" in value:
                toWrite.write("[" + key + ":children]\n")
                for child in value.get("children"):
                    toWrite.write(child + "\n")
                toWrite.write("\n")

            #host section
            if "host" in value:
                toWrite.write("[" + key + "]\n")
                for host in value.get("host"):
                    entry = host

                    if "ptf" in key:
                        try: #get ansible host
                            ansible_host = testbed.get(host).get("ansible").get("ansible_host")
                            entry += "\tansible_host=" + ansible_host.split("/")[0]
                        except:
                            print("\t\t" + host + ": ansible_host not found")

                        if ansible_host:
                            try: # get ansible ssh username
                                ansible_ssh_user = testbed.get(host.lower()).get("ansible").get("ansible_ssh_user")
                                entry += "\tansible_ssh_user=" + ansible_ssh_user
                            except:
                                print("\t\t" + host + ": ansible_ssh_user not found")

                            try: # get ansible ssh pass
                                ansible_ssh_pass = testbed.get(host.lower()).get("ansible").get("ansible_ssh_pass")
                                entry += "\tansible_ssh_pass=" + ansible_ssh_pass
                            except:
                                print("\t\t" + host + ": ansible_ssh_pass not found")
                    else: #not ptf container
                        try: #get ansible host
                            ansible_host = devices.get(host.lower()).get("ansible").get("ansible_host")
                            entry += "\tansible_host=" + ansible_host.split("/")[0]
                        except:
                            print("\t\t" + host + ": ansible_host not found")

                        if ansible_host:
                            try: # get ansible ssh username
                                ansible_ssh_user = devices.get(host.lower()).get("ansible").get("ansible_ssh_user")
                                entry += "\tansible_ssh_user=" + ansible_ssh_user
                            except:
                                print("\t\t" + host + ": ansible_ssh_user not found")

                            try: # get ansible ssh pass
                                ansible_ssh_pass = devices.get(host.lower()).get("ansible").get("ansible_ssh_pass")
                                entry += "\tansible_ssh_pass=" + ansible_ssh_pass
                            except:
                                print("\t\t" + host + ": ansible_ssh_pass not found")

                    toWrite.write(entry + "\n")
                toWrite.write("\n")

            #vars section
            if "vars" in value:
                toWrite.write("[" + key + ":vars]\n")
                for key2, val2 in value.get("vars").items():
                    if isinstance(val2, list) or isinstance(val2, dict):
                        toWrite.write(key2 + "=[" + ', '.join(val2) + "]\n")
                    else:
                        toWrite.write(key2 + "=" + val2 + "\n")
                toWrite.write("\n")

"""
makeVeos(data, veos, devices, outfile)
@:parameter data - reads from either veos-groups, this helps separate the function into 3 components; children, host, vars
@:parameter veos - reads from either veos
@:parameter devices - reads from devices
@:parameter outfile - writes to veos
"""
def makeVeos(data, veos, devices, outfile):
    group = data
    with open(outfile, "w") as toWrite:
        for key, value in group.items():
            # children section
            if "children" in value:
                toWrite.write("[" + key + ":children]\n")
                for child in value.get("children"):
                    toWrite.write(child + "\n")
                toWrite.write("\n")

            # host section
            if "host" in value:
                toWrite.write("[" + key + "]\n")
                for host in value.get("host"):
                    entry = host

                    try:
                        ansible_host = devices.get(host.lower()).get("ansible").get("ansible_host")
                        entry += "\tansible_host=" + ansible_host.split("/")[0]
                    except:
                        try:
                            ansible_host = veos.get(key).get(host).get("ansible_host")
                            entry += "\tansible_host=" + ansible_host.split("/")[0]
                        except:
                            print("\t\t" + host + ": ansible_host not found")
                    toWrite.write(entry + "\n")

                toWrite.write("\n")

            #var section
            if "vars" in value:
                toWrite.write("[" + key + ":vars]\n")
                for key2, val2 in value.get("vars").items():
                    if isinstance(val2, list) or isinstance(val2, dict):
                        toWrite.write(key2 + "=[" + ', '.join(val2) + "]\n")
                    else:
                        toWrite.write(key2 + "=" + val2 + "\n")
                toWrite.write("\n")


"""
makeHost_var(data)
@:parameter data - reads from host_vars dictionary
Creates host variable files for each device
"""
def makeHostVar(data):
    host_vars = data
    for key, value in host_vars.items():  # iterate through all devices in host_vars dictionary
        with open(args.basedir + "host_vars/" + key.upper() + ".yml", "w") as toWrite:  # create (or overwrite) a file named <device>.yml
            for attribute, attribute_data in value.items():  # for each element in device's dictionary
                toWrite.write(str(attribute) + ": " + str(attribute_data) + "\n")  # write the attribute and the attribute value to <device>.yml

"""
updateDockerRegistry
@:parameter outfile - the file to write to
hard codes the docker registry to search locally rather than externally
"""
def updateDockerRegistry(docker_registry, outfile):
    if (not docker_registry.get("docker_registry_host")) or (not docker_registry.get("docker_registry_username")) or (not docker_registry.get("docker_registry_password")):
        print("\t\tREGISTRY FIELD BLANK - SKIPPING THIS STEP")
    else:
        with open(outfile, "w") as toWrite:
            toWrite.write("docker_registry_host: " + docker_registry.get("docker_registry_host"))
            toWrite.write("\n\n")
            toWrite.write("docker_registry_username: " + docker_registry.get("docker_registry_username") + "\n")
            toWrite.write("docker_registry_password: root" + docker_registry.get("docker_registry_password"))


def main():
    print("PROCESS STARTED")
    ##############################################################
    print("BACKUP PROCESS STARTED") # Backup data
    for file in backupList:
        try:
            copyfile(args.basedir + file, args.backupdir + "/" + timestamp + "/" + file)
        except IOError:  # filenotfound
            print("Error: could not back up " + args.basedir + file)

    host_var_files = os.listdir(args.basedir + "host_vars")
    for file_name in host_var_files:
        copyfile(args.basedir + "host_vars/" + file_name,
                 args.backupdir + "/" + timestamp + "/host_vars/" + file_name)

    print("BACKUP PROCESS COMPLETED")

    ##############################################################
    # Load Data
    print("LOADING PROCESS STARTED")
    print("LOADING: " + args.i)
    doc = yaml.load(open(args.i, 'r'))
    devices = dict()                                        # dictionary contains information about devices
    generateDictionary(doc, devices, "devices")             # load devices
    veos = dict()                                           # dictionary contains information about veos
    generateDictionary(doc, veos, "veos")                   # load veos
    testbed = dict()                                        # dictionary contains information about testbed (ptf)
    generateDictionary(doc, testbed, "testbed")             # load testbed
    topology = dict()                                       # dictionary contains information about toplogy
    generateDictionary(doc, topology, "topology")           # load topology
    host_vars = dict()                                      # dictionary contains information about host_vars
    generateDictionary(doc, host_vars, "host_vars")         # load host_vars
    veos_groups = dict()                                    # dictionary contains information about veos_groups
    generateDictionary(doc, veos_groups, "veos_groups")     # load veos_groups
    device_groups = dict()                                  # dictionary contains information about device_groups
    generateDictionary(doc, device_groups, "device_groups") # load device_groups
    docker_registry = dict()                                # dictionary contains information about docker_registry
    generateDictionary(doc, docker_registry, "docker_registry") #load docker_registry
    print("LOADING PROCESS COMPLETED")

    ##############################################################
    # Generate files
    print("GENERATING FILES FROM CONFIG FILE")
    print("\tCREATING SONIC LAB LINKS: " + args.basedir + labLinks_file)
    makeSonicLabLinks(topology, args.basedir + labLinks_file)  # Generate sonic_lab_links.csv (TOPOLOGY)
    print("\tCREATING SONIC LAB DEVICES: " + args.basedir + devices_file)
    makeSonicLabDevices(devices, args.basedir + devices_file)  # Generate sonic_lab_devices.csv (DEVICES)
    print("\tCREATING TEST BED: " + args.basedir + testbed_file)
    makeTestbed(testbed, args.basedir + testbed_file)  # Generate testbed.csv (TESTBED)
    print("\tCREATING VM_HOST/CREDS: " + args.basedir + vmHostCreds_file)
    makeVMHostCreds(veos, args.basedir + vmHostCreds_file)  # Generate vm_host\creds.yml (CREDS)
    print("\tCREATING EOS/CREDS: " + args.basedir + eosCred_file)
    makeEOSCreds(veos, args.basedir + eosCred_file)  # Generate eos\creds.yml (CREDS)
    print("\tCREATING FANOUT/SECRETS: " + args.basedir + fanoutSecrets_file)
    makeFanoutSecrets(devices, args.basedir + fanoutSecrets_file)  # Generate fanout\secrets.yml (SECRETS)
    print("\tCREATING LAB SECRETS: " + args.basedir + labSecrets_file)
    makeLabSecrets(devices, args.basedir + labSecrets_file)  # Generate lab\secrets.yml (SECRETS)
    print("\tCREATING MAIN.YML: " + args.basedir + main_file)
    makeMain(veos, args.basedir + main_file)  # Generate main.yml (MAIN)
    print("\tCREATING LAB FILE: " + args.basedir + lab_file)
    makeLab(device_groups, devices, testbed, args.basedir + lab_file)  # Generate lab (LAB)
    print("\tCREATING VEOS FILE: " + args.basedir + veos_file)
    makeVeos(veos_groups, veos, devices, args.basedir + veos_file)  # Generate veos (VEOS)
    print("\tCREATING HOST VARS FILE(S): one or more files generated")
    makeHostVar(host_vars)  # Generate host_vars (HOST_VARS)
    print("UPDATING FILES FROM CONFIG FILE")
    print("\tUPDATING DOCKER REGISTRY")
    updateDockerRegistry(docker_registry, args.basedir + dockerRegistry_file)
    print("PROCESS COMPLETED")


if __name__ == '__main__':
    main()

