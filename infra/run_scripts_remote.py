import datetime
import paramiko
import time
import os
import re
import argparse
import sys
import json

# VXR sim failed
def handle_sim_failure(error_msg):
    SUMMARY_REPORT_FILENAME = "results.json"
    COMMON_REPORT_FILENAME = "sonic-whitebox-common.report"

    SUMMARY_REPORT_PATH = "../../{}".format(SUMMARY_REPORT_FILENAME)
    COMMON_REPORT_PATH = "../../{}".format(COMMON_REPORT_FILENAME)

    # Include sim_status field to indicate failure
    sum = {"total": 0, "failed": 0, "passed": 0, "skipped": 0, "success_rate": 0.0, "status" : error_msg}

    for file_path in [SUMMARY_REPORT_PATH, COMMON_REPORT_PATH]:
        with open(file_path, "w") as output_file:
            json.dump(sum, output_file)

def upload_sanity_file(host, username, password, script_file, sonic_test_dir, ssh_port=22):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print("connect", (host, ssh_port, username, password))
    ssh.connect(host, ssh_port, username, password)
    print("connected")
    ftp_client=ssh.open_sftp()
    uploaded_script_files = []
    for script_file_path in script_file.split(","):
        script_filename = script_file_path.rsplit('/', 1)[-1]
        ftp_client.put(script_file_path,'{}/sonic-test/sonic-mgmt/tests/{}'.format(sonic_test_dir, script_filename))
        uploaded_script_files.append(script_filename)
    ftp_client.close()

    return uploaded_script_files

def get_build_project_name():
    if os.getenv("MODE"):
        sanity_mode = os.getenv("MODE").replace("_", "")
    elif os.getenv("SANITY_MODE"):
        sanity_mode = os.getenv("SANITY_MODE").replace("_", "")
    else:
        sanity_mode = ""

    sanity_index = os.getenv("SANITY_INDEX")
    if os.getenv("JOB_BASE_NAME"):
        job_base_name = os.getenv("JOB_BASE_NAME").replace("_", "")
    else:
        job_base_name = ""
    if os.getenv("TIMESTAMP"):
        timestamp = re.sub(r'[^a-zA-Z0-9]', '', os.getenv("TIMESTAMP"))
    else:
        timestamp = ""
    
    build_id = os.getenv("BUILD_ID")
    if build_id is None:
        build_id = 99999

    if sanity_index:
        build_project_name = "sonic-{}-{}-{}-{}-{}".format(job_base_name, build_id, sanity_mode, sanity_index, timestamp)
    else:
        build_project_name = "sonic-{}-{}-{}-{}".format(job_base_name, build_id, sanity_mode, timestamp)

    build_project_name = build_project_name.lower()

    return build_project_name

def run_scripts(host, username, password, script_file,drop_version,log_dir,device_type,create_allure_report, additional_tests='', ssh_port=22, topo_name='docker-ptf', docker_mgmt_container='docker-sonic-mgmt'):
    print("starting run_scripts, params: ", host, username, password, script_file,drop_version,log_dir,device_type,create_allure_report, ssh_port, topo_name, docker_mgmt_container)
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, ssh_port, username, password)
    print("connected to host {}".format(host))
    chan = ssh.invoke_shell()
    resp = ''
    while ':~$' not in resp:
        resp = chan.recv(9999).decode("ascii")
        print(resp)
    time.sleep(3)

    print("Going into container '{}' to run tests".format(docker_mgmt_container))
    chan.send('docker exec -it {} /bin/bash \n'.format(docker_mgmt_container))
    resp = ''
    while ':~$' not in resp:
        resp = chan.recv(9999).decode("ascii")
        print(resp)
    time.sleep(3)

    chan.send('unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy \n')
    time.sleep(3)
    resp = chan.recv(9999)
    print(resp.decode("ascii"))

    chan.send('rm -f /tmp/allure_results/* \n')
    time.sleep(3)
    resp = chan.recv(9999)
    print(resp.decode("ascii"))

    chan.send('cd /data/tests \n')
    time.sleep(3)
    resp = chan.recv(9999)
    print(resp.decode("ascii"))

    build_project_name = get_build_project_name()

    print("calling run_scripts.py, the allure report build name is ", build_project_name)

    tstamp = datetime.datetime.now().strftime("%d-%b-%Y-%H:%M:%S.%f")
    result_file = "ongoing_result_{}_{}.csv".format(drop_version,tstamp)
    chan.send('rm run_script.log \n')
    time.sleep(3)
    chan.send('rm {} \n'.format(result_file))
    time.sleep(3)
    chan.send('rm -rf DT\n')
    time.sleep(3)
    resp = chan.recv(9999)
    print(resp.decode("ascii"))

    delta1 = datetime.datetime.now()

    additional_params = ""

    if create_allure_report:
        additional_params += " --create_allure_report "
    if additional_tests:
        additional_params += " --additional_tests={} ".format(additional_tests)


    print("Run command:")
    print('./run_scripts.py -s {} -v {} -l {} -d {} -t {} -g {} -b {} {} |& tee run_script.log &\n'.format(script_file,drop_version,log_dir,device_type,tstamp,topo_name,build_project_name, additional_params))

    chan.send('./run_scripts.py -s {} -v {} -l {} -d {} -t {} -g {} -b {} {} |& tee run_script.log &\n'.format(script_file,drop_version,log_dir,device_type,tstamp,topo_name,build_project_name, additional_params))
    
    time.sleep(3)
    resp = chan.recv(9999)

    chan.send('exit\n')
    time.sleep(10)

    chan.send('docker exec -it {} /bin/bash \n'.format(docker_mgmt_container))
    resp = ''
    while ':~$' not in resp:
        resp = chan.recv(9999).decode("ascii")
        print(resp)
    time.sleep(3)

    later = datetime.datetime.now() + datetime.timedelta(hours=30)
    while True:
        chan.send('ps -ef | grep run_scripts.py\n')
        time.sleep(3)
        resp = chan.recv(9999)
        print(resp.decode("ascii"))
        sys.stdout.flush()

        if script_file in resp.decode("ascii"):
            time.sleep(150)
            chan.send('cat /data/tests/{} \n'.format(result_file))
            time.sleep(3)
            resp = chan.recv(9999)
            print(resp.decode("ascii"))
            if datetime.datetime.now() < later:
                time.sleep(150)
            else:
                print("Looks like test is taking longer than 30 hours. Check list of sanity scripts or increase time to wait")
                break
        else:
            break
    
    chan.send('cat /data/tests/{} \n'.format(result_file))
    time.sleep(3)
    resp = chan.recv(9999)
    print(resp.decode("ascii"))
    if "Exiting" in resp.decode("ascii"):
        run_status = False
    else:
        run_status = True
    ssh.close()
    delta2 = datetime.datetime.now()
    time_delta = (delta2 - delta1)
    total_seconds = time_delta.total_seconds()
    minutes = total_seconds/60

    print("Total run time for sanity suite: {} mins".format(minutes))
    return run_status

def create_report_html(host, username, password, log_dir, sonic_test_dir, ssh_port=22):
    print("Creating report html on remote host {}. SSH port {}, username/password: {}/{}".format(host, ssh_port, username, password))
    print("running command: ")
    print('python3 ~/{}/sonic-test/sonic-mgmt/test_reporting/junit_xml_parser.py -o ~/{}/sonic-test/sonic-mgmt/tests/results.json \
        --directory ~/{}/sonic-test/sonic-mgmt/tests/{} > ~/{}/sonic-test/sonic-mgmt/tests/report.txt \n'.format(sonic_test_dir, sonic_test_dir, sonic_test_dir, log_dir, sonic_test_dir))
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, ssh_port, username, password)
    
    chan = ssh.invoke_shell()
    resp = ''
    while ':~$' not in resp:
        resp = chan.recv(9999).decode("ascii")
        print(resp)
    time.sleep(3)
    commands = []

    commands.append('python3 ~/golden-code/sonic-test/sonic-mgmt/test_reporting/junit_xml_parser.py -o ~/golden-code/sonic-test/sonic-mgmt/tests/results.json \
        --directory ~/golden-code/sonic-test/sonic-mgmt/tests/{} > ~/golden-code/sonic-test/sonic-mgmt/tests/report.txt \n'.format(log_dir))
    commands.append('junit2html ~/golden-code/sonic-test/sonic-mgmt/tests/{} --merge ~/golden-code/sonic-test/sonic-mgmt/tests/{}/test-results.xml\n'.format(log_dir, log_dir))
    commands.append('junit2html ~/golden-code/sonic-test/sonic-mgmt/tests/{}/test-results.xml --report-matrix ~/golden-code/sonic-test/sonic-mgmt/tests/report.html\n'.format(log_dir))
    commands.append('junit2html ~/golden-code/sonic-test/sonic-mgmt/tests/{}/test-results.xml --summary-matrix\n'.format(log_dir))
    i = 0
    while True:
        if len(commands) == i:
            break

        chan.send(commands[i])
        buff = ''
        while not buff.endswith(':~$ '):
            resp = chan.recv(9999)
            buff += resp.decode("ascii")
            print(resp.decode("ascii"))
        time.sleep(3)
        if chan.recv_ready():
            print(chan.recv(9999).decode("ascii"))
        i += 1

    ssh.close()


def parse_report(host, username, password, sonic_test_dir, ssh_port=22):
    print("Parsing report")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, ssh_port, username, password)
    ftp_client=ssh.open_sftp()
    ftp_client.get('{}/sonic-test/sonic-mgmt/tests/report.txt'.format(sonic_test_dir),'report.txt')
    ftp_client.close()
    ssh.close()

    read_report = open('report.txt', 'r')
    report_file = open('full_report.txt', 'w')
    out = read_report.read().splitlines()
    total, passed, fail, skip, error, xfail = 0, 0, 0, 0, 0, 0
    for line in out:
        print(line)
        if 'total' not in line.lower():
            continue
        report_file.write(line + "\n")
        report_file.flush()
        tc = line.split(',')
        if 'total' not in tc[1].lower():
            continue
        total += int(tc[1].strip(' ').split(' ')[0])
        passed += int(tc[2].strip(' ').split(' ')[0])
        fail += int(tc[3].strip(' ').split(' ')[0])
        skip += int(tc[4].strip(' ').split(' ')[0])
        error += int(tc[5].strip(' ').split(' ')[0])
        xfail += int(tc[6].strip(' ').split(' ')[0])
    resp = "Total TCs: {}, {} Pass, {} Fail, {} Skipped, {} Error, {} xFail\n".format(total,passed,fail,skip,error,xfail)
    report_file.write("=================================================================\n")
    print("=================================================================\n")
    print(resp)
    report_file.write(resp  + "\n")
    report_file.flush()
    report_file.close()
    return resp

def get_report_file(host, username, password, sonic_test_dir, ssh_port=22):
    print("Getting report file")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, ssh_port, username, password)
    ftp_client=ssh.open_sftp()
    #ftp_client.get('{}/sonic-test/sonic-mgmt/tests/full_report.txt','full_report.txt')
    ftp_client.get('{}/sonic-test/sonic-mgmt/tests/test-results.xml.html'.format(sonic_test_dir),'test-results.xml.html')
    ftp_client.get('{}/sonic-test/sonic-mgmt/tests/report.html'.format(sonic_test_dir),'report.html')
    ftp_client.close() 


def get_log_files(host, username, password, log_dir, sonic_test_dir, ssh_port=22):
    print("Get log files")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, ssh_port, username, password)
    chan = ssh.invoke_shell()
    time.sleep(3)
    chan.send("cd {}/sonic-test/sonic-mgmt/tests/{} \n".format(sonic_test_dir,log_dir))
    resp = ''
    while ':~/{}/sonic-test/sonic-mgmt/tests/{}$ '.format(sonic_test_dir,log_dir) not in resp:
        resp = chan.recv(9999).decode("ascii")
        print(resp)
    time.sleep(3)

    chan.send("tar -cvf sanity_logs.tar * \n")
    resp = ''
    while ':~/{}/sonic-test/sonic-mgmt/tests/{}$ '.format(sonic_test_dir, log_dir) not in resp:
        resp = chan.recv(9999).decode("ascii")
        print(resp)
    time.sleep(3)

    chan.send("gzip -f sanity_logs.tar \n")
    resp = ''
    while ':~/{}/sonic-test/sonic-mgmt/tests/{}$ '.format(sonic_test_dir, log_dir) not in resp:
        resp = chan.recv(9999).decode("ascii")
        print(resp)
    time.sleep(3)

    ftp_client=ssh.open_sftp()
    ftp_client.get('{}/sonic-test/sonic-mgmt/tests/{}/sanity_logs.tar.gz'.format(sonic_test_dir, log_dir),'sanity_logs.tar.gz')
    ftp_client.close() 
    ssh.close()

def run_scripts_remote(host, username, password, script_file,drop_version,log_dir,device_type,create_allure_report, ssh_port=22, topo_name='docker-ptf', additional_tests='', sonic_test_dir='golden-code', docker_mgmt_container='docker-sonic-mgmt'):
    sanity_start_time = datetime.datetime.now()
    print("Running scripts remotely on host {}. SSH port {}, username/password: {}/{}".format(host, ssh_port, username, password))
    print("Device type: {}, topo_name: {}".format(device_type, topo_name))
    print("Script file: {}, drop version: {}, log_dir {}, sonic-test directory: {}, docker-mgmt container name: '{}', create-allure-report: {}".format(script_file, drop_version, log_dir, sonic_test_dir, docker_mgmt_container, create_allure_report))
    print("Upload Sanity Script file")

    print("determine sonic_test_dir from docker_mgmt_container name")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, ssh_port, username, password)
    print("connected to host {}".format(host))

    cmd = f'docker inspect `docker ps -aqf name={docker_mgmt_container}` | grep sonic-test | head -1\n'

    stdin, stdout, stderr = ssh.exec_command(cmd)
    stdout.channel.recv_exit_status()
    out = stdout.read().decode("ascii").strip()

    print(f"resp for docker inspect is {out}")

    tmp_sonic_test_dir = ""
    for s in out.split("/"):
        if s == "sonic-test":
            break
        tmp_sonic_test_dir = s
    

    sys.stdout.flush()

    
    print("sonic-test dir is: ", tmp_sonic_test_dir)
    sonic_test_dir = tmp_sonic_test_dir


    uploaded_script_files = upload_sanity_file(host, username, password, script_file, sonic_test_dir, ssh_port)
    uploaded_script_files_str = ",".join(uploaded_script_files)

    print("Running Sanity Scripts : '{}', additional tests: '{}'".format(uploaded_script_files_str, additional_tests))
    run_result = run_scripts(host, username, password, uploaded_script_files_str,drop_version,log_dir,device_type,create_allure_report, additional_tests, ssh_port, topo_name, docker_mgmt_container)
    sanity_end_time = datetime.datetime.now()


    if not run_result:
        log_dir = 'logs'
        handle_sim_failure("bgp_failure")

    create_report_html(host, username, password, log_dir, sonic_test_dir, ssh_port)
    parse_report(host, username, password, sonic_test_dir, ssh_port)
    get_report_file(host, username, password, sonic_test_dir, ssh_port)
    get_log_files(host, username, password, log_dir, sonic_test_dir, ssh_port)
    # else:
    #     report_file = open('full_report.txt', 'w')
    #     report_file.write("Tried 3 times and BGP Fact testcase is still failing. No point continuing with the tests. There seems to be some issue with the sim setup. Exiting now")
    #     report_file.flush()
    #     report_file.close()
    #     print("Tried 3 times and BGP Fact testcase is still failing. No point continuing with the tests. There seems to be some issue with the sim setup. Exiting now")

    sanity_time_delta = (sanity_end_time - sanity_start_time).total_seconds()
    print("Time taken for the sanity tests to run : {} mins".format(sanity_time_delta/60))
    if not run_result:
        print("Sanity run unsuccesful !!!, Check log files for more details")
    
def _create_parser():
    parser = argparse.ArgumentParser(description='Reading ports file.')
    parser.add_argument('-a', '--host_address', type=str, help='host address to ssh into',
                      required=True,default=None)
    parser.add_argument('-r', '--ssh_port', type=str, help='port_used for ssh',
                      required=False,default=22)
    parser.add_argument('-u', '--username', type=str, help='username for ssh',
                      required=True,default=None)
    parser.add_argument('-p', '--password', type=str, help='ssh password',
                      required=True,default=None)
    parser.add_argument('-g', '--topo_name', type=str, help='Topo name specified to run tests',
                      required=False,default='docker-ptf')
    parser.add_argument('-v', '--drop_version', type=str, help='specify drop version',
                      required=False,default='DT')
    parser.add_argument('-l', '--log_dir', type=str, help='Log dir',
                      required=False,default='DT')
    parser.add_argument('-s', '--script_file', type=str, help='Input test script file',
                      required=False,default='sanity-scripts/sanity_scripts.txt')
    parser.add_argument('-d', '--device_type', type=str, help='options are sherman, mth32, crocodile, sfd',
                      required=False,default="mth64", choices=['sherman', 'mth32', 'mth64', 'crocodile', 'sfd', 'm64-zz-2', 'mth-t0-64', 'dut-400g'])
    parser.add_argument('-c', '--docker_mgmt_container', type=str, help='name of the docker management container',
                      required=False,default='docker-sonic-mgmt')
    parser.add_argument('-t', '--sonic_test_dir', type=str, help='Directory of sonic-test on DUT',
                      required=False, default='golden-code')
    parser.add_argument('--create_allure_report', action='store_true', help='When testing, specify if allure report to be created at the end of test',
                      default=False)           
    parser.add_argument('--additional_tests', type=str, help='Additional Testscases to test',
                      required=False, default='')
    return parser


if __name__ == '__main__':
    parser = _create_parser()
                      
    args = vars(parser.parse_args())
    host_address = args['host_address']
    ssh_port = args['ssh_port']
    username = args['username']
    password = args['password']
    topo_name = args['topo_name']
    drop_version = args['drop_version']
    log_dir = args['log_dir']
    script_file = args['script_file']
    device_type = args['device_type']
    docker_mgmt_container = args['docker_mgmt_container']
    sonic_test_dir = args['sonic_test_dir']
    create_allure_report = args['create_allure_report']
    additional_tests = args['additional_tests']

    run_scripts_remote(
        host_address, 
        username, 
        password,  
        script_file,
        drop_version,
        log_dir,
        device_type,
        create_allure_report, 
        ssh_port,
        topo_name,
        additional_tests,
        sonic_test_dir,
        docker_mgmt_container,
    )
