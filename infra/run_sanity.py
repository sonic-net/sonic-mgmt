import datetime
import paramiko
import time
import os
import re

def upload_sanity_file(data,script_file):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(data['sonic_mgmt']['HostAgent'], data['sonic_mgmt']['xr_redir22'], "vxr", "cisco123")
    ftp_client=ssh.open_sftp()
    ftp_client.put(script_file,'golden-code/sonic-test/sonic-mgmt/tests/{}'.format(script_file.rsplit('/', 1)[-1]))
    ftp_client.close()

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

def run_scripts(data,script_file,drop_version,log_dir,device_type,create_allure_report):

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(data['sonic_mgmt']['HostAgent'], data['sonic_mgmt']['xr_redir22'], "vxr", "cisco123")
    chan = ssh.invoke_shell()
    buff = ''
    while not buff.endswith(':~$ '):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))
    time.sleep(3)

    chan.send('docker exec -it docker-sonic-mgmt /bin/bash \n')
    buff = ''
    while not buff.endswith(':~$ '):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))
    time.sleep(3)

    chan.send('unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy \n')
    time.sleep(3)
    resp = chan.recv(9999)
    print(resp.decode("ascii"))

    chan.send('cd /data/tests \n')
    time.sleep(3)
    resp = chan.recv(9999)
    print(resp.decode("ascii"))

    build_project_name = get_build_project_name()

    print("calling run_scripts.py, the allure report build name is ", build_project_name)

    delta1 = datetime.datetime.now()
    tstamp = datetime.datetime.now().strftime("%d-%b-%Y-%H:%M:%S.%f")
    if create_allure_report:
        chan.send('./run_scripts.py  -s {} -v {} -l {} -d {} -t {} -b {} --create_allure_report |& tee run_script.log &\n'.format(script_file,drop_version,log_dir,device_type,tstamp,build_project_name))
    else:
        chan.send('./run_scripts.py  -s {} -v {} -l {} -d {} -t {} |& tee run_script.log &\n'.format(script_file,drop_version,log_dir,device_type,tstamp))
    time.sleep(3)
    resp = chan.recv(9999)

    chan.send('exit\n')
    time.sleep(10)

    chan.send('docker exec -it docker-sonic-mgmt /bin/bash \n')
    buff = ''
    while not buff.endswith(':~$ '):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))
    time.sleep(3)

    result_file = "ongoing_result_{}_{}.csv".format(drop_version,tstamp)
    later = datetime.datetime.now() + datetime.timedelta(hours=20)
    while True:
        chan.send('ps -ef | grep run_scripts.py\n')
        time.sleep(3)
        resp = chan.recv(9999)
        print(resp.decode("ascii"))

        if script_file in resp.decode("ascii"):
            time.sleep(150)
            chan.send('cat /data/tests/{} \n'.format(result_file))
            time.sleep(3)
            resp = chan.recv(9999)
            print(resp.decode("ascii"))
            if datetime.datetime.now() < later:
                time.sleep(150)
            else:
                print("Looks like test is taking longer than six hours. Check list of sanity scripts or increase time to wait")
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

def create_report_html(data,log_dir):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(data['sonic_mgmt']['HostAgent'], data['sonic_mgmt']['xr_redir22'], "vxr", "cisco123")
    
    chan = ssh.invoke_shell()
    buff = ''
    while not buff.endswith(':~$ '):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))
    time.sleep(3)

    chan.send('python3 ~/golden-code/sonic-test/sonic-mgmt/test_reporting/junit_xml_parser.py -o ~/golden-code/sonic-test/sonic-mgmt/tests/results.json \
        --directory ~/golden-code/sonic-test/sonic-mgmt/tests/{} > ~/golden-code/sonic-test/sonic-mgmt/tests/report.txt \n'.format(log_dir))
    time.sleep(3)
    
    chan.send('junit2html ~/golden-code/sonic-test/sonic-mgmt/tests/{} --merge ~/golden-code/sonic-test/sonic-mgmt/tests/DT/test-results.xml\n'.format(log_dir))
    time.sleep(3)

    chan.send('junit2html ~/golden-code/sonic-test/sonic-mgmt/tests/{}/test-results.xml --report-matrix ~/golden-code/sonic-test/sonic-mgmt/tests/report.html\n'.format(log_dir))
    time.sleep(3)

    chan.send('junit2html ~/golden-code/sonic-test/sonic-mgmt/tests/{}/test-results.xml --summary-matrix\n'.format(log_dir))
    time.sleep(3)

    ssh.close()


def parse_report(data):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(data['sonic_mgmt']['HostAgent'], data['sonic_mgmt']['xr_redir22'], "vxr", "cisco123")
    ftp_client=ssh.open_sftp()
    ftp_client.get('golden-code/sonic-test/sonic-mgmt/tests/report.txt','report.txt')
    ftp_client.close()
    ssh.close()

    read_report = open('report.txt', 'r')
    report_file = open('full_report.txt', 'w')
    out = read_report.read().splitlines()
    total, passed, fail, skip, error, xfail = 0, 0, 0, 0, 0, 0
    for line in out:
        if 'total' not in line.lower():
            continue
        print(line)
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

def get_report_file(data):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(data['sonic_mgmt']['HostAgent'], data['sonic_mgmt']['xr_redir22'], "vxr", "cisco123")
    ftp_client=ssh.open_sftp()
    #ftp_client.get('golden-code/sonic-test/sonic-mgmt/tests/full_report.txt','full_report.txt')
    ftp_client.get('golden-code/sonic-test/sonic-mgmt/tests/test-results.xml.html','test-results.xml.html')
    ftp_client.get('golden-code/sonic-test/sonic-mgmt/tests/report.html','report.html')
    ftp_client.close() 


def get_log_files(data,log_dir):

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(data['sonic_mgmt']['HostAgent'], data['sonic_mgmt']['xr_redir22'], "vxr", "cisco123")
    chan = ssh.invoke_shell()
    buff = ''
    while not buff.endswith(':~$ '):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))
    time.sleep(3)

    chan.send("cd golden-code/sonic-test/sonic-mgmt/tests/{} \n".format(log_dir))
    while not buff.endswith(':~/golden-code/sonic-test/sonic-mgmt/tests/{}$ '.format(log_dir)):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))
    time.sleep(3)

    chan.send("tar -cvf sanity_logs.tar * \n")
    while not buff.endswith(':~/golden-code/sonic-test/sonic-mgmt/tests/{}$ '.format(log_dir)):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))
    time.sleep(3)

    chan.send("gzip sanity_logs.tar \n")
    while not buff.endswith(':~/golden-code/sonic-test/sonic-mgmt/tests/{}$ '.format(log_dir)):
        resp = chan.recv(9999)
        buff += resp.decode("ascii")
        print(resp.decode("ascii"))
    time.sleep(3)

    ftp_client=ssh.open_sftp()
    ftp_client.get('golden-code/sonic-test/sonic-mgmt/tests/{}/sanity_logs.tar.gz'.format(log_dir),'sanity_logs.tar.gz')
    ftp_client.close() 
    ssh.close()

def run_sanity(data,script_file,drop_version,log_dir,device_type,create_allure_report):
    sanity_start_time = datetime.datetime.now()
    print("Upload Sanity Script file")
    upload_sanity_file(data,script_file)
    print("Running Sanity Scripts : {}".format(script_file.rsplit('/', 1)[-1]))
    run_result = run_scripts(data,script_file.rsplit('/', 1)[-1],drop_version,log_dir,device_type,create_allure_report)
    sanity_end_time = datetime.datetime.now()
    if run_result:
        create_report_html(data,log_dir)
        parse_report(data)
        get_report_file(data)
        get_log_files(data,log_dir)
    else:
        report_file = open('full_report.txt', 'w')
        report_file.write("Tried 3 times and BGP Fact testcase is still failing. No point continuing with the tests. There seems to be some issue with the sim setup. Exiting now")
        report_file.flush()
        report_file.close()
        print("Tried 3 times and BGP Fact testcase is still failing. No point continuing with the tests. There seems to be some issue with the sim setup. Exiting now")

    sanity_time_delta = (sanity_end_time - sanity_start_time).total_seconds()
    print("Time taken for the sanity tests to run : {} mins".format(sanity_time_delta/60))
    if not run_result:
        print("Sanity run unsuccesful !!!, Check log files for more details")