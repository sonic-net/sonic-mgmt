#!/usr/bin/env python

import os
import shutil
import sys
import yaml
import datetime
import paramiko
import smtplib
from email.mime.text import MIMEText
from scp import SCPClient

# This script will create archive and than upload it to webserver for redis consumption

def post_runtest(output_dir, build_dir, user, test_res, server_name):

    # web server details for scping the files
    srv1_ip = '152.148.160.21'
    srv1_user = 'minion'
    cur_time = datetime.datetime.now()

    # variable to create new directory based on current date time
    new_dir = "{}.{}".format(cur_time.strftime("%Y/%m/%d/%H%M"), user)
    base_dir= output_dir
    path_temp = os.path.normpath(os.path.join(base_dir,'../'))
    path_1 = os.path.join(path_temp,new_dir)

    # create variables to get current time and name for archive to be created
    arch_time = "{}.{}".format(cur_time.strftime("%d%H%M"),user)
    arch_name = os.path.join(path_1, arch_time)

    # version txt full path
    ver_file_path = os.path.join(build_dir,'version.txt')
    ver_file = build_dir + "/version.txt"

    # read the git branch info from version file, if does not exist ignore
    if os.path.exists(ver_file):
        f2 = open(ver_file, "r")
        ver_data = f2.read()
        f2.close()
    else:
        ver_data = "999999-0"

    #read args file
    args_file = output_dir + "/args"
    file2 = open(args_file, 'r')
    args_data = file2.read()
    file2.close()

    # generate email.txt
    email_file = output_dir + "/email.txt"
    url = "http://{}/results/{}/".format(srv1_ip,new_dir)

    f = open(email_file, 'w')
    f.write("TESTBED: {} \n".format(server_name))
    f.write("Regression test job: {}\n".format(new_dir))
    f.write("Version: {}\n\n\n".format(ver_data))
    f.write("complete details can be found at our {}\n".format(url))
    f.write("\t - Also at - \n")
    f.write("our base {}results.html\n\n".format(url))
    f.write("EXIT REASON\n")
    f.write("-"*11 +"\n")
    f.write("\tnormalExit, test case failures\n\n")
    f.write("FAILURE REASONS\n")
    f.write("-"*15 + "\n")
    f.write("\tOne or more test items had Test Non-severe Errors\n\n")
    f.write("FAILED SUITES\n")
    f.write("-" * 13 + "\n\n")
    f.write("FAILED TESTS - TEST Non-Severe Errors\n")
    f.write("-" * 37 + "\n\n")
    f.write("ARGS\n")
    f.write("-"*4 + "\n")
    f.write("{}".format(args_data))
    f.close()

    # create directory  and copy files for tar ball
    shutil.copytree(output_dir, path_1)

    # check if version.txt file exists
    if os.path.exists(ver_file_path):
        shutil.copy2(ver_file_path, path_1)
    shutil.make_archive(arch_name, 'gztar', path_temp, new_dir)
    src_file = arch_name + '.tar.gz'
    dst_file = '/var/www/html/results/' + arch_time + '.tar.gz'

    # scp the files to webserver folder
    file_path_pkey = build_dir + '/src/sonic-mgmt/tests/nokia/scripts/id_rsa_results_server'
    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    key1 = paramiko.RSAKey.from_private_key_file(file_path_pkey)
    ssh.connect(hostname=srv1_ip,
                username=srv1_user,
                pkey=key1)

    scp = SCPClient(ssh.get_transport())

    scp.put(src_file, dst_file)

    # derive test results
    test_res = int(test_res)
    if test_res != 0:
        res_fl = 'Failed'
    if test_res == 0:
        res_fl = 'Passed'

    # #send email out
    # port = 25
    # #for now sending to qa  only
    # receiver_list = ["amol.rawal@nokia.com",
    #                  "regressiondb@princess.sh.bel.alcatel.be",
    #                  "shuba.viswanathan@nokia.com",
    #                  "sandeep.malhotra@nokia.com",
    #                  "renu.falodiya@nokia.com",
    #                  "thomas.custodio@nokia.com"]
    # sender_email = "noreply@sonic-minion1.ipd.us.alcatel-lucent.com"
    # # Note: Subject should have the keyword Sonic. Otherwise, rdb parsing will fail
    # sub_summ = "REGRESS: {}: {} - SITE:Westford - SONiC {} {}".format(server_name, res_fl, ver_data, args_data)
    #
    # file_email = open(email_file, 'r')
    # message            = MIMEText(file_email.read())
    # message['Subject'] = sub_summ
    # message['To']      = ', '.join(receiver_list)
    #
    # server = smtplib.SMTP(srv1_ip, port)
    #
    # try:
    #     server.sendmail(sender_email, receiver_list, message.as_string())
    # except:
    #     smtplib.SMTPException()
    # server.quit()

    # delete the local folder
    shutil.rmtree(os.path.join(path_temp,format(cur_time.strftime("%Y"))))

# Generate args file - need version.txt
def pre_runtest(output_dir, build_dir, topology, subtopo):

    args_file = output_dir + "/args"
    ver_file = build_dir + "/version.txt"
    
    # read the git branch info from version file, if does not exist ignore
    if os.path.exists(ver_file):
       f2 = open(ver_file, "r")
       line = f2.readline()
       gitb = line.split('-')
       gitbrnch = gitb[0]
       f2.close()
    else:
        gitbrnch = "999999"

    # create args file and write info
    f = open(args_file, "w")
    f.write("-reason 'test'  ")
    f.write("-scm git  ")
    f.write("-subTopology {}  ".format(subtopo))
    f.write("-physTopology {}  ".format(topology))
    f.write("-git_tag {}  ".format(gitbrnch))
    f.write("-emailMode db")
    f.close()


def main(output_dir, build_dir, user, notify, **kwargs):
    stage = 'prerun'
    if 'stage' in kwargs:
        stage = kwargs['stage']
    if 'topology' in kwargs:
        topology = kwargs['topology']
    if 'notify' in kwargs:
        topology = kwargs['notify']
    if 'test_res' in kwargs:
        test_res = kwargs['test_res']
    if 'subtopo' in kwargs:
        subtopo = kwargs['subtopo']
    if 'server_name' in kwargs:
        server_name = kwargs['server_name']
    # get list of recipients
    notify_lst = notify.split(',')

    '''
       for loop to call post and pre for case when it is called by db in future 
       we will add support for multiple recipients
    '''
    for n in notify_lst:
        if n == "db":
           # Call function depending on stage the script was called at
           if stage == 'prerun':
              pre_runtest(output_dir, build_dir, topology, subtopo)
           if stage == 'postrun':
              post_runtest(output_dir, build_dir, user, test_res, server_name)
        if n == None:
           print("skipping sending results to regressdb")
           sys.exit(0)

if __name__ == '__main__':
    if len(sys.argv) < 4:
        raise SyntaxError("insufficient args")

    main(sys.argv[1], sys.argv[2], sys.argv[3], **dict(arg.split('=') for arg in sys.argv[4:]) )
