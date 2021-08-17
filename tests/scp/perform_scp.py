import pexpect
import sys

is_source_ip = sys.argv[1] 
ip = sys.argv[2]
source_path = sys.argv[3]
dest_path = sys.argv[4]
user = sys.argv[5]

command = ""
if is_source_ip == "y":
    command = "scp {}@{}:{} {}".format(user, ip, source_path, dest_path)
else:
    command = "scp {} {}@{}:{}".format(source_path, user, ip, dest_path)


try:
    #child = pexpect.spawn("scp root@10.250.0.102:/root/test_file.bin /home/admin")
    child = pexpect.spawn(command)
    prompt = child.expect(["Are you sure you want to continue connecting (yes/no)?", "password:"])

    if prompt == 0:
        child.sendline("yes")
        child.expect("password")

    child.sendline("root")
    while True:
        pxres = child.expect(['scp_progress_output_that_changes', pexpect.EOF, pexpect.TIMEOUT], timeout=2000)
        if pxres==0:
            continue
        else:
            break
except Exception as e:
    print("scp potentially failed with message: " + str(e))

