import pexpect
import sys

copy_direction = sys.argv[1] 
ip = sys.argv[2]
source_path = sys.argv[3]
dest_path = sys.argv[4]
user = sys.argv[5]
password = sys.argv[6]

command = ""
if copy_direction == "in":
    command = "scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {}@{}:{} {}".format(user, ip, source_path, dest_path)
else:
    command = "scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {} {}@{}:{}".format(source_path, user, ip, dest_path)


try:
    child = pexpect.spawn(command)
    prompt = child.expect(["password:"])

    child.sendline(password)
    while True:
        pxres = child.expect(['scp_progress_output_that_changes', pexpect.EOF, pexpect.TIMEOUT], timeout=4000)
        if pxres==0:
            continue
        else:
            break
except Exception as e:
    print("scp potentially failed with message: " + str(e))

