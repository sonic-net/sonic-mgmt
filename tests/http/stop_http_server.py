import subprocess
import os

# Get list of python processes
output = subprocess.check_output(["ps", "-ef"])
output = output.split("\n")

# Find process that is running the http server and kill it
for line in output:
    if "tmp/start_http_server.py" in line:
        pid = line.split()[1]
        os.system("kill {}".format(pid))