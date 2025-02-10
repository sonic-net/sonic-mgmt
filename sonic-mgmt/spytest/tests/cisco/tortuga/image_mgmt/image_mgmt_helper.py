
import os
import subprocess
import paramiko
import time
import re
import sys
import datetime

# A class to help provide is simple helper routines for img mgmt tests
class ImgMgmtTestHelper:
    # all the locations we want to test mutability.
    # these locations should not retain the file after
    # a reload
    TestFiles = ["/root_immutability_test_file",
                 "/etc/etc_immutability_test",
                 "/usr/usr_immutability_test"]

    # initialize all the testbed variables
    def __init__(self, ip, port, uname, pw, img_path):
        self.ip = ip
        self.port = port
        self.uname = uname
        self.pw = pw
        self.img_path = img_path

    # figure out uptime of the router
    def uptime(self, client):
        stdin, stdout, stderr = client.exec_command("uptime -p")
        uptime_string = stdout.read().decode().strip()
        self.log("uptime on router: " + uptime_string)

        # Define a pattern to extract days, hours, and minutes
        # The pattern is adjusted to match the "up" prefix and both singular and plural forms
        pattern = re.compile(r'up\s+((?:(\d+)\s+day(?:s)?,?\s*)?(?:(\d+)\s+hour(?:s)?,?\s*)?(?:(\d+)\s+minute(?:s)?)?)')
        match = pattern.search(uptime_string)

        if not match:
            return 0  # Return 0 if no match is found

        # Extract days, hours, and minutes from the match, defaulting to '0' if not found
        days, hours, minutes = match.groups()[1:]  # Skip the first group which is the entire match
        days = days or '0'
        hours = hours or '0'
        minutes = minutes or '0'

        # Convert days, hours, and minutes to seconds
        total_seconds = int(days) * 86400 + int(hours) * 3600 + int(minutes) * 60

        return total_seconds

    # create the files for test
    def create_files_for_test(self):
        for f in self.TestFiles:
            self.exec_cmd("sudo -s touch " + f)

    # check if all files for immutable FS exist, if not return false
    def do_files_exist(self):
        for f in self.TestFiles:
            _, _, err = self.exec_cmd("ls " + f)
            if not self.does_file_exist(f):
                return False
        return True

    # check if one file exists on the router
    def does_file_exist(self, f):
        _, _, err = self.exec_cmd("ls " + f)
        if "No such file" in err or "cannot access" in err:
            return False
        else:
            return True

    # is immutable FS enabled on this router. Check for the file
    # that gets included during build on such systems
    def is_immutable_fs_enabled(self):
        return self.does_file_exist("/platform/immutable_fs_hw_sku.txt")

    # given a command execute it on the device
    def exec_cmd(self, command=""):
        self.log("Cmd: " + command)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy)
        try:
            client.connect(self.ip, self.port, username=self.uname, password=self.pw, look_for_keys=False, allow_agent=False)
            stdin, stdout, stderr = client.exec_command(command)
            output = stdout.read().decode().strip()
            err = stderr.read().decode().strip()
            return True, output, err
        except Exception as e:
            self.log(f"Error during config execution: {e}")
            return False, "", ""

    def log(self, args):
        print("log: " + str(args))

    def report_pass(self, args):
        self.log("TEST_PASSED: " + str(args))
        self.log("===================================================")

    def report_fail(self, args):
        self.log("TEST_FAILED: " + str(args))
        self.log("===================================================")
        os._exit(-1)

    def config_save(self):
        self.exec_cmd("sudo -s config save -y")

    # wait for interfaces to show up on the device.
    # this is used as a simple check to make sure basic
    # services are ok.
    # FIXME - Should actually check for all relevant services health
    # to claim device is good.
    def wait_for_interfaces(self):
        end_time = time.time() + 5 * 60
        self.log("Checking interfaces.")
        while time.time() < end_time:
            _, out, err = self.exec_cmd('show int status | wc -l')
            count = int(out)
            if count >= 34:
                self.log("Interface check passed")
                return True
            else:
                self.log(".")
                time.sleep(5)
        self.log("Timed out waiting for interface check: " + out)
        return False

    # reboot the device
    def reboot(self):
        # Establish SSH connection
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy)
        start_time = datetime.datetime.now()
        try:
            client.connect(self.ip, self.port, username=self.uname, password=self.pw, look_for_keys=False, allow_agent=False)
            ssh_session = client.get_transport().open_session()

            # Execute sudo reboot command
            ssh_session.exec_command(f'echo {self.pw} | sudo -S reboot\n')
            self.log("Reboot initiated")
            time.sleep(60)  # Wait for a bit for the reboot to start
        except paramiko.SSHException:
            self.log("Host key has changed or could not be verified.")
            # Remove the old host key
            command = f"ssh-keygen -f \"/home/pbuds/.ssh/known_hosts\" -R \"{ip}\""
            self.log("Executing command: " + command)
            subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.log("tried removing key")
        except Exception as e:
            self.log(f"Error during reboot: {e}")
            return False
        finally:
            client.close()

        # Try to reconnect periodically for 12 minutes
        end_time = time.time() + 12 * 60
        attempts = 0
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy)
        while time.time() < end_time:
            try:
                client.connect(self.ip, self.port, username=self.uname, password=self.pw, look_for_keys=False,
                               allow_agent=False)
                # Successfully reconnected, now check uptime
                uptime = self.uptime(client)
                end_time = datetime.datetime.now()
                time_taken = int((end_time - start_time).total_seconds())
                if time_taken > uptime:
                    self.log("Reboot successful: uptime: " + str(uptime) + ", time taken: " + str(time_taken))
                    if self.wait_for_interfaces():
                        self.log("Wait for interfaces worked")
                    else:
                        self.log("Wait for interfaces failed")
                    return True
                else:
                    self.log("Machine is up, but uptime is too long, reboot time: " + str(time_taken)
                          + ", uptime: " + str(uptime))
                    return False
            except paramiko.SSHException:
                attempts = attempts + 1
                time.sleep(5)  # Wait before trying to reconnect
            except Exception as e:
                attempts = attempts + 1
                self.log(f"Reconnection attempt after reboot attempt:{attempts} : {e}")
                time.sleep(30)  # Wait before trying to reconnect

        self.log("Reconnection attempts exceeded the time limit.")
        os._exit(-1)
        return False

    def find_img_directory(self, img_base_dir, img_prefix):
        ok, dir_listing, err = self.exec_cmd("ls -l " + img_base_dir)
        for line in str(dir_listing).splitlines():
            # Check if the line corresponds to a directory entry
            if line.startswith('d'):
                # Extract the directory name from the line
                dir_name = line.split()[-1]
                # Check if the directory name starts with the specified prefix
                if dir_name.startswith(img_prefix):
                    return dir_name
        return None
