import os
import pty
import subprocess
import time

commands = [
    "d0 = sdk.la_get_device(0)",
    "d0.clear_trap_configuration(sdk.la_event_e_ETHERNET_DHCPV4_SERVER)",
    "d0.clear_trap_configuration(sdk.la_event_e_ETHERNET_DHCPV4_CLIENT)",
    "quit()"
]

def run_in_tty():
    # Create a pseudo terminal
    master, slave = pty.openpty()

    cmd = [
        "sudo", "docker", "exec", "-it", "syncd",
        "/usr/bin/dshell_client.py", "-i"
    ]

    # Launch process with tty
    proc = subprocess.Popen(cmd, stdin=slave, stdout=slave, stderr=slave, text=True)
    time.sleep(2)
    print(os.read(master, 65535).decode("utf-8"))

    # Send each command with blank line
    for c in commands:
        os.write(master, (c + "\n\n").encode())
        time.sleep(1)
        output = os.read(master, 65535).decode("utf-8")
        print(output)

    proc.wait()

run_in_tty()
