#!/usr/bin/python

import time
import subprocess


def get_free_memory():
    command = "grep MemFree /proc/meminfo | awk '{print $2}'"
    output = subprocess.check_output(command, shell=True)
    free_memory = int(output.strip())
    return free_memory


reserve_free_memory = 256 * 1024 * 1024    # reserve 256M
free_memory = get_free_memory()            # KB
total_chars = 512000000

if free_memory * 1024 < (reserve_free_memory + total_chars):
    command = "sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'"
    subprocess.run(command, shell=True)
    total_chars = 256000000

# reserve 256M for system run
if (free_memory * 1024 - reserve_free_memory) > total_chars:
    load = []
    count = 5000
    for i in range(0, count):
        load.append([' ' * int(total_chars / count)])
        time.sleep(0.01)
