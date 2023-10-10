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
chunk_size = 32 * 1024 * 1024              # chunk size 32M
total_chars = 512000000

# reserve 256M for system run
if (free_memory * 1024 - reserve_free_memory) > total_chars:
    load = []
    count = 1000
    for i in range(0, count):
        load.append([' ' * int(total_chars / count)])
        time.sleep(0.01)
else:
    # for small memory device, use chunk size instead of total_chars
    command = "sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'"
    subprocess.run(command, shell=True)
    # reserve 256M for system run, 32M for chunk size
    free_memory = get_free_memory()
    if (free_memory * 1024) > (reserve_free_memory + chunk_size):
        large_string = ""
        remaining_chars = total_chars
        print("Free Memory: {} total_chars {} chunk_size {}".format(free_memory, total_chars, chunk_size))
        try:
            while remaining_chars > 0:
                chunk = ' ' * min(chunk_size, remaining_chars)
                large_string += chunk
                remaining_chars -= chunk_size

            for i in range(0, len(large_string), chunk_size):
                print(large_string[i:i+chunk_size])
        except MemoryError:
            print("Not enough memory to generate and print the large string.")
