#!/usr/bin/python

import time
import subprocess

def get_free_memory():
    command = "grep MemFree /proc/meminfo | awk '{print $2}'"
    output = subprocess.check_output(command, shell=True)
    free_memory = int(output.strip())
    return free_memory

free_memory = get_free_memory()
total_chars = 512000000

if (free_memory * 1024) > int(total_chars * 130 / 100):
    load = []
    count = 1000
    for i in range(0, count):
        load.append([' ' * int(total_chars / count)])
        time.sleep(0.01)
else:
    chunk_size = int((free_memory * 1024 * 100 / 130) / 2)
    large_string = ""
    remaining_chars = total_chars
    # print("Free Memory: {} total_chars {} chunk_size {}".format(free_memory, total_chars, chunk_size))

    try:
        while remaining_chars > 0:
            chunk = ' ' * min(chunk_size, remaining_chars)
            large_string += chunk
            remaining_chars -= chunk_size

        for i in range(0, len(large_string), chunk_size):
            print(large_string[i:i+chunk_size])
    except MemoryError:
        print("Not enough memory to generate and print the large string.")
