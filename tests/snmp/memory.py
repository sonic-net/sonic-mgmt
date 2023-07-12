#!/usr/bin/python
# memory.py <total_memory>
import sys
length = 512000000
iterations = 50
if len(sys.argv) > 1:
    total_memory = sys.argv[1]
    if total_memory <= 4 * 1024 * 1024:
        length = 320000000
load = [' ' * length]
print(load)
