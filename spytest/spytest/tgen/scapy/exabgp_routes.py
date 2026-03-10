#!/usr/bin/env python

import os
import sys
import time

inc_file = sys.argv[1] if len(sys.argv) > 1 else None
exc_file = sys.argv[2] if len(sys.argv) > 2 else None


def read_lines(filepath):
    if not filepath or not os.path.exists(filepath):
        return []
    fh = open(filepath, 'r')
    data = fh.readlines()
    fh.close()
    data = map(str.strip, data)
    return data


def send_msgs(msgs):
    for index, msg in enumerate(msgs):
        sys.stdout.write(msg + '\n')
        sys.stdout.flush()
        if index % 10 == 0:
            time.sleep(.1)


def wait_for_changes():
    import pyinotify
    while True:
        class ModHandler(pyinotify.ProcessEvent):
            # evt has useful properties, including pathname
            def process_default(self, event):
                pass

        handler = ModHandler()
        wm = pyinotify.WatchManager()
        notifier = pyinotify.Notifier(wm, handler)
        mask = pyinotify.ALL_EVENTS
        wm.add_watch(inc_file, mask)
        wm.add_watch(exc_file, mask)
        notifier.loop()


time.sleep(2)
send_msgs(read_lines(inc_file))
send_msgs(read_lines(exc_file))

while True:
    # wait_for_changes()
    time.sleep(1)
