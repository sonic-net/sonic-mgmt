#!/usr/bin/env python3
import time
from swsscommon.swsscommon import events_init_publisher, event_publish, events_deinit_publisher, FieldValueMap

for i in range(10):
    for j in range(100):
        source = "event-source-{}#{}".format(i, j)
        pub = events_init_publisher(source)
        fvm = FieldValueMap()
        fvm["id"] = "{}#{}".format(i, j)
        fvm["foo"] = "bar" * 10
        event_publish(pub, "lab-event", fvm)
        time.sleep(1/50)  # 50 events/sec
        events_deinit_publisher(pub)
