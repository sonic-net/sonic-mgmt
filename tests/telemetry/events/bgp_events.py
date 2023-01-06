#! /usr/bin/env python3

import json

logger = logging.getLogger(__name__)

def test_event(duthost, localhost, run_cmd, data_dir):
    ret = duthost.shell("sudo config bgp shutdown all")
    assert ret["rc"] == 0, "Failinhg to shutdown"

    ret = duthost.shell("sudo config bgp startup all")
    assert ret["rc"] == 0, "Failinhg to startup"

    op_file = os.path.join(data_dir, "bgp_state.json")
    run_cmd(localhost, [ "heartbeat=5"], op_file=op_file,
            filter_event="sonic-events-bgp:bgp-state",
            event_cnt=1, timeout=10)

    d = {}
    with open(op_file, "r") as s:
        d = json.load(s)
    logger.info("events received: ({})".format(json.dumps(d, indent=4)))
    assert len(d) > 0, "Failed to check heartbeat"
