#!/usr/bin/env python
import sonic_platform_base.sonic_sfp.sfputilhelper
import json
from sonic_daemon_base.daemon_base import DaemonBase
db = DaemonBase()
port_config_path = db.get_path_to_port_config_file()
platform_sfputil = sonic_platform_base.sonic_sfp.sfputilhelper.SfpUtilHelper()
platform_sfputil.read_porttab_mappings(port_config_path)
print json.dumps(platform_sfputil.logical_to_physical)

