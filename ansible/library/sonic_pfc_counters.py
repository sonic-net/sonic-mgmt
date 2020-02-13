#!/usr/bin/python
import time

DOCUMENTATION = '''
---
module: sonic_pfc_counters
version_added: "1.0"
author: Wei Bai (webai@microsoft.com)
short_description: Get/Clear PFC counters for a device  
'''

from ansible.module_utils.basic import *

tx_direction = "Tx"
rx_direction = "Rx"

def parse_pfc_counters(output):
    counters = dict()
	
    lines = output.splitlines()
    """ Tx or Rx """
    direction = None    

    for line in lines:
        line = line.strip()
        if 'Port Rx' in line:
            direction = rx_direction
            continue
		
        elif 'Port Tx' in line:
            direction = tx_direction
            continue
		
        elif line.startswith('---'):
            continue
					
        words = line.split()
        """ port_name, counter0, counter1, .... counter7 """
        if len(words) != 9:
            continue
		
        port = words[0]
        if port not in counters:
            counters[port] = dict()
        
        if direction is not None:
            counters[port][direction] = [x for x in words[1:]]
        else:
            module.fail_json(msg = "Direction is unknown")

    return counters	

def get_pfc_counters(module):
    out = None
    while True:
        rc, out, err = module.run_command("sudo pfcstat")
        if rc != 0:
            module.fail_json(msg = "Command pfcstat failed rc=%d, out=%s, err=%s" % (rc, out, err))
        
        elif out is None or len(out) == 0:
            time.sleep(1)
        
        else:
            break

    return out		

def clear_pfc_counters(module):
    rc, out, err = module.run_command("sudo pfcstat -c")
    if rc != 0:
        module.fail_json(msg = "Command pfcstat -c failed rc=%d, out=%s, err=%s" % (rc, out, err))

def main():
    module = AnsibleModule(argument_spec = dict(method = dict(required = True)), supports_check_mode = False)	
	
    method = module.params['method']
    if method == "get":
        counters = parse_pfc_counters(get_pfc_counters(module))
        module.exit_json(ansible_facts = counters)
	
    elif method == "clear":
        clear_pfc_counters(module)
        module.exit_json()

    else:
        module.fail_json(msg = "Unknown method %s" % (method))		

if __name__ == "__main__":
    main()
