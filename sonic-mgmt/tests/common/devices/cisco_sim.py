import time
import re
import logging
logger = logging.getLogger(__name__)

# Define a list of commands with corresponding delays to be applied for sim
cmds = []  # Define an empty list for cmds

if len(cmds) == 0:
    cmds = [
        {
            "cmd": r'(?:sudo\s+)?\s*config\s+acl\s+remove\s+.*',
            "delay": 5,
        },
        {
            "cmd": r'(?:sudo\s+)?\s*config\s+acl\s+add\s+.*',
            "delay": 5,
        },
        {
            "cmd": r'(?:sudo\s+)?\s*ip neigh (add|del)\.*',
            "delay": 5,
        },
        {
            "cmd": r'(?:sudo\s+)?\s*arp (-s|-d)\.*',
            "delay": 5,
        },
        {
            "cmd": r'(?:sudo\s+)?\s*ip -6 neigh (add|del).*',
            "delay": 5,
        },
        {
            "cmd": r'(?:sudo\s+)?\s*sonic-clear (arp|ndp).*',
            "delay": 5,
        },
        {
            "cmd": r'(?:sudo\s+)?\s*config pfcwd start_default.*',
            "delay": 60,
        },
        {
            "cmd": r'(?:sudo\s+)?\s*config loopback del.*',
            "delay": 30,
        },
        {
            "cmd": r'(?:sudo\s+)?\s*config bgp remove neighbor.*',
            "delay": 60,
        },
        {
            "cmd": r'(?:sudo\s+)?\s*ifconfig\s+.*\s(up|down).*',
            "delay": 30,
        },
        {
            "cmd": r'(?:sudo\s+)?\s*config rollback.*',
            "delay": 90,
        },
        {
            "cmd": r'(?:sudo\s+)?\s*fast-reboot.*',
            "delay": 300,
        },
        { 
            "cmd": r'(?:sudo\s+)?\s*warm-reboot.*',
            "delay": 300,
        },
        {
            "cmd": r'(?:sudo\s+)?\s*ip\s+route\s+(add|del|flush).*',
            "delay": 5,
        },
        {
            "cmd": r'(?:sudo\s+)?\s*docker exec\s.*\sswssconfig.*',
            "delay": 10,
        }

    ]



## check for kwargs as well
# kwargs={"cmds": ["docker cp /tmp/decap_conf_SET.json swss:/decap_conf_SET.json", "docker exec swss swssconfig /decap_conf_SET.json", "docker exec swss rm /decap_conf_SET.json"]}


def delay(cmd):
    for c in cmds:
        if re.match(c["cmd"], cmd):
            logger.info("sleeping {} seconds after executing '{}' to ensure the command is completed in sim\n'".format(c["delay"],cmd))
            time.sleep(c["delay"])
            return
    return

## this function is a decorator that adds a delay to the execution of the function
## we use this to decorate run() function in AnsibleHostBase class (sonic-mgmt/tests/common/devices/base.py) to add delay to the execution of the command via sim
## the main reason for this is due to the fact that most cmds in sonic is processed asynchronously and we need to add a delay to ensure that the command 
# is processed before the next command is executed, sepceially in sim where the programing is relatively slow compare to hardware
def sim_conditional_delay(func):
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        if len(args) < 2:
            return result
        cmd = args[1]
        delay(cmd)
        return result
    return wrapper
