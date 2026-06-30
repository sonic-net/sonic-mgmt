import tests.transceiver.attribute_parser.attribute_keys as at_keys

#NOTE TEMP FILE - need to move to established files per file_organization.md

############################# CONSTANTS #############################
# from docs/testplan/transceiver/test_plan.md
XCVRD_RESTART = r"docker exec pmon supervisorctl restart xcvrd"
XCVRD_UPTIME = r"docker exec pmon supervisorctl status xcvrd | awk '{print $NF}'"
PMON_RESTART = r"sudo systemctl restart pmon"
SWSS_RESTART = r"sudo systemctl restart swss"
SYNCD_RESTART = r"sudo systemctl restart syncd"

# from playing around on the DUTs
LLDP_NEIGHBORS = r"show lldp neighbors"
SEARCH_COREFILES = r"find /var/core/ -maxdepth 1 -type f -printf '%f '"

# from docs/testplan/transceiver/system_test_plan.md
DEFAULT_XCVRD_SETTLE_SEC = 120
DEFAULT_PMON_SETTLE_SEC = 120
DEFAULT_SWSS_SETTLE_SEC = 180
DEFAULT_SYNCD_SETTLE_SEC = 240

############################# GENERIC HELPERS #############################
def sys_attr(port_attrs, name, default):
    """Extract system attribute from port attributes dict with default fallback."""
    return port_attrs.get(at_keys.SYSTEM_ATTRIBUTES_KEY, {}).get(name, default)

def restart_process(duthost, process):
    if process == "xcvrd": cmd = XCVRD_RESTART
    elif process == "pmon": cmd = PMON_RESTART
    elif process == "swss": cmd = SWSS_RESTART  
    elif process == "syncd": cmd = SYNCD_RESTART
    if process:
        duthost.shell(cmd)
        return True

def get_xcvrd_uptime(duthost):
    return duthost.shell(XCVRD_UPTIME)

def get_lldp_neighbors(duthost):
    return duthost.shell(LLDP_NEIGHBORS)

def get_corefiles(duthost):
    return duthost.shell(SEARCH_COREFILES)

def get_db_port_table(duthost, port, namespace=None, attr_filter=None):
    """
    Example of UNFILTERED Output:
        {'admin_status': 'up',
        'alias': 'etp5a', 
        'autoneg': 'off', 
        'fec': 'rs', 
        'index': '5', 
        'lanes': '57', 
        'mtu': '9100', 
        'speed': '100000', 
        'subport': '1', 
        'description': '', 
        'oper_status': 'up', 
        'flap_count': '1', 
        'last_up_time': 'Wed Jun 24 17:31:05 2026'}
    """
    cmd = ''
    if namespace: #MULTI-ASIC
        cmd = f'sonic-db-cli -n "{namespace}" APPL_DB hgetall "PORT_TABLE:{port}" '
    else: #SINGLE ASIC
        cmd = f'sonic-db-cli APPL_DB hgetall "PORT_TABLE:{port}"'

    if attr_filter:
        cmd = cmd.replace('hgetall', 'hget')
        cmd = cmd + f' "{attr_filter}"'
    return duthost.shell(cmd)
