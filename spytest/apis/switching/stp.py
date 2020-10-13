from collections import OrderedDict
from spytest import st

def config_bridge_priority(dut, port, prio):
    """

    :param dut:
    :type dut:
    :param port:
    :type port:
    :param prio:
    :type prio:
    :return:
    :rtype:
    """
    st.log("TODO: config_bridge_priority {}/{} {}".format(dut, port, prio))


def read_all_props(dut, port):
    """

    :param dut:
    :type dut:
    :param port:
    :type port:
    :return:
    :rtype:
    """
    st.log("TODO: read_all_props {}/{}".format(dut, port))
    retval = OrderedDict()
    retval[dut] = OrderedDict()
    retval[dut][port] = OrderedDict()
    retval[dut][port]["prop1"] = "v1"
    retval[dut][port]["prop2"] = "v2"
    return retval


CFG_STP         = "config spanning_tree"
CFG_STP_INTF    = "config spanning_tree interface"
CFG_STP_VLAN    = "config spanning_tree vlan"
SHOW_STP        = "show spanning_tree"

def config_stp_intf_param(dut, cfgdictionary={}):
    """
    config spanning_tree interface <enable/disable> <ifname>
    cfgdictionary={'' : 'enable', 'ifname'}
    cfgdictionary={'' : 'disable', 'ifname'}

    config spanning_tree interface priority <prio> <ifname>
    cfgdictionary={'priority' : 'prio', 'ifname'}

    config spanning_tree interface cost <cost> <ifname>
    cfgdictionary={'cost' : 'cost', 'ifname'}

    config spanning_tree interface portfast <enable/disable> <ifname>
    cfgdictionary={'portfast' : 'enable', 'ifname'}
    cfgdictionary={'portfast' : 'disable', 'ifname'}

    config spanning_tree interface bpdu_guard <enable/disable> <ifname>
    config spanning_tree interface root_guard <enable/disable> <ifname>
    config spanning_tree interface uplink_fast <enable/disable> <ifname>
    """

    for key in cfgdictionary:
        values = cfgdictionary[key]
        cmd = CFG_STP_INTF+" "+key
        for value in values:
            cmd += " "+value
        rv = st.config(dut, cmd, skip_error_check=True)
        if "Error" in rv:
            st.log(rv)
            return False
            # no output expected on console for success
        st.wait(.200) # add 200 ms delay after config to avoid timing issues
        st.log("success : " + cmd)
    return True


def config_stp_vlan_param(dut, cfgdictionary={}):
    """
    config spanning_tree vlan <enable/disable> <vlanid>
    cfgdictionary={'' : ['enable', 'vlanid']}
    cfgdictionary={'' : ['disable', 'vlanid']}

    config spanning_tree vlan forward_delay <vlanid> <forward_delay>
    cfgdictionary={'forward_delay' : ['vid', 'forward_delay']}

    config spanning_tree vlan hello <vid> <hello_interval>
    cfgdictionary={'hello' : ['vid', 'hello_interval']}

    config spanning_tree vlan max_age <vid> <max_age>
    config spanning_tree vlan priority <vid> <priority>

    config spanning_tree vlan interface priority  <vid> <interface_name> <priority>
    cfgdictionary={'interface' : ['priority', 'vid', 'ifname', 'prio']}
    cfgdictionary={'interface' : ['cost', 'vid', 'ifname', 'cost_val']}

    """

    for key in cfgdictionary:
        values = cfgdictionary[key]
        cmd = CFG_STP_VLAN+" "+key
        for value in values:
            cmd += " "+value
        rv = st.config(dut, cmd, skip_error_check=True)
        if "Error" in rv:
            st.log(rv)
            return False
            # no output expected on console for success
        st.wait(.200) # add 200 ms delay after config to avoid timing issues
        st.log("success : " + cmd)
    return True



def config_stp_param(dut, cfgdictionary={}):
    """
    config spanning_tree disable pvst
    config spanning_tree enable pvst
    config spanning_tree priority <prio>
    config spanning_tree hello <sec>
    config spanning_tree forward_delay <sec>
    config spanning_tree max_age <sec>
    config spanning_tree root_guard_timeout <sec>
    """
    for key in cfgdictionary:
        value = cfgdictionary[key]
        cmd = CFG_STP+" "+key+" "+str(value)
        rv = st.config(dut, cmd, skip_error_check=True)
        if "Error" in rv:
            st.log(rv)
            return False
            # no output expected on console for success
        st.wait(.200) # add 200 ms delay after config to avoid timing issues
        st.log("success : " + cmd)
    return True


""" Wrapper CLI-functions for ease of use"""

def config_stp_enable_pvst(dut):
    return config_stp_param(dut, {'enable':'pvst'})

def config_stp_enable_rpvst(dut):
    return config_stp_param(dut, {'enable':'rpvst'})

def config_stp_disable_pvst(dut):
    return config_stp_param(dut, {'disable':'pvst'})

def config_stp_disable_rpvst(dut):
    return config_stp_param(dut, {'disable':'rpvst'})

def config_stp_global_hello(dut, hello):
    return config_stp_param(dut, {'hello':hello})


def config_stp_global_priority(dut, priority):
    return config_stp_param(dut, {'priority':priority})


def config_stp_global_maxage(dut, maxage):
    return config_stp_param(dut, {'max_age':maxage})


def config_stp_global_rootguardtimeout(dut, rg_timeout):
    return config_stp_param(dut, {'root_guard_timeout':rg_timeout})


def config_stp_global_fwddly(dut, fwddly):
    return config_stp_param(dut, {'forward_delay':fwddly})


def config_stp_vlan_enable(dut, vlanid):
    return config_stp_vlan_param(dut, cfgdictionary={'' : ['enable', str(vlanid)]})


def config_stp_vlan_disable(dut, vlanid):
    return config_stp_vlan_param(dut, cfgdictionary={'' : ['disable', str(vlanid)]})


def config_stp_vlan_hello(dut, vlanid, hello):
    return config_stp_vlan_param(dut, cfgdictionary={'hello' : [str(vlanid), str(hello)]})


def config_stp_vlan_fwddly(dut, vlanid, fwddly):
    return config_stp_vlan_param(dut, cfgdictionary={'fwddly' : [str(vlanid), str(fwddly)]})


def config_stp_vlan_maxage(dut, vlanid, maxage):
    return config_stp_vlan_param(dut, cfgdictionary={'maxage' : [str(vlanid), str(maxage)]})


def config_stp_vlan_priority(dut, vlanid, priority):
    return config_stp_vlan_param(dut, cfgdictionary={'priority' : [str(vlanid), str(priority)]})


def config_stp_vlan_intf_cost(dut, vlanid, ifname, cost):
    return config_stp_vlan_param(dut, cfgdictionary={'interface' : ['cost', str(vlanid), ifname, str(cost)]})


def config_stp_vlan_intf_priority(dut, vlanid, ifname, priority):
    return config_stp_vlan_param(dut, cfgdictionary={'interface' : [str(vlanid), ifname, str(priority)]})


def config_stp_intf_enable(dut, ifname):
    return config_stp_intf_param(dut, cfgdictionary={'' : ['enable', ifname]})


def config_stp_intf_disable(dut, ifname):
    return config_stp_intf_param(dut, cfgdictionary={'' : ['disable', ifname]})


def config_stp_intf_cost(dut, ifname, cost):
    return config_stp_intf_param(dut, cfgdictionary={'cost' : [ifname, str(cost)]})


def config_stp_intf_portfast(dut, ifname, action):
    if action not in ['enable', 'disable']:
        st.log("Invalid param: action = {}".format(action))
        return
    return config_stp_intf_param(dut, cfgdictionary={'portfast' : [action, ifname]})


def config_stp_intf_uplinkfast(dut, ifname, action):
    if action not in ['enable', 'disable']:
        st.log("Invalid param: action = {}".format(action))
        return
    return config_stp_intf_param(dut, cfgdictionary={'uplink_fast' : [action, ifname]})


def config_stp_intf_priority(dut, ifname, priority):
    return config_stp_intf_param(dut, cfgdictionary={'priority' : [ifname, str(priority)]})


def config_stp_intf_bpduguard(dut, ifname, cfg_shut=False, action='enable'):
    if action not in ['enable', 'disable']:
        st.log("Invalid param: action = {}".format(action))
        return
    if cfg_shut and action == 'enable':
        return config_stp_intf_param(dut, cfgdictionary={'bpdu_guard' : [action, '-s', ifname]})

    return config_stp_intf_param(dut, cfgdictionary={'bpdu_guard' : [action, ifname]})


def config_stp_intf_rootguard(dut, ifname, action):
    if action not in ['enable', 'disable']:
        st.log("Invalid param: action = {}".format(action))
        return
    return config_stp_intf_param(dut, cfgdictionary={'root_guard' : [action, ifname]})


""" SHOW commands """
def show_spanning_tree(dut, params=[]):
    cmd = SHOW_STP

    for param in params:
        cmd += " "+param

    return st.show(dut, cmd)


""" Wrapper CLI-functions for ease of use"""
def show_spanning_tree_vlan(dut, vlanid):
    return show_spanning_tree(dut, ['vlan', str(vlanid)])


def show_spanning_tree_vlan_intf(dut, vlanid, ifname):
    return show_spanning_tree(dut, ['vlan', str(vlanid), 'interface', ifname])


def show_spanning_tree_statistics(dut, vlanid=0):
    if vlanid == 0:
        return show_spanning_tree(dut, ['statistics'])
    else:
        return show_spanning_tree(dut, ['statistics', str(vlanid)])


def get_stp_mode(dut):
    rows = show_spanning_tree(dut)
    if not rows:
        return None
    return rows[0]['mode']


def _get_stp_vlan_row(dut, vlanid):
    rows = show_spanning_tree_vlan(dut, vlanid)
    if not rows:
        return None

    for row in rows: 
        if row['vid'] == vlanid:
            return row
    return None


def get_stp_vlan_entry(dut, vlanid):
    return _get_stp_vlan_row(dut, vlanid)


def get_stp_vlan_instance(dut, vlanid):
    matched_row = _get_stp_vlan_row(dut, vlanid)
    return matched_row['inst'] if matched_row else None


def get_stp_vlan_br_id(dut, vlanid):
    matched_row = _get_stp_vlan_row(dut, vlanid)
    return matched_row['br_id'] if matched_row else None


def get_stp_vlan_br_maxage(dut, vlanid):
    matched_row = _get_stp_vlan_row(dut, vlanid)
    return matched_row['br_maxage'] if matched_row else None


def get_stp_vlan_br_hello(dut, vlanid):
    matched_row = _get_stp_vlan_row(dut, vlanid)
    return matched_row['br_hello'] if matched_row else None


def get_stp_vlan_br_fwddly(dut, vlanid):
    matched_row = _get_stp_vlan_row(dut, vlanid)
    return matched_row['br_fwddly'] if matched_row else None


def get_stp_vlan_br_hold(dut, vlanid):
    matched_row = _get_stp_vlan_row(dut, vlanid)
    return matched_row['br_hold'] if matched_row else None


def get_stp_vlan_br_lasttopo(dut, vlanid):
    matched_row = _get_stp_vlan_row(dut, vlanid)
    return matched_row['br_lasttopo'] if matched_row else None


def get_stp_vlan_br_topoch(dut, vlanid):
    matched_row = _get_stp_vlan_row(dut, vlanid)
    return matched_row['br_topoch'] if matched_row else None


def get_stp_vlan_rt_id(dut, vlanid):
    matched_row = _get_stp_vlan_row(dut, vlanid)
    return matched_row['rt_id'] if matched_row else None


def get_stp_vlan_rt_pathcost(dut, vlanid):
    matched_row = _get_stp_vlan_row(dut, vlanid)
    return matched_row['rt_pathcost'] if matched_row else None


def get_stp_vlan_rt_desigbridgeid(dut, vlanid):
    matched_row = _get_stp_vlan_row(dut, vlanid)
    return matched_row['rt_desigbridgeid'] if matched_row else None


def get_stp_vlan_rt_port(dut, vlanid):
    matched_row = _get_stp_vlan_row(dut, vlanid)
    return matched_row['rt_port'] if matched_row else None


def get_stp_vlan_rt_maxage(dut, vlanid):
    matched_row = _get_stp_vlan_row(dut, vlanid)
    return matched_row['rt_maxage'] if matched_row else None


def get_stp_vlan_rt_hello(dut, vlanid):
    matched_row = _get_stp_vlan_row(dut, vlanid)
    return matched_row['rt_hello'] if matched_row else None


def get_stp_vlan_rt_fwddly(dut, vlanid):
    matched_row = _get_stp_vlan_row(dut, vlanid)
    return matched_row['rt_fwddly'] if matched_row else None


def _get_stp_vlan_port_row(dut, vlanid, ifname):
    rows = show_spanning_tree_vlan(dut, vlanid)
    for row in rows:
        if (row['vid'] == vlanid) and (row['port_name'] == ifname):
            return row
    return None


def get_stp_vlan_port_entry(dut, vlanid, ifname):
    return _get_stp_vlan_port_row(dut, vlanid, ifname)


def get_stp_vlan_port_priority(dut, vlanid, ifname):
    matched_row = _get_stp_vlan_port_row(dut, vlanid, ifname)
    return matched_row['port_priority'] if matched_row else None


def get_stp_vlan_port_pathcost(dut, vlanid, ifname):
    matched_row = _get_stp_vlan_port_row(dut, vlanid, ifname)
    return matched_row['port_pathcost'] if matched_row else None


def get_stp_vlan_port_portfast(dut, vlanid, ifname):
    matched_row = _get_stp_vlan_port_row(dut, vlanid, ifname)
    return matched_row['port_portfast'] if matched_row else None


def get_stp_vlan_port_uplinkfast(dut, vlanid, ifname):
    matched_row = _get_stp_vlan_port_row(dut, vlanid, ifname)
    return matched_row['port_uplinkfast'] if matched_row else None


def get_stp_vlan_port_state(dut, vlanid, ifname):
    matched_row = _get_stp_vlan_port_row(dut, vlanid, ifname)
    return matched_row['port_state'] if matched_row else None


def get_stp_vlan_port_desigcost(dut, vlanid, ifname):
    matched_row = _get_stp_vlan_port_row(dut, vlanid, ifname)
    return matched_row['port_desigcost'] if matched_row else None


def get_stp_vlan_port_desigroot(dut, vlanid, ifname):
    matched_row = _get_stp_vlan_port_row(dut, vlanid, ifname)
    return matched_row['port_desigroot'] if matched_row else None


def get_stp_vlan_port_desigbridgeid(dut, vlanid, ifname):
    matched_row = _get_stp_vlan_port_row(dut, vlanid, ifname)
    return matched_row['port_desigbridgeid'] if matched_row else None


def _get_stp_bpdu_guard_row(dut, ifname):
    rows = show_spanning_tree(dut, ['bpdu_guard'])
    for row in rows:
        if row['bg_ifname'] == ifname:
            return row
    return None


def get_stp_bg_entry(dut, ifname):
    return _get_stp_bpdu_guard_row(dut, ifname)

def get_stp_bg_cfg_shut(dut, ifname):
    matched_row = _get_stp_bpdu_guard_row(dut, ifname)
    return matched_row['bg_cfg_shut'] if matched_row else None


def get_stp_bg_oper_shut(dut, ifname):
    matched_row = _get_stp_bpdu_guard_row(dut, ifname)
    return matched_row['bg_oper_shut'] if matched_row else None


def _get_stp_root_guard_row(dut, ifname):
    rows = show_spanning_tree(dut, ['root_guard'])
    if not rows:
        return None

    if ifname is None:
        return rows[0]
    else:
        for row in rows: 
            if row['rg_ifname'] == ifname:
                return row
    return None


def get_stp_rg_timeout(dut):
    matched_row = _get_stp_root_guard_row(dut, None)
    return matched_row['rg_timeout'] if matched_row else None


def get_stp_rg_entry(dut, ifname):
    matched_row = _get_stp_root_guard_row(dut, ifname)
    return matched_row 


def get_stp_rg_vid(dut, ifname):
    matched_row = _get_stp_root_guard_row(dut, ifname)
    return matched_row['rg_vid'] if matched_row else None


def get_stp_rg_status(dut, ifname):
    matched_row = _get_stp_root_guard_row(dut, ifname)
    return matched_row['rg_status'] if matched_row else None


def _get_stp_stats_row(dut, vlanid, ifname):
    rows = show_spanning_tree_statistics(dut, vlanid)
    if not rows:
        return None

    for row in rows: 
        if (row['st_vid'] == vlanid) and (row['st_portno'] == ifname):
            return row
    return None


def get_stp_stats_entry(dut, vlanid, ifname):
    return _get_stp_stats_row(dut, vlanid, ifname)


def get_stp_stats_bpdurx(dut, vlanid, ifname):
    matched_row = _get_stp_stats_row(dut, vlanid, ifname)
    return matched_row['st_bpdurx'] if matched_row else None


def get_stp_stats_bpdutx(dut, vlanid, ifname):
    matched_row = _get_stp_stats_row(dut, vlanid, ifname)
    return matched_row['st_bpdutx'] if matched_row else None


def get_stp_stats_tcnrx(dut, vlanid, ifname):
    matched_row = _get_stp_stats_row(dut, vlanid, ifname)
    return matched_row['st_tcnrx'] if matched_row else None


def get_stp_stats_tcntx(dut, vlanid, ifname):
    matched_row = _get_stp_stats_row(dut, vlanid, ifname)
    return matched_row['st_tcntx'] if matched_row else None


def get_stpctl_vlan_port(dut, vlanid, ifname):
    output = st.show(dut, 'stpctl port {} {}'.format(vlanid, ifname))
    if len(output) != 1:
        return None
    return output[0]

"""

if __name__== "__main__":
    config_stp_param("dut1", {'enable':'pvst', 'forward_delay': '20'})
    config_stp_intf_param('dut2',
                          {'':['enable', 'Eth1'],
                           'cost': ['2', 'Eth0'],
                           'portfast' : ['disable', 'Eth2'],
                           'portfast' : ['enable', 'Eth3']})

    config_stp_vlan_param('dut3',
                          {'interface':['cost', '100', 'Ethernet1', '20']})

    show_spanning_tree('dut1')
    show_spanning_tree('dut1', ['vlan'])
    show_spanning_tree('dut1', ['vlan', '100'])
    show_spanning_tree('dut1', ['vlan', '100', 'interface', 'Eth0'])
"""
