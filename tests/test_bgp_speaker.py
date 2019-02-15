from netaddr import *
import sys
import time
import ipaddress

def generate_ips(num, prefix, exclude_ips):
    """
       Generate random ips within prefix
    """
    prefix = IPNetwork(prefix)
    exclude_ips.append(prefix.broadcast)
    exclude_ips.append(prefix.network)
    available_ips = list(prefix)

    if len(available_ips) - len(exclude_ips)< num:
        raise Exception("Not enough available IPs")

    generated_ips = []
    for available_ip in available_ips:
        if available_ip not in exclude_ips:
            generated_ips.append(str(available_ip) + '/' + str(prefix.prefixlen))
        if len(generated_ips) == num:
            break

    return generated_ips

def run_shell(host, hostname, cmd):
    res = host.shell(cmd)[hostname]
    if res['failed']:
        raise Exception("shell cmd={} error: {}".format(src, res['msg']))

def run_template(host, hostname, src, dest, mode=None):
    if not mode:
        res = host.template(src=src, dest=dest)[hostname]
    else:
        res = host.template(src=src, dest=dest, mode=mode)[hostname]
    if res.has_key('failed') and res['failed']:
        raise Exception("template src={} error: {}".format(src, res['msg']))

def ptf_runner(host, hostname, testdir, testname, platform_dir, params={}, \
               platform="remote", qlen=0, relax=True, debug_level="info", log_file=None):

    ptf_test_params = ";".join(["{}=\"{}\"".format(k, v) for k, v in params.items()])

    cmd = "ptf --test-dir {} {} --platform-dir {}".format(testdir, testname, platform_dir)
    if qlen:
        cmd += " --qlen={}".format(qlen)
    if platform:
        cmd += " --platform {}".format(platform)
    if ptf_test_params:
        cmd += " -t '{}'".format(ptf_test_params)
    if relax:
        cmd += " --relax"
    if debug_level:
        cmd += " --debug {}".format(debug_level)
    if log_file:
        cmd += " --log-file {}".format(log_file)

    res = host.shell(cmd, chdir="/root")[hostname]
    if res.has_key('failed') and res['failed']:
        raise Exception("run ptf test {} failed. error: {}".format(testname, res))

def test_bgp_speaker(localhost, ansible_adhoc):
    hostname = 'vlab-01'
    ptf_hostname = 'ptf-01'
    host = ansible_adhoc(become=True)[hostname]
    ptfhost = ansible_adhoc(become=True)[ptf_hostname]

    mg_facts  = host.minigraph_facts(host=hostname)[hostname]['ansible_facts']
    host_facts  = host.setup()[hostname]['ansible_facts']

    res = host.shell("sonic-cfggen -m -d -y /etc/sonic/deployment_id_asn_map.yml -v \"deployment_id_asn_map[DEVICE_METADATA['localhost']['deployment_id']]\"")[hostname]
    bgp_speaker_asn = res['stdout']

    vlan_ips = generate_ips(3, \
            "%s/%s" % (mg_facts['minigraph_vlan_interfaces'][0]['addr'], mg_facts['minigraph_vlan_interfaces'][0]['prefixlen']),
            [IPAddress(mg_facts['minigraph_vlan_interfaces'][0]['addr'])])

    # three speaker ips, two from peer range, another is vlan ip [0]
    speaker_ips = generate_ips(2, mg_facts['minigraph_bgp_peers_with_range'][0]['ip_range'][0], [])
    speaker_ips.append(vlan_ips[0])

    for ip in vlan_ips:
        host.command("ip route flush %s/32" % ip)
        host.command("ip route add %s/32 dev %s" % (ip, mg_facts['minigraph_vlan_interfaces'][0]['attachto']))

    root_dir   = "/root"
    exabgp_dir = "/root/exabgp"
    helper_dir = "/root/helpers"
    port_num = [5000, 6000, 7000]
    cfnames = ["config_1.ini", "config_2.ini", "config_3.ini"]
    vlan_ports = []
    for i in range(0, 3):
        vlan_ports.append(mg_facts['minigraph_port_indices'][mg_facts['minigraph_vlans'][mg_facts['minigraph_vlan_interfaces'][0]['attachto']]['members'][i]])

    ptfhost.file(path=exabgp_dir, state="directory")
    ptfhost.file(path=helper_dir, state="directory")
    ptfhost.copy(src="bgp_speaker/dump.py", dest=helper_dir)
    ptfhost.copy(src="bgp_speaker/http_api.py", dest=helper_dir)
    ptfhost.copy(src="bgp_speaker/announce_routes.py", dest=helper_dir)

    # deploy config file
    extra_vars = \
                { 'helper_dir': helper_dir,
                  'exabgp_dir': exabgp_dir,
                  'lo_addr'   : mg_facts['minigraph_lo_interfaces'][0]['addr'],
                  'lo_addr_prefixlen' : mg_facts['minigraph_lo_interfaces'][0]['prefixlen'],
                  'vlan_addr' : mg_facts['minigraph_vlan_interfaces'][0]['addr'],
                  'peer_range': mg_facts['minigraph_bgp_peers_with_range'][0]['ip_range'][0],
                  'announce_prefix': '10.10.10.0/26',
                  'minigraph_portchannels'  : mg_facts['minigraph_portchannels'],
                  'minigraph_vlans'  : mg_facts['minigraph_vlans'],
                  'minigraph_port_indices'  : mg_facts['minigraph_port_indices'],
                  'peer_asn'  : mg_facts['minigraph_bgp_asn'],
                  'peer_asn'  : mg_facts['minigraph_bgp_asn'],
                  'my_asn'    : bgp_speaker_asn,
                  'vlan_ports' : vlan_ports,
                  'port_num'  : port_num,
                  'speaker_ips': speaker_ips,
                  'vlan_ips': vlan_ips,
                  'cfnames': cfnames }

    for i in range(0, 3):
        extra_vars.update({ 'cidx':i })
        extra_vars.update({ 'speaker_ip': speaker_ips[i].split('/')[0] })
        ptfhost.options['variable_manager'].extra_vars = extra_vars
        run_template(ptfhost, ptf_hostname, src="bgp_speaker/config.j2", dest="%s/%s" % (exabgp_dir, cfnames[i]))

    # deploy routes
    run_template(ptfhost, ptf_hostname, src="bgp_speaker/routes.j2", dest="%s/%s" % (exabgp_dir, "routes"))

    # deploy start script
    run_template(ptfhost, ptf_hostname, src="bgp_speaker/start.j2", dest="%s/%s" % (exabgp_dir, "start.sh"), mode="u+rwx")
    # kill exabgp
    res = ptfhost.shell("pkill exabgp")[ptf_hostname]
    print res

    # start exabgp instance
    res = ptfhost.shell("bash %s/start.sh" % exabgp_dir)[ptf_hostname]
    print res

    time.sleep(10)

    # announce route
    res = ptfhost.shell("nohup python %s/announce_routes.py %s/routes >/dev/null 2>&1 &" % (helper_dir, exabgp_dir))[ptf_hostname]
    print res

    # make sure routes announced to dynamic bgp neighbors
    time.sleep(60)

    bgp_facts = host.bgp_facts()[hostname]['ansible_facts']

    # Verify bgp sessions are established
    for k, v in bgp_facts['bgp_neighbors'].items():
        assert v['state'] == 'established'

    # Verify accepted prefixes of the dynamic neighbors are correct
    for ip in speaker_ips:
        assert bgp_facts['bgp_neighbors'][ip.split('/')[0]]['accepted prefixes'] == 1
    assert bgp_facts['bgp_neighbors'][vlan_ips[0].split('/')[0]]['accepted prefixes'] == 1


    # Generate route-port map information
    run_template(ptfhost, ptf_hostname, src="bgp_speaker/bgp_speaker_route.j2", dest="/root/bgp_speaker_route.txt")

    ptfhost.copy(src="ptftests", dest=root_dir)

    ptf_runner(ptfhost, \
               ptf_hostname, \
               "ptftests",
               "fib_test.FibTest",
               platform_dir="ptftests",
               params={"testbed_type": "t0",
                      "router_mac": host_facts['ansible_Ethernet0']['macaddress'],
                      "fib_info": "/root/bgp_speaker_route.txt",
                      "ipv4": True,
                      "ipv6": False },
               log_file="/tmp/bgp_speaker_test.FibTest.log")

    res = ptfhost.shell("pkill exabgp")[ptf_hostname]

    for ip in vlan_ips:
        host.command("ip route flush %s/32" % ip)

    # ptfhost.shell("ip addr flush dev eth{{ '%d' % (minigraph_vlans[minigraph_vlan_interfaces[0]['attachto']]['members'][0] | replace("Ethernet", "") | int / 4)}}
