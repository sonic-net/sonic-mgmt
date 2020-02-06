def verify_port(host_facts, ports):
    for port in ports:
        ans_ifname = "ansible_%s" % port
        assert host_facts[ans_ifname]['active'], "Port {} is down!".format(port)

def verify_port_multi_npu(duthost,namespace, ports):
    for port in ports:
        cmd  = "sudo ip netns exec {} bash -c \"cat /sys/class/net/{}/carrier\"".format(namespace, port)
        output = duthost.shell(cmd)["stdout"]
        for line in output:
            port_state = int(line.strip())
        print port_state
        assert port_state == 1, "Port {} is down!".format(port)

        
def check_critical_services(duthost):
    syncd_dockers = duthost.get_syncd_docker_names()
    for syncd_name in syncd_dockers:
        syncd_res = duthost.shell("docker exec -i {} ps aux | grep /usr/bin/syncd".format(syncd_name))
        assert syncd_res[u'rc'] == 0, "{} is not running!".format(syncd_name)

    swss_dockers = duthost.get_swss_docker_names()
    for swss in swss_dockers:
        orchagent_res = duthost.shell("docker exec -i {} ps aux | grep /usr/bin/orchagent".format(swss))
        assert orchagent_res[u'rc'] == 0, "Orchagent is not running in {}!".format(swss)

def check_multi_npu_links_up(duthost, cfg_file_path=None):
    npus = duthost.num_npus()
    for npu in range(0,npus):
        cfg_file_path = "/etc/sonic/config_db{}.json".format(npu)
        namespace = "asic"+str(npu)
        config_facts = duthost.config_facts(
            host=duthost.hostname,
            source="persistent",
            filename=cfg_file_path)['ansible_facts']
        admin_up_ports = { key:value for (key,value) in config_facts['PORT'].items() if value.get('admin_status', 'down') == 'up' }
        ports = admin_up_ports.keys()
        verify_port_multi_npu(duthost, namespace,ports)
       
def check_links_up(duthost):
    # for multi-npu platforms we have one Namespace per NPU.
    # the ansible module setup doesn't support Namespaces, so we will be unable
    # to the get the interfaces binded to network namespaces.
    # for multi-npu platform, the interface state will got from the DUT.
    if duthost.num_npus() > 1:
        check_multi_npu_links_up(duthost)
        
    config_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']
    host_facts = duthost.setup()['ansible_facts']

    admin_up_ports = { key:value for (key,value) in config_facts['PORT'].items() if value.get('admin_status', 'down') == 'up' }
    ports = admin_up_ports.keys()
    verify_port(host_facts, ports)
