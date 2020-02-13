def verify_port(host_facts, ports):
    for port in ports:
        ans_ifname = "ansible_%s" % port
        assert host_facts[ans_ifname]['active'], "Port {} is down!".format(port)

def check_critical_services(duthost):
    syncd_res = duthost.shell("docker exec -i syncd ps aux | grep /usr/bin/syncd")
    orchagent_res = duthost.shell("pgrep orchagent -a")

    assert syncd_res[u'rc'] == 0, "Syncd is not running!"
    assert orchagent_res[u'rc'] == 0, "Orchagent is not running!"

def check_links_up(duthost):
    config_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']
    host_facts = duthost.setup()['ansible_facts']

    admin_up_ports = { key:value for (key,value) in config_facts['PORT'].items() if value.get('admin_status', 'down') == 'up' }
    ports = admin_up_ports.keys()
    verify_port(host_facts, ports)
