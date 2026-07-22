import ipaddress
import logging
import pytest
import json


@pytest.fixture
def ptf_arp_responder(duthost, tbinfo, ptfhost, ptfadapter):
    """
    Set up the ARP responder utility in the PTF container.
    """
    if 'ptf' not in tbinfo["topo"]["name"]:
        yield
        return

    logging.info("Generating ARP responder topology")
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    arp_responder_conf = {}
    for bgp_info in mg_facts["minigraph_bgp"]:
        if (ipaddress.ip_address(bgp_info['peer_addr']).version != 4):
            continue
        ptf_ip_addr = bgp_info['addr']
        for port in mg_facts["minigraph_neighbors"]:
            if (bgp_info['name'] == mg_facts["minigraph_neighbors"][port]['name']):
                ptf_port_idx = mg_facts["minigraph_ptf_indices"][port]
                ptf_mac_addr = ptfadapter.dataplane.get_mac(0, ptf_port_idx).decode("utf-8")
                arp_responder_conf["eth{}".format(ptf_port_idx)] = {
                    "{}".format(ptf_ip_addr): "{}".format(ptf_mac_addr)
                }
                break

    logging.info("Copying ARP responder topology to PTF")
    with open("/tmp/from_t1.json", "w") as ar_config:
        json.dump(arp_responder_conf, ar_config)
    ptfhost.copy(src="/tmp/from_t1.json", dest="/tmp/from_t1.json")

    logging.info("Copying ARP responder to PTF container")

    logging.info("Copying ARP responder config file")
    ptfhost.host.options["variable_manager"].extra_vars.update({"arp_responder_args": ""})
    ptfhost.template(src="templates/arp_responder.conf.j2",
                     dest="/etc/supervisor/conf.d/arp_responder.conf")

    logging.info("Refreshing supervisor and starting ARP responder")
    ptfhost.shell("supervisorctl reread && supervisorctl update")
    ptfhost.shell("supervisorctl restart arp_responder")

    yield

    logging.info("Stopping ARP responder")
    ptfhost.shell("supervisorctl stop arp_responder", module_ignore_errors=True)
