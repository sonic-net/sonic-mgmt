import json
import logging
import pytest

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)

LOOP_TIMES_LEVEL_MAP = {
    'debug': 10,
    'basic': 1000,
    'confident': 10000
}

# Template json file used to test scale rules
IP_ACL_FILE = "/tmp/acltb_test_stress_acl.json"
IP_ACL_BASH_TEMPLATE = "acl/templates/acltb_test_stress_acl.sh"
IP_ACL_BASH_FILE = "/tmp/acltb_test_stress_acl.sh"
IP_ACL_BASH_LOG_FILE = "/tmp/acltb_test_stress_acl.log"


def generate_acl_rule(duthost, ip_type):
    """
    Generate acl rule with template json file
    """
    rules_data = {}
    ip_acl_entry = {}

    ip_type == "ipv4"
    acl_entry = {}
    acl_entry[1] = {
                    "actions": {
                        "config": {
                            "forwarding-action": "ACCEPT"
                        }
                    },
                    "config": {
                        "sequence-id": 1
                    },
                    "ip": {
                        "config": {
                            "source-ip-address": "20.0.0.1/32"
                        }
                    }
                }
    ip_acl_entry.update(acl_entry)
    rules_data['acl'] = {
        "acl-sets": {
            "acl-set": {
                "IP_STRESS_ACL": {
                    "acl-entries": {
                        "acl-entry": ip_acl_entry
                    }
                }
            }
        }
    }

    duthost.copy(content=json.dumps(rules_data, indent=4), dest=IP_ACL_FILE)


def test_acl_add_del_stress(duthosts, rand_one_dut_hostname, get_function_conpleteness_level):
    duthost = duthosts[rand_one_dut_hostname]
    generate_acl_rule(duthost, "ipv4")
    table_ports = ",".join(duthost.acl_facts()["ansible_facts"]["ansible_acl_facts"]["DATAACL"]["ports"])
    duthost.shell("config acl add table -p {} IP_STRESS_ACL L3".format(table_ports))
    normalized_level = get_function_conpleteness_level
    if normalized_level is None:
        normalized_level = 'basic'
    loop_time = LOOP_TIMES_LEVEL_MAP[normalized_level]

    with open(IP_ACL_BASH_TEMPLATE, 'r') as f:
        file_data = ""
        for line in f:
            if "loop_times=" in line:
                line = "loop_times={}\n".format(loop_time)
            file_data += line
    with open(IP_ACL_BASH_TEMPLATE, 'w') as f:
        f.write(file_data)

    duthost.template(src=IP_ACL_BASH_TEMPLATE, dest=IP_ACL_BASH_FILE)
    duthost.shell("bash {} > {}".format(IP_ACL_BASH_FILE, IP_ACL_BASH_LOG_FILE))
    duthost.fetch(src=IP_ACL_BASH_LOG_FILE, dest="logs/")

    logger.info("End")
