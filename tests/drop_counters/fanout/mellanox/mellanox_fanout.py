import pytest
from ..fanout_base import BaseFanoutHandler

MAX_OPENFLOW_RULE_ID = 65535
RUN_ANSIBLE_PLAYBOOK = "cd {ansible_path}; ansible-playbook {playbook} -i lab -l {fanout_host} --extra-vars \"{extra_vars}\" -vvvvv"
# Ansible config files
LAB_CONNECTION_GRAPH = os.path.normpath((os.path.join(os.path.dirname(__file__), "../../../../ansible/files/lab_connection_graph.xml")))
ANSIBLE_ROOT = os.path.normpath((os.path.join(__file__, "../../../../../ansible")))
# Ansible playbook which executes Jinja template
ANSIBLE_PLAYBOOK = os.path.join(os.path.dirname(__file__), "exec_template.yml")
# Jinja template which delete specific openflow rule
DEL_RULE_TEMPLATE = os.path.join(os.path.dirname(__file__), "mlnx_del_of_rule.j2")


class FanoutHandler(BaseFanoutHandler):
    def __init__(self, testbed_devices):
        self.initialized = False
        self.rule_id = MAX_OPENFLOW_RULE_ID
        # Ansible localhost fixture which calls ansible playbook on the local host
        self.ansible_localhost = testbed_devices["localhost"]

        dut_facts = self.ansible_localhost.conn_graph_facts(host=testbed_devices["dut"].hostname, filename=LAB_CONNECTION_GRAPH)["ansible_facts"]
        self.fanout_host = dut_facts["device_conn"]["Ethernet0"]["peerdevice"]
        fanout_facts = self.ansible_localhost.conn_graph_facts(host=self.fanout_host, filename=LAB_CONNECTION_GRAPH)["ansible_facts"]

        self.fanout_trunk_port = None
        for iface, iface_info in fanout_facts["device_port_vlans"].items():
            if iface_info["mode"] == "Trunk":
                self.fanout_trunk_port = iface[iface.find("/") + 1:]
                break
        else:
            raise Exception("Unable to identify Fanout Trunk port")

    def update_config(self, **kwargs):
        """
        Execute Jinja template on fanout switch which creates openflow rule.
        @kwargs: Parameters used as 'extra-vars' for 'ansible-playbook' CLI utility.
        """
        for attempt in range(100):
            kwargs["rule_id"] = self.rule_id
            kwargs["trunk_port"] = "eth{}".format(self.fanout_trunk_port)
            extra_vars = ""
            for key, value in kwargs.items():
                extra_vars += "{}={} ".format(key, value)

            add_flow = RUN_ANSIBLE_PLAYBOOK.format(ansible_path=ANSIBLE_ROOT, playbook=ANSIBLE_PLAYBOOK,
                                                        fanout_host=self.fanout_host, extra_vars=extra_vars)

            res = self.ansible_localhost.shell(add_flow)
            if res["rc"] != 0:
                raise Exception("Unable to add openflow rule\n{}".format(res["stdout"]))

            if "already exist" in res["stdout"]:
                self.rule_id = random.randint(300, 65500)
                continue
            break
        else:
            raise Exception("Unable to add openflow rule. To many rules already exist.\n{}".format(res["stdout"]))
        self.initialized = True

    def restore_config(self):
        """ Delete openflow rule to clear previous configuration """
        if self.initialized:
            del_flow = RUN_ANSIBLE_PLAYBOOK.format(ansible_path=ANSIBLE_ROOT, playbook=ANSIBLE_PLAYBOOK,
                                                        fanout_host=self.fanout_host,
                                                        extra_vars="rule_id={} template_path={}".format(self.rule_id,
                                                                                                DEL_RULE_TEMPLATE))
            res = self.ansible_localhost.shell(del_flow)
            if res["rc"] != 0:
                raise Exception("Unable to delete openflow rule\n{}".format(res["stdout"]))
        self.initialized = False
