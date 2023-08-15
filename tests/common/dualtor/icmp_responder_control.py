import json
import pytest

from tests.common.dualtor.dual_tor_common import mux_config    # noqa F401


ICMP_RESPONDER_PIPE = "/tmp/icmp_responder.pipe"


@pytest.fixture
def pause_icmp_responder(duthost, mux_config, ptfhost, tbinfo):     # noqa F811

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    ptf_port_index = mg_facts['minigraph_ptf_indices']
    ptf_ports = {k: ("eth%s" % v) for k, v in list(ptf_port_index.items())}

    def _pause_icmp_respond(mux_ports):
        if not mux_ports:
            return

        icmp_responder_status = ptfhost.shell("supervisorctl status icmp_responder",
                                              module_ignore_errors=True)["stdout"]
        if "RUNNING" not in icmp_responder_status:
            raise RuntimeError("icmp_responder not running in ptf")

        for mux_port in mux_ports:
            if mux_port not in mux_config:
                raise ValueError("port %s is not configured as mux port" % mux_port)

        pause_dict = {}
        for mux_port in mux_ports:
            ptf_port = ptf_ports[mux_port]
            pause_dict[ptf_port] = True

        pause_message = json.dumps(pause_dict)
        ptfhost.shell("echo '%s' > %s" % (pause_message, ICMP_RESPONDER_PIPE), module_ignore_errors=True)

    yield _pause_icmp_respond

    ptfhost.shell("supervisorctl restart icmp_responder", module_ignore_errors=True)
