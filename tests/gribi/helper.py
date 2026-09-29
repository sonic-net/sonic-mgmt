"""
gRIBI client and DUT-state helpers for tests/gribi.

gribid (the gribi container) serves gRIBI on the DUT and programs routes into
orchagent over its ZeroMQ route channel. These helpers drive it with grpcurl
from the PTF container (tests/common/ptf_grpc.py), relying on gRPC reflection,
so no gRIBI protos are needed on either side.
"""
import logging
import time

from tests.common.ptf_grpc import PtfGrpc
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

GRIBI_PORT = 9340
GRIBI_SERVICE = "gribi.gRIBI"
DEFAULT_NI = "DEFAULT"
# Keeps the unresolved-next-hop test short; gribid's default is 30s.
FIB_ACK_TIMEOUT = 10

_election = [0]


def next_election_id():
    """Strictly increasing across the session, so every Modify call wins the election."""
    _election[0] = max(_election[0] + 1, int(time.time() * 1000))
    return _election[0]


def nh_op(op_id, index, ip=None, ni=DEFAULT_NI, op="ADD"):
    """A next hop; a DELETE needs only its index."""
    key = {"index": str(index)}
    if ip:
        key["nextHop"] = {"ipAddress": {"value": ip}}
    return {"id": str(op_id), "networkInstance": ni, "op": op, "nextHop": key}


def nhg_op(op_id, nhg_id, members, ni=DEFAULT_NI, op="ADD"):
    """members: list of (next-hop index, weight)."""
    return {"id": str(op_id), "networkInstance": ni, "op": op,
            "nextHopGroup": {"id": str(nhg_id), "nextHopGroup": {"nextHop": [
                {"index": str(idx), "nextHop": {"weight": {"value": str(w)}}} for idx, w in members]}}}


def route_op(op_id, prefix, nhg_id, ni=DEFAULT_NI, op="ADD"):
    if ":" in prefix:
        return {"id": str(op_id), "networkInstance": ni, "op": op,
                "ipv6": {"prefix": prefix, "ipv6Entry": {"nextHopGroup": {"value": str(nhg_id)}}}}
    return {"id": str(op_id), "networkInstance": ni, "op": op,
            "ipv4": {"prefix": prefix, "ipv4Entry": {"nextHopGroup": {"value": str(nhg_id)}}}}


class GribiClient(object):
    """One Modify session per call: session parameters, election, operations."""

    def __init__(self, ptfhost, duthost, port=GRIBI_PORT):
        self.grpc = PtfGrpc(ptfhost, "{}:{}".format(duthost.mgmt_ip, port), plaintext=True)
        # A route's FIB result can take up to gribid's fib_ack_timeout.
        self.grpc.configure_max_time(FIB_ACK_TIMEOUT + 30)

    def services(self):
        return self.grpc.list_services()

    def modify(self, ops):
        """
        Send ops (in order) in one RIB_AND_FIB_ACK session and return
        {op id: [statuses in arrival order]} plus {op id: error message}.
        """
        election = next_election_id()
        requests = [
            {"params": {"redundancy": "SINGLE_PRIMARY", "persistence": "PRESERVE",
                        "ackType": "RIB_AND_FIB_ACK"}},
            {"electionId": {"low": str(election)}},
        ]
        for op in ops:
            op = dict(op, electionId={"low": str(election)})
            requests.append({"operation": [op]})
        responses = self.grpc.call_bidirectional_streaming(GRIBI_SERVICE, "Modify", requests)

        statuses, errors = {}, {}
        for res in responses:
            for r in res.get("result", []):
                op_id = int(r["id"])
                statuses.setdefault(op_id, []).append(r.get("status"))
                msg = r.get("errorDetails", {}).get("errorMessage")
                if msg:
                    errors[op_id] = msg
        logger.info("gRIBI results: %s errors: %s", statuses, errors)
        return statuses, errors


def final_status(statuses, op_id):
    return statuses.get(op_id, [None])[-1]


def route_key(prefix, vrf=None):
    return "{}:{}".format(vrf, prefix) if vrf else prefix


def state_protocol(duthost, prefix, vrf=None):
    """APPL_STATE_DB ROUTE_TABLE protocol, or None if orchagent holds no such route."""
    out = duthost.shell("sonic-db-cli APPL_STATE_DB HGET 'ROUTE_TABLE:{}' protocol"
                        .format(route_key(prefix, vrf)), module_ignore_errors=True)["stdout"].strip()
    return out or None


def asic_next_hops(duthost, prefix):
    """
    Sorted next-hop IPs of the ASIC route for prefix, via NEXT_HOP or
    NEXT_HOP_GROUP members; None if the ASIC has no such route.
    """
    script = r"""
k=$(sonic-db-cli ASIC_DB KEYS 'ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY:*"dest":"{prefix}"*' | head -1)
[ -z "$k" ] && {{ echo NONE; exit 0; }}
nh=$(sonic-db-cli ASIC_DB HGET "$k" SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID)
ip=$(sonic-db-cli ASIC_DB HGET "ASIC_STATE:SAI_OBJECT_TYPE_NEXT_HOP:$nh" SAI_NEXT_HOP_ATTR_IP)
if [ -n "$ip" ]; then echo "$ip"; exit 0; fi
for m in $(sonic-db-cli ASIC_DB KEYS 'ASIC_STATE:SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER:*'); do
  if [ "$(sonic-db-cli ASIC_DB HGET "$m" SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID)" = "$nh" ]; then
    id=$(sonic-db-cli ASIC_DB HGET "$m" SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID)
    sonic-db-cli ASIC_DB HGET "ASIC_STATE:SAI_OBJECT_TYPE_NEXT_HOP:$id" SAI_NEXT_HOP_ATTR_IP
  fi
done
""".format(prefix=prefix)
    out = duthost.shell(script, module_ignore_errors=True)["stdout"].split()
    if out == ["NONE"]:
        return None
    return sorted(out)


def gribi_listening(duthost, port=GRIBI_PORT):
    out = duthost.shell("ss -ltnH 'sport = :{}'".format(port), module_ignore_errors=True)["stdout"]
    return bool(out.strip())


def restart_gribi(duthost, port=GRIBI_PORT):
    """gribid reads CONFIG_DB (GRIBI, VRF) only at startup."""
    duthost.shell("sudo systemctl reset-failed gribi; sudo systemctl restart gribi")
    return wait_until(60, 2, 0, gribi_listening, duthost, port)


def neighbor_resolved(duthost, ifname, ip):
    out = duthost.shell("sonic-db-cli APPL_DB EXISTS 'NEIGH_TABLE:{}:{}'".format(ifname, ip),
                        module_ignore_errors=True)["stdout"].strip()
    return out == "1"
