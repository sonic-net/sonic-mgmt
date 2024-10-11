import p4runtime_sh.p4runtime as p4sh_rt
import p4runtime_sh.shell as p4sh
import logging
from p4_utils import disable_print, enable_print, init_p4runtime_shell


def insert_underlay_entry(entry, match: str, action: str, next_hop_id: str):
    try:
        logging.info(f"Inserting underlay entry: {match} -> (Action:{action}, NextHopId: {next_hop_id})")

        disable_print()
        entry.match["meta.dst_ip_addr"] = match
        entry.action["packet_action"] = action
        entry.action["next_hop_id"] = next_hop_id
        entry.insert()
    except p4sh_rt.P4RuntimeWriteException as e:
        logging.error(f"Failed to insert underlay entry: {e}")
    finally:
        enable_print()


def init_underlay():
    logging.info("Inserting underlay entries ...")

    underlay_entry = p4sh.TableEntry("dash_ingress.underlay.underlay_routing")(action="dash_ingress.underlay.pkt_act")
    insert_underlay_entry(underlay_entry, "::10.0.0.0/120", action="1", next_hop_id="1")


def init_appliance():
    try:
        logging.info("Inserting appliance entry ...")

        disable_print()
        appliance = p4sh.TableEntry("dash_ingress.appliance")(action="dash_ingress.set_appliance")
        appliance.match["meta.appliance_id"] = "0&&&0xff"
        appliance.action["neighbor_mac"] = "62:d6:08:7f:04:e7"
        appliance.action["mac"] = "22:48:23:27:33:d8"
        appliance.priority = 1
        appliance.insert()
    except p4sh_rt.P4RuntimeWriteException as e:
        logging.error(f"Failed to insert appliance: {e}")
    finally:
        enable_print()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    # sh.global_options["verbose"] = False

    init_p4runtime_shell()
    init_underlay()
    init_appliance()
