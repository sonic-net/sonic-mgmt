import logging
import json

logger = logging.getLogger(__name__)


ACL_TABLE = "ACL_LINK_DROP_TEST"
ACL_RULE = "DROP_ALL"
ACL_DIR = "egress"


def add_acl_link_drop(duthost, interface):
    """
    Simulate link failure by adding an ACL table with a DROP_ALL rule and
    binding it to the given interface in the egress direction.
    """
    logger.info(
        f"{duthost.hostname} Binding {ACL_TABLE} to "
        f"interface {interface} in the {ACL_DIR} direction"
    )
    duthost.command(
        f"config acl add table "
        f"{ACL_TABLE} L3 -p {interface} -s {ACL_DIR}"
    )

    acl_rule_config = {
        "ACL_RULE": {
            f"{ACL_TABLE}|{ACL_RULE}": {
                "PACKET_ACTION": "DROP",
                "PRIORITY": "1",
                "IP_TYPE": "IP"
            }
        }
    }
    acl_rule_json_path = f"/tmp/{ACL_TABLE}_{ACL_RULE}.json"
    duthost.copy(
        content=json.dumps(acl_rule_config, indent=4),
        dest=acl_rule_json_path
    )
    duthost.shell(f"sonic-cfggen -j {acl_rule_json_path} -w")
    duthost.shell(f"rm -f {acl_rule_json_path}")


def remove_acl_link_drop(duthost, interface):
    """
    Restore link by unbinding the ACL table from the given interface.
    """
    logger.info(
        f"{duthost.hostname} Unbinding "
        f"{ACL_TABLE} from {interface}"
    )

    ports_str = duthost.shell(
        f"sonic-db-cli CONFIG_DB HGET "
        f"'ACL_TABLE|{ACL_TABLE}' 'ports@'"
    )['stdout'].strip()

    if not ports_str:
        logger.warning(
            f"{duthost.hostname} {ACL_TABLE} not found or has no ports"
        )
        return

    current_ports = [p.strip() for p in ports_str.split(",")]

    if interface not in current_ports:
        logger.info(
            f"{duthost.hostname} {ACL_TABLE} "
            f"not bound to {interface}"
        )
        return

    current_ports.remove(interface)

    if current_ports:
        new_ports = ",".join(current_ports)
        duthost.shell(
            f"sonic-db-cli CONFIG_DB HSET "
            f"'ACL_TABLE|{ACL_TABLE}' 'ports@' "
            f"'{new_ports}'"
        )
    else:
        # ACL table is not bound to any ports, remove it
        remove_acl_link_drop_table(duthost)


def remove_acl_link_drop_table(duthost):
    """
    Remove the ACL table and its rules entirely.
    """
    logger.info(
        f"{duthost.hostname} Removing ACL rule via CONFIG_DB"
    )
    duthost.shell(
        f"sonic-db-cli CONFIG_DB DEL "
        f"'ACL_RULE|{ACL_TABLE}|{ACL_RULE}'"
    )

    logger.info(
        f"{duthost.hostname} Removing ACL table via CONFIG_DB"
    )
    duthost.shell(
        f"sonic-db-cli CONFIG_DB DEL "
        f"'ACL_TABLE|{ACL_TABLE}'"
    )
