import logging
import json
from tests.common.helpers.constants import DEFAULT_NAMESPACE
from tests.common.devices.sonic_asic import SonicAsic

logger = logging.getLogger(__name__)


class SonicDbCli(object):
    """Base class for interface to SonicDb using sonic-db-cli command.

        Attributes:
            host: a SonicHost or SonicAsic.  Commands will be run on this shell.
            database: database number.
        """

    def __init__(self, host, database='APPL_DB'):
        """Initializes base class with defaults"""
        self.host = host
        self.database = database

    def _cli_prefix(self):
        """Builds opening of sonic-db-cli command for other methods."""
        return " {db} ".format(db=self.database)

    def _run_and_check(self, cmd):
        """
        Executes a sonic-db CLI command and checks the output for empty string.

        Args:
            cmd: Full CLI command to run.

        Returns:
            Ansible CLI output dictionary with stdout and stdout_lines keys on success.
            Empty dictionary on error.

        """
        logger.debug("SONIC-DB-CLI: %s", cmd)
        result = self.host.run_sonic_db_cli_cmd(cmd)

        if len(result["stdout_lines"]) == 0:
            logger.error("No command response: %s" % cmd)
            return {}

        return result

    def _run_and_raise(self, cmd):
        """
        Executes a sonic-db CLI command and checks the output for empty string.

        Args:
            cmd: Full CLI command to run.

        Returns:
            Ansible CLI output dictionary with stdout and stdout_lines keys on success.

        Raises:
            Exception: If the command had no output.

        """
        logger.debug("SONIC-DB-CLI: %s", cmd)
        result = self.host.run_sonic_db_cli_cmd(cmd)

        if len(result["stdout_lines"]) == 0:
            logger.warning("No command response: %s" % cmd)
            raise SonicDbNoCommandOutput("Command: %s returned no response." % cmd)

        return result

    def hget_key_value(self, key, field):
        """
        Executes a sonic-db-cli hget command.

        Args:
            key: full name of the key to get.
            field: Name of the hash field to get.

        Returns:
            The corresponding value of the key.
        Raises:
            SonicDbKeyNotFound: If the key or field has no value or is not present.


        """
        cmd = self._cli_prefix() + "hget {} {}".format(key, field)
        result = self._run_and_check(cmd)
        if result == {}:
            raise SonicDbKeyNotFound("Key: %s, field: %s not found in sonic-db cmd: %s" % (key, field, cmd))
        else:
            return result['stdout'].decode('unicode-escape')

    def get_and_check_key_value(self, key, value, field=None):
        """
        Executes a sonic-db CLI get or hget and validates the response against a provided field.

        Args:
            key: full name of the key to get.
            value: expected value to test against.
            field: Optional; Name of the hash field to use with hget.

        Returns:
            True if the validation succeeds.

        Raises:
            SonicDbKeyNotFound: If the key or field has no value or is not present.
            AssertionError: If the fetched value from sonic-db does not match the provided value.

        """
        if field is None:
            raise SonicDbKeyNotFound("Can't do a get_and_check_key_value for key {} with field as None".format(key))
        else:
            result = self.hget_key_value(key, field)

        if str(result).lower() == str(value).lower():
            logger.info("Value {val} matches output {out}".format(val=value, out=result))
            return True
        else:
            raise AssertionError("sonic-db value error: %s != %s key was: %s" % (result, value, key))

    def get_keys(self, table):
        """
        Gets the list of keys in a table.

        Args:
            table: full name of the table for which to get the keys.

            Returns:
                list of keys retrieved

            Raises:
                SonicDbKeyNotFound: If the key or field has no value or is not present.

        """
        cmd = self._cli_prefix() + " keys {}".format(table)
        result = self._run_and_check(cmd)
        if result == {}:
            raise SonicDbKeyNotFound("No keys for %s found in sonic-db cmd: %s" % (table, cmd))
        else:
            return result['stdout'].decode('unicode-escape')

    def dump(self, table):
        """
        Dumps and entire table with sonic-db-dump.

        Args:
            table: The table to dump.

        Returns:
            Dictionary containing the parsed json output of the sonic-db-dump.

        """
        cli = "sonic-db-dump"
        cmd_str = ""

        cmd_str += "-n {db} -y -k *{t}*".format(db=self.database, t=table)

        # We are on an asic, it could be single asic card, or multiasic and need a namespace.
        if isinstance(self.host, SonicAsic):
            if self.host.namespace != DEFAULT_NAMESPACE:
                cmd = "sudo ip netns exec {} {} {}".format(self.host.namespace, cli, cmd_str)
                output = self.host.sonichost.command(cmd)
            # for single asic platform
            else:
                cmd = cli + " " + cmd_str
                output = self.host.sonichost.command(cmd)
        else:
            # We are on a sonichost, no namespace required.
            cmd = cli + " " + cmd_str
            output = self.host.sonichost.command(cmd)

        parsed = json.loads(output["stdout"])
        return parsed


class AsicDbCli(SonicDbCli):
    """
    Class to interface with the ASICDB on a host.

    Attributes:
        host: a SonicHost or SonicAsic.  Commands will be run on this shell.

    """
    ASIC_SWITCH_TABLE = "ASIC_STATE:SAI_OBJECT_TYPE_SWITCH"
    ASIC_SYSPORT_TABLE = "ASIC_STATE:SAI_OBJECT_TYPE_SYSTEM_PORT"
    ASIC_PORT_TABLE = "ASIC_STATE:SAI_OBJECT_TYPE_PORT"
    ASIC_HOSTIF_TABLE = "ASIC_STATE:SAI_OBJECT_TYPE_HOSTIF"
    ASIC_LAG_TABLE = "ASIC_STATE:SAI_OBJECT_TYPE_LAG"
    ASIC_LAG_MEMBER_TABLE = "ASIC_STATE:SAI_OBJECT_TYPE_LAG_MEMBER"
    ASIC_ROUTERINTF_TABLE = "ASIC_STATE:SAI_OBJECT_TYPE_ROUTER_INTERFACE"
    ASIC_NEIGH_ENTRY_TABLE = "ASIC_STATE:SAI_OBJECT_TYPE_NEIGHBOR_ENTRY"

    def __init__(self, host):
        """
        Initializes a connection to the ASIC DB (database 1)
        """
        super(AsicDbCli, self).__init__(host, 'ASIC_DB')
        # cache this to improve speed
        self.hostif_portidlist = []
        self.hostif_table = []
        self.system_port_key_list = []
        self.port_key_list = []
        self.lagid_key_list = []

    def get_switch_key(self):
        """Returns a list of keys in the switch table"""
        cmd = self._cli_prefix() + "KEYS %s*" % AsicDbCli.ASIC_SWITCH_TABLE
        return self._run_and_raise(cmd)["stdout_lines"][0]

    def get_system_port_key_list(self, refresh=False):
        """Returns a list of keys in the system port table"""
        if self.system_port_key_list != [] and refresh is False:
            return self.system_port_key_list

        cmd = self._cli_prefix() + "KEYS %s*" % AsicDbCli.ASIC_SYSPORT_TABLE
        self.system_port_key_list = self._run_and_raise(cmd)["stdout_lines"]
        return self.system_port_key_list

    def get_port_key_list(self, refresh=False):
        """Returns a list of keys in the local port table"""

        if self.port_key_list != [] and refresh is False:
            return self.port_key_list

        cmd = self._cli_prefix() + "KEYS %s*" % AsicDbCli.ASIC_PORT_TABLE
        self.port_key_list = self._run_and_raise(cmd)["stdout_lines"]
        return self.port_key_list

    def get_hostif_list(self):
        """Returns a list of keys in the host interface table"""
        cmd = self._cli_prefix() + "KEYS %s:*" % AsicDbCli.ASIC_HOSTIF_TABLE
        return self._run_and_raise(cmd)["stdout_lines"]

    def get_asic_db_lag_list(self, refresh=False):
        """Returns a list of keys in the lag table"""
        if self.lagid_key_list != [] and refresh is False:
            return self.lagid_key_list

        cmd = self._cli_prefix() + "KEYS %s:*" % AsicDbCli.ASIC_LAG_TABLE
        self.lagid_key_list =self._run_and_raise(cmd)["stdout_lines"]
        return self.lagid_key_list

    def get_asic_db_lag_member_list(self):
        """Returns a list of keys in the lag member table"""
        cmd = self._cli_prefix() + "KEYS %s:*" % AsicDbCli.ASIC_LAG_MEMBER_TABLE
        return self._run_and_raise(cmd)["stdout_lines"]

    def get_router_if_list(self):
        """Returns a list of keys in the router interface table"""
        cmd = self._cli_prefix() + "KEYS %s:*" % AsicDbCli.ASIC_ROUTERINTF_TABLE
        return self._run_and_raise(cmd)["stdout_lines"]

    def get_neighbor_list(self):
        """Returns a list of keys in the neighbor table"""
        cmd = self._cli_prefix() + "KEYS %s:*" % AsicDbCli.ASIC_NEIGH_ENTRY_TABLE
        return self._run_and_raise(cmd)["stdout_lines"]

    def get_neighbor_key_by_ip(self, ipaddr):
        """Returns the key in the neighbor table that is for a specific IP neighbor

        Args:
            ipaddr: The IP address to search for in the neighbor table.

        """
        result = self._run_and_raise(self._cli_prefix() + "KEYS %s*%s*" % (AsicDbCli.ASIC_NEIGH_ENTRY_TABLE, ipaddr))
        match_str = '"ip":"%s"' % ipaddr
        for key in result["stdout_lines"]:
            if match_str in key:
                neighbor_key = key
                break
        else:
            raise SonicDbKeyNotFound("Did not find key: %s*%s* in asicdb" % (AsicDbCli.ASIC_NEIGH_ENTRY_TABLE, ipaddr))

        return neighbor_key

    def get_neighbor_value(self, neighbor_key, field):
        """
        Returns a value of a field in the neighbor table.

        Note:
            The structure of the keys in this table cause the command() method to fail, so this function uses shell() to
            retrieve the command output.

        Args:
            neighbor_key: The full key of the neighbor table.
            field: The field to get in the neighbor hash table.
        """
        cmd = "%s ASIC_DB HGET '%s' %s" % (self.host.sonic_db_cli, neighbor_key, field)

        result = self.host.sonichost.shell(cmd)
        return result['stdout']

    def get_hostif_table(self, refresh=False):
        """
        Returns a fresh hostif table if refresh is true, else returns the entry from cache.  Initializes instance
        table on first run.

        Args:
            refresh: If True, get a fresh copy from the DUT.

        Returns:
            The table dump of ASIC_HOSTIF_TABLE

        """

        if self.hostif_table != [] and refresh is False:
            hostif_table = self.hostif_table
        else:
            hostif_table = self.dump("%s:" % AsicDbCli.ASIC_HOSTIF_TABLE)
            self.hostif_table = hostif_table

        return hostif_table

    def get_hostif_portid_oidlist(self, refresh=False):
        """
        Returns a list of portids associated with the hostif entries on the asics.

        Walks through the HOSTIF table getting each port ID from the cache and returns the list.  The list
        is saved so it can be returned directly in subsequent calls.

        Args:
            refresh: Forces the DB to be queried after the first time.


        """
        if self.hostif_portidlist != [] and refresh is False:
            return self.hostif_portidlist

        hostif_table = self.get_hostif_table(refresh)

        return_list = []
        for hostif_key in hostif_table.keys():
            hostif_portid = hostif_table[hostif_key]['value']['SAI_HOSTIF_ATTR_OBJ_ID']
            return_list.append(hostif_portid)
        self.hostif_portidlist = return_list
        return return_list

    def find_hostif_by_portid(self, portid, refresh=False):
        """
        Returns an HOSTIF table key for the port specified.

        Args:
            portid: A port OID (oid:0x1000000000004)
            refresh: Forces the DB to be queried after the first time.

        Raises:
            SonicDbKeyNotFound: If no hostif exists with the portid provided.
        """
        hostif_table = self.get_hostif_table(refresh)

        for hostif_key in hostif_table:
            hostif_portid = hostif_table[hostif_key]['value']['SAI_HOSTIF_ATTR_OBJ_ID']
            if hostif_portid == portid:
                return hostif_key

        raise SonicDbKeyNotFound("Can't find hostif in asicdb with portid: %s", portid)

    def get_rif_porttype(self, portid, refresh=False):
        """
        Determines whether a specific port OID referenced in a router interface entry is a local port or a system port.

        Args:
            portid: the port oid from SAI_ROUTER_INTERFACE_ATTR_PORT_ID (oid:0x6000000000c4d)
            refresh: Forces the DB to be queried after the first time.

        Returns:
            "hostif" if the port ID has a host interface
            "sysport" if it is a system port.
            "port" if the port ID is in local port table but has no hostif (inband)
            "lag" if the portid is a portchannel.
            "other" if it is not found in any port table
        """

        port_key_list = self.get_port_key_list(refresh=refresh)
        system_port_keylist = self.get_system_port_key_list(refresh=refresh)
        lag_keylist = self.get_asic_db_lag_list(refresh=refresh)

        # could be a frontpanel port
        if "%s:%s" % (
                AsicDbCli.ASIC_PORT_TABLE,
                portid) in port_key_list and portid in self.get_hostif_portid_oidlist():
            return "hostif"
        # could be a system port
        elif "%s:%s" % (AsicDbCli.ASIC_SYSPORT_TABLE, portid) in system_port_keylist:
            return "sysport"
        # could be a lag
        elif "%s:%s" % (AsicDbCli.ASIC_LAG_TABLE, portid) in lag_keylist:
            return "lag"
        # could be something else
        elif "%s:%s" % (AsicDbCli.ASIC_PORT_TABLE, portid) in port_key_list:
            return "port"
        else:
            return "other"

    def dump_neighbor_table(self):
        """
        Dumps out the ASIC neighbor table and returns the parsed dictionary.
        """
        return self.dump(AsicDbCli.ASIC_NEIGH_ENTRY_TABLE)


class AppDbCli(SonicDbCli):
    """
    Class to interface with the APPDB on a host.

    Attributes:
        host: a SonicHost or SonicAsic.  Commands will be run on this shell.

    """
    APP_NEIGH_TABLE = "NEIGH_TABLE"
    APP_LAG_TABLE = "LAG_TABLE"
    APP_LAG_MEMBER_TABLE = "LAG_MEMBER_TABLE"

    def __init__(self, host):
        super(AppDbCli, self).__init__(host, 'APPL_DB')

    def get_neighbor_key_by_ip(self, ipaddr):
        """Returns the key in the neighbor table that is for a specific IP neighbor

        Args:
            ipaddr: The IP address to search for in the neighbor table.

        """
        result = self._run_and_raise(self._cli_prefix() + "KEYS %s:*%s" % (AppDbCli.APP_NEIGH_TABLE, ipaddr))
        neighbor_key = None
        for key in result["stdout_lines"]:
            if key.endswith(ipaddr):
                neighbor_key = key
                break

        return neighbor_key

    def get_app_db_lag_list(self):
        """
        Retuns lag list in app db
        """
        result = self._run_and_raise(self._cli_prefix() + "KEYS *%s*" % AppDbCli.APP_LAG_TABLE)
        return result["stdout_lines"]

    def get_app_db_lag_member_list(self):
        """
        return lag member list in app db
        """
        result = self._run_and_raise(self._cli_prefix() + "KEYS *{}:*".format(AppDbCli.APP_LAG_MEMBER_TABLE))
        return result["stdout_lines"]

    def dump_neighbor_table(self):
        """
        Dumps out the APP DB neighbor table and returns the parsed dictionary.
        """
        return self.dump(AppDbCli.APP_NEIGH_TABLE)


class VoqDbCli(SonicDbCli):
    """
    Class to interface with the Chassis VOQ DB on a supervisor.

    Attributes:
        host: a SonicHost instance for a supervisor card.  Commands will be run on this shell.

    """
    SYSTEM_LAG_TABLE = "SYSTEM_LAG_TABLE"
    SYSTEM_LAG_MEMBER_TABLE = "SYSTEM_LAG_MEMBER_TABLE"
    SYSTEM_NEIGHBOR_TABLE = "SYSTEM_NEIGH"

    def __init__(self, host):
        """Initializes the class with the database parameters and finds the IP address of the database"""
        super(VoqDbCli, self).__init__(host, 'CHASSIS_APP_DB')
        output = host.command("grep chassis_db_address /etc/sonic/chassisdb.conf")
        self.ip = output['stdout'].split("=")[1]

    def get_neighbor_key_by_ip(self, ipaddr):
        """Returns the key in the neighbor table that is for a specific IP neighbor

        Args:
            ipaddr: The IP address to search for in the neighbor table.

        """
        cmd = self._cli_prefix() + 'KEYS "%s|*%s"' % (VoqDbCli.SYSTEM_NEIGHBOR_TABLE, ipaddr)
        result = self._run_and_raise(cmd)
        neighbor_key = None
        for key in result["stdout_lines"]:
            if key.endswith(ipaddr):
                neighbor_key = key
                break

        return neighbor_key

    def get_router_interface_id(self, slot, asic, port):
        """Returns the router OID stored in the router interface table entry for the provided entry.

        Args:
            slot: slot of the router interface in either numeric or text. (3 or Slot3)
            asic: ASIC number of the router interface in either numeric or text (0 or Asic0)
            port: Full text of port (Ethernet17)


        """
        slot = str(slot)
        if slot.isdigit():
            slot_str = "Linecard" + slot
        else:
            slot_str = slot

        asic = str(asic)
        if asic.isdigit():
            asic_str = "Asic" + asic
        else:
            asic_str = asic

        key = "SYSTEM_INTERFACE|{}|{}|{}".format(slot_str, asic_str, port)
        return self.hget_key_value(key, "rif_id")

    def get_lag_list(self):
        """Returns a list of keys in the system lag table"""
        cmd = self._cli_prefix() + "KEYS *{}*".format(VoqDbCli.SYSTEM_LAG_TABLE)
        return self._run_and_raise(cmd)["stdout_lines"]

    def get_lag_member_list(self):
        """Returns a list of keys in the ststem lag member table"""
        cmd = self._cli_prefix() + "KEYS *{}*".format(VoqDbCli.SYSTEM_LAG_MEMBER_TABLE)
        return self._run_and_raise(cmd)["stdout_lines"]

    def dump_neighbor_table(self):
        """
        Dumps out the Chassis APP DB neighbor table and returns the parsed dictionary.
        """
        return self.dump(VoqDbCli.SYSTEM_NEIGHBOR_TABLE)


class SonicDbKeyNotFound(KeyError):
    """
    Raised when requested keys or fields are not found in the db.
    """
    pass


class SonicDbNoCommandOutput(Exception):
    """
    Raised when no output is generated by the sonic-db-cli command.
    """
    pass
