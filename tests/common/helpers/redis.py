import logging

logger = logging.getLogger(__name__)


class RedisCli(object):
    """Base class for interface to RedisDb using redis-cli command.

    Attributes:
        host: a SonicHost or SonicAsic.  Commands will be run on this shell.
        database: Redis database number.
        pid: Port number of redis db.
    """

    def __init__(self, host, database=1, pid=6379):
        """Initializes base class with defaults"""
        self.host = host
        self.database = database
        self.pid = pid

    def _cli_prefix(self):
        """Builds opening of redis CLI command for other methods."""
        # return "docker exec -i {docker} redis-cli -p {pid} --raw -n {db} ".format(
        #     docker=self.docker, db=self.database, pid=self.pid)
        return " -p {pid} --raw -n {db} ".format(db=self.database, pid=self.pid)

    def _run_and_check(self, cmd):
        """
        Executes a redis CLI command and checks the output for empty string.

        Args:
            cmd: Full CLI command to run.

        Returns:
            Ansible CLI output dictionary with stdout and stdout_lines keys on success.
            Empty dictionary on error.

        """
        result = self.host.run_redis_cli_cmd(cmd)

        if len(result["stdout_lines"]) == 0:
            logger.error("No command response: %s" % cmd)
            return {}

        return result

    def _run_and_raise(self, cmd):
        """
        Executes a redis CLI command and checks the output for empty string.

        Args:
            cmd: Full CLI command to run.

        Returns:
            Ansible CLI output dictionary with stdout and stdout_lines keys on success.

        Raises:
            Exception: If the command had no output.

        """
        result = self.host.run_redis_cli_cmd(cmd)

        if len(result["stdout_lines"]) == 0:
            logger.error("No command response: %s" % cmd)
            raise Exception("Command: %s returned no response." % cmd)

        return result

    def get_key_value(self, key):
        """
        Executes a redis CLI get command.

        Args:
            key: full name of the key to get.

        Returns:
            The corresponding value of the key.

        Raises:
            RedisKeyNotFound: If the key has no value or is not present.

        """
        cmd = self._cli_prefix() + "get " + key
        result = self._run_and_check(cmd)
        if result == {}:
            raise RedisKeyNotFound("Key: %s not found in rediscmd: %s" % (key, cmd))
        else:
            return result['stdout']

    def hget_key_value(self, key, field):
        """
        Executes a redis CLI hget command.

        Args:
            key: full name of the key to get.
            field: Name of the hash field to get.

        Returns:
            The corresponding value of the key.

        Raises:
            RedisKeyNotFound: If the key or field has no value or is not present.

        """
        cmd = self._cli_prefix() + "hget {} {}".format(key, field)
        result = self._run_and_check(cmd)
        if result == {}:
            raise RedisKeyNotFound("Key: %s, field: %s not found in rediscmd: %s" % (key, field, cmd))
        else:
            return result['stdout']

    def get_and_check_key_value(self, key, value, field=None):
        """
        Executes a redis CLI get or hget and validates the response against a provided field.

        Args:
            key: full name of the key to get.
            value: expected value to test against.
            field: Optional; Name of the hash field to use with hget.

        Returns:
            True if the validation succeeds.

        Raises:
            RedisKeyNotFound: If the key or field has no value or is not present.
            AssertionError: If the fetched value from redis does not match the provided value.

        """
        if field is None:
            result = self.get_key_value(key)
        else:
            result = self.hget_key_value(key, field)

        if str(result).lower() == str(value).lower():
            logger.info("Value {val} matches output {out}".format(val=value, out=result))
            return True
        else:
            raise AssertionError("redis value error: %s != %s key was: %s" % (result, value, key))


class AsicDbCli(RedisCli):
    """
    Class to interface with the ASICDB on a host.

    Attributes:
        host: a SonicHost or SonicAsic.  Commands will be run on this shell.

    """
    ASIC_SWITCH_TABLE = "ASIC_STATE:SAI_OBJECT_TYPE_SWITCH"
    ASIC_SYSPORT_TABLE = "ASIC_STATE:SAI_OBJECT_TYPE_SYSTEM_PORT"
    ASIC_PORT_TABLE = "ASIC_STATE:SAI_OBJECT_TYPE_PORT"
    ASIC_HOSTIF_TABLE = "ASIC_STATE:SAI_OBJECT_TYPE_HOSTIF"
    ASIC_ROUTERINTF_TABLE = "ASIC_STATE:SAI_OBJECT_TYPE_ROUTER_INTERFACE"
    ASIC_NEIGH_ENTRY_TABLE = "ASIC_STATE:SAI_OBJECT_TYPE_NEIGHBOR_ENTRY"

    def __init__(self, host):
        """
        Initializes a connection to the ASIC DB (database 1)
        """
        super(AsicDbCli, self).__init__(host, 1)
        # cache this to improve speed
        self.hostif_portidlist = []

    def get_switch_key(self):
        """Returns a list of keys in the switch table"""
        cmd = self._cli_prefix() + "KEYS %s*" % AsicDbCli.ASIC_SWITCH_TABLE
        return self._run_and_raise(cmd)["stdout_lines"][0]

    def get_system_port_key_list(self):
        """Returns a list of keys in the system port table"""
        cmd = self._cli_prefix() + "KEYS %s*" % AsicDbCli.ASIC_SYSPORT_TABLE
        return self._run_and_raise(cmd)["stdout_lines"]

    def get_port_key_list(self):
        """Returns a list of keys in the local port table"""
        cmd = self._cli_prefix() + "KEYS %s*" % AsicDbCli.ASIC_PORT_TABLE
        return self._run_and_raise(cmd)["stdout_lines"]

    def get_hostif_list(self):
        """Returns a list of keys in the host interface table"""
        cmd = self._cli_prefix() + "KEYS %s:*" % AsicDbCli.ASIC_HOSTIF_TABLE
        return self._run_and_raise(cmd)["stdout_lines"]

    def get_router_if_list(self):
        """Returns a list of keys in the router interface table"""
        cmd = self._cli_prefix() + "KEYS %s:*" % AsicDbCli.ASIC_ROUTERINTF_TABLE
        return self._run_and_raise(cmd)["stdout_lines"]

    def get_neighbor_key_by_ip(self, ipaddr):
        """Returns the key in the neighbor table that is for a specific IP neighbor

        Args:
            ipaddr: The IP address to search for in the neighbor table.

        """
        result = self._run_and_raise(self._cli_prefix() + "KEYS %s*%s*" % (AsicDbCli.ASIC_NEIGH_ENTRY_TABLE, ipaddr))
        neighbor_key = None
        match_str = '"ip":"%s"' % ipaddr
        for key in result["stdout_lines"]:
            if match_str in key:
                neighbor_key = key
                break

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
        cmd = ["/usr/bin/redis-cli", "-n", "1", "HGET", neighbor_key, field]
        if self.host.namespace is not None:
            cmd = ["sudo", "ip", "netns", "exec"] + cmd
        result = self.host.sonichost.shell(argv=cmd)
        logger.debug("neigh result: %s", result['stdout'])
        return result['stdout']

    def get_hostif_portid_oidlist(self, refresh=False):
        """
        Returns a list of portids associated with the hostif entries on the asics.

        Walks through the HOSTIF table getting each port ID from the cache and returns the list.  The list
        is saved so it can be returned directly in subsequent calls.

        Args:
            refresh: Forces the redis DB to be requeried after the first time.


        """
        if self.hostif_portidlist != [] and refresh is False:
            return self.hostif_portidlist

        hostif_keylist = self.get_hostif_list()
        return_list = []
        for hostif_key in hostif_keylist:
            hostif_portid = self.hget_key_value(hostif_key, 'SAI_HOSTIF_ATTR_OBJ_ID')
            return_list.append(hostif_portid)
        self.hostif_portidlist = return_list
        return return_list

    def find_hostif_by_portid(self, portid):
        """
        Returns an HOSTIF table key for the port specified.

        Args:
            portid: A port OID (oid:0x1000000000004)

        Raises:
            RedisKeyNotFound: If no hostif exists with the portid provided.
        """
        hostif_keylist = self.get_hostif_list()
        for hostif_key in hostif_keylist:
            hostif_portid = self.hget_key_value(hostif_key, 'SAI_HOSTIF_ATTR_OBJ_ID')
            if hostif_portid == portid:
                return hostif_key

        raise RedisKeyNotFound("Can't find hostif in asicdb with portid: %s", portid)

    def get_rif_porttype(self, portid):
        """
        Determines whether a specific port OID referenced in a router interface entry is a local port or a system port.

        Args:
            portid: the port oid from SAI_ROUTER_INTERFACE_ATTR_PORT_ID (oid:0x6000000000c4d)

        Returns:
            "hostif" if the port ID has a host interface
            "sysport" if it is a system port.
            "port" if the port ID is in local port table but has no hostif
            "other" if it is not found in any port table
        """
        # could be a localport
        if "%s:%s" % (
                AsicDbCli.ASIC_PORT_TABLE,
                portid) in self.get_port_key_list() and portid in self.get_hostif_portid_oidlist():
            return "hostif"
        # could be a system port
        elif "%s:%s" % (AsicDbCli.ASIC_SYSPORT_TABLE, portid) in self.get_system_port_key_list():
            return "sysport"
        # could be something else
        elif "%s:%s" % (AsicDbCli.ASIC_PORT_TABLE, portid) in self.get_port_key_list():
            return "port"
        else:
            return "other"


class AppDbCli(RedisCli):
    """
    Class to interface with the APPDB on a host.

    Attributes:
        host: a SonicHost or SonicAsic.  Commands will be run on this shell.

    """
    APP_NEIGH_TABLE = "NEIGH_TABLE"

    def __init__(self, host):
        super(AppDbCli, self).__init__(host, 0)

    def get_neighbor_key_by_ip(self, ipaddr):
        """Returns the key in the neighbor table that is for a specific IP neighbor

        Args:
            ipaddr: The IP address to search for in the neighbor table.

        """
        result = self._run_and_raise(self._cli_prefix() + "KEYS %s:*%s*" % (AppDbCli.APP_NEIGH_TABLE, ipaddr))
        neighbor_key = None
        for key in result["stdout_lines"]:
            if key.endswith(ipaddr):
                neighbor_key = key
                break

        return neighbor_key


class VoqDbCli(RedisCli):
    """
    Class to interface with the Chassis VOQ DB on a supervisor.

    Attributes:
        host: a SonicHost instance for a supervisor card.  Commands will be run on this shell.

    """

    def __init__(self, host):
        """Initializes the class with the database parameters and finds the IP address of the database"""
        super(VoqDbCli, self).__init__(host, 12, 6380)
        output = host.command("grep chassis_db_address /etc/sonic/chassisdb.conf")
        # chassis_db_address=10.0.0.16
        self.ip = output['stdout'].split("=")[1]

    def _cli_prefix(self):
        """Builds opening of redis CLI command for other methods."""
        return "-h {ip} -p {pid} --raw -n {db} ".format(
            ip=self.ip, db=self.database, pid=self.pid)

    def get_neighbor_key_by_ip(self, ipaddr):
        """Returns the key in the neighbor table that is for a specific IP neighbor

        Args:
            ipaddr: The IP address to search for in the neighbor table.

        """
        cmd = self._cli_prefix() + 'KEYS "SYSTEM_NEIGH|*%s*"' % ipaddr
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


class RedisKeyNotFound(KeyError):
    """
    Raised when requested keys or fields are not found in the redis db.
    """
    pass
