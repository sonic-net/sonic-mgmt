# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
from ._version import LooseVersion
__metaclass__ = type


class CommandResolver():
    def __init__(self, server_implementation, server_version):
        self.server_implementation = server_implementation
        self.server_version = LooseVersion(server_version)

    def resolve_command(self, command):
        """
        Resolves the appropriate SQL command based on the server implementation and version.

        Parameters:
        command (str): The base SQL command to be resolved (e.g., "SHOW SLAVE HOSTS").

        Returns:
        str: The resolved SQL command suitable for the given server implementation and version.

        Raises:
        ValueError: If the command is not supported or recognized.

        Example:
        Given a server implementation `mysql` and server version `8.0.23`, and a command `SHOW SLAVE HOSTS`,
        the method will resolve the command based on the following table of versions:

        Table:
            [
                ("mysql", "default", "SHOW SLAVES HOSTS default"),
                ("mysql", "5.7.0", "SHOW SLAVES HOSTS"),
                ("mysql", "8.0.22", "SHOW REPLICAS"),
                ("mysql", "8.4.0", "SHOW REPLICAS  8.4"),
                ("mariadb", "10.5.1", "SHOW REPLICAS HOSTS"),
            ]

        Example usage:
        >>> resolver = CommandResolver("mysql", "8.0.23")
        >>> resolver.resolve_command("SHOW SLAVE HOSTS")
        'SHOW REPLICAS'

        In this example, the resolver will:
        - Filter and sort applicable versions: [
            ("8.4.0", "SHOW REPLICAS  8.4"),
            ("8.0.22", "HOW REPLICAS"),
            ("5.7.0", "SHOW SLAVES HOSTS")
          ]

        - Iterate through the sorted list and find the first version less than or equal to 8.0.23,
          which is 8.0.22, and return the corresponding command.
        """

        # Convert the command to uppercase to ensure case-insensitive lookup
        command = command.upper()

        commands = {
            "SHOW MASTER STATUS": {
                ("mysql", "default"): "SHOW MASTER STATUS",
                ("mariadb", "default"): "SHOW MASTER STATUS",
                ("mysql", "8.2.0"): "SHOW BINARY LOG STATUS",
                ("mariadb", "10.5.2"): "SHOW BINLOG STATUS",
            },
            "SHOW SLAVE STATUS": {
                ("mysql", "default"): "SHOW SLAVE STATUS",
                ("mariadb", "default"): "SHOW SLAVE STATUS",
                ("mysql", "8.0.22"): "SHOW REPLICA STATUS",
                ("mariadb", "10.5.1"): "SHOW REPLICA STATUS",
            },
            "SHOW SLAVE HOSTS": {
                ("mysql", "default"): "SHOW SLAVE HOSTS",
                ("mariadb", "default"): "SHOW SLAVE HOSTS",
                ("mysql", "8.0.22"): "SHOW REPLICAS",
                ("mariadb", "10.5.1"): "SHOW REPLICA HOSTS",
            },
            "CHANGE MASTER": {
                ("mysql", "default"): "CHANGE MASTER",
                ("mariadb", "default"): "CHANGE MASTER",
                ("mysql", "8.0.23"): "CHANGE REPLICATION SOURCE",
            },
            "MASTER_HOST": {
                ("mysql", "default"): "MASTER_HOST",
                ("mariadb", "default"): "MASTER_HOST",
                ("mysql", "8.0.23"): "SOURCE_HOST",
            },
            "MASTER_USER": {
                ("mysql", "default"): "MASTER_USER",
                ("mariadb", "default"): "MASTER_USER",
                ("mysql", "8.0.23"): "SOURCE_USER",
            },
            "MASTER_PASSWORD": {
                ("mysql", "default"): "MASTER_PASSWORD",
                ("mariadb", "default"): "MASTER_PASSWORD",
                ("mysql", "8.0.23"): "SOURCE_PASSWORD",
            },
            "MASTER_PORT": {
                ("mysql", "default"): "MASTER_PORT",
                ("mariadb", "default"): "MASTER_PORT",
                ("mysql", "8.0.23"): "SOURCE_PORT",
            },
            "MASTER_CONNECT_RETRY": {
                ("mysql", "default"): "MASTER_CONNECT_RETRY",
                ("mariadb", "default"): "MASTER_CONNECT_RETRY",
                ("mysql", "8.0.23"): "SOURCE_CONNECT_RETRY",
            },
            "MASTER_LOG_FILE": {
                ("mysql", "default"): "MASTER_LOG_FILE",
                ("mariadb", "default"): "MASTER_LOG_FILE",
                ("mysql", "8.0.23"): "SOURCE_LOG_FILE",
            },
            "MASTER_LOG_POS": {
                ("mysql", "default"): "MASTER_LOG_POS",
                ("mariadb", "default"): "MASTER_LOG_POS",
                ("mysql", "8.0.23"): "SOURCE_LOG_POS",
            },
            "MASTER_DELAY": {
                ("mysql", "default"): "MASTER_DELAY",
                ("mariadb", "default"): "MASTER_DELAY",
                ("mysql", "8.0.23"): "SOURCE_DELAY",
            },
            "MASTER_SSL": {
                ("mysql", "default"): "MASTER_SSL",
                ("mariadb", "default"): "MASTER_SSL",
                ("mysql", "8.0.23"): "SOURCE_SSL",
            },
            "MASTER_SSL_CA": {
                ("mysql", "default"): "MASTER_SSL_CA",
                ("mariadb", "default"): "MASTER_SSL_CA",
                ("mysql", "8.0.23"): "SOURCE_SSL_CA",
            },
            "MASTER_SSL_CAPATH": {
                ("mysql", "default"): "MASTER_SSL_CAPATH",
                ("mariadb", "default"): "MASTER_SSL_CAPATH",
                ("mysql", "8.0.23"): "SOURCE_SSL_CAPATH",
            },
            "MASTER_SSL_CERT": {
                ("mysql", "default"): "MASTER_SSL_CERT",
                ("mariadb", "default"): "MASTER_SSL_CERT",
                ("mysql", "8.0.23"): "SOURCE_SSL_CERT",
            },
            "MASTER_SSL_KEY": {
                ("mysql", "default"): "MASTER_SSL_KEY",
                ("mariadb", "default"): "MASTER_SSL_KEY",
                ("mysql", "8.0.23"): "SOURCE_SSL_KEY",
            },
            "MASTER_SSL_CIPHER": {
                ("mysql", "default"): "MASTER_SSL_CIPHER",
                ("mariadb", "default"): "MASTER_SSL_CIPHER",
                ("mysql", "8.0.23"): "SOURCE_SSL_CIPHER",
            },
            "MASTER_SSL_VERIFY_SERVER_CERT": {
                ("mysql", "default"): "MASTER_SSL_VERIFY_SERVER_CERT",
                ("mariadb", "default"): "MASTER_SSL_VERIFY_SERVER_CERT",
                ("mysql", "8.0.23"): "SOURCE_SSL_VERIFY_SERVER_CERT",
            },
            "MASTER_AUTO_POSITION": {
                ("mysql", "default"): "MASTER_AUTO_POSITION",
                ("mariadb", "default"): "MASTER_AUTO_POSITION",
                ("mysql", "8.0.23"): "SOURCE_AUTO_POSITION",
            },
            "RESET MASTER": {
                ("mysql", "default"): "RESET MASTER",
                ("mariadb", "default"): "RESET MASTER",
                ("mysql", "8.4.0"): "RESET BINARY LOGS AND GTIDS",
            },
            # Add more command mappings here
        }

        if command in commands:
            cmd_syntaxes = commands[command]
            applicable_versions = [(v, cmd) for (impl, v), cmd in cmd_syntaxes.items() if impl == self.server_implementation and v != 'default']
            applicable_versions.sort(reverse=True, key=lambda x: LooseVersion(x[0]))

            for version, cmd in applicable_versions:
                if self.server_version >= LooseVersion(version):
                    return cmd

            return cmd_syntaxes[(self.server_implementation, "default")]
        raise ValueError("Unsupported command: %s" % command)
