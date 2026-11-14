"""Choose transport for ordinary-user sonic-db-cli reads."""
import json


def redis_reader_cli(duthost, database):
    metadata = json.loads(duthost.command(
        argv=["cat", "/var/run/redis/sonic-db/database_config.json"])["stdout"])
    instance = metadata["INSTANCES"][metadata["DATABASES"][database]["instance"]]
    if int(instance.get("port", 6379)) == 0:
        if not instance.get("unix_socket_path"):
            raise ValueError("TCP-disabled database has no configured Unix socket")
        return "sonic-db-cli -s"
    return "sonic-db-cli"
