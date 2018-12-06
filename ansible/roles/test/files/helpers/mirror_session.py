import click
from swsssdk import ConfigDBConnector


@click.group()
def cli():
    pass


@cli.command()
@click.argument('session_name', type=click.STRING, required=True)
@click.argument('src_ip', type=click.STRING, required=True)
@click.argument('dst_ip', type=click.STRING, required=True)
@click.argument('gre_type', type=click.STRING, required=True)
@click.argument('dscp', type=click.STRING, required=True)
@click.argument('ttl', type=click.STRING, required=True)
@click.argument('queue', type=click.STRING, required=True)
def create(session_name, src_ip, dst_ip, gre_type, dscp, ttl, queue):
    """
    Create mirror session.
    """
    configdb = ConfigDBConnector()
    configdb.connect()

    session_info = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "gre_type": gre_type,
        "dscp": dscp,
        "ttl": ttl,
        "queue": queue
    }

    configdb.set_entry("MIRROR_SESSION", session_name, session_info)


@cli.command()
@click.argument('session_name', type=click.STRING, required=False)
def delete(session_name):
    """
    Delete mirror session.
    """
    configdb = ConfigDBConnector()
    configdb.connect()

    configdb.set_entry("MIRROR_SESSION", session_name, None)


if __name__ == "__main__":
    cli()
