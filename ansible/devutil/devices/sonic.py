import logging
import yaml

from .ansible_hosts import AnsibleHosts
from .ansible_hosts import RunAnsibleModuleFailed

logger = logging.getLogger(__name__)


class SonicHosts(AnsibleHosts):
    SUPPORTED_UPGRADE_TYPES = ["onie", "sonic"]

    def __init__(self, inventories, host_pattern, options={}, hostvars={}):
        super(SonicHosts, self).__init__(inventories, host_pattern, options=options.copy(), hostvars=hostvars.copy())

    @property
    def sonic_version(self):
        try:
            output = self.command("cat /etc/sonic/sonic_version.yml")
            versions = {}
            for hostname in self.hostnames:
                versions[hostname] = yaml.safe_load(output[hostname]["stdout"])
            return versions
        except Exception as e:
            logger.error("Failed to run `cat /etc/sonic/sonic_version.yml`: {}".format(repr(e)))
            return {}


def upgrade_by_sonic(sonichosts, image_url, disk_used_percent):
    try:
        sonichosts.reduce_and_add_sonic_images(
            disk_used_pcent=disk_used_percent,
            new_image_url=image_url,
            module_attrs={"become": True}
        )
        sonichosts.shell("reboot", module_attrs={"become": True, "async": 300, "poll": 0})
        return True
    except RunAnsibleModuleFailed as e:
        logger.error(
            "SONiC upgrade image failed, devices: {}, url: {}, error: {}".format(
                str(sonichosts.hostnames), image_url, repr(e)
            )
        )
        return False


def upgrade_by_onie(sonichosts, localhost, image_url, pause_time):
    try:
        sonichosts.shell("grub-editenv /host/grub/grubenv set next_entry=ONIE", module_attrs={"become": True})
        sonichosts.shell(
            'sleep 2 && shutdown -r now "Boot into onie."',
            module_attrs={"become": True, "async": 5, "poll": 0}
        )

        for i in range(len(sonichosts.ips)):
            localhost.wait_for(
                host=sonichosts.ips[i],
                port=22,
                state="started",
                search_regex="OpenSSH",
                delay=60 if i == 0 else 0,
                timeout=300,
                module_attrs={"changed_when": False}
            )
        if pause_time > 0:
            localhost.pause(
                seconds=pause_time, prompt="Pause {} seconds for ONIE initialization".format(str(pause_time))
            )
        sonichosts.onie(
            install="yes",
            url=image_url,
            module_attrs={"connection": "onie"}
        )
        return True
    except RunAnsibleModuleFailed as e:
        logger.error(
            "ONIE upgrade image failed, devices: {}, url: {}, error: {}".format(
                str(sonichosts.hostnames), image_url, repr(e)
            )
        )
        return False


def patch_rsyslog(sonichosts):
    rsyslog_conf_files = [
        "/usr/share/sonic/templates/rsyslog.conf.j2",
        "/etc/rsyslog.conf"
    ]

    # Get sonic version, use version of the first host
    sonic_build_version = sonichosts.shell(
        "sonic-cfggen -y /etc/sonic/sonic_version.yml -v build_version"
    ).values()[0]["stdout"]

    # Patch rsyslog to stop sending syslog to production and use new template for remote syslog
    for conf_file in rsyslog_conf_files:
        sonichosts.lineinfile(
            path=conf_file,
            state="present",
            backrefs=True,
            regexp=r"(^[^#]*@\[10\.20\.6\.16\]:514)",
            line=r"# \g<1>",
            module_attrs={"become": True}
        )
        sonichosts.lineinfile(
            path=conf_file,
            state="present",
            insertafter="# Define a custom template",
            line=r'$template RemoteSONiCFileFormat,"<%PRI%>1 %TIMESTAMP:::date-rfc3339% %HOSTNAME% %APP-NAME% '
                 r'%PROCID% %MSGID% [origin swVersion=\"{}\"] %msg%\n"'.format(sonic_build_version),
            module_attrs={"become": True}
        )

    # Patch rsyslog.conf.j2 to use new template for remote syslog
    sonichosts.lineinfile(
        path="/usr/share/sonic/templates/rsyslog.conf.j2",
        state="present",
        backrefs=True,
        regex=r"(\*\.\* @\[\{\{ server \}\}\]:514)",
        line=r'\g<1>;RemoteSONiCFileFormat',
        module_attrs={"become": True}
    )

    # Patch rsyslog.conf to use new template for remote syslog
    sonichosts.shell(
        r"sed -E -i 's/(^[^#]*@\[[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\]:514).*$/\1;RemoteSONiCFileFormat/g' "
        "/etc/rsyslog.conf",
        module_attrs={"become": True}
    )

    # Workaround for PR https://msazure.visualstudio.com/One/_git/Networking-acs-buildimage/pullrequest/6631568
    # This PR updated the rsyslog.conf to use a new method for sending out syslog. Need to configure the new method
    # to use RemoteSONiCFileFormat too.
    remote_template = sonichosts.shell(
        "echo `grep -c 'template=\".*SONiCFileFormat\"' /usr/share/sonic/templates/rsyslog.conf.j2`"
    ).values()[0]["stdout"]
    if remote_template == "0":
        for conf_file in rsyslog_conf_files:
            sonichosts.lineinfile(
                path=conf_file,
                state="present",
                backrefs=True,
                regex=r'^(\*\.\* action\(type="omfwd") target=(.*)$',
                line=r'\g<1> template="RemoteSONiCFileFormat" target=\g<2>',
                module_attrs={"become": True}
            )
    elif remote_template != "0":
        for conf_file in rsyslog_conf_files:
            sonichosts.replace(
                dest=conf_file,
                regexp='template=".*SONiCFileFormat"',
                replace='template="RemoteSONiCFileFormat"',
                module_attrs={"become": True}
            )
    sonichosts.shell("systemctl restart rsyslog", module_attrs={"become": True})


def post_upgrade_actions(sonichosts, localhost, disk_used_percent):
    try:
        for i in range(len(sonichosts.ips)):
            localhost.wait_for(
                host=sonichosts.ips[i],
                port=22,
                state="started",
                search_regex="OpenSSH",
                delay=180 if i == 0 else 0,
                timeout=600,
                module_attrs={"changed_when": False}
            )
        localhost.pause(seconds=60, prompt="Wait for SONiC initialization")

        # PR https://github.com/sonic-net/sonic-buildimage/pull/12109 decreased the sshd timeout
        # This change may cause timeout when executing `generate_dump -s yesterday`.
        # Increase this time after image upgrade
        sonichosts.shell(
            'sed -i "s/^ClientAliveInterval [0-9].*/ClientAliveInterval 900/g" /etc/ssh/sshd_config '
            '&& systemctl restart sshd',
            module_attrs={"become": True}
        )

        patch_rsyslog(sonichosts)

        sonichosts.command("config bgp startup all", module_attrs={"become": True})
        sonichosts.command("config save -y", module_attrs={"become": True})
        sonichosts.reduce_and_add_sonic_images(
            disk_used_pcent=disk_used_percent,
            module_attrs={"become": True}
        )
        return True
    except RunAnsibleModuleFailed as e:
        logger.error(
            "Post upgrade actions failed, devices: {}, error: {}".format(str(sonichosts.hostnames), repr(e))
        )
        return False


def upgrade_image(sonichosts, localhost, image_url, upgrade_type="sonic", disk_used_percent=50, onie_pause_time=0):
    if upgrade_type not in sonichosts.SUPPORTED_UPGRADE_TYPES:
        logger.error(
            "Upgrade type '{}' is not in SUPPORTED_UPGRADE_TYPES={}".format(
                upgrade_type, sonichosts.SUPPORTED_UPGRADE_TYPES
            )
        )
        return False

    if upgrade_type == "sonic":
        upgrade_result = upgrade_by_sonic(sonichosts, image_url, disk_used_percent)
    elif upgrade_type == "onie":
        upgrade_result = upgrade_by_onie(sonichosts, localhost, image_url, onie_pause_time)
    if not upgrade_result:
        return False

    return post_upgrade_actions(sonichosts, localhost, disk_used_percent)
