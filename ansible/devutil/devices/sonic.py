import logging
import time

import yaml

from .ansible_hosts import AnsibleHosts
from .ansible_hosts import RunAnsibleModuleFailed
from .chassis_utils import is_chassis, get_chassis_hostnames, ChassisCardType

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


# Copies the running base-OS /etc/shadow into the freshly installed target
# image's overlay so user credentials (notably "admin") survive the upgrade
# reboot. Best effort: a missing precondition logs and exits 0 rather than
# failing the upgrade.
#
# /host/image-<ver>/rw/etc is the overlayfs upperdir backing the live rootfs, so
# when the target image is the one already running, SRC_SHADOW and TARGET_SHADOW
# address the same data. No identity check detects that reliably, because
# overlayfs numbers the merged path differently depending on when the copy-up
# happened -- which is how cp's (st_dev, st_ino) guard missed it and truncated
# the source it was about to read, costing four DUTs every credential. So the
# write is safe by construction, not by case analysis: the checks below are
# defence in depth and none of them is load-bearing.
_ROLLOVER_SHADOW_SCRIPT = r"""
set -eu
# A missing sonic-installer does not abort here: this is a pipeline, so the exit
# status is head's and the empty result is caught by the -z test below.
TARGET_FW_VER=$(sonic-installer list 2>/dev/null | sed -n 's/^Next: *//p' | head -1)
TARGET_FW_VER=${TARGET_FW_VER#SONiC-OS-}
if [ -z "$TARGET_FW_VER" ]; then
    echo "preserve-shadow: could not determine Next image version; skipping"
    exit 0
fi
# The version is interpolated into a path, so reject anything that is not a
# plain version string.
case "$TARGET_FW_VER" in
    *[!A-Za-z0-9._-]*|*..*)
        echo "preserve-shadow: refusing unexpected Next image version '${TARGET_FW_VER}'; skipping"
        exit 0
        ;;
esac
CURRENT_FW_VER=$(sonic-installer list 2>/dev/null | sed -n 's/^Current: *//p' | head -1)
CURRENT_FW_VER=${CURRENT_FW_VER#SONiC-OS-}
# The clearest signal that the target is the live rootfs, but only available
# when the two images carry different version names.
if [ "$TARGET_FW_VER" = "$CURRENT_FW_VER" ]; then
    echo "preserve-shadow: Next == Current (${TARGET_FW_VER}); target overlay is the live rootfs, nothing to roll over"
    exit 0
fi
SRC_SHADOW=/etc/shadow
SRC_DIR=/etc
TARGET_DIR=/host/image-${TARGET_FW_VER}/rw/etc
TARGET_SHADOW=${TARGET_DIR}/shadow
# -s, not -f: an empty shadow must never be propagated.
if [ ! -s "$SRC_SHADOW" ]; then
    echo "preserve-shadow: /etc/shadow is missing or empty in base OS; skipping"
    exit 0
fi
# Inode only, not the (st_dev, st_ino) pair: overlayfs gives the merged and
# upperdir paths different st_dev, so comparing the pair would never fire. This
# catches a copy-up from an earlier boot and misses one from the current mount.
if [ -d "$TARGET_DIR" ] && \
   [ "$(stat -c %i "$SRC_DIR")" = "$(stat -c %i "$TARGET_DIR")" ]; then
    echo "preserve-shadow: ${TARGET_DIR} is the live ${SRC_DIR}; skipping"
    exit 0
fi
if [ -e "$TARGET_SHADOW" ] && \
   [ "$(stat -c %i "$SRC_SHADOW")" = "$(stat -c %i "$TARGET_SHADOW")" ]; then
    echo "preserve-shadow: ${SRC_SHADOW} and ${TARGET_SHADOW} are the same inode; skipping"
    exit 0
fi
# Decided before anything is written. The old script copied first, then looked
# for admin: in the source it had just truncated, and deleted the target.
if ! grep -q '^admin:' "$SRC_SHADOW"; then
    echo "preserve-shadow: no admin entry in base OS; leaving the target untouched to fall back to the image default"
    exit 0
fi
write_shadow() {
    mkdir -p "$TARGET_DIR" || return 1
    # In TARGET_DIR so that mv is a same-filesystem rename, and therefore
    # atomic; from /tmp it would degrade to copy-then-unlink.
    TMP_SHADOW=$(mktemp "${TARGET_DIR}/.shadow.XXXXXX") || return 1
    # After the assignment, so it is safe under set -u. Once mv succeeds the
    # path is gone and the cleanup is a no-op.
    trap 'rm -f "$TMP_SHADOW"' EXIT
    # cat, never cp: the source is only ever opened for reading, so even a
    # perfect alias cannot destroy it.
    cat "$SRC_SHADOW" > "$TMP_SHADOW" || return 1
    chown root:shadow "$TMP_SHADOW" || return 1
    chmod 0600 "$TMP_SHADOW" || return 1
    mv -f "$TMP_SHADOW" "$TARGET_SHADOW" || return 1
}
echo "preserve-shadow: copying ${SRC_SHADOW} to ${TARGET_SHADOW}"
if write_shadow; then
    echo "preserve-shadow: admin entry found; target admin credential will match base OS"
else
    echo "preserve-shadow: could not write ${TARGET_SHADOW}; target left untouched"
fi
exit 0
"""


def rollover_shadow_to_target_image(sonichosts, target_hosts):
    """Preserve user credentials across an image upgrade.

    Copies the running base-OS /etc/shadow into the freshly-installed target
    image overlay (/host/image-<ver>/rw/etc/shadow). Must run after the target
    image is installed (so the overlay exists) and before the reboot into it.

    Best effort: failures are logged but never fail the upgrade.
    """
    logger.info("preserve-shadow: rolling over /etc/shadow to target image on {}".format(target_hosts))
    try:
        results = sonichosts.shell(
            _ROLLOVER_SHADOW_SCRIPT,
            target_hosts=target_hosts,
            module_attrs={"become": True}
        )
        if isinstance(results, dict):
            for hostname, result in results.items():
                stdout = result.get("stdout", "") if isinstance(result, dict) else result
                logger.info("preserve-shadow: host {} output:\n{}".format(hostname, stdout))
    except RunAnsibleModuleFailed as e:
        logger.error("preserve-shadow: rollover failed (continuing upgrade): {}".format(repr(e)))


def upgrade_by_sonic(sonichosts, localhost, image_url, disk_used_percent, preserve_shadow=False):
    try:
        # Skip upgrade image on DPU hosts
        target_hosts = []
        for hostname in sonichosts.hostnames:
            if "dpu" in hostname.lower():
                logger.info("Skip upgrade image on DPU hosts: {}".format(hostname))
            else:
                target_hosts.append(hostname)

        if len(target_hosts) == 0:
            logger.info("No hosts to upgrade")
            return True

        sonichosts.reduce_and_add_sonic_images(
            disk_used_pcent=disk_used_percent,
            new_image_url=image_url,
            target_hosts=target_hosts,
            module_attrs={"become": True}
        )
        # The target image is now installed and its overlay exists, but the DUT
        # has not rebooted into it yet. This is the only window in which we can
        # roll the current credentials forward into the target image.
        if preserve_shadow:
            rollover_shadow_to_target_image(sonichosts, target_hosts)
        if is_chassis(sonichosts):
            logger.info("Upgrading image on chassis device...")
            # Chassis DUT need to firstly upgrade and reboot supervisor cards.
            # Until supervisor cards back online, then upgrade and reboot line cards.
            rp_hostnames = get_chassis_hostnames(sonichosts, ChassisCardType.SUPERVISOR_CARD)
            sonichosts.shell("reboot", target_hosts=rp_hostnames,
                             module_attrs={"become": True, "async": 300, "poll": 0})
            logger.info("Sleep 900s to wait for supervisor card to be ready...")
            time.sleep(900)
        else:
            sonichosts.shell("reboot", target_hosts=target_hosts,
                             module_attrs={"become": True, "async": 300, "poll": 0})
            is_cisco8000_platform = False
            for hostname in target_hosts:
                cfg_facts = sonichosts.config_facts(host=hostname, source='running')[hostname]
                hwsku = cfg_facts.get('ansible_facts', {}) \
                    .get('DEVICE_METADATA', {}) \
                    .get('localhost', {}) \
                    .get('hwsku', 'unknown')
                logger.info("Host {} has hwsku {}".format(hostname, hwsku))
                if 'Cisco' in hwsku:
                    is_cisco8000_platform = True
            if is_cisco8000_platform:
                logger.info("Sleep 600s before rebooting cisco-8000 device...")
                time.sleep(600)

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


def patch_rsyslog(sonichosts, target_hosts):
    """Patch rsyslog configuration with DPU filtering support."""
    rsyslog_conf_files = [
        "/usr/share/sonic/templates/rsyslog.conf.j2",
        "/etc/rsyslog.conf"
    ]

    # Get sonic version, use version of the first target host
    sonic_build_version = list(sonichosts.shell(
        "sonic-cfggen -y /etc/sonic/sonic_version.yml -v build_version",
        target_hosts=target_hosts
    ).values())[0]["stdout"]

    # Patch rsyslog to stop sending syslog to production and use new template for remote syslog
    for conf_file in rsyslog_conf_files:
        sonichosts.lineinfile(
            path=conf_file,
            state="present",
            backrefs=True,
            regexp=r"(^[^#]*@\[10\.20\.6\.16\]:514)",
            line=r"# \g<1>",
            target_hosts=target_hosts,
            module_attrs={"become": True}
        )
        sonichosts.lineinfile(
            path=conf_file,
            state="present",
            insertafter="# Define a custom template",
            line=r'$template RemoteSONiCFileFormat,"<%PRI%>1 %TIMESTAMP:::date-rfc3339% %HOSTNAME% %APP-NAME% '
                 r'%PROCID% %MSGID% [origin swVersion=\"{}\"] %msg%\n"'.format(sonic_build_version),
            target_hosts=target_hosts,
            module_attrs={"become": True}
        )

    # Patch rsyslog.conf.j2 to use new template for remote syslog
    sonichosts.lineinfile(
        path="/usr/share/sonic/templates/rsyslog.conf.j2",
        state="present",
        backrefs=True,
        regex=r"(\*\.\* @\[\{\{ server \}\}\]:514)",
        line=r'\g<1>;RemoteSONiCFileFormat',
        target_hosts=target_hosts,
        module_attrs={"become": True}
    )

    # Patch rsyslog.conf to use new template for remote syslog
    sonichosts.shell(
        r"sed -E -i 's/(^[^#]*@\[[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\]:514).*$/\1;RemoteSONiCFileFormat/g' "
        "/etc/rsyslog.conf",
        target_hosts=target_hosts,
        module_attrs={"become": True}
    )

    # Workaround for PR https://msazure.visualstudio.com/One/_git/Networking-acs-buildimage/pullrequest/6631568
    # This PR updated the rsyslog.conf to use a new method for sending out syslog. Need to configure the new method
    # to use RemoteSONiCFileFormat too.
    remote_template = list(sonichosts.shell(
        "echo `grep -c 'template=\".*SONiCFileFormat\"' /usr/share/sonic/templates/rsyslog.conf.j2`",
        target_hosts=target_hosts
    ).values())[0]["stdout"]
    if remote_template == "0":
        for conf_file in rsyslog_conf_files:
            sonichosts.lineinfile(
                path=conf_file,
                state="present",
                backrefs=True,
                regex=r'^(\*\.\* action\(type="omfwd") target=(.*)$',
                line=r'\g<1> template="RemoteSONiCFileFormat" target=\g<2>',
                target_hosts=target_hosts,
                module_attrs={"become": True}
            )
    elif remote_template != "0":
        for conf_file in rsyslog_conf_files:
            sonichosts.replace(
                dest=conf_file,
                regexp='template=".*SONiCFileFormat"',
                replace='template="RemoteSONiCFileFormat"',
                target_hosts=target_hosts,
                module_attrs={"become": True}
            )
    sonichosts.shell("systemctl restart rsyslog",
                     target_hosts=target_hosts,
                     module_attrs={"become": True})


def post_upgrade_actions(sonichosts, localhost, disk_used_percent):
    try:
        # Skip post-upgrade actions on DPU hosts
        target_hosts = []
        for hostname in sonichosts.hostnames:
            if "dpu" in hostname.lower():
                logger.info("Skip post-upgrade actions on DPU host: {}".format(hostname))
            else:
                target_hosts.append(hostname)

        if len(target_hosts) == 0:
            logger.info("No hosts for post-upgrade actions")
            return True

        # Calculate target IPs for the filtered hosts
        target_ips = [sonichosts.ips[sonichosts.hostnames.index(hostname)] for hostname in target_hosts]

        for i in range(len(target_ips)):
            localhost.wait_for(
                host=target_ips[i],
                port=22,
                state="started",
                search_regex="OpenSSH",
                delay=180 if i == 0 else 0,
                timeout=600,
                module_attrs={"changed_when": False}
            )
        localhost.pause(seconds=60, prompt="Wait for SONiC initialization")

        # NOTE: Clear Ansible cached facts to avoid using stale data
        # from old SONiC image before upgrade
        sonichosts.meta("clear_facts")

        # PR https://github.com/sonic-net/sonic-buildimage/pull/12109 decreased the sshd timeout
        # This change may cause timeout when executing `generate_dump -s yesterday`.
        # Increase this time after image upgrade
        sonichosts.shell(
            'sed -i "s/^ClientAliveInterval [0-9].*/ClientAliveInterval 900/g" /etc/ssh/sshd_config '
            '&& systemctl restart sshd',
            target_hosts=target_hosts,
            module_attrs={"become": True}
        )

        patch_rsyslog(sonichosts, target_hosts)

        sonichosts.command("config bgp startup all",
                           target_hosts=target_hosts,
                           module_attrs={"become": True})
        sonichosts.command("config save -y",
                           target_hosts=target_hosts,
                           module_attrs={"become": True})
        logger.info("Run reduce_and_add_sonic_images to cleanup disk")
        sonichosts.reduce_and_add_sonic_images(
            disk_used_pcent=disk_used_percent,
            target_hosts=target_hosts,
            module_attrs={"become": True}
        )
        return True
    except RunAnsibleModuleFailed as e:
        logger.error(
            "Post upgrade actions failed, devices: {}, error: {}".format(str(sonichosts.hostnames), repr(e))
        )
        return False


def upgrade_image(sonichosts, localhost, image_url, upgrade_type="sonic", disk_used_percent=50, onie_pause_time=0,
                  preserve_shadow=False):
    if upgrade_type not in sonichosts.SUPPORTED_UPGRADE_TYPES:
        logger.error(
            "Upgrade type '{}' is not in SUPPORTED_UPGRADE_TYPES={}".format(
                upgrade_type, sonichosts.SUPPORTED_UPGRADE_TYPES
            )
        )
        return False

    if upgrade_type == "sonic":
        upgrade_result = upgrade_by_sonic(sonichosts, localhost, image_url, disk_used_percent,
                                          preserve_shadow=preserve_shadow)
    elif upgrade_type == "onie":
        if preserve_shadow:
            logger.warning("preserve-shadow is not applicable to ONIE upgrades "
                           "(no running base OS and no target overlay); ignoring")
        upgrade_result = upgrade_by_onie(sonichosts, localhost, image_url, onie_pause_time)
    if not upgrade_result:
        return False

    return post_upgrade_actions(sonichosts, localhost, disk_used_percent)
