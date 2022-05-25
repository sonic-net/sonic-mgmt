import re

ignore_list = {
    "cp_proc_files": {},
}

copy_proc_files = [
    "/proc/buddyinfo",
    "/proc/cmdline",
    "/proc/consoles",
    "/proc/cpuinfo",
    "/proc/devices",
    "/proc/diskstats",
    "/proc/dma",
    "/proc/interrupts",
    "/proc/iomem",
    "/proc/ioports",
    "/proc/kallsyms",
    "/proc/loadavg",
    "/proc/locks",
    "/proc/meminfo",
    "/proc/misc",
    "/proc/modules",
    "/proc/self/mounts",
    "/proc/self/net",
    "/proc/pagetypeinfo",
    "/proc/partitions",
    "/proc/sched_debug",
    "/proc/slabinfo",
    "/proc/softirqs",
    "/proc/stat",
    "/proc/swaps",
    "/proc/sysvipc",
    "/proc/timer_list",
    "/proc/uptime",
    "/proc/version",
    "/proc/vmallocinfo",
    "/proc/vmstat",
    "/proc/zoneinfo",
]

show_platform_cmds = [
    "show platform syseeprom",
    "show platform psustatus",
    "show platform ssdhealth",
    "show platform temperature",
    "show platform fan",
    "show platform summary",
]

ip_cmds = [
    "ip link",
    "ip addr",
    "ip rule",
    "ip route show table all",
    "ip neigh",
    "ip -s neigh show nud noarp",
]

bridge_cmds = [
    "bridge fdb show",
    "bridge vlan show",
]

frr_cmds = [
    "vtysh{} -c 'show running-config'",
    "vtysh{} -c 'show ip route vrf all'",
    "vtysh{} -c 'show ipv6 route vrf all'",
    "vtysh{} -c 'show zebra fpm stats'",
    "vtysh{} -c 'show zebra dplane detailed'",
    "vtysh{} -c 'show interface vrf all'",
    "vtysh{} -c 'show zebra client summary'",
]


bgp_cmds = [
    "vtysh{} -c 'show ip bgp summary'",
    "vtysh{} -c 'show ip bgp neighbors'",
    "vtysh{} -c 'show ip bgp'",
    "vtysh{} -c 'show bgp ipv6 summary'",
    "vtysh{} -c 'show bgp ipv6 neighbors'",
    "vtysh{} -c 'show bgp ipv6'",
    re.compile('vtysh{}\s+-c \\\\"show ip bgp neighbors .* advertised-routes\\\\"'),
    re.compile('vtysh{}\s+-c \\\\"show ip bgp neighbors .* routes\\\\"'),
    re.compile('vtysh{}\s+-c \\\\"show bgp ipv6 neighbors .* advertised-routes\\\\"'),
    re.compile('vtysh{}\s+-c \\\\"show bgp ipv6 neighbors .* routes\\\\"'),
]

nat_cmds = [
    "iptables -t nat -nv -L",
    "conntrack -j -L",
    "conntrack -j -L | wc",
    "conntrack -L",
    "conntrack -L | wc",
    "show nat config",
]

bfd_cmds = [
    "vtysh{} -c 'show bfd peers'",
    "vtysh{} -c 'show bfd peers counters'",
    "vtysh{} -c 'show bfd peers json'",
    "vtysh{} -c 'show bfd peers counters json'",
]

redis_db_cmds = [
    "{}sonic-db-dump -n 'APPL_DB' -y",
    "{}sonic-db-dump -n 'ASIC_DB' -y",
    "{}sonic-db-dump -n 'COUNTERS_DB' -y",
    "{}sonic-db-dump -n 'CONFIG_DB' -y",
    "{}sonic-db-dump -n 'FLEX_COUNTER_DB' -y",
    "{}sonic-db-dump -n 'STATE_DB' -y",
    "{}sonic-db-dump -n 'COUNTERS_DB' -y",
]

docker_cmds = [
    "docker exec syncd{} saidump",
    "docker stats --no-stream",
    "docker ps -a",
    "docker top pmon",
    "docker exec lldp{} lldpcli show statistics",
    "docker logs bgp{}",
    "docker logs swss{}",
]

docker_cmds_201911 = [
    "docker exec -it syncd{} saidump",
    "docker stats --no-stream",
    "docker ps -a",
    "docker top pmon",
    "docker exec -it lldp{} lldpcli show statistics",
    "docker logs bgp{}",
    "docker logs swss{}",
]

misc_show_cmds = [
    "show services",
    "show reboot-cause",
    "show vlan brief",
    "show version",
    "show interface status -d all",
    "show interface transceiver presence",
    "show interface transceiver eeprom --dom",
    "show ip interface",
    "show interface counters",
    "{}show queue counters",
    "{}netstat -i",
    "{}ifconfig -a",
]

misc_cmds = [
    "systemd-analyze blame",
    "systemd-analyze dump",
    "systemd-analyze plot",
    "sensors",
    "lspci -vvv -xx",
    "lsusb -v",
    "sysctl -a",
    "lldpctl",
    "ps aux",
    "top -b -n 1",
    "free",
    "vmstat 1 5",
    "vmstat -m",
    "vmstat -s",
    "mount",
    "df",
    "dmesg",
    "cat /host/machine.conf",
    "cp -r /etc",
]

copy_config_cmds = [
    "cp .{}/buffers.json.j2",
    "cp .{}/buffers_defaults",
    "cp .{}/pg_profile_lookup.ini",
    "cp .{}/port_config.ini",
    "cp .{}/qos.json.j2",
    "cp .{}/sai.profile",
]

copy_config_cmds_no_qos = [
    "cp .{}/port_config.ini",
    "cp .{}/sai.profile",
]

broadcom_cmd_bcmcmd = [
    'bcmcmd{} -t5 version',
    'bcmcmd{} -t5 soc',
    'bcmcmd{} -t5 ps',
    'bcmcmd{} "l3 nat_ingress show"',
    'bcmcmd{} "l3 nat_egress show"',
    'bcmcmd{} "ipmc table show"',
    'bcmcmd{} "multicast show"',
    'bcmcmd{} "conf show"',
    'bcmcmd{} "fp show"',
    'bcmcmd{} "pvlan show"',
    'bcmcmd{} "l2 show"',
    'bcmcmd{} "l3 intf show"',
    'bcmcmd{} "l3 defip show"',
    'bcmcmd{} "l3 l3table show"',
    'bcmcmd{} "l3 egress show"',
    'bcmcmd{} "l3 ecmp egress show"',
    'bcmcmd{} "l3 multipath show"',
    'bcmcmd{} "l3 ip6host show"',
    'bcmcmd{} "l3 ip6route show"',
    'bcmcmd{} "mc show"',
    'bcmcmd{} "cstat *"',
    'bcmcmd{} "mirror show"',
    'bcmcmd{} "mirror dest show"',
    'bcmcmd{} "port *"',
    'bcmcmd{} "d chg my_station_tcam"',
]

broadcom_cmd_misc = [
    "cat /proc/bcm/knet/debug",
    "cat /proc/bcm/knet/dma",
    "cat /proc/bcm/knet/link",
    "cat /proc/bcm/knet/rate",
    "cat /proc/bcm/knet/dstats",
    "cat /proc/bcm/knet/stats",
    "docker cp syncd{}:/var/log/bcm_diag_post",
    "docker cp syncd{}:/var/log/diagrun.log",
]
