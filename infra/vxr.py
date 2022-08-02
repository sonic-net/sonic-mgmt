#!/nobackup/qiwang4/t0t1_test/sonic-test/infra/pyats/bin/python3.8
""" A VXR simulation backend for test automation tool """
__author__ = "Rafal Skorka <skorka@cisco.com>"

import argparse
import os
import sys
import logging
import json
from pyvxr.vxr import Vxr


def parse_cli_args(log_file):
    """ Parse arguments from the CLI """

    def process_help_flag(args, allParsers):
        """ Process 'help' flag """
        parser = allParsers['help']
        if args.command is None:
            allParsers['main'].print_help()
        else:
            parser = allParsers[args.command]
            parser.print_help()
        exit(0)

    progName = os.path.basename(sys.argv[0])
    progDir = os.path.dirname(sys.argv[0])

    help_epilog = """
Launch and manage VXR simulation

Typical usage
-------------
    # bringup topology
    {prog} start <TOPO_YAML_FILE>

    # connect to serial consoles
    {prog} consoles

    # clean up simulation and release resources
    {prog} clean

    # For sample yaml topologies, check
    # {prog_dir}/examples

Documentation
-------------
http://pyvxr.cisco.com
http://pyvxr.cisco.com/pyvxr/schema.html
    """.format(prog=progName, prog_dir=progDir)

    # epilog strings
    stop_epilog = "Shut down routers. Routers can be restarted with 'restart'"\
                  " command."
    clean_epilog = "Release all resources associated with sim session and"\
                   " clean all router state."
    status_epilog = "Show simulation status (running, ended, aborted, etc)"
    console_epilog = "Connect to devices via serial console"
    start_epilog = "Start a fresh simulation and 'bring up the topology"
    toxml_epilog = "Generate VXR's sim-config.xml file from pyvxr yaml file"
    sim_info_epilog = "Show simulation host and simulation directory"
    sim_check_epilog = "Run simulation diagnostics"
    bringup_epilog = "Re-attempt to bringup router"
    restart_epilog = "Powercycle all or specific nodes"
    ports_epilog = "Dump serial console ports (serial0, serial1), "\
                   "redirects, etc"
    logs_epilog = "Download log files from the simulation server"
    vcpucount_epilog = "Estimate the number of cpu cores required for a "\
                       "given topology"

    tgngui_epilog = "Start a VNC viewer for TGN devices"
    oir_epilog = "Perform an OIR operation (spitfire_d only)"
    user_ctl_epilog = "Perform VXR user control operation"
    nsim_epilog = "Set NSIM logging level"
    save_cfg_epilog = "Save XR config to a file"
    restore_cfg_epilog = "Restore XR config from a file"

    epilogs = {
        'clean': clean_epilog,
        'stop': stop_epilog,
        'start': start_epilog,
        'status': status_epilog,
        'consoles': console_epilog,
        'sim-info': sim_info_epilog,
        'sim-check': sim_check_epilog,
        'bringup': bringup_epilog,
        'ports': ports_epilog,
        'toxml': toxml_epilog,
        'restart': restart_epilog,
        'logs': logs_epilog,
        'vcpu-count': vcpucount_epilog,
        'tgngui': tgngui_epilog,
        'oir': oir_epilog,
        'user_ctl': user_ctl_epilog,
        'nsim-log': nsim_epilog,
        'save-xr-config': save_cfg_epilog,
        'restore-xr-config': restore_cfg_epilog,
    }

    # help strings
    output_dir_help = "override pyvxr's default output directory"
    nodes_help = "a comma separated list of devices (eg. R0,R5)"
    termtype_help = "terminal type: mrxvt, gnome, remote-mrxvt, "\
                    "remote-gnome (default mrxvt)"
    config_help = "Pyvxr yaml configuration file (see "\
                  "http://pyvxr.cisco.com/pyvxr/schema.html"
    nologfile_help = "do not create %s file" % log_file
    all_help = "open all serial console ports"

    allParsers = {}

    # main parser
    main_parser = argparse.ArgumentParser(
        epilog=help_epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    main_parser.add_argument(
        '--version', action='version', version='%s' % (Vxr.version))
    allParsers['main'] = main_parser

    # subparsers
    subparsers = main_parser.add_subparsers(title="Available subcommands")
    all_commands = ['start', 'clean', 'consoles', 'stop', 'ports', 'restart',
                    'sim-info', 'sim-check', 'status', 'logs',
                    'bringup', 'toxml', 'vcpu-count', 'tgngui', 'oir',
                    'save-xr-config', 'restore-xr-config', 'nsim-log',
                    'user_ctl']

    cmds_with_nodes = {'consoles', 'ports', 'oir', 'nsim-log', 'restart',
                       'save-xr-config', 'restore-xr-config', 'user_ctl'}
    cmds_with_config = {'start', 'toxml', 'vcpu-count'}
    cmds_with_nologfile = {'start', 'restart'}

    for cmd in all_commands:
        p = subparsers.add_parser(
            cmd,
            help=epilogs[cmd],
            epilog=epilogs[cmd])
        if cmd in cmds_with_nodes:
            p.add_argument("--nodes", help=nodes_help)
        if cmd in cmds_with_config:
            p.add_argument("cfg", metavar="TOPO_YAML_FILE",
                           help=config_help)
        if cmd in cmds_with_nologfile:
            p.add_argument("--no-logfile", help=nologfile_help,
                           action='store_true', default=False)
        if cmd == 'consoles':
            p.add_argument("--term-type", help=termtype_help)
            p.add_argument("--all", help=all_help,
                           action='store_true', default=False)
        if cmd == 'oir':
            p.add_argument("--op", help="OIR operation", required=True,
                           choices={'insert', 'remove', 'list', 'reload'})

        if cmd == 'user_ctl':
            p.add_argument("--args", help="vxr user control args",
                           required=True)

        if cmd == 'nsim-log':
            p.add_argument("--op", help="log operation", required=True,
                           choices={'list', 'set'})
            p.add_argument("--level", help="log level",
                           choices={'FULL', 'MACRO', 'TABLE', 'PACKET',
                                    'NONE', 'LINE'})
            p.add_argument("--json", help="json output format on/off",
                           choices={'on', 'off'})
            p.add_argument("--vxr_log", help="VXR logging on/off",
                           choices={'on', 'off'})
        if cmd in ('save-xr-config', 'restore-xr-config'):
            p.add_argument("--save-restore-file", required=True,
                           help="path to XR config save/restore file")
        p.add_argument("--output-dir", help=output_dir_help)
        p.add_argument("--profile", help="Select a custom pyvxr profile "
                       "(e.g. cisco-aws)", choices={'cisco-aws',
                                                    'cisco-internal'})
        p.set_defaults(cmd=cmd, cfg=None)
        allParsers[cmd] = p

    # help parser
    parser_help = subparsers.add_parser(
        'help', help='Show help', add_help=False)
    parser_help.add_argument(
        'command',
        choices=all_commands,
        nargs='?',
        help='command help')
    parser_help.set_defaults(func=process_help_flag)
    allParsers['help'] = parser_help

    args = main_parser.parse_args()
    if len(sys.argv) == 1:
        print("Type '%s help' for usage." % progName)
        exit(0)

    if 'func' in args:
        args.func(args, allParsers)

    return args


def _add_dot_yaml_cfg_to_args(args, vxr):
    if args.cfg is None:
        if os.path.exists(vxr.dot_config_file):
            args.cfg = vxr.dot_config_file


def get_filehandler(log_file, log_level, fmt_pattern, fmt_date):

    try:
        file_handler = logging.FileHandler(filename=log_file, mode="w")
    except PermissionError:
        base = os.path.abspath(log_file)
        base = os.path.dirname(base)
        msg = "Looks like you don't have write access to '%s' " \
              "directory. Make sure you have write privileges to the "\
              "directory from which you launch pyvxr." % base
        sys.stderr.write("FATAL:: %s\n" % msg)
        exit(1)

    file_handler.setLevel(log_level)
    formatter = logging.Formatter(fmt_pattern, datefmt=fmt_date)
    file_handler.setFormatter(formatter)
    return file_handler


def main():
    """ PYVXR script's main entry function """

    log_file = "pyvxr.log"
    args = parse_cli_args(log_file)

    if args.output_dir:
        log_file = os.path.join(args.output_dir, log_file)

    log_level = logging.INFO
    if args.cmd in ('vcpu-count', 'ports', 'status', 'sim-info'):
        log_level = logging.WARNING
    fmt_pattern = '%(asctime)s %(levelname).4s %(message)s'
    fmt_date = '%H:%M:%S'
    logging.basicConfig(level=log_level, format=fmt_pattern, datefmt=fmt_date)
    log = logging.getLogger('')
    if args.cmd in ('start', 'restart') and not args.no_logfile:
        fh = get_filehandler(log_file, log_level, fmt_pattern, fmt_date)
        if fh:
            log.addHandler(fh)

    vxr = Vxr(exit_on_error=True, output_dir=args.output_dir,
              profile=args.profile)
    _add_dot_yaml_cfg_to_args(args, vxr)

    if args.cmd == 'start':
        try:
            vxr.start(args.cfg)
        except Exception as err:
            log.removeHandler(log.handlers[0])
            log.error(err)
            raise
    elif args.cmd == 'stop':
        vxr.stop(args.cfg)
    elif args.cmd == 'clean':
        vxr.clean(args.cfg)
        if os.path.exists(log_file):
            os.unlink(log_file)
    elif args.cmd == 'bringup':
        vxr.bringup(args.cfg)
    elif args.cmd == 'restart':
        vxr.restart(args.cfg, args.nodes)
    elif args.cmd == 'logs':
        vxr.logs(args.cfg)
    elif args.cmd == 'toxml':
        vxr.toxml(args.cfg)
    elif args.cmd == 'consoles':
        ttype = args.term_type or 'mrxvt'
        vxr.consoles(args.cfg, args.nodes, ttype, args.all)
    elif args.cmd == 'ports':
        ports = vxr.ports() or vxr.get_ports(args.cfg)
        if ports:
            if args.nodes:
                nodes = set(args.nodes.split(','))
                for node in list(ports.keys()):
                    if node not in nodes:
                        del ports[node]
            print(json.dumps(ports, indent=2))
        else:
            log.info("No ports available....")
    elif args.cmd == 'sim-info':
        vxr.sim_info(args.cfg)
    elif args.cmd == 'oir':
        vxr.oir(args.op, args.nodes, args.cfg)
    elif args.cmd == 'user_ctl':
        vxr.user_ctl(args.args, args.nodes, args.cfg)
    elif args.cmd == 'nsim-log':
        vxr.nsim_log(args.op, args.nodes, args.level, args.json,
                     args.vxr_log, args.cfg)
    elif args.cmd == 'status':
        status = vxr.status(args.cfg)
        print(json.dumps(status))
    elif args.cmd == 'sim-check':
        vxr.sim_check(args.cfg)
    elif args.cmd == 'vcpu-count':
        cfg = Vxr.load_yaml_file(args.cfg)
        print(vxr.get_vcpu_count(cfg))
    elif args.cmd in ('save-xr-config', 'restore-xr-config'):
        vxr.save_restore_config(args.save_restore_file, args.cmd,
                                args.cfg, args.nodes)
    elif args.cmd == 'tgngui':
        vxr.tgngui(args.cfg)
    else:
        vxr.fatal("Unsupported command %s" % args.cmd)


if __name__ == "__main__":
    main()
