#!/auto/vxr/pyvxr/python3/bin/python
""" A VXR simulation backend for test automation tools (Cafy, pyATS, XRUT,
FireX, etc).
"""
__author__ = "Rafal Skorka <skorka@cisco.com>"

import argparse
import os
import logging
import pprint
from pyvxr.vxr import Vxr


def parse_cli_args(supported_commands):
    """ Parse arguments from the CLI """

    parser = argparse.ArgumentParser(description="Launch and manage vxr "
                                     "simulation (v %s)" % Vxr.version)

    parser.add_argument("cfg", metavar="YAML_CONFIG", nargs='?',
                        help="Pyvxr yaml configuration file\n"
                        "(see https://wiki.cisco.com/display/VXRSIM/VXR+YAML+"
                        "SPECIFICATION)")

    parser.add_argument("--cmd",
                        help="Vxr command (%s)" % ','.join(supported_commands),
                        required=True)

    parser.add_argument("--no-image-copy",
                        help="Do not copy router images to simulation host",
                        action='store_true', default=False)

    parser.add_argument("--output-dir",
                        help="Override pyvxr's default ('./') output directory"
                        )

    parser.add_argument("--nodes",
                        help="A comma separated list of router node(s)  "
                             "for the 'console' command (optional)"
                        )

    parser.add_argument("--save-restore-file",
                        help="Path to XR config save/restore file"
                        )

    parser.add_argument('--version', action='version', version='%s' %
                        Vxr.version)

    parsed_args = parser.parse_args()

    return parsed_args


def _add_dot_yaml_cfg_to_args(args, vxr):
    if args.cfg is None:
        if os.path.exists(vxr.dot_config_file):
            args.cfg = vxr.dot_config_file
        else:
            if args.cmd != 'clean':
                vxr.fatal("The '{}' command requires YAML_CONFIG argument "
                          "since there is no existing 'dot' yaml config "
                          "file.".format(args.cmd))


def main():
    """ PYVXR script's main entry function """

    supported_commands = ['start', 'stop', 'clean', 'consoles', 'restart',
                          'ports', 'logs', 'status', 'toxml', 'vcpu-count',
                          'reconnect', 'save-xr-config', 'restore-xr-confg',
                          'tgngui', 'sim-check'
                          ]
    args = parse_cli_args(supported_commands)
    if args.cmd in ('vcpu_count', 'vcpu-count', 'ports'):
        logging.basicConfig(level=logging.WARNING)
    else:
        logging.basicConfig(level=logging.INFO)

    log = logging.getLogger(__name__)
    vxr = Vxr(exit_on_error=True, output_dir=args.output_dir)
    vxr.no_image_copy = args.no_image_copy
    _add_dot_yaml_cfg_to_args(args, vxr)

    if args.cmd == 'start':
        vxr.start(args.cfg)
    elif args.cmd == 'stop':
        vxr.stop(args.cfg)
    elif args.cmd == 'clean':
        vxr.clean(args.cfg)
    elif args.cmd == 'reconnect':
        vxr.reconnect(args.cfg)
    elif args.cmd == 'restart':
        vxr.restart(args.cfg)
    elif args.cmd == 'logs':
        vxr.logs(args.cfg)
    elif args.cmd == 'toxml':
        vxr.toxml(args.cfg)
    elif args.cmd == 'consoles':
        ports = vxr.ports() or vxr.get_ports(args.cfg)
        vxr.consoles(args.nodes)
    elif args.cmd == 'ports':
        ports = vxr.ports() or vxr.get_ports(args.cfg)
        if ports:
            pprint.pprint(ports)
        else:
            log.info("No ports available....")
    elif args.cmd == 'status':
        status = vxr.status(args.cfg)
        pprint.pprint(status)
    elif args.cmd == 'sim-check':
        vxr.sim_check(args.cfg)
    elif args.cmd == 'vcpu_count' or args.cmd == 'vcpu-count':
        cfg = Vxr.load_yaml_file(args.cfg)
        print(vxr.get_vcpu_count(cfg))
    elif args.cmd == 'save-xr-config' or args.cmd == 'restore-xr-config':
        if not args.save_restore_file:
            vxr.fatal("'{}' command requires '--save-restore-file' argument"
                      "".format(args.cmd))
        vxr.save_restore_config(args.save_restore_file, args.cmd, args.cfg)
    elif args.cmd == 'tgngui':
        vxr.tgngui(args.cfg)
    else:
        vxr.fatal("Unsupported command %s. Supported commands:%s" %
                  (args.cmd, ','.join(supported_commands)))


if __name__ == "__main__":
    main()
