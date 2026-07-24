#!/usr/bin/env python3
from .gnmi_utils import apply_gnmi_file, gnmi_get, gnmi_set, GNMIEnvironment, _make_client
import argparse
from jinja2 import Environment, FileSystemLoader
import tempfile
import os
import logging
import json


def render_template(template_path, context, out_file, reverse=False):
    # Create a Jinja2 environment (renders JSON for gNMI, not HTML — no XSS risk)
    env = Environment(loader=FileSystemLoader('.'))  # nosemgrep: direct-use-of-jinja2

    # Load the template
    template = env.get_template(template_path)

    # Render the template with the provided context (renders JSON for gNMI, not HTML — no XSS risk)
    rendered_content = template.render(context)  # nosemgrep: direct-use-of-jinja2
    if reverse:
        reqs = json.loads(rendered_content)
        reversed_reqs = reqs[::-1]
        rendered_content = json.dumps(reversed_reqs)
    out_file.write(rendered_content)


# Override error method, to display help message on error as well
class MyParser(argparse.ArgumentParser):
    def error(self, message):
        print('error: %s\n' % message)
        self.print_help()
        raise argparse.ArgumentTypeError(message)


def int_range_type(min_val, max_val):
    def check_range(value):
        ivalue = int(value)
        if ivalue < min_val or ivalue > max_val:
            raise argparse.ArgumentTypeError(f"Value must be between {min_val} and {max_val}")
        return ivalue
    return check_range


# parse command line arguments and return result
def parse_args():
    # Create the parser
    parser = MyParser(description='Parse command line arguments')
    parser.add_argument('-t', '--target', type=str, default="127.0.0.1:8080",
                        help='GNMI server address in the format of host:port')
    parser.add_argument('-u', '--username', type=str, default="cisco",
                        help='Username for GNMI server authentication')
    parser.add_argument('-p', '--password', type=str, default="cisco123",
                        help='Password for GNMI server authentication')
    parser.add_argument('-d', '--debug', action='store_true', required=False,
                        default=False, help='turn on debug log')
    parser.add_argument('-i', "--dpu_index", type=int_range_type(0, 7),
                        default=0, required=False, help="DPU index [0-7]")
    parser.add_argument('-n', "--num_dpus", type=int_range_type(1, 8),
                        default=1, required=False, help="Number of DPUs")
    parser.add_argument('-s', "--sleep_secs", type=int, default=0, required=False,
                        help="Delay before each batch operation in seconds")
    parser.add_argument('-b', "--batch_val", type=int, default=10, required=False,
                        help="Batch operation size")

    # Create the subparser
    subparsers = parser.add_subparsers(title='subcommands', dest='topsubcmd', required=True)
    update_parser = subparsers.add_parser('update', help='Update operation')
    update_parser.add_argument('-f', '--filename', type=str, required=True, help='the path of json template file')

    replace_parser = subparsers.add_parser('replace', help='Replace operation')
    replace_parser.add_argument('-f', '--filename', type=str, required=True, help='the path of json template file')

    delete_parser = subparsers.add_parser('delete', help='Delete operation')
    delete_group = delete_parser.add_mutually_exclusive_group(required=True)
    delete_group.add_argument('-f', '--filename', type=str, help='the path of json template file')
    delete_group.add_argument('-x', '--xpath', type=str, help='the xpath of the object to be deleted')

    get_parser = subparsers.add_parser('get', help='Get operation')
    get_group = get_parser.add_mutually_exclusive_group(required=True)
    get_group.add_argument('-f', '--filename', type=str, help='the path of json template file')
    get_group.add_argument('-x', '--xpath', type=str, help='the xpath of the object to return')

    args = parser.parse_args()
    if args.debug:
        logging.basicConfig(level=logging.DEBUG,
                            format='%(asctime)s - %(levelname)s - %(message)s')
    else:
        logging.basicConfig(level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')
    return args


def exec_action(args):
    env = GNMIEnvironment()
    env.username = args.username
    env.password = args.password
    target = args.target.split(":", 1)
    env.gnmi_ip = target[0]
    if len(target) == 1:
        env.gnmi_port = 8080
    else:
        env.gnmi_port = int(target[1])
    env.dpu_index = args.dpu_index
    env.num_dpus = args.num_dpus
    template_args = {}
    template_args['dpu_index'] = env.dpu_index
    template_args['num_dpus'] = env.num_dpus

    if not args.filename:
        with _make_client(env) as gc:
            env.gc = gc
            if args.topsubcmd == "delete":
                gnmi_set(env, [args.xpath], [], [])
            elif args.topsubcmd == "get":
                gnmi_get(env, [args.xpath])
        env.gc = None
        return
    reverse = False
    if args.topsubcmd == "update":
        template_args['op'] = "SET"
    elif args.topsubcmd == "replace":
        template_args['op'] = "REP"
    elif args.topsubcmd == "delete":
        template_args['op'] = "DEL"
        reverse = True
    else:
        template_args['op'] = "GET"
    try:
        out_file = tempfile.NamedTemporaryFile("w", delete=False)

        render_template(args.filename, template_args, out_file, reverse)
        out_file.close()
        with _make_client(env) as gc:
            env.gc = gc
            apply_gnmi_file(env, out_file.name, args.batch_val, args.sleep_secs)
        env.gc = None
    finally:
        os.unlink(out_file.name)


def main():
    try:
        parsedArgs = parse_args()
    except argparse.ArgumentTypeError as e:
        # Handle the error
        print(str(e))
        return
    if not parsedArgs:
        return
    exec_action(parsedArgs)


if __name__ == '__main__':
    main()
