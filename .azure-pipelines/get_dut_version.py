import argparse
import logging
import os
import sys
import json

_self_dir = os.path.dirname(os.path.abspath(__file__))
base_path = os.path.realpath(os.path.join(_self_dir, ".."))
if base_path not in sys.path:
    sys.path.append(base_path)
ansible_path = os.path.realpath(os.path.join(_self_dir, "../ansible"))
if ansible_path not in sys.path:
    sys.path.append(ansible_path)

from devutil.devices import init_localhost, init_testbed_sonichosts     # noqa E402

logger = logging.getLogger(__name__)

RC_INIT_FAILED = 1
RC_GET_DUT_VERSION_FAILED = 2


def get_duts_version(sonichosts, output=None):
    try:
        ret = {}
        duts_version = sonichosts.command("show version")
        for dut, version in duts_version.items():
            ret[dut] = {}
            dut_version = version["stdout_lines"]

            for line in dut_version:
                if ":" in line:
                    line_splitted = line.split(":", 1)
                    key = line_splitted[0].strip()
                    value = line_splitted[1].strip()
                    if key == "Docker images":
                        ret[dut]["Docker images"] = []
                        continue
                    ret[dut][key] = value
                elif "docker" in line:
                    line_splitted = line.split()
                    ret[dut]["Docker images"].append({"REPOSITORY": line_splitted[0],
                                                      "TAG": line_splitted[1],
                                                      "IMAGE ID": line_splitted[2],
                                                      "SIZE": line_splitted[3]})

        if output:
            with open(output, "w") as f:
                f.write(json.dumps(ret))
                f.close()
        else:
            print(ret)
    except Exception as e:
        logger.error("Failed to get DUT version: {}".format(e))
        sys.exit(RC_GET_DUT_VERSION_FAILED)


def validate_args(args):
    _log_level_map = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warning": logging.WARNING,
        "error": logging.ERROR,
        "critical": logging.CRITICAL
    }
    logging.basicConfig(
        stream=sys.stdout,
        level=_log_level_map[args.log_level],
        format="%(asctime)s %(filename)s#%(lineno)d %(levelname)s - %(message)s"
    )


def main(args):
    logger.info("Validating arguments")
    validate_args(args)

    logger.info("Initializing hosts")
    localhost = init_localhost(args.inventory, options={"verbosity": args.verbosity})
    sonichosts = init_testbed_sonichosts(
        args.inventory, args.testbed_name, testbed_file=args.tbfile, options={"verbosity": args.verbosity}
    )

    if not localhost or not sonichosts:
        sys.exit(RC_INIT_FAILED)

    get_duts_version(sonichosts, args.output)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Tool for getting sonic device version.")

    parser.add_argument(
        "-i", "--inventory",
        type=str,
        dest="inventory",
        required=True,
        help="Ansible inventory file")

    parser.add_argument(
        "-t", "--testbed-name",
        type=str,
        required=True,
        dest="testbed_name",
        help="Testbed name."
    )

    parser.add_argument(
        "--tbfile",
        type=str,
        dest="tbfile",
        default="testbed.yaml",
        help="Testbed definition file."
    )

    parser.add_argument(
        "-v", "--verbosity",
        type=int,
        dest="verbosity",
        default=2,
        help="Log verbosity (0-3)."
    )

    parser.add_argument(
        "--log-level",
        type=str,
        dest="log_level",
        choices=["debug", "info", "warning", "error", "critical"],
        default="debug",
        help="Loglevel"
    )

    parser.add_argument(
        "-o", "--output",
        type=str,
        dest="output",
        required=False,
        help="Output duts version to the specified file."
    )

    args = parser.parse_args()
    main(args)
