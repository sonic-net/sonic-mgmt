#!/usr/bin/env python2

import argparse
import random
import string
import subprocess
import syslog


# Function to create the fuzz commands to send to the cli
def create_list_of_random_chars(items_in_list=1, min_string_length=10, string_length=10):
    random_list = []

    # Create the random fuzz commands for the sonic command
    for i in range(items_in_list):
        str_len = random.randint(min_string_length, string_length)
        random_list.append(''.join(random.choice(string.printable) for i in range(str_len)))

    return random_list


def send_commands(base=None, repetitions=1, qty_of_sub_commands=1, sub_command_max_length=10, sub_command_min_length=None):
    for i in range(repetitions):
        fuzz_cmds = create_list_of_random_chars(items_in_list=qty_of_sub_commands,
                                                min_string_length=sub_command_min_length,
                                                string_length=sub_command_max_length)

        # Run the command with the base and the fuzz commands
        cmds = base + fuzz_cmds
        syslog.syslog(str(cmds))
        subprocess.call(cmds)


def initialize_arg_parser():
    # Returns a list of values containing the minimum and maximum values for the fuzz string length
    def length_calc(value):
        to_return = None
        if "-" in value:
            min, max = value.split("-")

            if not min.isdigit() and not max.isdigit():
                raise argparse.ArgumentError("You can only pass integers into the length field.  You passed in: {0} {1}".format(min, max))

            if int(min) > int(max):
                to_return = [int(max), int(min)]
            else:
                to_return = [int(min), int(max)]
        elif not value.isdigit():
            raise argparse.ArgumentError("You can only pass integers into the length field.  You passed in: {0}".format(value))

        else:
            to_return = [int(value), int(value)]

        return to_return

    description = 'Program to do cli fuzzing of the Sonic CLI commands'

    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("-S", "--sonic_cmd", help="sonic command to test (Required)", action="store", nargs='*', required=True)
    parser.add_argument("-C", "--sub_cmds", help="number of fake sub commands to create. (Default=1)", action="store", type=int, nargs=1, default=[1])
    parser.add_argument("-Q", "--qty", help="number of times to fuzz the command (Default=10)", type=int, nargs=1, default=[10])

    help_msg = "number of characters or a range of characters in the subcommand (Example=1-10) (Default=10)"
    parser.add_argument("-L", "--length", help=help_msg, action="store", type=length_calc, nargs=1, default=[[10,10]])

    return parser.parse_args()


def main():
    args = initialize_arg_parser()

    # Pull the sonic commands to test out of the cli args
    base_cmds = args.sonic_cmd
    qty_sub_cmds = args.sub_cmds[0]
    reps = args.qty[0]
    length = args.length[0]

    min_length = length[0]
    max_length = length[1]

    send_commands(base=base_cmds,
                  repetitions=reps,
                  qty_of_sub_commands=qty_sub_cmds,
                  sub_command_max_length=max_length,
                  sub_command_min_length=min_length)


if __name__ == '__main__':
    main()
