import sys
import argparse
from config.main import config
from show.main import cli as show

parser = argparse.ArgumentParser()
parser.add_argument("--format", help="output format", default="txt")
c_args = parser.parse_args()

class ListCommands:
    sources = [config, show]
    config_commands = {}
    show_commands = {}
    def __init__(self):
        pass

    @staticmethod
    def walk_sources():
        for source in ListCommands.sources:
            if source.name == 'cli':
                source.name = "show"
            ListCommands.walk_source(source)

    @staticmethod
    def get_param_string(params):
        param_string = ""
        prefix = '< '
        suffix = ' >'
        argName = 'argName: '
        for param in params:
            paramName=param.name
            if param.__class__.__name__ == "Option":
                prefix = '[ '
                suffix = ' ]'
                argName = 'opts: '
                paramName = str(param.opts)
            param_string += ' ' + prefix + argName + paramName + ', type: ' + str(param.type) + ', required: ' + str(param.required) + suffix
        return param_string

    @staticmethod
    def walk_source(source, cmd_string=""):
        param_string = ListCommands.get_param_string(source.params)
        cmd_string = cmd_string + ' ' + source.name + ' ' + param_string
        if hasattr(source, 'commands'):
            for command in source.commands:
                ListCommands.walk_source(source.commands[command], cmd_string)
        else:
            cmd_string = " ".join(list(filter(None, cmd_string.split(' '))))
            cmd_entry = {'help': ' ' if source.help is None else source.help, 'cmd': cmd_string}
            if cmd_string.startswith('config'):
                ListCommands.config_commands[cmd_string] = cmd_entry
            elif cmd_string.startswith('show'):
                ListCommands.show_commands[cmd_string] = cmd_entry
            else:
                pass


if __name__ == '__main__':
    ListCommands.walk_sources()
    cmd_sources = [ListCommands.config_commands, ListCommands.show_commands]

    if c_args.format == "txt":
        for source in cmd_sources:
            for cmd in sorted(source):
                command = source[cmd]
                print(command["cmd"])
                print("\tDescription: " + command["help"])
    elif c_args.format == "xml":
        print("Not implemented yet")
    else:
        print("Not supported format")
        sys.exit(2)


