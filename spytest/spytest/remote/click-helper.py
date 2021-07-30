import argparse
from config.main import config      # pylint: disable=no-name-in-module,import-error
from show.main import cli as show   # pylint: disable=import-error

parser = argparse.ArgumentParser()
parser.add_argument("--include-description", help="include command description", default=1, type=int, choices=[0, 1])
parser.add_argument("--include-param-name", help="include exact parameter name", default=1, type=int, choices=[0, 1])
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
        for index, param in enumerate(params, start=1):
            paramName=param.name
            if param.__class__.__name__ == "Option":
                prefix = '[ '
                suffix = ' ]'
                argName = 'opts: '
                paramName = str(param.opts)
            if not c_args.include_param_name:
                paramName = "arg-{}".format(index)
            param_string += ' ' + prefix
            param_string += argName + paramName
            if "click.types.Path" in str(param.type):
                param_string += ', type: PATH '
            elif "STRING" not in str(param.type):
                param_string += ', type: ' + str(param.type)
            if param.required:
                param_string += ', required: ' + str(param.required)
            param_string += suffix
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
    incl_desc = c_args.include_description

    for source in cmd_sources:
        for cmd in sorted(source):
            command = source[cmd]
            print(command["cmd"])
            if c_args.include_description:
                print("\tDescription: " + command["help"])


