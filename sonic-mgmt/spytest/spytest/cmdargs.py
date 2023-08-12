import argparse

default_exec_scopes = ["function", "module", "none"]

save_types = ["sairedis", "config-db", "running-config", "warmboot"]
save_default = {"sairedis": "none", "config-db": "none", "running-config": "none"}
save_scopes = default_exec_scopes + ["session"]

max_time_default = {"reboot": 0, "port": 300, "session": 5400, "module": 1200, "function": 1200}

max_time_help_msg = """
    Maximum time for various operations.
        <reboot>: Wait time in seconds for ports to come up after reboot default {} seconds
        <port>: time for ports to comeup default {} seconds
        <session>: time for session init to complete default {} seconds
        <module>: time for session module to complete default {} seconds
        <function>: time for session function to complete default {} seconds
    """.format(max_time_default["reboot"], max_time_default["port"], max_time_default["session"],
               max_time_default["module"], max_time_default["function"])

sub_report_help_msg = """
    Sub reports to be generated.
        <name>: name of the sub report
        <type>: input data type and currently supported types are: suite
        <data>: input data for given type
    """

random_order_help_msg = """
    Enable executing tests in random order.
        <0> disable random order execution
        <1> execute the modules in random order (default).
        <2> execute the test cases in random order
        <3> use the random order from module info
"""

tryssh_help_msg = """
    Try executing through SSH
        <0> disable (default)
        <1> enable for all modules
        <2> use the value from module info
"""

arg_defaults_1 = {
    "--ignore-tcmap-errors": 0,
    "--tclist-bucket": None,
    "--tclist-file": [],
    "--tclist-file-exclude": [],
    "--tclist-csv": [],
    "--tclist-csv-exclude": [],
    "--logs-path": None,
    "--file-mode": False,
    "--quick-test": False,
    "--email": None,
    "--email-subject": "Run Report",
    "--email-subject-nargs": [],
    "--email-attachments": 0,
    "--skip-tgen": False,
    "--tgen-module-init": 1,
    "--topology-check": ["module"],
    "--load-config-method": "none",
    "--skip-init-config": False,
    "--skip-load-config": "module",
    "--load-image": "onie",
    "--ignore-dep-check": 0,
    "--memory-check": None,
    "--sysinfo-check": None,
    "--syslog-check": "err",
    "--save-sairedis": "none",
    "--save sairedis": save_default["sairedis"],
    "--save running-config": save_default["running-config"],
    "--save config-db": save_default["config-db"],
    "--save-warmboot": 0,
    "--faster-init": 1,
    "--faster-cli": 1,
    "--reboot-wait": max_time_default["reboot"],
    "--port-init-wait": max_time_default["port"],
    "--tc-max-timeout": max_time_default["function"],
    "--module-init-max-timeout": max_time_default["module"],
    "--max-time reboot": max_time_default["reboot"],
    "--max-time port": max_time_default["port"],
    "--max-time function": max_time_default["function"],
    "--max-time module": max_time_default["module"],
    "--max-time session": max_time_default["session"],
    "--results-prefix": None,
    "--results-compare": None,
    "--exclude-devices": None,
    "--include-devices": None,
    "--run-progress-report": 0,
    "--env": {},
    "--random-order": 1,
    "--repeat-test": ["", 1],
    "--rps-reboot": None,
    "--pde": False,
    "--community-build": "none",
    "--tryssh": 0,
    "--first-test-only": False,
    "--config-profile": None,
    "--build-url": None,
    "--libsai-url": None,
    "--clear-tech-support": 0,
    "--module-epilog-tgen-cleanup": 1,
    "--module-epilog": 1,
    "--graceful-exit": 1,
    "--reuse-results": "none",
    "--link-param": [],
    "--dev-prop": [],
    "--dev-param": [],
    "--change-section": [],
    "--ixserver": [],
    "--ui-type": "click",
    "--breakout-mode": "native",
    "--speed-mode": "configured",
    "--ifname-type": "std-ext",
    "--mgmt-vrf": 0,
    "--gcov": 0
}

arg_defaults_2 = {
    "--fetch-core-files": "session",
    "--get-tech-support": "onfail-epilog",
}


def get_default_1(name, default):
    if name in arg_defaults_1:
        return arg_defaults_1[name]
    return default


def get_default_2(name, default):
    if name in arg_defaults_2:
        return arg_defaults_2[name]
    return default


def get_default_all():
    retval = {}
    for name in arg_defaults_1:
        retval[name] = arg_defaults_1[name]
    for name in arg_defaults_2:
        retval[name] = arg_defaults_2[name]
    return sorted(retval.items())


def validate_repeat():
    class ArgValidateRepeat(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            message = ''
            types_supported = ["function", "module"]
            if len(values) != 2:
                message = "requires both <type> and <times>"
            elif values[0] not in types_supported:
                message = "<type> should be one of {}".format(types_supported)
            else:
                try:
                    values[1] = int(values[1])
                except ValueError:
                    message = "<times> should be integer"
            if message:
                raise argparse.ArgumentError(self, message)
            setattr(namespace, self.dest, values)
    return ArgValidateRepeat


def csv2list(value):
    retval = []
    if value is not None:
        for val in value.split(","):
            retval.append(val)
    return retval


def validate_exec_phase(exec_phases):
    class ArgValidateExecPhase(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            all_values = csv2list(getattr(namespace, self.dest))
            all_values.extend(csv2list(values))
            for value in all_values:
                if value not in exec_phases:
                    message = "unknown sub-option {}".format(value)
                    raise argparse.ArgumentError(self, message)
            all_values = list(set(all_values))
            if "none" in all_values:
                all_values = ["none"]
            setattr(namespace, self.dest, ",".join(all_values))
    return ArgValidateExecPhase


def validate_exec_scope(multiple, exec_scopes=None):
    exec_scopes = exec_scopes or default_exec_scopes

    class ArgValidateExecScope(argparse.Action):
        def _check_(self, value):
            if value not in exec_scopes:
                msgs = ["unknown value '{}'".format(value)]
                msgs.append("should be one of {}".format(exec_scopes))
                raise argparse.ArgumentError(self, " - ".join(msgs))

        def __call__(self, parser, namespace, values, option_string=None):
            all_values = csv2list(getattr(namespace, self.dest))
            if not multiple:
                all_values = []
            all_values.extend(csv2list(values))
            if not multiple and len(all_values) > 1:
                self._check_(values)
            for value in all_values:
                self._check_(value)
            all_values = list(set(all_values))
            if "none" in all_values:
                all_values = ["none"]
            setattr(namespace, self.dest, ",".join(all_values))
    return ArgValidateExecScope


def validate_env():
    class ArgValidateEnv(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            help1 = "requires <name> and <value>"
            help1 = help1 + "separated by '=' or space"
            if len(values) > 2:
                values[1] = " ".join(values[1:])
            elif len(values) == 1:
                values = values[0].split('=')
            elif len(values) != 2:
                raise argparse.ArgumentError(self, help1)
            getattr(namespace, self.dest).update({values[0]: values[1]})
    return ArgValidateEnv


def validate_max_time():
    class ArgValidateMaxTime(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            options = ['port', 'session', "module", "function"]
            help1 = "requires <type> and <time> where type: {}".format(options)
            help1 = help1 + "separated by '=' or space"
            help2 = "<type> should be one of {}".format(options)
            help3 = "<time> should be integer"
            if len(values) > 2:
                raise argparse.ArgumentError(self, help1)
            if len(values) == 1:
                values = values[0].split('=')
            if len(values) != 2:
                raise argparse.ArgumentError(self, help1)
            if values[0] not in options:
                raise argparse.ArgumentError(self, help2)
            try:
                values[1] = int(values[1])
            except ValueError:
                raise argparse.ArgumentError(self, help3)
            getattr(namespace, self.dest).update({values[0]: values[1]})
    return ArgValidateMaxTime


def validate_sub_report():
    class ArgValidateSubReport(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            actions, types = ["include", "exclude"], ["folders"]  # ["suite", "folders"]
            help1 = "requires <name> <action> <type> and <data>"
            help1 = help1 + " where action: {}".format(actions)
            help1 = help1 + " type: {}".format(types)
            help1 = help1 + " separated space"
            help2 = "<action> should be one of {}".format(actions)
            help3 = "<type> should be one of {}".format(types)
            if len(values) < 4:
                raise argparse.ArgumentError(self, help1)
            if values[1] not in actions:
                raise argparse.ArgumentError(self, help2)
            if values[2] not in types:
                raise argparse.ArgumentError(self, help3)
            key = "-".join([values[0], values[1], values[2]])
            val = [values[0], values[1], values[2], values[3].split(",")]
            getattr(namespace, self.dest)[key] = val

    return ArgValidateSubReport


def validate_save():
    class ArgValidateSave(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            common_help = "requires <type> and <scope>"
            common_help = common_help + " where type: {}".format(save_types)
            common_help = common_help + " scope: {}".format(save_scopes)
            common_help = common_help + " separated space"
            type_help = "<type> should be one of {}".format(save_types)
            scope_help = "<scope> should be CSV of {}".format(save_scopes)
            if len(values) != 2:
                raise argparse.ArgumentError(self, common_help)
            if values[0] not in save_types:
                raise argparse.ArgumentError(self, type_help)
            val_list = values[1].split(",")
            for val in val_list:
                if val not in save_scopes:
                    raise argparse.ArgumentError(self, scope_help)
            if "none" in val_list:
                getattr(namespace, self.dest)[values[0]] = "none"
            else:
                getattr(namespace, self.dest)[values[0]] = values[1]

    return ArgValidateSave


class HelpFormatter(argparse.HelpFormatter):
    def _format_action(self, action):
        if type(action).__name__ in ["ArgValidateEnv", "ArgValidateMaxTime"]:
            action.nargs = 1
        if type(action) == argparse._SubParsersAction:
            # inject new class variable for sub command formatting
            subactions = action._get_subactions()
            invocations = [self._format_action_invocation(a) for a in subactions]
            self._subcommand_max_length = max(len(i) for i in invocations)

        if type(action) == argparse._SubParsersAction._ChoicesPseudoAction:
            # format sub command help line
            subcommand = self._format_action_invocation(action)  # type: str
            width = self._subcommand_max_length
            help_text = ""
            if action.help:
                help_text = self._expand_help(action)
            return "  {:{width}} -  {}\n".format(subcommand, help_text, width=width)

        elif type(action) == argparse._SubParsersAction:
            # process sub command help section
            msg = '\n'
            for subaction in action._get_subactions():
                msg += self._format_action(subaction)
            return msg
        else:
            return super(HelpFormatter, self)._format_action(action)
