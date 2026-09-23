import logging

from tests.common.constants import CounterpollConstants


class ConterpollHelper:
    @staticmethod
    def get_counterpoll_show_output(duthost):
        return duthost.show_and_parse(CounterpollConstants.COUNTERPOLL_SHOW)

    @staticmethod
    def get_available_counterpoll_types(duthost):
        available_option_list = []
        COMMANDS = 'Commands:'
        counterpoll_show = duthost.command(CounterpollConstants.COUNTERPOLL_QUEST)[CounterpollConstants.STDOUT]
        index = counterpoll_show.find(COMMANDS) + len(COMMANDS) + 1
        for line in counterpoll_show[index:].splitlines():
            available_option_list.append(line.split()[0])
        return [option for option in available_option_list
                if option not in CounterpollConstants.EXCLUDE_COUNTER_SUB_COMMAND]

    @staticmethod
    def get_parsed_counterpoll_show(counterpoll_show):
        parsed_counterpoll = {}
        for counterpoll in counterpoll_show:
            parsed_counterpoll[counterpoll[CounterpollConstants.TYPE]] = {
                CounterpollConstants.INTERVAL: counterpoll[CounterpollConstants.INTERVAL],
                CounterpollConstants.STATUS: counterpoll[CounterpollConstants.STATUS]}
        return parsed_counterpoll

    @staticmethod
    def restore_counterpoll_status(duthost, counterpoll_before, counterpoll_after):
        for counterpoll, value in list(counterpoll_after.items()):
            if counterpoll not in counterpoll_before:
                continue
            else:
                if counterpoll_after[counterpoll][CounterpollConstants.STATUS] \
                        != counterpoll_before[counterpoll][CounterpollConstants.STATUS]:
                    duthost.command(CounterpollConstants.COUNTERPOLL_RESTORE.format(
                        CounterpollConstants.COUNTERPOLL_MAPPING[counterpoll],
                        counterpoll_before[counterpoll][CounterpollConstants.STATUS]))

    @staticmethod
    def _run_command_ignore_errors(duthost, cmd):
        """Run command handling both SonicHost and SonicAsic interfaces.

        SonicAsic.command() does not support module_ignore_errors, so
        we try that kwarg first and fall back to catching the exception.
        """
        try:
            return duthost.command(cmd, module_ignore_errors=True)
        except TypeError:
            # SonicAsic.command() doesn't accept module_ignore_errors
            try:
                return duthost.command(cmd)
            except Exception as e:
                # Return a synthetic failed result
                return {'rc': 1, 'stdout': str(e), 'stderr': str(e)}

    @staticmethod
    def disable_counterpoll(duthost, counter_type_list):
        for counterpoll_type in counter_type_list:
            result = ConterpollHelper._run_command_ignore_errors(
                duthost,
                CounterpollConstants.COUNTERPOLL_DISABLE.format(
                    counterpoll_type))
            if result.get('rc', 0) != 0:
                stdout = result.get('stdout', '').lower()
                stderr = result.get('stderr', '').lower()
                if 'not supported' in stdout or \
                        'not supported' in stderr:
                    logging.warning(
                        "Counterpoll type '%s' not supported "
                        "on this platform, skipping",
                        counterpoll_type)
                else:
                    raise Exception(
                        "Failed to disable counterpoll "
                        "'{}': rc={}".format(
                            counterpoll_type,
                            result.get('rc', -1)))

    @staticmethod
    def enable_counterpoll(duthost, counter_type_list):
        for counterpoll_type in counter_type_list:
            result = ConterpollHelper._run_command_ignore_errors(
                duthost,
                CounterpollConstants.COUNTERPOLL_ENABLE.format(
                    counterpoll_type))
            if result.get('rc', 0) != 0:
                stdout = result.get('stdout', '').lower()
                stderr = result.get('stderr', '').lower()
                if 'not supported' in stdout or \
                        'not supported' in stderr:
                    logging.warning(
                        "Counterpoll type '%s' not supported "
                        "on this platform, skipping",
                        counterpoll_type)
                else:
                    raise Exception(
                        "Failed to enable counterpoll "
                        "'{}': rc={}".format(
                            counterpoll_type,
                            result.get('rc', -1)))

    @staticmethod
    def set_counterpoll_interval(duthost, counterpoll_type, interval):
        duthost.command(CounterpollConstants.COUNTERPOLL_INTERVAL_STR.format(counterpoll_type, interval))
