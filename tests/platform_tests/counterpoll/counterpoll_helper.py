import re

from tests.platform_tests.counterpoll.counterpoll_constants import CounterpollConstants


class ConterpollHelper:
    @staticmethod
    def get_counterpoll_show_output(duthost):
        counterpoll_show = duthost.command(CounterpollConstants.COUNTERPOLL_SHOW)
        return counterpoll_show[CounterpollConstants.STDOUT]

    @staticmethod
    def get_available_counterpoll_types(duthost):
        available_option_list = []
        COMMANDS = 'Commands:'
        counterpoll_show = duthost.command(CounterpollConstants.COUNTERPOLL_QUEST)[CounterpollConstants.STDOUT]
        index = counterpoll_show.find(COMMANDS) + len(COMMANDS) + 1
        for line in counterpoll_show[index:].splitlines():
            available_option_list.append(line.split()[0])
        return [option for option in available_option_list if option not in CounterpollConstants.EXCLUDE_COUNTER_SUB_COMMAND]

    @staticmethod
    def get_parsed_counterpoll_show(counterpoll_show):
        parsed_counterpoll = {}
        for line in counterpoll_show.splitlines():
            match = re.search('(?P<type>\w+)\s+(?P<interval>(default \(\d+\))|\d+)\s+(?P<status>\w+)', line)
            if match:
                parsed_counterpoll[match.group(CounterpollConstants.TYPE)] = {
                    CounterpollConstants.INTERVAL: match.group(CounterpollConstants.INTERVAL),
                    CounterpollConstants.STATUS: match.group(CounterpollConstants.STATUS)}
        return parsed_counterpoll

    @staticmethod
    def restore_counterpoll_interval(duthost, counterpoll_before, counterpoll_after):
        for counterpoll, value in counterpoll_before.items():
            if counterpoll_after[counterpoll] != counterpoll_before[counterpoll]:
                duthost.command(
                    CounterpollConstants.COUNTERPOLL_INTERVAL_STR.format(
                        CounterpollConstants.COUNTERPOLL_MAPPING[counterpoll],
                        re.search('\d+', value[CounterpollConstants.INTERVAL]).group()))

    @staticmethod
    def restore_counterpoll_status(duthost, counterpoll_before, counterpoll_after):
        for counterpoll, value in counterpoll_after.items():
            if counterpoll_after[counterpoll][CounterpollConstants.STATUS] \
                    != counterpoll_before[counterpoll][CounterpollConstants.STATUS]:
                duthost.command(CounterpollConstants.COUNTERPOLL_RESTORE.format(
                    CounterpollConstants.COUNTERPOLL_MAPPING[counterpoll],
                    counterpoll_before[counterpoll][CounterpollConstants.STATUS]))

    @staticmethod
    def disable_counterpoll(duthost, counter_type_list):
        for counterpoll_type in counter_type_list:
            duthost.command(CounterpollConstants.COUNTERPOLL_DISABLE.format(counterpoll_type))
