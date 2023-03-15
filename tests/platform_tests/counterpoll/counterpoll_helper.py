from tests.platform_tests.counterpoll.counterpoll_constants import CounterpollConstants


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
        return [option for option in available_option_list if option not in CounterpollConstants.EXCLUDE_COUNTER_SUB_COMMAND]

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
        for counterpoll, value in counterpoll_after.items():
            if counterpoll not in counterpoll_before:
                continue
            else:
                if counterpoll_after[counterpoll][CounterpollConstants.STATUS] \
                        != counterpoll_before[counterpoll][CounterpollConstants.STATUS]:
                    duthost.command(CounterpollConstants.COUNTERPOLL_RESTORE.format(
                        CounterpollConstants.COUNTERPOLL_MAPPING[counterpoll],
                        counterpoll_before[counterpoll][CounterpollConstants.STATUS]))

    @staticmethod
    def disable_counterpoll(duthost, counter_type_list):
        for counterpoll_type in counter_type_list:
            duthost.command(CounterpollConstants.COUNTERPOLL_DISABLE.format(counterpoll_type))

    @staticmethod
    def enable_counterpoll(duthost, counter_type_list):
        for counterpoll_type in counter_type_list:
            duthost.command(CounterpollConstants.COUNTERPOLL_ENABLE.format(counterpoll_type))

    @staticmethod
    def set_counterpoll_interval(duthost, counterpoll_type, interval):
        duthost.command(CounterpollConstants.COUNTERPOLL_INTERVAL_STR.format(counterpoll_type, interval))
