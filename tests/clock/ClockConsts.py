
class ClockConsts:
    STDOUT = "stdout"
    STDERR = "stderr"

    DATE = "date"
    TIME = "time"
    TIMEZONE = "timezone"

    TEST_TIMEZONE = "Asia/Jerusalem"
    TIME_MARGIN = 6
    RANDOM_NUM = 6

    # sonic commands
    CMD_SHOW_CLOCK = "show clock"
    CMD_SHOW_CLOCK_TIMEZONES = "show clock timezones"
    CMD_CONFIG_CLOCK_TIMEZONE = "config clock timezone"
    CMD_CONFIG_CLOCK_DATE = "config clock date"

    # expected outputs
    OUTPUT_CMD_SUCCESS = ''

    # expected errors
    ERR_BAD_TIMEZONE = 'Timezone {} does not conform format'
    ERR_MISSING_DATE = 'Error: Missing argument "<YYYY-MM-DD>"'
    ERR_MISSING_TIME = 'Error: Missing argument "<HH:MM:SS>"'
    ERR_BAD_DATE = 'Date {} does not conform format YYYY-MM-DD'
    ERR_BAD_TIME = 'Time {} does not conform format HH:MM:SS'

    # timedatectl
    CMD_TIMEDATECTL = "timedatectl"
    TIME_ZONE = "Time zone"

    MIN_SYSTEM_DATE = "1970-01-01"
    MAX_SYSTEM_DATE = "2231-12-31"

    # ntp
    CMD_SHOW_NTP = "show ntp"
    CMD_CONFIG_NTP_ADD = "config ntp add"
    CMD_CONFIG_NTP_DEL = "config ntp del"
    OUTPUT_CMD_NTP_ADD_SUCCESS = 'NTP server {} added to configuration\nRestarting ntp-config service...'
    OUTPUT_CMD_NTP_DEL_SUCCESS = 'NTP server {} removed from configuration\nRestarting ntp-config service...'
    REGEX_NTP_POLLING_TIME = r'polling server every (\d+)'
