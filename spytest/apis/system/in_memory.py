
import os
import re
import datetime
from spytest import st, SpyTestDict
from utilities.common import remove_last_line_from_string
from apis.system.basic import list_file, remove_file, get_dut_date_time_obj, show_techsupport_file_content
from apis.system.logging import generate_log_from_script, sonic_clear, show_logging
from apis.system.box_services import generate_tech_support

imlog_data = SpyTestDict()

imlog_data.disk_log_path = r'/var/log'
imlog_data.dummy_file_name = 'testing.file'
imlog_data.in_memory_log_path = r'/var/log/ramfs'
imlog_data.ramdisk_file_size_limit_byte = 2097152  # In-Memory Syslog Rotation after 20000 logs, which accounts to 2 MB considering each DEBUG log entry size to be 125 Bytes
imlog_data.file_size_limit_error_margin_byte = 1048576
imlog_data.disk_file_size_limit_byte = 6291456    # Disk Syslog Rotation after 50000 logs, which accounts to 6 MB considering each NOTICE log entry size to be 127 Bytes.
imlog_data.file_list_regex = r'([\w-]+)\s+([0-9]+)\s+(\w+)\s+(\w+)\s+([0-9]+)\s+({})\s+([\.\/\_\w-]+)'
imlog_data.log_level_list = ['DEBUG', 'INFO', 'NOTICE', 'WARNING', 'ERR', 'CRIT', 'ALERT', 'EMERG']
imlog_data.log_level_location_map = {'DEBUG': 'IN_MEMORY', 'INFO': 'IN_MEMORY', 'NOTICE': 'STANDARD',
                                     'WARNING': 'STANDARD', 'ERR': 'STANDARD', 'CRIT': 'STANDARD',
                                     'ALERT': 'STANDARD', 'EMERG': 'STANDARD'}
imlog_data.log_level_location_incorrect_map = {'DEBUG': 'STANDARD', 'INFO': 'STANDARD', 'NOTICE': 'IN_MEMORY',
                                               'WARNING': 'IN_MEMORY', 'ERR': 'IN_MEMORY', 'CRIT': 'IN_MEMORY',
                                               'ALERT': 'IN_MEMORY',
                                               'EMERG': 'IN_MEMORY'}
imlog_data.log_level_priority_map = {'DEBUG': 7, 'INFO': 6, 'NOTICE': 5, 'WARNING': 4, 'ERR': 3, 'CRIT': 2, 'ALERT': 1,
                                     'EMERG': 0}
imlog_data.log_message_format = r'Testing_log_msg_id_{}_start_{}_end'
imlog_data.log_msg_id = 0
imlog_data.logger_file_name = "generate_log.py"
imlog_data.kernel_crash_first_cmd = r'echo 1 | sudo tee /proc/sys/kernel/sysrq'
kernel_crash_second_cmd = r'echo c | sudo tee /proc/sysrq-trigger'
imlog_data.mem_range = "40000000-43ffffff"
imlog_data.ramdisk_path = "/dev/ramdisk"
imlog_data.techsupport_filename_regex = r'sonic_dump_sonic_\d+_\d+.tar.gz'
imlog_data.techsupport_filename_regex_for_grep = r'sonic_dump_sonic_[0-9]\+_[0-9]\+.tar.gz'
imlog_data.techsupport_file_path = "/var/dump"
imlog_data.techsupport_file_content_search_pattern = [r'[-\/]syslog[-\.]', 'gz']
imlog_data.time_full_iso_regex = r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}'
imlog_data.time_full_iso_regex_for_grep = r'[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}\s\+[0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}\.[0-9]\{6,9\}'
imlog_data.time_auto_log_rotate_seconds = 300
imlog_data.time_auto_log_rotate_error_margin_seconds = 30
imlog_data.time_full_iso_option = '+%Y-%m-%d %T'


def download_log_generator(dut):
    """
    Copies log generator script from test script folder to location: /home/admin on dut

    :param dut:
    :return:
    """

    srcpath = os.path.join(os.path.dirname(__file__), '../../', 'tests/system/in_memory_log/', imlog_data.logger_file_name)
    dstpath = "/home/admin" + "/" + imlog_data.logger_file_name
    cmd = "chmod +x {}".format(imlog_data.logger_file_name)
    st.log("Downloading log generator file '{}' to /home/admin".format(imlog_data.logger_file_name))
    st.upload_file_to_dut(dut, src_file=srcpath, dst_file=dstpath)
    st.log("Making File executable")
    st.config(dut, cmd, skip_error_check=True)
    return True


def remove_log_generator(dut):
    """
    Deletes log generator from location: /home/admin on dut

    :param dut:
    :return:
    """

    remove_file(dut, "home/admin/" + imlog_data.logger_file_name)
    return True


def delete_all_syslogs(dut):
    """
    Clears syslogs from In-memory log location and removes syslogs from disk log location

    :param dut:
    :return:
    """

    st.log("Clearing syslogs from In-memory location")
    sonic_clear(dut)
    st.log("Deleting syslog files on disk")
    remove_file(dut, "{}/*log!(*rotate*)".format(imlog_data.disk_log_path))
    return True


def syslog_file_path(**kwargs):
    """
    Create syslog file path string based on Log level and Log location
    Author: Piyush Darshan Pattnayak

    :param log_level: 'DEBUG', 'INFO', 'NOTICE', 'WARNING', 'ERR', 'CRIT', 'ALERT', 'EMERG'
    :param location: 'IN_MEMORY' for in_memory location log file, Pass nothing for disk location log file
    :param file_sequence: 0 or Positive number; 0 for file name without any numeric extension,
                          Used only for log files in disk location.
    :return: Full file path
    """

    log_level = kwargs.get("log_level", None)
    log_location = kwargs.get("log_location", "")
    file_sequence = kwargs.get("file_sequence", 0)
    folder_path = imlog_data.disk_log_path
    file_name = r'syslog'
    file_ext = r'.log'
    if log_level in ['DEBUG', 'INFO']:
        if "IN_MEMORY" in log_location:
            folder_path = imlog_data.in_memory_log_path
            file_name = r'in-memory-' + file_name
        file_name += "-" + log_level.lower() + file_ext
    if file_sequence > 0 and 'IN_MEMORY' not in log_location:
        file_name += r'.' + str(file_sequence)
    file_path = folder_path + "/" + file_name
    return file_path


def convert_size_in_byte_to_units(byte):
    """
    Converts file size in Bytes to a human readable format.
    Display unit is can be scalable by appending new units to the mem_unit list in ascending order of size.
    Author: Piyush Darshan Pattnayak

    :param byte: File size in Bytes
    :return: Type- string; Size upto two Unit places
    example: For byte: 1023; Returns 1023 B
             For byte: 1024: Returns 1 KB
             For byte: 1026; Returns 1 KB  2 B
    """

    most_significant_value = int(byte)
    if most_significant_value < 0:
        st.error("File size received is not a positive number")
        return -1
    least_significant_value = 0
    mem_unit = ['B', 'KB', 'MB', 'GB']
    msv_unit = 0
    lsv_unit = 0
    while most_significant_value >= 1024 and msv_unit < len(mem_unit) - 1:
        if most_significant_value % 1024:
            least_significant_value = most_significant_value % 1024
            lsv_unit = msv_unit
        most_significant_value = most_significant_value // 1024
        msv_unit += 1
    size_with_unit = "{} ".format(most_significant_value) + mem_unit[msv_unit]
    if least_significant_value:
        size_with_unit += "  {} ".format(least_significant_value) + mem_unit[lsv_unit]
    return size_with_unit


def log_message_pattern(**kwargs):
    """
    Creates log message search pattern for glob and regex

    :param log_msg_id: 0 to 7 digit Positive number; Message id to search in log.
    :param log_msg_id_offset: 0 to 7 digit Positive Number; Negative offset for message id.
    :return:
    """

    log_msg_id = kwargs.get("log_msg_id", 0)
    log_msg_id_offset = kwargs.get("log_msg_id_offset", 0)
    for_grep = kwargs.get("for_grep", 0)
    if for_grep:
        return imlog_data.log_message_format.format(str(log_msg_id - log_msg_id_offset).zfill(7),
                                                    imlog_data.time_full_iso_regex_for_grep)
    return imlog_data.log_message_format.format(str(log_msg_id - log_msg_id_offset).zfill(7),
                                                imlog_data.time_full_iso_regex + r'.\d+')


def search_log_in_file(dut, log_level, **kwargs):
    """
    Searches log in only syslog files using grep command

    :param dut: DUT Name
    :param log_level: 'DEBUG', 'INFO', 'NOTICE', 'WARNING', 'ERR', 'CRIT', 'ALERT', 'EMERG'
    :param log_location: 'IN_MEMORY' for in_memory location log file, Pass nothing for disk location log file
    :param file_sequence: 0 or Positive number; 0 for file name without any numeric extension,
                          Used only for log files in disk location.
    :param log_msg_id: 0 to 7 digit Positive number; Message id to search in log.
    :param log_msg_id_offset: 0 to 7 digit Positive Number; Negative offset for message id.
    :return:
    """

    log_location = kwargs.get("log_location", "")
    file_sequence = kwargs.get("file_sequence", 0)
    log_msg_id = kwargs.get("log_msg_id", 0)
    log_msg_id_offset = kwargs.get("log_msg_id_offset", 0)
    command = 'zgrep' if file_sequence > 1 else 'grep'
    block_size = get_disk_block_size(dut)
    if block_size < 1024:
        path = syslog_file_path(log_level=log_level, log_location=log_location, file_sequence=file_sequence + 1)
    else:
        path = syslog_file_path(log_level=log_level, log_location=log_location, file_sequence=file_sequence)
    path = "{}.gz".format(path) if file_sequence > 1 else path
    result = "found in file {}.".format(path.split('/')[-1])
    msg_pattern_for_grep = log_message_pattern(log_msg_id=log_msg_id, log_msg_id_offset=log_msg_id_offset, for_grep=True)
    command += " '" + msg_pattern_for_grep + "' " + path
    output = st.config(dut, command, skip_tmpl=True, skip_error_check=True)
    if output:
        msg_pattern_for_search = log_message_pattern(log_msg_id=log_msg_id, log_msg_id_offset=log_msg_id_offset)
        if re.search(msg_pattern_for_search, output):
            st.log("Log " + result)
            return True
    st.log("Log not " + result)
    return False


def verify_log(dut, **kwargs):
    """
    Searches for log in Syslog and In-Memory log location using command 'show logging'
    which have been logged by function 'generate_log_from_script' or 'generate_log_from_cmd' from logging.py

    :param dut: DUT Name
    :param log_type: 'IN_MEMORY' for 'show in-memory logging', 'STANDARD' for 'show logging'
    :param log_level: 'DEBUG', 'INFO', 'NOTICE', 'WARNING', 'ERR', 'CRIT', 'ALERT', 'EMERG'
    :param filter_list: List of keywords to be filtered from the logging output using 'grep'
    :param log_msg_id_offset: 0 to 7 digit Positive Number; Negative offset for message id.
    :return:
    """

    log_level = kwargs.get("log_level", None)
    log_type = kwargs.get("log_type", None)
    filter_list = kwargs.get("filter_list", None)
    log_msg_id = kwargs.get("log_msg_id", 0)
    log_msg_id_offset = kwargs.get("log_msg_id_offset", 0)
    search_list = [log_level]
    match_result = []
    if not filter_list:
        filter_list = log_message_pattern(log_msg_id=imlog_data.log_msg_id, log_msg_id_offset=log_msg_id_offset, for_grep=True)
        search_list += [str(log_msg_id - log_msg_id_offset).zfill(7)]
#       Using 'severity' option for filtering instead of 'filter_list', because string with
#       escape characters is not stored as raw string while being converted to List,
#       i.e., backslash is added before each special character
        output = show_logging(dut, keyword=log_level, log_type=log_type, severity=filter_list)
    else:
        if not isinstance(filter_list, list):
            filter_list = [filter_list]
        search_list += filter_list
        output = show_logging(dut, keyword=log_level, log_type=log_type, filter_list=filter_list)
    if output:
        out_list = output[0].split('\n')
        for line in out_list:
            match_result = []
            for word in search_list:
                match_result.append((False, True)[word in line])
            if False not in match_result:
                break
        for i in range(len(search_list)):
            st.log("Match for [{}] : {} ".format(search_list[i], "Found" if match_result[i] else "Not found"))
        if False not in match_result:
            st.log('Log found')
            return True
    st.log('Log not found')
    return False


def get_disk_block_size(dut):
    cli_type = 'click'
    output = st.show(dut, "(df --block-size=1M |grep -E '/var/log$') | awk '{ print $2}'", type=cli_type, skip_tmpl=True)
    if len(output) == 0:
        st.error("Output is Empty")
        return 0
    output = int(remove_last_line_from_string(output))
    st.log('/var/log block size in device is {}M'.format(output))
    return output


def generate_and_check_file_rotated(dut, log_level, logger_file_name, **kwargs):
    """
    Generates logs of desired level until the respective log file is rotated

    :param dut:
    :param log_level: 'DEBUG', 'INFO', 'NOTICE', 'WARNING', 'ERR', 'CRIT', 'ALERT', 'EMERG'
    :param logger_file_name: Name of script to be used for generating logs.
    :param log_location: Specify from which location
    :return:
    """

    log_location = kwargs.get("log_location", "")
    log_msg_id = kwargs.get("log_msg_id", 0)
    log_priority = imlog_data.log_level_priority_map[log_level]
    retry_ls = 5
    retry_rotated = 10
    attempt = 0
    last_size = 0
    file_sequence = 0
    size = -1
    file_size_limit_byte = imlog_data.disk_file_size_limit_byte
    if log_level in imlog_data.log_level_list[0:2]:
        file_size_limit_byte = imlog_data.ramdisk_file_size_limit_byte
    block_size = get_disk_block_size(dut)

    # Log generation and rotation detection logic
    for _ in range(100):
        for i in range(retry_ls):
            st.log("Get file size, Attempt {}".format(i + 1))
            log_file = list_file(dut, path=syslog_file_path(log_level=log_level, log_location=log_location,
                                                            file_sequence=file_sequence))
            if log_file:
                last_size = size
                size = int(log_file[0]["size"])
                st.log("File size: {}".format(convert_size_in_byte_to_units(size)))
                break
        if size < 0:
            st.error("Unable to get file size")
            break

        # Check if log file size reduced, then look for file of respective log level in disk log location.
        # This pplies to both In-Memory syslog file and Disk syslog file
        # At the time of writing this content, on log count exceeding 20K limit for In-memory syslog files
        # Files are moved from in-memory storage to disk location for further storage.
        if size < last_size:
            st.log("Decrease in Log file size observed.")
            st.log("Verify syslog{} file present on disk of size greater than {}"
                   .format(" " + log_level.lower(), convert_size_in_byte_to_units(last_size)))
            # If checking for rotation of 'syslog' log file,
            # then look for size of the next file in sequence i.e., 'syslog.1' log file to confirm rotation.
            # If checking for In-memory log file rotation, then look for 'syslog-debug.log'
            # or 'syslog-info.log' file size in disk log folder to confirm rotation as per the level of logs generated.
            if "IN_MEMORY" not in log_location:
                file_sequence += 1
            rotated_log_file = []
            for i in range(retry_ls):
                st.log("Get file size, Attempt {}".format(i + 1))
                if block_size < 1024:
                    rotated_log_file = list_file(dut, path=syslog_file_path(log_level=log_level,
                                                                            file_sequence=file_sequence + 1) + "*")
                else:
                    rotated_log_file = list_file(dut, path=syslog_file_path(log_level=log_level, file_sequence=file_sequence))
                if rotated_log_file:
                    size = int(rotated_log_file[0]["size"])
                    break
            if rotated_log_file:
                st.log("File size = {}".format(convert_size_in_byte_to_units(size)))
                # Check if the rotated file exists on disk and size of the log file rotated is at least same as
                # the last observed file size in In-memory/Disk space, then confirm rotation success
                if size >= last_size:
                    st.log("Pass: Log file present and size greater than last"
                           " file size [{}]".format(convert_size_in_byte_to_units(last_size)))
                    st.banner("Display Log file line count for debugging")
                    block_size = get_disk_block_size(dut)
                    if block_size < 1024:
                        st.config(dut, cmd="wc -l {}".format(
                            syslog_file_path(log_level=log_level, file_sequence=file_sequence + 1) + "*"), skip_error_check=True)
                    else:
                        st.config(dut, cmd="wc -l {}".format(
                            syslog_file_path(log_level=log_level, file_sequence=file_sequence)), skip_error_check=True)
                    return log_msg_id
                # If the rotated file exists on disk but file size is less, display if any log file with .2 extension
                # exists,for debugging.
                # At time of writing this content Syslog file with extension .2 gets compressed on generation
                else:
                    st.error("Log file size is less than last"
                             " file size [{}]".format(convert_size_in_byte_to_units(last_size)))
                    st.log("Check if a new log file exists with higher file extension")
                    new_log_file = list_file(dut, path=syslog_file_path(log_level=log_level, file_sequence=file_sequence + 1) + "*")
                    if new_log_file:
                        st.log("File size: {}".format(convert_size_in_byte_to_units(int(new_log_file[0]["size"]))))
                        st.error("Log file rotated more than once after exceeding file size limit")
                        st.banner("Display Log file line count for debugging")
                        st.config(dut, cmd="wc -l {}".format(syslog_file_path(log_level=log_level, file_sequence=file_sequence + 1)),
                                  skip_error_check=True)
                    else:
                        st.error("Rotated log file is either compressed or missing from disk")
                    return False
            else:
                st.error("Fail: Log file with extension [.{}] not found on disk".format(file_sequence))
                break
        elif size > file_size_limit_byte + imlog_data.file_size_limit_error_margin_byte:
            # Wait and retry logic: After log file exceeding expected size it takes some time for the file to be rotated.
            if attempt < retry_rotated:
                attempt += 1
                st.wait(30, "Waiting for sometime before checking file rotated or not, Attempt {}".format(attempt))
                continue
            st.error("Fail: File size exceeded {}, auto log rotate not triggered"
                     .format(convert_size_in_byte_to_units(file_size_limit_byte
                                                           + imlog_data.file_size_limit_error_margin_byte)))
            break
        # Calculate the amount of logs needed to generate to trigger rotation
        # Each log size for each level based on observation
        # For 'DEBUG' level  - 125 Bytes
        # For 'INFO' level   - 124 Bytes
        # For 'NOTICE' level - 126 Bytes
        # Using an average of 125 bytes/log for calculation
        logs_required = abs((file_size_limit_byte - size)) // 125
        # In Python 3, / is float division
        # In Python 2, / is integer division (assuming int inputs)
        # In both 2 and 3, // is integer division
        if logs_required // 2 == 0:
            logs_required = 2
        log_msg_id = generate_log_from_script(dut, log_level, no_of_logs=logs_required // 2,
                                              logger_file_name=logger_file_name, log_priority=log_priority,
                                              log_msg_id=imlog_data.log_msg_id)
        imlog_data.log_msg_id = log_msg_id
        if st.get_args("filemode"):
            break

    return False


def verify_log_rotate(dut, log_level, logger_file_name, **kwargs):
    """
    Verify Log rotation functionality

    :param dut: DUT Name
    :param log_level: 'DEBUG', 'INFO', 'NOTICE', 'WARNING', 'ERR', 'CRIT', 'ALERT', 'EMERG'
    :param log_location: IN_MEMORY for In-memory log location, Nothing for disk log location
    :param test: Type of test, SIZE - Size based rotation, TIME - time based rotation
    :param msg_id_offset: 0 to 7 digit Positive Number; Negative offset for message id.
    :return:
    """

    log_location = kwargs.get("log_location", "")
    log_msg_id = kwargs.get("log_msg_id", 0)
    log_msg_id_offset = kwargs.get("log_msg_id_offset", 0)
    test = kwargs.get("test", None)
    log_priority = imlog_data.log_level_priority_map[log_level]
    retry = 5

    if test == 'SIZE':
        msg_id = generate_and_check_file_rotated(dut, log_level, logger_file_name, log_location=log_location,
                                                 log_msg_id=imlog_data.log_msg_id, log_msg_id_offset=log_msg_id_offset)
        return msg_id

    elif test == 'TIME':
        wait_time = 10
        curr_system_time = system_time = None
        output = []
        st.log("Clearing logs before starting test")
        sonic_clear(dut)
        st.log("Fetching file size")
        for _ in range(retry):
            output = list_file(dut, path=syslog_file_path(log_level=log_level, log_location=log_location))
            if output:
                break
        if not output:
            st.error("File not found")
            return False
        st.log("File size = {}".format(convert_size_in_byte_to_units(output[0]["size"])))
        last_size = int(output[0]["size"])
        st.log("Fetching current system time")
        for _ in range(retry):
            curr_system_time = system_time = get_dut_date_time_obj(dut)
            if curr_system_time:
                st.log("System Date and Time is [{}]".format(curr_system_time))
                break
        if not curr_system_time:
            st.error("Unable to proceed with test without system time")
            return False
        st.log("Generating a {} level log with message id [{}]".format(log_level, log_msg_id))
        imlog_data.log_msg_id = generate_log_from_script(dut, log_level, logger_file_name=logger_file_name,
                                                         log_priority=log_priority, log_msg_id=log_msg_id, no_of_logs=1)
        delta = datetime.timedelta(seconds=imlog_data.time_auto_log_rotate_seconds)
        error_margin = datetime.timedelta(seconds=imlog_data.time_auto_log_rotate_error_margin_seconds)
        while True:
            size = -1
            for _ in range(retry):
                list_output = list_file(dut, path=syslog_file_path(log_level=log_level, log_location=log_location))
                if list_output:
                    size = int(list_output[0]["size"])
                    st.log("File size = {}".format(convert_size_in_byte_to_units(size)))
                    break
            if size < 0:
                st.error("Unable to proceed with test without file size")
                return False
            for _ in range(retry):
                curr_system_time = get_dut_date_time_obj(dut)
                if curr_system_time:
                    st.log("System Date and Time is [{}]".format(curr_system_time))
                    break
            if not curr_system_time:
                st.error("Unable to get system time")
                return False
            time_diff = curr_system_time - system_time
            st.log("Time elapsed : [{}] seconds".format(time_diff.total_seconds()))
            if size < last_size:
                st.log("Decrease in file size observed")
                if delta - error_margin < time_diff < delta + error_margin:
                    st.log("Pass: Time based log rotation near {} Minute interval success"
                           .format(imlog_data.time_auto_log_rotate_seconds / 60))
                    st.log("Verify generated log with message id {} present in disk file".format(imlog_data.log_msg_id))
                    if search_log_in_file(dut, log_level, log_msg_id=log_msg_id, file_sequence=1):
                        st.log("Pass: Log found in disk location")
                        return True
                    else:
                        st.error("Fail: Log not found in disk location")
                        break
                elif time_diff < delta + error_margin:
                    st.error("Fail: Log rotated before 5 minutes")
                    break
                else:
                    st.error("Fail: Log rotated after 5 minutes")
                    break
            if time_diff > (delta + error_margin):
                st.error("Fail: Logs not rotated after 5 minutes")
                break
            last_size = size
            st.wait(wait_time)
        return False
    else:
        return False


def verify_file_list_in_techsupport(dut, file_list):
    """
    Generates techsupport and verifies for list if files in it

    :param dut: DUT Name
    :param file_list: List of file names to search in techsupport
    :return: True/False, Result of match for each name in file_list
    """

    retry = 5
    output = []
    match_result = dict.fromkeys(file_list, None)
    st.log("Collecting Techsupport")
    generate_tech_support(dut, skip_error_check=True)
    for _ in range(retry):
        output = list_file(dut, imlog_data.techsupport_file_path,
                           search_keyword=imlog_data.techsupport_filename_regex_for_grep)
        if output:
            break
    if output:
        tech_filename = output[0]['entry_name']
        st.log("Techsupport Filename = {}".format(tech_filename))
        st.log("Verify Techsupport contents for {} types of log files".format(len(file_list)))
        for _ in range(retry):
            output = show_techsupport_file_content(dut, tech_filename,
                                                   search_list=imlog_data.techsupport_file_content_search_pattern)
            if output:
                break
        if output:
            for filename in file_list:
                for each_entry in output:
                    match_result[filename] = filename in each_entry['entry_name']
                    if match_result[filename]:
                        break
            for filename in file_list:
                st.log("Match for [{}] : {} ".format(filename, ("Not found", "Found")[match_result[filename]]))
        else:
            st.error("Unable to fetch techsupport contents")
    else:
        st.error("Techsupport file not found at location {}".format(imlog_data.techsupport_file_path))

    return match_result
