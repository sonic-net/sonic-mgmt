import argparse
import time
import os

from  datetime import datetime


FETCH_CPU_CMD = "ps -eo pcpu,args | sort -k 1 -r | tail -n +2"
FETCH_HDD_CMD = "df -hm /"
MEASURE_DELAY = 2


def process_cpu(log_file):
    """
    @summary: Fetch CPU utilization. Write to the file total and top 10 process CPU utilization.
    @param log_file: Opened file object to store fetched CPU utilization.
    """
    buff = []
    general_template = """
"{timestamp}":
    total: {total}
    top_consumer:
"""
    per_process_template = "        {cpu_utilization}: \"{process}\""
    top_consumer_list = []
    total = 0
    top_consumer_counter = 10

    for line in os.popen(FETCH_CPU_CMD).readlines():
        process_consumed = float(line.split()[0])
        total += process_consumed
        if top_consumer_counter:
            top_consumer_list.append(per_process_template.format(cpu_utilization=process_consumed,
                                     process=" ".join(line.split()[1:])))
            top_consumer_counter -= 1

    result = general_template.format(timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"), total=total) \
                + "\n".join(top_consumer_list)
    log_file.write(result)


def process_ram(log_file):
    """
    @summary: Fetch RAM utilization and write it to the file.
              Use 'MemTotal' and 'MemAvailable' from '/proc/meminfo' to obtain used RAM amount.
    @param log_file: Opened file object to store fetched RAM utilization.
    """
    with open('/proc/meminfo') as stream:
        for line in stream:
            if 'MemAvailable' in line:
                available_mem_in_kb = int(line.split()[1])
            if 'MemTotal' in line:
                total_mem_in_kb = int(line.split()[1])

    used = total_mem_in_kb - available_mem_in_kb
    used_percent = used * 100 / total_mem_in_kb
    log_file.write("\"{date}\": {used_ram}\n".format(date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                   used_ram=used_percent))


def process_hdd(log_file):
    """
    @summary: Fetch used amount of HDD and write it to the file. Execute command defined in FETCH_HDD_CMD.
    @param log_file: Opened file object to store fetched HDD utilization.
    """
    output_line_id = 1
    use_value_id = 4
    hdd_usage = os.popen(FETCH_HDD_CMD).read().split("\n")[output_line_id].split()[use_value_id].rstrip("%")
    log_file.write("\"{date}\": {used_ram}\n".format(date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                   used_ram=hdd_usage))


def main():
    cpu_log = open("/tmp/cpu.log", "w")
    ram_log = open("/tmp/ram.log", "w")
    hdd_log = open("/tmp/hdd.log", "w")

    print "Started resources monitoring ..."
    while True:
        process_cpu(cpu_log)
        process_ram(ram_log)
        process_hdd(hdd_log)
        time.sleep(MEASURE_DELAY)
        cpu_log.flush()
        ram_log.flush()
        hdd_log.flush()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--start", help="device file", action="store_true", default=False)
    args = parser.parse_args()

    if args.start:
        main()
