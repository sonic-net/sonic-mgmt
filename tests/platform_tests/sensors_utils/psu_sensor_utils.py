import json
import logging
import os
import re
import yaml

PSU_SENSORS_DATA_FILE = "psu_data.yaml"
PSU_SENSORS_JSON_FILE = "psu_sensors.json"
MISSING_PSU = "N/A"
PSU_NUM_SENSOR_PATTERN = r'PSU-(\d+)(?:\([A-Z]\))?'
SKIPPED_CHECK_TYPES = ["psu_skips", "sensor_skip_per_version"]
logger = logging.getLogger()


def update_sensor(sensor_path, psu_num, bus_num, bus_address, psu_side):
    """
    Updates the sensor_path (original format can be seen in psu-data.yml) to contain platform related information
    :param sensor_path: Sensor path as taken from psu-data.yml (contains * where platform related data is needed)
    :param psu_num: The psu number
    :param bus_num: bus number of sensors from this psu number
    :param bus_address: bus address of sensors from this psu number
    :param psu_side: psu_side of this psu number, could be empty
    :returns: full parsed psu sensor path
    """
    # Some of the sensors from sku-sensors-data.yml are parsed together as a list and not separately as a string,
    # to make the processing identical, we process both cases as a list
    paths_to_add = []
    add_as_list = False
    if isinstance(sensor_path, list):
        sensor_paths = sensor_path
        add_as_list = True
    else:
        sensor_paths = [sensor_path]
    for path in sensor_paths:
        path_with_bus_data = path.replace("*-*", f"{bus_num}-{bus_address}")
        if psu_side:
            path_with_psu_num = path_with_bus_data.replace("*", f"{psu_num}({psu_side})")
        else:
            path_with_psu_num = path_with_bus_data.replace("*", f"{psu_num}")
        paths_to_add.append(path_with_psu_num)
    if add_as_list:
        return paths_to_add
    return paths_to_add[0]


def is_psu_sensor(sensor, psu_sensor_prefix):
    """
    The function returns whether the current sensor is a psu sensor
    :param sensor: a sensor path in the format of sensors-sku-data.yml file
    :param psu_sensor_prefix: psu sensor prefix of the platform - for example dps460-i2c
    :return: True if sensor is a psu sensor and False otherwise
    """
    psu_sensor_pattern = rf'^{psu_sensor_prefix}-.*-.*'
    # Sometimes (line in compares section, the yaml will convert the sensors to list of sensor paths)
    if isinstance(sensor, list):
        return all([re.match(psu_sensor_pattern, sensor_path) for sensor_path in sensor])
    else:
        return bool(re.match(psu_sensor_pattern, sensor))


def parse_num_from_sensor_path(sensor_path):
    """
    Parses the psu number from the sensor_path
    :param sensor_path: a sensor path in the format of sensors-sku-data.yml file
    :return: The slot of the PSU sensor_path is a part of or None if no slot was found (means it's not a PSU sensor)
    """
    match = re.search(PSU_NUM_SENSOR_PATTERN, sensor_path)
    if match:
        return match.group(1)
    else:
        logger.error(f"Couldn't find PSU number in {sensor_path}")


def should_replace_sensor(sensor_path, psu_nums_to_remove, psu_sensor_prefix):
    """
    The function returns whether the sensor_path is related to a PSU slot in psu_nums_to_replace
    :param sensor_path: a sensor path in the format of sensors-sku-data.yml file
    :param psu_nums_to_remove: set of psu numbers whose numbers we want to remove
    :param psu_sensor_prefix: psu sensor prefix of the platform - for example dps460-i2c
    :return: a dictionary of installed PSUs entries, mapping psu slots (numbers) to the psu models

    """
    if not is_psu_sensor(sensor_path, psu_sensor_prefix):
        return False

    if isinstance(sensor_path, list):
        return all([parse_num_from_sensor_path(path) in psu_nums_to_remove for path in sensor_path])
    else:
        return parse_num_from_sensor_path(sensor_path) in psu_nums_to_remove


def update_sensor_data(alarm_data, psu_platform_data, psu_numbers):
    """
    The function updates the alarm_data according to psu_platform_data for each of the psu_numbers listed
    :param alarm_data: a list of psu sensors of some alarm_type
    :param psu_platform_data: A dictionary containing for each psu number, the bus number, bus address and PSU slot side
     (empty if doesn't exist)
    :param psu_numbers: A list of numbers we want to retrieve psu info from psu_platform_data
    :return: a dictionary of installed PSUs entries, mapping psu slots (numbers) to the psu models
    """
    updated_alarm_data = []
    for psu_num in psu_numbers:
        bus_num, bus_address, psu_side = psu_platform_data[psu_num]
        updated_alarm_data.extend([update_sensor(sensor_path, psu_num, bus_num, bus_address, psu_side) for
                                   sensor_path in alarm_data])
    return updated_alarm_data


class SensorHelper:
    """
    Helper class to the test_sensors tests
    """

    def __init__(self, duthost):
        """
        Setup important variables of the class
        """

        self.missing_psus = None
        self.supports_dynamic_psus = False
        self.psu_dict = None
        self.uncovered_psus = None
        self.psu_platform_data = None
        self.psu_sensors_checks = None
        self.duthost = duthost
        self.platform = self.duthost.facts['platform']
        self.fetch_psu_data()
        self.read_psus_from_dut()

    def fetch_psu_data(self):
        """
        Parses psu_data and psu_sensor files into needed variables
        """
        psu_sensors_data_file_fullpath = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                      PSU_SENSORS_DATA_FILE)
        psu_sensors_data = yaml.safe_load(open(psu_sensors_data_file_fullpath).read())
        self.psu_sensors_checks = psu_sensors_data['sensors_checks']
        psu_sensors_json_file_fullpath = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                      PSU_SENSORS_JSON_FILE)
        with open(psu_sensors_json_file_fullpath) as file:
            psu_json_mapping = json.load(file)
        if self.platform in psu_json_mapping:
            self.psu_platform_data = psu_json_mapping[self.platform]
            self.supports_dynamic_psus = True
        else:
            logger.warning(f"Platform {self.platform} does not support dynamic testing of PSU sensors. "
                           f"Test will run without fetching psu sensors dynamically.")

    def read_psus_from_dut(self):
        """
        The function reads the psus installed on the dut and initialized 2 fields of the class.
        The first field is a dictionary called psu_dict that consists of entries {psuNum: psuModel} of PSU installed on
        the dut that exist in the dictionary field psu_sensors_checks .
        The second field is a set called uncovered_psus and consists of psu models not in the dictionary field
        psu_sensors_checks
        """
        self.psu_dict = dict()
        self.uncovered_psus = set()
        self.missing_psus = set()
        if self.supports_dynamic_psus:
            psu_data = json.loads(self.duthost.shell('show platform psu --json')['stdout'])
            covered_psus = set(self.psu_sensors_checks.keys())
            for psu in psu_data:
                psu_index, psu_model = psu["index"], psu["model"]
                if psu_model in covered_psus:
                    self.psu_dict[psu_index] = psu_model
                elif psu["model"] == MISSING_PSU:
                    self.missing_psus.add(psu_index)
                    logger.warning(f"Slot {psu_index} is missing a PSU.")
                else:
                    self.uncovered_psus.add(psu_model)

    def platform_supports_dynamic_psu(self):
        """
        Getter function for the field supports_dynamic_psus
        """
        return self.supports_dynamic_psus

    def get_missing_psus(self):
        """
        Getter function for the field missing_psus
        """
        return self.missing_psus

    def get_psu_index_model_dict(self):
        """
        Getter function for self.psu_dict created in the function read_psus_from_dut.
        """
        return self.psu_dict

    def get_uncovered_psus(self):
        """
        Returns a set of psus on the platform that do not have their sensors in psu_data.yml
        """
        return self.uncovered_psus

    def remove_psu_checks(self, sensor_checks, psu_nums_to_remove):
        """
        This function removes all psu sensor_checks of a certain psu from the platform sensor_checks
        :param sensor_checks: the sensors data fetched from sensors-sku-data.yml file
        :param psu_nums_to_remove: set of psu numbers whose numbers we want to remove from sensor_checks
        """
        for check_type, checks in sensor_checks.items():
            if check_type in SKIPPED_CHECK_TYPES:
                continue
            for alarm_hw_type, alarm_data in checks.items():
                platform_sensors = []
                for sensor_path in alarm_data:
                    if not should_replace_sensor(sensor_path, psu_nums_to_remove, self.get_sensor_psu_prefix()):
                        platform_sensors.append(sensor_path)
                    else:
                        logger.debug(f"Removed PSU sensor - {sensor_path}")
                checks[alarm_hw_type] = platform_sensors

    def get_sensor_psu_prefix(self):
        """
        This function will fetch the sensor bus pattern prefix from psu_sensors_data.
        :return: sensor psu sensor prefix without bus num and address of dut - i.e., dps460-i2c of dps460-i2c-4-58"
        """
        psu_bus_path = list(self.psu_platform_data["default"]["chip"].keys())[0]  # grab some key from the chip part
        # the psu_bus_path will look something like dps460-i2c-*-58 - we want to generalize it - dps460-i2c-*-*
        psu_bus_parts = psu_bus_path.split('-')[:2]  # Split the string by '-', the prefix is the first 2 words
        return '-'.join(psu_bus_parts)

    def update_psu_sensors(self, sensors_checks, psu_models_to_replace, hardware_version):
        """
        This function adds to sensor_checks the PSU sensors fetched in runtime from psu-sensors.yml file.
        :param sensors_checks: the sensors data fetched from sensors-sku-data.yml file, after removal of psu sensors
        :param psu_models_to_replace: set of psu numbers whose numbers we want to remove from sensor_checks
        :param hardware_version: hardware version as retrieved from mellanox_data.get_hardware_version
        """
        psu_platform_data = self.parse_psu_json_mapping(set(psu_models_to_replace.keys()), hardware_version)
        # create mapping from psu_models to sets of psu numbers matching them
        psu_nums_per_psu = dict()
        for psu_num, psu_model in psu_models_to_replace.items():
            psu_nums_per_psu.setdefault(psu_model, set()).add(psu_num)

        # For each psu, update the generalized psu sensors in psu_sensors_data with this psu platform related data
        for psu_model, psu_nums in psu_nums_per_psu.items():
            # Grab the generalized checks we need to update for each psu slot that matches the model
            psu_sensors_checks = self.psu_sensors_checks[psu_model]
            for check_type, checks in sensors_checks.items():
                if check_type in SKIPPED_CHECK_TYPES:
                    continue
                for alarm_hw_type, alarm_data in checks.items():
                    psu_alarm_data = psu_sensors_checks[check_type][alarm_hw_type]
                    updated_alarm_data = update_sensor_data(psu_alarm_data, psu_platform_data, psu_nums)
                    checks[alarm_hw_type].extend(updated_alarm_data)

    def parse_psu_json_mapping(self, psu_nums_to_replace, hardware_version):
        """
        This function returns a dictionary that contains for each PSU slot in the device, the bus number,
        bus address and psu side
        :param psu_json_mapping: mapping from platform to relevant data regarding the psu sensors
        :param psu_nums_to_replace: set  of psu numbers we want to fetch sensors for
        :param platform: the platform of the dut
        :param hardware_version: hardware version as retrieved from mellanox_data.get_hardware_version
        :returns: A dictionary containing for each psu number, the bus number, bus address and PSU slot
        side (empty if doesn't exist)
        """

        psu_json_data = dict()
        hw_type = hardware_version if hardware_version in self.psu_platform_data.keys() else "default"
        bus_data = self.psu_platform_data[hw_type]["bus"]
        chip_data = self.psu_platform_data[hw_type]["chip"]
        for chip_key, chip_value in chip_data.items():
            if len(chip_value) == 1:  # means we have no side in the sensor path
                psu_num = chip_value[0]
                psu_side = ""
            else:
                psu_num, psu_side = chip_value
            bus_address = chip_key.split('-')[-1]
            if psu_num in psu_nums_to_replace:
                bus_number = chip_key.split('-')[-2]  # we try to get it from the bus_data of chip part but it can be *
                if bus_number == '*':  # if the bus data is same for all slots, it will be * in the chip part and we
                    # take it from general bus_data part
                    bus_number = bus_data[0].split('-')[1]
                psu_json_data[psu_num] = (bus_number, bus_address, psu_side)
        return psu_json_data
