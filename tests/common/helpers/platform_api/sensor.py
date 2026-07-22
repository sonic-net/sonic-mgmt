"""
Interface to interact with the sensors of the DUT via platform APIs remotely
"""

import json
import logging


class Sensor():
    """
    Base sensor API interface
    Must be inherited by sensor types that conform to SensorBase
    """

    logger = logging.getLogger(__name__)
    sensor_type = "INVALID"

    @classmethod
    def sensor_api_helper(cls, conn, index, name, args=None):
        """
        Helper to run http API command for varying sensor types

        Args:
            conn: Platform API connector
            index(int/str): Sensor index
            name(str): Sensor name
            args(list): Extra arguments for http POST command

        Returns:
            Value returned from platform API by http POST
        """
        if args is None:
            args = []
        conn.request("POST", f"/platform/chassis/{cls.sensor_type}_sensor/{index}/{name}", json.dumps({"args": args}))
        resp = conn.getresponse()
        res = json.loads(resp.read())["res"]
        cls.logger.info('Executing sensor API: "%s", index: %s, arguments: "%s", result: "%s"', name, index, args, res)
        return res

    @classmethod
    def sensor_api(cls, conn, index, name, args=None):
        """
        Run http API command for generic sensor

        Args:
            conn: Platform API connector
            index(int): Sensor index
            name(str): Sensor name
            args(list): Extra arguments for http POST command

        Returns:
            Value returned from platform API by http POST
        """
        return cls.sensor_api_helper(conn, index, name, args)

    #
    # Methods inherited from DeviceBase class
    #

    @classmethod
    def get_name(cls, conn, index):
        """
        Retrieves the name of the sensor

        Args:
            conn: Platform API connector
            index(int/str): Sensor index

        Returns:
            string: The name of the sensor
        """
        return cls.sensor_api(conn, index, "get_name")

    @classmethod
    def get_presence(cls, conn, index):
        """
        Retrieves the presence of the sensor

        Args:
            conn: Platform API connector
            index(int/str): Sensor index

        Returns:
            bool: True if sensor is present, False if not
        """
        return cls.sensor_api(conn, index, "get_presence")

    @classmethod
    def get_model(cls, conn, index):
        """
        Retrieves the model number (or part number) of the sensor

        Args:
            conn: Platform API connector
            index(int/str): Sensor index

        Returns:
            string: Model/part number of sensor
        """
        return cls.sensor_api(conn, index, "get_model")

    @classmethod
    def get_serial(cls, conn, index):
        """
        Retrieves the serial number of the sensor

        Args:
            conn: Platform API connector
            index(int/str): Sensor index

        Returns:
            string: Serial number of sensor
        """
        return cls.sensor_api(conn, index, "get_serial")

    @classmethod
    def get_revision(cls, conn, index):
        """
        Retrieves the hardware revision of the device

        Args:
            conn: Platform API connector
            index(int/str): Sensor index

        Returns:
            string: Revision value of device
        """
        return cls.sensor_api(conn, index, "get_revision")

    @classmethod
    def get_status(cls, conn, index):
        """
        Retrieves the operational status of the sensor

        Args:
            conn: Platform API connector
            index(int/str): Sensor index

        Returns:
            A boolean value, True if sensor is operating properly, False if not
        """
        return cls.sensor_api(conn, index, "get_status")

    @classmethod
    def get_position_in_parent(cls, conn, index):
        """
        Retrieves 1-based relative physical position in parent device.
        If the agent cannot determine the parent-relative position for some reason,
        or if the associated value of entPhysicalContainedIn is '0',
        then the value '-1' is returned

        Args:
            conn: Platform API connector
            index(int/str): Sensor index

        Returns:
            integer: The 1-based relative physical position in parent device or -1 if cannot determine the position
        """
        return cls.sensor_api(conn, index, "get_position_in_parent")

    @classmethod
    def is_replaceable(cls, conn, index):
        """
        Indicate whether this sensor is replaceable.

        Args:
            conn: Platform API connector
            index(int/str): Sensor index

        Returns:
            bool: True if it is replaceable.
        """
        return cls.sensor_api(conn, index, "is_replaceable")

    #
    # Methods defined in SensorBase class
    #

    @classmethod
    def get_type(cls, conn, index):
        """
        Specifies the type of the sensor such as current/voltage etc.

        Args:
            conn: Platform API connector
            index(int/str): Sensor index

        Returns:
            Sensor type
        """
        return cls.sensor_api(conn, index, "get_type")

    @classmethod
    def get_value(cls, conn, index):
        """
        Retrieves measurement reported by sensor

        Args:
            conn: Platform API connector
            index(int/str): Sensor index

        Returns:
            Sensor measurement
        """
        return cls.sensor_api(conn, index, "get_value")

    @classmethod
    def get_unit(cls, conn, index):
        """
        Retrieves unit of measurement reported by sensor

        Args:
            conn: Platform API connector
            index(int/str): Sensor index

        Returns:
            Sensor measurement unit
        """
        return cls.sensor_api(conn, index, "get_unit")

    @classmethod
    def get_high_threshold(cls, conn, index):
        """
        Retrieves the high threshold of sensor

        Args:
            conn: Platform API connector
            index(int/str): Sensor index

        Returns:
            High threshold
        """
        return cls.sensor_api(conn, index, "get_high_threshold")

    @classmethod
    def get_low_threshold(cls, conn, index):
        """
        Retrieves the low threshold

        Args:
            conn: Platform API connector
            index(int/str): Sensor index

        Returns:
            Low threshold
        """
        return cls.sensor_api(conn, index, "get_low_threshold")

    @classmethod
    def set_high_threshold(cls, conn, index, value):
        """
        Sets the high threshold value of sensor

        Args:
            conn: Platform API connector
            index(int/str): Sensor index
            value: High threshold value to set

        Returns:
            A boolean, True if threshold is set successfully, False if not
        """
        return cls.sensor_api(conn, index, "set_high_threshold", [value])

    @classmethod
    def set_low_threshold(cls, conn, index, value):
        """
        Sets the low threshold value of sensor

        Args:
            conn: Platform API connector
            index(int/str): Sensor index
            value: Value

        Returns:
            A boolean, True if threshold is set successfully, False if not
        """
        return cls.sensor_api(conn, index, "set_low_threshold", [value])

    @classmethod
    def get_high_critical_threshold(cls, conn, index):
        """
        Retrieves the high critical threshold value of sensor

        Args:
            conn: Platform API connector
            index(int/str): Sensor index

        Returns:
            The high critical threshold value of sensor
        """
        return cls.sensor_api(conn, index, "get_high_critical_threshold")

    @classmethod
    def get_low_critical_threshold(cls, conn, index):
        """
        Retrieves the low critical threshold value of sensor

        Args:
            conn: Platform API connector
            index(int/str): Sensor index

        Returns:
            The low critical threshold value of sensor
        """
        return cls.sensor_api(conn, index, "get_low_critical_threshold")

    @classmethod
    def set_high_critical_threshold(cls, conn, index, value):
        """
        Sets the critical high threshold value of sensor

        Args:
            conn: Platform API connector
            index(int/str): Sensor index
            value: Critical high threshold Value

        Returns:
            A boolean, True if threshold is set successfully, False if not
        """
        return cls.sensor_api(conn, index, "set_high_critical_threshold", [value])

    @classmethod
    def set_low_critical_threshold(cls, conn, index, value):
        """
        Sets the critical low threshold value of sensor

        Args:
            conn: Platform API connector
            index(int/str): Sensor index
            value: Critial low threshold Value

        Returns:
            A boolean, True if threshold is set successfully, False if not
        """
        return cls.sensor_api(conn, index, "set_low_critical_threshold", [value])

    @classmethod
    def get_minimum_recorded(cls, conn, index):
        """
        Retrieves the minimum recorded value of sensor

        Args:
            conn: Platform API connector
            index(int/str): Sensor index

        Returns:
            The minimum recorded value of sensor
        """
        return cls.sensor_api(conn, index, "get_minimum_recorded")

    @classmethod
    def get_maximum_recorded(cls, conn, index):
        """
        Retrieves the maximum recorded value of sensor

        Args:
            conn: Platform API connector
            index(int/str): Sensor index

        Returns:
            The maximum recorded value of sensor
        """
        return cls.sensor_api(conn, index, "get_maximum_recorded")


class VoltageSensor(Sensor):
    """
    Voltage sensor API interface
    """

    sensor_type = "voltage"


class CurrentSensor(Sensor):
    """
    Current sensor API interface
    """

    sensor_type = "current"
