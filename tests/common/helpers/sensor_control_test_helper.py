import pytest
from tests.common.reboot import reboot


class BaseMocker:
    """
    @summary: Base class for sensor control data mocker

    This base class defines the basic interface to be provided by base mocker. Mockers implemented by each
    vendor must be a subclass of this base class.
    """
    # Mocker type dictionary. Vendor must register their concrete mocker class to this dictionary.
    _mocker_type_dict = {}

    def __init__(self, dut):
        """
        Constructor of a mocker.
        :param dut: DUT object representing a SONiC switch under test.
        """
        self.dut = dut

    def mock_data(self):
        """
        Generate mock data.
        :return:
        """
        pass

    def check_result(self, actual_data):
        """
        Check actual data with mocked data.
        :param actual_data: A dictionary contains actual command line data. Key of the dictionary is the unique id
                            of a line of command line data. For 'show platform fan', the key is FAN name. Value
                            of the dictionary is a list of field values for a line.
        :return: True if actual data match mocked data else False
        """
        pass

    def deinit(self):
        """
        Destructor. Vendor specific clean up work should do here.
        :return:
        """
        pass

    @classmethod
    def register_mocker_type(cls, name, mocker_type):
        """
        Register mocker type with its name.
        :param name: Name of a mocker type. For example: FanStatusMocker.
        :param mocker_type: Class of a mocker.
        :return:
        """
        cls._mocker_type_dict[name] = mocker_type

    @classmethod
    def get_mocker_type(cls, name):
        """
        Get mocker type by its name.
        :param name: Name of a mocker type. For example: FanStatusMocker.
        :return: Class of a mocker.
        """
        return cls._mocker_type_dict[name] if name in cls._mocker_type_dict else None


def mocker(type_name):
    """
    Decorator for register mocker type.
    :param type_name: Name of a mocker type.
    :return:
    """
    def wrapper(object_type):
        BaseMocker.register_mocker_type(type_name, object_type)
        return object_type
    return wrapper


@pytest.fixture
def mocker_factory(localhost, duthosts, enum_rand_one_per_hwsku_hostname):
    """
    Fixture for thermal control data mocker factory.
    :return: A function for creating thermal control related data mocker.
    """
    mockers = []
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    def _create_mocker(dut, mocker_name):
        """
        Create vendor specified mocker object by mocker name.
        :param dut: DUT object representing a SONiC switch under test.
        :param mocker_name: Name of a mocker type.
        :return: Created mocker instance.
        """
        platform = dut.facts['platform']
        mocker_object = None

        if 'mlnx' in platform or 'nvidia' in platform:
            mocker_type = BaseMocker.get_mocker_type(mocker_name)
            if mocker_type:
                mocker_object = mocker_type(dut)
                mockers.append(mocker_object)
        else:
            pytest.skip("No mocker defined for this platform {}".format(platform))
        return mocker_object

    yield _create_mocker

    try:
        for m in mockers:
            m.deinit()
    except Exception as e:
        reboot(duthost, localhost)
        assert 0, "Caught exception while recovering from mock - {}".format(
            repr(e))
