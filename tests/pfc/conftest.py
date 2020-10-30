import pytest
@pytest.fixture(scope='session')
def serializer(request):
    """Popular serialization methods
    """
    class Serializer(object):
        def json(self, obj):
            """Return a json string serialization of obj
            """
            import json
            return json.dumps(obj, indent=2, default=lambda x: x.__dict__)

        def yaml(self, obj):
            """Return a yaml string serialization of obj
            """
            return yaml.dump(obj, indent=2)

        def json_to_dict(self, json_string):
            """Return a dict from a json string serialization
            """
            return json.loads(json_string)

        def yaml_to_dict(self, yaml_string):
            """Return a dict from a yaml string serialization
            """
            return yaml.load(yaml_string)

    return Serializer()


def generate_params_port_id(metafunc):
    return range(1)


def generate_params_lossless_priorities(metafunc):
    #priolist = [[3], [4], [3, 4]]
    priolist =[[3]]
    return priolist


def pytest_generate_tests(metafunc):
    if "port_id" in metafunc.fixturenames:
        port_ids = generate_params_port_id(metafunc)
        metafunc.parametrize("port_id", port_ids)

    if "lossless_prio" in metafunc.fixturenames:
        lossless_priorities = generate_params_lossless_priorities(metafunc)
        metafunc.parametrize("lossless_prio", lossless_priorities)   
