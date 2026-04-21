try:
    from pyVmomi import vim, VmomiSupport
except ImportError:
    pass


class AdvancedSettings():
    def __init__(self, cast_all_values_to_str: bool = False):
        """
        Advanced settings are essentially a dictionary of options attached to a
        vsphere entity. Depending on the object type, there may be restrictions
        about what keys and value types are accepted. Generally though, any value
        type can be added as long as it can be cast to a pyvmomi class type.
        Typical use cases include taking a dictionary from the user and comparing it
        to a list of Option objects (key/value pairs) from vsphere.
        """
        self._settings = dict()
        self.cast_all_values_to_str = cast_all_values_to_str

    def add_setting(self, key, value):
        self._settings[key] = self._convert_py_primitive_to_vmodl_type(value)

    @classmethod
    def from_py_dict(cls, data, cast_all_values_to_str: bool = False):
        obj = cls(cast_all_values_to_str=cast_all_values_to_str)
        for key, value in data.items():
            obj.add_setting(key, value)

        return obj

    @classmethod
    def from_vsphere_config(cls, config):
        obj = cls()
        for option in config:
            obj._settings[option.key] = option.value

        return obj

    def to_vsphere_config(self):
        """
        Converts the current settings dict into an array of OptionValues, which
        can be used in vSphere config specs
        """
        config = []
        for k, v in self._settings.items():
            option = vim.option.OptionValue()
            option.key = k
            option.value = v
            config.append(option)
        return config

    def is_empty(self):
        return len(self._settings.keys()) == 0

    def difference(self, other):
        """
        Returns settings that are in self but are not in other, similar to set.difference()
        Returns
            AdvancedSettings
        """
        diff = self._settings.copy()
        for other_key, other_value in other._settings.items():
            if other_key not in self._settings:
                continue

            if self._settings[other_key] != other_value:
                continue

            del diff[other_key]
        return AdvancedSettings.from_py_dict(diff, self.cast_all_values_to_str)

    def _convert_py_primitive_to_vmodl_type(self, value):
        """
        Advanced setting options can allow "any type" according to vSphere, but
        in practice only strings and integers are used. In some cases (Cluster HA),
        using the wrong type can provide an error. Until someone mentions a use case
        that requires a different type, just use strings and integers
        """
        if not self.cast_all_values_to_str:
            if isinstance(value, bool):
                return VmomiSupport.vmodlTypes['bool'](value)

            elif isinstance(value, float):
                return VmomiSupport.vmodlTypes['float'](value)

            elif isinstance(value, int):
                return VmomiSupport.vmodlTypes['int'](value)

        return VmomiSupport.vmodlTypes['string'](value)
