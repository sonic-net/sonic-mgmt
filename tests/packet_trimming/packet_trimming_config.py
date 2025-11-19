class PacketTrimmingConfig:
    DSCP = 48

    @staticmethod
    def get_trim_size(duthost):
        if duthost.get_asic_name() == 'th5':
            return 206
        else:
            return 256

    @staticmethod
    def get_max_trim_size(duthost):
        if duthost.get_asic_name() == 'th5':
            # th5 only supports a trim size of 206
            return 206
        else:
            return 4084

    @staticmethod
    def get_trim_queue(duthost):
        if duthost.get_asic_name() == 'th5':
            return 4
        else:
            return 6

    @staticmethod
    def get_valid_trim_configs(duthost, asymmetric=False):
        configs = {
            'th5': {
                'symmetric': [
                    (206, 48, 4)
                ],
                'asymmetric': [
                    (206, 'from-tc', 4, 5)
                ]
            },
            'default': {
                'symmetric': [
                    (300, 32, 5),    # Valid values
                    (256, 0, 0),     # Min Boundary values
                    (4084, 63, 7)    # Max Boundary values
                ],
                'asymmetric': [
                    (300, 'from-tc', 3, 5),     # Valid values
                    (256, 'from-tc', 0, 0),     # Min Boundary values
                    (4084, 'from-tc', 6, 14)    # Max Boundary values
                ]
            }
        }

        asic_name = duthost.get_asic_name()
        key = 'asymmetric' if asymmetric else 'symmetric'
        if asic_name in configs.keys():
            return configs[asic_name][key]
        else:
            return configs['default'][key]

    @staticmethod
    def get_invalid_trim_configs(duthost, asymmetric=False):
        configs = {
            'default': {
                'symmetric': [
                    (1.1, 32, 5),    # Invalid size value
                    (256, -1, 5),    # Invalid dscp value
                    (256, 63, -3.0)  # Invalid queue value
                ],
                'asymmetric': [
                    (1.1, 'from-tc', 3, 5),     # Invalid size value
                    (256, 'test', 3, 5),        # Invalid dscp value
                    (256, 'from-tc', -3.0, 5),  # Invalid queue value
                    (300, 'from-tc', 3, 256)    # Invalid tc value
                ]
            }
        }

        asic_name = duthost.get_asic_name()
        key = 'asymmetric' if asymmetric else 'symmetric'
        if asic_name in configs.keys():
            return configs[asic_name][key]
        else:
            return configs['default'][key]

    @staticmethod
    def get_asym_tc(duthost):
        return PacketTrimmingConfig.get_trim_queue(duthost)
