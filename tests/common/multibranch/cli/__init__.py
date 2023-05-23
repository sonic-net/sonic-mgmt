from tests.common.multibranch.cli.auto_techsupport import AutoTechSupportCli


class SonicCli:

    def __init__(self, duthost):
        self.duthost = duthost
        self.release = self.duthost.sonichost.sonic_release

        self.auto_techsupport = AutoTechSupportCli(duthost=self.duthost, release=self.release)
