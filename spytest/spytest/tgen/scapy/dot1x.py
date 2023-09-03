import time
import textwrap

from emulation import Emulation


class Dot1x(Emulation):

    def __init__(self, pif):
        super(Dot1x, self).__init__(pif, "dot1x")

    def config_one(self, enable, client, index=0):
        intf = client.intf
        ns = "{}_{}".format(intf.name, index)
        if not enable:
            self.stop_one(ns)
            return True
        self.nslist.append(ns)

        logfile = self._file(ns, "log", True)
        pidfile = self._file(ns, "pid", True)
        cfgfile = self._file(ns, "cfg", True)

        cmds = textwrap.dedent("""
            ctrl_interface=/var/run/wpa_supplicant-{0}
            ctrl_interface_group=0
            eapol_version=2
            ap_scan=0
            network={{
                    key_mgmt=IEEE8021X
                    eap=TTLS MD5
                    identity="{1}"
                    anonymous_identity="{1}"
                    password="{2}"
                    phase1="auth=MD5"
                    phase2="auth=PAP password={2}"
                    eapol_flags=0
            }}
        """.format(ns, client.get("username"), client.get("password")))
        self.utils.fwrite(cmds, cfgfile)

        cmds = textwrap.dedent("""
            set -x
            wpa_supplicant -c {0} -B -P {1} -D wired -i {2} -f {3} -dddd
        """.format(cfgfile, pidfile, "veth1", logfile))

        sh_file = self.utils.fwrite(cmds)
        self.utils.nsexec(ns, "bash {}".format(sh_file))

        self.logger.info(self.utils.cat_file(cfgfile))
        time.sleep(5)
        self.logger.info(self.utils.cat_file(pidfile))
        self.pif.log_large_file(logfile)

        return True

    def control(self, mode, client):
        retval = self.config_one(False, client)
        if mode not in ["disable", "stop", "logoff"]:
            retval = self.config_one(True, client)
        return retval
