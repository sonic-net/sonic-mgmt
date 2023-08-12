import sys
import logging
import warnings
from signal import signal, SIGINT

import rpyc
from rpyc.utils.server import ThreadedServer
from server import ScapyServer

warnings.filterwarnings("ignore", "BaseException.message")

logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

data = {}


class ScapyService(rpyc.Service, ScapyServer):
    def on_connect(self, conn):
        print("connected")
        conn._config.update(dict(
            allow_all_attrs=True,
            allow_public_attrs=True,
            allow_pickle=True,
            allow_getattr=True,
            allow_setattr=True,
            allow_delattr=True,
            import_custom_exceptions=False,
            propagate_SystemExit_locally=True,
            propagate_KeyboardInterrupt_locally=True,
            instantiate_custom_exceptions=True,
            instantiate_oldstyle_exceptions=True,
        ))

    def on_disconnect(self, conn):
        print("disconnected")


def main():
    data["scapyServiceObj"] = ScapyService()

    def handler(signal_received, frame):
        # Handle any cleanup here
        scapyServiceObj = data.pop("scapyServiceObj", None)
        if scapyServiceObj:
            del data["scapyServiceObj"]
        print('SIGINT or CTRL-C detected. Exiting gracefully')
        sys.exit(0)

    # install packages needed
    # os.system("apt-get install -y iputils-arping")
    # os.system("pip install pybrctl")
    # os.system("pip install pyroute2")

    signal(SIGINT, handler)
    protocol_config = {"allow_pickle": True, "sync_request_timeout": 300, "allow_public_attrs": True, "allow_all_attrs": True, "instantiate_oldstyle_exceptions": True}
    t = ThreadedServer(data["scapyServiceObj"], port=8009, logger=logger, protocol_config=protocol_config, backlog=1)
    t.start()


if __name__ == "__main__":
    main()
