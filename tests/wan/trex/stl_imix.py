import stl_path
from trex_stl_lib.api import *

import argparse
import sys

# IMIX test
# it maps the ports to sides
# then it load a predefind profile 'IMIX'
# and attach it to both sides and inject
# at a certain rate for some time
# finally it checks that all packets arrived


def imix_test(server, mult):
    # create client
    c = STLClient(server=server)

    try:

        # connect to server
        c.connect()

        # take all the ports
        c.reset(ports=[0, 1])

        dir_0 = [0]
        dir_1 = [1]

        # load IMIX profile
        profile_file = os.path.join(stl_path.STL_PROFILES_PATH, 'imix.py')
        profile = STLProfile.load_py(profile_file)
        streams = profile.get_streams()

        # add both streams to ports
        c.add_streams(streams, ports=dir_0)

        # clear the stats before injecting
        c.clear_stats()

        # choose rate and start traffic for 10 seconds
        duration = 5

        c.start(ports=(dir_0), mult=mult, duration=duration, total=True)

        # block until done
        c.wait_on_traffic(ports=(dir_0))

        # read the stats after the test
        stats = c.get_stats()

        # sum dir 0
        dir_0_opackets = sum([stats[i]["opackets"] for i in dir_0])
        dir_1_ipackets = sum([stats[i]["ipackets"] for i in dir_1])
        lost_0 = dir_0_opackets - dir_1_ipackets

        print("opackets:{0}".format(dir_0_opackets))
        print("ipackets:{0}".format(dir_1_ipackets))
        print("lost:{0}".format(lost_0))
    except STLErro:
        sys.exit(1)

    finally:
        c.disconnect()


parser = argparse.ArgumentParser(description="Example for TRex Stateless, sending IMIX traffic")
parser.add_argument('-s', '--server',
                    dest='server',
                    help='Remote trex address',
                    default='127.0.0.1',
                    type=str)
parser.add_argument('-m', '--mult',
                    dest='mult',
                    help='Multiplier of traffic, see Stateless help for more info',
                    default='0.01%',
                    type=str)
args = parser.parse_args()

# run the tests
imix_test(args.server, args.mult)
