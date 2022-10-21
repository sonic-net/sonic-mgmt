import argparse
from swsscommon import swsscommon
import time


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Change APPL DB")
    parser.add_argument("-t", help="Table name in APPL DB", required=True)
    parser.add_argument("-k", help="Key in APPL DB", required=True)
    parser.add_argument("-p", help="Pairs in APPL DB", action="append", nargs=2)
    opts = parser.parse_args()

    appl_db = swsscommon.DBConnector(swsscommon.APPL_DB, "/var/run/redis/redis.sock", 0)
    tbl = swsscommon.ProducerStateTable(appl_db, opts.t)
    fvs = swsscommon.FieldValuePairs(opts.p)
    tbl.set(opts.k, fvs)
    time.sleep(1)
