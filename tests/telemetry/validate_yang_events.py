import yang as ly
import sys
import json
import argparse
import logging
from glob import glob

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("debug.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

YANG_DIR = "/usr/local/yang-models/"
NO_FILE_ERROR = "No file provided for validation"
INVALID_FILE_ERROR = "Could not load module from yang file"
INVALID_YANG_ERROR = "Invalid file, empty json file"


class YangValidator:
    def __init__(self, file, yangModule):
        self.file = file
        self.yangModule = yangModule
        self.ctx = ly.Context(YANG_DIR)

    def loadYangModels(self):
        try:
            yangFiles = glob(YANG_DIR + "/*.yang")
            for file in yangFiles:
                module = self.ctx.parse_module_path(file, ly.LYS_IN_YANG)
                if module is None:
                    logging.info("Could not load module from file {}".format(file))
                    raise Exception(INVALID_YANG_ERROR)
        except Exception as e:
            logging.info("Exception thrown: {}".format(e))
            raise e

    def validateJSON(self):
        self.loadYangModels()

        try:
            with open(self.file, 'r') as f:
                data = json.load(f)
        except Exception as e:
            logging.info("Exception thrown: {}".format(e))
            raise e

        if data is None:
            logging.info("INVALID FILE, empty json file.")
            raise Exception(INVALID_FILE_ERROR)

        for element in data:
            data_json = json.dumps(element, indent=2)
            data_json = "{\"" + self.yangModule + ":" + self.yangModule + "\":" + data_json + "}"

            try:
                self.ctx.parse_data_mem(data_json, ly.LYD_JSON,
                                        ly.LYD_OPT_CONFIG | ly.LYD_OPT_STRICT)
            except Exception as e:
                logging.info("Exception thrown: {}".format(e))
                raise e
        logging.info("Libyang validation for {} passed successfully".format(self.yangModule))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", nargs='?', const='', default='', help="File containing event json")
    parser.add_argument("-y", "--yang", nargs='?', const='', default='', help="YANG file name")
    args = parser.parse_args()
    if args.file == '' or args.yang == '':
        logging.info("No file or yang name provided, please provide valid file path using -f and yang file using -y")
        raise Exception(NO_FILE_ERROR)
    validator = YangValidator(args.file, args.yang)
    validator.validateJSON()


if __name__ == "__main__":
    main()
