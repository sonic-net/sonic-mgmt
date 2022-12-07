import yang as ly
import sys
import json
import argparse
import logging
from glob import glob

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers = [
        logging.FileHandler("debug.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

YANG_DIR = "/usr/local/yang-models/"
NO_FILE_ERROR = -1
INVALID_FILE_ERROR = -2
FAILED_VALIDATION_ERROR = -3
INVALID_YANG_ERROR = -4
YANG_LOAD_SUCCESS = 0
YANG_VALIDATION_SUCCESS = 0

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
        except Exception as e:
            logging.info("Exception thrown: {}".format(e))
            return INVALID_YANG_ERROR
        return YANG_LOAD_SUCCESS

    def validateJSON(self):
        if(self.loadYangModels() < 0):
            return INVALID_YANG_ERROR

        try:
            with open(self.file, 'r') as f:
                data = json.load(f)
        except Exception as e:
            logging.info("Exception thrown: {}".format(e))
            return INVALID_FILE_ERROR

        if data is None:
            logging.info("Invalid file, empty json file.")
            return INVALID_FILE_ERROR

        for element in data:
            data_json = json.dumps(element, indent=2)
            data_json = "{\"" + self.yangModule + ":" + self.yangModule + "\":" + data_json + "}"

            try:
                node = self.ctx.parse_data_mem(data_json, ly.LYD_JSON, \
                    ly.LYD_OPT_CONFIG | ly.LYD_OPT_STRICT)
            except Exception as e:
                logging.info("Exception thrown: {}".format(e))
                return FAILED_VALIDATION_ERROR
        
        logging.info("Libyang validation for {} passed successfully".format(self.yangModule))
        return YANG_VALIDATION_SUCCESS

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", nargs='?', const='', default='', help="File containing event json for validation")
    parser.add_argument("-y", "--yang", nargs='?', const='', default='', help="YANG file name")
    args = parser.parse_args()
    if args.file == '' or args.yang == '':
        logging.info("No file or yang name provided, please provide valid file path using -f and yang file using -y")
        return NO_FILE_ERROR
    validator = YangValidator(args.file, args.yang)
    return validator.validateJSON()

if __name__ == "__main__":
    main()
