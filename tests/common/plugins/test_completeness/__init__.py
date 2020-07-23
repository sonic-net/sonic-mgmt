import sys
import enum
import logging
import warnings

class CompletenessLevel(enum.IntEnum):
    debug = 0 # Minimum execution
    basic = 1
    confident = 2
    thorough = 3 # Maximum execution

def set_default(specified_level):
    if not specified_level: # Case 1
        logging.info("Completeness level not set during test execution. Setting to default level: {}".format(str(CompletenessLevel.basic)))
        specified_level = CompletenessLevel.basic # - every testcase should run BASIC by default
    else:
        specified_level = specified_level.lower()
        if specified_level not in CompletenessLevel._member_names_:
            specified_level = CompletenessLevel.basic
            warnings.warn("Unidentified completeness level specified. Specified: {}. Allowed: {}".format(str(CompletenessLevel(specified_level)), \
                str(CompletenessLevel._member_names_)))
            logging.info("Unidentified completeness level specified. Setting to default level: {}".format(CompletenessLevel.basic))
        else:
            specified_level = CompletenessLevel[specified_level]

    return specified_level

def normalize_levels(specified_level, defined_levels):
    logging.info("Setting test completeness level. Specified: {}. Defined: {}".format(str(CompletenessLevel(specified_level)), str(defined_levels)))

    if specified_level not in defined_levels:
        if specified_level > max(defined_levels): # Case 3.1
            completeness_level = max(defined_levels)
        elif specified_level < min(defined_levels): # Case 3.2
            completeness_level = min(defined_levels)
        else: # Case 3.3
            # Find the maximum defined level less than specified_level
            lesser_defined_level_dist = sys.maxsize
            for level in defined_levels:
                if level <= specified_level and lesser_defined_level_dist > (specified_level - level):
                    completeness_level = level
                    lesser_defined_level_dist = lesser_defined_level_dist - level
        logging.info("Specified level ({}) not found in defined levels. Setting level to {}".format(str(CompletenessLevel(specified_level)), str(completeness_level)))
    else: # Case 4
        completeness_level = specified_level
        logging.info("Setting the completeness level to {}".format(str(CompletenessLevel(completeness_level))))

    return completeness_level