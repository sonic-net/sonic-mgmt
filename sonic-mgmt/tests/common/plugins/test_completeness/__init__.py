import sys
import enum
import logging
import warnings

class CompletenessLevel(enum.IntEnum):
    debug = 0 # Minimum execution
    basic = 1
    confident = 2
    thorough = 3 # Maximum execution
    diagnose = 100 # diagnose is an unordered level. INT value 100 is assigned for simplicity reasons

    @classmethod
    def get_normalized_level(cls, request):
        """Get the normalized completeness level for a given test instance.

        For example, if a testcase supports "CompletenessLevel.basic, CompletenessLevel.thorough", and the specified level
        during test execution is "confident", then this method will normalize the level to "basic".

         Returns:
             CompletenessLevel as a string
        """
        all_supported_levels = [mark.args for mark in request.node.iter_markers(name="supported_completeness_level")]
        logging.info("All supported completeness levels of the test: {}".format(str(all_supported_levels)))
        normalized_level = all_supported_levels[0][0]
        normalized_level_name = CompletenessLevel.get_level_name(normalized_level)
        logging.info("Normalized completeness level set to: {}".format(normalized_level_name))
        return normalized_level_name

    @classmethod
    def get_level_name(cls, level):
        """Converts a type CompletenessLevel to type str.

        For example, if input is CompletenessLevel.basic, this method will return "basic."

        Arguments:
            level - An enum value of type CompletenessLevel

        Returns:
            CompletenessLevel as a string
        """
        if not isinstance(level, CompletenessLevel):
            logging.error("Invalid completeness type. Expected: {}. Format {}".format(str(CompletenessLevel), type(level))) 
        level_name = level.name.lower()
        return level_name

def set_default(specified_level):
    if not specified_level: # Case 1
        logging.info("Completeness level not set during test execution. Setting to default level: {}".format(str(CompletenessLevel.basic)))
        specified_level = CompletenessLevel.basic # - every testcase should run BASIC by default
    else:
        specified_level = specified_level.lower()
        if specified_level not in CompletenessLevel._member_names_:
            specified_level = CompletenessLevel.basic
            warnings.warn("Unidentified completeness level specified. Specified: {}. Allowed: {}"\
                .format(str(CompletenessLevel(specified_level)), str(CompletenessLevel._member_names_)))
            logging.info("Unidentified completeness level specified. Setting to default level: {}".format(CompletenessLevel.basic))
        else:
            specified_level = CompletenessLevel[specified_level]

    return specified_level

def normalize_levels(specified_level, defined_levels):
    logging.info("Setting test completeness level. Specified: {}. Defined: {}".\
        format(str(CompletenessLevel(specified_level)), str(defined_levels)))

    if specified_level not in defined_levels:
        # if specified_level is diagnose and the testcase does not support it, default level is basic.
        if specified_level == CompletenessLevel.diagnose:
            specified_level = CompletenessLevel.basic

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
        logging.info("Specified level ({}) not found in defined levels. Setting level to {}".\
            format(str(CompletenessLevel(specified_level)), str(completeness_level)))
    else: # Case 4
        completeness_level = specified_level
        logging.info("Setting the completeness level to {}".format(str(CompletenessLevel(completeness_level))))

    return completeness_level
