import enum

class CompletenessLevel(enum.IntEnum):
    debug = 0 # Minimum execution
    basic = 1
    confident = 2
    thorough = 3 # Maximum execution
