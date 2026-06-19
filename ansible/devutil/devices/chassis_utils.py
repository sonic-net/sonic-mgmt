import enum


class ChassisCardType(str, enum.Enum):
    # Sample: lab-1111-sup-1
    SUPERVISOR_CARD = "-sup-"
    # Sample: lab-1111-lc1-1
    LINE_CARD = "-lc"


def is_chassis(sonichosts):
    supervisor_card_exists, line_card_exists = False, False
    for hostname in sonichosts.hostnames:
        if ChassisCardType.SUPERVISOR_CARD.value in hostname:
            supervisor_card_exists = True
        if ChassisCardType.LINE_CARD.value in hostname:
            line_card_exists = True
    return supervisor_card_exists and line_card_exists


def get_chassis_hostnames(sonichosts, chassis_card_type: ChassisCardType):
    res = []
    for hostname in sonichosts.hostnames:
        if chassis_card_type.value in hostname:
            res.append(hostname)
    return res
