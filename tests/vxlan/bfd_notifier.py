
'''
# Description: This script is used to force notify the BFD state change to Orchagent.
This script can be called as
>>python script.py
{'363:1d0:e:88d::64c:ed8': 'oid:0x45000000000ae7', '203:1d0:e:288::64c:e18': 'oid:0x45000000000adc'}
>>python script.py --set "oid:0x45000000000ae7, oid:0x45000000000adc" "Up"
>>python script.py --set "oid:0x45000000000ae7, oid:0x45000000000adc" "Down"
>>python script.py --set "oid:0x45000000000ae7, oid:0x45000000000adc" "Init"
>>python script.py --set "oid:0x45000000000ae7, oid:0x45000000000adc" "Admin_Down"

'''
import swsscommon.swsscommon as swsscommon
import argparse

def main():
    parser = argparse.ArgumentParser(description="BFD Notifier Script")
    parser.add_argument("--set", nargs=2, metavar=('KEYLIST', 'STATE'), help="Comma separated key list and state")
    args = parser.parse_args()

    notifier = BFDNotifier()
    if args.set:
        key_list_str, state = args.set
        key_list = key_list_str.split(',')
        key_list = [key.strip() for key in key_list]
        notifier.update_bfds_state(key_list, state)
    else:
        addr_list = []  # Define the address list as needed
        result = notifier.get_asic_db_bfd_session_id()
        print(result)

class BFDNotifier:
    def get_asic_db_bfd_session_id(self):
        asic_db = swsscommon.DBConnector("ASIC_DB", 0, True)
        tbl = swsscommon.Table(asic_db, "ASIC_STATE:SAI_OBJECT_TYPE_BFD_SESSION")
        entries = set(tbl.getKeys())
        result = {}
        for entry in entries:
            status, fvs = tbl.get(entry)
            fvs = dict(fvs)
            assert status, "Got an error when get a key"
            result[fvs["SAI_BFD_SESSION_ATTR_DST_IP_ADDRESS"]] = entry
        return result

    def update_bfds_state(self, bfd_ids, state):
        bfd_sai_state = {"Admin_Down":  "SAI_BFD_SESSION_STATE_ADMIN_DOWN",
                            "Down":        "SAI_BFD_SESSION_STATE_DOWN",
                            "Init":        "SAI_BFD_SESSION_STATE_INIT",
                            "Up":          "SAI_BFD_SESSION_STATE_UP"}

        asic_db = swsscommon.DBConnector("ASIC_DB", 0, True)
        ntf = swsscommon.NotificationProducer(asic_db, "NOTIFICATIONS")
        fvp = swsscommon.FieldValuePairs()
        for bfd_id in bfd_ids:
            ntf_data = "[{\"bfd_session_id\":\""+bfd_id+"\",\"session_state\":\""+bfd_sai_state[state]+"\"}]"
            ntf.send("bfd_session_state_change", ntf_data, fvp)

if __name__ == "__main__":
    main()
