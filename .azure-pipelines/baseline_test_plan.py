import argparse
import os

TEST_PLAN_SCRIPT = ".azure-pipelines\test_plan.py"
TEST_PLAN_ID_TXT = "new_test_plan_id.txt"

def get_test_plan_list_id(current_path):
    current_path = os.path.dirname(os.path.realpath(__file__))
    test_plan_id_path = os.path.join(current_path, TEST_PLAN_ID_TXT)
    test_plan_id_list = []
    with open(test_plan_id_path, "r") as file:
        for line in file:
            test_plan_id_list.append(line.strip())
    return test_plan_id_list


if __name__ == "__main__":
    current_path = os.path.dirname(os.path.realpath(__file__))
    test_plan_script_path = os.path.join(current_path, TEST_PLAN_SCRIPT)

    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Tool for managing test plan.")

    subparsers = parser.add_subparsers(
        title="action",
        help="Action to perform on test plan",
        dest="action"
    )

    parser_create = subparsers.add_parser("create", help="Create new test plan.")
    if parser_create:
        parser_create.add_argument(
            "--test-plan-num",
            type=int,
            dest="test_plan_num",
            nargs="?",
            const="",
            default="",
            required=False,
            help="Test plan num to be created."
        )
        parser_create.add_argument(
            "--parameters",
            type=str,
            dest="parameters",
            required=False,
            help="Parameters of test plan."
        )

        args = parser.parse_args()
        for test_plan_id in range(args.test_plan_num):
            os.system("python {} create -o new_test_plan_id_{}.txt {}"
                      .format(test_plan_script_path, test_plan_id, args.parameters))


    parser_poll = subparsers.add_parser("poll", help="Poll test plan status.")
    if parser_poll:
        parser_poll.add_argument(
            "--parameters",
            type=str,
            dest="parameters",
            required=False,
            help="Parameters of test plan."
        )

        args = parser.parse_args()
        test_plan_id_list = get_test_plan_list_id(current_path)
        for test_plan_id in test_plan_id_list:
            os.system("python {} poll -i {} {}".format(test_plan_script_path, test_plan_id, args.parameters))

    parser_cancel = subparsers.add_parser("cancel", help="Cancel running test plan.")
    if parser_cancel:
        parser_cancel.add_argument(
            "--parameters",
            type=str,
            dest="parameters",
            required=False,
            help="Parameters of test plan."
        )

        args = parser.parse_args()
        test_plan_id_list = get_test_plan_list_id(current_path)
        for test_plan_id in test_plan_id_list:
            os.system("python {} cancel -i {} {}".format(test_plan_script_path, test_plan_id, args.parameters))
