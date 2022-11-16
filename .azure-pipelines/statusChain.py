import time

TestPlanStatus = {
    "INIT": 10,
    "LOCK_TESTBED": 20,
    "PREPARE_TESTBED": 30,
    "EXECUTING": 40,
    "KVMDUMP": 50,
    "FAILED": 60,
    "CANCELLED": 70,
    "FINISHED": 80
}


class AbstractStatus():
    def __init__(self, status):
        self.status = status
        self.success = True

    def get_success_status(self):
        return self.success

    def print_logs(self, test_plan_id, resp_data, start_time):
        status = resp_data.get("status", None)
        if(TestPlanStatus[status] == self.status):
            print("Test plan id: {}, status: {},  elapsed: {:.0f} seconds"
                  .format(test_plan_id, resp_data.get("status", None), time.time() - start_time))


class InitStatus(AbstractStatus):
    pass


class LockStatus(AbstractStatus):
    pass


class PrePareStatus(AbstractStatus):
    pass


class ExecutingStatus(AbstractStatus):
    def print_logs(self, test_plan_id, resp_data, start_time):
        print("Test plan id: {}, status: {}, progress: {}%, elapsed: {:.0f} seconds"
              .format(test_plan_id, resp_data.get("status", None),
                      resp_data.get("progress", 0) * 100, time.time() - start_time))


class KvmDumpStatus(AbstractStatus):
    pass


class FailedStatus(AbstractStatus):
    pass


class CancelledStatus(AbstractStatus):
    pass


class FinishStatus(AbstractStatus):
    pass
