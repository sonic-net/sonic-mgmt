class ansible_host():
    
    def __init__(self, ansible_adhoc, hostname, is_local = False):
        if is_local:
            self.host = ansible_adhoc(inventory='localhost', connection='local')[hostname]
        else:
            self.host = ansible_adhoc(become=True)[hostname]
        self.hostname = hostname

    def __getattr__(self, item):
        self.module_name = item
        self.module = getattr(self.host, item)
 
        return self._run

    def _run(self, *module_args, **complex_args):
   
        res = self.module(*module_args, **complex_args)[self.hostname]
        if res.is_failed:
            raise Exception("run module {} failed, errmsg {}".format(self.module_name, res))

        return res
