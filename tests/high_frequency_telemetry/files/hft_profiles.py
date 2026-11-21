"""One run's HFT rows. Called only with the DUT transaction directory locked."""

import hashlib
import json
import re
import subprocess
import tempfile
import time


PROFILE = "HIGH_FREQUENCY_TELEMETRY_PROFILE"
GROUP = "HIGH_FREQUENCY_TELEMETRY_GROUP"
SESSION = "HIGH_FREQUENCY_TELEMETRY_SESSION_TABLE"

# A validated create must not replace whole CONFIG_DB tables if an operator
# writes after validation. Compare and write just these two hashes atomically.
# SONiC serializes leaf-list fields as comma-separated values with an '@' suffix.
MUTATE = """
local op, spec = ARGV[1], cjson.decode(ARGV[4])
local p, g = KEYS[1], KEYS[2]
local function write(k, fields)
    for f,v in pairs(fields) do redis.call('HSET', k, f, v) end
end
if op == 'create' then
    if #redis.call('KEYS', ARGV[2] .. '|*') + #redis.call('KEYS', ARGV[3] .. '|*') > 0 then return 0 end
    write(p,spec.profile); write(g,spec.group); return 1
end
local function matches(k, fields)
    if redis.call('EXISTS',k) == 0 then return true end
    local n = 0
    for f,v in pairs(fields) do
        n = n + 1
        local actual = redis.call('HGET',k,f)
        if f == 'stream_state' then
            local ok = false
            for _,s in ipairs(spec.states) do if s == actual then ok = true end end
            if not ok then return false end
        elseif actual ~= v then return false end
    end
    return redis.call('HLEN',k) == n
end
if not matches(p,spec.profile) or not matches(g,spec.group) then return 0 end
for _,k in ipairs(redis.call('KEYS',ARGV[3] .. '|' .. spec.name .. '|*')) do
    if k ~= g then return 0 end
end
if op == 'state' then
    if redis.call('EXISTS',p,g) ~= 2 then return 0 end
    redis.call('HSET',p,'stream_state',spec.next_state)
elseif op == 'quiesce' then
    if redis.call('EXISTS',p) == 1 then redis.call('HSET',p,'stream_state','disabled') end
elseif op == 'drop-group' then redis.call('DEL',g)
elseif op == 'drop-profile' and redis.call('EXISTS',g) == 0 then redis.call('DEL',p)
else return 0 end
return 1
"""


class ProfileConflict(RuntimeError):
    """Redis refused the comparison and did not modify the running configuration."""


class OwnedProfile:
    def __init__(self, work, command, save, lock_fd):
        self.work, self.command, self.save = work, command, save
        self.lock_fd = lock_fd
        self.record = work / "profile.json"

    def read(self):
        return json.loads(self.record.read_text()) if self.record.exists() else None

    def mutate(self, op, spec):
        name = spec["name"]
        args = ["redis-cli", "-n", "4", "--raw", "-x", "EVAL", MUTATE, "2", PROFILE + "|" + name,
                GROUP + "|" + name + "|" + spec["type"], op, PROFILE, GROUP]
        # The payload can contain every queue on a switch; send on stdin, not as an exec argument.
        # -x appends stdin as the last Redis command argument.
        value = subprocess.check_output(args, input=json.dumps(spec), text=True, pass_fds=(self.lock_fd,)).strip()
        if value == "0":
            raise ProfileConflict(f"HFT {op} refused for {name}: configuration does not match this run's journal")
        if value != "1":
            raise RuntimeError(f"Unexpected Redis response to HFT {op}: {value!r}")

    def create(self, case, group, objects, counters, poll_interval, state):
        if not re.fullmatch(r"[0-9a-f]{32}", case) or self.record.exists():
            raise RuntimeError("Invalid case ID or an HFT profile still awaits cleanup")
        if (group not in ("PORT", "QUEUE", "INGRESS_PRIORITY_GROUP", "BUFFER_POOL") or
                state not in ("enabled", "disabled")):
            raise ValueError("Invalid HFT group or stream state")
        if not all(isinstance(seq, list) and seq and all(isinstance(x, str) and x and ',' not in x for x in seq)
                   for seq in (objects, counters)):
            raise ValueError("Invalid HFT leaf-list")
        name = "hft_" + hashlib.sha256((self.work.name + case).encode()).hexdigest()[:32]
        profile = {"stream_state": state, "poll_interval": str(int(poll_interval))}
        row = {"object_names": objects, "object_counters": counters}
        patch = [{"op": "add", "path": "/" + PROFILE, "value": {name: profile}},
                 {"op": "add", "path": "/" + GROUP, "value": {name + "|" + group: row}}]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", dir=self.work) as tmp:
            json.dump(patch, tmp)
            tmp.flush()
            self.command("config", "apply-patch", "--dry-run", tmp.name)
        spec = {"name": name, "case": case, "type": group, "profile": profile, "states": [state],
                "group": {k + "@": ",".join(v) for k, v in row.items()}}
        self.save(self.record, spec)
        try:
            self.mutate("create", spec)
        except ProfileConflict:
            self.record.unlink()  # An existing row prevented the create; none of it is ours.
            raise
        return name

    def transition(self, spec, op, state):
        # The write-ahead record accepts either side after a crash. The live CAS
        # accepts only states that were ours *before* this particular mutation.
        old_states = spec["states"]
        intent = dict(spec, states=sorted(set(old_states) | {state}))
        self.save(self.record, intent)
        try:
            self.mutate(op, dict(spec, next_state=state))
        except ProfileConflict:
            self.save(self.record, spec)
            raise
        spec["states"] = [state]
        self.save(self.record, spec)

    def set_state(self, case, state):
        spec = self.read()
        if not spec or spec["case"] != case or state not in ("enabled", "disabled"):
            raise RuntimeError("Cannot change another HFT case's profile")
        self.transition(spec, "state", state)

    def wait_session(self, spec, *, removed):
        key = "|".join((SESSION, spec["name"], spec["type"]))
        deadline = time.monotonic() + 30
        while True:
            row = json.loads(self.command("redis-cli", "-n", "6", "--json", "HGETALL", key))
            if not row or (not removed and row.get("stream_status") == "disabled"):
                return
            if time.monotonic() >= deadline:
                raise RuntimeError(f"HFT session {key} did not {'disappear' if removed else 'stop'}")
            time.sleep(1)

    def remove(self, case=None):
        spec = self.read()
        if not spec:
            return
        if case is not None and case != spec["case"]:
            raise RuntimeError("Refusing to clean another HFT case's profile")
        self.transition(spec, "quiesce", "disabled")
        self.wait_session(spec, removed=False)
        self.mutate("drop-group", spec)
        self.wait_session(spec, removed=True)
        self.mutate("drop-profile", spec)
        self.record.unlink()
