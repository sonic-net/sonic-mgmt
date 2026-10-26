import time
import re
from .base_console_conn import CONSOLE_SSH_DIGI_CONFIG, BaseConsoleConn, CONSOLE_SSH
try:
    from netmiko.ssh_exception import NetMikoAuthenticationException
except ImportError:
    from netmiko.exceptions import NetMikoAuthenticationException
from paramiko.ssh_exception import SSHException


# Bootloader / autoboot prompts seen on the serial console across SONiC platforms.
# Sending a Ctrl-C (or any interrupt key) while the console shows one of these traps
# the DUT in the bootloader and aborts autoboot, so SONiC never boots and the device
# becomes permanently unreachable -- e.g. Arista Aboot's "Press Control-C now to enter
# Aboot shell", plus GRUB, U-Boot and ONIE equivalents. The console must never write
# control characters while in this state.
#
# The tokens are deliberately specific to avoid false positives on ordinary SONiC
# shell output: the real Aboot states are the autoboot prompt ("Press Control-C ...")
# and the shell prompt ("Aboot#") -- a bare "Aboot" word is NOT used because image
# filenames like "sonic-aboot-broadcom.swi" would match it (the hyphens form word
# boundaries) and wrongly suppress the leftover-shell Ctrl-C recovery. The generic
# boot-in-progress verbs are line-anchored (re.M) and the "Loading" verb is scoped to
# kernel/ramdisk loads so shell strings like "reloading"/"Loading configuration" do
# not match.
BOOTLOADER_BANNER_RE = re.compile(
    r"Press\s+Control[-\s]?C\s+now|"              # Arista Aboot autoboot window ("...now to enter Aboot shell")
    r"Aboot#|"                                    # Arista Aboot shell prompt
    r"GNU\s+GRUB|grub\s*>|grub\s+rescue\s*>|"     # GRUB menu / shell
    r"Hit\s+any\s+key\s+to\s+stop\s+autoboot|"    # U-Boot autoboot window
    r"autoboot\s+in\b|stop\s+autoboot|"           # autoboot countdown ("autoboot in N"),
                                                  # "... stop autoboot". NOT a bare "autoboot"
                                                  # word: that false-positives on shell/log
                                                  # text (e.g. "fw_printenv | grep autoboot").
    r"ONIE:|"                                     # ONIE installer / rescue (anchored;
                                                  # bare \bONIE\b matches "ONIE Version")
    r"^\s*Booting\b|"                             # boot-in-progress (line-anchored)
    r"^\s*Loading\s+(?:Linux|initrd|initial\s+ramdisk|kernel|vmlinuz)",  # kernel/ramdisk load
    flags=re.I | re.M,
)


class ConsoleRebootStartedError(Exception):
    """Raised to abort console I/O once the DUT reboot has started.

    The reboot flow (tests/common/reboot.py) sets a cancel event right before it
    reboots the DUT. If a console worker is still preparing its session at that
    point, any further write to the serial line could land in the bootloader
    autoboot window and trap the DUT, so write_channel() raises this to unwind
    the (now useless) session preparation without sending another byte.
    """
    pass


class SSHConsoleConn(BaseConsoleConn):
    def __init__(self, **kwargs):
        # A threading.Event the reboot flow sets right before it reboots the DUT.
        # Popped here so it never reaches netmiko's BaseConnection. Once set,
        # every write to the DUT serial line is refused (see write_channel) so a
        # late login/wake-up CR cannot abort bootloader autoboot.
        self._cancel_event = kwargs.pop("cancel_event", None)
        if "console_username" not in kwargs \
                or "console_password" not in kwargs:
            raise ValueError("Either console_username or console_password is not set")

        # Console via SSH connection need two groups of user/passwd
        self.sonic_username = kwargs['sonic_username']
        self.sonic_password = kwargs['sonic_password']

        # Store console type for later use
        self.console_type = kwargs['console_type']

        if self.console_type == CONSOLE_SSH:
            # Login requires port to be provided
            kwargs['username'] = kwargs['console_username'] + r':' + str(kwargs['console_port'])
            self.menu_port = None
        elif self.console_type.endswith("config"):
            # Login to config menu only requires username
            kwargs['username'] = kwargs['console_username']
        else:
            # Login requires menu port
            kwargs['username'] = kwargs['console_username']
            self.menu_port = kwargs['console_port']
        kwargs['password'] = kwargs['console_password']
        kwargs['host'] = kwargs['console_host']
        kwargs['device_type'] = "_ssh"
        super(SSHConsoleConn, self).__init__(**kwargs)

    def write_channel(self, out):
        """Single chokepoint for every byte we send to the DUT serial line.

        All DUT-side writes -- login CRs, username/password, menu-port selection,
        the silent-console CR nudge in _recover_to_login_prompt(), and find_prompt()
        CRs -- go through here. If the reboot has already started, refuse the write
        and abort: reboot.py's console worker is run via pool.apply_async().get(
        timeout=10), and that timeout does NOT cancel the underlying ThreadPool
        task, so without this guard a late CR from a still-running worker could
        land in the bootloader autoboot window and trap the DUT.
        """
        if self._cancel_event is not None and self._cancel_event.is_set():
            raise ConsoleRebootStartedError(
                "Reboot started; aborting console write to keep bootloader autoboot intact")
        return super(SSHConsoleConn, self).write_channel(out)

    def _try_session_preparation(self, force_data=False):
        """Suppress netmiko's pre-session priming CR (bootloader-safe).

        netmiko's BaseConnection._open() calls _try_session_preparation() with
        force_data=True, which writes a bare RETURN to the channel BEFORE
        session_preparation() runs, to guarantee there is data to read. On a
        serial console whose DUT may be sitting in a bootloader "hit any key to
        stop autoboot" window at connect time, that unguarded CR counts as a
        keypress, aborts autoboot and traps the DUT -- the exact failure this
        class defends against everywhere else, but happening before any of our
        bootloader classification can run. session_preparation() already reads
        the initial banner passively via _read_initial_console() (which tolerates
        a silent channel), so the priming CR is unnecessary. Force it off so no
        byte reaches the DUT until the bootloader guards below have run.

        The inherited ``force_data`` argument (netmiko's _open() passes ``True``) is
        intentionally IGNORED, not removed: the override must keep the parameter to
        accept netmiko's call signature, but we never honour it. Do not "fix" this by
        threading the value through -- doing so re-introduces the priming CR.
        """
        return super(SSHConsoleConn, self)._try_session_preparation(force_data=False)

    def _read_initial_console(self, max_reads=6, delay_factor=1):
        """Passively read the initial console output WITHOUT writing anything.

        session_preparation() must inspect the first console output (a console
        server "port is in use" notice, or a bootloader "hit any key to stop
        autoboot" banner) BEFORE it has classified the console state. Netmiko's
        inherited _test_channel_read() is unsafe here: when its first read
        returns empty it writes RETURN (an "any key" press) to coax data out,
        and on a quiet bootloader autoboot window that CR aborts autoboot and
        traps the DUT in the bootloader. This helper mirrors that
        read-until-data behaviour but never writes a byte, so no key can reach
        the DUT before the bootloader guards below run. It follows the same
        passive "read first, classify, only then maybe nudge" idiom used by
        _recover_to_login_prompt() and _is_at_sonic_prompt().

        The wait is deliberately short (max_reads*0.5s). Because we suppress
        netmiko's priming CR (see _try_session_preparation), a genuinely SILENT
        console now returns nothing here; stopping early is safe because a silent
        console is by definition NOT in an active autoboot window (autoboot prints
        a continuous countdown that arrives within the first read or two) and the
        console-server "port is in use" notice is sent immediately on connect.
        Bounding the wait keeps session_preparation() well inside the reboot
        console-log collector's ~10s budget (reboot.py collect_console_log); the
        later guarded steps elicit the login prompt when needed.
        """
        delay_factor = max(self.select_delay_factor(delay_factor), 1)
        output = ""
        for _ in range(max_reads):
            output += self.read_channel()
            if output:
                break
            time.sleep(0.5 * delay_factor)
        return output

    def session_preparation(self):
        # Read the initial banner PASSIVELY -- never write to the channel before
        # the console state is classified below. The inherited netmiko
        # _test_channel_read() would write a RETURN on an empty read, which on a
        # quiet autoboot window aborts autoboot and traps the DUT (see
        # _read_initial_console).
        session_init_msg = self._read_initial_console()
        self.logger.debug(session_init_msg)
        # Reset the bootloader-deferred signal at the start of every preparation. This is
        # currently INTERNAL state only: it coordinates the early-returns within
        # session_preparation()/login_stage_2() and has no external reader today (reboot.py
        # just holds the connection open and later disconnects). It is set at any of several
        # checkpoints that can be the FIRST to observe a boot banner (initial read, menu-port
        # login, _recover_to_login_prompt, and login_stage_2's mid-wait / final-try) --
        # defense-in-depth so no single missed classification lets a key reach a
        # 'hit any key to stop autoboot' window. Kept as an instance flag so a future caller
        # (e.g. the reboot collector) could detect a deferred boot-stage login if needed.
        self._bootloader_deferred = False

        if re.search(
            r"(Port is in use. Closing connection...|Cannot connect: line \[\d{2}\] is busy)",
            session_init_msg,
            flags=re.M
        ):
            console_port = self.username.split(':')[-1]
            raise PortInUseException(f"Host closed connection, as console port '{console_port}' is currently occupied.")

        if self.console_type.endswith("config"):
            # We can skip stage 2 login for config menu connections
            self.session_preparation_finalise()
            return

        if (self.menu_port):
            # For devices logining via menu port, 2 additional login are needed
            # Since we have attempted all passwords in __init__ of base class until successful login
            # So self.username and self.password must be the correct ones
            self.login_stage_2(username=self.username,
                               password=self.password,
                               menu_port=self.menu_port,
                               pri_prompt_terminator=r".*login",
                               defer_on_bootloader=True)
            if getattr(self, "_bootloader_deferred", False):
                # login_stage_2() saw a bootloader/boot banner on the DUT serial line
                # after selecting the menu port and stopped before sending any DUT-side
                # CR. Defer interactive login so we do not abort a "hit any key to stop
                # autoboot" window; the caller can then passively monitor the boot.
                self.logger.warning(
                    "DUT is in a bootloader/boot stage (menu port); deferring "
                    "interactive login to avoid interrupting autoboot")
                return
        # The initial passive read itself may contain a one-shot bootloader/boot banner
        # (e.g. a single "Hit any key to stop autoboot" or ONIE line) that then goes
        # quiet. _recover_to_login_prompt() re-reads from scratch and, on a now-silent
        # line, nudges with a bare CR -- which aborts autoboot on U-Boot/ONIE. Classify
        # the first read here and defer immediately if it already shows a boot stage, so
        # no key is ever sent even when the banner appeared only in that first read.
        if BOOTLOADER_BANNER_RE.search(session_init_msg):
            self.logger.warning(
                "Initial console banner shows a bootloader/boot stage; deferring "
                "interactive login to avoid interrupting autoboot")
            self._bootloader_deferred = True
            return
        # Exit any leftover shell from a previous test so we start at a clean login prompt.
        # If the DUT is in a bootloader / boot stage, defer interactive login entirely:
        # login_stage_2() sends periodic CRs while waiting for the username prompt, and on
        # a "hit any key to stop autoboot" window (e.g. U-Boot) those CRs would abort
        # autoboot and trap the DUT. Return immediately without attempting login.
        if self._recover_to_login_prompt():
            self.logger.warning(
                "DUT is in a bootloader/boot stage; deferring interactive login to "
                "avoid interrupting autoboot")
            # Do NOT call session_preparation_finalise() here: it runs set_base_prompt()
            # -> find_prompt(), which writes RETURN(s) to the console to elicit a prompt.
            # During a bootloader "hit any key to stop autoboot" window those RETURNs would
            # abort autoboot and trap the DUT (and find_prompt() would raise since no prompt
            # exists yet). Return with zero writes so the caller can passively monitor boot.
            # Mirror the menu-port path: record the deferral so callers can detect the
            # non-interactive boot stage and avoid later writes that could abort autoboot.
            self._bootloader_deferred = True
            return
        # Attempt all sonic password. A wrong password must not prevent a
        # subsequent correct password in the list from succeeding, so we
        # re-synchronise the terminal back to a fresh "login:" prompt between
        # attempts (the failed attempt leaves a "Login incorrect" banner in the
        # buffer that would otherwise desync the next login).
        for i in range(0, len(self.sonic_password)):
            password = self.sonic_password[i]
            try:
                self.login_stage_2(username=self.sonic_username,
                                   password=password,
                                   defer_on_bootloader=True)
            except NetMikoAuthenticationException as e:
                if i == len(self.sonic_password) - 1:
                    raise e
                # Drain any leftover "Login incorrect" output and wait until the
                # getty presents a clean login prompt before trying the next
                # password in the list.
                self._resync_to_login_prompt()
            else:
                if getattr(self, "_bootloader_deferred", False):
                    # login_stage_2() saw a bootloader/boot banner on the DUT serial
                    # line while waiting for the login prompt and stopped before
                    # sending any wake-up CR. Defer interactive login (mirror the
                    # menu-port and _recover_to_login_prompt paths) so a "hit any key
                    # to stop autoboot" window missed by the earlier classification is
                    # never aborted, and do NOT finalise (set_base_prompt would write).
                    self.logger.warning(
                        "DUT is in a bootloader/boot stage (direct console); deferring "
                        "interactive login to avoid interrupting autoboot")
                    return
                break

        self.session_preparation_finalise()

    def session_preparation_finalise(self):
        """
        Helper function to handle final stages of session preparation.
        """
        # Digi config menu has a unique prompt terminator (----->)
        if self.console_type == CONSOLE_SSH_DIGI_CONFIG:
            self.set_base_prompt(">")
        else:
            self.set_base_prompt()

        # Clear the read buffer
        time.sleep(0.3 * self.global_delay_factor)
        self.clear_buffer()

    def _recover_to_login_prompt(self, max_attempts=4, delay_factor=1):
        """
        Ensure the console is at a fresh "login:" prompt before logging in.

        If a previous console session was left logged in (its cleanup did not
        run or could not log out), the serial line still has an authenticated
        shell and a new connection lands on the shell prompt instead of
        "login:". In that case the username sent below is interpreted as a
        shell command and the login never happens. Detect a leftover shell
        prompt and send "exit" to return to a clean login prompt so each
        console test is independent of the previous one's teardown.

        Control characters (Ctrl-C / "exit") are only ever sent once a leftover
        SONiC shell prompt has been positively identified. If the console is in
        a bootloader / boot stage (Arista Aboot, GRUB, U-Boot, ONIE) this method
        sends nothing and returns, because a Ctrl-C during the bootloader's
        autoboot window would trap the DUT in the bootloader and abort autoboot.

        Returns:
            bool: ``True`` if the console was found in a bootloader / boot stage
            (interactive login must be deferred so the caller does not send any
            keys -- even a bare CR aborts a "hit any key" autoboot window such as
            U-Boot's). ``False`` otherwise (login prompt, recovered shell, or an
            indeterminate state), in which case the normal login flow may proceed.
        """
        shell_prompt_patterns = (
            r'admin@.*:.*[\$#]',
            r'root@.*:.*#',
            r'.*@sonic.*[\$#]',
        )
        # Floor the delay factor so the probe waits long enough for the serial prompt to echo.
        delay_factor = max(self.select_delay_factor(delay_factor), 1)
        for _ in range(max_attempts):
            try:
                # Passively read the console FIRST -- do not send anything yet. If
                # the DUT is sitting in a bootloader "hit any key to stop autoboot"
                # window, ANY keypress (including a bare CR) aborts autoboot and
                # traps the DUT in the bootloader, so we must observe before nudging.
                output = ""
                for _ in range(4):
                    time.sleep(0.5 * delay_factor)
                    output += self.read_channel()
                # Only if the console stayed silent do we nudge it with a bare CR
                # (never Ctrl-C) to coax a login prompt to echo. This rests on the
                # assumption that an active autoboot window REPAINTS its countdown, so a
                # fully silent probe window is not one -- true for Aboot and the common
                # U-Boot countdown. The boundary of that guarantee is a rare U-Boot build
                # that prints "press any key" once and then waits silently; that case is
                # caught earlier by classifying session_init_msg in session_preparation(),
                # before this passive re-read could see only silence.
                if not output.strip():
                    self.write_channel(self.RETURN)
                    for _ in range(4):
                        time.sleep(0.5 * delay_factor)
                        output += self.read_channel()
            except Exception as e:
                self.logger.warning(f"Error probing console state: {e}")
                return False
            # Never send Ctrl-C / keys while the DUT is in a bootloader or boot
            # stage: on Arista Aboot the "Press Control-C now to enter Aboot shell"
            # window would trap the DUT at the Aboot# shell and abort autoboot so
            # SONiC never boots (the same applies to GRUB / U-Boot / ONIE). Signal
            # the bootloader state to the caller so it also defers interactive
            # login (login_stage_2 sends periodic CRs that would abort a "hit any
            # key to stop autoboot" window such as U-Boot's).
            if BOOTLOADER_BANNER_RE.search(output):
                self.logger.warning(
                    "Console is in a bootloader/boot stage; skipping login-prompt "
                    "recovery to avoid trapping autoboot")
                return True
            # Already at a login prompt -> nothing to recover.
            if re.search(r"login:\s*$", output, flags=re.I | re.M):
                return False
            # Logged-in shell left over from a previous session -> abort any pending
            # command with Ctrl-C, then log out to return to a clean login prompt.
            if any(re.search(p, output) for p in shell_prompt_patterns):
                self.logger.warning(
                    "Console is at a leftover shell prompt; sending Ctrl-C + 'exit' "
                    "to return to the login prompt")
                try:
                    self.write_channel("\x03")
                    time.sleep(0.5 * delay_factor)
                    self.write_channel("exit" + self.RETURN)
                    time.sleep(1 * delay_factor)
                except Exception as e:
                    self.logger.warning(f"Error sending exit during recovery: {e}")
                    return False
                continue
            # Unknown / transient state: try once more.
        # Best effort: clear whatever is pending so the login starts clean.
        self.clear_buffer()
        return False

    def _resync_to_login_prompt(self, max_loops=20, delay_factor=1):
        """
        Re-synchronise the console to a fresh "login:" prompt.

        After a failed password attempt the getty prints a "Login incorrect"
        banner followed by a new login prompt. Drain that stale output and wait
        for a clean login prompt so the next credential in the list starts from
        a known state (otherwise the leftover banner desyncs the next attempt).
        """
        # Floor the delay factor so the wait spans the ~3s pam_faildelay after a failed login.
        delay_factor = max(self.select_delay_factor(delay_factor), 1)
        # Drop any pending "Login incorrect" / banner output.
        self.clear_buffer()
        i = 1
        while i <= max_loops:
            try:
                self.write_channel(self.RETURN)
                time.sleep(0.5 * delay_factor)
                output = self.read_channel()
                # A fresh prompt ends with "login:" (with the colon); this does
                # not match the "Login incorrect" failure banner.
                if re.search(r"login:\s*$", output, flags=re.I | re.M):
                    self.clear_buffer()
                    return
            except EOFError:
                self.remote_conn.close()
                raise NetMikoAuthenticationException(
                    "Login failed: {}".format(self.host))
            i += 1
        # Best effort: leave the buffer clean for the next attempt.
        self.clear_buffer()

    def login_stage_2(self,
                      username,
                      password,
                      menu_port=None,
                      pri_prompt_terminator=r".*# ",
                      alt_prompt_terminator=r".*\$ ",
                      username_pattern=r"(?:user:|username|login:|user name)",
                      pwd_pattern=r"assword",
                      delay_factor=1,
                      max_loops=20,
                      defer_on_bootloader=False
                      ):
        """
        Perform a stage_2 login
        """
        delay_factor = self.select_delay_factor(delay_factor)
        # Floor the delay factor so the loop waits long enough for a slow/faildelayed password prompt.
        delay_factor = max(delay_factor, 1)
        time.sleep(1 * delay_factor)

        output = ""
        return_msg = ""
        i = 1
        menu_port_sent = False
        user_sent = False
        password_sent = False
        if defer_on_bootloader:
            self._bootloader_deferred = False
        # The following prompt is only for SONiC
        # Need to add more login failure prompt for other system
        login_failure_prompt = r".*incorrect"
        while i <= max_loops:
            try:
                if menu_port and not menu_port_sent:
                    self.write_and_poll("menu ports", "Selection:")
                    self.write_channel(str(self.menu_port) + self.RETURN)
                    menu_port_sent = True

                # Read the DUT serial line. In defer_on_bootloader mode, observe it
                # PASSIVELY over a few reads before the loop can send any wake-up CR:
                # a single read can land in an autoboot countdown gap and miss a
                # bootloader banner, and a premature CR counts as "hit any key to stop
                # autoboot" and would trap the DUT. This mirrors _recover_to_login_prompt()
                # (read first, classify, only then maybe nudge). Non-defer callers keep the
                # original single read, so ordinary login timing is unchanged, and the reads
                # feed the same `output` the username detection below uses so a real
                # login/username prompt is still handled normally.
                if defer_on_bootloader and not user_sent:
                    output = ""
                    for _ in range(4):
                        output += self.read_channel()
                        if (BOOTLOADER_BANNER_RE.search(return_msg + output)
                                or re.search(username_pattern, output, flags=re.I)):
                            break
                        time.sleep(0.5 * delay_factor)
                else:
                    output = self.read_channel()
                return_msg += output

                # Search for username pattern / send username
                if not user_sent and re.search(username_pattern, output, flags=re.I):
                    self.write_channel(username + self.RETURN)
                    time.sleep(1 * delay_factor)
                    output = self.read_channel()
                    return_msg += output
                    user_sent = True

                # Search for password pattern / send password
                # Use return_msg (accumulated) instead of output to handle cases where
                # 'Password:' prompt is split across multiple TCP reads (e.g. 'Pa' + 'ssword:')
                if user_sent and not password_sent and re.search(pwd_pattern, return_msg, flags=re.I):
                    self.write_channel(password + self.RETURN)
                    time.sleep(0.5 * delay_factor)
                    output = self.read_channel()
                    return_msg += output
                    password_sent = True
                    if re.search(
                            pri_prompt_terminator, output, flags=re.M
                    ) or re.search(alt_prompt_terminator, output, flags=re.M):
                        return return_msg

                # Check if proper data received
                if re.search(pri_prompt_terminator, output, flags=re.M) or re.search(
                        alt_prompt_terminator, output, flags=re.M
                ):
                    return return_msg

                # Check if login failed
                if re.search(login_failure_prompt, output, flags=re.M):
                    # Wait a short time or the next login will be refused
                    time.sleep(1 * delay_factor)
                    msg = "Login failed: {}".format(self.host)
                    raise NetMikoAuthenticationException(msg)

                # Only send blank CR to wake up terminal when still waiting for username prompt;
                # once username has been sent, stop sending CRs so no empty password arrives before 'Password:' prompt
                if not user_sent:
                    if defer_on_bootloader and BOOTLOADER_BANNER_RE.search(return_msg):
                        # A bootloader/boot banner is on the DUT serial line: do NOT send
                        # the wake-up CR -- it counts as "hit any key to stop autoboot"
                        # and would trap the DUT. Signal the caller to defer login.
                        self.logger.warning(
                            "Console is in a bootloader/boot stage; deferring login to "
                            "avoid aborting autoboot")
                        self._bootloader_deferred = True
                        return return_msg
                    self.write_channel(self.RETURN)
                time.sleep(0.5 * delay_factor)
                i += 1
            except EOFError:
                self.remote_conn.close()
                msg = "Login failed: {}".format(self.host)
                raise NetMikoAuthenticationException(msg)

        # Last try to see if we already logged in
        if defer_on_bootloader and BOOTLOADER_BANNER_RE.search(return_msg):
            self.logger.warning(
                "Console is in a bootloader/boot stage; deferring login to avoid "
                "aborting autoboot")
            self._bootloader_deferred = True
            return return_msg
        self.write_channel(self.RETURN)
        time.sleep(0.5 * delay_factor)
        output = self.read_channel()
        return_msg += output
        if re.search(pri_prompt_terminator, output, flags=re.M) or re.search(
                alt_prompt_terminator, output, flags=re.M
        ):
            return return_msg

        self.remote_conn.close()
        msg = "Login failed: {}".format(self.host)
        raise NetMikoAuthenticationException(msg)

    def _is_at_sonic_prompt(self):
        """
        Check if we're at a SONiC shell prompt by examining the last line in the buffer.

        Returns:
            bool: True if at SONiC prompt, False otherwise (including GRUB, ONIE, boot stages, etc.)
        """
        try:
            # Passively read the console FIRST -- never send a key before we know the
            # state. If the DUT is in a bootloader/boot stage (e.g. a reboot autoboot
            # window while cleanup() runs), a CR here counts as "hit any key to stop
            # autoboot" and would trap the DUT, so classify from passive output and bail.
            output = ""
            for i in range(4):
                if i:
                    time.sleep(0.5)
                output += self.read_channel()
            if BOOTLOADER_BANNER_RE.search(output):
                self.logger.warning(
                    "Console is in a bootloader/boot stage; not at a SONiC prompt")
                return False
            # Not a bootloader -> elicit the prompt (empty after login) with a CR.
            for _ in range(4):
                self.write_channel(self.RETURN)
                time.sleep(0.5)
                output += self.read_channel()
        except Exception as e:
            self.logger.warning(f"Error reading channel: {e}, assuming not at SONiC prompt")
            return False

        if not output:
            self.logger.warning("Console buffer is empty, cannot determine prompt state")
            return False

        # Get the last line (most recent output, likely the current prompt)
        # Split by common line endings and get the last non-empty line
        lines = output.replace('\r\n', '\n').replace('\r', '\n').split('\n')
        last_line = ''
        for line in reversed(lines):
            if line.strip():
                last_line = line
                break
        else:
            self.logger.debug("No non-empty lines in buffer")
            return False

        # Check for SONiC prompt patterns (admin@sonic:~$, root@sonic:~#, etc.)
        sonic_prompt_patterns = [
            r'admin@.*:.*[\$#]',
            r'root@.*:.*#',
            r'.*@sonic.*[\$#]'
        ]

        # Check if the last line matches a SONiC prompt
        for pattern in sonic_prompt_patterns:
            if re.search(pattern, last_line):
                self.logger.debug(f"Matched SONiC prompt pattern: {pattern}")
                return True

        self.logger.debug(f"Last line does not match SONiC prompt: {last_line}")
        return False

    def cleanup(self):
        """
        Cleanup console connection.
        Only send 'exit' if we're certain the DUT is at a SONiC prompt.
        This prevents issues during reboot when DUT might be in GRUB or other boot stages.
        """
        # A console whose session preparation was deferred (DUT still in the
        # bootloader/boot stage) has no SONiC prompt to probe. Probing would call
        # _is_at_sonic_prompt(), which sends up to four RETURNs when the one-shot
        # bootloader banner is no longer buffered -- those CRs would land in an
        # autoboot "hit any key" window and trap the DUT. Skip all interactive
        # probing and just close the transport below.
        if getattr(self, "_bootloader_deferred", False):
            self.logger.warning(
                "Session preparation was deferred (bootloader/boot stage); "
                "closing console transport without prompt probing")
        # Otherwise, if we are in SONiC and the session is ready, exit to logout.
        elif self._is_at_sonic_prompt():
            self.logger.warning("At SONiC prompt, sending exit to logout")
            try:
                self.send_command(command_string="exit", expect_string="login:")
            except Exception as e:
                self.logger.warning(f"Failed to send exit command during cleanup: {e}")

        # remote_conn must be closed, or the SSH session will be kept on Digi,
        # and any other login is prevented
        self.remote_conn.close()
        del self.remote_conn


class PortInUseException(SSHException):
    '''Exception to denote a console port is in use.'''
    pass
