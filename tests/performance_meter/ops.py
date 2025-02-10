import asyncio


async def async_command(duthost, command):
    return duthost.command(command)


async def async_command_ignore_errors(duthost, command):
    try:
        return duthost.command(command, module_ignore_errors=True)
    except Exception:
        return


def get_op_by_name(op):
    return globals()[op]


# Defining an op.
# An op is seperated into 2 parts by yield.
#     first part setup, prepare for checking
#     checking for success criteria
#     second part cleanup, make sure nothing is leftover
# The op can be async or blocking, e.g., we might want reboot to block
# until it is successfully done before next step, or we want reboot to not
# block at all to calculate how much time it takes to reboot.
# Timing for checking will only start after the first part of operation
# is over. The op should make sure op is started correctly and ended
# correctly. If either part is unsuccessful, op should yeild False and
# log the error, otherwise yielding True is expected.
# Op is also expected to be async. If no async feature is needed, simply
# add async before def.


async def noop(duthost):
    yield True


async def bad_op(duthost):
    yield False


async def reboot_by_cmd(duthost):
    command = asyncio.create_task(async_command_ignore_errors(duthost, "reboot"))
    yield True
    await command
