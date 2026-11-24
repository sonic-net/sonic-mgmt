"""Redis CLI prefix for an ordinary-user test scenario."""


def redis_reader_cli(*, use_tcp):
    return "sonic-db-cli" if use_tcp else "sonic-db-cli -s"
