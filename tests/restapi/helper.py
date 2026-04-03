import time

# The restapi service requires around 30 seconds to start
RESTAPI_SERVER_START_WAIT_TIME = 40


def apply_cert_config(duthost):
    # Set client certificate subject name in config DB
    dut_command = "redis-cli -n 4 hset \
                    'RESTAPI|certs' \
                    'client_crt_cname' \
                    'test.client.restapi.sonic'"
    duthost.shell(dut_command)

    # Set CA cert path in config DB
    dut_command = "redis-cli -n 4 hset \
                    'RESTAPI|certs' \
                    'ca_crt' \
                    '/etc/sonic/credentials/restapiCA.pem'"
    duthost.shell(dut_command)

    # Set server certificate path in config DB
    dut_command = "redis-cli -n 4 hset \
                    'RESTAPI|certs' \
                    'server_crt' \
                    '/etc/sonic/credentials/testrestapiserver.crt'"
    duthost.shell(dut_command)
    dut_command = "redis-cli -n 4 hset \
                    'RESTAPI|certs' \
                    'server_key' \
                    '/etc/sonic/credentials/testrestapiserver.key'"
    duthost.shell(dut_command)

    time.sleep(5)

    # Restart RESTAPI server with the updated config
    dut_command = "docker restart restapi"
    duthost.shell(dut_command)
    time.sleep(RESTAPI_SERVER_START_WAIT_TIME)


def set_trusted_client_cert_subject_name(duthost, new_subject_name):
    # Set trusted client certificate subject name in config DB
    dut_command = f"redis-cli -n 4 hset \
                    'RESTAPI|certs' \
                    'client_crt_cname' \
                    '{new_subject_name}'"
    duthost.shell(dut_command)

    time.sleep(5)

    # Restart RESTAPI server with the updated config
    dut_command = "docker restart restapi"
    duthost.shell(dut_command)
    time.sleep(RESTAPI_SERVER_START_WAIT_TIME)
