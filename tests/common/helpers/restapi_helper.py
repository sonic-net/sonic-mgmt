import time

RESTAPI_SERVER_START_WAIT_TIME = 15
RESTAPI_CONTAINER_NAME = 'restapi'

def generate_cert(duthost, localhost):
    # Create Root key
    local_command = "openssl genrsa -out restapiCA.key 2048"
    localhost.shell(local_command)

    local_command = "openssl req \
                        -x509 \
                        -new \
                        -nodes \
                        -key restapiCA.key \
                        -sha256 \
                        -days 1825 \
                        -subj '/CN=test.restapi.sonic' \
                        -out restapiCA.pem"
    localhost.shell(local_command)

    # Create server key
    local_command = "openssl genrsa -out restapiserver.key 2048"
    localhost.shell(local_command)

    # Create server CSR
    local_command = "openssl req \
                        -new \
                        -key restapiserver.key \
                        -subj '/CN=test.server.restapi.sonic' \
                        -out restapiserver.csr"
    localhost.shell(local_command)

    # Sign server certificate
    local_command = "openssl x509 \
                        -req \
                        -in restapiserver.csr \
                        -CA restapiCA.pem \
                        -CAkey restapiCA.key \
                        -CAcreateserial \
                        -out restapiserver.crt \
                        -days 825 \
                        -sha256"
    localhost.shell(local_command)

    # Copy CA certificate and server certificate over to the DUT
    duthost.copy(src='restapiCA.pem', dest='/etc/sonic/credentials/')
    duthost.copy(src='restapiserver.crt',
                 dest='/etc/sonic/credentials/testrestapiserver.crt')
    duthost.copy(src='restapiserver.key',
                 dest='/etc/sonic/credentials/testrestapiserver.key')
 
    # Delete all created certs
    local_command = "rm -f \
                        restapiCA.* \
                        restapiserver.* \
                        restapiclient.*"
    localhost.shell(local_command)

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

    # Restart RESTAPI server with the updated config
    dut_command = "sudo systemctl restart restapi"
    duthost.shell(dut_command)
    time.sleep(RESTAPI_SERVER_START_WAIT_TIME)
