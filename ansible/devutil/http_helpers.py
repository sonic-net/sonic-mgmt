## Helpers related to HTTP
import time

def wait_for_http(host_ip, http_port, timeout=10):
    """Waits for HTTP server to open. Tries until timeout is reached and returns whether localhost received HTTP response"""
    started = False
    tries = 0
    while not started and tries < timeout:
        if os.system("curl {}:{}".format(host_ip, http_port)) == 0:
            started = True
        tries += 1
        time.sleep(1)
    
    return started