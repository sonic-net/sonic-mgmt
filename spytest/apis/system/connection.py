from spytest.access.connection import DeviceConnectionTimeout
from spytest import st


class DryRunConnection(object):
    def __init__(self, **kwargs):
        for name, value in kwargs.items():
            setattr(self, name, value)

    def find_prompt(self):
        return "#"

    def send_command(self, command, **kwargs):
        return "#"

    def disconnect(self):
        pass


def connect_to_device(ip, username, password, protocol='ssh', port=22,
                      retry=0, alt_password=None, sudo=True, retry_wait=2):

    if st.is_dry_run():
        return DryRunConnection(username=username)

    if protocol == "telnet":
        type = 'sonic_terminal'
    else:
        type = 'sonic_ssh'

    blocking_timeout = 30
    device = {
        'access_model': type,
        'ip': ip,
        'port': port,
        'username': username,
        'password': password,
        'blocking_timeout': blocking_timeout,
    }

    connected = False
    net_connect = None
    count = 1
    while True:
        try:
            st.log("Trying %d.." % count)
            net_connect = st.do_ssh(ipaddress=ip, username=username, password=password, altpassword=alt_password,
                                    port=port, blocking_timeout=blocking_timeout, access_model=type)
            connected = True
            break
        except DeviceConnectionTimeout:
            st.log("Timed-out..")
            count += 1
            if count > retry:
                break
            if retry_wait > 0:
                st.wait(retry_wait)
        except Exception:
            st.log("Exception: Cannot connect..")
            if alt_password:
                st.log("Retrying with Alternate password..")
                count = 1
                device['password'] = alt_password
                try:
                    st.log("Trying %d.." % count)
                    net_connect = st.do_ssh(ipaddress=ip, username=username, password=password, altpassword=alt_password,
                                            port=port, blocking_timeout=blocking_timeout, access_model=type)
                    connected = True
                    break
                except DeviceConnectionTimeout:
                    st.log("Timed-out..")
                    count += 1
                    if count > retry:
                        break
                    if retry_wait > 0:
                        st.wait(retry_wait)
                except Exception:
                    st.log("Except2: Cannot connect..")
                    break
            break

    if net_connect and connected:
        st.log("Connected ...")
        prompt = net_connect.find_prompt()
        st.log("Detected prompt - {}".format(prompt))
        if sudo:
            command = "sudo su \n{}".format(password)
            net_connect.send_command(command, r"#|\?|$")

        # set cols to avoid echo on new line
        command = "stty cols 5000"
        net_connect.send_command(command, r"#|\?|$")

        return net_connect

    connstr = "/".join(["{}={}".format(k, v) for k, v in device.items()])
    st.log("Cannot connect {}".format(connstr))
    return None


def ssh_disconnect(ssh_obj):
    if ssh_obj:
        ssh_obj.disconnect()


def make_sudo(ssh_conn_obj, password):
    command = "sudo su \n{}".format(password)
    ssh_conn_obj.send_command(command, "#")


def execute_command(ssh_obj, command):
    if not ssh_obj:
        st.warn("Invalid connection handle")
        return None
    try:
        prompt = ssh_obj.find_prompt()
        result = ssh_obj.send_command(command, expect_string="{}|:|#".format(prompt))
        st.log(result)
        return result
    except Exception as e:
        st.warn("Exception : {}".format(e))
        return None
