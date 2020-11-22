from spytest.access.connection import DeviceConnection, DeviceConnectionTimeout
from spytest import st

def connect_to_device(ip, username, password, protocol='ssh', port=22,retry=0, alt_password=None, sudo=True):

    if st.is_dry_run():
        return None

    if protocol == "telnet":
        type = 'sonic_terminal'
    else:
        type = 'sonic_ssh'

    device = {
        'access_model': type,
        'ip': ip,
        'port': port,
        'username': username,
        'password': password,
        'blocking_timeout': 30,
    }

    connected = False
    net_connect = None
    count = 1
    while True:
        try:
            st.log("Trying %d.." % count)
            net_connect = DeviceConnection(**device)
            connected = True
            break
        except DeviceConnectionTimeout:
            st.log("Timed-out..")
            count += 1
            if count > retry:
                break
        except Exception:
            st.log("Exception: Cannot connect..")
            if alt_password:
                st.log("Retrying with Alternate password..")
                count = 1
                device['password'] = alt_password
                try:
                    st.log("Trying %d.." % count)
                    net_connect = DeviceConnection(**device)
                    connected = True
                    break
                except DeviceConnectionTimeout:
                    st.log("Timed-out..")
                    count += 1
                    if count > retry:
                        break
                except Exception:
                    st.log("Except2: Cannot connect..")
                    break
            break

    if connected:
        st.log("Connected ...")
        prompt = net_connect.find_prompt()
        st.log("Detected prompt - {}".format(prompt))
        if sudo:
            command = "sudo su \n{}".format(password)
            net_connect.send_command(command, r"#|\?|$")
        return net_connect

    st.log("Cannot connect..")
    return None


def ssh_disconnect(ssh_obj):
    if ssh_obj:
        ssh_obj.disconnect()


def make_sudo(ssh_conn_obj, password):
    command = "sudo su \n{}".format(password)
    ssh_conn_obj.send_command(command, "#")


def execute_command(ssh_obj, command):
    try:
        prompt = ssh_obj.find_prompt()
        result = ssh_obj.send_command(command, expect_string="{}|#".format(prompt))
        st.log(result)
        return result
    except Exception as e:
        st.log("Exception : {}".format(e))
        return None
