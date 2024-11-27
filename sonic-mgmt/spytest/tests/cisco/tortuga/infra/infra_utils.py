from spytest import st

def is_simulation(node):
    cmd_output = st.config(node,"cat /proc/cpuinfo | grep '^model name.: VXR$'")
    try:
        if 'VXR' in str(cmd_output.encode('ascii','ignore')):
            return True
    except:
       pass
    return False

