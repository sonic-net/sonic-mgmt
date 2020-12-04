import subprocess
import re


def download(build_url, local_path):

    print("Build-URL: {}".format(build_url))
    print("Local-PATH: {}".format(local_path))
    if not build_url: return False

    retval = ""
    status = False
    curl_cmd = "curl --retry 15 -o {} {}".format(local_path, build_url)
    for count in range(3):
        try:
            print("Download CURL CMD: '{}'".format(curl_cmd))
            proc = subprocess.Popen(curl_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            out, err = proc.communicate()
            proc.wait()
            if proc.returncode != 0:
                retval = "Error: Failed to execute '{}' ('{}')\n".format(curl_cmd, err.strip())
            else:
                retval = retval + out.strip() + err.strip()
        except Exception:
            print("Error: Exception occurred while executing the command '{}'".format(curl_cmd))
            return None

        if retval.strip() != "":
            print(retval)
            if re.search(r"curl:\s+\(\d+\)", retval):
                errorline = [m for m in retval.split("\n") if re.search(r"curl:\s+\(\d+\)", m)]
                errorline = str("".join(errorline))
                msg = "Image download to host location failed using curl command. Error: '{}'"
                msg = msg.format(errorline)
                print(msg)
                if count < 2: continue

        retval = ""
        filetype_cmd = "file {}".format(local_path)
        try:
            print("File CMD: '{}'".format(filetype_cmd))
            proc = subprocess.Popen(filetype_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            out, err = proc.communicate()
            proc.wait()
            if proc.returncode != 0:
                retval = "Error: Failed to execute '{}' ('{}')\n".format(filetype_cmd, err.strip())
            else:
                retval = retval + out.strip() + err.strip()
        except Exception:
            pass

        if not re.search(r":\s+data", retval):
            print(retval)
            errorline = retval.split("\n")[0]
            msg = "Image downloaded to host location is not a proper image type. File type: '{}'"
            msg = msg.format(errorline)
            print(msg)
            if count < 2: continue
        else:
            status = True
            break

    return status

