#!/usr/bin/env python3

import json
import time
import sys
import argparse
from urllib.request import urlopen, urlretrieve

_start_time = None
_last_time = None
artifact_size = 0
def reporthook(count, block_size, total_size):
    global _start_time, _last_time, artifact_size
    cur_time = int(time.time())
    if count == 0:
        _start_time = cur_time
        _last_time = cur_time
        return

    if cur_time == _last_time:
        return

    _last_time = cur_time

    duration = cur_time - _start_time
    progress_size = int(count * block_size)
    speed = int(progress_size / (1024 * duration))
    if total_size < 0 and artifact_size > 0:
        total_size = artifact_size
    if total_size > 0:
        percent = int(count * block_size * 100 / total_size)
        time_left = (total_size - progress_size) / speed / 1024
        sys.stdout.write("\r...%d%%, %d(%d) MB, %d KB/s, %d seconds left..." %
                     (percent, progress_size / (1024 * 1024), total_size / (1024 * 1024), speed, time_left))
    else:
        sys.stdout.write("\r...%d MB, %d KB/s, ..." %
                     (progress_size / (1024 * 1024), speed))
    sys.stdout.flush()

def validate_url_or_abort(url):
    # Attempt to retrieve HTTP response code
    try:
        urlfile = urlopen(url)
        response_code = urlfile.getcode()
        urlfile.close()
    except IOError:
        response_code = None

    if not response_code:
        print("Did not receive a response from remote machine. Aborting...")
        sys.exit(1)
    else:
        # Check for a 4xx response code which indicates a nonexistent URL
        if response_code / 100 == 4:
            print("Image file not found on remote machine. Aborting...")
            sys.exit(1)

def get_download_url(buildid, artifact_name):
    """get download url"""

    artifact_url = "https://dev.azure.com/mssonic/build/_apis/build/builds/{}/artifacts?artifactName={}&api-version=5.0".format(buildid, artifact_name)

    resp = urlopen(artifact_url)

    j = json.loads(resp.read().decode('utf-8'))

    download_url = j['resource']['downloadUrl']
    artifact_size = int(j['resource']['properties']['artifactsize'])

    return (download_url, artifact_size)


def download_artifacts(url, content_type, platform, buildid):
    """find latest successful build id for a branch"""

    if content_type == 'image':
        if platform == 'kvm':
            filename = 'sonic-vs.img.gz'
        else:
            filename = "sonic-{}.bin".format(platform)

        url = url.replace('zip', 'file')
        url += "&subPath=%2Ftarget%2F{}".format(filename)
    else:
        filename = "{}.zip".format(platform)

    if url.startswith('http://') or url.startswith('https://'):
        print('Downloading {} from build {}...'.format(filename, buildid))
        validate_url_or_abort(url)
        try:
            urlretrieve(url, filename, reporthook)
        except Exception as e:
            print("Download error", e)
            sys.exit(1)

def find_latest_build_id(branch):
    """find latest successful build id for a branch"""

    builds_url = "https://dev.azure.com/mssonic/build/_apis/build/builds?definitions=1&branchName=refs/heads/{}&resultFilter=succeeded&statusFilter=completed&api-version=6.0".format(branch)

    resp = urlopen(builds_url)

    j = json.loads(resp.read().decode('utf-8'))

    latest_build_id = int(j['value'][0]['id'])

    return latest_build_id

def main():
    global artifact_size

    parser = argparse.ArgumentParser(description='Download artifacts from sonic azure devops.')
    parser.add_argument('--buildid', metavar='buildid', type=int, help='build id')
    parser.add_argument('--branch', metavar='branch', type=str, help='branch name')
    parser.add_argument('--platform', metavar='platform', type=str,
            choices=['broadcom', 'mellanox', 'kvm'],
            help='platform to download')
    parser.add_argument('--content', metavar='content', type=str,
            choices=['all', 'image'], default='image',
            help='download content type [all|image(default)]')
    args = parser.parse_args()

    if args.buildid is None:
        buildid = find_latest_build_id(args.branch)
    else:
        buildid = int(args.buildid)

    artifact_name = "sonic-buildimage.{}".format(args.platform)

    (dl_url, artifact_size) = get_download_url(buildid, artifact_name)

    download_artifacts(dl_url, args.content, args.platform, buildid)

if __name__ == '__main__':
    main()
