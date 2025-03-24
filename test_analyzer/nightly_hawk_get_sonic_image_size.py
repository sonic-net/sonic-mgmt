#!/usr/bin/python

import logging
import sys
import subprocess
import time
import csv
from os import path


logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    # level=logging.DEBUG,
    format='%(asctime)s %(filename)s:%(name)s:%(lineno)d %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


results = {}

def exec_command(cmd, ignore_error=False, verbose=False, msg="executing command"):
    if verbose: logger.debug("*** cmd: %s ***" % cmd)
    p = subprocess.Popen(cmd, shell=True, executable='/bin/bash', stdout=subprocess.PIPE)
    outs, errs = p.communicate()
    msg = outs.decode('utf8')
    if outs and verbose: logger.debug('exec_cmd stdout = '+msg)
    if not ignore_error and errs: logger.error('exec_cmd stderr = '+errs)

    return (p.returncode, msg)


def get_memory_sizes():
    """Return total/available memory size in MB, -1, -1 means failed to get the sizes
    """
    _, out = exec_command(cmd="free -m", msg="checking memory total/free sizes")
    lines = out.split('\n')

    for line in lines:
        if line.startswith("Mem:"):
            fields = line.split()
            if len(fields) < 3:
                return -1, -1
            else:
                total_mem, avail_mem = int(fields[1]), int(fields[-1])
        elif line.startswith("Swap:"):
            fields = line.split()
            if len(fields) < 3:
                return -1, -1
            else:
                total_swap, avail_swap = int(fields[1]), int(fields[-1])

    total = total_mem + total_swap
    avail = avail_mem + avail_swap
    return total, avail




def setup_get_image_size(image_size_base_folder):
    """Setup the environment for getting image size
    """

    need_memory_size = 5120
    total, avail = get_memory_sizes()
    if avail < need_memory_size:
        logger.error("Memory free space ({} < {}) low or failed to obtain memory information".format(avail, need_memory_size))
        return -1

    exec_command(cmd="mkdir -p {}".format(image_size_base_folder), ignore_error=True)
    exec_command(cmd="sudo umount {}".format(image_size_base_folder), ignore_error=True)
    exec_command(
        cmd="sudo mount -t tmpfs -o size={}M tmpfs {}".format(need_memory_size, image_size_base_folder),
        msg="mounting tmpfs"
    )
    logger.debug("Mounted tmpfs at {}".format(image_size_base_folder))
    exec_command(cmd="df -h", ignore_error=True)
    return 0

def teardown_get_image_size(image_size_base_folder):
    """teardown the environment for getting image size
    """
    exec_command(cmd="sudo umount {}".format(image_size_base_folder), ignore_error=True)
    logger.debug("Mounted tmpfs at {}".format(image_size_base_folder))
    exec_command(cmd="df -h", ignore_error=True)
    return 0


def download_new_sonic_image(image_url, save_as):
    logger.debug("download_new_sonic_image")
    global results

    image_version = None

    if image_url:
        logger.debug("Before downloading new image, clean-up previous downloads first")
        exec_command(
            cmd="rm -f {}".format(save_as),
            msg="clean up previously downloaded image",
            ignore_error=True
        )
        logger.debug("Downloading new image using curl")
        exec_command(
            cmd="curl -Lo {} {}".format(save_as, image_url),
            msg="downloading new image"
        )
        logger.debug("Completed downloading image")


    if path.exists(save_as):
        logger.debug("Checking downloaded image version")
        rst, out = exec_command(cmd="sudo sonic_installer binary_version {}".format(save_as))
        if rst != 0:
            logger.error("Failed to get sonic image version")
            return
        logger.debug("Got sonic image version")
        image_version = out.rstrip('\n')
        results[image_version] = {"image_version": image_version, "image_url": image_url, "image_size": 0, "dockerfs": 0, "docker_folder": 0, "squashfs": 0}
        logger.info("Downloaded image version: {}".format(image_version))
        
    return image_version


def get_file_size(file_name):
    logger.debug("get_file_size")
    file_size = 0

    _, out = exec_command(cmd="sudo ls -al {}".format(file_name), msg="get file size")
    lines = out.split('\n')
    for line in lines:
        if file_name in line:
            fields = line.split()
            if len(fields) < 3:
                logger.error("Failed to get file size")
            else:
                file_size = int(fields[4])
                logger.debug("file size: {}".format(file_size))
                break

    return file_size


def get_sonic_image_file_size(image_version, save_as, image_folder, docker_name):
    logger.debug("get_sonic_image_file_size")
    global results

    if path.exists(save_as):
        logger.debug("Unzipping the image file")
        if path.exists(image_folder):
            logger.debug("Cleaning up previous image folder")
            exec_command(cmd="sudo rm -rf {}".format(image_folder), ignore_error=True)
        else:
            logger.debug("Image folder does not exist, creating it")
        exec_command(cmd="sudo mkdir -p {}".format(image_folder), ignore_error=True)
        exec_command(cmd="sudo unzip -oq {} -d {}".format(save_as, image_folder))
        logger.debug("Unzipped the image file")
        exec_command(cmd="sudo ls -al {}".format(image_folder))

        image_size = get_file_size(save_as)
        results[image_version]["image_size"] = image_size
        logger.info("image size: {}".format(image_size))

        dockerfs_file = image_folder + "/" + docker_name
        dockerfs_size = get_file_size(dockerfs_file)
        results[image_version]["dockerfs"] = dockerfs_size
        logger.info("dockerfs size: {}".format(dockerfs_size))

        squashfs_file = image_folder + "/fs.squashfs"
        squashfs_size = get_file_size(squashfs_file)
        results[image_version]["squashfs"] = squashfs_size
        logger.info("squashfs size: {}".format(squashfs_size))


def get_docker_file_size(image_version, image_folder, docker_name, docker_folder):
    logger.debug("get_docker_file_size")
    global results

    docker_file = image_folder + "/" + docker_name
    if path.exists(docker_file):
        logger.debug("Cleaning up previous docker folder")
        exec_command(cmd="sudo rm -rf {}".format(docker_folder), ignore_error=True)
    else:
        logger.debug("Docker folder does not exist, creating it")
    exec_command(cmd="sudo mkdir -p {}".format(docker_folder), ignore_error=True)

    if path.exists(docker_file):
        _, out = exec_command(cmd="sudo file -b --mime-type {}".format(docker_file), ignore_error=True)
        file_type = out.strip()
        logger.debug("File type: {}".format(file_type))
        if file_type == "application/zstd":
            logger.debug("Detected zstd compression, extracting with pzstd...")
            exec_command(cmd="sudo sh -c 'pzstd -d -q {} -c | tar x --numeric-owner -C {}'".format(docker_file, docker_folder))
        else:
            logger.debug("Using default extraction method (gzip assumed)...")
            exec_command(cmd="sudo tar xzf {} -C {}".format(docker_file, docker_folder))

        if path.exists(docker_folder):
            logger.debug("docker_dir: {}".format(docker_folder))

            _, out = exec_command(cmd="sudo du -sb {}".format(docker_folder), msg="get docker_dir")
            lines = out.split('\n')
            for line in lines:
                if docker_folder in line:
                    fields = line.split()
                    if len(fields) < 2:
                        return
                    else:
                        docker_dir_size = int(fields[0])
                        results[image_version]["docker_folder"] = docker_dir_size
                        logger.info("docker dir size: {}".format(docker_dir_size))
                        break


def write_results_to_csv(results_dict, csv_file_path):
    """Write the results dictionary to a CSV file
    
    Args:
        results_dict: Dictionary containing image analysis results
        csv_file_path: Path to save the CSV file
    """
    logger.debug(f"Writing results to CSV file: {csv_file_path}")
    
    # Define CSV headers including MB conversion columns
    headers = [
        'image_version', 'image_url', 
        'image_size', 'image_size_MB', 
        'dockerfs', 'dockerfs_MB', 
        'docker_folder', 'docker_folder_MB', 
        'squashfs', 'squashfs_MB'
    ]
    
    try:
        with open(csv_file_path, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers)
            writer.writeheader()
            
            # Write each image's data as a row with MB conversions
            for image_version, data in results_dict.items():
                # Create a copy of the data to avoid modifying the original
                row_data = data.copy()
                
                # Add MB conversion columns
                for size_field in ['image_size', 'dockerfs', 'docker_folder', 'squashfs']:
                    if size_field in row_data and isinstance(row_data[size_field], (int, float)) and row_data[size_field] > 0:
                        # Convert bytes to MB (divide by 1024*1024 and round to 2 decimal places)
                        mb_value = round(row_data[size_field] / (1024 * 1024), 2)
                        row_data[f"{size_field}_MB"] = mb_value
                    else:
                        row_data[f"{size_field}_MB"] = 0.0
                
                writer.writerow(row_data)
                
        logger.info(f"Results successfully written to {csv_file_path}")
    except Exception as e:
        logger.error(f"Failed to write results to CSV: {e}")

def main():
    # it's a local python script to get image size
    # input: 
    #   - image_url: it's a string input, including the image url, use "," to separate if multiple urls
    
    if len(sys.argv) < 2:
        logger.error("Usage: python nightly_hawk_get_sonic_image_size.py 'image_url1,image_url2'")
        sys.exit(1)
    image_urls = sys.argv[1]
    image_urls = image_urls.split(",")
    global results

    image_size_base_folder = "/tmp/tmpfs"
    docker_folder = image_size_base_folder + "/docker_folder"
    image_folder = image_size_base_folder + "/image_folder"
    download_image_name = "download_image"
    save_as = image_size_base_folder + "/" + download_image_name
    docker_name = "dockerfs.tar.gz"

    if setup_get_image_size(image_size_base_folder) != 0:
        logger.error("Failed to setup tmpfs")
        sys.exit(1)
    
    for image_url in image_urls:
        # download and get image file size
        image_version = download_new_sonic_image(image_url, save_as)
        if image_version is None:
            logger.error("Failed to download image")
            continue
        results[image_version] = {"image_version": image_version, "image_url": image_url, "image_size": 0, "dockerfs": 0, "docker_folder": 0, "squashfs": 0}
        # get image size
        get_sonic_image_file_size(image_version, save_as, image_folder, docker_name)
        # get image size
        get_docker_file_size(image_version, image_folder, docker_name, docker_folder)

    logger.info("Get image size done")
    logger.info("results: {}".format(results))
    
    # Write results to CSV file
    csv_file_path = "/tmp/sonic_image_sizes.csv"
    write_results_to_csv(results, csv_file_path)

    if teardown_get_image_size(image_size_base_folder) != 0:
        logger.error("Failed to setup tmpfs")
        sys.exit(1)

if __name__ == '__main__':
    main()
