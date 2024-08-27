import os

import argparse
import re
import sys

from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient


def sanitize_filename(filename):
    # Define the set of disallowed characters
    disallowed_chars = r'[<>:"\\|?*]'

    # Replace disallowed characters with an underscore
    sanitized = re.sub(disallowed_chars, '_', filename)

    # Trim spaces and periods from the end of the filename
    sanitized = sanitized.rstrip(' .')

    return sanitized


def download_blobs(container, testplan_id, local_directory):
    ACCOUNT_URL = os.environ.get("ELASTICTEST_STORAGE_ACCOUNT_URL", None)

    if not ACCOUNT_URL:
        print("ACCOUNT_URL required!")
        sys.exit(1)

    # Create BlobServiceClient
    blob_service_client = BlobServiceClient(account_url=ACCOUNT_URL, credential=DefaultAzureCredential())

    # Init container client with given container name
    container_client = blob_service_client.get_container_client(container)

    # List blobs with the specified testplan_id
    blob_list = container_client.list_blobs(name_starts_with=testplan_id)

    # Create a local directory to store downloaded files
    os.makedirs(local_directory, exist_ok=True)

    # Download each blob
    for blob in blob_list:
        # Define the local file path
        file_name = sanitize_filename(blob.name)
        local_file_path = os.path.join(local_directory, file_name)

        # Create directories if needed
        os.makedirs(os.path.dirname(local_file_path), exist_ok=True)

        # Download the blob
        with open(local_file_path, 'wb') as file:
            blob_client = container_client.get_blob_client(blob.name)
            download_stream = blob_client.download_blob()
            file.write(download_stream.readall())

        print(f'Downloaded {blob.name} to {local_file_path}', flush=True)


def main():
    # Set up argument parsing
    parser = argparse.ArgumentParser(description='Download blobs from Azure Blob Storage.')
    parser.add_argument('--container', required=True, help='The name of the container to download from.')
    parser.add_argument('--testplan-id', required=True, help='The test plan id (directory) of the blobs to download.')
    parser.add_argument('--local-directory', default='downloaded_directory',
                        help='Local directory to save downloaded files.')

    args = parser.parse_args()

    # Call the download function
    download_blobs(args.container, args.testplan_id, args.local_directory)


if __name__ == '__main__':
    main()
