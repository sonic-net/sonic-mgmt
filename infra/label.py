import os
import json
from pathlib import Path

def get_folders_with_labels(directory):
    # Ensure the directory exists
    if not os.path.exists(directory):
        raise FileNotFoundError(f"The directory '{directory}' does not exist.")

    # List all folders in the directory
    folders = [name for name in os.listdir(directory) if os.path.isdir(os.path.join(directory, name))]
    json_file = "output.json"

    # Create a dictionary with folder names and labels
    folder_labels = {folder: f"label_for_{folder}" for folder in folders}
    '''
    path = Path(directory)
    base_level = len(path.parts)
    for subdir in path.rglob('*'):
        current_level = len(subdir.parts)
        if current_level <= base_level + 1 and subdir.is_dir():
            print(subdir)
    '''
    for folder in folders:
        folder_dict = dict()
        #folder_dict['NAME'] = f'cisco/{folder}'
        folder_dict['NAME'] = folder
        if folder in ["platform_tests"]:
            folder_dict['TEAM'] = "SONIC-PLAT-INFRA"
            folder_dict['SCRUM_LEAD'] = "Shivu Vibhuti"
        elif folder in ['qos', 'pfc', 'snappi', 'ixia', 'pfc_asym', 'pfc_wd']:
            folder_dict['SCRUM_LEAD'] = "Alpesh Patel"
            folder_dict['TEAM'] = "SONIC-PFC"
        else:
            folder_dict['TEAM'] = "SONIC-MSFT-T2-FWD-FEAT"
            folder_dict['SCRUM_LEAD'] = "James An"

        folder_dict['202305_LABEL'] = "202305"
        folder_dict['202311_LABEL'] = "202311"
        folder_dict['MASTER_LABEL'] = "MASTER"
        folder_dict['T0_LABEL'] = "T0"
        folder_dict['T1_LABEL'] = "T1"
        folder_dict['T2_LABEL'] = "T2-PASS%"
        folder_dict['EXTRA_LABEL'] = ["CICD"]
        #folder_dict['CURRENT_QUARTER'] = [""]
        #folder_dict['CURRENT_SPRINT']

        write_to_json(folder_dict,json_file)

    return folder_dict

def write_to_json(data, json_file):
    with open(json_file, 'a') as f:
        json.dump(data, f, indent=4)
        f.write(",\n")

if __name__ == "__main__":
    # Define the directory and JSON file name
    directory = "/Users/pevenkat/whitebox/sonic-test/sonic-mgmt/tests"
    json_file = "output.json"

    # Get folders and labels
    try:
        folder_labels = get_folders_with_labels(directory)

        # Write the dictionary to a JSON file
        #write_to_json(folder_labels, json_file)

        print(f"JSON file '{json_file}' created successfully with folder labels.")
    except Exception as e:
        print(f"An error occurred: {e}")
