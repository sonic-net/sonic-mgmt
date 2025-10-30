#!/bin/sh

codeowners-cli --repo ../ --contributors_file contributors.yaml --folder_presets_file folder_presets.yaml > ../CODEOWNERS
