import os

if __name__ == '__main__':
    # Success of "az account get-access-token" depends on "az login". However, the "az login" session may expire
    # after 24 hours. So we re-login every 12 hours to ensure success of "az account get-access-token".

    cmd = "az login --identity --username e41c8a84-4662-48b0-b8a6-3f52230bcc5e"

    print(os.system(cmd))

    cmd = 'az account get-access-token --resource {}'.format(os.environ.get("ELASTICTEST_MSAL_CLIENT_ID"))

    print(os.system(cmd))
