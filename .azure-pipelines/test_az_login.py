import os

if __name__ == '__main__':
    # Success of "az account get-access-token" depends on "az login". However, the "az login" session may expire
    # after 24 hours. So we re-login every 12 hours to ensure success of "az account get-access-token".

    cmd = "az login --service-principal -u {} --tenant {} --allow-no-subscriptions --federated-token {}".format(
        os.environ.get("SONIC_AUTOMATION_SERVICE_PRINCIPAL"),
        os.environ.get("ELASTICTEST_MSAL_TENANT_ID"),
        os.environ.get("SYSTEM_ACCESS_TOKEN")
    )

    print(os.system(cmd))

    cmd = 'az account get-access-token --resource {}'.format(os.environ.get("ELASTICTEST_MSAL_CLIENT_ID"))

    print(os.system(cmd))
