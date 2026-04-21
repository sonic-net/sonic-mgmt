from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


secret_fields = [
    "kerberos_keytab", "ldap_password", "password", "private_key", "scep_password", "enckey",
    "keytab", "server_keytab", "admin_password", "preshared_key", "forticlient_reg_key",
    "aaa_shared_secret", "ha_shared_secret", "login_password", "modem_passwd", "ppp_password",
    "ssh_host_key", "mmsc_password", "firewall_ssh_host_key", "firewall_ssh_local_key",
    "hostkey_dsa1024", "hostkey_ecdsa256", "hostkey_ecdsa384", "hostkey_ecdsa521", "hostkey_ed25519",
    "hostkey_rsa2048", "uploadpass", "server_key", "auth_keychain", "auth_keychain_l1", "auth_keychain_l2",
    "auth_password_l1", "auth_password_l2", "authentication_key", "key_string", "keychain", "md5_key",
    "md5_keychain", "md5_keys", "auth_key", "enc_key", "ipsec_keys", "key_rollover_interval", "privatekey",
    "alicloud_access_key_secret", "access_token", "fixed_key", "group_password", "ddns_key", "ddns_password",
    "proxy_password", "auth_password", "key_inbound", "key_outbound", "pptp_password", "passwd", "key",
    "access_key", "api_key", "client_secret", "key_passwd", "secret_key", "secret_token", "vcenter_password",
    "password2", "password3", "password4", "password5", "user_krb_keytab", "account_key_filter",
    "fortipresence_secret", "login_passwd", "sam_cwp_password", "sam_password", "wan_port_auth_password",
    "captive_portal_macauth_radius_secret", "captive_portal_radius_secret", "ft_r0_key_lifetime",
    "gtk_rekey_intv", "keyindex", "mpsk_key", "passphrase", "ptk_rekey_intv", "sae_password", "inter_controller_key",
    "passwd_value", "keyword_match", "sso_password", "logon_password", "keylifeseconds", "keylifekbs",
    "psksecret", "keylife", "ppk_secret", "psksecret_remote", "authpasswd", "group_authentication_secret",
    "vpn_ipsec_manualkey_interface", "authkey", "vpn_ipsec_manualkey", "scep_password", "videofilter_youtube_key",
    "parent_key", "switch_dhcp_opt43_key", "fortitoken", "password_expire", "aws_api_key", "azure_api_key",
    "ddns_keyname", "eap_password", "n_mhae_key", "passwd1", "passwd2", "passwd3", "http_password", "password_attr",
    "passwd_policy", "passwd_time", "rsso_secret", "secondary_secret", "secret", "sso_attribute_key", "secondary_key",
    "tertiary_key", "sae_private_key", "tertiary_secret", "search_key", "est_http_password", "est_srp_password",
    "fortitoken_cloud_sync_interval", "mfa_password", "default_user_password_policy", "polestar_server_token",
    "ssh_hostkey", "ssh_hostkey_password", "keyword", "sam_private_key", "sam_private_key_password",
    "videofilter_keyword", "cloud_authentication_access_key", "cloud_authentication_access_key", "auth_server_secret",
    "ssh_hsk_password", "user_history_password_threshold", "reuse_password_limit", "client_secret_token",
    "token_certificate", "ble_rtls_server_token", "admin_auth_tacacs+", "gch_cryptokey", "gch_cryptokey_version",
    "gch_keyring", "acme_eab_key_hmac", "eab_key_hmac", "gck_access_token_lifetime", "gck_keyid", "gch_private_key",
    "fortitoken_cloud_region", "gck_private_key"
]


def is_secret_field(key_name):
    if key_name in secret_fields:
        return True
    return False
