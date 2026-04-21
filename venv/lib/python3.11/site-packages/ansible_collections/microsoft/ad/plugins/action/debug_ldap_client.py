# Copyright (c) 2023 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import importlib
import importlib.metadata
import typing as t
import traceback


from ansible.plugins.action import ActionBase
from ansible.utils.display import Display

display = Display()

try:
    import dns.resolver

    HAS_DNSRESOLVER = True
except Exception:
    HAS_DNSRESOLVER = False


try:
    import krb5

    HAS_KRB5 = True
except Exception:
    HAS_KRB5 = False


class ActionModule(ActionBase):
    def run(
        self,
        tmp: t.Optional[str] = None,
        task_vars: t.Optional[t.Dict[str, t.Any]] = None,
    ) -> t.Dict[str, t.Any]:
        self._supports_check_mode = True
        self._supports_async = True

        result = super().run(tmp=tmp, task_vars=task_vars)
        del tmp

        kerb_info = self._get_kerberos_info()

        dns_info: t.Dict[str, t.Any] = {}
        default_realm = kerb_info.get("default_realm", None)
        if default_realm:
            dns_info = self._get_server_lookup_info(default_realm)

        result.update(
            {
                "dns": dns_info,
                "kerberos": kerb_info,
                "packages": {
                    "dnspython": self._import_lib(
                        "dns.resolver", package_name="dnspython"
                    ),
                    "dpapi_ng": self._import_lib("dpapi_ng", package_name="dpapi-ng"),
                    "krb5": self._import_lib("krb5"),
                    "pyspnego": self._import_lib("spnego", package_name="pyspnego"),
                    "sansldap": self._import_lib("sansldap"),
                },
            }
        )

        return result

    def _get_kerberos_info(self) -> t.Dict[str, t.Any]:
        if not HAS_KRB5:
            return {}

        res: t.Dict[str, t.Any] = {
            "exception": None,
            "default_realm": None,
            "default_cc": {},
        }

        try:
            ctx = krb5.init_context()
        except Exception:
            res["exception"] = traceback.format_exc()
            return res

        try:
            res["default_realm"] = krb5.get_default_realm(ctx).decode("utf-8")
        except Exception:
            res["exception"] = traceback.format_exc()

        res["default_cc"] = self._get_kerberos_cc_info(ctx)

        return res

    def _get_kerberos_cc_info(
        self,
        ctx: "krb5.Context",
    ) -> t.Dict[str, t.Any]:
        creds: t.List[t.Dict[str, t.Any]] = []
        res: t.Dict[str, t.Any] = {
            "exception": None,
            "name": None,
            "principal": None,
            "creds": creds,
        }

        try:
            default_cc = krb5.cc_default(ctx)
        except Exception:
            res["exception"] = traceback.format_exc()
            return res

        try:
            res["name"] = str(default_cc)
            res["principal"] = str(default_cc.principal)
            for cred in default_cc:
                # cred attrs added in krb5 0.5.0
                creds.append(
                    {
                        "client": str(getattr(cred, "client", "krb5 too old")),
                        "server": str(getattr(cred, "server", "krb5 too old")),
                    }
                )
        except Exception:
            res["exception"] = traceback.format_exc()

        return res

    def _get_server_lookup_info(
        self,
        default_realm: str,
    ) -> t.Dict[str, t.Any]:
        if not HAS_DNSRESOLVER:
            return {}

        records: t.List[t.Dict[str, t.Any]] = []
        res: t.Dict[str, t.Any] = {
            "exception": None,
            "default_server": None,
            "default_port": None,
            "records": records,
        }

        try:
            srv_record = f"_ldap._tcp.dc._msdcs.{default_realm}"

            for rec in dns.resolver.resolve(srv_record, "SRV"):
                records.append(
                    {
                        "target": str(rec.target),
                        "port": rec.port,
                        "weight": rec.weight,
                        "priority": rec.priority,
                    }
                )

            highest_record = next(
                iter(sorted(records, key=lambda k: (k["priority"], -k["weight"]))), None
            )
            if highest_record:
                res["default_server"] = highest_record["target"].rstrip(".")
                res["default_port"] = highest_record["port"]

        except Exception:
            res["exception"] = traceback.format_exc()

        return res

    def _import_lib(
        self,
        name: str,
        package_name: t.Optional[str] = None,
    ) -> str:
        try:
            importlib.import_module(name)
            return importlib.metadata.version(package_name or name)
        except Exception:
            return traceback.format_exc()
