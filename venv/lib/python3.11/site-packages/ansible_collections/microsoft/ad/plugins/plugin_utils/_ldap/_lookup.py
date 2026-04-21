# Copyright: (c) 2023, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# FOR INTERNAL COLLECTION USE ONLY
# The interfaces in this file are meant for use within this collection
# and may not remain stable to outside uses. Changes may be made in ANY release, even a bugfix release.
# See also: https://github.com/ansible/community/issues/539#issuecomment-780839686
# Please open an issue if you have questions about this.

import typing as t

# dnspython is used for dynamic server lookups
try:
    import dns.resolver

    HAS_DNSPYTHON = True
except Exception:
    HAS_DNSPYTHON = False


# krb5 is used to retrieve the default realm for dynamic server lookups.
try:
    import krb5

    HAS_KRB5 = True
except Exception:
    HAS_KRB5 = False


class SrvRecord(t.NamedTuple):
    target: str
    port: int
    weight: int
    priority: int

    @classmethod
    def lookup(
        cls,
        service: str,
        proto: str,
        name: str,
    ) -> t.List["SrvRecord"]:
        """Performs an SRV lookup.

        Args:
            service: The SRV service.
            proto: The SRV protocol.
            name: The SRV name.

        Returns:
            List[SrvRecord]: A list of records ordered by priority and weight.
        """
        record = f"_{service}._{proto}.{name}"

        answers: t.List[SrvRecord] = []
        for answer in dns.resolver.resolve(record, "SRV"):
            answers.append(
                SrvRecord(
                    target=str(answer.target),
                    port=answer.port,
                    weight=answer.weight,
                    priority=answer.priority,
                )
            )

        # Sorts the array by lowest priority then highest weight.
        return sorted(answers, key=lambda a: (a.priority, -a.weight))


def lookup_ldap_server() -> t.Tuple[str, int]:
    """Attempts to lookup LDAP server.

    Attempts to lookup LDAP server based on the current Kerberos host
    configuration. Will them perform an SRV lookup for
    '_ldap._tcp.dc._msdcs.{realm}' to get the LDAP server hostname nad port.

    Returns:
        Tuple[str, int]: The LDAP hostname and port.

    Raises:
        ImportError: Missing krb5 or dnspython.
        krb5.Krb5Error: Kerberos configuration problem
        dns.exception.DNSException: DNS lookup error.
    """
    required_libs = [(HAS_KRB5, "krb5"), (HAS_DNSPYTHON, "dnspython")]
    missing_libs = [lib for present, lib in required_libs if not present]
    if missing_libs:
        raise ImportError(f"Cannot lookup server without the python libraries {', '.join(missing_libs)}")

    ctx = krb5.init_context()
    default_realm = krb5.get_default_realm(ctx).decode("utf-8")
    answer = SrvRecord.lookup("ldap", "tcp", f"dc._msdcs.{default_realm}")[0]
    return answer.target, answer.port
