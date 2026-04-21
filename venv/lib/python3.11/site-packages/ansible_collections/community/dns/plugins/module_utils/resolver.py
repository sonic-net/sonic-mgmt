# -*- coding: utf-8 -*-

# Copyright (c) 2021, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type

import traceback

from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.common.text.converters import to_native, to_text


try:
    import dns
    import dns.exception
    import dns.inet
    import dns.message
    import dns.name
    import dns.query
    import dns.rcode
    import dns.rdatatype
    import dns.resolver
except ImportError:
    DNSPYTHON_IMPORTERROR = traceback.format_exc()
else:
    DNSPYTHON_IMPORTERROR = None  # type: ignore  # TODO


_EDNS_SIZE = 1232  # equals dns.message.DEFAULT_EDNS_PAYLOAD; larger values cause problems with Route53 nameservers for me


class ResolverError(Exception):
    pass


class InvalidInput(ResolverError):
    pass


class _Resolve(object):
    def __init__(self, timeout=10, timeout_retries=3, servfail_retries=0):
        self.timeout = timeout
        self.timeout_retries = timeout_retries
        self.servfail_retries = servfail_retries
        self.default_resolver = dns.resolver.get_default_resolver()

    def _handle_reponse_errors(self, target, response, nameserver=None, query=None, accept_errors=None):
        rcode = response.rcode()
        if rcode == dns.rcode.NOERROR:
            return True
        if accept_errors and rcode in accept_errors:
            return True
        if rcode == dns.rcode.NXDOMAIN:
            raise dns.resolver.NXDOMAIN(qnames=[target], responses={target: response})
        msg = 'Error %s' % dns.rcode.to_text(rcode)
        if nameserver:
            msg = '%s while querying %s' % (msg, nameserver)
        if query:
            msg = '%s with query %s' % (msg, query)
        raise ResolverError(msg)

    def _handle_timeout(self, function, *args, **kwargs):
        retry = 0
        while True:
            try:
                return function(*args, **kwargs)
            except dns.exception.Timeout as exc:
                if retry >= self.timeout_retries:
                    raise exc
                retry += 1

    def _resolve(self, resolver, dnsname, handle_response_errors=False, **kwargs):
        retry = 0
        while True:
            try:
                response = self._handle_timeout(resolver.resolve, dnsname, lifetime=self.timeout, **kwargs)
            except AttributeError:
                # For dnspython < 2.0.0
                resolver.search = kwargs.pop('search', False)
                try:
                    response = self._handle_timeout(resolver.query, dnsname, lifetime=self.timeout, **kwargs)
                except TypeError:
                    # For dnspython < 1.6.0
                    resolver.lifetime = self.timeout
                    response = self._handle_timeout(resolver.query, dnsname, **kwargs)
            if response.response.rcode() == dns.rcode.SERVFAIL and retry < self.servfail_retries:
                retry += 1
                continue
            if handle_response_errors:
                self._handle_reponse_errors(dnsname, response.response, nameserver=resolver.nameservers)
            return response.rrset


class SimpleResolver(_Resolve):
    def __init__(
        self,
        timeout=10,
        timeout_retries=3,
        servfail_retries=0,
    ):
        super(SimpleResolver, self).__init__(
            timeout=timeout,
            timeout_retries=timeout_retries,
            servfail_retries=servfail_retries,
        )

    def resolve(self, target, nxdomain_is_empty=True, server_addresses=None, target_can_be_relative=False, **kwargs):
        if target_can_be_relative:
            dnsname = dns.name.from_unicode(to_text(target), origin=None)
        else:
            dnsname = dns.name.from_unicode(to_text(target))

        resolver = self.default_resolver
        if server_addresses:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.timeout = self.timeout
            resolver.nameservers = server_addresses

        resolver.use_edns(0, ednsflags=dns.flags.DO, payload=_EDNS_SIZE)

        try:
            return self._resolve(resolver, dnsname, handle_response_errors=True, **kwargs)
        except dns.resolver.NXDOMAIN:
            if nxdomain_is_empty:
                return None
            raise
        except dns.resolver.NoAnswer:
            return None

    def resolve_addresses(self, target, **kwargs):
        dnsname = dns.name.from_unicode(to_text(target))
        resolver = self.default_resolver
        result = []
        try:
            for data in self._resolve(resolver, dnsname, handle_response_errors=True, rdtype=dns.rdatatype.A, **kwargs):
                result.append(str(data))
        except dns.resolver.NoAnswer:
            pass
        try:
            for data in self._resolve(resolver, dnsname, handle_response_errors=True, rdtype=dns.rdatatype.AAAA, **kwargs):
                result.append(str(data))
        except dns.resolver.NoAnswer:
            pass
        return result


class ResolveDirectlyFromNameServers(_Resolve):
    def __init__(
        self,
        timeout=10,
        timeout_retries=3,
        servfail_retries=0,
        always_ask_default_resolver=True,
        server_addresses=None,
    ):
        super(ResolveDirectlyFromNameServers, self).__init__(
            timeout=timeout,
            timeout_retries=timeout_retries,
            servfail_retries=servfail_retries,
        )
        self.cache = {}
        self.default_nameservers = self.default_resolver.nameservers if server_addresses is None else server_addresses
        self.always_ask_default_resolver = always_ask_default_resolver

    def _lookup_ns_names(self, target, nameservers=None, nameserver_ips=None):
        if self.always_ask_default_resolver:
            nameservers = None
            nameserver_ips = self.default_nameservers
        if nameservers is None and nameserver_ips is None:
            nameserver_ips = self.default_nameservers
        if not nameserver_ips and nameservers:
            nameserver_ips = self._lookup_address(nameservers[0])
        if not nameserver_ips:
            raise ResolverError('Have neither nameservers nor nameserver IPs')

        # Sanity check: do we have a valid nameserver IP?
        try:
            dns.inet.af_for_address(nameserver_ips[0])
        except ValueError:
            raise InvalidInput("Invalid nameserver IP address {0}".format(nameserver_ips[0]))

        query = dns.message.make_query(target, dns.rdatatype.NS)
        retry = 0
        while True:
            response = self._handle_timeout(dns.query.udp, query, nameserver_ips[0], timeout=self.timeout)
            if response.rcode() == dns.rcode.SERVFAIL and retry < self.servfail_retries:
                retry += 1
                continue
            break
        self._handle_reponse_errors(
            target, response, nameserver=nameserver_ips[0], query='get NS for "%s"' % target, accept_errors=[dns.rcode.NXDOMAIN],
        )

        cname = None
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.CNAME:
                cname = dns.name.from_text(to_text(rrset[0]))

        new_nameservers = []
        rrsets = list(response.authority)
        rrsets.extend(response.answer)
        for rrset in rrsets:
            if rrset.rdtype == dns.rdatatype.SOA:
                # We keep the current nameservers
                return None, cname
            if rrset.rdtype == dns.rdatatype.NS:
                new_nameservers.extend(str(ns_record.target) for ns_record in rrset)
        return sorted(set(new_nameservers)) if new_nameservers else None, cname

    def _lookup_address_impl(self, target, rdtype):
        try:
            answer = self._resolve(self.default_resolver, target, handle_response_errors=True, rdtype=rdtype)
            return [str(res) for res in answer]
        except dns.resolver.NoAnswer:
            return []

    def _lookup_address(self, target):
        result = self.cache.get((target, 'addr'))
        if not result:
            result = self._lookup_address_impl(target, dns.rdatatype.A)
            result.extend(self._lookup_address_impl(target, dns.rdatatype.AAAA))
            self.cache[(target, 'addr')] = result
        return result

    def _do_lookup_ns(self, target):
        nameserver_ips = self.default_nameservers
        nameservers = None
        for i in range(2, len(target.labels) + 1):
            target_part = target.split(i)[1]
            _nameservers = self.cache.get((str(target_part), 'ns'))
            if _nameservers is None:
                nameserver_names, cname = self._lookup_ns_names(target_part, nameservers=nameservers, nameserver_ips=nameserver_ips)
                if nameserver_names is not None:
                    nameservers = nameserver_names

                self.cache[(str(target_part), 'ns')] = nameservers
                self.cache[(str(target_part), 'cname')] = cname
            else:
                nameservers = _nameservers
            nameserver_ips = None

        return nameservers

    def _lookup_ns(self, target):
        result = self.cache.get((str(target), 'ns'))
        if not result:
            result = self._do_lookup_ns(target)
            self.cache[(str(target), 'ns')] = result
        return result

    def _get_resolver(self, dnsname, nameservers):
        cache_index = ('|'.join([str(dnsname)] + sorted(nameservers)), 'resolver')
        resolver = self.cache.get(cache_index)
        if resolver is None:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.use_edns(0, ednsflags=dns.flags.DO, payload=_EDNS_SIZE)
            resolver.timeout = self.timeout
            nameserver_ips = set()
            for nameserver in nameservers:
                nameserver_ips.update(self._lookup_address(nameserver))
            resolver.nameservers = sorted(nameserver_ips)
            self.cache[cache_index] = resolver
        return resolver

    def resolve_nameservers(self, target, resolve_addresses=False):
        nameservers = self._lookup_ns(dns.name.from_unicode(to_text(target)))
        if resolve_addresses:
            nameserver_ips = set()
            for nameserver in nameservers or []:
                nameserver_ips.update(self._lookup_address(nameserver))
            nameservers = list(nameserver_ips)
        return sorted(nameservers or [])

    def resolve(self, target, nxdomain_is_empty=True, **kwargs):
        dnsname = dns.name.from_unicode(to_text(target))
        loop_catcher = set()
        while True:
            try:
                nameservers = self._lookup_ns(dnsname)
            except dns.resolver.NXDOMAIN:
                if nxdomain_is_empty:
                    return {}
                raise
            cname = self.cache.get((str(dnsname), 'cname'))
            if cname is None:
                break
            dnsname = cname
            if dnsname in loop_catcher:
                raise ResolverError('Found CNAME loop starting at {0}'.format(target))
            loop_catcher.add(dnsname)

        results = {}
        for nameserver in nameservers or []:
            results[nameserver] = None
            resolver = self._get_resolver(dnsname, [nameserver])
            try:
                results[nameserver] = self._resolve(resolver, dnsname, handle_response_errors=True, **kwargs)
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                if nxdomain_is_empty:
                    results[nameserver] = []
                else:
                    raise
        return results


def guarded_run(runner, module, server=None, generate_additional_results=None):
    suffix = ' for {0}'.format(server) if server is not None else ''
    kwargs = {}
    try:
        return runner()
    except InvalidInput as e:
        if generate_additional_results is not None:
            kwargs = generate_additional_results()
        module.fail_json(
            msg='Invalid input{0}: {1}'.format(suffix, to_native(e)),
            exception=traceback.format_exc(),
            **kwargs
        )
    except ResolverError as e:
        if generate_additional_results is not None:
            kwargs = generate_additional_results()
        module.fail_json(
            msg='Unexpected resolving error{0}: {1}'.format(suffix, to_native(e)),
            exception=traceback.format_exc(),
            **kwargs
        )
    except dns.exception.DNSException as e:
        if generate_additional_results is not None:
            kwargs = generate_additional_results()
        module.fail_json(
            msg='Unexpected DNS error{0}: {1}'.format(suffix, to_native(e)),
            exception=traceback.format_exc(),
            **kwargs
        )


def assert_requirements_present(module):
    if DNSPYTHON_IMPORTERROR is not None:
        module.fail_json(
            msg=missing_required_lib('dnspython'),
            exception=DNSPYTHON_IMPORTERROR,
        )
