import re
import logging
import validators
import dns.resolver
import dns.dnssec

import deepcheck.exceptions

SPF_A = "a"
SPF_MX = "mx"
SPF_IP4 = "ip4"
SPF_IP6 = "ip6"
SPF_INCLUDE = "include"
SPF_EXISTS = "exists"
SPF_REDIRECT = "redirect"
SPF_PTR = "ptr"
SPF_ALL = "all"
SPF_EXP = "exp"

SPF_PASS = "+"
SPF_FAIL = "-"
SPF_SOFT_FAIL = "~"
SPF_NEUTRAL = "?"
SPF_QUALIFIERS = [SPF_PASS, SPF_FAIL, SPF_SOFT_FAIL, SPF_NEUTRAL]

SPF_LOOKUP_MECHANISMS = [
    SPF_A, SPF_MX, SPF_INCLUDE, SPF_EXISTS, SPF_PTR,
    SPF_REDIRECT]

DMARC_V = "v"
DMARC_RUA = "rua"
DMARC_RUF = "ruf"
DMARC_RF = "rf"
DMARC_RI = "ri"
DMARC_PCT = "pct"
DMARC_P = "p"
DMARC_FO = "fo"
DMARC_ADKIM = "adkim"
DMARC_ASPF = "aspf"
DMARC_SP = "sp"

DMARC_POL_NON = "none"
DMARC_POL_QUA = "quarantine"
DMARC_POL_RJT = "reject"

DMARC_TAGS = [DMARC_V, DMARC_RUA, DMARC_RUF, DMARC_RF, DMARC_RI,
              DMARC_PCT, DMARC_P, DMARC_FO, DMARC_ADKIM, DMARC_ASPF, DMARC_SP]
DMARC_POLICIES = [DMARC_POL_NON, DMARC_POL_QUA, DMARC_POL_RJT]

RE_STR_SPF_RECORD = \
    r'v=spf1\s+([+\-~?])?(mx|ip4|ip6|exists|include|all|a|redirect|exp|ptr)[:/=]?([\w+/_.:\-{%}]*)'
RE_SPF_RECORD = re.compile(RE_STR_SPF_RECORD, re.IGNORECASE)

RE_STR_DMARC_RECORD = r'(?:([a-z]{1,5})=([^;]+))+'
RE_DMARC_RECORD = re.compile(RE_STR_DMARC_RECORD, re.IGNORECASE)
RE_STR_MAILTO = r"^(mailto):" \
                r"([\w\-!#$%&'*+-/=?^_`{|}~]" \
                r"[\w\-.!#$%&'*+-/=?^_`{|}~]*@[\w\-.]+)(!\w+)?"

RE_MAILTO = re.compile(RE_STR_MAILTO)
RE_DMARC_POLICY = re.compile(r'none|quarantine|reject', re.IGNORECASE)

DMARC_VALUES = {
    DMARC_V: re.compile(r'dmarc1', re.IGNORECASE),
    DMARC_RUA: RE_MAILTO,
    DMARC_RUF: RE_MAILTO,
    DMARC_RF: re.compile(r'afrf|iodef|afrf:iodef', re.IGNORECASE),
    DMARC_RI: re.compile(r'\d+'),
    DMARC_PCT: re.compile(r'\d{1,3}'),
    DMARC_P: RE_DMARC_POLICY,
    DMARC_FO: re.compile(r'(?![^01ds:]+)', re.IGNORECASE),
    DMARC_ADKIM: re.compile(r'[rs]', re.IGNORECASE),
    DMARC_ASPF: re.compile(r'[rs]', re.IGNORECASE),
    DMARC_SP: RE_DMARC_POLICY
}

DEFAULT_TIMEOUT = 2.0

NAMESERVERS = ["208.67.222.222", "208.67.220.220"]

logger = logging.getLogger(__name__)


def query_spf_record(_domain):
    records = []

    try:
        txt_records = query_record_for_domain(_domain, dns.rdatatype.TXT)

        for record in txt_records:
            if "v=spf" in record.lower():
                # We removed the quotes around the record
                records.append(record[1:-1])
    except Exception:
        pass

    return records


def spf_record_is_valid(_record):
    assert _record is not None
    m = RE_SPF_RECORD.match(_record)
    return m is not None


def parse_spf_record(_record, _domain):
    assert _record is not None
    tokens = list(filter(None, _record.split()))
    record = {}
    if len(tokens) > 0:
        for token in tokens:
            token = token.lower()
            mechanism = {}
            if token[0] in SPF_QUALIFIERS:
                mechanism["qualifier"] = token[0]
                token = token[1:]
            else:
                mechanism["qualifier"] = SPF_PASS

            if "=" in token:
                mecha, value = token.split("=")
            elif "all" in token:
                mecha = "all"
                value = ""
            elif ":" in token:
                mecha, value = token.split(":", 1)
            elif "/" in token:
                mecha, value = token.split("/")
                value = "{dom:s}/{val:s}".format(dom=_domain, val=value)
            else:
                mecha = token
                value = _domain

            mechanism["value"] = value
            if mecha in record:
                record[mecha].append(mechanism)
            else:
                record[mecha] = [mechanism]

    return record


def get_spf_record_lookup_mechanisms(_parsed):
    """
    This function will returns lookup mechanisms contained in the
    parsed SPF record given.

    :param _parsed: A parsed SPF record.
    :return: A dictionary containing lookup mechanism and their values.
    """
    assert _parsed is not None
    lookups = {}

    for m in SPF_LOOKUP_MECHANISMS:
        if m in _parsed:
            lookups[m] = _parsed[m]

    return lookups


def count_spf_lookups_for_record(_domain, _parsed, _count=0, _stop=10):

    if _parsed is None or len(_parsed) <= 0:
        return _count

    lookups = get_spf_record_lookup_mechanisms(_parsed)
    if _count >= _stop:
        return _count
    c = _count
    for m in lookups.keys():
        for v in lookups[m]:
            if validators.domain(v["value"]) and v["value"] != _domain:
                c += 1
                r = query_spf_record(v["value"])
                if len(r) > 0:
                    # Assume only one SPF record exists, otherwise
                    # don't bother.
                    p = parse_spf_record(r[0], v["value"])
                    c = count_spf_lookups_for_record(_domain, p, c, _stop)

    return c


def get_spf_record_lookup_count(_lookups):
    count = 0
    for m in _lookups:
        count += len(_lookups[m])
    return count


def is_spf_void_lookup(_mechanism, _host):
    assert _mechanism is not None
    assert _host is not None

    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = NAMESERVERS

        if _mechanism == SPF_MX:
            resolver.query(_host, dns.rdatatype.MX, tcp=True)
        elif _mechanism == SPF_A:
            resolver.query(_host, dns.rdatatype.A, tcp=True)
        elif _mechanism in [SPF_INCLUDE, SPF_EXP, SPF_REDIRECT, SPF_EXISTS]:
            resolver.query(_host, dns.rdatatype.TXT, tcp=True)
        elif _mechanism in [SPF_PTR]:
            resolver.query(_host, dns.rdatatype.PTR)
        return False
    except dns.resolver.NXDOMAIN:
        return True
    except dns.resolver.NoAnswer:
        return True
    except dns.exception.Timeout:
        return True


def is_dkim_supported(_domain):
    dkim_domain = "_domainkey.{:s}".format(_domain)
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = NAMESERVERS
        resolver.query(dkim_domain, dns.rdatatype.TXT)
        return True
    except dns.resolver.NXDOMAIN:
        return False
    except dns.resolver.NoAnswer:
        return True
    except dns.exception.Timeout:
        return False


def query_dmarc_record(_domain):
    assert validators.domain(_domain)

    records = []
    dmarc_record = "_dmarc.{dom:s}".format(dom=_domain)
    try:
        txt_records = query_record_for_domain(dmarc_record, dns.rdatatype.TXT)

        for record in txt_records:
            if "v=dmarc" in record.lower():
                records.append(record[1:-1])
    except Exception:
        pass

    return records


def query_mx_records(_domain):
    assert validators.domain(_domain)

    records = []
    try:
        records = query_record_for_domain(_domain, dns.rdatatype.MX)
        records = list(map(lambda x: str(x).rstrip(".").split(" ")[1], records))
    except Exception:
        pass

    return records


def query_dnskey_records(_domain):
    assert validators.domain(_domain)
    records = []
    try:
        records = query_record_for_domain(_domain, dns.rdatatype.DNSKEY)
    except Exception:
        pass

    return records


def dnssec_is_valid(_domain, _timeout=DEFAULT_TIMEOUT):
    valid_for_all = True

    # Obtain the name servers for the domain
    resolver = dns.resolver.Resolver()
    resolver.nameservers = NAMESERVERS
    response = resolver.query(_domain, dns.rdatatype.NS)

    for nsname in response.rrset:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = NAMESERVERS
        response = resolver.query(nsname.target, dns.rdatatype.A)
        nsaddr = response.rrset[0].to_text()

        # Obtain the DNSKEY
        request = dns.message.make_query(_domain + '.',
                                         dns.rdatatype.DNSKEY,
                                         want_dnssec=True)
        response = dns.query.udp(request, nsaddr, timeout=_timeout)
        if response.rcode() != 0:
            return False

        answer = response.answer
        # answer should contain two RRSET: DNSKEY and RRSIG(DNSKEY), if not
        # something is wrong
        if len(answer) != 2:
            return False

        name = dns.name.from_text(_domain + '.')
        try:
            dns.dnssec.validate(answer[0], answer[1], {name: answer[0]})
        except dns.dnssec.ValidationFailure:
            return False
        except Exception as e:
            logger.debug(str(e))
            return False
        else:
            valid_for_all |= True

    return valid_for_all


def dmarc_syntax_is_valid(_record):
    assert _record is not None

    record = _record.strip()
    if len(record) <= 0:
        return False

    # Special case: records that are quoted are invalid
    badchars = ["\"", "'"]
    if record[0] in badchars or record[-1] in badchars:
        return False

    m = RE_DMARC_RECORD.match(_record)
    if m is not None:
        tokens = _record.lower().split(";")
        # If we failed to break down the record into
        # more then one token, then the record is not using
        # semi-colons properly.
        if len(tokens) <= 1:
            return False
        for token in tokens:
            if "=" not in token:
                return False
            tag, value = token.split("=")
            if tag.strip() not in DMARC_TAGS:
                return False

    return True


def parse_dmarc_record(_record):
    assert _record is not None
    record = {}
    m = RE_DMARC_RECORD.findall(_record)
    for tag, value in m:
        record[tag.lower()] = value.lower()
    return record


def dmarc_record_is_valid(_record):
    assert _record is not None

    is_valid = dmarc_syntax_is_valid(_record)
    if not is_valid:
        return False
    parsed = parse_dmarc_record(_record)

    for tag, value in parsed.items():
        if tag not in DMARC_TAGS:
            return False
        else:
            m = DMARC_VALUES[tag].match(value)
            if m is None:
                return False

    return True


def query_record_for_domain(_domain, _recordtype):
    assert _domain is not None
    assert _recordtype is not None

    records = []

    try:
        r = dns.resolver.Resolver()
        r.nameservers = NAMESERVERS
        answer = r.query(_domain, _recordtype)
        for rdata in answer:
            records.append(rdata.to_text())
        return records
    except dns.resolver.NoAnswer:
        return records
    except Exception as e:
        raise deepcheck.exceptions.DnsQueryException(
            _domain=_domain,
            _recordtype=str(_recordtype),
            _message=str(e)
        )
