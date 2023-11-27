import os
import logging
import socket
import requests
import tempfile
import tldextract
import validators
from xml.etree import ElementTree

import deepcheck.exceptions

# Default network timeout value
DEFAULT_TIMEOUT = 2.0

WEAK_CIPHERS = ["sslv2", "sslv3"]

MAX_MX_RECORD = 2
URL_CHECKTLS = ("https://www.checktls.com/TestReceiver?"
                "CUSTOMERCODE={user:s};"
                "CUSTOMERPASS={password:s};"
                "EMAIL={domain:s};"
                "LEVEL=XML_SSLDetail")

logger = logging.getLogger(__name__)


def extract_base_domain(_domain):
    cache_file = os.path.join(tempfile.gettempdir(), "tdlextract.cache")
    extract = tldextract.TLDExtract(cache_file=cache_file)
    ext = extract(_domain)
    return ext.registered_domain


def query_mail_data_from_checktls(_domain, _user, _password, _headers=None):
    assert _user is not None and len(_user) > 0
    assert _password is not None and len(_password) > 0

    data = {}
    url = URL_CHECKTLS.format(user=_user, password=_password, domain=_domain, _headers=None)
    logger.debug(url)
    headers = _headers
    response = requests.get(url, headers=headers)
    if "Invalid CUSTOMERCODE or CUSTOMERPASS" in response.text:
        logger.error(response.text)
        logger.debug("User: {:s}, Password: {:s}".format(str(_user), str(_password)))
        return data

    root = ElementTree.fromstring(response.content)

    try:
        if root is not None:
            data = {
                "overall_tls": float(root.find("TLS").text),
                "overall_cert": float(root.find("Cert").text),
                "overall_secure": float(root.find("Secure").text),
                "mx": {}
            }
            OK = [None, "0"]
            for mx in root.iterfind('MX'):
                if mx.attrib["address"] != "unresolvable" and mx.attrib["name"] not in data["mx"]:
                    data["mx"][mx.attrib["name"]] = {
                        "tls_score": float(mx.find("TLS").text),
                        "cert_score": float(mx.find("Cert").text),
                        "secure_score": float(mx.find("Secure").text),
                        "preference": int(mx.attrib["preference"]),
                        "ssl_version": mx.find("SSL/SSLVersion").text,
                        "ssl_cipher": mx.find("SSL/Cipher").text,
                        "ssl_deprecated": (mx.find("SSL/SSLDeprecated").text not in OK),
                        "cert_count": int(mx.find("Certs").attrib["count"]),
                        "port": mx.attrib["port"],
                    }
                    data["mx"][mx.attrib["name"]]["certs"] = {}
                    for cert in mx.find("Certs").iterfind("Cert"):
                        issuer = cert.find("Issuer/commonName").text.lower()
                        data["mx"][mx.attrib["name"]]["certs"][issuer] = {
                            "invalid": (cert.find("ValidateError").text not in OK),
                            "expired": (cert.find("Expired").text not in OK),
                            "revoked": (cert.find("RevokedByCRL").text not in OK),
                        }

                if len(data["mx"]) > MAX_MX_RECORD:
                    break
    except Exception as e:
        logger.error(str(e))

    return data


def query_host_on_shodan(_host, _key, _timeout=DEFAULT_TIMEOUT):
    assert _host is not None
    assert _key is not None

    ip = resolve_host_to_ip_address(
        _hostname=_host,
        _timeout=_timeout
    )

    if ip is not None:
        return query_ip_on_shodan(
            _ip=ip,
            _key=_key,
            _timeout=_timeout
        )
    else:
        logger.error("Could not result '{host:s}' to an IP address.".format(host=_host))
        raise deepcheck.exceptions.IpResolutionException(_host=_host)


def query_ip_on_shodan(_ip, _key, _timeout=DEFAULT_TIMEOUT):
    """
    Obtains port and ssl information for the given host be query Shodan.io
    for the information.

    A query done using this method does requires any query credit to be used.

    :param _key:
    :param _ip:
    :param _timeout: A timeout value to avoid hangups.
    :return:
    """
    assert validators.ipv4(_ip) or validators.ipv6(_ip)
    url = "https://api.shodan.io/shodan/host/{}?key={}".format(_ip, _key)
    # Make the query to Shodan using the IP address.
    response = requests.get(url, timeout=_timeout)

    if response is not None and response.status_code == requests.codes.ok:
        return response.json()
    else:
        if response is None:
            code = "response is null"
        else:
            code = response.status_code

        raise deepcheck.exceptions.InvalidResponseException(
            _url=url,
            _code=code
        )


def get_port_data_from_shodan(_shodan_data, _port):
    assert _shodan_data is not None
    assert 0 <= _port <= 2 ** 16
    data = {}

    if "ports" in _shodan_data and _port in _shodan_data["ports"]:
        if "data" in _shodan_data:
            for service in _shodan_data["data"]:
                if "port" in service and service["port"] == _port:
                    return service

    return data


def get_ssl_data_of_port_from_shodan(_shodan_data, _port):
    assert _shodan_data is not None
    assert 0 <= _port <= 2 ** 16
    data = {}

    service_data = get_port_data_from_shodan(
        _shodan_data=_shodan_data,
        _port=_port
    )

    if len(service_data) > 0 and "ssl" in service_data:
        return service_data["ssl"]

    return data


def get_certificate_from_shodan_data(_shodan_data, _port):
    assert _shodan_data is not None
    assert 0 <= _port <= 2 ** 16
    ssl_data = get_ssl_data_of_port_from_shodan(
        _shodan_data=_shodan_data,
        _port=_port
    )
    if ssl_data is not None and len(ssl_data) > 0 and "cert" in ssl_data:
        return ssl_data["cert"]

    return {}


def resolve_host_to_ip_address(_hostname, _timeout=DEFAULT_TIMEOUT):
    ip = None
    try:
        socket.timeout(_timeout)
        # Get the first associated IP address with the hostname
        ip = socket.gethostbyname(_hostname)
    except socket.gaierror as e:
        raise deepcheck.exceptions.InvalidHostOrDomainException(_hostname, str(e))
    except socket.herror:
        pass
    finally:
        return ip


def resolve_ip_address_to_host(_ip, _timeout=DEFAULT_TIMEOUT):
    host = None
    try:
        socket.timeout(_timeout)
        # Get the first associated IP address with the hostname
        host = socket.gethostbyaddr(_ip)
        if len(host) > 0:
            host = host[0]
    except socket.gaierror as e:
        raise deepcheck.exceptions.InvalidHostOrDomainException(_ip, str(e))
    except socket.herror:
        pass
    finally:
        return host


def certificate_from_shodan_is_self_signed(_shodan_data, _port):
    assert _shodan_data is not None
    assert 0 <= _port <= 2 ** 16

    cert = get_certificate_from_shodan_data(
        _shodan_data=_shodan_data,
        _port=_port
    )

    if cert is None or len(cert) <= 0:
        raise deepcheck.exceptions.NoCertificateFoundException(
            _host=_shodan_data["ip_str"],
            _port=_port
        )

    return cert["issuer"] == cert["subject"]
