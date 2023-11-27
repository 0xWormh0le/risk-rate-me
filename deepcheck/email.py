import logging
import socket
import smtplib

import deepcheck.common
import deepcheck.exceptions
import deepcheck.ssl

# Default network timeout value
DEFAULT_TIMEOUT = 2.0

# Usual SMTP ports
STANDARD_SMTP_PORTS = [
    25, 465, 587
]

# Usual IMAP ports
STANDARD_IMAP_PORTS = [
    143, 993
]

logger = logging.getLogger(__name__)


def get_mail_data_from_shodan(_shodan_data, _timeout=DEFAULT_TIMEOUT):
    assert _shodan_data is not None
    data = {}
    ports = STANDARD_IMAP_PORTS + STANDARD_SMTP_PORTS
    if _shodan_data is None or len(_shodan_data) <= 0:
        raise deepcheck.exceptions.ResponseContainsNoDataException(_host="N/A")

    if "data" not in _shodan_data:
        return data

    for service in _shodan_data["data"]:
        if "port" in service and service["port"] in ports:
            port = service["port"]
            data[port] = {}
            if "data" in service:
                data[port]["banner"] = service["data"]
            else:
                data[port]["banner"] = ""

            if "ssl" in service:
                data[port]["ssl"] = service["ssl"]
            else:
                data[port]["ssl"] = {}

    return data


def mail_data_has_certificate(_shodan_data):
    assert _shodan_data is not None
    mail_data = get_mail_data_from_shodan(_shodan_data=_shodan_data)

    if mail_data is None or len(mail_data) <= 0:
        raise deepcheck.exceptions.NoMailAgentDataFoundException(
            _host=_shodan_data["ip_str"]
        )

    for port in mail_data.keys():
        cert = deepcheck.common.get_certificate_from_shodan_data(
            _shodan_data=_shodan_data,
            _port=port
        )
        if cert is not None and len(cert) > 0:
            return True


def mail_data_from_shodan_has_expired_certificates(_shodan_data):
    assert _shodan_data is not None
    mail_data = get_mail_data_from_shodan(_shodan_data=_shodan_data)

    if mail_data is None or len(mail_data) <= 0:
        raise deepcheck.exceptions.NoMailAgentDataFoundException(
            _host=_shodan_data["ip_str"]
        )

    for port in mail_data.keys():
        cert = deepcheck.common.get_certificate_from_shodan_data(
            _shodan_data=_shodan_data,
            _port=port
        )
        if cert is not None and len(cert) > 0:
            if cert["expired"] is True:
                return True

    return False


def mail_data_from_shodan_has_self_signed_certificates(_shodan_data):
    assert _shodan_data is not None
    mail_data = get_mail_data_from_shodan(_shodan_data=_shodan_data)

    if mail_data is None or len(mail_data) <= 0:
        raise deepcheck.exceptions.NoMailAgentDataFoundException(
            _host=_shodan_data["ip_str"]
        )

    for port in mail_data.keys():
        # Only check ports with certificates
        if "ssl" in mail_data[port] and "cert" in mail_data[port]["ssl"]:
            deepcheck.common.certificate_from_shodan_is_self_signed(
                _shodan_data=_shodan_data,
                _port=port
            )

    return False


def mail_data_from_shodan_has_weak_ciphers(_shodan_data):
    assert _shodan_data is not None
    mail_data = get_mail_data_from_shodan(_shodan_data=_shodan_data)

    if mail_data is None or len(mail_data) <= 0:
        raise deepcheck.exceptions.NoMailAgentDataFoundException(
            _host=_shodan_data["ip_str"]
        )

    contains_ssl_data = False
    for port in mail_data.keys():
        contains_ssl_data = contains_ssl_data or ("ssl" in mail_data[port] and (len(mail_data[port]["ssl"]) > 0))

    if not contains_ssl_data:
        raise deepcheck.exceptions.NoCipherDataAvailableException()

    for port in mail_data.keys():
        # Only check ports with certificates
        if "ssl" in mail_data[port] and "versions" in mail_data[port]["ssl"]:
            ciphers = mail_data[port]["ssl"]["versions"]
            ciphers = [x.lower() for x in ciphers]
            weak_ciphers = set(ciphers) & set(deepcheck.common.WEAK_CIPHERS)
            if len(weak_ciphers) > 0:
                return True, ciphers

    return False, []


def banner_contains_text(_banner, _text, _ignorecase=True):
    assert _banner is not None
    assert _text is not None
    if len(_banner) > 0:
        if _ignorecase:
            return _text.lower() in _banner.lower()
        else:
            return _text in _banner
    return False


def server_supports_starttls(_mail_data):
    assert _mail_data is not None

    if _mail_data is not None and len(_mail_data) > 0:
        for port, data in _mail_data.items():
            if "banner" in data and banner_contains_text(data["banner"], "starttls", _ignorecase=True):
                return True

    return False


def try_send_unauthenticated_email_via(_server, _port, _use_starttls, _timeout=DEFAULT_TIMEOUT):
    assert _server is not None
    assert 0 <= _port <= 2 ** 16

    sender = 'sender@mailinator.com'
    receivers = ['recipient@mailinator.com']

    message = """From: From Person <from@fromdomain.com>
    To: To Person <to@todomain.com>
    Subject: SMTP e-mail test

    This is a test e-mail message.
    """

    try:
        socket.setdefaulttimeout(_timeout)
        if _use_starttls:
            smtp = smtplib.SMTP_SSL(_server, port=_port)
        else:
            smtp = smtplib.SMTP(_server, port=_port)
        smtp.sendmail(sender, receivers, message)
        return True
    except smtplib.SMTPException as e:
        raise deepcheck.exceptions.RemoteConnectionException(
            _url=_server,
            _message=str(e)
        )
    except socket.timeout as e:
        raise deepcheck.exceptions.RemoteConnectionException(
            _url=_server,
            _message=str(e)
        )
    except Exception as e:
        raise deepcheck.exceptions.RemoteConnectionException(
            _url=_server,
            _message=str(e)
        )
