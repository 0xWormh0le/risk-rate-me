import time
import datetime

import ssl
from OpenSSL import SSL

import idna
import logging
import socket

DEFAULT_TIMEOUT = 1.0
DEFAULT_RETRIES = 2

SUITE_SSLV2 = "SSLv2"
SUITE_SSLV3 = "SSLv3"
SUITE_TLS10 = "TLS10"
SUITE_TLS11 = "TLS11"
SUITE_TLS12 = "TLS12"
SUITE_TLS13 = "TLS13"

WEAK_SUITES = [SSL.SSLv2_METHOD, SSL.SSLv3_METHOD]
WEAK_CIPHERS = 'NULL:aNULL:LOW:RC4'

logger = logging.getLogger(__name__)


def host_certificate_is_self_signed(_certificate):
    return _certificate.issuer == _certificate.subject


def host_certificate_is_expired(_certificate):
    return _certificate.not_valid_after < datetime.datetime.utcnow()


def get_ssl_certificate(_hostname, _port, _timeout=2.5):
    context = ssl.create_default_context()
    cert = None
    connected = False
    with socket.create_connection((_hostname, _port)) as sock:
        sock.settimeout(_timeout)
        with context.wrap_socket(sock, server_hostname=_hostname) as ssock:
            ssock.setblocking(True)
            cert = ssock.getpeercert()
            connected = True

    return connected, cert


def get_ssl_accepted_protocols(hostname, port):
    return get_ssl_cipher_methods(hostname, port)


def get_ssl_cipher_methods(hostname, port):
    accepted = []
    hostname_idna = idna.encode(hostname)

    methods = [SSL.SSLv23_METHOD, SSL.TLSv1_1_METHOD, SSL.TLSv1_2_METHOD]
    connect_count = 0
    cert = None
    for method in methods:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock_ssl = None
        try:
            sock.settimeout(3)
            sock.connect((hostname, port))
            sock.setblocking(True)
            ctx = SSL.Context(method)
            sock_ssl = SSL.Connection(ctx, sock)
            sock_ssl.set_connect_state()
            sock_ssl.set_tlsext_host_name(hostname_idna)
            sock_ssl.do_handshake()
            cert = sock_ssl.get_peer_certificate()
            accepted.append(method)
            connect_count += 1
            time.sleep(0.3)
        except Exception as e:
            logger.error(str(e))
        finally:
            if sock_ssl is not None:
                sock_ssl.close()
            sock.close()

    if connect_count <= 0:
        raise Exception("Failed to connect to remote host.")
    return accepted, cert


def test_ssl_protocols2(_hostname, _port, _methods):
    accepted = []
    hostname_idna = idna.encode(_hostname)

    timeouts = 0
    methods = _methods
    cert = None
    for method in methods:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock_ssl = None
        try:
            sock.settimeout(5)
            sock.connect((_hostname, _port))
            sock.setblocking(True)
            ctx = SSL.Context(method)
            sock_ssl = SSL.Connection(ctx, sock)
            sock_ssl.set_connect_state()
            sock_ssl.set_tlsext_host_name(hostname_idna)
            sock_ssl.do_handshake()
            cert = sock_ssl.get_peer_certificate()
            accepted.append(method)
            time.sleep(0.3)
        except socket.timeout as e:
            logger.error(str(e))
            timeouts += 1
        except TimeoutError as e:
            logger.error(str(e))
            timeouts += 1
        except Exception as e:
            logger.error(str(e))
        finally:
            if sock_ssl is not None:
                sock_ssl.close()
            sock.close()

    if timeouts >= len(methods):
        raise Exception("Failed to connect to remote host.")

    return accepted, cert


def test_ssl_ciphers(_hostname, _port, _ciphers, _timeout=2.5):
    context = ssl.create_default_context()
    context.set_ciphers(_ciphers)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.load_default_certs()
    cert = None
    connected = False
    with socket.create_connection((_hostname, _port)) as sock:
        sock.settimeout(_timeout)
        with context.wrap_socket(sock, server_hostname=_hostname) as ssock:
            ssock.setblocking(True)
            cert = ssock.getpeercert()
            connected = True

    return connected, cert
