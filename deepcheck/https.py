import logging
import requests
import validators
from urllib.parse import urlparse

import deepcheck.exceptions

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 1.0
UA_FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0"
UA_GOOGLE_WIN = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"

REQUEST_HEADERS = {
    "Accept-Charset": "utf-8",
    "User-Agent": UA_GOOGLE_WIN,
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate"
}


def find_website_from_domain(_domain, _timeout=DEFAULT_TIMEOUT):
    """
    This function attempts to determine the website associated with the current
    domain. If found, it will return the URL which responded first

    The function wll try to connect to http://<base-domain> and http://www.<base-domain> to see if
    a  website exists. If a connection is established, the responding URL, i.e. http://www.website.com
    is returned

    :return: The url found, None if no website responded
    """
    url_templates = [
        "http://www.{dom:s}",
        "http://{dom:s}",
        "https://www.{dom:s}",
        "https://{dom:s}"
    ]

    for template in url_templates:
        try:
            url = template.format(dom=_domain)
            response = requests.get(url, headers=REQUEST_HEADERS, verify=False, timeout=_timeout)
            if response is not None and response.status_code in \
                    [requests.codes.ok, requests.codes.found, requests.codes.moved]:
                return url
        except Exception as e:
            logger.debug(str(e))

    return None


def is_redirected_to_https(_url, _timeout=DEFAULT_TIMEOUT):
    assert validators.url(_url)
    # Try to contact the remote server first.
    try:
        response = requests.get(_url, headers=REQUEST_HEADERS, timeout=_timeout, allow_redirects=True, verify=False)
        # Make sure we get a valid response to ensure we get the normal headers
        if response is not None and response.status_code == requests.codes.ok:
            end_url = urlparse(response.url)
            return end_url.scheme.lower() == "https"
        else:
            raise deepcheck.exceptions.InvalidResponseException(_url, response.status_code)
    except Exception as e:
        # This will catch failed connections attempts.
        raise deepcheck.exceptions.InvalidResponseException(_url, "failed to connect: {:s}".format(str(e)))


def is_responding(_url, _timeout=DEFAULT_TIMEOUT):
    assert validators.url(_url)
    # Try to contact the remote server first.

    response = None

    try:
        response = requests.head(_url, headers=REQUEST_HEADERS, timeout=_timeout, allow_redirects=True, verify=False)
    except Exception as e:
        logger.debug(str(e))

    try:
        # If the server doesn't allow for the HEAD method, get the entire page then..
        if response is None or response.status_code == requests.codes.not_allowed:
            response = requests.get(_url, headers=REQUEST_HEADERS, timeout=_timeout, verify=False)

        # Make sure we get a valid response to ensure we get the normal headers
        if response is None:
            return None
        else:
            return response.status_code
    except Exception as e:
        # This will catch failed connections attempts.
        logger.debug(str(e))
        return None
