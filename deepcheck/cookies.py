import logging
import requests
import requests.cookies
import validators

import deepcheck.exceptions
import deepcheck.headers

DEFAULT_TIMEOUT = 3.0

logger = logging.getLogger(__name__)


def get_cookies_via_requests(_url, _timeout=DEFAULT_TIMEOUT, _redirect=False):
    """
    Attempts to extract cookies from a given URL using the requests module.

    This function will attempt a connection to the given URL and read cookies from the response
    given, if any. A single connection is made and thus this function may not capture cookies created
    after login or other similar actions.

    A dictionary structure will be created, using the name of the cookie as key. The value will be a
    secondary dictionary containing the properties of the cookie, including its value and any flags set.

    @param _url The URL to extract cookies from.
    @param _timeout Time in seconds after which to give up. Defaults to 3.0 seconds.
    @param _redirect Indicates if the request should follow redirections in order to obtain cookies. Only cookies
            at the endpoint will be read. Defaults to False.
    """
    assert validators.url(_url)
    assert 0 <= _timeout

    # Use the default headers
    headers = deepcheck.headers.REQUEST_HEADERS
    # Start a session in order to keep cookies stored.
    session = requests.Session()
    # make the request
    session.get(_url, allow_redirects=_redirect, verify=False, headers=headers, timeout=_timeout)
    cookies = dict()
    for cookie in session.cookies:
        cookies[cookie.name] = {
            "value": cookie.value,
            "secure": cookie.secure,
            "path": cookie.path,
            "expires": cookie.expires,
            "domain": cookie.domain,
            "samesite": None,
            "max-age": None,
            "httponly": ("httponly" in [a.lower() for a in cookie._rest.keys()])
        }
        # Get the non-standard/uncommon flags we need for testing.
        for flag, value in cookie._rest.items():
            if flag.lower() == "max-age":
                cookies[cookie.name]["max-age"] = value
            elif flag.lower() == "samesite":
                cookies[cookie.name]["samesite"] = value

    return cookies
