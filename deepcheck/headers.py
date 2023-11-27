#!/usr/bin/env python
# -*- coding: utf-8 -*-
# /////////////////////////////////////////////////////////////////////////////
#   ____                   ____          _
# |  _ \  ___  ___ _ __  / ___|___   __| | ___
# | | | |/ _ \/ _ \ '_ \| |   / _ \ / _` |/ _ \
# | |_| |  __/  __/ |_) | |__| (_) | (_| |  __/
# |____/ \___|\___| .__/ \____\___/ \__,_|\___|
#                 |_|
#
# Author: Jon Rasiko, DeepCode.ca
# Version: 1.0
# Date: 2018-12-01
#
# License
# --------
# This file is subject to the terms and conditions defined in
# file 'LICENSE.txt', which is part of this source code package.
#
# Description:
# -------------
#
# /////////////////////////////////////////////////////////////////////////////
import logging
import re
import requests
import validators

import deepcheck.exceptions

DEFAULT_TIMEOUT = 1.0
MIN_RECOMMENDED_HSTS_MAX_AGE = 10368000

HEADER_SERVER = "Server"
HEADER_XPOWERED_BY = "X-Powered-By"
HEADER_FRAME_OPTIONS = "X-Frame-Options"
HEADER_XSS_PROTECTION = "X-Xss-Protection"
HEADER_CONTENT_OPTIONS = "X-Content-Type-Options"
HEADER_FEATURE_POLICY = "Feature-Policy"
HEADER_CONTENT_SEC_POL = "Content-Security-Policy"
HEADER_HSTS = "Strict-Transport-Security"
HEADER_REFERRER_POLICY = "Referrer-Policy"
HEADER_EXPECT_CT = "Expect-CT"

HEADER_FRAME_OPT_DENY = "Deny"
HEADER_FRAME_OPT_SAMEORIGIN = "SameOrigin"
HEADER_FRAME_OPT_ALLOW_FROM = "Allow-From"

HEADER_XSS_PROT_FILTER_OFF = "0"
HEADER_XSS_PROT_FILTER_ON = "1"
HEADER_XSS_PROT_BLOCK = "block"

REFP_NO_REFFERER = "no-referrer"
REFP_NO_REFFERER_DOWNGRADE = "no-referrer-when-downgrade"
REFP_ORIGIN = "origin"
REFP_ORIGIN_CROSS = "origin-when-cross-origin"
REFP_ORIGIN_SAME = "same-origin"
REFP_ORIGIN_STRICT = "strict-origin"
REFP_ORIGIN_STRICT_CROSS = "strict-origin-when-cross-origin"
REFP_UNSAFE = "unsafe-url"

HEADER_CONTENT_OPT_NOSNIFF = "nosniff"

RE_STR_HEADER_HSTS_MAX_AGE = r'max-age=([0-9]+);?\s*(preload|includeSubDomains){0,2};?'
RE_STR_HEADER_XSS_PROTECTION = r'(0|1)\s*;?\s*(mode\s*=\s*block|report\s*=\s*.*)?'
RE_STR_HEADER_FRAME_OPT = r'(Deny|SameOrigin|Allow-From)\s?(.*)'
RE_STR_VERS = r'([^0-9]+)\s*([\d+\.]{1,4}[\.\\/]\d+[a-z]?)'
RE_STR_CONTENT_SEC_POL = r'(([a-z-]+)\s+([^;]*))+'
RE_STR_REFERRER = r'(no-referrer|no-referrer-when-downgrade|origin|' \
                  'origin-when-cross-origin|same-origin|strict-origin|unsafe-url)'

RE_HEADER_HSTS_MAX_AGE = re.compile(RE_STR_HEADER_HSTS_MAX_AGE, re.IGNORECASE)
RE_HEADER_FRAME_OPTIONS = re.compile(RE_STR_HEADER_FRAME_OPT, re.IGNORECASE)
RE_HEADER_CONTECT_SEL_POL = re.compile(RE_STR_CONTENT_SEC_POL, re.IGNORECASE)
RE_HEADER_REFERRER = re.compile(RE_STR_REFERRER, re.IGNORECASE)
RE_HEADER_XSS_PROT = re.compile(RE_STR_HEADER_XSS_PROTECTION, re.IGNORECASE)
RE_HEADER_HSTS = re.compile(RE_STR_HEADER_HSTS_MAX_AGE, re.IGNORECASE)
RE_VERSION = re.compile(RE_STR_VERS, re.IGNORECASE)

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) " \
     "Chrome/60.0.3112.113 Safari/537.36 "

# Headers to send when performing a request.
REQUEST_HEADERS = {
    "Accept-Charset": "utf-8",
    "User-Agent": UA,
    "Cache-Control": "no-cache",
    "Pragma": "no-cache"
}

logger = logging.getLogger(__name__)


def get_headers(_url, _timeout=DEFAULT_TIMEOUT):
    """
    Retrieves the HTTP headers from the given URL.

    :param _url: The URL to read the headers from.
    :param _timeout: A timeout, in seconds, after which the connection will be dropped.
    :return: A dictionary containing the headers sent by the remote server.
    """
    assert validators.url(_url)

    # Try to contact the remote server first.
    try:
        response = requests.get(_url, headers=REQUEST_HEADERS, allow_redirects=True, verify=False, timeout=_timeout)
        # Make sure we get a valid response to ensure we get the normal headers
        if response is not None and response.status_code == requests.codes.ok:
            return response.headers
        else:
            raise deepcheck.exceptions.InvalidResponseException(_url, response.status_code)
    except Exception as e:
        # This will catch failed connections attempts.
        logger.error(str(e))
        raise deepcheck.exceptions.InvalidResponseException(_url, str(e))


def header_exists(_headers, _header_sought, _ignorecase=True):
    """
    Verifies if a given header is containing within the given dictionary. This
    function allows to search a specific header case insensitive.

    :param _headers: A dictionary of HTTP headers
    :param _header_sought: The header to look for
    :param _ignorecase: Specifies whether to ignorecase or not.
    :return: True if the header is found, False otherwise.
    """
    # If no headers are defined, the header does not exist,
    if _headers is not None and len(_headers) > 0:
        # Similarly, if no header is sought, it does not exist,
        if _header_sought is not None and len(_header_sought) > 0:
            # Remove any trailing whitespace
            header_sought = str(_header_sought).strip()
            # Verify if the header exists, return the associated
            # value.
            if _ignorecase:
                for key in _headers.keys():
                    if key.strip().lower() == header_sought.lower():
                        return _headers[key]
            else:
                if _header_sought in _headers.keys():
                    return header_sought in _headers.keys()

    # Return 'None' if no such header exists.
    return False


def header_value(_headers, _header_sought, _ignorecase=True):
    # If no headers are defined, the header does not exist,
    if _headers is not None and len(_headers) > 0:
        # Similarly, if no header is sought, it does not exist,
        if _header_sought is not None and len(_header_sought) > 0:
            # Remove any trailing whitespace
            header_sought = str(_header_sought).strip()
            # Verify if the header exists, return the associated
            # value.
            if _ignorecase:
                for key in _headers.keys():
                    if key.strip().lower() == header_sought.lower():
                        return _headers[key]
            else:
                if _header_sought in _headers.keys():
                    return _headers[header_sought]

    # Return 'None' if no such header exists.
    return None


def header_is_defined(_headers, _header_sought):
    """
    Verifies if the given header is contained in the given dictionary and
    if so, has a non-empty value.
    :param _headers: A dictionary of headers
    :param _header_sought: The HTTP header sought.
    :return: True if the header sought exists and is not empty.
    """
    value = header_value(
        _headers=_headers,
        _header_sought=_header_sought,
        _ignorecase=True
    )

    return value is not None and len(value.strip()) > 0


def contains_version_info(_string):
    """
    Attempts to determine if the given string contains version information.

    This function is designed to assess if a header contains version
    information and is not tested to assess long texts. It uses the
    regular expression defined by RE_STR_VERS

    :param _string: The string to verify.
    :return: True if the string contains version information, False otherwise.
    """
    assert _string is not None
    m = RE_VERSION.match(_string)
    return m is not None and len(m.groups()) > 0


def header_server_contains_version_info(_headers):
    """
    Verifies if the 'Server' header contains version information about the
    underlying webserver. This only applies when the header is present.

    :param _headers: Headers returned by the web server
    :return: True if the 'Server' contains versioning, False in any other case,
    including if the header is not in the header.
    """
    if _headers is not None and len(_headers) > 0:
        value = header_value(
            _headers=_headers,
            _header_sought=HEADER_SERVER,
            _ignorecase=True
        )

        if value is not None:
            return contains_version_info(value.strip())

    return False


def header_x_powered_by_contains_version_info(_headers):
    if _headers is not None and len(_headers) > 0:
        value = header_value(
            _headers=_headers,
            _header_sought=HEADER_XPOWERED_BY,
            _ignorecase=True
        )

        if value is not None:
            return contains_version_info(value.strip())

    return False


def header_x_frame_option_is_valid(_headers):
    if _headers is not None and len(_headers) > 0:
        value = header_value(
            _headers=_headers,
            _header_sought=HEADER_FRAME_OPTIONS,
            _ignorecase=True
        )
        if value is not None:
            m = RE_HEADER_FRAME_OPTIONS.match(value)
            return m is not None and len(m.groups()) > 0

        return False

    raise deepcheck.exceptions.HeaderNotFoundException(_header=HEADER_FRAME_OPTIONS)


def header_feature_policy_is_valid(_headers):
    if _headers is not None and len(_headers) > 0:
        value = header_value(
            _headers=_headers,
            _header_sought=HEADER_FEATURE_POLICY,
            _ignorecase=True
        )
        if value is not None:
            # Split into policies
            policies = list(filter(None, value.split(";")))
            for policy in policies:
                origins = list(filter(None, policy.split(" ")))
                if len(origins) < 2:
                    # No Origin specified for the policy
                    return False
                else:
                    for origin in origins[1:]:
                        if not (origin in ["*", "'self'", "'none'"] or validators.url(origin)):
                            return False
            # We have not found any invalid value at this point
            return True
        # If not value was associated with the header, then it is invalid
        return False

    raise deepcheck.exceptions.HeaderNotFoundException(_header=HEADER_FEATURE_POLICY)


def header_x_content_sec_pol_is_valid(_headers):
    if _headers is not None and len(_headers) > 0:
        value = header_value(
            _headers=_headers,
            _header_sought=HEADER_CONTENT_SEC_POL,
            _ignorecase=True
        )
        if value is not None:
            m = RE_HEADER_CONTECT_SEL_POL.match(value)
            return m is not None and len(m.groups()) > 0

        return False

    raise deepcheck.exceptions.HeaderNotFoundException(_header=HEADER_CONTENT_SEC_POL)


def header_referrer_policy_is_valid(_headers):
    if _headers is not None and len(_headers) > 0:
        value = header_value(
            _headers=_headers,
            _header_sought=HEADER_REFERRER_POLICY,
            _ignorecase=True
        )
        if value is not None:
            m = RE_HEADER_REFERRER.match(value)
            return m is not None and len(m.groups()) > 0

        return False

    raise deepcheck.exceptions.HeaderNotFoundException(_header=HEADER_REFERRER_POLICY)


def header_x_content_type_is_valid(_headers):
    if _headers is not None and len(_headers) > 0:
        value = header_value(
            _headers=_headers,
            _header_sought=HEADER_CONTENT_OPTIONS,
            _ignorecase=True
        )
        return value.lower() == "nosniff"


def header_x_xss_protection_is_valid(_headers):
    if _headers is not None and len(_headers) > 0:
        value = header_value(
            _headers=_headers,
            _header_sought=HEADER_XSS_PROTECTION,
            _ignorecase=True
        )
        if value is not None:
            m = RE_HEADER_XSS_PROT.match(value)
            return m is not None and len(m.groups()) > 0

        return False

    raise deepcheck.exceptions.HeaderNotFoundException(_header=HEADER_XSS_PROTECTION)


def get_hsts_max_age(_headers):
    if _headers is not None and len(_headers) > 0:
        value = header_value(
            _headers=_headers,
            _header_sought=HEADER_HSTS,
            _ignorecase=True
        )
        if value is not None:
            m = RE_HEADER_HSTS.match(value)
            if m is not None and len(m.groups()) >= 1:
                return m[1]

        return None

    raise deepcheck.exceptions.HeaderNotFoundException(_header=HEADER_HSTS)


def hsts_has_recommended_max_age(_headers):
    exists = header_exists(
        _headers=_headers,
        _header_sought=HEADER_HSTS,
        _ignorecase=True
    )
    if exists:
        max_age = get_hsts_max_age(_headers=_headers)
        if max_age is not None:
            return int(max_age) >= MIN_RECOMMENDED_HSTS_MAX_AGE

        return False
    else:
        raise deepcheck.exceptions.HeaderNotFoundException(HEADER_HSTS)
