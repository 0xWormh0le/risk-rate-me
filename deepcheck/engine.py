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
# Date: 2018-08-18
#
# License
# --------
# This file is subject to the terms and conditions defined in
# file 'LICENSE.txt', which is part of this source code package.
#
# Description:
# -------------
# Core module of the application it is responsible to host functions and
# object analyzing the data and generating reports based on the inputs
# received.
#
# /////////////////////////////////////////////////////////////////////////////
import os
import logging


import deepcheck.tests
import deepcheck.scoring
import deepcheck.common
import deepcheck.exceptions
import deepcheck.https

logger = logging.getLogger(__name__)

STEPS = 9.0

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFINITIONS_FILE = "../res/definitions.json"

DEFAULT_DELAY_TIME = 1.5
DEFAULT_TIMEOUT = 1.9
DEFAULT_RETRIES = 2

EMAIL_SECURITY = "email_security"
WEB_SECURITY = "web_security"
HTTP_HEADERS = "http_headers"
IP_REPUTATION = "ip_reputation"
ALL = "all"

ALL_ASSESSMENTS_TYPES = [
    EMAIL_SECURITY, WEB_SECURITY, HTTP_HEADERS, IP_REPUTATION
]

# Various CSV-related constant for parsing purposes.
CSV_COL_DELIMITER = ","
CSV_WORD_DELIMITER = "/"


def to_array_if_single(_data, _delim):
    if _delim in _data:
        data = [x.strip() for x in list(filter(None, _data.split(_delim)))]
    else:
        data = [_data]

    return data


def get_base_domain(_domain):
    base_domain = deepcheck.common.extract_base_domain(_domain=_domain)
    if base_domain is None or len(base_domain) <= 0:
        raise deepcheck.exceptions.ExtractBaseDomainException(_domain=_domain)
    return base_domain


def get_website_from_domain(_base_domain):
    website = deepcheck.https.find_website_from_domain(
        _domain=_base_domain, _timeout=5.5)
    return website
