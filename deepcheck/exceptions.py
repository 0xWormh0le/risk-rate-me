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
# Contains common exceptions used throughout the module.
#
# /////////////////////////////////////////////////////////////////////////////


class DeepCheckException(Exception):
    def __init__(self, _message):
        super().__init__(_message)


class NoHeadersException(DeepCheckException):
    def __init__(self):
        super().__init__("Object containing headers is none or is empty.")


class HeaderNotFoundException(DeepCheckException):
    def __init__(self, _header):
        super().__init__("Could not find header '{hdr:s}' in the provided set of headers.".format(hdr=_header))


class HeaderInvalidValueException(DeepCheckException):
    def __init__(self, _header, _value):
        super().__init__("Invalid value for header '{hdr:s}': {val:s}".format(hdr=_header, val=str(_value)))


class InvalidResponseException(DeepCheckException):
    def __init__(self, _url, _code):
        super().__init__("Invalid response received from '{url:s}': {code:s}".format(url=_url, code=str(_code)))


class NoCipherDataAvailableException(DeepCheckException):
    def __init__(self):
        super().__init__("No information about accepted cipher suites is available.")


class NoMatchingCertificateFoundException(DeepCheckException):
    def __init__(self):
        super().__init__("No matching certificate found.")


class ThirdPartyApiException(DeepCheckException):
    def __init__(self, _url, _message):
        super().__init__("An exception occured while requesting resources at '{url:s}': {err:s}.".format(
            url=_url,
            err=_message
        ))


class DnsQueryException(DeepCheckException):
    def __init__(self, _domain, _recordtype, _message):
        super().__init__("An exception occured while quering {type:s} records for '{domain:s}': {err:s}.".format(
            domain=_domain,
            type=_recordtype,
            err=_message
        ))


class InvalidSpfRecord(DeepCheckException):
    def __init__(self, _record, _message):
        super().__init__("Invalid SPF record: {record:s}. {err:s}.".format(
            record=_record,
            err=_message
        ))


class InvalidDmarcRecord(DeepCheckException):
    def __init__(self, _record, _message):
        super().__init__("Invalid DMARC record: {record:s}. {err:s}.".format(
            record=_record,
            err=_message
        ))


class InvalidHostOrDomainException(DeepCheckException):
    def __init__(self, _url, _message):
        super().__init__("'{url:s}': {err:s}.".format(
            url=_url,
            err=_message
        ))


class IpResolutionException(DeepCheckException):
    def __init__(self, _host):
        super().__init__("Failed to resolve host '{url:s}' to an IP address.".format(
            url=_host
        ))


class ResponseContainsNoDataException(DeepCheckException):
    def __init__(self, _host):
        super().__init__("Response from '{host:s}' contains no data.".format(
            host=_host
        ))


class NoCertificateFoundException(DeepCheckException):
    def __init__(self, _host, _port):
        super().__init__("No certificate was found on port '{port:s}' on host '{host:s}'.".format(
            host=_host,
            port=str(_port)
        ))


class NoMailAgentDataFoundException(DeepCheckException):
    def __init__(self, _host):
        super().__init__("No email-related ports/data found for '{host:s}'.".format(
            host=_host
        ))


class ExtractBaseDomainException(DeepCheckException):
    def __init__(self, _domain):
        super().__init__("Unable to retrieve base domain for '{domain:s}'.".format(
            domain=_domain
        ))


class RemoteConnectionException(DeepCheckException):
    def __init__(self, _url, _message):
        super().__init__("Failed to connect to '{url:s}': {err:s}.".format(
            url=_url,
            err=_message
        ))


class DefinitionFileNotFound(DeepCheckException):
    def __init__(self, _file):
        super().__init__("Could not open definition file at '{f:s}'.".format(
            f=_file
        ))


class InvalidTestDefinitionException(DeepCheckException):
    def __init__(self, _defname, _message):
        super().__init__("Invalid test definition for '{dname:s}': {err:s}.".format(
            dname=_defname,
            err=_message
        ))


class TestNotFoundException(DeepCheckException):
    def __init__(self, _name, _message):
        super().__init__("Test '{dname:s}' was not found: {err:s}.".format(
            dname=_name,
            err=_message
        ))


class InvalidDatabaseException(DeepCheckException):
    def __init__(self, _host, _port, _dbname, _dbuser):
        super().__init__("Unable to connect to database '{db:s}' at '{host:s}:{port:s}' with user '{user:s}'.".format(
            host=str(_host),
            port=str(_port),
            db=str(_dbname),
            user=str(_dbuser)
        ))


class InvalidParameterException(DeepCheckException):
    def __init__(self, _parameter, _value):
        super().__init__("Received invalid parameter '{param:s}' with value '{val:s}'.".format(
            param=str(_parameter),
            val=str(_value)
        ))
