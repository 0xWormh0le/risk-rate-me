#!/usr/bin/env python
# -*- coding: utf-8 -*-
from django.conf import settings

import dns.exception
import reports.models

import decimal
import datetime
import email.utils as eut
import logging
from urllib.parse import urlparse
from requests import codes
import traceback
import validators

import deepcheck.common
import deepcheck.cookies
import deepcheck.https
import deepcheck.dns
import deepcheck.headers
import deepcheck.email
import deepcheck.ssl
import deepcheck.trust
import deepcheck.exceptions

MX_RECORD_ANALYZE = 2

TEST_RESULT = "result"
TEST_MSG = "message"
TEST_DATA = "data"

MSG_TEST_ERROR_OCCURED = "This test is currently waiting for manual verification from an analyst."
MSG_SPF_NO_POLICY = "Your SPF record does not specify a policy."
MSG_DMARC_INVALID_POLICY = "Your DMARC policy is invalid."
MSG_DMARC_NO_POLICY = "No policy is defined in your DMARC report."
MSG_DMARC_NOT_FOUND = "No DMARC policy was found in your record."
MSG_DMARC_NO_PCT = "The 'pct' tag is not defined in your DMARC record, defaulting to 100."
MSG_DMARC_NO_REPORT_CONFIGURED = "No reporting configuration was found in the DMARC report."
MSG_CERT_WEAK_CIPHERS = "One or more certificates advertises weak/obsolete cipher suites."
MSG_NO_CERT = "No certificate found."
MSG_CERT_CN_INVALID = "The common name of the certificate is invalid."
MSG_CERT_INVALID = "The certificate is self-signed, expired or the common name doesn't match the domain of the site."
MSG_COOKIE_NO_COOKIE = "No cookie found on this website."
MSG_COOKIE_HTTP_ALL_INCLUDE_SECURE = "All cookies sent via HTTP were sent with the 'secure' flag"
MSG_COOKIE_HTTP_SOME_INCLUDE_SECURE = "At least one cookie sent via HTTP was sent with the 'secure' flag"
MSG_COOKIE_HTTP_NO_PREFIX = "No cookie with the '__Secure-' or '__Host-' prefixes was found on via HTTP."
MSG_COOKIE_HTTP_ALL_PREFIX = "All cookies sent via HTTP are prefixed with '__Secure-' or '__Host-'."
MSG_COOKIE_HTTP_SOME_PREFIX = "At least one cookie sent via HTTP was prefixed with '__Secure-' or '__Host-'"
MSG_COOKIE_SOME_SAMESITE_INVALID = "At least one cookie has the 'SameSite' flag with an invalid value."
MSG_COOKIE_NONE_SAMESITE = "No cookie have the 'SameSite' flag set."
MSG_COOKIE_ALL_SAMESITE = "All cookies have the 'SameSite' flag set to 'Strict'."
MSG_COOKIE_SOME_SAMESITE = "One or more cookies do not have the 'SameSite' flag set, or set to 'Lax'."
MSG_COOKIE_NO_SECURE_PREFIX = "No cookie with the '__Secure-' prefix was found."
MSG_COOKIE_NO_HOST_PREFIX = "No cookie with the '__Host-' prefix was found."
MSG_RESOLVE_IP_FAIL = "Could not retrieve the IP address the host"
MSG_NO_DATA_FOR_IP = "No data found on Shodan for '{host:s}'."
MAX_SPF_MECHANISMS = 10
ERROR_COOKIE_DATE_FMT_INVALID = "Date is not using recommended format as per RFC7231, section 7.1.1.1"

logger = logging.getLogger(__name__)


class TestResult(object):
    """
    Possible results for tests.
    """
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILURE = "failed"
    NA = "not_available"
    ERROR = "error"


def test_domain(_domain):
    """
    This is the main testing function, which will accept a valid domain, extract
    the necessary information such as DNS records, websites and other data to perform
    all tests.

    Procedure:
    1. TODO: COmment on overall procedure

    :param _domain:
    :return:
    """
    assert validators.domain(_domain)
    results = {}
    try:
        base_domain = deepcheck.common.extract_base_domain(_domain=_domain)
        if base_domain is None or len(base_domain) <= 0:
            raise deepcheck.exceptions.ExtractBaseDomainException(_domain=_domain)

        # DNS related tests, including SPF, DKIM and DMARC
        results_dns_spf = spf(_domain=base_domain)
        results_dns_dkim = dkim(_domain=base_domain)
        results_dns_dmarc = dmarc(_domain=base_domain)
        results_dnssec = test_dns_dnssec(_domain=base_domain)

        # Email-related tests, including SMTP, IMAP
        results_mail = test_mail(_domain=base_domain)

        # Web-related tests, including HTTPS, web application
        website = deepcheck.https.find_website_from_domain(
            _domain=base_domain, _timeout=5.0)
        results_https = test_https(website)
        results_headers = test_http_headers(_url=website)
        results_cookies = test_cookies(_url=website)

        # Trustworthiness tests
        results_trust_host = test_trust_host(_host=_domain)

        # Collate results into one large dictionary
        results.update(results_dns_spf)
        results.update(results_dns_dkim)
        results.update(results_dns_dmarc)
        results.update(results_dnssec)
        results.update(results_mail)
        results.update(results_https)
        results.update(results_headers)
        results.update(results_cookies)
        results.update(results_trust_host)
        return results
    except Exception as e:
        results["error"] = str(e)
        traceback.print_exc()
        return results


def get_testing_summary(_results):
    assert _results is not None

    stats = {
        "count": 0,
        TestResult.SUCCESS: 0,
        TestResult.PARTIAL: 0,
        TestResult.FAILURE: 0,
        TestResult.NA: 0,
        TestResult.ERROR: 0,
    }

    for _, test_results in _results.items():
        if TEST_RESULT in test_results:
            stats["count"] += 1
            stats[test_results[TEST_RESULT]] += 1
        else:
            for _, subtest_results in test_results.items():
                stats["count"] += 1
                stats[subtest_results[TEST_RESULT]] += 1

    return stats


def create_failed_test_result(_definition: str, _score_modifier=0.0, _message=None, _data=None):
    """
    Generates a app.models.SecurityTest object with a state set
    to TestResult.FAILURE.

    :param _definition: The TestDefinition object related to the test conducted.
    :param _message: Specific result message describing a specific test result.
    :param _score_modifier
    :param _data: Additional reference data generated by the test.
    :return: app.models.SecurityTest object set to TestResult.FAILURE
    """
    return create_test_result(_definition, TestResult.FAILURE, _score_modifier, _message, _data)


def create_success_test_result(_definition: str, _score_modifier=0.0, _message=None, _data=None):
    """
    Generates a app.models.SecurityTest object with a state set
    to TestResult.SUCCESS.

    :param _definition: The TestDefinition object related to the test conducted.
    :param _score_modifier: Variable delta to the score to be applied
    :param _message: Specific result message describing a specific test result.
    :param _data: Additional reference data generated by the test.
    :return: app.models.SecurityTest object set to TestResult.SUCCESS
    """
    return create_test_result(_definition, TestResult.SUCCESS, _score_modifier, _message, _data)


def create_partial_test_result(_definition: str, _score_modifier=0.0, _message=None, _data=None):
    return create_test_result(_definition, TestResult.PARTIAL, _score_modifier, _message, _data)


def create_na_test_result(_definition: str, _score_modifier=0.0, _message=None, _data=None):
    return create_test_result(_definition, TestResult.NA, _score_modifier, _message, _data)


def create_error_test_result(_definition: str, _score_modifier=0.0, _message=None, _data=None):
    return create_test_result(_definition, TestResult.ERROR, _score_modifier, _message, _data)


def create_test_result(_definition: str, test_status, _score_modifier=0.0, _message=None, _data=None):
    assert _definition is not None
    assert test_status in [TestResult.SUCCESS, TestResult.FAILURE, TestResult.PARTIAL, TestResult.ERROR, TestResult.NA]

    _definition = _definition.strip().lower()
    _score_modifier = decimal.Decimal(_score_modifier)
    logger.debug("Creating test result for '{test:s}'.".format(test=_definition))
    definition = reports.models.TestDefinition.objects.get(label=_definition)
    result = reports.models.TestResult()
    result.definition = definition

    if test_status == TestResult.ERROR:
        score = definition.score_error
    elif test_status == TestResult.NA:
        score = definition.score_na
    elif test_status == TestResult.FAILURE:
        score = definition.score_failed
    elif test_status == TestResult.SUCCESS:
        score = definition.score_success
    else:
        score = definition.score_partial

    result.score = definition.weight * score + _score_modifier

    if test_status == TestResult.ERROR:
        result.state = TestResult.ERROR
        result.message = definition.message_error
    elif test_status == TestResult.NA:
        result.state = TestResult.NA
        result.message = definition.message_na
    elif result.score <= definition.failing_score:
        result.state = TestResult.FAILURE
        result.message = definition.message_failed
    elif result.score >= definition.passing_score:
        result.state = TestResult.SUCCESS
        result.message = definition.message_success
    else:
        result.state = TestResult.PARTIAL
        result.message = definition.message_partial

    logger.debug("Test: {test:s}, Score: {score:.2f}".format(test=result.definition.label, score=result.score))

    if _data is not None:
        result.data = _data

    if result is None:
        logger.error("create_test_result generated a None result")

    return result


def spf(_report):
    """
    Performs tests relating to SPF records.

    :param _domain: The domain under test.
    :return:
    """

    # Store the SecurityTest objects.
    results = []
    labels = ["SpfRecordNotDeprecatedCheck",
              "SpfValidLookupCount",
              "SpfSyntaxIsValid",
              "SpfRecordDontUsePtr",
              "SpfVoidLookupsCount",
              "SpfRecordNotTooPermissive",
              "SpfRecordExpectedTerminator"]
    try:
        _domain = _report.domain.domain
        # Get all the records, including old SPF records if any
        spf_records = deepcheck.dns.query_record_for_domain(_domain=_domain, _recordtype="SPF")
        txt_records = deepcheck.dns.query_spf_record(_domain=_domain)
        records = spf_records + txt_records

        if len(records) != 1:
            if len(records) <= 0:
                message = "No SPF record found."
            else:
                message = "More than one (1) SPF record found."

            # If no record is found, then the 'SpfRecordCountTest' fails
            # and all remaining tests are set as "Not Available"
            result = create_failed_test_result("spfrecordcount", _message=message)
            results.append(result)

            for label in labels:
                # Mark all other tests as Not Available
                results.append(create_na_test_result(label))

            return results
        else:
            # If records were found
            result = create_success_test_result("spfrecordcount", _data={"record": records})
            results.append(result)

        # Check to see if we have received more than one SPF records, which
        # means something is misconfigured.
        if len(spf_records) > 0:
            result = create_failed_test_result("spfrecordnotdeprecatedcheck", _data={"record": spf_records})
        else:
            result = create_success_test_result("spfrecordnotdeprecatedcheck")
        results.append(result)

        # Only the first record is considered if more than one
        # is found.
        record = records[0]

        results.append(spf_record_is_valid_syntax(record))
        # Parse the record for the next tests
        parsed = deepcheck.dns.parse_spf_record(_record=record, _domain=_domain)
        # Do the remaining tests
        results.append(spf_record_lookups_count(_domain, parsed))
        results.append(spf_not_using_ptr(parsed))
        results.append(spf_has_limited_void_lookups(parsed))
        results.append(spf_record_is_secure(parsed))
        results.append(spf_records_ends_with_all(record))
        return results
    except dns.exception.Timeout as e:
        logger.error(str(e))
        traceback.print_exc()
        results = []
        for label in labels:
            results.append(create_na_test_result(label.lower()))
        return results
    except Exception as e:
        logger.error(str(e))
        traceback.print_exc()
        return []


def spf_record_is_valid_syntax(_record):
    """
    Verifies if the syntax of a given SPF record is valid.

    :param _record: A non-parsed SPF record. Cannot be None
    :return:
    """
    assert _record is not None
    definition = "spfsyntaxisvalid"

    try:
        # Call the function perfomring the syntax check using the record
        if deepcheck.dns.spf_record_is_valid(_record=_record):
            # If valid, the test succeeds
            return create_success_test_result(definition)
        else:
            # Otherwise the test fails.
            return create_failed_test_result(definition, _data={"record": _record})
    except Exception as e:
        # Record an error for this test.
        return create_error_test_result(definition, _data={"record": _record, "error": str(e)})


def spf_record_lookups_count(_domain, _parsed):
    """
    Validates tje number of lookup mechanisms contained in a SPF record.
    :param _parsed:
    :param _domain:
    :return:
    """
    assert _parsed is not None
    label = "spfvalidlookupcount"
    try:
        # Obtain the number of lookups in the parsed records
        count = deepcheck.dns.count_spf_lookups_for_record(_domain, _parsed, 0, MAX_SPF_MECHANISMS)
        if count >= MAX_SPF_MECHANISMS:
            return create_failed_test_result(label, _data={"lookup_count": count})
        else:
            return create_success_test_result(label, _data={"lookup_count": count})
    except Exception as e:
        return create_error_test_result(label, _data={"error": str(e)})


def spf_not_using_ptr(_parsed):
    """
    Verifies if the SPF record uses PTR mechanism, which is not recommended.
    SpfRecordDontUsePtr
    :param _parsed: A parsed SPF record.
    :return: TestResult.SUCCESS if no PTR mechanism was found in the record.
    """
    assert _parsed is not None
    label = "spfrecorddontuseptr"
    try:
        # Check if one or more PTR mechanisms can be found in the parsed records.
        if deepcheck.dns.SPF_PTR not in _parsed.keys():
            return create_success_test_result(label)
        else:
            return create_failed_test_result(label, _data={"ptr": _parsed[deepcheck.dns.SPF_PTR]})
    except Exception as e:
        return create_error_test_result(label, _data={"error": str(e)})


def spf_has_limited_void_lookups(_parsed):
    """

    The void lookup limit was introduced in RFC 7208 and refers to DNS lookups which either return an empty
    response (NOERROR with no answers) or an NXDOMAIN response. This is a separate count from the 10 DNS
    lookup overall count.

    As described at the end of Section 11.1, there may be cases where it is useful to limit the number of
    "terms" for which DNS queries return either a positive answer (RCODE 0) with an answer count of 0, or a
    "Name Error" (RCODE 3) answer. These are sometimes collectively referred to as "void lookups". SPF
    implementations SHOULD limit "void lookups" to two. An implementation MAY choose to make such a limit
    configurable. In this case, a default of two is RECOMMENDED. Exceeding the limit produces a "permerror" result.
    """
    assert _parsed is not None
    label = "spfvoidlookupscount"
    try:
        lookups = deepcheck.dns.get_spf_record_lookup_mechanisms(_parsed)
        void_lookups = 0

        for m in lookups:
            for lookup in lookups[m]:
                if deepcheck.dns.is_spf_void_lookup(m, lookup["value"]):
                    void_lookups += 1
                    if void_lookups >= 2:
                        result = create_failed_test_result(label, _data={"void_lookups_count": void_lookups})
                        return result

        return create_success_test_result(label, _data={"void_lookups_count": void_lookups})
    except Exception as e:
        return create_error_test_result(label, _data={"error": str(e)})


def spf_record_is_secure(_parsed):
    assert _parsed is not None
    label = "spfrecordnottoopermissive"
    try:
        # Confirm that the ALL mechanism is in the record
        if deepcheck.dns.SPF_ALL in _parsed:
            # Get the qualifier for the ALL mechanism
            q = _parsed[deepcheck.dns.SPF_ALL][0]["qualifier"]
            # Prep the data to return for this test
            data = {"policy": "{:s}all".format(q)}
            # Check if the qualifier is considered sufficiently secure
            if q in [deepcheck.dns.SPF_FAIL, deepcheck.dns.SPF_SOFT_FAIL]:
                return create_success_test_result(label, _data=data)
            else:
                return create_failed_test_result(label, _data=data)
        else:
            return create_failed_test_result(label, _message=MSG_SPF_NO_POLICY)
    except Exception as e:
        return create_error_test_result(label, _data={"error": str(e)})


def spf_records_ends_with_all(_record):
    assert _record is not None
    label = "spfrecordexpectedterminator"
    try:
        # Confirm that the record ends with the ALL mechanism
        if _record.lower().endswith(deepcheck.dns.SPF_ALL):
            return create_success_test_result(label, _data={"record": _record})
        else:
            return create_failed_test_result(label, _data={"record": _record})
    except Exception as e:
        return create_error_test_result(label, _data={"error": str(e)})


def dkim(_report):
    """
    Performs test to assess the DKIM protection mechanism on the
    given target.

    This function only contains one (1) test:
    * dkim_support: Verifies if the domain potentially supports/implements DKIM records.

    :param _domain: The domain to test
    :return: List of app.models.SecurityTest, or empty list if an error occured.
    """
    return [dkim_support(_report.domain.domain)]


def dkim_support(_domain):
    label = "dkimrecordsexisttest"
    try:
        # Checks if DKIM is potentially implemented
        if deepcheck.dns.is_dkim_supported(_domain=_domain):
            return create_success_test_result(label)
        else:
            return create_failed_test_result(label)

    except Exception as e:
        if "All nameservers failed to answer the query _domainkey" in str(e):
            return create_failed_test_result(label)
        else:
            return create_error_test_result(label, _data={"error": str(e)})


def dmarc(_report):
    results = []
    try:
        labels = ["dmarcsyntaxisvalid",
                  "dmarcexternalreportstest",
                  "dmarcpolicyisnotnone",
                  "dmarcpctis100",
                  "dmarcruaisset",
                  "dmarcrufisset"]

        # Get the DMARC record of the domain
        records = deepcheck.dns.query_dmarc_record(_domain=_report.domain.domain)
        label = "dmarcrecordcounttest"
        # Verify if at least one record was retrieved
        data = {"records": len(records)}
        if len(records) != 1:
            results.append(create_failed_test_result(label, _data=data))
            for label in labels:
                # Mark all other tests as Not Available if no record was found
                results.append(create_na_test_result(label.lower(), _data=data))

            return results
        else:
            # If at least one record was found, append them and move on
            # with the testing
            results.append(create_success_test_result(label, _data={"record": records}))

        # If more than one record is found, only the first one is
        # considered.
        record = records[0]
        results.append(dmarc_syntax_is_valid(record))
        parsed = deepcheck.dns.parse_dmarc_record(record)
        results.append(dmarc_policy_is_not_none(parsed))
        results.append(dmarc_pct_is_100(parsed))
        results.append(dmarc_external_reporting_valid(parsed, _report.domain.domain))
        results.append(dmarc_aggregate_reporting_is_set(parsed))
        results.append(dmarc_forensics_reporting_is_set(parsed))
        return results
    except Exception as e:
        logger.error(str(e))
        traceback.print_exc()
        return []


def dmarc_syntax_is_valid(_record):
    """
    DmarcSyntaxIsValid
    :param _record: The DMARC record to validate.
    :return: An app.model.SecurityTest object
    """
    assert _record is not None
    label = "dmarcsyntaxisvalid"
    try:
        if deepcheck.dns.dmarc_record_is_valid(_record):
            return create_success_test_result(label, _data={"record": _record})
        else:
            return create_failed_test_result(label, _data={"record": _record})
    except Exception as e:
        return create_error_test_result(label, _data={"error": str(e)})


def dmarc_policy_is_not_none(_parsed):
    """
    This test assess the strength of the DMARC policy.

    This test will consider the following 4 cases when assessing the strength
    og the DMARC policy:
    1) p=none; No message is filtered/checked. This will result in a TestResult.FAILED
        result;
    2) p=quarantine; Suspicious message are flagged as suspicious. This will result in a
        TestResult.PARTIAL result. <-- We now return a SUCCESS for a quarantine policy
    3) p=reject; All suspicious messages are rejected. This will result in a
        TestResult.SUCCESS result.
    4) No policy or invalid policy will be considered as a TestResult.FAILED.

    :param _parsed: A parsed DMARC record.
    :return: app.models.SecurityTest
    """
    assert _parsed is not None

    label = "dmarcpolicyisnotnone"
    try:
        if deepcheck.dns.DMARC_P in _parsed:
            data = {"policy": _parsed[deepcheck.dns.DMARC_P]}
            if _parsed[deepcheck.dns.DMARC_P] == deepcheck.dns.DMARC_POL_NON:
                return create_failed_test_result(label, _data=data)
            elif _parsed[deepcheck.dns.DMARC_P] in [deepcheck.dns.DMARC_POL_QUA]:
                return create_success_test_result(label, _data=data)
            elif _parsed[deepcheck.dns.DMARC_P] in [deepcheck.dns.DMARC_POL_RJT]:
                return create_success_test_result(label, _data=data)
            else:
                return create_failed_test_result(label, _message=MSG_DMARC_INVALID_POLICY, _data=data)
        else:
            return create_failed_test_result(label, _message=MSG_DMARC_NOT_FOUND)
    except Exception as e:
        return create_error_test_result(label, _data={"error": str(e)})


def dmarc_pct_is_100(_parsed):
    assert _parsed is not None
    label = "dmarcpctis100"
    try:
        if deepcheck.dns.DMARC_PCT in _parsed:
            data = {"pct": _parsed[deepcheck.dns.DMARC_PCT]}
            if _parsed[deepcheck.dns.DMARC_PCT] == "100":
                return create_success_test_result(label, _data=data)
            elif _parsed[deepcheck.dns.DMARC_PCT] == "0":
                return create_failed_test_result(label, _message=MSG_DMARC_NO_POLICY, _data=data)
            else:
                return create_failed_test_result(label, _data=data)
        else:
            return create_success_test_result(label, _message=MSG_DMARC_NO_PCT)
    except Exception as e:
        return create_error_test_result(label, _data={"error": str(e)})


def dmarc_aggregate_reporting_is_set(_parsed):
    assert _parsed is not None
    label = "dmarcruaisset"
    try:
        if deepcheck.dns.DMARC_RUA in _parsed:
            return create_success_test_result(label, _data={
                deepcheck.dns.DMARC_RUA: _parsed[deepcheck.dns.DMARC_RUA]
            })
        else:
            return create_failed_test_result(label)
    except Exception as e:
        return create_error_test_result(label, _data={"error": str(e)})


def dmarc_forensics_reporting_is_set(_parsed):
    assert _parsed is not None
    label = "dmarcrufisset"
    try:
        if deepcheck.dns.DMARC_RUF in _parsed:
            return create_success_test_result(label, _data={
                deepcheck.dns.DMARC_RUF: _parsed[deepcheck.dns.DMARC_RUF]
            })
        else:
            return create_failed_test_result(label)
    except Exception as e:
        return create_error_test_result(label, _data={"error": str(e)})


def dmarc_external_reporting_valid(_parsed, _domain):
    assert _parsed is not None
    label = "dmarcexternalreportstest"
    try:
        if deepcheck.dns.DMARC_RUA not in _parsed and deepcheck.dns.DMARC_RUF not in _parsed:
            return create_failed_test_result(label, _message=MSG_DMARC_NO_REPORT_CONFIGURED)

        raf_results = test_dns_dmarc_external_raf_valid(_parsed, _domain)
        ruf_results = test_dns_dmarc_external_ruf_valid(_parsed, _domain)

        if raf_results[TEST_RESULT] == ruf_results[TEST_RESULT] == TestResult.SUCCESS:
            return create_success_test_result(label)
        else:
            return create_failed_test_result(label, _data={
                "RAF": raf_results[TEST_MSG],
                "RUF": ruf_results[TEST_MSG]
            })
    except Exception as e:
        return create_error_test_result(label, _data={"error": str(e)})


def test_dns_dmarc_external_raf_valid(_parsed, _domain):
    if deepcheck.dns.DMARC_RUA in _parsed:
        report_emails = _parsed[deepcheck.dns.DMARC_RUA].split(",")

        for report_email in report_emails:
            if "@" not in report_email:
                return {
                    TEST_RESULT: TestResult.FAILURE,
                    TEST_MSG: "The email address defined in the 'rua' tag appears invalid: {:s}".format(report_email)
                }
            rua_report_domain = report_email.split("@")[1]
            if rua_report_domain.lower() != _domain:
                # Check if the receiving domain has DMARC setup
                base_report_domain = deepcheck.common.extract_base_domain(rua_report_domain)
                report_record = deepcheck.dns.query_dmarc_record(_domain=base_report_domain)
                if report_record is None or len(report_record) <= 0:
                    return {
                        TEST_RESULT: TestResult.FAILURE,
                        TEST_MSG: "The domain used for reporting does not appear to have a DMARC record."
                    }
    return {
        TEST_RESULT: TestResult.SUCCESS,
        TEST_MSG: "Aggregate reporting is properly setup for your domain."
    }


def test_dns_dmarc_external_ruf_valid(_parsed, _domain):
    if deepcheck.dns.DMARC_RUF in _parsed:
        report_emails = _parsed[deepcheck.dns.DMARC_RUF].split(",")
        for report_email in report_emails:
            if "@" not in report_email:
                return {
                    TEST_RESULT: TestResult.FAILURE,
                    TEST_MSG: "The email address defined in the 'ruf' tag appears invalid: {:s}".format(report_email)
                }
            ruf_report_domain = report_email.split("@")[1]
            if ruf_report_domain.lower() != _domain:
                # Check if the receiving domain has DMARC setup
                base_report_domain = deepcheck.common.extract_base_domain(ruf_report_domain)
                report_record = deepcheck.dns.query_dmarc_record(_domain=base_report_domain)
                if report_record is None or len(report_record) <= 0:
                    return {
                        TEST_RESULT: TestResult.FAILURE,
                        TEST_MSG: "The domain used for reporting does not appear to have a DMARC record."
                    }

    return {
        TEST_RESULT: TestResult.SUCCESS,
        TEST_MSG: "Forensics reporting is properly setup for your domain."
    }


def test_dns_dnssec(_report):
    results = []
    try:
        # Verify if DNSKEY/RRSIG records exists
        result = dnssec_records_exists(_report.domain.domain)
        results.append(result)
        # If not, then the validation test is not available
        if result.state == TestResult.FAILURE:
            results.append(create_na_test_result("dnssecrecordisvalid"))
        else:
            results.append(dnssec_record_is_valid(_report.domain.domain))

        return results
    except Exception as e:
        logger.error(str(e))
        return []


def dnssec_records_exists(_domain):
    assert validators.domain(_domain)
    label = "dnskeyandrrsigrecordsexists"
    try:
        dnskey = deepcheck.dns.query_dnskey_records(_domain)
        if len(dnskey) > 0:
            return create_success_test_result(label, _data={"dnskey": dnskey})
        else:
            return create_failed_test_result(label)
    except Exception as e:
        return create_error_test_result(label, _data={"error": str(e)})


def dnssec_record_is_valid(_domain):
    assert validators.domain(_domain)
    label = "dnssecrecordisvalid"
    try:
        if deepcheck.dns.dnssec_is_valid(_domain, _timeout=5.5):
            return create_success_test_result(label)
        else:
            return create_failed_test_result(label)
    except Exception as e:
        return create_error_test_result(label, _data={"error": str(e)})


def test_starttls_is_supported(_record, _data):
    assert _data is not None
    label = "smtpstarttlsisenabled"
    data = {"host": _record}
    count = 0
    try:
        for port, info in _data.items():
            if "starttls" in info:
                if info["starttls"] == "not offered":
                    count += 1

        if count <= 0:
            return create_success_test_result(label, _data=data)
        elif count >= len(_data):
            return create_failed_test_result(label, _data=data)
        else:
            return create_partial_test_result(label, _data=data)
    except Exception as e:
        logger.error(str(e))
        return create_error_test_result(label, _data=_data)


def test_starttls_certificate_common_name(_record, _data):
    assert _data is not None
    label = "smtpcertificatecn"
    data = {"host": _record}
    count = 0
    try:
        for port, info in _data.items():
            if "cert_subjectaltname" in info and _record in info["cert_subjectaltname"]:
                count += 1
            elif "cert_commonname" in info and _record in info["cert_commonname"]:
                count += 1

        if count <= 0:
            return create_failed_test_result(label, _data=data)
        elif count >= len(_data):
            return create_success_test_result(label, _data=data)
        else:
            return create_partial_test_result(label, _data=data)
    except Exception as e:
        logger.error(str(e))
        return create_error_test_result(label, _data=_data)


def test_starttls_tls_protocol(_record, _data):
    assert _data is not None
    label = "smtpprotocols"
    data = {"host": _record}
    count = 0
    try:
        for port, info in _data.items():
            if "sslv3" in info and info["sslv3"] == "offered":
                count += 1
            elif "sslv2" in info and info["sslv2"] == "offered":
                count += 1

        if count <= 0:
            return create_success_test_result(label, _data=data)
        elif count >= len(_data):
            return create_failed_test_result(label, _data=data)
        else:
            return create_partial_test_result(label, _data=data)
    except Exception as e:
        logger.error(str(e))
        return create_error_test_result(label, _data=_data)


def test_starttls_tls_ciphers(_record, _data):
    assert _data is not None
    label = "smtpciphers"
    data = {"host": _record}
    strong_only = 0
    try:
        for port, info in _data.items():
            weak_count = 0
            strong_count = 0
            if _contains_weak_ciphers(info):
                weak_count += 1
            elif "cipherlist_strong" in info and info["cipherlist_strong"] == "offered":
                strong_count += 1

            if weak_count <= 0 and strong_count >= 1:
                strong_only += 1

        if strong_only >= len(_data):
            return create_success_test_result(label, _data=data)
        elif strong_only <= 0:
            return create_failed_test_result(label, _data=data)
        else:
            return create_partial_test_result(label, _data=data)
    except Exception as e:
        logger.error(str(e))
        return create_error_test_result(label, _data=_data)


def _contains_weak_ciphers(info):
    if "cipherlist_null" in info and info["cipherlist_null"] == "offered":
        return True
    elif "cipherlist_anull" in info and info["cipherlist_anull"] == "offered":
        return True
    elif "cipherlist_anull" in info and info["cipherlist_anull"] == "offered":
        return True
    elif "cipherlist_export" in info and info["cipherlist_export"] == "offered":
        return True
    elif "cipherlist_low" in info and info["cipherlist_low"] == "offered":
        return True
    elif "cipherlist_3des_idea" in info and info["cipherlist_3des_idea"] == "offered":
        return True

    return False


def test_ma_closed_relay(_record, _port, _starttls=False):
    label = "smtpisclosedrelay"
    try:
        can_send = deepcheck.email.try_send_unauthenticated_email_via(
            _server=_record,
            _port=_port,
            _use_starttls=_starttls
        )

        if can_send:
            result = create_failed_test_result(label, _data={"host": _record, "port": _port})
            return result
    except Exception as e:
        # There's a high likelihood the connection fails because the mail server
        # is protected/filtered. If the connection fails, we assume that the server
        # is closed. There's very few open-relays nowadays
        logger.error(str(e))

    return create_success_test_result(label)


def test_mail(_report):  # noqa C901
    checktls_user = settings.API_CHECKTLS_USER
    checktls_pass = settings.API_CHECKTLS_PASSWORD

    agents = deepcheck.common.query_mail_data_from_checktls(_report.domain.domain, checktls_user, checktls_pass)

    results = []

    if "mx" not in agents or len(agents["mx"]) <= 0:
        if "mx" not in agents:
            # If "mx" is not in the response, then something went wrong.
            results.append(create_na_test_result("smtpserverfoundtest"))
        else:
            # If no mail record was found
            results.append(create_failed_test_result("smtpserverfoundtest"))
        results.append(create_na_test_result("smtpstarttlsisenabled"))
        results.append(create_na_test_result("smtpcertificatecn"))
        results.append(create_na_test_result("smtpprotocols"))
        results.append(create_na_test_result("smtpciphers"))
        results.append(create_na_test_result("smtpisclosedrelay"))
        return results
    else:
        servers = list(agents["mx"].keys())
        smtpserverfoundtest = create_success_test_result("smtpserverfoundtest", _data=servers)

    if int(agents["overall_tls"]) >= int(agents["overall_cert"]) >= int(agents["overall_secure"]) >= 100:
        # If all scores are over 100, then we already know all tests
        # were successful. Move on with the tests
        data = []
        for server in servers:
            data.append({"host": server, "data": TestResult.SUCCESS})
        results.append(create_success_test_result("smtpserverfoundtest", _data=data))
        results.append(create_success_test_result("smtpstarttlsisenabled", _data=data))
        results.append(create_success_test_result("smtpcertificatecn", _data=data))
        results.append(create_success_test_result("smtpprotocols", _data=data))
        results.append(create_success_test_result("smtpciphers", _data=data))
        results.append(create_success_test_result("smtpisclosedrelay", _data=data))
        return results

    # Otherwise, we need to pinpoint issues for remediation,
    # so we go thru each MX record in the data.
    for mx, info in agents["mx"].items():
        data = {
            "host": mx
        }

        # Since the Closed-relay test does not depend on encryption
        # we do this test first
        results.append(test_ma_closed_relay(mx, _port=int(info["port"])))

        # If no SSL version is found, then we have no STARTTLS enabled,
        # we fail the appropriate test and skip the remaining
        if info["ssl_version"] is None or len(info["ssl_version"]) <= 0:
            results.append(create_failed_test_result("smtpstarttlsisenabled",
                                                     _data={"host": mx, "data": TestResult.FAILURE}))
            results.append(create_na_test_result("smtpcertificatecn", _data={"host": mx, "data": TestResult.NA}))
            results.append(create_na_test_result("smtpprotocols", _data={"host": mx, "data": TestResult.NA}))
            results.append(create_na_test_result("smtpciphers", _data={"host": mx, "data": TestResult.NA}))
            break
        else:
            results.append(create_success_test_result("smtpstarttlsisenabled",
                                                      _data={"host": mx, "data": TestResult.SUCCESS}))

        if float(info["cert_score"]) <= 0.0:
            # If the score for certification is already 0, then we
            # know the certificate does not validate:
            results.append(create_failed_test_result("smtpcertificatecn",
                                                     _data={
                                                         "host": mx,
                                                         "data": TestResult.FAILURE,
                                                     }))
        elif float(info["cert_score"]) >= 1.0:
            # Similarly, a score above 1 is a known-success;
            results.append(create_success_test_result("smtpcertificatecn", _data={
                "host": mx,
                "data": TestResult.SUCCESS,
            }))
        else:
            results.append(create_partial_test_result("smtpcertificatecn", _data={
                "host": mx,
                "data": TestResult.PARTIAL,
            }))

        # checktls only verifies the highest TLS version supported
        # and omits checks for deprecated version. As such, here
        # we first check if the highest version supported is deprecated
        # If so, then the smtpprotocols fail. Otherwise, we need to
        # ensure that nothing lower than TLS1.0 is supported.
        if info["ssl_deprecated"] and info["ssl_version"] in ["sslv2", "sslv3"]:
            results.append(create_failed_test_result("smtpprotocols",
                                                     _data={
                                                         "host": mx,
                                                         "data": TestResult.FAILURE,
                                                     }))
        else:
            try:
                # check for SSLv2 and SSLv3 connections
                accepted, cert = deepcheck.ssl.test_ssl_protocols2(mx,
                                                                   int(info["port"]),
                                                                   deepcheck.ssl.WEAK_SUITES)
                if len(accepted) > 0:
                    results.append(create_failed_test_result("smtpprotocols",
                                                             _data={
                                                                 "host": mx,
                                                                 "data": TestResult.FAILURE
                                                             }))
                else:
                    results.append(create_success_test_result("smtpprotocols",
                                                              _data={
                                                                  "host": mx,
                                                                  "data": TestResult.SUCCESS
                                                              }))
            except Exception as e:
                logger.error(str(e))
                results.append(create_na_test_result("smtpprotocols",
                                                     _data={
                                                         "host": mx,
                                                         "data": TestResult.ERROR
                                                     }))

        # Any cipher using 3DES or RC4 is deprecated
        if "DES" in info["ssl_cipher"] or "-RC4" in info["ssl_cipher"] or "NULL" in info["ssl_cipher"]:
            results.append(create_failed_test_result("smtpciphers", _data={"host": mx, "ciphers": info["cipher"]}))
        else:
            try:
                # check for weak ciphers
                accepted, cert = deepcheck.ssl.test_ssl_ciphers(mx,
                                                                int(info["port"]),
                                                                deepcheck.ssl.WEAK_CIPHERS)
                if accepted:
                    results.append(create_failed_test_result("smtpciphers",
                                                             _data={"host": mx, "data": TestResult.FAILURE}))
                else:
                    results.append(create_success_test_result("smtpciphers",
                                                              _data={"host": mx, "data": TestResult.SUCCESS}))
            except Exception as e:
                logger.error(str(e))
                results.append(create_na_test_result("smtpciphers",
                                                     _data={"host": mx, "data": TestResult.NA}))

    results = _merge_email_servers_results(results)
    results.append(smtpserverfoundtest)
    return results


def test_https(_website):
    results = []
    try:
        if _website is not None:
            result = https_exists(_website)
            results.append(result)

            if result.state in [TestResult.SUCCESS, TestResult.PARTIAL]:
                results.append(https_certificate_is_valid(_website))
                results.append(https_certificate_weak_ciphers(_website))
                results.append(https_redirection(_website))
                return results
        else:
            results.append(create_na_test_result("httpsenabledtest"))

        # If no website was found, then the HTTPS test will be set
        # as not available
        results.append(create_na_test_result("httpscertificateisvalid"))
        results.append(create_na_test_result("httpscertificatecipherstrength"))
        results.append(create_na_test_result("automatichttpsredirection"))
        return results
    except Exception as e:
        logger.error(str(e))
        traceback.print_exc()
        # If an exception occur, the set of test will be flagged as
        # error.
        results.append(create_error_test_result("httpsenabledtest"))
        results.append(create_error_test_result("httpscertificateisvalid"))
        results.append(create_error_test_result("httpscertificatecipherstrength"))
        results.append(create_error_test_result("automatichttpsredirection"))
        return results


def https_exists(_website):
    assert _website is not None
    # Get the definition for this test
    label = "httpsenabledtest"
    try:
        # Parse the website provided and append the HTTPS scheme
        parsed = urlparse(_website)
        swebsite = "https://{:s}".format(parsed.netloc)
        # Attempt to contact the https version of the website
        response = deepcheck.https.is_responding(
            _url=swebsite,
            _timeout=5.5
        )

        if response is None:
            return create_failed_test_result(label, _data={"website": swebsite})
        elif response in [codes.ok, codes.found, codes.moved, codes.created, codes.no_content]:
            return create_success_test_result(label, _data={"website": swebsite})
        else:
            return create_partial_test_result(label, _data={"website": swebsite, "status_code": response})
    except Exception as e:
        return create_error_test_result(label, _data={"error": str(e)})


def https_redirection(_website):
    assert _website is not None
    label = "automatichttpsredirection"
    try:
        # Get the unsecure version of the websitw
        url = urlparse(_website)
        http_url = "http://{nl:s}".format(nl=url.netloc)
        # Connect to the unsecure website and see if we land on the https version
        # after redirection.
        is_redirected = deepcheck.https.is_redirected_to_https(
            _url=http_url,
            _timeout=settings.NETWORK_TIMEOUT
        )

        if is_redirected:
            return create_success_test_result(label, _data={"website": http_url})
        else:
            return create_failed_test_result(label, _data={"website": http_url})
    except Exception as e:
        return create_error_test_result(label, _data={"error": str(e)})


def https_certificate_is_valid(_website, _port=443):
    assert _website is not None
    label = "httpscertificateisvalid"
    import ssl
    try:
        # Obtain the certificate by establishing a SSL
        # connection
        url = urlparse(_website)
        base_domain = deepcheck.common.extract_base_domain(_domain=url.netloc)
        connected, certificate = deepcheck.ssl.get_ssl_certificate(url.netloc, _port)
        is_self_signed = (certificate["issuer"] == certificate["subject"])
        expiration = datetime.datetime.strptime(certificate["notAfter"], "%b %d %H:%M:%S %Y %Z")
        is_expired = (expiration <= datetime.datetime.utcnow())
        subject_attrs = certificate["subject"]

        # Get the common name of the issuer of the certificate
        cn = None
        for attr in subject_attrs:
            if attr[0][0] == "commonName":
                cn = attr[0][1]
                break

        if cn is None or len(cn.strip()) <= 0:
            result = create_failed_test_result(label, _message=MSG_CERT_CN_INVALID, _data=str(certificate))
            return result

        cn_base_domain = deepcheck.common.extract_base_domain(cn)
        common_name_invalid = (cn_base_domain not in [base_domain, "*.{:s}".format(base_domain)])

        if is_self_signed or is_expired or common_name_invalid:
            return create_failed_test_result(label,
                                             _message=MSG_CERT_INVALID,
                                             _data={
                                                 "self-signed": is_self_signed,
                                                 "is-expired": is_expired,
                                                 "invalid-cn": common_name_invalid
                                             })
        else:
            return create_success_test_result(label)
    except ssl.CertificateError as e:
        logger.error(str(e))
        return create_failed_test_result(label,
                                         _message=MSG_CERT_INVALID,
                                         _data={
                                             "issue": str(e)
                                         })
    except Exception as e:
        return create_error_test_result(label, _data={"error": str(e)})


def https_certificate_weak_ciphers(_website):
    assert _website is not None
    label = "httpscertificatecipherstrength"
    try:
        url = urlparse(_website)
        ssl_methods, _ = deepcheck.ssl.test_ssl_protocols2(url.netloc, 443, deepcheck.ssl.WEAK_SUITES)
        if len(ssl_methods) <= 0:
            return create_success_test_result(label)
        else:
            return create_failed_test_result(label, _data={"ciphers": ssl_methods})
    except Exception as e:
        return create_error_test_result(label, _data={"error": str(e)})


def test_http_headers(_url):
    results = []
    try:
        if _url is not None:
            # The secure and unsecure versions of a single
            # website may send different headers, such as the HSTS. As such
            # we attempt to conntect to both and read al headers.
            assert validators.url(_url)
            parsed = urlparse(_url)
            http_url = "http://{:s}".format(parsed.netloc)
            https_url = "https://{:s}".format(parsed.netloc)
            http_headers = {}
            https_headers = {}

            try:
                http_headers = deepcheck.headers.get_headers(_url=http_url,
                                                             _timeout=5.5)
            except Exception as e:
                logger.error(str(e))

            try:
                https_headers = deepcheck.headers.get_headers(_url=https_url,
                                                              _timeout=5.5)
            except Exception as e:
                logger.error(str(e))

            headers = http_headers
            headers.update(https_headers)

            if len(headers) <= 0:
                results = [
                    results.append(create_failed_test_result("hstsenabledtest")),
                    results.append(create_failed_test_result("XFrameOptionHeaderTest")),
                    results.append(create_failed_test_result("XXssProtectionHeaderTest")),
                    results.append(create_failed_test_result("XContentTypeOptionsHeaderTest")),
                    results.append(create_failed_test_result("ContentSecurityHeaderTest")),
                    results.append(create_failed_test_result("ReferrerPolicyHeaderTest")),
                    results.append(create_failed_test_result("FeaturePolicyHeaderTest")),
                    results.append(create_success_test_result("XPoweredByHeaderTest")),
                    results.append(create_success_test_result("ServerHeaderTest")),
                ]
                return results

            results.append(header(_test="hstsenabledtest",
                                  _headers=headers,
                                  _header=deepcheck.headers.HEADER_HSTS,
                                  _validator_func=deepcheck.headers.hsts_has_recommended_max_age))
            results.append(header(_test="XFrameOptionHeaderTest",
                                  _headers=headers,
                                  _header=deepcheck.headers.HEADER_FRAME_OPTIONS,
                                  _validator_func=deepcheck.headers.header_x_frame_option_is_valid))
            results.append(header(_test="XXssProtectionHeaderTest",
                                  _headers=headers,
                                  _header=deepcheck.headers.HEADER_XSS_PROTECTION,
                                  _validator_func=deepcheck.headers.header_x_xss_protection_is_valid))
            results.append(header(_test="XContentTypeOptionsHeaderTest",
                                  _headers=headers,
                                  _header=deepcheck.headers.HEADER_CONTENT_OPTIONS,
                                  _validator_func=deepcheck.headers.header_x_content_type_is_valid))
            results.append(header(_test="ContentSecurityHeaderTest",
                                  _headers=headers,
                                  _header=deepcheck.headers.HEADER_CONTENT_SEC_POL,
                                  _validator_func=deepcheck.headers.header_x_content_sec_pol_is_valid))
            results.append(header(_test="ReferrerPolicyHeaderTest",
                                  _headers=headers,
                                  _header=deepcheck.headers.HEADER_REFERRER_POLICY,
                                  _validator_func=deepcheck.headers.header_referrer_policy_is_valid))
            results.append(header_server(headers))
            results.append(header_x_powered_by(headers))
            results.append(header(_test="FeaturePolicyHeaderTest",
                                  _headers=headers,
                                  _header=deepcheck.headers.HEADER_FEATURE_POLICY,
                                  _validator_func=deepcheck.headers.header_feature_policy_is_valid))
            return results
    except Exception as e:
        logger.error(str(e))
        traceback.print_exc()
        return [
            results.append(create_error_test_result("hstsenabledtest")),
            results.append(create_error_test_result("XFrameOptionHeaderTest")),
            results.append(create_error_test_result("XXssProtectionHeaderTest")),
            results.append(create_error_test_result("XContentTypeOptionsHeaderTest")),
            results.append(create_error_test_result("ContentSecurityHeaderTest")),
            results.append(create_error_test_result("ReferrerPolicyHeaderTest")),
            results.append(create_error_test_result("FeaturePolicyHeaderTest")),
        ]


def header(_test, _headers, _header, _validator_func):
    assert _test is not None and len(_test.strip()) > 0
    assert _headers is not None
    assert _header is not None and len(_header.strip()) > 0
    assert _validator_func is not None

    # Get the definition for this test
    label = _test.lower()
    try:
        # Verify if the header exists in the headers map
        if deepcheck.headers.header_exists(_headers=_headers, _header_sought=_header):
            # Define the data to include in the results
            test_data = {
                "header": _header,
                "value": deepcheck.headers.header_value(_headers, _header)
            }
            # Check if the value of the header is valid
            if _validator_func(_headers):
                # The value is valid
                return create_success_test_result(label, _data=test_data)
            else:
                # The value is invalid
                return create_partial_test_result(label, _data=test_data)
        else:
            # The header is not found
            return create_failed_test_result(label)
    except Exception as e:
        logger.error(str(e))
        return create_error_test_result(label, _data={"error": str(e)})


def header_server(_headers):
    assert _headers is not None
    label = "serverheadertest"
    header = "Server"

    try:
        # Verify if the header exists in the headers map
        if deepcheck.headers.header_exists(_headers=_headers, _header_sought=header):
            # Define the data to include in the results
            test_data = {
                "header": header,
                "value": deepcheck.headers.header_value(_headers, header)
            }
            # Check if the value of the header is valid
            if deepcheck.headers.header_server_contains_version_info(_headers):
                # The server header contains product + version information
                return create_failed_test_result(label, _data=test_data)
            else:
                # The server is present and may contain product information
                return create_partial_test_result(label, _data=test_data)
        else:
            # The header is not found
            return create_success_test_result(label)
    except Exception as e:
        return create_error_test_result(label, _data={"error": str(e)})


def header_x_powered_by(_headers):
    """
    This test verifies if the X-Powered-By header is returned by the target
    server.

    This function will test if the header is present in the list of headers
    and if it contains a product name and a version number.

    - If the header is present, contains product information AND version
    information, then the test fails.
    - If the header is present, contains product information but does NOT
    contain version information, then the test partially succeeds
    - The if the header is absent, hte test succeeds.

    :param _headers: A dictionary of headers returned by the server.
    :return: app.models.SecurityTest()
    """
    assert _headers is not None
    label = "xpoweredbyheadertest"
    header = "X-Powered-By"

    try:
        # Verify if the header exists in the headers map
        if deepcheck.headers.header_exists(_headers=_headers, _header_sought=header):
            # Define the data to include in the results
            test_data = {
                "header": header,
                "value": deepcheck.headers.header_value(_headers, header)
            }
            # Check if the value of the header contains what seems to be a
            # version number.
            if deepcheck.headers.header_x_powered_by_contains_version_info(_headers):
                # The server header contains product + version information
                return create_failed_test_result(label, _data=test_data)
            else:
                # The server is present and may contain product information
                return create_partial_test_result(label, _data=test_data)
        else:
            # The header is not found
            return create_success_test_result(label)
    except Exception as e:
        logger.error(str(e))
        return create_error_test_result(label, _data={"error": str(e)})


def test_trust_host(_report):
    results = []
    try:
        _host = _report.domain.domain
        logger.debug("{host:s}: Verifying if listed in IP blocklist.".format(host=_host))
        results.append(trust_ip_blocklist(_host))

        logger.debug("{host:s}: Verifying host reputation.".format(host=_host))
        results.append(trust_host_reputation(_host))

        logger.debug("{host:s}: Verifying related CVEs.".format(host=_host))
        results.append(trust_cve_associated(_host))

        logger.debug("{host:s}: Verifying open ports.".format(host=_host))
        results.append(trust_open_ports(_host))

        logger.debug("{host:s}: Looking for data leaks.".format(host=_host))
        results.append(trust_email_leaks(_host))

        return results
    except Exception as e:
        logger.error(str(e))
        traceback.print_exc()
        return [
            create_error_test_result("ipblocklist"),
            create_error_test_result("hostreputation"),
            create_error_test_result("hosthaspotentialvulnerabilities"),
            create_error_test_result("hostopenports"),
            create_error_test_result("emailleaks"),
        ]


def trust_ip_blocklist(_host):
    assert _host is not None
    label = "ipblocklist"
    try:
        ip = deepcheck.common.resolve_host_to_ip_address(
            _hostname=_host,
            _timeout=settings.NETWORK_TIMEOUT
        )

        data = deepcheck.trust.query_ip_blocklist_from_neutrino(
            _ip=ip,
            _userid=settings.API_NEUTRINO_USER,
            _key=settings.API_NEUTRINO_KEY,
            _timeout=settings.NETWORK_TIMEOUT
        )

        if data is None or len(data) <= 0:
            logger.error("No data found for '{ip:s}'.".format(ip=str(ip)))
            return create_error_test_result(label, _data={"error": "No data found for '{ip:s}'.".format(ip=str(ip))})

        if data["is-listed"]:
            return create_failed_test_result(label, _data=data)
        else:
            return create_success_test_result(label, _data=data)
    except Exception as e:
        return create_error_test_result(label, _data={"error": str(e)})


def trust_host_reputation(_host):
    assert _host is not None
    # Get the definition for this test
    label = "hostreputation"
    try:
        data = deepcheck.trust.query_host_reputation_from_neutrino(
            _host=_host,
            _userid=settings.API_NEUTRINO_USER,
            _key=settings.API_NEUTRINO_KEY,
            _timeout=settings.NETWORK_TIMEOUT
        )

        if data is None or len(data) <= 0:
            return create_na_test_result(label,
                                         _data={"error": MSG_NO_DATA_FOR_IP.format(host=str(_host))})

        if data["is-listed"]:
            return create_failed_test_result(label, _data=data)
        else:
            return create_success_test_result(label, _data=data)
    except Exception as e:
        return create_error_test_result(label, _data={"error": str(e)})


def trust_cve_associated(_host):
    assert _host is not None
    label = "hosthaspotentialvulnerabilities"

    try:
        record_data = deepcheck.common.query_host_on_shodan(
            _host=_host,
            _key=settings.API_SHODAN_KEY,
            _timeout=settings.NETWORK_TIMEOUT
        )

        if record_data and len(record_data) > 0 and "vulns" in record_data:
            host_cves = record_data["vulns"]
            if len(host_cves) > 0:
                # Additional penalty is added based on the number of CVE
                # potentially exposed.
                score_modifier = len(host_cves) * -0.15
                if (1.0 + score_modifier) <= 0:
                    return create_failed_test_result(label, _score_modifier=-1.0, _data=host_cves)
                else:
                    return create_partial_test_result(label, _score_modifier=score_modifier, _data=host_cves)

        return create_success_test_result(label)
    except Exception as e:
        if "404" in str(e):
            return create_na_test_result(label)
        else:
            return create_error_test_result(label, _data={"error": str(e)})


def trust_open_ports(_host):
    assert _host is not None
    label = "hostopenports"
    try:
        record_data = deepcheck.common.query_host_on_shodan(
            _host=_host,
            _key=settings.API_SHODAN_KEY,
            _timeout=settings.NETWORK_TIMEOUT
        )

        if record_data and len(record_data) > 0 and "ports" in record_data:
            if len(record_data["ports"]) > 3:
                # We expect most online websites to have 22, 80 and 443 open
                # Maybe another port for FTP/SFTP
                # Beyond that, additional ports might be superfluous (i.e cPanel, database)
                score_modifier = (len(record_data["ports"]) - 3) * -0.15
                if (1.0 + score_modifier) <= 0.0:
                    return create_failed_test_result(label, _score_modifier=-1.0, _data=record_data["ports"])
                else:
                    return create_partial_test_result(label, _score_modifier=score_modifier, _data=record_data["ports"])
            else:
                return create_success_test_result(label, _score_modifier=0.0, _data=record_data["ports"])
        else:
            return create_success_test_result(label)

    except Exception as e:
        return create_error_test_result(label, _data={"error": str(e)})


def trust_email_leaks(_domain):
    """
    {"total":0,"groups":[],"query":"deepcode.ca"}
    :param _domain:
    :return:
    """
    assert validators.domain(_domain)
    label = "emailleaks"
    try:
        leak_data = deepcheck.trust.query_emails_leak_from_be(
            _domain=_domain,
            _key=settings.API_BINARYEDGE_KEY,
            _timeout=settings.NETWORK_TIMEOUT
        )

        if "total" in leak_data and leak_data["total"] <= 0:
            return create_success_test_result(label, _data=leak_data)
        else:
            # We add a penalty based on the number of public leaks
            # the domain was found in.
            score_modifier = leak_data["total"] * -0.1
            if (1.0 - score_modifier) <= 0:
                return create_failed_test_result(label, _score_modifier=-1.0, _data=leak_data)
            else:
                return create_partial_test_result(label, _score_modifier=score_modifier, _data=leak_data)

    except Exception as e:
        return create_error_test_result(label, _data={"error": str(e)})


def test_cookies(_url):
    """
    Performs a set of test against the HTTP cookies provided by the websites
    hosted on the URL provided.

    :param _url:
    :return:
    """
    results = []
    try:
        if _url is not None:
            assert validators.url(_url)
            parsed = urlparse(_url)
            # Tests conducted will be different based on cookies sent
            # via the unsecure and secure versions of the website.
            http_url = "http://{:s}".format(parsed.netloc)
            https_url = "https://{:s}".format(parsed.netloc)
            http_cookies = deepcheck.cookies.get_cookies_via_requests(_url=http_url,
                                                                      _redirect=False,
                                                                      _timeout=settings.NETWORK_TIMEOUT)
            https_cookies = deepcheck.cookies.get_cookies_via_requests(_url=https_url,
                                                                       _redirect=True,
                                                                       _timeout=settings.NETWORK_TIMEOUT)

            # First verify if we have receive any cookie
            nb_cookies = len(http_cookies) + len(https_cookies)

            # If no cookie was found, then no more test is needed
            # No cookies also mean that there is no unsecure cookies and therefore,
            # the http_cookies category should be successful.
            logger.debug("Total number of cookies sent by '{host:s}': {cc:d}".format(host=_url, cc=nb_cookies))
            if nb_cookies <= 0:
                results.append(create_success_test_result("nocookietest", _score_modifier=0.0))
                # Make sure the other tests are set to N/A to avoid errors in the scoring
                results.append(create_na_test_result(_definition="cookiesyntaxisvalid"))
                results.append(create_na_test_result(_definition="httpcookienoprefix"))
                results.append(create_na_test_result(_definition="HttpCookieHttpOnly".lower()))
                results.append(create_na_test_result(_definition="HttpCookieIsNotSecure".lower()))
                results.append(create_na_test_result(_definition="CookieSameSite".lower()))
                results.append(create_na_test_result(_definition="HttpsCookieIsSecure".lower()))
                results.append(create_na_test_result(_definition="HttpsCookieHostPrefixIsValid".lower()))
                results.append(create_na_test_result(_definition="HttpsCookieSecurePrefixIsValid".lower()))
                return results
            else:
                # Having cookies is not an security issue per se, but
                # having unsecure/misconfigured cookies is. Hence this test
                # will always be successful, but not having cookies does no require
                # additional testing.
                results.append(create_success_test_result("nocookietest",
                                                          _message="The website is sending cookies",
                                                          _data={"cookie_count": nb_cookies}))

            # The syntax of all cookies, both from the non-secure and secure
            # websites are verified.
            result_syntax_u = cookies_valid_syntax(http_cookies)
            result_syntax_s = cookies_valid_syntax(https_cookies)
            results.append(_combine_results([result_syntax_u, result_syntax_s]))
            result_httponly_u = cookies_are_httponly(http_cookies)
            result_httponly_s = cookies_are_httponly(https_cookies)
            results.append(_combine_results([result_httponly_u, result_httponly_s]))

            result_samesite_u = cookies_samesite_flag(http_cookies)
            result_samesite_s = cookies_samesite_flag(https_cookies)
            results.append(_combine_results([result_samesite_u, result_samesite_s]))

            if len(http_cookies) > 0:
                results.append(http_cookies_not_include_secure(_cookies=http_cookies))
            else:
                results.append(create_na_test_result(_definition="HttpCookieIsNotSecure".lower()))

            if len(https_cookies) > 0:
                results.append(http_cookies_no_prefix(_cookies=http_cookies))
                results.append(https_cookies_include_secure(_cookies=https_cookies))
                results.append(https_cookies_host_prefix_valid(_cookies=https_cookies))
                results.append(https_cookies_secure_prefix_valid(_cookies=https_cookies))
            else:
                results.append(create_na_test_result(_definition="httpcookiehttponly"))
                results.append(create_na_test_result(_definition="HttpsCookieIsSecure".lower()))
                results.append(create_na_test_result(_definition="HttpsCookieHostPrefixIsValid".lower()))
                results.append(create_na_test_result(_definition="HttpsCookieSecurePrefixIsValid".lower()))

        return results
    except Exception as e:
        traceback.print_exc()
        logger.error(str(e))
        results.append(create_na_test_result(_definition="cookiesyntaxisvalid"))
        results.append(create_na_test_result(_definition="httpcookienoprefix"))
        results.append(create_na_test_result(_definition="httpcookiehttponly"))
        results.append(create_na_test_result(_definition="HttpCookieIsNotSecure".lower()))
        results.append(create_na_test_result(_definition="CookieSameSite".lower()))
        results.append(create_na_test_result(_definition="HttpsCookieIsSecure".lower()))
        results.append(create_na_test_result(_definition="HttpsCookieHostPrefixIsValid".lower()))
        results.append(create_na_test_result(_definition="HttpsCookieSecurePrefixIsValid".lower()))
        return results


def cookies_valid_syntax(_cookies):
    assert _cookies is not None
    label = "cookiesyntaxisvalid"

    try:
        # Skip this test if no cookie was provided.
        if len(_cookies) <= 0:
            return create_na_test_result(label, _message=MSG_COOKIE_NO_COOKIE)

        invalid_cookies = []

        # Iterate all cookies in the dictionary
        for name, attr in _cookies.items():
            invalid_cookie = _validate_cookie_flags(_cookies, name, attr)
            if invalid_cookie is not None:
                invalid_cookies.append(invalid_cookie)

        if len(invalid_cookies) <= 0:
            return create_success_test_result(label)
        elif len(invalid_cookies) == len(_cookies):
            return create_failed_test_result(label, _data={"invalid": invalid_cookies})
        else:
            return create_partial_test_result(label, _data={"invalid": invalid_cookies})
    except Exception as e:
        return create_error_test_result(label, _data={"error": str(e)})


def _validate_cookie_flags(_cookies, name, attr):
    if "max-age" in attr and _cookies[name]["max-age"] is not None:
        # If max age contains anything else than digits, then the value
        # is invalid.
        if not str.isdigit(_cookies[name]["max-age"]):
            return {"cookie": name,
                    "value": attr["max-age"],
                    "issue": "Max-age value is not a digit."}

    if "expires" in attr and _cookies[name]["expires"] is not None:
        # Try to parse the date, if we can't the date is in an invalid
        # format or is invalid.
        try:
            eut.parsedate(_cookies[name]["expires"])
        except Exception:
            return {"cookie": name,
                    "value": attr["expires"],
                    "issue": ERROR_COOKIE_DATE_FMT_INVALID}

    if "domain" in attr and _cookies[name]["domain"] is not None:
        if _cookies[name]["domain"].startswith("."):
            _cookies[name]["domain"] = _cookies[name]["domain"][1:]
        if not validators.domain(_cookies[name]["domain"]):
            return {"cookie": name,
                    "value": attr["domain"],
                    "issue": "Invalid domain format."}

    return None


def cookies_via_https_are_secure(_cookies):
    assert _cookies is not None
    label = "cookiesyntaxisvalid"
    try:
        unsecure_cookies = []
        if len(_cookies) <= 0:
            return create_na_test_result(label)

        for cookie_name, cookie_attr in _cookies.items():
            if cookie_attr["secure"] is False:
                unsecure_cookies.append(cookie_name)

        if len(unsecure_cookies) <= 0:
            return create_success_test_result(label)
        elif len(unsecure_cookies) == len(_cookies):
            return create_failed_test_result(label, _data={"unsecure": unsecure_cookies})
        else:
            return create_partial_test_result(label, _data={"unsecure": unsecure_cookies})
    except Exception as e:
        return create_error_test_result(label, _data={"error": str(e)})


def cookies_are_httponly(_cookies):
    assert _cookies is not None
    label = "httpcookiehttponly"
    try:
        unsecure_cookies = []
        if len(_cookies) <= 0:
            return create_na_test_result(label)

        for cookie_name, cookie_attr in _cookies.items():
            if cookie_attr["httponly"] is False:
                unsecure_cookies.append(cookie_name)

        if len(unsecure_cookies) <= 0:
            return create_success_test_result(label)
        elif len(unsecure_cookies) == len(_cookies):
            return create_failed_test_result(label, _data={"unsecure": unsecure_cookies})
        else:
            return create_partial_test_result(label, _data={"unsecure": unsecure_cookies})
    except Exception as e:
        return create_error_test_result(label, _data={"error": str(e)})


def http_cookies_not_include_secure(_cookies):
    assert _cookies is not None
    label = "httpcookieisnotsecure"
    try:
        secure_cookies = []
        if len(_cookies) <= 0:
            return create_na_test_result(label)

        for cookie_name, cookie_attr in _cookies.items():
            if cookie_attr["secure"] is True:
                secure_cookies.append(cookie_name)

        data = {"secure": secure_cookies}

        if len(secure_cookies) <= 0:
            return create_success_test_result(label)
        elif len(secure_cookies) == len(_cookies):
            return create_failed_test_result(label, _message=MSG_COOKIE_HTTP_ALL_INCLUDE_SECURE, _data=data)
        else:
            return create_failed_test_result(label, _message=MSG_COOKIE_HTTP_SOME_INCLUDE_SECURE, _data=data)
    except Exception as e:
        return create_error_test_result(label, _data={"error": str(e)})


def https_cookies_include_secure(_cookies):
    assert _cookies is not None
    label = "httpscookieissecure"
    try:
        unsecure_cookies = []
        if len(_cookies) <= 0:
            return create_na_test_result(label)

        for cookie_name, cookie_attr in _cookies.items():
            if cookie_attr["secure"] is False:
                unsecure_cookies.append(cookie_name)

        if len(unsecure_cookies) <= 0:
            return create_success_test_result(label)
        elif len(unsecure_cookies) == len(_cookies):
            return create_failed_test_result(label, _data={"unsecure": unsecure_cookies})
        else:
            return create_partial_test_result(label, _data={"unsecure": unsecure_cookies})
    except Exception as e:
        return create_error_test_result(label, _data={"error": str(e)})


def https_cookies_host_prefix_valid(_cookies):
    assert _cookies is not None
    label = "httpscookiehostprefixisvalid"
    try:
        invalid_cookies = []
        if len(_cookies) <= 0:
            return create_na_test_result(label, _message=MSG_COOKIE_NO_COOKIE)

        prefixed_cookies = 0
        for cookie_name, cookie_attr in _cookies.items():
            if cookie_name.lower().startswith("__host-"):
                prefixed_cookies += 1
                if not (cookie_attr["path"] == "/" and cookie_attr["secure"] is True and cookie_attr["domain"] is None):
                    invalid_cookies.append(cookie_name)

        if prefixed_cookies <= 0:
            return create_na_test_result(label, _message=MSG_COOKIE_NO_HOST_PREFIX)

        if len(invalid_cookies) <= 0:
            return create_success_test_result(label)
        elif len(invalid_cookies) == len(_cookies):
            return create_failed_test_result(label, _data={"invalid": invalid_cookies})
        else:
            return create_failed_test_result(label, _data={"invalid": invalid_cookies})
    except Exception as e:
        return create_error_test_result(label, _data={"error": str(e)})


def https_cookies_secure_prefix_valid(_cookies):
    assert _cookies is not None
    label = "httpscookiesecureprefixisvalid"

    try:
        invalid_cookies = []
        if len(_cookies) <= 0:
            return create_na_test_result(label, _message=MSG_COOKIE_NO_COOKIE)

        prefixed_cookies = 0
        for cookie_name, cookie_attr in _cookies.items():
            if cookie_name.lower().startswith("__secure-"):
                prefixed_cookies += 1
                if cookie_attr["secure"] is False:
                    invalid_cookies.append(cookie_name)

        if prefixed_cookies <= 0:
            return create_na_test_result(label, _message=MSG_COOKIE_NO_SECURE_PREFIX)

        if len(invalid_cookies) <= 0:
            return create_success_test_result(label)
        elif len(invalid_cookies) == len(_cookies):
            return create_failed_test_result(label, _data={"invalid": invalid_cookies})
        else:
            return create_failed_test_result(label, _data={"invalid": invalid_cookies})
    except Exception as e:
        return create_error_test_result(label, _data={"error": str(e)})


def http_cookies_no_prefix(_cookies):
    assert _cookies is not None
    label = "httpcookienoprefix"

    try:
        invalid_cookies = []
        if len(_cookies) <= 0:
            return create_na_test_result(label, _message=MSG_COOKIE_NO_COOKIE)

        for cookie_name, cookie_attr in _cookies.items():
            if cookie_name.lower().startswith("__secure-") or cookie_name.lower().startswith("__host-"):
                invalid_cookies.append(cookie_name)

        if len(invalid_cookies) <= 0:
            return create_success_test_result(label, _message=MSG_COOKIE_HTTP_NO_PREFIX)
        elif len(invalid_cookies) == len(_cookies):
            return create_failed_test_result(label,
                                             _message=MSG_COOKIE_HTTP_ALL_PREFIX,
                                             _data={"invalid": invalid_cookies})
        else:
            return create_failed_test_result(label,
                                             _message=MSG_COOKIE_HTTP_SOME_PREFIX,
                                             _data={"invalid": invalid_cookies})
    except Exception as e:
        return create_error_test_result(label, _data={"error": str(e)})


def cookies_samesite_flag(_cookies):
    """
    Verifies if the 'samesite' flag is included in the cookies.
    :param _cookies: A dictionary containing 1 or more cookies. Cannot be None.
    :return:
    """
    assert _cookies is not None
    label = "cookiesamesite"
    try:
        invalid_cookies = []
        cookie_score = 0.0
        # If no cookies included, then return N/A result
        if len(_cookies) <= 0:
            return create_na_test_result(label, _message=MSG_COOKIE_NO_COOKIE)

        # Go thru each cookie
        for cookie_name, cookie_attr in _cookies.items():
            # Verify if the samesite flag is set to lax or strict
            if "samesite" in cookie_attr:
                # Partial points for lax
                if cookie_attr["samesite"] == "lax":
                    cookie_score += 0.5
                # All points for strict
                elif cookie_attr["samesite"] == "strict":
                    cookie_score += 1.0
                else:
                    # No point for cookies without the samesite flag.
                    invalid_cookies.append(cookie_name)

        # If at least one cookie does not have the samesite flag, the test dails
        if len(invalid_cookies) > 0:
            return create_failed_test_result(label, _message=MSG_COOKIE_SOME_SAMESITE_INVALID)
        else:
            cookie_score = cookie_score / len(_cookies)
            data = {"cookies": _cookies, "invalid": invalid_cookies}
            if cookie_score <= 0:
                return create_failed_test_result(label, _message=MSG_COOKIE_NONE_SAMESITE, _data=data)
            else:
                # If all cookies have the samesite flag set to lax or strict, success
                return create_success_test_result(label, _message=MSG_COOKIE_ALL_SAMESITE)

    except Exception as e:
        return create_error_test_result(label, _data={"error": str(e)})


def _combine_results(_results: iter, _average=False):  # noqa: C901
    assert _results is not None
    assert len(_results) > 0

    if len(_results) == 1:
        return _results[0]
    else:
        combined = reports.models.TestResult()
        # Define a 'model', which will be used for values
        # that should not change
        model: reports.models.TestResult = _results[0]

        # Initialize the value of the combined result
        # using the values of the first element of the list
        combined.definition = model.definition
        combined.message = model.message
        combined.score = model.score
        # combined.data = model.data
        combined.state = model.state

        # Sum the score and append any data from other results to
        # the 'combined' SecurityTest object
        data = [model.data]
        count = 0
        na_count = 0
        err_count = 0

        if combined.state == TestResult.NA:
            na_count = 1
        elif combined.state == TestResult.ERROR:
            err_count = 1

        for result in _results[1:]:
            assert isinstance(result, reports.models.TestResult)
            assert model.definition == result.definition

            # Test with errors or that were not conducted  are
            # not totalled in the score
            if result.state == TestResult.ERROR:
                err_count += 1

            if result.state == TestResult.NA:
                na_count += 1

            if result.state not in [TestResult.ERROR, TestResult.NA]:
                count += 1
                combined.score += result.score

            if result.data is not None:
                data.append(result.data)

        combined.data = data
        if _average:
            combined.score = combined.score / len(_results)

        # Update the result based on the new score
        d = reports.models.TestDefinition.objects.get(label=model.definition)

        if err_count > 0:
            combined.state = TestResult.ERROR
        elif na_count == len(_results):
            combined.state = TestResult.NA
        elif count <= 0:
            combined.state = model.state
            if model.state == TestResult.FAILURE:
                combined.message = d.message_failed
            elif model.state == TestResult.SUCCESS:
                combined.message = d.message_success
            elif model.state == TestResult.PARTIAL:
                combined.message = d.message_partial
        elif combined.score <= d.failing_score:
            combined.state = TestResult.FAILURE
            combined.message = d.message_failed
        elif combined.score >= d.passing_score:
            combined.state = TestResult.SUCCESS
            combined.message = d.message_success
        else:
            combined.state = TestResult.PARTIAL
            combined.message = d.message_partial

        return combined


def _merge_email_servers_results(_results):
    assert _results is not None
    email_tests = {}
    results = []
    labels = [
        "smtpstarttlsisenabled",
        "smtpcertificatecn",
        "smtpprotocols",
        "smtpciphers",
        "smtpisclosedrelay"
    ]
    # Filter email-related tests
    for test in _results:
        d = reports.models.TestDefinition.objects.get(label=test.definition)
        if d.category == "email_security" and d.label in labels:
            # Sort email tests by test
            if d.label not in email_tests:
                email_tests[d.label] = [test]
            else:
                email_tests[d.label].append(test)

    for test, test_results in email_tests.items():
        result = _combine_results(test_results)
        # Add data for each of the server tested
        data = []
        for server_result in test_results:
            if server_result.data and "host" in server_result.data:
                host_data = {
                    "host": server_result.data["host"],
                    "data": server_result.state
                }
                data.append(host_data)
            else:
                logger.warning("No 'host' information found for '{test:s}'.".format(test=test))
        result.data = data
        results.append(result)

    return results
