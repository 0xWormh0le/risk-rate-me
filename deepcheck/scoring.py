import logging

from django.db.models import Avg, Sum, Count
import reports.models

STATUS_PASSED = "passed"
STATUS_PARTIAL = "partial"
STATUS_FAILED = "failed"
STATUS_ERROR = "error"
STATUS_NA = "not_available"
STATUS_EXCLUDED = "excluded"

logger = logging.getLogger(__name__)


def score_for_keyword(_report: reports.models.RiskReport, _keyword: str, _starting_score=1.0):
    """
    Computes the score for a set of test tagged with the given keyword.

    :param _report: A RiskReport object with tests completed.
    :param _keyword: A keyword as found in the 'keywords' list of the test definitions.
    :return:
    """
    assert _report is not None
    results = reports.models.TestResult.objects.filter(report=_report,
                                                       definition__information_only=False,
                                                       definition__keywords__icontains=_keyword.strip())
    score = results.aggregate(score=Sum('score'))

    return max(0.0, _starting_score + float(score["score"]))


def normalize(_score):
    if 0.43 < _score < 0.9:
        return 2
    elif _score <= 0.43:
        return 0
    else:
        return 5


def normalize_es(_score):
    if 0.55 < _score < 0.9:
        return 2
    elif _score <= 0.55:
        return 0
    else:
        return 5


def score_report(_report: reports.models.RiskReport):
    assert _report is not None

    # We first obtains stats about each subcategories, these
    # will be returned as well.
    # Email Security
    email_security = score_email_security(_report)

    # Web Security
    web_security = score_web_security(_report)

    # Web application
    web_application = score_web_application(_report)

    # Score for infrastructure
    infrastructure = score_infrastructure(_report)

    # At this point, we should have 4 scores between [0, 1]:
    #   s_es: email security
    #   s_ws: web security
    #   s_wa: web application
    #   s_if: infrastructure
    # For email security and web security, we take a hard approach;
    #
    s_es = normalize_es(email_security)
    s_ws = normalize(web_security)
    s_wa = normalize_es(web_application)
    s_if = normalize(infrastructure)
    s = (s_es + s_ws + s_wa + s_if) / 20.0

    s_spf = score_for_keyword(_report, "spf")
    s_dkim = score_for_keyword(_report, "dkim")
    s_dmarc = score_for_keyword(_report, "dmarc")
    s_ma = score_for_keyword(_report, "mail-agent")
    s_dnssec = score_for_keyword(_report, "dnssec")
    s_https = score_for_keyword(_report, "https")
    s_hdrs = score_for_keyword(_report, "headers")
    s_cook = score_for_keyword(_report, "cookies")
    s_rep = score_for_keyword(_report, "reputation")
    s_ports = score_ports(_report)
    s_cve = score_cves(_report)
    s_leaks = score_leaks(_report)

    return {
        "score_overall": s,
        "score_email_security": s_es,
        "score_web_security": s_ws,
        "score_web_application": s_wa,
        "score_infrastructure": s_if,
        "score_spf": s_spf,
        "score_dkim": s_dkim,
        "score_dmarc": s_dmarc,
        "score_mail_agents": s_ma,
        "score_dnssec": s_dnssec,
        "score_https": s_https,
        "score_http_headers": s_hdrs,
        "score_http_cookies": s_cook,
        "score_reputation": s_rep,
        "score_ports": s_ports,
        "score_cves": s_cve,
        "score_leaks": s_leaks,
    }


def score_email_security(_report):
    # Email security

    # score_spf should return a value between 0 and 1
    s_spf = float(score_for_keyword(_report, "spf"))
    # score_dkim should return a either 0 or 1
    s_dkim = float(score_for_keyword(_report, "dkim"))
    # score_dmarc should return a value between 0 and 1
    s_dmarc = float(score_for_keyword(_report, "dmarc"))
    # score_ma should return a value between 0 and 1
    # score_mail_agents considers all mail servers found
    s_ma = float(score_mail_agents(_report))

    # Adjust weights here
    w_spf = 0.3
    w_dkim = 0.1
    w_dmarc = 0.4
    w_ma = 0.2
    # Score for Email Security
    s_es = (w_spf * s_spf) + (w_dkim * s_dkim) + (w_dmarc * s_dmarc) + (w_ma * s_ma)

    return s_es


def score_web_security(_report):
    # Web security
    s_https = float(score_for_keyword(_report, "https"))
    s_dnssec = float(score_for_keyword(_report, "dnssec"))

    w_https = 0.9
    w_dnssec = 0.1

    # Score for Web Security
    s_ws = (w_https * s_https) + (w_dnssec * s_dnssec)
    return s_ws


def score_web_application(_report):
    # Web Application
    s_headers = float(score_for_keyword(_report, "headers"))
    s_cookies = float(score_for_keyword(_report, "cookies"))

    w_headers = 0.7
    w_cookies = 0.3

    # Score for web application tests
    s_wa = (w_headers * s_headers) + (w_cookies * s_cookies)
    return s_wa


def score_infrastructure(_report):
    s_rep = float(score_for_keyword(_report, "reputation"))
    s_cve = float(score_ports(_report))
    s_ports = float(score_leaks(_report))
    s_leaks = float(score_cves(_report))

    w_rep = 0.7
    w_cves = 0.3
    w_ports = 0.0
    w_leaks = 0.0

    s_if = (w_rep * s_rep) + (w_cves * s_cve)
    s_if = max(0.0, min(s_if, 1.0))
    return s_if


def score_mail_agents(_report):
    assert _report is not None

    test_smtpfound = reports.models.TestResult.objects.get(report=_report, definition__label__iexact="smtpserverfoundtest")
    if test_smtpfound.has_failed:
        return 1.0

    score_starttls = reports.models.ScoreItem.objects.filter(report=_report,
                                                             definition__keywords__icontains="mail-agent-starttls").aggregate(score=Sum("score"))
    score_ciphers = reports.models.ScoreItem.objects.filter(report=_report,
                                                            definition__keywords__icontains="mail-agent-cipher").aggregate(score=Sum("score"))
    score_relays = reports.models.ScoreItem.objects.filter(report=_report,
                                                           definition__keywords__icontains="mail-agent-relay").aggregate(score=Sum("score"))

    s_starttls = score_starttls["score"]
    s_ciphers = score_ciphers["score"]
    s_relays = score_relays["score"]

    # STARTTLS, Ciphers Strength and Open Relays are all critical
    # tests. If any of them is 0, then the entire mail agent subcategory
    # shall fail.
    # As such, multiply them will yield a total score between
    # 0 and 1. Anything below 1.0 is a fail, but we let the application
    # decide. We just provide a numeric value here.
    s_ma = s_starttls * s_ciphers * s_relays
    return s_ma
    if s_ma > 1:
        s_ma = 1



def score_ports(_report):
    assert _report is not None
    test = reports.models.TestResult.objects.get(report=_report,
                                                 definition__label__iexact="hostopenports")
    return max(0.0, float(test.score))


def score_leaks(_report, _max=10):
    assert _report is not None
    test = reports.models.TestResult.objects.get(report=_report,
                                                 definition__label__iexact="emailleaks")
    return max(0.0, test.score)


def score_cves(_report, _max=0):
    assert _report is not None
    test = reports.models.TestResult.objects.get(report=_report,
                                                 definition__label__iexact="hosthaspotentialvulnerabilities")
    return max(0.0, test.score)
