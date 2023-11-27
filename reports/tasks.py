from celery import shared_task

import datetime
import dateutil.relativedelta
import logging
import traceback
import validators

from django.core.mail import send_mail

import deepcheck.engine
import deepcheck.tests
import deepcheck.scoring

logger = logging.getLogger(__name__)

NO_REPORT = None
NB_STEPS_ANALYSIS = 11
AUDIT_NO_REPORT_DOMAIN = "No report retrieve for domain '{domain:s}'."
AUDIT_NO_REPORT_SECTOR = "No report retrieve for sector '{sector:s}'."
AUDIT_ACCESS_DENIED = "User '{email:s}' was prevented access to '{view:s}' due to missing permission."
AUDIT_ACTION_SECTOR_SUMMARY = "User '{email:s}' requested summary for sector '{sector:s}'."
AUDIT_ACTION_COMPANY_SUMMARY = "User '{email:s}' requested report for company '{company:s}'."
AUDIT_ACTION_USER_DOM_SUMMARY = "User '{email:s}' requested report for his/her own domain."
AUDIT_ACTION_DOMAIN_SUMMARY = "User '{email:s}' requested report for domain '{domain:s}'."
AUDIT_ACTION_TAG_SUMMARY = "User '{email:s}' requested summary for tag '{tag:s}'."
AUDIT_ACTION_REPORT_REQUEST = "Request to generate report for '{domain:s}' for '{company:s}'."
AUDIT_ACTION_TEST_RESULT = "{domain:s}: {test:s} [{result:s}]"
AUDIT_ACTION_TEST_NOT_FOUND = "Failed to find definition for test '{label:s}'."
MSG_ERROR_REPORT_CREATE = "An error occurred while creating the report for '{domain:s}': {err:s}"
AUDIT_ACTION_TEST_COUNT = "Upto {cnt:d} test(s) will be conducted on '{domain:s}'."
MSG_ANALYSIS_STEP_SPF = "Analyzing SPF record(s)."
MSG_ANALYSIS_STEP_DKIM = "Veryfying DKIM support."
MSG_ANALYSIS_STEP_DMARC = "Assessing DMARC record(s)"
MSG_ANALYSIS_STEP_MAIL = "Checking mail agents"
MSG_ANALYSIS_STEP_DNSSEC = "Validating DNSSEC record(s)"
MSG_ANALYSIS_STEP_HTTPS = "Looking at the HTTPS setup"
MSG_ANALYSIS_STEP_HEADERS = "Parsing HTTP headers"
MSG_ANALYSIS_STEP_COOKIES = "Validating cookie(s) received."
MSG_ANALYSIS_STEP_TRUST = "Searching online for trust issues"
MSG_ANALYSIS_COMPILE_SCORE = "Compiling data and scoring..."
MSG_ANALYSIS_COMPLETED = "Analysis completed successfully"
MSG_ANALYSIS_FAILED = "Unable to assess the domain provided"

RATING_A = "A"
RATING_A_LOW = "A-"
RATING_B = "B"
RATING_C = "C"
RATING_D = "D"
RATING_E = "E"
RATING_F = "F"

RANGE_RATING_A = (0.85, 1.00)
RANGE_RATING_B = (0.75, 0.85)
RANGE_RATING_C = (0.56, 0.75)
RANGE_RATING_D = (0.37, 0.56)
RANGE_RATING_E = (0.18, 0.37)
RANGE_RATING_F = (0.00, 0.18)


@shared_task
def send_report_completion_email(_email, _domain):
    from reports.models import RiskReport, ScoreItem

    if validators.email(_email):
        report = RiskReport.objects.filter(domain__domain=_domain, latest=True).first()
        overall = ScoreItem.objects.get(report=report, label="score_overall")
        report_url = "/dashboard/report/{d:s}".format(d=_domain)
        subject = "Riskrate.me - Analysis of {domain:s} Completed".format(domain=_domain)
        message = "We're done analysing '{domain:s}'<br><br> The domain has an overall rating of {rating_overall:s}. Click " \
                  "<a href='{report_url:s}'>here</a> to find out more!".format(rating_overall=overall.rating,
                                                                               report_url=report_url,
                                                                               domain=_domain)
        send_mail(
            subject,
            message,
            'no-reply@riskrate.me',
            [_email],
            fail_silently=False,
        )


def past_month_date_range():
    """
    This function will generate two (2) datetime objects; the first represents
    the current date minus one month, and the second date is the current date.

    For example, calling this function on 29 for March 2019, will generate this tuple:
    (datetime.datetime(year=2019, month=2, day=29, hour=0, minute=0, second=0),
    datetime.datetime(year=2019, month=3, day=59, hour=23, minute=59, second=59)

    :return: A tuple containing two (2) datetime objects.
    """
    # Get the current date
    end_date = datetime.datetime.utcnow()
    end_date = end_date.replace(hour=23, minute=59, second=59)
    # Substract one month
    start_date = end_date - dateutil.relativedelta.relativedelta(days=1)
    start_date = start_date.replace(hour=0, minute=0, second=0)
    return start_date, end_date


def score_to_rating(_score):
    """
    Translate a numeric score to a letter-grade format.

    :param _score: Floating point value
    :return: A, B, C, D, E, or F
    """
    if _score <= RANGE_RATING_F[1]:
        return RATING_F
    elif RANGE_RATING_E[0] < _score <= RANGE_RATING_E[1]:
        return RATING_E
    elif RANGE_RATING_D[0] < _score <= RANGE_RATING_D[1]:
        return RATING_D
    elif RANGE_RATING_C[0] < _score <= RANGE_RATING_C[1]:
        return RATING_C
    elif RANGE_RATING_B[0] < _score <= RANGE_RATING_B[1]:
        return RATING_B
    else:
        return RATING_A


@shared_task(bind=True)
def create_report(self, _domain, _company=None, _sector=None, _tags="", _user=None):
    from users.models import DomainProfile, User
    from reports.models import Domain, Company, RiskReport, ScoreItem, TestDefinition, Sector

    try:
        logger.info(AUDIT_ACTION_REPORT_REQUEST.format(
            domain=_domain, company=str(_company)
        ))

        # Ensure we have the base domain of the domain provided
        # base_domain = deepcheck.engine.get_base_domain(_domain)

        user = User.objects.get(id=_user)
        sector = None
        if _sector:
            sector = Sector.objects.filter(code=_sector.strip().upper()).first()

        try:
            domain = Domain.objects.get(domain=_domain)
        except:
            domain = Domain(domain=_domain)
            domain.save()

        if domain.company:
            if _company:
                domain.company.name = _company
            domain.company.sector = sector
            domain.company.save()
        elif _company:
            company = Company(name=_company, sector=sector)
            company.save()
            domain.company = company
            domain.save()

        profile = DomainProfile.objects.filter(profile=user.profile, domain=domain).first()
        if profile is None:
            profile = DomainProfile(profile=user.profile, domain=domain)
        
        profile.tags = ",".join(_tags)
        profile.save()

        # Search for a report than is less than 30 days old
        # if found, return this report to avoid cluttering the db
        (last_month, _) = past_month_date_range()
        report = RiskReport.objects.filter(domain=domain, generated_on__gte=last_month).first()
        if report:
            self.update_state(state='COMPLETED',
                              meta={'current': NB_STEPS_ANALYSIS,
                                    'total': NB_STEPS_ANALYSIS,
                                    'status': MSG_ANALYSIS_COMPLETED})

            logger.debug("Recent report found: {id:s}.".format(id=str(report.pk)))
            result = {'current': NB_STEPS_ANALYSIS,
                      'total': NB_STEPS_ANALYSIS,
                      'status': MSG_ANALYSIS_COMPLETED,
                      'report_id': str(report.pk)}
            send_report_completion_email.delay(_email=user.email, _domain=_domain)
            return result

        report = RiskReport(domain=domain)
        logger.debug("Base domain for {dom:s} is {bdom:s}.".format(dom=_domain, bdom=report.domain.domain))

        nb_tests = TestDefinition.objects.count()
        logger.debug(AUDIT_ACTION_TEST_COUNT.format(cnt=nb_tests, domain=report.domain.domain))

        # 1. SPF-related tests
        step = 1
        if self is not None:
            self.update_state(state='RUNNING',
                              meta={'current': step, 'total': NB_STEPS_ANALYSIS, 'status': MSG_ANALYSIS_STEP_SPF})
        results = deepcheck.tests.spf(report)

        # 2. DKIM-related tests
        step += 1
        if self is not None:
            self.update_state(state='RUNNING',
                              meta={'current': step, 'total': NB_STEPS_ANALYSIS, 'status': MSG_ANALYSIS_STEP_DKIM})
        results += deepcheck.tests.dkim(report)

        # 3. DMARC-related tests
        step += 1
        if self is not None:
            self.update_state(state='RUNNING',
                              meta={'current': step, 'total': NB_STEPS_ANALYSIS, 'status': MSG_ANALYSIS_STEP_DMARC})
        results += deepcheck.tests.dmarc(report)

        # 4. Email-related tests, including SMTP, IMAP
        step += 1
        if self is not None:
            self.update_state(state='RUNNING',
                              meta={'current': step, 'total': NB_STEPS_ANALYSIS, 'status': MSG_ANALYSIS_STEP_MAIL})
        results += deepcheck.tests.test_mail(report)

        # 5. DNSSEC-related tests
        step += 1
        if self is not None:
            self.update_state(state='RUNNING',
                              meta={'current': step, 'total': NB_STEPS_ANALYSIS,
                                    'status': MSG_ANALYSIS_STEP_DNSSEC})
        results += deepcheck.tests.test_dns_dnssec(_report=report)

        # 6. HTTPS-related tests
        step += 1
        if self is not None:
            self.update_state(state='RUNNING',
                              meta={'current': step, 'total': NB_STEPS_ANALYSIS, 'status': MSG_ANALYSIS_STEP_HTTPS})
        website = deepcheck.engine.get_website_from_domain(report.domain.domain)
        results += deepcheck.tests.test_https(website)

        # 7. HTTP Headers related tests
        step += 1
        if self is not None:
            self.update_state(state='RUNNING',
                              meta={'current': step, 'total': NB_STEPS_ANALYSIS,
                                    'status': MSG_ANALYSIS_STEP_HEADERS})
        results += deepcheck.tests.test_http_headers(_url=website)

        # 8.HTTP Cookies related tests
        step += 1
        if self is not None:
            self.update_state(state='RUNNING',
                              meta={'current': step, 'total': NB_STEPS_ANALYSIS,
                                    'status': MSG_ANALYSIS_STEP_COOKIES})
        results += deepcheck.tests.test_cookies(_url=website)

        # 9. Trustworthiness related tests
        step += 1
        if self is not None:
            self.update_state(state='RUNNING',
                              meta={'current': step, 'total': NB_STEPS_ANALYSIS, 'status': MSG_ANALYSIS_STEP_TRUST})
        results += deepcheck.tests.test_trust_host(report)

        # 10. Compiling results
        step += 1

        RiskReport.objects.filter(domain=domain).update(latest=False)
        domain.latest = True
        domain.save()
        report.domain = domain
        report.save()
        for result in results:
            result.report = report
            result.save()

        if self is not None:
            self.update_state(state='RUNNING',
                              meta={'current': step, 'total': NB_STEPS_ANALYSIS, 'status': MSG_ANALYSIS_COMPILE_SCORE})

        summary = deepcheck.scoring.score_report(report)
        print(summary)
        # Save the summary to the database
        for item, score in summary.items():
            rating = score_to_rating(score)
            new_score = ScoreItem(report=report, label=item, score=score, rating=rating)
            new_score.save()

        # 11. Commit to db
        step = NB_STEPS_ANALYSIS
        if self is not None:
            self.update_state(state='COMPLETED',
                              meta={'current': NB_STEPS_ANALYSIS,
                                    'total': NB_STEPS_ANALYSIS,
                                    'status': MSG_ANALYSIS_COMPLETED})

        logger.debug("Report created: {id:s}.".format(id=str(report.pk)))
        result = {'current': NB_STEPS_ANALYSIS,
                  'total': NB_STEPS_ANALYSIS,
                  'status': MSG_ANALYSIS_COMPLETED,
                  'report_id': str(report.pk)}
        send_report_completion_email.delay(_email=user.email, _domain=_domain)
        return result
    except Exception as e:
        logger.error(MSG_ERROR_REPORT_CREATE.format(domain=_domain, err=str(e)))
        traceback.print_exc()

        result = {'current': NB_STEPS_ANALYSIS,
                  'total': NB_STEPS_ANALYSIS,
                  'status': MSG_ANALYSIS_FAILED,
                  'report_id': "0"}
        return result
