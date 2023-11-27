import ast
import json

from django.db import models
import django.utils.timezone
from django.db.models import Avg, Sum, Count
from django_countries.fields import CountryField


class Sector(models.Model):
    """
    Represents an economic/industrial sector of activity used to classify
    companies.
    """

    # Unique 2 to 5 letters unifier for this sector
    code = models.CharField(
        blank=False,
        max_length=5,
        default="NA",
        unique=True
    )

    # Full name for this sector
    name = models.CharField(
        max_length=96,
        default="",
        blank=True)

    def __str__(self):
        return self.name


class Company(models.Model):
    """
    Regroups fields describing a company or organization.
    """
    # Main name of the company
    name = models.CharField(max_length=256, blank=False, default="")

    # Other names associated with the company, or name in different languages
    other_names = models.TextField(blank=True, default="")

    # Number and name of the street
    street_1 = models.CharField(max_length=128, blank=True, default="")
    street_2 = models.CharField(max_length=128, blank=True, default="")

    # City/Town/Village
    city = models.CharField(max_length=128, blank=True, default="")

    # State/Province/Prefecture...
    region = models.CharField(max_length=128, blank=True, default="")

    # Country document related to this address
    country = CountryField(blank=True, default="", blank_label='Select your Country')

    # Zip/Postal code for this address
    postal_code = models.CharField(max_length=10, blank=True, default="")
    # Main website/portal for the company
    website = models.URLField(blank=True, default="")
    # Industrial/commercial sector of the company
    sector = models.ForeignKey(Sector, null=True, on_delete=models.SET_NULL)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name_plural = "Companies"


class Domain(models.Model):
    domain = models.CharField(
        blank=False,
        unique=True,
        max_length=255,
        default="example.com"
    )

    company = models.ForeignKey(Company, blank=True, default=None, null=True, on_delete=models.SET_NULL)
    tags = models.TextField(blank=True, default="")

    def __str__(self):
        return self.domain

    def tags_as_list(self):
        return list(filter(None, self.tags.lower().split(",")))


class TestDefinition(models.Model):
    # Alphanumeric ID for the test
    label = models.CharField(blank=False, max_length=128, unique=True)
    # Name/Short description of the test
    name = models.CharField(max_length=128, blank=False, default="", unique=True)
    # A more detailed description of the test
    description = models.TextField(max_length=512, blank=True, default="")
    # Main category, i.e. Email, Web, ...
    category = models.TextField(blank=False, max_length=256, default="")
    # Any additional keyword for searching/identifying tests
    keywords = models.TextField(blank=True, default="", max_length=256)
    # Overall weight/importance of the test in the greater scoring context
    weight = models.DecimalField(blank=False, decimal_places=4, max_digits=7, default=1.0)
    # Minimum score required to pass the test
    passing_score = models.DecimalField(blank=False, decimal_places=4, max_digits=7, default=1.0)
    # Score below which the test is assessed as failed
    failing_score = models.DecimalField(blank=False, decimal_places=4, max_digits=7, default=0.0)
    # If set to true, the score is not included in the overall scores/averages
    information_only = models.BooleanField(default=False)

    score_failed = models.DecimalField(blank=False, decimal_places=4, max_digits=7, default=0.0)
    score_partial = models.DecimalField(blank=False, decimal_places=4, max_digits=7, default=0.5)
    score_success = models.DecimalField(blank=False, decimal_places=4, max_digits=7, default=1.0)
    score_error = models.DecimalField(blank=False, decimal_places=4, max_digits=7, default=0.0)
    score_na = models.DecimalField(blank=False, decimal_places=4, max_digits=7, default=0.0)

    message_failed = models.TextField(blank=True, max_length=1024, default="")
    message_partial = models.TextField(blank=True, max_length=1024, default="")
    message_success = models.TextField(blank=True, max_length=1024, default="")
    message_error = models.TextField(blank=True, max_length=512, default="")
    message_na = models.TextField(blank=True, max_length=512, default="")

    def __str__(self):
        return self.label

    def keywords_as_list(self):
        return list(filter(None, self.keywords.lower().split(",")))


class RiskReport(models.Model):
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE)
    # Date the report was created
    generated_on = models.DateTimeField(default=django.utils.timezone.now, blank=False)
    latest = models.BooleanField(default=True, blank=False)

    def __str__(self):
        return "{domain:s} ({date:s})".format(domain=self.domain.domain, date=str(self.generated_on))

    def overall_score(self):
        item = ScoreItem.objects.filter(report=self, label="score_overall").first()
        if item:
            return item.score
        else:
            return 0.0

    def overall_rating(self):
        item = ScoreItem.objects.filter(report=self, label="score_overall").first()
        if item:
            return item.rating
        else:
            return "N/A"

    def email_security_score(self):
        item = ScoreItem.objects.filter(report=self, label="score_email_security").first()
        if item:
            return round(item.score)
        else:
            return "N/A"

    def email_security_rating(self):
        item = ScoreItem.objects.filter(report=self, label="score_email_security").first()
        if item:
            return item.rating
        else:
            return "N/A"

    def web_security_score(self):
        item = ScoreItem.objects.filter(report=self, label="score_web_security").first()
        if item:
            return round(item.score)
        else:
            return "N/A"

    def web_security_rating(self):
        item = ScoreItem.objects.filter(report=self, label="score_web_security").first()
        if item:
            return item.rating
        else:
            return "N/A"

    def web_application_score(self):
        item = ScoreItem.objects.filter(report=self, label="score_web_application").first()
        if item:
            return round(item.score)
        else:
            return "N/A"

    def web_application_rating(self):
        item = ScoreItem.objects.filter(report=self, label="score_web_application").first()
        if item:
            return item.rating
        else:
            return "N/A"

    def infrastructure_score(self):
        item = ScoreItem.objects.filter(report=self, label="score_infrastructure").first()
        if item:
            return round(item.score)
        else:
            return "N/A"

    def infrastructure_rating(self):
        item = ScoreItem.objects.filter(report=self, label="score_infrastructure").first()
        if item:
            return item.rating
        else:
            return "N/A"

    def spf_rating(self):
        item = ScoreItem.objects.filter(report=self, label="score_spf").first()
        if item:
            return item.rating
        else:
            return "N/A"

    def dkim_rating(self):
        item = ScoreItem.objects.filter(report=self, label="score_dkim").first()
        if item:
            return item.rating
        else:
            return "N/A"

    def dmarc_rating(self):
        item = ScoreItem.objects.filter(report=self, label="score_dmarc").first()
        if item:
            return item.rating
        else:
            return "N/A"

    def mail_agent_rating(self):
        item = ScoreItem.objects.filter(report=self, label="score_mail_agents").first()
        if item:
            return item.rating
        else:
            return "N/A"

    def dnssec_rating(self):
        item = ScoreItem.objects.filter(report=self, label="score_dnssec").first()
        if item:
            return item.rating
        else:
            return "N/A"

    def https_rating(self):
        item = ScoreItem.objects.filter(report=self, label="score_https").first()
        if item:
            return item.rating
        else:
            return "N/A"

    def http_headers_rating(self):
        item = ScoreItem.objects.filter(report=self, label="score_http_headers").first()
        if item:
            return item.rating
        else:
            return "N/A"

    def http_cookies_rating(self):
        item = ScoreItem.objects.filter(report=self, label="score_http_cookies").first()
        if item:
            return item.rating
        else:
            return "N/A"

    def reputation_rating(self):
        item = ScoreItem.objects.filter(report=self, label="score_reputation").first()
        if item:
            return item.rating
        else:
            return "N/A"

    def ports_rating(self):
        item = ScoreItem.objects.filter(report=self, label="score_ports").first()
        if item:
            return item.rating
        else:
            return "N/A"

    def cves_rating(self):
        item = ScoreItem.objects.filter(report=self, label="score_cves").first()
        if item:
            return item.rating
        else:
            return "N/A"

    def leaks_rating(self):
        item = ScoreItem.objects.filter(report=self, label="score_leaks").first()
        if item:
            return item.rating
        else:
            return "N/A"

    def has_spf_or_dkim(self):
        test_spf = TestResult.objects.filter(report=self, definition__label="spfrecordcount").first()
        test_dkim = TestResult.objects.filter(report=self, definition__label="dkimrecordsexisttest").first()
        return (test_spf is not None and test_spf.has_succeed()) or (test_dkim is not None and test_dkim.has_succeed)

    def has_https(self):
        test = TestResult.objects.filter(report=self, definition__label="httpsenabledtest").first()
        return test is not None and test.has_succeed()

    def is_blacklisted(self):
        test = TestResult.objects.filter(report=self, definition__label="ipblocklist").first()
        return test is not None and test.has_failed()

    def has_vulnerabilities(self):
        test = TestResult.objects.filter(report=self, definition__label="hosthaspotentialvulnerabilities").first()
        return test is not None and test.has_failed()

    def count_partial_results(self):
        tests = TestResult.objects.filter(report=self, state=TestResult.PARTIAL).aggregate(count=Count('id'))
        return tests["count"]

    def count_failed_results(self):
        tests = TestResult.objects.filter(report=self, state=TestResult.FAILED).aggregate(count=Count('id'))
        return tests["count"]

    def search_result_dict(self, user):
        from users.models import DomainProfile

        if self.domain.company:
            company_name = self.domain.company.name
            if self.domain.company.sector:
                company_sector = self.domain.company.sector.name
            else:
                company_sector = None
        else:
            company_name = None
            company_sector = None
        
        domain_profile = DomainProfile.objects.filter(domain=self.domain, profile=user.profile).first()
        if domain_profile:
            company_tags = domain_profile.tags_as_list()
        else:
            company_tags = []

        return {
            "domain": self.domain.domain,
            "updated": self.generated_on,
            "company_name": company_name,
            "company_sector": company_sector,
            "company_tags": company_tags,
            "overall_score": self.overall_score(),
            "overall_rating": self.overall_rating(),
            "email_security_score": self.email_security_score(),
            "email_security_rating": self.email_security_rating(),
            "web_security_score": self.web_security_score(),
            "web_security_rating": self.web_security_rating(),
            "web_application_score": self.web_application_score(),
            "web_application_rating": self.web_application_rating(),
            "infrastructure_score": self.infrastructure_score(),
            "infrastructure_rating": self.infrastructure_rating()
        }


class ScoreItem(models.Model):
    report = models.ForeignKey(RiskReport, on_delete=models.CASCADE)
    label = models.CharField(blank=False, default="", max_length=64)
    score = models.DecimalField(blank=False, decimal_places=4, max_digits=7, default=0.0)
    rating = models.CharField(blank=False, max_length=1, default='Z')

    def __str__(self):
        fmt = "{domain:s}: {item:s} = {score:.2f}"
        return fmt.format(domain=self.report.domain.domain, item=self.label, score=self.score)


class TestResult(models.Model):
    FAILED = "failed"
    PARTIAL = "partial"
    ERROR = "error"
    SUCCESS = "success"
    NA = "na"

    STATES_CHOICES = [
        (FAILED, "Failed"),
        (PARTIAL, "Partial"),
        (ERROR, "Error"),
        (SUCCESS, "Success"),
        (NA, "Not Available")
    ]
    report = models.ForeignKey(RiskReport, on_delete=models.CASCADE)
    # Reference to the test definition associated with this test
    definition = models.ForeignKey(TestDefinition, on_delete=models.CASCADE)
    # Description of the result
    state = models.CharField(blank=False, max_length=16, default=NA, choices=STATES_CHOICES)
    score = models.FloatField(blank=False, default=0.0)
    # Any additional messages resulting from the test
    message = models.TextField(max_length=1024, blank=True, default="")
    # Data generated by the test
    data = models.TextField(blank=True, max_length=6144, default="")

    def __str__(self):
        return self.definition.label

    def has_failed(self):
        return self.state == TestResult.FAILED

    def has_succeed(self):
        return self.state == TestResult.SUCCESS

    def has_partially_succeed(self):
        return self.state == TestResult.PARTIAL

    def has_no_value(self):
        return self.state == TestResult.NA

    def has_error(self):
        return self.state == TestResult.ERROR

    def test_data(self):
        d = ast.literal_eval(str(self.data))
        return d

    def spf_policy(self):
        data = self.test_data()
        if "policy" in data.keys():
            return data["policy"]
        else:
            return ""

    def spf_records(self):
        data = self.test_data()
        if "record" in data.keys():
            return data["record"]
        else:
            return []

    def info_void_lookups(self):
        data = self.test_data()
        if "void_lookups_count" in data.keys():
            return data["void_lookups_count"]
        else:
            return 0

    def info_lookups(self):
        data = self.test_data()
        if "lookup_count" in data.keys():
            return data["lookup_count"]
        else:
            return 0

    def dmarc_records(self):
        data = self.test_data()
        if "record" in data.keys():
            return data["record"]
        else:
            return []

    def dmarc_policy(self):
        data = self.test_data()
        if "policy" in data.keys():
            return data["policy"]
        else:
            return ""

    def dmarc_rua(self):
        data = self.test_data()
        if "rua" in data.keys():
            return data["rua"]
        else:
            return ""

    def dmarc_ruf(self):
        data = self.test_data()
        if "ruf" in data.keys():
            return data["ruf"]
        else:
            return ""

    def smtp_servers(self):
        return self.test_data()

    def cves(self):
        return self.test_data()

    def ports(self):
        return self.test_data()

    def ip_state(self):
        data = self.test_data()
        del data["ip"]
        del data["list-count"]
        del data["sensors"]
        del data["blocklists"]
        del data["last-seen"]
        return data

    def blacklists(self):
        data = self.test_data()
        lists = []
        for list in data["lists"]:
            if list["is-listed"]:
                lists.append(list["list-name"])
        return lists

    def leaked_groups(self):
        data = self.test_data()
        return data["groups"]

    def reputation_state_desc(self):
        data = self.ip_state()
        states = []
        for k, v in data.items():
            if v:
                q = "is"
            else:
                q = "is not"

            if k == "is-proxy":
                m = "Your IP address {qual:s} being detected as an anonymous web proxy or anonymous HTTP proxy.".format(
                    qual=q)
            elif k == "is-tor":
                m = "Your IP address {qual:s} being detected as a Tor node or running a Tor related service.".format(qual=q)
            elif k == "is-vpn":
                m = "Your IP address {qual:s} being detected as belonging to a VPN provider.".format(qual=q)
            elif k == "is-malware":
                m = "Your IP address {qual:s} involved in distributing or is running malware.".format(qual=q)
            elif k == "is-spyware":
                m = "Your IP address {qual:s} involved in distributing or is running spyware.".format(qual=q)
            elif k == "is-dshield":
                m = "Your IP address {qual:s} being flagged as an attack source on DShield (dshield.org).".format(qual=q)
            elif k == "is-hijacked":
                m = "Your IP address {qual:s} part of a hijacked netblock or a netblock controlled by a criminal organization.".format(
                    qual=q)
            elif k == "is-spider":
                m = "Your IP address {qual:s} running a hostile web spider / web crawler.".format(qual=q)
            elif k == "is-bot":
                m = "Your IP address {qual:s} hosting a malicious bot or is part of a botnet. Includes brute-force crackers.".format(
                    qual=q)
            elif k == "is-spam-bot":
                m = "Your IP address {qual:s} hosting a spam bot, comment spamming or any other spamming type software.".format(
                    qual=q)
            elif k == "is-exploit-bot":
                m = "Your IP address {qual:s} hosting an exploit finding bot or is running exploit scanning software.".format(
                    qual=q)
            else:
                m = ""

            states.append((v, m))
        return states
