from urllib.parse import urlparse
import validators
import logging
import tldextract

from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save, pre_save, pre_init, post_init
from django.dispatch import receiver
from django.utils.functional import cached_property
from django_countries.fields import CountryField
from django.contrib.auth import get_user_model

from allauth.account.signals import user_signed_up

from djstripe.models import Customer, Plan
from djstripe import webhooks

from djstripe.utils import subscriber_has_active_subscription

from reports.models import Company, Domain
from reports.tasks import create_report

logger = logging.getLogger(__name__)


class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    domain = models.ForeignKey(Domain, null=True, on_delete=models.DO_NOTHING)
    domain_temp = models.TextField(blank=True, default="") # temporary use until email confirmation
    domains = models.TextField(blank=True, default="")

    def __str__(self):
        return self.user.email

    def has_related_object(self):
        return hasattr(self, 'company') and self.company

    def followed_domains(self):
        return list(filter(None, self.domains.split(",")))

    def followed(self, domain):
        return domain in self.followed_domains()

    def add_followed_domain(self, _domain):
        _domain = _domain.lower().strip()
        if validators.domain(_domain):
            current_domains = self.followed_domains()
            if _domain not in current_domains:
                current_domains.append(_domain)
                self.domains = ",".join(current_domains)
                self.save()
                return True
        return False

    def remove_followed_domain(self, _domain):
        _domain = _domain.lower().strip()
        current_domains = self.followed_domains()
        if _domain in current_domains:
            current_domains.remove(_domain)
            self.domains = ",".join(current_domains)
            self.save()
            return True
        return False

    @property
    def company(self):
        if self.domain and self.domain.company:
            return self.domain.company
        else:
            return None

    def user_domain(self):
        if self.company and self.company.website:
            p = urlparse(self.company.website)
            e = tldextract.extract(p.netloc)
            return e.registered_domain
        elif validators.email(self.user.email):
            p = self.user.email.split("@")[1]
            e = tldextract.extract(p)
            return e.registered_domain
        else:
            return None

    @cached_property
    def has_active_subscription(self):
        """Checks if a user has an active subscription."""
        return subscriber_has_active_subscription(self.user)

    @cached_property
    def on_trial_or_free_account(self):
        if self.user.is_superuser or self.user.is_staff:
            return False
        plan_free = Plan.objects.get(id="plan_free01")
        return subscriber_has_active_subscription(self.user, plan=plan_free)

    @cached_property
    def on_sme_account(self):
        if self.user.is_superuser or self.user.is_staff:
            return False
        plan_sme = Plan.objects.get(id="plan_sme01")
        return subscriber_has_active_subscription(self.user, plan=plan_sme)

    @cached_property
    def can_access_full_report(self):
        return not self.on_trial_or_free_account

    @cached_property
    def can_track_companies(self):
        return not self.on_trial_or_free_account


class DomainProfile(models.Model):
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE)
    profile = models.ForeignKey(Profile, blank=False, default=None, on_delete=models.CASCADE)
    tags = models.TextField(blank=True, default="")

    def __str__(self):
        return self.domain.domain

    def tags_as_list(self):
        return list(filter(None, self.tags.split(",")))

    def search_result_dict(self):
        company = self.domain.company
        
        if company:
            company_name = company.name
            company_tags = self.tags_as_list()
            if company.sector:
                company_sector = company.sector.name
            else:
                company_sector = None
        else:
            company_name = None
            company_sector = None
            company_tags = []

        data = {
            "domain": self.domain.domain,
            "user_defined_company_name": company_name,
            "user_defined_company_sector": company_sector,
            "user_defined_company_tags": company_tags,
            "is_followed": self.domain.domain in self.profile.followed_domains()
        }
        return data


class Contact(models.Model):
    """
    Contact information for domains.
    """
    profile = models.ForeignKey(DomainProfile, default=None, on_delete=models.CASCADE)

    # Title, i.e. Mr, Mme, Dr, etc...
    title = models.CharField(
        blank=True,
        default="",
        max_length=5)

    first_name = models.CharField(
        blank=True,
        default="",
        max_length=64)

    middle_name = models.CharField(
        blank=True,
        default="",
        max_length=64)

    last_name = models.CharField(
        blank=True,
        default="",
        max_length=64)

    # Number and name of the street
    street_1 = models.CharField(max_length=128, blank=True, default="")
    street_2 = models.CharField(max_length=128, blank=True, default="")

    # City/Town/Village
    city = models.CharField(max_length=128, default="")

    # State/Province/Prefecture...
    region = models.CharField(max_length=128, default="")

    # Country document related to this address
    country = CountryField(blank=True, default="")

    work_phone = models.CharField(blank=True, default="", max_length=16)
    mobile_phone = models.CharField(blank=True, default="", max_length=16)
    email = models.CharField(blank=True, default="", max_length=256)

    # Professional title or position name
    role = models.CharField(blank=True, default="", max_length=256)
    # Additional notes about this contact, i.e. "contact via email only" etc...
    notes = models.TextField(blank=True, max_length=4096)


@receiver(post_save, sender=User)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.get_or_create(user=instance)
        user = get_user_model().objects.get(id=instance.id)
        customer, created = Customer.get_or_create(subscriber=user)
        if created:
            # Subscribe the user to the Free plan immediately
            plan = Plan.objects.get(id="plan_free01")
            customer.subscribe(plan=plan, charge_immediately=False)
            logger.info("Created new user '{uid:s}' with customer id {cid:s}.".format(uid=str(instance.id),
                                                                                     cid=str(customer.id)))


@receiver(user_signed_up)
def post_signup(request, user, **kwargs):
    model = get_user_model().objects.get(id=user.id)
    customer, _ = Customer.get_or_create(subscriber=model)
    plan = customer.subscription.plan
    user_domain = user.profile.user_domain()
    logger.info("User {uid} from '{dom:s}' signed up with plan ID {pid:s}.".format(uid=user.email, dom=user_domain,
                                                                                   pid=str(plan.id)))
    print("User {uid} from '{dom:s}' signed up with plan ID {pid:s}. (models)".format(uid=user.email, dom=user_domain, pid=str(plan.id)))
    if user_domain and validators.domain(user_domain):
        if user.profile and user.profile.company:
            company_name = user.profile.company.name
        else:
            company_name = ""
        create_report.delay(_domain=user_domain, _company=company_name, _user=user.id)


@webhooks.handler("checkout.session.completed")
def checkout_session_completed(event, **kwargs):
    id = event.data["object"]["client_reference_id"]
    user = User.objects.get(id=int(id))
    logger.info("Checkout completed for user '{uid:s}'.".format(uid=user.id))


@webhooks.handler("customer.subscription.trial_will_end")
def customer_subscription_trial_will_end(event, **kwargs):
    id = event.data["object"]["client_reference_id"]
    user = User.objects.get(id=int(id))
    logger.info("Trial for user '{uid:s}' is ending soon.".format(uid=user.id))
