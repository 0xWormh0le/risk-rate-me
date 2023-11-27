from django import forms
from .models import User, Profile
from allauth.account.forms import SignupForm, LoginForm
import djstripe.models
from quickemailverification import Client
from django.conf import settings
from django_countries import fields
from reports.models import Sector, Domain, Company
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError
from captcha.fields import ReCaptchaField
from captcha.widgets import ReCaptchaV2Checkbox, ReCaptchaV3
import validators


class OptionalSchemeURLValidator(URLValidator):
    def __call__(self, value):
        if '://' not in value:
            # Validate as if it were http://
            value = 'https://' + value
        super(OptionalSchemeURLValidator, self).__call__(value)


def validate_domain(value):
    if not validators.domain(value):
        raise ValidationError('Not a valid domain')


class UserForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'email')


class ProfileForm(forms.Form):
    PLAN_CHOICES = [("plan_pro01", "Professional"),
                    ("plan_free01", "Free"),
                    ("plan_ent01", "Enterprise"),
                    ("plan_sme01", "Small & Medium Sized Enterprise")]
    plan = forms.ChoiceField(choices=PLAN_CHOICES)
    first_name = forms.CharField(max_length=30, label='First Name')
    last_name = forms.CharField(max_length=30, label='Last Name')
    company_name = forms.CharField(max_length=256, label="Company")
    # City/Town/Village
    city = forms.CharField(max_length=128, required=False)

    # State/Province/Prefecture...
    region = forms.CharField(max_length=128, required=False)

    # Country document related to this address
    country = fields.CountryField().formfield()
    # Industrial/commercial sector of the company
    company_sector = forms.ModelChoiceField(label='Sector', queryset=Sector.objects.all())
    company_website = forms.URLField(label="Website")


class UpdatePlanForm(forms.Form):
    PLAN_CHOICES = [("plan_pro01", "Professional"),
                    ("plan_free01", "Free"),
                    ("plan_sme01", "Small & Medium Sized Enterprise")]
    plan = forms.ChoiceField(label="Plan", choices=PLAN_CHOICES)


class CustomSignupForm(SignupForm):
    PLAN_CHOICES = [("plan_pro01", "Professional"),
                    ("plan_free01", "Free"),
                    ("plan_ent01", "Enterprise"),
                    ("plan_sme01", "Small & Medium Sized Enterprise")]

    plan = forms.ChoiceField(choices=PLAN_CHOICES, widget=forms.RadioSelect, initial="plan_pro01")
    first_name = forms.CharField(max_length=30, label='First Name')
    last_name = forms.CharField(max_length=30, label='Last Name')
    domain = forms.CharField(label="Domain", validators=[validate_domain])
    captcha = ReCaptchaField(widget=ReCaptchaV2Checkbox)
    accepted_terms = forms.BooleanField()

    def save(self, request):
        # Ensure you call the parent class's save.
        # .save() returns a User object.
        first_name = self.cleaned_data['first_name']
        last_name = self.cleaned_data['last_name']
        domain = self.cleaned_data['domain']

        user = super(CustomSignupForm, self).save(request)
        user.first_name = first_name
        user.last_name = last_name

        profile = user.profile
        profile.domain_temp = domain.lower()
        profile.save()

        user.profile = profile
        user.save()
        # You must return the original result.
        return user


class CustomLoginForm(LoginForm):
    def login(self, *args, **kwargs):
        from allauth.account.utils import perform_login
        parent = super(CustomLoginForm, self)
        request = args[0]

        if self.user.is_superuser:
            ret = perform_login(*args, user=self.user, email_verification="none", **kwargs)
            remember = settings.ACCOUNT_SESSION_REMEMBER

            if remember is None:
                remember = self.cleaned_data['remember']
            if remember:
                request.session.set_expiry(settings.SESSION_COOKIE_AGE)
            else:
                request.session.set_expiry(0)
            return ret

        else:
            return parent.login(*args, **kwargs)

class PurchaseSubscriptionForm(forms.Form):
    email = forms.EmailField()
    plan = forms.CharField(
        max_length="255", widget=forms.HiddenInput(), required=True
    )
    stripe_source = forms.CharField(
        max_length="255", widget=forms.HiddenInput(), required=True
    )
