from django.shortcuts import render, redirect
from django.db import transaction
from django.contrib import messages
from django.contrib.auth import login, authenticate
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.http import JsonResponse
import djstripe.models
import stripe
from django.contrib.auth import get_user_model
from django.urls import reverse
from .models import User
from .forms import UserForm, ProfileForm, CustomSignupForm, PurchaseSubscriptionForm, UpdatePlanForm
from django.views.generic import DetailView, FormView
import reports.forms
from django.contrib.auth import update_session_auth_hash
import reports.models
from django.contrib.auth.forms import PasswordChangeForm
import logging
from django_countries import countries
from reports.tasks import create_report
from reports.models import Domain
from users.models import User
from allauth.account.utils import send_email_confirmation
from allauth.account.signals import email_confirmed
from allauth.account.views import SignupView
from django.dispatch import receiver



logger = logging.getLogger(__name__)


def subscribe(request):
    if request.method == 'POST':
        if request.user.is_anonymous:
            form = CustomSignupForm(request.POST)
            if form.is_valid():
                user = form.save(request)
                send_email_confirmation(request, user, settings.ACCOUNT_EMAIL_VERIFICATION)

                plan_id = form.cleaned_data.get("plan")
                plan = djstripe.models.Plan.objects.filter(id=plan_id).first()
                if plan:
                    ctx = {
                        "user": user,
                        "plan": plan,
                        "stripe_public_key": settings.STRIPE_PUBLIC_KEY,
                        "amount": plan.amount * 100
                    }
                    return render(request, 'subscribe.html', ctx)

            ctx = {
                "form": form
            }
            return render(request, 'account/signup.html', ctx)
        else:
            plan_id = "plan_pro01"
            plan = djstripe.models.Plan.objects.filter(id=plan_id).first()
            if plan:
                ctx = {
                    "user": request.user,
                    "plan": plan,
                    "stripe_public_key": settings.STRIPE_PUBLIC_KEY,
                    "amount": plan.amount * 100
                }
                return render(request, 'subscribe.html', ctx)
    else:
        if not request.user.is_anonymous:
            plan_id = "plan_pro01"
            plan = djstripe.models.Plan.objects.filter(id=plan_id).first()
            if plan:
                ctx = {
                    "user": request.user,
                    "plan": plan,
                    "stripe_public_key": settings.STRIPE_PUBLIC_KEY,
                    "amount": plan.amount * 100
                }
                return render(request, 'subscribe.html', ctx)
    return redirect("account_signup")


def upgrade(request):
    if request.method == 'POST':
        user_id = request.POST.get("user", "")
        plan_id = request.POST.get("plan", "")
        stripe_token = request.POST.get("stripe_source", "")

        if len(user_id) > 0 and len(plan_id) > 0 and len(stripe_token) > 0:
            # Guest checkout with the provided email
            user = User.objects.get(id=user_id)

            # Create the stripe Customer, by default subscriber Model is User,
            # this can be overridden with settings.DJSTRIPE_SUBSCRIBER_MODEL
            customer, created = djstripe.models.Customer.get_or_create(subscriber=user)
            plan = djstripe.models.Plan.objects.get(id=plan_id)

            # Add the source as the customer's default card
            customer.add_card(stripe_token)

            # Make sure we don't end up with multiple subscriptions
            if not created:
                customer.subscription.update(plan=plan, trial_end='now')
                ctx = {
                    "subscription": customer.subscription
                }
                return render(request, "subscription_success.html", ctx)

            # Using the Stripe API, create a subscription for this customer,
            # using the customer's default payment source
            stripe_subscription = stripe.Subscription.create(
                customer=customer.id,
                items=[{"plan": plan.id}],
                billing="charge_automatically",
                # tax_percent=15,
                api_key=settings.STRIPE_SECRET_KEY,
            )

            # Sync the Stripe API return data to the database,
            # this way we don't need to wait for a webhook-triggered sync
            subscription = djstripe.models.Subscription.sync_from_stripe_data(stripe_subscription)
            ctx = {
                "subscription": subscription
            }
            return render(request, "subscription_success.html", ctx)

    ctx = {}
    return render(request, "subscribe.html", ctx)


@receiver(email_confirmed)
def email_confirmed_handler(request, email_address, **kwargs):
    user = email_address.user
    domain = user.profile.domain_temp
    report_domain = Domain.objects.filter(domain__iexact=domain).first()

    if report_domain is None:
        report_domain = Domain(domain=domain)
        report_domain.save()

    user_profile = user.profile
    user_profile.domain = report_domain
    user_profile.save()

    create_report.delay(_domain=domain, _user=user.id)


@login_required
@transaction.atomic
def profile(request):

    c_user = {
        "first_name": request.user.first_name,
        "last_name": request.user.last_name,
        "email": request.user.email
    }

    if request.user.profile.company:
        c_company = {
            "name": request.user.profile.company.name,
            "website": request.user.profile.company.website,
            "sector": request.user.profile.company.sector,
            "city": request.user.profile.company.city,
            "region": request.user.profile.company.region,
            "country": request.user.profile.company.country,
        }
    else:
        c_company = {}

    customer, created = djstripe.models.Customer.get_or_create(subscriber=request.user)
    plan = customer.subscription.plan

    form_company = reports.forms.CompanyForm(initial=c_company)
    form_user = UserForm(initial=c_user)
    form_password = PasswordChangeForm(request.user, request.POST)
    form_plan = UpdatePlanForm(initial={"plan": plan})

    ctx = {
        "form_user": form_user,
        "form_company": form_company,
        "form_password": form_password,
        "form_plan": form_plan,
        "plan": plan
    }
    return render(request, 'private_profile.html', ctx)


@login_required
@transaction.atomic
def update_user(request):
    if request.method == 'POST':
        form = UserForm(request.POST)
        if form.is_valid():
            request.user.first_name = form.cleaned_data['first_name']
            request.user.last_name = form.cleaned_data['last_name']
            request.user.email = form.cleaned_data['email']
            request.user.save()
    return redirect('profile')


@login_required
@transaction.atomic
def update_company(request):
    if request.method == 'POST':
        form = reports.forms.CompanyForm(request.POST)
        if form.is_valid():
            request.user.profile.company.name = form.cleaned_data['name']
            request.user.profile.company.website = form.cleaned_data['website']
            request.user.profile.company.sector = form.cleaned_data['sector']
            request.user.profile.company.city = form.cleaned_data['city']
            request.user.profile.company.region = form.cleaned_data['region']
            request.user.profile.company.country = form.cleaned_data['country']
            request.user.profile.company.save()
    return redirect('profile')


@login_required
@transaction.atomic
def update_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)  # Important!
            messages.success(request, 'Your password was successfully updated!')
            return JsonResponse({"status": "ok"}, status=200)
        else:
            return JsonResponse({"status": "error", "errors": form.errors}, status=400)
    else:
        form = PasswordChangeForm(request.user)
    return redirect('profile')
