import logging
import validators

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.views import View
from django.http import JsonResponse, HttpResponseRedirect
from django.db.models import Avg, Count
from django.db.models.functions import Coalesce
from django.db.models import Q
from django.urls import reverse
from users.models import DomainProfile
from reports.models import (
    RiskReport,
    TestResult,
    ScoreItem,
    Company,
    Domain,
    Sector
)

from .forms import (
    DomainScanRequestForm,
    DomainBulkUploadRequestForm,
    DomainProfileCompanyUpdate,
    MultipleDomainScanRequestForm
)

from reports.tasks import (
    create_report,
    score_to_rating,
    NB_STEPS_ANALYSIS
)

logger = logging.getLogger(__name__)


@login_required
def my_rating(request, *args, **kwargs):
    domain = request.user.profile.user_domain()
    report = RiskReport.objects.filter(domain__domain__iexact=domain, latest=True).first()
    scores = dict(list(ScoreItem.objects.filter(report=report).values_list('label', 'score')))
    tests = list(TestResult.objects.filter(report=report))
    domain_profile = DomainProfile.objects.filter(profile=request.user.profile,
                                                  domain__domain__iexact=domain).first()
    ctx = {
        "domain": domain,
        "report": report,
        "scores": scores,
        "tests": tests,
        "domain_profile": domain_profile
    }
    return render(request, "private_my_rating.html", ctx)

@login_required
def dashboard(request, *args, **kwargs):
    profile = request.user.profile
    domain = profile.user_domain()
    domains = profile.followed_domains()
    report = RiskReport.objects.filter(domain__domain__iexact=domain, latest=True).first()
    scores = dict(list(ScoreItem.objects.filter(report=report).values_list('label', 'score')))
    tests = list(TestResult.objects.filter(report=report))
    domain_profile = DomainProfile.objects.filter(profile=profile,
                                                  domain__domain__iexact=domain).first()
    vulns = []

    followed_profiles = DomainProfile.objects.filter(domain__domain__in=domains, profile=profile)
    tags = []

    for fp in followed_profiles:
        for t in fp.tags.split(","):
             if len(t): tags.append(t)

    c_vuln_email = (TestResult.objects.filter(
        Q(report__domain__domain__in=domains) &
        Q(report__latest=True) &
        (Q(definition__label="spfrecordcount") & Q(state="failed")))
        .values("report__domain__domain")
        .distinct()
        .count())

    c_vuln_websec = (ScoreItem.objects.filter(
        Q(report__domain__domain__in=domains) &
        Q(report__latest=True) &
        (Q(label="score_web_security") & Q(score="0")))
        .values("report__domain__domain")
        .distinct()
        .count())

    c_vuln_sites = (ScoreItem.objects.filter(
        Q(report__domain__domain__in=domains) &
        Q(report__latest=True) &
        (Q(label="score_web_application") & Q(score="0")))
        .values("report__domain__domain")
        .distinct()
        .count())

    c_vuln_blist = (ScoreItem.objects.filter(
        Q(report__domain__domain__in=domains) &
        Q(report__latest=True) &
        ((Q(label="score_infrastructure") & Q(score="0")) |
         (Q(label="score_infrastructure") & Q(score="3"))))
        .values("report__domain__domain")
        .distinct()
        .count())

    c = len(domains)
    if c > 0:
        vulns = {
            "count": c,
            "p_vuln_email": round((c_vuln_email / c) * 100),
            "p_vuln_websec": round((c_vuln_websec / c) * 100),
            "p_vuln_webapp": round((c_vuln_sites / c) * 100),
            "p_vuln_trust": round((c_vuln_blist / c) * 100)
        }

    ctx = {
        "domain": domain,
        "report": report,
        "scores": scores,
        "tests": tests,
        "domain_profile": domain_profile,
        "vulns": vulns,
        "tags": set(tags)
    }
    
    return render(request, "dashboard_domain.html", ctx)


@login_required
def domain_report(request, domain, *args, **kwargs):

    # Prevent free users from getting data
    profile = request.user.profile
    if profile.on_trial_or_free_account:
        return redirect('subscribe')
    
    if profile.on_sme_account and profile.domain.domain != domain:
        return JsonResponse({}, status=401)

    report = None
    tests = None
    domain_profile = None
    company = None
    
    if validators.domain(domain):
        report_domain = Domain.objects.filter(domain__iexact=domain).first()
        report = RiskReport.objects.filter(domain=report_domain, latest=True).first()
        scores = dict(list(ScoreItem.objects.filter(report=report).values_list('label', 'score')))
        tests = list(TestResult.objects.filter(report=report))
        domain_profile = DomainProfile.objects.filter(profile=profile, domain=report_domain).first()

    if report_domain:
        finitial = { "domain": report_domain }
        company = report_domain.company
        if company:
            finitial["sector"] = company.sector
        if domain_profile:
            finitial["tags"] = domain_profile.tags
        form_company = DomainProfileCompanyUpdate(initial=finitial)
    else:
        form_company = DomainProfileCompanyUpdate

    ctx = {
        "domain": domain,
        "domain_profile": domain_profile,
        "company": company,
        "companies": Company.objects.all(),
        "followed": profile.followed(domain),
        "report": report,
        "scores": scores,
        "tests": tests,
        "form_company": form_company
    }
    return render(request, "dashboard_report.html", ctx)


@login_required
def my_companies(request, *args, **kwargs):
    if request.user.profile.on_trial_or_free_account:
        return redirect('subscribe')

    if request.user.profile.on_sme_account:
        return redirect('subscribe')
    
    profile = request.user.profile
    domains = profile.followed_domains()
    followed_profiles = DomainProfile.objects.filter(domain__domain__in=domains, profile=profile)
    tags = []

    for fp in followed_profiles:
        for t in fp.tags.split(","):
             if len(t): tags.append(t)

    ctx = {
        "report": score_report_for_domains(domains),
        "tags": set(tags)
    }
    
    return render(request, "my_companies.html", ctx)


@login_required
def do_bulkdomain(request):
    from django.contrib import messages
    import csv, io

    if not request.user.is_superuser:
        return JsonResponse({}, status=401)
    
    domains = []

    if request.method == 'POST':
        form = DomainBulkUploadRequestForm(request.POST, request.FILES)
        try:
            if not form.is_valid():
                raise Exception

            domain_csv = form.cleaned_data['domain_csv'].read().decode('UTF-8')
            lines = domain_csv.splitlines()
            header = lines[0]
            lines = lines[1:]

            if header != 'domain,company,sector,tags':
                raise Exception

            for line in lines:
                cols = line.split(",")
                _domain = None
                _company = None
                _sector = None
                _tags = None

                if len(cols) > 0:
                    _domain = cols[0]
                if len(cols) > 1:
                    _company = cols[1]
                if len(cols) > 2:
                    _sector = cols[2][0:5]
                if len(cols) > 3:
                    _tags = cols[3:]
                if _domain is None or len(_domain) == 0 or not validators.domain(_domain):
                    continue

                domain = Domain.objects.filter(domain__iexact=_domain).first()
                
                if domain is None:
                    domain = Domain(domain=_domain)
                if _tags:
                    domain.tags = ",".join(_tags)
                
                if _company is None or len(_company) == 0:
                    domain.save()
                    continue

                company = Company.objects.filter(name__iexact=_company).first()

                if company is None:
                    company = Company(name=_company)
                
                if _sector is None or len(_sector) == 0:
                    company.save()
                    domain.company = company
                    domain.save()
                    continue

                sector = Sector.objects.filter(code__iexact=_sector).first()

                if sector is None:
                    sector = Sector(code=_sector.upper())
                    sector.save()

                company.sector = sector
                company.save()
                domain.company = company
                domain.save()
                domains.append(domain.domain)
                
        except Exception as e:
            return JsonResponse({ "code": "CSV Format Incorrect" }, status=400)

    return JsonResponse({ "domains": domains })


@login_required
def search(request, *args, **kwargs):
    return render(request, "search.html", {})


@login_required
def scan(request, *args, **kwargs):
    if request.user.profile.on_sme_account:
        return redirect('subscribe')

    form_s = DomainScanRequestForm()
    form_m = MultipleDomainScanRequestForm()
    form_d = DomainBulkUploadRequestForm()

    return render(
        request,
        "domain_scan.html",
        { "form_s": form_s, "form_m": form_m, "form_d": form_d }
    )


@login_required
def do_scan(request, *args, **kwargs):
    if request.user.profile.on_sme_account:
        return JsonResponse({}, status=401)

    if request.method == 'POST':
        form = DomainScanRequestForm(request.POST)
        if form.is_valid():
            domain = form.cleaned_data['domain']
            logger.info("Request for analysis of '{domain:s}' is initiated.".format(domain=domain))
            task = create_report.delay(_domain=domain, _user=request.user.id)
            return JsonResponse({"id": task.id, "company_domain": domain})
        else:
            logger.error(form.errors)
            return JsonResponse({"form": form}, {"id": "0"})


@login_required
def do_follow(request, *args, **kwargs):

    # Prevent free users from following companies
    if not request.user.profile.can_track_companies:
        return JsonResponse({}, status=401)

    if request.method == 'GET':
        domains = request.user.profile.followed_domains()
        results = []
        if len(domains) > 0:
            for domain in domains:
                report = RiskReport.objects.filter(domain__domain__iexact=domain, latest=True).first()
                r = report.search_result_dict(request.user)
                r["is_followed"] = True
                results.append(r)
        return JsonResponse(results, safe=False)

    elif request.method == 'POST':
        new_domain = request.POST.get("domain", "")
        state = request.user.profile.add_followed_domain(new_domain)
        if state:
            return JsonResponse({"message": "Domain successfully added to list of tracked domains."}, status=200)
        else:
            return JsonResponse({"message": "We were unable to add this domain to your list or tracked domain."},
                                status=400)


@login_required
def do_unfollow(request, *args, **kwargs):
    state = False
    if request.method == 'POST':
        domain = request.POST.get("domain", "")
        if len(domain) > 0:
            state = request.user.profile.remove_followed_domain(domain)
    if state:
        return JsonResponse({"message": "The domain is now unfollowed."}, status=200)
    else:
        return JsonResponse({"message": "A problem occurred while trying to unfollow the domain."}, status=400)


@login_required
def do_search(request, *args, **kwargs):
    if request.method == 'GET':
        domain = request.GET.get("domain", "")
        company_name = request.GET.get("company", "")
        tag = request.GET.get("tag", "")
    elif request.method == 'POST':
        domain = request.POST.get("domain", "")
        company_name = request.POST.get("company", "")
    else:
        return JsonResponse({})

    response = []
    profile = request.user.profile

    if len(domain) > 0 and validators.domain(domain):
        domain = Domain.objects.filter(domain__iexact=domain).first()
        results = RiskReport.objects.filter(domain=domain, latest=True)[:128]
    elif len(tag) > 0:
        domains_with_tag=DomainProfile.objects.filter(tags__icontains=tag, profile=profile).values('domain')
        results = RiskReport.objects.filter(domain__in=domains_with_tag, latest=True)
    elif len(company_name) > 0:
        results = RiskReport.objects.filter(domain__company__name__icontains=company_name, latest=True)
    else:
        return JsonResponse({})
    
    for result in results:
        r = result.search_result_dict(request.user)
        r["is_followed"] = (result.domain.domain in profile.followed_domains())
        d = DomainProfile.objects.filter(profile=profile, domain=result.domain).first()
        if d:
            r.update(d.search_result_dict())
        response.append(r)
        
    return JsonResponse(response, safe=False)
    


@login_required
def do_update_company(request, *args, **kwargs):
    import deepcheck.engine

    if request.method == 'POST':
        form = DomainProfileCompanyUpdate(request.POST)
        if form.is_valid():
            domain = form.cleaned_data.get("domain")
            existing_company = form.cleaned_data.get("existing_company")
            sector = form.cleaned_data.get("sector", None)
            website = form.cleaned_data.get("website", f"http://www.{domain}")
            name = request.POST.get("name", None)
            tags = form.cleaned_data.get("tags")
            
            domain = Domain.objects.filter(domain__iexact=domain).first()
            domain_profile = DomainProfile.objects.filter(profile=request.user.profile, domain=domain).first()
            company = None

            if domain_profile is None:
                domain_profile = DomainProfile(profile=request.user.profile, domain=domain)

                if existing_company:
                    if int(name):
                        company = Company.objects.get(id=name)
                else:
                    company = Company(
                        name=name,
                        sector=sector,
                        website=website
                    )
                    company.save()
            elif existing_company and int(name) == 0:
                pass
            elif existing_company and domain.company is None:
                company = Company.objects.get(id=name)
            else:
                if request.user.is_superuser or domain.company is None:
                    if existing_company:
                        company = Company.objects.get(id=name)
                    else:
                        company = Company()
                        company.name = name
                else:
                    company = domain.company

                if sector and (request.user.is_superuser or company.sector is None):
                    company.sector = sector
                if website and (request.user.is_superuser or company.website is None):
                    company.website = website

                company.save()

            if domain and company:
                domain.company = company
                domain.save()

            domain_profile.tags = tags
            domain_profile.save()
            return JsonResponse({}, status=200)
        else:
            return JsonResponse({"error": form.errors})
    return JsonResponse({}, status=400)


@login_required
def status(request, *args, **kwargs):
    id = request.GET.get("id", "")
    if len(id) > 0:
        task = create_report.AsyncResult(id)
        if task.state == 'PENDING':
            # job did not start yet
            response = {
                'state': task.state,
                'current': 0,
                'total': NB_STEPS_ANALYSIS,
                'status': 'Pending...'
            }
        elif task.state != 'FAILURE':
            response = {
                'state': task.state,
                'current': task.info.get('current', 1),
                'total': task.info.get('total', NB_STEPS_ANALYSIS),
                'status': task.info.get('status', '')
            }
            if 'report_id' in task.info:
                response['report_id'] = task.info['report_id']
        else:
            # something went wrong in the background job
            response = {
                'state': task.state,
                'current': 1,
                'total': 1,
                'status': str(task.info),  # this is the exception raised
            }
        return JsonResponse(response)


@login_required
def dashboard_for_domains(request, *args, **kwargs):
    if request.method == 'GET':
        domain = request.GET.get("domain", "").strip()
        company_name = request.GET.get("company_name", "").strip()
    else:
        domain = ""
        company_name = ""

    if validators.domain(domain):
        report_domain = Domain.objects.filter(domain=domain).first()
        report = RiskReport.objects.filter(domain=report_domain, latest=True).first()
        scores = dict(list(ScoreItem.objects.filter(report=report).values_list('label', 'score')))
        tests = list(TestResult.objects.filter(report=report))
        domain_profile = DomainProfile.objects.filter(profile=request.user.profile,
                                                      domain=report_domain).first()
    elif len(company_name) > 0:
        report = RiskReport.objects.filter(domain__company__name__iexact=company_name,
                                           latest=True).first()
        scores = dict(list(ScoreItem.objects.filter(report=report).values_list('label', 'score')))
        tests = list(TestResult.objects.filter(report=report))
        domain_profile = DomainProfile.objects.filter(profile=request.user.profile,
                                                      company__name__iexact=company_name).first()
    else:
        report = None
        domain_profile = None
        scores = None
        tests = None

    if domain_profile:
        finitial = {
            "domain": domain_profile.domain,
            "name": domain_profile.domain.company.name,
            "sector": domain_profile.domain.company.sector,
            "tags": domain_profile.tags
        }
        form_company = DomainProfileCompanyUpdate(initial=finitial)
    elif report is not None:
        form_company = DomainProfileCompanyUpdate(initial={"domain": report.domain})
    else:
        form_company = None

    ctx = {
        "report": report,
        "scores": scores,
        "domain": domain,
        "tests": tests,
        "form_company": form_company,
        "domain_profile": domain_profile,
        "sectors": list(Sector.objects.all()),
        "user": request.user
    }

    return render(request, "dashboard_domain.html", ctx)


@login_required
def dashboard_for_sectors(request, *args, **kwargs):
    report = None

    if request.method == 'GET':
        sector = request.GET.get("sector", "").strip().upper()
        sector = Sector.objects.filter(code=sector).first()
        if sector is not None:
            results = DomainProfile.objects.filter(profile=request.user.profile, company__sector=sector)
            c = len(results)
            if c > 0:
                report = {}
                report["count"] = c
                report["avg_overall_score"] = 0.0
                report["avg_overall_rating"] = "F"
                report["email_security_score"] = 0.0
                report["email_security_rating"] = "F"
                report["web_security_score"] = 0.0
                report["web_security_rating"] = "F"
                report["web_application_score"] = 0.0
                report["web_application_rating"] = "F"
                report["infrastructure_score"] = 0.0
                report["infrastructure_rating"] = "F"
                report["distribution"] = {
                    "A": 10,
                    "B": 20,
                    "C": 30,
                    "D": 40,
                    "E": 50,
                    "F": 60
                }
                report["p_vuln_email"] = (p_vuln_email / c) * 100
                report["p_vuln_websec"] = (0.0 / c) * 100
                report["p_vuln_webapp"] = (0.0 / c) * 100
                report["p_vuln_trust"] = (0.0 / c) * 100
    else:
        sector = None

    ctx = {
        "report": report,
        "sector": sector,
        "sectors": list(Sector.objects.all()),
        "user": request.user
    }
    return render(request, "dashboard_sector.html", ctx)


def score_report_for_domains(domains):
    if domains is None:
        return None

    c = len(domains)
    if not c:
        return None

    s_ov_avg = (ScoreItem.objects.filter(
        report__domain__domain__in=domains,
        report__latest=True,
        label="score_overall")
        .aggregate(score=Avg('score'))["score"])

    s_em_avg = (ScoreItem.objects.filter(
        report__domain__domain__in=domains,
        report__latest=True,
        label="score_email_security")
        .aggregate(score=Avg('score'))["score"])

    s_ws_avg = (ScoreItem.objects.filter(
        report__domain__domain__in=domains,
        report__latest=True,
        label="score_web_security")
        .aggregate(score=Avg('score'))["score"])

    s_wa_avg = (ScoreItem.objects.filter(
        report__domain__domain__in=domains,
        report__latest=True,
        label="score_web_application")
        .aggregate(score=Avg('score'))["score"])

    s_in_avg = (ScoreItem.objects.filter(
        report__domain__domain__in=domains,
        report__latest=True,
        label="score_infrastructure")
        .aggregate(score=Avg('score'))["score"])

    c_a = (ScoreItem.objects.filter(
        report__domain__domain__in=domains,
        label="score_overall",
        report__latest=True,
        rating="A")
        .aggregate(count=Coalesce(Count('report__id'), 0))["count"])

    c_b = (ScoreItem.objects.filter(
        report__domain__domain__in=domains,
        label="score_overall",
        report__latest=True,
        rating="B")
        .aggregate(count=Coalesce(Count('report__id'), 0))["count"])

    c_c = (ScoreItem.objects.filter(
        report__domain__domain__in=domains,
        label="score_overall",
        report__latest=True,
        rating="C")
        .aggregate(count=Coalesce(Count('report__id'), 0))["count"])

    c_d = (ScoreItem.objects.filter(
        report__domain__domain__in=domains,
        label="score_overall",
        report__latest=True,
        rating="D")
        .aggregate(count=Coalesce(Count('report__id'), 0))["count"])

    c_e = (ScoreItem.objects.filter(
        report__domain__domain__in=domains,
        label="score_overall",
        report__latest=True,
        rating="E")
        .aggregate(count=Coalesce(Count('report__id'), 0))["count"])
        
    c_f = (ScoreItem.objects.filter(
        report__domain__domain__in=domains,
        label="score_overall",
        report__latest=True,
        rating="F")
        .aggregate(count=Coalesce(Count('report__id'), 0))["count"])

    c_vuln_email = (TestResult.objects.filter(
        Q(report__domain__domain__in=domains) &
        Q(report__latest=True) &
        (Q(definition__label="spfrecordcount") & Q(state="failed")))
        .values("report__domain__domain")
        .distinct()
        .count())

    c_vuln_websec = (ScoreItem.objects.filter(
        Q(report__domain__domain__in=domains) &
        Q(report__latest=True) &
        (Q(label="score_web_security") & Q(score="0")))
        .values("report__domain__domain")
        .distinct()
        .count())

    c_vuln_sites = (ScoreItem.objects.filter(
        Q(report__domain__domain__in=domains) &
        Q(report__latest=True) &
        (Q(label="score_web_application") & Q(score="0")))
        .values("report__domain__domain")
        .distinct()
        .count())

    c_vuln_blist = (ScoreItem.objects.filter(
        Q(report__domain__domain__in=domains) &
        Q(report__latest=True) &
        ((Q(label="score_infrastructure") & Q(score="0")) |
         (Q(label="score_infrastructure") & Q(score="3"))))
        .values("report__domain__domain")
        .distinct()
        .count())

    return {
        "count": c,
        "avg_overall_score": s_ov_avg,
        "avg_overall_rating": score_to_rating(s_ov_avg),
        "email_security_score": s_em_avg,
        "email_security_rating": score_to_rating(s_em_avg),
        "web_security_score": s_ws_avg,
        "web_security_rating": score_to_rating(s_ws_avg),
        "web_application_score": s_wa_avg,
        "web_application_rating": score_to_rating(s_wa_avg),
        "infrastructure_score": s_in_avg,
        "infrastructure_rating": score_to_rating(s_in_avg),
        "distribution": {
            "A": c_a,
            "B": c_b,
            "C": c_c,
            "D": c_d,
            "E": c_e,
            "F": c_f
        },
        "p_vuln_email": round((c_vuln_email / c) * 100),
        "p_vuln_websec": round((c_vuln_websec / c) * 100),
        "p_vuln_webapp": round((c_vuln_sites / c) * 100),
        "p_vuln_trust": round((c_vuln_blist / c) * 100)
    }

@login_required
def dashboard_for_tags(request, tag, *args, **kwargs):
    if request.method == 'GET':
        report = None

        if len(tag) > 0:
            domains = []

            profile = request.user.profile
            domain_profiles = DomainProfile.objects.filter(domain__domain__in=profile.followed_domains(),
                                                           tags__icontains=tag,
                                                           profile=profile)

            for p in domain_profiles:
                domains.append(p.domain.domain)

            report = score_report_for_domains(domains)
    else:
        tag = None

    ctx = {
        "report": report,
        "tag": tag,
        "sectors": list(Sector.objects.all()),
        "user": request.user
    }
    return render(request, "dashboard_tag.html", ctx)


@login_required
def data_view(request, domain, *args, **kwargs):

    # Prevent free users from getting data
    profile = request.user.profile

    if profile.on_trial_or_free_account:
        return redirect('subscribe')
    if profile.on_sme_account and profile.domain.domain != domain:
        return JsonResponse({}, status=401)
    
    report = None
    tests = None
    domain_profile = None
    if validators.domain(domain):
        report = RiskReport.objects.filter(domain__domain__iexact=domain, latest=True).first()
        tests = list(TestResult.objects.filter(report=report))
        domain_profile = DomainProfile.objects.filter(profile=profile,
                                                      domain__domain__iexact=domain).first()

    ctx = {
        "domain": domain,
        "domain_profile": domain_profile,
        "report": report,
        "tests": tests,
    }
    return render(request, "report.html", ctx)


@login_required
def privacy_report(request, *args, **kwargs):
    return render(request, "privacy_report.html", {})


@login_required
def remediation_email(request, *args, **kwargs):
    return render(request, "remediation_email.html", {})


@login_required
def remediation_spf(request, *args, **kwargs):
    return render(request, "remediation_spf.html", {})


@login_required
def remediation_dkim(request, *args, **kwargs):
    return render(request, "remediation_dkim.html", {})


@login_required
def remediation_dmarc(request, *args, **kwargs):
    return render(request, "remediation_dmarc.html", {})


@login_required
def remediation_smtp(request, *args, **kwargs):
    return render(request, "remediation_smtp.html", {})


@login_required
def remediation_https(request, *args, **kwargs):
    return render(request, "remediation_https.html", {})


@login_required
def remediation_dnssec(request, *args, **kwargs):
    return render(request, "remediation_dnssec.html", {})


@login_required
def remediation_hsts(request, *args, **kwargs):
    return render(request, "remediation_hsts.html", {})


@login_required
def remediation_xxss(request, *args, **kwargs):
    return render(request, "remediation_x-xss.html", {})


@login_required
def remediation_xframe(request, *args, **kwargs):
    return render(request, "remediation_x-frame.html", {})


@login_required
def remediation_xct(request, *args, **kwargs):
    return render(request, "remediation_xct.html", {})


@login_required
def remediation_csp(request, *args, **kwargs):
    return render(request, "remediation_csp.html", {})


@login_required
def remediation_referrer(request, *args, **kwargs):
    return render(request, "remediation_referrer.html", {})


@login_required
def remediation_feature(request, *args, **kwargs):
    return render(request, "remediation_feature.html", {})


@login_required
def remediation_servhead(request, *args, **kwargs):
    return render(request, "remediation_servhead.html", {})


@login_required
def remediation_xpower(request, *args, **kwargs):
    return render(request, "remediation_xpower.html", {})


@login_required
def remediation_headers(request, *args, **kwargs):
    return render(request, "remediation_headers.html", {})


@login_required
def remediation_cookies(request, *args, **kwargs):
    return render(request, "remediation_cookies.html", {})


@login_required
def remediation_ip(request, *args, **kwargs):
    return render(request, "remediation_ip.html", {})


@login_required
def remediation_ports(request, *args, **kwargs):
    return render(request, "remediation_ports.html", {})


@login_required
def remediation_vulns(request, *args, **kwargs):
    return render(request, "remediation_vulns.html", {})


@login_required
def security_framework(request, *args, **kwargs):
    return render(request, "security_framework.html", {})


@login_required
def policies(request, *args, **kwargs):
    return render(request, "policies_all.html", {})


@login_required
def policies_high_level(request, *args, **kwargs):
    return render(request, "policies_high_level.html", {})


@login_required
def policy_cybersec(request, *args, **kwargs):
    return render(request, "policies_cybersec.html", {})


@login_required
def policy_email(request, *args, **kwargs):
    return render(request, "policies_email.html", {})


@login_required
def policy_employees(request, *args, **kwargs):
    return render(request, "policies_employees.html", {})


@login_required
def policy_internet(request, *args, **kwargs):
    return render(request, "policies_internet.html", {})


@login_required
def policy_mobile_devices(request, *args, **kwargs):
    return render(request, "policies_mobile_devices.html", {})


@login_required
def policy_remote_work(request, *args, **kwargs):
    return render(request, "policies_remote_work.html", {})


@login_required
def policy_social_media(request, *args, **kwargs):
    return render(request, "policies_social_media.html", {})


@login_required
def resources_security_framework(request, *args, **kwargs):
    if request.user.profile.on_trial_or_free_account:
        return redirect('subscribe')
    return render(request, "security_framework.html", {})


@login_required
def resources_infosec_guidelines(request, *args, **kwargs):
    if request.user.profile.on_trial_or_free_account:
        return redirect('subscribe')
    return render(request, "infosec_guidelines.html", {})


@login_required
def resources_incident_response(request, *args, **kwargs):
    if request.user.profile.on_trial_or_free_account:
        return redirect('subscribe')
    return render(request, "incident_response.html", {})


@login_required
def resources_awareness(request, *args, **kwargs):
    if request.user.profile.on_trial_or_free_account:
        return redirect('subscribe')
    return render(request, "security_awareness_material.html", {})


@login_required
def security_training(request, *args, **kwargs):
    if request.user.profile.on_trial_or_free_account:
        return redirect('subscribe')
    return render(request, "security_training.html", {})


@login_required
def security_training_LMS(request, *args, **kwargs):
    if request.user.profile.on_trial_or_free_account:
        return redirect('subscribe')
    return render(request, "security_training_LMS.html", {})


@login_required
def security_phishing(request, *args, **kwargs):
    if request.user.profile.on_trial_or_free_account:
        return redirect('subscribe')
    return render(request, "security_phishing.html", {})


@login_required
def security_bite_sized(request, *args, **kwargs):
    if request.user.profile.on_trial_or_free_account:
        return redirect('subscribe')
    return render(request, "security_bite_sized.html", {})


login_required
def security_csaas(request, *args, **kwargs):
    if request.user.profile.on_trial_or_free_account:
        return redirect('subscribe')
    return render(request, "security_csaas.html", {})


@login_required
def contact_us(request, *args, **kwargs):
    return render(request, "contact.html", {})
