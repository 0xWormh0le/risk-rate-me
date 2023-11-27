"""riskrateme URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include

import public.views
import users.views
import dashboard.views
import assessments.views
import download.views

admin.site.site_header = 'Riskrate.me Administration'

urlpatterns = [
    path('admin/', admin.site.urls),
    # Public Website pages/views
    path('', public.views.home, name="home"),
    path("stripe/", include("djstripe.urls", namespace="djstripe")),
    path('accounts/', include('allauth.urls')),

    path('subscribe/', users.views.subscribe, name="subscribe"),
    path('profile/company/', users.views.update_company, name="update-profile-company"),
    path('profile/user/', users.views.update_user, name="update-profile-user"),
    path('profile/password/', users.views.update_password, name="update-password"),
    path('upgrade/', users.views.upgrade, name="upgrade"),
    path('contact/', public.views.contact, name="contact"),
    path('feedback/', public.views.feedback, name="feedback"),
    path('pricing/', public.views.pricing, name="pricing"),
    path('about-ratings/', public.views.about_ratings, name="about-ratings"),
    path('training/', public.views.security_training, name="security-training"),
    path('security-starter/', public.views.security_starter, name="security-starter"),
    path('threat-assessment/', public.views.threat_assessment, name="threat-assessment"),
    path('consultancy/', public.views.consultancy, name="consultancy"),
    path('remediation-reports/', public.views.remediation_reports, name="remediation-reports"),
    path('industry-uses/', public.views.industry_uses, name="industry-uses"),
    path('phishing-defence/', public.views.security_phishing, name="security-phishing"),
    path('privacy/', public.views.privacy, name="privacy"),
    path('dashboard/my-rating/', dashboard.views.my_rating, name="my-rating"),
    path('dashboard/report/<domain>', dashboard.views.domain_report, name="report"),
    path('dashboard/my-companies/', dashboard.views.my_companies, name="my-companies"),
    path('dashboard/search/', dashboard.views.search, name="report-search"),
    path('dashboard/scan/', dashboard.views.scan, name="domain-scan"),
    path('dashboard/privacy-report', dashboard.views.privacy_report, name="privacy-report"),
    path('dashboard/', dashboard.views.dashboard, name="dashboard"),
    path('dashboard/domain', dashboard.views.dashboard_for_domains, name="domain-info"),
    path('dashboard/sector/<sector>', dashboard.views.dashboard_for_sectors, name="sector-info"),
    path('dashboard/tag/<tag>', dashboard.views.dashboard_for_tags, name="tag-info"),
    path('dashboard/data-view/<domain>', dashboard.views.data_view, name="data-view"),

    path('dashboard/actions/scan', dashboard.views.do_scan, name="do-scan"),
    path('dashboard/actions/search', dashboard.views.do_search, name="do-search"),
    path('dashboard/actions/status', dashboard.views.status, name="get-status"),
    path('dashboard/actions/domain/profile', dashboard.views.do_update_company, name="update-domain-info"),
    path('dashboard/actions/follow', dashboard.views.do_follow, name="do-follow"),
    path('dashboard/actions/unfollow', dashboard.views.do_unfollow, name="do-unfollow"),
    path('dashboard/actions/bulk-domain', dashboard.views.do_bulkdomain, name="bulk-domain"),
    path('dashboard/contact-us', dashboard.views.contact_us, name="contact-us"),

    path('dashboard/profile/', users.views.profile, name="profile"),

    path('dashboard/remediation/email', dashboard.views.remediation_email, name="remediation-email"),
    path('dashboard/remediation/spf', dashboard.views.remediation_spf, name="remediation-spf"),
    path('dashboard/remediation/dkim', dashboard.views.remediation_dkim, name="remediation-dkim"),
    path('dashboard/remediation/dmarc', dashboard.views.remediation_dmarc, name="remediation-dmarc"),
    path('dashboard/remediation/smtp', dashboard.views.remediation_smtp, name="remediation-smtp"),
    path('dashboard/remediation/https', dashboard.views.remediation_https, name="remediation-https"),
    path('dashboard/remediation/dnssec', dashboard.views.remediation_dnssec, name="remediation-dnssec"),
    path('dashboard/remediation/hsts', dashboard.views.remediation_hsts, name="remediation-hsts"),
    path('dashboard/remediation/xxss', dashboard.views.remediation_xxss, name="remediation-xxss"),
    path('dashboard/remediation/xframe', dashboard.views.remediation_xframe, name="remediation-xframe"),
    path('dashboard/remediation/xct', dashboard.views.remediation_xct, name="remediation-xct"),
    path('dashboard/remediation/csp', dashboard.views.remediation_csp, name="remediation-csp"),
    path('dashboard/remediation/referrer', dashboard.views.remediation_referrer, name="remediation-referrer"),
    path('dashboard/remediation/feature', dashboard.views.remediation_feature, name="remediation-feature"),
    path('dashboard/remediation/servhead', dashboard.views.remediation_servhead, name="remediation-servhead"),
    path('dashboard/remediation/xpower', dashboard.views.remediation_xpower, name="remediation-xpower"),
    path('dashboard/remediation/cookies', dashboard.views.remediation_cookies, name="remediation-cookies"),
    path('dashboard/remediation/ip', dashboard.views.remediation_ip, name="remediation-ip"),
    path('dashboard/remediation/ports', dashboard.views.remediation_ports, name="remediation-ports"),
    path('dashboard/remediation/vulns', dashboard.views.remediation_vulns, name="remediation-vulns"),
    path('dashboard/remediation/headers', dashboard.views.remediation_headers, name="remediation-headers"),

    path('dashboard/resources/security-framework', dashboard.views.resources_security_framework, name="security_framework"),
    path('dashboard/resources/infosec-guide', dashboard.views.resources_infosec_guidelines, name="infosec_guidelines"),
    path('dashboard/resources/incident-response', dashboard.views.resources_incident_response, name="incident_response"),
    
    path('dashboard/resources/internal-assessment', assessments.views.resources_internal_asessment,
         name="internal_assessment"),
    path('dashboard/resources/internal-assessment/nist', assessments.views.nist,
         name="nist_assessment"),
    path('dashboard/resources/internal-assessment/cyber-essentials', assessments.views.cyber_essentials,
         name="cyber_essentials_assessment"),
    path('dashboard/actions/do-internal-assessment', assessments.views.do_resources_internal_asessment, name="do_internal_assessment"),

    path('dashboard/resources/internal-assessment/nist/result', assessments.views.nist,
         name="nist_assessment_result"),
    path('dashboard/resources/internal-assessment/cyber-essentials/result', assessments.views.cyber_essentials,
         name="cyber_essentials_assessment_result"),
    
    path('dashboard/resources/awareness-material', dashboard.views.resources_awareness, name="awareness_material"),
    path('dashboard/resources/bite-sized', dashboard.views.security_bite_sized, name="security_bite_sized"),
    path('dashboard/resources/security-training', dashboard.views.security_training, name="security_training"),
    path('dashboard/resources/employee-training', dashboard.views.security_training_LMS, name="security_training_LMS"),
    path('dashboard/resources/phishing', dashboard.views.security_phishing, name="security_phishing"),
    path('dashboard/resources/consultancy', dashboard.views.security_csaas, name="security_csaas"),

    path('dashboard/policies/employees', dashboard.views.policies, name="policies"),
    path('dashboard/policies/it-management', dashboard.views.policies_high_level, name="policies_high_level"),
    path('dashboard/policies/cyber-security', dashboard.views.policy_cybersec, name="policies_cybersec"),
    path('dashboard/policies/email', dashboard.views.policy_email, name="policies_email_usage"),
    path('dashboard/policies/employees', dashboard.views.policy_employees, name="policies_employees"),
    path('dashboard/policies/internet', dashboard.views.policy_internet, name="policies_internet_usage"),
    path('dashboard/policies/mobile-devices', dashboard.views.policy_mobile_devices, name="policies_mobile_devices_usage"),
    path('dashboard/policies/remote-work', dashboard.views.policy_remote_work, name="policies_remote_work"),
    path('dashboard/policies/social-media', dashboard.views.policy_social_media, name="policies_social_media_usage"),

    path('download/incident-response/<str:name>', download.views.serve_file, name="download_incident_response"),
    path('download/policies/<str:name>', download.views.serve_file, name="download_policy"),
    path('download/bite-sized/<str:name>', download.views.serve_file, name="download_bite_sized")
]
