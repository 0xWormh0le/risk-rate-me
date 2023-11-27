from django.contrib import admin

from .models import Sector, Company, Domain, TestDefinition, RiskReport, TestResult, ScoreItem


@admin.register(Sector)
class SectorAdmin(admin.ModelAdmin):
    class Meta:
        verbose_name_plural = "Sectors"


@admin.register(Company)
class CompanyAdmin(admin.ModelAdmin):
    class Meta:
        verbose_name_plural = "Companies"


@admin.register(Domain)
class DomainAdmin(admin.ModelAdmin):
    class Meta:
        verbose_name_plural = "Domains"


@admin.register(TestDefinition)
class TestDefinitionAdmin(admin.ModelAdmin):
    list_display = ["label", "name"]
    class Meta:
        verbose_name_plural = "Tests"


class TestResultsAdmin(admin.TabularInline):
    model = TestResult
    class Meta:
        verbose_name_plural = "Results"


class ReportScoresAdmin(admin.TabularInline):
    model = ScoreItem
    class Meta:
        verbose_name_plural = "Scores"


@admin.register(RiskReport)
class RiskReportAdmin(admin.ModelAdmin):
    inlines = [
        ReportScoresAdmin,
        TestResultsAdmin
    ]
    list_display = ["domain", "generated_on"]
    class Meta:
        verbose_name_plural = "Reports"
