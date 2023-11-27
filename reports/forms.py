from django import forms
from django_countries import fields
from .models import Company, Sector


class CompanyForm(forms.ModelForm):
    class Meta:
        model = Company
        fields = ('name', 'sector', 'website', 'city', 'region', 'country')
