from django import forms

from reports.models import Sector


class DomainScanRequestForm(forms.Form):
    domain = forms.CharField(label="Domain",
                             max_length=256,
                             help_text="Provide the domain to analyze.",
                             widget=forms.TextInput(
                                 attrs={
                                     'placeholder': 'example.com'
                                 }
                             ))

class DomainBulkUploadRequestForm(forms.Form):
    domain_csv = forms.FileField()


class MultipleDomainScanRequestForm(forms.Form):
    domains = forms.CharField(
        label="Domains",
        max_length=256,
        help_text="Provide the domains to analyze.",
        widget=forms.Textarea(
            attrs={
                'placeholder': ('One domain per line')
            }
        )
    )



class DomainProfileCompanyUpdate(forms.Form):
    domain = forms.CharField(label="Domain",
                             max_length=128,
                             widget=forms.HiddenInput(),
                             required=True)
    # if existing_company is false, name is new company name
    # if existing_company is true, name is existing company id
    existing_company  = forms.BooleanField(required=False)
    sector = forms.ModelChoiceField(label='Sector',
                                    required=False,
                                    empty_label="(Choose Sector)",
                                    queryset=Sector.objects.all())
    tags = forms.CharField(label="Tags",
                           required=False,
                           max_length=128)
